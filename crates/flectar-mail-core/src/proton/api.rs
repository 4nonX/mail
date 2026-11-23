//! Proton's REST API: one session, its tokens, and the error shape every
//! endpoint shares.
//!
//! Proton answers each request with JSON carrying a `Code`; 1000 and 1001 mean
//! success. Errors carry the same `Code` plus `Error` and, for human
//! verification (9001), `Details` with the challenge.

use crate::error::{CoreError, Result};
use crate::http_body;
use crate::net::proxy::{Owner, SharedClient};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

/// Proton's API for mail accounts.
pub const API_BASE: &str = "https://mail.proton.me/api";
/// The host of [`API_BASE`].
pub const API_HOST: &str = "mail.proton.me";

/// The app identity sent with every request. Proton only serves apps it
/// knows, so this names one of Proton's own; set
/// `FLECTAR_PROTON_APP_VERSION` to try another.
const DEFAULT_APP_VERSION: &str = "ios-mail@7.5.0";

const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Proton's success codes.
const CODE_OK: i64 = 1000;
const CODE_OK_MULTI: i64 = 1001;
/// Proton wants proof that a person is signing in.
pub const CODE_HUMAN_VERIFICATION: i64 = 9001;

pub fn app_version() -> String {
    std::env::var("FLECTAR_PROTON_APP_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_APP_VERSION.to_owned())
}

fn http_client(owner: Owner) -> Result<reqwest::Client> {
    static HTTP: SharedClient = SharedClient::new(|builder| {
        builder
            .user_agent(concat!("FlectarMail/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
    });
    HTTP.get(owner)
        .map_err(|error| CoreError::Network(format!("Proton HTTP client: {error}")))
}

/// The tokens of a signed-in (or not yet signed-in) Proton session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
}

/// Proton's challenge to prove a person is signing in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HumanVerification {
    pub token: String,
    pub methods: Vec<String>,
}

/// A solved challenge, sent back with the request that asked for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HumanVerificationAnswer {
    pub token: String,
    pub kind: String,
}

/// An error Proton returned for a request.
#[derive(Clone, Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: i64,
    pub message: String,
    pub details: Value,
}

impl ApiError {
    pub fn human_verification(&self) -> Option<HumanVerification> {
        if self.code != CODE_HUMAN_VERIFICATION {
            return None;
        }
        let token = self.details.get("HumanVerificationToken")?.as_str()?;
        let methods = self
            .details
            .get("HumanVerificationMethods")
            .and_then(Value::as_array)
            .map(|methods| {
                methods
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Some(HumanVerification {
            token: token.to_owned(),
            methods,
        })
    }
}

/// What a request can end in.
#[derive(Debug)]
pub enum Failure {
    /// Proton answered with an error.
    Api(ApiError),
    /// The request did not get an answer Proton gave.
    Core(CoreError),
}

impl From<CoreError> for Failure {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

impl From<Failure> for CoreError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Core(error) => error,
            Failure::Api(error) => match (error.status, error.code) {
                (401, _) => CoreError::NeedsReauth,
                (_, CODE_HUMAN_VERIFICATION) => CoreError::Auth(format!(
                    "Proton wants to verify that a person is signing in: {}",
                    error.message
                )),
                (400 | 422, _) if error.code == 8002 => {
                    CoreError::Auth(format!("Proton refused the sign-in: {}", error.message))
                }
                // What Proton turns down in its own words it turns down
                // again, so it is not tried again.
                (400 | 402 | 403 | 404 | 409 | 413 | 422, _) => {
                    CoreError::Other(format!("Proton: {}", error.message))
                }
                _ => CoreError::Network(format!(
                    "Proton answered {} (code {}): {}",
                    error.status, error.code, error.message
                )),
            },
        }
    }
}

pub type ApiResult<T> = std::result::Result<T, Failure>;

/// Parses Proton's answer: the JSON on success, [`ApiError`] otherwise.
pub(crate) fn parse_answer<T: DeserializeOwned>(status: u16, body: &[u8]) -> ApiResult<T> {
    let value: Value = serde_json::from_slice(body).map_err(|error| {
        Failure::Core(CoreError::Network(format!(
            "Proton answered {status} with a body that is not JSON: {error}"
        )))
    })?;
    let code = value.get("Code").and_then(Value::as_i64).unwrap_or(0);
    if (200..300).contains(&status) && (code == CODE_OK || code == CODE_OK_MULTI) {
        return serde_json::from_value(value).map_err(|error| {
            Failure::Core(CoreError::Network(format!(
                "Proton's answer has an unexpected shape: {error}"
            )))
        });
    }
    Err(Failure::Api(ApiError {
        status,
        code,
        message: value
            .get("Error")
            .and_then(Value::as_str)
            .unwrap_or("no message")
            .to_owned(),
        details: value.get("Details").cloned().unwrap_or(Value::Null),
    }))
}

/// One part of a form: a field, or a file when `file` names its type.
pub struct FormPart<'a> {
    pub name: &'a str,
    pub file: Option<&'a str>,
    pub data: &'a [u8],
}

/// A Proton API session. Requests that fail because the access token
/// expired refresh it once and are sent again.
pub struct Session {
    owner: Owner,
    base: String,
    app_version: String,
    tokens: Mutex<Option<Tokens>>,
    /// One refresh at a time: a refresh token works once, so two requests
    /// that find the access token expired must not both spend it.
    refreshing: Mutex<()>,
    saver: std::sync::Mutex<Option<Saver>>,
}

/// Keeps a refreshed token pair. It runs before the request that needed the
/// refresh goes on, so the pair is never only in memory.
pub type Saver =
    std::sync::Arc<dyn Fn(Tokens) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync>;

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RefreshRequest<'a> {
    #[serde(rename = "UID")]
    uid: &'a str,
    refresh_token: &'a str,
    response_type: &'static str,
    grant_type: &'static str,
    #[serde(rename = "RedirectURI")]
    redirect_uri: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    #[serde(rename = "UID", default)]
    uid: Option<String>,
}

impl Session {
    pub fn new(owner: Owner, tokens: Option<Tokens>) -> Self {
        Self::with_base(owner, API_BASE, tokens)
    }

    pub fn with_base(owner: Owner, base: &str, tokens: Option<Tokens>) -> Self {
        Self {
            owner,
            base: base.trim_end_matches('/').to_owned(),
            app_version: app_version(),
            tokens: Mutex::new(tokens),
            refreshing: Mutex::new(()),
            saver: std::sync::Mutex::new(None),
        }
    }

    /// Has every refreshed token pair kept by `saver`.
    pub fn keep_tokens_with(&self, saver: Saver) {
        *self.saver.lock().unwrap_or_else(|e| e.into_inner()) = Some(saver);
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub async fn tokens(&self) -> Option<Tokens> {
        self.tokens.lock().await.clone()
    }

    pub async fn set_tokens(&self, tokens: Option<Tokens>) {
        *self.tokens.lock().await = tokens;
    }

    /// Sends a request and parses the answer, refreshing the access token
    /// once when Proton says it expired.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        verification: Option<&HumanVerificationAnswer>,
    ) -> ApiResult<T> {
        let used = self.tokens().await;
        match self.send(method.clone(), path, body, verification).await {
            Err(Failure::Api(error)) if error.status == 401 => {
                if self.refresh_after(used.as_ref()).await.is_err() {
                    return Err(Failure::Api(error));
                }
                self.send(method, path, body, verification).await
            }
            other => other,
        }
    }

    /// Refreshes the tokens unless another request already replaced the
    /// ones `used` since.
    async fn refresh_after(&self, used: Option<&Tokens>) -> ApiResult<()> {
        let _one = self.refreshing.lock().await;
        if self.tokens().await.as_ref() != used {
            return Ok(());
        }
        self.refresh_unguarded().await
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> ApiResult<T> {
        self.call(reqwest::Method::GET, path, None, None).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> ApiResult<T> {
        self.call(reqwest::Method::POST, path, Some(body), None)
            .await
    }

    pub async fn put<T: DeserializeOwned>(&self, path: &str, body: &Value) -> ApiResult<T> {
        self.call(reqwest::Method::PUT, path, Some(body), None)
            .await
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        verification: Option<&HumanVerificationAnswer>,
    ) -> ApiResult<T> {
        let (status, bytes) = self.send_raw(method, path, body, verification).await?;
        parse_answer(status, &bytes)
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> ApiResult<T> {
        self.call(reqwest::Method::DELETE, path, None, None).await
    }

    /// Fetches data that is not JSON, such as an attachment, refreshing the
    /// access token once when it expired.
    pub async fn get_bytes(&self, path: &str) -> ApiResult<(u16, Vec<u8>)> {
        let used = self.tokens().await;
        let (status, bytes) = self
            .send_raw(reqwest::Method::GET, path, None, None)
            .await?;
        if status != 401 || self.refresh_after(used.as_ref()).await.is_err() {
            return Ok((status, bytes));
        }
        self.send_raw(reqwest::Method::GET, path, None, None).await
    }

    /// Posts a form of named parts, some of them files.
    pub async fn post_form<T: DeserializeOwned>(
        &self,
        path: &str,
        parts: &[FormPart<'_>],
    ) -> ApiResult<T> {
        let used = self.tokens().await;
        match self.send_form(path, parts).await {
            Err(Failure::Api(error)) if error.status == 401 => {
                if self.refresh_after(used.as_ref()).await.is_err() {
                    return Err(Failure::Api(error));
                }
                self.send_form(path, parts).await
            }
            other => other,
        }
    }

    async fn send_form<T: DeserializeOwned>(
        &self,
        path: &str,
        parts: &[FormPart<'_>],
    ) -> ApiResult<T> {
        let boundary = format!("flectar-{:032x}", rand::random::<u128>());
        let mut body = Vec::new();
        for part in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            let name = part.name.replace(['"', '\r', '\n'], "_");
            match part.file {
                Some(content_type) => body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"blob\"\r\nContent-Type: {content_type}\r\n\r\n"
                    )
                    .as_bytes(),
                ),
                None => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                ),
            }
            body.extend_from_slice(part.data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let http = http_client(self.owner)?;
        let mut request = http
            .post(format!("{}{}", self.base, path))
            .header("x-pm-appversion", &self.app_version)
            .header("Accept", "application/vnd.protonmail.v1+json")
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            // A large upload gets time at 64 KiB/s.
            .timeout(std::time::Duration::from_secs(
                120 + body.len() as u64 / (64 * 1024),
            ))
            .body(body);
        if let Some(tokens) = self.tokens.lock().await.as_ref() {
            request = request
                .header("x-pm-uid", &tokens.uid)
                .bearer_auth(&tokens.access_token);
        }
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() || error.is_connect() {
                CoreError::Offline
            } else {
                CoreError::Network(format!("Proton request failed: {error}"))
            }
        })?;
        let status = response.status().as_u16();
        let bytes = http_body::bytes(response, MAX_RESPONSE_BYTES, "Proton answer").await?;
        parse_answer(status, &bytes)
    }

    /// Sends a request and returns Proton's status and body unparsed, for
    /// endpoints that answer with data other than JSON.
    pub async fn send_raw(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        verification: Option<&HumanVerificationAnswer>,
    ) -> ApiResult<(u16, Vec<u8>)> {
        let http = http_client(self.owner)?;
        let url = format!("{}{}", self.base, path);
        let mut request = http
            .request(method, &url)
            .header("x-pm-appversion", &self.app_version)
            .header("Accept", "application/vnd.protonmail.v1+json");
        if let Some(tokens) = self.tokens.lock().await.as_ref() {
            request = request
                .header("x-pm-uid", &tokens.uid)
                .bearer_auth(&tokens.access_token);
        }
        if let Some(answer) = verification {
            request = request
                .header("x-pm-human-verification-token", &answer.token)
                .header("x-pm-human-verification-token-type", &answer.kind);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() || error.is_connect() {
                CoreError::Offline
            } else {
                CoreError::Network(format!("Proton request failed: {error}"))
            }
        })?;
        let status = response.status().as_u16();
        if status == 429 || status == 503 {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(std::time::Duration::from_secs);
            return Err(Failure::Core(CoreError::RateLimited {
                service: "Proton".into(),
                kind: crate::error::LimitKind::Requests,
                retry_after,
                detail: format!("Proton answered {status}"),
            }));
        }
        let bytes = http_body::bytes(response, MAX_RESPONSE_BYTES, "Proton answer").await?;
        Ok((status, bytes))
    }

    /// Trades the refresh token for a new pair.
    pub async fn refresh(&self) -> ApiResult<()> {
        let _one = self.refreshing.lock().await;
        self.refresh_unguarded().await
    }

    async fn refresh_unguarded(&self) -> ApiResult<()> {
        let Some(current) = self.tokens().await else {
            return Err(Failure::Core(CoreError::NeedsReauth));
        };
        let request = serde_json::to_value(RefreshRequest {
            uid: &current.uid,
            refresh_token: &current.refresh_token,
            response_type: "token",
            grant_type: "refresh_token",
            redirect_uri: "https://protonmail.ch",
        })
        .expect("refresh request serializes");
        let answer: RefreshResponse = self
            .send(
                reqwest::Method::POST,
                "/auth/v4/refresh",
                Some(&request),
                None,
            )
            .await
            .map_err(|failure| match failure {
                // A refresh token Proton no longer takes means signing in again.
                Failure::Api(error) if matches!(error.status, 400 | 401 | 422) => {
                    Failure::Core(CoreError::NeedsReauth)
                }
                other => other,
            })?;
        let tokens = Tokens {
            uid: answer.uid.unwrap_or(current.uid),
            access_token: answer.access_token,
            refresh_token: answer.refresh_token,
        };
        self.set_tokens(Some(tokens.clone())).await;
        let saver = self.saver.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(saver) = saver {
            saver(tokens).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_codes_parse_the_body() {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Answer {
            value: u32,
        }
        let answer: Answer = parse_answer(200, br#"{"Code":1000,"Value":7}"#).unwrap();
        assert_eq!(answer.value, 7);
        let answer: Answer = parse_answer(200, br#"{"Code":1001,"Value":8}"#).unwrap();
        assert_eq!(answer.value, 8);
    }

    #[test]
    fn errors_keep_code_message_and_verification_challenge() {
        let body = br#"{"Code":9001,"Error":"Human verification required",
            "Details":{"HumanVerificationToken":"abc","HumanVerificationMethods":["captcha","email"]}}"#;
        let Err(Failure::Api(error)) = parse_answer::<Value>(422, body) else {
            panic!("expected an API error");
        };
        assert_eq!(error.code, CODE_HUMAN_VERIFICATION);
        assert_eq!(error.message, "Human verification required");
        assert_eq!(
            error.human_verification(),
            Some(HumanVerification {
                token: "abc".into(),
                methods: vec!["captcha".into(), "email".into()],
            })
        );
    }

    #[test]
    fn a_success_status_with_an_error_code_is_an_error() {
        let Err(Failure::Api(error)) =
            parse_answer::<Value>(200, br#"{"Code":2001,"Error":"Invalid input"}"#)
        else {
            panic!("expected an API error");
        };
        assert_eq!(error.code, 2001);
        assert!(error.human_verification().is_none());
    }

    #[test]
    fn expired_sessions_ask_to_sign_in_again() {
        let failure = Failure::Api(ApiError {
            status: 401,
            code: 0,
            message: "Invalid access token".into(),
            details: Value::Null,
        });
        assert!(matches!(CoreError::from(failure), CoreError::NeedsReauth));
    }
}
