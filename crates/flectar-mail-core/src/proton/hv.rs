//! Solving Proton's CAPTCHA in the user's browser.
//!
//! Proton's CAPTCHA page reports the solved token to the page that frames
//! it with a web message, and refuses to be framed by anyone but Proton. So
//! a server on the loopback address serves a small page that frames the
//! CAPTCHA from the same origin, and passes every other request through to
//! Proton without the headers that forbid framing. When the CAPTCHA reports
//! its token, the page hands it to the server and the sign-in continues.
//!
//! The server answers only requests for its own loopback address, takes one
//! token, and stops.

use crate::error::{CoreError, Result};
use crate::net::proxy::{Owner, SharedClient};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_UPSTREAM_BYTES: usize = 16 * 1024 * 1024;
/// How long the user has to solve the CAPTCHA.
pub const SOLVE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DONE_PATH: &str = "/__flectar/captcha-solved";

fn http_client(owner: Owner) -> Result<reqwest::Client> {
    static HTTP: SharedClient = SharedClient::new(|builder| {
        builder
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
    });
    HTTP.get(owner)
        .map_err(|error| CoreError::Network(format!("Proton HTTP client: {error}")))
}

/// A CAPTCHA waiting to be solved in the browser.
pub struct Captcha {
    /// The page to open in the browser.
    pub url: String,
    token: Option<oneshot::Receiver<String>>,
    server: tokio::task::JoinHandle<()>,
}

impl Captcha {
    /// Waits for the solved token, in the form Proton takes back as the
    /// `x-pm-human-verification-token` header with type `captcha`.
    pub async fn solved(mut self) -> Result<String> {
        let receiver = self.token.take().expect("a CAPTCHA is solved once");
        let result = tokio::time::timeout(SOLVE_TIMEOUT, receiver).await;
        self.server.abort();
        match result {
            Ok(Ok(token)) => Ok(token),
            Ok(Err(_)) => Err(CoreError::Auth("the CAPTCHA page closed".into())),
            Err(_) => Err(CoreError::Auth(
                "the CAPTCHA was not solved in time; sign in again to get a new one".into(),
            )),
        }
    }
}

impl Drop for Captcha {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Starts the loopback server for a challenge token from Proton.
pub async fn start(owner: Owner, api_base: &str, challenge: &str) -> Result<Captcha> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let host = format!("127.0.0.1:{port}");
    let (sender, receiver) = oneshot::channel();
    let state = std::sync::Arc::new(State {
        owner,
        host: host.clone(),
        api_base: api_base.trim_end_matches('/').to_owned(),
        challenge: challenge.to_owned(),
        sender: std::sync::Mutex::new(Some(sender)),
    });
    let server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(error) = serve(stream, &state).await {
                    tracing::debug!(%error, "Proton CAPTCHA request failed");
                }
            });
        }
    });
    Ok(Captcha {
        url: format!("http://{host}/"),
        token: Some(receiver),
        server,
    })
}

struct State {
    owner: Owner,
    host: String,
    api_base: String,
    challenge: String,
    sender: std::sync::Mutex<Option<oneshot::Sender<String>>>,
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut buffer = Vec::with_capacity(4096);
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(CoreError::Network("connection closed".into()));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return Err(CoreError::Network("request head too large".into()));
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let target = request_line.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err(CoreError::Network("request body too large".into()));
    }
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let mut chunk = vec![0u8; (length - body.len()).min(64 * 1024)];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Ok(Request {
        method,
        target,
        headers,
        body,
    })
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Status",
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    ));
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

fn html(body: &str) -> (Vec<(String, String)>, Vec<u8>) {
    (
        vec![(
            "Content-Type".to_owned(),
            "text/html; charset=utf-8".to_owned(),
        )],
        body.as_bytes().to_vec(),
    )
}

async fn serve(mut stream: TcpStream, state: &State) -> Result<()> {
    let request = read_request(&mut stream).await?;
    // Only this server's own address: a page elsewhere that points a name
    // at the loopback address gets nothing.
    if request.header("host") != Some(state.host.as_str()) {
        return respond(&mut stream, 403, &[], b"").await;
    }
    let path = request.target.split('?').next().unwrap_or_default();
    if request.method == "GET" && path == "/" {
        let (headers, body) = html(&wrapper_page(&state.challenge));
        return respond(&mut stream, 200, &headers, &body).await;
    }
    if path == DONE_PATH {
        let origin = format!("http://{}", state.host);
        if request.method != "POST" || request.header("origin") != Some(origin.as_str()) {
            return respond(&mut stream, 403, &[], b"").await;
        }
        let token = String::from_utf8_lossy(&request.body).trim().to_owned();
        if token.is_empty() || token.len() > 16 * 1024 || token.chars().any(char::is_control) {
            return respond(&mut stream, 400, &[], b"").await;
        }
        if let Some(sender) = state.sender.lock().expect("sender lock").take() {
            let _ = sender.send(token);
        }
        return respond(&mut stream, 204, &[], b"").await;
    }
    pass_through(&mut stream, state, &request).await
}

/// Passes a request on to Proton and its answer back, without the headers
/// that keep the CAPTCHA from being framed here.
async fn pass_through(stream: &mut TcpStream, state: &State, request: &Request) -> Result<()> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|_| CoreError::Network("bad method".into()))?;
    let url = format!("{}{}", state.api_base, request.target);
    let mut upstream = http_client(state.owner)?.request(method, &url);
    for name in ["content-type", "accept", "accept-language", "cookie"] {
        if let Some(value) = request.header(name) {
            upstream = upstream.header(name, value);
        }
    }
    upstream = upstream.header("x-pm-appversion", super::api::app_version());
    if !request.body.is_empty() {
        upstream = upstream.body(request.body.clone());
    }
    let response = match upstream.send().await {
        Ok(response) => response,
        Err(error) => {
            let (headers, body) = html(&format!("Proton could not be reached: {error}"));
            return respond(stream, 502, &headers, &body).await;
        }
    };
    let status = response.status().as_u16();
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        let name = name.as_str().to_ascii_lowercase();
        let Ok(value) = value.to_str() else { continue };
        match name.as_str() {
            "content-security-policy"
            | "content-security-policy-report-only"
            | "x-frame-options"
            | "strict-transport-security"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "alt-svc" => {}
            "set-cookie" => headers.push(("Set-Cookie".to_owned(), local_cookie(value))),
            _ => headers.push((name, value.to_owned())),
        }
    }
    let body = crate::http_body::bytes(response, MAX_UPSTREAM_BYTES, "Proton CAPTCHA").await?;
    respond(stream, status, &headers, &body).await
}

/// A cookie Proton set for its own domain, made to stick to the loopback
/// address over plain HTTP.
fn local_cookie(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|part| {
            let lower = part.to_ascii_lowercase();
            !(lower.starts_with("domain=") || lower == "secure" || lower.starts_with("samesite="))
        })
        .collect::<Vec<_>>()
        .join("; ")
        + "; SameSite=Lax"
}

fn wrapper_page(challenge: &str) -> String {
    let token =
        percent_encoding::utf8_percent_encode(challenge, percent_encoding::NON_ALPHANUMERIC);
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Flectar Mail – Proton sign-in check</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 0; display: flex; flex-direction: column;
        align-items: center; padding: 32px 16px; background: #f6f6f4; color: #1d1d1b; }}
 @media (prefers-color-scheme: dark) {{ body {{ background: #18191a; color: #e8e8e6; }} }}
 h1 {{ font-size: 20px; font-weight: 600; margin: 0 0 8px; }}
 p {{ margin: 0 0 24px; max-width: 440px; text-align: center; line-height: 1.45; }}
 iframe {{ border: 0; width: 100%; max-width: 440px; height: 520px; background: transparent; }}
 #done {{ display: none; }}
</style></head>
<body>
<h1>Confirm it's you</h1>
<p id="ask">Proton wants to make sure a person is signing in. Solve the puzzle below, then return to Flectar Mail.</p>
<p id="done">Done. You can close this tab and return to Flectar Mail.</p>
<iframe id="captcha" src="/core/v4/captcha?Token={token}&amp;ForceWebMessaging=1" title="Proton CAPTCHA"></iframe>
<script>
window.addEventListener("message", function (event) {{
  if (event.origin !== window.location.origin) return;
  var data = event.data;
  if (typeof data === "string") {{ try {{ data = JSON.parse(data); }} catch (e) {{ return; }} }}
  if (!data || typeof data !== "object") return;
  if (data.type === "pm_height" && typeof data.height === "number") {{
    document.getElementById("captcha").style.height = Math.max(200, data.height + 40) + "px";
    return;
  }}
  if ((data.type === "pm_captcha" || data.type === "proton_captcha") && typeof data.token === "string") {{
    fetch("{DONE_PATH}", {{ method: "POST", body: data.token }}).then(function () {{
      document.getElementById("captcha").remove();
      document.getElementById("ask").style.display = "none";
      document.getElementById("done").style.display = "block";
    }});
  }}
}});
</script>
</body></html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_lose_domain_secure_and_cross_site() {
        assert_eq!(
            local_cookie(
                "Session-Id=abc; Domain=proton.me; Path=/; Secure; HttpOnly; SameSite=None"
            ),
            "Session-Id=abc; Path=/; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn the_wrapper_frames_the_challenge_from_this_origin() {
        let page = wrapper_page("tok/en+1");
        assert!(
            page.contains("src=\"/core/v4/captcha?Token=tok%2Fen%2B1&amp;ForceWebMessaging=1\"")
        );
        assert!(page.contains(DONE_PATH));
    }

    async fn send(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        answer
    }

    #[tokio::test]
    async fn the_token_comes_back_only_from_this_origin() {
        let captcha = start(Owner::App, "http://127.0.0.1:9", "challenge")
            .await
            .unwrap();
        let port: u16 = captcha
            .url
            .trim_start_matches("http://127.0.0.1:")
            .trim_end_matches('/')
            .parse()
            .unwrap();
        let host = format!("127.0.0.1:{port}");

        let page = send(port, &format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains("Token=challenge"));

        let foreign = send(port, "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n").await;
        assert!(foreign.starts_with("HTTP/1.1 403"));

        let wrong_origin = send(
            port,
            &format!("POST {DONE_PATH} HTTP/1.1\r\nHost: {host}\r\nOrigin: http://evil.example\r\nContent-Length: 3\r\n\r\nabc"),
        )
        .await;
        assert!(wrong_origin.starts_with("HTTP/1.1 403"));

        let done = send(
            port,
            &format!("POST {DONE_PATH} HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nContent-Length: 9\r\n\r\nchal:solv"),
        )
        .await;
        assert!(done.starts_with("HTTP/1.1 204"));
        assert_eq!(captcha.solved().await.unwrap(), "chal:solv");
    }
}
