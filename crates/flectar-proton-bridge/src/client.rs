// Copyright (c) 2026 Dan Dressen
//
// This file is part of Flectar Mail and is licensed under AGPL-3.0-only.

//! The gRPC client: connecting to the core, the sign-in state machine, and
//! reading out the local connection details.

use crate::pb::google::protobuf::{Empty, StringValue};
use crate::pb::grpc::bridge_client::BridgeClient as GenClient;
use crate::pb::grpc::{
    EventStreamRequest, ImapSmtpSettings, LoginAbortRequest, LoginErrorEvent, LoginErrorType,
    LoginRequest, login_event, stream_event,
};
use crate::{Error, Result};
use std::path::Path;
use std::sync::Once;
use std::time::{Duration, Instant};
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

/// The client platform name Flectar reports to the event stream.
const CLIENT_PLATFORM: &str = "flectar";

/// Installs a rustls crypto provider once per process, so a standalone use of
/// this crate (and its tests) has one even if the host app has not set it.
fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Adds the server token to every gRPC call, as the core's interceptor demands.
#[derive(Clone)]
struct AuthInterceptor {
    token: MetadataValue<tonic::metadata::Ascii>,
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("server-token", self.token.clone());
        Ok(request)
    }
}

type Inner = GenClient<InterceptedService<Channel, AuthInterceptor>>;

/// What Flectar needs after a successful Bridge sign-in.
#[derive(Clone, Debug)]
pub struct LoggedInUser {
    /// Bridge's internal id for the account.
    pub user_id: String,
    /// The account's email addresses, the primary first.
    pub addresses: Vec<String>,
    /// The per-account password Bridge generated for the local IMAP/SMTP
    /// servers. This is what Flectar stores and uses, never the Proton
    /// password.
    pub bridge_password: String,
}

/// The local IMAP/SMTP endpoints Bridge serves.
#[derive(Clone, Copy, Debug)]
pub struct MailServerSettings {
    pub imap_port: u16,
    pub smtp_port: u16,
    pub imap_ssl: bool,
    pub smtp_ssl: bool,
}

/// Supplies the extra factors Bridge asks for during sign-in. Returning `None`
/// (or `false` for human verification) cancels the sign-in.
#[async_trait::async_trait]
pub trait LoginHandler: Send + Sync {
    /// The current authenticator-app code, or `None` to cancel.
    async fn two_factor_code(&self) -> Option<String>;
    /// The mailbox (second) password for two-password accounts, or `None` to
    /// cancel.
    async fn mailbox_password(&self) -> Option<String>;
    /// Opens `url` for the person to complete human verification, returning
    /// `true` once done or `false` to cancel. Bridge captures the solved token
    /// itself at that URL; sign-in then retries automatically.
    async fn human_verification(&self, url: &str) -> bool;
}

/// A connected Bridge gRPC client.
#[derive(Clone)]
pub struct BridgeClient {
    inner: Inner,
}

impl BridgeClient {
    /// Connects to the core over TLS, trusting its self-signed certificate and
    /// presenting the server token.
    pub async fn connect(config: &crate::ServerConfig) -> Result<Self> {
        install_crypto_provider();

        if !config.is_tcp() {
            return Err(Error::Connect(
                "the Bridge core is using a file socket; Flectar's managed Bridge runs the core \
                 over loopback TCP (its Windows mode)"
                    .to_owned(),
            ));
        }

        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(config.cert.clone()))
            .domain_name("127.0.0.1");

        let endpoint = Endpoint::from_shared(format!("https://127.0.0.1:{}", config.port))
            .map_err(|error| Error::Connect(error.to_string()))?
            .tls_config(tls)
            .map_err(|error| Error::Connect(error.to_string()))?
            .connect_timeout(Duration::from_secs(15));

        let channel = endpoint
            .connect()
            .await
            .map_err(|error| Error::Connect(error.to_string()))?;

        let token = MetadataValue::try_from(config.token.as_str())
            .map_err(|_| Error::Connect("the server token is not valid metadata".to_owned()))?;

        Ok(Self {
            inner: GenClient::with_interceptor(channel, AuthInterceptor { token }),
        })
    }

    /// Drives Bridge's sign-in for `email`/`password`, using `handler` for any
    /// second factor, mailbox password or human verification Bridge asks for.
    pub async fn login(
        &mut self,
        email: &str,
        password: &str,
        handler: &dyn LoginHandler,
    ) -> Result<LoggedInUser> {
        // Open the event stream before asking the core to do anything, so no
        // login event can be missed, then announce the frontend is ready.
        let mut events = self
            .inner
            .clone()
            .run_event_stream(EventStreamRequest {
                client_platform: CLIENT_PLATFORM.to_owned(),
            })
            .await?
            .into_inner();

        self.inner.gui_ready(Empty {}).await?;
        self.inner
            .login(LoginRequest {
                username: email.to_owned(),
                password: password.as_bytes().to_vec(),
                use_hv_details: None,
            })
            .await?;

        let user_id = loop {
            let Some(event) = events.message().await? else {
                return Err(Error::StreamClosed);
            };
            let Some(stream_event::Event::Login(login)) = event.event else {
                continue;
            };

            use login_event::Event as Ev;
            match login.event {
                Some(Ev::TfaRequested(_)) => match handler.two_factor_code().await {
                    Some(code) => {
                        self.inner
                            .login2_fa(LoginRequest {
                                username: email.to_owned(),
                                password: code.into_bytes(),
                                use_hv_details: None,
                            })
                            .await?;
                    }
                    None => return self.abort(email, "two-factor code").await,
                },
                Some(Ev::TwoPasswordRequested(_)) => match handler.mailbox_password().await {
                    Some(mailbox) => {
                        self.inner
                            .login2_passwords(LoginRequest {
                                username: email.to_owned(),
                                password: mailbox.into_bytes(),
                                use_hv_details: None,
                            })
                            .await?;
                    }
                    None => return self.abort(email, "mailbox password").await,
                },
                Some(Ev::HvRequested(hv)) => {
                    if handler.human_verification(&hv.hv_url).await {
                        self.inner
                            .login(LoginRequest {
                                username: email.to_owned(),
                                password: password.as_bytes().to_vec(),
                                use_hv_details: Some(true),
                            })
                            .await?;
                    } else {
                        return self.abort(email, "human verification").await;
                    }
                }
                Some(Ev::Finished(finished)) | Some(Ev::AlreadyLoggedIn(finished)) => {
                    break finished.user_id;
                }
                Some(Ev::Error(error)) => return Err(map_login_error(error)),
                Some(Ev::FidoRequested(_))
                | Some(Ev::TfaOrFidoRequested(_))
                | Some(Ev::LoginFidoPinRequired(_)) => {
                    return Err(Error::Login(
                        "this account uses a security key for two-factor sign-in, which is not \
                         supported here; use an authenticator-app code instead"
                            .to_owned(),
                    ));
                }
                Some(Ev::LoginFidoTouchRequested(_)) | Some(Ev::LoginFidoTouchCompleted(_)) => {}
                None => {}
            }
        };

        let user = self
            .inner
            .get_user(StringValue {
                value: user_id.clone(),
            })
            .await?
            .into_inner();

        Ok(LoggedInUser {
            user_id,
            addresses: user.addresses,
            bridge_password: String::from_utf8_lossy(&user.password).into_owned(),
        })
    }

    /// The local IMAP/SMTP ports Bridge serves.
    pub async fn mail_server_settings(&mut self) -> Result<MailServerSettings> {
        let settings: ImapSmtpSettings = self
            .inner
            .mail_server_settings(Empty {})
            .await?
            .into_inner();
        Ok(MailServerSettings {
            imap_port: settings.imap_port.clamp(0, u16::MAX as i32) as u16,
            smtp_port: settings.smtp_port.clamp(0, u16::MAX as i32) as u16,
            imap_ssl: settings.use_ssl_for_imap,
            smtp_ssl: settings.use_ssl_for_smtp,
        })
    }

    /// Asks Bridge to export its TLS certificate into `dir` and returns the
    /// certificate as PEM, for Flectar to trust on the local account.
    pub async fn export_tls_certificate(&mut self, dir: &Path) -> Result<String> {
        std::fs::create_dir_all(dir).map_err(|error| Error::Certificate(error.to_string()))?;
        self.inner
            .export_tls_certificates(StringValue {
                value: dir.to_string_lossy().into_owned(),
            })
            .await?;

        // The export runs asynchronously on the core side and reports failure
        // as an event, so the call returning does not mean the file is there
        // yet. Wait briefly for it to appear.
        let cert_path = dir.join("cert.pem");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(pem) = std::fs::read_to_string(&cert_path)
                && pem.contains("BEGIN CERTIFICATE")
            {
                return Ok(pem);
            }
            if Instant::now() >= deadline {
                return Err(Error::Certificate(
                    "the core did not write cert.pem in time".to_owned(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Aborts an in-progress sign-in and returns a cancellation error.
    async fn abort(&mut self, email: &str, missing: &str) -> Result<LoggedInUser> {
        let _ = self
            .inner
            .login_abort(LoginAbortRequest {
                username: email.to_owned(),
            })
            .await;
        Err(Error::Login(format!("sign-in cancelled at the {missing}")))
    }
}

/// Turns Bridge's login error event into our error, singling out the
/// free-account case so the UI can show a clear message.
fn map_login_error(error: LoginErrorEvent) -> Error {
    if error.r#type == LoginErrorType::FreeUser as i32 {
        return Error::FreeAccount;
    }
    if error.message.is_empty() {
        let kind =
            LoginErrorType::try_from(error.r#type).unwrap_or(LoginErrorType::UsernamePasswordError);
        Error::Login(format!("{kind:?}"))
    } else {
        Error::Login(error.message)
    }
}
