// Copyright (c) 2026 Dan Dressen
//
// This file is part of Flectar Mail and is licensed under AGPL-3.0-only.

//! Drives the real gRPC client against a mock Bridge server that speaks the
//! same TLS + server-token + event-stream protocol the Bridge core does, so
//! the sign-in choreography and the readout are exercised end to end.

use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Mutex as StdMutex;

use flectar_proton_bridge as fpb;
use fpb::pb::google::protobuf as pbwk;
use fpb::pb::grpc::bridge_server::{Bridge, BridgeServer};
use fpb::pb::grpc::{
    ImapSmtpSettings, LoginErrorEvent, LoginErrorType, LoginEvent, LoginFinishedEvent,
    LoginHvRequestedEvent, LoginTfaRequestedEvent, LoginTwoPasswordsRequestedEvent, StreamEvent,
    User, login_event, stream_event,
};
use fpb::{BridgeClient, LoginHandler, ServerConfig};
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::{TcpListenerStream, UnboundedReceiverStream};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

const TOKEN: &str = "test-token-123";
const TOTP: &str = "123456";

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Clone, Copy)]
enum Mode {
    Direct,
    Tfa,
    TwoPassword,
    FreeUser,
    Hv,
}

type EventTx = mpsc::UnboundedSender<Result<StreamEvent, Status>>;

struct Mock {
    mode: Mode,
    tx: StdMutex<Option<EventTx>>,
}

impl Mock {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            tx: StdMutex::new(None),
        }
    }

    fn emit(&self, event: login_event::Event) {
        let guard = self.tx.lock().unwrap();
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(Ok(StreamEvent {
                event: Some(stream_event::Event::Login(LoginEvent {
                    event: Some(event),
                })),
            }));
        }
    }
}

fn finished() -> login_event::Event {
    login_event::Event::Finished(LoginFinishedEvent {
        user_id: "u1".to_owned(),
        was_signed_out: false,
    })
}

#[tonic::async_trait]
impl Bridge for Mock {
    type RunEventStreamStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, Status>> + Send>>;

    async fn run_event_stream(
        &self,
        _request: Request<fpb::pb::grpc::EventStreamRequest>,
    ) -> Result<Response<Self::RunEventStreamStream>, Status> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.tx.lock().unwrap() = Some(tx);
        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(rx))))
    }

    async fn gui_ready(
        &self,
        _request: Request<pbwk::Empty>,
    ) -> Result<Response<fpb::pb::grpc::GuiReadyResponse>, Status> {
        Ok(Response::new(fpb::pb::grpc::GuiReadyResponse {
            show_splash_screen: false,
        }))
    }

    async fn login(
        &self,
        request: Request<fpb::pb::grpc::LoginRequest>,
    ) -> Result<Response<pbwk::Empty>, Status> {
        match self.mode {
            Mode::Direct => self.emit(finished()),
            Mode::Tfa => self.emit(login_event::Event::TfaRequested(LoginTfaRequestedEvent {
                username: String::new(),
            })),
            Mode::TwoPassword => self.emit(login_event::Event::TwoPasswordRequested(
                LoginTwoPasswordsRequestedEvent {
                    username: String::new(),
                },
            )),
            Mode::FreeUser => self.emit(login_event::Event::Error(LoginErrorEvent {
                r#type: LoginErrorType::FreeUser as i32,
                message: String::new(),
            })),
            Mode::Hv => {
                if request.get_ref().use_hv_details == Some(true) {
                    self.emit(finished());
                } else {
                    self.emit(login_event::Event::HvRequested(LoginHvRequestedEvent {
                        hv_url: "https://127.0.0.1/hv".to_owned(),
                    }));
                }
            }
        }
        Ok(Response::new(pbwk::Empty {}))
    }

    async fn login2_fa(
        &self,
        request: Request<fpb::pb::grpc::LoginRequest>,
    ) -> Result<Response<pbwk::Empty>, Status> {
        let code = String::from_utf8_lossy(&request.get_ref().password).into_owned();
        if code == TOTP {
            self.emit(finished());
        } else {
            self.emit(login_event::Event::Error(LoginErrorEvent {
                r#type: LoginErrorType::TfaError as i32,
                message: "wrong code".to_owned(),
            }));
        }
        Ok(Response::new(pbwk::Empty {}))
    }

    async fn login2_passwords(
        &self,
        _request: Request<fpb::pb::grpc::LoginRequest>,
    ) -> Result<Response<pbwk::Empty>, Status> {
        self.emit(finished());
        Ok(Response::new(pbwk::Empty {}))
    }

    async fn login_abort(
        &self,
        _request: Request<fpb::pb::grpc::LoginAbortRequest>,
    ) -> Result<Response<pbwk::Empty>, Status> {
        Ok(Response::new(pbwk::Empty {}))
    }

    async fn get_user(
        &self,
        _request: Request<pbwk::StringValue>,
    ) -> Result<Response<User>, Status> {
        Ok(Response::new(User {
            id: "u1".to_owned(),
            username: "dan@proton.me".to_owned(),
            avatar_text: String::new(),
            state: 0,
            split_mode: false,
            used_bytes: 0,
            total_bytes: 0,
            password: b"s3cr3t-bridge-pass".to_vec(),
            addresses: vec!["dan@proton.me".to_owned(), "dan@pm.me".to_owned()],
        }))
    }

    async fn mail_server_settings(
        &self,
        _request: Request<pbwk::Empty>,
    ) -> Result<Response<ImapSmtpSettings>, Status> {
        Ok(Response::new(ImapSmtpSettings {
            imap_port: 1143,
            smtp_port: 1025,
            use_ssl_for_imap: true,
            use_ssl_for_smtp: true,
        }))
    }

    async fn export_tls_certificates(
        &self,
        request: Request<pbwk::StringValue>,
    ) -> Result<Response<pbwk::Empty>, Status> {
        let dir = std::path::PathBuf::from(request.get_ref().value.clone());
        std::fs::create_dir_all(&dir).ok();
        std::fs::write(
            dir.join("cert.pem"),
            "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n",
        )
        .ok();
        Ok(Response::new(pbwk::Empty {}))
    }

    // Every other RPC the frontend contract declares; unused by the sign-in
    // path and left unimplemented for the mock.
    async fn check_tokens(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn add_log_entry(
        &self,
        _request: tonic::Request<fpb::pb::grpc::AddLogEntryRequest>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn quit(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn restart(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn show_on_startup(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_is_autostart_on(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::BoolValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_autostart_on(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_is_beta_enabled(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::BoolValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_beta_enabled(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_is_all_mail_visible(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::BoolValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_all_mail_visible(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_is_telemetry_disabled(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::BoolValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_telemetry_disabled(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn go_os(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn trigger_reset(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn version(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn logs_path(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn license_path(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn release_notes_page_link(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn dependency_licenses_link(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn landing_page_link(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_color_scheme_name(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn color_scheme_name(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn current_email_client(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn report_bug(
        &self,
        _request: tonic::Request<fpb::pb::grpc::ReportBugRequest>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn force_launcher(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_main_executable(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn request_knowledge_base_suggestions(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn login_fido(
        &self,
        _request: tonic::Request<fpb::pb::grpc::LoginRequest>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn fido_assertion_abort(
        &self,
        _request: tonic::Request<fpb::pb::grpc::LoginAbortRequest>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn check_update(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn install_update(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_is_automatic_update_on(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::BoolValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_automatic_update_on(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn disk_cache_path(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_disk_cache_path(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_is_do_h_enabled(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::BoolValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_do_h_enabled(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_mail_server_settings(
        &self,
        _request: tonic::Request<fpb::pb::grpc::ImapSmtpSettings>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn hostname(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_port_free(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Int32Value>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn available_keychains(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<
        tonic::Response<fpb::pb::grpc::AvailableKeychainsResponse>,
        tonic::Status,
    > {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_current_keychain(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn current_keychain(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::StringValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn get_user_list(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::grpc::UserListResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn set_user_split_mode(
        &self,
        _request: tonic::Request<fpb::pb::grpc::UserSplitModeRequest>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn send_bad_event_user_feedback(
        &self,
        _request: tonic::Request<fpb::pb::grpc::UserBadEventFeedbackRequest>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn logout_user(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn remove_user(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::StringValue>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn configure_user_apple_mail(
        &self,
        _request: tonic::Request<fpb::pb::grpc::ConfigureAppleMailRequest>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn is_tls_certificate_installed(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::BoolValue>, tonic::Status>
    {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn install_tls_certificate(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn stop_event_stream(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
    async fn trigger_repair(
        &self,
        _request: tonic::Request<fpb::pb::google::protobuf::Empty>,
    ) -> std::result::Result<tonic::Response<fpb::pb::google::protobuf::Empty>, tonic::Status> {
        Err(tonic::Status::unimplemented("mock"))
    }
}

// The interceptor signature (and the large `tonic::Status`) is fixed by tonic.
#[allow(clippy::result_large_err)]
fn check_token(request: Request<()>) -> Result<Request<()>, Status> {
    match request.metadata().get("server-token") {
        Some(value) if value == TOKEN => Ok(request),
        _ => Err(Status::unauthenticated("bad or missing server token")),
    }
}

/// Starts a mock Bridge over TLS on a loopback port and returns the port and
/// the server certificate (PEM), as the handshake file would carry them.
async fn start_mock(mode: Mode) -> (u16, String) {
    install_crypto();

    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();

    let identity = Identity::from_pem(cert_pem.clone(), key_pem);
    tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))
            .unwrap()
            .add_service(BridgeServer::with_interceptor(Mock::new(mode), check_token))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    (port, cert_pem)
}

async fn connect(mode: Mode) -> (BridgeClient, String) {
    let (port, cert) = start_mock(mode).await;
    let config = ServerConfig {
        port,
        cert: cert.clone(),
        token: TOKEN.to_owned(),
        file_socket_path: String::new(),
    };
    // Give the spawned server a moment to enter its accept loop.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let client = BridgeClient::connect(&config).await.expect("connect");
    (client, cert)
}

struct Handler {
    totp: Option<String>,
    mailbox: Option<String>,
    hv_ok: bool,
}

#[async_trait::async_trait]
impl LoginHandler for Handler {
    async fn two_factor_code(&self) -> Option<String> {
        self.totp.clone()
    }
    async fn mailbox_password(&self) -> Option<String> {
        self.mailbox.clone()
    }
    async fn human_verification(&self, _url: &str) -> bool {
        self.hv_ok
    }
}

fn no_prompts() -> Handler {
    Handler {
        totp: None,
        mailbox: None,
        hv_ok: false,
    }
}

#[tokio::test]
async fn direct_sign_in_reads_out_the_bridge_password_and_addresses() {
    let (mut client, _) = connect(Mode::Direct).await;
    let user = client
        .login("dan@proton.me", "pw", &no_prompts())
        .await
        .expect("login");
    assert_eq!(user.user_id, "u1");
    assert_eq!(user.bridge_password, "s3cr3t-bridge-pass");
    assert_eq!(user.addresses, vec!["dan@proton.me", "dan@pm.me"]);
}

#[tokio::test]
async fn two_factor_sign_in_sends_the_code() {
    let (mut client, _) = connect(Mode::Tfa).await;
    let handler = Handler {
        totp: Some(TOTP.to_owned()),
        ..no_prompts()
    };
    let user = client.login("dan@proton.me", "pw", &handler).await.unwrap();
    assert_eq!(user.user_id, "u1");
}

#[tokio::test]
async fn a_wrong_two_factor_code_is_an_error() {
    let (mut client, _) = connect(Mode::Tfa).await;
    let handler = Handler {
        totp: Some("000000".to_owned()),
        ..no_prompts()
    };
    let error = client
        .login("dan@proton.me", "pw", &handler)
        .await
        .unwrap_err();
    assert!(matches!(error, fpb::Error::Login(_)), "got {error:?}");
}

#[tokio::test]
async fn a_cancelled_two_factor_prompt_aborts() {
    let (mut client, _) = connect(Mode::Tfa).await;
    let error = client
        .login("dan@proton.me", "pw", &no_prompts())
        .await
        .unwrap_err();
    assert!(matches!(error, fpb::Error::Login(_)));
}

#[tokio::test]
async fn two_password_account_sends_the_mailbox_password() {
    let (mut client, _) = connect(Mode::TwoPassword).await;
    let handler = Handler {
        mailbox: Some("mbox-pw".to_owned()),
        ..no_prompts()
    };
    let user = client.login("dan@proton.me", "pw", &handler).await.unwrap();
    assert_eq!(user.user_id, "u1");
}

#[tokio::test]
async fn a_free_account_is_reported_clearly() {
    let (mut client, _) = connect(Mode::FreeUser).await;
    let error = client
        .login("free@proton.me", "pw", &no_prompts())
        .await
        .unwrap_err();
    assert!(matches!(error, fpb::Error::FreeAccount), "got {error:?}");
}

#[tokio::test]
async fn human_verification_retries_with_the_solved_challenge() {
    let (mut client, _) = connect(Mode::Hv).await;
    let handler = Handler {
        hv_ok: true,
        ..no_prompts()
    };
    let user = client.login("dan@proton.me", "pw", &handler).await.unwrap();
    assert_eq!(user.user_id, "u1");
}

#[tokio::test]
async fn reads_mail_server_settings_and_exports_the_certificate() {
    let (mut client, _) = connect(Mode::Direct).await;
    let settings = client.mail_server_settings().await.unwrap();
    assert_eq!(settings.imap_port, 1143);
    assert_eq!(settings.smtp_port, 1025);
    assert!(settings.imap_ssl && settings.smtp_ssl);

    let dir = std::env::temp_dir().join(format!("fpb-cert-{}", std::process::id()));
    let pem = client.export_tls_certificate(&dir).await.unwrap();
    assert!(pem.contains("BEGIN CERTIFICATE"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn a_bad_server_token_is_rejected() {
    let (port, cert) = start_mock(Mode::Direct).await;
    let config = ServerConfig {
        port,
        cert,
        token: "wrong".to_owned(),
        file_socket_path: String::new(),
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut client = BridgeClient::connect(&config).await.expect("connect");
    let error = client
        .login("dan@proton.me", "pw", &no_prompts())
        .await
        .unwrap_err();
    assert!(matches!(error, fpb::Error::Rpc(_)), "got {error:?}");
}
