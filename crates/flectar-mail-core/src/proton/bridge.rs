// Copyright (c) 2026 Dan Dressen
//
// This file is part of Flectar Mail and is licensed under AGPL-3.0-only.

//! Signing in to Proton through a Bridge core that Flectar manages itself.
//!
//! Flectar bundles Proton's own Bridge core and starts it headless; this
//! module drives its gRPC frontend (see the `flectar-proton-bridge` crate) to
//! sign an account in, then creates an ordinary local IMAP/SMTP account that
//! points at the Bridge server on `127.0.0.1`. The sign-in is genuinely
//! Proton's Bridge authenticating, so no Proton app is impersonated.
//!
//! The same `Core::proton_sign_in*` methods the UI already calls are
//! implemented here; the direct-API sign-in is kept under `proton_direct_*`
//! for when Proton grants third-party clients an app identifier. Because the
//! UI is a step-by-step state machine (ask for a TOTP code, come back) and the
//! Bridge driver is callback-based, a background task runs the Bridge sign-in
//! and exchanges prompts and answers with the UI thread over channels.

use super::setup::ProtonSignIn;
use crate::error::{CoreError, Result};
use crate::models::{
    Account, AddPasswordAccountArgs, ConnectionSecurity, LoginMethod, MailConnectionSettings,
    MailProtocol,
};
use flectar_proton_bridge::{
    BridgeClient, BridgeCore, BridgeOptions, Error as BridgeError, LoggedInUser, LoginHandler,
    MailServerSettings,
};
use std::path::{Path, PathBuf};
use tokio::sync::{Mutex, mpsc};

/// The one running Bridge core and a client connected to it. There is a single
/// core for all Proton accounts; Bridge serves them all from it.
struct Running {
    #[allow(dead_code)] // Owned so the core process lives as long as the app.
    core: BridgeCore,
    client: BridgeClient,
}

static BRIDGE: Mutex<Option<Running>> = Mutex::const_new(None);
/// The sign-in under way; there is one at a time, as the UI enforces.
static SIGNIN: Mutex<Option<SignInState>> = Mutex::const_new(None);

/// What the background sign-in task asks the UI for, or hands back.
enum Prompt {
    Totp,
    MailboxPassword,
    HumanVerification(String),
    Ready(Box<Ready>),
    Failed(String),
}

/// The UI's answer to a [`Prompt`].
enum Answer {
    Totp(String),
    MailboxPassword(String),
    HumanVerificationDone,
    Cancel,
}

/// Everything needed to create the local account once sign-in succeeds.
struct Ready {
    user: LoggedInUser,
    settings: MailServerSettings,
    certificate: String,
}

/// The channels and task of the in-flight sign-in.
struct SignInState {
    prompts: mpsc::Receiver<Prompt>,
    answers: mpsc::Sender<Answer>,
    task: tokio::task::JoinHandle<()>,
}

fn nothing_pending() -> CoreError {
    CoreError::Auth("the Proton sign-in was cancelled or ran out; start it again".into())
}

/// A human-readable reason for a Bridge failure, used both by the background
/// task and when mapping errors on the calling side.
fn describe(error: &BridgeError) -> String {
    match error {
        BridgeError::FreeAccount => "This Proton account needs a paid plan — Proton Mail Bridge \
             is not available for free accounts."
            .to_owned(),
        other => format!("Proton Bridge: {other}"),
    }
}

fn core_err(error: BridgeError) -> CoreError {
    CoreError::Auth(describe(&error))
}

/// The sign-in engine. Abstracted so the flow can be tested without a real
/// Bridge core; the only production implementation is [`BridgeClient`].
#[async_trait::async_trait]
trait BridgeEngine: Send {
    async fn login(
        &mut self,
        email: &str,
        password: &str,
        handler: &dyn LoginHandler,
    ) -> std::result::Result<LoggedInUser, BridgeError>;
    async fn mail_server_settings(
        &mut self,
    ) -> std::result::Result<MailServerSettings, BridgeError>;
    async fn export_tls_certificate(
        &mut self,
        dir: &Path,
    ) -> std::result::Result<String, BridgeError>;
}

#[async_trait::async_trait]
impl BridgeEngine for BridgeClient {
    async fn login(
        &mut self,
        email: &str,
        password: &str,
        handler: &dyn LoginHandler,
    ) -> std::result::Result<LoggedInUser, BridgeError> {
        BridgeClient::login(self, email, password, handler).await
    }
    async fn mail_server_settings(
        &mut self,
    ) -> std::result::Result<MailServerSettings, BridgeError> {
        BridgeClient::mail_server_settings(self).await
    }
    async fn export_tls_certificate(
        &mut self,
        dir: &Path,
    ) -> std::result::Result<String, BridgeError> {
        BridgeClient::export_tls_certificate(self, dir).await
    }
}

/// Turns the UI's answers into the callbacks the Bridge driver expects, over
/// channels, so the login can run as one call in a background task while the
/// UI drives it step by step.
struct ChannelHandler {
    prompts: mpsc::Sender<Prompt>,
    answers: Mutex<mpsc::Receiver<Answer>>,
}

#[async_trait::async_trait]
impl LoginHandler for ChannelHandler {
    async fn two_factor_code(&self) -> Option<String> {
        self.prompts.send(Prompt::Totp).await.ok()?;
        match self.answers.lock().await.recv().await {
            Some(Answer::Totp(code)) => Some(code),
            _ => None,
        }
    }
    async fn mailbox_password(&self) -> Option<String> {
        self.prompts.send(Prompt::MailboxPassword).await.ok()?;
        match self.answers.lock().await.recv().await {
            Some(Answer::MailboxPassword(password)) => Some(password),
            _ => None,
        }
    }
    async fn human_verification(&self, url: &str) -> bool {
        if self
            .prompts
            .send(Prompt::HumanVerification(url.to_owned()))
            .await
            .is_err()
        {
            return false;
        }
        matches!(
            self.answers.lock().await.recv().await,
            Some(Answer::HumanVerificationDone)
        )
    }
}

/// Spawns the background sign-in task and returns the channels to drive it.
fn start_flow(
    mut engine: Box<dyn BridgeEngine>,
    email: String,
    password: String,
    cert_dir: PathBuf,
) -> SignInState {
    let (prompt_tx, prompt_rx) = mpsc::channel::<Prompt>(4);
    let (answer_tx, answer_rx) = mpsc::channel::<Answer>(4);
    let task = tokio::spawn(async move {
        let handler = ChannelHandler {
            prompts: prompt_tx.clone(),
            answers: Mutex::new(answer_rx),
        };
        let user = match engine.login(&email, &password, &handler).await {
            Ok(user) => user,
            Err(error) => {
                let _ = prompt_tx.send(Prompt::Failed(describe(&error))).await;
                return;
            }
        };
        let settings = match engine.mail_server_settings().await {
            Ok(settings) => settings,
            Err(error) => {
                let _ = prompt_tx.send(Prompt::Failed(describe(&error))).await;
                return;
            }
        };
        let certificate = match engine.export_tls_certificate(&cert_dir).await {
            Ok(certificate) => certificate,
            Err(error) => {
                let _ = prompt_tx.send(Prompt::Failed(describe(&error))).await;
                return;
            }
        };
        let _ = prompt_tx
            .send(Prompt::Ready(Box::new(Ready {
                user,
                settings,
                certificate,
            })))
            .await;
    });
    SignInState {
        prompts: prompt_rx,
        answers: answer_tx,
        task,
    }
}

/// Builds the local IMAP/SMTP account that connects to the Bridge server.
fn build_account_args(ready: &Ready) -> Result<AddPasswordAccountArgs> {
    let email = ready.user.addresses.first().cloned().ok_or_else(|| {
        CoreError::Auth("Proton Bridge returned no address for the account".into())
    })?;

    let incoming_security = if ready.settings.imap_ssl {
        ConnectionSecurity::Tls
    } else {
        ConnectionSecurity::Starttls
    };
    let smtp_security = if ready.settings.smtp_ssl {
        ConnectionSecurity::Tls
    } else {
        ConnectionSecurity::Starttls
    };
    let mut connection = MailConnectionSettings::new(incoming_security, smtp_security);
    // Bridge presents a self-signed certificate on the loopback servers; trust
    // exactly it, for this account only.
    connection.trusted_certificate_pem = ready.certificate.clone();
    connection.incoming_login = LoginMethod::Automatic;
    connection.smtp_login = LoginMethod::Automatic;

    Ok(AddPasswordAccountArgs {
        email: email.clone(),
        display_name: None,
        username: email,
        // The per-account password Bridge generated, never the Proton password.
        password: ready.user.bridge_password.clone(),
        mail_protocol: MailProtocol::Imap,
        jmap_url: String::new(),
        incoming_host: "127.0.0.1".to_owned(),
        incoming_port: ready.settings.imap_port,
        smtp_host: "127.0.0.1".to_owned(),
        smtp_port: ready.settings.smtp_port,
        smtp_password: None,
        connection,
    })
}

/// Starts the Bridge core if it is not already running and returns a client.
async fn ensure_client(binary: PathBuf, config_home: PathBuf) -> Result<BridgeClient> {
    let mut guard = BRIDGE.lock().await;
    if guard.is_none() {
        let core = BridgeCore::start(BridgeOptions::new(binary, config_home))
            .await
            .map_err(core_err)?;
        let client = BridgeClient::connect(core.server_config())
            .await
            .map_err(core_err)?;
        *guard = Some(Running { core, client });
    }
    Ok(guard.as_ref().expect("just set").client.clone())
}

impl crate::Core {
    /// Where the bundled Bridge core keeps its state, inside Flectar's data
    /// directory so it is isolated from any separately installed Bridge.
    fn proton_bridge_config_home(&self) -> PathBuf {
        self.paths.data_dir.join("proton-bridge")
    }

    /// Locates the bundled Bridge core binary: an explicit override first, then
    /// next to Flectar's own executable (where CI places it).
    fn proton_bridge_binary(&self) -> Result<PathBuf> {
        if let Ok(path) = std::env::var("FLECTAR_PROTON_BRIDGE_CORE") {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Ok(path);
            }
        }
        // Proton installs the launcher as `proton-bridge(.exe)`; it locates
        // and runs the core, forwarding the --grpc/--no-window/--parent-pid
        // flags to it.
        let name = if cfg!(windows) {
            "proton-bridge.exe"
        } else {
            "proton-bridge"
        };
        let exe = std::env::current_exe()
            .map_err(|error| CoreError::Auth(format!("could not locate Flectar: {error}")))?;
        if let Some(dir) = exe.parent() {
            for candidate in [dir.join("proton-bridge").join(name), dir.join(name)] {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
        Err(CoreError::Auth(
            "the bundled Proton Mail Bridge was not found next to Flectar".into(),
        ))
    }

    async fn ensure_bridge_client(&self) -> Result<BridgeClient> {
        let binary = self.proton_bridge_binary()?;
        let config_home = self.proton_bridge_config_home();
        ensure_client(binary, config_home).await
    }

    /// Records a Bridge-backed account so the core is started again at the next
    /// launch, before the account's IMAP worker tries to connect.
    fn remember_bridge_account(&self, email: &str) -> Result<()> {
        let home = self.proton_bridge_config_home();
        std::fs::create_dir_all(&home).map_err(|error| CoreError::Auth(error.to_string()))?;
        let marker = home.join("accounts.json");
        let mut list: Vec<String> = std::fs::read(&marker)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        if !list.iter().any(|known| known.eq_ignore_ascii_case(email)) {
            list.push(email.to_owned());
        }
        let bytes =
            serde_json::to_vec(&list).map_err(|error| CoreError::Auth(error.to_string()))?;
        std::fs::write(&marker, bytes).map_err(|error| CoreError::Auth(error.to_string()))?;
        Ok(())
    }

    /// Starts the Bridge core at launch when at least one Bridge-backed account
    /// exists, so its loopback IMAP/SMTP servers are up before sync begins.
    /// Best-effort: a failure here only delays that account's first sync.
    pub(crate) async fn proton_bridge_boot(&self) {
        let marker = self.proton_bridge_config_home().join("accounts.json");
        let any = std::fs::read(&marker)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<String>>(&bytes).ok())
            .is_some_and(|list| !list.is_empty());
        if !any {
            return;
        }
        if let Err(error) = self.ensure_bridge_client().await {
            tracing::warn!(%error, "could not start the Proton Bridge core at launch");
        }
    }

    /// Creates the local account from a finished sign-in.
    async fn create_bridge_account(&self, ready: Ready) -> Result<Account> {
        let args = build_account_args(&ready)?;
        let email = args.email.clone();
        let account = self.add_account_password(args).await?;
        self.remember_bridge_account(&email)?;
        Ok(account)
    }

    /// Sends the UI's answer to the background task (if any) and maps the next
    /// prompt. Terminal prompts clear the in-flight state.
    async fn bridge_pump(&self, answer: Option<Answer>) -> Result<Prompt> {
        let mut guard = SIGNIN.lock().await;
        let state = guard.as_mut().ok_or_else(nothing_pending)?;
        if let Some(answer) = answer {
            let _ = state.answers.send(answer).await;
        }
        let prompt = state.prompts.recv().await.unwrap_or_else(|| {
            Prompt::Failed("the Proton Bridge sign-in ended unexpectedly".to_owned())
        });
        if matches!(prompt, Prompt::Ready(_) | Prompt::Failed(_))
            && let Some(state) = guard.take()
        {
            state.task.abort();
        }
        Ok(prompt)
    }

    async fn map_prompt(&self, prompt: Prompt) -> Result<ProtonSignIn> {
        match prompt {
            Prompt::Totp => Ok(ProtonSignIn::Totp),
            Prompt::MailboxPassword => Ok(ProtonSignIn::MailboxPassword),
            Prompt::HumanVerification(url) => Ok(ProtonSignIn::Captcha { url }),
            Prompt::Ready(ready) => Ok(ProtonSignIn::Done(
                self.create_bridge_account(*ready).await?,
            )),
            Prompt::Failed(message) => Err(CoreError::Auth(message)),
        }
    }

    /// Starts signing in to Proton through the managed Bridge.
    pub async fn proton_sign_in(&self, username: &str, password: &str) -> Result<ProtonSignIn> {
        let username = username.trim().to_owned();
        if username.is_empty() || password.is_empty() {
            return Err(CoreError::Auth(
                "enter the Proton account's address and password".into(),
            ));
        }
        crate::accounts::credentials::check_available_async(self.credentials.clone()).await?;
        let client = self.ensure_bridge_client().await?;
        let cert_dir = self.proton_bridge_config_home().join("cert");

        let state = start_flow(Box::new(client), username, password.to_owned(), cert_dir);
        {
            let mut guard = SIGNIN.lock().await;
            if let Some(previous) = guard.replace(state) {
                previous.task.abort();
            }
        }

        let prompt = self.bridge_pump(None).await?;
        self.map_prompt(prompt).await
    }

    /// Goes on once the human-verification page has been completed.
    pub async fn proton_sign_in_verified(&self) -> Result<ProtonSignIn> {
        let prompt = self
            .bridge_pump(Some(Answer::HumanVerificationDone))
            .await?;
        self.map_prompt(prompt).await
    }

    /// Supplies the authenticator-app code.
    pub async fn proton_sign_in_totp(&self, code: &str) -> Result<ProtonSignIn> {
        let prompt = self
            .bridge_pump(Some(Answer::Totp(code.trim().to_owned())))
            .await?;
        self.map_prompt(prompt).await
    }

    /// Supplies the mailbox (second) password for a two-password account.
    pub async fn proton_sign_in_mailbox_password(&self, password: &str) -> Result<ProtonSignIn> {
        let prompt = self
            .bridge_pump(Some(Answer::MailboxPassword(password.to_owned())))
            .await?;
        self.map_prompt(prompt).await
    }

    /// Cancels an in-flight sign-in.
    pub async fn proton_sign_in_cancel(&self) {
        let mut guard = SIGNIN.lock().await;
        if let Some(state) = guard.take() {
            let _ = state.answers.send(Answer::Cancel).await;
            state.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeEngine {
        scenario: Scenario,
    }
    #[derive(Clone, Copy)]
    enum Scenario {
        Direct,
        Totp,
        TwoPassword,
        FreeAccount,
    }

    fn user() -> LoggedInUser {
        LoggedInUser {
            user_id: "u1".into(),
            addresses: vec!["dan@proton.me".into(), "dan@pm.me".into()],
            bridge_password: "bridge-pass".into(),
        }
    }

    #[async_trait::async_trait]
    impl BridgeEngine for FakeEngine {
        async fn login(
            &mut self,
            _email: &str,
            _password: &str,
            handler: &dyn LoginHandler,
        ) -> std::result::Result<LoggedInUser, BridgeError> {
            match self.scenario {
                Scenario::Direct => Ok(user()),
                Scenario::FreeAccount => Err(BridgeError::FreeAccount),
                Scenario::Totp => match handler.two_factor_code().await {
                    Some(code) if code == "123456" => Ok(user()),
                    Some(_) => Err(BridgeError::Login("bad code".into())),
                    None => Err(BridgeError::Login("cancelled".into())),
                },
                Scenario::TwoPassword => match handler.mailbox_password().await {
                    Some(_) => Ok(user()),
                    None => Err(BridgeError::Login("cancelled".into())),
                },
            }
        }
        async fn mail_server_settings(
            &mut self,
        ) -> std::result::Result<MailServerSettings, BridgeError> {
            Ok(MailServerSettings {
                imap_port: 1143,
                smtp_port: 1025,
                imap_ssl: false,
                smtp_ssl: false,
            })
        }
        async fn export_tls_certificate(
            &mut self,
            _dir: &Path,
        ) -> std::result::Result<String, BridgeError> {
            Ok("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n".into())
        }
    }

    async fn run(scenario: Scenario, answers: Vec<Answer>) -> Vec<&'static str> {
        let mut state = start_flow(
            Box::new(FakeEngine { scenario }),
            "dan@proton.me".into(),
            "pw".into(),
            std::env::temp_dir().join("fpb-flow"),
        );
        let mut seen = Vec::new();
        let mut answers = answers.into_iter();
        loop {
            let prompt = state.prompts.recv().await.expect("a prompt");
            match prompt {
                Prompt::Totp => {
                    seen.push("totp");
                    state.answers.send(answers.next().unwrap()).await.unwrap();
                }
                Prompt::MailboxPassword => {
                    seen.push("mailbox");
                    state.answers.send(answers.next().unwrap()).await.unwrap();
                }
                Prompt::HumanVerification(_) => {
                    seen.push("hv");
                    state.answers.send(answers.next().unwrap()).await.unwrap();
                }
                Prompt::Ready(ready) => {
                    seen.push("ready");
                    let args = build_account_args(&ready).unwrap();
                    assert_eq!(args.incoming_host, "127.0.0.1");
                    assert_eq!(args.incoming_port, 1143);
                    assert_eq!(args.smtp_port, 1025);
                    assert_eq!(args.password, "bridge-pass");
                    assert_eq!(args.email, "dan@proton.me");
                    assert_eq!(args.mail_protocol, MailProtocol::Imap);
                    assert!(
                        args.connection
                            .trusted_certificate_pem
                            .contains("CERTIFICATE")
                    );
                    assert_eq!(
                        args.connection.incoming_security,
                        ConnectionSecurity::Starttls
                    );
                    break;
                }
                Prompt::Failed(_) => {
                    seen.push("failed");
                    break;
                }
            }
        }
        seen
    }

    #[tokio::test]
    async fn direct_sign_in_goes_straight_to_ready() {
        assert_eq!(run(Scenario::Direct, vec![]).await, vec!["ready"]);
    }

    #[tokio::test]
    async fn totp_prompt_then_ready() {
        assert_eq!(
            run(Scenario::Totp, vec![Answer::Totp("123456".into())]).await,
            vec!["totp", "ready"]
        );
    }

    #[tokio::test]
    async fn wrong_totp_fails() {
        assert_eq!(
            run(Scenario::Totp, vec![Answer::Totp("000000".into())]).await,
            vec!["totp", "failed"]
        );
    }

    #[tokio::test]
    async fn two_password_prompt_then_ready() {
        assert_eq!(
            run(
                Scenario::TwoPassword,
                vec![Answer::MailboxPassword("m".into())]
            )
            .await,
            vec!["mailbox", "ready"]
        );
    }

    #[tokio::test]
    async fn free_account_fails() {
        assert_eq!(run(Scenario::FreeAccount, vec![]).await, vec!["failed"]);
    }

    #[test]
    fn account_args_map_tls_from_settings() {
        let ready = Ready {
            user: user(),
            settings: MailServerSettings {
                imap_port: 1143,
                smtp_port: 1025,
                imap_ssl: true,
                smtp_ssl: true,
            },
            certificate: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n".into(),
        };
        let args = build_account_args(&ready).unwrap();
        assert_eq!(args.connection.incoming_security, ConnectionSecurity::Tls);
        assert_eq!(args.connection.smtp_security, ConnectionSecurity::Tls);
    }
}
