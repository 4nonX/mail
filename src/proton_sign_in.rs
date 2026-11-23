//! The Proton sign-in of the account forms. After the password, Proton may
//! ask for a CAPTCHA solved in the browser, a code from an authenticator
//! app, and the mailbox password of an account with two; each answer comes
//! back here until the account is connected.
use super::*;
use flectar_mail_core::proton::setup::ProtonSignIn as Step;

// The page of the CAPTCHA under way, to open again when asked.
thread_local! {
    static CAPTCHA_URL: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[derive(Clone)]
pub(super) struct ProtonSetup {
    app: slint::Weak<AppWindow>,
    runtime: tokio::runtime::Handle,
    updates: UiSender<UiTaskUpdate>,
    opener: ExternalUrlOpener,
}

/// What the user gave for the step the sign-in is at.
enum Answer {
    Password {
        username: String,
        password: String,
    },
    /// The CAPTCHA page is open; its answer comes from the browser.
    Verified,
    Totp(String),
    MailboxPassword(String),
}

impl ProtonSetup {
    pub(super) fn register(
        app: &AppWindow,
        state: &Rc<RefCell<InboxState>>,
        runtime: &tokio::runtime::Handle,
        updates: &UiSender<UiTaskUpdate>,
        opener: ExternalUrlOpener,
    ) -> Self {
        let setup = Self {
            app: app.as_weak(),
            runtime: runtime.clone(),
            updates: updates.clone(),
            opener,
        };
        let ui = app.global::<ProtonSignIn>();
        ui.on_answer({
            let setup = setup.clone();
            let state = Rc::clone(state);
            move |value| {
                let Some(app) = setup.app.upgrade() else {
                    return;
                };
                let Some(core) = state.borrow().core.clone() else {
                    return;
                };
                let ui = app.global::<ProtonSignIn>();
                let answer = match ui.get_step().as_str() {
                    "totp" => Answer::Totp(value.to_string()),
                    "mailbox" => Answer::MailboxPassword(value.to_string()),
                    _ => return,
                };
                setup.go(&app, core, answer);
            }
        });
        ui.on_cancel({
            let setup = setup.clone();
            let state = Rc::clone(state);
            move || {
                let Some(app) = setup.app.upgrade() else {
                    return;
                };
                let ui = app.global::<ProtonSignIn>();
                if ui.get_step().is_empty() {
                    return;
                }
                ui.set_step("".into());
                ui.set_busy(false);
                CAPTCHA_URL.with(|url| url.borrow_mut().take());
                app.set_account_setup_in_progress(false);
                app.set_sync_status(UiMessage::plain("The Proton sign-in was cancelled."));
                if let Some(core) = state.borrow().core.clone() {
                    setup.runtime.spawn(async move {
                        core.proton_sign_in_cancel().await;
                    });
                }
            }
        });
        ui.on_open_captcha({
            let setup = setup.clone();
            move || {
                if let Some(url) = CAPTCHA_URL.with(|url| url.borrow().clone()) {
                    setup.open(url);
                }
            }
        });
        setup
    }

    /// Starts the sign-in with the form's address and password.
    pub(super) fn start(
        &self,
        app: &AppWindow,
        core: mail::CoreMailSource,
        username: String,
        password: String,
    ) {
        app.set_account_setup_in_progress(true);
        app.set_sync_status(UiMessage::plain("Signing in to Proton…"));
        self.go(app, core, Answer::Password { username, password });
    }

    fn open(&self, url: String) {
        let opener = self.opener.clone();
        let app = self.app.clone();
        std::thread::spawn(move || {
            if opener.open_external(&url).is_err() {
                let _ = app.upgrade_in_event_loop(move |app| {
                    app.set_sync_status(UiMessage::detail(
                        "The browser did not open. Open this address in it to go on: {}",
                        url,
                    ));
                });
            }
        });
    }

    fn go(&self, app: &AppWindow, core: mail::CoreMailSource, answer: Answer) {
        app.global::<ProtonSignIn>().set_busy(true);
        let setup = self.clone();
        self.runtime.spawn(async move {
            let step = match answer {
                Answer::Password { username, password } => {
                    core.proton_sign_in(&username, &password).await
                }
                Answer::Verified => core.proton_sign_in_verified().await,
                Answer::Totp(code) => core.proton_sign_in_totp(&code).await,
                Answer::MailboxPassword(password) => {
                    core.proton_sign_in_mailbox_password(&password).await
                }
            };
            match step {
                Ok(Step::Done(account)) => {
                    let accounts = core.load_account_snapshot().await.ok();
                    setup.show("", None);
                    let _ = setup
                        .updates
                        .send(UiTaskUpdate {
                            message: UiMessage::detail(
                                "Connected {}. Initial sync is running in the background.",
                                account.email,
                            ),
                            accounts,
                            calendar_connections: None,
                            carddav_connections: None,
                            calendar_error: None,
                            account_removal: None,
                            clear_account_form: true,
                            finishes_account_setup: true,
                            finishes_oauth: false,
                            close_to_tray: None,
                        })
                        .await;
                }
                Ok(Step::Captcha { url }) => {
                    setup.open(url.clone());
                    setup.show("captcha", Some(url));
                    // The browser hands the answer over; nothing is typed here.
                    let waiting = setup.clone();
                    let _ = setup.app.upgrade_in_event_loop(move |app| {
                        app.set_sync_status(UiMessage::plain(
                            "Solve Proton's CAPTCHA in your browser to go on.",
                        ));
                        waiting.go(&app, core, Answer::Verified);
                    });
                }
                Ok(Step::Totp) => {
                    setup.show("totp", None);
                    setup.say(UiMessage::plain(
                        "Enter the code from your authenticator app.",
                    ));
                }
                Ok(Step::MailboxPassword) => {
                    setup.show("mailbox", None);
                    setup.say(UiMessage::plain(
                        "Enter this Proton account's mailbox password.",
                    ));
                }
                Err(error) => {
                    // A wrong code or mailbox password is asked for again;
                    // anything else ends the sign-in.
                    let retry = setup.app.clone();
                    let message = error.to_string();
                    let _ = retry.upgrade_in_event_loop(move |app| {
                        let ui = app.global::<ProtonSignIn>();
                        // Given up meanwhile: that was said already.
                        if ui.get_step().is_empty() && !app.get_account_setup_in_progress() {
                            return;
                        }
                        ui.set_busy(false);
                        let typed = matches!(ui.get_step().as_str(), "totp" | "mailbox");
                        let again = typed
                            && matches!(error, flectar_mail_core::error::CoreError::Auth(_))
                            && !message.contains("start it again");
                        if !again {
                            ui.set_step("".into());
                            CAPTCHA_URL.with(|url| url.borrow_mut().take());
                            app.set_account_setup_in_progress(false);
                        }
                        app.set_sync_status(UiMessage::detail("Account setup failed: {}", message));
                    });
                }
            }
        });
    }

    fn show(&self, step: &'static str, captcha: Option<String>) {
        let _ = self.app.upgrade_in_event_loop(move |app| {
            CAPTCHA_URL.with(|url| *url.borrow_mut() = captcha);
            let ui = app.global::<ProtonSignIn>();
            ui.set_step(step.into());
            ui.set_busy(false);
        });
    }

    fn say(&self, message: UiMessage) {
        let _ = self.app.upgrade_in_event_loop(move |app| {
            app.set_sync_status(message);
        });
    }
}
