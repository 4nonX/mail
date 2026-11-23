//! Signing in to a Proton account, for a new account and for one that has
//! to sign in again.
//!
//! The password proves the sign-in to Proton without being sent (SRP) and
//! derives the passphrase of the account's keys. Proton may first want a
//! CAPTCHA solved, then a code from an authenticator app, then the mailbox
//! password of an account that has two. What is kept afterwards is the
//! session and the key passphrase, never a password.

use super::api::{HumanVerificationAnswer, Session};
use super::auth::{self, SignedIn, Step};
use super::hv::{self, Captcha};
use super::stored::{self, StoredSession};
use super::sync::Link;
use super::{api, keys};
use crate::db::repo;
use crate::error::{CoreError, Result};
use crate::models::{
    Account, AccountSettings, AuthKind, ConnectionSecurity, MailConnectionSettings, MailProtocol,
    Provider,
};
use crate::net::proxy::Owner;
use tokio::sync::Mutex;

/// What a Proton sign-in needs next.
#[derive(Debug)]
pub enum ProtonSignIn {
    /// Proton wants a CAPTCHA solved at this address, in the browser. Call
    /// [`crate::Core::proton_sign_in_verified`] once it is open.
    Captcha { url: String },
    /// The code from the authenticator app.
    Totp,
    /// The mailbox password of an account with two passwords.
    MailboxPassword,
    /// Signed in: the account, new or signed in again.
    Done(Account),
}

/// The sign-in under way. There is one at a time.
struct Pending {
    /// Tells this sign-in from one started after it.
    id: u64,
    session: Session,
    username: String,
    password: String,
    captcha: Option<Captcha>,
    signed_in: Option<SignedIn>,
}

static PENDING: Mutex<Option<Pending>> = Mutex::const_new(None);
/// Ends the wait for a CAPTCHA when the sign-in is given up.
static CANCELLED: tokio::sync::Notify = tokio::sync::Notify::const_new();

fn nothing_pending() -> CoreError {
    CoreError::Auth("the Proton sign-in was cancelled or ran out; start it again".into())
}

fn security_key_only() -> CoreError {
    CoreError::Auth(
        "This Proton account signs in with a security key only, which Flectar Mail can't use. Add an authenticator app in Proton's security settings, then sign in again."
            .into(),
    )
}

impl crate::Core {
    /// Starts signing in to Proton with the account's name or address and
    /// its password.
    pub async fn proton_sign_in(&self, username: &str, password: &str) -> Result<ProtonSignIn> {
        let username = username.trim().to_owned();
        if username.is_empty() || password.is_empty() {
            return Err(CoreError::Auth(
                "enter the Proton account's address and password".into(),
            ));
        }
        crate::accounts::credentials::check_available_async(self.credentials.clone()).await?;
        let mut pending = PENDING.lock().await;
        if let Some(previous) = pending.take() {
            auth::sign_out(&previous.session).await;
        }
        let session = Session::new(Owner::App, None);
        let step = auth::password(&session, &username, password, None).await?;
        let mut next = Pending {
            id: rand::random(),
            session,
            username,
            password: password.to_owned(),
            captcha: None,
            signed_in: None,
        };
        let step = self.after_password(&mut next, step).await;
        self.keep(&mut pending, next, step).await
    }

    /// Goes on once the CAPTCHA page is open: waits until it is solved and
    /// signs in with its answer.
    pub async fn proton_sign_in_verified(&self) -> Result<ProtonSignIn> {
        // The wait can take minutes, so nothing is held meanwhile that
        // giving the sign-in up needs.
        let (id, captcha) = PENDING
            .lock()
            .await
            .as_mut()
            .and_then(|current| Some((current.id, current.captcha.take()?)))
            .ok_or_else(nothing_pending)?;
        let solved = tokio::select! {
            solved = captcha.solved() => solved,
            _ = CANCELLED.notified() => Err(nothing_pending()),
        };
        let mut pending = PENDING.lock().await;
        // Another sign-in may have begun while this one waited.
        if pending.as_ref().map(|current| current.id) != Some(id) {
            return Err(nothing_pending());
        }
        let current = pending.take().ok_or_else(nothing_pending)?;
        let token = match solved {
            Ok(token) => token,
            Err(error) => {
                auth::sign_out(&current.session).await;
                return Err(error);
            }
        };
        let mut current = current;
        let answer = HumanVerificationAnswer {
            token,
            kind: "captcha".into(),
        };
        let step = match auth::password(
            &current.session,
            &current.username,
            &current.password,
            Some(&answer),
        )
        .await
        {
            Ok(step) => self.after_password(&mut current, step).await,
            Err(failure) => Err(failure.into()),
        };
        self.keep(&mut pending, current, step).await
    }

    /// Gives the code from the authenticator app.
    pub async fn proton_sign_in_totp(&self, code: &str) -> Result<ProtonSignIn> {
        let mut pending = PENDING.lock().await;
        let mut current = pending.take().ok_or_else(nothing_pending)?;
        let needs_mailbox_password = current
            .signed_in
            .as_ref()
            .ok_or_else(nothing_pending)?
            .needs_mailbox_password;
        if let Err(failure) = auth::totp(&current.session, code).await {
            // A wrong code can be typed again while Proton allows it.
            let error = CoreError::from(failure);
            *pending = Some(current);
            return Err(match error {
                CoreError::Other(message) | CoreError::Network(message) => CoreError::Auth(message),
                other => other,
            });
        }
        let step = if needs_mailbox_password {
            Ok(ProtonSignIn::MailboxPassword)
        } else {
            let password = current.password.clone();
            self.finish(&mut current, &password).await
        };
        self.keep(&mut pending, current, step).await
    }

    /// Gives the mailbox password of an account with two passwords.
    pub async fn proton_sign_in_mailbox_password(&self, password: &str) -> Result<ProtonSignIn> {
        let mut pending = PENDING.lock().await;
        let mut current = pending.take().ok_or_else(nothing_pending)?;
        match self.finish(&mut current, password).await {
            // A wrong mailbox password can be typed again.
            Err(error @ CoreError::Auth(_)) => {
                *pending = Some(current);
                Err(error)
            }
            step => self.keep(&mut pending, current, step).await,
        }
    }

    /// Gives up the sign-in under way, and ends its session on Proton.
    pub async fn proton_sign_in_cancel(&self) {
        CANCELLED.notify_waiters();
        if let Some(previous) = PENDING.lock().await.take() {
            auth::sign_out(&previous.session).await;
        }
    }

    /// Keeps the sign-in for its next step, or ends it when it is done or
    /// failed.
    async fn keep(
        &self,
        pending: &mut Option<Pending>,
        current: Pending,
        step: Result<ProtonSignIn>,
    ) -> Result<ProtonSignIn> {
        match &step {
            Ok(ProtonSignIn::Done(_)) => {}
            Ok(_) => *pending = Some(current),
            Err(_) => auth::sign_out(&current.session).await,
        }
        step
    }

    async fn after_password(&self, current: &mut Pending, step: Step) -> Result<ProtonSignIn> {
        match step {
            Step::HumanVerification(challenge) => {
                if !challenge.methods.iter().any(|method| method == "captcha") {
                    return Err(CoreError::Auth(
                        "Proton wants this sign-in verified in a way Flectar Mail can't do. Sign in at account.proton.me once, then try again."
                            .into(),
                    ));
                }
                let captcha =
                    hv::start(Owner::App, current.session.base(), &challenge.token).await?;
                let url = captcha.url.clone();
                current.captcha = Some(captcha);
                Ok(ProtonSignIn::Captcha { url })
            }
            Step::SignedIn(signed_in) => {
                if signed_in.security_key_only {
                    return Err(security_key_only());
                }
                let (needs_totp, needs_mailbox_password) =
                    (signed_in.needs_totp, signed_in.needs_mailbox_password);
                current.signed_in = Some(signed_in);
                if needs_totp {
                    Ok(ProtonSignIn::Totp)
                } else if needs_mailbox_password {
                    Ok(ProtonSignIn::MailboxPassword)
                } else {
                    let password = current.password.clone();
                    self.finish(current, &password).await
                }
            }
        }
    }

    /// Unlocks the keys with `key_password`, stores the session, and adds
    /// the account or signs the existing one in again.
    async fn finish(&self, current: &mut Pending, key_password: &str) -> Result<ProtonSignIn> {
        let passphrase = auth::key_passphrase(&current.session, key_password).await?;
        let tokens = current
            .session
            .tokens()
            .await
            .ok_or(CoreError::NeedsReauth)?;
        let addresses = keys::fetch_addresses(&current.session).await?;
        let primary = addresses
            .iter()
            .filter(|address| address.status == 1)
            .min_by_key(|address| address.order)
            .ok_or_else(|| CoreError::Auth("the Proton account has no mail address".into()))?;
        let email = primary.email.clone();
        let display_name = (!primary.display_name.is_empty()).then(|| primary.display_name.clone());
        let stored = StoredSession::new(tokens, passphrase);

        let existing = self
            .db
            .read({
                let email = email.clone();
                move |conn| repo::accounts::find_by_mailbox(conn, &email)
            })
            .await?;
        let ctx = self.sync_ctx();
        let account_id = match existing {
            Some(existing) if existing.mail_protocol == MailProtocol::Proton => {
                // Signing in again: the worker stops before the session it
                // uses is replaced.
                if let Some(handle) = self.handles.write().await.remove(&existing.id) {
                    handle.abort();
                }
                stored::store(self.credentials.clone(), existing.id, &stored).await?;
                Link::for_account(&ctx, existing.id).reset().await;
                let id = existing.id;
                self.db
                    .write(move |conn| repo::accounts::set_sync_state(conn, id, "idle"))
                    .await?;
                id
            }
            Some(existing) => {
                return Err(CoreError::Auth(format!(
                    "{} is already here as another kind of account; remove that one first",
                    existing.email
                )));
            }
            None => {
                let id = self
                    .db
                    .write({
                        let email = email.clone();
                        let display_name = display_name.clone();
                        move |conn| {
                            repo::accounts::insert_with_sync_state(
                                conn,
                                &repo::accounts::NewAccount {
                                    email: &email,
                                    display_name: display_name.as_deref(),
                                    avatar_url: None,
                                    provider: Provider::Generic,
                                    auth_kind: AuthKind::Password,
                                    mail_protocol: MailProtocol::Proton,
                                    username: &email,
                                    jmap_url: "",
                                    jmap_account_id: None,
                                    incoming_host: api::API_HOST,
                                    incoming_port: 443,
                                    smtp_host: "",
                                    smtp_port: 0,
                                },
                                // Proton is only ever reached over TLS.
                                &AccountSettings::new(MailConnectionSettings::new(
                                    ConnectionSecurity::Tls,
                                    ConnectionSecurity::Tls,
                                )),
                                repo::accounts::CREDENTIAL_SETUP_STATE,
                            )
                        }
                    })
                    .await?;
                if let Err(error) = stored::store(self.credentials.clone(), id, &stored).await {
                    self.rollback_incomplete_account_credentials(id).await;
                    return Err(error);
                }
                Link::for_account(&ctx, id).reset().await;
                if let Err(error) = self
                    .db
                    .write(move |conn| repo::accounts::set_sync_state(conn, id, "idle"))
                    .await
                {
                    self.rollback_incomplete_account_credentials(id).await;
                    return Err(error);
                }
                id
            }
        };
        // The session is the account's now; nothing here ends it.
        current.password.clear();
        let config = self
            .db
            .read(move |conn| repo::accounts::get_config(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;
        self.spawn_actor(config).await;
        let account = self
            .db
            .read(move |conn| repo::accounts::get(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;
        Ok(ProtonSignIn::Done(account))
    }

    /// Ends a removed account's session on Proton, as far as it can be
    /// reached, and forgets it here.
    pub(crate) async fn proton_sign_out(&self, account_id: i64) {
        let ctx = self.sync_ctx();
        if let Ok(stored) = stored::load(self.credentials.clone(), account_id).await {
            let session = Session::new(Owner::Account(account_id), Some(stored.tokens));
            auth::sign_out(&session).await;
        }
        Link::forget(&ctx, account_id);
    }
}
