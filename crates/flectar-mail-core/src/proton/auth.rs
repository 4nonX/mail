//! Signing in to Proton: SRP, the second factor, and the passphrase that
//! unlocks the account's keys.
//!
//! The password never leaves the device. SRP proves it to Proton, and the
//! key passphrase is derived from it locally and kept instead of it.

use super::api::{ApiResult, Failure, HumanVerification, HumanVerificationAnswer, Session, Tokens};
use super::keys;
use crate::error::CoreError;
use proton_crypto::srp::SRPProvider;
use serde::Deserialize;
use serde_json::json;

/// Proton's second-factor bits in `2FA.Enabled`.
const TWO_FACTOR_TOTP: u32 = 1;
const TWO_FACTOR_FIDO2: u32 = 2;
/// `PasswordMode` 2: a separate mailbox password unlocks the keys.
const PASSWORD_MODE_TWO: u32 = 2;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SessionAnswer {
    #[serde(rename = "UID")]
    uid: String,
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AuthInfo {
    version: u8,
    modulus: String,
    server_ephemeral: String,
    salt: String,
    #[serde(rename = "SRPSession")]
    srp_session: String,
}

#[derive(Deserialize, Default)]
struct TwoFactorInfo {
    #[serde(rename = "Enabled", default)]
    enabled: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AuthAnswer {
    #[serde(rename = "UID")]
    uid: String,
    access_token: String,
    refresh_token: String,
    server_proof: String,
    #[serde(default)]
    password_mode: u32,
    #[serde(rename = "2FA", default)]
    two_factor: TwoFactorInfo,
}

/// Where a sign-in stands after the password.
#[derive(Debug)]
pub enum Step {
    /// Proton wants proof that a person is signing in. Solve it and call
    /// [`password`] again with the answer.
    HumanVerification(HumanVerification),
    /// Signed in. The second factor and, with two-password accounts, the
    /// mailbox password may still be needed before the keys unlock.
    SignedIn(SignedIn),
}

/// A session that proved the password.
#[derive(Debug)]
pub struct SignedIn {
    pub tokens: Tokens,
    pub needs_totp: bool,
    /// The account only offers a security key, which this app can't use.
    pub security_key_only: bool,
    pub needs_mailbox_password: bool,
}

/// Opens an unauthenticated session, as Proton's own clients do before
/// signing in.
pub async fn open_session(session: &Session) -> ApiResult<()> {
    session.set_tokens(None).await;
    let answer: SessionAnswer = session.post("/auth/v4/sessions", &json!({})).await?;
    session
        .set_tokens(Some(Tokens {
            uid: answer.uid,
            access_token: answer.access_token,
            refresh_token: answer.refresh_token,
        }))
        .await;
    Ok(())
}

/// Proves the password with SRP.
pub async fn password(
    session: &Session,
    username: &str,
    password: &str,
    verification: Option<&HumanVerificationAnswer>,
) -> ApiResult<Step> {
    if session.tokens().await.is_none() {
        open_session(session).await?;
    }
    let info: AuthInfo = session
        .post("/auth/v4/info", &json!({ "Username": username }))
        .await?;
    let srp = proton_crypto::new_srp_provider();
    let proof = srp
        .generate_client_proof(
            username,
            password,
            info.version,
            &info.salt,
            &info.modulus,
            &info.server_ephemeral,
        )
        .map_err(|error| Failure::Core(CoreError::Auth(format!("SRP failed: {error}"))))?;
    let request = json!({
        "Username": username,
        "ClientEphemeral": proof.ephemeral,
        "ClientProof": proof.proof,
        "SRPSession": info.srp_session,
    });
    let answer: AuthAnswer = match session
        .call(
            reqwest::Method::POST,
            "/auth/v4",
            Some(&request),
            verification,
        )
        .await
    {
        Ok(answer) => answer,
        Err(Failure::Api(error)) => {
            return match error.human_verification() {
                Some(challenge) => Ok(Step::HumanVerification(challenge)),
                None => Err(Failure::Api(error)),
            };
        }
        Err(other) => return Err(other),
    };
    if !proof.compare_server_proof(&answer.server_proof) {
        return Err(Failure::Core(CoreError::Auth(
            "Proton's server proof did not match; the sign-in was stopped".into(),
        )));
    }
    let tokens = Tokens {
        uid: answer.uid,
        access_token: answer.access_token,
        refresh_token: answer.refresh_token,
    };
    session.set_tokens(Some(tokens.clone())).await;
    let enabled = answer.two_factor.enabled;
    Ok(Step::SignedIn(SignedIn {
        tokens,
        needs_totp: enabled & TWO_FACTOR_TOTP != 0,
        security_key_only: enabled & TWO_FACTOR_FIDO2 != 0 && enabled & TWO_FACTOR_TOTP == 0,
        needs_mailbox_password: answer.password_mode == PASSWORD_MODE_TWO,
    }))
}

/// Sends the code from the authenticator app.
pub async fn totp(session: &Session, code: &str) -> ApiResult<()> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let _: serde_json::Value = session
        .post("/auth/v4/2fa", &json!({ "TwoFactorCode": code }))
        .await?;
    // The scopes changed, so the access token is refreshed with them.
    Ok(())
}

/// Derives the passphrase that unlocks the account's keys, and checks that
/// it does.
///
/// `key_password` is the account password, or the mailbox password of a
/// two-password account.
pub async fn key_passphrase(session: &Session, key_password: &str) -> ApiResult<String> {
    let user = keys::fetch_user(session).await?;
    let salts = keys::fetch_salts(session).await?;
    let passphrase = keys::derive_passphrase(&user, &salts, key_password)
        .map_err(|error| Failure::Core(CoreError::Auth(error)))?;
    keys::unlock_user_keys(&user, &passphrase)
        .map_err(|error| Failure::Core(CoreError::Auth(error)))?;
    Ok(passphrase)
}

/// Ends the session on Proton's side.
pub async fn sign_out(session: &Session) {
    let _ = session
        .send_raw(reqwest::Method::DELETE, "/auth/v4", None, None)
        .await;
    session.set_tokens(None).await;
}
