//! What a Proton account keeps in the credential store: the session tokens
//! and the passphrase that unlocks its keys. The account's password proves
//! the sign-in and derives the passphrase, and is then dropped.

use super::api::{Session, Tokens};
use crate::accounts::credentials::{self, CredentialStoreHandle, Slot};
use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;

/// A signed-in Proton account's secrets, stored as one value so a refreshed
/// token pair can never be saved half.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSession {
    version: u32,
    pub tokens: Tokens,
    /// Derived from the (mailbox) password and the key salt; unlocks the
    /// user keys.
    pub key_passphrase: String,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSession")
            .field("uid", &self.tokens.uid)
            .finish_non_exhaustive()
    }
}

impl StoredSession {
    pub fn new(tokens: Tokens, key_passphrase: String) -> Self {
        Self {
            version: VERSION,
            tokens,
            key_passphrase,
        }
    }

    fn decode(encoded: &str) -> Result<Self> {
        let stored: Self = serde_json::from_str(encoded).map_err(|_| invalid())?;
        if stored.version != VERSION
            || stored.tokens.uid.is_empty()
            || stored.tokens.refresh_token.is_empty()
            || stored.key_passphrase.is_empty()
        {
            return Err(invalid());
        }
        Ok(stored)
    }
}

/// Signing in again replaces whatever is stored, so that is the way out.
fn invalid() -> CoreError {
    CoreError::NeedsReauth
}

pub async fn store(
    credentials: CredentialStoreHandle,
    account_id: i64,
    stored: &StoredSession,
) -> Result<()> {
    let encoded = serde_json::to_string(stored)?;
    credentials::store_async(credentials, account_id, Slot::ProtonSession, encoded).await
}

/// The account's stored session. An account with none, or with one this
/// version can't read, has to sign in again.
pub async fn load(credentials: CredentialStoreHandle, account_id: i64) -> Result<StoredSession> {
    match credentials::load_async(credentials, account_id, Slot::ProtonSession).await {
        Ok(encoded) => StoredSession::decode(&encoded),
        Err(error) if credentials::is_missing(&error) => Err(CoreError::NeedsReauth),
        Err(error) => Err(error),
    }
}

/// Saves the tokens `session` holds now when a refresh replaced the stored
/// ones. Proton's refresh tokens are single-use, so losing the new pair would
/// sign the account out.
pub async fn keep_refreshed(
    credentials: CredentialStoreHandle,
    account_id: i64,
    session: &Session,
    stored: &mut StoredSession,
) -> Result<()> {
    let Some(tokens) = session.tokens().await else {
        return Ok(());
    };
    if tokens == stored.tokens {
        return Ok(());
    }
    let refreshed = StoredSession::new(tokens, stored.key_passphrase.clone());
    store(credentials, account_id, &refreshed).await?;
    *stored = refreshed;
    Ok(())
}

#[cfg(all(test, desktop))]
mod tests {
    use super::*;
    use crate::accounts::credentials::DevelopmentFileCredentialStore;
    use crate::net::proxy::Owner;
    use std::sync::Arc;

    fn tokens(suffix: &str) -> Tokens {
        Tokens {
            uid: "uid".into(),
            access_token: format!("access-{suffix}"),
            refresh_token: format!("refresh-{suffix}"),
        }
    }

    fn file_store(directory: &tempfile::TempDir) -> CredentialStoreHandle {
        Arc::new(DevelopmentFileCredentialStore::new(
            directory.path().join("credentials.json"),
        ))
    }

    #[tokio::test]
    async fn a_stored_session_comes_back_whole() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = file_store(&directory);
        let stored = StoredSession::new(tokens("1"), "passphrase".into());

        store(credentials.clone(), 7, &stored).await.unwrap();

        assert_eq!(load(credentials, 7).await.unwrap(), stored);
    }

    #[tokio::test]
    async fn a_missing_or_unreadable_session_asks_to_sign_in_again() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = file_store(&directory);

        assert!(matches!(
            load(credentials.clone(), 7).await,
            Err(CoreError::NeedsReauth)
        ));

        for encoded in [
            "not json",
            r#"{"version":2,"tokens":{"uid":"u","access_token":"a","refresh_token":"r"},"key_passphrase":"p"}"#,
            r#"{"version":1,"tokens":{"uid":"u","access_token":"a","refresh_token":"r"},"key_passphrase":""}"#,
        ] {
            credentials::store_async(credentials.clone(), 7, Slot::ProtonSession, encoded.into())
                .await
                .unwrap();
            assert!(matches!(
                load(credentials.clone(), 7).await,
                Err(CoreError::NeedsReauth)
            ));
        }
    }

    #[tokio::test]
    async fn refreshed_tokens_replace_the_stored_ones() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = file_store(&directory);
        let mut stored = StoredSession::new(tokens("1"), "passphrase".into());
        store(credentials.clone(), 7, &stored).await.unwrap();
        let session = Session::new(Owner::App, Some(tokens("1")));

        keep_refreshed(credentials.clone(), 7, &session, &mut stored)
            .await
            .unwrap();
        assert_eq!(stored.tokens, tokens("1"));

        session.set_tokens(Some(tokens("2"))).await;
        keep_refreshed(credentials.clone(), 7, &session, &mut stored)
            .await
            .unwrap();

        let loaded = load(credentials, 7).await.unwrap();
        assert_eq!(loaded.tokens, tokens("2"));
        assert_eq!(loaded.key_passphrase, "passphrase");
        assert_eq!(stored, loaded);
    }

    #[test]
    fn debug_output_names_no_secret() {
        let stored = StoredSession::new(tokens("1"), "passphrase".into());
        let shown = format!("{stored:?}");
        assert!(!shown.contains("passphrase"));
        assert!(!shown.contains("access-1"));
        assert!(!shown.contains("refresh-1"));
    }
}
