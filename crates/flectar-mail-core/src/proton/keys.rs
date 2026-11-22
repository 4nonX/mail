//! The account's OpenPGP keys: fetching them locked, unlocking them with the
//! key passphrase, and decrypting messages with them.
//!
//! Proton keeps two layers. User keys are locked with a passphrase derived
//! from the (mailbox) password; each address's keys are locked with a token
//! encrypted to the user keys.

use super::api::{ApiResult, Session};
use base64::Engine as _;
use proton_crypto::crypto::{
    DataEncoding, Decryptor, DecryptorSync, PGPProviderSync, VerifiedData,
};
use proton_crypto_account::keys::{AddressKeys, LockedKey, UnlockedAddressKey, UserKeys};
use proton_crypto_account::salts::{KeySecret, Salt, Salts};
use serde::Deserialize;
use std::collections::HashMap;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct User {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub keys: Vec<LockedKey>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Address {
    #[serde(rename = "ID")]
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub display_name: String,
    /// 1: enabled.
    #[serde(default)]
    pub status: u8,
    /// 1: may send. Addresses that only receive have 0.
    #[serde(default)]
    pub send: u8,
    #[serde(default)]
    pub order: i64,
    #[serde(default)]
    pub keys: Vec<LockedKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserAnswer {
    user: User,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SaltsAnswer {
    key_salts: Vec<Salt>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AddressesAnswer {
    addresses: Vec<Address>,
}

pub async fn fetch_user(session: &Session) -> ApiResult<User> {
    let answer: UserAnswer = session.get("/core/v4/users").await?;
    Ok(answer.user)
}

pub async fn fetch_salts(session: &Session) -> ApiResult<Salts> {
    let answer: SaltsAnswer = session.get("/core/v4/keys/salts").await?;
    Ok(Salts::new(answer.key_salts))
}

pub async fn fetch_addresses(session: &Session) -> ApiResult<Vec<Address>> {
    let answer: AddressesAnswer = session.get("/core/v4/addresses").await?;
    let mut addresses = answer.addresses;
    addresses.sort_by_key(|address| address.order);
    Ok(addresses)
}

/// Derives the key passphrase from the (mailbox) password with the salt of
/// the primary user key, encoded for storage.
pub fn derive_passphrase(user: &User, salts: &Salts, key_password: &str) -> Result<String, String> {
    let primary = user
        .keys
        .iter()
        .find(|key| key.primary)
        .or_else(|| user.keys.first())
        .ok_or("the Proton account has no keys")?;
    let srp = proton_crypto::new_srp_provider();
    let secret = salts
        .salt_for_key(&srp, &primary.id, key_password.as_bytes())
        .map_err(|error| format!("could not derive the key passphrase: {error}"))?;
    Ok(B64.encode(secret.as_bytes()))
}

fn key_secret(passphrase: &str) -> Result<KeySecret, String> {
    B64.decode(passphrase)
        .map(KeySecret::new)
        .map_err(|_| "the stored Proton key passphrase is damaged".to_owned())
}

/// Checks that the passphrase opens at least one user key.
pub fn unlock_user_keys(user: &User, passphrase: &str) -> Result<(), String> {
    let provider = proton_crypto::new_pgp_provider();
    let secret = key_secret(passphrase)?;
    let unlocked = UserKeys::new(user.keys.clone()).unlock(&provider, &secret);
    if unlocked.unlocked_keys.is_empty() {
        return Err("the password does not unlock the Proton keys".into());
    }
    Ok(())
}

/// Decrypts messages for every address of the account.
pub trait Decrypter: Send + Sync {
    /// Decrypts an armored message sent to the address.
    fn decrypt_message(&self, address_id: &str, armored: &str) -> Result<Vec<u8>, String>;
    /// Decrypts an attachment from its key packets and data packets.
    fn decrypt_attachment(
        &self,
        address_id: &str,
        key_packets: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, String>;
    /// The addresses whose keys opened.
    fn address_ids(&self) -> Vec<String>;
}

struct Keyring<P: PGPProviderSync> {
    provider: P,
    by_address: HashMap<String, Vec<UnlockedAddressKey<P>>>,
}

impl<P: PGPProviderSync> Keyring<P> {
    fn keys(&self, address_id: &str) -> Result<&[UnlockedAddressKey<P>], String> {
        self.by_address
            .get(address_id)
            .map(Vec::as_slice)
            .filter(|keys| !keys.is_empty())
            .ok_or_else(|| format!("no unlocked key for Proton address {address_id}"))
    }
}

impl<P: PGPProviderSync + Send + Sync> Decrypter for Keyring<P>
where
    P::PrivateKey: Send + Sync,
    P::PublicKey: Send + Sync,
{
    fn decrypt_message(&self, address_id: &str, armored: &str) -> Result<Vec<u8>, String> {
        let keys = self.keys(address_id)?;
        let private: Vec<&P::PrivateKey> = keys.iter().map(|key| &key.private_key).collect();
        self.provider
            .new_decryptor()
            .with_decryption_keys(private)
            .decrypt(armored, DataEncoding::Armor)
            .map(VerifiedData::into_vec)
            .map_err(|error| format!("could not decrypt the message: {error}"))
    }

    fn decrypt_attachment(
        &self,
        address_id: &str,
        key_packets: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let keys = self.keys(address_id)?;
        let private: Vec<&P::PrivateKey> = keys.iter().map(|key| &key.private_key).collect();
        let mut message = Vec::with_capacity(key_packets.len() + data.len());
        message.extend_from_slice(key_packets);
        message.extend_from_slice(data);
        self.provider
            .new_decryptor()
            .with_decryption_keys(private)
            .decrypt(&message, DataEncoding::Bytes)
            .map(VerifiedData::into_vec)
            .map_err(|error| format!("could not decrypt the attachment: {error}"))
    }

    fn address_ids(&self) -> Vec<String> {
        self.by_address
            .iter()
            .filter(|(_, keys)| !keys.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Unlocks the user keys and, through them, every address's keys.
pub fn unlock(
    user: &User,
    addresses: &[Address],
    passphrase: &str,
) -> Result<std::sync::Arc<dyn Decrypter>, String> {
    let provider = proton_crypto::new_pgp_provider();
    let secret = key_secret(passphrase)?;
    let user_keys = UserKeys::new(user.keys.clone())
        .unlock(&provider, &secret)
        .unlocked_keys;
    if user_keys.is_empty() {
        return Err("the stored passphrase no longer unlocks the Proton keys".into());
    }
    let mut by_address = HashMap::new();
    for address in addresses {
        let unlocked = AddressKeys::new(address.keys.clone())
            .unlock(&provider, &user_keys, Some(&secret))
            .unlocked_keys;
        if unlocked.is_empty() && !address.keys.is_empty() {
            tracing::warn!(address = %address.email, "no Proton address key unlocked");
        }
        by_address.insert(address.id.clone(), unlocked);
    }
    Ok(std::sync::Arc::new(Keyring {
        provider,
        by_address,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_and_addresses_parse_from_proton_answers() {
        let user: UserAnswer = serde_json::from_str(
            r#"{"Code":1000,"User":{"ID":"u1","Name":"dan","Keys":[{"ID":"k1","Version":3,
            "PrivateKey":"-----BEGIN PGP PRIVATE KEY BLOCK-----","Primary":1,"Active":1}]}}"#,
        )
        .unwrap();
        assert_eq!(user.user.id, "u1");
        assert!(user.user.keys[0].primary);

        let addresses: AddressesAnswer = serde_json::from_str(
            r#"{"Code":1000,"Addresses":[
                {"ID":"a2","Email":"second@proton.me","Status":1,"Send":1,"Order":2,"Keys":[]},
                {"ID":"a1","Email":"first@proton.me","DisplayName":"Dan","Status":1,"Send":1,"Order":1,"Keys":[]}]}"#,
        )
        .unwrap();
        assert_eq!(addresses.addresses.len(), 2);
        assert_eq!(addresses.addresses[1].display_name, "Dan");
    }

    #[test]
    fn a_damaged_stored_passphrase_is_reported() {
        assert!(key_secret("not base64 !!").is_err());
        assert!(key_secret(&B64.encode(b"secret")).is_ok());
    }
}
