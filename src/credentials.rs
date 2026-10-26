//! Account persistence compatible with the Go macOS Keychain item names.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
use crate::state::KEYCHAIN_SERVICE_NAME;

pub const ACCOUNT_KEY: &str = "account";
pub const KBSYNC_CACHE_KEY: &str = "kbsync-v1";

pub trait CredentialStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &str, data: &[u8]) -> Result<()>;
    /// Returns true when an item was removed.
    fn remove(&self, key: &str) -> Result<bool>;
}

impl<T: CredentialStore + ?Sized> CredentialStore for Box<T> {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        (**self).get(key)
    }
    fn set(&self, key: &str, data: &[u8]) -> Result<()> {
        (**self).set(key, data)
    }
    fn remove(&self, key: &str) -> Result<bool> {
        (**self).remove(key)
    }
}

#[cfg(target_os = "macos")]
pub struct MacKeychain;

#[cfg(target_os = "macos")]
impl CredentialStore for MacKeychain {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        use security_framework::passwords::get_generic_password;
        match get_generic_password(KEYCHAIN_SERVICE_NAME, key) {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.code() == -25300 => Ok(None),
            Err(error) => Err(anyhow!("read macOS Keychain item {key}: {error}")),
        }
    }

    fn set(&self, key: &str, data: &[u8]) -> Result<()> {
        security_framework::passwords::set_generic_password(KEYCHAIN_SERVICE_NAME, key, data)
            .with_context(|| format!("save macOS Keychain item {key}"))
    }

    fn remove(&self, key: &str) -> Result<bool> {
        use security_framework::passwords::delete_generic_password;
        match delete_generic_password(KEYCHAIN_SERVICE_NAME, key) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == -25300 => Ok(false),
            Err(error) => Err(anyhow!("remove macOS Keychain item {key}: {error}")),
        }
    }
}

pub fn open_system_keychain() -> Result<Box<dyn CredentialStore + Send + Sync>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacKeychain))
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!("system credential storage is not yet implemented for this platform")
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct Account {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(
        default,
        rename = "passwordToken",
        skip_serializing_if = "String::is_empty"
    )]
    pub password_token: String,
    #[serde(
        default,
        rename = "directoryServicesIdentifier",
        skip_serializing_if = "String::is_empty"
    )]
    pub directory_services_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(
        default,
        rename = "storeFront",
        skip_serializing_if = "String::is_empty"
    )]
    pub store_front: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pod: String,
}

impl Drop for Account {
    fn drop(&mut self) {
        self.email.zeroize();
        self.password_token.zeroize();
        self.directory_services_id.zeroize();
        self.name.zeroize();
        self.store_front.zeroize();
        self.password.zeroize();
        self.pod.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AccountSummary {
    pub name: String,
    pub email: String,
    pub success: bool,
}

pub struct AccountStore<S> {
    credentials: S,
}

impl<S: CredentialStore> AccountStore<S> {
    pub fn new(credentials: S) -> Self {
        Self { credentials }
    }

    pub fn load(&self) -> Result<Account> {
        let data = self
            .credentials
            .get(ACCOUNT_KEY)?
            .ok_or_else(|| anyhow!("account not found in keychain"))?;
        let data = Zeroizing::new(data);
        serde_json::from_slice(&data).context("failed to decode account JSON")
    }

    pub fn save(&self, account: &Account) -> Result<()> {
        let data = Zeroizing::new(serde_json::to_vec(account)?);
        self.credentials.set(ACCOUNT_KEY, &data)
    }

    pub fn info(&self) -> Result<AccountSummary> {
        let account = self.load()?;
        Ok(AccountSummary {
            name: account.name.clone(),
            email: account.email.clone(),
            success: true,
        })
    }

    pub fn revoke(&self) -> Result<()> {
        let account_result = self.credentials.remove(ACCOUNT_KEY);
        let cache_result = self.credentials.remove(KBSYNC_CACHE_KEY);
        let account_error = match account_result {
            Ok(true) => None,
            Ok(false) => Some(anyhow!("account not found in keychain")),
            Err(error) => Some(error.context("failed to remove account from keychain")),
        };
        let cache_error = cache_result
            .err()
            .map(|error| error.context("failed to remove kbsync cache from keychain"));
        match (account_error, cache_error) {
            (None, None) => Ok(()),
            (Some(error), None) | (None, Some(error)) => Err(error),
            (Some(account), Some(cache)) => bail!("{account:#}; {cache:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex};

    #[derive(Default)]
    struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);
    impl CredentialStore for MemoryStore {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, data: &[u8]) -> Result<()> {
            self.0.lock().unwrap().insert(key.into(), data.to_vec());
            Ok(())
        }
        fn remove(&self, key: &str) -> Result<bool> {
            Ok(self.0.lock().unwrap().remove(key).is_some())
        }
    }

    #[test]
    fn reads_go_account_fields_without_exposing_secrets() {
        let store = AccountStore::new(MemoryStore::default());
        store.credentials.set(ACCOUNT_KEY, br#"{"email":"person@example.test","passwordToken":"secret-token","directoryServicesIdentifier":"123","name":"Person","storeFront":"143441","password":"secret-password","pod":"42"}"#).unwrap();
        let summary = store.info().unwrap();
        assert_eq!(summary.name, "Person");
        assert_eq!(summary.email, "person@example.test");
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(!encoded.contains("secret-token"));
        assert!(!encoded.contains("secret-password"));
    }

    #[test]
    fn revoke_removes_account_and_kbsync_cache() {
        let store = AccountStore::new(MemoryStore::default());
        store.credentials.set(ACCOUNT_KEY, b"account").unwrap();
        store.credentials.set(KBSYNC_CACHE_KEY, b"cache").unwrap();
        store.revoke().unwrap();
        assert!(store.credentials.get(ACCOUNT_KEY).unwrap().is_none());
        assert!(store.credentials.get(KBSYNC_CACHE_KEY).unwrap().is_none());
        assert!(store.revoke().is_err());
    }

    #[test]
    fn saves_go_compatible_account_shape() {
        let store = AccountStore::new(MemoryStore::default());
        let mut account = Account::default();
        account.email = "person@example.test".into();
        account.password_token = "token".into();
        store.save(&account).unwrap();
        let bytes = store.credentials.get(ACCOUNT_KEY).unwrap().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({"email":"person@example.test","passwordToken":"token"})
        );
    }
}
