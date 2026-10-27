//! Account persistence compatible with the Go macOS Keychain item names.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(target_os = "linux", target_os = "windows", all(test, unix)))]
use crate::file_keychain::FileKeychain;
#[cfg(target_os = "linux")]
use crate::linux_secret_service::LinuxSecretService;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::state::KEYCHAIN_SERVICE_NAME;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::state::prepare_state_directory_from_environment;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(target_os = "linux", target_os = "windows", all(test, unix)))]
struct FileKeychainOptions {
    passphrase: std::sync::Mutex<Option<Zeroizing<String>>>,
    interactive: bool,
}

#[cfg(any(target_os = "linux", target_os = "windows", all(test, unix)))]
struct LazyFileKeychain<'a> {
    directory: std::path::PathBuf,
    options: &'a FileKeychainOptions,
}

#[cfg(any(target_os = "linux", target_os = "windows", all(test, unix)))]
impl CredentialStore for LazyFileKeychain<'_> {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if !FileKeychain::item_exists(&self.directory, key)? {
            return Ok(None);
        }
        open_file_keychain(self.directory.clone(), self.options)?.get(key)
    }

    fn set(&self, key: &str, data: &[u8]) -> Result<()> {
        open_file_keychain(self.directory.clone(), self.options)?.set(key, data)
    }

    fn remove(&self, key: &str) -> Result<bool> {
        FileKeychain::remove_item(&self.directory, key)
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
static FILE_KEYCHAIN_OPTIONS: std::sync::OnceLock<FileKeychainOptions> = std::sync::OnceLock::new();

/// Configure the Go-compatible file keychain before opening it on Linux or Windows.
pub fn configure_file_keychain(passphrase: Option<String>, interactive: bool) {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let _ = FILE_KEYCHAIN_OPTIONS.set(FileKeychainOptions {
            passphrase: std::sync::Mutex::new(passphrase.map(Zeroizing::new)),
            interactive,
        });
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (passphrase, interactive);
    }
}

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

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub struct AppleKeychain {
    allow_ui: bool,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
static APPLE_KEYCHAIN_UI_ALLOWED: AtomicBool = AtomicBool::new(true);

/// Control whether Apple Keychain operations may display an authorization dialog.
pub fn configure_apple_keychain_ui(allow_ui: bool) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    APPLE_KEYCHAIN_UI_ALLOWED.store(allow_ui, Ordering::Relaxed);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let _ = allow_ui;
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn apple_password_options(
    key: &str,
    allow_ui: bool,
) -> security_framework::passwords::PasswordOptions {
    use core_foundation::{base::TCFType, string::CFString};
    use security_framework::passwords::PasswordOptions;
    use security_framework_sys::item::kSecUseAuthenticationUI;

    let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE_NAME, key);
    if !allow_ui {
        // The sys crate omits this public Security.framework constant. Apple's
        // SecItem API returns errSecInteractionNotAllowed when UI is required.
        unsafe extern "C" {
            static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
        }
        #[allow(deprecated)]
        unsafe {
            options.query.push((
                CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
                CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
            ));
        }
    }
    options
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn apple_keychain_error(
    operation: &str,
    key: &str,
    error: security_framework::base::Error,
) -> anyhow::Error {
    if error.code() == -25308 {
        anyhow!(
            "{operation} Apple Keychain item {key}: interactive authorization is required; approve access from an interactive ipatool account command"
        )
    } else {
        anyhow!("{operation} Apple Keychain item {key}: {error}")
    }
}

#[cfg(target_os = "macos")]
pub type MacKeychain = AppleKeychain;

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl CredentialStore for AppleKeychain {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        use security_framework::passwords::generic_password;
        match generic_password(apple_password_options(key, self.allow_ui)) {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.code() == -25300 => Ok(None),
            Err(error) => Err(apple_keychain_error("read", key, error)),
        }
    }

    fn set(&self, key: &str, data: &[u8]) -> Result<()> {
        security_framework::passwords::set_generic_password_options(
            data,
            apple_password_options(key, self.allow_ui),
        )
        .map_err(|error| apple_keychain_error("save", key, error))
    }

    fn remove(&self, key: &str) -> Result<bool> {
        use security_framework::passwords::delete_generic_password_options;
        match delete_generic_password_options(apple_password_options(key, self.allow_ui)) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == -25300 => Ok(false),
            Err(error) => Err(apple_keychain_error("remove", key, error)),
        }
    }
}

pub fn open_system_keychain() -> Result<Box<dyn CredentialStore + Send + Sync>> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Ok(Box::new(AppleKeychain {
            allow_ui: APPLE_KEYCHAIN_UI_ALLOWED.load(Ordering::Relaxed),
        }))
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let options = FILE_KEYCHAIN_OPTIONS
            .get()
            .context("file keychain is not configured")?;
        #[cfg(target_os = "linux")]
        {
            let explicit_file_backend = options
                .passphrase
                .lock()
                .map_err(|_| anyhow!("file keychain lock failed"))?
                .is_some();
            if !explicit_file_backend
                && let Some(service) = LinuxSecretService::probe(options.interactive)
            {
                return Ok(Box::new(service));
            }
        }
        let directory = prepare_state_directory_from_environment()?;
        Ok(Box::new(LazyFileKeychain { directory, options }))
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "windows"
    )))]
    {
        bail!("system credential storage is not yet implemented for this platform")
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", all(test, unix)))]
fn open_file_keychain(
    directory: std::path::PathBuf,
    options: &FileKeychainOptions,
) -> Result<Box<dyn CredentialStore + Send + Sync>> {
    let mut stored = options
        .passphrase
        .lock()
        .map_err(|_| anyhow!("file keychain lock failed"))?;
    if stored.is_none() {
        if !options.interactive {
            bail!("keychain passphrase is required; use --keychain-passphrase");
        }
        *stored = Some(Zeroizing::new(prompt_file_passphrase()?));
    }
    let passphrase = stored
        .as_ref()
        .expect("passphrase initialized")
        .as_str()
        .to_owned();
    drop(stored);
    Ok(Box::new(FileKeychain::new(directory, passphrase)?))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn prompt_file_passphrase() -> Result<String> {
    use std::io::{self, Write};

    struct EchoGuard(libc::termios);
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            // SAFETY: this restores the settings read from the same terminal.
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) };
        }
    }
    // SAFETY: tcgetattr initializes the termios value before it is used.
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: stdin is checked by the CLI before enabling interactive mode.
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read terminal settings");
    }
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    eprint!("enter passphrase to unlock ipatool file keychain (separate from Apple ID password): ");
    io::stderr().flush()?;
    // SAFETY: hidden is derived from valid terminal settings.
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
        return Err(std::io::Error::last_os_error()).context("hide keychain passphrase input");
    }
    let guard = EchoGuard(original);
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("read keychain passphrase")?;
    drop(guard);
    eprintln!();
    let passphrase = input.trim_end_matches(['\r', '\n']).to_owned();
    input.zeroize();
    if passphrase.is_empty() {
        bail!("file keychain passphrase must not be empty");
    }
    Ok(passphrase)
}

#[cfg(target_os = "windows")]
fn prompt_file_passphrase() -> Result<String> {
    use std::io::{self, Write};
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        System::Console::{
            ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
        },
    };

    struct EchoGuard(windows_sys::Win32::Foundation::HANDLE, u32);
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            // SAFETY: the handle and original mode came from this process's input console.
            unsafe { SetConsoleMode(self.0, self.1) };
        }
    }
    // SAFETY: GetStdHandle returns a process-owned handle; GetConsoleMode writes one u32.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        bail!("input console is unavailable; use --keychain-passphrase");
    }
    let mut original = 0;
    if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
        return Err(std::io::Error::last_os_error()).context("read console settings");
    }
    eprint!("enter passphrase to unlock ipatool file keychain (separate from Apple ID password): ");
    io::stderr().flush()?;
    if unsafe { SetConsoleMode(handle, original & !ENABLE_ECHO_INPUT) } == 0 {
        return Err(std::io::Error::last_os_error()).context("hide keychain passphrase input");
    }
    let guard = EchoGuard(handle, original);
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("read keychain passphrase")?;
    drop(guard);
    eprintln!();
    let passphrase = input.trim_end_matches(['\r', '\n']).to_owned();
    input.zeroize();
    if passphrase.is_empty() {
        bail!("file keychain passphrase must not be empty");
    }
    Ok(passphrase)
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
        self.load_optional()?
            .ok_or_else(|| anyhow!("account not found in keychain"))
    }

    pub fn load_optional(&self) -> Result<Option<Account>> {
        let Some(data) = self.credentials.get(ACCOUNT_KEY)? else {
            return Ok(None);
        };
        let data = Zeroizing::new(data);
        Ok(Some(
            serde_json::from_slice(&data).context("failed to decode account JSON")?,
        ))
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

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn noninteractive_apple_password_query_forbids_authentication_ui() {
        use core_foundation::base::TCFType;
        use security_framework_sys::item::kSecUseAuthenticationUI;

        let options = apple_password_options("account", false);
        #[allow(deprecated)]
        {
            assert_eq!(apple_password_options("account", true).query.len(), 3);
            assert_eq!(options.query.len(), 4);
            assert_eq!(options.query[3].0.as_concrete_TypeRef(), unsafe {
                kSecUseAuthenticationUI
            });
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_keychain_supports_account_store_without_reprompting() {
        let directory = tempfile::tempdir().unwrap();
        let options = FileKeychainOptions {
            passphrase: Mutex::new(Some(Zeroizing::new("test passphrase".into()))),
            interactive: false,
        };
        let store =
            AccountStore::new(open_file_keychain(directory.path().to_owned(), &options).unwrap());
        let mut account = Account::default();
        account.email = "person@example.test".into();
        account.password_token = "test token".into();
        store.save(&account).unwrap();
        let reopened =
            AccountStore::new(open_file_keychain(directory.path().to_owned(), &options).unwrap());
        assert_eq!(reopened.load().unwrap().email, account.email);
        assert_eq!(
            reopened.load().unwrap().password_token,
            account.password_token
        );
        reopened.revoke().unwrap();

        let missing = FileKeychainOptions {
            passphrase: Mutex::new(None),
            interactive: false,
        };
        assert!(open_file_keychain(directory.path().to_owned(), &missing).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_keychain_only_unlocks_when_an_item_needs_decryption_or_encryption() {
        let directory = tempfile::tempdir().unwrap();
        let options = FileKeychainOptions {
            passphrase: Mutex::new(None),
            interactive: false,
        };
        let store = LazyFileKeychain {
            directory: directory.path().to_owned(),
            options: &options,
        };
        assert!(store.get(ACCOUNT_KEY).unwrap().is_none());
        assert!(!store.remove(ACCOUNT_KEY).unwrap());
        assert!(store.get("../account").is_err());
        assert!(store.set(ACCOUNT_KEY, b"account").is_err());

        let populated =
            FileKeychain::new(directory.path().to_owned(), "test passphrase".into()).unwrap();
        populated.set(ACCOUNT_KEY, b"account").unwrap();
        assert!(store.get(ACCOUNT_KEY).is_err());
        assert!(store.remove(ACCOUNT_KEY).unwrap());
        assert!(store.get(ACCOUNT_KEY).unwrap().is_none());
    }

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
    fn optional_account_load_distinguishes_missing_from_invalid_data() {
        let store = AccountStore::new(MemoryStore::default());
        assert!(store.load_optional().unwrap().is_none());
        store.credentials.set(ACCOUNT_KEY, b"not-json").unwrap();
        assert!(store.load_optional().is_err());
        store
            .credentials
            .set(ACCOUNT_KEY, br#"{"email":"person@example.test"}"#)
            .unwrap();
        assert_eq!(
            store.load_optional().unwrap().unwrap().email,
            "person@example.test"
        );
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
