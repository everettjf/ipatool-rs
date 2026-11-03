//! Account operations return challenges to the front end instead of prompting.

use super::{
    context::ApplicationContext,
    operation::{self, Stage},
};
use crate::{
    credentials::{Account, AccountStore, CredentialStore},
    store_login::{self, AuthenticationBackend, LoginInput, NativeAuthenticationBackend},
};
use anyhow::Result;

#[derive(Debug)]
pub struct AccountChanged;

impl std::fmt::Display for AccountChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .write_str("the account changed; reload it and review the operation before retrying")
    }
}

impl std::error::Error for AccountChanged {}

pub(crate) fn require_same_identity(before: &Account, after: &Account) -> Result<()> {
    if operation::is_active()
        && (before.directory_services_id != after.directory_services_id
            || !before.email.eq_ignore_ascii_case(&after.email)
            || before.store_front != after.store_front)
    {
        return Err(AccountChanged.into());
    }
    Ok(())
}

/// Shared login boundary. AuthCodeRequired remains a typed, resumable challenge;
/// the CLI/GUI decides how to obtain a new code and how long to retain inputs.
pub fn login<B: AuthenticationBackend, S: CredentialStore>(
    backend: &B,
    accounts: &AccountStore<S>,
    input: LoginInput,
) -> Result<Account> {
    operation::stage(Stage::Authenticating)?;
    store_login::login(backend, accounts, input)
}

pub fn login_native(context: &ApplicationContext, input: LoginInput) -> Result<Account> {
    operation::stage(Stage::Preparing)?;
    let backend = NativeAuthenticationBackend::open_in(&context.state_directory)?;
    login(&backend, &context.accounts(), input)
}

pub fn refresh(context: &ApplicationContext, account: &Account) -> Result<Account> {
    let refreshed = login_native(
        context,
        LoginInput {
            email: account.email.clone(),
            password: account.password.clone(),
            auth_code: String::new(),
        },
    )?;
    require_same_identity(account, &refreshed)?;
    Ok(refreshed)
}

/// One refresh is the existing list/purchase/MCP policy. Download keeps its
/// separate three-attempt contract in download::retry_download.
pub fn with_account<T, B>(
    context: &ApplicationContext,
    prepare_backend: impl FnOnce() -> Result<B>,
    mut work: impl FnMut(&B, &Account) -> Result<T>,
) -> Result<T> {
    let mut account = context.accounts().load()?;
    // Preserve the CLI's early missing-account failure before loading pinned
    // frameworks or starting their first-time download.
    let backend = prepare_backend()?;
    match work(&backend, &account) {
        Err(error) if error.is::<crate::store_purchase::PasswordTokenExpired>() => {
            account = refresh(context, &account)?;
            operation::check()?;
            work(&backend, &account)
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_account_does_not_start_backend_resource_preparation() {
        let directory = tempfile::tempdir().unwrap();
        let context = ApplicationContext::configured(
            directory.path(),
            false,
            true,
            Some("fixture-passphrase".into()),
        )
        .unwrap();
        let prepared = std::cell::Cell::new(false);
        let result = with_account(
            &context,
            || {
                prepared.set(true);
                Ok(())
            },
            |_, _| Ok(()),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "account not found in keychain"
        );
        assert!(!prepared.get());
    }

    #[test]
    fn desktop_refresh_pins_account_and_storefront_while_allowing_token_rotation() {
        let mut before = Account::default();
        before.email = "fixture@example.invalid".into();
        before.directory_services_id = "123".into();
        before.store_front = "143441".into();
        let mut after = Account::default();
        after.directory_services_id = before.directory_services_id.clone();
        after.store_front = before.store_front.clone();
        after.email = "FIXTURE@example.invalid".into();
        after.password_token = "rotated-fixture-token".into();
        operation::Operation::default()
            .run(|| require_same_identity(&before, &after))
            .unwrap();
        after.store_front = "143444".into();
        let error = operation::Operation::default()
            .run(|| require_same_identity(&before, &after))
            .unwrap_err();
        assert!(error.is::<AccountChanged>());
        // The unscoped CLI keeps its existing refresh policy.
        require_same_identity(&before, &after).unwrap();
    }
}
