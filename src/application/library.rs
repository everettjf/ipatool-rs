//! Account-scoped catalog and entitlement workflows used by both front ends.

use super::{
    account::with_account,
    context::ApplicationContext,
    operation::{self, Stage},
};
use crate::{
    App, CatalogClient, Platform,
    credentials::Account,
    ipa_metadata::VersionMetadata,
    store_download_product::{DownloadProductClient, ListVersionsOutput},
    store_owned::{self, MAX_LIMIT, NativeOwnedBackend, OwnedAppsOutput},
    store_purchase::{self, LicenseAlreadyExists, NativePurchaseBackend},
    storefront::country_code_from_storefront,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppIdentity {
    pub app_id: Option<i64>,
    pub bundle_identifier: Option<String>,
    pub platform: Option<Platform>,
}

impl AppIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.app_id.is_none_or(|id| id <= 0)
            && self.bundle_identifier.as_deref().is_none_or(str::is_empty)
        {
            bail!("either the app ID or the bundle identifier must be specified");
        }
        Ok(())
    }

    pub fn resolve(&self, account: &Account) -> Result<App> {
        self.validate()?;
        operation::stage(Stage::Metadata)?;
        if let Some(bundle) = self
            .bundle_identifier
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            CatalogClient::new()?.lookup(
                None,
                Some(bundle),
                country_code_from_storefront(&account.store_front)?,
                self.platform,
            )
        } else {
            Ok(App {
                id: self.app_id.context("app ID is required")?,
                ..Default::default()
            })
        }
    }
}

pub fn purchases(
    context: &ApplicationContext,
    page: usize,
    limit: usize,
    platform: Option<Platform>,
) -> Result<OwnedAppsOutput> {
    if page == 0 || limit == 0 || limit > MAX_LIMIT {
        bail!("page must be positive and max results must be between 1 and {MAX_LIMIT}");
    }
    operation::stage(Stage::Metadata)?;
    with_account(
        context,
        || NativeOwnedBackend::open_in(&context.state_directory),
        |backend, account| store_owned::owned_apps(backend, account, page, limit, platform),
    )
}

pub fn versions(
    context: &ApplicationContext,
    identity: &AppIdentity,
) -> Result<ListVersionsOutput> {
    identity.validate()?;
    with_account(
        context,
        || {
            Ok((
                DownloadProductClient::open_in(
                    &context.state_directory,
                    Arc::clone(&context.credentials),
                )?,
                CatalogClient::new()?,
            ))
        },
        |(backend, catalog), account| {
            backend.list_versions(
                catalog,
                account,
                &identity.resolve(account)?,
                identity.platform.unwrap_or(Platform::Iphone),
            )
        },
    )
}

pub fn version_metadata(
    context: &ApplicationContext,
    identity: &AppIdentity,
    version: &str,
) -> Result<VersionMetadata> {
    identity.validate()?;
    if version.is_empty() {
        bail!("an external version ID is required");
    }
    with_account(
        context,
        || {
            DownloadProductClient::open_in(
                &context.state_directory,
                Arc::clone(&context.credentials),
            )
        },
        |backend, account| {
            backend.get_version_metadata(
                account,
                &identity.resolve(account)?,
                version,
                identity.platform,
            )
        },
    )
}

/// Returns true when the account already held the license.
pub fn purchase(context: &ApplicationContext, identity: &AppIdentity) -> Result<bool> {
    identity.validate()?;
    with_account(
        context,
        || NativePurchaseBackend::open_in(&context.state_directory),
        |backend, account| {
            let app = identity.resolve(account)?;
            operation::stage(Stage::Licensing)?;
            match store_purchase::purchase(backend, account, &app, identity.platform) {
                Ok(()) => Ok(false),
                Err(error) if error.is::<LicenseAlreadyExists>() => Ok(true),
                Err(error) => Err(error),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_validation_keeps_identifier_precedence_without_accepting_missing_ids() {
        assert!(AppIdentity::default().validate().is_err());
        assert!(
            AppIdentity {
                app_id: Some(0),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            AppIdentity {
                app_id: Some(42),
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
        assert!(
            AppIdentity {
                app_id: Some(-1),
                bundle_identifier: Some("com.example.app".into()),
                platform: None
            }
            .validate()
            .is_ok()
        );
    }
}
