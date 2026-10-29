//! Worker-side desktop session. GPUI never owns credential or protocol objects.

use anyhow::{Context, Result};
use ipatool_rs::{
    Platform,
    application::{
        account,
        context::ApplicationContext,
        download, fairplay,
        library::{self, AppIdentity},
        operation::Operation,
        tasks::{Artifact, ArtifactKind, JobOutcome, JobRequest},
    },
    credentials::Account,
    store_download_product::ListVersionsOutput,
    store_login::LoginInput,
    store_owned::OwnedAppsOutput,
};
use std::{
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[derive(Clone)]
pub struct AccountView {
    pub name: String,
    pub email: String,
    pub country: String,
}

/// Front-end services are replaceable in controller tests. The native
/// implementation remains the same shared application layer used by the CLI.
pub trait DesktopSession: Send + Sync {
    fn saved_model_count(&self) -> Result<usize> {
        Ok(0)
    }
    fn is_fixture(&self) -> bool {
        false
    }
    fn directory(&self) -> &std::path::Path;
    fn catalog(
        &self,
        query: &ipatool_rs::application::catalog::Query,
    ) -> Result<Vec<ipatool_rs::App>>;
    fn generation(&self) -> u64;
    fn account_identity(&self) -> Option<String>;
    fn load(&self, force_file: bool, passphrase: Option<String>) -> Result<Option<AccountView>>;
    fn login(
        &self,
        input: LoginInput,
        force_file: bool,
        passphrase: Option<String>,
    ) -> Result<AccountView>;
    fn revoke(&self) -> Result<()>;
    fn purchases(&self, page: usize, platform: Option<Platform>) -> Result<OwnedAppsOutput>;
    fn versions(&self, identity: &AppIdentity) -> Result<ListVersionsOutput>;
    fn version_metadata(
        &self,
        identity: &AppIdentity,
        version: &str,
    ) -> Result<ipatool_rs::ipa_metadata::VersionMetadata>;
    fn execute(
        &self,
        request: JobRequest,
        generation: u64,
        operation: &Operation,
    ) -> Result<JobOutcome>;
}

impl AccountView {
    fn from_account(account: &Account) -> Self {
        Self {
            name: account.name.clone(),
            email: account.email.clone(),
            country: ipatool_rs::storefront::country_code_from_storefront(&account.store_front)
                .unwrap_or("Unknown")
                .to_owned(),
        }
    }
}

pub struct Session {
    pub directory: PathBuf,
    context: Mutex<Option<ApplicationContext>>,
    generation: AtomicU64,
    file_store: AtomicBool,
    identity: Mutex<Option<String>>,
}

impl Session {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            context: Mutex::new(None),
            generation: AtomicU64::new(0),
            file_store: AtomicBool::new(false),
            identity: Mutex::new(None),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn fingerprint(account: &Account) -> String {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        for field in [
            &account.directory_services_id,
            &account.email.to_ascii_lowercase(),
            &account.store_front,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        format!("{:x}", hash.finalize())
    }

    pub fn account_identity(&self) -> Option<String> {
        self.identity
            .lock()
            .ok()
            .and_then(|identity| identity.clone())
    }

    fn configured(
        &self,
        force_file: bool,
        passphrase: Option<String>,
    ) -> Result<ApplicationContext> {
        ApplicationContext::configured(&self.directory, true, force_file, passphrase)
    }

    pub fn context(&self) -> Result<ApplicationContext> {
        self.context
            .lock()
            .map_err(|_| anyhow::anyhow!("account session lock failed"))?
            .clone()
            .context("load or sign in to an account before continuing")
    }

    pub fn load(
        &self,
        force_file: bool,
        passphrase: Option<String>,
    ) -> Result<Option<AccountView>> {
        let context = self.configured(force_file, passphrase)?;
        self.file_store.store(force_file, Ordering::Release);
        let account = context.accounts().load_optional()?;
        *self
            .identity
            .lock()
            .map_err(|_| anyhow::anyhow!("account identity lock failed"))? =
            account.as_ref().map(Self::fingerprint);
        *self
            .context
            .lock()
            .map_err(|_| anyhow::anyhow!("account session lock failed"))? = Some(context);
        self.generation.fetch_add(1, Ordering::AcqRel);
        Ok(account.as_ref().map(AccountView::from_account))
    }

    pub fn login(
        &self,
        input: LoginInput,
        force_file: bool,
        passphrase: Option<String>,
    ) -> Result<AccountView> {
        // Reuse an explicitly unlocked store during a verification challenge.
        let existing = self
            .context
            .lock()
            .map_err(|_| anyhow::anyhow!("account session lock failed"))?
            .clone();
        let context = match existing {
            Some(context)
                if self.file_store.load(Ordering::Acquire) == force_file
                    && passphrase.is_none() =>
            {
                context
            }
            _ => self.configured(force_file, passphrase)?,
        };
        self.file_store.store(force_file, Ordering::Release);
        let result = account::login_native(&context, input);
        *self
            .context
            .lock()
            .map_err(|_| anyhow::anyhow!("account session lock failed"))? = Some(context);
        let account = result?;
        *self
            .identity
            .lock()
            .map_err(|_| anyhow::anyhow!("account identity lock failed"))? =
            Some(Self::fingerprint(&account));
        self.generation.fetch_add(1, Ordering::AcqRel);
        Ok(AccountView::from_account(&account))
    }

    pub fn revoke(&self) -> Result<()> {
        self.context()?.accounts().revoke()?;
        self.generation.fetch_add(1, Ordering::AcqRel);
        *self
            .identity
            .lock()
            .map_err(|_| anyhow::anyhow!("account identity lock failed"))? = None;
        *self
            .context
            .lock()
            .map_err(|_| anyhow::anyhow!("account session lock failed"))? = None;
        Ok(())
    }

    pub fn purchases(&self, page: usize, platform: Option<Platform>) -> Result<OwnedAppsOutput> {
        library::purchases(&self.context()?, page, 25, platform)
    }

    pub fn versions(&self, identity: &AppIdentity) -> Result<ListVersionsOutput> {
        library::versions(&self.context()?, identity)
    }

    pub fn version_metadata(
        &self,
        identity: &AppIdentity,
        version: &str,
    ) -> Result<ipatool_rs::ipa_metadata::VersionMetadata> {
        library::version_metadata(&self.context()?, identity, version)
    }

    pub fn execute(
        &self,
        request: JobRequest,
        generation: u64,
        operation: &Operation,
    ) -> Result<JobOutcome> {
        if matches!(request, JobRequest::Download(_)) && generation != self.generation() {
            return Err(account::AccountChanged.into());
        }
        operation.run(|| match request {
            JobRequest::Download(request) => {
                let context = self.context()?;
                let account = context.accounts().load()?;
                if self.account_identity().as_deref() != Some(Self::fingerprint(&account).as_str()) {
                    return Err(account::AccountChanged.into());
                }
                let country = ipatool_rs::storefront::country_code_from_storefront(&account.store_front)?;
                ipatool_rs::application::operation::stage(ipatool_rs::application::operation::Stage::Metadata)?;
                ipatool_rs::application::catalog::lookup_for_account(&ipatool_rs::CatalogClient::new()?, request.app_id, request.bundle_identifier.as_deref(), country, request.platform)?;
                let result = download::download(&context, request)?;
                let mut artifacts = vec![Artifact { kind: ArtifactKind::Package, path: result.output }];
                if let Some(path) = result.decrypted_output { artifacts.push(Artifact { kind: ArtifactKind::DecryptedIpa, path }); }
                if let Some(path) = result.report { artifacts.push(Artifact { kind: ArtifactKind::Report, path }); }
                if let Some(path) = result.fairplay_capture { artifacts.push(Artifact { kind: ArtifactKind::Capture, path }); }
                Ok(JobOutcome { summary: "Package downloaded, processed, and published. An account entitlement was required.".into(), artifacts, details: None })
            }
            JobRequest::FairPlay(request) => fairplay::execute_in(request, &self.directory),
        })
    }
}

impl DesktopSession for Session {
    fn saved_model_count(&self) -> Result<usize> {
        ipatool_rs::application::fairplay_setup::SavedModels::new(&self.directory).count()
    }
    fn catalog(
        &self,
        query: &ipatool_rs::application::catalog::Query,
    ) -> Result<Vec<ipatool_rs::App>> {
        query.execute()
    }
    fn directory(&self) -> &std::path::Path {
        &self.directory
    }
    fn generation(&self) -> u64 {
        Session::generation(self)
    }
    fn account_identity(&self) -> Option<String> {
        Session::account_identity(self)
    }
    fn load(&self, force_file: bool, passphrase: Option<String>) -> Result<Option<AccountView>> {
        Session::load(self, force_file, passphrase)
    }
    fn login(
        &self,
        input: LoginInput,
        force_file: bool,
        passphrase: Option<String>,
    ) -> Result<AccountView> {
        Session::login(self, input, force_file, passphrase)
    }
    fn revoke(&self) -> Result<()> {
        Session::revoke(self)
    }
    fn purchases(&self, page: usize, platform: Option<Platform>) -> Result<OwnedAppsOutput> {
        Session::purchases(self, page, platform)
    }
    fn versions(&self, identity: &AppIdentity) -> Result<ListVersionsOutput> {
        Session::versions(self, identity)
    }
    fn version_metadata(
        &self,
        identity: &AppIdentity,
        version: &str,
    ) -> Result<ipatool_rs::ipa_metadata::VersionMetadata> {
        Session::version_metadata(self, identity, version)
    }
    fn execute(
        &self,
        request: JobRequest,
        generation: u64,
        operation: &Operation,
    ) -> Result<JobOutcome> {
        Session::execute(self, request, generation, operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipatool_rs::credentials::{CredentialStore, CredentialUnlockRequired, KBSYNC_CACHE_KEY};

    #[test]
    fn encrypted_store_unlock_is_instance_scoped_and_wrong_unlock_does_not_replace_it() {
        let directory = tempfile::tempdir().unwrap();
        let context = ApplicationContext::configured(
            directory.path(),
            false,
            true,
            Some("fixture-store-passphrase".into()),
        )
        .unwrap();
        let mut account = Account::default();
        account.email = "fixture@example.invalid".into();
        account.name = "Fixture Account".into();
        account.store_front = "143441".into();
        account.password_token = "fixture-token".into();
        context.accounts().save(&account).unwrap();
        let session = Session::new(directory.path().to_path_buf());
        assert!(
            session
                .load(true, None)
                .err()
                .unwrap()
                .is::<CredentialUnlockRequired>()
        );
        let summary = session
            .load(true, Some("fixture-store-passphrase".into()))
            .unwrap()
            .unwrap();
        assert_eq!(summary.country, "US");
        let generation = session.generation();
        assert!(
            session
                .load(true, Some("wrong-fixture-passphrase".into()))
                .is_err()
        );
        assert_eq!(session.generation(), generation);
        assert_eq!(
            session.context().unwrap().accounts().load().unwrap().email,
            account.email
        );
    }

    #[test]
    fn revoke_removes_only_saved_credentials_and_does_not_delete_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let context = ApplicationContext::configured(
            directory.path(),
            false,
            true,
            Some("fixture-store-passphrase".into()),
        )
        .unwrap();
        context.accounts().save(&Account::default()).unwrap();
        context
            .credentials
            .set(KBSYNC_CACHE_KEY, b"fixture-cache")
            .unwrap();
        let output = directory.path().join("fixture.ipa");
        std::fs::write(&output, b"fixture-package").unwrap();
        let session = Session::new(directory.path().to_path_buf());
        session
            .load(true, Some("fixture-store-passphrase".into()))
            .unwrap();
        session.revoke().unwrap();
        assert!(session.context().is_err());
        assert!(context.accounts().load_optional().unwrap().is_none());
        assert!(context.credentials.get(KBSYNC_CACHE_KEY).unwrap().is_none());
        assert_eq!(std::fs::read(output).unwrap(), b"fixture-package");
    }

    #[test]
    fn changed_account_generation_rejects_download_before_credentials_or_network_access() {
        let directory = tempfile::tempdir().unwrap();
        let session = Session::new(directory.path().to_path_buf());
        let request = JobRequest::Download(download::DownloadRequest {
            app_id: Some(42),
            ..Default::default()
        });
        let error = session
            .execute(request, 1, &Operation::default())
            .unwrap_err();
        assert!(error.to_string().contains("account changed"));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn externally_replaced_account_or_storefront_is_rejected_before_network_access() {
        let directory = tempfile::tempdir().unwrap();
        let context = ApplicationContext::configured(
            directory.path(),
            false,
            true,
            Some("fixture-passphrase".into()),
        )
        .unwrap();
        let mut account = Account::default();
        account.email = "fixture@example.invalid".into();
        account.directory_services_id = "123".into();
        account.store_front = "143441".into();
        context.accounts().save(&account).unwrap();
        let session = Session::new(directory.path().to_path_buf());
        session
            .load(true, Some("fixture-passphrase".into()))
            .unwrap();
        let generation = session.generation();
        for (email, storefront) in [
            ("other@example.invalid", "143441"),
            ("fixture@example.invalid", "143444"),
        ] {
            account.email = email.into();
            account.store_front = storefront.into();
            context.accounts().save(&account).unwrap();
            let error = session
                .execute(
                    JobRequest::Download(download::DownloadRequest {
                        app_id: Some(42),
                        ..Default::default()
                    }),
                    generation,
                    &Operation::default(),
                )
                .unwrap_err();
            assert!(error.to_string().contains("account changed"));
            assert_eq!(generation, session.generation());
        }
    }
}
