//! Opt-in native UI fixtures. Compiled only with `gui-test`; never use Apple services.

use super::session::{AccountView, DesktopSession};
use anyhow::{Context, Result, bail};
use ipatool_rs::{
    App, Platform,
    application::{
        catalog::Query,
        fairplay::FairPlayRequest,
        library::AppIdentity,
        operation::{self, Operation, Progress, Stage},
        tasks::{Artifact, ArtifactKind, JobOutcome, JobRequest},
    },
    credentials::CredentialUnlockRequired,
    ipa_metadata::VersionMetadata,
    store_download_product::ListVersionsOutput,
    store_login::{AuthCodeRequired, LoginInput},
    store_owned::OwnedAppsOutput,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

pub(super) const MARKER: &str = ".ipatool-gui-fixtures";

/// Require both an explicit test-build opt-in and an independently created
/// marker. A misspelled fixture configuration must never fall back to Apple.
pub(super) fn from_environment(directory: &Path) -> Result<Option<Arc<dyn DesktopSession>>> {
    let Some(mode) = std::env::var_os("IPATOOL_GUI_PREVIEW") else {
        return Ok(None);
    };
    if mode != "fixtures" || std::fs::read(directory.join(MARKER))? != b"local-only\n" {
        bail!(
            "fixture preview requires IPATOOL_GUI_PREVIEW=fixtures and a local-only state marker"
        );
    }
    Ok(Some(Arc::new(PreviewSession::new(
        directory.to_path_buf(),
    )?)))
}

struct PreviewSession {
    directory: PathBuf,
    generation: AtomicU64,
    authenticated: AtomicBool,
    expired_once: AtomicBool,
}

impl PreviewSession {
    fn new(directory: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(directory.join("fixture-output"))?;
        Ok(Self {
            directory,
            generation: AtomicU64::new(0),
            authenticated: AtomicBool::new(false),
            expired_once: AtomicBool::new(false),
        })
    }

    fn account(&self) -> AccountView {
        self.authenticated.store(true, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
        AccountView {
            name: "Fixture Account".into(),
            email: "fixture@example.invalid".into(),
            country: "US".into(),
        }
    }

    fn apps(page: usize) -> Vec<App> {
        (0..25)
            .map(|offset| {
                let number = (page.saturating_sub(1)) * 25 + offset + 1;
                App {
                    id: 400_000 + number as i64,
                    name: format!("Fixture Application {number:03}"),
                    bundle_id: format!("invalid.example.fixture.app{number:03}"),
                    version: "1.2.3".into(),
                    platforms: Some(vec![Platform::Iphone, Platform::Macos]),
                    ..Default::default()
                }
            })
            .collect()
    }

    fn wait(milliseconds: u64) -> Result<()> {
        for _ in 0..milliseconds.div_ceil(100) {
            operation::check()?;
            std::thread::sleep(Duration::from_millis(100));
        }
        operation::check()
    }
}

impl DesktopSession for PreviewSession {
    fn is_fixture(&self) -> bool {
        true
    }
    fn directory(&self) -> &Path {
        &self.directory
    }
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
    fn account_identity(&self) -> Option<String> {
        self.authenticated
            .load(Ordering::SeqCst)
            .then(|| "fixture-account-and-storefront".into())
    }
    fn catalog(&self, _: &Query) -> Result<Vec<App>> {
        Self::wait(400)?;
        Ok(Self::apps(1))
    }
    fn load(&self, force_file: bool, passphrase: Option<String>) -> Result<Option<AccountView>> {
        Self::wait(1000)?;
        if force_file && passphrase.as_deref() != Some("fixture-store-passphrase") {
            return Err(CredentialUnlockRequired.into());
        }
        Ok(Some(self.account()))
    }
    fn login(&self, input: LoginInput, _: bool, _: Option<String>) -> Result<AccountView> {
        Self::wait(1000)?;
        if input.email != "fixture@example.invalid" || input.password != "fixture-password" {
            bail!("Apple authentication failed: fixture credentials required");
        }
        if input.auth_code != "123456" {
            return Err(AuthCodeRequired.into());
        }
        Ok(self.account())
    }
    fn revoke(&self) -> Result<()> {
        Self::wait(3000)?;
        self.authenticated.store(false, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn purchases(&self, page: usize, _: Option<Platform>) -> Result<OwnedAppsOutput> {
        Self::wait(1500)?;
        Ok(OwnedAppsOutput {
            count: 25,
            total_count: 150,
            page,
            apps: Self::apps(page),
        })
    }
    fn versions(&self, _: &AppIdentity) -> Result<ListVersionsOutput> {
        Self::wait(1500)?;
        Ok(ListVersionsOutput {
            external_version_identifiers: (100..120).map(|id| id.to_string()).collect(),
            latest_external_version_id: "119".into(),
        })
    }
    fn version_metadata(&self, _: &AppIdentity, _: &str) -> Result<VersionMetadata> {
        Self::wait(1000)?;
        Ok(VersionMetadata {
            display_version: "1.2.3 (fixture)".into(),
            release_date: "2026-10-28T00:00:00Z".into(),
        })
    }
    fn execute(
        &self,
        request: JobRequest,
        generation: u64,
        operation: &Operation,
    ) -> Result<JobOutcome> {
        operation.run(|| match request {
            JobRequest::Download(request) => {
                if !self.authenticated.load(Ordering::SeqCst) || generation != self.generation() { return Err(ipatool_rs::store_purchase::PasswordTokenExpired.into()); }
                if request.external_version_id == "100" && !self.expired_once.swap(true, Ordering::SeqCst) { return Err(ipatool_rs::store_purchase::PasswordTokenExpired.into()); }
                for completed in 0..=200 {
                    operation.check()?;
                    operation.report(Progress { stage: Stage::Downloading, completed, total: Some(200) });
                    Self::wait(100)?;
                }
                let directory = tempfile::Builder::new().prefix("fixture-job-").tempdir_in(self.directory.join("fixture-output"))?;
                let path = directory.path().join("fixture.ipa");
                operation::publish(|| write_fixture_package(&path))?;
                let _ = directory.keep();
                Ok(JobOutcome { summary: "Fixture ZIP published. It is synthetic and contains no encrypted account package.".into(), artifacts: vec![Artifact { kind: ArtifactKind::Package, path }], details: None })
            }
            JobRequest::FairPlay(request @ FairPlayRequest::Inspect { .. }) => ipatool_rs::application::fairplay::execute(request),
            JobRequest::FairPlay(FairPlayRequest::DecryptSaved { .. }) => Err(ipatool_rs::application::fairplay_setup::ModelProblem::Missing.into()),
            JobRequest::FairPlay(_) => bail!("fixture preview does not run private FairPlay processing"),
        })
    }
}

fn write_fixture_package(path: &Path) -> Result<()> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().context("fixture path has no parent")?)?;
    {
        let mut zip = zip::ZipWriter::new(temporary.as_file_mut());
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Payload/Fixture.app/Info.plist", options)?;
        zip.write_all(br#"<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Fixture</string><key>CFBundleIdentifier</key><string>invalid.example.fixture</string></dict></plist>"#)?;
        zip.start_file("Payload/Fixture.app/Fixture", options)?;
        // A synthetic arm64 Mach-O header with no load commands or encryption.
        for value in [0xfeedfacf_u32, 0x0100000c, 0, 2, 0, 0, 0, 0] {
            zip.write_all(&value.to_le_bytes())?;
        }
        zip.finish()?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_package_is_synthetic_and_never_replaces_an_existing_output() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.ipa");
        write_fixture_package(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            zip::ZipArchive::new(std::io::Cursor::new(&before))
                .unwrap()
                .len(),
            2
        );
        assert!(write_fixture_package(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
