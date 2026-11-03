//! Shared Store download orchestration, preserving the CLI retry contract.

use super::{
    context::ApplicationContext,
    operation::{self, Stage},
};
use crate::{
    App, CatalogClient, Platform,
    catalog::AppNotFound,
    credentials::Account,
    fairplay_download_capture::write_download_capture,
    fairplay_ipa::require_model_diagnostic,
    store_download_product::{DownloadProductClient, LicenseRequired},
    store_login::{LoginInput, NativeAuthenticationBackend},
    store_purchase::{self, LicenseAlreadyExists, NativePurchaseBackend, PasswordTokenExpired},
    storefront::country_code_from_storefront,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DownloadRequest {
    pub app_id: Option<i64>,
    pub bundle_identifier: Option<String>,
    pub output: Option<PathBuf>,
    pub external_version_id: String,
    pub platform: Option<Platform>,
    pub purchase: bool,
    pub fairplay_decrypt: bool,
    pub fairplay_model: Option<PathBuf>,
    pub fairplay_output: Option<PathBuf>,
    pub fairplay_report: Option<PathBuf>,
    pub fairplay_force: bool,
    pub fairplay_capture_dir: Option<PathBuf>,
}

impl DownloadRequest {
    pub fn validate(&self) -> Result<()> {
        super::library::AppIdentity {
            app_id: self.app_id,
            bundle_identifier: self.bundle_identifier.clone(),
            platform: self.platform,
        }
        .validate()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DownloadResult {
    pub output: PathBuf,
    pub purchased: bool,
    pub success: bool,
    #[serde(rename = "decryptedOutput", skip_serializing_if = "Option::is_none")]
    pub decrypted_output: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<PathBuf>,
    #[serde(rename = "fairplayCapture", skip_serializing_if = "Option::is_none")]
    pub fairplay_capture: Option<PathBuf>,
}

pub fn download(context: &ApplicationContext, request: DownloadRequest) -> Result<DownloadResult> {
    request.validate()?;
    if let Some(active) = operation::current() {
        use sha2::{Digest, Sha256};
        let account = context.accounts().load()?;
        let identity = serde_json::to_vec(&(
            &account.directory_services_id,
            account.email.to_ascii_lowercase(),
            &account.store_front,
            request.app_id,
            &request.bundle_identifier,
            request.platform,
            &request.external_version_id,
        ))?;
        return active
            .with_transfer_identity(format!("{:x}", Sha256::digest(identity)))
            .run(|| download_inner(context, request));
    }
    download_inner(context, request)
}

fn download_inner(
    context: &ApplicationContext,
    request: DownloadRequest,
) -> Result<DownloadResult> {
    operation::stage(Stage::Preparing)?;
    let DownloadRequest {
        app_id,
        bundle_identifier,
        output,
        external_version_id,
        platform,
        purchase,
        fairplay_decrypt,
        fairplay_model,
        fairplay_output,
        fairplay_report,
        fairplay_force,
        fairplay_capture_dir,
    } = request;
    if app_id.is_none_or(|id| id <= 0) && bundle_identifier.as_deref().is_none_or(str::is_empty) {
        bail!("either the app ID or the bundle identifier must be specified");
    }
    let requested_platform = platform;
    let platform = requested_platform.unwrap_or(Platform::Iphone);
    let account_store = context.accounts();
    let mut account = account_store.load()?;
    operation::stage(Stage::Metadata)?;
    let backend =
        DownloadProductClient::open_in(&context.state_directory, context.credentials.clone())?;
    let catalog = CatalogClient::new()?;
    let ((app, path, captured_download), purchased) = retry_download(
        &mut account,
        purchase,
        |account| {
            let authentication_backend =
                NativeAuthenticationBackend::open_in(&context.state_directory)?;
            let refreshed = super::account::login(
                &authentication_backend,
                &account_store,
                LoginInput {
                    email: account.email.clone(),
                    password: account.password.clone(),
                    auth_code: String::new(),
                },
            )?;
            super::account::require_same_identity(account, &refreshed)?;
            Ok(refreshed)
        },
        |account, purchase_required, purchased| {
            let mut app = App {
                id: app_id.unwrap_or_default(),
                bundle_id: bundle_identifier.clone().unwrap_or_default(),
                ..App::default()
            };
            if let Some(bundle_id) = bundle_identifier.as_deref().filter(|id| !id.is_empty()) {
                let country = country_code_from_storefront(&account.store_front)?;
                match catalog.lookup(None, Some(bundle_id), country, requested_platform) {
                    Ok(found) => app = found,
                    Err(error) if app.id > 0 && error.downcast_ref::<AppNotFound>().is_some() => {}
                    Err(error) => return Err(error),
                }
            }
            operation::check()?;
            if *purchase_required {
                operation::stage(Stage::Licensing)?;
                let purchase_backend = NativePurchaseBackend::open_in(&context.state_directory)?;
                match store_purchase::purchase(&purchase_backend, account, &app, requested_platform)
                {
                    Ok(()) => {}
                    Err(error) if error.downcast_ref::<LicenseAlreadyExists>().is_some() => {}
                    Err(error) => return Err(error),
                }
                *purchase_required = false;
                *purchased = true;
            }
            operation::stage(Stage::Downloading)?;
            let mut captured_download = None;
            let result = if platform == Platform::Macos && fairplay_capture_dir.is_some() {
                match backend.download_macos_ipa_with_capture(
                    &catalog,
                    account,
                    &app,
                    &external_version_id,
                    output.as_deref(),
                ) {
                    Ok(download) => {
                        let path = download.path.clone();
                        captured_download = Some(download);
                        Ok(path)
                    }
                    Err(error) => Err(error),
                }
            } else if platform == Platform::Macos {
                backend.download_macos(
                    &catalog,
                    account,
                    &app,
                    &external_version_id,
                    output.as_deref(),
                )
            } else if fairplay_capture_dir.is_some() {
                match backend.download_ipa_with_capture(
                    &catalog,
                    account,
                    &app,
                    &external_version_id,
                    platform,
                    output.as_deref(),
                ) {
                    Ok(download) => {
                        let path = download.path.clone();
                        captured_download = Some(download);
                        Ok(path)
                    }
                    Err(error) => Err(error),
                }
            } else {
                backend.download_ipa(
                    &catalog,
                    account,
                    &app,
                    &external_version_id,
                    platform,
                    output.as_deref(),
                )
            };
            result.map(|path| (app, path, captured_download))
        },
    )?;
    let capture_output = if let Some(directory) = fairplay_capture_dir.as_deref() {
        let download = captured_download
            .as_ref()
            .context("missing paired FairPlay download capture")?;
        Some(write_download_capture(
            directory,
            download,
            &app,
            &external_version_id,
            platform,
        )?)
    } else {
        None
    };
    let decrypted = if fairplay_decrypt {
        let model = match fairplay_model.as_deref() {
            Some(model) => model,
            None => bail!("{}", require_model_diagnostic(&path)?),
        };
        let (decrypted_path, report_path) = fairplay_download_paths(
            &path,
            fairplay_output.as_deref(),
            fairplay_report.as_deref(),
        )?;
        super::fairplay::decrypt(
            &path,
            &decrypted_path,
            model,
            Some(&report_path),
            fairplay_force,
        )?;
        Some((decrypted_path, report_path))
    } else {
        None
    };

    Ok(DownloadResult {
        output: path,
        purchased,
        success: true,
        decrypted_output: decrypted.as_ref().map(|(path, _)| path.clone()),
        report: decrypted.map(|(_, report)| report),
        fairplay_capture: capture_output,
    })
}

pub fn fairplay_download_paths(
    package: &std::path::Path,
    output: Option<&std::path::Path>,
    report: Option<&std::path::Path>,
) -> Result<(PathBuf, PathBuf)> {
    if !package
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("ipa"))
    {
        bail!("FairPlay post-processing requires an IPA download");
    }
    Ok((
        output
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| package.with_extension("decrypted.ipa")),
        report
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| package.with_extension("decrypted.json")),
    ))
}

pub fn retry_download<T>(
    account: &mut Account,
    acquire_license: bool,
    mut refresh: impl FnMut(&Account) -> Result<Account>,
    mut attempt: impl FnMut(&Account, &mut bool, &mut bool) -> Result<T>,
) -> Result<(T, bool)> {
    let mut purchase_required = false;
    let mut purchased = false;
    let mut token_expired = false;
    for attempt_index in 0..3 {
        operation::check()?;
        let result = (|| {
            if token_expired {
                *account = refresh(account)?;
            }
            attempt(account, &mut purchase_required, &mut purchased)
        })();
        match result {
            Ok(output) => return Ok((output, purchased)),
            Err(error) if attempt_index < 2 => {
                if error.downcast_ref::<PasswordTokenExpired>().is_some() {
                    token_expired = true;
                } else if acquire_license && error.downcast_ref::<LicenseRequired>().is_some() {
                    purchase_required = true;
                    token_expired = false;
                } else {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("download retry loop always returns on its final attempt")
}
