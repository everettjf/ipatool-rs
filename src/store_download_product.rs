//! Native Store download-product requests and version-history metadata.

use std::{
    error::Error,
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Method,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use zeroize::Zeroize;

use crate::{
    App, CatalogClient, Platform,
    credentials::{Account, CredentialStore, KBSYNC_CACHE_KEY, open_system_keychain},
    download_file::download_file,
    download_package::{package_platform, validate_ipa_platform},
    host::hardware_mac_address,
    ipa_metadata::{self, VersionMetadata},
    ipa_patch::patch_ipa,
    mac_package::{download_mac_package, read_mac_package_version_metadata},
    mac_preflight,
    sap_assets::SapAssetBundle,
    state::prepare_state_directory_from_environment,
    store_agent::create_kbsync,
    store_backend::{DEFAULT_USER_AGENT, PURCHASE_USER_AGENT},
    store_purchase::PasswordTokenExpired,
    storefront::country_code_from_storefront,
    transport::{DEFAULT_AUTHENTICATION_TIMEOUT, Request, Response, Transport},
};

const VOLUME_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";
const REDOWNLOAD_URL: &str = "https://downloaddispatch.itunes.apple.com/r/redownload";
const UPDATE_URL: &str = "https://downloaddispatch.itunes.apple.com/up/updateProduct";
const ENT_DOWNLOAD_URL: &str =
    "https://downloaddispatch.itunes.apple.com/WebObjects/DownloadDispatch.woa/wa/ent/download";
type Sender = dyn Fn(Request) -> Result<Response> + Send + Sync;
type KbsyncGenerator = dyn Fn([u8; 6], u64) -> Result<Vec<u8>> + Send + Sync;

#[derive(Debug)]
pub struct LicenseRequired;

impl fmt::Display for LicenseRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a license is required for this app")
    }
}

impl Error for LicenseRequired {}

pub struct DownloadProductClient {
    hardware_id: [u8; 6],
    sender: Arc<Sender>,
    kbsync_generator: Option<Arc<KbsyncGenerator>>,
    kbsync_cache: Mutex<Option<KbsyncCacheEntry>>,
    credentials: Option<Arc<dyn CredentialStore + Send + Sync>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct KbsyncCacheEntry {
    dsid: u64,
    guid: String,
    data: String,
}

impl Drop for KbsyncCacheEntry {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DownloadProductResult {
    #[serde(default, rename = "failureType")]
    pub failure_type: String,
    #[serde(default, rename = "customerMessage")]
    pub customer_message: String,
    #[serde(default, rename = "songList")]
    pub items: Vec<DownloadItem>,
}

/// Private request/response material from one successful ent/download call.
#[derive(Clone)]
pub struct FairPlayDownloadCapture {
    pub kbsync: Vec<u8>,
    pub keybag: Vec<u8>,
}

impl fmt::Debug for FairPlayDownloadCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FairPlayDownloadCapture")
            .field("kbsync_bytes", &self.kbsync.len())
            .field("keybag_bytes", &self.keybag.len())
            .finish()
    }
}

impl Drop for FairPlayDownloadCapture {
    fn drop(&mut self) {
        self.kbsync.zeroize();
        self.keybag.zeroize();
    }
}

pub struct CapturedIpaDownload {
    pub path: PathBuf,
    pub sinfs: Vec<Vec<u8>>,
    pub capture: FairPlayDownloadCapture,
}

impl fmt::Debug for CapturedIpaDownload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedIpaDownload")
            .field("path", &self.path)
            .field("sinf_count", &self.sinfs.len())
            .field("capture", &self.capture)
            .finish()
    }
}

impl Drop for CapturedIpaDownload {
    fn drop(&mut self) {
        for sinf in &mut self.sinfs {
            sinf.zeroize();
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DownloadItem {
    #[serde(default, rename = "URL")]
    pub url: String,
    #[serde(default, rename = "preflightPackageURL")]
    pub preflight_package_url: String,
    #[serde(default, rename = "artworkURL")]
    pub artwork_url: String,
    #[serde(default)]
    pub sinfs: Vec<plist::Value>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListVersionsOutput {
    #[serde(rename = "externalVersionIdentifiers")]
    pub external_version_identifiers: Vec<String>,
    #[serde(rename = "latestExternalVersionID")]
    pub latest_external_version_id: String,
}

#[derive(Clone, Copy)]
enum Endpoint {
    Volume,
    Redownload,
    Update,
}

impl DownloadProductClient {
    pub fn open() -> Result<Self> {
        let hardware_id = hardware_mac_address().context("read Store hardware identity")?;
        let state_directory = prepare_state_directory_from_environment()?;
        let transport = Arc::new(Transport::with_cookies(&state_directory)?);
        let credentials = Arc::from(open_system_keychain()?);
        Ok(
            Self::with_sender(hardware_id, move |request| transport.send(request))
                .with_credential_store(credentials)
                .with_kbsync_generator(|hardware, dsid| {
                    let bundle =
                        SapAssetBundle::load_or_download().context("load StoreAgent assets")?;
                    create_kbsync(&bundle, &hardware, dsid).context("generate download KBSync")
                }),
        )
    }

    pub fn with_sender(
        hardware_id: [u8; 6],
        sender: impl Fn(Request) -> Result<Response> + Send + Sync + 'static,
    ) -> Self {
        Self {
            hardware_id,
            sender: Arc::new(sender),
            kbsync_generator: None,
            kbsync_cache: Mutex::new(None),
            credentials: None,
        }
    }

    pub fn with_credential_store(
        mut self,
        credentials: Arc<dyn CredentialStore + Send + Sync>,
    ) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn with_kbsync_generator(
        mut self,
        generator: impl Fn([u8; 6], u64) -> Result<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        self.kbsync_generator = Some(Arc::new(generator));
        self
    }

    /// Download an owned mobile app, validate its platform, and publish a patched IPA.
    pub fn download_ipa(
        &self,
        catalog: &CatalogClient,
        account: &Account,
        app: &App,
        version: &str,
        platform: Platform,
        output: Option<&Path>,
    ) -> Result<PathBuf> {
        if matches!(platform, Platform::Macos | Platform::Unknown) {
            bail!(
                "mobile IPA download requires an iOS, iPadOS, tvOS, watchOS, or visionOS platform"
            );
        }
        let country = country_code_from_storefront(&account.store_front)?;
        let response = self.send_product(account, app, version, || {
            catalog.latest_external_version_id(app, country, platform)
        })?;
        let item = checked_item(&response)?;
        self.download_mobile_item(account, app, item, platform, output)
    }

    /// Download a mobile IPA while retaining the paired ent/download KBSync,
    /// keybag, and SINF values for a private diagnostic capture.
    pub fn download_ipa_with_capture(
        &self,
        catalog: &CatalogClient,
        account: &Account,
        app: &App,
        version: &str,
        platform: Platform,
        output: Option<&Path>,
    ) -> Result<CapturedIpaDownload> {
        if matches!(platform, Platform::Macos | Platform::Unknown) {
            bail!("FairPlay capture requires a mobile IPA platform");
        }
        let country = country_code_from_storefront(&account.store_front)?;
        let response = self.send_product(account, app, version, || {
            catalog.latest_external_version_id(app, country, platform)
        })?;
        let item = checked_item(&response)?;
        self.captured_mobile_item(account, app, item, &response, platform, output)
    }

    /// Capture a macOS Store offer only when it resolves to a universal IPA.
    pub fn download_macos_ipa_with_capture(
        &self,
        catalog: &CatalogClient,
        account: &Account,
        app: &App,
        version: &str,
        output: Option<&Path>,
    ) -> Result<CapturedIpaDownload> {
        let country = country_code_from_storefront(&account.store_front)?;
        let selected = if version.is_empty() {
            catalog.latest_external_version_id(app, country, Platform::Macos)?
        } else {
            version.to_owned()
        };
        let response = self.send_product(account, app, &selected, || Ok(selected.clone()))?;
        let item = checked_item(&response)?;
        if package_platform(Platform::Macos, item)? != Platform::Iphone {
            bail!("FairPlay download capture requires an IPA package; the macOS offer is a PKG");
        }
        self.captured_mobile_item(account, app, item, &response, Platform::Iphone, output)
    }

    fn captured_mobile_item(
        &self,
        account: &Account,
        app: &App,
        item: &DownloadItem,
        response: &DownloadProductResponse,
        platform: Platform,
        output: Option<&Path>,
    ) -> Result<CapturedIpaDownload> {
        let capture = response.capture.clone().context(
            "FairPlay capture requires a successful ent/download response containing a keybag",
        )?;
        let sinfs = item
            .sinfs
            .iter()
            .map(|sinf| {
                let bytes = sinf
                    .as_dictionary()
                    .and_then(|fields| fields.get("sinf"))
                    .and_then(plist::Value::as_data)
                    .context("Store SINF entry has no data")?;
                if bytes.is_empty() {
                    bail!("Store SINF entry is empty");
                }
                Ok(bytes.to_vec())
            })
            .collect::<Result<Vec<_>>>()?;
        if sinfs.is_empty() {
            bail!("download returned no SINF for the FairPlay capture");
        }
        let path = self.download_mobile_item(account, app, item, platform, output)?;
        Ok(CapturedIpaDownload {
            path,
            sinfs,
            capture,
        })
    }

    /// Download the selected macOS offer, including universal apps supplied as IPAs.
    pub fn download_macos(
        &self,
        catalog: &CatalogClient,
        account: &Account,
        app: &App,
        version: &str,
        output: Option<&Path>,
    ) -> Result<PathBuf> {
        let country = country_code_from_storefront(&account.store_front)?;
        let selected = if version.is_empty() {
            catalog.latest_external_version_id(app, country, Platform::Macos)?
        } else {
            version.to_owned()
        };
        let response = self.send_product(account, app, &selected, || Ok(selected.clone()))?;
        let item = checked_item(&response)?;
        match package_platform(Platform::Macos, item)? {
            Platform::Iphone => {
                self.download_mobile_item(account, app, item, Platform::Iphone, output)
            }
            Platform::Macos => {
                let display_version = display_version(item);
                let destination = package_destination(app, display_version, output, "pkg")?;
                download_mac_package(item, &destination, &self.hardware_id)?;
                Ok(destination)
            }
            _ => bail!("unexpected platform in macOS download metadata"),
        }
    }

    fn download_mobile_item(
        &self,
        account: &Account,
        app: &App,
        item: &DownloadItem,
        platform: Platform,
        output: Option<&Path>,
    ) -> Result<PathBuf> {
        if item.url.is_empty() {
            bail!("App Store download response has no IPA URL");
        }
        let destination = package_destination(app, display_version(item), output, "ipa")?;
        let mut temporary = destination.as_os_str().to_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        download_file(&item.url, &temporary).context("download IPA package")?;
        validate_ipa_platform(&temporary, platform).context("validate downloaded IPA platform")?;
        let artwork = fetch_artwork(&item.artwork_url)?;
        patch_ipa(
            &temporary,
            &destination,
            &item.metadata,
            &account.email,
            &artwork,
            &item.sinfs,
        )
        .context("patch downloaded IPA")?;
        fs::remove_file(&temporary).context("remove temporary IPA")?;
        Ok(destination)
    }

    /// Select a version and read its history from the authenticated Store response.
    pub fn list_versions(
        &self,
        catalog: &CatalogClient,
        account: &Account,
        app: &App,
        platform: Platform,
    ) -> Result<ListVersionsOutput> {
        if app.id <= 0 || platform == Platform::Unknown {
            bail!("a valid app ID and platform are required");
        }
        let country = country_code_from_storefront(&account.store_front)?;
        let version = if matches!(
            platform,
            Platform::Macos | Platform::Appletv | Platform::Watchos | Platform::Visionos
        ) {
            catalog.latest_external_version_id(app, country, platform)?
        } else {
            String::new()
        };
        let response = self.send_product(account, app, &version, || {
            catalog.latest_external_version_id(app, country, platform)
        })?;
        let item = checked_item(&response)?;
        let metadata = &item.metadata;
        let identifiers = metadata
            .get("softwareVersionExternalIdentifiers")
            .and_then(Value::as_array)
            .context("download metadata has no version identifiers")?;
        let external_version_identifiers = identifiers
            .iter()
            .map(version_string)
            .collect::<Result<Vec<_>>>()?;
        let latest_external_version_id = metadata
            .get("softwareVersionExternalIdentifier")
            .context("download metadata has no latest version")
            .and_then(version_string)?;
        Ok(ListVersionsOutput {
            external_version_identifiers,
            latest_external_version_id,
        })
    }

    pub fn get_version_metadata(
        &self,
        account: &Account,
        app: &App,
        version: &str,
        platform: Option<Platform>,
    ) -> Result<VersionMetadata> {
        self.get_version_metadata_with(
            account,
            app,
            version,
            platform,
            (
                ipa_metadata::read_version_metadata_from_ipa,
                mac_preflight::read_preflight_version_metadata,
                |item, bundle_id| {
                    read_mac_package_version_metadata(item, &self.hardware_id, bundle_id)
                },
            ),
        )
    }

    fn get_version_metadata_with(
        &self,
        account: &Account,
        app: &App,
        version: &str,
        platform: Option<Platform>,
        readers: (
            impl FnOnce(&str) -> Result<VersionMetadata>,
            impl FnOnce(&str, &str) -> Result<VersionMetadata>,
            impl FnOnce(&DownloadItem, &str) -> Result<VersionMetadata>,
        ),
    ) -> Result<VersionMetadata> {
        let (read_ipa, read_preflight, read_mac_package) = readers;
        if version.is_empty() || platform == Some(Platform::Unknown) {
            bail!("a version ID and valid platform are required");
        }
        let response = self.send_product(account, app, version, || Ok(version.to_owned()))?;
        let item = checked_item(&response)?;
        let software_platform = item
            .metadata
            .get("software-platform")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let product_type = item
            .metadata
            .get("product-type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let response_is_mac = software_platform.eq_ignore_ascii_case("macos")
            || (software_platform.is_empty() && product_type.eq_ignore_ascii_case("mac-os-app"));
        let selected_platform = platform.unwrap_or(if response_is_mac {
            Platform::Macos
        } else {
            Platform::Iphone
        });
        if selected_platform == Platform::Macos
            && !software_platform.eq_ignore_ascii_case("ios")
            && !(software_platform.is_empty() && product_type.eq_ignore_ascii_case("ios-app"))
        {
            let has_dp_info = item.sinfs.iter().any(|sinf| {
                sinf.as_dictionary()
                    .and_then(|fields| fields.get("dpInfo"))
                    .and_then(plist::Value::as_data)
                    .is_some_and(|data| !data.is_empty())
            });
            let bundle_id = if app.bundle_id.is_empty() {
                item.metadata
                    .get("softwareVersionBundleId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            } else {
                &app.bundle_id
            };
            if !has_dp_info && !item.preflight_package_url.is_empty() {
                return read_preflight(&item.preflight_package_url, bundle_id)
                    .context("read version metadata from Mac preflight package");
            }
            return read_mac_package(item, bundle_id)
                .context("read version metadata from decrypted Mac package");
        }
        if item.url.is_empty() {
            bail!("App Store download response has no IPA URL");
        }
        read_ipa(&item.url).context("read version metadata from IPA")
    }

    /// Prefer ent/download, then try volumeStore, redownload, and update.
    pub fn send_product(
        &self,
        account: &Account,
        app: &App,
        version: &str,
        fallback_version: impl Fn() -> Result<String>,
    ) -> Result<DownloadProductResponse> {
        if app.id <= 0 {
            bail!("app ID is required for download metadata");
        }
        let mut bag = None;
        if let Some(generator) = &self.kbsync_generator
            && let Ok(fetched) = self.fetch_bag()
        {
            if let Some(endpoint) = fetched.ent_download.as_deref() {
                let selected = if version.is_empty() {
                    fallback_version()
                } else {
                    Ok(version.to_owned())
                };
                if let Ok(selected) = selected
                    && let Ok(response) =
                        self.send_ent_download(endpoint, account, app, &selected, generator)
                {
                    return Ok(response);
                }
            }
            bag = Some(fetched);
        }
        let primary = self.send_request(Endpoint::Volume, account, app, version)?;
        if !primary.is_empty_or_unavailable() {
            return Ok(primary);
        }
        let bag = match bag {
            Some(bag) => bag,
            None => self.fetch_bag()?,
        };
        let Some(redownload_url) = bag.redownload.as_deref() else {
            return Ok(primary);
        };
        if redownload_url != REDOWNLOAD_URL {
            bail!("invalid redownload endpoint in Store bag");
        }
        let selected_version = if version.is_empty() {
            fallback_version().context("resolve version for redownload")?
        } else {
            version.to_owned()
        };
        let redownload =
            self.send_request(Endpoint::Redownload, account, app, &selected_version)?;
        if (redownload.is_empty_or_unavailable() || redownload.is_empty_server_error())
            && !selected_version.is_empty()
            && let Some(update_url) = bag.update.as_deref()
        {
            if update_url != UPDATE_URL {
                bail!("invalid update endpoint in Store bag");
            }
            let update = self.send_request(Endpoint::Update, account, app, &selected_version)?;
            validate_fallback(&update, app, &selected_version)?;
            return Ok(update);
        }
        validate_fallback(&redownload, app, &selected_version)?;
        Ok(redownload)
    }

    fn fetch_bag(&self) -> Result<DownloadBag> {
        let guid = self.guid();
        let url = Url::parse(&format!(
            "https://init.itunes.apple.com/bag.xml?guid={guid}"
        ))?;
        let mut request = Request::get(url);
        request
            .headers
            .insert("Accept", HeaderValue::from_static("application/xml"));
        request
            .headers
            .insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        request.no_redirects = true;
        request.timeout = Some(DEFAULT_AUTHENTICATION_TIMEOUT);
        let response = (self.sender)(request).context("request Store URL bag")?;
        response.ensure_success()?;
        let value: Value = response.plist(false)?;
        let bag = value
            .get("urlBag")
            .context("Store URL bag is missing urlBag")?;
        Ok(DownloadBag {
            ent_download: bag
                .get("volumeStoreDownloadProduct")
                .and_then(Value::as_str)
                .map(str::to_owned),
            redownload: bag
                .get("redownloadProduct")
                .and_then(Value::as_str)
                .map(str::to_owned),
            update: bag
                .get("updateProduct")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    fn send_ent_download(
        &self,
        endpoint: &str,
        account: &Account,
        app: &App,
        version: &str,
        generator: &Arc<KbsyncGenerator>,
    ) -> Result<DownloadProductResponse> {
        if endpoint != ENT_DOWNLOAD_URL {
            bail!("invalid ent/download endpoint in Store bag");
        }
        let dsid = account
            .directory_services_id
            .parse::<u64>()
            .context("ent/download requires a numeric account DSID")?;
        if dsid == 0 || version.is_empty() {
            bail!("ent/download requires an account DSID and version ID");
        }
        let guid = self.guid();
        if let Some(cached) = self.cached_kbsync(dsid, &guid) {
            match self.send_ent_download_request(account, app, version, &guid, &cached) {
                Ok(response) => return Ok(response),
                Err(_) => self.invalidate_kbsync(dsid, &guid, &cached),
            }
        }
        let blob = generator(self.hardware_id, dsid)?;
        if blob.is_empty() {
            bail!("KBSync generator returned an empty blob");
        }
        let data = STANDARD.encode(blob);
        let response = self.send_ent_download_request(account, app, version, &guid, &data)?;
        self.store_kbsync(dsid, &guid, &data);
        Ok(response)
    }

    fn send_ent_download_request(
        &self,
        account: &Account,
        app: &App,
        version: &str,
        guid: &str,
        kbsync: &str,
    ) -> Result<DownloadProductResponse> {
        let serial = [
            0x54,
            0xc8,
            0xb0,
            0xa9,
            0x88,
            self.hardware_id[2],
            self.hardware_id[3],
            self.hardware_id[4],
            self.hardware_id[5],
        ];
        let parameters = serde_json::json!({
            "creditDisplay": "",
            "guid": guid,
            "kbsync": kbsync,
            "salableAdamId": app.id.to_string(),
            "serialNumber": STANDARD.encode(serial),
            "externalVersionId": version,
        });
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &parameters).context("encode ent/download plist")?;
        let mut url = Url::parse(ENT_DOWNLOAD_URL)?;
        url.query_pairs_mut().append_pair("guid", guid);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
        );
        headers.insert(
            "iCloud-DSID",
            HeaderValue::from_str(&account.directory_services_id)?,
        );
        headers.insert(
            "X-Dsid",
            HeaderValue::from_str(&account.directory_services_id)?,
        );
        headers.insert(
            "X-Apple-Store-Front",
            HeaderValue::from_str(&account.store_front)?,
        );
        headers.insert("X-Token", HeaderValue::from_str(&account.password_token)?);
        headers.insert(USER_AGENT, HeaderValue::from_static(PURCHASE_USER_AGENT));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("br, gzip, deflate"),
        );
        headers.insert("Accept-Language", HeaderValue::from_static("en"));
        headers.insert(
            "X-Apple-Client-Application",
            HeaderValue::from_static("me.majd.ipatool"),
        );
        headers.insert("X-Apple-TZ", HeaderValue::from_static("0"));
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string())?,
        );
        let response = (self.sender)(Request {
            method: Method::POST,
            url,
            headers,
            body: Some(body),
            no_redirects: true,
            timeout: Some(DEFAULT_AUTHENTICATION_TIMEOUT),
        })
        .context("send ent/download request")?;
        let data: DownloadProductResult = response.plist(false)?;
        let keybag = response
            .plist::<plist::Value>(false)
            .ok()
            .and_then(|value| response_keybag(&value));
        let capture = keybag.and_then(|keybag| {
            STANDARD
                .decode(kbsync)
                .ok()
                .map(|kbsync| FairPlayDownloadCapture { kbsync, keybag })
        });
        let result = DownloadProductResponse {
            status: response.status,
            data,
            capture,
        };
        validate_fallback(&result, app, version)?;
        if result.data.failure_type.is_empty()
            && result
                .data
                .items
                .first()
                .is_none_or(|item| item.url.is_empty())
        {
            bail!("ent/download response has no package URL");
        }
        if !result.data.failure_type.is_empty() {
            bail!("ent/download returned failure {}", result.data.failure_type);
        }
        Ok(result)
    }

    fn cached_kbsync(&self, dsid: u64, guid: &str) -> Option<String> {
        let mut guard = self.kbsync_cache.lock().ok()?;
        if let Some(entry) = guard.as_ref()
            && entry.dsid == dsid
            && entry.guid == guid
            && !entry.data.is_empty()
        {
            return Some(entry.data.clone());
        }
        let encoded = self.credentials.as_ref()?.get(KBSYNC_CACHE_KEY).ok()??;
        let entry: KbsyncCacheEntry = serde_json::from_slice(&encoded).ok()?;
        if entry.dsid != dsid || entry.guid != guid {
            return None;
        }
        if STANDARD.decode(&entry.data).ok()?.is_empty() {
            return None;
        }
        let data = entry.data.clone();
        *guard = Some(entry);
        Some(data)
    }

    fn store_kbsync(&self, dsid: u64, guid: &str, data: &str) {
        let entry = KbsyncCacheEntry {
            dsid,
            guid: guid.to_owned(),
            data: data.to_owned(),
        };
        if let Ok(mut guard) = self.kbsync_cache.lock() {
            *guard = Some(entry.clone());
        }
        if let Some(credentials) = &self.credentials
            && let Ok(encoded) = serde_json::to_vec(&entry)
        {
            let _ = credentials.set(KBSYNC_CACHE_KEY, &encoded);
        }
    }

    fn invalidate_kbsync(&self, dsid: u64, guid: &str, data: &str) {
        let rejected = KbsyncCacheEntry {
            dsid,
            guid: guid.to_owned(),
            data: data.to_owned(),
        };
        if let Ok(mut guard) = self.kbsync_cache.lock()
            && guard.as_ref() == Some(&rejected)
        {
            *guard = None;
        }
        if let Some(credentials) = &self.credentials
            && let Ok(Some(encoded)) = credentials.get(KBSYNC_CACHE_KEY)
            && let Ok(saved) = serde_json::from_slice::<KbsyncCacheEntry>(&encoded)
            && saved == rejected
        {
            let _ = credentials.remove(KBSYNC_CACHE_KEY);
        }
    }

    fn send_request(
        &self,
        endpoint: Endpoint,
        account: &Account,
        app: &App,
        version: &str,
    ) -> Result<DownloadProductResponse> {
        let guid = self.guid();
        let mut url = match endpoint {
            Endpoint::Volume => volume_url(account)?,
            Endpoint::Redownload => Url::parse(REDOWNLOAD_URL)?,
            Endpoint::Update => Url::parse(UPDATE_URL)?,
        };
        url.query_pairs_mut().append_pair("guid", &guid);
        let mut parameters = serde_json::json!({
            "creditDisplay": "",
            "guid": guid,
            "salableAdamId": app.id,
            "serialNumber": "0",
        });
        if !version.is_empty() {
            parameters[match endpoint {
                Endpoint::Volume => "externalVersionId",
                _ => "appExtVrsId",
            }] = Value::String(version.to_owned());
        }
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &parameters).context("encode download-product plist")?;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-apple-plist"),
        );
        headers.insert(
            "iCloud-DSID",
            HeaderValue::from_str(&account.directory_services_id)?,
        );
        headers.insert(
            "X-Dsid",
            HeaderValue::from_str(&account.directory_services_id)?,
        );
        headers.insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("br, gzip, deflate"),
        );
        headers.insert("Accept-Language", HeaderValue::from_static("en"));
        headers.insert(
            "X-Apple-Client-Application",
            HeaderValue::from_static("me.majd.ipatool"),
        );
        headers.insert("X-Apple-TZ", HeaderValue::from_static("0"));
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string())?,
        );
        let response = (self.sender)(Request {
            method: Method::POST,
            url,
            headers,
            body: Some(body),
            no_redirects: true,
            timeout: None,
        })
        .context("send Store download-product request")?;
        if response.status == 500 && response.body.is_empty() {
            return Ok(DownloadProductResponse {
                status: 500,
                data: DownloadProductResult {
                    failure_type: String::new(),
                    customer_message: String::new(),
                    items: Vec::new(),
                },
                capture: None,
            });
        }
        let data = response
            .plist(false)
            .context("decode Store download-product response")?;
        Ok(DownloadProductResponse {
            status: response.status,
            data,
            capture: None,
        })
    }

    fn guid(&self) -> String {
        self.hardware_id
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct DownloadProductResponse {
    pub status: u16,
    pub data: DownloadProductResult,
    capture: Option<FairPlayDownloadCapture>,
}

fn response_keybag(value: &plist::Value) -> Option<Vec<u8>> {
    const NAMES: [&str; 3] = ["keybag", "subKeyBag", "sbKeyBag"];
    let dictionary = value.as_dictionary()?;
    for name in NAMES {
        if let Some(bytes) = dictionary.get(name).and_then(decode_keybag) {
            return Some(bytes);
        }
    }
    for item in dictionary
        .get("songList")
        .and_then(plist::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(fields) = item.as_dictionary() else {
            continue;
        };
        for name in NAMES {
            if let Some(bytes) = fields.get(name).and_then(decode_keybag) {
                return Some(bytes);
            }
        }
        if let Some(metadata) = fields.get("metadata").and_then(plist::Value::as_dictionary) {
            for name in NAMES {
                if let Some(bytes) = metadata.get(name).and_then(decode_keybag) {
                    return Some(bytes);
                }
            }
        }
    }
    None
}

fn decode_keybag(value: &plist::Value) -> Option<Vec<u8>> {
    let bytes = match value {
        plist::Value::Data(bytes) => bytes.clone(),
        plist::Value::String(text) => STANDARD.decode(text).ok()?,
        _ => return None,
    };
    (!bytes.is_empty()).then_some(bytes)
}

impl DownloadProductResponse {
    fn is_empty_server_error(&self) -> bool {
        self.status == 500
            && self.data.failure_type.is_empty()
            && self.data.customer_message.is_empty()
            && self.data.items.is_empty()
    }

    fn is_empty_or_unavailable(&self) -> bool {
        if self.status != 200 || !self.data.failure_type.is_empty() || !self.data.items.is_empty() {
            return false;
        }
        let message = self.data.customer_message.trim().to_ascii_lowercase();
        message.is_empty()
            || message == "no longer available"
            || message.ends_with(" no longer available")
    }
}

struct DownloadBag {
    ent_download: Option<String>,
    redownload: Option<String>,
    update: Option<String>,
}

fn volume_url(account: &Account) -> Result<Url> {
    let host = if account.pod.is_empty() {
        "buy.itunes.apple.com".to_owned()
    } else {
        if !account.pod.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("invalid Store pod identifier");
        }
        format!("p{}-buy.itunes.apple.com", account.pod)
    };
    Url::parse(&format!("https://{host}{VOLUME_PATH}")).context("invalid Store volume URL")
}

fn display_version(item: &DownloadItem) -> &str {
    item.metadata
        .get("bundleShortVersionString")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
}

fn package_destination(
    app: &App,
    version: &str,
    output: Option<&Path>,
    extension: &str,
) -> Result<PathBuf> {
    let parts = [
        (!app.bundle_id.is_empty()).then(|| safe_filename_part(&app.bundle_id)),
        (app.id > 0).then(|| app.id.to_string()),
        (!version.is_empty()).then(|| safe_filename_part(version)),
    ];
    let name = format!(
        "{}.{}",
        parts.into_iter().flatten().collect::<Vec<_>>().join("_"),
        extension
    );
    let destination = match output {
        Some(path) if path.is_dir() => path.join(name),
        Some(path) => path.to_owned(),
        None => std::env::current_dir()
            .context("read current directory")?
            .join(name),
    };
    if destination.file_name().is_none() {
        bail!("package output path has no file name");
    }
    Ok(destination)
}

fn safe_filename_part(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn fetch_artwork(url: &str) -> Result<Vec<u8>> {
    if url.is_empty() {
        return Ok(Vec::new());
    }
    let url = Url::parse(url).context("invalid Store artwork URL")?;
    if !matches!(url.scheme(), "https" | "http") {
        bail!("Store artwork URL must use HTTP or HTTPS");
    }
    let mut response = reqwest::blocking::Client::builder()
        .timeout(DEFAULT_AUTHENTICATION_TIMEOUT)
        .build()
        .context("create artwork HTTP client")?
        .get(url)
        .send()
        .context("download Store artwork")?;
    if response.status().as_u16() != 200 {
        bail!("unexpected Store artwork status: {}", response.status());
    }
    const MAX_ARTWORK: u64 = 32 * 1024 * 1024;
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_ARTWORK + 1)
        .read_to_end(&mut bytes)
        .context("read Store artwork")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ARTWORK {
        bail!("Store artwork is empty or too large");
    }
    Ok(bytes)
}

fn version_string(value: &Value) -> Result<String> {
    match value {
        Value::String(value) if !value.is_empty() => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        _ => bail!("invalid external version identifier in download metadata"),
    }
}

fn checked_item(response: &DownloadProductResponse) -> Result<&DownloadItem> {
    let result = &response.data;
    if matches!(result.failure_type.as_str(), "2034" | "2042") {
        return Err(PasswordTokenExpired.into());
    }
    if result.failure_type == "9610" {
        return Err(LicenseRequired.into());
    }
    if !result.failure_type.is_empty() {
        bail!(
            "App Store download metadata failed: {}",
            if result.customer_message.is_empty() {
                &result.failure_type
            } else {
                &result.customer_message
            }
        );
    }
    if response.status != 200 || result.items.is_empty() {
        if result.customer_message.is_empty() {
            bail!(
                "App Store returned no download metadata (HTTP {})",
                response.status
            );
        }
        bail!(
            "App Store download metadata failed: {}",
            result.customer_message
        );
    }
    Ok(&result.items[0])
}

fn validate_fallback(response: &DownloadProductResponse, app: &App, version: &str) -> Result<()> {
    if !response.data.failure_type.is_empty() || !response.data.customer_message.is_empty() {
        return Ok(());
    }
    if response.status != 200 || response.data.items.len() != 1 {
        bail!("redownload response has no unique app item");
    }
    let metadata = &response.data.items[0].metadata;
    let id = metadata
        .get("itemId")
        .context("redownload response has no app ID")?;
    if version_string(id)? != app.id.to_string() {
        bail!("redownload response does not match the requested app");
    }
    let bundle = metadata
        .get("softwareVersionBundleId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if bundle.is_empty() || (!app.bundle_id.is_empty() && bundle != app.bundle_id) {
        bail!("redownload response does not match the requested bundle identifier");
    }
    if !version.is_empty()
        && metadata
            .get("softwareVersionExternalIdentifier")
            .map(version_string)
            .transpose()?
            .as_deref()
            != Some(version)
    {
        bail!("redownload response does not match the requested version");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        io::{Cursor, Write},
        net::TcpListener,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
    };

    use crate::{
        sap_assets::SapAssetBundle,
        store_backend::{StoreBackend, StoreBackendRequest},
    };

    #[derive(Default)]
    struct MemoryCredentials(Mutex<HashMap<String, Vec<u8>>>);

    impl CredentialStore for MemoryCredentials {
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

    fn ent_sender(request: Request) -> Result<Response> {
        if request.url.path().ends_with("bag.xml") {
            return Ok(response(serde_json::json!({"urlBag": {
                "volumeStoreDownloadProduct": ENT_DOWNLOAD_URL
            }})));
        }
        Ok(item_response("101"))
    }

    fn account() -> Account {
        let mut account = Account::default();
        account.directory_services_id = "123456".into();
        account.pod = "42".into();
        account.store_front = "143441-1,29".into();
        account
    }

    fn app() -> App {
        App {
            id: 42,
            bundle_id: "com.example.app".into(),
            ..App::default()
        }
    }

    fn response(value: Value) -> Response {
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &value).unwrap();
        Response {
            status: 200,
            headers: Default::default(),
            body,
        }
    }

    fn item_response(version: &str) -> Response {
        response(
            serde_json::json!({"songList": [{"URL": "https://example.test/app.ipa", "metadata": {
                "itemId": 42,
                "softwareVersionBundleId": "com.example.app",
                "softwareVersionExternalIdentifier": version,
                "softwareVersionExternalIdentifiers": [100, 101]
            }}]}),
        )
    }

    #[test]
    fn volume_request_matches_pinned_store_guest() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let seen_guest = Arc::new(Mutex::new(None));
        let capture = Arc::clone(&seen_guest);
        let guest = StoreBackend::with_sender(
            assets.apple_media_services,
            [0, 1, 2, 3, 4, 5],
            move |request| {
                *capture.lock().unwrap() = Some(request);
                Ok(item_response("101"))
            },
        );
        let url = "https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=000102030405";
        let params = serde_json::json!({"creditDisplay": "", "guid": "000102030405", "salableAdamId": 42, "serialNumber": "0", "externalVersionId": "101"});
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-apple-plist"),
        );
        headers.insert("iCloud-DSID", HeaderValue::from_static("123456"));
        headers.insert("X-Dsid", HeaderValue::from_static("123456"));
        guest
            .execute_standard(StoreBackendRequest {
                method: "POST",
                url,
                headers: &headers,
                parameters: Some(&params),
                body: None,
                raw: false,
                response_format: "plist",
                no_redirects: false,
                timeout: None,
            })
            .unwrap();

        let seen_native = Arc::new(Mutex::new(None));
        let capture = Arc::clone(&seen_native);
        let native = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            *capture.lock().unwrap() = Some(request);
            Ok(item_response("101"))
        });
        native
            .send_product(&account(), &app(), "101", || unreachable!())
            .unwrap();
        let guest = seen_guest.lock().unwrap().take().unwrap();
        let native = seen_native.lock().unwrap().take().unwrap();
        assert_eq!(native.method, guest.method);
        assert_eq!(native.url, guest.url);
        assert_eq!(native.headers, guest.headers);
        assert_eq!(native.body, guest.body);
        assert_eq!(native.no_redirects, guest.no_redirects);
        assert_eq!(native.timeout, guest.timeout);
    }

    #[test]
    fn falls_back_to_pinned_redownload_and_update() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&requests);
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            let url = request.url.to_string();
            let body: Option<Value> = request
                .body
                .as_ref()
                .map(|body| plist::from_bytes(body).unwrap());
            capture.lock().unwrap().push((url.clone(), body));
            if url.contains("volumeStoreDownloadProduct") {
                return Ok(response(serde_json::json!({})));
            }
            if url.contains("/r/redownload") {
                return Ok(Response {
                    status: 500,
                    headers: Default::default(),
                    body: Vec::new(),
                });
            }
            if url.contains("bag.xml") {
                return Ok(response(serde_json::json!({"urlBag": {
                    "redownloadProduct": REDOWNLOAD_URL,
                    "updateProduct": UPDATE_URL
                }})));
            }
            Ok(item_response("101"))
        });
        let result = client
            .send_product(&account(), &app(), "101", || unreachable!())
            .unwrap();
        assert_eq!(result.data.items.len(), 1);
        let calls = requests.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert!(calls[0].0.contains("volumeStoreDownloadProduct"));
        assert!(calls[1].0.contains("bag.xml"));
        assert!(calls[2].0.contains("/r/redownload"));
        assert!(calls[3].0.contains("/up/updateProduct"));
        assert_eq!(calls[0].1.as_ref().unwrap()["externalVersionId"], "101");
        assert_eq!(calls[2].1.as_ref().unwrap()["appExtVrsId"], "101");
    }

    #[test]
    fn refuses_untrusted_pod_and_bag_endpoints() {
        let mut bad = account();
        bad.pod = "42.evil.example".into();
        assert!(volume_url(&bad).is_err());
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |request| {
            if request.url.path().ends_with("bag.xml") {
                return Ok(response(
                    serde_json::json!({"urlBag": {"redownloadProduct": "https://evil.example/r/redownload"}}),
                ));
            }
            Ok(response(serde_json::json!({})))
        });
        assert!(
            client
                .send_product(&account(), &app(), "101", || unreachable!())
                .is_err()
        );
    }

    #[test]
    fn list_versions_reads_store_metadata_and_surfaces_token_expiry() {
        let catalog = CatalogClient::new().unwrap();
        let client =
            DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |_| Ok(item_response("101")));
        let versions = client
            .list_versions(&catalog, &account(), &app(), Platform::Iphone)
            .unwrap();
        assert_eq!(versions.external_version_identifiers, ["100", "101"]);
        assert_eq!(versions.latest_external_version_id, "101");

        let expired = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |_| {
            Ok(response(serde_json::json!({"failureType": "2034"})))
        });
        let error = expired
            .list_versions(&catalog, &account(), &app(), Platform::Iphone)
            .unwrap_err();
        assert!(error.downcast_ref::<PasswordTokenExpired>().is_some());
    }

    #[test]
    fn version_metadata_reads_selected_ipa_url_and_rejects_mac_without_preflight() {
        let client =
            DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |_| Ok(item_response("101")));
        let metadata = client
            .get_version_metadata_with(
                &account(),
                &app(),
                "101",
                Some(Platform::Iphone),
                (
                    |url| {
                        assert_eq!(url, "https://example.test/app.ipa");
                        Ok(VersionMetadata {
                            display_version: "1.0".into(),
                            release_date: "2025-01-01T00:00:00Z".into(),
                        })
                    },
                    |_, _| unreachable!(),
                    |_, _| unreachable!(),
                ),
            )
            .unwrap();
        assert_eq!(metadata.display_version, "1.0");
        assert!(
            client
                .get_version_metadata_with(
                    &account(),
                    &app(),
                    "101",
                    Some(Platform::Macos),
                    (
                        |_| unreachable!(),
                        |_, _| unreachable!(),
                        |item, _| crate::mac_package::mac_dp_info(item).map(|_| unreachable!()),
                    )
                )
                .is_err()
        );
    }

    #[test]
    fn version_metadata_uses_mac_preflight_for_native_package() {
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |_| {
            Ok(response(serde_json::json!({"songList": [{
                "URL": "https://example.test/encrypted.pkg",
                "preflightPackageURL": "https://example.test/preflight.pkg",
                "metadata": {"software-platform": "macos", "softwareVersionBundleId": "com.example.mac"}
            }]})))
        });
        let result = client
            .get_version_metadata_with(
                &account(),
                &App {
                    id: 42,
                    ..App::default()
                },
                "101",
                None,
                (
                    |_| unreachable!(),
                    |url, bundle| {
                        assert_eq!(url, "https://example.test/preflight.pkg");
                        assert_eq!(bundle, "com.example.mac");
                        Ok(VersionMetadata {
                            display_version: "4.2".into(),
                            release_date: "2012-07-06T09:54:33Z".into(),
                        })
                    },
                    |_, _| unreachable!(),
                ),
            )
            .unwrap();
        assert_eq!(result.display_version, "4.2");
    }

    #[test]
    fn mac_dp_info_does_not_use_unrelated_preflight_package() {
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |_| {
            Ok(Response {
                status: 200,
                headers: Default::default(),
                body: br#"<plist version="1.0"><dict><key>songList</key><array><dict><key>URL</key><string>https://example.test/encrypted.pkg</string><key>preflightPackageURL</key><string>https://example.test/preflight.pkg</string><key>metadata</key><dict><key>software-platform</key><string>macos</string></dict><key>sinfs</key><array><dict><key>dpInfo</key><data>AQID</data></dict></array></dict></array></dict></plist>"#.to_vec(),
            })
        });
        let metadata = client
            .get_version_metadata_with(
                &account(),
                &app(),
                "101",
                Some(Platform::Macos),
                (
                    |_| unreachable!(),
                    |_, _| unreachable!(),
                    |item, bundle| {
                        assert_eq!(item.url, "https://example.test/encrypted.pkg");
                        assert_eq!(bundle, "com.example.app");
                        assert_eq!(crate::mac_package::mac_dp_info(item)?, [1, 2, 3]);
                        Ok(VersionMetadata {
                            display_version: "4.2".into(),
                            release_date: "2012-07-06T09:54:33Z".into(),
                        })
                    },
                ),
            )
            .unwrap();
        assert_eq!(metadata.display_version, "4.2");
    }

    #[test]
    fn ent_download_uses_kbsync_and_short_circuits_legacy_path() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            let url = request.url.to_string();
            seen.lock().unwrap().push(url.clone());
            if url.contains("bag.xml") {
                return Ok(response(
                    serde_json::json!({"urlBag": {"volumeStoreDownloadProduct": ENT_DOWNLOAD_URL}}),
                ));
            }
            assert!(url.starts_with(ENT_DOWNLOAD_URL));
            assert_eq!(request.headers.get("X-Token").unwrap(), "test-token");
            assert_eq!(
                request.headers.get("X-Apple-Store-Front").unwrap(),
                "143441-1,29"
            );
            assert_eq!(
                request.headers.get(CONTENT_TYPE).unwrap(),
                "application/x-www-form-urlencoded; charset=utf-8"
            );
            assert!(request.no_redirects);
            let body: Value = plist::from_bytes(request.body.as_ref().unwrap()).unwrap();
            assert_eq!(body["kbsync"], STANDARD.encode(b"test-kbsync"));
            assert_eq!(body["salableAdamId"], "42");
            assert_eq!(
                body["serialNumber"],
                STANDARD.encode([0x54, 0xc8, 0xb0, 0xa9, 0x88, 2, 3, 4, 5])
            );
            assert_eq!(body["externalVersionId"], "101");
            Ok(item_response("101"))
        })
        .with_kbsync_generator(|hardware, dsid| {
            assert_eq!(hardware, [0, 1, 2, 3, 4, 5]);
            assert_eq!(dsid, 123456);
            Ok(b"test-kbsync".to_vec())
        });
        let mut account = account();
        account.password_token = "test-token".into();
        let result = client
            .send_product(&account, &app(), "101", || unreachable!())
            .unwrap();
        assert_eq!(result.data.items.len(), 1);
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn captures_matching_ent_download_kbsync_and_keybag() {
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |request| {
            if request.url.path().ends_with("bag.xml") {
                return Ok(response(
                    serde_json::json!({"urlBag": {"volumeStoreDownloadProduct": ENT_DOWNLOAD_URL}}),
                ));
            }
            Ok(response(serde_json::json!({
                "keybag": STANDARD.encode(b"response-keybag"),
                "songList": [{"URL": "https://example.test/app.ipa", "metadata": {
                    "itemId": 42, "softwareVersionBundleId": "com.example.app",
                    "softwareVersionExternalIdentifier": "101"
                }}]
            })))
        })
        .with_kbsync_generator(|_, _| Ok(b"request-kbsync".to_vec()));
        let result = client
            .send_product(&account(), &app(), "101", || unreachable!())
            .unwrap();
        let capture = result.capture.unwrap();
        assert_eq!(capture.kbsync, b"request-kbsync");
        assert_eq!(capture.keybag, b"response-keybag");
        let debug = format!("{capture:?}");
        assert!(!debug.contains("request-kbsync"));
        assert!(!debug.contains("response-keybag"));
    }

    #[test]
    fn decodes_binary_and_metadata_keybags() {
        let mut top = plist::Dictionary::new();
        top.insert("keybag".into(), plist::Value::Data(b"binary".to_vec()));
        assert_eq!(
            response_keybag(&plist::Value::Dictionary(top)),
            Some(b"binary".to_vec())
        );
        let mut metadata = plist::Dictionary::new();
        metadata.insert(
            "subKeyBag".into(),
            plist::Value::String(STANDARD.encode(b"metadata")),
        );
        let mut item = plist::Dictionary::new();
        item.insert("metadata".into(), plist::Value::Dictionary(metadata));
        let mut root = plist::Dictionary::new();
        root.insert(
            "songList".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(item)]),
        );
        assert_eq!(
            response_keybag(&plist::Value::Dictionary(root)),
            Some(b"metadata".to_vec())
        );
    }

    #[test]
    fn failed_ent_generation_falls_back_to_legacy_volume_store() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            let url = request.url.to_string();
            seen.lock().unwrap().push(url.clone());
            if url.contains("bag.xml") {
                return Ok(response(
                    serde_json::json!({"urlBag": {"volumeStoreDownloadProduct": ENT_DOWNLOAD_URL}}),
                ));
            }
            assert!(url.contains("volumeStoreDownloadProduct"));
            Ok(item_response("101"))
        })
        .with_kbsync_generator(|_, _| bail!("test guest unavailable"));
        let result = client
            .send_product(&account(), &app(), "101", || unreachable!())
            .unwrap();
        assert_eq!(result.data.items.len(), 1);
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn ent_download_request_matches_pinned_store_guest() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let captured_guest = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&captured_guest);
        let guest = StoreBackend::with_sender(
            assets.apple_media_services,
            [0, 1, 2, 3, 4, 5],
            move |request| {
                *seen.lock().unwrap() = Some(request);
                Ok(item_response("101"))
            },
        );
        let mut account = account();
        account.password_token = "test-token".into();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
        );
        headers.insert("iCloud-DSID", HeaderValue::from_static("123456"));
        headers.insert("X-Dsid", HeaderValue::from_static("123456"));
        headers.insert(
            "X-Apple-Store-Front",
            HeaderValue::from_static("143441-1,29"),
        );
        headers.insert("X-Token", HeaderValue::from_static("test-token"));
        headers.insert(USER_AGENT, HeaderValue::from_static(PURCHASE_USER_AGENT));
        let url = format!("{ENT_DOWNLOAD_URL}?guid=000102030405");
        let parameters = serde_json::json!({
            "creditDisplay": "", "guid": "000102030405", "kbsync": STANDARD.encode(b"test-kbsync"),
            "salableAdamId": "42", "serialNumber": STANDARD.encode([0x54, 0xc8, 0xb0, 0xa9, 0x88, 2, 3, 4, 5]),
            "externalVersionId": "101"
        });
        guest
            .execute_standard(StoreBackendRequest {
                method: "POST",
                url: &url,
                headers: &headers,
                parameters: Some(&parameters),
                body: None,
                raw: false,
                response_format: "plist",
                no_redirects: true,
                timeout: Some(DEFAULT_AUTHENTICATION_TIMEOUT),
            })
            .unwrap();

        let captured_native = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&captured_native);
        let native = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            if request.url.path().ends_with("bag.xml") {
                return Ok(response(
                    serde_json::json!({"urlBag": {"volumeStoreDownloadProduct": ENT_DOWNLOAD_URL}}),
                ));
            }
            *seen.lock().unwrap() = Some(request);
            Ok(item_response("101"))
        })
        .with_kbsync_generator(|_, _| Ok(b"test-kbsync".to_vec()));
        native
            .send_product(&account, &app(), "101", || unreachable!())
            .unwrap();
        let guest = captured_guest.lock().unwrap().take().unwrap();
        let native = captured_native.lock().unwrap().take().unwrap();
        assert_eq!(native.method, guest.method);
        assert_eq!(native.url, guest.url);
        assert_eq!(native.headers, guest.headers);
        assert_eq!(native.body, guest.body);
        assert_eq!(native.no_redirects, guest.no_redirects);
        assert_eq!(native.timeout, guest.timeout);
    }

    #[test]
    fn kbsync_cache_reused_across_clients_for_same_account_and_device() {
        let credentials = Arc::new(MemoryCredentials::default());
        let generated = Arc::new(AtomicUsize::new(0));
        let build = || {
            let generated = Arc::clone(&generated);
            DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], ent_sender)
                .with_credential_store(credentials.clone())
                .with_kbsync_generator(move |_, _| {
                    generated.fetch_add(1, Ordering::SeqCst);
                    Ok(b"cached-kbsync".to_vec())
                })
        };
        build()
            .send_product(&account(), &app(), "101", || unreachable!())
            .unwrap();
        build()
            .send_product(&account(), &app(), "101", || unreachable!())
            .unwrap();
        assert_eq!(generated.load(Ordering::SeqCst), 1);
        let saved = credentials.get(KBSYNC_CACHE_KEY).unwrap().unwrap();
        let saved: KbsyncCacheEntry = serde_json::from_slice(&saved).unwrap();
        assert_eq!(saved.dsid, 123456);
        assert_eq!(saved.guid, "000102030405");
        assert_eq!(saved.data, STANDARD.encode(b"cached-kbsync"));
    }

    #[test]
    fn rejected_cached_kbsync_is_replaced_after_fresh_request_succeeds() {
        let credentials = Arc::new(MemoryCredentials::default());
        credentials
            .set(
                KBSYNC_CACHE_KEY,
                &serde_json::to_vec(&KbsyncCacheEntry {
                    dsid: 123456,
                    guid: "000102030405".into(),
                    data: STANDARD.encode(b"rejected"),
                })
                .unwrap(),
            )
            .unwrap();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&sent);
        let generated = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&generated);
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            if request.url.path().ends_with("bag.xml") {
                return ent_sender(request);
            }
            let body: Value = plist::from_bytes(request.body.as_ref().unwrap()).unwrap();
            let kbsync = body["kbsync"].as_str().unwrap().to_owned();
            capture.lock().unwrap().push(kbsync.clone());
            if kbsync == STANDARD.encode(b"rejected") {
                bail!("Store rejected cached blob");
            }
            Ok(item_response("101"))
        })
        .with_credential_store(credentials.clone())
        .with_kbsync_generator(move |_, _| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(b"fresh".to_vec())
        });
        client
            .send_product(&account(), &app(), "101", || unreachable!())
            .unwrap();
        assert_eq!(generated.load(Ordering::SeqCst), 1);
        assert_eq!(
            *sent.lock().unwrap(),
            [STANDARD.encode(b"rejected"), STANDARD.encode(b"fresh")]
        );
        let saved = credentials.get(KBSYNC_CACHE_KEY).unwrap().unwrap();
        let saved: KbsyncCacheEntry = serde_json::from_slice(&saved).unwrap();
        assert_eq!(saved.data, STANDARD.encode(b"fresh"));
    }

    #[test]
    fn kbsync_cache_ignores_wrong_account_and_malformed_data() {
        let credentials = Arc::new(MemoryCredentials::default());
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], ent_sender)
            .with_credential_store(credentials.clone());
        for entry in [
            KbsyncCacheEntry {
                dsid: 7,
                guid: "000102030405".into(),
                data: STANDARD.encode(b"old"),
            },
            KbsyncCacheEntry {
                dsid: 123456,
                guid: "wrong".into(),
                data: STANDARD.encode(b"old"),
            },
            KbsyncCacheEntry {
                dsid: 123456,
                guid: "000102030405".into(),
                data: "bad!".into(),
            },
        ] {
            credentials
                .set(KBSYNC_CACHE_KEY, &serde_json::to_vec(&entry).unwrap())
                .unwrap();
            assert!(client.cached_kbsync(123456, "000102030405").is_none());
        }
    }

    #[test]
    fn downloads_validates_and_patches_mobile_ipa() {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file(
                "Payload/App.app/Info.plist",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive
            .write_all(br#"<plist version="1.0"><dict><key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array></dict></plist>"#)
            .unwrap();
        let ipa = archive.finish().unwrap().into_inner();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/app.ipa", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            let mut request = Vec::new();
            while std::io::Read::read_exact(&mut stream, &mut byte).is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                ipa.len()
            )
            .unwrap();
            stream.write_all(&ipa).unwrap();
        });
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |_| {
            Ok(response(serde_json::json!({"songList": [{
                "URL": url,
                "metadata": {
                    "itemId": 42,
                    "softwareVersionBundleId": "com.example.app",
                    "softwareVersionExternalIdentifier": "101",
                    "bundleShortVersionString": "1.2.3"
                }
            }]})))
        });
        let directory = tempfile::tempdir().unwrap();
        let mut account = account();
        account.email = "person@example.test".into();
        let path = client
            .download_ipa(
                &CatalogClient::new().unwrap(),
                &account,
                &app(),
                "101",
                Platform::Iphone,
                Some(directory.path()),
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(path.file_name().unwrap(), "com.example.app_42_1.2.3.ipa");
        assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
        let mut archive = zip::ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
        let mut metadata = Vec::new();
        std::io::Read::read_to_end(
            &mut archive.by_name("iTunesMetadata.plist").unwrap(),
            &mut metadata,
        )
        .unwrap();
        let metadata: plist::Value = plist::from_bytes(&metadata).unwrap();
        assert_eq!(
            metadata.as_dictionary().unwrap()["apple-id"].as_string(),
            Some("person@example.test")
        );
    }

    #[test]
    fn mac_offer_with_mobile_sinf_downloads_as_ipa() {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file(
                "Payload/App.app/Info.plist",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive
            .write_all(br#"<plist version="1.0"><dict><key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array><key>CFBundleExecutable</key><string>App</string></dict></plist>"#)
            .unwrap();
        let ipa = archive.finish().unwrap().into_inner();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/app.ipa", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            let mut request = Vec::new();
            while std::io::Read::read_exact(&mut stream, &mut byte).is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                ipa.len()
            )
            .unwrap();
            stream.write_all(&ipa).unwrap();
        });
        let plist = format!(
            r#"<plist version="1.0"><dict><key>songList</key><array><dict><key>URL</key><string>{url}</string><key>sinfs</key><array><dict><key>sinf</key><data>AQID</data></dict></array><key>metadata</key><dict><key>software-platform</key><string>ios</string><key>itemId</key><integer>42</integer><key>softwareVersionBundleId</key><string>com.example.app</string><key>softwareVersionExternalIdentifier</key><string>101</string><key>bundleShortVersionString</key><string>2.0</string></dict></dict></array></dict></plist>"#
        );
        let client = DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], move |_| {
            Ok(Response {
                status: 200,
                headers: Default::default(),
                body: plist.as_bytes().to_vec(),
            })
        });
        let directory = tempfile::tempdir().unwrap();
        let path = client
            .download_macos(
                &CatalogClient::new().unwrap(),
                &account(),
                &app(),
                "101",
                Some(directory.path()),
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(path.extension().unwrap(), "ipa");
        let mut archive = zip::ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
        let mut sinf = Vec::new();
        std::io::Read::read_to_end(
            &mut archive.by_name("Payload/App.app/SC_Info/App.sinf").unwrap(),
            &mut sinf,
        )
        .unwrap();
        assert_eq!(sinf, [1, 2, 3]);
    }
}
