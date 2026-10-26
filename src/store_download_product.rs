//! Native Store download-product requests and version-history metadata.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use reqwest::{
    Method,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::{
    App, CatalogClient, Platform,
    credentials::Account,
    host::hardware_mac_address,
    ipa_metadata::{self, VersionMetadata},
    state::prepare_state_directory_from_environment,
    store_backend::DEFAULT_USER_AGENT,
    store_purchase::PasswordTokenExpired,
    storefront::country_code_from_storefront,
    transport::{DEFAULT_AUTHENTICATION_TIMEOUT, Request, Response, Transport},
};

const VOLUME_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";
const REDOWNLOAD_URL: &str = "https://downloaddispatch.itunes.apple.com/r/redownload";
const UPDATE_URL: &str = "https://downloaddispatch.itunes.apple.com/up/updateProduct";
type Sender = dyn Fn(Request) -> Result<Response> + Send + Sync;

pub struct DownloadProductClient {
    hardware_id: [u8; 6],
    sender: Arc<Sender>,
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

#[derive(Clone, Debug, Deserialize)]
pub struct DownloadItem {
    #[serde(default, rename = "URL")]
    pub url: String,
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
        Ok(Self::with_sender(hardware_id, move |request| {
            transport.send(request)
        }))
    }

    pub fn with_sender(
        hardware_id: [u8; 6],
        sender: impl Fn(Request) -> Result<Response> + Send + Sync + 'static,
    ) -> Self {
        Self {
            hardware_id,
            sender: Arc::new(sender),
        }
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
        platform: Platform,
    ) -> Result<VersionMetadata> {
        self.get_version_metadata_with(
            account,
            app,
            version,
            platform,
            ipa_metadata::read_version_metadata_from_ipa,
        )
    }

    fn get_version_metadata_with(
        &self,
        account: &Account,
        app: &App,
        version: &str,
        platform: Platform,
        read_ipa: impl FnOnce(&str) -> Result<VersionMetadata>,
    ) -> Result<VersionMetadata> {
        if version.is_empty() || platform == Platform::Unknown {
            bail!("a version ID and platform are required");
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
        if platform == Platform::Macos
            && !software_platform.eq_ignore_ascii_case("ios")
            && !(software_platform.is_empty() && product_type.eq_ignore_ascii_case("ios-app"))
        {
            bail!("macOS package version metadata requires the XAR package reader");
        }
        if item.url.is_empty() {
            bail!("App Store download response has no IPA URL");
        }
        read_ipa(&item.url).context("read version metadata from IPA")
    }

    /// Try volumeStore, then the bag-provided redownload and update endpoints.
    pub fn send_product(
        &self,
        account: &Account,
        app: &App,
        version: &str,
        fallback_version: impl FnOnce() -> Result<String>,
    ) -> Result<DownloadProductResponse> {
        if app.id <= 0 {
            bail!("app ID is required for download metadata");
        }
        let primary = self.send_request(Endpoint::Volume, account, app, version)?;
        if !primary.is_empty_or_unavailable() {
            return Ok(primary);
        }
        let bag = self.fetch_bag()?;
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
            });
        }
        let data = response
            .plist(false)
            .context("decode Store download-product response")?;
        Ok(DownloadProductResponse {
            status: response.status,
            data,
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
        bail!("a license is required for this app");
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
    use std::sync::Mutex;

    use crate::{
        sap_assets::SapAssetBundle,
        store_backend::{StoreBackend, StoreBackendRequest},
    };

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
    fn version_metadata_reads_selected_ipa_url_and_rejects_mac_package() {
        let client =
            DownloadProductClient::with_sender([0, 1, 2, 3, 4, 5], |_| Ok(item_response("101")));
        let metadata = client
            .get_version_metadata_with(&account(), &app(), "101", Platform::Iphone, |url| {
                assert_eq!(url, "https://example.test/app.ipa");
                Ok(VersionMetadata {
                    display_version: "1.0".into(),
                    release_date: "2025-01-01T00:00:00Z".into(),
                })
            })
            .unwrap();
        assert_eq!(metadata.display_version, "1.0");
        assert!(
            client
                .get_version_metadata_with(
                    &account(),
                    &app(),
                    "101",
                    Platform::Macos,
                    |_| unreachable!()
                )
                .is_err()
        );
    }
}
