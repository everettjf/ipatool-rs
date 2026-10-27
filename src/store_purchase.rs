//! Free-app purchase protocol with native and pinned Store backends.

use std::{error::Error, fmt, sync::Arc};

use anyhow::{Context, Result, bail};
use reqwest::{
    Method,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT},
};
use serde::Deserialize;
use url::Url;

use crate::{
    catalog::App,
    credentials::Account,
    host::hardware_mac_address,
    platform::Platform,
    state::prepare_state_directory_from_environment,
    store_backend::{PURCHASE_USER_AGENT, StoreBackend, StoreBackendRequest},
    transport::{Request, Response, Transport},
};

const PURCHASE_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";

type PurchaseSender = dyn Fn(Request) -> Result<Response> + Send + Sync;

/// Sends the purchase plist directly from Rust without the Store framework guest.
pub struct NativePurchaseBackend {
    hardware_id: [u8; 6],
    sender: Arc<PurchaseSender>,
}

impl NativePurchaseBackend {
    pub fn open() -> Result<Self> {
        let hardware_id = hardware_mac_address().context("read Store hardware identity")?;
        let state_directory = prepare_state_directory_from_environment()?;
        let transport = Arc::new(Transport::with_cookies(&state_directory)?);
        Ok(Self::with_sender(hardware_id, move |request| {
            transport.send_store(request)
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
}

impl PurchaseBackend for NativePurchaseBackend {
    fn hardware_id(&self) -> [u8; 6] {
        self.hardware_id
    }

    fn send_purchase(&self, request: StoreBackendRequest<'_>) -> Result<Response> {
        if request.method != "POST" || request.body.is_some() {
            bail!("invalid native purchase request");
        }
        let url = Url::parse(request.url).context("invalid purchase URL")?;
        let host = url.host_str().context("purchase URL has no host")?;
        let pod = host
            .strip_prefix('p')
            .and_then(|value| value.strip_suffix("-buy.itunes.apple.com"));
        if url.scheme() != "https"
            || url.path() != PURCHASE_PATH
            || url.query().is_some()
            || !(host == "buy.itunes.apple.com"
                || pod.is_some_and(|id| {
                    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
                }))
        {
            bail!("unsupported native purchase URL");
        }
        let parameters = request
            .parameters
            .context("native purchase parameters are missing")?;
        let mut parameters = parameters.clone();
        let fields = parameters
            .as_object_mut()
            .context("native purchase parameters must be a dictionary")?;
        fields.insert("hasBeenAuthedForBuy".into(), serde_json::Value::Bool(true));
        fields.insert(
            "clientCorrelationKey".into(),
            serde_json::Value::String(random_correlation_key()?),
        );
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &parameters).context("encode native purchase plist")?;
        let mut headers = request.headers.clone();
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
        (self.sender)(Request {
            method: Method::POST,
            url,
            headers,
            body: Some(body),
            no_redirects: request.no_redirects,
            timeout: request.timeout,
        })
    }
}

fn random_correlation_key() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).context("generate purchase correlation key")?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok([
        &bytes[..4],
        &bytes[4..6],
        &bytes[6..8],
        &bytes[8..10],
        &bytes[10..],
    ]
    .into_iter()
    .map(|group| {
        group
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    })
    .collect::<Vec<_>>()
    .join("-"))
}

#[derive(Debug)]
pub struct PasswordTokenExpired;

impl fmt::Display for PasswordTokenExpired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("password token is expired")
    }
}

impl Error for PasswordTokenExpired {}

#[derive(Debug)]
pub struct LicenseAlreadyExists;

impl fmt::Display for LicenseAlreadyExists {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("license already exists")
    }
}

impl Error for LicenseAlreadyExists {}

#[derive(Debug)]
struct TemporarilyUnavailable;

impl fmt::Display for TemporarilyUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("item is temporarily unavailable")
    }
}

impl Error for TemporarilyUnavailable {}

pub trait PurchaseBackend {
    fn hardware_id(&self) -> [u8; 6];
    fn send_purchase(&self, request: StoreBackendRequest<'_>) -> Result<Response>;
}

impl PurchaseBackend for StoreBackend {
    fn hardware_id(&self) -> [u8; 6] {
        self.hardware_id()
    }

    fn send_purchase(&self, request: StoreBackendRequest<'_>) -> Result<Response> {
        self.execute_purchase(request)
    }
}

pub fn purchase<B: PurchaseBackend>(
    backend: &B,
    account: &Account,
    app: &App,
    platform: Option<Platform>,
) -> Result<()> {
    if app.id <= 0 {
        bail!("an app ID is required to purchase a license");
    }
    if app.price > 0.0 {
        bail!("purchasing paid apps is not supported");
    }
    match purchase_with_pricing(backend, account, app, "STDQ") {
        Err(error)
            if platform != Some(Platform::Macos)
                && error.downcast_ref::<TemporarilyUnavailable>().is_some() =>
        {
            purchase_with_pricing(backend, account, app, "GAME")
                .context("failed to purchase item with param GAME")
        }
        result => result.context("failed to purchase item with param STDQ"),
    }
}

fn purchase_with_pricing<B: PurchaseBackend>(
    backend: &B,
    account: &Account,
    app: &App,
    pricing: &str,
) -> Result<()> {
    let pod = if account.pod.is_empty() {
        String::new()
    } else if account.pod.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("p{}-", account.pod)
    } else {
        bail!("invalid Store pod identifier");
    };
    let url = format!("https://{pod}buy.itunes.apple.com{PURCHASE_PATH}");
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-apple-plist"),
    );
    for (name, value) in [
        ("iCloud-DSID", &account.directory_services_id),
        ("X-Dsid", &account.directory_services_id),
        ("X-Apple-Store-Front", &account.store_front),
        ("X-Token", &account.password_token),
    ] {
        headers.insert(
            name,
            HeaderValue::from_str(value).context("invalid saved account header")?,
        );
    }
    let guid = backend
        .hardware_id()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let parameters = serde_json::json!({
        "appExtVrsId": "0",
        "hasAskedToFulfillPreorder": "true",
        "buyWithoutAuthorization": "true",
        "hasDoneAgeCheck": "true",
        "guid": guid,
        "needDiv": "0",
        "origPage": format!("Software-{}", app.id),
        "origPageLocation": "Buy",
        "price": "0",
        "pricingParameters": pricing,
        "productType": "C",
        "salableAdamId": app.id,
    });
    let response = backend.send_purchase(StoreBackendRequest {
        method: "POST",
        url: &url,
        headers: &headers,
        parameters: Some(&parameters),
        body: None,
        raw: false,
        response_format: "plist",
        no_redirects: true,
        timeout: None,
    })?;
    let result: PurchaseResponse = response.plist(false)?;
    if result.failure_type == "2059" {
        return Err(TemporarilyUnavailable.into());
    }
    if result.customer_message == "Subscription Required" {
        bail!("subscription required");
    }
    if matches!(result.failure_type.as_str(), "2034" | "2042" | "1008")
        || result.customer_message == "Your password has changed."
    {
        return Err(PasswordTokenExpired.into());
    }
    if result.failure_type == "5002" {
        return Err(LicenseAlreadyExists.into());
    }
    if !result.failure_type.is_empty() {
        if result.customer_message.is_empty() {
            bail!("Apple purchase failed: {}", result.failure_type);
        }
        bail!("Apple purchase failed: {}", result.customer_message);
    }
    if response.status == 500 {
        return Err(LicenseAlreadyExists.into());
    }
    if result.jingle_doc_type != "purchaseSuccess" || result.status != 0 {
        bail!("failed to purchase app");
    }
    Ok(())
}

#[derive(Default, Deserialize)]
struct PurchaseResponse {
    #[serde(default, rename = "failureType")]
    failure_type: String,
    #[serde(default, rename = "customerMessage")]
    customer_message: String,
    #[serde(default, rename = "jingleDocType")]
    jingle_doc_type: String,
    #[serde(default)]
    status: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sap_assets::SapAssetBundle;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug, PartialEq)]
    struct WirePurchase {
        url: String,
        body_len: usize,
        body: plist::Value,
        headers: Vec<(String, String)>,
    }

    fn wire_purchase(request: &Request) -> WirePurchase {
        let mut headers: Vec<_> = request
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
            .collect();
        headers.sort();
        let mut body: plist::Value = plist::from_bytes(request.body.as_ref().unwrap()).unwrap();
        let key = body
            .as_dictionary_mut()
            .unwrap()
            .remove("clientCorrelationKey")
            .unwrap();
        let key = key.as_string().unwrap();
        assert_eq!(key.len(), 36);
        assert_eq!(key.as_bytes()[14], b'4');
        WirePurchase {
            url: request.url.to_string(),
            body_len: request.body.as_ref().unwrap().len(),
            body,
            headers,
        }
    }

    struct FixtureBackend {
        responses: Mutex<Vec<Response>>,
        pricing: Mutex<Vec<String>>,
    }

    impl PurchaseBackend for FixtureBackend {
        fn hardware_id(&self) -> [u8; 6] {
            [0, 1, 2, 3, 4, 5]
        }
        fn send_purchase(&self, request: StoreBackendRequest<'_>) -> Result<Response> {
            assert_eq!(request.method, "POST");
            assert_eq!(
                request.url,
                "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct"
            );
            assert_eq!(request.headers["X-Dsid"], "123456");
            assert_eq!(request.headers["X-Token"], "token");
            assert_eq!(request.headers["X-Apple-Store-Front"], "143441-1,29");
            assert!(request.no_redirects);
            assert_eq!(request.parameters.unwrap()["guid"], "000102030405");
            assert_eq!(request.parameters.unwrap()["salableAdamId"], 1234);
            self.pricing.lock().unwrap().push(
                request.parameters.unwrap()["pricingParameters"]
                    .as_str()
                    .unwrap()
                    .into(),
            );
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    fn response(body: &str) -> Response {
        Response {
            set_cookie_headers: Vec::new(),
            status: 200,
            headers: std::collections::HashMap::from([(
                "content-type".into(),
                "application/x-apple-plist".into(),
            )]),
            body: body.as_bytes().to_vec(),
        }
    }

    fn fixture_account() -> Account {
        let mut account = Account::default();
        account.directory_services_id = "123456".into();
        account.password_token = "token".into();
        account.store_front = "143441-1,29".into();
        account
    }

    #[test]
    fn retries_arcade_pricing_after_temporary_unavailability() {
        let backend = FixtureBackend {
            responses: Mutex::new(vec![
                response(
                    r#"<plist version="1.0"><dict><key>failureType</key><string>2059</string></dict></plist>"#,
                ),
                response(
                    r#"<plist version="1.0"><dict><key>jingleDocType</key><string>purchaseSuccess</string><key>status</key><integer>0</integer></dict></plist>"#,
                ),
            ]),
            pricing: Mutex::new(Vec::new()),
        };
        let app = App {
            id: 1234,
            ..App::default()
        };
        purchase(&backend, &fixture_account(), &app, Some(Platform::Iphone)).unwrap();
        assert_eq!(*backend.pricing.lock().unwrap(), ["STDQ", "GAME"]);
    }

    #[test]
    fn rejects_paid_apps_before_contacting_store() {
        let backend = FixtureBackend {
            responses: Mutex::new(Vec::new()),
            pricing: Mutex::new(Vec::new()),
        };
        let app = App {
            id: 1234,
            price: 1.0,
            ..App::default()
        };
        assert!(purchase(&backend, &fixture_account(), &app, None).is_err());
        assert!(backend.pricing.lock().unwrap().is_empty());
    }

    #[test]
    fn exposes_expired_token_for_one_login_retry() {
        let backend = FixtureBackend {
            responses: Mutex::new(vec![response(
                r#"<plist version="1.0"><dict><key>failureType</key><string>2034</string></dict></plist>"#,
            )]),
            pricing: Mutex::new(Vec::new()),
        };
        let app = App {
            id: 1234,
            ..App::default()
        };
        let error = purchase(&backend, &fixture_account(), &app, None).unwrap_err();
        assert!(error.downcast_ref::<PasswordTokenExpired>().is_some());
        assert_eq!(*backend.pricing.lock().unwrap(), ["STDQ"]);
    }

    #[test]
    fn treats_plain_http_500_as_existing_license_after_other_errors() {
        let mut owned = response(r#"<plist version="1.0"><dict/></plist>"#);
        owned.status = 500;
        let backend = FixtureBackend {
            responses: Mutex::new(vec![owned]),
            pricing: Mutex::new(Vec::new()),
        };
        let app = App {
            id: 1234,
            ..App::default()
        };
        let error = purchase(&backend, &fixture_account(), &app, None).unwrap_err();
        assert!(error.downcast_ref::<LicenseAlreadyExists>().is_some());
    }

    #[test]
    fn macos_does_not_retry_arcade_pricing() {
        let backend = FixtureBackend {
            responses: Mutex::new(vec![response(
                r#"<plist version="1.0"><dict><key>failureType</key><string>2059</string></dict></plist>"#,
            )]),
            pricing: Mutex::new(Vec::new()),
        };
        let app = App {
            id: 1234,
            ..App::default()
        };
        assert!(purchase(&backend, &fixture_account(), &app, Some(Platform::Macos)).is_err());
        assert_eq!(*backend.pricing.lock().unwrap(), ["STDQ"]);
    }

    #[test]
    fn buys_free_app_through_pinned_store_backend() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let backend = StoreBackend::with_sender(
            assets.apple_media_services,
            [0, 1, 2, 3, 4, 5],
            move |request| {
                let call = seen.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    assert_eq!(
                        request.url.as_str(),
                        "https://init.itunes.apple.com/bag.xml?guid=000102030405"
                    );
                    return Ok(response(
                        r#"<plist version="1.0"><dict><key>urlBag</key><dict><key>buyProduct</key><string>https://buy.itunes.apple.com/from-bag</string></dict></dict></plist>"#,
                    ));
                }
                assert_eq!(call, 1);
                assert_eq!(
                    request.url.as_str(),
                    "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct"
                );
                let body: plist::Value = plist::from_bytes(request.body.as_ref().unwrap()).unwrap();
                let fields = body.as_dictionary().unwrap();
                assert_eq!(fields["salableAdamId"].as_signed_integer(), Some(1234));
                assert_eq!(fields["guid"].as_string(), Some("000102030405"));
                assert_eq!(fields["pricingParameters"].as_string(), Some("STDQ"));
                assert_eq!(fields["price"].as_string(), Some("0"));
                Ok(response(
                    r#"<plist version="1.0"><dict><key>jingleDocType</key><string>purchaseSuccess</string><key>status</key><integer>0</integer></dict></plist>"#,
                ))
            },
        );
        let app = App {
            id: 1234,
            ..App::default()
        };
        purchase(&backend, &fixture_account(), &app, Some(Platform::Iphone)).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn native_purchase_matches_pinned_store_wire_request() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let guest_request = Arc::new(Mutex::new(None));
        let observed_guest = Arc::clone(&guest_request);
        let guest = StoreBackend::with_sender(
            assets.apple_media_services,
            [0, 1, 2, 3, 4, 5],
            move |request| {
                if request.url.host_str() == Some("init.itunes.apple.com") {
                    return Ok(response(
                        r#"<plist version="1.0"><dict><key>urlBag</key><dict><key>buyProduct</key><string>https://buy.itunes.apple.com/stale</string></dict></dict></plist>"#,
                    ));
                }
                *observed_guest.lock().unwrap() = Some(wire_purchase(&request));
                Ok(response(
                    r#"<plist version="1.0"><dict><key>jingleDocType</key><string>purchaseSuccess</string><key>status</key><integer>0</integer></dict></plist>"#,
                ))
            },
        );
        let native_request = Arc::new(Mutex::new(None));
        let observed_native = Arc::clone(&native_request);
        let native = NativePurchaseBackend::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            *observed_native.lock().unwrap() = Some(wire_purchase(&request));
            Ok(response(
                r#"<plist version="1.0"><dict><key>jingleDocType</key><string>purchaseSuccess</string><key>status</key><integer>0</integer></dict></plist>"#,
            ))
        });
        let app = App {
            id: 1234,
            ..App::default()
        };
        purchase(&guest, &fixture_account(), &app, Some(Platform::Iphone)).unwrap();
        purchase(&native, &fixture_account(), &app, Some(Platform::Iphone)).unwrap();
        assert_eq!(
            *native_request.lock().unwrap(),
            *guest_request.lock().unwrap()
        );
    }
}
