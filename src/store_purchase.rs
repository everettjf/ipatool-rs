//! Free-app purchase protocol over the pinned Store request backend.

use std::{error::Error, fmt};

use anyhow::{Context, Result, bail};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;

use crate::{
    catalog::App,
    credentials::Account,
    platform::Platform,
    store_backend::{StoreBackend, StoreBackendRequest},
    transport::Response,
};

const PURCHASE_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";

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
}
