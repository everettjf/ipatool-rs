//! Per-request Store guests backed by shared HTTP transport and URL bag data.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde_json::Value;

use crate::auth::{SapConfig, sap_config_from_bag_value};
use crate::host::hardware_mac_address;
use crate::sap_assets::SapAssetBundle;
use crate::state::prepare_state_directory_from_environment;
use crate::store_runtime::{StoreRuntime, StoreStandardRequest};
use crate::transport::{
    DEFAULT_AUTHENTICATION_TIMEOUT, Request as HostRequest, Response as HostResponse, Transport,
};

pub(crate) const DEFAULT_USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";
pub(crate) const PURCHASE_USER_AGENT: &str =
    "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6";

type StoreSender = dyn Fn(HostRequest) -> Result<HostResponse> + Send + Sync;
type StoreSigner<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>> + 'a;

pub struct StoreBackend {
    image: Arc<[u8]>,
    hardware_id: [u8; 6],
    sender: Arc<StoreSender>,
    bag: Mutex<Option<Value>>,
}

pub struct StoreBackendRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a HeaderMap,
    pub parameters: Option<&'a Value>,
    pub body: Option<&'a [u8]>,
    pub raw: bool,
    pub response_format: &'a str,
    pub no_redirects: bool,
    pub timeout: Option<Duration>,
}

#[derive(Clone, Copy)]
enum Operation {
    Standard,
    Purchase,
    Authenticate,
}

impl StoreBackend {
    pub fn open() -> Result<Self> {
        let hardware_id = hardware_mac_address().context("read Store hardware identity")?;
        let state_directory = prepare_state_directory_from_environment()?;
        let transport = Arc::new(Transport::with_cookies(&state_directory)?);
        let assets = SapAssetBundle::load_or_download().context("load pinned Apple frameworks")?;
        Ok(Self::new(&assets, hardware_id, transport))
    }

    pub fn new(assets: &SapAssetBundle, hardware_id: [u8; 6], transport: Arc<Transport>) -> Self {
        Self::with_sender(
            assets.apple_media_services.clone(),
            hardware_id,
            move |request| transport.send(request),
        )
    }

    pub fn with_sender(
        image: Vec<u8>,
        hardware_id: [u8; 6],
        sender: impl Fn(HostRequest) -> Result<HostResponse> + Send + Sync + 'static,
    ) -> Self {
        Self {
            image: Arc::from(image),
            hardware_id,
            sender: Arc::new(sender),
            bag: Mutex::new(None),
        }
    }

    pub fn hardware_id(&self) -> [u8; 6] {
        self.hardware_id
    }

    pub fn bag(&self) -> Result<Value> {
        if let Some(bag) = self.bag.lock().expect("Store bag lock poisoned").clone() {
            return Ok(bag);
        }
        let guid = self
            .hardware_id
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        let url = format!("https://init.itunes.apple.com/bag.xml?guid={guid}");
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/xml"));
        let response = self.run(
            StoreBackendRequest {
                method: "GET",
                url: &url,
                headers: &headers,
                parameters: None,
                body: None,
                raw: false,
                response_format: "plist",
                no_redirects: true,
                timeout: Some(DEFAULT_AUTHENTICATION_TIMEOUT),
            },
            None,
            Operation::Standard,
            None,
        )?;
        if response.status != 200 {
            bail!("Store bag returned HTTP {}", response.status);
        }
        let raw: plist::Value =
            plist::from_bytes(&response.body).context("decode Store URL bag")?;
        if raw.as_dictionary().is_none() {
            bail!("Store URL bag is not a dictionary");
        }
        let bag = serde_json::to_value(&raw).context("convert Store URL bag for guest")?;
        *self.bag.lock().expect("Store bag lock poisoned") = Some(bag.clone());
        Ok(bag)
    }

    pub fn sap_config(&self) -> Result<SapConfig> {
        sap_config_from_bag_value(&self.bag()?)
    }

    pub fn execute_standard(&self, input: StoreBackendRequest<'_>) -> Result<HostResponse> {
        let bag = self.bag.lock().expect("Store bag lock poisoned").clone();
        self.run(input, bag.as_ref(), Operation::Standard, None)
    }

    pub fn execute_standard_signed(
        &self,
        input: StoreBackendRequest<'_>,
        signer: &mut StoreSigner<'_>,
    ) -> Result<HostResponse> {
        let bag = self.bag.lock().expect("Store bag lock poisoned").clone();
        self.run(input, bag.as_ref(), Operation::Standard, Some(signer))
    }

    pub fn execute_purchase(&self, input: StoreBackendRequest<'_>) -> Result<HostResponse> {
        let bag = self.bag()?;
        self.run(input, Some(&bag), Operation::Purchase, None)
    }

    pub fn execute_authentication(
        &self,
        input: StoreBackendRequest<'_>,
        signer: &mut StoreSigner<'_>,
    ) -> Result<HostResponse> {
        let bag = self.bag()?;
        self.run(input, Some(&bag), Operation::Authenticate, Some(signer))
    }

    fn run(
        &self,
        input: StoreBackendRequest<'_>,
        bag: Option<&Value>,
        operation: Operation,
        signer: Option<&mut StoreSigner<'_>>,
    ) -> Result<HostResponse> {
        let mut runtime = StoreRuntime::open_image(&self.image)?;
        let sender = Arc::clone(&self.sender);
        runtime.set_transport(move |request| sender(request));
        let mut headers = input.headers.clone();
        if !headers.contains_key(USER_AGENT) {
            headers.insert(
                USER_AGENT,
                HeaderValue::from_static(if matches!(operation, Operation::Purchase) {
                    PURCHASE_USER_AGENT
                } else {
                    DEFAULT_USER_AGENT
                }),
            );
        }
        let request = StoreStandardRequest {
            method: input.method,
            url: input.url,
            headers: &headers,
            parameters: input.parameters,
            body: input.body,
            bag,
            hardware_id: &self.hardware_id,
            raw: input.raw,
            response_format: input.response_format,
            no_redirects: input.no_redirects,
            timeout: input.timeout,
        };
        match operation {
            Operation::Standard => match signer {
                Some(signer) => runtime.execute_standard_signed(request, signer),
                None => runtime.execute_standard(request),
            },
            Operation::Purchase => runtime.execute_purchase(request),
            Operation::Authenticate => runtime.execute_authentication(
                request,
                signer.context("authentication requires a SAP signer")?,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn loads_bag_once_and_uses_current_purchase_url() {
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
                    return Ok(HostResponse {
                        status: 200,
                        headers: std::collections::HashMap::from([("content-type".into(), "application/x-apple-plist".into())]),
                        body: br#"<plist version="1.0"><dict><key>urlBag</key><dict><key>buyProduct</key><string>https://buy.itunes.apple.com/stale</string></dict><key>unrelatedCertificate</key><data>AQID</data><key>unrelatedDate</key><date>2024-05-01T00:00:00Z</date></dict></plist>"#.to_vec(),
                    });
                }
                assert_eq!(request.url.as_str(), "https://buy.itunes.apple.com/request");
                assert_eq!(
                    request.headers.get(USER_AGENT).unwrap(),
                    PURCHASE_USER_AGENT
                );
                Ok(HostResponse {
                    status: 200,
                    headers: std::collections::HashMap::from([("content-type".into(), "application/x-apple-plist".into())]),
                    body: br#"<plist version="1.0"><dict><key>status</key><integer>0</integer></dict></plist>"#.to_vec(),
                })
            },
        );
        let mut headers = HeaderMap::new();
        headers.insert("X-Dsid", HeaderValue::from_static("123456"));
        headers.insert("X-Token", HeaderValue::from_static("test-token"));
        headers.insert(
            "X-Apple-Store-Front",
            HeaderValue::from_static("143441-1,29"),
        );
        let parameters = serde_json::json!({
            "salableAdamId": "1234", "pricingParameters": "STDQ", "price": "0",
            "productType": "C", "appleId": "test@example.com", "password": "test"
        });
        let response = backend
            .execute_purchase(StoreBackendRequest {
                method: "POST",
                url: "https://buy.itunes.apple.com/request",
                headers: &headers,
                parameters: Some(&parameters),
                body: None,
                raw: false,
                response_format: "plist",
                no_redirects: false,
                timeout: None,
            })
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(backend.bag().is_ok());
        assert_eq!(backend.sap_config().unwrap().version, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
