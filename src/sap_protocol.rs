//! Certificate and setup-message exchange for Apple's SAP signer.

use std::{io::Read, time::Duration};

use anyhow::{Context, Result, bail};
use plist::{Dictionary, Value};
use reqwest::{
    Method,
    blocking::Client,
    header::{CONTENT_TYPE, USER_AGENT},
};
use url::Url;

const CERTIFICATE_KEY: &str = "sign-sap-setup-cert";
const BUFFER_KEY: &str = "sign-sap-setup-buffer";
const MAX_SETUP_BODY: usize = 1 << 20;
const USER_AGENT_VALUE: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

pub struct SapRequest {
    pub method: Method,
    pub url: Url,
    pub user_agent: &'static str,
    pub content_type: Option<&'static str>,
    pub body: Option<Vec<u8>>,
}

pub struct SapResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait SapHttpClient {
    fn send(&self, request: SapRequest) -> Result<SapResponse>;
}

pub struct ReqwestSapClient {
    client: Client,
}

impl ReqwestSapClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("create SAP HTTP client")?,
        })
    }
}

impl SapHttpClient for ReqwestSapClient {
    fn send(&self, request: SapRequest) -> Result<SapResponse> {
        let mut builder = self.client.request(request.method, request.url);
        builder = builder.header(USER_AGENT, request.user_agent);
        if let Some(content_type) = request.content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder.send().context("send SAP request")?;
        let status = response.status().as_u16();
        if status != 200 {
            return Ok(SapResponse {
                status,
                body: Vec::new(),
            });
        }
        let mut body = Vec::new();
        response
            .take((MAX_SETUP_BODY + 1) as u64)
            .read_to_end(&mut body)
            .context("read SAP response")?;
        if body.len() > MAX_SETUP_BODY {
            bail!("apple response exceeds {MAX_SETUP_BODY} bytes");
        }
        Ok(SapResponse { status, body })
    }
}

pub struct SapProtocol<C> {
    client: C,
}

impl<C: SapHttpClient> SapProtocol<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }

    pub fn certificate(&self, endpoint: Url) -> Result<Vec<u8>> {
        validate_endpoint(&endpoint)?;
        let response = self
            .client
            .send(SapRequest {
                method: Method::GET,
                url: endpoint,
                user_agent: USER_AGENT_VALUE,
                content_type: None,
                body: None,
            })
            .context("fetch SAP certificate")?;
        parse_response(response, CERTIFICATE_KEY).context("fetch SAP certificate")
    }

    pub fn exchange(&self, endpoint: Url, input: &[u8]) -> Result<Vec<u8>> {
        validate_endpoint(&endpoint)?;
        let envelope = encode_plist_bytes(BUFFER_KEY, input).context("encode SAP setup message")?;
        let response = self
            .client
            .send(SapRequest {
                method: Method::POST,
                url: endpoint,
                user_agent: USER_AGENT_VALUE,
                content_type: Some("application/x-plist"),
                body: Some(envelope),
            })
            .context("exchange SAP setup message")?;
        parse_response(response, BUFFER_KEY).context("exchange SAP setup message")
    }
}

fn validate_endpoint(url: &Url) -> Result<()> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("SAP endpoint must be an absolute HTTPS URL");
    }
    Ok(())
}

fn parse_response(response: SapResponse, key: &str) -> Result<Vec<u8>> {
    if response.status != 200 {
        bail!("apple returned HTTP {}", response.status);
    }
    if response.body.len() > MAX_SETUP_BODY {
        bail!("apple response exceeds {MAX_SETUP_BODY} bytes");
    }
    plist_bytes(&response.body, key)
}

fn encode_plist_bytes(key: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut dictionary = Dictionary::new();
    dictionary.insert(key.into(), Value::Data(bytes.to_vec()));
    let mut output = Vec::new();
    plist::to_writer_xml(&mut output, &Value::Dictionary(dictionary))?;
    Ok(output)
}

fn plist_bytes(document: &[u8], key: &str) -> Result<Vec<u8>> {
    let values: Value = plist::from_bytes(document).context("decode Apple plist")?;
    let value = values
        .as_dictionary()
        .and_then(|values| values.get(key))
        .and_then(Value::as_data)
        .filter(|data| !data.is_empty());
    match value {
        Some(data) => Ok(data.to_vec()),
        None => bail!("Apple plist is missing {key}"),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct MockClient {
        calls: RefCell<Vec<SapRequest>>,
    }

    impl SapHttpClient for MockClient {
        fn send(&self, request: SapRequest) -> Result<SapResponse> {
            let key = if request.method == Method::GET {
                CERTIFICATE_KEY
            } else {
                BUFFER_KEY
            };
            let value = if request.method == Method::GET {
                b"certificate".as_slice()
            } else {
                b"reply".as_slice()
            };
            self.calls.borrow_mut().push(request);
            Ok(SapResponse {
                status: 200,
                body: encode_plist_bytes(key, value)?,
            })
        }
    }

    #[test]
    fn exchanges_certificate_and_setup_plists() {
        let client = MockClient {
            calls: RefCell::new(Vec::new()),
        };
        let protocol = SapProtocol::new(client);
        let endpoint = Url::parse("https://example.test/setup").unwrap();
        assert_eq!(
            protocol.certificate(endpoint.clone()).unwrap(),
            b"certificate"
        );
        assert_eq!(protocol.exchange(endpoint, b"request").unwrap(), b"reply");
        let calls = protocol.client.calls.borrow();
        assert_eq!(calls[0].method, Method::GET);
        assert_eq!(calls[0].user_agent, USER_AGENT_VALUE);
        assert!(calls[0].body.is_none());
        assert_eq!(calls[1].method, Method::POST);
        assert_eq!(calls[1].content_type, Some("application/x-plist"));
        assert_eq!(
            plist_bytes(calls[1].body.as_ref().unwrap(), BUFFER_KEY).unwrap(),
            b"request"
        );
    }

    #[test]
    fn rejects_invalid_status_body_and_endpoint() {
        assert!(
            parse_response(
                SapResponse {
                    status: 503,
                    body: vec![]
                },
                CERTIFICATE_KEY
            )
            .is_err()
        );
        assert!(
            parse_response(
                SapResponse {
                    status: 200,
                    body: vec![0; MAX_SETUP_BODY + 1]
                },
                CERTIFICATE_KEY
            )
            .is_err()
        );
        assert!(plist_bytes(b"<plist><dict/></plist>", CERTIFICATE_KEY).is_err());
        assert!(validate_endpoint(&Url::parse("http://example.test").unwrap()).is_err());
        assert!(validate_endpoint(&Url::parse("https://user@example.test").unwrap()).is_err());
    }
}
