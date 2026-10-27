//! Certificate and setup-message exchange for Apple's SAP signer.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use plist::{Dictionary, Value};
use reqwest::{
    Method,
    header::{CONTENT_TYPE, HeaderValue, USER_AGENT},
};
use url::Url;

use crate::{
    state::prepare_state_directory_from_environment,
    transport::{Request, Transport},
};

const CERTIFICATE_KEY: &str = "sign-sap-setup-cert";
const BUFFER_KEY: &str = "sign-sap-setup-buffer";
const MAX_SETUP_BODY: usize = 1 << 20;
const MAX_SETUP_REQUEST_BODY: usize = 1 << 20;
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
    transport: Transport,
}

impl ReqwestSapClient {
    pub fn new() -> Result<Self> {
        let state_directory = prepare_state_directory_from_environment()?;
        Ok(Self {
            transport: Transport::with_cookies(&state_directory)
                .context("create SAP HTTP client")?,
        })
    }
}

impl SapHttpClient for ReqwestSapClient {
    fn send(&self, request: SapRequest) -> Result<SapResponse> {
        if request
            .body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_SETUP_REQUEST_BODY)
        {
            bail!("Store request body exceeds {MAX_SETUP_REQUEST_BODY} bytes");
        }
        let mut host_request = Request::get(request.url);
        host_request.method = request.method;
        host_request.timeout = Some(Duration::from_secs(30));
        host_request
            .headers
            .insert(USER_AGENT, HeaderValue::from_static(request.user_agent));
        if let Some(content_type) = request.content_type {
            host_request
                .headers
                .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        host_request.body = request.body;
        let response = self
            .transport
            .send_bounded(host_request, MAX_SETUP_BODY)
            .context("send SAP request")?;
        Ok(SapResponse {
            status: response.status,
            body: response.body,
        })
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
    use std::{
        cell::RefCell,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
    };

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

    #[test]
    fn sap_setup_shares_store_session_cookies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for index in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut lines = Vec::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    lines.push(line);
                }
                let length = lines
                    .iter()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let (value, cookie) = match index {
                    0 => {
                        assert!(lines[0].starts_with("GET /store "));
                        (b"ok".to_vec(), "Set-Cookie: session=fixture; Path=/\r\n")
                    }
                    1 => {
                        assert!(lines[0].starts_with("GET /certificate "));
                        assert!(lines.iter().any(|line| {
                            line.to_ascii_lowercase()
                                .starts_with("cookie: session=fixture")
                        }));
                        (
                            encode_plist_bytes(CERTIFICATE_KEY, b"certificate").unwrap(),
                            "Set-Cookie: sap=ready; Path=/\r\n",
                        )
                    }
                    _ => {
                        assert!(lines[0].starts_with("POST /exchange "));
                        assert_eq!(plist_bytes(&body, BUFFER_KEY).unwrap(), b"request");
                        assert!(
                            lines
                                .iter()
                                .any(|line| line.to_ascii_lowercase().contains("session=fixture")
                                    && line.contains("sap=ready"))
                        );
                        (encode_plist_bytes(BUFFER_KEY, b"reply").unwrap(), "")
                    }
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    value.len()
                )
                .unwrap();
                stream.write_all(&value).unwrap();
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let store = Transport::with_cookies(directory.path()).unwrap();
        let sap = ReqwestSapClient {
            transport: Transport::with_cookies(directory.path()).unwrap(),
        };
        store
            .send(Request::get(
                Url::parse(&format!("http://{address}/store")).unwrap(),
            ))
            .unwrap();
        let certificate = sap
            .send(SapRequest {
                method: Method::GET,
                url: Url::parse(&format!("http://{address}/certificate")).unwrap(),
                user_agent: USER_AGENT_VALUE,
                content_type: None,
                body: None,
            })
            .unwrap();
        assert_eq!(
            plist_bytes(&certificate.body, CERTIFICATE_KEY).unwrap(),
            b"certificate"
        );
        let exchange = sap
            .send(SapRequest {
                method: Method::POST,
                url: Url::parse(&format!("http://{address}/exchange")).unwrap(),
                user_agent: USER_AGENT_VALUE,
                content_type: Some("application/x-plist"),
                body: Some(encode_plist_bytes(BUFFER_KEY, b"request").unwrap()),
            })
            .unwrap();
        assert_eq!(plist_bytes(&exchange.body, BUFFER_KEY).unwrap(), b"reply");
        server.join().unwrap();
    }

    #[test]
    fn rejects_oversized_sap_setup_request_before_network_io() {
        let client = ReqwestSapClient {
            transport: Transport::new().unwrap(),
        };
        let result = client.send(SapRequest {
            method: Method::POST,
            url: Url::parse("http://127.0.0.1:1/setup").unwrap(),
            user_agent: USER_AGENT_VALUE,
            content_type: Some("application/x-plist"),
            body: Some(vec![0; MAX_SETUP_REQUEST_BODY + 1]),
        });
        assert!(result.err().unwrap().to_string().contains("body exceeds"));
    }
}
