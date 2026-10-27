//! Shared Store HTTP transport and typed response decoding.

use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use reqwest::{
    Method,
    blocking::{Client, Response as HttpResponse},
    header::{
        AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, HeaderMap, HeaderValue,
        LOCATION, PROXY_AUTHORIZATION, SET_COOKIE,
    },
    redirect::Policy,
};
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use url::Url;

use crate::cookies::SavedCookies;

static DOCUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<Document\b[^>]*>(.*?)</Document>").unwrap());
static PLIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<plist\b[^>]*>.*?</plist>").unwrap());
static DICT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<dict\b[^>]*>.*</dict>").unwrap());
static HTML_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<[^>]*>").unwrap());
static SHARED_COOKIES: LazyLock<Mutex<HashMap<PathBuf, Weak<Mutex<SavedCookies>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub const DEFAULT_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STORE_RESPONSE_BODY: usize = 32 << 20;
static VERBOSE_HTTP: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
enum BodyPolicy {
    Unbounded,
    Sap(usize),
    Store(usize),
}

pub fn set_verbose(enabled: bool) {
    VERBOSE_HTTP.store(enabled, Ordering::Relaxed);
}

fn shared_cookies(state_directory: &Path) -> Result<Arc<Mutex<SavedCookies>>> {
    let key = state_directory
        .canonicalize()
        .unwrap_or_else(|_| state_directory.to_path_buf());
    let mut registry = SHARED_COOKIES
        .lock()
        .map_err(|_| anyhow!("shared cookie registry lock is poisoned"))?;
    registry.retain(|_, weak| weak.strong_count() > 0);
    if let Some(existing) = registry.get(&key).and_then(Weak::upgrade) {
        return Ok(existing);
    }
    let cookies = Arc::new(Mutex::new(SavedCookies::open(state_directory)?));
    registry.insert(key, Arc::downgrade(&cookies));
    Ok(cookies)
}

pub struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
    pub no_redirects: bool,
    pub timeout: Option<Duration>,
}

impl Request {
    pub fn get(url: Url) -> Self {
        Self {
            method: Method::GET,
            url,
            headers: HeaderMap::new(),
            body: None,
            no_redirects: false,
            timeout: None,
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub set_cookie_headers: Vec<String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .get(&key.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn ensure_success(&self) -> Result<()> {
        if (200..300).contains(&self.status) {
            Ok(())
        } else {
            bail!("App Store returned HTTP {}", self.status)
        }
    }

    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).context("failed to decode JSON response")
    }

    pub fn plist<T: DeserializeOwned>(&self, authentication: bool) -> Result<T> {
        if authentication
            && is_authentication_redirect(self.status)
            && self.header("location").is_none_or(str::is_empty)
        {
            return Err(
                self.unexpected_authentication("authentication redirect is missing Location")
            );
        }
        if (300..400).contains(&self.status) {
            bail!("redirect response (HTTP {})", self.status);
        }
        if self.status == 429 && !authentication {
            bail!(
                "rate limited by Apple (HTTP 429): {}",
                body_snippet(&self.body)
            );
        }
        let normalized = normalize_plist_body(&self.body);
        if !looks_like_plist(&normalized) {
            if authentication {
                if self.status == 429 {
                    return Err(self.unexpected_authentication("rate limited by Apple"));
                }
                return Err(
                    self.unexpected_authentication("empty or non-plist authentication response")
                );
            }
            bail!(
                "unexpected response from Apple (HTTP {}): {}",
                self.status,
                body_snippet(&self.body)
            );
        }
        plist::from_bytes(&normalized).map_err(|err| {
            if authentication {
                self.unexpected_authentication("malformed authentication plist")
            } else {
                anyhow!("failed to decode property list: {err}")
            }
        })
    }

    fn unexpected_authentication(&self, reason: &str) -> anyhow::Error {
        // Auth response bodies can contain tokens and cookies. Never include them in errors.
        anyhow!(
            "unexpected response from Apple (HTTP {}): {} (body length={}, content type={:?}, correlation ID={:?})",
            self.status,
            reason,
            self.body.len(),
            self.header("content-type").unwrap_or_default(),
            self.header("x-apple-jingle-correlation-key")
                .unwrap_or_default()
        )
    }
}

pub struct Transport {
    follow_redirects: Client,
    no_redirects: Client,
    cookies: Option<Arc<Mutex<SavedCookies>>>,
}

impl Transport {
    pub fn new() -> Result<Self> {
        Ok(Self {
            follow_redirects: Client::builder()
                .build()
                .context("failed to create HTTP client")?,
            no_redirects: Client::builder()
                .redirect(Policy::none())
                .build()
                .context("failed to create non-redirecting HTTP client")?,
            cookies: None,
        })
    }

    pub fn with_cookies(state_directory: &Path) -> Result<Self> {
        let mut transport = Self::new()?;
        transport.cookies = Some(shared_cookies(state_directory)?);
        Ok(transport)
    }

    pub fn send(&self, request: Request) -> Result<Response> {
        self.send_with_policy(request, BodyPolicy::Unbounded)
    }

    /// Bound decoded Store API responses while retaining finance error bodies.
    pub(crate) fn send_store(&self, request: Request) -> Result<Response> {
        self.send_with_policy(request, BodyPolicy::Store(MAX_STORE_RESPONSE_BODY))
    }

    fn send_with_policy(&self, request: Request, policy: BodyPolicy) -> Result<Response> {
        let trace = VERBOSE_HTTP
            .load(Ordering::Relaxed)
            .then(|| (request.method.clone(), request.url.clone(), Instant::now()));
        let result = self.send_inner(request, policy);
        if let Some((method, url, started)) = trace {
            let status = result.as_ref().map_or_else(
                |_| "error".to_owned(),
                |response| response.status.to_string(),
            );
            eprintln!(
                "{}",
                verbose_http_line(&method, &url, &status, started.elapsed())
            );
        }
        result
    }

    /// Share Store cookies while bounding responses from setup endpoints.
    pub(crate) fn send_bounded(&self, request: Request, max_body: usize) -> Result<Response> {
        self.send_with_policy(request, BodyPolicy::Sap(max_body))
    }

    /// Send a Store transfer without buffering its body. Transfers share the
    /// same in-memory cookie jar as Store requests, including session cookies.
    pub fn stream_get(
        &self,
        mut url: Url,
        headers: HeaderMap,
        timeout: Option<Duration>,
    ) -> Result<HttpResponse> {
        if !matches!(url.scheme(), "http" | "https") {
            bail!("unsupported transfer URL scheme");
        }
        let mut client_builder = Client::builder().redirect(Policy::none());
        if headers.contains_key(reqwest::header::RANGE)
            || headers
                .get(reqwest::header::ACCEPT_ENCODING)
                .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            client_builder = client_builder.no_gzip().no_brotli().no_deflate();
        }
        let client = client_builder
            .build()
            .context("create Store transfer client")?;
        let mut headers = headers;
        for redirects in 0..=10 {
            let mut send_headers = headers.clone();
            if !send_headers.contains_key(COOKIE)
                && let Some(cookies) = &self.cookies
                && let Some(cookie_header) = cookies
                    .lock()
                    .map_err(|_| anyhow!("cookie jar lock is poisoned"))?
                    .header_for(&url, OffsetDateTime::now_utc())
            {
                send_headers.insert(
                    COOKIE,
                    HeaderValue::from_str(&cookie_header).context("invalid saved cookie header")?,
                );
            }
            let mut builder = client.get(url.clone()).headers(send_headers);
            if let Some(timeout) = timeout {
                builder = builder.timeout(timeout);
            }
            let response = builder.send().context("Store transfer request failed")?;
            if let Some(cookies) = &self.cookies {
                let mut jar = cookies
                    .lock()
                    .map_err(|_| anyhow!("cookie jar lock is poisoned"))?;
                let now = OffsetDateTime::now_utc();
                for value in response.headers().get_all(SET_COOKIE).iter() {
                    if let Ok(raw) = value.to_str() {
                        jar.set_cookie(&url, raw, now);
                    }
                }
                jar.save(now).context("failed to save transfer cookies")?;
            }
            if !response.status().is_redirection() {
                return Ok(response);
            }
            let Some(location) = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
            else {
                return Ok(response);
            };
            if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            if redirects == 10 {
                bail!("too many Store transfer redirects");
            }
            let next = url
                .join(location)
                .context("invalid Store transfer redirect")?;
            if !matches!(next.scheme(), "http" | "https") {
                bail!("unsupported Store transfer redirect scheme");
            }
            if next.origin() != url.origin() {
                headers.remove(AUTHORIZATION);
                headers.remove(PROXY_AUTHORIZATION);
                headers.remove(COOKIE);
                headers.remove(HOST);
            }
            url = next;
        }
        unreachable!("redirect limit returns before loop exhaustion")
    }

    fn send_inner(&self, request: Request, policy: BodyPolicy) -> Result<Response> {
        if let Some(cookies) = &self.cookies {
            return self.send_with_cookies(request, cookies, policy);
        }
        let client = if request.no_redirects {
            &self.no_redirects
        } else {
            &self.follow_redirects
        };
        let mut builder = client
            .request(request.method, request.url)
            .headers(request.headers);
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder.send().context("request failed")?;
        Self::response_from_http(response, policy)
    }

    fn send_with_cookies(
        &self,
        request: Request,
        cookies: &Mutex<SavedCookies>,
        policy: BodyPolicy,
    ) -> Result<Response> {
        let mut method = request.method;
        let mut url = request.url;
        let mut headers = request.headers;
        let mut body = request.body;
        for redirects in 0..=10 {
            let mut send_headers = headers.clone();
            if !send_headers.contains_key(COOKIE) {
                let cookie_header = cookies
                    .lock()
                    .map_err(|_| anyhow!("cookie jar lock is poisoned"))?
                    .header_for(&url, OffsetDateTime::now_utc());
                if let Some(cookie_header) = cookie_header {
                    send_headers.insert(
                        COOKIE,
                        HeaderValue::from_str(&cookie_header)
                            .context("invalid saved cookie header")?,
                    );
                }
            }
            let mut builder = self
                .no_redirects
                .request(method.clone(), url.clone())
                .headers(send_headers);
            if let Some(data) = &body {
                builder = builder.body(data.clone());
            }
            if let Some(timeout) = request.timeout {
                builder = builder.timeout(timeout);
            }
            let response = builder.send().context("request failed")?;
            {
                let mut jar = cookies
                    .lock()
                    .map_err(|_| anyhow!("cookie jar lock is poisoned"))?;
                let now = OffsetDateTime::now_utc();
                for value in response.headers().get_all(SET_COOKIE).iter() {
                    if let Ok(raw) = value.to_str() {
                        jar.set_cookie(&url, raw, now);
                    }
                }
                jar.save(now).context("failed to save cookies")?;
            }
            let status = response.status().as_u16();
            let Some(location) = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
            else {
                return Self::response_from_http(response, policy);
            };
            if request.no_redirects || !matches!(status, 301 | 302 | 303 | 307 | 308) {
                return Self::response_from_http(response, policy);
            }
            if redirects == 10 {
                bail!("too many HTTP redirects");
            }
            let next = url.join(location).context("invalid redirect Location")?;
            if !matches!(next.scheme(), "http" | "https") {
                bail!("unsupported redirect scheme");
            }
            if next.origin() != url.origin() {
                headers.remove(AUTHORIZATION);
                headers.remove(PROXY_AUTHORIZATION);
                headers.remove(COOKIE);
                headers.remove(HOST);
            }
            if status == 303 || (matches!(status, 301 | 302) && method == Method::POST) {
                method = Method::GET;
                body = None;
                headers.remove(CONTENT_TYPE);
                headers.remove(CONTENT_LENGTH);
            }
            url = next;
        }
        unreachable!("redirect limit returns before loop exhaustion")
    }

    fn response_from_http(response: HttpResponse, policy: BodyPolicy) -> Result<Response> {
        let status = response.status().as_u16();
        let set_cookie_headers = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect();
        let mut headers: HashMap<String, String> = HashMap::new();
        for (key, value) in response.headers().iter() {
            let value = value.to_str().unwrap_or_default();
            headers
                .entry(key.as_str().to_ascii_lowercase())
                .and_modify(|combined| {
                    combined.push_str(", ");
                    combined.push_str(value);
                })
                .or_insert_with(|| value.to_owned());
        }
        let body = match policy {
            BodyPolicy::Sap(_) if status != 200 => Vec::new(),
            BodyPolicy::Sap(limit) | BodyPolicy::Store(limit) => {
                let mut body = Vec::new();
                response
                    .take(limit.saturating_add(1) as u64)
                    .read_to_end(&mut body)
                    .context("failed to read response body")?;
                if body.len() > limit {
                    match policy {
                        BodyPolicy::Store(_) => bail!("Store API response exceeds size limit"),
                        BodyPolicy::Sap(_) => bail!("Apple response exceeds {limit} bytes"),
                        BodyPolicy::Unbounded => unreachable!(),
                    }
                }
                body
            }
            BodyPolicy::Unbounded => response
                .bytes()
                .context("failed to read response body")?
                .to_vec(),
        };
        Ok(Response {
            status,
            headers,
            set_cookie_headers,
            body,
        })
    }
}

fn verbose_http_line(method: &Method, url: &Url, status: &str, elapsed: Duration) -> String {
    format!(
        "http {} {}://{} status={} elapsed_ms={}",
        method,
        url.scheme(),
        url.host_str().unwrap_or("unknown"),
        status,
        elapsed.as_millis()
    )
}

pub fn is_authentication_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 307 | 308)
}

fn normalize_plist_body(body: &[u8]) -> Vec<u8> {
    let trimmed = trim_ascii(body);
    if trimmed.starts_with(b"bplist") {
        return trimmed.to_vec();
    }
    let text = String::from_utf8_lossy(trimmed);
    let document = DOCUMENT
        .captures(&text)
        .and_then(|match_| match_.get(1))
        .map_or(text.as_ref(), |inner| inner.as_str())
        .trim();
    if let Some(plist) = PLIST.find(document) {
        return plist.as_str().as_bytes().to_vec();
    }
    if let Some(dict) = DICT.find(document) {
        return format!("<plist version=\"1.0\">{}</plist>", dict.as_str()).into_bytes();
    }
    if document.contains("<key>") {
        return format!("<plist version=\"1.0\"><dict>{document}</dict></plist>").into_bytes();
    }
    trimmed.to_vec()
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn looks_like_plist(body: &[u8]) -> bool {
    if body.starts_with(b"bplist") {
        return true;
    }
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    ["<?xml", "<plist", "<dict", "<key"]
        .iter()
        .any(|marker| text.contains(marker))
}

fn body_snippet(body: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(body);
    let text = HTML_TAG.replace_all(&decoded, " ");
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let head: String = chars.by_ref().take(200).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread,
    };

    fn response(status: u16, body: &str) -> Response {
        Response {
            set_cookie_headers: Vec::new(),
            status,
            headers: HashMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn verbose_http_line_omits_url_credentials_and_request_details() {
        let url = Url::parse(
            "https://user:secret@buy.itunes.apple.com/private/token?password=secret#fragment",
        )
        .unwrap();
        let line = verbose_http_line(&Method::POST, &url, "200", Duration::from_millis(12));
        assert_eq!(
            line,
            "http POST https://buy.itunes.apple.com status=200 elapsed_ms=12"
        );
    }

    #[test]
    fn normalizes_apple_document_envelope_and_decodes_plist() {
        let res = response(
            200,
            "<Document><key>answer</key><string>yes</string></Document>",
        );
        let value: HashMap<String, String> = res.plist(false).unwrap();
        assert_eq!(value["answer"], "yes");
    }

    #[test]
    fn authentication_errors_never_echo_response_body() {
        let res = response(200, "<html>passwordToken=private-secret</html>");
        let error = res
            .plist::<HashMap<String, String>>(true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("empty or non-plist"));
        assert!(!error.contains("private-secret"));
    }

    #[test]
    fn authentication_429_with_plist_keeps_server_error() {
        let res = response(
            429,
            r#"<plist version="1.0"><dict><key>failureType</key><string>2034</string></dict></plist>"#,
        );
        let value: HashMap<String, String> = res.plist(true).unwrap();
        assert_eq!(value["failureType"], "2034");
    }

    #[test]
    fn redirect_allowlist_excludes_303_and_requires_location_for_authentication() {
        assert!(is_authentication_redirect(301));
        assert!(is_authentication_redirect(302));
        assert!(is_authentication_redirect(307));
        assert!(is_authentication_redirect(308));
        assert!(!is_authentication_redirect(303));
        let res = response(302, "sensitive");
        let error = res
            .plist::<HashMap<String, String>>(true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing Location"));
        assert!(!error.contains("sensitive"));
    }

    #[test]
    fn raw_response_keeps_status_and_case_insensitive_headers() {
        let mut res = response(206, "part");
        res.headers
            .insert("content-range".into(), "bytes 0-3/8".into());
        assert_eq!(res.header("Content-Range"), Some("bytes 0-3/8"));
        assert_eq!(res.body, b"part");
    }

    #[test]
    fn preserves_all_set_cookie_headers_for_store_guest() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: one=1; Path=/\r\nSet-Cookie: two=2; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let transport = Transport::with_cookies(directory.path()).unwrap();
        let response = transport
            .send_store(Request::get(
                Url::parse(&format!("http://{address}/cookies")).unwrap(),
            ))
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            response.set_cookie_headers,
            ["one=1; Path=/", "two=2; Path=/"]
        );
        assert_eq!(
            response.header("set-cookie"),
            Some("one=1; Path=/, two=2; Path=/")
        );
        let jar = transport.cookies.as_ref().unwrap().lock().unwrap();
        let header = jar
            .header_for(
                &Url::parse(&format!("http://{address}/cookies")).unwrap(),
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        assert!(header.contains("one=1"));
        assert!(header.contains("two=2"));
    }

    #[test]
    fn cookie_transport_saves_and_replays_cookie_across_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for index in 0..2 {
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
                if index == 0 {
                    assert!(lines[0].starts_with("GET /start "));
                    stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nSet-Cookie: sid=dummy-value; Max-Age=3600; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else {
                    assert!(lines[0].starts_with("GET /next "));
                    assert!(lines.iter().any(|line| {
                        line.to_ascii_lowercase()
                            .starts_with("cookie: sid=dummy-value")
                    }));
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .unwrap();
                }
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let transport = Transport::with_cookies(directory.path()).unwrap();
        let response = transport
            .send(Request::get(
                Url::parse(&format!("http://{address}/start")).unwrap(),
            ))
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        server.join().unwrap();
        let saved = SavedCookies::open(directory.path()).unwrap();
        assert_eq!(
            saved
                .header_for(
                    &Url::parse(&format!("http://{address}/next")).unwrap(),
                    OffsetDateTime::now_utc()
                )
                .as_deref(),
            Some("sid=dummy-value")
        );
    }

    #[test]
    fn separate_store_clients_share_session_cookies_only_within_state_directory() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for index in 0..2 {
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
                if index == 0 {
                    assert!(lines[0].starts_with("GET /login "));
                    stream.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: session=fixture; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                } else {
                    assert!(lines[0].starts_with("GET /purchase "));
                    assert!(lines.iter().any(|line| {
                        line.to_ascii_lowercase()
                            .starts_with("cookie: session=fixture")
                    }));
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .unwrap();
                }
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let separate = tempfile::tempdir().unwrap();
        let login = Transport::with_cookies(directory.path()).unwrap();
        let purchase = Transport::with_cookies(directory.path()).unwrap();
        let unrelated = Transport::with_cookies(separate.path()).unwrap();
        assert!(Arc::ptr_eq(
            login.cookies.as_ref().unwrap(),
            purchase.cookies.as_ref().unwrap()
        ));
        assert!(!Arc::ptr_eq(
            login.cookies.as_ref().unwrap(),
            unrelated.cookies.as_ref().unwrap()
        ));
        login
            .send(Request::get(
                Url::parse(&format!("http://{address}/login")).unwrap(),
            ))
            .unwrap();
        purchase
            .send(Request::get(
                Url::parse(&format!("http://{address}/purchase")).unwrap(),
            ))
            .unwrap();
        server.join().unwrap();
        let unrelated_cookie = unrelated
            .cookies
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .header_for(
                &Url::parse(&format!("http://{address}/purchase")).unwrap(),
                OffsetDateTime::now_utc(),
            );
        assert!(unrelated_cookie.is_none());
    }

    #[test]
    fn authentication_style_no_redirects_still_saves_cookie() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /login-next\r\nSet-Cookie: auth=dummy; Max-Age=3600; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let transport = Transport::with_cookies(directory.path()).unwrap();
        let url = Url::parse(&format!("http://{address}/login")).unwrap();
        let mut request = Request::get(url.clone());
        request.no_redirects = true;
        assert_eq!(transport.send(request).unwrap().status, 302);
        server.join().unwrap();
        let saved = SavedCookies::open(directory.path()).unwrap();
        assert_eq!(
            saved.header_for(&url, OffsetDateTime::now_utc()).as_deref(),
            Some("auth=dummy")
        );
    }

    #[test]
    fn store_response_limit_keeps_server_error_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (status, body) in [("200 OK", "12345"), ("500 Error", "oops")] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let transport = Transport::new().unwrap();
        let url = Url::parse(&format!("http://{address}/store")).unwrap();
        let error = transport
            .send_with_policy(Request::get(url.clone()), BodyPolicy::Store(4))
            .err()
            .unwrap();
        assert!(error.to_string().contains("response exceeds size limit"));
        let response = transport
            .send_with_policy(Request::get(url), BodyPolicy::Store(4))
            .unwrap();
        assert_eq!(response.status, 500);
        assert_eq!(response.body, b"oops");
        server.join().unwrap();
    }
}
