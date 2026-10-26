//! Shared Store HTTP transport and typed response decoding.

use std::{collections::HashMap, sync::LazyLock, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use reqwest::{Method, blocking::Client, header::HeaderMap, redirect::Policy};
use serde::de::DeserializeOwned;
use url::Url;

static DOCUMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<Document\b[^>]*>(.*?)</Document>").unwrap());
static PLIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<plist\b[^>]*>.*?</plist>").unwrap());
static DICT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<dict\b[^>]*>.*</dict>").unwrap());
static HTML_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<[^>]*>").unwrap());

pub const DEFAULT_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);

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
        if self.status == 429 {
            if authentication {
                return Err(self.unexpected_authentication("rate limited by Apple"));
            }
            bail!(
                "rate limited by Apple (HTTP 429): {}",
                body_snippet(&self.body)
            );
        }
        let normalized = normalize_plist_body(&self.body);
        if !looks_like_plist(&normalized) {
            if authentication {
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
        })
    }

    pub fn send(&self, request: Request) -> Result<Response> {
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
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(key, value)| {
                (
                    key.as_str().to_ascii_lowercase(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let body = response
            .bytes()
            .context("failed to read response body")?
            .to_vec();
        Ok(Response {
            status,
            headers,
            body,
        })
    }
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

    fn response(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: HashMap::new(),
            body: body.as_bytes().to_vec(),
        }
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
}
