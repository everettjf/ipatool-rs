//! Read-only interoperability with juju/persistent-cookiejar's saved JSON.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, de::IgnoredAny};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::state::COOKIE_JAR_FILE_NAME;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    #[serde(rename = "HttpOnly")]
    _http_only: bool,
    persistent: bool,
    host_only: bool,
    expires: String,
    creation: String,
    #[serde(rename = "LastAccess")]
    _last_access: String,
    #[serde(rename = "Updated")]
    _updated: String,
    canonical_host: String,
}

/// Cookies loaded from a Go session. The jar does not change or save the file.
pub struct SavedCookies {
    entries: Vec<Entry>,
}

impl Drop for SavedCookies {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.value.zeroize();
        }
    }
}

impl SavedCookies {
    pub fn open(state_directory: &Path) -> Result<Self> {
        let path = state_directory.join(COOKIE_JAR_FILE_NAME);
        match fs::read(&path) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                if bytes.iter().all(u8::is_ascii_whitespace) {
                    return Ok(Self {
                        entries: Vec::new(),
                    });
                }
                let entries = match serde_json::from_slice::<Vec<Entry>>(&bytes) {
                    Ok(entries) => entries,
                    Err(_) => {
                        // The Go jar ignores valid JSON in an older or unknown format.
                        serde_json::from_slice::<IgnoredAny>(&bytes).with_context(|| {
                            format!("failed to decode cookie jar: {}", path.display())
                        })?;
                        Vec::new()
                    }
                };
                Ok(Self { entries })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                entries: Vec::new(),
            }),
            Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    /// Return the request Cookie header, if any, using Go's domain, path and ordering rules.
    pub fn header_for(&self, url: &Url, now: OffsetDateTime) -> Option<String> {
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
        let request_path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        let mut selected = self
            .entries
            .iter()
            .filter(|entry| {
                entry.persistent
                    && !entry.value.is_empty()
                    && !entry.canonical_host.is_empty()
                    && valid_cookie_pair(&entry.name, &entry.value)
                    && OffsetDateTime::parse(&entry.expires, &Rfc3339)
                        .is_ok_and(|expires| expires > now)
                    && (!entry.secure || url.scheme() == "https")
                    && domain_matches(entry, &host)
                    && path_matches(&entry.path, request_path)
            })
            .collect::<Vec<_>>();
        selected.sort_by(|left, right| {
            right.path.len().cmp(&left.path.len()).then_with(|| {
                let left_date = OffsetDateTime::parse(&left.creation, &Rfc3339).ok();
                let right_date = OffsetDateTime::parse(&right.creation, &Rfc3339).ok();
                left_date.cmp(&right_date)
            })
        });
        if selected.is_empty() {
            return None;
        }
        Some(
            selected
                .iter()
                .map(|entry| format!("{}={}", entry.name, entry.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

fn domain_matches(entry: &Entry, host: &str) -> bool {
    entry.domain.eq_ignore_ascii_case(host)
        || (!entry.host_only
            && host.len() > entry.domain.len()
            && host.ends_with(&format!(".{}", entry.domain.to_ascii_lowercase())))
}

fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path.is_empty() || !cookie_path.starts_with('/') {
        return false;
    }
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/')
                || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}

fn valid_cookie_pair(name: &str, value: &str) -> bool {
    !name.is_empty()
        && !name
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || matches!(byte, b'=' | b';'))
        && !value
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b';')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_go_jar_and_matches_scope_without_leaking_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let data = r#"[{"Name":"a","Value":"one","Domain":"example.test","Path":"/","Secure":true,"HttpOnly":true,"Persistent":true,"HostOnly":false,"Expires":"2030-01-01T00:00:00Z","Creation":"2020-01-01T00:00:00Z","LastAccess":"2020-01-01T00:00:00Z","Updated":"2020-01-01T00:00:00Z","CanonicalHost":"example.test"},{"Name":"b","Value":"two","Domain":"example.test","Path":"/account","Secure":false,"HttpOnly":false,"Persistent":true,"HostOnly":true,"Expires":"2030-01-01T00:00:00Z","Creation":"2021-01-01T00:00:00Z","LastAccess":"2021-01-01T00:00:00Z","Updated":"2021-01-01T00:00:00Z","CanonicalHost":"example.test"}]"#;
        fs::write(directory.path().join(COOKIE_JAR_FILE_NAME), data).unwrap();
        let jar = SavedCookies::open(directory.path()).unwrap();
        let now = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339).unwrap();
        let url = Url::parse("https://example.test/account/home").unwrap();
        assert_eq!(jar.header_for(&url, now).as_deref(), Some("b=two; a=one"));
        assert_eq!(
            jar.header_for(
                &Url::parse("https://sub.example.test/account").unwrap(),
                now
            )
            .as_deref(),
            Some("a=one")
        );
        assert!(
            jar.header_for(&Url::parse("http://example.test/other").unwrap(), now)
                .is_none()
        );
        assert!(
            jar.header_for(
                &url,
                OffsetDateTime::parse("2031-01-01T00:00:00Z", &Rfc3339).unwrap()
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_bad_files_without_echoing_contents() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join(COOKIE_JAR_FILE_NAME),
            b"secret-invalid-json",
        )
        .unwrap();
        let error = SavedCookies::open(directory.path())
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("secret-invalid-json"));
        assert!(SavedCookies::open(tempfile::tempdir().unwrap().path()).is_ok());
    }

    #[test]
    fn discards_valid_legacy_json() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(COOKIE_JAR_FILE_NAME), b"{}").unwrap();
        let jar = SavedCookies::open(directory.path()).unwrap();
        let now = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339).unwrap();
        assert!(
            jar.header_for(&Url::parse("https://example.test/").unwrap(), now)
                .is_none()
        );
    }
}
