//! Interoperability with juju/persistent-cookiejar's saved JSON.

use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use cookie::Cookie;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::state::COOKIE_JAR_FILE_NAME;

mod lock;
use lock::CookieFileLock;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    #[serde(rename = "HttpOnly")]
    http_only: bool,
    persistent: bool,
    host_only: bool,
    expires: String,
    creation: String,
    #[serde(rename = "LastAccess")]
    last_access: String,
    #[serde(rename = "Updated")]
    updated: String,
    canonical_host: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Go-compatible cookie entries, including in-memory session cookies.
pub struct SavedCookies {
    entries: Vec<Entry>,
    path: PathBuf,
}

impl SavedCookies {
    pub fn open(state_directory: &Path) -> Result<Self> {
        let path = state_directory.join(COOKIE_JAR_FILE_NAME);
        let _lock = if state_directory.exists() {
            Some(CookieFileLock::acquire(&path)?)
        } else {
            None
        };
        let entries = read_entries(&path)?;
        Ok(Self { entries, path })
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
                !entry.value.is_empty()
                    && !entry.canonical_host.is_empty()
                    && jar_key(&entry.canonical_host) == jar_key(&host)
                    && valid_cookie_pair(&entry.name, &entry.value)
                    && OffsetDateTime::parse(&entry.expires, &Rfc3339)
                        .is_ok_and(|expires| expires > now)
                    && (!entry.secure || url.scheme() == "https")
                    && domain_matches(entry, &host)
                    && path_matches(&entry.path, request_path)
            })
            .collect::<Vec<_>>();
        selected.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then_with(|| {
                    let left_date = OffsetDateTime::parse(&left.creation, &Rfc3339).ok();
                    let right_date = OffsetDateTime::parse(&right.creation, &Rfc3339).ok();
                    left_date.cmp(&right_date)
                })
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.value.cmp(&right.value))
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

    /// Apply a Set-Cookie header. Invalid or out-of-scope cookies are ignored.
    pub fn set_cookie(&mut self, url: &Url, raw: &str, now: OffsetDateTime) {
        if !matches!(url.scheme(), "http" | "https") {
            return;
        }
        let Some(host) = url.host_str() else {
            return;
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let Ok(cookie) = Cookie::parse(raw.to_owned()) else {
            return;
        };
        if !valid_cookie_pair(cookie.name(), cookie.value()) {
            return;
        }
        let domain = match cookie.domain() {
            Some(domain) => {
                let domain = domain
                    .strip_prefix('.')
                    .unwrap_or(domain)
                    .to_ascii_lowercase();
                if domain.is_empty()
                    || domain.starts_with('.')
                    || domain.ends_with('.')
                    || host.parse::<IpAddr>().is_ok()
                    || (host != domain && !host.ends_with(&format!(".{domain}")))
                {
                    return;
                }
                domain
            }
            None => host.clone(),
        };
        let host_only = cookie.domain().is_none();
        let path = cookie
            .path()
            .filter(|path| path.starts_with('/'))
            .map(str::to_owned)
            .unwrap_or_else(|| default_path(url.path()));
        let max_age = cookie.max_age();
        let (persistent, expires) = if let Some(age) = max_age {
            (true, now.checked_add(age).unwrap_or(now))
        } else if let Some(expires) = cookie.expires_datetime() {
            (true, expires)
        } else {
            (
                false,
                OffsetDateTime::parse("9999-12-31T23:59:59Z", &Rfc3339).unwrap(),
            )
        };
        let Ok(now_text) = now.format(&Rfc3339) else {
            return;
        };
        let Ok(expires_text) = expires.format(&Rfc3339) else {
            return;
        };
        let mut entry = Entry {
            name: cookie.name().to_owned(),
            value: if expires <= now {
                String::new()
            } else {
                cookie.value().to_owned()
            },
            domain,
            path,
            secure: cookie.secure().unwrap_or(false),
            http_only: cookie.http_only().unwrap_or(false),
            persistent,
            host_only,
            expires: expires_text,
            creation: now_text.clone(),
            last_access: now_text.clone(),
            updated: now_text,
            canonical_host: host,
        };
        if let Some(previous) = self
            .entries
            .iter_mut()
            .find(|existing| same_cookie(existing, &entry))
        {
            entry.creation.clone_from(&previous.creation);
            *previous = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Save persistent cookies after merging any newer on-disk entries.
    pub fn save(&mut self, now: OffsetDateTime) -> Result<()> {
        let _lock = CookieFileLock::acquire(&self.path)?;
        let disk_entries = read_entries(&self.path)?;
        for entry in disk_entries {
            merge_entry(&mut self.entries, entry);
        }
        let day_ago = now - time::Duration::days(1);
        self.entries.retain(|entry| {
            OffsetDateTime::parse(&entry.expires, &Rfc3339).is_ok_and(|expires| expires > now)
                || OffsetDateTime::parse(&entry.updated, &Rfc3339)
                    .is_ok_and(|updated| updated > day_ago)
        });
        let mut entries: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|entry| entry.persistent)
            .collect();
        entries.sort_by(|left, right| {
            left.canonical_host
                .cmp(&right.canonical_host)
                .then_with(|| right.path.len().cmp(&left.path.len()))
                .then_with(|| {
                    OffsetDateTime::parse(&left.creation, &Rfc3339)
                        .ok()
                        .cmp(&OffsetDateTime::parse(&right.creation, &Rfc3339).ok())
                })
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.value.cmp(&right.value))
        });
        let mut file = open_private_cookie_file(&self.path)?;
        file.set_len(0).context("failed to truncate cookie jar")?;
        file.seek(SeekFrom::Start(0))
            .context("failed to seek cookie jar")?;
        serde_json::to_writer(&mut file, &entries).context("failed to encode cookie jar")?;
        file.write_all(b"\n")
            .context("failed to finish cookie jar")?;
        file.sync_all().context("failed to sync cookie jar")?;
        Ok(())
    }
}

fn read_entries(path: &Path) -> Result<Vec<Entry>> {
    match fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            if bytes.iter().all(u8::is_ascii_whitespace) {
                return Ok(Vec::new());
            }
            match serde_json::from_slice::<Vec<Entry>>(&bytes) {
                Ok(entries) => {
                    let mut merged = Vec::new();
                    for entry in entries
                        .into_iter()
                        .filter(|entry| !entry.canonical_host.is_empty())
                    {
                        merge_entry(&mut merged, entry);
                    }
                    Ok(merged)
                }
                Err(_) => {
                    // The Go jar ignores valid JSON in an older or unknown format.
                    serde_json::from_slice::<IgnoredAny>(&bytes).with_context(|| {
                        format!("failed to decode cookie jar: {}", path.display())
                    })?;
                    Ok(Vec::new())
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn same_cookie(left: &Entry, right: &Entry) -> bool {
    jar_key(&left.canonical_host) == jar_key(&right.canonical_host)
        && left.domain == right.domain
        && left.path == right.path
        && left.name == right.name
}

fn merge_entry(entries: &mut Vec<Entry>, incoming: Entry) {
    if let Some(existing) = entries
        .iter_mut()
        .find(|entry| same_cookie(entry, &incoming))
    {
        let old_time = OffsetDateTime::parse(&existing.updated, &Rfc3339).ok();
        let new_time = OffsetDateTime::parse(&incoming.updated, &Rfc3339).ok();
        if new_time > old_time {
            *existing = incoming;
        }
    } else {
        entries.push(incoming);
    }
}

fn default_path(path: &str) -> String {
    path.rsplit_once('/')
        .filter(|(parent, _)| !parent.is_empty())
        .map_or_else(|| "/".to_owned(), |(parent, _)| parent.to_owned())
}

fn jar_key(host: &str) -> &str {
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }
    let Some(last_dot) = host.rfind('.') else {
        return host;
    };
    host[..last_dot]
        .rfind('.')
        .map_or(host, |previous_dot| &host[previous_dot + 1..])
}

fn open_private_cookie_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("failed to protect cookie jar")?;
    }
    Ok(file)
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
        let wrong_jar_key = data.replace(
            "\"CanonicalHost\":\"example.test\"",
            "\"CanonicalHost\":\"other.test\"",
        );
        fs::write(directory.path().join(COOKIE_JAR_FILE_NAME), wrong_jar_key).unwrap();
        assert!(
            SavedCookies::open(directory.path())
                .unwrap()
                .header_for(&url, now)
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

    #[test]
    fn saves_persistent_cookies_and_keeps_session_cookies_in_memory() {
        let directory = tempfile::tempdir().unwrap();
        let url = Url::parse("https://example.test/account/login").unwrap();
        let now = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339).unwrap();
        let mut jar = SavedCookies::open(directory.path()).unwrap();
        jar.set_cookie(
            &url,
            "persistent=one; Path=/account; Max-Age=3600; Secure; HttpOnly",
            now,
        );
        jar.set_cookie(&url, "session=two; Path=/account", now);
        assert_eq!(
            jar.header_for(&url, now).as_deref(),
            Some("persistent=one; session=two")
        );
        jar.save(now).unwrap();
        let saved = fs::read_to_string(directory.path().join(COOKIE_JAR_FILE_NAME)).unwrap();
        assert!(saved.contains("\"Name\":\"persistent\""));
        assert!(!saved.contains("session=two"));
        let reopened = SavedCookies::open(directory.path()).unwrap();
        assert_eq!(
            reopened.header_for(&url, now).as_deref(),
            Some("persistent=one")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.path().join(COOKIE_JAR_FILE_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn save_merges_another_writers_newer_cookies() {
        let directory = tempfile::tempdir().unwrap();
        let url = Url::parse("https://example.test/").unwrap();
        let early = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339).unwrap();
        let later = early + time::Duration::minutes(1);
        let mut first = SavedCookies::open(directory.path()).unwrap();
        let mut second = SavedCookies::open(directory.path()).unwrap();
        first.set_cookie(&url, "first=one; Max-Age=3600", early);
        first.save(early).unwrap();
        second.set_cookie(&url, "second=two; Max-Age=3600", later);
        second.save(later).unwrap();
        let merged = SavedCookies::open(directory.path()).unwrap();
        assert_eq!(
            merged.header_for(&url, later).as_deref(),
            Some("first=one; second=two")
        );
    }

    #[test]
    fn expired_cookie_tombstone_prevents_resurrection() {
        let directory = tempfile::tempdir().unwrap();
        let url = Url::parse("https://example.test/").unwrap();
        let early = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339).unwrap();
        let later = early + time::Duration::minutes(1);
        let mut old = SavedCookies::open(directory.path()).unwrap();
        let mut current = SavedCookies::open(directory.path()).unwrap();
        old.set_cookie(&url, "token=secret; Max-Age=3600", early);
        old.save(early).unwrap();
        current.set_cookie(&url, "token=deleted; Max-Age=0", later);
        current.save(later).unwrap();
        assert!(
            SavedCookies::open(directory.path())
                .unwrap()
                .header_for(&url, later)
                .is_none()
        );
        assert!(
            !fs::read_to_string(directory.path().join(COOKIE_JAR_FILE_NAME))
                .unwrap()
                .contains("secret")
        );
    }
}
