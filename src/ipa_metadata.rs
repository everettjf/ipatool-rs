//! Read selected IPA metadata through validated HTTP byte-range requests.

use std::{
    io::{self, Read, Seek, SeekFrom},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use plist::Value;
use reqwest::{Method, header::HeaderValue};
use serde::Serialize;
use time::{Date, Month, OffsetDateTime, Time, format_description::well_known::Rfc3339};
use url::Url;
use zip::ZipArchive;

use crate::{
    duplicate_zip,
    transport::{Request, Response, Transport},
};

const CHUNK_SIZE: u64 = 256 * 1024;
type Sender = dyn Fn(Request) -> Result<Response> + Send + Sync;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VersionMetadata {
    #[serde(rename = "displayVersion")]
    pub display_version: String,
    #[serde(rename = "releaseDate")]
    pub release_date: String,
}

pub fn read_version_metadata_from_ipa(url: &str) -> Result<VersionMetadata> {
    let transport = Arc::new(Transport::new()?);
    read_version_metadata_with_sender(url, move |request| transport.send(request))
}

pub fn read_version_metadata_with_sender(
    url: &str,
    sender: impl Fn(Request) -> Result<Response> + Send + Sync + 'static,
) -> Result<VersionMetadata> {
    let reader = HttpRangeReader::open(url, Arc::new(sender))?;
    let mut raw_reader = reader.clone();
    let mut archive = ZipArchive::new(reader).context("open remote IPA ZIP")?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).context("read remote IPA entry")?;
        let raw_name =
            duplicate_zip::read_raw_central_name(&mut raw_reader, file.central_header_start())?;
        if !is_main_info_plist(&String::from_utf8_lossy(&raw_name)) {
            continue;
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .read_to_end(&mut bytes)
            .context("read IPA Info.plist")?;
        return parse_info_plist(&bytes, file.extra_data_fields(), file.last_modified());
    }
    bail!("IPA has no top-level app Info.plist")
}

fn is_main_info_plist(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    parts.len() == 3
        && parts[0] == "Payload"
        && parts[1].ends_with(".app")
        && parts[2] == "Info.plist"
}

fn parse_info_plist<'a>(
    bytes: &[u8],
    extra_fields: impl Iterator<Item = &'a zip::ExtraField>,
    modified: Option<zip::DateTime>,
) -> Result<VersionMetadata> {
    let info: Value = plist::from_bytes(bytes).context("decode IPA Info.plist")?;
    let fields = info
        .as_dictionary()
        .context("IPA Info.plist is not a dictionary")?;
    let display = ["CFBundleShortVersionString", "bundleShortVersionString"]
        .iter()
        .find_map(|key| fields.get(key))
        .context("IPA Info.plist has no display version")?;
    let display_version = match display {
        Value::String(text) => text.trim().to_owned(),
        Value::Integer(number) => number
            .as_signed()
            .map(|n| n.to_string())
            .or_else(|| number.as_unsigned().map(|n| n.to_string()))
            .unwrap_or_default(),
        Value::Real(number) => number.to_string(),
        _ => bail!("IPA display version has unsupported type"),
    };
    if display_version.is_empty() {
        bail!("IPA display version is empty");
    }
    let release_date = if let Some(value) = ["releaseDate", "ReleaseDate"]
        .iter()
        .find_map(|key| fields.get(key))
    {
        parse_release_date(value)?
    } else {
        zip_modified_time(extra_fields, modified)?
            .context("IPA Info.plist has no release date or ZIP timestamp")?
    };
    Ok(VersionMetadata {
        display_version,
        release_date: release_date.format(&Rfc3339)?,
    })
}

fn parse_release_date(value: &Value) -> Result<OffsetDateTime> {
    match value {
        Value::Date(date) => OffsetDateTime::parse(&date.to_xml_format(), &Rfc3339)
            .context("invalid IPA release date"),
        Value::String(text) => {
            let text = text.trim();
            if let Ok(date) = OffsetDateTime::parse(text, &Rfc3339) {
                return Ok(date.to_offset(time::UtcOffset::UTC));
            }
            for layout in [
                "[weekday repr:long], [month repr:long] [day padding:none], [year]",
                "[year]-[month]-[day]",
            ] {
                let format = time::format_description::parse_borrowed::<2>(layout)?;
                if let Ok(date) = Date::parse(text, &format) {
                    return Ok(date.with_time(Time::MIDNIGHT).assume_utc());
                }
            }
            bail!("invalid IPA release date")
        }
        Value::Integer(number) => {
            let timestamp = number
                .as_signed()
                .or_else(|| number.as_unsigned().and_then(|n| i64::try_from(n).ok()))
                .context("IPA release date timestamp is too large")?;
            OffsetDateTime::from_unix_timestamp(timestamp)
                .context("invalid IPA release date timestamp")
        }
        Value::Real(number) if number.is_finite() => {
            let timestamp = *number as i64;
            OffsetDateTime::from_unix_timestamp(timestamp)
                .context("invalid IPA release date timestamp")
        }
        _ => bail!("IPA release date has unsupported type"),
    }
}

fn zip_time(modified: zip::DateTime) -> Result<OffsetDateTime> {
    let month = Month::try_from(modified.month()).context("invalid IPA ZIP month")?;
    let date = Date::from_calendar_date(modified.year().into(), month, modified.day())
        .context("invalid IPA ZIP date")?;
    let time = Time::from_hms(modified.hour(), modified.minute(), modified.second())
        .context("invalid IPA ZIP time")?;
    Ok(date.with_time(time).assume_utc())
}

fn zip_modified_time<'a>(
    fields: impl Iterator<Item = &'a zip::ExtraField>,
    fallback: Option<zip::DateTime>,
) -> Result<Option<OffsetDateTime>> {
    let mut modified = None;
    for field in fields {
        let timestamp = match field {
            zip::ExtraField::ExtendedTimestamp(value) => value
                .mod_time()
                .and_then(|seconds| OffsetDateTime::from_unix_timestamp(i64::from(seconds)).ok()),
            zip::ExtraField::Custom(value)
                if matches!(value.header_id, 0x000d | 0x5855) && value.data.len() >= 8 =>
            {
                let seconds = u32::from_le_bytes(value.data[4..8].try_into().unwrap());
                OffsetDateTime::from_unix_timestamp(i64::from(seconds)).ok()
            }
            zip::ExtraField::Custom(value) if value.header_id == 0x000a => {
                ntfs_custom_modified_time(&value.data)
            }
            zip::ExtraField::Ntfs(value) => ntfs_modified_time(value.mtime()),
            _ => None,
        };
        if timestamp.is_some() {
            modified = timestamp;
        }
    }
    modified.map_or_else(|| fallback.map(zip_time).transpose(), |time| Ok(Some(time)))
}

fn ntfs_modified_time(ticks: u64) -> Option<OffsetDateTime> {
    let unix_nanos = i128::from(ticks) * 100 - 11_644_473_600i128 * 1_000_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(unix_nanos).ok()
}

fn ntfs_custom_modified_time(field: &[u8]) -> Option<OffsetDateTime> {
    let mut attributes = field.get(4..)?;
    let mut modified = None;
    while attributes.len() >= 4 {
        let tag = u16::from_le_bytes(attributes[..2].try_into().unwrap());
        let size = u16::from_le_bytes(attributes[2..4].try_into().unwrap()) as usize;
        attributes = &attributes[4..];
        if size > attributes.len() {
            break;
        }
        if tag == 1 && size == 24 {
            let ticks = u64::from_le_bytes(attributes[..8].try_into().unwrap());
            modified = ntfs_modified_time(ticks);
        }
        attributes = &attributes[size..];
    }
    modified
}

#[derive(Clone)]
struct HttpRangeReader {
    url: Url,
    sender: Arc<Sender>,
    position: u64,
    size: u64,
    cache_start: u64,
    cache: Vec<u8>,
}

impl HttpRangeReader {
    fn open(url: &str, sender: Arc<Sender>) -> Result<Self> {
        let url = Url::parse(url).context("invalid IPA download URL")?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            bail!("unsupported IPA download URL");
        }
        let probe = send_range(&sender, &url, 0, 0)?;
        let size = validate_range(&probe, 0, 0, None)?;
        if size > i64::MAX as u64 {
            bail!("IPA is too large for ZIP reader");
        }
        Ok(Self {
            url,
            sender,
            position: 0,
            size,
            cache_start: 0,
            cache: Vec::new(),
        })
    }

    fn fetch_chunk(&mut self) -> Result<()> {
        let start = (self.position / CHUNK_SIZE) * CHUNK_SIZE;
        let end = start.saturating_add(CHUNK_SIZE - 1).min(self.size - 1);
        let response = send_range(&self.sender, &self.url, start, end)?;
        validate_range(&response, start, end, Some(self.size))?;
        self.cache_start = start;
        self.cache = response.body;
        Ok(())
    }
}

impl Read for HttpRangeReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.size {
            return Ok(0);
        }
        if self.cache.is_empty()
            || self.position < self.cache_start
            || self.position >= self.cache_start + self.cache.len() as u64
        {
            self.fetch_chunk().map_err(io::Error::other)?;
        }
        let offset = (self.position - self.cache_start) as usize;
        let length = output.len().min(self.cache.len() - offset);
        output[..length].copy_from_slice(&self.cache[offset..offset + length]);
        self.position += length as u64;
        Ok(length)
    }
}

impl Seek for HttpRangeReader {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::Current(value) => self.position as i128 + value as i128,
            SeekFrom::End(value) => self.size as i128 + value as i128,
        };
        if !(0..=i64::MAX as i128).contains(&position) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPA seek outside supported range",
            ));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

fn send_range(sender: &Arc<Sender>, url: &Url, start: u64, end: u64) -> Result<Response> {
    let mut request = Request::get(url.clone());
    request.method = Method::GET;
    request
        .headers
        .insert("Accept-Encoding", HeaderValue::from_static("identity"));
    request.headers.insert(
        "Range",
        HeaderValue::from_str(&format!("bytes={start}-{end}"))?,
    );
    request.no_redirects = false;
    sender(request).context("request IPA byte range")
}

fn validate_range(
    response: &Response,
    start: u64,
    end: u64,
    expected_size: Option<u64>,
) -> Result<u64> {
    if response.status != 206 {
        bail!(
            "IPA server did not honor byte range (HTTP {})",
            response.status
        );
    }
    let header = response
        .header("content-range")
        .context("IPA response has no Content-Range")?;
    let value = header
        .strip_prefix("bytes ")
        .context("invalid IPA Content-Range unit")?;
    let (bounds, total) = value.split_once('/').context("invalid IPA Content-Range")?;
    let (actual_start, actual_end) = bounds
        .split_once('-')
        .context("invalid IPA Content-Range bounds")?;
    let actual_start: u64 = actual_start.parse().context("invalid IPA range start")?;
    let actual_end: u64 = actual_end.parse().context("invalid IPA range end")?;
    let size: u64 = total.parse().context("invalid IPA range size")?;
    if actual_start != start
        || actual_end != end
        || size == 0
        || size <= end
        || expected_size.is_some_and(|expected| expected != size)
        || response.body.len() as u64 != end - start + 1
    {
        bail!("IPA response byte range does not match request");
    }
    if let Some(length) = response.header("content-length") {
        let length: u64 = length.parse().context("invalid IPA Content-Length")?;
        if length != response.body.len() as u64 {
            bail!("IPA Content-Length does not match byte range");
        }
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Cursor, Write},
        sync::atomic::{AtomicUsize, Ordering},
    };
    use zip::{
        CompressionMethod, ZipWriter,
        write::{FullFileOptions, SimpleFileOptions},
    };

    fn fixture_ipa(info: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut archive = ZipWriter::new(cursor);
        archive
            .start_file(
                "Payload/Test.app/Filler.bin",
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        archive.write_all(&vec![0; 2 * 1024 * 1024]).unwrap();
        let modified = zip::DateTime::from_date_and_time(2025, 2, 3, 4, 5, 6).unwrap();
        archive
            .start_file(
                "Payload/Test.app/Info.plist",
                SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated)
                    .last_modified_time(modified),
            )
            .unwrap();
        archive.write_all(info).unwrap();
        archive.finish().unwrap().into_inner()
    }

    fn fixture_ipa_with_extra_time(tag: u16, field: &[u8], info: &[u8]) -> Vec<u8> {
        let mut archive = ZipWriter::new(Cursor::new(Vec::new()));
        let modified = zip::DateTime::from_date_and_time(2025, 2, 3, 4, 5, 6).unwrap();
        let mut options = FullFileOptions::default().last_modified_time(modified);
        options.add_extra_field(tag, field, true).unwrap();
        archive
            .start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        archive.write_all(info).unwrap();
        archive.finish().unwrap().into_inner()
    }

    fn fixture_sender(
        data: Arc<Vec<u8>>,
        served: Arc<AtomicUsize>,
    ) -> impl Fn(Request) -> Result<Response> + Send + Sync + 'static {
        move |request| {
            assert_eq!(request.method, Method::GET);
            assert!(request.timeout.is_none());
            assert_eq!(request.headers.get("Accept-Encoding").unwrap(), "identity");
            let range = request.headers.get("Range").unwrap().to_str().unwrap();
            let (start, end) = range
                .strip_prefix("bytes=")
                .unwrap()
                .split_once('-')
                .unwrap();
            let start: usize = start.parse().unwrap();
            let end: usize = end.parse().unwrap();
            assert!(start <= end && end < data.len());
            let bytes = data[start..=end].to_vec();
            served.fetch_add(bytes.len(), Ordering::SeqCst);
            Ok(Response {
                status: 206,
                headers: std::collections::HashMap::from([
                    (
                        "content-range".into(),
                        format!("bytes {start}-{end}/{}", data.len()),
                    ),
                    ("content-length".into(), bytes.len().to_string()),
                ]),
                body: bytes,
            })
        }
    }

    #[test]
    fn reads_info_plist_without_downloading_entire_ipa() {
        let info = br#"<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>2.3.4</string><key>releaseDate</key><string>2025-01-02T03:04:05Z</string></dict></plist>"#;
        let data = Arc::new(fixture_ipa(info));
        let served = Arc::new(AtomicUsize::new(0));
        let metadata = read_version_metadata_with_sender(
            "https://example.test/app.ipa",
            fixture_sender(Arc::clone(&data), Arc::clone(&served)),
        )
        .unwrap();
        assert_eq!(metadata.display_version, "2.3.4");
        assert_eq!(metadata.release_date, "2025-01-02T03:04:05Z");
        assert!(served.load(Ordering::SeqCst) < data.len() / 2);
    }

    #[test]
    fn reads_info_plist_larger_than_four_megabytes() {
        let info = format!(
            "<plist version=\"1.0\"><dict><key>CFBundleShortVersionString</key><string>2.3.4</string><key>releaseDate</key><string>2025-01-02T03:04:05Z</string><key>Note</key><string>{}</string></dict></plist>",
            "x".repeat(4 * 1024 * 1024)
        );
        assert!(info.len() > 4 * 1024 * 1024);
        let data = Arc::new(fixture_ipa(info.as_bytes()));
        let metadata = read_version_metadata_with_sender(
            "https://example.test/app.ipa",
            fixture_sender(data, Arc::new(AtomicUsize::new(0))),
        )
        .unwrap();
        assert_eq!(metadata.display_version, "2.3.4");
        assert_eq!(metadata.release_date, "2025-01-02T03:04:05Z");
    }

    #[test]
    fn reads_original_info_plist_name_when_unicode_path_aliases_it() {
        let info = br#"<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>2.3.4</string></dict></plist>"#;
        let mut unicode_path = vec![1];
        unicode_path.extend_from_slice(&0x8b17_b45cu32.to_le_bytes());
        unicode_path.extend_from_slice(b"Payload/Fake.app/Other.plist");
        let data = Arc::new(fixture_ipa_with_extra_time(0x7075, &unicode_path, info));
        let served = Arc::new(AtomicUsize::new(0));
        let metadata = read_version_metadata_with_sender(
            "https://example.test/app.ipa",
            fixture_sender(data, served),
        )
        .unwrap();
        assert_eq!(metadata.display_version, "2.3.4");
    }

    #[test]
    fn reads_metadata_from_http_ipa_url_with_userinfo_and_fragment() {
        let info = br#"<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>2.3.4</string></dict></plist>"#;
        let data = Arc::new(fixture_ipa(info));
        let served = Arc::new(AtomicUsize::new(0));
        let metadata = read_version_metadata_with_sender(
            "http://user:pass@example.test/app.ipa#fragment",
            fixture_sender(Arc::clone(&data), Arc::clone(&served)),
        )
        .unwrap();
        assert_eq!(metadata.display_version, "2.3.4");
        assert!(served.load(Ordering::SeqCst) < data.len());
    }

    #[test]
    fn uses_zip_timestamp_when_release_date_is_absent() {
        let info = br#"<plist version="1.0"><dict><key>bundleShortVersionString</key><string>1.0</string></dict></plist>"#;
        let data = Arc::new(fixture_ipa(info));
        let metadata = read_version_metadata_with_sender(
            "https://example.test/app.ipa",
            fixture_sender(data, Arc::new(AtomicUsize::new(0))),
        )
        .unwrap();
        assert_eq!(metadata.display_version, "1.0");
        assert_eq!(metadata.release_date, "2025-02-03T04:05:06Z");
    }

    #[test]
    fn prefers_central_zip_extended_timestamps_over_dos_time() {
        let info = br#"<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>1.0</string></dict></plist>"#;
        let seconds = 1_720_431_011u32;
        let mut extended = vec![1];
        extended.extend_from_slice(&seconds.to_le_bytes());
        let mut unix = vec![0; 4];
        unix.extend_from_slice(&seconds.to_le_bytes());
        let ticks = (u64::from(seconds) + 11_644_473_600) * 10_000_000;
        let mut ntfs = vec![0; 4];
        ntfs.extend_from_slice(&1u16.to_le_bytes());
        ntfs.extend_from_slice(&24u16.to_le_bytes());
        ntfs.extend_from_slice(&ticks.to_le_bytes());
        ntfs.extend_from_slice(&[0; 16]);
        let mut ntfs_with_other_attribute = vec![0; 4];
        ntfs_with_other_attribute.extend_from_slice(&2u16.to_le_bytes());
        ntfs_with_other_attribute.extend_from_slice(&0u16.to_le_bytes());
        ntfs_with_other_attribute.extend_from_slice(&ntfs[4..]);
        for (tag, field) in [
            (0x5455, extended.clone()),
            (0x5855, unix),
            (0x000a, ntfs),
            (0x000a, ntfs_with_other_attribute),
        ] {
            let data = Arc::new(fixture_ipa_with_extra_time(tag, &field, info));
            let metadata = read_version_metadata_with_sender(
                "https://example.test/app.ipa",
                fixture_sender(data, Arc::new(AtomicUsize::new(0))),
            )
            .unwrap();
            assert_eq!(
                metadata.release_date, "2024-07-08T09:30:11Z",
                "tag {tag:#06x}"
            );
        }
        let explicit = br#"<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>1.0</string><key>releaseDate</key><string>2023-01-02T03:04:05Z</string></dict></plist>"#;
        let data = Arc::new(fixture_ipa_with_extra_time(0x5455, &extended, explicit));
        let metadata = read_version_metadata_with_sender(
            "https://example.test/app.ipa",
            fixture_sender(data, Arc::new(AtomicUsize::new(0))),
        )
        .unwrap();
        assert_eq!(metadata.release_date, "2023-01-02T03:04:05Z");
    }

    #[test]
    fn rejects_server_that_ignores_range_or_lies_about_offsets() {
        let data = Arc::new(fixture_ipa(b"<plist version=\"1.0\"><dict/></plist>"));
        let wrong_status =
            read_version_metadata_with_sender("https://example.test/app.ipa", |_| {
                Ok(Response {
                    status: 200,
                    headers: Default::default(),
                    body: Vec::new(),
                })
            });
        assert!(wrong_status.is_err());
        let wrong_range =
            read_version_metadata_with_sender("https://example.test/app.ipa", move |_| {
                Ok(Response {
                    status: 206,
                    headers: std::collections::HashMap::from([(
                        "content-range".into(),
                        format!("bytes 1-1/{}", data.len()),
                    )]),
                    body: vec![0],
                })
            });
        assert!(wrong_range.is_err());
        assert!(
            read_version_metadata_with_sender("ftp://example.test/app.ipa", |_| unreachable!())
                .is_err()
        );
    }
}
