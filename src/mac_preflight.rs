//! Version metadata from the preflight XAR of legacy Mac App Store packages.

use std::{
    collections::HashSet,
    fmt::Debug,
    io::{Cursor, Read, Seek, SeekFrom},
};

use anyhow::{Context, Result, bail};
use apple_xar::reader::XarReader;
use roxmltree::Document;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

use crate::{
    download_file::{download_file, download_file_with_transport},
    ipa_metadata::VersionMetadata,
    transport::Transport,
};

pub fn read_preflight_version_metadata(url: &str, bundle_id: &str) -> Result<VersionMetadata> {
    read_preflight_version_metadata_using(url, bundle_id, None)
}

pub fn read_preflight_version_metadata_with_transport(
    url: &str,
    bundle_id: &str,
    transport: &Transport,
) -> Result<VersionMetadata> {
    read_preflight_version_metadata_using(url, bundle_id, Some(transport))
}

fn read_preflight_version_metadata_using(
    url: &str,
    bundle_id: &str,
    transport: Option<&Transport>,
) -> Result<VersionMetadata> {
    let url = Url::parse(url).context("invalid Mac preflight URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("unsupported Mac preflight URL");
    }
    let package = tempfile::NamedTempFile::new().context("create Mac preflight staging")?;
    if let Some(transport) = transport {
        download_file_with_transport(transport, url.as_str(), package.path())
    } else {
        download_file(url.as_str(), package.path())
    }
    .context("download Mac preflight package")?;
    parse_preflight_reader(package.reopen()?, bundle_id)
}

pub fn parse_preflight_xar(bytes: &[u8], bundle_id: &str) -> Result<VersionMetadata> {
    parse_preflight_reader(Cursor::new(bytes), bundle_id)
}

fn parse_preflight_reader<R: Read + Seek + Debug>(
    mut reader: R,
    bundle_id: &str,
) -> Result<VersionMetadata> {
    let size = reader.seek(SeekFrom::End(0))?;
    reader.rewind()?;
    if size < 28 {
        bail!("invalid Mac preflight XAR header");
    }
    let mut header = [0u8; 28];
    reader.read_exact(&mut header)?;
    if &header[..4] != b"xar!" {
        bail!("invalid Mac preflight XAR header");
    }
    let header_size = u16::from_be_bytes(header[4..6].try_into().unwrap()) as u64;
    let compressed = u64::from_be_bytes(header[8..16].try_into().unwrap());
    if !(28..=4096).contains(&header_size)
        || header_size
            .checked_add(compressed)
            .is_none_or(|end| end > size)
    {
        bail!("invalid Mac preflight XAR table of contents");
    }
    reader.rewind()?;
    let mut archive = XarReader::new(reader).context("open Mac preflight XAR")?;
    if !archive
        .verify_table_of_contents_checksum()
        .context("verify Mac preflight XAR")?
    {
        bail!("Mac preflight XAR checksum mismatch");
    }
    let files = archive.files().context("list Mac preflight XAR files")?;
    let mut distributions = files.iter().filter(|(name, _)| name == "Distribution");
    let (_, distribution) = distributions
        .next()
        .context("Mac preflight package has no Distribution")?;
    if distributions.next().is_some() {
        bail!("Mac preflight package has multiple Distribution files");
    }
    let data = distribution
        .data
        .as_ref()
        .context("Mac preflight Distribution has no data")?;
    let mut raw = Vec::new();
    archive
        .write_file_data_heap_from_file(distribution, &mut raw)
        .context("read Mac preflight Distribution")?;
    verify_file_checksum(&raw, &data.archived_checksum)?;
    let mut decoded = Vec::new();
    archive
        .write_file_data_decoded_from_file(distribution, &mut decoded)
        .context("decode Mac preflight Distribution")?;
    verify_file_checksum(&decoded, &data.extracted_checksum)?;
    parse_distribution(&decoded, bundle_id)
}

fn verify_file_checksum(
    bytes: &[u8],
    checksum: &apple_xar::table_of_contents::FileChecksum,
) -> Result<()> {
    let expected = checksum.checksum.trim();
    if !expected.len().is_multiple_of(2) {
        bail!("Mac preflight Distribution checksum is malformed");
    }
    let expected = expected
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
        })
        .collect::<Option<Vec<_>>>()
        .context("Mac preflight Distribution checksum is malformed")?;
    let actual = checksum
        .style
        .digest_data(bytes)
        .context("digest Mac preflight Distribution")?;
    if actual != expected {
        bail!("Mac preflight Distribution checksum mismatch");
    }
    Ok(())
}

fn parse_distribution(bytes: &[u8], bundle_id: &str) -> Result<VersionMetadata> {
    let text = std::str::from_utf8(bytes).context("Mac preflight Distribution is not UTF-8")?;
    let document = Document::parse(text).context("parse Mac preflight Distribution")?;
    let root = document.root_element();
    if root.tag_name().name() != "installer-gui-script" {
        bail!("Mac preflight Distribution has no installer script");
    }
    let products = root
        .children()
        .filter(|node| node.has_tag_name("product"))
        .collect::<Vec<_>>();
    if products.len() != 1 {
        bail!("Mac preflight package has no unique product");
    }
    let product = products[0];
    let id = product.attribute("id").unwrap_or_default();
    if id.is_empty() || (!bundle_id.is_empty() && id != bundle_id) {
        bail!("Mac preflight package has no product for the requested bundle");
    }
    let version = product.attribute("version").unwrap_or_default().trim();
    if version.is_empty() {
        bail!("Mac preflight package has no display version");
    }
    let packages = root
        .children()
        .filter(|node| node.has_tag_name("pkg-ref"))
        .collect::<Vec<_>>();
    let ids: HashSet<_> = packages
        .iter()
        .filter(|package| {
            package.children().any(|child| {
                child.has_tag_name("relocate")
                    && child.children().any(|bundle| {
                        bundle.has_tag_name("bundle") && bundle.attribute("id") == Some(id)
                    })
            })
        })
        .filter_map(|package| package.attribute("id").filter(|id| !id.is_empty()))
        .collect();
    let mut timestamp = None;
    for package in packages {
        if !package.attribute("id").is_some_and(|id| ids.contains(id)) {
            continue;
        }
        let Some(package_version) = package
            .attribute("version")
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let build = legacy_build_time(version, package_version)?;
        if timestamp.is_some_and(|previous| previous != build) {
            bail!("Mac preflight package has conflicting build timestamps");
        }
        timestamp = Some(build);
    }
    let timestamp = timestamp
        .context("Mac preflight package has no build timestamp for the requested bundle")?;
    Ok(VersionMetadata {
        display_version: version.to_owned(),
        release_date: timestamp.format(&Rfc3339)?,
    })
}

fn legacy_build_time(display_version: &str, package_version: &str) -> Result<OffsetDateTime> {
    let mut version = display_version.split('.').collect::<Vec<_>>();
    while version.len() < 3 {
        version.push("0");
    }
    let parts = package_version.split('.').collect::<Vec<_>>();
    if version.len() != 3
        || parts.len() != 6
        || parts[..3] != version[..]
        || parts[3] != "0"
        || parts[4] != "1"
        || parts[5].len() != 10
    {
        bail!("Mac preflight package has no supported build timestamp");
    }
    if parts
        .iter()
        .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        bail!("Mac preflight package has an invalid installer version");
    }
    let seconds: i64 = parts[5]
        .parse()
        .context("invalid Mac preflight build timestamp")?;
    if seconds <= 0 {
        bail!("Mac preflight package has an invalid build timestamp");
    }
    OffsetDateTime::from_unix_timestamp(seconds).context("invalid Mac preflight build timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use apple_xar::table_of_contents::ChecksumType;
    use flate2::{Compression, write::ZlibEncoder};
    use std::{io::Write, net::TcpListener, thread};

    const DISTRIBUTION: &str = r#"<installer-gui-script><product id="com.example.mac" version="4.2"/>
<pkg-ref id="com.example.pkg"><relocate><bundle id="com.example.mac"/></relocate></pkg-ref>
<pkg-ref id="com.unrelated.pkg" version="9.9.9.0.1.1700000000"/>
<pkg-ref id="com.example.pkg" version="4.2.0.0.1.1341568473"/>
</installer-gui-script>"#;

    fn fixture_xar(distribution: &str) -> Vec<u8> {
        fixture_xar_with_extra(distribution, 0)
    }

    fn fixture_xar_with_extra(distribution: &str, extra_size: usize) -> Vec<u8> {
        fixture_xar_with_padding(distribution, extra_size, 0)
    }

    fn fixture_xar_with_padding(
        distribution: &str,
        extra_size: usize,
        toc_padding: usize,
    ) -> Vec<u8> {
        let checksum = ChecksumType::Sha1
            .digest_data(distribution.as_bytes())
            .unwrap();
        let hex = checksum
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let entry = format!(
            r#"<file id="1"><type>file</type><name>Distribution</name><data><length>{}</length><offset>20</offset><size>{}</size><encoding style="application/octet-stream"/><archived-checksum style="sha1">{hex}</archived-checksum><extracted-checksum style="sha1">{hex}</extracted-checksum></data></file>"#,
            distribution.len(),
            distribution.len()
        );
        let extra = vec![0x5a; extra_size];
        let extra_entry = if extra_size == 0 {
            String::new()
        } else {
            let checksum = ChecksumType::Sha1.digest_data(&extra).unwrap();
            let hex = checksum
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!(
                r#"<file id="2"><type>file</type><name>AdditionalResources</name><data><length>{extra_size}</length><offset>{}</offset><size>{extra_size}</size><encoding style="application/octet-stream"/><archived-checksum style="sha1">{hex}</archived-checksum><extracted-checksum style="sha1">{hex}</extracted-checksum></data></file>"#,
                20 + distribution.len()
            )
        };
        let comment = if toc_padding == 0 {
            String::new()
        } else {
            format!("<!--{}-->", "x".repeat(toc_padding))
        };
        let toc = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum><creation-time>2023-01-04T22:53:15</creation-time>{entry}{extra_entry}{comment}</toc></xar>"#
        );
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(toc.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let toc_checksum = ChecksumType::Sha1.digest_data(&compressed).unwrap();
        let mut result = Vec::new();
        result.extend_from_slice(b"xar!");
        result.extend_from_slice(&28u16.to_be_bytes());
        result.extend_from_slice(&1u16.to_be_bytes());
        result.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
        result.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        result.extend_from_slice(&1u32.to_be_bytes());
        result.extend_from_slice(&compressed);
        result.extend_from_slice(&toc_checksum);
        result.extend_from_slice(distribution.as_bytes());
        result.extend_from_slice(&extra);
        result
    }

    #[test]
    fn reads_preflight_version_and_checksums() {
        let package = fixture_xar(DISTRIBUTION);
        let metadata = parse_preflight_xar(&package, "com.example.mac").unwrap();
        assert_eq!(metadata.display_version, "4.2");
        assert_eq!(metadata.release_date, "2012-07-06T09:54:33Z");
        let mut corrupt = package;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            parse_preflight_xar(&corrupt, "com.example.mac")
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch")
        );
    }

    #[test]
    fn reads_preflight_distribution_larger_than_four_megabytes() {
        let distribution = DISTRIBUTION.replace(
            "</installer-gui-script>",
            &format!(
                "<note>{}</note></installer-gui-script>",
                "x".repeat(4 * 1024 * 1024)
            ),
        );
        assert!(distribution.len() > 4 * 1024 * 1024);
        let metadata = parse_preflight_xar(&fixture_xar(&distribution), "com.example.mac").unwrap();
        assert_eq!(metadata.display_version, "4.2");
        assert_eq!(metadata.release_date, "2012-07-06T09:54:33Z");
    }

    #[test]
    fn reads_preflight_toc_larger_than_sixteen_megabytes() {
        let package = fixture_xar_with_padding(DISTRIBUTION, 0, 17 * 1024 * 1024);
        let uncompressed = u64::from_be_bytes(package[16..24].try_into().unwrap());
        assert!(uncompressed > 16 * 1024 * 1024);
        let metadata = parse_preflight_xar(&package, "com.example.mac").unwrap();
        assert_eq!(metadata.display_version, "4.2");
        assert_eq!(metadata.release_date, "2012-07-06T09:54:33Z");
    }

    #[test]
    fn reads_preflight_metadata_over_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let package = fixture_xar(DISTRIBUTION);
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let read = stream.read(&mut request).unwrap();
                assert!(request[..read].starts_with(b"GET /preflight.pkg HTTP/1.1"));
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    package.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&package).unwrap();
            }
        });
        let url = format!("http://user:pass@{address}/preflight.pkg#fragment");
        let metadata = read_preflight_version_metadata(&url, "com.example.mac").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let transport = Transport::with_cookies(directory.path()).unwrap();
        let streamed =
            read_preflight_version_metadata_with_transport(&url, "com.example.mac", &transport)
                .unwrap();
        server.join().unwrap();
        assert_eq!(metadata.display_version, "4.2");
        assert_eq!(metadata.release_date, "2012-07-06T09:54:33Z");
        assert_eq!(streamed, metadata);
    }

    #[test]
    fn reads_preflight_metadata_from_range_only_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let package = fixture_xar(DISTRIBUTION);
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while stream.read_exact(&mut byte).is_ok() {
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("GET /preflight.pkg HTTP/1.1"));
                assert!(request.to_ascii_lowercase().contains("range: bytes=0-\r\n"));
                write!(
                    stream,
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    package.len() - 1,
                    package.len(),
                    package.len()
                )
                .unwrap();
                stream.write_all(&package).unwrap();
            }
        });
        let url = format!("http://{address}/preflight.pkg");
        let direct = read_preflight_version_metadata(&url, "com.example.mac").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let transport = Transport::with_cookies(directory.path()).unwrap();
        let authenticated =
            read_preflight_version_metadata_with_transport(&url, "com.example.mac", &transport)
                .unwrap();
        server.join().unwrap();
        assert_eq!(direct.display_version, "4.2");
        assert_eq!(direct.release_date, "2012-07-06T09:54:33Z");
        assert_eq!(authenticated, direct);
    }

    #[test]
    fn reads_preflight_package_over_previous_size_limit() {
        let package = fixture_xar_with_extra(DISTRIBUTION, 33 * 1024 * 1024);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            assert!(request[..read].starts_with(b"GET /preflight.pkg HTTP/1.1"));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                package.len()
            )
            .unwrap();
            stream.write_all(&package).unwrap();
        });
        let metadata = read_preflight_version_metadata(
            &format!("http://{address}/preflight.pkg"),
            "com.example.mac",
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(metadata.display_version, "4.2");
        assert_eq!(metadata.release_date, "2012-07-06T09:54:33Z");
    }

    #[test]
    fn rejects_wrong_product_and_ambiguous_builds() {
        assert!(parse_preflight_xar(&fixture_xar(DISTRIBUTION), "com.other.mac").is_err());
        let conflict = DISTRIBUTION.replace("</installer-gui-script>", "<pkg-ref id=\"com.example.pkg\" version=\"4.2.0.0.1.1341568474\"/></installer-gui-script>");
        assert!(parse_preflight_xar(&fixture_xar(&conflict), "com.example.mac").is_err());
        let unsupported = DISTRIBUTION.replace("4.2.0.0.1.1341568473", "4.2.0");
        assert!(parse_preflight_xar(&fixture_xar(&unsupported), "com.example.mac").is_err());
    }
}
