//! Download, decrypt, validate, and publish macOS App Store packages.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use apple_xar::{
    reader::XarReader,
    table_of_contents::{ChecksumType, FileType},
};
use roxmltree::Document;
use sha2::digest::DynDigest;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::{
    download_file::{download_file, download_file_with_transport},
    ipa_metadata::VersionMetadata,
    sap_assets::SapAssetBundle,
    store_agent::StoreAgentSession,
    store_download_product::DownloadItem,
    transport::Transport,
};

pub fn mac_dp_info(item: &DownloadItem) -> Result<Vec<u8>> {
    let mut result: Option<&[u8]> = None;
    for sinf in &item.sinfs {
        let data = sinf
            .as_dictionary()
            .and_then(|fields| fields.get("dpInfo"))
            .and_then(plist::Value::as_data)
            .unwrap_or_default();
        if data.is_empty() {
            continue;
        }
        if result.is_some_and(|previous| previous != data) {
            bail!("download response contains conflicting dpInfo values");
        }
        result = Some(data);
    }
    result
        .map(ToOwned::to_owned)
        .context("download response does not contain dpInfo")
}

pub fn download_mac_package(
    item: &DownloadItem,
    destination: &Path,
    hardware_id: &[u8],
) -> Result<()> {
    download_mac_package_using(item, destination, hardware_id, download_file)
}

pub fn download_mac_package_with_transport(
    item: &DownloadItem,
    destination: &Path,
    hardware_id: &[u8],
    transport: &Transport,
) -> Result<()> {
    download_mac_package_using(item, destination, hardware_id, |url, path| {
        download_file_with_transport(transport, url, path)
    })
}

fn download_mac_package_using(
    item: &DownloadItem,
    destination: &Path,
    hardware_id: &[u8],
    download: impl FnOnce(&str, &Path) -> Result<u64>,
) -> Result<()> {
    download_mac_package_with(
        item,
        destination,
        hardware_id,
        download,
        |hardware_id, dp_info, source, target| {
            let assets = SapAssetBundle::load_or_download().context("load StoreAgent assets")?;
            let mut agent = StoreAgentSession::open(&assets, hardware_id, dp_info)
                .context("open StoreAgent package decrypter")?;
            let mut input = File::open(source).context("open encrypted macOS package")?;
            let mut output = create_private_decrypted_file(target)
                .context("create decrypted package staging")?;
            let decrypted = agent.decrypt(&mut input, &mut output);
            let closed = agent.close();
            decrypted.context("decrypt macOS package")?;
            closed.context("close StoreAgent decrypter")?;
            output.sync_all().context("sync decrypted macOS package")
        },
    )
}

fn create_private_decrypted_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create private decrypted package {}", path.display()))
}

pub fn read_mac_package_version_metadata(
    item: &DownloadItem,
    hardware_id: &[u8],
    bundle_id: &str,
) -> Result<VersionMetadata> {
    read_mac_package_version_metadata_using(item, hardware_id, bundle_id, download_mac_package)
}

pub fn read_mac_package_version_metadata_with_transport(
    item: &DownloadItem,
    hardware_id: &[u8],
    bundle_id: &str,
    transport: &Transport,
) -> Result<VersionMetadata> {
    read_mac_package_version_metadata_using(item, hardware_id, bundle_id, |item, path, hw| {
        download_mac_package_with_transport(item, path, hw, transport)
    })
}

fn read_mac_package_version_metadata_using(
    item: &DownloadItem,
    hardware_id: &[u8],
    bundle_id: &str,
    download: impl FnOnce(&DownloadItem, &Path, &[u8]) -> Result<()>,
) -> Result<VersionMetadata> {
    let directory = tempfile::Builder::new()
        .prefix("ipatool-version-metadata-")
        .tempdir()
        .context("create Mac version metadata staging")?;
    let package = directory.path().join("app.pkg");
    download(item, &package, hardware_id)?;
    read_package_version_from_path(&package, bundle_id)
}

fn read_package_version_from_path(path: &Path, bundle_id: &str) -> Result<VersionMetadata> {
    let mut archive = XarReader::new(File::open(path)?).context("open Mac package for metadata")?;
    if !archive.verify_table_of_contents_checksum()? {
        bail!("Mac package table of contents checksum mismatch");
    }
    let files = archive.files().context("list Mac package entries")?;
    let mut result = None;
    for (name, entry) in &files {
        if name.rsplit('/').next() != Some("PackageInfo")
            || !matches!(entry.file_type, FileType::File)
        {
            continue;
        }
        let data = entry.data.as_ref().context("Mac PackageInfo has no data")?;
        let mut decoded = Vec::new();
        archive
            .write_file_data_decoded_from_file(entry, &mut decoded)
            .context("decode Mac PackageInfo")?;
        let expected = decode_hex(&data.extracted_checksum.checksum)?;
        let actual = data.extracted_checksum.style.digest_data(&decoded)?;
        if actual != expected {
            bail!("Mac PackageInfo checksum mismatch");
        }
        let text = std::str::from_utf8(&decoded).context("Mac PackageInfo is not UTF-8")?;
        let document = Document::parse(text).context("parse Mac PackageInfo")?;
        for bundle in document
            .root_element()
            .children()
            .filter(|node| node.has_tag_name("bundle"))
        {
            if !bundle_id.is_empty() && bundle.attribute("id") != Some(bundle_id) {
                continue;
            }
            let display_version = bundle
                .attribute("CFBundleShortVersionString")
                .unwrap_or_default()
                .trim();
            if display_version.is_empty() {
                bail!("Mac package has no display version");
            }
            if result.is_some() {
                bail!("Mac package contains multiple matching bundles");
            }
            let payload = match name.rsplit_once('/') {
                Some((directory, _)) => format!("{directory}/Payload"),
                None => "Payload".to_owned(),
            };
            let modified = files
                .iter()
                .find(|(candidate, _)| candidate == &payload)
                .and_then(|(_, file)| file.mtime.as_deref())
                .context("Mac package has no payload timestamp")?;
            let modified = OffsetDateTime::parse(modified, &Rfc3339)
                .context("invalid Mac package payload timestamp")?
                .to_offset(UtcOffset::UTC);
            if modified.unix_timestamp() <= 0 {
                bail!("Mac package has no payload timestamp");
            }
            let release_date = modified.replace_nanosecond(0)?.format(&Rfc3339)?;
            result = Some(VersionMetadata {
                display_version: display_version.to_owned(),
                release_date,
            });
        }
    }
    result.context("Mac package has no metadata for the requested bundle")
}

fn download_mac_package_with(
    item: &DownloadItem,
    destination: &Path,
    hardware_id: &[u8],
    download: impl FnOnce(&str, &Path) -> Result<u64>,
    decrypt: impl FnOnce(&[u8], &[u8], &Path, &Path) -> Result<()>,
) -> Result<()> {
    let dp_info = mac_dp_info(item)?;
    if item.url.is_empty() {
        bail!("Mac App Store download response has no package URL");
    }
    let encrypted = suffixed(destination, ".ipatool-encrypted");
    let decrypted = suffixed(destination, ".ipatool-decrypted");
    remove_if_present(&encrypted).context("prepare encrypted package staging")?;
    remove_if_present(&decrypted).context("prepare decrypted package staging")?;
    let result: Result<()> = (|| {
        download(&item.url, &encrypted).context("download encrypted macOS package")?;
        decrypt(hardware_id, &dp_info, &encrypted, &decrypted)?;
        validate_mac_package(&decrypted).context("validate decrypted macOS package")?;
        publish_mac_package(&decrypted, destination)?;
        for suffix in [".dpInfo", ".hwInfo"] {
            let _ = remove_if_present(&suffixed(destination, suffix));
        }
        Ok(())
    })();
    let cleanup_encrypted = remove_if_present(&encrypted);
    let cleanup_decrypted = remove_if_present(&decrypted);
    match result {
        Ok(()) => Ok(()),
        Err(mut error) => {
            if let Err(cleanup) = cleanup_encrypted {
                error = error.context(format!("clean encrypted package staging: {cleanup:#}"));
            }
            if let Err(cleanup) = cleanup_decrypted {
                error = error.context(format!("clean decrypted package staging: {cleanup:#}"));
            }
            Err(error)
        }
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

fn file_exists_for_publish(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn publish_mac_package(staged: &Path, destination: &Path) -> Result<()> {
    let backup = if file_exists_for_publish(destination)? {
        let base = suffixed(destination, ".ipatool-backup");
        let mut candidate = base.clone();
        for index in 1.. {
            if !file_exists_for_publish(&candidate)? {
                break;
            }
            candidate = suffixed(&base, &format!(".{index}"));
        }
        fs::rename(destination, &candidate).context("preserve existing macOS package")?;
        Some(candidate)
    } else {
        None
    };
    if let Err(error) = fs::rename(staged, destination) {
        let publish_error = anyhow::Error::new(error).context("publish macOS package");
        let mut rollback_errors = Vec::new();
        if let Err(error) = remove_if_present(destination) {
            rollback_errors.push(format!("remove partial package: {error:#}"));
        }
        if let Some(backup) = &backup
            && let Err(error) =
                fs::rename(backup, destination).context("restore existing macOS package")
        {
            rollback_errors.push(format!("restore backup: {error:#}"));
        }
        if !rollback_errors.is_empty() {
            return Err(
                publish_error.context(format!("rollback failed: {}", rollback_errors.join("; ")))
            );
        }
        return Err(publish_error);
    }
    if let Some(backup) = backup {
        let _ = remove_if_present(&backup);
    }
    Ok(())
}

pub fn validate_mac_package(path: &Path) -> Result<()> {
    let mut file =
        File::open(path).with_context(|| format!("open macOS package {}", path.display()))?;
    let size = file.metadata()?.len();
    if size < 28 {
        bail!("decrypted macOS package is empty or truncated");
    }
    let mut header = [0u8; 28];
    file.read_exact(&mut header)?;
    if &header[..4] != b"xar!" {
        bail!("decrypted macOS package is not a XAR archive");
    }
    let header_size = u16::from_be_bytes(header[4..6].try_into().unwrap()) as u64;
    let compressed = u64::from_be_bytes(header[8..16].try_into().unwrap());
    if !(28..=4096).contains(&header_size)
        || header_size
            .checked_add(compressed)
            .is_none_or(|end| end > size)
    {
        bail!("invalid macOS XAR table of contents");
    }
    let mut archive = XarReader::new(File::open(path)?).context("parse macOS XAR archive")?;
    if !archive.verify_table_of_contents_checksum()? {
        bail!("macOS XAR table of contents checksum mismatch");
    }
    let files = archive.files()?;
    if files.is_empty() {
        bail!("macOS XAR archive contains no files");
    }
    for (name, entry) in &files {
        if !matches!(entry.file_type, FileType::File) {
            continue;
        }
        let data = entry
            .data
            .as_ref()
            .with_context(|| format!("macOS XAR entry {name} has no data"))?;
        let mut digest = digest_for(data.archived_checksum.style)?;
        let mut sink = DigestWriter(&mut *digest);
        archive
            .write_file_data_heap_from_file(entry, &mut sink)
            .with_context(|| format!("read macOS XAR entry {name}"))?;
        let actual = digest.finalize();
        let expected = decode_hex(&data.archived_checksum.checksum)?;
        if actual.as_ref() != expected {
            bail!("macOS XAR entry {name} failed checksum validation");
        }
    }
    Ok(())
}

fn digest_for(style: ChecksumType) -> Result<Box<dyn DynDigest>> {
    Ok(match style {
        ChecksumType::Sha1 => Box::<sha1::Sha1>::default(),
        ChecksumType::Sha256 => Box::<sha2::Sha256>::default(),
        ChecksumType::Sha512 => Box::<sha2::Sha512>::default(),
        ChecksumType::Md5 => Box::<md5::Md5>::default(),
        ChecksumType::None => bail!("macOS XAR file has no checksum"),
    })
}

struct DigestWriter<'a>(&'a mut dyn DynDigest);

impl Write for DigestWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("malformed macOS XAR checksum");
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair)?, 16)
                .context("malformed macOS XAR checksum")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use sha1::Digest;
    use std::{net::TcpListener, thread};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn xar(payload: &[u8], corrupt: bool) -> Vec<u8> {
        xar_with_toc_padding(payload, corrupt, 0)
    }

    fn xar_with_toc_padding(payload: &[u8], corrupt: bool, toc_padding: usize) -> Vec<u8> {
        let checksum = sha1::Sha1::digest(payload);
        let bad = [0xff; 20];
        let stored = if corrupt { &bad[..] } else { &checksum[..] };
        let comment = if toc_padding == 0 {
            String::new()
        } else {
            format!("<!--{}-->", "x".repeat(toc_padding))
        };
        let toc = format!(
            "<xar><toc><checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum><creation-time>2025-01-01T00:00:00Z</creation-time><file id=\"1\"><type>file</type><name>Payload</name><data><length>{}</length><offset>20</offset><size>{}</size><encoding style=\"application/octet-stream\"/><archived-checksum style=\"sha1\">{}</archived-checksum><extracted-checksum style=\"sha1\">{}</extracted-checksum></data></file>{comment}</toc></xar>",
            payload.len(),
            payload.len(),
            hex(stored),
            hex(&checksum)
        );
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(toc.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let toc_checksum = sha1::Sha1::digest(&compressed);
        let mut archive = vec![0u8; 28];
        archive[..4].copy_from_slice(b"xar!");
        archive[4..6].copy_from_slice(&28u16.to_be_bytes());
        archive[6..8].copy_from_slice(&1u16.to_be_bytes());
        archive[8..16].copy_from_slice(&(compressed.len() as u64).to_be_bytes());
        archive[16..24].copy_from_slice(&(toc.len() as u64).to_be_bytes());
        archive[24..28].copy_from_slice(&1u32.to_be_bytes());
        archive.extend_from_slice(&compressed);
        archive.extend_from_slice(&toc_checksum);
        archive.extend_from_slice(payload);
        archive
    }

    fn xar_with_package_info(package_info: &str, mtime: Option<&str>) -> Vec<u8> {
        let info = package_info.as_bytes();
        let payload = b"installer payload";
        let info_checksum = sha1::Sha1::digest(info);
        let payload_checksum = sha1::Sha1::digest(payload);
        let mtime = mtime
            .map(|value| format!("<mtime>{value}</mtime>"))
            .unwrap_or_default();
        let toc = format!(
            "<xar><toc><checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum><creation-time>2025-01-01T00:00:00Z</creation-time><file id=\"1\"><type>directory</type><name>App.pkg</name><file id=\"2\"><type>file</type><name>PackageInfo</name><data><length>{}</length><offset>20</offset><size>{}</size><encoding style=\"application/octet-stream\"/><archived-checksum style=\"sha1\">{}</archived-checksum><extracted-checksum style=\"sha1\">{}</extracted-checksum></data></file><file id=\"3\"><type>file</type><name>Payload</name>{mtime}<data><length>{}</length><offset>{}</offset><size>{}</size><encoding style=\"application/octet-stream\"/><archived-checksum style=\"sha1\">{}</archived-checksum><extracted-checksum style=\"sha1\">{}</extracted-checksum></data></file></file></toc></xar>",
            info.len(),
            info.len(),
            hex(&info_checksum),
            hex(&info_checksum),
            payload.len(),
            20 + info.len(),
            payload.len(),
            hex(&payload_checksum),
            hex(&payload_checksum)
        );
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(toc.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let toc_checksum = sha1::Sha1::digest(&compressed);
        let mut archive = vec![0u8; 28];
        archive[..4].copy_from_slice(b"xar!");
        archive[4..6].copy_from_slice(&28u16.to_be_bytes());
        archive[6..8].copy_from_slice(&1u16.to_be_bytes());
        archive[8..16].copy_from_slice(&(compressed.len() as u64).to_be_bytes());
        archive[16..24].copy_from_slice(&(toc.len() as u64).to_be_bytes());
        archive[24..28].copy_from_slice(&1u32.to_be_bytes());
        archive.extend_from_slice(&compressed);
        archive.extend_from_slice(&toc_checksum);
        archive.extend_from_slice(info);
        archive.extend_from_slice(payload);
        archive
    }

    fn item(url: String, dp_info: &[u8]) -> DownloadItem {
        let mut fields = plist::Dictionary::new();
        fields.insert("dpInfo".into(), plist::Value::Data(dp_info.to_vec()));
        DownloadItem {
            url,
            preflight_package_url: String::new(),
            artwork_url: String::new(),
            sinfs: vec![plist::Value::Dictionary(fields)],
            metadata: plist::Value::Dictionary(plist::Dictionary::new()),
        }
    }

    fn server(bytes: Vec<u8>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/app.pkg", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read_exact(&mut byte).is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .unwrap();
            stream.write_all(&bytes).unwrap();
        });
        (url, handle)
    }

    #[test]
    fn validates_xar_header_toc_and_file_checksum() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.pkg");
        fs::write(&path, xar(b"package payload", false)).unwrap();
        validate_mac_package(&path).unwrap();
        fs::write(&path, xar(b"package payload", true)).unwrap();
        assert!(
            validate_mac_package(&path)
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );
    }

    #[test]
    fn validates_toc_larger_than_sixty_four_megabytes() {
        let package = xar_with_toc_padding(b"package payload", false, 65 * 1024 * 1024);
        let uncompressed = u64::from_be_bytes(package[16..24].try_into().unwrap());
        assert!(uncompressed > 64 * 1024 * 1024);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.pkg");
        fs::write(&path, package).unwrap();
        validate_mac_package(&path).unwrap();
    }

    #[test]
    fn ignores_inflated_toc_size_hint_when_parsing_actual_stream() {
        let mut package = xar(b"package payload", false);
        package[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.pkg");
        fs::write(&path, package).unwrap();
        validate_mac_package(&path).unwrap();
    }

    #[test]
    fn reads_selected_mac_package_version_and_payload_timestamp() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.pkg");
        fs::write(
            &path,
            xar_with_package_info(
                r#"<pkg-info><bundle id="com.other.app" CFBundleShortVersionString="1.0"/><bundle id="com.example.mac" CFBundleShortVersionString="4.2"/></pkg-info>"#,
                Some("2012-07-06T09:54:33Z"),
            ),
        )
        .unwrap();
        validate_mac_package(&path).unwrap();
        let metadata = read_package_version_from_path(&path, "com.example.mac").unwrap();
        assert_eq!(metadata.display_version, "4.2");
        assert_eq!(metadata.release_date, "2012-07-06T09:54:33Z");
        assert!(read_package_version_from_path(&path, "com.missing.app").is_err());
        assert!(read_package_version_from_path(&path, "").is_err());
        fs::write(
            &path,
            xar_with_package_info(
                r#"<pkg-info><bundle id="com.example.mac" CFBundleShortVersionString="4.2"/></pkg-info>"#,
                None,
            ),
        )
        .unwrap();
        assert!(read_package_version_from_path(&path, "com.example.mac").is_err());
        for timestamp in ["1970-01-01T00:00:00Z", "1969-12-31T23:59:59Z"] {
            fs::write(
                &path,
                xar_with_package_info(
                    r#"<pkg-info><bundle id="com.example.mac" CFBundleShortVersionString="4.2"/></pkg-info>"#,
                    Some(timestamp),
                ),
            )
            .unwrap();
            assert!(read_package_version_from_path(&path, "com.example.mac").is_err());
        }
    }

    #[test]
    fn reads_package_info_larger_than_four_megabytes() {
        let package_info = format!(
            "<pkg-info><bundle id=\"com.example.mac\" CFBundleShortVersionString=\"4.2\"/><note>{}</note></pkg-info>",
            "x".repeat(4 * 1024 * 1024)
        );
        assert!(package_info.len() > 4 * 1024 * 1024);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.pkg");
        fs::write(
            &path,
            xar_with_package_info(&package_info, Some("2012-07-06T09:54:33Z")),
        )
        .unwrap();
        let metadata = read_package_version_from_path(&path, "com.example.mac").unwrap();
        assert_eq!(metadata.display_version, "4.2");
        assert_eq!(metadata.release_date, "2012-07-06T09:54:33Z");
    }

    #[test]
    fn decrypts_and_publishes_only_validated_package() {
        let (url, handle) = server(b"encrypted package".to_vec());
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("app.pkg");
        fs::write(&destination, b"previous package").unwrap();
        fs::write(suffixed(&destination, ".dpInfo"), b"old sidecar").unwrap();
        let package = xar(b"decrypted payload", false);
        download_mac_package_with(
            &item(url, b"session"),
            &destination,
            b"hardware",
            download_file,
            |hardware, dp_info, source, target| {
                assert_eq!(hardware, b"hardware");
                assert_eq!(dp_info, b"session");
                assert_eq!(fs::read(source).unwrap(), b"encrypted package");
                fs::write(target, &package).unwrap();
                Ok(())
            },
        )
        .unwrap();
        handle.join().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), package);
        assert!(!suffixed(&destination, ".ipatool-encrypted").exists());
        assert!(!suffixed(&destination, ".ipatool-decrypted").exists());
        assert!(!suffixed(&destination, ".dpInfo").exists());
    }

    #[test]
    fn bad_decryption_preserves_existing_package() {
        let (url, handle) = server(b"encrypted package".to_vec());
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("app.pkg");
        fs::write(&destination, b"previous package").unwrap();
        let result = download_mac_package_with(
            &item(url, b"session"),
            &destination,
            b"hardware",
            download_file,
            |_, _, _, target| {
                fs::write(target, b"invalid XAR").unwrap();
                Ok(())
            },
        );
        handle.join().unwrap();
        assert!(result.is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"previous package");
        assert!(!suffixed(&destination, ".ipatool-encrypted").exists());
        assert!(!suffixed(&destination, ".ipatool-decrypted").exists());
    }

    #[test]
    fn publish_failure_restores_existing_package_without_replacing_prior_backup() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("app.pkg");
        let prior_backup = suffixed(&destination, ".ipatool-backup");
        let next_backup = suffixed(&prior_backup, ".1");
        fs::write(&destination, b"previous package").unwrap();
        fs::write(&prior_backup, b"older backup").unwrap();
        let missing_staging = directory.path().join("missing-staging.pkg");
        let error = publish_mac_package(&missing_staging, &destination).unwrap_err();
        assert!(error.to_string().contains("publish macOS package"));
        assert_eq!(fs::read(&destination).unwrap(), b"previous package");
        assert_eq!(fs::read(&prior_backup).unwrap(), b"older backup");
        assert!(!next_backup.exists());
    }

    #[test]
    fn rejects_missing_or_conflicting_dp_info_before_network() {
        assert!(mac_dp_info(&item(String::new(), b"")).is_err());
        let mut conflicting = item(String::new(), b"first");
        conflicting
            .sinfs
            .extend(item(String::new(), b"second").sinfs);
        assert!(mac_dp_info(&conflicting).is_err());
    }

    #[test]
    fn decrypted_staging_never_replaces_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged.pkg");
        let mut file = create_private_decrypted_file(&path).unwrap();
        file.write_all(b"new package").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o077, 0);
        }
        assert!(create_private_decrypted_file(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), b"new package");
    }
}
