//! Download, decrypt, validate, and publish macOS App Store packages.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use apple_xar::{
    reader::XarReader,
    table_of_contents::{ChecksumType, FileType},
};
use sha2::digest::DynDigest;

use crate::{
    download_file::download_file, sap_assets::SapAssetBundle, store_agent::StoreAgentSession,
    store_download_product::DownloadItem,
};

const MAX_TOC: u64 = 64 * 1024 * 1024;

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
    download_mac_package_with(
        item,
        destination,
        hardware_id,
        |hardware_id, dp_info, source, target| {
            let assets = SapAssetBundle::load_or_download().context("load StoreAgent assets")?;
            let mut agent = StoreAgentSession::open(&assets, hardware_id, dp_info)
                .context("open StoreAgent package decrypter")?;
            let mut input = File::open(source).context("open encrypted macOS package")?;
            let mut output = File::create(target).context("create decrypted package staging")?;
            let decrypted = agent.decrypt(&mut input, &mut output);
            let closed = agent.close();
            decrypted.context("decrypt macOS package")?;
            closed.context("close StoreAgent decrypter")?;
            output.sync_all().context("sync decrypted macOS package")
        },
    )
}

fn download_mac_package_with(
    item: &DownloadItem,
    destination: &Path,
    hardware_id: &[u8],
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
        download_file(&item.url, &encrypted).context("download encrypted macOS package")?;
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
    result?;
    cleanup_encrypted.context("clean encrypted package staging")?;
    cleanup_decrypted.context("clean decrypted package staging")?;
    Ok(())
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

fn publish_mac_package(staged: &Path, destination: &Path) -> Result<()> {
    let backup = if destination.exists() {
        let base = suffixed(destination, ".ipatool-backup");
        let mut candidate = base.clone();
        for index in 1.. {
            if !candidate.exists() {
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
        if let Some(backup) = &backup {
            fs::rename(backup, destination).context("restore existing macOS package")?;
        }
        return Err(error).context("publish macOS package");
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
    let uncompressed = u64::from_be_bytes(header[16..24].try_into().unwrap());
    if !(28..=4096).contains(&header_size)
        || compressed > MAX_TOC
        || uncompressed > MAX_TOC
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
        let checksum = sha1::Sha1::digest(payload);
        let bad = [0xff; 20];
        let stored = if corrupt { &bad[..] } else { &checksum[..] };
        let toc = format!(
            "<xar><toc><checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum><creation-time>2025-01-01T00:00:00Z</creation-time><file id=\"1\"><type>file</type><name>Payload</name><data><length>{}</length><offset>20</offset><size>{}</size><encoding style=\"application/octet-stream\"/><archived-checksum style=\"sha1\">{}</archived-checksum><extracted-checksum style=\"sha1\">{}</extracted-checksum></data></file></toc></xar>",
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

    fn item(url: String, dp_info: &[u8]) -> DownloadItem {
        let mut fields = plist::Dictionary::new();
        fields.insert("dpInfo".into(), plist::Value::Data(dp_info.to_vec()));
        DownloadItem {
            url,
            preflight_package_url: String::new(),
            artwork_url: String::new(),
            sinfs: vec![plist::Value::Dictionary(fields)],
            metadata: serde_json::json!({}),
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
    fn rejects_missing_or_conflicting_dp_info_before_network() {
        assert!(mac_dp_info(&item(String::new(), b"")).is_err());
        let mut conflicting = item(String::new(), b"first");
        conflicting
            .sinfs
            .extend(item(String::new(), b"second").sinfs);
        assert!(mac_dp_info(&conflicting).is_err());
    }
}
