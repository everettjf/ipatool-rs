//! Persist one paired Store ent/download FairPlay transaction privately.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    App, Platform, fairplay::parse_sinf_selector, store_download_product::CapturedIpaDownload,
};

#[derive(Serialize)]
struct BlobReceipt {
    file: String,
    bytes: usize,
    sha256: String,
}

#[derive(Serialize)]
struct SinfReceipt {
    #[serde(flatten)]
    blob: BlobReceipt,
    selector: String,
}

#[derive(Serialize)]
struct CaptureReceipt {
    schema: &'static str,
    source: &'static str,
    app_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    bundle_id: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    external_version_id: String,
    platform: Platform,
    downloaded_package: String,
    contains_credentials: bool,
    contains_personalized_material: bool,
    kbsync: BlobReceipt,
    keybag: BlobReceipt,
    sinfs: Vec<SinfReceipt>,
}

struct IncompleteDirectory(PathBuf);

impl Drop for IncompleteDirectory {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// Write the paired material and a hash receipt to a new private directory.
/// The directory is removed if any receipt or file fails validation.
pub fn write_download_capture(
    directory: &Path,
    download: &CapturedIpaDownload,
    app: &App,
    external_version_id: &str,
    platform: Platform,
) -> Result<PathBuf> {
    if download.capture.kbsync.is_empty() || download.capture.keybag.is_empty() {
        bail!("download returned no paired FairPlay KBSync/keybag capture");
    }
    if download.sinfs.is_empty() {
        bail!("download returned no SINF for the FairPlay capture");
    }
    let name = directory
        .file_name()
        .context("capture directory has no name")?;
    let parent = directory
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create capture parent {}", parent.display()))?;
    let absolute = fs::canonicalize(parent)?.join(name);
    create_private_directory(&absolute)?;
    let mut cleanup = IncompleteDirectory(absolute.clone());

    let mut sinfs = Vec::with_capacity(download.sinfs.len());
    for (index, data) in download.sinfs.iter().enumerate() {
        if data.is_empty() {
            bail!("FairPlay capture SINF {index} is empty");
        }
        let selector = parse_sinf_selector(data)
            .with_context(|| format!("parse captured SINF {index} selector"))?;
        let filename = if download.sinfs.len() == 1 {
            "sinf.bin".to_owned()
        } else {
            format!("sinf-{index:02}.bin")
        };
        sinfs.push(SinfReceipt {
            blob: write_blob(&absolute, &filename, data)?,
            selector: selector.identifier(),
        });
    }
    let receipt = CaptureReceipt {
        schema: "ipatool-fairplay-enrollment-capture-v1",
        source: "ent/download",
        app_id: app.id,
        bundle_id: app.bundle_id.clone(),
        external_version_id: external_version_id.to_owned(),
        platform,
        downloaded_package: download
            .path
            .file_name()
            .context("downloaded IPA has no file name")?
            .to_string_lossy()
            .into_owned(),
        contains_credentials: false,
        contains_personalized_material: true,
        kbsync: write_blob(&absolute, "kbsync.bin", &download.capture.kbsync)?,
        keybag: write_blob(&absolute, "keybag.bin", &download.capture.keybag)?,
        sinfs,
    };
    let mut encoded = serde_json::to_vec_pretty(&receipt)?;
    encoded.push(b'\n');
    write_blob(&absolute, "receipt.json", &encoded)?;
    cleanup.0 = PathBuf::new();
    Ok(absolute)
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("create private capture directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)
        .with_context(|| format!("create private capture directory {}", path.display()))?;
    Ok(())
}

fn write_blob(directory: &Path, name: &str, bytes: &[u8]) -> Result<BlobReceipt> {
    let path = directory.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file: File = options
        .open(&path)
        .with_context(|| format!("create private capture file {name}"))?;
    file.write_all(bytes)
        .with_context(|| format!("write private capture file {name}"))?;
    file.sync_all()
        .with_context(|| format!("sync private capture file {name}"))?;
    Ok(BlobReceipt {
        file: name.to_owned(),
        bytes: bytes.len(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_download_product::FairPlayDownloadCapture;

    fn atom(name: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut bytes = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn sinf() -> Vec<u8> {
        let mut fields = atom(b"user", &1u32.to_be_bytes());
        fields.extend_from_slice(&atom(b"key ", &2u32.to_be_bytes()));
        atom(b"sinf", &atom(b"schi", &fields))
    }

    #[test]
    fn writes_private_capture_and_hash_receipt() {
        let root = tempfile::tempdir().unwrap();
        let download = CapturedIpaDownload {
            path: root.path().join("App.ipa"),
            sinfs: vec![sinf()],
            capture: FairPlayDownloadCapture {
                kbsync: b"request".to_vec(),
                keybag: b"response".to_vec(),
            },
        };
        let directory = root.path().join("capture");
        let output = write_download_capture(
            &directory,
            &download,
            &App {
                id: 12,
                bundle_id: "example.app".into(),
                ..App::default()
            },
            "100",
            Platform::Iphone,
        )
        .unwrap();
        assert_eq!(output, fs::canonicalize(&directory).unwrap());
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("receipt.json")).unwrap()).unwrap();
        assert_eq!(receipt["sinfs"][0]["selector"], "00000001:00000002");
        assert_eq!(
            receipt["kbsync"]["sha256"],
            format!("{:x}", Sha256::digest(b"request"))
        );
        assert_eq!(fs::read(directory.join("keybag.bin")).unwrap(), b"response");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(directory.join("keybag.bin"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn removes_directory_after_invalid_sinf() {
        let root = tempfile::tempdir().unwrap();
        let download = CapturedIpaDownload {
            path: root.path().join("App.ipa"),
            sinfs: vec![b"bad".to_vec()],
            capture: FairPlayDownloadCapture {
                kbsync: b"request".to_vec(),
                keybag: b"response".to_vec(),
            },
        };
        let directory = root.path().join("capture");
        assert!(
            write_download_capture(&directory, &download, &App::default(), "", Platform::Iphone)
                .is_err()
        );
        assert!(!directory.exists());
    }
}
