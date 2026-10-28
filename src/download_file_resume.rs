//! Conservative desktop transfer checkpoints. Signed URLs are hashed, never saved.

use anyhow::{Context, Result};
use reqwest::header::{ETAG, HeaderMap, LAST_MODIFIED};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
pub(super) struct Checkpoint {
    schema: u32,
    identity: String,
    pub validator: String,
    pub total: Option<u64>,
    length: u64,
    digest: String,
}

pub(super) fn path(package: &Path) -> PathBuf {
    let mut name = package.as_os_str().to_owned();
    name.push(".resume.json");
    name.into()
}

pub(super) fn identity(scope: &str, url: &str) -> String {
    let mut hash = Sha256::new();
    hash.update((scope.len() as u64).to_le_bytes());
    hash.update(scope);
    hash.update(url);
    format!("{hash:x}", hash = hash.finalize())
}

fn digest(package: &Path) -> Result<(u64, Sha256)> {
    let mut file = File::open(package)?;
    let mut hash = Sha256::new();
    let mut length = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        crate::application::operation::check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        length += count as u64;
    }
    Ok((length, hash))
}

pub(super) fn load(package: &Path, identity: &str) -> Result<Option<(Checkpoint, Sha256)>> {
    let sidecar = path(package);
    let Ok(metadata) = fs::symlink_metadata(&sidecar) else {
        return Ok(None);
    };
    if !metadata.is_file() || metadata.len() > 4096 {
        return Ok(None);
    }
    let bytes = fs::read(sidecar)?;
    let Ok(record) = serde_json::from_slice::<Checkpoint>(&bytes) else {
        return Ok(None);
    };
    if record.schema != 1 || record.identity != identity || record.validator.is_empty() {
        return Ok(None);
    }
    let (length, hash) = digest(package)?;
    Ok(
        (length == record.length && format!("{:x}", hash.clone().finalize()) == record.digest)
            .then_some((record, hash)),
    )
}

pub(super) fn validator(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.starts_with('"') && value.ends_with('"'))
        .or_else(|| {
            headers
                .get(LAST_MODIFIED)
                .and_then(|value| value.to_str().ok())
        })
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// A checkpoint is committed only after file contents are flushed. Interrupted
/// checkpoint publication leaves an old digest, which forces a fresh transfer.
pub(super) fn save(
    package: &Path,
    identity: &str,
    validator: Option<&str>,
    length: u64,
    total: Option<u64>,
    hash: &Sha256,
) -> Result<()> {
    let sidecar = path(package);
    let Some(validator) = validator else {
        return match fs::remove_file(sidecar) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        };
    };
    let digest = format!("{:x}", hash.clone().finalize());
    let record = Checkpoint {
        schema: 1,
        identity: identity.into(),
        validator: validator.into(),
        length,
        total,
        digest,
    };
    let mut output = tempfile::NamedTempFile::new_in(
        package
            .parent()
            .context("package has no parent directory")?,
    )?;
    serde_json::to_writer(&mut output, &record)?;
    output.write_all(b"\n")?;
    output.as_file().sync_all()?;
    output.persist(sidecar).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resume_requires_account_request_url_and_unchanged_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let package = directory.path().join("app.partial");
        fs::write(&package, b"partial").unwrap();
        let identity = identity(
            "account-app-version-offer",
            "https://example.invalid/package?token=private",
        );
        assert!(load(&package, &identity).unwrap().is_none());
        save(
            &package,
            &identity,
            Some("\"version-a\""),
            7,
            Some(10),
            &Sha256::new_with_prefix(b"partial"),
        )
        .unwrap();
        assert!(load(&package, &identity).unwrap().is_some());
        assert!(
            !fs::read_to_string(path(&package))
                .unwrap()
                .contains("private")
        );
        assert!(
            load(
                &package,
                &super::identity(
                    "other-account",
                    "https://example.invalid/package?token=private"
                )
            )
            .unwrap()
            .is_none()
        );
        assert!(
            load(
                &package,
                &super::identity(
                    "account-app-version-offer",
                    "https://example.invalid/package?token=replaced"
                )
            )
            .unwrap()
            .is_none()
        );
        fs::write(&package, b"changed").unwrap();
        assert!(load(&package, &identity).unwrap().is_none());
        save(&package, &identity, None, 0, None, &Sha256::new()).unwrap();
        assert!(!path(&package).exists());
    }
}
