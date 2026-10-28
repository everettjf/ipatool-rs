//! Encode a bounded startup candidate after a verified pre-request trace.
//!
//! This writer does not trace `fairplayd` or prove the stop boundary. Collection
//! must supply those guarantees before calling it. No collection path calls it
//! until the dedicated startup runner is implemented and validated.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
};

use anyhow::{Context, Result, bail};
use flate2::{Compression, GzBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::fairplay_recovery_output::write_private_binary;

const SCHEMA: &str = "ipatool-fairplay-startup-cache-v1";
const MAX_BINARY_BYTES: usize = 256 * 1024 * 1024;
const MAX_MEMORY_BYTES: usize = 2_000_000;
const MAX_ONCE_TOKENS: usize = 65_536;
const MAX_GUEST_ADDRESS: u64 = 0xf000_0000_0000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCandidateSummary {
    pub binary_sha256: String,
    pub memory_bytes: usize,
    pub once_tokens: usize,
    pub compressed_bytes: usize,
}

#[derive(Serialize)]
struct StartupCandidateDocument {
    schema: &'static str,
    binary_sha256: String,
    memory: Vec<(String, u8)>,
    once_tokens: Vec<String>,
}

/// Write a deterministic, private candidate from a verified pre-request trace.
///
/// The caller must verify that `memory` and `once_tokens` were recorded before
/// any application, account, hardware, SINF, or request data entered the guest.
/// The output parent must already be a private directory (mode 0700 on Unix).
/// An existing output is never replaced.
pub fn write_startup_candidate(
    fairplayd: &[u8],
    memory: &BTreeMap<u64, u8>,
    once_tokens: &BTreeSet<u64>,
    output: &Path,
) -> Result<StartupCandidateSummary> {
    if fairplayd.is_empty() || fairplayd.len() > MAX_BINARY_BYTES {
        bail!("fairplayd startup image size is outside the bounded range");
    }
    if memory.is_empty() || memory.len() > MAX_MEMORY_BYTES {
        bail!("startup memory byte count is outside the bounded range");
    }
    if once_tokens.len() > MAX_ONCE_TOKENS {
        bail!("startup once-token count exceeds the bounded range");
    }
    if memory.keys().any(|address| *address >= MAX_GUEST_ADDRESS)
        || once_tokens
            .iter()
            .any(|address| *address >= MAX_GUEST_ADDRESS)
    {
        bail!("startup profile contains an address outside the guest range");
    }

    let binary_sha256 = format!("{:x}", Sha256::digest(fairplayd));
    let document = StartupCandidateDocument {
        schema: SCHEMA,
        binary_sha256: binary_sha256.clone(),
        memory: memory
            .iter()
            .map(|(address, byte)| (format!("{address:#x}"), *byte))
            .collect(),
        once_tokens: once_tokens
            .iter()
            .map(|address| format!("{address:#x}"))
            .collect(),
    };
    let json = serde_json::to_vec(&document).context("serialize startup candidate")?;
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    encoder
        .write_all(&json)
        .context("compress startup candidate")?;
    let compressed = encoder.finish().context("finish startup candidate gzip")?;
    write_private_binary(output, &compressed).context("publish startup candidate")?;

    Ok(StartupCandidateSummary {
        binary_sha256,
        memory_bytes: memory.len(),
        once_tokens: once_tokens.len(),
        compressed_bytes: compressed.len(),
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Read};

    use flate2::read::GzDecoder;

    use super::*;

    #[test]
    fn writes_deterministic_bounded_candidate_without_extra_fields() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let memory = BTreeMap::from([(0x1002, 7), (0x1000, 9)]);
        let tokens = BTreeSet::from([0x2002, 0x2000]);
        let first = root.path().join("one.json.gz");
        let second = root.path().join("two.json.gz");
        let summary =
            write_startup_candidate(b"synthetic fairplayd", &memory, &tokens, &first).unwrap();
        write_startup_candidate(b"synthetic fairplayd", &memory, &tokens, &second).unwrap();
        let encoded = fs::read(&first).unwrap();
        assert_eq!(encoded, fs::read(&second).unwrap());
        assert_eq!(&encoded[4..8], &[0, 0, 0, 0]);
        assert_eq!(summary.memory_bytes, 2);
        assert_eq!(summary.once_tokens, 2);
        assert_eq!(summary.compressed_bytes, encoded.len());
        let mut json = String::new();
        GzDecoder::new(encoded.as_slice())
            .read_to_string(&mut json)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["binary_sha256"], summary.binary_sha256);
        assert_eq!(
            value["memory"],
            serde_json::json!([["0x1000", 9], ["0x1002", 7]])
        );
        assert_eq!(
            value["once_tokens"],
            serde_json::json!(["0x2000", "0x2002"])
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(first).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn rejects_unbounded_or_existing_candidate() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = root.path().join("candidate.json.gz");
        let memory = BTreeMap::from([(0x1000, 1)]);
        assert!(write_startup_candidate(b"", &memory, &BTreeSet::new(), &path).is_err());
        assert!(
            write_startup_candidate(b"fairplayd", &BTreeMap::new(), &BTreeSet::new(), &path)
                .is_err()
        );
        assert!(
            write_startup_candidate(
                b"fairplayd",
                &BTreeMap::from([(MAX_GUEST_ADDRESS, 1)]),
                &BTreeSet::new(),
                &path
            )
            .is_err()
        );
        let summary =
            write_startup_candidate(b"fairplayd", &memory, &BTreeSet::new(), &path).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(write_startup_candidate(b"fairplayd", &memory, &BTreeSet::new(), &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(summary.binary_sha256.len(), 64);
    }
}
