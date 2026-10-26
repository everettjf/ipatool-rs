//! Embedded Store runtime profile, extracted from the Go source snapshot.

use std::{
    io::Read,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::store_memory::group_pages;

const MANIFEST: &str = include_str!("../assets/store/manifest.json");
const METADATA: &[u8] = include_bytes!("../assets/store/metadata.zst");
const PAGES: &[u8] = include_bytes!("../assets/store/pages.zst");
const PLUGIN: &[u8] = include_bytes!("../assets/store/plugin.zst");

static PROFILE: OnceLock<Arc<ProfileData>> = OnceLock::new();

pub struct ProfileData {
    pub metadata: Vec<u8>,
    pub pages: Vec<u8>,
    pub plugin: Vec<u8>,
}

#[derive(Deserialize)]
struct Manifest {
    framework_uuid: String,
    plugin_uuid: String,
    artifacts: Artifacts,
}

#[derive(Deserialize)]
struct Artifacts {
    metadata: Artifact,
    pages: Artifact,
    plugin: Artifact,
}

#[derive(Clone, Deserialize)]
struct Artifact {
    name: String,
    size: usize,
    sha256: String,
    file: String,
}

#[derive(Deserialize)]
struct MetadataIndex {
    #[serde(rename = "UUID")]
    uuid: String,
    #[serde(rename = "PluginUUID")]
    plugin_uuid: String,
    #[serde(rename = "Pages")]
    pages: Vec<Page>,
}

#[derive(Deserialize)]
struct Page {
    #[serde(rename = "Address")]
    address: u64,
    #[serde(rename = "Offset")]
    offset: u64,
}

/// Decode and validate the committed profile once per process.
pub fn load() -> Result<Arc<ProfileData>> {
    if let Some(profile) = PROFILE.get() {
        return Ok(Arc::clone(profile));
    }
    let profile = Arc::new(decode_profile()?);
    Ok(Arc::clone(PROFILE.get_or_init(|| profile)))
}

fn decode_profile() -> Result<ProfileData> {
    let manifest: Manifest =
        serde_json::from_str(MANIFEST).context("invalid Store profile manifest")?;
    let metadata = decode_artifact(
        &manifest.artifacts.metadata,
        "metadata.zst",
        METADATA,
        128 << 20,
    )?;
    let pages = decode_artifact(&manifest.artifacts.pages, "pages.zst", PAGES, 256 << 20)?;
    let plugin = decode_artifact(&manifest.artifacts.plugin, "plugin.zst", PLUGIN, 64 << 20)?;
    let index: MetadataIndex =
        serde_json::from_slice(&metadata).context("invalid Store metadata index")?;
    if index.uuid != manifest.framework_uuid || index.plugin_uuid != manifest.plugin_uuid {
        bail!("Store profile uses unexpected Apple images");
    }
    if index.pages.is_empty()
        || pages.is_empty()
        || pages.len() % 4096 != 0
        || index.pages.len() != pages.len() / 4096
        || plugin.is_empty()
    {
        bail!("incomplete Store profile");
    }
    for (index, page) in index.pages.iter().enumerate() {
        if page.address % 4096 != 0 || page.offset != (index as u64) * 4096 {
            bail!("invalid Store page index");
        }
    }
    let addresses = index
        .pages
        .iter()
        .map(|page| page.address)
        .collect::<Vec<_>>();
    group_pages(&addresses).context("invalid Store page mapping")?;
    Ok(ProfileData {
        metadata,
        pages,
        plugin,
    })
}

fn decode_artifact(
    item: &Artifact,
    expected_file: &str,
    frame: &[u8],
    limit: usize,
) -> Result<Vec<u8>> {
    if item.file != expected_file || item.size == 0 || item.size > limit {
        bail!("invalid compiled {} artifact", item.name);
    }
    let decoder = zstd::stream::read::Decoder::new(frame)
        .with_context(|| format!("failed to open compiled {}", item.name))?;
    let mut output = Vec::with_capacity(item.size);
    decoder
        .take((item.size + 1) as u64)
        .read_to_end(&mut output)
        .with_context(|| format!("failed to decode compiled {}", item.name))?;
    if output.len() != item.size {
        bail!("compiled {} has an invalid decoded size", item.name);
    }
    let digest = Sha256::digest(&output);
    if format!("{digest:x}") != item.sha256 {
        bail!("compiled {} failed integrity verification", item.name);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_caches_committed_profile() {
        let first = load().unwrap();
        assert_eq!(first.metadata.len(), 4_807_917);
        assert_eq!(first.pages.len(), 20_893_696);
        assert_eq!(first.plugin.len(), 138_088);
        assert!(Arc::ptr_eq(&first, &load().unwrap()));
    }

    #[test]
    fn rejects_tampered_and_oversized_artifacts() {
        let manifest: Manifest = serde_json::from_str(MANIFEST).unwrap();
        let mut damaged = METADATA.to_vec();
        damaged[0] ^= 0x80;
        assert!(
            decode_artifact(
                &manifest.artifacts.metadata,
                "metadata.zst",
                &damaged,
                128 << 20
            )
            .is_err()
        );
        let mut bad_size = manifest.artifacts.metadata.clone();
        bad_size.size = 1;
        assert!(decode_artifact(&bad_size, "metadata.zst", METADATA, 128 << 20).is_err());
    }
}
