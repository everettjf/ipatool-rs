//! Embedded Store runtime profile, extracted from the Go source snapshot.

use std::{
    io::Read,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{store_memory::group_pages, unicorn_runtime::Engine};

const MANIFEST: &str = include_str!("../assets/store/manifest.json");
const METADATA: &[u8] = include_bytes!("../assets/store/metadata.zst");
const PAGES: &[u8] = include_bytes!("../assets/store/pages.zst");
const PLUGIN: &[u8] = include_bytes!("../assets/store/plugin.zst");

static PROFILE: OnceLock<Arc<ProfileData>> = OnceLock::new();

pub struct ProfileData {
    pub metadata: Vec<u8>,
    pub pages: Vec<u8>,
    pub plugin: Vec<u8>,
    pub index: ProfileIndex,
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
pub struct ProfileIndex {
    #[serde(rename = "UUID")]
    pub uuid: String,
    #[serde(rename = "PluginUUID")]
    pub plugin_uuid: String,
    #[serde(rename = "Pages")]
    pub pages: Vec<Page>,
    #[serde(rename = "Calls")]
    pub calls: Vec<Call>,
}

#[derive(Deserialize)]
pub struct Page {
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Offset")]
    pub offset: u64,
}

#[derive(Deserialize)]
pub struct Call {
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Symbol")]
    pub symbol: String,
    #[serde(rename = "Selector")]
    pub selector: String,
    #[serde(rename = "SelectorAddress")]
    pub selector_address: u64,
}

impl ProfileData {
    /// Map and initialize the exported Store pages in a fresh Unicorn engine.
    /// Image segments and call stubs are installed by the runtime separately.
    pub fn map_pages(&self, engine: &mut Engine) -> Result<()> {
        let addresses = self
            .index
            .pages
            .iter()
            .map(|page| page.address)
            .collect::<Vec<_>>();
        for region in group_pages(&addresses)? {
            engine
                .mem_map(region.address, region.size as usize)
                .with_context(|| format!("map Store region at {:#x}", region.address))?;
        }
        for page in &self.index.pages {
            let offset = page.offset as usize;
            engine
                .mem_write(page.address, &self.pages[offset..offset + 4096])
                .with_context(|| format!("load Store page at {:#x}", page.address))?;
        }
        Ok(())
    }
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
    let index: ProfileIndex =
        serde_json::from_slice(&metadata).context("invalid Store metadata index")?;
    if index.uuid != manifest.framework_uuid || index.plugin_uuid != manifest.plugin_uuid {
        bail!("Store profile uses unexpected Apple images");
    }
    if index.pages.is_empty()
        || index.calls.is_empty()
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
        index,
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
        assert_eq!(first.index.pages.len(), 5101);
        assert_eq!(first.index.calls.len(), 13369);
        assert!(Arc::ptr_eq(&first, &load().unwrap()));
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn maps_and_initializes_exported_store_pages() {
        let profile = load().unwrap();
        let mut engine = Engine::new().unwrap();
        profile.map_pages(&mut engine).unwrap();
        for page in [
            &profile.index.pages[0],
            &profile.index.pages[profile.index.pages.len() / 2],
            profile.index.pages.last().unwrap(),
        ] {
            let offset = page.offset as usize;
            assert_eq!(
                engine.mem_read(page.address, 4096).unwrap(),
                profile.pages[offset..offset + 4096]
            );
        }
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
