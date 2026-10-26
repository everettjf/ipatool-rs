//! Embedded Store runtime profile, extracted from the Go source snapshot.

use std::{
    collections::{HashMap, HashSet},
    io::Read,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    store_memory::{MemoryRegion, exclude_mapped_regions, group_pages},
    unicorn_runtime::Engine,
};

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
    pub runtime: RuntimeIndex,
}

/// Address and selector lookups prepared once from the immutable Store profile.
pub struct RuntimeIndex {
    pub classes_by_name: HashMap<String, usize>,
    pub class_names_by_address: HashMap<u64, String>,
    pub methods: HashMap<String, u64>,
    pub entry_names: HashMap<u64, String>,
    pub calls_by_address: HashMap<u64, usize>,
    pub selectors_by_address: HashMap<u64, String>,
    pub selector_addresses: HashMap<String, u64>,
    pub strings: HashMap<u64, String>,
    pub constants: HashMap<u64, ProfileConstant>,
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
    #[serde(rename = "Classes")]
    pub classes: Vec<ProfileClass>,
    #[serde(rename = "Strings", default, deserialize_with = "null_default")]
    pub strings: HashMap<String, String>,
    #[serde(rename = "Constants", default, deserialize_with = "null_default")]
    pub constants: HashMap<String, ProfileConstant>,
    #[serde(rename = "MetadataPatches", default, deserialize_with = "null_default")]
    pub metadata_patches: Vec<MetadataPatch>,
    #[serde(rename = "Symbols", default, deserialize_with = "null_default")]
    pub symbols: HashMap<String, u64>,
    #[serde(rename = "Bridges", default, deserialize_with = "null_default")]
    pub bridges: HashMap<String, u64>,
    #[serde(rename = "ObjCMetadata", default, deserialize_with = "null_default")]
    pub objc_metadata: HashMap<String, u64>,
    #[serde(rename = "SwiftSingletons", default, deserialize_with = "null_default")]
    pub swift_singletons: HashMap<String, u64>,
    #[serde(rename = "SwiftForeign", default, deserialize_with = "null_default")]
    pub swift_foreign: HashMap<String, u64>,
    #[serde(
        rename = "SwiftDictionaries",
        default,
        deserialize_with = "null_default"
    )]
    pub swift_dictionaries: HashMap<String, DictionaryLayout>,
    #[serde(rename = "SwiftGlobals", default, deserialize_with = "null_default")]
    pub swift_globals: HashMap<String, u64>,
    #[serde(rename = "SwiftTypes", default, deserialize_with = "null_default")]
    pub swift_types: HashMap<String, u64>,
    #[serde(rename = "SwiftWitnesses", default, deserialize_with = "null_default")]
    pub swift_witnesses: HashMap<String, u64>,
    #[serde(rename = "SwiftAccessors", default, deserialize_with = "null_default")]
    pub swift_accessors: HashMap<String, u64>,
    #[serde(rename = "Features", default, deserialize_with = "null_default")]
    pub features: HashMap<String, bool>,
}

#[derive(Deserialize)]
pub struct ProfileClass {
    #[serde(rename = "MetaAddress")]
    pub meta_address: u64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Super")]
    pub superclass: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "Ivars", default, deserialize_with = "null_default")]
    pub ivars: HashMap<String, u64>,
    #[serde(rename = "Methods", default, deserialize_with = "null_default")]
    pub methods: Vec<ProfileMethod>,
}

#[derive(Deserialize)]
pub struct ProfileMethod {
    #[serde(rename = "Selector")]
    pub selector: String,
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "ClassMethod")]
    pub class_method: bool,
    #[serde(rename = "Types")]
    pub types: String,
}

#[derive(Deserialize)]
pub struct ProfileConstant {
    #[serde(rename = "IsBoolean", default)]
    pub is_boolean: bool,
    #[serde(rename = "Boolean", default)]
    pub boolean: bool,
    #[serde(rename = "Kind")]
    pub kind: String,
    #[serde(rename = "Text", default)]
    pub text: String,
    #[serde(rename = "Number", default)]
    pub number: i64,
    #[serde(rename = "Entries", default, deserialize_with = "null_default")]
    pub entries: HashMap<String, u64>,
    #[serde(rename = "Items", default, deserialize_with = "null_default")]
    pub items: Vec<u64>,
}

#[derive(Deserialize)]
pub struct DictionaryLayout {
    #[serde(rename = "Metadata")]
    pub metadata: u64,
    #[serde(rename = "KeyStride")]
    pub key_stride: u64,
    #[serde(rename = "ValueStride")]
    pub value_stride: u64,
}

#[derive(Deserialize)]
pub struct MetadataPatch {
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Data", deserialize_with = "decode_patch_bytes")]
    pub data: Vec<u8>,
}

fn null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn decode_patch_bytes<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(serde::de::Error::custom)
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
    /// Map exported pages and install return stubs in a fresh Unicorn engine.
    pub fn map_pages_and_calls(&self, engine: &mut Engine) -> Result<()> {
        self.map_pages_and_calls_after_images(engine, &[])
    }

    /// Install profile data after prelinked image segments have been loaded.
    /// Already mapped image ranges are skipped during mapping but may receive
    /// profile page data and call stubs.
    pub fn map_pages_and_calls_after_images(
        &self,
        engine: &mut Engine,
        image_regions: &[MemoryRegion],
    ) -> Result<()> {
        let mut addresses = self
            .index
            .pages
            .iter()
            .map(|page| page.address)
            .collect::<Vec<_>>();
        addresses.extend(self.index.calls.iter().map(|call| call.address & !4095));
        addresses.sort_unstable();
        addresses.dedup();
        for region in exclude_mapped_regions(&group_pages(&addresses)?, image_regions)? {
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
        for call in &self.index.calls {
            engine
                .mem_write(call.address, &[0xc0, 0x03, 0x5f, 0xd6])
                .with_context(|| format!("install Store call at {:#x}", call.address))?;
        }
        Ok(())
    }
}

impl RuntimeIndex {
    fn prepare(profile: &mut ProfileIndex) -> Result<Self> {
        let mut prepared = Self {
            classes_by_name: HashMap::with_capacity(profile.classes.len()),
            class_names_by_address: HashMap::with_capacity(profile.classes.len() * 2),
            methods: HashMap::new(),
            entry_names: HashMap::new(),
            calls_by_address: HashMap::with_capacity(profile.calls.len()),
            selectors_by_address: HashMap::new(),
            selector_addresses: HashMap::new(),
            strings: HashMap::with_capacity(profile.strings.len()),
            constants: HashMap::with_capacity(profile.constants.len()),
        };
        for (index, class) in profile.classes.iter().enumerate() {
            prepared.classes_by_name.insert(class.name.clone(), index);
            prepared
                .class_names_by_address
                .insert(class.address, class.name.clone());
            if class.meta_address != 0 {
                prepared
                    .class_names_by_address
                    .insert(class.meta_address, class.name.clone());
            }
            for method in &class.methods {
                let prefix = if method.class_method { '+' } else { '-' };
                let key = format!("{prefix}[{} {}]", class.name, method.selector);
                prepared.methods.insert(key.clone(), method.address);
                prepared.entry_names.insert(method.address, key);
            }
        }
        for (address, value) in std::mem::take(&mut profile.strings) {
            let address = address
                .parse::<u64>()
                .with_context(|| format!("invalid Store string address {address}"))?;
            prepared.strings.insert(address, value);
        }
        for (address, value) in std::mem::take(&mut profile.constants) {
            let address = address
                .parse::<u64>()
                .with_context(|| format!("invalid Store constant address {address}"))?;
            prepared.constants.insert(address, value);
        }
        for (index, call) in profile.calls.iter().enumerate() {
            prepared.calls_by_address.insert(call.address, index);
            if !call.selector.is_empty() {
                prepared
                    .selectors_by_address
                    .insert(call.selector_address, call.selector.clone());
                prepared
                    .selector_addresses
                    .insert(call.selector.clone(), call.selector_address);
            }
        }
        Ok(prepared)
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
    let mut index: ProfileIndex =
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
    // Dyld lazy-import trampoline present in the pinned shared-cache image.
    index.calls.push(Call {
        address: 0x1a2d_0fb94,
        symbol: "CRIsAutoSubmitEnabled".into(),
        selector: String::new(),
        selector_address: 0,
    });
    for (index, page) in index.pages.iter().enumerate() {
        if page.address % 4096 != 0 || page.offset != (index as u64) * 4096 {
            bail!("invalid Store page index");
        }
    }
    let mut call_addresses = HashSet::with_capacity(index.calls.len());
    for call in &index.calls {
        if call.address % 4 != 0 || !call_addresses.insert(call.address) {
            bail!("invalid Store call index");
        }
    }
    let addresses = index
        .pages
        .iter()
        .map(|page| page.address)
        .chain(index.calls.iter().map(|call| call.address & !4095))
        .collect::<Vec<_>>();
    group_pages(&addresses).context("invalid Store page mapping")?;
    let runtime = RuntimeIndex::prepare(&mut index)?;
    Ok(ProfileData {
        metadata,
        pages,
        plugin,
        index,
        runtime,
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
        assert_eq!(first.index.calls.len(), 13370);
        assert_eq!(first.index.classes.len(), 6006);
        assert_eq!(first.index.metadata_patches.len(), 1988);
        let account = first
            .index
            .classes
            .iter()
            .find(|class| class.name == "ACAccount")
            .unwrap();
        assert!(!account.methods.is_empty());
        assert!(account.ivars.contains_key("_accountStore"));
        assert!(!first.runtime.strings.is_empty());
        assert!(!first.runtime.constants.is_empty());
        assert_eq!(
            first.runtime.classes_by_name["ACAccount"],
            first
                .index
                .classes
                .iter()
                .position(|class| class.name == "ACAccount")
                .unwrap()
        );
        assert_eq!(
            first.runtime.class_names_by_address[&account.address],
            "ACAccount"
        );
        let method = &account.methods[0];
        let prefix = if method.class_method { '+' } else { '-' };
        let key = format!("{prefix}[ACAccount {}]", method.selector);
        assert_eq!(first.runtime.methods[&key], method.address);
        assert_eq!(
            first.runtime.calls_by_address[&0x1a2d_0fb94],
            first.index.calls.len() - 1
        );
        assert!(
            first
                .index
                .metadata_patches
                .iter()
                .all(|patch| !patch.data.is_empty())
        );
        assert!(Arc::ptr_eq(&first, &load().unwrap()));
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn maps_store_pages_and_call_stubs() {
        let profile = load().unwrap();
        let mut engine = Engine::new().unwrap();
        profile.map_pages_and_calls(&mut engine).unwrap();
        let call_pages = profile
            .index
            .calls
            .iter()
            .map(|call| call.address & !4095)
            .collect::<HashSet<_>>();
        for page in profile
            .index
            .pages
            .iter()
            .filter(|page| !call_pages.contains(&page.address))
            .take(3)
        {
            let offset = page.offset as usize;
            assert_eq!(
                engine.mem_read(page.address, 4096).unwrap(),
                profile.pages[offset..offset + 4096]
            );
        }
        for call in [
            &profile.index.calls[0],
            &profile.index.calls[profile.index.calls.len() / 2],
            profile.index.calls.last().unwrap(),
        ] {
            assert_eq!(
                engine.mem_read(call.address, 4).unwrap(),
                [0xc0, 0x03, 0x5f, 0xd6]
            );
        }
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn overlays_store_profile_on_prelinked_plugin_image() {
        let profile = load().unwrap();
        let mut image =
            crate::machimage::Image::open("AMSAccountAuthenticationPlugin", &profile.plugin)
                .unwrap();
        image.prepare_prelinked(&[], |_| unreachable!()).unwrap();
        let regions = image.mapped_regions().unwrap();
        let overlapping = profile
            .index
            .pages
            .iter()
            .find(|page| {
                regions.iter().any(|region| {
                    page.address >= region.address && page.address < region.address + region.size
                })
            })
            .unwrap();
        let mut engine = Engine::new().unwrap();
        image.load(&mut engine).unwrap();
        profile
            .map_pages_and_calls_after_images(&mut engine, &regions)
            .unwrap();
        let start = overlapping.offset as usize;
        assert_eq!(
            engine.mem_read(overlapping.address, 4096).unwrap(),
            profile.pages[start..start + 4096]
        );
        let call = &profile.index.calls[0];
        assert_eq!(
            engine.mem_read(call.address, 4).unwrap(),
            [0xc0, 0x03, 0x5f, 0xd6]
        );
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
