//! StoreAgent guest memory prepared from the pinned AMS images and profile.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::{
    machimage::{Image, Memory},
    sap_assets::SapAssetBundle,
    store_memory::{MemoryRegion, exclude_mapped_regions},
    store_profile::{self, ProfileData},
    unicorn_runtime::Engine,
};

const AMS_SHA256: &str = "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4";
const HEAP_BASE: u64 = 0x4000_0000_0000;
const HEAP_SIZE: usize = 64 << 20;
const STACK_BASE: u64 = 0x5000_0000_0000;
const STACK_SIZE: usize = 8 << 20;
const RETURN_PC: u64 = 0x1_0000_0000;

pub struct StoreRuntime {
    pub engine: Engine,
    pub profile: Arc<ProfileData>,
    pub code_ranges: Vec<(u64, u64)>,
    pub heap_cursor: u64,
    dynamic_selectors: HashMap<String, u64>,
    dynamic_selector_addresses: HashMap<u64, String>,
    pub objects: HashMap<u64, StoreObject>,
}

pub struct StoreObject {
    pub class: String,
    pub value: StoreValue,
    pub properties: HashMap<String, u64>,
}

pub enum StoreValue {
    Empty,
    String(String),
    Number(i64),
    Boolean(bool),
    Addresses(Vec<u64>),
    Entries(HashMap<String, u64>),
}

struct ImageMemory<'a> {
    engine: &'a mut Engine,
    occupied: &'a [MemoryRegion],
}

impl Memory for ImageMemory<'_> {
    fn map(&mut self, address: u64, size: u64) -> Result<()> {
        for region in exclude_mapped_regions(&[MemoryRegion { address, size }], self.occupied)? {
            self.engine.mem_map(region.address, region.size as usize)?;
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        self.engine.mem_write(address, bytes)
    }
}

impl StoreRuntime {
    /// Prepare the guest image and exported Store memory from validated assets.
    pub fn open(assets: &SapAssetBundle) -> Result<Self> {
        Self::open_image(&assets.apple_media_services)
    }

    pub fn open_image(ams: &[u8]) -> Result<Self> {
        if format!("{:x}", Sha256::digest(ams)) != AMS_SHA256 {
            bail!("AppleMediaServices does not match the pinned Store image");
        }
        let profile = store_profile::load()?;
        let mut engine = Engine::new().context("create Store ARM64 guest")?;
        for (address, size) in [
            (HEAP_BASE, HEAP_SIZE),
            (STACK_BASE, STACK_SIZE),
            (RETURN_PC, 4096),
        ] {
            engine
                .mem_map(address, size)
                .with_context(|| format!("map Store guest memory at {address:#x}"))?;
        }
        let mut image_regions = Vec::new();
        let mut code_ranges = Vec::new();
        let mut ivar_symbols = Vec::new();
        for (name, bytes) in [
            ("AppleMediaServices", ams),
            ("AMSAccountAuthenticationPlugin", profile.plugin.as_slice()),
        ] {
            let mut image = Image::open(name, bytes).with_context(|| format!("open {name}"))?;
            image
                .prepare_prelinked(&[], |symbol| bail!("unexpected Store relocation {symbol}"))
                .with_context(|| format!("prepare {name}"))?;
            let regions = image.mapped_regions()?;
            code_ranges.extend_from_slice(image.code_ranges());
            ivar_symbols.extend(image.objc_ivar_symbols()?);
            image
                .load(&mut ImageMemory {
                    engine: &mut engine,
                    occupied: &image_regions,
                })
                .with_context(|| format!("load {name}"))?;
            image_regions.extend(regions);
        }
        profile
            .map_pages_and_calls_after_images(&mut engine, &image_regions)
            .context("overlay Store profile")?;
        for (symbol, address) in ivar_symbols {
            let Some((class_name, ivar_name)) = symbol.split_once('.') else {
                continue;
            };
            let Some(&class_index) = profile.runtime.classes_by_name.get(class_name) else {
                continue;
            };
            let Some(&offset) = profile.index.classes[class_index].ivars.get(ivar_name) else {
                continue;
            };
            let offset = u32::try_from(offset).context("Store ivar offset exceeds 32 bits")?;
            engine
                .mem_write(address, &offset.to_le_bytes())
                .with_context(|| format!("write Store ivar offset {symbol} at {address:#x}"))?;
        }
        for patch in &profile.index.metadata_patches {
            engine
                .mem_write(patch.address, &patch.data)
                .with_context(|| format!("apply Store metadata patch at {:#x}", patch.address))?;
        }
        let mut objects =
            HashMap::with_capacity(profile.runtime.strings.len() + profile.runtime.constants.len());
        for (&address, value) in &profile.runtime.strings {
            objects.insert(
                address,
                StoreObject {
                    class: "NSString".into(),
                    value: StoreValue::String(value.clone()),
                    properties: HashMap::new(),
                },
            );
        }
        for (&address, constant) in &profile.runtime.constants {
            let value = match constant.kind.as_str() {
                "NSString" => StoreValue::String(constant.text.clone()),
                "NSNumber" if constant.is_boolean => StoreValue::Boolean(constant.boolean),
                "NSNumber" => StoreValue::Number(constant.number),
                "NSDictionary" => StoreValue::Entries(constant.entries.clone()),
                "NSArray" | "NSSet" => StoreValue::Addresses(constant.items.clone()),
                _ => StoreValue::Empty,
            };
            objects.insert(
                address,
                StoreObject {
                    class: constant.kind.clone(),
                    value,
                    properties: HashMap::new(),
                },
            );
        }
        Ok(Self {
            engine,
            profile,
            code_ranges,
            heap_cursor: HEAP_BASE,
            dynamic_selectors: HashMap::new(),
            dynamic_selector_addresses: HashMap::new(),
            objects,
        })
    }

    pub fn allocate(&mut self, size: u64) -> Result<u64> {
        let size = size
            .max(1)
            .checked_add(15)
            .context("Store allocation size overflow")?
            & !15;
        let next = self
            .heap_cursor
            .checked_add(size)
            .context("Store heap address overflow")?;
        if next > HEAP_BASE + HEAP_SIZE as u64 {
            bail!("Store guest heap exhausted");
        }
        let address = self.heap_cursor;
        self.heap_cursor = next;
        Ok(address)
    }

    pub fn read_u64(&self, address: u64) -> Result<u64> {
        let bytes = self.engine.mem_read(address, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    }

    pub fn write_u64(&mut self, address: u64, value: u64) -> Result<()> {
        self.engine.mem_write(address, &value.to_le_bytes())
    }

    pub fn class_address(&self, name: &str) -> Option<u64> {
        self.profile
            .runtime
            .classes_by_name
            .get(name)
            .map(|&index| self.profile.index.classes[index].address)
    }

    pub fn method_address(
        &self,
        class_name: &str,
        selector: &str,
        class_method: bool,
    ) -> Option<u64> {
        let mut name = class_name;
        let prefix = if class_method { '+' } else { '-' };
        loop {
            let key = format!("{prefix}[{name} {selector}]");
            if let Some(&address) = self.profile.runtime.methods.get(&key) {
                return Some(address);
            }
            let &index = self.profile.runtime.classes_by_name.get(name)?;
            let superclass = &self.profile.index.classes[index].superclass;
            if superclass.is_empty() {
                return None;
            }
            name = superclass;
        }
    }

    pub fn selector_address(&mut self, selector: &str) -> Result<u64> {
        if let Some(&address) = self.profile.runtime.selector_addresses.get(selector) {
            return Ok(address);
        }
        if let Some(&address) = self.dynamic_selectors.get(selector) {
            return Ok(address);
        }
        let address = self.allocate((selector.len() + 1) as u64)?;
        self.engine.mem_write(address, selector.as_bytes())?;
        self.engine
            .mem_write(address + selector.len() as u64, &[0])?;
        self.dynamic_selectors.insert(selector.to_owned(), address);
        self.dynamic_selector_addresses
            .insert(address, selector.to_owned());
        Ok(address)
    }

    pub fn cstring(&self, address: u64) -> Result<String> {
        if address == 0 {
            return Ok(String::new());
        }
        if let Some(value) = self.profile.runtime.selectors_by_address.get(&address) {
            return Ok(value.clone());
        }
        if let Some(value) = self.dynamic_selector_addresses.get(&address) {
            return Ok(value.clone());
        }
        let mut bytes = Vec::new();
        for offset in 0..16_384u64 {
            let byte = self.engine.mem_read(address + offset, 1)?[0];
            if byte == 0 {
                return String::from_utf8(bytes).context("Store guest C string is not UTF-8");
            }
            bytes.push(byte);
        }
        bail!("unterminated Store guest C string")
    }

    pub fn new_object(&mut self, class: &str, value: StoreValue) -> Result<u64> {
        let class_index = self.profile.runtime.classes_by_name.get(class).copied();
        let size = class_index.map_or(256, |index| self.profile.index.classes[index].size.max(16));
        let address = self.allocate(size)?;
        if let Some(index) = class_index {
            self.write_u64(address, self.profile.index.classes[index].address)?;
        }
        self.objects.insert(
            address,
            StoreObject {
                class: class.to_owned(),
                value,
                properties: HashMap::new(),
            },
        );
        Ok(address)
    }

    pub fn set_ivar(&mut self, address: u64, name: &str, value: u64) -> Result<()> {
        let object = self
            .objects
            .get(&address)
            .context("unknown Store guest object")?;
        let mut class_name = object.class.as_str();
        while let Some(&index) = self.profile.runtime.classes_by_name.get(class_name) {
            let class = &self.profile.index.classes[index];
            if let Some(&offset) = class.ivars.get(name) {
                return self.write_u64(address + offset, value);
            }
            class_name = &class.superclass;
        }
        bail!("unknown Store ivar {}.{name}", object.class)
    }

    pub fn object_string(&self, address: u64) -> Result<&str> {
        if address == 0 {
            return Ok("");
        }
        match &self
            .objects
            .get(&address)
            .context("unknown Store string object")?
            .value
        {
            StoreValue::String(value) => Ok(value),
            _ => bail!("Store object is not a string"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unpinned_store_image() {
        assert!(StoreRuntime::open_image(b"wrong image").is_err());
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn boots_pinned_store_profile() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        assert!(!runtime.code_ranges.is_empty());
        let allocated = runtime.allocate(17).unwrap();
        assert_eq!(runtime.heap_cursor, allocated + 32);
        runtime.write_u64(allocated, 0x1234_5678_90ab_cdef).unwrap();
        assert_eq!(runtime.read_u64(allocated).unwrap(), 0x1234_5678_90ab_cdef);
        let selector = runtime.selector_address("codexStoreProbe:").unwrap();
        assert_eq!(
            runtime.selector_address("codexStoreProbe:").unwrap(),
            selector
        );
        assert_eq!(runtime.cstring(selector).unwrap(), "codexStoreProbe:");
        let account =
            &runtime.profile.index.classes[runtime.profile.runtime.classes_by_name["ACAccount"]];
        assert_eq!(runtime.class_address("ACAccount"), Some(account.address));
        let method = &account.methods[0];
        assert_eq!(
            runtime.method_address("ACAccount", &method.selector, method.class_method),
            Some(method.address)
        );
        let ivar_offset = account.ivars["_accountStore"];
        let account_address = account.address;
        let object = runtime.new_object("ACAccount", StoreValue::Empty).unwrap();
        runtime.set_ivar(object, "_accountStore", 42).unwrap();
        assert_eq!(runtime.read_u64(object + ivar_offset).unwrap(), 42);
        assert_eq!(runtime.read_u64(object).unwrap(), account_address);
        let string = runtime
            .new_object("NSString", StoreValue::String("example".into()))
            .unwrap();
        assert_eq!(runtime.object_string(string).unwrap(), "example");
        let (&profile_string_address, profile_string_value) =
            runtime.profile.runtime.strings.iter().next().unwrap();
        assert_eq!(
            runtime.object_string(profile_string_address).unwrap(),
            profile_string_value
        );
        let patch = &runtime.profile.index.metadata_patches[0];
        assert_eq!(
            runtime
                .engine
                .mem_read(patch.address, patch.data.len())
                .unwrap(),
            patch.data
        );
        let synthetic = 0x1a2d_0fb94;
        assert_eq!(
            runtime.engine.mem_read(synthetic, 4).unwrap(),
            [0xc0, 0x03, 0x5f, 0xd6]
        );
    }
}
