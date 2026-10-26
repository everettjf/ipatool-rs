//! StoreAgent guest memory prepared from the pinned AMS images and profile.

use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::{
    machimage::{Image, Memory},
    sap_assets::SapAssetBundle,
    store_memory::{MemoryRegion, exclude_mapped_regions},
    store_profile::{self, Call, ProfileData},
    unicorn_runtime::{Engine, HookContext, REG_PC, REG_X0},
};

const AMS_SHA256: &str = "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4";
const HEAP_BASE: u64 = 0x4000_0000_0000;
const HEAP_SIZE: usize = 64 << 20;
const STACK_BASE: u64 = 0x5000_0000_0000;
const STACK_SIZE: usize = 8 << 20;
const RETURN_PC: u64 = 0x1_0000_0000;
const REG_LR: i32 = 2;
const REG_SP: i32 = 4;
const GUEST_TIMEOUT: Duration = Duration::from_secs(120);
const GUEST_INSTRUCTION_LIMIT: usize = 20_000_000;

pub struct StoreRuntime {
    pub engine: Engine,
    pub profile: Arc<ProfileData>,
    pub code_ranges: Vec<(u64, u64)>,
    state: Rc<RefCell<StoreState>>,
    hook_error: Rc<RefCell<Option<String>>>,
}

struct StoreState {
    heap_cursor: u64,
    dynamic_selectors: HashMap<String, u64>,
    dynamic_selector_addresses: HashMap<u64, String>,
    objects: HashMap<u64, StoreObject>,
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
        let state = Rc::new(RefCell::new(StoreState {
            heap_cursor: HEAP_BASE,
            dynamic_selectors: HashMap::new(),
            dynamic_selector_addresses: HashMap::new(),
            objects,
        }));
        let hook_error = Rc::new(RefCell::new(None));
        let error_slot = Rc::clone(&hook_error);
        let hook_profile = Arc::clone(&profile);
        let hook_code_ranges = code_ranges.clone();
        let hook_state = Rc::clone(&state);
        engine.add_code_hook(0, u64::MAX, move |context, address, _| {
            if let Some(&index) = hook_profile.runtime.calls_by_address.get(&address) {
                let call = &hook_profile.index.calls[index];
                if let Err(error) =
                    dispatch_call(context, &hook_profile, &mut hook_state.borrow_mut(), call)
                {
                    *error_slot.borrow_mut() =
                        Some(format!("Store bridge at {address:#x}: {error:#}"));
                    context.stop().expect("stop Store guest after bridge error");
                }
            } else if address != RETURN_PC
                && !hook_code_ranges
                    .iter()
                    .any(|&(start, end)| address >= start && address < end)
            {
                *error_slot.borrow_mut() = Some(format!(
                    "Store guest executed outside pinned image at {address:#x}"
                ));
                context.stop().expect("stop Store guest outside image");
            }
        })?;
        Ok(Self {
            engine,
            profile,
            code_ranges,
            state,
            hook_error,
        })
    }

    pub fn allocate(&mut self, size: u64) -> Result<u64> {
        self.state.borrow_mut().allocate(size)
    }

    pub fn heap_cursor(&self) -> u64 {
        self.state.borrow().heap_cursor
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
        method_address(&self.profile, class_name, selector, class_method)
    }

    pub fn selector_address(&mut self, selector: &str) -> Result<u64> {
        if let Some(&address) = self.profile.runtime.selector_addresses.get(selector) {
            return Ok(address);
        }
        if let Some(&address) = self.state.borrow().dynamic_selectors.get(selector) {
            return Ok(address);
        }
        let address = self.allocate((selector.len() + 1) as u64)?;
        self.engine.mem_write(address, selector.as_bytes())?;
        self.engine
            .mem_write(address + selector.len() as u64, &[0])?;
        let mut state = self.state.borrow_mut();
        state.dynamic_selectors.insert(selector.to_owned(), address);
        state
            .dynamic_selector_addresses
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
        if let Some(value) = self.state.borrow().dynamic_selector_addresses.get(&address) {
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
        self.state.borrow_mut().objects.insert(
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
        let class_name = self
            .state
            .borrow()
            .objects
            .get(&address)
            .context("unknown Store guest object")?
            .class
            .clone();
        let mut current = class_name.as_str();
        while let Some(&index) = self.profile.runtime.classes_by_name.get(current) {
            let class = &self.profile.index.classes[index];
            if let Some(&offset) = class.ivars.get(name) {
                return self.write_u64(address + offset, value);
            }
            current = &class.superclass;
        }
        bail!("unknown Store ivar {class_name}.{name}")
    }

    pub fn object_string(&self, address: u64) -> Result<String> {
        if address == 0 {
            return Ok(String::new());
        }
        match &self
            .state
            .borrow()
            .objects
            .get(&address)
            .context("unknown Store string object")?
            .value
        {
            StoreValue::String(value) => Ok(value.clone()),
            _ => bail!("Store object is not a string"),
        }
    }

    /// Execute a pinned guest entry. Bridge calls not yet ported fail explicitly.
    pub fn call(&mut self, entry: u64, arguments: &[u64]) -> Result<u64> {
        if entry == 0 {
            bail!("Store guest entry point is unavailable");
        }
        *self.hook_error.borrow_mut() = None;
        for index in 0..8 {
            self.engine.reg_write(
                REG_X0 + index,
                arguments.get(index as usize).copied().unwrap_or(0),
            )?;
        }
        let extras = arguments.len().saturating_sub(8);
        if extras > 512 {
            bail!("Store guest stack argument limit exceeded");
        }
        let stack_pointer = STACK_BASE + STACK_SIZE as u64 - 4096;
        for (index, value) in arguments.iter().skip(8).enumerate() {
            self.write_u64(stack_pointer + (index as u64) * 8, *value)?;
        }
        self.engine.reg_write(REG_SP, stack_pointer)?;
        self.engine.reg_write(REG_LR, RETURN_PC)?;
        let result =
            self.engine
                .start_bounded(entry, RETURN_PC, GUEST_TIMEOUT, GUEST_INSTRUCTION_LIMIT);
        if let Some(error) = self.hook_error.borrow_mut().take() {
            bail!("{error}");
        }
        result.context("execute Store guest")?;
        let pc = self.engine.reg_read(REG_PC)?;
        if pc != RETURN_PC {
            bail!("Store guest stopped before return at {pc:#x}");
        }
        self.engine.reg_read(REG_X0)
    }
}

impl StoreState {
    fn allocate(&mut self, size: u64) -> Result<u64> {
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
}

fn method_address(
    profile: &ProfileData,
    class_name: &str,
    selector: &str,
    class_method: bool,
) -> Option<u64> {
    let mut name = class_name;
    let prefix = if class_method { '+' } else { '-' };
    loop {
        let key = format!("{prefix}[{name} {selector}]");
        if let Some(&address) = profile.runtime.methods.get(&key) {
            return Some(address);
        }
        let &index = profile.runtime.classes_by_name.get(name)?;
        let superclass = &profile.index.classes[index].superclass;
        if superclass.is_empty() {
            return None;
        }
        name = superclass;
    }
}

fn dispatch_call(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    call: &Call,
) -> Result<()> {
    if !call.selector.is_empty() {
        return dispatch_message(
            context,
            profile,
            state,
            &call.selector,
            call.selector_address,
        );
    }
    let symbol = call.symbol.trim_start_matches('_');
    match symbol {
        "CRIsAutoSubmitEnabled" | "CFURLResponseCopyPeerAddress" => {
            context.reg_write(REG_X0, 0)?;
        }
        "getuid" | "geteuid" => context.reg_write(REG_X0, 501)?,
        "getgid" | "getegid" => context.reg_write(REG_X0, 20)?,
        "getpid" => context.reg_write(REG_X0, 123)?,
        "objc_msgSend" => {
            let selector_address = context.reg_read(REG_X0 + 1)?;
            let selector = guest_cstring(context, profile, state, selector_address)?;
            return dispatch_message(context, profile, state, &selector, selector_address);
        }
        _ => bail!(
            "unsupported Store bridge call: {} {}",
            call.symbol,
            call.selector
        ),
    }
    Ok(())
}

fn guest_cstring(
    context: &HookContext,
    profile: &ProfileData,
    state: &StoreState,
    address: u64,
) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }
    if let Some(value) = profile.runtime.selectors_by_address.get(&address) {
        return Ok(value.clone());
    }
    if let Some(value) = state.dynamic_selector_addresses.get(&address) {
        return Ok(value.clone());
    }
    let mut bytes = Vec::new();
    for offset in 0..16_384u64 {
        let byte = context.mem_read(address + offset, 1)?[0];
        if byte == 0 {
            return String::from_utf8(bytes).context("Store guest C string is not UTF-8");
        }
        bytes.push(byte);
    }
    bail!("unterminated Store guest C string")
}

fn dispatch_message(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    selector: &str,
    selector_address: u64,
) -> Result<()> {
    let receiver = context.reg_read(REG_X0)?;
    if receiver == 0 {
        context.reg_write(REG_X0, 0)?;
        context.reg_write(REG_X0 + 1, 0)?;
        return Ok(());
    }
    let class = profile.runtime.class_names_by_address.get(&receiver);
    let class_method = class.is_some();
    let class_name = if let Some(name) = class {
        name.clone()
    } else {
        state
            .objects
            .get(&receiver)
            .with_context(|| format!("unknown Store receiver {receiver:#x} for {selector}"))?
            .class
            .clone()
    };
    if let Some(entry) = method_address(profile, &class_name, selector, class_method) {
        context.reg_write(REG_X0 + 1, selector_address)?;
        context.reg_write(REG_PC, entry)?;
        return Ok(());
    }
    match (class_method, selector) {
        (true, "alloc" | "allocWithZone:") => {
            let class_index = profile.runtime.classes_by_name[&class_name];
            let class = &profile.index.classes[class_index];
            let size = class.size.max(16);
            let address = state.allocate(size)?;
            context.mem_write(address, &class.address.to_le_bytes())?;
            state.objects.insert(
                address,
                StoreObject {
                    class: class_name,
                    value: StoreValue::Empty,
                    properties: HashMap::new(),
                },
            );
            context.reg_write(REG_X0, address)?;
        }
        (true, "class") | (false, "init" | "retain" | "autorelease") => {
            context.reg_write(REG_X0, receiver)?;
        }
        (false, "class") => {
            let class_index = profile.runtime.classes_by_name[&class_name];
            context.reg_write(REG_X0, profile.index.classes[class_index].address)?;
        }
        (false, "release") => context.reg_write(REG_X0, 0)?,
        _ => bail!("unsupported Store message {class_name} {selector}"),
    }
    Ok(())
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
        assert_eq!(runtime.heap_cursor(), allocated + 32);
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
            profile_string_value.as_str()
        );
        assert_eq!(runtime.call(0x1a2d_0fb94, &[]).unwrap(), 0);
        let objc_msg_send = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol.trim_start_matches('_') == "objc_msgSend")
            .unwrap()
            .address;
        assert_eq!(runtime.call(objc_msg_send, &[0, 0]).unwrap(), 0);
        assert!(runtime.method_address("ACAccount", "alloc", true).is_none());
        let alloc_selector = runtime.selector_address("alloc").unwrap();
        let allocated_account = runtime
            .call(objc_msg_send, &[account_address, alloc_selector])
            .unwrap();
        assert_eq!(
            runtime.read_u64(allocated_account).unwrap(),
            account_address
        );
        assert_eq!(
            runtime.state.borrow().objects[&allocated_account].class,
            "ACAccount"
        );
        assert!(
            runtime
                .call(objc_msg_send, &[u64::MAX, selector])
                .unwrap_err()
                .to_string()
                .contains("unknown Store receiver")
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
