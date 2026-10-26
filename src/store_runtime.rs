//! StoreAgent guest memory prepared from the pinned AMS images and profile.

use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

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
    callbacks: HashMap<u64, CallbackResume>,
}

struct CallbackResume {
    link: u64,
    action: CallbackAction,
}

enum CallbackAction {
    ReturnZero,
    CopyProperty { destination: u64 },
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
            callbacks: HashMap::new(),
        }));
        let hook_error = Rc::new(RefCell::new(None));
        let error_slot = Rc::clone(&hook_error);
        let hook_profile = Arc::clone(&profile);
        let hook_code_ranges = code_ranges.clone();
        let hook_state = Rc::clone(&state);
        engine.add_code_hook(0, u64::MAX, move |context, address, _| {
            if let Some(resume) = hook_state.borrow_mut().callbacks.remove(&address) {
                if let Err(error) = resume_callback(context, resume) {
                    *error_slot.borrow_mut() =
                        Some(format!("Store callback at {address:#x}: {error:#}"));
                    context
                        .stop()
                        .expect("stop Store guest after callback error");
                }
            } else if let Some(&index) = hook_profile.runtime.calls_by_address.get(&address) {
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

    pub fn invoke(&mut self, receiver: u64, selector: &str, arguments: &[u64]) -> Result<u64> {
        let entry = self
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol.trim_start_matches('_') == "objc_msgSend")
            .context("Store profile has no objc_msgSend bridge")?
            .address;
        let selector_address = self.selector_address(selector)?;
        let mut args = Vec::with_capacity(arguments.len() + 2);
        args.extend_from_slice(&[receiver, selector_address]);
        args.extend_from_slice(arguments);
        self.call(entry, &args)
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

fn class_is_kind_of(profile: &ProfileData, class_name: &str, target: &str) -> bool {
    if class_name == target || target == "NSObject" {
        return true;
    }
    let mut current = class_name;
    while let Some(&index) = profile.runtime.classes_by_name.get(current) {
        let superclass = &profile.index.classes[index].superclass;
        if superclass == target {
            return true;
        }
        current = superclass;
    }
    false
}

fn responds_to(profile: &ProfileData, state: &StoreState, receiver: u64, selector: &str) -> bool {
    if receiver == 0 {
        return false;
    }
    let meta = profile.runtime.class_names_by_address.get(&receiver);
    let object = state.objects.get(&receiver);
    let class_name = if let Some(class_name) = meta {
        class_name.as_str()
    } else if let Some(object) = object {
        object.class.as_str()
    } else {
        return false;
    };
    if method_address(profile, class_name, selector, meta.is_some()).is_some() {
        return true;
    }
    if meta.is_some() {
        return matches!(selector, "class" | "alloc" | "new");
    }
    if matches!(
        selector,
        "class"
            | "retain"
            | "release"
            | "autorelease"
            | "copy"
            | "mutableCopy"
            | "isKindOfClass:"
            | "isEqual:"
            | "respondsToSelector:"
    ) {
        return true;
    }
    match &object.expect("instance object").value {
        StoreValue::String(_) => matches!(
            selector,
            "length"
                | "isEqualToString:"
                | "hasPrefix:"
                | "UTF8String"
                | "integerValue"
                | "intValue"
                | "longLongValue"
                | "unsignedIntegerValue"
                | "unsignedLongLongValue"
                | "boolValue"
        ),
        StoreValue::Number(_) | StoreValue::Boolean(_) => matches!(
            selector,
            "integerValue"
                | "intValue"
                | "longLongValue"
                | "unsignedIntegerValue"
                | "unsignedLongLongValue"
                | "boolValue"
        ),
        StoreValue::Entries(_) => matches!(
            selector,
            "count"
                | "objectForKey:"
                | "objectForKeyedSubscript:"
                | "allKeys"
                | "setObject:forKey:"
                | "setObject:forKeyedSubscript:"
        ),
        StoreValue::Addresses(_) => matches!(selector, "count" | "length"),
        StoreValue::Empty => false,
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
            false,
        );
    }
    let symbol = call.symbol.trim_start_matches('_');
    match symbol {
        "CRIsAutoSubmitEnabled"
        | "CFURLResponseCopyPeerAddress"
        | "os_signpost_enabled"
        | "os_log_type_enabled"
        | "os_variant_has_internal_content"
        | "swift_isUniquelyReferenced_nonNull_native"
        | "swift_isUniquelyReferenced_nonNull_bridgeObject" => {
            context.reg_write(REG_X0, 0)?;
        }
        "getuid" | "geteuid" => context.reg_write(REG_X0, 501)?,
        "getgid" | "getegid" => context.reg_write(REG_X0, 20)?,
        "getpid" => context.reg_write(REG_X0, 123)?,
        "objc_opt_self"
        | "swift_getObjCClassMetadata"
        | "swift_retain_n"
        | "swift_bridgeObjectRetain_n"
        | "swift_retain"
        | "swift_bridgeObjectRetain"
        | "swift_unknownObjectRetain"
        | "swift_destroy_strong"
        | "swift_pod_destroy"
        | "swift_arrayDestroy"
        | "swift_deallocPartialClassInstance"
        | "swift_cvw_destroy"
        | "swift_noop_void_return"
        | "swift_release_n"
        | "swift_bridgeObjectRelease_n"
        | "swift_release"
        | "swift_bridgeObjectRelease"
        | "swift_unknownObjectRelease"
        | "swift_deallocObject"
        | "objc_unsafeClaimAutoreleasedReturnValue"
        | "objc_retain"
        | "objc_retainAutoreleasedReturnValue"
        | "objc_claimAutoreleasedReturnValue"
        | "objc_autoreleaseReturnValue"
        | "objc_autorelease"
        | "objc_retainAutoreleaseReturnValue"
        | "objc_retainAutorelease"
        | "objc_release"
        | "objc_autoreleasePoolPop" => {}
        "objc_autoreleasePoolPush" => context.reg_write(REG_X0, 0)?,
        "objc_getProperty" => {
            let object = context.reg_read(REG_X0)?;
            let offset = context.reg_read(REG_X0 + 2)?;
            let value = read_guest_u64(context, object + offset)?;
            context.reg_write(REG_X0, value)?;
        }
        "objc_setProperty_nonatomic" | "objc_setProperty_atomic" => {
            let object = context.reg_read(REG_X0)?;
            let value = context.reg_read(REG_X0 + 2)?;
            let offset = context.reg_read(REG_X0 + 3)?;
            write_guest_u64(context, object + offset, value)?;
        }
        "objc_setProperty_nonatomic_copy" | "objc_setProperty_atomic_copy" => {
            let object = context.reg_read(REG_X0)?;
            let value = context.reg_read(REG_X0 + 2)?;
            let offset = context.reg_read(REG_X0 + 3)?;
            let destination = object + offset;
            let copy_entry = state
                .objects
                .get(&value)
                .and_then(|object| method_address(profile, &object.class, "copyWithZone:", false));
            if let Some(entry) = copy_entry {
                let selector = guest_selector_address(context, profile, state, "copyWithZone:")?;
                begin_callback(
                    context,
                    state,
                    entry,
                    &[value, selector, 0],
                    CallbackAction::CopyProperty { destination },
                )?;
            } else {
                write_guest_u64(context, destination, value)?;
                context.reg_write(REG_X0, 0)?;
            }
        }
        "objc_storeStrong" | "objc_storeWeak" | "objc_initWeak" => {
            let destination = context.reg_read(REG_X0)?;
            let value = context.reg_read(REG_X0 + 1)?;
            write_guest_u64(context, destination, value)?;
            context.reg_write(REG_X0, value)?;
        }
        "objc_copyWeak" | "objc_moveWeak" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            write_guest_u64(context, destination, read_guest_u64(context, source)?)?;
            if symbol == "objc_moveWeak" {
                write_guest_u64(context, source, 0)?;
            }
        }
        "objc_loadWeakRetained" | "objc_loadWeak" => {
            let address = context.reg_read(REG_X0)?;
            context.reg_write(REG_X0, read_guest_u64(context, address)?)?;
        }
        "objc_destroyWeak" => {
            let address = context.reg_read(REG_X0)?;
            write_guest_u64(context, address, 0)?;
        }
        "objc_alloc" | "objc_allocWithZone" | "objc_alloc_init" | "objc_opt_new" => {
            let class_address = context.reg_read(REG_X0)?;
            let class_name = profile
                .runtime
                .class_names_by_address
                .get(&class_address)
                .with_context(|| format!("unknown allocated Store class {class_address:#x}"))?;
            let address = new_guest_object(context, profile, state, class_name, StoreValue::Empty)?;
            context.reg_write(REG_X0, address)?;
            if matches!(symbol, "objc_alloc_init" | "objc_opt_new") {
                let selector = guest_selector_address(context, profile, state, "init")?;
                dispatch_message(context, profile, state, "init", selector, false)?;
            }
        }
        "objc_opt_class" => {
            let address = context.reg_read(REG_X0)?;
            if !profile
                .runtime
                .class_names_by_address
                .contains_key(&address)
            {
                let object = state
                    .objects
                    .get(&address)
                    .with_context(|| format!("unknown Store object class at {address:#x}"))?;
                let class_index = profile.runtime.classes_by_name[&object.class];
                context.reg_write(REG_X0, profile.index.classes[class_index].address)?;
            }
        }
        "objc_opt_isKindOfClass" => {
            let address = context.reg_read(REG_X0)?;
            let target_address = context.reg_read(REG_X0 + 1)?;
            let value = match (
                state.objects.get(&address),
                profile.runtime.class_names_by_address.get(&target_address),
            ) {
                (Some(object), Some(target)) => class_is_kind_of(profile, &object.class, target),
                _ => false,
            };
            context.reg_write(REG_X0, u64::from(value))?;
        }
        "objc_opt_respondsToSelector" => {
            let receiver = context.reg_read(REG_X0)?;
            let selector = guest_cstring(context, profile, state, context.reg_read(REG_X0 + 1)?)?;
            context.reg_write(
                REG_X0,
                u64::from(responds_to(profile, state, receiver, &selector)),
            )?;
        }
        "CFBundleGetMainBundle" => {
            let bundle = new_main_bundle(context, profile, state)?;
            context.reg_write(REG_X0, bundle)?;
        }
        "dispatch_once" => {
            let predicate = context.reg_read(REG_X0)?;
            let block = context.reg_read(REG_X0 + 1)?;
            if read_guest_u64(context, predicate)? != 0 {
                context.reg_write(REG_X0, 0)?;
            } else {
                write_guest_u64(context, predicate, u64::MAX)?;
                let function = read_guest_u64(context, block + 16)?;
                begin_callback(
                    context,
                    state,
                    function,
                    &[block],
                    CallbackAction::ReturnZero,
                )?;
            }
        }
        "swift_once" | "dispatch_once_f" => {
            let predicate = context.reg_read(REG_X0)?;
            if read_guest_u64(context, predicate)? != 0 {
                context.reg_write(REG_X0, 0)?;
            } else {
                write_guest_u64(context, predicate, u64::MAX)?;
                let (function, argument) = if symbol == "swift_once" {
                    (context.reg_read(REG_X0 + 1)?, context.reg_read(REG_X0 + 2)?)
                } else {
                    (context.reg_read(REG_X0 + 2)?, context.reg_read(REG_X0 + 1)?)
                };
                begin_callback(
                    context,
                    state,
                    function,
                    &[argument],
                    CallbackAction::ReturnZero,
                )?;
            }
        }
        "os_unfair_lock_assert_not_owner"
        | "objc_sync_enter"
        | "objc_sync_exit"
        | "os_unfair_lock_lock_with_options"
        | "os_unfair_lock_lock"
        | "os_unfair_lock_unlock"
        | "os_unfair_lock_assert_owner"
        | "os_unfair_recursive_lock_lock_with_options"
        | "os_unfair_recursive_lock_unlock" => context.reg_write(REG_X0, 0)?,
        "os_feature_enabled_impl" => {
            let domain = guest_cstring(context, profile, state, context.reg_read(REG_X0)?)?;
            let feature = guest_cstring(context, profile, state, context.reg_read(REG_X0 + 1)?)?;
            let key = format!("{domain}/{feature}");
            let enabled = profile
                .index
                .features
                .get(&key)
                .with_context(|| format!("unresolved native feature flag {key}"))?;
            context.reg_write(REG_X0, u64::from(*enabled))?;
        }
        "swift_getWitnessTable" => {
            let descriptor = context.reg_read(REG_X0)?;
            let metadata = context.reg_read(REG_X0 + 1)?;
            let key = format!("{descriptor}:{metadata}");
            let witness = profile.index.swift_witnesses.get(&key).with_context(|| {
                format!("unprepared Swift witness descriptor {descriptor:#x} for {metadata:#x}")
            })?;
            context.reg_write(REG_X0, *witness)?;
        }
        "swift_getTypeByMangledNameInContext2" => {
            let mangled = context.reg_read(REG_X0)?;
            let parent = context.reg_read(REG_X0 + 2)?;
            let arguments = context.reg_read(REG_X0 + 3)?;
            let value = profile.index.swift_types.get(&mangled.to_string());
            if parent != 0 || arguments != 0 || value.is_none_or(|value| *value == 0) {
                bail!("unprepared Swift type {mangled:#x}");
            }
            context.reg_write(REG_X0, *value.expect("checked Swift type"))?;
        }
        "$sSD17dictionaryLiteralSDyxq_Gx_q_td_tcfC" => {
            let literal = context.reg_read(REG_X0)?;
            if read_guest_u64(context, literal + 16)? != 0 {
                bail!("nonempty Swift dictionary literal is unsupported");
            }
            let empty = profile
                .index
                .symbols
                .get("_swiftEmptyDictionarySingleton")
                .context("missing Swift empty dictionary singleton")?;
            context.reg_write(REG_X0, *empty)?;
        }
        "$sSo9OS_os_logC0B0E9subsystem8categoryABSS_SStcfC" => {
            let address =
                new_guest_object(context, profile, state, "HostOSLog", StoreValue::Empty)?;
            context.reg_write(REG_X0, address)?;
        }
        "$ss6HasherV5_seedABSi_tcfC" => {
            let output = context.reg_read(REG_X0 + 8)?;
            init_hasher(context, profile, output, context.reg_read(REG_X0)?)?;
        }
        "$ss6HasherV8_combineyySuF" => {
            let hasher = context.reg_read(REG_X0 + 20)?;
            hash_word(context, hasher, context.reg_read(REG_X0)?)?;
        }
        "$ss6HasherV9_finalizeSiyF" => {
            let hasher = context.reg_read(REG_X0 + 20)?;
            let tail = read_guest_u64(context, hasher)?;
            context.reg_write(REG_X0, hash_compress(context, hasher, tail, true)?)?;
        }
        "$sSS4hash4intoys6HasherVz_tF" => {
            let hasher = context.reg_read(REG_X0)?;
            let string = swift_string(
                context,
                state,
                context.reg_read(REG_X0 + 1)?,
                context.reg_read(REG_X0 + 2)?,
            )?;
            let normalized = string.nfc().collect::<String>();
            let mut bytes = normalized.into_bytes();
            bytes.push(255);
            hash_bytes(context, hasher, &bytes)?;
        }
        "$ss17_NativeDictionaryV12ensureUnique02isD08capacityS2b_SitF" => {
            let slot = context.reg_read(REG_X0 + 20)?;
            let unique = context.reg_read(REG_X0)? != 0;
            let capacity = context.reg_read(REG_X0 + 1)?;
            let metadata = context.reg_read(REG_X0 + 2)?;
            ensure_unique_dictionary(context, profile, state, slot, unique, capacity, metadata)?;
        }
        "$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF" => {
            let value = swift_string(
                context,
                state,
                context.reg_read(REG_X0)?,
                context.reg_read(REG_X0 + 1)?,
            )?;
            let object = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, object)?;
        }
        "$sSS10FoundationE36_unconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ" => {
            let address = context.reg_read(REG_X0)?;
            let StoreValue::String(value) = &state
                .objects
                .get(&address)
                .context("unknown Objective-C string")?
                .value
            else {
                bail!("Objective-C bridge source is not a string");
            };
            let value = value.clone();
            return_swift_string(context, state, &value)?;
        }
        "$s10ObjectiveC8SelectorV4hash4intoys6HasherVz_tF" => {
            hash_word(
                context,
                context.reg_read(REG_X0)?,
                context.reg_read(REG_X0 + 1)?,
            )?;
        }
        "objc_msgSend" => {
            let selector_address = context.reg_read(REG_X0 + 1)?;
            let selector = guest_cstring(context, profile, state, selector_address)?;
            return dispatch_message(context, profile, state, &selector, selector_address, false);
        }
        "objc_msgSendSuper2" => {
            let super_ptr = context.reg_read(REG_X0)?;
            let receiver = read_guest_u64(context, super_ptr)?;
            let class_address = read_guest_u64(context, super_ptr + 8)?;
            let selector_address = context.reg_read(REG_X0 + 1)?;
            let selector = guest_cstring(context, profile, state, selector_address)?;
            let class_name = profile
                .runtime
                .class_names_by_address
                .get(&class_address)
                .context("unknown Store super class")?;
            let class_index = profile.runtime.classes_by_name[class_name];
            let superclass = &profile.index.classes[class_index].superclass;
            let meta = profile
                .runtime
                .class_names_by_address
                .contains_key(&receiver);
            if let Some(entry) = method_address(profile, superclass, &selector, meta) {
                context.reg_write(REG_X0, receiver)?;
                context.reg_write(REG_X0 + 1, selector_address)?;
                context.reg_write(REG_PC, entry)?;
                return Ok(());
            }
            context.reg_write(REG_X0, receiver)?;
            return dispatch_message(context, profile, state, &selector, selector_address, true);
        }
        _ => bail!(
            "unsupported Store bridge call: {} {}",
            call.symbol,
            call.selector
        ),
    }
    Ok(())
}

fn read_guest_u64(context: &HookContext, address: u64) -> Result<u64> {
    let bytes = context.mem_read(address, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
}

fn write_guest_u64(context: &HookContext, address: u64, value: u64) -> Result<()> {
    context.mem_write(address, &value.to_le_bytes())
}

fn begin_callback(
    context: &HookContext,
    state: &mut StoreState,
    function: u64,
    arguments: &[u64],
    action: CallbackAction,
) -> Result<()> {
    if function == 0 || arguments.len() > 8 {
        bail!("invalid Store guest callback");
    }
    let link = context.reg_read(REG_LR)?;
    let resume = state.allocate(16)?;
    context.mem_write(resume, &[0xc0, 0x03, 0x5f, 0xd6])?;
    state
        .callbacks
        .insert(resume, CallbackResume { link, action });
    for (index, &value) in arguments.iter().enumerate() {
        context.reg_write(REG_X0 + index as i32, value)?;
    }
    context.reg_write(REG_LR, resume)?;
    context.reg_write(REG_PC, function)?;
    Ok(())
}

fn resume_callback(context: &HookContext, resume: CallbackResume) -> Result<()> {
    match resume.action {
        CallbackAction::ReturnZero => context.reg_write(REG_X0, 0)?,
        CallbackAction::CopyProperty { destination } => {
            let value = context.reg_read(REG_X0)?;
            write_guest_u64(context, destination, value)?;
            context.reg_write(REG_X0, 0)?;
        }
    }
    context.reg_write(REG_LR, resume.link)?;
    context.reg_write(REG_PC, resume.link)?;
    Ok(())
}

fn init_hasher(
    context: &HookContext,
    profile: &ProfileData,
    address: u64,
    seed: u64,
) -> Result<()> {
    let (mut a, mut b) = (0, 0);
    if let Some(&parameters) = profile
        .index
        .symbols
        .get("_swift_stdlib_Hashing_parameters")
    {
        a = read_guest_u64(context, parameters)?;
        b = read_guest_u64(context, parameters + 8)?;
    }
    a ^= seed;
    for (index, value) in [
        0,
        0x736f_6d65_7073_6575 ^ a,
        0x646f_7261_6e64_6f6d ^ b,
        0x6c79_6765_6e65_7261 ^ a,
        0x7465_6462_7974_6573 ^ b,
        0,
        0,
        0,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        write_guest_u64(context, address + index as u64 * 8, value)?;
    }
    Ok(())
}

fn sip_round(values: &mut [u64; 4]) {
    values[0] = values[0].wrapping_add(values[1]);
    values[1] = values[1].rotate_left(13) ^ values[0];
    values[0] = values[0].rotate_left(32);
    values[2] = values[2].wrapping_add(values[3]);
    values[3] = values[3].rotate_left(16) ^ values[2];
    values[0] = values[0].wrapping_add(values[3]);
    values[3] = values[3].rotate_left(21) ^ values[0];
    values[2] = values[2].wrapping_add(values[1]);
    values[1] = values[1].rotate_left(17) ^ values[2];
    values[2] = values[2].rotate_left(32);
}

fn hash_compress(context: &HookContext, address: u64, word: u64, final_round: bool) -> Result<u64> {
    let mut values = [0u64; 4];
    for (index, value) in values.iter_mut().enumerate() {
        *value = read_guest_u64(context, address + 8 + index as u64 * 8)?;
    }
    values[3] ^= word;
    sip_round(&mut values);
    values[0] ^= word;
    if final_round {
        values[2] ^= 255;
        for _ in 0..3 {
            sip_round(&mut values);
        }
    }
    for (index, value) in values.iter().enumerate() {
        write_guest_u64(context, address + 8 + index as u64 * 8, *value)?;
    }
    Ok(values.into_iter().fold(0, |acc, value| acc ^ value))
}

fn hash_word(context: &HookContext, address: u64, word: u64) -> Result<()> {
    let mut tail = read_guest_u64(context, address)?;
    let count = tail >> 56;
    let shift = (count & 7) * 8;
    let chunk = if shift != 0 {
        let chunk = (tail & 0x00ff_ffff_ffff_ffff) | word.wrapping_shl(shift as u32);
        tail = ((count + 8) << 56) | (word >> (64 - shift));
        chunk
    } else {
        tail = tail.wrapping_add(8 << 56);
        word
    };
    write_guest_u64(context, address, tail)?;
    hash_compress(context, address, chunk, false)?;
    Ok(())
}

fn hash_bytes(context: &HookContext, address: u64, bytes: &[u8]) -> Result<()> {
    for &byte in bytes {
        let tail = read_guest_u64(context, address)?;
        let count = tail >> 56;
        let shift = (count & 7) * 8;
        let word = (tail & 0x00ff_ffff_ffff_ffff) | (u64::from(byte) << shift);
        if shift == 56 {
            hash_compress(context, address, word, false)?;
            write_guest_u64(context, address, (count + 1) << 56)?;
        } else {
            write_guest_u64(context, address, ((count + 1) << 56) | word)?;
        }
    }
    Ok(())
}

fn swift_string(
    context: &HookContext,
    state: &StoreState,
    first: u64,
    second: u64,
) -> Result<String> {
    if second & (1 << 61) != 0 {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&first.to_le_bytes());
        bytes[8..].copy_from_slice(&second.to_le_bytes());
        let length = ((second >> 56) & 15) as usize;
        return String::from_utf8(bytes[..length].to_vec()).context("invalid inline Swift string");
    }
    let pointer = second & 0x0fff_ffff_ffff_ffff;
    if second & (1 << 60) != 0 {
        let object = state
            .objects
            .get(&pointer)
            .context("unknown bridged Swift string")?;
        let StoreValue::String(value) = &object.value else {
            bail!("bridged Swift object is not a string");
        };
        return Ok(value.clone());
    }
    if second & (1 << 63) == 0 {
        bail!("unsupported mortal Swift string");
    }
    let length = first & 0x0000_ffff_ffff_ffff;
    if length > 1 << 20 {
        bail!("Swift string exceeds runtime limit");
    }
    String::from_utf8(context.mem_read(pointer + 32, length as usize)?)
        .context("invalid native Swift string")
}

fn return_swift_string(context: &HookContext, state: &mut StoreState, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() <= 15 {
        let mut words = [0u8; 16];
        words[..bytes.len()].copy_from_slice(bytes);
        words[15] = 0xa0 | bytes.len() as u8;
        if value.is_ascii() {
            words[15] |= 0x40;
        }
        context.reg_write(REG_X0, u64::from_le_bytes(words[..8].try_into()?))?;
        context.reg_write(REG_X0 + 1, u64::from_le_bytes(words[8..].try_into()?))?;
        return Ok(());
    }
    let address = state.allocate(bytes.len() as u64 + 33)?;
    context.mem_write(address + 32, bytes)?;
    context.mem_write(address + 32 + bytes.len() as u64, &[0])?;
    let mut flags = bytes.len() as u64 | 0x3000_0000_0000_0000;
    if value.is_ascii() {
        flags |= 0xc000_0000_0000_0000;
    }
    context.reg_write(REG_X0, flags)?;
    context.reg_write(REG_X0 + 1, address | 0x8000_0000_0000_0000)?;
    Ok(())
}

fn ensure_unique_dictionary(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    slot: u64,
    unique: bool,
    capacity: u64,
    metadata: u64,
) -> Result<()> {
    const BUCKETS: u64 = 1024;
    const STORAGE_CAPACITY: u64 = BUCKETS * 3 / 4;
    let old = read_guest_u64(context, slot)?;
    let old_capacity = read_guest_u64(context, old + 24)?;
    if unique && capacity <= old_capacity {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    let layout = profile
        .index
        .swift_dictionaries
        .get(&metadata.to_string())
        .with_context(|| format!("unprepared Swift dictionary metadata {metadata:#x}"))?;
    if ![16, 32, 40].contains(&layout.key_stride) || ![8, 16, 32].contains(&layout.value_stride) {
        bail!("unsupported Swift dictionary copy layout");
    }
    if capacity > STORAGE_CAPACITY {
        bail!("Swift dictionary exceeds runtime capacity");
    }
    let count = read_guest_u64(context, old + 16)?;
    if count != 0 && old_capacity != STORAGE_CAPACITY {
        bail!("Swift dictionary resizing requires rehash");
    }
    let header_size = 64 + BUCKETS / 8;
    let size = header_size + BUCKETS * (layout.key_stride + layout.value_stride);
    let storage = state.allocate(size)?;
    write_guest_u64(context, storage, layout.metadata)?;
    write_guest_u64(context, storage + 8, 3)?;
    write_guest_u64(context, storage + 16, count)?;
    write_guest_u64(context, storage + 24, STORAGE_CAPACITY)?;
    write_guest_u64(context, storage + 32, 10)?;
    write_guest_u64(context, storage + 40, read_guest_u64(context, old + 40)?)?;
    let keys = storage + header_size;
    let values = keys + BUCKETS * layout.key_stride;
    write_guest_u64(context, storage + 48, keys)?;
    write_guest_u64(context, storage + 56, values)?;
    if count != 0 {
        for (destination, source, size) in [
            (storage + 64, old + 64, BUCKETS / 8),
            (
                keys,
                read_guest_u64(context, old + 48)?,
                BUCKETS * layout.key_stride,
            ),
            (
                values,
                read_guest_u64(context, old + 56)?,
                BUCKETS * layout.value_stride,
            ),
        ] {
            context.mem_write(destination, &context.mem_read(source, size as usize)?)?;
        }
    }
    write_guest_u64(context, slot, storage)?;
    context.reg_write(REG_X0, u64::from(old_capacity != STORAGE_CAPACITY))?;
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

fn guest_selector_address(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    selector: &str,
) -> Result<u64> {
    if let Some(&address) = profile.runtime.selector_addresses.get(selector) {
        return Ok(address);
    }
    if let Some(&address) = state.dynamic_selectors.get(selector) {
        return Ok(address);
    }
    let address = state.allocate(selector.len() as u64 + 1)?;
    context.mem_write(address, selector.as_bytes())?;
    context.mem_write(address + selector.len() as u64, &[0])?;
    state.dynamic_selectors.insert(selector.to_owned(), address);
    state
        .dynamic_selector_addresses
        .insert(address, selector.to_owned());
    Ok(address)
}

fn dispatch_message(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    selector: &str,
    selector_address: u64,
    skip_lookup: bool,
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
    if !skip_lookup
        && let Some(entry) = method_address(profile, &class_name, selector, class_method)
    {
        context.reg_write(REG_X0 + 1, selector_address)?;
        context.reg_write(REG_PC, entry)?;
        return Ok(());
    }
    match (class_method, selector) {
        (true, "mainBundle") => {
            context.reg_write(REG_X0, new_main_bundle(context, profile, state)?)?;
        }
        (true, "currentThread") => {
            let address = new_guest_object(context, profile, state, "NSThread", StoreValue::Empty)?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "isMainThread") => context.reg_write(REG_X0, 1)?,
        (true, "UUID") => {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).context("generate Store guest UUID")?;
            bytes[6] = (bytes[6] & 15) | 64;
            bytes[8] = (bytes[8] & 63) | 128;
            let value = [
                &bytes[..4],
                &bytes[4..6],
                &bytes[6..8],
                &bytes[8..10],
                &bytes[10..],
            ]
            .into_iter()
            .map(|group| {
                group
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("-");
            let address =
                new_guest_object(context, profile, state, "NSUUID", StoreValue::String(value))?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "alloc" | "allocWithZone:") => {
            let address =
                new_guest_object(context, profile, state, &class_name, StoreValue::Empty)?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "numberWithBool:") => {
            let value = context.reg_read(REG_X0 + 2)? != 0;
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSNumber",
                StoreValue::Boolean(value),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "URLWithString:" | "fileURLWithPath:" | "fileURLWithPath:isDirectory:") => {
            let source = context.reg_read(REG_X0 + 2)?;
            let value = match state.objects.get(&source) {
                Some(StoreObject {
                    value: StoreValue::String(value),
                    ..
                }) => value.clone(),
                _ if source == 0 => String::new(),
                _ => bail!("URL initializer source is not a string"),
            };
            let value = if selector.starts_with("fileURL") {
                url::Url::from_file_path(&value)
                    .map_err(|()| anyhow::anyhow!("invalid guest file URL path"))?
                    .to_string()
            } else {
                value
            };
            let address =
                new_guest_object(context, profile, state, "NSURL", StoreValue::String(value))?;
            context.reg_write(REG_X0, address)?;
        }
        (
            true,
            "numberWithInteger:"
            | "numberWithInt:"
            | "numberWithUnsignedInteger:"
            | "numberWithLongLong:"
            | "numberWithUnsignedLongLong:",
        ) => {
            let value = context.reg_read(REG_X0 + 2)? as i64;
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSNumber",
                StoreValue::Number(value),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (
            false,
            "valueForKey:"
            | "__swift_objectForKeyedSubscript:"
            | "objectForKey:"
            | "objectForKeyedSubscript:",
        ) => {
            let key = collection_key(state, context.reg_read(REG_X0 + 2)?);
            let object = &state.objects[&receiver];
            let StoreValue::Entries(entries) = &object.value else {
                bail!("dictionary access on {class_name}");
            };
            context.reg_write(REG_X0, entries.get(&key).copied().unwrap_or(0))?;
        }
        (false, "setValue:forKey:" | "setObject:forKey:" | "setObject:forKeyedSubscript:") => {
            let value = context.reg_read(REG_X0 + 2)?;
            let key = collection_key(state, context.reg_read(REG_X0 + 3)?);
            let object = state.objects.get_mut(&receiver).expect("known receiver");
            let StoreValue::Entries(entries) = &mut object.value else {
                bail!("dictionary mutation on {class_name}");
            };
            if value == 0 {
                entries.remove(&key);
            } else {
                entries.insert(key, value);
            }
            context.reg_write(REG_X0, 0)?;
        }
        (false, "count" | "length") => {
            let object = &state.objects[&receiver];
            let count = match &object.value {
                StoreValue::String(value) => value.len(),
                StoreValue::Addresses(values) => values.len(),
                StoreValue::Entries(values) => values.len(),
                _ => bail!("count of {class_name}"),
            };
            context.reg_write(REG_X0, count as u64)?;
        }
        (false, "containsObject:") => {
            let needle = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Addresses(values) = &state.objects[&receiver].value else {
                bail!("containsObject: on {class_name}");
            };
            let found = values
                .iter()
                .any(|&value| foundation_equal(state, value, needle, 0));
            context.reg_write(REG_X0, u64::from(found))?;
        }
        (false, "firstObject" | "lastObject") => {
            let StoreValue::Addresses(values) = &state.objects[&receiver].value else {
                bail!("array access on {class_name}");
            };
            let value = if selector == "firstObject" {
                values.first()
            } else {
                values.last()
            };
            context.reg_write(REG_X0, value.copied().unwrap_or(0))?;
        }
        (false, "objectAtIndex:" | "objectAtIndexedSubscript:") => {
            let index = context.reg_read(REG_X0 + 2)? as usize;
            let StoreValue::Addresses(values) = &state.objects[&receiver].value else {
                bail!("array access on {class_name}");
            };
            let value = values
                .get(index)
                .context("Store array index out of bounds")?;
            context.reg_write(REG_X0, *value)?;
        }
        (false, "addObject:") => {
            let value = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Addresses(values) = &mut state
                .objects
                .get_mut(&receiver)
                .expect("known receiver")
                .value
            else {
                bail!("addObject: on {class_name}");
            };
            values.push(value);
            context.reg_write(REG_X0, 0)?;
        }
        (false, "bundleIdentifier" | "bundlePath" | "processName" | "environment") => {
            let object = &state.objects[&receiver];
            context.reg_write(
                REG_X0,
                object.properties.get(selector).copied().unwrap_or(0),
            )?;
        }
        (false, "threadDictionary") => {
            let existing = state.objects[&receiver]
                .properties
                .get("threadDictionary")
                .copied();
            let value = if let Some(value) = existing {
                value
            } else {
                let value = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSMutableDictionary",
                    StoreValue::Entries(HashMap::new()),
                )?;
                state
                    .objects
                    .get_mut(&receiver)
                    .expect("known thread")
                    .properties
                    .insert("threadDictionary".into(), value);
                value
            };
            context.reg_write(REG_X0, value)?;
        }
        (false, "executableURL" | "bundleURL") => {
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSURL",
                StoreValue::String("file:///ipatool".into()),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (false, "lowercaseString" | "uppercaseString") => {
            let StoreValue::String(value) = &state.objects[&receiver].value else {
                bail!("string conversion on {class_name}");
            };
            let value = if selector == "lowercaseString" {
                value.to_lowercase()
            } else {
                value.to_uppercase()
            };
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (false, "UUIDString") => {
            let StoreValue::String(value) = &state.objects[&receiver].value else {
                bail!("UUIDString on {class_name}");
            };
            let value = value.clone();
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (false, "componentsSeparatedByString:") => {
            let separator_address = context.reg_read(REG_X0 + 2)?;
            let (
                StoreValue::String(value),
                Some(StoreObject {
                    value: StoreValue::String(separator),
                    ..
                }),
            ) = (
                &state.objects[&receiver].value,
                state.objects.get(&separator_address),
            )
            else {
                bail!("string split requires NSString values");
            };
            let (value, separator) = (value.clone(), separator.clone());
            let mut parts = Vec::new();
            for part in value.split(&separator) {
                parts.push(new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(part.into()),
                )?);
            }
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(parts),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (false, "path" | "lastPathComponent") => {
            let StoreValue::String(value) = &state.objects[&receiver].value else {
                bail!("path operation on {class_name}");
            };
            let value = if class_name == "NSURL" {
                url::Url::parse(value)?.path().to_owned()
            } else {
                value.clone()
            };
            let value = if selector == "lastPathComponent" {
                std::path::Path::new(&value)
                    .file_name()
                    .map(|part| part.to_string_lossy().into_owned())
                    .unwrap_or_default()
            } else {
                value
            };
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (false, "stringByDeletingPathExtension") => {
            let StoreValue::String(value) = &state.objects[&receiver].value else {
                bail!("path extension removal on {class_name}");
            };
            let cut = value
                .rfind('.')
                .filter(|&dot| value.rfind('/').is_none_or(|slash| dot > slash));
            let text = cut.map_or(value.as_str(), |index| &value[..index]);
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(text.to_owned()),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (false, "isEqual:" | "isEqualToString:" | "isEqualToDictionary:" | "isEqualToArray:") => {
            let other = context.reg_read(REG_X0 + 2)?;
            context.reg_write(
                REG_X0,
                u64::from(foundation_equal(state, receiver, other, 0)),
            )?;
        }
        (false, "infoDictionary") => {
            let existing = state.objects[&receiver]
                .properties
                .get("infoDictionary")
                .copied();
            let value = if let Some(value) = existing {
                value
            } else {
                let mut entries = HashMap::new();
                for (key, value) in [
                    ("CFBundleIdentifier", "me.majd.ipatool"),
                    ("CFBundleVersion", "1.0"),
                    ("CFBundleExecutable", "ipatool"),
                    ("CFBundleName", "ipatool"),
                ] {
                    let value = new_guest_object(
                        context,
                        profile,
                        state,
                        "NSString",
                        StoreValue::String(value.into()),
                    )?;
                    entries.insert(key.into(), value);
                }
                new_guest_object(
                    context,
                    profile,
                    state,
                    "NSDictionary",
                    StoreValue::Entries(entries),
                )?
            };
            context.reg_write(REG_X0, value)?;
        }
        (
            false,
            "integerValue"
            | "intValue"
            | "longLongValue"
            | "unsignedIntegerValue"
            | "unsignedLongLongValue"
            | "boolValue",
        ) => {
            let object = &state.objects[&receiver];
            let value = match &object.value {
                StoreValue::Number(value) => *value,
                StoreValue::Boolean(value) => i64::from(*value),
                StoreValue::String(value) => value.parse::<i64>().unwrap_or(0),
                _ => 0,
            };
            context.reg_write(REG_X0, value as u64)?;
        }
        (false, "init") => {
            let object = state.objects.get_mut(&receiver).expect("known receiver");
            if matches!(object.value, StoreValue::Empty) {
                object.value = match class_name.as_str() {
                    "NSString" | "NSMutableString" => StoreValue::String(String::new()),
                    "NSCache" | "NSDictionary" | "NSMutableDictionary" => {
                        StoreValue::Entries(HashMap::new())
                    }
                    "NSArray"
                    | "NSMutableArray"
                    | "NSSet"
                    | "NSMutableSet"
                    | "NSOrderedSet"
                    | "NSMutableOrderedSet" => StoreValue::Addresses(Vec::new()),
                    _ => StoreValue::Empty,
                };
            }
            context.reg_write(REG_X0, receiver)?;
        }
        (true, "class") | (false, "retain" | "autorelease" | "copy" | "copyWithZone:") => {
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

fn collection_key(state: &StoreState, address: u64) -> String {
    if let Some(object) = state.objects.get(&address) {
        match &object.value {
            StoreValue::String(value) => return value.clone(),
            StoreValue::Number(value) => return format!("#number:{value}"),
            _ => {}
        }
    }
    format!("#object:{address:x}")
}

fn foundation_equal(state: &StoreState, first: u64, second: u64, depth: usize) -> bool {
    if first == second {
        return true;
    }
    if depth >= 32 {
        return false;
    }
    let (Some(first), Some(second)) = (state.objects.get(&first), state.objects.get(&second))
    else {
        return false;
    };
    match (&first.value, &second.value) {
        (StoreValue::String(a), StoreValue::String(b)) => a == b,
        (StoreValue::Number(a), StoreValue::Number(b)) => a == b,
        (StoreValue::Boolean(a), StoreValue::Boolean(b)) => a == b,
        (StoreValue::Number(a), StoreValue::Boolean(b))
        | (StoreValue::Boolean(b), StoreValue::Number(a)) => *a == i64::from(*b),
        (StoreValue::Addresses(a), StoreValue::Addresses(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|(&a, &b)| foundation_equal(state, a, b, depth + 1))
        }
        (StoreValue::Entries(a), StoreValue::Entries(b)) => {
            a.len() == b.len()
                && a.iter().all(|(key, &value)| {
                    b.get(key)
                        .is_some_and(|&other| foundation_equal(state, value, other, depth + 1))
                })
        }
        _ => false,
    }
}

fn new_guest_object(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    class_name: &str,
    value: StoreValue,
) -> Result<u64> {
    let class = profile
        .runtime
        .classes_by_name
        .get(class_name)
        .map(|&index| &profile.index.classes[index]);
    let size = class.map_or(256, |class| class.size.max(16));
    let address = state.allocate(size)?;
    if let Some(class) = class {
        context.mem_write(address, &class.address.to_le_bytes())?;
    }
    state.objects.insert(
        address,
        StoreObject {
            class: class_name.to_owned(),
            value,
            properties: HashMap::new(),
        },
    );
    Ok(address)
}

fn new_main_bundle(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
) -> Result<u64> {
    let bundle = new_guest_object(context, profile, state, "NSBundle", StoreValue::Empty)?;
    for (key, value) in [
        ("bundleIdentifier", "me.majd.ipatool"),
        ("bundlePath", "/ipatool"),
    ] {
        let address = new_guest_object(
            context,
            profile,
            state,
            "NSString",
            StoreValue::String(value.into()),
        )?;
        state
            .objects
            .get_mut(&bundle)
            .expect("new bundle")
            .properties
            .insert(key.into(), address);
    }
    Ok(bundle)
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
        let options = runtime
            .new_object("AMSAuthenticateOptions", StoreValue::Empty)
            .unwrap();
        assert_eq!(runtime.invoke(options, "init", &[]).unwrap(), options);
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
