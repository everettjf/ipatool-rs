//! StoreAgent guest memory prepared from the pinned AMS images and profile.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde_json::Value;
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
    hardware_id: Option<[u8; 6]>,
    preferences: HashMap<String, u64>,
    current_queue: u64,
    pending: Vec<(u64, u64)>,
    allocations: HashMap<u64, u64>,
    main_queue: Option<u64>,
    associations: HashMap<(u64, u64), u64>,
}

struct CallbackResume {
    link: u64,
    action: CallbackAction,
}

enum CallbackAction {
    ReturnZero,
    ReturnValue {
        value: u64,
    },
    QueueBlock {
        block: u64,
        queue: u64,
    },
    StoreAt {
        destination: u64,
        value: u64,
    },
    StoreProperty {
        receiver: u64,
        key: String,
        value: u64,
    },
    ReturnUnavailableProxy {
        error_block: u64,
    },
    EnumerateEntries {
        block: u64,
        entries: Vec<(String, u64)>,
        index: usize,
        stop: u64,
    },
    ArrayCopy {
        destination: u64,
        source: u64,
        metadata: u64,
        stride: u64,
        count: u64,
        index: u64,
        function: u64,
        reverse: bool,
    },
    RestoreQueue {
        previous: u64,
    },
    RestoreQueueWithValue {
        previous: u64,
        value: u64,
    },
    CopyProperty {
        destination: u64,
    },
}

pub struct StoreObject {
    pub class: String,
    pub value: StoreValue,
    pub properties: HashMap<String, u64>,
}

#[derive(Clone)]
pub enum StoreValue {
    Empty,
    String(String),
    Number(i64),
    Float(f64),
    Boolean(bool),
    Bytes(Vec<u8>),
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
            hardware_id: None,
            preferences: HashMap::new(),
            current_queue: 0,
            pending: Vec::new(),
            allocations: HashMap::new(),
            main_queue: None,
            associations: HashMap::new(),
        }));
        let hook_error = Rc::new(RefCell::new(None));
        let error_slot = Rc::clone(&hook_error);
        let hook_profile = Arc::clone(&profile);
        let hook_code_ranges = code_ranges.clone();
        let hook_state = Rc::clone(&state);
        engine.add_code_hook(0, u64::MAX, move |context, address, _| {
            let resume = hook_state.borrow_mut().callbacks.remove(&address);
            if let Some(resume) = resume {
                if let Err(error) =
                    resume_callback(context, &hook_profile, &mut hook_state.borrow_mut(), resume)
                {
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

    pub fn set_hardware_id(&mut self, hardware_id: &[u8]) -> Result<()> {
        let hardware_id: [u8; 6] = hardware_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Store hardware identity must be six bytes"))?;
        self.state.borrow_mut().hardware_id = Some(hardware_id);
        Ok(())
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

    pub fn export(&self, address: u64) -> Result<Value> {
        export_object(&self.state.borrow(), address, &mut HashSet::new(), 0)
    }

    pub fn import_json(&mut self, value: &Value) -> Result<u64> {
        self.import_json_inner(value, 0)
    }

    fn import_json_inner(&mut self, value: &Value, depth: usize) -> Result<u64> {
        if depth > 32 {
            bail!("Store Foundation import exceeds nesting limit");
        }
        match value {
            Value::Null => Ok(0),
            Value::String(value) => self.new_object("NSString", StoreValue::String(value.clone())),
            Value::Bool(value) => self.new_object("NSNumber", StoreValue::Boolean(*value)),
            Value::Number(value) => {
                let value = if let Some(integer) = value.as_i64() {
                    StoreValue::Number(integer)
                } else if let Some(integer) =
                    value.as_u64().filter(|value| *value <= i64::MAX as u64)
                {
                    StoreValue::Number(integer as i64)
                } else {
                    StoreValue::Float(value.as_f64().context("invalid Store JSON number")?)
                };
                self.new_object("NSNumber", value)
            }
            Value::Array(values) => {
                if values.len() > 65_536 {
                    bail!("Store Foundation array exceeds size limit");
                }
                let mut imported = Vec::with_capacity(values.len());
                for value in values {
                    imported.push(self.import_json_inner(value, depth + 1)?);
                }
                self.new_object("NSArray", StoreValue::Addresses(imported))
            }
            Value::Object(values) => {
                if values.len() > 65_536 {
                    bail!("Store Foundation dictionary exceeds size limit");
                }
                let mut imported = HashMap::with_capacity(values.len());
                for (key, value) in values {
                    imported.insert(key.clone(), self.import_json_inner(value, depth + 1)?);
                }
                self.new_object("NSDictionary", StoreValue::Entries(imported))
            }
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

    /// Run Apple's pinned credential-parameter builder in the Store guest.
    /// `bag` is a guest pointer to a prepared frozen bag, or zero.
    pub fn build_authentication_parameters(
        &mut self,
        email: &str,
        password: &str,
        hardware_id: &[u8],
        bag: u64,
    ) -> Result<Value> {
        self.set_hardware_id(hardware_id)?;
        let account_class = self
            .class_address("ACAccount")
            .context("Store profile is missing ACAccount")?;
        let account = self.invoke(account_class, "ams_createEphemeralAccount", &[])?;
        let username = self.new_object("NSString", StoreValue::String(email.into()))?;
        self.invoke(account, "setUsername:", &[username])?;

        let options = self.new_object("AMSAuthenticateOptions", StoreValue::Empty)?;
        self.invoke(options, "init", &[])?;
        for (selector, value) in [
            ("setEphemeral:", 1),
            ("setCanMakeAccountActive:", 0),
            ("setAllowServerDialogs:", 0),
            ("setCredentialSource:", 0),
        ] {
            self.invoke(options, selector, &[value])?;
        }
        let password_object = self.new_object("NSString", StoreValue::String(password.into()))?;
        self.invoke(options, "setPassword:", &[password_object])?;

        let task = self.new_object("AMSVerifyCredentialsTask", StoreValue::Empty)?;
        self.invoke(task, "init", &[])?;
        for (name, value) in [("_account", account), ("_options", options), ("_bag", bag)] {
            self.set_ivar(task, name, value)?;
        }
        let parameters = self.invoke(
            task,
            "_createAuthenticateRequestParametersForAccount:",
            &[account],
        )?;
        let parameters = self.export(parameters)?;
        let expected_guid = hardware_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if !parameters
            .get("guid")
            .and_then(Value::as_str)
            .is_some_and(|guid| guid.eq_ignore_ascii_case(&expected_guid))
        {
            bail!("Store authentication hardware identity mismatch");
        }
        Ok(parameters)
    }

    pub fn new_request_encoder(&mut self, bag: u64) -> Result<u64> {
        let encoder = self.new_object("AMSURLRequestEncoder", StoreValue::Empty)?;
        self.invoke(encoder, "initWithBag:", &[bag])
    }

    pub fn resolve_promise(&mut self, promise: u64) -> Result<u64> {
        let failure = self.allocate(8)?;
        let result = self.invoke(promise, "resultWithError:", &[failure])?;
        let error = self.read_u64(failure)?;
        if error != 0 {
            let domain = self.invoke(error, "domain", &[])?;
            let code = self.invoke(error, "code", &[])? as i64;
            let domain = self.object_string(domain)?;
            bail!("Store framework error {domain}/{code}");
        }
        if result == 0 {
            bail!("Store framework returned no result");
        }
        Ok(result)
    }

    pub fn encode_request(
        &mut self,
        account: u64,
        bag: u64,
        method: &str,
        endpoint: &str,
        parameters: &Value,
    ) -> Result<u64> {
        let encoder = self.new_request_encoder(bag)?;
        for (selector, value) in [
            ("setAccount:", account),
            ("setRequestEncoding:", 2),
            ("setAnisetteType:", 0),
            ("setMescalType:", 0),
            ("setEnableRemoteSecuritySigning:", 0),
            ("setUrlKnownToBeTrusted:", 1),
            ("setShouldSetCookieHeader:", 0),
            ("setShouldSetStorefrontHeader:", 0),
            ("setDisableLoadURLMetrics:", 1),
        ] {
            self.invoke(encoder, selector, &[value])?;
        }
        let method_id = match method {
            "GET" => 2,
            "POST" => 4,
            "PUT" => 5,
            _ => bail!("unsupported encoded Store request method"),
        };
        let url = self.new_object("NSURL", StoreValue::String(endpoint.into()))?;
        let parameters = self.import_json(parameters)?;
        let promise = self.invoke(
            encoder,
            "requestWithMethod:URL:parameters:",
            &[method_id, url, parameters],
        )?;
        self.resolve_promise(promise)
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
        self.allocations.insert(address, size);
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
        StoreValue::Number(_) | StoreValue::Boolean(_) | StoreValue::Float(_) => matches!(
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
        StoreValue::Bytes(_) => matches!(selector, "count" | "length"),
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
        | "os_signpost_id_make_with_pointer"
        | "os_log_type_enabled"
        | "os_variant_has_internal_content"
        | "swift_isUniquelyReferenced_nonNull_native"
        | "swift_isUniquelyReferenced_nonNull_bridgeObject" => {
            context.reg_write(REG_X0, 0)?;
        }
        "getuid" | "geteuid" => context.reg_write(REG_X0, 501)?,
        "getgid" | "getegid" => context.reg_write(REG_X0, 20)?,
        "getpid" => context.reg_write(REG_X0, 123)?,
        "NSSearchPathForDirectoriesInDomains" => {
            if context.reg_read(REG_X0)? != 5 || context.reg_read(REG_X0 + 1)? != 8 {
                bail!("unsupported virtual filesystem directory");
            }
            let path = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String("/System/Library".into()),
            )?;
            let array = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(vec![path]),
            )?;
            context.reg_write(REG_X0, array)?;
        }
        "MGCopyAnswerWithError" | "MGCopyAnswer" => {
            let key = object_string_value(state, context.reg_read(REG_X0)?)?;
            let value = match key {
                "BuildVersion" => "26A434",
                "ProductVersion" => "27.0.1",
                "DeviceClass" => "Mac",
                "ProductType" => "Mac14,2",
                _ => bail!("unsupported device property {key}"),
            };
            if symbol == "MGCopyAnswerWithError" {
                let error = context.reg_read(REG_X0 + 2)?;
                if error != 0 {
                    context.mem_write(error, &[0; 4])?;
                }
            }
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value.into()),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        "time" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let output = context.reg_read(REG_X0)?;
            if output != 0 {
                write_guest_u64(context, output, now)?;
            }
            context.reg_write(REG_X0, now)?;
        }
        "localtime" | "localtime_r" | "gmtime_r" => {
            let timestamp = read_guest_u64(context, context.reg_read(REG_X0)?)? as i64;
            let date = time::OffsetDateTime::from_unix_timestamp(timestamp)
                .context("invalid guest time value")?;
            let output = if symbol == "localtime" {
                state.allocate(56)?
            } else {
                context.reg_read(REG_X0 + 1)?
            };
            let fields = [
                date.second() as i32,
                date.minute() as i32,
                date.hour() as i32,
                date.day() as i32,
                date.month() as i32 - 1,
                date.year() - 1900,
                date.weekday().number_days_from_sunday() as i32,
                date.ordinal() as i32 - 1,
                0,
            ];
            let mut bytes = [0u8; 56];
            for (index, field) in fields.iter().enumerate() {
                bytes[index * 4..index * 4 + 4].copy_from_slice(&field.to_le_bytes());
            }
            context.mem_write(output, &bytes)?;
            context.reg_write(REG_X0, output)?;
        }
        "os_transaction_create" => {
            let name = guest_cstring(context, profile, state, context.reg_read(REG_X0)?)?;
            let transaction = new_guest_object(
                context,
                profile,
                state,
                "HostOSTransaction",
                StoreValue::String(name),
            )?;
            context.reg_write(REG_X0, transaction)?;
        }
        "chkstk_darwin" | "free" => {}
        "malloc_size" => {
            let address = context.reg_read(REG_X0)?;
            context.reg_write(
                REG_X0,
                state.allocations.get(&address).copied().unwrap_or(0),
            )?;
        }
        "malloc" | "calloc" | "malloc_type_malloc" | "malloc_type_calloc" => {
            let mut size = context.reg_read(REG_X0)?;
            if matches!(symbol, "calloc" | "malloc_type_calloc") {
                size = size
                    .checked_mul(context.reg_read(REG_X0 + 1)?)
                    .context("guest calloc size overflow")?;
            }
            let address = state.allocate(size)?;
            context.reg_write(REG_X0, address)?;
        }
        "swift_allocObject" => {
            let metadata = context.reg_read(REG_X0)?;
            let size = context.reg_read(REG_X0 + 1)?;
            if !(16..=1_048_576).contains(&size) {
                bail!("invalid Swift object size {size}");
            }
            let object = state.allocate(size)?;
            write_guest_u64(context, object, metadata)?;
            write_guest_u64(context, object + 8, 3)?;
            context.reg_write(REG_X0, object)?;
        }
        "swift_arrayInitWithCopy"
        | "swift_arrayInitWithTakeFrontToBack"
        | "swift_arrayInitWithTakeBackToFront" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            let count = context.reg_read(REG_X0 + 2)?;
            let metadata = context.reg_read(REG_X0 + 3)?;
            if count == 0 {
                context.reg_write(REG_X0, destination)?;
            } else {
                let witnesses = read_guest_u64(context, metadata - 8)?;
                let stride = read_guest_u64(context, witnesses + 72)?;
                if count > 65_536 || stride > 1_048_576 {
                    bail!("Swift array copy exceeds budget");
                }
                let offset = if symbol == "swift_arrayInitWithCopy" {
                    16
                } else {
                    32
                };
                let function = read_guest_u64(context, witnesses + offset)?;
                let reverse = symbol == "swift_arrayInitWithTakeBackToFront";
                let element = if reverse { count - 1 } else { 0 };
                begin_callback(
                    context,
                    state,
                    function,
                    &[
                        destination + element * stride,
                        source + element * stride,
                        metadata,
                    ],
                    CallbackAction::ArrayCopy {
                        destination,
                        source,
                        metadata,
                        stride,
                        count,
                        index: 1,
                        function,
                        reverse,
                    },
                )?;
            }
        }
        "swift_getObjectType" => {
            let object = context.reg_read(REG_X0)?;
            context.reg_write(REG_X0, read_guest_u64(context, object)?)?;
        }
        "swift_defaultActor_initialize" => {
            let actor = context.reg_read(REG_X0)?;
            if actor == 0 {
                bail!("cannot initialize null Swift actor");
            }
            state.objects.insert(
                actor,
                StoreObject {
                    class: "HostSwiftActor".into(),
                    value: StoreValue::Empty,
                    properties: HashMap::new(),
                },
            );
        }
        "objc_opt_self"
        | "swift_getObjCClassMetadata"
        | "swift_retain_n"
        | "swift_bridgeObjectRetain_n"
        | "swift_retain"
        | "swift_bridgeObjectRetain"
        | "swift_unknownObjectRetain"
        | "swift_destroy_strong"
        | "$ss15CollectionOfOneV8IteratorVwxx"
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
        "Block_copy" | "objc_retainBlock" => {
            let block = context.reg_read(REG_X0)?;
            if block == 0 || (read_guest_u64(context, block + 8)? as u32) & (1 << 28) != 0 {
                return Ok(());
            }
            let flags = read_guest_u64(context, block + 8)? as u32;
            let descriptor = read_guest_u64(context, block + 24)?;
            let size = read_guest_u64(context, descriptor + 8)?;
            if !(32..=1_048_576).contains(&size) {
                bail!("invalid guest block size {size}");
            }
            let copied = state.allocate(size)?;
            let data = context.mem_read(block, size as usize)?;
            context.mem_write(copied, &data)?;
            if flags & (1 << 25) != 0 {
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, descriptor + 16)?,
                    &[copied, block],
                    CallbackAction::ReturnValue { value: copied },
                )?;
            } else {
                context.reg_write(REG_X0, copied)?;
            }
        }
        "Block_release" | "Block_object_dispose" => {}
        "Block_object_assign" => {
            let destination = context.reg_read(REG_X0)?;
            let value = context.reg_read(REG_X0 + 1)?;
            let flags = context.reg_read(REG_X0 + 2)?;
            if flags & 15 == 7 && value != 0 {
                let block_flags = read_guest_u64(context, value + 8)? as u32;
                if block_flags & (1 << 28) != 0 {
                    write_guest_u64(context, destination, value)?;
                } else {
                    let descriptor = read_guest_u64(context, value + 24)?;
                    let size = read_guest_u64(context, descriptor + 8)?;
                    if !(32..=1_048_576).contains(&size) {
                        bail!("invalid guest block size {size}");
                    }
                    let copied = state.allocate(size)?;
                    context.mem_write(copied, &context.mem_read(value, size as usize)?)?;
                    if block_flags & (1 << 25) != 0 {
                        begin_callback(
                            context,
                            state,
                            read_guest_u64(context, descriptor + 16)?,
                            &[copied, value],
                            CallbackAction::StoreAt {
                                destination,
                                value: copied,
                            },
                        )?;
                    } else {
                        write_guest_u64(context, destination, copied)?;
                    }
                }
            } else if flags & 8 != 0 && value != 0 {
                let forwarded = read_guest_u64(context, value + 8)?;
                if forwarded != 0 && forwarded != value {
                    write_guest_u64(context, destination, forwarded)?;
                } else {
                    let header = read_guest_u64(context, value + 16)?;
                    let size = header >> 32;
                    if !(24..=1_048_576).contains(&size) {
                        bail!("invalid byref capture size {size}");
                    }
                    let copied = state.allocate(size)?;
                    context.mem_write(copied, &context.mem_read(value, size as usize)?)?;
                    write_guest_u64(context, copied + 8, copied)?;
                    write_guest_u64(context, value + 8, copied)?;
                    if (header as u32) & (1 << 25) != 0 {
                        begin_callback(
                            context,
                            state,
                            read_guest_u64(context, value + 24)?,
                            &[copied, value],
                            CallbackAction::StoreAt {
                                destination,
                                value: copied,
                            },
                        )?;
                    } else {
                        write_guest_u64(context, destination, copied)?;
                    }
                }
            } else {
                write_guest_u64(context, destination, value)?;
            }
        }
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
        "objc_getAssociatedObject" => {
            let object = context.reg_read(REG_X0)?;
            let key = context.reg_read(REG_X0 + 1)?;
            context.reg_write(
                REG_X0,
                state.associations.get(&(object, key)).copied().unwrap_or(0),
            )?;
        }
        "objc_setAssociatedObject" => {
            let object = context.reg_read(REG_X0)?;
            let key = context.reg_read(REG_X0 + 1)?;
            let value = context.reg_read(REG_X0 + 2)?;
            state.associations.insert((object, key), value);
            context.reg_write(REG_X0, 0)?;
        }
        "objc_opt_respondsToSelector" => {
            let receiver = context.reg_read(REG_X0)?;
            let selector = guest_cstring(context, profile, state, context.reg_read(REG_X0 + 1)?)?;
            context.reg_write(
                REG_X0,
                u64::from(responds_to(profile, state, receiver, &selector)),
            )?;
        }
        "NSClassFromString" => {
            let name = object_string_value(state, context.reg_read(REG_X0)?)?;
            let address = profile
                .runtime
                .classes_by_name
                .get(name)
                .map(|&index| profile.index.classes[index].address)
                .unwrap_or(0);
            context.reg_write(REG_X0, address)?;
        }
        "objc_getClass" => {
            let name = guest_cstring(context, profile, state, context.reg_read(REG_X0)?)?;
            let address = profile
                .runtime
                .classes_by_name
                .get(&name)
                .map(|&index| profile.index.classes[index].address)
                .unwrap_or(0);
            context.reg_write(REG_X0, address)?;
        }
        "NSStringFromClass" => {
            let class = context.reg_read(REG_X0)?;
            let address = if let Some(name) = profile.runtime.class_names_by_address.get(&class) {
                new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(name.clone()),
                )?
            } else {
                0
            };
            context.reg_write(REG_X0, address)?;
        }
        "NSSelectorFromString" => {
            let selector = object_string_value(state, context.reg_read(REG_X0)?)?.to_owned();
            context.reg_write(
                REG_X0,
                guest_selector_address(context, profile, state, &selector)?,
            )?;
        }
        "NSStringFromSelector" => {
            let selector = guest_cstring(context, profile, state, context.reg_read(REG_X0)?)?;
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(selector),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        "CFBundleGetMainBundle" => {
            let bundle = new_main_bundle(context, profile, state)?;
            context.reg_write(REG_X0, bundle)?;
        }
        "NSUserName"
        | "NSFullUserName"
        | "NSTemporaryDirectory"
        | "CPSharedResourcesDirectory"
        | "NSHomeDirectory" => {
            let value = match symbol {
                "NSUserName" | "NSFullUserName" => "ipatool",
                "NSTemporaryDirectory" => "/ipatool/tmp/",
                _ => "/ipatool",
            };
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value.into()),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        "IOMasterPort" => {
            let output = context.reg_read(REG_X0 + 1)?;
            context.mem_write(output, &1u32.to_le_bytes())?;
            context.reg_write(REG_X0, 0)?;
        }
        "IOServiceMatching" | "IOBSDNameMatching" => {
            let (key, argument) = if symbol == "IOServiceMatching" {
                ("IOProviderClass", REG_X0)
            } else {
                ("IOBSDName", REG_X0 + 2)
            };
            let value = guest_cstring(context, profile, state, context.reg_read(argument)?)?;
            let string = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            let dictionary = new_guest_object(
                context,
                profile,
                state,
                "NSDictionary",
                StoreValue::Entries(HashMap::from([(key.into(), string)])),
            )?;
            context.reg_write(REG_X0, dictionary)?;
        }
        "IOServiceGetMatchingService" => context.reg_write(REG_X0, 0)?,
        "IOServiceGetMatchingServices" => {
            let output = context.reg_read(REG_X0 + 2)?;
            context.mem_write(output, &1u32.to_le_bytes())?;
            context.reg_write(REG_X0, 0)?;
        }
        "IOIteratorNext" => context.reg_write(REG_X0, 1)?,
        "IORegistryEntryGetParentEntry" => {
            let output = context.reg_read(REG_X0 + 2)?;
            context.mem_write(output, &2u32.to_le_bytes())?;
            context.reg_write(REG_X0, 0)?;
        }
        "IORegistryEntryCreateCFProperty" | "IORegistryEntrySearchCFProperty" => {
            let service = context.reg_read(REG_X0)?;
            if service == 0 {
                context.reg_write(REG_X0, 0)?;
            } else {
                let argument = if symbol == "IORegistryEntrySearchCFProperty" {
                    REG_X0 + 2
                } else {
                    REG_X0 + 1
                };
                let key_address = context.reg_read(argument)?;
                let StoreValue::String(key) = &state
                    .objects
                    .get(&key_address)
                    .context("unknown IOKit property name")?
                    .value
                else {
                    bail!("IOKit property name is not a string");
                };
                let value = match key.as_str() {
                    "IOBuiltin" | "IOPrimaryInterface" => StoreValue::Boolean(true),
                    "IOMACAddress" => StoreValue::Bytes(
                        state
                            .hardware_id
                            .context("Store hardware identity is missing")?
                            .to_vec(),
                    ),
                    _ => bail!("unsupported IOKit property {key}"),
                };
                let class = if matches!(value, StoreValue::Bytes(_)) {
                    "NSData"
                } else {
                    "NSNumber"
                };
                let object = new_guest_object(context, profile, state, class, value)?;
                context.reg_write(REG_X0, object)?;
            }
        }
        "IOObjectRelease" | "CFRelease" => context.reg_write(REG_X0, 0)?,
        "CFGetTypeID" => {
            let address = context.reg_read(REG_X0)?;
            let object = state
                .objects
                .get(&address)
                .context("CFGetTypeID of unknown object")?;
            let kind = match object.value {
                StoreValue::Boolean(_) => 4,
                StoreValue::Bytes(_) => 1,
                StoreValue::String(_) => 2,
                _ => 3,
            };
            context.reg_write(REG_X0, kind)?;
        }
        "CFBooleanGetTypeID" => context.reg_write(REG_X0, 4)?,
        "CFDataGetTypeID" => context.reg_write(REG_X0, 1)?,
        "CFStringGetTypeID" => context.reg_write(REG_X0, 2)?,
        "CFBooleanGetValue" => {
            let address = context.reg_read(REG_X0)?;
            let object = state
                .objects
                .get(&address)
                .context("unknown CFBoolean object")?;
            let StoreValue::Boolean(value) = object.value else {
                bail!("CFBooleanGetValue requires boolean object");
            };
            context.reg_write(REG_X0, u64::from(value))?;
        }
        "CFDataGetLength" => {
            let address = context.reg_read(REG_X0)?;
            let StoreValue::Bytes(value) = &state
                .objects
                .get(&address)
                .context("unknown CFData object")?
                .value
            else {
                bail!("CFDataGetLength requires byte data");
            };
            context.reg_write(REG_X0, value.len() as u64)?;
        }
        "CFDataGetBytePtr" => {
            let address = context.reg_read(REG_X0)?;
            let StoreValue::Bytes(value) = &state
                .objects
                .get(&address)
                .context("unknown CFData object")?
                .value
            else {
                bail!("CFDataGetBytePtr requires byte data");
            };
            let value = value.clone();
            let pointer = state.allocate(value.len() as u64)?;
            context.mem_write(pointer, &value)?;
            context.reg_write(REG_X0, pointer)?;
        }
        "CFDataGetBytes" => {
            let address = context.reg_read(REG_X0)?;
            let start = context.reg_read(REG_X0 + 1)? as usize;
            let length = context.reg_read(REG_X0 + 2)? as usize;
            let destination = context.reg_read(REG_X0 + 3)?;
            let StoreValue::Bytes(value) = &state
                .objects
                .get(&address)
                .context("unknown CFData object")?
                .value
            else {
                bail!("CFDataGetBytes requires byte data");
            };
            let end = start
                .checked_add(length)
                .context("CFData range overflows")?;
            context.mem_write(
                destination,
                value.get(start..end).context("CFData range exceeds data")?,
            )?;
            context.reg_write(REG_X0, 0)?;
        }
        "CFPreferencesAppSynchronize" | "CFPreferencesSynchronize" => {
            context.reg_write(REG_X0, 1)?;
        }
        "CFPreferencesGetAppBooleanValue" | "CFPreferencesGetAppIntegerValue" => {
            let key = object_string_value(state, context.reg_read(REG_X0)?)?;
            let app = object_string_value(state, context.reg_read(REG_X0 + 1)?)?;
            let object = state
                .preferences
                .get(&format!("{app}/{key}"))
                .and_then(|address| state.objects.get(address));
            let value = match object.map(|object| &object.value) {
                Some(StoreValue::Boolean(value)) => Some(i64::from(*value)),
                Some(StoreValue::Number(value)) => Some(*value),
                _ => None,
            };
            let output = context.reg_read(REG_X0 + 2)?;
            if output != 0 {
                context.mem_write(output, &[u8::from(value.is_some())])?;
            }
            context.reg_write(REG_X0, value.unwrap_or(0) as u64)?;
        }
        "CFPreferencesCopyAppValue" | "CFPreferencesCopyValue" => {
            let key = object_string_value(state, context.reg_read(REG_X0)?)?;
            let app = object_string_value(state, context.reg_read(REG_X0 + 1)?)?;
            let value = state
                .preferences
                .get(&format!("{app}/{key}"))
                .copied()
                .unwrap_or(0);
            context.reg_write(REG_X0, value)?;
        }
        "CFPreferencesSetAppValue" | "CFPreferencesSetValue" => {
            let key = object_string_value(state, context.reg_read(REG_X0)?)?.to_owned();
            let value = context.reg_read(REG_X0 + 1)?;
            let app = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
            state.preferences.insert(format!("{app}/{key}"), value);
            context.reg_write(REG_X0, 0)?;
        }
        "SecTaskCreateFromSelf" => {
            let task = new_guest_object(
                context,
                profile,
                state,
                "HostSecurityTask",
                StoreValue::Empty,
            )?;
            context.reg_write(REG_X0, task)?;
        }
        "SecTaskCopyValueForEntitlement" => {
            let error = context.reg_read(REG_X0 + 2)?;
            if error != 0 {
                write_guest_u64(context, error, 0)?;
            }
            context.reg_write(REG_X0, 0)?;
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
        "dispatch_queue_attr_make_with_autorelease_frequency"
        | "dispatch_queue_attr_make_with_qos_class"
        | "dispatch_retain"
        | "dispatch_release" => {}
        "dispatch_sync" | "dispatch_sync_f" => {
            let previous = std::mem::replace(&mut state.current_queue, context.reg_read(REG_X0)?);
            let (function, arguments) = if symbol == "dispatch_sync" {
                let block = context.reg_read(REG_X0 + 1)?;
                (read_guest_u64(context, block + 16)?, vec![block])
            } else {
                (
                    context.reg_read(REG_X0 + 2)?,
                    vec![context.reg_read(REG_X0 + 1)?],
                )
            };
            begin_callback(
                context,
                state,
                function,
                &arguments,
                CallbackAction::RestoreQueue { previous },
            )?;
        }
        "dispatch_async" => {
            let queue = context.reg_read(REG_X0)?;
            let block = context.reg_read(REG_X0 + 1)?;
            if block == 0 {
                bail!("cannot dispatch null block");
            }
            let flags = read_guest_u64(context, block + 8)? as u32;
            let copied = if flags & (1 << 28) != 0 {
                block
            } else {
                let descriptor = read_guest_u64(context, block + 24)?;
                let size = read_guest_u64(context, descriptor + 8)?;
                if !(32..=1_048_576).contains(&size) {
                    bail!("invalid guest block size {size}");
                }
                let copied = state.allocate(size)?;
                context.mem_write(copied, &context.mem_read(block, size as usize)?)?;
                if flags & (1 << 25) != 0 {
                    begin_callback(
                        context,
                        state,
                        read_guest_u64(context, descriptor + 16)?,
                        &[copied, block],
                        CallbackAction::QueueBlock {
                            block: copied,
                            queue,
                        },
                    )?;
                    return Ok(());
                }
                copied
            };
            state.pending.push((copied, queue));
            context.reg_write(REG_X0, 0)?;
        }
        "dispatch_set_target_queue" => {
            let queue = context.reg_read(REG_X0)?;
            let target = context.reg_read(REG_X0 + 1)?;
            state
                .objects
                .get_mut(&queue)
                .context("unknown dispatch queue")?
                .properties
                .insert("targetQueue".into(), target);
        }
        "dispatch_queue_create"
        | "dispatch_get_global_queue"
        | "dispatch_get_main_queue"
        | "dispatch_queue_create_with_target" => {
            if symbol == "dispatch_get_main_queue"
                && let Some(queue) = state.main_queue
            {
                context.reg_write(REG_X0, queue)?;
                return Ok(());
            }
            let queue = new_guest_object(context, profile, state, "HostQueue", StoreValue::Empty)?;
            if symbol == "dispatch_get_main_queue" {
                state.main_queue = Some(queue);
            }
            if symbol == "dispatch_queue_create_with_target" {
                let target = context.reg_read(REG_X0 + 2)?;
                state
                    .objects
                    .get_mut(&queue)
                    .expect("new queue")
                    .properties
                    .insert("targetQueue".into(), target);
            }
            context.reg_write(REG_X0, queue)?;
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
            let enabled = match profile.index.features.get(&key) {
                Some(value) => *value,
                None if key == "AppleMediaServices/BetaLocalAccount" => false,
                None => bail!("unresolved native feature flag {key}"),
            };
            context.reg_write(REG_X0, u64::from(enabled))?;
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
        "$s8Dispatch0A3QoSV11unspecifiedACvgZ" => {
            let output = context.reg_read(REG_X0 + 8)?;
            write_guest_u64(context, output, 5)?;
            write_guest_u64(context, output + 8, 0)?;
        }
        "$sSo17OS_dispatch_queueC8DispatchE4mainABvgZ" => {
            let queue = match state.main_queue {
                Some(queue) => queue,
                None => {
                    let queue =
                        new_guest_object(context, profile, state, "HostQueue", StoreValue::Empty)?;
                    state.main_queue = Some(queue);
                    queue
                }
            };
            context.reg_write(REG_X0, queue)?;
        }
        "$sSo18OS_dispatch_sourceC8DispatchE16makeSignalSource6signal5queueSo0a1_b1_c1_H0_ps5Int32V_So0a1_b1_I0CSgtFZ" =>
        {
            let signal = context.reg_read(REG_X0)?;
            let queue = context.reg_read(REG_X0 + 1)?;
            let source = new_guest_object(
                context,
                profile,
                state,
                "HostDispatchSource",
                StoreValue::Number(signal as i64),
            )?;
            let properties = &mut state
                .objects
                .get_mut(&source)
                .expect("new dispatch source")
                .properties;
            properties.insert("queue".into(), queue);
            properties.insert("suspendCount".into(), 1);
            context.reg_write(REG_X0, source)?;
        }
        "$sSo18OS_dispatch_sourceP8DispatchE15setEventHandler3qos5flags7handleryAC0D3QoSV_AC0D13WorkItemFlagsVyyXBSgtF" =>
        {
            let source = context.reg_read(REG_X0 + 20)?;
            let handler = context.reg_read(REG_X0 + 2)?;
            let object = state
                .objects
                .get_mut(&source)
                .context("unknown Swift dispatch source")?;
            if object.class != "HostDispatchSource" {
                bail!("setEventHandler receiver is not a dispatch source");
            }
            object.properties.insert("eventHandler".into(), handler);
            context.reg_write(REG_X0, 0)?;
        }
        "$sSo18OS_dispatch_sourceP8DispatchE8activateyyF" => {
            let source = context.reg_read(REG_X0 + 20)?;
            let object = state
                .objects
                .get_mut(&source)
                .context("unknown Swift dispatch source")?;
            if object.class != "HostDispatchSource" {
                bail!("activate receiver is not a dispatch source");
            }
            object.properties.insert("suspendCount".into(), 0);
            context.reg_write(REG_X0, 0)?;
        }
        "$sSo13os_log_type_ta0A0E5errorABvgZ" => context.reg_write(REG_X0, 16)?,
        "$sSo13os_log_type_ta0A0E5faultABvgZ" => context.reg_write(REG_X0, 17)?,
        "$sSo13os_log_type_ta0A0E4infoABvgZ" => context.reg_write(REG_X0, 1)?,
        "$sSo13os_log_type_ta0A0E5debugABvgZ" => context.reg_write(REG_X0, 2)?,
        "$sSo13os_log_type_ta0A0E7defaultABvgZ" => context.reg_write(REG_X0, 0)?,
        "$s2os12OSSignpostIDVwst" => {
            let destination = context.reg_read(REG_X0)?;
            let tag = context.reg_read(REG_X0 + 1)?;
            let cases = context.reg_read(REG_X0 + 2)?;
            if cases != 1 || tag > 1 {
                bail!("unsupported signpost ID optional tag");
            }
            if tag == 1 {
                write_guest_u64(context, destination, 0)?;
            }
        }
        "$s2os12OSSignposterV9logHandleACSo03OS_a1_C0C_tcfC" => {
            let output = context.reg_read(REG_X0 + 8)?;
            let metadata = *profile
                .index
                .swift_accessors
                .get("$s2os12OSSignposterVMa")
                .context("missing OS signposter metadata")?;
            let witnesses = read_guest_u64(context, metadata - 8)?;
            let size = read_guest_u64(context, witnesses + 64)?;
            if size != 8 {
                bail!("unsupported OS signposter layout: {size} bytes");
            }
            write_guest_u64(context, output, context.reg_read(REG_X0)?)?;
        }
        "$s2os12OSSignposterV9isEnabledSbvg" => context.reg_write(REG_X0, 0)?,
        "$sSo17OS_dispatch_queueC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0D3QoSVAbCE10AttributesVAbCE011AutoreleaseI0OABSgtcfC"
        | "$sSo24OS_dispatch_queue_serialC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0E3QoSVAbCE10AttributesVSo0a1_b1_C0CACE011AutoreleaseJ0OANSgtcfC" =>
        {
            let label = swift_string(
                context,
                state,
                context.reg_read(REG_X0)?,
                context.reg_read(REG_X0 + 1)?,
            )?;
            let target = context.reg_read(REG_X0 + 5)?;
            let queue = new_guest_object(
                context,
                profile,
                state,
                "HostQueue",
                StoreValue::String(label),
            )?;
            state
                .objects
                .get_mut(&queue)
                .expect("new queue")
                .properties
                .insert("targetQueue".into(), target);
            context.reg_write(REG_X0, queue)?;
        }
        "$ss10SetAlgebraPyxqd__ncSTRd__7ElementQyd__ACRtzlufCTj" => {
            let metadata = context.reg_read(REG_X0 + 3)?;
            let accepted = [
                "$sSo24OS_dispatch_queue_serialC8DispatchE10AttributesVMa",
                "$sSo17OS_dispatch_queueC8DispatchE10AttributesVMa",
                "$s8Dispatch0A13WorkItemFlagsVMa",
            ]
            .iter()
            .any(|name| profile.index.swift_accessors.get(*name) == Some(&metadata));
            let source = context.reg_read(REG_X0)?;
            if !accepted || read_guest_u64(context, read_guest_u64(context, source)? + 16)? != 0 {
                bail!("unsupported Swift SetAlgebra initializer");
            }
            write_guest_u64(context, context.reg_read(REG_X0 + 8)?, 0)?;
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
        "$sSS6appendyySSF" => {
            let destination = context.reg_read(REG_X0 + 20)?;
            let left = swift_string(
                context,
                state,
                read_guest_u64(context, destination)?,
                read_guest_u64(context, destination + 8)?,
            )?;
            let right = swift_string(
                context,
                state,
                context.reg_read(REG_X0)?,
                context.reg_read(REG_X0 + 1)?,
            )?;
            return_swift_string(context, state, &(left + &right))?;
            write_guest_u64(context, destination, context.reg_read(REG_X0)?)?;
            write_guest_u64(context, destination + 8, context.reg_read(REG_X0 + 1)?)?;
        }
        "$sSS11utf8CStrings15ContiguousArrayVys4Int8VGvg" => {
            let value = swift_string(
                context,
                state,
                context.reg_read(REG_X0)?,
                context.reg_read(REG_X0 + 1)?,
            )?;
            if value.len() > 1_048_576 {
                bail!("Swift UTF-8 C string exceeds runtime limit");
            }
            let empty = *profile
                .index
                .symbols
                .get("_swiftEmptyArrayStorage")
                .context("missing Swift empty array storage")?;
            let metadata = read_guest_u64(context, empty)?;
            let count = value.len() as u64 + 1;
            let storage = state.allocate(32 + count)?;
            write_guest_u64(context, storage, metadata)?;
            write_guest_u64(context, storage + 8, 3)?;
            write_guest_u64(context, storage + 16, count)?;
            write_guest_u64(context, storage + 24, count * 2)?;
            context.mem_write(storage + 32, value.as_bytes())?;
            context.mem_write(storage + 32 + value.len() as u64, &[0])?;
            context.reg_write(REG_X0, storage)?;
        }
        "$sSKsSS7ElementRtzrlE6joined9separatorS2S_tF" => {
            let separator = swift_string(
                context,
                state,
                context.reg_read(REG_X0)?,
                context.reg_read(REG_X0 + 1)?,
            )?;
            let sequence = context.reg_read(REG_X0 + 20)?;
            let storage = read_guest_u64(context, sequence)?;
            let count = read_guest_u64(context, storage + 16)?;
            if count > 65_536 {
                bail!("Swift joined sequence exceeds item limit");
            }
            let mut values = Vec::with_capacity(count as usize);
            for index in 0..count {
                let element = storage + 32 + index * 16;
                values.push(swift_string(
                    context,
                    state,
                    read_guest_u64(context, element)?,
                    read_guest_u64(context, element + 8)?,
                )?);
            }
            return_swift_string(context, state, &values.join(&separator))?;
        }
        "$ss17CodingUserInfoKeyVwCP" | "$sSSwCP" | "$sSSwcp" | "$sSSwca" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            context.mem_write(destination, &context.mem_read(source, 16)?)?;
            context.reg_write(REG_X0, destination)?;
        }
        "$sSqwta"
        | "$sSqwca"
        | "$sSqwcp"
        | "$sSqwtk"
        | "swift_cvw_initWithCopy"
        | "swift_cvw_assignWithCopy"
        | "swift_cvw_initWithTake"
        | "swift_cvw_assignWithTake" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            let metadata = context.reg_read(REG_X0 + 2)?;
            let witnesses = read_guest_u64(context, metadata - 8)?;
            let size = read_guest_u64(context, witnesses + 64)?;
            if size > 1024 {
                bail!("Swift value copy exceeds budget");
            }
            context.mem_write(destination, &context.mem_read(source, size as usize)?)?;
            context.reg_write(REG_X0, destination)?;
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
        _ => {
            if (symbol.starts_with("$sSo17OS_dispatch_queueC8DispatchE")
                || symbol.starts_with("$s10Foundation3URLV13DirectoryHintO"))
                && symbol.ends_with("Owui")
            {
                let metadata = context.reg_read(REG_X0 + 2)?;
                let witnesses = read_guest_u64(context, metadata - 8)?;
                if read_guest_u64(context, witnesses + 64)? != 1 {
                    bail!("unexpected Swift enum size");
                }
                let value = context.reg_read(REG_X0 + 1)? as u8;
                context.mem_write(context.reg_read(REG_X0)?, &[value])?;
            } else if symbol.contains("SwiftRetainableBox")
                && symbol.contains("initializeBufferWithCopyOfBuffer")
            {
                let destination = context.reg_read(REG_X0)?;
                let source = context.reg_read(REG_X0 + 1)?;
                write_guest_u64(context, destination, read_guest_u64(context, source)?)?;
                context.reg_write(REG_X0, destination)?;
            } else if symbol.contains("SwiftRetainableBox") && symbol.contains("7destroy") {
            } else if let Some(&value) = profile.index.swift_globals.get(symbol) {
                context.reg_write(REG_X0, value)?;
            } else if let Some(&value) = profile.index.swift_accessors.get(symbol) {
                context.reg_write(REG_X0, value)?;
                context.reg_write(REG_X0 + 1, 0)?;
            } else {
                bail!(
                    "unsupported Store bridge call: {} {}",
                    call.symbol,
                    call.selector
                );
            }
        }
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

fn resume_callback(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    resume: CallbackResume,
) -> Result<()> {
    match resume.action {
        CallbackAction::ReturnZero => context.reg_write(REG_X0, 0)?,
        CallbackAction::ReturnValue { value } => context.reg_write(REG_X0, value)?,
        CallbackAction::QueueBlock { block, queue } => {
            state.pending.push((block, queue));
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::StoreAt { destination, value } => {
            write_guest_u64(context, destination, value)?;
        }
        CallbackAction::StoreProperty {
            receiver,
            key,
            value,
        } => {
            state
                .objects
                .get_mut(&receiver)
                .context("missing block owner")?
                .properties
                .insert(key, value);
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::ReturnUnavailableProxy { error_block } => {
            let proxy = state.allocate(256)?;
            state.objects.insert(
                proxy,
                StoreObject {
                    class: "HostUnavailableProxy".into(),
                    value: StoreValue::Empty,
                    properties: HashMap::from([("errorBlock".into(), error_block)]),
                },
            );
            context.reg_write(REG_X0, proxy)?;
        }
        CallbackAction::EnumerateEntries {
            block,
            entries,
            index,
            stop,
        } => {
            if index < entries.len() && read_guest_u64(context, stop)? == 0 {
                let (name, value) = &entries[index];
                let key = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(name.clone()),
                )?;
                context.reg_write(REG_LR, resume.link)?;
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, block + 16)?,
                    &[block, key, *value, stop],
                    CallbackAction::EnumerateEntries {
                        block,
                        entries,
                        index: index + 1,
                        stop,
                    },
                )?;
                return Ok(());
            }
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::ArrayCopy {
            destination,
            source,
            metadata,
            stride,
            count,
            index,
            function,
            reverse,
        } => {
            if index < count {
                let element = if reverse { count - index - 1 } else { index };
                context.reg_write(REG_LR, resume.link)?;
                begin_callback(
                    context,
                    state,
                    function,
                    &[
                        destination + element * stride,
                        source + element * stride,
                        metadata,
                    ],
                    CallbackAction::ArrayCopy {
                        destination,
                        source,
                        metadata,
                        stride,
                        count,
                        index: index + 1,
                        function,
                        reverse,
                    },
                )?;
                return Ok(());
            }
            context.reg_write(REG_X0, destination)?;
        }
        CallbackAction::RestoreQueue { previous } => {
            state.current_queue = previous;
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::RestoreQueueWithValue { previous, value } => {
            state.current_queue = previous;
            context.reg_write(REG_X0, value)?;
        }
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

fn object_string_value(state: &StoreState, address: u64) -> Result<&str> {
    if address == 0 {
        return Ok("");
    }
    let object = state
        .objects
        .get(&address)
        .context("unknown Store string object")?;
    let StoreValue::String(value) = &object.value else {
        bail!("Store object is not a string");
    };
    Ok(value)
}

fn guest_format(
    context: &HookContext,
    profile: &ProfileData,
    state: &StoreState,
    format: &str,
    stack_pointer: u64,
) -> Result<String> {
    let mut output = Vec::new();
    let bytes = format.as_bytes();
    let mut index = 0;
    let mut offset = 0u64;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        if index >= bytes.len() {
            bail!("incomplete Store format");
        }
        if bytes[index] == b'%' {
            output.push(b'%');
            index += 1;
            continue;
        }
        let width_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let width_text = std::str::from_utf8(&bytes[width_start..index])?;
        let width = if width_text.is_empty() {
            0
        } else {
            width_text.parse::<usize>()?
        };
        if width > 1024 {
            bail!("Store format width exceeds limit");
        }
        while index < bytes.len() && matches!(bytes[index], b'l' | b'z') {
            index += 1;
        }
        let Some(&specifier) = bytes.get(index) else {
            bail!("invalid Store format");
        };
        index += 1;
        let value = read_guest_u64(context, stack_pointer + offset)?;
        offset += 8;
        let rendered = match specifier {
            b'@' => {
                if value == 0 {
                    "(null)".to_owned()
                } else {
                    let object = state.objects.get(&value).context("unknown format object")?;
                    match &object.value {
                        StoreValue::String(value) => value.clone(),
                        StoreValue::Number(value) => value.to_string(),
                        StoreValue::Float(value) => value.to_string(),
                        StoreValue::Boolean(value) => value.to_string(),
                        _ => bail!("unsupported formatted Store object"),
                    }
                }
            }
            b'd' | b'i' => (value as i64).to_string(),
            b'u' => value.to_string(),
            b'x' => {
                if width_text.starts_with('0') {
                    format!("{value:0width$x}")
                } else {
                    format!("{value:width$x}")
                }
            }
            b'X' => {
                if width_text.starts_with('0') {
                    format!("{value:0width$X}")
                } else {
                    format!("{value:width$X}")
                }
            }
            b'p' => format!("0x{value:x}"),
            b's' => guest_cstring(context, profile, state, value)?,
            _ => bail!("unsupported Store format specifier {}", specifier as char),
        };
        output.extend_from_slice(rendered.as_bytes());
    }
    String::from_utf8(output).context("formatted Store string is not UTF-8")
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
        if !state.objects.contains_key(&receiver) && selector == "copy" {
            let flags = read_guest_u64(context, receiver + 8)? as u32;
            if flags & (1 << 28) != 0 {
                return Ok(());
            }
            let descriptor = read_guest_u64(context, receiver + 24)?;
            let size = read_guest_u64(context, descriptor + 8)?;
            if !(32..=1_048_576).contains(&size) {
                bail!("invalid guest block size {size}");
            }
            let copied = state.allocate(size)?;
            context.mem_write(copied, &context.mem_read(receiver, size as usize)?)?;
            if flags & (1 << 25) != 0 {
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, descriptor + 16)?,
                    &[copied, receiver],
                    CallbackAction::ReturnValue { value: copied },
                )?;
            } else {
                context.reg_write(REG_X0, copied)?;
            }
            return Ok(());
        }
        state
            .objects
            .get(&receiver)
            .with_context(|| format!("unknown Store receiver {receiver:#x} for {selector}"))?
            .class
            .clone()
    };
    if class_name == "HostUnavailableProxy" {
        let error_block = state.objects[&receiver]
            .properties
            .get("errorBlock")
            .copied()
            .unwrap_or(0);
        if error_block == 0 {
            bail!("unavailable XPC proxy has no error callback");
        }
        let domain = new_guest_object(
            context,
            profile,
            state,
            "NSString",
            StoreValue::String("NSCocoaErrorDomain".into()),
        )?;
        let code = new_guest_object(
            context,
            profile,
            state,
            "NSNumber",
            StoreValue::Number(4099),
        )?;
        let user_info = new_guest_object(
            context,
            profile,
            state,
            "NSDictionary",
            StoreValue::Entries(HashMap::new()),
        )?;
        let error = new_guest_object(
            context,
            profile,
            state,
            "NSError",
            StoreValue::Entries(HashMap::from([
                ("domain".into(), domain),
                ("code".into(), code),
                ("userInfo".into(), user_info),
            ])),
        )?;
        begin_callback(
            context,
            state,
            read_guest_u64(context, error_block + 16)?,
            &[error_block, error],
            CallbackAction::ReturnZero,
        )?;
        return Ok(());
    }
    if !skip_lookup
        && let Some(entry) = method_address(profile, &class_name, selector, class_method)
    {
        context.reg_write(REG_X0 + 1, selector_address)?;
        context.reg_write(REG_PC, entry)?;
        return Ok(());
    }
    if !class_method && matches!(class_name.as_str(), "ACAccountStore" | "ACDAccountStore") {
        if selector == "accountTypeWithIdentifier:completion:" {
            let identifier = context.reg_read(REG_X0 + 2)?;
            let completion = context.reg_read(REG_X0 + 3)?;
            let account_type =
                new_guest_object(context, profile, state, "ACAccountType", StoreValue::Empty)?;
            state
                .objects
                .get_mut(&account_type)
                .expect("new account type")
                .properties
                .insert("identifier".into(), identifier);
            begin_callback(
                context,
                state,
                read_guest_u64(context, completion + 16)?,
                &[completion, account_type, 0],
                CallbackAction::ReturnZero,
            )?;
            return Ok(());
        }
        if selector == "accountsWithAccountType:options:completion:" {
            let completion = context.reg_read(REG_X0 + 4)?;
            let accounts = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(Vec::new()),
            )?;
            begin_callback(
                context,
                state,
                read_guest_u64(context, completion + 16)?,
                &[completion, accounts, 0],
                CallbackAction::ReturnZero,
            )?;
            return Ok(());
        }
    }
    if !class_method && class_name == "RBSProcessHandle" && selector == "isManaged" {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method && class_name == "NSCharacterSet" && selector == "invertedSet" {
        let StoreValue::String(characters) = &state.objects[&receiver].value else {
            bail!("invalid Store character set")
        };
        let characters = characters.clone();
        let inverted = state.objects[&receiver]
            .properties
            .get("inverted")
            .copied()
            .unwrap_or(0)
            == 0;
        let set = new_guest_object(
            context,
            profile,
            state,
            "NSCharacterSet",
            StoreValue::String(characters),
        )?;
        state
            .objects
            .get_mut(&set)
            .expect("new character set")
            .properties
            .insert("inverted".into(), u64::from(inverted));
        context.reg_write(REG_X0, set)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSURL"
        && matches!(
            selector,
            "host" | "scheme" | "query" | "fragment" | "isFileURL"
        )
    {
        let url = url::Url::parse(object_string_value(state, receiver)?)?;
        if selector == "isFileURL" {
            context.reg_write(REG_X0, u64::from(url.scheme() == "file"))?;
        } else {
            let text = match selector {
                "host" => url.host_str().unwrap_or(""),
                "scheme" => url.scheme(),
                "query" => url.query().unwrap_or(""),
                _ => url.fragment().unwrap_or(""),
            };
            let value = if selector == "fragment" && text.is_empty() {
                0
            } else {
                new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(text.into()),
                )?
            };
            context.reg_write(REG_X0, value)?;
        }
        return Ok(());
    }
    if !class_method
        && matches!(
            selector,
            "rangeOfCharacterFromSet:" | "rangeOfCharacterFromSet:options:"
        )
    {
        let value = object_string_value(state, receiver)?;
        let set = state
            .objects
            .get(&context.reg_read(REG_X0 + 2)?)
            .context("unknown Store character set")?;
        let StoreValue::String(characters) = &set.value else {
            bail!("invalid Store character set")
        };
        let inverted = set.properties.get("inverted").copied().unwrap_or(0) != 0;
        let options = if selector.ends_with("options:") {
            context.reg_read(REG_X0 + 3)?
        } else {
            0
        };
        let mut start = i64::MAX as u64;
        let mut length = 0;
        let mut offset = 0;
        for character in value.chars() {
            let width = character.len_utf16() as u64;
            let matches = if characters == "0123456789" {
                character.is_numeric()
            } else {
                characters.contains(character)
            };
            if matches != inverted {
                start = offset;
                length = width;
                if options & 4 == 0 {
                    break;
                }
            }
            offset += width;
        }
        context.reg_write(REG_X0, start)?;
        context.reg_write(REG_X0 + 1, length)?;
        return Ok(());
    }
    if !class_method && class_name == "NSProcessInfo" && selector == "operatingSystemVersion" {
        let output = context.reg_read(REG_X0 + 8)?;
        for (index, value) in [27u64, 0, 1].into_iter().enumerate() {
            write_guest_u64(context, output + index as u64 * 8, value)?;
        }
        return Ok(());
    }
    if !class_method
        && class_name == "NSURLComponents"
        && selector == "initWithURL:resolvingAgainstBaseURL:"
    {
        let url = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
        url::Url::parse(&url).context("invalid Store URL components source")?;
        state
            .objects
            .get_mut(&receiver)
            .expect("known URL components")
            .value = StoreValue::String(url);
        context.reg_write(REG_X0, receiver)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSURLComponents"
        && matches!(selector, "queryItems" | "percentEncodedQueryItems")
    {
        let raw = object_string_value(state, receiver)?.to_owned();
        let url = url::Url::parse(&raw)?;
        let mut items = Vec::new();
        if let Some(query) = url.query().filter(|query| !query.is_empty()) {
            for part in query.split('&') {
                let (name, value) = part
                    .split_once('=')
                    .map_or((part, None), |(name, value)| (name, Some(value)));
                let decode = |input: &str| -> String {
                    if selector == "percentEncodedQueryItems" {
                        return input.to_owned();
                    }
                    let protected = input.replace('+', "%2B");
                    url::form_urlencoded::parse(format!("{protected}=").as_bytes())
                        .next()
                        .map(|(value, _)| value.into_owned())
                        .unwrap_or_default()
                };
                let name = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(decode(name)),
                )?;
                let value = value
                    .map(|value| {
                        new_guest_object(
                            context,
                            profile,
                            state,
                            "NSString",
                            StoreValue::String(decode(value)),
                        )
                    })
                    .transpose()?
                    .unwrap_or(0);
                let item =
                    new_guest_object(context, profile, state, "NSURLQueryItem", StoreValue::Empty)?;
                let properties = &mut state
                    .objects
                    .get_mut(&item)
                    .expect("new query item")
                    .properties;
                properties.insert("name".into(), name);
                properties.insert("value".into(), value);
                items.push(item);
            }
        }
        let array = new_guest_object(
            context,
            profile,
            state,
            "NSArray",
            StoreValue::Addresses(items),
        )?;
        context.reg_write(REG_X0, array)?;
        return Ok(());
    }
    if !class_method && class_name == "NSBundle" && selector == "objectForInfoDictionaryKey:" {
        let key = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
        let info = state.objects[&receiver]
            .properties
            .get("infoDictionary")
            .copied()
            .unwrap_or(0);
        let value = if let Some(StoreObject {
            value: StoreValue::Entries(entries),
            ..
        }) = state.objects.get(&info)
        {
            entries.get(&key).copied().unwrap_or(0)
        } else {
            let text = match key.as_str() {
                "CFBundleIdentifier" => Some("me.majd.ipatool"),
                "CFBundleVersion" => Some("1.0"),
                "CFBundleExecutable" | "CFBundleName" => Some("ipatool"),
                _ => None,
            };
            if let Some(text) = text {
                new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(text.into()),
                )?
            } else {
                0
            }
        };
        context.reg_write(REG_X0, value)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSXPCConnection"
        && selector == "initWithMachServiceName:options:"
    {
        let service = context.reg_read(REG_X0 + 2)?;
        state
            .objects
            .get_mut(&receiver)
            .expect("known connection")
            .properties
            .insert("serviceName".into(), service);
        context.reg_write(REG_X0, receiver)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSXPCConnection"
        && matches!(selector, "_setQueue:" | "setRemoteObjectInterface:")
    {
        let key = if selector == "_setQueue:" {
            "queue"
        } else {
            "interface"
        };
        let value = context.reg_read(REG_X0 + 2)?;
        state
            .objects
            .get_mut(&receiver)
            .expect("known connection")
            .properties
            .insert(key.into(), value);
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSXPCConnection"
        && matches!(
            selector,
            "setInterruptionHandler:" | "setInvalidationHandler:"
        )
    {
        let block = context.reg_read(REG_X0 + 2)?;
        let copied = if block == 0 || (read_guest_u64(context, block + 8)? as u32) & (1 << 28) != 0
        {
            block
        } else {
            let flags = read_guest_u64(context, block + 8)? as u32;
            let descriptor = read_guest_u64(context, block + 24)?;
            let size = read_guest_u64(context, descriptor + 8)?;
            if !(32..=1_048_576).contains(&size) {
                bail!("invalid XPC handler block size {size}");
            }
            let copied = state.allocate(size)?;
            context.mem_write(copied, &context.mem_read(block, size as usize)?)?;
            if flags & (1 << 25) != 0 {
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, descriptor + 16)?,
                    &[copied, block],
                    CallbackAction::StoreProperty {
                        receiver,
                        key: selector.into(),
                        value: copied,
                    },
                )?;
                return Ok(());
            }
            copied
        };
        state
            .objects
            .get_mut(&receiver)
            .expect("known connection")
            .properties
            .insert(selector.into(), copied);
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSXPCConnection"
        && selector == "remoteObjectProxyWithErrorHandler:"
    {
        let block = context.reg_read(REG_X0 + 2)?;
        let copied = if block == 0 || (read_guest_u64(context, block + 8)? as u32) & (1 << 28) != 0
        {
            block
        } else {
            let flags = read_guest_u64(context, block + 8)? as u32;
            let descriptor = read_guest_u64(context, block + 24)?;
            let size = read_guest_u64(context, descriptor + 8)?;
            if !(32..=1_048_576).contains(&size) {
                bail!("invalid XPC error block size {size}");
            }
            let copied = state.allocate(size)?;
            context.mem_write(copied, &context.mem_read(block, size as usize)?)?;
            if flags & (1 << 25) != 0 {
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, descriptor + 16)?,
                    &[copied, block],
                    CallbackAction::ReturnUnavailableProxy {
                        error_block: copied,
                    },
                )?;
                return Ok(());
            }
            copied
        };
        let proxy = new_guest_object(
            context,
            profile,
            state,
            "HostUnavailableProxy",
            StoreValue::Empty,
        )?;
        state
            .objects
            .get_mut(&proxy)
            .expect("new unavailable proxy")
            .properties
            .insert("errorBlock".into(), copied);
        context.reg_write(REG_X0, proxy)?;
        return Ok(());
    }
    if !class_method
        && matches!(class_name.as_str(), "NSXPCConnection" | "NSXPCInterface")
        && matches!(
            selector,
            "resume"
                | "invalidate"
                | "setClass:forSelector:argumentIndex:ofReply:"
                | "setClasses:forSelector:argumentIndex:ofReply:"
                | "setInterface:forSelector:argumentIndex:ofReply:"
        )
    {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method && class_is_kind_of(profile, &class_name, "NSError") {
        let StoreValue::Entries(fields) = &state.objects[&receiver].value else {
            bail!("invalid Store error object");
        };
        if matches!(selector, "domain" | "userInfo" | "code") {
            let mut value = fields.get(selector).copied().unwrap_or(0);
            if selector == "code" {
                let StoreValue::Number(code) = state
                    .objects
                    .get(&value)
                    .context("missing Store error code")?
                    .value
                else {
                    bail!("invalid Store error code");
                };
                value = code as u64;
            }
            context.reg_write(REG_X0, value)?;
            return Ok(());
        }
    }
    if !class_method && class_name == "NSIndexSet" {
        match selector {
            "initWithIndexesInRange:" => {
                let object = state.objects.get_mut(&receiver).expect("known index set");
                object
                    .properties
                    .insert("rangeStart".into(), context.reg_read(REG_X0 + 2)?);
                object
                    .properties
                    .insert("rangeLength".into(), context.reg_read(REG_X0 + 3)?);
                context.reg_write(REG_X0, receiver)?;
                return Ok(());
            }
            "containsIndex:" => {
                let object = &state.objects[&receiver];
                let start = object.properties.get("rangeStart").copied().unwrap_or(0);
                let length = object.properties.get("rangeLength").copied().unwrap_or(0);
                let index = context.reg_read(REG_X0 + 2)?;
                context.reg_write(REG_X0, u64::from(index >= start && index - start < length))?;
                return Ok(());
            }
            _ => {}
        }
    }
    if !class_method
        && matches!(
            class_name.as_str(),
            "NSCondition" | "NSLock" | "NSRecursiveLock"
        )
    {
        match selector {
            "lock" | "unlock" | "signal" | "broadcast" => {
                context.reg_write(REG_X0, 0)?;
                return Ok(());
            }
            "wait" | "waitUntilDate:" if class_name == "NSCondition" => {
                if state.pending.is_empty() {
                    bail!("guest condition has no runnable callback");
                }
                let (block, queue) = state.pending.remove(0);
                let previous = std::mem::replace(&mut state.current_queue, queue);
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, block + 16)?,
                    &[block],
                    CallbackAction::RestoreQueueWithValue { previous, value: 1 },
                )?;
                return Ok(());
            }
            _ => {}
        }
    }
    if !class_method && class_is_kind_of(profile, &class_name, "NSURLRequest") {
        if selector == "valueForHTTPHeaderField:" {
            let key = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
            let headers = state.objects[&receiver]
                .properties
                .get("allHTTPHeaderFields")
                .copied()
                .unwrap_or(0);
            let value = state
                .objects
                .get(&headers)
                .and_then(|object| match &object.value {
                    StoreValue::Entries(entries) => entries
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(&key))
                        .map(|(_, &value)| value),
                    _ => None,
                })
                .unwrap_or(0);
            context.reg_write(REG_X0, value)?;
            return Ok(());
        }
        if matches!(
            selector,
            "setValue:forHTTPHeaderField:" | "addValue:forHTTPHeaderField:"
        ) {
            let value = context.reg_read(REG_X0 + 2)?;
            let key = object_string_value(state, context.reg_read(REG_X0 + 3)?)?.to_owned();
            let headers = state.objects[&receiver]
                .properties
                .get("allHTTPHeaderFields")
                .copied()
                .unwrap_or(0);
            let dictionary = state
                .objects
                .get_mut(&headers)
                .context("request has no header dictionary")?;
            let StoreValue::Entries(entries) = &mut dictionary.value else {
                bail!("invalid request header dictionary")
            };
            let existing = entries
                .keys()
                .find(|name| name.eq_ignore_ascii_case(&key))
                .cloned();
            if let Some(existing) = existing {
                entries.remove(&existing);
            }
            if value != 0 {
                entries.insert(key, value);
            }
            context.reg_write(REG_X0, 0)?;
            return Ok(());
        }
        if selector == "_CFURLRequest" {
            context.reg_write(REG_X0, receiver)?;
            return Ok(());
        }
        if selector == "_initWithCFURLRequest:" {
            let source = context.reg_read(REG_X0 + 2)?;
            let properties = state
                .objects
                .get(&source)
                .context("unknown source URL request")?
                .properties
                .clone();
            state
                .objects
                .get_mut(&receiver)
                .expect("known request")
                .properties = properties;
            context.reg_write(REG_X0, receiver)?;
            return Ok(());
        }
    }
    if !class_method
        && (class_is_kind_of(profile, &class_name, "ACAccount")
            || matches!(class_name.as_str(), "ACAccountType" | "ACAccountCredential"))
    {
        if let Some(key) = setter_property_key(selector) {
            let value = context.reg_read(REG_X0 + 2)?;
            state
                .objects
                .get_mut(&receiver)
                .expect("known account")
                .properties
                .insert(key, value);
            context.reg_write(REG_X0, 0)?;
            return Ok(());
        }
        if matches!(
            selector,
            "accountType"
                | "identifier"
                | "username"
                | "credential"
                | "accountProperties"
                | "authenticated"
                | "active"
                | "owningBundleID"
                | "accountDescription"
                | "parentAccount"
                | "isDirty"
        ) {
            let value = state.objects[&receiver]
                .properties
                .get(selector)
                .copied()
                .unwrap_or(0);
            context.reg_write(REG_X0, value)?;
            return Ok(());
        }
    }
    if !class_method
        && (matches!(
            class_name.as_str(),
            "NSURLSessionConfiguration"
                | "NSOperationQueue"
                | "NSCache"
                | "NSURLSession"
                | "NSURLSessionDataTask"
                | "NSHTTPURLResponse"
                | "NSURLResponse"
        ) || class_is_kind_of(profile, &class_name, "NSURLRequest"))
    {
        if let Some(key) = setter_property_key(selector) {
            let value = context.reg_read(REG_X0 + 2)?;
            state
                .objects
                .get_mut(&receiver)
                .expect("known configurable object")
                .properties
                .insert(key, value);
            context.reg_write(REG_X0, 0)?;
            return Ok(());
        }
        if let Some(&value) = state.objects[&receiver].properties.get(selector) {
            context.reg_write(REG_X0, value)?;
            return Ok(());
        }
    }
    match (class_method, selector) {
        (true, "null") if class_name == "NSNull" => {
            let null = new_guest_object(context, profile, state, "NSNull", StoreValue::Empty)?;
            context.reg_write(REG_X0, null)?;
        }
        (true, "decimalDigitCharacterSet") if class_name == "NSCharacterSet" => {
            let set = new_guest_object(
                context,
                profile,
                state,
                "NSCharacterSet",
                StoreValue::String("0123456789".into()),
            )?;
            context.reg_write(REG_X0, set)?;
        }
        (true, "bundleWithPath:") if class_name == "NSBundle" => {
            let path = context.reg_read(REG_X0 + 2)?;
            if object_string_value(state, path)? != "/System/Library/Frameworks/WebKit.framework" {
                context.reg_write(REG_X0, 0)?;
            } else {
                let version = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String("22625.1.29.11.28".into()),
                )?;
                let info = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSDictionary",
                    StoreValue::Entries(HashMap::from([("CFBundleVersion".into(), version)])),
                )?;
                let bundle =
                    new_guest_object(context, profile, state, "NSBundle", StoreValue::Empty)?;
                let properties = &mut state
                    .objects
                    .get_mut(&bundle)
                    .expect("new bundle")
                    .properties;
                properties.insert("bundlePath".into(), path);
                properties.insert("infoDictionary".into(), info);
                context.reg_write(REG_X0, bundle)?;
            }
        }
        (true, "standardUserDefaults") if class_name == "NSUserDefaults" => {
            let defaults = new_guest_object(
                context,
                profile,
                state,
                "NSUserDefaults",
                StoreValue::Entries(HashMap::new()),
            )?;
            context.reg_write(REG_X0, defaults)?;
        }
        (true, "propertyList:isValidForFormat:") if class_name == "NSPropertyListSerialization" => {
            let object = context.reg_read(REG_X0 + 2)?;
            let valid = export_object(state, object, &mut HashSet::new(), 0)
                .and_then(|value| {
                    let mut output = Vec::new();
                    plist::to_writer_xml(&mut output, &value).map_err(anyhow::Error::from)
                })
                .is_ok();
            context.reg_write(REG_X0, u64::from(valid))?;
        }
        (true, "dataWithPropertyList:format:options:error:")
            if class_name == "NSPropertyListSerialization" =>
        {
            let object = context.reg_read(REG_X0 + 2)?;
            let format = context.reg_read(REG_X0 + 3)?;
            let value = export_object(state, object, &mut HashSet::new(), 0)?;
            let mut bytes = Vec::new();
            if format == 200 {
                plist::to_writer_binary(&mut bytes, &value)?;
            } else {
                plist::to_writer_xml(&mut bytes, &value)?;
            }
            let data =
                new_guest_object(context, profile, state, "NSData", StoreValue::Bytes(bytes))?;
            context.reg_write(REG_X0, data)?;
        }
        (true, "setWithObjects:" | "arrayWithObjects:")
            if matches!(
                class_name.as_str(),
                "NSSet" | "NSMutableSet" | "NSArray" | "NSMutableArray"
            ) =>
        {
            let first = context.reg_read(REG_X0 + 2)?;
            let mut values = Vec::new();
            if first != 0 {
                values.push(first);
                let stack = context.reg_read(REG_SP)?;
                for index in 0..1024 {
                    let value = read_guest_u64(context, stack + index * 8)?;
                    if value == 0 {
                        break;
                    }
                    values.push(value);
                }
            }
            let collection = new_guest_object(
                context,
                profile,
                state,
                &class_name,
                StoreValue::Addresses(values),
            )?;
            context.reg_write(REG_X0, collection)?;
        }
        (true, "setWithArray:") if matches!(class_name.as_str(), "NSSet" | "NSMutableSet") => {
            let array = context.reg_read(REG_X0 + 2)?;
            let values = if array == 0 {
                Vec::new()
            } else {
                let StoreValue::Addresses(values) = &state
                    .objects
                    .get(&array)
                    .context("unknown set source array")?
                    .value
                else {
                    bail!("set source is not an array");
                };
                values.clone()
            };
            let set = new_guest_object(
                context,
                profile,
                state,
                &class_name,
                StoreValue::Addresses(values),
            )?;
            context.reg_write(REG_X0, set)?;
        }
        (true, "interfaceWithProtocol:") if class_name == "NSXPCInterface" => {
            let interface =
                new_guest_object(context, profile, state, "NSXPCInterface", StoreValue::Empty)?;
            context.reg_write(REG_X0, interface)?;
        }
        (true, "currentProcess") if class_name == "RBSProcessHandle" => {
            let process = new_guest_object(
                context,
                profile,
                state,
                "RBSProcessHandle",
                StoreValue::Empty,
            )?;
            context.reg_write(REG_X0, process)?;
        }
        (true, "errorWithDomain:code:userInfo:") if class_name == "NSError" => {
            let code = new_guest_object(
                context,
                profile,
                state,
                "NSNumber",
                StoreValue::Number(context.reg_read(REG_X0 + 3)? as i64),
            )?;
            let mut entries = HashMap::new();
            entries.insert("domain".into(), context.reg_read(REG_X0 + 2)?);
            entries.insert("code".into(), code);
            entries.insert("userInfo".into(), context.reg_read(REG_X0 + 4)?);
            let error = new_guest_object(
                context,
                profile,
                state,
                "NSError",
                StoreValue::Entries(entries),
            )?;
            context.reg_write(REG_X0, error)?;
        }
        (true, "isSubclassOfClass:") => {
            let target = profile
                .runtime
                .class_names_by_address
                .get(&context.reg_read(REG_X0 + 2)?);
            let value = target.is_some_and(|target| class_is_kind_of(profile, &class_name, target));
            context.reg_write(REG_X0, u64::from(value))?;
        }
        (true, "stringWithFormat:")
            if matches!(class_name.as_str(), "NSString" | "NSMutableString") =>
        {
            let format = object_string_value(state, context.reg_read(REG_X0 + 2)?)?;
            let value = guest_format(context, profile, state, format, context.reg_read(REG_SP)?)?;
            let string = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, string)?;
        }
        (true, "distantPast" | "distantFuture") if class_name == "NSDate" => {
            let seconds = if selector == "distantPast" {
                -62_135_769_600
            } else {
                64_092_211_200
            };
            let date = new_guest_object(
                context,
                profile,
                state,
                "NSDate",
                StoreValue::Number(seconds),
            )?;
            context.reg_write(REG_X0, date)?;
        }
        (true, "requestWithURL:")
            if matches!(class_name.as_str(), "NSURLRequest" | "NSMutableURLRequest") =>
        {
            let request =
                new_guest_object(context, profile, state, &class_name, StoreValue::Empty)?;
            let method = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String("GET".into()),
            )?;
            let headers = new_guest_object(
                context,
                profile,
                state,
                "NSMutableDictionary",
                StoreValue::Entries(HashMap::new()),
            )?;
            let properties = &mut state
                .objects
                .get_mut(&request)
                .expect("new request")
                .properties;
            properties.insert("URL".into(), context.reg_read(REG_X0 + 2)?);
            properties.insert("HTTPMethod".into(), method);
            properties.insert("allHTTPHeaderFields".into(), headers);
            context.reg_write(REG_X0, request)?;
        }
        (true, "sessionWithConfiguration:delegate:delegateQueue:")
            if class_name == "NSURLSession" =>
        {
            let session =
                new_guest_object(context, profile, state, "NSURLSession", StoreValue::Empty)?;
            let properties = &mut state
                .objects
                .get_mut(&session)
                .expect("new session")
                .properties;
            for (name, register) in [
                ("configuration", REG_X0 + 2),
                ("delegate", REG_X0 + 3),
                ("delegateQueue", REG_X0 + 4),
            ] {
                properties.insert(name.into(), context.reg_read(register)?);
            }
            context.reg_write(REG_X0, session)?;
        }
        (true, "mainBundle") => {
            context.reg_write(REG_X0, new_main_bundle(context, profile, state)?)?;
        }
        (true, "currentThread") => {
            let address = new_guest_object(context, profile, state, "NSThread", StoreValue::Empty)?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "processInfo") => {
            let process =
                new_guest_object(context, profile, state, "NSProcessInfo", StoreValue::Empty)?;
            let name = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String("ipatool".into()),
            )?;
            let environment = new_guest_object(
                context,
                profile,
                state,
                "NSDictionary",
                StoreValue::Entries(HashMap::new()),
            )?;
            let properties = &mut state
                .objects
                .get_mut(&process)
                .expect("new process")
                .properties;
            properties.insert("processName".into(), name);
            properties.insert("environment".into(), environment);
            context.reg_write(REG_X0, process)?;
        }
        (true, "defaultSessionConfiguration" | "ephemeralSessionConfiguration") => {
            let configuration = new_guest_object(
                context,
                profile,
                state,
                "NSURLSessionConfiguration",
                StoreValue::Empty,
            )?;
            let protocol_classes = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(Vec::new()),
            )?;
            let properties = &mut state
                .objects
                .get_mut(&configuration)
                .expect("new configuration")
                .properties;
            properties.insert("usesClassicLoadingMode".into(), 1);
            properties.insert("protocolClasses".into(), protocol_classes);
            properties.insert("HTTPShouldSetCookies".into(), 1);
            properties.insert("HTTPMaximumConnectionsPerHost".into(), 6);
            context.reg_write(REG_X0, configuration)?;
        }
        (true, "isMainThread") => context.reg_write(REG_X0, 1)?,
        (true, "UUID") => {
            let value = random_uuid_string()?;
            let address =
                new_guest_object(context, profile, state, "NSUUID", StoreValue::String(value))?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "alloc" | "allocWithZone:") => {
            let address =
                new_guest_object(context, profile, state, &class_name, StoreValue::Empty)?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "set" | "setWithCapacity:" | "array" | "arrayWithCapacity:") => {
            let address = new_guest_object(
                context,
                profile,
                state,
                &class_name,
                StoreValue::Addresses(Vec::new()),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "dictionary" | "dictionaryWithCapacity:") => {
            let address = new_guest_object(
                context,
                profile,
                state,
                &class_name,
                StoreValue::Entries(HashMap::new()),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "setWithObject:" | "arrayWithObject:") => {
            let value = context.reg_read(REG_X0 + 2)?;
            let address = new_guest_object(
                context,
                profile,
                state,
                &class_name,
                StoreValue::Addresses(vec![value]),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "dictionaryWithObjects:forKeys:count:") => {
            let values = context.reg_read(REG_X0 + 2)?;
            let keys = context.reg_read(REG_X0 + 3)?;
            let count = context.reg_read(REG_X0 + 4)?;
            if count > 65_536 {
                bail!("Store guest dictionary exceeds runtime limit");
            }
            let mut entries = HashMap::new();
            for index in 0..count {
                let key_address = read_guest_u64(context, keys + index * 8)?;
                let key = object_string_value(state, key_address)?.to_owned();
                entries.insert(key, read_guest_u64(context, values + index * 8)?);
            }
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSDictionary",
                StoreValue::Entries(entries),
            )?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "setWithObjects:count:" | "arrayWithObjects:count:") => {
            let values = context.reg_read(REG_X0 + 2)?;
            let count = context.reg_read(REG_X0 + 3)?;
            if count > 65_536 {
                bail!("Store guest array exceeds runtime limit");
            }
            let mut items = Vec::with_capacity(count as usize);
            for index in 0..count {
                items.push(read_guest_u64(context, values + index * 8)?);
            }
            let address = new_guest_object(
                context,
                profile,
                state,
                &class_name,
                StoreValue::Addresses(items),
            )?;
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
        (false, "addEntriesFromDictionary:") => {
            let source = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Entries(entries) = &state.objects[&source].value else {
                bail!("dictionary merge source on {class_name}");
            };
            let entries = entries.clone();
            let StoreValue::Entries(destination) = &mut state
                .objects
                .get_mut(&receiver)
                .expect("known receiver")
                .value
            else {
                bail!("dictionary merge destination on {class_name}");
            };
            destination.extend(entries);
            context.reg_write(REG_X0, 0)?;
        }
        (false, "allKeys" | "allValues") => {
            let StoreValue::Entries(entries) = &state.objects[&receiver].value else {
                bail!("dictionary keys on {class_name}");
            };
            let mut keys: Vec<String> = entries.keys().cloned().collect();
            keys.sort();
            let values = if selector == "allKeys" {
                keys.into_iter()
                    .map(|key| {
                        new_guest_object(
                            context,
                            profile,
                            state,
                            "NSString",
                            StoreValue::String(key),
                        )
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                keys.iter().map(|key| entries[key]).collect()
            };
            let array = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(values),
            )?;
            context.reg_write(REG_X0, array)?;
        }
        (false, "enumerateKeysAndObjectsUsingBlock:") => {
            let StoreValue::Entries(entries) = &state.objects[&receiver].value else {
                bail!("dictionary enumeration on {class_name}")
            };
            let mut pairs: Vec<(String, u64)> = entries
                .iter()
                .map(|(key, &value)| (key.clone(), value))
                .collect();
            pairs.sort_by(|left, right| left.0.cmp(&right.0));
            if pairs.is_empty() {
                context.reg_write(REG_X0, 0)?;
            } else {
                let block = context.reg_read(REG_X0 + 2)?;
                let stop = state.allocate(8)?;
                let (name, value) = &pairs[0];
                let key = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(name.clone()),
                )?;
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, block + 16)?,
                    &[block, key, *value, stop],
                    CallbackAction::EnumerateEntries {
                        block,
                        entries: pairs,
                        index: 1,
                        stop,
                    },
                )?;
            }
        }
        (false, "countByEnumeratingWithState:objects:count:") => {
            let enumeration = context.reg_read(REG_X0 + 2)?;
            let buffer = context.reg_read(REG_X0 + 3)?;
            let limit = context.reg_read(REG_X0 + 4)?;
            if limit > 100_000 {
                bail!("enumeration limit too large");
            }
            let items = match &state.objects[&receiver].value {
                StoreValue::Addresses(items) => items.clone(),
                StoreValue::Entries(entries) => {
                    let mut keys: Vec<String> = entries.keys().cloned().collect();
                    keys.sort();
                    keys.into_iter()
                        .map(|key| {
                            new_guest_object(
                                context,
                                profile,
                                state,
                                "NSString",
                                StoreValue::String(key),
                            )
                        })
                        .collect::<Result<Vec<_>>>()?
                }
                _ => bail!("invalid Store enumeration collection"),
            };
            let index = read_guest_u64(context, enumeration)?;
            if index >= items.len() as u64 {
                context.reg_write(REG_X0, 0)?;
            } else {
                let count = limit.min(items.len() as u64 - index);
                for offset in 0..count {
                    write_guest_u64(
                        context,
                        buffer + offset * 8,
                        items[(index + offset) as usize],
                    )?;
                }
                let mutation_counter =
                    match state.objects[&receiver].properties.get("mutationCounter") {
                        Some(&value) => value,
                        None => {
                            let address = state.allocate(8)?;
                            state
                                .objects
                                .get_mut(&receiver)
                                .expect("known collection")
                                .properties
                                .insert("mutationCounter".into(), address);
                            address
                        }
                    };
                write_guest_u64(context, enumeration, index + count)?;
                write_guest_u64(context, enumeration + 8, buffer)?;
                write_guest_u64(context, enumeration + 16, mutation_counter)?;
                context.reg_write(REG_X0, count)?;
            }
        }
        (false, "count" | "length") => {
            let object = &state.objects[&receiver];
            let count = match &object.value {
                StoreValue::String(value) => value.len(),
                StoreValue::Bytes(value) => value.len(),
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
        (false, "removeAllObjects") => {
            let object = state.objects.get_mut(&receiver).expect("known collection");
            match &mut object.value {
                StoreValue::Addresses(values) => values.clear(),
                StoreValue::Entries(entries) => entries.clear(),
                _ => bail!("removeAllObjects on {class_name}"),
            }
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
        (false, "initWithIdentifier:description:") if class_name == "ACAccountType" => {
            let identifier = context.reg_read(REG_X0 + 2)?;
            let description = context.reg_read(REG_X0 + 3)?;
            let properties = &mut state
                .objects
                .get_mut(&receiver)
                .expect("known account type")
                .properties;
            properties.insert("identifier".into(), identifier);
            properties.insert("accountTypeDescription".into(), description);
            context.reg_write(REG_X0, receiver)?;
        }
        (false, "initWithAccountType:") if class_is_kind_of(profile, &class_name, "ACAccount") => {
            let account_type = context.reg_read(REG_X0 + 2)?;
            let identifier = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(random_uuid_string()?),
            )?;
            let account_properties = new_guest_object(
                context,
                profile,
                state,
                "NSMutableDictionary",
                StoreValue::Entries(HashMap::new()),
            )?;
            let properties = &mut state
                .objects
                .get_mut(&receiver)
                .expect("known account")
                .properties;
            properties.insert("identifier".into(), identifier);
            properties.insert("accountType".into(), account_type);
            properties.insert("accountProperties".into(), account_properties);
            context.reg_write(REG_X0, receiver)?;
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
                StoreValue::Float(value) => *value as i64,
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
        (false, "initWithCapacity:") => {
            let value = if class_name == "NSMutableString" {
                StoreValue::String(String::new())
            } else if class_name.contains("Array") {
                StoreValue::Addresses(Vec::new())
            } else {
                StoreValue::Entries(HashMap::new())
            };
            state
                .objects
                .get_mut(&receiver)
                .expect("known receiver")
                .value = value;
            context.reg_write(REG_X0, receiver)?;
        }
        (false, "appendFormat:" | "initWithFormat:") => {
            let format_address = context.reg_read(REG_X0 + 2)?;
            let format = object_string_value(state, format_address)?.to_owned();
            let stack_pointer = context.reg_read(REG_SP)?;
            let formatted = guest_format(context, profile, state, &format, stack_pointer)?;
            let object = state.objects.get_mut(&receiver).expect("known string");
            if selector == "appendFormat:" {
                let StoreValue::String(value) = &mut object.value else {
                    bail!("appendFormat: on nonstring object");
                };
                value.push_str(&formatted);
                context.reg_write(REG_X0, 0)?;
            } else {
                object.value = StoreValue::String(formatted);
                context.reg_write(REG_X0, receiver)?;
            }
        }
        (false, "UTF8String" | "cStringUsingEncoding:") => {
            let value = object_string_value(state, receiver)?;
            let bytes = value.as_bytes().to_vec();
            let address = state.allocate(bytes.len() as u64 + 1)?;
            context.mem_write(address, &bytes)?;
            context.mem_write(address + bytes.len() as u64, &[0])?;
            context.reg_write(REG_X0, address)?;
        }
        (false, "stringValue") => {
            let value = match &state.objects[&receiver].value {
                StoreValue::Number(value) => value.to_string(),
                StoreValue::Float(value) => value.to_string(),
                StoreValue::Boolean(value) => value.to_string(),
                StoreValue::String(value) => value.clone(),
                _ => bail!("stringValue on {class_name}"),
            };
            let string = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, string)?;
        }
        (false, "componentsJoinedByString:") => {
            let separator = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
            let StoreValue::Addresses(items) = &state.objects[&receiver].value else {
                bail!("componentsJoinedByString: on {class_name}")
            };
            let parts = items
                .iter()
                .map(|&item| object_string_value(state, item).map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            let result = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(parts.join(&separator)),
            )?;
            context.reg_write(REG_X0, result)?;
        }
        (false, "stringByAppendingPathComponent:") => {
            let base = object_string_value(state, receiver)?.to_owned();
            let component = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
            let value = format!(
                "{}/{}",
                base.trim_end_matches('/'),
                component.trim_start_matches('/')
            );
            let result = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, result)?;
        }
        (false, "substringFromIndex:" | "substringToIndex:" | "substringWithRange:") => {
            let value: Vec<u16> = object_string_value(state, receiver)?
                .encode_utf16()
                .collect();
            let argument = context.reg_read(REG_X0 + 2)? as usize;
            let (start, end) = match selector {
                "substringFromIndex:" => (argument, value.len()),
                "substringToIndex:" => (0, argument),
                _ => (
                    argument,
                    argument
                        .checked_add(context.reg_read(REG_X0 + 3)? as usize)
                        .context("substring range overflow")?,
                ),
            };
            if start > end || end > value.len() {
                bail!("substring range exceeds string");
            }
            let result = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(String::from_utf16_lossy(&value[start..end])),
            )?;
            context.reg_write(REG_X0, result)?;
        }
        (false, "hasSuffix:" | "containsString:") => {
            let value = object_string_value(state, receiver)?;
            let needle = object_string_value(state, context.reg_read(REG_X0 + 2)?)?;
            let found = if selector == "hasSuffix:" {
                value.ends_with(needle)
            } else {
                value.contains(needle)
            };
            context.reg_write(REG_X0, u64::from(found))?;
        }
        (false, "copy" | "mutableCopy" | "mutableCopyWithZone:") => {
            let object = &state.objects[&receiver];
            let mutable = selector != "copy";
            let target = match object.class.as_str() {
                "NSArray" | "NSMutableArray" => {
                    if mutable {
                        "NSMutableArray"
                    } else {
                        "NSArray"
                    }
                }
                "NSSet" | "NSMutableSet" => {
                    if mutable {
                        "NSMutableSet"
                    } else {
                        "NSSet"
                    }
                }
                "NSDictionary" | "NSMutableDictionary" => {
                    if mutable {
                        "NSMutableDictionary"
                    } else {
                        "NSDictionary"
                    }
                }
                "NSMutableString" if !mutable => "NSString",
                _ if !mutable => {
                    context.reg_write(REG_X0, receiver)?;
                    return Ok(());
                }
                _ => object.class.as_str(),
            };
            let target = target.to_owned();
            let value = object.value.clone();
            let address = new_guest_object(context, profile, state, &target, value)?;
            context.reg_write(REG_X0, address)?;
        }
        (true, "class") | (false, "retain" | "autorelease" | "copyWithZone:") => {
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

fn setter_property_key(selector: &str) -> Option<String> {
    let name = selector.strip_prefix("set")?.strip_suffix(':')?.to_owned();
    if name.is_empty() || name.contains(':') {
        return None;
    }
    let mut key = name;
    if key.len() < 2 || !key.as_bytes()[1].is_ascii_uppercase() {
        key.replace_range(..1, &key[..1].to_ascii_lowercase());
    }
    Some(key)
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

fn export_object(
    state: &StoreState,
    address: u64,
    active: &mut HashSet<u64>,
    depth: usize,
) -> Result<Value> {
    if address == 0 {
        return Ok(Value::Null);
    }
    if depth > 32 || !active.insert(address) {
        bail!("cyclic or excessively nested Store guest value");
    }
    let object = state
        .objects
        .get(&address)
        .with_context(|| format!("unknown exported Store object {address:#x}"))?;
    let result = match &object.value {
        StoreValue::Empty => Value::Null,
        StoreValue::String(value) => Value::String(value.clone()),
        StoreValue::Number(value) => Value::Number((*value).into()),
        StoreValue::Float(value) => Value::Number(
            serde_json::Number::from_f64(*value).context("nonfinite Store guest number")?,
        ),
        StoreValue::Boolean(value) => Value::Bool(*value),
        StoreValue::Bytes(value) => {
            Value::String(base64::engine::general_purpose::STANDARD.encode(value))
        }
        StoreValue::Addresses(values) => Value::Array(
            values
                .iter()
                .map(|&address| export_object(state, address, active, depth + 1))
                .collect::<Result<Vec<_>>>()?,
        ),
        StoreValue::Entries(values) => {
            let mut result = serde_json::Map::with_capacity(values.len());
            for (key, &address) in values {
                result.insert(
                    key.clone(),
                    export_object(state, address, active, depth + 1)?,
                );
            }
            Value::Object(result)
        }
    };
    active.remove(&address);
    Ok(result)
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
        (StoreValue::Bytes(a), StoreValue::Bytes(b)) => a == b,
        (StoreValue::Number(a), StoreValue::Number(b)) => a == b,
        (StoreValue::Float(a), StoreValue::Float(b)) => a == b,
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

fn random_uuid_string() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).context("generate Store guest UUID")?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    Ok([
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
    .join("-"))
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
        runtime.set_hardware_id(&[1, 2, 3, 4, 5, 6]).unwrap();
        let nested = serde_json::json!({"values": [1, 2.5, true, null], "label": "测试"});
        let imported = runtime.import_json(&nested).unwrap();
        assert_eq!(runtime.export(imported).unwrap(), nested);
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
        for (selector, value) in [
            ("setEphemeral:", 1),
            ("setCanMakeAccountActive:", 0),
            ("setAllowServerDialogs:", 0),
            ("setCredentialSource:", 0),
        ] {
            runtime.invoke(options, selector, &[value]).unwrap();
        }
        let password = runtime
            .new_object("NSString", StoreValue::String("secret".into()))
            .unwrap();
        runtime
            .invoke(options, "setPassword:", &[password])
            .unwrap();
        let task = runtime
            .new_object("AMSVerifyCredentialsTask", StoreValue::Empty)
            .unwrap();
        assert_eq!(runtime.invoke(task, "init", &[]).unwrap(), task);
        let ephemeral = runtime
            .invoke(account_address, "ams_createEphemeralAccount", &[])
            .unwrap();
        assert_eq!(
            runtime.state.borrow().objects[&ephemeral].class,
            "AMSEphemeralAccount"
        );
        let username = runtime
            .new_object("NSString", StoreValue::String("test@example.com".into()))
            .unwrap();
        runtime
            .invoke(ephemeral, "setUsername:", &[username])
            .unwrap();
        runtime.set_ivar(task, "_account", ephemeral).unwrap();
        runtime.set_ivar(task, "_options", options).unwrap();
        runtime.set_ivar(task, "_bag", 0).unwrap();
        let parameters = runtime
            .invoke(
                task,
                "_createAuthenticateRequestParametersForAccount:",
                &[ephemeral],
            )
            .unwrap();
        let parameters = runtime.export(parameters).unwrap();
        assert_eq!(parameters["appleId"], "test@example.com");
        assert_eq!(parameters["password"], "secret");
        assert!(
            parameters["guid"]
                .as_str()
                .unwrap()
                .eq_ignore_ascii_case("010203040506")
        );
        let encoder = runtime.new_request_encoder(0).unwrap();
        assert_eq!(
            runtime.state.borrow().objects[&encoder].class,
            "AMSURLRequestEncoder"
        );
        let request = runtime
            .encode_request(0, 0, "POST", "https://example.com/test", &nested)
            .unwrap();
        assert_eq!(
            runtime.state.borrow().objects[&request].class,
            "AMSURLRequest"
        );
        let url = runtime.invoke(request, "URL", &[]).unwrap();
        assert_eq!(
            runtime.object_string(url).unwrap(),
            "https://example.com/test"
        );
        let joined_call = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| {
                call.symbol.trim_start_matches('_')
                    == "$sSKsSS7ElementRtzrlE6joined9separatorS2S_tF"
            })
            .unwrap()
            .address;
        let storage = runtime.allocate(64).unwrap();
        runtime.write_u64(storage + 16, 2).unwrap();
        for (index, character) in [(0, b'a'), (1, b'b')] {
            let mut word = [0u8; 16];
            word[0] = character;
            word[15] = 0xe1;
            runtime
                .engine
                .mem_write(storage + 32 + index * 16, &word)
                .unwrap();
        }
        let sequence = runtime.allocate(8).unwrap();
        runtime.write_u64(sequence, storage).unwrap();
        runtime.engine.reg_write(REG_X0 + 20, sequence).unwrap();
        let result = runtime
            .call(joined_call, &[0x202c, 0xe200_0000_0000_0000])
            .unwrap();
        assert_eq!(
            result,
            u64::from_le_bytes([b'a', b',', b' ', b'b', 0, 0, 0, 0])
        );
        assert_eq!(runtime.engine.reg_read(REG_X0 + 1).unwrap() >> 56, 0xe4);
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

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn builds_authentication_parameters_with_pinned_apple_code() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let parameters = runtime
            .build_authentication_parameters("test@example.com", "secret", &[1, 2, 3, 4, 5, 6], 0)
            .unwrap();
        assert_eq!(parameters["appleId"], "test@example.com");
        assert_eq!(parameters["password"], "secret");
        assert!(
            parameters["guid"]
                .as_str()
                .unwrap()
                .eq_ignore_ascii_case("010203040506")
        );
        assert!(parameters["createSession"].is_boolean());
    }
}
