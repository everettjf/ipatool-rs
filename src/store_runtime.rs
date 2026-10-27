//! StoreAgent guest memory prepared from the pinned AMS images and profile.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use reqwest::{
    Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

use crate::{
    credentials::Account,
    machimage::{Image, Memory},
    sap_assets::SapAssetBundle,
    store_memory::{MemoryRegion, exclude_mapped_regions},
    store_profile::{self, Call, ProfileData},
    transport::{Request as HostRequest, Response as HostResponse},
    unicorn_runtime::{Engine, HookContext, REG_PC, REG_X0, REG_X29},
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

/// Inputs for a Store request. Authentication uses additional Apple guest
/// objects and is handled separately.
pub struct StoreStandardRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a HeaderMap,
    pub parameters: Option<&'a Value>,
    pub body: Option<&'a [u8]>,
    pub bag: Option<&'a plist::Value>,
    pub hardware_id: &'a [u8],
    pub raw: bool,
    pub response_format: &'a str,
    pub no_redirects: bool,
    pub timeout: Option<Duration>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StoreOperation {
    Standard,
    Purchase,
    Authenticate,
}

type StoreSigner<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>> + 'a;

#[derive(Debug)]
struct StoreFrameworkError {
    domain: String,
    code: i64,
    message: Option<String>,
}

impl fmt::Display for StoreFrameworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Store framework error {}/{}",
            self.domain, self.code
        )?;
        if let Some(message) = &self.message {
            write!(formatter, ": {message}")?;
        }
        Ok(())
    }
}

impl std::error::Error for StoreFrameworkError {}

struct StoreState {
    heap_cursor: u64,
    dynamic_selectors: HashMap<String, u64>,
    dynamic_selector_addresses: HashMap<u64, String>,
    objects: HashMap<u64, StoreObject>,
    callbacks: HashMap<u64, CallbackResume>,
    hardware_id: Option<[u8; 6]>,
    preferences: HashMap<String, u64>,
    current_queue: u64,
    pending: Vec<PendingWork>,
    transport: Option<Rc<dyn Fn(HostRequest) -> Result<HostResponse>>>,
    transport_authenticated: bool,
    transport_no_redirects: bool,
    transport_timeout: Option<Duration>,
    http_responses: HashMap<u64, HostResponse>,
    last_http_task: Option<u64>,
    host_blocks: HashMap<u64, HostBlockAction>,
    allocations: HashMap<u64, u64>,
    main_queue: Option<u64>,
    notification_center: Option<u64>,
    observers: Vec<NotificationObserver>,
    swift_tasks: HashMap<u64, SwiftTask>,
    current_swift_task: Option<u64>,
    task_locals: TaskLocalBindings,
    swift_query_array_metadata: Option<u64>,
    associations: HashMap<(u64, u64), u64>,
}

struct CallbackResume {
    link: u64,
    action: CallbackAction,
}

struct DelegateCall {
    selector: String,
    arguments: Vec<u64>,
    action: Box<CallbackAction>,
    depth: u8,
}

struct NotificationObserver {
    observer: u64,
    selector: u64,
    name: u64,
    object: u64,
}

struct PurchaseEncodeState {
    receiver: u64,
    request: u64,
    parameters: u64,
    selector: u64,
    properties: u64,
    step: u8,
}

struct SwiftTask {
    context: u64,
    entry: u64,
    closure: u64,
    result: u64,
    continuation: Option<u64>,
    executor: [u64; 2],
    done: bool,
}

#[derive(Clone, Copy)]
struct TaskLocalBinding {
    key: u64,
    value: u64,
}

#[derive(Default)]
struct TaskLocalBindings {
    frames: HashMap<u64, Vec<TaskLocalBinding>>,
}

impl TaskLocalBindings {
    fn get(&self, owner: u64, key: u64) -> u64 {
        self.frames
            .get(&owner)
            .and_then(|bindings| bindings.iter().rev().find(|binding| binding.key == key))
            .map_or(0, |binding| binding.value)
    }

    fn push(&mut self, owner: u64, key: u64, value: u64) {
        self.frames
            .entry(owner)
            .or_default()
            .push(TaskLocalBinding { key, value });
    }

    fn pop(&mut self, owner: u64) -> Result<()> {
        let bindings = self
            .frames
            .get_mut(&owner)
            .context("empty TaskLocal binding stack")?;
        bindings.pop().context("empty TaskLocal binding stack")?;
        Ok(())
    }

    fn copy_to(&mut self, source: u64, target: u64) {
        let bindings = self.frames.get(&source).cloned().unwrap_or_default();
        self.frames.insert(target, bindings);
    }
}

enum PendingWork {
    Guest {
        block: u64,
        queue: u64,
        group: Option<u64>,
    },
    Http {
        task: u64,
    },
    DeliverData {
        task: u64,
    },
    Complete {
        task: u64,
    },
    SwiftTask {
        task: u64,
    },
}

enum HostBlockAction {
    AcceptResponse { task: u64 },
    Redirect { task: u64 },
}

enum CallbackAction {
    ReturnZero,
    ReturnCurrentValue,
    ReturnValue {
        value: u64,
    },
    QueueBlock {
        block: u64,
        queue: u64,
        group: Option<u64>,
    },
    LeaveGroup {
        group: u64,
        then: Box<CallbackAction>,
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
    DictionaryCopy {
        receiver: u64,
        keys: Vec<String>,
        index: usize,
        key: String,
    },
    RestoreQueue {
        previous: u64,
    },
    RestoreQueueWithValue {
        previous: u64,
        value: u64,
    },
    SemaphoreWait {
        semaphore: u64,
        previous_queue: u64,
    },
    GroupWait {
        group: u64,
        timeout: u64,
        previous_queue: u64,
    },
    ScheduleComplete {
        task: u64,
    },
    ForwardDelegate {
        source: u64,
        call: DelegateCall,
    },
    CopyProperty {
        destination: u64,
    },
    CompleteSwiftTask {
        task: u64,
        previous: Option<u64>,
        saved: Vec<(i32, u64)>,
        poll_after: Option<(u64, u64)>,
        semaphore_after: Option<u64>,
        group_after: Option<(u64, u64)>,
    },
    PollSwiftContinuation {
        task: u64,
        continuation: u64,
        previous_queue: u64,
    },
    SortArray {
        items: Vec<u64>,
        block: u64,
        i: usize,
        j: usize,
    },
    NotificationNext {
        observers: Vec<(u64, u64)>,
        index: usize,
        notification: u64,
    },
    PurchaseEncode(PurchaseEncodeState),
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
            transport: None,
            transport_authenticated: true,
            transport_no_redirects: false,
            transport_timeout: None,
            http_responses: HashMap::new(),
            last_http_task: None,
            host_blocks: HashMap::new(),
            allocations: HashMap::new(),
            main_queue: None,
            notification_center: None,
            observers: Vec::new(),
            swift_tasks: HashMap::new(),
            current_swift_task: None,
            task_locals: TaskLocalBindings::default(),
            swift_query_array_metadata: None,
            associations: HashMap::new(),
        }));
        let hook_error = Rc::new(RefCell::new(None));
        let error_slot = Rc::clone(&hook_error);
        let hook_profile = Arc::clone(&profile);
        let hook_code_ranges = code_ranges.clone();
        let hook_state = Rc::clone(&state);
        engine.add_code_hook(0, u64::MAX, move |context, address, _| {
            let host_block = hook_state.borrow_mut().host_blocks.remove(&address);
            if let Some(action) = host_block {
                if let Err(error) = dispatch_host_block(
                    context,
                    &hook_profile,
                    &mut hook_state.borrow_mut(),
                    action,
                ) {
                    *error_slot.borrow_mut() =
                        Some(format!("Store host block at {address:#x}: {error:#}"));
                    context
                        .stop()
                        .expect("stop Store guest after host block error");
                }
                return;
            }
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
                    "Store guest executed outside pinned image at {address:#x}; lr={:#x} x0={:#x} x1={:#x}",
                    context.reg_read(REG_LR).unwrap_or(0),
                    context.reg_read(REG_X0).unwrap_or(0),
                    context.reg_read(REG_X0 + 1).unwrap_or(0)
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

    pub fn set_transport(
        &mut self,
        transport: impl Fn(HostRequest) -> Result<HostResponse> + 'static,
    ) {
        self.state.borrow_mut().transport = Some(Rc::new(transport));
    }

    pub fn set_transport_policy(
        &mut self,
        authenticated: bool,
        no_redirects: bool,
        timeout: Option<Duration>,
    ) {
        let mut state = self.state.borrow_mut();
        state.transport_authenticated = authenticated;
        state.transport_no_redirects = no_redirects;
        state.transport_timeout = timeout;
    }

    pub fn take_http_response(&mut self, task: u64) -> Option<HostResponse> {
        self.state.borrow_mut().http_responses.remove(&task)
    }

    pub fn take_last_http_response(&mut self) -> Option<HostResponse> {
        let mut state = self.state.borrow_mut();
        let task = state.last_http_task.take()?;
        state.http_responses.remove(&task)
    }

    pub fn send_request(&mut self, session: u64, request: u64) -> Result<(u64, HostResponse)> {
        self.state.borrow_mut().last_http_task = None;
        let promise = self.invoke(session, "dataTaskPromiseWithRequest:", &[request])?;
        let result = self.resolve_promise(promise)?;
        let mut state = self.state.borrow_mut();
        let task = state
            .last_http_task
            .take()
            .context("Store session did not issue an HTTP task")?;
        let response = state
            .http_responses
            .remove(&task)
            .context("Store HTTP task has no response")?;
        Ok((result, response))
    }

    /// Prepare, send, and decode one ordinary Store request through the pinned
    /// Apple code. The host HTTP transport must be installed with set_transport.
    pub fn execute_standard(&mut self, input: StoreStandardRequest<'_>) -> Result<HostResponse> {
        self.execute_request(input, StoreOperation::Standard, None)
    }

    pub fn execute_standard_signed(
        &mut self,
        input: StoreStandardRequest<'_>,
        signer: &mut StoreSigner<'_>,
    ) -> Result<HostResponse> {
        self.execute_request(input, StoreOperation::Standard, Some(signer))
    }

    /// Prepare, send, and decode a free-app purchase through the pinned Apple
    /// code. The host HTTP transport must be installed with set_transport.
    pub fn execute_purchase(&mut self, input: StoreStandardRequest<'_>) -> Result<HostResponse> {
        if input.method != "POST" {
            bail!("purchase requests must use POST");
        }
        if input.parameters.is_none() {
            bail!("purchase parameters are required");
        }
        self.execute_request(input, StoreOperation::Purchase, None)
    }

    /// Build and sign a Store authentication request using Apple's pinned
    /// credential task. The caller supplies an initialized SAP signer.
    pub fn execute_authentication(
        &mut self,
        input: StoreStandardRequest<'_>,
        signer: &mut StoreSigner<'_>,
    ) -> Result<HostResponse> {
        if input.method != "POST" {
            bail!("authentication requests must use POST");
        }
        if input.parameters.is_none() {
            bail!("authentication parameters are required");
        }
        self.execute_request(input, StoreOperation::Authenticate, Some(signer))
    }

    fn execute_request(
        &mut self,
        input: StoreStandardRequest<'_>,
        operation: StoreOperation,
        mut signer: Option<&mut StoreSigner<'_>>,
    ) -> Result<HostResponse> {
        self.set_hardware_id(input.hardware_id)?;
        self.set_transport_policy(true, input.no_redirects, input.timeout);

        let mut saved = Account::default();
        let account = if let Some(dsid) = input.headers.get("X-Dsid") {
            saved.directory_services_id = dsid
                .to_str()
                .context("invalid saved account identifier header")?
                .into();
            saved.password_token = input
                .headers
                .get("X-Token")
                .map(|value| value.to_str())
                .transpose()
                .context("invalid saved account token header")?
                .unwrap_or_default()
                .into();
            saved.store_front = input
                .headers
                .get("X-Apple-Store-Front")
                .map(|value| value.to_str())
                .transpose()
                .context("invalid saved storefront header")?
                .unwrap_or_default()
                .into();
            self.ephemeral_account(Some(&saved))?
        } else {
            self.ephemeral_account(None)?
        };
        let mut bag_values = input.bag.cloned();
        if operation == StoreOperation::Purchase
            && let Some(values) = bag_values
                .as_mut()
                .and_then(plist::Value::as_dictionary_mut)
        {
            let endpoint = plist::Value::String(input.url.into());
            values.insert("buyProduct".into(), endpoint.clone());
            if let Some(nested) = values
                .get_mut("urlBag")
                .and_then(plist::Value::as_dictionary_mut)
            {
                nested.insert("buyProduct".into(), endpoint);
            }
        }
        let bag = bag_values
            .as_ref()
            .map(|value| self.frozen_bag_from_plist(value))
            .transpose()?
            .unwrap_or(0);
        let session = self.new_session()?;
        let mut parameters = input.parameters.cloned();
        let delegate = if operation == StoreOperation::Authenticate {
            let source = parameters
                .as_ref()
                .and_then(Value::as_object)
                .context("authentication parameters must be an object")?;
            let email = source
                .get("appleId")
                .and_then(Value::as_str)
                .context("authentication Apple ID is required")?;
            let password = source
                .get("password")
                .and_then(Value::as_str)
                .context("authentication password is required")?;
            let username = self.new_object("NSString", StoreValue::String(email.into()))?;
            self.invoke(account, "setUsername:", &[username])?;
            let (task, mut built) =
                self.authentication_task(account, bag, password, input.hardware_id)?;
            for key in ["attempt", "why"] {
                if let Some(value) = source.get(key) {
                    built
                        .as_object_mut()
                        .context("Store authentication builder returned no dictionary")?
                        .insert(key.into(), value.clone());
                }
            }
            parameters = Some(built);
            task
        } else {
            self.new_object("NSObject", StoreValue::Empty)?
        };
        self.invoke(session, "setDelegate:", &[delegate])?;

        let request = if operation == StoreOperation::Purchase {
            self.encode_purchase_request(
                account,
                bag,
                parameters.as_ref().expect("validated purchase parameters"),
            )?
        } else if let Some(parameters) = parameters.as_ref() {
            self.encode_request(account, bag, input.method, input.url, parameters)?
        } else {
            let request = self.new_object("AMSURLRequest", StoreValue::Empty)?;
            let url = self.new_object("NSURL", StoreValue::String(input.url.into()))?;
            let request = self.invoke(
                request,
                "initWithURL:cachePolicy:timeoutInterval:",
                &[url, 0, 0],
            )?;
            let method = self.new_object("NSString", StoreValue::String(input.method.into()))?;
            self.invoke(request, "setHTTPMethod:", &[method])?;
            if let Some(body) = input.body {
                let body = self.new_object("NSData", StoreValue::Bytes(body.to_vec()))?;
                self.invoke(request, "setHTTPBody:", &[body])?;
            }
            request
        };
        self.configure_request(request, account, bag, input.raw)?;
        let mut headers: HashMap<String, Vec<&str>> = HashMap::new();
        for (name, value) in input.headers {
            if name.as_str().eq_ignore_ascii_case("content-length") {
                continue;
            }
            headers.entry(name.to_string()).or_default().push(
                value
                    .to_str()
                    .context("Store request header is not UTF-8")?,
            );
        }
        for (name, values) in headers {
            let name = self.new_object("NSString", StoreValue::String(name))?;
            let value = self.new_object("NSString", StoreValue::String(values.join(", ")))?;
            self.invoke(request, "setValue:forHTTPHeaderField:", &[value, name])?;
        }

        if let Some(sign) = signer.as_mut() {
            let body = self.invoke(request, "HTTPBody", &[])?;
            let bytes = match self.state.borrow().objects.get(&body) {
                Some(StoreObject {
                    value: StoreValue::Bytes(bytes),
                    ..
                }) => bytes.clone(),
                _ => bail!("signed Store request has no body"),
            };
            let signature = sign(&bytes).context("sign Store request")?;
            if signature.is_empty() {
                bail!("Store signer returned an empty signature");
            }
            let encoded = base64::engine::general_purpose::STANDARD.encode(signature);
            let encoded = self.new_object("NSString", StoreValue::String(encoded))?;
            let name = self.new_object(
                "NSString",
                StoreValue::String("X-Apple-ActionSignature".into()),
            )?;
            self.invoke(request, "setValue:forHTTPHeaderField:", &[encoded, name])?;
        }

        let (result, mut response) = match self.send_request(session, request) {
            Ok(result) => result,
            Err(error) if !input.raw && error.downcast_ref::<StoreFrameworkError>().is_some() => {
                if let Some(response) = self.take_last_http_response() {
                    return Ok(response);
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if input.raw {
            return Ok(response);
        }
        let object = self.invoke(result, "object", &[])?;
        if object != 0 {
            let json = input.response_format == "json"
                || response
                    .header("content-type")
                    .is_some_and(|content_type| content_type.to_ascii_lowercase().contains("json"));
            let body = if json {
                let value = self.export(object)?;
                serde_json::to_vec(&value).context("encode decoded Store JSON")?
            } else {
                let value =
                    export_plist_object(&self.state.borrow(), object, &mut HashSet::new(), 0)?;
                let mut bytes = Vec::new();
                plist::to_writer_xml(&mut bytes, &value)
                    .context("encode decoded Store property list")?;
                bytes
            };
            response.body = body;
            response.headers.retain(|name, _| {
                !name.eq_ignore_ascii_case("content-encoding")
                    && !name.eq_ignore_ascii_case("content-length")
            });
        }
        Ok(response)
    }

    pub fn set_hardware_id(&mut self, hardware_id: &[u8]) -> Result<()> {
        let hardware_id: [u8; 6] = hardware_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Store hardware identity must be six bytes"))?;
        self.state.borrow_mut().hardware_id = Some(hardware_id);
        Ok(())
    }

    /// Construct the ephemeral account used for a Store request. Saved account
    /// fields come from the host credential store, not from guest memory.
    pub fn ephemeral_account(&mut self, saved: Option<&Account>) -> Result<u64> {
        let account_class = self
            .class_address("ACAccount")
            .context("Store profile is missing ACAccount")?;
        let account = self.invoke(account_class, "ams_createEphemeralAccount", &[])?;
        if let Some(saved) = saved {
            let dsid = saved
                .directory_services_id
                .parse::<i64>()
                .context("invalid saved account identifier")?;
            let fields = [
                ("setUsername:", &saved.email),
                ("ams_setPassword:", &saved.password_token),
                ("ams_setStorefront:", &saved.store_front),
            ];
            for (selector, text) in fields {
                let value = self.new_object("NSString", StoreValue::String(text.clone()))?;
                self.invoke(account, selector, &[value])?;
            }
            let dsid = self.new_object("NSNumber", StoreValue::Number(dsid))?;
            self.invoke(account, "ams_setDSID:", &[dsid])?;
        }
        Ok(account)
    }

    /// Build the same short-lived frozen Store bag as the Go backend. A nested
    /// `urlBag` overrides its parent entries, matching the input bag response.
    pub fn frozen_bag_from_values(&mut self, values: &Value) -> Result<u64> {
        let values = plist::to_value(values).context("convert Store bag to property list")?;
        self.frozen_bag_from_plist(&values)
    }

    pub fn frozen_bag_from_plist(&mut self, values: &plist::Value) -> Result<u64> {
        let source = values
            .as_dictionary()
            .context("Store bag must be a property list dictionary")?;
        let mut flattened = source.clone();
        if let Some(nested) = source.get("urlBag").and_then(plist::Value::as_dictionary) {
            flattened.extend(nested.clone());
        }
        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(flattened))?;
        let bytes = self.new_object("NSData", StoreValue::Bytes(bytes))?;
        let serializer = self
            .class_address("NSPropertyListSerialization")
            .context("Store profile is missing NSPropertyListSerialization")?;
        let data = self.invoke(
            serializer,
            "propertyListWithData:options:format:error:",
            &[bytes, 0, 0, 0],
        )?;
        let profile = self.new_object("NSString", StoreValue::String("AMSPurchase".into()))?;
        let version = self.new_object("NSString", StoreValue::String("1".into()))?;
        let expiration = self.new_object(
            "NSDate",
            StoreValue::Float(time::OffsetDateTime::now_utc().unix_timestamp() as f64 + 300.0),
        )?;
        let builder = self.new_object("AMSBagFrozenDataSourceBuilder", StoreValue::Empty)?;
        for (selector, value) in [
            ("setData:", data),
            ("setProfile:", profile),
            ("setProfileVersion:", version),
            ("setExpirationDate:", expiration),
        ] {
            self.invoke(builder, selector, &[value])?;
        }
        self.invoke(builder, "createFrozenBag", &[])
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
        let account = self.ephemeral_account(None)?;
        let username = self.new_object("NSString", StoreValue::String(email.into()))?;
        self.invoke(account, "setUsername:", &[username])?;

        let (_, parameters) = self.authentication_task(account, bag, password, hardware_id)?;
        Ok(parameters)
    }

    fn authentication_task(
        &mut self,
        account: u64,
        bag: u64,
        password: &str,
        hardware_id: &[u8],
    ) -> Result<(u64, Value)> {
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
        Ok((task, parameters))
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
            let domain = self.object_string(domain)?.to_owned();
            let message = self
                .invoke(error, "localizedDescription", &[])
                .ok()
                .and_then(|address| self.object_string(address).ok());
            return Err(StoreFrameworkError {
                domain,
                code,
                message,
            }
            .into());
        }
        if result == 0 {
            bail!("Store framework returned no result");
        }
        Ok(result)
    }

    pub fn new_session(&mut self) -> Result<u64> {
        let session = self.new_object("AMSURLSession", StoreValue::Empty)?;
        let session = self.invoke(
            session,
            "initWithConfiguration:delegate:delegateQueue:",
            &[0, 0, 0],
        )?;
        self.invoke(session, "setUseFallbackBag:", &[0])?;
        Ok(session)
    }

    pub fn configure_request(
        &mut self,
        request: u64,
        account: u64,
        bag: u64,
        raw: bool,
    ) -> Result<()> {
        let properties = self.invoke(request, "properties", &[])?;
        for (selector, value) in [
            ("setAccount:", account),
            ("setBag:", bag),
            ("setKnownToBeTrusted:", 1),
            ("setShouldSetCookiesFromResponse:", 0),
            ("setShouldSetStorefrontFromResponse:", 0),
            ("setDisableLoadURLMetrics:", 1),
            ("setDisableBiometricsResponseHandling:", 1),
            ("setMaxRetryCount:", 0),
            ("setDisableResponseDecoding:", u64::from(raw)),
        ] {
            self.invoke(properties, selector, &[value])?;
        }
        Ok(())
    }

    pub fn host_request(
        &self,
        request: u64,
        authenticated: bool,
        no_redirects: bool,
        timeout: Option<Duration>,
    ) -> Result<HostRequest> {
        let state = self.state.borrow();
        host_request_from_state(
            &self.profile,
            &state,
            request,
            authenticated,
            no_redirects,
            timeout,
        )
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

    /// Ask Apple's purchase encoder for a free-app request and verify the
    /// encoded product and price before the request can leave the host.
    pub fn encode_purchase_request(
        &mut self,
        account: u64,
        bag: u64,
        parameters: &Value,
    ) -> Result<u64> {
        if bag == 0 {
            bail!("purchase requires a Store bag");
        }
        let parameters = parameters
            .as_object()
            .context("purchase parameters must be an object")?;
        if parameters.get("price").map(json_scalar) != Some("0".into())
            || parameters.get("productType").map(json_scalar) != Some("C".into())
        {
            bail!("purchasing paid apps is not supported");
        }
        let buy_params = self.new_object("AMSBuyParams", StoreValue::Empty)?;
        self.invoke(buy_params, "init", &[])?;
        for (key, value) in parameters {
            let key = self.new_object("NSString", StoreValue::String(key.clone()))?;
            let value = self.import_json(value)?;
            self.invoke(buy_params, "setParameter:forKey:", &[value, key])?;
        }
        let purchase = self.new_object("AMSPurchase", StoreValue::Empty)?;
        let purchase = self.invoke(
            purchase,
            "initWithPurchaseType:buyParams:",
            &[0, buy_params],
        )?;
        self.invoke(purchase, "setAccount:", &[account])?;
        let info = self.new_object("AMSPurchaseInfo", StoreValue::Empty)?;
        let info = self.invoke(info, "initWithPurchase:", &[purchase])?;
        self.invoke(info, "setAddKBSync:", &[0])?;
        self.invoke(info, "setHasBeenAuthedForBuy:", &[1])?;
        let encoder = self.new_object("AMSPurchaseRequestEncoder", StoreValue::Empty)?;
        let encoder = self.invoke(encoder, "initWithPurchaseInfo:bag:", &[info, bag])?;
        for (selector, value) in [
            ("setAnisetteType:", 0),
            ("setMescalType:", 0),
            ("setUrlKnownToBeTrusted:", 1),
            ("setEnableRemoteSecuritySigning:", 0),
            ("setDisableLoadURLMetrics:", 1),
            ("setCompressRequestBody:", 0),
            ("setShouldSetStorefrontHeader:", 0),
            ("setShouldSetCookieHeader:", 0),
        ] {
            self.invoke(encoder, selector, &[value])?;
        }
        let promise = self.invoke(encoder, "encodeRequest", &[])?;
        let request = self.resolve_promise(promise)?;
        let body = self.invoke(request, "HTTPBody", &[])?;
        let body = match &self
            .state
            .borrow()
            .objects
            .get(&body)
            .context("purchase encoder returned no body")?
            .value
        {
            StoreValue::Bytes(body) => body.clone(),
            _ => bail!("purchase encoder returned an invalid body"),
        };
        validate_encoded_purchase(&body, parameters)?;
        Ok(request)
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
        result.with_context(|| {
            format!(
                "execute Store guest at {:#x}",
                self.engine.reg_read(REG_PC).unwrap_or(0)
            )
        })?;
        let pc = self.engine.reg_read(REG_PC)?;
        if pc != RETURN_PC {
            bail!("Store guest stopped before return at {pc:#x}");
        }
        self.engine.reg_read(REG_X0)
    }
}

fn json_scalar(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn validate_encoded_purchase(
    body: &[u8],
    parameters: &serde_json::Map<String, Value>,
) -> Result<()> {
    let encoded: plist::Value = plist::from_bytes(body).context("invalid encoded purchase")?;
    let encoded = encoded
        .as_dictionary()
        .context("encoded purchase is not a dictionary")?;
    for key in ["price", "salableAdamId", "pricingParameters", "productType"] {
        let actual = encoded.get(key).and_then(plist_scalar);
        if actual != parameters.get(key).map(json_scalar) {
            bail!("purchase encoder changed product or price");
        }
    }
    Ok(())
}

fn plist_scalar(value: &plist::Value) -> Option<String> {
    match value {
        plist::Value::String(value) => Some(value.clone()),
        plist::Value::Boolean(value) => Some(value.to_string()),
        plist::Value::Integer(value) => value
            .as_signed()
            .map(|value| value.to_string())
            .or_else(|| value.as_unsigned().map(|value| value.to_string())),
        plist::Value::Real(value) => Some(value.to_string()),
        _ => None,
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
        "CC_SHA512" => {
            let input = context.reg_read(REG_X0)?;
            let length = context.reg_read(REG_X0 + 1)? as u32 as usize;
            if length > HEAP_SIZE {
                bail!("SHA-512 input exceeds runtime budget");
            }
            let digest = Sha512::digest(context.mem_read(input, length)?);
            let output = match context.reg_read(REG_X0 + 2)? {
                0 => state.allocate(64)?,
                output => output,
            };
            context.mem_write(output, &digest)?;
            context.reg_write(REG_X0, output)?;
        }
        "strftime" => {
            let output = context.reg_read(REG_X0)?;
            let limit = context.reg_read(REG_X0 + 1)?;
            let format = guest_cstring(context, profile, state, context.reg_read(REG_X0 + 2)?)?;
            if format != "%a, %d %b %Y %H:%M:%S GMT" {
                bail!("unsupported date output format {format}");
            }
            let tm = read_guest_tm(context, context.reg_read(REG_X0 + 3)?)?;
            let value = format_guest_http_date(normalize_guest_tm(tm)?);
            if value.len() as u64 + 1 > limit {
                context.reg_write(REG_X0, 0)?;
            } else {
                let mut bytes = value.into_bytes();
                bytes.push(0);
                context.mem_write(output, &bytes)?;
                context.reg_write(REG_X0, (bytes.len() - 1) as u64)?;
            }
        }
        "strptime" => {
            let input = context.reg_read(REG_X0)?;
            let value = guest_cstring(context, profile, state, input)?;
            let format = guest_cstring(context, profile, state, context.reg_read(REG_X0 + 1)?)?;
            if format != "%a, %d %b %Y %H:%M:%S GMT" && format != "%a, %d %b %Y %H:%M:%S %Z" {
                bail!("unsupported date format {format}");
            }
            if let Some(tm) = parse_guest_http_date(&value) {
                write_guest_tm(context, context.reg_read(REG_X0 + 2)?, tm)?;
                context.reg_write(REG_X0, input + value.len() as u64)?;
            } else {
                context.reg_write(REG_X0, 0)?;
            }
        }
        "timegm" => {
            let tm = read_guest_tm(context, context.reg_read(REG_X0)?)?;
            context.reg_write(REG_X0, normalize_guest_tm(tm)?.unix_timestamp() as u64)?;
        }
        "res_9_ninit" => context.reg_write(REG_X0, u32::MAX as u64)?,
        "res_9_ndestroy" => {}
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
        "CFNotificationCenterGetDarwinNotifyCenter" => {
            let center = new_guest_object(
                context,
                profile,
                state,
                "HostDarwinNotificationCenter",
                StoreValue::Empty,
            )?;
            context.reg_write(REG_X0, center)?;
        }
        "CFNotificationCenterAddObserver" | "CFNotificationCenterRemoveObserver" => {
            context.reg_write(REG_X0, 0)?;
        }
        "nw_activity_create" => {
            let activity = new_guest_object(
                context,
                profile,
                state,
                "HostNetworkActivity",
                StoreValue::Empty,
            )?;
            context.reg_write(REG_X0, activity)?;
        }
        "nw_activity_activate" | "nw_activity_complete" | "nw_activity_cancel" => {
            context.reg_write(REG_X0, 0)?;
        }
        "swift_task_localValueGet" => {
            let owner = state.current_swift_task.unwrap_or(0);
            let key = context.reg_read(REG_X0)?;
            context.reg_write(REG_X0, state.task_locals.get(owner, key))?;
        }
        "swift_task_localValuePush" => {
            let key = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            let metadata = context.reg_read(REG_X0 + 2)?;
            let witnesses = read_guest_u64(
                context,
                metadata
                    .checked_sub(8)
                    .context("invalid TaskLocal metadata")?,
            )?;
            let size = read_guest_u64(context, witnesses + 64)?;
            if size > 1 << 20 {
                bail!("TaskLocal value exceeds budget");
            }
            let value = state.allocate(size)?;
            context.mem_write(value, &context.mem_read(source, size as usize)?)?;
            let owner = state.current_swift_task.unwrap_or(0);
            state.task_locals.push(owner, key, value);
            context.reg_write(REG_X0, 0)?;
        }
        "swift_task_localValuePop" => {
            let owner = state.current_swift_task.unwrap_or(0);
            state.task_locals.pop(owner)?;
        }
        "swift_task_localsCopyTo" => {
            let target = context.reg_read(REG_X0)?;
            if !state.swift_tasks.contains_key(&target) {
                bail!("unknown task for local bindings");
            }
            let owner = state.current_swift_task.unwrap_or(0);
            state.task_locals.copy_to(owner, target);
        }
        "swift_dynamicCast" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            let mut source_type = context.reg_read(REG_X0 + 2)?;
            let target_type = context.reg_read(REG_X0 + 3)?;
            let flags = context.reg_read(REG_X0 + 4)?;
            let string = profile.index.symbols["$sSSN"];
            if source_type == profile.index.symbols["$ss11AnyHashableVN"] && target_type == string {
                if read_guest_u64(context, source + 24)?
                    != profile.index.bridges["anyHashableStringMetadata"]
                {
                    bail!("unsupported Swift AnyHashable cast box");
                }
                source_type = target_type;
            } else if source_type == profile.index.symbols["$sypN"] + 8 {
                source_type = read_guest_u64(context, source + 24)?;
            }
            if source_type == target_type {
                let witnesses = read_guest_u64(context, source_type - 8)?;
                let size = read_guest_u64(context, witnesses + 64)?;
                if size > 24 {
                    bail!("unsupported Swift cast value size");
                }
                context.mem_write(destination, &context.mem_read(source, size as usize)?)?;
                context.reg_write(REG_X0, 1)?;
            } else if target_type == string
                && ["$sSiN", "$sSbN", "$sSdN"]
                    .iter()
                    .any(|name| source_type == profile.index.symbols[*name])
                && flags & 1 == 0
            {
                context.reg_write(REG_X0, 0)?;
            } else {
                bail!(
                    "unsupported Swift cast metadata {source_type:#x} -> {target_type:#x} flags={flags}"
                );
            }
        }
        "swift_allocError" => {
            let metadata = context.reg_read(REG_X0)?;
            let witness = context.reg_read(REG_X0 + 1)?;
            let source = context.reg_read(REG_X0 + 2)?;
            let witnesses = read_guest_u64(context, metadata - 8)?;
            let size = read_guest_u64(context, witnesses + 64)?;
            if size > 1 << 20 {
                bail!("Swift error exceeds budget");
            }
            let value = state.allocate(size)?;
            let box_address =
                new_guest_object(context, profile, state, "HostSwiftError", StoreValue::Empty)?;
            state
                .objects
                .get_mut(&box_address)
                .expect("new Swift error box")
                .properties = HashMap::from([
                ("metadata".into(), metadata),
                ("witness".into(), witness),
                ("value".into(), value),
            ]);
            if source != 0 {
                context.mem_write(value, &context.mem_read(source, size as usize)?)?;
            }
            context.reg_write(REG_X0, box_address)?;
            context.reg_write(REG_X0 + 1, value)?;
        }
        "swift_getErrorValue" => {
            let address = context.reg_read(REG_X0)?;
            let object = state
                .objects
                .get(&address)
                .context("unknown Swift error box")?;
            if object.class != "HostSwiftError" {
                bail!("unsupported unboxed Swift error");
            }
            let out = context.reg_read(REG_X0 + 2)?;
            for (offset, name) in [(0, "value"), (8, "metadata"), (16, "witness")] {
                write_guest_u64(context, out + offset, object.properties[name])?;
            }
        }
        "swift_errorRetain" | "swift_errorRelease" => {}
        "swift_task_create" => {
            let flags = context.reg_read(REG_X0)?;
            let options = context.reg_read(REG_X0 + 1)?;
            let result_type = context.reg_read(REG_X0 + 2)?;
            let descriptor = context.reg_read(REG_X0 + 3)?;
            let closure = context.reg_read(REG_X0 + 4)?;
            if options != 0 || flags & !0x1cff != 0 {
                bail!("unsupported Swift task options");
            }
            let bits = read_guest_u64(context, descriptor)?;
            let size = bits >> 32;
            if !(16..=1 << 20).contains(&size) {
                bail!("invalid Swift async context size");
            }
            let entry = descriptor.wrapping_add((bits as u32 as i32 as i64) as u64);
            let result_size = if result_type == 0 {
                0
            } else {
                let witnesses = read_guest_u64(context, result_type - 8)?;
                read_guest_u64(context, witnesses + 64)?
            };
            if result_size > 1 << 20 {
                bail!("Swift task result exceeds budget");
            }
            let handle =
                new_guest_object(context, profile, state, "HostSwiftTask", StoreValue::Empty)?;
            let task = SwiftTask {
                context: state.allocate(size + 32)? + 32,
                entry,
                closure,
                result: state.allocate(result_size)?,
                continuation: None,
                executor: [0, 0],
                done: false,
            };
            let result_record = state.allocate(0x30)?;
            write_guest_u64(context, result_record + 0x28, task.result)?;
            write_guest_u64(context, handle + 0x40, result_record)?;
            let context_address = task.context;
            state.swift_tasks.insert(handle, task);
            if flags & (1 << 10) != 0 {
                let owner = state.current_swift_task.unwrap_or(0);
                state.task_locals.copy_to(owner, handle);
            }
            state.pending.push(PendingWork::SwiftTask { task: handle });
            context.reg_write(REG_X0, handle)?;
            context.reg_write(REG_X0 + 1, context_address)?;
        }
        "swift_task_alloc" => {
            let size = context.reg_read(REG_X0)?;
            context.reg_write(REG_X0, state.allocate(size)?)?;
        }
        "swift_task_dealloc" => {}
        "dispatch_semaphore_create" => {
            let initial = context.reg_read(REG_X0)? as i64;
            let semaphore = new_guest_object(
                context,
                profile,
                state,
                "HostSemaphore",
                StoreValue::Number(initial),
            )?;
            context.reg_write(REG_X0, semaphore)?;
        }
        "dispatch_semaphore_signal" => {
            let semaphore = context.reg_read(REG_X0)?;
            let count = semaphore_count(state, semaphore)?;
            *count = count.wrapping_add(1);
            context.reg_write(REG_X0, 0)?;
        }
        "dispatch_semaphore_wait" => {
            let semaphore = context.reg_read(REG_X0)?;
            if *semaphore_count(state, semaphore)? > 0 {
                consume_signaled_semaphore(state, semaphore)?;
                context.reg_write(REG_X0, 0)?;
            } else {
                let has_pending = !state.pending.is_empty();
                let Some(work) = take_runnable_pending(state) else {
                    if has_pending {
                        bail!("all pending queues are suspended");
                    }
                    bail!("guest waits on an unavailable host service");
                };
                dispatch_pending_for_semaphore(context, profile, state, semaphore, work)?;
            }
        }
        "dispatch_group_create" => {
            let group = new_guest_object(
                context,
                profile,
                state,
                "HostDispatchGroup",
                StoreValue::Number(0),
            )?;
            context.reg_write(REG_X0, group)?;
        }
        "dispatch_group_enter" => {
            let group = context.reg_read(REG_X0)?;
            let count = group_count(state, group)?;
            *count = count
                .checked_add(1)
                .context("guest dispatch group overflow")?;
            context.reg_write(REG_X0, 0)?;
        }
        "dispatch_group_leave" => {
            let group = context.reg_read(REG_X0)?;
            let count = group_count(state, group)?;
            if *count <= 0 {
                bail!("guest dispatch group leave without enter");
            }
            *count -= 1;
            context.reg_write(REG_X0, 0)?;
        }
        "dispatch_group_wait" => {
            let group = context.reg_read(REG_X0)?;
            let timeout = context.reg_read(REG_X0 + 1)?;
            poll_dispatch_group(context, profile, state, group, timeout)?;
        }
        "dispatch_block_create" => {
            let block = context.reg_read(REG_X0 + 1)?;
            if block == 0 {
                bail!("cannot create a null dispatch block");
            }
            let flags = read_guest_u64(context, block + 8)? as u32;
            if flags & (1 << 28) != 0 {
                context.reg_write(REG_X0, block)?;
            } else {
                let descriptor = read_guest_u64(context, block + 24)?;
                let size = read_guest_u64(context, descriptor + 8)?;
                if !(32..=1_048_576).contains(&size) {
                    bail!("invalid dispatch block size");
                }
                let copied = state.allocate(size)?;
                context.mem_write(copied, &context.mem_read(block, size as usize)?)?;
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
        }
        "swift_task_getCurrent" => {
            context.reg_write(REG_X0, state.current_swift_task.unwrap_or(0))?;
        }
        "swift_task_isCancelled" => context.reg_write(REG_X0, 0)?,
        "swift_task_switch" => {
            let task = state
                .current_swift_task
                .context("Swift executor switch outside task")?;
            let function = context.reg_read(REG_X0)?;
            state
                .swift_tasks
                .get_mut(&task)
                .expect("current task")
                .executor = [context.reg_read(REG_X0 + 1)?, context.reg_read(REG_X0 + 2)?];
            context.reg_write(REG_PC, function)?;
        }
        "swift_task_getCurrentExecutor" => {
            let executor = state
                .current_swift_task
                .and_then(|task| state.swift_tasks.get(&task))
                .map(|task| task.executor)
                .unwrap_or([0, 0]);
            context.reg_write(REG_X0, executor[0])?;
            context.reg_write(REG_X0 + 1, executor[1])?;
        }
        "swift_task_isCurrentExecutor" => {
            let executor = state
                .current_swift_task
                .and_then(|task| state.swift_tasks.get(&task))
                .map(|task| task.executor)
                .unwrap_or([0, 0]);
            context.reg_write(
                REG_X0,
                u64::from(executor == [context.reg_read(REG_X0)?, context.reg_read(REG_X0 + 1)?]),
            )?;
        }
        "swift_continuation_init" => {
            let task = state
                .current_swift_task
                .context("Swift continuation outside task")?;
            let continuation = context.reg_read(REG_X0)?;
            let flags = context.reg_read(REG_X0 + 1)?;
            if flags & 4 != 0 {
                bail!("preawaited Swift continuation is unsupported");
            }
            state
                .swift_tasks
                .get_mut(&task)
                .expect("current task")
                .continuation = Some(continuation);
            write_guest_u64(context, continuation + 16, (flags & 1) | ((flags & 8) >> 2))?;
            write_guest_u64(context, continuation + 24, 0)?;
            write_guest_u64(context, continuation + 32, 0)?;
            if flags & 2 == 0 {
                write_guest_u64(context, continuation + 48, 0)?;
                write_guest_u64(context, continuation + 56, 0)?;
            }
            context.reg_write(REG_X0, task)?;
        }
        "swift_continuation_resume"
        | "swift_continuation_throwingResume"
        | "swift_continuation_throwingResumeWithError" => {
            let task = context.reg_read(REG_X0)?;
            let continuation = state
                .swift_tasks
                .get(&task)
                .and_then(|task| task.continuation)
                .context("unknown Swift continuation")?;
            if read_guest_u64(context, continuation + 24)? == 2 {
                bail!("Swift continuation resumed twice");
            }
            if symbol == "swift_continuation_throwingResumeWithError" {
                write_guest_u64(context, continuation + 32, context.reg_read(REG_X0 + 1)?)?;
            }
            write_guest_u64(context, continuation + 24, 2)?;
            context.reg_write(REG_X0, 0)?;
        }
        "swift_continuation_await" => {
            let continuation = context.reg_read(REG_X0)?;
            let task = state
                .current_swift_task
                .context("Swift continuation awaited outside task")?;
            if state.swift_tasks[&task].continuation != Some(continuation) {
                bail!("awaiting unknown Swift continuation");
            }
            poll_swift_continuation(context, profile, state, task, continuation)?;
        }
        "swift_getDynamicType" => {
            let value = read_guest_u64(context, context.reg_read(REG_X0)?)?;
            let metadata = state
                .objects
                .get(&value)
                .and_then(|object| profile.runtime.classes_by_name.get(&object.class))
                .map(|&index| profile.index.classes[index].address)
                .unwrap_or(context.reg_read(REG_X0 + 1)?);
            context.reg_write(REG_X0, metadata)?;
        }
        "getuid" | "geteuid" => context.reg_write(REG_X0, 501)?,
        "swift_getObjCClassFromMetadata" => {
            let metadata = context.reg_read(REG_X0)?;
            if !profile
                .runtime
                .class_names_by_address
                .contains_key(&metadata)
            {
                if read_guest_u64(context, metadata)? != 0x305 {
                    bail!("unknown Objective-C class metadata");
                }
                context.reg_write(REG_X0, read_guest_u64(context, metadata + 8)?)?;
            }
        }
        "swift_initWithCopy_strong"
        | "swift_initWithTake_strong"
        | "swift_assignWithCopy_strong"
        | "swift_assignWithTake_strong" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            write_guest_u64(context, destination, read_guest_u64(context, source)?)?;
        }
        "swift_initStackObject" => {
            let metadata = context.reg_read(REG_X0)?;
            let object = context.reg_read(REG_X0 + 1)?;
            write_guest_u64(context, object, metadata)?;
            write_guest_u64(context, object + 8, 3)?;
            context.reg_write(REG_X0, object)?;
        }
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
        "chkstk_darwin" | "free" | "swift_willThrow" => {}
        "platform_memmove" | "platform_memcpy" | "memcpy" | "memmove" | "memcpy_chk"
        | "memmove_chk" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            let size = context.reg_read(REG_X0 + 2)?;
            if size > HEAP_SIZE as u64 {
                bail!("guest copy exceeds memory budget");
            }
            if size != 0 {
                context.mem_write(destination, &context.mem_read(source, size as usize)?)?;
            }
            context.reg_write(REG_X0, destination)?;
        }
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
        "CFBundleGetIdentifier" => {
            let bundle = context.reg_read(REG_X0)?;
            let object = state.objects.get(&bundle).context("unknown CFBundle")?;
            if object.class != "NSBundle" {
                bail!("CFBundle identifier receiver is not a bundle");
            }
            context.reg_write(
                REG_X0,
                object
                    .properties
                    .get("bundleIdentifier")
                    .copied()
                    .unwrap_or(0),
            )?;
        }
        "CFBundleCopyBundleURL" => {
            let bundle = context.reg_read(REG_X0)?;
            let object = state.objects.get(&bundle).context("unknown CFBundle")?;
            if object.class != "NSBundle" {
                bail!("CFBundle URL receiver is not a bundle");
            }
            let path = object
                .properties
                .get("bundlePath")
                .copied()
                .context("CFBundle has no path")?;
            let path = object_string_value(state, path)?;
            let url = url::Url::from_file_path(path)
                .map_err(|_| anyhow::anyhow!("invalid CFBundle path"))?;
            let url = new_guest_object(
                context,
                profile,
                state,
                "NSURL",
                StoreValue::String(url.to_string()),
            )?;
            context.reg_write(REG_X0, url)?;
        }
        "CFBundleGetInfoDictionary" => {
            context.reg_write(REG_X0, new_bundle_info(context, profile, state)?)?;
        }
        "CFBundleCopyExecutableURL" => {
            let url = new_guest_object(
                context,
                profile,
                state,
                "NSURL",
                StoreValue::String("file:///ipatool".into()),
            )?;
            context.reg_write(REG_X0, url)?;
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
        "CFUUIDCreate" => {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).context("generate Store UUID")?;
            bytes[6] = (bytes[6] & 15) | 64;
            bytes[8] = (bytes[8] & 63) | 128;
            let uuid = new_guest_object(
                context,
                profile,
                state,
                "HostUUID",
                StoreValue::Bytes(bytes.to_vec()),
            )?;
            context.reg_write(REG_X0, uuid)?;
        }
        "CFUUIDGetUUIDBytes" => {
            let address = context.reg_read(REG_X0)?;
            let StoreValue::Bytes(bytes) = &state
                .objects
                .get(&address)
                .context("unknown Store UUID")?
                .value
            else {
                bail!("Store UUID has invalid data");
            };
            let bytes: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .context("Store UUID must be 16 bytes")?;
            context.reg_write(REG_X0, u64::from_le_bytes(bytes[..8].try_into()?))?;
            context.reg_write(REG_X0 + 1, u64::from_le_bytes(bytes[8..].try_into()?))?;
        }
        "dispatch_time" => {
            let base = context.reg_read(REG_X0)?;
            let offset = context.reg_read(REG_X0 + 1)?;
            let base = if base == 0 {
                time::OffsetDateTime::now_utc().unix_timestamp_nanos() as u64
            } else {
                base
            };
            context.reg_write(REG_X0, base.wrapping_add(offset))?;
        }
        "clock_gettime_nsec_np" => {
            let clock = context.reg_read(REG_X0)?;
            context.reg_write(REG_X0, guest_clock_gettime_nsec(clock)?)?;
        }
        "dispatch_after" => {
            // The Go guest retains deadline blocks without firing them. The
            // request promise supplies its own completion path.
            let block = context.reg_read(REG_X0 + 2)?;
            if block == 0 {
                bail!("cannot schedule a null Store block");
            }
            let flags = read_guest_u64(context, block + 8)? as u32;
            if flags & (1 << 28) == 0 {
                let descriptor = read_guest_u64(context, block + 24)?;
                let size = read_guest_u64(context, descriptor + 8)?;
                if !(32..=1_048_576).contains(&size) {
                    bail!("invalid scheduled block size {size}");
                }
                let copied = state.allocate(size)?;
                context.mem_write(copied, &context.mem_read(block, size as usize)?)?;
                if flags & (1 << 25) != 0 {
                    begin_callback(
                        context,
                        state,
                        read_guest_u64(context, descriptor + 16)?,
                        &[copied, block],
                        CallbackAction::ReturnZero,
                    )?;
                    return Ok(());
                }
            }
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
            copy_and_queue_block(context, state, queue, block, None)?;
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
        "dispatch_assert_queue" => {
            let expected = context.reg_read(REG_X0)?;
            let mut queue = state.current_queue;
            let mut matched = false;
            for _ in 0..32 {
                if queue == expected {
                    matched = true;
                    break;
                }
                queue = state
                    .objects
                    .get(&queue)
                    .and_then(|object| object.properties.get("targetQueue"))
                    .copied()
                    .unwrap_or(0);
                if queue == 0 {
                    break;
                }
            }
            if !matched {
                bail!(
                    "dispatch queue mismatch: running {:#x} expected {expected:#x}",
                    state.current_queue
                );
            }
        }
        "dispatch_suspend" => {
            let queue = context.reg_read(REG_X0)?;
            let object = state
                .objects
                .get_mut(&queue)
                .context("unknown suspended queue")?;
            let count = object.properties.entry("suspendCount".into()).or_default();
            *count += 1;
            context.reg_write(REG_X0, 0)?;
        }
        "dispatch_resume" => {
            let queue = context.reg_read(REG_X0)?;
            let object = state
                .objects
                .get_mut(&queue)
                .context("unknown resumed queue")?;
            let count = object.properties.entry("suspendCount".into()).or_default();
            if *count == 0 {
                bail!("resuming active dispatch queue");
            }
            *count -= 1;
            context.reg_write(REG_X0, 0)?;
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
        "swift_getSingletonMetadata" => {
            let candidate = context.reg_read(REG_X0 + 1)?;
            let metadata = profile
                .index
                .swift_singletons
                .get(&candidate.to_string())
                .copied()
                .filter(|value| *value != 0)
                .with_context(|| format!("unprepared Swift singleton metadata {candidate:#x}"))?;
            context.reg_write(REG_X0, metadata)?;
            context.reg_write(REG_X0 + 1, 0)?;
        }
        "swift_getForeignTypeMetadata" => {
            let candidate = context.reg_read(REG_X0 + 1)?;
            let metadata = match profile.index.swift_foreign.get(&candidate.to_string()) {
                Some(&value) if value != 0 => value,
                _ if candidate == 0x1eaa52f08 && read_guest_u64(context, candidate)? == 0x201 => {
                    candidate
                }
                _ => bail!("unsupported foreign metadata {candidate:#x}"),
            };
            context.reg_write(REG_X0, metadata)?;
            context.reg_write(REG_X0 + 1, 0)?;
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
        "$sSo17OS_dispatch_queueC8DispatchE5async5group3qos5flags7executeySo0a1_b1_F0CSg_AC0D3QoSVAC0D13WorkItemFlagsVyyXBtF" =>
        {
            let group = context.reg_read(REG_X0)?;
            let queue = context.reg_read(REG_X0 + 20)?;
            let block = context.reg_read(REG_X0 + 3)?;
            copy_and_queue_block(context, state, queue, block, (group != 0).then_some(group))?;
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
        "$s10Foundation10URLRequestV36_unconditionallyBridgeFromObjectiveCyACSo12NSURLRequestCSgFZ" =>
        {
            let request = context.reg_read(REG_X0)?;
            let class = &state
                .objects
                .get(&request)
                .context("invalid Swift request bridge input")?
                .class;
            if !class_is_kind_of(profile, class, "NSURLRequest") {
                bail!("invalid Swift request bridge input");
            }
            write_guest_u64(context, context.reg_read(REG_X0 + 8)?, request)?;
        }
        "$s10Foundation10URLRequestV19_bridgeToObjectiveCSo12NSURLRequestCyF" => {
            let value = read_guest_u64(context, context.reg_read(REG_X0 + 20)?)?;
            context.reg_write(REG_X0, value)?;
        }
        "$s10Foundation3URLV19_bridgeToObjectiveCSo5NSURLCyF" => {
            let value = read_guest_u64(context, context.reg_read(REG_X0 + 20)?)?;
            context.reg_write(REG_X0, value)?;
        }
        "$s10Foundation10URLRequestV3urlAA3URLVSgvg" => {
            let request = read_guest_u64(context, context.reg_read(REG_X0 + 20)?)?;
            let url = state
                .objects
                .get(&request)
                .context("invalid Swift URLRequest value")?
                .properties
                .get("URL")
                .copied()
                .unwrap_or(0);
            let output = context.reg_read(REG_X0 + 8)?;
            write_guest_u64(context, output, url)?;
            write_guest_u64(context, output + 8, 0)?;
        }
        "$s10Foundation10URLRequestV8setValue_18forHTTPHeaderFieldySSSg_SStF" => {
            let request = mutable_swift_request(context, profile, state)?;
            let field = swift_string(
                context,
                state,
                context.reg_read(REG_X0 + 2)?,
                context.reg_read(REG_X0 + 3)?,
            )?;
            let header_dictionary = state.objects[&request]
                .properties
                .get("allHTTPHeaderFields")
                .copied()
                .unwrap_or(0);
            let header_dictionary = if header_dictionary == 0 {
                let headers = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSMutableDictionary",
                    StoreValue::Entries(HashMap::new()),
                )?;
                state
                    .objects
                    .get_mut(&request)
                    .expect("known Swift request")
                    .properties
                    .insert("allHTTPHeaderFields".into(), headers);
                headers
            } else {
                header_dictionary
            };
            let value = if context.reg_read(REG_X0 + 1)? == 0 {
                0
            } else {
                let value = swift_string(
                    context,
                    state,
                    context.reg_read(REG_X0)?,
                    context.reg_read(REG_X0 + 1)?,
                )?;
                new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(value),
                )?
            };
            let StoreValue::Entries(entries) = &mut state
                .objects
                .get_mut(&header_dictionary)
                .context("missing Swift request headers")?
                .value
            else {
                bail!("invalid Swift request headers");
            };
            let previous = entries
                .keys()
                .find(|name| name.eq_ignore_ascii_case(&field))
                .cloned();
            if let Some(previous) = previous {
                entries.remove(&previous);
            }
            if value != 0 {
                entries.insert(field, value);
            }
        }
        "$sScPwst" | "$s10Foundation3URLVwst" => {
            let destination = context.reg_read(REG_X0)?;
            let tag = context.reg_read(REG_X0 + 1)?;
            if context.reg_read(REG_X0 + 2)? != 1 || tag > 1 {
                bail!("unsupported Swift URL optional tag");
            }
            if tag == 1 {
                write_guest_u64(context, destination, 0)?;
                write_guest_u64(context, destination + 8, 0)?;
            }
        }
        "$sScPwet" | "$s10Foundation3URLVwet" => {
            if context.reg_read(REG_X0 + 1)? != 1 {
                bail!("unsupported Swift URL optional tag");
            }
            let value = read_guest_u64(context, context.reg_read(REG_X0)?)?;
            context.reg_write(REG_X0, u64::from(value == 0))?;
        }
        "$s10Foundation3URLV14absoluteStringSSvg" => {
            let url = read_guest_u64(context, context.reg_read(REG_X0 + 20)?)?;
            let value = object_string_value(state, url)?.to_owned();
            return_swift_string(context, state, &value)?;
        }
        "$s10Foundation3URLV06isFileB0Sbvg" => {
            let url = read_guest_u64(context, context.reg_read(REG_X0 + 20)?)?;
            let value = url::Url::parse(object_string_value(state, url)?)?;
            context.reg_write(REG_X0, u64::from(value.scheme() == "file"))?;
        }
        "$ss9TaskLocalC12wrappedValueAByxGx_tcfc" => {
            let value_source = context.reg_read(REG_X0)?;
            let self_address = context.reg_read(REG_X0 + 20)?;
            let metadata = read_guest_u64(context, self_address)?;
            let value_type = read_guest_u64(context, metadata + 80)?;
            let witnesses = read_guest_u64(context, value_type - 8)?;
            let size = read_guest_u64(context, witnesses + 64)?;
            let allocated = state
                .allocations
                .get(&self_address)
                .copied()
                .context("unknown Swift task-local allocation")?;
            if size > allocated.saturating_sub(16) {
                bail!("Swift task-local value exceeds allocation");
            }
            context.mem_write(
                self_address + 16,
                &context.mem_read(value_source, size as usize)?,
            )?;
            state.objects.insert(
                self_address,
                StoreObject {
                    class: "HostSwiftTaskLocal".into(),
                    value: StoreValue::Empty,
                    properties: HashMap::from([
                        ("valueSize".into(), size),
                        ("defaultValue".into(), self_address + 16),
                    ]),
                },
            );
            context.reg_write(REG_X0, self_address)?;
        }
        "$ss9TaskLocalC3getxyF" | "$ss9TaskLocalC12wrappedValuexvg" => {
            let self_address = context.reg_read(REG_X0 + 20)?;
            let object = state
                .objects
                .get(&self_address)
                .context("unknown Swift task-local")?;
            let size = object.properties["valueSize"];
            let owner = state.current_swift_task.unwrap_or(0);
            let source = state.task_locals.get(owner, self_address);
            let source = if source == 0 {
                object.properties["defaultValue"]
            } else {
                source
            };
            let output = context.reg_read(REG_X0 + 8)?;
            context.mem_write(output, &context.mem_read(source, size as usize)?)?;
        }
        "$ss9_typeName_9qualifiedSSypXp_SbtF" => {
            let metadata = context.reg_read(REG_X0)?;
            let class = profile
                .runtime
                .class_names_by_address
                .get(&metadata)
                .or_else(|| {
                    (read_guest_u64(context, metadata).ok()? == 0x305)
                        .then(|| read_guest_u64(context, metadata + 8).ok())
                        .flatten()
                        .and_then(|address| profile.runtime.class_names_by_address.get(&address))
                })
                .context("unknown Swift type name")?;
            return_swift_string(context, state, class)?;
        }
        "$ss27_stringCompareWithSmolCheck__9expectingSbs11_StringGutsV_ADs01_G16ComparisonResultOtF" =>
        {
            let left = swift_string(
                context,
                state,
                context.reg_read(REG_X0)?,
                context.reg_read(REG_X0 + 1)?,
            )?;
            let right = swift_string(
                context,
                state,
                context.reg_read(REG_X0 + 2)?,
                context.reg_read(REG_X0 + 3)?,
            )?;
            let ordering = left.nfc().cmp(right.nfc());
            let matches = match context.reg_read(REG_X0 + 4)? {
                0 => ordering == std::cmp::Ordering::Equal,
                1 => ordering == std::cmp::Ordering::Less,
                _ => bail!("unsupported Swift string comparison"),
            };
            context.reg_write(REG_X0, u64::from(matches))?;
        }
        "$sSy10FoundationE8containsySbqd__SyRd__lF" => {
            let needle_address = context.reg_read(REG_X0)?;
            let self_address = context.reg_read(REG_X0 + 20)?;
            let needle = swift_string(
                context,
                state,
                read_guest_u64(context, needle_address)?,
                read_guest_u64(context, needle_address + 8)?,
            )?;
            let haystack = swift_string(
                context,
                state,
                read_guest_u64(context, self_address)?,
                read_guest_u64(context, self_address + 8)?,
            )?;
            context.reg_write(REG_X0, u64::from(haystack.contains(&needle)))?;
        }
        "$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ" => {
            let url = context.reg_read(REG_X0)?;
            if !matches!(state.objects.get(&url), Some(object) if object.class == "NSURL") {
                bail!("invalid Swift URL bridge input");
            }
            let output = context.reg_read(REG_X0 + 8)?;
            write_guest_u64(context, output, url)?;
            write_guest_u64(context, output + 8, 0)?;
        }
        "$s10Foundation3URLV6append10components13directoryHintyxd_AC09DirectoryF0OtSyRzlF"
        | "$s10Foundation3URLV9appending10components13directoryHintACxd_AC09DirectoryF0OtSyRzlF" => {
            let storage = context.reg_read(REG_X0)?;
            let count = read_guest_u64(context, storage + 16)?;
            if count > 32 {
                bail!("Swift URL component count exceeds limit");
            }
            let self_address = context.reg_read(REG_X0 + 20)?;
            let original = read_guest_u64(context, self_address)?;
            let mut url = url::Url::parse(object_string_value(state, original)?)?;
            {
                let mut segments = url
                    .path_segments_mut()
                    .map_err(|()| anyhow::anyhow!("Swift URL does not have path segments"))?;
                for index in 0..count {
                    let element = storage + 32 + index * 16;
                    let component = swift_string(
                        context,
                        state,
                        read_guest_u64(context, element)?,
                        read_guest_u64(context, element + 8)?,
                    )?;
                    segments.push(&component);
                }
            }
            let updated = new_guest_object(
                context,
                profile,
                state,
                "NSURL",
                StoreValue::String(url.into()),
            )?;
            if symbol.contains("9appending") {
                let output = context.reg_read(REG_X0 + 8)?;
                write_guest_u64(context, output, updated)?;
                write_guest_u64(context, output + 8, 0)?;
            } else {
                write_guest_u64(context, self_address, updated)?;
            }
        }
        "$s10Foundation12CharacterSetV15urlQueryAllowedACvgZ" => {
            let set = new_guest_object(
                context,
                profile,
                state,
                "NSCharacterSet",
                StoreValue::String(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@/?"
                        .into(),
                ),
            )?;
            let output = context.reg_read(REG_X0 + 8)?;
            write_guest_u64(context, output, set)?;
            write_guest_u64(context, output + 8, 0)?;
        }
        "$s10Foundation12CharacterSetV6removeys7UnicodeO6ScalarVSgAHF" => {
            let scalar = char::from_u32(context.reg_read(REG_X0)? as u32)
                .context("invalid Swift character set scalar")?;
            let self_address = context.reg_read(REG_X0 + 20)?;
            let set = read_guest_u64(context, self_address)?;
            let Some(StoreObject {
                value: StoreValue::String(characters),
                ..
            }) = state.objects.get_mut(&set)
            else {
                bail!("invalid Swift character set at {self_address:#x}: {set:#x}");
            };
            characters.retain(|character| character != scalar);
            context.reg_write(REG_X0, scalar as u64)?;
        }
        "$sSy10FoundationE21addingPercentEncoding21withAllowedCharactersSSSgAA12CharacterSetV_tF" =>
        {
            let set = read_guest_u64(context, context.reg_read(REG_X0)?)?;
            let StoreValue::String(allowed) = &state
                .objects
                .get(&set)
                .context("unknown percent encoding character set")?
                .value
            else {
                bail!("invalid percent encoding character set");
            };
            let allowed = allowed.clone();
            let input = context.reg_read(REG_X0 + 20)?;
            let value = swift_string(
                context,
                state,
                read_guest_u64(context, input)?,
                read_guest_u64(context, input + 8)?,
            )?;
            let mut encoded = String::new();
            for byte in value.bytes() {
                if allowed.as_bytes().contains(&byte) {
                    encoded.push(byte as char);
                } else {
                    use std::fmt::Write as _;
                    write!(&mut encoded, "%{byte:02X}")?;
                }
            }
            return_swift_string(context, state, &encoded)?;
        }
        "$s10Foundation12URLQueryItemV4name5valueACSSh_SSSghtcfC" => {
            let output = context.reg_read(REG_X0 + 8)?;
            for index in 0..4 {
                write_guest_u64(
                    context,
                    output + index as u64 * 8,
                    context.reg_read(REG_X0 + index)?,
                )?;
            }
        }
        "$s10Foundation12URLQueryItemV4nameSSvg" => {
            let item = context.reg_read(REG_X0 + 20)?;
            context.reg_write(REG_X0, read_guest_u64(context, item)?)?;
            context.reg_write(REG_X0 + 1, read_guest_u64(context, item + 8)?)?;
        }
        "$s10Foundation12URLQueryItemV5valueSSSgvg" => {
            let item = context.reg_read(REG_X0 + 20)?;
            context.reg_write(REG_X0, read_guest_u64(context, item + 16)?)?;
            context.reg_write(REG_X0 + 1, read_guest_u64(context, item + 24)?)?;
        }
        "$sSa10FoundationE19_bridgeToObjectiveCSo7NSArrayCyF" => {
            let storage = context.reg_read(REG_X0)?;
            state.swift_query_array_metadata = Some(read_guest_u64(context, storage)?);
            let count = read_guest_u64(context, storage + 16)?;
            if count > 4096 {
                bail!("Swift array bridge exceeds item limit");
            }
            let items = (0..count)
                .map(|index| {
                    let element = storage + 32 + index * 32;
                    let name = swift_string(
                        context,
                        state,
                        read_guest_u64(context, element)?,
                        read_guest_u64(context, element + 8)?,
                    )?;
                    let value_words = (
                        read_guest_u64(context, element + 16)?,
                        read_guest_u64(context, element + 24)?,
                    );
                    let value = if value_words.1 == 0 {
                        0
                    } else {
                        let value = swift_string(context, state, value_words.0, value_words.1)?;
                        new_guest_object(
                            context,
                            profile,
                            state,
                            "NSString",
                            StoreValue::String(value),
                        )?
                    };
                    let name = new_guest_object(
                        context,
                        profile,
                        state,
                        "NSString",
                        StoreValue::String(name),
                    )?;
                    let item = new_guest_object(
                        context,
                        profile,
                        state,
                        "NSURLQueryItem",
                        StoreValue::Empty,
                    )?;
                    state
                        .objects
                        .get_mut(&item)
                        .expect("new query item")
                        .properties =
                        HashMap::from([("name".into(), name), ("value".into(), value)]);
                    Ok(item)
                })
                .collect::<Result<Vec<_>>>()?;
            let array = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(items),
            )?;
            context.reg_write(REG_X0, array)?;
        }
        "$sSa10FoundationE36_unconditionallyBridgeFromObjectiveCySayxGSo7NSArrayCSgFZ" => {
            let address = context.reg_read(REG_X0)?;
            let object = state
                .objects
                .get(&address)
                .context("unknown Swift array bridge input")?;
            let StoreValue::Addresses(items) = &object.value else {
                bail!("Swift array bridge input is not NSArray");
            };
            let items = items.clone();
            let empty = profile
                .index
                .symbols
                .get("_swiftEmptyArrayStorage")
                .context("missing Swift empty array storage")?;
            if items.is_empty() {
                context.reg_write(REG_X0, *empty)?;
            } else {
                let metadata = state
                    .swift_query_array_metadata
                    .context("Swift URLQueryItem array metadata is unavailable")?;
                let storage = state.allocate(32 + items.len() as u64 * 32)?;
                for (offset, value) in [metadata, 3, items.len() as u64, items.len() as u64]
                    .into_iter()
                    .enumerate()
                {
                    write_guest_u64(context, storage + offset as u64 * 8, value)?;
                }
                for (index, item) in items.into_iter().enumerate() {
                    let object = state
                        .objects
                        .get(&item)
                        .context("unknown Swift bridged query item")?;
                    if object.class != "NSURLQueryItem" {
                        bail!("Swift array bridge only supports URLQueryItem");
                    }
                    let name = object_string_value(state, object.properties["name"])?.to_owned();
                    let value = object
                        .properties
                        .get("value")
                        .copied()
                        .filter(|&address| address != 0)
                        .map(|address| object_string_value(state, address).map(str::to_owned))
                        .transpose()?;
                    let element = storage + 32 + index as u64 * 32;
                    return_swift_string(context, state, &name)?;
                    write_guest_u64(context, element, context.reg_read(REG_X0)?)?;
                    write_guest_u64(context, element + 8, context.reg_read(REG_X0 + 1)?)?;
                    if let Some(value) = value {
                        return_swift_string(context, state, &value)?;
                        write_guest_u64(context, element + 16, context.reg_read(REG_X0)?)?;
                        write_guest_u64(context, element + 24, context.reg_read(REG_X0 + 1)?)?;
                    } else {
                        write_guest_u64(context, element + 16, 0)?;
                        write_guest_u64(context, element + 24, 0)?;
                    }
                }
                context.reg_write(REG_X0, storage)?;
            }
        }
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
        "$ss18_DictionaryStorageC6resize8original8capacity4moveAByxq_Gs05__RawaB0C_SiSbtFZ" => {
            let capacity = context.reg_read(REG_X0 + 1)?;
            let storage_type = context.reg_read(REG_X0 + 3)?;
            let metadata = profile
                .index
                .swift_dictionaries
                .iter()
                .find(|(_, layout)| layout.metadata == storage_type)
                .and_then(|(key, _)| key.parse::<u64>().ok())
                .with_context(|| {
                    format!("unprepared Swift dictionary storage {storage_type:#x}")
                })?;
            let slot = state.allocate(8)?;
            write_guest_u64(
                context,
                slot,
                profile.index.symbols["_swiftEmptyDictionarySingleton"],
            )?;
            ensure_unique_dictionary(context, profile, state, slot, false, capacity, metadata)?;
            context.reg_write(REG_X0, read_guest_u64(context, slot)?)?;
        }
        "$ss11AnyHashableVwxx" | "$sSSwxx" => {}
        "$ss11AnyHashableVwcp" | "$ss11AnyHashableVwca" => {
            let destination = context.reg_read(REG_X0)?;
            let source = context.reg_read(REG_X0 + 1)?;
            let metadata = read_guest_u64(context, source + 24)?;
            if metadata != profile.index.bridges["anyHashableStringMetadata"] {
                bail!("unsupported Swift AnyHashable copy layout");
            }
            context.mem_write(destination, &context.mem_read(source, 40)?)?;
            context.reg_write(REG_X0, destination)?;
        }
        "$sSD10FoundationE36_unconditionallyBridgeFromObjectiveCySDyxq_GSo12NSDictionaryCSgFZ" => {
            let object = context.reg_read(REG_X0)?;
            let key_type = context.reg_read(REG_X0 + 1)?;
            let value_type = context.reg_read(REG_X0 + 2)?;
            let string = profile.index.symbols["$sSSN"];
            let any_hashable = profile.index.symbols["$ss11AnyHashableVN"];
            let any = profile.index.symbols["$sypN"] + 8;
            if !matches!(key_type, value if value == string || value == any_hashable)
                || !matches!(value_type, value if value == any || value == string)
            {
                bail!("unsupported Swift dictionary bridge metadata {key_type:#x}/{value_type:#x}");
            }
            bridge_dictionary_to_swift(context, profile, state, object, key_type, value_type)?;
        }
        "$sSD10FoundationE19_bridgeToObjectiveCSo12NSDictionaryCyF" => {
            let storage = context.reg_read(REG_X0)?;
            let key_type = context.reg_read(REG_X0 + 1)?;
            let value_type = context.reg_read(REG_X0 + 2)?;
            bridge_dictionary_to_objc(context, profile, state, storage, key_type, value_type)?;
        }
        "$ss38_bridgeAnythingNonVerbatimToObjectiveCyyXlxnlF" => {
            let source = context.reg_read(REG_X0)?;
            let metadata = context.reg_read(REG_X0 + 1)?;
            let (class, value) = if metadata == profile.index.symbols["$sSSN"] {
                let text = swift_string(
                    context,
                    state,
                    read_guest_u64(context, source)?,
                    read_guest_u64(context, source + 8)?,
                )?;
                ("NSString", StoreValue::String(text))
            } else if metadata == profile.index.symbols["$sSiN"] {
                (
                    "NSNumber",
                    StoreValue::Number(read_guest_u64(context, source)? as i64),
                )
            } else {
                bail!("unsupported nonverbatim Swift bridge metadata {metadata:#x}");
            };
            let object = new_guest_object(context, profile, state, class, value)?;
            context.reg_write(REG_X0, object)?;
        }
        "$s10Foundation22_convertErrorToNSErrorySo0E0Cs0C0_pF" => {
            let mut value = context.reg_read(REG_X0)?;
            let wrapper_metadata = profile
                .index
                .swift_types
                .get(&0x1a2e1c7fau64.to_string())
                .copied()
                .context("missing Swift NSError wrapper metadata")?;
            let mut result = None;
            for _ in 0..16 {
                let object = state
                    .objects
                    .get(&value)
                    .context("unknown Swift error value")?;
                if class_is_kind_of(profile, &object.class, "NSError") {
                    result = Some(value);
                    break;
                }
                if object.class != "HostSwiftError"
                    || object.properties.get("metadata") != Some(&wrapper_metadata)
                {
                    bail!("unsupported Swift error bridge {}", object.class);
                }
                value = read_guest_u64(context, object.properties["value"])?;
            }
            context.reg_write(REG_X0, result.context("recursive Swift error box")?)?;
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
            if address == 0 {
                return_swift_string(context, state, "")?;
                return Ok(());
            }
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
        "$s10ObjectiveC8SelectorV2eeoiySbAC_ACtFZ" => {
            context.reg_write(
                REG_X0,
                u64::from(context.reg_read(REG_X0)? == context.reg_read(REG_X0 + 1)?),
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
            } else if let Some((size, alignment)) = symbol
                .strip_prefix("swift_memcpy")
                .and_then(|suffix| suffix.split_once('_'))
            {
                let size = size.parse::<usize>().context("invalid Swift copy size")?;
                let alignment = alignment
                    .parse::<usize>()
                    .context("invalid Swift copy alignment")?;
                if size > 1024 || alignment == 0 || !alignment.is_power_of_two() {
                    bail!("unsupported Swift copy layout");
                }
                let destination = context.reg_read(REG_X0)?;
                let source = context.reg_read(REG_X0 + 1)?;
                context.mem_write(destination, &context.mem_read(source, size)?)?;
            } else if symbol.contains("NativeBoxIyLm8ELm8ELm8E")
                && symbol.contains("initializeBufferWithCopyOfBuffer")
            {
                let destination = context.reg_read(REG_X0)?;
                let source = context.reg_read(REG_X0 + 1)?;
                write_guest_u64(context, destination, read_guest_u64(context, source)?)?;
            } else if symbol.contains("BridgeObjectBox")
                && (symbol.contains("initializeWithCopy") || symbol.contains("assignWithCopy"))
            {
                let destination = context.reg_read(REG_X0)?;
                let source = context.reg_read(REG_X0 + 1)?;
                write_guest_u64(context, destination, read_guest_u64(context, source)?)?;
                context.reg_write(REG_X0, destination)?;
            } else if symbol.contains("BridgeObjectBox") && symbol.contains("destroy") {
            } else if (symbol.contains("SwiftRetainableBox")
                || symbol.contains("ObjCRetainableBox"))
                && symbol.contains("initializeBufferWithCopyOfBuffer")
            {
                let destination = context.reg_read(REG_X0)?;
                let source = context.reg_read(REG_X0 + 1)?;
                write_guest_u64(context, destination, read_guest_u64(context, source)?)?;
                context.reg_write(REG_X0, destination)?;
            } else if (symbol.contains("SwiftRetainableBox")
                || symbol.contains("ObjCRetainableBox"))
                && symbol.contains("7destroy")
            {
            } else if symbol.contains("tuple_initializeWithCopy")
                || symbol.contains("tuple_assignWithCopy")
            {
                let destination = context.reg_read(REG_X0)?;
                let source = context.reg_read(REG_X0 + 1)?;
                let metadata = context.reg_read(REG_X0 + 2)?;
                let witnesses = read_guest_u64(context, metadata - 8)?;
                let size = read_guest_u64(context, witnesses + 64)?;
                if size > 1024 {
                    bail!("tuple copy exceeds budget");
                }
                context.mem_write(destination, &context.mem_read(source, size as usize)?)?;
                context.reg_write(REG_X0, destination)?;
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

fn copy_and_queue_block(
    context: &HookContext,
    state: &mut StoreState,
    queue: u64,
    block: u64,
    group: Option<u64>,
) -> Result<()> {
    if block == 0 {
        bail!("cannot dispatch null block");
    }
    if let Some(group) = group {
        group_count(state, group)?;
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
                    group,
                },
            )?;
            return Ok(());
        }
        copied
    };
    queue_guest_block(state, copied, queue, group)?;
    context.reg_write(REG_X0, 0)?;
    Ok(())
}

fn queue_guest_block(
    state: &mut StoreState,
    block: u64,
    queue: u64,
    group: Option<u64>,
) -> Result<()> {
    if let Some(group) = group {
        let count = group_count(state, group)?;
        *count = count
            .checked_add(1)
            .context("guest dispatch group overflow")?;
    }
    state.pending.push(PendingWork::Guest {
        block,
        queue,
        group,
    });
    Ok(())
}

fn group_callback_action(group: Option<u64>, action: CallbackAction) -> CallbackAction {
    match group {
        Some(group) => CallbackAction::LeaveGroup {
            group,
            then: Box::new(action),
        },
        None => action,
    }
}

fn new_host_block(
    context: &HookContext,
    state: &mut StoreState,
    action: HostBlockAction,
) -> Result<u64> {
    let function = state.allocate(16)?;
    context.mem_write(function, &[0xc0, 0x03, 0x5f, 0xd6])?;
    state.host_blocks.insert(function, action);
    let descriptor = state.allocate(16)?;
    write_guest_u64(context, descriptor + 8, 32)?;
    let block = state.allocate(32)?;
    write_guest_u64(context, block + 8, 1 << 28)?;
    write_guest_u64(context, block + 16, function)?;
    write_guest_u64(context, block + 24, descriptor)?;
    Ok(block)
}

fn dispatch_host_block(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    action: HostBlockAction,
) -> Result<()> {
    match action {
        HostBlockAction::AcceptResponse { task } => {
            if context.reg_read(REG_X0 + 1)? != 1 {
                bail!("Store framework rejected HTTP response");
            }
            state.pending.push(PendingWork::DeliverData { task });
            context.reg_write(REG_X0, 0)?;
        }
        HostBlockAction::Redirect { task } => {
            let next = context.reg_read(REG_X0 + 1)?;
            if next == 0 {
                deliver_http_response(context, profile, state, task, CallbackAction::ReturnZero)?;
            } else {
                if !state.objects.contains_key(&next) {
                    bail!("invalid redirected Store request");
                }
                let task_object = state
                    .objects
                    .get_mut(&task)
                    .context("unknown redirected task")?;
                task_object.properties.insert("currentRequest".into(), next);
                let count = task_object
                    .properties
                    .entry("redirectCount".into())
                    .or_default();
                *count += 1;
                state.pending.push(PendingWork::Http { task });
                context.reg_write(REG_X0, 0)?;
            }
        }
    }
    Ok(())
}

fn selector_address_for_hook(
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
    let address = state.allocate((selector.len() + 1) as u64)?;
    context.mem_write(address, selector.as_bytes())?;
    context.mem_write(address + selector.len() as u64, &[0])?;
    state.dynamic_selectors.insert(selector.into(), address);
    state
        .dynamic_selector_addresses
        .insert(address, selector.into());
    Ok(address)
}

fn call_delegate(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    delegate: u64,
    selector: &str,
    arguments: &[u64],
    action: CallbackAction,
) -> Result<()> {
    call_delegate_inner(
        context,
        profile,
        state,
        delegate,
        DelegateCall {
            selector: selector.into(),
            arguments: arguments.to_vec(),
            action: Box::new(action),
            depth: 0,
        },
    )
}

fn purchase_encode_step(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    encode: PurchaseEncodeState,
) -> Result<()> {
    let PurchaseEncodeState {
        receiver,
        request,
        parameters,
        selector,
        properties,
        step,
    } = encode;
    const ENCODE: &str = "requestByEncodingRequestAndReturnSigningErrors:parameters:";
    if step == 7 {
        let implementation = method_address(profile, "AMSURLRequestEncoder", ENCODE, false)
            .context("Store profile lacks the base purchase encoder")?;
        return begin_callback(
            context,
            state,
            implementation,
            &[receiver, selector, request, parameters],
            CallbackAction::ReturnCurrentValue,
        );
    }
    let (target, method, arguments): (u64, &str, &[u64]) = match step {
        0 => (receiver, "setAnisetteType:", &[0]),
        1 => (receiver, "setMescalType:", &[0]),
        2 => (request, "properties", &[]),
        3 => (properties, "setAnisetteType:", &[0]),
        4 => (properties, "setMescalType:", &[0]),
        5 => (properties, "setDisableLoadURLMetrics:", &[1]),
        6 => (receiver, "setDisableLoadURLMetrics:", &[1]),
        _ => bail!("invalid purchase encoder step"),
    };
    if target == 0 {
        bail!(
            "purchase encoder has no request properties at step {step}: request={request:#x} receiver={receiver:#x}"
        );
    }
    call_delegate(
        context,
        profile,
        state,
        target,
        method,
        arguments,
        CallbackAction::PurchaseEncode(PurchaseEncodeState {
            receiver,
            request,
            parameters,
            selector,
            properties,
            step: step + 1,
        }),
    )
}

fn call_delegate_inner(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    delegate: u64,
    call: DelegateCall,
) -> Result<()> {
    let DelegateCall {
        selector,
        arguments,
        action,
        depth,
    } = call;
    let class_name = state
        .objects
        .get(&delegate)
        .context("missing Store transport delegate")?
        .class
        .clone();
    let selector_address = selector_address_for_hook(context, profile, state, &selector)?;
    let Some(entry) = method_address(profile, &class_name, &selector, false) else {
        if depth >= 8 {
            bail!("Store transport delegate forwarding loop");
        }
        let forward = method_address(profile, &class_name, "forwardingTargetForSelector:", false)
            .with_context(|| {
            format!("missing Store transport delegate method {class_name} {selector}")
        })?;
        let forward_selector =
            selector_address_for_hook(context, profile, state, "forwardingTargetForSelector:")?;
        return begin_callback(
            context,
            state,
            forward,
            &[delegate, forward_selector, selector_address],
            CallbackAction::ForwardDelegate {
                source: delegate,
                call: DelegateCall {
                    selector,
                    arguments,
                    action,
                    depth: depth + 1,
                },
            },
        );
    };
    let mut call_arguments = Vec::with_capacity(arguments.len() + 2);
    call_arguments.extend_from_slice(&[delegate, selector_address]);
    call_arguments.extend_from_slice(&arguments);
    begin_callback(context, state, entry, &call_arguments, *action)
}

fn perform_http(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    task: u64,
) -> Result<()> {
    let task_object = state
        .objects
        .get(&task)
        .context("unknown Store data task")?;
    let request = *task_object
        .properties
        .get("currentRequest")
        .context("Store data task has no request")?;
    let host_request = host_request_from_state(
        profile,
        state,
        request,
        state.transport_authenticated,
        true,
        state.transport_timeout,
    )?;
    let source_url = host_request.url.clone();
    let transport = Rc::clone(
        state
            .transport
            .as_ref()
            .context("Store HTTP transport is not configured")?,
    );
    let response = transport(host_request).context("send Store HTTP request")?;
    let status = response.status;
    let redirect_location = if matches!(status, 301 | 302 | 303 | 307 | 308) {
        response.header("location").map(str::to_owned)
    } else {
        None
    };
    if response.body.len() > 32 << 20 {
        bail!("Store API response exceeds size limit");
    }
    let mut header_values = HashMap::new();
    for (name, value) in &response.headers {
        header_values.insert(
            name.clone(),
            new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value.clone()),
            )?,
        );
    }
    let headers = new_guest_object(
        context,
        profile,
        state,
        "NSDictionary",
        StoreValue::Entries(header_values),
    )?;
    let mime = response
        .header("content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_owned();
    let mime = new_guest_object(
        context,
        profile,
        state,
        "NSString",
        StoreValue::String(mime),
    )?;
    let response_object = new_guest_object(
        context,
        profile,
        state,
        "NSHTTPURLResponse",
        StoreValue::Empty,
    )?;
    let request_url = state.objects[&request]
        .properties
        .get("URL")
        .copied()
        .unwrap_or(0);
    state
        .objects
        .get_mut(&response_object)
        .expect("new HTTP response")
        .properties
        .extend([
            ("statusCode".into(), u64::from(response.status)),
            ("allHeaderFields".into(), headers),
            ("URL".into(), request_url),
            ("MIMEType".into(), mime),
            ("expectedContentLength".into(), response.body.len() as u64),
        ]);
    state
        .objects
        .get_mut(&task)
        .expect("known data task")
        .properties
        .insert("response".into(), response_object);
    state.http_responses.insert(task, response);
    state.last_http_task = Some(task);
    if let Some(location) = redirect_location
        && !state.transport_no_redirects
    {
        return redirect_http_response(
            context,
            profile,
            state,
            RedirectResponse {
                task,
                request,
                response_object,
                source_url: &source_url,
                status,
                location: &location,
            },
        );
    }
    deliver_http_response(
        context,
        profile,
        state,
        task,
        CallbackAction::ReturnValue { value: 1 },
    )
}

fn deliver_http_response(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    task: u64,
    action: CallbackAction,
) -> Result<()> {
    let session = state.objects[&task].properties["session"];
    let delegate = state.objects[&session].properties["delegate"];
    let response_object = state.objects[&task].properties["response"];
    let completion = new_host_block(context, state, HostBlockAction::AcceptResponse { task })?;
    call_delegate(
        context,
        profile,
        state,
        delegate,
        "URLSession:dataTask:didReceiveResponse:completionHandler:",
        &[session, task, response_object, completion],
        action,
    )
}

struct RedirectResponse<'a> {
    task: u64,
    request: u64,
    response_object: u64,
    source_url: &'a url::Url,
    status: u16,
    location: &'a str,
}

fn redirect_http_response(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    RedirectResponse {
        task,
        request,
        response_object,
        source_url,
        status,
        location,
    }: RedirectResponse<'_>,
) -> Result<()> {
    let destination = source_url
        .join(location)
        .context("invalid Store redirect location")?;
    if !allowed_store_url(&destination, state.transport_authenticated) {
        bail!("invalid Store redirect destination");
    }
    let count = state.objects[&task]
        .properties
        .get("redirectCount")
        .copied()
        .unwrap_or(0);
    if count >= 4 {
        bail!("Store redirect limit exceeded");
    }
    let request_properties = state.objects[&request].properties.clone();
    let method = object_string_value(
        state,
        request_properties.get("HTTPMethod").copied().unwrap_or(0),
    )?
    .to_owned();
    let mut headers = match request_properties
        .get("allHTTPHeaderFields")
        .and_then(|address| state.objects.get(address))
    {
        Some(StoreObject {
            value: StoreValue::Entries(entries),
            ..
        }) => entries.clone(),
        _ => HashMap::new(),
    };
    if destination.host_str() != source_url.host_str() {
        headers.retain(|name, _| {
            ![
                "Authorization",
                "Cookie",
                "X-Token",
                "X-Dsid",
                "Icloud-Dsid",
            ]
            .iter()
            .any(|secret| name.eq_ignore_ascii_case(secret))
        });
    }
    let change_to_get = status == 303 || (matches!(status, 301 | 302) && method == "POST");
    if change_to_get {
        headers.retain(|name, _| {
            !["Content-Length", "Content-Type"]
                .iter()
                .any(|header| name.eq_ignore_ascii_case(header))
        });
    }
    let url = new_guest_object(
        context,
        profile,
        state,
        "NSURL",
        StoreValue::String(destination.to_string()),
    )?;
    let headers = new_guest_object(
        context,
        profile,
        state,
        "NSMutableDictionary",
        StoreValue::Entries(headers),
    )?;
    let proposed = new_guest_object(
        context,
        profile,
        state,
        "NSMutableURLRequest",
        StoreValue::Empty,
    )?;
    let mut properties = request_properties;
    properties.insert("URL".into(), url);
    properties.insert("allHTTPHeaderFields".into(), headers);
    if change_to_get {
        let method = new_guest_object(
            context,
            profile,
            state,
            "NSString",
            StoreValue::String("GET".into()),
        )?;
        properties.insert("HTTPMethod".into(), method);
        properties.insert("HTTPBody".into(), 0);
    }
    state
        .objects
        .get_mut(&proposed)
        .expect("new redirected request")
        .properties = properties;
    let completion = new_host_block(context, state, HostBlockAction::Redirect { task })?;
    let session = state.objects[&task].properties["session"];
    let delegate = state.objects[&session].properties["delegate"];
    call_delegate(
        context,
        profile,
        state,
        delegate,
        "URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:",
        &[session, task, response_object, proposed, completion],
        CallbackAction::ReturnValue { value: 1 },
    )
}

fn deliver_http_data(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    task: u64,
) -> Result<()> {
    let object = state
        .objects
        .get(&task)
        .context("unknown Store data task")?;
    let session = object.properties["session"];
    let delegate = state.objects[&session].properties["delegate"];
    let bytes = state
        .http_responses
        .get(&task)
        .context("missing Store HTTP response")?
        .body
        .clone();
    let data = new_guest_object(context, profile, state, "NSData", StoreValue::Bytes(bytes))?;
    call_delegate(
        context,
        profile,
        state,
        delegate,
        "URLSession:dataTask:didReceiveData:",
        &[session, task, data],
        CallbackAction::ScheduleComplete { task },
    )
}

fn complete_http_task(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    task: u64,
) -> Result<()> {
    let object = state
        .objects
        .get_mut(&task)
        .context("unknown Store data task")?;
    object.properties.insert("state".into(), 3);
    let session = object.properties["session"];
    let delegate = state.objects[&session].properties["delegate"];
    call_delegate(
        context,
        profile,
        state,
        delegate,
        "URLSession:task:didCompleteWithError:",
        &[session, task, 0],
        CallbackAction::ReturnValue { value: 1 },
    )
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
    let resume = install_callback_resume(context, state, action)?;
    for (index, &value) in arguments.iter().enumerate() {
        context.reg_write(REG_X0 + index as i32, value)?;
    }
    context.reg_write(REG_LR, resume)?;
    context.reg_write(REG_PC, function)?;
    Ok(())
}

fn install_callback_resume(
    context: &HookContext,
    state: &mut StoreState,
    action: CallbackAction,
) -> Result<u64> {
    let link = context.reg_read(REG_LR)?;
    let resume = state.allocate(16)?;
    context.mem_write(resume, &[0xc0, 0x03, 0x5f, 0xd6])?;
    state
        .callbacks
        .insert(resume, CallbackResume { link, action });
    Ok(resume)
}

fn start_swift_task(
    context: &HookContext,
    state: &mut StoreState,
    handle: u64,
    poll_after: Option<(u64, u64)>,
    semaphore_after: Option<u64>,
    group_after: Option<(u64, u64)>,
) -> Result<()> {
    let task = state
        .swift_tasks
        .get(&handle)
        .context("unknown Swift task")?;
    if task.done {
        bail!("attempt to restart completed Swift task");
    }
    let (task_context, entry, closure, result) =
        (task.context, task.entry, task.closure, task.result);
    let mut saved = Vec::with_capacity(15);
    for register in [REG_SP, REG_LR, REG_X29]
        .into_iter()
        .chain((19..=28).map(|index| REG_X0 + index))
    {
        saved.push((register, context.reg_read(register)?));
    }
    let previous = state.current_swift_task.replace(handle);
    let completion = state.allocate(16)?;
    context.mem_write(completion, &[0xc0, 0x03, 0x5f, 0xd6])?;
    state.callbacks.insert(
        completion,
        CallbackResume {
            link: context.reg_read(REG_LR)?,
            action: CallbackAction::CompleteSwiftTask {
                task: handle,
                previous,
                saved,
                poll_after,
                semaphore_after,
                group_after,
            },
        },
    );
    write_guest_u64(context, task_context, 0)?;
    write_guest_u64(context, task_context + 8, completion)?;
    write_guest_u64(context, task_context - 32, result)?;
    write_guest_u64(context, task_context - 24, entry)?;
    write_guest_u64(context, task_context - 16, closure)?;
    context.reg_write(REG_X0, result)?;
    context.reg_write(REG_X0 + 20, closure)?;
    context.reg_write(REG_X0 + 21, 0)?;
    context.reg_write(REG_X0 + 22, task_context)?;
    context.reg_write(REG_PC, entry)?;
    Ok(())
}

fn start_notification_callback(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    observers: Vec<(u64, u64)>,
    index: usize,
    notification: u64,
) -> Result<()> {
    let Some(&(receiver, selector_address)) = observers.get(index) else {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    };
    let selector = guest_cstring(context, profile, state, selector_address)?;
    let class_name = &state
        .objects
        .get(&receiver)
        .context("notification observer is unavailable")?
        .class;
    let function = method_address(profile, class_name, &selector, false)
        .with_context(|| format!("missing notification handler {class_name} {selector}"))?;
    begin_callback(
        context,
        state,
        function,
        &[receiver, selector_address, notification],
        CallbackAction::NotificationNext {
            observers,
            index: index + 1,
            notification,
        },
    )
}

fn semaphore_count(state: &mut StoreState, address: u64) -> Result<&mut i64> {
    let object = state
        .objects
        .get_mut(&address)
        .context("unknown guest semaphore")?;
    if object.class != "HostSemaphore" {
        bail!("invalid guest semaphore");
    }
    match &mut object.value {
        StoreValue::Number(count) => Ok(count),
        _ => bail!("invalid guest semaphore count"),
    }
}

fn consume_signaled_semaphore(state: &mut StoreState, address: u64) -> Result<()> {
    let count = semaphore_count(state, address)?;
    if *count <= 0 {
        bail!("guest semaphore remains unsignaled");
    }
    *count -= 1;
    Ok(())
}

fn group_count(state: &mut StoreState, address: u64) -> Result<&mut i64> {
    let object = state
        .objects
        .get_mut(&address)
        .context("unknown guest dispatch group")?;
    if object.class != "HostDispatchGroup" {
        bail!("invalid guest dispatch group");
    }
    match &mut object.value {
        StoreValue::Number(count) if *count >= 0 => Ok(count),
        _ => bail!("invalid guest dispatch group count"),
    }
}

fn take_runnable_pending(state: &mut StoreState) -> Option<PendingWork> {
    let index = state.pending.iter().position(|work| match work {
        PendingWork::Guest { queue, .. } => state
            .objects
            .get(queue)
            .and_then(|object| object.properties.get("suspendCount"))
            .is_none_or(|count| *count == 0),
        _ => true,
    })?;
    Some(state.pending.remove(index))
}

fn dispatch_pending_for_semaphore(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    semaphore: u64,
    work: PendingWork,
) -> Result<()> {
    match work {
        PendingWork::Guest {
            block,
            queue,
            group,
        } => {
            let previous_queue = std::mem::replace(&mut state.current_queue, queue);
            begin_callback(
                context,
                state,
                read_guest_u64(context, block + 16)?,
                &[block],
                group_callback_action(
                    group,
                    CallbackAction::SemaphoreWait {
                        semaphore,
                        previous_queue,
                    },
                ),
            )
        }
        PendingWork::SwiftTask { task } => {
            start_swift_task(context, state, task, None, Some(semaphore), None)
        }
        work => {
            let resume = install_callback_resume(
                context,
                state,
                CallbackAction::SemaphoreWait {
                    semaphore,
                    previous_queue: state.current_queue,
                },
            )?;
            context.reg_write(REG_LR, resume)?;
            match work {
                PendingWork::Http { task } => perform_http(context, profile, state, task),
                PendingWork::DeliverData { task } => {
                    deliver_http_data(context, profile, state, task)
                }
                PendingWork::Complete { task } => complete_http_task(context, profile, state, task),
                _ => unreachable!(),
            }
        }
    }
}

fn poll_dispatch_group(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    group: u64,
    timeout: u64,
) -> Result<()> {
    if *group_count(state, group)? == 0 {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if timeout == 0
        || (timeout != u64::MAX
            && timeout <= time::OffsetDateTime::now_utc().unix_timestamp_nanos() as u64)
    {
        context.reg_write(REG_X0, 1)?;
        return Ok(());
    }
    let Some(work) = take_runnable_pending(state) else {
        if timeout == u64::MAX {
            bail!("guest dispatch group has no runnable completion");
        }
        context.reg_write(REG_X0, 1)?;
        return Ok(());
    };
    dispatch_pending_for_group(context, profile, state, group, timeout, work)
}

fn dispatch_pending_for_group(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    group: u64,
    timeout: u64,
    work: PendingWork,
) -> Result<()> {
    match work {
        PendingWork::Guest {
            block,
            queue,
            group: work_group,
        } => {
            let previous_queue = std::mem::replace(&mut state.current_queue, queue);
            begin_callback(
                context,
                state,
                read_guest_u64(context, block + 16)?,
                &[block],
                group_callback_action(
                    work_group,
                    CallbackAction::GroupWait {
                        group,
                        timeout,
                        previous_queue,
                    },
                ),
            )
        }
        PendingWork::SwiftTask { task } => {
            start_swift_task(context, state, task, None, None, Some((group, timeout)))
        }
        work => {
            let resume = install_callback_resume(
                context,
                state,
                CallbackAction::GroupWait {
                    group,
                    timeout,
                    previous_queue: state.current_queue,
                },
            )?;
            context.reg_write(REG_LR, resume)?;
            match work {
                PendingWork::Http { task } => perform_http(context, profile, state, task),
                PendingWork::DeliverData { task } => {
                    deliver_http_data(context, profile, state, task)
                }
                PendingWork::Complete { task } => complete_http_task(context, profile, state, task),
                _ => unreachable!(),
            }
        }
    }
}

fn poll_swift_continuation(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    task: u64,
    continuation: u64,
) -> Result<()> {
    if read_guest_u64(context, continuation + 24)? == 2 {
        state
            .swift_tasks
            .get_mut(&task)
            .expect("current task")
            .continuation = None;
        state.current_swift_task = Some(task);
        context.reg_write(REG_X0 + 22, continuation)?;
        context.reg_write(REG_PC, read_guest_u64(context, continuation + 8)?)?;
        return Ok(());
    }
    let Some(work) = take_runnable_pending(state) else {
        bail!("Swift continuation has no runnable completion");
    };
    match work {
        PendingWork::Guest {
            block,
            queue,
            group,
        } => {
            let previous_queue = std::mem::replace(&mut state.current_queue, queue);
            state.current_swift_task = None;
            begin_callback(
                context,
                state,
                read_guest_u64(context, block + 16)?,
                &[block],
                group_callback_action(
                    group,
                    CallbackAction::PollSwiftContinuation {
                        task,
                        continuation,
                        previous_queue,
                    },
                ),
            )
        }
        PendingWork::SwiftTask { task: child } => {
            state.current_swift_task = None;
            start_swift_task(
                context,
                state,
                child,
                Some((task, continuation)),
                None,
                None,
            )
        }
        work => {
            // The transport helpers start guest callbacks. Route their return
            // through this poll trampoline so the awaited continuation can
            // process the next completion or resume once its result arrives.
            let resume = install_callback_resume(
                context,
                state,
                CallbackAction::PollSwiftContinuation {
                    task,
                    continuation,
                    previous_queue: state.current_queue,
                },
            )?;
            state.current_swift_task = None;
            context.reg_write(REG_LR, resume)?;
            match work {
                PendingWork::Http { task } => perform_http(context, profile, state, task),
                PendingWork::DeliverData { task } => {
                    deliver_http_data(context, profile, state, task)
                }
                PendingWork::Complete { task } => complete_http_task(context, profile, state, task),
                _ => unreachable!(),
            }
        }
    }
}

fn resume_callback(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    resume: CallbackResume,
) -> Result<()> {
    match resume.action {
        CallbackAction::ReturnZero => context.reg_write(REG_X0, 0)?,
        CallbackAction::ReturnCurrentValue => {}
        CallbackAction::ReturnValue { value } => context.reg_write(REG_X0, value)?,
        CallbackAction::PurchaseEncode(PurchaseEncodeState {
            receiver,
            request,
            parameters,
            selector,
            properties,
            step,
        }) => {
            let properties = if step == 3 {
                let value = context.reg_read(REG_X0)?;
                if value == 0 {
                    let object = state.objects.get(&request);
                    bail!(
                        "purchase request properties getter returned nil: class={:?} properties={:?}",
                        object.map(|object| &object.class),
                        object.map(|object| &object.properties)
                    );
                }
                value
            } else {
                properties
            };
            context.reg_write(REG_LR, resume.link)?;
            purchase_encode_step(
                context,
                profile,
                state,
                PurchaseEncodeState {
                    receiver,
                    request,
                    parameters,
                    selector,
                    properties,
                    step,
                },
            )?;
            return Ok(());
        }
        CallbackAction::QueueBlock {
            block,
            queue,
            group,
        } => {
            queue_guest_block(state, block, queue, group)?;
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::LeaveGroup { group, then } => {
            let count = group_count(state, group)?;
            if *count <= 0 {
                bail!("guest dispatch group leave without enter");
            }
            *count -= 1;
            return resume_callback(
                context,
                profile,
                state,
                CallbackResume {
                    link: resume.link,
                    action: *then,
                },
            );
        }
        CallbackAction::ScheduleComplete { task } => {
            state.pending.push(PendingWork::Complete { task });
            context.reg_write(REG_X0, 1)?;
        }
        CallbackAction::ForwardDelegate { source, call } => {
            let target = context.reg_read(REG_X0)?;
            if target == 0 || target == source {
                bail!("Store transport delegate cannot forward {}", call.selector);
            }
            context.reg_write(REG_LR, resume.link)?;
            call_delegate_inner(context, profile, state, target, call)?;
            return Ok(());
        }
        CallbackAction::SortArray {
            mut items,
            block,
            mut i,
            mut j,
        } => {
            if (context.reg_read(REG_X0)? as i64) > 0 {
                items.swap(j - 1, j);
                j -= 1;
            } else {
                i += 1;
                j = i;
            }
            while i < items.len() && j == 0 {
                i += 1;
                j = i;
            }
            if i < items.len() {
                context.reg_write(REG_LR, resume.link)?;
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, block + 16)?,
                    &[block, items[j - 1], items[j]],
                    CallbackAction::SortArray { items, block, i, j },
                )?;
                return Ok(());
            }
            let sorted = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(items),
            )?;
            context.reg_write(REG_X0, sorted)?;
        }
        CallbackAction::NotificationNext {
            observers,
            index,
            notification,
        } => {
            if index < observers.len() {
                context.reg_write(REG_LR, resume.link)?;
                start_notification_callback(
                    context,
                    profile,
                    state,
                    observers,
                    index,
                    notification,
                )?;
                return Ok(());
            }
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
        CallbackAction::DictionaryCopy {
            receiver,
            keys,
            index,
            key,
        } => {
            let value = context.reg_read(REG_X0)?;
            let StoreValue::Entries(entries) = &mut state.objects.get_mut(&receiver).unwrap().value
            else {
                bail!("dictionary copy target is not a dictionary");
            };
            entries.insert(key, value);
            context.reg_write(REG_LR, resume.link)?;
            if copy_dictionary_items(context, profile, state, receiver, keys, index)? {
                return Ok(());
            }
        }
        CallbackAction::RestoreQueue { previous } => {
            state.current_queue = previous;
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::RestoreQueueWithValue { previous, value } => {
            state.current_queue = previous;
            context.reg_write(REG_X0, value)?;
        }
        CallbackAction::SemaphoreWait {
            semaphore,
            previous_queue,
        } => {
            state.current_queue = previous_queue;
            consume_signaled_semaphore(state, semaphore)?;
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::GroupWait {
            group,
            timeout,
            previous_queue,
        } => {
            state.current_queue = previous_queue;
            context.reg_write(REG_LR, resume.link)?;
            context.reg_write(REG_PC, resume.link)?;
            poll_dispatch_group(context, profile, state, group, timeout)?;
            return Ok(());
        }
        CallbackAction::CopyProperty { destination } => {
            let value = context.reg_read(REG_X0)?;
            write_guest_u64(context, destination, value)?;
            context.reg_write(REG_X0, 0)?;
        }
        CallbackAction::CompleteSwiftTask {
            task,
            previous,
            saved,
            poll_after,
            semaphore_after,
            group_after,
        } => {
            let task = state
                .swift_tasks
                .get_mut(&task)
                .context("completed unknown Swift task")?;
            if task.done {
                bail!("Swift task completed twice");
            }
            task.done = true;
            state.current_swift_task = previous;
            let link = saved
                .iter()
                .find(|(register, _)| *register == REG_LR)
                .map(|(_, value)| *value)
                .context("Swift task lacks saved return address")?;
            for (register, value) in saved {
                context.reg_write(register, value)?;
            }
            context.reg_write(
                REG_X0,
                u64::from(
                    poll_after.is_none() && semaphore_after.is_none() && group_after.is_none(),
                ),
            )?;
            if let Some((parent, continuation)) = poll_after {
                state.current_swift_task = Some(parent);
                poll_swift_continuation(context, profile, state, parent, continuation)?;
            } else {
                if let Some(semaphore) = semaphore_after {
                    consume_signaled_semaphore(state, semaphore)?;
                }
                context.reg_write(REG_PC, link)?;
                if let Some((group, timeout)) = group_after {
                    poll_dispatch_group(context, profile, state, group, timeout)?;
                }
            }
            return Ok(());
        }
        CallbackAction::PollSwiftContinuation {
            task,
            continuation,
            previous_queue,
        } => {
            state.current_queue = previous_queue;
            state.current_swift_task = Some(task);
            context.reg_write(REG_LR, resume.link)?;
            poll_swift_continuation(context, profile, state, task, continuation)?;
            return Ok(());
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

fn mutable_swift_request(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
) -> Result<u64> {
    let self_address = context.reg_read(REG_X0 + 20)?;
    let source = read_guest_u64(context, self_address)?;
    let object = state
        .objects
        .get(&source)
        .context("invalid Swift request storage")?;
    let (class, value, properties) = (
        object.class.clone(),
        object.value.clone(),
        object.properties.clone(),
    );
    let copied = new_guest_object(context, profile, state, &class, value)?;
    if let Some(&index) = profile.runtime.classes_by_name.get(&class) {
        let size = profile.index.classes[index].size.max(16);
        context.mem_write(copied, &context.mem_read(source, size as usize)?)?;
    }
    state
        .objects
        .get_mut(&copied)
        .expect("new Swift request")
        .properties = properties.clone();
    if let Some(&headers) = properties.get("allHTTPHeaderFields")
        && let StoreValue::Entries(entries) = &state.objects[&headers].value
    {
        let headers = new_guest_object(
            context,
            profile,
            state,
            "NSMutableDictionary",
            StoreValue::Entries(entries.clone()),
        )?;
        state
            .objects
            .get_mut(&copied)
            .expect("new Swift request")
            .properties
            .insert("allHTTPHeaderFields".into(), headers);
    }
    write_guest_u64(context, self_address, copied)?;
    Ok(copied)
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

fn bridge_dictionary_to_swift(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    object: u64,
    key_type: u64,
    value_type: u64,
) -> Result<()> {
    let empty = profile.index.symbols["_swiftEmptyDictionarySingleton"];
    let entries = if object == 0 {
        HashMap::new()
    } else {
        let StoreValue::Entries(entries) = &state
            .objects
            .get(&object)
            .context("unknown Objective-C dictionary")?
            .value
        else {
            bail!("Swift dictionary bridge source is not a dictionary");
        };
        entries.clone()
    };
    if entries.is_empty() {
        context.reg_write(REG_X0, empty)?;
        return Ok(());
    }
    let string = profile.index.symbols["$sSSN"];
    let any_hashable = profile.index.symbols["$ss11AnyHashableVN"];
    let (type_ref, key_stride, value_stride) = if key_type == any_hashable {
        (0x1a2e1db1au64, 40u64, 32u64)
    } else if value_type == string {
        if key_type != string {
            bail!("unsupported typed Swift dictionary bridge");
        }
        (0x1a2e1d7c6u64, 16, 16)
    } else {
        (0x1a2e1d5d6u64, 16, 32)
    };
    let metadata = profile
        .index
        .swift_types
        .get(&type_ref.to_string())
        .copied()
        .context("Swift dictionary metadata is not prepared")?;
    let slot = state.allocate(8)?;
    write_guest_u64(context, slot, empty)?;
    ensure_unique_dictionary(
        context,
        profile,
        state,
        slot,
        false,
        entries.len() as u64,
        metadata,
    )?;
    let storage = read_guest_u64(context, slot)?;
    let keys = read_guest_u64(context, storage + 48)?;
    let values = read_guest_u64(context, storage + 56)?;
    let seed = read_guest_u64(context, storage + 40)?;
    let buckets = 1u64 << (read_guest_u64(context, storage + 32)? as u8);
    let mut names = entries.keys().collect::<Vec<_>>();
    names.sort();
    for name in names {
        let hasher = state.allocate(72)?;
        init_hasher(context, profile, hasher, seed)?;
        let mut bytes = name.nfc().collect::<String>().into_bytes();
        bytes.push(255);
        hash_bytes(context, hasher, &bytes)?;
        let hash = hash_compress(context, hasher, read_guest_u64(context, hasher)?, true)?;
        let mut index = hash & (buckets - 1);
        while read_guest_u64(context, storage + 64 + (index / 64) * 8)? & (1 << (index % 64)) != 0 {
            index = (index + 1) & (buckets - 1);
        }
        let bitmap = storage + 64 + (index / 64) * 8;
        write_guest_u64(
            context,
            bitmap,
            read_guest_u64(context, bitmap)? | (1 << (index % 64)),
        )?;
        return_swift_string(context, state, name)?;
        write_guest_u64(
            context,
            keys + index * key_stride,
            context.reg_read(REG_X0)?,
        )?;
        write_guest_u64(
            context,
            keys + index * key_stride + 8,
            context.reg_read(REG_X0 + 1)?,
        )?;
        if key_stride == 40 {
            write_guest_u64(
                context,
                keys + index * key_stride + 24,
                profile.index.bridges["anyHashableStringMetadata"],
            )?;
            write_guest_u64(
                context,
                keys + index * key_stride + 32,
                profile.index.bridges["anyHashableStringWitness"],
            )?;
        }
        let destination = values + index * value_stride;
        let value = entries[name];
        if value_stride == 16 {
            let StoreValue::String(text) = &state
                .objects
                .get(&value)
                .context("missing typed Swift dictionary value")?
                .value
            else {
                bail!("non-string value in typed Swift dictionary");
            };
            let text = text.clone();
            return_swift_string(context, state, &text)?;
            write_guest_u64(context, destination, context.reg_read(REG_X0)?)?;
            write_guest_u64(context, destination + 8, context.reg_read(REG_X0 + 1)?)?;
        } else {
            store_swift_any(context, profile, state, destination, value)?;
        }
    }
    write_guest_u64(context, storage + 16, entries.len() as u64)?;
    context.reg_write(REG_X0, storage)?;
    Ok(())
}

fn store_swift_any(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    destination: u64,
    address: u64,
) -> Result<()> {
    let object = state
        .objects
        .get(&address)
        .context("unknown object bridged to Swift Any")?;
    let class = object.class.clone();
    let value = object.value.clone();
    let metadata = match value {
        StoreValue::String(text) => {
            return_swift_string(context, state, &text)?;
            write_guest_u64(context, destination, context.reg_read(REG_X0)?)?;
            write_guest_u64(context, destination + 8, context.reg_read(REG_X0 + 1)?)?;
            profile.index.symbols["$sSSN"]
        }
        StoreValue::Number(number) => {
            write_guest_u64(context, destination, number as u64)?;
            profile.index.symbols["$sSiN"]
        }
        StoreValue::Boolean(boolean) => {
            write_guest_u64(context, destination, u64::from(boolean))?;
            profile.index.symbols["$sSbN"]
        }
        StoreValue::Float(float) => {
            write_guest_u64(context, destination, float.to_bits())?;
            profile.index.symbols["$sSdN"]
        }
        _ => {
            let metadata_class = if class.contains("Dictionary") {
                "NSDictionary"
            } else if class.contains("Array") {
                "NSArray"
            } else if class.contains("Data") {
                "NSData"
            } else {
                &class
            };
            write_guest_u64(context, destination, address)?;
            *profile
                .index
                .objc_metadata
                .get(metadata_class)
                .with_context(|| format!("unprepared Swift Any metadata for {metadata_class}"))?
        }
    };
    if metadata == 0 {
        bail!("unprepared Swift Any metadata");
    }
    write_guest_u64(context, destination + 24, metadata)
}

fn bridge_dictionary_to_objc(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    storage: u64,
    key_type: u64,
    value_type: u64,
) -> Result<()> {
    let count = read_guest_u64(context, storage + 16)?;
    let mut entries = HashMap::new();
    if count != 0 {
        let string = profile.index.symbols["$sSSN"];
        if key_type != string || value_type != string {
            bail!(
                "unsupported Swift dictionary Objective-C bridge types {key_type:#x}/{value_type:#x}"
            );
        }
        let exponent = read_guest_u64(context, storage + 32)? & 255;
        if count > 768 || exponent > 10 {
            bail!("Swift dictionary bridge exceeds budget");
        }
        let keys = read_guest_u64(context, storage + 48)?;
        let values = read_guest_u64(context, storage + 56)?;
        let buckets = 1u64 << exponent;
        for index in 0..buckets {
            if read_guest_u64(context, storage + 64 + (index / 64) * 8)? & (1 << (index % 64)) == 0
            {
                continue;
            }
            let key = swift_string(
                context,
                state,
                read_guest_u64(context, keys + index * 16)?,
                read_guest_u64(context, keys + index * 16 + 8)?,
            )?;
            let value = swift_string(
                context,
                state,
                read_guest_u64(context, values + index * 16)?,
                read_guest_u64(context, values + index * 16 + 8)?,
            )?;
            let value = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            entries.insert(key, value);
        }
        if entries.len() != count as usize {
            bail!("Swift dictionary count mismatch");
        }
    }
    let dictionary = new_guest_object(
        context,
        profile,
        state,
        "NSDictionary",
        StoreValue::Entries(entries),
    )?;
    context.reg_write(REG_X0, dictionary)
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
                } else if let Some(class_name) = profile.runtime.class_names_by_address.get(&value)
                {
                    class_name.clone()
                } else {
                    let object = state.objects.get(&value).context("unknown format object")?;
                    match &object.value {
                        StoreValue::String(value) => value.clone(),
                        StoreValue::Number(value) => value.to_string(),
                        StoreValue::Float(value) => value.to_string(),
                        StoreValue::Boolean(value) => value.to_string(),
                        _ => object.class.clone(),
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
    if !class_method
        && selector == "copy"
        && let Some(entry) = method_address(profile, &class_name, "copyWithZone:", false)
    {
        let zone_selector = selector_address_for_hook(context, profile, state, "copyWithZone:")?;
        context.reg_write(REG_X0 + 1, zone_selector)?;
        context.reg_write(REG_X0 + 2, 0)?;
        context.reg_write(REG_PC, entry)?;
        return Ok(());
    }
    if !class_method && class_name == "NSURLSessionDataTask" && selector == "_timingData" {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method
        && ((class_name == "NSURLSessionDataTask" && selector == "cancel")
            || (class_name == "NSURLSession"
                && matches!(selector, "invalidateAndCancel" | "finishTasksAndInvalidate")))
    {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSURLSessionConfiguration"
        && matches!(
            selector,
            "_allowsTCPFastOpen" | "_allowsTLSSessionTickets" | "URLCache"
        )
    {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if class_method && class_name == "NSURLCache" && selector == "sharedURLCache" {
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method && class_name == "NSHTTPURLResponse" && selector == "_CFURLResponse" {
        context.reg_write(REG_X0, receiver)?;
        return Ok(());
    }
    if !class_method
        && class_name == "AMSPurchaseRequestEncoder"
        && selector == "requestByEncodingRequestAndReturnSigningErrors:parameters:"
    {
        let request = context.reg_read(REG_X0 + 2)?;
        let parameters = context.reg_read(REG_X0 + 3)?;
        return purchase_encode_step(
            context,
            profile,
            state,
            PurchaseEncodeState {
                receiver,
                request,
                parameters,
                selector: selector_address,
                properties: 0,
                step: 0,
            },
        );
    }
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
    if class_method && selector == "instanceMethodForSelector:" {
        let target = guest_cstring(context, profile, state, context.reg_read(REG_X0 + 2)?)?;
        let method = method_address(profile, &class_name, &target, false).unwrap_or(0);
        context.reg_write(REG_X0, method)?;
        return Ok(());
    }
    if !class_method && matches!(class_name.as_str(), "ACAccountStore" | "ACDAccountStore") {
        if matches!(
            selector,
            "accounts"
                | "accountsWithAccountType:"
                | "accountsWithAccountType:options:error:"
                | "accountsWithAccountType:options:classification:error:"
        ) {
            let error_register = match selector {
                "accountsWithAccountType:options:error:" => Some(REG_X0 + 4),
                "accountsWithAccountType:options:classification:error:" => Some(REG_X0 + 5),
                _ => None,
            };
            if let Some(register) = error_register {
                let error = context.reg_read(register)?;
                if error != 0 {
                    write_guest_u64(context, error, 0)?;
                }
            }
            let accounts = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(Vec::new()),
            )?;
            context.reg_write(REG_X0, accounts)?;
            return Ok(());
        }
        if matches!(
            selector,
            "accountTypeWithAccountTypeIdentifier:" | "accountTypeWithAccountTypeIdentifier:error:"
        ) {
            let identifier = context.reg_read(REG_X0 + 2)?;
            let account_type =
                new_guest_object(context, profile, state, "ACAccountType", StoreValue::Empty)?;
            state
                .objects
                .get_mut(&account_type)
                .expect("new account type")
                .properties
                .insert("identifier".into(), identifier);
            if selector.ends_with(":error:") {
                let error = context.reg_read(REG_X0 + 3)?;
                if error != 0 {
                    write_guest_u64(context, error, 0)?;
                }
            }
            context.reg_write(REG_X0, account_type)?;
            return Ok(());
        }
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
    if !class_method
        && class_name == "RBSProcessHandle"
        && matches!(selector, "isManaged" | "isDaemon" | "isXPCService")
    {
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
    if !class_method && class_name == "NSURL" && selector == "absoluteString" {
        let value = object_string_value(state, receiver)?.to_owned();
        let string = new_guest_object(
            context,
            profile,
            state,
            "NSString",
            StoreValue::String(value),
        )?;
        context.reg_write(REG_X0, string)?;
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
        && matches!(
            selector,
            "initWithURL:resolvingAgainstBaseURL:" | "initWithString:"
        )
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
    if !class_method
        && class_name == "NSURLComponents"
        && matches!(selector, "setQueryItems:" | "setPercentEncodedQueryItems:")
    {
        let array = context.reg_read(REG_X0 + 2)?;
        let items = if array == 0 {
            Vec::new()
        } else {
            let StoreValue::Addresses(items) = &state
                .objects
                .get(&array)
                .context("unknown URL query items")?
                .value
            else {
                bail!("URL query items are not an array");
            };
            items.clone()
        };
        let encode = |value: &str| -> String {
            if selector == "setPercentEncodedQueryItems:" {
                value.to_owned()
            } else {
                url::form_urlencoded::byte_serialize(value.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20")
            }
        };
        let mut parts = Vec::with_capacity(items.len());
        for item in items {
            let properties = &state
                .objects
                .get(&item)
                .context("unknown URL query item")?
                .properties;
            let name = encode(object_string_value(state, properties["name"])?);
            let value = properties.get("value").copied().unwrap_or(0);
            parts.push(if value == 0 {
                name
            } else {
                format!("{name}={}", encode(object_string_value(state, value)?))
            });
        }
        let mut url = url::Url::parse(object_string_value(state, receiver)?)?;
        url.set_query(Some(&parts.join("&")));
        state
            .objects
            .get_mut(&receiver)
            .expect("known URL components")
            .value = StoreValue::String(url.into());
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method && class_name == "NSURLComponents" && selector == "URL" {
        let value = object_string_value(state, receiver)?.to_owned();
        let url = new_guest_object(context, profile, state, "NSURL", StoreValue::String(value))?;
        context.reg_write(REG_X0, url)?;
        return Ok(());
    }
    if !class_method && class_name == "NSURLComponents" && selector == "setFragment:" {
        let fragment = context.reg_read(REG_X0 + 2)?;
        let fragment = (fragment != 0)
            .then(|| object_string_value(state, fragment))
            .transpose()?
            .map(str::to_owned);
        let mut url = url::Url::parse(object_string_value(state, receiver)?)?;
        url.set_fragment(fragment.as_deref());
        state
            .objects
            .get_mut(&receiver)
            .expect("known URL components")
            .value = StoreValue::String(url.into());
        context.reg_write(REG_X0, 0)?;
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
        && matches!(
            selector,
            "remoteObjectProxyWithErrorHandler:" | "synchronousRemoteObjectProxyWithErrorHandler:"
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
    if !class_method
        && class_is_kind_of(profile, &class_name, "NSError")
        && matches!(selector, "domain" | "userInfo" | "code")
    {
        let StoreValue::Entries(fields) = &state.objects[&receiver].value else {
            bail!("invalid Store error object");
        };
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
            "NSCondition" | "NSConditionLock" | "NSLock" | "NSRecursiveLock"
        )
    {
        match selector {
            "initWithCondition:" if class_name == "NSConditionLock" => {
                state
                    .objects
                    .get_mut(&receiver)
                    .expect("known condition lock")
                    .properties
                    .insert("condition".into(), context.reg_read(REG_X0 + 2)?);
                context.reg_write(REG_X0, receiver)?;
                return Ok(());
            }
            "condition" if class_name == "NSConditionLock" => {
                context.reg_write(
                    REG_X0,
                    state.objects[&receiver]
                        .properties
                        .get("condition")
                        .copied()
                        .unwrap_or(0),
                )?;
                return Ok(());
            }
            "unlockWithCondition:" if class_name == "NSConditionLock" => {
                state
                    .objects
                    .get_mut(&receiver)
                    .expect("known condition lock")
                    .properties
                    .insert("condition".into(), context.reg_read(REG_X0 + 2)?);
                context.reg_write(REG_X0, 0)?;
                return Ok(());
            }
            "lockWhenCondition:" if class_name == "NSConditionLock" => {
                let expected = context.reg_read(REG_X0 + 2)?;
                let actual = state.objects[&receiver]
                    .properties
                    .get("condition")
                    .copied()
                    .unwrap_or(0);
                if actual != expected {
                    bail!("guest condition lock expected {expected}, found {actual}");
                }
                context.reg_write(REG_X0, 0)?;
                return Ok(());
            }
            "lock" | "unlock" | "signal" | "broadcast" => {
                context.reg_write(REG_X0, 0)?;
                return Ok(());
            }
            "wait" | "waitUntilDate:" if class_name == "NSCondition" => {
                let Some(work) = take_runnable_pending(state) else {
                    bail!("guest condition has no runnable callback");
                };
                match work {
                    PendingWork::Guest {
                        block,
                        queue,
                        group,
                    } => {
                        let previous = std::mem::replace(&mut state.current_queue, queue);
                        begin_callback(
                            context,
                            state,
                            read_guest_u64(context, block + 16)?,
                            &[block],
                            group_callback_action(
                                group,
                                CallbackAction::RestoreQueueWithValue { previous, value: 1 },
                            ),
                        )?;
                    }
                    PendingWork::Http { task } => perform_http(context, profile, state, task)?,
                    PendingWork::DeliverData { task } => {
                        deliver_http_data(context, profile, state, task)?
                    }
                    PendingWork::Complete { task } => {
                        complete_http_task(context, profile, state, task)?
                    }
                    PendingWork::SwiftTask { task } => {
                        start_swift_task(context, state, task, None, None, None)?
                    }
                }
                return Ok(());
            }
            _ => {}
        }
    }
    if !class_method && class_is_kind_of(profile, &class_name, "NSURLRequest") {
        if matches!(
            selector,
            "initWithURL:" | "initWithURL:cachePolicy:timeoutInterval:"
        ) {
            let url = context.reg_read(REG_X0 + 2)?;
            let policy = if selector == "initWithURL:" {
                0
            } else {
                context.reg_read(REG_X0 + 3)?
            };
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
            state
                .objects
                .get_mut(&receiver)
                .expect("known request")
                .properties = HashMap::from([
                ("URL".into(), url),
                ("cachePolicy".into(), policy),
                ("HTTPMethod".into(), method),
                ("allHTTPHeaderFields".into(), headers),
            ]);
            if class_name == "AMSURLRequest" {
                let request_properties = new_guest_object(
                    context,
                    profile,
                    state,
                    "AMSURLRequestProperties",
                    StoreValue::Empty,
                )?;
                let index = profile.runtime.classes_by_name["AMSURLRequest"];
                let offset = profile.index.classes[index].ivars["_properties"];
                write_guest_u64(context, receiver + offset, request_properties)?;
            }
            context.reg_write(REG_X0, receiver)?;
            return Ok(());
        }
        if matches!(
            selector,
            "copy" | "copyWithZone:" | "mutableCopy" | "mutableCopyWithZone:"
        ) {
            let object = &state.objects[&receiver];
            let (value, properties) = (object.value.clone(), object.properties.clone());
            let copied = new_guest_object(context, profile, state, &class_name, value)?;
            state
                .objects
                .get_mut(&copied)
                .expect("new request copy")
                .properties = properties.clone();
            if let Some(&headers) = properties.get("allHTTPHeaderFields")
                && let StoreValue::Entries(entries) = &state.objects[&headers].value
            {
                let headers = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSMutableDictionary",
                    StoreValue::Entries(entries.clone()),
                )?;
                state
                    .objects
                    .get_mut(&copied)
                    .expect("new request copy")
                    .properties
                    .insert("allHTTPHeaderFields".into(), headers);
            }
            context.reg_write(REG_X0, copied)?;
            return Ok(());
        }
        if matches!(selector, "HTTPBody" | "HTTPBodyStream") {
            let value = state.objects[&receiver]
                .properties
                .get(selector)
                .copied()
                .unwrap_or(0);
            context.reg_write(REG_X0, value)?;
            return Ok(());
        }
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
            let mut headers = state.objects[&receiver]
                .properties
                .get("allHTTPHeaderFields")
                .copied()
                .unwrap_or(0);
            if headers == 0 {
                headers = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSMutableDictionary",
                    StoreValue::Entries(HashMap::new()),
                )?;
                state
                    .objects
                    .get_mut(&receiver)
                    .expect("known request")
                    .properties
                    .insert("allHTTPHeaderFields".into(), headers);
            }
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
    if !class_method && class_name == "NSURLSession" && selector == "dataTaskWithRequest:" {
        let request = context.reg_read(REG_X0 + 2)?;
        let task = new_guest_object(
            context,
            profile,
            state,
            "NSURLSessionDataTask",
            StoreValue::Empty,
        )?;
        state
            .objects
            .get_mut(&task)
            .expect("new data task")
            .properties
            .extend([
                ("currentRequest".into(), request),
                ("originalRequest".into(), request),
                ("session".into(), receiver),
                ("taskIdentifier".into(), task),
                ("state".into(), 1),
            ]);
        context.reg_write(REG_X0, task)?;
        return Ok(());
    }
    if !class_method && class_name == "NSURLSessionDataTask" && selector == "resume" {
        let task = state.objects.get_mut(&receiver).expect("known data task");
        let task_state = task.properties.get("state").copied().unwrap_or(0);
        if task_state != 1 {
            bail!("Store data task resumed twice");
        }
        task.properties.insert("state".into(), 0);
        state.pending.push(PendingWork::Http { task: receiver });
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method && class_name == "NSOperationQueue" && selector == "addOperationWithBlock:" {
        let block = context.reg_read(REG_X0 + 2)?;
        copy_and_queue_block(context, state, receiver, block, None)?;
        return Ok(());
    }
    if !class_method
        && class_name == "AKAppleIDSession"
        && selector == "handleResponse:forRequest:shouldRetry:"
    {
        let response = context.reg_read(REG_X0 + 2)?;
        let status = state
            .objects
            .get(&response)
            .and_then(|object| object.properties.get("statusCode"))
            .copied()
            .unwrap_or(0);
        if matches!(status, 431 | 433 | 434 | 441 | 442 | 443 | 444) {
            bail!("AuthKit anisette challenge is not supported");
        }
        let retry = context.reg_read(REG_X0 + 4)?;
        if retry != 0 {
            context.mem_write(retry, &[0])?;
        }
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method && class_name == "NSHTTPURLResponse" && selector == "valueForHTTPHeaderField:"
    {
        let key = object_string_value(state, context.reg_read(REG_X0 + 2)?)?;
        let headers = state.objects[&receiver]
            .properties
            .get("allHeaderFields")
            .copied()
            .unwrap_or(0);
        let value = state
            .objects
            .get(&headers)
            .and_then(|object| match &object.value {
                StoreValue::Entries(entries) => entries
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(key))
                    .map(|(_, &value)| value),
                _ => None,
            })
            .unwrap_or(0);
        context.reg_write(REG_X0, value)?;
        return Ok(());
    }
    if !class_method && class_name == "NSURLQueryItem" && matches!(selector, "name" | "value") {
        let value = state.objects[&receiver]
            .properties
            .get(selector)
            .copied()
            .unwrap_or(0);
        context.reg_write(REG_X0, value)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSFileManager"
        && selector == "URLForDirectory:inDomain:appropriateForURL:create:error:"
    {
        let url = new_guest_object(
            context,
            profile,
            state,
            "NSURL",
            StoreValue::String("file:///ipatool/cache/".into()),
        )?;
        context.reg_write(REG_X0, url)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSFileManager"
        && matches!(
            selector,
            "isWritableFileAtPath:" | "fileExistsAtPath:" | "fileExistsAtPath:isDirectory:"
        )
    {
        if selector == "fileExistsAtPath:isDirectory:" {
            let is_directory = context.reg_read(REG_X0 + 3)?;
            if is_directory != 0 {
                context.mem_write(is_directory, &[0])?;
            }
        }
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSFileManager"
        && matches!(
            selector,
            "createDirectoryAtPath:withIntermediateDirectories:attributes:error:"
                | "createDirectoryAtURL:withIntermediateDirectories:attributes:error:"
        )
    {
        let out = context.reg_read(REG_X0 + 5)?;
        if out != 0 {
            let domain = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String("NSCocoaErrorDomain".into()),
            )?;
            let code =
                new_guest_object(context, profile, state, "NSNumber", StoreValue::Number(513))?;
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
            write_guest_u64(context, out, error)?;
        }
        context.reg_write(REG_X0, 0)?;
        return Ok(());
    }
    if !class_method
        && class_name == "NSNotification"
        && matches!(selector, "name" | "object" | "userInfo")
    {
        context.reg_write(
            REG_X0,
            state.objects[&receiver]
                .properties
                .get(selector)
                .copied()
                .unwrap_or(0),
        )?;
        return Ok(());
    }
    if !class_method && class_name == "NSNotificationCenter" {
        match selector {
            "addObserver:selector:name:object:" => {
                state.observers.push(NotificationObserver {
                    observer: context.reg_read(REG_X0 + 2)?,
                    selector: context.reg_read(REG_X0 + 3)?,
                    name: context.reg_read(REG_X0 + 4)?,
                    object: context.reg_read(REG_X0 + 5)?,
                });
                context.reg_write(REG_X0, 0)?;
                return Ok(());
            }
            "removeObserver:" | "removeObserver:name:object:" => {
                let observer = context.reg_read(REG_X0 + 2)?;
                let name = if selector == "removeObserver:name:object:" {
                    context.reg_read(REG_X0 + 3)?
                } else {
                    0
                };
                let object = if selector == "removeObserver:name:object:" {
                    context.reg_read(REG_X0 + 4)?
                } else {
                    0
                };
                state.observers = state
                    .observers
                    .iter()
                    .filter(|entry| {
                        entry.observer != observer
                            || (name != 0 && !foundation_equal(state, entry.name, name, 0))
                            || (object != 0 && entry.object != object)
                    })
                    .map(|entry| NotificationObserver {
                        observer: entry.observer,
                        selector: entry.selector,
                        name: entry.name,
                        object: entry.object,
                    })
                    .collect();
                context.reg_write(REG_X0, 0)?;
                return Ok(());
            }
            "postNotificationName:object:" | "postNotificationName:object:userInfo:" => {
                let name = context.reg_read(REG_X0 + 2)?;
                let object = context.reg_read(REG_X0 + 3)?;
                let user_info = if selector.ends_with(":userInfo:") {
                    context.reg_read(REG_X0 + 4)?
                } else {
                    0
                };
                let observers = state
                    .observers
                    .iter()
                    .filter(|entry| {
                        (entry.name == 0 || foundation_equal(state, entry.name, name, 0))
                            && (entry.object == 0 || entry.object == object)
                    })
                    .map(|entry| (entry.observer, entry.selector))
                    .collect::<Vec<_>>();
                if observers.is_empty() {
                    context.reg_write(REG_X0, 0)?;
                    return Ok(());
                }
                let notification =
                    new_guest_object(context, profile, state, "NSNotification", StoreValue::Empty)?;
                state
                    .objects
                    .get_mut(&notification)
                    .expect("new notification")
                    .properties = HashMap::from([
                    ("name".into(), name),
                    ("object".into(), object),
                    ("userInfo".into(), user_info),
                ]);
                start_notification_callback(context, profile, state, observers, 0, notification)?;
                return Ok(());
            }
            _ => {}
        }
    }
    if !class_method && matches!(class_name.as_str(), "NSData" | "NSMutableData") {
        match selector {
            "bytes" => {
                let StoreValue::Bytes(bytes) = &state.objects[&receiver].value else {
                    bail!("invalid Store data object");
                };
                let bytes = bytes.clone();
                let address = state.allocate(bytes.len() as u64)?;
                context.mem_write(address, &bytes)?;
                context.reg_write(REG_X0, address)?;
                return Ok(());
            }
            "appendData:" | "appendBytes:length:" => {
                let source = context.reg_read(REG_X0 + 2)?;
                let other = if selector == "appendData:" {
                    let StoreValue::Bytes(bytes) = &state.objects[&source].value else {
                        bail!("invalid appended Store data");
                    };
                    bytes.clone()
                } else {
                    let size = context.reg_read(REG_X0 + 3)?;
                    if size > 32 << 20 {
                        bail!("data append exceeds budget");
                    }
                    context.mem_read(source, size as usize)?
                };
                let data = &mut state.objects.get_mut(&receiver).expect("known data").value;
                if matches!(data, StoreValue::Empty) {
                    *data = StoreValue::Bytes(Vec::new());
                }
                let StoreValue::Bytes(bytes) = data else {
                    bail!("invalid mutable Store data");
                };
                if bytes.len().saturating_add(other.len()) > 32 << 20 {
                    bail!("data append exceeds budget");
                }
                bytes.extend_from_slice(&other);
                context.reg_write(REG_X0, 0)?;
                return Ok(());
            }
            _ => {}
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
        (true, "currentLocale" | "systemLocale") if class_name == "NSLocale" => {
            let locale = new_guest_object(
                context,
                profile,
                state,
                "NSLocale",
                StoreValue::String("en_US".into()),
            )?;
            context.reg_write(REG_X0, locale)?;
        }
        (true, "preferredLanguages") if class_name == "NSLocale" => {
            let language = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String("en-US".into()),
            )?;
            let languages = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(vec![language]),
            )?;
            context.reg_write(REG_X0, languages)?;
        }
        (false, "initWithObjectsAndKeys:") | (true, "dictionaryWithObjectsAndKeys:") => {
            let mut values = HashMap::new();
            let mut value = context.reg_read(REG_X0 + 2)?;
            let stack = context.reg_read(REG_SP)?;
            let mut index = 0u64;
            while value != 0 {
                if index >= 1024 {
                    bail!("Store dictionary varargs exceed budget");
                }
                let offset = index * 16;
                let key = read_guest_u64(context, stack + offset)?;
                values.insert(collection_key(state, key), value);
                value = read_guest_u64(context, stack + offset + 8)?;
                index += 1;
            }
            if class_method {
                let dictionary = new_guest_object(
                    context,
                    profile,
                    state,
                    &class_name,
                    StoreValue::Entries(values),
                )?;
                context.reg_write(REG_X0, dictionary)?;
            } else {
                state
                    .objects
                    .get_mut(&receiver)
                    .expect("known dictionary")
                    .value = StoreValue::Entries(values);
                context.reg_write(REG_X0, receiver)?;
            }
        }
        (true, "defaultManager") if class_name == "NSFileManager" => {
            let manager =
                new_guest_object(context, profile, state, "NSFileManager", StoreValue::Empty)?;
            context.reg_write(REG_X0, manager)?;
        }
        (true, "defaultCenter") if class_name == "NSNotificationCenter" => {
            let center = match state.notification_center {
                Some(center) => center,
                None => {
                    let center = new_guest_object(
                        context,
                        profile,
                        state,
                        "NSNotificationCenter",
                        StoreValue::Empty,
                    )?;
                    state.notification_center = Some(center);
                    center
                }
            };
            context.reg_write(REG_X0, center)?;
        }
        (true, "requestHeaderFieldsWithCookies:") if class_name == "NSHTTPCookie" => {
            let array = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Addresses(cookies) = &state
                .objects
                .get(&array)
                .context("unknown cookies array")?
                .value
            else {
                bail!("cookies source is not an array");
            };
            let mut parts = Vec::with_capacity(cookies.len());
            for &cookie in cookies {
                let properties = &state
                    .objects
                    .get(&cookie)
                    .context("unknown request cookie")?
                    .properties;
                let name = object_string_value(state, properties["name"])?;
                let value = object_string_value(state, properties["value"])?;
                parts.push(format!("{name}={value}"));
            }
            let mut entries = HashMap::new();
            if !parts.is_empty() {
                let value = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(parts.join("; ")),
                )?;
                entries.insert("Cookie".into(), value);
            }
            let fields = new_guest_object(
                context,
                profile,
                state,
                "NSDictionary",
                StoreValue::Entries(entries),
            )?;
            context.reg_write(REG_X0, fields)?;
        }
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
        (true, "characterSetWithCharactersInString:") if class_name == "NSCharacterSet" => {
            let characters = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
            let set = new_guest_object(
                context,
                profile,
                state,
                "NSCharacterSet",
                StoreValue::String(characters),
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
        (true, "isValidJSONObject:") if class_name == "NSJSONSerialization" => {
            let object = context.reg_read(REG_X0 + 2)?;
            let valid = export_object(state, object, &mut HashSet::new(), 0).is_ok_and(|value| {
                (value.is_object() || value.is_array()) && serde_json::to_vec(&value).is_ok()
            });
            context.reg_write(REG_X0, u64::from(valid))?;
        }
        (true, "JSONObjectWithData:options:error:") if class_name == "NSJSONSerialization" => {
            let data = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Bytes(bytes) = &state.objects[&data].value else {
                bail!("JSON input is not NSData");
            };
            match serde_json::from_slice::<Value>(bytes) {
                Ok(parsed) => {
                    let value = import_guest_json(context, profile, state, &parsed, 0)?;
                    context.reg_write(REG_X0, value)?;
                }
                Err(_) => {
                    let error_slot = context.reg_read(REG_X0 + 4)?;
                    guest_parser_error(context, profile, state, error_slot)?;
                    context.reg_write(REG_X0, 0)?;
                }
            }
        }
        (true, "propertyListWithData:options:format:error:")
            if class_name == "NSPropertyListSerialization" =>
        {
            let data = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Bytes(bytes) = &state.objects[&data].value else {
                bail!("property list input is not NSData");
            };
            match plist::from_bytes::<plist::Value>(bytes) {
                Ok(parsed) => {
                    let value = import_guest_plist(context, profile, state, &parsed, 0)?;
                    context.reg_write(REG_X0, value)?;
                }
                Err(_) => {
                    let error_slot = context.reg_read(REG_X0 + 5)?;
                    guest_parser_error(context, profile, state, error_slot)?;
                    context.reg_write(REG_X0, 0)?;
                }
            }
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
        (true, "errorWithDomain:code:userInfo:") => {
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
        (true, "stringWithUTF8String:")
            if matches!(class_name.as_str(), "NSString" | "NSMutableString") =>
        {
            let value = guest_cstring(context, profile, state, context.reg_read(REG_X0 + 2)?)?;
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
        (true, "date" | "now") if class_name == "NSDate" => {
            let seconds = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1e9;
            let date = new_guest_object(
                context,
                profile,
                state,
                "NSDate",
                StoreValue::Float(seconds),
            )?;
            context.reg_write(REG_X0, date)?;
        }
        (true, "dateWithTimeIntervalSinceNow:" | "dateWithTimeIntervalSince1970:")
            if class_name == "NSDate" =>
        {
            let mut seconds = f64::from_bits(context.reg_read(40)?);
            if selector == "dateWithTimeIntervalSinceNow:" {
                seconds += time::OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1e9;
            }
            if !seconds.is_finite() || seconds <= i64::MIN as f64 || seconds >= i64::MAX as f64 {
                bail!("unsupported Store date interval");
            }
            let date = new_guest_object(
                context,
                profile,
                state,
                "NSDate",
                StoreValue::Float(seconds),
            )?;
            context.reg_write(REG_X0, date)?;
        }
        (false, "initWithTimeIntervalSince1970:") if class_name == "NSDate" => {
            let seconds = f64::from_bits(context.reg_read(40)?);
            if !seconds.is_finite() || seconds <= i64::MIN as f64 || seconds >= i64::MAX as f64 {
                bail!("unsupported Store date interval");
            }
            state.objects.get_mut(&receiver).expect("known date").value =
                StoreValue::Float(seconds);
            context.reg_write(REG_X0, receiver)?;
        }
        (
            false,
            "timeIntervalSinceNow" | "timeIntervalSince1970" | "timeIntervalSinceReferenceDate",
        ) if class_name == "NSDate" => {
            let seconds = match state.objects[&receiver].value {
                StoreValue::Float(seconds) => seconds,
                StoreValue::Number(seconds) => seconds as f64,
                _ => bail!("invalid Store date value"),
            };
            let interval = match selector {
                "timeIntervalSinceNow" => {
                    seconds - time::OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1e9
                }
                "timeIntervalSinceReferenceDate" => seconds - 978_307_200.0,
                _ => seconds,
            };
            context.reg_write(40, interval.to_bits())?;
        }
        (false, "timeIntervalSinceDate:") if class_name == "NSDate" => {
            let other = context.reg_read(REG_X0 + 2)?;
            let seconds = match state.objects[&receiver].value {
                StoreValue::Float(seconds) => seconds,
                StoreValue::Number(seconds) => seconds as f64,
                _ => bail!("invalid Store date value"),
            };
            let other_seconds = match state.objects[&other].value {
                StoreValue::Float(seconds) => seconds,
                StoreValue::Number(seconds) => seconds as f64,
                _ => bail!("invalid Store comparison date"),
            };
            context.reg_write(40, (seconds - other_seconds).to_bits())?;
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
        (true, "bundleForClass:") if class_name == "NSBundle" => {
            let bundle = new_main_bundle(context, profile, state)?;
            let target = context.reg_read(REG_X0 + 2)?;
            if profile
                .runtime
                .class_names_by_address
                .get(&target)
                .is_some_and(|name| name.contains("AMS"))
            {
                let identifier = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String("com.apple.AppleMediaServices".into()),
                )?;
                state
                    .objects
                    .get_mut(&bundle)
                    .expect("new bundle")
                    .properties
                    .insert("bundleIdentifier".into(), identifier);
            }
            context.reg_write(REG_X0, bundle)?;
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
        (true, "dictionaryWithDictionary:") => {
            let source = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Entries(entries) = &state
                .objects
                .get(&source)
                .context("unknown source dictionary")?
                .value
            else {
                bail!("dictionaryWithDictionary: source is not a dictionary");
            };
            let entries = entries.clone();
            let copied = new_guest_object(
                context,
                profile,
                state,
                &class_name,
                StoreValue::Entries(entries),
            )?;
            context.reg_write(REG_X0, copied)?;
        }
        (
            true,
            "strongToStrongObjectsMapTable"
            | "strongToWeakObjectsMapTable"
            | "weakToStrongObjectsMapTable"
            | "weakToWeakObjectsMapTable",
        ) if class_name == "NSMapTable" => {
            let table = new_guest_object(
                context,
                profile,
                state,
                "NSMapTable",
                StoreValue::Entries(HashMap::new()),
            )?;
            context.reg_write(REG_X0, table)?;
        }
        (true, "cookiesWithResponseHeaderFields:forURL:") if class_name == "NSHTTPCookie" => {
            let headers = context.reg_read(REG_X0 + 2)?;
            let origin = context.reg_read(REG_X0 + 3)?;
            let origin = url::Url::parse(object_string_value(state, origin)?)?;
            let StoreValue::Entries(entries) = &state.objects[&headers].value else {
                bail!("cookie response headers are not a dictionary");
            };
            let raw = entries
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, &value)| object_string_value(state, value))
                .transpose()?
                .map(str::to_owned);
            let mut items = Vec::new();
            if let Some(raw) = raw
                && let Ok(cookie) = cookie::Cookie::parse(raw)
            {
                let name = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(cookie.name().into()),
                )?;
                let value = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(cookie.value().into()),
                )?;
                let domain = cookie
                    .domain()
                    .map(str::to_owned)
                    .unwrap_or_else(|| origin.host_str().unwrap_or("").into());
                let domain = if cookie.domain().is_some() && !domain.starts_with('.') {
                    format!(".{domain}")
                } else {
                    domain
                };
                let domain = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(domain),
                )?;
                let path = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSString",
                    StoreValue::String(cookie.path().unwrap_or("/").into()),
                )?;
                let object =
                    new_guest_object(context, profile, state, "NSHTTPCookie", StoreValue::Empty)?;
                state
                    .objects
                    .get_mut(&object)
                    .expect("new cookie")
                    .properties
                    .extend([
                        ("name".into(), name),
                        ("value".into(), value),
                        ("domain".into(), domain),
                        ("path".into(), path),
                        (
                            "isSecure".into(),
                            u64::from(cookie.secure().unwrap_or(false)),
                        ),
                        (
                            "isHTTPOnly".into(),
                            u64::from(cookie.http_only().unwrap_or(false)),
                        ),
                    ]);
                items.push(object);
            }
            let array = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(items),
            )?;
            context.reg_write(REG_X0, array)?;
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
        (true, "numberWithDouble:" | "numberWithFloat:") if class_name == "NSNumber" => {
            let bits = context.reg_read(40)?;
            let value = if selector == "numberWithFloat:" {
                f32::from_bits(bits as u32) as f64
            } else {
                f64::from_bits(bits)
            };
            let address = new_guest_object(
                context,
                profile,
                state,
                "NSNumber",
                StoreValue::Float(value),
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
        (false, "removeObjectForKey:") => {
            let key = collection_key(state, context.reg_read(REG_X0 + 2)?);
            let StoreValue::Entries(entries) = &mut state
                .objects
                .get_mut(&receiver)
                .expect("known dictionary")
                .value
            else {
                bail!("dictionary removal on {class_name}");
            };
            entries.remove(&key);
            context.reg_write(REG_X0, 0)?;
        }
        (false, "initWithArray:") => {
            let source = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Addresses(items) = &state
                .objects
                .get(&source)
                .context("unknown source array")?
                .value
            else {
                bail!("initWithArray: source is not an array");
            };
            let items = items.clone();
            state.objects.get_mut(&receiver).expect("known array").value =
                StoreValue::Addresses(items);
            context.reg_write(REG_X0, receiver)?;
        }
        (false, "removeObject:" | "removeObjectsInArray:") => {
            let argument = context.reg_read(REG_X0 + 2)?;
            if argument != 0 {
                let remove = if selector == "removeObjectsInArray:" {
                    let StoreValue::Addresses(items) = &state
                        .objects
                        .get(&argument)
                        .context("unknown removal array")?
                        .value
                    else {
                        bail!("removeObjectsInArray: argument is not an array");
                    };
                    items.clone()
                } else {
                    vec![argument]
                };
                let StoreValue::Addresses(items) = &state.objects[&receiver].value else {
                    bail!("object removal on {class_name}");
                };
                let retained = items
                    .iter()
                    .copied()
                    .filter(|&item| {
                        !remove
                            .iter()
                            .any(|&candidate| foundation_equal(state, item, candidate, 0))
                    })
                    .collect();
                state
                    .objects
                    .get_mut(&receiver)
                    .expect("known collection")
                    .value = StoreValue::Addresses(retained);
            }
            context.reg_write(REG_X0, 0)?;
        }
        (false, "initWithDictionary:") => {
            let source = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Entries(entries) = &state
                .objects
                .get(&source)
                .context("unknown source dictionary")?
                .value
            else {
                bail!("initWithDictionary: source is not a dictionary");
            };
            let entries = entries.clone();
            state
                .objects
                .get_mut(&receiver)
                .expect("known dictionary")
                .value = StoreValue::Entries(entries);
            context.reg_write(REG_X0, receiver)?;
        }
        (false, "initWithDictionary:copyItems:") => {
            let source = context.reg_read(REG_X0 + 2)?;
            let copy_items = context.reg_read(REG_X0 + 3)? != 0;
            let StoreValue::Entries(entries) = &state
                .objects
                .get(&source)
                .context("unknown source dictionary")?
                .value
            else {
                bail!("initWithDictionary:copyItems: source is not a dictionary");
            };
            let entries = entries.clone();
            let mut keys = entries.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            state
                .objects
                .get_mut(&receiver)
                .expect("known dictionary")
                .value = StoreValue::Entries(entries);
            if copy_items {
                copy_dictionary_items(context, profile, state, receiver, keys, 0)?;
            } else {
                context.reg_write(REG_X0, receiver)?;
            }
        }
        (false, "boolForKey:") if class_name == "NSUserDefaults" => {
            let key = object_string_value(state, context.reg_read(REG_X0 + 2)?)?;
            let StoreValue::Entries(entries) = &state.objects[&receiver].value else {
                bail!("user defaults storage is not a dictionary");
            };
            let address = entries.get(key).copied().unwrap_or(0);
            let value = if address == 0 {
                0
            } else {
                match &state.objects[&address].value {
                    StoreValue::Number(value) => *value as u64,
                    StoreValue::Float(value) => u64::from(*value != 0.0),
                    StoreValue::Boolean(value) => u64::from(*value),
                    StoreValue::String(value) => value.parse::<i64>().unwrap_or(0) as u64,
                    _ => 0,
                }
            };
            context.reg_write(REG_X0, value)?;
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
        (false, "allObjects") if matches!(class_name.as_str(), "NSSet" | "NSMutableSet") => {
            let StoreValue::Addresses(values) = &state.objects[&receiver].value else {
                bail!("set contents are not an array");
            };
            let array = new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(values.clone()),
            )?;
            context.reg_write(REG_X0, array)?;
        }
        (false, "sortedArrayUsingComparator:") => {
            let StoreValue::Addresses(items) = &state.objects[&receiver].value else {
                bail!("sort receiver is not an array");
            };
            let items = items.clone();
            if items.len() > 4096 {
                bail!("Store array sort exceeds item limit");
            }
            if items.len() < 2 {
                let sorted = new_guest_object(
                    context,
                    profile,
                    state,
                    "NSArray",
                    StoreValue::Addresses(items),
                )?;
                context.reg_write(REG_X0, sorted)?;
            } else {
                let block = context.reg_read(REG_X0 + 2)?;
                begin_callback(
                    context,
                    state,
                    read_guest_u64(context, block + 16)?,
                    &[block, items[0], items[1]],
                    CallbackAction::SortArray {
                        items,
                        block,
                        i: 1,
                        j: 1,
                    },
                )?;
            }
        }
        (false, "compare:") if matches!(class_name.as_str(), "NSString" | "NSMutableString") => {
            let left = object_string_value(state, receiver)?;
            let right = object_string_value(state, context.reg_read(REG_X0 + 2)?)?;
            let ordering = match left.cmp(right) {
                std::cmp::Ordering::Less => -1i64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            context.reg_write(REG_X0, ordering as u64)?;
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
        (false, "addObjectsFromArray:") if class_name == "NSMutableArray" => {
            let source = context.reg_read(REG_X0 + 2)?;
            let StoreValue::Addresses(items) = &state
                .objects
                .get(&source)
                .context("unknown source array")?
                .value
            else {
                bail!("addObjectsFromArray: source is not an array");
            };
            let items = items.clone();
            let StoreValue::Addresses(values) = &mut state
                .objects
                .get_mut(&receiver)
                .expect("known mutable array")
                .value
            else {
                bail!("addObjectsFromArray: receiver is not an array");
            };
            values.extend(items);
            context.reg_write(REG_X0, 0)?;
        }
        (false, "removeObjectAtIndex:") if class_name == "NSMutableArray" => {
            let index = context.reg_read(REG_X0 + 2)? as usize;
            let StoreValue::Addresses(values) = &mut state
                .objects
                .get_mut(&receiver)
                .expect("known mutable array")
                .value
            else {
                bail!("removeObjectAtIndex: on non-array");
            };
            if index >= values.len() {
                bail!("Store array index out of bounds");
            }
            values.remove(index);
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
        (
            false,
            "isEqual:"
            | "isEqualToDate:"
            | "isEqualToString:"
            | "isEqualToDictionary:"
            | "isEqualToArray:",
        ) => {
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
                new_bundle_info(context, profile, state)?
            };
            context.reg_write(REG_X0, value)?;
        }
        (false, "localizedStringForKey:value:table:") if class_name == "NSBundle" => {
            let key = context.reg_read(REG_X0 + 2)?;
            let fallback = context.reg_read(REG_X0 + 3)?;
            let result = if fallback != 0 && !object_string_value(state, fallback)?.is_empty() {
                fallback
            } else {
                key
            };
            context.reg_write(REG_X0, result)?;
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
        (false, "doubleValue" | "floatValue") => {
            let value = match &state.objects[&receiver].value {
                StoreValue::Number(value) => *value as f64,
                StoreValue::Float(value) => *value,
                StoreValue::Boolean(value) => f64::from(u8::from(*value)),
                StoreValue::String(value) => value.parse::<f64>().unwrap_or(0.0),
                _ => bail!("unsupported Store numeric conversion"),
            };
            let bits = if selector == "floatValue" {
                f32::to_bits(value as f32) as u64
            } else {
                f64::to_bits(value)
            };
            context.reg_write(40, bits)?;
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
        (false, "appendFormat:" | "initWithFormat:" | "initWithFormat:locale:arguments:") => {
            let format_address = context.reg_read(REG_X0 + 2)?;
            let format = object_string_value(state, format_address)?.to_owned();
            let stack_pointer = if selector == "initWithFormat:locale:arguments:" {
                context.reg_read(REG_X0 + 4)?
            } else {
                context.reg_read(REG_SP)?
            };
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
        (false, "description") if class_is_kind_of(profile, &class_name, "NSString") => {
            context.reg_write(REG_X0, receiver)?;
        }
        (false, "appendString:") => {
            let suffix = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
            let StoreValue::String(value) = &mut state.objects.get_mut(&receiver).unwrap().value
            else {
                bail!("appendString: on nonstring object");
            };
            value.push_str(&suffix);
            context.reg_write(REG_X0, 0)?;
        }
        (false, "initWithBytesNoCopy:length:encoding:freeWhenDone:")
            if class_is_kind_of(profile, &class_name, "NSString") =>
        {
            let address = context.reg_read(REG_X0 + 2)?;
            let length = context.reg_read(REG_X0 + 3)?;
            let encoding = context.reg_read(REG_X0 + 4)?;
            if !matches!(encoding, 1 | 4) || length > 1 << 20 {
                bail!("unsupported string buffer initialization");
            }
            let bytes = context.mem_read(address, length as usize)?;
            state
                .objects
                .get_mut(&receiver)
                .expect("known string")
                .value = StoreValue::String(String::from_utf8_lossy(&bytes).into_owned());
            context.reg_write(REG_X0, receiver)?;
        }
        (false, "stringByAppendingString:") => {
            let prefix = object_string_value(state, receiver)?;
            let suffix = object_string_value(state, context.reg_read(REG_X0 + 2)?)?;
            let value = format!("{prefix}{suffix}");
            let string = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(value),
            )?;
            context.reg_write(REG_X0, string)?;
        }
        (false, "dataUsingEncoding:") => {
            let value = object_string_value(state, receiver)?;
            let encoding = context.reg_read(REG_X0 + 2)?;
            let data = match encoding {
                4 => value.as_bytes().to_vec(),
                10 => {
                    let mut data = vec![0xff, 0xfe];
                    for word in value.encode_utf16() {
                        data.extend_from_slice(&word.to_le_bytes());
                    }
                    data
                }
                _ => bail!("unsupported string encoding {encoding}"),
            };
            let object =
                new_guest_object(context, profile, state, "NSData", StoreValue::Bytes(data))?;
            context.reg_write(REG_X0, object)?;
        }
        (false, "stringByTrimmingCharactersInSet:") => {
            let value = object_string_value(state, receiver)?;
            let set = state
                .objects
                .get(&context.reg_read(REG_X0 + 2)?)
                .context("unknown Store character set")?;
            let StoreValue::String(characters) = &set.value else {
                bail!("invalid Store character set");
            };
            let inverted = set.properties.get("inverted").copied().unwrap_or(0) != 0;
            let trimmed = value
                .trim_matches(|character: char| {
                    let matches = if characters == "0123456789" {
                        character.is_numeric()
                    } else {
                        characters.contains(character)
                    };
                    matches != inverted
                })
                .to_owned();
            let string = new_guest_object(
                context,
                profile,
                state,
                "NSString",
                StoreValue::String(trimmed),
            )?;
            context.reg_write(REG_X0, string)?;
        }
        (false, "initWithDomain:code:userInfo:") if class_name == "NSError" => {
            let domain = context.reg_read(REG_X0 + 2)?;
            let code = new_guest_object(
                context,
                profile,
                state,
                "NSNumber",
                StoreValue::Number(context.reg_read(REG_X0 + 3)? as i64),
            )?;
            let user_info = context.reg_read(REG_X0 + 4)?;
            state.objects.get_mut(&receiver).expect("known error").value =
                StoreValue::Entries(HashMap::from([
                    ("domain".into(), domain),
                    ("code".into(), code),
                    ("userInfo".into(), user_info),
                ]));
            context.reg_write(REG_X0, receiver)?;
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
        (false, "hasPrefix:" | "hasSuffix:" | "containsString:") => {
            let value = object_string_value(state, receiver)?;
            let needle = object_string_value(state, context.reg_read(REG_X0 + 2)?)?;
            let found = match selector {
                "hasPrefix:" => value.starts_with(needle),
                "hasSuffix:" => value.ends_with(needle),
                _ => value.contains(needle),
            };
            context.reg_write(REG_X0, u64::from(found))?;
        }
        (false, "caseInsensitiveCompare:") => {
            let value = object_string_value(state, receiver)?.to_lowercase();
            let other = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_lowercase();
            let order = match value.cmp(&other) {
                std::cmp::Ordering::Less => -1i64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            context.reg_write(REG_X0, order as u64)?;
        }
        (false, "rangeOfString:" | "rangeOfString:options:") => {
            let value = object_string_value(state, receiver)?.to_owned();
            let needle = object_string_value(state, context.reg_read(REG_X0 + 2)?)?.to_owned();
            let options = if selector.ends_with("options:") {
                context.reg_read(REG_X0 + 3)?
            } else {
                0
            };
            let (search, target) = if options & 1 != 0 {
                (value.to_lowercase(), needle.to_lowercase())
            } else {
                (value, needle)
            };
            let index = if options & 4 != 0 {
                search.rfind(&target)
            } else {
                search.find(&target)
            };
            let (start, length) = if let Some(index) = index {
                (
                    search[..index].encode_utf16().count() as u64,
                    target.encode_utf16().count() as u64,
                )
            } else {
                (i64::MAX as u64, 0)
            };
            context.reg_write(REG_X0, start)?;
            context.reg_write(REG_X0 + 1, length)?;
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

fn guest_parser_error(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    error_slot: u64,
) -> Result<()> {
    if error_slot == 0 {
        return Ok(());
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
        StoreValue::Number(3840),
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
    write_guest_u64(context, error_slot, error)
}

fn import_guest_json(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    value: &Value,
    depth: usize,
) -> Result<u64> {
    if depth > 32 {
        bail!("Store Foundation import exceeds nesting limit");
    }
    match value {
        Value::Null => Ok(0),
        Value::String(value) => new_guest_object(
            context,
            profile,
            state,
            "NSString",
            StoreValue::String(value.clone()),
        ),
        Value::Bool(value) => new_guest_object(
            context,
            profile,
            state,
            "NSNumber",
            StoreValue::Boolean(*value),
        ),
        Value::Number(value) => {
            let value = if let Some(integer) = value.as_i64() {
                StoreValue::Number(integer)
            } else if let Some(integer) = value.as_u64().filter(|value| *value <= i64::MAX as u64) {
                StoreValue::Number(integer as i64)
            } else {
                StoreValue::Float(value.as_f64().context("invalid Store JSON number")?)
            };
            new_guest_object(context, profile, state, "NSNumber", value)
        }
        Value::Array(values) => {
            if values.len() > 65_536 {
                bail!("Store Foundation array exceeds size limit");
            }
            let mut imported = Vec::with_capacity(values.len());
            for value in values {
                imported.push(import_guest_json(
                    context,
                    profile,
                    state,
                    value,
                    depth + 1,
                )?);
            }
            new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(imported),
            )
        }
        Value::Object(values) => {
            if values.len() > 65_536 {
                bail!("Store Foundation dictionary exceeds size limit");
            }
            let mut imported = HashMap::with_capacity(values.len());
            for (key, value) in values {
                imported.insert(
                    key.clone(),
                    import_guest_json(context, profile, state, value, depth + 1)?,
                );
            }
            new_guest_object(
                context,
                profile,
                state,
                "NSDictionary",
                StoreValue::Entries(imported),
            )
        }
    }
}

fn import_guest_plist(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    value: &plist::Value,
    depth: usize,
) -> Result<u64> {
    if depth > 32 {
        bail!("Store Foundation import exceeds nesting limit");
    }
    match value {
        plist::Value::String(value) => new_guest_object(
            context,
            profile,
            state,
            "NSString",
            StoreValue::String(value.clone()),
        ),
        plist::Value::Boolean(value) => new_guest_object(
            context,
            profile,
            state,
            "NSNumber",
            StoreValue::Boolean(*value),
        ),
        plist::Value::Integer(value) => {
            let number = value.as_signed().map_or_else(
                || StoreValue::Float(value.as_unsigned().unwrap() as f64),
                StoreValue::Number,
            );
            new_guest_object(context, profile, state, "NSNumber", number)
        }
        plist::Value::Real(value) => new_guest_object(
            context,
            profile,
            state,
            "NSNumber",
            StoreValue::Float(*value),
        ),
        plist::Value::Uid(value) => {
            let value = value.get();
            let number = i64::try_from(value)
                .map(StoreValue::Number)
                .unwrap_or_else(|_| StoreValue::Float(value as f64));
            new_guest_object(context, profile, state, "NSNumber", number)
        }
        plist::Value::Data(value) => new_guest_object(
            context,
            profile,
            state,
            "NSData",
            StoreValue::Bytes(value.clone()),
        ),
        plist::Value::Date(value) => {
            let time: std::time::SystemTime = (*value).into();
            let seconds = match time.duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => duration.as_secs_f64(),
                Err(error) => -error.duration().as_secs_f64(),
            };
            new_guest_object(
                context,
                profile,
                state,
                "NSDate",
                StoreValue::Float(seconds),
            )
        }
        plist::Value::Array(values) => {
            if values.len() > 65_536 {
                bail!("Store Foundation array exceeds size limit");
            }
            let items = values
                .iter()
                .map(|value| import_guest_plist(context, profile, state, value, depth + 1))
                .collect::<Result<Vec<_>>>()?;
            new_guest_object(
                context,
                profile,
                state,
                "NSArray",
                StoreValue::Addresses(items),
            )
        }
        plist::Value::Dictionary(values) => {
            if values.len() > 65_536 {
                bail!("Store Foundation dictionary exceeds size limit");
            }
            let mut entries = HashMap::with_capacity(values.len());
            for (key, value) in values {
                entries.insert(
                    key.clone(),
                    import_guest_plist(context, profile, state, value, depth + 1)?,
                );
            }
            new_guest_object(
                context,
                profile,
                state,
                "NSDictionary",
                StoreValue::Entries(entries),
            )
        }
        _ => bail!("unsupported Store property list value"),
    }
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

fn export_plist_object(
    state: &StoreState,
    address: u64,
    active: &mut HashSet<u64>,
    depth: usize,
) -> Result<plist::Value> {
    if address == 0 || depth > 32 || !active.insert(address) {
        bail!("null, cyclic, or excessively nested Store property list value");
    }
    let object = state
        .objects
        .get(&address)
        .with_context(|| format!("unknown exported Store object {address:#x}"))?;
    let result = match &object.value {
        StoreValue::Empty => bail!("empty Store property list value"),
        StoreValue::String(value) => plist::Value::String(value.clone()),
        StoreValue::Number(value) => plist::Value::Integer((*value).into()),
        StoreValue::Float(value) if object.class == "NSDate" => {
            if !value.is_finite() || value.abs() > 253_402_300_799.0 {
                bail!("Store date is out of range");
            }
            let time = if *value >= 0.0 {
                std::time::UNIX_EPOCH + Duration::from_secs_f64(*value)
            } else {
                std::time::UNIX_EPOCH - Duration::from_secs_f64(-*value)
            };
            plist::Value::Date(time.into())
        }
        StoreValue::Float(value) => plist::Value::Real(*value),
        StoreValue::Boolean(value) => plist::Value::Boolean(*value),
        StoreValue::Bytes(value) => plist::Value::Data(value.clone()),
        StoreValue::Addresses(values) => plist::Value::Array(
            values
                .iter()
                .map(|&address| export_plist_object(state, address, active, depth + 1))
                .collect::<Result<Vec<_>>>()?,
        ),
        StoreValue::Entries(values) => {
            let mut result = plist::Dictionary::new();
            for (key, &address) in values {
                result.insert(
                    key.clone(),
                    export_plist_object(state, address, active, depth + 1)?,
                );
            }
            plist::Value::Dictionary(result)
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

fn copy_foundation_value(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    address: u64,
) -> Result<u64> {
    let object = state
        .objects
        .get(&address)
        .context("unknown dictionary copy value")?;
    let class = object.class.as_str();
    let target = match class {
        "NSArray" | "NSMutableArray" => "NSArray",
        "NSSet" | "NSMutableSet" => "NSSet",
        "NSDictionary" | "NSMutableDictionary" => "NSDictionary",
        "NSMutableString" => "NSString",
        _ => return Ok(address),
    };
    let value = object.value.clone();
    new_guest_object(context, profile, state, target, value)
}

fn copy_dictionary_items(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
    receiver: u64,
    keys: Vec<String>,
    mut index: usize,
) -> Result<bool> {
    while index < keys.len() {
        let key = keys[index].clone();
        let value = {
            let StoreValue::Entries(entries) = &state.objects[&receiver].value else {
                bail!("dictionary copy target is not a dictionary");
            };
            entries[&key]
        };
        let class = state
            .objects
            .get(&value)
            .context("unknown dictionary copy value")?
            .class
            .clone();
        if let Some(function) = method_address(profile, &class, "copyWithZone:", false) {
            let selector = selector_address_for_hook(context, profile, state, "copyWithZone:")?;
            begin_callback(
                context,
                state,
                function,
                &[value, selector, 0],
                CallbackAction::DictionaryCopy {
                    receiver,
                    keys,
                    index: index + 1,
                    key,
                },
            )?;
            return Ok(true);
        }
        let copied = copy_foundation_value(context, profile, state, value)?;
        let StoreValue::Entries(entries) = &mut state.objects.get_mut(&receiver).unwrap().value
        else {
            unreachable!("dictionary was checked before copying")
        };
        entries.insert(key, copied);
        index += 1;
    }
    context.reg_write(REG_X0, receiver)?;
    Ok(false)
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

fn new_bundle_info(
    context: &HookContext,
    profile: &ProfileData,
    state: &mut StoreState,
) -> Result<u64> {
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
    )
}

fn read_guest_tm(context: &HookContext, address: u64) -> Result<[i32; 9]> {
    let bytes = context.mem_read(address, 36)?;
    Ok(std::array::from_fn(|index| {
        i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().expect("tm word"))
    }))
}

fn write_guest_tm(context: &HookContext, address: u64, fields: [i32; 9]) -> Result<()> {
    for (index, field) in fields.into_iter().enumerate() {
        context.mem_write(address + (index * 4) as u64, &field.to_le_bytes())?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "linux"))]
fn guest_clock_gettime_nsec(clock: u64) -> Result<u64> {
    #[cfg(target_os = "linux")]
    let host_clock = match clock {
        0 => libc::CLOCK_REALTIME,
        4 | 5 => libc::CLOCK_MONOTONIC_RAW,
        6 | 8 | 9 => libc::CLOCK_MONOTONIC,
        _ => bail!("unsupported Store clock {clock}"),
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let host_clock = libc::clockid_t::try_from(clock).context("invalid Store clock identifier")?;
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a writable timespec and `host_clock` is passed by value.
    if unsafe { libc::clock_gettime(host_clock, &mut value) } != 0 {
        bail!(
            "read Store clock {clock}: {}",
            std::io::Error::last_os_error()
        );
    }
    let seconds = u64::try_from(value.tv_sec).context("Store clock is before its epoch")?;
    let nanoseconds = u64::try_from(value.tv_nsec).context("invalid Store clock nanoseconds")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .context("Store clock nanoseconds overflow")
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
fn guest_clock_gettime_nsec(clock: u64) -> Result<u64> {
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    let duration = match clock {
        0 => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Store clock is before the Unix epoch")?,
        4 | 5 | 6 | 8 | 9 => {
            static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
            START.get_or_init(Instant::now).elapsed()
        }
        _ => bail!("unsupported Store clock {clock}"),
    };
    u64::try_from(duration.as_nanos()).context("Store clock nanoseconds overflow")
}

fn normalize_guest_tm(fields: [i32; 9]) -> Result<time::OffsetDateTime> {
    let month = i64::from(fields[4]);
    let year = i64::from(fields[5]) + 1900 + month.div_euclid(12);
    let year = i32::try_from(year).context("guest date year is out of range")?;
    let month = time::Month::try_from((month.rem_euclid(12) + 1) as u8)?;
    let date = time::Date::from_calendar_date(year, month, 1)?;
    let seconds = (i64::from(fields[3]) - 1) * 86_400
        + i64::from(fields[2]) * 3600
        + i64::from(fields[1]) * 60
        + i64::from(fields[0]);
    date.midnight()
        .checked_add(time::Duration::seconds(seconds))
        .context("guest date is out of range")
        .map(time::PrimitiveDateTime::assume_utc)
}

fn format_guest_http_date(date: time::OffsetDateTime) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let weekday = WEEKDAYS[date.weekday().number_days_from_sunday() as usize];
    let month = MONTHS[date.month() as usize - 1];
    format!(
        "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        date.day(),
        date.year(),
        date.hour(),
        date.minute(),
        date.second()
    )
}

fn parse_guest_http_date(value: &str) -> Option<[i32; 9]> {
    if !value.is_ascii() || value.len() != 29 {
        return None;
    }
    if !matches!(
        &value[..3],
        "Sun" | "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat"
    ) || &value[3..5] != ", "
        || &value[7..8] != " "
        || &value[11..12] != " "
        || &value[16..17] != " "
        || &value[19..20] != ":"
        || &value[22..23] != ":"
        || &value[25..] != " GMT"
    {
        return None;
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|month| *month == &value[8..11])?;
    let day: u8 = value[5..7].parse().ok()?;
    let year: i32 = value[12..16].parse().ok()?;
    let hour: u8 = value[17..19].parse().ok()?;
    let minute: u8 = value[20..22].parse().ok()?;
    let second: u8 = value[23..25].parse().ok()?;
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month as u8 + 1).ok()?, day)
            .ok()?;
    time::Time::from_hms(hour, minute, second).ok()?;
    Some([
        i32::from(second),
        i32::from(minute),
        i32::from(hour),
        i32::from(day),
        month as i32,
        year - 1900,
        i32::from(date.weekday().number_days_from_sunday()),
        i32::from(date.ordinal()) - 1,
        0,
    ])
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

fn host_request_from_state(
    profile: &ProfileData,
    state: &StoreState,
    request: u64,
    authenticated: bool,
    no_redirects: bool,
    timeout: Option<Duration>,
) -> Result<HostRequest> {
    let object = state
        .objects
        .get(&request)
        .context("unknown Store request")?;
    if !class_is_kind_of(profile, &object.class, "NSURLRequest") {
        bail!("Store object is not a URL request");
    }
    let property = |name: &str| object.properties.get(name).copied().unwrap_or(0);
    let endpoint = object_string_value(state, property("URL"))?;
    let url = url::Url::parse(endpoint).context("invalid Store request URL")?;
    if !allowed_store_url(&url, authenticated) {
        bail!("unsupported Store request URL");
    }
    let method = Method::from_bytes(object_string_value(state, property("HTTPMethod"))?.as_bytes())
        .context("invalid Store request method")?;
    let body = match property("HTTPBody") {
        0 => None,
        address => match &state
            .objects
            .get(&address)
            .context("missing Store request body")?
            .value
        {
            StoreValue::Bytes(bytes) => Some(bytes.clone()),
            _ => bail!("Store request body is not NSData"),
        },
    };
    let mut headers = HeaderMap::new();
    if let Some(address) = object.properties.get("allHTTPHeaderFields") {
        let StoreValue::Entries(entries) = &state
            .objects
            .get(address)
            .context("missing Store request headers")?
            .value
        else {
            bail!("Store request headers are not a dictionary");
        };
        for (name, &value) in entries {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).context("invalid Store header name")?,
                HeaderValue::from_str(object_string_value(state, value)?)
                    .context("invalid Store header value")?,
            );
        }
    }
    Ok(HostRequest {
        method,
        url,
        headers,
        body,
        no_redirects,
        timeout,
    })
}

fn allowed_store_url(url: &url::Url, authenticated: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    if !authenticated {
        return matches!(url.scheme(), "http" | "https");
    }
    url.scheme() == "https"
        && (host.eq_ignore_ascii_case("apple.com")
            || [".apple.com", ".mzstatic.com", ".cdn-apple.com"]
                .iter()
                .any(|suffix| host.to_ascii_lowercase().ends_with(suffix)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_http_date_parser_matches_go_layout_and_tm_normalization() {
        let parsed = parse_guest_http_date("Mon, 27 Oct 2026 12:34:56 GMT").unwrap();
        assert_eq!(parsed, [56, 34, 12, 27, 9, 126, 2, 299, 0]);
        assert_eq!(
            normalize_guest_tm(parsed).unwrap().unix_timestamp(),
            1_793_104_496
        );
        assert_eq!(
            format_guest_http_date(normalize_guest_tm(parsed).unwrap()),
            "Tue, 27 Oct 2026 12:34:56 GMT"
        );
        assert_eq!(
            format_guest_http_date(normalize_guest_tm([0, 0, 0, 0, 12, 126, 0, 0, 0]).unwrap()),
            "Thu, 31 Dec 2026 00:00:00 GMT"
        );
        for value in [
            "Tue, 27 Oct 2026 12:34:56 UTC",
            "Tue, 27 Oct 2026 12:34:56 +0000",
            "Tue,  7 Oct 2026 12:34:56 GMT",
            "Tue, 27 Oct 2026 12:34:56 GMT extra",
        ] {
            assert!(parse_guest_http_date(value).is_none(), "{value}");
        }
    }

    #[test]
    fn task_locals_shadow_pop_and_copy_to_child() {
        let mut locals = TaskLocalBindings::default();
        assert_eq!(locals.get(0, 7), 0);
        assert!(locals.pop(0).is_err());

        locals.push(0, 7, 100);
        locals.push(0, 8, 200);
        locals.push(0, 7, 300);
        assert_eq!(locals.get(0, 7), 300);
        assert_eq!(locals.get(0, 8), 200);

        locals.copy_to(0, 42);
        locals.pop(0).unwrap();
        assert_eq!(locals.get(0, 7), 100);
        assert_eq!(locals.get(42, 7), 300);
        locals.push(42, 7, 400);
        assert_eq!(locals.get(42, 7), 400);
        assert_eq!(locals.get(0, 7), 100);
        locals.pop(42).unwrap();
        assert_eq!(locals.get(42, 7), 300);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_task_local_get_uses_current_task_binding() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let get = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol.trim_start_matches('_') == "swift_task_localValueGet")
            .unwrap()
            .address;
        let key = 0x1234;
        let value = runtime.allocate(16).unwrap();
        {
            let mut state = runtime.state.borrow_mut();
            state.task_locals.push(0, key, value);
            state.task_locals.copy_to(0, 42);
            state.current_swift_task = Some(42);
        }
        assert_eq!(runtime.call(get, &[key]).unwrap(), value);
        runtime.state.borrow_mut().current_swift_task = None;
        assert_eq!(runtime.call(get, &[key]).unwrap(), value);
        assert_eq!(runtime.call(get, &[key + 1]).unwrap(), 0);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_task_local_wrapper_reads_bound_value() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let get = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol == "$ss9TaskLocalC3getxyF")
            .unwrap()
            .address;
        let wrapper = runtime.allocate(32).unwrap();
        let bound = runtime.allocate(8).unwrap();
        let output = runtime.allocate(8).unwrap();
        runtime.write_u64(wrapper + 16, 11).unwrap();
        runtime.write_u64(bound, 22).unwrap();
        runtime.state.borrow_mut().objects.insert(
            wrapper,
            StoreObject {
                class: "HostSwiftTaskLocal".into(),
                value: StoreValue::Empty,
                properties: HashMap::from([
                    ("valueSize".into(), 8),
                    ("defaultValue".into(), wrapper + 16),
                ]),
            },
        );
        runtime.engine.reg_write(REG_X0 + 20, wrapper).unwrap();
        runtime.engine.reg_write(REG_X0 + 8, output).unwrap();
        runtime.call(get, &[]).unwrap();
        assert_eq!(runtime.read_u64(output).unwrap(), 11);

        {
            let mut state = runtime.state.borrow_mut();
            state.task_locals.push(42, wrapper, bound);
            state.current_swift_task = Some(42);
        }
        runtime.engine.reg_write(REG_X0 + 20, wrapper).unwrap();
        runtime.engine.reg_write(REG_X0 + 8, output).unwrap();
        runtime.call(get, &[]).unwrap();
        assert_eq!(runtime.read_u64(output).unwrap(), 22);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_resolves_swift_metadata_and_url_bridge() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |symbol: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.symbol == symbol)
                .unwrap()
                .address
        };
        let singleton_call = call_address("swift_getSingletonMetadata");
        let foreign_call = call_address("swift_getForeignTypeMetadata");
        let url_call = call_address("$s10Foundation3URLV19_bridgeToObjectiveCSo5NSURLCyF");
        let (singleton_candidate, &singleton_metadata) = runtime
            .profile
            .index
            .swift_singletons
            .iter()
            .next()
            .unwrap();
        let singleton_candidate: u64 = singleton_candidate.parse().unwrap();
        assert_eq!(
            runtime
                .call(singleton_call, &[0, singleton_candidate])
                .unwrap(),
            singleton_metadata
        );
        assert_eq!(runtime.engine.reg_read(REG_X0 + 1).unwrap(), 0);

        let (foreign_candidate, &foreign_metadata) =
            runtime.profile.index.swift_foreign.iter().next().unwrap();
        let foreign_candidate: u64 = foreign_candidate.parse().unwrap();
        assert_eq!(
            runtime.call(foreign_call, &[0, foreign_candidate]).unwrap(),
            foreign_metadata
        );
        assert_eq!(runtime.engine.reg_read(REG_X0 + 1).unwrap(), 0);
        assert!(runtime.call(foreign_call, &[0, 1]).is_err());

        let url_value = runtime.allocate(8).unwrap();
        runtime.write_u64(url_value, 0x1234).unwrap();
        runtime.engine.reg_write(REG_X0 + 20, url_value).unwrap();
        assert_eq!(runtime.call(url_call, &[]).unwrap(), 0x1234);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_hashes_sha512_and_exposes_bundle_resources() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |symbol: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.symbol == symbol)
                .unwrap()
                .address
        };
        let hash_call = call_address("CC_SHA512");
        let main_bundle_call = call_address("CFBundleGetMainBundle");
        let identifier_call = call_address("CFBundleGetIdentifier");
        let bundle_url_call = call_address("CFBundleCopyBundleURL");
        let info_call = call_address("CFBundleGetInfoDictionary");
        let executable_call = call_address("CFBundleCopyExecutableURL");

        let input = runtime.allocate(3).unwrap();
        runtime.engine.mem_write(input, b"abc").unwrap();
        let digest_address = runtime.call(hash_call, &[input, 3, 0]).unwrap();
        let digest = runtime.engine.mem_read(digest_address, 64).unwrap();
        let digest_hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            digest_hex,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let output = runtime.allocate(64).unwrap();
        assert_eq!(
            runtime.call(hash_call, &[input, 3, output]).unwrap(),
            output
        );
        assert_eq!(runtime.engine.mem_read(output, 64).unwrap(), digest);

        let info = runtime.call(info_call, &[0]).unwrap();
        assert_eq!(
            runtime.export(info).unwrap()["CFBundleIdentifier"],
            "me.majd.ipatool"
        );
        assert_eq!(
            runtime.export(info).unwrap()["CFBundleExecutable"],
            "ipatool"
        );
        let executable = runtime.call(executable_call, &[0]).unwrap();
        let state = runtime.state.borrow();
        let StoreValue::String(value) = &state.objects[&executable].value else {
            panic!("bundle executable URL is not a string");
        };
        assert_eq!(value, "file:///ipatool");
        drop(state);

        let bundle = runtime.call(main_bundle_call, &[]).unwrap();
        let identifier = runtime.call(identifier_call, &[bundle]).unwrap();
        assert_eq!(runtime.export(identifier).unwrap(), "me.majd.ipatool");
        let bundle_url = runtime.call(bundle_url_call, &[bundle]).unwrap();
        assert_eq!(runtime.export(bundle_url).unwrap(), "file:///ipatool");
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_parses_formats_and_converts_http_dates() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |symbol: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.symbol == symbol)
                .unwrap()
                .address
        };
        let parse_call = call_address("strptime");
        let format_call = call_address("strftime");
        let timegm_call = call_address("timegm");
        let input = b"Tue, 27 Oct 2026 12:34:56 GMT\0";
        let parse_format = b"%a, %d %b %Y %H:%M:%S %Z\0";
        let output_format = b"%a, %d %b %Y %H:%M:%S GMT\0";
        let input_address = runtime.allocate(input.len() as u64).unwrap();
        let parse_format_address = runtime.allocate(parse_format.len() as u64).unwrap();
        let output_format_address = runtime.allocate(output_format.len() as u64).unwrap();
        let tm_address = runtime.allocate(36).unwrap();
        let output_address = runtime.allocate(30).unwrap();
        runtime.engine.mem_write(input_address, input).unwrap();
        runtime
            .engine
            .mem_write(parse_format_address, parse_format)
            .unwrap();
        runtime
            .engine
            .mem_write(output_format_address, output_format)
            .unwrap();
        assert_eq!(
            runtime
                .call(
                    parse_call,
                    &[input_address, parse_format_address, tm_address]
                )
                .unwrap(),
            input_address + 29
        );
        let tm_bytes = runtime.engine.mem_read(tm_address, 36).unwrap();
        let fields: [i32; 9] = std::array::from_fn(|index| {
            i32::from_le_bytes(tm_bytes[index * 4..index * 4 + 4].try_into().unwrap())
        });
        assert_eq!(fields, [56, 34, 12, 27, 9, 126, 2, 299, 0]);
        assert_eq!(
            runtime.call(timegm_call, &[tm_address]).unwrap(),
            1_793_104_496
        );
        assert_eq!(
            runtime
                .call(
                    format_call,
                    &[output_address, 30, output_format_address, tm_address]
                )
                .unwrap(),
            29
        );
        assert_eq!(runtime.engine.mem_read(output_address, 30).unwrap(), input);
        assert_eq!(
            runtime
                .call(
                    format_call,
                    &[output_address, 29, output_format_address, tm_address]
                )
                .unwrap(),
            0
        );
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_semaphore_wait_runs_runnable_callback() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |symbol: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.symbol == symbol)
                .unwrap()
                .address
        };
        let create = call_address("dispatch_semaphore_create");
        let signal = call_address("dispatch_semaphore_signal");
        let wait = call_address("dispatch_semaphore_wait");
        let semaphore = runtime.call(create, &[0]).unwrap();
        assert!(runtime.call(wait, &[semaphore, 0]).is_err());
        assert_eq!(runtime.call(signal, &[semaphore]).unwrap(), 0);
        assert_eq!(runtime.call(wait, &[semaphore, 0]).unwrap(), 0);

        runtime.write_u64(semaphore + 16, signal).unwrap();
        let suspended_queue = runtime.new_object("HostQueue", StoreValue::Empty).unwrap();
        runtime
            .state
            .borrow_mut()
            .objects
            .get_mut(&suspended_queue)
            .unwrap()
            .properties
            .insert("suspendCount".into(), 1);
        runtime.state.borrow_mut().pending.push(PendingWork::Guest {
            block: semaphore,
            queue: suspended_queue,
            group: None,
        });
        assert!(
            runtime
                .call(wait, &[semaphore, 0])
                .unwrap_err()
                .to_string()
                .contains("all pending queues are suspended")
        );
        runtime.state.borrow_mut().pending.push(PendingWork::Guest {
            block: semaphore,
            queue: 0,
            group: None,
        });
        assert_eq!(runtime.call(wait, &[semaphore, 0]).unwrap(), 0);
        assert_eq!(runtime.state.borrow().pending.len(), 1);
        runtime
            .state
            .borrow_mut()
            .objects
            .get_mut(&suspended_queue)
            .unwrap()
            .properties
            .insert("suspendCount".into(), 0);
        assert_eq!(runtime.call(wait, &[semaphore, 0]).unwrap(), 0);
        assert!(runtime.state.borrow().pending.is_empty());
        let state = runtime.state.borrow();
        let StoreValue::Number(count) = state.objects[&semaphore].value else {
            panic!("guest semaphore count is not numeric");
        };
        assert_eq!(count, 0);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_dispatch_group_wait_drains_runnable_callbacks() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |symbol: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.symbol == symbol)
                .unwrap()
                .address
        };
        let create = call_address("dispatch_group_create");
        let enter = call_address("dispatch_group_enter");
        let leave = call_address("dispatch_group_leave");
        let wait = call_address("dispatch_group_wait");
        let group = runtime.call(create, &[]).unwrap();
        assert_eq!(runtime.call(wait, &[group, 0]).unwrap(), 0);
        assert!(runtime.call(leave, &[group]).is_err());
        runtime.call(enter, &[group]).unwrap();
        runtime.call(enter, &[group]).unwrap();
        assert_eq!(runtime.call(wait, &[group, 0]).unwrap(), 1);
        assert_eq!(runtime.call(wait, &[group, 1]).unwrap(), 1);
        runtime.write_u64(group + 16, leave).unwrap();
        for _ in 0..2 {
            runtime.state.borrow_mut().pending.push(PendingWork::Guest {
                block: group,
                queue: 0,
                group: None,
            });
        }
        assert_eq!(runtime.call(wait, &[group, 1]).unwrap(), 1);
        assert_eq!(runtime.state.borrow().pending.len(), 2);
        assert_eq!(runtime.call(wait, &[group, u64::MAX]).unwrap(), 0);
        assert!(runtime.state.borrow().pending.is_empty());
        let state = runtime.state.borrow();
        let StoreValue::Number(count) = state.objects[&group].value else {
            panic!("guest dispatch group count is not numeric");
        };
        assert_eq!(count, 0);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_swift_group_async_leaves_after_queued_block() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let profile = Arc::clone(&runtime.profile);
        let call_address = |symbol: &str| {
            profile
                .index
                .calls
                .iter()
                .find(|call| call.symbol == symbol)
                .unwrap()
                .address
        };
        let group = runtime
            .call(call_address("dispatch_group_create"), &[])
            .unwrap();
        let semaphore = runtime
            .call(call_address("dispatch_semaphore_create"), &[0])
            .unwrap();
        let queue = runtime.new_object("HostQueue", StoreValue::Empty).unwrap();
        runtime.write_u64(semaphore + 8, 1 << 28).unwrap();
        runtime
            .write_u64(semaphore + 16, call_address("dispatch_semaphore_signal"))
            .unwrap();
        let swift_async = call_address(
            "$sSo17OS_dispatch_queueC8DispatchE5async5group3qos5flags7executeySo0a1_b1_F0CSg_AC0D3QoSVAC0D13WorkItemFlagsVyyXBtF",
        );
        runtime.engine.reg_write(REG_X0 + 20, queue).unwrap();
        assert!(
            runtime
                .call(swift_async, &[semaphore, 0, 0, semaphore])
                .is_err()
        );
        assert_eq!(runtime.state.borrow().pending.len(), 0);
        runtime.engine.reg_write(REG_X0 + 20, queue).unwrap();
        runtime
            .call(swift_async, &[group, 0, 0, semaphore])
            .unwrap();
        assert_eq!(runtime.state.borrow().pending.len(), 1);
        let state = runtime.state.borrow();
        let StoreValue::Number(count) = state.objects[&group].value else {
            panic!("guest dispatch group count is not numeric");
        };
        assert_eq!(count, 1);
        drop(state);
        assert_eq!(
            runtime
                .call(call_address("dispatch_group_wait"), &[group, u64::MAX])
                .unwrap(),
            0
        );
        assert_eq!(runtime.state.borrow().pending.len(), 0);
        assert_eq!(
            runtime
                .call(call_address("dispatch_semaphore_wait"), &[semaphore, 0])
                .unwrap(),
            0
        );
        let state = runtime.state.borrow();
        let StoreValue::Number(count) = state.objects[&group].value else {
            panic!("guest dispatch group count is not numeric");
        };
        assert_eq!(count, 0);
        drop(state);

        let retain = call_address("objc_retain");
        let descriptor = runtime.allocate(32).unwrap();
        runtime.write_u64(descriptor + 8, 32).unwrap();
        runtime.write_u64(descriptor + 16, retain).unwrap();
        let block = runtime.allocate(32).unwrap();
        runtime.write_u64(block + 8, 1 << 25).unwrap();
        runtime.write_u64(block + 16, retain).unwrap();
        runtime.write_u64(block + 24, descriptor).unwrap();
        runtime.engine.reg_write(REG_X0 + 20, queue).unwrap();
        runtime.call(swift_async, &[group, 0, 0, block]).unwrap();
        assert_eq!(runtime.state.borrow().pending.len(), 1);
        assert_eq!(
            runtime
                .call(call_address("dispatch_group_wait"), &[group, u64::MAX])
                .unwrap(),
            0
        );
        let state = runtime.state.borrow();
        let StoreValue::Number(count) = state.objects[&group].value else {
            panic!("guest dispatch group count is not numeric");
        };
        assert_eq!(count, 0);
        drop(state);

        runtime.engine.reg_write(REG_X0 + 20, queue).unwrap();
        runtime
            .call(swift_async, &[group, 0, 0, semaphore])
            .unwrap();
        assert_eq!(
            runtime
                .call(call_address("dispatch_semaphore_wait"), &[semaphore, 0])
                .unwrap(),
            0
        );
        assert_eq!(
            runtime
                .call(call_address("dispatch_group_wait"), &[group, 0])
                .unwrap(),
            0
        );
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_clock_gettime_nsec_uses_host_clock() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol == "clock_gettime_nsec_np")
            .unwrap()
            .address;
        let epoch_nanoseconds = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        };
        let before = epoch_nanoseconds();
        let actual = u128::from(runtime.call(call, &[0]).unwrap());
        let after = epoch_nanoseconds();
        assert!((before..=after).contains(&actual));
        let first = runtime.call(call, &[6]).unwrap();
        let second = runtime.call(call, &[6]).unwrap();
        assert!(first > 0 && second >= first);
        assert!(runtime.call(call, &[u64::MAX]).is_err());
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_getpid_matches_go_emulator() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let calls = runtime
            .profile
            .index
            .calls
            .iter()
            .filter(|call| call.symbol.trim_start_matches('_') == "getpid")
            .map(|call| call.address)
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2);
        for address in calls {
            assert_eq!(runtime.call(address, &[]).unwrap(), 123);
        }
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_mutable_string_append_and_description() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let append = call_address("appendString:");
        let description = call_address("description");
        let receiver = runtime
            .new_object("NSMutableString", StoreValue::String("Hello ".into()))
            .unwrap();
        let suffix = runtime
            .new_object("NSString", StoreValue::String("世界".into()))
            .unwrap();
        assert_eq!(runtime.call(append, &[receiver, 0, suffix]).unwrap(), 0);
        assert_eq!(
            object_string_value(&runtime.state.borrow(), receiver).unwrap(),
            "Hello 世界"
        );
        assert_eq!(runtime.call(description, &[suffix]).unwrap(), suffix);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_locale_methods_match_go_emulator() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let locale_class =
            runtime.profile.index.classes[runtime.profile.runtime.classes_by_name["NSLocale"]]
                .address;
        let current_locale = call_address("currentLocale");
        let preferred_languages = call_address("preferredLanguages");
        let locale = runtime.call(current_locale, &[locale_class]).unwrap();
        assert_eq!(
            object_string_value(&runtime.state.borrow(), locale).unwrap(),
            "en_US"
        );
        let languages = runtime.call(preferred_languages, &[locale_class]).unwrap();
        let state = runtime.state.borrow();
        let StoreValue::Addresses(items) = &state.objects[&languages].value else {
            panic!("preferredLanguages did not return an array");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(object_string_value(&state, items[0]).unwrap(), "en-US");
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_user_defaults_and_file_manager_fallbacks() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let defaults_call = call_address("standardUserDefaults");
        let bool_call = call_address("boolForKey:");
        let set_call = call_address("setObject:forKey:");
        let manager_call = call_address("defaultManager");
        let exists_call = call_address("fileExistsAtPath:");
        let writable_call = call_address("isWritableFileAtPath:");
        let defaults_class = runtime.profile.index.classes
            [runtime.profile.runtime.classes_by_name["NSUserDefaults"]]
            .address;
        let manager_class = runtime.profile.index.classes
            [runtime.profile.runtime.classes_by_name["NSFileManager"]]
            .address;
        let defaults = runtime.call(defaults_call, &[defaults_class]).unwrap();
        let key = runtime
            .new_object("NSString", StoreValue::String("feature".into()))
            .unwrap();
        assert_eq!(runtime.call(bool_call, &[defaults, 0, key]).unwrap(), 0);
        let value = runtime
            .new_object("NSNumber", StoreValue::Number(2))
            .unwrap();
        assert_eq!(
            runtime.call(set_call, &[defaults, 0, value, key]).unwrap(),
            0
        );
        assert_eq!(runtime.call(bool_call, &[defaults, 0, key]).unwrap(), 2);

        let manager = runtime.call(manager_call, &[manager_class]).unwrap();
        let path = runtime
            .new_object("NSString", StoreValue::String("/tmp/nonexistent".into()))
            .unwrap();
        assert_eq!(runtime.call(exists_call, &[manager, 0, path]).unwrap(), 0);
        assert_eq!(runtime.call(writable_call, &[manager, 0, path]).unwrap(), 0);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_character_set_from_string() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.selector == "characterSetWithCharactersInString:")
            .unwrap()
            .address;
        let class = runtime.profile.index.classes
            [runtime.profile.runtime.classes_by_name["NSCharacterSet"]]
            .address;
        let characters = runtime
            .new_object("NSString", StoreValue::String("é9".into()))
            .unwrap();
        let set = runtime.call(call, &[class, 0, characters]).unwrap();
        assert_eq!(
            object_string_value(&runtime.state.borrow(), set).unwrap(),
            "é9"
        );
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_bundle_for_class_uses_ams_identifier() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.selector == "bundleForClass:")
            .unwrap()
            .address;
        let class = |name: &str| {
            runtime.profile.index.classes[runtime.profile.runtime.classes_by_name[name]].address
        };
        let bundle_class = class("NSBundle");
        let ams_class = class("AMSURLRequest");
        let string_class = class("NSString");
        let bundle = runtime.call(call, &[bundle_class, 0, ams_class]).unwrap();
        let identifier = runtime.state.borrow().objects[&bundle].properties["bundleIdentifier"];
        assert_eq!(
            object_string_value(&runtime.state.borrow(), identifier).unwrap(),
            "com.apple.AppleMediaServices"
        );
        let bundle = runtime
            .call(call, &[bundle_class, 0, string_class])
            .unwrap();
        let identifier = runtime.state.borrow().objects[&bundle].properties["bundleIdentifier"];
        assert_eq!(
            object_string_value(&runtime.state.borrow(), identifier).unwrap(),
            "me.majd.ipatool"
        );
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_collection_constructors_copy_containers() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let dictionary_with_dictionary = call_address("dictionaryWithDictionary:");
        let init_with_dictionary = call_address("initWithDictionary:");
        let init_with_array = call_address("initWithArray:");
        let dictionary_class = runtime.profile.index.classes
            [runtime.profile.runtime.classes_by_name["NSDictionary"]]
            .address;
        let value = runtime
            .new_object("NSString", StoreValue::String("value".into()))
            .unwrap();
        let source_dictionary = runtime
            .new_object(
                "NSDictionary",
                StoreValue::Entries(HashMap::from([("key".into(), value)])),
            )
            .unwrap();
        let copied_dictionary = runtime
            .call(
                dictionary_with_dictionary,
                &[dictionary_class, 0, source_dictionary],
            )
            .unwrap();
        let initialized_dictionary = runtime
            .new_object("NSMutableDictionary", StoreValue::Empty)
            .unwrap();
        assert_eq!(
            runtime
                .call(
                    init_with_dictionary,
                    &[initialized_dictionary, 0, source_dictionary]
                )
                .unwrap(),
            initialized_dictionary
        );
        let source_array = runtime
            .new_object("NSArray", StoreValue::Addresses(vec![value]))
            .unwrap();
        let initialized_array = runtime
            .new_object("NSMutableArray", StoreValue::Empty)
            .unwrap();
        assert_eq!(
            runtime
                .call(init_with_array, &[initialized_array, 0, source_array])
                .unwrap(),
            initialized_array
        );
        let mut state = runtime.state.borrow_mut();
        state.objects.get_mut(&source_dictionary).unwrap().value =
            StoreValue::Entries(HashMap::new());
        state.objects.get_mut(&source_array).unwrap().value = StoreValue::Addresses(Vec::new());
        for dictionary in [copied_dictionary, initialized_dictionary] {
            let StoreValue::Entries(entries) = &state.objects[&dictionary].value else {
                panic!("copy is not a dictionary");
            };
            assert_eq!(entries["key"], value);
        }
        let StoreValue::Addresses(items) = &state.objects[&initialized_array].value else {
            panic!("copy is not an array");
        };
        assert_eq!(items.as_slice(), &[value]);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_string_creation_conversion_and_trimming() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let create = call_address("stringWithUTF8String:");
        let append = call_address("stringByAppendingString:");
        let encode = call_address("dataUsingEncoding:");
        let trim = call_address("stringByTrimmingCharactersInSet:");
        let string_class =
            runtime.profile.index.classes[runtime.profile.runtime.classes_by_name["NSString"]]
                .address;
        let bytes = runtime.allocate(16).unwrap();
        runtime.engine.mem_write(bytes, "éx\0".as_bytes()).unwrap();
        let string = runtime.call(create, &[string_class, 0, bytes]).unwrap();
        assert_eq!(
            object_string_value(&runtime.state.borrow(), string).unwrap(),
            "éx"
        );
        let suffix = runtime
            .new_object("NSString", StoreValue::String("世界".into()))
            .unwrap();
        let combined = runtime.call(append, &[string, 0, suffix]).unwrap();
        assert_eq!(
            object_string_value(&runtime.state.borrow(), combined).unwrap(),
            "éx世界"
        );
        let utf8 = runtime.call(encode, &[combined, 0, 4]).unwrap();
        let utf16 = runtime.call(encode, &[combined, 0, 10]).unwrap();
        let state = runtime.state.borrow();
        let StoreValue::Bytes(utf8_bytes) = &state.objects[&utf8].value else {
            panic!("UTF-8 conversion did not return data");
        };
        assert_eq!(utf8_bytes, "éx世界".as_bytes());
        let StoreValue::Bytes(utf16_bytes) = &state.objects[&utf16].value else {
            panic!("UTF-16 conversion did not return data");
        };
        assert_eq!(&utf16_bytes[..2], &[0xff, 0xfe]);
        assert_eq!(utf16_bytes.len(), 10);
        drop(state);
        let padded = runtime
            .new_object("NSString", StoreValue::String("éé hello é".into()))
            .unwrap();
        let characters = runtime
            .new_object("NSCharacterSet", StoreValue::String("é ".into()))
            .unwrap();
        let trimmed = runtime.call(trim, &[padded, 0, characters]).unwrap();
        assert_eq!(
            object_string_value(&runtime.state.borrow(), trimmed).unwrap(),
            "hello"
        );
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_map_table_factories_return_empty_maps() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let class =
            runtime.profile.index.classes[runtime.profile.runtime.classes_by_name["NSMapTable"]]
                .address;
        let calls = runtime
            .profile
            .index
            .calls
            .iter()
            .filter(|call| {
                matches!(
                    call.selector.as_str(),
                    "strongToStrongObjectsMapTable"
                        | "strongToWeakObjectsMapTable"
                        | "weakToStrongObjectsMapTable"
                )
            })
            .map(|call| call.address)
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 3);
        for call in calls {
            let table = runtime.call(call, &[class]).unwrap();
            let state = runtime.state.borrow();
            assert_eq!(state.objects[&table].class, "NSMapTable");
            let StoreValue::Entries(entries) = &state.objects[&table].value else {
                panic!("map table has no dictionary storage");
            };
            assert!(entries.is_empty());
        }
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_directory_and_localization_fallbacks() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let create_path =
            call_address("createDirectoryAtPath:withIntermediateDirectories:attributes:error:");
        let create_url =
            call_address("createDirectoryAtURL:withIntermediateDirectories:attributes:error:");
        let localized = call_address("localizedStringForKey:value:table:");
        let init_error = call_address("initWithDomain:code:userInfo:");
        let manager = runtime
            .new_object("NSFileManager", StoreValue::Empty)
            .unwrap();
        let path = runtime
            .new_object("NSString", StoreValue::String("/ipatool/test".into()))
            .unwrap();
        let out = runtime.allocate(8).unwrap();
        for call in [create_path, create_url] {
            runtime.write_u64(out, 0).unwrap();
            assert_eq!(
                runtime.call(call, &[manager, 0, path, 1, 0, out]).unwrap(),
                0
            );
            let error = runtime.read_u64(out).unwrap();
            let state = runtime.state.borrow();
            let StoreValue::Entries(fields) = &state.objects[&error].value else {
                panic!("directory failure did not return NSError");
            };
            assert_eq!(
                object_string_value(&state, fields["domain"]).unwrap(),
                "NSCocoaErrorDomain"
            );
            let StoreValue::Number(code) = &state.objects[&fields["code"]].value else {
                panic!("directory error code is not numeric");
            };
            assert_eq!(*code, 513);
        }

        let bundle = runtime.new_object("NSBundle", StoreValue::Empty).unwrap();
        let key = runtime
            .new_object("NSString", StoreValue::String("missing.key".into()))
            .unwrap();
        let fallback = runtime
            .new_object("NSString", StoreValue::String("fallback".into()))
            .unwrap();
        let empty = runtime
            .new_object("NSString", StoreValue::String(String::new()))
            .unwrap();
        assert_eq!(
            runtime
                .call(localized, &[bundle, 0, key, fallback, 0])
                .unwrap(),
            fallback
        );
        assert_eq!(
            runtime
                .call(localized, &[bundle, 0, key, empty, 0])
                .unwrap(),
            key
        );

        let error = runtime.new_object("NSError", StoreValue::Empty).unwrap();
        let domain = runtime
            .new_object("NSString", StoreValue::String("TestDomain".into()))
            .unwrap();
        let user_info = runtime
            .new_object("NSDictionary", StoreValue::Entries(HashMap::new()))
            .unwrap();
        assert_eq!(
            runtime
                .call(init_error, &[error, 0, domain, 42, user_info])
                .unwrap(),
            error
        );
        let state = runtime.state.borrow();
        let StoreValue::Entries(fields) = &state.objects[&error].value else {
            panic!("initialized NSError has no fields");
        };
        assert_eq!(fields["domain"], domain);
        assert_eq!(fields["userInfo"], user_info);
        let StoreValue::Number(code) = &state.objects[&fields["code"]].value else {
            panic!("initialized error code is not numeric");
        };
        assert_eq!(*code, 42);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_date_and_string_buffer_initializers() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let init_date = call_address("initWithTimeIntervalSince1970:");
        let equal_date = call_address("isEqualToDate:");
        let init_string = call_address("initWithBytesNoCopy:length:encoding:freeWhenDone:");
        let date = runtime.new_object("NSDate", StoreValue::Empty).unwrap();
        runtime.engine.reg_write(40, 123.5f64.to_bits()).unwrap();
        assert_eq!(runtime.call(init_date, &[date]).unwrap(), date);
        let matching = runtime
            .new_object("NSDate", StoreValue::Float(123.5))
            .unwrap();
        let different = runtime
            .new_object("NSDate", StoreValue::Float(124.0))
            .unwrap();
        assert_eq!(runtime.call(equal_date, &[date, 0, matching]).unwrap(), 1);
        assert_eq!(runtime.call(equal_date, &[date, 0, different]).unwrap(), 0);

        let bytes = "héllo".as_bytes();
        let buffer = runtime.allocate(bytes.len() as u64).unwrap();
        runtime.engine.mem_write(buffer, bytes).unwrap();
        let string = runtime
            .new_object("NSMutableString", StoreValue::Empty)
            .unwrap();
        assert_eq!(
            runtime
                .call(init_string, &[string, 0, buffer, bytes.len() as u64, 4, 1])
                .unwrap(),
            string
        );
        assert_eq!(
            object_string_value(&runtime.state.borrow(), string).unwrap(),
            "héllo"
        );
        assert!(
            runtime
                .call(init_string, &[string, 0, buffer, 1, 10, 0])
                .is_err()
        );
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_collection_removal_uses_value_equality() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call_address = |selector: &str| {
            runtime
                .profile
                .index
                .calls
                .iter()
                .find(|call| call.selector == selector)
                .unwrap()
                .address
        };
        let remove_one = call_address("removeObject:");
        let remove_many = call_address("removeObjectsInArray:");
        let first = runtime
            .new_object("NSString", StoreValue::String("same".into()))
            .unwrap();
        let duplicate = runtime
            .new_object("NSString", StoreValue::String("same".into()))
            .unwrap();
        let different = runtime
            .new_object("NSString", StoreValue::String("other".into()))
            .unwrap();
        let equal = runtime
            .new_object("NSString", StoreValue::String("same".into()))
            .unwrap();
        let collection = runtime
            .new_object(
                "NSMutableArray",
                StoreValue::Addresses(vec![first, different, duplicate]),
            )
            .unwrap();
        assert_eq!(
            runtime.call(remove_one, &[collection, 0, equal]).unwrap(),
            0
        );
        let state = runtime.state.borrow();
        let StoreValue::Addresses(items) = &state.objects[&collection].value else {
            panic!("removal target is not an array");
        };
        assert_eq!(items.as_slice(), &[different]);
        drop(state);

        runtime
            .state
            .borrow_mut()
            .objects
            .get_mut(&collection)
            .unwrap()
            .value = StoreValue::Addresses(vec![first, different, duplicate]);
        let removal = runtime
            .new_object("NSArray", StoreValue::Addresses(vec![equal, different]))
            .unwrap();
        assert_eq!(
            runtime
                .call(remove_many, &[collection, 0, removal])
                .unwrap(),
            0
        );
        let state = runtime.state.borrow();
        let StoreValue::Addresses(items) = &state.objects[&collection].value else {
            panic!("removal target is not an array");
        };
        assert!(items.is_empty());
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_dictionary_copy_items_copies_immediate_values() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.selector == "initWithDictionary:copyItems:")
            .unwrap()
            .address;
        let string = runtime
            .new_object("NSMutableString", StoreValue::String("original".into()))
            .unwrap();
        let array = runtime
            .new_object("NSMutableArray", StoreValue::Addresses(vec![string]))
            .unwrap();
        let number = runtime
            .new_object("NSNumber", StoreValue::Number(7))
            .unwrap();
        let source = runtime
            .new_object(
                "NSDictionary",
                StoreValue::Entries(HashMap::from([
                    ("array".into(), array),
                    ("number".into(), number),
                    ("string".into(), string),
                ])),
            )
            .unwrap();
        let shallow = runtime
            .new_object("NSMutableDictionary", StoreValue::Empty)
            .unwrap();
        let copied = runtime
            .new_object("NSMutableDictionary", StoreValue::Empty)
            .unwrap();
        assert_eq!(
            runtime.call(call, &[shallow, 0, source, 0]).unwrap(),
            shallow
        );
        assert_eq!(runtime.call(call, &[copied, 0, source, 1]).unwrap(), copied);
        let state = runtime.state.borrow();
        let StoreValue::Entries(shallow_entries) = &state.objects[&shallow].value else {
            panic!("shallow copy is not a dictionary");
        };
        assert_eq!(shallow_entries["string"], string);
        assert_eq!(shallow_entries["array"], array);
        let StoreValue::Entries(entries) = &state.objects[&copied].value else {
            panic!("copied value is not a dictionary");
        };
        assert_ne!(entries["string"], string);
        assert_eq!(state.objects[&entries["string"]].class, "NSString");
        assert_eq!(
            object_string_value(&state, entries["string"]).unwrap(),
            "original"
        );
        assert_ne!(entries["array"], array);
        assert_eq!(state.objects[&entries["array"]].class, "NSArray");
        assert_eq!(entries["number"], number);
    }

    #[test]
    #[ignore = "requires cached pinned Apple image and Unicorn library"]
    fn pinned_guest_dictionary_copy_items_runs_native_copy_callback() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let call = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.selector == "initWithDictionary:copyItems:")
            .unwrap()
            .address;
        let custom = runtime
            .new_object("AMSLogConfig", StoreValue::Empty)
            .unwrap();
        let second = runtime
            .new_object("AMSLogConfig", StoreValue::Empty)
            .unwrap();
        assert!(
            runtime
                .method_address("AMSLogConfig", "copyWithZone:", false)
                .is_some()
        );
        let source = runtime
            .new_object(
                "NSDictionary",
                StoreValue::Entries(HashMap::from([
                    ("custom".into(), custom),
                    ("second".into(), second),
                ])),
            )
            .unwrap();
        let target = runtime
            .new_object("NSMutableDictionary", StoreValue::Empty)
            .unwrap();
        assert_eq!(runtime.call(call, &[target, 0, source, 1]).unwrap(), target);
        let state = runtime.state.borrow();
        let StoreValue::Entries(entries) = &state.objects[&target].value else {
            panic!("copy target is not a dictionary");
        };
        assert!(state.objects.contains_key(&entries["custom"]));
        assert!(state.objects.contains_key(&entries["second"]));
    }

    #[test]
    fn purchase_validation_accepts_unrelated_plist_data() {
        let body = br#"<plist version="1.0"><dict><key>price</key><string>0</string><key>salableAdamId</key><string>1234</string><key>pricingParameters</key><string>STDQ</string><key>productType</key><string>C</string><key>opaque</key><data>AQID</data></dict></plist>"#;
        let parameters = serde_json::json!({
            "price": "0", "salableAdamId": "1234", "pricingParameters": "STDQ", "productType": "C"
        });
        let parameters = parameters.as_object().unwrap();
        validate_encoded_purchase(body, parameters).unwrap();
        let changed = serde_json::json!({
            "price": "1", "salableAdamId": "1234", "pricingParameters": "STDQ", "productType": "C"
        });
        assert!(validate_encoded_purchase(body, changed.as_object().unwrap()).is_err());
    }

    #[test]
    fn rejects_unpinned_store_image() {
        assert!(StoreRuntime::open_image(b"wrong image").is_err());
    }

    #[test]
    fn limits_authenticated_store_urls() {
        for value in [
            "https://apple.com/path",
            "https://buy.itunes.apple.com/path",
            "https://images.mzstatic.com/a",
        ] {
            assert!(allowed_store_url(&url::Url::parse(value).unwrap(), true));
        }
        for value in [
            "http://apple.com/path",
            "https://example.com/path",
            "https://apple.com.evil.test/path",
            "https://apple.com/path#fragment",
            "https://user@apple.com/path",
        ] {
            assert!(!allowed_store_url(&url::Url::parse(value).unwrap(), true));
        }
    }

    #[test]
    fn swift_continuation_semaphore_and_group_run_pending_http_callbacks() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let request = runtime
            .new_object("AMSURLRequest", StoreValue::Empty)
            .unwrap();
        let url = runtime
            .new_object(
                "NSURL",
                StoreValue::String("https://buy.itunes.apple.com/request".into()),
            )
            .unwrap();
        let request = runtime
            .invoke(
                request,
                "initWithURL:cachePolicy:timeoutInterval:",
                &[url, 0, 0],
            )
            .unwrap();
        let session = runtime.new_session().unwrap();
        let http_task = runtime
            .new_object("NSURLSessionDataTask", StoreValue::Empty)
            .unwrap();
        {
            let mut state = runtime.state.borrow_mut();
            state
                .objects
                .get_mut(&session)
                .unwrap()
                .properties
                .insert("delegate".into(), session);
            state
                .objects
                .get_mut(&http_task)
                .unwrap()
                .properties
                .extend([
                    ("currentRequest".into(), request),
                    ("session".into(), session),
                    ("state".into(), 0),
                ]);
            state.pending.push(PendingWork::Http { task: http_task });
        }
        runtime.set_transport(|request| {
            assert_eq!(request.url.as_str(), "https://buy.itunes.apple.com/request");
            Ok(HostResponse {
                status: 200,
                headers: HashMap::from([("content-type".into(), "application/x-apple-plist".into())]),
                body: br#"<plist version="1.0"><dict><key>status</key><integer>0</integer></dict></plist>"#.to_vec(),
            })
        });
        assert_eq!(runtime.state.borrow().pending.len(), 1);

        let continuation = runtime.allocate(64).unwrap();
        let swift_task = runtime.allocate(64).unwrap();
        runtime.write_u64(continuation + 24, 0).unwrap();
        {
            let mut state = runtime.state.borrow_mut();
            state.swift_tasks.insert(
                swift_task,
                SwiftTask {
                    context: 0,
                    entry: 0,
                    closure: 0,
                    result: 0,
                    continuation: Some(continuation),
                    executor: [0; 2],
                    done: false,
                },
            );
            state.current_swift_task = Some(swift_task);
        }
        let await_call = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol.trim_start_matches('_') == "swift_continuation_await")
            .unwrap()
            .address;
        // This synthetic task has no guest code to resume its continuation.
        // Exhausting the queued work is expected after each callback phase.
        let error = runtime.call(await_call, &[continuation]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Swift continuation has no runnable completion"),
            "{error:#}"
        );
        assert!(
            runtime
                .state
                .borrow()
                .http_responses
                .contains_key(&http_task)
        );
        runtime
            .state
            .borrow_mut()
            .pending
            .push(PendingWork::DeliverData { task: http_task });
        let error = runtime.call(await_call, &[continuation]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Swift continuation has no runnable completion"),
            "{error:#}"
        );
        let state = runtime.state.borrow();
        assert_eq!(state.objects[&http_task].properties["state"], 3);
        assert!(state.pending.is_empty());
        drop(state);

        let create_semaphore = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol == "dispatch_semaphore_create")
            .unwrap()
            .address;
        let wait_semaphore = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol == "dispatch_semaphore_wait")
            .unwrap()
            .address;
        let semaphore = runtime.call(create_semaphore, &[0]).unwrap();
        {
            let mut state = runtime.state.borrow_mut();
            state.current_swift_task = None;
            state.pending.push(PendingWork::Http { task: http_task });
        }
        let error = runtime.call(wait_semaphore, &[semaphore, 0]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("guest semaphore remains unsignaled"),
            "{error:#}"
        );
        assert!(
            runtime
                .state
                .borrow()
                .http_responses
                .contains_key(&http_task)
        );

        let group_create = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol == "dispatch_group_create")
            .unwrap()
            .address;
        let group_enter = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol == "dispatch_group_enter")
            .unwrap()
            .address;
        let group_wait = runtime
            .profile
            .index
            .calls
            .iter()
            .find(|call| call.symbol == "dispatch_group_wait")
            .unwrap()
            .address;
        let group = runtime.call(group_create, &[]).unwrap();
        runtime.call(group_enter, &[group]).unwrap();
        {
            let mut state = runtime.state.borrow_mut();
            state.http_responses.remove(&http_task);
            state.pending.push(PendingWork::Http { task: http_task });
        }
        assert_eq!(runtime.call(group_wait, &[group, u64::MAX - 1]).unwrap(), 1);
        assert!(
            runtime
                .state
                .borrow()
                .http_responses
                .contains_key(&http_task)
        );
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
        let mut saved = Account::default();
        saved.email = "saved@example.com".into();
        saved.password_token = "saved-token".into();
        saved.directory_services_id = "12345".into();
        saved.store_front = "143441-1,29".into();
        let saved_ephemeral = runtime.ephemeral_account(Some(&saved)).unwrap();
        assert_eq!(
            runtime.state.borrow().objects[&saved_ephemeral].class,
            "AMSEphemeralAccount"
        );
        let username = runtime.invoke(saved_ephemeral, "username", &[]).unwrap();
        assert_eq!(runtime.object_string(username).unwrap(), saved.email);
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
            .encode_request(
                ephemeral,
                0,
                "POST",
                "https://buy.itunes.apple.com/request",
                &nested,
            )
            .unwrap();
        assert_eq!(
            runtime.state.borrow().objects[&request].class,
            "AMSURLRequest"
        );
        let url = runtime.invoke(request, "URL", &[]).unwrap();
        assert_eq!(
            runtime.object_string(url).unwrap(),
            "https://buy.itunes.apple.com/request"
        );
        let host_request = runtime.host_request(request, true, true, None).unwrap();
        assert_eq!(host_request.method, Method::POST);
        assert_eq!(
            host_request.url.as_str(),
            "https://buy.itunes.apple.com/request"
        );
        runtime
            .configure_request(request, ephemeral, 0, false)
            .unwrap();
        let session = runtime.new_session().unwrap();
        assert_eq!(
            runtime.state.borrow().objects[&session].class,
            "AMSURLSession"
        );
        let client_delegate = runtime.new_object("NSObject", StoreValue::Empty).unwrap();
        runtime
            .invoke(session, "setDelegate:", &[client_delegate])
            .unwrap();
        let task = runtime
            .invoke(session, "dataTaskWithRequest:", &[request])
            .unwrap();
        assert_eq!(
            runtime.state.borrow().objects[&task].class,
            "NSURLSessionDataTask"
        );
        assert_eq!(
            runtime.invoke(task, "currentRequest", &[]).unwrap(),
            request
        );
        runtime.set_transport(|request| {
            assert_eq!(request.url.as_str(), "https://buy.itunes.apple.com/request");
            Ok(HostResponse {
                status: 200,
                headers: HashMap::from([("content-type".into(), "application/x-apple-plist".into())]),
                body: br#"<plist version="1.0"><dict><key>status</key><integer>0</integer></dict></plist>"#.to_vec(),
            })
        });
        let (result, response) = runtime.send_request(session, request).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("content-type"),
            Some("application/x-apple-plist")
        );
        let object = runtime.invoke(result, "object", &[]).unwrap();
        assert_eq!(runtime.export(object).unwrap()["status"], 0);
        let headers = HeaderMap::new();
        let decoded = runtime
            .execute_standard(StoreStandardRequest {
                method: "POST",
                url: "https://buy.itunes.apple.com/request",
                headers: &headers,
                parameters: Some(&nested),
                body: None,
                bag: None,
                hardware_id: &[1, 2, 3, 4, 5, 6],
                raw: false,
                response_format: "plist",
                no_redirects: true,
                timeout: None,
            })
            .unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(
            plist::from_bytes::<Value>(&decoded.body).unwrap()["status"],
            0
        );
        runtime.set_transport(|request| {
            assert_eq!(request.method, Method::POST);
            assert_eq!(request.body.as_deref(), Some(b"raw request".as_slice()));
            assert_eq!(request.headers.get("x-test").unwrap(), "present, second");
            Ok(HostResponse {
                status: 200,
                headers: HashMap::from([(
                    "content-type".into(),
                    "application/octet-stream".into(),
                )]),
                body: b"raw response".to_vec(),
            })
        });
        let mut raw_headers = HeaderMap::new();
        raw_headers.insert("x-test", HeaderValue::from_static("present"));
        raw_headers.append("x-test", HeaderValue::from_static("second"));
        let raw = runtime
            .execute_standard(StoreStandardRequest {
                method: "POST",
                url: "https://buy.itunes.apple.com/request",
                headers: &raw_headers,
                parameters: None,
                body: Some(b"raw request"),
                bag: None,
                hardware_id: &[1, 2, 3, 4, 5, 6],
                raw: true,
                response_format: "",
                no_redirects: true,
                timeout: None,
            })
            .unwrap();
        assert_eq!(raw.body, b"raw response");
        let bag = runtime
            .frozen_bag_from_values(&serde_json::json!({
                "buyProduct": "https://buy.itunes.apple.com/request",
                "redirect-cookie-removal-exclusion-list": [],
                "clientIDDomains": [],
                "storefront-header-suffix": "29",
                "absinthe-requests": false
            }))
            .unwrap();
        let storefront = runtime
            .new_object("NSString", StoreValue::String("143441-1,29".into()))
            .unwrap();
        runtime
            .invoke(ephemeral, "ams_setStorefront:", &[storefront])
            .unwrap();
        runtime
            .configure_request(request, ephemeral, bag, false)
            .unwrap();
        let configured = runtime.invoke(request, "properties", &[]).unwrap();
        assert_eq!(runtime.invoke(configured, "bag", &[]).unwrap(), bag);
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

    #[test]
    fn encodes_free_purchase_with_pinned_apple_code() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        runtime.set_hardware_id(&[0, 1, 2, 3, 4, 5]).unwrap();
        let mut saved = Account::default();
        saved.email = "test@example.com".into();
        saved.password_token = "test-token".into();
        saved.directory_services_id = "123456".into();
        saved.store_front = "143441-1,29".into();
        let account = runtime.ephemeral_account(Some(&saved)).unwrap();
        let bag = runtime
            .frozen_bag_from_values(&serde_json::json!({
                "buyProduct": "https://buy.itunes.apple.com/request"
            }))
            .unwrap();
        let request = runtime
            .encode_purchase_request(
                account,
                bag,
                &serde_json::json!({
                    "salableAdamId": "1234",
                    "pricingParameters": "STDQ",
                    "price": "0",
                    "productType": "C",
                    "appleId": "test@example.com",
                    "password": "test"
                }),
            )
            .unwrap();
        let url = runtime.invoke(request, "URL", &[]).unwrap();
        assert_eq!(
            runtime.object_string(url).unwrap(),
            "https://buy.itunes.apple.com/request"
        );
    }

    #[test]
    fn frozen_bag_keeps_binary_data_and_date_objects() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        let bag: plist::Value = plist::from_bytes(
            br#"<plist version="1.0"><dict><key>unrelatedCertificate</key><data>AQID</data><key>unrelatedDate</key><date>2024-05-01T00:00:00Z</date></dict></plist>"#,
        )
        .unwrap();
        runtime.frozen_bag_from_plist(&bag).unwrap();
        let state = runtime.state.borrow();
        assert!(state.objects.values().any(|object| {
            object.class == "NSData"
                && matches!(&object.value, StoreValue::Bytes(bytes) if bytes == &[1, 2, 3])
        }));
        assert!(state.objects.values().any(|object| {
            object.class == "NSDate"
                && matches!(object.value, StoreValue::Float(seconds) if seconds == 1_714_521_600.0)
        }));
    }

    #[test]
    fn executes_free_purchase_with_pinned_apple_code() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        runtime.set_transport(|request| {
            assert_eq!(request.method, Method::POST);
            assert_eq!(request.url.as_str(), "https://buy.itunes.apple.com/request");
            let body: Value = plist::from_bytes(request.body.as_ref().unwrap()).unwrap();
            assert_eq!(body["salableAdamId"], "1234");
            assert_eq!(body["price"], "0");
            Ok(HostResponse {
                status: 200,
                headers: HashMap::from([("content-type".into(), "application/x-apple-plist".into())]),
                body: br#"<plist version="1.0"><dict><key>status</key><integer>0</integer></dict></plist>"#.to_vec(),
            })
        });
        let mut headers = HeaderMap::new();
        headers.insert("X-Dsid", HeaderValue::from_static("123456"));
        headers.insert("X-Token", HeaderValue::from_static("test-token"));
        headers.insert(
            "X-Apple-Store-Front",
            HeaderValue::from_static("143441-1,29"),
        );
        let parameters = serde_json::json!({
            "salableAdamId": "1234",
            "pricingParameters": "STDQ",
            "price": "0",
            "productType": "C",
            "appleId": "test@example.com",
            "password": "test"
        });
        let bag = plist::to_value(
            &serde_json::json!({"buyProduct": "https://buy.itunes.apple.com/stale"}),
        )
        .unwrap();
        let response = runtime
            .execute_purchase(StoreStandardRequest {
                method: "POST",
                url: "https://buy.itunes.apple.com/request",
                headers: &headers,
                parameters: Some(&parameters),
                body: None,
                bag: Some(&bag),
                hardware_id: &[0, 1, 2, 3, 4, 5],
                raw: false,
                response_format: "plist",
                no_redirects: false,
                timeout: None,
            })
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            plist::from_bytes::<Value>(&response.body).unwrap()["status"],
            0
        );
    }

    #[test]
    fn preserves_purchase_failure_response_for_appstore_error_handling() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        runtime.set_transport(|_| {
            Ok(HostResponse {
                status: 200,
                headers: HashMap::from([("content-type".into(), "application/x-apple-plist".into())]),
                body: br#"<plist version="1.0"><dict><key>failureType</key><string>9610</string><key>customerMessage</key><string>fixture-value</string></dict></plist>"#.to_vec(),
            })
        });
        let mut headers = HeaderMap::new();
        headers.insert("X-Dsid", HeaderValue::from_static("123456"));
        headers.insert("X-Token", HeaderValue::from_static("test-token"));
        headers.insert(
            "X-Apple-Store-Front",
            HeaderValue::from_static("143441-1,29"),
        );
        let parameters = serde_json::json!({
            "salableAdamId": "1234",
            "pricingParameters": "STDQ",
            "price": "0",
            "productType": "C",
            "appleId": "test@example.com",
            "password": "test"
        });
        let bag = plist::to_value(
            &serde_json::json!({"buyProduct": "https://buy.itunes.apple.com/request"}),
        )
        .unwrap();
        let response = runtime
            .execute_purchase(StoreStandardRequest {
                method: "POST",
                url: "https://buy.itunes.apple.com/request",
                headers: &headers,
                parameters: Some(&parameters),
                body: None,
                bag: Some(&bag),
                hardware_id: &[0, 1, 2, 3, 4, 5],
                raw: false,
                response_format: "plist",
                no_redirects: false,
                timeout: None,
            })
            .unwrap();
        let body: Value = plist::from_bytes(&response.body).unwrap();
        assert_eq!(body["failureType"], "9610");
        assert_eq!(body["customerMessage"], "fixture-value");
    }

    #[test]
    fn executes_signed_authentication_with_pinned_apple_code() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        runtime.set_transport(|request| {
            assert_eq!(request.method, Method::POST);
            assert_eq!(request.url.as_str(), "https://buy.itunes.apple.com/request");
            assert_eq!(
                request.headers.get("x-apple-actionsignature").unwrap(),
                "AQID"
            );
            let body: Value = plist::from_bytes(request.body.as_ref().unwrap()).unwrap();
            assert_eq!(body["appleId"], "test@example.com");
            assert_eq!(body["guid"], "000102030405");
            assert_eq!(body["attempt"], 2);
            assert_eq!(body["why"], "signin");
            Ok(HostResponse {
                status: 200,
                headers: HashMap::from([("content-type".into(), "application/x-apple-plist".into())]),
                body: br#"<plist version="1.0"><dict><key>status</key><integer>0</integer></dict></plist>"#.to_vec(),
            })
        });
        let parameters = serde_json::json!({
            "appleId": "test@example.com",
            "password": "test",
            "attempt": 2,
            "why": "signin"
        });
        let bag = plist::to_value(
            &serde_json::json!({"buyProduct": "https://buy.itunes.apple.com/request"}),
        )
        .unwrap();
        let mut signer = |body: &[u8]| {
            assert!(!body.is_empty());
            Ok(vec![1, 2, 3])
        };
        let response = runtime
            .execute_authentication(
                StoreStandardRequest {
                    method: "POST",
                    url: "https://buy.itunes.apple.com/request",
                    headers: &HeaderMap::new(),
                    parameters: Some(&parameters),
                    body: None,
                    bag: Some(&bag),
                    hardware_id: &[0, 1, 2, 3, 4, 5],
                    raw: false,
                    response_format: "plist",
                    no_redirects: false,
                    timeout: None,
                },
                &mut signer,
            )
            .unwrap();
        assert_eq!(response.status, 200);
    }

    #[test]
    fn signs_raw_purchase_history_request_with_pinned_apple_code() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let mut runtime = StoreRuntime::open(&assets).unwrap();
        runtime.set_transport(|request| {
            assert_eq!(request.method, Method::POST);
            assert_eq!(
                request.url.as_str(),
                "https://pd.itunes.apple.com/WebObjects/MZPurchaseDaap.woa/purchase/update"
            );
            assert_eq!(
                request.headers.get("x-apple-actionsignature").unwrap(),
                "AQID"
            );
            assert_eq!(request.body.as_deref(), Some(b"session-id=7".as_slice()));
            Ok(HostResponse {
                status: 200,
                headers: HashMap::new(),
                body: b"raw DMAP response".to_vec(),
            })
        });
        let mut headers = HeaderMap::new();
        headers.insert("X-Dsid", HeaderValue::from_static("123456"));
        headers.insert("X-Token", HeaderValue::from_static("test-token"));
        headers.insert(
            "X-Apple-Store-Front",
            HeaderValue::from_static("143441-1,34"),
        );
        let mut signer = |body: &[u8]| {
            assert_eq!(body, b"session-id=7");
            Ok(vec![1, 2, 3])
        };
        let response = runtime.execute_standard_signed(
            StoreStandardRequest {
                method: "POST",
                url: "https://pd.itunes.apple.com/WebObjects/MZPurchaseDaap.woa/purchase/update",
                headers: &headers,
                parameters: None,
                body: Some(b"session-id=7"),
                bag: None,
                hardware_id: &[0, 1, 2, 3, 4, 5],
                raw: true,
                response_format: "raw",
                no_redirects: false,
                timeout: None,
            },
            &mut signer,
        ).unwrap();
        assert_eq!(response.body, b"raw DMAP response");
    }
}
