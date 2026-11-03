//! Load a matching fairplayd image and resume a private checkpoint for a
//! bounded span. Supported external imports have Rust guest-memory models;
//! other imports remain named stubs until their host services are modeled.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
    rc::Rc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use flate2::{Compression, write::GzEncoder};
use serde::Serialize;
use serde_pickle::{HashableValue, SerOptions, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    arm64_compat::{emulate_hook_instruction, emulate_preserved_pointer_auth},
    fairplay_checkpoint::{FairplayCheckpoint, clear_value},
    fairplay_recovery_output::write_private_binary,
    machimage::{Image, without_pointer_authentication},
    store_memory::MemoryRegion,
    unicorn_runtime::{Engine, HookContext, REG_PC},
};

const EXTERNAL_BASE: u64 = 0xf100_0000_0000_0000;
const EXTERNAL_STRIDE: u64 = 0x1000;
const MAX_EXTERNALS: usize = 1 << 20;
const MAX_ONCE_TOKENS: usize = 65_536;
const PAGE_BYTES: u64 = 4096;
const MAX_SNAPSHOT_PAGES: usize = 30_000;
const MAX_EXTERNAL_BYTES: u64 = 0x1000_0000;
const EXTERNAL_CHUNK_BYTES: usize = 64 * 1024;
const MAX_VIRTUAL_FILE_BYTES: usize = 128 * 1024 * 1024;
const MAX_VIRTUAL_FILES: usize = 1024;
const DARWIN_STAT_BYTES: usize = 144;
const MAX_DARWIN_OBJECTS: usize = 4096;
const MAX_CF_DATA_BYTES: usize = 1024 * 1024;
const MAX_CF_STRING_BYTES: usize = 64 * 1024;
const MAX_CF_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const CF_STRING_TYPE_ID: u64 = 0x535452;
const CF_BOOLEAN_TYPE_ID: u64 = 0x424f4f4c;
const CF_DATA_TYPE_ID: u64 = 0x44415441;
const IOKIT15_STRUCTURE_BYTES: usize = 0x228;
const RET_X30: [u8; 4] = 0xd65f_03c0u32.to_le_bytes();
const SYNTHETIC_ERRNO_ADDRESS: u64 = 0x7100_fff0_0000;
const SYNTHETIC_NOOP_CALLBACK: u64 = 0x7200_0000_0000;
const SYNTHETIC_DLOPEN_HANDLE: u64 = 0x7000_3000_0000;
const SYNTHETIC_DLSYM_BASE: u64 = 0x7000_4000_0000;
const MAX_DYNAMIC_SYMBOLS: usize = 1024;
const MAX_SHA1_CONTEXTS: usize = 64;
const MAX_SHA1_INPUT_BYTES: usize = 32 * 1024 * 1024;
const SYNTHETIC_THREAD: u64 = 0x7000_2000_0000;
const PTHREAD_ONCE_STUB: [u32; 6] = [
    0xa9bf_7bfd, // stp x29, x30, [sp, #-16]!
    0x9100_03fd, // mov x29, sp
    0xd63f_0020, // blr x1
    0xa8c1_7bfd, // ldp x29, x30, [sp], #16
    0x5280_0000, // mov w0, #0
    0xd65f_03c0, // ret x30
];
const SYNTHETIC_ALLOCATION_BASE: u64 = 0x7101_0000_0000;
const LAZY_DATA_START: u64 = 0x7000_0000_0000;
const LAZY_DATA_END: u64 = 0x8000_0000_0000;
const STATIC_ALLOCATION_START: u64 = 0x7000_1000_0000;
const STATIC_ALLOCATION_END: u64 = 0x7000_2000_0000;
const STATIC_ALLOCATION_STRIDE: u64 = 0x10_0000;

struct HostState {
    random_state: u32,
    dynamic_symbols: BTreeMap<u64, String>,
    sha1_contexts: BTreeMap<u64, Zeroizing<Vec<u8>>>,
}

impl HostState {
    fn from_checkpoint(checkpoint: &FairplayCheckpoint) -> Result<Self> {
        let mut state = Self {
            random_state: checkpoint.random_state()?,
            dynamic_symbols: BTreeMap::new(),
            sha1_contexts: BTreeMap::new(),
        };
        if let Some(value) = checkpoint.optional_metadata("dynamic_symbols") {
            let Value::Dict(symbols) = value else {
                bail!("FairPlay dynamic symbols are not a dictionary");
            };
            if symbols.len() > MAX_DYNAMIC_SYMBOLS {
                bail!("too many FairPlay dynamic symbols");
            }
            for (index, (key, value)) in symbols.iter().enumerate() {
                let address = pickle_hash_u64(key)?;
                if address != SYNTHETIC_DLSYM_BASE + index as u64 * PAGE_BYTES {
                    bail!("FairPlay dynamic symbol address is invalid");
                }
                let Value::String(symbol) = value else {
                    bail!("FairPlay dynamic symbol name is invalid");
                };
                if symbol.is_empty() || symbol.len() > 1024 {
                    bail!("FairPlay dynamic symbol name is outside the bounded range");
                }
                state.dynamic_symbols.insert(address, symbol.clone());
            }
        }
        if let Some(value) = checkpoint.optional_metadata("sha1_contexts") {
            let Value::Dict(contexts) = value else {
                bail!("FairPlay SHA-1 contexts are not a dictionary");
            };
            if contexts.len() > MAX_SHA1_CONTEXTS {
                bail!("too many FairPlay SHA-1 contexts");
            }
            let mut total = 0usize;
            for (key, value) in contexts {
                let address = pickle_hash_u64(key)?;
                let Value::Bytes(bytes) = value else {
                    bail!("FairPlay SHA-1 context data is not bytes");
                };
                total = total
                    .checked_add(bytes.len())
                    .context("SHA-1 context size overflow")?;
                if total > MAX_SHA1_INPUT_BYTES {
                    bail!("FairPlay SHA-1 contexts exceed input limit");
                }
                state
                    .sha1_contexts
                    .insert(address, Zeroizing::new(bytes.clone()));
            }
        }
        Ok(state)
    }

    fn dynamic_symbols_snapshot(&self) -> Value {
        Value::Dict(
            self.dynamic_symbols
                .iter()
                .map(|(&address, name)| {
                    (
                        HashableValue::Int(address.into()),
                        Value::String(name.clone()),
                    )
                })
                .collect(),
        )
    }

    fn sha1_contexts_snapshot(&self) -> Value {
        Value::Dict(
            self.sha1_contexts
                .iter()
                .map(|(&address, bytes)| {
                    (
                        HashableValue::Int(address.into()),
                        Value::Bytes(bytes.to_vec()),
                    )
                })
                .collect(),
        )
    }
}

#[derive(Clone, Copy)]
pub struct VirtualFileStat {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Serialize)]
pub struct MemoryTraceEvent {
    pub ordinal: usize,
    pub pc: String,
    pub address: String,
    pub size: u32,
}

#[derive(Default, Debug, Serialize)]
pub struct MemoryTrace {
    pub memory_read_events: Vec<MemoryTraceEvent>,
    pub memory_write_events: Vec<MemoryTraceEvent>,
    #[serde(skip)]
    next_ordinal: usize,
}

pub struct MemoryTraceOptions {
    pub reads: bool,
    pub writes: bool,
    pub max_events: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryReadStop {
    pub pc: u64,
    pub address: u64,
    pub size: u32,
}

fn record_memory_event(
    context: &HookContext,
    address: u64,
    size: u32,
    is_read: bool,
    trace: &RefCell<MemoryTrace>,
    maximum: usize,
    failure: &RefCell<Option<String>>,
) {
    let mut trace = trace.borrow_mut();
    if trace.next_ordinal >= maximum {
        *failure.borrow_mut() = Some("FairPlay memory trace event limit reached".to_owned());
        let _ = context.stop();
        return;
    }
    let pc = match context.reg_read(REG_PC) {
        Ok(pc) => pc,
        Err(error) => {
            *failure.borrow_mut() = Some(format!("read FairPlay trace PC: {error:#}"));
            let _ = context.stop();
            return;
        }
    };
    let event = MemoryTraceEvent {
        ordinal: trace.next_ordinal,
        pc: format!("{pc:#x}"),
        address: format!("{address:#x}"),
        size,
    };
    trace.next_ordinal += 1;
    if is_read {
        trace.memory_read_events.push(event);
    } else {
        trace.memory_write_events.push(event);
    }
}

impl Default for VirtualFileStat {
    fn default() -> Self {
        Self {
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }
}

struct OpenVirtualFile {
    data: Zeroizing<Vec<u8>>,
    offset: usize,
    path: Vec<u8>,
    suffix: Vec<u8>,
}

struct VirtualFileState {
    payloads: BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>,
    stats: BTreeMap<Vec<u8>, VirtualFileStat>,
    open: BTreeMap<u64, OpenVirtualFile>,
    next_fd: u64,
    removed: BTreeSet<Vec<u8>>,
    missing_are_enoent: bool,
}

fn pickle_u64(value: &Value) -> Result<u64> {
    match value {
        Value::I64(value) => Ok(u64::try_from(*value)?),
        Value::Int(value) => Ok(value.to_string().parse()?),
        _ => bail!("FairPlay virtual file number has invalid type"),
    }
}

fn pickle_field<'a>(fields: &'a BTreeMap<HashableValue, Value>, name: &str) -> Result<&'a Value> {
    fields
        .get(&HashableValue::String(name.into()))
        .with_context(|| format!("FairPlay open-file entry has no {name}"))
}

impl VirtualFileState {
    fn from_checkpoint(checkpoint: &FairplayCheckpoint) -> Result<Self> {
        let mut state = Self {
            payloads: BTreeMap::new(),
            stats: BTreeMap::new(),
            open: BTreeMap::new(),
            next_fd: 100,
            removed: BTreeSet::new(),
            missing_are_enoent: false,
        };
        if let Some(value) = checkpoint.optional_metadata("next_fd") {
            state.next_fd = pickle_u64(value)?;
        }
        if let Some(value) = checkpoint.optional_metadata("open_files") {
            let Value::Dict(entries) = value else {
                bail!("FairPlay open_files is not a dictionary");
            };
            if entries.len() > MAX_VIRTUAL_FILES {
                bail!("FairPlay checkpoint has too many open files");
            }
            for (key, value) in entries {
                let descriptor = match key {
                    HashableValue::I64(value) => u64::try_from(*value)?,
                    HashableValue::Int(value) => value.to_string().parse()?,
                    _ => bail!("FairPlay open-file descriptor has invalid type"),
                };
                if descriptor >= state.next_fd {
                    bail!("FairPlay checkpoint has invalid next_fd");
                }
                let Value::Dict(fields) = value else {
                    bail!("FairPlay open-file entry is not a dictionary");
                };
                let Value::Bytes(data) = pickle_field(fields, "data")? else {
                    bail!("FairPlay open-file data is not bytes");
                };
                let Value::Bytes(path) = pickle_field(fields, "path")? else {
                    bail!("FairPlay open-file path is not bytes");
                };
                let Value::Bytes(suffix) = pickle_field(fields, "suffix")? else {
                    bail!("FairPlay open-file suffix is not bytes");
                };
                let offset = usize::try_from(pickle_u64(pickle_field(fields, "offset")?)?)?;
                if data.len() > MAX_VIRTUAL_FILE_BYTES {
                    bail!("FairPlay open-file size exceeds limit");
                }
                state.open.insert(
                    descriptor,
                    OpenVirtualFile {
                        data: Zeroizing::new(data.clone()),
                        offset,
                        path: path.clone(),
                        suffix: suffix.clone(),
                    },
                );
            }
        }
        if let Some(value) = checkpoint.optional_metadata("removed_file_suffixes") {
            let Value::List(suffixes) = value else {
                bail!("FairPlay removed_file_suffixes is not a list");
            };
            for suffix in suffixes {
                let Value::String(suffix) = suffix else {
                    bail!("FairPlay removed-file suffix is not a string");
                };
                state.removed.insert(suffix.as_bytes().to_vec());
            }
        }
        Ok(state)
    }

    fn match_file(&self, path: &[u8]) -> Option<(&Vec<u8>, &Zeroizing<Vec<u8>>)> {
        self.payloads
            .iter()
            .filter(|(suffix, _)| !self.removed.contains(*suffix) && path.ends_with(suffix))
            .max_by_key(|(suffix, _)| suffix.len())
    }

    fn snapshot(&self) -> (Value, Value, Value) {
        let open = self
            .open
            .iter()
            .map(|(&descriptor, entry)| {
                let fields = [
                    ("data", Value::Bytes(entry.data.to_vec())),
                    ("offset", Value::Int(entry.offset.into())),
                    ("path", Value::Bytes(entry.path.clone())),
                    ("suffix", Value::Bytes(entry.suffix.clone())),
                ]
                .into_iter()
                .map(|(name, value)| (HashableValue::String(name.into()), value))
                .collect();
                (HashableValue::Int(descriptor.into()), Value::Dict(fields))
            })
            .collect();
        let removed = self
            .removed
            .iter()
            .map(|suffix| Value::String(String::from_utf8_lossy(suffix).into_owned()))
            .collect();
        (
            Value::Dict(open),
            Value::Int(self.next_fd.into()),
            Value::List(removed),
        )
    }
}

enum CfValue {
    Boolean(bool),
    Data(Zeroizing<Vec<u8>>),
    String(Zeroizing<Vec<u8>>),
}

fn validate_iokit15_output(output: &[u8]) -> Result<()> {
    if output.len() != IOKIT15_STRUCTURE_BYTES {
        bail!("FairPlay IOKit selector 0x15 output must be 0x228 bytes");
    }
    let length = u32::from_le_bytes(output[0x220..0x224].try_into()?);
    let status = u32::from_le_bytes(output[0x224..0x228].try_into()?);
    if length > 0x200 || status != 0 {
        bail!("FairPlay IOKit selector 0x15 output has invalid length or status");
    }
    Ok(())
}

impl CfValue {
    fn byte_len(&self) -> usize {
        match self {
            Self::Boolean(_) => 0,
            Self::Data(bytes) | Self::String(bytes) => bytes.len(),
        }
    }
}

struct DarwinState {
    next_iterator: u64,
    next_service: u64,
    next_connection: u64,
    next_bootstrap_port: u64,
    next_cf_object: u64,
    next_xpc_connection: u64,
    iterator_services: BTreeMap<u64, u64>,
    cf_values: BTreeMap<u64, CfValue>,
    mac_address: [u8; 6],
    iokit15_output: Option<Zeroizing<Vec<u8>>>,
}

type ServiceRefs<'a> = (
    &'a Rc<RefCell<HostState>>,
    &'a Rc<RefCell<VirtualFileState>>,
    &'a Rc<RefCell<DarwinState>>,
);

impl Drop for DarwinState {
    fn drop(&mut self) {
        self.mac_address.zeroize();
    }
}

impl DarwinState {
    fn from_checkpoint(checkpoint: &FairplayCheckpoint) -> Result<Self> {
        let mut state = Self {
            next_iterator: 0x100,
            next_service: 0x200,
            next_connection: 0x300,
            next_bootstrap_port: 0x500,
            next_cf_object: 0x7000_7000_0000,
            next_xpc_connection: 0x7000_9000_0000,
            iterator_services: BTreeMap::new(),
            cf_values: BTreeMap::new(),
            mac_address: [2, 0, 0, 0, 0, 1],
            iokit15_output: None,
        };
        let Some(value) = checkpoint.optional_metadata("darwin_services") else {
            return Ok(state);
        };
        let Value::Dict(fields) = value else {
            bail!("FairPlay darwin_services is not a dictionary");
        };
        for (name, destination) in [
            ("next_iterator", &mut state.next_iterator),
            ("next_service", &mut state.next_service),
            ("next_connection", &mut state.next_connection),
            ("next_bootstrap_port", &mut state.next_bootstrap_port),
            ("next_cf_object", &mut state.next_cf_object),
            ("next_xpc_connection", &mut state.next_xpc_connection),
        ] {
            *destination = pickle_u64(pickle_field(fields, name)?)?;
        }
        let Value::Bytes(mac) = pickle_field(fields, "mac_address")? else {
            bail!("FairPlay MAC address is not bytes");
        };
        state.mac_address = mac
            .as_slice()
            .try_into()
            .context("invalid FairPlay MAC length")?;
        let Value::Dict(iterators) = pickle_field(fields, "iterator_services")? else {
            bail!("FairPlay iterator services are not a dictionary");
        };
        if iterators.len() > MAX_DARWIN_OBJECTS {
            bail!("too many FairPlay iterator services");
        }
        for (key, service) in iterators {
            let iterator = pickle_hash_u64(key)?;
            state
                .iterator_services
                .insert(iterator, pickle_u64(service)?);
        }
        let Value::Dict(values) = pickle_field(fields, "cf_values")? else {
            bail!("FairPlay CF values are not a dictionary");
        };
        if values.len() > MAX_DARWIN_OBJECTS {
            bail!("too many FairPlay CF values");
        }
        let mut total_cf_bytes = 0usize;
        for (key, value) in values {
            let handle = pickle_hash_u64(key)?;
            let value = match value {
                Value::Bool(value) => CfValue::Boolean(*value),
                Value::Bytes(bytes) if bytes.len() <= MAX_CF_DATA_BYTES => {
                    CfValue::Data(Zeroizing::new(bytes.clone()))
                }
                Value::String(value) if value.len() <= MAX_CF_STRING_BYTES => {
                    CfValue::String(Zeroizing::new(value.as_bytes().to_vec()))
                }
                _ => bail!("invalid FairPlay CF value"),
            };
            total_cf_bytes = total_cf_bytes
                .checked_add(value.byte_len())
                .context("FairPlay CF value size overflow")?;
            if total_cf_bytes > MAX_CF_TOTAL_BYTES {
                bail!("FairPlay CF values exceed total size limit");
            }
            state.cf_values.insert(handle, value);
        }
        if let Some(value) = fields.get(&HashableValue::String("iokit15_output".into())) {
            let Value::Bytes(bytes) = value else {
                bail!("FairPlay IOKit output is not bytes");
            };
            validate_iokit15_output(bytes)?;
            state.iokit15_output = Some(Zeroizing::new(bytes.clone()));
        }
        Ok(state)
    }

    fn next_handle(value: &mut u64, increment: u64) -> Result<u64> {
        let handle = *value;
        *value = value
            .checked_add(increment)
            .context("FairPlay handle overflow")?;
        Ok(handle)
    }

    fn insert_cf_value(
        &mut self,
        context: &HookContext,
        allocations: &Rc<RefCell<AllocationState>>,
        value: CfValue,
    ) -> Result<u64> {
        if self.cf_values.len() >= MAX_DARWIN_OBJECTS {
            bail!("too many FairPlay CF values");
        }
        let total = self
            .cf_values
            .values()
            .try_fold(value.byte_len(), |sum, entry| {
                sum.checked_add(entry.byte_len())
                    .context("FairPlay CF value size overflow")
            })?;
        if total > MAX_CF_TOTAL_BYTES {
            bail!("FairPlay CF values exceed total size limit");
        }
        let handle = allocations.borrow_mut().allocate(context, 1)?;
        self.cf_values.insert(handle, value);
        Ok(handle)
    }

    fn snapshot(&self) -> Value {
        let mut fields = BTreeMap::new();
        let mut insert = |name: &str, value: Value| {
            fields.insert(HashableValue::String(name.into()), value);
        };
        for (name, value) in [
            ("next_iterator", self.next_iterator),
            ("next_service", self.next_service),
            ("next_connection", self.next_connection),
            ("next_bootstrap_port", self.next_bootstrap_port),
            ("next_cf_object", self.next_cf_object),
            ("next_xpc_connection", self.next_xpc_connection),
        ] {
            insert(name, Value::Int(value.into()));
        }
        insert("mac_address", Value::Bytes(self.mac_address.to_vec()));
        insert(
            "iterator_services",
            Value::Dict(
                self.iterator_services
                    .iter()
                    .map(|(&iterator, &service)| {
                        (
                            HashableValue::Int(iterator.into()),
                            Value::Int(service.into()),
                        )
                    })
                    .collect(),
            ),
        );
        insert(
            "cf_values",
            Value::Dict(
                self.cf_values
                    .iter()
                    .map(|(&handle, value)| {
                        let value = match value {
                            CfValue::Boolean(value) => Value::Bool(*value),
                            CfValue::Data(bytes) => Value::Bytes(bytes.to_vec()),
                            CfValue::String(bytes) => {
                                Value::String(String::from_utf8_lossy(bytes).into_owned())
                            }
                        };
                        (HashableValue::Int(handle.into()), value)
                    })
                    .collect(),
            ),
        );
        if let Some(output) = &self.iokit15_output {
            insert("iokit15_output", Value::Bytes(output.to_vec()));
        }
        Value::Dict(fields)
    }
}

fn pickle_hash_u64(value: &HashableValue) -> Result<u64> {
    match value {
        HashableValue::I64(value) => Ok(u64::try_from(*value)?),
        HashableValue::Int(value) => Ok(value.to_string().parse()?),
        _ => bail!("FairPlay state key is not numeric"),
    }
}

struct AllocationState {
    next: u64,
    stride: Option<u64>,
    mapped_pages: BTreeSet<u64>,
    new_pages: BTreeSet<u64>,
}

impl AllocationState {
    fn from_checkpoint(checkpoint: &FairplayCheckpoint) -> Result<Self> {
        let mapped_pages: BTreeSet<_> = checkpoint.page_addresses()?.into_iter().collect();
        let static_page = mapped_pages
            .range(STATIC_ALLOCATION_START..STATIC_ALLOCATION_END)
            .next_back()
            .copied();
        let (next, stride) = if let Some(next) = checkpoint.next_allocation()? {
            (next, None)
        } else if let Some(last) = static_page {
            (
                last.checked_add(STATIC_ALLOCATION_STRIDE)
                    .context("static allocation address overflow")?
                    & !(STATIC_ALLOCATION_STRIDE - 1),
                Some(STATIC_ALLOCATION_STRIDE),
            )
        } else {
            (SYNTHETIC_ALLOCATION_BASE, None)
        };
        Ok(Self {
            next,
            stride,
            mapped_pages,
            new_pages: BTreeSet::new(),
        })
    }

    fn allocate(&mut self, context: &HookContext, size: u64) -> Result<u64> {
        if size > MAX_EXTERNAL_BYTES {
            bail!("FairPlay allocation exceeds size limit");
        }
        let rounded = size
            .max(1)
            .checked_add(PAGE_BYTES - 1)
            .context("FairPlay allocation size overflow")?
            & !(PAGE_BYTES - 1);
        let allocation_size = self.stride.unwrap_or(rounded.max(PAGE_BYTES));
        let address = self.next;
        if !address.is_multiple_of(PAGE_BYTES) || address >= 0xf000_0000_0000_0000 {
            bail!("FairPlay allocation address is invalid");
        }
        let end = address
            .checked_add(allocation_size)
            .context("FairPlay allocation address overflow")?;
        if end >= 0xf000_0000_0000_0000 {
            bail!("FairPlay allocation exceeds guest address range");
        }
        for page in (address..end).step_by(PAGE_BYTES as usize) {
            if !self.mapped_pages.contains(&page) {
                context.mem_map(page, PAGE_BYTES as usize)?;
                self.mapped_pages.insert(page);
                self.new_pages.insert(page);
            }
        }
        self.next = end;
        Ok(address)
    }
}

struct SensitiveValue(Value);

impl Drop for SensitiveValue {
    fn drop(&mut self) {
        clear_value(&mut self.0);
    }
}

pub struct LoadedFairplayd {
    pub regions: Vec<MemoryRegion>,
    pub externals: HashMap<u64, String>,
    pub image_base: u64,
    pub fixups: usize,
    pub data_pages: Vec<u64>,
    pub compatibility_sites: Vec<(u64, u32)>,
    pub preserved_text_sites: Vec<(u64, u32)>,
}

/// Load the exact arm64e image with chained rebases and deterministic external
/// bind addresses. The caller owns the engine and can install import hooks.
pub fn load_fairplayd(engine: &mut Engine, binary: &[u8]) -> Result<LoadedFairplayd> {
    load_fairplayd_preserving(engine, binary, &[])
}

fn load_fairplayd_preserving(
    engine: &mut Engine,
    binary: &[u8],
    preserved_text: &[u64],
) -> Result<LoadedFairplayd> {
    let mut image = Image::open_preserving_instructions("fairplayd", binary, preserved_text)
        .context("parse fairplayd arm64e Mach-O")?;
    let image_base = image.base();
    let fixups = image.fixup_count();
    let compatibility_sites = image.compatibility_sites()?;
    let mut data_pages = Vec::new();
    for segment in image.segments() {
        if !segment.name.starts_with("__DATA") && !segment.name.starts_with("__AUTH") {
            continue;
        }
        let start = segment.address & !(PAGE_BYTES - 1);
        let end = segment
            .address
            .checked_add(segment.size)
            .and_then(|end| end.checked_add(PAGE_BYTES - 1))
            .context("fairplayd data segment address overflow")?
            & !(PAGE_BYTES - 1);
        let count = usize::try_from((end - start) / PAGE_BYTES)?;
        if data_pages.len().saturating_add(count) > MAX_SNAPSHOT_PAGES {
            bail!("fairplayd data pages exceed checkpoint budget");
        }
        data_pages.extend((start..end).step_by(PAGE_BYTES as usize));
    }
    let mut by_name = HashMap::<String, u64>::new();
    image
        .relocate(image_base, |name| {
            if let Some(&address) = by_name.get(name) {
                return Ok(address);
            }
            if by_name.len() >= MAX_EXTERNALS {
                bail!("fairplayd has too many external imports");
            }
            let offset = (by_name.len() as u64)
                .checked_mul(EXTERNAL_STRIDE)
                .context("fairplayd external address overflow")?;
            let address = EXTERNAL_BASE
                .checked_add(offset)
                .context("fairplayd external address overflow")?;
            by_name.insert(name.to_owned(), address);
            Ok(address)
        })
        .context("relocate fairplayd chained fixups")?;
    let regions = image.mapped_regions()?;
    image.load(engine).context("load fairplayd into Unicorn")?;
    let mut preserved_text_sites = Vec::with_capacity(preserved_text.len());
    for &address in preserved_text {
        let bytes = engine.mem_read(address, 4)?;
        preserved_text_sites.push((address, u32::from_le_bytes(bytes.as_slice().try_into()?)));
    }
    let externals = by_name
        .into_iter()
        .map(|(name, address)| (address, name))
        .collect();
    Ok(LoadedFairplayd {
        regions,
        externals,
        image_base,
        fixups,
        data_pages,
        compatibility_sites,
        preserved_text_sites,
    })
}

pub struct CheckpointRunner {
    pub engine: Engine,
    pub image: LoadedFairplayd,
    pub checkpoint_pages: usize,
    pub start_pc: u64,
    pub modeled_imports: usize,
    pub compatibility_instruction_sites: usize,
    pub preserved_text_instruction_sites: usize,
    external_failure: Rc<RefCell<Option<String>>>,
    allocation_state: Rc<RefCell<AllocationState>>,
    once_tokens: Rc<RefCell<BTreeSet<u64>>>,
    host_state: Rc<RefCell<HostState>>,
    virtual_files: Rc<RefCell<VirtualFileState>>,
    darwin: Rc<RefCell<DarwinState>>,
    errno_mapped: bool,
}

fn guest_register(context: &HookContext, index: i32) -> Result<u64> {
    context.reg_read(199 + index)
}

fn copy_guest_memory(
    context: &HookContext,
    destination: u64,
    source: u64,
    count: u64,
) -> Result<()> {
    let backward = destination > source && destination < source.saturating_add(count);
    let mut done = 0u64;
    while done < count {
        let chunk = (count - done).min(EXTERNAL_CHUNK_BYTES as u64);
        let offset = if backward { count - done - chunk } else { done };
        let read_address = source
            .checked_add(offset)
            .context("external memory source address overflow")?;
        let write_address = destination
            .checked_add(offset)
            .context("external memory destination address overflow")?;
        let bytes = Zeroizing::new(context.mem_read(read_address, chunk as usize)?);
        context.mem_write(write_address, &bytes)?;
        done += chunk;
    }
    Ok(())
}

fn fill_guest_memory(context: &HookContext, destination: u64, value: u8, count: u64) -> Result<()> {
    let bytes = vec![value; EXTERNAL_CHUNK_BYTES];
    let mut done = 0u64;
    while done < count {
        let chunk = (count - done).min(EXTERNAL_CHUNK_BYTES as u64) as usize;
        let address = destination
            .checked_add(done)
            .context("external memory destination address overflow")?;
        context.mem_write(address, &bytes[..chunk])?;
        done += chunk as u64;
    }
    Ok(())
}

fn guest_string_length(context: &HookContext, address: u64, limit: u64) -> Result<u64> {
    for offset in 0..limit {
        let cursor = address
            .checked_add(offset)
            .context("external string address overflow")?;
        if context.mem_read(cursor, 1)?[0] == 0 {
            return Ok(offset);
        }
    }
    Ok(limit)
}

fn guest_path(context: &HookContext, address: u64) -> Result<Vec<u8>> {
    let length = guest_string_length(context, address, 0x10000)?;
    if length == 0x10000 {
        bail!("unterminated FairPlay virtual file path");
    }
    context.mem_read(address, length as usize)
}

fn set_guest_errno(context: &HookContext, errno: u32) -> Result<()> {
    context.mem_write(SYNTHETIC_ERRNO_ADDRESS, &errno.to_le_bytes())
}

fn read_guest_u64(context: &HookContext, address: u64) -> Result<u64> {
    let bytes = context.mem_read(address, 8)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(value))
}

fn write_guest_stat(
    context: &HookContext,
    address: u64,
    size: usize,
    metadata: VirtualFileStat,
) -> Result<()> {
    let mut stat = [0u8; DARWIN_STAT_BYTES];
    stat[4..6].copy_from_slice(&(0o100000 | (metadata.mode & 0o7777)).to_le_bytes());
    stat[6..8].copy_from_slice(&1u16.to_le_bytes());
    stat[16..20].copy_from_slice(&metadata.uid.to_le_bytes());
    stat[20..24].copy_from_slice(&metadata.gid.to_le_bytes());
    stat[96..104].copy_from_slice(&(size as u64).to_le_bytes());
    context.mem_write(address, &stat)
}

fn run_virtual_file_external(
    context: &HookContext,
    symbol: &str,
    files: &Rc<RefCell<VirtualFileState>>,
) -> Result<()> {
    match symbol {
        "open" | "open_dprotected_np" | "stat" | "lstat" | "unlink" => {
            let path = guest_path(context, guest_register(context, 0)?)?;
            let mut files = files.borrow_mut();
            let Some(suffix) = files.match_file(&path).map(|(suffix, _)| suffix.clone()) else {
                if symbol == "unlink" || files.missing_are_enoent {
                    set_guest_errno(context, 2)?;
                    context.reg_write(199, 0xffff_ffff)?;
                    return Ok(());
                }
                bail!("unmodeled FairPlay virtual file for {symbol}");
            };
            match symbol {
                "open" | "open_dprotected_np" => {
                    if files.open.len() >= MAX_VIRTUAL_FILES {
                        bail!("too many FairPlay virtual files are open");
                    }
                    let open_bytes = files.open.values().try_fold(0usize, |sum, entry| {
                        sum.checked_add(entry.data.len())
                            .context("FairPlay virtual file memory overflow")
                    })?;
                    if open_bytes.saturating_add(files.payloads[&suffix].len())
                        > MAX_VIRTUAL_FILE_BYTES
                    {
                        bail!("FairPlay open-file data exceeds memory limit");
                    }
                    let data = files.payloads[&suffix].to_vec();
                    let descriptor = files.next_fd;
                    files.next_fd = files
                        .next_fd
                        .checked_add(1)
                        .context("FairPlay fd overflow")?;
                    files.open.insert(
                        descriptor,
                        OpenVirtualFile {
                            data: Zeroizing::new(data),
                            offset: 0,
                            path,
                            suffix,
                        },
                    );
                    context.reg_write(199, descriptor)?;
                }
                "stat" | "lstat" => {
                    let metadata = files.stats.get(&suffix).copied().unwrap_or_default();
                    write_guest_stat(
                        context,
                        guest_register(context, 1)?,
                        files.payloads[&suffix].len(),
                        metadata,
                    )?;
                    context.reg_write(199, 0)?;
                }
                "unlink" => {
                    files.removed.insert(suffix);
                    context.reg_write(199, 0)?;
                }
                _ => unreachable!(),
            }
        }
        "fstat" | "read" | "close" => {
            let descriptor = guest_register(context, 0)?;
            let mut files = files.borrow_mut();
            match symbol {
                "fstat" => {
                    if let Some(entry) = files.open.get(&descriptor) {
                        let metadata = files.stats.get(&entry.suffix).copied().unwrap_or_default();
                        write_guest_stat(
                            context,
                            guest_register(context, 1)?,
                            entry.data.len(),
                            metadata,
                        )?;
                        context.reg_write(199, 0)?;
                    } else {
                        set_guest_errno(context, 9)?;
                        context.reg_write(199, 0xffff_ffff)?;
                    }
                }
                "read" => {
                    if let Some(entry) = files.open.get_mut(&descriptor) {
                        let count =
                            usize::try_from(guest_register(context, 2)?.min(MAX_EXTERNAL_BYTES))?;
                        let start = entry.offset.min(entry.data.len());
                        let end = start.saturating_add(count).min(entry.data.len());
                        let data = &entry.data[start..end];
                        context.mem_write(guest_register(context, 1)?, data)?;
                        entry.offset = entry.offset.saturating_add(data.len());
                        context.reg_write(199, data.len() as u64)?;
                    } else {
                        set_guest_errno(context, 9)?;
                        context.reg_write(199, 0xffff_ffff)?;
                    }
                }
                "close" => {
                    files.open.remove(&descriptor);
                    context.reg_write(199, 0)?;
                }
                _ => unreachable!(),
            }
        }
        _ => bail!("unmodeled FairPlay virtual file function {symbol}"),
    }
    Ok(())
}

fn run_darwin_external(
    context: &HookContext,
    symbol: &str,
    allocations: &Rc<RefCell<AllocationState>>,
    darwin: &Rc<RefCell<DarwinState>>,
) -> Result<()> {
    let mut state = darwin.borrow_mut();
    match symbol {
        "IOMainPort" => {
            let destination = guest_register(context, 1)?;
            if destination != 0 {
                context.mem_write(destination, &1u32.to_le_bytes())?;
            }
            context.reg_write(199, 0)?;
        }
        "IOBSDNameMatching" | "IOServiceMatching" => {
            context.reg_write(199, 0x7102_0000_0000)?;
        }
        "IOServiceGetMatchingServices" => {
            if state.iterator_services.len() >= MAX_DARWIN_OBJECTS {
                bail!("too many FairPlay IO iterators");
            }
            let iterator = DarwinState::next_handle(&mut state.next_iterator, 1)?;
            let service = DarwinState::next_handle(&mut state.next_service, 1)?;
            context.mem_write(
                guest_register(context, 2)?,
                &u32::try_from(iterator)?.to_le_bytes(),
            )?;
            state.iterator_services.insert(iterator, service);
            context.reg_write(199, 0)?;
        }
        "IOIteratorNext" => {
            let iterator = guest_register(context, 0)? & 0xffff_ffff;
            context.reg_write(199, state.iterator_services.remove(&iterator).unwrap_or(0))?;
        }
        "IOServiceOpen" => {
            let connection = DarwinState::next_handle(&mut state.next_connection, 1)?;
            context.mem_write(
                guest_register(context, 3)?,
                &u32::try_from(connection)?.to_le_bytes(),
            )?;
            context.reg_write(199, 0)?;
        }
        "IORegistryEntryGetParentEntry" => {
            let parent = DarwinState::next_handle(&mut state.next_service, 1)?;
            context.mem_write(
                guest_register(context, 2)?,
                &u32::try_from(parent)?.to_le_bytes(),
            )?;
            context.reg_write(199, 0)?;
        }
        "IORegistryEntryCreateCFProperty" => {
            let key_object = guest_register(context, 1)?;
            let pointer = read_guest_u64(
                context,
                key_object
                    .checked_add(16)
                    .context("CFString address overflow")?,
            )?;
            let length = read_guest_u64(
                context,
                key_object
                    .checked_add(24)
                    .context("CFString address overflow")?,
            )?;
            if length > 0x1000 {
                bail!("FairPlay IORegistry property key exceeds limit");
            }
            let key = context.mem_read(pointer, length as usize)?;
            let value = match key.as_slice() {
                b"IOBuiltin" => CfValue::Boolean(true),
                b"IOMACAddress" => CfValue::Data(Zeroizing::new(state.mac_address.to_vec())),
                _ => bail!("unmodeled FairPlay IORegistry property"),
            };
            let handle = state.insert_cf_value(context, allocations, value)?;
            context.reg_write(199, handle)?;
        }
        "CFStringGetSystemEncoding" => context.reg_write(199, 0)?,
        "CFStringCreateWithCString" | "CFStringCreateWithCStringNoCopy" => {
            let input = guest_path(context, guest_register(context, 1)?)?;
            if input.len() > MAX_CF_STRING_BYTES {
                bail!("FairPlay CF string exceeds size limit");
            }
            let value = String::from_utf8_lossy(&input).into_owned().into_bytes();
            let handle = state.insert_cf_value(
                context,
                allocations,
                CfValue::String(Zeroizing::new(value)),
            )?;
            context.reg_write(199, handle)?;
        }
        "CFStringGetLength" => {
            let Some(CfValue::String(value)) = state.cf_values.get(&guest_register(context, 0)?)
            else {
                bail!("FairPlay CF value is not a string");
            };
            context.reg_write(199, value.len() as u64)?;
        }
        "CFStringGetCString" => {
            let value = state.cf_values.get(&guest_register(context, 0)?);
            let capacity = guest_register(context, 2)?;
            if let Some(CfValue::String(value)) = value {
                if capacity > value.len() as u64 {
                    context.mem_write(guest_register(context, 1)?, value)?;
                    let terminator = guest_register(context, 1)?
                        .checked_add(value.len() as u64)
                        .context("CF string destination overflow")?;
                    context.mem_write(terminator, &[0])?;
                    context.reg_write(199, 1)?;
                } else {
                    context.reg_write(199, 0)?;
                }
            } else {
                context.reg_write(199, 0)?;
            }
        }
        "CFStringGetMaximumSizeForEncoding" => {
            let length = guest_register(context, 0)?;
            context.reg_write(
                199,
                length.checked_mul(4).context("CF string size overflow")?,
            )?;
        }
        "CFGetTypeID" => {
            let id = match state.cf_values.get(&guest_register(context, 0)?) {
                Some(CfValue::String(_)) => CF_STRING_TYPE_ID,
                Some(CfValue::Boolean(_)) => CF_BOOLEAN_TYPE_ID,
                Some(CfValue::Data(_)) => CF_DATA_TYPE_ID,
                None => bail!("FairPlay CF type query used unknown object"),
            };
            context.reg_write(199, id)?;
        }
        "CFStringGetTypeID" => context.reg_write(199, CF_STRING_TYPE_ID)?,
        "CFBooleanGetTypeID" => context.reg_write(199, CF_BOOLEAN_TYPE_ID)?,
        "CFDataGetTypeID" => context.reg_write(199, CF_DATA_TYPE_ID)?,
        "CFBooleanGetValue" => {
            let handle = guest_register(context, 0)?;
            let Some(CfValue::Boolean(value)) = state.cf_values.get(&handle) else {
                bail!("FairPlay CF value is not a boolean");
            };
            context.reg_write(199, u64::from(*value))?;
        }
        "CFDataCreate" => {
            let source = guest_register(context, 1)?;
            let length = usize::try_from(guest_register(context, 2)?)?;
            if length > MAX_CF_DATA_BYTES {
                bail!("FairPlay CF data exceeds size limit");
            }
            let bytes = Zeroizing::new(context.mem_read(source, length)?);
            let handle = state.insert_cf_value(context, allocations, CfValue::Data(bytes))?;
            context.reg_write(199, handle)?;
        }
        "CFDataGetLength" => {
            let Some(CfValue::Data(data)) = state.cf_values.get(&guest_register(context, 0)?)
            else {
                bail!("FairPlay CF value is not data");
            };
            context.reg_write(199, data.len() as u64)?;
        }
        "CFDataGetBytePtr" => {
            let Some(CfValue::Data(data)) = state.cf_values.get(&guest_register(context, 0)?)
            else {
                bail!("FairPlay CF value is not data");
            };
            let address = allocations
                .borrow_mut()
                .allocate(context, data.len() as u64)?;
            context.mem_write(address, data)?;
            context.reg_write(199, address)?;
        }
        "CFDataGetBytes" => {
            let handle = guest_register(context, 0)?;
            let Some(CfValue::Data(data)) = state.cf_values.get(&handle) else {
                bail!("FairPlay CF value is not data");
            };
            let offset = usize::try_from(guest_register(context, 1)?)?;
            let length = usize::try_from(guest_register(context, 2)?)?;
            let start = offset.min(data.len());
            let end = start.saturating_add(length).min(data.len());
            context.mem_write(guest_register(context, 3)?, &data[start..end])?;
        }
        "CFRelease" => {
            state.cf_values.remove(&guest_register(context, 0)?);
        }
        "IOConnectCallStructMethod" => {
            let selector = guest_register(context, 1)? & 0xffff_ffff;
            let output = match selector {
                0x16 => 0x4b13_0000u32.to_le_bytes().to_vec(),
                0x17 => 0x1f8u32.to_le_bytes().to_vec(),
                0x15 => state
                    .iokit15_output
                    .as_ref()
                    .context("FairPlay IOKit selector 0x15 needs private output")?
                    .to_vec(),
                _ => bail!("unmodeled FairPlay IOKit selector {selector:#x}"),
            };
            let size_pointer = guest_register(context, 5)?;
            let capacity = if size_pointer == 0 {
                0
            } else {
                read_guest_u64(context, size_pointer)?
            };
            if output.len() as u64 > capacity {
                bail!("FairPlay IOKit output exceeds caller capacity");
            }
            context.mem_write(guest_register(context, 4)?, &output)?;
            context.mem_write(size_pointer, &(output.len() as u64).to_le_bytes())?;
            context.reg_write(199, 0)?;
        }
        "bootstrap_check_in" => {
            let port = DarwinState::next_handle(&mut state.next_bootstrap_port, 1)?;
            context.mem_write(
                guest_register(context, 2)?,
                &u32::try_from(port)?.to_le_bytes(),
            )?;
            context.reg_write(199, 0)?;
        }
        "CFMachPortCreateWithPort" => {
            let context_pointer = guest_register(context, 4)?;
            if context_pointer != 0 {
                context.mem_write(context_pointer, &[0])?;
            }
            let handle = DarwinState::next_handle(&mut state.next_cf_object, PAGE_BYTES)?;
            context.reg_write(199, handle)?;
        }
        "CFMachPortCreateRunLoopSource"
        | "CFFileDescriptorCreate"
        | "CFFileDescriptorCreateRunLoopSource" => {
            let handle = DarwinState::next_handle(&mut state.next_cf_object, PAGE_BYTES)?;
            context.reg_write(199, handle)?;
        }
        "CFRunLoopGetMain" => context.reg_write(199, 0x7000_7000_f000)?,
        "xpc_connection_create_mach_service" => {
            let handle = DarwinState::next_handle(&mut state.next_xpc_connection, PAGE_BYTES)?;
            context.reg_write(199, handle)?;
        }
        "IOObjectRelease" => context.reg_write(199, 0)?,
        "CFFileDescriptorEnableCallBacks"
        | "CFRunLoopAddSource"
        | "xpc_connection_activate"
        | "xpc_connection_cancel"
        | "xpc_connection_resume"
        | "xpc_connection_send_message"
        | "xpc_connection_set_event_handler"
        | "xpc_connection_set_target_queue" => {}
        _ => bail!("unmodeled Darwin external function {symbol}"),
    }
    Ok(())
}

fn run_modeled_external(
    context: &HookContext,
    symbol: &str,
    allocations: &Rc<RefCell<AllocationState>>,
    once_tokens: &Rc<RefCell<BTreeSet<u64>>>,
    host_state: &Rc<RefCell<HostState>>,
    virtual_files: &Rc<RefCell<VirtualFileState>>,
    darwin: &Rc<RefCell<DarwinState>>,
) -> Result<()> {
    match symbol {
        "IOMainPort"
        | "IOBSDNameMatching"
        | "IOServiceMatching"
        | "IOServiceGetMatchingServices"
        | "IOIteratorNext"
        | "IOServiceOpen"
        | "IORegistryEntryGetParentEntry"
        | "IORegistryEntryCreateCFProperty"
        | "CFStringGetSystemEncoding"
        | "CFStringCreateWithCString"
        | "CFStringCreateWithCStringNoCopy"
        | "CFStringGetLength"
        | "CFStringGetCString"
        | "CFStringGetMaximumSizeForEncoding"
        | "CFGetTypeID"
        | "CFStringGetTypeID"
        | "CFBooleanGetTypeID"
        | "CFDataGetTypeID"
        | "CFBooleanGetValue"
        | "CFDataCreate"
        | "CFDataGetLength"
        | "CFDataGetBytePtr"
        | "CFDataGetBytes"
        | "CFRelease"
        | "IOConnectCallStructMethod"
        | "bootstrap_check_in"
        | "CFMachPortCreateWithPort"
        | "CFMachPortCreateRunLoopSource"
        | "CFFileDescriptorCreate"
        | "CFFileDescriptorCreateRunLoopSource"
        | "CFRunLoopGetMain"
        | "xpc_connection_create_mach_service"
        | "IOObjectRelease"
        | "CFFileDescriptorEnableCallBacks"
        | "CFRunLoopAddSource"
        | "xpc_connection_activate"
        | "xpc_connection_cancel"
        | "xpc_connection_resume"
        | "xpc_connection_send_message"
        | "xpc_connection_set_event_handler"
        | "xpc_connection_set_target_queue" => {
            run_darwin_external(context, symbol, allocations, darwin)?;
        }
        "open" | "open_dprotected_np" | "stat" | "lstat" | "fstat" | "read" | "close"
        | "unlink" => run_virtual_file_external(context, symbol, virtual_files)?,
        "malloc" | "malloc_type_malloc" | "calloc" | "malloc_type_calloc" => {
            let size = if matches!(symbol, "calloc" | "malloc_type_calloc") {
                guest_register(context, 0)?
                    .checked_mul(guest_register(context, 1)?)
                    .context("FairPlay calloc size overflow")?
            } else {
                guest_register(context, 0)?
            };
            let address = allocations.borrow_mut().allocate(context, size)?;
            if matches!(symbol, "calloc" | "malloc_type_calloc") {
                fill_guest_memory(context, address, 0, size)?;
            }
            context.reg_write(199, address)?;
        }
        "memcpy" | "memmove" => {
            let destination = guest_register(context, 0)?;
            let source = guest_register(context, 1)?;
            let count = guest_register(context, 2)?.min(MAX_EXTERNAL_BYTES);
            copy_guest_memory(context, destination, source, count)?;
            context.reg_write(199, destination)?;
        }
        "memset" => {
            let destination = guest_register(context, 0)?;
            let value = guest_register(context, 1)? as u8;
            let count = guest_register(context, 2)?.min(MAX_EXTERNAL_BYTES);
            fill_guest_memory(context, destination, value, count)?;
            context.reg_write(199, destination)?;
        }
        "bzero" => {
            let destination = guest_register(context, 0)?;
            let count = guest_register(context, 1)?.min(MAX_EXTERNAL_BYTES);
            fill_guest_memory(context, destination, 0, count)?;
        }
        "strlen" | "strnlen" => {
            let address = guest_register(context, 0)?;
            let limit = if symbol == "strlen" {
                0x10000
            } else {
                guest_register(context, 1)?.min(0x100000)
            };
            let length = guest_string_length(context, address, limit)?;
            if symbol == "strlen" && length == limit {
                bail!("unterminated guest string at {address:#x}");
            }
            context.reg_write(199, length)?;
        }
        "free" => {}
        "pthread_once" => {
            let token = guest_register(context, 0)?;
            let mut tokens = once_tokens.borrow_mut();
            if tokens.contains(&token) {
                context.reg_write(200, SYNTHETIC_NOOP_CALLBACK)?;
            } else {
                if tokens.len() >= MAX_ONCE_TOKENS {
                    bail!("FairPlay once token count exceeds limit");
                }
                tokens.insert(token);
            }
        }
        "dispatch_once" => {
            let token = guest_register(context, 0)?;
            let block = guest_register(context, 1)?;
            let mut tokens = once_tokens.borrow_mut();
            if tokens.contains(&token) {
                context.reg_write(200, SYNTHETIC_NOOP_CALLBACK)?;
            } else {
                let invoke = read_guest_u64(
                    context,
                    block
                        .checked_add(0x10)
                        .context("dispatch block address overflow")?,
                )?;
                if invoke == 0 {
                    bail!("dispatch_once block has a null invoke");
                }
                if tokens.len() >= MAX_ONCE_TOKENS {
                    bail!("FairPlay once token count exceeds limit");
                }
                tokens.insert(token);
                context.reg_write(199, block)?;
                context.reg_write(200, invoke)?;
            }
        }
        "arc4random" => {
            let mut state = host_state.borrow_mut();
            state.random_state = state
                .random_state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223);
            context.reg_write(199, u64::from(state.random_state))?;
        }
        "CC_SHA1_Init" => {
            let address = guest_register(context, 0)?;
            let mut state = host_state.borrow_mut();
            if !state.sha1_contexts.contains_key(&address)
                && state.sha1_contexts.len() >= MAX_SHA1_CONTEXTS
            {
                bail!("too many FairPlay SHA-1 contexts");
            }
            state
                .sha1_contexts
                .insert(address, Zeroizing::new(Vec::new()));
            context.reg_write(199, 1)?;
        }
        "CC_SHA1_Update" => {
            let address = guest_register(context, 0)?;
            let source = guest_register(context, 1)?;
            let length = usize::try_from(guest_register(context, 2)?)?;
            if length > 0x1000000 {
                bail!("FairPlay SHA-1 update input exceeds call limit");
            }
            let mut state = host_state.borrow_mut();
            let total = state
                .sha1_contexts
                .values()
                .try_fold(0usize, |sum, bytes| {
                    sum.checked_add(bytes.len())
                        .context("SHA-1 context size overflow")
                })?;
            if total.saturating_add(length) > MAX_SHA1_INPUT_BYTES {
                bail!("FairPlay SHA-1 contexts exceed input limit");
            }
            let bytes = state
                .sha1_contexts
                .get_mut(&address)
                .context("FairPlay SHA-1 update used unknown context")?;
            let mut offset = 0usize;
            while offset < length {
                let count = (length - offset).min(EXTERNAL_CHUNK_BYTES);
                let read_address = source
                    .checked_add(offset as u64)
                    .context("SHA-1 source address overflow")?;
                bytes.extend_from_slice(&context.mem_read(read_address, count)?);
                offset += count;
            }
            context.reg_write(199, 1)?;
        }
        "CC_SHA1_Final" => {
            let destination = guest_register(context, 0)?;
            let address = guest_register(context, 1)?;
            let mut state = host_state.borrow_mut();
            let bytes = state
                .sha1_contexts
                .remove(&address)
                .context("FairPlay SHA-1 final used unknown context")?;
            context.mem_write(destination, &Sha1::digest(bytes.as_slice()))?;
            context.reg_write(199, 1)?;
        }
        "audit_token_to_au32" => {
            let destination = guest_register(context, 6)?;
            if destination != 0 {
                context.mem_write(destination, &0u32.to_le_bytes())?;
            }
            context.reg_write(199, 0)?;
        }
        "pthread_self" => context.reg_write(199, SYNTHETIC_THREAD)?,
        "pthread_get_qos_class_np" => {
            context.mem_write(guest_register(context, 1)?, &0x15u32.to_le_bytes())?;
            context.mem_write(guest_register(context, 2)?, &0u32.to_le_bytes())?;
            context.reg_write(199, 0)?;
        }
        "notify_register_check" | "notify_check" => {
            let destination = guest_register(context, 1)?;
            if destination != 0 {
                let value = u32::from(symbol == "notify_register_check");
                context.mem_write(destination, &value.to_le_bytes())?;
            }
            context.reg_write(199, 0)?;
        }
        "gettimeofday" => {
            let destination = guest_register(context, 0)?;
            if destination != 0 {
                let mut time = [0u8; 16];
                time[..8].copy_from_slice(&1_700_000_000u64.to_le_bytes());
                context.mem_write(destination, &time)?;
            }
            context.reg_write(199, 0)?;
        }
        "getpid" => context.reg_write(199, 1234)?,
        "proc_pidpath" => {
            const PROCESS_PATH: &[u8] = b"/usr/sbin/fairplayd.H2";
            let destination = guest_register(context, 1)?;
            let capacity = guest_register(context, 2)?;
            if capacity < (PROCESS_PATH.len() + 1) as u64 {
                context.reg_write(199, 0)?;
            } else {
                context.mem_write(destination, &[PROCESS_PATH, b"\0"].concat())?;
                context.reg_write(199, PROCESS_PATH.len() as u64)?;
            }
        }
        "getuid" | "geteuid" | "getgid" | "getegid" => context.reg_write(199, 0)?,
        "dlopen" => context.reg_write(199, SYNTHETIC_DLOPEN_HANDLE)?,
        "dlsym" => {
            let name = guest_path(context, guest_register(context, 1)?)?;
            if name.is_empty() || name.len() > 1024 {
                bail!("FairPlay dynamic symbol name is outside the bounded range");
            }
            let name = String::from_utf8(name).context("FairPlay dynamic symbol is not UTF-8")?;
            let mut state = host_state.borrow_mut();
            let index = state.dynamic_symbols.len();
            if index >= MAX_DYNAMIC_SYMBOLS {
                bail!("too many FairPlay dynamic symbols");
            }
            let address = SYNTHETIC_DLSYM_BASE + index as u64 * PAGE_BYTES;
            context.mem_map(address, PAGE_BYTES as usize)?;
            context.mem_write(address, &RET_X30)?;
            state.dynamic_symbols.insert(address, name);
            context.reg_write(199, address)?;
        }
        "dlclose" | "dlerror" => context.reg_write(199, 0)?,
        "sysctlbyname" => {
            let name = guest_path(context, guest_register(context, 0)?)?;
            let output = guest_register(context, 1)?;
            let size_pointer = guest_register(context, 2)?;
            let capacity = if size_pointer == 0 {
                0
            } else {
                read_guest_u64(context, size_pointer)?
            };
            if name == b"kern.hv_vmm_present" && output != 0 && capacity >= 4 {
                context.mem_write(output, &0u32.to_le_bytes())?;
                context.mem_write(size_pointer, &4u64.to_le_bytes())?;
                context.reg_write(199, 0)?;
            } else {
                set_guest_errno(context, 2)?;
                context.reg_write(199, 0xffff_ffff)?;
            }
        }
        "vm_allocate" => {
            let destination = guest_register(context, 1)?;
            let size = guest_register(context, 2)?.max(0x4000);
            let address = allocations.borrow_mut().allocate(context, size)?;
            if destination != 0 {
                context.mem_write(destination, &address.to_le_bytes())?;
            }
            context.reg_write(199, 0)?;
        }
        "kqueue" => context.reg_write(199, 0x900)?,
        "kevent"
        | "signal"
        | "sched_yield"
        | "umask"
        | "notify_cancel"
        | "notify_post"
        | "vm_deallocate"
        | "pthread_set_qos_class_self_np"
        | "pthread_mutex_destroy"
        | "pthread_mutex_init"
        | "pthread_mutex_lock"
        | "pthread_mutex_unlock"
        | "pthread_rwlock_destroy"
        | "pthread_rwlock_init"
        | "pthread_rwlock_rdlock"
        | "pthread_rwlock_unlock"
        | "pthread_rwlock_wrlock"
        | "CSBackupSetItemExcluded" => {
            context.reg_write(199, 0)?;
        }
        "chkstk_darwin" => {}
        "error" => context.reg_write(199, SYNTHETIC_ERRNO_ADDRESS)?,
        "mmap" => {
            let length = guest_register(context, 1)?;
            let flags = guest_register(context, 3)?;
            let descriptor = guest_register(context, 4)?;
            let files = virtual_files.borrow();
            if let Some(entry) = files.open.get(&descriptor) {
                let accessible = length
                    .checked_add(0x3fff)
                    .context("FairPlay mmap length overflow")?
                    & !0x3fff;
                let address = allocations.borrow_mut().allocate(context, accessible)?;
                let offset = usize::try_from(guest_register(context, 5)?)?;
                if offset < entry.data.len() {
                    let available = (entry.data.len() - offset).min(accessible as usize);
                    for (index, chunk) in entry.data[offset..offset + available]
                        .chunks(EXTERNAL_CHUNK_BYTES)
                        .enumerate()
                    {
                        context
                            .mem_write(address + (index * EXTERNAL_CHUNK_BYTES) as u64, chunk)?;
                    }
                }
                context.reg_write(199, address)?;
            } else if matches!(descriptor, 0xffff_ffff | u64::MAX) && flags & 0x1000 != 0 {
                let address = allocations.borrow_mut().allocate(context, length)?;
                context.reg_write(199, address)?;
            } else {
                context.mem_write(SYNTHETIC_ERRNO_ADDRESS, &9u32.to_le_bytes())?;
                context.reg_write(199, u64::MAX)?;
            }
        }
        "munmap" => context.reg_write(199, 0)?,
        _ => bail!("unmodeled external function {symbol}"),
    }
    Ok(())
}

fn install_modeled_external(
    engine: &mut Engine,
    address: u64,
    symbol: &str,
    failure: &Rc<RefCell<Option<String>>>,
    allocations: &Rc<RefCell<AllocationState>>,
    once_tokens: &Rc<RefCell<BTreeSet<u64>>>,
    services: ServiceRefs<'_>,
) -> Result<bool> {
    let symbol = symbol.trim_start_matches('_');
    if !matches!(
        symbol,
        "memcpy"
            | "memmove"
            | "memset"
            | "bzero"
            | "strlen"
            | "strnlen"
            | "malloc"
            | "malloc_type_malloc"
            | "calloc"
            | "malloc_type_calloc"
            | "free"
            | "pthread_once"
            | "dispatch_once"
            | "arc4random"
            | "CC_SHA1_Init"
            | "CC_SHA1_Update"
            | "CC_SHA1_Final"
            | "audit_token_to_au32"
            | "pthread_self"
            | "pthread_get_qos_class_np"
            | "notify_register_check"
            | "notify_check"
            | "gettimeofday"
            | "getpid"
            | "proc_pidpath"
            | "getuid"
            | "geteuid"
            | "getgid"
            | "getegid"
            | "dlopen"
            | "dlsym"
            | "dlclose"
            | "dlerror"
            | "sysctlbyname"
            | "vm_allocate"
            | "kqueue"
            | "kevent"
            | "signal"
            | "sched_yield"
            | "umask"
            | "notify_cancel"
            | "notify_post"
            | "vm_deallocate"
            | "pthread_set_qos_class_self_np"
            | "pthread_mutex_destroy"
            | "pthread_mutex_init"
            | "pthread_mutex_lock"
            | "pthread_mutex_unlock"
            | "pthread_rwlock_destroy"
            | "pthread_rwlock_init"
            | "pthread_rwlock_rdlock"
            | "pthread_rwlock_unlock"
            | "pthread_rwlock_wrlock"
            | "CSBackupSetItemExcluded"
            | "chkstk_darwin"
            | "error"
            | "mmap"
            | "munmap"
            | "open"
            | "open_dprotected_np"
            | "stat"
            | "lstat"
            | "fstat"
            | "read"
            | "close"
            | "unlink"
            | "IOMainPort"
            | "IOBSDNameMatching"
            | "IOServiceMatching"
            | "IOServiceGetMatchingServices"
            | "IOIteratorNext"
            | "IOServiceOpen"
            | "IORegistryEntryGetParentEntry"
            | "IORegistryEntryCreateCFProperty"
            | "CFStringGetSystemEncoding"
            | "CFStringCreateWithCString"
            | "CFStringCreateWithCStringNoCopy"
            | "CFStringGetLength"
            | "CFStringGetCString"
            | "CFStringGetMaximumSizeForEncoding"
            | "CFGetTypeID"
            | "CFStringGetTypeID"
            | "CFBooleanGetTypeID"
            | "CFDataGetTypeID"
            | "CFBooleanGetValue"
            | "CFDataCreate"
            | "CFDataGetLength"
            | "CFDataGetBytePtr"
            | "CFDataGetBytes"
            | "CFRelease"
            | "IOConnectCallStructMethod"
            | "bootstrap_check_in"
            | "CFMachPortCreateWithPort"
            | "CFMachPortCreateRunLoopSource"
            | "CFFileDescriptorCreate"
            | "CFFileDescriptorCreateRunLoopSource"
            | "CFRunLoopGetMain"
            | "xpc_connection_create_mach_service"
            | "IOObjectRelease"
            | "CFFileDescriptorEnableCallBacks"
            | "CFRunLoopAddSource"
            | "xpc_connection_activate"
            | "xpc_connection_cancel"
            | "xpc_connection_resume"
            | "xpc_connection_send_message"
            | "xpc_connection_set_event_handler"
            | "xpc_connection_set_target_queue"
    ) {
        return Ok(false);
    }
    engine
        .mem_map(address, PAGE_BYTES as usize)
        .with_context(|| format!("map external {symbol} stub"))?;
    if matches!(symbol, "pthread_once" | "dispatch_once") {
        let instructions = PTHREAD_ONCE_STUB
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        engine.mem_write(address, &instructions)?;
    } else {
        engine.mem_write(address, &RET_X30)?;
    }
    let symbol_name = symbol.to_owned();
    let failure = Rc::clone(failure);
    let allocations = Rc::clone(allocations);
    let once_tokens = Rc::clone(once_tokens);
    let host_state = Rc::clone(services.0);
    let virtual_files = Rc::clone(services.1);
    let darwin = Rc::clone(services.2);
    engine.add_code_hook(address, address, move |context, _, _| {
        if let Err(error) = run_modeled_external(
            context,
            &symbol_name,
            &allocations,
            &once_tokens,
            &host_state,
            &virtual_files,
            &darwin,
        ) {
            *failure.borrow_mut() = Some(format!("FairPlay external {symbol_name}: {error:#}"));
            let _ = context.stop();
        }
    })?;
    Ok(true)
}

fn install_dynamic_symbol_hook(
    engine: &mut Engine,
    host_state: &Rc<RefCell<HostState>>,
    failure: &Rc<RefCell<Option<String>>>,
    source_pages: &[u64],
) -> Result<()> {
    let symbols = Rc::clone(host_state);
    let failure = Rc::clone(failure);
    engine.add_code_hook(
        SYNTHETIC_DLSYM_BASE,
        SYNTHETIC_DLSYM_BASE + MAX_DYNAMIC_SYMBOLS as u64 * PAGE_BYTES - 1,
        move |context, address, _| {
            let execution = (|| -> Result<()> {
                if !symbols.borrow().dynamic_symbols.contains_key(&address) {
                    bail!("unknown FairPlay dynamic symbol at {address:#x}");
                }
                let operation = guest_register(context, 0)? & 0xffff_ffff;
                if operation == 10 {
                    let destination = guest_register(context, 2)?
                        .checked_add(8)
                        .context("CoreKE output address overflow")?;
                    context.mem_write(destination, &[0, 0, 0, 0, 0, 0, 0, 1])?;
                }
                context.reg_write(199, 0xffff_58fe)?;
                Ok(())
            })();
            if let Err(error) = execution {
                *failure.borrow_mut() = Some(format!("FairPlay CoreKE: {error:#}"));
                let _ = context.stop();
            }
        },
    )?;
    for &address in host_state.borrow().dynamic_symbols.keys() {
        if !source_pages.contains(&address) {
            engine.mem_map(address, PAGE_BYTES as usize)?;
        }
        engine.mem_write(address, &RET_X30)?;
    }
    Ok(())
}

impl CheckpointRunner {
    pub fn new(checkpoint: &FairplayCheckpoint, binary: &[u8]) -> Result<Self> {
        Self::new_preserving_text(checkpoint, binary, &[])
    }

    pub fn new_preserving_text(
        checkpoint: &FairplayCheckpoint,
        binary: &[u8],
        preserved_text: &[u64],
    ) -> Result<Self> {
        if preserved_text.len() > 256 {
            bail!("too many preserved FairPlay text instructions");
        }
        if preserved_text
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != preserved_text.len()
        {
            bail!("duplicate preserved FairPlay text instruction");
        }
        let actual_hash: [u8; 32] = Sha256::digest(binary).into();
        if actual_hash != checkpoint.binary_hash {
            bail!("fairplayd SHA-256 does not match checkpoint");
        }
        let mut engine = Engine::new().context("create FairPlay ARM64 emulator")?;
        let image = load_fairplayd_preserving(&mut engine, binary, preserved_text)?;
        let checkpoint_pages = checkpoint
            .restore_into(&mut engine, &image.regions)
            .context("restore FairPlay checkpoint")?;
        let preserved_text_instruction_sites = image.preserved_text_sites.len();
        let external_failure = Rc::new(RefCell::new(None));
        for &(address, opcode) in &image.preserved_text_sites {
            engine.mem_write(address, &opcode.to_le_bytes())?;
            let prepared = without_pointer_authentication(opcode);
            if prepared == opcode {
                continue;
            }
            let failure = Rc::clone(&external_failure);
            engine.add_code_hook(address, address, move |context, pc, _| {
                if let Err(error) = emulate_preserved_pointer_auth(context, pc, prepared) {
                    *failure.borrow_mut() =
                        Some(format!("FairPlay preserved text instruction: {error:#}"));
                    let _ = context.stop();
                }
            })?;
        }
        let start_pc = checkpoint.pc()?;
        if !image.regions.iter().any(|region| {
            region.address <= start_pc
                && region
                    .address
                    .checked_add(region.size)
                    .is_some_and(|end| start_pc < end)
        }) {
            bail!("checkpoint PC is outside the fairplayd image");
        }
        let allocation_state = Rc::new(RefCell::new(AllocationState::from_checkpoint(checkpoint)?));
        {
            let failure = Rc::clone(&external_failure);
            let hook_allocations = Rc::clone(&allocation_state);
            engine.add_memory_fault_hook(move |context, address, _size| {
                if !(LAZY_DATA_START..LAZY_DATA_END).contains(&address)
                    || context.reg_read(REG_PC).ok() == Some(address)
                {
                    return false;
                }
                let page = address & !(PAGE_BYTES - 1);
                let mapped = (|| -> Result<()> {
                    let mut state = hook_allocations.borrow_mut();
                    if state.mapped_pages.len() >= MAX_SNAPSHOT_PAGES {
                        bail!("FairPlay lazy data page limit exceeded");
                    }
                    context.mem_map(page, PAGE_BYTES as usize)?;
                    state.mapped_pages.insert(page);
                    state.new_pages.insert(page);
                    Ok(())
                })();
                if let Err(error) = mapped {
                    *failure.borrow_mut() = Some(format!("FairPlay lazy data page: {error:#}"));
                    return false;
                }
                true
            })?;
        }
        let compatibility_instruction_sites = image.compatibility_sites.len();
        for &(address, opcode) in &image.compatibility_sites {
            let failure = Rc::clone(&external_failure);
            engine.add_code_hook(address, address, move |context, pc, _| {
                let execution = (|| -> Result<()> {
                    let bytes = context.mem_read(pc, 4)?;
                    let actual = u32::from_le_bytes(bytes.as_slice().try_into()?);
                    if actual != opcode && actual != 0xd503_201f {
                        bail!("FairPlay compatibility opcode changed at {pc:#x}");
                    }
                    if !emulate_hook_instruction(context, pc, opcode)? {
                        bail!("FairPlay compatibility opcode is unsupported at {pc:#x}");
                    }
                    Ok(())
                })();
                if let Err(error) = execution {
                    *failure.borrow_mut() = Some(format!("FairPlay ARM64 instruction: {error:#}"));
                    let _ = context.stop();
                }
            })?;
        }
        let once_tokens = Rc::new(RefCell::new(
            checkpoint.once_tokens()?.into_iter().collect(),
        ));
        let host_state = Rc::new(RefCell::new(HostState::from_checkpoint(checkpoint)?));
        let virtual_files = Rc::new(RefCell::new(VirtualFileState::from_checkpoint(checkpoint)?));
        let darwin = Rc::new(RefCell::new(DarwinState::from_checkpoint(checkpoint)?));
        let source_pages = checkpoint.page_addresses()?;
        if image
            .externals
            .values()
            .any(|symbol| symbol.trim_start_matches('_') == "dlsym")
            || !host_state.borrow().dynamic_symbols.is_empty()
        {
            install_dynamic_symbol_hook(
                &mut engine,
                &host_state,
                &external_failure,
                &source_pages,
            )?;
        }
        let errno_mapped = image.externals.values().any(|symbol| {
            matches!(
                symbol.trim_start_matches('_'),
                "error"
                    | "mmap"
                    | "open"
                    | "open_dprotected_np"
                    | "stat"
                    | "lstat"
                    | "fstat"
                    | "read"
                    | "unlink"
                    | "sysctlbyname"
            )
        });
        if errno_mapped && !source_pages.contains(&SYNTHETIC_ERRNO_ADDRESS) {
            engine.mem_map(SYNTHETIC_ERRNO_ADDRESS, PAGE_BYTES as usize)?;
        }
        if image.externals.values().any(|symbol| {
            matches!(
                symbol.trim_start_matches('_'),
                "pthread_once" | "dispatch_once"
            )
        }) {
            if !source_pages.contains(&SYNTHETIC_NOOP_CALLBACK) {
                engine.mem_map(SYNTHETIC_NOOP_CALLBACK, PAGE_BYTES as usize)?;
            }
            engine.mem_write(SYNTHETIC_NOOP_CALLBACK, &RET_X30)?;
        }
        let mut modeled_imports = 0;
        for (&address, symbol) in &image.externals {
            if install_modeled_external(
                &mut engine,
                address,
                symbol,
                &external_failure,
                &allocation_state,
                &once_tokens,
                (&host_state, &virtual_files, &darwin),
            )? {
                modeled_imports += 1;
            }
        }
        Ok(Self {
            engine,
            image,
            checkpoint_pages,
            start_pc,
            modeled_imports,
            compatibility_instruction_sites,
            preserved_text_instruction_sites,
            external_failure,
            allocation_state,
            once_tokens,
            host_state,
            virtual_files,
            darwin,
            errno_mapped,
        })
    }

    pub(crate) fn replay_allocation_cursor(&self) -> u64 {
        self.allocation_state.borrow().next
    }

    pub(crate) fn replay_new_pages(&self) -> BTreeSet<u64> {
        self.allocation_state.borrow().new_pages.clone()
    }

    pub(crate) fn reset_replay_allocations(&mut self, original_next: u64) -> Result<()> {
        let pages = self.replay_new_pages();
        for &page in &pages {
            self.engine.mem_unmap(page, PAGE_BYTES as usize)?;
        }
        let mut state = self.allocation_state.borrow_mut();
        for page in pages {
            state.mapped_pages.remove(&page);
        }
        state.new_pages.clear();
        state.next = original_next;
        self.external_failure.borrow_mut().take();
        Ok(())
    }

    pub fn add_file_payload(&mut self, suffix: &str, data: Zeroizing<Vec<u8>>) -> Result<()> {
        if suffix.is_empty() || suffix.len() > 4096 || data.len() > MAX_VIRTUAL_FILE_BYTES {
            bail!("FairPlay virtual file suffix or payload exceeds limit");
        }
        let mut files = self.virtual_files.borrow_mut();
        if files.payloads.len() >= MAX_VIRTUAL_FILES
            && !files.payloads.contains_key(suffix.as_bytes())
        {
            bail!("too many FairPlay virtual file payloads");
        }
        let total = files
            .payloads
            .iter()
            .try_fold(0usize, |sum, (key, payload)| {
                if key.as_slice() == suffix.as_bytes() {
                    Ok(sum)
                } else {
                    sum.checked_add(payload.len())
                        .context("FairPlay virtual file memory overflow")
                }
            })?;
        if total.saturating_add(data.len()) > MAX_VIRTUAL_FILE_BYTES {
            bail!("FairPlay virtual file payloads exceed memory limit");
        }
        files.payloads.insert(suffix.as_bytes().to_vec(), data);
        Ok(())
    }

    pub fn add_file_stat(&mut self, suffix: &str, metadata: VirtualFileStat) -> Result<()> {
        if suffix.is_empty() || suffix.len() > 4096 {
            bail!("FairPlay virtual file suffix exceeds limit");
        }
        self.virtual_files
            .borrow_mut()
            .stats
            .insert(suffix.as_bytes().to_vec(), metadata);
        Ok(())
    }

    pub fn set_missing_files_are_enoent(&mut self, enabled: bool) {
        self.virtual_files.borrow_mut().missing_are_enoent = enabled;
    }

    pub fn set_mac_address(&mut self, address: [u8; 6]) {
        self.darwin.borrow_mut().mac_address = address;
    }

    pub fn set_iokit15_output(&mut self, output: Zeroizing<Vec<u8>>) -> Result<()> {
        validate_iokit15_output(&output)?;
        self.darwin.borrow_mut().iokit15_output = Some(output);
        Ok(())
    }

    pub fn run_until(
        &mut self,
        stop_pc: u64,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<()> {
        self.run_until_hit(stop_pc, 1, timeout, instruction_limit)
    }

    pub fn run_until_hit(
        &mut self,
        stop_pc: u64,
        stop_hit: usize,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<()> {
        if instruction_limit == 0 || instruction_limit > 500_000_000 {
            bail!("FairPlay instruction limit is outside the bounded range");
        }
        if stop_hit == 0 || stop_hit > 1_000_000 {
            bail!("FairPlay stop hit count is outside the bounded range");
        }
        let start = self.engine.reg_read(REG_PC)?;
        if stop_hit == 1 && start == stop_pc {
            return Ok(());
        }
        let mut hits = None;
        let execution = if stop_hit == 1 {
            self.engine
                .start_bounded(start, stop_pc, timeout, instruction_limit)
        } else {
            let observed = Rc::new(Cell::new(0usize));
            let hook_observed = Rc::clone(&observed);
            let hook = self
                .engine
                .add_code_hook(stop_pc, stop_pc, move |context, _, _| {
                    let next = hook_observed.get() + 1;
                    hook_observed.set(next);
                    if next == stop_hit {
                        let _ = context.stop();
                    }
                })?;
            let result = self
                .engine
                .start_bounded(start, 0, timeout, instruction_limit);
            self.engine.remove_hook(hook)?;
            hits = Some(observed.get());
            result
        };
        if let Some(failure) = self.external_failure.borrow().as_deref() {
            bail!("{failure}");
        }
        if let Err(error) = execution {
            let actual = self.engine.reg_read(REG_PC).unwrap_or(start);
            if let Some(name) = self.image.externals.get(&actual) {
                bail!("FairPlay reached unmodeled external {name} at {actual:#x}: {error:#}");
            }
            return Err(error).with_context(|| format!("resume FairPlay checkpoint at {start:#x}"));
        }
        let actual = self.engine.reg_read(REG_PC)?;
        if actual != stop_pc || hits.is_some_and(|count| count != stop_hit) {
            if let Some(name) = self.image.externals.get(&actual) {
                bail!("FairPlay reached unmodeled external {name} at {actual:#x}");
            }
            bail!("FairPlay stopped at {actual:#x} before target {stop_pc:#x}");
        }
        Ok(())
    }

    pub fn run_until_memory_read_range(
        &mut self,
        range_start: u64,
        range_size: u64,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<MemoryReadStop> {
        if instruction_limit == 0 || instruction_limit > 500_000_000 {
            bail!("FairPlay instruction limit is outside the bounded range");
        }
        if range_size == 0 || range_size > 0x1000_0000 {
            bail!("FairPlay memory-read range size is outside the bounded range");
        }
        let range_end = range_start
            .checked_add(range_size)
            .context("FairPlay memory-read range overflows address space")?;
        let observed = Rc::new(RefCell::new(None));
        let failure = Rc::new(RefCell::new(None));
        let hook_observed = Rc::clone(&observed);
        let hook_failure = Rc::clone(&failure);
        let hook = self
            .engine
            .add_memory_read_hook(move |context, address, size| {
                if address >= range_end || address.saturating_add(u64::from(size)) <= range_start {
                    return;
                }
                match context.reg_read(REG_PC) {
                    Ok(pc) => {
                        *hook_observed.borrow_mut() = Some(MemoryReadStop { pc, address, size });
                    }
                    Err(error) => {
                        *hook_failure.borrow_mut() =
                            Some(format!("read FairPlay memory stop PC: {error:#}"));
                    }
                }
                if let Err(error) = context.stop() {
                    *hook_failure.borrow_mut() =
                        Some(format!("stop FairPlay memory read: {error:#}"));
                }
            })?;
        let start = self.engine.reg_read(REG_PC)?;
        let execution = self
            .engine
            .start_bounded(start, 0, timeout, instruction_limit);
        self.engine.remove_hook(hook)?;
        if let Some(message) = failure.borrow().as_deref() {
            bail!("{message}");
        }
        if let Some(message) = self.external_failure.borrow().as_deref() {
            bail!("{message}");
        }
        execution.with_context(|| format!("resume FairPlay checkpoint at {start:#x}"))?;
        let stop = observed
            .borrow()
            .as_ref()
            .copied()
            .context("FairPlay instruction limit reached before memory-read range")?;
        let actual = self.engine.reg_read(REG_PC)?;
        if actual != stop.pc {
            bail!(
                "FairPlay memory read stopped at {actual:#x}, expected {:#x}",
                stop.pc
            );
        }
        Ok(stop)
    }

    pub fn run_until_hit_with_memory_trace(
        &mut self,
        stop_pc: u64,
        stop_hit: usize,
        timeout: Duration,
        instruction_limit: usize,
        options: MemoryTraceOptions,
    ) -> Result<MemoryTrace> {
        if !options.reads && !options.writes {
            bail!("FairPlay memory trace needs read or write events");
        }
        if options.max_events == 0 || options.max_events > 2_000_000 {
            bail!("FairPlay memory trace event limit is outside the bounded range");
        }
        let trace = Rc::new(RefCell::new(MemoryTrace::default()));
        let failure = Rc::new(RefCell::new(None));
        let mut hooks = Vec::with_capacity(2);
        if options.reads {
            let trace = Rc::clone(&trace);
            let failure = Rc::clone(&failure);
            let max_events = options.max_events;
            hooks.push(
                self.engine
                    .add_memory_read_hook(move |context, address, size| {
                        record_memory_event(
                            context, address, size, true, &trace, max_events, &failure,
                        );
                    })?,
            );
        }
        if options.writes {
            let trace = Rc::clone(&trace);
            let failure = Rc::clone(&failure);
            let max_events = options.max_events;
            let added = self
                .engine
                .add_memory_write_hook(move |context, address, size| {
                    record_memory_event(
                        context, address, size, false, &trace, max_events, &failure,
                    );
                });
            match added {
                Ok(hook) => hooks.push(hook),
                Err(error) => {
                    for hook in hooks {
                        self.engine.remove_hook(hook)?;
                    }
                    return Err(error);
                }
            }
        }
        let execution = self.run_until_hit(stop_pc, stop_hit, timeout, instruction_limit);
        for hook in hooks {
            self.engine.remove_hook(hook)?;
        }
        if let Some(message) = failure.borrow().as_deref() {
            bail!("{message}");
        }
        execution?;
        Ok(Rc::try_unwrap(trace)
            .map_err(|_| anyhow::anyhow!("FairPlay trace hook retained state"))?
            .into_inner())
    }

    /// Save a private schema-2 checkpoint that Python and Rust can both resume.
    pub fn write_checkpoint(
        &self,
        source: &FairplayCheckpoint,
        binary_path: &Path,
        output: &Path,
    ) -> Result<usize> {
        let mut addresses: BTreeSet<u64> = source.page_addresses()?.into_iter().collect();
        addresses.extend(self.image.data_pages.iter().copied());
        addresses.extend(self.allocation_state.borrow().new_pages.iter().copied());
        if self.errno_mapped {
            addresses.insert(SYNTHETIC_ERRNO_ADDRESS);
        }
        if addresses.is_empty() || addresses.len() > MAX_SNAPSHOT_PAGES {
            bail!("FairPlay output checkpoint page count is outside the bounded range");
        }
        let mut pages = SensitiveValue(Value::Dict(BTreeMap::new()));
        let Value::Dict(ref mut page_map) = pages.0 else {
            unreachable!();
        };
        for &address in &addresses {
            crate::application::operation::check()?;
            let bytes = self
                .engine
                .mem_read(address, PAGE_BYTES as usize)
                .with_context(|| format!("snapshot FairPlay page {address:#x}"))?;
            page_map.insert(
                HashableValue::I64(i64::try_from(address)?),
                Value::Bytes(bytes),
            );
        }
        let mut registers = BTreeMap::new();
        for index in 0..31 {
            let register = match index {
                29 => 1,
                30 => 2,
                _ => 199 + index,
            };
            registers.insert(
                HashableValue::String(format!("x{index}")),
                Value::Int(self.engine.reg_read(register)?.into()),
            );
        }
        registers.insert(
            HashableValue::String("sp".into()),
            Value::Int(self.engine.reg_read(4)?.into()),
        );
        for index in 0..32 {
            let bytes = self.engine.reg_read_128(228 + index)?;
            registers.insert(
                HashableValue::String(format!("v{index}")),
                Value::Int(u128::from_le_bytes(bytes).into()),
            );
        }
        let flags = self.engine.reg_read(3)?;
        let nzcv = ["n", "z", "c", "v"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    HashableValue::String(name.into()),
                    Value::I64(((flags >> (31 - index)) & 1) as i64),
                )
            })
            .collect();
        let binary = std::fs::canonicalize(binary_path).context("resolve fairplayd path")?;
        let binary = binary
            .to_str()
            .context("fairplayd path is not UTF-8")?
            .to_owned();
        let pc = self.engine.reg_read(REG_PC)?;
        let (open_files, next_fd, removed_file_suffixes) = self.virtual_files.borrow().snapshot();
        let mut darwin_services = SensitiveValue(self.darwin.borrow().snapshot());
        let mut root = SensitiveValue(source.clone_root()?);
        let Value::Dict(ref mut fields) = root.0 else {
            bail!("checkpoint root is not a dictionary");
        };
        let updates = [
            ("schema", Value::I64(2)),
            ("binary", Value::String(binary)),
            ("pc", Value::String(format!("{pc:#x}"))),
            ("registers", Value::Dict(registers)),
            ("nzcv", Value::Dict(nzcv)),
            ("memory_pages", std::mem::replace(&mut pages.0, Value::None)),
            (
                "next_allocation",
                Value::Int(self.allocation_state.borrow().next.into()),
            ),
            (
                "once_tokens",
                Value::List(
                    self.once_tokens
                        .borrow()
                        .iter()
                        .map(|&token| Value::Int(token.into()))
                        .collect(),
                ),
            ),
            (
                "random_state",
                Value::I64(i64::from(self.host_state.borrow().random_state)),
            ),
            (
                "dynamic_symbols",
                self.host_state.borrow().dynamic_symbols_snapshot(),
            ),
            (
                "sha1_contexts",
                self.host_state.borrow().sha1_contexts_snapshot(),
            ),
            ("open_files", open_files),
            ("next_fd", next_fd),
            ("removed_file_suffixes", removed_file_suffixes),
            (
                "darwin_services",
                std::mem::replace(&mut darwin_services.0, Value::None),
            ),
        ];
        for (name, value) in updates {
            if let Some(mut old) = fields.insert(HashableValue::String(name.into()), value) {
                clear_value(&mut old);
            }
        }
        let serialized = serde_pickle::value_to_vec(&root.0, SerOptions::new())
            .context("serialize FairPlay checkpoint");
        let serialized = Zeroizing::new(serialized?);
        if serialized.len() > 128 * 1024 * 1024 {
            bail!("FairPlay output checkpoint exceeds decompressed size limit");
        }
        crate::application::operation::check()?;
        let mut compressed = Zeroizing::new(Vec::new());
        let mut encoder = GzEncoder::new(&mut *compressed, Compression::fast());
        crate::application::operation::copy(&mut serialized.as_slice(), &mut encoder)?;
        encoder.finish()?;
        write_private_binary(output, &compressed)?;
        Ok(addresses.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SYNTHETIC_BINARY: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-run-synthetic.macho");
    const SYNTHETIC_CHECKPOINT: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-run-synthetic.pkl.gz");
    const SYNTHETIC_SCHEMA1_CHECKPOINT: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-run-schema1-synthetic.pkl.gz");

    #[test]
    fn iokit15_fixture_requires_exact_success_structure() {
        let mut output = vec![0; IOKIT15_STRUCTURE_BYTES];
        assert!(validate_iokit15_output(&output).is_ok());
        output[0x220..0x224].copy_from_slice(&0x201u32.to_le_bytes());
        assert!(validate_iokit15_output(&output).is_err());
        output[0x220..0x224].copy_from_slice(&0x200u32.to_le_bytes());
        output[0x224..0x228].copy_from_slice(&1u32.to_le_bytes());
        assert!(validate_iokit15_output(&output).is_err());
        output[0x224..0x228].fill(0);
        assert!(validate_iokit15_output(&output[..0x227]).is_err());
    }

    #[test]
    fn modeled_memory_externals_execute_in_guest_and_return_to_lr() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, PAGE_BYTES as usize).unwrap();
        engine.mem_map(0x2000, PAGE_BYTES as usize).unwrap();
        engine.mem_write(0x1000, b"abcdef\0").unwrap();
        let failure = Rc::new(RefCell::new(None));
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let allocations = Rc::new(RefCell::new(
            AllocationState::from_checkpoint(&source).unwrap(),
        ));
        let once_tokens = Rc::new(RefCell::new(BTreeSet::new()));
        let host_state = Rc::new(RefCell::new(HostState::from_checkpoint(&source).unwrap()));
        let virtual_files = Rc::new(RefCell::new(
            VirtualFileState::from_checkpoint(&source).unwrap(),
        ));
        let darwin = Rc::new(RefCell::new(DarwinState::from_checkpoint(&source).unwrap()));
        let call = |engine: &mut Engine, index: u64, symbol: &str, args: [u64; 3]| {
            let address = EXTERNAL_BASE + index * EXTERNAL_STRIDE;
            assert!(
                install_modeled_external(
                    engine,
                    address,
                    symbol,
                    &failure,
                    &allocations,
                    &once_tokens,
                    (&host_state, &virtual_files, &darwin),
                )
                .unwrap()
            );
            for (index, value) in args.into_iter().enumerate() {
                engine.reg_write(199 + index as i32, value).unwrap();
            }
            engine.reg_write(2, 0x5000).unwrap();
            engine
                .start_bounded(address, 0x5000, Duration::from_secs(2), 4)
                .unwrap();
            assert!(failure.borrow().is_none());
        };
        call(&mut engine, 0, "_memcpy", [0x2000, 0x1000, 6]);
        assert_eq!(engine.mem_read(0x2000, 6).unwrap(), b"abcdef");
        assert_eq!(engine.reg_read(199).unwrap(), 0x2000);
        call(&mut engine, 1, "_memmove", [0x1002, 0x1000, 6]);
        assert_eq!(engine.mem_read(0x1000, 8).unwrap(), b"ababcdef");
        call(&mut engine, 2, "_memset", [0x2000, 0x41, 4]);
        assert_eq!(engine.mem_read(0x2000, 4).unwrap(), b"AAAA");
        call(&mut engine, 3, "_bzero", [0x2000, 2, 0]);
        assert_eq!(engine.mem_read(0x2000, 4).unwrap(), b"\0\0AA");
        engine.mem_write(0x1000, b"hello\0").unwrap();
        call(&mut engine, 4, "_strlen", [0x1000, 0, 0]);
        assert_eq!(engine.reg_read(199).unwrap(), 5);
        call(&mut engine, 5, "_strnlen", [0x1000, 3, 0]);
        assert_eq!(engine.reg_read(199).unwrap(), 3);
        call(&mut engine, 6, "_free", [0x2000, 0, 0]);
        assert_eq!(engine.reg_read(199).unwrap(), 0x2000);
        call(&mut engine, 7, "_pthread_mutex_lock", [0x2000, 0, 0]);
        assert_eq!(engine.reg_read(199).unwrap(), 0);
        call(&mut engine, 8, "_chkstk_darwin", [0x1234, 0, 0]);
        assert_eq!(engine.reg_read(199).unwrap(), 0x1234);
        engine.mem_write(0x1000, b"kern.hv_vmm_present\0").unwrap();
        engine.mem_write(0x2000, &4u64.to_le_bytes()).unwrap();
        call(&mut engine, 10, "_sysctlbyname", [0x1000, 0x2010, 0x2000]);
        assert_eq!(engine.reg_read(199).unwrap(), 0);
        assert_eq!(engine.mem_read(0x2010, 4).unwrap(), [0; 4]);
        assert_eq!(engine.mem_read(0x2000, 8).unwrap(), 4u64.to_le_bytes());
        call(&mut engine, 11, "_getuid", [0, 0, 0]);
        assert_eq!(engine.reg_read(199).unwrap(), 0);
        call(&mut engine, 12, "_vm_allocate", [0, 0x2020, 8]);
        let allocated = u64::from_le_bytes(engine.mem_read(0x2020, 8).unwrap().try_into().unwrap());
        assert_eq!(allocated, SYNTHETIC_ALLOCATION_BASE);
        assert_eq!(engine.reg_read(199).unwrap(), 0);
        call(&mut engine, 13, "_notify_register_check", [0, 0x2000, 0]);
        assert_eq!(engine.mem_read(0x2000, 4).unwrap(), 1u32.to_le_bytes());
        call(&mut engine, 14, "_notify_check", [0, 0x2000, 0]);
        assert_eq!(engine.mem_read(0x2000, 4).unwrap(), 0u32.to_le_bytes());
        call(&mut engine, 15, "_proc_pidpath", [1234, 0x2040, 64]);
        assert_eq!(engine.reg_read(199).unwrap(), 22);
        assert_eq!(
            engine.mem_read(0x2040, 23).unwrap(),
            b"/usr/sbin/fairplayd.H2\0"
        );
        call(&mut engine, 16, "_pthread_self", [0, 0, 0]);
        assert_eq!(engine.reg_read(199).unwrap(), SYNTHETIC_THREAD);
        call(
            &mut engine,
            17,
            "_pthread_get_qos_class_np",
            [0, 0x2000, 0x2004],
        );
        assert_eq!(engine.mem_read(0x2000, 4).unwrap(), 0x15u32.to_le_bytes());
        engine.mem_write(0x2008, &1234u32.to_le_bytes()).unwrap();
        engine.reg_write(205, 0x2008).unwrap();
        call(&mut engine, 18, "_audit_token_to_au32", [0, 0, 0]);
        assert_eq!(engine.mem_read(0x2008, 4).unwrap(), 0u32.to_le_bytes());
        assert!(
            !install_modeled_external(
                &mut engine,
                EXTERNAL_BASE + 9 * EXTERNAL_STRIDE,
                "_unmodeled",
                &failure,
                &allocations,
                &once_tokens,
                (&host_state, &virtual_files, &darwin),
            )
            .unwrap()
        );
        assert!(
            engine
                .start_bounded(
                    EXTERNAL_BASE + 9 * EXTERNAL_STRIDE,
                    0x5000,
                    Duration::from_secs(2),
                    4
                )
                .is_err()
        );
    }

    #[test]
    fn modeled_external_reports_invalid_guest_memory() {
        let mut engine = Engine::new().unwrap();
        let failure = Rc::new(RefCell::new(None));
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let allocations = Rc::new(RefCell::new(
            AllocationState::from_checkpoint(&source).unwrap(),
        ));
        let once_tokens = Rc::new(RefCell::new(BTreeSet::new()));
        let host_state = Rc::new(RefCell::new(HostState::from_checkpoint(&source).unwrap()));
        let virtual_files = Rc::new(RefCell::new(
            VirtualFileState::from_checkpoint(&source).unwrap(),
        ));
        let darwin = Rc::new(RefCell::new(DarwinState::from_checkpoint(&source).unwrap()));
        install_modeled_external(
            &mut engine,
            EXTERNAL_BASE,
            "_memset",
            &failure,
            &allocations,
            &once_tokens,
            (&host_state, &virtual_files, &darwin),
        )
        .unwrap();
        engine.reg_write(199, 0x9000).unwrap();
        engine.reg_write(200, 0x41).unwrap();
        engine.reg_write(201, 1).unwrap();
        engine.reg_write(2, 0x5000).unwrap();
        let _ = engine.start_bounded(EXTERNAL_BASE, 0x5000, Duration::from_secs(2), 4);
        assert!(failure.borrow().as_ref().unwrap().contains("memset"));
    }

    #[test]
    fn resolved_coreke_symbol_survives_checkpoint_reload() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("dynamic.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x1000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_write(0x1000, b"CoreKEOperation\0")
            .unwrap();
        install_dynamic_symbol_hook(
            &mut runner.engine,
            &runner.host_state,
            &runner.external_failure,
            &source.page_addresses().unwrap(),
        )
        .unwrap();
        install_modeled_external(
            &mut runner.engine,
            EXTERNAL_BASE,
            "_dlsym",
            &runner.external_failure,
            &runner.allocation_state,
            &runner.once_tokens,
            (&runner.host_state, &runner.virtual_files, &runner.darwin),
        )
        .unwrap();
        runner.engine.reg_write(200, 0x1000).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(EXTERNAL_BASE, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        assert_eq!(runner.engine.reg_read(199).unwrap(), SYNTHETIC_DLSYM_BASE);
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();

        let reloaded = FairplayCheckpoint::load_private(&output_path).unwrap();
        let mut resumed = CheckpointRunner::new(&reloaded, SYNTHETIC_BINARY).unwrap();
        resumed.engine.mem_map(0x2000, PAGE_BYTES as usize).unwrap();
        resumed.engine.reg_write(199, 10).unwrap();
        resumed.engine.reg_write(201, 0x2000).unwrap();
        resumed.engine.reg_write(2, 0x5000).unwrap();
        resumed
            .engine
            .start_bounded(SYNTHETIC_DLSYM_BASE, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        assert_eq!(resumed.engine.reg_read(199).unwrap(), 0xffff_58fe);
        assert_eq!(
            resumed.engine.mem_read(0x2008, 8).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn sha1_context_survives_checkpoint_reload() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("sha1.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x2000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_write(0x2000, b"abc").unwrap();
        for (index, symbol) in ["_CC_SHA1_Init", "_CC_SHA1_Update"].into_iter().enumerate() {
            install_modeled_external(
                &mut runner.engine,
                EXTERNAL_BASE + index as u64 * EXTERNAL_STRIDE,
                symbol,
                &runner.external_failure,
                &runner.allocation_state,
                &runner.once_tokens,
                (&runner.host_state, &runner.virtual_files, &runner.darwin),
            )
            .unwrap();
        }
        runner.engine.reg_write(199, 0x1000).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(EXTERNAL_BASE, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        runner.engine.reg_write(199, 0x1000).unwrap();
        runner.engine.reg_write(200, 0x2000).unwrap();
        runner.engine.reg_write(201, 3).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(
                EXTERNAL_BASE + EXTERNAL_STRIDE,
                0x5000,
                Duration::from_secs(2),
                4,
            )
            .unwrap();
        assert!(runner.external_failure.borrow().is_none());
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();

        let reloaded = FairplayCheckpoint::load_private(&output_path).unwrap();
        let mut resumed = CheckpointRunner::new(&reloaded, SYNTHETIC_BINARY).unwrap();
        resumed.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        install_modeled_external(
            &mut resumed.engine,
            EXTERNAL_BASE,
            "_CC_SHA1_Final",
            &resumed.external_failure,
            &resumed.allocation_state,
            &resumed.once_tokens,
            (&resumed.host_state, &resumed.virtual_files, &resumed.darwin),
        )
        .unwrap();
        resumed.engine.reg_write(199, 0x3000).unwrap();
        resumed.engine.reg_write(200, 0x1000).unwrap();
        resumed.engine.reg_write(2, 0x5000).unwrap();
        resumed
            .engine
            .start_bounded(EXTERNAL_BASE, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        assert!(resumed.external_failure.borrow().is_none());
        assert_eq!(resumed.engine.reg_read(199).unwrap(), 1);
        assert_eq!(
            resumed.engine.mem_read(0x3000, 20).unwrap(),
            Sha1::digest(b"abc").to_vec()
        );
    }

    #[test]
    fn core_foundation_values_survive_checkpoint_reload() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("cf-values.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x1000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_write(0x1000, b"FairPlay\0").unwrap();
        runner.engine.mem_write(0x1010, b"data").unwrap();
        for (index, symbol) in ["_CFStringCreateWithCString", "_CFDataCreate"]
            .into_iter()
            .enumerate()
        {
            install_modeled_external(
                &mut runner.engine,
                EXTERNAL_BASE + index as u64 * EXTERNAL_STRIDE,
                symbol,
                &runner.external_failure,
                &runner.allocation_state,
                &runner.once_tokens,
                (&runner.host_state, &runner.virtual_files, &runner.darwin),
            )
            .unwrap();
        }
        runner.engine.reg_write(200, 0x1000).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(EXTERNAL_BASE, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        let string_handle = runner.engine.reg_read(199).unwrap();
        runner.engine.reg_write(200, 0x1010).unwrap();
        runner.engine.reg_write(201, 4).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(
                EXTERNAL_BASE + EXTERNAL_STRIDE,
                0x5000,
                Duration::from_secs(2),
                4,
            )
            .unwrap();
        let data_handle = runner.engine.reg_read(199).unwrap();
        assert!(runner.external_failure.borrow().is_none());
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();

        let reloaded = FairplayCheckpoint::load_private(&output_path).unwrap();
        let mut resumed = CheckpointRunner::new(&reloaded, SYNTHETIC_BINARY).unwrap();
        resumed.engine.mem_map(0x2000, PAGE_BYTES as usize).unwrap();
        for (index, symbol) in [
            "_CFGetTypeID",
            "_CFStringGetCString",
            "_CFDataGetBytes",
            "_CFDataGetLength",
        ]
        .into_iter()
        .enumerate()
        {
            install_modeled_external(
                &mut resumed.engine,
                EXTERNAL_BASE + index as u64 * EXTERNAL_STRIDE,
                symbol,
                &resumed.external_failure,
                &resumed.allocation_state,
                &resumed.once_tokens,
                (&resumed.host_state, &resumed.virtual_files, &resumed.darwin),
            )
            .unwrap();
        }
        let call = |runner: &mut CheckpointRunner, index: u64, args: [u64; 4]| {
            for (register, value) in args.into_iter().enumerate() {
                runner
                    .engine
                    .reg_write(199 + register as i32, value)
                    .unwrap();
            }
            runner.engine.reg_write(2, 0x5000).unwrap();
            runner
                .engine
                .start_bounded(
                    EXTERNAL_BASE + index * EXTERNAL_STRIDE,
                    0x5000,
                    Duration::from_secs(2),
                    4,
                )
                .unwrap();
            assert!(runner.external_failure.borrow().is_none());
            runner.engine.reg_read(199).unwrap()
        };
        assert_eq!(
            call(&mut resumed, 0, [string_handle, 0, 0, 0]),
            CF_STRING_TYPE_ID
        );
        assert_eq!(
            call(&mut resumed, 0, [data_handle, 0, 0, 0]),
            CF_DATA_TYPE_ID
        );
        assert_eq!(call(&mut resumed, 1, [string_handle, 0x2000, 16, 0]), 1);
        assert_eq!(resumed.engine.mem_read(0x2000, 9).unwrap(), b"FairPlay\0");
        assert_eq!(call(&mut resumed, 3, [data_handle, 0, 0, 0]), 4);
        call(&mut resumed, 2, [data_handle, 0, 4, 0x2010]);
        assert_eq!(resumed.engine.mem_read(0x2010, 4).unwrap(), b"data");
    }

    #[test]
    fn allocation_pages_and_next_address_survive_checkpoint_reload() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        assert_eq!(
            runner.allocation_state.borrow().next,
            SYNTHETIC_ALLOCATION_BASE
        );
        let malloc_address = EXTERNAL_BASE;
        install_modeled_external(
            &mut runner.engine,
            malloc_address,
            "_malloc",
            &runner.external_failure,
            &runner.allocation_state,
            &runner.once_tokens,
            (&runner.host_state, &runner.virtual_files, &runner.darwin),
        )
        .unwrap();
        runner.engine.reg_write(199, 5000).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(malloc_address, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        assert_eq!(
            runner.engine.reg_read(199).unwrap(),
            SYNTHETIC_ALLOCATION_BASE
        );
        runner
            .engine
            .mem_write(SYNTHETIC_ALLOCATION_BASE + PAGE_BYTES, b"Rust")
            .unwrap();
        let calloc_address = EXTERNAL_BASE + EXTERNAL_STRIDE;
        install_modeled_external(
            &mut runner.engine,
            calloc_address,
            "_calloc",
            &runner.external_failure,
            &runner.allocation_state,
            &runner.once_tokens,
            (&runner.host_state, &runner.virtual_files, &runner.darwin),
        )
        .unwrap();
        runner.engine.reg_write(199, 2).unwrap();
        runner.engine.reg_write(200, 32).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(calloc_address, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        assert_eq!(
            runner.engine.reg_read(199).unwrap(),
            SYNTHETIC_ALLOCATION_BASE + 2 * PAGE_BYTES
        );
        assert_eq!(
            runner
                .engine
                .mem_read(SYNTHETIC_ALLOCATION_BASE + 2 * PAGE_BYTES, 64)
                .unwrap(),
            [0; 64]
        );
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        assert_eq!(
            runner
                .write_checkpoint(&source, &binary_path, &output_path)
                .unwrap(),
            4
        );
        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        assert_eq!(
            resumed.next_allocation().unwrap(),
            Some(SYNTHETIC_ALLOCATION_BASE + 3 * PAGE_BYTES)
        );
        assert_eq!(
            resumed
                .read_block::<4>(SYNTHETIC_ALLOCATION_BASE + PAGE_BYTES)
                .unwrap()
                .as_slice(),
            b"Rust"
        );
        let replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        assert_eq!(
            replay.allocation_state.borrow().next,
            SYNTHETIC_ALLOCATION_BASE + 3 * PAGE_BYTES
        );
        assert_eq!(
            replay
                .engine
                .mem_read(SYNTHETIC_ALLOCATION_BASE + PAGE_BYTES, 4)
                .unwrap(),
            b"Rust"
        );
    }

    #[test]
    fn lazy_guest_data_pages_survive_checkpoint_reload_without_mapping_fetches() {
        const DATA: u64 = 0x7000_3000_0000;
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_write(0x3000, &0xf940_0020u32.to_le_bytes())
            .unwrap();
        runner.engine.reg_write(200, DATA).unwrap();
        runner
            .engine
            .start_bounded(0x3000, 0x3004, Duration::from_secs(2), 4)
            .unwrap();
        assert_eq!(runner.engine.reg_read(199).unwrap(), 0);
        assert!(runner.allocation_state.borrow().new_pages.contains(&DATA));
        runner.engine.mem_write(DATA, b"live").unwrap();
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();
        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        assert_eq!(resumed.read_block::<4>(DATA).unwrap().as_slice(), b"live");
        let replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        assert_eq!(replay.engine.mem_read(DATA, 4).unwrap(), b"live");

        let mut fetch = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        assert!(
            fetch
                .engine
                .start_bounded(DATA, DATA + 4, Duration::from_secs(2), 4)
                .is_err()
        );
        assert!(!fetch.allocation_state.borrow().new_pages.contains(&DATA));
    }

    #[test]
    fn pthread_once_runs_callback_once_and_persists_token() {
        const STACK: u64 = 0x7300_0000_0000;
        const CALLBACK: u64 = STACK + PAGE_BYTES;
        const RETURN: u64 = STACK + 2 * PAGE_BYTES;
        const TOKEN: u64 = 0x1234;

        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let setup = |runner: &mut CheckpointRunner| {
            runner.engine.mem_map(STACK, PAGE_BYTES as usize).unwrap();
            runner
                .engine
                .mem_map(CALLBACK, PAGE_BYTES as usize)
                .unwrap();
            runner
                .engine
                .mem_map(SYNTHETIC_NOOP_CALLBACK, PAGE_BYTES as usize)
                .unwrap();
            runner
                .engine
                .mem_write(SYNTHETIC_NOOP_CALLBACK, &RET_X30)
                .unwrap();
            let callback = [0x9100_0484u32, 0xd65f_03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            runner.engine.mem_write(CALLBACK, &callback).unwrap();
            install_modeled_external(
                &mut runner.engine,
                EXTERNAL_BASE,
                "_pthread_once",
                &runner.external_failure,
                &runner.allocation_state,
                &runner.once_tokens,
                (&runner.host_state, &runner.virtual_files, &runner.darwin),
            )
            .unwrap();
        };
        let call = |runner: &mut CheckpointRunner| {
            runner.engine.reg_write(199, TOKEN).unwrap();
            runner.engine.reg_write(200, CALLBACK).unwrap();
            runner.engine.reg_write(2, RETURN).unwrap();
            runner.engine.reg_write(4, CALLBACK).unwrap();
            runner
                .engine
                .start_bounded(EXTERNAL_BASE, RETURN, Duration::from_secs(2), 20)
                .unwrap();
            assert!(runner.external_failure.borrow().is_none());
            assert_eq!(runner.engine.reg_read(199).unwrap(), 0);
        };

        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        setup(&mut runner);
        runner.engine.reg_write(203, 0).unwrap();
        call(&mut runner);
        assert_eq!(runner.engine.reg_read(203).unwrap(), 1);
        call(&mut runner);
        assert_eq!(runner.engine.reg_read(203).unwrap(), 1);
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();

        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        assert_eq!(resumed.once_tokens().unwrap(), vec![TOKEN]);
        let mut replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        setup(&mut replay);
        replay.engine.reg_write(203, 0).unwrap();
        call(&mut replay);
        assert_eq!(replay.engine.reg_read(203).unwrap(), 0);
    }

    #[test]
    fn dispatch_once_invokes_block_once() {
        const STACK: u64 = 0x7300_0000_0000;
        const BLOCK: u64 = STACK + 0x100;
        const CALLBACK: u64 = STACK + PAGE_BYTES;
        const RETURN: u64 = STACK + 2 * PAGE_BYTES;
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(STACK, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_map(CALLBACK, PAGE_BYTES as usize)
            .unwrap();
        runner
            .engine
            .mem_map(SYNTHETIC_NOOP_CALLBACK, PAGE_BYTES as usize)
            .unwrap();
        runner
            .engine
            .mem_write(SYNTHETIC_NOOP_CALLBACK, &RET_X30)
            .unwrap();
        runner
            .engine
            .mem_write(BLOCK + 0x10, &CALLBACK.to_le_bytes())
            .unwrap();
        let callback = [0x9100_0484u32, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        runner.engine.mem_write(CALLBACK, &callback).unwrap();
        install_modeled_external(
            &mut runner.engine,
            EXTERNAL_BASE,
            "_dispatch_once",
            &runner.external_failure,
            &runner.allocation_state,
            &runner.once_tokens,
            (&runner.host_state, &runner.virtual_files, &runner.darwin),
        )
        .unwrap();
        runner.engine.reg_write(203, 0).unwrap();
        for _ in 0..2 {
            runner.engine.reg_write(199, 0x1234).unwrap();
            runner.engine.reg_write(200, BLOCK).unwrap();
            runner.engine.reg_write(2, RETURN).unwrap();
            runner.engine.reg_write(4, STACK + 0x800).unwrap();
            runner
                .engine
                .start_bounded(EXTERNAL_BASE, RETURN, Duration::from_secs(2), 20)
                .unwrap();
            assert!(runner.external_failure.borrow().is_none());
            assert_eq!(runner.engine.reg_read(199).unwrap(), 0);
        }
        assert_eq!(runner.engine.reg_read(203).unwrap(), 1);
        assert!(runner.once_tokens.borrow().contains(&0x1234));
    }

    #[test]
    fn deterministic_host_calls_and_random_state_survive_checkpoint_reload() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x8000, PAGE_BYTES as usize).unwrap();
        let call = |runner: &mut CheckpointRunner, index: u64, symbol: &str, x0: u64| {
            let address = EXTERNAL_BASE + index * EXTERNAL_STRIDE;
            install_modeled_external(
                &mut runner.engine,
                address,
                symbol,
                &runner.external_failure,
                &runner.allocation_state,
                &runner.once_tokens,
                (&runner.host_state, &runner.virtual_files, &runner.darwin),
            )
            .unwrap();
            runner.engine.reg_write(199, x0).unwrap();
            runner.engine.reg_write(2, 0x5000).unwrap();
            runner
                .engine
                .start_bounded(address, 0x5000, Duration::from_secs(2), 4)
                .unwrap();
            assert!(runner.external_failure.borrow().is_none());
            runner.engine.reg_read(199).unwrap()
        };

        let expected = source
            .random_state()
            .unwrap()
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        assert_eq!(call(&mut runner, 0, "_arc4random", 0), u64::from(expected));
        assert_eq!(call(&mut runner, 1, "_gettimeofday", 0x8000), 0);
        assert_eq!(
            runner.engine.mem_read(0x8000, 16).unwrap(),
            [1_700_000_000u64.to_le_bytes(), [0; 8]].concat()
        );
        assert_eq!(call(&mut runner, 2, "_getpid", 0), 1234);
        assert_eq!(call(&mut runner, 3, "_kqueue", 0), 0x900);
        runner
            .engine
            .mem_map(SYNTHETIC_ERRNO_ADDRESS, PAGE_BYTES as usize)
            .unwrap();
        runner.errno_mapped = true;
        let mmap_address = EXTERNAL_BASE + 4 * EXTERNAL_STRIDE;
        install_modeled_external(
            &mut runner.engine,
            mmap_address,
            "_mmap",
            &runner.external_failure,
            &runner.allocation_state,
            &runner.once_tokens,
            (&runner.host_state, &runner.virtual_files, &runner.darwin),
        )
        .unwrap();
        runner.engine.reg_write(200, 8192).unwrap();
        runner.engine.reg_write(202, 0x1000).unwrap();
        runner.engine.reg_write(203, u64::MAX).unwrap();
        runner.engine.reg_write(2, 0x5000).unwrap();
        runner
            .engine
            .start_bounded(mmap_address, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        let mapped = runner.engine.reg_read(199).unwrap();
        assert_eq!(mapped, SYNTHETIC_ALLOCATION_BASE);
        runner
            .engine
            .mem_write(mapped + PAGE_BYTES, b"mapped")
            .unwrap();
        runner.engine.reg_write(202, 0).unwrap();
        runner.engine.reg_write(203, 17).unwrap();
        runner
            .engine
            .start_bounded(mmap_address, 0x5000, Duration::from_secs(2), 4)
            .unwrap();
        assert_eq!(runner.engine.reg_read(199).unwrap(), u64::MAX);
        assert_eq!(
            runner.engine.mem_read(SYNTHETIC_ERRNO_ADDRESS, 4).unwrap(),
            9u32.to_le_bytes()
        );
        assert_eq!(call(&mut runner, 5, "_error", 0), SYNTHETIC_ERRNO_ADDRESS);
        assert_eq!(call(&mut runner, 6, "_munmap", mapped), 0);
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();

        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        assert_eq!(resumed.random_state().unwrap(), expected);
        assert_eq!(
            resumed
                .read_block::<6>(mapped + PAGE_BYTES)
                .unwrap()
                .as_slice(),
            b"mapped"
        );
        assert_eq!(
            resumed
                .read_block::<4>(SYNTHETIC_ERRNO_ADDRESS)
                .unwrap()
                .as_slice(),
            &9u32.to_le_bytes()
        );
        let mut replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        let next = expected.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        assert_eq!(call(&mut replay, 0, "_arc4random", 0), u64::from(next));
    }

    #[test]
    fn virtual_file_operations_resume_with_open_offset_and_removed_suffix() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x8000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_map(0x9000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_map(0xa000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_map(SYNTHETIC_ERRNO_ADDRESS, PAGE_BYTES as usize)
            .unwrap();
        runner.errno_mapped = true;
        runner
            .engine
            .mem_write(0x8000, b"/var/db/fpsd/SC Info.demo\0")
            .unwrap();
        runner
            .add_file_payload("SC Info.demo", Zeroizing::new(b"abcdef".to_vec()))
            .unwrap();
        runner
            .add_file_stat(
                "SC Info.demo",
                VirtualFileStat {
                    mode: 0o666,
                    uid: 265,
                    gid: 265,
                },
            )
            .unwrap();
        runner.set_missing_files_are_enoent(true);
        let call = |runner: &mut CheckpointRunner, index: u64, symbol: &str, args: [u64; 6]| {
            let address = EXTERNAL_BASE + index * EXTERNAL_STRIDE;
            install_modeled_external(
                &mut runner.engine,
                address,
                symbol,
                &runner.external_failure,
                &runner.allocation_state,
                &runner.once_tokens,
                (&runner.host_state, &runner.virtual_files, &runner.darwin),
            )
            .unwrap();
            for (index, value) in args.into_iter().enumerate() {
                runner.engine.reg_write(199 + index as i32, value).unwrap();
            }
            runner.engine.reg_write(2, 0x5000).unwrap();
            runner
                .engine
                .start_bounded(address, 0x5000, Duration::from_secs(2), 4)
                .unwrap();
            assert!(runner.external_failure.borrow().is_none());
            runner.engine.reg_read(199).unwrap()
        };

        let descriptor = call(&mut runner, 0, "_open", [0x8000, 0, 0, 0, 0, 0]);
        assert_eq!(descriptor, 100);
        assert_eq!(
            call(&mut runner, 1, "_stat", [0x8000, 0xa000, 0, 0, 0, 0]),
            0
        );
        let stat = runner.engine.mem_read(0xa000, DARWIN_STAT_BYTES).unwrap();
        assert_eq!(u16::from_le_bytes(stat[4..6].try_into().unwrap()), 0o100666);
        assert_eq!(u32::from_le_bytes(stat[16..20].try_into().unwrap()), 265);
        assert_eq!(u64::from_le_bytes(stat[96..104].try_into().unwrap()), 6);
        assert_eq!(
            call(&mut runner, 2, "_fstat", [descriptor, 0xa000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            call(&mut runner, 3, "_read", [descriptor, 0x9000, 3, 0, 0, 0]),
            3
        );
        assert_eq!(runner.engine.mem_read(0x9000, 3).unwrap(), b"abc");
        let mapped = call(&mut runner, 4, "_mmap", [0, 6, 0, 0, descriptor, 0]);
        assert_eq!(runner.engine.mem_read(mapped, 6).unwrap(), b"abcdef");
        assert_eq!(call(&mut runner, 5, "_unlink", [0x8000, 0, 0, 0, 0, 0]), 0);
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();

        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        let mut replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        replay.engine.mem_map(0x8000, PAGE_BYTES as usize).unwrap();
        replay.engine.mem_map(0x9000, PAGE_BYTES as usize).unwrap();
        replay
            .engine
            .mem_write(0x8000, b"/var/db/fpsd/SC Info.demo\0")
            .unwrap();
        replay
            .add_file_payload("SC Info.demo", Zeroizing::new(b"abcdef".to_vec()))
            .unwrap();
        replay.set_missing_files_are_enoent(true);
        assert_eq!(
            call(&mut replay, 0, "_open", [0x8000, 0, 0, 0, 0, 0]),
            0xffff_ffff
        );
        assert_eq!(
            replay.engine.mem_read(SYNTHETIC_ERRNO_ADDRESS, 4).unwrap(),
            2u32.to_le_bytes()
        );
        assert_eq!(
            call(&mut replay, 1, "_read", [descriptor, 0x9000, 6, 0, 0, 0]),
            3
        );
        assert_eq!(replay.engine.mem_read(0x9000, 3).unwrap(), b"def");
        assert_eq!(
            call(&mut replay, 2, "_close", [descriptor, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            call(&mut replay, 3, "_read", [descriptor, 0x9000, 1, 0, 0, 0]),
            0xffff_ffff
        );
        assert_eq!(
            replay.engine.mem_read(SYNTHETIC_ERRNO_ADDRESS, 4).unwrap(),
            9u32.to_le_bytes()
        );
    }

    #[test]
    fn darwin_iokit_and_cf_objects_survive_checkpoint_reload() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        let prepare = |runner: &mut CheckpointRunner| {
            runner.engine.mem_map(0x8000, PAGE_BYTES as usize).unwrap();
            runner.engine.mem_map(0x9000, PAGE_BYTES as usize).unwrap();
            runner.engine.mem_map(0xa000, PAGE_BYTES as usize).unwrap();
            runner.engine.mem_write(0x9000, b"IOBuiltin").unwrap();
            runner.engine.mem_write(0x9010, b"IOMACAddress").unwrap();
            runner
                .engine
                .mem_write(0x8010, &0x9000u64.to_le_bytes())
                .unwrap();
            runner
                .engine
                .mem_write(0x8018, &9u64.to_le_bytes())
                .unwrap();
            runner
                .engine
                .mem_write(0x8050, &0x9010u64.to_le_bytes())
                .unwrap();
            runner
                .engine
                .mem_write(0x8058, &12u64.to_le_bytes())
                .unwrap();
        };
        let call = |runner: &mut CheckpointRunner, index: u64, symbol: &str, args: [u64; 6]| {
            let address = EXTERNAL_BASE + index * EXTERNAL_STRIDE;
            install_modeled_external(
                &mut runner.engine,
                address,
                symbol,
                &runner.external_failure,
                &runner.allocation_state,
                &runner.once_tokens,
                (&runner.host_state, &runner.virtual_files, &runner.darwin),
            )
            .unwrap();
            for (index, value) in args.into_iter().enumerate() {
                runner.engine.reg_write(199 + index as i32, value).unwrap();
            }
            runner.engine.reg_write(2, 0x5000).unwrap();
            runner
                .engine
                .start_bounded(address, 0x5000, Duration::from_secs(2), 4)
                .unwrap();
            assert!(runner.external_failure.borrow().is_none());
            runner.engine.reg_read(199).unwrap()
        };
        prepare(&mut runner);
        runner.set_mac_address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert!(
            runner
                .set_iokit15_output(Zeroizing::new(b"test".to_vec()))
                .is_err()
        );
        let mut iokit15 = vec![0; IOKIT15_STRUCTURE_BYTES];
        iokit15[0x20..0x24].copy_from_slice(b"test");
        iokit15[0x220..0x224].copy_from_slice(&4u32.to_le_bytes());
        runner.set_iokit15_output(Zeroizing::new(iokit15)).unwrap();
        assert_eq!(
            call(&mut runner, 0, "_IOMainPort", [0, 0xa000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            runner.engine.mem_read(0xa000, 4).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            call(&mut runner, 1, "_IOServiceMatching", [0, 0, 0, 0, 0, 0]),
            0x7102_0000_0000
        );
        assert_eq!(
            call(
                &mut runner,
                2,
                "_IOServiceGetMatchingServices",
                [0, 0, 0xa000, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            runner.engine.mem_read(0xa000, 4).unwrap(),
            0x100u32.to_le_bytes()
        );
        assert_eq!(
            call(&mut runner, 3, "_IOIteratorNext", [0x100, 0, 0, 0, 0, 0]),
            0x200
        );
        assert_eq!(
            call(&mut runner, 4, "_IOIteratorNext", [0x100, 0, 0, 0, 0, 0]),
            0
        );
        let boolean = call(
            &mut runner,
            5,
            "_IORegistryEntryCreateCFProperty",
            [0x200, 0x8000, 0, 0, 0, 0],
        );
        assert_eq!(
            call(
                &mut runner,
                6,
                "_CFBooleanGetValue",
                [boolean, 0, 0, 0, 0, 0]
            ),
            1
        );
        let data = call(
            &mut runner,
            7,
            "_IORegistryEntryCreateCFProperty",
            [0x200, 0x8040, 0, 0, 0, 0],
        );
        call(
            &mut runner,
            8,
            "_CFDataGetBytes",
            [data, 0, 6, 0xa010, 0, 0],
        );
        assert_eq!(
            runner.engine.mem_read(0xa010, 6).unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        runner
            .engine
            .mem_write(0xa100, &8u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            call(
                &mut runner,
                9,
                "_IOConnectCallStructMethod",
                [0, 0x16, 0, 0, 0xa200, 0xa100]
            ),
            0
        );
        assert_eq!(
            runner.engine.mem_read(0xa200, 4).unwrap(),
            0x4b13_0000u32.to_le_bytes()
        );
        runner
            .engine
            .mem_write(0xa100, &(IOKIT15_STRUCTURE_BYTES as u64).to_le_bytes())
            .unwrap();
        assert_eq!(
            call(
                &mut runner,
                10,
                "_IOConnectCallStructMethod",
                [0, 0x15, 0, 0, 0xa200, 0xa100]
            ),
            0
        );
        assert_eq!(runner.engine.mem_read(0xa220, 4).unwrap(), b"test");
        assert_eq!(
            call(
                &mut runner,
                11,
                "_IOServiceGetMatchingServices",
                [0, 0, 0xa000, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            runner.engine.mem_read(0xa000, 4).unwrap(),
            0x101u32.to_le_bytes()
        );
        runner
            .engine
            .reg_write(REG_PC, source.pc().unwrap())
            .unwrap();
        runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();

        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        let mut replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        prepare(&mut replay);
        assert_eq!(
            call(&mut replay, 0, "_IOIteratorNext", [0x101, 0, 0, 0, 0, 0]),
            0x201
        );
        call(
            &mut replay,
            1,
            "_CFDataGetBytes",
            [data, 1, 3, 0xa010, 0, 0],
        );
        assert_eq!(
            replay.engine.mem_read(0xa010, 3).unwrap(),
            [0xbb, 0xcc, 0xdd]
        );
        call(&mut replay, 2, "_CFRelease", [data, 0, 0, 0, 0, 0]);
        assert!(!replay.darwin.borrow().cf_values.contains_key(&data));
    }

    #[test]
    fn resumes_checked_macho_and_checkpoint_to_target() {
        let checkpoint = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        assert!(CheckpointRunner::new(&checkpoint, b"wrong fairplayd").is_err());
        let mut runner = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        assert_eq!(runner.checkpoint_pages, 1);
        assert_eq!(runner.image.fixups, 0);
        let stop = checkpoint.pc().unwrap() + 8;
        assert!(runner.run_until(stop, Duration::from_secs(2), 1).is_err());
        let mut runner = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        runner.run_until(stop, Duration::from_secs(2), 8).unwrap();
        assert_eq!(runner.engine.reg_read(199).unwrap(), 43);
    }

    #[test]
    fn stops_on_requested_address_visit_with_one_instruction_budget() {
        let checkpoint = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_write(0x3000, &0x9100_0400u32.to_le_bytes())
            .unwrap(); // add x0, x0, #1
        runner
            .engine
            .mem_write(0x3004, &0x17ff_ffffu32.to_le_bytes())
            .unwrap(); // b #-4
        runner.engine.reg_write(REG_PC, 0x3000).unwrap();
        runner.engine.reg_write(199, 0).unwrap();
        runner
            .run_until_hit(0x3000, 3, Duration::from_secs(2), 10)
            .unwrap();
        assert_eq!(runner.engine.reg_read(REG_PC).unwrap(), 0x3000);
        assert_eq!(runner.engine.reg_read(199).unwrap(), 2);

        let mut bounded = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        bounded.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        bounded
            .engine
            .mem_write(0x3000, &0x9100_0400u32.to_le_bytes())
            .unwrap();
        bounded
            .engine
            .mem_write(0x3004, &0x17ff_ffffu32.to_le_bytes())
            .unwrap();
        bounded.engine.reg_write(REG_PC, 0x3000).unwrap();
        assert!(
            bounded
                .run_until_hit(0x3000, 3, Duration::from_secs(2), 2)
                .is_err()
        );
        assert!(
            bounded
                .run_until_hit(0x3000, 0, Duration::from_secs(2), 10)
                .is_err()
        );
    }

    #[test]
    fn traces_guest_memory_accesses_in_execution_order() {
        let checkpoint = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_map(0x4000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_write(0x3000, &0xf940_0020u32.to_le_bytes())
            .unwrap(); // ldr x0, [x1]
        runner
            .engine
            .mem_write(0x3004, &0xf900_0420u32.to_le_bytes())
            .unwrap(); // str x0, [x1, #8]
        runner
            .engine
            .mem_write(0x4000, &42u64.to_le_bytes())
            .unwrap();
        runner.engine.reg_write(REG_PC, 0x3000).unwrap();
        runner.engine.reg_write(200, 0x4000).unwrap();
        let trace = runner
            .run_until_hit_with_memory_trace(
                0x3008,
                1,
                Duration::from_secs(2),
                10,
                MemoryTraceOptions {
                    reads: true,
                    writes: true,
                    max_events: 10,
                },
            )
            .unwrap();
        assert_eq!(trace.memory_read_events.len(), 1);
        assert_eq!(trace.memory_write_events.len(), 1);
        assert_eq!(trace.memory_read_events[0].ordinal, 0);
        assert_eq!(trace.memory_read_events[0].pc, "0x3000");
        assert_eq!(trace.memory_read_events[0].address, "0x4000");
        assert_eq!(trace.memory_write_events[0].ordinal, 1);
        assert_eq!(trace.memory_write_events[0].pc, "0x3004");
        assert_eq!(trace.memory_write_events[0].address, "0x4008");
        assert_eq!(
            runner.engine.mem_read(0x4008, 8).unwrap(),
            42u64.to_le_bytes()
        );

        runner.engine.reg_write(REG_PC, 0x3000).unwrap();
        assert!(
            runner
                .run_until_hit_with_memory_trace(
                    0x3008,
                    1,
                    Duration::from_secs(2),
                    10,
                    MemoryTraceOptions {
                        reads: true,
                        writes: true,
                        max_events: 1,
                    },
                )
                .unwrap_err()
                .to_string()
                .contains("memory trace event limit")
        );
    }

    #[test]
    fn stops_on_a_guest_read_overlapping_the_requested_range() {
        let checkpoint = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        runner.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_map(0x4000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_write(0x3000, &0xf940_0020u32.to_le_bytes())
            .unwrap(); // ldr x0, [x1]
        runner.engine.reg_write(REG_PC, 0x3000).unwrap();
        runner.engine.reg_write(200, 0x4000).unwrap();
        let stopped = runner
            .run_until_memory_read_range(0x4004, 4, Duration::from_secs(2), 10)
            .unwrap();
        assert_eq!(
            stopped,
            MemoryReadStop {
                pc: 0x3000,
                address: 0x4000,
                size: 8,
            }
        );
        assert_eq!(runner.engine.reg_read(REG_PC).unwrap(), 0x3000);
        assert!(
            runner
                .run_until_memory_read_range(0x4000, 0, Duration::from_secs(2), 10)
                .is_err()
        );
    }

    #[test]
    fn preserves_selected_instruction_bytes_through_checkpoint_restore() {
        let mut binary = SYNTHETIC_BINARY.to_vec();
        binary[20..24].copy_from_slice(&152u32.to_le_bytes());
        binary[36..40].copy_from_slice(&152u32.to_le_bytes());
        binary[96..100].copy_from_slice(&1u32.to_le_bytes());
        let section = 104;
        binary[section..section + 6].copy_from_slice(b"__text");
        binary[section + 16..section + 22].copy_from_slice(b"__TEXT");
        let address = 0x1_0000_0100u64;
        binary[section + 32..section + 40].copy_from_slice(&address.to_le_bytes());
        binary[section + 40..section + 48].copy_from_slice(&16u64.to_le_bytes());
        binary[section + 48..section + 52].copy_from_slice(&0x100u32.to_le_bytes());
        binary[section + 64..section + 68].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        let opcode = 0xd503_211fu32;
        binary[0x100..0x104].copy_from_slice(&opcode.to_le_bytes());

        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut root = source.clone_root().unwrap();
        let Value::Dict(ref mut fields) = root else {
            unreachable!();
        };
        fields.insert(
            HashableValue::String("binary_sha256".into()),
            Value::String(format!("{:x}", Sha256::digest(&binary))),
        );
        let serialized = serde_pickle::value_to_vec(&root, SerOptions::new()).unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&serialized).unwrap();
        let checkpoint = FairplayCheckpoint::parse_gzip(&encoder.finish().unwrap()).unwrap();
        let mut runner =
            CheckpointRunner::new_preserving_text(&checkpoint, &binary, &[address]).unwrap();
        assert_eq!(runner.preserved_text_instruction_sites, 1);
        assert_eq!(
            runner.engine.mem_read(address, 4).unwrap(),
            opcode.to_le_bytes()
        );
        runner.engine.reg_write(REG_PC, address).unwrap();
        runner
            .run_until(address + 4, Duration::from_secs(2), 2)
            .unwrap();
        assert_eq!(runner.engine.reg_read(REG_PC).unwrap(), address + 4);
        assert!(
            CheckpointRunner::new_preserving_text(&checkpoint, &binary, &[address, address])
                .is_err()
        );
    }

    #[test]
    fn writes_private_checkpoint_that_can_be_restored() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        let stop = source.pc().unwrap() + 8;
        runner.run_until(stop, Duration::from_secs(2), 8).unwrap();
        let pages = runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();
        assert_eq!(pages, 1);
        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        assert_eq!(resumed.pc().unwrap(), stop);
        assert_eq!(resumed.register_u64("x0").unwrap(), 43);
        assert_eq!(resumed.binary_hash, source.binary_hash);
        assert_eq!(
            resumed.page_addresses().unwrap(),
            source.page_addresses().unwrap()
        );
        let replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        assert_eq!(replay.engine.reg_read(199).unwrap(), 43);
    }

    #[test]
    fn upgrades_sparse_schema1_checkpoint_without_losing_metadata() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_SCHEMA1_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        let stop = source.pc().unwrap() + 8;
        runner.run_until(stop, Duration::from_secs(2), 8).unwrap();
        assert_eq!(
            runner
                .write_checkpoint(&source, &binary_path, &output_path)
                .unwrap(),
            1
        );
        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        assert_eq!(resumed.pc().unwrap(), stop);
        assert_eq!(resumed.register_u64("x0").unwrap(), 43);
        assert_eq!(resumed.binary_hash, source.binary_hash);
        let Value::Dict(fields) = resumed.clone_root().unwrap() else {
            panic!("resumed checkpoint root is not a dictionary");
        };
        assert_eq!(
            fields.get(&HashableValue::String("once_tokens".into())),
            Some(&Value::List(vec![Value::I64(0x1234), Value::I64(0x5678),]))
        );
        let replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        assert_eq!(replay.engine.reg_read(199).unwrap(), 43);
    }

    #[test]
    #[ignore = "requires the host's Apple fairplayd image"]
    fn loads_local_fairplayd_into_unicorn_when_available() {
        let path = "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd";
        let Ok(binary) = std::fs::read(path) else {
            return;
        };
        let mut engine = Engine::new().unwrap();
        let loaded = load_fairplayd(&mut engine, &binary).unwrap();
        assert!(loaded.fixups > 100);
        assert!(!loaded.compatibility_sites.is_empty());
        assert!(!loaded.externals.is_empty());
        assert!(!loaded.regions.is_empty());
        let bytes = engine.mem_read(loaded.image_base, 4).unwrap();
        assert_eq!(bytes.len(), 4);
    }
}
