//! Guest service address space and dispatch for SAP's imported symbols.

use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};

use crate::unicorn_runtime::{Engine, HookContext, REG_PC, REG_X0, REG_X1};

const SHIM_BASE: u64 = 0x0000_7ff8_8000_0000;
const CODE_SIZE: u64 = 0x80000;
const SHIM_SIZE: u64 = 0x100000;
const SLOT_SIZE: u64 = 16;
const FAKE_HANDLE: u64 = u64::MAX;
const REG_LR: i32 = 2;
const HEAP_BASE: u64 = 0x0000_4000_0000_0000;
const HEAP_SIZE: u64 = 64 << 20;
const MAX_TRANSFER: u64 = 64 << 20;

const ZERO_ALIASES: &[&str] = &[
    "_CFBundleGetMainBundle",
    "_CFDataGetBytePtr",
    "_CFDataGetLength",
    "_CFStringGetLength",
    "_CFStringGetMaximumSizeForEncoding",
    "_CFUUIDCreateString",
    "_IORegistryEntryFromPath",
    "_IORegistryEntrySearchCFProperty",
    "_IOServiceMatching",
    "_getenv",
    "_pthread_self",
    "_CFRelease",
    "_IOObjectRelease",
    "_close",
    "_close$UNIX2003",
    "_pthread_mutex_lock",
    "_pthread_mutex_unlock",
    "_pthread_rwlock_init",
    "_pthread_rwlock_init$UNIX2003",
    "_pthread_rwlock_unlock",
    "_pthread_rwlock_unlock$UNIX2003",
    "_pthread_rwlock_wrlock",
    "_pthread_rwlock_wrlock$UNIX2003",
];
const FAKE_ALIASES: &[&str] = &[
    "_CFDictionaryGetValue",
    "_DADiskCopyDescription",
    "_DADiskCreateFromBSDName",
    "_DASessionCreate",
    "_IORegistryEntryCreateCFProperty",
];
const MINUS_ONE_ALIASES: &[&str] = &[
    "_fcntl",
    "_fcntl$UNIX2003",
    "_lstat$INODE64",
    "_statfs",
    "_statfs$INODE64",
    "_sysctl",
];
const MAX_U32_ALIASES: &[&str] = &["_IOServiceGetMatchingService"];
const UNCHANGED_ALIASES: &[&str] = &["___chkstk_darwin", "____chkstk_darwin"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Handler {
    Return(u64),
    Unchanged,
    PthreadOnce,
    DispatchOnce,
    CallbackComplete,
    Malloc,
    MallocGoodSize,
    MallocSize,
    Calloc,
    Realloc,
    Free,
    Arc4random,
    ErrorPointer,
    Abort,
    Gettimeofday,
    Unsupported,
}

#[derive(Clone, Copy)]
struct Allocation {
    size: u64,
    reserved: u64,
}

#[derive(Clone, Copy)]
struct FreeBlock {
    address: u64,
    size: u64,
}

struct Entry {
    name: String,
    handler: Handler,
}

struct State {
    symbols: HashMap<String, u64>,
    entries: HashMap<u64, Entry>,
    data: Vec<(u64, Vec<u8>)>,
    code_cursor: u64,
    data_cursor: u64,
    fault: Option<String>,
    callback_returns: Vec<u64>,
    heap_cursor: u64,
    allocations: HashMap<u64, Allocation>,
    free_blocks: Vec<FreeBlock>,
}

impl State {
    fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            entries: HashMap::new(),
            data: Vec::new(),
            code_cursor: SHIM_BASE,
            data_cursor: SHIM_BASE + CODE_SIZE,
            fault: None,
            callback_returns: Vec::new(),
            heap_cursor: 0,
            allocations: HashMap::new(),
            free_blocks: Vec::new(),
        }
    }

    fn function(&mut self, name: &str, handler: Handler) -> Result<u64> {
        if let Some(&address) = self.symbols.get(name) {
            return Ok(address);
        }
        let end = self
            .code_cursor
            .checked_add(SLOT_SIZE)
            .context("guest service code overflow")?;
        if end > SHIM_BASE + CODE_SIZE {
            bail!("guest service code area is full");
        }
        let address = self.code_cursor;
        self.code_cursor = end;
        self.symbols.insert(name.to_owned(), address);
        self.entries.insert(
            address,
            Entry {
                name: name.to_owned(),
                handler,
            },
        );
        Ok(address)
    }

    fn data(&mut self, name: &str, bytes: &[u8]) -> Result<u64> {
        if let Some(&address) = self.symbols.get(name) {
            return Ok(address);
        }
        let address = (self.data_cursor + 7) & !7;
        let end = address
            .checked_add(bytes.len().max(8) as u64)
            .context("guest service data overflow")?;
        if end > SHIM_BASE + SHIM_SIZE {
            bail!("guest service data area is full");
        }
        self.data_cursor = end;
        self.symbols.insert(name.to_owned(), address);
        self.data.push((address, bytes.to_vec()));
        Ok(address)
    }

    fn allocate(&mut self, size: u64) -> Result<u64> {
        if size > MAX_TRANSFER {
            bail!("guest allocation exceeds transfer limit");
        }
        let reserved = size
            .max(1)
            .checked_add(15)
            .context("allocation size overflows")?
            & !15;
        if let Some(index) = self
            .free_blocks
            .iter()
            .position(|block| block.size >= reserved)
        {
            let block = &mut self.free_blocks[index];
            let address = block.address;
            block.address += reserved;
            block.size -= reserved;
            if block.size == 0 {
                self.free_blocks.remove(index);
            }
            self.allocations
                .insert(address, Allocation { size, reserved });
            return Ok(address);
        }
        if reserved > HEAP_SIZE.saturating_sub(self.heap_cursor) {
            bail!("guest heap exhausted");
        }
        let address = HEAP_BASE + self.heap_cursor;
        self.heap_cursor += reserved;
        self.allocations
            .insert(address, Allocation { size, reserved });
        Ok(address)
    }

    fn release(&mut self, context: &HookContext, address: u64) -> Result<()> {
        let allocation = self
            .allocations
            .get(&address)
            .copied()
            .with_context(|| format!("free unknown pointer {address:#x}"))?;
        context.mem_write(address, &vec![0; allocation.reserved as usize])?;
        self.allocations.remove(&address);
        self.free_blocks.push(FreeBlock {
            address,
            size: allocation.reserved,
        });
        self.free_blocks.sort_unstable_by_key(|block| block.address);
        let mut merged: Vec<FreeBlock> = Vec::new();
        for block in self.free_blocks.drain(..) {
            if let Some(last) = merged.last_mut()
                && last.address + last.size == block.address
            {
                last.size += block.size;
                continue;
            }
            merged.push(block);
        }
        while let Some(last) = merged.last() {
            if last.address + last.size != HEAP_BASE + self.heap_cursor {
                break;
            }
            self.heap_cursor -= last.size;
            merged.pop();
        }
        self.free_blocks = merged;
        Ok(())
    }
}

pub struct SapShims {
    state: Rc<RefCell<State>>,
    installed: bool,
}

impl SapShims {
    pub fn new() -> Result<Self> {
        let mut state = State::new();
        for &name in ZERO_ALIASES {
            state.function(name, Handler::Return(0))?;
        }
        for &name in FAKE_ALIASES {
            state.function(name, Handler::Return(FAKE_HANDLE))?;
        }
        for &name in MINUS_ONE_ALIASES {
            state.function(name, Handler::Return(u64::MAX))?;
        }
        for &name in MAX_U32_ALIASES {
            state.function(name, Handler::Return(u32::MAX as u64))?;
        }
        for &name in UNCHANGED_ALIASES {
            state.function(name, Handler::Unchanged)?;
        }
        state.function("_pthread_once", Handler::PthreadOnce)?;
        state.function("_dispatch_once", Handler::DispatchOnce)?;
        state.function("callback.complete", Handler::CallbackComplete)?;
        for (names, handler) in [
            (&["_malloc"][..], Handler::Malloc),
            (&["_malloc_good_size"][..], Handler::MallocGoodSize),
            (&["_malloc_size"][..], Handler::MallocSize),
            (&["_calloc"][..], Handler::Calloc),
            (&["_realloc", "_reallocf"][..], Handler::Realloc),
            (&["_free"][..], Handler::Free),
        ] {
            for &name in names {
                state.function(name, handler)?;
            }
        }
        state.function("_arc4random", Handler::Arc4random)?;
        state.function("___error", Handler::ErrorPointer)?;
        state.function("_gettimeofday", Handler::Gettimeofday)?;
        for name in ["_abort", "___stack_chk_fail", "dyld_stub_binder"] {
            state.function(name, Handler::Abort)?;
        }
        state.data("guest.errno", &[0; 8])?;
        state.data(
            "___stack_chk_guard",
            &[0xa5, 0x71, 0x3c, 0xd9, 0x86, 0x42, 0xef, 0x10],
        )?;
        for name in [
            "_kCFAllocatorDefault",
            "_kCFAllocatorNull",
            "_kDADiskDescriptionVolumeUUIDKey",
            "_kIOMasterPortDefault",
        ] {
            state.data(name, &[0; 8])?;
        }
        Ok(Self {
            state: Rc::new(RefCell::new(state)),
            installed: false,
        })
    }

    /// Attach one service-area hook. The entire code area contains RET stubs,
    /// so resolving a new import only changes the dispatch table.
    pub fn install(&mut self, engine: &mut Engine) -> Result<()> {
        if self.installed {
            bail!("SAP guest services are already installed");
        }
        engine
            .mem_map(SHIM_BASE, SHIM_SIZE as usize)
            .context("map SAP guest services")?;
        let mut code = vec![0; CODE_SIZE as usize];
        for slot in code.as_chunks_mut::<16>().0 {
            slot[..4].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
        }
        engine
            .mem_write(SHIM_BASE, &code)
            .context("write SAP guest service stubs")?;
        for (address, bytes) in &self.state.borrow().data {
            engine
                .mem_write(*address, bytes)
                .with_context(|| format!("write SAP guest service data at {address:#x}"))?;
        }
        let state = Rc::clone(&self.state);
        engine
            .add_code_hook(
                SHIM_BASE,
                SHIM_BASE + CODE_SIZE - 1,
                move |context, address, _| {
                    if let Err(error) = dispatch(context, &state, address) {
                        let mut state = state.borrow_mut();
                        if state.fault.is_none() {
                            state.fault = Some(error.to_string());
                        }
                        drop(state);
                        let _ = context.stop();
                    }
                },
            )
            .context("register SAP guest service dispatcher")?;
        self.installed = true;
        Ok(())
    }

    pub fn resolve(&mut self, name: &str) -> Result<u64> {
        self.state.borrow_mut().function(name, Handler::Unsupported)
    }

    pub fn take_fault(&mut self) -> Option<String> {
        self.state.borrow_mut().fault.take()
    }
}

fn dispatch(context: &HookContext, state: &Rc<RefCell<State>>, address: u64) -> Result<()> {
    let mut state = state.borrow_mut();
    let entry = state
        .entries
        .get(&address)
        .with_context(|| format!("guest entered unknown service address {address:#x}"))?;
    let handler = entry.handler;
    let name = entry.name.clone();
    match handler {
        Handler::Return(value) => context
            .reg_write(REG_X0, value)
            .with_context(|| format!("execute {name}")),
        Handler::Unchanged => Ok(()),
        Handler::PthreadOnce => {
            let control = context.reg_read(REG_X0)?;
            let initializer = context.reg_read(REG_X1)?;
            let value = read_u64(context, control)?;
            if value == 0 || value == 0x4f4e_4345 {
                return context.reg_write(REG_X0, 0);
            }
            context.mem_write(control, &0x4f4e_4345u64.to_le_bytes())?;
            invoke_callback(context, &mut state, initializer)
        }
        Handler::DispatchOnce => {
            let predicate = context.reg_read(REG_X0)?;
            let block = context.reg_read(REG_X1)?;
            if read_u64(context, predicate)? == u64::MAX {
                return context.reg_write(REG_X0, 0);
            }
            context.mem_write(predicate, &u64::MAX.to_le_bytes())?;
            let initializer = read_u64(
                context,
                block.checked_add(16).context("dispatch block overflows")?,
            )?;
            context.reg_write(REG_X0, block)?;
            invoke_callback(context, &mut state, initializer)
        }
        Handler::CallbackComplete => {
            let return_address = state
                .callback_returns
                .pop()
                .context("guest callback has no return address")?;
            context.reg_write(REG_LR, return_address)?;
            context.reg_write(REG_X0, 0)
        }
        Handler::Malloc => {
            let size = context.reg_read(REG_X0)?;
            context.reg_write(REG_X0, state.allocate(size)?)
        }
        Handler::MallocGoodSize => {
            let size = context.reg_read(REG_X0)?.max(1);
            let rounded = size.checked_add(15).context("malloc good size overflows")? & !15;
            context.reg_write(REG_X0, rounded)
        }
        Handler::MallocSize => {
            let address = context.reg_read(REG_X0)?;
            let size = state
                .allocations
                .get(&address)
                .map_or(0, |allocation| allocation.reserved);
            context.reg_write(REG_X0, size)
        }
        Handler::Calloc => {
            let count = context.reg_read(REG_X0)?;
            let item_size = context.reg_read(REG_X1)?;
            let size = count
                .checked_mul(item_size)
                .context("calloc size overflows")?;
            let address = state.allocate(size)?;
            if size != 0
                && let Err(error) = context.mem_write(address, &vec![0; size as usize])
            {
                let _ = state.release(context, address);
                return Err(error);
            }
            context.reg_write(REG_X0, address)
        }
        Handler::Realloc => {
            let old = context.reg_read(REG_X0)?;
            let size = context.reg_read(REG_X1)?;
            if old == 0 {
                return context.reg_write(REG_X0, state.allocate(size)?);
            }
            let previous = state
                .allocations
                .get(&old)
                .copied()
                .with_context(|| format!("reallocate unknown pointer {old:#x}"))?;
            if size <= previous.reserved {
                state
                    .allocations
                    .get_mut(&old)
                    .expect("checked allocation")
                    .size = size;
                return context.reg_write(REG_X0, old);
            }
            let address = state.allocate(size)?;
            let bytes = context.mem_read(old, previous.size as usize)?;
            if let Err(error) = context.mem_write(address, &bytes) {
                let _ = state.release(context, address);
                return Err(error);
            }
            state.release(context, old)?;
            context.reg_write(REG_X0, address)
        }
        Handler::Free => {
            let address = context.reg_read(REG_X0)?;
            if address != 0 {
                state.release(context, address)?;
            }
            context.reg_write(REG_X0, 0)
        }
        Handler::Arc4random => {
            let mut bytes = [0u8; 4];
            getrandom::fill(&mut bytes).context("generate guest random value")?;
            context.reg_write(REG_X0, u32::from_le_bytes(bytes) as u64)
        }
        Handler::ErrorPointer => context.reg_write(REG_X0, state.symbols["guest.errno"]),
        Handler::Abort => bail!("guest aborted via {name}"),
        Handler::Gettimeofday => {
            let time_address = context.reg_read(REG_X0)?;
            let zone_address = context.reg_read(REG_X1)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("guest clock precedes Unix epoch")?;
            if time_address != 0 {
                let mut value = [0u8; 16];
                value[..8].copy_from_slice(&now.as_secs().to_le_bytes());
                value[8..12].copy_from_slice(&now.subsec_micros().to_le_bytes());
                context.mem_write(time_address, &value)?;
            }
            if zone_address != 0 {
                context.mem_write(zone_address, &[0; 8])?;
            }
            context.reg_write(REG_X0, 0)
        }
        Handler::Unsupported => bail!("guest called unsupported import {name}"),
    }
}

fn read_u64(context: &HookContext, address: u64) -> Result<u64> {
    let bytes = context.mem_read(address, 8)?;
    Ok(u64::from_le_bytes(
        bytes.as_slice().try_into().expect("eight bytes"),
    ))
}

fn invoke_callback(context: &HookContext, state: &mut State, initializer: u64) -> Result<()> {
    let return_address = context.reg_read(REG_LR)?;
    let completion = state.symbols["callback.complete"];
    state.callback_returns.push(return_address);
    context.reg_write(REG_LR, completion)?;
    context.reg_write(REG_PC, initializer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sap_machine::GuestMachine;

    #[test]
    fn aliases_and_dynamic_imports_have_stable_slots() {
        let mut shims = SapShims::new().unwrap();
        let first = shims.resolve("_CFRelease").unwrap();
        assert_eq!(first, shims.resolve("_CFRelease").unwrap());
        assert_eq!(
            shims.state.borrow().entries[&first].handler,
            Handler::Return(0)
        );
        let missing = shims.resolve("_missing").unwrap();
        assert_eq!(missing, shims.resolve("_missing").unwrap());
        assert_eq!(
            shims.state.borrow().entries[&missing].handler,
            Handler::Unsupported
        );
        assert!((SHIM_BASE..SHIM_BASE + CODE_SIZE).contains(&missing));
        assert!(shims.resolve("___stack_chk_guard").unwrap() >= SHIM_BASE + CODE_SIZE);
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn dispatches_service_results_and_reports_unsupported_imports() {
        let mut machine = GuestMachine::new().unwrap();
        let mut shims = SapShims::new().unwrap();
        shims.install(machine.engine()).unwrap();
        let zero = shims.resolve("_CFRelease").unwrap();
        assert_eq!(machine.invoke(zero, &[123]).unwrap(), 0);
        let unchanged = shims.resolve("___chkstk_darwin").unwrap();
        assert_eq!(machine.invoke(unchanged, &[123]).unwrap(), 123);
        let malloc = shims.resolve("_malloc").unwrap();
        let malloc_size = shims.resolve("_malloc_size").unwrap();
        let free = shims.resolve("_free").unwrap();
        let pointer = machine.invoke(malloc, &[24]).unwrap();
        assert_eq!(pointer, HEAP_BASE);
        assert_eq!(machine.invoke(malloc_size, &[pointer]).unwrap(), 32);
        machine.engine().mem_write(pointer, &[1, 2, 3, 4]).unwrap();
        assert_eq!(machine.invoke(free, &[pointer]).unwrap(), 0);
        assert_eq!(machine.engine().mem_read(pointer, 4).unwrap(), &[0; 4]);
        assert_eq!(machine.invoke(malloc, &[24]).unwrap(), pointer);
        let unsupported = shims.resolve("_unknown").unwrap();
        assert!(machine.invoke(unsupported, &[]).is_err());
        assert!(shims.take_fault().unwrap().contains("_unknown"));
    }
}
