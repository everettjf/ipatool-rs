//! Typed ARM64 Unicorn operations over the pinned dynamic library.

use std::{
    cell::RefCell,
    error::Error as StdError,
    ffi::{CStr, c_char, c_void},
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};

use super::UnicornLibrary;

pub const REG_X0: i32 = 199;
pub const REG_X1: i32 = 200;
pub const REG_PC: i32 = 260;
const ARM64: i32 = 2;
const MODE_ARM: i32 = 0;
const PROT_ALL: u32 = 7;
const QUERY_TIMEOUT: i32 = 4;
const CONTROL_CPU_MODEL: u32 = 7 | 1 << 26 | 1 << 30;
const ARM64_CPU_MODEL_MAX: u32 = 3;
const HOOK_CODE: i32 = 1 << 2;
const HOOK_UNMAPPED_MEMORY: i32 = 1 << 4 | 1 << 5 | 1 << 6;
const HOOK_MEMORY_ACCESS: i32 = 1 << 10 | 1 << 11;

type Handle = *mut c_void;

struct Api {
    open: unsafe extern "C" fn(i32, i32, *mut Handle) -> i32,
    close: unsafe extern "C" fn(Handle) -> i32,
    control: unsafe extern "C" fn(Handle, u32, ...) -> i32,
    query: unsafe extern "C" fn(Handle, i32, *mut u64) -> i32,
    strerror: unsafe extern "C" fn(i32) -> *const c_char,
    mem_map: unsafe extern "C" fn(Handle, u64, usize, u32) -> i32,
    mem_unmap: unsafe extern "C" fn(Handle, u64, usize) -> i32,
    mem_read: unsafe extern "C" fn(Handle, u64, *mut c_void, usize) -> i32,
    mem_write: unsafe extern "C" fn(Handle, u64, *const c_void, usize) -> i32,
    reg_read: unsafe extern "C" fn(Handle, i32, *mut c_void) -> i32,
    reg_write: unsafe extern "C" fn(Handle, i32, *const c_void) -> i32,
    emu_start: unsafe extern "C" fn(Handle, u64, u64, u64, usize) -> i32,
    emu_stop: unsafe extern "C" fn(Handle) -> i32,
    hook_add: unsafe extern "C" fn(
        Handle,
        *mut usize,
        i32,
        *mut c_void,
        *mut c_void,
        u64,
        u64,
        ...
    ) -> i32,
    hook_del: unsafe extern "C" fn(Handle, usize) -> i32,
}

impl Api {
    fn load(library: &UnicornLibrary) -> Result<Self> {
        unsafe fn symbol<T: Copy>(library: &UnicornLibrary, name: &[u8]) -> Result<T> {
            let symbol = unsafe { library.library.get::<T>(name) }.with_context(|| {
                format!(
                    "Unicorn library is missing {}",
                    String::from_utf8_lossy(name)
                )
            })?;
            Ok(*symbol)
        }
        Ok(Self {
            open: unsafe { symbol(library, b"uc_open")? },
            close: unsafe { symbol(library, b"uc_close")? },
            control: unsafe { symbol(library, b"uc_ctl")? },
            query: unsafe { symbol(library, b"uc_query")? },
            strerror: unsafe { symbol(library, b"uc_strerror")? },
            mem_map: unsafe { symbol(library, b"uc_mem_map")? },
            mem_unmap: unsafe { symbol(library, b"uc_mem_unmap")? },
            mem_read: unsafe { symbol(library, b"uc_mem_read")? },
            mem_write: unsafe { symbol(library, b"uc_mem_write")? },
            reg_read: unsafe { symbol(library, b"uc_reg_read")? },
            reg_write: unsafe { symbol(library, b"uc_reg_write")? },
            emu_start: unsafe { symbol(library, b"uc_emu_start")? },
            emu_stop: unsafe { symbol(library, b"uc_emu_stop")? },
            hook_add: unsafe { symbol(library, b"uc_hook_add")? },
            hook_del: unsafe { symbol(library, b"uc_hook_del")? },
        })
    }
}

pub struct HookContext {
    handle: Handle,
    operations: HookOperations,
}

impl HookContext {
    pub fn stop(&self) -> Result<()> {
        let code = unsafe { (self.operations.stop)(self.handle) };
        if code == 0 {
            Ok(())
        } else {
            bail!("failed to stop Unicorn emulator: error {code}")
        }
    }

    pub fn mem_map(&self, address: u64, size: usize) -> Result<()> {
        let code = unsafe { (self.operations.mem_map)(self.handle, address, size, PROT_ALL) };
        if code == 0 {
            Ok(())
        } else {
            bail!("failed to map Unicorn memory: error {code}")
        }
    }

    pub fn mem_write(&self, address: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.check_memory(address, data.len())?;
        let code = unsafe {
            (self.operations.mem_write)(self.handle, address, data.as_ptr().cast(), data.len())
        };
        if code == 0 {
            Ok(())
        } else {
            bail!("failed to write Unicorn memory: error {code}")
        }
    }

    pub fn mem_read(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        self.check_memory(address, size)?;
        let mut data = vec![0u8; size];
        if size != 0 {
            let code = unsafe {
                (self.operations.mem_read)(self.handle, address, data.as_mut_ptr().cast(), size)
            };
            if code != 0 {
                bail!("failed to read Unicorn memory: error {code}");
            }
        }
        Ok(data)
    }

    pub fn reg_read(&self, register: i32) -> Result<u64> {
        let mut value = 0u64;
        let code = unsafe {
            (self.operations.reg_read)(self.handle, register, (&mut value as *mut u64).cast())
        };
        if code == 0 {
            Ok(value)
        } else {
            bail!("failed to read Unicorn register {register}: error {code}")
        }
    }

    pub fn reg_write(&self, register: i32, value: u64) -> Result<()> {
        let code = unsafe {
            (self.operations.reg_write)(self.handle, register, (&value as *const u64).cast())
        };
        if code == 0 {
            Ok(())
        } else {
            bail!("failed to write Unicorn register {register}: error {code}")
        }
    }

    pub fn reg_read_128(&self, register: i32) -> Result<[u8; 16]> {
        let mut value = [0u8; 16];
        let code =
            unsafe { (self.operations.reg_read)(self.handle, register, value.as_mut_ptr().cast()) };
        if code == 0 {
            Ok(value)
        } else {
            bail!("failed to read Unicorn register {register}: error {code}")
        }
    }

    pub fn reg_write_128(&self, register: i32, value: [u8; 16]) -> Result<()> {
        let code =
            unsafe { (self.operations.reg_write)(self.handle, register, value.as_ptr().cast()) };
        if code == 0 {
            Ok(())
        } else {
            bail!("failed to write Unicorn register {register}: error {code}")
        }
    }

    fn check_memory(&self, address: u64, size: usize) -> Result<()> {
        if size != 0 {
            let check = self.operations.guard_slot.borrow().clone();
            if let Some(check) = check {
                check(address, size as u64)?;
            }
        }
        Ok(())
    }
}

type CodeCallback = dyn FnMut(&HookContext, u64, u32);
type FaultCallback = dyn FnMut(&HookContext, u64, u32) -> bool;

type GuardCheck = Rc<dyn Fn(u64, u64) -> Result<()>>;
type GuardSlot = Rc<RefCell<Option<GuardCheck>>>;

#[derive(Clone)]
struct HookOperations {
    stop: unsafe extern "C" fn(Handle) -> i32,
    mem_map: unsafe extern "C" fn(Handle, u64, usize, u32) -> i32,
    mem_read: unsafe extern "C" fn(Handle, u64, *mut c_void, usize) -> i32,
    mem_write: unsafe extern "C" fn(Handle, u64, *const c_void, usize) -> i32,
    reg_read: unsafe extern "C" fn(Handle, i32, *mut c_void) -> i32,
    reg_write: unsafe extern "C" fn(Handle, i32, *const c_void) -> i32,
    guard_slot: GuardSlot,
}

struct HookData {
    callback: RefCell<Box<CodeCallback>>,
    failure: RefCell<Option<String>>,
    operations: HookOperations,
}

struct MemoryFaultData {
    callback: RefCell<Box<FaultCallback>>,
    failure: RefCell<Option<String>>,
    operations: HookOperations,
}

struct MemoryAccessData {
    callback: RefCell<Box<CodeCallback>>,
    failure: RefCell<Option<String>>,
    operations: HookOperations,
}

enum HookOwner {
    Code(Box<HookData>),
    Fault(Box<MemoryFaultData>),
    Access(Box<MemoryAccessData>),
}

impl HookOwner {
    fn failure(&self) -> Option<String> {
        match self {
            Self::Code(data) => data.failure.borrow().clone(),
            Self::Fault(data) => data.failure.borrow().clone(),
            Self::Access(data) => data.failure.borrow().clone(),
        }
    }
}

#[derive(Clone)]
struct GuardError(Arc<anyhow::Error>);

impl fmt::Display for GuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#}", self.0)
    }
}

impl fmt::Debug for GuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl StdError for GuardError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

struct MemoryGuard {
    check: GuardCheck,
    failure: Rc<RefCell<Option<GuardError>>>,
    access_hook_id: u64,
    code_hook_id: u64,
}

fn guard_callback(
    check: Rc<dyn Fn(u64, u64) -> Result<()>>,
    failure: Rc<RefCell<Option<GuardError>>>,
) -> impl FnMut(&HookContext, u64, u32) {
    move |context, address, size| {
        if failure.borrow().is_some() {
            let _ = context.stop();
            return;
        }
        if let Err(error) = check(address, u64::from(size)) {
            *failure.borrow_mut() = Some(GuardError(Arc::new(error)));
            let _ = context.stop();
        }
    }
}

struct HookRegistration {
    id: u64,
    handle: usize,
    data: HookOwner,
}

extern "C" fn code_trampoline(handle: Handle, address: u64, size: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    let data = unsafe { &*user_data.cast::<HookData>() };
    let context = HookContext {
        handle,
        operations: data.operations.clone(),
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Ok(mut callback) = data.callback.try_borrow_mut() else {
            panic!("reentrant Unicorn code hook");
        };
        callback(&context, address, size);
    }));
    if result.is_err() {
        *data.failure.borrow_mut() = Some("Unicorn code hook panicked".to_owned());
        unsafe { (data.operations.stop)(handle) };
    }
}

extern "C" fn fault_trampoline(
    handle: Handle,
    _kind: i32,
    address: u64,
    size: i32,
    _value: i64,
    user_data: *mut c_void,
) -> bool {
    if user_data.is_null() {
        return false;
    }
    let data = unsafe { &*user_data.cast::<MemoryFaultData>() };
    let context = HookContext {
        handle,
        operations: data.operations.clone(),
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Ok(mut callback) = data.callback.try_borrow_mut() else {
            panic!("reentrant Unicorn memory fault hook");
        };
        callback(&context, address, size.max(0) as u32)
    }));
    match result {
        Ok(retry) => retry,
        Err(_) => {
            *data.failure.borrow_mut() = Some("Unicorn memory fault hook panicked".to_owned());
            unsafe { (data.operations.stop)(handle) };
            false
        }
    }
}

extern "C" fn access_trampoline(
    handle: Handle,
    _kind: i32,
    address: u64,
    size: i32,
    _value: i64,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    let data = unsafe { &*user_data.cast::<MemoryAccessData>() };
    let context = HookContext {
        handle,
        operations: data.operations.clone(),
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Ok(mut callback) = data.callback.try_borrow_mut() else {
            panic!("reentrant Unicorn memory access hook");
        };
        callback(&context, address, size.max(0) as u32);
    }));
    if result.is_err() {
        *data.failure.borrow_mut() = Some("Unicorn memory access hook panicked".to_owned());
        unsafe { (data.operations.stop)(handle) };
    }
}

pub struct Engine {
    api: Api,
    handle: Handle,
    _library: UnicornLibrary,
    hooks: Vec<HookRegistration>,
    next_hook_id: u64,
    memory_guard: Option<MemoryGuard>,
    guard_slot: GuardSlot,
}

impl Engine {
    pub fn new() -> Result<Self> {
        let library = super::load()?;
        let api = Api::load(&library)?;
        let mut handle = ptr::null_mut();
        let code = unsafe { (api.open)(ARM64, MODE_ARM, &mut handle) };
        if code != 0 {
            return Err(api_error(&api, code)).context("failed to create ARM64 emulator");
        }
        let mut engine = Self {
            api,
            handle,
            _library: library,
            hooks: Vec::new(),
            next_hook_id: 1,
            memory_guard: None,
            guard_slot: Rc::new(RefCell::new(None)),
        };
        let code = unsafe { (engine.api.control)(handle, CONTROL_CPU_MODEL, ARM64_CPU_MODEL_MAX) };
        if let Err(error) = engine.check(code) {
            engine.close_handle();
            return Err(error).context("failed to configure ARM64 CPU model");
        }
        Ok(engine)
    }

    pub fn mem_map(&mut self, address: u64, size: usize) -> Result<()> {
        self.check(unsafe { (self.api.mem_map)(self.handle, address, size, PROT_ALL) })
    }

    pub fn mem_unmap(&mut self, address: u64, size: usize) -> Result<()> {
        self.check(unsafe { (self.api.mem_unmap)(self.handle, address, size) })
    }

    pub fn mem_read(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        self.check_memory(address, size)?;
        let mut data = vec![0; size];
        if size != 0 {
            self.check(unsafe {
                (self.api.mem_read)(self.handle, address, data.as_mut_ptr().cast(), size)
            })?;
        }
        Ok(data)
    }

    pub fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.check_memory(address, data.len())?;
        self.check(unsafe {
            (self.api.mem_write)(self.handle, address, data.as_ptr().cast(), data.len())
        })
    }

    pub fn reg_read(&self, register: i32) -> Result<u64> {
        let mut value = 0u64;
        self.check(unsafe {
            (self.api.reg_read)(self.handle, register, (&mut value as *mut u64).cast())
        })?;
        Ok(value)
    }

    pub fn reg_write(&mut self, register: i32, value: u64) -> Result<()> {
        self.check(unsafe {
            (self.api.reg_write)(self.handle, register, (&value as *const u64).cast())
        })
    }

    pub fn reg_read_128(&self, register: i32) -> Result<[u8; 16]> {
        let mut value = [0u8; 16];
        self.check(unsafe {
            (self.api.reg_read)(self.handle, register, value.as_mut_ptr().cast())
        })?;
        Ok(value)
    }

    pub fn reg_write_128(&mut self, register: i32, value: [u8; 16]) -> Result<()> {
        self.check(unsafe { (self.api.reg_write)(self.handle, register, value.as_ptr().cast()) })
    }

    pub fn start_bounded(
        &mut self,
        begin: u64,
        end: u64,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<()> {
        if timeout.is_zero() {
            bail!("Unicorn timeout must be positive");
        }
        if let Some(failure) = self.guard_failure() {
            return Err(anyhow::Error::new(failure));
        }
        let micros = u64::try_from(timeout.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        let result = self.check(unsafe {
            (self.api.emu_start)(self.handle, begin, end, micros, instruction_limit)
        });
        if let Some(failure) = self.hooks.iter().find_map(|hook| hook.data.failure()) {
            bail!("{failure}");
        }
        if let Some(failure) = self.guard_failure() {
            return Err(anyhow::Error::new(failure));
        }
        result?;
        let mut timed_out = 0u64;
        self.check(unsafe { (self.api.query)(self.handle, QUERY_TIMEOUT, &mut timed_out) })?;
        if timed_out != 0 {
            bail!("Unicorn emulation timed out after {timeout:?}");
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.check(unsafe { (self.api.emu_stop)(self.handle) })
    }

    pub fn add_code_hook<F>(&mut self, begin: u64, end: u64, callback: F) -> Result<u64>
    where
        F: FnMut(&HookContext, u64, u32) + 'static,
    {
        let id = self.next_hook_id;
        let next_id = id.checked_add(1).context("Unicorn hook ID overflow")?;
        let data = Box::new(HookData {
            callback: RefCell::new(Box::new(callback)),
            failure: RefCell::new(None),
            operations: self.hook_operations(),
        });
        let mut hook_handle = 0usize;
        let user_data = (&*data as *const HookData).cast_mut().cast::<c_void>();
        let trampoline = code_trampoline as *const () as *mut c_void;
        self.check(unsafe {
            (self.api.hook_add)(
                self.handle,
                &mut hook_handle,
                HOOK_CODE,
                trampoline,
                user_data,
                begin,
                end,
            )
        })?;
        self.next_hook_id = next_id;
        self.hooks.push(HookRegistration {
            id,
            handle: hook_handle,
            data: HookOwner::Code(data),
        });
        Ok(id)
    }

    pub fn add_memory_fault_hook<F>(&mut self, callback: F) -> Result<u64>
    where
        F: FnMut(&HookContext, u64, u32) -> bool + 'static,
    {
        let id = self.next_hook_id;
        let next_id = id.checked_add(1).context("Unicorn hook ID overflow")?;
        let data = Box::new(MemoryFaultData {
            callback: RefCell::new(Box::new(callback)),
            failure: RefCell::new(None),
            operations: self.hook_operations(),
        });
        let mut hook_handle = 0usize;
        let user_data = (&*data as *const MemoryFaultData)
            .cast_mut()
            .cast::<c_void>();
        let trampoline = fault_trampoline as *const () as *mut c_void;
        self.check(unsafe {
            (self.api.hook_add)(
                self.handle,
                &mut hook_handle,
                HOOK_UNMAPPED_MEMORY,
                trampoline,
                user_data,
                1,
                0,
            )
        })?;
        self.next_hook_id = next_id;
        self.hooks.push(HookRegistration {
            id,
            handle: hook_handle,
            data: HookOwner::Fault(data),
        });
        Ok(id)
    }

    fn add_memory_access_hook<F>(&mut self, callback: F) -> Result<u64>
    where
        F: FnMut(&HookContext, u64, u32) + 'static,
    {
        let id = self.next_hook_id;
        let next_id = id.checked_add(1).context("Unicorn hook ID overflow")?;
        let data = Box::new(MemoryAccessData {
            callback: RefCell::new(Box::new(callback)),
            failure: RefCell::new(None),
            operations: self.hook_operations(),
        });
        let mut hook_handle = 0usize;
        let user_data = (&*data as *const MemoryAccessData)
            .cast_mut()
            .cast::<c_void>();
        let trampoline = access_trampoline as *const () as *mut c_void;
        self.check(unsafe {
            (self.api.hook_add)(
                self.handle,
                &mut hook_handle,
                HOOK_MEMORY_ACCESS,
                trampoline,
                user_data,
                1,
                0,
            )
        })?;
        self.next_hook_id = next_id;
        self.hooks.push(HookRegistration {
            id,
            handle: hook_handle,
            data: HookOwner::Access(data),
        });
        Ok(id)
    }

    pub fn guard_memory<F>(&mut self, check: F) -> Result<()>
    where
        F: Fn(u64, u64) -> Result<()> + 'static,
    {
        if self.memory_guard.is_some() {
            bail!("Unicorn memory validator is already installed");
        }
        let check: GuardCheck = Rc::new(check);
        let failure = Rc::new(RefCell::new(None));
        let access_id =
            self.add_memory_access_hook(guard_callback(Rc::clone(&check), Rc::clone(&failure)))?;
        let code_id = match self.add_code_hook(
            1,
            0,
            guard_callback(Rc::clone(&check), Rc::clone(&failure)),
        ) {
            Ok(id) => id,
            Err(error) => {
                let _ = self.remove_hook(access_id);
                return Err(error);
            }
        };
        self.memory_guard = Some(MemoryGuard {
            check: Rc::clone(&check),
            failure,
            access_hook_id: access_id,
            code_hook_id: code_id,
        });
        *self.guard_slot.borrow_mut() = Some(Rc::clone(&check));
        Ok(())
    }

    pub fn remove_hook(&mut self, id: u64) -> Result<()> {
        if self
            .memory_guard
            .as_ref()
            .is_some_and(|guard| id == guard.access_hook_id || id == guard.code_hook_id)
        {
            bail!("cannot remove an active Unicorn memory guard hook");
        }
        let position = self
            .hooks
            .iter()
            .position(|hook| hook.id == id)
            .context("Unicorn hook not found")?;
        self.check(unsafe { (self.api.hook_del)(self.handle, self.hooks[position].handle) })?;
        self.hooks.remove(position);
        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        self.remove_all_hooks();
        let handle = std::mem::replace(&mut self.handle, ptr::null_mut());
        self.check(unsafe { (self.api.close)(handle) })
    }

    fn check(&self, code: i32) -> Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(api_error(&self.api, code))
        }
    }

    fn check_memory(&self, address: u64, size: usize) -> Result<()> {
        if size != 0
            && let Some(guard) = &self.memory_guard
        {
            (guard.check)(address, size as u64)?;
        }
        Ok(())
    }

    fn guard_failure(&self) -> Option<GuardError> {
        self.memory_guard.as_ref()?.failure.borrow().clone()
    }

    fn hook_operations(&self) -> HookOperations {
        HookOperations {
            stop: self.api.emu_stop,
            mem_map: self.api.mem_map,
            mem_read: self.api.mem_read,
            mem_write: self.api.mem_write,
            reg_read: self.api.reg_read,
            reg_write: self.api.reg_write,
            guard_slot: Rc::clone(&self.guard_slot),
        }
    }

    fn close_handle(&mut self) {
        if !self.handle.is_null() {
            self.remove_all_hooks();
            let handle = std::mem::replace(&mut self.handle, ptr::null_mut());
            unsafe { (self.api.close)(handle) };
        }
    }

    fn remove_all_hooks(&mut self) {
        for hook in self.hooks.drain(..) {
            unsafe { (self.api.hook_del)(self.handle, hook.handle) };
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.close_handle();
    }
}

fn api_error(api: &Api, code: i32) -> anyhow::Error {
    let pointer = unsafe { (api.strerror)(code) };
    let message = if pointer.is_null() {
        "unknown".into()
    } else {
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    };
    anyhow::anyhow!("Unicorn error {code}: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    const REG_V0: i32 = 228;

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn code_hook_stops_and_can_be_removed() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        engine
            .mem_write(0x1000, &[0x20, 0x00, 0x80, 0xd2, 0x00, 0x04, 0x00, 0x91])
            .unwrap();
        let calls = Rc::new(Cell::new(0));
        let observed = Rc::clone(&calls);
        let hook = engine
            .add_code_hook(0x1004, 0x1004, move |context, address, size| {
                assert_eq!((address, size), (0x1004, 4));
                observed.set(observed.get() + 1);
                context.stop().unwrap();
            })
            .unwrap();
        engine
            .start_bounded(0x1000, 0x1008, Duration::from_secs(1), 10)
            .unwrap();
        assert_eq!(engine.reg_read(REG_X0).unwrap(), 1);
        assert_eq!(calls.get(), 1);
        engine.remove_hook(hook).unwrap();
        engine.reg_write(REG_X0, 0).unwrap();
        engine
            .start_bounded(0x1000, 0x1008, Duration::from_secs(1), 10)
            .unwrap();
        assert_eq!(engine.reg_read(REG_X0).unwrap(), 2);
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn memory_fault_hook_maps_and_retries_missing_page() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        engine.mem_write(0x1000, &[0x20, 0x00, 0x40, 0xf9]).unwrap();
        engine.reg_write(REG_X1, 0x2000).unwrap();
        let calls = Rc::new(Cell::new(0));
        let observed = Rc::clone(&calls);
        engine
            .add_memory_fault_hook(move |context, address, size| {
                assert_eq!((address, size), (0x2000, 8));
                observed.set(observed.get() + 1);
                context.mem_map(0x2000, 4096).unwrap();
                context.mem_write(0x2000, &42u64.to_le_bytes()).unwrap();
                true
            })
            .unwrap();
        engine
            .start_bounded(0x1000, 0x1004, Duration::from_secs(1), 10)
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(engine.reg_read(REG_X0).unwrap(), 42);
    }

    #[derive(Debug)]
    struct MissingPage;

    impl fmt::Display for MissingPage {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "missing dependency")
        }
    }

    impl StdError for MissingPage {}

    fn is_missing_page(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| cause.is::<MissingPage>())
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn memory_guard_checks_host_guest_and_sticky_failures() {
        let mut engine = Engine::new().unwrap();
        let base = 0x6000000u64;
        engine.mem_map(base, 3 * 4096).unwrap();
        engine.mem_write(base, &[0x20, 0x00, 0x40, 0xf9]).unwrap();
        engine.reg_write(REG_X1, base + 4096).unwrap();
        engine
            .guard_memory(move |address, size| {
                if size > 0 && address < base + 8192 && address + size > base + 4096 {
                    return Err(MissingPage.into());
                }
                Ok(())
            })
            .unwrap();
        assert!(is_missing_page(
            &engine.mem_read(base + 4092, 8).unwrap_err()
        ));
        assert!(is_missing_page(
            &engine.mem_write(base + 4092, &[0; 8]).unwrap_err()
        ));
        assert!(is_missing_page(
            &engine
                .start_bounded(base, base + 4, Duration::from_secs(1), 10)
                .unwrap_err()
        ));
        assert!(is_missing_page(
            &engine
                .start_bounded(base, base + 4, Duration::from_secs(1), 10)
                .unwrap_err()
        ));
        assert!(engine.guard_memory(|_, _| Ok(())).is_err());
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn memory_guard_checks_cached_instruction_fetch() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        engine.mem_write(0x1000, &[0xe0, 0x00, 0x80, 0xd2]).unwrap();
        let allowed = Rc::new(Cell::new(true));
        let observed = Rc::clone(&allowed);
        engine
            .guard_memory(move |_, _| {
                if observed.get() {
                    Ok(())
                } else {
                    Err(MissingPage.into())
                }
            })
            .unwrap();
        engine
            .start_bounded(0x1000, 0x1004, Duration::from_secs(1), 10)
            .unwrap();
        allowed.set(false);
        engine.reg_write(REG_X0, 0).unwrap();
        assert!(is_missing_page(
            &engine
                .start_bounded(0x1000, 0x1004, Duration::from_secs(1), 10)
                .unwrap_err()
        ));
        assert_eq!(engine.reg_read(REG_X0).unwrap(), 0);
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn hook_context_memory_access_obeys_guard() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        engine.mem_map(0x2000, 4096).unwrap();
        engine.mem_write(0x1000, &[0x1f, 0x20, 0x03, 0xd5]).unwrap();
        let allow_data = Rc::new(Cell::new(false));
        let allowed = Rc::clone(&allow_data);
        engine
            .guard_memory(move |address, size| {
                if size != 0 && address < 0x3000 && address + size > 0x2000 && !allowed.get() {
                    return Err(MissingPage.into());
                }
                Ok(())
            })
            .unwrap();
        let denied = Rc::new(Cell::new(0));
        let observed = Rc::clone(&denied);
        engine
            .add_code_hook(0x1000, 0x1000, move |context, _, _| {
                if is_missing_page(&context.mem_read(0x2000, 1).unwrap_err()) {
                    observed.set(observed.get() + 1);
                }
                if is_missing_page(&context.mem_write(0x2000, &[42]).unwrap_err()) {
                    observed.set(observed.get() + 1);
                }
                context.stop().unwrap();
            })
            .unwrap();
        engine
            .start_bounded(0x1000, 0x1004, Duration::from_secs(1), 10)
            .unwrap();
        assert_eq!(denied.get(), 2);
        allow_data.set(true);
        assert_eq!(engine.mem_read(0x2000, 1).unwrap(), [0]);
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn hook_context_can_read_and_write_guest_registers() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        engine
            .mem_write(0x1000, &[0x20, 0x00, 0x80, 0xd2, 0x00, 0x04, 0x00, 0x91])
            .unwrap();
        engine
            .add_code_hook(0x1004, 0x1004, |context, _, _| {
                assert_eq!(context.reg_read(REG_X0).unwrap(), 1);
                context.reg_write(REG_X0, 7).unwrap();
                let vector = [0xa5; 16];
                context.reg_write_128(REG_V0, vector).unwrap();
                assert_eq!(context.reg_read_128(REG_V0).unwrap(), vector);
                context.stop().unwrap();
            })
            .unwrap();
        engine
            .start_bounded(0x1000, 0x1008, Duration::from_secs(1), 10)
            .unwrap();
        assert_eq!(engine.reg_read(REG_X0).unwrap(), 7);
    }
}
