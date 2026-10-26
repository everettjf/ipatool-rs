//! Typed ARM64 Unicorn operations over the pinned dynamic library.

use std::{
    cell::RefCell,
    ffi::{CStr, c_char, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
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
    stop: unsafe extern "C" fn(Handle) -> i32,
}

impl HookContext {
    pub fn stop(&self) -> Result<()> {
        let code = unsafe { (self.stop)(self.handle) };
        if code == 0 {
            Ok(())
        } else {
            bail!("failed to stop Unicorn emulator: error {code}")
        }
    }
}

type CodeCallback = dyn FnMut(&HookContext, u64, u32);

struct HookData {
    callback: RefCell<Box<CodeCallback>>,
    failure: RefCell<Option<String>>,
    stop: unsafe extern "C" fn(Handle) -> i32,
}

struct HookRegistration {
    id: u64,
    handle: usize,
    _data: Box<HookData>,
}

extern "C" fn code_trampoline(handle: Handle, address: u64, size: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    let data = unsafe { &*user_data.cast::<HookData>() };
    let context = HookContext {
        handle,
        stop: data.stop,
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Ok(mut callback) = data.callback.try_borrow_mut() else {
            panic!("reentrant Unicorn code hook");
        };
        callback(&context, address, size);
    }));
    if result.is_err() {
        *data.failure.borrow_mut() = Some("Unicorn code hook panicked".to_owned());
        unsafe { (data.stop)(handle) };
    }
}

pub struct Engine {
    api: Api,
    handle: Handle,
    _library: UnicornLibrary,
    hooks: Vec<HookRegistration>,
    next_hook_id: u64,
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
        let micros = u64::try_from(timeout.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        let result = self.check(unsafe {
            (self.api.emu_start)(self.handle, begin, end, micros, instruction_limit)
        });
        if let Some(failure) = self
            .hooks
            .iter()
            .find_map(|hook| hook._data.failure.borrow().clone())
        {
            bail!("{failure}");
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
            stop: self.api.emu_stop,
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
            _data: data,
        });
        Ok(id)
    }

    pub fn remove_hook(&mut self, id: u64) -> Result<()> {
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
}
