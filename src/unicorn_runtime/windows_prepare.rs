//! Prepare the pinned Windows Unicorn DLL before invoking its JIT.
//!
//! The 2.1.4 MinGW DLL needs the same VirtualAlloc and longjmp compatibility
//! fixes as the Go implementation. Only the checksum-pinned DLL is loaded.

use std::{
    ffi::c_void,
    path::Path,
    ptr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use libloading::Library;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
#[cfg(target_arch = "x86_64")]
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;
#[cfg(target_arch = "x86_64")]
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

static PREPARE_LOCK: Mutex<()> = Mutex::new(());
static ORIGINAL_VIRTUAL_ALLOC: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static LONGJMP_ADDRESS: AtomicUsize = AtomicUsize::new(0);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualProtect(address: *mut c_void, size: usize, protection: u32, old: *mut u32) -> i32;
    #[cfg(target_arch = "x86_64")]
    fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
    #[cfg(target_arch = "x86_64")]
    fn GetCurrentProcess() -> *mut c_void;
    #[cfg(target_arch = "x86_64")]
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
}

type VirtualAllocFn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;

pub(super) fn load(
    path: &Path,
    dependencies: &[std::path::PathBuf],
) -> Result<(Library, Vec<Library>)> {
    let mut loaded_dependencies = Vec::with_capacity(dependencies.len());
    for dependency in dependencies {
        let library = unsafe { Library::new(dependency) }.with_context(|| {
            format!(
                "failed to load Unicorn dependency: {}",
                dependency.display()
            )
        })?;
        loaded_dependencies.push(library);
    }
    let os_library = unsafe { libloading::os::windows::Library::new(path.as_os_str()) }
        .with_context(|| format!("failed to load Unicorn library: {}", path.display()))?;
    let handle = os_library.into_raw();
    let prepared = prepare(handle as usize);
    // Reconstruct even on failure so the module is unloaded correctly.
    let library = unsafe { libloading::os::windows::Library::from_raw(handle) };
    prepared?;
    Ok((library.into(), loaded_dependencies))
}

fn prepare(base: usize) -> Result<()> {
    let _guard = PREPARE_LOCK
        .lock()
        .expect("Unicorn preparation lock poisoned");
    let image = Image::new(base)?;
    let virtual_alloc = image.find_import("kernel32.dll", "VirtualAlloc")?;
    let current = unsafe { ptr::read_unaligned(virtual_alloc as *const usize) };
    let hook = committed_virtual_alloc as *const () as usize;
    if current != hook {
        let known = ORIGINAL_VIRTUAL_ALLOC.load(Ordering::Acquire);
        if known != 0 && known != current {
            bail!("Unicorn VirtualAlloc import changed unexpectedly");
        }
        ORIGINAL_VIRTUAL_ALLOC.store(current, Ordering::Release);
        replace_import(virtual_alloc, hook).context("patch Unicorn VirtualAlloc")?;
    } else if ORIGINAL_VIRTUAL_ALLOC.load(Ordering::Acquire) == 0 {
        bail!("Unicorn VirtualAlloc hook has no original function");
    }
    prepare_architecture(&image)
}

#[cfg(target_arch = "x86_64")]
fn prepare_architecture(image: &Image) -> Result<()> {
    let slot = image.find_import("msvcrt.dll", "longjmp")?;
    let replacement = allocate_compatible_longjmp()?;
    replace_import(slot, replacement).context("patch Unicorn longjmp")
}

#[cfg(target_arch = "aarch64")]
fn prepare_architecture(image: &Image) -> Result<()> {
    const MINGW_LONGJMP_PATTERN: &[u8] = &[
        0x13, 0x50, 0x41, 0xa9, 0x15, 0x58, 0x42, 0xa9, 0x17, 0x60, 0x43, 0xa9, 0x19, 0x68, 0x44,
        0xa9,
    ];
    let slot = image.find_import("api-ms-win-crt-private-l1-1-0.dll", "longjmp")?;
    let replacement = image.find_unique_pattern(MINGW_LONGJMP_PATTERN)?;
    replace_import(slot, replacement).context("patch Unicorn ARM64 longjmp")
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn prepare_architecture(_image: &Image) -> Result<()> {
    bail!("Windows Unicorn preparation is not implemented for this architecture")
}

extern "system" fn committed_virtual_alloc(
    address: *mut c_void,
    size: usize,
    mut allocation_type: u32,
    protection: u32,
) -> *mut c_void {
    if allocation_type == MEM_RESERVE && protection == PAGE_EXECUTE_READWRITE {
        allocation_type |= MEM_COMMIT;
    }
    let original = ORIGINAL_VIRTUAL_ALLOC.load(Ordering::Acquire);
    if original == 0 {
        return ptr::null_mut();
    }
    let call: VirtualAllocFn = unsafe { std::mem::transmute(original) };
    unsafe { call(address, size, allocation_type, protection) }
}

#[cfg(target_arch = "x86_64")]
const AMD64_LONGJMP: &[u8] = &[
    0x89, 0xd0, 0x85, 0xc0, 0x75, 0x02, 0xff, 0xc0, 0x0f, 0xae, 0x51, 0x58, 0xd9, 0x69, 0x5c, 0xf3,
    0x0f, 0x6f, 0x71, 0x60, 0xf3, 0x0f, 0x6f, 0x79, 0x70, 0xf3, 0x44, 0x0f, 0x6f, 0x81, 0x80, 0x00,
    0x00, 0x00, 0xf3, 0x44, 0x0f, 0x6f, 0x89, 0x90, 0x00, 0x00, 0x00, 0xf3, 0x44, 0x0f, 0x6f, 0x91,
    0xa0, 0x00, 0x00, 0x00, 0xf3, 0x44, 0x0f, 0x6f, 0x99, 0xb0, 0x00, 0x00, 0x00, 0xf3, 0x44, 0x0f,
    0x6f, 0xa1, 0xc0, 0x00, 0x00, 0x00, 0xf3, 0x44, 0x0f, 0x6f, 0xa9, 0xd0, 0x00, 0x00, 0x00, 0xf3,
    0x44, 0x0f, 0x6f, 0xb1, 0xe0, 0x00, 0x00, 0x00, 0xf3, 0x44, 0x0f, 0x6f, 0xb9, 0xf0, 0x00, 0x00,
    0x00, 0x48, 0x8b, 0x59, 0x08, 0x48, 0x8b, 0x69, 0x18, 0x48, 0x8b, 0x71, 0x20, 0x48, 0x8b, 0x79,
    0x28, 0x4c, 0x8b, 0x61, 0x30, 0x4c, 0x8b, 0x69, 0x38, 0x4c, 0x8b, 0x71, 0x40, 0x4c, 0x8b, 0x79,
    0x48, 0x4c, 0x8b, 0x59, 0x50, 0x48, 0x8b, 0x61, 0x10, 0x41, 0xff, 0xe3,
];

#[cfg(target_arch = "x86_64")]
fn allocate_compatible_longjmp() -> Result<usize> {
    let existing = LONGJMP_ADDRESS.load(Ordering::Acquire);
    if existing != 0 {
        return Ok(existing);
    }
    let original = ORIGINAL_VIRTUAL_ALLOC.load(Ordering::Acquire);
    if original == 0 {
        bail!("Unicorn VirtualAlloc original is unavailable");
    }
    let call: VirtualAllocFn = unsafe { std::mem::transmute(original) };
    let address = unsafe {
        call(
            ptr::null_mut(),
            AMD64_LONGJMP.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if address.is_null() {
        return Err(std::io::Error::last_os_error()).context("allocate compatible longjmp");
    }
    let result = (|| {
        unsafe {
            ptr::copy_nonoverlapping(AMD64_LONGJMP.as_ptr(), address.cast(), AMD64_LONGJMP.len())
        };
        let mut old = 0;
        if unsafe { VirtualProtect(address, AMD64_LONGJMP.len(), PAGE_EXECUTE_READ, &mut old) } == 0
        {
            return Err(std::io::Error::last_os_error()).context("protect compatible longjmp");
        }
        if unsafe { FlushInstructionCache(GetCurrentProcess(), address, AMD64_LONGJMP.len()) } == 0
        {
            return Err(std::io::Error::last_os_error()).context("flush compatible longjmp");
        }
        Ok(())
    })();
    if let Err(error) = result {
        unsafe { VirtualFree(address, 0, MEM_RELEASE) };
        return Err(error);
    }
    LONGJMP_ADDRESS.store(address as usize, Ordering::Release);
    Ok(address as usize)
}

fn replace_import(slot: usize, replacement: usize) -> Result<()> {
    if unsafe { ptr::read_unaligned(slot as *const usize) } == replacement {
        return Ok(());
    }
    let mut old = 0;
    if unsafe {
        VirtualProtect(
            slot as *mut c_void,
            size_of::<usize>(),
            PAGE_READWRITE,
            &mut old,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("make Unicorn import writable");
    }
    unsafe { ptr::write_unaligned(slot as *mut usize, replacement) };
    let mut ignored = 0;
    if unsafe { VirtualProtect(slot as *mut c_void, size_of::<usize>(), old, &mut ignored) } == 0 {
        return Err(std::io::Error::last_os_error()).context("restore Unicorn import protection");
    }
    Ok(())
}

struct Image {
    base: usize,
    size: usize,
    imports: usize,
}

impl Image {
    fn new(base: usize) -> Result<Self> {
        // This module was already verified against the pinned SHA-256 before loading.
        if unsafe { ptr::read_unaligned(base as *const u16) } != 0x5a4d {
            bail!("invalid Unicorn DOS header");
        }
        let nt_offset = unsafe { ptr::read_unaligned((base + 0x3c) as *const u32) } as usize;
        if nt_offset > 0x1000 {
            bail!("invalid Unicorn PE header offset");
        }
        let nt = base + nt_offset;
        if unsafe { ptr::read_unaligned(nt as *const u32) } != 0x0000_4550 {
            bail!("invalid Unicorn PE header");
        }
        let optional = nt + 24;
        if unsafe { ptr::read_unaligned(optional as *const u16) } != 0x020b {
            bail!("Unicorn is not a 64-bit PE image");
        }
        let size = unsafe { ptr::read_unaligned((optional + 56) as *const u32) } as usize;
        let imports_rva =
            unsafe { ptr::read_unaligned((optional + 112 + 8) as *const u32) } as usize;
        if size == 0 || imports_rva == 0 || imports_rva.checked_add(20).is_none_or(|end| end > size)
        {
            bail!("Unicorn PE import directory is missing");
        }
        Ok(Self {
            base,
            size,
            imports: base + imports_rva,
        })
    }

    fn bytes(&self, address: usize, length: usize) -> Result<&[u8]> {
        let offset = address
            .checked_sub(self.base)
            .context("PE address before image")?;
        if offset > self.size || length > self.size - offset {
            bail!("Unicorn PE import table extends beyond image");
        }
        Ok(unsafe { std::slice::from_raw_parts(address as *const u8, length) })
    }

    fn u32(&self, address: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.bytes(address, 4)?.try_into().unwrap(),
        ))
    }

    fn u64(&self, address: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.bytes(address, 8)?.try_into().unwrap(),
        ))
    }

    fn name(&self, rva: usize) -> Result<&str> {
        if rva >= self.size {
            bail!("Unicorn PE string extends beyond image");
        }
        let bytes = self.bytes(self.base + rva, self.size - rva)?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated PE string")?;
        std::str::from_utf8(&bytes[..end]).context("invalid PE string")
    }

    fn find_import(&self, dll: &str, function: &str) -> Result<usize> {
        for index in 0..self.size / 20 {
            let descriptor = self.imports + index * 20;
            let name_rva = self.u32(descriptor + 12)? as usize;
            if name_rva == 0 {
                break;
            }
            if !self.name(name_rva)?.eq_ignore_ascii_case(dll) {
                continue;
            }
            let names = self.u32(descriptor)? as usize;
            let addresses = self.u32(descriptor + 16)? as usize;
            if names == 0 || addresses == 0 {
                break;
            }
            for slot in 0..self.size / 8 {
                let name_slot = self.base + names + slot * 8;
                let address_slot = self.base + addresses + slot * 8;
                let entry = self.u64(name_slot)?;
                self.bytes(address_slot, 8)?;
                if entry == 0 {
                    break;
                }
                if entry & (1 << 63) != 0 {
                    continue;
                }
                let rva = usize::try_from(entry).context("invalid PE import name")?;
                if self.name(rva + 2)? == function {
                    return Ok(address_slot);
                }
            }
        }
        bail!("Unicorn import {dll}!{function} was not found")
    }

    #[cfg(target_arch = "aarch64")]
    fn find_unique_pattern(&self, pattern: &[u8]) -> Result<usize> {
        let image = self.bytes(self.base, self.size)?;
        let mut offsets = image
            .windows(pattern.len())
            .enumerate()
            .filter_map(|(offset, candidate)| (candidate == pattern).then_some(offset));
        let first = offsets
            .next()
            .context("Unicorn ARM64 longjmp pattern was not found")?;
        if offsets.next().is_some() {
            bail!("Unicorn ARM64 longjmp pattern is not unique");
        }
        Ok(self.base + first)
    }
}
