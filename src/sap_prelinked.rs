//! External function and data addresses used by the pinned macOS 27.0.1
//! AppleMediaServices shared-cache image.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};

use crate::machimage::Memory;

const PAGE_SIZE: u64 = 4096;

pub const FUNCTIONS: &[(u64, &str)] = &[
    (0x180675ce8, "_malloc"),
    (0x1806766f0, "_free"),
    (0x1806cf570, "_dispatch_once"),
    (0x18071acc8, "_sysctlbyname"),
    (0x18071bec4, "_gettimeofday"),
    (0x180721fb8, "_arc4random"),
    (0x1807238a4, "___memset_chk"),
    (0x1807903c4, "_abort"),
    (0x180849604, "___error"),
    (0x180889bc4, "_pthread_once"),
    (0x18088a6f8, "_pthread_rwlock_unlock"),
    (0x18088a7c0, "_pthread_rwlock_wrlock"),
    (0x18088b2d8, "_pthread_rwlock_init"),
    (0x180894b40, "_strlen"),
    (0x1808cf540, "_CFStringCreateWithCString"),
    (0x1808d4200, "_CFStringGetLength"),
    (0x1808d44dc, "_CFStringGetCString"),
    (0x1808d7278, "_CFRelease"),
    (0x1808e89e8, "_CFDataGetLength"),
    (0x184d6b4cc, "_IOServiceMatching"),
    (0x184d6c168, "_IOServiceGetMatchingServices"),
    (0x184d6c4fc, "_IOIteratorNext"),
    (0x184d6cb50, "_IOObjectRelease"),
];

pub const SLOTS: &[(u64, &str)] = &[
    (0x1e02205c0, "___stack_chk_guard"),
    (0x1e800c958, "___chkstk_darwin"),
];

/// Map the pinned external addresses and install direct branches/data pointers.
pub fn install<M, F>(memory: &mut M, mut resolve: F) -> Result<()>
where
    M: Memory,
    F: FnMut(&str) -> Result<u64>,
{
    let mut functions = Vec::with_capacity(FUNCTIONS.len());
    let mut slots = Vec::with_capacity(SLOTS.len());
    let mut pages = BTreeSet::new();
    for &(address, name) in FUNCTIONS {
        if address % 4 != 0 {
            bail!("unaligned shared-cache function {name}");
        }
        let target =
            resolve(name).with_context(|| format!("resolve shared-cache function {name}"))?;
        let end = address
            .checked_add(15)
            .context("shared-cache function range overflows")?;
        pages.insert(address & !(PAGE_SIZE - 1));
        pages.insert(end & !(PAGE_SIZE - 1));
        functions.push((address, target));
    }
    for &(address, name) in SLOTS {
        if address % 8 != 0 {
            bail!("unaligned shared-cache slot {name}");
        }
        let value = resolve(name).with_context(|| format!("resolve shared-cache slot {name}"))?;
        pages.insert(address & !(PAGE_SIZE - 1));
        slots.push((address, value));
    }
    for page in pages {
        memory
            .map(page, PAGE_SIZE)
            .with_context(|| format!("map shared-cache page {page:#x}"))?;
    }
    for (address, target) in functions {
        let mut trampoline = [0u8; 16];
        trampoline[..4].copy_from_slice(&0x5800_0050u32.to_le_bytes()); // ldr x16, #8
        trampoline[4..8].copy_from_slice(&0xd61f_0200u32.to_le_bytes()); // br x16
        trampoline[8..].copy_from_slice(&target.to_le_bytes());
        memory
            .write(address, &trampoline)
            .with_context(|| format!("write trampoline at {address:#x}"))?;
    }
    for (address, value) in slots {
        memory
            .write(address, &value.to_le_bytes())
            .with_context(|| format!("write shared-cache slot at {address:#x}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordedMemory {
        maps: Vec<(u64, u64)>,
        writes: Vec<(u64, Vec<u8>)>,
    }

    impl Memory for RecordedMemory {
        fn map(&mut self, address: u64, size: u64) -> Result<()> {
            self.maps.push((address, size));
            Ok(())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
            assert!(self.maps.iter().any(
                |(page, size)| address >= *page && address + bytes.len() as u64 <= page + size
            ));
            self.writes.push((address, bytes.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn installs_pinned_trampolines_and_slots() {
        let mut memory = RecordedMemory::default();
        install(&mut memory, |_| Ok(0x1234_5678_9abc_def0)).unwrap();
        assert_eq!(memory.writes.len(), FUNCTIONS.len() + SLOTS.len());
        assert_eq!(memory.maps.len(), 21);
        assert_eq!(
            &memory.writes[0].1[..8],
            &[0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6]
        );
        assert_eq!(
            &memory.writes[0].1[8..],
            &0x1234_5678_9abc_def0u64.to_le_bytes()
        );
        assert_eq!(
            memory.writes.last().unwrap().1,
            0x1234_5678_9abc_def0u64.to_le_bytes()
        );
    }

    #[test]
    fn resolve_failure_does_not_map_memory() {
        let mut memory = RecordedMemory::default();
        assert!(install(&mut memory, |_| bail!("unavailable")).is_err());
        assert!(memory.maps.is_empty());
    }
}
