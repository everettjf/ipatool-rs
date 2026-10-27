//! Stable Store hardware identity from Windows IP Helper adapter metadata.

use std::{mem, ptr};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::ERROR_BUFFER_OVERFLOW,
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GetIfEntry2, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP,
        IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
    },
};

const MAX_ADAPTER_BYTES: usize = 1024 * 1024;
const MAX_ADAPTERS: usize = 4096;
const PHYSICAL_PRIORITY: u8 = 1;
const FALLBACK_PRIORITY: u8 = 2;
const BLUETOOTH_MEDIUM: i32 = 10;

fn usable(mac: &[u8; 6]) -> bool {
    mac[0] & 1 == 0 && *mac != [0; 6] && *mac != [2, 0, 0, 0, 0, 0]
}

fn choose(candidates: impl IntoIterator<Item = (u8, [u8; 6])>) -> Option<[u8; 6]> {
    candidates
        .into_iter()
        .filter(|(_, mac)| usable(mac))
        .min()
        .map(|(_, mac)| mac)
}

fn adapter_candidates() -> Result<Vec<(u8, [u8; 6])>> {
    let mut size = 16 * 1024u32;
    for _ in 0..4 {
        if size as usize > MAX_ADAPTER_BYTES {
            bail!("Windows adapter metadata exceeds size limit");
        }
        let words = (size as usize).div_ceil(mem::size_of::<u64>());
        let mut buffer = vec![0u64; words];
        let start = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: the aligned buffer has at least `size` bytes and remains live
        // while the returned linked list is inspected.
        let status = unsafe { GetAdaptersAddresses(0, 0, ptr::null(), start, &mut size) };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status != 0 {
            bail!("query Windows network adapters failed with status {status}");
        }
        let mut candidates = Vec::new();
        let mut cursor = start;
        for _ in 0..MAX_ADAPTERS {
            if cursor.is_null() {
                return Ok(candidates);
            }
            // SAFETY: GetAdaptersAddresses returned a linked list inside `buffer`.
            let adapter = unsafe { &*cursor };
            cursor = adapter.Next;
            if adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter.IfType == IF_TYPE_PPP {
                continue;
            }
            if adapter.PhysicalAddressLength != 6 {
                continue;
            }
            let fallback: [u8; 6] = adapter.PhysicalAddress[..6].try_into().unwrap();
            let mut row = MIB_IF_ROW2::default();
            row.InterfaceLuid = adapter.Luid;
            // SAFETY: GetIfEntry2 fills the initialized row for this adapter.
            let result = unsafe { GetIfEntry2(&mut row) };
            if result != 0 {
                candidates.push((FALLBACK_PRIORITY, fallback));
                continue;
            }
            if row.PhysicalAddressLength != 6 {
                continue;
            }
            let physical: [u8; 6] = row.PhysicalAddress[..6].try_into().unwrap();
            let permanent: [u8; 6] = row.PermanentPhysicalAddress[..6].try_into().unwrap();
            let selected = if usable(&permanent) {
                permanent
            } else {
                physical
            };
            let flags = row.InterfaceAndOperStatusFlags._bitfield;
            let physical_interface = flags & 3 == 1
                && row.PhysicalMediumType != BLUETOOTH_MEDIUM
                && matches!(row.Type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211);
            candidates.push((
                if physical_interface {
                    PHYSICAL_PRIORITY
                } else {
                    FALLBACK_PRIORITY
                },
                selected,
            ));
        }
        bail!("Windows adapter list exceeds item limit");
    }
    bail!("Windows adapter metadata changed during enumeration")
}

pub(crate) fn hardware_mac_address() -> Result<[u8; 6]> {
    choose(adapter_candidates()?).context("no usable network hardware MAC address")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_stable_physical_address_independent_of_enumeration_order() {
        let a = (FALLBACK_PRIORITY, [0x10, 0, 0, 0, 0, 1]);
        let b = (PHYSICAL_PRIORITY, [0x22, 0, 0, 0, 0, 2]);
        let c = (PHYSICAL_PRIORITY, [0x20, 0, 0, 0, 0, 3]);
        assert_eq!(choose([a, b, c]), Some(c.1));
        assert_eq!(choose([c, b, a]), Some(c.1));
        assert_eq!(choose([(PHYSICAL_PRIORITY, [0; 6]), a]), Some(a.1));
    }
}
