//! Store emulator page grouping and strict profile access checks.

use std::collections::HashSet;

use anyhow::{Result, bail};

pub const PROFILE_PAGE_SIZE: u64 = 4096;
pub const MAX_REGION_GAP: u64 = 1 << 20;
pub const MAX_REGION_SIZE: u64 = 32 << 20;
pub const MAX_PROFILE_SPAN: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    pub address: u64,
    pub size: u64,
}

pub fn group_pages(addresses: &[u64]) -> Result<Vec<MemoryRegion>> {
    let mut addresses = addresses.to_vec();
    addresses.sort_unstable();
    for &address in &addresses {
        if address % PROFILE_PAGE_SIZE != 0 || address > u64::MAX - PROFILE_PAGE_SIZE {
            bail!("invalid Store profile page address");
        }
    }
    let mut regions = Vec::new();
    let mut total = 0;
    let mut start = 0;
    while start < addresses.len() {
        let mut end = start + 1;
        while end < addresses.len()
            && addresses[end] - addresses[end - 1] <= MAX_REGION_GAP
            && addresses[end] - addresses[start] + PROFILE_PAGE_SIZE <= MAX_REGION_SIZE
        {
            end += 1;
        }
        let size = addresses[end - 1] - addresses[start] + PROFILE_PAGE_SIZE;
        if size > MAX_PROFILE_SPAN - total {
            bail!("Store profile mapping exceeds size limit");
        }
        total += size;
        regions.push(MemoryRegion {
            address: addresses[start],
            size,
        });
        start = end;
    }
    Ok(regions)
}

pub fn check_profile_access(allowed: &HashSet<u64>, address: u64, size: u64) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let Some(last_byte) = address.checked_add(size - 1) else {
        bail!("Store memory access overflows address space");
    };
    let last_page = last_byte & !(PROFILE_PAGE_SIZE - 1);
    let mut page = address & !(PROFILE_PAGE_SIZE - 1);
    loop {
        if !allowed.contains(&page) {
            bail!("missing Store profile page {page:#x} for access {address:#x} ({size} bytes)");
        }
        if page == last_page {
            return Ok(());
        }
        page += PROFILE_PAGE_SIZE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_nearby_unsorted_pages_and_bounds_regions() {
        assert_eq!(
            group_pages(&[0x3000, 0x1000, 0x1000, 0x800000]).unwrap(),
            [
                MemoryRegion {
                    address: 0x1000,
                    size: 0x3000
                },
                MemoryRegion {
                    address: 0x800000,
                    size: 4096
                }
            ]
        );
        let pages = (0..3 * MAX_REGION_SIZE)
            .step_by(MAX_REGION_GAP as usize)
            .collect::<Vec<_>>();
        let regions = group_pages(&pages).unwrap();
        assert!(regions.iter().all(|region| region.size <= MAX_REGION_SIZE));
        assert!(
            pages
                .iter()
                .all(|page| regions.iter().any(|region| *page >= region.address
                    && *page + PROFILE_PAGE_SIZE <= region.address + region.size))
        );
    }

    #[test]
    fn rejects_invalid_page_addresses_and_excessive_span() {
        assert!(group_pages(&[1]).is_err());
        assert!(group_pages(&[u64::MAX - 4095]).is_err());
        let pages = (0..2 * MAX_PROFILE_SPAN)
            .step_by(MAX_REGION_GAP as usize)
            .collect::<Vec<_>>();
        assert!(
            group_pages(&pages)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
    }

    #[test]
    fn checks_all_pages_and_address_overflow() {
        let allowed = HashSet::from([0x1000, 0x3000]);
        assert!(
            check_profile_access(&allowed, 0x1ffc, 8)
                .unwrap_err()
                .to_string()
                .contains("0x2000")
        );
        assert!(check_profile_access(&allowed, 0x1000, 4096).is_ok());
        assert!(check_profile_access(&allowed, u64::MAX, 0).is_ok());
        assert!(
            check_profile_access(&allowed, u64::MAX, 2)
                .unwrap_err()
                .to_string()
                .contains("overflows")
        );
        assert!(check_profile_access(&HashSet::from([u64::MAX - 4095]), u64::MAX, 1).is_ok());
    }
}
