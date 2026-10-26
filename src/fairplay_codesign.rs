//! Audit embedded CodeDirectory hashes over encrypted Mach-O pages.

use anyhow::{Result, bail};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use crate::fairplay_macho::MachOLayout;

const EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
const CODE_DIRECTORY: u32 = 0xfade0c02;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CodeDirectoryAudit {
    pub hash_type: u8,
    pub hash_size: usize,
    pub page_size: usize,
    pub first_slot: usize,
    pub slot_count: usize,
    pub matched_slots: usize,
}

fn be32(bytes: &[u8], offset: usize) -> usize {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

fn hash_code_page(hash_type: u8, bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(match hash_type {
        1 => Sha1::digest(bytes).to_vec(),
        2 | 3 => Sha256::digest(bytes).to_vec(),
        4 => Sha384::digest(bytes).to_vec(),
        _ => bail!("unsupported CodeDirectory hash type {hash_type}"),
    })
}

pub fn audit_code_directories(
    executable: &[u8],
    layout: &MachOLayout,
) -> Result<Vec<CodeDirectoryAudit>> {
    let signature_end = layout
        .signature_offset
        .checked_add(layout.signature_size)
        .ok_or_else(|| anyhow::anyhow!("invalid Mach-O signature range"))?;
    let crypt_end = layout
        .crypt_offset
        .checked_add(layout.crypt_size)
        .ok_or_else(|| anyhow::anyhow!("invalid Mach-O encrypted range"))?;
    if signature_end > executable.len() || crypt_end > executable.len() || layout.crypt_size == 0 {
        bail!("invalid Mach-O audit ranges");
    }
    let signature = &executable[layout.signature_offset..signature_end];
    if signature.len() < 12 || be32(signature, 0) != EMBEDDED_SIGNATURE as usize {
        bail!("invalid embedded signature");
    }
    let total = be32(signature, 4);
    let count = be32(signature, 8);
    if total > signature.len() || count > (total.saturating_sub(12)) / 8 {
        bail!("invalid embedded signature geometry");
    }
    let mut reports = Vec::new();
    for index in 0..count {
        let offset = be32(signature, 16 + index * 8);
        if offset > total || total - offset < 8 {
            bail!("signature item exceeds superblob");
        }
        let magic = be32(signature, offset);
        let length = be32(signature, offset + 4);
        if length < 8 || length > total - offset {
            bail!("signature item has invalid length");
        }
        if magic != CODE_DIRECTORY as usize {
            continue;
        }
        let directory = &signature[offset..offset + length];
        if directory.len() < 44 {
            bail!("CodeDirectory is truncated");
        }
        let version = be32(directory, 8);
        let mut header_size = 44;
        if version >= 0x20100 {
            header_size = 48;
            if directory.len() < header_size || be32(directory, 44) != 0 {
                bail!("truncated or unsupported scattered CodeDirectory");
            }
        }
        let mut code_limit = be32(directory, 32);
        if version >= 0x20300 {
            header_size = 64;
            if directory.len() < header_size {
                bail!("extended CodeDirectory is truncated");
            }
            if code_limit == 0 {
                code_limit =
                    usize::try_from(u64::from_be_bytes(directory[56..64].try_into().unwrap()))
                        .map_err(|_| {
                            anyhow::anyhow!("CodeDirectory code limit exceeds platform")
                        })?;
            }
        }
        let hash_offset = be32(directory, 16);
        let code_slots = be32(directory, 28);
        let hash_size = directory[36] as usize;
        let hash_type = directory[37];
        let shift = directory[39];
        let expected_size = match hash_type {
            1 | 3 => 20,
            2 => 32,
            4 => 48,
            _ => 0,
        };
        if expected_size == 0 || hash_size != expected_size || shift > 30 {
            bail!("CodeDirectory geometry is invalid");
        }
        if code_limit < crypt_end || code_limit > executable.len() {
            bail!("CodeDirectory does not cover encrypted range");
        }
        let page_size = if shift == 0 {
            code_limit
        } else {
            1usize << shift
        };
        if page_size == 0 {
            bail!("CodeDirectory page size is zero");
        }
        let first_slot = layout.crypt_offset / page_size;
        let last_slot = crypt_end.div_ceil(page_size);
        if code_slots != code_limit.div_ceil(page_size)
            || last_slot > code_slots
            || hash_offset < header_size
            || code_slots
                .checked_mul(hash_size)
                .and_then(|length| hash_offset.checked_add(length))
                .is_none_or(|end| end > directory.len())
        {
            bail!("CodeDirectory table is truncated");
        }
        let mut matched_slots = 0;
        for slot in first_slot..last_slot {
            let start = slot * page_size;
            let end = start.saturating_add(page_size).min(code_limit);
            let actual = hash_code_page(hash_type, &executable[start..end])?;
            let expected =
                &directory[hash_offset + slot * hash_size..hash_offset + (slot + 1) * hash_size];
            if actual[..hash_size] == *expected {
                matched_slots += 1;
            }
        }
        reports.push(CodeDirectoryAudit {
            hash_type,
            hash_size,
            page_size,
            first_slot,
            slot_count: last_slot - first_slot,
            matched_slots,
        });
    }
    if reports.is_empty() {
        bail!("embedded signature contains no CodeDirectory");
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(shift: u8, hash_type: u8) -> (Vec<u8>, MachOLayout) {
        let crypt_offset = 4096;
        let crypt_size = 8192;
        let code_limit: usize = crypt_offset + crypt_size;
        let page_size = if shift == 0 {
            code_limit
        } else {
            1usize << shift
        };
        let slots = code_limit.div_ceil(page_size);
        let hash_size = match hash_type {
            1 | 3 => 20,
            2 => 32,
            4 => 48,
            _ => unreachable!(),
        };
        let mut directory = vec![0u8; 44 + slots * hash_size];
        directory[0..4].copy_from_slice(&CODE_DIRECTORY.to_be_bytes());
        let length = directory.len() as u32;
        directory[4..8].copy_from_slice(&length.to_be_bytes());
        directory[8..12].copy_from_slice(&0x20000u32.to_be_bytes());
        directory[16..20].copy_from_slice(&44u32.to_be_bytes());
        directory[28..32].copy_from_slice(&(slots as u32).to_be_bytes());
        directory[32..36].copy_from_slice(&(code_limit as u32).to_be_bytes());
        directory[36] = hash_size as u8;
        directory[37] = hash_type;
        directory[39] = shift;
        let mut blob: Vec<u8> = (0..code_limit).map(|index| (index % 251) as u8).collect();
        for slot in 0..slots {
            let digest = hash_code_page(
                hash_type,
                &blob[slot * page_size..((slot + 1) * page_size).min(code_limit)],
            )
            .unwrap();
            directory[44 + slot * hash_size..44 + (slot + 1) * hash_size]
                .copy_from_slice(&digest[..hash_size]);
        }
        let mut signature = vec![0u8; 20];
        signature[0..4].copy_from_slice(&EMBEDDED_SIGNATURE.to_be_bytes());
        signature[4..8].copy_from_slice(&(20u32 + directory.len() as u32).to_be_bytes());
        signature[8..12].copy_from_slice(&1u32.to_be_bytes());
        signature[16..20].copy_from_slice(&20u32.to_be_bytes());
        signature.extend_from_slice(&directory);
        let layout = MachOLayout {
            cpu_type: 0x0100_000c,
            cpu_subtype: 2,
            crypt_offset,
            crypt_size,
            crypt_id: 1,
            crypt_id_offset: 48,
            signature_offset: code_limit,
            signature_size: signature.len(),
            instruction_ranges: Vec::new(),
        };
        blob.extend_from_slice(&signature);
        (blob, layout)
    }

    #[test]
    fn verifies_all_intersecting_code_slots_and_detects_mutation() {
        for shift in [0, 12, 13, 14] {
            for hash_type in [1, 2, 3, 4] {
                let (mut blob, layout) = fixture(shift, hash_type);
                let audits = audit_code_directories(&blob, &layout).unwrap();
                assert_eq!(audits[0].matched_slots, audits[0].slot_count);
                blob[layout.crypt_offset + layout.crypt_size - 1] ^= 1;
                let audits = audit_code_directories(&blob, &layout).unwrap();
                assert_eq!(audits[0].matched_slots + 1, audits[0].slot_count);
            }
        }
    }

    #[test]
    fn rejects_invalid_hash_geometry_and_missing_coverage() {
        let (mut blob, layout) = fixture(12, 2);
        blob[layout.signature_offset + 20 + 36] = 31;
        assert!(audit_code_directories(&blob, &layout).is_err());
        let (mut blob, layout) = fixture(12, 2);
        blob[layout.signature_offset + 20 + 32..layout.signature_offset + 20 + 36]
            .copy_from_slice(&4096u32.to_be_bytes());
        assert!(audit_code_directories(&blob, &layout).is_err());
    }
}
