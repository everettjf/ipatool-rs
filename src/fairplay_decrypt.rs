//! Validate and decrypt all encrypted slices of one Mach-O file.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    fairplay_codesign::{CodeDirectoryAudit, audit_code_directories},
    fairplay_macho::parse_macho_slices,
    fairplay_page::PageKeyDeriver,
    fairplay_supf::{Supf, decrypt_pages_in_place},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DecryptedSlice {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub slice_offset: usize,
    pub pages: usize,
    pub encrypted_sha256: String,
    pub decrypted_sha256: String,
    pub code_directories: Vec<CodeDirectoryAudit>,
}

/// Return a new Mach-O image after validating its encrypted CodeDirectory
/// slots and decrypting every matching SUPF-backed slice.
pub fn decrypt_macho(
    source: &[u8],
    supf: &Supf,
    logical_key: [u8; 16],
) -> Result<(Vec<u8>, Vec<DecryptedSlice>)> {
    let slices = parse_macho_slices(source)?;
    let encrypted: Vec<_> = slices
        .into_iter()
        .filter(|slice| slice.layout.crypt_id != 0)
        .collect();
    if encrypted.is_empty() {
        bail!("Mach-O contains no supported encrypted slices");
    }
    let mut audits = Vec::with_capacity(encrypted.len());
    for slice in &encrypted {
        let layout = &slice.layout;
        let records = supf.records_for(layout.cpu_type, layout.cpu_subtype)?;
        if records.len() != layout.crypt_size / crate::fairplay_supf::PAGE_BYTES {
            bail!("SUPF page count differs from Mach-O encrypted region");
        }
        let image = &source[slice.offset..slice.offset + slice.size];
        let checks = audit_code_directories(image, layout)
            .with_context(|| format!("audit Mach-O slice at {:#x}", slice.offset))?;
        if checks
            .iter()
            .any(|check| check.matched_slots != check.slot_count)
        {
            bail!("encrypted Mach-O source fails CodeDirectory page hashes");
        }
        audits.push(checks);
    }
    let mut output = source.to_vec();
    let deriver = PageKeyDeriver::from_logical_key(logical_key);
    let mut reports = Vec::with_capacity(encrypted.len());
    for (slice, checks) in encrypted.into_iter().zip(audits) {
        let layout = slice.layout;
        let image = &mut output[slice.offset..slice.offset + slice.size];
        let encrypted_sha256 = format!("{:x}", Sha256::digest(&*image));
        let records = supf.records_for(layout.cpu_type, layout.cpu_subtype)?;
        decrypt_pages_in_place(
            image,
            layout.crypt_offset,
            layout.crypt_size,
            slice.offset as u64,
            records,
            &deriver,
        )?;
        image[layout.crypt_id_offset..layout.crypt_id_offset + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        let decrypted_sha256 = format!("{:x}", Sha256::digest(&*image));
        reports.push(DecryptedSlice {
            cpu_type: layout.cpu_type,
            cpu_subtype: layout.cpu_subtype,
            slice_offset: slice.offset,
            pages: records.len(),
            encrypted_sha256,
            decrypted_sha256,
            code_directories: checks,
        });
    }
    Ok((output, reports))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fairplay_supf::{PAGE_BYTES, SupfArchitecture};
    use aes::{
        Aes128,
        cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
    };

    pub(crate) fn encrypted_fixture(logical: [u8; 16]) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        let mut record = [0u8; 32];
        for (index, byte) in record.iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }
        let mut source = vec![0u8; PAGE_BYTES * 3];
        source[..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        source[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        source[8..12].copy_from_slice(&2u32.to_le_bytes());
        source[16..20].copy_from_slice(&2u32.to_le_bytes());
        source[20..24].copy_from_slice(&40u32.to_le_bytes());
        source[32..36].copy_from_slice(&0x2cu32.to_le_bytes());
        source[36..40].copy_from_slice(&24u32.to_le_bytes());
        source[40..44].copy_from_slice(&(PAGE_BYTES as u32).to_le_bytes());
        source[44..48].copy_from_slice(&(PAGE_BYTES as u32).to_le_bytes());
        source[48..52].copy_from_slice(&1u32.to_le_bytes());
        source[56..60].copy_from_slice(&0x1du32.to_le_bytes());
        source[60..64].copy_from_slice(&16u32.to_le_bytes());
        source[64..68].copy_from_slice(&(PAGE_BYTES as u32 * 2).to_le_bytes());
        source[68..72].copy_from_slice(&(20u32 + 44 + 2 * 32).to_le_bytes());
        let plaintext = vec![0x5a; PAGE_BYTES];
        source[PAGE_BYTES..PAGE_BYTES * 2].copy_from_slice(&plaintext);
        let key = PageKeyDeriver::from_logical_key(logical)
            .page_key(record[..16].try_into().unwrap(), PAGE_BYTES as u64);
        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut previous: [u8; 16] = record[16..].try_into().unwrap();
        for chunk in source[PAGE_BYTES..PAGE_BYTES * 2].as_chunks_mut::<16>().0 {
            let mut block = GenericArray::clone_from_slice(chunk);
            for index in 0..16 {
                block[index] ^= previous[index];
            }
            cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            previous.copy_from_slice(&block);
        }
        let mut directory = vec![0u8; 44 + 2 * 32];
        let directory_size = directory.len() as u32;
        directory[..4].copy_from_slice(&0xfade0c02u32.to_be_bytes());
        directory[4..8].copy_from_slice(&directory_size.to_be_bytes());
        directory[8..12].copy_from_slice(&0x20000u32.to_be_bytes());
        directory[16..20].copy_from_slice(&44u32.to_be_bytes());
        directory[28..32].copy_from_slice(&2u32.to_be_bytes());
        directory[32..36].copy_from_slice(&(PAGE_BYTES as u32 * 2).to_be_bytes());
        directory[36] = 32;
        directory[37] = 2;
        directory[39] = 12;
        for slot in 0..2 {
            directory[44 + slot * 32..44 + (slot + 1) * 32].copy_from_slice(&Sha256::digest(
                &source[slot * PAGE_BYTES..(slot + 1) * PAGE_BYTES],
            ));
        }
        let mut signature = vec![0u8; 20];
        signature[..4].copy_from_slice(&0xfade0cc0u32.to_be_bytes());
        signature[4..8].copy_from_slice(&(20u32 + directory.len() as u32).to_be_bytes());
        signature[8..12].copy_from_slice(&1u32.to_be_bytes());
        signature[16..20].copy_from_slice(&20u32.to_be_bytes());
        signature.extend_from_slice(&directory);
        source[68..72].copy_from_slice(&(signature.len() as u32).to_le_bytes());
        source[PAGE_BYTES * 2..PAGE_BYTES * 2 + signature.len()].copy_from_slice(&signature);
        (source, record, plaintext)
    }

    #[test]
    fn decrypts_signed_encrypted_image_and_rejects_tampered_source() {
        let logical = [0x31; 16];
        let (source, record, plaintext) = encrypted_fixture(logical);
        let supf = Supf {
            variant: 5,
            architectures: vec![SupfArchitecture {
                cpu_type: 0x0100_000c,
                cpu_subtype: 2,
                records: vec![record],
            }],
        };
        let (output, reports) = decrypt_macho(&source, &supf, logical).unwrap();
        assert_eq!(&output[PAGE_BYTES..PAGE_BYTES * 2], &plaintext);
        assert_eq!(&output[48..52], &[0; 4]);
        assert_eq!(reports[0].pages, 1);
        let mut tampered = source;
        tampered[PAGE_BYTES + 99] ^= 1;
        assert!(decrypt_macho(&tampered, &supf, logical).is_err());
    }
}
