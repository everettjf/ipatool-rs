//! Validate and decrypt all encrypted slices of one Mach-O file.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    fairplay_codesign::{
        CodeDirectoryAudit, audit_code_directories, audit_pre_encryption_code_directories,
    },
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
    pub first_plaintext_page_sha256: String,
    pub code_directories: Vec<CodeDirectoryAudit>,
    pub pre_encryption_code_directories: Vec<CodeDirectoryAudit>,
    pub plaintext_verified: bool,
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
        if layout.crypt_id != 1 {
            bail!("unsupported Mach-O FairPlay cryptid");
        }
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
        let first =
            &image[layout.crypt_offset..layout.crypt_offset + crate::fairplay_supf::PAGE_BYTES];
        let first_plaintext_page_sha256 = format!("{:x}", Sha256::digest(first));
        // Restore the pre-encryption header before auditing a hash page that
        // can intersect both the header and the encrypted range.
        image[layout.crypt_id_offset..layout.crypt_id_offset + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        let pre_encryption_code_directories =
            audit_pre_encryption_code_directories(image, &layout)?;
        if pre_encryption_code_directories
            .iter()
            .any(|check| check.matched_slots != check.slot_count)
        {
            bail!("decrypted Mach-O fails CodeDirectory pre-encryption page hashes");
        }
        let plaintext_verified = !pre_encryption_code_directories.is_empty();
        let decrypted_sha256 = format!("{:x}", Sha256::digest(&*image));
        reports.push(DecryptedSlice {
            cpu_type: layout.cpu_type,
            cpu_subtype: layout.cpu_subtype,
            slice_offset: slice.offset,
            pages: records.len(),
            encrypted_sha256,
            decrypted_sha256,
            first_plaintext_page_sha256,
            code_directories: checks,
            pre_encryption_code_directories,
            plaintext_verified,
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
        let mut plaintext = vec![0u8; PAGE_BYTES];
        for chunk in plaintext.as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&0xd503_201fu32.to_le_bytes());
        }
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

    /// Two encrypted pages with independent page records and plaintext hashes.
    pub(crate) fn pre_encryption_fixture(logical: [u8; 16]) -> (Vec<u8>, Vec<[u8; 32]>, Vec<u8>) {
        pre_encryption_fixture_with_page_shift(logical, 12)
    }

    fn pre_encryption_fixture_with_page_shift(
        logical: [u8; 16],
        shift: u8,
    ) -> (Vec<u8>, Vec<[u8; 32]>, Vec<u8>) {
        let (original, record, _) = encrypted_fixture(logical);
        let records = vec![record, [0x47; 32]];
        let mut source = vec![0; PAGE_BYTES * 4];
        source[..PAGE_BYTES].copy_from_slice(&original[..PAGE_BYTES]);
        source[44..48].copy_from_slice(&(2 * PAGE_BYTES as u32).to_le_bytes());
        source[64..68].copy_from_slice(&(3 * PAGE_BYTES as u32).to_le_bytes());
        let page_size = if shift == 0 {
            3 * PAGE_BYTES
        } else {
            1 << shift
        };
        let slots = (3 * PAGE_BYTES).div_ceil(page_size);
        let pre_offset = 96 + slots * 32;
        let signature_size = 20 + 96 + 2 * slots * 32;
        source[68..72].copy_from_slice(&(signature_size as u32).to_le_bytes());
        let plaintext: Vec<u8> = (0..2 * PAGE_BYTES)
            .map(|index| (index.wrapping_mul(37).wrapping_add(7)) as u8)
            .collect();
        source[PAGE_BYTES..3 * PAGE_BYTES].copy_from_slice(&plaintext);
        let mut directory = vec![0; signature_size - 20];
        directory[..4].copy_from_slice(&0xfade0c02u32.to_be_bytes());
        let length = directory.len() as u32;
        directory[4..8].copy_from_slice(&length.to_be_bytes());
        directory[8..12].copy_from_slice(&0x20500u32.to_be_bytes());
        directory[16..20].copy_from_slice(&96u32.to_be_bytes());
        directory[28..32].copy_from_slice(&(slots as u32).to_be_bytes());
        directory[32..36].copy_from_slice(&(3 * PAGE_BYTES as u32).to_be_bytes());
        directory[36] = 32;
        directory[37] = 2;
        directory[39] = shift;
        directory[92..96].copy_from_slice(&(pre_offset as u32).to_be_bytes());
        source[48..52].copy_from_slice(&0u32.to_le_bytes());
        for slot in 0..slots {
            directory[pre_offset + slot * 32..pre_offset + (slot + 1) * 32].copy_from_slice(
                &Sha256::digest(
                    &source[slot * page_size..((slot + 1) * page_size).min(3 * PAGE_BYTES)],
                ),
            );
        }
        source[48..52].copy_from_slice(&1u32.to_le_bytes());
        for (index, record) in records.iter().enumerate() {
            let offset = (index + 1) * PAGE_BYTES;
            let key = PageKeyDeriver::from_logical_key(logical)
                .page_key(record[..16].try_into().unwrap(), offset as u64);
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut previous: [u8; 16] = record[16..].try_into().unwrap();
            for chunk in source[offset..offset + PAGE_BYTES].as_chunks_mut::<16>().0 {
                let mut block = GenericArray::clone_from_slice(chunk);
                for i in 0..16 {
                    block[i] ^= previous[i];
                }
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                previous.copy_from_slice(&block);
            }
        }
        for slot in 0..slots {
            directory[96 + slot * 32..96 + (slot + 1) * 32].copy_from_slice(&Sha256::digest(
                &source[slot * page_size..((slot + 1) * page_size).min(3 * PAGE_BYTES)],
            ));
        }
        let start = 3 * PAGE_BYTES;
        source[start..start + 4].copy_from_slice(&0xfade0cc0u32.to_be_bytes());
        source[start + 4..start + 8].copy_from_slice(&(signature_size as u32).to_be_bytes());
        source[start + 8..start + 12].copy_from_slice(&1u32.to_be_bytes());
        source[start + 16..start + 20].copy_from_slice(&20u32.to_be_bytes());
        source[start + 20..start + signature_size].copy_from_slice(&directory);
        (source, records, plaintext)
    }

    #[test]
    fn validates_plaintext_without_instruction_scoring_and_rejects_wrong_final_page() {
        let logical = [0x31; 16];
        let (source, records, plaintext) = pre_encryption_fixture(logical);
        let mut supf = Supf {
            variant: 5,
            architectures: vec![SupfArchitecture {
                cpu_type: 0x0100_000c,
                cpu_subtype: 2,
                records,
            }],
        };
        let (output, reports) = decrypt_macho(&source, &supf, logical).unwrap();
        assert_eq!(&output[PAGE_BYTES..3 * PAGE_BYTES], plaintext);
        assert!(reports[0].plaintext_verified);
        assert_eq!(reports[0].pre_encryption_code_directories[0].slot_count, 2);
        assert!(decrypt_macho(&source, &supf, [0x32; 16]).is_err());
        // A correct first page must not hide an incorrect final page key.
        supf.architectures[0].records[1][0] ^= 1;
        assert!(decrypt_macho(&source, &supf, logical).is_err());
    }

    #[test]
    fn restores_cryptid_before_auditing_pages_that_overlap_the_header() {
        for shift in [0, 13, 14] {
            let logical = [0x31; 16];
            let (source, records, plaintext) =
                pre_encryption_fixture_with_page_shift(logical, shift);
            let supf = Supf {
                variant: 5,
                architectures: vec![SupfArchitecture {
                    cpu_type: 0x0100_000c,
                    cpu_subtype: 2,
                    records,
                }],
            };
            let (output, reports) = decrypt_macho(&source, &supf, logical).unwrap();
            assert_eq!(&output[PAGE_BYTES..3 * PAGE_BYTES], plaintext);
            assert!(reports[0].plaintext_verified);
            assert_eq!(&output[48..52], &[0; 4]);
        }
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
        assert!(!reports[0].plaintext_verified);
        assert!(reports[0].pre_encryption_code_directories.is_empty());
        // A legacy image without plaintext hashes cannot identify a wrong key.
        assert!(!decrypt_macho(&source, &supf, [0x32; 16]).unwrap().1[0].plaintext_verified);
        let mut tampered = source;
        tampered[PAGE_BYTES + 99] ^= 1;
        assert!(decrypt_macho(&tampered, &supf, logical).is_err());
    }
}
