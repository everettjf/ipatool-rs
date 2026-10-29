//! Parse FairPlay SUPF page records and decrypt their matching Mach-O region.

use aes::{
    Aes128,
    cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::fairplay_page::PageKeyDeriver;

pub const PAGE_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupfArchitecture {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub records: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Supf {
    pub variant: u8,
    pub architectures: Vec<SupfArchitecture>,
}

impl Supf {
    pub fn parse(blob: &[u8]) -> Result<Self> {
        if blob.len() < 12 {
            bail!("SUPF is truncated");
        }
        let variant = blob[0];
        if !matches!(variant, 3 | 5) {
            bail!("unsupported SUPF variant {variant}");
        }
        let outer_len = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
        let outer_end = 8usize
            .checked_add(outer_len)
            .ok_or_else(|| anyhow::anyhow!("SUPF outer length overflow"))?;
        if outer_end > blob.len() {
            bail!("SUPF outer payload exceeds file");
        }
        let count = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
        if !(1..=32).contains(&count) {
            bail!("SUPF architecture count is invalid");
        }
        let mut cursor = 12usize;
        let mut architectures: Vec<SupfArchitecture> = Vec::with_capacity(count);
        for _ in 0..count {
            if outer_end.saturating_sub(cursor) < 4 {
                bail!("SUPF architecture length is truncated");
            }
            let length = u32::from_be_bytes(blob[cursor..cursor + 4].try_into().unwrap()) as usize;
            let start = cursor + 4;
            let end = start
                .checked_add(length)
                .ok_or_else(|| anyhow::anyhow!("SUPF architecture length overflow"))?;
            if length < 8 || end > outer_end {
                bail!("SUPF architecture has invalid geometry");
            }
            let cpu_type = u32::from_be_bytes(blob[start..start + 4].try_into().unwrap());
            let cpu_subtype = u32::from_be_bytes(blob[start + 4..start + 8].try_into().unwrap());
            let payload = start + if variant == 3 { 28 } else { 8 };
            if end.saturating_sub(payload) < 4 {
                bail!("SUPF page count is truncated");
            }
            let pages = u32::from_be_bytes(blob[payload..payload + 4].try_into().unwrap()) as usize;
            let keys = payload + 4;
            let record_bytes = pages
                .checked_mul(32)
                .ok_or_else(|| anyhow::anyhow!("SUPF page count overflow"))?;
            if keys.checked_add(record_bytes) != Some(end) {
                bail!("SUPF page-key table has inconsistent length");
            }
            if architectures
                .iter()
                .any(|arch| arch.cpu_type == cpu_type && arch.cpu_subtype == cpu_subtype)
            {
                bail!("SUPF contains duplicate architecture");
            }
            let records = blob[keys..end].as_chunks::<32>().0.to_vec();
            architectures.push(SupfArchitecture {
                cpu_type,
                cpu_subtype,
                records,
            });
            cursor = end;
        }
        if cursor != outer_end {
            bail!("SUPF records do not fill outer payload");
        }
        Ok(Self {
            variant,
            architectures,
        })
    }

    pub fn records_for(&self, cpu_type: u32, cpu_subtype: u32) -> Result<&[[u8; 32]]> {
        self.architectures
            .iter()
            .find(|arch| arch.cpu_type == cpu_type && arch.cpu_subtype == cpu_subtype)
            .map(|arch| arch.records.as_slice())
            .ok_or_else(|| {
                anyhow::anyhow!("SUPF has no matching architecture {cpu_type:#x}/{cpu_subtype:#x}")
            })
    }
}

/// Decrypt a validated image's page-aligned encrypted region in place.
/// `crypt_offset` is relative to `image`; `slice_offset` is its offset in the fat Mach-O.
pub fn decrypt_pages_in_place(
    image: &mut [u8],
    crypt_offset: usize,
    crypt_size: usize,
    slice_offset: u64,
    records: &[[u8; 32]],
    deriver: &PageKeyDeriver,
) -> Result<()> {
    let end = crypt_offset
        .checked_add(crypt_size)
        .ok_or_else(|| anyhow::anyhow!("FairPlay encrypted range overflow"))?;
    if end > image.len()
        || crypt_size == 0
        || !crypt_size.is_multiple_of(PAGE_BYTES)
        || records.len() != crypt_size / PAGE_BYTES
    {
        bail!("FairPlay encrypted range and SUPF page count differ");
    }
    let absolute_offset = slice_offset
        .checked_add(crypt_offset as u64)
        .ok_or_else(|| anyhow::anyhow!("FairPlay crypt offset overflow"))?;
    for (page, record) in image[crypt_offset..end]
        .as_chunks_mut::<PAGE_BYTES>()
        .0
        .iter_mut()
        .zip(records)
    {
        crate::application::operation::check()?;
        let key =
            Zeroizing::new(deriver.page_key(record[..16].try_into().unwrap(), absolute_offset));
        let cipher = Aes128::new_from_slice(&key[..]).unwrap();
        let mut previous: [u8; 16] = record[16..32].try_into().unwrap();
        for chunk in page.as_chunks_mut::<16>().0 {
            let ciphertext = *chunk;
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for index in 0..16 {
                chunk[index] = block[index] ^ previous[index];
            }
            previous = ciphertext;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    fn architecture(variant: u8, cpu: u32, subtype: u32, records: &[[u8; 32]]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&cpu.to_be_bytes());
        payload.extend_from_slice(&subtype.to_be_bytes());
        if variant == 3 {
            payload.extend_from_slice(&[0; 20]);
        }
        payload.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for record in records {
            payload.extend_from_slice(record);
        }
        let mut entry = Vec::new();
        entry.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        entry.extend_from_slice(&payload);
        entry
    }

    fn supf(variant: u8, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut result = vec![variant, 0, 0, 0];
        let outer_len = 4 + entries.iter().map(Vec::len).sum::<usize>();
        result.extend_from_slice(&(outer_len as u32).to_be_bytes());
        result.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for entry in entries {
            result.extend_from_slice(entry);
        }
        result
    }

    #[test]
    fn parses_both_variants_and_rejects_bad_geometry() {
        let record = [0x42; 32];
        for variant in [3, 5] {
            let bytes = supf(variant, &[architecture(variant, 0x0100_000c, 2, &[record])]);
            let parsed = Supf::parse(&bytes).unwrap();
            assert_eq!(parsed.records_for(0x0100_000c, 2).unwrap(), &[record]);
            assert!(parsed.records_for(0x0100_000c, 3).is_err());
            let mut corrupt = bytes.clone();
            let last = corrupt.len() - 36;
            corrupt[last..last + 4].copy_from_slice(&2u32.to_be_bytes());
            assert!(Supf::parse(&corrupt).is_err());
            let duplicate = supf(
                variant,
                &[
                    architecture(variant, 1, 2, &[]),
                    architecture(variant, 1, 2, &[]),
                ],
            );
            assert!(Supf::parse(&duplicate).is_err());
        }
    }

    #[test]
    fn decrypts_pages_and_rejects_mismatched_table_without_mutation() {
        let logical = std::array::from_fn::<_, 16, _>(|i| i as u8 + 1);
        let deriver = PageKeyDeriver::from_logical_key(logical);
        let record = std::array::from_fn::<_, 32, _>(|i| i as u8 + 0x40);
        let mut image = vec![0x7b; PAGE_BYTES * 2];
        let plaintext = image[PAGE_BYTES..].to_vec();
        let key = deriver.page_key(record[..16].try_into().unwrap(), 0x5000);
        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut previous: [u8; 16] = record[16..].try_into().unwrap();
        for chunk in image[PAGE_BYTES..].as_chunks_mut::<16>().0 {
            let mut block = GenericArray::clone_from_slice(chunk);
            for index in 0..16 {
                block[index] ^= previous[index];
            }
            cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            previous.copy_from_slice(&block);
        }
        let encrypted = image.clone();
        assert!(
            decrypt_pages_in_place(&mut image, PAGE_BYTES, PAGE_BYTES, 0x4000, &[], &deriver)
                .is_err()
        );
        assert_eq!(image, encrypted);
        decrypt_pages_in_place(
            &mut image,
            PAGE_BYTES,
            PAGE_BYTES,
            0x4000,
            &[record],
            &deriver,
        )
        .unwrap();
        assert_eq!(&image[..PAGE_BYTES], &encrypted[..PAGE_BYTES]);
        assert_eq!(&image[PAGE_BYTES..], &plaintext);
    }
}
