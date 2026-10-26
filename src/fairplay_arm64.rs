//! Check whether a decrypted ARM64 first page looks like executable code.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Serialize;
use yaxpeax_arch::{Arch, Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::ARMv8;

use crate::fairplay_macho::FileRange;

const MINIMUM_VALID_PERCENT: usize = 90;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Arm64Audit {
    pub instruction_words: usize,
    pub valid_words: usize,
    pub mnemonics: BTreeMap<String, usize>,
}

fn supplemental_mnemonic(word: u32) -> Option<&'static str> {
    match word {
        word if word & 0xbf80_f400 == 0x0f00_1000 => Some("FMLA"),
        word if word & 0xbfe0_fc00 == 0x0e40_3400 => Some("FMAX"),
        word if word & 0xbfe0_fc00 == 0x0ec0_3400 => Some("FMIN"),
        _ => None,
    }
}

fn audit_words(bytes: &[u8], audit: &mut Arm64Audit) {
    let decoder = <ARMv8 as Arch>::Decoder::default();
    for chunk in bytes.as_chunks::<4>().0 {
        audit.instruction_words += 1;
        let word = u32::from_le_bytes(*chunk);
        let mnemonic = if word == 0xd503_201f {
            Some("NOP".to_owned())
        } else if word & 0xffe0_001f == 0 {
            Some("UDF".to_owned())
        } else {
            decoder
                .decode(&mut U8Reader::new(chunk.as_slice()))
                .ok()
                .map(|instruction| instruction.opcode.to_string().to_ascii_uppercase())
                .or_else(|| supplemental_mnemonic(word).map(str::to_owned))
        };
        if let Some(mnemonic) = mnemonic {
            audit.valid_words += 1;
            *audit.mnemonics.entry(mnemonic).or_default() += 1;
        }
    }
}

pub fn audit_first_page(
    page: &[u8],
    page_offset: usize,
    ranges: &[FileRange],
) -> Result<Arm64Audit> {
    if page.len() != crate::fairplay_supf::PAGE_BYTES {
        bail!("ARM64 audit requires one complete FairPlay page");
    }
    let mut audit = Arm64Audit {
        instruction_words: 0,
        valid_words: 0,
        mnemonics: BTreeMap::new(),
    };
    if ranges.is_empty() {
        audit_words(page, &mut audit);
    } else {
        let page_end = page_offset
            .checked_add(page.len())
            .ok_or_else(|| anyhow::anyhow!("ARM64 page range overflow"))?;
        for range in ranges {
            let range_end = range
                .offset
                .checked_add(range.size)
                .ok_or_else(|| anyhow::anyhow!("ARM64 instruction range overflow"))?;
            let start = page_offset.max(range.offset).div_ceil(4) * 4;
            let end = page_end.min(range_end) / 4 * 4;
            if start < end {
                audit_words(&page[start - page_offset..end - page_offset], &mut audit);
            }
        }
    }
    if audit.instruction_words == 0
        || audit.valid_words * 100 < audit.instruction_words * MINIMUM_VALID_PERCENT
    {
        bail!(
            "first ARM64 page has only {}/{} decodable instruction words",
            audit.valid_words,
            audit.instruction_words
        );
    }
    Ok(audit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audits_arm64_code_and_rejects_non_code() {
        let mut page = vec![0u8; crate::fairplay_supf::PAGE_BYTES];
        for word in page.as_chunks_mut::<4>().0 {
            word.copy_from_slice(&0xd503_201fu32.to_le_bytes());
        }
        let audit = audit_first_page(&page, 0x4000, &[]).unwrap();
        assert_eq!(audit.valid_words, 1024);
        assert_eq!(audit.mnemonics["NOP"], 1024);
        page.fill(0xff);
        assert!(audit_first_page(&page, 0x4000, &[]).is_err());
    }

    #[test]
    fn limits_audit_to_executable_section_intersection() {
        let mut page = vec![0xff; crate::fairplay_supf::PAGE_BYTES];
        for chunk in page[0x180..0x400].as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&0xd503_201fu32.to_le_bytes());
        }
        let audit = audit_first_page(
            &page,
            0x4000,
            &[FileRange {
                offset: 0x4180,
                size: 0x280,
            }],
        )
        .unwrap();
        assert_eq!(audit.instruction_words, 0x280 / 4);
        assert_eq!(audit.valid_words, audit.instruction_words);
    }
}
