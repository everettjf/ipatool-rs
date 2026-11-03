//! Deterministic SUPF/SUPP selection and file-origin page mapping.
//! Ported from UnfairPlay b3a7a432 internal/fairplay (MIT).

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use zeroize::Zeroizing;

use crate::{
    fairplay_macho::MachOSlice,
    fairplay_scinfo::{Trust, parse_envelope},
    fairplay_supf::{PAGE_BYTES, Supf, SupfArchitecture},
};

pub(crate) fn select(
    member: &str,
    names: &HashSet<String>,
    slices: &[MachOSlice],
    mut read: impl FnMut(&str) -> Result<Vec<u8>>,
    trust: &Trust,
) -> Result<(String, Supf)> {
    // Reuse the canonical image rule; these are archive member names, never
    // privileged filesystem paths. Root-level images retain Go's SC_Info form.
    let adjacent = crate::fairplay_licenses::adjacent_sinf(member)?;
    let base = adjacent
        .strip_suffix(".sinf")
        .expect("adjacent license suffix");
    let f_names = [format!("{base}.supf"), format!("{base}.v5.supf")];
    if f_names.iter().any(|name| names.contains(name)) {
        return select_supf(&f_names, names, &mut read);
    }
    let p_names = [format!("{base}.supp"), format!("{base}.v4.supp")];
    let mut tables = [None, None];
    for (index, name) in p_names.iter().enumerate() {
        if !names.contains(name) {
            continue;
        }
        crate::application::operation::check()?;
        let data = Zeroizing::new(read(name)?);
        let table = Supp::parse(&data, trust).with_context(|| format!("parse {name}"))?;
        if table.variant != if index == 0 { 1 } else { 4 } {
            bail!("SUPP suffix disagrees with its variant");
        }
        tables[index] = Some(table);
    }
    if let [Some(legacy), Some(current)] = &mut tables {
        if legacy.records != current.records {
            bail!("SUPP variants have different page records");
        }
        current.signature_sha1 = legacy.signature_sha1;
    }
    let index = usize::from(tables[1].is_some());
    let table = tables[index]
        .take()
        .context("encrypted image has no adjacent SUPF or SUPP")?;
    let table = table.for_slices(slices)?;
    Ok((p_names[index].clone(), table))
}

fn select_supf(
    candidates: &[String; 2],
    names: &HashSet<String>,
    read: &mut impl FnMut(&str) -> Result<Vec<u8>>,
) -> Result<(String, Supf)> {
    let mut parsed: [Option<Supf>; 2] = [None, None];
    for (index, name) in candidates.iter().enumerate() {
        if !names.contains(name) {
            continue;
        }
        crate::application::operation::check()?;
        let data = Zeroizing::new(read(name)?);
        if data.is_empty() && index == 0 {
            // Only a valid v5 companion can replace this known placeholder.
            continue;
        }
        let table = Supf::parse(&data).with_context(|| format!("parse {name}"))?;
        if table.variant != if index == 0 { 3 } else { 5 } {
            bail!("SUPF suffix disagrees with its variant");
        }
        parsed[index] = Some(table);
    }
    if let [Some(legacy), Some(current)] = &mut parsed {
        if legacy.architectures.len() != current.architectures.len() {
            bail!("SUPF variants have different architecture sets");
        }
        for arch in &mut current.architectures {
            let old = legacy
                .architectures
                .iter()
                .find(|old| old.cpu_type == arch.cpu_type && old.cpu_subtype == arch.cpu_subtype)
                .context("SUPF variants have different architecture sets")?;
            if old.records != arch.records {
                bail!("SUPF variants have different page records");
            }
            arch.signature_sha1 = old.signature_sha1;
        }
    }
    let index = usize::from(parsed[1].is_some());
    let table = parsed[index]
        .take()
        .context("empty legacy SUPF requires valid v5 SUPF")?;
    Ok((candidates[index].clone(), table))
}

struct Supp {
    variant: u8,
    records: Vec<[u8; 32]>,
    signature_sha1: Option<[u8; 20]>,
}

impl Supp {
    fn parse(data: &[u8], trust: &Trust) -> Result<Self> {
        let variant = trust.keyfile(data, true)?;
        let envelope = parse_envelope(data)?;
        let records_start = if variant == 1 { 28 } else { 8 };
        // Signed-envelope geometry was validated before allocating records.
        let records = envelope.prefix[records_start..]
            .as_chunks::<32>()
            .0
            .to_vec();
        let signature_sha1 = (variant == 1).then(|| data[4..24].try_into().unwrap());
        Ok(Self {
            variant,
            records,
            signature_sha1,
        })
    }

    fn for_slices(self, slices: &[MachOSlice]) -> Result<Supf> {
        if slices.is_empty() {
            bail!("SUPP has no Mach-O slices");
        }
        let thin = slices.len() == 1 && slices[0].offset == 0;
        let mut ranges = Vec::new();
        let mut last_end = 0;
        let mut seen = HashSet::new();
        for slice in slices {
            if slice.layout.crypt_id == 0 {
                continue;
            }
            let start = slice
                .offset
                .checked_add(slice.layout.crypt_offset)
                .context("SUPP encrypted offset overflow")?;
            let end = start
                .checked_add(slice.layout.crypt_size)
                .context("SUPP encrypted extent overflow")?;
            let slice_end = slice
                .offset
                .checked_add(slice.size)
                .context("SUPP slice extent overflow")?;
            if slice.layout.crypt_size == 0
                || !start.is_multiple_of(PAGE_BYTES)
                || !end.is_multiple_of(PAGE_BYTES)
                || end > slice_end
            {
                bail!("SUPP encrypted range has invalid geometry");
            }
            if !seen.insert((slice.layout.cpu_type, slice.layout.cpu_subtype)) {
                bail!("SUPP image has duplicate encrypted architecture");
            }
            ranges.push((slice, start / PAGE_BYTES, end / PAGE_BYTES));
            last_end = last_end.max(end / PAGE_BYTES);
        }
        if ranges.is_empty() || self.records.len() != last_end {
            bail!("SUPP record count differs from encrypted ranges");
        }
        let architectures = ranges
            .into_iter()
            .map(|(slice, start, end)| SupfArchitecture {
                cpu_type: slice.layout.cpu_type,
                cpu_subtype: slice.layout.cpu_subtype,
                records: self.records[start..end].to_vec(),
                signature_sha1: if thin { self.signature_sha1 } else { None },
            })
            .collect();
        Ok(Supf {
            variant: self.variant,
            architectures,
            universal_signature_sha1: if thin { None } else { self.signature_sha1 },
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fairplay_macho::MachOLayout;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    struct Vectors {
        authority_modulus: Vec<u8>,
        authority_exponent: Vec<u8>,
        controls: Vec<Control>,
    }
    #[derive(Deserialize)]
    struct Slice {
        offset: usize,
        size: usize,
        cpu_type: u32,
        cpu_subtype: u32,
        crypt_offset: usize,
        crypt_size: usize,
        crypt_id: u32,
        signature_offset: usize,
        signature_size: usize,
    }
    impl Slice {
        fn native(&self) -> MachOSlice {
            MachOSlice {
                offset: self.offset,
                size: self.size,
                layout: MachOLayout {
                    cpu_type: self.cpu_type,
                    cpu_subtype: self.cpu_subtype,
                    crypt_offset: self.crypt_offset,
                    crypt_size: self.crypt_size,
                    crypt_id: self.crypt_id,
                    crypt_id_offset: 0,
                    signature_offset: self.signature_offset,
                    signature_size: self.signature_size,
                    instruction_ranges: vec![],
                },
            }
        }
    }
    #[derive(Deserialize)]
    struct Signature {
        offset: usize,
        bytes: Vec<u8>,
    }
    #[derive(Deserialize)]
    struct Architecture {
        cpu_type: u32,
        cpu_subtype: u32,
        pages: usize,
        records_sha256: String,
        signature_sha1: Option<String>,
    }
    #[derive(Deserialize)]
    struct Control {
        name: String,
        files: BTreeMap<String, Vec<u8>>,
        slices: Vec<Slice>,
        accepted: bool,
        member: Option<String>,
        variant: Option<u8>,
        #[serde(default)]
        architectures: Vec<Architecture>,
        universal_signature_sha1: Option<String>,
        source_bytes: usize,
        signature_chunks: Vec<Signature>,
        changed_signature: bool,
        binding_accepted: Option<bool>,
    }
    fn vectors() -> Vectors {
        serde_json::from_str(include_str!(
            "../tests/fixtures/fairplay-key-table-public-vectors.json"
        ))
        .unwrap()
    }
    fn hash_hex(bytes: [u8; 20]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(crate) struct SignedSuppSample {
        pub trust: Trust,
        pub table: Vec<u8>,
        pub source: Vec<u8>,
        pub plaintext: Vec<u8>,
    }

    pub(crate) fn signed_supp_sample() -> SignedSuppSample {
        let vectors = vectors();
        let trust = Trust::synthetic(vectors.authority_modulus, vectors.authority_exponent);
        // This signed three-record table is too long for the corpus's one-page
        // image, but exactly covers this two-page image plus its file header.
        let control = vectors
            .controls
            .into_iter()
            .find(|control| control.name == "p too many records")
            .unwrap();
        let table = control.files["Payload/A.app/SC_Info/A.v4.supp"].clone();
        let parsed = Supp::parse(&table, &trust).unwrap();
        let (source, _, plaintext) =
            crate::fairplay_decrypt::tests::pre_encryption_fixture_with_records(
                [0x31; 16],
                parsed.records[1..].to_vec(),
            );
        SignedSuppSample {
            trust,
            table,
            source,
            plaintext,
        }
    }

    #[test]
    fn table_classes_variants_page_mapping_and_signature_bindings_match_pinned_go() {
        let vectors = vectors();
        let trust = Trust::synthetic(vectors.authority_modulus, vectors.authority_exponent);
        assert_eq!(vectors.controls.len(), 39);
        for control in vectors.controls {
            let names = control.files.keys().cloned().collect();
            let slices: Vec<_> = control.slices.iter().map(Slice::native).collect();
            let result = select(
                "Payload/A.app/A",
                &names,
                &slices,
                |name| Ok(control.files[name].clone()),
                &trust,
            );
            assert_eq!(
                result.is_ok(),
                control.accepted,
                "{}: {result:?}",
                control.name
            );
            let Ok((name, table)) = result else { continue };
            assert_eq!(Some(name), control.member, "{}", control.name);
            assert_eq!(Some(table.variant), control.variant, "{}", control.name);
            assert_eq!(
                table.architectures.len(),
                control.architectures.len(),
                "{}",
                control.name
            );
            for (actual, expected) in table.architectures.iter().zip(control.architectures) {
                assert_eq!(
                    (actual.cpu_type, actual.cpu_subtype, actual.records.len()),
                    (expected.cpu_type, expected.cpu_subtype, expected.pages),
                    "{}",
                    control.name
                );
                let mut digest = Sha256::new();
                for record in &actual.records {
                    digest.update(record);
                }
                assert_eq!(
                    format!("{:x}", digest.finalize()),
                    expected.records_sha256,
                    "{}",
                    control.name
                );
                assert_eq!(
                    actual.signature_sha1.map(hash_hex),
                    expected.signature_sha1,
                    "{}",
                    control.name
                );
            }
            assert_eq!(
                table.universal_signature_sha1.map(hash_hex),
                control.universal_signature_sha1,
                "{}",
                control.name
            );
            let mut source = vec![0; control.source_bytes];
            for chunk in &control.signature_chunks {
                source[chunk.offset..chunk.offset + chunk.bytes.len()]
                    .copy_from_slice(&chunk.bytes);
            }
            if control.changed_signature {
                source[control.signature_chunks[0].offset] ^= 1;
            }
            assert_eq!(
                Some(table.validate_signature_bindings(&source, &slices).is_ok()),
                control.binding_accepted,
                "{}",
                control.name
            );
            if matches!(table.variant, 1 | 4) {
                assert!(
                    select(
                        "Payload/A.app/A",
                        &names,
                        &slices,
                        |name| Ok(control.files[name].clone()),
                        &Trust::pinned()
                    )
                    .is_err(),
                    "test authority accepted at runtime"
                );
            }
        }
    }
}
