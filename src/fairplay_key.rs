//! Decode a selector-bound FairPlay enrollment model and personalized SINF.

use aes::{
    Aes128,
    cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

use crate::fairplay::SinfSelector;

const TABLE_BYTES: usize = 16 * 256;
const V3_SOURCE_BYTES: usize = 27 * 16;
const V1_BYTES: usize = 8 + 4 + 4 + 32 + 16 + 16 + TABLE_BYTES;
const V2_BYTES: usize = 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + TABLE_BYTES;
const V3_BYTES: usize =
    8 + 4 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 16 + TABLE_BYTES + V3_SOURCE_BYTES + TABLE_BYTES;

pub struct CurrentSinfModel {
    version: u32,
    selector: Option<SinfSelector>,
    key: [u8; 16],
    whitening: [u8; 16],
    input_decode: [u8; TABLE_BYTES],
    source_offset: usize,
    output_encode: [u8; TABLE_BYTES],
    output_mask: [u8; V3_SOURCE_BYTES],
    post_decode: [u8; TABLE_BYTES],
    final_xor: u8,
}

impl Drop for CurrentSinfModel {
    fn drop(&mut self) {
        self.key.zeroize();
        self.whitening.zeroize();
        self.input_decode.zeroize();
        self.output_encode.zeroize();
        self.output_mask.zeroize();
        self.post_decode.zeroize();
        self.final_xor.zeroize();
    }
}

impl CurrentSinfModel {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 16
            || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize != bytes.len()
        {
            bail!("invalid current SINF model envelope");
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let (payload, selector, source_offset, final_xor) =
            match (bytes.len(), &bytes[..8], version) {
                (V1_BYTES, b"FPS26A4\0" | b"FPSENR1\0", 1) => (48, None, 0, 0),
                (V2_BYTES, b"FPSENR2\0", 2) => (56, Some(selector_from_model(bytes)), 0, 0),
                (V3_BYTES, b"FPSENR3\0", 3) => {
                    let offset = i32::from_le_bytes(bytes[56..60].try_into().unwrap());
                    let length = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
                    if offset < 0 || length != V3_SOURCE_BYTES || bytes[65..68] != [0, 0, 0] {
                        bail!("invalid current SINF version 3 geometry");
                    }
                    (
                        68,
                        Some(selector_from_model(bytes)),
                        offset as usize,
                        bytes[64],
                    )
                }
                _ => bail!("invalid current SINF model envelope"),
            };
        let mut model = Self {
            version,
            selector,
            key: bytes[payload..payload + 16].try_into().unwrap(),
            whitening: [0; 16],
            input_decode: [0; TABLE_BYTES],
            source_offset,
            output_encode: [0; TABLE_BYTES],
            output_mask: [0; V3_SOURCE_BYTES],
            post_decode: [0; TABLE_BYTES],
            final_xor,
        };
        if version < 3 {
            model
                .whitening
                .copy_from_slice(&bytes[payload + 16..payload + 32]);
            model.input_decode.copy_from_slice(&bytes[payload + 32..]);
            validate_permutations(&model.input_decode)?;
        } else {
            let mut cursor = payload + 16;
            model
                .output_encode
                .copy_from_slice(&bytes[cursor..cursor + TABLE_BYTES]);
            cursor += TABLE_BYTES;
            model
                .output_mask
                .copy_from_slice(&bytes[cursor..cursor + V3_SOURCE_BYTES]);
            cursor += V3_SOURCE_BYTES;
            model.post_decode.copy_from_slice(&bytes[cursor..]);
            validate_permutations(&model.output_encode)?;
            validate_permutations(&model.post_decode)?;
        }
        Ok(model)
    }

    pub fn logical_key(&self, sinf: &[u8]) -> Result<[u8; 16]> {
        let (selector, private) = sinf_private(sinf)?;
        if self.selector.is_some_and(|expected| expected != selector) {
            bail!("SINF selector does not match the FairPlay model");
        }
        let inner = if self.version < 3 {
            self.legacy_inner_key(&sinf[private.start..private.end])?
        } else {
            self.v3_inner_key(sinf, private)?
        };
        Ok(logical_from_inner(&inner))
    }

    fn legacy_inner_key(&self, source: &[u8]) -> Result<[u8; 16]> {
        if source.len() < 48 {
            bail!("SINF priv source is too short for selected model");
        }
        let body = source.len() - 16;
        let trailer = body % 16;
        let ciphertext = body - trailer;
        if ciphertext < 32 || !matches!(trailer, 0 | 8) {
            bail!("SINF priv block geometry does not match selected model");
        }
        let encoded = 16 + ciphertext;
        if source[encoded..].iter().any(|byte| *byte != 0) {
            bail!("SINF priv trailer does not match selected model");
        }
        let mut logical = zeroize::Zeroizing::new(vec![0u8; encoded]);
        for (index, value) in source[..encoded].iter().enumerate() {
            let position = index % 16;
            logical[index] =
                self.input_decode[position * 256 + (value ^ self.whitening[position]) as usize];
        }
        let cipher = Aes128::new_from_slice(&self.key).context("invalid FairPlay model AES key")?;
        let mut plaintext = zeroize::Zeroizing::new(vec![0u8; ciphertext + trailer]);
        let mut previous: [u8; 16] = logical[..16].try_into().unwrap();
        for (index, chunk) in logical[16..].as_chunks::<16>().0.iter().enumerate() {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for offset in 0..16 {
                plaintext[index * 16 + offset] = block[offset] ^ previous[offset];
            }
            previous.copy_from_slice(chunk);
        }
        validate_legacy_plaintext(&plaintext)
    }

    fn v3_inner_key(&self, sinf: &[u8], private: AtomSpan) -> Result<[u8; 16]> {
        let end = self
            .source_offset
            .checked_add(V3_SOURCE_BYTES)
            .context("FairPlay source offset overflow")?;
        if self.source_offset < private.start
            || self.source_offset > private.end
            || end > sinf.len()
        {
            bail!("SINF version 3 source has invalid bounds");
        }
        let source = &sinf[self.source_offset..end];
        let cipher = Aes128::new_from_slice(&self.key).context("invalid FairPlay model AES key")?;
        let mut plaintext = zeroize::Zeroizing::new([0u8; V3_SOURCE_BYTES]);
        for (index, chunk) in source.as_chunks::<16>().0.iter().enumerate() {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for position in 0..16 {
                let byte_index = index * 16 + position;
                let external = self.output_encode[position * 256 + block[position] as usize]
                    ^ self.output_mask[byte_index];
                plaintext[byte_index] =
                    self.post_decode[position * 256 + external as usize] ^ self.final_xor;
            }
        }
        validate_v3_plaintext(&plaintext)?;
        Ok(plaintext[24..40].try_into().unwrap())
    }
}

fn selector_from_model(bytes: &[u8]) -> SinfSelector {
    SinfSelector {
        user: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
        key: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
    }
}

fn validate_permutations(tables: &[u8]) -> Result<()> {
    for (index, table) in tables.as_chunks::<256>().0.iter().enumerate() {
        let mut seen = [false; 256];
        for byte in table {
            if seen[*byte as usize] {
                bail!("FairPlay model table {index} is not a permutation");
            }
            seen[*byte as usize] = true;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AtomSpan {
    typ: [u8; 4],
    start: usize,
    end: usize,
}

fn atoms(bytes: &[u8], start: usize, end: usize) -> Result<Vec<AtomSpan>> {
    let mut result = Vec::new();
    let mut cursor = start;
    while cursor < end {
        if end - cursor < 8 {
            bail!("SINF atom list has a truncated header");
        }
        let size = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        if size < 8 || size > end - cursor {
            bail!("SINF atom has invalid bounds");
        }
        result.push(AtomSpan {
            typ: bytes[cursor + 4..cursor + 8].try_into().unwrap(),
            start: cursor + 8,
            end: cursor + size,
        });
        cursor += size;
    }
    Ok(result)
}

fn unique(atoms: &[AtomSpan], typ: [u8; 4]) -> Result<AtomSpan> {
    let mut found = atoms.iter().copied().filter(|atom| atom.typ == typ);
    match (found.next(), found.next()) {
        (Some(atom), None) => Ok(atom),
        _ => bail!(
            "SINF does not contain exactly one {} atom",
            String::from_utf8_lossy(&typ)
        ),
    }
}

fn sinf_private(bytes: &[u8]) -> Result<(SinfSelector, AtomSpan)> {
    let roots = atoms(bytes, 0, bytes.len())?;
    if roots.len() != 1 || roots[0].typ != *b"sinf" {
        bail!("SINF must contain one complete root atom");
    }
    let children = atoms(bytes, roots[0].start, roots[0].end)?;
    let schi = unique(&children, *b"schi")?;
    let fields = atoms(bytes, schi.start, schi.end)?;
    let user = unique(&fields, *b"user")?;
    let key = unique(&fields, *b"key ")?;
    if user.end - user.start != 4 || key.end - key.start != 4 {
        bail!("SINF selector has invalid geometry");
    }
    Ok((
        SinfSelector {
            user: u32::from_be_bytes(bytes[user.start..user.end].try_into().unwrap()),
            key: u32::from_be_bytes(bytes[key.start..key.end].try_into().unwrap()),
        },
        unique(&fields, *b"priv")?,
    ))
}

fn validate_legacy_plaintext(plaintext: &[u8]) -> Result<[u8; 16]> {
    let expected: [([u8; 4], &[usize]); 5] = [
        (*b"key ", &[24]),
        (*b"iviv", &[24]),
        (*b"tmpr", &[24]),
        (*b"righ", &[88, 96]),
        (*b"name", &[264]),
    ];
    let mut cursor = 0;
    let mut key = [0u8; 16];
    for (index, (typ, sizes)) in expected.iter().enumerate() {
        if plaintext.len().saturating_sub(cursor) < 8 {
            bail!("FairPlay plaintext atom is truncated");
        }
        let size = u32::from_be_bytes(plaintext[cursor..cursor + 4].try_into().unwrap()) as usize;
        if !sizes.contains(&size)
            || size > plaintext.len() - cursor
            || plaintext[cursor + 4..cursor + 8] != *typ
        {
            bail!("FairPlay plaintext has invalid atom geometry");
        }
        if index == 0 {
            key.copy_from_slice(&plaintext[cursor + 8..cursor + 24]);
        }
        cursor += size;
    }
    if cursor != plaintext.len() {
        bail!("FairPlay plaintext has trailing data");
    }
    Ok(key)
}

fn validate_v3_plaintext(bytes: &[u8; V3_SOURCE_BYTES]) -> Result<()> {
    if &bytes[..4] != b"itun"
        || u32::from_be_bytes(bytes[4..8].try_into().unwrap()) != 12
        || &bytes[8..12] != b"vers"
        || u32::from_be_bytes(bytes[12..16].try_into().unwrap()) != 1
    {
        bail!("FairPlay version 3 plaintext has invalid header");
    }
    for (offset, size, typ) in [
        (16, 24, *b"key "),
        (40, 24, *b"iviv"),
        (64, 24, *b"tmpr"),
        (88, 88, *b"righ"),
        (176, 264, *b"name"),
    ] {
        if u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) != size
            || bytes[offset + 4..offset + 8] != typ
        {
            bail!("FairPlay version 3 plaintext has invalid atom geometry");
        }
    }
    if 176 + u32::from_be_bytes(bytes[176..180].try_into().unwrap()) as usize != bytes.len() + 8 {
        bail!("FairPlay version 3 plaintext has invalid name geometry");
    }
    Ok(())
}

pub fn logical_from_inner(inner: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for word in 0..4 {
        let decoded = u32::from_be_bytes(inner[word * 4..word * 4 + 4].try_into().unwrap());
        let logical = decoded.wrapping_add((13 + word as u32).wrapping_mul(0xa6b13d89));
        result[word * 4..word * 4 + 4].copy_from_slice(&logical.to_le_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    fn atom(typ: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(payload.len() + 8);
        result.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
        result.extend_from_slice(&typ);
        result.extend_from_slice(payload);
        result
    }

    fn sinf(selector: SinfSelector, private: &[u8]) -> Vec<u8> {
        let mut fields = Vec::new();
        fields.extend(atom(*b"user", &selector.user.to_be_bytes()));
        fields.extend(atom(*b"key ", &selector.key.to_be_bytes()));
        fields.extend(atom(*b"priv", private));
        atom(*b"sinf", &atom(*b"schi", &fields))
    }

    fn identity_tables(bytes: &mut [u8]) {
        for table in bytes.as_chunks_mut::<256>().0 {
            for (index, value) in table.iter_mut().enumerate() {
                *value = index as u8;
            }
        }
    }

    fn v1_model(key: [u8; 16]) -> Vec<u8> {
        let mut model = vec![0u8; V1_BYTES];
        model[..8].copy_from_slice(b"FPSENR1\0");
        model[8..12].copy_from_slice(&1u32.to_le_bytes());
        model[12..16].copy_from_slice(&(V1_BYTES as u32).to_le_bytes());
        model[48..64].copy_from_slice(&key);
        identity_tables(&mut model[80..]);
        model
    }

    fn inner_key() -> [u8; 16] {
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56,
            0x34, 0x12,
        ]
    }

    #[test]
    fn derives_legacy_logical_key_and_rejects_corrupt_model() {
        let aes_key = [0x42; 16];
        let model_bytes = v1_model(aes_key);
        let cipher = Aes128::new_from_slice(&aes_key).unwrap();
        let mut plaintext = Vec::new();
        for (index, (typ, size)) in [
            (*b"key ", 24),
            (*b"iviv", 24),
            (*b"tmpr", 24),
            (*b"righ", 88),
            (*b"name", 264),
        ]
        .into_iter()
        .enumerate()
        {
            let mut body = vec![0u8; size - 8];
            if index == 0 {
                body.copy_from_slice(&inner_key());
            }
            plaintext.extend(atom(typ, &body));
        }
        assert_eq!(plaintext.len(), 424);
        let iv = [0x11; 16];
        let mut protected = iv.to_vec();
        let mut previous = iv;
        for block in plaintext[..416].as_chunks::<16>().0 {
            let mut encrypted = GenericArray::clone_from_slice(block);
            for offset in 0..16 {
                encrypted[offset] ^= previous[offset];
            }
            cipher.encrypt_block(&mut encrypted);
            protected.extend_from_slice(&encrypted);
            previous.copy_from_slice(&encrypted);
        }
        protected.extend_from_slice(&plaintext[416..]);
        let selector = SinfSelector { user: 7, key: 9 };
        let sinf = sinf(selector, &protected);
        let model = CurrentSinfModel::parse(&model_bytes).unwrap();
        assert_eq!(
            model.logical_key(&sinf).unwrap(),
            logical_from_inner(&inner_key())
        );

        let mut corrupt = model_bytes;
        corrupt[81] = corrupt[80];
        assert!(CurrentSinfModel::parse(&corrupt).is_err());
        let mut corrupt_sinf = sinf;
        *corrupt_sinf.last_mut().unwrap() = 0xff;
        assert!(model.logical_key(&corrupt_sinf).is_err());
    }

    #[test]
    fn derives_version_three_key_with_bound_selector() {
        let aes_key = [0x24; 16];
        let cipher = Aes128::new_from_slice(&aes_key).unwrap();
        let mut plaintext = [0u8; V3_SOURCE_BYTES];
        plaintext[..4].copy_from_slice(b"itun");
        plaintext[4..8].copy_from_slice(&12u32.to_be_bytes());
        plaintext[8..12].copy_from_slice(b"vers");
        plaintext[12..16].copy_from_slice(&1u32.to_be_bytes());
        for (offset, size, typ) in [
            (16, 24u32, *b"key "),
            (40, 24, *b"iviv"),
            (64, 24, *b"tmpr"),
            (88, 88, *b"righ"),
            (176, 264, *b"name"),
        ] {
            plaintext[offset..offset + 4].copy_from_slice(&size.to_be_bytes());
            plaintext[offset + 4..offset + 8].copy_from_slice(&typ);
        }
        plaintext[24..40].copy_from_slice(&inner_key());
        let mut private = Vec::new();
        for block in plaintext.as_chunks::<16>().0 {
            let mut encrypted = GenericArray::clone_from_slice(block);
            cipher.encrypt_block(&mut encrypted);
            private.extend_from_slice(&encrypted);
        }
        private.extend_from_slice(&[0; 8]);
        let selector = SinfSelector { user: 11, key: 13 };
        let sinf = sinf(selector, &private);
        let (_, span) = sinf_private(&sinf).unwrap();
        let mut model = vec![0u8; V3_BYTES];
        model[..8].copy_from_slice(b"FPSENR3\0");
        model[8..12].copy_from_slice(&3u32.to_le_bytes());
        model[12..16].copy_from_slice(&(V3_BYTES as u32).to_le_bytes());
        model[48..52].copy_from_slice(&selector.user.to_le_bytes());
        model[52..56].copy_from_slice(&selector.key.to_le_bytes());
        model[56..60].copy_from_slice(&(span.start as u32).to_le_bytes());
        model[60..64].copy_from_slice(&(V3_SOURCE_BYTES as u32).to_le_bytes());
        model[68..84].copy_from_slice(&aes_key);
        identity_tables(&mut model[84..84 + TABLE_BYTES]);
        identity_tables(&mut model[84 + TABLE_BYTES + V3_SOURCE_BYTES..]);
        let parsed = CurrentSinfModel::parse(&model).unwrap();
        assert_eq!(
            parsed.logical_key(&sinf).unwrap(),
            logical_from_inner(&inner_key())
        );
        model[48] ^= 1;
        assert!(
            CurrentSinfModel::parse(&model)
                .unwrap()
                .logical_key(&sinf)
                .is_err()
        );
    }
}
