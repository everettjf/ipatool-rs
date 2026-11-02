//! Hardware-dependent tag constructor from UnfairPlay (MIT), b3a7a432.
//! Direct byte mixing and AES-CBC; no native image or constructor profile.

use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Result, bail};
use std::num::Wrapping;
use zeroize::Zeroizing;

pub const SEMANTIC_TAGS: [&str; 44] = [
    "sean", "vers", "grup", "head", "guid", "user", "sess", "key ", "valu", "type", "salt", "iviv",
    "sign", "tail", "itgr", "rand", "usag", "flur", "dong", "dval", "dtyp", "dsal", "dgui", "rbag",
    "time", "cfid", "poli", "leew", "dirs", "dstg", "filt", "base", "suff", "poli", "rtal", "rori",
    "rwri", "gval", "dval", "qhtz", "hi32", "drml", "mpos", "dmid",
];

/// Serialized tag words in SEMANTIC_TAGS order. The result is private: it is
/// hardware dependent even though the algorithm and its constants are public.
pub fn generate_codebook(hardware: &[u8]) -> Result<Zeroizing<[u32; 44]>> {
    if hardware.len() != 6 {
        bail!("tag constructor requires a six-byte hardware identity");
    }
    crate::application::operation::check()?;
    let mut state = Zeroizing::new([0u8; 256]);
    for (i, byte) in state.iter_mut().enumerate() {
        let (q, r) = (i / 6, i % 6);
        let shift = ((q ^ ((q & 2) << 1)) + 5 * q * r) & 7;
        *byte = hardware[r].rotate_left(shift as u32);
    }
    for iteration in 0..2569 + 256 * usize::from(hardware[3] % 7) {
        crate::application::operation::check()?;
        mix_step(&mut state, iteration);
    }
    let cipher = Aes128::new_from_slice(&[
        0x8c, 0x92, 0x0e, 0x14, 0x8b, 0x4f, 0x48, 0xa6, 0x2f, 0x8a, 0x54, 0x97, 0x95, 0x23, 0x38,
        0xcd,
    ])
    .expect("fixed AES-128 algorithm key");
    let mut chain = Zeroizing::new(std::array::from_fn::<_, 16, _>(|i| i as u8));
    for chunk in state.as_chunks_mut::<16>().0 {
        crate::application::operation::check()?;
        for i in 0..16 {
            chunk[i] ^= chain[i];
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        chain.copy_from_slice(chunk);
    }
    let mut result = Zeroizing::new([0u32; 44]);
    for i in 0..result.len() {
        let value = u32::from_be_bytes(state[4 * i..4 * i + 4].try_into().unwrap())
            .wrapping_mul(0x75f58395)
            .wrapping_add(0x84bed201);
        if result[..i].contains(&value) {
            bail!("ambiguous tag constructor codebook");
        }
        result[i] = value;
    }
    Ok(result)
}

fn mix_step(state: &mut [u8; 256], iteration: usize) {
    // Indexed stores intentionally precede later reads, including aliases.
    let i = iteration & 255;
    match state[i] & 3 {
        0 => {
            let x = Wrapping(u32::from(state[i]));
            let y = Wrapping(u32::from(state[(5 * i + 8) & 255]));
            let (x2, y2) = (x * x, y * y);
            let p = y
                + Wrapping(231) * x * y2
                + x2 * y2 * y
                + Wrapping(11) * x2 * x * y2 * y2 * y
                + Wrapping(117) * x2 * x2 * x;
            // The native polynomial wraps before its signed remainder.
            let r = ((p.0 as i32) % 599) as u32;
            let index = r.wrapping_mul(129).wrapping_add(201) as u8;
            state[i] = SUBSTITUTION[usize::from(index)] ^ 0x1b;
        }
        1 => {
            let x = Wrapping((u32::from(state[i]) << 8) | u32::from(state[(i + 3) & 255]));
            let y =
                Wrapping((u32::from(state[(i + 5) & 255]) << 8) | u32::from(state[(i + 9) & 255]));
            let (x2, y2) = (x * x, y * y);
            let n = Wrapping(0x7e0d)
                + Wrapping(0xf707) * x * y2 * y2 * y
                + Wrapping(0xa14b) * x2 * x2 * x * y;
            state[i] = ((n.0 as i32) % 0xf6eb) as u8;
        }
        case => {
            if case == 2 {
                state[i] =
                    21u8.wrapping_sub(5u8.wrapping_mul(SUBSTITUTION[usize::from(state[i])] ^ 0x1b));
                state[i] = (state[i] ^ state[(i + 11) & 255]).wrapping_add(1);
            }
            state[i] = state[i].rotate_right(u32::from(state[(i + 1) & 255]));
            let p = Wrapping(
                (u32::from(state[i]) << 24)
                    | (u32::from(state[(i + 17) & 255]) << 16)
                    | (u32::from(state[(2 * i) & 255]) << 8)
                    | u32::from(state[(i * i + 17) & 255]),
            );
            let x = p + ((p << 3) ^ (p >> 5));
            let (y, z) = (x >> 8, x >> 16);
            let (y2, z2) = (y * y, z * z);
            state[i] = (x * x * x + y2 * y2 * y + z2 * z2 * z2 * z + z).0 as u8;
        }
    }
}

// Public substitution table from the mapped reference constructor.
const SUBSTITUTION: [u8; 256] = [
    0xa4, 0x24, 0xf0, 0xde, 0x86, 0x8b, 0x16, 0xbb, 0x27, 0x32, 0x0b, 0xfa, 0x76, 0x4b, 0xdb, 0x43,
    0x6b, 0x41, 0x2a, 0x8d, 0x19, 0xb6, 0x97, 0x98, 0x13, 0xa5, 0xb3, 0x71, 0x09, 0x69, 0x83, 0x3c,
    0x77, 0x89, 0x08, 0xbe, 0x40, 0xbf, 0x5b, 0xda, 0xdd, 0x9e, 0x9b, 0x46, 0x51, 0x3d, 0xeb, 0x90,
    0x0d, 0x88, 0xab, 0xe6, 0xfd, 0xc3, 0x54, 0xae, 0x0f, 0x20, 0x60, 0x96, 0x95, 0xf9, 0x56, 0x8e,
    0xad, 0xb4, 0x6c, 0xed, 0x36, 0x4d, 0xc6, 0x68, 0xf1, 0x9f, 0x3a, 0x50, 0x58, 0xe3, 0x17, 0x1d,
    0x1c, 0xd9, 0x1e, 0x5a, 0x3e, 0x39, 0xe7, 0xb2, 0xc2, 0xe9, 0x48, 0xc7, 0x63, 0x21, 0x52, 0x2f,
    0xd3, 0xe0, 0x37, 0x38, 0xea, 0x14, 0xb0, 0xa1, 0x00, 0x5e, 0x8a, 0xd6, 0x57, 0x6e, 0x79, 0x87,
    0x78, 0x1f, 0x6f, 0xc4, 0x93, 0x30, 0x23, 0x2c, 0x2b, 0xc5, 0x22, 0xfc, 0x2d, 0x35, 0xe8, 0xa3,
    0x81, 0x8f, 0x45, 0x73, 0xe5, 0xf8, 0x44, 0x7f, 0xb7, 0x92, 0x0a, 0xe4, 0xc0, 0x74, 0xf2, 0x4c,
    0x9a, 0xce, 0xb5, 0x7b, 0x6a, 0xcd, 0x7c, 0x94, 0x75, 0xf4, 0xbd, 0xcb, 0x64, 0x66, 0x62, 0xbc,
    0xb9, 0x6d, 0x05, 0xc9, 0xdc, 0xef, 0xca, 0xf7, 0x72, 0xd1, 0x03, 0x5f, 0xcf, 0xfe, 0x18, 0xaf,
    0xd7, 0xdf, 0xe1, 0x82, 0xe2, 0xc1, 0x61, 0x34, 0xa8, 0x85, 0x2e, 0x9d, 0x53, 0x07, 0xfb, 0x33,
    0x55, 0xaa, 0x0e, 0x26, 0x5c, 0x25, 0x9c, 0xa7, 0x10, 0x80, 0x1a, 0xcc, 0xd5, 0x29, 0xc8, 0xa6,
    0xf6, 0x7d, 0x5d, 0xf5, 0x04, 0x47, 0x4e, 0x49, 0x70, 0xd8, 0xa2, 0xd2, 0xd4, 0x3b, 0x67, 0x28,
    0x0c, 0x31, 0x4a, 0x06, 0x3f, 0x99, 0x12, 0xec, 0xac, 0x11, 0xa0, 0xd0, 0x01, 0x4f, 0x91, 0x59,
    0xb8, 0x02, 0x7a, 0xa9, 0xb1, 0xba, 0x8c, 0x15, 0x1b, 0x7e, 0x65, 0xee, 0x84, 0xff, 0xf3, 0x42,
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn matches_pinned_go_codebooks_for_public_synthetic_identities() {
        #[derive(serde::Deserialize)]
        struct Vector {
            hardware: Vec<u8>,
            sha256: String,
        }
        let vectors: Vec<Vector> = serde_json::from_str(include_str!(
            "../../tests/fixtures/fairplay-current-tag-public-vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors.len(), 32);
        for vector in vectors {
            let before = vector.hardware.clone();
            let codebook = generate_codebook(&vector.hardware).unwrap();
            let mut hash = Sha256::new();
            for word in codebook.iter() {
                hash.update(word.to_be_bytes());
            }
            assert_eq!(format!("{:x}", hash.finalize()), vector.sha256);
            assert_eq!(vector.hardware, before);
        }
    }

    #[test]
    fn rejects_invalid_identity_and_observes_cancellation() {
        for length in [0, 5, 7] {
            assert!(generate_codebook(&vec![0; length]).is_err());
        }
        let operation = crate::application::operation::Operation::default();
        let result = operation.run(|| {
            operation.cancel();
            generate_codebook(&[0, 1, 2, 3, 4, 5])
        });
        assert!(
            result
                .unwrap_err()
                .is::<crate::application::operation::Cancelled>()
        );
    }
}
