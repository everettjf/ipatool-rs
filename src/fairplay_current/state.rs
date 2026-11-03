//! Authenticated current SIDB state selection from UnfairPlay b3a7a432 (MIT).

use super::outer::{self, Layout};
use aes::{
    Aes128,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Result, bail};
use md5::Md5;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const STATE_KEY: [u8; 16] = [
    0x36, 0xc0, 0x11, 0x2f, 0xc8, 0x4c, 0x50, 0x17, 0x62, 0x7f, 0x53, 0x53, 0x35, 0xe5, 0xe7, 0xc9,
];
const STATE_IV: [u8; 16] = [
    0x1c, 0x64, 0x35, 0xdf, 0x5c, 0xe3, 0x16, 0xce, 0x0f, 0x8f, 0xd0, 0xa4, 0x17, 0x9d, 0x12, 0x56,
];
const PRODUCER_KEY: [u8; 16] = [
    0xa3, 0x22, 0xec, 0xaf, 0xa8, 0xc2, 0x68, 0xbf, 0x49, 0x3c, 0x21, 0xc5, 0xd2, 0x57, 0x65, 0xfc,
];
const INPUT_MASK: [u8; 16] = [
    0x0c, 0xc2, 0xa2, 0xea, 0xe7, 0xb1, 0x7b, 0x94, 0xb7, 0xd8, 0x82, 0x58, 0x10, 0x4b, 0xc5, 0xad,
];
const OUTPUT_MASK: [u8; 16] = [
    0xe4, 0x34, 0x93, 0x3c, 0x0b, 0x85, 0x61, 0x5e, 0x68, 0x18, 0xfa, 0x61, 0x4f, 0x2f, 0x29, 0x9c,
];
const CHAIN_MASK: [u8; 16] = [
    0x31, 0x7a, 0xa2, 0xc1, 0xa5, 0xbf, 0x38, 0xdb, 0x5d, 0x73, 0x61, 0xbc, 0x2f, 0xb9, 0x7c, 0x7e,
];

pub struct DecodedSidb {
    pub body: Zeroizing<Vec<u8>>,
    pub layout: Layout,
    pub state_sha256: String,
}

/// Advance only through the state slot selected by the native codec layout.
pub fn selected_key(source_tail: &[u8], slot: usize) -> Result<Zeroizing<[u8; 16]>> {
    if source_tail.is_empty()
        || !source_tail.len().is_multiple_of(16)
        || source_tail.len() > 18 * 16
        || slot >= source_tail.len() / 16
    {
        bail!("invalid current SIDB selected state slot");
    }
    let cipher = Aes128::new_from_slice(&STATE_KEY).expect("fixed state key");
    let mut previous = Zeroizing::new(STATE_IV);
    for block in source_tail.as_chunks::<16>().0.iter().take(slot + 1) {
        crate::application::operation::check()?;
        for i in 0..16 {
            previous[i] ^= block[i] ^ 0x1b;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut *previous));
    }
    let producer = Aes128::new_from_slice(&PRODUCER_KEY).expect("fixed producer key");
    producer.encrypt_block(GenericArray::from_mut_slice(&mut *previous));
    Ok(previous)
}

pub fn authenticate_container(container: &[u8], source: &[u8]) -> Result<()> {
    if container.len() < 16
        || source.len() < 48
        || source.len() > 320
        || !(source.len() - 32).is_multiple_of(16)
    {
        bail!("invalid current SIDB authentication geometry");
    }
    crate::application::operation::check()?;
    let key = Zeroizing::new(std::array::from_fn::<_, 16, _>(|i| source[i] ^ 0x1b));
    let cipher = Aes128::new_from_slice(&*key).expect("validated footer key");
    let end = container.len() - 16;
    let mut expected = Zeroizing::new([0u8; 16]);
    expected.copy_from_slice(&Md5::digest(&container[..end]));
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut *expected));
    if !bool::from(expected.as_slice().ct_eq(&container[end..])) {
        bail!("current SIDB container authentication failed");
    }
    Ok(())
}

/// The protected input projection and first decoder XOR cancel. Following
/// blocks chain in the projected external domain, rather than ordinary CBC.
fn decode_wire_payload(wire: &[u8], key: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>> {
    if wire.is_empty() || wire.len() > 1 << 20 || !wire.len().is_multiple_of(16) {
        bail!("invalid current SIDB payload size");
    }
    let cipher = Aes128::new_from_slice(key).expect("validated selected key");
    let mut output = Zeroizing::new(vec![0; wire.len()]);
    let mut previous = Zeroizing::new([0u8; 16]);
    for (index, chunk) in wire.as_chunks::<16>().0.iter().enumerate() {
        crate::application::operation::check()?;
        let offset = index * 16;
        let block = &mut output[offset..offset + 16];
        block.copy_from_slice(chunk);
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for i in 0..16 {
            block[i] ^= OUTPUT_MASK[i];
            if index != 0 {
                block[i] ^= previous[i] ^ INPUT_MASK[i] ^ CHAIN_MASK[i];
            }
        }
        previous.copy_from_slice(chunk);
    }
    Ok(output)
}

pub fn decode(container: &[u8], hardware: &[u8]) -> Result<DecodedSidb> {
    let derived = outer::derive_selection_source(container, hardware)?;
    authenticate_container(container, &derived.source)?;
    let key = selected_key(&derived.source[32..], derived.layout.selected_slot)?;
    let start = derived.layout.payload_offset;
    let body = decode_wire_payload(
        &container[start..start + derived.layout.payload_bytes],
        &key,
    )?;
    let mut hash = Sha256::new();
    hash.update(Sha256::digest(container));
    hash.update(&*derived.source);
    Ok(DecodedSidb {
        body,
        layout: derived.layout,
        state_sha256: format!("{:x}", hash.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticates_openssl_known_answer_and_rejects_every_changed_boundary() {
        let mut source = vec![0; 256];
        for (i, byte) in source[..16].iter_mut().enumerate() {
            *byte = i as u8 ^ 0x1b;
        }
        let mut container = vec![0, 7, 0, 11];
        container.extend(b"public synthetic authentication fixture");
        container.extend([
            0x75, 0xd6, 0x82, 0xd7, 0x3c, 0xa1, 0x53, 0x47, 0x16, 0xa0, 0x2f, 0xa2, 0x47, 0x9b,
            0x3f, 0xae,
        ]);
        authenticate_container(&container, &source).unwrap();
        for offset in [0, 4, container.len() - 1] {
            let mut changed = container.clone();
            changed[offset] ^= 1;
            assert!(authenticate_container(&changed, &source).is_err());
        }
        source[0] ^= 1;
        assert!(authenticate_container(&container, &source).is_err());
        for length in [0, 15, 32, 255, 257, 321, 336] {
            assert!(authenticate_container(&container, &vec![0; length]).is_err());
        }
    }
}
