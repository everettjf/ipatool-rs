//! Build a selector-bound FPSENR3 model from recovered 26B118 buffers.

use aes::{
    Aes128,
    cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Context, Result, bail};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    fairplay::{SinfSelector, parse_sinf_selector},
    fairplay_enrollment_model::FIRST_TRANSFORM_BYTES,
    fairplay_key::{CurrentSinfModel, logical_from_inner, validate_v3_plaintext},
    fairplay_recovery::Recovery,
};

const OUTPUT_ENCODING_OFFSET: usize = 68 + 16;
const OUTPUT_MASK_OFFSET: usize = OUTPUT_ENCODING_OFFSET + 16 * 256;
const POST_DECODE_OFFSET: usize = OUTPUT_MASK_OFFSET + FIRST_TRANSFORM_BYTES;
pub const FPSENR3_BYTES: usize = POST_DECODE_OFFSET + 16 * 256;

#[derive(Clone, Copy)]
pub struct V3Material<'a> {
    pub recovered: &'a Recovery,
    pub selector: SinfSelector,
    pub fairplayd_sha256: [u8; 32],
    pub source_offset: i32,
    pub final_xor: u8,
    pub whitebox_entry: &'a [u8; FIRST_TRANSFORM_BYTES],
    pub postcodec_entry: &'a [u8; FIRST_TRANSFORM_BYTES],
    pub postcodec_exit: &'a [u8; FIRST_TRANSFORM_BYTES],
    pub sinf: &'a [u8],
}

pub fn build_fpsenr3(material: V3Material<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let V3Material {
        recovered,
        selector,
        fairplayd_sha256,
        source_offset,
        final_xor,
        whitebox_entry,
        postcodec_entry,
        postcodec_exit,
        sinf,
    } = material;
    if source_offset < 0 {
        bail!("version-3 SINF source offset must be nonnegative");
    }
    if parse_sinf_selector(sinf)? != selector {
        bail!("version-3 SINF fixture selector does not match the enrollment");
    }
    recovered.input_encoding.check_permutation()?;
    recovered.output_encoding.check_permutation()?;
    let input_decode = recovered.input_encoding.inverse()?;
    let mut plaintext = Zeroizing::new([0u8; FIRST_TRANSFORM_BYTES]);
    for (index, byte) in postcodec_exit.iter().enumerate() {
        plaintext[index] = byte ^ final_xor;
    }
    validate_v3_plaintext(&plaintext)?;
    let inner = Zeroizing::new(plaintext[24..40].try_into().unwrap());
    let expected_logical = Zeroizing::new(logical_from_inner(&inner));

    let period: [u8; 16] =
        core::array::from_fn(|index| postcodec_entry[index] ^ postcodec_exit[index]);
    for index in 0..FIRST_TRANSFORM_BYTES {
        if postcodec_entry[index] ^ postcodec_exit[index] != period[index % 16] {
            bail!("version-3 post-codec is not a sixteen-byte XOR period");
        }
    }
    let cipher = Aes128::new_from_slice(&recovered.key).context("invalid recovered AES key")?;
    let mut masks = Zeroizing::new([0u8; FIRST_TRANSFORM_BYTES]);
    for block_index in 0..FIRST_TRANSFORM_BYTES / 16 {
        let start = block_index * 16;
        let mut logical = Zeroizing::new([0u8; 16]);
        for position in 0..16 {
            logical[position] = input_decode.0[position][whitebox_entry[start + position] as usize];
        }
        let mut internal = GenericArray::clone_from_slice(&*logical);
        cipher.decrypt_block(&mut internal);
        for position in 0..16 {
            let base = recovered.output_encoding.0[position][internal[position] as usize];
            masks[start + position] = base ^ postcodec_entry[start + position];
        }
        internal.as_mut_slice().zeroize();
    }
    if masks[..16].iter().any(|byte| *byte != 0) {
        bail!("version-3 block-zero output mask is not zero");
    }
    let mut bytes = Zeroizing::new(vec![0u8; FPSENR3_BYTES]);
    bytes[..8].copy_from_slice(b"FPSENR3\0");
    bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&(FPSENR3_BYTES as u32).to_le_bytes());
    bytes[16..48].copy_from_slice(&fairplayd_sha256);
    bytes[48..52].copy_from_slice(&selector.user.to_le_bytes());
    bytes[52..56].copy_from_slice(&selector.key.to_le_bytes());
    bytes[56..60].copy_from_slice(&source_offset.to_le_bytes());
    bytes[60..64].copy_from_slice(&(FIRST_TRANSFORM_BYTES as u32).to_le_bytes());
    bytes[64] = final_xor;
    bytes[68..84].copy_from_slice(&recovered.key);
    for position in 0..16 {
        bytes[OUTPUT_ENCODING_OFFSET + position * 256
            ..OUTPUT_ENCODING_OFFSET + (position + 1) * 256]
            .copy_from_slice(&recovered.output_encoding.0[position]);
    }
    bytes[OUTPUT_MASK_OFFSET..POST_DECODE_OFFSET].copy_from_slice(&*masks);
    for position in 0..16 {
        for value in 0..=255 {
            bytes[POST_DECODE_OFFSET + position * 256 + value] = value as u8 ^ period[position];
        }
    }
    let model = CurrentSinfModel::parse(&bytes)?;
    let actual_logical = Zeroizing::new(model.logical_key(sinf)?);
    if *actual_logical != *expected_logical {
        bail!("version-3 SINF fixture logical key does not match recovered material");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_recovery_math::Encoding;
    use aes::cipher::BlockEncrypt;

    fn atom(name: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(body.len() + 8);
        result.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
        result.extend_from_slice(&name);
        result.extend_from_slice(body);
        result
    }

    #[test]
    fn derives_v3_masks_and_decodes_bound_sinf_with_nonidentity_encodings() {
        let recovered = Recovery {
            key: [0x24; 16],
            input_encoding: Encoding::affine([2; 16], core::array::from_fn(|index| index as u8)),
            output_encoding: Encoding::affine(
                [3; 16],
                core::array::from_fn(|index| (index * 7) as u8),
            ),
            milliseconds: 0.0,
        };
        let selector = SinfSelector { user: 11, key: 13 };
        let mut plaintext = [0u8; FIRST_TRANSFORM_BYTES];
        plaintext[..4].copy_from_slice(b"itun");
        plaintext[4..8].copy_from_slice(&12u32.to_be_bytes());
        plaintext[8..12].copy_from_slice(b"vers");
        plaintext[12..16].copy_from_slice(&1u32.to_be_bytes());
        for (offset, size, name) in [
            (16, 24u32, *b"key "),
            (40, 24, *b"iviv"),
            (64, 24, *b"tmpr"),
            (88, 88, *b"righ"),
            (176, 264, *b"name"),
        ] {
            plaintext[offset..offset + 4].copy_from_slice(&size.to_be_bytes());
            plaintext[offset + 4..offset + 8].copy_from_slice(&name);
        }
        let inner: [u8; 16] = core::array::from_fn(|index| index as u8);
        plaintext[24..40].copy_from_slice(&inner);
        let final_xor = 0x98;
        let post_exit = plaintext.map(|byte| byte ^ final_xor);
        let period: [u8; 16] = core::array::from_fn(|index| (index * 3) as u8);
        let post_entry: [u8; FIRST_TRANSFORM_BYTES] =
            core::array::from_fn(|index| post_exit[index] ^ period[index % 16]);
        let mut whitebox_entry: [u8; FIRST_TRANSFORM_BYTES] =
            core::array::from_fn(|index| index as u8);
        let inverse_output = recovered.output_encoding.inverse().unwrap();
        let internal = inverse_output.encode(post_entry[..16].try_into().unwrap());
        let cipher = Aes128::new_from_slice(&recovered.key).unwrap();
        let mut logical = GenericArray::clone_from_slice(&internal);
        cipher.encrypt_block(&mut logical);
        whitebox_entry[..16].copy_from_slice(
            &recovered
                .input_encoding
                .encode(logical.as_slice().try_into().unwrap()),
        );

        let source_offset = 0x1e0;
        let mut private = vec![0u8; source_offset as usize - 48];
        let input_decode = recovered.input_encoding.inverse().unwrap();
        let sinf_source: [u8; FIRST_TRANSFORM_BYTES] = core::array::from_fn(|index| {
            input_decode.0[index % 16][whitebox_entry[index] as usize]
        });
        private.extend_from_slice(&sinf_source);
        private.extend_from_slice(&[0; 8]);
        let mut fields = Vec::new();
        fields.extend(atom(*b"user", &selector.user.to_be_bytes()));
        fields.extend(atom(*b"key ", &selector.key.to_be_bytes()));
        fields.extend(atom(*b"priv", &private));
        let sinf = atom(*b"sinf", &atom(*b"schi", &fields));

        let material = V3Material {
            recovered: &recovered,
            selector,
            fairplayd_sha256: [0xa5; 32],
            source_offset,
            final_xor,
            whitebox_entry: &whitebox_entry,
            postcodec_entry: &post_entry,
            postcodec_exit: &post_exit,
            sinf: &sinf,
        };
        let model = build_fpsenr3(material).unwrap();
        assert_eq!(model.len(), FPSENR3_BYTES);
        assert_eq!(&model[..8], b"FPSENR3\0");
        assert_eq!(&model[68..84], &recovered.key);
        assert_eq!(
            CurrentSinfModel::parse(&model)
                .unwrap()
                .logical_key(&sinf)
                .unwrap(),
            logical_from_inner(&inner)
        );
        let mut bad_post_entry = post_entry;
        bad_post_entry[17] ^= 1;
        assert!(
            build_fpsenr3(V3Material {
                postcodec_entry: &bad_post_entry,
                ..material
            })
            .is_err()
        );
        let mut bad_sinf = sinf.clone();
        bad_sinf[source_offset as usize] ^= 1;
        assert!(
            build_fpsenr3(V3Material {
                sinf: &bad_sinf,
                ..material
            })
            .is_err()
        );
    }
}
