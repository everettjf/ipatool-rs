//! Build a selector-bound FPSENR2 enrollment model from a recovered AES model
//! and the checked 26A428 first transform's 432-byte input/output blocks.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::{
    fairplay::{SinfSelector, parse_sinf_selector},
    fairplay_key::CurrentSinfModel,
    fairplay_recovery::Recovery,
};

pub const FIRST_TRANSFORM_BYTES: usize = 27 * 16;
pub const FPSENR2_BYTES: usize = 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16 * 256;

/// A SINF and its independently known 16-byte logical key.
pub struct EnrollmentFixture<'a> {
    pub sinf: &'a [u8],
    pub logical_key: [u8; 16],
}

pub fn build_fpsenr2(
    recovered: &Recovery,
    selector: SinfSelector,
    fairplayd_sha256: [u8; 32],
    source: &[u8; FIRST_TRANSFORM_BYTES],
    encoded: &[u8; FIRST_TRANSFORM_BYTES],
    fixtures: &[EnrollmentFixture<'_>],
) -> Result<Zeroizing<Vec<u8>>> {
    recovered.input_encoding.check_permutation()?;
    recovered.output_encoding.check_permutation()?;
    let input_decode = recovered.input_encoding.inverse()?;
    let whitening: [u8; 16] = core::array::from_fn(|index| source[index] ^ encoded[index]);
    for index in 0..FIRST_TRANSFORM_BYTES {
        if source[index] ^ encoded[index] != whitening[index % 16] {
            bail!("first protected transform is not a sixteen-byte XOR period");
        }
    }
    let mut bytes = Zeroizing::new(vec![0u8; FPSENR2_BYTES]);
    bytes[..8].copy_from_slice(b"FPSENR2\0");
    bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&(FPSENR2_BYTES as u32).to_le_bytes());
    bytes[16..48].copy_from_slice(&fairplayd_sha256);
    bytes[48..52].copy_from_slice(&selector.user.to_le_bytes());
    bytes[52..56].copy_from_slice(&selector.key.to_le_bytes());
    bytes[56..72].copy_from_slice(&recovered.key);
    bytes[72..88].copy_from_slice(&whitening);
    for position in 0..16 {
        bytes[88 + position * 256..88 + (position + 1) * 256]
            .copy_from_slice(&input_decode.0[position]);
    }
    let model = CurrentSinfModel::parse(&bytes)?;
    for fixture in fixtures {
        if parse_sinf_selector(fixture.sinf)? != selector {
            bail!("fixture SINF selector does not match the recovered enrollment");
        }
        if model.logical_key(fixture.sinf)? != fixture.logical_key {
            bail!("fixture logical key does not match the recovered enrollment");
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_recovery_math::Encoding;
    use sha2::{Digest, Sha256};

    fn recovery() -> Recovery {
        Recovery {
            key: [0x42; 16],
            input_encoding: Encoding::identity(),
            output_encoding: Encoding::identity(),
            milliseconds: 0.0,
        }
    }

    #[test]
    fn builds_current_sinf_model_with_checked_envelope_and_input_inverse() {
        let selector = SinfSelector {
            user: 0x1234_5678,
            key: 9,
        };
        let source = core::array::from_fn(|index| index as u8);
        let encoded = core::array::from_fn(|index| source[index] ^ (index % 16) as u8);
        let bytes =
            build_fpsenr2(&recovery(), selector, [0xa5; 32], &source, &encoded, &[]).unwrap();
        assert_eq!(bytes.len(), FPSENR2_BYTES);
        assert_eq!(&bytes[..8], b"FPSENR2\0");
        assert_eq!(&bytes[16..48], &[0xa5; 32]);
        assert_eq!(&bytes[48..52], &selector.user.to_le_bytes());
        assert_eq!(&bytes[52..56], &selector.key.to_le_bytes());
        assert_eq!(&bytes[56..72], &[0x42; 16]);
        assert_eq!(
            &bytes[72..88],
            &core::array::from_fn::<_, 16, _>(|index| index as u8)
        );
        assert!(CurrentSinfModel::parse(&bytes).is_ok());
        let digest = format!("{:x}", Sha256::digest(&*bytes));
        assert_eq!(
            digest,
            "1e534f61e801fb8b305b031daf173d5da3075cda46a7a179b33ee60b3f30c2b7"
        );
    }

    #[test]
    fn rejects_transform_without_exact_sixteen_byte_period() {
        let source = [0; FIRST_TRANSFORM_BYTES];
        let mut encoded = [0; FIRST_TRANSFORM_BYTES];
        encoded[16] = 1;
        assert!(
            build_fpsenr2(
                &recovery(),
                SinfSelector { user: 1, key: 2 },
                [0; 32],
                &source,
                &encoded,
                &[]
            )
            .is_err()
        );
    }
}
