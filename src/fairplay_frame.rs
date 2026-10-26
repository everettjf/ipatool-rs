//! Pure Rust evaluator for the sanitized macOS 26A428 frame oracle.

use anyhow::{Result, bail};

use crate::fairplay_oracle_model::{OracleModel, OracleState};

pub(crate) const BUILD_HASH: [u8; 32] = [
    0x1e, 0x58, 0xd3, 0x7e, 0x96, 0x02, 0xdd, 0x0c, 0xa5, 0xe2, 0x4b, 0x14, 0x76, 0x20, 0x63, 0xb6,
    0xc3, 0x10, 0x24, 0x8b, 0x4d, 0x3a, 0x94, 0x27, 0x27, 0x71, 0xd8, 0x15, 0xe4, 0xea, 0x17, 0x84,
];

pub fn evaluate(model: &OracleModel, input: &[u8; 16]) -> Result<[u8; 16]> {
    if model.binary_hash != BUILD_HASH {
        bail!("frame oracle model does not match the checked 26A428 build");
    }
    let mut state = model.state();
    state.begin(input)?;
    run_generated(&mut state)?;
    state.output()
}

pub(crate) fn add_offset(value: u64, offset: i64) -> u64 {
    value.wrapping_add(offset as u64)
}

pub(crate) fn shift_left(value: u64, amount: u64, width: u32) -> u64 {
    if width == 32 {
        ((value as u32).wrapping_shl(amount as u32)) as u64
    } else {
        value.wrapping_shl(amount as u32)
    }
}

pub(crate) fn shift_right(value: u64, amount: u64, width: u32) -> u64 {
    if width == 32 {
        ((value as u32).wrapping_shr(amount as u32)) as u64
    } else {
        value.wrapping_shr(amount as u32)
    }
}

pub(crate) fn rotate_right(value: u64, amount: u64, width: u32) -> u64 {
    if width == 32 {
        (value as u32).rotate_right(amount as u32) as u64
    } else {
        value.rotate_right(amount as u32)
    }
}

pub(crate) fn bit_mask(bits: u32, width: u32) -> u64 {
    if bits >= width {
        return if width == 32 {
            u32::MAX as u64
        } else {
            u64::MAX
        };
    }
    (1u64 << bits) - 1
}

pub(crate) fn insert_bits(destination: u64, source: u64, lsb: u32, bits: u32, width: u32) -> u64 {
    let mask = bit_mask(bits, width).wrapping_shl(lsb);
    let value = (destination & !mask) | (source.wrapping_shl(lsb) & mask);
    if width == 32 {
        value as u32 as u64
    } else {
        value
    }
}

pub(crate) fn extract_pair(high: u64, low: u64, amount: u64, width: u32) -> u64 {
    if width == 32 {
        let pair = ((high as u32 as u64) << 32) | low as u32 as u64;
        return (pair >> amount) as u32 as u64;
    }
    if amount == 0 {
        low
    } else {
        high.wrapping_shl((64 - amount) as u32) | low.wrapping_shr(amount as u32)
    }
}

pub(crate) fn sign_extend32(value: u32) -> u64 {
    (value as i32 as i64) as u64
}
pub(crate) fn select_value(condition: bool, left: u64, right: u64) -> u64 {
    if condition { left } else { right }
}

pub(crate) fn bool_value(value: bool) -> u64 {
    u64::from(value)
}

include!("fairplay_frame_generated.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn sanitized_frame_matches_original_zero_input_hash() {
        let bytes = include_bytes!("../tests/fixtures/fairplay-oracle-frame-public.model.gz");
        let model = OracleModel::parse_gzip(bytes).unwrap();
        let output = evaluate(&model, &[0; 16]).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(output)),
            "7d3b5648332a3ca5df0971442b796a4df472c09e63e9861756d982c2ff3d5fb4"
        );
    }

    #[test]
    fn sanitized_frame_matches_reference_on_distinct_inputs() {
        let bytes = include_bytes!("../tests/fixtures/fairplay-oracle-frame-public.model.gz");
        let model = OracleModel::parse_gzip(bytes).unwrap();
        let cases = [
            (
                core::array::from_fn(|index| index as u8),
                "7f16546e18e54d0fc45af5832836532c",
            ),
            ([0xff; 16], "3a85524f95f6419c1d21687a65bee3ca"),
            (
                core::array::from_fn(|index| if index % 2 == 0 { 0x55 } else { 0xaa }),
                "eca4155e7a7a5c51e42249706b17dcb5",
            ),
        ];
        for (input, expected) in cases {
            let output = evaluate(&model, &input).unwrap();
            let actual = output
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(actual, expected);
        }
    }
}
