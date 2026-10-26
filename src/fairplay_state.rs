//! Pure Rust evaluator for the 26A428 14-slot FairPlay state transform.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::{
    fairplay_frame::{
        BUILD_HASH, add_offset, bit_mask, bool_value, extract_pair, insert_bits, rotate_right,
        select_value, shift_left, shift_right, sign_extend32,
    },
    fairplay_oracle_model::{OracleModel, OracleState},
};

const INPUT_MASK: [u8; 16] = [
    0xa8, 0xd6, 0x01, 0x92, 0xfe, 0x37, 0x94, 0x0f, 0xe3, 0x33, 0x04, 0xfd, 0x34, 0xe0, 0xad, 0x43,
];

/// Evaluate a 192- or 224-byte captured state slot. The input mask is the
/// checked build's outer encoding and the result is always 224 bytes.
pub fn evaluate(model: &OracleModel, input: &[u8]) -> Result<Vec<u8>> {
    if model.binary_hash != BUILD_HASH {
        bail!("state oracle model does not match the checked 26A428 build");
    }
    if !matches!(input.len(), 192 | 224) {
        bail!("state-slot input is {} bytes, want 192 or 224", input.len());
    }
    let mut prepared = Zeroizing::new([0u8; 224]);
    for (index, byte) in input.iter().enumerate() {
        prepared[index] = byte ^ INPUT_MASK[index % INPUT_MASK.len()];
    }
    let mut state = model.state();
    state.begin(&prepared[..])?;
    run_generated(&mut state)?;
    state.output_bytes(224)
}

include!("fairplay_state_generated.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn model() -> OracleModel {
        OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-state-public.model.gz"
        ))
        .unwrap()
    }

    #[test]
    fn raw_zero_slots_match_original_reference_hash() {
        let model = model();
        let mut state = model.state();
        state.begin(&[0u8; 224]).unwrap();
        run_generated(&mut state).unwrap();
        let output = state.output_bytes(224).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(output)),
            "9e9f0073f8732cd41f7afa3106b5d25c068864e4974814944186664865b3aa93"
        );
    }

    #[test]
    fn prepared_state_inputs_match_go_reference() {
        let model = model();
        for (input, expected) in [
            (
                vec![0u8; 192],
                "77e57830920bbf3d68e8566a143a0d0f3c7998154573acddb9cd1fb30e4e5e83",
            ),
            (
                vec![0u8; 224],
                "dbfb58ced0660063f9de17b93eb18997986d166ada93c3ef42c4315fd257f640",
            ),
            (
                (0..224).map(|byte| byte as u8).collect(),
                "d78e5aa1c02b0f000de7d2abd8e766763c402e18c4dcd9df43844d3c06f0464a",
            ),
        ] {
            let output = evaluate(&model, &input).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(output)), expected);
        }
        assert!(evaluate(&model, &[0; 208]).is_err());
    }
}
