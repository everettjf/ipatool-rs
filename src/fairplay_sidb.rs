//! Pure Rust evaluator for the checked 26A428 SIDB enrollment transform.

use anyhow::{Result, bail};

use crate::{
    fairplay_frame::{
        BUILD_HASH, add_offset, bit_mask, bool_value, extract_pair, insert_bits, rotate_right,
        select_value, shift_left, shift_right, sign_extend32,
    },
    fairplay_oracle_model::{FaultKind, OracleFault, OracleModel, OracleState},
};

const ENROLLMENT_FRAME_ADDRESS: u64 = 0x7000_000f_b724;
const ROUND6: [(u8, u8); 16] = [
    (2, 8),
    (8, 8),
    (8, 0),
    (16, 0),
    (2, 0),
    (6, 16),
    (8, 24),
    (16, 24),
    (2, 24),
    (6, 8),
    (8, 16),
    (16, 16),
    (2, 16),
    (6, 0),
    (10, 0),
    (16, 8),
];
const ROUND7: [(u8, u8); 16] = [
    (2, 0),
    (10, 24),
    (16, 0),
    (15, 24),
    (8, 24),
    (15, 0),
    (10, 8),
    (15, 16),
    (10, 16),
    (8, 8),
    (10, 0),
    (16, 8),
    (1, 8),
    (8, 0),
    (15, 8),
    (20, 8),
];
const ROUND8: [(u8, u8); 16] = [
    (1, 0),
    (8, 8),
    (10, 16),
    (16, 16),
    (2, 16),
    (8, 0),
    (10, 8),
    (16, 8),
    (2, 8),
    (8, 24),
    (15, 0),
    (16, 0),
    (2, 0),
    (8, 16),
    (10, 24),
    (16, 24),
];

/// Decode the fault metadata used by the original SIDB recovery driver.
pub fn fault_for_metadata(metadata: u32) -> Result<OracleFault> {
    let round = metadata as u16;
    if round == u16::MAX {
        return Ok(OracleFault::NONE);
    }
    let byte_index = ((metadata >> 16) & 0xff) as usize;
    let value = (metadata >> 24) as u8;
    let (pc, sites) = match round {
        6 | 7 => (0x10008fbc0, &ROUND6),
        8 => (0x10008fd3c, &ROUND7),
        9 => (0x10008fefc, &ROUND8),
        _ => bail!("unsupported oracle fault round={round}"),
    };
    if byte_index >= 16 || value == 0 {
        bail!("unsupported oracle fault round={round} byte={byte_index} xor={value}");
    }
    let (register, shift) = sites[byte_index];
    Ok(OracleFault {
        pc,
        register,
        shift,
        value,
        kind: FaultKind::Index,
        restore: false,
        table_bytes: 0x400,
        entry_bytes: 4,
    })
}

pub fn evaluate(
    model: &OracleModel,
    frame: &[u8; 16],
    input: &[u8; 16],
    fault: OracleFault,
) -> Result<[u8; 16]> {
    if model.binary_hash != BUILD_HASH {
        bail!("SIDB oracle model does not match the checked 26A428 build");
    }
    let mut state = model.state();
    evaluate_in_state(&mut state, frame, input, fault)
}

pub(crate) fn evaluate_in_state(
    state: &mut OracleState<'_>,
    frame: &[u8; 16],
    input: &[u8; 16],
    fault: OracleFault,
) -> Result<[u8; 16]> {
    state.begin(input)?;
    state.store(ENROLLMENT_FRAME_ADDRESS, frame)?;
    run_generated(state, fault)?;
    state.output()
}

include!("fairplay_sidb_generated.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn public_fixture_matches_original_sidb_output() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        assert_eq!(model.page_count(), 71);
        let frame_digest = Sha256::digest(b"ipatool public SIDB frame fixture");
        let input_digest = Sha256::digest(b"ipatool public SIDB block fixture");
        let frame: [u8; 16] = frame_digest[..16].try_into().unwrap();
        let input: [u8; 16] = input_digest[..16].try_into().unwrap();
        let output = evaluate(&model, &frame, &input, OracleFault::NONE).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(output)),
            "fa60630407415ac643265feb92f467340dd4bc63fb3f37cf308a6619436cb898"
        );
    }

    #[test]
    fn fault_metadata_maps_to_checked_sites() {
        assert_eq!(fault_for_metadata(0xffff).unwrap(), OracleFault::NONE);
        let round6 = fault_for_metadata(0x0100_0006).unwrap();
        assert_eq!(
            (round6.pc, round6.register, round6.shift, round6.value),
            (0x10008fbc0, 2, 8, 1)
        );
        let round7 = fault_for_metadata(0x800f_0008).unwrap();
        assert_eq!(
            (round7.pc, round7.register, round7.shift, round7.value),
            (0x10008fd3c, 20, 8, 0x80)
        );
        let round8 = fault_for_metadata(0xff05_0009).unwrap();
        assert_eq!(
            (round8.pc, round8.register, round8.shift, round8.value),
            (0x10008fefc, 8, 0, 0xff)
        );
        assert!(fault_for_metadata(0x0000_0009).is_err());
        assert!(fault_for_metadata(0x0110_0009).is_err());
        assert!(fault_for_metadata(0x0100_0005).is_err());
    }

    #[test]
    fn sidb_matches_go_on_distinct_frames_and_blocks() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let cases = [
            ([0u8; 16], [0u8; 16], "ac95f1b50aff72888eaa4e292ccd0792"),
            (
                core::array::from_fn(|index| index as u8),
                core::array::from_fn(|index| (index + 16) as u8),
                "cb4c023b71ef42228531b0434c560b9d",
            ),
            (
                core::array::from_fn(|index| if index % 2 == 0 { 0x55 } else { 0xaa }),
                core::array::from_fn(|index| if index % 2 == 0 { 0xff } else { 0 }),
                "a5e7ac298930adbfe75c07bb8fcb3566",
            ),
        ];
        for (frame, input, expected) in cases {
            let output = evaluate(&model, &frame, &input, OracleFault::NONE).unwrap();
            assert_eq!(hex(&output), expected);
        }
    }

    #[test]
    fn injected_faults_match_go_reference() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let cases = [
            (0x0100_0006, "cd10256356f0e15a75683e27c8e4fbf3"),
            (0x0100_0008, "2ef55ae0e5c2187467323c601a01096e"),
            (0x0100_0009, "3195f1b50a1e72888eaa6b292ccd0772"),
            (0x0101_0006, "644574b5e14a1d29724b390fb4c86a2f"),
            (0x0101_0009, "ac95f1fbb6ff72888e034e292ccd1b92"),
        ];
        for (metadata, expected) in cases {
            let fault = fault_for_metadata(metadata).unwrap();
            let output = evaluate(&model, &[0; 16], &[0; 16], fault).unwrap();
            assert_eq!(hex(&output), expected, "fault metadata {metadata:08x}");
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
