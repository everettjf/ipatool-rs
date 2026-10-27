//! Pure Rust evaluator for the checked macOS 26A428 FairPlay white-box core.

use anyhow::{Result, bail};

use crate::{
    fairplay_frame::{
        BUILD_HASH, add_offset, bit_mask, bool_value, extract_pair, insert_bits, rotate_right,
        select_value, shift_left, shift_right, sign_extend32,
    },
    fairplay_oracle_model::{FaultKind, OracleFault, OracleModel, OracleState},
};

pub const BLOCK_ADDRESS: u64 = 0x7100_0001_4ee8;

const ROUND6: [(u8, u8); 16] = [
    (10, 16),
    (12, 8),
    (14, 16),
    (15, 0),
    (10, 8),
    (12, 0),
    (14, 8),
    (14, 0),
    (10, 0),
    (12, 24),
    (12, 16),
    (15, 16),
    (10, 24),
    (11, 8),
    (14, 24),
    (15, 8),
];
const ROUND7: [(u8, u8); 16] = [
    (8, 8),
    (9, 24),
    (11, 8),
    (12, 24),
    (8, 0),
    (9, 16),
    (11, 0),
    (12, 16),
    (8, 24),
    (9, 8),
    (11, 24),
    (11, 16),
    (8, 16),
    (9, 0),
    (10, 8),
    (12, 0),
];
const ROUND8: [(u8, u8); 16] = [
    (8, 8),
    (9, 8),
    (10, 16),
    (11, 0),
    (8, 0),
    (9, 0),
    (10, 8),
    (11, 24),
    (8, 24),
    (9, 24),
    (10, 0),
    (11, 16),
    (8, 16),
    (9, 16),
    (10, 24),
    (11, 8),
];

/// Decode the fault metadata used by the original 26A428 recovery driver.
pub fn fault_for_metadata(metadata: u32) -> Result<OracleFault> {
    let round = metadata as u16;
    if round == u16::MAX {
        return Ok(OracleFault::NONE);
    }
    let (pc, sites) = match round {
        6 | 7 => (0x1002_35dd0, &ROUND6),
        8 => (0x1002_35fa8, &ROUND7),
        9 => (0x1002_361bc, &ROUND8),
        _ => bail!("unsupported 26A428 oracle fault round={round}"),
    };
    let byte = ((metadata >> 16) & 0xff) as usize;
    let value = (metadata >> 24) as u8;
    if byte >= sites.len() || value == 0 {
        bail!("unsupported 26A428 oracle fault round={round} byte={byte} xor={value}");
    }
    let (register, shift) = sites[byte];
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

pub fn evaluate(model: &OracleModel, input: &[u8; 16], metadata: u32) -> Result<[u8; 16]> {
    if model.binary_hash != BUILD_HASH || model.block_address != BLOCK_ADDRESS {
        bail!("26A428 oracle model does not match the checked build and block");
    }
    let mut state = model.state();
    evaluate_in_state(&mut state, input, fault_for_metadata(metadata)?)
}

pub(crate) fn evaluate_in_state(
    state: &mut OracleState<'_>,
    input: &[u8; 16],
    fault: OracleFault,
) -> Result<[u8; 16]> {
    state.begin(input)?;
    run_generated(state, fault)?;
    state.output()
}

include!("fairplay_26a428_generated.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_recovery_target::deterministic_input;
    use sha2::{Digest, Sha256};

    #[test]
    fn fault_map_matches_checked_go_rounds() {
        assert_eq!(fault_for_metadata(0xffff).unwrap(), OracleFault::NONE);
        let round6 = fault_for_metadata(0x0100_0006).unwrap();
        assert_eq!(
            (round6.pc, round6.register, round6.shift, round6.value),
            (0x1002_35dd0, 10, 16, 1)
        );
        let round7 = fault_for_metadata(0x0700_0008).unwrap();
        assert_eq!(
            (round7.pc, round7.register, round7.shift),
            (0x1002_35fa8, 8, 8)
        );
        let round8 = fault_for_metadata(0xff0f_0009).unwrap();
        assert_eq!(
            (round8.pc, round8.register, round8.shift, round8.value),
            (0x1002_361bc, 11, 8, 255)
        );
        assert!(fault_for_metadata(0x0000_0009).is_err());
        assert!(fault_for_metadata(0x0110_0009).is_err());
    }

    #[test]
    fn generated_core_matches_go_on_synthetic_state() {
        // The fixture contains deterministic public-pattern pages and no enrollment data.
        // The reference digest was produced by the checked original Go evaluator.
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-26a428-synthetic.model.gz"
        ))
        .unwrap();
        assert_eq!(model.page_count(), 51);
        let mut state = model.state();
        let mut hash = Sha256::new();
        for index in 0..16 {
            let input = deterministic_input(index);
            evaluate_in_state(&mut state, &input, OracleFault::NONE).unwrap();
            hash.update(state.digest().as_bytes());
        }
        let input = deterministic_input(0);
        for round in [6u32, 8, 9] {
            for byte in 0..16u32 {
                for value in [1u32, 7, 255] {
                    let metadata = round | (byte << 16) | (value << 24);
                    evaluate_in_state(&mut state, &input, fault_for_metadata(metadata).unwrap())
                        .unwrap();
                    hash.update(state.digest().as_bytes());
                }
            }
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "bf0e5d4b181ffe2ae3c3010ea554b7d427a3621f55e8d7752b2a43ea4c24ae71"
        );
    }
}
