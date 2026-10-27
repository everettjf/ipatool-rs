//! Pure Rust evaluator for the checked macOS 26B118 FairPlay white-box boundary.

use std::collections::BTreeSet;

use anyhow::{Result, bail};

use crate::{
    fairplay_frame::{
        add_offset, bit_mask, bool_value, extract_pair, insert_bits, rotate_right, select_value,
        shift_left, shift_right,
    },
    fairplay_oracle_model::{FaultKind, OracleFault, OracleModel, OracleState},
};

pub(crate) const BUILD_HASH: [u8; 32] = [
    0xf6, 0x8e, 0x44, 0x07, 0xe9, 0x0a, 0xf5, 0x46, 0x6d, 0x27, 0x66, 0xe1, 0xb1, 0xc4, 0x63, 0x72,
    0x60, 0xd0, 0x8c, 0xb0, 0x51, 0x8f, 0x99, 0x1e, 0x17, 0x97, 0xac, 0x6c, 0x49, 0x64, 0x43, 0x9d,
];

include!("fairplay_26b118_faults.rs");

// The round-7 w9 site is an index-after fault: it XORs the register at the
// following instruction and does not have a 256-value encoded index domain.
pub(crate) const INDEX_AFTER_PC: u64 = 0x1002_22c58;

pub(crate) fn required_index_sites() -> BTreeSet<(u64, u8)> {
    ROUND6
        .iter()
        .chain(ROUND7.iter())
        .chain(ROUND8.iter())
        .filter(|site| site.kind == FaultKind::Index && site.pc != INDEX_AFTER_PC)
        .map(|site| (site.pc, site.register))
        .collect()
}

/// Decode the fault metadata used by the original 26B118 recovery driver.
pub fn fault_for_metadata(metadata: u32) -> Result<OracleFault> {
    let round = metadata as u16;
    if round == u16::MAX {
        return Ok(OracleFault::NONE);
    }
    let sites = match round {
        6 | 7 => &ROUND6,
        8 => &ROUND7,
        9 => &ROUND8,
        _ => bail!("unsupported 26B118 oracle fault round={round}"),
    };
    let byte_index = ((metadata >> 16) & 0xff) as usize;
    let value = (metadata >> 24) as u8;
    if byte_index >= sites.len() || value == 0 {
        bail!("unsupported 26B118 oracle fault round={round} byte={byte_index} xor={value}");
    }
    Ok(OracleFault {
        value,
        ..sites[byte_index]
    })
}

pub fn evaluate(model: &OracleModel, input: &[u8; 16], metadata: u32) -> Result<[u8; 16]> {
    if model.binary_hash != BUILD_HASH {
        bail!("oracle model does not match the checked 26B118 build");
    }
    let fault = fault_for_metadata(metadata)?;
    if fault.kind == FaultKind::Index && model.domain(fault.pc, fault.register).is_none() {
        bail!("26B118 index fault requires its learned domain");
    }
    let mut state = model.state();
    evaluate_in_state(&mut state, input, fault)
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

include!("fairplay_26b118_generated.rs");

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_MODEL: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-oracle-26b118-synthetic.model.gz");

    #[test]
    fn fault_map_preserves_go_round_mapping_and_geometry() {
        assert_eq!(required_index_sites().len(), 17);
        assert!(!required_index_sites().contains(&(INDEX_AFTER_PC, 9)));
        assert_eq!(
            fault_for_metadata(0x0103_0008).unwrap().kind,
            FaultKind::IndexAfter
        );
        assert_eq!(fault_for_metadata(0xffff).unwrap(), OracleFault::NONE);
        let round6 = fault_for_metadata(0x0100_0006).unwrap();
        assert_eq!(
            (round6.pc, round6.register, round6.value),
            (0x1002_22ac4, 12, 1)
        );
        assert_eq!(round6.kind, FaultKind::Index);
        let round7 = fault_for_metadata(0x8000_0007).unwrap();
        assert_eq!(
            (round7.pc, round7.register, round7.value),
            (0x1002_22ac4, 12, 0x80)
        );
        let round8 = fault_for_metadata(0x0100_0008).unwrap();
        assert_eq!((round8.pc, round8.register), (0x1002_22dbc, 7));
        assert_eq!(round8.kind, FaultKind::Pointer);
        let round9 = fault_for_metadata(0x010f_0009).unwrap();
        assert_eq!((round9.pc, round9.register), (0x1002_22fac, 24));
        assert_eq!(round9.table_bytes, 0x400);
        assert_eq!(round9.entry_bytes, 4);
        assert!(fault_for_metadata(0x0000_0009).is_err());
        assert!(fault_for_metadata(0x0110_0009).is_err());
        assert!(fault_for_metadata(0x0100_0005).is_err());
    }

    #[test]
    fn generated_evaluator_matches_go_on_synthetic_state() {
        // This public model has deterministic byte-pattern pages and no enrollment state.
        // The reference digests were produced by the original Go evaluator.
        let model = OracleModel::parse_gzip(SYNTHETIC_MODEL).unwrap();
        assert_eq!(model.page_count(), 27);
        let cases = [
            (
                [0; 16],
                "8d211cb8245d34037a52bdb5f4a91861b4ad7a055bde3d4a0815ceda795da4f3",
            ),
            (
                core::array::from_fn(|index| index as u8),
                "42b0f78bb1b711459a2f3e1d3192a9e16563eb51c285de53be9c474fe7f56c79",
            ),
            (
                [0xff; 16],
                "b6d4ce30c1fd14c9f1a5b1cfa92112cc324e278a70313ef6104e454e0f041007",
            ),
        ];
        let mut state = model.state();
        for (input, expected_digest) in cases {
            let output = evaluate_in_state(&mut state, &input, OracleFault::NONE).unwrap();
            assert_eq!(output, input);
            assert_eq!(state.digest(), expected_digest);
        }

        let input = core::array::from_fn(|index| index as u8);
        let fault_cases = [
            (
                0x0100_0006,
                "a6e9ff2688a49f5ceedb3a9d2eac18cf91aac9760813cd36ca80fa29fcd0b7b3",
            ),
            (
                0x0100_0008,
                "be849dbd2dc2935d99b2e1b70c99ce349d5ccb6069b202492297bbce21ee9b3a",
            ),
            (
                0x010f_0009,
                "28da33c5cebf46d6bd237e17d9d910d66774f5cc61083095e2b8abf9194c6975",
            ),
        ];
        for (metadata, expected_digest) in fault_cases {
            let fault = fault_for_metadata(metadata).unwrap();
            evaluate_in_state(&mut state, &input, fault).unwrap();
            assert_eq!(state.digest(), expected_digest);
        }
    }
}
