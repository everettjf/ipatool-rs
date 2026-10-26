//! Recover the second external encoding and MixColumns coefficients.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. Attribution is in `licenses/LICENSE-DARKPHOENIX.txt`.

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::{
    fairplay_recovery_linear::{
        MatrixCandidate, association, c_coefficient, c_value, decrypt_candidates, inverse_table,
    },
    fairplay_recovery_math::{Encoding, Mat8, intertwiner_basis, invertible_from_basis},
    fairplay_recovery_target::{OracleJob, SidbTarget, attack_view, deterministic_input},
};

#[derive(Default)]
struct ColumnFaults {
    positions: Vec<usize>,
    words: Vec<Zeroizing<[[u8; 4]; 256]>>,
}

pub struct Step3Recovery {
    pub gbar: Encoding,
    pub coefficient: [u8; 16],
}

pub fn recover(target: &mut SidbTarget<'_>, gtilde: &Encoding) -> Result<Step3Recovery> {
    let reference = deterministic_input(0);
    let raw = target.apply(reference)?;
    let reference_view = attack_view(raw, std::slice::from_ref(gtilde), false);
    let mut jobs = Vec::with_capacity(16 * 255);
    for position in 0..16 {
        for value in 1..=255 {
            jobs.push(OracleJob {
                block: reference,
                metadata: 9u32 | ((position as u32) << 16) | ((value as u32) << 24),
            });
        }
    }
    let outputs = Zeroizing::new(target.evaluate_jobs(&jobs)?);
    let mut columns: [ColumnFaults; 4] = core::array::from_fn(|_| ColumnFaults::default());
    for position in 0..16 {
        let mut column = None;
        let mut words = Zeroizing::new([[0; 4]; 256]);
        for value in 1..=255 {
            let view = attack_view(
                outputs[position * 255 + value - 1],
                std::slice::from_ref(gtilde),
                false,
            );
            let differences = (0..16)
                .filter(|&index| view[index] != reference_view[index])
                .collect::<Vec<_>>();
            if differences.len() != 4
                || differences[1] != differences[0] + 1
                || differences[2] != differences[0] + 2
                || differences[3] != differences[0] + 3
            {
                bail!("step3 invalid fault geometry");
            }
            let current = differences[0] / 4;
            if let Some(previous) = column {
                if previous != current {
                    bail!("step3 fault changed column");
                }
            } else {
                column = Some(current);
                words[0].copy_from_slice(&reference_view[current * 4..current * 4 + 4]);
            }
            words[value].copy_from_slice(&view[current * 4..current * 4 + 4]);
        }
        let current = column.context("step3 fault yielded no column")?;
        columns[current].positions.push(position);
        columns[current].words.push(words);
    }
    if columns.iter().any(|column| column.words.len() != 4) {
        bail!("step3 fault columns are incomplete");
    }
    solve_gbar(&columns)
}

fn solve_gbar(columns: &[ColumnFaults; 4]) -> Result<Step3Recovery> {
    let mut maps = Zeroizing::new([[0; 256]; 16]);
    let mut pairs = [[0; 2]; 16];
    const PAIR_BY_ROW: [[usize; 2]; 4] = [[0, 1], [2, 3], [1, 3], [2, 0]];
    for position in 0..16 {
        let (column, row) = (position / 4, position % 4);
        let other = 2 * (row / 2) + (row + 1) % 2;
        pairs[position] = [row, other];
        let pair = PAIR_BY_ROW[row];
        let first = &columns[column].words[pair[0]];
        let second = &columns[column].words[pair[1]];
        if first[0] != second[0] {
            bail!("step3 bases differ");
        }
        let base = first[0];
        let mut forward = [-1i16; 256];
        let mut reverse = [-1i16; 256];
        for fault in 0..256 {
            let a = (base[row] ^ first[fault][row]) as usize;
            let b = (base[other] ^ second[fault][other]) as usize;
            if forward[a] >= 0 || reverse[b] >= 0 {
                bail!("step3 nonlinear differential");
            }
            forward[a] = (base[other] ^ first[fault][other]) as i16;
            reverse[b] = (base[row] ^ second[fault][row]) as i16;
        }
        for value in 0..256 {
            let mapped = forward[value];
            if mapped < 0 || reverse[mapped as usize] < 0 {
                bail!("step3 incomplete map");
            }
            maps[position][value] = reverse[mapped as usize] as u8;
        }
    }
    let candidates = decrypt_candidates();
    let mut names = [0usize; 16];
    for position in 0..16 {
        let left = Mat8::from_map(maps[position]);
        let hits = candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                !invertible_from_basis(&intertwiner_basis(left, candidate.matrix), 1).is_empty()
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if hits.len() != 1 {
            bail!("step3 matrix candidates={}", hits.len());
        }
        names[position] = hits[0];
    }
    let mut associations = [[None; 4]; 4];
    for position in 0..16 {
        let column = position / 4;
        let pair = PAIR_BY_ROW[position % 4];
        let (left, right) = association(
            candidates[names[position]].name,
            pairs[position][0],
            pairs[position][1],
        )
        .context("step3 association missing")?;
        for (slot, row) in [(pair[0], left), (pair[1], right)] {
            if associations[column][slot].is_some_and(|earlier| earlier != row) {
                bail!("step3 association conflict");
            }
            associations[column][slot] = Some(row);
        }
    }
    build_gbar(columns, &maps, &names, &associations, &candidates)
}

fn build_gbar(
    columns: &[ColumnFaults; 4],
    maps: &[[u8; 256]; 16],
    names: &[usize; 16],
    associations: &[[Option<usize>; 4]; 4],
    candidates: &[MatrixCandidate; 12],
) -> Result<Step3Recovery> {
    let mut decoded = Encoding([[0; 256]; 16]);
    for position in 0..16 {
        let basis = intertwiner_basis(
            Mat8::from_map(maps[position]),
            candidates[names[position]].matrix,
        );
        let gauges = invertible_from_basis(&basis, 48);
        if gauges.is_empty() {
            bail!("step3 no invertible encoding");
        }
        let (column, row) = (position / 4, position % 4);
        let chosen = if row == 0 {
            0
        } else {
            let slot0 = associations[column]
                .iter()
                .position(|&value| value == Some(0))
                .context("step3 association lacks root row")?;
            gauges
                .iter()
                .position(|gauge| {
                    let inverse = inverse_table(gauge.table());
                    c_value(
                        &decoded.0[column * 4],
                        &inverse,
                        &columns[column].words[slot0],
                        row,
                        c_coefficient(row),
                    )
                    .is_some()
                })
                .context("step3 gauge failed")?
        };
        decoded.0[position] = inverse_table(gauges[chosen].table());
    }
    let mut coefficient = [1; 16];
    for (position, slot) in coefficient.iter_mut().enumerate() {
        if position % 4 == 0 {
            continue;
        }
        let (column, row) = (position / 4, position % 4);
        let slot0 = associations[column]
            .iter()
            .position(|&value| value == Some(0))
            .context("step3 association lacks root row")?;
        *slot = c_value(
            &decoded.0[column * 4],
            &decoded.0[position],
            &columns[column].words[slot0],
            row,
            c_coefficient(row),
        )
        .context("step3 C mismatch")?;
    }
    Ok(Step3Recovery {
        gbar: decoded,
        coefficient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fairplay_oracle_model::OracleModel, fairplay_recovery_step1::search,
        fairplay_recovery_step2,
    };
    use sha2::{Digest, Sha256};

    #[test]
    #[ignore = "runs full SIDB recovery Steps 1-3; execute in release mode"]
    fn full_public_sidb_step3_matches_go_encoding_and_coefficients() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let mut target = SidbTarget::new(&model, [0; 16]);
        let step1 = search(&mut target).unwrap();
        let gtilde = fairplay_recovery_step2::recover(&mut target, &step1).unwrap();
        let result = recover(&mut target, &gtilde).unwrap();
        let mut hash = Sha256::new();
        for table in &result.gbar.0 {
            hash.update(table);
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "e9bb54e411950459d8645a2f8b94ac549d7b2e43c6fd4c886eabcbfa7dac20be"
        );
        assert_eq!(
            result.coefficient,
            [
                0x01, 0xeb, 0x88, 0x51, 0x01, 0x93, 0xda, 0xfd, 0x01, 0x9b, 0x7d, 0xa7, 0x01, 0x55,
                0xaf, 0x15
            ]
        );
    }
}
