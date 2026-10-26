//! Recover the AES-128 round key from the checked SIDB fault sites.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. Attribution is in `licenses/LICENSE-DARKPHOENIX.txt`.

use std::collections::HashMap;

use anyhow::{Result, bail};
use zeroize::Zeroize;

use crate::{
    fairplay_recovery_math::{
        Encoding, INV_SHIFT, SBOX, gf_inv, gf_mul, inv_shift_rows, revert_aes128_round_key,
    },
    fairplay_recovery_step3::Step3Recovery,
    fairplay_recovery_target::{OracleJob, SidbTarget, attack_view, deterministic_input},
};

#[derive(Clone, Copy)]
struct MeetSolution {
    lambda: [u8; 4],
    beta: [u8; 4],
}

#[derive(Clone, Copy)]
struct MeetRowSolution {
    root_lambda: u8,
    root_beta: u8,
    row_lambda: u8,
    row_beta: u8,
}

pub struct RoundRecovery {
    pub lambda: [u8; 16],
    pub beta: [u8; 16],
    pub round_key: [u8; 16],
    pub aes_key: [u8; 16],
}

impl Drop for RoundRecovery {
    fn drop(&mut self) {
        self.lambda.zeroize();
        self.beta.zeroize();
        self.round_key.zeroize();
        self.aes_key.zeroize();
    }
}

fn meet_coefficients(position: usize) -> [u8; 4] {
    let (root, others) = match position {
        0 => (14, [9, 13, 11]),
        1 => (11, [14, 9, 13]),
        2 => (13, [11, 14, 9]),
        _ => (9, [13, 11, 14]),
    };
    [
        0,
        gf_mul(root, gf_inv(others[0])),
        gf_mul(root, gf_inv(others[1])),
        gf_mul(root, gf_inv(others[2])),
    ]
}

fn lambda_candidates(column: usize, row: usize, limited: Option<&[u8; 4]>) -> Vec<u8> {
    match limited {
        Some(values) => vec![values[(column + row) % 4]],
        None => (1..=255).collect(),
    }
}

fn meet_at(
    column: usize,
    fault: &[[u8; 4]],
    middle: usize,
    fault_position: usize,
    limited: Option<&[u8; 4]>,
) -> Option<MeetSolution> {
    if middle >= fault.len() || middle > 4 {
        return None;
    }
    let coefficient = meet_coefficients(fault_position);
    let fault0 = &fault[..=middle];
    let mut fault1 = Vec::with_capacity(fault.len() - middle);
    fault1.push(fault[0]);
    fault1.extend_from_slice(&fault[middle + 1..]);
    let root_candidates = lambda_candidates(column, 0, limited);
    let mut table: HashMap<u32, Vec<(u8, u8)>> =
        HashMap::with_capacity(root_candidates.len() * 256);
    for lambda in root_candidates {
        for beta in 0..=255 {
            let root = SBOX[(gf_mul(lambda, fault0[0][0]) ^ beta) as usize];
            let mut hash = 0;
            for (index, value) in fault0[1..].iter().enumerate() {
                let difference = root ^ SBOX[(gf_mul(lambda, value[0]) ^ beta) as usize];
                hash |= (difference as u32) << (8 * index);
            }
            table.entry(hash).or_default().push((lambda, beta));
        }
    }
    let solve_row = |row: usize| -> Vec<MeetRowSolution> {
        let mut result = Vec::new();
        let coef = coefficient[row];
        for lambda in lambda_candidates(column, row, limited) {
            for beta in 0..=255 {
                let root = SBOX[(gf_mul(lambda, fault0[0][row]) ^ beta) as usize];
                let mut hash = 0;
                for (index, value) in fault0[1..].iter().enumerate() {
                    let difference = root ^ SBOX[(gf_mul(lambda, value[row]) ^ beta) as usize];
                    hash |= (gf_mul(coef, difference) as u32) << (8 * index);
                }
                let Some(hits) = table.get(&hash) else {
                    continue;
                };
                let second = fault1[1..]
                    .iter()
                    .map(|value| {
                        let difference = root ^ SBOX[(gf_mul(lambda, value[row]) ^ beta) as usize];
                        gf_mul(coef, difference)
                    })
                    .collect::<Vec<_>>();
                for &(root_lambda, root_beta) in hits {
                    let root_value = SBOX[(gf_mul(root_lambda, fault1[0][0]) ^ root_beta) as usize];
                    let same = fault1[1..].iter().zip(&second).all(|(value, &expected)| {
                        root_value ^ SBOX[(gf_mul(root_lambda, value[0]) ^ root_beta) as usize]
                            == expected
                    });
                    if same {
                        result.push(MeetRowSolution {
                            root_lambda,
                            root_beta,
                            row_lambda: lambda,
                            row_beta: beta,
                        });
                    }
                }
            }
        }
        result
    };
    let rows = [solve_row(1), solve_row(2), solve_row(3)];
    if rows.iter().any(|row| row.len() != 1) {
        return None;
    }
    let roots = [rows[0][0], rows[1][0], rows[2][0]];
    if roots[0].root_lambda != roots[1].root_lambda
        || roots[0].root_lambda != roots[2].root_lambda
        || roots[0].root_beta != roots[1].root_beta
        || roots[0].root_beta != roots[2].root_beta
    {
        return None;
    }
    Some(MeetSolution {
        lambda: [
            roots[0].root_lambda,
            roots[0].row_lambda,
            roots[1].row_lambda,
            roots[2].row_lambda,
        ],
        beta: [
            roots[0].root_beta,
            roots[0].row_beta,
            roots[1].row_beta,
            roots[2].row_beta,
        ],
    })
}

fn meet(
    column: usize,
    fault: &[[u8; 4]],
    middle: usize,
    limited: Option<&[u8; 4]>,
) -> Option<MeetSolution> {
    (0..4).find_map(|position| meet_at(column, fault, middle, position, limited))
}

fn column_slice(
    target: &mut SidbTarget<'_>,
    plaintext: [u8; 16],
    reference: [u8; 16],
    column: usize,
    permutations: &[Encoding],
    protocol_round: u16,
) -> Result<Vec<[u8; 4]>> {
    const ALPHA: usize = 16;
    let mut jobs = Vec::with_capacity(16 * ALPHA);
    for position in 0..16 {
        let fault_position = (column * 4 + position) % 16;
        let fault_byte = INV_SHIFT[fault_position] as u32;
        for value in 1..=ALPHA {
            jobs.push(OracleJob {
                block: plaintext,
                metadata: protocol_round as u32 | (fault_byte << 16) | ((value as u32) << 24),
            });
        }
    }
    let outputs = target.evaluate_jobs(&jobs)?;
    for position in 0..16 {
        let mut columns = Vec::with_capacity(ALPHA + 1);
        columns.push(reference[column * 4..column * 4 + 4].try_into().unwrap());
        let mut valid = true;
        for value in 1..=ALPHA {
            let view = attack_view(outputs[position * ALPHA + value - 1], permutations, true);
            let differences = (0..16)
                .filter(|&index| view[index] != reference[index])
                .collect::<Vec<_>>();
            if differences.len() != 4 {
                if value == 1 {
                    valid = false;
                    break;
                }
                bail!("fault diffusion changed");
            }
            let fault_column = differences[0] / 4;
            if fault_column != column
                || differences
                    != [
                        fault_column * 4,
                        fault_column * 4 + 1,
                        fault_column * 4 + 2,
                        fault_column * 4 + 3,
                    ]
            {
                if value == 1 {
                    valid = false;
                    break;
                }
                bail!("fault column changed");
            }
            columns.push(view[column * 4..column * 4 + 4].try_into().unwrap());
        }
        if valid {
            return Ok(columns);
        }
    }
    bail!("no fault position affects column {column}")
}

pub fn first_permutation(gtilde: &Encoding, gbar: &Encoding, coefficient: [u8; 16]) -> Encoding {
    Encoding::affine(coefficient, [0; 16])
        .combine(gbar)
        .combine(gtilde)
}

pub fn recover_step4(
    target: &mut SidbTarget<'_>,
    gtilde: &Encoding,
    step3: &Step3Recovery,
) -> Result<([u8; 16], [u8; 16])> {
    let reference = deterministic_input(0);
    let permutation = first_permutation(gtilde, &step3.gbar, step3.coefficient);
    let reference_view = attack_view(
        target.apply(reference)?,
        std::slice::from_ref(&permutation),
        true,
    );
    let mut lambdas = [[0; 4]; 4];
    let mut betas = [[0; 4]; 4];
    for column in 0..4 {
        let mut solution = None;
        for attempt in 0..10 {
            let plaintext = if attempt == 0 {
                reference
            } else {
                deterministic_input(attempt)
            };
            let view = if attempt == 0 {
                reference_view
            } else {
                attack_view(
                    target.apply(plaintext)?,
                    std::slice::from_ref(&permutation),
                    true,
                )
            };
            let fault = column_slice(
                target,
                plaintext,
                view,
                column,
                std::slice::from_ref(&permutation),
                8,
            )?;
            let limited = if column == 0 { None } else { Some(&lambdas[0]) };
            solution = meet(column, &fault, 4, limited);
            if solution.is_some() {
                break;
            }
        }
        let found = solution.ok_or_else(|| anyhow::anyhow!("step4 failed for column {column}"))?;
        lambdas[column] = found.lambda;
        betas[column] = found.beta;
    }
    let mut lambda = [0; 16];
    let mut beta = [0; 16];
    for column in 0..4 {
        lambda[column * 4..column * 4 + 4].copy_from_slice(&lambdas[column]);
        beta[column * 4..column * 4 + 4].copy_from_slice(&betas[column]);
    }
    let shifted = inv_shift_rows(lambda);
    for position in 0..16 {
        if shifted[position] != shifted[position - position % 4] {
            bail!("step4 lambda disagreement");
        }
    }
    Ok((lambda, beta))
}

pub fn round_permutation(lambda: [u8; 16], beta: [u8; 16]) -> Encoding {
    Encoding(core::array::from_fn(|position| {
        core::array::from_fn(|value| {
            SBOX[(gf_mul(lambda[position], value as u8) ^ beta[position]) as usize]
        })
    }))
}

pub fn recover_step5(
    target: &mut SidbTarget<'_>,
    gtilde: &Encoding,
    step3: &Step3Recovery,
    lambda: [u8; 16],
    beta: [u8; 16],
) -> Result<[u8; 16]> {
    let reference = deterministic_input(0);
    let permutations = [
        first_permutation(gtilde, &step3.gbar, step3.coefficient),
        round_permutation(lambda, beta),
    ];
    let fixed = [1; 4];
    let mut beta_round = [0; 16];
    for column in 0..4 {
        let mut solution = None;
        for attempt in 0..10 {
            let plaintext = if attempt == 0 {
                reference
            } else {
                deterministic_input(attempt)
            };
            let view = attack_view(target.apply(plaintext)?, &permutations, true);
            let fault = column_slice(target, plaintext, view, column, &permutations, 7)?;
            solution = meet(column, &fault, 4, Some(&fixed));
            if solution.is_some() {
                break;
            }
        }
        let found = solution.ok_or_else(|| anyhow::anyhow!("step5 failed for column {column}"))?;
        beta_round[column * 4..column * 4 + 4].copy_from_slice(&found.beta);
    }
    Ok(inv_shift_rows(beta_round))
}

pub fn recover_round(
    target: &mut SidbTarget<'_>,
    gtilde: &Encoding,
    step3: &Step3Recovery,
) -> Result<RoundRecovery> {
    let (lambda, beta) = recover_step4(target, gtilde, step3)?;
    let round_key = recover_step5(target, gtilde, step3, lambda, beta)?;
    let aes_key = revert_aes128_round_key(round_key, 2);
    Ok(RoundRecovery {
        lambda,
        beta,
        round_key,
        aes_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fairplay_oracle_model::OracleModel, fairplay_recovery_step1::search,
        fairplay_recovery_step2, fairplay_recovery_step3,
    };

    #[test]
    #[ignore = "runs full SIDB recovery Steps 1-5; execute in release mode"]
    fn full_public_sidb_round_key_matches_go() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let mut target = SidbTarget::new(&model, [0; 16]);
        let step1 = search(&mut target).unwrap();
        let gtilde = fairplay_recovery_step2::recover(&mut target, &step1).unwrap();
        let step3 = fairplay_recovery_step3::recover(&mut target, &gtilde).unwrap();
        let result = recover_round(&mut target, &gtilde, &step3).unwrap();
        assert_eq!(hex(&result.lambda), "d8b83ac9b83ac9d83ac9d8b8c9d8b83a");
        assert_eq!(hex(&result.beta), "a5d57d291a90f42f207a720e042d8f78");
        assert_eq!(hex(&result.round_key), "f703b97ba7bc62e933b8523acf20fdb1");
        assert_eq!(hex(&result.aes_key), "6ca1ee8ee3c55f59c4bbeb41689c9f58");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
