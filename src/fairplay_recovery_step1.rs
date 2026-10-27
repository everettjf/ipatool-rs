//! First stage of the partial AES-128 decrypt attack: collect input matrices.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. Attribution is in `licenses/LICENSE-DARKPHOENIX.txt`.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::{
    fairplay_recovery_math::shift_rows,
    fairplay_recovery_target::{OracleJob, OracleTarget, counter},
};

const PAIRS: [[usize; 4]; 3] = [[0, 1, 2, 3], [0, 2, 3, 1], [0, 3, 1, 2]];
const SLOTS: usize = 16 * 3 * 256;
const BATCH_SIZE: usize = 4096;
const MAX_PROBES: u64 = 8 << 20;

pub struct Step1State {
    flags: Vec<bool>,
    inputs: Zeroizing<Vec<u8>>,
    reference_output: [u8; 16],
}

pub struct Step1Selection {
    pub matrices: Vec<Zeroizing<Vec<u8>>>,
    pub companions: Vec<usize>,
}

impl Step1State {
    pub fn new(reference_input: [u8; 16], reference_output: [u8; 16]) -> Self {
        let mut state = Self {
            flags: vec![false; SLOTS],
            inputs: Zeroizing::new(vec![0; SLOTS * 16]),
            reference_output,
        };
        for (position, &value) in reference_output.iter().enumerate() {
            for pair in 0..3 {
                state.claim(position, pair, value, reference_input);
            }
        }
        state
    }

    fn claim(&mut self, position: usize, pair: usize, value: u8, input: [u8; 16]) {
        let slot = (position * 3 + pair) * 256 + value as usize;
        if self.flags[slot] {
            return;
        }
        self.flags[slot] = true;
        self.inputs[slot * 16..(slot + 1) * 16].copy_from_slice(&input);
    }

    pub fn consider(&mut self, value: [u8; 16], input: [u8; 16]) {
        for column in 0..4 {
            for (pair_index, pair) in PAIRS.iter().enumerate() {
                let [a1, a2, b1, b2] = pair.map(|row| column * 4 + row);
                if value[a1] == self.reference_output[a1] {
                    self.claim(b1, pair_index, value[b1], input);
                }
                if value[a2] == self.reference_output[a2] {
                    self.claim(b2, pair_index, value[b2], input);
                }
                if value[b1] == self.reference_output[b1] {
                    self.claim(a1, pair_index, value[a1], input);
                }
                if value[b2] == self.reference_output[b2] {
                    self.claim(a2, pair_index, value[a2], input);
                }
            }
        }
    }

    pub fn claimed_count(&self) -> usize {
        self.flags.iter().filter(|&&flag| flag).count()
    }

    pub fn done(&self) -> bool {
        (0..16).all(|position| {
            (0..3).any(|pair| {
                let base = (position * 3 + pair) * 256;
                self.flags[base..base + 256].iter().all(|&flag| flag)
            })
        })
    }

    pub fn select(&self) -> Result<Step1Selection> {
        let mut matrices = Vec::with_capacity(16);
        let mut companions = Vec::with_capacity(16);
        for column in 0..4 {
            for row in 0..4 {
                let position = column * 4 + row;
                let mut selected = None;
                for (pair_index, pair) in PAIRS.iter().enumerate() {
                    let base = (position * 3 + pair_index) * 256;
                    if !self.flags[base..base + 256].iter().all(|&flag| flag) {
                        continue;
                    }
                    let companion = if row == pair[0] {
                        column * 4 + pair[2]
                    } else if row == pair[1] {
                        column * 4 + pair[3]
                    } else if row == pair[2] {
                        column * 4 + pair[0]
                    } else {
                        column * 4 + pair[1]
                    };
                    selected = Some((base, companion));
                    break;
                }
                let Some((base, companion)) = selected else {
                    bail!("step1 incomplete at column {column} row {row}");
                };
                matrices.push(Zeroizing::new(
                    self.inputs[base * 16..(base + 256) * 16].to_vec(),
                ));
                companions.push(companion);
            }
        }
        Ok(Step1Selection {
            matrices,
            companions,
        })
    }
}

/// Search up to the checked eight-million-block bound for a complete Step 1.
/// The reference is the same deterministic input used by the original attack.
pub fn search(target: &mut impl OracleTarget) -> Result<Step1Selection> {
    let reference_input = crate::fairplay_recovery_target::deterministic_input(0);
    let reference_output = shift_rows(target.apply(reference_input)?);
    let mut state = Step1State::new(reference_input, reference_output);
    for base in (0..MAX_PROBES).step_by(BATCH_SIZE) {
        if state.done() {
            break;
        }
        let jobs = (0..BATCH_SIZE)
            .map(|index| OracleJob {
                block: counter(base + index as u64),
                metadata: 0xffff,
            })
            .collect::<Vec<_>>();
        let outputs = target.evaluate_jobs(&jobs)?;
        for (job, raw) in jobs.iter().zip(outputs) {
            state.consider(shift_rows(raw), job.block);
        }
    }
    if !state.done() {
        bail!("step1 did not complete");
    }
    let selection = state.select()?;
    verify(target, reference_input, &selection)?;
    Ok(selection)
}

pub fn verify(
    target: &mut impl OracleTarget,
    reference_input: [u8; 16],
    selection: &Step1Selection,
) -> Result<()> {
    if selection.matrices.len() != 16 || selection.companions.len() != 16 {
        bail!("step1 selection does not contain sixteen byte positions");
    }
    let reference_output = shift_rows(target.apply(reference_input)?);
    let mut jobs = Vec::with_capacity(16 * 256);
    for matrix in &selection.matrices {
        if matrix.len() != 256 * 16 {
            bail!("step1 matrix is not 256 blocks");
        }
        for block in matrix.as_chunks::<16>().0 {
            jobs.push(OracleJob {
                block: *block,
                metadata: 0xffff,
            });
        }
    }
    let outputs = target.evaluate_jobs(&jobs)?;
    for position in 0..16 {
        let companion = selection.companions[position];
        if companion >= 16 {
            bail!("step1 companion is out of range");
        }
        for value in 0..256 {
            let view = shift_rows(outputs[position * 256 + value]);
            if view[position] != value as u8 {
                bail!("step1 verify byte {position} value {value}");
            }
            if view[companion] != reference_output[companion] {
                bail!("step1 companion mismatch");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_recovery_target::SidbTarget;
    use crate::{
        fairplay_oracle_model::OracleModel, fairplay_recovery_target::deterministic_input,
    };
    use sha2::{Digest, Sha256};

    #[test]
    fn first_64_public_sidb_probes_match_go_checkpoint() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let mut target = SidbTarget::new(&model, [0; 16]);
        let reference_input = deterministic_input(0);
        let reference_output = shift_rows(target.apply(reference_input).unwrap());
        assert_eq!(hex(&reference_output), "57a6cb226606bfe2b0332933ff95d1d1");
        let mut state = Step1State::new(reference_input, reference_output);
        let jobs = (0..64)
            .map(|index| OracleJob {
                block: counter(index),
                metadata: 0xffff,
            })
            .collect::<Vec<_>>();
        for (job, output) in jobs.iter().zip(target.evaluate_jobs(&jobs).unwrap()) {
            state.consider(shift_rows(output), job.block);
        }
        assert_eq!(state.claimed_count(), 54);
        let flags = state
            .flags
            .iter()
            .map(|flag| u8::from(*flag))
            .collect::<Vec<_>>();
        assert_eq!(
            format!("{:x}", Sha256::digest(flags)),
            "b78e834695c171d2470b99309a0f761bf2ae9ce34ebce937e42948f27c6fde2f"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&*state.inputs)),
            "a75129d381d3e51f209be07c3924adf20f2fab0d2da5a45105aba018f22c1416"
        );
    }

    #[test]
    #[ignore = "runs a full offline SIDB recovery search; execute in release mode"]
    fn full_public_sidb_step1_matches_go_matrices() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let mut target = SidbTarget::new(&model, [0; 16]);
        let selection = search(&mut target).unwrap();
        let mut hash = Sha256::new();
        for matrix in &selection.matrices {
            hash.update(&**matrix);
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "b507c3f104e70d64eb14946d678cea4828601a5691710be21b80b046858e7349"
        );
        assert_eq!(
            selection.companions,
            [2, 3, 3, 2, 6, 4, 5, 5, 11, 11, 8, 8, 15, 14, 13, 14]
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
