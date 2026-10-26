//! Rust oracle adapter used by the FairPlay AES-model recovery attack.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. Attribution is in `licenses/LICENSE-DARKPHOENIX.txt`.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    fairplay_frame::BUILD_HASH,
    fairplay_oracle_model::{OracleModel, OracleState},
    fairplay_recovery_math::{Encoding, mix_columns, shift_rows},
    fairplay_sidb::{evaluate_in_state, fault_for_metadata},
};

#[derive(Clone, Copy)]
pub struct OracleJob {
    pub block: [u8; 16],
    pub metadata: u32,
}

pub struct SidbTarget<'a> {
    model: &'a OracleModel,
    state: OracleState<'a>,
    frame: Zeroizing<[u8; 16]>,
}

impl<'a> SidbTarget<'a> {
    pub fn new(model: &'a OracleModel, frame: [u8; 16]) -> Self {
        Self {
            model,
            state: model.state(),
            frame: Zeroizing::new(frame),
        }
    }

    pub fn evaluate_jobs(&mut self, jobs: &[OracleJob]) -> Result<Vec<[u8; 16]>> {
        if self.model.binary_hash != BUILD_HASH {
            bail!("SIDB oracle model does not match the checked 26A428 build");
        }
        jobs.iter()
            .map(|job| {
                let fault = fault_for_metadata(job.metadata)?;
                evaluate_in_state(&mut self.state, &self.frame, &job.block, fault)
            })
            .collect()
    }

    pub fn apply(&mut self, block: [u8; 16]) -> Result<[u8; 16]> {
        Ok(self.evaluate_jobs(&[OracleJob {
            block,
            metadata: 0xffff,
        }])?[0])
    }

    pub fn apply_fault(
        &mut self,
        block: [u8; 16],
        round: u16,
        position: u8,
        xor: u8,
    ) -> Result<[u8; 16]> {
        let metadata = u32::from(round) | (u32::from(position) << 16) | (u32::from(xor) << 24);
        Ok(self.evaluate_jobs(&[OracleJob { block, metadata }])?[0])
    }
}

pub fn deterministic_input(index: u32) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"macOS FairPlay Go oracle input");
    hash.update(index.to_be_bytes());
    hash.finalize()[..16].try_into().unwrap()
}

pub fn counter(value: u64) -> [u8; 16] {
    let mut result = [0; 16];
    result[8..].copy_from_slice(&value.to_be_bytes());
    result
}

pub fn attack_view(raw: [u8; 16], output: &[Encoding], reverse_mc: bool) -> [u8; 16] {
    let mut data = shift_rows(raw);
    for (index, encoding) in output.iter().enumerate() {
        data = encoding.encode(data);
        if reverse_mc || index + 1 < output.len() {
            data = shift_rows(mix_columns(data));
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_recovery_math::Encoding;

    #[test]
    fn sidb_target_matches_original_go_batch_protocol() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let mut target = SidbTarget::new(&model, [0; 16]);
        let jobs = [
            OracleJob {
                block: [0; 16],
                metadata: 0xffff,
            },
            OracleJob {
                block: [0; 16],
                metadata: 0x0100_0006,
            },
            OracleJob {
                block: [0; 16],
                metadata: 0x0100_0008,
            },
            OracleJob {
                block: [0; 16],
                metadata: 0x0100_0009,
            },
        ];
        let outputs = target.evaluate_jobs(&jobs).unwrap();
        assert_eq!(hex(&outputs[0]), "ac95f1b50aff72888eaa4e292ccd0792");
        assert_eq!(hex(&outputs[1]), "cd10256356f0e15a75683e27c8e4fbf3");
        assert_eq!(hex(&outputs[2]), "2ef55ae0e5c2187467323c601a01096e");
        assert_eq!(hex(&outputs[3]), "3195f1b50a1e72888eaa6b292ccd0772");
        assert_eq!(target.apply([0; 16]).unwrap(), outputs[0]);
        assert_eq!(target.apply_fault([0; 16], 9, 0, 1).unwrap(), outputs[3]);
    }

    #[test]
    fn deterministic_inputs_use_go_seed_and_big_endian_counter() {
        let expected = Sha256::digest(b"macOS FairPlay Go oracle input\0\0\0\0");
        assert_eq!(&deterministic_input(0)[..], &expected[..16]);
        assert_eq!(
            &counter(0x0102_0304_0506_0708)[..],
            &[0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        let encoding = Encoding::identity();
        let input = counter(42);
        assert_eq!(attack_view(input, &[encoding], false), shift_rows(input));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
