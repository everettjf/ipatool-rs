//! In-process Rust recovery of the checked SIDB AES-128 external encoding model.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. Attribution is in `licenses/LICENSE-DARKPHOENIX.txt`.

use std::time::Instant;

use anyhow::{Result, bail};
use zeroize::Zeroize;

use crate::{
    fairplay_recovery_math::{
        Encoding, aes_encrypt, expand_key, inv_mix_columns, inv_shift_rows, inv_sub_bytes,
        mix_columns, round_key, shift_rows, xor,
    },
    fairplay_recovery_round::{RoundRecovery, first_permutation, recover_round, round_permutation},
    fairplay_recovery_step1, fairplay_recovery_step2,
    fairplay_recovery_step3::Step3Recovery,
    fairplay_recovery_target::{OracleTarget, deterministic_input},
};

pub struct Recovery {
    pub key: [u8; 16],
    pub input_encoding: Encoding,
    pub output_encoding: Encoding,
    pub milliseconds: f64,
}

impl Drop for Recovery {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn apply_last_round_decrypt(
    data: [u8; 16],
    round_key0: [u8; 16],
    round_key1: [u8; 16],
) -> [u8; 16] {
    let state = xor(inv_sub_bytes(inv_shift_rows(data)), round_key1);
    xor(
        inv_sub_bytes(inv_shift_rows(inv_mix_columns(state))),
        round_key0,
    )
}

fn external_encodings(
    target: &mut impl OracleTarget,
    gtilde: &Encoding,
    step3: &Step3Recovery,
    round: &RoundRecovery,
) -> Result<(Encoding, Encoding)> {
    let first = first_permutation(gtilde, &step3.gbar, step3.coefficient);
    let lambda_beta = round_permutation(round.lambda, round.beta);
    let expanded = expand_key(round.aes_key);
    let (round_key0, round_key1) = (round_key(&expanded, 0), round_key(&expanded, 1));
    let mut output = Encoding([[0; 256]; 16]);
    let mut output_set = [[false; 256]; 16];
    for value in 0..=255 {
        let block = [value as u8; 16];
        let middle = lambda_beta.encode(shift_rows(mix_columns(first.encode(shift_rows(block)))));
        let decoded = apply_last_round_decrypt(middle, round_key0, round_key1);
        for position in 0..16 {
            if output_set[position][decoded[position] as usize] {
                bail!("output encoding collision");
            }
            output_set[position][decoded[position] as usize] = true;
            output.0[position][decoded[position] as usize] = value as u8;
        }
    }
    let output_decoder = output.inverse()?;
    let mut input = Encoding([[0; 256]; 16]);
    let mut input_set = [[false; 256]; 16];
    for value in 0..=255 {
        let plaintext = [value as u8; 16];
        let raw = target.apply(plaintext)?;
        let decoded = output_decoder.encode(raw);
        let inner = aes_encrypt(decoded, &expanded);
        for position in 0..16 {
            if input_set[position][inner[position] as usize] {
                bail!("input encoding collision");
            }
            input_set[position][inner[position] as usize] = true;
            input.0[position][inner[position] as usize] = value as u8;
        }
    }
    input.check_permutation()?;
    output.check_permutation()?;
    for index in 0..4 {
        let plaintext = deterministic_input(100 + index);
        let raw = target.apply(plaintext)?;
        let decoded = output_decoder.encode(raw);
        let inner = aes_encrypt(decoded, &expanded);
        if input.encode(inner) != plaintext {
            bail!("external encoding verification failed");
        }
    }
    Ok((input, output))
}

/// Recover one private SIDB model using the checked public transform and a
/// caller-supplied enrollment frame. The result contains secret key material.
pub fn recover(target: &mut impl OracleTarget) -> Result<Recovery> {
    let started = Instant::now();
    let step1 = fairplay_recovery_step1::search(target)?;
    let gtilde = fairplay_recovery_step2::recover(target, &step1)?;
    let step3 = crate::fairplay_recovery_step3::recover(target, &gtilde)?;
    let round = recover_round(target, &gtilde, &step3)?;
    let (input_encoding, output_encoding) = external_encodings(target, &gtilde, &step3, &round)?;
    Ok(Recovery {
        key: round.aes_key,
        input_encoding,
        output_encoding,
        milliseconds: started.elapsed().as_secs_f64() * 1000.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_oracle_model::OracleModel;
    use crate::fairplay_recovery_target::SidbTarget;
    use sha2::{Digest, Sha256};

    #[test]
    #[ignore = "runs complete SIDB AES recovery; execute in release mode"]
    fn public_sidb_full_recovery_matches_go() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let mut target = SidbTarget::new(&model, [0; 16]);
        let recovered = recover(&mut target).unwrap();
        assert_eq!(hex(&recovered.key), "6ca1ee8ee3c55f59c4bbeb41689c9f58");
        assert_eq!(
            encoding_digest(&recovered.input_encoding),
            "a591fbe4a9eed83397ec6bd86519241709d4d0107d726258fee1c06c8267669a"
        );
        assert_eq!(
            encoding_digest(&recovered.output_encoding),
            "739622aab6aa2f23f1096e24c35a89fe09e493fe9e18f33b3270e3e4f06a52b4"
        );
    }

    fn encoding_digest(value: &Encoding) -> String {
        let mut hash = Sha256::new();
        for table in &value.0 {
            hash.update(table);
        }
        format!("{:x}", hash.finalize())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
