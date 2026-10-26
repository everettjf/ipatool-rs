//! Recover the first external byte encoding with SIDB fault probes.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. Attribution is in `licenses/LICENSE-DARKPHOENIX.txt`.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::{
    fairplay_recovery_math::{Encoding, INV_SHIFT, shift_rows},
    fairplay_recovery_step1::Step1Selection,
    fairplay_recovery_target::{OracleJob, SidbTarget},
};

fn fault_byte(position: usize, candidate: usize) -> u8 {
    let fault_position = (position - position % 4 + candidate) % 16;
    INV_SHIFT[fault_position] as u8
}

fn fault_metadata(position: usize, candidate: usize, value: u8) -> u32 {
    if value == 0 {
        0xffff
    } else {
        9u32 | ((fault_byte(position, candidate) as u32) << 16) | ((value as u32) << 24)
    }
}

/// Reconstruct one byte permutation from its 256x256 differential table.
pub fn tolhuizen(rows: &[[u8; 256]; 256]) -> Result<[u8; 256]> {
    let mut by_pivot = [None; 256];
    for (index, row) in rows.iter().enumerate() {
        let pivot = row[0] as usize;
        if by_pivot[pivot].replace(index).is_some() {
            bail!("Tolhuizen duplicate pivot");
        }
    }
    let mut permutation = [-1i16; 256];
    permutation[0] = 0;
    let mut next = 1;
    for bit in 0..8 {
        while next < 256 && permutation[next] >= 0 {
            next += 1;
        }
        let Some(&row_index) = by_pivot.get(next).and_then(Option::as_ref) else {
            bail!("Tolhuizen missing pivot");
        };
        permutation[next] = 1 << bit;
        let row = &rows[row_index];
        for index in 1..256 {
            if permutation[index] < 0 {
                continue;
            }
            let target = row[index] as usize;
            let expected = permutation[index] ^ permutation[next];
            if permutation[target] < 0 {
                permutation[target] = expected;
            } else if permutation[target] != expected {
                bail!("Tolhuizen inconsistency");
            }
        }
    }
    let mut result = [0; 256];
    for (index, value) in permutation.into_iter().enumerate() {
        if value < 0 {
            bail!("Tolhuizen incomplete");
        }
        result[index] = value as u8;
    }
    Ok(result)
}

pub fn recover(target: &mut SidbTarget<'_>, step1: &Step1Selection) -> Result<Encoding> {
    if step1.matrices.len() != 16 || step1.companions.len() != 16 {
        bail!("step1 selection does not contain sixteen byte positions");
    }
    let mut probe_jobs = Vec::with_capacity(16 * 16 * 256);
    for position in 0..16 {
        let matrix = &step1.matrices[position];
        if matrix.len() != 256 * 16 || step1.companions[position] >= 16 {
            bail!("step1 selection is malformed at byte {position}");
        }
        let plaintext: [u8; 16] = matrix[..16].try_into().unwrap();
        for candidate in 0..16 {
            for value in 0..=255 {
                probe_jobs.push(OracleJob {
                    block: plaintext,
                    metadata: fault_metadata(position, candidate, value as u8),
                });
            }
        }
    }
    let probe = Zeroizing::new(target.evaluate_jobs(&probe_jobs)?);
    let mut positions = [0; 16];
    for position in 0..16 {
        let companion = step1.companions[position];
        let found = (0..16).find(|&candidate| {
            let mut seen = [false; 256];
            for value in 0..256 {
                let view = shift_rows(probe[(position * 16 + candidate) * 256 + value]);
                if value == 0 && view[position] != 0 {
                    return false;
                }
                let item = view[companion] as usize;
                if seen[item] {
                    return false;
                }
                seen[item] = true;
            }
            true
        });
        positions[position] =
            found.ok_or_else(|| anyhow::anyhow!("step2 no fault position for byte {position}"))?;
    }

    let mut jobs = Vec::with_capacity(16 * 256 * 256);
    for (position, &candidate) in positions.iter().enumerate() {
        let matrix = &step1.matrices[position];
        for input in 0..256 {
            let block: [u8; 16] = matrix[input * 16..(input + 1) * 16].try_into().unwrap();
            for value in 0..=255 {
                jobs.push(OracleJob {
                    block,
                    metadata: fault_metadata(position, candidate, value as u8),
                });
            }
        }
    }
    let outputs = Zeroizing::new(target.evaluate_jobs(&jobs)?);
    let mut encoding = Encoding([[0; 256]; 16]);
    for position in 0..16 {
        let companion = step1.companions[position];
        let mut rows = Zeroizing::new([[0; 256]; 256]);
        for input in 0..256 {
            let mut seen = [false; 256];
            for value in 0..256 {
                let view = shift_rows(outputs[(position * 256 + input) * 256 + value]);
                if value == 0 && view[position] != input as u8 {
                    bail!("step2 unfaulted mismatch");
                }
                let key = view[companion] as usize;
                if seen[key] {
                    bail!("step2 duplicate companion");
                }
                seen[key] = true;
                rows[key][input] = view[position];
            }
        }
        encoding.0[position] = tolhuizen(&rows)?;
    }
    encoding.check_permutation()?;
    Ok(encoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fairplay_oracle_model::OracleModel, fairplay_recovery_step1::search};
    use sha2::{Digest, Sha256};

    #[test]
    fn tolhuizen_recovers_linear_xor_labeling() {
        let mut rows = [[0; 256]; 256];
        for (pivot, row) in rows.iter_mut().enumerate() {
            for (input, cell) in row.iter_mut().enumerate() {
                *cell = (pivot ^ input) as u8;
            }
        }
        assert_eq!(
            tolhuizen(&rows).unwrap(),
            core::array::from_fn(|index| index as u8)
        );
    }

    #[test]
    #[ignore = "runs over a million SIDB fault probes; execute in release mode"]
    fn full_public_sidb_step2_matches_go_encoding() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-sidb-public.model.gz"
        ))
        .unwrap();
        let mut target = SidbTarget::new(&model, [0; 16]);
        let step1 = search(&mut target).unwrap();
        let encoding = recover(&mut target, &step1).unwrap();
        let mut hash = Sha256::new();
        for table in &encoding.0 {
            hash.update(table);
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "5a4b99b24e3e7a9ee161b96e1bcde9528502ce1d94a0c2e771f7dd1748679d80"
        );
    }
}
