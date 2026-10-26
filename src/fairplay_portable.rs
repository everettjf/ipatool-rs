//! Account-independent 26A428 FairPlay evaluators with sanitized pinned models.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::{
    fairplay_frame,
    fairplay_oracle_model::OracleModel,
    fairplay_recovery::{self, Recovery},
    fairplay_recovery_target::SidbTarget,
    fairplay_state,
};

const STATE_MODEL: &[u8] =
    include_bytes!("../tests/fixtures/fairplay-oracle-state-public.model.gz");
const FRAME_MODEL: &[u8] =
    include_bytes!("../tests/fixtures/fairplay-oracle-frame-public.model.gz");
const SIDB_MODEL: &[u8] = include_bytes!("../tests/fixtures/fairplay-oracle-sidb-public.model.gz");

pub fn evaluate_state(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !matches!(input.len(), 192 | 224) {
        bail!("state source must be exactly 192 or 224 bytes");
    }
    let model = OracleModel::parse_gzip(STATE_MODEL)?;
    Ok(Zeroizing::new(fairplay_state::evaluate(&model, input)?))
}

pub fn evaluate_frame(input: &[u8; 16]) -> Result<Zeroizing<[u8; 16]>> {
    let model = OracleModel::parse_gzip(FRAME_MODEL)?;
    Ok(Zeroizing::new(fairplay_frame::evaluate(&model, input)?))
}

pub fn recover_sidb(frame: [u8; 16]) -> Result<Recovery> {
    let model = OracleModel::parse_gzip(SIDB_MODEL)?;
    let mut target = SidbTarget::new(&model, frame);
    fairplay_recovery::recover(&mut target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_state_and_frame_match_reference() {
        let state = evaluate_state(&[0; 192]).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&*state)),
            "77e57830920bbf3d68e8566a143a0d0f3c7998154573acddb9cd1fb30e4e5e83"
        );
        let frame = evaluate_frame(&core::array::from_fn(|index| index as u8)).unwrap();
        assert_eq!(
            frame
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "7f16546e18e54d0fc45af5832836532c"
        );
    }
}
