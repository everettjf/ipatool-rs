//! Account-independent 26A428 FairPlay evaluators with sanitized pinned models.

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::{
    fairplay::{SinfSelector, inspect_sinf},
    fairplay_enrollment_model::{FIRST_TRANSFORM_BYTES, build_fpsenr2, first_transform_whitening},
    fairplay_frame,
    fairplay_key::CurrentSinfModel,
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

pub struct PortableEnrollment {
    pub slot: usize,
    pub model: Zeroizing<Vec<u8>>,
    pub recovery_milliseconds: f64,
}

/// Recover a selector-bound enrollment model from the 26A428 state source.
/// The SINF atom tree selects the slot whose decrypted private data validates.
pub fn recover_enrollment_from_state(
    state_source: &[u8],
    transform_source: &[u8; FIRST_TRANSFORM_BYTES],
    transform_encoded: &[u8; FIRST_TRANSFORM_BYTES],
    selector: SinfSelector,
    fairplayd_sha256: [u8; 32],
    sinf: &[u8],
    selected_slot: Option<usize>,
) -> Result<PortableEnrollment> {
    if !matches!(state_source.len(), 192 | 224) {
        bail!("state source must be exactly 192 or 224 bytes");
    }
    if fairplayd_sha256 != fairplay_frame::BUILD_HASH {
        bail!("embedded FairPlay evaluators require the checked 26A428 build");
    }
    let sinf_diagnostic = inspect_sinf(sinf)?;
    if sinf_diagnostic.selector != selector {
        bail!("SINF selector does not match requested enrollment");
    }
    if !sinf_diagnostic.current_layout {
        bail!("SINF private data is not the current 26A428 layout");
    }
    first_transform_whitening(transform_source, transform_encoded)?;
    let slot_count = state_source.len() / 16;
    if selected_slot.is_some_and(|slot| slot >= slot_count) {
        bail!("selected state slot is out of range");
    }
    let transformed = evaluate_state(state_source)?;
    let frame_model = OracleModel::parse_gzip(FRAME_MODEL)?;
    let sidb_model = OracleModel::parse_gzip(SIDB_MODEL)?;
    let slots = if let Some(slot) = selected_slot {
        slot..slot + 1
    } else {
        0..slot_count
    };
    let mut first_candidate_error = None;
    for slot in slots {
        let block: [u8; 16] = transformed[slot * 16..(slot + 1) * 16]
            .try_into()
            .expect("validated state slot bounds");
        let frame = Zeroizing::new(fairplay_frame::evaluate(&frame_model, &block)?);
        let mut target = SidbTarget::new(&sidb_model, *frame);
        let recovered = match fairplay_recovery::recover(&mut target) {
            Ok(recovered) => recovered,
            Err(error) if selected_slot.is_none() => {
                first_candidate_error
                    .get_or_insert_with(|| error.context(format!("recover state slot {slot}")));
                continue;
            }
            Err(error) => return Err(error).context(format!("recover state slot {slot}")),
        };
        let model = match build_fpsenr2(
            &recovered,
            selector,
            fairplayd_sha256,
            transform_source,
            transform_encoded,
            &[],
        ) {
            Ok(model) => model,
            Err(error) if selected_slot.is_none() => {
                first_candidate_error
                    .get_or_insert_with(|| error.context(format!("build state slot {slot}")));
                continue;
            }
            Err(error) => return Err(error).context(format!("build state slot {slot}")),
        };
        if let Ok(parsed) = CurrentSinfModel::parse(&model)
            && parsed.logical_key(sinf).is_ok()
        {
            return Ok(PortableEnrollment {
                slot,
                model,
                recovery_milliseconds: recovered.milliseconds,
            });
        }
    }
    if let Some(error) = first_candidate_error {
        return Err(error).context("no state slot produced a valid SINF enrollment model");
    }
    bail!("no state slot produced a valid SINF enrollment model")
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
