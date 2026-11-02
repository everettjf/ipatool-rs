//! Current-format FairPlay recovery, ported from UnfairPlay b3a7a432.
//! Public algorithm constants are independent of private enrollment material.

pub mod class;
pub mod outer;
pub mod state;
pub mod tags;
pub mod tree;

use aes::{
    Aes128,
    cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct RecoveredEnrollment {
    pub model: Zeroizing<Vec<u8>>,
    pub state_sha256: String,
    pub layout: outer::Layout,
    pub route: tree::RouteEvidence,
}

/// Algorithm identity stored in typed models; this is not an OS image hash.
pub fn algorithm_sha256() -> String {
    format!(
        "{:x}",
        Sha256::digest(b"unfairplay/typed-current-enrollment/v1")
    )
}

/// Recover from exactly one authenticated SIDB and one installed SINF. This
/// validates the selected license. The capture adapter must verify signed
/// keyfiles and process the matching IPA before publishing a managed model.
/// There is no alternate-record or engine retry.
pub fn recover(container: &[u8], hardware: &[u8], sinf: &[u8]) -> Result<RecoveredEnrollment> {
    if sinf.len() > 1 << 20 {
        bail!("installed SINF exceeds the supported bound");
    }
    crate::application::operation::check()?;
    let selector = crate::fairplay::parse_sinf_selector(sinf)?;
    let decoded = state::decode(container, hardware)?;
    let mut selected = tree::select(&decoded.body, hardware, selector)?;
    let key = class::account_key(hardware, selector.user, selector.key)?;
    let cipher = Aes128::new_from_slice(&*key).expect("validated account-class key");
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut *selected.ciphertext));
    let mut model = Zeroizing::new(vec![0u8; 4184]);
    model[..8].copy_from_slice(b"FPSENR2\0");
    model[8..12].copy_from_slice(&2u32.to_le_bytes());
    model[12..16].copy_from_slice(&4184u32.to_le_bytes());
    model[16..48].copy_from_slice(&Sha256::digest(b"unfairplay/typed-current-enrollment/v1"));
    model[48..52].copy_from_slice(&selector.user.to_le_bytes());
    model[52..56].copy_from_slice(&selector.key.to_le_bytes());
    model[56..72].copy_from_slice(&*selected.ciphertext);
    for table in model[88..].as_chunks_mut::<256>().0 {
        for (value, byte) in table.iter_mut().enumerate() {
            *byte = value as u8;
        }
    }
    let _logical = Zeroizing::new(
        crate::fairplay_key::CurrentSinfModel::parse(&model)?
            .logical_key(sinf)
            .context("selected SIDB value did not authenticate the SINF")?,
    );
    Ok(RecoveredEnrollment {
        model,
        state_sha256: decoded.state_sha256,
        layout: decoded.layout,
        route: selected.evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Control {
        container: Vec<u8>,
        hardware: Vec<u8>,
        sinf: Vec<u8>,
        trap_sinf: Vec<u8>,
        model_sha256: String,
        body_sha256: String,
        state_sha256: String,
        slot: usize,
        source_bytes: usize,
        route: serde_json::Value,
    }
    #[derive(serde::Deserialize)]
    struct Class {
        hardware: Vec<u8>,
        user: u32,
        key: u32,
        class_key: Vec<u8>,
    }
    #[derive(serde::Deserialize)]
    struct Vectors {
        controls: Vec<Control>,
        classes: Vec<Class>,
    }
    fn vectors() -> Vectors {
        serde_json::from_str(include_str!(
            "../tests/fixtures/fairplay-current-recovery-public-vectors.json"
        ))
        .unwrap()
    }

    #[test]
    fn account_class_keys_match_pinned_go_for_public_synthetic_inputs() {
        let vectors = vectors();
        assert_eq!(vectors.classes.len(), 32);
        for class in vectors.classes {
            let result = class::account_key(&class.hardware, class.user, class.key).unwrap();
            assert_eq!(result.as_slice(), class.class_key);
        }
    }

    #[test]
    fn authenticates_current_containers_and_recovers_identical_go_models_and_routes() {
        let vectors = vectors();
        assert_eq!(vectors.controls.len(), 2);
        assert!(vectors.controls.iter().any(|control| control.slot >= 14));
        for control in vectors.controls {
            let decoded = state::decode(&control.container, &control.hardware).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&*decoded.body)),
                control.body_sha256
            );
            let result = recover(&control.container, &control.hardware, &control.sinf).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&*result.model)),
                control.model_sha256
            );
            assert_eq!(result.state_sha256, control.state_sha256);
            assert_eq!(result.layout.selected_slot, control.slot);
            assert_eq!(result.layout.source_bytes, control.source_bytes);
            let route = serde_json::to_value(&result.route).unwrap();
            for (ours, reference) in [
                ("root_version", "RootVersion"),
                ("account_version", "AccountVersion"),
                ("type_cursor", "TypeCursor"),
                ("type_length", "TypeLength"),
                ("sign_cursor", "SignCursor"),
                ("sign_length", "SignLength"),
                ("value_cursor", "ValueCursor"),
                ("value_length", "ValueLength"),
                ("selected_record_index", "SelectedRecordIndex"),
                ("selected_payload_offset", "SelectedPayloadOffset"),
                ("selected_window_offset", "SelectedWindowOffset"),
            ] {
                assert_eq!(route[ours], control.route[reference], "route field {ours}");
            }
            assert!(
                crate::fairplay_key::CurrentSinfModel::parse(&result.model)
                    .unwrap()
                    .logical_key(&control.sinf)
                    .is_ok()
            );
            assert!(
                crate::fairplay::inspect_sinf(&control.sinf)
                    .unwrap()
                    .current_layout
            );
        }
    }

    #[test]
    fn rejects_metadata_fallback_tampering_unknown_tags_and_cancellation() {
        for control in vectors().controls {
            assert!(
                recover(&control.container, &control.hardware, &control.trap_sinf).is_err(),
                "a valid metadata record must not replace the selected route"
            );
            for offset in [0, control.container.len() / 2, control.container.len() - 1] {
                let mut changed = control.container.clone();
                changed[offset] ^= 1;
                assert!(recover(&changed, &control.hardware, &control.sinf).is_err());
            }
            let selector = crate::fairplay::parse_sinf_selector(&control.sinf).unwrap();
            let mut decoded = state::decode(&control.container, &control.hardware).unwrap();
            let tag = decoded.layout.root_cursor + 4;
            decoded.body[tag] ^= 1;
            assert!(tree::select(&decoded.body, &control.hardware, selector).is_err());
            let mut other_hardware = control.hardware.clone();
            other_hardware[0] ^= 1;
            assert!(recover(&control.container, &other_hardware, &control.sinf).is_err());
            let operation = crate::application::operation::Operation::default();
            let error = operation
                .run(|| {
                    operation.cancel();
                    recover(&control.container, &control.hardware, &control.sinf)
                })
                .err()
                .unwrap();
            assert!(error.is::<crate::application::operation::Cancelled>());
        }
    }
}
