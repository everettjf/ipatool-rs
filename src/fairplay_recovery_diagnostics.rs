//! Fixed diagnostic identifiers for current recovery; raw error chains remain private.

use anyhow::Error;

#[derive(Clone, Copy, Debug)]
pub enum Phase {
    Inputs,
    Database,
    Selection,
    License,
    Sample,
}

#[derive(Debug)]
pub struct RecoveryProblem {
    pub phase: Phase,
    check: Option<usize>,
}

impl RecoveryProblem {
    pub fn annotate(error: Error, phase: Phase) -> Error {
        let check = error.chain().find_map(|cause| {
            let text = cause.to_string();
            CHECKS.iter().position(|known| *known == text)
        });
        error.context(Self { phase, check })
    }
    pub fn message(&self) -> String {
        let message = match self.phase {
            Phase::Inputs => "The collected files did not pass the integrity and signature checks.",
            Phase::Database => {
                "This Mac's local authorization data could not be read or authenticated by the current recovery method."
            }
            Phase::Selection => {
                "The selected app's authorization could not be located in this Mac's supported authorization records."
            }
            Phase::License => {
                "The recovered authorization did not validate the selected app's license."
            }
            Phase::Sample => {
                "The recovered model did not pass decryption of the matching sample IPA."
            }
        };
        let code = self.check.map_or_else(
            || "unclassified".to_owned(),
            |index| format!("{:03}", index + 1),
        );
        format!("{message} No model was saved. Diagnostic: FP-R-{code}.")
    }
}
impl std::fmt::Display for RecoveryProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Model preparation checks failed")
    }
}
impl std::error::Error for RecoveryProblem {}

// Append new checks; existing diagnostic identifiers must remain stable.
const CHECKS: &[&str] = &[
    "SIDB body exceeds the supported bound",
    "SIDB children do not fill their parent",
    "account-class derivation requires six hardware bytes",
    "ambiguous tag constructor codebook",
    "capture contains an unsafe relative path",
    "capture contains distinct SIDB databases; selection is ambiguous",
    "capture contains duplicate descriptors",
    "capture contains no SIDB database",
    "capture descriptor has an invalid size",
    "capture directories and files must be private",
    "capture exceeds its total size limit",
    "capture executable or selector metadata is inconsistent",
    "capture hardware descriptor is inconsistent",
    "capture input does not match its descriptor",
    "capture input exceeds its size limit",
    "capture input grew beyond its size limit",
    "capture input grew while reading",
    "capture is missing a required role descriptor",
    "capture keyfile suffix disagrees with its variant",
    "capture path has an invalid file type",
    "capture role input exceeds its size limit",
    "capture sample IPA descriptor is inconsistent",
    "capture size overflow",
    "current SIDB codec did not reach its bounded exit",
    "current SIDB container authentication failed",
    "current SIDB has unmapped source or payload geometry",
    "current capture recovery requires Unix private-file permissions",
    "current outer digest exceeded its iteration bound",
    "current outer digest has an unmapped control state",
    "current recovery requires a six-byte hardware identity",
    "duplicate selected SIDB route tag",
    "empty captured legacy SUPF requires a signed v5 companion",
    "excessive SIDB child count",
    "excessive SIDB trailing padding",
    "installed SINF does not match the current capture selector",
    "installed SINF exceeds the supported bound",
    "installed SINF must belong to the captured app",
    "invalid SIDB node extent",
    "invalid SIDB version leaf",
    "invalid capture path component",
    "invalid current SIDB authentication geometry",
    "invalid current SIDB payload size",
    "invalid current SIDB selected state slot",
    "invalid current outer pre-round",
    "invalid current outer state geometry",
    "invalid or excessive SIDB tree geometry",
    "missing hardware snapshot",
    "missing installed SINF snapshot",
    "negative capture file size",
    "recovery output already exists",
    "recovery output needs a parent",
    "recovery requires a matching sample IPA",
    "recovery requires a signed SUPF or SUPP keyfile for the installed executable",
    "sample SINF selector does not match the capture",
    "selected SIDB value did not authenticate the SINF",
    "tag constructor requires a six-byte hardware identity",
    "unknown SIDB tag constructor code",
    "unsupported SIDB account schema",
    "unsupported SIDB format",
    "unsupported SIDB root tag",
    "unsupported SIDB schema version",
    "unsupported SIDB selected value leaf",
    "unsupported SIDB sign leaf",
    "unsupported SIDB type leaf",
    "unsupported capture schema or file count",
    "unsupported current SIDB version or input geometry",
    "unsupported optional outer input",
    "unsupported selected SIDB route",
    "FairPlay certificate authority signature failed",
    "FairPlay keyfile has an invalid size",
    "FairPlay keyfile variant disagrees with its file class",
    "FairPlay signed keyfile prefix authentication failed",
    "SUPF certificate has invalid bounds",
    "SUPF signature has invalid bounds",
    "SUPP certificate and signature have invalid bounds",
    "SUPP page records have invalid bounds",
    "invalid BMP distinguished name",
    "invalid FairPlay certificate or signature extent",
    "invalid RSA public key bit string",
    "invalid authority signature bit string",
    "invalid authority signature length",
    "missing selected SIDB route tag",
    "parse FairPlay certificate",
    "truncated keyfile length",
    "unexpected FairPlay certificate authority",
    "unexpected FairPlay certificate subject",
    "unsupported FairPlay RSA key geometry",
    "unsupported FairPlay authority signature algorithm",
    "unsupported FairPlay distinguished-name string",
    "unsupported FairPlay keyfile envelope variant",
    "unsupported FairPlay public key algorithm",
];
