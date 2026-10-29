//! User-facing guidance; protocol diagnostics remain available in task details.

use super::FairMode;
use serde_json::Value;

pub(super) struct Guide {
    pub tab: &'static str,
    pub title: &'static str,
    pub introduction: &'static str,
    pub prepare: &'static str,
    pub result: &'static str,
    pub action: &'static str,
    pub action_hint: &'static str,
}

pub(super) fn guide(mode: FairMode) -> Guide {
    match mode {
        FairMode::Setup | FairMode::Saved => Guide {
            tab: "Reusable decryption",
            title: "Reusable decryption",
            introduction: "Prepare once and reuse matching models.",
            prepare: "Use the guided preparation.",
            result: "Models stay private.",
            action: "Continue",
            action_hint: "Original IPAs are preserved.",
        },
        FairMode::Inspect => Guide {
            tab: "1. Check files",
            title: "Find out what you need next",
            introduction: "Choose your IPA and any materials you already have. This checks compatibility; it does not decrypt the app.",
            prepare: "Prepare: an IPA downloaded with your account, or a previously collected materials folder. A decryption model is optional at this stage.",
            result: "Next: read the results in Downloads, then open the suggested step to review its inputs. Nothing starts automatically.",
            action: "Check compatibility",
            action_hint: "Checks your files without decrypting the IPA.",
        },
        FairMode::Collect => Guide {
            tab: "2. Collect files",
            title: "Collect the materials needed for a model",
            introduction: "Use this step when you have neither collected materials nor a matching decryption model.",
            prepare: "Prepare: the installed .app on a supported Mac, permission to read its local FairPlay data, and a new output folder. Having only an IPA is not enough for collection.",
            result: "Result: a private materials folder. After success, choose Create decryption model on the result to continue to step 3. Keep the folder private.",
            action: "Collect files",
            action_hint: "Reads local FairPlay data and saves a private folder.",
        },
        FairMode::Recover => Guide {
            tab: "3. Create model",
            title: "Create a decryption model from collected files",
            introduction: "A model contains the FairPlay parameters needed by the final step. It is not an AI model.",
            prepare: "Prepare: the complete materials folder from step 2 and a new output folder. Run step 1 first if you do not know whether its system build is supported. Add any requested matching files under Advanced options.",
            result: "Result: a decryption model. After success, choose Use for decryption on the result, then select the matching IPA in step 4.",
            action: "Create model",
            action_hint: "Processes collected files; this does not decrypt the IPA.",
        },
        FairMode::Decrypt => Guide {
            tab: "4. Decrypt IPA",
            title: "Decrypt an IPA with a matching model",
            introduction: "Already have a compatible model? You can start here without repeating collection or model creation.",
            prepare: "Prepare: your downloaded IPA and its matching decryption model. Use step 1 to check them together if you are unsure.",
            result: "Result: a separate IPA and a processing report. Your original is preserved. Inspect the output before relying on it; task completion alone does not verify its contents.",
            action: "Decrypt IPA",
            action_hint: "Creates a new IPA and report; preserves existing files.",
        },
    }
}

pub(super) fn inspection_summary(details: &Value) -> &'static str {
    if details.get("ready").and_then(Value::as_bool) != Some(true) {
        "Some files or compatibility requirements need attention. Review the items below before continuing."
    } else if details
        .get("compatible_model")
        .and_then(Value::as_str)
        .is_some()
    {
        "The selected IPA and model passed the prerequisite checks. You can review decryption next; no decryption has run."
    } else {
        "The supplied files passed the prerequisite checks. A matching decryption model is still needed before you can decrypt an IPA."
    }
}

pub(super) fn check_description(name: &str, passed: bool) -> &'static str {
    match (name, passed) {
        ("ipa_sinf", true) => "IPA authorization data can be read.",
        ("current_sinf_layout", true) => "IPA authorization format is supported.",
        ("current_sinf_layout", false) => {
            "IPA authorization format is unsupported. This IPA cannot use the current workflow."
        }
        ("model_valid", true) => "Decryption model can be read.",
        ("selector_match", true) => {
            "A decryption model matches the IPA and any selected materials' system build."
        }
        ("selector_match", false) => {
            "No matching model was found. Choose the model for this IPA and the same system build."
        }
        ("capture_integrity", true) => "Collected files passed their integrity checks.",
        ("supported_fairplayd", true) => "The detected system build supports model creation.",
        ("supported_fairplayd", false) => {
            "This system build is not supported for model creation. A different version label will not fix this."
        }
        ("native_state_accessible", true) => "Local FairPlay data is accessible for collection.",
        ("native_state_accessible", false) => {
            "Local FairPlay data is missing or inaccessible. Collection needs permission to read it."
        }
        ("hardware_iomac", true) => "The Mac's required hardware identifier is available.",
        ("hardware_iomac", false) => {
            "The required hardware identifier is unavailable. Review the collection settings."
        }
        ("capture_selector_match", true) => {
            "The collected materials match this IPA's authorization identifier."
        }
        ("capture_selector_match", false) => {
            "The collected materials do not match this IPA. Choose materials for the same app and version."
        }
        (_, true) => "An additional requirement passed. See task details for its technical name.",
        (_, false) => {
            "An additional requirement needs attention. Open task details for more information."
        }
    }
}

pub(super) fn inspection_error(error: &str) -> &'static str {
    if error.starts_with("ipa:") {
        "Could not read the IPA's authorization data. Select the original downloaded IPA; see task details for the exact error."
    } else if error.starts_with("model:") {
        "Could not read the decryption model. Choose a valid model file or folder; see task details for the exact error."
    } else if error.starts_with("capture:") || error.starts_with("capture IPA:") {
        "Could not verify the collected materials. Choose the complete original folder; see task details for the exact error."
    } else if error.starts_with("host:") {
        "Could not inspect this Mac's FairPlay environment. See task details before attempting collection."
    } else {
        "A compatibility requirement was not met. Review the matching checks and open task details for the exact error."
    }
}

pub(super) fn inspection_warning(warning: &str) -> &'static str {
    if warning.starts_with("SINF geometry cannot prove account age") {
        "This experimental workflow assumes a newly created Apple account enrolled on a supported Mac. The IPA check cannot confirm that condition."
    } else if warning.starts_with("one or more SINF files") {
        "Part of this IPA uses an unsupported authorization format. Review the format check before continuing."
    } else if warning.starts_with("this capture requires the checked compatibility evaluator") {
        "Creating a model from these materials also requires a matching system file. Select it under Advanced options in step 3."
    } else {
        "An additional limitation applies. Open task details to read the full warning before continuing."
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_completed_ipa_check_never_implies_a_model_or_decryption_exists() {
        let ipa_only = json!({"ready": true, "checks": {"ipa_sinf": true}});
        assert!(inspection_summary(&ipa_only).contains("model is still needed"));
        let matched = json!({"ready": true, "compatible_model": "fixture.bin"});
        assert!(inspection_summary(&matched).contains("no decryption has run"));
        let mismatch = json!({"ready": false, "compatible_model": "fixture.bin"});
        assert!(inspection_summary(&mismatch).contains("need attention"));
        assert!(check_description("future_requirement", false).contains("needs attention"));
        assert!(inspection_error("model: invalid header").contains("model file or folder"));
    }
}
