//! Non-secret error summaries for desktop tasks and persisted history.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureKind {
    Cancelled,
    VerificationRequired,
    UnlockRequired,
    AuthenticationRequired,
    AuthenticationRejected,
    NetworkUnavailable,
    LicenseRequired,
    NotFound,
    PermissionDenied,
    OutputExists,
    Unavailable,
    ModelRequired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub title: String,
    pub message: String,
    pub action: String,
}

impl Failure {
    /// Raw error chains can contain signed URLs or private inputs. Persist only
    /// this allowlisted summary; the CLI retains its existing error formatter.
    pub fn from_error(error: &anyhow::Error) -> Self {
        use FailureKind::*;
        if super::operation::is_cancellation(error) {
            return Self {
                kind: Cancelled,
                title: "Cancelled".into(),
                message: "The operation stopped at a safe boundary.".into(),
                action: "Retry".into(),
            };
        }
        if let Some(problem) = error.downcast_ref::<super::fairplay_setup::ModelProblem>() {
            use super::fairplay_setup::ModelProblem;
            let (kind, message, action) = match problem {
                ModelProblem::Missing | ModelProblem::NoMatch => (
                    ModelRequired,
                    "Your original IPA is preserved. Prepare reusable decryption for this App Store enrollment, or import a matching model in Advanced options.",
                    "Prepare decryption",
                ),
                ModelProblem::Ambiguous => (
                    Unavailable,
                    "Several models conflict for this authorization. No model was guessed. Review the saved model folder in Advanced tools.",
                    "Review saved models",
                ),
                ModelProblem::Collection => (
                    Unavailable,
                    "Confirm that you installed and opened an iPhone or iPad app through this Mac's App Store using the same Apple account as the sample IPA. Collection needs readable local FairPlay data; the app cannot elevate its permissions. Check system support in Advanced tools.",
                    "Review preparation",
                ),
                ModelProblem::Recovery => (
                    Unavailable,
                    "The collected authorization or system build could not use the supported recovery path. Review matching system files in Advanced options and compatibility diagnostics. No model was saved.",
                    "Review preparation",
                ),
                ModelProblem::Validation => (
                    Unavailable,
                    "The selected model or generated materials did not pass the sample IPA checks. Nothing was activated. Review that the app, IPA, and materials belong to the same enrollment.",
                    "Review preparation",
                ),
                ModelProblem::InvalidStore => (
                    Unavailable,
                    "Saved model files are missing, changed, or not private. No model was selected. Review the saved model folder in Advanced tools.",
                    "Review saved models",
                ),
                ModelProblem::UnsupportedPlatform => (
                    Unavailable,
                    "Managed model storage currently requires macOS or Linux private-file permissions. Windows preparation and automatic decryption remain unavailable.",
                    "Review platform support",
                ),
            };
            return Self {
                kind,
                title: problem.to_string(),
                message: message.into(),
                action: action.into(),
            };
        }
        if let Some(region) = error.downcast_ref::<super::catalog::AccountRegionUnavailable>() {
            return Self {
                kind: NotFound,
                title: format!("Application unavailable in {}", region.country()),
                message: format!(
                    "The application was not found for the selected platform in your account's {} region. Search can show applications from other regions; changing the browsing region does not change your Apple account's region. No package download started.",
                    region.country()
                ),
                action: "Review platform and account region".into(),
            };
        }
        let verification_rejected = error.chain().any(|cause| {
            cause
                .to_string()
                .starts_with("Apple did not complete verification;")
        });
        let authentication_rejected = error.chain().any(|cause| {
            cause
                .to_string()
                .starts_with("Apple authentication failed:")
                || cause.to_string() == "account is disabled"
        });
        let missing_account = error
            .chain()
            .any(|cause| cause.to_string() == "account not found in keychain");
        let (kind, title, message, action) = if super::operation::is_cancellation(error) {
            (
                Cancelled,
                "Cancelled",
                "The operation stopped at a safe boundary.",
                "Retry",
            )
        } else if error.is::<crate::store_login::AuthCodeRequired>() || verification_rejected {
            (
                VerificationRequired,
                "Verification code required",
                "Enter a fresh code from your trusted Apple device.",
                "Enter code",
            )
        } else if error.is::<crate::credentials::CredentialUnlockRequired>() {
            (
                UnlockRequired,
                "Unlock credential storage",
                "Enter the passphrase for the encrypted file store.",
                "Unlock",
            )
        } else if error.is::<super::account::AccountChanged>() {
            (
                AuthenticationRequired,
                "Account or storefront changed",
                "Load the active account and review this operation before retrying. The previous account's task was not resumed automatically.",
                "Open account",
            )
        } else if error.is::<crate::store_purchase::PasswordTokenExpired>() || missing_account {
            (
                AuthenticationRequired,
                "Session expired",
                "Sign in again to continue this operation.",
                "Sign in",
            )
        } else if authentication_rejected {
            (
                AuthenticationRejected,
                "Apple did not accept the sign-in",
                "Check your Apple ID and password, account status, and any verification requirements. No account response or credentials are included in task history.",
                "Review credentials",
            )
        } else if error.is::<reqwest::Error>() {
            (
                NetworkUnavailable,
                "Network request did not complete",
                "Check your network connection and retry. Apple may also be temporarily unavailable. Received download bytes are retained where the package workflow supports safe resumption.",
                "Retry",
            )
        } else if error.is::<crate::store_download_product::LicenseRequired>() {
            (
                LicenseRequired,
                "License required",
                "This account needs an application license before downloading. You can explicitly request a free license.",
                "Review license",
            )
        } else if error.is::<crate::catalog::AppNotFound>() {
            (
                NotFound,
                "Application unavailable",
                "The application was not found for the selected platform and storefront.",
                "Review filters",
            )
        } else if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists)
        {
            (
                OutputExists,
                "Output already exists",
                "The existing file was preserved. Review this task and choose a new output path before retrying.",
                "Choose another path",
            )
        } else if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
        {
            (
                PermissionDenied,
                "Access denied",
                "The application could not access a required file or folder. Choose an accessible path and review the material requirements.",
                "Review paths",
            )
        } else {
            (
                Unavailable,
                "Operation could not complete",
                "Review the selected inputs, account access, network connection, and available disk space before retrying. Private protocol responses are not included in task history.",
                "Review and retry",
            )
        };
        Self {
            kind,
            title: title.into(),
            message: message.into(),
            action: action.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_model_failures_keep_private_context_out_of_history() {
        use crate::application::fairplay_setup::ModelProblem;
        let error = anyhow::anyhow!("private fixture-model-bytes and /private/fixture/path")
            .context(ModelProblem::NoMatch);
        let failure = Failure::from_error(&error);
        assert_eq!(failure.kind, FailureKind::ModelRequired);
        let text = serde_json::to_string(&failure).unwrap();
        assert!(!text.contains("fixture-model-bytes") && !text.contains("/private/fixture/path"));
    }
    #[test]
    fn private_protocol_details_do_not_enter_serialized_history() {
        let error = anyhow::anyhow!(
            "request https://example.invalid/download?token=fixture-private failed"
        );
        let failure = Failure::from_error(&error);
        assert_eq!(failure.kind, FailureKind::Unavailable);
        let serialized = serde_json::to_string(&failure).unwrap();
        assert!(!serialized.contains("fixture-private"));
        assert!(!serialized.contains("https://"));
        let wrapped = anyhow::Error::new(crate::store_login::AuthCodeRequired)
            .context("private account fixture");
        assert_eq!(
            Failure::from_error(&wrapped).kind,
            FailureKind::VerificationRequired
        );
    }
}
