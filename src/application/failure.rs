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
