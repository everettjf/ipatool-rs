//! A small native authorization boundary, independent of the Store, guest
//! execution, model recovery, networking and IPA decryption implementations.

mod files;
#[cfg(target_os = "macos")]
mod native;

use std::{error::Error, fmt};
use zeroize::Zeroizing;

pub const APP_ID: &str = "dev.ipatool.rust";
pub const SERVICE: &str = "dev.ipatool.rust.fairplay-collector";
pub const PLIST: &str = "dev.ipatool.rust.fairplay-collector.plist";
pub const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
pub const NONCE_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Problem {
    Unsupported,
    SigningRequired,
    ApprovalRequired,
    Unavailable,
    InvalidRequest,
    NotConsoleUser,
    MissingState,
    PermissionDenied,
    InvalidState,
    StateChanged,
    Cancelled,
    UnsafeStateMetadata,
    StateTooLarge,
    UnsupportedStateFormat,
}

#[cfg(any(target_os = "macos", test))]
impl Problem {
    pub(crate) fn code(self) -> u64 {
        match self {
            Self::Unsupported => 1,
            Self::SigningRequired => 2,
            Self::ApprovalRequired => 3,
            Self::Unavailable => 4,
            Self::InvalidRequest => 5,
            Self::NotConsoleUser => 6,
            Self::MissingState => 7,
            Self::PermissionDenied => 8,
            Self::InvalidState => 9,
            Self::StateChanged => 10,
            Self::Cancelled => 11,
            Self::UnsafeStateMetadata => 12,
            Self::StateTooLarge => 13,
            Self::UnsupportedStateFormat => 14,
        }
    }
    pub(crate) fn from_code(code: u64) -> Self {
        match code {
            1 => Self::Unsupported,
            2 => Self::SigningRequired,
            3 => Self::ApprovalRequired,
            4 => Self::Unavailable,
            5 => Self::InvalidRequest,
            6 => Self::NotConsoleUser,
            7 => Self::MissingState,
            8 => Self::PermissionDenied,
            9 => Self::InvalidState,
            10 => Self::StateChanged,
            11 => Self::Cancelled,
            12 => Self::UnsafeStateMetadata,
            13 => Self::StateTooLarge,
            14 => Self::UnsupportedStateFormat,
            _ => Self::InvalidRequest,
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "Automatic authorization collection requires macOS 13 or later.",
            Self::SigningRequired => "Authorization collection requires the Developer ID signed application and matching helper.",
            Self::ApprovalRequired => "Approve local authorization access in macOS System Settings before preparing a model.",
            Self::Unavailable => "The authorization helper is unavailable or did not respond. Review its status before retrying.",
            Self::InvalidRequest => "The authorization helper rejected an invalid request or reply.",
            Self::NotConsoleUser => "Authorization collection is available only to the current signed-in Mac user.",
            Self::MissingState => "This Mac has no readable App Store authorization database. Install and open a matching iPhone or iPad app first.",
            Self::PermissionDenied => "macOS did not allow the required authorization data to be read.",
            Self::InvalidState => "This Mac's authorization database has an unsupported format or unsafe file metadata.",
            Self::StateChanged => "App Store authorization changed while being read. Finish any App Store activity before retrying.",
            Self::Cancelled => "Authorization collection was cancelled.",
            Self::UnsafeStateMetadata => "The local authorization database has an unsupported file type, owner, link or write permission. Its permissions were not changed.",
            Self::StateTooLarge => "The local authorization database exceeds the supported collection size. No model was saved.",
            Self::UnsupportedStateFormat => "The local authorization database version is not supported by this collector. No model was saved.",
        })
    }
}
impl Error for Problem {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    System,
    Shared,
}
impl Source {
    pub const ALL: [Self; 2] = [Self::System, Self::Shared];
    pub fn capture_path(self) -> &'static str {
        match self {
            Self::System => "state/fpsd-sc-info/SC Info.sidb",
            Self::Shared => "state/shared-sc-info/SC Info.sidb",
        }
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn components(self) -> &'static [&'static str] {
        match self {
            Self::System => &["private", "var", "db", "fpsd", "SC Info", "SC Info.sidb"],
            Self::Shared => &["Users", "Shared", "SC Info", "SC Info.sidb"],
        }
    }
}

pub struct StateFile {
    pub source: Source,
    pub bytes: Zeroizing<Vec<u8>>,
}
pub struct Snapshot {
    pub files: Vec<StateFile>,
}
impl Snapshot {
    pub fn checked(files: Vec<StateFile>) -> Result<Self, Problem> {
        if files.is_empty() {
            return Err(Problem::MissingState);
        }
        if files.len() > 2 {
            return Err(Problem::InvalidState);
        }
        let mut seen = Vec::new();
        for file in &files {
            if seen.contains(&file.source) {
                return Err(Problem::InvalidState);
            }
            if file.bytes.len() > MAX_STATE_BYTES {
                return Err(Problem::StateTooLarge);
            }
            if file.bytes.get(..4) != Some(&[0, 7, 0, 11]) {
                return Err(Problem::UnsupportedStateFormat);
            }
            seen.push(file.source);
        }
        Ok(Self { files })
    }
}

/// Read the same fixed inputs with existing user permissions. No system
/// registration or elevation occurs here, including on a permission failure.
pub fn read_local_snapshot() -> Result<Snapshot, Problem> {
    files::local()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Unsupported,
    SigningRequired,
    NotRegistered,
    RequiresApproval,
    Enabled,
    NotFound,
}

#[cfg(target_os = "macos")]
pub use native::{open_settings, register, request_snapshot, run_helper, status, unregister};

#[cfg(not(target_os = "macos"))]
pub fn status() -> Status {
    Status::Unsupported
}
#[cfg(not(target_os = "macos"))]
pub fn register() -> Result<Status, Problem> {
    Err(Problem::Unsupported)
}
#[cfg(not(target_os = "macos"))]
pub fn unregister() -> Result<Status, Problem> {
    Err(Problem::Unsupported)
}
#[cfg(not(target_os = "macos"))]
pub fn open_settings() -> Result<(), Problem> {
    Err(Problem::Unsupported)
}
#[cfg(not(target_os = "macos"))]
pub fn request_snapshot(_cancel: impl Fn() -> bool) -> Result<Snapshot, Problem> {
    Err(Problem::Unsupported)
}
#[cfg(not(target_os = "macos"))]
pub fn run_helper() -> Result<(), Problem> {
    Err(Problem::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_rejects_missing_duplicate_oversize_and_unknown_state() {
        assert_eq!(Snapshot::checked(vec![]).err(), Some(Problem::MissingState));
        let file = || StateFile {
            source: Source::System,
            bytes: Zeroizing::new(vec![0, 7, 0, 11]),
        };
        assert!(Snapshot::checked(vec![file()]).is_ok());
        assert_eq!(
            Snapshot::checked(vec![file(), file()]).err(),
            Some(Problem::InvalidState)
        );
        assert_eq!(
            Snapshot::checked(vec![StateFile {
                source: Source::Shared,
                bytes: Zeroizing::new(vec![0; MAX_STATE_BYTES + 1])
            }])
            .err(),
            Some(Problem::StateTooLarge)
        );
        assert_eq!(
            Snapshot::checked(vec![StateFile {
                source: Source::Shared,
                bytes: Zeroizing::new(vec![0, 7, 0, 12])
            }])
            .err(),
            Some(Problem::UnsupportedStateFormat)
        );
    }
    #[test]
    fn wire_problem_codes_are_fixed_redacted_and_closed() {
        for problem in [
            Problem::Unsupported,
            Problem::SigningRequired,
            Problem::ApprovalRequired,
            Problem::Unavailable,
            Problem::InvalidRequest,
            Problem::NotConsoleUser,
            Problem::MissingState,
            Problem::PermissionDenied,
            Problem::InvalidState,
            Problem::StateChanged,
            Problem::Cancelled,
            Problem::UnsafeStateMetadata,
            Problem::StateTooLarge,
            Problem::UnsupportedStateFormat,
        ] {
            assert_eq!(Problem::from_code(problem.code()), problem);
            assert!(!problem.to_string().contains("/Users/"));
        }
        assert_eq!(Problem::from_code(u64::MAX), Problem::InvalidRequest);
    }
}
