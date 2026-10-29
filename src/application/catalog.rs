//! Public catalog requests shared by the desktop controls and background worker.

use crate::{App, CatalogClient, Platform};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Safe context for a catalog miss during account-region download preflight.
/// Only a validated region code is retained in desktop task history.
#[derive(Debug)]
pub struct AccountRegionUnavailable {
    country: String,
}

impl AccountRegionUnavailable {
    pub fn country(&self) -> &str {
        &self.country
    }
}

impl std::fmt::Display for AccountRegionUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "application unavailable in account region {}",
            self.country
        )
    }
}

impl std::error::Error for AccountRegionUnavailable {}

pub fn lookup_for_account(
    client: &CatalogClient,
    id: Option<i64>,
    bundle: Option<&str>,
    country: &str,
    platform: Option<Platform>,
) -> Result<App> {
    // Validate before retaining input in a user-visible error summary.
    let country = country.to_ascii_uppercase();
    if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        bail!("account region must be a two-letter code");
    }
    account_lookup_result(client.lookup(id, bundle, &country, platform), country)
}

fn account_lookup_result(result: Result<App>, country: String) -> Result<App> {
    result.map_err(|error| {
        if error.is::<crate::catalog::AppNotFound>() {
            error.context(AccountRegionUnavailable { country })
        } else {
            error
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Auto,
    Search,
    AppId,
    BundleId,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Automatic",
            Self::Search => "Search",
            Self::AppId => "App ID",
            Self::BundleId => "Bundle ID",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    pub mode: Mode,
    pub term: String,
    pub country: String,
    pub platform: Platform,
    app_id: Option<i64>,
}

impl Query {
    pub fn new(mode: Mode, term: &str, country: &str, platform: Platform) -> Result<Self> {
        let mut term = term.trim().to_owned();
        if term.is_empty() {
            bail!("Enter a search term, app ID, or bundle identifier.");
        }
        let mode = if mode == Mode::Auto {
            if term.starts_with("https://apps.apple.com/") {
                let url = url::Url::parse(&term)?;
                term = url
                    .path_segments()
                    .and_then(|mut parts| {
                        parts.find(|part| {
                            part.starts_with("id")
                                && part[2..].bytes().all(|byte| byte.is_ascii_digit())
                        })
                    })
                    .map(|part| part[2..].to_owned())
                    .ok_or_else(|| {
                        anyhow::anyhow!("The App Store link does not contain a numeric app ID.")
                    })?;
                Mode::AppId
            } else if term.bytes().all(|byte| byte.is_ascii_digit()) {
                Mode::AppId
            } else if term.contains('.')
                && term
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            {
                Mode::BundleId
            } else {
                Mode::Search
            }
        } else {
            mode
        };
        let country = country.trim().to_ascii_uppercase();
        if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            bail!("Enter a two-letter country code, such as US or GB.");
        }
        let app_id = if mode == Mode::AppId {
            let id = term.parse::<i64>().ok().filter(|id| *id > 0);
            if id.is_none() {
                bail!("App ID must be a positive integer.");
            }
            id
        } else {
            None
        };
        Ok(Self {
            mode,
            term,
            country,
            platform,
            app_id,
        })
    }

    pub fn limit(&self) -> i64 {
        if self.platform == Platform::Visionos {
            12
        } else {
            25
        }
    }

    pub fn execute(&self) -> Result<Vec<App>> {
        let client = CatalogClient::new()?;
        match self.mode {
            Mode::Search | Mode::Auto => Ok(client
                .search(&self.term, &self.country, self.limit(), Some(self.platform))?
                .apps),
            Mode::AppId | Mode::BundleId => Ok(vec![client.lookup(
                self.app_id,
                (self.mode == Mode::BundleId).then_some(self.term.as_str()),
                &self.country,
                Some(self.platform),
            )?]),
        }
    }

    pub fn description(&self) -> String {
        format!(
            "{} / {} / {} / {}",
            self.mode.label(),
            self.term,
            platform_name(self.platform),
            self.country
        )
    }

    pub fn lookup_command(&self, app: &App) -> String {
        format!(
            "ipatool-rs lookup --app-id {} --platform {} --country {}",
            app.id,
            platform_name(self.platform),
            self.country
        )
    }

    pub fn download_command(&self, app: &App) -> String {
        format!(
            "ipatool-rs download --app-id {} --platform {}",
            app.id,
            platform_name(self.platform)
        )
    }
}

pub fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::Unknown => "unknown",
        Platform::Iphone => "iphone",
        Platform::Ipad => "ipad",
        Platform::Appletv => "appletv",
        Platform::Watchos => "watchos",
        Platform::Visionos => "visionos",
        Platform::Macos => "macos",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_lookup_misses_explain_the_account_region_without_persisting_private_context() {
        use crate::application::failure::{Failure, FailureKind};
        let miss = anyhow::Error::new(crate::catalog::AppNotFound)
            .context("https://example.invalid/?token=private-fixture");
        let error = account_lookup_result(Err(miss), "CN".into())
            .unwrap_err()
            .context("private-account@example.invalid");
        let failure = Failure::from_error(&error);
        assert_eq!(failure.kind, FailureKind::NotFound);
        assert!(failure.title.contains("CN"));
        assert!(failure.message.contains("account's CN region"));
        assert!(failure.message.contains("No package download started"));
        let serialized = serde_json::to_string(&failure).unwrap();
        assert!(!serialized.contains("private-fixture"));
        assert!(!serialized.contains("private-account"));
        let other =
            account_lookup_result(Err(anyhow::anyhow!("decode error")), "CN".into()).unwrap_err();
        assert_eq!(Failure::from_error(&other).kind, FailureKind::Unavailable);
        assert!(account_lookup_result(Ok(App::default()), "US".into()).is_ok());
    }

    #[test]
    fn automatic_identity_detection_can_be_overridden_without_changing_storefront() {
        for (term, mode) in [
            ("42", Mode::AppId),
            ("invalid.example.fixture", Mode::BundleId),
            ("fixture app", Mode::Search),
            (
                "https://apps.apple.com/us/app/fixture/id42?platform=mac",
                Mode::AppId,
            ),
        ] {
            let query = Query::new(Mode::Auto, term, "gb", Platform::Macos).unwrap();
            assert_eq!(query.mode, mode);
            assert_eq!(query.country, "GB");
            if mode == Mode::AppId {
                assert_eq!(query.app_id, Some(42));
            }
        }
        let manual = Query::new(
            Mode::Search,
            "invalid.example.fixture",
            "GB",
            Platform::Macos,
        )
        .unwrap();
        assert_eq!(manual.mode, Mode::Search);
        assert_eq!(manual.term, "invalid.example.fixture");
    }

    #[test]
    fn rejects_invalid_requests_before_network_access() {
        for term in ["", " ", "0", "-1", "abc", "9223372036854775808"] {
            assert!(Query::new(Mode::AppId, term, "US", Platform::Iphone).is_err());
        }
        for country in ["", "USA", "1A", "\u{00e9}"] {
            assert!(Query::new(Mode::Search, "notes", country, Platform::Iphone).is_err());
        }
        assert!(Query::new(Mode::BundleId, "  ", "US", Platform::Macos).is_err());
    }

    #[test]
    fn normalizes_inputs_and_retains_unicode_search_terms() {
        let query = Query::new(Mode::Search, "  caf\u{00e9}  ", " gb ", Platform::Macos).unwrap();
        assert_eq!(query.term, "caf\u{00e9}");
        assert_eq!(query.country, "GB");
        assert_eq!(query.limit(), 25);
        assert_eq!(
            Query::new(Mode::Search, "notes", "US", Platform::Visionos)
                .unwrap()
                .limit(),
            12
        );
    }

    #[test]
    fn numeric_bundle_identifier_is_not_treated_as_app_id() {
        let query = Query::new(Mode::BundleId, "123", "US", Platform::Iphone).unwrap();
        assert_eq!(query.app_id, None);
        let query = Query::new(Mode::AppId, "123", "US", Platform::Iphone).unwrap();
        assert_eq!(query.app_id, Some(123));
    }

    #[test]
    fn commands_use_the_result_snapshot_and_never_interpolate_search_text() {
        let query = Query::new(Mode::Search, "$(example)", "gb", Platform::Macos).unwrap();
        let app = App {
            id: 42,
            ..Default::default()
        };
        assert_eq!(
            query.lookup_command(&app),
            "ipatool-rs lookup --app-id 42 --platform macos --country GB"
        );
        assert_eq!(
            query.download_command(&app),
            "ipatool-rs download --app-id 42 --platform macos"
        );
    }
}
