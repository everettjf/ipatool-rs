//! Public catalog lookup of the latest platform external version identifier.

use std::{error::Error, fmt};

use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use url::Url;

use crate::{
    App, CatalogClient, Platform, buy_params::parse_buy_params, catalog::validate_country, macos,
    vision,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VersionLookupNotFound {
    PlatformApp,
    PlatformOffers,
    IosCatalog,
}

impl fmt::Display for VersionLookupNotFound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PlatformApp => "platform version lookup returned no app",
            Self::PlatformOffers => "platform version lookup returned no offers",
            Self::IosCatalog => "iOS catalog lookup returned HTTP 404",
        })
    }
}

impl Error for VersionLookupNotFound {}

impl CatalogClient {
    pub fn latest_external_version_id(
        &self,
        app: &App,
        country: &str,
        platform: Platform,
    ) -> Result<String> {
        if app.id <= 0 {
            bail!("app ID is required for platform version lookup");
        }
        validate_country(country)?;
        if platform == Platform::Visionos {
            let url = vision::product_url(app.id, country)?;
            let body = self.get(url)?.body;
            return vision::product_version_id_bytes(&body, app.id);
        }

        if platform == Platform::Macos {
            let url = macos::product_url(app.id, country)?;
            let body = self.get(url)?.body;
            return macos::product_version_id_bytes(&body, app);
        }

        let catalogs: &[&str] = match platform {
            Platform::Iphone | Platform::Ipad | Platform::Watchos => {
                &["enterprisestore", "iphone", "ipad"]
            }
            Platform::Appletv => &["atv9"],
            Platform::Macos => unreachable!("handled above"),
            Platform::Unknown | Platform::Visionos => bail!("invalid platform"),
        };
        let mut last_missing = VersionLookupNotFound::PlatformApp;
        for catalog in catalogs {
            let url = mdm_lookup_url(app.id, country, catalog)?;
            let value: Value = self.get(url)?.json()?;
            match mdm_version_id(&value, app.id) {
                Ok(Some(id)) => return Ok(id),
                Ok(None) => {
                    last_missing = mdm_missing_reason(&value, app.id);
                }
                Err(error) => return Err(error),
            }
        }

        if matches!(platform, Platform::Iphone | Platform::Ipad) {
            let url = ios_catalog_url(app.id, country, platform)?;
            let response = self
                .get_allow_not_found(url)?
                .ok_or(VersionLookupNotFound::IosCatalog)?;
            let value: Value = response.json()?;
            return ios_catalog_version_id(&value, app, platform);
        }
        Err(anyhow!(last_missing).context(format!(
            "app {} in storefront {} (catalogs: {})",
            app.id,
            country,
            catalogs.join(", "),
        )))
    }
}

pub fn mdm_lookup_url(app_id: i64, country: &str, catalog: &str) -> Result<Url> {
    validate_country(country)?;
    let mut url = Url::parse(
        "https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/wa/lookup",
    )?;
    url.query_pairs_mut()
        .append_pair("version", "2")
        .append_pair("id", &app_id.to_string())
        .append_pair("p", "mdm-lockup")
        .append_pair("caller", "MDM")
        .append_pair("platform", catalog)
        .append_pair("cc", &country.to_ascii_lowercase())
        .append_pair("l", "en");
    Ok(url)
}

fn ios_catalog_url(app_id: i64, country: &str, platform: Platform) -> Result<Url> {
    let mut url = Url::parse(&format!(
        "https://apps.apple.com/api/apps/v1/catalog/{}/apps/{app_id}",
        country.to_ascii_lowercase()
    ))?;
    url.query_pairs_mut().append_pair(
        "platform",
        match platform {
            Platform::Iphone => "iphone",
            Platform::Ipad => "ipad",
            _ => bail!("invalid iOS catalog platform"),
        },
    );
    Ok(url)
}

fn version_value(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn mdm_version_id(value: &Value, app_id: i64) -> Result<Option<String>> {
    let id = app_id.to_string();
    let Some(item) = value.get("results").and_then(|results| results.get(&id)) else {
        return Ok(None);
    };
    let Some(offer) = item
        .get("offers")
        .and_then(Value::as_array)
        .and_then(|offers| offers.first())
    else {
        return Ok(None);
    };
    if let Some(id) = offer.pointer("/version/externalId").and_then(version_value)
        && !id.is_empty()
    {
        return Ok(Some(id));
    }
    let buy_params = offer
        .get("buyParams")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = parse_buy_params(buy_params)
        .map_err(|error| anyhow!("failed to parse buy params: {error}"))?;
    let id = params.get("appExtVrsId").cloned().unwrap_or_default();
    if id.is_empty() {
        bail!("platform version lookup returned no external version id");
    }
    Ok(Some(id))
}

fn mdm_missing_reason(value: &Value, app_id: i64) -> VersionLookupNotFound {
    if value
        .get("results")
        .and_then(|results| results.get(app_id.to_string().as_str()))
        .is_some()
    {
        VersionLookupNotFound::PlatformOffers
    } else {
        VersionLookupNotFound::PlatformApp
    }
}

fn ios_catalog_version_id(value: &Value, app: &App, platform: Platform) -> Result<String> {
    let items = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("iOS catalog lookup must return exactly one app"))?;
    if items.len() != 1 {
        bail!("iOS catalog lookup must return exactly one app");
    }
    let item = &items[0];
    if item.get("id").and_then(Value::as_str) != Some(app.id.to_string().as_str())
        || item.get("type").and_then(Value::as_str) != Some("apps")
    {
        bail!("iOS catalog lookup returned a different app");
    }
    let attributes = item
        .get("attributes")
        .ok_or_else(|| anyhow!("iOS catalog lookup returned no metadata"))?;
    let family = match platform {
        Platform::Iphone => "iphone",
        Platform::Ipad => "ipad",
        _ => bail!("invalid iOS catalog platform"),
    };
    let has_family = attributes
        .get("deviceFamilies")
        .and_then(Value::as_array)
        .is_some_and(|families| families.iter().any(|value| value.as_str() == Some(family)));
    let ios = attributes.pointer("/platformAttributes/ios");
    if !has_family || ios.is_none() {
        bail!("iOS catalog lookup returned no metadata for the requested platform");
    }
    let ios = ios.unwrap();
    if !app.bundle_id.is_empty()
        && ios.get("bundleId").and_then(Value::as_str) != Some(app.bundle_id.as_str())
    {
        bail!("iOS catalog lookup returned a different bundle identifier");
    }
    let id = ios
        .get("externalVersionId")
        .and_then(version_value)
        .unwrap_or_default();
    if id.parse::<u64>().ok().filter(|id| *id > 0).is_none() {
        bail!("iOS catalog lookup returned no valid external version id");
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdm_url_uses_account_country_and_platform() {
        let url = mdm_lookup_url(42, "GB", "atv9").unwrap();
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["cc"], "gb");
        assert_eq!(params["platform"], "atv9");
        assert_eq!(params["id"], "42");
    }

    #[test]
    fn mdm_version_accepts_numeric_and_buy_param_ids() {
        let data: Value = serde_json::from_str(
            r#"{"results":{"42":{"offers":[{"version":{"externalId":123}}]}}}"#,
        )
        .unwrap();
        assert_eq!(mdm_version_id(&data, 42).unwrap(), Some("123".into()));
        let data: Value = serde_json::from_str(
            r#"{"results":{"42":{"offers":[{"buyParams":"salableAdamId=42&appExtVrsId=456"}]}}}"#,
        )
        .unwrap();
        assert_eq!(mdm_version_id(&data, 42).unwrap(), Some("456".into()));
        let malformed =
            serde_json::json!({"results": {"42": {"offers": [{"buyParams": "appExtVrsId=%zz"}]}}});
        assert!(mdm_version_id(&malformed, 42).is_err());
        let duplicate = serde_json::json!({"results": {"42": {"offers": [{"buyParams": "appExtVrsId=456&appExtVrsId=789"}]}}});
        assert_eq!(mdm_version_id(&duplicate, 42).unwrap(), Some("456".into()));
        assert_eq!(mdm_version_id(&data, 43).unwrap(), None);
        assert_eq!(
            mdm_missing_reason(&data, 43),
            VersionLookupNotFound::PlatformApp
        );
        let no_offers = serde_json::json!({"results": {"42": {"offers": []}}});
        assert_eq!(mdm_version_id(&no_offers, 42).unwrap(), None);
        assert_eq!(
            mdm_missing_reason(&no_offers, 42),
            VersionLookupNotFound::PlatformOffers
        );
    }

    #[test]
    fn ios_fallback_validates_identity_and_device_family() {
        let app = App {
            id: 42,
            bundle_id: "com.example.app".into(),
            ..App::default()
        };
        let data: Value = serde_json::from_str(r#"{"data":[{"id":"42","type":"apps","attributes":{"deviceFamilies":["iphone","ipad"],"platformAttributes":{"ios":{"bundleId":"com.example.app","externalVersionId":"12345"}}}}]}"#).unwrap();
        assert_eq!(
            ios_catalog_version_id(&data, &app, Platform::Ipad).unwrap(),
            "12345"
        );
        let wrong = App {
            bundle_id: "com.other.app".into(),
            ..app
        };
        assert!(ios_catalog_version_id(&data, &wrong, Platform::Ipad).is_err());
    }
}
