//! Select the native Mac App Store offer from serialized product-page data.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use url::Url;

use crate::{App, buy_params::parse_buy_params, vision::serialized_server_data};

pub fn product_url(app_id: i64, country: &str) -> Result<Url> {
    let mut url = Url::parse(&format!(
        "https://apps.apple.com/{}/app/id{app_id}",
        country.to_ascii_lowercase()
    ))?;
    url.query_pairs_mut().append_pair("platform", "mac");
    Ok(url)
}

pub fn product_version_id(body: &str, app: &App) -> Result<String> {
    let data = serialized_server_data(body)?;
    let page: Value = serde_json::from_str(data).context("failed to decode Mac product page")?;
    let mut versions = HashSet::new();
    collect_versions(&page, app, &mut versions);
    match versions.len() {
        0 => bail!("macOS purchase configuration has no external version id for the requested app"),
        1 => Ok(versions.into_iter().next().unwrap()),
        _ => bail!("macOS purchase configurations contain conflicting external version ids"),
    }
}

fn collect_versions(value: &Value, app: &App, versions: &mut HashSet<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_versions(item, app, versions);
            }
        }
        Value::Object(map) => {
            if let Some(config) = map.get("purchaseConfiguration").and_then(Value::as_object) {
                let is_mac = config
                    .get("appPlatforms")
                    .and_then(Value::as_array)
                    .is_some_and(|platforms| platforms.iter().any(|p| p.as_str() == Some("mac")));
                let bundle = config
                    .get("bundleId")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if is_mac && (app.bundle_id.is_empty() || bundle == app.bundle_id) {
                    let buy_params = config
                        .get("buyParams")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if let Ok(params) = parse_buy_params(buy_params)
                        && params.get("salableAdamId") == Some(&app.id.to_string())
                        && let Some(version) = params.get("appExtVrsId")
                        && version.parse::<u64>().ok().is_some_and(|id| id != 0)
                    {
                        versions.insert(version.clone());
                    }
                }
            }
            for child in map.values() {
                collect_versions(child, app, versions);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_OFFER: &str = r#"{"purchaseConfiguration":{"bundleId":"com.nebula.karing","appPlatforms":["mac","tv","phone","pad"],"metricsPlatformDisplayStyle":"ios","buyParams":"salableAdamId=6472431552&appExtVrsId=876660716"}}"#;

    fn app() -> App {
        App {
            id: 6472431552,
            bundle_id: "com.nebula.karing".into(),
            ..App::default()
        }
    }

    fn page(config: &str) -> String {
        format!(r#"<script id="serialized-server-data">{config}</script>"#)
    }

    #[test]
    fn selects_mac_offer_and_ignores_other_platforms_and_apps() {
        let mixed = format!(
            r#"[{{"purchaseConfiguration":{{"bundleId":"com.nebula.karing","appPlatforms":["phone","pad"],"buyParams":"salableAdamId=6472431552&appExtVrsId=891116578"}}}},{{"purchaseConfiguration":{{"appPlatforms":["mac"],"buyParams":"salableAdamId=100&appExtVrsId=123"}}}},{MAC_OFFER}]"#
        );
        assert_eq!(
            product_version_id(&page(&mixed), &app()).unwrap(),
            "876660716"
        );
        assert_eq!(
            product_url(app().id, "DE").unwrap().as_str(),
            "https://apps.apple.com/de/app/id6472431552?platform=mac"
        );
    }

    #[test]
    fn rejects_missing_wrong_or_conflicting_mac_offers() {
        for config in [
            "{",
            "{}",
            r#"{"purchaseConfiguration":{"bundleId":"com.nebula.karing","appPlatforms":["phone"],"buyParams":"salableAdamId=6472431552&appExtVrsId=876660716"}}"#,
            r#"{"purchaseConfiguration":{"bundleId":"other","appPlatforms":["mac"],"buyParams":"salableAdamId=6472431552&appExtVrsId=876660716"}}"#,
            r#"{"purchaseConfiguration":{"bundleId":"com.nebula.karing","appPlatforms":["mac"],"buyParams":"salableAdamId=6472431552&appExtVrsId=invalid"}}"#,
            r#"{"purchaseConfiguration":{"bundleId":"com.nebula.karing","appPlatforms":["mac"],"buyParams":"salableAdamId=6472431552&appExtVrsId=123&other=%zz"}}"#,
            r#"{"purchaseConfiguration":{"bundleId":"com.nebula.karing","appPlatforms":["mac"],"buyParams":"salableAdamId=06472431552&appExtVrsId=876660716"}}"#,
            &format!(
                "[{MAC_OFFER},{{\"purchaseConfiguration\":{{\"bundleId\":\"com.nebula.karing\",\"appPlatforms\":[\"mac\"],\"buyParams\":\"salableAdamId=6472431552&appExtVrsId=123\"}}}}]"
            ),
        ] {
            assert!(product_version_id(&page(config), &app()).is_err());
        }
    }

    #[test]
    fn prefers_double_quoted_product_data_marker_over_earlier_single_quoted_text() {
        let body = format!(
            r#"<script>const example = "id='serialized-server-data'";</script><script id="serialized-server-data">{MAC_OFFER}</script>"#
        );
        assert_eq!(product_version_id(&body, &app()).unwrap(), "876660716");
    }
}
