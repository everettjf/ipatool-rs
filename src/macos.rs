//! Select native Mac and compatible iOS offers from serialized Mac product-page data.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use url::Url;

use crate::{App, buy_params::parse_buy_params, vision::serialized_server_data_bytes};

pub fn product_url(app_id: i64, country: &str) -> Result<Url> {
    let mut url = Url::parse(&format!(
        "https://apps.apple.com/{}/app/id{app_id}",
        country.to_ascii_lowercase()
    ))?;
    url.query_pairs_mut().append_pair("platform", "mac");
    Ok(url)
}

pub fn product_version_id(body: &str, app: &App) -> Result<String> {
    product_version_id_bytes(body.as_bytes(), app)
}

pub(crate) fn product_version_id_bytes(body: &[u8], app: &App) -> Result<String> {
    let data = serialized_server_data_bytes(body)?;
    let page: Value = serde_json::from_str(&data).context("failed to decode Mac product page")?;
    let mut native_versions = HashSet::new();
    let mut mobile_versions = HashSet::new();
    collect_versions(
        &page,
        app,
        false,
        &mut native_versions,
        &mut mobile_versions,
    );
    let versions = if native_versions.is_empty() {
        mobile_versions
    } else {
        native_versions
    };
    match versions.len() {
        0 => bail!("macOS purchase configuration has no external version id for the requested app"),
        1 => Ok(versions.into_iter().next().unwrap()),
        _ => bail!("macOS purchase configurations contain conflicting external version ids"),
    }
}

fn collect_versions(
    value: &Value,
    app: &App,
    mobile_mac_compatible: bool,
    native_versions: &mut HashSet<String>,
    mobile_versions: &mut HashSet<String>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_versions(
                    item,
                    app,
                    mobile_mac_compatible,
                    native_versions,
                    mobile_versions,
                );
            }
        }
        Value::Object(map) => {
            let mobile_mac_compatible = mobile_mac_compatible
                || map.get("isIOSBinaryMacOSCompatible") == Some(&Value::Bool(true));
            if let Some(config) = map.get("purchaseConfiguration").and_then(Value::as_object) {
                let platforms = config.get("appPlatforms").and_then(Value::as_array);
                let is_mac = platforms
                    .is_some_and(|platforms| platforms.iter().any(|p| p.as_str() == Some("mac")));
                let is_mobile = platforms.is_some_and(|platforms| {
                    platforms
                        .iter()
                        .any(|p| matches!(p.as_str(), Some("phone" | "pad")))
                });
                let bundle = config
                    .get("bundleId")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if (is_mac || (mobile_mac_compatible && is_mobile))
                    && (app.bundle_id.is_empty() || bundle == app.bundle_id)
                {
                    let buy_params = config
                        .get("buyParams")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if let Ok(params) = parse_buy_params(buy_params)
                        && params.get("salableAdamId") == Some(&app.id.to_string())
                        && let Some(version) = params.get("appExtVrsId")
                        && version.parse::<u64>().ok().is_some_and(|id| id != 0)
                    {
                        if is_mac {
                            native_versions.insert(version.clone());
                        } else {
                            mobile_versions.insert(version.clone());
                        }
                    }
                }
            }
            for child in map.values() {
                collect_versions(
                    child,
                    app,
                    mobile_mac_compatible,
                    native_versions,
                    mobile_versions,
                );
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
            r#"[{{"isIOSBinaryMacOSCompatible":true,"purchaseConfiguration":{{"bundleId":"com.nebula.karing","appPlatforms":["phone","pad"],"buyParams":"salableAdamId=6472431552&appExtVrsId=891116578"}}}},{{"purchaseConfiguration":{{"appPlatforms":["mac"],"buyParams":"salableAdamId=100&appExtVrsId=123"}}}},{MAC_OFFER}]"#
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
    fn selects_ios_binary_marked_compatible_with_mac() {
        let app = App {
            id: 6773347027,
            bundle_id: "com.flexdesign.touchlink".into(),
            ..App::default()
        };
        let offer = r#"{"lockup":{"isIOSBinaryMacOSCompatible":true,"buttonAction":{"purchaseConfiguration":{"bundleId":"com.flexdesign.touchlink","appPlatforms":["phone"],"metricsPlatformDisplayStyle":"ios","buyParams":"salableAdamId=6773347027&appExtVrsId=887524728"}}}}"#;
        assert_eq!(product_version_id(&page(offer), &app).unwrap(), "887524728");
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

    #[test]
    fn reads_product_json_when_unrelated_html_bytes_are_not_utf8() {
        let mut body = vec![0xff];
        body.extend_from_slice(page(MAC_OFFER).as_bytes());
        body.push(0xfe);
        assert_eq!(
            product_version_id_bytes(&body, &app()).unwrap(),
            "876660716"
        );
    }

    #[test]
    fn reads_product_json_with_invalid_utf8_in_unrelated_string() {
        let mut body = page(&format!(r#"{{"note":"bad","offer":{MAC_OFFER}}}"#)).into_bytes();
        let note = body.windows(3).position(|part| part == b"bad").unwrap();
        body[note] = 0xff;
        assert_eq!(
            product_version_id_bytes(&body, &app()).unwrap(),
            "876660716"
        );
    }
}
