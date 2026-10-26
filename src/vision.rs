use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use url::Url;

use crate::{App, Platform};

const SCRIPT_ID: &str = "serialized-server-data";
const MAX_RESULTS: usize = 12;

pub fn search_url(term: &str, country: &str) -> Result<Url> {
    let mut url = Url::parse(&format!(
        "https://apps.apple.com/{}/vision/search",
        country.to_ascii_lowercase()
    ))?;
    url.query_pairs_mut().append_pair("term", term);
    Ok(url)
}

pub fn product_url(app_id: i64, country: &str) -> Result<Url> {
    let mut url = Url::parse(&format!(
        "https://apps.apple.com/{}/app/id{app_id}",
        country.to_ascii_lowercase()
    ))?;
    url.query_pairs_mut().append_pair("platform", "vision");
    Ok(url)
}

fn serialized_server_data(body: &str) -> Result<&str> {
    let marker = [format!("id=\"{SCRIPT_ID}\""), format!("id='{SCRIPT_ID}'")]
        .into_iter()
        .filter_map(|needle| body.find(&needle))
        .min()
        .ok_or_else(|| anyhow!("serialized server data was not found"))?;
    let script_start = body[..marker]
        .rfind("<script")
        .ok_or_else(|| anyhow!("serialized server data script was not found"))?;
    let opening_end = body[marker..]
        .find('>')
        .map(|offset| marker + offset + 1)
        .ok_or_else(|| anyhow!("serialized server data script is malformed"))?;
    if script_start > marker || body[script_start..marker].contains('>') {
        bail!("serialized server data script is malformed");
    }
    let closing = body[opening_end..]
        .find("</script>")
        .map(|offset| opening_end + offset)
        .ok_or_else(|| anyhow!("serialized server data script is not closed"))?;
    Ok(body[opening_end..closing].trim())
}

fn vision_version_id(value: &Value, app_id: i64) -> Option<String> {
    match value {
        Value::Array(items) => {
            let mut matched = false;
            for item in items {
                if let Some(id) = vision_version_id(item, app_id) {
                    if !id.is_empty() {
                        return Some(id);
                    }
                    matched = true;
                }
            }
            matched.then(String::new)
        }
        Value::Object(map) => {
            let direct = map.get("purchaseConfiguration").and_then(|config| {
                if config.get("metricsPlatformDisplayStyle")?.as_str()? != "vision" {
                    return None;
                }
                let platforms = config.get("appPlatforms")?.as_array()?;
                if !platforms
                    .iter()
                    .any(|platform| platform.as_str() == Some("vision"))
                {
                    return None;
                }
                let buy_params = config.get("buyParams")?.as_str()?;
                let values: std::collections::HashMap<_, _> =
                    url::form_urlencoded::parse(buy_params.as_bytes())
                        .into_owned()
                        .collect();
                if values.get("salableAdamId")?.parse::<i64>().ok()? != app_id {
                    return None;
                }
                Some(values.get("appExtVrsId").cloned().unwrap_or_default())
            });
            if direct.as_ref().is_some_and(|id| !id.is_empty()) {
                return direct;
            }
            let mut matched = direct.is_some();
            for item in map.values() {
                if let Some(id) = vision_version_id(item, app_id) {
                    if !id.is_empty() {
                        return Some(id);
                    }
                    matched = true;
                }
            }
            matched.then(String::new)
        }
        _ => None,
    }
}

pub fn storefront_apps(body: &str, limit: i64) -> Result<Vec<App>> {
    let data = serialized_server_data(body)?;
    let page: Value =
        serde_json::from_str(data).context("failed to decode serialized server data")?;
    let max_count = limit.max(0).min(MAX_RESULTS as i64) as usize;
    let mut apps = Vec::with_capacity(max_count);
    let mut seen = HashSet::new();
    let Some(pages) = page.get("data").and_then(Value::as_array) else {
        return Ok(apps);
    };
    for page in pages {
        let Some(shelves) = page.pointer("/data/shelves").and_then(Value::as_array) else {
            continue;
        };
        for shelf in shelves {
            let Some(items) = shelf.get("items").and_then(Value::as_array) else {
                continue;
            };
            for item in items {
                if apps.len() == max_count {
                    return Ok(apps);
                }
                if item.get("$kind").and_then(Value::as_str) != Some("AppSearchResult") {
                    continue;
                }
                let Some(id) = item
                    .pointer("/lockup/adamId")
                    .and_then(Value::as_str)
                    .and_then(|id| id.parse::<i64>().ok())
                else {
                    continue;
                };
                if id == 0 || seen.contains(&id) || vision_version_id(item, id).is_none() {
                    continue;
                }
                seen.insert(id);
                apps.push(App {
                    id,
                    bundle_id: item
                        .pointer("/lockup/bundleId")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    name: item
                        .pointer("/lockup/title")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    platforms: None,
                    ..App::default()
                });
            }
        }
    }
    Ok(apps)
}

pub fn product_version_id(body: &str, app_id: i64) -> Result<String> {
    let data = serialized_server_data(body)?;
    let page: Value =
        serde_json::from_str(data).context("failed to decode serialized server data")?;
    match vision_version_id(&page, app_id) {
        Some(id) if !id.is_empty() => Ok(id),
        Some(_) => bail!("visionOS purchase configuration has no external version id"),
        None => bail!("visionOS purchase configuration was not found"),
    }
}

pub fn ensure_vision_platform(app: &mut App) {
    let platforms = app.platforms.get_or_insert_with(Vec::new);
    platforms.retain(|p| *p != Platform::Unknown);
    if !platforms.contains(&Platform::Visionos) {
        platforms.push(Platform::Visionos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        r#"<html><script id='serialized-server-data' type="application/json">{"data":[{"data":{"shelves":[{"items":[
          {"$kind":"EditorialItem","lockup":{"adamId":"9"},"purchaseConfiguration":{"metricsPlatformDisplayStyle":"vision","appPlatforms":["vision"],"buyParams":"salableAdamId=9&appExtVrsId=90"}},
          {"$kind":"AppSearchResult","lockup":{"adamId":"200","bundleId":"bundle.two","title":"Two"},"offer":{"purchaseConfiguration":{"metricsPlatformDisplayStyle":"vision","appPlatforms":["vision"],"buyParams":"salableAdamId=200&appExtVrsId=2000"}}},
          {"$kind":"AppSearchResult","lockup":{"adamId":"300"},"purchaseConfiguration":{"metricsPlatformDisplayStyle":"ios","appPlatforms":["iphone"],"buyParams":"salableAdamId=300&appExtVrsId=3000"}},
          {"$kind":"AppSearchResult","lockup":{"adamId":"200"},"purchaseConfiguration":{"metricsPlatformDisplayStyle":"vision","appPlatforms":["vision"],"buyParams":"salableAdamId=200&appExtVrsId=2000"}},
          {"$kind":"AppSearchResult","lockup":{"adamId":"100","title":"One"},"purchaseConfiguration":{"metricsPlatformDisplayStyle":"vision","appPlatforms":["vision"],"buyParams":"salableAdamId=100&appExtVrsId=1000"}}
        ]}]}}]}</script></html>"#.to_owned()
    }

    #[test]
    fn keeps_native_vision_apps_in_storefront_order() {
        let apps = storefront_apps(&fixture(), 2).unwrap();
        assert_eq!(
            apps.iter().map(|app| app.id).collect::<Vec<_>>(),
            vec![200, 100]
        );
        assert_eq!(apps[0].bundle_id, "bundle.two");
        assert!(storefront_apps(&fixture(), 0).unwrap().is_empty());
    }

    #[test]
    fn extracts_matching_version_id() {
        assert_eq!(product_version_id(&fixture(), 200).unwrap(), "2000");
        assert!(product_version_id(&fixture(), 300).is_err());
        assert!(storefront_apps("<html></html>", 5).is_err());
    }

    #[test]
    fn distinguishes_missing_version_from_missing_configuration() {
        let body = r#"<script id="serialized-server-data">{"purchaseConfiguration":{"metricsPlatformDisplayStyle":"vision","appPlatforms":["vision"],"buyParams":"salableAdamId=100"}}</script>"#;
        assert_eq!(
            product_version_id(body, 100).unwrap_err().to_string(),
            "visionOS purchase configuration has no external version id"
        );
        assert_eq!(
            product_version_id(body, 101).unwrap_err().to_string(),
            "visionOS purchase configuration was not found"
        );
    }
}
