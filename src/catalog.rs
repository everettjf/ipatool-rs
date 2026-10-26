use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    platform::Platform,
    transport::{Request, Response, Transport},
    vision,
};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct App {
    pub id: i64,
    #[serde(rename = "bundleID")]
    pub bundle_id: String,
    pub name: String,
    pub version: String,
    pub price: f64,
    #[serde(rename = "purchaseDate", skip_serializing_if = "Option::is_none")]
    pub purchase_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<Platform>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SearchOutput {
    pub count: usize,
    pub apps: Vec<App>,
}

#[derive(Debug, Deserialize)]
struct CatalogResponse {
    #[serde(rename = "resultCount", default)]
    count: usize,
    #[serde(default)]
    results: Vec<CatalogApp>,
}

#[derive(Debug, Deserialize)]
struct CatalogApp {
    #[serde(rename = "trackId", default)]
    id: i64,
    #[serde(rename = "bundleId", default)]
    bundle_id: String,
    #[serde(rename = "trackName", default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    price: f64,
    #[serde(rename = "kind", default)]
    kind: String,
    #[serde(rename = "supportedDevices", default)]
    supported_devices: Vec<String>,
    #[serde(default)]
    platforms: Vec<Platform>,
    #[serde(rename = "purchaseDate", default)]
    purchase_date: Option<String>,
}

impl From<CatalogApp> for App {
    fn from(raw: CatalogApp) -> Self {
        let mut platforms = raw.platforms;
        let families = [
            ("iPhone", Platform::Iphone),
            ("iPod", Platform::Iphone),
            ("iPad", Platform::Ipad),
            ("AppleTV", Platform::Appletv),
            ("Watch", Platform::Watchos),
            ("RealityDevice", Platform::Visionos),
            ("Mac", Platform::Macos),
        ];
        for (prefix, platform) in families {
            if raw
                .supported_devices
                .iter()
                .any(|device| device.starts_with(prefix))
                && !platforms.contains(&platform)
            {
                platforms.push(platform);
            }
        }
        if raw.kind == "mac-software" && !platforms.contains(&Platform::Macos) {
            platforms.push(Platform::Macos);
        }
        if platforms.is_empty() {
            platforms.push(Platform::Unknown);
        }
        Self {
            id: raw.id,
            bundle_id: raw.bundle_id,
            name: raw.name,
            version: raw.version,
            price: raw.price,
            purchase_date: raw.purchase_date,
            platforms: Some(platforms),
        }
    }
}

pub struct CatalogClient {
    http: Transport,
}

impl CatalogClient {
    pub fn new() -> Result<Self> {
        let http = Transport::new()?;
        Ok(Self { http })
    }

    pub(crate) fn get(&self, url: Url) -> Result<Response> {
        let mut request = Request::get(url);
        request.timeout = Some(std::time::Duration::from_secs(30));
        let response = self.http.send(request)?;
        response.ensure_success()?;
        Ok(response)
    }

    pub fn search(
        &self,
        term: &str,
        country: &str,
        limit: i64,
        platform: Option<Platform>,
    ) -> Result<SearchOutput> {
        validate_country(country)?;
        if platform == Some(Platform::Visionos) {
            return self.search_vision(term, country, limit);
        }
        let url = search_url(term, country, limit, platform)?;
        let response: CatalogResponse = self
            .get(url)?
            .json()
            .context("failed to decode App Store search results")?;
        Ok(search_output(response, platform))
    }

    fn search_vision(&self, term: &str, country: &str, limit: i64) -> Result<SearchOutput> {
        let url = vision::search_url(term, country)?;
        let body = self.get(url)?.body;
        let body = String::from_utf8(body).context("visionOS search page is not UTF-8")?;
        let mut apps = vision::storefront_apps(&body, limit)?;
        if apps.is_empty() {
            return Ok(SearchOutput { count: 0, apps });
        }

        let ids: Vec<i64> = apps.iter().map(|app| app.id).collect();
        let url = lookup_url(Some(&ids), None, country, Some(Platform::Visionos))?;
        let response: CatalogResponse = self.get(url)?.json()?;
        let hydrated: std::collections::HashMap<i64, App> = response
            .results
            .into_iter()
            .map(App::from)
            .map(|app| (app.id, app))
            .collect();

        for app in &mut apps {
            if let Some(metadata) = hydrated.get(&app.id) {
                *app = metadata.clone();
            }
            vision::ensure_vision_platform(app);
        }
        Ok(SearchOutput {
            count: apps.len(),
            apps,
        })
    }

    pub fn lookup(
        &self,
        id: Option<i64>,
        bundle_id: Option<&str>,
        country: &str,
        platform: Option<Platform>,
    ) -> Result<App> {
        validate_country(country)?;
        let ids = id.map(|value| vec![value]);
        let url = lookup_url(ids.as_deref(), bundle_id, country, platform)?;
        let response: CatalogResponse = self.get(url)?.json()?;
        let app = response
            .results
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("app not found"))?;
        let app = App::from(app);
        if platform == Some(Platform::Watchos)
            && !app
                .platforms
                .as_ref()
                .is_some_and(|p| p.contains(&Platform::Watchos))
        {
            bail!("app not found");
        }
        Ok(app)
    }
}

fn search_output(response: CatalogResponse, platform: Option<Platform>) -> SearchOutput {
    let mut apps: Vec<App> = response.results.into_iter().map(App::from).collect();
    let count = if platform == Some(Platform::Watchos) {
        apps.retain(|app| {
            app.platforms
                .as_ref()
                .is_some_and(|p| p.contains(&Platform::Watchos))
        });
        apps.len()
    } else {
        response.count
    };
    SearchOutput { count, apps }
}

pub(crate) fn validate_country(country: &str) -> Result<()> {
    if country.len() != 2 || !country.bytes().all(|c| c.is_ascii_alphabetic()) {
        bail!("country must be a two-letter country code");
    }
    Ok(())
}

pub fn search_url(
    term: &str,
    country: &str,
    limit: i64,
    platform: Option<Platform>,
) -> Result<Url> {
    validate_country(country)?;
    let mut url = Url::parse("https://itunes.apple.com/search")?;
    url.query_pairs_mut()
        .append_pair("entity", Platform::search_entity_for(platform))
        .append_pair("limit", &limit.to_string())
        .append_pair("media", "software")
        .append_pair("term", term)
        .append_pair("country", country);
    Ok(url)
}

pub fn lookup_url(
    ids: Option<&[i64]>,
    bundle_id: Option<&str>,
    country: &str,
    platform: Option<Platform>,
) -> Result<Url> {
    validate_country(country)?;
    let mut url = Url::parse("https://itunes.apple.com/lookup")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("entity", Platform::lookup_entity_for(platform));
        if let Some(bundle_id) = bundle_id.filter(|value| !value.is_empty()) {
            query
                .append_pair("limit", "1")
                .append_pair("media", "software")
                .append_pair("bundleId", bundle_id);
        } else if let Some(ids) = ids.filter(|values| !values.is_empty()) {
            query.append_pair(
                "id",
                &ids.iter().map(i64::to_string).collect::<Vec<_>>().join(","),
            );
        } else {
            bail!("an app ID or bundle identifier is required");
        }
        query.append_pair("country", country);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_url_preserves_platform_and_encodes_term() {
        let url = search_url("spatial notes", "US", 5, Some(Platform::Appletv)).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["entity"], "software,tvSoftware");
        assert_eq!(query["term"], "spatial notes");
        assert_eq!(query["country"], "US");
    }

    #[test]
    fn derives_platforms_without_duplicates() {
        let raw: CatalogResponse = serde_json::from_str(r#"{"resultCount":1,"results":[{"trackId":42,"supportedDevices":["iPadAir","iPhone5s","iPhone6","iPodTouch"]}]}"#).unwrap();
        let output = search_output(raw, None);
        assert_eq!(
            output.apps[0].platforms,
            Some(vec![Platform::Iphone, Platform::Ipad])
        );
    }

    #[test]
    fn watch_search_filters_iphone_only_results() {
        let raw: CatalogResponse = serde_json::from_str(r#"{"resultCount":2,"results":[{"trackId":1,"supportedDevices":["iPhone6"]},{"trackId":2,"supportedDevices":["iPhone6","Watch4"]}]}"#).unwrap();
        let output = search_output(raw, Some(Platform::Watchos));
        assert_eq!(output.count, 1);
        assert_eq!(output.apps[0].id, 2);
    }

    #[test]
    fn keeps_catalog_platforms_and_purchase_date() {
        let raw: CatalogResponse = serde_json::from_str(r#"{"resultCount":1,"results":[{"trackId":7,"platforms":["visionos"],"supportedDevices":["RealityDevice","iPadAir"],"purchaseDate":"2026-01-01T00:00:00Z"}]}"#).unwrap();
        let output = search_output(raw, None);
        assert_eq!(
            output.apps[0].platforms,
            Some(vec![Platform::Visionos, Platform::Ipad])
        );
        assert_eq!(
            output.apps[0].purchase_date.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn lookup_selects_expected_query_shape() {
        let url = lookup_url(None, Some("com.example.test"), "GB", None).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["bundleId"], "com.example.test");
        assert_eq!(query["limit"], "1");
        assert!(!query.contains_key("id"));
        assert!(lookup_url(None, None, "US", None).is_err());
    }
}
