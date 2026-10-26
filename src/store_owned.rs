//! Purchase-history record parsing and result selection.

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use time::{
    OffsetDateTime,
    format_description::well_known::{Rfc2822, Rfc3339},
};

use crate::{
    auth::SapConfig,
    catalog::App,
    credentials::Account,
    dmap,
    platform::Platform,
    sap_signer::Signer,
    store_backend::{StoreBackend, StoreBackendRequest},
    store_purchase::PasswordTokenExpired,
    transport::Response,
};

pub const DEFAULT_LIMIT: usize = 10;
pub const MAX_LIMIT: usize = 100;
const APP_MEDIA_KIND: u64 = 131_072;
const ARCADE_MEDIA_KIND: u64 = 262_144;
const MAC_MEDIA_KIND: u64 = 67_108_864;
const PURCHASE_DAAP_BASE: &str =
    "https://pd.itunes.apple.com/WebObjects/MZPurchaseDaap.woa/purchase";
const PURCHASE_QUERY: &str = "('com.apple.itunes.extended\\-media\\-kind:131072','com.apple.itunes.extended\\-media\\-kind:262144','com.apple.itunes.extended\\-media\\-kind:67108864')";

type ActionSigner<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>> + 'a;

pub trait OwnedBackend {
    fn hardware_id(&self) -> [u8; 6];
    fn sap_config(&self) -> Result<SapConfig>;
    fn send_history(
        &self,
        request: StoreBackendRequest<'_>,
        signer: Option<&mut ActionSigner<'_>>,
    ) -> Result<Response>;
}

impl OwnedBackend for StoreBackend {
    fn hardware_id(&self) -> [u8; 6] {
        self.hardware_id()
    }

    fn sap_config(&self) -> Result<SapConfig> {
        self.sap_config()
    }

    fn send_history(
        &self,
        request: StoreBackendRequest<'_>,
        signer: Option<&mut ActionSigner<'_>>,
    ) -> Result<Response> {
        match signer {
            Some(signer) => self.execute_standard_signed(request, signer),
            None => self.execute_standard(request),
        }
    }
}

pub fn owned_apps(
    backend: &StoreBackend,
    account: &Account,
    page: usize,
    limit: usize,
    platform: Option<Platform>,
) -> Result<OwnedAppsOutput> {
    validate_selection(page, limit, platform)?;
    let config = backend
        .sap_config()
        .context("load purchase-history SAP configuration")?;
    let mut signer = Signer::open(&config, &backend.hardware_id())
        .context("initialize purchase-history SAP signer")?;
    let result = owned_apps_with_signer(backend, account, page, limit, platform, &mut |body| {
        signer.sign(body)
    });
    let close = signer.close().context("close purchase-history SAP signer");
    match (result, close) {
        (Ok(apps), Ok(())) => Ok(apps),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(first.context(second)),
    }
}

pub fn owned_apps_with_signer<B: OwnedBackend>(
    backend: &B,
    account: &Account,
    page: usize,
    limit: usize,
    platform: Option<Platform>,
    signer: &mut ActionSigner<'_>,
) -> Result<OwnedAppsOutput> {
    validate_selection(page, limit, platform)?;
    let guid = backend
        .hardware_id()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let base_storefront = account.store_front.split(',').next().unwrap_or_default();
    if base_storefront.is_empty() {
        bail!("saved account has no Store storefront");
    }
    let mut apps = Vec::new();
    for store in ["34", "13"] {
        let storefront = format!("{base_storefront},{store}");
        let results = fetch_storefront(backend, account, &storefront, &guid, signer)
            .with_context(|| format!("fetch purchase history for storefront {store}"))?;
        apps.extend(results);
    }
    select_page(merge_owned_apps(apps), page, limit, platform)
}

fn fetch_storefront<B: OwnedBackend>(
    backend: &B,
    account: &Account,
    storefront: &str,
    guid: &str,
    signer: &mut ActionSigner<'_>,
) -> Result<Vec<App>> {
    let now = OffsetDateTime::now_utc();
    let headers = history_headers(account, storefront, guid, now)?;
    let login_url = format!("{PURCHASE_DAAP_BASE}/login");
    let login = backend
        .send_history(history_request(&login_url, &headers, None), None)
        .context("open purchase history session")?;
    check_history_response("purchase history login", &login)?;
    let session = dmap::first_uint(&login.body, b"mlid")?
        .context("purchase history login response has no session ID")?;
    let session = u32::try_from(session).context("purchase history session ID exceeds uint32")?;

    let update_body = format!("session-id={session}&revision-number=(null)&query={PURCHASE_QUERY}");
    let mut update_headers = history_headers(account, storefront, guid, OffsetDateTime::now_utc())?;
    update_headers.insert(
        "Content-Type",
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let update_url = format!("{PURCHASE_DAAP_BASE}/update");
    let update = backend
        .send_history(
            history_request(&update_url, &update_headers, Some(update_body.as_bytes())),
            Some(signer),
        )
        .context("update purchase history")?;
    check_history_response("purchase history update", &update)?;
    let revision = dmap::first_uint(&update.body, b"musr")?
        .context("purchase history update response has no revision")?;
    let revision = u32::try_from(revision).context("purchase history revision exceeds uint32")?;

    let now = OffsetDateTime::now_utc();
    let items_body = items_body(session, revision, now)?;
    let mut items_headers = history_headers(account, storefront, guid, now)?;
    items_headers.insert(
        "Content-Type",
        HeaderValue::from_static("application/x-dmap-tagged"),
    );
    let items_url = format!("{PURCHASE_DAAP_BASE}/databases/{revision}/items");
    let items = backend
        .send_history(
            history_request(&items_url, &items_headers, Some(&items_body)),
            Some(signer),
        )
        .context("retrieve purchase history items")?;
    check_history_response("purchase history items", &items)?;
    parse_owned_apps(&items.body).context("parse purchase history items")
}

fn history_request<'a>(
    url: &'a str,
    headers: &'a HeaderMap,
    body: Option<&'a [u8]>,
) -> StoreBackendRequest<'a> {
    StoreBackendRequest {
        method: "POST",
        url,
        headers,
        parameters: None,
        body,
        raw: true,
        response_format: "raw",
        no_redirects: false,
        timeout: None,
    }
}

fn history_headers(
    account: &Account,
    storefront: &str,
    guid: &str,
    now: OffsetDateTime,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let date = now.format(&Rfc2822)?.replace("+0000", "GMT");
    let (timezone, offset_minutes) = local_timezone(now);
    for (name, value) in [
        ("Accept", "*/*".to_owned()),
        ("Accept-Language", "en-us".to_owned()),
        ("Client-Cloud-DAAP-Request-Reason", "5".to_owned()),
        (
            "Client-Cloud-Purchase-Daap-Version",
            "1.1/Configurator-2.0".to_owned(),
        ),
        ("Client-DAAP-Version", "3.12".to_owned()),
        ("Date", date),
        ("iCloud-DSID", account.directory_services_id.clone()),
        (
            "X-Apple-I-Client-Time",
            now.replace_nanosecond(0)?.format(&Rfc3339)?,
        ),
        ("X-Apple-I-Locale", "en_US".to_owned()),
        ("X-Apple-I-TimeZone", timezone),
        ("X-Apple-Store-Front", storefront.to_owned()),
        ("X-Apple-TZ", offset_minutes.to_string()),
        ("X-Dsid", account.directory_services_id.clone()),
        ("X-Guid", guid.to_owned()),
        ("X-Token", account.password_token.clone()),
    ] {
        headers.insert(
            name,
            HeaderValue::from_str(&value).context("invalid history request header")?,
        );
    }
    Ok(headers)
}

fn local_timezone(now: OffsetDateTime) -> (String, i64) {
    #[cfg(unix)]
    {
        let timestamp: libc::time_t = now.unix_timestamp();
        // SAFETY: localtime_r writes to the initialized output and does not retain pointers.
        let mut local: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: timestamp and local are valid pointers for this call.
        if !unsafe { libc::localtime_r(&timestamp, &mut local) }.is_null() {
            let timezone = std::env::var("TZ").unwrap_or_else(|_| "Local".into());
            return (timezone, local.tm_gmtoff / 60);
        }
    }
    ("UTC".into(), 0)
}

fn items_body(session: u32, revision: u32, now: OffsetDateTime) -> Result<Vec<u8>> {
    let timestamp =
        u32::try_from(now.unix_timestamp()).context("purchase history timestamp exceeds uint32")?;
    let mut payload = Vec::with_capacity(73 + PURCHASE_QUERY.len());
    payload.extend(dmap::uint32(b"mstc", timestamp)?);
    payload.extend(dmap::uint32(b"mlid", session)?);
    payload.extend(dmap::uint8(b"mikd", 2)?);
    payload.extend(dmap::uint32(b"musr", revision)?);
    payload.extend(dmap::uint32(b"mder", 0)?);
    payload.extend(dmap::string(b"mque", PURCHASE_QUERY)?);
    payload.extend(dmap::tag(b"aetl", &[])?);
    dmap::tag(b"adsr", &payload)
}

fn check_history_response(label: &str, response: &Response) -> Result<()> {
    if matches!(response.status, 401 | 403) {
        return Err(PasswordTokenExpired.into());
    }
    if response.status != 200 {
        bail!("{label} request returned HTTP {}", response.status);
    }
    if let Some(status) = dmap::first_uint(&response.body, b"mstt")? {
        if matches!(status, 401 | 403) {
            return Err(PasswordTokenExpired.into());
        }
        if status != 200 {
            bail!("{label} response returned DAAP status {status}");
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedAppsOutput {
    pub count: usize,
    pub total_count: usize,
    pub page: usize,
    pub apps: Vec<App>,
}

pub fn parse_owned_apps(data: &[u8]) -> Result<Vec<App>> {
    let mut apps = Vec::new();
    dmap::walk(data, |name, payload| {
        if name == b"mlit" {
            let app = parse_owned_app(payload)?;
            if app.id != 0 {
                apps.push(app);
            }
        }
        Ok(())
    })?;
    Ok(merge_owned_apps(apps))
}

fn parse_owned_app(data: &[u8]) -> Result<App> {
    let mut app = App::default();
    let mut media_kind = 0;
    let mut supported_products = 0;
    dmap::walk(data, |name, payload| {
        match name {
            b"aeMk" => media_kind = parse_uint(payload, "aeMk")?,
            b"aeSS" => supported_products = parse_uint(payload, "aeSS")?,
            b"aeSI" => {
                let id = parse_uint(payload, "aeSI")?;
                app.id = i64::try_from(id).context("owned app ID exceeds int64")?;
                if !matches!(payload.len(), 4 | 8) {
                    bail!("owned app ID has invalid integer length");
                }
            }
            b"aeBI" => app.bundle_id = String::from_utf8_lossy(payload).into_owned(),
            b"aeLN" => app.name = String::from_utf8_lossy(payload).into_owned(),
            b"minm" if app.name.is_empty() => {
                app.name = String::from_utf8_lossy(payload).into_owned()
            }
            b"aePd" => app.version = String::from_utf8_lossy(payload).into_owned(),
            b"asdp" => {
                if payload.len() != 4 {
                    bail!(
                        "owned app purchase date has invalid length {}",
                        payload.len()
                    );
                }
                let seconds = u32::from_be_bytes(payload.try_into()?) as i64;
                app.purchase_date = Some(
                    OffsetDateTime::from_unix_timestamp(seconds)?
                        .format(&Rfc3339)
                        .context("format purchase date")?,
                );
            }
            _ => {}
        }
        Ok(())
    })?;
    let platforms = match media_kind {
        MAC_MEDIA_KIND => vec![Platform::Macos],
        APP_MEDIA_KIND | ARCADE_MEDIA_KIND => {
            let mut found = Vec::new();
            for (bit, platform) in [
                (1, Platform::Iphone),
                (2, Platform::Ipad),
                (16, Platform::Visionos),
                (8, Platform::Macos),
            ] {
                if supported_products & bit != 0 {
                    found.push(platform);
                }
            }
            found
        }
        _ => Vec::new(),
    };
    app.platforms = Some(if platforms.is_empty() {
        vec![Platform::Unknown]
    } else {
        platforms
    });
    Ok(app)
}

fn parse_uint(payload: &[u8], tag: &str) -> Result<u64> {
    Ok(match payload.len() {
        1 => u64::from(payload[0]),
        2 => u16::from_be_bytes(payload.try_into()?) as u64,
        4 => u32::from_be_bytes(payload.try_into()?) as u64,
        8 => u64::from_be_bytes(payload.try_into()?),
        _ => bail!(
            "owned app {tag} has invalid integer length {}",
            payload.len()
        ),
    })
}

pub fn merge_owned_apps(apps: impl IntoIterator<Item = App>) -> Vec<App> {
    let mut merged: Vec<App> = Vec::new();
    let mut seen: std::collections::HashMap<i64, usize> = std::collections::HashMap::new();
    for app in apps {
        if let Some(&index) = seen.get(&app.id) {
            let prior = &mut merged[index];
            for platform in app.platforms.unwrap_or_default() {
                let platforms = prior.platforms.get_or_insert_with(Vec::new);
                if !platforms.contains(&platform) {
                    platforms.push(platform);
                }
            }
            if app.purchase_date > prior.purchase_date {
                prior.purchase_date = app.purchase_date;
            }
        } else {
            seen.insert(app.id, merged.len());
            merged.push(app);
        }
    }
    for app in &mut merged {
        if let Some(platforms) = app.platforms.as_mut()
            && platforms.len() > 1
        {
            platforms.retain(|platform| *platform != Platform::Unknown);
        }
    }
    merged
}

pub fn select_page(
    mut apps: Vec<App>,
    page: usize,
    limit: usize,
    platform: Option<Platform>,
) -> Result<OwnedAppsOutput> {
    validate_selection(page, limit, platform)?;
    if let Some(platform) = platform {
        apps.retain(|app| {
            app.platforms
                .as_ref()
                .is_some_and(|platforms| platforms.contains(&platform))
        });
    }
    apps.sort_by(|left, right| right.purchase_date.cmp(&left.purchase_date));
    let total_count = apps.len();
    let start = page.saturating_sub(1).saturating_mul(limit);
    let apps = if start >= total_count {
        Vec::new()
    } else {
        apps.into_iter().skip(start).take(limit).collect()
    };
    Ok(OwnedAppsOutput {
        count: apps.len(),
        total_count,
        page,
        apps,
    })
}

fn validate_selection(page: usize, limit: usize, platform: Option<Platform>) -> Result<()> {
    if page == 0 {
        bail!("page must be greater than 0");
    }
    if limit == 0 || limit > MAX_LIMIT {
        bail!("limit must be between 1 and {MAX_LIMIT}");
    }
    if matches!(platform, Some(Platform::Unknown | Platform::Watchos)) {
        bail!("invalid platform for purchase history");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sap_assets::SapAssetBundle;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    fn item(id: u32, media: u32, products: u8, timestamp: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(dmap::uint32(b"aeSI", id).unwrap());
        body.extend(dmap::uint32(b"aeMk", media).unwrap());
        body.extend(dmap::uint8(b"aeSS", products).unwrap());
        body.extend(dmap::uint32(b"asdp", timestamp).unwrap());
        dmap::tag(b"mlit", &body).unwrap()
    }

    #[test]
    fn merges_storefront_platforms_and_keeps_latest_purchase() {
        let mut body = Vec::new();
        body.extend(item(42, APP_MEDIA_KIND as u32, 1, 100));
        body.extend(item(42, MAC_MEDIA_KIND as u32, 0, 200));
        body.extend(item(43, APP_MEDIA_KIND as u32, 2, 150));
        let apps = parse_owned_apps(&dmap::tag(b"mlcl", &body).unwrap()).unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(
            apps[0].platforms.as_ref().unwrap(),
            &[Platform::Iphone, Platform::Macos]
        );
        assert!(apps[0].purchase_date > apps[1].purchase_date);
        let selected = select_page(apps, 1, 1, Some(Platform::Macos)).unwrap();
        assert_eq!(
            (selected.count, selected.total_count, selected.apps[0].id),
            (1, 1, 42)
        );
    }

    #[test]
    fn rejects_bad_lengths_and_out_of_range_pages() {
        let bad_item = dmap::tag(b"mlit", &dmap::tag(b"aeSI", &[1, 2, 3]).unwrap()).unwrap();
        assert!(parse_owned_apps(&bad_item).is_err());
        let page = select_page(vec![], usize::MAX, 10, None).unwrap();
        assert_eq!(page.count, 0);
    }

    struct FixtureBackend {
        calls: Mutex<usize>,
    }

    impl OwnedBackend for FixtureBackend {
        fn hardware_id(&self) -> [u8; 6] {
            [0, 1, 2, 3, 4, 5]
        }

        fn sap_config(&self) -> Result<SapConfig> {
            unreachable!("test supplies signer")
        }

        fn send_history(
            &self,
            request: StoreBackendRequest<'_>,
            signer: Option<&mut ActionSigner<'_>>,
        ) -> Result<Response> {
            let mut calls = self.calls.lock().unwrap();
            let call = *calls;
            *calls += 1;
            assert_eq!(request.method, "POST");
            assert!(request.raw);
            assert_eq!(request.headers["X-Guid"], "000102030405");
            assert_eq!(
                request.headers["X-Apple-Store-Front"],
                if call < 3 {
                    "143441-1,34"
                } else {
                    "143441-1,13"
                }
            );
            let body = match call % 3 {
                0 => {
                    assert!(request.url.ends_with("/login"));
                    assert!(signer.is_none());
                    dmap::tag(b"mlog", &dmap::uint32(b"mlid", 7)?)?
                }
                1 => {
                    assert!(request.url.ends_with("/update"));
                    assert!(
                        request
                            .body
                            .unwrap()
                            .starts_with(b"session-id=7&revision-number=(null)&query=")
                    );
                    assert_eq!(signer.unwrap()(request.body.unwrap())?, b"signed");
                    dmap::tag(b"mupd", &dmap::uint32(b"musr", 99)?)?
                }
                _ => {
                    assert!(request.url.ends_with("/databases/99/items"));
                    assert_eq!(dmap::first_uint(request.body.unwrap(), b"mlid")?, Some(7));
                    assert_eq!(signer.unwrap()(request.body.unwrap())?, b"signed");
                    let media = if call == 2 {
                        APP_MEDIA_KIND
                    } else {
                        MAC_MEDIA_KIND
                    };
                    let products = if call == 2 { 1 } else { 0 };
                    dmap::tag(b"mlcl", &item(42, media as u32, products, 100))?
                }
            };
            Ok(Response {
                status: 200,
                headers: std::collections::HashMap::new(),
                body,
            })
        }
    }

    #[test]
    fn fetches_both_storefronts_with_signed_update_and_items() {
        let backend = FixtureBackend {
            calls: Mutex::new(0),
        };
        let signatures = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&signatures);
        let mut account = Account::default();
        account.store_front = "143441-1,29".into();
        account.directory_services_id = "123".into();
        account.password_token = "token".into();
        let output = owned_apps_with_signer(&backend, &account, 1, 10, None, &mut |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(b"signed".to_vec())
        })
        .unwrap();
        assert_eq!(
            (output.count, output.total_count, output.apps[0].id),
            (1, 1, 42)
        );
        assert_eq!(
            output.apps[0].platforms.as_ref().unwrap(),
            &[Platform::Iphone, Platform::Macos]
        );
        assert_eq!(*backend.calls.lock().unwrap(), 6);
        assert_eq!(signatures.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn fetches_purchase_history_through_pinned_store_backend() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let backend = StoreBackend::with_sender(
            assets.apple_media_services,
            [0, 1, 2, 3, 4, 5],
            move |request| {
                let call = seen.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.method, reqwest::Method::POST);
                assert_eq!(
                    request.headers["x-apple-store-front"],
                    if call < 3 {
                        "143441-1,34"
                    } else {
                        "143441-1,13"
                    }
                );
                if !call.is_multiple_of(3) {
                    assert_eq!(request.headers["x-apple-actionsignature"], "AQID");
                }
                let body = match call % 3 {
                    0 => dmap::tag(b"mlog", &dmap::uint32(b"mlid", 7)?)?,
                    1 => dmap::tag(b"mupd", &dmap::uint32(b"musr", 99)?)?,
                    _ => dmap::tag(b"mlcl", &item(42, APP_MEDIA_KIND as u32, 1, 100))?,
                };
                Ok(Response {
                    status: 200,
                    headers: std::collections::HashMap::new(),
                    body,
                })
            },
        );
        let mut account = Account::default();
        account.store_front = "143441-1,29".into();
        account.directory_services_id = "123".into();
        account.password_token = "token".into();
        let output =
            owned_apps_with_signer(&backend, &account, 1, 10, None, &mut |_| Ok(vec![1, 2, 3]))
                .unwrap();
        assert_eq!(output.total_count, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 6);
    }
}
