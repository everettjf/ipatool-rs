//! Purchase-history record parsing and result selection.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Method,
    header::{HeaderMap, HeaderValue, USER_AGENT},
};
use serde::Serialize;
use time::{
    OffsetDateTime,
    format_description::well_known::{Rfc2822, Rfc3339},
};

use crate::{
    auth::{SapConfig, sap_config_from_bag_response},
    catalog::App,
    credentials::Account,
    dmap,
    host::hardware_mac_address,
    platform::Platform,
    sap_signer::Signer,
    state::prepare_state_directory_from_environment,
    store_backend::{DEFAULT_USER_AGENT, StoreBackend, StoreBackendRequest},
    store_purchase::PasswordTokenExpired,
    transport::{DEFAULT_AUTHENTICATION_TIMEOUT, Request, Response, Transport},
};

pub const DEFAULT_LIMIT: usize = 10;
pub const MAX_LIMIT: usize = 100;
const APP_MEDIA_KIND: u64 = 131_072;
const ARCADE_MEDIA_KIND: u64 = 262_144;
const MAC_MEDIA_KIND: u64 = 67_108_864;
const PURCHASE_DAAP_BASE: &str =
    "https://pd.itunes.apple.com/WebObjects/MZPurchaseDaap.woa/purchase";
const PURCHASE_DAAP_PATH: &str = "/WebObjects/MZPurchaseDaap.woa/purchase";
const PURCHASE_QUERY: &str = "('com.apple.itunes.extended\\-media\\-kind:131072','com.apple.itunes.extended\\-media\\-kind:262144','com.apple.itunes.extended\\-media\\-kind:67108864')";

type ActionSigner<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>> + 'a;
type HistorySender = dyn Fn(Request) -> Result<Response> + Send + Sync;

/// Direct HTTP backend for purchase history; SAP signing remains separate.
pub struct NativeOwnedBackend {
    hardware_id: [u8; 6],
    sender: Arc<HistorySender>,
}

impl NativeOwnedBackend {
    pub fn open() -> Result<Self> {
        let hardware_id = hardware_mac_address().context("read Store hardware identity")?;
        let state_directory = prepare_state_directory_from_environment()?;
        let transport = Arc::new(Transport::with_cookies(&state_directory)?);
        Ok(Self::with_sender(hardware_id, move |request| {
            transport.send_store(request)
        }))
    }

    pub fn with_sender(
        hardware_id: [u8; 6],
        sender: impl Fn(Request) -> Result<Response> + Send + Sync + 'static,
    ) -> Self {
        Self {
            hardware_id,
            sender: Arc::new(sender),
        }
    }
}

impl OwnedBackend for NativeOwnedBackend {
    fn hardware_id(&self) -> [u8; 6] {
        self.hardware_id
    }

    fn sap_config(&self) -> Result<SapConfig> {
        let guid = self
            .hardware_id
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        let url = url::Url::parse(&format!(
            "https://init.itunes.apple.com/bag.xml?guid={guid}"
        ))?;
        let mut request = Request::get(url);
        request
            .headers
            .insert("Accept", HeaderValue::from_static("application/xml"));
        request
            .headers
            .insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        request.no_redirects = true;
        request.timeout = Some(DEFAULT_AUTHENTICATION_TIMEOUT);
        let response = (self.sender)(request).context("request Apple URL bag")?;
        response.ensure_success()?;
        sap_config_from_bag_response(&response)
    }

    fn send_history(
        &self,
        request: StoreBackendRequest<'_>,
        signer: Option<&mut ActionSigner<'_>>,
    ) -> Result<Response> {
        if request.method != "POST" || request.parameters.is_some() || !request.raw {
            bail!("invalid native purchase-history request");
        }
        let url = url::Url::parse(request.url).context("invalid purchase-history URL")?;
        if url.scheme() != "https"
            || url.host_str() != Some("pd.itunes.apple.com")
            || !valid_history_path(url.path())
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("unsupported native purchase-history URL");
        }
        let mut headers = request.headers.clone();
        headers.insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        if let Some(signer) = signer {
            let body = request
                .body
                .context("signed purchase-history request has no body")?;
            let signature = signer(body).context("sign purchase-history request")?;
            if signature.is_empty() {
                bail!("purchase-history signer returned an empty signature");
            }
            headers.insert(
                "X-Apple-ActionSignature",
                HeaderValue::from_str(&STANDARD.encode(signature))?,
            );
        }
        (self.sender)(Request {
            method: Method::POST,
            url,
            headers,
            body: request.body.map(ToOwned::to_owned),
            no_redirects: request.no_redirects,
            timeout: request.timeout,
        })
    }
}

fn valid_history_path(path: &str) -> bool {
    if path == format!("{PURCHASE_DAAP_PATH}/login")
        || path == format!("{PURCHASE_DAAP_PATH}/update")
    {
        return true;
    }
    let Some(remainder) = path.strip_prefix(&format!("{PURCHASE_DAAP_PATH}/databases/")) else {
        return false;
    };
    let Some(id) = remainder.strip_suffix("/items") else {
        return false;
    };
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
}

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

pub fn owned_apps<B: OwnedBackend>(
    backend: &B,
    account: &Account,
    page: usize,
    limit: usize,
    platform: Option<Platform>,
) -> Result<OwnedAppsOutput> {
    let (page, limit) = normalize_selection(page, limit, platform)?;
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
    let (page, limit) = normalize_selection(page, limit, platform)?;
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
    let timezone = timezone_label();
    if timezone == "UTC" {
        return (timezone, 0);
    }
    #[cfg(unix)]
    {
        let timestamp: libc::time_t = now.unix_timestamp();
        // SAFETY: localtime_r writes to the initialized output and does not retain pointers.
        let mut local: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: timestamp and local are valid pointers for this call.
        if !unsafe { libc::localtime_r(&timestamp, &mut local) }.is_null() {
            return (timezone, local.tm_gmtoff / 60);
        }
    }
    #[cfg(windows)]
    if let Ok(offset) = time::UtcOffset::local_offset_at(now) {
        return (timezone, i64::from(offset.whole_seconds()) / 60);
    }
    ("UTC".into(), 0)
}

fn timezone_label() -> String {
    let value = std::env::var("TZ").ok();
    resolve_timezone_label(value.as_deref())
}

fn resolve_timezone_label(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "Local".into();
    };
    let value = value.strip_prefix(':').unwrap_or(value);
    if value.is_empty() || value == "UTC" {
        return "UTC".into();
    }
    #[cfg(unix)]
    {
        use std::path::Path;

        let path = if value.starts_with('/') {
            Path::new(value).to_path_buf()
        } else {
            if value.contains("..") {
                return "UTC".into();
            }
            Path::new("/usr/share/zoneinfo").join(value)
        };
        if !valid_tzfile(&path) {
            return "UTC".into();
        }
        if value == "/etc/localtime" {
            return "Local".into();
        }
    }
    value.into()
}

#[cfg(unix)]
fn valid_tzfile(path: &std::path::Path) -> bool {
    use std::io::Read;

    // Go's zoneinfo loader rejects files larger than 10 MiB.
    const MAX_TZFILE_SIZE: u64 = 10 * 1024 * 1024;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if file
        .metadata()
        .is_ok_and(|info| info.len() > MAX_TZFILE_SIZE)
    {
        return false;
    }
    let mut bytes = Vec::new();
    if file
        .by_ref()
        .take(MAX_TZFILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_TZFILE_SIZE
    {
        return false;
    }
    valid_tzif_bytes(&bytes)
}

#[cfg(unix)]
fn valid_tzif_bytes(bytes: &[u8]) -> bool {
    fn header(bytes: &[u8], start: usize) -> Option<([usize; 6], u8)> {
        let raw = bytes.get(start..start.checked_add(44)?)?;
        if &raw[..4] != b"TZif" || !matches!(raw[4], 0 | b'2' | b'3') {
            return None;
        }
        let counts = std::array::from_fn(|index| {
            u32::from_be_bytes(raw[20 + index * 4..24 + index * 4].try_into().unwrap()) as usize
        });
        Some((counts, raw[4]))
    }

    fn block(
        bytes: &[u8],
        start: usize,
        counts: [usize; 6],
        width: usize,
        check_entries: bool,
    ) -> Option<usize> {
        let [utc_local, std_wall, leaps, transitions, zones, chars] = counts;
        let time_end = start.checked_add(transitions.checked_mul(width)?)?;
        let index_end = time_end.checked_add(transitions)?;
        let zone_end = index_end.checked_add(zones.checked_mul(6)?)?;
        let char_end = zone_end.checked_add(chars)?;
        let leap_end = char_end.checked_add(leaps.checked_mul(width.checked_add(4)?)?)?;
        let end = leap_end.checked_add(std_wall)?.checked_add(utc_local)?;
        bytes.get(start..end)?;
        if check_entries {
            if zones == 0 || chars == 0 {
                return None;
            }
            if bytes[index_end..zone_end]
                .as_chunks::<6>()
                .0
                .iter()
                .any(|zone| usize::from(zone[5]) >= chars)
                || bytes[time_end..index_end]
                    .iter()
                    .any(|index| usize::from(*index) >= zones)
            {
                return None;
            }
        }
        Some(end)
    }

    let Some((counts, version)) = header(bytes, 0) else {
        return false;
    };
    let Some(first_end) = block(bytes, 44, counts, 4, version == 0) else {
        return false;
    };
    if version == 0 {
        return true;
    }
    let Some((counts, _)) = header(bytes, first_end) else {
        return false;
    };
    block(bytes, first_end + 44, counts, 8, true).is_some()
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
    let (page, limit) = normalize_selection(page, limit, platform)?;
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

fn normalize_selection(
    page: usize,
    limit: usize,
    platform: Option<Platform>,
) -> Result<(usize, usize)> {
    let page = if page == 0 { 1 } else { page };
    let limit = if limit == 0 { DEFAULT_LIMIT } else { limit };
    if limit > MAX_LIMIT {
        bail!("limit must not exceed {MAX_LIMIT}");
    }
    if matches!(platform, Some(Platform::Unknown | Platform::Watchos)) {
        bail!("invalid platform for purchase history");
    }
    Ok((page, limit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sap_assets::SapAssetBundle;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    #[cfg(target_os = "macos")]
    fn timezone_labels_follow_go_local_rules() {
        assert_eq!(resolve_timezone_label(None), "Local");
        assert_eq!(resolve_timezone_label(Some("")), "UTC");
        assert_eq!(resolve_timezone_label(Some(":UTC")), "UTC");
        assert_eq!(resolve_timezone_label(Some("Not/AZone")), "UTC");
        assert_eq!(resolve_timezone_label(Some("PST8")), "UTC");
        assert_eq!(
            resolve_timezone_label(Some("America/Los_Angeles")),
            "America/Los_Angeles"
        );
        assert_eq!(resolve_timezone_label(Some(":/etc/localtime")), "Local");

        let directory = tempfile::tempdir().unwrap();
        let invalid = directory.path().join("broken-tzfile");
        std::fs::write(&invalid, b"TZif").unwrap();
        assert_eq!(resolve_timezone_label(invalid.to_str()), "UTC");
        assert!(!valid_tzif_bytes(b"TZif"));

        let mut tzif = vec![0u8; 54];
        tzif[..4].copy_from_slice(b"TZif");
        tzif[36..40].copy_from_slice(&1u32.to_be_bytes());
        tzif[40..44].copy_from_slice(&4u32.to_be_bytes());
        tzif[50..54].copy_from_slice(b"UTC\0");
        assert!(valid_tzif_bytes(&tzif));
        tzif[49] = 4;
        assert!(!valid_tzif_bytes(&tzif));
        assert!(valid_tzfile(std::path::Path::new(
            "/usr/share/zoneinfo/America/Los_Angeles"
        )));
    }

    #[derive(Debug, PartialEq)]
    struct WireHistory {
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn wire_history(request: &Request) -> WireHistory {
        let mut headers: Vec<_> = request
            .headers
            .iter()
            .map(|(name, value)| {
                let name = name.to_string();
                let value = if matches!(name.as_str(), "date" | "x-apple-i-client-time") {
                    "<time>".into()
                } else {
                    value.to_str().unwrap().to_owned()
                };
                (name, value)
            })
            .collect();
        headers.sort();
        let mut body = request.body.clone().unwrap_or_default();
        if request.url.path().ends_with("/items") {
            assert_eq!(&body[..4], b"adsr");
            assert_eq!(&body[8..12], b"mstc");
            body[16..20].fill(0);
        }
        WireHistory {
            url: request.url.to_string(),
            headers,
            body,
        }
    }

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

    #[test]
    fn zero_pagination_uses_go_owned_apps_defaults() {
        let apps = (0..12)
            .map(|id| App {
                id,
                ..App::default()
            })
            .collect();
        let output = select_page(apps, 0, 0, None).unwrap();
        assert_eq!((output.page, output.count, output.total_count), (1, 10, 12));
        assert_eq!(output.apps[0].id, 0);
        assert_eq!(output.apps[9].id, 9);
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
                set_cookie_headers: Vec::new(),
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
        let output = owned_apps_with_signer(&backend, &account, 0, 0, None, &mut |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(b"signed".to_vec())
        })
        .unwrap();
        assert_eq!(
            (
                output.page,
                output.count,
                output.total_count,
                output.apps[0].id
            ),
            (1, 1, 1, 42)
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
                    set_cookie_headers: Vec::new(),
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

    #[test]
    fn native_purchase_history_matches_pinned_store_requests() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let guest_requests = Arc::new(Mutex::new(Vec::new()));
        let observed_guest = Arc::clone(&guest_requests);
        let guest_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&guest_calls);
        let guest = StoreBackend::with_sender(
            assets.apple_media_services,
            [0, 1, 2, 3, 4, 5],
            move |request| {
                observed_guest.lock().unwrap().push(wire_history(&request));
                let call = observed_calls.fetch_add(1, Ordering::SeqCst);
                history_response(call)
            },
        );
        let native_requests = Arc::new(Mutex::new(Vec::new()));
        let observed_native = Arc::clone(&native_requests);
        let native_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&native_calls);
        let native = NativeOwnedBackend::with_sender([0, 1, 2, 3, 4, 5], move |request| {
            observed_native.lock().unwrap().push(wire_history(&request));
            let call = observed_calls.fetch_add(1, Ordering::SeqCst);
            history_response(call)
        });
        let mut account = Account::default();
        account.store_front = "143441-1,29".into();
        account.directory_services_id = "123".into();
        account.password_token = "token".into();
        owned_apps_with_signer(&guest, &account, 1, 10, None, &mut |_| Ok(vec![1, 2, 3])).unwrap();
        owned_apps_with_signer(&native, &account, 1, 10, None, &mut |_| Ok(vec![1, 2, 3])).unwrap();
        assert_eq!(
            *native_requests.lock().unwrap(),
            *guest_requests.lock().unwrap()
        );
    }

    fn history_response(call: usize) -> Result<Response> {
        let body = match call % 3 {
            0 => dmap::tag(b"mlog", &dmap::uint32(b"mlid", 7)?)?,
            1 => dmap::tag(b"mupd", &dmap::uint32(b"musr", 99)?)?,
            _ => dmap::tag(b"mlcl", &item(42, APP_MEDIA_KIND as u32, 1, 100))?,
        };
        Ok(Response {
            set_cookie_headers: Vec::new(),
            status: 200,
            headers: std::collections::HashMap::new(),
            body,
        })
    }

    #[test]
    fn native_backend_reads_sap_config_without_store_guest() {
        let backend = NativeOwnedBackend::with_sender([0, 1, 2, 3, 4, 5], |request| {
            assert_eq!(request.method, Method::GET);
            assert_eq!(
                request.url.as_str(),
                "https://init.itunes.apple.com/bag.xml?guid=000102030405"
            );
            assert!(request.no_redirects);
            Ok(Response {
                set_cookie_headers: Vec::new(),
                status: 200,
                headers: std::collections::HashMap::new(),
                body: br#"<plist version="1.0"><dict><key>urlBag</key><dict/></dict></plist>"#
                    .to_vec(),
            })
        });
        assert_eq!(backend.sap_config().unwrap().version, 200);
    }
}
