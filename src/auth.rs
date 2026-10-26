//! Authentication protocol preparation and Apple URL bag handling.

use anyhow::{Context, Result, bail};
use reqwest::{
    Method,
    header::{ACCEPT, HeaderValue},
};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::transport::{DEFAULT_AUTHENTICATION_TIMEOUT, Request, Transport};

const AUTH_PATH: &str = "/WebObjects/MZFinance.woa/wa/authenticate";
const FALLBACK_AUTH_ENDPOINT: &str =
    "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate";
const FALLBACK_SAP_SETUP: &str = "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy";
const FALLBACK_SAP_CERTIFICATE: &str = "https://s.mzstatic.com/sap/setupCert.plist";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SapConfig {
    pub auth_endpoint: Url,
    pub setup_url: Url,
    pub certificate_url: Url,
    pub version: u32,
}

#[derive(Debug, Deserialize)]
struct BagResponse {
    #[serde(rename = "urlBag")]
    bag: UrlBag,
}

#[derive(Debug, Deserialize)]
struct UrlBag {
    #[serde(rename = "authenticateAccount")]
    auth_endpoint: Option<String>,
    #[serde(rename = "sign-sap-setup")]
    setup_url: Option<String>,
    #[serde(rename = "sign-sap-setup-cert")]
    certificate_url: Option<String>,
    #[serde(rename = "sign-sap-version")]
    version: Option<String>,
}

pub fn normalize_auth_code(code: &str) -> Result<String> {
    if code.is_empty() {
        return Ok(String::new());
    }
    let mut code = code.trim();
    if let Some(inner) = code.strip_prefix("\x1b[200~")
        && let Some(inner) = inner.strip_suffix("\x1b[201~")
    {
        code = inner;
    }
    let normalized: String = code
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if normalized.len() != 6 || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("2FA code must contain exactly six digits");
    }
    Ok(normalized)
}

pub fn phone_number_storefront(apple_id: &str) -> Option<&'static str> {
    let mut number = apple_id.trim().replace([' ', '-'], "");
    let international = if number.starts_with('+') {
        number.remove(0);
        true
    } else if number.starts_with("00") {
        number.drain(..2);
        true
    } else {
        false
    };
    if !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if number.len() == 13 && number.starts_with("861") {
        return Some("143465");
    }
    if number.len() == 12 && number.starts_with("91") {
        number.drain(..2);
    } else if international {
        return None;
    }
    if number.len() == 11 && number.starts_with('1') {
        return Some("143465");
    }
    if !international && number.len() == 11 && number.starts_with('0') {
        number.remove(0);
    }
    if number.len() == 10
        && number.as_bytes()[0].is_ascii_digit()
        && (b'6'..=b'9').contains(&number.as_bytes()[0])
    {
        return Some("143467");
    }
    None
}

pub fn machine_identity(mac_address: &str) -> Result<(String, Vec<u8>)> {
    let parts: Vec<&str> = mac_address.split([':', '-']).collect();
    if parts.is_empty() || parts.len() > 20 || parts.iter().any(|part| part.len() != 2) {
        bail!("invalid hardware address");
    }
    let bytes: Vec<u8> = parts
        .iter()
        .map(|part| u8::from_str_radix(part, 16).context("invalid hardware address"))
        .collect::<Result<_>>()?;
    let guid = bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    Ok((guid, bytes))
}

pub fn validate_auth_endpoint(url: &Url) -> Result<()> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.path().contains('%')
    {
        bail!("invalid authentication endpoint");
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host != "buy.itunes.apple.com" && !host.ends_with("-buy.itunes.apple.com") {
        bail!("unsupported authentication endpoint");
    }
    if url.path() != AUTH_PATH && url.path() != format!("{AUTH_PATH}/") {
        bail!("unsupported authentication endpoint");
    }
    Ok(())
}

pub fn resolve_auth_redirect(endpoint: &Url, location: &str) -> Result<Url> {
    if location.trim().is_empty() {
        bail!("invalid authentication redirect location");
    }
    let destination = endpoint
        .join(location.trim())
        .context("invalid authentication redirect location")?;
    validate_auth_endpoint(&destination).context("invalid authentication redirect")?;
    Ok(destination)
}

pub fn validate_sap_config(config: &SapConfig) -> Result<()> {
    validate_auth_endpoint(&config.auth_endpoint)?;
    for (name, endpoint) in [
        ("SAP setup", &config.setup_url),
        ("SAP setup certificate", &config.certificate_url),
    ] {
        if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
            bail!("invalid {name} endpoint in bag");
        }
    }
    if config.version != 200 {
        bail!("unsupported SAP version {} in bag", config.version);
    }
    Ok(())
}

pub fn fetch_bag(transport: &Transport, mac_address: &str) -> Result<SapConfig> {
    let (guid, _) = machine_identity(mac_address)?;
    let url = Url::parse(&format!(
        "https://init.itunes.apple.com/bag.xml?guid={guid}"
    ))?;
    let mut request = Request::get(url);
    request.method = Method::GET;
    request
        .headers
        .insert(ACCEPT, HeaderValue::from_static("application/xml"));
    request.timeout = Some(DEFAULT_AUTHENTICATION_TIMEOUT);
    let response = transport
        .send(request)
        .context("failed to request Apple URL bag")?;
    response.ensure_success()?;
    let parsed: BagResponse = response.plist(false)?;
    config_from_bag(parsed)
}

pub fn sap_config_from_bag_value(value: &Value) -> Result<SapConfig> {
    let parsed: BagResponse =
        serde_json::from_value(value.clone()).context("invalid Store URL bag")?;
    config_from_bag(parsed)
}

fn config_from_bag(parsed: BagResponse) -> Result<SapConfig> {
    // Apple may omit the legacy Store and SAP keys from an otherwise valid
    // bag. Use the independently validated endpoints only for absent keys.
    let mut config = SapConfig {
        auth_endpoint: Url::parse(
            parsed
                .bag
                .auth_endpoint
                .as_deref()
                .unwrap_or(FALLBACK_AUTH_ENDPOINT),
        )
        .context("invalid authentication endpoint in bag")?,
        setup_url: Url::parse(
            parsed
                .bag
                .setup_url
                .as_deref()
                .unwrap_or(FALLBACK_SAP_SETUP),
        )
        .context("invalid SAP setup endpoint in bag")?,
        certificate_url: Url::parse(
            parsed
                .bag
                .certificate_url
                .as_deref()
                .unwrap_or(FALLBACK_SAP_CERTIFICATE),
        )
        .context("invalid SAP setup certificate endpoint in bag")?,
        version: parsed
            .bag
            .version
            .as_deref()
            .unwrap_or("200")
            .parse()
            .context("invalid SAP version in bag")?,
    };
    validate_sap_config(&config)?;
    config.auth_endpoint.set_path(&format!("{AUTH_PATH}/"));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_legacy_bag_keys_use_validated_endpoints() {
        let parsed: BagResponse = plist::from_bytes(
            b"<plist version=\"1.0\"><dict><key>urlBag</key><dict/></dict></plist>",
        )
        .unwrap();
        let config = config_from_bag(parsed).unwrap();
        assert_eq!(config.setup_url.as_str(), FALLBACK_SAP_SETUP);
        assert_eq!(config.certificate_url.as_str(), FALLBACK_SAP_CERTIFICATE);
        assert_eq!(config.version, 200);
        assert_eq!(config.auth_endpoint.path(), format!("{AUTH_PATH}/"));
        let parsed: BagResponse = plist::from_bytes(b"<plist version=\"1.0\"><dict><key>urlBag</key><dict><key>sign-sap-setup</key><string>http://invalid.test</string></dict></dict></plist>").unwrap();
        assert!(config_from_bag(parsed).is_err());
    }

    #[test]
    #[ignore = "contacts the live Apple URL bag"]
    fn fetches_current_apple_bag_with_legacy_endpoint_fallbacks() {
        let transport = Transport::new().unwrap();
        let config = fetch_bag(&transport, "02:00:00:00:00:01").unwrap();
        assert_eq!(config.version, 200);
        assert_eq!(config.setup_url.scheme(), "https");
    }

    #[test]
    fn normalizes_pasted_codes_and_rejects_non_ascii_digits() {
        assert_eq!(
            normalize_auth_code(" \x1b[200~123 456\n\x1b[201~ ").unwrap(),
            "123456"
        );
        assert_eq!(normalize_auth_code("").unwrap(), "");
        assert!(normalize_auth_code("１２３４５６").is_err());
        assert!(normalize_auth_code("\x1b[200~123456").is_err());
    }

    #[test]
    fn routes_phone_ids_without_rewriting_them() {
        assert_eq!(
            phone_number_storefront(" +86 139-1234-5678 "),
            Some("143465")
        );
        assert_eq!(phone_number_storefront("+919123456789"), Some("143467"));
        assert_eq!(phone_number_storefront("9123456789"), Some("143467"));
        assert_eq!(phone_number_storefront("person@example.test"), None);
        assert_eq!(phone_number_storefront("+13912345678"), None);
    }

    #[test]
    fn machine_guid_matches_source_format() {
        let (guid, bytes) = machine_identity("00:11:22:aa:bb:cc").unwrap();
        assert_eq!(guid, "001122AABBCC");
        assert_eq!(bytes, [0, 17, 34, 170, 187, 204]);
        assert!(machine_identity("not-a-hardware-address").is_err());
    }

    #[test]
    fn redirect_rejects_foreign_hosts_and_downgrades() {
        let base =
            Url::parse("https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/")
                .unwrap();
        assert!(validate_auth_endpoint(&base).is_ok());
        assert!(
            resolve_auth_redirect(
                &base,
                "https://p45-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"
            )
            .is_ok()
        );
        assert!(
            resolve_auth_redirect(
                &base,
                "https://evil.example/WebObjects/MZFinance.woa/wa/authenticate/"
            )
            .is_err()
        );
        assert!(
            resolve_auth_redirect(
                &base,
                "http://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"
            )
            .is_err()
        );
        assert!(
            resolve_auth_redirect(
                &base,
                "https://buy.itunes.apple.com:444/WebObjects/MZFinance.woa/wa/authenticate/"
            )
            .is_err()
        );
    }

    #[test]
    fn bag_fields_decode_from_plist_names() {
        let xml = r#"<plist version="1.0"><dict><key>urlBag</key><dict><key>authenticateAccount</key><string>https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate</string><key>sign-sap-setup</key><string>https://example.test/setup</string><key>sign-sap-setup-cert</key><string>https://example.test/cert</string><key>sign-sap-version</key><string>200</string></dict></dict></plist>"#;
        let parsed: BagResponse = plist::from_bytes(xml.as_bytes()).unwrap();
        assert_eq!(parsed.bag.version.as_deref(), Some("200"));
        assert_eq!(
            parsed.bag.auth_endpoint.as_deref(),
            Some("https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate")
        );
    }
}
