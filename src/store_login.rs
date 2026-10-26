//! App Store login protocol over the pinned Store request backend.

use std::{error::Error, fmt, thread, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::{SapConfig, normalize_auth_code, phone_number_storefront, resolve_auth_redirect},
    credentials::{Account, AccountStore, CredentialStore},
    sap_signer::Signer,
    store_backend::{StoreBackend, StoreBackendRequest},
    transport::{DEFAULT_AUTHENTICATION_TIMEOUT, Response, is_authentication_redirect},
};

const BAD_LOGIN: &str = "MZFinance.BadLogin.Configurator_message";
const ACCOUNT_DISABLED: &str = "Your account is disabled.";
const MAX_REDIRECTS: usize = 4;
const MAX_HTTP_ATTEMPTS: usize = 3;

type LoginSigner<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>> + 'a;

#[derive(Debug)]
pub struct AuthCodeRequired;

impl fmt::Display for AuthCodeRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("2FA code is required")
    }
}

impl Error for AuthCodeRequired {}

pub struct LoginInput {
    pub email: String,
    pub password: String,
    pub auth_code: String,
}

impl Drop for LoginInput {
    fn drop(&mut self) {
        self.password.zeroize();
        self.auth_code.zeroize();
    }
}

pub trait AuthenticationBackend {
    fn hardware_id(&self) -> [u8; 6];
    fn sap_config(&self) -> Result<SapConfig>;
    fn send_authentication(
        &self,
        request: StoreBackendRequest<'_>,
        signer: &mut LoginSigner<'_>,
    ) -> Result<Response>;
}

impl AuthenticationBackend for StoreBackend {
    fn hardware_id(&self) -> [u8; 6] {
        self.hardware_id()
    }

    fn sap_config(&self) -> Result<SapConfig> {
        self.sap_config()
    }

    fn send_authentication(
        &self,
        request: StoreBackendRequest<'_>,
        signer: &mut LoginSigner<'_>,
    ) -> Result<Response> {
        self.execute_authentication(request, signer)
    }
}

/// Complete the login protocol with the real SAP signer and save the account.
pub fn login<S: CredentialStore>(
    backend: &StoreBackend,
    accounts: &AccountStore<S>,
    input: LoginInput,
) -> Result<Account> {
    let config = backend
        .sap_config()
        .context("load Store SAP configuration")?;
    let mut signer =
        Signer::open(&config, &backend.hardware_id()).context("initialize SAP action signer")?;
    let result = login_with_config(
        backend,
        accounts,
        input,
        &config,
        &mut |body| signer.sign(body),
        thread::sleep,
    );
    let close = signer.close().context("close SAP action signer");
    match (result, close) {
        (Ok(account), Ok(())) => Ok(account),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(first.context(second)),
    }
}

pub fn login_with_signer<B: AuthenticationBackend, S: CredentialStore>(
    backend: &B,
    accounts: &AccountStore<S>,
    input: LoginInput,
    signer: &mut LoginSigner<'_>,
) -> Result<Account> {
    let config = backend
        .sap_config()
        .context("load Store SAP configuration")?;
    login_with_config(backend, accounts, input, &config, signer, thread::sleep)
}

fn login_with_config<B: AuthenticationBackend, S: CredentialStore>(
    backend: &B,
    accounts: &AccountStore<S>,
    input: LoginInput,
    config: &SapConfig,
    signer: &mut LoginSigner<'_>,
    mut sleep: impl FnMut(Duration),
) -> Result<Account> {
    if input.email.trim().is_empty() || input.password.is_empty() {
        bail!("Apple ID and password are required");
    }
    let auth_code = Zeroizing::new(normalize_auth_code(&input.auth_code)?);
    let mut endpoint = config.auth_endpoint.clone();
    let mut redirects = 0usize;
    let mut attempt = 1usize;
    let guid = backend
        .hardware_id()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    loop {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        if let Some(storefront) = phone_number_storefront(&input.email) {
            headers.insert("X-Apple-Store-Front", HeaderValue::from_static(storefront));
        }
        let parameters = serde_json::json!({
            "appleId": input.email,
            "attempt": attempt.to_string(),
            "guid": guid,
            "password": format!("{}{}", input.password, auth_code.as_str()),
            "rmp": "0",
            "why": "signIn"
        });
        let request = StoreBackendRequest {
            method: "POST",
            url: endpoint.as_str(),
            headers: &headers,
            parameters: Some(&parameters),
            body: None,
            raw: false,
            response_format: "plist",
            no_redirects: true,
            timeout: Some(DEFAULT_AUTHENTICATION_TIMEOUT),
        };
        let response = send_with_retries(backend, request, signer, &mut sleep)?;
        if (300..400).contains(&response.status) {
            if !is_authentication_redirect(response.status) {
                bail!(
                    "unsupported authentication redirect status {}",
                    response.status
                );
            }
            let location = response
                .header("location")
                .context("authentication redirect is missing Location")?;
            if redirects == MAX_REDIRECTS {
                bail!("too many authentication redirects");
            }
            endpoint = resolve_auth_redirect(&endpoint, location)?;
            redirects += 1;
            continue;
        }
        let result: LoginResponse = response.plist(true)?;
        if attempt == 1 && result.failure_type == "-5000" {
            attempt += 1;
            continue;
        }
        if result.failure_type.is_empty() && result.customer_message == BAD_LOGIN {
            if auth_code.is_empty() {
                return Err(AuthCodeRequired.into());
            }
            bail!("Apple did not complete verification; try a fresh 2FA code");
        }
        if result.failure_type.is_empty() && result.customer_message == ACCOUNT_DISABLED {
            bail!("account is disabled");
        }
        if !result.failure_type.is_empty() {
            if result.customer_message.is_empty() {
                bail!("Apple authentication failed: {}", result.failure_type);
            }
            bail!("Apple authentication failed: {}", result.customer_message);
        }
        if response.status != 200
            || result.password_token.is_empty()
            || result.directory_services_id.is_empty()
        {
            bail!(
                "Apple returned no usable authentication response (HTTP {}): missing account credentials or unexpected status",
                response.status
            );
        }
        let storefront = response
            .header("x-set-apple-store-front")
            .context("authentication response has no storefront header")?;
        let account = Account {
            email: result.account.email,
            password_token: result.password_token,
            directory_services_id: result.directory_services_id,
            name: format!(
                "{} {}",
                result.account.address.first_name, result.account.address.last_name
            ),
            store_front: storefront.into(),
            password: input.password.clone(),
            pod: response.header("pod").unwrap_or_default().into(),
        };
        accounts.save(&account).context("save App Store account")?;
        return Ok(account);
    }
}

fn send_with_retries<B: AuthenticationBackend>(
    backend: &B,
    request: StoreBackendRequest<'_>,
    signer: &mut LoginSigner<'_>,
    sleep: &mut impl FnMut(Duration),
) -> Result<Response> {
    let mut outcomes = Vec::new();
    for retry in 0..MAX_HTTP_ATTEMPTS {
        let result = backend.send_authentication(
            StoreBackendRequest {
                method: request.method,
                url: request.url,
                headers: request.headers,
                parameters: request.parameters,
                body: request.body,
                raw: request.raw,
                response_format: request.response_format,
                no_redirects: request.no_redirects,
                timeout: request.timeout,
            },
            signer,
        );
        match result {
            Ok(response)
                if !retryable_status(response.status)
                    || response.plist::<LoginResponse>(true).is_ok() =>
            {
                return Ok(response);
            }
            Ok(response) => {
                outcomes.push(format!("HTTP {}", response.status));
                if retry + 1 == MAX_HTTP_ATTEMPTS {
                    bail!(
                        "authentication request failed after {MAX_HTTP_ATTEMPTS} attempts ({})",
                        outcomes.join(", ")
                    );
                }
                let delay = retry_delay(&response, retry)?;
                sleep(delay);
            }
            Err(error) => {
                let retryable = error.chain().any(|cause| {
                    cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                        matches!(
                            io.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe
                        )
                    }) || cause
                        .downcast_ref::<reqwest::Error>()
                        .is_some_and(reqwest::Error::is_timeout)
                });
                if !retryable {
                    return Err(error).context("authentication request failed");
                }
                outcomes.push("transport error".into());
                if retry + 1 == MAX_HTTP_ATTEMPTS {
                    return Err(error).with_context(|| {
                        format!(
                            "authentication request failed after {MAX_HTTP_ATTEMPTS} attempts ({})",
                            outcomes.join(", ")
                        )
                    });
                }
                sleep(Duration::from_secs(10u64 << retry));
            }
        }
    }
    unreachable!("authentication retries have a fixed positive limit")
}

fn retryable_status(status: u16) -> bool {
    matches!(status, 204 | 403 | 404 | 429) || status >= 500
}

fn retry_delay(response: &Response, retry: usize) -> Result<Duration> {
    let fallback = Duration::from_secs((10u64 << retry).min(30));
    let Some(value) = response.header("retry-after") else {
        return Ok(fallback);
    };
    if let Ok(seconds) = value.trim().parse::<u64>() {
        if seconds > 30 {
            bail!("Apple requested a wait longer than 30 seconds; try again later");
        }
        return Ok(Duration::from_secs(seconds.max(1)));
    }
    Ok(fallback)
}

#[derive(Default, Deserialize)]
struct LoginResponse {
    #[serde(default, rename = "failureType")]
    failure_type: String,
    #[serde(default, rename = "customerMessage")]
    customer_message: String,
    #[serde(default, rename = "accountInfo")]
    account: LoginAccount,
    #[serde(default, rename = "dsPersonId")]
    directory_services_id: String,
    #[serde(default, rename = "passwordToken")]
    password_token: String,
}

#[derive(Default, Deserialize)]
struct LoginAccount {
    #[serde(default, rename = "appleId")]
    email: String,
    #[serde(default)]
    address: LoginAddress,
}

#[derive(Default, Deserialize)]
struct LoginAddress {
    #[serde(default, rename = "firstName")]
    first_name: String,
    #[serde(default, rename = "lastName")]
    last_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sap_assets::SapAssetBundle;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct MemoryStore(Mutex<Option<Vec<u8>>>);
    impl CredentialStore for MemoryStore {
        fn get(&self, _: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn set(&self, _: &str, data: &[u8]) -> Result<()> {
            *self.0.lock().unwrap() = Some(data.to_vec());
            Ok(())
        }
        fn remove(&self, _: &str) -> Result<bool> {
            Ok(self.0.lock().unwrap().take().is_some())
        }
    }

    struct FixtureBackend {
        responses: Mutex<Vec<Response>>,
        seen: Mutex<Vec<(String, String)>>,
    }
    impl FixtureBackend {
        fn new(responses: Vec<Response>) -> Self {
            Self {
                responses: Mutex::new(responses),
                seen: Mutex::new(Vec::new()),
            }
        }
    }
    impl AuthenticationBackend for FixtureBackend {
        fn hardware_id(&self) -> [u8; 6] {
            [0, 1, 2, 3, 4, 5]
        }
        fn sap_config(&self) -> Result<SapConfig> {
            Ok(SapConfig {
                auth_endpoint:
                    "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"
                        .parse()?,
                setup_url: "https://fpinit.itunes.apple.com/setup".parse()?,
                certificate_url: "https://s.mzstatic.com/cert".parse()?,
                version: 200,
            })
        }
        fn send_authentication(
            &self,
            request: StoreBackendRequest<'_>,
            _: &mut LoginSigner<'_>,
        ) -> Result<Response> {
            assert_eq!(request.method, "POST");
            assert!(request.no_redirects);
            assert_eq!(request.parameters.unwrap()["guid"], "000102030405");
            self.seen.lock().unwrap().push((
                request.url.into(),
                request.parameters.unwrap()["attempt"]
                    .as_str()
                    .unwrap()
                    .into(),
            ));
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    fn fixture_response(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: std::collections::HashMap::from([(
                "x-set-apple-store-front".into(),
                "143441-1,29".into(),
            )]),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn retries_invalid_credentials_then_saves_account() {
        let backend = FixtureBackend::new(vec![
            fixture_response(
                200,
                r#"<plist version="1.0"><dict><key>failureType</key><string>-5000</string></dict></plist>"#,
            ),
            fixture_response(
                200,
                r#"<plist version="1.0"><dict><key>passwordToken</key><string>token</string><key>dsPersonId</key><string>123</string><key>accountInfo</key><dict><key>appleId</key><string>test@example.com</string><key>address</key><dict><key>firstName</key><string>Test</string><key>lastName</key><string>User</string></dict></dict></dict></plist>"#,
            ),
        ]);
        let accounts = AccountStore::new(MemoryStore::default());
        let account = login_with_signer(
            &backend,
            &accounts,
            LoginInput {
                email: "test@example.com".into(),
                password: "secret".into(),
                auth_code: "".into(),
            },
            &mut |_| Ok(vec![1]),
        )
        .unwrap();
        assert_eq!(account.name, "Test User");
        assert_eq!(account.password_token, "token");
        assert_eq!(accounts.load().unwrap().directory_services_id, "123");
        assert_eq!(backend.seen.lock().unwrap()[0].1, "1");
        assert_eq!(backend.seen.lock().unwrap()[1].1, "2");
    }

    #[test]
    fn reports_two_factor_challenge_without_saving() {
        let backend = FixtureBackend::new(vec![fixture_response(
            200,
            r#"<plist version="1.0"><dict><key>customerMessage</key><string>MZFinance.BadLogin.Configurator_message</string></dict></plist>"#,
        )]);
        let accounts = AccountStore::new(MemoryStore::default());
        let error = login_with_signer(
            &backend,
            &accounts,
            LoginInput {
                email: "test@example.com".into(),
                password: "secret".into(),
                auth_code: "".into(),
            },
            &mut |_| Ok(vec![1]),
        )
        .err()
        .unwrap();
        assert!(error.downcast_ref::<AuthCodeRequired>().is_some());
        assert!(accounts.load().is_err());
    }

    #[test]
    fn follows_allowlisted_store_pod_without_incrementing_attempt() {
        let mut redirect = fixture_response(302, "");
        redirect.headers.insert(
            "location".into(),
            "https://p1-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/".into(),
        );
        let backend = FixtureBackend::new(vec![
            redirect,
            fixture_response(
                200,
                r#"<plist version="1.0"><dict><key>passwordToken</key><string>token</string><key>dsPersonId</key><string>123</string><key>accountInfo</key><dict><key>appleId</key><string>test@example.com</string></dict></dict></plist>"#,
            ),
        ]);
        let accounts = AccountStore::new(MemoryStore::default());
        login_with_signer(
            &backend,
            &accounts,
            LoginInput {
                email: "test@example.com".into(),
                password: "secret".into(),
                auth_code: "".into(),
            },
            &mut |_| Ok(vec![1]),
        )
        .unwrap();
        let seen = backend.seen.lock().unwrap();
        assert_eq!(seen[0].1, "1");
        assert_eq!(seen[1].1, "1");
        assert!(seen[1].0.starts_with("https://p1-buy.itunes.apple.com/"));
    }

    #[test]
    fn decodes_populated_credential_error_without_retrying() {
        let backend = FixtureBackend::new(vec![fixture_response(
            403,
            r#"<plist version="1.0"><dict><key>failureType</key><string>2034</string><key>customerMessage</key><string>credentials expired</string></dict></plist>"#,
        )]);
        let accounts = AccountStore::new(MemoryStore::default());
        let error = login_with_signer(
            &backend,
            &accounts,
            LoginInput {
                email: "test@example.com".into(),
                password: "secret".into(),
                auth_code: "".into(),
            },
            &mut |_| Ok(vec![1]),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("credentials expired"));
        assert_eq!(backend.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn signs_and_saves_login_through_pinned_store_backend() {
        let assets = SapAssetBundle::load_cached().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let backend = StoreBackend::with_sender(
            assets.apple_media_services,
            [0, 1, 2, 3, 4, 5],
            move |request| {
                let call = seen.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    assert_eq!(request.url.host_str(), Some("init.itunes.apple.com"));
                    return Ok(fixture_response(
                        200,
                        r#"<plist version="1.0"><dict><key>urlBag</key><dict><key>authenticateAccount</key><string>https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate</string></dict></dict></plist>"#,
                    ));
                }
                assert_eq!(request.method, reqwest::Method::POST);
                assert_eq!(
                    request.headers.get("x-apple-actionsignature").unwrap(),
                    "AQID"
                );
                let body: serde_json::Value =
                    plist::from_bytes(request.body.as_ref().unwrap()).unwrap();
                assert_eq!(body["appleId"], "test@example.com");
                assert_eq!(body["guid"], "000102030405");
                Ok(fixture_response(
                    200,
                    r#"<plist version="1.0"><dict><key>passwordToken</key><string>token</string><key>dsPersonId</key><string>123</string><key>accountInfo</key><dict><key>appleId</key><string>test@example.com</string></dict></dict></plist>"#,
                ))
            },
        );
        let accounts = AccountStore::new(MemoryStore::default());
        let account = login_with_signer(
            &backend,
            &accounts,
            LoginInput {
                email: "test@example.com".into(),
                password: "secret".into(),
                auth_code: "".into(),
            },
            &mut |_| Ok(vec![1, 2, 3]),
        )
        .unwrap();
        assert_eq!(account.directory_services_id, "123");
        assert_eq!(accounts.load().unwrap().password_token, "token");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
