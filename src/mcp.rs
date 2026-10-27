//! Non-interactive App Store MCP server. Store calls are synchronous and share
//! account/cache state, so each invocation runs behind a single async gate.

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use ipatool_rs::catalog::AppNotFound;
use ipatool_rs::credentials::{Account, AccountStore, open_system_keychain};
use ipatool_rs::store_download_product::{DownloadProductClient, LicenseRequired};
use ipatool_rs::store_login::{self, LoginInput, NativeAuthenticationBackend};
use ipatool_rs::store_owned::{self, DEFAULT_LIMIT, MAX_LIMIT, NativeOwnedBackend};
use ipatool_rs::store_purchase::{
    self, LicenseAlreadyExists, NativePurchaseBackend, PasswordTokenExpired,
};
use ipatool_rs::storefront::country_code_from_storefront;
use ipatool_rs::{App, CatalogClient, Platform};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppStoreServer {
    gate: Arc<Mutex<()>>,
}

impl AppStoreServer {
    fn new() -> Self {
        Self {
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn run(&self, work: impl FnOnce() -> Result<Value> + Send + 'static) -> CallToolResult {
        let guard = Arc::clone(&self.gate).lock_owned().await;
        match tokio::task::spawn_blocking(move || {
            let _guard = guard;
            work()
        })
        .await
        {
            Ok(Ok(value)) => CallToolResult::structured(value),
            Ok(Err(error)) => {
                CallToolResult::structured_error(json!({ "error": format!("{error:#}") }))
            }
            Err(error) => CallToolResult::structured_error(
                json!({ "error": format!("tool task failed: {error}") }),
            ),
        }
    }
}

#[derive(Deserialize, JsonSchema)]
struct SearchInput {
    /// Search term.
    term: String,
    /// Maximum results (default 5; visionOS supports up to 12).
    limit: Option<i64>,
    /// iphone, ipad, appletv, watchos, visionos, or macos.
    platform: Option<String>,
}

#[derive(Clone, Deserialize, JsonSchema)]
struct AppInput {
    /// Numeric app ID; required unless bundle_identifier is supplied.
    app_id: Option<i64>,
    /// Bundle identifier; takes precedence over app_id when found.
    bundle_identifier: Option<String>,
    /// iphone, ipad, appletv, watchos, visionos, or macos.
    platform: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct DownloadInput {
    /// Numeric app ID.
    app_id: Option<i64>,
    /// Bundle identifier.
    bundle_identifier: Option<String>,
    /// Target file or directory; defaults to the working directory.
    output: Option<String>,
    /// External version identifier; latest when omitted.
    external_version_id: Option<String>,
    /// Store platform; defaults to iphone.
    platform: Option<String>,
    /// Acquire a free license if required.
    purchase: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct MetadataInput {
    app_id: Option<i64>,
    bundle_identifier: Option<String>,
    platform: Option<String>,
    /// Required external version identifier.
    external_version_id: String,
}

#[derive(Deserialize, JsonSchema)]
struct PurchasesInput {
    /// Page number, starting at 1.
    page: Option<usize>,
    /// Apps per page, 1 to 100.
    max_results: Option<usize>,
    /// Optional platform filter.
    platform: Option<String>,
}

#[tool_router]
impl AppStoreServer {
    #[tool(
        name = "search_apps",
        description = "Search for apps on the App Store."
    )]
    async fn search_apps(&self, Parameters(input): Parameters<SearchInput>) -> CallToolResult {
        self.run(move || {
            if input.term.trim().is_empty() { bail!("search term must not be empty"); }
            let limit = input.limit.unwrap_or(5);
            if limit < 1 { bail!("limit must be greater than 0"); }
            let platform = parse_platform(input.platform.as_deref())?;
            with_account(|account| {
                let country = country_code_from_storefront(&account.store_front)?;
                let result = CatalogClient::new()?.search(&input.term, country, limit, platform)?;
                Ok(json!({"term": input.term, "limit": limit, "platform": platform, "count": result.count,
                    "apps": result.apps.iter().map(app_value).collect::<Vec<_>>() }))
            })
        }).await
    }

    #[tool(
        name = "list_app_versions",
        description = "List available external version identifiers for an app."
    )]
    async fn list_app_versions(&self, Parameters(input): Parameters<AppInput>) -> CallToolResult {
        self.run(move || {
            let platform = parse_platform(input.platform.as_deref())?.unwrap_or(Platform::Iphone);
            with_account(|account| {
                let catalog = CatalogClient::new()?;
                let app = resolve_app(&catalog, account, &input, Some(platform), false)?;
                let out = DownloadProductClient::open()?.list_versions(&catalog, account, &app, platform)?;
                Ok(json!({"app_id": app.id, "bundle_identifier": app.bundle_id, "platform": platform,
                    "app": app_value(&app), "externalVersionIdentifiers": out.external_version_identifiers,
                    "latestExternalVersionID": out.latest_external_version_id, "bundleID": app.bundle_id, "success": true}))
            })
        }).await
    }

    #[tool(
        name = "get_version_metadata",
        description = "Get a display version and release date for an external version ID."
    )]
    async fn get_version_metadata(
        &self,
        Parameters(input): Parameters<MetadataInput>,
    ) -> CallToolResult {
        self.run(move || {
            if input.external_version_id.trim().is_empty() { bail!("external version identifier must not be empty"); }
            let app_input = AppInput { app_id: input.app_id, bundle_identifier: input.bundle_identifier, platform: input.platform };
            let platform = parse_platform(app_input.platform.as_deref())?;
            with_account(|account| {
                let catalog = CatalogClient::new()?;
                let app = resolve_app(&catalog, account, &app_input, platform, false)?;
                let out = DownloadProductClient::open()?.get_version_metadata(account, &app, &input.external_version_id, platform)?;
                Ok(json!({"app_id": app.id, "bundle_identifier": app.bundle_id, "platform": platform,
                    "app": app_value(&app), "external_version_id": input.external_version_id,
                    "displayVersion": out.display_version, "releaseDate": out.release_date, "success": true}))
            })
        }).await
    }

    #[tool(
        name = "list_purchases",
        description = "List apps owned by the authenticated account, with pagination."
    )]
    async fn list_purchases(
        &self,
        Parameters(input): Parameters<PurchasesInput>,
    ) -> CallToolResult {
        self.run(move || {
            let page = input.page.unwrap_or(1);
            let limit = input.max_results.unwrap_or(DEFAULT_LIMIT);
            if page == 0 || limit == 0 || limit > MAX_LIMIT {
                bail!("page must be positive and max results must be between 1 and {MAX_LIMIT}");
            }
            let platform = parse_platform(input.platform.as_deref())?;
            with_account(|account| {
                let out = store_owned::owned_apps(
                    &NativeOwnedBackend::open()?,
                    account,
                    page,
                    limit,
                    platform,
                )?;
                Ok(
                    json!({"count": out.count, "totalCount": out.total_count, "page": out.page,
                    "max_results": limit, "platform": platform,
                    "apps": out.apps.iter().map(app_value).collect::<Vec<_>>() }),
                )
            })
        })
        .await
    }

    #[tool(
        name = "purchase_app",
        description = "Acquire a license for a free app; paid apps are unsupported."
    )]
    async fn purchase_app(&self, Parameters(input): Parameters<AppInput>) -> CallToolResult {
        self.run(move || {
            let platform = parse_platform(input.platform.as_deref())?;
            with_account(|account| {
                let app = resolve_app(&CatalogClient::new()?, account, &input, platform, false)?;
                let result = store_purchase::purchase(&NativePurchaseBackend::open()?, account, &app, platform);
                let already_owned = result.as_ref().err().is_some_and(|e| e.downcast_ref::<LicenseAlreadyExists>().is_some());
                if !already_owned { result?; }
                Ok(json!({"app_id": app.id, "bundle_identifier": app.bundle_id, "platform": platform,
                    "app": app_value(&app), "alreadyOwned": already_owned, "success": true}))
            })
        }).await
    }

    #[tool(
        name = "download_app",
        description = "Download an app package; optionally acquire a free license."
    )]
    async fn download_app(&self, Parameters(input): Parameters<DownloadInput>) -> CallToolResult {
        self.run(move || {
            let app_input = AppInput { app_id: input.app_id, bundle_identifier: input.bundle_identifier.clone(), platform: input.platform.clone() };
            let platform = parse_platform(input.platform.as_deref())?.unwrap_or(Platform::Iphone);
            let version = input.external_version_id.unwrap_or_default();
            let output = input.output.map(PathBuf::from);
            let purchase = input.purchase.unwrap_or(false);
            let mut purchased = false;
            with_account(|account| {
                let catalog = CatalogClient::new()?;
                let app = resolve_app(&catalog, account, &app_input, Some(platform), true)?;
                let client = DownloadProductClient::open()?;
                let download = || {
                    if platform == Platform::Macos {
                        client.download_macos(&catalog, account, &app, &version, output.as_deref())
                    } else {
                        client.download_ipa(&catalog, account, &app, &version, platform, output.as_deref())
                    }
                };
                let path = match download() {
                    Err(error) if purchase && !purchased && error.downcast_ref::<LicenseRequired>().is_some() => {
                        match store_purchase::purchase(&NativePurchaseBackend::open()?, account, &app, Some(platform)) {
                            Ok(()) => {},
                            Err(error) if error.downcast_ref::<LicenseAlreadyExists>().is_some() => {},
                            Err(error) => return Err(error),
                        }
                        purchased = true;
                        download()?
                    }
                    result => result?,
                };
                Ok(json!({"app_id": app.id, "bundle_identifier": app.bundle_id, "platform": platform,
                    "app": app_value(&app), "output": path, "external_version_id": version,
                    "purchase": purchase, "purchased": purchased, "success": true}))
            })
        }).await
    }
}

#[tool_handler]
impl ServerHandler for AppStoreServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ipatool", env!("CARGO_PKG_VERSION")))
            .with_instructions("Use the existing ipatool account. For authentication, run 'ipatool auth login' outside MCP. Purchases support free apps only.")
    }
}

pub fn serve() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let service = AppStoreServer::new()
                .serve(rmcp::transport::stdio())
                .await?;
            service.waiting().await?;
            Ok(())
        })
}

fn with_account(mut work: impl FnMut(&Account) -> Result<Value>) -> Result<Value> {
    let store = AccountStore::new(open_system_keychain()?);
    let mut account = store
        .load()
        .context("account unavailable; run 'ipatool auth login' before using MCP")?;
    match work(&account) {
        Err(error) if error.downcast_ref::<PasswordTokenExpired>().is_some() => {
            account = store_login::login(
                &NativeAuthenticationBackend::open()?,
                &store,
                LoginInput {
                    email: account.email.clone(),
                    password: account.password.clone(),
                    auth_code: String::new(),
                },
            )
            .context("session refresh failed; run 'ipatool auth login' outside MCP")?;
            work(&account).context("operation failed after session refresh")
        }
        result => result,
    }
}

fn parse_platform(value: Option<&str>) -> Result<Option<Platform>> {
    Platform::parse(value.unwrap_or_default())
}

fn resolve_app(
    catalog: &CatalogClient,
    account: &Account,
    input: &AppInput,
    platform: Option<Platform>,
    allow_delisted: bool,
) -> Result<App> {
    let id = input.app_id.unwrap_or_default();
    let bundle = input
        .bundle_identifier
        .as_deref()
        .unwrap_or_default()
        .trim();
    if id < 0 || (id == 0 && bundle.is_empty()) {
        bail!("a positive app ID or bundle identifier is required");
    }
    if bundle.is_empty() {
        return Ok(App {
            id,
            ..App::default()
        });
    }
    let country = country_code_from_storefront(&account.store_front)?;
    match catalog.lookup(None, Some(bundle), country, platform) {
        Ok(app) => Ok(app),
        Err(error) if allow_delisted && id > 0 && error.downcast_ref::<AppNotFound>().is_some() => {
            Ok(App {
                id,
                bundle_id: bundle.to_owned(),
                ..App::default()
            })
        }
        Err(error) => Err(error),
    }
}

fn app_value(app: &App) -> Value {
    json!({"trackId": app.id, "bundleId": app.bundle_id, "trackName": app.name,
        "version": app.version, "price": app.price, "purchaseDate": app.purchase_date,
        "platforms": app.platforms.clone().unwrap_or_default()})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_call_keeps_store_gate_until_blocking_work_finishes() {
        let server = AppStoreServer::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = tokio::spawn({
            let server = server.clone();
            async move {
                server
                    .run(move || {
                        let _ = started_tx.send(());
                        release_rx.recv()?;
                        Ok(json!({ "first": true }))
                    })
                    .await
            }
        });
        started_rx.await.unwrap();
        first.abort();
        let (second_started_tx, mut second_started_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            server
                .run(move || {
                    let _ = second_started_tx.send(());
                    Ok(json!({ "second": true }))
                })
                .await
        });
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut second_started_rx
            )
            .await
            .is_err(),
            "second Store call entered while cancelled first call was still running"
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), second_started_rx)
            .await
            .unwrap()
            .unwrap();
        second.await.unwrap();
    }

    #[test]
    fn exposes_all_six_store_tools_with_object_schemas() {
        let tools = AppStoreServer::tool_router().list_all();
        let names: std::collections::BTreeSet<_> =
            tools.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(
            names,
            [
                "download_app",
                "get_version_metadata",
                "list_app_versions",
                "list_purchases",
                "purchase_app",
                "search_apps"
            ]
            .into()
        );
        for tool in tools {
            assert_eq!(
                tool.input_schema.get("type").and_then(Value::as_str),
                Some("object")
            );
        }
    }
}
