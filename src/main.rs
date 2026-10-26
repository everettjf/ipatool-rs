use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use ipatool_rs::credentials::{AccountStore, open_system_keychain};
use ipatool_rs::fairplay::{doctor_fairplay, write_doctor_report};
use ipatool_rs::store_download_product::{DownloadProductClient, LicenseRequired};
use ipatool_rs::store_login::{self, AuthCodeRequired, LoginInput, NativeAuthenticationBackend};
use ipatool_rs::store_owned::{self, DEFAULT_LIMIT, MAX_LIMIT, NativeOwnedBackend};
use ipatool_rs::store_purchase::{
    self, LicenseAlreadyExists, NativePurchaseBackend, PasswordTokenExpired,
};
use ipatool_rs::storefront::country_code_from_storefront;
use ipatool_rs::{App, CatalogClient, Platform, SearchOutput};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "ipatool",
    version,
    about = "Rust port of ipatool-fairplay (in progress)"
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = Format::Text)]
    format: Format,
    #[arg(long, global = true)]
    verbose: bool,
    #[arg(long, global = true)]
    non_interactive: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a shell completion script for the current command set.
    Completion { shell: Shell },
    /// Inspect or remove the account stored by ipatool in the system keychain.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Search the public App Store catalog.
    Search {
        term: String,
        #[arg(short, long, default_value_t = 5)]
        limit: i64,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long, default_value = "US")]
        country: String,
    },
    /// Look up an app by numeric ID or bundle identifier.
    Lookup {
        #[arg(long, conflicts_with = "bundle_identifier")]
        app_id: Option<i64>,
        #[arg(long, conflicts_with = "app_id")]
        bundle_identifier: Option<String>,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long, default_value = "US")]
        country: String,
    },
    /// Obtain a license for a free app from the App Store.
    Purchase {
        #[arg(short = 'i', long)]
        app_id: Option<i64>,
        #[arg(short = 'b', long)]
        bundle_identifier: Option<String>,
        #[arg(long)]
        platform: Option<String>,
    },
    /// Download an owned app package from the App Store.
    Download {
        #[arg(short = 'i', long)]
        app_id: Option<i64>,
        #[arg(short = 'b', long)]
        bundle_identifier: Option<String>,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "")]
        external_version_id: String,
        #[arg(long, default_value = "iphone")]
        platform: String,
        #[arg(long)]
        purchase: bool,
    },
    /// List apps owned by the authenticated App Store account.
    ListPurchases {
        #[arg(short = 'p', long, default_value_t = 1)]
        page: usize,
        #[arg(short = 'l', long, default_value_t = DEFAULT_LIMIT)]
        max_results: usize,
        #[arg(long)]
        platform: Option<String>,
    },
    /// List version IDs available in the account's Store download metadata.
    ListVersions {
        #[arg(short = 'i', long)]
        app_id: Option<i64>,
        #[arg(short = 'b', long)]
        bundle_identifier: Option<String>,
        #[arg(long, default_value = "iphone")]
        platform: String,
    },
    /// Read one app version's display version and release date.
    GetVersionMetadata {
        #[arg(short = 'i', long)]
        app_id: Option<i64>,
        #[arg(short = 'b', long)]
        bundle_identifier: Option<String>,
        #[arg(long)]
        external_version_id: String,
        #[arg(long)]
        platform: Option<String>,
    },
    /// Resolve the latest external version ID from the public platform catalog.
    LatestVersionId {
        #[arg(long)]
        app_id: i64,
        #[arg(long)]
        bundle_identifier: Option<String>,
        #[arg(long, default_value = "iphone")]
        platform: String,
        #[arg(long, default_value = "US")]
        country: String,
    },
    /// Diagnose IPA SINF and enrollment model compatibility.
    FairplayDoctor {
        #[arg(long)]
        capture: Option<PathBuf>,
        #[arg(long)]
        ipa: Option<PathBuf>,
        #[arg(long)]
        model: Option<PathBuf>,
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Sign in to the App Store and save the account in the system keychain.
    Login {
        #[arg(short, long)]
        email: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        auth_code: Option<String>,
    },
    /// Show the stored account's name and email address.
    Info,
    /// Remove the stored account and KBSync cache.
    Revoke,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Completion { shell } => {
            let mut command = Cli::command();
            generate(shell, &mut command, "ipatool", &mut std::io::stdout());
        }
        Command::Auth { command } => {
            let account_store = AccountStore::new(open_system_keychain()?);
            match command {
                AuthCommand::Login {
                    email,
                    password,
                    auth_code,
                } => {
                    let interactive = !cli.non_interactive && io::stdin().is_terminal();
                    let email = match email {
                        Some(value) if !value.is_empty() => value,
                        _ if interactive => {
                            prompt("enter Apple ID (email address or phone number): ", false)?
                        }
                        _ => bail!(
                            "an Apple ID is required when not running in interactive mode; use --email"
                        ),
                    };
                    let password = Zeroizing::new(match password {
                        Some(value) if !value.is_empty() => value,
                        _ if interactive => prompt("enter password: ", true)?,
                        _ => bail!(
                            "password is required when not running in interactive mode; use --password"
                        ),
                    });
                    let mut auth_code = Zeroizing::new(auth_code.unwrap_or_default());
                    let backend = NativeAuthenticationBackend::open()?;
                    let mut code_prompts = 0;
                    let account = loop {
                        let result = store_login::login(
                            &backend,
                            &account_store,
                            LoginInput {
                                email: email.clone(),
                                password: password.to_string(),
                                auth_code: auth_code.to_string(),
                            },
                        );
                        match result {
                            Ok(account) => break account,
                            Err(error) if error.downcast_ref::<AuthCodeRequired>().is_some() => {
                                if !interactive || code_prompts == 1 {
                                    return Err(
                                        error.context("supply a fresh code with --auth-code")
                                    );
                                }
                                *auth_code = prompt("enter 2FA code: ", false)?;
                                code_prompts += 1;
                            }
                            Err(error) => return Err(error),
                        }
                    };
                    let summary = ipatool_rs::credentials::AccountSummary {
                        name: account.name.clone(),
                        email: account.email.clone(),
                        success: true,
                    };
                    match cli.format {
                        Format::Json => println!("{}", serde_json::to_string(&summary)?),
                        Format::Text => {
                            println!("name: {}", summary.name);
                            println!("email: {}", summary.email);
                            println!("success: true");
                        }
                    }
                }
                AuthCommand::Info => {
                    let summary = account_store.info()?;
                    match cli.format {
                        Format::Json => println!("{}", serde_json::to_string(&summary)?),
                        Format::Text => {
                            println!("name: {}", summary.name);
                            println!("email: {}", summary.email);
                            println!("success: true");
                        }
                    }
                }
                AuthCommand::Revoke => {
                    account_store.revoke()?;
                    match cli.format {
                        Format::Json => println!("{{\"success\":true}}"),
                        Format::Text => println!("success: true"),
                    }
                }
            }
        }
        Command::Search {
            term,
            limit,
            platform,
            country,
        } => {
            let client = CatalogClient::new()?;
            let platform = parse_platform(platform.as_deref())?;
            let output = client.search(&term, &country, limit, platform)?;
            print_search(&output, cli.format)?;
        }
        Command::Lookup {
            app_id,
            bundle_identifier,
            platform,
            country,
        } => {
            let client = CatalogClient::new()?;
            if app_id.is_none() && bundle_identifier.is_none() {
                bail!("an app ID or bundle identifier is required");
            }
            let platform = parse_platform(platform.as_deref())?;
            let app = client.lookup(app_id, bundle_identifier.as_deref(), &country, platform)?;
            print_app(&app, cli.format)?;
        }
        Command::Purchase {
            app_id,
            bundle_identifier,
            platform,
        } => {
            if app_id.is_none_or(|id| id <= 0)
                && bundle_identifier.as_deref().is_none_or(str::is_empty)
            {
                bail!("either the app ID or the bundle identifier must be specified");
            }
            let platform = parse_platform(platform.as_deref())?;
            let account_store = AccountStore::new(open_system_keychain()?);
            let mut account = account_store.load()?;
            let backend = NativePurchaseBackend::open()?;
            let mut refreshed = false;
            loop {
                let app = if let Some(bundle_id) =
                    bundle_identifier.as_deref().filter(|id| !id.is_empty())
                {
                    let country = country_code_from_storefront(&account.store_front)?;
                    CatalogClient::new()?.lookup(None, Some(bundle_id), country, platform)?
                } else {
                    App {
                        id: app_id.context("app ID is required")?,
                        ..App::default()
                    }
                };
                match store_purchase::purchase(&backend, &account, &app, platform) {
                    Ok(()) => {
                        print_purchase_success(false, cli.format)?;
                        break;
                    }
                    Err(error) if error.downcast_ref::<LicenseAlreadyExists>().is_some() => {
                        print_purchase_success(true, cli.format)?;
                        break;
                    }
                    Err(error)
                        if !refreshed && error.downcast_ref::<PasswordTokenExpired>().is_some() =>
                    {
                        let authentication_backend = NativeAuthenticationBackend::open()?;
                        account = store_login::login(
                            &authentication_backend,
                            &account_store,
                            LoginInput {
                                email: account.email.clone(),
                                password: account.password.clone(),
                                auth_code: String::new(),
                            },
                        )?;
                        refreshed = true;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Command::Download {
            app_id,
            bundle_identifier,
            output,
            external_version_id,
            platform,
            purchase,
        } => {
            if app_id.is_none_or(|id| id <= 0)
                && bundle_identifier.as_deref().is_none_or(str::is_empty)
            {
                bail!("either the app ID or the bundle identifier must be specified");
            }
            let platform = Platform::parse(&platform)?.context("platform is required")?;
            let account_store = AccountStore::new(open_system_keychain()?);
            let mut account = account_store.load()?;
            let backend = DownloadProductClient::open()?;
            let catalog = CatalogClient::new()?;
            let mut refreshed = false;
            let mut purchased = false;
            loop {
                let mut app = App {
                    id: app_id.unwrap_or_default(),
                    bundle_id: bundle_identifier.clone().unwrap_or_default(),
                    ..App::default()
                };
                if let Some(bundle_id) = bundle_identifier.as_deref().filter(|id| !id.is_empty()) {
                    let country = country_code_from_storefront(&account.store_front)?;
                    match catalog.lookup(None, Some(bundle_id), country, Some(platform)) {
                        Ok(found) => app = found,
                        Err(error) if app.id <= 0 => return Err(error),
                        Err(_) => {}
                    }
                }
                let result = if platform == Platform::Macos {
                    backend.download_macos(
                        &catalog,
                        &account,
                        &app,
                        &external_version_id,
                        output.as_deref(),
                    )
                } else {
                    backend.download_ipa(
                        &catalog,
                        &account,
                        &app,
                        &external_version_id,
                        platform,
                        output.as_deref(),
                    )
                };
                match result {
                    Ok(path) => {
                        match cli.format {
                            Format::Json => println!(
                                "{}",
                                serde_json::json!({
                                    "output": path, "purchased": purchased, "success": true
                                })
                            ),
                            Format::Text => println!("{}", path.display()),
                        }
                        break;
                    }
                    Err(error)
                        if purchase
                            && !purchased
                            && error.downcast_ref::<LicenseRequired>().is_some() =>
                    {
                        let purchase_backend = NativePurchaseBackend::open()?;
                        match store_purchase::purchase(
                            &purchase_backend,
                            &account,
                            &app,
                            Some(platform),
                        ) {
                            Ok(()) => {}
                            Err(error)
                                if error.downcast_ref::<LicenseAlreadyExists>().is_some() => {}
                            Err(error) => return Err(error),
                        }
                        purchased = true;
                    }
                    Err(error)
                        if !refreshed && error.downcast_ref::<PasswordTokenExpired>().is_some() =>
                    {
                        let authentication_backend = NativeAuthenticationBackend::open()?;
                        account = store_login::login(
                            &authentication_backend,
                            &account_store,
                            LoginInput {
                                email: account.email.clone(),
                                password: account.password.clone(),
                                auth_code: String::new(),
                            },
                        )?;
                        refreshed = true;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Command::ListPurchases {
            page,
            max_results,
            platform,
        } => {
            if page == 0 || max_results == 0 || max_results > MAX_LIMIT {
                bail!("page must be positive and max results must be between 1 and {MAX_LIMIT}");
            }
            let platform = parse_platform(platform.as_deref())?;
            let account_store = AccountStore::new(open_system_keychain()?);
            let mut account = account_store.load()?;
            let backend = NativeOwnedBackend::open()?;
            let mut refreshed = false;
            loop {
                match store_owned::owned_apps(&backend, &account, page, max_results, platform) {
                    Ok(output) => {
                        match cli.format {
                            Format::Json => println!("{}", serde_json::to_string(&output)?),
                            Format::Text => {
                                println!("count: {}", output.count);
                                println!("totalCount: {}", output.total_count);
                                println!("page: {}", output.page);
                                for app in &output.apps {
                                    print_app(app, Format::Text)?;
                                }
                            }
                        }
                        break;
                    }
                    Err(error)
                        if !refreshed && error.downcast_ref::<PasswordTokenExpired>().is_some() =>
                    {
                        let authentication_backend = NativeAuthenticationBackend::open()?;
                        account = store_login::login(
                            &authentication_backend,
                            &account_store,
                            LoginInput {
                                email: account.email.clone(),
                                password: account.password.clone(),
                                auth_code: String::new(),
                            },
                        )?;
                        refreshed = true;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Command::LatestVersionId {
            app_id,
            bundle_identifier,
            platform,
            country,
        } => {
            let client = CatalogClient::new()?;
            let platform = Platform::parse(&platform)?.context("platform is required")?;
            let app = App {
                id: app_id,
                bundle_id: bundle_identifier.unwrap_or_default(),
                ..App::default()
            };
            let id = client.latest_external_version_id(&app, &country, platform)?;
            match cli.format {
                Format::Text => println!("{id}"),
                Format::Json => println!("{}", serde_json::json!({ "externalVersionID": id })),
            }
        }
        Command::ListVersions {
            app_id,
            bundle_identifier,
            platform,
        } => {
            if app_id.is_none_or(|id| id <= 0)
                && bundle_identifier.as_deref().is_none_or(str::is_empty)
            {
                bail!("either the app ID or the bundle identifier must be specified");
            }
            let platform = Platform::parse(&platform)?.context("platform is required")?;
            let account_store = AccountStore::new(open_system_keychain()?);
            let mut account = account_store.load()?;
            let backend = DownloadProductClient::open()?;
            let catalog = CatalogClient::new()?;
            let mut refreshed = false;
            loop {
                let app = if let Some(bundle_id) =
                    bundle_identifier.as_deref().filter(|id| !id.is_empty())
                {
                    let country = country_code_from_storefront(&account.store_front)?;
                    catalog.lookup(None, Some(bundle_id), country, Some(platform))?
                } else {
                    App {
                        id: app_id.context("app ID is required")?,
                        ..App::default()
                    }
                };
                match backend.list_versions(&catalog, &account, &app, platform) {
                    Ok(output) => {
                        match cli.format {
                            Format::Json => println!("{}", serde_json::to_string(&output)?),
                            Format::Text => {
                                println!(
                                    "latestExternalVersionID: {}",
                                    output.latest_external_version_id
                                );
                                for id in output.external_version_identifiers {
                                    println!("{id}");
                                }
                            }
                        }
                        break;
                    }
                    Err(error)
                        if !refreshed && error.downcast_ref::<PasswordTokenExpired>().is_some() =>
                    {
                        let authentication_backend = NativeAuthenticationBackend::open()?;
                        account = store_login::login(
                            &authentication_backend,
                            &account_store,
                            LoginInput {
                                email: account.email.clone(),
                                password: account.password.clone(),
                                auth_code: String::new(),
                            },
                        )?;
                        refreshed = true;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Command::GetVersionMetadata {
            app_id,
            bundle_identifier,
            external_version_id,
            platform,
        } => {
            if app_id.is_none_or(|id| id <= 0)
                && bundle_identifier.as_deref().is_none_or(str::is_empty)
            {
                bail!("either the app ID or the bundle identifier must be specified");
            }
            if external_version_id.is_empty() {
                bail!("an external version ID is required");
            }
            let platform = parse_platform(platform.as_deref())?;
            let account_store = AccountStore::new(open_system_keychain()?);
            let mut account = account_store.load()?;
            let backend = DownloadProductClient::open()?;
            let catalog = CatalogClient::new()?;
            let mut refreshed = false;
            loop {
                let app = if let Some(bundle_id) =
                    bundle_identifier.as_deref().filter(|id| !id.is_empty())
                {
                    let country = country_code_from_storefront(&account.store_front)?;
                    catalog.lookup(None, Some(bundle_id), country, platform)?
                } else {
                    App {
                        id: app_id.context("app ID is required")?,
                        ..App::default()
                    }
                };
                match backend.get_version_metadata(&account, &app, &external_version_id, platform) {
                    Ok(metadata) => {
                        match cli.format {
                            Format::Json => println!("{}", serde_json::to_string(&metadata)?),
                            Format::Text => {
                                println!("displayVersion: {}", metadata.display_version);
                                println!("releaseDate: {}", metadata.release_date);
                            }
                        }
                        break;
                    }
                    Err(error)
                        if !refreshed && error.downcast_ref::<PasswordTokenExpired>().is_some() =>
                    {
                        let authentication_backend = NativeAuthenticationBackend::open()?;
                        account = store_login::login(
                            &authentication_backend,
                            &account_store,
                            LoginInput {
                                email: account.email.clone(),
                                password: account.password.clone(),
                                auth_code: String::new(),
                            },
                        )?;
                        refreshed = true;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Command::FairplayDoctor {
            capture,
            ipa,
            model,
            report,
        } => {
            let output = doctor_fairplay(capture.as_deref(), ipa.as_deref(), model.as_deref());
            if let Some(path) = report.as_deref() {
                write_doctor_report(path, &output)?;
            }
            println!("{}", serde_json::to_string_pretty(&output)?);
            if !output.ready {
                bail!("FairPlay diagnostics are not ready; see errors and next_actions");
            }
        }
    }
    if cli.verbose {
        // Accepted for CLI compatibility. HTTP diagnostics will be added with the transport port.
    }
    Ok(())
}

fn prompt(label: &str, secret: bool) -> Result<String> {
    eprint!("{label}");
    io::stderr().flush().context("write prompt")?;
    #[cfg(unix)]
    let echo = if secret {
        Some(EchoGuard::hide()?)
    } else {
        None
    };
    #[cfg(not(unix))]
    if secret {
        bail!("hidden password prompt is unavailable on this platform; use --password");
    }
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read prompt")?;
    #[cfg(unix)]
    drop(echo);
    if secret {
        eprintln!();
    }
    Ok(input.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(unix)]
struct EchoGuard(libc::termios);

#[cfg(unix)]
impl EchoGuard {
    fn hide() -> Result<Self> {
        // SAFETY: termios is initialized by tcgetattr before it is read.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: stdin is an open terminal in the interactive login path.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return Err(io::Error::last_os_error()).context("read terminal settings");
        }
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        // SAFETY: hidden is a valid termios value from tcgetattr.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
            return Err(io::Error::last_os_error()).context("hide password input");
        }
        Ok(Self(original))
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: this restores the terminal settings captured by tcgetattr.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) };
    }
}

fn parse_platform(value: Option<&str>) -> Result<Option<Platform>> {
    Platform::parse(value.unwrap_or_default())
}

fn print_search(output: &SearchOutput, format: Format) -> Result<()> {
    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string(output).context("failed to encode output")?
        ),
        Format::Text => {
            println!("{} result(s)", output.count);
            for app in &output.apps {
                print_app(app, Format::Text)?;
            }
        }
    }
    Ok(())
}

fn print_app(app: &App, format: Format) -> Result<()> {
    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string(app).context("failed to encode app")?
        ),
        Format::Text => println!(
            "{}\t{}\t{}\t{}",
            app.id, app.name, app.bundle_id, app.version
        ),
    }
    Ok(())
}

fn print_purchase_success(already_owned: bool, format: Format) -> Result<()> {
    match format {
        Format::Json => println!(
            "{}",
            serde_json::json!({ "alreadyOwned": already_owned, "success": true })
        ),
        Format::Text => {
            println!("alreadyOwned: {already_owned}");
            println!("success: true");
        }
    }
    Ok(())
}
