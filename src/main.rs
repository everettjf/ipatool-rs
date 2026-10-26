use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use ipatool_rs::credentials::{AccountStore, open_system_keychain};
use ipatool_rs::fairplay::{SinfSelector, doctor_fairplay, write_doctor_report};
use ipatool_rs::fairplay_checkpoint::FairplayCheckpoint;
use ipatool_rs::fairplay_collect::{EnrollmentCollectOptions, collect_enrollment};
use ipatool_rs::fairplay_download_capture::write_download_capture;
use ipatool_rs::fairplay_enrollment_model::{FIRST_TRANSFORM_BYTES, build_fpsenr2};
use ipatool_rs::fairplay_enrollment_v3::{V3Material, build_fpsenr3};
use ipatool_rs::fairplay_ipa::decrypt_ipa_with_options;
use ipatool_rs::fairplay_key::CurrentSinfModel;
use ipatool_rs::fairplay_oracle_model::OracleModel;
use ipatool_rs::fairplay_portable;
use ipatool_rs::fairplay_recovery;
use ipatool_rs::fairplay_recovery_output::{
    read_private_block, read_private_bytes, read_private_frame, read_private_model,
    write_private_binary, write_private_model,
};
use ipatool_rs::fairplay_recovery_target::SidbTarget;
use ipatool_rs::store_download_product::{DownloadProductClient, LicenseRequired};
use ipatool_rs::store_login::{self, AuthCodeRequired, LoginInput, NativeAuthenticationBackend};
use ipatool_rs::store_owned::{self, DEFAULT_LIMIT, MAX_LIMIT, NativeOwnedBackend};
use ipatool_rs::store_purchase::{
    self, LicenseAlreadyExists, NativePurchaseBackend, PasswordTokenExpired,
};
use ipatool_rs::storefront::country_code_from_storefront;
use ipatool_rs::{App, CatalogClient, Platform, SearchOutput};
use zeroize::Zeroizing;

mod mcp;

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
    /// Serve App Store tools over MCP using stdio.
    Mcp,
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
        #[arg(long)]
        fairplay_decrypt: bool,
        #[arg(long, requires = "fairplay_decrypt")]
        fairplay_model: Option<PathBuf>,
        #[arg(long, requires = "fairplay_decrypt")]
        fairplay_output: Option<PathBuf>,
        #[arg(long, requires = "fairplay_decrypt")]
        fairplay_report: Option<PathBuf>,
        #[arg(long, requires = "fairplay_decrypt")]
        fairplay_force: bool,
        #[arg(long)]
        fairplay_capture_dir: Option<PathBuf>,
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
    /// Decrypt a personalized IPA with a private FairPlay enrollment model.
    FairplayDecrypt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Collect private native FairPlay enrollment material.
    FairplayEnroll {
        #[command(subcommand)]
        command: FairplayEnrollCommand,
    },
}

#[derive(Debug, Subcommand)]
enum FairplayEnrollCommand {
    /// Collect an installed app and matching private FairPlay state.
    Collect {
        #[arg(long)]
        app: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        ipa: Option<PathBuf>,
        #[arg(long)]
        fairplayd: Option<PathBuf>,
        #[arg(long)]
        system_state: Option<PathBuf>,
        #[arg(long)]
        shared_state: Option<PathBuf>,
        #[arg(long)]
        adi_state: Option<PathBuf>,
        #[arg(long = "iomac-file")]
        iomac_file: Option<PathBuf>,
        #[arg(long, default_value = "en0")]
        interface: String,
        #[arg(long)]
        product_version: Option<String>,
        #[arg(long)]
        build_version: Option<String>,
    },
    /// Transform a private 192/224-byte source with the embedded 26A428 state model.
    EvaluateState {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate one transformed 16-byte slot with the embedded 26A428 frame model.
    EvaluateFrame {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        slot: Option<usize>,
    },
    /// Recover an FPSENR2 enrollment model by testing state slots against a private SINF.
    RecoverState {
        #[arg(long, help = "Private 192/224-byte state field at object +0x304")]
        state_source: PathBuf,
        #[arg(long, help = "Private 432-byte input before the first transform")]
        source_block: PathBuf,
        #[arg(long, help = "Private 432-byte output after the first transform")]
        encoded_block: PathBuf,
        #[arg(long)]
        sinf: PathBuf,
        #[arg(long)]
        selector: String,
        #[arg(long)]
        fairplayd_sha256: String,
        #[arg(long)]
        slot: Option<usize>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Recover a private AES model from a frame and embedded or supplied SIDB oracle.
    RecoverOracle {
        #[arg(long)]
        model: Option<PathBuf>,
        #[arg(long)]
        enrollment_frame: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build a private FPSENR2 decoder from a recovered AES model and raw transform blocks.
    BuildModel {
        #[arg(long)]
        recovered_model: PathBuf,
        #[arg(long, help = "Private 432-byte input before the first transform")]
        source_block: PathBuf,
        #[arg(long, help = "Private 432-byte output after the first transform")]
        encoded_block: PathBuf,
        #[arg(long)]
        selector: String,
        #[arg(long)]
        fairplayd_sha256: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build an FPSENR2 decoder directly from private schema-1/2 checkpoints.
    BuildModelV2Checkpoints {
        #[arg(long)]
        recovered_model: PathBuf,
        #[arg(long)]
        source_checkpoint: PathBuf,
        #[arg(long)]
        transformed_checkpoint: PathBuf,
        #[arg(long, help = "Source address; defaults to source checkpoint x23")]
        source_address: Option<String>,
        #[arg(long, help = "Address of the 432-byte transformed output")]
        output_address: String,
        #[arg(long)]
        selector: String,
        #[arg(long, help = "Optional private SINF for end-to-end validation")]
        sinf: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build and validate a private FPSENR3 decoder from three recovered buffers.
    BuildModelV3 {
        #[arg(long)]
        recovered_model: PathBuf,
        #[arg(long, help = "Private 432-byte white-box entry buffer")]
        whitebox_entry: PathBuf,
        #[arg(long, help = "Private 432-byte post-codec entry buffer")]
        postcodec_entry: PathBuf,
        #[arg(long, help = "Private 432-byte post-codec exit buffer")]
        postcodec_exit: PathBuf,
        #[arg(long, help = "Private SINF fixture for end-to-end validation")]
        sinf: PathBuf,
        #[arg(long)]
        selector: String,
        #[arg(long)]
        fairplayd_sha256: String,
        #[arg(long, help = "Absolute source offset within the SINF, e.g. 0x1e0")]
        source_offset: String,
        #[arg(long, default_value = "0x98")]
        final_xor: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build an FPSENR3 decoder directly from three private schema-1/2 checkpoints.
    BuildModelV3Checkpoints {
        #[arg(long)]
        recovered_model: PathBuf,
        #[arg(long)]
        whitebox_checkpoint: PathBuf,
        #[arg(long)]
        postcodec_entry_checkpoint: PathBuf,
        #[arg(long)]
        postcodec_exit_checkpoint: PathBuf,
        #[arg(long, default_value = "0x710000014ee0")]
        buffer_address: String,
        #[arg(long)]
        sinf: PathBuf,
        #[arg(long)]
        selector: String,
        #[arg(long)]
        source_offset: String,
        #[arg(long, default_value = "0x98")]
        final_xor: String,
        #[arg(long)]
        output: PathBuf,
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
        Command::Mcp => mcp::serve()?,
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
            fairplay_decrypt,
            fairplay_model,
            fairplay_output,
            fairplay_report,
            fairplay_force,
            fairplay_capture_dir,
        } => {
            if app_id.is_none_or(|id| id <= 0)
                && bundle_identifier.as_deref().is_none_or(str::is_empty)
            {
                bail!("either the app ID or the bundle identifier must be specified");
            }
            let platform = Platform::parse(&platform)?.context("platform is required")?;
            if fairplay_decrypt && fairplay_model.is_none() {
                bail!("--fairplay-model is required with --fairplay-decrypt");
            }
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
                let mut captured_download = None;
                let result = if platform == Platform::Macos && fairplay_capture_dir.is_some() {
                    match backend.download_macos_ipa_with_capture(
                        &catalog,
                        &account,
                        &app,
                        &external_version_id,
                        output.as_deref(),
                    ) {
                        Ok(download) => {
                            let path = download.path.clone();
                            captured_download = Some(download);
                            Ok(path)
                        }
                        Err(error) => Err(error),
                    }
                } else if platform == Platform::Macos {
                    backend.download_macos(
                        &catalog,
                        &account,
                        &app,
                        &external_version_id,
                        output.as_deref(),
                    )
                } else if fairplay_capture_dir.is_some() {
                    match backend.download_ipa_with_capture(
                        &catalog,
                        &account,
                        &app,
                        &external_version_id,
                        platform,
                        output.as_deref(),
                    ) {
                        Ok(download) => {
                            let path = download.path.clone();
                            captured_download = Some(download);
                            Ok(path)
                        }
                        Err(error) => Err(error),
                    }
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
                        let capture_output =
                            if let Some(directory) = fairplay_capture_dir.as_deref() {
                                let download = captured_download
                                    .as_ref()
                                    .context("missing paired FairPlay download capture")?;
                                Some(write_download_capture(
                                    directory,
                                    download,
                                    &app,
                                    &external_version_id,
                                    platform,
                                )?)
                            } else {
                                None
                            };
                        let decrypted = if fairplay_decrypt {
                            let (decrypted_path, report_path) = fairplay_download_paths(
                                &path,
                                fairplay_output.as_deref(),
                                fairplay_report.as_deref(),
                            )?;
                            decrypt_ipa_with_options(
                                &path,
                                &decrypted_path,
                                fairplay_model.as_deref().expect("validated model"),
                                Some(&report_path),
                                fairplay_force,
                            )?;
                            Some((decrypted_path, report_path))
                        } else {
                            None
                        };
                        match cli.format {
                            Format::Json => {
                                let mut output = serde_json::json!({
                                    "output": path, "purchased": purchased, "success": true
                                });
                                if let Some((decrypted_path, report_path)) = &decrypted {
                                    output["decryptedOutput"] = serde_json::json!(decrypted_path);
                                    output["report"] = serde_json::json!(report_path);
                                }
                                if let Some(capture_output) = &capture_output {
                                    output["fairplayCapture"] = serde_json::json!(capture_output);
                                }
                                println!("{output}");
                            }
                            Format::Text => {
                                println!("{}", path.display());
                                if let Some((decrypted_path, report_path)) = decrypted {
                                    println!("decrypted: {}", decrypted_path.display());
                                    println!("report: {}", report_path.display());
                                }
                                if let Some(capture_output) = capture_output {
                                    println!("fairplay capture: {}", capture_output.display());
                                }
                            }
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
        Command::FairplayDecrypt {
            input,
            model,
            output,
            report,
            force,
        } => {
            if !input
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ipa"))
            {
                bail!("FairPlay input must be an IPA file");
            }
            let output = output.unwrap_or_else(|| input.with_extension("decrypted.ipa"));
            let report = report.unwrap_or_else(|| input.with_extension("decrypted.json"));
            let result = decrypt_ipa_with_options(&input, &output, &model, Some(&report), force)?;
            match cli.format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                Format::Text => println!(
                    "Decrypted {} images ({} pages) to {}; report: {}",
                    result.encrypted_images,
                    result.decrypted_pages,
                    output.display(),
                    report.display()
                ),
            }
        }
        Command::FairplayEnroll { command } => match command {
            FairplayEnrollCommand::Collect {
                app,
                output,
                ipa,
                fairplayd,
                system_state,
                shared_state,
                adi_state,
                iomac_file,
                interface,
                product_version,
                build_version,
            } => {
                let manifest = collect_enrollment(&EnrollmentCollectOptions {
                    app,
                    ipa,
                    output: output.clone(),
                    fairplayd,
                    system_state,
                    shared_state,
                    adi_state,
                    iomac_file,
                    interface,
                    product_version,
                    build_version,
                })?;
                match cli.format {
                    Format::Json => println!("{}", serde_json::to_string_pretty(&manifest)?),
                    Format::Text => println!(
                        "Collected {} private files for selector {} in {}",
                        manifest.files.len(),
                        manifest.app.selector_id,
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::EvaluateState { input, output } => {
                let source = read_private_bytes(&input, 224)?;
                let transformed = fairplay_portable::evaluate_state(&source)?;
                write_private_binary(&output, &transformed)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({ "output": output, "bytes": transformed.len() })
                    ),
                    Format::Text => println!(
                        "Evaluated {} private FairPlay state bytes in {}",
                        source.len(),
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::EvaluateFrame {
                input,
                output,
                slot,
            } => {
                let source = read_private_bytes(&input, 224)?;
                let block: [u8; 16] = if let Some(index) = slot {
                    if !matches!(source.len(), 192 | 224) || index >= source.len() / 16 {
                        bail!("slot index requires a 192/224-byte input and an in-range slot");
                    }
                    source[index * 16..(index + 1) * 16].try_into().unwrap()
                } else {
                    source
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("frame input must be exactly 16 bytes"))?
                };
                let frame = fairplay_portable::evaluate_frame(&block)?;
                write_private_binary(&output, &*frame)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({ "output": output, "bytes": frame.len(), "slot": slot })
                    ),
                    Format::Text => {
                        println!("Evaluated private FairPlay frame in {}", output.display())
                    }
                }
            }
            FairplayEnrollCommand::RecoverState {
                state_source,
                source_block,
                encoded_block,
                sinf,
                selector,
                fairplayd_sha256,
                slot,
                output,
            } => {
                let selector = parse_enrollment_selector(&selector)?;
                let fairplayd_sha256 = parse_sha256(&fairplayd_sha256)?;
                let state_source = read_private_bytes(&state_source, 224)?;
                let source = read_private_block::<FIRST_TRANSFORM_BYTES>(&source_block)?;
                let encoded = read_private_block::<FIRST_TRANSFORM_BYTES>(&encoded_block)?;
                let sinf = read_private_bytes(&sinf, 1024 * 1024)?;
                let enrollment = fairplay_portable::recover_enrollment_from_state(
                    &state_source,
                    &source,
                    &encoded,
                    selector,
                    fairplayd_sha256,
                    &sinf,
                    slot,
                )?;
                write_private_binary(&output, &enrollment.model)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.enrollment-model.v2",
                            "output": output,
                            "selector": selector.identifier(),
                            "slot": enrollment.slot,
                            "bytes": enrollment.model.len(),
                            "recovery_milliseconds": enrollment.recovery_milliseconds,
                        })
                    ),
                    Format::Text => println!(
                        "Recovered private FairPlay enrollment model from slot {} in {}",
                        enrollment.slot,
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::RecoverOracle {
                model,
                enrollment_frame,
                output,
            } => {
                let frame = read_private_frame(&enrollment_frame)?;
                let recovered = if let Some(model) = model {
                    let oracle = OracleModel::load_private(&model)?;
                    let mut target = SidbTarget::new(&oracle, *frame);
                    fairplay_recovery::recover(&mut target)?
                } else {
                    fairplay_portable::recover_sidb(*frame)?
                };
                write_private_model(&output, &recovered)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "darkphoenix.external-encoding-model.v1",
                            "output": output,
                            "milliseconds": recovered.milliseconds,
                        })
                    ),
                    Format::Text => println!(
                        "Recovered private SIDB AES model in {} ({:.1} ms)",
                        output.display(),
                        recovered.milliseconds
                    ),
                }
            }
            FairplayEnrollCommand::BuildModel {
                recovered_model,
                source_block,
                encoded_block,
                selector,
                fairplayd_sha256,
                output,
            } => {
                let recovered = read_private_model(&recovered_model)?;
                let source = read_private_block::<FIRST_TRANSFORM_BYTES>(&source_block)?;
                let encoded = read_private_block::<FIRST_TRANSFORM_BYTES>(&encoded_block)?;
                let selector = parse_enrollment_selector(&selector)?;
                let fairplayd_sha256 = parse_sha256(&fairplayd_sha256)?;
                let model = build_fpsenr2(
                    &recovered,
                    selector,
                    fairplayd_sha256,
                    &source,
                    &encoded,
                    &[],
                )?;
                write_private_binary(&output, &model)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.enrollment-model.v2",
                            "output": output,
                            "selector": selector.identifier(),
                            "bytes": model.len(),
                        })
                    ),
                    Format::Text => println!(
                        "Built private FairPlay enrollment model for {} in {}",
                        selector.identifier(),
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::BuildModelV2Checkpoints {
                recovered_model,
                source_checkpoint,
                transformed_checkpoint,
                source_address,
                output_address,
                selector,
                sinf,
                output,
            } => {
                let recovered = read_private_model(&recovered_model)?;
                let source_checkpoint = FairplayCheckpoint::load_private(&source_checkpoint)?;
                let transformed_checkpoint =
                    FairplayCheckpoint::load_private(&transformed_checkpoint)?;
                if source_checkpoint.binary_hash != transformed_checkpoint.binary_hash {
                    bail!("version-2 checkpoints have different fairplayd builds");
                }
                let source_address = match source_address {
                    Some(address) => parse_address(&address)?,
                    None => source_checkpoint.register_u64("x23")?,
                };
                let source =
                    source_checkpoint.read_block::<FIRST_TRANSFORM_BYTES>(source_address)?;
                let encoded = transformed_checkpoint
                    .read_block::<FIRST_TRANSFORM_BYTES>(parse_address(&output_address)?)?;
                let selector = parse_enrollment_selector(&selector)?;
                let model = build_fpsenr2(
                    &recovered,
                    selector,
                    source_checkpoint.binary_hash,
                    &source,
                    &encoded,
                    &[],
                )?;
                if let Some(sinf) = sinf {
                    let sinf = read_private_bytes(&sinf, 1024 * 1024)?;
                    let _logical =
                        Zeroizing::new(CurrentSinfModel::parse(&model)?.logical_key(&sinf)?);
                }
                write_private_binary(&output, &model)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.enrollment-model.v2",
                            "output": output,
                            "selector": selector.identifier(),
                            "bytes": model.len(),
                        })
                    ),
                    Format::Text => println!(
                        "Built private FairPlay v2 enrollment model from checkpoints in {}",
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::BuildModelV3 {
                recovered_model,
                whitebox_entry,
                postcodec_entry,
                postcodec_exit,
                sinf,
                selector,
                fairplayd_sha256,
                source_offset,
                final_xor,
                output,
            } => {
                let recovered = read_private_model(&recovered_model)?;
                let whitebox_entry = read_private_block::<FIRST_TRANSFORM_BYTES>(&whitebox_entry)?;
                let postcodec_entry =
                    read_private_block::<FIRST_TRANSFORM_BYTES>(&postcodec_entry)?;
                let postcodec_exit = read_private_block::<FIRST_TRANSFORM_BYTES>(&postcodec_exit)?;
                let sinf = read_private_bytes(&sinf, 1024 * 1024)?;
                let selector = parse_enrollment_selector(&selector)?;
                let fairplayd_sha256 = parse_sha256(&fairplayd_sha256)?;
                let source_offset = parse_nonnegative_i32(&source_offset)?;
                let final_xor = parse_byte(&final_xor)?;
                let model = build_fpsenr3(V3Material {
                    recovered: &recovered,
                    selector,
                    fairplayd_sha256,
                    source_offset,
                    final_xor,
                    whitebox_entry: &whitebox_entry,
                    postcodec_entry: &postcodec_entry,
                    postcodec_exit: &postcodec_exit,
                    sinf: &sinf,
                })?;
                write_private_binary(&output, &model)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.enrollment-model.v3",
                            "output": output,
                            "selector": selector.identifier(),
                            "bytes": model.len(),
                        })
                    ),
                    Format::Text => println!(
                        "Built private FairPlay v3 enrollment model for {} in {}",
                        selector.identifier(),
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::BuildModelV3Checkpoints {
                recovered_model,
                whitebox_checkpoint,
                postcodec_entry_checkpoint,
                postcodec_exit_checkpoint,
                buffer_address,
                sinf,
                selector,
                source_offset,
                final_xor,
                output,
            } => {
                let recovered = read_private_model(&recovered_model)?;
                let whitebox = FairplayCheckpoint::load_private(&whitebox_checkpoint)?;
                let post_entry = FairplayCheckpoint::load_private(&postcodec_entry_checkpoint)?;
                let post_exit = FairplayCheckpoint::load_private(&postcodec_exit_checkpoint)?;
                if whitebox.binary_hash != post_entry.binary_hash
                    || whitebox.binary_hash != post_exit.binary_hash
                {
                    bail!("version-3 checkpoints have different fairplayd builds");
                }
                let buffer_address = parse_address(&buffer_address)?;
                let whitebox_entry =
                    whitebox.read_block::<FIRST_TRANSFORM_BYTES>(buffer_address)?;
                let postcodec_entry =
                    post_entry.read_block::<FIRST_TRANSFORM_BYTES>(buffer_address)?;
                let postcodec_exit =
                    post_exit.read_block::<FIRST_TRANSFORM_BYTES>(buffer_address)?;
                let sinf = read_private_bytes(&sinf, 1024 * 1024)?;
                let selector = parse_enrollment_selector(&selector)?;
                let source_offset = parse_nonnegative_i32(&source_offset)?;
                let final_xor = parse_byte(&final_xor)?;
                let model = build_fpsenr3(V3Material {
                    recovered: &recovered,
                    selector,
                    fairplayd_sha256: whitebox.binary_hash,
                    source_offset,
                    final_xor,
                    whitebox_entry: &whitebox_entry,
                    postcodec_entry: &postcodec_entry,
                    postcodec_exit: &postcodec_exit,
                    sinf: &sinf,
                })?;
                write_private_binary(&output, &model)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.enrollment-model.v3",
                            "output": output,
                            "selector": selector.identifier(),
                            "bytes": model.len(),
                        })
                    ),
                    Format::Text => println!(
                        "Built private FairPlay v3 enrollment model from checkpoints in {}",
                        output.display()
                    ),
                }
            }
        },
    }
    if cli.verbose {
        // Accepted for CLI compatibility. HTTP diagnostics will be added with the transport port.
    }
    Ok(())
}

fn parse_enrollment_selector(value: &str) -> Result<SinfSelector> {
    let (user, key) = value
        .split_once(':')
        .context("selector must be eight hex digits:eight hex digits")?;
    if user.len() != 8 || key.len() != 8 {
        bail!("selector must be eight hex digits:eight hex digits");
    }
    Ok(SinfSelector {
        user: u32::from_str_radix(user, 16).context("invalid selector user")?,
        key: u32::from_str_radix(key, 16).context("invalid selector key")?,
    })
}

fn parse_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("fairplayd SHA-256 must be 64 hex digits");
    }
    let mut hash = [0u8; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        let digits = value
            .get(index * 2..index * 2 + 2)
            .context("invalid fairplayd SHA-256")?;
        *byte = u8::from_str_radix(digits, 16).context("invalid fairplayd SHA-256")?;
    }
    Ok(hash)
}

fn parse_nonnegative_i32(value: &str) -> Result<i32> {
    let parsed = u32::try_from(parse_address(value)?)?;
    i32::try_from(parsed).context("SINF source offset exceeds signed 32-bit range")
}

fn parse_address(value: &str) -> Result<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
    }
}

fn parse_byte(value: &str) -> Result<u8> {
    if let Some(hex) = value.strip_prefix("0x") {
        Ok(u8::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse::<u8>()?)
    }
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

fn fairplay_download_paths(
    package: &std::path::Path,
    output: Option<&std::path::Path>,
    report: Option<&std::path::Path>,
) -> Result<(PathBuf, PathBuf)> {
    if !package
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("ipa"))
    {
        bail!("FairPlay post-processing requires an IPA download");
    }
    Ok((
        output
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| package.with_extension("decrypted.ipa")),
        report
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| package.with_extension("decrypted.json")),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fairplay_recover_oracle_accepts_private_input_paths() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-oracle",
            "--model",
            "/private/model.gz",
            "--enrollment-frame",
            "/private/frame.bin",
            "--output",
            "/private/recovered.json",
        ])
        .unwrap();
        match cli.command {
            Command::FairplayEnroll {
                command:
                    FairplayEnrollCommand::RecoverOracle {
                        model,
                        enrollment_frame,
                        output,
                    },
            } => {
                assert_eq!(model, Some(PathBuf::from("/private/model.gz")));
                assert_eq!(enrollment_frame, PathBuf::from("/private/frame.bin"));
                assert_eq!(output, PathBuf::from("/private/recovered.json"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn portable_fairplay_pipeline_accepts_embedded_models() {
        let state = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "evaluate-state",
            "--input",
            "/private/source.bin",
            "--output",
            "/private/slots.bin",
        ])
        .unwrap();
        assert!(matches!(
            state.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::EvaluateState { .. }
            }
        ));
        let frame = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "evaluate-frame",
            "--input",
            "/private/slots.bin",
            "--slot",
            "8",
            "--output",
            "/private/frame.bin",
        ])
        .unwrap();
        assert!(matches!(
            frame.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::EvaluateFrame { slot: Some(8), .. }
            }
        ));
        let recover = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-oracle",
            "--enrollment-frame",
            "/private/frame.bin",
            "--output",
            "/private/recovered.json",
        ])
        .unwrap();
        assert!(matches!(
            recover.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverOracle { model: None, .. }
            }
        ));
    }

    #[test]
    fn recover_state_accepts_capture_material_and_optional_slot() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-state",
            "--state-source",
            "/private/state.bin",
            "--source-block",
            "/private/source.bin",
            "--encoded-block",
            "/private/encoded.bin",
            "--sinf",
            "/private/app.sinf",
            "--selector",
            "12345678:00000009",
            "--fairplayd-sha256",
            "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784",
            "--slot",
            "8",
            "--output",
            "/private/enrollment.bin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverState { slot: Some(8), .. }
            }
        ));
    }

    #[test]
    fn build_model_v3_requires_fixture_and_accepts_hex_geometry() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "build-model-v3",
            "--recovered-model",
            "/private/recovered.json",
            "--whitebox-entry",
            "/private/whitebox.bin",
            "--postcodec-entry",
            "/private/post-entry.bin",
            "--postcodec-exit",
            "/private/post-exit.bin",
            "--sinf",
            "/private/installed.sinf",
            "--selector",
            "0000000b:0000000d",
            "--fairplayd-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--source-offset",
            "0x1e0",
            "--output",
            "/private/enrollment.bin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::BuildModelV3 { .. }
            }
        ));
        assert_eq!(parse_nonnegative_i32("0x1e0").unwrap(), 480);
        assert_eq!(parse_byte("0x98").unwrap(), 0x98);
        assert!(parse_nonnegative_i32("0x80000000").is_err());
        assert!(parse_byte("256").is_err());
    }

    #[test]
    fn build_model_v3_checkpoints_accepts_private_sources() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "build-model-v3-checkpoints",
            "--recovered-model",
            "/private/recovered.json",
            "--whitebox-checkpoint",
            "/private/whitebox.pkl.gz",
            "--postcodec-entry-checkpoint",
            "/private/post-entry.pkl.gz",
            "--postcodec-exit-checkpoint",
            "/private/post-exit.pkl.gz",
            "--sinf",
            "/private/installed.sinf",
            "--selector",
            "0000000b:0000000d",
            "--source-offset",
            "0x1e0",
            "--output",
            "/private/enrollment.bin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::BuildModelV3Checkpoints { .. }
            }
        ));
        assert_eq!(parse_address("0x710000014ee0").unwrap(), 0x7100_0001_4ee0);
    }

    #[test]
    fn build_model_v2_checkpoints_uses_source_register_by_default() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "build-model-v2-checkpoints",
            "--recovered-model",
            "/private/recovered.json",
            "--source-checkpoint",
            "/private/source.pkl.gz",
            "--transformed-checkpoint",
            "/private/transformed.pkl.gz",
            "--output-address",
            "0x710000014ee8",
            "--selector",
            "12345678:00000009",
            "--output",
            "/private/enrollment.bin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::BuildModelV2Checkpoints {
                    source_address: None,
                    sinf: None,
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_build_model_accepts_private_recovery_inputs() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "build-model",
            "--recovered-model",
            "/private/recovered.json",
            "--source-block",
            "/private/source.bin",
            "--encoded-block",
            "/private/encoded.bin",
            "--selector",
            "12345678:00000009",
            "--fairplayd-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--output",
            "/private/enrollment.bin",
        ])
        .unwrap();
        match cli.command {
            Command::FairplayEnroll {
                command:
                    FairplayEnrollCommand::BuildModel {
                        recovered_model,
                        source_block,
                        encoded_block,
                        selector,
                        fairplayd_sha256,
                        output,
                    },
            } => {
                assert_eq!(recovered_model, PathBuf::from("/private/recovered.json"));
                assert_eq!(source_block, PathBuf::from("/private/source.bin"));
                assert_eq!(encoded_block, PathBuf::from("/private/encoded.bin"));
                assert_eq!(output, PathBuf::from("/private/enrollment.bin"));
                assert_eq!(
                    parse_enrollment_selector(&selector).unwrap().identifier(),
                    selector
                );
                assert_eq!(parse_sha256(&fairplayd_sha256).unwrap(), [0xaa; 32]);
            }
            _ => panic!("unexpected command"),
        }
        assert!(parse_enrollment_selector("1234:00000009").is_err());
        assert!(parse_sha256(&"é".repeat(32)).is_err());
    }

    #[test]
    fn fairplay_download_paths_require_ipa_and_default_beside_it() {
        let paths =
            fairplay_download_paths(std::path::Path::new("/tmp/App.IPA"), None, None).unwrap();
        assert_eq!(paths.0, PathBuf::from("/tmp/App.decrypted.ipa"));
        assert_eq!(paths.1, PathBuf::from("/tmp/App.decrypted.json"));
        assert!(fairplay_download_paths(std::path::Path::new("/tmp/App.pkg"), None, None).is_err());
    }

    #[test]
    fn fairplay_download_flags_parse_without_signing_in() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "download",
            "--app-id",
            "123",
            "--fairplay-decrypt",
            "--fairplay-model",
            "/private/model.bin",
            "--fairplay-force",
            "--fairplay-capture-dir",
            "/private/capture",
        ])
        .unwrap();
        match cli.command {
            Command::Download {
                fairplay_decrypt,
                fairplay_model,
                fairplay_force,
                fairplay_capture_dir,
                ..
            } => {
                assert!(fairplay_decrypt);
                assert_eq!(fairplay_model, Some(PathBuf::from("/private/model.bin")));
                assert!(fairplay_force);
                assert_eq!(
                    fairplay_capture_dir,
                    Some(PathBuf::from("/private/capture"))
                );
            }
            _ => panic!("unexpected command"),
        }
    }
}
