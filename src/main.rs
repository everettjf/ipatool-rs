use std::{
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use ipatool_rs::catalog::AppNotFound;
use ipatool_rs::credentials::{
    Account, AccountStore, configure_apple_keychain_ui, configure_file_keychain,
    open_system_keychain,
};
use ipatool_rs::fairplay::{SinfSelector, doctor_fairplay, write_doctor_report};
use ipatool_rs::fairplay_26a428;
use ipatool_rs::fairplay_checkpoint::FairplayCheckpoint;
use ipatool_rs::fairplay_checkpoint_run::{CheckpointRunner, MemoryTraceOptions, VirtualFileStat};
use ipatool_rs::fairplay_collect::{EnrollmentCollectOptions, collect_enrollment};
use ipatool_rs::fairplay_download_capture::write_download_capture;
use ipatool_rs::fairplay_enrollment_model::{FIRST_TRANSFORM_BYTES, build_fpsenr2};
use ipatool_rs::fairplay_enrollment_v3::{V3Material, build_fpsenr3};
use ipatool_rs::fairplay_ipa::{decrypt_ipa_with_options, require_model_diagnostic};
use ipatool_rs::fairplay_key::CurrentSinfModel;
use ipatool_rs::fairplay_oracle_domains::{
    learn_26b118_domains, validate_26a428_model, validate_26b118_model,
};
use ipatool_rs::fairplay_oracle_export::export_checked_model;
use ipatool_rs::fairplay_oracle_model::OracleModel;
use ipatool_rs::fairplay_portable;
use ipatool_rs::fairplay_raw_source::run_kernel;
use ipatool_rs::fairplay_recover_capture::{
    RecoverCaptureOptions, RecoverFromAccountOptions, RecoverFromSinfCopyOptions, recover_capture,
    recover_from_account, recover_from_sinf_copy,
};
use ipatool_rs::fairplay_recovery;
use ipatool_rs::fairplay_recovery_output::{
    read_private_block, read_private_bytes, read_private_frame, read_private_model,
    write_private_binary, write_private_json, write_private_model,
};
use ipatool_rs::fairplay_recovery_target::{OracleJob, OracleTarget, SidbTarget, WhiteboxTarget};
use ipatool_rs::fairplay_startup::seed_request_checkpoint;
use ipatool_rs::store_download_product::{DownloadProductClient, LicenseRequired};
use ipatool_rs::store_login::{self, AuthCodeRequired, LoginInput, NativeAuthenticationBackend};
use ipatool_rs::store_owned::{self, DEFAULT_LIMIT, MAX_LIMIT, NativeOwnedBackend};
use ipatool_rs::store_purchase::{
    self, LicenseAlreadyExists, NativePurchaseBackend, PasswordTokenExpired,
};
use ipatool_rs::storefront::country_code_from_storefront;
use ipatool_rs::{App, CatalogClient, Platform, SearchOutput};
use sha2::{Digest, Sha256};
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
    disable_version_flag = true,
    about = "Rust port of ipatool-fairplay (in progress)"
)]
struct Cli {
    /// Print the ipatool version.
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version, required = false)]
    _version: Option<bool>,
    #[arg(long, global = true, value_enum, default_value_t = Format::Text)]
    format: Format,
    #[arg(long, global = true)]
    verbose: bool,
    /// Disable terminal prompts and Apple Keychain authorization dialogs.
    #[arg(long, global = true)]
    non_interactive: bool,
    /// Passphrase for the encrypted file keychain on Linux or Windows (selects file storage on Linux).
    #[arg(long, global = true)]
    keychain_passphrase: Option<String>,
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
        /// Store country; defaults to US when omitted.
        #[arg(long)]
        country: Option<String>,
    },
    /// Look up an app by numeric ID or bundle identifier.
    Lookup {
        #[arg(long, conflicts_with = "bundle_identifier")]
        app_id: Option<i64>,
        #[arg(long, conflicts_with = "app_id")]
        bundle_identifier: Option<String>,
        #[arg(long)]
        platform: Option<String>,
        /// Store country; defaults to US when omitted.
        #[arg(long)]
        country: Option<String>,
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
        #[arg(long)]
        platform: Option<String>,
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
        #[arg(long)]
        platform: Option<String>,
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
        /// Store country; defaults to US when omitted.
        #[arg(long)]
        country: Option<String>,
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
        model: Option<PathBuf>,
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
    /// Recover and decrypt a 26A428 capture from its private account-entry checkpoint.
    RecoverFromAccount {
        #[arg(long)]
        capture: PathBuf,
        #[arg(long)]
        account_checkpoint: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 600)]
        timeout_seconds: u64,
        #[arg(long)]
        skip_differential: bool,
    },
    /// Recover and decrypt a 26B118 capture from its private SINF-copy checkpoint.
    RecoverFromSinfCopy {
        #[arg(long)]
        capture: PathBuf,
        #[arg(long)]
        sinf_copy_checkpoint: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 600)]
        timeout_seconds: u64,
        #[arg(long)]
        skip_differential: bool,
    },
    /// Recover and decrypt a checked capture with its bundled startup profile.
    #[command(name = "recover", visible_alias = "recover-capture")]
    RecoverCapture {
        #[arg(long)]
        capture: PathBuf,
        #[arg(
            long,
            help = "Exact checked 26A428 arm64e fairplayd for a 26B118 capture"
        )]
        compat_fairplayd: Option<PathBuf>,
        #[arg(long, hide = true, conflicts_with = "compat_fairplayd")]
        native_26b_research: bool,
        #[arg(long)]
        startup_profile: Option<PathBuf>,
        #[arg(long, help = "Private verified 0x228-byte IOKit selector 0x15 output")]
        iokit15_output: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 600)]
        timeout_seconds: u64,
        #[arg(long)]
        skip_differential: bool,
    },
    /// Seed the first private request checkpoint from a matching fairplayd startup profile.
    SeedRequestCheckpoint {
        #[arg(long)]
        startup_profile: PathBuf,
        #[arg(long)]
        fairplayd: PathBuf,
        #[arg(long)]
        executable_path: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Resume a matching private FairPlay checkpoint for a bounded instruction span.
    ContinueCheckpoint {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        fairplayd: PathBuf,
        #[arg(
            long,
            help = "Write a private checkpoint after reaching the stop address"
        )]
        output_checkpoint: Option<PathBuf>,
        #[arg(long, help = "Instruction address at which to stop")]
        stop_address: Option<String>,
        #[arg(
            long,
            value_name = "START:SIZE",
            help = "Stop when a guest read overlaps this range"
        )]
        stop_memory_read_range: Option<String>,
        #[arg(long, default_value_t = 1, help = "Stop on this visit to the address")]
        stop_hit: usize,
        #[arg(long, default_value_t = 100_000)]
        instruction_limit: usize,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        #[arg(
            long,
            help = "Write bounded guest memory read/write events as private JSON"
        )]
        memory_trace_output: Option<PathBuf>,
        #[arg(long, help = "Trace only reads when paired with memory trace output")]
        trace_memory_reads: bool,
        #[arg(long, help = "Trace only writes when paired with memory trace output")]
        trace_memory_writes: bool,
        #[arg(long, default_value_t = 1_000_000)]
        max_memory_events: usize,
        #[arg(long = "file-payload", value_name = "SUFFIX=PATH")]
        file_payloads: Vec<String>,
        #[arg(long = "file-stat", value_name = "SUFFIX=MODE,UID,GID")]
        file_stats: Vec<String>,
        #[arg(long)]
        missing_files_are_enoent: bool,
        #[arg(long)]
        mac_address_file: Option<PathBuf>,
        #[arg(long)]
        iokit15_output: Option<PathBuf>,
        #[arg(long = "preserve-text-instruction", value_name = "ADDRESS")]
        preserve_text_instructions: Vec<String>,
    },
    /// Export a private 26A428 or 26B118 oracle model from a checkpoint and memory trace.
    ExportOracleModel {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        fairplayd: PathBuf,
        #[arg(long)]
        memory_trace: PathBuf,
        #[arg(
            long,
            help = "Private 26B118 JSON containing all learned index domains"
        )]
        index_domains: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Learn all 26B118 indexed-fault domains by replaying a private checkpoint.
    LearnIndexDomains {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        fairplayd: PathBuf,
        #[arg(long, default_value_t = 20_000)]
        max_inputs: usize,
        #[arg(long, default_value_t = 2)]
        timeout_seconds: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Differentially validate a private 26A428 or 26B118 model against checkpoint execution.
    ValidateOracleModel {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        fairplayd: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(long, default_value_t = 2)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 16)]
        normal_cases: usize,
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
    /// Evaluate one private 16-byte block with a checked 26A428 or 26B118 oracle model.
    EvaluateWhitebox {
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(
            long,
            default_value = "0xffff",
            help = "Fault metadata; 0xffff disables faults"
        )]
        metadata: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Run a checked 26A428 raw source kernel from a private model.
    RawSource {
        #[arg(long)]
        model: PathBuf,
        #[arg(long, value_parser = ["writer", "tail", "even", "odd", "digest", "cycle", "outer-primary", "outer"])]
        kernel: String,
        #[arg(long = "loop")]
        loop_mode: bool,
        #[arg(long, default_value_t = 0)]
        iterations: usize,
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        output_bytes: Option<usize>,
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
    /// Recover a 26A428 FPSENR2 model from private state and transform checkpoints.
    RecoverStateCheckpoints {
        #[arg(long, help = "Checkpoint containing the state source at object +0x304")]
        state_checkpoint: PathBuf,
        #[arg(long)]
        source_checkpoint: PathBuf,
        #[arg(long)]
        transformed_checkpoint: PathBuf,
        #[arg(long, default_value = "0x7000000fb304")]
        state_address: String,
        #[arg(
            long,
            default_value_t = 224,
            help = "State source size: 192 or 224 bytes"
        )]
        state_bytes: usize,
        #[arg(long, help = "Source address; defaults to source checkpoint x23")]
        source_address: Option<String>,
        #[arg(long, default_value = "0x710000014ee8")]
        output_address: String,
        #[arg(long)]
        sinf: PathBuf,
        #[arg(long)]
        selector: String,
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
    /// Recover a 26A428 or 26B118 AES model from a private white-box oracle model.
    RecoverWhitebox {
        #[arg(long)]
        model: PathBuf,
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

fn read_fairplayd_binary(path: &Path) -> Result<Vec<u8>> {
    const MAX_FAIRPLAYD_BYTES: u64 = 256 * 1024 * 1024;
    let file = File::open(path).with_context(|| format!("open fairplayd {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FAIRPLAYD_BYTES {
        bail!("fairplayd has invalid file type or size");
    }
    let mut binary = Vec::new();
    file.take(MAX_FAIRPLAYD_BYTES + 1)
        .read_to_end(&mut binary)
        .context("read fairplayd image")?;
    if binary.len() as u64 > MAX_FAIRPLAYD_BYTES {
        bail!("fairplayd exceeds size limit");
    }
    Ok(binary)
}

fn run() -> Result<()> {
    let mut cli = Cli::parse();
    ipatool_rs::transport::set_verbose(cli.verbose);
    ipatool_rs::download_file::set_progress(
        matches!(&cli.command, Command::Download { .. })
            && !cli.non_interactive
            && matches!(cli.format, Format::Text)
            && io::stderr().is_terminal(),
    );
    configure_file_keychain(
        cli.keychain_passphrase.take(),
        !cli.non_interactive && io::stdin().is_terminal(),
    );
    configure_apple_keychain_ui(
        !cli.non_interactive && !matches!(&cli.command, Command::Mcp) && io::stdin().is_terminal(),
    );
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
                    const PREPARING: &str =
                        "preparing authentication; the first login may take a few minutes";
                    match cli.format {
                        Format::Json => println!(
                            "{}",
                            serde_json::json!({ "level": "info", "message": PREPARING })
                        ),
                        Format::Text => println!("{PREPARING}"),
                    }
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
                                if !interactive {
                                    const MESSAGE: &str = "2FA code is required; run the command again and supply a code using the `--auth-code` flag";
                                    match cli.format {
                                        Format::Json => println!(
                                            "{}",
                                            serde_json::json!({ "level": "info", "message": MESSAGE })
                                        ),
                                        Format::Text => println!("{MESSAGE}"),
                                    }
                                    return Ok(());
                                }
                                if code_prompts == 1 {
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
            let country = catalog_country(country.as_deref());
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
            let country = catalog_country(country.as_deref());
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
            let requested_platform = parse_platform(platform.as_deref())?;
            let platform = requested_platform.unwrap_or(Platform::Iphone);
            let account_store = AccountStore::new(open_system_keychain()?);
            let mut account = account_store.load()?;
            let backend = DownloadProductClient::open()?;
            let catalog = CatalogClient::new()?;
            let ((app, path, captured_download), purchased) = retry_download(
                &mut account,
                purchase,
                |account| {
                    let authentication_backend = NativeAuthenticationBackend::open()?;
                    store_login::login(
                        &authentication_backend,
                        &account_store,
                        LoginInput {
                            email: account.email.clone(),
                            password: account.password.clone(),
                            auth_code: String::new(),
                        },
                    )
                },
                |account, purchase_required, purchased| {
                    let mut app = App {
                        id: app_id.unwrap_or_default(),
                        bundle_id: bundle_identifier.clone().unwrap_or_default(),
                        ..App::default()
                    };
                    if let Some(bundle_id) =
                        bundle_identifier.as_deref().filter(|id| !id.is_empty())
                    {
                        let country = country_code_from_storefront(&account.store_front)?;
                        match catalog.lookup(None, Some(bundle_id), country, requested_platform) {
                            Ok(found) => app = found,
                            Err(error)
                                if app.id > 0 && error.downcast_ref::<AppNotFound>().is_some() => {}
                            Err(error) => return Err(error),
                        }
                    }
                    if *purchase_required {
                        let purchase_backend = NativePurchaseBackend::open()?;
                        match store_purchase::purchase(
                            &purchase_backend,
                            account,
                            &app,
                            requested_platform,
                        ) {
                            Ok(()) => {}
                            Err(error)
                                if error.downcast_ref::<LicenseAlreadyExists>().is_some() => {}
                            Err(error) => return Err(error),
                        }
                        *purchase_required = false;
                        *purchased = true;
                    }
                    let mut captured_download = None;
                    let result = if platform == Platform::Macos && fairplay_capture_dir.is_some() {
                        match backend.download_macos_ipa_with_capture(
                            &catalog,
                            account,
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
                            account,
                            &app,
                            &external_version_id,
                            output.as_deref(),
                        )
                    } else if fairplay_capture_dir.is_some() {
                        match backend.download_ipa_with_capture(
                            &catalog,
                            account,
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
                            account,
                            &app,
                            &external_version_id,
                            platform,
                            output.as_deref(),
                        )
                    };
                    result.map(|path| (app, path, captured_download))
                },
            )?;
            {
                let capture_output = if let Some(directory) = fairplay_capture_dir.as_deref() {
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
                    let model = match fairplay_model.as_deref() {
                        Some(model) => model,
                        None => bail!("{}", require_model_diagnostic(&path)?),
                    };
                    let (decrypted_path, report_path) = fairplay_download_paths(
                        &path,
                        fairplay_output.as_deref(),
                        fairplay_report.as_deref(),
                    )?;
                    decrypt_ipa_with_options(
                        &path,
                        &decrypted_path,
                        model,
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
            let country = catalog_country(country.as_deref());
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
            let requested_platform = parse_platform(platform.as_deref())?;
            let platform = requested_platform.unwrap_or(Platform::Iphone);
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
                    catalog.lookup(None, Some(bundle_id), country, requested_platform)?
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
            let model = match model.as_deref() {
                Some(model) => model,
                None => bail!("{}", require_model_diagnostic(&input)?),
            };
            let output = output.unwrap_or_else(|| input.with_extension("decrypted.ipa"));
            let report = report.unwrap_or_else(|| input.with_extension("decrypted.json"));
            let result = decrypt_ipa_with_options(&input, &output, model, Some(&report), force)?;
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
            FairplayEnrollCommand::RecoverFromAccount {
                capture,
                account_checkpoint,
                output,
                timeout_seconds,
                skip_differential,
            } => {
                let result = recover_from_account(RecoverFromAccountOptions {
                    capture: &capture,
                    account_checkpoint: &account_checkpoint,
                    output: &output,
                    timeout: Duration::from_secs(timeout_seconds),
                    skip_differential,
                })?;
                match cli.format {
                    Format::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                    Format::Text => println!(
                        "Recovered FairPlay enrollment for {} and decrypted IPA to {}",
                        result.selector,
                        result.decrypted_ipa.display()
                    ),
                }
            }
            FairplayEnrollCommand::RecoverFromSinfCopy {
                capture,
                sinf_copy_checkpoint,
                output,
                timeout_seconds,
                skip_differential,
            } => {
                let result = recover_from_sinf_copy(RecoverFromSinfCopyOptions {
                    capture: &capture,
                    sinf_copy_checkpoint: &sinf_copy_checkpoint,
                    output: &output,
                    timeout: Duration::from_secs(timeout_seconds),
                    skip_differential,
                })?;
                match cli.format {
                    Format::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                    Format::Text => println!(
                        "Recovered FairPlay enrollment for {} and decrypted IPA to {}",
                        result.selector,
                        result.decrypted_ipa.display()
                    ),
                }
            }
            FairplayEnrollCommand::RecoverCapture {
                capture,
                compat_fairplayd,
                native_26b_research,
                startup_profile,
                iokit15_output,
                output,
                timeout_seconds,
                skip_differential,
            } => {
                let result = recover_capture(RecoverCaptureOptions {
                    capture: &capture,
                    compat_fairplayd: compat_fairplayd.as_deref(),
                    native_26b_research,
                    startup_profile: startup_profile.as_deref(),
                    iokit15_output: iokit15_output.as_deref(),
                    output: &output,
                    timeout: Duration::from_secs(timeout_seconds),
                    skip_differential,
                })?;
                match cli.format {
                    Format::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                    Format::Text => println!(
                        "Recovered FairPlay enrollment for {} and decrypted IPA to {}",
                        result.selector,
                        result.decrypted_ipa.display()
                    ),
                }
            }
            FairplayEnrollCommand::SeedRequestCheckpoint {
                startup_profile,
                fairplayd,
                executable_path,
                output,
            } => {
                let plain_bytes = seed_request_checkpoint(
                    &startup_profile,
                    &fairplayd,
                    &executable_path,
                    &output,
                )?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.request-checkpoint.v1",
                            "output": output,
                            "plain_bytes": plain_bytes,
                        })
                    ),
                    Format::Text => println!(
                        "Seeded private FairPlay request checkpoint in {}",
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::ContinueCheckpoint {
                checkpoint,
                fairplayd,
                output_checkpoint,
                stop_address,
                stop_memory_read_range,
                stop_hit,
                instruction_limit,
                timeout_seconds,
                memory_trace_output,
                trace_memory_reads,
                trace_memory_writes,
                max_memory_events,
                file_payloads,
                file_stats,
                missing_files_are_enoent,
                mac_address_file,
                iokit15_output,
                preserve_text_instructions,
            } => {
                if timeout_seconds == 0 || timeout_seconds > 3600 {
                    bail!("FairPlay timeout must be between 1 and 3600 seconds");
                }
                let stop = stop_address.as_deref().map(parse_address).transpose()?;
                let read_range = stop_memory_read_range
                    .as_deref()
                    .map(|specification| {
                        let (start, size) = specification
                            .split_once(':')
                            .context("--stop-memory-read-range requires START:SIZE")?;
                        Ok::<_, anyhow::Error>((parse_address(start)?, parse_address(size)?))
                    })
                    .transpose()?;
                if stop.is_some() == read_range.is_some() {
                    bail!("choose exactly one of --stop-address or --stop-memory-read-range");
                }
                if read_range.is_some() && stop_hit != 1 {
                    bail!("--stop-hit requires --stop-address");
                }
                if read_range.is_some() && memory_trace_output.is_some() {
                    bail!("memory tracing currently requires --stop-address");
                }
                let binary = read_fairplayd_binary(&fairplayd)?;
                let snapshot = FairplayCheckpoint::load_private(&checkpoint)?;
                let binary_sha256 = format!("{:x}", Sha256::digest(&binary));
                let preserved_text = preserve_text_instructions
                    .iter()
                    .map(|address| parse_address(address))
                    .collect::<Result<Vec<_>>>()?;
                let mut runner =
                    CheckpointRunner::new_preserving_text(&snapshot, &binary, &preserved_text)?;
                if let Some(path) = mac_address_file {
                    let input = read_private_bytes(&path, 64)?;
                    runner.set_mac_address(parse_private_mac(&input)?);
                }
                if let Some(path) = iokit15_output {
                    runner.set_iokit15_output(read_private_bytes(&path, 1024 * 1024)?)?;
                }
                runner.set_missing_files_are_enoent(missing_files_are_enoent);
                for specification in file_payloads {
                    let (suffix, path) = specification
                        .split_once('=')
                        .context("--file-payload requires SUFFIX=PATH")?;
                    if suffix.is_empty() || path.is_empty() {
                        bail!("--file-payload requires nonempty SUFFIX and PATH");
                    }
                    let data = read_private_bytes(&PathBuf::from(path), 128 * 1024 * 1024)?;
                    runner.add_file_payload(suffix, data)?;
                }
                for specification in file_stats {
                    let (suffix, fields) = specification
                        .split_once('=')
                        .context("--file-stat requires SUFFIX=MODE,UID,GID")?;
                    let parts = fields.split(',').collect::<Vec<_>>();
                    if suffix.is_empty() || parts.len() != 3 {
                        bail!("--file-stat requires SUFFIX=MODE,UID,GID");
                    }
                    runner.add_file_stat(
                        suffix,
                        VirtualFileStat {
                            mode: u16::try_from(parse_address(parts[0])?)?,
                            uid: u32::try_from(parse_address(parts[1])?)?,
                            gid: u32::try_from(parse_address(parts[2])?)?,
                        },
                    )?;
                }
                if memory_trace_output.is_none() && (trace_memory_reads || trace_memory_writes) {
                    bail!("memory trace flags require --memory-trace-output");
                }
                let (trace, read_stop) = if memory_trace_output.is_some() {
                    let stop = stop.context("memory tracing requires --stop-address")?;
                    let trace_both = !trace_memory_reads && !trace_memory_writes;
                    (
                        Some(runner.run_until_hit_with_memory_trace(
                            stop,
                            stop_hit,
                            Duration::from_secs(timeout_seconds),
                            instruction_limit,
                            MemoryTraceOptions {
                                reads: trace_memory_reads || trace_both,
                                writes: trace_memory_writes || trace_both,
                                max_events: max_memory_events,
                            },
                        )?),
                        None,
                    )
                } else if let Some(stop) = stop {
                    runner.run_until_hit(
                        stop,
                        stop_hit,
                        Duration::from_secs(timeout_seconds),
                        instruction_limit,
                    )?;
                    (None, None)
                } else {
                    let (start, size) = read_range.context("missing memory-read stop range")?;
                    let stopped = runner.run_until_memory_read_range(
                        start,
                        size,
                        Duration::from_secs(timeout_seconds),
                        instruction_limit,
                    )?;
                    (None, Some(stopped))
                };
                let stop_pc = runner
                    .engine
                    .reg_read(ipatool_rs::unicorn_runtime::REG_PC)?;
                let written_pages = output_checkpoint
                    .as_ref()
                    .map(|output| runner.write_checkpoint(&snapshot, &fairplayd, output))
                    .transpose()?;
                if let (Some(output), Some(trace)) = (&memory_trace_output, trace) {
                    let report = serde_json::json!({
                        "schema": "fairplay.checkpoint-memory-trace.v1",
                        "binary_sha256": binary_sha256,
                        "start_pc": format!("{:#x}", runner.start_pc),
                        "stop_pc": format!("{stop_pc:#x}"),
                        "stop_hit": stop_hit,
                        "memory_read_events": trace.memory_read_events,
                        "memory_write_events": trace.memory_write_events,
                    });
                    write_private_binary(output, &serde_json::to_vec_pretty(&report)?)?;
                }
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.checkpoint-run.v1",
                            "start_pc": format!("{:#x}", runner.start_pc),
                            "stop_pc": format!("{stop_pc:#x}"),
                            "stop_hit": stop.map(|_| stop_hit),
                            "stop_memory_read_range": stop_memory_read_range,
                            "memory_read_stop": read_stop.map(|hit| serde_json::json!({
                                "pc": format!("{:#x}", hit.pc),
                                "address": format!("{:#x}", hit.address),
                                "size": hit.size,
                            })),
                            "checkpoint_pages": runner.checkpoint_pages,
                            "fairplayd_fixups": runner.image.fixups,
                            "external_imports": runner.image.externals.len(),
                            "modeled_imports": runner.modeled_imports,
                            "compatibility_instruction_sites": runner.compatibility_instruction_sites,
                            "preserved_text_instruction_sites": runner.preserved_text_instruction_sites,
                            "output_checkpoint": output_checkpoint,
                            "output_pages": written_pages,
                            "memory_trace_output": memory_trace_output,
                        })
                    ),
                    Format::Text => {
                        println!(
                            "Resumed FairPlay checkpoint from {:#x} to {stop_pc:#x}",
                            runner.start_pc
                        );
                        if let Some(hit) = read_stop {
                            println!(
                                "Stopped on guest read at {:#x} ({} bytes)",
                                hit.address, hit.size
                            );
                        }
                        if let Some(path) = output_checkpoint {
                            println!("Saved private checkpoint to {}", path.display());
                        }
                    }
                }
            }
            FairplayEnrollCommand::ExportOracleModel {
                checkpoint,
                fairplayd,
                memory_trace,
                index_domains,
                output,
            } => {
                let binary = read_fairplayd_binary(&fairplayd)?;
                let snapshot = FairplayCheckpoint::load_private(&checkpoint)?;
                let model = export_checked_model(
                    &snapshot,
                    &binary,
                    &memory_trace,
                    index_domains.as_deref(),
                )?;
                write_private_binary(&output, &model.compressed)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.oracle-export.v1",
                            "model": output,
                            "pages": model.pages,
                            "domains": model.domains,
                            "binary_sha256": format!("{:x}", Sha256::digest(&binary)),
                        })
                    ),
                    Format::Text => println!(
                        "Exported private FairPlay oracle model with {} pages to {}",
                        model.pages,
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::LearnIndexDomains {
                checkpoint,
                fairplayd,
                max_inputs,
                timeout_seconds,
                output,
            } => {
                if !(1..=30).contains(&timeout_seconds) {
                    bail!("index-domain replay timeout must be between 1 and 30 seconds");
                }
                let binary = read_fairplayd_binary(&fairplayd)?;
                let snapshot = FairplayCheckpoint::load_private(&checkpoint)?;
                let result = learn_26b118_domains(
                    &snapshot,
                    &binary,
                    max_inputs,
                    Duration::from_secs(timeout_seconds),
                )?;
                write_private_binary(&output, &result.json)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.index-domains-export.v1",
                            "output": output,
                            "inputs": result.inputs,
                            "domains": result.domains,
                        })
                    ),
                    Format::Text => println!(
                        "Learned {} private FairPlay index domains from {} inputs in {}",
                        result.domains,
                        result.inputs,
                        output.display()
                    ),
                }
            }
            FairplayEnrollCommand::ValidateOracleModel {
                checkpoint,
                fairplayd,
                model,
                timeout_seconds,
                normal_cases,
            } => {
                if !(1..=30).contains(&timeout_seconds) {
                    bail!("oracle validation timeout must be between 1 and 30 seconds");
                }
                let binary = read_fairplayd_binary(&fairplayd)?;
                let snapshot = FairplayCheckpoint::load_private(&checkpoint)?;
                let model = OracleModel::load_private(&model)?;
                let (build, result) = if model.block_address == fairplay_26a428::BLOCK_ADDRESS {
                    (
                        "26A428",
                        validate_26a428_model(
                            &snapshot,
                            &binary,
                            &model,
                            Duration::from_secs(timeout_seconds),
                            normal_cases,
                        )?,
                    )
                } else {
                    (
                        "26B118",
                        validate_26b118_model(
                            &snapshot,
                            &binary,
                            &model,
                            Duration::from_secs(timeout_seconds),
                            normal_cases,
                        )?,
                    )
                };
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "schema": "fairplay.oracle-differential.v1",
                            "cases": result.cases,
                            "matches": result.cases,
                            "mismatches": 0,
                            "domains": result.domains,
                            "build": build,
                            "output_sha256": result.output_sha256,
                        })
                    ),
                    Format::Text => println!(
                        "Validated {} native {} FairPlay cases against Rust ({} domains)",
                        result.cases, build, result.domains
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
            FairplayEnrollCommand::EvaluateWhitebox {
                model,
                input,
                metadata,
                output,
            } => {
                let model = OracleModel::load_private(&model)?;
                let input = read_private_block::<16>(&input)?;
                let metadata = u32::try_from(parse_address(&metadata)?)
                    .context("white-box fault metadata exceeds 32 bits")?;
                let mut target = WhiteboxTarget::new(&model)?;
                let result = target.evaluate_jobs(&[OracleJob {
                    block: *input,
                    metadata,
                }])?[0];
                write_private_binary(&output, &result)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "output": output,
                            "bytes": result.len(),
                            "metadata": format!("{metadata:#x}"),
                        })
                    ),
                    Format::Text => {
                        println!("Evaluated private white-box block in {}", output.display())
                    }
                }
            }
            FairplayEnrollCommand::RawSource {
                model,
                kernel,
                loop_mode,
                iterations,
                report,
                output,
                output_bytes,
            } => {
                if output.is_some() != output_bytes.is_some() {
                    bail!("--output and --output-bytes must be supplied together");
                }
                let model = OracleModel::load_private(&model)?;
                let result = run_kernel(
                    &model,
                    &kernel,
                    loop_mode,
                    iterations,
                    report.is_some(),
                    output_bytes,
                )?;
                if let (Some(path), Some(value)) = (&report, &result.report) {
                    write_private_json(path, value)?;
                }
                if let (Some(path), Some(value)) = (&output, &result.output) {
                    write_private_binary(path, value)?;
                }
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "kernel": kernel,
                            "iterations": result.iterations,
                            "state_sha256": result.state_sha256,
                            "report": report,
                            "output": output,
                            "output_bytes": output_bytes,
                        })
                    ),
                    Format::Text => println!(
                        "FairPlay raw source {}: {} iteration(s), state SHA-256 {}",
                        kernel, result.iterations, result.state_sha256
                    ),
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
            FairplayEnrollCommand::RecoverStateCheckpoints {
                state_checkpoint,
                source_checkpoint,
                transformed_checkpoint,
                state_address,
                state_bytes,
                source_address,
                output_address,
                sinf,
                selector,
                slot,
                output,
            } => {
                if !matches!(state_bytes, 192 | 224) {
                    bail!("state source size must be 192 or 224 bytes");
                }
                let state_checkpoint = FairplayCheckpoint::load_private(&state_checkpoint)?;
                let source_checkpoint = FairplayCheckpoint::load_private(&source_checkpoint)?;
                let transformed_checkpoint =
                    FairplayCheckpoint::load_private(&transformed_checkpoint)?;
                if state_checkpoint.binary_hash != source_checkpoint.binary_hash
                    || source_checkpoint.binary_hash != transformed_checkpoint.binary_hash
                {
                    bail!("state and transform checkpoints have different fairplayd builds");
                }
                let state_address = parse_address(&state_address)?;
                let state_source = match state_bytes {
                    192 => {
                        Zeroizing::new(state_checkpoint.read_block::<192>(state_address)?.to_vec())
                    }
                    224 => {
                        Zeroizing::new(state_checkpoint.read_block::<224>(state_address)?.to_vec())
                    }
                    _ => unreachable!("validated state source size"),
                };
                let source_address = match source_address {
                    Some(address) => parse_address(&address)?,
                    None => source_checkpoint.register_u64("x23")?,
                };
                let source =
                    source_checkpoint.read_block::<FIRST_TRANSFORM_BYTES>(source_address)?;
                let encoded = transformed_checkpoint
                    .read_block::<FIRST_TRANSFORM_BYTES>(parse_address(&output_address)?)?;
                let selector = parse_enrollment_selector(&selector)?;
                let sinf = read_private_bytes(&sinf, 1024 * 1024)?;
                let enrollment = fairplay_portable::recover_enrollment_from_state(
                    &state_source,
                    &source,
                    &encoded,
                    selector,
                    state_checkpoint.binary_hash,
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
                            "state_bytes": state_bytes,
                            "bytes": enrollment.model.len(),
                            "recovery_milliseconds": enrollment.recovery_milliseconds,
                        })
                    ),
                    Format::Text => println!(
                        "Recovered private FairPlay enrollment model from checkpoints, slot {} in {}",
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
            FairplayEnrollCommand::RecoverWhitebox { model, output } => {
                let oracle = OracleModel::load_private(&model)?;
                let mut target = WhiteboxTarget::new(&oracle)?;
                let recovered = fairplay_recovery::recover(&mut target)?;
                write_private_model(&output, &recovered)?;
                match cli.format {
                    Format::Json => println!(
                        "{}",
                        serde_json::json!({
                            "output": output,
                            "recovery_milliseconds": recovered.milliseconds,
                        })
                    ),
                    Format::Text => println!(
                        "Recovered private white-box AES model in {}",
                        output.display()
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
    } else if let Some(octal) = value.strip_prefix("0o") {
        Ok(u64::from_str_radix(octal, 8)?)
    } else {
        Ok(value.parse()?)
    }
}

fn parse_private_mac(input: &[u8]) -> Result<[u8; 6]> {
    if input.len() == 6 {
        return Ok(input.try_into()?);
    }
    let text = std::str::from_utf8(input)
        .context("MAC address file must contain six raw bytes or hexadecimal text")?;
    let digits = text
        .trim()
        .bytes()
        .filter(|byte| !matches!(byte, b':' | b'-'))
        .collect::<Vec<_>>();
    if digits.len() != 12 || !digits.iter().all(u8::is_ascii_hexdigit) {
        bail!("MAC address file must contain six raw bytes or twelve hexadecimal digits");
    }
    let mut address = [0u8; 6];
    for (index, byte) in address.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&digits[index * 2..index * 2 + 2])?;
        *byte = u8::from_str_radix(pair, 16)?;
    }
    Ok(address)
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
    #[cfg(any(unix, windows))]
    let echo = if secret {
        Some(EchoGuard::hide()?)
    } else {
        None
    };
    #[cfg(not(any(unix, windows)))]
    if secret {
        bail!("hidden password prompt is unavailable on this platform; use --password");
    }
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read prompt")?;
    #[cfg(any(unix, windows))]
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

#[cfg(windows)]
struct EchoGuard(windows_sys::Win32::Foundation::HANDLE, u32);

#[cfg(windows)]
impl EchoGuard {
    fn hide() -> Result<Self> {
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            System::Console::{
                ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
            },
        };

        // SAFETY: the process owns its standard input handle; GetConsoleMode writes one u32.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            bail!("input console is unavailable; use --password");
        }
        let mut mode = 0;
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return Err(io::Error::last_os_error()).context("read console settings");
        }
        if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
            return Err(io::Error::last_os_error()).context("hide password input");
        }
        Ok(Self(handle, mode))
    }
}

#[cfg(windows)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleMode;
        // SAFETY: this restores the original settings of the same input console.
        unsafe { SetConsoleMode(self.0, self.1) };
    }
}

fn parse_platform(value: Option<&str>) -> Result<Option<Platform>> {
    Platform::parse(value.unwrap_or_default())
}

fn catalog_country(explicit: Option<&str>) -> String {
    explicit.unwrap_or("US").to_owned()
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

fn retry_download<T>(
    account: &mut Account,
    acquire_license: bool,
    mut refresh: impl FnMut(&Account) -> Result<Account>,
    mut attempt: impl FnMut(&Account, &mut bool, &mut bool) -> Result<T>,
) -> Result<(T, bool)> {
    let mut purchase_required = false;
    let mut purchased = false;
    let mut token_expired = false;
    for attempt_index in 0..3 {
        let result = (|| {
            if token_expired {
                *account = refresh(account)?;
            }
            attempt(account, &mut purchase_required, &mut purchased)
        })();
        match result {
            Ok(output) => return Ok((output, purchased)),
            Err(error) if attempt_index < 2 => {
                if error.downcast_ref::<PasswordTokenExpired>().is_some() {
                    token_expired = true;
                } else if acquire_license && error.downcast_ref::<LicenseRequired>().is_some() {
                    purchase_required = true;
                    token_expired = false;
                } else {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("download retry loop always returns on its final attempt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_version_flag_does_not_make_other_commands_require_it() {
        let version = Cli::try_parse_from(["ipatool", "-v"]).unwrap_err();
        assert_eq!(version.kind(), clap::error::ErrorKind::DisplayVersion);
        Cli::try_parse_from(["ipatool", "mcp"]).unwrap();
    }

    #[test]
    fn download_reauthenticates_twice_within_three_attempts() {
        let mut account = Account::default();
        account.password_token = "token-0".into();
        let mut attempted_tokens = Vec::new();
        let mut refresh_count = 0;
        let (output, purchased) = retry_download(
            &mut account,
            false,
            |account| {
                refresh_count += 1;
                let mut refreshed_account = Account::default();
                refreshed_account.password_token = format!("token-{refresh_count}");
                assert_eq!(
                    account.password_token,
                    format!("token-{}", refresh_count - 1)
                );
                Ok(refreshed_account)
            },
            |account, purchase_required, purchased| {
                assert!(!*purchase_required);
                assert!(!*purchased);
                attempted_tokens.push(account.password_token.clone());
                if account.password_token != "token-2" {
                    return Err(PasswordTokenExpired.into());
                }
                Ok("downloaded")
            },
        )
        .unwrap();
        assert_eq!(output, "downloaded");
        assert!(!purchased);
        assert_eq!(refresh_count, 2);
        assert_eq!(attempted_tokens, ["token-0", "token-1", "token-2"]);
    }

    #[test]
    fn download_keeps_license_pending_after_purchase_token_expiry() {
        let mut account = Account::default();
        account.password_token = "old".into();
        let mut events = Vec::new();
        let (output, purchased) = retry_download(
            &mut account,
            true,
            |account| {
                assert_eq!(account.password_token, "old");
                let mut renewed = Account::default();
                renewed.password_token = "new".into();
                Ok(renewed)
            },
            |account, purchase_required, purchased| {
                if !*purchase_required {
                    events.push("download without license");
                    return Err(LicenseRequired.into());
                }
                if account.password_token == "old" {
                    events.push("purchase with expired token");
                    return Err(PasswordTokenExpired.into());
                }
                events.push("purchase and download with new token");
                *purchase_required = false;
                *purchased = true;
                Ok("downloaded")
            },
        )
        .unwrap();
        assert_eq!(output, "downloaded");
        assert!(purchased);
        assert_eq!(
            events,
            [
                "download without license",
                "purchase with expired token",
                "purchase and download with new token"
            ]
        );
    }

    #[test]
    fn download_stops_after_three_expired_attempts() {
        let mut account = Account::default();
        let mut refreshes = 0;
        let mut attempts = 0;
        let error = retry_download::<()>(
            &mut account,
            false,
            |_| {
                refreshes += 1;
                Ok(Account::default())
            },
            |_, _, _| {
                attempts += 1;
                Err(PasswordTokenExpired.into())
            },
        )
        .unwrap_err();
        assert!(error.downcast_ref::<PasswordTokenExpired>().is_some());
        assert_eq!(refreshes, 2);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn public_catalog_country_defaults_to_us_without_account() {
        assert_eq!(catalog_country(None), "US");
        assert_eq!(catalog_country(Some("JP")), "JP");
    }

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
    fn recover_state_checkpoints_accepts_private_capture_paths() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-state-checkpoints",
            "--state-checkpoint",
            "/private/state.checkpoint.pkl.gz",
            "--source-checkpoint",
            "/private/source.checkpoint.pkl.gz",
            "--transformed-checkpoint",
            "/private/transformed.checkpoint.pkl.gz",
            "--state-bytes",
            "192",
            "--sinf",
            "/private/app.sinf",
            "--selector",
            "12345678:00000009",
            "--output",
            "/private/enrollment.bin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverStateCheckpoints {
                    state_bytes: 192,
                    source_address: None,
                    slot: None,
                    ..
                }
            }
        ));
    }

    #[test]
    fn whitebox_commands_accept_private_model_and_fault_metadata() {
        let evaluate = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "evaluate-whitebox",
            "--model",
            "/private/oracle.model.gz",
            "--input",
            "/private/block.bin",
            "--metadata",
            "0x01000008",
            "--output",
            "/private/result.bin",
        ])
        .unwrap();
        assert!(matches!(
            evaluate.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::EvaluateWhitebox { .. }
            }
        ));
        let recover = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-whitebox",
            "--model",
            "/private/oracle.model.gz",
            "--output",
            "/private/recovered.json",
        ])
        .unwrap();
        assert!(matches!(
            recover.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverWhitebox { .. }
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
    fn fairplay_checkpoint_virtual_file_options_parse() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "continue-checkpoint",
            "--checkpoint",
            "/private/entry.pkl.gz",
            "--fairplayd",
            "/private/fairplayd",
            "--stop-address",
            "0x1000",
            "--stop-hit",
            "432",
            "--memory-trace-output",
            "/private/oracle-trace.json",
            "--trace-memory-reads",
            "--max-memory-events",
            "200000",
            "--file-payload",
            "SC Info.demo=/private/state",
            "--file-stat",
            "SC Info.demo=0o666,265,265",
            "--missing-files-are-enoent",
            "--mac-address-file",
            "/private/iomac.bin",
            "--iokit15-output",
            "/private/iokit15.bin",
        ])
        .unwrap();
        match cli.command {
            Command::FairplayEnroll {
                command:
                    FairplayEnrollCommand::ContinueCheckpoint {
                        file_payloads,
                        file_stats,
                        missing_files_are_enoent,
                        stop_hit,
                        memory_trace_output,
                        trace_memory_reads,
                        max_memory_events,
                        mac_address_file,
                        iokit15_output,
                        ..
                    },
            } => {
                assert_eq!(file_payloads, ["SC Info.demo=/private/state"]);
                assert_eq!(file_stats, ["SC Info.demo=0o666,265,265"]);
                assert!(missing_files_are_enoent);
                assert_eq!(stop_hit, 432);
                assert_eq!(
                    memory_trace_output,
                    Some(PathBuf::from("/private/oracle-trace.json"))
                );
                assert!(trace_memory_reads);
                assert_eq!(max_memory_events, 200_000);
                assert_eq!(mac_address_file, Some(PathBuf::from("/private/iomac.bin")));
                assert_eq!(iokit15_output, Some(PathBuf::from("/private/iokit15.bin")));
            }
            _ => panic!("unexpected command"),
        }
        assert_eq!(parse_address("0o666").unwrap(), 0o666);
        assert_eq!(
            parse_private_mac(&[1, 2, 3, 4, 5, 6]).unwrap(),
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            parse_private_mac(b"aa:bb:cc:dd:ee:ff\n").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(parse_private_mac(b"aa:bb:cc:dd:ee:xx").is_err());
    }

    #[test]
    fn fairplay_oracle_export_accepts_private_capture_paths() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "export-oracle-model",
            "--checkpoint",
            "/private/oracle.pkl.gz",
            "--fairplayd",
            "/private/fairplayd",
            "--memory-trace",
            "/private/oracle-trace.json",
            "--output",
            "/private/oracle-model.gz",
        ])
        .unwrap();
        match cli.command {
            Command::FairplayEnroll {
                command:
                    FairplayEnrollCommand::ExportOracleModel {
                        checkpoint,
                        fairplayd,
                        memory_trace,
                        index_domains,
                        output,
                    },
            } => {
                assert_eq!(checkpoint, PathBuf::from("/private/oracle.pkl.gz"));
                assert_eq!(fairplayd, PathBuf::from("/private/fairplayd"));
                assert_eq!(memory_trace, PathBuf::from("/private/oracle-trace.json"));
                assert!(index_domains.is_none());
                assert_eq!(output, PathBuf::from("/private/oracle-model.gz"));
            }
            _ => panic!("unexpected command"),
        }
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "export-oracle-model",
            "--checkpoint",
            "/private/26b118.pkl.gz",
            "--fairplayd",
            "/private/fairplayd",
            "--memory-trace",
            "/private/oracle-trace.json",
            "--index-domains",
            "/private/index-domains.json",
            "--output",
            "/private/oracle-model.gz",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::ExportOracleModel {
                    index_domains: Some(_),
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_index_domain_learning_accepts_private_capture_paths() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "learn-index-domains",
            "--checkpoint",
            "/private/26b118.pkl.gz",
            "--fairplayd",
            "/private/fairplayd",
            "--max-inputs",
            "4096",
            "--timeout-seconds",
            "3",
            "--output",
            "/private/index-domains.json",
        ])
        .unwrap();
        match cli.command {
            Command::FairplayEnroll {
                command:
                    FairplayEnrollCommand::LearnIndexDomains {
                        checkpoint,
                        fairplayd,
                        max_inputs,
                        timeout_seconds,
                        output,
                    },
            } => {
                assert_eq!(checkpoint, PathBuf::from("/private/26b118.pkl.gz"));
                assert_eq!(fairplayd, PathBuf::from("/private/fairplayd"));
                assert_eq!(max_inputs, 4096);
                assert_eq!(timeout_seconds, 3);
                assert_eq!(output, PathBuf::from("/private/index-domains.json"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn fairplay_raw_source_accepts_private_model_and_output_options() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "raw-source",
            "--model",
            "/private/oracle.model.gz",
            "--kernel",
            "outer",
            "--loop",
            "--report",
            "/private/report.json",
            "--output",
            "/private/source.bin",
            "--output-bytes",
            "224",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RawSource {
                    kernel,
                    loop_mode: true,
                    iterations: 0,
                    output_bytes: Some(224),
                    ..
                }
            } if kernel == "outer"
        ));
    }

    #[test]
    fn fairplay_oracle_validation_accepts_private_capture_paths() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "validate-oracle-model",
            "--checkpoint",
            "/private/26b118.pkl.gz",
            "--fairplayd",
            "/private/fairplayd",
            "--model",
            "/private/oracle-model.gz",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::ValidateOracleModel {
                    timeout_seconds: 2,
                    normal_cases: 16,
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_recover_from_account_accepts_private_paths() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-from-account",
            "--capture",
            "/private/capture",
            "--account-checkpoint",
            "/private/account.pkl.gz",
            "--output",
            "/private/recovery",
            "--timeout-seconds",
            "900",
            "--skip-differential",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverFromAccount {
                    timeout_seconds: 900,
                    skip_differential: true,
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_recover_from_sinf_copy_accepts_private_paths() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-from-sinf-copy",
            "--capture",
            "/private/capture",
            "--sinf-copy-checkpoint",
            "/private/sinf-copy.pkl.gz",
            "--output",
            "/private/recovery",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverFromSinfCopy {
                    timeout_seconds: 600,
                    skip_differential: false,
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_recover_capture_accepts_startup_profile() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover-capture",
            "--capture",
            "/private/capture",
            "--startup-profile",
            "/profiles/macos26b118-startup.json.gz",
            "--iokit15-output",
            "/private/iokit15-output.bin",
            "--output",
            "/private/recovery",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverCapture {
                    timeout_seconds: 600,
                    skip_differential: false,
                    iokit15_output: Some(_),
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_recover_uses_bundled_profile_by_default() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover",
            "--capture",
            "/private/capture",
            "--output",
            "/private/recovery",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverCapture {
                    startup_profile: None,
                    timeout_seconds: 600,
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_recover_accepts_checked_compatibility_binary() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "recover",
            "--capture",
            "/private/capture",
            "--compat-fairplayd",
            "/private/fairplayd.arm64e",
            "--output",
            "/private/recovery",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::FairplayEnroll {
                command: FairplayEnrollCommand::RecoverCapture {
                    compat_fairplayd: Some(_),
                    startup_profile: None,
                    ..
                }
            }
        ));
    }

    #[test]
    fn fairplay_checkpoint_accepts_memory_read_stop_range() {
        let cli = Cli::try_parse_from([
            "ipatool",
            "fairplay-enroll",
            "continue-checkpoint",
            "--checkpoint",
            "/private/entry.pkl.gz",
            "--fairplayd",
            "/private/fairplayd",
            "--stop-memory-read-range",
            "0x710000014ee0:432",
            "--instruction-limit",
            "10000000",
            "--timeout-seconds",
            "600",
            "--preserve-text-instruction",
            "0x100a05900",
        ])
        .unwrap();
        match cli.command {
            Command::FairplayEnroll {
                command:
                    FairplayEnrollCommand::ContinueCheckpoint {
                        stop_address,
                        stop_memory_read_range,
                        instruction_limit,
                        timeout_seconds,
                        preserve_text_instructions,
                        ..
                    },
            } => {
                assert!(stop_address.is_none());
                assert_eq!(
                    stop_memory_read_range.as_deref(),
                    Some("0x710000014ee0:432")
                );
                assert_eq!(instruction_limit, 10_000_000);
                assert_eq!(timeout_seconds, 600);
                assert_eq!(preserve_text_instructions, ["0x100a05900"]);
            }
            _ => panic!("unexpected command"),
        }
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

    #[test]
    fn download_and_version_list_leave_catalog_platform_unspecified() {
        let download = Cli::try_parse_from(["ipatool", "download", "--app-id", "123"]).unwrap();
        match download.command {
            Command::Download { platform, .. } => assert!(platform.is_none()),
            _ => panic!("unexpected command"),
        }
        let versions =
            Cli::try_parse_from(["ipatool", "list-versions", "--app-id", "123"]).unwrap();
        match versions.command {
            Command::ListVersions { platform, .. } => assert!(platform.is_none()),
            _ => panic!("unexpected command"),
        }
        assert_eq!(parse_platform(None).unwrap(), None);
    }

    #[test]
    fn fairplay_decrypt_parses_without_model_for_profile_diagnostic() {
        let cli = Cli::try_parse_from(["ipatool", "fairplay-decrypt", "--input", "A.ipa"]).unwrap();
        match cli.command {
            Command::FairplayDecrypt { input, model, .. } => {
                assert_eq!(input, PathBuf::from("A.ipa"));
                assert!(model.is_none());
            }
            _ => panic!("unexpected command"),
        }
    }
}
