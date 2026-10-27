//! Continue checked FairPlay captures from their private early checkpoints.
//! All subsequent tracing, model recovery, and IPA decryption run in Rust.

use std::{
    fs::{self, DirBuilder},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    capture::{
        FAIRPLAY_BUILD_26A428_HASH, FAIRPLAY_BUILD_26B118_HASH, capture_file_path,
        load_enrollment_capture,
    },
    fairplay_checkpoint::FairplayCheckpoint,
    fairplay_checkpoint_run::{CheckpointRunner, MemoryTraceOptions, VirtualFileStat},
    fairplay_enrollment_model::{FIRST_TRANSFORM_BYTES, build_fpsenr2},
    fairplay_enrollment_v3::{V3Material, build_fpsenr3},
    fairplay_ipa::decrypt_ipa_with_options,
    fairplay_key::CurrentSinfModel,
    fairplay_oracle_domains::{learn_26b118_domains, validate_26a428_model, validate_26b118_model},
    fairplay_oracle_export::export_checked_model,
    fairplay_oracle_model::OracleModel,
    fairplay_recovery,
    fairplay_recovery_output::{
        open_private_file, read_private_bytes, write_private_binary, write_private_model,
    },
    fairplay_recovery_target::WhiteboxTarget,
};

const ACCOUNT_ENTRY: u64 = 0x1005_7ae74;
const SOURCE_ENTRY: u64 = 0x1001_5321c;
const TRANSFORM_EXIT: u64 = 0x1001_53310;
const ORACLE_ENTRY: u64 = 0x1002_34cdc;
const ORACLE_BLOCK: u64 = 0x7100_0001_4ee8;
const MAX_FAIRPLAYD_BYTES: usize = 256 * 1024 * 1024;
const MAX_VIRTUAL_FILE_BYTES: usize = 128 * 1024 * 1024;
const PRESERVED_26B118_TEXT: [u64; 1] = [0x100a_05900];

pub struct RecoverFromAccountOptions<'a> {
    pub capture: &'a Path,
    pub account_checkpoint: &'a Path,
    pub output: &'a Path,
    pub timeout: Duration,
    pub skip_differential: bool,
}

pub struct RecoverFromSinfCopyOptions<'a> {
    pub capture: &'a Path,
    pub sinf_copy_checkpoint: &'a Path,
    pub output: &'a Path,
    pub timeout: Duration,
    pub skip_differential: bool,
}

#[derive(Debug, Serialize)]
pub struct CaptureRecoveryResult {
    pub schema: &'static str,
    pub success: bool,
    pub capture_manifest_sha256: String,
    pub selector: String,
    pub fairplayd_sha256: String,
    pub capture_fairplayd_sha256: String,
    pub compatibility_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<&'static str>,
    pub enrollment_model: PathBuf,
    pub enrollment_model_sha256: String,
    pub decrypted_ipa: PathBuf,
    pub decrypted_ipa_sha256: String,
    pub encrypted_images: usize,
    pub decrypted_pages: usize,
    pub all_cryptids_zero: bool,
    pub all_code_directory_slots_match: bool,
    pub differential_cases: Option<usize>,
}

fn private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("create private recovery directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        DirBuilder::new()
            .create(path)
            .with_context(|| format!("create private recovery directory {}", path.display()))?;
    }
    Ok(())
}

fn read_checked_fairplayd(path: &Path, expected: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = open_private_file(path, None, MAX_FAIRPLAYD_BYTES as u64)?;
    let mut data = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(MAX_FAIRPLAYD_BYTES as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > MAX_FAIRPLAYD_BYTES || format!("{:x}", Sha256::digest(&*data)) != expected {
        bail!("captured fairplayd does not match its checked SHA-256");
    }
    Ok(data)
}

fn parse_private_mac(path: &Path) -> Result<[u8; 6]> {
    let data = read_private_bytes(path, 64)?;
    if data.len() == 6 {
        return Ok(data.as_slice().try_into()?);
    }
    let text = std::str::from_utf8(&data).context("captured MAC address is not UTF-8")?;
    let digits = text
        .trim()
        .bytes()
        .filter(|byte| !matches!(byte, b':' | b'-'))
        .collect::<Vec<_>>();
    if digits.len() != 12 || !digits.iter().all(u8::is_ascii_hexdigit) {
        bail!("captured MAC address must contain six raw bytes or twelve hex digits");
    }
    let mut address = [0u8; 6];
    for (index, byte) in address.iter_mut().enumerate() {
        *byte = u8::from_str_radix(std::str::from_utf8(&digits[index * 2..index * 2 + 2])?, 16)?;
    }
    Ok(address)
}

fn add_capture_files(
    runner: &mut CheckpointRunner,
    capture: &Path,
    executable: &str,
    target_sinf: &str,
    fpsd_stat: Option<VirtualFileStat>,
) -> Result<()> {
    if executable.is_empty() || executable.contains('/') || executable.contains('\\') {
        bail!("capture executable name is invalid");
    }
    let payloads = [
        (format!("/{executable}"), capture.join("app/executable")),
        (
            format!("{executable}.sinf"),
            capture_file_path(capture, target_sinf)?,
        ),
        (
            format!("{executable}.v5.supf"),
            capture.join(format!("app/SC_Info/{executable}.v5.supf")),
        ),
        (
            format!("{executable}.supf"),
            capture.join(format!("app/SC_Info/{executable}.supf")),
        ),
    ];
    for (suffix, path) in payloads {
        runner.add_file_payload(&suffix, read_private_bytes(&path, MAX_VIRTUAL_FILE_BYTES)?)?;
    }
    let state = capture.join("state/fpsd-sc-info");
    if state.is_dir() {
        let mut entries = fs::read_dir(&state)
            .context("read captured FPSD SC Info directory")?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_str().context("non-UTF-8 captured FPSD filename")?;
            if name.starts_with("SC Info.") && entry.file_type()?.is_file() {
                let suffix = format!("/var/db/fpsd/SC Info/{name}");
                runner.add_file_payload(
                    &suffix,
                    read_private_bytes(&entry.path(), MAX_VIRTUAL_FILE_BYTES)?,
                )?;
                if let Some(stat) = fpsd_stat {
                    runner.add_file_stat(&suffix, stat)?;
                }
            }
        }
    }
    Ok(())
}

struct CheckpointStage {
    stop: u64,
    hits: usize,
    limit: usize,
}

fn checkpoint_stage(
    source: &FairplayCheckpoint,
    binary: &[u8],
    binary_path: &Path,
    output: &Path,
    stage: CheckpointStage,
    timeout: Duration,
    preserved_text: &[u64],
) -> Result<()> {
    let mut runner = CheckpointRunner::new_preserving_text(source, binary, preserved_text)?;
    runner.run_until_hit(stage.stop, stage.hits, timeout, stage.limit)?;
    runner.write_checkpoint(source, binary_path, output)?;
    Ok(())
}

pub fn recover_from_account(
    options: RecoverFromAccountOptions<'_>,
) -> Result<CaptureRecoveryResult> {
    if options.timeout.is_zero() || options.timeout > Duration::from_secs(3600) {
        bail!("recovery phase timeout must be between 1 and 3600 seconds");
    }
    let manifest = load_enrollment_capture(options.capture, true)?;
    if manifest.fairplayd.sha256 != FAIRPLAY_BUILD_26A428_HASH {
        bail!("account-checkpoint recovery currently requires the checked 26A428 capture");
    }
    let ipa_entry = manifest.ipa.as_ref().context("capture has no IPA")?;
    let ipa = capture_file_path(options.capture, &ipa_entry.path)?;
    let fairplayd = capture_file_path(options.capture, &manifest.fairplayd.path)?;
    let binary = read_checked_fairplayd(&fairplayd, FAIRPLAY_BUILD_26A428_HASH)?;
    let account = FairplayCheckpoint::load_private(options.account_checkpoint)?;
    let binary_hash: [u8; 32] = Sha256::digest(&*binary).into();
    if account.binary_hash != binary_hash || account.pc()? != ACCOUNT_ENTRY {
        bail!("account checkpoint does not match the checked 26A428 entry");
    }
    let target_sinf = if manifest.app.target_sinf_path.is_empty() {
        &manifest.app.sinf_path
    } else {
        &manifest.app.target_sinf_path
    };
    let sinf = capture_file_path(options.capture, target_sinf)?;
    let iomac = capture_file_path(options.capture, &manifest.hardware_iomac.path)?;
    let mac = parse_private_mac(&iomac)?;
    if manifest.app.selector.identifier() != manifest.app.selector_id {
        bail!("capture selector and selector ID disagree");
    }
    private_directory(options.output)?;
    let checkpoints = options.output.join("checkpoints");
    private_directory(&checkpoints)?;

    eprintln!("fairplay_recovery_stage=derive-source");
    let source_path = checkpoints.join("first-private-read.checkpoint.pkl.gz");
    let mut runner = CheckpointRunner::new(&account, &binary)?;
    runner.set_missing_files_are_enoent(true);
    runner.set_mac_address(mac);
    add_capture_files(
        &mut runner,
        options.capture,
        &manifest.app.executable,
        target_sinf,
        None,
    )?;
    runner.run_until_hit(SOURCE_ENTRY, 1, options.timeout, 500_000_000)?;
    runner.write_checkpoint(&account, &fairplayd, &source_path)?;
    let source = FairplayCheckpoint::load_private(&source_path)?;

    eprintln!("fairplay_recovery_stage=derive-transform");
    let transformed_path = checkpoints.join("first-transform-output.checkpoint.pkl.gz");
    checkpoint_stage(
        &source,
        &binary,
        &fairplayd,
        &transformed_path,
        CheckpointStage {
            stop: TRANSFORM_EXIT,
            hits: FIRST_TRANSFORM_BYTES,
            limit: 50_000_000,
        },
        options.timeout,
        &[],
    )?;
    let transformed = FairplayCheckpoint::load_private(&transformed_path)?;

    eprintln!("fairplay_recovery_stage=derive-oracle");
    let oracle_path = checkpoints.join("core-entry.checkpoint.pkl.gz");
    checkpoint_stage(
        &source,
        &binary,
        &fairplayd,
        &oracle_path,
        CheckpointStage {
            stop: ORACLE_ENTRY,
            hits: 1,
            limit: 500_000_000,
        },
        options.timeout,
        &[],
    )?;
    let oracle = FairplayCheckpoint::load_private(&oracle_path)?;

    eprintln!("fairplay_recovery_stage=trace-oracle");
    let trace_path = options.output.join("oracle-memory-trace.json");
    let mut runner = CheckpointRunner::new(&oracle, &binary)?;
    let trace = runner.run_until_hit_with_memory_trace(
        ORACLE_ENTRY,
        2,
        options.timeout,
        200_000,
        MemoryTraceOptions {
            reads: true,
            writes: true,
            max_events: 1_000_000,
        },
    )?;
    write_private_binary(
        &trace_path,
        &serde_json::to_vec(&serde_json::json!({
            "schema": "fairplay.checkpoint-memory-trace.v1",
            "binary_sha256": manifest.fairplayd.sha256,
            "start_pc": format!("{ORACLE_ENTRY:#x}"),
            "stop_pc": format!("{ORACLE_ENTRY:#x}"),
            "stop_hit": 2,
            "memory_read_events": trace.memory_read_events,
            "memory_write_events": trace.memory_write_events,
        }))?,
    )?;

    eprintln!("fairplay_recovery_stage=export-oracle");
    let oracle_model_path = options.output.join("fairplay-oracle.model.gz");
    let exported = export_checked_model(&oracle, &binary, &trace_path, None)?;
    write_private_binary(&oracle_model_path, &exported.compressed)?;
    let model = OracleModel::parse_gzip(&exported.compressed)?;
    let differential_cases = if options.skip_differential {
        None
    } else {
        eprintln!("fairplay_recovery_stage=validate-oracle");
        Some(validate_26a428_model(&oracle, &binary, &model, options.timeout, 16)?.cases)
    };

    eprintln!("fairplay_recovery_stage=recover-aes");
    let recovered_path = options.output.join("recovered-whitebox-model.json");
    let mut target = WhiteboxTarget::new(&model)?;
    let recovered = fairplay_recovery::recover(&mut target)?;
    write_private_model(&recovered_path, &recovered)?;

    eprintln!("fairplay_recovery_stage=build-enrollment");
    let source_address = source.register_u64("x23")?;
    let source_block = source.read_block::<FIRST_TRANSFORM_BYTES>(source_address)?;
    let encoded = transformed.read_block::<FIRST_TRANSFORM_BYTES>(ORACLE_BLOCK)?;
    let enrollment = build_fpsenr2(
        &recovered,
        manifest.app.selector,
        account.binary_hash,
        &source_block,
        &encoded,
        &[],
    )?;
    let sinf_bytes = read_private_bytes(&sinf, 1024 * 1024)?;
    let _logical = Zeroizing::new(CurrentSinfModel::parse(&enrollment)?.logical_key(&sinf_bytes)?);
    let candidate = options.output.join("fairplay-enrollment.candidate.bin");
    write_private_binary(&candidate, &enrollment)?;

    eprintln!("fairplay_recovery_stage=decrypt-and-verify");
    let decrypted_ipa = options.output.join("App.decrypted.ipa");
    let decryption_report = options.output.join("App.decrypted.json");
    let decrypted = decrypt_ipa_with_options(
        &ipa,
        &decrypted_ipa,
        &candidate,
        Some(&decryption_report),
        false,
    )?;
    let enrollment_model = options.output.join("fairplay-enrollment.bin");
    fs::rename(&candidate, &enrollment_model).context("publish validated enrollment model")?;
    let result = CaptureRecoveryResult {
        schema: "ipatool-fairplay-enrollment-recovery-v1",
        success: true,
        capture_manifest_sha256: format!(
            "{:x}",
            Sha256::digest(fs::read(options.capture.join("manifest.json"))?)
        ),
        selector: manifest.app.selector_id,
        fairplayd_sha256: manifest.fairplayd.sha256.clone(),
        capture_fairplayd_sha256: manifest.fairplayd.sha256,
        compatibility_profile: None,
        profile: None,
        enrollment_model,
        enrollment_model_sha256: format!("{:x}", Sha256::digest(&enrollment)),
        decrypted_ipa,
        decrypted_ipa_sha256: decrypted.output_sha256,
        encrypted_images: decrypted.encrypted_images,
        decrypted_pages: decrypted.decrypted_pages,
        all_cryptids_zero: true,
        all_code_directory_slots_match: true,
        differential_cases,
    };
    write_private_binary(
        &options.output.join("recovery-report.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

/// Continue the checked native 26B118 recovery after its SINF-copy checkpoint.
pub fn recover_from_sinf_copy(
    options: RecoverFromSinfCopyOptions<'_>,
) -> Result<CaptureRecoveryResult> {
    const SINF_COPY_ENTRY: u64 = 0x1005_d0374;
    const NORMALIZER_ENTRY: u64 = 0x1000_bdb0c;
    const NORMALIZER_EXIT: u64 = 0x1001_1965c;
    const FIRST_CONSUMER: u64 = 0x1001_7ee78;
    const GENERATED_TABLES: u64 = 0x1001_eb32c;
    const WHITEBOX_ENTRY: u64 = 0x1002_21894;
    const WHITEBOX_EXIT: u64 = 0x1002_23a30;
    const POSTCODEC_ENTRY: u64 = 0x1000_ca6f4;
    const POSTCODEC_EXIT: u64 = 0x1004_dd8b8;
    const BUFFER: u64 = 0x7100_0001_4ee0;

    if options.timeout.is_zero() || options.timeout > Duration::from_secs(3600) {
        bail!("recovery phase timeout must be between 1 and 3600 seconds");
    }
    let manifest = load_enrollment_capture(options.capture, true)?;
    if manifest.fairplayd.sha256 != FAIRPLAY_BUILD_26B118_HASH {
        bail!("SINF-copy recovery requires the checked 26B118 capture");
    }
    let ipa_entry = manifest.ipa.as_ref().context("capture has no IPA")?;
    let ipa = capture_file_path(options.capture, &ipa_entry.path)?;
    let fairplayd = capture_file_path(options.capture, &manifest.fairplayd.path)?;
    let binary = read_checked_fairplayd(&fairplayd, FAIRPLAY_BUILD_26B118_HASH)?;
    let entry = FairplayCheckpoint::load_private(options.sinf_copy_checkpoint)?;
    let binary_hash: [u8; 32] = Sha256::digest(&*binary).into();
    if entry.binary_hash != binary_hash || entry.pc()? != SINF_COPY_ENTRY {
        bail!("SINF-copy checkpoint does not match the checked 26B118 entry");
    }
    let system_state = options.capture.join("state/fpsd-sc-info");
    if !system_state.is_dir() {
        bail!("26B118 recovery requires captured FPSD SC Info state");
    }
    let sinf = capture_file_path(options.capture, &manifest.app.sinf_path)?;
    let iomac = capture_file_path(options.capture, &manifest.hardware_iomac.path)?;
    let mac = parse_private_mac(&iomac)?;
    if manifest.app.selector.identifier() != manifest.app.selector_id {
        bail!("capture selector and selector ID disagree");
    }
    private_directory(options.output)?;
    let checkpoints = options.output.join("checkpoints");
    private_directory(&checkpoints)?;

    eprintln!("fairplay_recovery_stage=derive-26b-normalizer");
    let normalizer_entry_path = checkpoints.join("normalizer-entry.checkpoint.pkl.gz");
    let mut runner =
        CheckpointRunner::new_preserving_text(&entry, &binary, &PRESERVED_26B118_TEXT)?;
    runner.set_missing_files_are_enoent(true);
    runner.set_mac_address(mac);
    add_capture_files(
        &mut runner,
        options.capture,
        &manifest.app.executable,
        &manifest.app.sinf_path,
        Some(VirtualFileStat {
            mode: 0o666,
            uid: 265,
            gid: 265,
        }),
    )?;
    runner.run_until_hit(NORMALIZER_ENTRY, 1, options.timeout, 350_000_000)?;
    runner.write_checkpoint(&entry, &fairplayd, &normalizer_entry_path)?;
    let normalizer_entry = FairplayCheckpoint::load_private(&normalizer_entry_path)?;

    let normalizer_exit_path = checkpoints.join("normalizer-exit.checkpoint.pkl.gz");
    checkpoint_stage(
        &normalizer_entry,
        &binary,
        &fairplayd,
        &normalizer_exit_path,
        CheckpointStage {
            stop: NORMALIZER_EXIT,
            hits: 1,
            limit: 1_000_000,
        },
        options.timeout,
        &PRESERVED_26B118_TEXT,
    )?;
    let normalizer_exit = FairplayCheckpoint::load_private(&normalizer_exit_path)?;

    let first_consumer_path = checkpoints.join("first-consumer.checkpoint.pkl.gz");
    let mut runner =
        CheckpointRunner::new_preserving_text(&normalizer_exit, &binary, &PRESERVED_26B118_TEXT)?;
    let stopped = runner.run_until_memory_read_range(
        BUFFER,
        FIRST_TRANSFORM_BYTES as u64,
        options.timeout,
        10_000_000,
    )?;
    if stopped.pc != FIRST_CONSUMER {
        bail!("26B118 normalized object reached an unexpected first consumer");
    }
    runner.write_checkpoint(&normalizer_exit, &fairplayd, &first_consumer_path)?;
    let first_consumer = FairplayCheckpoint::load_private(&first_consumer_path)?;

    let generated_tables_path = checkpoints.join("generated-tables.checkpoint.pkl.gz");
    checkpoint_stage(
        &first_consumer,
        &binary,
        &fairplayd,
        &generated_tables_path,
        CheckpointStage {
            stop: GENERATED_TABLES,
            hits: 1,
            limit: 10_000_000,
        },
        options.timeout,
        &PRESERVED_26B118_TEXT,
    )?;
    let generated_tables = FairplayCheckpoint::load_private(&generated_tables_path)?;
    let oracle_path = checkpoints.join("whitebox-entry.checkpoint.pkl.gz");
    checkpoint_stage(
        &generated_tables,
        &binary,
        &fairplayd,
        &oracle_path,
        CheckpointStage {
            stop: WHITEBOX_ENTRY,
            hits: 1,
            limit: 10_000_000,
        },
        options.timeout,
        &PRESERVED_26B118_TEXT,
    )?;
    let oracle = FairplayCheckpoint::load_private(&oracle_path)?;

    eprintln!("fairplay_recovery_stage=trace-26b-oracle");
    let trace_path = options.output.join("oracle-memory-trace.json");
    let mut runner =
        CheckpointRunner::new_preserving_text(&oracle, &binary, &PRESERVED_26B118_TEXT)?;
    let trace = runner.run_until_hit_with_memory_trace(
        WHITEBOX_EXIT,
        1,
        options.timeout,
        200_000,
        MemoryTraceOptions {
            reads: true,
            writes: true,
            max_events: 1_000_000,
        },
    )?;
    write_private_binary(
        &trace_path,
        &serde_json::to_vec(&serde_json::json!({
            "schema": "fairplay.checkpoint-memory-trace.v1",
            "binary_sha256": manifest.fairplayd.sha256,
            "start_pc": format!("{WHITEBOX_ENTRY:#x}"),
            "stop_pc": format!("{WHITEBOX_EXIT:#x}"),
            "stop_hit": 1,
            "memory_read_events": trace.memory_read_events,
            "memory_write_events": trace.memory_write_events,
        }))?,
    )?;
    eprintln!("fairplay_recovery_stage=learn-26b-index-domains");
    let domains_path = options.output.join("index-domains.json");
    let domains = learn_26b118_domains(
        &oracle,
        &binary,
        20_000,
        options.timeout.min(Duration::from_secs(2)),
    )?;
    write_private_binary(&domains_path, &domains.json)?;

    eprintln!("fairplay_recovery_stage=export-26b-oracle");
    let oracle_model_path = options.output.join("fairplay-oracle.model.gz");
    let exported = export_checked_model(&oracle, &binary, &trace_path, Some(&domains_path))?;
    write_private_binary(&oracle_model_path, &exported.compressed)?;
    let model = OracleModel::parse_gzip(&exported.compressed)?;
    let differential_cases = if options.skip_differential {
        None
    } else {
        eprintln!("fairplay_recovery_stage=validate-26b-oracle");
        Some(validate_26b118_model(&oracle, &binary, &model, options.timeout, 16)?.cases)
    };

    eprintln!("fairplay_recovery_stage=recover-26b-aes");
    let recovered_path = options.output.join("recovered-whitebox-model.json");
    let mut target = WhiteboxTarget::new(&model)?;
    let recovered = fairplay_recovery::recover(&mut target)?;
    write_private_model(&recovered_path, &recovered)?;

    let postcodec_entry_path = checkpoints.join("postcodec-entry.checkpoint.pkl.gz");
    checkpoint_stage(
        &oracle,
        &binary,
        &fairplayd,
        &postcodec_entry_path,
        CheckpointStage {
            stop: POSTCODEC_ENTRY,
            hits: 1,
            limit: 2_000_000,
        },
        options.timeout,
        &PRESERVED_26B118_TEXT,
    )?;
    let postcodec_entry = FairplayCheckpoint::load_private(&postcodec_entry_path)?;
    let postcodec_exit_path = checkpoints.join("postcodec-exit.checkpoint.pkl.gz");
    checkpoint_stage(
        &postcodec_entry,
        &binary,
        &fairplayd,
        &postcodec_exit_path,
        CheckpointStage {
            stop: POSTCODEC_EXIT,
            hits: 1,
            limit: 2_000_000,
        },
        options.timeout,
        &PRESERVED_26B118_TEXT,
    )?;
    let postcodec_exit = FairplayCheckpoint::load_private(&postcodec_exit_path)?;

    eprintln!("fairplay_recovery_stage=build-26b-enrollment");
    let whitebox_entry = oracle.read_block::<FIRST_TRANSFORM_BYTES>(BUFFER)?;
    let postcodec_input = postcodec_entry.read_block::<FIRST_TRANSFORM_BYTES>(BUFFER)?;
    let postcodec_output = postcodec_exit.read_block::<FIRST_TRANSFORM_BYTES>(BUFFER)?;
    let sinf_bytes = read_private_bytes(&sinf, 1024 * 1024)?;
    let enrollment = build_fpsenr3(V3Material {
        recovered: &recovered,
        selector: manifest.app.selector,
        fairplayd_sha256: binary_hash,
        source_offset: 0x1e0,
        final_xor: 0x98,
        whitebox_entry: &whitebox_entry,
        postcodec_entry: &postcodec_input,
        postcodec_exit: &postcodec_output,
        sinf: &sinf_bytes,
    })?;
    let candidate = options.output.join("fairplay-enrollment.candidate.bin");
    write_private_binary(&candidate, &enrollment)?;

    eprintln!("fairplay_recovery_stage=decrypt-and-verify");
    let decrypted_ipa = options.output.join("App.decrypted.ipa");
    let decryption_report = options.output.join("App.decrypted.json");
    let decrypted = decrypt_ipa_with_options(
        &ipa,
        &decrypted_ipa,
        &candidate,
        Some(&decryption_report),
        false,
    )?;
    let enrollment_model = options.output.join("fairplay-enrollment.bin");
    fs::rename(&candidate, &enrollment_model).context("publish validated enrollment model")?;
    let result = CaptureRecoveryResult {
        schema: "ipatool-fairplay-enrollment-recovery-v1",
        success: true,
        capture_manifest_sha256: format!(
            "{:x}",
            Sha256::digest(fs::read(options.capture.join("manifest.json"))?)
        ),
        selector: manifest.app.selector_id,
        fairplayd_sha256: manifest.fairplayd.sha256.clone(),
        capture_fairplayd_sha256: manifest.fairplayd.sha256,
        compatibility_profile: None,
        profile: Some("macos26b118"),
        enrollment_model,
        enrollment_model_sha256: format!("{:x}", Sha256::digest(&enrollment)),
        decrypted_ipa,
        decrypted_ipa_sha256: decrypted.output_sha256,
        encrypted_images: decrypted.encrypted_images,
        decrypted_pages: decrypted.decrypted_pages,
        all_cryptids_zero: true,
        all_code_directory_slots_match: true,
        differential_cases,
    };
    write_private_binary(
        &options.output.join("recovery-report.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{ENROLLMENT_CAPTURE_SCHEMA, EnrollmentCaptureManifest};

    #[test]
    fn recovery_directory_is_private_and_must_be_new() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("recovery");
        private_directory(&output).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(private_directory(&output).is_err());
    }

    #[test]
    fn captured_mac_accepts_raw_and_hex_forms() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("iomac");
        fs::write(&input, [2, 0, 0, 0, 0, 1]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(parse_private_mac(&input).unwrap(), [2, 0, 0, 0, 0, 1]);
        fs::write(&input, b"02:00:00:00:00:01\n").unwrap();
        assert_eq!(parse_private_mac(&input).unwrap(), [2, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn sinf_copy_rejects_wrong_build_before_creating_output() {
        let root = tempfile::tempdir().unwrap();
        let capture = root.path().join("capture");
        private_directory(&capture).unwrap();
        let mut manifest = EnrollmentCaptureManifest {
            schema: ENROLLMENT_CAPTURE_SCHEMA.into(),
            ..EnrollmentCaptureManifest::default()
        };
        manifest.fairplayd.sha256 = FAIRPLAY_BUILD_26A428_HASH.into();
        fs::write(
            capture.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let output = root.path().join("output");
        let error = recover_from_sinf_copy(RecoverFromSinfCopyOptions {
            capture: &capture,
            sinf_copy_checkpoint: &root.path().join("missing.pkl.gz"),
            output: &output,
            timeout: Duration::from_secs(1),
            skip_differential: true,
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("checked 26B118 capture"));
        assert!(!output.exists());
    }
}
