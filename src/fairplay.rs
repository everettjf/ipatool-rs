//! Offline FairPlay SINF and enrollment model inspection.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;
use zip::ZipArchive;

use crate::capture::{
    EnrollmentCaptureManifest, FairPlayBuildSupport, capture_file_path, load_enrollment_capture,
    model_matches_capture_build,
};
use crate::duplicate_zip;
use crate::host::{FairPlayHostDiagnostic, inspect_local_fairplay_host};

const MODEL_V1_BYTES: usize = 8 + 4 + 4 + 32 + 16 + 16 + 16 * 256;
const MODEL_V2_BYTES: usize = 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16 * 256;
const MODEL_V3_SOURCE_BYTES: usize = 27 * 16;
const MODEL_V3_BYTES: usize =
    8 + 4 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 16 + 16 * 256 + MODEL_V3_SOURCE_BYTES + 16 * 256;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SinfSelector {
    pub user: u32,
    pub key: u32,
}

impl SinfSelector {
    pub fn identifier(self) -> String {
        format!("{:08x}:{:08x}", self.user, self.key)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SinfDiagnostic {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub sha256: String,
    pub bytes: usize,
    pub selector: SinfSelector,
    pub selector_id: String,
    pub private_bytes: usize,
    pub atoms: Vec<String>,
    pub current_layout: bool,
    pub legacy_markers: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrollmentModelDiagnostic {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub version: u32,
    pub fairplayd_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<SinfSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_id: Option<String>,
}

#[derive(Clone, Copy)]
struct Atom<'a> {
    typ: [u8; 4],
    payload: &'a [u8],
}

fn atoms(mut bytes: &[u8]) -> Result<Vec<Atom<'_>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            bail!("SINF atom list has a truncated header");
        }
        let size = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if size < 8 || size > bytes.len() {
            bail!("SINF atom has invalid bounds");
        }
        result.push(Atom {
            typ: bytes[4..8].try_into().unwrap(),
            payload: &bytes[8..size],
        });
        bytes = &bytes[size..];
    }
    Ok(result)
}

fn unique_atom<'a>(atoms: &[Atom<'a>], typ: [u8; 4]) -> Result<Atom<'a>> {
    let mut found = atoms.iter().copied().filter(|atom| atom.typ == typ);
    match (found.next(), found.next()) {
        (Some(atom), None) => Ok(atom),
        (None, _) => bail!(
            "SINF requires one {:?} atom, found 0",
            String::from_utf8_lossy(&typ)
        ),
        _ => bail!(
            "SINF requires one {:?} atom, found multiple",
            String::from_utf8_lossy(&typ)
        ),
    }
}

fn sinf_fields(bytes: &[u8]) -> Result<Vec<Atom<'_>>> {
    let roots = atoms(bytes)?;
    if roots.len() != 1 || roots[0].typ != *b"sinf" {
        bail!("SINF must contain one complete root atom");
    }
    let children = atoms(roots[0].payload)?;
    let schi = unique_atom(&children, *b"schi")?;
    atoms(schi.payload)
}

fn selector_from_fields(fields: &[Atom<'_>]) -> Result<SinfSelector> {
    let user = unique_atom(fields, *b"user")?;
    let key = unique_atom(fields, *b"key ")?;
    if user.payload.len() != 4 || key.payload.len() != 4 {
        bail!("SINF user/key atom has invalid geometry");
    }
    Ok(SinfSelector {
        user: u32::from_be_bytes(user.payload.try_into().unwrap()),
        key: u32::from_be_bytes(key.payload.try_into().unwrap()),
    })
}

pub fn parse_sinf_selector(bytes: &[u8]) -> Result<SinfSelector> {
    selector_from_fields(&sinf_fields(bytes)?)
}

pub fn inspect_sinf(bytes: &[u8]) -> Result<SinfDiagnostic> {
    let fields = sinf_fields(bytes)?;
    let selector = selector_from_fields(&fields)?;
    let mut private_bytes = 0;
    let mut legacy_markers = false;
    let mut names = Vec::with_capacity(fields.len());
    for atom in fields {
        let name = String::from_utf8_lossy(&atom.typ).into_owned();
        if atom.typ == *b"priv" {
            private_bytes = atom.payload.len();
        }
        if atom.typ == *b"crdt" || atom.typ == *b"asdt" {
            legacy_markers = true;
        }
        names.push(name);
    }
    Ok(SinfDiagnostic {
        path: None,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        bytes: bytes.len(),
        selector,
        selector_id: selector.identifier(),
        private_bytes,
        atoms: names,
        current_layout: private_bytes == 440 || private_bytes == 448,
        legacy_markers,
    })
}

pub(crate) fn has_sinf_extension(name: &str) -> bool {
    // Go's strings.ToLower uses the simple Unicode mapping: U+0130 becomes
    // `i`, while Rust's full lowercase mapping yields `i` plus a combining dot.
    let mut chars = name.chars().rev();
    for expected in ['f', 'n', 'i', 's', '.'] {
        let Some(ch) = chars.next() else {
            return false;
        };
        let lower = if ch == '\u{0130}' {
            Some('i')
        } else {
            let mut lower = ch.to_lowercase();
            let first = lower.next();
            first.filter(|_| lower.next().is_none())
        };
        if lower != Some(expected) {
            return false;
        }
    }
    true
}

pub(crate) fn is_sinf_extension_equal_fold(extension: &str) -> bool {
    // Go's strings.EqualFold also groups the long s with ASCII s. Unlike
    // strings.ToLower, it does not group U+0130 with ASCII i.
    let mut chars = extension.chars();
    for expected in ['s', 'i', 'n', 'f'] {
        let Some(ch) = chars.next() else {
            return false;
        };
        if !ch.eq_ignore_ascii_case(&expected) && !(ch == '\u{017f}' && expected == 's') {
            return false;
        }
    }
    chars.next().is_none()
}

pub fn inspect_ipa_sinfs(path: &Path) -> Result<Vec<SinfDiagnostic>> {
    let file = fs::File::open(path).with_context(|| format!("open IPA: {}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("open IPA ZIP archive")?;
    let mut raw_source = fs::File::open(path).context("open IPA for ZIP filename inspection")?;
    let mut result = Vec::new();
    if archive.has_duplicate_names() {
        for (name, bytes) in duplicate_zip::read_matching_entries(path, |name| {
            name.contains("/SC_Info/") && has_sinf_extension(name)
        })? {
            let mut diagnostic = inspect_sinf(&bytes).with_context(|| format!("inspect {name}"))?;
            diagnostic.path = Some(name);
            result.push(diagnostic);
        }
    } else {
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).context("read IPA ZIP member")?;
            let raw_name = duplicate_zip::read_raw_central_name(
                &mut raw_source,
                entry.central_header_start(),
            )?;
            let name = String::from_utf8_lossy(&raw_name).into_owned();
            if !name.contains("/SC_Info/") || !has_sinf_extension(&name) {
                continue;
            }
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .with_context(|| format!("read {name}"))?;
            let mut diagnostic = inspect_sinf(&bytes).with_context(|| format!("inspect {name}"))?;
            diagnostic.path = Some(name);
            result.push(diagnostic);
        }
    }
    if result.is_empty() {
        bail!("IPA contains no SINF files");
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

fn validate_permutation_tables(kind: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(256) {
        bail!("current SINF {kind} tables have invalid size");
    }
    for (index, table) in bytes.as_chunks::<256>().0.iter().enumerate() {
        let mut seen = [false; 256];
        for byte in table {
            if seen[*byte as usize] {
                bail!("current SINF {kind} table {index} is not a permutation");
            }
            seen[*byte as usize] = true;
        }
    }
    Ok(())
}

fn model_details(bytes: &[u8]) -> Result<(u32, String, Option<SinfSelector>)> {
    if bytes.len() < 16
        || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize != bytes.len()
    {
        bail!("invalid current SINF model envelope");
    }
    let magic = &bytes[..8];
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let (payload_offset, selector) = match (bytes.len(), magic, version) {
        (MODEL_V1_BYTES, b"FPS26A4\0" | b"FPSENR1\0", 1) => (48, None),
        (MODEL_V2_BYTES, b"FPSENR2\0", 2) => (
            56,
            Some(SinfSelector {
                user: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
                key: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
            }),
        ),
        (MODEL_V3_BYTES, b"FPSENR3\0", 3) => {
            let source_offset = i32::from_le_bytes(bytes[56..60].try_into().unwrap());
            let source_bytes = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
            if bytes[65..68] != [0, 0, 0]
                || source_offset < 0
                || source_bytes != MODEL_V3_SOURCE_BYTES
            {
                bail!("invalid current SINF version 3 geometry");
            }
            (
                68,
                Some(SinfSelector {
                    user: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
                    key: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
                }),
            )
        }
        _ => bail!("invalid current SINF model envelope"),
    };
    if version < 3 {
        validate_permutation_tables("input", &bytes[payload_offset + 32..])?;
    } else {
        let output_start = payload_offset + 16;
        validate_permutation_tables("output", &bytes[output_start..output_start + 4096])?;
        let post_start = output_start + 4096 + MODEL_V3_SOURCE_BYTES;
        validate_permutation_tables("post-codec", &bytes[post_start..])?;
    }
    Ok((version, hex_string(&bytes[16..48]), selector))
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn check_private_permissions(metadata: &fs::Metadata, kind: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "FairPlay enrollment model {kind} must not be accessible by group or other users"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, kind);
    Ok(())
}

pub fn inspect_enrollment_model(path: &Path) -> Result<EnrollmentModelDiagnostic> {
    let metadata = fs::metadata(path).context("inspect FairPlay enrollment model")?;
    if !metadata.is_file() {
        bail!("FairPlay enrollment model is not a regular file");
    }
    check_private_permissions(&metadata, "file")?;
    let bytes = Zeroizing::new(fs::read(path).context("read FairPlay enrollment model")?);
    let (version, fairplayd_sha256, selector) = model_details(bytes.as_slice())?;
    Ok(EnrollmentModelDiagnostic {
        path: path.to_string_lossy().into_owned(),
        sha256: format!("{:x}", Sha256::digest(bytes.as_slice())),
        bytes: bytes.len(),
        version,
        fairplayd_sha256,
        selector,
        selector_id: selector.map(SinfSelector::identifier),
    })
}

pub fn inspect_model_path(path: &Path) -> Result<Vec<EnrollmentModelDiagnostic>> {
    inspect_model_path_with_rules(path, false)
}

pub(crate) fn inspect_model_registry(path: &Path) -> Result<Vec<EnrollmentModelDiagnostic>> {
    inspect_model_path_with_rules(path, true)
}

fn inspect_model_path_with_rules(
    path: &Path,
    registry_rules: bool,
) -> Result<Vec<EnrollmentModelDiagnostic>> {
    let metadata = fs::metadata(path).context("inspect FairPlay enrollment model path")?;
    if !metadata.is_dir() {
        return Ok(vec![inspect_enrollment_model(path)?]);
    }
    check_private_permissions(&metadata, "directory")?;
    let mut result = Vec::new();
    for entry in fs::read_dir(path).context("read FairPlay enrollment model directory")? {
        let entry = entry?;
        let entry_path = entry.path();
        if !entry_path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"))
        {
            continue;
        }
        let file_type = entry.file_type()?;
        if registry_rules && file_type.is_symlink() {
            bail!(
                "FairPlay enrollment model registry contains a symlink: {}",
                entry.file_name().to_string_lossy()
            );
        }
        if file_type.is_dir() {
            continue;
        }
        if registry_rules && result.len() == 256 {
            bail!("FairPlay enrollment model registry contains more than 256 models");
        }
        result.push(inspect_enrollment_model(&entry_path)?);
    }
    if result.is_empty() {
        return Err(anyhow!("model directory contains no .bin models"));
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrollmentCaptureDiagnostic {
    pub product_version: String,
    pub build_version: String,
    pub fairplayd_sha256: String,
    pub fairplay_support: FairPlayBuildSupport,
    pub selector_id: String,
    pub files: usize,
    pub has_ipa: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FairPlayDoctorReport {
    pub schema: &'static str,
    pub created_at: String,
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<FairPlayHostDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<EnrollmentCaptureDiagnostic>,
    pub capture_verified: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sinf: Vec<SinfDiagnostic>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<EnrollmentModelDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatible_model: Option<String>,
    pub checks: BTreeMap<String, bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<String>,
}

/// Diagnose local host, capture, IPA and model compatibility.
pub fn doctor_fairplay(
    capture_path: Option<&Path>,
    ipa_path: Option<&Path>,
    model_path: Option<&Path>,
) -> FairPlayDoctorReport {
    let mut report = FairPlayDoctorReport {
        schema: "ipatool-fairplay-doctor-v1",
        created_at: OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("zero nanoseconds are valid")
            .format(&Rfc3339)
            .unwrap_or_default(),
        ready: false,
        host: None,
        capture: None,
        capture_verified: false,
        sinf: Vec::new(),
        models: Vec::new(),
        compatible_model: None,
        checks: BTreeMap::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
        next_actions: Vec::new(),
    };

    let mut capture_manifest: Option<EnrollmentCaptureManifest> = None;
    let mut resolved_ipa: Option<PathBuf> = ipa_path.map(Path::to_path_buf);
    if capture_path.is_none() {
        match inspect_local_fairplay_host() {
            Ok(host) => {
                report
                    .checks
                    .insert("supported_fairplayd".into(), host.fairplay_support.recovery);
                report.checks.insert(
                    "native_state_accessible".into(),
                    host.state_accessible && host.state_files != 0,
                );
                report
                    .checks
                    .insert("hardware_iomac".into(), host.hardware_iomac_present);
                report.host = Some(host);
            }
            Err(error) if ipa_path.is_none() && model_path.is_none() => {
                report.errors.push(format!("host: {error:#}"))
            }
            Err(_) => {}
        }
    }
    if let Some(path) = capture_path {
        match load_enrollment_capture(path, true) {
            Ok(manifest) => {
                report.capture = Some(EnrollmentCaptureDiagnostic {
                    product_version: manifest.product_version.clone(),
                    build_version: manifest.build_version.clone(),
                    fairplayd_sha256: manifest.fairplayd.sha256.clone(),
                    fairplay_support: manifest.fairplay.clone(),
                    selector_id: manifest.app.selector_id.clone(),
                    files: manifest.files.len(),
                    has_ipa: manifest.ipa.is_some(),
                });
                report.capture_verified = true;
                report.checks.insert("capture_integrity".into(), true);
                report
                    .checks
                    .insert("supported_fairplayd".into(), manifest.fairplay.recovery);
                if !manifest.fairplay.compatibility_sha256.is_empty() && model_path.is_none() {
                    report.warnings.push(format!("this capture requires the checked compatibility evaluator; pass --compat-fairplayd with arm64e SHA-256 {} to fairplay-enroll recover", manifest.fairplay.compatibility_sha256));
                }
                if resolved_ipa.is_none()
                    && let Some(ipa) = manifest.ipa.as_ref()
                {
                    match capture_file_path(path, &ipa.path) {
                        Ok(ipa) => resolved_ipa = Some(ipa),
                        Err(error) => report.errors.push(format!("capture IPA: {error:#}")),
                    }
                }
                capture_manifest = Some(manifest);
            }
            Err(error) => report.errors.push(format!("capture: {error:#}")),
        }
    }
    if let Some(path) = resolved_ipa.as_deref() {
        match inspect_ipa_sinfs(path) {
            Ok(sinfs) => {
                let current = sinfs.iter().all(|sinf| sinf.current_layout);
                report.checks.insert("ipa_sinf".into(), true);
                report.checks.insert("current_sinf_layout".into(), current);
                if !current {
                    report
                        .warnings
                        .push("one or more SINF files use an unsupported or legacy layout".into());
                }
                report.sinf = sinfs;
            }
            Err(error) => report.errors.push(format!("ipa: {error:#}")),
        }
    }
    if !report.sinf.is_empty() || capture_manifest.is_some() {
        report.warnings.push("SINF geometry cannot prove account age; current support assumes a newly created, natively enrolled Apple Account".into());
    }
    if let Some(path) = model_path {
        match inspect_model_path(path) {
            Ok(models) => {
                report.checks.insert("model_valid".into(), true);
                report.models = models;
            }
            Err(error) => report.errors.push(format!("model: {error:#}")),
        }
    }
    if !report.sinf.is_empty() && !report.models.is_empty() {
        report.compatible_model = report.models.iter().find_map(|model| {
            let id = model.selector_id.as_deref()?;
            let build_matches = capture_manifest.as_ref().is_none_or(|capture| {
                model_matches_capture_build(&model.fairplayd_sha256, capture)
            });
            (build_matches && report.sinf.iter().any(|sinf| sinf.selector_id == id))
                .then(|| model.path.clone())
        });
        let matched = report.compatible_model.is_some();
        report.checks.insert("selector_match".into(), matched);
        if !matched {
            report
                .errors
                .push("no enrollment model matches the IPA SINF selector".into());
        }
    }
    if let Some(capture) = capture_manifest.as_ref()
        && !report.sinf.is_empty()
    {
        let matched = report
            .sinf
            .iter()
            .any(|sinf| sinf.selector == capture.app.selector);
        report
            .checks
            .insert("capture_selector_match".into(), matched);
        if !matched {
            report
                .errors
                .push("capture selector does not match the IPA".into());
        }
    }
    match capture_manifest.as_ref() {
        None => {
            if report
                .host
                .as_ref()
                .is_some_and(|host| !host.state_accessible)
            {
                report
                    .next_actions
                    .push("rerun collection with permission to read /private/var/db/fpsd".into());
            }
            report
                .next_actions
                .push("collect native enrollment with fairplay-enroll collect".into());
        }
        Some(capture) if !capture.fairplay.recovery => report
            .next_actions
            .push("add and validate an exact evaluator for this fairplayd hash".into()),
        Some(capture) if model_path.is_none() => {
            if capture.fairplay.compatibility_sha256.is_empty() {
                report
                    .next_actions
                    .push("recover fairplay-enrollment.bin with fairplay-enroll recover".into());
            } else {
                report.next_actions.push("recover fairplay-enrollment.bin with fairplay-enroll recover --compat-fairplayd /private/path/fairplayd.arm64e".into());
            }
        }
        Some(_) => {}
    }
    if report.compatible_model.is_some() {
        report
            .next_actions
            .push("run fairplay-decrypt with the compatible model".into());
    }
    report.ready = if !report.sinf.is_empty() || capture_manifest.is_some() || model_path.is_some()
    {
        report.errors.is_empty()
            && report.checks.get("current_sinf_layout") == Some(&true)
            && (capture_manifest.is_none()
                || report.checks.get("capture_integrity") == Some(&true)
                    && report.checks.get("supported_fairplayd") == Some(&true)
                    && report.checks.get("capture_selector_match") == Some(&true))
            && (model_path.is_none() || report.checks.get("selector_match") == Some(&true))
    } else if report.host.is_some() {
        report.checks.get("supported_fairplayd") == Some(&true)
            && report.checks.get("native_state_accessible") == Some(&true)
            && report.checks.get("hardware_iomac") == Some(&true)
    } else {
        false
    };
    report
}

pub fn write_doctor_report(path: &Path, report: &FairPlayDoctorReport) -> Result<()> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(path)
        .with_context(|| format!("create private report: {}", path.display()))?;
    serde_json::to_writer_pretty(&mut output, report)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn atom(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
        data.extend_from_slice(typ);
        data.extend_from_slice(payload);
        data
    }

    fn sinf(selector: SinfSelector, private_size: usize) -> Vec<u8> {
        let mut fields = atom(b"user", &selector.user.to_be_bytes());
        fields.extend(atom(b"key ", &selector.key.to_be_bytes()));
        fields.extend(atom(b"priv", &vec![0; private_size]));
        atom(b"sinf", &atom(b"schi", &fields))
    }

    fn model(selector: SinfSelector) -> Vec<u8> {
        let mut bytes = vec![0; MODEL_V2_BYTES];
        bytes[..8].copy_from_slice(b"FPSENR2\0");
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(MODEL_V2_BYTES as u32).to_le_bytes());
        bytes[48..52].copy_from_slice(&selector.user.to_le_bytes());
        bytes[52..56].copy_from_slice(&selector.key.to_le_bytes());
        for table in bytes[88..].as_chunks_mut::<256>().0 {
            for (index, byte) in table.iter_mut().enumerate() {
                *byte = index as u8;
            }
        }
        bytes
    }

    #[test]
    fn parses_selector_and_current_layout() {
        let selector = SinfSelector {
            user: 0x12345678,
            key: 2,
        };
        let bytes = sinf(selector, 448);
        assert_eq!(parse_sinf_selector(&bytes).unwrap(), selector);
        let diagnostic = inspect_sinf(&bytes).unwrap();
        assert!(diagnostic.current_layout);
        assert_eq!(diagnostic.selector_id, "12345678:00000002");
        assert_eq!(diagnostic.private_bytes, 448);
        assert!(!diagnostic.legacy_markers);
    }

    #[test]
    fn rejects_truncated_and_duplicate_atoms() {
        let selector = SinfSelector { user: 1, key: 2 };
        let mut bytes = sinf(selector, 440);
        bytes.pop();
        assert!(inspect_sinf(&bytes).is_err());
        let mut fields = atom(b"user", &1u32.to_be_bytes());
        fields.extend(atom(b"user", &1u32.to_be_bytes()));
        fields.extend(atom(b"key ", &2u32.to_be_bytes()));
        assert!(parse_sinf_selector(&atom(b"sinf", &atom(b"schi", &fields))).is_err());
    }

    #[test]
    fn inspects_ipa_sinfs_in_path_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.ipa");
        let file = fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for name in [
            "Payload/B.app/SC_Info/B.sinf",
            "Payload/A.app/SC_Info/A.sinf",
        ] {
            zip.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(&sinf(SinfSelector { user: 1, key: 2 }, 448))
                .unwrap();
        }
        zip.finish().unwrap();
        let diagnostics = inspect_ipa_sinfs(&path).unwrap();
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].path.as_deref(),
            Some("Payload/A.app/SC_Info/A.sinf")
        );
    }

    #[test]
    fn inspects_duplicate_sinf_members_in_archive_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("duplicate.ipa");
        let first = sinf(SinfSelector { user: 1, key: 2 }, 440);
        let second = sinf(SinfSelector { user: 3, key: 4 }, 448);
        crate::duplicate_zip::write_duplicate_sinf_fixture(&path, &first, &second);
        let diagnostics = inspect_ipa_sinfs(&path).unwrap();
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].selector.user, 1);
        assert_eq!(diagnostics[1].selector.user, 3);

        crate::duplicate_zip::write_duplicate_sinf_fixture(&path, b"bad", &second);
        assert!(inspect_ipa_sinfs(&path).is_err());
    }

    #[test]
    fn reports_non_utf8_zip_name_like_go() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("non-utf8.ipa");
        let file = fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "Payload/A.app/SC_Info/A.sinf",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(&sinf(SinfSelector { user: 1, key: 2 }, 448))
            .unwrap();
        zip.finish().unwrap();
        crate::duplicate_zip::replace_fixture_filename_bytes(&path, b"/A.sinf", b"/\x82.sinf");

        let diagnostics = inspect_ipa_sinfs(&path).unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].path.as_deref(),
            Some("Payload/A.app/SC_Info/\u{fffd}.sinf")
        );
    }

    #[test]
    fn ignores_unicode_path_extra_field_like_go() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unicode-path.ipa");
        let bytes = sinf(SinfSelector { user: 1, key: 2 }, 448);
        crate::duplicate_zip::write_unicode_path_fixture(&path, &bytes);

        let diagnostics = inspect_ipa_sinfs(&path).unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].path.as_deref(),
            Some("Payload/A.app/SC_Info/A.sinf")
        );
    }

    #[test]
    fn matches_go_unicode_lowercase_for_sinf_extension() {
        assert!(has_sinf_extension("A.SİNF"));
        assert!(!has_sinf_extension("A.ſinf"));
        assert!(!is_sinf_extension_equal_fold("SİNF"));
        assert!(is_sinf_extension_equal_fold("ſinf"));
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.ipa");
        let file = fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for name in [
            "Payload/A.app/SC_Info/A.SİNF",
            "Payload/A.app/SC_Info/A.Si\u{307}nf",
        ] {
            zip.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(&sinf(SinfSelector { user: 1, key: 2 }, 440))
                .unwrap();
        }
        zip.finish().unwrap();
        let diagnostics = inspect_ipa_sinfs(&path).unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].path.as_deref(),
            Some("Payload/A.app/SC_Info/A.SİNF")
        );
    }

    #[test]
    fn checks_model_selector_permutations_and_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("model.bin");
        let selector = SinfSelector {
            user: 0x12345678,
            key: 2,
        };
        fs::write(&path, model(selector)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let diagnostic = inspect_enrollment_model(&path).unwrap();
        assert_eq!(diagnostic.selector, Some(selector));
        assert_eq!(diagnostic.version, 2);
        let mut invalid = model(selector);
        invalid[89] = invalid[88];
        fs::write(&path, invalid).unwrap();
        assert!(inspect_enrollment_model(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(inspect_enrollment_model(&path).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn model_directory_diagnostics_are_sorted_by_path() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for (name, user) in [("z.bin", 2), ("a.bin", 1)] {
            let path = directory.path().join(name);
            fs::write(&path, model(SinfSelector { user, key: 3 })).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let names: Vec<_> = inspect_model_registry(directory.path())
            .unwrap()
            .into_iter()
            .map(|diagnostic| {
                Path::new(&diagnostic.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["a.bin", "z.bin"]);
    }

    #[cfg(unix)]
    #[test]
    fn model_registry_rejects_symlinks_and_more_than_256_models() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let model_path = directory.path().join("model.bin");
        fs::write(&model_path, model(SinfSelector { user: 1, key: 2 })).unwrap();
        fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();

        let link_path = directory.path().join("linked.bin");
        symlink(&model_path, &link_path).unwrap();
        assert_eq!(inspect_model_path(directory.path()).unwrap().len(), 2);
        let error = inspect_model_registry(directory.path()).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error:#}");
        fs::remove_file(link_path).unwrap();

        for index in 0..256 {
            fs::hard_link(&model_path, directory.path().join(format!("{index}.bin"))).unwrap();
        }
        assert!(
            inspect_model_registry(directory.path())
                .unwrap_err()
                .to_string()
                .contains("more than 256 models")
        );
    }

    #[test]
    fn doctor_matches_ipa_sinf_to_private_model() {
        let directory = tempfile::tempdir().unwrap();
        let ipa = directory.path().join("app.ipa");
        let selector = SinfSelector {
            user: 0x12345678,
            key: 2,
        };
        let file = fs::File::create(&ipa).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "Payload/App.app/SC_Info/App.sinf",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(&sinf(selector, 448)).unwrap();
        zip.finish().unwrap();
        let model_path = directory.path().join("model.bin");
        fs::write(&model_path, model(selector)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let report = doctor_fairplay(None, Some(&ipa), Some(&model_path));
        assert!(report.ready, "{:?}", report.errors);
        assert!(report.checks["selector_match"]);
        assert_eq!(
            report.compatible_model.as_deref(),
            Some(model_path.to_str().unwrap())
        );
        let report_path = directory.path().join("reports/doctor.json");
        write_doctor_report(&report_path, &report).unwrap();
        assert!(write_doctor_report(&report_path, &report).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(report_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn doctor_does_not_claim_capture_is_verified() {
        let report = doctor_fairplay(Some(Path::new("capture")), None, None);
        assert!(!report.ready);
        assert!(!report.capture_verified);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.starts_with("capture:"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn doctor_verifies_capture_and_uses_its_ipa() {
        use std::os::unix::fs::PermissionsExt;

        use crate::capture::{
            CaptureApp, CaptureFile, ENROLLMENT_CAPTURE_SCHEMA, FAIRPLAY_BUILD_26A428_HASH,
        };

        let directory = tempfile::tempdir().unwrap();
        let capture = directory.path().join("capture");
        fs::create_dir(&capture).unwrap();
        fs::set_permissions(&capture, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(capture.join("ipa")).unwrap();
        let ipa = capture.join("ipa/App.ipa");
        let selector = SinfSelector {
            user: 0x12345678,
            key: 2,
        };
        let file = fs::File::create(&ipa).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "Payload/App.app/SC_Info/App.sinf",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(&sinf(selector, 448)).unwrap();
        zip.finish().unwrap();
        fs::set_permissions(&ipa, fs::Permissions::from_mode(0o600)).unwrap();

        let ipa_bytes = fs::read(&ipa).unwrap();
        let ipa_entry = CaptureFile {
            path: "ipa/App.ipa".into(),
            bytes: ipa_bytes.len() as i64,
            sha256: format!("{:x}", Sha256::digest(&ipa_bytes)),
            mode: "0600".into(),
        };
        let manifest = EnrollmentCaptureManifest {
            schema: ENROLLMENT_CAPTURE_SCHEMA.into(),
            fairplayd: CaptureFile {
                sha256: FAIRPLAY_BUILD_26A428_HASH.into(),
                ..CaptureFile::default()
            },
            app: CaptureApp {
                selector,
                selector_id: selector.identifier(),
                ..CaptureApp::default()
            },
            ipa: Some(ipa_entry.clone()),
            files: vec![ipa_entry],
            ..EnrollmentCaptureManifest::default()
        };
        fs::write(
            capture.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let model_path = directory.path().join("model.bin");
        let mut model_bytes = model(selector);
        for (index, pair) in FAIRPLAY_BUILD_26A428_HASH
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
        {
            model_bytes[16 + index] =
                u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        fs::write(&model_path, model_bytes).unwrap();
        fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();

        let report = doctor_fairplay(Some(&capture), None, Some(&model_path));
        assert!(report.ready, "{:?}", report.errors);
        assert!(report.capture_verified);
        assert!(report.checks["capture_selector_match"]);
        assert!(report.checks["selector_match"]);
    }
}
