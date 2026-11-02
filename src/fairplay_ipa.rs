//! Apply a local enrollment model to all encrypted Mach-O images in an IPA.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::{ZipArchive, ZipWriter, read::ZipFile, write::FullFileOptions};

use crate::{
    fairplay::{
        EnrollmentModelDiagnostic, inspect_model_path, inspect_model_registry, parse_sinf_selector,
    },
    fairplay_decrypt::{DecryptedSlice, decrypt_macho},
    fairplay_key::{CurrentSinfModel, missing_model_diagnostic},
    fairplay_macho::{MachOSlice, is_macho, parse_macho_slices, parse_macho_slices_probe},
    fairplay_page::{PageKeyDeriver, app_mask_from_logical_key},
    fairplay_supf::{PAGE_BYTES, Supf},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IpaDecryptResult {
    pub encrypted_images: usize,
    pub decrypted_pages: usize,
    pub output_sha256: String,
    pub plaintext_verified: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ImageReport {
    member: String,
    supf_member: String,
    key_table_variant: u8,
    key_table_envelope_verified: bool,
    key_table_signature_binding: &'static str,
    sinf_member: String,
    logical_key_sha256: String,
    architecture: String,
    cpu_type: u32,
    cpu_subtype: u32,
    slice_offset: usize,
    slice_size: usize,
    encrypted_sha256: String,
    decrypted_sha256: String,
    cryptoff: usize,
    cryptsize: usize,
    pages: usize,
    first_plaintext_page_sha256: String,
    plaintext_validation: &'static str,
    pre_encryption_code_directories: Vec<crate::fairplay_codesign::CodeDirectoryAudit>,
    ordered_page_keys_sha256: String,
    app_mask_sha256: String,
    code_directories: Vec<crate::fairplay_codesign::CodeDirectoryAudit>,
    cryptid_before: u32,
    cryptid_after: u32,
    exact_mutation_scope: bool,
}

#[derive(Serialize)]
struct ReportFile {
    path: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'static str>,
}

#[derive(Clone, Serialize)]
struct OracleEvidence {
    device_state_imported: bool,
    fairplayd_sha256: String,
    hardware_backend: &'static str,
    logical_key_sha256: String,
    model_name: String,
    model_sha256: String,
    model_version: u32,
    provider_kind: &'static str,
    provider_status: u32,
    request_ipa_sha256: String,
    request_selector: String,
    request_sinf_sha256: String,
    runtime_hardware_calls: u32,
    selector_status: u32,
    state_origin: &'static str,
    status_patched: bool,
}

#[derive(Serialize)]
struct DecryptionReport {
    schema: &'static str,
    model_build: String,
    input: ReportFile,
    output: ReportFile,
    provider: &'static str,
    oracle: serde_json::Value,
    licenses: Vec<LicenseReport>,
    encrypted_image_count: usize,
    decrypted_page_count: usize,
    images: Vec<ImageReport>,
    complete: bool,
    plaintext_verified: bool,
    signature_verified: bool,
    warnings: [&'static str; 4],
}

fn raw_member_name(source: &mut File, member: &ZipFile<'_, File>) -> Result<String> {
    let raw = crate::duplicate_zip::read_raw_central_name(source, member.central_header_start())?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

fn read_entry(archive: &mut ZipArchive<File>, source: &mut File, name: &str) -> Result<Vec<u8>> {
    let mut selected = None;
    for index in 0..archive.len() {
        let member = archive.by_index_raw(index)?;
        if raw_member_name(source, &member)? == name {
            selected = Some(index);
            break;
        }
    }
    let index = selected.with_context(|| format!("open IPA member {name}"))?;
    let mut entry = archive.by_index(index)?;
    let limit = if crate::fairplay::has_sinf_extension(name) {
        1024 * 1024
    } else if name.ends_with(".plist") {
        4 * 1024 * 1024
    } else {
        128 * 1024 * 1024
    };
    if entry.size() > limit {
        bail!("IPA license member exceeds its size limit");
    }
    let mut bytes = Vec::new();
    crate::application::operation::copy(&mut (&mut entry).take(limit + 1), &mut bytes)
        .with_context(|| format!("read IPA member {name}"))?;
    if bytes.len() as u64 > limit {
        bail!("IPA license member grew beyond its size limit");
    }
    Ok(bytes)
}

struct ImageBinding {
    sinf_member: String,
    supf_member: String,
    table: Supf,
    encrypted_slices: usize,
}

struct Inventory {
    images: BTreeMap<String, ImageBinding>,
    sinfs: BTreeSet<String>,
}

pub fn required_ipa_sinfs(input: &Path) -> Result<Vec<crate::fairplay::SinfDiagnostic>> {
    required_ipa_sinfs_for(input, None)
}

pub(crate) fn required_ipa_sinf_for_image(
    input: &Path,
    image: &str,
) -> Result<crate::fairplay::SinfDiagnostic> {
    required_ipa_sinfs_for(input, Some(image))?
        .pop()
        .context("image has no active license")
}

fn required_ipa_sinfs_for(
    input: &Path,
    image: Option<&str>,
) -> Result<Vec<crate::fairplay::SinfDiagnostic>> {
    let mut raw = File::open(input)?;
    let mut archive = ZipArchive::new(File::open(input)?)?;
    validate_unique_zip_members(&mut raw, &archive)?;
    let inventory = preflight_encrypted_images(
        &mut archive,
        &mut raw,
        &crate::fairplay_scinfo::Trust::pinned(),
    )?;
    let sinfs = if let Some(image) = image {
        BTreeSet::from([inventory
            .images
            .get(image)
            .context("main executable is not an inventoried encrypted image")?
            .sinf_member
            .clone()])
    } else {
        inventory.sinfs
    };
    sinfs
        .iter()
        .map(|name| {
            let bytes = Zeroizing::new(read_entry(&mut archive, &mut raw, name)?);
            let mut diagnostic = crate::fairplay::inspect_sinf(&bytes)?;
            diagnostic.path = Some(name.clone());
            Ok(diagnostic)
        })
        .collect()
}

pub fn require_model_diagnostic(input: &Path) -> Result<String> {
    let source = File::open(input).with_context(|| format!("open IPA {}", input.display()))?;
    let mut directory_source = File::open(input).context("open IPA ZIP directory handle")?;
    let mut archive = ZipArchive::new(source).context("open IPA ZIP archive")?;
    validate_unique_zip_members(&mut directory_source, &archive)?;
    let inventory = preflight_encrypted_images(
        &mut archive,
        &mut directory_source,
        &crate::fairplay_scinfo::Trust::pinned(),
    )?;
    let mut diagnostics = Vec::new();
    for name in &inventory.sinfs {
        let sinf = Zeroizing::new(read_entry(&mut archive, &mut directory_source, name)?);
        diagnostics.push(format!("{name}: {}", missing_model_diagnostic(&sinf)?));
    }
    Ok(diagnostics.join("\n"))
}

// zip's public file list is keyed by name and silently replaces duplicate
// central-directory entries. Only repeated empty directory markers are harmless.
fn validate_unique_zip_members(source: &mut File, archive: &ZipArchive<File>) -> Result<()> {
    source.seek(SeekFrom::Start(archive.central_directory_start()))?;
    let mut names = BTreeMap::new();
    let mut count = 0usize;
    loop {
        let mut signature = [0u8; 4];
        source.read_exact(&mut signature)?;
        if signature != *b"PK\x01\x02" {
            break;
        }
        let mut header = [0u8; 42];
        source.read_exact(&mut header)?;
        let name_len = u16::from_le_bytes(header[24..26].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(header[26..28].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(header[28..30].try_into().unwrap()) as usize;
        let mut name = vec![0; name_len];
        source.read_exact(&mut name)?;
        let mut extra = vec![0; extra_len];
        source.read_exact(&mut extra)?;
        let empty = empty_directory_marker(&name, &header, &extra)?;
        if let Some(previous_empty) = names.insert(name.clone(), empty)
            && !(empty && previous_empty)
        {
            bail!("duplicate IPA member {:?}", String::from_utf8_lossy(&name));
        }
        source.seek(SeekFrom::Current(comment_len as i64))?;
        count += 1;
        if count > 250_000 {
            bail!("IPA ZIP central directory exceeds its member limit");
        }
    }
    if names.len() != archive.len() {
        bail!("IPA ZIP central directory member count is inconsistent");
    }
    Ok(())
}

fn empty_directory_marker(name: &[u8], header: &[u8; 42], extra: &[u8]) -> Result<bool> {
    if !name.ends_with(b"/") {
        return Ok(false);
    }
    let size = u32::from_le_bytes(header[20..24].try_into().unwrap());
    if size != u32::MAX {
        return Ok(size == 0);
    }
    let mut remaining = extra;
    let mut size64 = None;
    while !remaining.is_empty() {
        if remaining.len() < 4 {
            bail!("truncated directory ZIP extra field");
        }
        let id = u16::from_le_bytes(remaining[..2].try_into().unwrap());
        let length = u16::from_le_bytes(remaining[2..4].try_into().unwrap()) as usize;
        let payload = remaining
            .get(4..4 + length)
            .context("invalid directory ZIP extra extent")?;
        if id == 1 {
            if size64.is_some() || payload.len() < 8 {
                bail!("ambiguous directory ZIP64 size");
            }
            size64 = Some(u64::from_le_bytes(payload[..8].try_into().unwrap()));
        }
        remaining = &remaining[4 + length..];
    }
    Ok(size64.context("missing directory ZIP64 size")? == 0)
}

fn read_macho_probe(member: &mut ZipFile<'_, File>) -> Result<Vec<u8>> {
    let total_size = usize::try_from(member.size()).context("Mach-O member exceeds platform")?;
    let mut header = vec![0; total_size.min(32)];
    member.read_exact(&mut header)?;
    if header.len() < 4 || !is_macho(&header) {
        return Ok(header);
    }
    let magic = u32::from_le_bytes(header[..4].try_into().unwrap());
    if matches!(magic, 0xfeedface | 0xfeedfacf) {
        let header_size = if magic == 0xfeedfacf { 32 } else { 28 };
        if header.len() < header_size {
            return Ok(header);
        }
        let command_bytes = u32::from_le_bytes(header[20..24].try_into().unwrap()) as usize;
        let required = header_size
            .checked_add(command_bytes)
            .context("Mach-O load-command extent overflow")?;
        if required > 1024 * 1024 || required > total_size {
            bail!("Mach-O load-command extent is invalid");
        }
        if required > header.len() {
            let previous = header.len();
            header.resize(required, 0);
            member.read_exact(&mut header[previous..])?;
        }
    } else if matches!(
        u32::from_be_bytes(header[..4].try_into().unwrap()),
        0xcafebabe | 0xcafebabf | 0xbebafeca | 0xbfbafeca
    ) {
        member.read_to_end(&mut header)?;
    }
    Ok(header)
}

fn preflight_encrypted_images(
    archive: &mut ZipArchive<File>,
    source: &mut File,
    trust: &crate::fairplay_scinfo::Trust,
) -> Result<Inventory> {
    if archive.len() > 250_000 {
        bail!("IPA exceeds the supported member count");
    }
    let mut names = HashSet::with_capacity(archive.len());
    for index in 0..archive.len() {
        let member = archive.by_index(index).context("inspect IPA ZIP member")?;
        let name = raw_member_name(source, &member)?;
        if !names.insert(name.clone()) {
            bail!("duplicate IPA member {name:?}");
        }
    }
    let mappings = crate::fairplay_licenses::associations(&names, |name| {
        read_entry(archive, source, name).map(Zeroizing::new)
    })?;
    let mut inventory = Inventory {
        images: BTreeMap::new(),
        sinfs: BTreeSet::new(),
    };
    let mut table_bytes = 0usize;
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).context("inspect IPA ZIP member")?;
        let name = raw_member_name(source, &member)?;
        if name.ends_with('/') {
            continue;
        }
        let total_size =
            usize::try_from(member.size()).context("Mach-O member exceeds platform")?;
        let probe = read_macho_probe(&mut member).with_context(|| format!("inspect {name}"))?;
        drop(member);
        if !is_macho(&probe) {
            continue;
        }
        let slices = parse_macho_slices_probe(&probe, total_size)
            .with_context(|| format!("inspect {name}"))?;
        let encrypted: Vec<_> = slices
            .iter()
            .filter(|slice| slice.layout.crypt_id != 0)
            .collect();
        if encrypted.is_empty() {
            continue;
        }
        let (supf_name, supf) = crate::fairplay_key_tables::select(
            &name,
            &names,
            &slices,
            |path| read_entry(archive, source, path),
            trust,
        )
        .with_context(|| format!("key table for {name}"))?;
        if supf.universal_signature_sha1.is_some() {
            // Universal probes retain every slice. Check the whole-file SUPP
            // binding before resolving models or creating output staging.
            supf.validate_signature_bindings(&probe, &slices)?;
        }
        for architecture in &supf.architectures {
            table_bytes = table_bytes
                .checked_add(architecture.records.len() * 32)
                .context("IPA key-table size overflow")?;
        }
        if table_bytes > 256 * 1024 * 1024 {
            bail!("IPA key tables exceed their total size limit");
        }
        let sinf_member = crate::fairplay_licenses::image_license(&name, &names, &mappings)
            .with_context(|| format!("license for {name}"))?;
        let encrypted_slices = encrypted.len();
        for slice in encrypted {
            let records = supf.records_for(slice.layout.cpu_type, slice.layout.cpu_subtype)?;
            if records.len() != slice.layout.crypt_size / PAGE_BYTES {
                bail!(
                    "{name}: SUPF page count mismatch for architecture {:#x}/{:#x}",
                    slice.layout.cpu_type,
                    slice.layout.cpu_subtype
                );
            }
        }
        inventory.sinfs.insert(sinf_member.clone());
        inventory.images.insert(
            name,
            ImageBinding {
                sinf_member,
                supf_member: supf_name,
                table: supf,
                encrypted_slices,
            },
        );
    }
    if inventory.images.is_empty() {
        bail!("IPA contains no supported encrypted Mach-O images");
    }
    Ok(inventory)
}

fn local_extra(source: &mut File, member: &ZipFile<'_, File>) -> Result<Vec<u8>> {
    source.seek(SeekFrom::Start(member.header_start()))?;
    let mut header = [0u8; 30];
    source.read_exact(&mut header)?;
    if header[..4] != [0x50, 0x4b, 0x03, 0x04] {
        bail!("IPA member has an invalid local ZIP header");
    }
    let name_len = u16::from_le_bytes(header[26..28].try_into().unwrap()) as u64;
    let extra_len = u16::from_le_bytes(header[28..30].try_into().unwrap()) as usize;
    source.seek(SeekFrom::Current(name_len as i64))?;
    let mut extra = vec![0u8; extra_len];
    source.read_exact(&mut extra)?;
    Ok(extra)
}

fn add_extra_fields(
    options: &mut FullFileOptions<'_, '_>,
    extra: &[u8],
    central: bool,
) -> Result<()> {
    let mut cursor = 0;
    while cursor < extra.len() {
        if extra.len() - cursor < 4 {
            bail!("IPA ZIP extra field is truncated");
        }
        let id = u16::from_le_bytes(extra[cursor..cursor + 2].try_into().unwrap());
        let length = u16::from_le_bytes(extra[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if length > extra.len() - cursor {
            bail!("IPA ZIP extra field has invalid length");
        }
        options.add_extra_field(id, &extra[cursor..cursor + length], central)?;
        cursor += length;
    }
    Ok(())
}

fn without_zip64(extra: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while cursor < extra.len() {
        if extra.len() - cursor < 4 {
            bail!("IPA ZIP extra field is truncated");
        }
        let id = u16::from_le_bytes(extra[cursor..cursor + 2].try_into().unwrap());
        let length = u16::from_le_bytes(extra[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
        let end = cursor + 4 + length;
        if end > extra.len() {
            bail!("IPA ZIP extra field has invalid length");
        }
        if id != 0x0001 {
            result.extend_from_slice(&extra[cursor..end]);
        }
        cursor = end;
    }
    Ok(result)
}

fn full_options(
    member: &ZipFile<'_, File>,
    local: &[u8],
    central: &[u8],
) -> Result<FullFileOptions<'static, 'static>> {
    let mut options = FullFileOptions::default()
        .compression_method(member.compression())
        .unix_permissions(member.unix_mode().unwrap_or(0o644))
        .large_file(member.size().max(member.compressed_size()) >= u32::MAX as u64)
        .last_modified_time(member.last_modified().unwrap_or_default());
    let local = without_zip64(local)?;
    let central = without_zip64(central)?;
    let central_only = central
        .strip_prefix(local.as_slice())
        .context("IPA ZIP central extras do not contain the local extras as a prefix")?;
    add_extra_fields(&mut options, &local, false)?;
    add_extra_fields(&mut options, central_only, true)?;
    Ok(options)
}

fn write_reencoded(
    writer: &mut ZipWriter<crate::application::operation::CancellableWriter<File>>,
    member: &mut ZipFile<'_, File>,
    name: &str,
    local: &[u8],
    central: &[u8],
    prefix: &[u8],
    rest: Option<&[u8]>,
) -> Result<()> {
    let options = full_options(member, local, central)?;
    writer.start_file(name, options)?;
    writer.write_all(prefix)?;
    if let Some(bytes) = rest {
        writer.write_all(bytes)?;
    } else {
        crate::application::operation::copy(member, writer)?;
    }
    Ok(())
}

fn macho_architecture(cpu_type: u32, cpu_subtype: u32) -> String {
    match cpu_type {
        0x0c => match cpu_subtype & 0xff {
            6 => "armv6".to_owned(),
            9 => "armv7".to_owned(),
            10 => "armv7f".to_owned(),
            11 => "armv7s".to_owned(),
            12 => "armv7k".to_owned(),
            13 => "armv8".to_owned(),
            _ => "arm".to_owned(),
        },
        0x0100_000c if cpu_subtype & 0xff == 2 => "arm64e".to_owned(),
        0x0100_000c => "arm64".to_owned(),
        0x0200_000c => "arm64_32".to_owned(),
        _ => format!("cpu-{cpu_type:#x}"),
    }
}

struct ImageReportContext<'a> {
    member: &'a str,
    supf_member: &'a str,
    sinf_member: &'a str,
    logical_key_sha256: &'a str,
    before: &'a [u8],
    after: &'a [u8],
    supf: &'a Supf,
    deriver: &'a PageKeyDeriver,
    app_mask_sha256: &'a str,
}

fn image_report(
    context: &ImageReportContext<'_>,
    slice: &MachOSlice,
    decrypted: DecryptedSlice,
) -> Result<ImageReport> {
    let layout = &slice.layout;
    let id = layout.crypt_id_offset;
    let start = layout.crypt_offset;
    let end = start + layout.crypt_size;
    if context.before.len() != context.after.len()
        || end > context.before.len()
        || id + 4 > start
        || context.before[..id] != context.after[..id]
        || context.before[id + 4..start] != context.after[id + 4..start]
        || context.before[end..] != context.after[end..]
    {
        bail!(
            "{}: decryption escaped the FairPlay mutation range",
            context.member
        );
    }
    let cryptid_after = u32::from_le_bytes(context.after[id..id + 4].try_into().unwrap());
    if cryptid_after != 0 {
        bail!(
            "{}: decrypted Mach-O still has a nonzero cryptid",
            context.member
        );
    }
    let records = context
        .supf
        .records_for(layout.cpu_type, layout.cpu_subtype)?;
    let offset = (slice.offset + layout.crypt_offset) as u64;
    let mut keys_hash = Sha256::new();
    for (index, record) in records.iter().enumerate() {
        crate::application::operation::check()?;
        let key = Zeroizing::new(context.deriver.page_key(
            record[..16].try_into().unwrap(),
            offset + (index * PAGE_BYTES) as u64,
        ));
        keys_hash.update(&key[..]);
    }
    Ok(ImageReport {
        member: context.member.to_owned(),
        supf_member: context.supf_member.to_owned(),
        key_table_variant: context.supf.variant,
        key_table_envelope_verified: matches!(context.supf.variant, 1 | 4),
        key_table_signature_binding: if context.supf.universal_signature_sha1.is_some() {
            "universal-code-signatures-sha1"
        } else if context.supf.architectures.iter().any(|arch| {
            arch.cpu_type == layout.cpu_type
                && arch.cpu_subtype == layout.cpu_subtype
                && arch.signature_sha1.is_some()
        }) {
            "slice-code-signature-sha1"
        } else {
            "not-present"
        },
        sinf_member: context.sinf_member.to_owned(),
        logical_key_sha256: context.logical_key_sha256.to_owned(),
        architecture: macho_architecture(layout.cpu_type, layout.cpu_subtype),
        cpu_type: layout.cpu_type,
        cpu_subtype: layout.cpu_subtype,
        slice_offset: slice.offset,
        slice_size: slice.size,
        encrypted_sha256: decrypted.encrypted_sha256,
        decrypted_sha256: decrypted.decrypted_sha256,
        cryptoff: layout.crypt_offset,
        cryptsize: layout.crypt_size,
        pages: decrypted.pages,
        first_plaintext_page_sha256: decrypted.first_plaintext_page_sha256,
        plaintext_validation: if decrypted.plaintext_verified {
            "code-directory-pre-encryption-hashes"
        } else {
            "unavailable-no-pre-encryption-hashes"
        },
        pre_encryption_code_directories: decrypted.pre_encryption_code_directories,
        ordered_page_keys_sha256: format!("{:x}", keys_hash.finalize()),
        app_mask_sha256: context.app_mask_sha256.to_owned(),
        code_directories: decrypted.code_directories,
        cryptid_before: layout.crypt_id,
        cryptid_after,
        exact_mutation_scope: true,
    })
}

struct LoadedModel {
    diagnostic: EnrollmentModelDiagnostic,
    bytes: Zeroizing<Vec<u8>>,
}

struct ModelRegistry {
    models: Vec<LoadedModel>,
}

impl ModelRegistry {
    fn load(path: &Path) -> Result<Self> {
        let directory = fs::metadata(path)
            .context("inspect FairPlay enrollment model path")?
            .is_dir();
        let diagnostics = if directory {
            inspect_model_registry(path)?
        } else {
            inspect_model_path(path)?
        };
        if directory && diagnostics.iter().any(|model| model.selector.is_none()) {
            bail!("FairPlay version 1 model cannot be used in a registry");
        }
        let mut models = Vec::with_capacity(diagnostics.len());
        for diagnostic in diagnostics {
            crate::application::operation::check()?;
            let bytes = crate::fairplay_recovery_output::read_private_bytes(
                Path::new(&diagnostic.path),
                16 * 1024,
            )?;
            if format!("{:x}", Sha256::digest(&*bytes)) != diagnostic.sha256 {
                bail!("selected FairPlay model changed during resolution");
            }
            models.push(LoadedModel { diagnostic, bytes });
        }
        Ok(Self { models })
    }

    fn logical_key(&self, sinf: &[u8]) -> Result<([u8; 16], EnrollmentModelDiagnostic)> {
        let selector = parse_sinf_selector(sinf)?;
        let compatible: Vec<_> = self
            .models
            .iter()
            .filter(|model| {
                model
                    .diagnostic
                    .selector
                    .is_none_or(|bound| bound == selector)
            })
            .collect();
        let [selected] = compatible.as_slice() else {
            bail!(
                "FairPlay model path has {} models compatible with selector {}; expected one",
                compatible.len(),
                selector.identifier()
            );
        };
        let key = CurrentSinfModel::parse(&selected.bytes)?.logical_key(sinf)?;
        Ok((key, selected.diagnostic.clone()))
    }
}

#[cfg(test)]
fn logical_key(model_path: &Path, sinf: &[u8]) -> Result<([u8; 16], EnrollmentModelDiagnostic)> {
    ModelRegistry::load(model_path)?.logical_key(sinf)
}

struct IpaLicense {
    key: Zeroizing<[u8; 16]>,
    deriver: PageKeyDeriver,
    logical_key_sha256: String,
    app_mask_sha256: String,
}

#[derive(Serialize)]
struct LicenseReport {
    member: String,
    provider: &'static str,
    model_build: String,
    logical_key_sha256: String,
    oracle: OracleEvidence,
}

fn resolve_licenses(
    inventory: &Inventory,
    archive: &mut ZipArchive<File>,
    source: &mut File,
    model_path: &Path,
    input_sha256: &str,
) -> Result<(BTreeMap<String, IpaLicense>, Vec<LicenseReport>)> {
    if inventory.sinfs.len() > 4096 {
        bail!("IPA requires too many independent licenses");
    }
    // Resolve all licenses against one checked private snapshot of the registry.
    // A model file changing midway cannot mix generations within an output IPA.
    let models = ModelRegistry::load(model_path)?;
    let mut licenses = BTreeMap::new();
    let mut reports = Vec::new();
    for name in &inventory.sinfs {
        crate::application::operation::check()?;
        let sinf = Zeroizing::new(read_entry(archive, source, name)?);
        let (logical, model) = models
            .logical_key(&sinf)
            .with_context(|| format!("resolve license {name}"))?;
        let key = Zeroizing::new(logical);
        let logical_key_sha256 = format!("{:x}", Sha256::digest(key.as_slice()));
        let mask = Zeroizing::new(app_mask_from_logical_key(*key));
        let app_mask_sha256 = format!("{:x}", Sha256::digest(mask.as_slice()));
        let model_name = format!("external-current-sinf-{}", &model.sha256[..16]);
        let provider = if model.version == 3 {
            "current-sinf-whitebox-direct-v3"
        } else {
            "current-sinf-whitebox-direct-v1"
        };
        reports.push(LicenseReport {
            member: name.clone(),
            provider,
            model_build: model_name.clone(),
            logical_key_sha256: logical_key_sha256.clone(),
            oracle: OracleEvidence {
                device_state_imported: false,
                fairplayd_sha256: model.fairplayd_sha256,
                hardware_backend: "none",
                logical_key_sha256: logical_key_sha256.clone(),
                model_name,
                model_sha256: model.sha256,
                model_version: model.version,
                provider_kind: provider,
                provider_status: 0,
                request_ipa_sha256: input_sha256.to_owned(),
                request_selector: parse_sinf_selector(&sinf)?.identifier(),
                request_sinf_sha256: format!("{:x}", Sha256::digest(&*sinf)),
                runtime_hardware_calls: 0,
                selector_status: 0,
                state_origin: "external-enrollment-model",
                status_patched: false,
            },
        });
        let deriver = PageKeyDeriver::from_logical_key(*key);
        licenses.insert(
            name.clone(),
            IpaLicense {
                key,
                deriver,
                logical_key_sha256,
                app_mask_sha256,
            },
        );
    }
    Ok((licenses, reports))
}

/// Decrypt an IPA into a new file. The input is never modified. The model must
/// be a private enrollment file or a private directory containing one match.
pub fn decrypt_ipa(input: &Path, output: &Path, model_path: &Path) -> Result<IpaDecryptResult> {
    decrypt_ipa_with_options(input, output, model_path, None, false)
}

pub fn decrypt_ipa_with_options(
    input: &Path,
    output: &Path,
    model_path: &Path,
    report: Option<&Path>,
    force: bool,
) -> Result<IpaDecryptResult> {
    decrypt_ipa_trusted(
        input,
        output,
        model_path,
        report,
        force,
        &crate::fairplay_scinfo::Trust::pinned(),
    )
}

fn decrypt_ipa_trusted(
    input: &Path,
    output: &Path,
    model_path: &Path,
    report: Option<&Path>,
    force: bool,
    trust: &crate::fairplay_scinfo::Trust,
) -> Result<IpaDecryptResult> {
    crate::application::operation::stage(crate::application::operation::Stage::Decrypting)?;
    validate_destinations(input, output, model_path, report, force)?;
    let source = File::open(input).with_context(|| format!("open IPA {}", input.display()))?;
    let mut raw_source = File::open(input).context("open IPA ZIP directory handle")?;
    let mut archive = ZipArchive::new(source).context("open IPA ZIP archive")?;
    validate_unique_zip_members(&mut raw_source, &archive)?;
    let inventory = preflight_encrypted_images(&mut archive, &mut raw_source, trust)?;
    let input_sha256 = sha256_file(input)?;
    let (licenses, license_reports) = resolve_licenses(
        &inventory,
        &mut archive,
        &mut raw_source,
        model_path,
        &input_sha256,
    )?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let temporary = tempfile::NamedTempFile::new_in(parent).context("create temporary IPA")?;
    let mut writer = ZipWriter::new(crate::application::operation::CancellableWriter(
        temporary.reopen().context("open temporary IPA")?,
    ));
    let mut images = 0usize;
    let mut pages = 0usize;
    let mut image_reports = Vec::new();
    for index in 0..archive.len() {
        crate::application::operation::check()?;
        crate::application::operation::progress(
            crate::application::operation::Stage::Decrypting,
            index as u64,
            Some(archive.len() as u64),
        );
        let mut member = archive.by_index(index).context("read IPA member")?;
        let name = raw_member_name(&mut raw_source, &member)?;
        let local = local_extra(&mut raw_source, &member)?;
        let central = member.extra_data().unwrap_or_default().to_vec();
        let has_extra = !local.is_empty() || !central.is_empty();
        if name.ends_with('/') {
            if has_extra {
                let options = full_options(&member, &local, &central)?;
                writer.add_directory(name, options)?;
            } else {
                writer.raw_copy_file(member)?;
            }
            continue;
        }
        if member.size() < 4 {
            if has_extra {
                write_reencoded(&mut writer, &mut member, &name, &local, &central, &[], None)?;
            } else {
                writer.raw_copy_file(member)?;
            }
            continue;
        }
        let mut prefix = [0u8; 4];
        member.read_exact(&mut prefix)?;
        if !is_macho(&prefix) {
            if has_extra {
                write_reencoded(
                    &mut writer,
                    &mut member,
                    &name,
                    &local,
                    &central,
                    &prefix,
                    None,
                )?;
            } else {
                drop(member);
                writer.raw_copy_file(archive.by_index_raw(index)?)?;
            }
            continue;
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&prefix);
        crate::application::operation::copy(&mut member, &mut blob)
            .with_context(|| format!("read Mach-O IPA member {name}"))?;
        let slices = parse_macho_slices(&blob).with_context(|| format!("inspect {name}"))?;
        let encrypted = slices.iter().any(|slice| slice.layout.crypt_id != 0);
        if !encrypted {
            if has_extra {
                write_reencoded(
                    &mut writer,
                    &mut member,
                    &name,
                    &local,
                    &central,
                    &blob,
                    Some(&[]),
                )?;
            } else {
                drop(member);
                writer.raw_copy_file(archive.by_index_raw(index)?)?;
            }
            continue;
        }
        let options = member.options();
        let rich_options = has_extra
            .then(|| full_options(&member, &local, &central))
            .transpose()?;
        drop(member);
        let binding = inventory
            .images
            .get(&name)
            .context("encrypted image was absent from preflight")?;
        let license = &licenses[&binding.sinf_member];
        let supf_name = &binding.supf_member;
        let supf = &binding.table;
        let (decrypted, reports) =
            decrypt_macho(&blob, supf, *license.key).with_context(|| format!("decrypt {name}"))?;
        if let Some(rich_options) = rich_options {
            writer.start_file(&name, rich_options)
        } else {
            writer.start_file(&name, options)
        }
        .with_context(|| format!("create decrypted IPA member {name}"))?;
        writer
            .write_all(&decrypted)
            .with_context(|| format!("write decrypted IPA member {name}"))?;
        images += reports.len();
        pages += reports.iter().map(|report| report.pages).sum::<usize>();
        if reports.len() != binding.encrypted_slices {
            bail!("{name}: encrypted slice inventory changed during decryption");
        }
        let encrypted_slices = slices.iter().filter(|slice| slice.layout.crypt_id != 0);
        for (slice, decrypted_report) in encrypted_slices.zip(reports) {
            let range = slice.offset..slice.offset + slice.size;
            let context = ImageReportContext {
                member: &name,
                supf_member: supf_name,
                sinf_member: &binding.sinf_member,
                logical_key_sha256: &license.logical_key_sha256,
                before: &blob[range.clone()],
                after: &decrypted[range],
                supf,
                deriver: &license.deriver,
                app_mask_sha256: &license.app_mask_sha256,
            };
            image_reports.push(image_report(&context, slice, decrypted_report)?);
        }
    }
    let inventoried_slices: usize = inventory
        .images
        .values()
        .map(|image| image.encrypted_slices)
        .sum();
    if images == 0 || images != inventoried_slices {
        bail!("IPA encrypted image inventory changed during processing");
    }
    writer
        .finish()?
        .0
        .sync_all()
        .context("sync decrypted IPA")?;
    let output_sha256 = sha256_file(temporary.path())?;
    let plaintext_verified = image_reports
        .iter()
        .all(|image| image.plaintext_validation == "code-directory-pre-encryption-hashes");
    let report_stage = if let Some(report_path) = report {
        let first = license_reports
            .first()
            .expect("at least one inventoried license");
        let model_name = if license_reports
            .iter()
            .all(|license| license.model_build == first.model_build)
        {
            first.model_build.clone()
        } else {
            "multiple".into()
        };
        let provider = if license_reports
            .iter()
            .all(|license| license.provider == first.provider)
        {
            first.provider
        } else {
            "multiple"
        };
        let oracle = if license_reports.len() == 1 {
            serde_json::to_value(&first.oracle)?
        } else {
            serde_json::json!({"request_ipa_sha256": input_sha256})
        };
        let report_data = DecryptionReport {
            schema: "ipatool-fairplay-decryption-v2",
            model_build: model_name.clone(),
            input: ReportFile {
                path: fs::canonicalize(input)?.display().to_string(),
                sha256: input_sha256.clone(),
                bytes: Some(fs::metadata(input)?.len()),
                mode: None,
            },
            output: ReportFile {
                path: canonical_target(output)?.display().to_string(),
                sha256: output_sha256.clone(),
                bytes: None,
                mode: Some("0600"),
            },
            provider,
            oracle,
            licenses: license_reports,
            encrypted_image_count: images,
            decrypted_page_count: pages,
            images: image_reports,
            complete: true,
            plaintext_verified,
            signature_verified: false,
            warnings: [
                "Complete means every inventoried encrypted image was processed; plaintext_verified requires pre-encryption hash coverage for every image.",
                "Missing pre-encryption hash tables leave plaintext validation unavailable; present malformed or mismatching tables reject publication.",
                "Embedded page hash consistency does not establish Apple CMS signature trust; unencrypted pages are outside the plaintext audit.",
                "Analysis IPA requires recursive re-signing before installation.",
            ],
        };
        let report_parent = report_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(report_parent)?;
        let mut staged = tempfile::NamedTempFile::new_in(report_parent)?;
        serde_json::to_writer_pretty(&mut staged, &report_data)?;
        staged.write_all(b"\n")?;
        staged.as_file().sync_all()?;
        Some(staged)
    } else {
        None
    };
    validate_destinations(input, output, model_path, report, force)?;
    let mut staged = vec![(&temporary, output)];
    if let (Some(staged_report), Some(report_path)) = (&report_stage, report) {
        staged.push((staged_report, report_path));
    }
    crate::application::operation::publish(|| publish_staged(&staged, force))?;
    Ok(IpaDecryptResult {
        encrypted_images: images,
        decrypted_pages: pages,
        output_sha256,
        plaintext_verified,
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        crate::application::operation::check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn canonical_target(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("FairPlay destination has no filename")?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(fs::canonicalize(parent)?.join(name))
}

fn validate_destinations(
    input: &Path,
    output: &Path,
    model_path: &Path,
    report: Option<&Path>,
    force: bool,
) -> Result<()> {
    let input = fs::canonicalize(input).context("resolve FairPlay input IPA")?;
    let model = fs::canonicalize(model_path).context("resolve FairPlay model path")?;
    let mut destinations = Vec::new();
    for path in [Some(output), report].into_iter().flatten() {
        let resolved = canonical_target(path)?;
        if resolved == input || resolved == model {
            bail!("refusing to overwrite FairPlay input or private model");
        }
        if destinations.contains(&resolved) {
            bail!("FairPlay output and report paths must be distinct");
        }
        destinations.push(resolved);
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.is_file() => {
                bail!(
                    "FairPlay destination is not a regular file: {}",
                    path.display()
                );
            }
            Ok(_) if !force => bail!("refusing to replace {}", path.display()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn file_identity(path: &Path) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let file = File::open(path)?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file is open and info is a writable structure of the required type.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        Ok((u64::from(info.dwVolumeSerialNumber), index))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        bail!("FairPlay publication needs file identity support on this platform")
    }
}

fn publish_staged(files: &[(&tempfile::NamedTempFile, &Path)], force: bool) -> Result<()> {
    let staged_identities = files
        .iter()
        .map(|(staged, _)| file_identity(staged.path()))
        .collect::<Result<Vec<_>>>()?;
    let mut backups = Vec::with_capacity(files.len());
    for (_, destination) in files {
        if force && destination.exists() {
            let parent = destination.parent().unwrap_or_else(|| Path::new("."));
            let directory = tempfile::Builder::new()
                .prefix(".fairplay-backup-")
                .tempdir_in(parent)?;
            let backup = directory.path().join("previous");
            fs::hard_link(destination, &backup)?;
            backups.push(Some((directory, backup)));
        } else {
            backups.push(None);
        }
    }
    let mut published: Vec<(PathBuf, (u64, u64))> = Vec::new();
    for ((staged, destination), staged_identity) in files.iter().zip(staged_identities) {
        let outcome = if force {
            fs::rename(staged.path(), destination)
        } else {
            fs::hard_link(staged.path(), destination)
        };
        if let Err(error) = outcome {
            for ((previous, published_identity), prior_backup) in published
                .iter()
                .rev()
                .zip(backups[..published.len()].iter().rev())
            {
                if file_identity(previous).is_ok_and(|current| current == *published_identity) {
                    if let Some((_, backup_path)) = prior_backup {
                        let _ = fs::rename(backup_path, previous);
                    } else {
                        let _ = fs::remove_file(previous);
                    }
                }
            }
            return Err(error).with_context(|| format!("publish {}", destination.display()));
        }
        published.push((destination.to_path_buf(), staged_identity));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fairplay_decrypt::tests::encrypted_fixture;
    use crate::fairplay_supf::PAGE_BYTES;
    use aes::{
        Aes128,
        cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
    };
    use zip::write::SimpleFileOptions;

    fn atom(name: [u8; 4], bytes: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&((bytes.len() + 8) as u32).to_be_bytes());
        result.extend_from_slice(&name);
        result.extend_from_slice(bytes);
        result
    }

    pub(crate) fn model_and_sinf(logical: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
        let mut model = vec![0u8; 8 + 4 + 4 + 32 + 16 + 16 + 4096];
        let model_size = model.len() as u32;
        model[..8].copy_from_slice(b"FPSENR1\0");
        model[8..12].copy_from_slice(&1u32.to_le_bytes());
        model[12..16].copy_from_slice(&model_size.to_le_bytes());
        model[48..64].copy_from_slice(&[0x42; 16]);
        for table in model[80..].as_chunks_mut::<256>().0 {
            for (index, byte) in table.iter_mut().enumerate() {
                *byte = index as u8;
            }
        }
        let mut inner = [0u8; 16];
        for word in 0..4 {
            let value = u32::from_le_bytes(logical[word * 4..word * 4 + 4].try_into().unwrap())
                .wrapping_sub((13 + word as u32).wrapping_mul(0xa6b13d89));
            inner[word * 4..word * 4 + 4].copy_from_slice(&value.to_be_bytes());
        }
        let mut plaintext = Vec::new();
        for (index, (name, size)) in [
            (*b"key ", 24),
            (*b"iviv", 24),
            (*b"tmpr", 24),
            (*b"righ", 88),
            (*b"name", 264),
        ]
        .into_iter()
        .enumerate()
        {
            let mut bytes = vec![0u8; size - 8];
            if index == 0 {
                bytes.copy_from_slice(&inner);
            }
            plaintext.extend(atom(name, &bytes));
        }
        let cipher = Aes128::new_from_slice(&[0x42; 16]).unwrap();
        let mut private = vec![0x11; 16];
        let mut previous = [0x11; 16];
        for block in plaintext[..416].as_chunks::<16>().0 {
            let mut encrypted = GenericArray::clone_from_slice(block);
            for index in 0..16 {
                encrypted[index] ^= previous[index];
            }
            cipher.encrypt_block(&mut encrypted);
            private.extend_from_slice(&encrypted);
            previous.copy_from_slice(&encrypted);
        }
        private.extend_from_slice(&[0u8; 8]);
        let mut fields = Vec::new();
        fields.extend(atom(*b"user", &7u32.to_be_bytes()));
        fields.extend(atom(*b"key ", &9u32.to_be_bytes()));
        fields.extend(atom(*b"priv", &private));
        let sinf = atom(*b"sinf", &atom(*b"schi", &fields));
        (model, sinf)
    }

    pub(crate) fn supf(record: [u8; 32]) -> Vec<u8> {
        supf_records(&[record])
    }

    pub(crate) fn supf_records(records: &[[u8; 32]]) -> Vec<u8> {
        let mut arch = Vec::new();
        arch.extend_from_slice(&0x0100_000cu32.to_be_bytes());
        arch.extend_from_slice(&2u32.to_be_bytes());
        arch.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for record in records {
            arch.extend_from_slice(record);
        }
        let mut bytes = vec![5, 0, 0, 0];
        bytes.extend_from_slice(&(4u32 + 4 + arch.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&(arch.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&arch);
        bytes
    }

    #[test]
    fn signed_supp_uses_file_origin_pages_and_preserves_outputs_after_authentication_failure() {
        let sample = crate::fairplay_key_tables::tests::signed_supp_sample();
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("synthetic.ipa");
        let output = directory.path().join("decrypted.ipa");
        let report = directory.path().join("report.json");
        let model_path = directory.path().join("model.bin");
        let (model, sinf) = model_and_sinf([0x31; 16]);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let make_ipa = |table: &[u8]| {
            let mut writer = ZipWriter::new(File::create(&input).unwrap());
            for (name, bytes) in [
                ("Payload/A.app/A", sample.source.as_slice()),
                ("Payload/A.app/SC_Info/A.sinf", sinf.as_slice()),
                ("Payload/A.app/SC_Info/A.v4.supp", table),
            ] {
                writer
                    .start_file(name, SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        };
        make_ipa(&sample.table);
        let original = fs::read(&input).unwrap();
        // There is no production trust override for this invented authority.
        assert!(
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), false).is_err()
        );
        assert!(!output.exists());
        assert!(!report.exists());
        let result = decrypt_ipa_trusted(
            &input,
            &output,
            &model_path,
            Some(&report),
            false,
            &sample.trust,
        )
        .unwrap();
        assert_eq!((result.encrypted_images, result.decrypted_pages), (1, 2));
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(value["plaintext_verified"], true);
        assert_eq!(value["signature_verified"], false);
        assert_eq!(value["images"][0]["key_table_variant"], 4);
        assert_eq!(value["images"][0]["key_table_envelope_verified"], true);
        assert_eq!(
            value["images"][0]["key_table_signature_binding"],
            "not-present"
        );
        assert_eq!(
            value["images"][0]["supf_member"],
            "Payload/A.app/SC_Info/A.v4.supp"
        );
        let mut zip = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut actual = Vec::new();
        zip.by_name("Payload/A.app/A")
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(&actual[PAGE_BYTES..3 * PAGE_BYTES], sample.plaintext);
        assert_eq!(&actual[48..52], &[0; 4]);
        assert_eq!(fs::read(&input).unwrap(), original);
        let previous_output = fs::read(&output).unwrap();
        let previous_report = fs::read(&report).unwrap();
        let mut tampered = sample.table.clone();
        *tampered.last_mut().unwrap() ^= 1;
        make_ipa(&tampered);
        let changed_input = fs::read(&input).unwrap();
        assert!(
            decrypt_ipa_trusted(
                &input,
                &output,
                &model_path,
                Some(&report),
                true,
                &sample.trust
            )
            .is_err()
        );
        assert_eq!(fs::read(&output).unwrap(), previous_output);
        assert_eq!(fs::read(&report).unwrap(), previous_report);
        assert_eq!(fs::read(&input).unwrap(), changed_input);
    }

    #[test]
    fn publishes_plaintext_coverage_and_rejects_wrong_last_page_without_replacing_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("synthetic.ipa");
        let output = directory.path().join("decrypted.ipa");
        let report = directory.path().join("report.json");
        let model_path = directory.path().join("model.bin");
        let logical = [0x31; 16];
        let (model, sinf) = model_and_sinf(logical);
        let (image, mut records, plaintext) =
            crate::fairplay_decrypt::tests::pre_encryption_fixture(logical);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let make_ipa = |records: &[[u8; 32]]| {
            let mut writer = ZipWriter::new(File::create(&input).unwrap());
            for (name, bytes) in [
                ("Payload/A.app/A", image.clone()),
                ("Payload/A.app/SC_Info/A.sinf", sinf.clone()),
                ("Payload/A.app/SC_Info/A.v5.supf", supf_records(records)),
            ] {
                writer
                    .start_file(name, SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(&bytes).unwrap();
            }
            writer.finish().unwrap();
        };
        make_ipa(&records);
        let before = fs::read(&input).unwrap();
        let result =
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), false).unwrap();
        assert!(result.plaintext_verified);
        assert_eq!(result.decrypted_pages, 2);
        assert_eq!(fs::read(&input).unwrap(), before);
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(value["schema"], "ipatool-fairplay-decryption-v2");
        assert_eq!(value["plaintext_verified"], true);
        assert_eq!(value["signature_verified"], false);
        assert_eq!(
            value["images"][0]["pre_encryption_code_directories"][0]["matched_slots"],
            2
        );
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut actual = Vec::new();
        archive
            .by_name("Payload/A.app/A")
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(&actual[PAGE_BYTES..3 * PAGE_BYTES], plaintext);
        drop(archive);
        let valid_output = fs::read(&output).unwrap();
        let valid_report = fs::read(&report).unwrap();
        records[1][0] ^= 1;
        make_ipa(&records);
        let bad_input = fs::read(&input).unwrap();
        assert!(
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), true).is_err()
        );
        assert_eq!(fs::read(&output).unwrap(), valid_output);
        assert_eq!(fs::read(&report).unwrap(), valid_report);
        assert_eq!(fs::read(&input).unwrap(), bad_input);
        fs::remove_file(&output).unwrap();
        fs::remove_file(&report).unwrap();
        assert!(
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), false).is_err()
        );
        assert!(!output.exists());
        assert!(!report.exists());
    }

    fn extras(path: &Path, name: &str) -> (Vec<u8>, Vec<u8>) {
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        let member = archive.by_name(name).unwrap();
        let local = local_extra(&mut File::open(path).unwrap(), &member).unwrap();
        (local, member.extra_data().unwrap_or_default().to_vec())
    }

    #[test]
    fn decrypts_ipa_with_private_model_and_preserves_other_members() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let output = directory.path().join("decrypted.ipa");
        let report = directory.path().join("decrypted.json");
        let model_path = directory.path().join("enrollment.bin");
        let logical = [0x31; 16];
        let (model, sinf) = model_and_sinf(logical);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (encrypted, record, plaintext) = encrypted_fixture(logical);
        let supf_bytes = supf(record);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        let options = SimpleFileOptions::default();
        for (name, data) in [
            ("Payload/A.app/SC_Info/A.sinf", sinf.as_slice()),
            ("Payload/A.app/SC_Info/A.v5.supf", supf_bytes.as_slice()),
            ("Payload/A.app/A", encrypted.as_slice()),
            ("Payload/A.app/Info.plist", b"unchanged".as_slice()),
            ("Payload/A.app/Resources/ignored.SINF", b"other".as_slice()),
        ] {
            if name == "Payload/A.app/A" || name == "Payload/A.app/Info.plist" {
                let mut extra = FullFileOptions::default();
                extra.add_extra_field(0xcafe, [1, 2, 3], false).unwrap();
                extra.add_extra_field(0xbeef, [4, 5, 6], true).unwrap();
                writer.start_file(name, extra).unwrap();
            } else {
                writer.start_file(name, options).unwrap();
            }
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        let original_extras = extras(&input, "Payload/A.app/A");
        assert_ne!(original_extras.0, original_extras.1);
        let input_before = fs::read(&input).unwrap();
        let result =
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), false).unwrap();
        assert_eq!(result.encrypted_images, 1);
        assert_eq!(result.decrypted_pages, 1);
        let report_data: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(report_data["output"]["sha256"], result.output_sha256);
        assert_eq!(report_data["output"]["mode"], "0600");
        assert!(report_data["output"].get("bytes").is_none());
        assert_eq!(report_data["encrypted_image_count"], 1);
        assert_eq!(report_data["decrypted_page_count"], 1);
        assert_eq!(report_data["provider"], "current-sinf-whitebox-direct-v1");
        assert_eq!(
            report_data["oracle"]["request_selector"],
            "00000007:00000009"
        );
        assert_eq!(report_data["oracle"]["model_version"], 1);
        assert_eq!(report_data["plaintext_verified"], false);
        assert_eq!(report_data["signature_verified"], false);
        assert_eq!(report_data["images"].as_array().unwrap().len(), 1);
        assert_eq!(report_data["images"][0]["architecture"], "arm64e");
        assert_eq!(report_data["images"][0]["cryptoff"], 4096);
        assert_eq!(report_data["images"][0]["cryptsize"], 4096);
        assert_eq!(report_data["schema"], "ipatool-fairplay-decryption-v2");
        assert_eq!(
            report_data["images"][0]["plaintext_validation"],
            "unavailable-no-pre-encryption-hashes"
        );
        assert!(report_data["images"][0].get("first_page_audit").is_none());
        assert!(!result.plaintext_verified);
        assert_eq!(
            report_data["images"][0]["ordered_page_keys_sha256"],
            "faae625eb5ec65fddbefe83887fe0535163b7b4653a7fdf5843d39d832182f80"
        );
        assert_eq!(
            report_data["images"][0]["app_mask_sha256"],
            "c6f10e37c99d2243bf590f0f0e2beed406b0391e056d255d3c12e194135fdb01"
        );
        assert_eq!(report_data["images"][0]["exact_mutation_scope"], true);
        assert!(
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), false).is_err()
        );
        decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), true).unwrap();
        assert_eq!(fs::read(&input).unwrap(), input_before);
        assert_eq!(extras(&output, "Payload/A.app/A"), original_extras);
        assert_eq!(
            extras(&output, "Payload/A.app/Info.plist"),
            extras(&input, "Payload/A.app/Info.plist")
        );
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut image = Vec::new();
        archive
            .by_name("Payload/A.app/A")
            .unwrap()
            .read_to_end(&mut image)
            .unwrap();
        assert_eq!(&image[PAGE_BYTES..PAGE_BYTES * 2], &plaintext);
        let mut unchanged = Vec::new();
        archive
            .by_name("Payload/A.app/Info.plist")
            .unwrap()
            .read_to_end(&mut unchanged)
            .unwrap();
        assert_eq!(unchanged, b"unchanged");
        let mut ignored = Vec::new();
        archive
            .by_name("Payload/A.app/Resources/ignored.SINF")
            .unwrap()
            .read_to_end(&mut ignored)
            .unwrap();
        assert_eq!(ignored, b"other");
    }

    #[test]
    fn decrypts_multiple_images_with_both_supf_variants() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let output = directory.path().join("decrypted.ipa");
        let report = directory.path().join("decrypted.json");
        let model_path = directory.path().join("model.bin");
        let logical = [0x31; 16];
        let (model, sinf) = model_and_sinf(logical);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (encrypted, record, plaintext) = encrypted_fixture(logical);
        let mut unencrypted = encrypted.clone();
        unencrypted[48..52].fill(0);
        let mut arch = Vec::new();
        arch.extend_from_slice(&0x0100_000cu32.to_be_bytes());
        arch.extend_from_slice(&2u32.to_be_bytes());
        let signature = &crate::fairplay_macho::parse_macho_slices(&encrypted).unwrap()[0].layout;
        arch.extend_from_slice(&sha1::Sha1::digest(
            &encrypted
                [signature.signature_offset..signature.signature_offset + signature.signature_size],
        ));
        arch.extend_from_slice(&1u32.to_be_bytes());
        arch.extend_from_slice(&record);
        let mut supf3 = vec![3, 0, 0, 0];
        supf3.extend_from_slice(&(8u32 + arch.len() as u32).to_be_bytes());
        supf3.extend_from_slice(&1u32.to_be_bytes());
        supf3.extend_from_slice(&(arch.len() as u32).to_be_bytes());
        supf3.extend_from_slice(&arch);
        let supf5 = supf(record);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        for (name, bytes) in [
            ("Payload/A.app/SC_Info/A.sinf", sinf.as_slice()),
            ("Payload/A.app/SC_Info/B.sinf", sinf.as_slice()),
            ("Payload/A.app/SC_Info/A.v5.supf", supf5.as_slice()),
            ("Payload/A.app/SC_Info/B.supf", supf3.as_slice()),
            ("Payload/A.app/A", encrypted.as_slice()),
            ("Payload/A.app/B", encrypted.as_slice()),
            ("Payload/A.app/C", unencrypted.as_slice()),
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        let result =
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), false).unwrap();
        assert_eq!(result.encrypted_images, 2);
        assert_eq!(result.decrypted_pages, 2);
        let report_data: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(report_data["encrypted_image_count"], 2);
        assert_eq!(report_data["decrypted_page_count"], 2);
        assert_eq!(report_data["licenses"].as_array().unwrap().len(), 2);
        assert!(report_data["oracle"].get("request_selector").is_none());
        assert_eq!(
            report_data["images"][1]["sinf_member"],
            "Payload/A.app/SC_Info/B.sinf"
        );
        assert_eq!(
            report_data["images"][1]["supf_member"],
            "Payload/A.app/SC_Info/B.supf"
        );
        assert_eq!(report_data["images"][1]["key_table_variant"], 3);
        assert_eq!(
            report_data["images"][1]["key_table_envelope_verified"],
            false
        );
        assert_eq!(
            report_data["images"][1]["key_table_signature_binding"],
            "slice-code-signature-sha1"
        );
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        for name in ["Payload/A.app/A", "Payload/A.app/B"] {
            let mut bytes = Vec::new();
            archive
                .by_name(name)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(&bytes[PAGE_BYTES..PAGE_BYTES * 2], &plaintext);
        }
        let mut unchanged = Vec::new();
        archive
            .by_name("Payload/A.app/C")
            .unwrap()
            .read_to_end(&mut unchanged)
            .unwrap();
        assert_eq!(unchanged, unencrypted);
    }

    #[cfg(unix)]
    #[test]
    fn resolves_distinct_extension_licenses_with_a_registry_and_preserves_outputs_on_missing_match()
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let models = temp.path().join("models");
        fs::DirBuilder::new().mode(0o700).create(&models).unwrap();
        let mut entries = Vec::new();
        let mut expected = Vec::new();
        for (member, key_id, logical) in [
            ("Payload/A.app/A", 9u32, [0x31; 16]),
            ("Payload/A.app/PlugIns/B.appex/B", 10u32, [0x61; 16]),
        ] {
            let (old, mut sinf) = model_and_sinf(logical);
            sinf[36..40].copy_from_slice(&key_id.to_be_bytes());
            let mut model = old[..48].to_vec();
            model.extend(7u32.to_le_bytes());
            model.extend(key_id.to_le_bytes());
            model.extend(&old[48..]);
            model[..8].copy_from_slice(b"FPSENR2\0");
            model[8..12].copy_from_slice(&2u32.to_le_bytes());
            let size = model.len() as u32;
            model[12..16].copy_from_slice(&size.to_le_bytes());
            let path = models.join(format!("{key_id}.bin"));
            fs::write(&path, model).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let (image, records, plain) =
                crate::fairplay_decrypt::tests::pre_encryption_fixture(logical);
            let sinf_member = crate::fairplay_licenses::adjacent_sinf(member).unwrap();
            let supf_member = sinf_member.strip_suffix(".sinf").unwrap().to_owned() + ".v5.supf";
            entries.extend([
                (member.to_owned(), image),
                (sinf_member, sinf),
                (supf_member, supf_records(&records)),
            ]);
            expected.push((member, plain, format!("{:x}", Sha256::digest(logical))));
        }
        // An unreferenced license must not make managed matching require an
        // unrelated selector, nor be tried as a replacement for a missing one.
        entries.push((
            "Payload/A.app/SC_Info/Unused.sinf".into(),
            b"not an active license".to_vec(),
        ));
        let input = temp.path().join("source.ipa");
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        for (name, bytes) in entries {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
        let before = fs::read(&input).unwrap();
        let required = required_ipa_sinfs(&input).unwrap();
        assert_eq!(required.len(), 2);
        assert_eq!(
            required.iter().map(|s| s.selector.key).collect::<Vec<_>>(),
            [10, 9]
        );
        let output = temp.path().join("processed.ipa");
        let report = temp.path().join("processed.json");
        let result =
            decrypt_ipa_with_options(&input, &output, &models, Some(&report), false).unwrap();
        assert!(result.plaintext_verified);
        assert_eq!(result.encrypted_images, 2);
        assert_eq!(result.decrypted_pages, 4);
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(metadata["model_build"], "multiple");
        assert_eq!(metadata["licenses"].as_array().unwrap().len(), 2);
        assert!(metadata["oracle"].get("logical_key_sha256").is_none());
        let mut processed = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        for (member, plain, hash) in expected {
            let image = metadata["images"]
                .as_array()
                .unwrap()
                .iter()
                .find(|image| image["member"] == member)
                .unwrap();
            assert_eq!(image["logical_key_sha256"], hash);
            let mut bytes = Vec::new();
            processed
                .by_name(member)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(&bytes[PAGE_BYTES..3 * PAGE_BYTES], plain.as_slice());
        }
        drop(processed);
        let previous_output = fs::read(&output).unwrap();
        let previous_report = fs::read(&report).unwrap();
        fs::remove_file(models.join("10.bin")).unwrap();
        assert!(decrypt_ipa_with_options(&input, &output, &models, Some(&report), true).is_err());
        assert_eq!(fs::read(&output).unwrap(), previous_output);
        assert_eq!(fs::read(&report).unwrap(), previous_report);
        assert_eq!(fs::read(&input).unwrap(), before);
    }

    #[test]
    fn resolves_declared_missing_license_replicas_and_rejects_conflicts_before_staging() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("source.ipa");
        let output = temp.path().join("processed.ipa");
        let model_path = temp.path().join("model.bin");
        let (model, sinf) = model_and_sinf([0x31; 16]);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (image, record, _) = encrypted_fixture([0x31; 16]);
        let mut manifest = plist::Dictionary::new();
        manifest.insert(
            "SinfPaths".into(),
            plist::Value::Array(vec![plist::Value::String("SC_Info/A.sinf".into())]),
        );
        manifest.insert(
            "SinfReplicationPaths".into(),
            plist::Value::Array(vec![plist::Value::String(
                "PlugIns/B.appex/SC_Info/B.sinf".into(),
            )]),
        );
        let mut plist = Vec::new();
        plist::to_writer_binary(&mut plist, &manifest).unwrap();
        let make = |conflict: bool| {
            let mut writer = ZipWriter::new(File::create(&input).unwrap());
            for (name, bytes) in [
                ("Payload/A.app/SC_Info/A.sinf", sinf.clone()),
                ("Payload/A.app/SC_Info/Manifest.plist", plist.clone()),
                ("Payload/A.app/PlugIns/B.appex/B", image.clone()),
                (
                    "Payload/A.app/PlugIns/B.appex/SC_Info/B.v5.supf",
                    supf(record),
                ),
            ] {
                writer
                    .start_file(name, SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(&bytes).unwrap();
            }
            if conflict {
                writer
                    .start_file(
                        "Payload/A.app/PlugIns/B.appex/SC_Info/B.sinf",
                        SimpleFileOptions::default(),
                    )
                    .unwrap();
                writer.write_all(b"other source").unwrap();
            }
            writer.finish().unwrap();
        };
        make(false);
        decrypt_ipa(&input, &output, &model_path).unwrap();
        fs::remove_file(&output).unwrap();
        make(true);
        let error = decrypt_ipa(&input, &output, &model_path).unwrap_err();
        assert!(format!("{error:#}").contains("differs from every declared source"));
        assert!(!output.exists());
    }

    #[test]
    fn decrypts_two_encrypted_slices_in_one_universal_macho() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let output = directory.path().join("decrypted.ipa");
        let report = directory.path().join("decrypted.json");
        let model_path = directory.path().join("model.bin");
        let logical = [0x31; 16];
        let (model, sinf) = model_and_sinf(logical);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (template, record, plaintext) = encrypted_fixture(logical);
        let mut fat = vec![0u8; PAGE_BYTES * 7];
        fat[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        let deriver = PageKeyDeriver::from_logical_key(logical);
        for (index, offset) in [PAGE_BYTES, PAGE_BYTES * 4].into_iter().enumerate() {
            let mut thin = template.clone();
            thin[PAGE_BYTES..PAGE_BYTES * 2].copy_from_slice(&plaintext);
            let key = deriver.page_key(
                record[..16].try_into().unwrap(),
                (offset + PAGE_BYTES) as u64,
            );
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut previous: [u8; 16] = record[16..].try_into().unwrap();
            for chunk in thin[PAGE_BYTES..PAGE_BYTES * 2].as_chunks_mut::<16>().0 {
                let mut block = GenericArray::clone_from_slice(chunk);
                for byte in 0..16 {
                    block[byte] ^= previous[byte];
                }
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                previous.copy_from_slice(&block);
            }
            let slot = PAGE_BYTES * 2 + 20 + 44 + 32;
            let page_hash = Sha256::digest(&thin[PAGE_BYTES..PAGE_BYTES * 2]);
            thin[slot..slot + 32].copy_from_slice(&page_hash);
            let entry = 8 + index * 20;
            fat[entry..entry + 4].copy_from_slice(&0x0100_000cu32.to_be_bytes());
            fat[entry + 4..entry + 8].copy_from_slice(&2u32.to_be_bytes());
            fat[entry + 8..entry + 12].copy_from_slice(&(offset as u32).to_be_bytes());
            fat[entry + 12..entry + 16].copy_from_slice(&(thin.len() as u32).to_be_bytes());
            fat[entry + 16..entry + 20].copy_from_slice(&12u32.to_be_bytes());
            fat[offset..offset + thin.len()].copy_from_slice(&thin);
        }
        let supf = supf(record);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        for (name, bytes) in [
            ("Payload/A.app/SC_Info/A.sinf", sinf.as_slice()),
            ("Payload/A.app/SC_Info/A.v5.supf", supf.as_slice()),
            ("Payload/A.app/A", fat.as_slice()),
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        let result =
            decrypt_ipa_with_options(&input, &output, &model_path, Some(&report), false).unwrap();
        assert_eq!(result.encrypted_images, 2);
        assert_eq!(result.decrypted_pages, 2);
        let report_data: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        assert_eq!(report_data["images"].as_array().unwrap().len(), 2);
        for (index, offset) in [PAGE_BYTES, PAGE_BYTES * 4].into_iter().enumerate() {
            assert_eq!(report_data["images"][index]["slice_offset"], offset);
            assert_eq!(report_data["images"][index]["exact_mutation_scope"], true);
        }
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut decrypted = Vec::new();
        archive
            .by_name("Payload/A.app/A")
            .unwrap()
            .read_to_end(&mut decrypted)
            .unwrap();
        for offset in [PAGE_BYTES, PAGE_BYTES * 4] {
            assert_eq!(&decrypted[offset + 48..offset + 52], &[0; 4]);
            assert_eq!(
                &decrypted[offset + PAGE_BYTES..offset + PAGE_BYTES * 2],
                &plaintext
            );
        }
    }

    #[test]
    fn publication_rolls_back_output_when_report_cannot_be_written() {
        let directory = tempfile::tempdir().unwrap();
        let first = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        let second = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        let output = directory.path().join("output.ipa");
        let report = directory.path().join("report.json");
        fs::create_dir(&report).unwrap();
        assert!(publish_staged(&[(&first, &output), (&second, &report)], false).is_err());
        assert!(!output.exists());
        assert!(report.is_dir());
    }

    #[test]
    fn forced_publication_restores_previous_output_on_failure() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.ipa");
        let report = directory.path().join("missing/report.json");
        fs::write(&output, b"previous").unwrap();
        let mut first = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        first.write_all(b"replacement").unwrap();
        let second = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        assert!(publish_staged(&[(&first, &output), (&second, &report)], true).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"previous");
        assert!(!report.exists());
    }

    #[test]
    fn ignores_unreferenced_sinf_resources_while_resolving_adjacent_license() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let output = directory.path().join("decrypted.ipa");
        let (encrypted, record, _) = encrypted_fixture([0x12; 16]);
        let supf_bytes = supf(record);
        let (model, sinf) = model_and_sinf([0x12; 16]);
        let model_path = directory.path().join("model.bin");
        fs::write(&model_path, &model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        writer
            .start_file(
                "Payload/A.app/Resources/B.sinf",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(b"first").unwrap();
        writer
            .start_file("Payload/A.app/SC_Info/A.sinf", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&sinf).unwrap();
        writer
            .start_file(
                "Payload/A.app/SC_Info/A.v5.supf",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(&supf_bytes).unwrap();
        writer
            .start_file("Payload/A.app/A", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&encrypted).unwrap();
        writer.finish().unwrap();
        let result = decrypt_ipa(&input, &output, &model_path).unwrap();
        assert_eq!(result.encrypted_images, 1);
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut ignored = Vec::new();
        archive
            .by_name("Payload/A.app/Resources/B.sinf")
            .unwrap()
            .read_to_end(&mut ignored)
            .unwrap();
        assert_eq!(ignored, b"first");
    }

    #[test]
    fn missing_model_reports_the_ipa_selector_and_private_payload() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let (_, sinf) = model_and_sinf([0x12; 16]);
        let (encrypted, record, _) = encrypted_fixture([0x12; 16]);
        let supf_bytes = supf(record);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        writer
            .start_file("Payload/A.app/SC_Info/A.sinf", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&sinf).unwrap();
        writer
            .start_file(
                "Payload/A.app/SC_Info/A.v5.supf",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(&supf_bytes).unwrap();
        writer
            .start_file("Payload/A.app/A", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&encrypted).unwrap();
        writer.finish().unwrap();
        let diagnostic = require_model_diagnostic(&input).unwrap();
        let selector = parse_sinf_selector(&sinf).unwrap();
        assert!(diagnostic.contains(&selector.identifier()));
        assert!(diagnostic.contains(&format!("sinf_sha256={:x}", Sha256::digest(&sinf))));
        assert!(diagnostic.contains("priv_bytes="));
        assert!(diagnostic.contains("requires a private enrollment model"));
    }

    #[test]
    fn decrypts_with_original_sinf_and_supf_names_under_unicode_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("aliased.ipa");
        let output = directory.path().join("decrypted.ipa");
        let model_path = directory.path().join("enrollment.bin");
        let logical = [0x31; 16];
        let (model, sinf) = model_and_sinf(logical);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (encrypted, record, _) = encrypted_fixture(logical);
        let supf_bytes = supf(record);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        for (name, alias, crc, data) in [
            (
                "Payload/A.app/SC_Info/A.sinf",
                "Payload/B.app/SC_Info/B.sinf",
                0x55bc_8223u32,
                sinf.as_slice(),
            ),
            (
                "Payload/A.app/SC_Info/A.v5.supf",
                "Payload/B.app/SC_Info/B.supf",
                0x94c1_e7e8u32,
                supf_bytes.as_slice(),
            ),
        ] {
            let mut options = FullFileOptions::default();
            let mut unicode_path = vec![1];
            unicode_path.extend_from_slice(&crc.to_le_bytes());
            unicode_path.extend_from_slice(alias.as_bytes());
            options
                .add_extra_field(0x7075, unicode_path, false)
                .unwrap();
            writer.start_file(name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer
            .start_file("Payload/A.app/A", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&encrypted).unwrap();
        writer.finish().unwrap();

        let diagnostic = require_model_diagnostic(&input).unwrap();
        assert!(diagnostic.contains("requires a private enrollment model"));
        let result = decrypt_ipa(&input, &output, &model_path).unwrap();
        assert_eq!(result.encrypted_images, 1);
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut names = Vec::new();
        let mut source = File::open(&output).unwrap();
        for index in 0..archive.len() {
            let entry = archive.by_index_raw(index).unwrap();
            names.push(
                crate::duplicate_zip::read_raw_central_name(
                    &mut source,
                    entry.central_header_start(),
                )
                .unwrap(),
            );
        }
        assert!(names.contains(&b"Payload/A.app/SC_Info/A.sinf".to_vec()));
        assert!(names.contains(&b"Payload/A.app/SC_Info/A.v5.supf".to_vec()));
    }

    #[test]
    fn missing_model_reports_unencrypted_ipa_before_model_requirement() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let (_, sinf) = model_and_sinf([0x12; 16]);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        writer
            .start_file("Payload/A.app/SC_Info/A.sinf", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&sinf).unwrap();
        writer.finish().unwrap();
        assert!(
            require_model_diagnostic(&input)
                .unwrap_err()
                .to_string()
                .contains("no supported encrypted Mach-O images")
        );
    }

    #[test]
    fn repeated_empty_directory_markers_do_not_hide_duplicate_files_or_nonempty_directories() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let output = directory.path().join("decrypted.ipa");
        let model_path = directory.path().join("model.bin");
        let (model, sinf) = model_and_sinf([0x31; 16]);
        let (image, records, plaintext) =
            crate::fairplay_decrypt::tests::pre_encryption_fixture([0x31; 16]);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        for name in ["Payload/A.app/", "Payload/B.app/"] {
            writer
                .add_directory(name, SimpleFileOptions::default())
                .unwrap();
        }
        for (name, bytes) in [
            ("Payload/A.app/A", image),
            ("Payload/A.app/SC_Info/A.sinf", sinf),
            ("Payload/A.app/SC_Info/A.v5.supf", supf_records(&records)),
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
        let mut original = fs::read(&input).unwrap();
        let old = b"Payload/B.app/";
        let new = b"Payload/A.app/";
        let mut replaced = 0;
        for offset in 0..=original.len() - old.len() {
            if &original[offset..offset + old.len()] == old {
                original[offset..offset + old.len()].copy_from_slice(new);
                replaced += 1;
            }
        }
        assert_eq!(replaced, 2);
        fs::write(&input, &original).unwrap();
        assert!(
            require_model_diagnostic(&input)
                .unwrap()
                .contains("requires a private enrollment model")
        );
        let result = decrypt_ipa(&input, &output, &model_path).unwrap();
        assert!(result.plaintext_verified);
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        assert_eq!(
            archive
                .file_names()
                .map(Result::unwrap)
                .filter(|name| *name == "Payload/A.app/")
                .count(),
            1
        );
        let mut actual = Vec::new();
        archive
            .by_name("Payload/A.app/A")
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(&actual[PAGE_BYTES..3 * PAGE_BYTES], plaintext);
        assert_eq!(fs::read(&input).unwrap(), original);
        // Both occurrences must be empty, even if zip's name index retains the
        // other occurrence. Reject the raw ambiguity before model resolution.
        let markers: Vec<_> = (0..original.len() - 46)
            .filter(|&offset| {
                original[offset..offset + 4] == *b"PK\x01\x02"
                    && u16::from_le_bytes(original[offset + 28..offset + 30].try_into().unwrap())
                        as usize
                        == new.len()
                    && original.get(offset + 46..offset + 46 + new.len()) == Some(new.as_slice())
            })
            .collect();
        assert_eq!(markers.len(), 2);
        let preserved = fs::read(&output).unwrap();
        for marker in markers {
            let mut changed = original.clone();
            changed[marker + 24..marker + 28].copy_from_slice(&1u32.to_le_bytes());
            fs::write(&input, &changed).unwrap();
            assert!(
                require_model_diagnostic(&input)
                    .unwrap_err()
                    .to_string()
                    .contains("duplicate IPA member")
            );
            assert!(decrypt_ipa_with_options(&input, &output, &model_path, None, true).is_err());
            assert_eq!(fs::read(&output).unwrap(), preserved);
            assert_eq!(fs::read(&input).unwrap(), changed);
        }
    }

    #[test]
    fn directory_zip64_empty_size_is_explicit_and_unambiguous() {
        let mut header = [0; 42];
        header[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut extra = vec![1, 0, 8, 0];
        extra.extend(0u64.to_le_bytes());
        assert!(empty_directory_marker(b"Payload/A.app/", &header, &extra).unwrap());
        let mut nonempty = extra.clone();
        nonempty[4] = 1;
        assert!(!empty_directory_marker(b"Payload/A.app/", &header, &nonempty).unwrap());
        assert!(empty_directory_marker(b"Payload/A.app/", &header, &[]).is_err());
        assert!(empty_directory_marker(b"Payload/A.app/", &header, &extra[..7]).is_err());
        let duplicate = [extra.as_slice(), extra.as_slice()].concat();
        assert!(empty_directory_marker(b"Payload/A.app/", &header, &duplicate).is_err());
        assert!(!empty_directory_marker(b"Payload/A.app/A", &header, &extra).unwrap());
    }

    #[test]
    fn rejects_duplicate_raw_zip_members_before_model_requirement() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let output = directory.path().join("decrypted.ipa");
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        for name in ["Payload/A.app/A", "Payload/A.app/B"] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"data").unwrap();
        }
        writer.finish().unwrap();
        let mut bytes = fs::read(&input).unwrap();
        let old = b"Payload/A.app/B";
        let new = b"Payload/A.app/A";
        let mut replacements = 0;
        for offset in 0..=bytes.len() - old.len() {
            if &bytes[offset..offset + old.len()] == old {
                bytes[offset..offset + old.len()].copy_from_slice(new);
                replacements += 1;
            }
        }
        assert_eq!(replacements, 2);
        fs::write(&input, bytes).unwrap();
        assert!(
            require_model_diagnostic(&input)
                .unwrap_err()
                .to_string()
                .contains("duplicate IPA member \"Payload/A.app/A\"")
        );
        assert!(
            decrypt_ipa(&input, &output, directory.path())
                .unwrap_err()
                .to_string()
                .contains("duplicate IPA member \"Payload/A.app/A\"")
        );
        assert!(!output.exists());
    }

    #[test]
    fn missing_model_reports_missing_supf_before_model_requirement() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let (encrypted, _, _) = encrypted_fixture([0x12; 16]);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        writer
            .start_file("Payload/A.app/A", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&encrypted).unwrap();
        writer.finish().unwrap();
        assert!(
            format!("{:#}", require_model_diagnostic(&input).unwrap_err())
                .contains("no adjacent SUPF or SUPP")
        );
    }

    #[test]
    fn version_one_model_requires_an_explicit_file_not_a_registry() {
        let directory = tempfile::tempdir().unwrap();
        let registry = directory.path().join("models");
        fs::create_dir(&registry).unwrap();
        let model_path = registry.join("legacy.bin");
        let (model, sinf) = model_and_sinf([0x31; 16]);
        fs::write(&model_path, model).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&model_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert_eq!(logical_key(&model_path, &sinf).unwrap().0, [0x31; 16]);
        assert!(
            logical_key(&registry, &sinf)
                .unwrap_err()
                .to_string()
                .contains("version 1 model cannot be used in a registry")
        );
        let snapshot = ModelRegistry::load(&model_path).unwrap();
        fs::write(&model_path, b"changed after snapshot").unwrap();
        assert_eq!(snapshot.logical_key(&sinf).unwrap().0, [0x31; 16]);
        assert!(ModelRegistry::load(&model_path).is_err());
    }
}
