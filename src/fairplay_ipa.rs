//! Apply a local enrollment model to all encrypted Mach-O images in an IPA.

use std::{
    collections::HashSet,
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
    fairplay::{inspect_model_path, inspect_model_registry, parse_sinf_selector},
    fairplay_decrypt::{DecryptedSlice, decrypt_macho},
    fairplay_key::{CurrentSinfModel, missing_model_diagnostic},
    fairplay_macho::{is_macho, parse_macho_slices},
    fairplay_supf::Supf,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IpaDecryptResult {
    pub encrypted_images: usize,
    pub decrypted_pages: usize,
    pub output_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct ImageReport {
    member: String,
    supf_member: String,
    #[serde(flatten)]
    slice: DecryptedSlice,
}

#[derive(Serialize)]
struct ReportFile {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Serialize)]
struct DecryptionReport {
    schema: &'static str,
    input: ReportFile,
    output: ReportFile,
    encrypted_images: usize,
    decrypted_pages: usize,
    images: Vec<ImageReport>,
    complete: bool,
    warnings: [&'static str; 4],
}

fn read_entry(archive: &mut ZipArchive<File>, name: &str) -> Result<Vec<u8>> {
    let mut entry = archive
        .by_name(name)
        .with_context(|| format!("open IPA member {name}"))?;
    let mut bytes = Vec::new();
    entry
        .read_to_end(&mut bytes)
        .with_context(|| format!("read IPA member {name}"))?;
    Ok(bytes)
}

fn find_sinf(archive: &mut ZipArchive<File>) -> Result<(HashSet<String>, Vec<u8>)> {
    let mut names = HashSet::with_capacity(archive.len());
    let mut sinf_name = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).context("inspect IPA ZIP member")?;
        let name = entry.name()?.into_owned();
        if !names.insert(name.clone()) {
            bail!("IPA contains duplicate member {name}");
        }
        if name.contains("/SC_Info/")
            && name.to_ascii_lowercase().ends_with(".sinf")
            && sinf_name.replace(name).is_some()
        {
            bail!("FairPlay decryption requires exactly one SINF");
        }
    }
    let sinf_name = sinf_name.context("FairPlay decryption requires exactly one SINF")?;
    Ok((names, read_entry(archive, &sinf_name)?))
}

pub fn require_model_diagnostic(input: &Path) -> Result<String> {
    let source = File::open(input).with_context(|| format!("open IPA {}", input.display()))?;
    let mut archive = ZipArchive::new(source).context("open IPA ZIP archive")?;
    let (_, sinf) = find_sinf(&mut archive)?;
    missing_model_diagnostic(&sinf)
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
    writer: &mut ZipWriter<File>,
    member: &mut ZipFile<'_, File>,
    local: &[u8],
    central: &[u8],
    prefix: &[u8],
    rest: Option<&[u8]>,
) -> Result<()> {
    let name = member.name()?.into_owned();
    let options = full_options(member, local, central)?;
    writer.start_file(name, options)?;
    writer.write_all(prefix)?;
    if let Some(bytes) = rest {
        writer.write_all(bytes)?;
    } else {
        std::io::copy(member, writer)?;
    }
    Ok(())
}

fn supf_for<'a>(member: &str, names: &'a HashSet<String>) -> Option<&'a str> {
    let (directory, base) = member.rsplit_once('/')?;
    for suffix in [".v5.supf", ".supf"] {
        let candidate = format!("{directory}/SC_Info/{base}{suffix}");
        if let Some(name) = names.get(&candidate) {
            return Some(name.as_str());
        }
    }
    None
}

fn logical_key(model_path: &Path, sinf: &[u8]) -> Result<[u8; 16]> {
    let selector = parse_sinf_selector(sinf)?;
    let registry = fs::metadata(model_path)
        .context("inspect FairPlay enrollment model path")?
        .is_dir();
    let models = if registry {
        inspect_model_registry(model_path)?
    } else {
        inspect_model_path(model_path)?
    };
    if registry && models.iter().any(|model| model.selector.is_none()) {
        bail!("FairPlay version 1 model cannot be used in a registry");
    }
    let compatible: Vec<_> = models
        .into_iter()
        .filter(|model| model.selector.is_none_or(|bound| bound == selector))
        .collect();
    if compatible.len() != 1 {
        bail!(
            "FairPlay model path has {} models compatible with selector {}; expected one",
            compatible.len(),
            selector.identifier()
        );
    }
    let bytes = Zeroizing::new(
        fs::read(&compatible[0].path).context("read selected FairPlay enrollment model")?,
    );
    CurrentSinfModel::parse(&bytes)?.logical_key(sinf)
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
    validate_destinations(input, output, model_path, report, force)?;
    let source = File::open(input).with_context(|| format!("open IPA {}", input.display()))?;
    let mut archive = ZipArchive::new(source).context("open IPA ZIP archive")?;
    let mut raw_source = File::open(input).context("open IPA ZIP headers")?;
    let (names, sinf) = find_sinf(&mut archive)?;
    let key = Zeroizing::new(logical_key(model_path, &sinf)?);
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let temporary = tempfile::NamedTempFile::new_in(parent).context("create temporary IPA")?;
    let mut writer = ZipWriter::new(temporary.reopen().context("open temporary IPA")?);
    let mut images = 0usize;
    let mut pages = 0usize;
    let mut image_reports = Vec::new();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).context("read IPA member")?;
        let name = member.name()?.into_owned();
        let local = local_extra(&mut raw_source, &member)?;
        let central = member.extra_data().unwrap_or_default().to_vec();
        let has_extra = !local.is_empty() || !central.is_empty();
        if member.is_dir() {
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
                write_reencoded(&mut writer, &mut member, &local, &central, &[], None)?;
            } else {
                writer.raw_copy_file(member)?;
            }
            continue;
        }
        let mut prefix = [0u8; 4];
        member.read_exact(&mut prefix)?;
        if !is_macho(&prefix) {
            if has_extra {
                write_reencoded(&mut writer, &mut member, &local, &central, &prefix, None)?;
            } else {
                drop(member);
                writer.raw_copy_file(archive.by_index_raw(index)?)?;
            }
            continue;
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&prefix);
        member
            .read_to_end(&mut blob)
            .with_context(|| format!("read Mach-O IPA member {name}"))?;
        let slices = parse_macho_slices(&blob).with_context(|| format!("inspect {name}"))?;
        let encrypted = slices.iter().any(|slice| slice.layout.crypt_id != 0);
        if !encrypted {
            if has_extra {
                write_reencoded(&mut writer, &mut member, &local, &central, &blob, Some(&[]))?;
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
        let supf_name = supf_for(&name, &names)
            .with_context(|| format!("encrypted Mach-O {name} has no adjacent SUPF"))?;
        let supf = Supf::parse(&read_entry(&mut archive, supf_name)?)
            .with_context(|| format!("parse {supf_name}"))?;
        let (decrypted, reports) =
            decrypt_macho(&blob, &supf, *key).with_context(|| format!("decrypt {name}"))?;
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
        image_reports.extend(reports.into_iter().map(|slice| ImageReport {
            member: name.clone(),
            supf_member: supf_name.to_owned(),
            slice,
        }));
    }
    if images == 0 {
        bail!("IPA contains no supported encrypted Mach-O images");
    }
    writer.finish()?.sync_all().context("sync decrypted IPA")?;
    let output_bytes = fs::metadata(temporary.path())?.len();
    let output_sha256 = sha256_file(temporary.path())?;
    let report_stage = if let Some(report_path) = report {
        let report_data = DecryptionReport {
            schema: "ipatool-fairplay-decryption-v1",
            input: ReportFile {
                path: input.display().to_string(),
                sha256: sha256_file(input)?,
                bytes: fs::metadata(input)?.len(),
            },
            output: ReportFile {
                path: output.display().to_string(),
                sha256: output_sha256.clone(),
                bytes: output_bytes,
            },
            encrypted_images: images,
            decrypted_pages: pages,
            images: image_reports,
            complete: true,
            warnings: [
                "Plaintext correctness is not authenticated by the source CodeDirectory.",
                "Only ARM64 first pages are checked for instruction plausibility.",
                "CodeDirectory hashes refer to encrypted pages and become stale after decryption.",
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
    publish_staged(&staged, force)?;
    Ok(IpaDecryptResult {
        encrypted_images: images,
        decrypted_pages: pages,
        output_sha256,
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
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

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn publish_staged(files: &[(&tempfile::NamedTempFile, &Path)], force: bool) -> Result<()> {
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
    let mut published: Vec<(PathBuf, fs::Metadata)> = Vec::new();
    for (staged, destination) in files {
        let outcome = if force {
            fs::rename(staged.path(), destination)
        } else {
            fs::hard_link(staged.path(), destination)
        };
        if let Err(error) = outcome {
            for ((previous, published_metadata), prior_backup) in published
                .iter()
                .rev()
                .zip(backups[..published.len()].iter().rev())
            {
                if fs::metadata(previous)
                    .is_ok_and(|current| same_file(&current, published_metadata))
                {
                    if let Some((_, backup_path)) = prior_backup {
                        let _ = fs::rename(backup_path, previous);
                    } else {
                        let _ = fs::remove_file(previous);
                    }
                }
            }
            return Err(error).with_context(|| format!("publish {}", destination.display()));
        }
        published.push((destination.to_path_buf(), fs::metadata(destination)?));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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

    fn model_and_sinf(logical: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
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

    fn supf(record: [u8; 32]) -> Vec<u8> {
        let mut arch = Vec::new();
        arch.extend_from_slice(&0x0100_000cu32.to_be_bytes());
        arch.extend_from_slice(&2u32.to_be_bytes());
        arch.extend_from_slice(&1u32.to_be_bytes());
        arch.extend_from_slice(&record);
        let mut bytes = vec![5, 0, 0, 0];
        bytes.extend_from_slice(&(4u32 + 4 + arch.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&(arch.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&arch);
        bytes
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
            ("Payload/A.app/SC_Info/A.supf", supf_bytes.as_slice()),
            ("Payload/A.app/A", encrypted.as_slice()),
            ("Payload/A.app/Info.plist", b"unchanged".as_slice()),
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
        assert_eq!(report_data["images"].as_array().unwrap().len(), 1);
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
        let report = directory.path().join("report.json");
        fs::write(&output, b"previous").unwrap();
        let mut first = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        first.write_all(b"replacement").unwrap();
        let second = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        fs::remove_file(second.path()).unwrap();
        assert!(publish_staged(&[(&first, &output), (&second, &report)], true).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"previous");
        assert!(!report.exists());
    }

    #[test]
    fn rejects_multiple_sinf_members_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let output = directory.path().join("decrypted.ipa");
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        writer
            .start_file("Payload/A.app/SC_Info/B.sinf", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"first").unwrap();
        writer
            .start_file("Payload/A.app/SC_Info/A.sinf", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"second").unwrap();
        writer.finish().unwrap();
        assert!(
            decrypt_ipa(&input, &output, directory.path())
                .unwrap_err()
                .to_string()
                .contains("exactly one SINF")
        );
        assert!(!output.exists());
    }

    #[test]
    fn missing_model_reports_the_ipa_selector_and_private_payload() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let (_, sinf) = model_and_sinf([0x12; 16]);
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        writer
            .start_file("Payload/A.app/SC_Info/A.sinf", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&sinf).unwrap();
        writer.finish().unwrap();
        let diagnostic = require_model_diagnostic(&input).unwrap();
        let selector = parse_sinf_selector(&sinf).unwrap();
        assert!(diagnostic.contains(&selector.identifier()));
        assert!(diagnostic.contains(&format!("sinf_sha256={:x}", Sha256::digest(&sinf))));
        assert!(diagnostic.contains("priv_bytes="));
        assert!(diagnostic.contains("requires a private enrollment model"));
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

        assert_eq!(logical_key(&model_path, &sinf).unwrap(), [0x31; 16]);
        assert!(
            logical_key(&registry, &sinf)
                .unwrap_err()
                .to_string()
                .contains("version 1 model cannot be used in a registry")
        );
    }
}
