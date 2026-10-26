//! Apply a local enrollment model to all encrypted Mach-O images in an IPA.

use std::{
    collections::HashSet,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use zeroize::Zeroizing;
use zip::{ZipArchive, ZipWriter};

use crate::{
    fairplay::{inspect_model_path, parse_sinf_selector},
    fairplay_decrypt::decrypt_macho,
    fairplay_key::CurrentSinfModel,
    fairplay_macho::{is_macho, parse_macho_slices},
    fairplay_supf::Supf,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IpaDecryptResult {
    pub encrypted_images: usize,
    pub decrypted_pages: usize,
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
    let models = inspect_model_path(model_path)?;
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
    if output.exists() {
        bail!("refusing to overwrite output IPA {}", output.display());
    }
    let source = File::open(input).with_context(|| format!("open IPA {}", input.display()))?;
    let mut archive = ZipArchive::new(source).context("open IPA ZIP archive")?;
    let mut names = HashSet::with_capacity(archive.len());
    let mut sinf_name = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).context("inspect IPA ZIP member")?;
        let name = entry.name().to_owned();
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
    let sinf = read_entry(&mut archive, &sinf_name)?;
    let key = Zeroizing::new(logical_key(model_path, &sinf)?);
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let temporary = tempfile::NamedTempFile::new_in(parent).context("create temporary IPA")?;
    let mut writer = ZipWriter::new(temporary.reopen().context("open temporary IPA")?);
    let mut images = 0usize;
    let mut pages = 0usize;
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).context("read IPA member")?;
        let name = member.name().to_owned();
        if member.is_dir() || member.size() < 4 {
            writer.raw_copy_file(member)?;
            continue;
        }
        let mut prefix = [0u8; 4];
        member.read_exact(&mut prefix)?;
        if !is_macho(&prefix) {
            drop(member);
            writer.raw_copy_file(archive.by_index_raw(index)?)?;
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
            drop(member);
            writer.raw_copy_file(archive.by_index_raw(index)?)?;
            continue;
        }
        let options = member.options();
        drop(member);
        let supf_name = supf_for(&name, &names)
            .with_context(|| format!("encrypted Mach-O {name} has no adjacent SUPF"))?;
        let supf = Supf::parse(&read_entry(&mut archive, supf_name)?)
            .with_context(|| format!("parse {supf_name}"))?;
        let (decrypted, reports) =
            decrypt_macho(&blob, &supf, *key).with_context(|| format!("decrypt {name}"))?;
        writer
            .start_file(&name, options)
            .with_context(|| format!("create decrypted IPA member {name}"))?;
        writer
            .write_all(&decrypted)
            .with_context(|| format!("write decrypted IPA member {name}"))?;
        images += reports.len();
        pages += reports.iter().map(|report| report.pages).sum::<usize>();
    }
    if images == 0 {
        bail!("IPA contains no supported encrypted Mach-O images");
    }
    writer.finish()?.sync_all().context("sync decrypted IPA")?;
    temporary
        .persist_noclobber(output)
        .with_context(|| format!("publish decrypted IPA {}", output.display()))?;
    Ok(IpaDecryptResult {
        encrypted_images: images,
        decrypted_pages: pages,
    })
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

    #[test]
    fn decrypts_ipa_with_private_model_and_preserves_other_members() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
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
            writer.start_file(name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        let result = decrypt_ipa(&input, &output, &model_path).unwrap();
        assert_eq!(result.encrypted_images, 1);
        assert_eq!(result.decrypted_pages, 1);
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
}
