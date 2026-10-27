//! Repack downloaded IPAs with account metadata, artwork, and Store SINF data.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use plist::Value;
use serde_json::Value as JsonValue;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::ipa_zip_repack;

const MAX_PLIST: u64 = 4 * 1024 * 1024;

/// Write a patched IPA atomically. The source stays available for a retry.
pub fn patch_ipa(
    source: &Path,
    destination: &Path,
    metadata: &JsonValue,
    apple_id: &str,
    artwork: &[u8],
    sinfs: &[Value],
) -> Result<()> {
    let source_file =
        File::open(source).with_context(|| format!("open IPA {}", source.display()))?;
    let mut archive = ZipArchive::new(source_file).context("open downloaded IPA ZIP")?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let output = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary IPA in {}", parent.display()))?;
    let additions = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary IPA entries in {}", parent.display()))?;
    let mut writer = ZipWriter::new(additions.reopen()?);
    if !artwork.is_empty() {
        writer
            .start_file("iTunesArtwork", SimpleFileOptions::default())
            .context("create IPA artwork entry")?;
        writer.write_all(artwork).context("write IPA artwork")?;
    }
    let mut metadata = metadata
        .as_object()
        .context("Store IPA metadata is not a dictionary")?
        .clone();
    metadata.insert("apple-id".into(), apple_id.into());
    metadata.insert("userName".into(), apple_id.into());
    writer
        .start_file("iTunesMetadata.plist", SimpleFileOptions::default())
        .context("create IPA metadata entry")?;
    plist::to_writer_binary(&mut writer, &metadata).context("write IPA metadata")?;
    if !sinfs.is_empty() {
        let paths = sinf_paths(&mut archive, sinfs.len())?;
        for (path, sinf) in paths.into_iter().zip(sinfs) {
            let fields = sinf
                .as_dictionary()
                .context("Store SINF entry is not a dictionary")?;
            let data = match fields.get("sinf") {
                Some(Value::Data(data)) => data.as_slice(),
                None => &[],
                Some(_) => bail!("Store SINF data has an invalid type"),
            };
            writer
                .start_file(path, SimpleFileOptions::default())
                .context("create IPA SINF entry")?;
            writer.write_all(data).context("write IPA SINF")?;
        }
    }
    let _ = writer
        .finish()
        .context("finalize IPA replacement entries")?;
    let mut file = output.reopen().context("open temporary IPA")?;
    ipa_zip_repack::repack(&File::open(source)?, &additions.reopen()?, &mut file)
        .context("repack IPA ZIP")?;
    file.sync_all().context("sync patched IPA")?;
    output
        .persist(destination)
        .with_context(|| format!("publish patched IPA {}", destination.display()))?;
    Ok(())
}

fn sinf_paths(archive: &mut ZipArchive<File>, count: usize) -> Result<Vec<String>> {
    let mut bundle = None;
    let mut info_index = None;
    let mut manifests = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).context("inspect IPA entry")?;
        let entry_name = entry.name()?.into_owned();
        let parts: Vec<_> = entry_name.split('/').collect();
        if parts.len() == 3
            && parts[0] == "Payload"
            && parts[1].ends_with(".app")
            && parts[1].len() > ".app".len()
            && parts[2] == "Info.plist"
            && info_index.is_none()
        {
            bundle = Some(parts[1].to_owned());
            info_index = Some(index);
        }
        if parts.len() == 4
            && parts[0] == "Payload"
            && parts[1].ends_with(".app")
            && parts[2] == "SC_Info"
            && parts[3] == "Manifest.plist"
        {
            manifests.push((parts[1].to_owned(), index));
        }
    }
    let bundle = bundle.context("IPA has no top-level app Info.plist")?;
    if let Some((_, index)) = manifests.iter().find(|(name, _)| name == &bundle) {
        let manifest = read_plist_entry(archive, *index)?;
        let paths = manifest
            .as_dictionary()
            .and_then(|fields| fields.get("SinfPaths"))
            .and_then(Value::as_array)
            .context("IPA SINF manifest has no paths")?;
        if paths.len() != count {
            bail!("IPA SINF manifest count does not match Store SINF count");
        }
        return paths
            .iter()
            .map(|value| {
                let relative = value.as_string().context("invalid IPA SINF path")?;
                if relative.is_empty()
                    || relative.starts_with('/')
                    || relative
                        .split('/')
                        .any(|part| part.is_empty() || part == "." || part == "..")
                    || relative.contains('\\')
                {
                    bail!("unsafe IPA SINF path");
                }
                Ok(format!("Payload/{bundle}/{relative}"))
            })
            .collect();
    }
    let info = read_plist_entry(archive, info_index.unwrap())?;
    let executable = info
        .as_dictionary()
        .and_then(|fields| fields.get("CFBundleExecutable"))
        .and_then(Value::as_string)
        .filter(|name| !name.is_empty() && !name.contains('/') && !name.contains('\\'))
        .context("IPA has no valid CFBundleExecutable")?;
    Ok(vec![format!("Payload/{bundle}/SC_Info/{executable}.sinf")])
}

fn read_plist_entry(archive: &mut ZipArchive<File>, index: usize) -> Result<Value> {
    let mut entry = archive.by_index(index).context("read IPA plist entry")?;
    if entry.size() > MAX_PLIST {
        bail!("IPA plist exceeds size limit");
    }
    let mut data = Vec::with_capacity(entry.size() as usize);
    entry
        .by_ref()
        .take(MAX_PLIST + 1)
        .read_to_end(&mut data)
        .context("read IPA plist")?;
    if data.len() as u64 > MAX_PLIST {
        bail!("IPA plist exceeds size limit");
    }
    plist::from_bytes(&data).context("decode IPA plist")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    fn source(manifest: Option<&str>) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.ipa");
        let mut writer = ZipWriter::new(File::create(&path).unwrap());
        let options = SimpleFileOptions::default();
        writer
            .start_file("Payload/App.app/Info.plist", options)
            .unwrap();
        writer
            .write_all(br#"<plist version="1.0"><dict><key>CFBundleExecutable</key><string>App</string></dict></plist>"#)
            .unwrap();
        if let Some(manifest) = manifest {
            writer
                .start_file("Payload/App.app/SC_Info/Manifest.plist", options)
                .unwrap();
            let mut fields = plist::Dictionary::new();
            fields.insert(
                "SinfPaths".into(),
                Value::Array(vec![Value::String(manifest.into())]),
            );
            plist::to_writer_xml(&mut writer, &Value::Dictionary(fields)).unwrap();
        }
        writer.start_file("Payload/App.app/App", options).unwrap();
        writer.write_all(b"executable").unwrap();
        writer.finish().unwrap();
        (directory, path)
    }

    fn mobile_sinf() -> Value {
        let mut fields = plist::Dictionary::new();
        fields.insert("sinf".into(), Value::Data(b"ticket".to_vec()));
        Value::Dictionary(fields)
    }

    fn zip_extras(path: &Path, entry_name: &str) -> (Vec<u8>, Vec<u8>) {
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        let entry = archive.by_name(entry_name).unwrap();
        let header_start = entry.header_start();
        let central = entry.extra_data().unwrap_or_default().to_vec();
        let mut file = File::open(path).unwrap();
        file.seek(SeekFrom::Start(header_start + 26)).unwrap();
        let mut lengths = [0u8; 4];
        file.read_exact(&mut lengths).unwrap();
        let name_len = u16::from_le_bytes(lengths[..2].try_into().unwrap()) as u64;
        let extra_len = u16::from_le_bytes(lengths[2..].try_into().unwrap()) as usize;
        file.seek(SeekFrom::Start(header_start + 30 + name_len))
            .unwrap();
        let mut local = vec![0; extra_len];
        file.read_exact(&mut local).unwrap();
        (local, central)
    }

    #[test]
    fn preserves_distinct_local_and_central_zip_extras() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.ipa");
        let mut writer = ZipWriter::new(File::create(&source).unwrap());
        let mut options = zip::write::FullFileOptions::default();
        options.add_extra_field(0xcafe, [1, 2, 3], false).unwrap();
        options.add_extra_field(0xbeef, [4, 5, 6], true).unwrap();
        writer.start_file("Payload/App.app/App", options).unwrap();
        writer.write_all(b"executable").unwrap();
        writer.finish().unwrap();
        let before = zip_extras(&source, "Payload/App.app/App");
        assert_ne!(before.0, before.1);

        let destination = directory.path().join("patched.ipa");
        patch_ipa(
            &source,
            &destination,
            &serde_json::json!({}),
            "account",
            &[],
            &[],
        )
        .unwrap();
        let after = zip_extras(&destination, "Payload/App.app/App");
        assert_eq!(after, before);
    }

    #[test]
    fn writes_metadata_artwork_and_manifest_sinf() {
        let (directory, input) = source(Some("SC_Info/Custom.sinf"));
        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &input,
            &output,
            &serde_json::json!({"itemId": 42}),
            "person@example.test",
            b"artwork",
            &[mobile_sinf()],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let mut executable = Vec::new();
        archive
            .by_name("Payload/App.app/App")
            .unwrap()
            .read_to_end(&mut executable)
            .unwrap();
        assert_eq!(executable, b"executable");
        let mut artwork = Vec::new();
        archive
            .by_name("iTunesArtwork")
            .unwrap()
            .read_to_end(&mut artwork)
            .unwrap();
        assert_eq!(artwork, b"artwork");
        let mut metadata = Vec::new();
        archive
            .by_name("iTunesMetadata.plist")
            .unwrap()
            .read_to_end(&mut metadata)
            .unwrap();
        let metadata: Value = plist::from_bytes(&metadata).unwrap();
        assert_eq!(
            metadata.as_dictionary().unwrap()["apple-id"].as_string(),
            Some("person@example.test")
        );
        assert_eq!(
            metadata.as_dictionary().unwrap()["itemId"].as_unsigned_integer(),
            Some(42)
        );
        let mut sinf = Vec::new();
        archive
            .by_name("Payload/App.app/SC_Info/Custom.sinf")
            .unwrap()
            .read_to_end(&mut sinf)
            .unwrap();
        assert_eq!(sinf, b"ticket");
    }

    #[test]
    fn replaces_existing_store_metadata() {
        let (directory, input) = source(None);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&input)
            .unwrap();
        let mut writer = ZipWriter::new_append(file).unwrap();
        writer
            .start_file("iTunesMetadata.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"old metadata").unwrap();
        writer.finish().unwrap();
        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &input,
            &output,
            &serde_json::json!({}),
            "new@example.com",
            &[],
            &[],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(output).unwrap()).unwrap();
        let mut metadata = Vec::new();
        archive
            .by_name("iTunesMetadata.plist")
            .unwrap()
            .read_to_end(&mut metadata)
            .unwrap();
        let plist = plist::from_bytes::<Value>(&metadata).unwrap();
        assert_eq!(
            plist.as_dictionary().unwrap()["apple-id"].as_string(),
            Some("new@example.com")
        );
    }

    #[test]
    fn replaces_existing_artwork_and_sinf() {
        let (directory, input) = source(None);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&input)
            .unwrap();
        let mut writer = ZipWriter::new_append(file).unwrap();
        for (name, bytes) in [
            ("iTunesArtwork", b"old artwork".as_slice()),
            ("Payload/App.app/SC_Info/App.sinf", b"old ticket".as_slice()),
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &input,
            &output,
            &serde_json::json!({}),
            "new@example.com",
            b"new artwork",
            &[mobile_sinf()],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(output).unwrap()).unwrap();
        for (name, expected) in [
            ("iTunesArtwork", b"new artwork".as_slice()),
            ("Payload/App.app/SC_Info/App.sinf", b"ticket".as_slice()),
        ] {
            let mut actual = Vec::new();
            archive
                .by_name(name)
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                archive
                    .file_names_raw()
                    .filter(|candidate| *candidate == name.as_bytes())
                    .count(),
                1
            );
        }
    }

    #[test]
    fn repacks_deflated_entries_for_streaming_without_orphan_headers() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let mut writer = ZipWriter::new(File::create(&input).unwrap());
        writer
            .start_file("Payload/App.app/Info.plist", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(br#"<plist version="1.0"><dict><key>CFBundleExecutable</key><string>App</string></dict></plist>"#)
            .unwrap();
        writer
            .start_file(
                "Payload/App.app/App",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&vec![b'A'; 16_384]).unwrap();
        writer
            .start_file("iTunesMetadata.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"old metadata").unwrap();
        writer.finish().unwrap();

        let output = directory.path().join("patched.ipa");
        patch_ipa(&input, &output, &serde_json::json!({}), "account", &[], &[]).unwrap();
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        assert_eq!(archive.len(), 3);
        let mut headers = Vec::new();
        for index in 0..archive.len() {
            let entry = archive.by_index(index).unwrap();
            headers.push((
                entry.header_start(),
                entry.data_start().unwrap(),
                entry.compressed_size(),
                entry.compression(),
                entry.central_header_start(),
            ));
        }
        headers.sort_by_key(|entry| entry.0);
        assert_eq!(headers[0].0, 0);
        let mut file = File::open(&output).unwrap();
        for (index, &(start, data_start, size, method, _)) in headers.iter().enumerate() {
            file.seek(SeekFrom::Start(start + 6)).unwrap();
            let mut flags = [0u8; 2];
            file.read_exact(&mut flags).unwrap();
            let uses_descriptor = u16::from_le_bytes(flags) & 8 != 0;
            assert_eq!(uses_descriptor, method == zip::CompressionMethod::Deflated);
            let end = data_start + size;
            if uses_descriptor {
                file.seek(SeekFrom::Start(end)).unwrap();
                let mut signature = [0u8; 4];
                file.read_exact(&mut signature).unwrap();
                assert_eq!(signature, 0x0807_4b50u32.to_le_bytes());
            }
            let next = end + if uses_descriptor { 16 } else { 0 };
            assert_eq!(next, headers.get(index + 1).map_or(headers[0].4, |h| h.0));
        }
        let mut executable = Vec::new();
        archive
            .by_name("Payload/App.app/App")
            .unwrap()
            .read_to_end(&mut executable)
            .unwrap();
        assert_eq!(executable, vec![b'A'; 16_384]);
    }

    #[test]
    fn clears_existing_stored_descriptors_and_inlines_sizes() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.ipa");
        let mut writer = ZipWriter::new_stream(File::create(&input).unwrap());
        writer
            .start_file(
                "Payload/App.app/Info.plist",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer
            .write_all(br#"<plist version="1.0"><dict><key>CFBundleExecutable</key><string>App</string></dict></plist>"#)
            .unwrap();
        writer.finish().unwrap();
        let output = directory.path().join("patched.ipa");
        patch_ipa(&input, &output, &serde_json::json!({}), "account", &[], &[]).unwrap();
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let entry = archive.by_name("Payload/App.app/Info.plist").unwrap();
        let start = entry.header_start();
        let end = entry.data_start().unwrap() + entry.compressed_size();
        let crc = entry.crc32();
        let size = entry.compressed_size() as u32;
        let mut file = File::open(&output).unwrap();
        let mut local = [0u8; 30];
        file.seek(SeekFrom::Start(start)).unwrap();
        file.read_exact(&mut local).unwrap();
        assert_eq!(u16::from_le_bytes(local[6..8].try_into().unwrap()) & 8, 0);
        assert_eq!(u32::from_le_bytes(local[14..18].try_into().unwrap()), crc);
        assert_eq!(u32::from_le_bytes(local[18..22].try_into().unwrap()), size);
        assert_eq!(u32::from_le_bytes(local[22..26].try_into().unwrap()), size);
        let mut signature = [0u8; 4];
        file.seek(SeekFrom::Start(end)).unwrap();
        file.read_exact(&mut signature).unwrap();
        assert_eq!(signature, 0x0403_4b50u32.to_le_bytes());
    }

    #[test]
    fn repacks_prefixed_archive_without_copying_prefix() {
        let (directory, input) = source(None);
        let prefixed = directory.path().join("prefixed.ipa");
        let mut file = File::create(&prefixed).unwrap();
        file.write_all(b"launcher prefix").unwrap();
        file.write_all(&std::fs::read(&input).unwrap()).unwrap();
        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &prefixed,
            &output,
            &serde_json::json!({}),
            "account",
            &[],
            &[],
        )
        .unwrap();
        let mut signature = [0u8; 4];
        File::open(&output)
            .unwrap()
            .read_exact(&mut signature)
            .unwrap();
        assert_eq!(signature, 0x0403_4b50u32.to_le_bytes());
        let mut archive = ZipArchive::new(File::open(output).unwrap()).unwrap();
        let mut executable = Vec::new();
        archive
            .by_name("Payload/App.app/App")
            .unwrap()
            .read_to_end(&mut executable)
            .unwrap();
        assert_eq!(executable, b"executable");
    }

    #[test]
    fn repacks_zip64_directory_and_entry_offset_without_stale_metadata() {
        let (directory, input) = source(None);
        let mut data = std::fs::read(&input).unwrap();
        let end = data.len() - 22;
        assert_eq!(&data[end..end + 4], &0x0605_4b50u32.to_le_bytes());
        let central_offset =
            u32::from_le_bytes(data[end + 16..end + 20].try_into().unwrap()) as usize;
        let original_central_size =
            u32::from_le_bytes(data[end + 12..end + 16].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(
            data[central_offset + 28..central_offset + 30]
                .try_into()
                .unwrap(),
        ) as usize;
        let extra_len = u16::from_le_bytes(
            data[central_offset + 30..central_offset + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(extra_len, 0);
        data[central_offset + 30..central_offset + 32].copy_from_slice(&12u16.to_le_bytes());
        data[central_offset + 42..central_offset + 46].copy_from_slice(&u32::MAX.to_le_bytes());
        let inserted_at = central_offset + 46 + name_len;
        let mut offset_extra = Vec::new();
        offset_extra.extend_from_slice(&1u16.to_le_bytes());
        offset_extra.extend_from_slice(&8u16.to_le_bytes());
        offset_extra.extend_from_slice(&0u64.to_le_bytes());
        data.splice(inserted_at..inserted_at, offset_extra);
        let new_end = end + 12;
        let ordinary_end = data[new_end..].to_vec();
        data.truncate(new_end);
        let zip64_end_offset = data.len() as u64;
        data.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
        data.extend_from_slice(&44u64.to_le_bytes());
        data.extend_from_slice(&45u16.to_le_bytes());
        data.extend_from_slice(&45u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&2u64.to_le_bytes());
        data.extend_from_slice(&2u64.to_le_bytes());
        data.extend_from_slice(&((original_central_size + 12) as u64).to_le_bytes());
        data.extend_from_slice(&(central_offset as u64).to_le_bytes());
        data.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&zip64_end_offset.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        let mut ordinary_end = ordinary_end;
        ordinary_end[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        ordinary_end[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        ordinary_end[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        ordinary_end[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        data.extend_from_slice(&ordinary_end);
        let zip64_input = directory.path().join("zip64.ipa");
        std::fs::write(&zip64_input, data).unwrap();
        assert_eq!(
            ZipArchive::new(File::open(&zip64_input).unwrap())
                .unwrap()
                .len(),
            2
        );

        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &zip64_input,
            &output,
            &serde_json::json!({}),
            "account",
            &[],
            &[],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        assert_eq!(archive.len(), 3);
        let mut executable = Vec::new();
        archive
            .by_name("Payload/App.app/App")
            .unwrap()
            .read_to_end(&mut executable)
            .unwrap();
        assert_eq!(executable, b"executable");
        let first = archive.by_index(0).unwrap();
        assert_eq!(first.header_start(), 0);
        assert!(first.extra_data().unwrap_or_default().is_empty());
    }

    #[test]
    fn uses_info_executable_and_rejects_unsafe_manifest_without_publishing() {
        let (directory, input) = source(None);
        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &input,
            &output,
            &serde_json::json!({}),
            "account",
            &[],
            &[mobile_sinf()],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        assert!(archive.by_name("Payload/App.app/SC_Info/App.sinf").is_ok());

        let (_, unsafe_input) = source(Some("../../outside.sinf"));
        let bad_output = directory.path().join("bad.ipa");
        assert!(
            patch_ipa(
                &unsafe_input,
                &bad_output,
                &serde_json::json!({}),
                "account",
                &[],
                &[mobile_sinf()]
            )
            .is_err()
        );
        assert!(!bad_output.exists());
    }

    #[test]
    fn accepts_empty_sinf_data_with_and_without_manifest() {
        for manifest in [Some("SC_Info/Custom.sinf"), None] {
            let (directory, input) = source(manifest);
            let output = directory.path().join("patched.ipa");
            let mut fields = plist::Dictionary::new();
            fields.insert("sinf".into(), Value::Data(Vec::new()));
            patch_ipa(
                &input,
                &output,
                &serde_json::json!({}),
                "account",
                &[],
                &[Value::Dictionary(fields)],
            )
            .unwrap();
            let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
            let name = manifest.unwrap_or("SC_Info/App.sinf");
            let path = format!("Payload/App.app/{name}");
            let entry = archive.by_name(&path).unwrap();
            assert_eq!(entry.size(), 0);
        }
    }

    #[test]
    fn accepts_omitted_sinf_data_as_empty() {
        let (directory, input) = source(None);
        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &input,
            &output,
            &serde_json::json!({}),
            "account",
            &[],
            &[Value::Dictionary(plist::Dictionary::new())],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        assert_eq!(
            archive
                .by_name("Payload/App.app/SC_Info/App.sinf")
                .unwrap()
                .size(),
            0
        );
    }

    #[test]
    fn ignores_manifest_from_a_different_app_bundle() {
        let (directory, input) = source(None);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&input)
            .unwrap();
        let mut writer = ZipWriter::new_append(file).unwrap();
        writer
            .start_file(
                "Payload/Other.app/SC_Info/Manifest.plist",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer
            .write_all(br#"<plist version="1.0"><dict><key>SinfPaths</key><array><string>SC_Info/Other.sinf</string></array></dict></plist>"#)
            .unwrap();
        writer.finish().unwrap();

        let output = directory.path().join("patched.ipa");
        patch_ipa(
            &input,
            &output,
            &serde_json::json!({}),
            "account",
            &[],
            &[mobile_sinf()],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        assert!(archive.by_name("Payload/App.app/SC_Info/App.sinf").is_ok());
        assert!(
            archive
                .by_name("Payload/App.app/SC_Info/Other.sinf")
                .is_err()
        );
    }
}
