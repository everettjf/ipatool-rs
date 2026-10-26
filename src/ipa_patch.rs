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
    let mut writer = ZipWriter::new(output.reopen().context("open temporary IPA")?);
    for index in 0..archive.len() {
        let entry = archive
            .by_index_raw(index)
            .context("read downloaded IPA entry")?;
        writer.raw_copy_file(entry).context("copy IPA ZIP entry")?;
    }
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
            let data = sinf
                .as_dictionary()
                .and_then(|fields| fields.get("sinf"))
                .and_then(Value::as_data)
                .context("Store SINF entry has no data")?;
            if data.is_empty() {
                bail!("Store SINF entry is empty");
            }
            writer
                .start_file(path, SimpleFileOptions::default())
                .context("create IPA SINF entry")?;
            writer.write_all(data).context("write IPA SINF")?;
        }
    }
    let file = writer.finish().context("finalize patched IPA ZIP")?;
    file.sync_all().context("sync patched IPA")?;
    output
        .persist(destination)
        .with_context(|| format!("publish patched IPA {}", destination.display()))?;
    Ok(())
}

fn sinf_paths(archive: &mut ZipArchive<File>, count: usize) -> Result<Vec<String>> {
    let mut bundle = None;
    let mut info_index = None;
    let mut manifest_index = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).context("inspect IPA entry")?;
        let parts: Vec<_> = entry.name().split('/').collect();
        if parts.len() == 3
            && parts[0] == "Payload"
            && parts[1].ends_with(".app")
            && parts[1].len() > ".app".len()
            && parts[2] == "Info.plist"
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
            manifest_index = Some(index);
        }
    }
    let bundle = bundle.context("IPA has no top-level app Info.plist")?;
    if let Some(index) = manifest_index {
        let manifest = read_plist_entry(archive, index)?;
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
}
