//! Identify and validate the package returned by the Store download endpoint.

use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result, bail};
use plist::Value;
use zip::ZipArchive;

use crate::{Platform, duplicate_zip, store_download_product::DownloadItem};

const MAX_INFO_PLIST: u64 = 4 * 1024 * 1024;

pub fn package_platform(requested: Platform, item: &DownloadItem) -> Result<Platform> {
    if requested != Platform::Macos {
        return Ok(requested);
    }
    let software_platform = item
        .metadata_field("software-platform")
        .and_then(Value::as_string)
        .unwrap_or_default();
    let product_type = item
        .metadata_field("product-type")
        .and_then(Value::as_string)
        .unwrap_or_default();
    let (mobile_metadata, mac_metadata) = if software_platform.is_empty() {
        (
            product_type.eq_ignore_ascii_case("ios-app"),
            product_type.eq_ignore_ascii_case("mac-os-app"),
        )
    } else {
        (
            software_platform.eq_ignore_ascii_case("ios"),
            software_platform.eq_ignore_ascii_case("macos"),
        )
    };
    let mobile_sinf_evidence = item
        .sinfs
        .iter()
        .any(|sinf| !sinf_data(sinf, "sinf").is_empty() && sinf_data(sinf, "dpInfo").is_empty());
    let mobile_sinf = !item.sinfs.is_empty()
        && item.sinfs.iter().all(|sinf| {
            !sinf_data(sinf, "sinf").is_empty() && sinf_data(sinf, "dpInfo").is_empty()
        });
    let mac_dp_info = item
        .sinfs
        .iter()
        .any(|sinf| !sinf_data(sinf, "dpInfo").is_empty());
    if (mobile_metadata && mac_dp_info)
        || (mac_metadata && mobile_sinf_evidence)
        || (mobile_sinf_evidence && mac_dp_info)
    {
        bail!("download response contains conflicting package metadata");
    }
    if mobile_metadata || mobile_sinf_evidence {
        if !mobile_sinf {
            bail!("download response does not contain mobile SINF data");
        }
        return Ok(Platform::Iphone);
    }
    Ok(Platform::Macos)
}

fn sinf_data<'a>(sinf: &'a Value, key: &str) -> &'a [u8] {
    sinf.as_dictionary()
        .and_then(|fields| fields.get(key))
        .and_then(Value::as_data)
        .unwrap_or_default()
}

pub fn validate_ipa_platform(path: &Path, platform: Platform) -> Result<()> {
    let expected = match platform {
        Platform::Iphone | Platform::Ipad => "iPhoneOS",
        Platform::Appletv => "AppleTVOS",
        Platform::Watchos => "WatchOS",
        Platform::Visionos => "XROS",
        Platform::Unknown | Platform::Macos => return Ok(()),
    };
    let file = File::open(path).with_context(|| format!("open IPA {}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("open IPA ZIP")?;
    let mut raw_source = File::open(path).context("open IPA ZIP filename source")?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("read IPA ZIP entry")?;
        let raw_name =
            duplicate_zip::read_raw_central_name(&mut raw_source, entry.central_header_start())?;
        let entry_name = String::from_utf8_lossy(&raw_name);
        let parts: Vec<_> = entry_name.split('/').collect();
        if parts.len() != 3
            || parts[0] != "Payload"
            || !parts[1].ends_with(".app")
            || parts[2] != "Info.plist"
        {
            continue;
        }
        if entry.size() > MAX_INFO_PLIST {
            bail!("IPA Info.plist exceeds size limit");
        }
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .by_ref()
            .take(MAX_INFO_PLIST + 1)
            .read_to_end(&mut data)
            .context("read IPA Info.plist")?;
        if data.len() as u64 > MAX_INFO_PLIST {
            bail!("IPA Info.plist exceeds size limit");
        }
        let info: Value = plist::from_bytes(&data).context("decode IPA Info.plist")?;
        let declared = info
            .as_dictionary()
            .context("IPA Info.plist is not a dictionary")?
            .get("CFBundleSupportedPlatforms");
        if declared.is_none() && expected == "iPhoneOS" {
            return Ok(());
        }
        if declared.and_then(Value::as_array).is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_string() == Some(expected))
        }) {
            return Ok(());
        }
    }
    bail!("downloaded package does not declare {expected} support")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn item(metadata: serde_json::Value, sinfs: Vec<Value>) -> DownloadItem {
        DownloadItem {
            url: String::new(),
            preflight_package_url: String::new(),
            artwork_url: String::new(),
            sinfs,
            metadata: serde_json::from_value(metadata).unwrap(),
        }
    }

    fn sinf(mobile: bool, mac: bool) -> Value {
        let mut fields = plist::Dictionary::new();
        if mobile {
            fields.insert("sinf".into(), Value::Data(vec![1, 2]));
        }
        if mac {
            fields.insert("dpInfo".into(), Value::Data(vec![3, 4]));
        }
        Value::Dictionary(fields)
    }

    #[test]
    fn detects_mobile_package_on_mac_and_rejects_conflicts() {
        assert_eq!(
            package_platform(
                Platform::Macos,
                &item(
                    serde_json::json!({"software-platform": "ios"}),
                    vec![sinf(true, false)]
                )
            )
            .unwrap(),
            Platform::Iphone
        );
        assert_eq!(
            package_platform(
                Platform::Macos,
                &item(
                    serde_json::json!({"software-platform": "macos", "product-type": "ios-app"}),
                    vec![sinf(false, true)]
                )
            )
            .unwrap(),
            Platform::Macos
        );
        assert!(
            package_platform(
                Platform::Macos,
                &item(
                    serde_json::json!({"software-platform": "macos"}),
                    vec![sinf(true, false)]
                )
            )
            .is_err()
        );
    }

    fn ipa(platforms: Option<&[&str]>) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(File::create(file.path()).unwrap());
        writer
            .start_file("Payload/App.app/Info.plist", SimpleFileOptions::default())
            .unwrap();
        let mut fields = plist::Dictionary::new();
        if let Some(platforms) = platforms {
            fields.insert(
                "CFBundleSupportedPlatforms".into(),
                Value::Array(
                    platforms
                        .iter()
                        .map(|value| Value::String((*value).into()))
                        .collect(),
                ),
            );
        }
        let mut data = Vec::new();
        plist::to_writer_xml(&mut data, &Value::Dictionary(fields)).unwrap();
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();
        file
    }

    #[test]
    fn validates_declared_platform_and_ios_legacy_exception() {
        assert!(validate_ipa_platform(ipa(Some(&["AppleTVOS"])).path(), Platform::Appletv).is_ok());
        assert!(validate_ipa_platform(ipa(Some(&["AppleTVOS"])).path(), Platform::Iphone).is_err());
        assert!(validate_ipa_platform(ipa(None).path(), Platform::Iphone).is_ok());
        assert!(validate_ipa_platform(ipa(Some(&[])).path(), Platform::Iphone).is_err());
        assert!(validate_ipa_platform(ipa(None).path(), Platform::Visionos).is_err());
    }

    #[test]
    fn validates_original_info_plist_name_when_unicode_path_aliases_it() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let info = br#"<plist version="1.0"><dict><key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array></dict></plist>"#;
        crate::duplicate_zip::write_unicode_path_member_fixture(
            file.path(),
            "Payload/A.app/Info.plist",
            "Payload/B.app/Other.plist",
            0xdfd6_01cb,
            info,
        );
        assert!(validate_ipa_platform(file.path(), Platform::Iphone).is_ok());
    }

    #[test]
    fn checks_all_top_level_apps_before_rejecting_platform() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(File::create(file.path()).unwrap());
        for (name, platform) in [("First", "AppleTVOS"), ("Second", "iPhoneOS")] {
            writer
                .start_file(
                    format!("Payload/{name}.app/Info.plist"),
                    SimpleFileOptions::default(),
                )
                .unwrap();
            let mut fields = plist::Dictionary::new();
            fields.insert(
                "CFBundleSupportedPlatforms".into(),
                Value::Array(vec![Value::String(platform.into())]),
            );
            plist::to_writer_xml(&mut writer, &Value::Dictionary(fields)).unwrap();
        }
        writer.finish().unwrap();

        assert!(validate_ipa_platform(file.path(), Platform::Iphone).is_ok());
        assert!(validate_ipa_platform(file.path(), Platform::Visionos).is_err());
    }

    #[test]
    fn accepts_go_top_level_app_name_and_patches_without_sinf() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(File::create(file.path()).unwrap());
        writer
            .start_file("Payload/.app/Info.plist", SimpleFileOptions::default())
            .unwrap();
        let mut fields = plist::Dictionary::new();
        fields.insert(
            "CFBundleSupportedPlatforms".into(),
            Value::Array(vec![Value::String("iPhoneOS".into())]),
        );
        plist::to_writer_xml(&mut writer, &Value::Dictionary(fields)).unwrap();
        writer.finish().unwrap();

        validate_ipa_platform(file.path(), Platform::Iphone).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("patched.ipa");
        crate::ipa_patch::patch_ipa(
            file.path(),
            &output,
            &Value::Dictionary(plist::Dictionary::new()),
            "person@example.test",
            &[],
            &[],
        )
        .unwrap();
        let mut archive = ZipArchive::new(File::open(output).unwrap()).unwrap();
        assert!(archive.by_name("iTunesMetadata.plist").is_ok());
    }
}
