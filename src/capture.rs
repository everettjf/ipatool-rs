//! Private FairPlay enrollment capture manifest validation.

use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fairplay::SinfSelector;

pub const ENROLLMENT_CAPTURE_SCHEMA: &str = "ipatool-fairplay-native-enrollment-capture-v1";
pub const FAIRPLAY_BUILD_26A428_HASH: &str =
    "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784";
pub const FAIRPLAY_BUILD_26B118_HASH: &str =
    "f68e4407e90af5466d2766e1b1c4637260d08cb0518f991e1797ac6c4964439d";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct FairPlayBuildSupport {
    pub profile: String,
    pub build: String,
    pub status: String,
    pub recovery: bool,
    #[serde(rename = "end_to_end_decryption")]
    pub decrypt: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub compatibility_profile: String,
    #[serde(
        rename = "compatibility_fairplayd_sha256",
        skip_serializing_if = "String::is_empty"
    )]
    pub compatibility_sha256: String,
}

pub fn lookup_fairplay_build(hash: &str) -> Option<FairPlayBuildSupport> {
    match hash.to_ascii_lowercase().as_str() {
        FAIRPLAY_BUILD_26A428_HASH => Some(FairPlayBuildSupport {
            profile: "macos26a428".into(),
            build: "26A428".into(),
            status: "supported".into(),
            recovery: true,
            decrypt: true,
            ..FairPlayBuildSupport::default()
        }),
        FAIRPLAY_BUILD_26B118_HASH => Some(FairPlayBuildSupport {
            profile: "macos26b118".into(),
            build: "26B118".into(),
            status: "supported-with-compatibility".into(),
            recovery: true,
            decrypt: true,
            compatibility_profile: "macos26a428".into(),
            compatibility_sha256: FAIRPLAY_BUILD_26A428_HASH.into(),
        }),
        _ => None,
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CaptureFile {
    pub path: String,
    pub bytes: i64,
    pub sha256: String,
    pub mode: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CaptureApp {
    pub bundle_identifier: String,
    pub executable: String,
    pub executable_path: String,
    pub selector: SinfSelector,
    pub selector_id: String,
    pub sinf_path: String,
    pub target_sinf_path: String,
    pub ipa_member_root: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct EnrollmentCaptureManifest {
    pub schema: String,
    pub created_at: String,
    pub product_version: String,
    pub build_version: String,
    pub fairplayd: CaptureFile,
    #[serde(rename = "fairplay_support")]
    pub fairplay: FairPlayBuildSupport,
    pub hardware_iomac: CaptureFile,
    pub app: CaptureApp,
    pub ipa: Option<CaptureFile>,
    pub files: Vec<CaptureFile>,
    pub warnings: Vec<String>,
}

pub fn capture_file_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() {
        bail!("capture contains an unsafe relative path: {relative:?}");
    }
    let value = Path::new(relative);
    if value.is_absolute()
        || value.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("capture contains an unsafe relative path: {relative:?}");
    }
    Ok(root.join(value))
}

pub fn load_enrollment_capture(path: &Path, verify: bool) -> Result<EnrollmentCaptureManifest> {
    let info = fs::metadata(path)
        .with_context(|| format!("inspect capture directory: {}", path.display()))?;
    if !info.is_dir() || !private_permissions(&info) {
        bail!("enrollment capture directory must be private (mode 0700 or stricter)");
    }
    let data = fs::read(path.join("manifest.json")).context("read enrollment capture manifest")?;
    let mut manifest: EnrollmentCaptureManifest =
        serde_json::from_slice(&data).context("decode enrollment capture manifest")?;
    if manifest.schema != ENROLLMENT_CAPTURE_SCHEMA {
        bail!(
            "unsupported enrollment capture schema {:?}",
            manifest.schema
        );
    }
    manifest.fairplay =
        lookup_fairplay_build(&manifest.fairplayd.sha256).unwrap_or_else(|| FairPlayBuildSupport {
            build: manifest.build_version.clone(),
            status: "unsupported".into(),
            ..FairPlayBuildSupport::default()
        });
    if verify {
        for entry in &manifest.files {
            let full = capture_file_path(path, &entry.path)?;
            let info = fs::symlink_metadata(&full)
                .with_context(|| format!("inspect capture file: {}", entry.path))?;
            if !info.file_type().is_file() || !private_permissions(&info) {
                bail!("capture file is not private and regular: {}", entry.path);
            }
            let mut input = fs::File::open(&full)
                .with_context(|| format!("open capture file: {}", entry.path))?;
            let mut hash = Sha256::new();
            let size = std::io::copy(&mut input, &mut hash)
                .with_context(|| format!("hash capture file: {}", entry.path))?;
            if format!("{:x}", hash.finalize()) != entry.sha256 || size as i64 != entry.bytes {
                bail!("capture file changed: {}", entry.path);
            }
        }
    }
    Ok(manifest)
}

fn private_permissions(info: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        info.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = info;
        true
    }
}

pub fn model_matches_capture_build(model_hash: &str, capture: &EnrollmentCaptureManifest) -> bool {
    model_hash == capture.fairplayd.sha256
        || (!capture.fairplay.compatibility_sha256.is_empty()
            && model_hash == capture.fairplay.compatibility_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_supported_build_and_detects_tampering() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("capture");
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let file = dir.join("private.bin");
        fs::write(&file, b"private fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut manifest = EnrollmentCaptureManifest {
            schema: ENROLLMENT_CAPTURE_SCHEMA.into(),
            fairplayd: CaptureFile {
                sha256: FAIRPLAY_BUILD_26B118_HASH.into(),
                ..CaptureFile::default()
            },
            files: vec![CaptureFile {
                path: "private.bin".into(),
                bytes: 15,
                sha256: format!("{:x}", Sha256::digest(b"private fixture")),
                mode: "0600".into(),
            }],
            ..EnrollmentCaptureManifest::default()
        };
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let loaded = load_enrollment_capture(&dir, true).unwrap();
        assert_eq!(loaded.fairplay.status, "supported-with-compatibility");
        assert!(model_matches_capture_build(
            FAIRPLAY_BUILD_26A428_HASH,
            &loaded
        ));
        fs::write(&file, b"changed").unwrap();
        assert!(load_enrollment_capture(&dir, true).is_err());
        manifest.files[0].path = "../outside.bin".into();
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(load_enrollment_capture(&dir, true).is_err());
    }

    #[test]
    fn rejects_absolute_and_parent_paths() {
        let root = Path::new("/private/capture");
        assert!(capture_file_path(root, "../secret").is_err());
        assert!(capture_file_path(root, "/tmp/secret").is_err());
        assert_eq!(
            capture_file_path(root, "state/info.bin").unwrap(),
            root.join("state/info.bin")
        );
    }
}
