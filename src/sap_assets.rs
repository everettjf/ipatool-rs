//! Pinned macOS 27.0.1 assets used by the SAP, KBSync, and FairPlay guests.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

const CACHE_DIRECTORY: &str = "apple-assets-macos-27-26A434-arm64-v1";

#[derive(Clone, Copy)]
struct AssetSpec {
    name: &'static str,
    size: usize,
    sha256: &'static str,
}

const SPECS: [AssetSpec; 4] = [
    AssetSpec {
        name: "AppleMediaServices",
        size: 14_813_888,
        sha256: "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4",
    },
    AssetSpec {
        name: "commerce",
        size: 8_092_640,
        sha256: "76de40a4a32f691947cb926ce3b128d2fc446f7cac9755f831c406cf5a316ac9",
    },
    AssetSpec {
        name: "CoreFP",
        size: 94_842_464,
        sha256: "2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46",
    },
    AssetSpec {
        name: "CoreFP.icxs",
        size: 7_365_344,
        sha256: "cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b",
    },
];

pub struct SapAssetBundle {
    pub apple_media_services: Vec<u8>,
    pub commerce: Vec<u8>,
    pub core_fp: Vec<u8>,
    pub core_fp_icxs: Vec<u8>,
}

impl SapAssetBundle {
    pub fn validate(&self) -> Result<()> {
        for (spec, bytes) in SPECS.iter().zip(self.files()) {
            validate_file(*spec, bytes)?;
        }
        Ok(())
    }

    fn files(&self) -> [&[u8]; 4] {
        [
            &self.apple_media_services,
            &self.commerce,
            &self.core_fp,
            &self.core_fp_icxs,
        ]
    }

    pub fn load_cached() -> Result<Self> {
        Self::load_from(&cache_directory()?)
    }

    pub fn load_from(directory: &Path) -> Result<Self> {
        let mut files = Vec::with_capacity(SPECS.len());
        for spec in SPECS {
            let path = directory.join(spec.name);
            let bytes = read_cache_file(&path, spec.size)
                .with_context(|| format!("read cached Apple SAP asset {}", spec.name))?;
            validate_file(spec, &bytes)?;
            files.push(bytes);
        }
        let mut files = files.into_iter();
        Ok(Self {
            apple_media_services: files.next().unwrap(),
            commerce: files.next().unwrap(),
            core_fp: files.next().unwrap(),
            core_fp_icxs: files.next().unwrap(),
        })
    }
}

pub fn cache_directory() -> Result<PathBuf> {
    let root = dirs::cache_dir().context("find user cache directory")?;
    Ok(root.join("ipatool").join("sap").join(CACHE_DIRECTORY))
}

fn read_cache_file(path: &Path, expected_size: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("inspect cached asset {}", path.display()))?;
    if metadata.len() != expected_size as u64 {
        bail!(
            "cached asset has size {}, expected {expected_size}",
            metadata.len()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("read cached asset {}", path.display()))?;
    if bytes.len() != expected_size {
        bail!("cached asset changed size while being read");
    }
    Ok(bytes)
}

fn validate_file(spec: AssetSpec, bytes: &[u8]) -> Result<()> {
    if bytes.len() != spec.size {
        bail!(
            "apple SAP asset {} has size {}, expected {}",
            spec.name,
            bytes.len(),
            spec.size
        );
    }
    if format!("{:x}", Sha256::digest(bytes)) != spec.sha256 {
        bail!(
            "apple SAP asset {} failed integrity verification",
            spec.name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_matches_go_layout() {
        let path = cache_directory().unwrap();
        assert!(path.ends_with("ipatool/sap/apple-assets-macos-27-26A434-arm64-v1"));
    }

    #[test]
    fn rejects_wrong_length_and_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asset");
        fs::write(&path, b"four").unwrap();
        assert_eq!(read_cache_file(&path, 4).unwrap(), b"four");
        assert!(read_cache_file(&path, 8).is_err());
        let spec = AssetSpec {
            name: "fixture",
            size: 4,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        };
        assert!(validate_file(spec, b"four").is_err());
        assert!(validate_file(spec, b"bad").is_err());
    }
}
