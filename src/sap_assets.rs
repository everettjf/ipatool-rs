//! Pinned macOS 27.0.1 assets used by the SAP, KBSync, and FairPlay guests.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::{
    dyld_export::export_image, sap_aea::AeaReader, sap_archive::PinnedRestore,
    sap_system_os::SystemOsCache,
};

const CACHE_DIRECTORY: &str = "apple-assets-macos-27-26A434-arm64-v1";
const FILE_SYSTEM_IMAGE_SIZE: u64 = 14_189_330_432;
const APPLE_MEDIA_SERVICES_IMAGE: &str =
    "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices";
const FRAMEWORK_PATHS: [&str; 3] = [
    "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce",
    "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP",
    "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/CoreFP.icxs",
];

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

pub struct SapFrameworkAssets {
    pub commerce: Vec<u8>,
    pub core_fp: Vec<u8>,
    pub core_fp_icxs: Vec<u8>,
}

impl SapFrameworkAssets {
    pub fn download_pinned() -> Result<Self> {
        let restore = PinnedRestore::open().context("open pinned macOS restore archive")?;
        Self::download_from_restore(&restore)
    }

    fn download_from_restore(restore: &PinnedRestore) -> Result<Self> {
        let image = AeaReader::open(&restore.remote, restore.file_system)
            .context("open encrypted macOS filesystem")?;
        if image.size() != FILE_SYSTEM_IMAGE_SIZE {
            bail!(
                "macOS filesystem has size {}, expected {FILE_SYSTEM_IMAGE_SIZE}",
                image.size()
            );
        }
        let mut volume = apfs::ApfsVolume::open(image).context("open macOS APFS volume")?;
        let mut files = Vec::with_capacity(FRAMEWORK_PATHS.len());
        for (path, spec) in FRAMEWORK_PATHS.into_iter().zip(&SPECS[1..]) {
            let stat = volume
                .stat(path)
                .with_context(|| format!("inspect Apple SAP asset {}", spec.name))?;
            if stat.size != spec.size as u64 {
                bail!(
                    "apple SAP asset {} has size {}, expected {}",
                    spec.name,
                    stat.size,
                    spec.size
                );
            }
            let mut data = Vec::with_capacity(spec.size);
            volume
                .read_file_to(path, &mut data)
                .with_context(|| format!("extract Apple SAP asset {}", spec.name))?;
            validate_file(*spec, &data)?;
            files.push(data);
        }
        let mut files = files.into_iter();
        Ok(Self {
            commerce: files.next().unwrap(),
            core_fp: files.next().unwrap(),
            core_fp_icxs: files.next().unwrap(),
        })
    }
}

impl SapAssetBundle {
    /// Load a validated cache or download and atomically replace the pinned assets.
    pub fn load_or_download() -> Result<Self> {
        if let Some(directory) = configured_cache_directory()? {
            return Self::load_from(&directory).context("validate IPATOOL_SAP_CACHE_DIR assets");
        }
        let directory = cache_directory()?;
        if let Ok(bundle) = Self::load_from(&directory) {
            return Ok(bundle);
        }
        let bundle = Self::download_pinned()?;
        bundle.save_to(&directory)?;
        Ok(bundle)
    }

    pub fn download_pinned() -> Result<Self> {
        let restore = PinnedRestore::open().context("open pinned macOS restore archive")?;
        let frameworks = SapFrameworkAssets::download_from_restore(&restore)?;
        let mut system_os = SystemOsCache::open(&restore)?;
        let apple_media_services = export_image(&mut system_os, APPLE_MEDIA_SERVICES_IMAGE)
            .context("extract AppleMediaServices from SystemOS shared cache")?;
        let bundle = Self {
            apple_media_services,
            commerce: frameworks.commerce,
            core_fp: frameworks.core_fp,
            core_fp_icxs: frameworks.core_fp_icxs,
        };
        bundle.validate()?;
        Ok(bundle)
    }

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

    pub fn save_to(&self, directory: &Path) -> Result<()> {
        self.validate()?;
        fs::create_dir_all(directory)
            .with_context(|| format!("create SAP asset cache {}", directory.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        for (spec, bytes) in SPECS.iter().zip(self.files()) {
            let mut temporary = tempfile::NamedTempFile::new_in(directory)
                .with_context(|| format!("create temporary cache file for {}", spec.name))?;
            temporary.write_all(bytes)?;
            temporary.flush()?;
            temporary.as_file().sync_all()?;
            let destination = directory.join(spec.name);
            temporary
                .persist(&destination)
                .with_context(|| format!("install cached SAP asset {}", spec.name))?;
        }
        Ok(())
    }
}

pub fn cache_directory() -> Result<PathBuf> {
    if let Some(directory) = configured_cache_directory()? {
        return Ok(directory);
    }
    let root = dirs::cache_dir().context("find user cache directory")?;
    Ok(root.join("ipatool").join("sap").join(CACHE_DIRECTORY))
}

fn configured_cache_directory() -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os("IPATOOL_SAP_CACHE_DIR") else {
        return Ok(None);
    };
    let directory = PathBuf::from(value);
    if !directory.is_absolute() {
        bail!("IPATOOL_SAP_CACHE_DIR must be an absolute path");
    }
    Ok(Some(directory))
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

    #[test]
    #[ignore = "downloads and verifies framework assets from the pinned Apple restore image"]
    fn downloads_pinned_frameworks() {
        let assets = SapFrameworkAssets::download_pinned().unwrap();
        assert_eq!(assets.commerce.len(), SPECS[1].size);
        assert_eq!(assets.core_fp.len(), SPECS[2].size);
        assert_eq!(assets.core_fp_icxs.len(), SPECS[3].size);
    }

    #[test]
    #[ignore = "downloads, validates, and caches all four pinned Apple SAP assets"]
    fn downloads_complete_pinned_bundle() {
        let bundle = SapAssetBundle::download_pinned().unwrap();
        bundle.validate().unwrap();
        let core = crate::machimage::Image::open("CoreFP", &bundle.core_fp).unwrap();
        for name in [
            "_WIn9UJ86JKdV4dM",
            "_X46O5IeS",
            "_YlCJ3lg",
            "_dku592fbFAj",
            "_fdjkDSAFjklaf2s",
            "_lxpgvVMLd0S7uRl",
        ] {
            assert_ne!(core.export(name, 0x0000_1000_0000_0000).unwrap(), 0);
        }
        let services =
            crate::machimage::Image::open("AppleMediaServices", &bundle.apple_media_services)
                .unwrap();
        for name in [
            "_cp2g1b9ro",
            "_Mib5yocT",
            "_Fc3vhtJDvr",
            "_IPaI1oem5iL",
            "_jEHf8Xzsv8K",
        ] {
            assert_ne!(services.export(name, services.base()).unwrap(), 0);
        }
        let directory = tempfile::tempdir().unwrap();
        bundle.save_to(directory.path()).unwrap();
        let restored = SapAssetBundle::load_from(directory.path()).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.apple_media_services, bundle.apple_media_services);
    }
}
