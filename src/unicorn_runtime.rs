//! Pinned Unicorn 2.1.4 dynamic library cache shared with the Go implementation.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use libloading::Library;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zip::ZipArchive;

mod engine;
#[cfg(target_os = "windows")]
mod windows_prepare;
pub use engine::{Engine, HookContext, REG_PC, REG_X0, REG_X1};

const VERSION: &str = "2.1.4";
const MAX_ARTIFACT_SIZE: u64 = 64 << 20;

#[derive(Clone, Copy)]
struct Artifact {
    url: &'static str,
    archive_sha256: &'static str,
    library_sha256: &'static str,
    member: &'static str,
    filename: &'static str,
    format: ArchiveFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchiveFormat {
    Zip,
    SevenZip,
}

pub struct UnicornLibrary {
    library: Library,
}

impl UnicornLibrary {
    pub fn api_version(&self) -> Result<(u32, u32)> {
        type Version = unsafe extern "C" fn(*mut u32, *mut u32) -> u32;
        let function = unsafe { self.library.get::<Version>(b"uc_version") }
            .context("Unicorn library is missing uc_version")?;
        let (mut major, mut minor) = (0, 0);
        unsafe { function(&mut major, &mut minor) };
        Ok((major, minor))
    }
}

pub fn load() -> Result<UnicornLibrary> {
    let selected = current_artifact()?;
    let cache = dirs::cache_dir().context("user cache directory is unavailable")?;
    let root = cache.join("ipatool").join("unicorn").join(VERSION);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("failed to create Unicorn downloader")?;
    let path = ensure_library(&root, selected, &client)?;
    // The library is selected by platform and verified against the pinned digest.
    #[cfg(not(target_os = "windows"))]
    let library = unsafe { Library::new(&path) }
        .with_context(|| format!("failed to load Unicorn library: {}", path.display()))?;
    #[cfg(target_os = "windows")]
    let library = windows_prepare::load(&path)?;
    let library = UnicornLibrary { library };
    let (major, minor) = library.api_version()?;
    if (major, minor) != (2, 1) {
        bail!("unsupported Unicorn API version {major}.{minor}");
    }
    Ok(library)
}

fn current_artifact() -> Result<Artifact> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let musl = cfg!(target_env = "musl");
    artifact_for(os, arch, musl)
}

fn artifact_for(os: &str, arch: &str, musl: bool) -> Result<Artifact> {
    let selected = match (os, arch, musl) {
        ("macos", "x86_64", _) => Artifact {
            url: "https://files.pythonhosted.org/packages/c8/a7/92b47771e2107a201632a199cec91e8a81ee8a071ca6b7e7d600d8c61ac9/unicorn-2.1.4-cp37-abi3-macosx_10_9_x86_64.whl",
            archive_sha256: "2a6f738fab5fabffa56af1e7bbf16ea1e91466c342f8dc64f125bd70f36c6b80",
            library_sha256: "51c4a6f3ce22628ecd3acd1c49b921a818ffb989ca2c473134cc7eb06094f256",
            member: "unicorn/lib/libunicorn.2.dylib",
            filename: "libunicorn.2.dylib",
            format: ArchiveFormat::Zip,
        },
        ("macos", "aarch64", _) => Artifact {
            url: "https://files.pythonhosted.org/packages/6c/ae/4943c6f8524d729ec7d5e69df6407ea05d710fe77471d91cecf3fc64eb57/unicorn-2.1.4-cp37-abi3-macosx_11_0_arm64.whl",
            archive_sha256: "d6c93e0f60328d8f4a1792af3f834137a28050fcc2305f2ec01efe8558a9844e",
            library_sha256: "7207c8e3d7a63118fb0bca73e01816797fd51b1d8a39a4cbc7abfd562ee59c85",
            member: "unicorn/lib/libunicorn.2.dylib",
            filename: "libunicorn.2.dylib",
            format: ArchiveFormat::Zip,
        },
        ("linux", "x86_64", false) => Artifact {
            url: "https://files.pythonhosted.org/packages/e7/df/ded5e3684c2d7600b30cc8a7530277b8cb36644a1a9d34cade7ebb45604c/unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            archive_sha256: "9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239",
            library_sha256: "ddb196ec82b52e502c18e4a34478bf7b9f61c83c2ebaa95c74d8ded45a95da9c",
            member: "unicorn/lib/libunicorn.so.2",
            filename: "libunicorn.so.2",
            format: ArchiveFormat::Zip,
        },
        ("linux", "aarch64", false) => Artifact {
            url: "https://files.pythonhosted.org/packages/33/9f/32d41eb942221bcf4417cdc65537fc8b3bbbd6079d6c161e621f1dd4e94a/unicorn-2.1.4-cp37-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
            archive_sha256: "bd1fb0c9af5f57e356d8a96928b4fe045b2e18f308ef23b481d5f970008aa722",
            library_sha256: "a0b99458a82e268aee258205a40590411c3a9f28e42abf2942ce4e87b7d9ac65",
            member: "unicorn/lib/libunicorn.so.2",
            filename: "libunicorn.so.2",
            format: ArchiveFormat::Zip,
        },
        ("linux", "x86_64", true) => Artifact {
            url: "https://files.pythonhosted.org/packages/ed/4b/4628ccb20eb3ad1af400de8181d1f4e5c1a3fc2affa1b3410c1b2d71af36/unicorn-2.1.4-cp37-abi3-musllinux_1_2_x86_64.whl",
            archive_sha256: "d348a90ee90219d141cb115ef8ed7e3fd1af42afaee105f7580761d775b25e32",
            library_sha256: "cc1a208c69b151fdd23439736b0fac9ac6e14409dae77deee900369e6daab302",
            member: "unicorn/lib/libunicorn.so.2",
            filename: "libunicorn.so.2",
            format: ArchiveFormat::Zip,
        },
        ("linux", "aarch64", true) => Artifact {
            url: "https://files.pythonhosted.org/packages/70/38/ba5a051c844026e59ab6e0017db8cec77dbe20ab5f1d6edae1ce9d885b06/unicorn-2.1.4-cp37-abi3-musllinux_1_2_aarch64.whl",
            archive_sha256: "01d744ba01c5cc68f1d7afe3d183f1868720fd440ec4eaedc4d1d5d9bf54b84c",
            library_sha256: "52179305928b32c937d2d527ad6fef9d500c6fa7cdb14bf32abf7021d67271a2",
            member: "unicorn/lib/libunicorn.so.2",
            filename: "libunicorn.so.2",
            format: ArchiveFormat::Zip,
        },
        ("windows", "x86_64", _) => Artifact {
            url: "https://github.com/unicorn-engine/unicorn/releases/download/2.1.4/windows-mingw64-shared.7z",
            archive_sha256: "0960f938e66fa12c448742bddd2a03aa88abeeb2b3cda7156493a2da86228d3a",
            library_sha256: "d8f9a89222ffa74493a1d47090e17f8e1db8ac171a3128c6a76a4ea09de11469",
            member: "bin/libunicorn.dll",
            filename: "libunicorn.dll",
            format: ArchiveFormat::SevenZip,
        },
        _ => bail!("unsupported Unicorn runtime platform {os}/{arch}"),
    };
    Ok(selected)
}

fn ensure_library(
    root: &Path,
    selected: Artifact,
    client: &reqwest::blocking::Client,
) -> Result<PathBuf> {
    let directory = root.join(selected.library_sha256);
    let destination = directory.join(selected.filename);
    if file_matches_sha256(&destination, selected.library_sha256)? {
        return Ok(destination);
    }
    fs::create_dir_all(&directory).context("failed to create Unicorn cache")?;
    let archive = download_archive(&directory, selected, client)?;
    let library = extract_library(&directory, archive.path(), selected)?;
    library
        .persist(&destination)
        .context("failed to install Unicorn library")?;
    if !file_matches_sha256(&destination, selected.library_sha256)? {
        bail!("cached Unicorn library failed integrity verification");
    }
    Ok(destination)
}

fn download_archive(
    directory: &Path,
    selected: Artifact,
    client: &reqwest::blocking::Client,
) -> Result<NamedTempFile> {
    let response = client
        .get(selected.url)
        .header(
            reqwest::header::USER_AGENT,
            "ipatool Unicorn runtime downloader",
        )
        .send()
        .context("failed to download Unicorn archive")?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("Unicorn archive returned HTTP {}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_ARTIFACT_SIZE)
    {
        bail!("Unicorn archive exceeds size limit");
    }
    let mut archive =
        NamedTempFile::new_in(directory).context("failed to create Unicorn download")?;
    let mut hash = Sha256::new();
    let written = std::io::copy(
        &mut response.take(MAX_ARTIFACT_SIZE + 1),
        &mut HashWriter {
            file: archive.as_file_mut(),
            hash: &mut hash,
        },
    )
    .context("failed to save Unicorn archive")?;
    if written > MAX_ARTIFACT_SIZE {
        bail!("Unicorn archive exceeds size limit");
    }
    if format!("{:x}", hash.finalize()) != selected.archive_sha256 {
        bail!("Unicorn archive failed integrity verification");
    }
    archive
        .as_file()
        .sync_all()
        .context("failed to sync Unicorn archive")?;
    Ok(archive)
}

fn extract_library(
    directory: &Path,
    archive_path: &Path,
    selected: Artifact,
) -> Result<NamedTempFile> {
    match selected.format {
        ArchiveFormat::Zip => extract_zip_library(directory, archive_path, selected),
        ArchiveFormat::SevenZip => extract_sevenz_library(directory, archive_path, selected),
    }
}

fn extract_zip_library(
    directory: &Path,
    archive_path: &Path,
    selected: Artifact,
) -> Result<NamedTempFile> {
    let file = File::open(archive_path).context("failed to open Unicorn archive")?;
    let mut zip = ZipArchive::new(file).context("invalid Unicorn wheel")?;
    let entry = zip
        .by_name(selected.member)
        .context("Unicorn library missing from wheel")?;
    let expected_size = entry.size();
    if expected_size > MAX_ARTIFACT_SIZE {
        bail!("Unicorn library exceeds size limit");
    }
    let mut extracted =
        NamedTempFile::new_in(directory).context("failed to create Unicorn library")?;
    let mut hash = Sha256::new();
    let written = std::io::copy(
        &mut entry.take(MAX_ARTIFACT_SIZE + 1),
        &mut HashWriter {
            file: extracted.as_file_mut(),
            hash: &mut hash,
        },
    )
    .context("failed to extract Unicorn library")?;
    if written != expected_size || written > MAX_ARTIFACT_SIZE {
        bail!("Unicorn library has invalid size");
    }
    if format!("{:x}", hash.finalize()) != selected.library_sha256 {
        bail!("Unicorn library failed integrity verification");
    }
    extracted
        .as_file()
        .sync_all()
        .context("failed to sync Unicorn library")?;
    Ok(extracted)
}

fn extract_sevenz_library(
    directory: &Path,
    archive_path: &Path,
    selected: Artifact,
) -> Result<NamedTempFile> {
    let mut reader = sevenz_rust::SevenZReader::open(archive_path, sevenz_rust::Password::empty())
        .context("invalid Unicorn 7z archive")?;
    let entry = reader
        .archive()
        .files
        .iter()
        .find(|entry| entry.name() == selected.member)
        .context("Unicorn library missing from 7z archive")?;
    if entry.is_directory() || entry.size() > MAX_ARTIFACT_SIZE {
        bail!("Unicorn library has invalid size or type");
    }
    let expected_size = entry.size();
    let mut extracted =
        NamedTempFile::new_in(directory).context("failed to create Unicorn library")?;
    let mut hash = Sha256::new();
    let mut found = false;
    reader
        .for_each_entries(|entry, stream| {
            if entry.name() != selected.member {
                return Ok(true);
            }
            let written = std::io::copy(
                &mut stream.take(MAX_ARTIFACT_SIZE + 1),
                &mut HashWriter {
                    file: extracted.as_file_mut(),
                    hash: &mut hash,
                },
            )?;
            if written != expected_size || written > MAX_ARTIFACT_SIZE {
                return Err(sevenz_rust::Error::other(
                    "Unicorn library has invalid size",
                ));
            }
            found = true;
            Ok(false)
        })
        .context("failed to extract Unicorn library from 7z archive")?;
    if !found || format!("{:x}", hash.finalize()) != selected.library_sha256 {
        bail!("Unicorn library failed integrity verification");
    }
    extracted
        .as_file()
        .sync_all()
        .context("failed to sync Unicorn library")?;
    Ok(extracted)
}

fn file_matches_sha256(path: &Path, expected: &str) -> Result<bool> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("failed to open cached Unicorn library"),
    };
    if file.metadata()?.len() > MAX_ARTIFACT_SIZE {
        return Ok(false);
    }
    let mut hash = Sha256::new();
    let mut file = file;
    std::io::copy(&mut file, &mut hash).context("failed to verify cached Unicorn library")?;
    Ok(format!("{:x}", hash.finalize()) == expected)
}

struct HashWriter<'a> {
    file: &'a mut File,
    hash: &'a mut Sha256,
}

impl Write for HashWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = self.file.write(data)?;
        self.hash.update(&data[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_pinned_wheels_for_supported_hosts() {
        assert!(
            artifact_for("macos", "aarch64", false)
                .unwrap()
                .url
                .contains("macosx_11_0_arm64")
        );
        assert!(
            artifact_for("linux", "x86_64", true)
                .unwrap()
                .url
                .contains("musllinux")
        );
        assert!(
            artifact_for("linux", "x86_64", false)
                .unwrap()
                .url
                .contains("manylinux")
        );
        let windows = artifact_for("windows", "x86_64", false).unwrap();
        assert_eq!(windows.format, ArchiveFormat::SevenZip);
        assert_eq!(windows.member, "bin/libunicorn.dll");
    }

    #[test]
    fn rejects_wrong_cached_checksum() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("libunicorn.2.dylib");
        fs::write(&path, b"tampered").unwrap();
        assert!(!file_matches_sha256(&path, "0").unwrap());
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn release artifact"]
    fn extracts_checked_windows_archive() {
        let selected = artifact_for("windows", "x86_64", false).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let client = reqwest::blocking::Client::new();
        let archive = download_archive(directory.path(), selected, &client).unwrap();
        let library = extract_library(directory.path(), archive.path(), selected).unwrap();
        assert!(file_matches_sha256(library.path(), selected.library_sha256).unwrap());
    }
}
