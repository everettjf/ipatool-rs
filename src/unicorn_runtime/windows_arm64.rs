//! Checked repair for the pinned Windows ARM64 Unicorn 2.1.4 DLL.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::{MAX_ARTIFACT_SIZE, file_matches_sha256, install_verified_library};

const FIRST: &[u8] = &[0xe8, 0x21, 0xcc, 0x1a, 0xe8, 0x03, 0x28, 0x2a];
const SECOND: &[u8] = &[0xef, 0x21, 0xc8, 0x1a, 0xef, 0x03, 0x2f, 0x2a];
const PATTERN_COUNT: usize = 16;

pub(super) fn prepare_runtime_library(path: &Path) -> Result<PathBuf> {
    if fs::metadata(path)?.len() > MAX_ARTIFACT_SIZE {
        bail!("Windows ARM64 Unicorn library exceeds size limit");
    }
    let mut image = fs::read(path).context("read Windows ARM64 Unicorn library")?;
    patch_tcg_masks(&mut image)?;
    let checksum = format!("{:x}", Sha256::digest(&image));
    let directory = path
        .parent()
        .context("Unicorn cache directory is unavailable")?;
    let destination = directory.join("libunicorn-windows-arm64.dll");
    if file_matches_sha256(&destination, &checksum)? {
        return Ok(destination);
    }
    let mut temporary = NamedTempFile::new_in(directory).context("create prepared Unicorn DLL")?;
    temporary
        .write_all(&image)
        .context("write prepared Unicorn DLL")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync prepared Unicorn DLL")?;
    install_verified_library(temporary, &destination, &checksum)
        .context("install prepared Unicorn DLL")?;
    if !file_matches_sha256(&destination, &checksum)? {
        bail!("prepared Windows ARM64 Unicorn DLL failed integrity verification");
    }
    Ok(destination)
}

fn patch_tcg_masks(image: &mut [u8]) -> Result<()> {
    let first = offsets(image, FIRST);
    let second = offsets(image, SECOND);
    if first.len() != PATTERN_COUNT || second.len() != PATTERN_COUNT {
        bail!(
            "unexpected Windows ARM64 TCG mask layout ({}/{})",
            first.len(),
            second.len()
        );
    }
    for (first, second) in first.into_iter().zip(second) {
        if second != first + 24 {
            bail!("unexpected Windows ARM64 TCG mask instruction spacing");
        }
        for offset in [first + 3, first + 7, second + 3, second + 7] {
            image[offset] |= 0x80;
        }
    }
    Ok(())
}

fn offsets(image: &[u8], pattern: &[u8]) -> Vec<usize> {
    image
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == pattern).then_some(offset))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_only_checked_arm64_mask_sites() {
        let mut image = vec![0; PATTERN_COUNT * 64];
        for index in 0..PATTERN_COUNT {
            let offset = index * 64;
            image[offset..offset + 8].copy_from_slice(FIRST);
            image[offset + 24..offset + 32].copy_from_slice(SECOND);
        }
        patch_tcg_masks(&mut image).unwrap();
        for index in 0..PATTERN_COUNT {
            let offset = index * 64;
            assert_eq!(
                &image[offset..offset + 8],
                &[0xe8, 0x21, 0xcc, 0x9a, 0xe8, 0x03, 0x28, 0xaa]
            );
            assert_eq!(
                &image[offset + 24..offset + 32],
                &[0xef, 0x21, 0xc8, 0x9a, 0xef, 0x03, 0x2f, 0xaa]
            );
            assert!(image[offset + 8..offset + 24].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn rejects_unrecognized_arm64_mask_layout() {
        assert!(patch_tcg_masks(&mut [0; 128]).is_err());
    }

    #[test]
    fn concurrently_prepares_one_checked_arm64_dll() {
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("libunicorn.dll");
        let mut image = vec![0; PATTERN_COUNT * 64];
        for index in 0..PATTERN_COUNT {
            let offset = index * 64;
            image[offset..offset + 8].copy_from_slice(FIRST);
            image[offset + 24..offset + 32].copy_from_slice(SECOND);
        }
        fs::write(&source, image).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                let barrier = Arc::clone(&barrier);
                let source = &source;
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    prepare_runtime_library(source).unwrap()
                }));
            }
            let mut paths = Vec::new();
            for worker in workers {
                paths.push(worker.join().unwrap());
            }
            assert!(paths.iter().all(|path| path == &paths[0]));
        });
    }

    #[test]
    #[ignore = "downloads the pinned Windows ARM64 Unicorn package"]
    fn prepares_checked_arm64_dll() {
        let selected = crate::unicorn_runtime::artifact_for("windows", "aarch64", false).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let client = reqwest::blocking::Client::new();
        let archive =
            crate::unicorn_runtime::download_archive(directory.path(), selected, &client).unwrap();
        let library =
            crate::unicorn_runtime::extract_library(directory.path(), archive.path(), selected)
                .unwrap();
        let prepared = prepare_runtime_library(library.path()).unwrap();
        assert!(
            file_matches_sha256(
                &prepared,
                "874003fb38ae4b3c57c83a86acee9d2660f431568ff0935af3984dc92e321164"
            )
            .unwrap()
        );
    }
}
