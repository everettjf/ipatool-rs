//! Locate the pinned encrypted cryptex images inside the macOS restore ZIP.

use std::io::{Read, Seek};

use anyhow::{Context, Result, bail};
use zip::{CompressionMethod, ZipArchive};

use crate::sap_remote::RemoteFile;

const FILE_SYSTEM_IMAGE: EntrySpec = EntrySpec {
    name: "043-70867-640.dmg.aea",
    size: 11_274_289_152,
};
const SYSTEM_OS_IMAGE: EntrySpec = EntrySpec {
    name: "043-70701-651.dmg.aea",
    size: 2_415_919_104,
};

#[derive(Clone, Copy)]
struct EntrySpec {
    name: &'static str,
    size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveEntry {
    pub offset: u64,
    pub size: u64,
}

pub struct PinnedRestore {
    pub remote: RemoteFile,
    pub file_system: ArchiveEntry,
    pub system_os: ArchiveEntry,
}

impl PinnedRestore {
    pub fn open() -> Result<Self> {
        let remote = RemoteFile::open_pinned()?;
        let mut archive = ZipArchive::new(remote).context("read pinned macOS restore archive")?;
        let file_system = pinned_entry(&mut archive, FILE_SYSTEM_IMAGE)?;
        let system_os = pinned_entry(&mut archive, SYSTEM_OS_IMAGE)?;
        let remote = archive.into_inner();
        for entry in [file_system, system_os] {
            if entry
                .offset
                .checked_add(entry.size)
                .is_none_or(|end| end > remote.size())
            {
                bail!("pinned restore member exceeds remote image");
            }
        }
        Ok(Self {
            remote,
            file_system,
            system_os,
        })
    }
}

fn pinned_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    spec: EntrySpec,
) -> Result<ArchiveEntry> {
    let file = archive
        .by_name(spec.name)
        .with_context(|| format!("restore image does not contain {}", spec.name))?;
    if file.compression() != CompressionMethod::Stored
        || file.compressed_size() != spec.size
        || file.size() != spec.size
    {
        bail!(
            "restore member {} does not match the pinned image",
            spec.name
        );
    }
    Ok(ArchiveEntry {
        offset: file.data_start(),
        size: spec.size,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use zip::{ZipWriter, write::FileOptions};

    #[test]
    fn accepts_exact_stored_member_and_rejects_changed_size() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "image.aea",
                FileOptions::<()>::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(b"abcd").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        let entry = pinned_entry(
            &mut archive,
            EntrySpec {
                name: "image.aea",
                size: 4,
            },
        )
        .unwrap();
        assert!(entry.offset > 0);
        assert_eq!(entry.size, 4);
        assert!(
            pinned_entry(
                &mut archive,
                EntrySpec {
                    name: "image.aea",
                    size: 5
                }
            )
            .is_err()
        );
        assert!(
            pinned_entry(
                &mut archive,
                EntrySpec {
                    name: "missing",
                    size: 4
                }
            )
            .is_err()
        );
    }
}
