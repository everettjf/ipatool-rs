//! Authenticated access to the pinned split dyld cache in SystemOS.

use anyhow::{Context, Result, bail};

use crate::{
    decmpfs::LzBitmapForkReader,
    dyld_cache::{MemberHeader, PrimaryIndex},
    sap_aea::{AeaReader, SharedAeaReader},
    sap_archive::PinnedRestore,
};

const SYSTEM_OS_IMAGE_SIZE: u64 = 2_879_389_696;
pub const ARM64E_CACHE_PATH: &str = "/System/Library/dyld/dyld_shared_cache_arm64e";

pub type MemberReader<'a> = LzBitmapForkReader<apfs::extents::ApfsForkReader<SharedAeaReader<'a>>>;

pub struct CacheMember<'a> {
    pub reader: MemberReader<'a>,
    pub header: MemberHeader,
}

pub struct SystemOsCache<'a> {
    shared: SharedAeaReader<'a>,
    volume: apfs::ApfsVolume<SharedAeaReader<'a>>,
    pub index: PrimaryIndex,
    pub base_address: u64,
}

impl<'a> SystemOsCache<'a> {
    pub fn open(restore: &'a PinnedRestore) -> Result<Self> {
        let image = AeaReader::open(&restore.remote, restore.system_os)
            .context("open pinned SystemOS AEA image")?;
        if image.size() != SYSTEM_OS_IMAGE_SIZE {
            bail!("SystemOS image size does not match the pinned restore");
        }
        let shared = SharedAeaReader::new(image);
        let mut volume =
            apfs::ApfsVolume::open(shared.clone()).context("mount SystemOS APFS volume")?;
        let mut primary = Self::open_raw_member(&mut volume, &shared, "")?;
        let index = PrimaryIndex::read(&mut primary.reader).context("index dyld primary cache")?;
        let base_address = primary.header.mappings[0].address;
        Ok(Self {
            shared,
            volume,
            index,
            base_address,
        })
    }

    fn open_raw_member(
        volume: &mut apfs::ApfsVolume<SharedAeaReader<'a>>,
        shared: &SharedAeaReader<'a>,
        suffix: &str,
    ) -> Result<CacheMember<'a>> {
        if suffix.contains(['/', '\\']) {
            bail!("invalid dyld cache suffix");
        }
        let path = format!("{ARM64E_CACHE_PATH}{suffix}");
        let stat = volume
            .stat(&path)
            .with_context(|| format!("inspect {path}"))?;
        if stat
            .compression
            .is_none_or(|header| header.compression_type != 14)
        {
            bail!("{path} is not LZBITMAP compressed");
        }
        let (extents, source_size) = volume.xattr_stream_info(&path, "com.apple.ResourceFork")?;
        let fork = apfs::extents::ApfsForkReader::new(
            shared.clone(),
            volume.volume_info().block_size,
            extents,
            source_size,
        );
        let mut reader = LzBitmapForkReader::open(fork, stat.size)
            .with_context(|| format!("open compressed dyld member {suffix}"))?;
        let header = MemberHeader::read(&mut reader)
            .with_context(|| format!("parse dyld member {suffix}"))?;
        Ok(CacheMember { reader, header })
    }

    pub fn open_member(&mut self, suffix: &str) -> Result<CacheMember<'a>> {
        let expected = if suffix.is_empty() {
            self.index.uuid
        } else {
            self.index
                .subcaches
                .iter()
                .find(|entry| entry.suffix == suffix)
                .with_context(|| format!("unknown dyld subcache {suffix}"))?
                .uuid
        };
        let member = Self::open_raw_member(&mut self.volume, &self.shared, suffix)?;
        if member.header.uuid != expected {
            bail!("dyld subcache {suffix} UUID differs from the primary index");
        }
        Ok(member)
    }

    pub fn member_suffix_for_address(&self, address: u64) -> Result<&str> {
        if self.index.subcaches.is_empty() {
            return Ok("");
        }
        self.index
            .candidate_for_address(self.base_address, address)
            .map(|entry| entry.suffix.as_str())
            .context("dyld address is outside indexed subcaches")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "downloads the pinned SystemOS image and validates dyld cache members"]
    fn opens_pinned_split_cache() {
        let restore = PinnedRestore::open().unwrap();
        let mut cache = SystemOsCache::open(&restore).unwrap();
        let image = cache.index.image_address("/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices").unwrap().unwrap();
        assert_eq!(cache.member_suffix_for_address(image).unwrap(), ".09");
        for suffix in [".09", ".25.dylddata", ".79.dyldlinkedit"] {
            let member = cache.open_member(suffix).unwrap();
            assert!(!member.header.mappings.is_empty());
        }
    }
}
