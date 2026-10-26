//! Authenticated access to the pinned split dyld cache in SystemOS.

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use anyhow::{Context, Result, bail};

use crate::{
    decmpfs::LzBitmapForkReader,
    dyld_cache::{ImageLayout, Mapping, MemberHeader, PrimaryIndex, read_image_layout},
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
    members: HashMap<String, CacheMember<'a>>,
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
        let mut members = HashMap::new();
        members.insert(String::new(), primary);
        Ok(Self {
            shared,
            volume,
            index,
            base_address,
            members,
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
        if self
            .members
            .get("")
            .and_then(|primary| primary.header.mapping_for_address(address))
            .is_some()
        {
            return Ok("");
        }
        self.index
            .candidate_for_address(self.base_address, address)
            .map(|entry| entry.suffix.as_str())
            .context("dyld address is outside indexed subcaches")
    }

    /// Read across mapped split-cache files by preferred VM address.
    pub fn read_vm_region(&mut self, mut address: u64, output: &mut [u8]) -> Result<()> {
        let mut written = 0usize;
        while written < output.len() {
            let suffix = self.member_suffix_for_address(address)?.to_string();
            let member = self.cached_member(&suffix)?;
            let mapping = member
                .header
                .mapping_for_address(address)
                .with_context(|| {
                    format!("dyld member {suffix} does not map address {address:#x}")
                })?;
            let count =
                (output.len() - written).min((mapping.address + mapping.size - address) as usize);
            let file_offset = mapping.file_offset + address - mapping.address;
            member.reader.seek(SeekFrom::Start(file_offset))?;
            member
                .reader
                .read_exact(&mut output[written..written + count])?;
            written += count;
            address = address
                .checked_add(count as u64)
                .context("dyld VM address overflow")?;
        }
        Ok(())
    }

    /// Read bytes by offset within one named split-cache member.
    pub fn read_member_at(&mut self, suffix: &str, offset: u64, output: &mut [u8]) -> Result<()> {
        let member = self.cached_member(suffix)?;
        if offset
            .checked_add(output.len() as u64)
            .is_none_or(|end| end > member.header.size)
        {
            bail!("dyld member {suffix} read exceeds its file");
        }
        member.reader.seek(SeekFrom::Start(offset))?;
        member.reader.read_exact(output)?;
        Ok(())
    }

    pub fn image_layout(&mut self, path: &str) -> Result<(u64, ImageLayout)> {
        let address = self
            .index
            .image_address(path)?
            .with_context(|| format!("{path} is absent from the dyld cache"))?;
        let suffix = self.member_suffix_for_address(address)?.to_string();
        let member = self.cached_member(&suffix)?;
        let mapping = member
            .header
            .mapping_for_address(address)
            .context("dyld image header address is not mapped")?;
        let offset = mapping.file_offset + address - mapping.address;
        let layout = read_image_layout(&mut member.reader, offset)?;
        Ok((address, layout))
    }

    pub fn mapping_for_address(&mut self, address: u64) -> Result<(String, Mapping)> {
        let suffix = self.member_suffix_for_address(address)?.to_string();
        let member = self.cached_member(&suffix)?;
        let mapping = member
            .header
            .mapping_for_address(address)
            .with_context(|| format!("dyld address {address:#x} is not mapped"))?;
        Ok((suffix, mapping.clone()))
    }

    fn cached_member(&mut self, suffix: &str) -> Result<&mut CacheMember<'a>> {
        if !self.members.contains_key(suffix) {
            let member = self.open_member(suffix)?;
            self.members.insert(suffix.to_string(), member);
        }
        Ok(self.members.get_mut(suffix).expect("member was opened"))
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
        let (image, layout) = cache.image_layout("/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices").unwrap();
        assert_eq!(layout.segments.len(), 7);
        assert_eq!(cache.member_suffix_for_address(image).unwrap(), ".09");
        for suffix in [".09", ".25.dylddata", ".79.dyldlinkedit"] {
            let member = cache.open_member(suffix).unwrap();
            assert!(!member.header.mappings.is_empty());
        }
        let mut header = [0u8; 32];
        cache.read_vm_region(image, &mut header).unwrap();
        assert_eq!(&header[..4], &0xfeed_facfu32.to_le_bytes());
        cache.read_member_at(".09", 0, &mut header).unwrap();
        assert_eq!(&header[..7], b"dyld_v1");
        let mut data = [0u8; 64];
        let data_address = layout
            .segments
            .iter()
            .find(|segment| segment.name == "__DATA")
            .unwrap()
            .address;
        cache.read_vm_region(data_address, &mut data).unwrap();
        assert!(data.iter().any(|&byte| byte != 0));
    }

    #[test]
    #[ignore = "downloads and rebuilds AppleMediaServices linkedit from the pinned dyld cache"]
    fn rebuilds_pinned_linkedit() {
        let restore = PinnedRestore::open().unwrap();
        let mut cache = SystemOsCache::open(&restore).unwrap();
        let (image, mut layout) = cache.image_layout("/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices").unwrap();
        let linkedit = layout
            .segments
            .iter()
            .find(|segment| segment.name == "__LINKEDIT")
            .unwrap();
        let suffix = cache
            .member_suffix_for_address(linkedit.address)
            .unwrap()
            .to_string();
        let start: u64 = layout
            .segments
            .iter()
            .take_while(|segment| segment.name != "__LINKEDIT")
            .map(|segment| segment.file_size.div_ceil(16_384) * 16_384)
            .sum();
        let result =
            crate::dyld_export::rebuild_linkedit(&mut cache, &mut layout, &suffix, start, image)
                .unwrap();
        eprintln!(
            "AppleMediaServices rebuilt linkedit: {} bytes, {} source symbols, {} output symbols, {} reexports",
            result.bytes.len(),
            result.original_symbols,
            result.exported_symbols,
            result.reexports
        );
        assert!(result.bytes.len() > 1_000_000);
    }

    #[test]
    #[ignore = "downloads and exports AppleMediaServices from the pinned dyld cache"]
    fn exports_pinned_apple_media_services() {
        use sha2::{Digest, Sha256};
        let restore = PinnedRestore::open().unwrap();
        let mut cache = SystemOsCache::open(&restore).unwrap();
        let image = crate::dyld_export::export_image(&mut cache, "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices").unwrap();
        let digest = format!("{:x}", Sha256::digest(&image));
        eprintln!(
            "AppleMediaServices export: {} bytes, SHA-256 {digest}",
            image.len()
        );
        assert_eq!(image.len(), 14_813_888);
        assert_eq!(
            digest,
            "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4"
        );
    }
}
