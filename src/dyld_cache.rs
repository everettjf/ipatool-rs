//! Bounds-checked index of a split arm64e dyld shared cache.

use std::io::{Read, Seek, SeekFrom};

use anyhow::{Result, bail};

const HEADER_SIZE: usize = 568;
const SUBCACHE_ENTRY_SIZE: usize = 56;
const IMAGE_INFO_SIZE: usize = 32;
const MAX_SUBCACHES: usize = 128;
const MAX_IMAGES: usize = 100_000;
const MAX_PRIMARY_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubcacheEntry {
    pub uuid: [u8; 16],
    pub vm_offset: u64,
    pub suffix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub slide_info_offset: u64,
    pub slide_info_size: u64,
}

pub struct MemberHeader {
    pub uuid: [u8; 16],
    pub size: u64,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachSegment {
    pub name: String,
    pub address: u64,
    pub memory_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
}

/// Read the segment commands of an image located in a cache member.
pub fn read_image_segments<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
) -> Result<Vec<MachSegment>> {
    let size = reader.seek(SeekFrom::End(0))?;
    if offset.checked_add(32).is_none_or(|end| end > size) {
        bail!("dyld image header is outside its cache member");
    }
    reader.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 32];
    reader.read_exact(&mut header)?;
    if u32_at(&header, 0)? != 0xfeed_facf {
        bail!("dyld image is not a 64-bit Mach-O");
    }
    let command_count = u32_at(&header, 16)? as usize;
    let command_size = u32_at(&header, 20)? as usize;
    if command_size > 16 << 20
        || offset
            .checked_add(32 + command_size as u64)
            .is_none_or(|end| end > size)
    {
        bail!("dyld image has invalid load commands");
    }
    let mut commands = vec![0u8; command_size];
    reader.read_exact(&mut commands)?;
    let mut segments = Vec::new();
    let mut cursor = 0usize;
    for _ in 0..command_count {
        let command = u32_at(&commands, cursor)?;
        let length = u32_at(&commands, cursor + 4)? as usize;
        if length < 8
            || cursor
                .checked_add(length)
                .is_none_or(|end| end > command_size)
        {
            bail!("dyld image has invalid load command size");
        }
        if command == 0x19 {
            let segment = range(&commands, cursor, 72)?;
            let end = segment[8..24]
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(16);
            segments.push(MachSegment {
                name: std::str::from_utf8(&segment[8..8 + end])?.to_string(),
                address: u64_at(segment, 24)?,
                memory_size: u64_at(segment, 32)?,
                file_offset: u64_at(segment, 40)?,
                file_size: u64_at(segment, 48)?,
            });
        }
        cursor += length;
    }
    if segments.is_empty() {
        bail!("dyld image has no segments");
    }
    Ok(segments)
}

impl MemberHeader {
    pub fn read<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let size = reader.seek(SeekFrom::End(0))?;
        if size < HEADER_SIZE as u64 {
            bail!("dyld cache member is too small");
        }
        reader.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header)?;
        if header[..16].split(|&b| b == 0).next() != Some(b"dyld_v1  arm64e".as_slice()) {
            bail!("unsupported dyld cache member format");
        }
        let offset = u32_at(&header, 312)? as u64;
        let count = u32_at(&header, 316)? as usize;
        if count == 0
            || count > 64
            || offset
                .checked_add((count * 56) as u64)
                .is_none_or(|end| end > size)
        {
            bail!("dyld cache member has invalid mappings");
        }
        reader.seek(SeekFrom::Start(offset))?;
        let mut table = vec![0u8; count * 56];
        reader.read_exact(&mut table)?;
        let mut mappings = Vec::with_capacity(count);
        for record in table.as_chunks::<56>().0 {
            let mapping = Mapping {
                address: u64_at(record, 0)?,
                size: u64_at(record, 8)?,
                file_offset: u64_at(record, 16)?,
                slide_info_offset: u64_at(record, 24)?,
                slide_info_size: u64_at(record, 32)?,
            };
            if mapping.size == 0
                || mapping.address.checked_add(mapping.size).is_none()
                || mapping
                    .file_offset
                    .checked_add(mapping.size)
                    .is_none_or(|end| end > size)
                || (mapping.slide_info_size != 0
                    && mapping
                        .slide_info_offset
                        .checked_add(mapping.slide_info_size)
                        .is_none_or(|end| end > size))
            {
                bail!("dyld cache member contains an invalid mapping");
            }
            mappings.push(mapping);
        }
        Ok(Self {
            uuid: header[88..104].try_into().expect("16 bytes"),
            size,
            mappings,
        })
    }

    pub fn mapping_for_address(&self, address: u64) -> Option<&Mapping> {
        self.mappings
            .iter()
            .find(|mapping| mapping.address <= address && address < mapping.address + mapping.size)
    }
}

pub struct PrimaryIndex {
    bytes: Vec<u8>,
    pub uuid: [u8; 16],
    pub subcaches: Vec<SubcacheEntry>,
    images_offset: usize,
    images_count: usize,
}

impl PrimaryIndex {
    pub fn read<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let size = reader.seek(SeekFrom::End(0))?;
        if !(HEADER_SIZE as u64..=MAX_PRIMARY_SIZE).contains(&size) {
            bail!("dyld primary cache has invalid size {size}");
        }
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0u8; size as usize];
        reader.read_exact(&mut bytes)?;
        if bytes[..16].split(|&b| b == 0).next() != Some(b"dyld_v1  arm64e".as_slice()) {
            bail!("unsupported dyld shared-cache format");
        }
        let subcache_offset = u32_at(&bytes, 392)? as usize;
        let subcache_count = u32_at(&bytes, 396)? as usize;
        if subcache_count > MAX_SUBCACHES {
            bail!("dyld subcache count exceeds limit");
        }
        let subcache_table = range(
            &bytes,
            subcache_offset,
            subcache_count * SUBCACHE_ENTRY_SIZE,
        )?;
        let mut subcaches = Vec::with_capacity(subcache_count);
        for entry in subcache_table.as_chunks::<SUBCACHE_ENTRY_SIZE>().0 {
            let suffix = c_string(&entry[24..56])?;
            if suffix.is_empty() || suffix.contains(['/', '\\']) {
                bail!("invalid dyld subcache suffix");
            }
            subcaches.push(SubcacheEntry {
                uuid: entry[..16].try_into().expect("16 bytes"),
                vm_offset: u64_at(entry, 16)?,
                suffix: suffix.to_string(),
            });
        }
        let images_offset = u32_at(&bytes, 448)? as usize;
        let images_count = u32_at(&bytes, 452)? as usize;
        if images_count == 0 || images_count > MAX_IMAGES {
            bail!("dyld image count is invalid");
        }
        range(&bytes, images_offset, images_count * IMAGE_INFO_SIZE)?;
        let uuid = bytes[88..104].try_into().expect("16 bytes");
        Ok(Self {
            bytes,
            uuid,
            subcaches,
            images_offset,
            images_count,
        })
    }

    pub fn image_address(&self, path: &str) -> Result<Option<u64>> {
        let table = range(
            &self.bytes,
            self.images_offset,
            self.images_count * IMAGE_INFO_SIZE,
        )?;
        for image in table.as_chunks::<IMAGE_INFO_SIZE>().0 {
            let path_offset = u32_at(image, 24)? as usize;
            let name = c_string(range(
                &self.bytes,
                path_offset,
                4096.min(self.bytes.len() - path_offset.min(self.bytes.len())),
            )?)?;
            if name == path {
                return Ok(Some(u64_at(image, 0)?));
            }
        }
        Ok(None)
    }

    /// Pick the split-cache member whose VM offset precedes this address.
    /// The member's mapping table must still be checked before reading data.
    pub fn candidate_for_address(&self, base: u64, address: u64) -> Option<&SubcacheEntry> {
        let relative = address.checked_sub(base)?;
        self.subcaches
            .iter()
            .filter(|entry| entry.vm_offset <= relative)
            .max_by_key(|entry| entry.vm_offset)
    }
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or_else(|| anyhow::anyhow!("dyld range overflow"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("dyld range is outside the cache"))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, 4)?.try_into().expect("four bytes"),
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        range(bytes, offset, 8)?.try_into().expect("eight bytes"),
    ))
}

fn c_string(bytes: &[u8]) -> Result<&str> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| anyhow::anyhow!("unterminated dyld string"))?;
    Ok(std::str::from_utf8(&bytes[..end])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_subcache_and_image_index() {
        let mut bytes = vec![0u8; 700];
        bytes[..15].copy_from_slice(b"dyld_v1  arm64e");
        bytes[392..396].copy_from_slice(&568u32.to_le_bytes());
        bytes[396..400].copy_from_slice(&1u32.to_le_bytes());
        bytes[448..452].copy_from_slice(&624u32.to_le_bytes());
        bytes[452..456].copy_from_slice(&1u32.to_le_bytes());
        bytes[568..584].copy_from_slice(&[7; 16]);
        bytes[592..594].copy_from_slice(b".1");
        bytes[624..632].copy_from_slice(&0x1234u64.to_le_bytes());
        bytes[648..652].copy_from_slice(&656u32.to_le_bytes());
        bytes[656..661].copy_from_slice(b"/app\0");
        let index = PrimaryIndex::read(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(index.subcaches[0].suffix, ".1");
        assert_eq!(
            index.candidate_for_address(0x1000, 0x1234).unwrap().suffix,
            ".1"
        );
        assert_eq!(index.image_address("/app").unwrap(), Some(0x1234));
        assert_eq!(index.image_address("/other").unwrap(), None);
    }

    #[test]
    fn reads_member_mapping_and_rejects_out_of_range_mapping() {
        let mut bytes = vec![0u8; 700];
        bytes[..15].copy_from_slice(b"dyld_v1  arm64e");
        bytes[312..316].copy_from_slice(&568u32.to_le_bytes());
        bytes[316..320].copy_from_slice(&1u32.to_le_bytes());
        bytes[568..576].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[576..584].copy_from_slice(&100u64.to_le_bytes());
        bytes[584..592].copy_from_slice(&600u64.to_le_bytes());
        let member = MemberHeader::read(&mut Cursor::new(bytes.clone())).unwrap();
        assert_eq!(member.mapping_for_address(0x1030).unwrap().file_offset, 600);
        assert!(member.mapping_for_address(0x2000).is_none());
        bytes[576..584].copy_from_slice(&101u64.to_le_bytes());
        assert!(MemberHeader::read(&mut Cursor::new(bytes)).is_err());
    }
}
