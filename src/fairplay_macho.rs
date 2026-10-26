//! Locate and validate encrypted Mach-O slices before FairPlay page mutation.

use anyhow::{Context, Result, bail};

use crate::fairplay_supf::PAGE_BYTES;

const MH_MAGIC32: u32 = 0xfeedface;
const MH_MAGIC64: u32 = 0xfeedfacf;
const MH_CIGAM32: u32 = 0xcefaedfe;
const MH_CIGAM64: u32 = 0xcffaedfe;
const FAT_MAGIC32: u32 = 0xcafebabe;
const FAT_CIGAM32: u32 = 0xbebafeca;
const FAT_MAGIC64: u32 = 0xcafebabf;
const FAT_CIGAM64: u32 = 0xbfbafeca;
const CPU_ARM: u32 = 0x0c;
const CPU_ARM64: u32 = 0x0100_000c;
const CPU_ARM64_32: u32 = 0x0200_000c;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRange {
    pub offset: usize,
    pub size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachOLayout {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub crypt_offset: usize,
    pub crypt_size: usize,
    pub crypt_id: u32,
    pub crypt_id_offset: usize,
    pub signature_offset: usize,
    pub signature_size: usize,
    pub instruction_ranges: Vec<FileRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachOSlice {
    pub offset: usize,
    pub size: usize,
    pub layout: MachOLayout,
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub fn is_macho(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (matches!(
            le32(bytes, 0),
            MH_MAGIC32 | MH_MAGIC64 | MH_CIGAM32 | MH_CIGAM64
        ) || matches!(
            be32(bytes, 0),
            FAT_MAGIC32 | FAT_CIGAM32 | FAT_MAGIC64 | FAT_CIGAM64
        ))
}

fn parse_thin(bytes: &[u8]) -> Result<MachOLayout> {
    if bytes.len() < 4 {
        bail!("Mach-O header is truncated");
    }
    let magic = le32(bytes, 0);
    let header_size = match magic {
        MH_MAGIC32 => 28,
        MH_MAGIC64 => 32,
        MH_CIGAM32 | MH_CIGAM64 => bail!("big-endian thin Mach-O is unsupported"),
        _ => bail!("expected thin little-endian Mach-O"),
    };
    if bytes.len() < header_size {
        bail!("Mach-O header is truncated");
    }
    let command_count = le32(bytes, 16) as usize;
    let command_bytes = le32(bytes, 20) as usize;
    let commands_end = header_size
        .checked_add(command_bytes)
        .context("Mach-O load-command size overflow")?;
    if commands_end > bytes.len() || command_count > command_bytes / 8 {
        bail!("Mach-O load commands are truncated or inconsistent");
    }
    let mut layout = MachOLayout {
        cpu_type: le32(bytes, 4),
        cpu_subtype: le32(bytes, 8),
        crypt_offset: 0,
        crypt_size: 0,
        crypt_id: 0,
        crypt_id_offset: 0,
        signature_offset: 0,
        signature_size: 0,
        instruction_ranges: Vec::new(),
    };
    let mut cursor = header_size;
    let mut encryption = false;
    let mut signature = false;
    for _ in 0..command_count {
        if commands_end - cursor < 8 {
            bail!("Mach-O load command header is truncated");
        }
        let command = le32(bytes, cursor);
        let size = le32(bytes, cursor + 4) as usize;
        if size < 8 || size > commands_end - cursor {
            bail!("Mach-O load command has invalid size");
        }
        match command {
            0x01 | 0x19 => {
                let is_64 = command == 0x19;
                let (header, section_size, count_offset, file_offset, byte_size, flags_offset) =
                    if is_64 {
                        (72, 80, 64, 48, 40, 64)
                    } else {
                        (56, 68, 48, 40, 36, 56)
                    };
                if size < header {
                    bail!("Mach-O segment command is truncated");
                }
                let count = le32(bytes, cursor + count_offset) as usize;
                if count > (size - header) / section_size || header + count * section_size != size {
                    bail!("Mach-O segment section table is invalid");
                }
                for index in 0..count {
                    let start = cursor + header + index * section_size;
                    let section = &bytes[start..start + section_size];
                    if le32(section, flags_offset) & (0x8000_0000 | 0x400) == 0 {
                        continue;
                    }
                    let offset = le32(section, file_offset) as usize;
                    let length = if is_64 {
                        u64::from_le_bytes(section[byte_size..byte_size + 8].try_into().unwrap())
                            as usize
                    } else {
                        le32(section, byte_size) as usize
                    };
                    if length == 0 {
                        continue;
                    }
                    let end = offset
                        .checked_add(length)
                        .context("Mach-O instruction section range overflow")?;
                    if end > bytes.len() {
                        bail!("Mach-O instruction section exceeds file");
                    }
                    if layout.instruction_ranges.iter().any(|previous| {
                        offset < previous.offset + previous.size && previous.offset < end
                    }) {
                        bail!("Mach-O instruction sections overlap");
                    }
                    layout.instruction_ranges.push(FileRange {
                        offset,
                        size: length,
                    });
                }
            }
            0x21 | 0x2c => {
                let minimum = if command == 0x2c { 24 } else { 20 };
                if size < minimum || encryption {
                    bail!("Mach-O encryption command is invalid");
                }
                layout.crypt_offset = le32(bytes, cursor + 8) as usize;
                layout.crypt_size = le32(bytes, cursor + 12) as usize;
                layout.crypt_id = le32(bytes, cursor + 16);
                layout.crypt_id_offset = cursor + 16;
                encryption = true;
            }
            0x1d => {
                if size < 16 || signature {
                    bail!("Mach-O code-signature command is invalid");
                }
                layout.signature_offset = le32(bytes, cursor + 8) as usize;
                layout.signature_size = le32(bytes, cursor + 12) as usize;
                signature = true;
            }
            _ => {}
        }
        cursor += size;
    }
    if cursor != commands_end {
        bail!("Mach-O load commands do not fill header");
    }
    if !encryption || layout.crypt_id == 0 {
        return Ok(layout);
    }
    if layout.crypt_id != 1
        || (magic == MH_MAGIC32 && !matches!(layout.cpu_type, CPU_ARM | CPU_ARM64_32))
        || (magic == MH_MAGIC64 && layout.cpu_type != CPU_ARM64)
    {
        bail!("unsupported encrypted Mach-O architecture or cryptid");
    }
    if !signature {
        bail!("Mach-O has no code-signature command");
    }
    let crypt_end = layout
        .crypt_offset
        .checked_add(layout.crypt_size)
        .context("Mach-O encrypted range overflow")?;
    let signature_end = layout
        .signature_offset
        .checked_add(layout.signature_size)
        .context("Mach-O signature range overflow")?;
    if crypt_end > bytes.len() || signature_end > bytes.len() {
        bail!("Mach-O range exceeds file");
    }
    if layout.crypt_size == 0
        || !layout.crypt_size.is_multiple_of(PAGE_BYTES)
        || !layout.crypt_offset.is_multiple_of(PAGE_BYTES)
    {
        bail!("Mach-O encrypted range must be nonempty and 4 KiB aligned");
    }
    if layout.crypt_offset < commands_end || crypt_end > layout.signature_offset {
        bail!("Mach-O encrypted range overlaps headers or signature");
    }
    Ok(layout)
}

pub fn parse_macho_slices(bytes: &[u8]) -> Result<Vec<MachOSlice>> {
    if bytes.len() < 4 {
        bail!("Mach-O header is truncated");
    }
    match le32(bytes, 0) {
        MH_MAGIC32 | MH_MAGIC64 | MH_CIGAM32 | MH_CIGAM64 => {
            return Ok(vec![MachOSlice {
                offset: 0,
                size: bytes.len(),
                layout: parse_thin(bytes)?,
            }]);
        }
        _ => {}
    }
    let magic = be32(bytes, 0);
    if !matches!(magic, FAT_MAGIC32 | FAT_CIGAM32 | FAT_MAGIC64 | FAT_CIGAM64) {
        bail!("expected Mach-O image");
    }
    if bytes.len() < 8 {
        bail!("universal Mach-O header is truncated");
    }
    let little = matches!(magic, FAT_CIGAM32 | FAT_CIGAM64);
    let is_64 = matches!(magic, FAT_MAGIC64 | FAT_CIGAM64);
    let entry_size = if is_64 { 32 } else { 20 };
    let read32 = |blob: &[u8], offset| {
        if little {
            le32(blob, offset)
        } else {
            be32(blob, offset)
        }
    };
    let count = read32(bytes, 4) as usize;
    if count == 0 || count > 32 || count > (bytes.len() - 8) / entry_size {
        bail!("universal Mach-O architecture count is invalid");
    }
    let table_end = 8 + count * entry_size;
    let mut slices: Vec<MachOSlice> = Vec::with_capacity(count);
    for index in 0..count {
        let entry = &bytes[8 + index * entry_size..8 + (index + 1) * entry_size];
        let cpu_type = read32(entry, 0);
        let cpu_subtype = read32(entry, 4);
        let read64 = |blob: &[u8], offset| {
            let chunk: [u8; 8] = blob[offset..offset + 8].try_into().unwrap();
            if little {
                u64::from_le_bytes(chunk)
            } else {
                u64::from_be_bytes(chunk)
            }
        };
        let (offset, size) = if is_64 {
            (read64(entry, 8), read64(entry, 16))
        } else {
            (u64::from(read32(entry, 8)), u64::from(read32(entry, 12)))
        };
        let align = read32(entry, if is_64 { 24 } else { 16 });
        let offset = usize::try_from(offset).context("Mach-O slice offset exceeds platform")?;
        let size = usize::try_from(size).context("Mach-O slice size exceeds platform")?;
        let end = offset
            .checked_add(size)
            .context("Mach-O slice range overflow")?;
        if size == 0 || offset < table_end || end > bytes.len() {
            bail!("universal Mach-O architecture {index} has invalid bounds");
        }
        if align > 63 || (offset as u64) & ((1u64 << align) - 1) != 0 {
            bail!("universal Mach-O architecture {index} is misaligned");
        }
        if slices
            .iter()
            .any(|previous| offset < previous.offset + previous.size && previous.offset < end)
        {
            bail!("universal Mach-O architectures overlap");
        }
        let layout = parse_thin(&bytes[offset..end])
            .with_context(|| format!("universal Mach-O architecture {index}"))?;
        if layout.cpu_type != cpu_type || layout.cpu_subtype != cpu_subtype {
            bail!("universal Mach-O architecture {index} does not match its slice");
        }
        slices.push(MachOSlice {
            offset,
            size,
            layout,
        });
    }
    Ok(slices)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thin() -> Vec<u8> {
        let mut bytes = vec![0u8; PAGE_BYTES * 3];
        bytes[..4].copy_from_slice(&MH_MAGIC64.to_le_bytes());
        bytes[4..8].copy_from_slice(&CPU_ARM64.to_le_bytes());
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&40u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x2cu32.to_le_bytes());
        bytes[36..40].copy_from_slice(&24u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&(PAGE_BYTES as u32).to_le_bytes());
        bytes[44..48].copy_from_slice(&(PAGE_BYTES as u32).to_le_bytes());
        bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&0x1du32.to_le_bytes());
        bytes[60..64].copy_from_slice(&16u32.to_le_bytes());
        bytes[64..68].copy_from_slice(&(PAGE_BYTES as u32 * 2).to_le_bytes());
        bytes[68..72].copy_from_slice(&(PAGE_BYTES as u32).to_le_bytes());
        bytes
    }

    #[test]
    fn parses_encrypted_thin_and_fat_images() {
        let thin = thin();
        let parsed = parse_macho_slices(&thin).unwrap();
        assert_eq!(parsed[0].layout.crypt_id_offset, 48);
        assert_eq!(parsed[0].layout.crypt_size, PAGE_BYTES);
        let mut fat = vec![0u8; PAGE_BYTES + thin.len()];
        fat[..4].copy_from_slice(&FAT_MAGIC32.to_be_bytes());
        fat[4..8].copy_from_slice(&1u32.to_be_bytes());
        fat[8..12].copy_from_slice(&CPU_ARM64.to_be_bytes());
        fat[12..16].copy_from_slice(&2u32.to_be_bytes());
        fat[16..20].copy_from_slice(&(PAGE_BYTES as u32).to_be_bytes());
        fat[20..24].copy_from_slice(&(thin.len() as u32).to_be_bytes());
        fat[24..28].copy_from_slice(&12u32.to_be_bytes());
        fat[PAGE_BYTES..].copy_from_slice(&thin);
        assert_eq!(parse_macho_slices(&fat).unwrap()[0].offset, PAGE_BYTES);
        fat[12..16].copy_from_slice(&3u32.to_be_bytes());
        assert!(parse_macho_slices(&fat).is_err());
    }

    #[test]
    fn rejects_encrypted_range_overlapping_signature() {
        let mut bytes = thin();
        bytes[64..68].copy_from_slice(&(PAGE_BYTES as u32).to_le_bytes());
        assert!(parse_macho_slices(&bytes).is_err());
    }
}
