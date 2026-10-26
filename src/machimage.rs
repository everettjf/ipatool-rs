//! ARM64e instruction preparation for images executed by Unicorn.

use anyhow::{Context, Result, bail};

use crate::{store_memory::MemoryRegion, unicorn_runtime::Engine};

const PAGE_SIZE: u64 = 4096;
const MAX_IMAGE_SPAN: u64 = 1 << 30;
const ARM64_CPU: u32 = 0x0100_000c;
const ARM64E_SUBTYPE: u32 = 2;
const MACH64_MAGIC: u32 = 0xfeed_facf;
const SEGMENT64_COMMAND: u32 = 0x19;
const PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const SOME_INSTRUCTIONS: u32 = 0x400;

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
}

pub struct Image {
    name: String,
    data: Vec<u8>,
    base: u64,
    segments: Vec<Segment>,
    code_ranges: Vec<(u64, u64)>,
    prelinked: bool,
}

pub trait Memory {
    fn map(&mut self, address: u64, size: u64) -> Result<()>;
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()>;
}

impl Memory for Engine {
    fn map(&mut self, address: u64, size: u64) -> Result<()> {
        self.mem_map(address, usize::try_from(size)?)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        self.mem_write(address, bytes)
    }
}

impl Image {
    pub fn open(name: impl Into<String>, input: &[u8]) -> Result<Self> {
        let name = name.into();
        let mut data = arm64_slice(input)?.to_vec();
        if read_le_u32(&data, 0)? != MACH64_MAGIC {
            bail!("open {name}: expected 64-bit Mach-O");
        }
        if read_le_u32(&data, 4)? != ARM64_CPU {
            bail!("open {name}: expected arm64 Mach-O");
        }
        let command_count = read_le_u32(&data, 16)? as usize;
        let commands_size = read_le_u32(&data, 20)? as usize;
        let commands_end = 32usize
            .checked_add(commands_size)
            .context("Mach-O load commands overflow")?;
        if commands_end > data.len() {
            bail!("open {name}: load commands exceed image");
        }
        let mut segments = Vec::new();
        let mut code_ranges = Vec::new();
        let mut command_offset = 32usize;
        for _ in 0..command_count {
            let command = read_le_u32(&data, command_offset)?;
            let size = read_le_u32(&data, command_offset + 4)? as usize;
            let command_end = command_offset
                .checked_add(size)
                .context("Mach-O command range overflows")?;
            if size < 8 || command_end > commands_end {
                bail!("open {name}: invalid Mach-O load command");
            }
            if command == SEGMENT64_COMMAND {
                if size < 72 {
                    bail!("open {name}: truncated segment command");
                }
                let segment_name = read_name(&data, command_offset + 8)?;
                let address = read_le_u64(&data, command_offset + 24)?;
                let segment_size = read_le_u64(&data, command_offset + 32)?;
                let file_offset = read_le_u64(&data, command_offset + 40)?;
                let file_size = read_le_u64(&data, command_offset + 48)?;
                let section_count = read_le_u32(&data, command_offset + 64)? as usize;
                let required = section_count
                    .checked_mul(80)
                    .and_then(|bytes| bytes.checked_add(72))
                    .context("Mach-O section table overflows")?;
                if required > size {
                    bail!("open {name}: segment section table exceeds command");
                }
                for section in 0..section_count {
                    let start = command_offset + 72 + section * 80;
                    let section_address = read_le_u64(&data, start + 32)?;
                    let section_size = read_le_u64(&data, start + 40)?;
                    let offset = read_le_u32(&data, start + 48)? as u64;
                    let flags = read_le_u32(&data, start + 64)?;
                    if flags & (PURE_INSTRUCTIONS | SOME_INSTRUCTIONS) != 0 {
                        rewrite_instruction_section(&mut data, offset, section_size)
                            .with_context(|| format!("prepare {name} instruction section"))?;
                        let end = section_address
                            .checked_add(section_size)
                            .context("instruction address overflows")?;
                        code_ranges.push((section_address, end));
                    }
                }
                segments.push(Segment {
                    name: segment_name,
                    address,
                    size: segment_size,
                    file_offset,
                    file_size,
                });
            }
            command_offset = command_end;
        }
        let base = segments
            .iter()
            .find(|segment| segment.name == "__TEXT")
            .map_or(0, |segment| segment.address);
        validate_segments(&name, data.len(), &segments)?;
        Ok(Self {
            name,
            data,
            base,
            segments,
            code_ranges,
            prelinked: false,
        })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    /// Resolve a Mach-O symbol and translate it to the image's load address.
    pub fn export(&self, name: &str, load_base: u64) -> Result<u64> {
        let commands_size = read_le_u32(&self.data, 20)? as usize;
        let count = read_le_u32(&self.data, 16)? as usize;
        let commands_end = 32usize
            .checked_add(commands_size)
            .context("Mach-O commands overflow")?;
        let mut cursor = 32usize;
        let mut symtab = None;
        for _ in 0..count {
            let kind = read_le_u32(&self.data, cursor)?;
            let size = read_le_u32(&self.data, cursor + 4)? as usize;
            if size < 8
                || cursor
                    .checked_add(size)
                    .is_none_or(|end| end > commands_end)
            {
                bail!("{} has invalid Mach-O load commands", self.name);
            }
            if kind == 2 {
                if size < 24 {
                    bail!("{} has truncated symbol table command", self.name);
                }
                symtab = Some((
                    read_le_u32(&self.data, cursor + 8)? as usize,
                    read_le_u32(&self.data, cursor + 12)? as usize,
                    read_le_u32(&self.data, cursor + 16)? as usize,
                    read_le_u32(&self.data, cursor + 20)? as usize,
                ));
            }
            cursor += size;
        }
        let (symbol_offset, symbol_count, string_offset, string_size) =
            symtab.with_context(|| format!("{} has no Mach-O symbol table", self.name))?;
        if symbol_count > 4 << 20 {
            bail!("{} has too many symbols", self.name);
        }
        let symbols_end = symbol_offset
            .checked_add(
                symbol_count
                    .checked_mul(16)
                    .context("symbol count overflow")?,
            )
            .context("symbol table overflow")?;
        let strings_end = string_offset
            .checked_add(string_size)
            .context("symbol strings overflow")?;
        let symbols = self
            .data
            .get(symbol_offset..symbols_end)
            .context("symbol table exceeds image")?;
        let strings = self
            .data
            .get(string_offset..strings_end)
            .context("symbol strings exceed image")?;
        for symbol in symbols.as_chunks::<16>().0 {
            let name_offset =
                u32::from_le_bytes(symbol[..4].try_into().expect("four bytes")) as usize;
            let Some(tail) = strings.get(name_offset..) else {
                continue;
            };
            let Some(end) = tail.iter().position(|&byte| byte == 0) else {
                continue;
            };
            if tail[..end].eq_ignore_ascii_case(name.as_bytes()) {
                let address = u64::from_le_bytes(symbol[8..16].try_into().expect("eight bytes"));
                let relative = address
                    .checked_sub(self.base)
                    .with_context(|| format!("symbol {name} precedes {} base", self.name))?;
                return load_base
                    .checked_add(relative)
                    .context("export address overflow");
            }
        }
        bail!("symbol {name} was not found in {}", self.name)
    }

    pub fn code_ranges(&self) -> &[(u64, u64)] {
        &self.code_ranges
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Cache images stay at their preferred address. Resolve the supplied
    /// external cache pointers in writable file-backed segments before load.
    pub fn prepare_prelinked<F>(&mut self, external: &[(u64, String)], mut resolve: F) -> Result<()>
    where
        F: FnMut(&str) -> Result<u64>,
    {
        if self.prelinked {
            bail!("{} is already prepared", self.name);
        }
        let mut replacements = std::collections::HashMap::new();
        for (address, name) in external {
            replacements.insert(*address, resolve(name)?);
        }
        for segment in &self.segments {
            if segment.name == "__TEXT" || segment.name == "__LINKEDIT" || segment.file_size < 8 {
                continue;
            }
            let mut offset = segment.file_offset;
            if segment.address % 8 != 0 {
                offset += 8 - segment.address % 8;
            }
            let end = segment.file_offset + segment.file_size;
            while offset <= end - 8 {
                let start = offset as usize;
                let current = u64::from_le_bytes(self.data[start..start + 8].try_into()?);
                if let Some(&value) = replacements.get(&current) {
                    self.data[start..start + 8].copy_from_slice(&value.to_le_bytes());
                }
                offset += 8;
            }
        }
        self.prelinked = true;
        Ok(())
    }

    pub fn mapped_regions(&self) -> Result<Vec<MemoryRegion>> {
        let mut ranges = Vec::new();
        for segment in &self.segments {
            if segment.name == "__PAGEZERO" || segment.size == 0 {
                continue;
            }
            if segment.address < self.base {
                bail!("segment {} precedes image base", segment.name);
            }
            let end = segment
                .address
                .checked_add(segment.size)
                .context("segment address range overflows")?;
            let aligned_end = end
                .checked_add(PAGE_SIZE - 1)
                .context("segment mapped range overflows")?
                & !(PAGE_SIZE - 1);
            ranges.push((segment.address & !(PAGE_SIZE - 1), aligned_end));
        }
        if ranges.is_empty() {
            bail!("{} has no loadable segments", self.name);
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        let mut mapped = 0u64;
        let mut regions = Vec::with_capacity(merged.len());
        for (start, end) in merged {
            let size = end - start;
            mapped = mapped
                .checked_add(size)
                .context("mapped image size overflows")?;
            if mapped > MAX_IMAGE_SPAN {
                bail!("mapped segments make {} too large", self.name);
            }
            regions.push(MemoryRegion {
                address: start,
                size,
            });
        }
        Ok(regions)
    }

    pub fn load(&self, memory: &mut impl Memory) -> Result<()> {
        if !self.prelinked {
            bail!("{} must be prepared before loading", self.name);
        }
        for region in self.mapped_regions()? {
            memory
                .map(region.address, region.size)
                .with_context(|| format!("map {}", self.name))?;
        }
        for segment in &self.segments {
            if segment.name == "__PAGEZERO" || segment.file_size == 0 {
                continue;
            }
            let start = segment.file_offset as usize;
            let end = start + segment.file_size as usize;
            memory
                .write(segment.address, &self.data[start..end])
                .with_context(|| format!("write segment {} from {}", segment.name, self.name))?;
        }
        Ok(())
    }
}

fn validate_segments(name: &str, data_len: usize, segments: &[Segment]) -> Result<()> {
    for segment in segments {
        if segment.file_size > segment.size {
            bail!(
                "segment {} file data exceeds its memory size in {name}",
                segment.name
            );
        }
        segment.address.checked_add(segment.size).with_context(|| {
            format!("segment {} address range overflows in {name}", segment.name)
        })?;
        let end = segment
            .file_offset
            .checked_add(segment.file_size)
            .with_context(|| format!("segment {} file range overflows in {name}", segment.name))?;
        if end > data_len as u64 {
            bail!("segment {} data exceeds {name}", segment.name);
        }
    }
    Ok(())
}

fn arm64_slice(input: &[u8]) -> Result<&[u8]> {
    let magic = read_be_u32(input, 0)?;
    let (arch_size, is_64, little_endian) = match magic {
        0xcafe_babe => (20usize, false, false),
        0xcafe_babf => (32usize, true, false),
        0xbeba_feca => (20usize, false, true),
        0xbfba_feca => (32usize, true, true),
        _ => return Ok(input),
    };
    let count = read_fat_u32(input, 4, little_endian)? as usize;
    let table_bytes = count
        .checked_mul(arch_size)
        .context("fat Mach-O table overflows")?;
    if 8usize
        .checked_add(table_bytes)
        .context("fat Mach-O table overflows")?
        > input.len()
    {
        bail!("fat Mach-O table exceeds input");
    }
    for index in 0..count {
        let offset = 8 + index * arch_size;
        let cpu = read_fat_u32(input, offset, little_endian)?;
        let subtype = read_fat_u32(input, offset + 4, little_endian)?;
        if cpu != ARM64_CPU || subtype & 0x00ff_ffff != ARM64E_SUBTYPE {
            continue;
        }
        let (start, size) = if is_64 {
            (
                read_fat_u64(input, offset + 8, little_endian)?,
                read_fat_u64(input, offset + 16, little_endian)?,
            )
        } else {
            (
                read_fat_u32(input, offset + 8, little_endian)? as u64,
                read_fat_u32(input, offset + 12, little_endian)? as u64,
            )
        };
        let end = start
            .checked_add(size)
            .context("arm64e slice range overflows")?;
        let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
            bail!("arm64e slice exceeds input size");
        };
        let Some(slice) = input.get(start..end) else {
            bail!("arm64e slice exceeds input size");
        };
        return Ok(slice);
    }
    bail!("universal binary has no arm64e slice")
}

fn read_name(data: &[u8], offset: usize) -> Result<String> {
    let bytes = data
        .get(offset..offset + 16)
        .context("truncated Mach-O name")?;
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(16);
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_le_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .context("truncated Mach-O")?
            .try_into()?,
    ))
}

fn read_le_u64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(offset..offset + 8)
            .context("truncated Mach-O")?
            .try_into()?,
    ))
}

fn read_be_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        data.get(offset..offset + 4)
            .context("truncated Mach-O")?
            .try_into()?,
    ))
}

fn read_fat_u32(data: &[u8], offset: usize, little: bool) -> Result<u32> {
    if little {
        read_le_u32(data, offset)
    } else {
        read_be_u32(data, offset)
    }
}

fn read_fat_u64(data: &[u8], offset: usize, little: bool) -> Result<u64> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .context("truncated fat Mach-O")?
        .try_into()?;
    Ok(if little {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

/// Replace pointer-authentication instructions with their unsigned ARM64
/// equivalents before placing an image in the guest address space.
pub fn without_pointer_authentication(instruction: u32) -> u32 {
    const NOP: u32 = 0xd503_201f;
    match instruction & 0xffff_fc00 {
        0xd71f_0800 | 0xd71f_0c00 | 0xd61f_0800 | 0xd61f_0c00 => {
            return 0xd61f_0000 | (instruction & 0x3e0);
        }
        0xd73f_0800 | 0xd73f_0c00 | 0xd63f_0800 | 0xd63f_0c00 => {
            return 0xd63f_0000 | (instruction & 0x3e0);
        }
        0xdac1_0000 | 0xdac1_0400 | 0xdac1_0800 | 0xdac1_0c00 | 0xdac1_1000 | 0xdac1_1400
        | 0xdac1_1800 | 0xdac1_1c00 => return NOP,
        _ => {}
    }
    match instruction {
        0xd65f_0bff | 0xd65f_0fff => return 0xd65f_03c0,
        0xd503_211f | 0xd503_215f | 0xd503_219f | 0xd503_21df | 0xd503_233f | 0xd503_237f
        | 0xd503_23bf | 0xd503_23ff | 0xd503_20ff => return NOP,
        _ => {}
    }
    match instruction & 0xffff_ffe0 {
        0xdac1_23e0 | 0xdac1_27e0 | 0xdac1_2be0 | 0xdac1_2fe0 | 0xdac1_33e0 | 0xdac1_37e0
        | 0xdac1_3be0 | 0xdac1_3fe0 | 0xdac1_43e0 | 0xdac1_47e0 => NOP,
        _ => instruction,
    }
}

/// Rewrite a validated instruction section in a private image copy.
pub fn rewrite_instruction_section(data: &mut [u8], offset: u64, size: u64) -> Result<()> {
    let Some(end) = offset.checked_add(size) else {
        bail!("instruction section range overflows");
    };
    let Ok(start) = usize::try_from(offset) else {
        bail!("instruction section exceeds image");
    };
    let Ok(end) = usize::try_from(end) else {
        bail!("instruction section exceeds image");
    };
    let Some(section) = data.get_mut(start..end) else {
        bail!("instruction section exceeds image");
    };
    for chunk in section.as_chunks_mut::<4>().0 {
        let instruction = u32::from_le_bytes(*chunk);
        chunk.copy_from_slice(&without_pointer_authentication(instruction).to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordedMemory {
        maps: Vec<(u64, u64)>,
        writes: Vec<(u64, Vec<u8>)>,
    }

    impl Memory for RecordedMemory {
        fn map(&mut self, address: u64, size: u64) -> Result<()> {
            self.maps.push((address, size));
            Ok(())
        }

        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
            if !self.maps.iter().any(|&(start, size)| {
                address >= start && address + bytes.len() as u64 <= start + size
            }) {
                bail!("write outside mapped image");
            }
            self.writes.push((address, bytes.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn parses_and_maps_committed_authentication_plugin() {
        let profile = crate::store_profile::load().unwrap();
        let mut image = Image::open("AMSAccountAuthenticationPlugin", &profile.plugin).unwrap();
        assert!(image.base() != 0);
        assert!(!image.code_ranges().is_empty());
        assert!(image.segments().iter().any(|s| s.name == "__TEXT"));
        let mut memory = RecordedMemory::default();
        assert!(image.load(&mut memory).is_err());
        image.prepare_prelinked(&[], |_| unreachable!()).unwrap();
        image.load(&mut memory).unwrap();
        assert!(!memory.maps.is_empty());
        assert_eq!(
            memory.writes.len(),
            image
                .segments()
                .iter()
                .filter(|s| s.name != "__PAGEZERO" && s.file_size != 0)
                .count()
        );
        for ((address, bytes), segment) in memory.writes.iter().zip(
            image
                .segments()
                .iter()
                .filter(|s| s.name != "__PAGEZERO" && s.file_size != 0),
        ) {
            assert_eq!(*address, segment.address);
            assert_eq!(bytes.len(), segment.file_size as usize);
            let start = segment.file_offset as usize;
            assert_eq!(bytes, &image.data[start..start + bytes.len()]);
        }
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn loads_committed_authentication_plugin_into_unicorn() {
        let profile = crate::store_profile::load().unwrap();
        let mut image = Image::open("AMSAccountAuthenticationPlugin", &profile.plugin).unwrap();
        image.prepare_prelinked(&[], |_| unreachable!()).unwrap();
        let mut engine = Engine::new().unwrap();
        image.load(&mut engine).unwrap();
        let segment = image
            .segments()
            .iter()
            .find(|segment| segment.name == "__TEXT" && segment.file_size >= 16)
            .unwrap();
        let start = segment.file_offset as usize;
        assert_eq!(
            engine.mem_read(segment.address, 16).unwrap(),
            image.data[start..start + 16]
        );
    }

    #[test]
    fn prelinked_import_replacement_only_changes_data_segments() {
        let old = 0x0102_0304_0506_0708u64;
        let replacement = 0x8877_6655_4433_2211u64;
        let mut data = vec![0; 32];
        data[0..8].copy_from_slice(&old.to_le_bytes());
        data[16..24].copy_from_slice(&old.to_le_bytes());
        let mut image = Image {
            name: "fixture".into(),
            data,
            base: 0x1000,
            segments: vec![
                Segment {
                    name: "__TEXT".into(),
                    address: 0x1000,
                    size: 16,
                    file_offset: 0,
                    file_size: 16,
                },
                Segment {
                    name: "__DATA".into(),
                    address: 0x2000,
                    size: 16,
                    file_offset: 16,
                    file_size: 16,
                },
            ],
            code_ranges: Vec::new(),
            prelinked: false,
        };
        image
            .prepare_prelinked(&[(old, "import".into())], |name| {
                assert_eq!(name, "import");
                Ok(replacement)
            })
            .unwrap();
        assert_eq!(&image.data[0..8], &old.to_le_bytes());
        assert_eq!(&image.data[16..24], &replacement.to_le_bytes());
        assert!(image.prepare_prelinked(&[], |_| unreachable!()).is_err());
    }

    #[test]
    fn rejects_invalid_segment_ranges() {
        let segment = Segment {
            name: "__DATA".into(),
            address: 0x1000,
            size: 8,
            file_offset: 8,
            file_size: 16,
        };
        assert!(validate_segments("test", 32, std::slice::from_ref(&segment)).is_err());
        let segment = Segment {
            size: 16,
            file_offset: u64::MAX - 7,
            ..segment
        };
        assert!(validate_segments("test", 32, &[segment]).is_err());
    }

    #[test]
    fn rewrites_arm64e_control_flow_and_data_authentication() {
        assert_eq!(without_pointer_authentication(0xd65f_0bff), 0xd65f_03c0);
        assert_eq!(without_pointer_authentication(0xd61f_0a00), 0xd61f_0200);
        assert_eq!(without_pointer_authentication(0xd63f_0a20), 0xd63f_0220);
        assert_eq!(without_pointer_authentication(0xdac1_23e3), 0xd503_201f);
        assert_eq!(without_pointer_authentication(0xd503_211f), 0xd503_201f);
        assert_eq!(without_pointer_authentication(0xd503_201f), 0xd503_201f);
    }

    #[test]
    fn section_rewrite_respects_bounds() {
        let mut image = [0xaa, 0xff, 0x0b, 0x5f, 0xd6, 0xaa];
        rewrite_instruction_section(&mut image, 1, 4).unwrap();
        assert_eq!(image, [0xaa, 0xc0, 0x03, 0x5f, 0xd6, 0xaa]);
        assert!(rewrite_instruction_section(&mut image, u64::MAX, 2).is_err());
        assert!(rewrite_instruction_section(&mut image, 4, 4).is_err());
    }
}
