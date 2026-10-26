//! Reconstruction of linkedit data for a Mach-O extracted from a dyld cache.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};

use crate::{
    dyld_cache::{ImageLayout, LoadCommand, MachSegment},
    sap_system_os::SystemOsCache,
};

const LC_SYMTAB: u32 = 2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_FUNCTION_VARIANTS: u32 = 0x37;
const MAX_SYMBOLS: usize = 4 << 20;
const PAGE_SIZE: u64 = 16_384;
const MAX_EXPORTED_IMAGE: u64 = 128 << 20;

struct OutputSegment {
    original: MachSegment,
    offset: u64,
    file_size: u64,
    memory_size: u64,
}

/// Export a cached dylib as a standalone Mach-O image.
pub fn export_image(cache: &mut SystemOsCache<'_>, path: &str) -> Result<Vec<u8>> {
    let (image_address, mut layout) = cache.image_layout(path)?;
    let text_first_section = first_section_offset(&layout)?;
    let mut segments = Vec::new();
    let mut next_offset = 0u64;
    let mut segment_index = 0usize;
    for command in layout.load_commands.clone() {
        if command.kind != 0x19 {
            continue;
        }
        let original = layout
            .segments
            .get(segment_index)
            .context("segment command count changed")?
            .clone();
        segment_index += 1;
        let aligned_size = page_align(original.file_size)?;
        let new_memory_size = if original.memory_size > original.file_size {
            aligned_size
                .checked_add(original.memory_size - original.file_size)
                .context("segment memory size overflow")?
        } else {
            aligned_size
        };
        set_u64(&mut layout.commands, command.offset + 32, new_memory_size)?;
        set_u64(&mut layout.commands, command.offset + 40, next_offset)?;
        set_u64(&mut layout.commands, command.offset + 48, aligned_size)?;
        let section_count = u32_at(&layout.commands, command.offset + 64)? as usize;
        for index in 0..section_count {
            let section = command.offset + 72 + index * 80;
            let old_offset = u32_at(&layout.commands, section + 48)?;
            if old_offset != 0 {
                let address = u64_at(&layout.commands, section + 32)?;
                let relative = address
                    .checked_sub(original.address)
                    .context("section precedes segment")?;
                set_u32(&mut layout.commands, section + 48, next_offset + relative)?;
            }
        }
        segments.push(OutputSegment {
            original,
            offset: next_offset,
            file_size: aligned_size,
            memory_size: new_memory_size,
        });
        next_offset = next_offset
            .checked_add(aligned_size)
            .context("export image size overflow")?;
    }
    let link_index = segments
        .iter()
        .position(|segment| segment.original.name == "__LINKEDIT")
        .context("cached image has no __LINKEDIT")?;
    if link_index + 1 != segments.len() {
        bail!("__LINKEDIT is not the final segment");
    }
    let linkedit_address = segments[link_index].original.address;
    let linkedit_suffix = cache
        .member_suffix_for_address(linkedit_address)?
        .to_string();
    let linkedit_start = segments[link_index].offset;
    let linkedit = rebuild_linkedit(
        cache,
        &mut layout,
        &linkedit_suffix,
        linkedit_start,
        image_address,
    )?;
    let linkedit_size = linkedit.bytes.len() as u64;
    let linkedit_cmd = layout
        .load_commands
        .iter()
        .filter(|command| command.kind == 0x19)
        .nth(link_index)
        .copied()
        .context("missing __LINKEDIT command")?;
    set_u64(
        &mut layout.commands,
        linkedit_cmd.offset + 32,
        page_align(linkedit_size)?,
    )?;
    set_u64(
        &mut layout.commands,
        linkedit_cmd.offset + 48,
        linkedit_size,
    )?;
    segments[link_index].file_size = linkedit_size;
    segments[link_index].memory_size = page_align(linkedit_size)?;

    let total = linkedit_start
        .checked_add(linkedit_size)
        .context("export size overflow")?;
    if total > MAX_EXPORTED_IMAGE {
        bail!("exported image exceeds size limit");
    }
    let mut output = vec![0u8; total as usize];
    let load_end = 32 + layout.commands.len();
    if load_end > output.len() {
        bail!("Mach-O commands exceed exported image");
    }
    let mut header = layout.header;
    let flags = u32_at(&header, 24)? & 0x7fff_ffff;
    header[24..28].copy_from_slice(&flags.to_le_bytes());
    output[..32].copy_from_slice(&header);
    output[32..load_end].copy_from_slice(&layout.commands);
    for segment in &segments {
        if segment.original.name == "__LINKEDIT" {
            output[segment.offset as usize..(segment.offset + linkedit_size) as usize]
                .copy_from_slice(&linkedit.bytes);
            continue;
        }
        if segment.original.file_size == 0 {
            continue;
        }
        let mut data = vec![0u8; segment.original.file_size as usize];
        cache
            .read_vm_region(segment.original.address, &mut data)
            .with_context(|| format!("read {} from split dyld cache", segment.original.name))?;
        let skip = if segment.original.name == "__TEXT" {
            text_first_section.max(load_end as u64) as usize
        } else {
            0
        };
        if skip > data.len() {
            bail!("Mach-O load commands exceed __TEXT data");
        }
        let start = segment.offset as usize + skip;
        output[start..start + data.len() - skip].copy_from_slice(&data[skip..]);
    }
    apply_slide(cache, &segments, &mut output)?;
    Ok(output)
}

fn first_section_offset(layout: &ImageLayout) -> Result<u64> {
    for command in &layout.load_commands {
        if command.kind != 0x19 {
            continue;
        }
        let raw = layout.command_bytes(*command);
        if &raw[8..14] != b"__TEXT" {
            continue;
        }
        let base = u64_at(raw, 24)?;
        let count = u32_at(raw, 64)? as usize;
        for index in 0..count {
            let section = 72 + index * 80;
            if u32_at(raw, section + 48)? != 0 {
                return u64_at(raw, section + 32)?
                    .checked_sub(base)
                    .context("TEXT section precedes segment");
            }
        }
    }
    Ok(0)
}

fn page_align(value: u64) -> Result<u64> {
    Ok(value
        .checked_add(PAGE_SIZE - 1)
        .context("page alignment overflow")?
        & !(PAGE_SIZE - 1))
}

fn apply_slide(
    cache: &mut SystemOsCache<'_>,
    segments: &[OutputSegment],
    output: &mut [u8],
) -> Result<()> {
    for segment in segments {
        let (suffix, mapping) = cache.mapping_for_address(segment.original.address)?;
        if mapping.slide_info_size == 0 {
            continue;
        }
        if mapping.slide_info_size < 24 {
            bail!("truncated dyld slide info");
        }
        let mut header = [0u8; 24];
        cache.read_member_at(&suffix, mapping.slide_info_offset, &mut header)?;
        if u32_at(&header, 0)? != 5 {
            bail!("unsupported dyld slide version");
        }
        let page_size = u32_at(&header, 4)? as u64;
        let page_count = u32_at(&header, 8)? as usize;
        let value_add = u64_at(&header, 16)?;
        if page_size == 0
            || page_count > 1_000_000
            || 24 + page_count * 2 > mapping.slide_info_size as usize
        {
            bail!("invalid dyld slide table");
        }
        let mut starts = vec![0u8; page_count * 2];
        cache.read_member_at(&suffix, mapping.slide_info_offset + 24, &mut starts)?;
        let first = (segment.original.address - mapping.address) / page_size;
        let end = (segment.original.address + segment.memory_size - mapping.address + page_size)
            / page_size;
        for page in first..end.min(page_count as u64) {
            let start = u16::from_le_bytes(
                starts[page as usize * 2..page as usize * 2 + 2]
                    .try_into()
                    .expect("two bytes"),
            );
            if start == 0xffff {
                continue;
            }
            let page_address = mapping.address + page * page_size;
            let page_offset = mapping.file_offset + page * page_size;
            let mut page_data = vec![0u8; page_size as usize];
            cache.read_member_at(&suffix, page_offset, &mut page_data)?;
            let mut offset = start as usize;
            for _ in 0..(1 << 16) {
                if offset + 8 > page_data.len() {
                    bail!("dyld slide chain escapes page");
                }
                let pointer = u64::from_le_bytes(
                    page_data[offset..offset + 8]
                        .try_into()
                        .expect("eight bytes"),
                );
                let target = if pointer == 0 {
                    0
                } else {
                    let mut target = pointer & ((1u64 << 34) - 1);
                    if pointer >> 63 == 0 {
                        target |= ((pointer >> 34) & 0xff) << 56;
                    }
                    value_add.wrapping_add(target)
                };
                let address = page_address + offset as u64;
                if let Some(file_offset) = output_offset(segments, address)
                    && file_offset + 8 <= output.len()
                {
                    output[file_offset..file_offset + 8].copy_from_slice(&target.to_le_bytes());
                }
                let next = ((pointer >> 52) & 0x7ff) as usize;
                if next == 0 {
                    break;
                }
                offset += next * 8;
            }
        }
    }
    Ok(())
}

fn output_offset(segments: &[OutputSegment], address: u64) -> Option<usize> {
    segments.iter().find_map(|segment| {
        let relative = address.checked_sub(segment.original.address)?;
        if relative < segment.file_size {
            Some((segment.offset + relative) as usize)
        } else {
            None
        }
    })
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("truncated Mach-O command")?
            .try_into()
            .expect("eight bytes"),
    ))
}

fn set_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    bytes
        .get_mut(offset..offset + 8)
        .context("truncated Mach-O command")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[derive(Clone)]
struct Symbol {
    name: Vec<u8>,
    kind: u8,
    section: u8,
    description: u16,
    value: u64,
}

pub struct LinkeditResult {
    pub bytes: Vec<u8>,
    pub original_symbols: usize,
    pub exported_symbols: usize,
    pub reexports: usize,
}

pub fn rebuild_linkedit(
    cache: &mut SystemOsCache<'_>,
    layout: &mut ImageLayout,
    linkedit_suffix: &str,
    linkedit_offset: u64,
    base_address: u64,
) -> Result<LinkeditResult> {
    let mut data = Vec::new();
    let mut exports = Vec::new();

    for kind in [
        LC_DYLD_EXPORTS_TRIE,
        LC_DATA_IN_CODE,
        LC_FUNCTION_STARTS,
        LC_FUNCTION_VARIANTS,
    ] {
        let Some(command) = first(layout, kind) else {
            continue;
        };
        let raw = layout.command_bytes(command);
        let old_offset = u32_at(raw, 8)? as u64;
        let length = u32_at(raw, 12)? as usize;
        if length > 16 << 20 {
            bail!("dyld linkedit payload exceeds limit");
        }
        let mut bytes = vec![0u8; length];
        if length != 0 {
            cache
                .read_member_at(linkedit_suffix, old_offset, &mut bytes)
                .with_context(|| format!("read linkedit payload {kind:#x}"))?;
        }
        if kind == LC_DYLD_EXPORTS_TRIE {
            exports = read_reexports(&bytes, base_address)?;
        }
        let new_offset = linkedit_offset
            .checked_add(data.len() as u64)
            .context("linkedit offset overflow")?;
        set_u32(&mut layout.commands, command.offset + 8, new_offset)?;
        data.extend_from_slice(&bytes);
        align_eight(&mut data);
    }

    let symtab = first(layout, LC_SYMTAB).context("dyld image lacks LC_SYMTAB")?;
    let dysymtab = first(layout, LC_DYSYMTAB).context("dyld image lacks LC_DYSYMTAB")?;
    let symtab_raw = layout.command_bytes(symtab);
    let symbol_offset = u32_at(symtab_raw, 8)? as u64;
    let symbol_count = u32_at(symtab_raw, 12)? as usize;
    let strings_offset = u32_at(symtab_raw, 16)? as u64;
    let strings_size = u32_at(symtab_raw, 20)? as u64;
    if symbol_count > MAX_SYMBOLS {
        bail!("dyld image has too many symbols");
    }
    let mut raw_symbols = vec![
        0u8;
        symbol_count
            .checked_mul(16)
            .context("symbol table size overflow")?
    ];
    cache.read_member_at(linkedit_suffix, symbol_offset, &mut raw_symbols)?;
    let mut name_offsets: Vec<u64> = raw_symbols
        .as_chunks::<16>()
        .0
        .iter()
        .map(|entry| u32::from_le_bytes(entry[..4].try_into().expect("four bytes")) as u64)
        .filter(|&offset| offset < strings_size)
        .collect();
    name_offsets.sort_unstable();
    name_offsets.dedup();
    let mut names_by_offset = HashMap::with_capacity(name_offsets.len());
    for offset in name_offsets {
        names_by_offset.insert(
            offset,
            read_symbol_name(cache, linkedit_suffix, strings_offset, strings_size, offset)?,
        );
    }
    let mut symbols = Vec::with_capacity(symbol_count + exports.len());
    for entry in raw_symbols.as_chunks::<16>().0 {
        let name_offset = u32_at(entry, 0)? as u64;
        let mut name = names_by_offset
            .get(&name_offset)
            .cloned()
            .unwrap_or_default();
        if name == b"<redacted>" {
            continue;
        }
        if name.first() == Some(&b'_') && name.contains(&b'.') {
            name.remove(0);
        }
        symbols.push(Symbol {
            name,
            kind: entry[4],
            section: entry[5],
            description: u16::from_le_bytes(entry[6..8].try_into().expect("two bytes")),
            value: u64::from_le_bytes(entry[8..16].try_into().expect("eight bytes")),
        });
    }
    let original_symbols = symbols.len();
    let reexports = exports.len();
    symbols.extend(exports);
    let mut locals = Vec::new();
    let mut extdefs = Vec::new();
    let mut undefs = Vec::new();
    for symbol in symbols {
        if symbol.kind & 1 == 0 {
            locals.push(symbol);
        } else if symbol.kind & 0x0e == 0 {
            undefs.push(symbol);
        } else {
            extdefs.push(symbol);
        }
    }
    let local_count = locals.len();
    let extdef_count = extdefs.len();
    let undef_count = undefs.len();
    let new_sym_offset = linkedit_offset + data.len() as u64;
    let mut names = vec![0u8];
    for symbol in locals.iter().chain(&extdefs).chain(&undefs) {
        let name_offset = u32::try_from(names.len()).context("symbol string pool exceeds u32")?;
        data.extend_from_slice(&name_offset.to_le_bytes());
        data.push(symbol.kind);
        data.push(symbol.section);
        data.extend_from_slice(&symbol.description.to_le_bytes());
        data.extend_from_slice(&symbol.value.to_le_bytes());
        names.extend_from_slice(&symbol.name);
        names.push(0);
    }
    align_eight(&mut data);
    let new_indirect_offset = linkedit_offset + data.len() as u64;
    let indirect_raw = layout.command_bytes(dysymtab);
    let indirect_offset = u32_at(indirect_raw, 56)? as u64;
    let indirect_count = u32_at(indirect_raw, 60)? as usize;
    if indirect_count > MAX_SYMBOLS {
        bail!("dyld image has too many indirect symbols");
    }
    let mut indirect = vec![
        0u8;
        indirect_count
            .checked_mul(4)
            .context("indirect table size overflow")?
    ];
    cache.read_member_at(linkedit_suffix, indirect_offset, &mut indirect)?;
    data.extend_from_slice(&indirect);
    align_eight(&mut data);
    let new_strings_offset = linkedit_offset + data.len() as u64;
    align_eight(&mut names);
    data.extend_from_slice(&names);

    set_u32(&mut layout.commands, symtab.offset + 8, new_sym_offset)?;
    set_u32(
        &mut layout.commands,
        symtab.offset + 12,
        (local_count + extdef_count + undef_count) as u64,
    )?;
    set_u32(&mut layout.commands, symtab.offset + 16, new_strings_offset)?;
    set_u32(&mut layout.commands, symtab.offset + 20, names.len() as u64)?;
    for (offset, value) in [
        (8, 0),
        (12, local_count),
        (16, local_count),
        (20, extdef_count),
        (24, local_count + extdef_count),
        (28, undef_count),
        (56, new_indirect_offset as usize),
        (60, indirect_count),
        (64, 0),
        (68, 0),
        (72, 0),
        (76, 0),
    ] {
        set_u32(&mut layout.commands, dysymtab.offset + offset, value as u64)?;
    }
    if let Some(command) = first(layout, LC_DATA_IN_CODE)
        && u32_at(layout.command_bytes(command), 12)? == 0
    {
        set_u32(&mut layout.commands, command.offset + 8, new_sym_offset)?;
    }
    Ok(LinkeditResult {
        bytes: data,
        original_symbols,
        exported_symbols: local_count + extdef_count + undef_count,
        reexports,
    })
}

fn first(layout: &ImageLayout, kind: u32) -> Option<LoadCommand> {
    layout
        .load_commands
        .iter()
        .find(|command| command.kind == kind)
        .copied()
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated Mach-O command")?
            .try_into()
            .expect("four bytes"),
    ))
}

fn set_u32(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let value = u32::try_from(value).context("Mach-O offset exceeds u32")?;
    bytes
        .get_mut(offset..offset + 4)
        .context("truncated Mach-O command")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align_eight(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().div_ceil(8) * 8, 0);
}

fn read_symbol_name(
    cache: &mut SystemOsCache<'_>,
    suffix: &str,
    strings_offset: u64,
    strings_size: u64,
    name_offset: u64,
) -> Result<Vec<u8>> {
    if name_offset >= strings_size {
        return Ok(Vec::new());
    }
    let length = (strings_size - name_offset).min(4096) as usize;
    let mut data = vec![0u8; length];
    cache.read_member_at(suffix, strings_offset + name_offset, &mut data)?;
    let end = data
        .iter()
        .position(|&byte| byte == 0)
        .context("unterminated dyld symbol")?;
    data.truncate(end);
    Ok(data)
}

fn read_reexports(input: &[u8], base: u64) -> Result<Vec<Symbol>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    let mut visited = std::collections::HashSet::new();
    walk_export_node(input, 0, Vec::new(), base, &mut visited, &mut output, 0)?;
    Ok(output)
}

fn walk_export_node(
    input: &[u8],
    at: usize,
    name: Vec<u8>,
    base: u64,
    visited: &mut std::collections::HashSet<usize>,
    output: &mut Vec<Symbol>,
    depth: usize,
) -> Result<()> {
    if depth > 4096 || output.len() > 100_000 || !visited.insert(at) {
        bail!("invalid dyld export trie graph");
    }
    let mut cursor = at;
    let terminal_size = read_uleb(input, &mut cursor)? as usize;
    let terminal_end = cursor
        .checked_add(terminal_size)
        .filter(|&end| end < input.len())
        .context("invalid dyld export terminal")?;
    if terminal_size != 0 {
        let flags = read_uleb(input, &mut cursor)?;
        let mut reexport_name = Vec::new();
        if flags == 8 {
            let _ordinal = read_uleb(input, &mut cursor)?;
            reexport_name = read_cstring(input, &mut cursor)?.to_vec();
        } else if flags == 0x10 {
            let _resolver = read_uleb(input, &mut cursor)?;
        }
        let mut value = read_uleb(input, &mut cursor)?;
        if (flags & 0x3 <= 1) && flags != 8 {
            value = value.checked_add(base).context("export address overflow")?;
        }
        if flags & 0x3 != 0 || flags == 8 {
            let mut encoded_name = name.clone();
            encoded_name.push(0);
            encoded_name.extend_from_slice(&reexport_name);
            output.push(Symbol {
                name: encoded_name,
                kind: 0x0b,
                section: 0,
                description: 0,
                value,
            });
        }
    }
    cursor = terminal_end;
    let children = *input
        .get(cursor)
        .context("missing dyld export child count")? as usize;
    cursor += 1;
    for _ in 0..children {
        let edge = read_cstring(input, &mut cursor)?;
        let child = read_uleb(input, &mut cursor)? as usize;
        let mut child_name = name.clone();
        child_name.extend_from_slice(edge);
        walk_export_node(input, child, child_name, base, visited, output, depth + 1)?;
    }
    visited.remove(&at);
    Ok(())
}

fn read_uleb(input: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input.get(*cursor).context("truncated dyld ULEB128")?;
        *cursor += 1;
        result |= ((byte & 0x7f) as u64)
            .checked_shl(shift)
            .context("dyld ULEB128 overflow")?;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    bail!("dyld ULEB128 is too long")
}

fn read_cstring<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let tail = input.get(*cursor..).context("invalid dyld string offset")?;
    let end = tail
        .iter()
        .position(|&byte| byte == 0)
        .context("unterminated dyld string")?;
    *cursor += end + 1;
    Ok(&tail[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_reexport_node() {
        // Root terminal: re-export "foo" from ordinal 1, followed by no children.
        let trie = [8, 8, 1, b'f', b'o', b'o', 0, 0, 0, 0];
        let symbols = read_reexports(&trie, 0x1000).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, b"\0foo");
    }
}
