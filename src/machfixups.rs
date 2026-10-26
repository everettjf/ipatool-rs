//! Decode arm64e userland chained fixups from a Mach-O linkedit command.

use anyhow::{Context, Result, bail};

const ARM64E_USERLAND24: u16 = 12;
const IMPORT_FORMAT: u32 = 1;
const IMPORT_ADDEND_FORMAT: u32 = 2;
const START_NONE: u16 = 0xffff;
const START_MULTI: u16 = 0x8000;
const MAX_IMPORTS: usize = 1 << 20;
const MAX_SEGMENTS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixupKind {
    Rebase { target: u64 },
    Bind { name: String, addend: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixup {
    pub file_offset: u64,
    pub kind: FixupKind,
}

#[derive(Debug, Clone)]
struct Import {
    name: String,
    addend: i64,
}

/// Parse `LC_DYLD_CHAINED_FIXUPS` in the selected 64-bit arm64e Mach-O slice.
pub fn parse(data: &[u8], payload_offset: u32, payload_size: u32) -> Result<Vec<Fixup>> {
    let payload = range(data, payload_offset as usize, payload_size as usize)?;
    if payload.len() < 28 {
        bail!("chained-fixups header is truncated");
    }
    let version = u32_at(payload, 0)?;
    let starts_offset = u32_at(payload, 4)? as usize;
    let imports_offset = u32_at(payload, 8)? as usize;
    let symbols_offset = u32_at(payload, 12)? as usize;
    let imports_count = u32_at(payload, 16)? as usize;
    let imports_format = u32_at(payload, 20)?;
    let symbols_format = u32_at(payload, 24)?;
    if version != 0
        || !matches!(imports_format, IMPORT_FORMAT | IMPORT_ADDEND_FORMAT)
        || symbols_format != 0
    {
        bail!("unsupported chained-fixups metadata format");
    }
    if imports_count > MAX_IMPORTS {
        bail!("too many chained imports");
    }
    let imports = parse_imports(
        payload,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
    )?;
    let segment_count = u32_at(payload, starts_offset)? as usize;
    if segment_count > MAX_SEGMENTS {
        bail!("too many chained-fixups segments");
    }
    let offsets = range(
        payload,
        starts_offset + 4,
        segment_count
            .checked_mul(4)
            .context("segment table overflow")?,
    )?;
    let mut fixups = Vec::new();
    for (segment_index, raw_offset) in offsets.as_chunks::<4>().0.iter().enumerate() {
        let relative = u32::from_le_bytes(*raw_offset) as usize;
        if relative == 0 {
            continue;
        }
        let start = starts_offset
            .checked_add(relative)
            .context("segment start overflow")?;
        let segment_size = u32_at(payload, start)? as usize;
        let segment = range(payload, start, segment_size)?;
        if segment.len() < 22 {
            bail!("chained-fixups segment {segment_index} is truncated");
        }
        let page_size = u16_at(segment, 4)? as usize;
        let pointer_format = u16_at(segment, 6)?;
        let segment_offset = u64_at(segment, 8)?;
        let page_count = u16_at(segment, 20)? as usize;
        if pointer_format != ARM64E_USERLAND24 || page_size == 0 {
            bail!("unsupported chained pointer format {pointer_format} in segment {segment_index}");
        }
        let start_bytes = range(
            segment,
            22,
            page_count.checked_mul(2).context("page count overflow")?,
        )?;
        for (page_index, start_bytes) in start_bytes.as_chunks::<2>().0.iter().enumerate() {
            let page_start = u16::from_le_bytes(*start_bytes);
            if page_start == START_NONE {
                continue;
            }
            if page_start & START_MULTI != 0 {
                let mut extra_index = (page_start & !START_MULTI) as usize;
                loop {
                    let entry = u16_at(
                        segment,
                        22 + extra_index.checked_mul(2).context("chain start overflow")?,
                    )?;
                    walk_chain(
                        data,
                        segment_offset,
                        page_index,
                        page_size,
                        (entry & !START_MULTI) as usize,
                        &imports,
                        &mut fixups,
                    )?;
                    extra_index += 1;
                    if entry & START_MULTI != 0 {
                        break;
                    }
                    if extra_index > segment_size / 2 {
                        bail!("unterminated chained page starts");
                    }
                }
            } else {
                walk_chain(
                    data,
                    segment_offset,
                    page_index,
                    page_size,
                    page_start as usize,
                    &imports,
                    &mut fixups,
                )?;
            }
        }
    }
    Ok(fixups)
}

fn parse_imports(
    payload: &[u8],
    imports_offset: usize,
    symbols_offset: usize,
    count: usize,
    format: u32,
) -> Result<Vec<Import>> {
    let stride = if format == IMPORT_ADDEND_FORMAT { 8 } else { 4 };
    let bytes = range(
        payload,
        imports_offset,
        count.checked_mul(stride).context("import table overflow")?,
    )?;
    let strings = payload
        .get(symbols_offset..)
        .context("chained symbol pool exceeds payload")?;
    let mut imports = Vec::with_capacity(count);
    for entry in bytes.chunks_exact(stride) {
        let encoded = u32::from_le_bytes(entry[..4].try_into()?);
        let name_offset = (encoded >> 9) as usize;
        let tail = strings
            .get(name_offset..)
            .context("chained import name exceeds pool")?;
        let end = tail
            .iter()
            .position(|&byte| byte == 0)
            .context("unterminated chained import name")?;
        imports.push(Import {
            name: String::from_utf8(tail[..end].to_vec()).context("invalid chained import name")?,
            addend: if stride == 8 {
                i32::from_le_bytes(entry[4..8].try_into()?) as i64
            } else {
                0
            },
        });
    }
    Ok(imports)
}

fn walk_chain(
    data: &[u8],
    segment_offset: u64,
    page_index: usize,
    page_size: usize,
    start: usize,
    imports: &[Import],
    fixups: &mut Vec<Fixup>,
) -> Result<()> {
    if start >= page_size {
        bail!("chained pointer starts outside its page");
    }
    let page_base = segment_offset
        .checked_add(
            (page_index as u64)
                .checked_mul(page_size as u64)
                .context("chained page overflow")?,
        )
        .context("chained page overflow")?;
    let mut offset = start;
    for _ in 0..=page_size / 8 {
        if offset.checked_add(8).is_none_or(|end| end > page_size) {
            bail!("chained pointer leaves its page");
        }
        let file_offset = page_base
            .checked_add(offset as u64)
            .context("chained pointer offset overflow")?;
        let raw = u64_at(
            data,
            usize::try_from(file_offset).context("chained file offset overflow")?,
        )?;
        let bound = raw >> 62 & 1 != 0;
        let authenticated = raw >> 63 != 0;
        let kind = if bound {
            let ordinal = (raw & 0x00ff_ffff) as usize;
            let import = imports
                .get(ordinal)
                .with_context(|| format!("chained import ordinal {ordinal} is invalid"))?;
            let pointer_addend = if authenticated {
                0
            } else {
                let encoded = ((raw >> 32) & 0x7ffff) as i64;
                if encoded & 0x40000 != 0 {
                    encoded | !0x7ffff
                } else {
                    encoded
                }
            };
            let addend = import
                .addend
                .checked_add(pointer_addend)
                .context("chained import addend overflows")?;
            FixupKind::Bind {
                name: import.name.clone(),
                addend,
            }
        } else {
            let target = if authenticated {
                raw & 0xffff_ffff
            } else {
                raw & ((1u64 << 43) - 1)
            };
            FixupKind::Rebase { target }
        };
        fixups.push(Fixup { file_offset, kind });
        let next = ((raw >> 51) & 0x7ff) as usize;
        if next == 0 {
            return Ok(());
        }
        offset = offset
            .checked_add(next * 8)
            .context("chained pointer step overflow")?;
    }
    bail!("chained pointer loop exceeds page")
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .context("chained range overflow")?,
        )
        .context("chained range exceeds data")
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(bytes, offset, 2)?.try_into().expect("two bytes"),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_metadata() {
        assert!(parse(&[0; 20], 0, 20).is_err());
    }

    #[test]
    fn decodes_authentication_and_signed_addend() {
        let mut data = vec![0u8; 512];
        let payload = 128usize;
        data[payload + 4..payload + 8].copy_from_slice(&32u32.to_le_bytes());
        data[payload + 8..payload + 12].copy_from_slice(&64u32.to_le_bytes());
        data[payload + 12..payload + 16].copy_from_slice(&68u32.to_le_bytes());
        data[payload + 16..payload + 20].copy_from_slice(&1u32.to_le_bytes());
        data[payload + 20..payload + 24].copy_from_slice(&1u32.to_le_bytes());
        data[payload + 32..payload + 36].copy_from_slice(&1u32.to_le_bytes());
        data[payload + 36..payload + 40].copy_from_slice(&8u32.to_le_bytes());
        let start = payload + 40;
        data[start..start + 4].copy_from_slice(&24u32.to_le_bytes());
        data[start + 4..start + 6].copy_from_slice(&64u16.to_le_bytes());
        data[start + 6..start + 8].copy_from_slice(&12u16.to_le_bytes());
        data[start + 20..start + 22].copy_from_slice(&1u16.to_le_bytes());
        data[payload + 68..payload + 73].copy_from_slice(b"name\0");
        let raw = (1u64 << 62) | (0x7ffffu64 << 32);
        data[..8].copy_from_slice(&raw.to_le_bytes());
        let result = parse(&data, payload as u32, 80).unwrap();
        assert_eq!(
            result,
            vec![Fixup {
                file_offset: 0,
                kind: FixupKind::Bind {
                    name: "name".into(),
                    addend: -1
                }
            }]
        );
    }

    #[test]
    fn combines_import_addend_with_pointer_addend() {
        let mut data = vec![0u8; 512];
        let payload = 128usize;
        data[payload + 4..payload + 8].copy_from_slice(&32u32.to_le_bytes());
        data[payload + 8..payload + 12].copy_from_slice(&64u32.to_le_bytes());
        data[payload + 12..payload + 16].copy_from_slice(&72u32.to_le_bytes());
        data[payload + 16..payload + 20].copy_from_slice(&1u32.to_le_bytes());
        data[payload + 20..payload + 24].copy_from_slice(&2u32.to_le_bytes());
        data[payload + 32..payload + 36].copy_from_slice(&1u32.to_le_bytes());
        data[payload + 36..payload + 40].copy_from_slice(&8u32.to_le_bytes());
        let start = payload + 40;
        data[start..start + 4].copy_from_slice(&24u32.to_le_bytes());
        data[start + 4..start + 6].copy_from_slice(&64u16.to_le_bytes());
        data[start + 6..start + 8].copy_from_slice(&12u16.to_le_bytes());
        data[start + 20..start + 22].copy_from_slice(&1u16.to_le_bytes());
        data[payload + 68..payload + 72].copy_from_slice(&(-7i32).to_le_bytes());
        data[payload + 72..payload + 77].copy_from_slice(b"name\0");
        data[..8].copy_from_slice(&((1u64 << 62) | (5u64 << 32)).to_le_bytes());
        assert_eq!(
            parse(&data, payload as u32, 84).unwrap(),
            vec![Fixup {
                file_offset: 0,
                kind: FixupKind::Bind {
                    name: "name".into(),
                    addend: -2,
                },
            }]
        );
    }
}
