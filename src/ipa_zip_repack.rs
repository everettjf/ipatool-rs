//! Copy IPA ZIP members without decompressing them, rebuilding their headers for streaming readers.

use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use anyhow::{Context, Result, ensure};
use zip::ZipArchive;

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;
const ZIP64_EXTRA: u16 = 1;

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn append_extra(extra: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "ZIP64 extra field is too large"
    );
    extra.extend_from_slice(&ZIP64_EXTRA.to_le_bytes());
    extra.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    extra.extend_from_slice(payload);
    Ok(())
}

fn without_zip64(extra: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(extra.len());
    let mut rest = extra;
    while !rest.is_empty() {
        ensure!(rest.len() >= 4, "truncated ZIP extra field");
        let size = u16_at(rest, 2) as usize + 4;
        ensure!(size <= rest.len(), "invalid ZIP extra field length");
        if u16_at(rest, 0) != ZIP64_EXTRA {
            result.extend_from_slice(&rest[..size]);
        }
        rest = &rest[size..];
    }
    Ok(result)
}

fn checked_len(len: usize, what: &str) -> Result<u16> {
    u16::try_from(len).with_context(|| format!("{what} is too long for ZIP"))
}

fn copy_member(
    archive: &mut ZipArchive<File>,
    source: &mut File,
    output: &mut File,
    central_records: &mut Vec<u8>,
    index: usize,
) -> Result<()> {
    let entry = archive
        .by_index_raw(index)
        .context("inspect IPA ZIP member")?;
    let name = entry.name_raw();
    let compressed = entry.compressed_size();
    let uncompressed = entry.size();
    let crc = entry.crc32();
    let data_start = entry.data_start().context("locate IPA ZIP member data")?;
    let mut local = [0u8; 30];
    source.seek(SeekFrom::Start(entry.header_start()))?;
    source.read_exact(&mut local)?;
    ensure!(u32_at(&local, 0) == LOCAL, "invalid IPA ZIP local header");
    let local_name_len = u16_at(&local, 26) as usize;
    let local_extra_len = u16_at(&local, 28) as usize;
    let mut local_metadata = vec![0; local_name_len + local_extra_len];
    source.read_exact(&mut local_metadata)?;
    ensure!(
        local_metadata[..local_name_len] == *name,
        "IPA ZIP local name mismatch"
    );
    ensure!(
        entry.header_start() + 30 + local_metadata.len() as u64 == data_start,
        "IPA ZIP data offset mismatch"
    );

    let mut central = [0u8; 46];
    source.seek(SeekFrom::Start(entry.central_header_start()))?;
    source.read_exact(&mut central)?;
    ensure!(
        u32_at(&central, 0) == CENTRAL,
        "invalid IPA ZIP central header"
    );
    let central_name_len = u16_at(&central, 28) as usize;
    let central_extra_len = u16_at(&central, 30) as usize;
    let comment_len = u16_at(&central, 32) as usize;
    let mut central_metadata = vec![0; central_name_len + central_extra_len + comment_len];
    source.read_exact(&mut central_metadata)?;
    ensure!(
        central_metadata[..central_name_len] == *name,
        "IPA ZIP central name mismatch"
    );

    let is_stored = u16_at(&central, 10) == 0 || name.ends_with(b"/");
    let is_deflated = u16_at(&central, 10) == 8 && !name.ends_with(b"/");
    let mut flags = u16_at(&central, 8);
    ensure!(flags & 1 == 0, "ZIP-encrypted IPA members are unsupported");
    if is_stored {
        flags &= !8;
    } else if is_deflated {
        flags |= 8;
    }
    let uses_descriptor = flags & 8 != 0;
    put16(&mut local, 6, flags);
    put16(&mut central, 8, flags);

    let large_size = compressed >= u32::MAX as u64 || uncompressed >= u32::MAX as u64;
    let mut local_extra = without_zip64(&local_metadata[local_name_len..])?;
    if large_size {
        let mut sizes = Vec::with_capacity(16);
        if uses_descriptor {
            sizes.extend_from_slice(&0u64.to_le_bytes());
            sizes.extend_from_slice(&0u64.to_le_bytes());
        } else {
            sizes.extend_from_slice(&uncompressed.to_le_bytes());
            sizes.extend_from_slice(&compressed.to_le_bytes());
        }
        append_extra(&mut local_extra, &sizes)?;
        let version = u16_at(&local, 4).max(45);
        put16(&mut local, 4, version);
    }
    put16(
        &mut local,
        28,
        checked_len(local_extra.len(), "local extra")?,
    );
    if uses_descriptor {
        put32(&mut local, 14, 0);
        put32(&mut local, 18, if large_size { u32::MAX } else { 0 });
        put32(&mut local, 22, if large_size { u32::MAX } else { 0 });
    } else {
        put32(&mut local, 14, crc);
        put32(&mut local, 18, compressed.min(u32::MAX as u64) as u32);
        put32(&mut local, 22, uncompressed.min(u32::MAX as u64) as u32);
    }

    let offset = output.stream_position()?;
    output.write_all(&local)?;
    output.write_all(name)?;
    output.write_all(&local_extra)?;
    source.seek(SeekFrom::Start(data_start))?;
    let copied = io::copy(&mut source.take(compressed), output)?;
    ensure!(copied == compressed, "truncated IPA ZIP member");
    if uses_descriptor {
        output.write_all(&DESCRIPTOR.to_le_bytes())?;
        output.write_all(&crc.to_le_bytes())?;
        if large_size {
            output.write_all(&compressed.to_le_bytes())?;
            output.write_all(&uncompressed.to_le_bytes())?;
        } else {
            output.write_all(&(compressed as u32).to_le_bytes())?;
            output.write_all(&(uncompressed as u32).to_le_bytes())?;
        }
    }

    let mut central_extra =
        without_zip64(&central_metadata[central_name_len..central_name_len + central_extra_len])?;
    let large_uncompressed = uncompressed >= u32::MAX as u64;
    let large_compressed = compressed >= u32::MAX as u64;
    let large_offset = offset >= u32::MAX as u64;
    let mut zip64 = Vec::new();
    if large_uncompressed {
        zip64.extend_from_slice(&uncompressed.to_le_bytes());
    }
    if large_compressed {
        zip64.extend_from_slice(&compressed.to_le_bytes());
    }
    if large_offset {
        zip64.extend_from_slice(&offset.to_le_bytes());
    }
    if !zip64.is_empty() {
        append_extra(&mut central_extra, &zip64)?;
        let needed = u16_at(&central, 6).max(45);
        let made_by = u16_at(&central, 4).max(45);
        put16(&mut central, 6, needed);
        put16(&mut central, 4, made_by);
    }
    put16(
        &mut central,
        30,
        checked_len(central_extra.len(), "central extra")?,
    );
    put32(&mut central, 16, crc);
    put32(&mut central, 20, compressed.min(u32::MAX as u64) as u32);
    put32(&mut central, 24, uncompressed.min(u32::MAX as u64) as u32);
    put32(&mut central, 42, offset.min(u32::MAX as u64) as u32);
    central_records.extend_from_slice(&central);
    central_records.extend_from_slice(name);
    central_records.extend_from_slice(&central_extra);
    central_records.extend_from_slice(&central_metadata[central_name_len + central_extra_len..]);
    Ok(())
}

/// Build a fresh ZIP from source members and a ZIP of replacement members.
/// A replacement with the same raw member name supersedes every source copy.
pub(crate) fn repack(source: &File, replacements: &File, output: &mut File) -> Result<()> {
    let mut source_file = source.try_clone()?;
    let mut replacement_file = replacements.try_clone()?;
    let mut source_archive = ZipArchive::new(source.try_clone()?)?;
    let mut replacement_archive = ZipArchive::new(replacements.try_clone()?)?;
    let replacement_names: HashSet<Vec<u8>> = replacement_archive
        .file_names_raw()
        .map(ToOwned::to_owned)
        .collect();
    let mut central_records = Vec::new();
    let mut count = 0u64;
    for index in 0..source_archive.len() {
        if replacement_names.contains(source_archive.by_index_raw(index)?.name_raw()) {
            continue;
        }
        copy_member(
            &mut source_archive,
            &mut source_file,
            output,
            &mut central_records,
            index,
        )?;
        count += 1;
    }
    for index in 0..replacement_archive.len() {
        copy_member(
            &mut replacement_archive,
            &mut replacement_file,
            output,
            &mut central_records,
            index,
        )?;
        count += 1;
    }
    let central_offset = output.stream_position()?;
    output.write_all(&central_records)?;
    let central_size = central_records.len() as u64;
    let comment = source_archive.comment();
    let comment_len = checked_len(comment.len(), "archive comment")?;
    let needs_zip64 = count >= u16::MAX as u64
        || central_size >= u32::MAX as u64
        || central_offset >= u32::MAX as u64;
    if needs_zip64 {
        let end64_offset = output.stream_position()?;
        output.write_all(&END64.to_le_bytes())?;
        output.write_all(&44u64.to_le_bytes())?;
        output.write_all(&45u16.to_le_bytes())?;
        output.write_all(&45u16.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&count.to_le_bytes())?;
        output.write_all(&count.to_le_bytes())?;
        output.write_all(&central_size.to_le_bytes())?;
        output.write_all(&central_offset.to_le_bytes())?;
        output.write_all(&LOCATOR64.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&end64_offset.to_le_bytes())?;
        output.write_all(&1u32.to_le_bytes())?;
    }
    output.write_all(&END.to_le_bytes())?;
    output.write_all(&0u16.to_le_bytes())?;
    output.write_all(&0u16.to_le_bytes())?;
    output.write_all(&(count.min(u16::MAX as u64) as u16).to_le_bytes())?;
    output.write_all(&(count.min(u16::MAX as u64) as u16).to_le_bytes())?;
    output.write_all(&(central_size.min(u32::MAX as u64) as u32).to_le_bytes())?;
    output.write_all(&(central_offset.min(u32::MAX as u64) as u32).to_le_bytes())?;
    output.write_all(&comment_len.to_le_bytes())?;
    output.write_all(comment)?;
    Ok(())
}
