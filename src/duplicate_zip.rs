//! Read ZIP members and preserve central-directory filename bytes as Go does.

use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use async_zip::base::read::seek::ZipFileReader;
use futures_util::io::AllowStdIo;

pub(crate) fn read_matching_entries(
    path: &Path,
    include: impl Fn(&str) -> bool,
) -> Result<Vec<(String, Vec<u8>)>> {
    let file = File::open(path).with_context(|| format!("open IPA: {}", path.display()))?;
    futures_lite::future::block_on(async {
        let source = AllowStdIo::new(BufReader::new(file));
        let mut reader = ZipFileReader::new(source)
            .await
            .context("open IPA ZIP archive with duplicate names")?;
        let mut entries = Vec::new();
        for index in 0..reader.file().entries().len() {
            let filename = reader.file().entries()[index].filename();
            let name = String::from_utf8_lossy(
                filename
                    .alternative()
                    .unwrap_or_else(|| filename.as_bytes()),
            )
            .into_owned();
            if !include(&name) {
                continue;
            }
            let mut data = Vec::new();
            reader
                .reader_with_entry(index)
                .await
                .with_context(|| format!("open IPA ZIP member {name}"))?
                .read_to_end_checked(&mut data)
                .await
                .with_context(|| format!("read IPA ZIP member {name}"))?;
            entries.push((name, data));
        }
        Ok(entries)
    })
}

/// zip's `name_raw()` can contain an Info-ZIP UnicodePath replacement. Go's
/// archive/zip instead exposes the bytes from the central directory filename.
pub(crate) fn read_raw_central_name<R: Read + Seek>(
    source: &mut R,
    offset: u64,
) -> Result<Vec<u8>> {
    source.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 46];
    source.read_exact(&mut header)?;
    ensure!(
        header[..4] == [0x50, 0x4b, 0x01, 0x02],
        "invalid IPA ZIP central header"
    );
    let name_length = u16::from_le_bytes([header[28], header[29]]) as usize;
    let mut name = vec![0u8; name_length];
    source.read_exact(&mut name)?;
    Ok(name)
}

#[cfg(test)]
pub(crate) fn write_duplicate_sinf_fixture(path: &Path, first: &[u8], second: &[u8]) {
    use std::{fs, io::Write};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    const FIRST: &[u8] = b"Payload/A.app/SC_Info/A.sinf";
    const SECOND: &[u8] = b"Payload/A.app/SC_Info/B.sinf";
    let mut writer = ZipWriter::new(File::create(path).unwrap());
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    writer
        .start_file(std::str::from_utf8(FIRST).unwrap(), options)
        .unwrap();
    writer.write_all(first).unwrap();
    writer
        .start_file(std::str::from_utf8(SECOND).unwrap(), options)
        .unwrap();
    writer.write_all(second).unwrap();
    writer.finish().unwrap();
    let mut bytes = fs::read(path).unwrap();
    let mut replaced = 0;
    for offset in 0..=bytes.len() - SECOND.len() {
        if &bytes[offset..offset + SECOND.len()] == SECOND {
            bytes[offset..offset + FIRST.len()].copy_from_slice(FIRST);
            replaced += 1;
        }
    }
    assert_eq!(replaced, 2);
    fs::write(path, bytes).unwrap();
}

#[cfg(test)]
pub(crate) fn replace_fixture_filename_bytes(path: &Path, from: &[u8], to: &[u8]) {
    use std::fs;

    assert_eq!(from.len(), to.len());
    let mut bytes = fs::read(path).unwrap();
    let mut replaced = 0;
    for offset in 0..=bytes.len() - from.len() {
        if &bytes[offset..offset + from.len()] == from {
            bytes[offset..offset + to.len()].copy_from_slice(to);
            replaced += 1;
        }
    }
    assert_eq!(replaced, 2); // local and central directory names
    fs::write(path, bytes).unwrap();
}

#[cfg(test)]
pub(crate) fn write_unicode_path_fixture(path: &Path, contents: &[u8]) {
    write_unicode_path_member_fixture(
        path,
        "Payload/A.app/SC_Info/A.sinf",
        "Payload/B.app/SC_Info/B.sinf",
        0x55bc_8223,
        contents,
    );
}

#[cfg(test)]
pub(crate) fn write_unicode_path_member_fixture(
    path: &Path,
    name: &str,
    alias: &str,
    name_crc32: u32,
    contents: &[u8],
) {
    use std::io::Write;
    use zip::{ZipWriter, write::FullFileOptions};

    let mut options = FullFileOptions::default();
    let mut unicode_path = vec![1];
    unicode_path.extend_from_slice(&name_crc32.to_le_bytes());
    unicode_path.extend_from_slice(alias.as_bytes());
    options.add_extra_field(0x7075, unicode_path, true).unwrap();
    let mut writer = ZipWriter::new(File::create(path).unwrap());
    writer.start_file(name, options).unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap();
}
