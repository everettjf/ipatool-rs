//! Read ZIP members in central-directory order when duplicate names are present.

use std::{fs::File, io::BufReader, path::Path};

use anyhow::{Context, Result};
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
            let name =
                String::from_utf8_lossy(reader.file().entries()[index].filename().as_bytes())
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
