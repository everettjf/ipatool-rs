//! Random access to APFS type-14 (LZBITMAP) resource-fork compression.

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Seek, SeekFrom},
};

use anyhow::{Context, Result, bail};

use crate::lzbitmap;

const BLOCK_SIZE: u64 = 65_536;
const MAX_CACHED_BLOCKS: usize = 128;

pub struct LzBitmapForkReader<R: Read + Seek> {
    source: R,
    size: u64,
    position: u64,
    offsets: Vec<u32>,
    cache: HashMap<usize, Vec<u8>>,
    cache_order: VecDeque<usize>,
}

impl<R: Read + Seek> LzBitmapForkReader<R> {
    pub fn open(mut source: R, output_size: u64) -> Result<Self> {
        let source_size = source.seek(SeekFrom::End(0))?;
        if source_size < 8 || output_size == 0 {
            bail!("invalid LZBITMAP resource fork size");
        }
        source.seek(SeekFrom::Start(0))?;
        let mut first = [0u8; 4];
        source.read_exact(&mut first)?;
        let table_size = u32::from_le_bytes(first) as u64;
        let block_count = output_size.div_ceil(BLOCK_SIZE);
        let expected_table_size = (block_count + 1)
            .checked_mul(4)
            .context("LZBITMAP index size overflow")?;
        if table_size != expected_table_size || table_size > source_size {
            bail!("LZBITMAP index has size {table_size}, expected {expected_table_size}");
        }
        let mut table = vec![0u8; table_size as usize];
        table[..4].copy_from_slice(&first);
        source.read_exact(&mut table[4..])?;
        let offsets: Vec<u32> = table
            .as_chunks::<4>()
            .0
            .iter()
            .map(|bytes| u32::from_le_bytes(*bytes))
            .collect();
        for (index, pair) in offsets.windows(2).enumerate() {
            let start = pair[0] as u64;
            let end = pair[1] as u64;
            if start < table_size
                || end <= start
                || end > source_size
                || end - start > BLOCK_SIZE + 1
            {
                bail!("LZBITMAP block {index} has invalid range {start}..{end}");
            }
        }
        if *offsets.last().expect("nonempty index") as u64 != source_size {
            bail!("LZBITMAP index does not cover the resource fork");
        }
        Ok(Self {
            source,
            size: output_size,
            position: 0,
            offsets,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    fn block(&mut self, index: usize) -> Result<&[u8]> {
        if !self.cache.contains_key(&index) {
            let start = self.offsets[index] as u64;
            let end = self.offsets[index + 1] as u64;
            let mut compressed = vec![0u8; (end - start) as usize];
            self.source.seek(SeekFrom::Start(start))?;
            self.source.read_exact(&mut compressed)?;
            let expected = (self.size - index as u64 * BLOCK_SIZE).min(BLOCK_SIZE) as usize;
            let plain = if compressed.first() == Some(&0xff) {
                compressed[1..].to_vec()
            } else {
                lzbitmap::decompress(&compressed, expected)
                    .with_context(|| format!("decode LZBITMAP block {index}"))?
            };
            if plain.len() != expected {
                bail!(
                    "LZBITMAP block {index} has size {}, expected {expected}",
                    plain.len()
                );
            }
            if self.cache_order.len() == MAX_CACHED_BLOCKS {
                let evicted = self.cache_order.pop_front().expect("nonempty cache");
                self.cache.remove(&evicted);
            }
            self.cache.insert(index, plain);
            self.cache_order.push_back(index);
        }
        Ok(&self.cache[&index])
    }
}

impl<R: Read + Seek> Read for LzBitmapForkReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let wanted = out
            .len()
            .min(self.size.saturating_sub(self.position) as usize);
        let mut written = 0;
        while written < wanted {
            let index = (self.position / BLOCK_SIZE) as usize;
            let offset = (self.position % BLOCK_SIZE) as usize;
            let block = self.block(index).map_err(io::Error::other)?;
            let count = (wanted - written).min(block.len() - offset);
            out[written..written + count].copy_from_slice(&block[offset..offset + count]);
            written += count;
            self.position += count as u64;
        }
        Ok(written)
    }
}

impl<R: Read + Seek> Seek for LzBitmapForkReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(value) => value as i128,
            SeekFrom::Current(value) => self.position as i128 + value as i128,
            SeekFrom::End(value) => self.size as i128 + value as i128,
        };
        if !(0..=u64::MAX as i128).contains(&next) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid LZBITMAP seek",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_stored_block_and_rejects_bad_index() {
        let bytes = [
            8u32.to_le_bytes().as_slice(),
            12u32.to_le_bytes().as_slice(),
            b"\xffabc",
        ]
        .concat();
        let mut reader = LzBitmapForkReader::open(Cursor::new(bytes.clone()), 3).unwrap();
        let mut out = [0u8; 2];
        reader.seek(SeekFrom::Start(1)).unwrap();
        reader.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"bc");
        reader.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(reader.read(&mut out).unwrap(), 2);
        assert_eq!(&out, b"ab");
        assert!(LzBitmapForkReader::open(Cursor::new(bytes), 65_537).is_err());
    }
}
