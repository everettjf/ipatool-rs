//! Stream the byte-addressed Python protocol-5 checkpoints emitted by the
//! original FairPlay tracer. Deserializing their `memory` dictionary as
//! ordinary pickle values can require several GiB for a much smaller image.

use std::{collections::HashMap, io::Read};

use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

const PAGE_BYTES: usize = 4096;
const MAX_PAGES: usize = 65_536;
const MAX_STACK: usize = 4096;
const MAX_MEMO: usize = 100_000;
const MAX_STRING: usize = 1024 * 1024;

pub struct SparsePage {
    bytes: Box<[u8; PAGE_BYTES]>,
    present: Box<[u64; PAGE_BYTES / 64]>,
}

impl SparsePage {
    fn new() -> Self {
        Self {
            bytes: Box::new([0; PAGE_BYTES]),
            present: Box::new([0; PAGE_BYTES / 64]),
        }
    }

    pub fn insert(&mut self, offset: usize, value: u8) -> Result<()> {
        let bit = 1u64 << (offset % 64);
        let word = &mut self.present[offset / 64];
        if *word & bit != 0 {
            bail!("checkpoint memory contains a repeated address");
        }
        *word |= bit;
        self.bytes[offset] = value;
        Ok(())
    }

    pub fn read(&self, offset: usize) -> Result<u8> {
        if self.present[offset / 64] & (1u64 << (offset % 64)) == 0 {
            bail!("checkpoint does not cover requested address");
        }
        Ok(self.bytes[offset])
    }
}

impl Drop for SparsePage {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.present.zeroize();
    }
}

pub struct Schema1Checkpoint {
    pub binary_hash: [u8; 32],
    pub registers: HashMap<String, u64>,
    pub pages: HashMap<u64, SparsePage>,
}

impl Drop for Schema1Checkpoint {
    fn drop(&mut self) {
        self.binary_hash.zeroize();
        for value in self.registers.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Clone, Copy)]
enum MapKind {
    Root,
    Registers,
    Memory,
    Other,
}

#[derive(Clone)]
enum Slot {
    Mark,
    Map(MapKind),
    List,
    Int(i128),
    Text(String),
    Other,
}

struct Parser<R> {
    reader: R,
    stack: Vec<Slot>,
    memo: Vec<Slot>,
    schema: Option<i128>,
    hash: Option<String>,
    registers: HashMap<String, u64>,
    pages: HashMap<u64, SparsePage>,
    memory_entries: usize,
}

impl<R: Read> Parser<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            stack: Vec::new(),
            memo: Vec::new(),
            schema: None,
            hash: None,
            registers: HashMap::new(),
            pages: HashMap::new(),
            memory_entries: 0,
        }
    }

    fn byte(&mut self) -> Result<u8> {
        let mut byte = [0];
        self.reader
            .read_exact(&mut byte)
            .context("truncated checkpoint pickle")?;
        Ok(byte[0])
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.reader
            .read_exact(&mut bytes)
            .context("truncated checkpoint pickle")?;
        Ok(bytes)
    }

    fn text(&mut self, length: usize) -> Result<String> {
        if length > MAX_STRING {
            bail!("checkpoint pickle string exceeds limit");
        }
        let mut bytes = vec![0; length];
        self.reader.read_exact(&mut bytes)?;
        String::from_utf8(bytes).context("checkpoint pickle contains invalid UTF-8")
    }

    fn skip(&mut self, length: u64) -> Result<()> {
        if length > 64 * 1024 * 1024 {
            bail!("checkpoint pickle byte string exceeds limit");
        }
        let copied = std::io::copy(&mut self.reader.by_ref().take(length), &mut std::io::sink())?;
        if copied != length {
            bail!("truncated checkpoint pickle byte string");
        }
        Ok(())
    }

    fn long(&mut self, length: usize) -> Result<Option<i128>> {
        if length > 32 {
            bail!("checkpoint pickle integer exceeds size limit");
        }
        if length > 16 {
            // The tracer includes 128-bit vector registers. Positive Python
            // integers above i128::MAX use a 17th sign byte; callers only ask
            // for scalar machine registers, so retain no giant value here.
            self.skip(length as u64)?;
            return Ok(None);
        }
        let mut bytes = [0; 16];
        self.reader.read_exact(&mut bytes[..length])?;
        if length != 0 && bytes[length - 1] & 0x80 != 0 {
            bytes[length..].fill(0xff);
        }
        Ok(Some(i128::from_le_bytes(bytes)))
    }

    fn push(&mut self, slot: Slot) -> Result<()> {
        if self.stack.len() >= MAX_STACK {
            bail!("checkpoint pickle stack exceeds limit");
        }
        self.stack.push(slot);
        Ok(())
    }

    fn pop(&mut self) -> Result<Slot> {
        self.stack
            .pop()
            .context("checkpoint pickle stack underflow")
    }

    fn map_for_next_value(&self) -> MapKind {
        match self.stack.last() {
            None => MapKind::Root,
            Some(Slot::Text(key)) if key == "registers" => MapKind::Registers,
            Some(Slot::Text(key)) if key == "memory" => MapKind::Memory,
            _ => MapKind::Other,
        }
    }

    fn assign(&mut self, kind: MapKind, key: Slot, value: Slot) -> Result<()> {
        match kind {
            MapKind::Root => match (key, value) {
                (Slot::Text(key), Slot::Int(schema)) if key == "schema" => {
                    self.schema = Some(schema)
                }
                (Slot::Text(key), Slot::Text(hash)) if key == "binary_sha256" => {
                    self.hash = Some(hash)
                }
                _ => {}
            },
            MapKind::Registers => {
                if let (Slot::Text(name), Slot::Int(value)) = (key, value)
                    && let Ok(value) = u64::try_from(value)
                {
                    self.registers.insert(name, value);
                }
            }
            MapKind::Memory => {
                let (Slot::Int(address), Slot::Int(value)) = (key, value) else {
                    bail!("checkpoint memory entry is not an integer pair");
                };
                let address = u64::try_from(address)?;
                let value = u8::try_from(value)
                    .context("checkpoint memory byte is outside the byte range")?;
                if address >= 0xf000_0000_0000_0000 {
                    return Ok(());
                }
                let page = address & !4095;
                if !self.pages.contains_key(&page) && self.pages.len() >= MAX_PAGES {
                    bail!("checkpoint memory exceeds page limit");
                }
                self.pages
                    .entry(page)
                    .or_insert_with(SparsePage::new)
                    .insert((address - page) as usize, value)?;
                self.memory_entries += 1;
            }
            MapKind::Other => {}
        }
        Ok(())
    }

    fn set_item(&mut self) -> Result<()> {
        let value = self.pop()?;
        let key = self.pop()?;
        let Some(Slot::Map(kind)) = self.stack.last() else {
            bail!("checkpoint pickle SETITEM target is not a dictionary");
        };
        self.assign(*kind, key, value)
    }

    fn marked_values(&mut self) -> Result<Vec<Slot>> {
        let marker = self
            .stack
            .iter()
            .rposition(|item| matches!(item, Slot::Mark))
            .context("checkpoint pickle has no MARK")?;
        let values = self.stack.split_off(marker + 1);
        self.stack.pop();
        Ok(values)
    }

    fn set_items(&mut self) -> Result<()> {
        let values = self.marked_values()?;
        if values.len() % 2 != 0 {
            bail!("checkpoint pickle dictionary has an odd item count");
        }
        let Some(Slot::Map(kind)) = self.stack.last() else {
            bail!("checkpoint pickle SETITEMS target is not a dictionary");
        };
        let kind = *kind;
        for pair in values.as_chunks::<2>().0 {
            self.assign(kind, pair[0].clone(), pair[1].clone())?;
        }
        Ok(())
    }

    fn parse(mut self) -> Result<Schema1Checkpoint> {
        if self.byte()? != 0x80 || self.byte()? != 5 {
            bail!("schema-1 checkpoint requires Python pickle protocol 5");
        }
        loop {
            let opcode = self.byte()?;
            match opcode {
                0x95 => {
                    let length = u64::from_le_bytes(self.fixed::<8>()?);
                    if length > 64 * 1024 * 1024 {
                        bail!("checkpoint pickle frame exceeds limit");
                    }
                }
                b'}' => {
                    let kind = self.map_for_next_value();
                    self.push(Slot::Map(kind))?;
                }
                b']' => self.push(Slot::List)?,
                b')' => self.push(Slot::Other)?,
                b'(' => self.push(Slot::Mark)?,
                0x94 => {
                    let slot = self.stack.last().cloned().context("empty pickle memoize")?;
                    if self.memo.len() >= MAX_MEMO {
                        bail!("checkpoint pickle memo exceeds limit");
                    }
                    self.memo.push(slot);
                }
                b'h' => {
                    let index = self.byte()? as usize;
                    self.push(
                        self.memo
                            .get(index)
                            .cloned()
                            .context("invalid pickle memo index")?,
                    )?;
                }
                b'j' => {
                    let index = u32::from_le_bytes(self.fixed::<4>()?) as usize;
                    self.push(
                        self.memo
                            .get(index)
                            .cloned()
                            .context("invalid pickle memo index")?,
                    )?;
                }
                0x8c => {
                    let length = self.byte()? as usize;
                    let value = self.text(length)?;
                    self.push(Slot::Text(value))?;
                }
                b'X' => {
                    let length = u32::from_le_bytes(self.fixed::<4>()?) as usize;
                    let value = self.text(length)?;
                    self.push(Slot::Text(value))?;
                }
                0x8d => {
                    let length = usize::try_from(u64::from_le_bytes(self.fixed::<8>()?))?;
                    let value = self.text(length)?;
                    self.push(Slot::Text(value))?;
                }
                b'K' => {
                    let value = self.byte()?;
                    self.push(Slot::Int(value.into()))?;
                }
                b'M' => {
                    let value = u16::from_le_bytes(self.fixed::<2>()?);
                    self.push(Slot::Int(value.into()))?;
                }
                b'J' => {
                    let value = i32::from_le_bytes(self.fixed::<4>()?);
                    self.push(Slot::Int(value.into()))?;
                }
                0x8a => {
                    let length = self.byte()? as usize;
                    let value = self.long(length)?;
                    self.push(value.map_or(Slot::Other, Slot::Int))?;
                }
                0x8b => {
                    let length = u32::from_le_bytes(self.fixed::<4>()?) as usize;
                    let value = self.long(length)?;
                    self.push(value.map_or(Slot::Other, Slot::Int))?;
                }
                b'N' | 0x88 | 0x89 => self.push(Slot::Other)?,
                b'C' => {
                    let length = self.byte()? as u64;
                    self.skip(length)?;
                    self.push(Slot::Other)?;
                }
                b'B' => {
                    let length = u32::from_le_bytes(self.fixed::<4>()?) as u64;
                    self.skip(length)?;
                    self.push(Slot::Other)?;
                }
                b's' => self.set_item()?,
                b'u' => self.set_items()?,
                b'a' => {
                    self.pop()?;
                    if !matches!(self.stack.last(), Some(Slot::List)) {
                        bail!("checkpoint pickle APPEND target is not a list");
                    }
                }
                b'e' => {
                    self.marked_values()?;
                    if !matches!(self.stack.last(), Some(Slot::List)) {
                        bail!("checkpoint pickle APPENDS target is not a list");
                    }
                }
                0x85 => {
                    self.pop()?;
                    self.push(Slot::Other)?;
                }
                0x86 => {
                    self.pop()?;
                    self.pop()?;
                    self.push(Slot::Other)?;
                }
                0x87 => {
                    for _ in 0..3 {
                        self.pop()?;
                    }
                    self.push(Slot::Other)?;
                }
                b't' => {
                    self.marked_values()?;
                    self.push(Slot::Other)?;
                }
                b'.' => break,
                _ => bail!("unsupported schema-1 checkpoint pickle opcode {opcode:#x}"),
            }
        }
        if self.stack.len() != 1
            || !matches!(self.stack[0], Slot::Map(MapKind::Root))
            || self.schema != Some(1)
            || self.memory_entries == 0
        {
            bail!("invalid schema-1 checkpoint structure");
        }
        let hash = self.hash.context("checkpoint has no binary SHA-256")?;
        if hash.len() != 64 {
            bail!("checkpoint binary SHA-256 has invalid length");
        }
        let mut binary_hash = [0; 32];
        for (index, byte) in binary_hash.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)
                .context("checkpoint binary SHA-256 is not hexadecimal")?;
        }
        Ok(Schema1Checkpoint {
            binary_hash,
            registers: self.registers,
            pages: self.pages,
        })
    }
}

pub fn parse<R: Read>(reader: R) -> Result<Schema1Checkpoint> {
    Parser::new(reader).parse()
}
