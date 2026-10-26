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
const MAX_ONCE_TOKENS: usize = 65_536;

#[derive(Default)]
pub struct Schema1Metadata {
    pub working_sinf: u64,
    pub priv_offset: u64,
    pub priv_length: u64,
    pub state_slot: u64,
    pub once_tokens: Vec<u64>,
}

impl Drop for Schema1Metadata {
    fn drop(&mut self) {
        self.working_sinf.zeroize();
        self.priv_offset.zeroize();
        self.priv_length.zeroize();
        self.state_slot.zeroize();
        self.once_tokens.zeroize();
    }
}

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

    pub fn overlay(&self, page: &mut [u8; PAGE_BYTES]) {
        for (word_index, &bits) in self.present.iter().enumerate() {
            let mut remaining = bits;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                let offset = word_index * 64 + bit;
                page[offset] = self.bytes[offset];
                remaining &= remaining - 1;
            }
        }
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
    pub pc: u64,
    pub nzcv: u64,
    pub registers: HashMap<String, u128>,
    pub pages: HashMap<u64, SparsePage>,
    pub metadata: Schema1Metadata,
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
    Nzcv,
    Other,
}

#[derive(Clone)]
enum Slot {
    Mark,
    Map(MapKind),
    List(Option<Vec<u64>>),
    Int(i128),
    Wide(u128),
    Text(String),
    Other,
}

struct Parser<R> {
    reader: R,
    stack: Vec<Slot>,
    memo: Vec<Slot>,
    schema: Option<i128>,
    hash: Option<String>,
    pc: Option<String>,
    nzcv: [Option<u8>; 4],
    registers: HashMap<String, u128>,
    pages: HashMap<u64, SparsePage>,
    memory_entries: usize,
    working_sinf: Option<u64>,
    priv_offset: Option<u64>,
    priv_length: Option<u64>,
    state_slot: Option<u64>,
    once_tokens: Option<Vec<u64>>,
}

impl<R: Read> Parser<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            stack: Vec::new(),
            memo: Vec::new(),
            schema: None,
            hash: None,
            pc: None,
            nzcv: [None; 4],
            registers: HashMap::new(),
            pages: HashMap::new(),
            memory_entries: 0,
            working_sinf: None,
            priv_offset: None,
            priv_length: None,
            state_slot: None,
            once_tokens: None,
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

    fn long(&mut self, length: usize) -> Result<Slot> {
        if length > 32 {
            bail!("checkpoint pickle integer exceeds size limit");
        }
        if length > 16 {
            let mut bytes = [0; 32];
            self.reader.read_exact(&mut bytes[..length])?;
            if length == 17 && bytes[16] == 0 {
                return Ok(Slot::Wide(u128::from_le_bytes(bytes[..16].try_into()?)));
            }
            return Ok(Slot::Other);
        }
        let mut bytes = [0; 16];
        self.reader.read_exact(&mut bytes[..length])?;
        if length != 0 && bytes[length - 1] & 0x80 != 0 {
            bytes[length..].fill(0xff);
        }
        Ok(Slot::Int(i128::from_le_bytes(bytes)))
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
            Some(Slot::Text(key)) if key == "nzcv" => MapKind::Nzcv,
            _ => MapKind::Other,
        }
    }

    fn list_for_next_value(&self) -> Option<Vec<u64>> {
        match self.stack.last() {
            Some(Slot::Text(key)) if key == "once_tokens" => Some(Vec::new()),
            _ => None,
        }
    }

    fn slot_u64(value: Slot) -> Result<u64> {
        match value {
            Slot::Int(value) => Ok(u64::try_from(value)?),
            Slot::Wide(value) => Ok(u64::try_from(value)?),
            _ => bail!("checkpoint metadata contains a noninteger value"),
        }
    }

    fn extend_list(list: &mut Vec<u64>, values: Vec<Slot>) -> Result<()> {
        if list.len().saturating_add(values.len()) > MAX_ONCE_TOKENS {
            bail!("checkpoint once-token list exceeds limit");
        }
        for value in values {
            list.push(Self::slot_u64(value)?);
        }
        Ok(())
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
                (Slot::Text(key), Slot::Text(pc)) if key == "pc" => self.pc = Some(pc),
                (Slot::Text(key), value) if key == "working_sinf" => {
                    self.working_sinf = Some(Self::slot_u64(value)?);
                }
                (Slot::Text(key), value) if key == "priv_offset" => {
                    self.priv_offset = Some(Self::slot_u64(value)?);
                }
                (Slot::Text(key), value) if key == "priv_length" => {
                    self.priv_length = Some(Self::slot_u64(value)?);
                }
                (Slot::Text(key), value) if key == "state_slot" => {
                    self.state_slot = Some(Self::slot_u64(value)?);
                }
                (Slot::Text(key), Slot::List(Some(tokens))) if key == "once_tokens" => {
                    self.once_tokens = Some(tokens);
                }
                _ => {}
            },
            MapKind::Registers => {
                if let Slot::Text(name) = key {
                    match value {
                        Slot::Int(value) => {
                            if let Ok(value) = u128::try_from(value) {
                                self.registers.insert(name, value);
                            }
                        }
                        Slot::Wide(value) => {
                            self.registers.insert(name, value);
                        }
                        _ => {}
                    }
                }
            }
            MapKind::Nzcv => {
                if let (Slot::Text(name), Slot::Int(value)) = (key, value) {
                    let index = match name.as_str() {
                        "n" => Some(0),
                        "z" => Some(1),
                        "c" => Some(2),
                        "v" => Some(3),
                        _ => None,
                    };
                    if let Some(index) = index {
                        self.nzcv[index] = Some(u8::try_from(value)?);
                    }
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
                b']' => {
                    let list = self.list_for_next_value();
                    self.push(Slot::List(list))?;
                }
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
                    self.push(value)?;
                }
                0x8b => {
                    let length = u32::from_le_bytes(self.fixed::<4>()?) as usize;
                    let value = self.long(length)?;
                    self.push(value)?;
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
                    let value = self.pop()?;
                    match self.stack.last_mut() {
                        Some(Slot::List(Some(list))) => Self::extend_list(list, vec![value])?,
                        Some(Slot::List(None)) => {}
                        _ => bail!("checkpoint pickle APPEND target is not a list"),
                    }
                }
                b'e' => {
                    let values = self.marked_values()?;
                    match self.stack.last_mut() {
                        Some(Slot::List(Some(list))) => Self::extend_list(list, values)?,
                        Some(Slot::List(None)) => {}
                        _ => bail!("checkpoint pickle APPENDS target is not a list"),
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
        let pc_text = self.pc.context("checkpoint has no program counter")?;
        let pc = u64::from_str_radix(pc_text.strip_prefix("0x").unwrap_or(&pc_text), 16)
            .context("checkpoint program counter is invalid")?;
        let mut nzcv = 0u64;
        for (index, flag) in self.nzcv.into_iter().enumerate() {
            let flag = flag.context("checkpoint has incomplete NZCV state")?;
            if flag > 1 {
                bail!("checkpoint NZCV flag is outside the bit range");
            }
            nzcv |= u64::from(flag) << (31 - index);
        }
        Ok(Schema1Checkpoint {
            binary_hash,
            pc,
            nzcv,
            registers: self.registers,
            pages: self.pages,
            metadata: Schema1Metadata {
                working_sinf: self
                    .working_sinf
                    .context("checkpoint has no working_sinf")?,
                priv_offset: self.priv_offset.context("checkpoint has no priv_offset")?,
                priv_length: self.priv_length.context("checkpoint has no priv_length")?,
                state_slot: self.state_slot.context("checkpoint has no state_slot")?,
                once_tokens: self.once_tokens.context("checkpoint has no once_tokens")?,
            },
        })
    }
}

pub fn parse<R: Read>(reader: R) -> Result<Schema1Checkpoint> {
    Parser::new(reader).parse()
}
