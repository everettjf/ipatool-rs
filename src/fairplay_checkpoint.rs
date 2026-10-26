//! Read the private Python checkpoints used by FairPlay recovery.

use std::{
    collections::{BTreeMap, HashMap},
    io::{Cursor, Read, Seek, SeekFrom},
    path::Path,
};

use anyhow::{Context, Result, bail};
use flate2::read::MultiGzDecoder;
use serde_pickle::{DeOptions, HashableValue, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    fairplay_checkpoint_schema1::{self, Schema1Metadata, SparsePage},
    fairplay_recovery_output::open_private_file,
    store_memory::{MemoryRegion, exclude_mapped_regions},
    unicorn_runtime::Engine,
};

const MAX_COMPRESSED_BYTES: usize = 512 * 1024 * 1024;
const MAX_PLAIN_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SCHEMA1_PLAIN_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const PAGE_BYTES: usize = 4096;
const REG_X0: i32 = 199;
const REG_X29: i32 = 1;
const REG_X30: i32 = 2;
const REG_SP: i32 = 4;
const REG_NZCV: i32 = 3;
const REG_V0: i32 = 228;
const REG_PC: i32 = 260;

pub struct FairplayCheckpoint {
    pub binary_hash: [u8; 32],
    root: Option<Value>,
    sparse_pages: Option<HashMap<u64, SparsePage>>,
    sparse_registers: HashMap<String, u128>,
    sparse_pc: u64,
    sparse_nzcv: u64,
    sparse_metadata: Option<Schema1Metadata>,
}

impl Drop for FairplayCheckpoint {
    fn drop(&mut self) {
        self.binary_hash.zeroize();
        if let Some(root) = &mut self.root {
            clear_value(root);
        }
        for value in self.sparse_registers.values_mut() {
            value.zeroize();
        }
        self.sparse_pc.zeroize();
        self.sparse_nzcv.zeroize();
    }
}

impl FairplayCheckpoint {
    pub fn load_private(path: &Path) -> Result<Self> {
        let file = open_private_file(path, None, MAX_COMPRESSED_BYTES as u64)?;
        Self::parse_reader(file)
    }

    pub fn parse_gzip(compressed: &[u8]) -> Result<Self> {
        if compressed.len() > MAX_COMPRESSED_BYTES {
            bail!("FairPlay checkpoint exceeds compressed size limit");
        }
        Self::parse_reader(Cursor::new(compressed))
    }

    fn parse_reader<R: Read + Seek>(mut compressed: R) -> Result<Self> {
        // The original Python tracer writes schema 1 with the first key set to
        // `schema`. Detect it before allocating the decompressed pickle.
        let mut prefix = [0u8; 32];
        {
            MultiGzDecoder::new(&mut compressed)
                .read_exact(&mut prefix)
                .context("read FairPlay checkpoint schema")?;
        }
        compressed.seek(SeekFrom::Start(0))?;
        const SCHEMA1_PREFIX: &[u8] = b"\x8c\x06schema\x94K\x01";
        if prefix
            .windows(SCHEMA1_PREFIX.len())
            .any(|part| part == SCHEMA1_PREFIX)
        {
            let mut reader = MultiGzDecoder::new(compressed).take(MAX_SCHEMA1_PLAIN_BYTES + 1);
            let mut parsed = fairplay_checkpoint_schema1::parse(&mut reader)?;
            let mut tail = [0u8; 4096];
            while reader.read(&mut tail)? != 0 {}
            if reader.limit() == 0 {
                bail!("schema-1 FairPlay checkpoint exceeds decompressed size limit");
            }
            return Ok(Self {
                binary_hash: parsed.binary_hash,
                root: None,
                sparse_pages: Some(std::mem::take(&mut parsed.pages)),
                sparse_registers: std::mem::take(&mut parsed.registers),
                sparse_pc: parsed.pc,
                sparse_nzcv: parsed.nzcv,
                sparse_metadata: Some(std::mem::take(&mut parsed.metadata)),
            });
        }
        let mut plain = Zeroizing::new(Vec::new());
        MultiGzDecoder::new(compressed)
            .take(MAX_PLAIN_BYTES + 1)
            .read_to_end(&mut plain)
            .context("decompress FairPlay checkpoint")?;
        if plain.len() as u64 > MAX_PLAIN_BYTES {
            bail!("FairPlay checkpoint exceeds decompressed size limit");
        }
        let root = serde_pickle::value_from_slice(
            &plain,
            DeOptions::new()
                .replace_unresolved_globals()
                .replace_recursive_structures(),
        )
        .context("decode FairPlay checkpoint pickle")?;
        let mut checkpoint = Self {
            binary_hash: [0; 32],
            root: Some(root),
            sparse_pages: None,
            sparse_registers: HashMap::new(),
            sparse_pc: 0,
            sparse_nzcv: 0,
            sparse_metadata: None,
        };
        if value_u64(checkpoint.field("schema")?)? != 2 {
            bail!("only page-packed FairPlay checkpoint schema 2 is supported");
        }
        let hash = match checkpoint.field("binary_sha256")? {
            Value::String(hash) => hash,
            _ => bail!("checkpoint binary SHA-256 is missing"),
        };
        if hash.len() != 64 {
            bail!("checkpoint binary SHA-256 has invalid length");
        }
        let mut decoded = [0u8; 32];
        for (index, byte) in decoded.iter_mut().enumerate() {
            let digits = hash
                .get(index * 2..index * 2 + 2)
                .context("checkpoint binary SHA-256 contains invalid UTF-8 boundaries")?;
            *byte = u8::from_str_radix(digits, 16)
                .context("checkpoint binary SHA-256 is not hexadecimal")?;
        }
        checkpoint.binary_hash = decoded;
        if !matches!(checkpoint.field("memory_pages")?, Value::Dict(_)) {
            bail!("checkpoint has no page-packed memory map");
        }
        Ok(checkpoint)
    }

    pub fn register_u64(&self, name: &str) -> Result<u64> {
        Ok(u64::try_from(self.register_u128(name)?)?)
    }

    pub fn register_u128(&self, name: &str) -> Result<u128> {
        if self.sparse_pages.is_some() {
            return self
                .sparse_registers
                .get(name)
                .copied()
                .with_context(|| format!("checkpoint has no {name} register"));
        }
        let registers = match self.field("registers")? {
            Value::Dict(registers) => registers,
            _ => bail!("checkpoint has no register map"),
        };
        let value = registers
            .get(&HashableValue::String(name.into()))
            .with_context(|| format!("checkpoint has no {name} register"))?;
        value_u128(value)
    }

    pub fn pc(&self) -> Result<u64> {
        if self.sparse_pages.is_some() {
            return Ok(self.sparse_pc);
        }
        value_u64(self.field("pc")?)
    }

    pub fn nzcv(&self) -> Result<u64> {
        if self.sparse_pages.is_some() {
            return Ok(self.sparse_nzcv);
        }
        let flags = match self.field("nzcv")? {
            Value::Dict(flags) => flags,
            _ => bail!("checkpoint has invalid NZCV state"),
        };
        let mut value = 0u64;
        for (index, name) in ["n", "z", "c", "v"].into_iter().enumerate() {
            let flag = flags
                .get(&HashableValue::String(name.into()))
                .with_context(|| format!("checkpoint has no NZCV {name} flag"))?;
            let flag = value_u64(flag)?;
            if flag > 1 {
                bail!("checkpoint NZCV flag is outside the bit range");
            }
            value |= flag << (31 - index);
        }
        Ok(value)
    }

    /// Restore the checkpoint over any already-loaded image mappings.
    /// The caller must verify that those image bytes match `binary_hash`.
    pub fn restore_into(&self, engine: &mut Engine, occupied: &[MemoryRegion]) -> Result<usize> {
        let pc = self.pc()?;
        let nzcv = self.nzcv()?;
        let sp = self.register_u64("sp")?;
        let mut general = Zeroizing::new(Vec::with_capacity(31));
        for index in 0..31 {
            general.push(self.register_u64(&format!("x{index}"))?);
        }
        let mut vector = Zeroizing::new(Vec::with_capacity(32));
        for index in 0..32 {
            vector.push(self.register_u128(&format!("v{index}"))?.to_le_bytes());
        }

        let mut addresses = Vec::new();
        if let Some(pages) = &self.sparse_pages {
            addresses.extend(pages.keys().copied());
        } else {
            let pages = match self.field("memory_pages")? {
                Value::Dict(pages) => pages,
                _ => bail!("checkpoint has no page-packed memory map"),
            };
            for (address, value) in pages {
                if !matches!(value, Value::Bytes(bytes) if bytes.len() == PAGE_BYTES) {
                    bail!("checkpoint page has invalid payload geometry");
                }
                addresses.push(page_key_u64(address)?);
            }
        }
        if addresses.is_empty() {
            bail!("checkpoint has invalid memory pages");
        }
        addresses.sort_unstable();
        let mut grouped: Vec<MemoryRegion> = Vec::new();
        for &address in &addresses {
            if address >= 0xf000_0000_0000_0000 || address % PAGE_BYTES as u64 != 0 {
                bail!("checkpoint has invalid memory page address");
            }
            if let Some(last) = grouped.last_mut()
                && last.address.checked_add(last.size) == Some(address)
            {
                last.size += PAGE_BYTES as u64;
            } else {
                if grouped.last().is_some_and(|last| {
                    last.address
                        .checked_add(last.size)
                        .is_some_and(|end| address < end)
                }) {
                    bail!("checkpoint has repeated memory page address");
                }
                grouped.push(MemoryRegion {
                    address,
                    size: PAGE_BYTES as u64,
                });
            }
        }
        let new_regions = exclude_mapped_regions(&grouped, occupied)?;
        for region in &new_regions {
            engine.mem_map(region.address, usize::try_from(region.size)?)?;
        }
        if let Some(pages) = &self.sparse_pages {
            for (&address, page) in pages {
                let already_mapped = occupied.iter().any(|region| {
                    region.address <= address
                        && region
                            .address
                            .checked_add(region.size)
                            .is_some_and(|end| end > address)
                });
                let mut buffer = Zeroizing::new(if already_mapped {
                    engine
                        .mem_read(address, PAGE_BYTES)?
                        .try_into()
                        .expect("page size")
                } else {
                    [0; PAGE_BYTES]
                });
                page.overlay(&mut buffer);
                engine.mem_write(address, buffer.as_slice())?;
            }
        } else {
            let Value::Dict(pages) = self.field("memory_pages")? else {
                unreachable!("validated page map")
            };
            for (address, value) in pages {
                let Value::Bytes(bytes) = value else {
                    unreachable!("validated page payload")
                };
                engine.mem_write(page_key_u64(address)?, bytes)?;
            }
        }
        for (index, &value) in general.iter().enumerate() {
            let register = match index {
                29 => REG_X29,
                30 => REG_X30,
                _ => REG_X0 + index as i32,
            };
            engine.reg_write(register, value)?;
        }
        engine.reg_write(REG_SP, sp)?;
        for (index, &value) in vector.iter().enumerate() {
            engine.reg_write_128(REG_V0 + index as i32, value)?;
        }
        engine.reg_write(REG_NZCV, nzcv)?;
        engine.reg_write(REG_PC, pc)?;
        Ok(addresses.len())
    }

    pub fn read_block<const N: usize>(&self, address: u64) -> Result<Zeroizing<[u8; N]>> {
        if N == 0 || N > 1024 * 1024 {
            bail!("checkpoint block size is outside the bounded range");
        }
        if let Some(pages) = &self.sparse_pages {
            let mut output = Zeroizing::new([0u8; N]);
            for (index, byte) in output.iter_mut().enumerate() {
                let cursor = address
                    .checked_add(index as u64)
                    .context("checkpoint address overflow")?;
                let page_address = cursor & !(PAGE_BYTES as u64 - 1);
                let page = pages
                    .get(&page_address)
                    .with_context(|| format!("checkpoint does not cover page {page_address:#x}"))?;
                *byte = page.read((cursor - page_address) as usize)?;
            }
            return Ok(output);
        }
        let pages = match self.field("memory_pages")? {
            Value::Dict(pages) => pages,
            _ => bail!("checkpoint has no page-packed memory map"),
        };
        let mut output = Zeroizing::new([0u8; N]);
        let mut written = 0;
        while written < N {
            let cursor = address
                .checked_add(written as u64)
                .context("checkpoint address overflow")?;
            let page_address = cursor & !(PAGE_BYTES as u64 - 1);
            let page = pages
                .get(&HashableValue::I64(i64::try_from(page_address)?))
                .with_context(|| format!("checkpoint does not cover page {page_address:#x}"))?;
            let data = match page {
                Value::Bytes(data) if data.len() == PAGE_BYTES => data,
                _ => bail!("checkpoint page has invalid payload geometry"),
            };
            let offset = (cursor - page_address) as usize;
            let count = (PAGE_BYTES - offset).min(N - written);
            output[written..written + count].copy_from_slice(&data[offset..offset + count]);
            written += count;
        }
        Ok(output)
    }

    /// Page addresses already represented by this checkpoint.
    pub fn page_addresses(&self) -> Result<Vec<u64>> {
        if let Some(pages) = &self.sparse_pages {
            return Ok(pages.keys().copied().collect());
        }
        let Value::Dict(pages) = self.field("memory_pages")? else {
            bail!("checkpoint has no page-packed memory map");
        };
        pages.keys().map(page_key_u64).collect()
    }

    pub fn next_allocation(&self) -> Result<Option<u64>> {
        let Some(Value::Dict(root)) = &self.root else {
            return Ok(None);
        };
        root.get(&HashableValue::String("next_allocation".into()))
            .map(value_u64)
            .transpose()
    }

    /// Preserve original metadata when writing a resumed schema-2 snapshot.
    pub(crate) fn clone_root(&self) -> Result<Value> {
        if let Some(root) = &self.root {
            return Ok(root.clone());
        }
        let metadata = self
            .sparse_metadata
            .as_ref()
            .context("schema-1 checkpoint metadata is missing")?;
        let mut fields = BTreeMap::new();
        let mut insert = |name: &str, value: Value| {
            fields.insert(HashableValue::String(name.into()), value);
        };
        insert(
            "binary_sha256",
            Value::String(
                self.binary_hash
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            ),
        );
        insert("working_sinf", Value::Int(metadata.working_sinf.into()));
        insert("priv_offset", Value::Int(metadata.priv_offset.into()));
        insert("priv_length", Value::Int(metadata.priv_length.into()));
        insert("state_slot", Value::Int(metadata.state_slot.into()));
        insert(
            "once_tokens",
            Value::List(
                metadata
                    .once_tokens
                    .iter()
                    .map(|&token| Value::Int(token.into()))
                    .collect(),
            ),
        );
        Ok(Value::Dict(fields))
    }

    fn field(&self, name: &str) -> Result<&Value> {
        let root = match self.root.as_ref() {
            Some(Value::Dict(root)) => root,
            _ => bail!("checkpoint root is not a dictionary"),
        };
        root.get(&HashableValue::String(name.into()))
            .with_context(|| format!("checkpoint has no {name} field"))
    }
}

fn value_u64(value: &Value) -> Result<u64> {
    Ok(u64::try_from(value_u128(value)?)?)
}

fn value_u128(value: &Value) -> Result<u128> {
    match value {
        Value::I64(value) => Ok(u128::try_from(*value)?),
        Value::Int(value) => Ok(value.to_string().parse()?),
        Value::String(value) => {
            if let Some(hex) = value.strip_prefix("0x") {
                Ok(u128::from_str_radix(hex, 16)?)
            } else {
                Ok(value.parse()?)
            }
        }
        _ => bail!("checkpoint numeric field has invalid type"),
    }
}

fn page_key_u64(value: &HashableValue) -> Result<u64> {
    match value {
        HashableValue::I64(value) => Ok(u64::try_from(*value)?),
        HashableValue::Int(value) => Ok(value.to_string().parse()?),
        _ => bail!("checkpoint page address has invalid type"),
    }
}

pub(crate) fn clear_value(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::String(text) => text.zeroize(),
        Value::List(values) | Value::Tuple(values) => {
            for item in values {
                clear_value(item);
            }
        }
        Value::Dict(values) => {
            for item in values.values_mut() {
                clear_value(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    const FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-schema2-synthetic.pkl.gz");
    const SCHEMA1_FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-schema1-synthetic.pkl.gz");
    const RESUME_FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-resume-synthetic.pkl.gz");

    #[test]
    fn restores_packed_cpu_snapshot_and_executes_next_instructions() {
        let checkpoint = FairplayCheckpoint::parse_gzip(RESUME_FIXTURE).unwrap();
        let mut engine = Engine::new().unwrap();
        let address = checkpoint.pc().unwrap();
        assert_eq!(checkpoint.restore_into(&mut engine, &[]).unwrap(), 1);
        assert_eq!(engine.reg_read(REG_X0).unwrap(), 7);
        assert_eq!(
            engine.reg_read(REG_NZCV).unwrap() & 0xf000_0000,
            0xa000_0000
        );
        assert_eq!(
            engine.reg_read_128(REG_V0).unwrap(),
            ((1u128 << 127) + 123).to_le_bytes()
        );
        engine
            .start_bounded(address, address + 8, Duration::from_secs(2), 8)
            .unwrap();
        assert_eq!(engine.reg_read(REG_X0).unwrap(), 43);
    }

    #[test]
    fn restores_sparse_bytes_over_an_existing_image_page() {
        let checkpoint = FairplayCheckpoint::parse_gzip(SCHEMA1_FIXTURE).unwrap();
        let mut engine = Engine::new().unwrap();
        let address = checkpoint.register_u64("x23").unwrap();
        let page = address & !4095;
        engine.mem_map(page, 8192).unwrap();
        engine.mem_write(page, &[0xaa; 8192]).unwrap();
        let occupied = [MemoryRegion {
            address: page,
            size: 8192,
        }];
        assert_eq!(checkpoint.restore_into(&mut engine, &occupied).unwrap(), 2);
        assert_eq!(engine.mem_read(page, 1).unwrap(), [0xaa]);
        assert_eq!(
            engine.mem_read(address, 432).unwrap(),
            (0..432).map(|index| index as u8).collect::<Vec<_>>()
        );
        assert_eq!(engine.mem_read(address + 432, 1).unwrap(), [0xaa]);
        assert_eq!(engine.reg_read(REG_X0 + 23).unwrap(), address);
        assert_eq!(engine.reg_read(REG_PC).unwrap(), checkpoint.pc().unwrap());
    }

    #[test]
    fn streams_python_protocol_five_byte_addressed_checkpoint() {
        let checkpoint = FairplayCheckpoint::parse_gzip(SCHEMA1_FIXTURE).unwrap();
        assert_eq!(checkpoint.binary_hash, [0xa5; 32]);
        let address = 0x7100_0001_4ee0;
        assert_eq!(checkpoint.register_u64("x23").unwrap(), address);
        assert!(checkpoint.register_u64("v0").is_err());
        assert_eq!(checkpoint.register_u128("v0").unwrap(), (1 << 127) + 123);
        assert_eq!(checkpoint.pc().unwrap(), 0x1005_7ae74);
        assert_eq!(checkpoint.nzcv().unwrap(), 0xa000_0000);
        let block = checkpoint.read_block::<432>(address).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(block.as_slice())),
            "ce7b1c71b87a0ab700b2547140d15258be75b927600d784ecc071f119f790a69"
        );
        assert!(checkpoint.read_block::<433>(address).is_err());
        assert!(checkpoint.read_block::<1>(0xf000_0000_0000_0123).is_err());
        let Value::Dict(metadata) = checkpoint.clone_root().unwrap() else {
            panic!("checkpoint metadata must be a dictionary");
        };
        let tokens = metadata
            .get(&HashableValue::String("once_tokens".into()))
            .unwrap();
        assert_eq!(
            tokens,
            &Value::List(vec![Value::Int(4660.into()), Value::Int(22136.into())])
        );
    }

    #[test]
    fn reads_python_protocol_five_page_packed_checkpoint_across_boundary() {
        let checkpoint = FairplayCheckpoint::parse_gzip(FIXTURE).unwrap();
        assert_eq!(checkpoint.binary_hash, [0xa5; 32]);
        let address = 0x7100_0001_4ee0;
        assert_eq!(checkpoint.register_u64("x23").unwrap(), address);
        let block = checkpoint.read_block::<432>(address).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(block.as_slice())),
            "5f55150f8d3c2f9d7b0c55b61dee6dc218979918b0dd7512bca1a366fd8aa26f"
        );
        assert!(checkpoint.read_block::<8192>(address).is_err());
    }

    #[test]
    fn requires_private_checkpoint_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("checkpoint.pkl.gz");
        std::fs::write(&path, FIXTURE).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(FairplayCheckpoint::load_private(&path).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(FairplayCheckpoint::load_private(&path).is_err());
        }
    }
}
