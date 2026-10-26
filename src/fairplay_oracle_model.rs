//! Private FPGOOR1 offline FairPlay oracle model and copy-on-write state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
};

use anyhow::{Context, Result, bail};
use flate2::read::MultiGzDecoder;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"FPGOOR1\0";
const VERSION: u32 = 2;
const PAGE_SIZE: usize = 4096;
const MAX_PAGES: usize = 4096;
const MAX_DOMAINS: usize = 64;
const MAX_PLAIN_BYTES: u64 = 20 * 1024 * 1024;
const MAX_COMPRESSED_BYTES: u64 = 20 * 1024 * 1024;

pub struct OracleModel {
    pub binary_hash: [u8; 32],
    pub block_address: u64,
    pub registers: [u64; 31],
    pub sp: u64,
    pub flags: [bool; 4],
    pages: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    domains: BTreeMap<(u64, u8), Zeroizing<[u64; 256]>>,
}

impl Drop for OracleModel {
    fn drop(&mut self) {
        self.binary_hash.zeroize();
        self.registers.zeroize();
        self.sp = 0;
    }
}

impl OracleModel {
    /// Load private enrollment state. Public sanitized models can be parsed
    /// from bytes without relaxing the private-file rule.
    pub fn load_private(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file: File = options
            .open(path)
            .with_context(|| format!("open oracle model {}", path.display()))?;
        let metadata = file
            .metadata()
            .context("inspect opened FairPlay oracle model")?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_COMPRESSED_BYTES {
            bail!("FairPlay oracle model must be a bounded regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("FairPlay oracle model must be mode 0600 or stricter");
            }
        }
        let mut compressed = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        file.by_ref()
            .take(MAX_COMPRESSED_BYTES + 1)
            .read_to_end(&mut compressed)
            .context("read private FairPlay oracle model")?;
        Self::parse_gzip(&compressed)
    }

    pub fn parse_gzip(compressed: &[u8]) -> Result<Self> {
        if compressed.len() as u64 > MAX_COMPRESSED_BYTES {
            bail!("FairPlay oracle model exceeds compressed size limit");
        }
        let mut decoder = MultiGzDecoder::new(compressed);
        let mut plain = Vec::new();
        decoder
            .by_ref()
            .take(MAX_PLAIN_BYTES + 1)
            .read_to_end(&mut plain)
            .context("decompress FairPlay oracle model")?;
        if plain.len() as u64 > MAX_PLAIN_BYTES {
            bail!("FairPlay oracle model exceeds decompressed size limit");
        }
        let result = Self::parse_plain(&plain);
        plain.zeroize();
        result
    }

    fn parse_plain(plain: &[u8]) -> Result<Self> {
        let mut cursor = Cursor {
            data: plain,
            offset: 0,
        };
        if cursor.read(8)? != MAGIC {
            bail!("invalid FairPlay oracle model magic");
        }
        if cursor.u32()? != VERSION {
            bail!("unsupported FairPlay oracle model version");
        }
        let binary_hash = cursor.read(32)?.try_into().unwrap();
        let block_address = cursor.u64()?;
        let mut registers = [0u64; 31];
        for register in &mut registers {
            *register = cursor.u64()?;
        }
        let sp = cursor.u64()?;
        let mut flags = [false; 4];
        for flag in &mut flags {
            *flag = match cursor.read(1)?[0] {
                0 => false,
                1 => true,
                _ => bail!("invalid FairPlay oracle flag"),
            };
        }
        let page_count = cursor.u32()? as usize;
        if page_count == 0 || page_count > MAX_PAGES {
            bail!("invalid FairPlay oracle page count");
        }
        let mut pages = BTreeMap::new();
        for _ in 0..page_count {
            let address = cursor.u64()?;
            if address % PAGE_SIZE as u64 != 0 {
                bail!("unaligned FairPlay oracle page");
            }
            let page = Zeroizing::new(cursor.read(PAGE_SIZE)?.to_vec());
            if pages.insert(address, page).is_some() {
                bail!("duplicate FairPlay oracle page");
            }
        }
        let domain_count = cursor.u32()? as usize;
        if domain_count > MAX_DOMAINS {
            bail!("invalid FairPlay oracle domain count");
        }
        let mut domains = BTreeMap::new();
        for _ in 0..domain_count {
            let pc = cursor.u64()?;
            let register = cursor.read(1)?[0];
            if register >= 31 || cursor.read(7)? != [0; 7] {
                bail!("invalid FairPlay oracle domain envelope");
            }
            let mut values = [0u64; 256];
            for index in 0..values.len() {
                values[index] = cursor.u64()?;
                if index > 0 && values[index] <= values[index - 1] {
                    bail!("FairPlay oracle domain is not ordered");
                }
            }
            if domains
                .insert((pc, register), Zeroizing::new(values))
                .is_some()
            {
                bail!("duplicate FairPlay oracle domain");
            }
        }
        if cursor.offset != plain.len() {
            bail!("FairPlay oracle model has trailing data");
        }
        Ok(Self {
            binary_hash,
            block_address,
            registers,
            sp,
            flags,
            pages,
            domains,
        })
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
    pub fn domain(&self, pc: u64, register: u8) -> Option<&[u64; 256]> {
        self.domains.get(&(pc, register)).map(|values| &**values)
    }
    pub fn state(&self) -> OracleState<'_> {
        OracleState::new(self)
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn read(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .context("oracle model length overflow")?;
        let result = self
            .data
            .get(self.offset..end)
            .context("truncated FairPlay oracle model")?;
        self.offset = end;
        Ok(result)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read(8)?.try_into().unwrap()))
    }
}

pub struct OracleState<'a> {
    model: &'a OracleModel,
    pub registers: [u64; 31],
    pub sp: u64,
    pub flags: [bool; 4],
    writable: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    touched: BTreeSet<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultKind {
    None,
    Index,
    Pointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleFault {
    pub pc: u64,
    pub register: u8,
    pub shift: u8,
    pub value: u8,
    pub kind: FaultKind,
    pub restore: bool,
    pub table_bytes: u16,
    pub entry_bytes: u8,
}

impl OracleFault {
    pub const NONE: Self = Self {
        pc: 0,
        register: 0,
        shift: 0,
        value: 0,
        kind: FaultKind::None,
        restore: false,
        table_bytes: 0,
        entry_bytes: 0,
    };
}

impl Drop for OracleState<'_> {
    fn drop(&mut self) {
        self.registers.zeroize();
        self.sp = 0;
    }
}

impl<'a> OracleState<'a> {
    fn new(model: &'a OracleModel) -> Self {
        Self {
            model,
            registers: model.registers,
            sp: model.sp,
            flags: model.flags,
            writable: BTreeMap::new(),
            touched: BTreeSet::new(),
        }
    }

    pub fn reset(&mut self) {
        for address in &self.touched {
            if let Some(page) = self.writable.get_mut(address) {
                page.copy_from_slice(&self.model.pages[address]);
            }
        }
        self.touched.clear();
        self.registers = self.model.registers;
        self.sp = self.model.sp;
        self.flags = self.model.flags;
    }

    pub fn begin(&mut self, input: &[u8]) -> Result<()> {
        self.reset();
        self.store(self.model.block_address, input)
    }

    pub fn load(&self, address: u64, size: usize) -> Result<u64> {
        if !matches!(size, 1 | 4 | 8) {
            bail!("unsupported oracle load size {size}");
        }
        let mut bytes = [0u8; 8];
        for (index, byte) in bytes[..size].iter_mut().enumerate() {
            let current = address
                .checked_add(index as u64)
                .context("oracle address overflow")?;
            let base = current & !(PAGE_SIZE as u64 - 1);
            let page = self
                .writable
                .get(&base)
                .or_else(|| self.model.pages.get(&base))
                .with_context(|| format!("oracle address {current:#x} is outside the model"))?;
            *byte = page[(current - base) as usize];
        }
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn store(&mut self, address: u64, value: &[u8]) -> Result<()> {
        let mut remaining = value;
        let mut current = address;
        while !remaining.is_empty() {
            let base = current & !(PAGE_SIZE as u64 - 1);
            let source = self
                .model
                .pages
                .get(&base)
                .with_context(|| format!("oracle address {current:#x} is outside the model"))?;
            let page = self.writable.entry(base).or_insert_with(|| source.clone());
            let offset = (current - base) as usize;
            let count = remaining.len().min(PAGE_SIZE - offset);
            page[offset..offset + count].copy_from_slice(&remaining[..count]);
            self.touched.insert(base);
            current = current
                .checked_add(count as u64)
                .context("oracle address overflow")?;
            remaining = &remaining[count..];
        }
        Ok(())
    }

    pub fn store_value(&mut self, address: u64, value: u64, size: usize) -> Result<()> {
        if !matches!(size, 1 | 4 | 8) {
            bail!("unsupported oracle store size {size}");
        }
        self.store(address, &value.to_le_bytes()[..size])
    }

    pub fn output(&self) -> Result<[u8; 16]> {
        let mut result = [0u8; 16];
        for (index, byte) in result.iter_mut().enumerate() {
            let address = self
                .model
                .block_address
                .checked_add(index as u64)
                .context("oracle output address overflow")?;
            *byte = self.load(address, 1)? as u8;
        }
        Ok(result)
    }

    pub fn output_bytes(&self, size: usize) -> Result<Vec<u8>> {
        if size > 4096 {
            bail!("oracle output exceeds one page");
        }
        let mut result = vec![0u8; size];
        for (index, byte) in result.iter_mut().enumerate() {
            let address = self
                .model
                .block_address
                .checked_add(index as u64)
                .context("oracle output address overflow")?;
            *byte = self.load(address, 1)? as u8;
        }
        Ok(result)
    }

    pub fn test32(&mut self, value: u32) {
        self.flags = [value & 0x8000_0000 != 0, value == 0, false, false];
    }

    pub fn compare32(&mut self, left: u32, right: u32) {
        let result = left.wrapping_sub(right);
        self.flags = [
            result & 0x8000_0000 != 0,
            result == 0,
            left >= right,
            ((left ^ right) & (left ^ result) & 0x8000_0000) != 0,
        ];
    }

    pub fn condition(&self, name: &str) -> bool {
        match name {
            "eq" => self.flags[1],
            "ne" => !self.flags[1],
            "lo" => !self.flags[2],
            "hi" => self.flags[2] && !self.flags[1],
            _ => panic!("unsupported generated condition {name}"),
        }
    }

    pub fn before_fault(&mut self, selected: OracleFault, pc: u64) -> Result<(u64, bool)> {
        if selected.kind == FaultKind::None || selected.pc != pc {
            return Ok((0, false));
        }
        let register = selected.register as usize;
        if register >= self.registers.len() {
            bail!("invalid oracle fault register");
        }
        let old = self.registers[register];
        self.registers[register] = match selected.kind {
            FaultKind::None => old,
            FaultKind::Index => {
                if let Some(values) = self.model.domain(pc, selected.register) {
                    let needle = old as u32 as u64;
                    let index = values.binary_search(&needle).map_err(|_| {
                        anyhow::anyhow!("index value {needle:#x} is outside the learned domain")
                    })?;
                    values[index ^ selected.value as usize]
                } else {
                    (old as u32 ^ (selected.value as u32).wrapping_shl(selected.shift as u32))
                        as u64
                }
            }
            FaultKind::Pointer => {
                let table = selected.table_bytes as u64;
                let entry = selected.entry_bytes as u64;
                if !table.is_power_of_two() || entry == 0 {
                    bail!("invalid pointer-fault geometry");
                }
                let base = old & !(table - 1);
                let offset = old - base;
                if offset >= table || !offset.is_multiple_of(entry) {
                    bail!("pointer fault is outside its table");
                }
                base.wrapping_add(((offset / entry) ^ selected.value as u64).wrapping_mul(entry))
            }
        };
        Ok((old, selected.restore))
    }

    pub fn after_fault(&mut self, selected: OracleFault, pc: u64, old: u64, restore: bool) {
        if restore && selected.pc == pc && (selected.register as usize) < self.registers.len() {
            self.registers[selected.register as usize] = old;
        }
    }

    pub fn digest(&self) -> String {
        let mut hash = Sha256::new();
        for register in self.registers {
            hash.update(register.to_le_bytes());
        }
        hash.update(self.sp.to_le_bytes());
        hash.update(self.flags.map(u8::from));
        for (address, page) in &self.model.pages {
            hash.update(address.to_le_bytes());
            hash.update(self.writable.get(address).unwrap_or(page));
        }
        format!("{:x}", hash.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::{fs, io::Write};

    fn fixture() -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&4094u64.to_le_bytes());
        for register in 0..31u64 {
            bytes.extend_from_slice(&register.to_le_bytes());
        }
        bytes.extend_from_slice(&0x8000u64.to_le_bytes());
        bytes.extend_from_slice(&[1, 0, 1, 0]);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        for address in [0u64, 4096] {
            bytes.extend_from_slice(&address.to_le_bytes());
            bytes.extend_from_slice(&vec![address as u8; PAGE_SIZE]);
        }
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0x1234u64.to_le_bytes());
        bytes.push(8);
        bytes.extend_from_slice(&[0; 7]);
        for index in 0..256u64 {
            bytes.extend_from_slice(&index.to_le_bytes());
        }
        let mut writer = GzEncoder::new(Vec::new(), Compression::default());
        writer.write_all(&bytes).unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn parses_private_model_and_resets_copied_pages() {
        let model = OracleModel::parse_gzip(&fixture()).unwrap();
        assert_eq!(model.binary_hash, [7; 32]);
        assert_eq!(model.page_count(), 2);
        assert_eq!(model.domain(0x1234, 8).unwrap()[255], 255);
        let mut state = model.state();
        let initial = state.digest();
        state.begin(&[1, 2, 3, 4]).unwrap();
        assert_eq!(state.load(4094, 4).unwrap(), 0x0403_0201);
        assert_ne!(state.digest(), initial);
        state.reset();
        assert_eq!(state.digest(), initial);
    }

    #[test]
    fn rejects_trailing_data_and_public_permissions() {
        let compressed = fixture();
        let mut plain = Vec::new();
        MultiGzDecoder::new(compressed.as_slice())
            .read_to_end(&mut plain)
            .unwrap();
        plain.push(0);
        let mut writer = GzEncoder::new(Vec::new(), Compression::default());
        writer.write_all(&plain).unwrap();
        assert!(OracleModel::parse_gzip(&writer.finish().unwrap()).is_err());
        let mut appended = compressed.clone();
        appended.extend_from_slice(b"trailing garbage");
        assert!(OracleModel::parse_gzip(&appended).is_err());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("model.gz");
        fs::write(&path, compressed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(OracleModel::load_private(&path).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let link = root.path().join("model-link.gz");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(OracleModel::load_private(&link).is_err());
        }
        assert!(OracleModel::load_private(&path).is_ok());
    }

    #[test]
    fn parses_sanitized_26a428_frame_model() {
        // Account-independent public build fixture from the original recovery tool.
        let compressed = include_bytes!("../tests/fixtures/fairplay-oracle-frame-public.model.gz");
        assert_eq!(
            format!("{:x}", Sha256::digest(compressed)),
            "b10da4b2e95e6a2efd9a3fe5fab9448a908bb7556e133e238d92ce8e03eba849"
        );
        let model = OracleModel::parse_gzip(compressed).unwrap();
        assert_eq!(
            model
                .binary_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784"
        );
        assert!(model.page_count() > 1);
        assert!(model.domain_count() <= MAX_DOMAINS);
    }
}
