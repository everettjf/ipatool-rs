//! Load a matching fairplayd image and resume a private checkpoint for a
//! bounded span. External imports are intentionally left as named stubs until
//! the corresponding FairPlay host services are modeled in Rust.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Write,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use flate2::{Compression, write::GzEncoder};
use serde_pickle::{HashableValue, SerOptions, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    fairplay_checkpoint::{FairplayCheckpoint, clear_value},
    fairplay_recovery_output::write_private_binary,
    machimage::Image,
    store_memory::MemoryRegion,
    unicorn_runtime::{Engine, REG_PC},
};

const EXTERNAL_BASE: u64 = 0xf100_0000_0000_0000;
const EXTERNAL_STRIDE: u64 = 0x1000;
const MAX_EXTERNALS: usize = 1 << 20;
const PAGE_BYTES: u64 = 4096;
const MAX_SNAPSHOT_PAGES: usize = 30_000;

struct SensitiveValue(Value);

impl Drop for SensitiveValue {
    fn drop(&mut self) {
        clear_value(&mut self.0);
    }
}

pub struct LoadedFairplayd {
    pub regions: Vec<MemoryRegion>,
    pub externals: HashMap<u64, String>,
    pub image_base: u64,
    pub fixups: usize,
    pub data_pages: Vec<u64>,
}

/// Load the exact arm64e image with chained rebases and deterministic external
/// bind addresses. The caller owns the engine and can install import hooks.
pub fn load_fairplayd(engine: &mut Engine, binary: &[u8]) -> Result<LoadedFairplayd> {
    let mut image = Image::open("fairplayd", binary).context("parse fairplayd arm64e Mach-O")?;
    let image_base = image.base();
    let fixups = image.fixup_count();
    let mut data_pages = Vec::new();
    for segment in image.segments() {
        if !segment.name.starts_with("__DATA") && !segment.name.starts_with("__AUTH") {
            continue;
        }
        let start = segment.address & !(PAGE_BYTES - 1);
        let end = segment
            .address
            .checked_add(segment.size)
            .and_then(|end| end.checked_add(PAGE_BYTES - 1))
            .context("fairplayd data segment address overflow")?
            & !(PAGE_BYTES - 1);
        let count = usize::try_from((end - start) / PAGE_BYTES)?;
        if data_pages.len().saturating_add(count) > MAX_SNAPSHOT_PAGES {
            bail!("fairplayd data pages exceed checkpoint budget");
        }
        data_pages.extend((start..end).step_by(PAGE_BYTES as usize));
    }
    let mut by_name = HashMap::<String, u64>::new();
    image
        .relocate(image_base, |name| {
            if let Some(&address) = by_name.get(name) {
                return Ok(address);
            }
            if by_name.len() >= MAX_EXTERNALS {
                bail!("fairplayd has too many external imports");
            }
            let offset = (by_name.len() as u64)
                .checked_mul(EXTERNAL_STRIDE)
                .context("fairplayd external address overflow")?;
            let address = EXTERNAL_BASE
                .checked_add(offset)
                .context("fairplayd external address overflow")?;
            by_name.insert(name.to_owned(), address);
            Ok(address)
        })
        .context("relocate fairplayd chained fixups")?;
    let regions = image.mapped_regions()?;
    image.load(engine).context("load fairplayd into Unicorn")?;
    let externals = by_name
        .into_iter()
        .map(|(name, address)| (address, name))
        .collect();
    Ok(LoadedFairplayd {
        regions,
        externals,
        image_base,
        fixups,
        data_pages,
    })
}

pub struct CheckpointRunner {
    pub engine: Engine,
    pub image: LoadedFairplayd,
    pub checkpoint_pages: usize,
    pub start_pc: u64,
}

impl CheckpointRunner {
    pub fn new(checkpoint: &FairplayCheckpoint, binary: &[u8]) -> Result<Self> {
        let actual_hash: [u8; 32] = Sha256::digest(binary).into();
        if actual_hash != checkpoint.binary_hash {
            bail!("fairplayd SHA-256 does not match checkpoint");
        }
        let mut engine = Engine::new().context("create FairPlay ARM64 emulator")?;
        let image = load_fairplayd(&mut engine, binary)?;
        let checkpoint_pages = checkpoint
            .restore_into(&mut engine, &image.regions)
            .context("restore FairPlay checkpoint")?;
        let start_pc = checkpoint.pc()?;
        if !image.regions.iter().any(|region| {
            region.address <= start_pc
                && region
                    .address
                    .checked_add(region.size)
                    .is_some_and(|end| start_pc < end)
        }) {
            bail!("checkpoint PC is outside the fairplayd image");
        }
        Ok(Self {
            engine,
            image,
            checkpoint_pages,
            start_pc,
        })
    }

    pub fn run_until(
        &mut self,
        stop_pc: u64,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<()> {
        if instruction_limit == 0 || instruction_limit > 100_000_000 {
            bail!("FairPlay instruction limit is outside the bounded range");
        }
        let start = self.engine.reg_read(REG_PC)?;
        if start == stop_pc {
            return Ok(());
        }
        if let Err(error) = self
            .engine
            .start_bounded(start, stop_pc, timeout, instruction_limit)
        {
            let actual = self.engine.reg_read(REG_PC).unwrap_or(start);
            if let Some(name) = self.image.externals.get(&actual) {
                bail!("FairPlay reached unmodeled external {name} at {actual:#x}: {error:#}");
            }
            return Err(error).with_context(|| format!("resume FairPlay checkpoint at {start:#x}"));
        }
        let actual = self.engine.reg_read(REG_PC)?;
        if actual != stop_pc {
            if let Some(name) = self.image.externals.get(&actual) {
                bail!("FairPlay reached unmodeled external {name} at {actual:#x}");
            }
            bail!("FairPlay stopped at {actual:#x} before target {stop_pc:#x}");
        }
        Ok(())
    }

    /// Save a private schema-2 checkpoint that Python and Rust can both resume.
    pub fn write_checkpoint(
        &self,
        source: &FairplayCheckpoint,
        binary_path: &Path,
        output: &Path,
    ) -> Result<usize> {
        let mut addresses: BTreeSet<u64> = source.page_addresses()?.into_iter().collect();
        addresses.extend(self.image.data_pages.iter().copied());
        if addresses.is_empty() || addresses.len() > MAX_SNAPSHOT_PAGES {
            bail!("FairPlay output checkpoint page count is outside the bounded range");
        }
        let mut pages = SensitiveValue(Value::Dict(BTreeMap::new()));
        let Value::Dict(ref mut page_map) = pages.0 else {
            unreachable!();
        };
        for &address in &addresses {
            let bytes = self
                .engine
                .mem_read(address, PAGE_BYTES as usize)
                .with_context(|| format!("snapshot FairPlay page {address:#x}"))?;
            page_map.insert(
                HashableValue::I64(i64::try_from(address)?),
                Value::Bytes(bytes),
            );
        }
        let mut registers = BTreeMap::new();
        for index in 0..31 {
            let register = match index {
                29 => 1,
                30 => 2,
                _ => 199 + index,
            };
            registers.insert(
                HashableValue::String(format!("x{index}")),
                Value::Int(self.engine.reg_read(register)?.into()),
            );
        }
        registers.insert(
            HashableValue::String("sp".into()),
            Value::Int(self.engine.reg_read(4)?.into()),
        );
        for index in 0..32 {
            let bytes = self.engine.reg_read_128(228 + index)?;
            registers.insert(
                HashableValue::String(format!("v{index}")),
                Value::Int(u128::from_le_bytes(bytes).into()),
            );
        }
        let flags = self.engine.reg_read(3)?;
        let nzcv = ["n", "z", "c", "v"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    HashableValue::String(name.into()),
                    Value::I64(((flags >> (31 - index)) & 1) as i64),
                )
            })
            .collect();
        let binary = std::fs::canonicalize(binary_path).context("resolve fairplayd path")?;
        let binary = binary
            .to_str()
            .context("fairplayd path is not UTF-8")?
            .to_owned();
        let pc = self.engine.reg_read(REG_PC)?;
        let mut root = SensitiveValue(source.clone_root()?);
        let Value::Dict(ref mut fields) = root.0 else {
            bail!("checkpoint root is not a dictionary");
        };
        let updates = [
            ("schema", Value::I64(2)),
            ("binary", Value::String(binary)),
            ("pc", Value::String(format!("{pc:#x}"))),
            ("registers", Value::Dict(registers)),
            ("nzcv", Value::Dict(nzcv)),
            ("memory_pages", std::mem::replace(&mut pages.0, Value::None)),
        ];
        for (name, value) in updates {
            if let Some(mut old) = fields.insert(HashableValue::String(name.into()), value) {
                clear_value(&mut old);
            }
        }
        let serialized = serde_pickle::value_to_vec(&root.0, SerOptions::new())
            .context("serialize FairPlay checkpoint");
        let serialized = Zeroizing::new(serialized?);
        if serialized.len() > 128 * 1024 * 1024 {
            bail!("FairPlay output checkpoint exceeds decompressed size limit");
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&serialized)?;
        let compressed = Zeroizing::new(encoder.finish()?);
        write_private_binary(output, &compressed)?;
        Ok(addresses.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_BINARY: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-run-synthetic.macho");
    const SYNTHETIC_CHECKPOINT: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-run-synthetic.pkl.gz");

    #[test]
    fn resumes_checked_macho_and_checkpoint_to_target() {
        let checkpoint = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        assert!(CheckpointRunner::new(&checkpoint, b"wrong fairplayd").is_err());
        let mut runner = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        assert_eq!(runner.checkpoint_pages, 1);
        assert_eq!(runner.image.fixups, 0);
        let stop = checkpoint.pc().unwrap() + 8;
        assert!(runner.run_until(stop, Duration::from_secs(2), 1).is_err());
        let mut runner = CheckpointRunner::new(&checkpoint, SYNTHETIC_BINARY).unwrap();
        runner.run_until(stop, Duration::from_secs(2), 8).unwrap();
        assert_eq!(runner.engine.reg_read(199).unwrap(), 43);
    }

    #[test]
    fn writes_private_checkpoint_that_can_be_restored() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let binary_path = directory.path().join("fairplayd.arm64e");
        let output_path = directory.path().join("resumed.pkl.gz");
        std::fs::write(&binary_path, SYNTHETIC_BINARY).unwrap();
        let source = FairplayCheckpoint::parse_gzip(SYNTHETIC_CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&source, SYNTHETIC_BINARY).unwrap();
        let stop = source.pc().unwrap() + 8;
        runner.run_until(stop, Duration::from_secs(2), 8).unwrap();
        let pages = runner
            .write_checkpoint(&source, &binary_path, &output_path)
            .unwrap();
        assert_eq!(pages, 1);
        let resumed = FairplayCheckpoint::load_private(&output_path).unwrap();
        assert_eq!(resumed.pc().unwrap(), stop);
        assert_eq!(resumed.register_u64("x0").unwrap(), 43);
        assert_eq!(resumed.binary_hash, source.binary_hash);
        assert_eq!(
            resumed.page_addresses().unwrap(),
            source.page_addresses().unwrap()
        );
        let replay = CheckpointRunner::new(&resumed, SYNTHETIC_BINARY).unwrap();
        assert_eq!(replay.engine.reg_read(199).unwrap(), 43);
    }

    #[test]
    #[ignore = "requires the host's Apple fairplayd image"]
    fn loads_local_fairplayd_into_unicorn_when_available() {
        let path = "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd";
        let Ok(binary) = std::fs::read(path) else {
            return;
        };
        let mut engine = Engine::new().unwrap();
        let loaded = load_fairplayd(&mut engine, &binary).unwrap();
        assert!(loaded.fixups > 100);
        assert!(!loaded.externals.is_empty());
        assert!(!loaded.regions.is_empty());
        let bytes = engine.mem_read(loaded.image_base, 4).unwrap();
        assert_eq!(bytes.len(), 4);
    }
}
