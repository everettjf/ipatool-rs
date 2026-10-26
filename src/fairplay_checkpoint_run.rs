//! Load a matching fairplayd image and resume a private checkpoint for a
//! bounded span. External imports are intentionally left as named stubs until
//! the corresponding FairPlay host services are modeled in Rust.

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::{
    fairplay_checkpoint::FairplayCheckpoint,
    machimage::Image,
    store_memory::MemoryRegion,
    unicorn_runtime::{Engine, REG_PC},
};

const EXTERNAL_BASE: u64 = 0xf100_0000_0000_0000;
const EXTERNAL_STRIDE: u64 = 0x1000;
const MAX_EXTERNALS: usize = 1 << 20;

pub struct LoadedFairplayd {
    pub regions: Vec<MemoryRegion>,
    pub externals: HashMap<u64, String>,
    pub image_base: u64,
    pub fixups: usize,
}

/// Load the exact arm64e image with chained rebases and deterministic external
/// bind addresses. The caller owns the engine and can install import hooks.
pub fn load_fairplayd(engine: &mut Engine, binary: &[u8]) -> Result<LoadedFairplayd> {
    let mut image = Image::open("fairplayd", binary).context("parse fairplayd arm64e Mach-O")?;
    let image_base = image.base();
    let fixups = image.fixup_count();
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
