//! Export the checked 26A428 oracle's private model directly from a checkpoint
//! and a guest-memory trace, without Python or a generated Go executable.

use std::{collections::BTreeSet, io::Write, path::Path};

use anyhow::{Context, Result, bail};
use flate2::{Compression, write::GzEncoder};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    fairplay_checkpoint::FairplayCheckpoint, fairplay_checkpoint_run::CheckpointRunner,
    fairplay_frame::BUILD_HASH, fairplay_oracle_model::OracleModel,
    fairplay_recovery_output::open_private_file,
};

const MAGIC: &[u8; 8] = b"FPGOOR1\0";
const VERSION: u32 = 2;
const PAGE_BYTES: u64 = 4096;
const MAX_PAGES: usize = 4096;
const MAX_TRACE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TRACE_EVENTS: usize = 2_000_000;
const ENTRY_26A428: u64 = 0x1002_34cdc;
const BLOCK_26A428: u64 = 0x7100_0001_4ee8;

#[derive(Deserialize)]
struct TraceEvent {
    address: String,
}

#[derive(Deserialize)]
struct MemoryTraceReport {
    binary_sha256: String,
    memory_read_events: Vec<TraceEvent>,
    memory_write_events: Vec<TraceEvent>,
}

pub struct ExportedOracleModel {
    pub compressed: Zeroizing<Vec<u8>>,
    pub pages: usize,
}

pub fn export_26a428_model(
    checkpoint: &FairplayCheckpoint,
    binary: &[u8],
    trace_path: &Path,
) -> Result<ExportedOracleModel> {
    if checkpoint.binary_hash != BUILD_HASH || checkpoint.pc()? != ENTRY_26A428 {
        bail!("oracle checkpoint does not match the checked 26A428 entry");
    }
    let file = open_private_file(trace_path, None, MAX_TRACE_BYTES)?;
    let trace: MemoryTraceReport =
        serde_json::from_reader(file).context("decode private FairPlay memory trace")?;
    build_model(checkpoint, binary, trace, ENTRY_26A428, BLOCK_26A428)
}

fn event_page(event: &TraceEvent) -> Result<u64> {
    let digits = event
        .address
        .strip_prefix("0x")
        .context("FairPlay trace address is not hexadecimal")?;
    let address = u64::from_str_radix(digits, 16).context("invalid FairPlay trace address")?;
    if address >= 0xf000_0000_0000_0000 {
        bail!("FairPlay trace address is outside guest memory");
    }
    Ok(address & !(PAGE_BYTES - 1))
}

fn build_model(
    checkpoint: &FairplayCheckpoint,
    binary: &[u8],
    trace: MemoryTraceReport,
    entry: u64,
    block: u64,
) -> Result<ExportedOracleModel> {
    if checkpoint.pc()? != entry {
        bail!("FairPlay checkpoint PC does not match the oracle entry");
    }
    if trace.binary_sha256 != format!("{:x}", Sha256::digest(binary)) {
        bail!("FairPlay memory trace does not match the checkpoint build");
    }
    let mut pages = BTreeSet::new();
    let total_events = trace
        .memory_read_events
        .len()
        .checked_add(trace.memory_write_events.len())
        .context("FairPlay trace event count overflow")?;
    if total_events == 0 || total_events > MAX_TRACE_EVENTS {
        bail!("FairPlay trace event count is outside the bounded range");
    }
    for event in trace
        .memory_read_events
        .iter()
        .chain(&trace.memory_write_events)
    {
        pages.insert(event_page(event)?);
        if pages.len() > MAX_PAGES {
            bail!("FairPlay oracle model exceeds page limit");
        }
    }
    if !pages.contains(&(block & !(PAGE_BYTES - 1))) {
        bail!("FairPlay trace does not include the oracle input block");
    }
    let runner = CheckpointRunner::new(checkpoint, binary)?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(MAGIC)?;
    encoder.write_all(&VERSION.to_le_bytes())?;
    encoder.write_all(&checkpoint.binary_hash)?;
    encoder.write_all(&block.to_le_bytes())?;
    for index in 0..31 {
        encoder.write_all(&checkpoint.register_u64(&format!("x{index}"))?.to_le_bytes())?;
    }
    encoder.write_all(&checkpoint.register_u64("sp")?.to_le_bytes())?;
    let nzcv = checkpoint.nzcv()?;
    for shift in [31, 30, 29, 28] {
        encoder.write_all(&[((nzcv >> shift) & 1) as u8])?;
    }
    encoder.write_all(&u32::try_from(pages.len())?.to_le_bytes())?;
    for &address in &pages {
        let data = Zeroizing::new(
            runner
                .engine
                .mem_read(address, PAGE_BYTES as usize)
                .with_context(|| format!("read oracle model page {address:#x}"))?,
        );
        encoder.write_all(&address.to_le_bytes())?;
        encoder.write_all(&data)?;
    }
    encoder.write_all(&0u32.to_le_bytes())?; // 26A428 has no learned index domains.
    let compressed = Zeroizing::new(encoder.finish()?);
    OracleModel::parse_gzip(&compressed).context("validate exported FairPlay oracle model")?;
    Ok(ExportedOracleModel {
        compressed,
        pages: pages.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINARY: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-run-synthetic.macho");
    const CHECKPOINT: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-run-synthetic.pkl.gz");

    #[test]
    fn exports_model_pages_from_checkpoint_and_trace() {
        let checkpoint = FairplayCheckpoint::parse_gzip(CHECKPOINT).unwrap();
        let page = checkpoint.page_addresses().unwrap()[0];
        let block = page + 32;
        let trace: MemoryTraceReport = serde_json::from_value(serde_json::json!({
            "schema": "fairplay.checkpoint-memory-trace.v1",
            "binary_sha256": format!("{:x}", Sha256::digest(BINARY)),
            "memory_read_events": [{"ordinal": 0, "pc": "0x1000", "address": format!("{block:#x}"), "size": 8}],
            "memory_write_events": [{"ordinal": 1, "pc": "0x1004", "address": format!("{block:#x}"), "size": 8}],
        }))
        .unwrap();
        let exported =
            build_model(&checkpoint, BINARY, trace, checkpoint.pc().unwrap(), block).unwrap();
        assert_eq!(exported.pages, 1);
        let parsed = OracleModel::parse_gzip(&exported.compressed).unwrap();
        assert_eq!(parsed.binary_hash, checkpoint.binary_hash);
        assert_eq!(parsed.block_address, block);
        assert_eq!(parsed.page_count(), 1);
        assert_eq!(parsed.domain_count(), 0);
        assert_eq!(parsed.registers[0], checkpoint.register_u64("x0").unwrap());
        assert_eq!(
            parsed.state().load(block, 1).unwrap() as u8,
            checkpoint.read_block::<1>(block).unwrap()[0]
        );
    }

    #[test]
    fn rejects_mismatched_trace_and_missing_oracle_block() {
        let checkpoint = FairplayCheckpoint::parse_gzip(CHECKPOINT).unwrap();
        let page = checkpoint.page_addresses().unwrap()[0];
        let trace = MemoryTraceReport {
            binary_sha256: "00".repeat(32),
            memory_read_events: vec![TraceEvent {
                address: format!("{page:#x}"),
            }],
            memory_write_events: vec![],
        };
        assert!(build_model(&checkpoint, BINARY, trace, checkpoint.pc().unwrap(), page).is_err());
        let trace = MemoryTraceReport {
            binary_sha256: format!("{:x}", Sha256::digest(BINARY)),
            memory_read_events: vec![TraceEvent {
                address: format!("{page:#x}"),
            }],
            memory_write_events: vec![],
        };
        assert!(
            build_model(
                &checkpoint,
                BINARY,
                trace,
                checkpoint.pc().unwrap(),
                page + PAGE_BYTES
            )
            .is_err()
        );
    }
}
