//! Export checked FairPlay oracle models from private checkpoints and traces.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
};

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
const HASH_26B118: [u8; 32] = [
    0xf6, 0x8e, 0x44, 0x07, 0xe9, 0x0a, 0xf5, 0x46, 0x6d, 0x27, 0x66, 0xe1, 0xb1, 0xc4, 0x63, 0x72,
    0x60, 0xd0, 0x8c, 0xb0, 0x51, 0x8f, 0x99, 0x1e, 0x17, 0x97, 0xac, 0x6c, 0x49, 0x64, 0x43, 0x9d,
];
const ENTRY_26B118: u64 = 0x1002_21894;
const BLOCK_26B118: u64 = 0x7100_0001_4ee0;
// The index-fault sites in generated_26b118.go. Pointer faults need no domains.
const INDEX_SITES_26B118: &[(u64, u8)] = &[
    (0x1002_22ab0, 14),
    (0x1002_22ac4, 12),
    (0x1002_22ad0, 14),
    (0x1002_22ae0, 1),
    (0x1002_22b98, 8),
    (0x1002_22c54, 9),
    (0x1002_22c58, 9),
    (0x1002_22c74, 9),
    (0x1002_22c84, 15),
    (0x1002_22d14, 19),
    (0x1002_22d20, 19),
    (0x1002_22e04, 9),
    (0x1002_22ea4, 8),
    (0x1002_22eb0, 19),
    (0x1002_22ebc, 21),
    (0x1002_22ecc, 23),
    (0x1002_22ed8, 2),
    (0x1002_22f48, 15),
];
type IndexDomains = BTreeMap<(u64, u8), Zeroizing<[u64; 256]>>;

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

#[derive(Deserialize)]
struct IndexDomainReport {
    binary_sha256: String,
    domains: Vec<IndexDomain>,
}

#[derive(Deserialize)]
struct IndexDomain {
    pc: String,
    register: u8,
    values: Vec<String>,
}

pub struct ExportedOracleModel {
    pub compressed: Zeroizing<Vec<u8>>,
    pub pages: usize,
    pub domains: usize,
}

pub fn export_checked_model(
    checkpoint: &FairplayCheckpoint,
    binary: &[u8],
    trace_path: &Path,
    domains_path: Option<&Path>,
) -> Result<ExportedOracleModel> {
    if checkpoint.binary_hash == BUILD_HASH {
        if domains_path.is_some() {
            bail!("26A428 does not use learned index domains");
        }
        export_26a428_model(checkpoint, binary, trace_path)
    } else if checkpoint.binary_hash == HASH_26B118 {
        let domains_path = domains_path.context("26B118 requires --index-domains")?;
        export_26b118_model(checkpoint, binary, trace_path, domains_path)
    } else {
        bail!("unsupported fairplayd oracle build")
    }
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
    build_model(
        checkpoint,
        binary,
        trace,
        ENTRY_26A428,
        BLOCK_26A428,
        &BTreeMap::new(),
    )
}

/// The checked 26B118 oracle additionally needs all eighteen learned index domains.
/// The private JSON has `binary_sha256` and a `domains` array. Each domain has
/// `pc` (hex string), `register` (0..30), and 256 ordered hex-string `values`.
/// Values are the register contents observed before the indexed load.
pub fn export_26b118_model(
    checkpoint: &FairplayCheckpoint,
    binary: &[u8],
    trace_path: &Path,
    domains_path: &Path,
) -> Result<ExportedOracleModel> {
    if checkpoint.binary_hash != HASH_26B118 || checkpoint.pc()? != ENTRY_26B118 {
        bail!("oracle checkpoint does not match the checked 26B118 entry");
    }
    let trace_file = open_private_file(trace_path, None, MAX_TRACE_BYTES)?;
    let trace: MemoryTraceReport =
        serde_json::from_reader(trace_file).context("decode private FairPlay memory trace")?;
    let domain_file = open_private_file(domains_path, None, 1024 * 1024)?;
    let report: IndexDomainReport =
        serde_json::from_reader(domain_file).context("decode private FairPlay index domains")?;
    let domains = validate_26b118_domains(report, &checkpoint.binary_hash)?;
    build_model(
        checkpoint,
        binary,
        trace,
        ENTRY_26B118,
        BLOCK_26B118,
        &domains,
    )
}

fn parse_hex(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .context("expected 0x-prefixed hex value")?;
    u64::from_str_radix(digits, 16).context("invalid hexadecimal value")
}

fn validate_26b118_domains(
    report: IndexDomainReport,
    binary_hash: &[u8; 32],
) -> Result<IndexDomains> {
    let expected_hash = binary_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if report.binary_sha256 != expected_hash {
        bail!("index domains do not match the checkpoint build");
    }
    let expected: BTreeSet<_> = INDEX_SITES_26B118.iter().copied().collect();
    if report.domains.len() != expected.len() {
        bail!("26B118 requires exactly {} index domains", expected.len());
    }
    let mut domains = BTreeMap::new();
    for domain in report.domains {
        let key = (parse_hex(&domain.pc)?, domain.register);
        if !expected.contains(&key) || domains.contains_key(&key) {
            bail!(
                "unknown or duplicate 26B118 index domain {:#x}/x{}",
                key.0,
                key.1
            );
        }
        if domain.values.len() != 256 {
            bail!(
                "26B118 index domain {:#x}/x{} must have 256 values",
                key.0,
                key.1
            );
        }
        let mut values = Zeroizing::new([0u64; 256]);
        for (index, value) in domain.values.iter().enumerate() {
            values[index] = parse_hex(value)?;
            if values[index] > u32::MAX as u64 || (index > 0 && values[index] <= values[index - 1])
            {
                bail!("26B118 index domain {:#x}/x{} is not ordered", key.0, key.1);
            }
        }
        domains.insert(key, values);
    }
    Ok(domains)
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
    domains: &IndexDomains,
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
    encoder.write_all(&u32::try_from(domains.len())?.to_le_bytes())?;
    for (&(pc, register), values) in domains {
        encoder.write_all(&pc.to_le_bytes())?;
        encoder.write_all(&[register, 0, 0, 0, 0, 0, 0, 0])?;
        for value in values.iter() {
            encoder.write_all(&value.to_le_bytes())?;
        }
    }
    let compressed = Zeroizing::new(encoder.finish()?);
    OracleModel::parse_gzip(&compressed).context("validate exported FairPlay oracle model")?;
    Ok(ExportedOracleModel {
        compressed,
        pages: pages.len(),
        domains: domains.len(),
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
        let exported = build_model(
            &checkpoint,
            BINARY,
            trace,
            checkpoint.pc().unwrap(),
            block,
            &BTreeMap::new(),
        )
        .unwrap();
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
        assert!(
            build_model(
                &checkpoint,
                BINARY,
                trace,
                checkpoint.pc().unwrap(),
                page,
                &BTreeMap::new(),
            )
            .is_err()
        );
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
                page + PAGE_BYTES,
                &BTreeMap::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn validates_complete_26b118_index_domains() {
        let hash = HASH_26B118
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let make_report = || IndexDomainReport {
            binary_sha256: hash.clone(),
            domains: INDEX_SITES_26B118
                .iter()
                .map(|&(pc, register)| IndexDomain {
                    pc: format!("{pc:#x}"),
                    register,
                    values: (0..256).map(|value| format!("{value:#x}")).collect(),
                })
                .collect(),
        };
        let domains = validate_26b118_domains(make_report(), &HASH_26B118).unwrap();
        assert_eq!(domains.len(), 18);
        assert_eq!(domains[&(0x1002_22ab0, 14)][255], 255);

        let mut incomplete = make_report();
        incomplete.domains.pop();
        assert!(validate_26b118_domains(incomplete, &HASH_26B118).is_err());
        let mut unordered = make_report();
        unordered.domains[0].values[255] = "0x0".into();
        assert!(validate_26b118_domains(unordered, &HASH_26B118).is_err());
        let mut wrong_build = make_report();
        wrong_build.binary_sha256 = "00".repeat(32);
        assert!(validate_26b118_domains(wrong_build, &HASH_26B118).is_err());
    }

    #[test]
    fn exports_learned_index_domain_in_model_format() {
        let checkpoint = FairplayCheckpoint::parse_gzip(CHECKPOINT).unwrap();
        let block = checkpoint.page_addresses().unwrap()[0] + 32;
        let trace = MemoryTraceReport {
            binary_sha256: format!("{:x}", Sha256::digest(BINARY)),
            memory_read_events: vec![TraceEvent {
                address: format!("{block:#x}"),
            }],
            memory_write_events: vec![],
        };
        let domain = Zeroizing::new(core::array::from_fn(|index| index as u64 * 4));
        let domains = BTreeMap::from([((0x1002_22ab0, 14), domain)]);
        let exported = build_model(
            &checkpoint,
            BINARY,
            trace,
            checkpoint.pc().unwrap(),
            block,
            &domains,
        )
        .unwrap();
        assert_eq!(exported.domains, 1);
        let parsed = OracleModel::parse_gzip(&exported.compressed).unwrap();
        assert_eq!(parsed.domain(0x1002_22ab0, 14).unwrap()[255], 1020);
    }
}
