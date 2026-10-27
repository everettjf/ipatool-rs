//! Learn the checked 26B118 indexed-fault domains from repeated checkpoint runs.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    fairplay_26b118::{self, BUILD_HASH, required_index_sites},
    fairplay_checkpoint::FairplayCheckpoint,
    fairplay_checkpoint_run::CheckpointRunner,
    fairplay_oracle_model::{FaultKind, OracleFault, OracleModel},
    fairplay_recovery_target::deterministic_input,
    unicorn_runtime::{Engine, HookContext, REG_PC, REG_X0},
};

const ENTRY: u64 = 0x1002_21894;
const STOP: u64 = 0x1002_23a30;
const BLOCK: u64 = 0x7100_0001_4ee0;
const PAGE_BYTES: u64 = 4096;
const MAX_INPUTS: usize = 20_000;
const INSTRUCTION_LIMIT: usize = 200_000;
const REG_X29: i32 = 1;
const REG_X30: i32 = 2;
const REG_SP: i32 = 4;
const REG_NZCV: i32 = 3;
const REG_V0: i32 = 228;

struct CpuSnapshot {
    general: Zeroizing<[u64; 31]>,
    vector: Zeroizing<[[u8; 16]; 32]>,
    sp: u64,
    nzcv: u64,
    pc: u64,
}

fn register_id(index: usize) -> i32 {
    match index {
        29 => REG_X29,
        30 => REG_X30,
        _ => REG_X0 + index as i32,
    }
}

impl CpuSnapshot {
    fn capture(engine: &Engine) -> Result<Self> {
        let mut general = Zeroizing::new([0; 31]);
        for (index, value) in general.iter_mut().enumerate() {
            *value = engine.reg_read(register_id(index))?;
        }
        let mut vector = Zeroizing::new([[0; 16]; 32]);
        for (index, value) in vector.iter_mut().enumerate() {
            *value = engine.reg_read_128(REG_V0 + index as i32)?;
        }
        Ok(Self {
            general,
            vector,
            sp: engine.reg_read(REG_SP)?,
            nzcv: engine.reg_read(REG_NZCV)?,
            pc: engine.reg_read(REG_PC)?,
        })
    }

    fn restore(&self, engine: &mut Engine) -> Result<()> {
        for (index, &value) in self.general.iter().enumerate() {
            engine.reg_write(register_id(index), value)?;
        }
        for (index, &value) in self.vector.iter().enumerate() {
            engine.reg_write_128(REG_V0 + index as i32, value)?;
        }
        engine.reg_write(REG_SP, self.sp)?;
        engine.reg_write(REG_NZCV, self.nzcv)?;
        engine.reg_write(REG_PC, self.pc)?;
        Ok(())
    }
}

type DirtyPages = BTreeMap<u64, Zeroizing<Vec<u8>>>;
type CapturedValues = BTreeMap<(u64, u8), BTreeSet<u64>>;

#[derive(Default)]
struct FaultProbe {
    fault: Option<OracleFault>,
    domain: Option<Zeroizing<[u64; 256]>>,
    applied: bool,
    restore: Option<(u64, i32, u64)>,
}

fn apply_fault_probe(context: &HookContext, pc: u64, probe: &mut FaultProbe) -> Result<()> {
    if let Some((restore_pc, register, value)) = probe.restore
        && pc == restore_pc
    {
        context.reg_write(register, value)?;
        probe.restore = None;
    }
    let Some(fault) = probe.fault else {
        return Ok(());
    };
    if probe.applied || pc != fault.pc {
        return Ok(());
    }
    let register = register_id(fault.register as usize);
    let raw = context.reg_read(register)?;
    let (original, altered) = match fault.kind {
        FaultKind::Index => {
            let original = raw as u32 as u64;
            let domain = probe.domain.as_ref().context("index fault has no domain")?;
            let position = domain
                .binary_search(&original)
                .map_err(|_| anyhow::anyhow!("index value {original:#x} is outside its domain"))?;
            (original, domain[position ^ fault.value as usize])
        }
        FaultKind::IndexAfter => {
            let original = raw as u32 as u64;
            let altered =
                (original as u32 ^ (fault.value as u32).wrapping_shl(fault.shift as u32)) as u64;
            (original, altered)
        }
        FaultKind::Pointer => {
            let table_bytes = u64::from(fault.table_bytes);
            let entry_bytes = u64::from(fault.entry_bytes);
            if !table_bytes.is_power_of_two() || entry_bytes == 0 {
                bail!("invalid pointer fault table geometry");
            }
            let table_base = raw & !(table_bytes - 1);
            let offset = raw - table_base;
            if offset >= table_bytes || offset % entry_bytes != 0 {
                bail!("pointer fault value {raw:#x} is outside its table");
            }
            let position = offset / entry_bytes;
            if position >= 256 {
                bail!("pointer fault position is outside the byte domain");
            }
            let altered = table_base
                .checked_add((position ^ u64::from(fault.value)) * entry_bytes)
                .context("pointer fault address overflow")?;
            (raw, altered)
        }
        FaultKind::None => bail!("cannot inject an empty oracle fault"),
    };
    context.reg_write(register, altered)?;
    if fault.restore {
        probe.restore = Some((
            pc.checked_add(4).context("fault PC overflow")?,
            register,
            original,
        ));
    }
    probe.applied = true;
    Ok(())
}

fn record_original_pages(
    context: &HookContext,
    address: u64,
    size: u32,
    dirty: &RefCell<DirtyPages>,
) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let last = address
        .checked_add(u64::from(size) - 1)
        .context("oracle write address overflow")?
        & !(PAGE_BYTES - 1);
    let mut page = address & !(PAGE_BYTES - 1);
    loop {
        if !dirty.borrow().contains_key(&page) {
            let original = Zeroizing::new(context.mem_read(page, PAGE_BYTES as usize)?);
            dirty.borrow_mut().insert(page, original);
        }
        if page == last {
            break;
        }
        page = page
            .checked_add(PAGE_BYTES)
            .context("oracle page overflow")?;
    }
    Ok(())
}

struct ReplayRunner {
    runner: CheckpointRunner,
    cpu: CpuSnapshot,
    initial_allocation_next: u64,
    block: u64,
    stop: u64,
    timeout: Duration,
    dirty: Rc<RefCell<DirtyPages>>,
    captured: Rc<RefCell<CapturedValues>>,
    fault_probe: Rc<RefCell<FaultProbe>>,
    hook_error: Rc<RefCell<Option<String>>>,
}

impl ReplayRunner {
    fn new(
        mut runner: CheckpointRunner,
        block: u64,
        stop: u64,
        sites: &BTreeSet<(u64, u8)>,
        fault_sites: &[OracleFault],
        timeout: Duration,
    ) -> Result<Self> {
        if timeout.is_zero()
            || (sites.is_empty() && fault_sites.is_empty())
            || sites.len() > 64
            || fault_sites.len() > 64
        {
            bail!("oracle replay configuration is invalid");
        }
        let cpu = CpuSnapshot::capture(&runner.engine)?;
        let initial_allocation_next = runner.replay_allocation_cursor();
        let dirty = Rc::new(RefCell::new(BTreeMap::new()));
        let captured = Rc::new(RefCell::new(
            sites
                .iter()
                .copied()
                .map(|site| (site, BTreeSet::new()))
                .collect::<CapturedValues>(),
        ));
        let fault_probe = Rc::new(RefCell::new(FaultProbe::default()));
        let hook_error = Rc::new(RefCell::new(None));
        {
            let dirty = Rc::clone(&dirty);
            let failure = Rc::clone(&hook_error);
            runner
                .engine
                .add_memory_write_hook(move |context, address, size| {
                    if let Err(error) = record_original_pages(context, address, size, &dirty) {
                        *failure.borrow_mut() = Some(format!("capture oracle write: {error:#}"));
                        let _ = context.stop();
                    }
                })?;
        }
        for &(pc, register) in sites {
            if register >= 31 {
                bail!("oracle index register is out of range");
            }
            let captured = Rc::clone(&captured);
            let failure = Rc::clone(&hook_error);
            runner.engine.add_code_hook(pc, pc, move |context, _, _| {
                let value = context.reg_read(register_id(register as usize));
                match value {
                    Ok(value) => {
                        captured
                            .borrow_mut()
                            .get_mut(&(pc, register))
                            .expect("installed oracle capture site")
                            .insert(value as u32 as u64);
                    }
                    Err(error) => {
                        *failure.borrow_mut() = Some(format!("capture oracle index: {error:#}"));
                        let _ = context.stop();
                    }
                }
            })?;
        }
        let mut fault_pcs = BTreeSet::new();
        for fault in fault_sites {
            if fault.kind == FaultKind::None || fault.register >= 31 {
                bail!("oracle fault site is invalid");
            }
            fault_pcs.insert(fault.pc);
            if fault.restore {
                fault_pcs.insert(fault.pc.checked_add(4).context("fault PC overflow")?);
            }
        }
        for pc in fault_pcs {
            let probe = Rc::clone(&fault_probe);
            let failure = Rc::clone(&hook_error);
            runner
                .engine
                .add_code_hook(pc, pc, move |context, address, _| {
                    if let Err(error) = apply_fault_probe(context, address, &mut probe.borrow_mut())
                    {
                        *failure.borrow_mut() = Some(format!("inject oracle fault: {error:#}"));
                        let _ = context.stop();
                    }
                })?;
        }
        Ok(Self {
            runner,
            cpu,
            initial_allocation_next,
            block,
            stop,
            timeout,
            dirty,
            captured,
            fault_probe,
            hook_error,
        })
    }

    fn restore(&mut self) -> Result<()> {
        let new_pages = self.runner.replay_new_pages();
        let originals = std::mem::take(&mut *self.dirty.borrow_mut());
        for (page, bytes) in originals {
            if !new_pages.contains(&page) {
                self.runner.engine.mem_write(page, &bytes)?;
            }
        }
        self.runner
            .reset_replay_allocations(self.initial_allocation_next)?;
        self.cpu.restore(&mut self.runner.engine)?;
        Ok(())
    }

    fn run_block(&mut self, input: &[u8; 16]) -> Result<[u8; 16]> {
        let first = self.block & !(PAGE_BYTES - 1);
        let last = self
            .block
            .checked_add(15)
            .context("oracle block address overflow")?
            & !(PAGE_BYTES - 1);
        for page in (first..=last).step_by(PAGE_BYTES as usize) {
            let original = Zeroizing::new(self.runner.engine.mem_read(page, PAGE_BYTES as usize)?);
            self.dirty.borrow_mut().insert(page, original);
        }
        self.runner.engine.mem_write(self.block, input)?;
        let execution = self
            .runner
            .run_until(self.stop, self.timeout, INSTRUCTION_LIMIT)
            .and_then(|()| {
                let bytes = self.runner.engine.mem_read(self.block, 16)?;
                Ok(bytes.try_into().expect("read exactly one oracle block"))
            });
        let hook_error = self.hook_error.borrow_mut().take();
        let fault_applied = {
            let probe = self.fault_probe.borrow();
            probe.fault.is_none() || probe.applied
        };
        let restoration = self.restore();
        if let Some(error) = hook_error {
            bail!("{error}");
        }
        let output = execution?;
        restoration?;
        if !fault_applied {
            bail!("oracle execution did not reach the requested fault site");
        }
        Ok(output)
    }

    fn run_fault_block(
        &mut self,
        input: &[u8; 16],
        fault: OracleFault,
        domain: Option<&[u64; 256]>,
    ) -> Result<[u8; 16]> {
        *self.fault_probe.borrow_mut() = FaultProbe {
            fault: Some(fault),
            domain: domain.map(|values| Zeroizing::new(*values)),
            applied: false,
            restore: None,
        };
        let result = self.run_block(input);
        *self.fault_probe.borrow_mut() = FaultProbe::default();
        result
    }

    fn domains_complete(&self) -> bool {
        self.captured
            .borrow()
            .values()
            .all(|values| values.len() == 256)
    }
}

#[derive(Serialize)]
struct DomainRow {
    pc: String,
    register: u8,
    values: Vec<String>,
}

#[derive(Serialize)]
struct DomainReport {
    schema: &'static str,
    binary_sha256: String,
    inputs: usize,
    domains: Vec<DomainRow>,
}

pub struct LearnedDomains {
    pub json: Zeroizing<Vec<u8>>,
    pub inputs: usize,
    pub domains: usize,
}

pub fn learn_26b118_domains(
    checkpoint: &FairplayCheckpoint,
    binary: &[u8],
    maximum_inputs: usize,
    timeout: Duration,
) -> Result<LearnedDomains> {
    if checkpoint.binary_hash != BUILD_HASH || checkpoint.pc()? != ENTRY {
        bail!("index-domain checkpoint does not match the checked 26B118 entry");
    }
    if !(1..=MAX_INPUTS).contains(&maximum_inputs) {
        bail!("index-domain input limit is outside the bounded range");
    }
    let runner = CheckpointRunner::new(checkpoint, binary)?;
    let sites = required_index_sites();
    let mut replay = ReplayRunner::new(runner, BLOCK, STOP, &sites, &[], timeout)?;
    let mut inputs = 0;
    for index in 0..maximum_inputs {
        let mut hash = Sha256::new();
        hash.update(b"macOS FairPlay encoded fault domain");
        hash.update((index as u64).to_be_bytes());
        let digest = hash.finalize();
        let block: [u8; 16] = digest[..16].try_into().unwrap();
        replay
            .run_block(&block)
            .with_context(|| format!("learn 26B118 index domains from input {index}"))?;
        inputs += 1;
        if replay.domains_complete() {
            break;
        }
    }
    let captured = replay.captured.borrow();
    if captured.values().any(|values| values.len() != 256) {
        let counts = captured
            .iter()
            .filter(|(_, values)| values.len() != 256)
            .map(|(&(pc, register), values)| format!("{pc:#x}/x{register}={}", values.len()))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("incomplete 26B118 encoded index domains: {counts}");
    }
    let report = DomainReport {
        schema: "fairplay.index-domains.v1",
        binary_sha256: format!("{:x}", Sha256::digest(binary)),
        inputs,
        domains: captured
            .iter()
            .map(|(&(pc, register), values)| DomainRow {
                pc: format!("{pc:#x}"),
                register,
                values: values.iter().map(|value| format!("{value:#x}")).collect(),
            })
            .collect(),
    };
    let json = Zeroizing::new(serde_json::to_vec(&report)?);
    Ok(LearnedDomains {
        json,
        inputs,
        domains: sites.len(),
    })
}

pub struct DifferentialResult {
    pub cases: usize,
    pub domains: usize,
    pub output_sha256: String,
}

/// Compare the checked Rust evaluator with native checkpoint execution for
/// the original block, deterministic inputs, and every 26B118 fault site at
/// three XOR values.
pub fn validate_26b118_model(
    checkpoint: &FairplayCheckpoint,
    binary: &[u8],
    model: &OracleModel,
    timeout: Duration,
    normal_cases: usize,
) -> Result<DifferentialResult> {
    if normal_cases > 256 {
        bail!("26B118 differential normal case count exceeds 256");
    }
    if checkpoint.binary_hash != BUILD_HASH
        || checkpoint.pc()? != ENTRY
        || model.binary_hash != BUILD_HASH
        || model.block_address != BLOCK
    {
        bail!("26B118 differential inputs do not match the checked build and entry");
    }
    let required = required_index_sites();
    if model.domain_count() != required.len()
        || required
            .iter()
            .any(|&(pc, register)| model.domain(pc, register).is_none())
    {
        bail!("26B118 differential requires all seventeen learned index domains");
    }
    let mut metadata = Vec::with_capacity(48 * 3);
    let mut faults = Vec::with_capacity(48);
    for round in [6u32, 8, 9] {
        for byte in 0..16u32 {
            let first = round | (byte << 16) | (1 << 24);
            faults.push(fairplay_26b118::fault_for_metadata(first)?);
            for value in [1u32, 7, 255] {
                metadata.push(round | (byte << 16) | (value << 24));
            }
        }
    }
    let input = checkpoint.read_block::<16>(BLOCK)?;
    let runner = CheckpointRunner::new(checkpoint, binary)?;
    let mut replay = ReplayRunner::new(runner, BLOCK, STOP, &BTreeSet::new(), &faults, timeout)?;
    let mut hash = Sha256::new();
    let baseline = replay.run_block(&input)?;
    if baseline != fairplay_26b118::evaluate(model, &input, u32::MAX)? {
        bail!("26B118 Rust evaluator differs from native execution without a fault");
    }
    hash.update(baseline);
    for index in 0..normal_cases {
        let block = deterministic_input(index as u32);
        let native = replay
            .run_block(&block)
            .with_context(|| format!("native 26B118 normal case {index}"))?;
        let rust = fairplay_26b118::evaluate(model, &block, u32::MAX)?;
        if native != rust {
            bail!("26B118 Rust evaluator differs from native normal case {index}");
        }
        hash.update(native);
    }
    for (index, &metadata) in metadata.iter().enumerate() {
        let fault = fairplay_26b118::fault_for_metadata(metadata)?;
        let domain = match fault.kind {
            FaultKind::Index => model.domain(fault.pc, fault.register),
            FaultKind::IndexAfter => None,
            FaultKind::Pointer => None,
            FaultKind::None => bail!("differential case has no fault"),
        };
        let native = replay
            .run_fault_block(&input, fault, domain)
            .with_context(|| format!("native 26B118 differential case {index} ({metadata:#x})"))?;
        let rust = fairplay_26b118::evaluate(model, &input, metadata)?;
        if native != rust {
            bail!("26B118 Rust evaluator differs from native case {index} ({metadata:#x})");
        }
        hash.update(native);
    }
    Ok(DifferentialResult {
        cases: metadata.len() + normal_cases + 1,
        domains: required.len(),
        output_sha256: format!("{:x}", hash.finalize()),
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
    fn replay_restores_cpu_and_guest_memory_before_each_input() {
        let checkpoint = FairplayCheckpoint::parse_gzip(CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&checkpoint, BINARY).unwrap();
        runner.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_map(0x4000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_write(0x3000, &0xf940_0020u32.to_le_bytes())
            .unwrap(); // ldr x0, [x1]
        runner
            .engine
            .mem_write(0x3004, &0x9100_0400u32.to_le_bytes())
            .unwrap(); // add x0, x0, #1
        runner
            .engine
            .mem_write(0x3008, &0xf900_0420u32.to_le_bytes())
            .unwrap(); // str x0, [x1,#8]
        runner.engine.reg_write(REG_PC, 0x3000).unwrap();
        runner.engine.reg_write(REG_X0 + 1, 0x4000).unwrap();
        let mut replay = ReplayRunner::new(
            runner,
            0x4000,
            0x300c,
            &BTreeSet::from([(0x3004, 0)]),
            &[],
            Duration::from_secs(2),
        )
        .unwrap();
        replay.run_block(&[1; 16]).unwrap();
        assert_eq!(replay.runner.engine.reg_read(REG_PC).unwrap(), 0x3000);
        assert_eq!(replay.runner.engine.mem_read(0x4000, 16).unwrap(), [0; 16]);
        replay.run_block(&[2; 16]).unwrap();
        let values = &replay.captured.borrow()[&(0x3004, 0)];
        assert_eq!(values.len(), 2);
        assert!(values.contains(&0x0101_0101));
        assert!(values.contains(&0x0202_0202));
        assert_eq!(replay.runner.engine.mem_read(0x4000, 16).unwrap(), [0; 16]);
    }

    #[test]
    fn replay_injects_index_fault_and_restores_register_when_requested() {
        let checkpoint = FairplayCheckpoint::parse_gzip(CHECKPOINT).unwrap();
        let mut runner = CheckpointRunner::new(&checkpoint, BINARY).unwrap();
        runner.engine.mem_map(0x3000, PAGE_BYTES as usize).unwrap();
        runner.engine.mem_map(0x4000, PAGE_BYTES as usize).unwrap();
        runner
            .engine
            .mem_write(0x3000, &0xf940_0020u32.to_le_bytes())
            .unwrap();
        runner
            .engine
            .mem_write(0x3004, &0x9100_0400u32.to_le_bytes())
            .unwrap();
        runner
            .engine
            .mem_write(0x3008, &0xf900_0420u32.to_le_bytes())
            .unwrap();
        runner.engine.reg_write(REG_PC, 0x3000).unwrap();
        runner.engine.reg_write(REG_X0 + 1, 0x4000).unwrap();
        let fault = OracleFault {
            pc: 0x3004,
            register: 0,
            shift: 0,
            value: 7,
            kind: FaultKind::Index,
            restore: true,
            table_bytes: 0,
            entry_bytes: 0,
        };
        let mut replay = ReplayRunner::new(
            runner,
            0x4000,
            0x300c,
            &BTreeSet::new(),
            &[fault],
            Duration::from_secs(2),
        )
        .unwrap();
        let domain = std::array::from_fn(|index| 0x0101_0100 + index as u64);
        let without_restore = replay
            .run_fault_block(
                &[1; 16],
                OracleFault {
                    restore: false,
                    ..fault
                },
                Some(&domain),
            )
            .unwrap();
        assert_eq!(&without_restore[8..], &[7, 1, 1, 1, 0, 0, 0, 0]);
        let with_restore = replay
            .run_fault_block(&[1; 16], fault, Some(&domain))
            .unwrap();
        assert_eq!(&with_restore[8..], &[1, 1, 1, 1, 0, 0, 0, 0]);
        let pointer_fault = OracleFault {
            kind: FaultKind::Pointer,
            table_bytes: 0x400,
            entry_bytes: 4,
            ..fault
        };
        let mut pointer_input = [0u8; 16];
        pointer_input[..8].copy_from_slice(&0x4004u64.to_le_bytes());
        let pointer_output = replay
            .run_fault_block(&pointer_input, pointer_fault, None)
            .unwrap();
        assert_eq!(&pointer_output[8..], &0x4004u64.to_le_bytes());
        let pointer_output = replay
            .run_fault_block(
                &pointer_input,
                OracleFault {
                    restore: false,
                    ..pointer_fault
                },
                None,
            )
            .unwrap();
        assert_eq!(&pointer_output[8..], &0x4019u64.to_le_bytes());
        let after_output = replay
            .run_fault_block(
                &[1; 16],
                OracleFault {
                    kind: FaultKind::IndexAfter,
                    shift: 8,
                    restore: false,
                    ..fault
                },
                None,
            )
            .unwrap();
        assert_eq!(&after_output[8..], &0x0101_0602u64.to_le_bytes());
        assert_eq!(replay.runner.engine.reg_read(REG_PC).unwrap(), 0x3000);
        assert_eq!(replay.runner.engine.mem_read(0x4000, 16).unwrap(), [0; 16]);
    }
}
