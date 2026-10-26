//! Bounded ARM64 guest calls used by the SAP and StoreAgent runtimes.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::{
    arm64_compat::emulate_invalid_instruction,
    sap_assets::SapAssetBundle,
    sap_images::SapImages,
    sap_shims::SapShims,
    sap_signer::SapGuest,
    unicorn_runtime::{Engine, REG_PC, REG_X0},
};

const RETURN_ADDRESS: u64 = 0x0000_0001_0000_0000;
const SCRATCH_BASE: u64 = 0x0000_3000_0000_0000;
const SCRATCH_SIZE: u64 = 32 << 20;
const HEAP_BASE: u64 = 0x0000_4000_0000_0000;
const HEAP_SIZE: u64 = 64 << 20;
const STACK_BASE: u64 = 0x0000_5000_0000_0000;
const STACK_SIZE: u64 = 8 << 20;
const STACK_END: u64 = STACK_BASE + STACK_SIZE;
const REG_LR: i32 = 2;
const REG_SP: i32 = 4;
const GUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT_SIZE: u64 = 16 << 20;
const STORE_AGENT_ZERO_ALIASES: &[&str] = &[
    "_pthread_rwlock_rdlock",
    "_pthread_rwlock_rdlock$UNIX2003",
    "_pthread_mutex_init",
    "_pthread_mutex_destroy",
    "_pthread_rwlock_destroy",
];

pub struct GuestMachine {
    engine: Engine,
    scratch_cursor: u64,
}

impl GuestMachine {
    pub fn new() -> Result<Self> {
        let mut engine = Engine::new().context("create SAP Unicorn engine")?;
        for (address, size) in [
            (RETURN_ADDRESS, 4096),
            (SCRATCH_BASE, SCRATCH_SIZE),
            (HEAP_BASE, HEAP_SIZE),
            (STACK_BASE, STACK_SIZE),
        ] {
            engine
                .mem_map(address, size as usize)
                .with_context(|| format!("map SAP guest memory at {address:#x}"))?;
        }
        engine
            .mem_write(RETURN_ADDRESS, &[0, 0, 0x20, 0xd4])
            .context("write SAP guest return instruction")?;
        Ok(Self {
            engine,
            scratch_cursor: 0,
        })
    }

    pub fn engine(&mut self) -> &mut Engine {
        &mut self.engine
    }

    pub fn begin_call(&mut self) -> Result<()> {
        self.clear_scratch()
    }

    pub fn scratch(&mut self, data: &[u8], size: u64) -> Result<u64> {
        let reserved = size
            .max(1)
            .checked_add(15)
            .context("SAP scratch size overflows")?
            & !15;
        if self.scratch_cursor > SCRATCH_SIZE || reserved > SCRATCH_SIZE - self.scratch_cursor {
            bail!("SAP guest scratch space exhausted");
        }
        if data.len() as u64 > size {
            bail!("scratch data exceeds reservation");
        }
        let address = SCRATCH_BASE + self.scratch_cursor;
        self.scratch_cursor += reserved;
        if data.is_empty() && size != 0 {
            self.engine.mem_write(address, &vec![0; size as usize])?;
        } else if !data.is_empty() {
            self.engine.mem_write(address, data)?;
        }
        Ok(address)
    }

    pub fn clear_scratch(&mut self) -> Result<()> {
        if self.scratch_cursor != 0 {
            self.engine
                .mem_write(SCRATCH_BASE, &vec![0; self.scratch_cursor as usize])?;
        }
        self.scratch_cursor = 0;
        Ok(())
    }

    pub fn invoke(&mut self, function: u64, arguments: &[u64]) -> Result<u64> {
        if function == 0 {
            bail!("SAP guest entry point is unavailable");
        }
        for index in 0..8 {
            self.engine
                .reg_write(
                    REG_X0 + index,
                    arguments.get(index as usize).copied().unwrap_or(0),
                )
                .context("write SAP guest argument register")?;
        }
        let extra = arguments.len().saturating_sub(8);
        let extra_bytes = extra
            .checked_mul(8)
            .context("SAP guest stack arguments overflow")?;
        if extra_bytes > STACK_SIZE as usize {
            bail!("SAP guest stack arguments exceed stack space");
        }
        let stack_pointer = (STACK_END - extra_bytes as u64) & !15;
        for (index, value) in arguments.iter().skip(8).enumerate() {
            self.engine
                .mem_write(stack_pointer + (index as u64) * 8, &value.to_le_bytes())
                .context("write SAP guest stack argument")?;
        }
        self.engine.reg_write(REG_SP, stack_pointer)?;
        self.engine.reg_write(REG_LR, RETURN_ADDRESS)?;

        let mut next = function;
        loop {
            match self
                .engine
                .start_bounded(next, RETURN_ADDRESS, GUEST_TIMEOUT, 0)
            {
                Ok(()) => break,
                Err(execution_error) => {
                    if emulate_invalid_instruction(&mut self.engine)? {
                        next = self
                            .engine
                            .reg_read(REG_PC)
                            .context("resume SAP guest function")?;
                        continue;
                    }
                    let pc = self.engine.reg_read(REG_PC).unwrap_or(0);
                    let lr = self.engine.reg_read(REG_LR).unwrap_or(0);
                    return Err(execution_error).with_context(|| {
                        format!("execute SAP guest function at {pc:#x} from {lr:#x}")
                    });
                }
            }
        }
        let pc = self.engine.reg_read(REG_PC)?;
        if pc != RETURN_ADDRESS {
            bail!("SAP guest stopped unexpectedly at {pc:#x}");
        }
        self.engine
            .reg_read(REG_X0)
            .context("read SAP guest result register")
    }
}

#[derive(Clone, Copy)]
pub struct SapEntrypoints {
    pub initialize: u64,
    pub exchange: u64,
    pub sign: u64,
    pub teardown: u64,
    pub dispose: u64,
}

pub struct SapRuntimeGuest {
    machine: Option<GuestMachine>,
    entries: SapEntrypoints,
    shims: Option<SapShims>,
}

impl SapRuntimeGuest {
    pub fn open(bundle: &SapAssetBundle) -> Result<Self> {
        Self::open_images(SapImages::open(bundle)?, false)
    }

    pub fn open_store_agent_runtime(bundle: &SapAssetBundle) -> Result<Self> {
        Self::open_images(SapImages::open_store_agent(bundle)?, true)
    }

    fn open_images(mut images: SapImages, store_agent: bool) -> Result<Self> {
        let entries = images.entrypoints();
        let mut machine = GuestMachine::new()?;
        let mut shims = SapShims::new()?;
        shims.set_core_exports(
            images
                .core_exports()
                .map(|(name, address)| (name.to_owned(), address)),
        );
        if store_agent {
            shims.add_zero_aliases(STORE_AGENT_ZERO_ALIASES)?;
        }
        shims.install(machine.engine())?;
        images.load(machine.engine(), |name| shims.resolve(name))?;
        Ok(Self {
            machine: Some(machine),
            entries,
            shims: Some(shims),
        })
    }

    pub fn new(machine: GuestMachine, entries: SapEntrypoints) -> Self {
        Self {
            machine: Some(machine),
            entries,
            shims: None,
        }
    }

    pub(crate) fn with_scratch<T>(
        &mut self,
        call: impl FnOnce(&mut GuestMachine, SapEntrypoints) -> Result<T>,
    ) -> Result<T> {
        let machine = self
            .machine
            .as_mut()
            .context("SAP guest machine is closed")?;
        if let Some(shims) = self.shims.as_mut() {
            shims.take_fault();
        }
        machine.begin_call()?;
        let result = call(machine, self.entries);
        let clear = machine.clear_scratch();
        if let Some(fault) = self.shims.as_mut().and_then(SapShims::take_fault) {
            bail!("SAP guest service failed: {fault}");
        }
        match (result, clear) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(first), Err(second)) => Err(first.context(second)),
        }
    }
}

impl SapGuest for SapRuntimeGuest {
    fn initialize(&mut self, hardware_id: &[u8]) -> Result<u64> {
        let hardware = hardware_block(hardware_id)?;
        self.with_scratch(|machine, entries| {
            let context_field = machine.scratch(&[], 8)?;
            let hardware_address = machine.scratch(&hardware, hardware.len() as u64)?;
            let status = machine.invoke(entries.initialize, &[context_field, hardware_address])?;
            if status as i32 != 0 {
                bail!("SAP initialization returned {}", status as i32);
            }
            let context = read_u64(machine, context_field)?;
            if context == 0 {
                bail!("SAP initialization returned a null context");
            }
            Ok(context)
        })
    }

    fn exchange(
        &mut self,
        version: u32,
        hardware_id: &[u8],
        context: u64,
        input: &[u8],
    ) -> Result<(Vec<u8>, u32)> {
        if input.len() > u32::MAX as usize {
            bail!("SAP exchange input is too large");
        }
        let hardware = hardware_block(hardware_id)?;
        self.with_scratch(|machine, entries| {
            let hardware_address = machine.scratch(&hardware, hardware.len() as u64)?;
            let input_address = machine.scratch(input, input.len() as u64)?;
            let output_field = machine.scratch(&[], 8)?;
            let length_field = machine.scratch(&[], 8)?;
            let result_field = machine.scratch(&[], 4)?;
            let status = machine.invoke(
                entries.exchange,
                &[
                    u64::from(version),
                    hardware_address,
                    context,
                    input_address,
                    input.len() as u64,
                    output_field,
                    length_field,
                    result_field,
                ],
            )?;
            if status as i32 != 0 {
                bail!("SAP exchange returned {}", status as i32);
            }
            let output = consume_output(machine, entries.dispose, output_field, length_field)?;
            let state = read_u32(machine, result_field)?;
            Ok((output, state))
        })
    }

    fn sign(&mut self, context: u64, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() > u32::MAX as usize {
            bail!("SAP signing input is too large");
        }
        self.with_scratch(|machine, entries| {
            let input_address = machine.scratch(input, input.len() as u64)?;
            let output_field = machine.scratch(&[], 8)?;
            let length_field = machine.scratch(&[], 8)?;
            let status = machine.invoke(
                entries.sign,
                &[
                    context,
                    input_address,
                    input.len() as u64,
                    output_field,
                    length_field,
                ],
            )?;
            if status as i32 != 0 {
                bail!("SAP signing returned {}", status as i32);
            }
            consume_output(machine, entries.dispose, output_field, length_field)
        })
    }

    fn teardown(&mut self, context: u64) -> Result<()> {
        self.with_scratch(|machine, entries| {
            let status = machine.invoke(entries.teardown, &[context])?;
            if status as i32 != 0 {
                bail!("SAP teardown returned {}", status as i32);
            }
            Ok(())
        })
    }

    fn close(&mut self) -> Result<()> {
        self.machine.take();
        self.shims.take();
        Ok(())
    }
}

pub(crate) fn hardware_block(hardware_id: &[u8]) -> Result<[u8; 24]> {
    if hardware_id.is_empty() || hardware_id.len() > 20 {
        bail!("hardware ID must contain between 1 and 20 bytes");
    }
    let mut block = [0u8; 24];
    block[..4].copy_from_slice(&(hardware_id.len() as u32).to_le_bytes());
    block[4..4 + hardware_id.len()].copy_from_slice(hardware_id);
    Ok(block)
}

fn read_u64(machine: &mut GuestMachine, address: u64) -> Result<u64> {
    let bytes = machine
        .engine
        .mem_read(address, 8)
        .context("read SAP guest uint64")?;
    Ok(u64::from_le_bytes(bytes.as_slice().try_into()?))
}

pub(crate) fn read_u32(machine: &mut GuestMachine, address: u64) -> Result<u32> {
    let bytes = machine
        .engine
        .mem_read(address, 4)
        .context("read SAP guest uint32")?;
    Ok(u32::from_le_bytes(bytes.as_slice().try_into()?))
}

pub(crate) fn consume_output(
    machine: &mut GuestMachine,
    dispose: u64,
    pointer_field: u64,
    length_field: u64,
) -> Result<Vec<u8>> {
    let pointer = read_u64(machine, pointer_field)?;
    let length = read_u64(machine, length_field)?;
    let output = match (pointer, length) {
        (_, size) if size > MAX_OUTPUT_SIZE => Err(anyhow!(
            "SAP output is {size} bytes, maximum is {MAX_OUTPUT_SIZE}"
        )),
        (_, 0) => Ok(Vec::new()),
        (0, _) => Err(anyhow!("SAP returned a null output pointer")),
        (address, size) => machine.engine.mem_read(address, size as usize),
    };
    let disposal = if pointer != 0 {
        machine.invoke(dispose, &[pointer]).and_then(|status| {
            if status as i32 != 0 {
                bail!("SAP storage disposal returned {}", status as i32);
            }
            Ok(())
        })
    } else {
        Ok(())
    };
    match (output, disposal) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(first.context(second)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "downloads pinned macOS restore assets when the cache is empty"]
    fn opens_pinned_sap_runtime() {
        let bundle = SapAssetBundle::load_or_download().unwrap();
        let mut guest = SapRuntimeGuest::open(&bundle).unwrap();
        assert!(guest.entries.initialize != 0);
        assert!(guest.entries.sign != 0);
        let context = guest.initialize(&[1; 20]).unwrap();
        assert_ne!(context, 0);
        guest.teardown(context).unwrap();
        guest.close().unwrap();
    }

    #[test]
    #[ignore = "downloads pinned macOS restore assets when the cache is empty"]
    fn opens_pinned_store_agent_runtime() {
        let bundle = SapAssetBundle::load_or_download().unwrap();
        let mut guest = SapRuntimeGuest::open_store_agent_runtime(&bundle).unwrap();
        assert!(guest.entries.initialize != 0);
        guest.close().unwrap();
    }
    use std::{cell::Cell, rc::Rc};

    #[test]
    fn hardware_block_matches_guest_abi() {
        let block = hardware_block(&[1, 2, 3]).unwrap();
        assert_eq!(&block[..8], &[3, 0, 0, 0, 1, 2, 3, 0]);
        assert!(hardware_block(&[]).is_err());
        assert!(hardware_block(&[0; 21]).is_err());
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn invokes_guest_with_register_and_stack_arguments() {
        let mut guest = GuestMachine::new().unwrap();
        guest.engine().mem_map(0x2000, 4096).unwrap();
        // add x0, x0, x1; ret
        guest
            .engine()
            .mem_write(0x2000, &[0, 0, 1, 0x8b, 0xc0, 3, 0x5f, 0xd6])
            .unwrap();
        assert_eq!(guest.invoke(0x2000, &[19, 23]).unwrap(), 42);
        // ldr x0, [sp]; ret
        guest
            .engine()
            .mem_write(0x2008, &[0xe0, 3, 0x40, 0xf9, 0xc0, 3, 0x5f, 0xd6])
            .unwrap();
        assert_eq!(
            guest.invoke(0x2008, &[0, 0, 0, 0, 0, 0, 0, 0, 99]).unwrap(),
            99
        );
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn scratch_reservations_are_aligned_and_cleared() {
        let mut guest = GuestMachine::new().unwrap();
        guest.begin_call().unwrap();
        let first = guest.scratch(&[1, 2, 3], 3).unwrap();
        let second = guest.scratch(&[], 8).unwrap();
        assert_eq!(second - first, 16);
        assert_eq!(guest.engine().mem_read(first, 3).unwrap(), [1, 2, 3]);
        guest.clear_scratch().unwrap();
        assert_eq!(guest.engine().mem_read(first, 24).unwrap(), [0; 24]);
        assert!(guest.scratch(&[], SCRATCH_SIZE + 1).is_err());
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn sap_guest_exchanges_signs_and_disposes_buffers() {
        let mut machine = GuestMachine::new().unwrap();
        machine.engine().mem_map(0x2000, 4096).unwrap();
        machine.engine().mem_map(0x3000, 4096).unwrap();
        machine
            .engine()
            .mem_write(0x2000, &[0xc0, 3, 0x5f, 0xd6].repeat(5))
            .unwrap();
        machine.engine().mem_write(0x3000, b"request").unwrap();
        machine.engine().mem_write(0x3010, b"sig").unwrap();
        machine
            .engine()
            .add_code_hook(0x2000, 0x2000, |context, _, _| {
                let field = context.reg_read(REG_X0).unwrap();
                context.mem_write(field, &42u64.to_le_bytes()).unwrap();
                context.reg_write(REG_X0, 0).unwrap();
            })
            .unwrap();
        let exchanges = Rc::new(Cell::new(0));
        let observed = Rc::clone(&exchanges);
        machine
            .engine()
            .add_code_hook(0x2004, 0x2004, move |context, _, _| {
                let first = observed.get() == 0;
                observed.set(observed.get() + 1);
                let pointer = context.reg_read(REG_X0 + 5).unwrap();
                let length = context.reg_read(REG_X0 + 6).unwrap();
                let state = context.reg_read(REG_X0 + 7).unwrap();
                context
                    .mem_write(pointer, &(if first { 0x3000u64 } else { 0 }).to_le_bytes())
                    .unwrap();
                context
                    .mem_write(length, &(if first { 7u64 } else { 0 }).to_le_bytes())
                    .unwrap();
                context
                    .mem_write(state, &(if first { 1u32 } else { 0 }).to_le_bytes())
                    .unwrap();
                context.reg_write(REG_X0, 0).unwrap();
            })
            .unwrap();
        machine
            .engine()
            .add_code_hook(0x2008, 0x2008, |context, _, _| {
                let pointer = context.reg_read(REG_X0 + 3).unwrap();
                let length = context.reg_read(REG_X0 + 4).unwrap();
                context
                    .mem_write(pointer, &0x3010u64.to_le_bytes())
                    .unwrap();
                context.mem_write(length, &3u64.to_le_bytes()).unwrap();
                context.reg_write(REG_X0, 0).unwrap();
            })
            .unwrap();
        machine
            .engine()
            .add_code_hook(0x200c, 0x200c, |context, _, _| {
                context.reg_write(REG_X0, 0).unwrap();
            })
            .unwrap();
        let disposals = Rc::new(Cell::new(0));
        let disposed = Rc::clone(&disposals);
        machine
            .engine()
            .add_code_hook(0x2010, 0x2010, move |context, _, _| {
                disposed.set(disposed.get() + 1);
                context.reg_write(REG_X0, 0).unwrap();
            })
            .unwrap();
        let entries = SapEntrypoints {
            initialize: 0x2000,
            exchange: 0x2004,
            sign: 0x2008,
            teardown: 0x200c,
            dispose: 0x2010,
        };
        let mut guest = SapRuntimeGuest::new(machine, entries);
        let hardware = [1, 2, 3, 4, 5, 6];
        assert_eq!(guest.initialize(&hardware).unwrap(), 42);
        assert_eq!(
            guest.exchange(200, &hardware, 42, b"certificate").unwrap(),
            (b"request".to_vec(), 1)
        );
        assert_eq!(
            guest.exchange(200, &hardware, 42, b"reply").unwrap(),
            (Vec::new(), 0)
        );
        assert_eq!(guest.sign(42, b"payload").unwrap(), b"sig");
        guest.teardown(42).unwrap();
        guest.close().unwrap();
        assert_eq!(exchanges.get(), 2);
        assert_eq!(disposals.get(), 2);
    }
}
