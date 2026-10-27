//! Fallback for ARM64 instructions unsupported by the pinned Unicorn runtime.

use anyhow::{Context, Result, bail};

use crate::unicorn_runtime::{Engine, HookContext, REG_PC, REG_X0};

const REG_X29: i32 = 1;
const REG_LR: i32 = 2;
const REG_SP: i32 = 4;
const REG_V0: i32 = 228;
const ATOMIC_MASK: u32 = 0xffe0_fc00;
const CASAL32: u32 = 0x88e0_fc00;
const CASAL64: u32 = 0xc8e0_fc00;
const SWPAL32: u32 = 0xb8e0_8000;
const SWPAL64: u32 = 0xf8e0_8000;
const EOR3_MASK: u32 = 0xffe0_8000;
const EOR3: u32 = 0xce00_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Instruction {
    Eor3,
    Casal(usize),
    Swpal(usize),
}

fn classify(instruction: u32) -> Option<Instruction> {
    if instruction & EOR3_MASK == EOR3 {
        return Some(Instruction::Eor3);
    }
    match instruction & ATOMIC_MASK {
        CASAL32 => Some(Instruction::Casal(4)),
        CASAL64 => Some(Instruction::Casal(8)),
        SWPAL32 => Some(Instruction::Swpal(4)),
        SWPAL64 => Some(Instruction::Swpal(8)),
        _ => None,
    }
}

pub fn needs_compat_hook(instruction: u32) -> bool {
    classify(instruction).is_some()
}

/// Execute the unsigned instruction that the image loader would have written
/// at a preserved arm64e text site, while leaving its original bytes intact.
pub fn emulate_preserved_pointer_auth(
    context: &HookContext,
    address: u64,
    prepared: u32,
) -> Result<()> {
    let next = address
        .checked_add(4)
        .context("arm64 instruction address overflows")?;
    match prepared {
        0xd503_201f => context.reg_write(REG_PC, next),
        0xd65f_03c0 => context.reg_write(REG_PC, context.reg_read(REG_LR)?),
        _ if prepared & 0xffff_fc1f == 0xd61f_0000 => {
            let register = (prepared >> 5) & 31;
            context.reg_write(REG_PC, context.reg_read(general_register(register)?)?)
        }
        _ if prepared & 0xffff_fc1f == 0xd63f_0000 => {
            let register = (prepared >> 5) & 31;
            let target = context.reg_read(general_register(register)?)?;
            context.reg_write(REG_LR, next)?;
            context.reg_write(REG_PC, target)
        }
        _ => bail!("unsupported preserved arm64e instruction at {address:#x}"),
    }
}

/// Execute a compatibility opcode from a Unicorn code hook and skip its native
/// instruction. The hook preserves the original bytes in checkpoint memory.
pub fn emulate_hook_instruction(
    context: &HookContext,
    address: u64,
    instruction: u32,
) -> Result<bool> {
    let Some(kind) = classify(instruction) else {
        return Ok(false);
    };
    match kind {
        Instruction::Eor3 => {
            let destination = (instruction & 31) as i32;
            let first = ((instruction >> 5) & 31) as i32;
            let third = ((instruction >> 10) & 31) as i32;
            let second = ((instruction >> 16) & 31) as i32;
            let a = context.reg_read_128(REG_V0 + first)?;
            let b = context.reg_read_128(REG_V0 + second)?;
            let c = context.reg_read_128(REG_V0 + third)?;
            let mut result = [0u8; 16];
            for index in 0..16 {
                result[index] = a[index] ^ b[index] ^ c[index];
            }
            context.reg_write_128(REG_V0 + destination, result)?;
        }
        Instruction::Casal(width) | Instruction::Swpal(width) => {
            let source = (instruction >> 16) & 31;
            let base = (instruction >> 5) & 31;
            let destination = instruction & 31;
            let address = if base == 31 {
                context.reg_read(REG_SP)?
            } else {
                context.reg_read(general_register(base)?)?
            };
            let memory = context.mem_read(address, width)?;
            let mut padded = [0u8; 8];
            padded[..width].copy_from_slice(&memory);
            let old_value = u64::from_le_bytes(padded);
            let mut source_value = read_hook_value_register(context, source)?;
            if width == 4 {
                source_value = u64::from(source_value as u32);
            }
            match kind {
                Instruction::Casal(_) => {
                    let mut new_value = read_hook_value_register(context, destination)?;
                    if width == 4 {
                        new_value = u64::from(new_value as u32);
                    }
                    if old_value == source_value {
                        context.mem_write(address, &new_value.to_le_bytes()[..width])?;
                    }
                    write_hook_value_register(context, source, old_value)?;
                }
                Instruction::Swpal(_) => {
                    context.mem_write(address, &source_value.to_le_bytes()[..width])?;
                    write_hook_value_register(context, destination, old_value)?;
                }
                Instruction::Eor3 => unreachable!(),
            }
        }
    }
    context.reg_write(
        REG_PC,
        address
            .checked_add(4)
            .context("arm64 instruction address overflows")?,
    )?;
    Ok(true)
}

fn read_hook_value_register(context: &HookContext, index: u32) -> Result<u64> {
    if index == 31 {
        Ok(0)
    } else {
        context.reg_read(general_register(index)?)
    }
}

fn write_hook_value_register(context: &HookContext, index: u32, value: u64) -> Result<()> {
    if index == 31 {
        Ok(())
    } else {
        context.reg_write(general_register(index)?, value)
    }
}

/// Emulate the instruction at PC after Unicorn reports an invalid instruction.
/// Returns false when the opcode is outside the compatibility set.
pub fn emulate_invalid_instruction(engine: &mut Engine) -> Result<bool> {
    let pc = engine
        .reg_read(REG_PC)
        .context("read arm64 instruction address")?;
    let data = match engine.mem_read(pc, 4) {
        Ok(data) => data,
        Err(_) => return Ok(false),
    };
    let instruction = u32::from_le_bytes(data.as_slice().try_into()?);
    let Some(kind) = classify(instruction) else {
        return Ok(false);
    };
    match kind {
        Instruction::Eor3 => emulate_eor3(engine, instruction)?,
        Instruction::Casal(width) | Instruction::Swpal(width) => {
            emulate_atomic(engine, instruction, kind, width)?
        }
    }
    let next = pc
        .checked_add(4)
        .context("arm64 instruction address overflows")?;
    engine
        .reg_write(REG_PC, next)
        .context("advance arm64 instruction address")?;
    Ok(true)
}

fn emulate_eor3(engine: &mut Engine, instruction: u32) -> Result<()> {
    let destination = (instruction & 31) as i32;
    let first = ((instruction >> 5) & 31) as i32;
    let third = ((instruction >> 10) & 31) as i32;
    let second = ((instruction >> 16) & 31) as i32;
    let a = engine.reg_read_128(REG_V0 + first)?;
    let b = engine.reg_read_128(REG_V0 + second)?;
    let c = engine.reg_read_128(REG_V0 + third)?;
    let mut result = [0u8; 16];
    for index in 0..16 {
        result[index] = a[index] ^ b[index] ^ c[index];
    }
    engine.reg_write_128(REG_V0 + destination, result)?;
    Ok(())
}

fn emulate_atomic(
    engine: &mut Engine,
    instruction: u32,
    kind: Instruction,
    width: usize,
) -> Result<()> {
    let source = (instruction >> 16) & 31;
    let base = (instruction >> 5) & 31;
    let destination = instruction & 31;
    let address = if base == 31 {
        engine.reg_read(REG_SP)?
    } else {
        engine.reg_read(general_register(base)?)?
    };
    let memory = engine
        .mem_read(address, width)
        .with_context(|| format!("read arm64 atomic operand at {address:#x}"))?;
    let mut padded = [0u8; 8];
    padded[..width].copy_from_slice(&memory);
    let old_value = u64::from_le_bytes(padded);
    let mut source_value = read_value_register(engine, source)?;
    if width == 4 {
        source_value = u64::from(source_value as u32);
    }
    match kind {
        Instruction::Casal(_) => {
            let mut new_value = read_value_register(engine, destination)?;
            if width == 4 {
                new_value = u64::from(new_value as u32);
            }
            if old_value == source_value {
                write_memory_value(engine, address, new_value, width)?;
            }
            write_value_register(engine, source, old_value)?;
        }
        Instruction::Swpal(_) => {
            write_memory_value(engine, address, source_value, width)?;
            write_value_register(engine, destination, old_value)?;
        }
        Instruction::Eor3 => unreachable!(),
    }
    Ok(())
}

fn general_register(index: u32) -> Result<i32> {
    match index {
        0..=28 => Ok(REG_X0 + index as i32),
        29 => Ok(REG_X29),
        30 => Ok(REG_LR),
        _ => bail!("invalid arm64 general register {index}"),
    }
}

fn read_value_register(engine: &Engine, index: u32) -> Result<u64> {
    if index == 31 {
        Ok(0)
    } else {
        engine.reg_read(general_register(index)?)
    }
}

fn write_value_register(engine: &mut Engine, index: u32, value: u64) -> Result<()> {
    if index == 31 {
        Ok(())
    } else {
        engine.reg_write(general_register(index)?, value)
    }
}

fn write_memory_value(engine: &mut Engine, address: u64, value: u64, width: usize) -> Result<()> {
    engine
        .mem_write(address, &value.to_le_bytes()[..width])
        .with_context(|| format!("write arm64 atomic operand at {address:#x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn recognizes_only_supported_opcodes_and_register_layout() {
        assert_eq!(classify(CASAL32), Some(Instruction::Casal(4)));
        assert_eq!(classify(CASAL64), Some(Instruction::Casal(8)));
        assert_eq!(classify(SWPAL32), Some(Instruction::Swpal(4)));
        assert_eq!(classify(SWPAL64), Some(Instruction::Swpal(8)));
        assert_eq!(classify(EOR3), Some(Instruction::Eor3));
        assert_eq!(classify(0xd503_201f), None);
        assert_eq!(general_register(29).unwrap(), REG_X29);
        assert_eq!(general_register(30).unwrap(), REG_LR);
        assert!(general_register(31).is_err());
    }

    #[test]
    fn compatibility_hooks_execute_guest_opcodes_with_one_bounded_run() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        engine.mem_map(0x2000, 4096).unwrap();
        let opcodes = [
            EOR3 | (1 << 5) | (2 << 16) | (3 << 10) | 4,
            CASAL64 | (1 << 16) | (2 << 5) | 3,
            SWPAL32 | (4 << 16) | (2 << 5) | 5,
        ];
        for (index, opcode) in opcodes.into_iter().enumerate() {
            let address = 0x1000 + (index as u64) * 4;
            engine.mem_write(address, &opcode.to_le_bytes()).unwrap();
            engine
                .add_code_hook(address, address, move |context, pc, _| {
                    emulate_hook_instruction(context, pc, opcode).unwrap();
                })
                .unwrap();
        }
        engine.reg_write_128(REG_V0 + 1, [0xf0; 16]).unwrap();
        engine.reg_write_128(REG_V0 + 2, [0x33; 16]).unwrap();
        engine.reg_write_128(REG_V0 + 3, [0x0f; 16]).unwrap();
        engine.mem_write(0x2000, &7u64.to_le_bytes()).unwrap();
        engine.reg_write(REG_X0 + 1, 7).unwrap();
        engine.reg_write(REG_X0 + 2, 0x2000).unwrap();
        engine.reg_write(REG_X0 + 3, 9).unwrap();
        engine.reg_write(REG_X0 + 4, 13).unwrap();
        engine
            .start_bounded(0x1000, 0x100c, Duration::from_secs(2), 3)
            .unwrap();
        assert_eq!(engine.reg_read(REG_PC).unwrap(), 0x100c);
        assert_eq!(engine.reg_read_128(REG_V0 + 4).unwrap(), [0xcc; 16]);
        assert_eq!(engine.reg_read(REG_X0 + 1).unwrap(), 7);
        assert_eq!(engine.reg_read(REG_X0 + 5).unwrap(), 9);
        assert_eq!(engine.mem_read(0x2000, 4).unwrap(), 13u32.to_le_bytes());
    }

    #[test]
    fn preserved_pointer_auth_hook_executes_without_rewriting_guest_text() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        let pac_nop = 0xd503_211fu32;
        engine.mem_write(0x1000, &pac_nop.to_le_bytes()).unwrap();
        engine
            .add_code_hook(0x1000, 0x1000, move |context, address, _| {
                emulate_preserved_pointer_auth(context, address, 0xd503_201f).unwrap();
            })
            .unwrap();
        engine
            .start_bounded(0x1000, 0x1004, Duration::from_secs(2), 2)
            .unwrap();
        assert_eq!(engine.reg_read(REG_PC).unwrap(), 0x1004);
        assert_eq!(engine.mem_read(0x1000, 4).unwrap(), pac_nop.to_le_bytes());

        let authenticated_call = 0xd63f_0a20u32;
        engine
            .mem_write(0x1004, &authenticated_call.to_le_bytes())
            .unwrap();
        engine.reg_write(REG_X0 + 17, 0x1010).unwrap();
        engine
            .add_code_hook(0x1004, 0x1004, move |context, address, _| {
                emulate_preserved_pointer_auth(context, address, 0xd63f_0220).unwrap();
            })
            .unwrap();
        engine
            .start_bounded(0x1004, 0x1010, Duration::from_secs(2), 2)
            .unwrap();
        assert_eq!(engine.reg_read(REG_LR).unwrap(), 0x1008);
        assert_eq!(engine.reg_read(REG_PC).unwrap(), 0x1010);
        assert_eq!(
            engine.mem_read(0x1004, 4).unwrap(),
            authenticated_call.to_le_bytes()
        );
    }

    #[test]
    #[ignore = "downloads the pinned Unicorn library when the cache is empty"]
    fn emulates_vector_and_atomic_instructions_in_guest_state() {
        let mut engine = Engine::new().unwrap();
        engine.mem_map(0x1000, 4096).unwrap();
        engine.mem_map(0x2000, 4096).unwrap();
        let eor3 = EOR3 | (1 << 5) | (2 << 16) | (3 << 10) | 4;
        engine.mem_write(0x1000, &eor3.to_le_bytes()).unwrap();
        engine.reg_write(REG_PC, 0x1000).unwrap();
        engine.reg_write_128(REG_V0 + 1, [0xf0; 16]).unwrap();
        engine.reg_write_128(REG_V0 + 2, [0x33; 16]).unwrap();
        engine.reg_write_128(REG_V0 + 3, [0x0f; 16]).unwrap();
        assert!(emulate_invalid_instruction(&mut engine).unwrap());
        assert_eq!(engine.reg_read_128(REG_V0 + 4).unwrap(), [0xcc; 16]);
        assert_eq!(engine.reg_read(REG_PC).unwrap(), 0x1004);

        let casal = CASAL64 | (1 << 16) | (2 << 5) | 3;
        engine.mem_write(0x1004, &casal.to_le_bytes()).unwrap();
        engine.mem_write(0x2000, &7u64.to_le_bytes()).unwrap();
        engine.reg_write(REG_X0 + 1, 7).unwrap();
        engine.reg_write(REG_X0 + 2, 0x2000).unwrap();
        engine.reg_write(REG_X0 + 3, 9).unwrap();
        assert!(emulate_invalid_instruction(&mut engine).unwrap());
        assert_eq!(engine.mem_read(0x2000, 8).unwrap(), 9u64.to_le_bytes());
        assert_eq!(engine.reg_read(REG_X0 + 1).unwrap(), 7);

        let swpal = SWPAL32 | (4 << 16) | (2 << 5) | 5;
        engine.mem_write(0x1008, &swpal.to_le_bytes()).unwrap();
        engine.mem_write(0x2000, &11u32.to_le_bytes()).unwrap();
        engine.reg_write(REG_X0 + 4, 0xffff_ffff_0000_000d).unwrap();
        assert!(emulate_invalid_instruction(&mut engine).unwrap());
        assert_eq!(engine.mem_read(0x2000, 4).unwrap(), 13u32.to_le_bytes());
        assert_eq!(engine.reg_read(REG_X0 + 5).unwrap(), 11);
        assert_eq!(engine.reg_read(REG_PC).unwrap(), 0x100c);
    }
}
