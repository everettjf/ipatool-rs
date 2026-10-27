// Generated from checked runRawSourceDigestPrologue Go source, SHA-256 0bb61d263a8cafb6116bd3012a7d23eaa8bebd5b00d8a7cfb5991ee60531f08d.
// Regenerate with scripts/port_raw_source.py; Rust runtime has no Go dependency.
#[rustfmt::skip]
#[allow(clippy::all, unused_parens, unused_variables, dead_code)]
fn run_raw_source_digest_prologue(s: &mut OracleState<'_>, selected: OracleFault) -> Result<()> {
    s.store_value(add_offset(s.sp, 3464u64 as i64), ((s.registers[0] as u32 as u64) as u64), 4u64 as usize)?;
    s.store_value(add_offset(s.sp, 3520u64 as i64), ((s.registers[16] as u32 as u64) as u64), 4u64 as usize)?;
    s.registers[14] = (((0x92b8u64 as u64) as u32 as u64) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32 as u64) as u64), 0xb039u64, 16u64 as u32, 16u64 as u32, 32u64 as u32) as u32 as u64) as u64);
    s.registers[14] = (((((s.registers[5] as u32 as u64) as u64)).wrapping_add(((s.registers[14] as u32 as u64) as u64)) as u32 as u64) as u64);
    s.registers[16] = ((unsigned_divide(((s.registers[14] as u32 as u64) as u64), ((s.registers[11] as u32 as u64) as u64), 32u64 as u32) as u32 as u64) as u64);
    s.registers[14] = (((((s.registers[14] as u32 as u64) as u64)).wrapping_sub((((s.registers[16] as u32 as u64) as u64)).wrapping_mul(((s.registers[11] as u32 as u64) as u64))) as u32 as u64) as u64);
    let value7 = s.load(add_offset(s.sp, 3424u64 as i64), 4u64 as usize)?;
    s.registers[15] = ((value7 as u32 as u64) as u64);
    s.registers[17] = (((((s.registers[15] as u32 as u64) as u64)).wrapping_add(((s.registers[8] as u32 as u64) as u64)) as u32 as u64) as u64);
    s.registers[0] = ((((((s.registers[17] as u32 as u64) as u64) as u32 as u64) as u64)).wrapping_mul(((((s.registers[9] as u32 as u64) as u64) as u32 as u64) as u64)) as u64);
    let value10 = s.load((s.registers[30]).wrapping_add(((((s.registers[14] as u32 as u64) as u64) as u32 as u64) as u64)), 1u64 as usize)?;
    s.registers[16] = ((value10 as u32 as u64) as u64);
    s.registers[0] = (shift_right(s.registers[0], ((0x22u64 as u64) as u64), 64u64 as u32) as u64);
    s.registers[17] = (((((s.registers[17] as u32 as u64) as u64)).wrapping_sub((((s.registers[0] as u32 as u64) as u64)).wrapping_mul(((s.registers[12] as u32 as u64) as u64))) as u32 as u64) as u64);
    Ok(())
}
