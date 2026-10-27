// Generated from ipatool-fairplay generated_26b118.go, SHA-256 81dae7acfdda7c3a9b0daba77841138a13e5e9ca8e51432fef26a45fb6e53cd3.
// The checked source is straight-line ARM64-derived arithmetic; this file is Rust only.
#[rustfmt::skip]
#[allow(clippy::all, unused_parens)]
fn run_generated(s: &mut OracleState<'_>, selected: OracleFault) -> Result<()> {
    s.store_value(add_offset(s.sp, 856), (0 as u64), 4)?;
    s.registers[8] = (((0x891b as u64) as u32) as u64);
    s.registers[13] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[10] as u32) as u64) & (0xfffffffb as u64))) as u32) as u64);
    s.registers[25] = (((0x4cf as u64) as u32) as u64);
    s.registers[25] = ((insert_bits(((s.registers[25] as u32) as u64), 0x339f, 16, 16, 32) as u32) as u64);
    s.registers[9] = (((s.registers[8] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 936), s.registers[9], 8)?;
    s.registers[8] = (((0xfffffff6 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[10] as u32) as u64) & ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((s.registers[8] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 1016), s.registers[12], 8)?;
    let value12 = s.load(((s.registers[22]).wrapping_add(s.registers[9])), 1)?;

    s.registers[8] = ((value12 as u32) as u64);
    s.registers[9] = (((0x3d as u64) as u32) as u64);
    s.registers[8] = (((s.registers[8] ^ s.registers[9])) as u64);
    let value15 = s.load(add_offset(s.sp, 816), 8)?;

    s.registers[4] = (value15 as u64);
    let value16 = s.load(((s.registers[4]).wrapping_add(s.registers[8])), 1)?;

    s.registers[8] = ((value16 as u32) as u64);
    let value17 = s.load(((s.registers[22]).wrapping_add(s.registers[12])), 1)?;

    s.registers[9] = ((value17 as u32) as u64);
    s.registers[12] = (s.registers[11] as u64);
    s.store_value(add_offset(s.sp, 1084), ((s.registers[11] as u32) as u64), 4)?;
    s.registers[11] = (((0x33e3 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x7611, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[12] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0xaf7f as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x89ee, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[11] as u32) as u64) & ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64)).wrapping_add((0x6c as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ (0x44444444 as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[11] = (((0xada6 as u64) as u32) as u64);
    s.store_value(add_offset(s.sp, 860), ((s.registers[13] as u32) as u64), 4)?;
    s.registers[11] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.store_value(add_offset(s.sp, 880), ((s.registers[12] as u32) as u64), 4)?;
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((shift_left(((s.registers[8] as u32) as u64), (((s.registers[11] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[11] = (((0xfffffff4 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[10] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((s.registers[11] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 1000), s.registers[13], 8)?;
    s.registers[11] = (((0x54 as u64) as u32) as u64);
    s.registers[11] = (((s.registers[9] ^ s.registers[11])) as u64);
    let value41 = s.load(add_offset(s.sp, 832), 8)?;

    s.registers[1] = (value41 as u64);
    let value42 = s.load(((s.registers[1]).wrapping_add(s.registers[11])), 1)?;

    s.registers[11] = ((value42 as u32) as u64);
    s.registers[12] = (((0xb4 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64)).wrapping_add(((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((shift_left(((s.registers[9] as u32) as u64), ((0x10 as u64) as u64), 32) as u32) as u64);
    let value47 = s.load(((s.registers[22]).wrapping_add(s.registers[13])), 1)?;

    s.registers[11] = ((value47 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_sub(shift_left((0x5d0 as u64), 12, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & (0xff0000 as u64))) as u32) as u64);
    s.registers[12] = (((0x42 as u64) as u32) as u64);
    s.registers[12] = (((s.registers[11] ^ s.registers[12])) as u64);
    s.registers[13] = (((0xa2 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value54 = s.load(((s.registers[1]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value54 as u32) as u64);
    s.registers[11] = ((((((s.registers[12] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_sub((0x5d as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[11] as u32) as u64) & (0x1ff as u64))) as u32) as u64);
    s.registers[13] = (((0xc27b as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x18, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ (0xfffffe0f as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[12] as u32) as u64) & ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x84 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) | ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xfffffff5 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[10] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((s.registers[11] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 944), s.registers[11], 8)?;
    let value70 = s.load(((s.registers[22]).wrapping_add(s.registers[11])), 1)?;

    s.registers[11] = ((value70 as u32) as u64);
    s.registers[12] = ((((((s.registers[10] as u32) as u64) & (0xfffffff3 as u64))) as u32) as u64);
    s.registers[14] = (((s.registers[12] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 968), s.registers[14], 8)?;
    s.registers[12] = (((0xffffffd8 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xd6 as u64) as u32) as u64);
    s.registers[11] = (((s.registers[11] ^ s.registers[13])) as u64);
    s.registers[13] = ((((((s.registers[12] as u32) as u64)).wrapping_sub((0x2c as u64))) as u32) as u64);
    let value79 = s.load(add_offset(s.sp, 824), 8)?;

    s.registers[2] = (value79 as u64);
    let value80 = s.load(((s.registers[2]).wrapping_add(s.registers[11])), 1)?;

    s.registers[11] = ((value80 as u32) as u64);
    let value81 = s.load(((s.registers[22]).wrapping_add(s.registers[14])), 1)?;

    s.registers[14] = ((value81 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((shift_left(((s.registers[11] as u32) as u64), ((0x8 as u64) as u64), 32) as u32) as u64);
    s.registers[12] = (((!(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xa63a as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x6ede, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) | (0xffff00ff as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((s.registers[14] ^ (0x1c as u64))) as u64);
    let value92 = s.load(add_offset(s.sp, 848), 8)?;

    s.registers[3] = (value92 as u64);
    let value93 = s.load(((s.registers[3]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value93 as u32) as u64);
    s.registers[13] = (((0x9b00 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = ((((s.registers[10] as u32) as u64) as u32) as u64);
    s.registers[13] = (((s.registers[13] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 984), s.registers[13], 8)?;
    let value99 = s.load(((s.registers[22]).wrapping_add(s.registers[13])), 1)?;

    s.registers[13] = ((value99 as u32) as u64);
    s.registers[14] = (((0x69 as u64) as u32) as u64);
    s.registers[16] = (((0xffffffe7 as u64) as u32) as u64);
    s.registers[12] = (((((((s.registers[12] as u32) as u64)).wrapping_mul(((s.registers[14] as u32) as u64))).wrapping_add(((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x5a as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x12 as u64) as u32) as u64);
    s.registers[12] = (((s.registers[13] ^ s.registers[12])) as u64);
    let value107 = s.load(((s.registers[1]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value107 as u32) as u64);
    s.registers[15] = ((((((s.registers[10] as u32) as u64) & (0xfffffffe as u64))) as u32) as u64);
    s.registers[17] = (((s.registers[15] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 992), s.registers[17], 8)?;
    s.registers[15] = (((0xd as u64) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[13] as u32) as u64)).wrapping_sub(((s.registers[12] as u32) as u64))) as u32) as u64);
    let value114 = s.load(((s.registers[22]).wrapping_add(s.registers[17])), 1)?;

    s.registers[13] = ((value114 as u32) as u64);
    s.registers[15] = (((0xde as u64) as u32) as u64);
    s.registers[13] = (((s.registers[13] ^ s.registers[15])) as u64);
    s.registers[15] = (((0x5d000000 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64)).wrapping_add(shift_left(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    let value119 = s.load(((s.registers[4]).wrapping_add(s.registers[13])), 1)?;

    s.registers[13] = ((value119 as u32) as u64);
    s.registers[13] = ((shift_left(((s.registers[13] as u32) as u64), ((0x10 as u64) as u64), 32) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64)).wrapping_add(shift_left((0x6c0 as u64), 12, 32))) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64) & (0xff0000 as u64))) as u32) as u64);
    s.registers[15] = (((0xd11 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0xa819, 16, 16, 32) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0x4d35 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0x2bff, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64) & ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0x57000000 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[13] as u32) as u64) | ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[13] = ((((((s.registers[10] as u32) as u64) & (0xfffffffd as u64))) as u32) as u64);
    s.registers[13] = (((s.registers[13] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 920), s.registers[13], 8)?;
    let value136 = s.load(((s.registers[22]).wrapping_add(s.registers[13])), 1)?;

    s.registers[13] = ((value136 as u32) as u64);
    s.registers[15] = ((((((s.registers[10] as u32) as u64) & (0xfffffff9 as u64))) as u32) as u64);
    s.registers[17] = (((s.registers[15] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 976), s.registers[17], 8)?;
    s.registers[27] = (s.registers[10] as u64);
    s.registers[10] = (((0xeb as u64) as u32) as u64);
    s.registers[15] = (((s.registers[13] ^ s.registers[10])) as u64);
    s.registers[10] = (((0xeb as u64) as u32) as u64);
    s.registers[0] = (((0xb as u64) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[0] as u32) as u64))) as u32) as u64);
    let value146 = s.load(((s.registers[1]).wrapping_add(s.registers[15])), 1)?;

    s.registers[15] = ((value146 as u32) as u64);
    s.registers[13] = ((((((s.registers[15] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    let value148 = s.load(((s.registers[22]).wrapping_add(s.registers[17])), 1)?;

    s.registers[15] = ((value148 as u32) as u64);
    s.registers[26] = (((0xffffa300 as u64) as u32) as u64);
    s.registers[13] = ((((((s.registers[26] as u32) as u64)).wrapping_add(shift_left(((s.registers[13] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[17] = ((((((s.registers[13] as u32) as u64) & (0xff00 as u64))) as u32) as u64);
    s.registers[0] = (((0x5a2c as u64) as u32) as u64);
    s.registers[0] = ((insert_bits(((s.registers[0] as u32) as u64), 0xe5fc, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[0] as u32) as u64))) as u32) as u64);
    s.registers[0] = (((0xffff293d as u64) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[0] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = (((0xa800 as u64) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64) & ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = (((0x1d as u64) as u32) as u64);
    s.registers[17] = (((s.registers[15] ^ s.registers[17])) as u64);
    s.registers[0] = ((((((s.registers[27] as u32) as u64) & (0xfffffff0 as u64))) as u32) as u64);
    s.registers[0] = (((s.registers[0] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 928), s.registers[0], 8)?;
    let value165 = s.load(((s.registers[1]).wrapping_add(s.registers[17])), 1)?;

    s.registers[17] = ((value165 as u32) as u64);
    let value166 = s.load(((s.registers[22]).wrapping_add(s.registers[0])), 1)?;

    s.registers[0] = ((value166 as u32) as u64);
    s.registers[24] = (((0xd3 as u64) as u32) as u64);
    s.registers[0] = (((s.registers[0] ^ s.registers[24])) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ (0xfffffffd as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[17] as u32) as u64)).wrapping_add(((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[26] as u32) as u64)).wrapping_add(shift_left(((s.registers[15] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) & (0xff00 as u64))) as u32) as u64);
    s.registers[17] = (((0x9cf3 as u64) as u32) as u64);
    s.registers[17] = ((insert_bits(((s.registers[17] as u32) as u64), 0x2944, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = (((0xfff7 as u64) as u32) as u64);
    s.registers[17] = ((insert_bits(((s.registers[17] as u32) as u64), 0x1ec7, 16, 16, 32) as u32) as u64);
    s.registers[17] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) & ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = (((0xd6000000 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[15] as u32) as u64) | ((s.registers[8] as u32) as u64))) as u32) as u64);
    let value183 = s.load(((s.registers[3]).wrapping_add(s.registers[0])), 1)?;

    s.registers[15] = ((value183 as u32) as u64);
    s.registers[24] = (((0x69 as u64) as u32) as u64);
    s.registers[15] = (((((((s.registers[15] as u32) as u64)).wrapping_mul(((s.registers[24] as u32) as u64))).wrapping_add(((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[27] as u32) as u64) & (0xfffffff7 as u64))) as u32) as u64);
    s.registers[26] = (((s.registers[17] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 1008), s.registers[26], 8)?;
    s.registers[17] = ((((((s.registers[15] as u32) as u64) & (0xfc as u64))) as u32) as u64);
    s.registers[0] = (((0x1994 as u64) as u32) as u64);
    s.registers[0] = ((insert_bits(((s.registers[0] as u32) as u64), 0x7940, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[0] as u32) as u64) ^ shift_left(((s.registers[14] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ (0xffffff7f as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[17] as u32) as u64) & ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[17] = (((0x6b as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) & ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) | ((s.registers[15] as u32) as u64))) as u32) as u64);
    let value198 = s.load(((s.registers[22]).wrapping_add(s.registers[26])), 1)?;

    s.registers[15] = ((value198 as u32) as u64);
    s.registers[17] = (((0xe9 as u64) as u32) as u64);
    s.registers[17] = (((s.registers[15] ^ s.registers[17])) as u64);
    let value201 = s.load(((s.registers[1]).wrapping_add(s.registers[17])), 1)?;

    s.registers[17] = ((value201 as u32) as u64);
    s.registers[26] = (((0x9 as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[26] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[17] as u32) as u64)).wrapping_add(((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64)).wrapping_sub((0x5d as u64))) as u32) as u64);
    s.registers[17] = (((0xdb as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((shift_left(((s.registers[15] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64) | ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xeccf as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x2c4d, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xb8ffffff as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64) & ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xbd000000 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[15] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[27] as u32) as u64) & (0xfffffff8 as u64))) as u32) as u64);
    s.registers[9] = (((s.registers[9] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 896), s.registers[9], 8)?;
    let value222 = s.load(((s.registers[22]).wrapping_add(s.registers[9])), 1)?;

    s.registers[9] = ((value222 as u32) as u64);
    s.registers[11] = (((0xffffffe5 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((s.registers[9] ^ s.registers[10])) as u64);
    s.registers[15] = ((((((s.registers[11] as u32) as u64)).wrapping_sub((0x2c as u64))) as u32) as u64);
    let value227 = s.load(((s.registers[2]).wrapping_add(s.registers[9])), 1)?;

    s.registers[9] = ((value227 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[9] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[15] = (((0xa1c0 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0x5f23, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0xff13 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0xffe7, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[11] as u32) as u64) & ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[10] = (((0xcc as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[27] as u32) as u64) & (0xfffffffc as u64))) as u32) as u64);
    s.registers[9] = (((s.registers[9] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 952), s.registers[9], 8)?;
    let value244 = s.load(((s.registers[22]).wrapping_add(s.registers[9])), 1)?;

    s.registers[9] = ((value244 as u32) as u64);
    s.registers[11] = (((0xc4 as u64) as u32) as u64);
    s.registers[9] = (((s.registers[9] ^ s.registers[11])) as u64);
    s.registers[11] = ((((((s.registers[27] as u32) as u64) & (0xfffffff1 as u64))) as u32) as u64);
    s.registers[15] = (((s.registers[11] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 960), s.registers[15], 8)?;
    let value250 = s.load(((s.registers[3]).wrapping_add(s.registers[9])), 1)?;

    s.registers[9] = ((value250 as u32) as u64);
    s.registers[9] = (((((((s.registers[9] as u32) as u64)).wrapping_mul(((s.registers[24] as u32) as u64))).wrapping_add(((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[13] as u32) as u64) | ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[9] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0xabf1 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x255c, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ (0xffffff07 as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[12] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value259 = s.load(((s.registers[22]).wrapping_add(s.registers[15])), 1)?;

    s.registers[12] = ((value259 as u32) as u64);
    s.registers[16] = (((0x33 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0xaf as u64) as u32) as u64);
    s.registers[9] = (((s.registers[12] ^ s.registers[9])) as u64);
    let value265 = s.load(((s.registers[4]).wrapping_add(s.registers[9])), 1)?;

    s.registers[9] = ((value265 as u32) as u64);
    s.registers[11] = (((0xfffffff2 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[27] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.store_value(add_offset(s.sp, 888), ((s.registers[27] as u32) as u64), 4)?;
    s.registers[13] = (((s.registers[11] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 904), s.registers[13], 8)?;
    s.registers[11] = (((0x6c00 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64)).wrapping_add(shift_left(((s.registers[9] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[11] = (((0xdd7 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xa228, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((!(((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) | (0xfff800ff as u64))) as u32) as u64);
    let value278 = s.load(((s.registers[22]).wrapping_add(s.registers[13])), 1)?;

    s.registers[13] = ((value278 as u32) as u64);
    s.registers[11] = ((((((s.registers[12] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[10] = (((0xcd as u64) as u32) as u64);
    s.registers[12] = (((s.registers[13] ^ s.registers[10])) as u64);
    let value282 = s.load(((s.registers[1]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value282 as u32) as u64);
    s.registers[10] = (((0x2d as u64) as u32) as u64);
    s.registers[13] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xeb00 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) | ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((shift_left(((s.registers[12] as u32) as u64), ((0x10 as u64) as u64), 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_sub(shift_left((0x5d0 as u64), 12, 32))) as u32) as u64);
    s.registers[12] = (((0xabe as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0xe589, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[11] as u32) as u64) & (0xff0000 as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ (0xffc3ffff as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[12] as u32) as u64) & ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & (0x1e0000 as u64))) as u32) as u64);
    s.registers[12] = (((0x60 as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x5100, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) | ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[0] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0xfffffffa as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[27] as u32) as u64) & ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((s.registers[9] ^ s.registers[25])) as u64);
    s.store_value(add_offset(s.sp, 912), s.registers[9], 8)?;
    let value306 = s.load(((s.registers[22]).wrapping_add(s.registers[9])), 1)?;

    s.registers[9] = ((value306 as u32) as u64);
    s.registers[11] = (((0x44 as u64) as u32) as u64);
    s.registers[9] = (((s.registers[9] ^ s.registers[11])) as u64);
    let value309 = s.load(((s.registers[4]).wrapping_add(s.registers[9])), 1)?;

    s.registers[9] = ((value309 as u32) as u64);
    s.registers[9] = ((shift_left(((s.registers[9] as u32) as u64), ((0x10 as u64) as u64), 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_add(shift_left((0x6c0 as u64), 12, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & (0xff0000 as u64))) as u32) as u64);
    s.registers[11] = (((0xe998 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x57ca, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0x832c as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xa198, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0x1667 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xa827, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[2] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0x54fc as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x3a83, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    let value327 = s.load(add_offset(s.sp, 1092), 4)?;

    s.registers[13] = ((value327 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.store_value(add_offset(s.sp, 872), ((s.registers[15] as u32) as u64), 4)?;
    s.registers[8] = ((((((s.registers[15] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    let value332 = s.load(add_offset(s.sp, 748), 4)?;

    s.registers[11] = ((value332 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xac55 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x5715, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[8] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x454 as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x1201, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xb40f as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xe6b, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value344 = s.load(add_offset(s.sp, 772), 4)?;

    s.registers[22] = ((value344 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[22] as u32) as u64))) as u32) as u64);
    let value346 = s.load(add_offset(s.sp, 580), 4)?;

    s.registers[11] = ((value346 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) | ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xe0f3 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x34e8, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((shift_left(((s.registers[8] as u32) as u64), (((s.registers[19] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[11] = (((0xdff6 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xbf09, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & shift_left(((s.registers[8] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64)).wrapping_sub(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((shift_right(((s.registers[9] as u32) as u64), (((s.registers[28] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[11] = (((0x630e as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xaaef, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & shift_left(((s.registers[9] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_sub(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xb187 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x5577, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[9] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0xeffb as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x5f84, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[8] as u32) as u64)).wrapping_add(((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((0xe900 as u64) as u32) as u64);
    s.registers[8] = ((insert_bits(((s.registers[8] as u32) as u64), 0xba3a, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0x1004 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xa07b, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[11] as u32) as u64) & ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((0x138a as u64) as u32) as u64);
    s.registers[8] = ((insert_bits(((s.registers[8] as u32) as u64), 0x4758, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.store_value(add_offset(s.sp, 876), ((s.registers[17] as u32) as u64), 4)?;
    s.registers[14] = ((((((s.registers[17] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[8] = (((0x7fc2 as u64) as u32) as u64);
    s.registers[8] = ((insert_bits(((s.registers[8] as u32) as u64), 0x5178, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[21] as u32) as u64))) as u32) as u64);
    let value384 = s.load(add_offset(s.sp, 752), 4)?;

    s.registers[11] = ((value384 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((shift_right(((s.registers[8] as u32) as u64), (((s.registers[28] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[11] = (((0x22d6 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x893e, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & shift_left(((s.registers[8] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[8] as u32) as u64)).wrapping_sub(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((0x1ef6 as u64) as u32) as u64);
    s.registers[8] = ((insert_bits(((s.registers[8] as u32) as u64), 0x7dfd, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[0] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[6] as u32) as u64))) as u32) as u64);
    s.store_value(add_offset(s.sp, 868), ((s.registers[0] as u32) as u64), 4)?;
    s.registers[8] = ((((((s.registers[0] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[11] = (((0x1ef7 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x7dfd, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value400 = s.load(add_offset(s.sp, 744), 4)?;

    s.registers[13] = ((value400 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x3701 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xe935, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[8] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x1601 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x6935, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xedfa as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xf7ef, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) & ((s.registers[6] as u32) as u64))) as u32) as u64);
    s.store_value(add_offset(s.sp, 864), ((s.registers[2] as u32) as u64), 4)?;
    s.registers[1] = ((((((s.registers[2] as u32) as u64) ^ shift_right(((s.registers[1] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[13] = (((0x2fb9 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x44aa, 16, 16, 32) as u32) as u64);
    s.registers[2] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) & ((s.registers[21] as u32) as u64))) as u32) as u64);
    let value419 = s.load(add_offset(s.sp, 572), 4)?;

    s.registers[13] = ((value419 as u32) as u64);
    s.registers[2] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[2] as u32) as u64))) as u32) as u64);
    s.registers[2] = ((shift_right(((s.registers[2] as u32) as u64), (((s.registers[7] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0x4e20 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x8568, 16, 16, 32) as u32) as u64);
    s.registers[3] = ((((((s.registers[13] as u32) as u64) & shift_left(((s.registers[2] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64)).wrapping_sub(((s.registers[3] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x2710 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xc2b4, 16, 16, 32) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    let value429 = s.load(add_offset(s.sp, 1088), 4)?;

    s.registers[10] = ((value429 as u32) as u64);
    let value430 = s.load(add_offset(s.sp, 1056), 4)?;

    s.registers[13] = ((value430 as u32) as u64);
    s.registers[3] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let value432 = s.load(add_offset(s.sp, 796), 4)?;

    s.registers[13] = ((value432 as u32) as u64);
    s.registers[3] = ((((((s.registers[3] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value434 = s.load(add_offset(s.sp, 548), 4)?;

    s.registers[13] = ((value434 as u32) as u64);
    s.registers[4] = ((((((s.registers[3] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value436 = s.load(add_offset(s.sp, 740), 4)?;

    s.registers[13] = ((value436 as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[2] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[2] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xcf9 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x2462, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) & ((s.registers[30] as u32) as u64))) as u32) as u64);
    let value443 = s.load(add_offset(s.sp, 588), 4)?;

    s.registers[13] = ((value443 as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) | ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xe102 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xd38d, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[1] = ((shift_left(((s.registers[1] as u32) as u64), (((s.registers[5] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0x6170 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xf4b5, 16, 16, 32) as u32) as u64);
    s.registers[4] = ((((((s.registers[13] as u32) as u64) & shift_left(((s.registers[1] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64)).wrapping_sub(((s.registers[4] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xb0b8 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xfa5a, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[4] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[1] as u32) as u64))) as u32) as u64);
    let value457 = s.load(add_offset(s.sp, 736), 4)?;

    s.registers[13] = ((value457 as u32) as u64);
    s.registers[1] = ((((((s.registers[3] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value459 = s.load(add_offset(s.sp, 800), 4)?;

    s.registers[13] = ((value459 as u32) as u64);
    let value460 = s.load(add_offset(s.sp, 792), 4)?;

    s.registers[6] = ((value460 as u32) as u64);
    s.registers[2] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value462 = s.load(add_offset(s.sp, 764), 4)?;

    s.registers[13] = ((value462 as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value464 = s.load(add_offset(s.sp, 768), 4)?;

    s.registers[13] = ((value464 as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[2] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xc465 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x1e07, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & ((s.registers[22] as u32) as u64))) as u32) as u64);
    let value471 = s.load(add_offset(s.sp, 576), 4)?;

    s.registers[13] = ((value471 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) | ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((shift_right(((s.registers[11] as u32) as u64), (((s.registers[7] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0xda92 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x63fa, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((shift_left(((s.registers[8] as u32) as u64), (((s.registers[19] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xa778 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x10b2, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value483 = s.load(add_offset(s.sp, 732), 4)?;

    s.registers[11] = ((value483 as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[7] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0xcb1a as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x7b1c, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[30] as u32) as u64))) as u32) as u64);
    let value490 = s.load(add_offset(s.sp, 584), 4)?;

    s.registers[11] = ((value490 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) | ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xd890 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x3c44, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((shift_left(((s.registers[9] as u32) as u64), (((s.registers[5] as u32) as u64) as u64), 32) as u32) as u64);
    s.registers[11] = (((0x812c as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x6224, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & shift_left(((s.registers[9] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_sub(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0x4096 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x3112, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[9] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0x116b as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0xc49f, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[15] as u32) as u64)).wrapping_add(((s.registers[9] as u32) as u64))) as u32) as u64);
    let value506 = s.load(add_offset(s.sp, 728), 4)?;

    s.registers[12] = ((value506 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0x75 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value511 = s.load(add_offset(s.registers[29], (-248)), 8)?;

    s.registers[13] = (value511 as u64);
    let value512 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[9] = ((value512 as u32) as u64);
    s.registers[22] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[7] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[12] = (((0xa3 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    let value517 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[12] = ((value517 as u32) as u64);
    s.registers[11] = (((0xb6 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    let value520 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[14] = ((value520 as u32) as u64);
    s.registers[11] = (((((((s.registers[22] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[15] = (((0x24 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    let value524 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[15] = ((value524 as u32) as u64);
    s.registers[11] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x4e as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let value528 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[1] = ((value528 as u32) as u64);
    s.registers[11] = ((shift_right(((s.registers[22] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[19] = ((((((s.registers[11] as u32) as u64) ^ (0x70 as u64))) as u32) as u64);
    s.registers[11] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[30] = (((0x92 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[30] as u32) as u64))) as u32) as u64);
    let value534 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[2] = ((value534 as u32) as u64);
    s.registers[11] = (((0x74 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ shift_right(((s.registers[4] as u32) as u64), 24, 32))) as u32) as u64);
    let value537 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[3] = ((value537 as u32) as u64);
    s.registers[10] = (((0xa6 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[10] as u32) as u64) ^ shift_right(((s.registers[7] as u32) as u64), 24, 32))) as u32) as u64);
    let value540 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[20] = ((value540 as u32) as u64);
    s.registers[11] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x51 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[23] = (((s.registers[13]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[11] = (((s.registers[11])).wrapping_neg() as u64);
    s.registers[21] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[11] = (((s.registers[21]).wrapping_add(shift_left(s.registers[11], 2, 64))) as u64);
    s.registers[21] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0x5e as u64) as u32) as u64);
    s.registers[24] = ((((((s.registers[21] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[19] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[21] = (((s.registers[11]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[21] = (((s.registers[21]).wrapping_add(shift_left(s.registers[19], 2, 64))) as u64);
    s.registers[19] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[19] = (((s.registers[21]).wrapping_add(shift_left(s.registers[19], 2, 64))) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[10] = (((0x45 as u64) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[19] = (((s.registers[19]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[24] = ((((((s.registers[22] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[24] = ((((((s.registers[24] as u32) as u64) ^ (0x10 as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[19]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[25] = (((s.registers[25]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[4] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[4] = (((s.registers[25]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[7] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[7] = ((((((s.registers[7] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[24] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[7] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((((((s.registers[22] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[0] = (((0x9e as u64) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[0] as u32) as u64))) as u32) as u64);
    s.registers[7] = (((s.registers[7])).wrapping_neg() as u64);
    s.registers[22] = (((s.registers[24]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[22]).wrapping_add(shift_left(s.registers[7], 2, 64))) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0x71 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[22] = (((s.registers[7]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[22] = (((s.registers[22]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    let value582 = s.load(s.registers[23], 4)?;

    s.registers[4] = ((value582 as u32) as u64);
    let value583 = s.load(add_offset(s.sp, 784), 4)?;

    s.registers[13] = ((value583 as u32) as u64);
    s.registers[27] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value585 = s.load(add_offset(s.sp, 724), 4)?;

    s.registers[13] = ((value585 as u32) as u64);
    s.registers[23] = ((((((s.registers[27] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value587 = s.load(add_offset(s.sp, 760), 4)?;

    s.registers[13] = ((value587 as u32) as u64);
    s.registers[23] = ((((((s.registers[23] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[4] = ((((((s.registers[23] as u32) as u64) ^ ((s.registers[4] as u32) as u64))) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ rotate_right(((s.registers[20] as u32) as u64), 24, 32))) as u32) as u64);
    let value591 = s.load(s.registers[19], 4)?;

    s.registers[19] = ((value591 as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ rotate_right(((s.registers[19] as u32) as u64), 16, 32))) as u32) as u64);
    let value593 = s.load(s.registers[7], 4)?;

    s.registers[7] = ((value593 as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ rotate_right(((s.registers[7] as u32) as u64), 8, 32))) as u32) as u64);
    let value595 = s.load(s.registers[11], 4)?;

    s.registers[11] = ((value595 as u32) as u64);
    let value596 = s.load(add_offset(s.sp, 720), 4)?;

    s.registers[13] = ((value596 as u32) as u64);
    s.registers[1] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[1] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[1] as u32) as u64) ^ rotate_right(((s.registers[11] as u32) as u64), 24, 32))) as u32) as u64);
    let value599 = s.load(s.registers[24], 4)?;

    s.registers[1] = ((value599 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ rotate_right(((s.registers[1] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[22]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    let value603 = s.load(s.registers[22], 4)?;

    s.registers[1] = ((value603 as u32) as u64);
    s.registers[1] = ((((((s.registers[11] as u32) as u64) ^ rotate_right(((s.registers[1] as u32) as u64), 16, 32))) as u32) as u64);
    let value605 = s.load(add_offset(s.sp, 788), 4)?;

    s.registers[11] = ((value605 as u32) as u64);
    let value606 = s.load(add_offset(s.sp, 780), 4)?;

    s.registers[13] = ((value606 as u32) as u64);
    s.registers[28] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value608 = s.load(add_offset(s.sp, 716), 4)?;

    s.registers[13] = ((value608 as u32) as u64);
    s.registers[7] = ((((((s.registers[28] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value610 = s.load(add_offset(s.sp, 712), 4)?;

    s.registers[13] = ((value610 as u32) as u64);
    s.registers[7] = ((((((s.registers[7] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[2] = ((((((s.registers[7] as u32) as u64) ^ rotate_right(((s.registers[2] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ rotate_right(((s.registers[3] as u32) as u64), 24, 32))) as u32) as u64);
    let value614 = s.load(s.registers[21], 4)?;

    s.registers[3] = ((value614 as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[3] as u32) as u64))) as u32) as u64);
    let value616 = s.load(s.registers[25], 4)?;

    s.registers[3] = ((value616 as u32) as u64);
    s.registers[7] = ((((((s.registers[2] as u32) as u64) ^ rotate_right(((s.registers[3] as u32) as u64), 16, 32))) as u32) as u64);
    let value618 = s.load(add_offset(s.sp, 708), 4)?;

    s.registers[13] = ((value618 as u32) as u64);
    s.registers[9] = ((((((s.registers[13] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[4] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ (0x78 as u64))) as u32) as u64);
    let value625 = s.load(((s.registers[8]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[12] = ((value625 as u32) as u64);
    s.registers[9] = ((shift_right(((s.registers[7] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[9] as u32) as u64) ^ (0x18 as u64))) as u32) as u64);
    s.registers[9] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0xf5 as u64) as u32) as u64);
    s.registers[2] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[2] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = (((s.registers[2])).wrapping_neg() as u64);
    s.registers[2] = (((s.registers[9]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[2] = (((s.registers[2]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[14])).wrapping_neg() as u64);
    s.registers[13] = (((0xfa as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[13] as u32) as u64) ^ shift_right(((s.registers[4] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[14] = (((s.registers[2]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[14] = (((s.registers[14]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[14]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[3] = (((((((s.registers[15] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x87 as u64) as u32) as u64);
    s.registers[19] = ((((((s.registers[3] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[3] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = ((((((s.registers[15] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[26] as u32) as u64))) as u32) as u64);
    s.registers[19] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[20] = (((s.registers[3]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[20] = (((s.registers[20]).wrapping_add(shift_left(s.registers[19], 2, 64))) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[20]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[19] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x2c as u64) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[21] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0xe4 as u64) as u32) as u64);
    s.registers[21] = ((((((s.registers[21] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[19] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[22] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[21] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[22] = (((s.registers[22]).wrapping_add(shift_left(s.registers[19], 2, 64))) as u64);
    s.registers[4] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0x48 as u64) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[19] = (((s.registers[21])).wrapping_neg() as u64);
    s.registers[21] = (((s.registers[22]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[19] = (((s.registers[21]).wrapping_add(shift_left(s.registers[19], 2, 64))) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[4] = (((s.registers[19]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[21] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[5] = (((0x88 as u64) as u32) as u64);
    s.registers[21] = ((((((s.registers[21] as u32) as u64) ^ ((s.registers[5] as u32) as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[21] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = ((((((s.registers[7] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[10] = (((0x57 as u64) as u32) as u64);
    s.registers[7] = ((((((s.registers[7] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[21] = (((s.registers[21])).wrapping_neg() as u64);
    s.registers[23] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[7] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[21] = (((s.registers[23]).wrapping_add(shift_left(s.registers[21], 2, 64))) as u64);
    s.registers[7] = (((s.registers[7])).wrapping_neg() as u64);
    s.registers[7] = (((s.registers[21]).wrapping_add(shift_left(s.registers[7], 2, 64))) as u64);
    s.registers[23] = ((((((s.registers[30] as u32) as u64) ^ shift_right(((s.registers[15] as u32) as u64), 24, 32))) as u32) as u64);
    let value684 = s.load(((s.registers[7]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[23] = ((value684 as u32) as u64);
    s.registers[16] = (((0x36 as u64) as u32) as u64);
    s.registers[24] = ((((((s.registers[16] as u32) as u64) ^ shift_right(((s.registers[1] as u32) as u64), 24, 32))) as u32) as u64);
    let value687 = s.load(((s.registers[7]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[24] = ((value687 as u32) as u64);
    s.registers[10] = (((0xff as u64) as u32) as u64);
    s.registers[25] = ((((((s.registers[10] as u32) as u64) & !(shift_right(((s.registers[1] as u32) as u64), 8, 32)))) as u32) as u64);
    s.registers[7] = (((s.registers[7]).wrapping_add(shift_left(((((s.registers[25] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[16] = (((0x77 as u64) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[25] = (((s.registers[25])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[7]).wrapping_add(shift_left(((((s.registers[1] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[25] = (((s.registers[26]).wrapping_add(shift_left(s.registers[25], 2, 64))) as u64);
    let value697 = s.load(s.registers[9], 4)?;

    s.registers[9] = ((value697 as u32) as u64);
    let value698 = s.load(s.registers[20], 4)?;

    s.registers[20] = ((value698 as u32) as u64);
    let value699 = s.load(add_offset(s.sp, 704), 4)?;

    s.registers[16] = ((value699 as u32) as u64);
    s.registers[9] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[20] as u32) as u64), 16, 32))) as u32) as u64);
    let value702 = s.load(s.registers[8], 4)?;

    s.registers[8] = ((value702 as u32) as u64);
    s.registers[8] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[24] as u32) as u64), 24, 32))) as u32) as u64);
    let value705 = s.load(s.registers[22], 4)?;

    s.registers[8] = ((value705 as u32) as u64);
    let value706 = s.load(add_offset(s.sp, 700), 4)?;

    s.registers[16] = ((value706 as u32) as u64);
    s.registers[12] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    let value709 = s.load(s.registers[4], 4)?;

    s.registers[12] = ((value709 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[4] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[23] as u32) as u64), 24, 32))) as u32) as u64);
    let value712 = s.load(s.registers[2], 4)?;

    s.registers[8] = ((value712 as u32) as u64);
    let value713 = s.load(s.registers[3], 4)?;

    s.registers[12] = ((value713 as u32) as u64);
    let value714 = s.load(add_offset(s.sp, 544), 4)?;

    s.registers[16] = ((value714 as u32) as u64);
    s.registers[8] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_left(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    let value718 = s.load(s.registers[19], 4)?;

    s.registers[12] = ((value718 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((s.registers[1])).wrapping_neg() as u64);
    s.registers[12] = (((s.registers[25]).wrapping_add(shift_left(s.registers[12], 2, 64))) as u64);
    let value722 = s.load(s.registers[25], 4)?;

    s.registers[1] = ((value722 as u32) as u64);
    s.registers[1] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[1] as u32) as u64), 16, 32))) as u32) as u64);
    let value724 = s.load(s.registers[14], 4)?;

    s.registers[8] = ((value724 as u32) as u64);
    let value725 = s.load(s.registers[21], 4)?;

    s.registers[14] = ((value725 as u32) as u64);
    let value726 = s.load(add_offset(s.sp, 696), 4)?;

    s.registers[16] = ((value726 as u32) as u64);
    s.registers[8] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 16, 32))) as u32) as u64);
    let value729 = s.load(s.registers[7], 4)?;

    s.registers[14] = ((value729 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[14] = (((((((s.registers[15] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[15] = (((0xb8 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    let value734 = s.load(((s.registers[12]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[14] = ((value734 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0xb5 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    let value738 = s.load(((s.registers[12]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[14] = ((value738 as u32) as u64);
    s.registers[15] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0xcd as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((s.registers[12]).wrapping_add(shift_left(((((s.registers[15] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[2] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0x5 as u64) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[10] = (((0x5 as u64) as u32) as u64);
    s.registers[15] = (((s.registers[15])).wrapping_neg() as u64);
    s.registers[3] = (((s.registers[12]).wrapping_add(shift_left(((((s.registers[2] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[3]).wrapping_add(shift_left(s.registers[15], 2, 64))) as u64);
    s.registers[15] = ((((((s.registers[8] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[16] = (((0xa1 as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((s.registers[2])).wrapping_neg() as u64);
    s.registers[2] = (((s.registers[7]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[15] = (((s.registers[2]).wrapping_add(shift_left(s.registers[15], 2, 64))) as u64);
    s.registers[2] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[2] = (((s.registers[15]).wrapping_add(shift_left(s.registers[2], 2, 64))) as u64);
    s.registers[3] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0x73 as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[3] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[2] = (((s.registers[2]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[19] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ (0xf as u64))) as u32) as u64);
    s.registers[3] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[20] = (((s.registers[2]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[3] = (((s.registers[20]).wrapping_add(shift_left(s.registers[3], 2, 64))) as u64);
    s.registers[16] = (((0x17a1 as u64) as u32) as u64);
    s.registers[16] = ((insert_bits(((s.registers[16] as u32) as u64), 0x8da4, 16, 16, 32) as u32) as u64);
    s.registers[21] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[4] = (((s.registers[3]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[8] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0x6a as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value775 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[8] = ((value775 as u32) as u64);
    s.registers[19] = (((((((s.registers[21] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    let value777 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[19] = ((value777 as u32) as u64);
    s.registers[22] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[19] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[21] as u32) as u64) & (0xff as u64))) as u32) as u64);
    let value780 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[8] = ((value780 as u32) as u64);
    s.registers[19] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[23] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[19] = (((((((s.registers[21] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[20] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[24] = (((s.registers[20]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[4] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[4] = (((s.registers[24]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[19] = ((((((s.registers[9] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0xa4 as u64) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value793 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[19] = ((value793 as u32) as u64);
    s.registers[16] = (((0x7a0d as u64) as u32) as u64);
    s.registers[20] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[16] = (((0xceb10000 as u64) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[19] = ((extract_pair(((s.registers[20] as u32) as u64), ((s.registers[19] as u32) as u64), 16, 32) as u32) as u64);
    s.registers[17] = (((0x976 as u64) as u32) as u64);
    s.registers[17] = ((insert_bits(((s.registers[17] as u32) as u64), 0x431f, 16, 16, 32) as u32) as u64);
    let value801 = s.load(add_offset(s.sp, 1048), 4)?;

    s.registers[16] = ((value801 as u32) as u64);
    s.compare32((((s.registers[16] as u32) as u64) as u32), (((s.registers[17] as u32) as u64) as u32));
    s.registers[16] = ((bool_value(s.condition("lo")) as u32) as u64);
    s.store_value(add_offset(s.sp, 892), ((s.registers[16] as u32) as u64), 4)?;
    s.registers[16] = (((0x2000000 as u64) as u32) as u64);
    s.registers[25] = ((((((s.registers[16] as u32) as u64) & !(((s.registers[22] as u32) as u64)))) as u32) as u64);
    s.test32(((((s.registers[19] as u32) as u64) & ((s.registers[25] as u32) as u64)) as u32));
    s.registers[26] = ((shift_left(((s.registers[25] as u32) as u64), ((0x1 as u64) as u64), 32) as u32) as u64);
    s.registers[26] = ((select_value(s.condition("eq"), (0 as u64), ((((s.registers[26] as u32) as u64))).wrapping_neg()) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64)).wrapping_add(((s.registers[25] as u32) as u64))) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64)).wrapping_add(((s.registers[26] as u32) as u64))) as u32) as u64);
    let value812 = s.load(s.registers[7], 4)?;

    s.registers[7] = ((value812 as u32) as u64);
    let value813 = s.load(add_offset(s.sp, 692), 4)?;

    s.registers[16] = ((value813 as u32) as u64);
    s.registers[14] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[7] as u32) as u64), 8, 32))) as u32) as u64);
    let value816 = s.load(s.registers[24], 4)?;

    s.registers[7] = ((value816 as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[7] as u32) as u64))) as u32) as u64);
    s.registers[7] = ((((((s.registers[1] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[16] = (((0xc2 as u64) as u32) as u64);
    s.registers[7] = ((((((s.registers[7] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    let value821 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[7] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[7] = ((value821 as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[7] as u32) as u64), 16, 32))) as u32) as u64);
    let value823 = s.load(s.registers[12], 4)?;

    s.registers[12] = ((value823 as u32) as u64);
    let value824 = s.load(s.registers[15], 4)?;

    s.registers[15] = ((value824 as u32) as u64);
    let value825 = s.load(add_offset(s.sp, 540), 4)?;

    s.registers[16] = ((value825 as u32) as u64);
    s.registers[12] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 16, 32))) as u32) as u64);
    let value828 = s.load(s.registers[2], 4)?;

    s.registers[15] = ((value828 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((shift_right(((s.registers[21] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    let value831 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[15] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[15] = ((value831 as u32) as u64);
    s.registers[21] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 24, 32))) as u32) as u64);
    let value833 = s.load(s.registers[3], 4)?;

    s.registers[12] = ((value833 as u32) as u64);
    let value834 = s.load(add_offset(s.sp, 688), 4)?;

    s.registers[15] = ((value834 as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 16, 32))) as u32) as u64);
    let value837 = s.load(s.registers[23], 4)?;

    s.registers[12] = ((value837 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x9c as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ shift_right(((s.registers[1] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[20] = (((0xdd as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[20] as u32) as u64) ^ shift_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    let value843 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[12] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[12] = ((value843 as u32) as u64);
    let value844 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[9] = ((value844 as u32) as u64);
    s.registers[9] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[22] as u32) as u64) & (0xfdffffff as u64))) as u32) as u64);
    let value847 = s.load(add_offset(s.sp, 684), 4)?;

    s.registers[15] = ((value847 as u32) as u64);
    s.registers[8] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[12] = (((0x5615 as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0xbe50, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[19] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[19] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((((((s.registers[21] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    let value856 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[2] = ((value856 as u32) as u64);
    s.registers[8] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[12] = (((0xee as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    let value860 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[12] = ((value860 as u32) as u64);
    s.registers[8] = ((((((s.registers[19] as u32) as u64) & (0xff as u64))) as u32) as u64);
    let value862 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[1] = ((value862 as u32) as u64);
    s.registers[8] = (((0x76 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_right(((s.registers[14] as u32) as u64), 24, 32))) as u32) as u64);
    let value865 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[3] = ((value865 as u32) as u64);
    s.registers[8] = ((((((s.registers[14] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[17] = (((0x34 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[16] = (((0x2d as u64) as u32) as u64);
    s.registers[4] = ((((((s.registers[16] as u32) as u64) ^ shift_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[7] = (((s.registers[15]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[7]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[22] = (((((((s.registers[19] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[4] = (((s.registers[7]).wrapping_add(shift_left(((((s.registers[22] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[4]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[22])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[4]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[22] = ((((((s.registers[21] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[23] = ((((((s.registers[22] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[22] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = (((s.registers[23])).wrapping_neg() as u64);
    s.registers[23] = ((shift_right(((s.registers[19] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[24] = (((s.registers[22]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = (((s.registers[24]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[24] = ((shift_right(((s.registers[21] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[24] = ((((((s.registers[24] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[23] = (((s.registers[23])).wrapping_neg() as u64);
    s.registers[23] = (((s.registers[8]).wrapping_add(shift_left(s.registers[23], 2, 64))) as u64);
    s.registers[21] = (((((((s.registers[21] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[21] = ((((((s.registers[21] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    let value894 = s.load(((s.registers[23]).wrapping_add(shift_left(((((s.registers[21] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[21] = ((value894 as u32) as u64);
    s.registers[25] = (((((((s.registers[14] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[16] = (((0xdf as u64) as u32) as u64);
    s.registers[25] = ((((((s.registers[25] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    let value898 = s.load(((s.registers[23]).wrapping_add(shift_left(((((s.registers[25] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[25] = ((value898 as u32) as u64);
    s.registers[26] = ((((((s.registers[9] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[16] = (((0x19 as u64) as u32) as u64);
    s.registers[26] = ((((((s.registers[26] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    let value902 = s.load(((s.registers[23]).wrapping_add(shift_left(((((s.registers[26] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[26] = ((value902 as u32) as u64);
    s.registers[23] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[19] = (((((((s.registers[19] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[24] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[6] = (((s.registers[6]).wrapping_add(shift_left(s.registers[24], 2, 64))) as u64);
    s.registers[14] = (((((((s.registers[14] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ (0x3f as u64))) as u32) as u64);
    s.registers[19] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[24] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[19] = (((s.registers[24]).wrapping_add(shift_left(s.registers[19], 2, 64))) as u64);
    s.registers[9] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[16] = (((0xf9 as u64) as u32) as u64);
    s.registers[24] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((s.registers[14])).wrapping_neg() as u64);
    s.registers[14] = (((s.registers[19]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[14] = (((s.registers[14]).wrapping_add(shift_left(s.registers[9], 2, 64))) as u64);
    let value919 = s.load(s.registers[8], 4)?;

    s.registers[8] = ((value919 as u32) as u64);
    let value920 = s.load(add_offset(s.sp, 680), 4)?;

    s.registers[9] = ((value920 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[2] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[9] as u32) as u64) ^ shift_left(((s.registers[8] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[26] as u32) as u64), 16, 32))) as u32) as u64);
    let value925 = s.load(s.registers[19], 4)?;

    s.registers[9] = ((value925 as u32) as u64);
    s.registers[9] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    let value927 = s.load(add_offset(s.sp, 676), 4)?;

    s.registers[8] = ((value927 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[1] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[3] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[21] as u32) as u64))) as u32) as u64);
    s.registers[1] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[1] = (((s.registers[14]).wrapping_add(shift_left(s.registers[1], 2, 64))) as u64);
    let value933 = s.load(s.registers[14], 4)?;

    s.registers[14] = ((value933 as u32) as u64);
    s.registers[2] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 8, 32))) as u32) as u64);
    let value935 = s.load(s.registers[7], 4)?;

    s.registers[8] = ((value935 as u32) as u64);
    let value936 = s.load(s.registers[22], 4)?;

    s.registers[14] = ((value936 as u32) as u64);
    let value937 = s.load(add_offset(s.sp, 672), 4)?;

    s.registers[16] = ((value937 as u32) as u64);
    s.registers[8] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_left(((s.registers[14] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_right(((s.registers[14] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[25] as u32) as u64), 8, 32))) as u32) as u64);
    let value942 = s.load(s.registers[6], 4)?;

    s.registers[14] = ((value942 as u32) as u64);
    s.registers[7] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    let value944 = s.load(s.registers[15], 4)?;

    s.registers[8] = ((value944 as u32) as u64);
    let value945 = s.load(add_offset(s.sp, 668), 4)?;

    s.registers[14] = ((value945 as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 16, 32))) as u32) as u64);
    let value948 = s.load(s.registers[4], 4)?;

    s.registers[12] = ((value948 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    let value950 = s.load(s.registers[23], 4)?;

    s.registers[12] = ((value950 as u32) as u64);
    s.registers[4] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value954 = s.load(((s.registers[1]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[12] = ((value954 as u32) as u64);
    s.registers[8] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ (0xf as u64))) as u32) as u64);
    let value957 = s.load(((s.registers[1]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[14] = ((value957 as u32) as u64);
    s.registers[8] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let value960 = s.load(((s.registers[1]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[19] = ((value960 as u32) as u64);
    s.registers[8] = ((((((s.registers[20] as u32) as u64) ^ shift_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[15] = (((s.registers[1]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[1] = ((((((s.registers[7] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[10] = (((0x45 as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[1] = (((s.registers[15]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[1] = (((s.registers[1]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[1]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[3] = ((((((s.registers[0] as u32) as u64) ^ shift_right(((s.registers[4] as u32) as u64), 24, 32))) as u32) as u64);
    let value972 = s.load(((s.registers[8]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[6] = ((value972 as u32) as u64);
    s.registers[3] = ((((((s.registers[4] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[11] = (((0xe7 as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[3] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value976 = s.load(((s.registers[8]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[3] = ((value976 as u32) as u64);
    s.registers[21] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0x4c as u64) as u32) as u64);
    s.registers[21] = ((((((s.registers[21] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value980 = s.load(((s.registers[8]).wrapping_add(shift_left(((((s.registers[21] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[21] = ((value980 as u32) as u64);
    s.registers[22] = ((((((s.registers[2] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[10] = (((0xbb as u64) as u32) as u64);
    s.registers[22] = ((((((s.registers[22] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let value984 = s.load(((s.registers[8]).wrapping_add(shift_left(((((s.registers[22] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[22] = ((value984 as u32) as u64);
    s.registers[10] = (((0x42 as u64) as u32) as u64);
    s.registers[23] = ((((((s.registers[10] as u32) as u64) ^ shift_right(((s.registers[7] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[24] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x43 as u64) as u32) as u64);
    s.registers[24] = ((((((s.registers[24] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[23] = (((s.registers[23])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[23] = (((s.registers[25]).wrapping_add(shift_left(s.registers[23], 2, 64))) as u64);
    s.registers[24] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[24] = (((s.registers[23]).wrapping_add(shift_left(s.registers[24], 2, 64))) as u64);
    s.registers[25] = ((shift_right(((s.registers[2] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[2] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[16] = (((0x29 as u64) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    let value1000 = s.load(((s.registers[24]).wrapping_add(shift_left(((((s.registers[2] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[26] = ((value1000 as u32) as u64);
    s.registers[2] = ((((((s.registers[25] as u32) as u64) ^ (0x1e as u64))) as u32) as u64);
    let value1002 = s.load(((s.registers[24]).wrapping_add(shift_left(((((s.registers[2] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[2] = ((value1002 as u32) as u64);
    s.registers[7] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[24] = (((s.registers[24]).wrapping_add(shift_left(((((s.registers[7] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0x8b as u64) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[7] = (((s.registers[7])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[24]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[25]).wrapping_add(shift_left(s.registers[7], 2, 64))) as u64);
    let value1011 = s.load(add_offset(s.sp, 664), 4)?;

    s.registers[16] = ((value1011 as u32) as u64);
    s.registers[19] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[19] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[6] = ((((((s.registers[19] as u32) as u64) ^ rotate_right(((s.registers[6] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[21] as u32) as u64))) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ rotate_right(((s.registers[22] as u32) as u64), 16, 32))) as u32) as u64);
    let value1016 = s.load(s.registers[24], 4)?;

    s.registers[19] = ((value1016 as u32) as u64);
    let value1017 = s.load(add_offset(s.sp, 660), 4)?;

    s.registers[16] = ((value1017 as u32) as u64);
    s.registers[2] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[2] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ rotate_right(((s.registers[19] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[4] = (((s.registers[7]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    let value1022 = s.load(s.registers[7], 4)?;

    s.registers[7] = ((value1022 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value1025 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[9] = ((value1025 as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[7] as u32) as u64))) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 16, 32))) as u32) as u64);
    let value1028 = s.load(s.registers[15], 4)?;

    s.registers[9] = ((value1028 as u32) as u64);
    let value1029 = s.load(add_offset(s.sp, 536), 4)?;

    s.registers[15] = ((value1029 as u32) as u64);
    s.registers[14] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    let value1032 = s.load(s.registers[1], 4)?;

    s.registers[14] = ((value1032 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[26] as u32) as u64))) as u32) as u64);
    let value1035 = s.load(add_offset(s.sp, 656), 4)?;

    s.registers[14] = ((value1035 as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[3] as u32) as u64), 16, 32))) as u32) as u64);
    let value1038 = s.load(s.registers[8], 4)?;

    s.registers[8] = ((value1038 as u32) as u64);
    s.registers[8] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    let value1040 = s.load(s.registers[23], 4)?;

    s.registers[12] = ((value1040 as u32) as u64);
    s.registers[1] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[8] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[12] = (((0x2f as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[12] = ((((((s.registers[2] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0x95 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[14] = (((s.registers[15]).wrapping_add(shift_left(((((s.registers[12] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[14]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((0x7768 as u64) as u32) as u64);
    s.registers[8] = ((insert_bits(((s.registers[8] as u32) as u64), 0xb97d, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((s.registers[12])).wrapping_neg() as u64);
    s.registers[3] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[14] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[14] = (((s.registers[14]).wrapping_add(shift_left(s.registers[12], 2, 64))) as u64);
    s.registers[12] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[12] = (((s.registers[14]).wrapping_add(shift_left(s.registers[12], 2, 64))) as u64);
    s.registers[3] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x1d as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[3] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[21] = (((s.registers[12]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[12] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[13] = (((0x7b as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[13] as u32) as u64) ^ shift_right(((s.registers[1] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[6] = (((s.registers[21]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[12] = (((s.registers[6]).wrapping_add(shift_left(s.registers[12], 2, 64))) as u64);
    s.registers[3] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[6] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[7] = (((s.registers[12]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[7]).wrapping_add(shift_left(s.registers[3], 2, 64))) as u64);
    s.registers[3] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[7]).wrapping_add(shift_left(s.registers[3], 2, 64))) as u64);
    s.registers[19] = ((shift_right(((s.registers[8] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) & (0xff as u64))) as u32) as u64);
    let value1078 = s.load(((s.registers[6]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[3] = ((value1078 as u32) as u64);
    s.registers[24] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[6] = ((((((s.registers[17] as u32) as u64) ^ shift_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[19] = (((s.registers[24]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[19] = (((s.registers[19]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[19]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[6] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ (0x1f as u64))) as u32) as u64);
    s.registers[22] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = ((((((s.registers[9] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0x11 as u64) as u32) as u64);
    s.registers[23] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[22]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = (((s.registers[6]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[6] = (((s.registers[23])).wrapping_neg() as u64);
    s.registers[25] = ((((((s.registers[5] as u32) as u64) ^ shift_right(((s.registers[2] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[23] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[25] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[23] = (((s.registers[23]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[2] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ (0x10 as u64))) as u32) as u64);
    s.registers[6] = (((s.registers[25])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[2] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[6] = (((s.registers[25]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[25] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0x53 as u64) as u32) as u64);
    s.registers[25] = ((((((s.registers[25] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[2] = (((s.registers[2])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[25] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[2] = (((s.registers[26]).wrapping_add(shift_left(s.registers[2], 2, 64))) as u64);
    s.registers[9] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0x67 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[25] = (((s.registers[25])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[2]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[25] = (((s.registers[26]).wrapping_add(shift_left(s.registers[25], 2, 64))) as u64);
    let value1116 = s.load(s.registers[4], 4)?;

    s.registers[4] = ((value1116 as u32) as u64);
    let value1117 = s.load(s.registers[21], 4)?;

    s.registers[21] = ((value1117 as u32) as u64);
    let value1118 = s.load(add_offset(s.sp, 652), 4)?;

    s.registers[16] = ((value1118 as u32) as u64);
    s.registers[4] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[4] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[21] as u32) as u64))) as u32) as u64);
    let value1121 = s.load(s.registers[24], 4)?;

    s.registers[21] = ((value1121 as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ rotate_right(((s.registers[21] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[9] = (((s.registers[9])).wrapping_neg() as u64);
    s.registers[21] = (((s.registers[25]).wrapping_add(shift_left(s.registers[9], 2, 64))) as u64);
    let value1125 = s.load(s.registers[25], 4)?;

    s.registers[9] = ((value1125 as u32) as u64);
    s.registers[9] = ((((((s.registers[4] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 8, 32))) as u32) as u64);
    let value1127 = s.load(s.registers[14], 4)?;

    s.registers[14] = ((value1127 as u32) as u64);
    let value1128 = s.load(s.registers[19], 4)?;

    s.registers[4] = ((value1128 as u32) as u64);
    let value1129 = s.load(add_offset(s.sp, 648), 4)?;

    s.registers[16] = ((value1129 as u32) as u64);
    s.registers[14] = ((((((s.registers[16] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[4] as u32) as u64), 24, 32))) as u32) as u64);
    let value1132 = s.load(s.registers[6], 4)?;

    s.registers[4] = ((value1132 as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[4] as u32) as u64))) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0x17 as u64) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value1137 = s.load(((s.registers[21]).wrapping_add(shift_left(((((s.registers[1] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[1] = ((value1137 as u32) as u64);
    s.registers[4] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[1] as u32) as u64), 16, 32))) as u32) as u64);
    let value1139 = s.load(s.registers[7], 4)?;

    s.registers[14] = ((value1139 as u32) as u64);
    let value1140 = s.load(s.registers[22], 4)?;

    s.registers[1] = ((value1140 as u32) as u64);
    let value1141 = s.load(add_offset(s.sp, 532), 4)?;

    s.registers[16] = ((value1141 as u32) as u64);
    s.registers[14] = ((((((s.registers[16] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ shift_left(((s.registers[1] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ shift_right(((s.registers[1] as u32) as u64), 8, 32))) as u32) as u64);
    let value1145 = s.load(s.registers[8], 4)?;

    s.registers[8] = ((value1145 as u32) as u64);
    s.registers[8] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 16, 32))) as u32) as u64);
    let value1147 = s.load(s.registers[15], 4)?;

    s.registers[14] = ((value1147 as u32) as u64);
    let value1148 = s.load(s.registers[12], 4)?;

    s.registers[12] = ((value1148 as u32) as u64);
    let value1149 = s.load(add_offset(s.sp, 644), 4)?;

    s.registers[15] = ((value1149 as u32) as u64);
    s.registers[14] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[3] as u32) as u64), 16, 32))) as u32) as u64);
    let value1153 = s.load(s.registers[2], 4)?;

    s.registers[14] = ((value1153 as u32) as u64);
    s.registers[24] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    let value1155 = s.load(s.registers[23], 4)?;

    s.registers[12] = ((value1155 as u32) as u64);
    s.registers[14] = ((((((s.registers[24] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[10] = (((0xf2 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let (old1159, restore1159) = s.before_fault(selected, 0x100222ab0)?;

    let value1159 = s.load(((s.registers[21]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[15] = ((value1159 as u32) as u64);
    s.after_fault(selected, 0x100222ab0, old1159, restore1159);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[10] = (((0x56 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[10] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[0] = (((0x56 as u64) as u32) as u64);
    let (old1164, restore1164) = s.before_fault(selected, 0x100222ac4)?;

    let value1164 = s.load(((s.registers[21]).wrapping_add(shift_left(((((s.registers[12] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[12] = ((value1164 as u32) as u64);
    s.after_fault(selected, 0x100222ac4, old1164, restore1164);
    s.registers[14] = ((((((s.registers[8] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[30] as u32) as u64))) as u32) as u64);
    let (old1167, restore1167) = s.before_fault(selected, 0x100222ad0)?;

    let value1167 = s.load(((s.registers[21]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[14] = ((value1167 as u32) as u64);
    s.after_fault(selected, 0x100222ad0, old1167, restore1167);
    s.registers[1] = (((((((s.registers[24] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0x8e as u64) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let (old1171, restore1171) = s.before_fault(selected, 0x100222ae0)?;

    let value1171 = s.load(((s.registers[21]).wrapping_add(shift_left(((((s.registers[1] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[1] = ((value1171 as u32) as u64);
    s.after_fault(selected, 0x100222ae0, old1171, restore1171);
    s.registers[13] = (((0x3b as u64) as u32) as u64);
    s.registers[3] = ((((((s.registers[13] as u32) as u64) ^ shift_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[2] = (((s.registers[21]).wrapping_add(shift_left(((((s.registers[3] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[6] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0xaa as u64) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[3] = (((s.registers[3])).wrapping_neg() as u64);
    s.registers[7] = (((s.registers[2]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[3] = (((s.registers[7]).wrapping_add(shift_left(s.registers[3], 2, 64))) as u64);
    s.registers[6] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[3]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[30] = (((0xeb as u64) as u32) as u64);
    s.registers[7] = ((((((s.registers[30] as u32) as u64) ^ shift_right(((s.registers[4] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[21] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[7] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[6] = (((((((s.registers[24] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x2c as u64) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[7] = (((s.registers[7])).wrapping_neg() as u64);
    s.registers[19] = (((s.registers[21]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[19]).wrapping_add(shift_left(s.registers[7], 2, 64))) as u64);
    s.registers[19] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x54 as u64) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[6] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[22] = (((s.registers[7]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[22] = (((s.registers[22]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[6] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[22]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[19] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0xb0 as u64) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[6] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[23] = (((((((s.registers[4] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x47 as u64) as u32) as u64);
    s.registers[23] = ((((((s.registers[23] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[19] = (((s.registers[19])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[19] = (((s.registers[25]).wrapping_add(shift_left(s.registers[19], 2, 64))) as u64);
    s.registers[13] = (((0xa0 as u64) as u32) as u64);
    s.registers[24] = ((((((s.registers[13] as u32) as u64) ^ shift_right(((s.registers[24] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[23] = (((s.registers[23])).wrapping_neg() as u64);
    s.registers[23] = (((s.registers[19]).wrapping_add(shift_left(s.registers[23], 2, 64))) as u64);
    s.registers[8] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[20] = (((0x87 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[20] as u32) as u64))) as u32) as u64);
    let (old1217, restore1217) = s.before_fault(selected, 0x100222b98)?;

    let value1217 = s.load(((s.registers[23]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[8] = ((value1217 as u32) as u64);
    s.after_fault(selected, 0x100222b98, old1217, restore1217);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ (0x78 as u64))) as u32) as u64);
    s.registers[23] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[25]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[25] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[17] = (((0x7d as u64) as u32) as u64);
    s.registers[25] = ((((((s.registers[25] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[24] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[25] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[24] = (((s.registers[26]).wrapping_add(shift_left(s.registers[24], 2, 64))) as u64);
    let (old1230, restore1230) = s.before_fault(selected, 0x100222bcc)?;

    let value1230 = s.load(s.registers[19], 4)?;

    s.registers[19] = ((value1230 as u32) as u64);
    s.after_fault(selected, 0x100222bcc, old1230, restore1230);
    let value1231 = s.load(add_offset(s.sp, 640), 4)?;

    s.registers[13] = ((value1231 as u32) as u64);
    s.registers[19] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[19] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[19] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 8, 32))) as u32) as u64);
    let (old1234, restore1234) = s.before_fault(selected, 0x100222bdc)?;

    let value1234 = s.load(s.registers[4], 4)?;

    s.registers[4] = ((value1234 as u32) as u64);
    s.after_fault(selected, 0x100222bdc, old1234, restore1234);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[4] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1236, restore1236) = s.before_fault(selected, 0x100222be4)?;

    let value1236 = s.load(s.registers[21], 4)?;

    s.registers[4] = ((value1236 as u32) as u64);
    s.after_fault(selected, 0x100222be4, old1236, restore1236);
    let value1237 = s.load(add_offset(s.sp, 636), 4)?;

    s.registers[13] = ((value1237 as u32) as u64);
    s.registers[15] = ((((((s.registers[13] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[4] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1240, restore1240) = s.before_fault(selected, 0x100222bf4)?;

    let value1240 = s.load(s.registers[6], 4)?;

    s.registers[4] = ((value1240 as u32) as u64);
    s.after_fault(selected, 0x100222bf4, old1240, restore1240);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[4] as u32) as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[25])).wrapping_neg() as u64);
    s.registers[4] = (((s.registers[24]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    let (old1244, restore1244) = s.before_fault(selected, 0x100222c04)?;

    let value1244 = s.load(s.registers[24], 4)?;

    s.registers[6] = ((value1244 as u32) as u64);
    s.after_fault(selected, 0x100222c04, old1244, restore1244);
    s.registers[21] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[6] as u32) as u64), 8, 32))) as u32) as u64);
    let value1246 = s.load(add_offset(s.sp, 632), 4)?;

    s.registers[13] = ((value1246 as u32) as u64);
    s.registers[15] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[1] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[14] as u32) as u64), 16, 32))) as u32) as u64);
    let (old1249, restore1249) = s.before_fault(selected, 0x100222c18)?;

    let value1249 = s.load(s.registers[2], 4)?;

    s.registers[15] = ((value1249 as u32) as u64);
    s.after_fault(selected, 0x100222c18, old1249, restore1249);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1251, restore1251) = s.before_fault(selected, 0x100222c20)?;

    let value1251 = s.load(s.registers[3], 4)?;

    s.registers[15] = ((value1251 as u32) as u64);
    s.after_fault(selected, 0x100222c20, old1251, restore1251);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 8, 32))) as u32) as u64);
    let (old1253, restore1253) = s.before_fault(selected, 0x100222c28)?;

    let value1253 = s.load(s.registers[7], 4)?;

    s.registers[15] = ((value1253 as u32) as u64);
    s.after_fault(selected, 0x100222c28, old1253, restore1253);
    let value1254 = s.load(add_offset(s.sp, 628), 4)?;

    s.registers[13] = ((value1254 as u32) as u64);
    s.registers[12] = ((((((s.registers[13] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 8, 32))) as u32) as u64);
    let (old1257, restore1257) = s.before_fault(selected, 0x100222c38)?;

    let value1257 = s.load(s.registers[22], 4)?;

    s.registers[15] = ((value1257 as u32) as u64);
    s.after_fault(selected, 0x100222c38, old1257, restore1257);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    let (old1259, restore1259) = s.before_fault(selected, 0x100222c40)?;

    let value1259 = s.load(s.registers[23], 4)?;

    s.registers[15] = ((value1259 as u32) as u64);
    s.after_fault(selected, 0x100222c40, old1259, restore1259);
    s.registers[2] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[12] = (((0x55 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    let (old1264, restore1264) = s.before_fault(selected, 0x100222c54)?;

    let value1264 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[9] = ((value1264 as u32) as u64);
    s.after_fault(selected, 0x100222c54, old1264, restore1264);
    let (old1265, restore1265) = s.before_fault(selected, 0x100222c58)?;

    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_right(((s.registers[9] as u32) as u64), 16, 32))) as u32) as u64);
    s.after_fault(selected, 0x100222c58, old1265, restore1265);
    s.registers[12] = ((((((s.registers[8] as u32) as u64) ^ shift_left(((s.registers[9] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[9] = (((0xcfe as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x9678, 16, 16, 32) as u32) as u64);
    s.registers[23] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((((((s.registers[12] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    let (old1272, restore1272) = s.before_fault(selected, 0x100222c74)?;

    let value1272 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[9] = ((value1272 as u32) as u64);
    s.after_fault(selected, 0x100222c74, old1272, restore1272);
    s.registers[14] = ((shift_right(((s.registers[21] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[15] = ((shift_right(((s.registers[23] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    let (old1276, restore1276) = s.before_fault(selected, 0x100222c84)?;

    let value1276 = s.load(((s.registers[4]).wrapping_add(shift_left(((((s.registers[15] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[1] = ((value1276 as u32) as u64);
    s.after_fault(selected, 0x100222c84, old1276, restore1276);
    s.registers[15] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[14] = (((s.registers[14])).wrapping_neg() as u64);
    s.registers[4] = (((((((s.registers[23] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[3] = (((s.registers[15]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[3] = (((s.registers[3]).wrapping_add(shift_left(s.registers[14], 2, 64))) as u64);
    s.registers[14] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0xaf as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[3]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[6]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[8] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[14] = (((s.registers[14])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[6]).wrapping_add(shift_left(s.registers[14], 2, 64))) as u64);
    s.registers[14] = ((((((s.registers[21] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[7]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[22] = (((s.registers[6]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[14])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[22]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[14] = ((((((s.registers[2] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[8] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[6] = (((((((s.registers[21] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[14] = (((s.registers[14])).wrapping_neg() as u64);
    s.registers[19] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[14] = (((s.registers[19]).wrapping_add(shift_left(s.registers[14], 2, 64))) as u64);
    s.registers[6] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[6] = (((s.registers[14]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[19] = (((((((s.registers[21] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    let (old1312, restore1312) = s.before_fault(selected, 0x100222d14)?;

    let value1312 = s.load(((s.registers[6]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[21] = ((value1312 as u32) as u64);
    s.after_fault(selected, 0x100222d14, old1312, restore1312);
    s.registers[19] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[19] = ((((((s.registers[19] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    let (old1315, restore1315) = s.before_fault(selected, 0x100222d20)?;

    let value1315 = s.load(((s.registers[6]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[19] = ((value1315 as u32) as u64);
    s.after_fault(selected, 0x100222d20, old1315, restore1315);
    s.registers[24] = (((((((s.registers[23] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[6] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[23] = ((((((s.registers[23] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[24] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[24] = (((s.registers[25]).wrapping_add(shift_left(s.registers[24], 2, 64))) as u64);
    s.registers[25] = ((shift_right(((s.registers[12] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[25] = ((((((s.registers[25] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[23] = (((s.registers[23])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[24]).wrapping_add(shift_left(((((s.registers[25] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[23] = (((s.registers[26]).wrapping_add(shift_left(s.registers[23], 2, 64))) as u64);
    s.registers[2] = ((shift_right(((s.registers[2] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ (0x30 as u64))) as u32) as u64);
    s.registers[25] = (((s.registers[25])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[23]).wrapping_add(shift_left(((((s.registers[2] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[25] = (((s.registers[26]).wrapping_add(shift_left(s.registers[25], 2, 64))) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[2] = (((s.registers[2])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[25]).wrapping_add(shift_left(((((s.registers[12] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[2] = (((s.registers[26]).wrapping_add(shift_left(s.registers[2], 2, 64))) as u64);
    let value1337 = s.load(add_offset(s.sp, 624), 4)?;

    s.registers[13] = ((value1337 as u32) as u64);
    s.registers[9] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[1] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1340, restore1340) = s.before_fault(selected, 0x100222d84)?;

    let value1340 = s.load(s.registers[8], 4)?;

    s.registers[8] = ((value1340 as u32) as u64);
    s.after_fault(selected, 0x100222d84, old1340, restore1340);
    s.registers[8] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 16, 32))) as u32) as u64);
    let (old1342, restore1342) = s.before_fault(selected, 0x100222d8c)?;

    let value1342 = s.load(s.registers[15], 4)?;

    s.registers[9] = ((value1342 as u32) as u64);
    s.after_fault(selected, 0x100222d8c, old1342, restore1342);
    let (old1343, restore1343) = s.before_fault(selected, 0x100222d90)?;

    let value1343 = s.load(s.registers[3], 4)?;

    s.registers[15] = ((value1343 as u32) as u64);
    s.after_fault(selected, 0x100222d90, old1343, restore1343);
    let value1344 = s.load(add_offset(s.sp, 620), 4)?;

    s.registers[13] = ((value1344 as u32) as u64);
    s.registers[9] = ((((((s.registers[13] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ shift_left(((s.registers[15] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ shift_right(((s.registers[15] as u32) as u64), 8, 32))) as u32) as u64);
    let (old1348, restore1348) = s.before_fault(selected, 0x100222da4)?;

    let value1348 = s.load(s.registers[4], 4)?;

    s.registers[15] = ((value1348 as u32) as u64);
    s.after_fault(selected, 0x100222da4, old1348, restore1348);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((s.registers[12])).wrapping_neg() as u64);
    s.registers[3] = (((s.registers[2]).wrapping_add(shift_left(s.registers[12], 2, 64))) as u64);
    let (old1352, restore1352) = s.before_fault(selected, 0x100222db4)?;

    let value1352 = s.load(s.registers[2], 4)?;

    s.registers[12] = ((value1352 as u32) as u64);
    s.after_fault(selected, 0x100222db4, old1352, restore1352);
    s.registers[1] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 16, 32))) as u32) as u64);
    let (old1354, restore1354) = s.before_fault(selected, 0x100222dbc)?;

    let value1354 = s.load(s.registers[7], 4)?;

    s.registers[9] = ((value1354 as u32) as u64);
    s.after_fault(selected, 0x100222dbc, old1354, restore1354);
    let (old1355, restore1355) = s.before_fault(selected, 0x100222dc0)?;

    let value1355 = s.load(s.registers[22], 4)?;

    s.registers[12] = ((value1355 as u32) as u64);
    s.after_fault(selected, 0x100222dc0, old1355, restore1355);
    let value1356 = s.load(add_offset(s.sp, 616), 4)?;

    s.registers[13] = ((value1356 as u32) as u64);
    s.registers[9] = ((((((s.registers[13] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 16, 32))) as u32) as u64);
    let (old1359, restore1359) = s.before_fault(selected, 0x100222dd0)?;

    let value1359 = s.load(s.registers[6], 4)?;

    s.registers[12] = ((value1359 as u32) as u64);
    s.after_fault(selected, 0x100222dd0, old1359, restore1359);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    let (old1361, restore1361) = s.before_fault(selected, 0x100222dd8)?;

    let value1361 = s.load(s.registers[25], 4)?;

    s.registers[12] = ((value1361 as u32) as u64);
    s.after_fault(selected, 0x100222dd8, old1361, restore1361);
    s.registers[2] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    let value1363 = s.load(add_offset(s.sp, 612), 4)?;

    s.registers[9] = ((value1363 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[21] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[19] as u32) as u64), 8, 32))) as u32) as u64);
    let (old1366, restore1366) = s.before_fault(selected, 0x100222dec)?;

    let value1366 = s.load(s.registers[24], 4)?;

    s.registers[12] = ((value1366 as u32) as u64);
    s.after_fault(selected, 0x100222dec, old1366, restore1366);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 16, 32))) as u32) as u64);
    let (old1368, restore1368) = s.before_fault(selected, 0x100222df4)?;

    let value1368 = s.load(s.registers[23], 4)?;

    s.registers[12] = ((value1368 as u32) as u64);
    s.after_fault(selected, 0x100222df4, old1368, restore1368);
    s.registers[15] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[9] = ((shift_right(((s.registers[2] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    let (old1372, restore1372) = s.before_fault(selected, 0x100222e04)?;

    let value1372 = s.load(((s.registers[3]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[12] = ((value1372 as u32) as u64);
    s.after_fault(selected, 0x100222e04, old1372, restore1372);
    s.registers[9] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[4] = ((((((s.registers[9] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[9] = (((s.registers[3]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[3] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[10] = (((0x4e as u64) as u32) as u64);
    s.registers[4] = ((((((s.registers[10] as u32) as u64) ^ shift_right(((s.registers[1] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[6] = (((s.registers[9]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[3] = (((s.registers[6]).wrapping_add(shift_left(s.registers[3], 2, 64))) as u64);
    s.registers[6] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[7] = (((s.registers[3]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[7] = (((s.registers[7]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    let value1386 = s.load(s.registers[14], 4)?;

    s.registers[14] = ((value1386 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_right(((s.registers[14] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[19] = ((((((s.registers[8] as u32) as u64) ^ shift_left(((s.registers[14] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[14] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[14] = (((s.registers[7]).wrapping_add(shift_left(s.registers[14], 2, 64))) as u64);
    s.registers[4] = ((((((s.registers[19] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[11] = (((0xf1 as u64) as u32) as u64);
    s.registers[4] = ((((((s.registers[4] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((s.registers[14]).wrapping_add(shift_left(((((s.registers[4] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[6] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x45 as u64) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[4])).wrapping_neg() as u64);
    s.registers[21] = (((s.registers[14]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[21]).wrapping_add(shift_left(s.registers[4], 2, 64))) as u64);
    s.registers[8] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0xae as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[6] = (((s.registers[6])).wrapping_neg() as u64);
    s.registers[21] = (((s.registers[4]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[6] = (((s.registers[21]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[22] = (((s.registers[6]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = ((((((s.registers[1] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[16] = (((0x42 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    let (old1412, restore1412) = s.before_fault(selected, 0x100222ea4)?;

    let value1412 = s.load(((s.registers[22]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[8] = ((value1412 as u32) as u64);
    s.after_fault(selected, 0x100222ea4, old1412, restore1412);
    s.registers[13] = (((0x81 as u64) as u32) as u64);
    s.registers[19] = ((((((s.registers[13] as u32) as u64) ^ shift_right(((s.registers[19] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1415, restore1415) = s.before_fault(selected, 0x100222eb0)?;

    let value1415 = s.load(((s.registers[22]).wrapping_add(shift_left(((((s.registers[19] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[19] = ((value1415 as u32) as u64);
    s.after_fault(selected, 0x100222eb0, old1415, restore1415);
    s.registers[13] = (((0x37 as u64) as u32) as u64);
    s.registers[21] = ((((((s.registers[13] as u32) as u64) ^ shift_right(((s.registers[15] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1418, restore1418) = s.before_fault(selected, 0x100222ebc)?;

    let value1418 = s.load(((s.registers[22]).wrapping_add(shift_left(((((s.registers[21] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[21] = ((value1418 as u32) as u64);
    s.after_fault(selected, 0x100222ebc, old1418, restore1418);
    s.registers[23] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0x51 as u64) as u32) as u64);
    s.registers[23] = ((((((s.registers[23] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let (old1422, restore1422) = s.before_fault(selected, 0x100222ecc)?;

    let value1422 = s.load(((s.registers[22]).wrapping_add(shift_left(((((s.registers[23] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[23] = ((value1422 as u32) as u64);
    s.after_fault(selected, 0x100222ecc, old1422, restore1422);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[2] = ((((((s.registers[2] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    let (old1425, restore1425) = s.before_fault(selected, 0x100222ed8)?;

    let value1425 = s.load(((s.registers[22]).wrapping_add(shift_left(((((s.registers[2] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[2] = ((value1425 as u32) as u64);
    s.after_fault(selected, 0x100222ed8, old1425, restore1425);
    s.registers[24] = (((((((s.registers[15] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[5] = (((0xcc as u64) as u32) as u64);
    s.registers[24] = ((((((s.registers[24] as u32) as u64) ^ ((s.registers[5] as u32) as u64))) as u32) as u64);
    s.registers[22] = (((s.registers[22]).wrapping_add(shift_left(((((s.registers[24] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[1] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[0] as u32) as u64))) as u32) as u64);
    s.registers[24] = (((s.registers[24])).wrapping_neg() as u64);
    s.registers[25] = (((s.registers[22]).wrapping_add(shift_left(((((s.registers[1] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[24] = (((s.registers[25]).wrapping_add(shift_left(s.registers[24], 2, 64))) as u64);
    s.registers[25] = (((((((s.registers[15] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0x4a as u64) as u32) as u64);
    s.registers[25] = ((((((s.registers[25] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[1] = (((s.registers[1])).wrapping_neg() as u64);
    s.registers[26] = (((s.registers[24]).wrapping_add(shift_left(((((s.registers[25] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[1] = (((s.registers[26]).wrapping_add(shift_left(s.registers[1], 2, 64))) as u64);
    let (old1441, restore1441) = s.before_fault(selected, 0x100222f18)?;

    let value1441 = s.load(s.registers[3], 4)?;

    s.registers[3] = ((value1441 as u32) as u64);
    s.after_fault(selected, 0x100222f18, old1441, restore1441);
    let (old1442, restore1442) = s.before_fault(selected, 0x100222f1c)?;

    let value1442 = s.load(s.registers[7], 4)?;

    s.registers[7] = ((value1442 as u32) as u64);
    s.after_fault(selected, 0x100222f1c, old1442, restore1442);
    let value1443 = s.load(add_offset(s.sp, 608), 4)?;

    s.registers[13] = ((value1443 as u32) as u64);
    s.registers[7] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[7] as u32) as u64))) as u32) as u64);
    s.registers[3] = ((((((s.registers[7] as u32) as u64) ^ rotate_right(((s.registers[3] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1446, restore1446) = s.before_fault(selected, 0x100222f2c)?;

    let value1446 = s.load(s.registers[6], 4)?;

    s.registers[6] = ((value1446 as u32) as u64);
    s.after_fault(selected, 0x100222f2c, old1446, restore1446);
    s.registers[3] = ((((((s.registers[3] as u32) as u64) ^ rotate_right(((s.registers[6] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[6] = (((s.registers[25])).wrapping_neg() as u64);
    s.registers[13] = (((s.registers[1]).wrapping_add(shift_left(s.registers[6], 2, 64))) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ (0x8 as u64))) as u32) as u64);
    s.store_value(add_offset(s.registers[29], (-248)), s.registers[13], 8)?;
    let (old1453, restore1453) = s.before_fault(selected, 0x100222f48)?;

    let value1453 = s.load(((s.registers[13]).wrapping_add(shift_left(((((s.registers[15] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[15] = ((value1453 as u32) as u64);
    s.after_fault(selected, 0x100222f48, old1453, restore1453);
    s.registers[7] = ((((((s.registers[3] as u32) as u64) ^ rotate_right(((s.registers[15] as u32) as u64), 16, 32))) as u32) as u64);
    let value1455 = s.load(add_offset(s.sp, 604), 4)?;

    s.registers[13] = ((value1455 as u32) as u64);
    s.registers[15] = ((((((s.registers[27] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[19] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[23] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[2] as u32) as u64), 16, 32))) as u32) as u64);
    let (old1460, restore1460) = s.before_fault(selected, 0x100222f64)?;

    let value1460 = s.load(s.registers[22], 4)?;

    s.registers[2] = ((value1460 as u32) as u64);
    s.after_fault(selected, 0x100222f64, old1460, restore1460);
    s.registers[22] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[2] as u32) as u64))) as u32) as u64);
    let (old1462, restore1462) = s.before_fault(selected, 0x100222f6c)?;

    let value1462 = s.load(s.registers[4], 4)?;

    s.registers[15] = ((value1462 as u32) as u64);
    s.after_fault(selected, 0x100222f6c, old1462, restore1462);
    let value1463 = s.load(add_offset(s.sp, 600), 4)?;

    s.registers[13] = ((value1463 as u32) as u64);
    s.registers[12] = ((((((s.registers[13] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 16, 32))) as u32) as u64);
    let (old1467, restore1467) = s.before_fault(selected, 0x100222f80)?;

    let value1467 = s.load(s.registers[1], 4)?;

    s.registers[12] = ((value1467 as u32) as u64);
    s.after_fault(selected, 0x100222f80, old1467, restore1467);
    s.registers[12] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    let (old1469, restore1469) = s.before_fault(selected, 0x100222f88)?;

    let value1469 = s.load(s.registers[9], 4)?;

    s.registers[8] = ((value1469 as u32) as u64);
    s.after_fault(selected, 0x100222f88, old1469, restore1469);
    let value1470 = s.load(add_offset(s.sp, 596), 4)?;

    s.registers[9] = ((value1470 as u32) as u64);
    s.registers[9] = ((((((s.registers[28] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    let value1472 = s.load(add_offset(s.sp, 592), 4)?;

    s.registers[11] = ((value1472 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[8] as u32) as u64), 8, 32))) as u32) as u64);
    let (old1475, restore1475) = s.before_fault(selected, 0x100222fa0)?;

    let value1475 = s.load(s.registers[14], 4)?;

    s.registers[9] = ((value1475 as u32) as u64);
    s.after_fault(selected, 0x100222fa0, old1475, restore1475);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ rotate_right(((s.registers[21] as u32) as u64), 24, 32))) as u32) as u64);
    let (old1478, restore1478) = s.before_fault(selected, 0x100222fac)?;

    let value1478 = s.load(s.registers[24], 4)?;

    s.registers[9] = ((value1478 as u32) as u64);
    s.after_fault(selected, 0x100222fac, old1478, restore1478);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0xdf as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let value1483 = s.load(add_offset(s.registers[29], (-240)), 8)?;

    s.registers[11] = (value1483 as u64);
    let value1484 = s.load(((s.registers[11]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[0] = ((value1484 as u32) as u64);
    s.registers[9] = ((((((s.registers[12] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0xd8 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value1488 = s.load(((s.registers[11]).wrapping_add(shift_left(((((s.registers[9] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[9] = ((value1488 as u32) as u64);
    s.registers[14] = (((((((s.registers[12] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[5] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((s.registers[11]).wrapping_add(shift_left(((((s.registers[14] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[14] = (((s.registers[14])).wrapping_neg() as u64);
    s.registers[10] = (((0xff as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[10] as u32) as u64) & !(shift_right(((s.registers[8] as u32) as u64), 8, 32)))) as u32) as u64);
    s.registers[1] = (((s.registers[11]).wrapping_add(shift_left(((((s.registers[15] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[4] = (((s.registers[1]).wrapping_add(shift_left(s.registers[14], 2, 64))) as u64);
    s.registers[14] = (((s.registers[15])).wrapping_neg() as u64);
    s.registers[14] = (((s.registers[4]).wrapping_add(shift_left(s.registers[14], 2, 64))) as u64);
    s.registers[15] = (((((((s.registers[8] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[5] = (((0x5f as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[5] as u32) as u64))) as u32) as u64);
    let value1502 = s.load(((s.registers[14]).wrapping_add(shift_left(((((s.registers[15] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[10] = ((value1502 as u32) as u64);
    s.store_value(add_offset(s.sp, 884), ((s.registers[10] as u32) as u64), 4)?;
    s.registers[15] = (((((((s.registers[22] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[13] = (((0xd0 as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((s.registers[14]).wrapping_add(shift_left(((((s.registers[15] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[1] = ((((((s.registers[8] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[10] = (((0x57 as u64) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((s.registers[15])).wrapping_neg() as u64);
    s.registers[2] = (((s.registers[14]).wrapping_add(shift_left(((((s.registers[1] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[15] = (((s.registers[2]).wrapping_add(shift_left(s.registers[15], 2, 64))) as u64);
    let value1514 = s.load(s.registers[11], 4)?;

    s.registers[11] = ((value1514 as u32) as u64);
    let value1515 = s.load(s.registers[14], 4)?;

    s.registers[14] = ((value1515 as u32) as u64);
    s.registers[11] = ((((((s.registers[14] as u32) as u64) ^ rotate_right(((s.registers[11] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[14] = (((s.registers[1])).wrapping_neg() as u64);
    s.registers[14] = (((s.registers[15]).wrapping_add(shift_left(s.registers[14], 2, 64))) as u64);
    let value1519 = s.load(s.registers[15], 4)?;

    s.registers[15] = ((value1519 as u32) as u64);
    s.registers[15] = ((rotate_right(((s.registers[15] as u32) as u64), ((0x8 as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0x77a as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xbe16, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[13] as u32) as u64) & shift_left(((s.registers[15] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64)).wrapping_sub(((s.registers[1] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x3bd as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xdf0b, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((((((s.registers[22] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[30] as u32) as u64))) as u32) as u64);
    let value1532 = s.load(((s.registers[14]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[3] = ((value1532 as u32) as u64);
    s.registers[11] = (((0x13 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[11] as u32) as u64) ^ shift_right(((s.registers[8] as u32) as u64), 24, 32))) as u32) as u64);
    let value1535 = s.load(((s.registers[14]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[2] = ((value1535 as u32) as u64);
    s.registers[8] = (((0xcd as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[1] = (((s.registers[14]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[11] = (((((((s.registers[12] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[12] = (((0xa8 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[12] = (((s.registers[1]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[21] = (((s.registers[12]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[8] = (((s.registers[11])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[21]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[11] = (((((((s.registers[7] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[10] = (((0xe9 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = ((((((s.registers[7] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[12] = (((0xba as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((s.registers[11])).wrapping_neg() as u64);
    s.registers[12] = (((s.registers[14]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[12] = (((s.registers[12]).wrapping_add(shift_left(s.registers[11], 2, 64))) as u64);
    s.registers[11] = ((((((s.registers[16] as u32) as u64) ^ shift_right(((s.registers[7] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[12]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.registers[6] = ((((((s.registers[5] as u32) as u64) ^ shift_right(((s.registers[22] as u32) as u64), 24, 32))) as u32) as u64);
    let value1561 = s.load(((s.registers[8]).wrapping_add(shift_left(((((s.registers[6] as u32) as u64) as u32) as u64), 2, 64))), 4)?;

    s.registers[7] = ((value1561 as u32) as u64);
    s.registers[6] = (((s.registers[8]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[8] = ((((((s.registers[22] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.store_value(add_offset(s.registers[29], (-240)), s.registers[8], 8)?;
    s.registers[11] = (((s.registers[11])).wrapping_neg() as u64);
    s.registers[19] = (((s.registers[6]).wrapping_add(shift_left(((((s.registers[8] as u32) as u64) as u32) as u64), 2, 64))) as u64);
    s.registers[23] = (((s.registers[19]).wrapping_add(shift_left(s.registers[11], 2, 64))) as u64);
    let value1569 = s.load(add_offset(s.sp, 1056), 4)?;

    s.registers[10] = ((value1569 as u32) as u64);
    let value1570 = s.load(add_offset(s.sp, 1088), 4)?;

    s.registers[8] = ((value1570 as u32) as u64);
    s.registers[11] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    let value1572 = s.load(add_offset(s.sp, 528), 4)?;

    s.registers[13] = ((value1572 as u32) as u64);
    s.registers[11] = ((((((s.registers[13] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    let value1574 = s.load(add_offset(s.sp, 776), 4)?;

    s.registers[17] = ((value1574 as u32) as u64);
    let value1575 = s.load(add_offset(s.sp, 1028), 4)?;

    s.registers[13] = ((value1575 as u32) as u64);
    s.registers[19] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[19] as u32) as u64))) as u32) as u64);
    let value1578 = s.load(s.registers[6], 4)?;

    s.registers[6] = ((value1578 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ rotate_right(((s.registers[6] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[13] = (((0x5d88 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x230d, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xf65c as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xe6c7, 16, 16, 32) as u32) as u64);
    s.registers[6] = ((((((s.registers[13] as u32) as u64) & shift_left(((s.registers[11] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_sub(((s.registers[6] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xfb2e as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xf363, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    let value1591 = s.load(add_offset(s.sp, 844), 4)?;

    s.registers[13] = ((value1591 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xe5d4 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xeb19, 16, 16, 32) as u32) as u64);
    s.registers[6] = ((((((s.registers[13] as u32) as u64) & shift_left(((s.registers[11] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[22] = ((((((s.registers[11] as u32) as u64)).wrapping_sub(((s.registers[6] as u32) as u64))) as u32) as u64);
    let value1597a = s.load(add_offset(s.registers[29], (-216)), 8)?;

    let value1597b = s.load(((add_offset(s.registers[29], (-216)))).wrapping_add(8), 8)?;

    s.registers[30] = (value1597a as u64);
    s.registers[19] = (value1597b as u64);
    let value1598 = s.load(s.registers[30], 4)?;

    s.registers[11] = ((value1598 as u32) as u64);
    let value1599 = s.load(add_offset(s.registers[29], (-160)), 8)?;

    s.registers[24] = (value1599 as u64);
    let value1600 = s.load(s.registers[24], 4)?;

    s.registers[6] = ((value1600 as u32) as u64);
    s.registers[11] = ((((((s.registers[6] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[16] = (((0xa6 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((0xd4cf as u64) as u32) as u64);
    s.registers[8] = ((insert_bits(((s.registers[8] as u32) as u64), 0xa5c, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_mul(((s.registers[8] as u32) as u64))) as u32) as u64);
    let value1607 = s.load(add_offset(s.registers[29], (-200)), 8)?;

    s.registers[6] = (value1607 as u64);
    s.registers[6] = (((s.registers[6]).wrapping_add(((((s.registers[11] as u32) as u64) as u8) as u64))) as u64);
    let value1609 = s.load(s.registers[6], 1)?;

    s.registers[6] = ((value1609 as u32) as u64);
    s.registers[13] = (((0xbb as u64) as u32) as u64);
    s.registers[6] = ((((((s.registers[6] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value1612 = s.load(((s.registers[19]).wrapping_add(((((s.registers[6] as u32) as u64) as u32) as u64))), 1)?;

    s.registers[6] = ((value1612 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[6] as u32) as u64))) as u32) as u64);
    let value1614 = s.load(s.registers[4], 4)?;

    s.registers[6] = ((value1614 as u32) as u64);
    let value1615 = s.load(s.registers[1], 4)?;

    s.registers[25] = ((value1615 as u32) as u64);
    let value1616 = s.load(s.registers[21], 4)?;

    s.registers[19] = ((value1616 as u32) as u64);
    let value1617 = s.load(s.registers[14], 4)?;

    s.registers[14] = ((value1617 as u32) as u64);
    s.registers[13] = (((0xf2ea as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xf58c, 16, 16, 32) as u32) as u64);
    s.registers[1] = ((((((s.registers[22] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[1] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[4] = ((((((s.registers[1] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[4] = (((s.registers[4] ^ s.registers[20])) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_add((0x393 as u64))) as u32) as u64);
    s.registers[28] = (0x1010a1000 as u64);
    s.registers[28] = (((s.registers[28]).wrapping_add((0x960 as u64))) as u64);
    let value1628 = s.load(((s.registers[28]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 3, 64))), 8)?;

    s.registers[11] = (value1628 as u64);
    s.registers[13] = ((0xffffffffffffae32 as u64) as u64);
    s.registers[13] = (insert_bits(s.registers[13], 0xfd6b, 16, 16, 64) as u64);
    s.registers[22] = (((s.registers[11]).wrapping_add(s.registers[13])) as u64);
    let value1632 = s.load(((s.registers[22]).wrapping_add(s.registers[4])), 1)?;

    s.registers[11] = ((value1632 as u32) as u64);
    let value1633 = s.load(s.registers[12], 4)?;

    s.registers[12] = ((value1633 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_sub((0x46 as u64))) as u32) as u64);
    s.registers[13] = (((0x96 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value1637 = s.load(s.registers[23], 4)?;

    s.registers[21] = ((value1637 as u32) as u64);
    let value1638 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[4] = (value1638 as u64);
    let value1639 = s.load(add_offset(s.sp, 896), 8)?;

    s.registers[13] = (value1639 as u64);
    s.store_value(((s.registers[4]).wrapping_add(s.registers[13])), ((s.registers[11] as u32) as u64), 1)?;
    let value1641 = s.load(s.registers[30], 4)?;

    s.registers[11] = ((value1641 as u32) as u64);
    s.registers[17] = (0x1010c4000 as u64);
    let value1643 = s.load(add_offset(s.registers[17], 1648), 4)?;

    s.registers[17] = ((value1643 as u32) as u64);
    s.registers[11] = ((((((s.registers[17] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_mul(((s.registers[8] as u32) as u64))) as u32) as u64);
    let value1647 = s.load(add_offset(s.registers[29], (-232)), 8)?;

    s.registers[5] = (value1647 as u64);
    s.registers[17] = (((s.registers[5]).wrapping_add(((((s.registers[11] as u32) as u64) as u8) as u64))) as u64);
    let value1649 = s.load(s.registers[17], 1)?;

    s.registers[17] = ((value1649 as u32) as u64);
    s.registers[13] = (((0xd7 as u64) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    let value1652 = s.load(add_offset(s.registers[29], (-224)), 8)?;

    s.registers[13] = (value1652 as u64);
    let value1653 = s.load(((s.registers[13]).wrapping_add(((((s.registers[17] as u32) as u64) as u32) as u64))), 1)?;

    s.registers[17] = ((value1653 as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_add((0x5d4 as u64))) as u32) as u64);
    let value1657 = s.load(((s.registers[28]).wrapping_add(shift_left(((((s.registers[11] as u32) as u64) as u32) as u64), 3, 64))), 8)?;

    s.registers[11] = (value1657 as u64);
    s.registers[17] = ((0xffffffffffff902e as u64) as u64);
    s.registers[17] = (insert_bits(s.registers[17], 0xf888, 16, 16, 64) as u64);
    s.registers[4] = (((s.registers[11]).wrapping_add(s.registers[17])) as u64);
    s.registers[11] = (((0x3731 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xbd1, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[1] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((shift_right(((s.registers[11] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[26] = (((s.registers[17] ^ (0x70 as u64))) as u64);
    let value1666 = s.load(((s.registers[4]).wrapping_add(s.registers[26])), 1)?;

    s.registers[26] = ((value1666 as u32) as u64);
    s.registers[20] = ((shift_right(((s.registers[11] as u32) as u64), ((0x17 as u64) as u64), 32) as u32) as u64);
    s.registers[20] = ((((((s.registers[20] as u32) as u64) & (0xf8 as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_sub(((s.registers[20] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_add((0x7c as u64))) as u32) as u64);
    s.registers[27] = (((0x6a as u64) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[27] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[26] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    let value1674 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[20] = (value1674 as u64);
    let value1675 = s.load(add_offset(s.sp, 936), 8)?;

    s.registers[26] = (value1675 as u64);
    s.store_value(((s.registers[20]).wrapping_add(s.registers[26])), ((s.registers[17] as u32) as u64), 1)?;
    let value1677 = s.load(add_offset(s.sp, 812), 4)?;

    s.registers[20] = ((value1677 as u32) as u64);
    let value1678 = s.load(add_offset(s.sp, 1036), 4)?;

    s.registers[17] = ((value1678 as u32) as u64);
    s.registers[17] = ((((((s.registers[20] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    let value1680 = s.load(add_offset(s.sp, 560), 4)?;

    s.registers[26] = ((value1680 as u32) as u64);
    s.registers[17] = ((((((s.registers[26] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[6] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ rotate_right(((s.registers[3] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ rotate_right(((s.registers[25] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[26] = ((((((s.registers[17] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[12] = (((((((s.registers[26] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[12] = (((s.registers[12] ^ (0x20 as u64))) as u64);
    let value1688 = s.load(((s.registers[22]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value1688 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_sub((0x46 as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[27] as u32) as u64))) as u32) as u64);
    let value1691 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[17] = (value1691 as u64);
    let value1692 = s.load(add_offset(s.sp, 920), 8)?;

    s.registers[3] = (value1692 as u64);
    s.store_value(((s.registers[17]).wrapping_add(s.registers[3])), ((s.registers[12] as u32) as u64), 1)?;
    s.registers[12] = ((rotate_right(((s.registers[0] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_sub(((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[12] as u32) as u64) & ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add(shift_left(((s.registers[17] as u32) as u64), 1, 32))) as u32) as u64);
    let value1699 = s.load(add_offset(s.sp, 1040), 4)?;

    s.registers[15] = ((value1699 as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ rotate_right(((s.registers[2] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[19] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[21] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[15] = (((0x5c83 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0x8ec5, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0x688a as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0xf37e, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) & shift_left(((s.registers[12] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_sub(((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0x3445 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0xf9bf, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add(((s.registers[15] as u32) as u64))) as u32) as u64);
    let value1714 = s.load(add_offset(s.sp, 564), 4)?;

    s.registers[15] = ((value1714 as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0xc602 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0xb52b, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) & shift_left(((s.registers[12] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_sub(((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0xe301 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0x5a95, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add(((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[20] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0x5368 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0xc1f5, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) & shift_left(((s.registers[12] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_sub(((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0xa9b4 as u64) as u32) as u64);
    s.registers[15] = ((insert_bits(((s.registers[15] as u32) as u64), 0xe0fa, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add(((s.registers[15] as u32) as u64))) as u32) as u64);
    let value1731 = s.load(add_offset(s.sp, 556), 4)?;

    s.registers[15] = ((value1731 as u32) as u64);
    s.registers[2] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0xb1cc as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x669c, 16, 16, 32) as u32) as u64);
    s.registers[6] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((shift_right(((s.registers[6] as u32) as u64), ((0x7 as u64) as u64), 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & (0xf8 as u64))) as u32) as u64);
    s.registers[15] = ((shift_right(((s.registers[6] as u32) as u64), ((0x8 as u64) as u64), 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64)).wrapping_sub(((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((((((s.registers[6] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[17] = (((0xc6 as u64) as u32) as u64);
    s.registers[15] = (((s.registers[15] ^ s.registers[17])) as u64);
    let value1743 = s.load(((s.registers[4]).wrapping_add(s.registers[15])), 1)?;

    s.registers[15] = ((value1743 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add((0x7c as u64))) as u32) as u64);
    s.registers[17] = (((0x15 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    let value1748 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[15] = (value1748 as u64);
    let value1749 = s.load(add_offset(s.sp, 944), 8)?;

    s.registers[17] = (value1749 as u64);
    s.store_value(((s.registers[15]).wrapping_add(s.registers[17])), ((s.registers[12] as u32) as u64), 1)?;
    let value1751 = s.load(add_offset(s.sp, 1032), 4)?;

    s.registers[12] = ((value1751 as u32) as u64);
    s.registers[9] = ((((((s.registers[12] as u32) as u64) ^ rotate_right(((s.registers[9] as u32) as u64), 8, 32))) as u32) as u64);
    let value1753 = s.load(add_offset(s.sp, 884), 4)?;

    s.registers[12] = ((value1753 as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[12] as u32) as u64), 24, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ rotate_right(((s.registers[7] as u32) as u64), 16, 32))) as u32) as u64);
    s.registers[12] = (((0x47a1 as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0xd5b4, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x12 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) & ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x313e as u64) as u32) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32) as u64), 0x7de0, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[12] as u32) as u64) & ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[12] as u32) as u64)).wrapping_sub(shift_left(((s.registers[9] as u32) as u64), 1, 32))) as u32) as u64);
    let value1767 = s.load(s.registers[30], 4)?;

    s.registers[12] = ((value1767 as u32) as u64);
    let value1768 = s.load(s.registers[24], 4)?;

    s.registers[14] = ((value1768 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_mul(((s.registers[8] as u32) as u64))) as u32) as u64);
    let value1772 = s.load(add_offset(s.registers[29], (-184)), 8)?;

    s.registers[14] = (value1772 as u64);
    s.registers[14] = (((s.registers[14]).wrapping_add(((((s.registers[12] as u32) as u64) as u8) as u64))) as u64);
    let value1774 = s.load(s.registers[14], 1)?;

    s.registers[14] = ((value1774 as u32) as u64);
    s.registers[15] = (((0xe4 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    let value1777 = s.load(add_offset(s.registers[29], (-192)), 8)?;

    s.registers[15] = (value1777 as u64);
    let value1778 = s.load(((s.registers[15]).wrapping_add(((((s.registers[14] as u32) as u64) as u32) as u64))), 1)?;

    s.registers[14] = ((value1778 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x312c as u64) as u32) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32) as u64), 0xfde0, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_add(((s.registers[14] as u32) as u64))) as u32) as u64);
    let value1783 = s.load(add_offset(s.sp, 568), 4)?;

    s.registers[14] = ((value1783 as u32) as u64);
    s.registers[9] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x2c32 as u64) as u32) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32) as u64), 0xe84a, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) & shift_left(((s.registers[9] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_sub(((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x1619 as u64) as u32) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32) as u64), 0xf425, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_add(((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x3caa as u64) as u32) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32) as u64), 0x9162, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) & shift_left(((s.registers[9] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_sub(((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((0x1e55 as u64) as u32) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32) as u64), 0x48b1, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_add(((s.registers[14] as u32) as u64))) as u32) as u64);
    let value1800 = s.load(add_offset(s.sp, 552), 4)?;

    s.registers[14] = ((value1800 as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0x6e0f as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x1e0d, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[15] = ((shift_right(((s.registers[9] as u32) as u64), ((0x10 as u64) as u64), 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[15] as u32) as u64) ^ (0x1e as u64))) as u32) as u64);
    s.registers[17] = ((shift_left(((s.registers[15] as u32) as u64), ((0x1 as u64) as u64), 32) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_add((0x46 as u64))) as u32) as u64);
    s.registers[7] = (((0x56 as u64) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) & ((s.registers[7] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[15] as u32) as u64)).wrapping_sub(((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_add((0x4e as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[15] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[0] = (((0xdb as u64) as u32) as u64);
    s.registers[3] = (((s.registers[15] ^ s.registers[0])) as u64);
    s.registers[15] = (((0x11ba as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64)).wrapping_add(((((s.registers[12] as u32) as u64) as u8) as u64))) as u32) as u64);
    let value1819 = s.load(((s.registers[28]).wrapping_add(shift_left(((((s.registers[12] as u32) as u64) as u32) as u64), 3, 64))), 8)?;

    s.registers[12] = (value1819 as u64);
    s.registers[15] = ((0xffffffffffff1af1 as u64) as u64);
    s.registers[15] = (insert_bits(s.registers[15], 0xcc37, 16, 16, 64) as u64);
    s.registers[15] = (((s.registers[12]).wrapping_add(s.registers[15])) as u64);
    let value1823 = s.load(((s.registers[15]).wrapping_add(s.registers[3])), 1)?;

    s.registers[12] = ((value1823 as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[0] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    let value1826 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[17] = (value1826 as u64);
    let value1827 = s.load(add_offset(s.sp, 904), 8)?;

    s.registers[0] = (value1827 as u64);
    s.store_value(((s.registers[17]).wrapping_add(s.registers[0])), ((s.registers[12] as u32) as u64), 1)?;
    s.registers[12] = ((((((s.registers[14] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[17] = (((0x14 as u64) as u32) as u64);
    s.registers[12] = (((s.registers[12] ^ s.registers[17])) as u64);
    let value1832 = s.load(((s.registers[4]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value1832 as u32) as u64);
    s.registers[17] = ((shift_left(((s.registers[14] as u32) as u64), ((0x1 as u64) as u64), 32) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) & (0xf8 as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64)).wrapping_sub(((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64)).wrapping_add((0x7c as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ (0xffffffcf as u64))) as u32) as u64);
    let value1839 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[14] = (value1839 as u64);
    let value1840 = s.load(add_offset(s.sp, 928), 8)?;

    s.registers[17] = (value1840 as u64);
    s.store_value(((s.registers[14]).wrapping_add(s.registers[17])), ((s.registers[12] as u32) as u64), 1)?;
    let value1842 = s.load(s.registers[30], 4)?;

    s.registers[12] = ((value1842 as u32) as u64);
    let value1843 = s.load(s.registers[24], 4)?;

    s.registers[14] = ((value1843 as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64)).wrapping_add(((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_mul(((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((s.registers[5]).wrapping_add(((((s.registers[12] as u32) as u64) as u8) as u64))) as u64);
    let value1848 = s.load(s.registers[14], 1)?;

    s.registers[14] = ((value1848 as u32) as u64);
    s.registers[5] = (((0x54 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[5] as u32) as u64))) as u32) as u64);
    let value1851 = s.load(((s.registers[13]).wrapping_add(((((s.registers[14] as u32) as u64) as u32) as u64))), 1)?;

    s.registers[14] = ((value1851 as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = (((((((s.registers[1] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[14] = (((s.registers[14] ^ (0x1e as u64))) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add((0xfe0 as u64))) as u32) as u64);
    let value1857 = s.load(((s.registers[28]).wrapping_add(shift_left(((((s.registers[12] as u32) as u64) as u32) as u64), 3, 64))), 8)?;

    s.registers[12] = (value1857 as u64);
    s.registers[8] = ((0xffffffffffff8a1a as u64) as u64);
    s.registers[8] = (insert_bits(s.registers[8], 0xcc24, 16, 16, 64) as u64);
    s.registers[12] = (((s.registers[12]).wrapping_add(s.registers[8])) as u64);
    let value1861 = s.load(((s.registers[12]).wrapping_add(s.registers[14])), 1)?;

    s.registers[14] = ((value1861 as u32) as u64);
    s.registers[10] = (((0x5 as u64) as u32) as u64);
    s.registers[17] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[8] = (((0xffffff98 as u64) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_mul(((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x49 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    let value1869 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[17] = (value1869 as u64);
    let value1870 = s.load(add_offset(s.sp, 912), 8)?;

    s.registers[13] = (value1870 as u64);
    s.store_value(((s.registers[17]).wrapping_add(s.registers[13])), ((s.registers[14] as u32) as u64), 1)?;
    s.registers[14] = ((shift_right(((s.registers[9] as u32) as u64), ((0x13 as u64) as u64), 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) & (0xe0 as u64))) as u32) as u64);
    s.registers[14] = ((insert_bits(((s.registers[14] as u32) as u64), (((s.registers[9] as u32) as u64)).wrapping_shr((27) as u32), 0, 5, 32) as u32) as u64);
    s.registers[13] = (((0x47 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((shift_right(((s.registers[14] as u32) as u64), ((0x5 as u64) as u64), 32) as u32) as u64);
    s.registers[17] = ((insert_bits(((s.registers[17] as u32) as u64), ((s.registers[14] as u32) as u64), 3, 5, 32) as u32) as u64);
    s.registers[13] = (((0xb as u64) as u32) as u64);
    s.registers[14] = (((s.registers[17] ^ s.registers[13])) as u64);
    let value1881 = s.load(((s.registers[12]).wrapping_add(s.registers[14])), 1)?;

    s.registers[14] = ((value1881 as u32) as u64);
    s.registers[17] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_mul(((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ (0xf as u64))) as u32) as u64);
    let value1886 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[17] = (value1886 as u64);
    let value1887 = s.load(add_offset(s.sp, 968), 8)?;

    s.registers[13] = (value1887 as u64);
    s.store_value(((s.registers[17]).wrapping_add(s.registers[13])), ((s.registers[14] as u32) as u64), 1)?;
    s.registers[13] = (((0xffffff86 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[2] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((shift_left(((s.registers[14] as u32) as u64), ((0x1 as u64) as u64), 32) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_add((0x46 as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) & ((s.registers[7] as u32) as u64))) as u32) as u64);
    s.registers[16] = (((0x56 as u64) as u32) as u64);
    s.registers[17] = ((((((s.registers[14] as u32) as u64)).wrapping_sub(((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_add((0x4e as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[2] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[13] = (((0x43 as u64) as u32) as u64);
    s.registers[17] = (((s.registers[17] ^ s.registers[13])) as u64);
    let value1901 = s.load(((s.registers[15]).wrapping_add(s.registers[17])), 1)?;

    s.registers[17] = ((value1901 as u32) as u64);
    s.registers[3] = (((0xb2 as u64) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[3] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    let value1905 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[17] = (value1905 as u64);
    let value1906 = s.load(add_offset(s.sp, 1000), 8)?;

    s.registers[13] = (value1906 as u64);
    s.store_value(((s.registers[17]).wrapping_add(s.registers[13])), ((s.registers[14] as u32) as u64), 1)?;
    s.registers[14] = (((((((s.registers[2] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[14] = (((s.registers[14] ^ (0xe as u64))) as u64);
    let value1910 = s.load(((s.registers[12]).wrapping_add(s.registers[14])), 1)?;

    s.registers[12] = ((value1910 as u32) as u64);
    s.registers[13] = (((0x8609 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x1009, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[26] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_mul(((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[17] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((shift_right(((s.registers[14] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ (0xffffffe3 as u64))) as u32) as u64);
    let value1919 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[0] = (value1919 as u64);
    let value1920 = s.load(add_offset(s.sp, 1016), 8)?;

    s.registers[8] = (value1920 as u64);
    s.store_value(((s.registers[0]).wrapping_add(s.registers[8])), ((s.registers[12] as u32) as u64), 1)?;
    s.registers[12] = (((0xec as u64) as u32) as u64);
    s.registers[12] = (((s.registers[17] ^ s.registers[12])) as u64);
    let value1924 = s.load(((s.registers[4]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value1924 as u32) as u64);
    s.registers[8] = (((0x7 as u64) as u32) as u64);
    s.registers[1] = ((((((s.registers[8] as u32) as u64) | (!shift_right(((s.registers[14] as u32) as u64), 23, 32)))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_add(((s.registers[1] as u32) as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64)).wrapping_add((0x7d as u64))) as u32) as u64);
    s.registers[17] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[3] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[17] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    let value1931 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[17] = (value1931 as u64);
    let value1932 = s.load(add_offset(s.sp, 984), 8)?;

    s.registers[8] = (value1932 as u64);
    s.store_value(((s.registers[17]).wrapping_add(s.registers[8])), ((s.registers[12] as u32) as u64), 1)?;
    s.registers[12] = ((((((s.registers[26] as u32) as u64) & (0xff as u64))) as u32) as u64);
    s.registers[12] = (((s.registers[12] ^ s.registers[5])) as u64);
    let value1936 = s.load(((s.registers[22]).wrapping_add(s.registers[12])), 1)?;

    s.registers[12] = ((value1936 as u32) as u64);
    let value1937 = s.load(add_offset(s.registers[29], (-176)), 8)?;

    s.registers[22] = (value1937 as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_sub((0x46 as u64))) as u32) as u64);
    s.registers[8] = (((0xf5 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    let value1941 = s.load(add_offset(s.sp, 952), 8)?;

    s.registers[8] = (value1941 as u64);
    s.store_value(((s.registers[22]).wrapping_add(s.registers[8])), ((s.registers[12] as u32) as u64), 1)?;
    let value1943 = s.load(add_offset(s.registers[29], (-240)), 8)?;

    s.registers[8] = (value1943 as u64);
    s.registers[8] = (((s.registers[8])).wrapping_neg() as u64);
    s.registers[8] = (((s.registers[23]).wrapping_add(shift_left(s.registers[8], 2, 64))) as u64);
    s.store_value(add_offset(s.registers[29], (-240)), s.registers[8], 8)?;
    s.registers[8] = (((((((s.registers[14] as u32) as u64)).wrapping_shr((16) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[12] = (((0xf4 as u64) as u32) as u64);
    s.registers[8] = (((s.registers[8] ^ s.registers[12])) as u64);
    let value1950 = s.load(((s.registers[4]).wrapping_add(s.registers[8])), 1)?;

    s.registers[8] = ((value1950 as u32) as u64);
    s.registers[12] = ((shift_right(((s.registers[14] as u32) as u64), ((0x10 as u64) as u64), 32) as u32) as u64);
    s.registers[14] = ((shift_right(((s.registers[14] as u32) as u64), ((0xf as u64) as u64), 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) & (0xf8 as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_sub(((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add((0x7c as u64))) as u32) as u64);
    s.registers[13] = (((0xb6 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    let value1959 = s.load(add_offset(s.sp, 992), 8)?;

    s.registers[12] = (value1959 as u64);
    s.store_value(((s.registers[22]).wrapping_add(s.registers[12])), ((s.registers[8] as u32) as u64), 1)?;
    s.registers[8] = (((0x39 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ shift_right(((s.registers[11] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[12] = ((shift_left(((s.registers[8] as u32) as u64), ((0x1 as u64) as u64), 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add((0x46 as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & ((s.registers[16] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[8] as u32) as u64)).wrapping_sub(((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add((0x4e as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((((((s.registers[11] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((s.registers[11] ^ (0xfc as u64))) as u64);
    let value1971 = s.load(((s.registers[15]).wrapping_add(s.registers[11])), 1)?;

    s.registers[11] = ((value1971 as u32) as u64);
    s.registers[12] = (((0x6f as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((shift_right(((s.registers[6] as u32) as u64), ((0x18 as u64) as u64), 32) as u32) as u64);
    let value1976 = s.load(add_offset(s.sp, 976), 8)?;

    s.registers[12] = (value1976 as u64);
    s.store_value(((s.registers[22]).wrapping_add(s.registers[12])), ((s.registers[11] as u32) as u64), 1)?;
    s.registers[9] = (((((((s.registers[9] as u32) as u64)).wrapping_shr((8) as u32)) & bit_mask(8, 32)) as u32) as u64);
    s.registers[11] = (((0x8d as u64) as u32) as u64);
    s.registers[11] = (((s.registers[9] ^ s.registers[11])) as u64);
    s.registers[10] = (((0x48 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[9] as u32) as u64)).wrapping_add((0xa3 as u64))) as u32) as u64);
    let value1984 = s.load(((s.registers[15]).wrapping_add(s.registers[11])), 1)?;

    s.registers[11] = ((value1984 as u32) as u64);
    s.registers[9] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[10] = (((0xf2 as u64) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xac as u64) as u32) as u64);
    s.registers[11] = (((s.registers[8] ^ s.registers[11])) as u64);
    let value1991 = s.load(add_offset(s.sp, 960), 8)?;

    s.registers[12] = (value1991 as u64);
    s.store_value(((s.registers[22]).wrapping_add(s.registers[12])), ((s.registers[9] as u32) as u64), 1)?;
    let value1993 = s.load(((s.registers[15]).wrapping_add(s.registers[11])), 1)?;

    s.registers[9] = ((value1993 as u32) as u64);
    s.registers[11] = (((0x8982 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xf19, 16, 16, 32) as u32) as u64);
    let value1996 = s.load(add_offset(s.sp, 888), 4)?;

    s.registers[10] = ((value1996 as u32) as u64);
    s.registers[11] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x767e as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0xf0e6, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_add(((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x7ee as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x43e2, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xf812 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xbc1d, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64)).wrapping_add(((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x8aa3 as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x7f64, 16, 16, 32) as u32) as u64);
    s.registers[10] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x755d as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x809b, 16, 16, 32) as u32) as u64);
    s.registers[10] = ((((((s.registers[10] as u32) as u64)).wrapping_add(((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[10] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[10] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xcc3d as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xb340, 16, 16, 32) as u32) as u64);
    s.registers[10] = ((((((s.registers[10] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0x7205 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0xa393, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = (((0x38a2 as u64) as u32) as u64);
    s.registers[12] = ((insert_bits(((s.registers[12] as u32) as u64), 0x805e, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[10] as u32) as u64) & ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x3201 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0xa31f, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) & shift_left(((s.registers[12] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((shift_left(((s.registers[11] as u32) as u64), ((0x1 as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0x954e as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x479a, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[15] as u32) as u64) & ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x4aa6 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x23cd, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x4aa1 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x2045, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x3880000 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) & shift_left(((s.registers[12] as u32) as u64), 2, 32))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((shift_left(((s.registers[14] as u32) as u64), ((0x2 as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0x2a9c as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x8f35, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[15] as u32) as u64) & ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x4aa4 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x23cd, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x4023 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x20c8, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xa80 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x305, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & shift_left(((s.registers[11] as u32) as u64), 4, 32))) as u32) as u64);
    s.registers[11] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((shift_left(((s.registers[14] as u32) as u64), ((0x4 as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0xaa70 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x3cd4, 16, 16, 32) as u32) as u64);
    s.registers[15] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[15] as u32) as u64) & ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x4aa0 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x23cd, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x4087 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x309, 16, 16, 32) as u32) as u64);
    s.registers[14] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0xa00 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x20c4, 16, 16, 32) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & shift_left(((s.registers[11] as u32) as u64), 8, 32))) as u32) as u64);
    s.registers[13] = (((0x4aa7 as u64) as u32) as u64);
    s.registers[13] = ((insert_bits(((s.registers[13] as u32) as u64), 0x23cd, 16, 16, 32) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((shift_left(((s.registers[14] as u32) as u64), ((0x8 as u64) as u64), 32) as u32) as u64);
    s.registers[13] = (((0x4d4a0000 as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[15] as u32) as u64) & ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[13] = (((0x23cd0000 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[15] = (((0x22850000 as u64) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[12] as u32) as u64) ^ ((s.registers[14] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((shift_left(((s.registers[11] as u32) as u64), ((0x10 as u64) as u64), 32) as u32) as u64);
    s.registers[15] = (((0x4aa70000 as u64) as u32) as u64);
    s.registers[15] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[15] as u32) as u64))) as u32) as u64);
    s.registers[12] = ((((((s.registers[15] as u32) as u64) & ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[14] = ((((((s.registers[14] as u32) as u64) & ((s.registers[13] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[14] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[10] = ((((((s.registers[10] as u32) as u64) ^ shift_left(((s.registers[11] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[11] = (((0x69 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0x38 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_sub(shift_left(((s.registers[8] as u32) as u64), 1, 32))) as u32) as u64);
    s.registers[12] = (((0xa9 as u64) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64) | ((s.registers[12] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[8] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[11] = ((((((s.registers[11] as u32) as u64)).wrapping_add((0x4f as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ (0xfc as u64))) as u32) as u64);
    let value2110 = s.load(add_offset(s.sp, 1008), 8)?;

    s.registers[9] = (value2110 as u64);
    s.store_value(((s.registers[22]).wrapping_add(s.registers[9])), ((s.registers[8] as u32) as u64), 1)?;
    s.registers[8] = (((0x6a51 as u64) as u32) as u64);
    s.registers[8] = ((insert_bits(((s.registers[8] as u32) as u64), 0x8977, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[8] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0x3c8e as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x87d9, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64)).wrapping_add(((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0xb156 as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x3deb, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0xe78b as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x3345, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0x76eb as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x7652, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[10] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[11] = (((0x2038 as u64) as u32) as u64);
    s.registers[11] = ((insert_bits(((s.registers[11] as u32) as u64), 0x78fc, 16, 16, 32) as u32) as u64);
    s.registers[9] = ((((((s.registers[9] as u32) as u64)).wrapping_add(((s.registers[11] as u32) as u64))) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0xe45 as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x76be, 16, 16, 32) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64)).wrapping_add(((s.registers[9] as u32) as u64))) as u32) as u64);
    s.registers[9] = (((0x976 as u64) as u32) as u64);
    s.registers[9] = ((insert_bits(((s.registers[9] as u32) as u64), 0x431f, 16, 16, 32) as u32) as u64);
    s.compare32((((s.registers[8] as u32) as u64) as u32), (((s.registers[9] as u32) as u64) as u32));
    s.registers[9] = ((bool_value(s.condition("lo")) as u32) as u64);
    let value2139 = s.load(add_offset(s.sp, 892), 4)?;

    s.registers[11] = ((value2139 as u32) as u64);
    s.registers[9] = ((((((s.registers[11] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    let value2141 = s.load(add_offset(s.sp, 1048), 4)?;

    s.registers[12] = ((value2141 as u32) as u64);
    s.compare32((((s.registers[12] as u32) as u64) as u32), (((s.registers[8] as u32) as u64) as u32));
    s.registers[8] = ((bool_value(s.condition("hi")) as u32) as u64);
    s.compare32((((s.registers[9] as u32) as u64) as u32), ((0x0 as u64) as u32));
    s.registers[8] = ((select_value(s.condition("ne"), ((s.registers[11] as u32) as u64), ((s.registers[8] as u32) as u64)) as u32) as u64);
    s.registers[9] = (((0xf78 as u64) as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64)).wrapping_mul(((s.registers[9] as u32) as u64))) as u32) as u64);
    let value2148 = s.load(add_offset(s.sp, 1084), 4)?;

    s.registers[9] = ((value2148 as u32) as u64);
    s.registers[8] = ((((((s.registers[8] as u32) as u64) ^ ((s.registers[9] as u32) as u64))) as u32) as u64);
    let value2150 = s.load(add_offset(s.registers[29], (-168)), 8)?;

    s.registers[12] = (value2150 as u64);
    Ok(())
}
