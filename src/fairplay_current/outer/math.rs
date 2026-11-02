// Generated from UnfairPlay b3a7a432da2047a0d4f1ed5a3152c538a5497183 (MIT).
// Development generator: scripts/port_current_math.go. Rust runtime only.
#![allow(
    unused_parens,
    clippy::unnecessary_cast,
    clippy::double_parens,
    clippy::needless_return,
    clippy::too_many_arguments,
    clippy::manual_range_contains
)]
use super::polynomial as outer_boolean_mask;
use super::polynomial as outer_front_polynomial;
use super::polynomial as outer_hook_polynomial;
pub(super) const OUTER_TABLE_LANE0_TERMS: &[(u32, u64)] = &[
    (0x57e031c3u32, 0x00u64),
    (0x0e731103u32, 0x01u64),
    (0x10600100u32, 0x02u64),
    (0x10000000u32, 0x03u64),
    (0x1a220001u32, 0x04u64),
    (0x18000100u32, 0x05u64),
    (0x00002100u32, 0x06u64),
    (0x00002000u32, 0x07u64),
    (0x1a622001u32, 0x08u64),
    (0x18002100u32, 0x09u64),
    (0x10202101u32, 0x0au64),
    (0x10002100u32, 0x0bu64),
    (0x00002100u32, 0x0cu64),
    (0x00002000u32, 0x0du64),
    (0x40808020u32, 0x10u64),
    (0x00201140u32, 0x11u64),
    (0x00200040u32, 0x12u64),
    (0x00000180u32, 0x13u64),
    (0x01200180u32, 0x14u64),
    (0x01000080u32, 0x15u64),
    (0x00002180u32, 0x16u64),
    (0x00002000u32, 0x17u64),
    (0x01200040u32, 0x18u64),
    (0x01000000u32, 0x19u64),
    (0x01200000u32, 0x1au64),
    (0x01000080u32, 0x1bu64),
    (0x00000080u32, 0x1cu64),
    (0x10200000u32, 0x20u64),
    (0x10000100u32, 0x21u64),
    (0x00002100u32, 0x22u64),
    (0x00002000u32, 0x23u64),
    (0x00002100u32, 0x28u64),
    (0x00002000u32, 0x29u64),
    (0x00200100u32, 0x30u64),
    (0x00002100u32, 0x32u64),
    (0x00002000u32, 0x33u64),
    (0x0a000000u32, 0x40u64),
    (0x08000000u32, 0x41u64),
    (0x08000000u32, 0x60u64),
    (0x08000000u32, 0x61u64),
    (0x00002000u32, 0x62u64),
    (0x00002000u32, 0x63u64),
    (0x00002000u32, 0x68u64),
    (0x00002000u32, 0x69u64),
    (0x00002000u32, 0x72u64),
    (0x00002000u32, 0x73u64),
    (0x00200000u32, 0x80u64),
    (0x00200000u32, 0x90u64),
    (0x00200000u32, 0xa0u64),
    (0x00200000u32, 0xb0u64),
];
pub(super) const OUTER_TABLE_LANE1_TERMS: &[(u32, u64)] = &[
    (0xe42514ddu32, 0u64),
    (0x02810004u32, 1u64),
    (0x19000010u32, 2u64),
    (0x02080800u32, 3u64),
    (0x80520000u32, 4u64),
    (0x00100000u32, 5u64),
    (0x01000000u32, 6u64),
    (0xc4006130u32, 8u64),
    (0x00008222u32, 9u64),
    (0x01004010u32, 10u64),
    (0x00000200u32, 11u64),
    (0x80400000u32, 12u64),
    (0x00000200u32, 13u64),
    (0x01000000u32, 14u64),
    (0x00000200u32, 15u64),
];

// outer_table_masks.go:outerTableLane0Mask
pub(super) fn outer_table_lane0_mask(
    pending_s2: u32,
    s0: u32,
    s1: u32,
    s3: u32,
    s4: u32,
    tap27: u32,
    tap69: u32,
    tap111: u32,
) -> u32 {
    return outer_boolean_mask(
        &[pending_s2, s0, s1, s3, s4, tap27, tap69, tap111],
        OUTER_TABLE_LANE0_TERMS,
    );
}
pub(super) const OUTER_TABLE_LANE5_TERMS: &[(u32, u64)] = &[
    (0x868aca50u32, 0u64),
    (0x854064c8u32, 1u64),
    (0x20300016u32, 2u64),
    (0x20002002u32, 3u64),
    (0x520d1200u32, 4u64),
    (0x00401100u32, 5u64),
    (0x00310000u32, 6u64),
];
pub(super) const OUTER_TABLE_LANE6_TERMS: &[(u32, u64)] = &[
    (0x530a702fu32, 0u64),
    (0x00824441u32, 1u64),
    (0x08035830u32, 2u64),
    (0x08824190u32, 3u64),
    (0xa5544001u32, 4u64),
    (0x00204001u32, 5u64),
    (0x8c014000u32, 6u64),
    (0x08004100u32, 7u64),
];
pub(super) const OUTER_TABLE_LANE9_TERMS: &[(u32, u64)] = &[
    (0x17a2bee8u32, 0u64),
    (0x383df723u32, 1u64),
    (0xc7c208dcu32, 2u64),
    (0x30cd3dc4u32, 4u64),
    (0xffffffffu32, 5u64),
    (0xffffffffu32, 6u64),
];
pub(super) const OUTER_TABLE_LANE11_TERMS: &[(u32, u64)] = &[
    (0xd0bb2ebdu32, 0u64),
    (0x0000a502u32, 1u64),
    (0x00200005u32, 2u64),
    (0x00900000u32, 3u64),
    (0x010100b8u32, 4u64),
    (0x00082020u32, 5u64),
    (0x00000024u32, 6u64),
    (0x00000020u32, 7u64),
    (0x00004200u32, 8u64),
    (0xd0000800u32, 10u64),
    (0x80100000u32, 11u64),
    (0x00020010u32, 12u64),
    (0x40000000u32, 14u64),
];
pub(super) const OUTER_TABLE_LANE12_TERMS: &[(u32, u64)] = &[
    (0x7c3ed75eu32, 0u64),
    (0x80001044u32, 1u64),
    (0x81830909u32, 2u64),
    (0x84020010u32, 3u64),
    (0x40400800u32, 4u64),
    (0x40001040u32, 5u64),
    (0x40020a00u32, 6u64),
    (0x40020010u32, 7u64),
    (0x201ccc82u32, 8u64),
    (0x20240402u32, 9u64),
    (0x00000802u32, 10u64),
    (0x04200002u32, 11u64),
    (0x18048800u32, 12u64),
    (0x10040000u32, 13u64),
    (0x00000800u32, 14u64),
];
pub(super) const OUTER_TABLE_LANE13_TERMS: &[(u32, u64)] = &[
    (0xc19056fdu32, 0u64),
    (0x01542000u32, 1u64),
    (0x32b0086cu32, 2u64),
    (0x00120000u32, 3u64),
    (0x410001a2u32, 4u64),
    (0x05000100u32, 5u64),
    (0x20088020u32, 6u64),
    (0x04000000u32, 7u64),
];
pub(super) const OUTER_TABLE_LANE14_TERMS: &[(u32, u64)] = &[
    (0x3cfd3b53u32, 0u64),
    (0x04008404u32, 1u64),
    (0x9a092020u32, 2u64),
    (0x20092000u32, 3u64),
    (0x42040852u32, 4u64),
    (0x00400002u32, 5u64),
    (0x02800002u32, 6u64),
    (0x00400002u32, 7u64),
    (0x02120180u32, 8u64),
    (0x00000200u32, 9u64),
    (0x02000001u32, 10u64),
    (0x02201810u32, 12u64),
    (0x00001000u32, 13u64),
    (0x02a00000u32, 14u64),
];
pub(super) const OUTER_TABLE_LANE20_TERMS: &[(u32, u64)] = &[
    (0x09b1c801u32, 0u64),
    (0x54719560u32, 1u64),
    (0x3c38c757u32, 2u64),
    (0x00342202u32, 3u64),
    (0x5100c41du32, 4u64),
    (0xffcbddfdu32, 6u64),
    (0xaa8a8a82u32, 8u64),
    (0x5004a602u32, 9u64),
    (0xafabcbdfu32, 10u64),
    (0x5475b762u32, 11u64),
    (0x5004a602u32, 12u64),
    (0x5475b762u32, 14u64),
];

// outer_table_masks.go:outerTableLane1Mask
pub(super) fn outer_table_lane1_mask(
    pending_s1: u32,
    pending_s2: u32,
    pending_s3: u32,
    s4: u32,
) -> u32 {
    return outer_boolean_mask(
        &[pending_s1, pending_s2, pending_s3, s4],
        OUTER_TABLE_LANE1_TERMS,
    );
}

// outer_table_masks.go:outerTableLane3Mask
pub(super) fn outer_table_lane3_mask(s0: u32, pending_s3: u32) -> u32 {
    return ((s0 ^ pending_s3) ^ 0x5d0bebe6u32);
}

// outer_table_masks.go:outerTableLane4Mask
pub(super) fn outer_table_lane4_mask(a: u32, b: u32, c: u32, d: u32) -> u32 {
    return !(((a ^ b) ^ c) ^ d);
}

// outer_table_masks.go:outerTableLane5Mask
pub(super) fn outer_table_lane5_mask(pending_s1: u32, s3: u32, s0: u32) -> u32 {
    return outer_boolean_mask(&[pending_s1, s3, s0], OUTER_TABLE_LANE5_TERMS);
}

// outer_table_masks.go:outerTableLane6Mask
pub(super) fn outer_table_lane6_mask(s1: u32, pending_s4: u32, s0: u32) -> u32 {
    return outer_boolean_mask(&[s1, pending_s4, s0], OUTER_TABLE_LANE6_TERMS);
}

// outer_table_masks.go:outerTableLane8Mask
pub(super) fn outer_table_lane8_mask(a: u32, b: u32, c: u32, d: u32) -> u32 {
    return !(((a ^ b) ^ c) ^ d);
}

// outer_table_masks.go:outerTableLane9Mask
pub(super) fn outer_table_lane9_mask(s2: u32, s0: u32, s4: u32) -> u32 {
    return outer_boolean_mask(&[s2, s0, s4], OUTER_TABLE_LANE9_TERMS);
}

// outer_table_masks.go:outerTableLane10Mask
pub(super) fn outer_table_lane10_mask(s2: u32, s3: u32, s4: u32) -> u32 {
    return (((s2 ^ s3) ^ s4) ^ 0x389cbd17u32);
}

// outer_table_masks.go:outerTableLane11Mask
pub(super) fn outer_table_lane11_mask(s2: u32, s0: u32, s3: u32, s1: u32) -> u32 {
    return outer_boolean_mask(&[s2, s0, s3, s1], OUTER_TABLE_LANE11_TERMS);
}

// outer_table_masks.go:outerTableLane12Mask
pub(super) fn outer_table_lane12_mask(s1: u32, s0: u32, s3: u32, s4: u32) -> u32 {
    return outer_boolean_mask(&[s1, s0, s3, s4], OUTER_TABLE_LANE12_TERMS);
}

// outer_table_masks.go:outerTableLane13Mask
pub(super) fn outer_table_lane13_mask(s3: u32, s2: u32, s4: u32) -> u32 {
    return outer_boolean_mask(&[s3, s2, s4], OUTER_TABLE_LANE13_TERMS);
}

// outer_table_masks.go:outerTableLane14Mask
pub(super) fn outer_table_lane14_mask(s0: u32, s2: u32, s3: u32, s4: u32) -> u32 {
    return outer_boolean_mask(&[s0, s2, s3, s4], OUTER_TABLE_LANE14_TERMS);
}

// outer_table_masks.go:outerTableLane15Mask
pub(super) fn outer_table_lane15_mask(a: u32, b: u32, c: u32, d: u32) -> u32 {
    return !(((a ^ b) ^ c) ^ d);
}

// outer_table_masks.go:outerTableLane16Mask
pub(super) fn outer_table_lane16_mask(s1: u32, s2: u32, s3: u32) -> u32 {
    return (((s1 ^ s2) ^ s3) ^ 0xeb1c4c71u32);
}

// outer_table_masks.go:outerTableLane17Mask
pub(super) fn outer_table_lane17_mask(s0: u32, s1: u32, s3: u32) -> u32 {
    return (((s0 ^ s1) ^ s3) ^ 0x5d1651a0u32);
}

// outer_table_masks.go:outerTableLane20Mask
pub(super) fn outer_table_lane20_mask(pending_s0: u32, s1: u32, late_mix: u32, s3: u32) -> u32 {
    return outer_boolean_mask(&[pending_s0, s1, late_mix, s3], OUTER_TABLE_LANE20_TERMS);
}

// outer_temporaries.go:outerTablePendingS2
pub(super) fn outer_table_pending_s2(s2: u32, tap70: u32, tap112: u32, tap154: u32) -> u32 {
    return ((((((s2 ^ (tap70 & 0x224ea33bu32)) ^ (tap112 & 0x0e054c0fu32)) ^ (tap70 & tap112))
        ^ (tap154 & 0xddb15cc4u32))
        ^ (tap112 & tap154))
        ^ 0x739060aeu32);
}

// outer_temporaries.go:outerTableLane0PendingS1
pub(super) fn outer_table_lane0_pending_s1(
    pending_s2: u32,
    s0: u32,
    s1: u32,
    s3: u32,
    tap27: u32,
    tap69: u32,
    tap111: u32,
    tap152: u32,
) -> u32 {
    let mut result: u32 = (((((((((((((0x569c3294u32 as u32)
        ^ (pending_s2 & 0xf7fedfefu32))
        ^ (s0 & 0x50e8c30cu32))
        ^ s1)
        ^ (s3 & 0xffbffcd7u32))
        ^ ((s0 & s3) & 0x51e9e7afu32))
        ^ (tap27 & 0x10612130u32))
        ^ (tap69 & 0x0a048000u32))
        ^ ((tap27 & tap69) & 0x08402000u32))
        ^ (tap111 & 0x20a00002u32))
        ^ ((tap27 & tap111) & 0x00200000u32))
        ^ (tap152 & 0xc0081008u32))
        ^ ((tap27 & tap152) & 0x00001000u32));
    result ^= ((((tap69 & tap152) & !(tap27)) & !(tap111)) & 0x00000004u32);
    return result;
}

// outer_temporaries.go:outerTableLane0PendingS3
pub(super) fn outer_table_lane0_pending_s3(pending_s2: u32, s0: u32, s3: u32, s4: u32) -> u32 {
    return ((((((pending_s2 & 0xefffefefu32) ^ (s0 & 0xf87ff72bu32)) ^ s3)
        ^ (s4 & 0x0e09cd90u32))
        ^ ((s0 & s4) & 0x1fbdfdf7u32))
        ^ 0x2e6f04e6u32);
}

// outer_temporaries.go:outerTableLane5PendingS4
pub(super) fn outer_table_lane5_pending_s4(s4: u32, s0: u32, pending_s1: u32, s3: u32) -> u32 {
    return ((((s4 ^ (s0 & 0x6dedf7ddu32)) ^ (pending_s1 & 0xf3ffefffu32)) ^ (s3 & 0xdfdfeffbu32))
        ^ 0xd6113160u32);
}

// outer_temporaries.go:outerTableLane18Mix
pub(super) fn outer_table_lane18_mix(s0: u32, s2: u32, s1: u32, s3: u32) -> u32 {
    return (((((s0 ^ (s2 & 0xc4ff9cfau32)) ^ (s1 & 0x69fff7ffu32)) ^ (s3 & 0x11634268u32))
        ^ ((s2 & s3) & 0x3ffbf77fu32))
        ^ 0x3f98f797u32);
}

// outer_temporaries.go:outerTableLane19LateMix
pub(super) fn outer_table_lane19_late_mix(mix: u32, tap2: u32, tap44: u32, tap86: u32) -> u32 {
    return ((((mix ^ tap2) ^ tap44) ^ tap86) ^ 0xf0820e81u32);
}

// outer_state_transitions.go:outerTableLane2NextS0
pub(super) fn outer_table_lane2_next_s0(
    pending_s2: u32,
    pending_s1: u32,
    pending_s3: u32,
    s0: u32,
) -> u32 {
    return ((((s0 ^ (pending_s2).rotate_left(((1u32).wrapping_neg()) as u32))
        ^ (pending_s1).rotate_left(((9u32).wrapping_neg()) as u32))
        ^ (pending_s3).rotate_left(((18u32).wrapping_neg()) as u32))
        ^ 0x5de927cdu32);
}

// outer_state_transitions.go:outerTableLane7NextS0
pub(super) fn outer_table_lane7_next_s0(s0: u32, s1: u32, s3: u32, s4: u32) -> u32 {
    return ((((s0 ^ (s1 & 0xfffeffffu32)) ^ (s3 & 0x7ffff3ffu32)) ^ (s4 & 0xffff6f7fu32))
        ^ 0xb9b2aaa4u32);
}

// outer_state_transitions.go:outerTableLane8NextS1
pub(super) fn outer_table_lane8_next_s1(mix17: u32, s2: u32, mix16: u32, s4: u32) -> u32 {
    let left: u32 = (((s2 & 0xfd9fffffu32) ^ 0xc404d3f6u32) | (mix16 ^ 0x48d4e698u32));
    let right: u32 = (((mix16 & 0x7ffc7654u32) ^ 0x7b006204u32) | (s4 ^ 0x71aae24bu32));
    return (mix17 ^ !(left & right));
}

// outer_state_transitions.go:outerTableLane15NextS4
pub(super) fn outer_table_lane15_next_s4(s1: u32, s4: u32, s2: u32, s0: u32) -> u32 {
    let mix_mask: u32 = (0x9c2cbf46u32 as u32);
    let from_s2: u32 =
        (((s2).rotate_left(((4u32).wrapping_neg()) as u32) & mix_mask) ^ 0x9008b240u32);
    let from_s0: u32 = (((s0).rotate_left((21isize) as u32) & mix_mask) ^ 0x98283706u32);
    return (((s4 ^ (s1).rotate_left(((17u32).wrapping_neg()) as u32)) ^ 0x57417d47u32)
        ^ (from_s2 | from_s0));
}

// outer_state_transitions.go:outerTableLane5NextS2
pub(super) fn outer_table_lane5_next_s2(
    s2: u32,
    source0: u32,
    source1: u32,
    source2: u32,
    codec0: u32,
    codec1: u32,
    codec2: u32,
) -> u32 {
    return (((((((s2 ^ ((codec0 >> 3u32) & 0x1fu32)) ^ ((codec0 & 0x07u32) << 29u32))
        ^ ((source0 & 0xffu32) << 6u32))
        ^ ((codec2 & 0xffu32) << 10u32))
        ^ ((source1 & 0xffu32) << 14u32))
        ^ ((codec1 & 0xffu32) << 19u32))
        ^ ((source2 & 0xffu32) << 22u32));
}

// outer_complex_masks_semantic.go:outerTableLane2Mask
pub(super) fn outer_table_lane2_mask(
    pending_s1: u32,
    pending_s2: u32,
    pending_s3: u32,
    s0: u32,
    s4: u32,
) -> u32 {
    let combined: u32 = (((s0 ^ (pending_s2).rotate_left(((1u32).wrapping_neg()) as u32))
        ^ (pending_s1).rotate_left(((9u32).wrapping_neg()) as u32))
        ^ (pending_s3).rotate_left(((18u32).wrapping_neg()) as u32));
    let parts: u32 = (((((s4 & 0x0a213609u32) ^ 0x0a211601u32)
        | ((combined & 0x3d838485u32) ^ 0x0d830085u32))
        | ((pending_s2 & 0x1dc2642cu32) ^ 0x09006424u32))
        | ((s4 & 0x111d4a54u32) ^ 0x00000210u32));
    return (!(parts) & 0x7fffffffu32);
}

// outer_complex_masks_semantic.go:outerTableLane7Mask
pub(super) fn outer_table_lane7_mask(s0: u32, s1: u32, s3: u32, s4: u32, _: u32) -> u32 {
    return ((((s0 ^ (s1 & 0x00010000u32)) ^ (s3 & 0x80000c00u32)) ^ (s4 & 0xffff6f7fu32))
        ^ 0xcac4ea7eu32);
}

// outer_complex_masks_semantic.go:outerTableLane19Mask
pub(super) fn outer_table_lane19_mask(
    mix: u32,
    s1: u32,
    s4: u32,
    tap2: u32,
    tap44: u32,
    tap86: u32,
) -> u32 {
    let combined: u32 = ((((mix ^ tap2) ^ tap44) ^ tap86) ^ 0x0e0ca003u32);
    let parts: u32 = (((((s1 & 0x0813cd04u32) ^ 0x08030900u32)
        | ((s4 & 0x2b680826u32) ^ 0x2b600000u32))
        | ((combined & 0x486a2a10u32) ^ 0x402a2800u32))
        | ((combined & 0x39628612u32) ^ 0x28428610u32));
    return ((!(parts) & 0x7fffffffu32) | (!(s1) & 0x80000000u32));
}

// outer_complex_masks_semantic.go:outerTableLane18Mask
pub(super) fn outer_table_lane18_mask(s1: u32, s3: u32, s0: u32, s2: u32, _: u32) -> u32 {
    return (((((s0 ^ (s1 & 0x69fff7ffu32)) ^ (s3 & 0xee9cbd97u32)) ^ (s2 & 0xc4ff9cfau32))
        ^ ((s3 & s2) & 0x3ffbf77fu32))
        ^ 0x3182dfbfu32);
}

// outer_optional_index_semantic.go:outerOptionalFirstIndex
pub(super) fn outer_optional_first_index(seed: u32) -> u32 {
    let phase: u32 = (((seed).wrapping_add(0xf587d4eeu32)) % OUTER_WRITER_SEED_STATES);
    return (((phase).wrapping_add(114u32)) % OUTER_WRITER_SEED_STATES);
}

// outer_optional_index_semantic.go:outerOptionalDecode
pub(super) fn outer_optional_decode(word: u32) -> u32 {
    let positive: i64 = ((word & 0xddb15cc4u32) as i64);
    let negative: i64 = ((word & !(0xddb15cc4u32)) as i64);
    let mut remainder: i64 = (((positive).wrapping_sub(negative)).wrapping_neg() % 300i64);
    if (remainder < 0i64) {
        remainder = remainder.wrapping_add(300i64);
    }
    let mut centered: i64 = remainder;
    if (centered >= 140i64) {
        centered = centered.wrapping_sub(300i64);
    }
    let value: u8 = ((centered).wrapping_add(4i64) as u8);
    let low: u8 = (((value).wrapping_sub((2u8).wrapping_mul((value & 0xf0u8)))) ^ 0x02u8);
    let mut high: u32 = (0u32 as u32);
    if ((remainder >= 140i64) && (remainder < 184i64)) {
        high = (1u32 << 8u32);
    }
    return ((0x976dec00u32 | high) | (low as u32));
}
pub(super) const OUTER_WRITER_SEED_BASE: u32 = (0x0a782f77u32 as u32);
pub(super) const OUTER_WRITER_SEED_STATES: u32 = (167u32 as u32);
pub(super) const OUTER_WRITER_SEED_STRIDE: u32 = (36u32 as u32);

// outer_writer_seed_semantic.go:outerWriterSeedStep
pub(super) fn outer_writer_seed_step(seed: u32) -> u32 {
    let phase: u32 = (((seed).wrapping_add(0xf587d953u32)) % OUTER_WRITER_SEED_STATES);
    return (OUTER_WRITER_SEED_BASE)
        .wrapping_add((((phase).wrapping_add(124u32)) % OUTER_WRITER_SEED_STATES));
}
pub(super) const OUTER_DIGEST_COUNTER_BIAS: u32 = (0xf587d089u32 as u32);

// outer_digest_counter.go:outerDigestInitialCounter
pub(super) fn outer_digest_initial_counter(control: u32, seed: u32) -> (u32, bool) {
    if (((control != 0x60319d83u32) && (control != 0x60319e4bu32)) && (control != 0x60319d87u32)) {
        return (0u32, false);
    }
    let mut base: u32 = (0x62477516u32 as u32);
    if (control == 0x60319d87u32) {
        base = base.wrapping_add(4u32);
    }
    return (
        (base).wrapping_add((((seed).wrapping_add(OUTER_DIGEST_COUNTER_BIAS) as u32) % 7u32)),
        true,
    );
}
pub(super) const OUTER_FRONT_WORD0_TERMS: &[(u32, u64)] = &[
    (0x6d53971bu32, 0x0000u64),
    (0x60022140u32, 0x0001u64),
    (0x224ea33bu32, 0x0002u64),
    (0x0b901081u32, 0x0004u64),
    (0x08921080u32, 0x0005u64),
    (0x7187de73u32, 0x0008u64),
    (0xffffffffu32, 0x000au64),
    (0x04048228u32, 0x0010u64),
    (0x00480010u32, 0x0011u64),
    (0x08001080u32, 0x0014u64),
    (0x08401090u32, 0x0015u64),
    (0xddb15cc4u32, 0x0020u64),
    (0xffffffffu32, 0x0028u64),
    (0x10200003u32, 0x0040u64),
    (0x10202100u32, 0x0041u64),
    (0x00004001u32, 0x0044u64),
    (0x00004000u32, 0x0045u64),
    (0x00200008u32, 0x0050u64),
    (0x00280010u32, 0x0051u64),
    (0x00004000u32, 0x0054u64),
    (0x00004010u32, 0x0055u64),
    (0x80560608u32, 0x0080u64),
    (0xffffffffu32, 0x0100u64),
    (0x020800c0u32, 0x0200u64),
    (0x00460040u32, 0x0280u64),
    (0xffffffffu32, 0x0400u64),
    (0x00000025u32, 0x0800u64),
    (0x000000a0u32, 0x0a00u64),
    (0x17004000u32, 0x1000u64),
    (0x05000008u32, 0x1080u64),
    (0x02001800u32, 0x1200u64),
    (0x00000800u32, 0x1280u64),
    (0x15000020u32, 0x1800u64),
    (0x05000000u32, 0x1880u64),
    (0x00000020u32, 0x1a00u64),
    (0xffffffffu32, 0x2000u64),
    (0xffffffffu32, 0x4000u64),
];
pub(super) const OUTER_FRONT_WORD1_TERMS: &[(u32, u64)] = &[
    (0xf662b4bdu32, 0x0000000u64),
    (0xddb15cc4u32, 0x0000001u64),
    (0x224ea33bu32, 0x0000002u64),
    (0xffffffffu32, 0x0000004u64),
    (0x21823101u32, 0x0000008u64),
    (0x224ea33bu32, 0x0000010u64),
    (0xb1e73fd9u32, 0x0000020u64),
    (0x09441402u32, 0x0000040u64),
    (0x01001220u32, 0x0000048u64),
    (0xffffffffu32, 0x0000080u64),
    (0x667f336bu32, 0x0000100u64),
    (0xffffffffu32, 0x0000101u64),
    (0xffffffffu32, 0x0000110u64),
    (0x00008814u32, 0x0000200u64),
    (0x20002004u32, 0x0000208u64),
    (0x00000020u32, 0x0000248u64),
    (0xddb15cc4u32, 0x0000400u64),
    (0xffffffffu32, 0x0000402u64),
    (0xffffffffu32, 0x0000800u64),
    (0xc2304000u32, 0x0001000u64),
    (0x00120000u32, 0x0001008u64),
    (0x00200000u32, 0x0001040u64),
    (0x00000020u32, 0x0001048u64),
    (0x14000000u32, 0x0001200u64),
    (0x00000020u32, 0x0001248u64),
    (0x80006090u32, 0x0002000u64),
    (0xffffffffu32, 0x0004000u64),
    (0x00000001u32, 0x0008000u64),
    (0x00000800u32, 0x000a000u64),
    (0xffffffffu32, 0x0010000u64),
    (0x2246a33bu32, 0x0020000u64),
    (0x00000410u32, 0x0040000u64),
    (0x00000410u32, 0x0042000u64),
    (0x04010000u32, 0x0048000u64),
    (0x00000800u32, 0x004a000u64),
    (0xffffffffu32, 0x0080000u64),
    (0x15852c0fu32, 0x0100000u64),
    (0xfff7ff7fu32, 0x0120000u64),
    (0x08000014u32, 0x0200000u64),
    (0x00000012u32, 0x0202000u64),
    (0x00400000u32, 0x0208000u64),
    (0x00100000u32, 0x020a000u64),
    (0x00000010u32, 0x0240000u64),
    (0x00000010u32, 0x0242000u64),
    (0x04000000u32, 0x0248000u64),
    (0xddb15c44u32, 0x000400000u64),
    (0xfff7ff7fu32, 0x000500000u64),
    (0x80560608u32, 0x000800000u64),
    (0xffff3f7fu32, 0x001000000u64),
    (0x02080040u32, 0x002000000u64),
    (0x00460040u32, 0x002800000u64),
    (0xffff3f7fu32, 0x004000000u64),
    (0x00000025u32, 0x008000000u64),
    (0x00000020u32, 0x00a000000u64),
    (0x17000000u32, 0x010000000u64),
    (0x05000008u32, 0x010800000u64),
    (0x02001800u32, 0x012000000u64),
    (0x00000800u32, 0x012800000u64),
    (0x15000020u32, 0x018000000u64),
    (0x05000000u32, 0x018800000u64),
    (0x00000020u32, 0x01a000000u64),
    (0xffff3f7fu32, 0x020000000u64),
    (0xfff7ff7fu32, 0x040000000u64),
    (0xffffffffu32, 0x080000000u64),
    (0xbfffffffu32, 0x100000000u64),
    (0xffff3f7fu32, 0x200000000u64),
];
pub(super) const OUTER_FRONT_WORD2_CORE_TERMS: &[(u32, u64)] = &[
    (0x1a83c5e4u32, 0x0000u64),
    (0xffffffffu32, 0x0001u64),
    (0xffffffffu32, 0x0004u64),
    (0x218a3101u32, 0x0008u64),
    (0x00008894u32, 0x0080u64),
    (0x20002004u32, 0x0088u64),
    (0xffffffffu32, 0x0100u64),
    (0xc2304000u32, 0x0200u64),
    (0x001a0000u32, 0x0208u64),
    (0x14000000u32, 0x0280u64),
    (0x224ea33bu32, 0x0400u64),
    (0x158d2c0fu32, 0x0800u64),
    (0xffffffffu32, 0x0c00u64),
    (0xddb15cc4u32, 0x1000u64),
    (0xffffffffu32, 0x1800u64),
    (0x09441402u32, 0x2000u64),
    (0x01001220u32, 0x2008u64),
    (0x00000020u32, 0x2088u64),
    (0x00200000u32, 0x2200u64),
    (0x00000020u32, 0x2208u64),
    (0x00000020u32, 0x2288u64),
    (0xffffffffu32, 0x4000u64),
];
pub(super) const OUTER_FRONT_WORD2_EXTRA_TERMS: &[(u32, u64)] = &[
    (0x05401555u32, 0x0002u64),
    (0x10c80002u32, 0x0010u64),
    (0x00400000u32, 0x0012u64),
    (0x8014c800u32, 0x0020u64),
    (0x05000004u32, 0x0022u64),
    (0x10000000u32, 0x0030u64),
    (0x40006008u32, 0x0040u64),
    (0x04002000u32, 0x0042u64),
    (0x10000008u32, 0x0050u64),
    (0x00024200u32, 0x0060u64),
    (0x04000200u32, 0x0062u64),
    (0x10020000u32, 0x0070u64),
];
pub(super) const OUTER_FRONT_WORD3_TERMS: &[(u32, u64)] = &[
    (0x0b400509u32, 0x000u64),
    (0xc2000000u32, 0x001u64),
    (0x0a429600u32, 0x002u64),
    (0x80000002u32, 0x004u64),
    (0x80010100u32, 0x005u64),
    (0x00008008u32, 0x008u64),
    (0x0004c000u32, 0x009u64),
    (0x00100000u32, 0x00cu64),
    (0x00100000u32, 0x00du64),
    (0x00480080u32, 0x010u64),
    (0x0a400088u32, 0x012u64),
    (0x00200240u32, 0x020u64),
    (0x00001250u32, 0x022u64),
    (0x00000080u32, 0x030u64),
    (0x00000080u32, 0x032u64),
    (0x01020000u32, 0x040u64),
    (0x40020040u32, 0x041u64),
    (0x08000000u32, 0x044u64),
    (0x00802000u32, 0x048u64),
    (0x00001000u32, 0x049u64),
    (0x08000000u32, 0x04cu64),
    (0x11020100u32, 0x080u64),
    (0x01029000u32, 0x082u64),
    (0x01000000u32, 0x090u64),
    (0x01000000u32, 0x092u64),
    (0x00001000u32, 0x0a2u64),
    (0x80006090u32, 0x0100u64),
    (0x00000001u32, 0x0200u64),
    (0x00000800u32, 0x0300u64),
    (0x00000410u32, 0x0400u64),
    (0x00000410u32, 0x0500u64),
    (0x04010000u32, 0x0600u64),
    (0x00000800u32, 0x0700u64),
    (0x08000014u32, 0x0800u64),
    (0x00000012u32, 0x0900u64),
    (0x00400000u32, 0x0a00u64),
    (0x00100000u32, 0x0b00u64),
    (0x00000010u32, 0x0c00u64),
    (0x00000010u32, 0x0d00u64),
    (0x04000000u32, 0x0e00u64),
    (0xffffffffu32, 0x1000u64),
];
pub(super) const OUTER_FRONT_WORD4_TERMS: &[(u32, u64)] = &[
    (0x9a13abe8u32, 0x000u64),
    (0x224ea33bu32, 0x001u64),
    (0xffffffffu32, 0x002u64),
    (0xef7becfbu32, 0x004u64),
    (0xffffffffu32, 0x008u64),
    (0xddb15cc4u32, 0x010u64),
    (0xffffffffu32, 0x011u64),
    (0xffffffffu32, 0x020u64),
    (0x4a856940u32, 0x040u64),
    (0x35081104u32, 0x080u64),
    (0x00000100u32, 0x0c0u64),
    (0x80220080u32, 0x100u64),
    (0x08804800u32, 0x140u64),
    (0x10001000u32, 0x180u64),
    (0x0020001au32, 0x200u64),
    (0x48800018u32, 0x240u64),
    (0x00000004u32, 0x280u64),
    (0x00200000u32, 0x300u64),
    (0x08800000u32, 0x340u64),
    (0xffffffffu32, 0x400u64),
];
pub(super) const OUTER_FRONT_SOURCE_EXTRAS: [[u32; 3]; 12] = [
    [103u32, 60u32, 143u32],
    [58u32, 15u32, 98u32],
    [13u32, 137u32, 53u32],
    [135u32, 92u32, 8u32],
    [90u32, 47u32, 130u32],
    [45u32, 2u32, 85u32],
    [0u32, 124u32, 40u32],
    [122u32, 79u32, 162u32],
    [77u32, 34u32, 117u32],
    [32u32, 156u32, 72u32],
    [154u32, 111u32, 27u32],
    [109u32, 66u32, 149u32],
];
pub(super) fn front_words(
    table: &[u32; 167],
    base: u32,
    digest: &super::Digest,
) -> ([u32; 5], u32) {
    let word0_inputs: [u32; 15] = [
        table[(((base).wrapping_add(106u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(127u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(148u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(2u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(23u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(44u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(64u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(134u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(141u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(51u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(57u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(9u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(93u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(99u32)) % OUTER_TABLE_WORDS) as usize],
        digest.x0,
    ];
    let word1_inputs: [u32; 34] = [
        table[(((base).wrapping_add(104u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(125u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(131u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(132u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(20u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(41u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(49u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(6u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(62u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(7u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(83u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(89u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(90u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(10u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(13u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(136u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(138u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(14u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(52u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(55u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(56u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(94u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(98u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(134u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(141u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(51u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(57u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(9u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(93u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(99u32)) % OUTER_TABLE_WORDS) as usize],
        digest.x10,
        digest.x27,
        digest.x4,
        digest.x0,
    ];
    let word2_inputs: [u32; 15] = [
        table[(((base).wrapping_add(1u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(105u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(126u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(132u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(147u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(21u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(63u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(7u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(84u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(90u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(14u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(56u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(98u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(49u32)) % OUTER_TABLE_WORDS) as usize],
        digest.x10,
    ];
    let word3_inputs: [u32; 13] = [
        table[(((base).wrapping_add(107u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(128u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(149u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(24u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(3u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(45u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(66u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(87u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(10u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(136u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(52u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(94u32)) % OUTER_TABLE_WORDS) as usize],
        digest.x4,
    ];
    let word4_inputs: [u32; 11] = [
        table[(((base).wrapping_add(109u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(130u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(25u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(46u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(67u32)) % OUTER_TABLE_WORDS) as usize],
        table[(((base).wrapping_add(88u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(12u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(137u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(53u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(95u32)) % OUTER_TABLE_WORDS) as usize],
        digest.x28,
    ];
    let word2_core: u32 = outer_front_polynomial(&word2_inputs[..], OUTER_FRONT_WORD2_CORE_TERMS);
    return (
        [
            outer_front_polynomial(&word0_inputs[..], OUTER_FRONT_WORD0_TERMS),
            outer_front_polynomial(&word1_inputs[..], OUTER_FRONT_WORD1_TERMS),
            (word2_core ^ outer_front_polynomial(&word2_inputs[..], OUTER_FRONT_WORD2_EXTRA_TERMS)),
            outer_front_polynomial(&word3_inputs[..], OUTER_FRONT_WORD3_TERMS),
            outer_front_polynomial(&word4_inputs[..], OUTER_FRONT_WORD4_TERMS),
        ],
        word2_core,
    );
}
pub(super) const OUTER_PRE_ROUND_STEP1_TERMS: &[(u32, u64)] = &[
    (0x77cdb19du32, 0x0u64),
    (0xfdffb7bfu32, 0x1u64),
    (0xffffdf37u32, 0x2u64),
    (0xffffffffu32, 0x4u64),
    (0xdfd6ffffu32, 0x8u64),
    (0x80014531u32, 0x10u64),
    (0x01001039u32, 0x20u64),
    (0xa21a4200u32, 0x40u64),
    (0x10800800u32, 0x80u64),
    (0x49041000u32, 0x100u64),
    (0x0040a400u32, 0x200u64),
    (0x00840004u32, 0x400u64),
    (0x00140244u32, 0x800u64),
    (0x8040c000u32, 0x50u64),
    (0x00000018u32, 0xa0u64),
    (0x09000100u32, 0x110u64),
    (0x0b080000u32, 0x140u64),
    (0x00000002u32, 0x220u64),
    (0x00008800u32, 0x280u64),
    (0x00000030u32, 0x410u64),
    (0x00020200u32, 0x440u64),
    (0x00040000u32, 0x500u64),
    (0x00000045u32, 0x820u64),
    (0x08004000u32, 0x880u64),
    (0x00508040u32, 0xa00u64),
    (0x09000000u32, 0x150u64),
    (0x00000002u32, 0x2a0u64),
    (0x00008000u32, 0x450u64),
    (0x00000042u32, 0xa20u64),
    (0x0000c000u32, 0xa80u64),
    (0x00000002u32, 0xaa0u64),
];
pub(super) const OUTER_PRE_ROUND_STEP3_TERMS: &[(u32, u64)] = &[
    (0x8d3ecb10u32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0x00010000u32, 0x2u64),
    (0x84200800u32, 0x4u64),
    (0x008687d4u32, 0x8u64),
    (0x00102020u32, 0x10u64),
    (0x80000000u32, 0x6u64),
    (0x00080000u32, 0xau64),
    (0x04200100u32, 0xcu64),
    (0x00100000u32, 0x12u64),
    (0x09004000u32, 0x14u64),
    (0x00000010u32, 0x18u64),
    (0x08004000u32, 0x16u64),
    (0x01004000u32, 0x1cu64),
    (0x00004000u32, 0x1eu64),
];
pub(super) const OUTER_PRE_ROUND_STEP5_TERMS: &[(u32, u64)] = &[
    (0x2651b1aeu32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0xffffffffu32, 0x2u64),
    (0x21001039u32, 0x4u64),
    (0xffffffffu32, 0x8u64),
    (0x10800800u32, 0x10u64),
    (0x0049a400u32, 0x20u64),
    (0xffffffffu32, 0x40u64),
    (0x00340244u32, 0x80u64),
    (0x00000018u32, 0x14u64),
    (0x00000002u32, 0x24u64),
    (0x00008800u32, 0x30u64),
    (0x20200045u32, 0x84u64),
    (0x08004000u32, 0x90u64),
    (0x00708040u32, 0xa0u64),
    (0x00000002u32, 0x34u64),
    (0x00200042u32, 0xa4u64),
    (0x0000c000u32, 0xb0u64),
    (0x00000002u32, 0xb4u64),
];
pub(super) const OUTER_PRE_ROUND_STEP13_TERMS: &[(u32, u64)] = &[
    (0x1fcfff3fu32, 0x0u64),
    (0x88600008u32, 0x1u64),
    (0xffffffffu32, 0x2u64),
    (0x00300080u32, 0x4u64),
    (0x28500048u32, 0x8u64),
    (0xa0000000u32, 0x10u64),
    (0x04600000u32, 0x5u64),
    (0xe87000c8u32, 0x9u64),
    (0x04500000u32, 0xcu64),
    (0x8c000008u32, 0x11u64),
    (0xe03000c0u32, 0x14u64),
    (0x2c000008u32, 0x18u64),
    (0x04700080u32, 0xdu64),
    (0x8c600008u32, 0x15u64),
    (0xac000008u32, 0x19u64),
    (0x2c500048u32, 0x1cu64),
    (0xec7000c8u32, 0x1du64),
];
pub(super) const OUTER_PRE_ROUND_STEP16_TERMS: &[(u32, u64)] = &[
    (0x8b5c921cu32, 0x0u64),
    (0x9e1cf003u32, 0x1u64),
    (0xffffffffu32, 0x2u64),
    (0x11ab9cc9u32, 0x4u64),
    (0x41010c94u32, 0x8u64),
    (0x00114249u32, 0x10u64),
    (0x41010c84u32, 0x20u64),
    (0x200a0000u32, 0x40u64),
    (0x00000010u32, 0x80u64),
    (0x124400c2u32, 0x100u64),
    (0xc9228004u32, 0x200u64),
    (0x41010484u32, 0x400u64),
    (0xf1ddfbb7u32, 0x5u64),
    (0x236907a1u32, 0x9u64),
    (0x4517ecd6u32, 0xcu64),
    (0x01210480u32, 0x21u64),
    (0x45114cc4u32, 0x24u64),
    (0x00000200u32, 0x50u64),
    (0x22480321u32, 0x81u64),
    (0x0006a012u32, 0x84u64),
    (0x41010c94u32, 0xa0u64),
    (0x00000150u32, 0x110u64),
    (0x00000002u32, 0x140u64),
    (0x81000009u32, 0x210u64),
    (0x00820000u32, 0x240u64),
    (0x08000004u32, 0x300u64),
    (0x21690781u32, 0x401u64),
    (0x4517a4c6u32, 0x404u64),
    (0xaf6b07e1u32, 0xdu64),
    (0x8d2104c0u32, 0x25u64),
    (0x224a0321u32, 0x85u64),
    (0x236907a1u32, 0xa1u64),
    (0x4517ecd6u32, 0xa4u64),
    (0x00000110u32, 0x150u64),
    (0x00000010u32, 0x310u64),
    (0x00800000u32, 0x340u64),
    (0xad6b07c1u32, 0x405u64),
    (0xaf6b07e1u32, 0xa5u64),
    (0x00000010u32, 0x350u64),
];
pub(super) const OUTER_PRE_ROUND_STEP18_TERMS: &[(u32, u64)] = &[
    (0x6766e433u32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0x44200408u32, 0x2u64),
    (0x2ad1a081u32, 0x4u64),
    (0x01084100u32, 0x8u64),
    (0x00061892u32, 0x10u64),
    (0x00202000u32, 0x6u64),
    (0x00400000u32, 0xcu64),
    (0x04060010u32, 0x12u64),
    (0x000000a0u32, 0x14u64),
    (0x00004002u32, 0x18u64),
    (0x00000020u32, 0x16u64),
];
pub(super) const OUTER_PRE_ROUND_STEP20_TERMS: &[(u32, u64)] = &[
    (0xdc5948ebu32, 0x0u64),
    (0x00088482u32, 0x1u64),
    (0x60088ec2u32, 0x2u64),
    (0xbff777ffu32, 0x4u64),
    (0xbfffffffu32, 0x8u64),
    (0x40000c80u32, 0x10u64),
    (0x0c3d457eu32, 0x20u64),
    (0xfb667fd7u32, 0x40u64),
    (0x00000240u32, 0x80u64),
    (0x0c314444u32, 0x100u64),
    (0xddb15cc4u32, 0x200u64),
    (0x20080000u32, 0x400u64),
    (0x000c013au32, 0x800u64),
    (0x224ea33bu32, 0x1000u64),
    (0x000000c2u32, 0x2000u64),
    (0x40008000u32, 0x4000u64),
    (0x0c3d054eu32, 0x8000u64),
    (0x60088e42u32, 0x5u64),
    (0x20080680u32, 0x11u64),
    (0x40008cc2u32, 0x14u64),
    (0x9339b483u32, 0x21u64),
    (0xf3fbbeefu32, 0x22u64),
    (0x50ba980du32, 0x24u64),
    (0x41010c84u32, 0x30u64),
    (0x00110249u32, 0xa0u64),
    (0x91311480u32, 0x101u64),
    (0xd1b11cc4u32, 0x102u64),
    (0x50b01804u32, 0x104u64),
    (0x41010c84u32, 0x110u64),
    (0x00110040u32, 0x180u64),
    (0x200a0000u32, 0x420u64),
    (0x00000200u32, 0x480u64),
    (0x0208a003u32, 0x801u64),
    (0x224aa22bu32, 0x802u64),
    (0x000a8009u32, 0x804u64),
    (0x00000209u32, 0x880u64),
    (0x0c3d457eu32, 0x900u64),
    (0x200a0000u32, 0xc00u64),
    (0xffffffffu32, 0x1200u64),
    (0x124000c2u32, 0x2020u64),
    (0x00000040u32, 0x2080u64),
    (0x100000c0u32, 0x2100u64),
    (0x00000002u32, 0x2400u64),
    (0x02400002u32, 0x2800u64),
    (0xc1228004u32, 0x4020u64),
    (0xc1200004u32, 0x4100u64),
    (0x00028000u32, 0x4800u64),
    (0x9139b483u32, 0x8001u64),
    (0xf17bb6cfu32, 0x8002u64),
    (0x503a900du32, 0x8004u64),
    (0x41010484u32, 0x8010u64),
    (0x00110249u32, 0x8080u64),
    (0x200a0000u32, 0x8400u64),
    (0x104000c2u32, 0xa000u64),
    (0xc1228004u32, 0xc000u64),
    (0x200806c0u32, 0x15u64),
    (0x70f8be67u32, 0x25u64),
    (0x236906a1u32, 0x31u64),
    (0x4113acc6u32, 0x34u64),
    (0x50b01c44u32, 0x105u64),
    (0x01210480u32, 0x111u64),
    (0x41110cc4u32, 0x114u64),
    (0x00000200u32, 0x4a0u64),
    (0x2048a223u32, 0x805u64),
    (0x22480221u32, 0x811u64),
    (0x0002a002u32, 0x814u64),
    (0x9339b483u32, 0x901u64),
    (0xf3fbbeefu32, 0x902u64),
    (0x50ba980du32, 0x904u64),
    (0x41010c84u32, 0x910u64),
    (0x00110249u32, 0x980u64),
    (0x00000200u32, 0xc80u64),
    (0x200a0000u32, 0xd00u64),
    (0x00000040u32, 0x20a0u64),
    (0x00000040u32, 0x2180u64),
    (0x00000002u32, 0x2420u64),
    (0x124000c2u32, 0x2900u64),
    (0x00000002u32, 0x2c00u64),
    (0x81000009u32, 0x40a0u64),
    (0x81000000u32, 0x4180u64),
    (0x00820000u32, 0x4420u64),
    (0x00800000u32, 0x4500u64),
    (0x00000009u32, 0x4880u64),
    (0xc1228004u32, 0x4900u64),
    (0x00020000u32, 0x4c00u64),
    (0x00000004u32, 0x6020u64),
    (0x00000004u32, 0x6100u64),
    (0x7078b647u32, 0x8005u64),
    (0x21690681u32, 0x8011u64),
    (0x4113a4c6u32, 0x8014u64),
    (0x00000200u32, 0x8480u64),
    (0x00000040u32, 0xa080u64),
    (0x00000002u32, 0xa400u64),
    (0x81000009u32, 0xc080u64),
    (0x00020000u32, 0xc400u64),
    (0x00000004u32, 0xe000u64),
    (0xa36b06e1u32, 0x35u64),
    (0x812104c0u32, 0x115u64),
    (0x224a0221u32, 0x815u64),
    (0x70f8be67u32, 0x905u64),
    (0x236906a1u32, 0x911u64),
    (0x4113acc6u32, 0x914u64),
    (0x00000200u32, 0xd80u64),
    (0x00000040u32, 0x2980u64),
    (0x00000002u32, 0x2d00u64),
    (0x81000009u32, 0x4980u64),
    (0x00820000u32, 0x4d00u64),
    (0x00800000u32, 0x6420u64),
    (0x00800000u32, 0x6500u64),
    (0x00000004u32, 0x6900u64),
    (0xa16b06c1u32, 0x8015u64),
    (0xa36b06e1u32, 0x915u64),
    (0x00800000u32, 0x6d00u64),
];
pub(super) const OUTER_PRE_ROUND_STEP21_TERMS: &[(u32, u64)] = &[
    (0xc40a3659u32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0x11890200u32, 0x2u64),
    (0x0810428cu32, 0x4u64),
    (0x00000560u32, 0x8u64),
    (0xa2448440u32, 0x10u64),
    (0x00200a00u32, 0x6u64),
    (0x01000000u32, 0xau64),
    (0x00104000u32, 0xcu64),
    (0x12c00000u32, 0x12u64),
    (0x00040000u32, 0x14u64),
    (0x00000442u32, 0x18u64),
    (0x00200000u32, 0xeu64),
    (0x00000800u32, 0x16u64),
    (0x00000002u32, 0x1au64),
];
pub(super) const OUTER_PRE_ROUND_STEP22_TERMS: &[(u32, u64)] = &[
    (0x316108c2u32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0xc8d01000u32, 0x2u64),
    (0x02082118u32, 0x4u64),
    (0x012208a1u32, 0x8u64),
    (0x04004400u32, 0x10u64),
    (0xc0102100u32, 0x6u64),
    (0x08001000u32, 0xau64),
    (0x00048200u32, 0xcu64),
    (0x00000004u32, 0x12u64),
    (0x02084500u32, 0x14u64),
    (0x00004020u32, 0x18u64),
    (0x00048000u32, 0xeu64),
    (0x00000100u32, 0x16u64),
    (0x0000c200u32, 0x1cu64),
    (0x00008000u32, 0x1eu64),
];
pub(super) const OUTER_PRE_ROUND_STEP28_TERMS: &[(u32, u64)] = &[
    (0xcd579428u32, 0x0u64),
    (0xbffdfffeu32, 0x1u64),
    (0xfffffffdu32, 0x2u64),
    (0xf3ffffffu32, 0x4u64),
    (0xffffffffu32, 0x8u64),
    (0xb4757415u32, 0x10u64),
    (0x2ff4ffcau32, 0x20u64),
    (0xffffffffu32, 0x40u64),
    (0xddb15cc4u32, 0x80u64),
    (0x9db15cc4u32, 0x100u64),
    (0xffffffffu32, 0x200u64),
    (0x224ca33au32, 0x400u64),
    (0xffffffffu32, 0x800u64),
    (0x224ea339u32, 0x1000u64),
    (0xfffffffdu32, 0x90u64),
    (0xbffdfffeu32, 0x500u64),
    (0xfffffffdu32, 0x1010u64),
];
pub(super) const OUTER_PRE_ROUND_STEP32_TERMS: &[(u32, u64)] = &[
    (0xbca990cbu32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0x862021e0u32, 0x2u64),
    (0x10460240u32, 0x4u64),
    (0x60000c0au32, 0x8u64),
    (0x20184004u32, 0x10u64),
    (0x00000050u32, 0x6u64),
    (0x40002400u32, 0xau64),
    (0x00040000u32, 0xcu64),
    (0x00006000u32, 0x12u64),
    (0x00500004u32, 0x14u64),
    (0x21000000u32, 0x18u64),
    (0x00002000u32, 0x1au64),
];
pub(super) const OUTER_PRE_ROUND_STEP35_TERMS: &[(u32, u64)] = &[
    (0x0150083fu32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0x0008aa00u32, 0x2u64),
    (0x02020100u32, 0x4u64),
    (0x10201490u32, 0x8u64),
    (0xc481407au32, 0x10u64),
    (0x20040000u32, 0x6u64),
    (0x10200000u32, 0xau64),
    (0x02020180u32, 0xcu64),
    (0xc0000040u32, 0x12u64),
    (0xc2830040u32, 0x14u64),
    (0x08000010u32, 0x18u64),
    (0xc0000040u32, 0x16u64),
    (0x08000000u32, 0x1au64),
    (0x02020000u32, 0x1cu64),
];
pub(super) const OUTER_PRE_ROUND_STEP36_TERMS: &[(u32, u64)] = &[
    (0x58f45057u32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0x00010891u32, 0x2u64),
    (0x00280200u32, 0x4u64),
    (0x04400c00u32, 0x8u64),
    (0x18905348u32, 0x10u64),
    (0x00040802u32, 0xau64),
    (0x00600000u32, 0xcu64),
    (0x08004050u32, 0x12u64),
    (0x40000204u32, 0x14u64),
    (0x00801000u32, 0x18u64),
    (0x40000000u32, 0x16u64),
    (0x00040000u32, 0x1au64),
    (0x40000000u32, 0x1cu64),
    (0x40000000u32, 0x1eu64),
];
pub(super) const OUTER_PRE_ROUND_STEP38_TERMS: &[(u32, u64)] = &[
    (0x5fe0076eu32, 0x0u64),
    (0xffffffffu32, 0x1u64),
    (0x80110288u32, 0x2u64),
    (0x2906a041u32, 0x4u64),
    (0x10200010u32, 0x8u64),
    (0x00400300u32, 0x10u64),
    (0x8006a080u32, 0x6u64),
    (0x80010080u32, 0xau64),
    (0x00080000u32, 0xcu64),
    (0x00005a00u32, 0x12u64),
    (0x20048000u32, 0x14u64),
    (0x80000080u32, 0xeu64),
    (0x00049800u32, 0x16u64),
    (0x00001000u32, 0x1au64),
    (0x00001000u32, 0x1eu64),
];
pub(super) const OUTER_PRE_ROUND_TAP_MASK: u32 = (0x224ea33bu32 as u32);

// outer_preround_semantic.go:outerPreRoundPivotMix
pub(super) fn outer_pre_round_pivot_mix(a: u32, b: u32, pivot: u32, mask: u32) -> u32 {
    return (((a & !(OUTER_PRE_ROUND_TAP_MASK)) ^ (b & OUTER_PRE_ROUND_TAP_MASK))
        ^ (pivot & ((a ^ b) ^ mask)));
}

// outer_preround_semantic.go:outerPreRoundPairMix
pub(super) fn outer_pre_round_pair_mix(a: u32, b: u32, third: u32, mask: u32) -> u32 {
    return (((a ^ OUTER_PRE_ROUND_TAP_MASK) & !(b ^ OUTER_PRE_ROUND_TAP_MASK)) ^ (third & mask));
}
pub(super) fn pre_round(table: &[u32; 167], base: u32, state: &mut super::OuterState) -> bool {
    if base >= 167 || state.hardware_index >= 6 {
        return false;
    }
    let tap = |offset: u32| table[((base + offset) % 167) as usize];
    let h = |offset: isize| {
        u32::from(state.hardware[((state.hardware_index as isize + offset) as usize) % 6])
    };
    let c = |offset: isize| u32::from(state.codec[offset as usize]);
    let (w0, w1, w2, w3, w4) = (
        state.words[(0isize) as usize],
        state.words[(1isize) as usize],
        state.words[(2isize) as usize],
        state.words[(3isize) as usize],
        state.words[(4isize) as usize],
    );
    let inputs1: [u32; 12] = [
        w1,
        w2,
        w3,
        w4,
        tap(20u32),
        tap(22u32),
        tap(62u32),
        tap(63u32),
        tap(104u32),
        tap(105u32),
        tap(146u32),
        tap(147u32),
    ];
    let c1: u32 = outer_front_polynomial(&inputs1[..], OUTER_PRE_ROUND_STEP1_TERMS);
    let c2: u32 = (0x16812fc0u32 ^ w2);
    let inputs3: [u32; 5] = [w0, tap(19u32), tap(61u32), tap(103u32), tap(144u32)];
    let c3: u32 = outer_front_polynomial(&inputs3[..], OUTER_PRE_ROUND_STEP3_TERMS);
    let inputs5: [u32; 8] = [
        w4,
        tap(18u32),
        tap(22u32),
        tap(60u32),
        tap(63u32),
        tap(105u32),
        tap(143u32),
        tap(147u32),
    ];
    let c5: u32 = outer_front_polynomial(&inputs5[..], OUTER_PRE_ROUND_STEP5_TERMS);
    let c6: u32 = ((((0x80f13affu32 ^ w1) ^ tap(17u32)) ^ tap(100u32)) ^ tap(142u32));
    let c7: u32 = ((c2 ^ 0x525c4637u32)
        ^ outer_pre_round_pivot_mix(tap(141u32), tap(57u32), tap(99u32), 0x28001aefu32));
    let c8: u32 = ((((0x7d32827cu32 ^ c1) ^ tap(14u32)) ^ tap(56u32)) ^ tap(98u32));
    let c9: u32 = ((((((c3 ^ (h(2isize) << 7u32)) ^ (c(14isize) << 8u32))
        ^ (h(3isize) << 14u32))
        ^ (c(12isize) << 16u32))
        ^ (h(4isize)).rotate_left(((7u32).wrapping_neg()) as u32))
        ^ (c(10isize) << 21u32));
    let c10: u32 = ((((((c5 ^ (h(3isize) << 6u32)) ^ (c(6isize) << 3u32))
        ^ (h(4isize) << 11u32))
        ^ (c(4isize) << 17u32))
        ^ (h(5isize) << 24u32))
        ^ (c(15isize)).rotate_left(((2u32).wrapping_neg()) as u32));
    let c11: u32 = ((((((c6 ^ (h(4isize) << 1u32)) ^ (c(11isize) << 9u32))
        ^ (h(5isize) << 9u32))
        ^ (c(9isize) << 19u32))
        ^ (h(0isize)).rotate_left(((3u32).wrapping_neg()) as u32))
        ^ (c(7isize)).rotate_left(((1u32).wrapping_neg()) as u32));
    let c12: u32 = ((((((c7 ^ (h(5isize) << 4u32)) ^ (c(16isize) << 11u32))
        ^ (h(0isize) << 12u32))
        ^ (c(14isize) << 20u32))
        ^ (h(1isize) << 20u32))
        ^ (c(12isize)).rotate_left(((6u32).wrapping_neg()) as u32));
    let inputs13: [u32; 5] = [
        (c10).rotate_left(((2u32).wrapping_neg()) as u32),
        c8,
        (c8).rotate_left((2isize) as u32),
        (c9).rotate_left((3isize) as u32),
        (c9).rotate_left(((15u32).wrapping_neg()) as u32),
    ];
    let c13: u32 = outer_front_polynomial(&inputs13[..], OUTER_PRE_ROUND_STEP13_TERMS);
    let c14: u32 = (0x8865aa8fu32 ^ c10);
    let inputs16: [u32; 11] = [
        c10,
        c11,
        c12,
        c9,
        tap(12u32),
        tap(13u32),
        tap(53u32),
        tap(55u32),
        tap(95u32),
        tap(137u32),
        tap(138u32),
    ];
    let c16: u32 = outer_front_polynomial(&inputs16[..], OUTER_PRE_ROUND_STEP16_TERMS);
    let c17: u32 = ((c9 ^ 0xdd3114c4u32)
        ^ outer_pre_round_pair_mix(tap(13u32), tap(55u32), tap(138u32), 0xfd7fb7cfu32));
    let inputs18: [u32; 5] = [c14, tap(10u32), tap(52u32), tap(94u32), tap(136u32)];
    let c18: u32 = outer_front_polynomial(&inputs18[..], OUTER_PRE_ROUND_STEP18_TERMS);
    let inputs20: [u32; 16] = [
        c10,
        c11,
        c12,
        c14,
        c17,
        c9,
        tap(9u32),
        tap(12u32),
        tap(13u32),
        tap(51u32),
        tap(53u32),
        tap(55u32),
        tap(93u32),
        tap(95u32),
        tap(137u32),
        tap(138u32),
    ];
    let c20: u32 = outer_front_polynomial(&inputs20[..], OUTER_PRE_ROUND_STEP20_TERMS);
    let inputs21: [u32; 5] = [c13, tap(8u32), tap(50u32), tap(91u32), tap(133u32)];
    let c21: u32 = outer_front_polynomial(&inputs21[..], OUTER_PRE_ROUND_STEP21_TERMS);
    let inputs22: [u32; 5] = [c17, tap(7u32), tap(48u32), tap(90u32), tap(132u32)];
    let c22: u32 = outer_front_polynomial(&inputs22[..], OUTER_PRE_ROUND_STEP22_TERMS);
    let c26: u32 = ((((0xfbd326d7u32 ^ c21) ^ tap(2u32)) ^ tap(85u32)) ^ tap(127u32));
    let inputs28: [u32; 13] = [
        c18,
        c20,
        c21,
        c22,
        tap(3u32),
        tap(4u32),
        tap(42u32),
        tap(45u32),
        tap(46u32),
        tap(84u32),
        tap(88u32),
        tap(126u32),
        tap(128u32),
    ];
    let c28: u32 = outer_front_polynomial(&inputs28[..], OUTER_PRE_ROUND_STEP28_TERMS);
    let c30: u32 = (((c18 ^ 0xd8010444u32)
        ^ outer_pre_round_pair_mix(tap(46u32), tap(88u32), tap(4u32), 0x2ff6ffcbu32))
        ^ outer_pre_round_pair_mix(tap(165u32), tap(40u32), tap(123u32), 0xf7fffb9fu32));
    let c31: u32 = (((((c20 ^ 0xa6499ec5u32) ^ tap(164u32)) ^ tap(80u32)) ^ tap(122u32))
        ^ outer_pre_round_pivot_mix(tap(45u32), tap(128u32), tap(3u32), 0xb4757417u32));
    let inputs32: [u32; 5] = [c26, tap(162u32), tap(37u32), tap(79u32), tap(121u32)];
    let c32: u32 = outer_front_polynomial(&inputs32[..], OUTER_PRE_ROUND_STEP32_TERMS);
    let c33: u32 = ((c28 ^ 0x51b15c84u32)
        ^ outer_pre_round_pair_mix(tap(36u32), tap(78u32), tap(161u32), 0x73b9dfaeu32));
    let c34: u32 = ((((c16 ^ 0x21440c1cu32)
        ^ outer_pre_round_pivot_mix(tap(131u32), tap(47u32), tap(89u32), 0x20741d9du32))
        ^ outer_pre_round_pair_mix(tap(41u32), tap(83u32), tap(166u32), 0xed4af7e9u32))
        ^ outer_pre_round_pivot_mix(tap(35u32), tap(118u32), tap(160u32), 0x6c24fc61u32));
    let inputs35: [u32; 5] = [c30, tap(33u32), tap(75u32), tap(117u32), tap(159u32)];
    let c35: u32 = outer_front_polynomial(&inputs35[..], OUTER_PRE_ROUND_STEP35_TERMS);
    let inputs36: [u32; 5] = [c31, tap(32u32), tap(74u32), tap(116u32), tap(157u32)];
    let c36: u32 = outer_front_polynomial(&inputs36[..], OUTER_PRE_ROUND_STEP36_TERMS);
    let c37: u32 = ((c32 ^ 0x7ae11e0bu32)
        ^ outer_pre_round_pivot_mix(tap(73u32), tap(156u32), tap(31u32), 0x45ce9fb5u32));
    let inputs38: [u32; 5] = [c33, tap(30u32), tap(71u32), tap(113u32), tap(155u32)];
    let c38: u32 = outer_front_polynomial(&inputs38[..], OUTER_PRE_ROUND_STEP38_TERMS);
    state.words = [c38, c35, c34, c37, c36];
    return true;
}
pub(super) const OUTER_HOOK_ODD_TERMS: &[(u32, u64)] = &[
    (0xde9fb102u32, 0x000u64),
    (0xffffffffu32, 0x001u64),
    (0xffffffffu32, 0x002u64),
    (0xffffffffu32, 0x004u64),
    (0x07ffffffu32, 0x008u64),
    (0x07ffffffu32, 0x010u64),
    (0x07ffffffu32, 0x020u64),
    (0x0402b030u32, 0x040u64),
    (0x00000001u32, 0x080u64),
    (0x00b80200u32, 0x100u64),
    (0x00280000u32, 0x140u64),
    (0x00a80001u32, 0x180u64),
    (0x00280000u32, 0x1c0u64),
    (0x00104006u32, 0x200u64),
    (0x00023002u32, 0x240u64),
    (0x00000005u32, 0x280u64),
    (0x001000c0u32, 0x300u64),
    (0x00000040u32, 0x340u64),
    (0x00000001u32, 0x380u64),
    (0xffffffffu32, 0x400u64),
    (0x07ffffffu32, 0x800u64),
];
pub(super) fn hook_seeds(
    table: &[u32; 167],
    base: u32,
    digest: &super::Digest,
    word2_core: u32,
) -> (u32, u32, u32) {
    let even: u32 = (digest.x28 ^ (digest.x0 >> 15u32));
    let odd_inputs: [u32; 12] = [
        table[((((14u32).wrapping_mul(base)).wrapping_add(55u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(13u32)) % OUTER_TABLE_WORDS) as usize],
        table[((((14u32).wrapping_mul(base)).wrapping_add(138u32)) % OUTER_TABLE_WORDS) as usize],
        (table[((((14u32).wrapping_mul(base)).wrapping_add(141u32)) % OUTER_TABLE_WORDS) as usize])
            .rotate_left((27isize) as u32),
        (table[((((14u32).wrapping_mul(base)).wrapping_add(99u32)) % OUTER_TABLE_WORDS) as usize])
            .rotate_left((27isize) as u32),
        (table[((((14u32).wrapping_mul(base)).wrapping_add(57u32)) % OUTER_TABLE_WORDS) as usize])
            .rotate_left((27isize) as u32),
        (table[((((14u32).wrapping_mul(base)).wrapping_add(134u32)) % OUTER_TABLE_WORDS) as usize])
            .rotate_left((27isize) as u32),
        (table[((((14u32).wrapping_mul(base)).wrapping_add(9u32)) % OUTER_TABLE_WORDS) as usize])
            .rotate_left((27isize) as u32),
        (table[((((14u32).wrapping_mul(base)).wrapping_add(93u32)) % OUTER_TABLE_WORDS) as usize])
            .rotate_left((27isize) as u32),
        (table[((((14u32).wrapping_mul(base)).wrapping_add(51u32)) % OUTER_TABLE_WORDS) as usize])
            .rotate_left((27isize) as u32),
        digest.x27,
        (digest.x0).rotate_left((27isize) as u32),
    ];
    let odd: u32 = outer_hook_polynomial(&odd_inputs[..], OUTER_HOOK_ODD_TERMS);
    let tail: u32 = ((word2_core ^ (word2_core >> 21u32)) ^ 0xea794ee0u32);
    return (even, odd, tail);
}

// outer_postround.go:outerPostRoundTapMix
pub(super) fn outer_post_round_tap_mix(tap82: u32, tap41: u32, tap124: u32, tap166: u32) -> u32 {
    return (((((((((((((((0x8901d237u32 as u32) ^ (tap82 & 0x010a2108u32))
        ^ (tap41 & 0x40300201u32))
        ^ ((tap82 & tap41) & 0x40200100u32))
        ^ (tap124 & 0x03050000u32))
        ^ ((tap82 & tap124) & 0x21400000u32))
        ^ ((tap41 & tap124) & 0x00240000u32))
        ^ (((tap82 & tap41) & tap124) & 0x00600000u32))
        ^ (tap166 & 0x14800490u32))
        ^ ((tap82 & tap166) & 0x10020580u32))
        ^ ((tap41 & tap166) & 0x00000840u32))
        ^ (((tap82 & tap41) & tap166) & 0x00000100u32))
        ^ ((tap124 & tap166) & 0x10800000u32))
        ^ (((tap82 & tap124) & tap166) & 0x10400000u32))
        ^ ((((tap82 & tap41) & tap124) & tap166) & 0x00400000u32));
}

// outer_postround.go:outerPostRoundStep
pub(super) fn outer_post_round_step(
    x14: u32,
    x16: u32,
    tap82: u32,
    tap41: u32,
    tap124: u32,
    tap166: u32,
) -> (u32, u32) {
    let next_x16: u32 = (x16 ^ outer_post_round_tap_mix(tap82, tap41, tap124, tap166));
    let next_x14: u32 = ((x14 ^ next_x16) ^ 0x0f015c57u32);
    return (next_x14, next_x16);
}
pub(super) const OUTER_TABLE_WORDS: u32 = (167u32 as u32);
pub(super) const OUTER_TABLE_INITIAL_BASE: u32 = (5u32 as u32);
pub(super) const OUTER_TABLE_LANE_OFFSETS: [u32; 21] = [
    68u32, 25u32, 149u32, 106u32, 63u32, 20u32, 144u32, 101u32, 58u32, 15u32, 139u32, 96u32, 53u32,
    10u32, 134u32, 91u32, 48u32, 5u32, 129u32, 43u32, 0u32,
];

// outer_table_schedule.go:nextOuterTableBase
pub(super) fn next_outer_table_base(base: u32) -> (u32, bool) {
    if (base >= OUTER_TABLE_WORDS) {
        return (0u32, false);
    }
    return (
        ((((24u32).wrapping_mul(base)).wrapping_add(58u32)) % OUTER_TABLE_WORDS),
        true,
    );
}
pub(super) const CURRENT_OUTER_INITIAL_TABLE: [u32; 167] = [
    0xb1e42d3bu32,
    0x7d21e1ccu32,
    0x70eaae14u32,
    0xfa0235dcu32,
    0x5c8dfca6u32,
    0x5f192caau32,
    0x6050f318u32,
    0x98f98ae2u32,
    0xf5ea5c8bu32,
    0x3da11bc7u32,
    0xf2d6955du32,
    0xdf5cfb53u32,
    0xc6f54dfau32,
    0xbbf0cef6u32,
    0x1bb7a270u32,
    0xc9395d2cu32,
    0xe22ec582u32,
    0xd28bbb8cu32,
    0x85a72e4du32,
    0x1c209916u32,
    0x333fab30u32,
    0x9a65bf14u32,
    0x01303b6du32,
    0xcf7bb0aeu32,
    0x8363e40au32,
    0x7f487da6u32,
    0x86986651u32,
    0xc13ca4e6u32,
    0xf1322977u32,
    0x25bb95b9u32,
    0x0fc06396u32,
    0x9eb24fcbu32,
    0x3e270430u32,
    0x26bf4893u32,
    0x3b2e9fbau32,
    0xa4e85491u32,
    0x6f2fa819u32,
    0x979fd626u32,
    0x3ad52274u32,
    0x82b47c83u32,
    0x91bb520eu32,
    0x1fcf1f2eu32,
    0x03d19907u32,
    0x2a0ecec1u32,
    0x8f4f201au32,
    0x7b795befu32,
    0x7c976db3u32,
    0x6411d213u32,
    0xdf965397u32,
    0x0b6c56a7u32,
    0xc80bbd70u32,
    0x9adb84e8u32,
    0xabacece0u32,
    0xd89659c1u32,
    0xd2a4ee6fu32,
    0x2be7d16du32,
    0x4d2e0bc0u32,
    0x9c339c92u32,
    0x7dca0da4u32,
    0xd7204d4eu32,
    0x39f4c55bu32,
    0x6305d02fu32,
    0x700a6f8fu32,
    0x29254d6fu32,
    0xffca57ccu32,
    0x1f99a500u32,
    0x23e3a447u32,
    0x07dd84dbu32,
    0x5d8916c6u32,
    0x5a6ddbc3u32,
    0xe91d9124u32,
    0x2e368e41u32,
    0xbc7c5645u32,
    0xb07c7380u32,
    0xf84acfe6u32,
    0x2ed5b31eu32,
    0x46ae7bddu32,
    0x3bd1b83fu32,
    0x28f41103u32,
    0x0e710c01u32,
    0xc846da3fu32,
    0xb932e1b9u32,
    0xafeb5e3bu32,
    0xa33da0cfu32,
    0x74e76ce5u32,
    0x2a9d963fu32,
    0xf4f64805u32,
    0xcdb232eau32,
    0x6f4bbfd0u32,
    0xe3d595dbu32,
    0xfc6bf981u32,
    0x29fecd6du32,
    0xde0f5314u32,
    0x3b3ccd26u32,
    0x19111329u32,
    0xb40b0978u32,
    0x5182fd39u32,
    0x080d8471u32,
    0x6dfa885eu32,
    0x9ab721b5u32,
    0x076a33cfu32,
    0xd75a2b6cu32,
    0x1c1987d9u32,
    0xb91d8220u32,
    0x18453a20u32,
    0x190d2ef3u32,
    0xbd7ebdfau32,
    0x5c725362u32,
    0xef8196bbu32,
    0x327dc87fu32,
    0xa4a999bdu32,
    0xf17082cfu32,
    0x631f3b8eu32,
    0x93f073e4u32,
    0x17dc28ffu32,
    0x66310380u32,
    0xe677d0d6u32,
    0xa4558308u32,
    0x099de2dau32,
    0x03340d8eu32,
    0x430fc8a5u32,
    0xa7ab71dfu32,
    0x31aad011u32,
    0x82716a32u32,
    0xa2841402u32,
    0x56dcbdc7u32,
    0xfb14d097u32,
    0x72ac63a5u32,
    0x325c7adcu32,
    0xd478e88fu32,
    0x0151af21u32,
    0x803e9710u32,
    0x17fd43d6u32,
    0xdc12c6d4u32,
    0xba03a905u32,
    0xb33d7a23u32,
    0x91856d97u32,
    0xcdf4ef6fu32,
    0x513c0c06u32,
    0x5ba2583cu32,
    0x57695b1fu32,
    0x566679e5u32,
    0x2e51cc3eu32,
    0x0c908a0fu32,
    0x797b6f8eu32,
    0x19862663u32,
    0x086e61d3u32,
    0x61f98df3u32,
    0xcfe134d7u32,
    0x0ae4bc81u32,
    0x9bb18921u32,
    0xa1cfa419u32,
    0x27b0afabu32,
    0x621fc926u32,
    0xa6624f77u32,
    0x230ea81fu32,
    0x317d7b93u32,
    0xe294cfa5u32,
    0x0a16a5bcu32,
    0x4d9eb290u32,
    0x9965aef9u32,
    0xdf83a499u32,
    0x869495f8u32,
    0x1bf724edu32,
    0xf5ce2c38u32,
    0x0de34be9u32,
    0x966970e2u32,
];
pub(super) const CURRENT_OUTER_INITIAL_WORDS: [u32; 5] = [
    0x6dc9bf74u32,
    0x31f0c2b6u32,
    0x8310792au32,
    0xa2c14bc4u32,
    0x3c55e264u32,
];
pub(super) const CURRENT_OUTER_INITIAL_OPTIONAL_WORD: u32 = (0x976dec8du32 as u32);
pub(super) const CURRENT_OUTER_INITIAL_X1: u32 = (0x60319d83u32 as u32);
pub(super) const CURRENT_OUTER_INITIAL_COUNTER_SEED: u32 = (0x0a782fecu32 as u32);
pub(super) const OUTER_DIGEST_HARDWARE_MAPS: [[&[(u32, u32)]; 5]; 6] = [
    [
        &[(18, 0x03fc0000)],
        &[(3, 0x000007f8), (28, 0xf000000f)],
        &[],
        &[(28, 0xf000000f)],
        &[(11, 0x0007f800)],
    ],
    [
        &[(18, 0x03fc0000)],
        &[(12, 0x000ff000)],
        &[],
        &[],
        &[(1, 0x000001fe), (16, 0x00ff0000)],
    ],
    [
        &[(27, 0xf8000007), (31, 0x8000007f)],
        &[(7, 0x00003f80), (30, 0xc000003f)],
        &[(7, 0x00007f80)],
        &[],
        &[(14, 0x003fc000)],
    ],
    [
        &[(2, 0x000003fc), (15, 0x007f8000), (29, 0xe000001f)],
        &[(9, 0x0001be00)],
        &[(9, 0x0001fe00)],
        &[],
        &[(30, 0xc000003f)],
    ],
    [
        &[(28, 0xf000000f)],
        &[(6, 0x00003dc0), (25, 0xfe000001)],
        &[(25, 0xfe000001)],
        &[(6, 0x00003fc0)],
        &[],
    ],
    [
        &[(19, 0x07f80000), (30, 0xc000003f)],
        &[(8, 0x0000fd00)],
        &[],
        &[(8, 0x0000ff00)],
        &[(2, 0x000003fc)],
    ],
];
pub(super) const OUTER_DIGEST_CODEC_MAPS: [[&[(u32, u32)]; 5]; 13] = [
    [&[(21, 0x1fe00000)], &[(10, 0x0003fc00)], &[], &[], &[]],
    [&[(9, 0x0001fe00)], &[], &[], &[], &[(24, 0xff000000)]],
    [&[(11, 0x0007f800)], &[], &[], &[], &[]],
    [
        &[(4, 0x00000ff0), (16, 0x00ff0000)],
        &[(26, 0xfc000003)],
        &[],
        &[(26, 0xfc000003)],
        &[(19, 0x07f80000)],
    ],
    [&[], &[], &[], &[], &[]],
    [
        &[(4, 0x00000ff0), (23, 0x7f800000)],
        &[(14, 0x003fc000)],
        &[],
        &[(14, 0x003fc000)],
        &[(6, 0x00003fc0)],
    ],
    [
        &[(9, 0x0001fe00)],
        &[(21, 0x1fe00000)],
        &[(21, 0x1fe00000)],
        &[],
        &[],
    ],
    [
        &[(31, 0x8000007f)],
        &[(9, 0x0001fc00)],
        &[],
        &[(9, 0x0001fe00)],
        &[],
    ],
    [
        &[(2, 0x000003fc)],
        &[(14, 0x00378000)],
        &[(14, 0x003fc000)],
        &[],
        &[],
    ],
    [&[], &[(23, 0x7f800000)], &[], &[], &[]],
    [
        &[(28, 0xf000000f)],
        &[(8, 0x0000bf00)],
        &[(8, 0x0000ff00)],
        &[],
        &[],
    ],
    [&[(23, 0x7f800000)], &[(18, 0x03fc0000)], &[], &[], &[]],
    [&[], &[], &[], &[], &[]],
];
