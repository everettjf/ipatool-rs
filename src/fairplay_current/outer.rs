//! Bounded current SIDB source derivation from UnfairPlay b3a7a432 (MIT).
//! The production path uses semantic state, not an Apple executable or profile.

use anyhow::{Result, bail};
use zeroize::{Zeroize, Zeroizing};

mod math;
use math::*;

const MAX_MODULUS: usize = 18;
const MAX_PAYLOAD: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Layout {
    pub codec_bytes: usize,
    pub payload_offset: usize,
    pub payload_bytes: usize,
    pub source_bytes: usize,
    pub selector_modulus: usize,
    pub selected_slot: usize,
    pub root_cursor: usize,
    pub iterations: usize,
}

pub struct SelectionSource {
    pub source: Zeroizing<Vec<u8>>,
    pub layout: Layout,
}

struct OuterState {
    words: [u32; 5],
    hardware: [u8; 6],
    hardware_index: usize,
    codec: [u8; 43],
    source: [u8; 224],
    tail: [u8; 140],
    writer: [u8; 140],
    optional_word: u32,
}

impl Drop for OuterState {
    fn drop(&mut self) {
        self.words.zeroize();
        self.hardware.zeroize();
        self.hardware_index.zeroize();
        self.codec.zeroize();
        self.source.zeroize();
        self.tail.zeroize();
        self.writer.zeroize();
        self.optional_word.zeroize();
    }
}

struct Digest {
    x0: u32,
    x4: u32,
    x10: u32,
    x27: u32,
    x28: u32,
    counter: u32,
    codec_selector: u32,
}

impl Drop for Digest {
    fn drop(&mut self) {
        self.x0.zeroize();
        self.x4.zeroize();
        self.x10.zeroize();
        self.x27.zeroize();
        self.x28.zeroize();
        self.counter.zeroize();
        self.codec_selector.zeroize();
    }
}

fn polynomial(inputs: &[u32], terms: &[(u32, u64)]) -> u32 {
    let mut output = 0;
    for &(mask, mut product) in terms {
        let mut value = mask;
        while product != 0 {
            value &= inputs[product.trailing_zeros() as usize];
            product &= product - 1;
        }
        output ^= value;
    }
    output
}

/// The hardware-derived root cursor does not inspect or search SIDB contents.
pub fn root_cursor(hardware: &[u8]) -> Result<usize> {
    if hardware.len() != 6 {
        bail!("current recovery requires a six-byte hardware identity");
    }
    let mut hash = 0u32;
    let mut polynomial = 0u32;
    let mut multiplier = 0x5f64ac89u32;
    for (&value, factor) in hardware.iter().zip([0, 13, 15, 11, 19, 9]) {
        let value = u32::from(value);
        hash ^= value.wrapping_mul(multiplier).wrapping_add(0x1b4591cd);
        polynomial = polynomial.wrapping_mul(factor).wrapping_add(value);
        multiplier = multiplier.wrapping_add(0x34139);
    }
    Ok(1 + ((hash ^ polynomial) % 12) as usize)
}

fn route_byte(value: u8, routes: &[(u32, u32)]) -> u32 {
    routes.iter().fold(0, |out, &(rotate, mask)| {
        out ^ (u32::from(value).rotate_left(rotate) & mask)
    })
}

fn digest_step(state: &mut Digest, hardware: &[u8; 6], codec: &[u8; 43], base: usize) -> bool {
    let exit = state.counter == 0x6247750e;
    let core =
        state.x0 ^ state.x4.rotate_left(20) ^ state.x10.rotate_left(22) ^ state.x28.rotate_left(17);
    let mut next = [
        core ^ 0x4ff57b2b,
        0xe11c7ff6 ^ (state.x4 & 0xfff7bfff) ^ (state.x10 & 0xfffffdff),
        state.x4,
        state.x10,
        state.x28,
    ];
    let phase = state.codec_selector.wrapping_add(0x9fce6288) as usize % 13;
    for (index, mapping) in OUTER_DIGEST_HARDWARE_MAPS.iter().enumerate() {
        for (lane, routes) in next.iter_mut().zip(mapping) {
            *lane ^= route_byte(hardware[(base + index) % 6], routes);
        }
    }
    for (index, mapping) in OUTER_DIGEST_CODEC_MAPS.iter().enumerate() {
        for (lane, routes) in next.iter_mut().zip(mapping) {
            *lane ^= route_byte(codec[4 + (phase + index) % 13], routes);
        }
    }
    state.x0 = state.x27 ^ (next[0] & 0xc7a9ffef) ^ next[1];
    state.x27 = next[0];
    state.x4 = next[2];
    state.x10 = next[3];
    state.x28 = next[4];
    state.counter = state.counter.wrapping_sub(1);
    next.zeroize();
    exit
}

fn front(
    table: &[u32; 167],
    base: u32,
    state: &mut OuterState,
    x1: u32,
    seed: u32,
) -> Result<(u32, u32, u32)> {
    let (counter, valid) = outer_digest_initial_counter(x1, seed);
    if !valid {
        bail!("current outer digest has an unmapped control state");
    }
    let mut digest = Digest {
        x0: state.words[0],
        x4: state.words[3],
        x10: state.words[2],
        x27: state.words[1],
        x28: state.words[4],
        counter,
        codec_selector: 0x60319d93,
    };
    let mut complete = false;
    for _ in 0..1024 {
        crate::application::operation::check()?;
        let exit = digest_step(
            &mut digest,
            &state.hardware,
            &state.codec,
            (state.hardware_index + 2) % 6,
        );
        digest.codec_selector = digest.codec_selector.wrapping_sub(1);
        if exit {
            complete = true;
            break;
        }
    }
    if !complete {
        bail!("current outer digest exceeded its iteration bound");
    }
    let (words, core) = front_words(table, base, &digest);
    let hooks = hook_seeds(table, base, &digest, core);
    let common = words[1] ^ (words[4] >> 11) ^ 0x3b;
    for (i, offsets) in OUTER_FRONT_SOURCE_EXTRAS.iter().enumerate() {
        let tap = |offset| table[((base + offset) % 167) as usize];
        state.source[i] =
            (common ^ tap(offsets[0]) ^ (tap(offsets[1]) >> 9) ^ (tap(offsets[2]) >> 22)) as u8;
    }
    for (i, offsets) in [[36, 160, 118], [159, 116, 74], [115, 72, 30], [71, 28, 153]]
        .iter()
        .enumerate()
    {
        let tap = |offset| table[((7 * base + offset) % 167) as usize];
        state.source[12 + i] = tap(offsets[0]) as u8
            ^ state.words[1] as u8
            ^ (state.words[4] >> 13) as u8
            ^ (tap(offsets[1]) >> 17) as u8
            ^ (tap(offsets[2]) >> 7) as u8
            ^ 0xd3;
    }
    state.words = words;
    Ok(hooks)
}

fn advance_seed(seed: u32, iterations: u32) -> u32 {
    if iterations == 0 {
        return seed;
    }
    let phase = outer_writer_seed_step(seed) - OUTER_WRITER_SEED_BASE;
    OUTER_WRITER_SEED_BASE + (phase + OUTER_WRITER_SEED_STRIDE * ((iterations - 1) % 167)) % 167
}

fn optional_transform(input: u32) -> Result<u32> {
    if input & 0xffffff00 != 0x976dec00 {
        bail!("unsupported optional outer input");
    }
    let value = input & 255;
    let delta = if value & 2 == 0 {
        0x182
    } else if value & 0x0c != 0 {
        0x17a
    } else if value & 0x70 == 0x70 {
        0x09a
    } else {
        0x19a
    };
    Ok(0x976dec00 + ((value + delta) & 0x1ff))
}

fn table_round(table: &mut [u32; 167], base: u32, state: &mut OuterState) {
    // Taps must read the live table, including writes from earlier lanes.
    macro_rules! tap {
        ($offset:expr) => {
            table[((base + $offset) % 167) as usize]
        };
    }
    let indexes = OUTER_TABLE_LANE_OFFSETS.map(|offset| ((base + offset) % 167) as usize);
    let [mut s0, mut s1, mut s2, mut s3, mut s4] = state.words;
    let pending_s2 = outer_table_pending_s2(s2, tap!(70), tap!(112), tap!(154));
    let pending_s1 = outer_table_lane0_pending_s1(
        pending_s2,
        s0,
        s1,
        s3,
        tap!(27),
        tap!(69),
        tap!(111),
        tap!(152),
    );
    let pending_s3 = outer_table_lane0_pending_s3(pending_s2, s0, s3, s4);
    table[indexes[0]] ^=
        outer_table_lane0_mask(pending_s2, s0, s1, s3, s4, tap!(27), tap!(69), tap!(111));
    table[indexes[1]] ^= outer_table_lane1_mask(pending_s1, pending_s2, pending_s3, s4);
    s2 = pending_s2;
    table[indexes[2]] ^= outer_table_lane2_mask(pending_s1, pending_s2, pending_s3, s0, s4);
    s0 = outer_table_lane2_next_s0(pending_s2, pending_s1, pending_s3, s0);
    table[indexes[3]] ^= outer_table_lane3_mask(s0, pending_s3);
    s3 = pending_s3;
    table[indexes[4]] ^= outer_table_lane4_mask(table[4], table[101], table[115], table[119]);
    table[indexes[5]] ^= outer_table_lane5_mask(pending_s1, s3, s0);
    s1 = pending_s1;
    let h = |offset| u32::from(state.hardware[(state.hardware_index + offset) % 6]);
    s2 = outer_table_lane5_next_s2(
        s2,
        h(0),
        h(1),
        h(2),
        u32::from(state.codec[4]),
        u32::from(state.codec[6]),
        u32::from(state.codec[8]),
    );
    let pending_s4 = outer_table_lane5_pending_s4(s4, s0, pending_s1, s3);
    table[indexes[6]] ^= outer_table_lane6_mask(s1, pending_s4, s0);
    s4 = pending_s4;
    table[indexes[7]] ^= outer_table_lane7_mask(s0, s1, s3, s4, table[indexes[7]]);
    s0 = outer_table_lane7_next_s0(s0, s1, s3, s4);
    table[indexes[8]] ^= outer_table_lane8_mask(table[28], table[72], table[76], table[123]);
    s1 = outer_table_lane8_next_s1(s1, s2, s3, s4);
    table[indexes[9]] ^= outer_table_lane9_mask(s2, s0, s4);
    table[indexes[10]] ^= outer_table_lane10_mask(s2, s3, s4);
    table[indexes[11]] ^= outer_table_lane11_mask(s2, s0, s3, s1);
    table[indexes[12]] ^= outer_table_lane12_mask(s1, s0, s3, s4);
    table[indexes[13]] ^= outer_table_lane13_mask(s3, s2, s4);
    table[indexes[14]] ^= outer_table_lane14_mask(s0, s2, s3, s4);
    table[indexes[15]] ^= outer_table_lane15_mask(table[27], table[56], table[88], table[141]);
    s4 = outer_table_lane15_next_s4(s1, s4, s2, s0);
    table[indexes[16]] ^= outer_table_lane16_mask(s1, s2, s3);
    table[indexes[17]] ^= outer_table_lane17_mask(s0, s1, s3);
    table[indexes[18]] ^= outer_table_lane18_mask(s1, s3, s0, s2, table[indexes[18]]);
    let mix = outer_table_lane18_mix(s0, s2, s1, s3);
    table[indexes[19]] ^= outer_table_lane19_mask(mix, s1, s4, tap!(2), tap!(44), tap!(86));
    let late = outer_table_lane19_late_mix(mix, tap!(2), tap!(44), tap!(86));
    let pending_s0 = late ^ 0x71563c28;
    table[indexes[20]] ^= outer_table_lane20_mask(pending_s0, s1, late, s3);
    state.words = [pending_s0, s1, s2, s3, s4];
    state.hardware_index = (state.hardware_index + 5) % 6;
}

fn full_iteration(
    table: &mut [u32; 167],
    base: u32,
    state: &mut OuterState,
    x1: &mut u32,
    seed: &mut u32,
) -> Result<u32> {
    crate::application::operation::check()?;
    if base >= 167 || state.hardware_index >= 6 {
        bail!("invalid current outer state geometry");
    }
    let initial_seed = *seed;
    let first = outer_optional_first_index(initial_seed) as usize;
    let second = ((table[first] ^ 0x224ea33b) % 167) as usize;
    let input = outer_optional_decode(table[second]);
    state.optional_word =
        if input & 0xffffff00 == 0x976dec00 && (input as u8 >= 0x80 || input as u8 == 0x0d) {
            optional_transform(input)?
        } else {
            input
        };
    let (even, odd, tail) = front(table, base, state, *x1, *seed)?;
    let mut even_index =
        advance_seed(initial_seed, (144 * base + 5) % 167).wrapping_add(0xf587d089) % 167;
    let mut odd_index =
        advance_seed(initial_seed, (144 * base + 129) % 167).wrapping_add(0xf587d089) % 167;
    for i in 0..50 {
        let a = even_index as usize;
        state.source[32 + 2 * i] =
            (even ^ (table[a] >> 9) ^ table[(a + 42) % 167] ^ (table[(a + 41) % 167] >> 23) ^ 0x6d)
                as u8;
        even_index = ((a + 41) % 167) as u32;
        let a = odd_index as usize;
        state.source[33 + 2 * i] =
            (odd ^ (table[a] >> 19) ^ table[(a + 42) % 167] ^ (table[(a + 82) % 167] >> 13) ^ 0x87)
                as u8;
        odd_index = ((2 * a + 41) % 167) as u32;
    }
    let mut tail_index =
        advance_seed(initial_seed, (139 * base) % 167).wrapping_add(0xf587d089) as usize % 167;
    for byte in &mut state.tail {
        let a = tail_index;
        *byte =
            (tail ^ (table[a] >> 18) ^ table[(a + 42) % 167] ^ (table[(a + 83) % 167] >> 2) ^ 0xb8)
                as u8;
        tail_index = (tail_index + 166) % 167;
    }
    if !pre_round(table, base, state) {
        bail!("invalid current outer pre-round");
    }
    table_round(table, base, state);
    *seed = advance_seed(*seed, (139 * base + 29) % 167);
    let mut x14 = state.words[2];
    let mut x16 = state.words[0];
    let writer_seed = state.words[4];
    let writer_start = seed.wrapping_add(0xf587d089) as usize % 167;
    let mut controls = Zeroizing::new([0; 140]);
    let mut indexes = [77, 36, 119, 161].map(|offset| ((base + offset) % 167) as usize);
    for control in controls.iter_mut() {
        *control = x16;
        (x14, x16) = outer_post_round_step(
            x14,
            x16,
            table[indexes[0]],
            table[indexes[1]],
            table[indexes[2]],
            table[indexes[3]],
        );
        *seed = outer_writer_seed_step(*seed);
        for index in &mut indexes {
            *index = (*index + 36) % 167;
        }
    }
    state.words[0] = x16;
    state.words[2] = x14;
    for (i, &control) in controls.iter().enumerate() {
        let index = (writer_start + i * 36) % 167;
        state.writer[i] = (control >> 11) as u8
            ^ writer_seed as u8
            ^ (table[index] >> 19) as u8
            ^ table[(index + 42) % 167] as u8
            ^ (table[(index + 82) % 167] >> 17) as u8
            ^ 0xd2;
    }
    state.source[92..].copy_from_slice(&state.writer[..132]);
    *x1 = 0x60319e4b;
    let (next, valid) = next_outer_table_base(base);
    debug_assert!(valid);
    Ok(next)
}

fn cycle(state: &mut OuterState, current: u8) {
    let h = |o| u32::from(state.hardware[(state.hardware_index + o) % 6]);
    let c = |o| u32::from(state.codec[o]);
    let current = u32::from(current);
    state.words[0] ^= (h(0) << 5)
        ^ (h(1) << 8)
        ^ h(2).rotate_left(30)
        ^ (current << 3)
        ^ (current << 9)
        ^ (current << 20);
    state.words[1] ^= (h(3) << 4)
        ^ (h(4) << 14)
        ^ (h(5) << 18)
        ^ (current << 3)
        ^ (current << 10)
        ^ current.rotate_left(30)
        ^ c(8).rotate_left(26)
        ^ (c(10) << 14)
        ^ (c(12) << 10);
    state.words[2] ^= (h(1) << 7)
        ^ (h(2) << 2)
        ^ (h(2) << 15)
        ^ (h(3) << 12)
        ^ (h(3) << 18)
        ^ h(4).rotate_left(28)
        ^ (current << 5)
        ^ (current << 6)
        ^ (current << 13)
        ^ (current << 16)
        ^ current.rotate_left(28)
        ^ (c(5) << 16)
        ^ (c(7) << 5)
        ^ c(10).rotate_left(25)
        ^ (c(12) << 17)
        ^ (c(14) << 7)
        ^ (c(16) << 23);
    state.words[3] ^= (h(0) << 12)
        ^ (h(1) << 22)
        ^ (h(5) << 1)
        ^ (current << 2)
        ^ (current << 3)
        ^ (current << 15)
        ^ (current << 21)
        ^ (current << 23)
        ^ c(5).rotate_left(28)
        ^ (c(7) << 19)
        ^ (c(9) << 4);
    state.words[4] ^= h(0).rotate_left(26)
        ^ (h(4) << 1)
        ^ (h(5) << 11)
        ^ (current << 7)
        ^ (current << 11)
        ^ (current << 16)
        ^ (current << 18)
        ^ current.rotate_left(28)
        ^ (c(4) << 3)
        ^ c(13).rotate_left(28)
        ^ (c(15) << 14);
}

fn stop_step(words: [u32; 5], accumulator: &mut u32) -> bool {
    let target = 0x05010000u32;
    let w11 = target ^ 0x050183f6;
    let mut w9 = words[3] ^ 0x189c788b ^ words[2];
    let mut w10 = words[1];
    w9 |= w10 ^ 0xdc6e37ea;
    let w12 = words[4] ^ 0xc7c208dc;
    let w14 = words[2] ^ 0x00000c09;
    let w13 = words[2] ^ 0x399b2000;
    let w13 = (((u64::from(w14) << 32) | u64::from(w13)) >> 13) as u32;
    let w14 = w11.wrapping_add(0xfa8e2a8c);
    w10 = (w14 ^ w10) & w12 & w13;
    w9 |= w10;
    w10 = 0x0fc20444 & (w9 << 1);
    w9 = w9.wrapping_sub(w10).wrapping_add(0x87e10222);
    w10 = (*accumulator ^ 0x5db37cfe) & (w9 ^ 0x87e10222);
    w9 = (w9 & 0x4d191d94) ^ w10;
    *accumulator = w9 ^ 0x15ab616a;
    w9 == target
}

pub fn derive_selection_source(container: &[u8], hardware: &[u8]) -> Result<SelectionSource> {
    if hardware.len() != 6
        || container.len() < 4 + 13 + 16
        || container.len() > MAX_PAYLOAD + 4 + 372 + 16
        || container[..4] != 0x0007000bu32.to_be_bytes()
    {
        bail!("unsupported current SIDB version or input geometry");
    }
    let mut table = Zeroizing::new(CURRENT_OUTER_INITIAL_TABLE);
    let mut state = OuterState {
        words: CURRENT_OUTER_INITIAL_WORDS,
        hardware: hardware.try_into()?,
        hardware_index: 0,
        codec: [0; 43],
        source: [0; 224],
        tail: [0; 140],
        writer: [0; 140],
        optional_word: CURRENT_OUTER_INITIAL_OPTIONAL_WORD,
    };
    state.codec[4..17].copy_from_slice(&container[4..17]);
    let mut x1 = CURRENT_OUTER_INITIAL_X1;
    let mut seed = CURRENT_OUTER_INITIAL_COUNTER_SEED;
    let mut base = OUTER_TABLE_INITIAL_BASE;
    let mut accumulator = 0xaf549e95;
    let available = 372.min(container.len() - 4 - 16);
    let mut cycles = 0;
    for iteration in 1..=11 * available - 2 {
        base = full_iteration(&mut table, base, &mut state, &mut x1, &mut seed)?;
        if iteration >= 9 && (iteration - 9) % 11 == 0 {
            cycles += 1;
            cycle(&mut state, container[4 + cycles - 1]);
            x1 = 0x60319d87;
            if cycles >= 14 && stop_step(state.words, &mut accumulator) {
                let payload_offset = 4 + cycles;
                let payload_bytes = container.len() - payload_offset - 16;
                let count = (0x0976dec8 ^ (state.optional_word >> 4)) as usize;
                if payload_bytes == 0
                    || !payload_bytes.is_multiple_of(16)
                    || payload_bytes > MAX_PAYLOAD
                    || !(1..=MAX_MODULUS).contains(&count)
                {
                    bail!("current SIDB has unmapped source or payload geometry");
                }
                let mut source = Zeroizing::new([0u8; 32 + 16 * MAX_MODULUS]);
                source[..224].copy_from_slice(&state.source);
                source[224..232].copy_from_slice(&state.writer[132..140]);
                source[232..].copy_from_slice(&state.tail[40..128]);
                let length = 32 + 16 * count;
                return Ok(SelectionSource {
                    source: Zeroizing::new(source[..length].to_vec()),
                    layout: Layout {
                        codec_bytes: cycles,
                        payload_offset,
                        payload_bytes,
                        source_bytes: length,
                        selector_modulus: count,
                        selected_slot: usize::from(container[payload_offset - 1]) % count,
                        root_cursor: root_cursor(hardware)?,
                        iterations: iteration,
                    },
                });
            }
        }
    }
    bail!("current SIDB codec did not reach its bounded exit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    #[derive(serde::Deserialize)]
    struct Iteration {
        index: usize,
        next: u32,
        sha256: String,
    }

    #[derive(serde::Deserialize)]
    struct Vectors {
        iterations: Vec<Iteration>,
        container: Vec<u8>,
        hardware: Vec<u8>,
        source_sha256: String,
        layout: Layout,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/fairplay-current-outer-public-vectors.json"
        ))
        .unwrap()
    }

    fn digest(table: &[u32; 167], state: &OuterState, x1: u32, seed: u32) -> String {
        let mut hash = Sha256::new();
        for word in table.iter().chain(&state.words) {
            hash.update(word.to_le_bytes());
        }
        hash.update(state.hardware);
        hash.update([state.hardware_index as u8]);
        hash.update(state.codec);
        hash.update(state.source);
        hash.update(state.tail);
        hash.update(state.writer);
        for word in [state.optional_word, x1, seed] {
            hash.update(word.to_le_bytes());
        }
        format!("{:x}", hash.finalize())
    }

    #[test]
    fn complete_semantic_iterations_match_pinned_go_on_public_synthetic_state() {
        let vectors = vectors();
        assert_eq!(vectors.iterations.len(), 32);
        for vector in vectors.iterations {
            let n = vector.index;
            let mut table = std::array::from_fn(|i| {
                (i as u32 + 1).wrapping_mul(0x9e3779b9) ^ (n as u32).wrapping_mul(0x1234567)
            });
            let mut state = OuterState {
                words: std::array::from_fn(|i| {
                    (i as u32 + 1).wrapping_mul(0x31415927) ^ (n as u32).wrapping_mul(0x1b2b3b4b)
                }),
                hardware: std::array::from_fn(|i| (n * 17 + i * 37) as u8),
                hardware_index: n % 6,
                codec: std::array::from_fn(|i| (i * 29 + n * 13) as u8),
                source: std::array::from_fn(|i| (i * 31 + n * 19) as u8),
                tail: std::array::from_fn(|i| (i * 41 + n * 3) as u8),
                writer: std::array::from_fn(|i| (i * 43 + n * 5) as u8),
                optional_word: 0,
            };
            let mut x1 = [0x60319d83, 0x60319e4b, 0x60319d87][n % 3];
            let mut seed = (n as u32).wrapping_mul(0xf1234567).wrapping_add(0x0a782fec);
            let next = full_iteration(
                &mut table,
                (n * 13 % 167) as u32,
                &mut state,
                &mut x1,
                &mut seed,
            )
            .unwrap();
            assert_eq!(next, vector.next, "synthetic iteration {n}");
            assert_eq!(
                digest(&table, &state, x1, seed),
                vector.sha256,
                "synthetic iteration {n}"
            );
        }
    }

    #[test]
    fn derives_content_selected_boundary_and_source_matching_go() {
        let vectors = vectors();
        let derived = derive_selection_source(&vectors.container, &vectors.hardware).unwrap();
        assert_eq!(derived.layout, vectors.layout);
        assert_eq!(
            format!("{:x}", Sha256::digest(&*derived.source)),
            vectors.source_sha256
        );
        let mut changed = vectors.container.clone();
        changed[derived.layout.payload_offset + 17] ^= 1;
        let other = derive_selection_source(&changed, &vectors.hardware).unwrap();
        assert_eq!(
            *other.source, *derived.source,
            "body authentication is a separate gate"
        );
        for (container, hardware) in [
            (
                &vectors.container[..vectors.container.len() - 1],
                &vectors.hardware[..],
            ),
            (&vectors.container[..], &vectors.hardware[..5]),
        ] {
            assert!(derive_selection_source(container, hardware).is_err());
        }
        changed[3] ^= 1;
        assert!(derive_selection_source(&changed, &vectors.hardware).is_err());
        let operation = crate::application::operation::Operation::default();
        let error = operation
            .run(|| {
                operation.cancel();
                derive_selection_source(&vectors.container, &vectors.hardware)
            })
            .err()
            .unwrap();
        assert!(error.is::<crate::application::operation::Cancelled>());
    }
}
