//! FairPlay page-key derivation for encrypted Mach-O pages.

use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};

const FIXED_PAGE_AES_KEY: [u8; 16] = [
    0xf5, 0x88, 0xff, 0xe1, 0x89, 0xf9, 0x89, 0xf8, 0xe1, 0xf8, 0x89, 0xfe, 0x8a, 0xe1, 0xf4, 0xfe,
];
const PERMUTATIONS: [[usize; 8]; 4] = [
    [0, 1, 2, 3, 4, 5, 6, 7],
    [2, 1, 0, 3, 4, 7, 6, 5],
    [2, 0, 4, 1, 6, 3, 7, 5],
    [1, 2, 4, 0, 7, 3, 5, 6],
];
const PAIR_XOR: [u32; 4] = [0x1e2a7432, 0x087be9c2, 0xa2eb0b97, 0x7ccc42c1];
const OUTPUT_XOR: [u32; 4] = [0x0b770182, 0xbb5b7b69, 0x5f8c31bf, 0xa6e7227a];

fn xtime(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 != 0 { 0x1b } else { 0 }
}

fn mix_column(input: &[u8]) -> [u8; 4] {
    let doubled = std::array::from_fn::<_, 4, _>(|i| xtime(input[i]));
    [
        doubled[0] ^ doubled[1] ^ input[1] ^ input[2] ^ input[3],
        input[0] ^ doubled[1] ^ doubled[2] ^ input[2] ^ input[3],
        input[0] ^ input[1] ^ doubled[2] ^ doubled[3] ^ input[3],
        doubled[0] ^ input[0] ^ input[1] ^ input[2] ^ doubled[3],
    ]
}

fn inverse_mix_column(input: &[u8]) -> [u8; 4] {
    let doubled = std::array::from_fn::<_, 4, _>(|i| xtime(input[i]));
    let quadrupled = doubled.map(xtime);
    let octupled = quadrupled.map(xtime);
    let m09 = std::array::from_fn::<_, 4, _>(|i| octupled[i] ^ input[i]);
    let m0b = std::array::from_fn::<_, 4, _>(|i| octupled[i] ^ doubled[i] ^ input[i]);
    let m0d = std::array::from_fn::<_, 4, _>(|i| octupled[i] ^ quadrupled[i] ^ input[i]);
    let m0e = std::array::from_fn::<_, 4, _>(|i| octupled[i] ^ quadrupled[i] ^ doubled[i]);
    [
        m0e[0] ^ m0b[1] ^ m0d[2] ^ m09[3],
        m09[0] ^ m0e[1] ^ m0b[2] ^ m0d[3],
        m0d[0] ^ m09[1] ^ m0e[2] ^ m0b[3],
        m0b[0] ^ m0d[1] ^ m09[2] ^ m0e[3],
    ]
}

pub fn app_mask_from_logical_key(logical: [u8; 16]) -> [u8; 16] {
    let mut encoded = [0u8; 16];
    for column in 0..4 {
        let word = &logical[column * 4..column * 4 + 4];
        let reversed = [word[3], word[2], word[1], word[0]];
        encoded[column * 4..column * 4 + 4].copy_from_slice(&mix_column(&reversed));
    }
    let writers = [0x1467cdb1, 0xbea0cbf9, 0xea98d9d3, 0x477a1e20];
    let mut state = [0u8; 16];
    for column in 0..4 {
        let mixed = inverse_mix_column(&encoded[column * 4..column * 4 + 4]);
        let mut value = 0u32;
        for byte in mixed {
            value = (((value & 0x00ff_ffff) << 8) | u32::from(byte)).wrapping_add(0x7db8_2c18);
        }
        let result = value
            .wrapping_add((column as u32 + 13).wrapping_mul(0x594e_c277))
            .wrapping_add(0x8603_bbe8)
            ^ 0x07d2_f11e
            ^ writers[column];
        state[column * 4..column * 4 + 4].copy_from_slice(&result.to_be_bytes());
    }
    let mask = [
        0xe6, 0x3d, 0xc3, 0x4e, 0x30, 0x8b, 0xb3, 0x1f, 0x0c, 0xb2, 0xa1, 0x33, 0xca, 0x49, 0x1b,
        0xc0,
    ];
    for (byte, mask_byte) in state.iter_mut().zip(mask) {
        *byte ^= mask_byte;
    }
    state
}

fn masked_select(value: u32, gate: u32) -> u32 {
    (((value ^ 0x2919_f272) & !gate) | (gate & 0xd6e6_0000)) ^ 0x2919_2e1e
}

fn feed_term(value: u16, mask_source: u16) -> u32 {
    let high = (u32::from(value) << 16) ^ 0xff99_de03;
    let mask = u32::from(mask_source) ^ 0xffff_2207;
    let fallback = u32::from(mask_source) & 0x21fc;
    ((high & mask) | fallback) ^ 0x23f5_de6f
}

fn post_square(value: u32, constant: u32) -> u64 {
    let product = u64::from(value) * u64::from(value);
    let high = product >> 32;
    let correction = high
        .wrapping_sub(0x0d09_f9b1_421d_b190)
        .wrapping_sub((high << 1) & 0x17bc_49ce0);
    product ^ u64::from(constant) ^ correction
}

fn page_fold(input: [u8; 16]) -> [u8; 16] {
    let initial = std::array::from_fn::<_, 8, _>(|i| {
        u16::from_be_bytes(input[i * 2..i * 2 + 2].try_into().unwrap()) ^ 0xdc6c
    });
    let mut state = initial;
    for permutation in PERMUTATIONS {
        let mut next = [0u16; 8];
        for pair in 0..4 {
            let left = u32::from(state[permutation[pair * 2]] ^ 0xdc6c);
            let right = u32::from(state[permutation[pair * 2 + 1]] ^ 0xdc6c);
            let sum = left + right;
            let square = sum.wrapping_mul(sum) ^ PAIR_XOR[pair];
            let carry = sum >> 16;
            next[pair * 2] = (square ^ (carry * carry) ^ 0xd470) as u16;
            next[pair * 2 + 1] = ((square >> 16) ^ 0xaa12) as u16;
        }
        state = next;
    }
    let gate3 = u32::from(state[3] ^ 0xdc6c) << 16;
    let gate6 = u32::from(state[6] ^ 0xdc6c) << 16;
    let gate7 = u32::from(state[7] ^ 0xdc6c) << 16;
    let combined = [
        masked_select(u32::from(state[2]), gate3).wrapping_add(feed_term(state[1], state[0])),
        masked_select(u32::from(state[4]), gate6).wrapping_add(feed_term(state[2], state[0])),
        masked_select(u32::from(state[5]), gate7).wrapping_add(feed_term(state[3], state[0])),
        masked_select(u32::from(state[6]), gate7).wrapping_add(feed_term(state[5], state[4])),
    ];
    let mut output = [0u8; 16];
    for pair in 0..4 {
        let square = post_square(combined[pair], OUTPUT_XOR[pair]);
        output[pair * 4..pair * 4 + 2]
            .copy_from_slice(&(initial[pair * 2] ^ square as u16 ^ 0x0b59).to_be_bytes());
        output[pair * 4 + 2..pair * 4 + 4].copy_from_slice(
            &(initial[pair * 2 + 1] ^ (square >> 16) as u16 ^ 0x3188).to_be_bytes(),
        );
    }
    output
}

pub struct PageKeyDeriver {
    cipher: Aes128,
}

impl PageKeyDeriver {
    pub fn from_logical_key(logical: [u8; 16]) -> Self {
        let mask = app_mask_from_logical_key(logical);
        let effective = std::array::from_fn::<_, 16, _>(|i| FIXED_PAGE_AES_KEY[i] ^ mask[i]);
        Self {
            cipher: Aes128::new_from_slice(&effective).unwrap(),
        }
    }

    pub fn page_key(&self, wrapped: &[u8; 16], crypt_offset: u64) -> [u8; 16] {
        let padding = crypt_offset.to_be_bytes();
        let mut blocks = [[0u8; 16]; 3];
        blocks[0][..8].copy_from_slice(&wrapped[8..]);
        blocks[0][8..].copy_from_slice(&padding);
        blocks[1].copy_from_slice(wrapped);
        blocks[2][..8].copy_from_slice(&padding);
        blocks[2][8..].copy_from_slice(&wrapped[..8]);
        for block in &mut blocks {
            let mut aes_block = GenericArray::clone_from_slice(block);
            self.cipher.encrypt_block(&mut aes_block);
            block.copy_from_slice(&aes_block);
        }
        let mut state = page_fold(blocks[0]);
        for (byte, encrypted) in state.iter_mut().zip(blocks[1]) {
            *byte ^= encrypted;
        }
        state = page_fold(state);
        for (byte, encrypted) in state.iter_mut().zip(blocks[2]) {
            *byte ^= encrypted;
        }
        page_fold(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_go_page_key_vectors() {
        let logical = std::array::from_fn::<_, 16, _>(|i| i as u8 + 1);
        let wrapped = std::array::from_fn::<_, 16, _>(|i| i as u8 + 0x40);
        assert_eq!(
            app_mask_from_logical_key(logical),
            hex_bytes("788a1ded63ac217fa650e6fc2e1ac183")
        );
        assert_eq!(
            page_fold(wrapped),
            hex_bytes("7932f6cfdf98456cc67a6a6d742174e2")
        );
        let deriver = PageKeyDeriver::from_logical_key(logical);
        assert_eq!(
            deriver.page_key(&wrapped, 0x4000),
            hex_bytes("1ab89876c564bd74ad78399082aac803")
        );
        assert_eq!(
            deriver.page_key(&wrapped, 0x5000),
            hex_bytes("69697c739ee6d719220cdf18efe879e4")
        );
    }

    fn hex_bytes(value: &str) -> [u8; 16] {
        std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
    }
}
