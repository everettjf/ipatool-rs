//! AES and GF(2) helpers for the Rust FairPlay recovery algorithm.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. DarkPhoenix attribution and Apache-2.0 terms are in
//! `licenses/LICENSE-DARKPHOENIX.txt`.

use std::sync::LazyLock;

use anyhow::{Result, bail};
use zeroize::{Zeroize, Zeroizing};

pub const SHIFT: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
pub const INV_SHIFT: [usize; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

pub static SBOX: LazyLock<[u8; 256]> = LazyLock::new(|| {
    let mut table = [0; 256];
    for (index, target) in table.iter_mut().enumerate() {
        let inverse = gf_inv(index as u8);
        let mut rotated = inverse;
        let mut value = inverse;
        for _ in 0..4 {
            rotated = rotated.rotate_left(1);
            value ^= rotated;
        }
        *target = value ^ 0x63;
    }
    table
});

pub static INV_SBOX: LazyLock<[u8; 256]> = LazyLock::new(|| {
    let mut table = [0; 256];
    for (source, &target) in SBOX.iter().enumerate() {
        table[target as usize] = source as u8;
    }
    table
});

pub fn xtime(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 != 0 { 0x1b } else { 0 }
}

pub fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;
    while right != 0 {
        if right & 1 != 0 {
            result ^= left;
        }
        left = xtime(left);
        right >>= 1;
    }
    result
}

pub fn gf_inv(value: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    let (mut result, mut base, mut exponent) = (1, value, 254);
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

pub fn shift_rows(input: [u8; 16]) -> [u8; 16] {
    core::array::from_fn(|index| input[SHIFT[index]])
}

pub fn inv_shift_rows(input: [u8; 16]) -> [u8; 16] {
    core::array::from_fn(|index| input[INV_SHIFT[index]])
}

pub fn sub_bytes(input: [u8; 16]) -> [u8; 16] {
    input.map(|value| SBOX[value as usize])
}

pub fn inv_sub_bytes(input: [u8; 16]) -> [u8; 16] {
    input.map(|value| INV_SBOX[value as usize])
}

pub fn xor(left: [u8; 16], right: [u8; 16]) -> [u8; 16] {
    core::array::from_fn(|index| left[index] ^ right[index])
}

pub fn mix_columns(input: [u8; 16]) -> [u8; 16] {
    let mut output = [0; 16];
    for column in 0..4 {
        let index = column * 4;
        let (a, b, c, d) = (
            input[index],
            input[index + 1],
            input[index + 2],
            input[index + 3],
        );
        output[index] = gf_mul(2, a) ^ gf_mul(3, b) ^ c ^ d;
        output[index + 1] = a ^ gf_mul(2, b) ^ gf_mul(3, c) ^ d;
        output[index + 2] = a ^ b ^ gf_mul(2, c) ^ gf_mul(3, d);
        output[index + 3] = gf_mul(3, a) ^ b ^ c ^ gf_mul(2, d);
    }
    output
}

pub fn inv_mix_columns(input: [u8; 16]) -> [u8; 16] {
    let mut output = [0; 16];
    for column in 0..4 {
        let index = column * 4;
        let (a, b, c, d) = (
            input[index],
            input[index + 1],
            input[index + 2],
            input[index + 3],
        );
        output[index] = gf_mul(14, a) ^ gf_mul(11, b) ^ gf_mul(13, c) ^ gf_mul(9, d);
        output[index + 1] = gf_mul(9, a) ^ gf_mul(14, b) ^ gf_mul(11, c) ^ gf_mul(13, d);
        output[index + 2] = gf_mul(13, a) ^ gf_mul(9, b) ^ gf_mul(14, c) ^ gf_mul(11, d);
        output[index + 3] = gf_mul(11, a) ^ gf_mul(13, b) ^ gf_mul(9, c) ^ gf_mul(14, d);
    }
    output
}

pub fn expand_key(key: [u8; 16]) -> Zeroizing<[u8; 176]> {
    let mut expanded = Zeroizing::new([0; 176]);
    expanded[..16].copy_from_slice(&key);
    let mut rcon = 1;
    for word in 4..44 {
        let mut temporary: [u8; 4] = expanded[(word - 1) * 4..word * 4].try_into().unwrap();
        if word % 4 == 0 {
            temporary = [
                SBOX[temporary[1] as usize],
                SBOX[temporary[2] as usize],
                SBOX[temporary[3] as usize],
                SBOX[temporary[0] as usize],
            ];
            temporary[0] ^= rcon;
            rcon = xtime(rcon);
        }
        for index in 0..4 {
            expanded[word * 4 + index] = temporary[index] ^ expanded[(word - 4) * 4 + index];
        }
    }
    expanded
}

pub fn round_key(expanded: &[u8; 176], round: usize) -> [u8; 16] {
    expanded[round * 16..(round + 1) * 16].try_into().unwrap()
}

pub fn revert_aes128_round_key(round_key: [u8; 16], mut round: usize) -> [u8; 16] {
    let mut current = round_key;
    while round > 0 {
        let mut previous = [0; 16];
        for word in (1..=3).rev() {
            for index in 0..4 {
                previous[word * 4 + index] =
                    current[word * 4 + index] ^ current[(word - 1) * 4 + index];
            }
        }
        let mut rcon = 1;
        for _ in 1..round {
            rcon = xtime(rcon);
        }
        let temporary = [
            SBOX[previous[13] as usize] ^ rcon,
            SBOX[previous[14] as usize],
            SBOX[previous[15] as usize],
            SBOX[previous[12] as usize],
        ];
        for index in 0..4 {
            previous[index] = current[index] ^ temporary[index];
        }
        current = previous;
        round -= 1;
    }
    current
}

pub fn aes_encrypt(input: [u8; 16], expanded: &[u8; 176]) -> [u8; 16] {
    let mut state = xor(input, round_key(expanded, 0));
    for round in 1..10 {
        state = xor(
            mix_columns(shift_rows(sub_bytes(state))),
            round_key(expanded, round),
        );
    }
    xor(shift_rows(sub_bytes(state)), round_key(expanded, 10))
}

pub fn aes_decrypt(input: [u8; 16], expanded: &[u8; 176]) -> [u8; 16] {
    let mut state = xor(input, round_key(expanded, 10));
    for round in (1..10).rev() {
        state = inv_mix_columns(xor(
            inv_sub_bytes(inv_shift_rows(state)),
            round_key(expanded, round),
        ));
    }
    xor(inv_sub_bytes(inv_shift_rows(state)), round_key(expanded, 0))
}

#[derive(Clone)]
pub struct Encoding(pub [[u8; 256]; 16]);

impl Drop for Encoding {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Encoding {
    pub fn identity() -> Self {
        Self(core::array::from_fn(|_| {
            core::array::from_fn(|index| index as u8)
        }))
    }

    pub fn affine(alpha: [u8; 16], beta: [u8; 16]) -> Self {
        Self(core::array::from_fn(|position| {
            core::array::from_fn(|value| gf_mul(alpha[position], value as u8) ^ beta[position])
        }))
    }

    pub fn encode(&self, input: [u8; 16]) -> [u8; 16] {
        core::array::from_fn(|position| self.0[position][input[position] as usize])
    }

    pub fn inverse(&self) -> Result<Self> {
        self.check_permutation()?;
        let mut result = Self([[0; 256]; 16]);
        for position in 0..16 {
            for (source, target) in self.0[position].iter().copied().enumerate() {
                result.0[position][target as usize] = source as u8;
            }
        }
        Ok(result)
    }

    /// Return `self` composed after `other`.
    pub fn combine(&self, other: &Self) -> Self {
        Self(core::array::from_fn(|position| {
            core::array::from_fn(|value| self.0[position][other.0[position][value] as usize])
        }))
    }

    pub fn check_permutation(&self) -> Result<()> {
        for (position, table) in self.0.iter().enumerate() {
            let mut seen = [false; 256];
            for &value in table {
                if seen[value as usize] {
                    bail!("encoding {position} is not bijective");
                }
                seen[value as usize] = true;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mat8(pub [u8; 8]);

impl Mat8 {
    pub fn identity() -> Self {
        Self(core::array::from_fn(|index| 1 << index))
    }

    pub fn multiply(self, right: Self) -> Self {
        let mut result = [0; 8];
        for (row, value) in self.0.into_iter().enumerate() {
            let mut bits = value;
            let mut column = 0;
            while bits != 0 {
                if bits & 1 != 0 {
                    result[row] ^= right.0[column];
                }
                bits >>= 1;
                column += 1;
            }
        }
        Self(result)
    }

    pub fn transpose(self) -> Self {
        let mut result = [0; 8];
        for row in 0..8 {
            for (column, target) in result.iter_mut().enumerate() {
                if self.0[row] >> column & 1 != 0 {
                    *target |= 1 << row;
                }
            }
        }
        Self(result)
    }

    pub fn inverse(self) -> Option<Self> {
        let mut left = self.0;
        let mut right = Self::identity().0;
        for column in 0..8 {
            let pivot = (column..8).find(|&row| left[row] >> column & 1 != 0)?;
            left.swap(column, pivot);
            right.swap(column, pivot);
            for row in 0..8 {
                if row != column && left[row] >> column & 1 != 0 {
                    left[row] ^= left[column];
                    right[row] ^= right[column];
                }
            }
        }
        Some(Self(right))
    }

    pub fn multiplication(value: u8) -> Self {
        Self(core::array::from_fn(|index| gf_mul(value, 1 << index)))
    }

    pub fn apply(self, mut value: u8) -> u8 {
        let mut result = 0;
        let mut index = 0;
        while value != 0 {
            if value & 1 != 0 {
                result ^= self.0[index];
            }
            value >>= 1;
            index += 1;
        }
        result
    }

    pub fn from_map(table: [u8; 256]) -> Self {
        Self(core::array::from_fn(|index| table[1 << index]))
    }

    pub fn from_bits(bits: u64) -> Self {
        Self(core::array::from_fn(|row| {
            (0..8).fold(0, |acc, column| {
                acc | (((bits >> (row * 8 + column)) as u8 & 1) << column)
            })
        }))
    }

    pub fn table(self) -> [u8; 256] {
        core::array::from_fn(|value| self.apply(value as u8))
    }
}

pub fn nullspace(input: &[u64]) -> Vec<u64> {
    let mut rows = [0; 64];
    rows[..input.len()].copy_from_slice(input);
    let mut pivot = [None; 64];
    let mut current_row = 0;
    for (column, slot) in pivot.iter_mut().enumerate() {
        let selected = (current_row..64).find(|&index| rows[index] >> column & 1 != 0);
        let Some(selected) = selected else { continue };
        rows.swap(current_row, selected);
        *slot = Some(current_row);
        for index in 0..64 {
            if index != current_row && rows[index] >> column & 1 != 0 {
                rows[index] ^= rows[current_row];
            }
        }
        current_row += 1;
        if current_row == 64 {
            break;
        }
    }
    let mut result = Vec::new();
    for free in 0..64 {
        if pivot[free].is_some() {
            continue;
        }
        let mut value = 1u64 << free;
        for (column, selected) in pivot.iter().enumerate() {
            if selected.is_some_and(|row| rows[row] >> free & 1 != 0) {
                value |= 1u64 << column;
            }
        }
        result.push(value);
    }
    result
}

pub fn intertwiner_basis(left: Mat8, right: Mat8) -> Vec<u64> {
    let mut equations = [0; 64];
    for row in 0..8 {
        for column in 0..8 {
            let mut coefficient = 0;
            for k in 0..8 {
                if left.0[k] >> column & 1 != 0 {
                    coefficient ^= 1u64 << (row * 8 + k);
                }
                if right.0[row] >> k & 1 != 0 {
                    coefficient ^= 1u64 << (k * 8 + column);
                }
            }
            equations[row * 8 + column] = coefficient;
        }
    }
    nullspace(&equations)
}

pub fn invertible_from_basis(basis: &[u64], limit: usize) -> Vec<Mat8> {
    if basis.is_empty() || basis.len() > 16 {
        return Vec::new();
    }
    let count = 1usize << basis.len().min(12);
    let mut result = Vec::new();
    for mask in 1..count {
        let mut bits = 0;
        for (index, &value) in basis.iter().enumerate() {
            if mask >> index & 1 != 0 {
                bits ^= value;
            }
        }
        let matrix = Mat8::from_bits(bits);
        if matrix.inverse().is_some() {
            result.push(matrix);
            if result.len() == limit {
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes128,
        cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
    };

    #[test]
    fn fips_aes128_vector_and_round_key_reversal() {
        let key: [u8; 16] = core::array::from_fn(|index| index as u8);
        let input = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let expanded = expand_key(key);
        assert_eq!(aes_encrypt(input, &expanded), expected);
        assert_eq!(aes_decrypt(expected, &expanded), input);
        assert_eq!(revert_aes128_round_key(round_key(&expanded, 2), 2), key);
        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut standard = GenericArray::clone_from_slice(&input);
        cipher.encrypt_block(&mut standard);
        assert_eq!(&standard[..], expected);
    }

    #[test]
    fn finite_field_and_intertwiner_match_go_self_check() {
        let matrix = Mat8::multiplication(2);
        let inverse = matrix.inverse().unwrap();
        assert_eq!(matrix.multiply(inverse), Mat8::identity());
        assert_eq!(intertwiner_basis(matrix, matrix).len(), 8);
        assert_eq!(matrix.table()[0x57], gf_mul(2, 0x57));
    }

    #[test]
    fn encoding_composition_and_permutation_validation() {
        let first = Encoding::affine([2; 16], [5; 16]);
        let second = Encoding::affine([3; 16], [7; 16]);
        first.check_permutation().unwrap();
        let value = core::array::from_fn(|index| index as u8);
        assert_eq!(
            first.combine(&second).encode(value),
            first.encode(second.encode(value))
        );
        assert_eq!(first.inverse().unwrap().encode(first.encode(value)), value);
        assert!(
            Encoding::affine([0; 16], [0; 16])
                .check_permutation()
                .is_err()
        );
    }
}
