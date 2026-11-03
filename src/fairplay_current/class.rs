//! Typed account-class key derivation from UnfairPlay b3a7a432 (MIT).

use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Result, bail};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

const MODULUS: u32 = 32767;

fn power(mut base: u64, mut exponent: u32) -> u16 {
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % u64::from(MODULUS);
        }
        base = base * base % u64::from(MODULUS);
        exponent >>= 1;
    }
    result as u16
}

fn multiply(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    result
}

fn workspace(word: u16) -> Result<u32> {
    let seed = u32::from(word) % MODULUS;
    let exponent = seed + 1;
    let mut product = Zeroizing::new(std::array::from_fn::<_, 9, _>(|i| {
        u32::from(power(u64::from((exponent + i as u32) % MODULUS), exponent))
    }));
    let mut current = Zeroizing::new([seed; 9]);
    for column in 0..3 {
        for row in 0..3 {
            crate::application::operation::check()?;
            let position = row * 3 + column;
            let mut force = 0u32;
            for other in 0..3 {
                if other == row {
                    continue;
                }
                let mut norm = 0u64;
                for coordinate in 0..3 {
                    let difference = (product[row * 3 + coordinate] + MODULUS
                        - product[other * 3 + coordinate])
                        % MODULUS;
                    norm += u64::from(difference) * u64::from(difference);
                }
                let weight = u32::from(power(norm % u64::from(MODULUS), 45));
                let delta = product[other * 3 + column].wrapping_sub(product[position]);
                force = force.wrapping_add(delta.wrapping_mul(weight));
            }
            let exponent = (product[position] + seed + current[position]) % 150;
            let forward = force
                .wrapping_add(u32::from(power(5, exponent)))
                .wrapping_add(seed)
                % MODULUS;
            current[position] = (forward + current[position]) % MODULUS;
            product[position] = (product[position] + current[position]) % MODULUS;
        }
    }
    let diagonal0 = product[0] + product[8];
    let diagonal1 = product[1] + product[3];
    let diagonal2 = product[2] + product[4] + product[6];
    let diagonal3 = product[5] + product[7];
    Ok(diagonal0
        .wrapping_add(diagonal1 << 8)
        .wrapping_add(diagonal2 << 16)
        .wrapping_add(diagonal3 << 24))
}

pub fn account_key(hardware: &[u8], user: u32, key: u32) -> Result<Zeroizing<[u8; 16]>> {
    if hardware.len() != 6 {
        bail!("account-class derivation requires six hardware bytes");
    }
    crate::application::operation::check()?;
    let mut message = Zeroizing::new([0u8; 45]);
    message[..17].copy_from_slice(&[
        0x5b, 0x53, 0xba, 0xe2, 0xa6, 0x6f, 0x01, 0x67, 0x73, 0x29, 0x10, 0xc5, 0x20, 0x99, 0xb7,
        0x33, 0x81,
    ]);
    message[17..23].copy_from_slice(hardware);
    message[23..27].copy_from_slice(&key.to_be_bytes());
    message[27..31].copy_from_slice(&user.to_be_bytes());
    message[31..33].copy_from_slice(&[0xff, 0xff]);
    message[33..].copy_from_slice(&[
        0x54, 0xda, 0x7b, 0x97, 0xe1, 0xf9, 0x0e, 0xc3, 0xae, 0x64, 0x6e, 0x3a,
    ]);
    let mut digest = Zeroizing::new([0u8; 20]);
    digest.copy_from_slice(&Sha1::digest(message.as_slice()));
    let mut first = Zeroizing::new([0u8; 16]);
    first.copy_from_slice(&digest[..16]);
    let cipher = Aes128::new_from_slice(&[
        0x75, 0x8f, 0xa5, 0x2a, 0xe1, 0xb0, 0x73, 0x0b, 0x84, 0x47, 0x87, 0x57, 0xf0, 0x23, 0xcd,
        0x38,
    ])
    .expect("fixed class algorithm key");
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut *first));
    let mut second = Zeroizing::new([0u8; 8]);
    for pass in 0..2 {
        let word = u16::from_be_bytes(digest[16 + pass * 2..18 + pass * 2].try_into().unwrap());
        second[pass * 4..pass * 4 + 4].copy_from_slice(&workspace(word)?.to_be_bytes());
    }
    let mut key = Zeroizing::new([0u8; 16]);
    for i in 0..8 {
        let mut value = 0;
        for j in 0..8 {
            value ^= multiply(first[(i + j) % 8], second[j]);
        }
        key[i] = value;
        key[i + 8] = value;
    }
    Ok(key)
}
