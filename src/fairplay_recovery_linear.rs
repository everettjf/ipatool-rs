//! Linear candidates and row associations for FairPlay recovery Step 3.
//!
//! Adapted from the Go DarkPhoenix subset in `ipatool-fairplay` and changed
//! for this Rust port. Attribution is in `licenses/LICENSE-DARKPHOENIX.txt`.

use crate::fairplay_recovery_math::{Mat8, gf_inv, gf_mul};

#[derive(Clone, Copy)]
pub struct MatrixCandidate {
    pub name: &'static str,
    pub matrix: Mat8,
}

pub fn decrypt_candidates() -> [MatrixCandidate; 12] {
    let (m9, m11, m13, m14) = (
        Mat8::multiplication(9),
        Mat8::multiplication(11),
        Mat8::multiplication(13),
        Mat8::multiplication(14),
    );
    let (i9, i11, i13, i14) = (
        m9.inverse().unwrap(),
        m11.inverse().unwrap(),
        m13.inverse().unwrap(),
        m14.inverse().unwrap(),
    );
    [
        MatrixCandidate {
            name: "9*11*13^(-2)",
            matrix: m9.multiply(m11).multiply(i13).multiply(i13),
        },
        MatrixCandidate {
            name: "9*11*14^(-2)",
            matrix: m9.multiply(m11).multiply(i14).multiply(i14),
        },
        MatrixCandidate {
            name: "9*11^(-1)*13*14^(-1)",
            matrix: m9.multiply(i11).multiply(m13).multiply(i14),
        },
        MatrixCandidate {
            name: "9*11^(-1)*13^(-1)*14",
            matrix: m9.multiply(i11).multiply(i13).multiply(m14),
        },
        MatrixCandidate {
            name: "9^(-1)*11*13*14^(-1)",
            matrix: i9.multiply(m11).multiply(m13).multiply(i14),
        },
        MatrixCandidate {
            name: "9^(-1)*11*13^(-1)*14",
            matrix: i9.multiply(m11).multiply(i13).multiply(m14),
        },
        MatrixCandidate {
            name: "9^(-1)*11^(-1)*13^(2)",
            matrix: i9.multiply(i11).multiply(m13).multiply(m13),
        },
        MatrixCandidate {
            name: "9^(-1)*11^(-1)*14^(2)",
            matrix: i9.multiply(i11).multiply(m14).multiply(m14),
        },
        MatrixCandidate {
            name: "9^(-2)*13*14",
            matrix: i9.multiply(i9).multiply(m13).multiply(m14),
        },
        MatrixCandidate {
            name: "9^(2)*13^(-1)*14^(-1)",
            matrix: m9.multiply(m9).multiply(i13).multiply(i14),
        },
        MatrixCandidate {
            name: "11^(-2)*13*14",
            matrix: i11.multiply(i11).multiply(m13).multiply(m14),
        },
        MatrixCandidate {
            name: "11^(2)*13^(-1)*14^(-1)",
            matrix: m11.multiply(m11).multiply(i13).multiply(i14),
        },
    ]
}

pub fn association(name: &str, p0: usize, p1: usize) -> Option<(usize, usize)> {
    let rows = match name {
        "9*11*14^(-2)" => [[0, 1, 0, 1], [1, 0, 1, 0], [2, 3, 2, 3], [3, 2, 3, 2]],
        "9^(-1)*11^(-1)*14^(2)" => [[1, 0, 0, 1], [0, 1, 1, 0], [3, 2, 2, 3], [2, 3, 3, 2]],
        "9*11*13^(-2)" => [[2, 3, 0, 1], [3, 2, 1, 0], [0, 1, 2, 3], [1, 0, 3, 2]],
        "9^(-1)*11^(-1)*13^(2)" => [[3, 2, 0, 1], [2, 3, 1, 0], [1, 0, 2, 3], [0, 1, 3, 2]],
        "9*11^(-1)*13*14^(-1)" => [[0, 1, 0, 2], [3, 2, 0, 2], [1, 0, 2, 0], [2, 3, 2, 0]],
        "9^(-1)*11*13^(-1)*14" => [[1, 0, 0, 2], [2, 3, 0, 2], [0, 1, 2, 0], [3, 2, 2, 0]],
        "9^(2)*13^(-1)*14^(-1)" => [[0, 1, 0, 3], [3, 2, 1, 2], [2, 3, 2, 1], [1, 0, 3, 0]],
        "9^(-2)*13*14" => [[1, 0, 0, 3], [2, 3, 1, 2], [3, 2, 2, 1], [0, 1, 3, 0]],
        "11^(2)*13^(-1)*14^(-1)" => [[2, 3, 0, 3], [1, 0, 1, 2], [0, 1, 2, 1], [3, 2, 3, 0]],
        "11^(-2)*13*14" => [[3, 2, 0, 3], [0, 1, 1, 2], [1, 0, 2, 1], [2, 3, 3, 0]],
        "9*11^(-1)*13^(-1)*14" => [[0, 1, 1, 3], [3, 2, 1, 3], [1, 0, 3, 1], [2, 3, 3, 1]],
        "9^(-1)*11*13*14^(-1)" => [[1, 0, 1, 3], [2, 3, 1, 3], [0, 1, 3, 1], [3, 2, 3, 1]],
        _ => return None,
    };
    rows.into_iter()
        .find(|row| row[0] == p0 && row[1] == p1)
        .map(|row| (row[2], row[3]))
}

pub fn inverse_table(table: [u8; 256]) -> [u8; 256] {
    let mut result = [0; 256];
    for (source, target) in table.into_iter().enumerate() {
        result[target as usize] = source as u8;
    }
    result
}

pub fn c_coefficient(row: usize) -> u8 {
    match row {
        1 => gf_mul(9, gf_inv(14)),
        2 => gf_mul(13, gf_inv(14)),
        _ => gf_mul(11, gf_inv(14)),
    }
}

pub fn c_value(
    g0: &[u8; 256],
    gb: &[u8; 256],
    words: &[[u8; 4]; 256],
    row: usize,
    coefficient: u8,
) -> Option<u8> {
    let mut found = None;
    for fault in 0..256 {
        let ti = gb[(words[0][row] ^ words[fault][row]) as usize];
        let t0 = g0[(words[0][0] ^ words[fault][0]) as usize];
        if ti == 0 {
            continue;
        }
        let value = gf_mul(gf_inv(ti), gf_mul(t0, coefficient));
        if found.is_some_and(|earlier| earlier != value) {
            return None;
        }
        found = Some(value);
    }
    found
}
