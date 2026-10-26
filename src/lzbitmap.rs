//! Bounded decoder for Apple's `ZBM\x09` LZBITMAP block stream.

use anyhow::{Result, bail};

const MAGIC: &[u8; 4] = b"ZBM\x09";
const MAX_CHUNK: usize = 0x8000;

#[derive(Clone, Copy, Default)]
struct Bitmap {
    bits: u8,
    period_bytes: u8,
}

struct ChunkDecoder<'a> {
    input: &'a [u8],
    end: usize,
    output: &'a mut Vec<u8>,
    remaining: usize,
    data: usize,
    meta1: usize,
    meta2: usize,
    meta3: usize,
    high_nibble: bool,
    period: usize,
    bitmaps: [Bitmap; 12],
}

pub fn decompress(input: &[u8], maximum_size: usize) -> Result<Vec<u8>> {
    if !input.starts_with(MAGIC) {
        bail!("invalid LZBITMAP magic");
    }
    let mut output = Vec::new();
    let mut pos = MAGIC.len();
    loop {
        let header = input
            .get(pos..pos + 6)
            .ok_or_else(|| anyhow::anyhow!("truncated LZBITMAP chunk header"))?;
        let length = u24(header);
        let decoded_size = u24(&header[3..]);
        let end = pos
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("LZBITMAP chunk offset overflow"))?;
        if length < 6 || end > input.len() || decoded_size > MAX_CHUNK {
            bail!("invalid LZBITMAP chunk size");
        }
        if output
            .len()
            .checked_add(decoded_size)
            .is_none_or(|size| size > maximum_size)
        {
            bail!("LZBITMAP output exceeds expected size");
        }
        if length == decoded_size + 6 {
            output.extend_from_slice(&input[pos + 6..end]);
        } else {
            decode_compressed_chunk(input, pos, end, decoded_size, &mut output)?;
        }
        pos = end;
        if decoded_size == 0 {
            return Ok(output);
        }
    }
}

fn decode_compressed_chunk(
    input: &[u8],
    pos: usize,
    end: usize,
    decoded_size: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
    let length = end - pos;
    if length < 32 {
        bail!("LZBITMAP compressed chunk is too short");
    }
    let offsets = [
        u24(&input[pos + 6..]),
        u24(&input[pos + 9..]),
        u24(&input[pos + 12..]),
    ];
    if offsets.iter().any(|offset| *offset >= length) {
        bail!("LZBITMAP metadata offset exceeds chunk");
    }
    let mut decoder = ChunkDecoder {
        input,
        end,
        output,
        remaining: decoded_size,
        data: pos + 15,
        meta1: pos + offsets[0],
        meta2: pos + offsets[1],
        meta3: pos + offsets[2],
        high_nibble: false,
        period: 8,
        bitmaps: [Bitmap::default(); 12],
    };
    decoder.read_bitmaps()?;
    while decoder.remaining > 0 {
        let number = decoder.read_nibble()?;
        let repeat = decoder.repetition_count()?;
        for _ in 0..repeat {
            decoder.apply_number(number)?;
        }
    }
    Ok(())
}

impl ChunkDecoder<'_> {
    fn read_bitmaps(&mut self) -> Result<()> {
        let mut at = self.end - 17;
        let mut bit = 0;
        for bitmap in &mut self.bitmaps {
            let mut bits = 0u8;
            let mut period_bytes = 0u8;
            for index in 0..10 {
                let byte = *self
                    .input
                    .get(at)
                    .ok_or_else(|| anyhow::anyhow!("truncated LZBITMAP bitmap table"))?;
                let value = (byte >> bit) & 1;
                if index < 8 {
                    bits |= value << index;
                } else {
                    period_bytes |= value << (index - 8);
                }
                bit += 1;
                if bit == 8 {
                    bit = 0;
                    at += 1;
                }
            }
            if period_bytes > 2 {
                bail!("invalid LZBITMAP repetition period width");
            }
            *bitmap = Bitmap { bits, period_bytes };
        }
        Ok(())
    }

    fn read_nibble(&mut self) -> Result<u8> {
        let byte = *self
            .input
            .get(self.meta3)
            .filter(|_| self.meta3 < self.end)
            .ok_or_else(|| anyhow::anyhow!("truncated LZBITMAP bitmap numbers"))?;
        if self.high_nibble {
            self.high_nibble = false;
            self.meta3 += 1;
            Ok(byte >> 4)
        } else {
            self.high_nibble = true;
            Ok(byte & 15)
        }
    }

    fn rewind_nibble(&mut self) {
        if self.high_nibble {
            self.high_nibble = false;
        } else {
            self.high_nibble = true;
            self.meta3 -= 1;
        }
    }

    fn repetition_count(&mut self) -> Result<usize> {
        if self.remaining <= 8 {
            return Ok(1);
        }
        let mut nibble = self.read_nibble()?;
        if nibble != 15 {
            self.rewind_nibble();
            return Ok(1);
        }
        let mut count = 4usize;
        while nibble == 15 {
            nibble = self.read_nibble()?;
            count += nibble as usize;
            if count > MAX_CHUNK {
                bail!("LZBITMAP repetition count is too large");
            }
        }
        Ok(count)
    }

    fn apply_number(&mut self, number: u8) -> Result<()> {
        if number == 15 {
            bail!("invalid LZBITMAP bitmap number");
        }
        let bitmap = if number <= 2 {
            let bits = *self
                .input
                .get(self.meta2)
                .filter(|_| self.meta2 < self.end)
                .ok_or_else(|| anyhow::anyhow!("truncated LZBITMAP inline bitmap"))?;
            self.meta2 += 1;
            Bitmap {
                bits,
                period_bytes: number,
            }
        } else {
            self.bitmaps[(number - 3) as usize]
        };
        self.apply(bitmap)
    }

    fn apply(&mut self, bitmap: Bitmap) -> Result<()> {
        if bitmap.period_bytes != 0 {
            self.period = 0;
            for index in 0..bitmap.period_bytes as usize {
                let byte = *self
                    .input
                    .get(self.meta1)
                    .filter(|_| self.meta1 < self.end)
                    .ok_or_else(|| anyhow::anyhow!("truncated LZBITMAP repetition period"))?;
                self.period |= (byte as usize) << (8 * index);
                self.meta1 += 1;
            }
        }
        if self.period == 0 {
            bail!("zero LZBITMAP repetition period");
        }
        for bit in 0..8 {
            if self.remaining == 0 {
                break;
            }
            let byte = if bitmap.bits & (1 << bit) != 0 {
                let byte = *self
                    .input
                    .get(self.data)
                    .filter(|_| self.data < self.end)
                    .ok_or_else(|| anyhow::anyhow!("truncated LZBITMAP literals"))?;
                self.data += 1;
                byte
            } else {
                let at = self
                    .output
                    .len()
                    .checked_sub(self.period)
                    .ok_or_else(|| anyhow::anyhow!("LZBITMAP period precedes output"))?;
                self.output[at]
            };
            self.output.push(byte);
            self.remaining -= 1;
        }
        Ok(())
    }
}

fn u24(bytes: &[u8]) -> usize {
    bytes[0] as usize | (bytes[1] as usize) << 8 | (bytes[2] as usize) << 16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_plain_chunk_and_rejects_invalid_lengths() {
        let stream = b"ZBM\x09\x0b\0\0\x05\0\0hello\x06\0\0\0\0\0";
        assert_eq!(decompress(stream, 5).unwrap(), b"hello");
        assert!(decompress(stream, 4).is_err());
        assert!(decompress(&stream[..stream.len() - 1], 5).is_err());
    }

    #[test]
    fn decodes_compressed_go_vector() {
        let hex = "5a424d092b0000000100170000170000170000616263616263616234ff0c00fc030000000000000000000000000000060000000000";
        let encoded = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let expected = b"abcabcab".repeat(32);
        assert_eq!(decompress(&encoded, expected.len()).unwrap(), expected);
        let mut corrupted = encoded;
        corrupted[12] = 0xff;
        assert!(decompress(&corrupted, expected.len()).is_err());
    }
}
