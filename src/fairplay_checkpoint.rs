//! Read the page-packed Python checkpoints used by the 26B118 recovery path.

use std::{io::Read, path::Path};

use anyhow::{Context, Result, bail};
use flate2::read::MultiGzDecoder;
use serde_pickle::{DeOptions, HashableValue, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::fairplay_recovery_output::read_private_bytes;

const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
const MAX_PLAIN_BYTES: u64 = 128 * 1024 * 1024;
const PAGE_BYTES: usize = 4096;

pub struct FairplayCheckpoint {
    pub binary_hash: [u8; 32],
    root: Value,
}

impl Drop for FairplayCheckpoint {
    fn drop(&mut self) {
        self.binary_hash.zeroize();
        clear_value(&mut self.root);
    }
}

impl FairplayCheckpoint {
    pub fn load_private(path: &Path) -> Result<Self> {
        let compressed = read_private_bytes(path, MAX_COMPRESSED_BYTES)?;
        Self::parse_gzip(&compressed)
    }

    pub fn parse_gzip(compressed: &[u8]) -> Result<Self> {
        if compressed.len() > MAX_COMPRESSED_BYTES {
            bail!("FairPlay checkpoint exceeds compressed size limit");
        }
        let mut plain = Zeroizing::new(Vec::new());
        MultiGzDecoder::new(compressed)
            .take(MAX_PLAIN_BYTES + 1)
            .read_to_end(&mut plain)
            .context("decompress FairPlay checkpoint")?;
        if plain.len() as u64 > MAX_PLAIN_BYTES {
            bail!("FairPlay checkpoint exceeds decompressed size limit");
        }
        let root = serde_pickle::value_from_slice(
            &plain,
            DeOptions::new()
                .replace_unresolved_globals()
                .replace_recursive_structures(),
        )
        .context("decode FairPlay checkpoint pickle")?;
        let mut checkpoint = Self {
            binary_hash: [0; 32],
            root,
        };
        if value_u64(checkpoint.field("schema")?)? != 2 {
            bail!("only page-packed FairPlay checkpoint schema 2 is supported");
        }
        let hash = match checkpoint.field("binary_sha256")? {
            Value::String(hash) => hash,
            _ => bail!("checkpoint binary SHA-256 is missing"),
        };
        if hash.len() != 64 {
            bail!("checkpoint binary SHA-256 has invalid length");
        }
        let mut decoded = [0u8; 32];
        for (index, byte) in decoded.iter_mut().enumerate() {
            let digits = hash
                .get(index * 2..index * 2 + 2)
                .context("checkpoint binary SHA-256 contains invalid UTF-8 boundaries")?;
            *byte = u8::from_str_radix(digits, 16)
                .context("checkpoint binary SHA-256 is not hexadecimal")?;
        }
        checkpoint.binary_hash = decoded;
        if !matches!(checkpoint.field("memory_pages")?, Value::Dict(_)) {
            bail!("checkpoint has no page-packed memory map");
        }
        Ok(checkpoint)
    }

    pub fn register_u64(&self, name: &str) -> Result<u64> {
        let registers = match self.field("registers")? {
            Value::Dict(registers) => registers,
            _ => bail!("checkpoint has no register map"),
        };
        let value = registers
            .get(&HashableValue::String(name.into()))
            .with_context(|| format!("checkpoint has no {name} register"))?;
        value_u64(value)
    }

    pub fn read_block<const N: usize>(&self, address: u64) -> Result<Zeroizing<[u8; N]>> {
        if N == 0 || N > 1024 * 1024 {
            bail!("checkpoint block size is outside the bounded range");
        }
        let pages = match self.field("memory_pages")? {
            Value::Dict(pages) => pages,
            _ => bail!("checkpoint has no page-packed memory map"),
        };
        let mut output = Zeroizing::new([0u8; N]);
        let mut written = 0;
        while written < N {
            let cursor = address
                .checked_add(written as u64)
                .context("checkpoint address overflow")?;
            let page_address = cursor & !(PAGE_BYTES as u64 - 1);
            let page = pages
                .get(&HashableValue::I64(i64::try_from(page_address)?))
                .with_context(|| format!("checkpoint does not cover page {page_address:#x}"))?;
            let data = match page {
                Value::Bytes(data) if data.len() == PAGE_BYTES => data,
                _ => bail!("checkpoint page has invalid payload geometry"),
            };
            let offset = (cursor - page_address) as usize;
            let count = (PAGE_BYTES - offset).min(N - written);
            output[written..written + count].copy_from_slice(&data[offset..offset + count]);
            written += count;
        }
        Ok(output)
    }

    fn field(&self, name: &str) -> Result<&Value> {
        let root = match &self.root {
            Value::Dict(root) => root,
            _ => bail!("checkpoint root is not a dictionary"),
        };
        root.get(&HashableValue::String(name.into()))
            .with_context(|| format!("checkpoint has no {name} field"))
    }
}

fn value_u64(value: &Value) -> Result<u64> {
    match value {
        Value::I64(value) => Ok(u64::try_from(*value)?),
        Value::Int(value) => Ok(value.to_string().parse()?),
        Value::String(value) => {
            if let Some(hex) = value.strip_prefix("0x") {
                Ok(u64::from_str_radix(hex, 16)?)
            } else {
                Ok(value.parse()?)
            }
        }
        _ => bail!("checkpoint numeric field has invalid type"),
    }
}

fn clear_value(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::String(text) => text.zeroize(),
        Value::List(values) | Value::Tuple(values) => {
            for item in values {
                clear_value(item);
            }
        }
        Value::Dict(values) => {
            for item in values.values_mut() {
                clear_value(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/fairplay-checkpoint-schema2-synthetic.pkl.gz");

    #[test]
    fn reads_python_protocol_five_page_packed_checkpoint_across_boundary() {
        let checkpoint = FairplayCheckpoint::parse_gzip(FIXTURE).unwrap();
        assert_eq!(checkpoint.binary_hash, [0xa5; 32]);
        let address = 0x7100_0001_4ee0;
        assert_eq!(checkpoint.register_u64("x23").unwrap(), address);
        let block = checkpoint.read_block::<432>(address).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(block.as_slice())),
            "5f55150f8d3c2f9d7b0c55b61dee6dc218979918b0dd7512bca1a366fd8aa26f"
        );
        assert!(checkpoint.read_block::<8192>(address).is_err());
    }

    #[test]
    fn requires_private_checkpoint_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("checkpoint.pkl.gz");
        std::fs::write(&path, FIXTURE).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(FairplayCheckpoint::load_private(&path).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(FairplayCheckpoint::load_private(&path).is_err());
        }
    }
}
