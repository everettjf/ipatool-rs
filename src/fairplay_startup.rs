//! Seed a private request-502 checkpoint from a packaged fairplayd startup overlay.

use std::{collections::BTreeMap, io::Read, path::Path};

use anyhow::{Context, Result, bail};
use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
use serde::Deserialize;
use serde_pickle::{HashableValue, SerOptions, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    capture::{FAIRPLAY_BUILD_26A428_HASH, FAIRPLAY_BUILD_26B118_HASH},
    fairplay_checkpoint_run::load_fairplayd,
    fairplay_recovery_output::{read_private_bytes, write_private_binary},
    store_memory::MemoryRegion,
    unicorn_runtime::Engine,
};

const PROFILE_SCHEMA: &str = "ipatool-fairplay-startup-cache-v1";
const MAX_PROFILE_BYTES: usize = 64 * 1024 * 1024;
const PAGE_BYTES: usize = 4096;
const MAX_PAGES: usize = 30_000;
const SYNTHETIC_SP: u64 = 0x7000_0010_0000;
const SYNTHETIC_PATH: u64 = 0x7000_0020_0000;
const SYNTHETIC_AUDIT: u64 = 0x7000_0021_0000;
const SYNTHETIC_OUT_136: u64 = 0x7000_0022_0000;
const SYNTHETIC_OUT_172: u64 = 0x7000_0023_0000;
const SYNTHETIC_ALLOC_BASE: u64 = 0x7000_1000_0000;

#[derive(Deserialize)]
struct StartupProfile {
    schema: String,
    binary_sha256: String,
    memory: Vec<(String, u8)>,
    once_tokens: Vec<String>,
}

fn address(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .context("address is not hexadecimal")?;
    Ok(u64::from_str_radix(digits, 16)?)
}

fn put_byte(
    pages: &mut BTreeMap<u64, Vec<u8>>,
    address: u64,
    byte: u8,
    image: Option<(&Engine, &[MemoryRegion])>,
) -> Result<()> {
    if address >= 0xf000_0000_0000_0000 {
        bail!("startup memory address is outside the guest range");
    }
    let page = address & !((PAGE_BYTES as u64) - 1);
    if !pages.contains_key(&page) && pages.len() >= MAX_PAGES {
        bail!("startup profile exceeds checkpoint page limit");
    }
    if let std::collections::btree_map::Entry::Vacant(entry) = pages.entry(page) {
        let original = if let Some((engine, regions)) = image {
            if regions.iter().any(|region| {
                region.address <= page
                    && region.address.checked_add(region.size).is_some_and(|end| {
                        page.checked_add(PAGE_BYTES as u64)
                            .is_some_and(|next| next <= end)
                    })
            }) {
                engine.mem_read(page, PAGE_BYTES)?
            } else {
                vec![0; PAGE_BYTES]
            }
        } else {
            vec![0; PAGE_BYTES]
        };
        entry.insert(original);
    }
    pages.get_mut(&page).expect("inserted page")[(address - page) as usize] = byte;
    Ok(())
}

fn put_bytes(
    pages: &mut BTreeMap<u64, Vec<u8>>,
    address: u64,
    data: &[u8],
    image: Option<(&Engine, &[MemoryRegion])>,
) -> Result<()> {
    for (offset, byte) in data.iter().copied().enumerate() {
        put_byte(
            pages,
            address
                .checked_add(offset as u64)
                .context("startup address overflow")?,
            byte,
            image,
        )?;
    }
    Ok(())
}

fn field(name: &str, value: Value) -> (HashableValue, Value) {
    (HashableValue::String(name.into()), value)
}

fn setup_address(hash: &str) -> Result<u64> {
    match hash {
        FAIRPLAY_BUILD_26A428_HASH => Ok(0x1003_40a34),
        FAIRPLAY_BUILD_26B118_HASH => Ok(0x1004_22d48),
        _ => bail!("startup profile has an unsupported fairplayd build"),
    }
}

/// Create a private schema-2 checkpoint at the request-502 entry point.
/// The caller can pass it to `continue-checkpoint` with the captured files.
pub fn seed_request_checkpoint(
    startup_profile: &Path,
    fairplayd: &Path,
    executable_path: &str,
    output: &Path,
) -> Result<usize> {
    if executable_path.is_empty() || executable_path.as_bytes().contains(&0) {
        bail!("executable path must be nonempty and contain no NUL byte");
    }
    if executable_path.len() > 16 * 1024 {
        bail!("executable path exceeds FairPlay request limit");
    }
    let binary = read_private_bytes(fairplayd, 256 * 1024 * 1024)?;
    let binary_hash = format!("{:x}", Sha256::digest(&*binary));
    let mut profile_file =
        std::fs::File::open(startup_profile).context("open FairPlay startup profile")?;
    let mut profile_compressed = Zeroizing::new(Vec::new());
    Read::by_ref(&mut profile_file)
        .take(MAX_PROFILE_BYTES as u64 + 1)
        .read_to_end(&mut profile_compressed)?;
    if profile_compressed.len() > MAX_PROFILE_BYTES {
        bail!("compressed FairPlay startup profile exceeds size limit");
    }
    let mut profile_json = Zeroizing::new(Vec::new());
    MultiGzDecoder::new(profile_compressed.as_slice())
        .take(MAX_PROFILE_BYTES as u64 + 1)
        .read_to_end(&mut profile_json)
        .context("decompress FairPlay startup profile")?;
    if profile_json.len() > MAX_PROFILE_BYTES {
        bail!("FairPlay startup profile exceeds size limit");
    }
    let profile: StartupProfile =
        serde_json::from_slice(&profile_json).context("parse FairPlay startup profile")?;
    let mut engine = Engine::new().context("create FairPlay startup emulator")?;
    let loaded = load_fairplayd(&mut engine, &binary)?;
    let (compressed, plain_bytes) = encode_request_checkpoint(
        profile,
        &binary_hash,
        fairplayd,
        executable_path,
        Some((&engine, &loaded.regions)),
    )?;
    write_private_binary(output, &compressed)?;
    Ok(plain_bytes)
}

fn encode_request_checkpoint(
    profile: StartupProfile,
    binary_hash: &str,
    fairplayd: &Path,
    executable_path: &str,
    image: Option<(&Engine, &[MemoryRegion])>,
) -> Result<(Zeroizing<Vec<u8>>, usize)> {
    if profile.schema != PROFILE_SCHEMA || profile.binary_sha256 != binary_hash {
        bail!("startup profile does not match captured fairplayd");
    }
    let pc = setup_address(binary_hash)?;
    let mut pages = BTreeMap::<u64, Vec<u8>>::new();
    let mut previous = None;
    for (text, byte) in profile.memory {
        let location = address(&text)?;
        if previous.is_some_and(|value| location <= value) {
            bail!("startup profile memory addresses are not strictly increasing");
        }
        previous = Some(location);
        put_byte(&mut pages, location, byte, image)?;
    }
    let mut path = Zeroizing::new(executable_path.as_bytes().to_vec());
    path.push(0);
    put_bytes(&mut pages, SYNTHETIC_PATH, &path, image)?;
    put_bytes(&mut pages, SYNTHETIC_AUDIT, &[0; 32], image)?;
    for (index, value) in [
        SYNTHETIC_OUT_172,
        0x7000_0024_0000,
        0x7000_0025_0000,
        0x7000_0026_0000,
        0x7000_0027_0000,
    ]
    .into_iter()
    .enumerate()
    {
        put_bytes(
            &mut pages,
            SYNTHETIC_SP + (index as u64) * 8,
            &value.to_le_bytes(),
            image,
        )?;
    }
    let mut registers = BTreeMap::new();
    for index in 0..31 {
        let value = match index {
            0 => 0x123,
            1 => SYNTHETIC_PATH,
            2 => path.len() as u64,
            3 => 0x0100_000c,
            6 => SYNTHETIC_AUDIT,
            7 => SYNTHETIC_OUT_136,
            _ => 0,
        };
        let (key, value) = field(&format!("x{index}"), Value::Int(value.into()));
        registers.insert(key, value);
    }
    let (key, value) = field("sp", Value::Int(SYNTHETIC_SP.into()));
    registers.insert(key, value);
    for index in 0..32 {
        let (key, value) = field(&format!("v{index}"), Value::I64(0));
        registers.insert(key, value);
    }
    let nzcv = ["n", "z", "c", "v"]
        .into_iter()
        .map(|name| field(name, Value::I64(0)))
        .collect();
    let once_tokens = profile
        .once_tokens
        .into_iter()
        .map(|token| address(&token).map(|value| Value::Int(value.into())))
        .collect::<Result<Vec<_>>>()?;
    if once_tokens.len() > 65_536 {
        bail!("startup profile has too many once tokens");
    }
    let memory_pages = pages
        .into_iter()
        .map(|(location, bytes)| (HashableValue::Int(location.into()), Value::Bytes(bytes)))
        .collect();
    let canonical_binary = std::fs::canonicalize(fairplayd).context("resolve fairplayd path")?;
    let root = Value::Dict(
        [
            field("schema", Value::I64(2)),
            field(
                "binary",
                Value::String(canonical_binary.to_string_lossy().into_owned()),
            ),
            field("binary_sha256", Value::String(binary_hash.into())),
            field("pc", Value::String(format!("{pc:#x}"))),
            field("registers", Value::Dict(registers)),
            field("nzcv", Value::Dict(nzcv)),
            field("memory_pages", Value::Dict(memory_pages)),
            field("once_tokens", Value::List(once_tokens)),
            field("next_allocation", Value::Int(SYNTHETIC_ALLOC_BASE.into())),
            field("next_fd", Value::I64(10)),
            field("random_state", Value::I64(0x1234_5678)),
        ]
        .into(),
    );
    let serialized = Zeroizing::new(serde_pickle::value_to_vec(&root, SerOptions::new())?);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    use std::io::Write;
    encoder.write_all(&serialized)?;
    let compressed = Zeroizing::new(encoder.finish()?);
    Ok((compressed, serialized.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_checkpoint::FairplayCheckpoint;

    #[test]
    fn seed_matches_request_502_register_and_memory_contract() {
        let temporary = tempfile::tempdir().unwrap();
        let binary = temporary.path().join("fairplayd");
        std::fs::write(&binary, b"fixture").unwrap();
        let profile = StartupProfile {
            schema: PROFILE_SCHEMA.into(),
            binary_sha256: FAIRPLAY_BUILD_26B118_HASH.into(),
            memory: vec![("0x1010b5d40".into(), 0x8d), ("0x1010b5d41".into(), 0xae)],
            once_tokens: vec!["0x1010b70c8".into()],
        };
        let (encoded, plain_bytes) = encode_request_checkpoint(
            profile,
            FAIRPLAY_BUILD_26B118_HASH,
            &binary,
            "/Applications/Test.app/Test",
            None,
        )
        .unwrap();
        assert!(plain_bytes > 0);
        let checkpoint = FairplayCheckpoint::parse_gzip(&encoded).unwrap();
        assert_eq!(checkpoint.pc().unwrap(), 0x1004_22d48);
        assert_eq!(checkpoint.register_u64("x0").unwrap(), 0x123);
        assert_eq!(checkpoint.register_u64("x1").unwrap(), SYNTHETIC_PATH);
        assert_eq!(checkpoint.register_u64("x2").unwrap(), 28);
        assert_eq!(checkpoint.register_u64("x3").unwrap(), 0x0100_000c);
        assert_eq!(checkpoint.register_u64("x6").unwrap(), SYNTHETIC_AUDIT);
        assert_eq!(checkpoint.register_u64("x7").unwrap(), SYNTHETIC_OUT_136);
        assert_eq!(checkpoint.register_u64("sp").unwrap(), SYNTHETIC_SP);
        assert_eq!(
            *checkpoint.read_block::<2>(0x1010_b5d40).unwrap(),
            [0x8d, 0xae]
        );
        assert_eq!(
            *checkpoint.read_block::<8>(SYNTHETIC_SP).unwrap(),
            SYNTHETIC_OUT_172.to_le_bytes()
        );
        assert_eq!(
            *checkpoint.read_block::<28>(SYNTHETIC_PATH).unwrap(),
            *b"/Applications/Test.app/Test\0"
        );
    }

    #[test]
    fn rejects_profile_hash_mismatch_and_duplicate_memory() {
        let temporary = tempfile::tempdir().unwrap();
        let binary = temporary.path().join("fairplayd");
        std::fs::write(&binary, b"fixture").unwrap();
        let profile = StartupProfile {
            schema: PROFILE_SCHEMA.into(),
            binary_sha256: FAIRPLAY_BUILD_26A428_HASH.into(),
            memory: vec![],
            once_tokens: vec![],
        };
        assert!(
            encode_request_checkpoint(profile, FAIRPLAY_BUILD_26B118_HASH, &binary, "test", None)
                .is_err()
        );
        let profile = StartupProfile {
            schema: PROFILE_SCHEMA.into(),
            binary_sha256: FAIRPLAY_BUILD_26A428_HASH.into(),
            memory: vec![("0x100ff0000".into(), 1), ("0x100ff0000".into(), 2)],
            once_tokens: vec![],
        };
        assert!(
            encode_request_checkpoint(profile, FAIRPLAY_BUILD_26A428_HASH, &binary, "test", None)
                .is_err()
        );
    }

    #[test]
    fn startup_overlay_preserves_unmodified_macho_page_bytes() {
        const BINARY: &[u8] =
            include_bytes!("../tests/fixtures/fairplay-checkpoint-run-synthetic.macho");
        let temporary = tempfile::tempdir().unwrap();
        let binary = temporary.path().join("fairplayd");
        std::fs::write(&binary, BINARY).unwrap();
        let mut engine = Engine::new().unwrap();
        let loaded = load_fairplayd(&mut engine, BINARY).unwrap();
        let page = loaded.regions[0].address;
        let original = engine.mem_read(page, PAGE_BYTES).unwrap();
        let changed = original[8] ^ 0xff;
        let profile = StartupProfile {
            schema: PROFILE_SCHEMA.into(),
            binary_sha256: FAIRPLAY_BUILD_26B118_HASH.into(),
            memory: vec![(format!("{:#x}", page + 8), changed)],
            once_tokens: vec![],
        };
        let (encoded, _) = encode_request_checkpoint(
            profile,
            FAIRPLAY_BUILD_26B118_HASH,
            &binary,
            "Test",
            Some((&engine, &loaded.regions)),
        )
        .unwrap();
        let checkpoint = FairplayCheckpoint::parse_gzip(&encoded).unwrap();
        let mut expected = original[..16].to_vec();
        expected[8] = changed;
        assert_eq!(
            checkpoint.read_block::<16>(page).unwrap().as_slice(),
            expected
        );
    }
}
