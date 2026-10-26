//! Publish a recovered AES encoding model in the original private JSON format.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeSeq};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use crate::fairplay_recovery::Recovery;
use crate::fairplay_recovery_math::Encoding;

struct EncodingRows<'a>(&'a Encoding);

fn open_private_file(path: &Path, size: Option<u64>, limit: u64) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open private recovery input {}", path.display()))?;
    let metadata = file.metadata().context("inspect private recovery input")?;
    if !metadata.file_type().is_file()
        || metadata.len() > limit
        || size.is_some_and(|expected| metadata.len() != expected)
    {
        bail!("private recovery input has an invalid file type or size");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("private recovery input must be mode 0600 or stricter");
        }
    }
    Ok(file)
}

/// Read a caller's exact-sized private binary input without following a final symlink.
pub fn read_private_block<const N: usize>(path: &Path) -> Result<Zeroizing<[u8; N]>> {
    let mut file = open_private_file(path, Some(N as u64), N as u64)?;
    let mut block = Zeroizing::new([0u8; N]);
    file.read_exact(&mut *block)
        .context("read private recovery input")?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        bail!("private recovery input changed while reading");
    }
    Ok(block)
}

/// Read a caller's private 16-byte SIDB frame without following a final symlink.
pub fn read_private_frame(path: &Path) -> Result<Zeroizing<[u8; 16]>> {
    read_private_block(path)
}

/// Read a bounded private input whose exact size is selected by the caller.
pub fn read_private_bytes(path: &Path, max_size: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = open_private_file(path, None, max_size as u64)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max_size as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read private recovery input")?;
    if bytes.len() > max_size {
        bail!("private recovery input grew beyond its size limit");
    }
    Ok(bytes)
}

impl Serialize for EncodingRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(16))?;
        for row in &self.0.0 {
            rows.serialize_element(&row[..])?;
        }
        rows.end()
    }
}

#[derive(Serialize)]
struct ModelJson<'a> {
    schema: &'static str,
    key_hex: &'a str,
    input_encoding: EncodingRows<'a>,
    output_encoding: EncodingRows<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelJsonRead {
    schema: String,
    key_hex: String,
    input_encoding: Vec<Vec<u8>>,
    output_encoding: Vec<Vec<u8>>,
}

impl Drop for ModelJsonRead {
    fn drop(&mut self) {
        self.key_hex.zeroize();
        for table in &mut self.input_encoding {
            table.zeroize();
        }
        for table in &mut self.output_encoding {
            table.zeroize();
        }
    }
}

fn parse_encoding(tables: &[Vec<u8>]) -> Result<Encoding> {
    if tables.len() != 16 || tables.iter().any(|row| row.len() != 256) {
        bail!("recovered external encoding has invalid geometry");
    }
    let mut encoding = Encoding([[0; 256]; 16]);
    for (index, table) in tables.iter().enumerate() {
        encoding.0[index].copy_from_slice(table);
    }
    encoding.check_permutation()?;
    Ok(encoding)
}

/// Load the private JSON emitted by `write_private_model` or the original Go tool.
pub fn read_private_model(path: &Path) -> Result<Recovery> {
    const MAX_MODEL_BYTES: u64 = 256 * 1024;
    let file = open_private_file(path, None, MAX_MODEL_BYTES)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_MODEL_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read private recovered model")?;
    if bytes.len() as u64 > MAX_MODEL_BYTES {
        bail!("private recovered model grew beyond the size limit");
    }
    let model: ModelJsonRead =
        serde_json::from_slice(&bytes).context("parse private recovered model")?;
    if model.schema != "darkphoenix.external-encoding-model.v1" || model.key_hex.len() != 32 {
        bail!("unsupported recovered FairPlay model");
    }
    let mut key = [0u8; 16];
    for (index, byte) in key.iter_mut().enumerate() {
        let digits = model
            .key_hex
            .get(index * 2..index * 2 + 2)
            .context("invalid recovered AES key")?;
        *byte = u8::from_str_radix(digits, 16).context("invalid recovered AES key")?;
    }
    let recovered = Recovery {
        key,
        input_encoding: parse_encoding(&model.input_encoding)?,
        output_encoding: parse_encoding(&model.output_encoding)?,
        milliseconds: 0.0,
    };
    Ok(recovered)
}

pub fn write_model_json(recovery: &Recovery, mut output: impl Write) -> Result<()> {
    let key_hex = Zeroizing::new(
        recovery
            .key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let model = ModelJson {
        schema: "darkphoenix.external-encoding-model.v1",
        key_hex: &key_hex,
        input_encoding: EncodingRows(&recovery.input_encoding),
        output_encoding: EncodingRows(&recovery.output_encoding),
    };
    serde_json::to_writer_pretty(&mut output, &model)
        .context("serialize recovered FairPlay model")?;
    output
        .write_all(b"\n")
        .context("finish recovered FairPlay model")?;
    Ok(())
}

fn write_private_output(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<()>,
) -> Result<()> {
    let parent = path.parent().context("recovery path has no parent")?;
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect recovery directory {}", parent.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("recovery parent must be a directory, not a symlink");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("recovery directory must be mode 0700 or stricter");
        }
    }
    let mut temporary =
        NamedTempFile::new_in(parent).context("create private recovery temporary file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    write(temporary.as_file_mut())?;
    temporary.as_file_mut().sync_all()?;
    fs::hard_link(temporary.path(), path)
        .with_context(|| format!("publish new recovered model {}", path.display()))?;
    Ok(())
}

/// Atomically publish a new 0600 file; never replace an existing recovery.
pub fn write_private_model(path: &Path, recovery: &Recovery) -> Result<()> {
    write_private_output(path, |file| write_model_json(recovery, file))
}

/// Atomically publish a new private binary model without replacing a prior one.
pub fn write_private_binary(path: &Path, bytes: &[u8]) -> Result<()> {
    write_private_output(path, |file| {
        file.write_all(bytes)
            .context("write private enrollment model")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fairplay_recovery_math::Encoding;

    #[test]
    fn reads_only_private_exact_sized_frame() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("frame.bin");
        fs::write(&path, [0x5a; 16]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(*read_private_frame(&path).unwrap(), [0x5a; 16]);
        fs::write(&path, [0x5a; 17]).unwrap();
        assert!(read_private_frame(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(&path, [0x5a; 16]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_private_frame(&path).is_err());
            let link = root.path().join("frame-link.bin");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_private_frame(&link).is_err());
        }
    }

    #[test]
    fn publishes_go_compatible_private_model_without_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private");
        fs::create_dir(&private).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let model = Recovery {
            key: core::array::from_fn(|index| index as u8),
            input_encoding: Encoding::identity(),
            output_encoding: Encoding::identity(),
            milliseconds: 1.0,
        };
        let path = private.join("recovered-whitebox-model.json");
        write_private_model(&path, &model).unwrap();
        let original = fs::read(&path).unwrap();
        let parsed = read_private_model(&path).unwrap();
        assert_eq!(parsed.key, model.key);
        assert_eq!(parsed.input_encoding.0, model.input_encoding.0);
        assert_eq!(parsed.output_encoding.0, model.output_encoding.0);
        let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(value["schema"], "darkphoenix.external-encoding-model.v1");
        assert_eq!(value["key_hex"], "000102030405060708090a0b0c0d0e0f");
        assert!(value.get("milliseconds").is_none());
        for name in ["input_encoding", "output_encoding"] {
            let rows = value[name].as_array().unwrap();
            assert_eq!(rows.len(), 16);
            for row in rows {
                let cells = row.as_array().unwrap();
                assert_eq!(cells.len(), 256);
                assert_eq!(cells[0], 0);
                assert_eq!(cells[255], 255);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(write_private_model(&path, &model).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn private_binary_output_is_exact_and_cannot_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private");
        fs::create_dir(&private).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let input = private.join("first-transform.bin");
        let block = [0x5a; 432];
        fs::write(&input, block).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(*read_private_block::<432>(&input).unwrap(), block);
        assert_eq!(&*read_private_bytes(&input, 432).unwrap(), &block);
        assert!(read_private_bytes(&input, 431).is_err());
        let output = private.join("enrollment.bin");
        write_private_binary(&output, &block).unwrap();
        assert_eq!(fs::read(&output).unwrap(), block);
        assert!(write_private_binary(&output, b"replacement").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_private_block::<432>(&input).is_err());
        }
    }
}
