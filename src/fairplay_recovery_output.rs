//! Publish a recovered AES encoding model in the original private JSON format.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::fairplay_recovery::Recovery;
use crate::fairplay_recovery_math::Encoding;

struct EncodingRows<'a>(&'a Encoding);

/// Read a caller's private 16-byte SIDB frame without following a final symlink.
pub fn read_private_frame(path: &Path) -> Result<Zeroizing<[u8; 16]>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open private enrollment frame {}", path.display()))?;
    let metadata = file.metadata().context("inspect opened enrollment frame")?;
    if !metadata.file_type().is_file() || metadata.len() != 16 {
        bail!("enrollment frame must be a 16-byte regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("enrollment frame must be mode 0600 or stricter");
        }
    }
    let mut frame = Zeroizing::new([0u8; 16]);
    file.read_exact(&mut *frame)
        .context("read private enrollment frame")?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        bail!("enrollment frame changed while reading");
    }
    Ok(frame)
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

/// Atomically publish a new 0600 file; never replace an existing recovery.
pub fn write_private_model(path: &Path, recovery: &Recovery) -> Result<()> {
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
    write_model_json(recovery, temporary.as_file_mut())?;
    temporary.as_file_mut().sync_all()?;
    fs::hard_link(temporary.path(), path)
        .with_context(|| format!("publish new recovered model {}", path.display()))?;
    Ok(())
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
}
