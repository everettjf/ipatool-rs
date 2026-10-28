//! Small, versioned desktop preferences containing no account information.

use anyhow::{Context, Result, bail};
use ipatool_rs::{Platform, application::catalog::Mode};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    pub schema: u32,
    pub country: String,
    pub platform: Platform,
    pub mode: Mode,
    pub output_directory: Option<PathBuf>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            schema: 1,
            country: "US".into(),
            platform: Platform::Iphone,
            mode: Mode::Auto,
            output_directory: None,
        }
    }
}

impl Preferences {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            bail!("unsupported preferences schema");
        }
        if self.country.len() != 2 || !self.country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            bail!("country must be a two-letter code");
        }
        if self.platform == Platform::Unknown {
            bail!("choose a supported offer platform");
        }
        if self
            .output_directory
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            bail!("default output directory must be absolute");
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) if !metadata.is_file() || metadata.len() > 64 * 1024 => {
                bail!("preferences file has invalid type or size")
            }
            _ => {}
        }
        let value: Self = serde_json::from_slice(&fs::read(path)?).context("decode preferences")?;
        value.validate()?;
        Ok(value)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let mut file = tempfile::NamedTempFile::new_in(
            path.parent().context("preferences path has no parent")?,
        )?;
        serde_json::to_writer_pretty(&mut file, self)?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        file.persist(path)
            .map_err(|error| error.error)
            .context("publish preferences")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preferences_round_trip_and_reject_invalid_country_and_relative_output() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("preferences.json");
        let mut preferences = Preferences {
            country: "GB".into(),
            platform: Platform::Macos,
            ..Default::default()
        };
        preferences.save(&path).unwrap();
        let loaded = Preferences::load(&path).unwrap();
        assert_eq!(loaded.country, "GB");
        assert_eq!(loaded.platform, Platform::Macos);
        preferences.country = "USA".into();
        assert!(preferences.save(&path).is_err());
        assert_eq!(Preferences::load(&path).unwrap().country, "GB");
        preferences.country = "US".into();
        preferences.output_directory = Some("relative".into());
        assert!(preferences.validate().is_err());
    }
}
