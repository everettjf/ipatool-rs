//! Session directory selection and migration from the legacy Go location.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

pub const CONFIG_DIRECTORY_NAME: &str = ".ipatool";
pub const COOKIE_JAR_FILE_NAME: &str = "cookies";
pub const KEYCHAIN_SERVICE_NAME: &str = "ipatool-auth.service";

/// Resolve the state path without exposing environment access to the migration logic.
pub fn prepare_state_directory(
    home: &Path,
    xdg_state_home: Option<&Path>,
    xdg_data_home: Option<&Path>,
) -> Result<PathBuf> {
    let legacy = home.join(CONFIG_DIRECTORY_NAME);
    let preferred = [xdg_state_home, xdg_data_home]
        .into_iter()
        .flatten()
        .find(|path| path.is_absolute())
        .map_or_else(|| legacy.clone(), |base| base.join("ipatool"));

    match fs::metadata(&legacy) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                bail!("legacy state path is not a directory: {}", legacy.display());
            }
            if preferred.starts_with(&legacy) || preferred.exists() {
                return Ok(legacy);
            }
            if let Some(parent) = preferred.parent()
                && create_private_directory(parent).is_err()
            {
                return Ok(legacy);
            }
            if fs::rename(&legacy, &preferred).is_err() {
                return Ok(legacy);
            }
            Ok(preferred)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&preferred).with_context(|| {
                format!("failed to create state directory: {}", preferred.display())
            })?;
            Ok(preferred)
        }
        Err(error) => Err(error).context("could not read legacy state directory metadata"),
    }
}

pub fn prepare_state_directory_from_environment() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("home directory is unavailable")?;
    let xdg_state_home = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from);
    let xdg_data_home = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
    prepare_state_directory(&home, xdg_state_home.as_deref(), xdg_data_home.as_deref())
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_legacy_directory_with_session_contents() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let legacy = home.join(CONFIG_DIRECTORY_NAME);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join(COOKIE_JAR_FILE_NAME), b"session").unwrap();
        let state_home = root.path().join("state");
        let new_path = prepare_state_directory(&home, Some(&state_home), None).unwrap();
        assert_eq!(new_path, state_home.join("ipatool"));
        assert_eq!(
            fs::read(new_path.join(COOKIE_JAR_FILE_NAME)).unwrap(),
            b"session"
        );
        assert!(!legacy.exists());
    }

    #[test]
    fn keeps_legacy_when_destination_already_exists() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let legacy = home.join(CONFIG_DIRECTORY_NAME);
        let state_home = root.path().join("state");
        fs::create_dir_all(&legacy).unwrap();
        fs::create_dir_all(state_home.join("ipatool")).unwrap();
        assert_eq!(
            prepare_state_directory(&home, Some(&state_home), None).unwrap(),
            legacy
        );
    }

    #[test]
    fn ignores_relative_xdg_paths_and_rejects_legacy_files() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let legacy = home.join(CONFIG_DIRECTORY_NAME);
        assert_eq!(
            prepare_state_directory(&home, Some(Path::new("relative")), None).unwrap(),
            legacy
        );
        fs::remove_dir(&legacy).unwrap();
        fs::write(&legacy, b"file").unwrap();
        assert!(prepare_state_directory(&home, None, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn new_state_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let path = prepare_state_directory(&home, None, None).unwrap();
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
