//! Explicit session dependencies shared by application workflows.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;

use crate::credentials::{AccountStore, CredentialStore};

pub type SharedCredentials = Arc<dyn CredentialStore + Send + Sync>;

#[derive(Clone)]
pub struct ApplicationContext {
    pub state_directory: PathBuf,
    pub credentials: SharedCredentials,
}

impl ApplicationContext {
    pub fn new(state_directory: PathBuf, credentials: SharedCredentials) -> Self {
        Self {
            state_directory,
            credentials,
        }
    }

    pub fn legacy() -> Result<Self> {
        Ok(Self::new(
            crate::state::prepare_state_directory_from_environment()?,
            Arc::from(crate::credentials::open_system_keychain()?),
        ))
    }

    pub fn configured(
        directory: &Path,
        allow_ui: bool,
        force_file: bool,
        passphrase: Option<String>,
    ) -> Result<Self> {
        let credentials = crate::credentials::open_configured_keychain(
            directory, allow_ui, force_file, passphrase,
        )?;
        Ok(Self::new(directory.to_path_buf(), Arc::from(credentials)))
    }

    pub fn accounts(&self) -> AccountStore<SharedCredentials> {
        AccountStore::new(Arc::clone(&self.credentials))
    }
}
