//! Linux Secret Service storage compatible with the Go keyring backend.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use secret_service::{EncryptionType, blocking::SecretService};
use zeroize::Zeroizing;

use crate::{
    credentials::CredentialStore, file_keychain::GoKeyringItem, state::KEYCHAIN_SERVICE_NAME,
};

pub(crate) struct LinuxSecretService {
    interactive: bool,
}

impl LinuxSecretService {
    pub(crate) fn probe(interactive: bool) -> Option<Self> {
        let service = SecretService::connect(EncryptionType::Plain).ok()?;
        service.get_all_collections().ok()?;
        Some(Self { interactive })
    }
}

impl CredentialStore for LinuxSecretService {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let service = SecretService::connect(EncryptionType::Plain)
            .context("connect to Linux Secret Service")?;
        let collections = service
            .get_all_collections()
            .context("list Linux Secret Service collections")?;
        let Some(collection) = collections.into_iter().find(|collection| {
            collection
                .get_label()
                .is_ok_and(|label| label == KEYCHAIN_SERVICE_NAME)
        }) else {
            return Ok(None);
        };
        let items = collection
            .search_items(HashMap::from([("profile", key)]))
            .context("find Linux Secret Service item")?;
        let Some(item) = items.into_iter().next() else {
            return Ok(None);
        };
        if item
            .is_locked()
            .context("inspect Linux Secret Service item")?
        {
            if !self.interactive {
                bail!("Linux Secret Service item requires interactive authorization");
            }
            item.unlock().context("unlock Linux Secret Service item")?;
        }
        let secret = Zeroizing::new(
            item.get_secret()
                .context("read Linux Secret Service item")?,
        );
        let stored: GoKeyringItem =
            serde_json::from_slice(&secret).context("decode Linux Secret Service item")?;
        if stored.key != key {
            bail!("Linux Secret Service item key does not match requested key");
        }
        Ok(Some(
            STANDARD
                .decode(&stored.data)
                .context("decode Linux Secret Service item data")?,
        ))
    }

    fn set(&self, key: &str, data: &[u8]) -> Result<()> {
        let service = SecretService::connect(EncryptionType::Plain)
            .context("connect to Linux Secret Service")?;
        let collections = service
            .get_all_collections()
            .context("list Linux Secret Service collections")?;
        let collection = match collections.into_iter().find(|collection| {
            collection
                .get_label()
                .is_ok_and(|label| label == KEYCHAIN_SERVICE_NAME)
        }) {
            Some(collection) => collection,
            None if self.interactive => service
                .create_collection(KEYCHAIN_SERVICE_NAME, "")
                .context("create ipatool Secret Service collection")?,
            None => bail!("Linux Secret Service collection requires interactive setup"),
        };
        if collection
            .is_locked()
            .context("inspect Linux Secret Service collection")?
        {
            if !self.interactive {
                bail!("Linux Secret Service collection requires interactive authorization");
            }
            collection
                .unlock()
                .context("unlock Linux Secret Service collection")?;
        }
        let stored = GoKeyringItem {
            key: key.to_owned(),
            data: STANDARD.encode(data),
            label: KEYCHAIN_SERVICE_NAME.to_owned(),
        };
        let secret = Zeroizing::new(
            serde_json::to_vec(&stored).context("encode Linux Secret Service item")?,
        );
        collection
            .create_item(
                key,
                HashMap::from([("profile", key)]),
                &secret,
                true,
                "application/json",
            )
            .context("save Linux Secret Service item")?;
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<bool> {
        let service = SecretService::connect(EncryptionType::Plain)
            .context("connect to Linux Secret Service")?;
        let collections = service
            .get_all_collections()
            .context("list Linux Secret Service collections")?;
        let Some(collection) = collections.into_iter().find(|collection| {
            collection
                .get_label()
                .is_ok_and(|label| label == KEYCHAIN_SERVICE_NAME)
        }) else {
            return Ok(false);
        };
        let items = collection
            .search_items(HashMap::from([("profile", key)]))
            .context("find Linux Secret Service item")?;
        let Some(item) = items.into_iter().next() else {
            return Ok(false);
        };
        if item
            .is_locked()
            .context("inspect Linux Secret Service item")?
        {
            if !self.interactive {
                bail!("Linux Secret Service item requires interactive authorization");
            }
            item.unlock().context("unlock Linux Secret Service item")?;
        }
        item.delete().context("remove Linux Secret Service item")?;
        Ok(true)
    }
}
