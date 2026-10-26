//! Prepare the pinned CoreFP and AppleMediaServices images for the SAP guest.

use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::{
    machimage::{Image, Memory},
    sap_assets::SapAssetBundle,
    sap_machine::SapEntrypoints,
    sap_prelinked,
};

pub const CORE_FP_BASE: u64 = 0x0000_1000_0000_0000;

const CORE_EXPORTS: [&str; 6] = [
    "_WIn9UJ86JKdV4dM",
    "_X46O5IeS",
    "_YlCJ3lg",
    "_dku592fbFAj",
    "_fdjkDSAFjklaf2s",
    "_lxpgvVMLd0S7uRl",
];
const AMS_EXPORTS: [&str; 5] = [
    "_cp2g1b9ro",
    "_Mib5yocT",
    "_Fc3vhtJDvr",
    "_IPaI1oem5iL",
    "_jEHf8Xzsv8K",
];

pub struct SapImages {
    core_fp: Image,
    apple_media_services: Image,
    exports: HashMap<String, u64>,
}

impl SapImages {
    pub fn open(bundle: &SapAssetBundle) -> Result<Self> {
        let core_fp = Image::open("CoreFP", &bundle.core_fp).context("open CoreFP")?;
        let apple_media_services = Image::open("AppleMediaServices", &bundle.apple_media_services)
            .context("open AppleMediaServices")?;
        let mut exports = HashMap::new();
        for name in CORE_EXPORTS {
            exports.insert(name.to_owned(), core_fp.export(name, CORE_FP_BASE)?);
        }
        for name in AMS_EXPORTS {
            exports.insert(
                name.to_owned(),
                apple_media_services.export(name, apple_media_services.base())?,
            );
        }
        Ok(Self {
            core_fp,
            apple_media_services,
            exports,
        })
    }

    pub fn core_exports(&self) -> impl Iterator<Item = (&str, u64)> {
        CORE_EXPORTS
            .into_iter()
            .map(|name| (name, self.exports[name]))
    }

    pub fn entrypoints(&self) -> SapEntrypoints {
        SapEntrypoints {
            initialize: self.exports[AMS_EXPORTS[0]],
            exchange: self.exports[AMS_EXPORTS[1]],
            sign: self.exports[AMS_EXPORTS[2]],
            teardown: self.exports[AMS_EXPORTS[3]],
            dispose: self.exports[AMS_EXPORTS[4]],
        }
    }

    /// Resolve remaining imports through the guest shim registry, then map
    /// all pinned images and shared-cache compatibility addresses.
    pub fn load<M, F>(&mut self, memory: &mut M, mut resolve_shim: F) -> Result<()>
    where
        M: Memory,
        F: FnMut(&str) -> Result<u64>,
    {
        let mut resolve = |name: &str| -> Result<u64> {
            if let Some(&address) = self.exports.get(name) {
                Ok(address)
            } else {
                resolve_shim(name)
            }
        };
        sap_prelinked::install(memory, &mut resolve)
            .context("install AppleMediaServices shared-cache addresses")?;
        self.core_fp
            .relocate(CORE_FP_BASE, &mut resolve)
            .context("relocate CoreFP")?;
        self.core_fp.load(memory).context("load CoreFP")?;
        let external = sap_prelinked::FUNCTIONS
            .iter()
            .map(|&(address, name)| (address, name.to_owned()))
            .collect::<Vec<_>>();
        self.apple_media_services
            .prepare_prelinked(&external, &mut resolve)
            .context("prepare AppleMediaServices")?;
        self.apple_media_services
            .load(memory)
            .context("load AppleMediaServices")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use sha2::{Digest, Sha256};

    #[derive(Default)]
    struct RecordedMemory {
        maps: Vec<(u64, u64)>,
        writes: usize,
    }

    impl Memory for RecordedMemory {
        fn map(&mut self, address: u64, size: u64) -> Result<()> {
            if self
                .maps
                .iter()
                .any(|&(start, length)| address < start + length && start < address + size)
            {
                bail!("overlapping guest mapping at {address:#x}");
            }
            self.maps.push((address, size));
            Ok(())
        }

        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
            if !self.maps.iter().any(|&(start, length)| {
                address >= start && address + bytes.len() as u64 <= start + length
            }) {
                bail!("write outside guest mapping at {address:#x}");
            }
            self.writes += 1;
            Ok(())
        }
    }

    #[test]
    fn loads_pinned_local_core_fp_with_embedded_plugin_when_available() {
        let path = "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP";
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        if format!("{:x}", Sha256::digest(&bytes))
            != "2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46"
        {
            return;
        }
        let profile = crate::store_profile::load().unwrap();
        let mut images = SapImages {
            core_fp: Image::open("CoreFP", &bytes).unwrap(),
            apple_media_services: Image::open("plugin fixture", &profile.plugin).unwrap(),
            exports: HashMap::new(),
        };
        let mut memory = RecordedMemory::default();
        images.load(&mut memory, |_| Ok(0x7ff8_8000_0000)).unwrap();
        assert!(memory.maps.len() > 21);
        assert!(memory.writes > sap_prelinked::FUNCTIONS.len() + sap_prelinked::SLOTS.len());
    }
}
