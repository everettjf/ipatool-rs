//! Entrypoints for the pinned commerce StoreAgent guest.

use anyhow::{Result, bail};

use crate::{
    sap_images::STORE_AGENT_BASE,
    sap_machine::{SapRuntimeGuest, hardware_block, read_u32},
};

const GLOBAL_INIT: u64 = STORE_AGENT_BASE + 0x1312fc;
const SC_INFO_PATH: &[u8] = b"/Users/Shared/SC Info\0";

pub fn initialize_global(guest: &mut SapRuntimeGuest, hardware_id: &[u8]) -> Result<u32> {
    let hardware = hardware_block(hardware_id)?;
    guest.with_scratch(|machine, _| {
        let hardware_address = machine.scratch(&hardware, hardware.len() as u64)?;
        let path_address = machine.scratch(SC_INFO_PATH, SC_INFO_PATH.len() as u64)?;
        let context_field = machine.scratch(&[], 4)?;
        let status = machine.invoke(
            GLOBAL_INIT,
            &[0, hardware_address, path_address, context_field],
        )?;
        if status as i32 != 0 {
            bail!(
                "StoreAgent global initialization returned {}",
                status as i32
            );
        }
        let context = read_u32(machine, context_field)?;
        if context == 0 {
            bail!("StoreAgent global initialization returned a null context");
        }
        Ok(context)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sap_assets::SapAssetBundle, sap_signer::SapGuest};

    #[test]
    #[ignore = "downloads pinned Apple assets when cache is empty"]
    fn initializes_pinned_store_agent_global_context() {
        let bundle = SapAssetBundle::load_or_download().unwrap();
        let mut guest = SapRuntimeGuest::open_store_agent_runtime(&bundle).unwrap();
        let context = initialize_global(&mut guest, &[0x02, 0, 0, 0, 0, 1]).unwrap();
        assert_ne!(context, 0);
        guest.close().unwrap();
    }
}
