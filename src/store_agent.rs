//! Entrypoints for the pinned commerce StoreAgent guest.

use anyhow::{Result, bail};

use crate::{
    sap_assets::SapAssetBundle,
    sap_images::STORE_AGENT_BASE,
    sap_machine::{SapRuntimeGuest, consume_output, hardware_block, read_u32},
    sap_signer::SapGuest,
};

const GLOBAL_INIT: u64 = STORE_AGENT_BASE + 0x1312fc;
const KBSYNC_ENTRY: u64 = STORE_AGENT_BASE + 0x19ae34;
const GLOBAL_CLOSE: u64 = STORE_AGENT_BASE + 0x130eb4;
const SC_INFO_PATH: &[u8] = b"/Users/Shared/SC Info\0";

pub fn create_kbsync(bundle: &SapAssetBundle, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>> {
    if dsid == 0 {
        bail!("KBSync requires a nonzero account DSID");
    }
    let mut guest = SapRuntimeGuest::open_store_agent_runtime(bundle)?;
    let context = initialize_global(&mut guest, hardware_id)?;
    let output = generate_kbsync(&mut guest, context, dsid);
    let closed_global = close_global(&mut guest, context);
    let closed_guest = guest.close();
    let output = output?;
    closed_global?;
    closed_guest?;
    Ok(output)
}

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

pub fn generate_kbsync(
    guest: &mut SapRuntimeGuest,
    global_context: u32,
    dsid: u64,
) -> Result<Vec<u8>> {
    if global_context == 0 || dsid == 0 {
        bail!("KBSync requires a nonzero context and account DSID");
    }
    guest.with_scratch(|machine, entries| {
        let pointer_field = machine.scratch(&[], 8)?;
        let length_field = machine.scratch(&[], 8)?;
        let status = machine.invoke(
            KBSYNC_ENTRY,
            &[
                global_context as u64,
                dsid,
                0,
                1,
                pointer_field,
                length_field,
            ],
        )?;
        let output = consume_output(machine, entries.dispose, pointer_field, length_field)?;
        if status as i32 != 0 {
            bail!("StoreAgent KBSync returned {}", status as i32);
        }
        if output.is_empty() {
            bail!("StoreAgent KBSync returned an empty buffer");
        }
        Ok(output)
    })
}

pub fn close_global(guest: &mut SapRuntimeGuest, global_context: u32) -> Result<()> {
    if global_context == 0 {
        return Ok(());
    }
    guest.with_scratch(|machine, _| {
        let status = machine.invoke(GLOBAL_CLOSE, &[global_context as u64])?;
        if status as i32 != 0 {
            bail!("StoreAgent global close returned {}", status as i32);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "downloads pinned Apple assets when cache is empty"]
    fn initializes_pinned_store_agent_global_context() {
        let bundle = SapAssetBundle::load_or_download().unwrap();
        let mut guest = SapRuntimeGuest::open_store_agent_runtime(&bundle).unwrap();
        let context = initialize_global(&mut guest, &[0x02, 0, 0, 0, 0, 1]).unwrap();
        assert_ne!(context, 0);
        close_global(&mut guest, context).unwrap();
        guest.close().unwrap();
    }

    #[test]
    #[ignore = "downloads pinned Apple assets when cache is empty"]
    fn generates_pinned_store_agent_kbsync() {
        let bundle = SapAssetBundle::load_or_download().unwrap();
        let blob = create_kbsync(&bundle, &[0x02, 0, 0, 0, 0, 1], 1).unwrap();
        assert!(!blob.is_empty());
    }
}
