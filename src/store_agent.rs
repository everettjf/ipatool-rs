//! Entrypoints for the pinned commerce StoreAgent guest.

use std::io::{Read, Write};

use anyhow::{Context, Result, bail};

use crate::{
    sap_assets::SapAssetBundle,
    sap_images::STORE_AGENT_BASE,
    sap_machine::{SapRuntimeGuest, consume_output, hardware_block, read_u32},
    sap_signer::SapGuest,
};

const GLOBAL_INIT: u64 = STORE_AGENT_BASE + 0x1312fc;
const KBSYNC_ENTRY: u64 = STORE_AGENT_BASE + 0x19ae34;
const SESSION_INIT: u64 = STORE_AGENT_BASE + 0x13ac60;
const DECRYPT_ENTRY: u64 = STORE_AGENT_BASE + 0x175390;
const GLOBAL_CLOSE: u64 = STORE_AGENT_BASE + 0x130eb4;
const SC_INFO_PATH: &[u8] = b"/Users/Shared/SC Info\0";
const CHUNK_SIZE: usize = 0x8000;

pub struct StoreAgentSession {
    guest: Option<SapRuntimeGuest>,
    global_context: u32,
    session: u64,
}

impl StoreAgentSession {
    pub fn open(bundle: &SapAssetBundle, hardware_id: &[u8], dp_info: &[u8]) -> Result<Self> {
        if dp_info.is_empty() {
            bail!("StoreAgent dpInfo is empty");
        }
        let mut guest = SapRuntimeGuest::open_store_agent_runtime(bundle)?;
        let global_context = initialize_global(&mut guest, hardware_id)?;
        let session = initialize_session(&mut guest, global_context, dp_info);
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                let _ = close_global(&mut guest, global_context);
                let _ = guest.close();
                return Err(error);
            }
        };
        Ok(Self {
            guest: Some(guest),
            global_context,
            session,
        })
    }

    pub fn decrypt<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<u64> {
        let guest = self
            .guest
            .as_mut()
            .context("StoreAgent session is closed")?;
        let session = self.session;
        decrypt_stream(reader, writer, |chunk| {
            guest.with_scratch(|machine, _| {
                let address = machine.scratch(chunk, chunk.len() as u64)?;
                let status = machine.invoke(
                    DECRYPT_ENTRY,
                    &[session, address, chunk.len() as u64, address, 0],
                )?;
                if status as i32 != 0 {
                    bail!("StoreAgent decryption returned {}", status as i32);
                }
                let decrypted = machine.engine().mem_read(address, chunk.len())?;
                chunk.copy_from_slice(&decrypted);
                Ok(())
            })
        })
    }

    pub fn close(&mut self) -> Result<()> {
        let Some(mut guest) = self.guest.take() else {
            return Ok(());
        };
        let global = std::mem::take(&mut self.global_context);
        self.session = 0;
        let closed_global = close_global(&mut guest, global);
        let closed_guest = guest.close();
        closed_global?;
        closed_guest
    }
}

impl Drop for StoreAgentSession {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn initialize_session(
    guest: &mut SapRuntimeGuest,
    global_context: u32,
    dp_info: &[u8],
) -> Result<u64> {
    if global_context == 0 || dp_info.is_empty() {
        bail!("StoreAgent session requires a context and dpInfo");
    }
    guest.with_scratch(|machine, _| {
        let dp_info_address = machine.scratch(dp_info, dp_info.len() as u64)?;
        let session_field = machine.scratch(&[], 8)?;
        let status = machine.invoke(
            SESSION_INIT,
            &[
                global_context as u64,
                dp_info_address,
                dp_info.len() as u64,
                session_field,
            ],
        )?;
        if status as i32 != 0 {
            bail!(
                "StoreAgent session initialization returned {}",
                status as i32
            );
        }
        let bytes = machine.engine().mem_read(session_field, 8)?;
        let session = u64::from_le_bytes(bytes.as_slice().try_into().expect("eight bytes"));
        if session == 0 {
            bail!("StoreAgent session initialization returned a null session");
        }
        Ok(session)
    })
}

fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut decrypt: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<u64> {
    let mut buffer = [0u8; CHUNK_SIZE];
    let mut written = 0u64;
    loop {
        let mut count = 0usize;
        let mut read_error = None;
        while count < CHUNK_SIZE {
            match reader.read(&mut buffer[count..]) {
                Ok(0) => break,
                Ok(size) => count += size,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    read_error = Some(error);
                    break;
                }
            }
        }
        if count != 0 {
            decrypt(&mut buffer[..count])?;
            let size = writer
                .write(&buffer[..count])
                .context("write decrypted StoreAgent stream")?;
            written += size as u64;
            if size != count {
                bail!("write decrypted StoreAgent stream: short write");
            }
        }
        if let Some(error) = read_error {
            return Err(error).context("read encrypted StoreAgent stream");
        }
        if count < CHUNK_SIZE {
            return Ok(written);
        }
    }
}

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
    fn rejects_empty_session_info_before_loading_assets() {
        let bundle = SapAssetBundle {
            apple_media_services: Vec::new(),
            commerce: Vec::new(),
            core_fp: Vec::new(),
            core_fp_icxs: Vec::new(),
        };
        assert!(StoreAgentSession::open(&bundle, &[2, 0, 0, 0, 0, 1], &[]).is_err());
    }

    #[test]
    fn decrypt_stream_uses_full_chunks_and_final_partial_chunk() {
        let input = vec![0x3c; 2 * CHUNK_SIZE + 17];
        let mut output = Vec::new();
        let mut sizes = Vec::new();
        let written = decrypt_stream(&mut input.as_slice(), &mut output, |chunk| {
            sizes.push(chunk.len());
            for byte in chunk {
                *byte ^= 0xff;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(written as usize, input.len());
        assert_eq!(sizes, vec![CHUNK_SIZE, CHUNK_SIZE, 17]);
        assert_eq!(output, vec![0xc3; input.len()]);
    }

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
