//! Bounded parsing of AEA cryptex headers and FCS metadata.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use url::Url;

use crate::{sap_archive::ArchiveEntry, sap_remote::RemoteFile};

const HEADER_SIZE: usize = 12;
const MAX_AUTH_DATA: usize = 1 << 20;

pub struct AeaHeader {
    pub profile_and_scrypt_strength: u32,
    pub metadata: HashMap<String, Vec<u8>>,
}

impl AeaHeader {
    pub fn fcs_key_url(&self) -> Result<Url> {
        let bytes = self
            .metadata
            .get("com.apple.wkms.fcs-key-url")
            .context("AEA metadata does not contain an FCS key URL")?;
        let text = std::str::from_utf8(bytes).context("invalid Apple FCS key URL")?;
        let url = Url::parse(text).context("invalid Apple FCS key URL")?;
        if url.scheme() != "https"
            || url.host_str() != Some("wkms-public.apple.com")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("invalid Apple FCS key URL {text:?}");
        }
        Ok(url)
    }

    pub fn fcs_response(&self) -> Result<&[u8]> {
        self.metadata
            .get("com.apple.wkms.fcs-response")
            .map(Vec::as_slice)
            .context("AEA metadata does not contain an FCS response")
    }
}

pub fn read_remote_header(remote: &RemoteFile, entry: ArchiveEntry) -> Result<AeaHeader> {
    if entry.size < HEADER_SIZE as u64
        || entry
            .offset
            .checked_add(entry.size)
            .is_none_or(|end| end > remote.size())
    {
        bail!("AEA archive entry exceeds remote image");
    }
    let mut prefix = [0u8; HEADER_SIZE];
    read_exact_at(remote, &mut prefix, entry.offset)?;
    let auth_size = validate_prefix(&prefix)?;
    if auth_size as u64 > entry.size - HEADER_SIZE as u64 {
        bail!("AEA authentication data exceeds archive entry");
    }
    let mut auth_data = vec![0u8; auth_size];
    read_exact_at(remote, &mut auth_data, entry.offset + HEADER_SIZE as u64)?;
    Ok(AeaHeader {
        profile_and_scrypt_strength: u32::from_le_bytes(prefix[4..8].try_into()?),
        metadata: parse_metadata(&auth_data)?,
    })
}

fn read_exact_at(remote: &RemoteFile, buffer: &mut [u8], offset: u64) -> Result<()> {
    if remote.read_at(buffer, offset)? != buffer.len() {
        bail!("short AEA archive read at {offset}");
    }
    Ok(())
}

fn validate_prefix(prefix: &[u8; HEADER_SIZE]) -> Result<usize> {
    if &prefix[..4] != b"AEA1" {
        bail!("invalid AEA magic");
    }
    let profile = u32::from_le_bytes(prefix[4..8].try_into()?);
    if profile & 0x00ff_ffff != 1 {
        bail!("unsupported AEA profile {}", profile & 0x00ff_ffff);
    }
    let auth_size = u32::from_le_bytes(prefix[8..12].try_into()?) as usize;
    if auth_size > MAX_AUTH_DATA {
        bail!("AEA authentication data is too large: {auth_size}");
    }
    Ok(auth_size)
}

pub fn parse_metadata(data: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    let mut metadata = HashMap::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let Some(length_bytes) = data.get(cursor..cursor + 4) else {
            bail!("read AEA metadata length: truncated record");
        };
        let length = u32::from_le_bytes(length_bytes.try_into()?) as usize;
        if length < 5 || length > data.len() - cursor {
            bail!("invalid AEA metadata record length {length}");
        }
        let record = &data[cursor + 4..cursor + length];
        let Some(separator) = record.iter().position(|byte| *byte == 0) else {
            bail!("invalid AEA metadata record");
        };
        if separator == 0 {
            bail!("invalid AEA metadata record");
        }
        let key = std::str::from_utf8(&record[..separator]).context("invalid AEA metadata key")?;
        metadata.insert(key.to_owned(), record[separator + 1..].to_vec());
        cursor += length;
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_aea_metadata_and_fcs_url() {
        let mut bytes = Vec::new();
        for (key, value) in [
            (
                "com.apple.wkms.fcs-key-url",
                b"https://wkms-public.apple.com/key".as_slice(),
            ),
            ("com.apple.wkms.fcs-response", b"{}".as_slice()),
        ] {
            let length = 4 + key.len() + 1 + value.len();
            bytes.extend_from_slice(&(length as u32).to_le_bytes());
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(value);
        }
        let header = AeaHeader {
            profile_and_scrypt_strength: 1,
            metadata: parse_metadata(&bytes).unwrap(),
        };
        assert_eq!(
            header.fcs_key_url().unwrap().host_str(),
            Some("wkms-public.apple.com")
        );
        assert_eq!(header.fcs_response().unwrap(), b"{}");
        assert!(validate_prefix(&[b'A', b'E', b'A', b'1', 1, 0, 0, 0, 0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn rejects_bad_profile_record_and_key_url() {
        assert!(validate_prefix(&[0; HEADER_SIZE]).is_err());
        let mut prefix = *b"AEA1\x01\x00\x00\x00\x00\x00\x20\x00";
        assert!(validate_prefix(&prefix).is_err());
        prefix[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate_prefix(&prefix).is_ok());
        assert!(parse_metadata(&[32, 0, 0, 0, 1, 2, 3, 4]).is_err());
        let header = AeaHeader {
            profile_and_scrypt_strength: 1,
            metadata: HashMap::from([(
                "com.apple.wkms.fcs-key-url".into(),
                b"https://example.com/key".to_vec(),
            )]),
        };
        assert!(header.fcs_key_url().is_err());
    }
}
