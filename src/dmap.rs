//! Bounded DAAP/DMAP tag encoding and decoding for purchase history.

use anyhow::{Result, bail};

const MAX_DEPTH: usize = 16;

pub fn tag(name: &[u8; 4], payload: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(payload.len())?;
    let mut bytes = Vec::with_capacity(8 + payload.len());
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn uint8(name: &[u8; 4], value: u8) -> Result<Vec<u8>> {
    tag(name, &[value])
}

pub fn uint32(name: &[u8; 4], value: u32) -> Result<Vec<u8>> {
    tag(name, &value.to_be_bytes())
}

pub fn string(name: &[u8; 4], value: &str) -> Result<Vec<u8>> {
    tag(name, value.as_bytes())
}

pub fn walk(data: &[u8], mut visit: impl FnMut(&[u8; 4], &[u8]) -> Result<()>) -> Result<()> {
    walk_at_depth(data, 0, &mut visit)
}

fn walk_at_depth(
    data: &[u8],
    depth: usize,
    visit: &mut impl FnMut(&[u8; 4], &[u8]) -> Result<()>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("DMAP nesting is too deep");
    }
    let mut offset = 0;
    while offset < data.len() {
        if data.len() - offset < 8 {
            bail!("truncated DMAP tag header at byte {offset}");
        }
        let name: &[u8; 4] = data[offset..offset + 4].try_into()?;
        if !name.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            bail!("invalid DMAP tag at byte {offset}");
        }
        let length = u32::from_be_bytes(data[offset + 4..offset + 8].try_into()?) as usize;
        let remaining = data.len() - offset - 8;
        if length > remaining {
            bail!(
                "DMAP tag {} length {length} exceeds remaining response length {remaining}",
                String::from_utf8_lossy(name)
            );
        }
        let end = offset + 8 + length;
        let payload = &data[offset + 8..end];
        visit(name, payload)?;
        if is_container(name) {
            walk_at_depth(payload, depth + 1, visit)?;
        }
        offset = end;
    }
    Ok(())
}

fn is_container(name: &[u8; 4]) -> bool {
    matches!(
        name,
        b"adbs"
            | b"adsr"
            | b"aply"
            | b"avdb"
            | b"mbcl"
            | b"mccr"
            | b"mcty"
            | b"mdcl"
            | b"mlcl"
            | b"mlit"
            | b"mlog"
            | b"msrv"
            | b"mupd"
    )
}

pub fn first_uint(data: &[u8], target: &[u8; 4]) -> Result<Option<u64>> {
    let mut result = None;
    walk(data, |name, payload| {
        if result.is_some() || name != target {
            return Ok(());
        }
        result = Some(match payload.len() {
            4 => u32::from_be_bytes(payload.try_into()?) as u64,
            8 => u64::from_be_bytes(payload.try_into()?),
            _ => bail!(
                "tag {} has invalid integer length {}",
                String::from_utf8_lossy(target),
                payload.len()
            ),
        });
        Ok(())
    })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nested_session_id_and_rejects_truncation() {
        let inner = uint32(b"mlid", 42).unwrap();
        let body = tag(b"mlog", &inner).unwrap();
        assert_eq!(first_uint(&body, b"mlid").unwrap(), Some(42));
        assert!(first_uint(&body[..body.len() - 1], b"mlid").is_err());
    }

    #[test]
    fn does_not_recurse_into_unknown_binary_payloads() {
        let body = tag(b"blob", &[0, 1, 2, 3]).unwrap();
        assert_eq!(first_uint(&body, b"mlid").unwrap(), None);
    }
}
