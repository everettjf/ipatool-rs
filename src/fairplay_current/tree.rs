//! Deterministic tagged SIDB selection from UnfairPlay b3a7a432 (MIT).
//! Parsing geometry is separate from authenticating the one selected value.

use super::{outer, tags};
use crate::fairplay::SinfSelector;
use anyhow::{Result, bail};
use zeroize::{Zeroize, Zeroizing};

const MASK: [u8; 16] = [
    0x49, 0x8b, 0x22, 0x11, 0x82, 0xb3, 0x19, 0x85, 0x70, 0xdd, 0x90, 0x4f, 0xd9, 0x8c, 0x93, 0x17,
];

struct Node {
    offset: usize,
    length: usize,
    children: Vec<usize>,
    tag: &'static str,
    identifier: Option<u32>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.offset.zeroize();
        self.length.zeroize();
        self.children.zeroize();
        self.identifier.zeroize();
    }
}

#[derive(Debug, serde::Serialize)]
pub struct RouteEvidence {
    pub root_version: u32,
    pub account_version: u32,
    pub type_cursor: usize,
    pub type_length: usize,
    pub sign_cursor: usize,
    pub sign_length: usize,
    pub value_cursor: usize,
    pub value_length: usize,
    pub selected_record_index: usize,
    pub selected_payload_offset: usize,
    pub selected_window_offset: usize,
}

pub struct SelectedValue {
    pub ciphertext: Zeroizing<[u8; 16]>,
    pub evidence: RouteEvidence,
}

fn raw(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(std::array::from_fn(|i| {
        data[offset + i] ^ MASK[(offset + i + 12) % 16]
    }))
}

fn word(data: &[u8], offset: usize, size: usize, prefix: u32) -> u32 {
    let mut value = 0u32;
    for i in 0..size {
        value = (value << 8) | u32::from(data[offset + i] ^ MASK[(offset + i + 12) % 16]);
    }
    let bits = size as u32 * 8;
    let width = value >> (bits - prefix);
    let width = if width == 0 { bits } else { width };
    if width == 32 {
        value
    } else {
        value & ((1u32 << width) - 1)
    }
}

fn parse(
    data: &[u8],
    offset: usize,
    limit: usize,
    depth: usize,
    nodes: &mut Vec<Node>,
) -> Result<usize> {
    crate::application::operation::check()?;
    if depth > 32
        || nodes.len() >= 4096
        || limit > data.len()
        || offset > limit
        || limit - offset < 20
    {
        bail!("invalid or excessive SIDB tree geometry");
    }
    let length = word(data, offset, 4, 5) as usize;
    if length < 20 || length > limit - offset {
        bail!("invalid SIDB node extent");
    }
    let count = word(data, offset + 14, 2, 4) as usize;
    if count > 4096 - nodes.len() - 1 {
        bail!("excessive SIDB child count");
    }
    let index = nodes.len();
    nodes.push(Node {
        offset,
        length,
        children: Vec::new(),
        tag: "",
        identifier: None,
    });
    let end = offset + length;
    if count == 0 {
        return Ok(end);
    }
    let mut cursor = offset + 20;
    for _ in 0..count {
        let child = nodes.len();
        nodes[index].children.push(child);
        cursor = parse(data, cursor, end, depth + 1, nodes)?;
    }
    if cursor != end {
        bail!("SIDB children do not fill their parent");
    }
    Ok(end)
}

fn unique(nodes: &[Node], parent: usize, tag: &str, id: Option<u32>) -> Result<usize> {
    let mut found = None;
    for &index in &nodes[parent].children {
        let node = &nodes[index];
        if node.tag != tag || id.is_some_and(|expected| node.identifier != Some(expected)) {
            continue;
        }
        if found.replace(index).is_some() {
            bail!("duplicate selected SIDB route tag");
        }
    }
    found.ok_or_else(|| anyhow::anyhow!("missing selected SIDB route tag"))
}

fn unsupported(nodes: &[Node], parent: usize, tags: &[&str]) -> Result<()> {
    if nodes[parent]
        .children
        .iter()
        .any(|&i| tags.contains(&nodes[i].tag))
    {
        bail!("unsupported selected SIDB route");
    }
    Ok(())
}

fn version(data: &[u8], node: &Node) -> Result<u32> {
    if !node.children.is_empty() || node.length < 36 {
        bail!("invalid SIDB version leaf");
    }
    let mut value = 0;
    for i in 0..4 {
        value = (value << 8) | (word(data, node.offset + 20 + 4 * i, 4, 5) & 255);
    }
    if !matches!(value, 0x10001 | 0x10002) {
        bail!("unsupported SIDB schema version");
    }
    Ok(value)
}

pub fn select(body: &[u8], hardware: &[u8], selector: SinfSelector) -> Result<SelectedValue> {
    if body.len() > 1 << 20 {
        bail!("SIDB body exceeds the supported bound");
    }
    let cursor = outer::root_cursor(hardware)?;
    let codebook = tags::generate_codebook(hardware)?;
    let mut nodes = Vec::new();
    let end = parse(body, cursor, body.len(), 1, &mut nodes)?;
    if body.len() - end > 15 {
        bail!("excessive SIDB trailing padding");
    }
    for node in &mut nodes {
        let code = raw(body, node.offset + 4);
        let Some(index) = codebook.iter().position(|value| *value == code) else {
            bail!("unknown SIDB tag constructor code");
        };
        node.tag = tags::SEMANTIC_TAGS[index];
        node.identifier = match node.tag {
            "user" => Some(
                raw(body, node.offset + 8)
                    .wrapping_mul(0xa46fd0ff)
                    .wrapping_add(0xfe063531),
            ),
            "key " | "vers" | "type" | "sign" => Some(word(body, node.offset + 8, 4, 5)),
            _ => None,
        };
    }
    if nodes[0].tag != "sean" {
        bail!("unsupported SIDB root tag");
    }
    unsupported(&nodes, 0, &["divi"])?;
    let root_version = version(body, &nodes[unique(&nodes, 0, "vers", Some(1))?])?;
    let group = unique(&nodes, 0, "grup", None)?;
    let user = unique(&nodes, group, "user", Some(selector.user))?;
    let account_version = version(body, &nodes[unique(&nodes, user, "vers", Some(1))?])?;
    if account_version != 0x10002 {
        bail!("unsupported SIDB account schema");
    }
    unsupported(&nodes, user, &["gval"])?;
    let key = unique(&nodes, user, "key ", Some(selector.key))?;
    let type_node = &nodes[unique(&nodes, key, "type", Some(1))?];
    if !type_node.children.is_empty() || type_node.length != 24 {
        bail!("unsupported SIDB type leaf");
    }
    let sign = &nodes[unique(&nodes, key, "sign", Some(1))?];
    if !sign.children.is_empty() || sign.length != 148 {
        bail!("unsupported SIDB sign leaf");
    }
    unsupported(&nodes, key, &["salt", "iviv", "dong"])?;
    let value_index = unique(&nodes, key, "valu", None)?;
    let value = &nodes[value_index];
    if nodes[key].children.first() != Some(&value_index)
        || !value.children.is_empty()
        || value.length != 36
    {
        bail!("unsupported SIDB selected value leaf");
    }
    let offset = value.offset + 20;
    let mut ciphertext = Zeroizing::new([0u8; 16]);
    for i in 0..4 {
        ciphertext[i * 4..i * 4 + 4].copy_from_slice(
            &raw(body, offset + i * 4)
                .wrapping_mul(0xa46fd0ff)
                .wrapping_add(0xfe063531)
                .to_be_bytes(),
        );
    }
    let record_index = nodes[..value_index]
        .iter()
        .filter(|n| n.children.is_empty() && n.length == 36)
        .count();
    Ok(SelectedValue {
        ciphertext,
        evidence: RouteEvidence {
            root_version,
            account_version,
            type_cursor: type_node.offset,
            type_length: type_node.length,
            sign_cursor: sign.offset,
            sign_length: sign.length,
            value_cursor: value.offset,
            value_length: value.length,
            selected_record_index: record_index,
            selected_payload_offset: offset,
            selected_window_offset: 0,
        },
    })
}
