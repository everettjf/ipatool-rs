use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::error::{ApfsError, Result};
use crate::fletcher;

// Object type constants (lower 16 bits of type_and_flags)
pub const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x01;
pub const OBJECT_TYPE_BTREE: u32 = 0x02;
pub const OBJECT_TYPE_BTREE_NODE: u32 = 0x03;
pub const OBJECT_TYPE_SPACEMAN: u32 = 0x05;
pub const OBJECT_TYPE_OMAP: u32 = 0x0B;
pub const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0C;
pub const OBJECT_TYPE_FS: u32 = 0x0D;
const OBJECT_TYPE_FSTREE: u32 = 0x0E;
pub(crate) const OBJECT_NOHEADER: u32 = 0x2000_0000;
const BTNODE_ROOT: u16 = 0x0001;
const BTNODE_NOHEADER: u16 = 0x0010;

// Object flag masks (upper 16 bits of type_and_flags)
pub const OBJ_PHYSICAL: u32 = 0x00000000;
pub const OBJ_VIRTUAL: u32 = 0x80000000;
pub const OBJ_EPHEMERAL: u32 = 0x40000000;
pub const OBJ_STORAGE_TYPE_MASK: u32 = 0xC0000000;
pub const OBJECT_TYPE_MASK: u32 = 0x0000FFFF;

/// 32-byte header present on every APFS on-disk object. All fields are little-endian.
#[derive(Debug, Clone)]
pub struct ObjectHeader {
    pub checksum: u64,       // 0x00
    pub oid: u64,            // 0x08
    pub xid: u64,            // 0x10
    pub type_and_flags: u32, // 0x18
    pub subtype: u32,        // 0x1C
}

impl ObjectHeader {
    /// Size of the on-disk header in bytes
    pub const SIZE: usize = 32;

    /// Parse an object header from the first 32 bytes of a block
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ApfsError::CorruptedData(format!(
                "object header too short: {} bytes",
                data.len()
            )));
        }

        let mut cursor = Cursor::new(data);
        Ok(ObjectHeader {
            checksum: cursor.read_u64::<LittleEndian>()?,
            oid: cursor.read_u64::<LittleEndian>()?,
            xid: cursor.read_u64::<LittleEndian>()?,
            type_and_flags: cursor.read_u32::<LittleEndian>()?,
            subtype: cursor.read_u32::<LittleEndian>()?,
        })
    }

    /// Get the object type (lower 16 bits, no flags)
    pub fn object_type(&self) -> u32 {
        self.type_and_flags & OBJECT_TYPE_MASK
    }

    /// Get the storage type flags (upper 2 bits)
    pub fn storage_type(&self) -> u32 {
        self.type_and_flags & OBJ_STORAGE_TYPE_MASK
    }

    /// Whether this is a physical object (address = block number)
    pub fn is_physical(&self) -> bool {
        self.storage_type() == OBJ_PHYSICAL
    }
}

/// Read a full block at the given block number, verify its checksum, and parse the header.
pub fn read_object<R: Read + Seek>(
    reader: &mut R,
    block_number: u64,
    block_size: u32,
) -> Result<(ObjectHeader, Vec<u8>)> {
    let offset = block_number * block_size as u64;
    reader.seek(SeekFrom::Start(offset))?;

    let mut block = vec![0u8; block_size as usize];
    reader.read_exact(&mut block)?;

    // Sealed filesystem B-tree nodes omit the usual object header. The
    // decrypted restore image is already authenticated by AEA; reconstruct
    // the header expected by the generic APFS B-tree parser.
    if block_size == 4096
        && block[..ObjectHeader::SIZE].iter().all(|byte| *byte == 0)
        && u16::from_le_bytes(block[32..34].try_into().unwrap()) & BTNODE_NOHEADER != 0
    {
        let flags = u16::from_le_bytes(block[32..34].try_into().unwrap());
        let object_type = if flags & BTNODE_ROOT != 0 {
            OBJECT_TYPE_BTREE
        } else {
            OBJECT_TYPE_BTREE_NODE
        };
        block[8..16].copy_from_slice(&block_number.to_le_bytes());
        block[24..28].copy_from_slice(&(OBJECT_NOHEADER | object_type).to_le_bytes());
        block[28..32].copy_from_slice(&OBJECT_TYPE_FSTREE.to_le_bytes());
        let checksum = fletcher::fletcher64(&block[8..]);
        block[..8].copy_from_slice(&checksum.to_le_bytes());
    }

    if !fletcher::verify_object(&block) {
        return Err(ApfsError::InvalidChecksum);
    }

    let header = ObjectHeader::parse(&block)?;
    Ok((header, block))
}

/// Read a block at the given block number without checksum verification.
pub fn read_block<R: Read + Seek>(
    reader: &mut R,
    block_number: u64,
    block_size: u32,
) -> Result<Vec<u8>> {
    let offset = block_number * block_size as u64;
    reader.seek(SeekFrom::Start(offset))?;

    let mut block = vec![0u8; block_size as usize];
    reader.read_exact(&mut block)?;
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn restores_sealed_tree_node_header() {
        for (flags, expected_type) in [
            (BTNODE_NOHEADER, OBJECT_TYPE_BTREE_NODE),
            (BTNODE_NOHEADER | BTNODE_ROOT, OBJECT_TYPE_BTREE),
        ] {
            let mut raw = vec![0u8; 4096];
            raw[32..34].copy_from_slice(&flags.to_le_bytes());
            let (header, block) = read_object(&mut Cursor::new(raw), 0, 4096).unwrap();
            assert_eq!(header.object_type(), expected_type);
            assert_eq!(header.subtype, OBJECT_TYPE_FSTREE);
            assert!(fletcher::verify_object(&block));
        }
    }

    #[test]
    fn does_not_repair_invalid_ordinary_block() {
        let mut raw = vec![0u8; 4096];
        raw[32..34].copy_from_slice(&BTNODE_ROOT.to_le_bytes());
        assert!(matches!(
            read_object(&mut Cursor::new(raw), 0, 4096),
            Err(ApfsError::InvalidChecksum)
        ));
    }
}
