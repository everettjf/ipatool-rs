//! Offline FairPlay SINF and enrollment model inspection.

use std::{fs, io::Read, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::ZipArchive;

const MODEL_V1_BYTES: usize = 8 + 4 + 4 + 32 + 16 + 16 + 16 * 256;
const MODEL_V2_BYTES: usize = 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16 * 256;
const MODEL_V3_SOURCE_BYTES: usize = 27 * 16;
const MODEL_V3_BYTES: usize =
    8 + 4 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 16 + 16 * 256 + MODEL_V3_SOURCE_BYTES + 16 * 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SinfSelector {
    pub user: u32,
    pub key: u32,
}

impl SinfSelector {
    pub fn identifier(self) -> String {
        format!("{:08x}:{:08x}", self.user, self.key)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SinfDiagnostic {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub sha256: String,
    pub bytes: usize,
    pub selector: SinfSelector,
    pub selector_id: String,
    pub private_bytes: usize,
    pub atoms: Vec<String>,
    pub current_layout: bool,
    pub legacy_markers: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrollmentModelDiagnostic {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub version: u32,
    pub fairplayd_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<SinfSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_id: Option<String>,
}

#[derive(Clone, Copy)]
struct Atom<'a> {
    typ: [u8; 4],
    payload: &'a [u8],
}

fn atoms(mut bytes: &[u8]) -> Result<Vec<Atom<'_>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            bail!("SINF atom list has a truncated header");
        }
        let size = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if size < 8 || size > bytes.len() {
            bail!("SINF atom has invalid bounds");
        }
        result.push(Atom {
            typ: bytes[4..8].try_into().unwrap(),
            payload: &bytes[8..size],
        });
        bytes = &bytes[size..];
    }
    Ok(result)
}

fn unique_atom<'a>(atoms: &[Atom<'a>], typ: [u8; 4]) -> Result<Atom<'a>> {
    let mut found = atoms.iter().copied().filter(|atom| atom.typ == typ);
    match (found.next(), found.next()) {
        (Some(atom), None) => Ok(atom),
        (None, _) => bail!(
            "SINF requires one {:?} atom, found 0",
            String::from_utf8_lossy(&typ)
        ),
        _ => bail!(
            "SINF requires one {:?} atom, found multiple",
            String::from_utf8_lossy(&typ)
        ),
    }
}

fn sinf_fields(bytes: &[u8]) -> Result<Vec<Atom<'_>>> {
    let roots = atoms(bytes)?;
    if roots.len() != 1 || roots[0].typ != *b"sinf" {
        bail!("SINF must contain one complete root atom");
    }
    let children = atoms(roots[0].payload)?;
    let schi = unique_atom(&children, *b"schi")?;
    atoms(schi.payload)
}

fn selector_from_fields(fields: &[Atom<'_>]) -> Result<SinfSelector> {
    let user = unique_atom(fields, *b"user")?;
    let key = unique_atom(fields, *b"key ")?;
    if user.payload.len() != 4 || key.payload.len() != 4 {
        bail!("SINF user/key atom has invalid geometry");
    }
    Ok(SinfSelector {
        user: u32::from_be_bytes(user.payload.try_into().unwrap()),
        key: u32::from_be_bytes(key.payload.try_into().unwrap()),
    })
}

pub fn parse_sinf_selector(bytes: &[u8]) -> Result<SinfSelector> {
    selector_from_fields(&sinf_fields(bytes)?)
}

pub fn inspect_sinf(bytes: &[u8]) -> Result<SinfDiagnostic> {
    let fields = sinf_fields(bytes)?;
    let selector = selector_from_fields(&fields)?;
    let mut private_bytes = 0;
    let mut legacy_markers = false;
    let mut names = Vec::with_capacity(fields.len());
    for atom in fields {
        let name = String::from_utf8_lossy(&atom.typ).into_owned();
        if atom.typ == *b"priv" {
            private_bytes = atom.payload.len();
        }
        if atom.typ == *b"crdt" || atom.typ == *b"asdt" {
            legacy_markers = true;
        }
        names.push(name);
    }
    Ok(SinfDiagnostic {
        path: None,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        bytes: bytes.len(),
        selector,
        selector_id: selector.identifier(),
        private_bytes,
        atoms: names,
        current_layout: private_bytes == 440 || private_bytes == 448,
        legacy_markers,
    })
}

pub fn inspect_ipa_sinfs(path: &Path) -> Result<Vec<SinfDiagnostic>> {
    let file = fs::File::open(path).with_context(|| format!("open IPA: {}", path.display()))?;
    let mut archive = ZipArchive::new(file).context("open IPA ZIP archive")?;
    let mut result = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("read IPA ZIP member")?;
        let name = entry.name().to_owned();
        if !name.contains("/SC_Info/") || !name.to_ascii_lowercase().ends_with(".sinf") {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {name}"))?;
        let mut diagnostic = inspect_sinf(&bytes).with_context(|| format!("inspect {name}"))?;
        diagnostic.path = Some(name);
        result.push(diagnostic);
    }
    if result.is_empty() {
        bail!("IPA contains no SINF files");
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

fn validate_permutation_tables(kind: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(256) {
        bail!("current SINF {kind} tables have invalid size");
    }
    for (index, table) in bytes.as_chunks::<256>().0.iter().enumerate() {
        let mut seen = [false; 256];
        for byte in table {
            if seen[*byte as usize] {
                bail!("current SINF {kind} table {index} is not a permutation");
            }
            seen[*byte as usize] = true;
        }
    }
    Ok(())
}

fn model_details(bytes: &[u8]) -> Result<(u32, String, Option<SinfSelector>)> {
    if bytes.len() < 16
        || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize != bytes.len()
    {
        bail!("invalid current SINF model envelope");
    }
    let magic = &bytes[..8];
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let (payload_offset, selector) = match (bytes.len(), magic, version) {
        (MODEL_V1_BYTES, b"FPS26A4\0" | b"FPSENR1\0", 1) => (48, None),
        (MODEL_V2_BYTES, b"FPSENR2\0", 2) => (
            56,
            Some(SinfSelector {
                user: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
                key: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
            }),
        ),
        (MODEL_V3_BYTES, b"FPSENR3\0", 3) => {
            let source_offset = i32::from_le_bytes(bytes[56..60].try_into().unwrap());
            let source_bytes = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
            if bytes[65..68] != [0, 0, 0]
                || source_offset < 0
                || source_bytes != MODEL_V3_SOURCE_BYTES
            {
                bail!("invalid current SINF version 3 geometry");
            }
            (
                68,
                Some(SinfSelector {
                    user: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
                    key: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
                }),
            )
        }
        _ => bail!("invalid current SINF model envelope"),
    };
    if version < 3 {
        validate_permutation_tables("input", &bytes[payload_offset + 32..])?;
    } else {
        let output_start = payload_offset + 16;
        validate_permutation_tables("output", &bytes[output_start..output_start + 4096])?;
        let post_start = output_start + 4096 + MODEL_V3_SOURCE_BYTES;
        validate_permutation_tables("post-codec", &bytes[post_start..])?;
    }
    Ok((version, hex_string(&bytes[16..48]), selector))
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn check_private_permissions(metadata: &fs::Metadata, kind: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "FairPlay enrollment model {kind} must not be accessible by group or other users"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, kind);
    Ok(())
}

pub fn inspect_enrollment_model(path: &Path) -> Result<EnrollmentModelDiagnostic> {
    let metadata = fs::metadata(path).context("inspect FairPlay enrollment model")?;
    if !metadata.is_file() {
        bail!("FairPlay enrollment model is not a regular file");
    }
    check_private_permissions(&metadata, "file")?;
    let bytes = Zeroizing::new(fs::read(path).context("read FairPlay enrollment model")?);
    let (version, fairplayd_sha256, selector) = model_details(bytes.as_slice())?;
    Ok(EnrollmentModelDiagnostic {
        path: path.to_string_lossy().into_owned(),
        sha256: format!("{:x}", Sha256::digest(bytes.as_slice())),
        bytes: bytes.len(),
        version,
        fairplayd_sha256,
        selector,
        selector_id: selector.map(SinfSelector::identifier),
    })
}

pub fn inspect_model_path(path: &Path) -> Result<Vec<EnrollmentModelDiagnostic>> {
    let metadata = fs::metadata(path).context("inspect FairPlay enrollment model path")?;
    if !metadata.is_dir() {
        return Ok(vec![inspect_enrollment_model(path)?]);
    }
    check_private_permissions(&metadata, "directory")?;
    let mut result = Vec::new();
    for entry in fs::read_dir(path).context("read FairPlay enrollment model directory")? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry.file_type()?.is_dir()
            || !entry_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"))
        {
            continue;
        }
        result.push(inspect_enrollment_model(&entry_path)?);
    }
    if result.is_empty() {
        return Err(anyhow!("model directory contains no .bin models"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn atom(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
        data.extend_from_slice(typ);
        data.extend_from_slice(payload);
        data
    }

    fn sinf(selector: SinfSelector, private_size: usize) -> Vec<u8> {
        let mut fields = atom(b"user", &selector.user.to_be_bytes());
        fields.extend(atom(b"key ", &selector.key.to_be_bytes()));
        fields.extend(atom(b"priv", &vec![0; private_size]));
        atom(b"sinf", &atom(b"schi", &fields))
    }

    fn model(selector: SinfSelector) -> Vec<u8> {
        let mut bytes = vec![0; MODEL_V2_BYTES];
        bytes[..8].copy_from_slice(b"FPSENR2\0");
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(MODEL_V2_BYTES as u32).to_le_bytes());
        bytes[48..52].copy_from_slice(&selector.user.to_le_bytes());
        bytes[52..56].copy_from_slice(&selector.key.to_le_bytes());
        for table in bytes[88..].as_chunks_mut::<256>().0 {
            for (index, byte) in table.iter_mut().enumerate() {
                *byte = index as u8;
            }
        }
        bytes
    }

    #[test]
    fn parses_selector_and_current_layout() {
        let selector = SinfSelector {
            user: 0x12345678,
            key: 2,
        };
        let bytes = sinf(selector, 448);
        assert_eq!(parse_sinf_selector(&bytes).unwrap(), selector);
        let diagnostic = inspect_sinf(&bytes).unwrap();
        assert!(diagnostic.current_layout);
        assert_eq!(diagnostic.selector_id, "12345678:00000002");
        assert_eq!(diagnostic.private_bytes, 448);
        assert!(!diagnostic.legacy_markers);
    }

    #[test]
    fn rejects_truncated_and_duplicate_atoms() {
        let selector = SinfSelector { user: 1, key: 2 };
        let mut bytes = sinf(selector, 440);
        bytes.pop();
        assert!(inspect_sinf(&bytes).is_err());
        let mut fields = atom(b"user", &1u32.to_be_bytes());
        fields.extend(atom(b"user", &1u32.to_be_bytes()));
        fields.extend(atom(b"key ", &2u32.to_be_bytes()));
        assert!(parse_sinf_selector(&atom(b"sinf", &atom(b"schi", &fields))).is_err());
    }

    #[test]
    fn inspects_ipa_sinfs_in_path_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.ipa");
        let file = fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for name in [
            "Payload/B.app/SC_Info/B.sinf",
            "Payload/A.app/SC_Info/A.sinf",
        ] {
            zip.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(&sinf(SinfSelector { user: 1, key: 2 }, 448))
                .unwrap();
        }
        zip.finish().unwrap();
        let diagnostics = inspect_ipa_sinfs(&path).unwrap();
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].path.as_deref(),
            Some("Payload/A.app/SC_Info/A.sinf")
        );
    }

    #[test]
    fn checks_model_selector_permutations_and_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("model.bin");
        let selector = SinfSelector {
            user: 0x12345678,
            key: 2,
        };
        fs::write(&path, model(selector)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let diagnostic = inspect_enrollment_model(&path).unwrap();
        assert_eq!(diagnostic.selector, Some(selector));
        assert_eq!(diagnostic.version, 2);
        let mut invalid = model(selector);
        invalid[89] = invalid[88];
        fs::write(&path, invalid).unwrap();
        assert!(inspect_enrollment_model(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(inspect_enrollment_model(&path).is_err());
        }
    }
}
