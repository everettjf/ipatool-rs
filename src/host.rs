//! Local macOS FairPlay host inspection and arm64e Mach-O selection.

use std::{fs, path::Path};

#[cfg(target_os = "macos")]
use std::process::Command;

use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "macos", test))]
use plist::Value;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::capture::FairPlayBuildSupport;
#[cfg(target_os = "macos")]
use crate::capture::lookup_fairplay_build;

const CPU_ARM64: u32 = 0x0100_000c;
#[cfg(target_os = "macos")]
const FAIRPLAYD_PATH: &str =
    "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd";

#[derive(Clone, Debug, Serialize)]
pub struct FairPlayHostDiagnostic {
    pub product_version: String,
    pub build_version: String,
    pub fairplayd_sha256: String,
    pub fairplay_support: FairPlayBuildSupport,
    pub state_accessible: bool,
    pub state_files: usize,
    pub hardware_iomac_present: bool,
}

#[derive(Clone, Copy)]
enum Endian {
    Big,
    Little,
}

fn read_u32(bytes: &[u8], endian: Endian) -> Result<u32> {
    let value: [u8; 4] = bytes.try_into().context("truncated Mach-O header")?;
    Ok(match endian {
        Endian::Big => u32::from_be_bytes(value),
        Endian::Little => u32::from_le_bytes(value),
    })
}

fn read_u64(bytes: &[u8], endian: Endian) -> Result<u64> {
    let value: [u8; 8] = bytes.try_into().context("truncated Mach-O header")?;
    Ok(match endian {
        Endian::Big => u64::from_be_bytes(value),
        Endian::Little => u64::from_le_bytes(value),
    })
}

pub fn arm64e_slice(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() < 4 {
        bail!("open fairplayd Mach-O: truncated header");
    }
    let magic = &bytes[..4];
    let (fat, is_64, endian) = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => (true, false, Endian::Big),
        [0xbe, 0xba, 0xfe, 0xca] => (true, false, Endian::Little),
        [0xca, 0xfe, 0xba, 0xbf] => (true, true, Endian::Big),
        [0xbf, 0xba, 0xfe, 0xca] => (true, true, Endian::Little),
        [0xcf, 0xfa, 0xed, 0xfe] => (false, true, Endian::Little),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, true, Endian::Big),
        [0xce, 0xfa, 0xed, 0xfe] => (false, false, Endian::Little),
        [0xfe, 0xed, 0xfa, 0xce] => (false, false, Endian::Big),
        _ => bail!("open fairplayd Mach-O: unsupported magic"),
    };
    if !fat {
        if bytes.len() < if is_64 { 32 } else { 28 } {
            bail!("open fairplayd Mach-O: truncated header");
        }
        let cpu = read_u32(&bytes[4..8], endian)?;
        let subtype = read_u32(&bytes[8..12], endian)?;
        if cpu != CPU_ARM64 || subtype & 0x00ff_ffff != 2 {
            bail!("fairplayd has no arm64e slice");
        }
        return Ok(bytes);
    }
    if bytes.len() < 8 {
        bail!("open fairplayd Mach-O: truncated fat header");
    }
    let count = read_u32(&bytes[4..8], endian)? as usize;
    let stride = if is_64 { 32usize } else { 20usize };
    let table_end = count
        .checked_mul(stride)
        .and_then(|size| size.checked_add(8))
        .context("invalid Mach-O fat archive size")?;
    if table_end > bytes.len() {
        bail!("open fairplayd Mach-O: truncated fat archive");
    }
    let mut selected = None;
    for index in 0..count {
        let entry = &bytes[8 + index * stride..8 + (index + 1) * stride];
        let cpu = read_u32(&entry[..4], endian)?;
        let subtype = read_u32(&entry[4..8], endian)?;
        if cpu != CPU_ARM64 || subtype & 0x00ff_ffff != 2 {
            continue;
        }
        let (offset, size) = if is_64 {
            (
                read_u64(&entry[8..16], endian)?,
                read_u64(&entry[16..24], endian)?,
            )
        } else {
            (
                read_u32(&entry[8..12], endian)? as u64,
                read_u32(&entry[12..16], endian)? as u64,
            )
        };
        let start = usize::try_from(offset).context("Mach-O slice offset overflows host size")?;
        let end = size
            .checked_add(offset)
            .and_then(|end| usize::try_from(end).ok())
            .context("Mach-O slice size overflows host size")?;
        if start >= end || end > bytes.len() {
            bail!("open fairplayd Mach-O: invalid arm64e slice bounds");
        }
        selected = Some(&bytes[start..end]);
        if subtype & 0xff00_0000 == 0 {
            break;
        }
    }
    selected.context("fairplayd has no arm64e slice")
}

pub fn arm64e_macho_hash(path: &Path) -> Result<(String, usize)> {
    let bytes =
        fs::read(path).with_context(|| format!("open fairplayd Mach-O: {}", path.display()))?;
    let slice = arm64e_slice(&bytes)?;
    Ok((format!("{:x}", Sha256::digest(slice)), slice.len()))
}

#[cfg(any(target_os = "macos", test))]
fn ioreg_hardware_mac(data: &[u8], interface: &str) -> Result<[u8; 6]> {
    let root: Value = plist::from_bytes(data).context("parse IORegistry")?;
    fn visit(node: &Value, parent: Option<&Value>, interface: &str) -> Option<[u8; 6]> {
        let dict = node.as_dictionary()?;
        if dict.get("BSD Name").and_then(Value::as_string) == Some(interface)
            && dict.get("IOBuiltin").and_then(Value::as_boolean) == Some(true)
            && let Some(mac) = parent
                .and_then(Value::as_dictionary)
                .and_then(|parent| parent.get("IOMACAddress"))
                .and_then(Value::as_data)
            && let Ok(mac) = <[u8; 6]>::try_from(mac)
        {
            return Some(mac);
        }
        dict.get("IORegistryEntryChildren")?
            .as_array()?
            .iter()
            .find_map(|child| visit(child, Some(node), interface))
    }
    visit(&root, None, interface).with_context(|| {
        format!("built-in interface {interface} has no six-byte parent IOMACAddress")
    })
}

#[cfg(any(target_os = "macos", test))]
fn ioreg_best_hardware_mac(data: &[u8]) -> Result<[u8; 6]> {
    let root: Value = plist::from_bytes(data).context("parse IORegistry")?;
    fn usable(mac: &[u8; 6]) -> bool {
        mac[0] & 1 == 0 && *mac != [0; 6] && *mac != [2, 0, 0, 0, 0, 0]
    }
    fn visit(node: &Value, parent: Option<&Value>, candidates: &mut Vec<(u8, [u8; 6])>) {
        let Some(dict) = node.as_dictionary() else {
            return;
        };
        if let Some(name) = dict.get("BSD Name").and_then(Value::as_string)
            && dict.get("IOBuiltin").and_then(Value::as_boolean) == Some(true)
            && let Some(mac) = parent
                .and_then(Value::as_dictionary)
                .and_then(|parent| parent.get("IOMACAddress"))
                .and_then(Value::as_data)
                .and_then(|mac| <[u8; 6]>::try_from(mac).ok())
            && usable(&mac)
        {
            candidates.push((u8::from(name != "en0"), mac));
        }
        if let Some(children) = dict
            .get("IORegistryEntryChildren")
            .and_then(Value::as_array)
        {
            for child in children {
                visit(child, Some(node), candidates);
            }
        }
    }
    let mut candidates = Vec::new();
    visit(&root, None, &mut candidates);
    candidates.sort_unstable();
    candidates
        .first()
        .map(|(_, mac)| *mac)
        .context("no usable built-in hardware MAC address in IORegistry")
}

/// Hardware identity used by the Store guest and SAP signer on macOS.
pub fn hardware_mac_address() -> Result<[u8; 6]> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/sbin/ioreg")
            .args(["-a", "-l", "-p", "IOService"])
            .output()
            .context("read IORegistry hardware identity")?;
        if !output.status.success() {
            bail!("IORegistry hardware identity query failed");
        }
        ioreg_best_hardware_mac(&output.stdout)
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!("automatic Store hardware identity is not yet implemented for this platform")
    }
}

/// Read the six-byte IOMACAddress of a specific built-in network interface.
pub fn hardware_mac_for_interface(interface: &str) -> Result<[u8; 6]> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/sbin/ioreg")
            .args(["-a", "-l", "-p", "IOService"])
            .output()
            .context("read IORegistry hardware identity")?;
        if !output.status.success() {
            bail!("IORegistry hardware identity query failed");
        }
        ioreg_hardware_mac(&output.stdout, interface)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = interface;
        bail!("automatic FairPlay hardware identity requires macOS")
    }
}

#[cfg(target_os = "macos")]
fn system_version(flag: &str) -> Result<String> {
    let output = Command::new("/usr/bin/sw_vers")
        .arg(flag)
        .output()
        .context("query macOS version")?;
    if !output.status.success() {
        bail!("sw_vers failed: {flag}");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub fn inspect_local_fairplay_host() -> Result<FairPlayHostDiagnostic> {
    #[cfg(not(target_os = "macos"))]
    {
        bail!("local FairPlay host inspection requires macOS");
    }
    #[cfg(target_os = "macos")]
    {
        let product_version = system_version("-productVersion")?;
        let build_version = system_version("-buildVersion")?;
        let (fairplayd_sha256, _) = arm64e_macho_hash(Path::new(FAIRPLAYD_PATH))?;
        let fairplay_support =
            lookup_fairplay_build(&fairplayd_sha256).unwrap_or_else(|| FairPlayBuildSupport {
                build: build_version.clone(),
                status: "unsupported".into(),
                ..FairPlayBuildSupport::default()
            });
        let (state_accessible, state_files) = match fs::read_dir("/private/var/db/fpsd/SC Info") {
            Ok(entries) => {
                let count = entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
                    .count();
                (true, count)
            }
            Err(_) => (false, 0),
        };
        let hardware_iomac_present = Command::new("/usr/sbin/ioreg")
            .args(["-a", "-l", "-p", "IOService"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| ioreg_hardware_mac(&output.stdout, "en0").ok())
            .is_some();
        Ok(FairPlayHostDiagnostic {
            product_version,
            build_version,
            fairplayd_sha256,
            fairplay_support,
            state_accessible,
            state_files,
            hardware_iomac_present,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_arm64e_slice_from_fat_archive() {
        let mut bytes = vec![0u8; 8 + 2 * 20 + 64];
        bytes[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        bytes[4..8].copy_from_slice(&2u32.to_be_bytes());
        let first = &mut bytes[8..28];
        first[..4].copy_from_slice(&CPU_ARM64.to_be_bytes());
        first[4..8].copy_from_slice(&0u32.to_be_bytes());
        first[8..12].copy_from_slice(&48u32.to_be_bytes());
        first[12..16].copy_from_slice(&32u32.to_be_bytes());
        let second = &mut bytes[28..48];
        second[..4].copy_from_slice(&CPU_ARM64.to_be_bytes());
        second[4..8].copy_from_slice(&2u32.to_be_bytes());
        second[8..12].copy_from_slice(&80u32.to_be_bytes());
        second[12..16].copy_from_slice(&32u32.to_be_bytes());
        bytes[80..112].fill(0xa5);
        assert_eq!(arm64e_slice(&bytes).unwrap(), &[0xa5; 32]);
        bytes[32..36].copy_from_slice(&3u32.to_be_bytes());
        assert!(arm64e_slice(&bytes).is_err());
    }

    #[test]
    fn parses_builtin_mac_from_parent_ioreg_node() {
        let mut child = plist::Dictionary::new();
        child.insert("BSD Name".into(), Value::String("en0".into()));
        child.insert("IOBuiltin".into(), Value::Boolean(true));
        let mut parent = plist::Dictionary::new();
        parent.insert("IOMACAddress".into(), Value::Data(vec![1, 2, 3, 4, 5, 6]));
        parent.insert(
            "IORegistryEntryChildren".into(),
            Value::Array(vec![Value::Dictionary(child)]),
        );
        let mut encoded = Vec::new();
        plist::to_writer_xml(&mut encoded, &Value::Dictionary(parent)).unwrap();
        assert_eq!(
            ioreg_hardware_mac(&encoded, "en0").unwrap(),
            [1, 2, 3, 4, 5, 6]
        );
        assert!(ioreg_hardware_mac(&encoded, "en9").is_err());
    }

    #[test]
    fn prefers_en0_physical_mac_and_rejects_unusable_addresses() {
        let interface = |name: &str, mac: Vec<u8>| {
            let mut child = plist::Dictionary::new();
            child.insert("BSD Name".into(), Value::String(name.into()));
            child.insert("IOBuiltin".into(), Value::Boolean(true));
            let mut parent = plist::Dictionary::new();
            parent.insert("IOMACAddress".into(), Value::Data(mac));
            parent.insert(
                "IORegistryEntryChildren".into(),
                Value::Array(vec![Value::Dictionary(child)]),
            );
            Value::Dictionary(parent)
        };
        let mut root = plist::Dictionary::new();
        root.insert(
            "IORegistryEntryChildren".into(),
            Value::Array(vec![
                interface("en4", vec![0x10, 0, 0, 0, 0, 1]),
                interface("en0", vec![0x02, 0, 0, 0, 0, 0]),
                interface("en0", vec![0x20, 0, 0, 0, 0, 2]),
            ]),
        );
        let mut encoded = Vec::new();
        plist::to_writer_xml(&mut encoded, &Value::Dictionary(root)).unwrap();
        assert_eq!(
            ioreg_best_hardware_mac(&encoded).unwrap(),
            [0x20, 0, 0, 0, 0, 2]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "depends on a local macOS hardware interface"]
    fn reads_local_hardware_mac() {
        let mac = hardware_mac_address().unwrap();
        assert_eq!(mac.len(), 6);
        assert_eq!(mac[0] & 1, 0);
    }
}
