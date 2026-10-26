//! Collect a private native FairPlay enrollment capture for offline recovery.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use plist::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zip::ZipArchive;

use crate::{
    capture::{
        CaptureApp, CaptureFile, ENROLLMENT_CAPTURE_SCHEMA, EnrollmentCaptureManifest,
        FairPlayBuildSupport, lookup_fairplay_build,
    },
    fairplay::{SinfSelector, parse_sinf_selector},
    host::{arm64e_slice, hardware_mac_for_interface},
};

const FAIRPLAYD_PATH: &str =
    "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd";
const SYSTEM_STATE_PATH: &str = "/private/var/db/fpsd/SC Info";
const SHARED_STATE_PATH: &str = "/Users/Shared/SC Info";
const ADI_STATE_PATH: &str = "/private/var/db/fpsd/adi";

#[derive(Default)]
pub struct EnrollmentCollectOptions {
    pub app: PathBuf,
    pub ipa: Option<PathBuf>,
    pub output: PathBuf,
    pub fairplayd: Option<PathBuf>,
    pub system_state: Option<PathBuf>,
    pub shared_state: Option<PathBuf>,
    pub adi_state: Option<PathBuf>,
    pub iomac_file: Option<PathBuf>,
    pub interface: String,
    pub product_version: Option<String>,
    pub build_version: Option<String>,
}

fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<File> {
    private_directory(path.parent().context("capture destination has no parent")?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn captured_file(relative: &Path, size: u64, sha256: String) -> CaptureFile {
    CaptureFile {
        path: relative.to_string_lossy().replace('\\', "/"),
        bytes: size as i64,
        sha256,
        mode: "0600".into(),
    }
}

fn write_private(root: &Path, relative: &Path, bytes: &[u8]) -> Result<CaptureFile> {
    let mut file = private_file(&root.join(relative))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(captured_file(
        relative,
        bytes.len() as u64,
        format!("{:x}", Sha256::digest(bytes)),
    ))
}

fn copy_private(root: &Path, relative: &Path, source: &Path) -> Result<CaptureFile> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect capture source {}", source.display()))?;
    if !metadata.file_type().is_file() {
        bail!("capture source is not a regular file: {}", source.display());
    }
    let mut input = File::open(source)?;
    let mut output = private_file(&root.join(relative))?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
        size += count as u64;
    }
    output.sync_all()?;
    Ok(captured_file(
        relative,
        size,
        format!("{:x}", hash.finalize()),
    ))
}

fn copy_tree(root: &Path, source: &Path, relative: &Path) -> Result<Vec<CaptureFile>> {
    let metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() {
        bail!(
            "capture state path is not a directory: {}",
            source.display()
        );
    }
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut files = Vec::new();
    for entry in entries {
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!(
                "capture state contains a symlink: {}",
                entry.path().display()
            );
        }
        let target = relative.join(entry.file_name());
        if kind.is_dir() {
            files.extend(copy_tree(root, &entry.path(), &target)?);
        } else if kind.is_file() {
            files.push(copy_private(root, &target, &entry.path())?);
        } else {
            bail!(
                "capture state contains a non-regular file: {}",
                entry.path().display()
            );
        }
    }
    Ok(files)
}

fn installed_app(path: &Path) -> Result<PathBuf> {
    if !path.is_dir()
        || !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
    {
        bail!("installed app path must name an .app directory");
    }
    let wrapper = path.join("Wrapper");
    if !wrapper.exists() {
        return Ok(path.to_path_buf());
    }
    let app = fs::read_dir(wrapper)?
        .filter_map(std::result::Result::ok)
        .find(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        })
        .context("outer app wrapper contains no inner .app")?;
    Ok(app.path())
}

fn app_info(app: &Path) -> Result<(String, String, Vec<u8>)> {
    let bytes = fs::read(app.join("Info.plist")).context("read app Info.plist")?;
    let value: Value = plist::from_bytes(&bytes).context("parse app Info.plist")?;
    let fields = value
        .as_dictionary()
        .context("app Info.plist is not a dictionary")?;
    let bundle = fields
        .get("CFBundleIdentifier")
        .and_then(Value::as_string)
        .unwrap_or("");
    let executable = fields
        .get("CFBundleExecutable")
        .and_then(Value::as_string)
        .unwrap_or("");
    if bundle.is_empty()
        || executable.is_empty()
        || executable.contains('/')
        || executable.contains('\\')
    {
        bail!("app Info.plist lacks a valid bundle identifier or executable");
    }
    Ok((bundle.into(), executable.into(), bytes))
}

fn installed_sinf(app: &Path) -> Result<(PathBuf, SinfSelector)> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(app.join("SC_Info"))? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sinf"))
        {
            paths.push(entry.path());
        }
    }
    if paths.len() != 1 {
        bail!(
            "installed app must contain exactly one root SINF, found {}",
            paths.len()
        );
    }
    let selector = parse_sinf_selector(&fs::read(&paths[0])?)?;
    Ok((paths.pop().unwrap(), selector))
}

fn hardware_mac(path: Option<&Path>, interface: &str) -> Result<[u8; 6]> {
    let Some(path) = path else {
        return hardware_mac_for_interface(interface);
    };
    let bytes = fs::read(path)?;
    if let Ok(mac) = <[u8; 6]>::try_from(bytes.as_slice()) {
        return Ok(mac);
    }
    let text: String = String::from_utf8(bytes)?;
    let hex: String = text
        .chars()
        .filter(|character| !matches!(character, ':' | '-' | ' ' | '\r' | '\n'))
        .collect();
    if hex.len() != 12 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("hardware IOMACAddress must contain six bytes");
    }
    let mut result = [0u8; 6];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}

fn system_version(flag: &str) -> Result<String> {
    let result = Command::new("/usr/bin/sw_vers").arg(flag).output()?;
    if !result.status.success() {
        bail!("sw_vers failed: {flag}");
    }
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}

fn capture_ipa(
    root: &Path,
    source: &Path,
    selector: SinfSelector,
    executable: &str,
) -> Result<(CaptureFile, String, CaptureFile)> {
    let mut archive = ZipArchive::new(File::open(source)?)?;
    let mut roots = Vec::new();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index)?;
        let name = member.name().to_owned();
        if !name.contains("/SC_Info/") || !name.to_ascii_lowercase().ends_with(".sinf") {
            continue;
        }
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes)?;
        if parse_sinf_selector(&bytes).ok() == Some(selector) {
            roots.push(name.split("/SC_Info/").next().unwrap().to_owned());
        }
    }
    roots.sort_by_key(String::len);
    let ipa_root = roots.into_iter().next().with_context(|| {
        format!(
            "IPA contains no SINF matching selector {}",
            selector.identifier()
        )
    })?;
    let target_name = format!("{ipa_root}/SC_Info/{executable}.sinf");
    let mut target = Vec::new();
    archive
        .by_name(&target_name)
        .with_context(|| format!("IPA member not found: {target_name}"))?
        .read_to_end(&mut target)?;
    if parse_sinf_selector(&target)? != selector {
        bail!("IPA target SINF selector mismatch");
    }
    let copied = copy_private(root, Path::new("ipa/App.ipa"), source)?;
    let target_file = write_private(root, Path::new("ipa/App.sinf"), &target)?;
    Ok((copied, ipa_root, target_file))
}

pub fn collect_enrollment(options: &EnrollmentCollectOptions) -> Result<EnrollmentCaptureManifest> {
    if options.app.as_os_str().is_empty() || options.output.as_os_str().is_empty() {
        bail!("capture requires app and output paths");
    }
    if !cfg!(target_os = "macos")
        && (options.product_version.is_none()
            || options.build_version.is_none()
            || options.iomac_file.is_none())
    {
        bail!("native enrollment collection requires macOS");
    }
    if options.output.exists() {
        bail!(
            "capture output already exists: {}",
            options.output.display()
        );
    }
    let app = installed_app(&options.app)?;
    let (bundle, executable, info_bytes) = app_info(&app)?;
    let (sinf_path, selector) = installed_sinf(&app)?;
    let product_version = match &options.product_version {
        Some(value) => value.clone(),
        None => system_version("-productVersion")?,
    };
    let build_version = match &options.build_version {
        Some(value) => value.clone(),
        None => system_version("-buildVersion")?,
    };
    let fairplayd_path = options
        .fairplayd
        .as_deref()
        .unwrap_or_else(|| Path::new(FAIRPLAYD_PATH));
    let fairplayd_bytes = fs::read(fairplayd_path).context("read fairplayd Mach-O")?;
    let fairplayd_slice = arm64e_slice(&fairplayd_bytes)?;
    let mac = hardware_mac(
        options.iomac_file.as_deref(),
        if options.interface.is_empty() {
            "en0"
        } else {
            &options.interface
        },
    )?;
    let parent = options.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".fairplay-capture-")
        .tempdir_in(parent)?;
    let root = staging.path();
    let mut files = Vec::new();
    let fairplayd = write_private(
        root,
        Path::new("fairplayd/fairplayd.arm64e"),
        fairplayd_slice,
    )?;
    files.push(fairplayd.clone());
    let support =
        lookup_fairplay_build(&fairplayd.sha256).unwrap_or_else(|| FairPlayBuildSupport {
            build: build_version.clone(),
            status: "unsupported".into(),
            ..FairPlayBuildSupport::default()
        });
    let hardware_iomac = write_private(root, Path::new("hardware/iomac.bin"), &mac)?;
    files.push(hardware_iomac.clone());
    files.push(write_private(
        root,
        Path::new("app/Info.plist"),
        &info_bytes,
    )?);
    let executable_path = app.join(&executable);
    files.push(copy_private(
        root,
        Path::new("app/executable"),
        &executable_path,
    )?);
    let sinf_relative = format!(
        "app/SC_Info/{}",
        sinf_path.file_name().unwrap().to_string_lossy()
    );
    let licenses = copy_tree(root, &app.join("SC_Info"), Path::new("app/SC_Info"))?;
    files.extend(licenses);
    let mut state_count = 0;
    for (source, relative) in [
        (
            options
                .system_state
                .as_deref()
                .unwrap_or_else(|| Path::new(SYSTEM_STATE_PATH)),
            "state/fpsd-sc-info",
        ),
        (
            options
                .shared_state
                .as_deref()
                .unwrap_or_else(|| Path::new(SHARED_STATE_PATH)),
            "state/shared-sc-info",
        ),
        (
            options
                .adi_state
                .as_deref()
                .unwrap_or_else(|| Path::new(ADI_STATE_PATH)),
            "state/adi",
        ),
    ] {
        let captured = copy_tree(root, source, Path::new(relative))?;
        state_count += captured.len();
        files.extend(captured);
    }
    if state_count == 0 {
        bail!("capture found no native FairPlay state files");
    }
    let (ipa, ipa_root, target_sinf_path) = if let Some(source) = options.ipa.as_deref() {
        let (copied, root_name, target) = capture_ipa(root, source, selector, &executable)?;
        files.push(copied.clone());
        files.push(target.clone());
        (Some(copied), root_name, target.path)
    } else {
        (None, String::new(), String::new())
    };
    let mut warnings = Vec::new();
    if ipa.is_none() {
        warnings.push("capture has no IPA; recovery requires a matching personalized IPA".into());
    }
    if support.status == "unsupported" {
        warnings.push("fairplayd hash is not supported".into());
    }
    let manifest = EnrollmentCaptureManifest {
        schema: ENROLLMENT_CAPTURE_SCHEMA.into(),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        product_version,
        build_version,
        fairplayd,
        fairplay: support,
        hardware_iomac,
        app: CaptureApp {
            bundle_identifier: bundle,
            executable: executable.clone(),
            executable_path: executable_path.display().to_string(),
            selector,
            selector_id: selector.identifier(),
            sinf_path: sinf_relative,
            target_sinf_path,
            ipa_member_root: ipa_root,
        },
        ipa,
        files,
        warnings,
    };
    let mut output = private_file(&root.join("manifest.json"))?;
    serde_json::to_writer_pretty(&mut output, &manifest)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    fs::rename(root, &options.output)
        .with_context(|| format!("publish capture {}", options.output.display()))?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::load_enrollment_capture;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn atom(name: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&((data.len() + 8) as u32).to_be_bytes());
        result.extend_from_slice(&name);
        result.extend_from_slice(data);
        result
    }

    fn sinf() -> Vec<u8> {
        let mut fields = Vec::new();
        fields.extend(atom(*b"user", &7u32.to_be_bytes()));
        fields.extend(atom(*b"key ", &9u32.to_be_bytes()));
        fields.extend(atom(*b"priv", b"sample"));
        atom(*b"sinf", &atom(*b"schi", &fields))
    }

    #[test]
    fn collects_private_capture_matching_installed_app_and_ipa() {
        let directory = tempfile::tempdir().unwrap();
        let app = directory.path().join("A.app");
        fs::create_dir_all(app.join("SC_Info")).unwrap();
        fs::write(app.join("Info.plist"), br#"<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.a</string><key>CFBundleExecutable</key><string>A</string></dict></plist>"#).unwrap();
        fs::write(app.join("A"), b"installed executable").unwrap();
        fs::write(app.join("SC_Info/A.sinf"), sinf()).unwrap();
        let fairplayd = directory.path().join("fairplayd");
        let mut macho = [0u8; 32];
        macho[..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        macho[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        macho[8..12].copy_from_slice(&2u32.to_le_bytes());
        fs::write(&fairplayd, macho).unwrap();
        let mac = directory.path().join("iomac.txt");
        fs::write(&mac, b"01:23:45:67:89:ab\n").unwrap();
        let system = directory.path().join("system-state");
        fs::create_dir_all(&system).unwrap();
        fs::write(system.join("state.bin"), b"private state").unwrap();
        let ipa = directory.path().join("App.ipa");
        let mut writer = ZipWriter::new(File::create(&ipa).unwrap());
        writer
            .start_file("Payload/A.app/SC_Info/A.sinf", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&sinf()).unwrap();
        writer.finish().unwrap();
        let output = directory.path().join("capture");
        let manifest = collect_enrollment(&EnrollmentCollectOptions {
            app,
            ipa: Some(ipa),
            output: output.clone(),
            fairplayd: Some(fairplayd),
            system_state: Some(system),
            shared_state: Some(directory.path().join("missing-shared")),
            adi_state: Some(directory.path().join("missing-adi")),
            iomac_file: Some(mac),
            product_version: Some("27.0.1".into()),
            build_version: Some("test-build".into()),
            ..EnrollmentCollectOptions::default()
        })
        .unwrap();
        assert_eq!(manifest.app.selector_id, "00000007:00000009");
        assert_eq!(manifest.app.ipa_member_root, "Payload/A.app");
        assert_eq!(manifest.hardware_iomac.bytes, 6);
        assert!(
            manifest
                .files
                .iter()
                .any(|file| file.path == "state/fpsd-sc-info/state.bin")
        );
        assert!(load_enrollment_capture(&output, true).is_ok());
        assert!(
            collect_enrollment(&EnrollmentCollectOptions {
                output: output.clone(),
                ..EnrollmentCollectOptions::default()
            })
            .is_err()
        );
    }
}
