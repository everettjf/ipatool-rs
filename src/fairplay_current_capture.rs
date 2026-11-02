//! Bounded, authenticated capture adapter for the current semantic recovery.
//! The selected SIDB is never replaced by a different candidate on failure.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    application::operation,
    capture::{CaptureFile, ENROLLMENT_CAPTURE_SCHEMA, EnrollmentCaptureManifest},
    fairplay_current::{outer::Layout, tree::RouteEvidence},
    fairplay_recover_capture::CaptureRecoveryResult,
    fairplay_recovery_output::{write_private_binary, write_private_json},
    fairplay_scinfo::Trust,
};

const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_CAPTURE_FILE: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct CurrentEvidence {
    pub signed_keyfiles: usize,
    pub state_sha256: String,
    pub layout: Layout,
    pub route: RouteEvidence,
    pub plaintext_verified: bool,
}

/// Open each directory relative to its already-open parent. On Unix this
/// prevents intermediate symlink replacement as well as final symlink reads.
fn private_file(root: &Path, relative: &str) -> Result<File> {
    if relative.is_empty()
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(relative)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("capture contains an unsafe relative path");
    }
    #[cfg(unix)]
    {
        use std::{
            ffi::CString,
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::fs::OpenOptionsExt,
            },
        };
        let mut parent = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        require_private(&parent, true)?;
        let parts: Vec<_> = relative.split('/').collect();
        for (index, part) in parts.iter().enumerate() {
            let directory = index + 1 != parts.len();
            let name = CString::new(*part).context("invalid capture path component")?;
            let flags = libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if directory {
                    libc::O_DIRECTORY
                } else {
                    libc::O_NONBLOCK
                };
            // SAFETY: the parent descriptor is live and `name` is terminated.
            let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: openat returned a fresh descriptor owned by this call.
            let child = unsafe { File::from_raw_fd(descriptor) };
            require_private(&child, directory)?;
            parent = child;
        }
        Ok(parent)
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        bail!("current capture recovery requires Unix private-file permissions")
    }
}

#[cfg(unix)]
fn require_private(file: &File, directory: bool) -> Result<()> {
    let meta = file.metadata()?;
    if (directory && !meta.is_dir()) || (!directory && !meta.is_file()) {
        bail!("capture path has an invalid file type");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("capture directories and files must be private");
        }
    }
    Ok(())
}

fn bounded(mut file: File, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    if file.metadata()?.len() > limit as u64 {
        bail!("capture input exceeds its size limit");
    }
    let mut data = Zeroizing::new(Vec::new());
    operation::copy(&mut (&mut file).take(limit as u64 + 1), &mut *data)?;
    if data.len() > limit {
        bail!("capture input grew beyond its size limit");
    }
    Ok(data)
}

fn verify_reader(mut file: File, descriptor: &CaptureFile, mut output: impl Write) -> Result<()> {
    if descriptor.bytes < 0
        || descriptor.bytes as u64 > MAX_CAPTURE_FILE
        || file.metadata()?.len() != descriptor.bytes as u64
    {
        bail!("capture descriptor has an invalid size");
    }
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut block = Zeroizing::new([0u8; 32 * 1024]);
    loop {
        operation::check()?;
        let read = file.read(&mut *block)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > descriptor.bytes as u64 {
            bail!("capture input grew while reading");
        }
        hash.update(&block[..read]);
        output.write_all(&block[..read])?;
    }
    if size != descriptor.bytes as u64 || format!("{:x}", hash.finalize()) != descriptor.sha256 {
        bail!("capture input does not match its descriptor");
    }
    Ok(())
}

struct Input {
    manifest: EnrollmentCaptureManifest,
    manifest_sha256: String,
    hardware: Zeroizing<Vec<u8>>,
    sinf: Zeroizing<Vec<u8>>,
    sidb: Zeroizing<Vec<u8>>,
    signed_keyfiles: usize,
}

fn descriptor<'a>(
    files: &'a BTreeMap<&str, &'a CaptureFile>,
    role: &str,
) -> Result<&'a CaptureFile> {
    files
        .get(role)
        .copied()
        .context("capture is missing a required role descriptor")
}

fn input(root: &Path, trust: &Trust) -> Result<Input> {
    let bytes = bounded(private_file(root, "manifest.json")?, MAX_MANIFEST)?;
    let manifest_sha256 = format!("{:x}", Sha256::digest(&*bytes));
    let manifest: EnrollmentCaptureManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema != ENROLLMENT_CAPTURE_SCHEMA || manifest.files.len() > 4096 {
        bail!("unsupported capture schema or file count");
    }
    if manifest.app.executable.is_empty()
        || manifest.app.executable.contains(['/', '\\'])
        || matches!(manifest.app.executable.as_str(), "." | "..")
        || manifest.app.selector.identifier() != manifest.app.selector_id
    {
        bail!("capture executable or selector metadata is inconsistent");
    }
    let mut files = BTreeMap::new();
    for file in &manifest.files {
        if files.insert(file.path.as_str(), file).is_some() {
            bail!("capture contains duplicate descriptors");
        }
    }
    descriptor(&files, "app/executable")?;
    let hardware = descriptor(&files, &manifest.hardware_iomac.path)?;
    if hardware.bytes != 6
        || hardware.bytes != manifest.hardware_iomac.bytes
        || hardware.sha256 != manifest.hardware_iomac.sha256
    {
        bail!("capture hardware descriptor is inconsistent");
    }
    if !manifest.app.sinf_path.starts_with("app/SC_Info/") {
        bail!("installed SINF must belong to the captured app");
    }
    descriptor(&files, &manifest.app.sinf_path)?;
    let ipa = manifest
        .ipa
        .as_ref()
        .context("recovery requires a matching sample IPA")?;
    let captured = descriptor(&files, &ipa.path)?;
    if ipa.path != "ipa/App.ipa" || ipa.bytes != captured.bytes || ipa.sha256 != captured.sha256 {
        bail!("capture sample IPA descriptor is inconsistent");
    }
    if !manifest.app.target_sinf_path.is_empty() {
        descriptor(&files, &manifest.app.target_sinf_path)?;
    }
    let mut snapshots = BTreeMap::new();
    let mut signed_keyfiles = 0;
    let mut signed_v5 = BTreeSet::new();
    let mut legacy_placeholders = BTreeSet::new();
    let mut sidb: Option<Zeroizing<Vec<u8>>> = None;
    let mut total = 0u64;
    for (path, file) in &files {
        if file.bytes < 0 {
            bail!("negative capture file size");
        }
        total = total
            .checked_add(file.bytes as u64)
            .context("capture size overflow")?;
        if total > 16 * 1024 * 1024 * 1024 {
            bail!("capture exceeds its total size limit");
        }
        let state =
            path.starts_with("state/fpsd-sc-info/") || path.starts_with("state/shared-sc-info/");
        let license = path.starts_with("app/SC_Info/") || state;
        let keyfile = license && (path.ends_with(".supf") || path.ends_with(".supp"));
        let database = state && path.rsplit('/').next() == Some("SC Info.sidb");
        let role = **path == manifest.hardware_iomac.path
            || **path == manifest.app.sinf_path
            || (!manifest.app.target_sinf_path.is_empty()
                && **path == manifest.app.target_sinf_path);
        let mut data = Zeroizing::new(Vec::new());
        let handle = private_file(root, path)?;
        if role || database || keyfile {
            let limit = if database {
                2 * 1024 * 1024
            } else if keyfile {
                128 * 1024 * 1024
            } else {
                1024 * 1024
            };
            if file.bytes as u64 > limit {
                bail!("capture role input exceeds its size limit");
            }
            verify_reader(handle, file, &mut *data)?;
        } else {
            verify_reader(handle, file, std::io::sink())?;
        }
        if keyfile {
            if data.is_empty() && path.ends_with(".supf") && !path.ends_with(".v5.supf") {
                legacy_placeholders
                    .insert(format!("{}.v5.supf", path.strip_suffix(".supf").unwrap()));
                continue;
            }
            let variant = trust.keyfile(&data, path.ends_with(".supp"))?;
            let expected = if path.ends_with(".v5.supf") {
                5
            } else if path.ends_with(".v4.supp") {
                4
            } else if path.ends_with(".supf") {
                3
            } else {
                1
            };
            if variant != expected {
                bail!("capture keyfile suffix disagrees with its variant");
            }
            if variant == 5 {
                signed_v5.insert(path.to_string());
            }
            let name = path.rsplit('/').next().unwrap();
            if [".supf", ".v5.supf", ".supp", ".v4.supp"]
                .iter()
                .any(|suffix| name == format!("{}{suffix}", manifest.app.executable))
            {
                signed_keyfiles += 1;
            }
        }
        if database {
            if data.get(..4) != Some(&[0, 7, 0, 11]) {
                bail!("unsupported SIDB format");
            }
            if let Some(existing) = &sidb {
                if existing.as_slice() != data.as_slice() {
                    bail!("capture contains distinct SIDB databases; selection is ambiguous");
                }
            } else {
                sidb = Some(data);
            }
        } else if role {
            snapshots.insert(*path, data);
        }
    }
    if !legacy_placeholders.is_subset(&signed_v5) {
        bail!("empty captured legacy SUPF requires a signed v5 companion");
    }
    if signed_keyfiles == 0 {
        bail!("recovery requires a signed SUPF or SUPP keyfile for the installed executable");
    }
    let sinf = snapshots
        .remove(manifest.app.sinf_path.as_str())
        .context("missing installed SINF snapshot")?;
    let installed = crate::fairplay::inspect_sinf(&sinf)?;
    if installed.selector != manifest.app.selector || !installed.current_layout {
        bail!("installed SINF does not match the current capture selector");
    }
    if let Some(target) = snapshots.remove(manifest.app.target_sinf_path.as_str())
        && crate::fairplay::parse_sinf_selector(&target)? != manifest.app.selector
    {
        bail!("sample SINF selector does not match the capture");
    }
    let hardware = snapshots
        .remove(manifest.hardware_iomac.path.as_str())
        .context("missing hardware snapshot")?;
    Ok(Input {
        manifest,
        manifest_sha256,
        hardware,
        sinf,
        sidb: sidb.context("capture contains no SIDB database")?,
        signed_keyfiles,
    })
}

pub fn recover(capture: &Path, output: &Path) -> Result<CaptureRecoveryResult> {
    recover_with_trust(capture, output, &Trust::pinned())
}

/// Check bounded role snapshots and signed keyfiles. This deliberately does not
/// claim selected SIDB authentication or successful model/sample validation.
pub fn validate_inputs(capture: &Path) -> Result<()> {
    input(capture, &Trust::pinned()).map(|_| ())
}

fn recover_with_trust(
    capture: &Path,
    output: &Path,
    trust: &Trust,
) -> Result<CaptureRecoveryResult> {
    operation::check()?;
    if fs::symlink_metadata(output).is_ok() {
        bail!("recovery output already exists");
    }
    let input = input(capture, trust)?;
    let recovered = crate::fairplay_current::recover(&input.sidb, &input.hardware, &input.sinf)?;
    let parent = output.parent().context("recovery output needs a parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".current-recovery-")
        .tempdir_in(parent)?;
    let work = staging.path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(work, fs::Permissions::from_mode(0o700))?;
    }
    let candidate = work.join("candidate.bin");
    write_private_binary(&candidate, &recovered.model)?;
    let ipa = input.manifest.ipa.as_ref().expect("validated sample role");
    let sample = work.join("sample.ipa");
    // Decrypt a verified private snapshot, never a path that can be swapped
    // between capture verification and the IPA parser.
    let mut copied = tempfile::NamedTempFile::new_in(work)?;
    verify_reader(private_file(capture, &ipa.path)?, ipa, copied.as_file_mut())?;
    copied.as_file_mut().sync_all()?;
    copied.persist_noclobber(&sample)?;
    let plaintext = work.join("App.decrypted.ipa");
    let decrypted = crate::fairplay_ipa::decrypt_ipa_with_options(
        &sample,
        &plaintext,
        &candidate,
        Some(&work.join("App.decrypted.json")),
        false,
    )?;
    let report_path = work.join("App.decrypted.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&bounded(File::open(&report_path)?, MAX_MANIFEST)?)?;
    report["input"]["path"] = capture.join(&ipa.path).display().to_string().into();
    report["output"]["path"] = output
        .join("App.decrypted.ipa")
        .display()
        .to_string()
        .into();
    fs::remove_file(&report_path)?;
    write_private_json(&report_path, &report)?;
    fs::remove_file(&sample)?;
    let model_hash = format!("{:x}", Sha256::digest(&*recovered.model));
    fs::rename(&candidate, work.join("fairplay-enrollment.bin"))?;
    let result = CaptureRecoveryResult {
        schema: "ipatool-fairplay-enrollment-recovery-v2",
        success: true,
        capture_manifest_sha256: input.manifest_sha256,
        selector: input.manifest.app.selector_id,
        fairplayd_sha256: crate::fairplay_current::algorithm_sha256(),
        capture_fairplayd_sha256: input.manifest.fairplayd.sha256,
        compatibility_profile: None,
        profile: Some("typed-current-enrollment-v1"),
        enrollment_model: output.join("fairplay-enrollment.bin"),
        enrollment_model_sha256: model_hash,
        decrypted_ipa: output.join("App.decrypted.ipa"),
        decrypted_ipa_sha256: decrypted.output_sha256,
        encrypted_images: decrypted.encrypted_images,
        decrypted_pages: decrypted.decrypted_pages,
        all_cryptids_zero: true,
        all_code_directory_slots_match: true,
        differential_cases: None,
        current_evidence: Some(CurrentEvidence {
            signed_keyfiles: input.signed_keyfiles,
            state_sha256: recovered.state_sha256,
            layout: recovered.layout,
            route: recovered.route,
            plaintext_verified: decrypted.plaintext_verified,
        }),
    };
    write_private_json(&work.join("recovery-report.json"), &result)?;
    // Create the destination exclusively before linking any completed files.
    // A competing directory/file is preserved. The model is linked last.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(output)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(output)?;
    let mut linked = Vec::new();
    let published = operation::publish(|| {
        for name in [
            "App.decrypted.ipa",
            "App.decrypted.json",
            "recovery-report.json",
            "fairplay-enrollment.bin",
        ] {
            let target = output.join(name);
            fs::hard_link(work.join(name), &target)?;
            linked.push(target);
        }
        Ok(())
    });
    if let Err(error) = published {
        for path in linked {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(output);
        return Err(error);
    }
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::capture::CaptureApp;
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::PathBuf,
    };
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[derive(serde::Deserialize)]
    struct Control {
        container: Vec<u8>,
        hardware: Vec<u8>,
        sinf: Vec<u8>,
        trap_sinf: Vec<u8>,
        model_sha256: String,
    }
    fn control() -> Control {
        #[derive(serde::Deserialize)]
        struct Vectors {
            controls: Vec<Control>,
        }
        let mut v: Vectors = serde_json::from_str(include_str!(
            "../tests/fixtures/fairplay-current-recovery-public-vectors.json"
        ))
        .unwrap();
        v.controls.remove(1)
    }
    fn put(root: &Path, path: &str, data: &[u8]) -> CaptureFile {
        let full = root.join(path);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(full.parent().unwrap())
            .unwrap();
        fs::write(&full, data).unwrap();
        fs::set_permissions(&full, fs::Permissions::from_mode(0o600)).unwrap();
        CaptureFile {
            path: path.into(),
            bytes: data.len() as i64,
            sha256: format!("{:x}", Sha256::digest(data)),
            mode: "0600".into(),
        }
    }
    fn manifest(root: &Path, value: &EnrollmentCaptureManifest) {
        put(root, "manifest.json", &serde_json::to_vec(value).unwrap());
    }
    fn fixture(root: &Path) -> (PathBuf, EnrollmentCaptureManifest, Trust, String) {
        fixture_with_wrong_key(root, false)
    }

    fn fixture_with_wrong_key(
        root: &Path,
        wrong: bool,
    ) -> (PathBuf, EnrollmentCaptureManifest, Trust, String) {
        let c = control();
        let vectors = crate::fairplay_scinfo::tests::vectors();
        let signed = &vectors
            .controls
            .iter()
            .find(|c| c.variant == 5 && c.accepted)
            .unwrap()
            .keyfile;
        let recovered =
            crate::fairplay_current::recover(&c.container, &c.hardware, &c.sinf).unwrap();
        let mut logical = crate::fairplay_key::CurrentSinfModel::parse(&recovered.model)
            .unwrap()
            .logical_key(&c.sinf)
            .unwrap();
        if wrong {
            logical[0] ^= 1;
        }
        let (image, records, _) = crate::fairplay_decrypt::tests::pre_encryption_fixture(logical);
        assert_eq!(
            crate::fairplay_supf::Supf::parse(signed)
                .unwrap()
                .architectures[0]
                .records,
            records
        );
        let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in [
            ("Payload/A.app/A", &image),
            ("Payload/A.app/SC_Info/A.sinf", &c.sinf),
            ("Payload/A.app/SC_Info/A.v5.supf", signed),
        ] {
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(bytes).unwrap();
        }
        let ipa = zip.finish().unwrap().into_inner();
        let capture = root.join("capture");
        fs::DirBuilder::new().mode(0o700).create(&capture).unwrap();
        let mut files = vec![
            put(&capture, "app/executable", &image),
            put(&capture, "app/SC_Info/A.sinf", &c.sinf),
            put(&capture, "app/SC_Info/A.v5.supf", signed),
            put(&capture, "state/fpsd-sc-info/SC Info.sidb", &c.container),
        ];
        let hardware = put(&capture, "hardware/iomac.bin", &c.hardware);
        let ipa = put(&capture, "ipa/App.ipa", &ipa);
        let target = put(&capture, "ipa/App.sinf", &c.sinf);
        files.extend([hardware.clone(), ipa.clone(), target]);
        let selector = crate::fairplay::parse_sinf_selector(&c.sinf).unwrap();
        let m = EnrollmentCaptureManifest {
            schema: ENROLLMENT_CAPTURE_SCHEMA.into(),
            app: CaptureApp {
                executable: "A".into(),
                selector,
                selector_id: selector.identifier(),
                sinf_path: "app/SC_Info/A.sinf".into(),
                target_sinf_path: "ipa/App.sinf".into(),
                ..Default::default()
            },
            hardware_iomac: hardware,
            ipa: Some(ipa),
            files,
            ..Default::default()
        };
        manifest(&capture, &m);
        (capture, m, vectors.trust(), c.model_sha256)
    }

    #[test]
    fn empty_legacy_keyfile_needs_a_signed_correctly_named_v5_companion() {
        let temp = tempfile::tempdir().unwrap();
        let (capture, mut m, trust, _) = fixture(temp.path());
        let legacy = "app/SC_Info/A.supf";
        m.files.push(put(&capture, legacy, &[]));
        manifest(&capture, &m);
        let prepared = temp.path().join("prepared");
        let result = recover_with_trust(&capture, &prepared, &trust).unwrap();
        assert_eq!(result.decrypted_pages, 2);
        assert_eq!(result.current_evidence.unwrap().signed_keyfiles, 1);
        let signed = fs::read(capture.join("app/SC_Info/A.v5.supf")).unwrap();
        m.files.retain(|file| file.path != "app/SC_Info/A.v5.supf");
        manifest(&capture, &m);
        assert!(
            input(&capture, &trust)
                .err()
                .unwrap()
                .to_string()
                .contains("requires a signed v5")
        );
        *m.files.iter_mut().find(|file| file.path == legacy).unwrap() =
            put(&capture, legacy, &signed);
        manifest(&capture, &m);
        assert!(
            input(&capture, &trust)
                .err()
                .unwrap()
                .to_string()
                .contains("suffix disagrees")
        );
    }

    #[test]
    fn current_capture_recovers_verifies_sample_and_publishes_only_after_success() {
        let temp = tempfile::tempdir().unwrap();
        let (capture, m, trust, hash) = fixture(temp.path());
        let output = temp.path().join("prepared");
        let before = fs::read(capture.join("ipa/App.ipa")).unwrap();
        let result = recover_with_trust(&capture, &output, &trust).unwrap();
        assert_eq!(result.enrollment_model_sha256, hash);
        assert_eq!(result.decrypted_pages, 2);
        let evidence = result.current_evidence.unwrap();
        assert!(evidence.plaintext_verified);
        assert_eq!(evidence.signed_keyfiles, 1);
        assert!(evidence.layout.selected_slot >= 14);
        assert_eq!(fs::read(capture.join("ipa/App.ipa")).unwrap(), before);
        for descriptor in m.files {
            verify_reader(
                private_file(&capture, &descriptor.path).unwrap(),
                &descriptor,
                std::io::sink(),
            )
            .unwrap();
        }
        for name in [
            "fairplay-enrollment.bin",
            "App.decrypted.ipa",
            "App.decrypted.json",
            "recovery-report.json",
        ] {
            assert_eq!(
                fs::metadata(output.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("App.decrypted.json")).unwrap()).unwrap();
        assert_eq!(
            report["output"]["path"],
            output.join("App.decrypted.ipa").display().to_string()
        );
        assert!(recover_with_trust(&capture, &output, &trust).is_err());
        assert!(recover(&capture, &temp.path().join("pinned")).is_err());
        assert!(!temp.path().join("pinned").exists());
    }

    #[test]
    fn rejects_ambiguous_state_and_never_retries_a_record_that_authenticates_another_sinf() {
        let temp = tempfile::tempdir().unwrap();
        let (capture, mut m, trust, _) = fixture(temp.path());
        let c = control();
        let mut second = c.container.clone();
        second[500] ^= 1;
        m.files
            .push(put(&capture, "state/shared-sc-info/SC Info.sidb", &second));
        manifest(&capture, &m);
        assert!(
            input(&capture, &trust)
                .err()
                .unwrap()
                .to_string()
                .contains("distinct SIDB")
        );
        m.files.pop();
        let changed = put(&capture, "app/SC_Info/A.sinf", &c.trap_sinf);
        *m.files
            .iter_mut()
            .find(|d| d.path == "app/SC_Info/A.sinf")
            .unwrap() = changed;
        manifest(&capture, &m);
        let output = temp.path().join("failed");
        assert!(recover_with_trust(&capture, &output, &trust).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn rejects_descriptor_and_signature_tampering_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let (capture, original, trust, _) = fixture(temp.path());
        let mut m = original.clone();
        m.files.push(m.files[0].clone());
        manifest(&capture, &m);
        assert!(
            input(&capture, &trust)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate")
        );
        let mut m = original.clone();
        m.hardware_iomac.bytes = 7;
        manifest(&capture, &m);
        assert!(input(&capture, &trust).is_err());
        let mut m = original;
        let path = "app/SC_Info/A.v5.supf";
        let mut keyfile = fs::read(capture.join(path)).unwrap();
        keyfile[40] ^= 1;
        let changed = put(&capture, path, &keyfile);
        *m.files.iter_mut().find(|d| d.path == path).unwrap() = changed;
        manifest(&capture, &m);
        assert!(
            input(&capture, &trust)
                .err()
                .unwrap()
                .to_string()
                .contains("authentication failed")
        );
        assert!(!temp.path().join("failed").exists());
    }

    #[test]
    fn rejects_private_path_aliases_symlinks_and_public_modes() {
        let temp = tempfile::tempdir().unwrap();
        let (capture, _, trust, _) = fixture(temp.path());
        for path in [
            "",
            "/manifest.json",
            "./manifest.json",
            "hardware/../manifest.json",
            "hardware//iomac.bin",
        ] {
            assert!(private_file(&capture, path).is_err());
        }
        let alias = temp.path().join("alias");
        symlink(&capture, &alias).unwrap();
        assert!(input(&alias, &trust).is_err());
        fs::rename(capture.join("hardware"), capture.join("hardware-real")).unwrap();
        symlink("hardware-real", capture.join("hardware")).unwrap();
        assert!(input(&capture, &trust).is_err());
        fs::remove_file(capture.join("hardware")).unwrap();
        fs::rename(capture.join("hardware-real"), capture.join("hardware")).unwrap();
        fs::set_permissions(
            capture.join("hardware/iomac.bin"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(input(&capture, &trust).is_err());
    }

    #[test]
    fn failed_sample_and_cancellation_leave_no_model_or_staging_directory() {
        let temp = tempfile::tempdir().unwrap();
        let (capture, _, trust, _) = fixture_with_wrong_key(temp.path(), true);
        let output = temp.path().join("failed");
        let error = recover_with_trust(&capture, &output, &trust).unwrap_err();
        assert!(format!("{error:#}").contains("pre-encryption page hashes"));
        assert!(!output.exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);

        let temp = tempfile::tempdir().unwrap();
        let (capture, _, trust, _) = fixture(temp.path());
        let output = temp.path().join("cancelled");
        let slot = std::sync::Arc::new(std::sync::OnceLock::<operation::Operation>::new());
        let callback = slot.clone();
        let op = operation::Operation::new(move |progress| {
            if progress.stage == operation::Stage::Decrypting {
                callback.get().unwrap().cancel();
            }
        });
        slot.set(op.clone()).ok().unwrap();
        let error = op
            .run(|| recover_with_trust(&capture, &output, &trust))
            .unwrap_err();
        assert!(error.downcast_ref::<operation::Cancelled>().is_some());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn recovered_typed_model_can_be_imported_and_matched_after_store_reopen() {
        use crate::application::fairplay_setup::{SavedModels, SetupOptions, SetupRequest};
        let temp = tempfile::tempdir().unwrap();
        let (capture, _, trust, _) = fixture(temp.path());
        let result = recover_with_trust(&capture, &temp.path().join("prepared"), &trust).unwrap();
        let state = temp.path().join("state");
        fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        let store = SavedModels::new(&state);
        store
            .setup(SetupRequest {
                app: Path::new("").to_path_buf(),
                ipa: capture.join("ipa/App.ipa"),
                options: SetupOptions {
                    existing_model: Some(result.enrollment_model),
                    ..Default::default()
                },
            })
            .unwrap();
        drop(store);
        // A different public synthetic archive exercises matching without
        // supplying a model path after reopening the managed store.
        let source = File::open(capture.join("ipa/App.ipa")).unwrap();
        let mut archive = zip::ZipArchive::new(source).unwrap();
        let second = temp.path().join("other.ipa");
        let mut zip = ZipWriter::new(File::create(&second).unwrap());
        for index in 0..archive.len() {
            let mut member = archive.by_index(index).unwrap();
            zip.start_file(
                member
                    .name()
                    .unwrap()
                    .replace("A.app/A", "B.app/B")
                    .replace("A.app/SC_Info/A", "B.app/SC_Info/B"),
                SimpleFileOptions::default(),
            )
            .unwrap();
            std::io::copy(&mut member, &mut zip).unwrap();
        }
        zip.finish().unwrap();
        assert_ne!(
            fs::read(&second).unwrap(),
            fs::read(capture.join("ipa/App.ipa")).unwrap()
        );
        let store = SavedModels::new(&state);
        assert_eq!(store.count().unwrap(), 1);
        store.decrypt_saved(&second, None, None).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(second.with_extension("decrypted.json")).unwrap())
                .unwrap();
        assert_eq!(report["plaintext_verified"], true);
    }
}
