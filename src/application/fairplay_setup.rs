//! One-time preparation and private, selector-bound model reuse.
//!
//! Receipts mean the pipeline processed a matching IPA and passed structural
//! checks, not that plaintext or Apple's signature was authenticated.

use super::{
    fairplay,
    operation::{self, Stage},
    tasks::{Artifact, ArtifactKind, JobOutcome},
};
use crate::{
    fairplay::{SinfSelector, inspect_enrollment_model, inspect_ipa_sinfs},
    fairplay_collect::EnrollmentCollectOptions,
    fairplay_recover_capture::RecoverCaptureOptions,
    fairplay_recovery_output::read_private_bytes,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetupRequest {
    pub app: PathBuf,
    pub ipa: PathBuf,
    #[serde(default)]
    pub options: SetupOptions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SetupOptions {
    pub existing_model: Option<PathBuf>,
    pub fairplayd: Option<PathBuf>,
    pub compat_fairplayd: Option<PathBuf>,
    pub startup_profile: Option<PathBuf>,
    pub iokit15_output: Option<PathBuf>,
    pub system_state: Option<PathBuf>,
    pub shared_state: Option<PathBuf>,
    pub adi_state: Option<PathBuf>,
    pub iomac_file: Option<PathBuf>,
    pub interface: String,
    pub product_version: Option<String>,
    pub build_version: Option<String>,
    pub timeout_seconds: u64,
}

impl Default for SetupOptions {
    fn default() -> Self {
        Self {
            existing_model: None,
            fairplayd: None,
            compat_fairplayd: None,
            startup_profile: None,
            iokit15_output: None,
            system_state: None,
            shared_state: None,
            adi_state: None,
            iomac_file: None,
            interface: "en0".into(),
            product_version: None,
            build_version: None,
            timeout_seconds: 600,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ModelProblem {
    Missing,
    NoMatch,
    Ambiguous,
    InvalidStore,
    Collection,
    Recovery,
    Validation,
    UnsupportedPlatform,
}

impl std::fmt::Display for ModelProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "No saved decryption model",
            Self::NoMatch => "No saved model matches this IPA",
            Self::Ambiguous => "More than one saved model matches this IPA",
            Self::InvalidStore => "Saved decryption models need attention",
            Self::Collection => "Could not collect this Mac's authorization materials",
            Self::Recovery => "Could not create a model from these materials",
            Self::Validation => "The model did not pass the matching IPA checks",
            Self::UnsupportedPlatform => {
                "Managed FairPlay models require Unix private-file permissions"
            }
        })
    }
}
impl std::error::Error for ModelProblem {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u32,
    selector: SinfSelector,
    model_sha256: String,
    validation_ipa_sha256: String,
    validation: String,
}

pub struct SavedModels {
    root: PathBuf,
}

fn private_directory(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    check_directory(path)
}

fn check_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("model storage must be a regular private directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("model storage directory must be mode 0700 or stricter");
        }
    }
    Ok(())
}

fn supported_storage() -> Result<()> {
    if cfg!(not(unix)) {
        return Err(ModelProblem::UnsupportedPlatform.into());
    }
    Ok(())
}

fn private_work(root: &Path, prefix: &str) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    Ok(builder.tempdir_in(root)?)
}

fn digest(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        operation::check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Conservative structural gate shared by fresh setup and existing-model import.
fn check_report(path: &Path) -> Result<()> {
    let bytes = read_private_bytes(path, 8 * 1024 * 1024)?;
    let report: serde_json::Value = serde_json::from_slice(&bytes)?;
    let images = report["images"]
        .as_array()
        .context("missing image validation")?;
    if report["schema"] != "ipatool-fairplay-decryption-v1"
        || report["complete"] != true
        || images.is_empty()
        || report["encrypted_image_count"].as_u64() != Some(images.len() as u64)
        || report["decrypted_page_count"].as_u64().unwrap_or(0) == 0
    {
        bail!("incomplete IPA processing report");
    }
    for image in images {
        if image["cryptid_before"].as_u64().unwrap_or(0) == 0
            || image["cryptid_after"] != 0
            || image["pages"].as_u64().unwrap_or(0) == 0
            || image["exact_mutation_scope"] != true
            || image["first_page_structurally_plausible"] != true
        {
            bail!("IPA structure checks did not pass");
        }
        let directories = image["code_directories"]
            .as_array()
            .context("missing code directory audit")?;
        if directories.is_empty() {
            bail!("no embedded code page audit");
        }
        for directory in directories {
            let count = directory["slot_count"]
                .as_u64()
                .filter(|count| *count > 0)
                .context("missing code page count")?;
            if directory["matched_slots"].as_u64() != Some(count) {
                bail!("embedded code page checks did not pass");
            }
        }
    }
    Ok(())
}

impl SavedModels {
    pub fn new(state: &Path) -> Self {
        Self {
            root: state.join("fairplay-models"),
        }
    }
    pub fn directory(&self) -> &Path {
        &self.root
    }

    fn inventory(&self) -> Result<Vec<(Receipt, PathBuf)>> {
        supported_storage()?;
        match fs::symlink_metadata(&self.root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
            Ok(_) => check_directory(&self.root)?,
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            operation::check()?;
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                bail!("invalid model entry");
            };
            if name.starts_with('.') {
                continue;
            }
            if name.len() != 64
                || !name.bytes().all(|c| c.is_ascii_hexdigit())
                || entries.len() >= 256
            {
                bail!("invalid model entry or count");
            }
            check_directory(&entry.path())?;
            let receipt: Receipt = serde_json::from_slice(&read_private_bytes(
                &entry.path().join("receipt.json"),
                4096,
            )?)?;
            let model = entry.path().join("model.bin");
            let bytes = read_private_bytes(&model, 16 * 1024)?;
            let hash = format!("{:x}", Sha256::digest(&*bytes));
            let info = inspect_enrollment_model(&model)?;
            if receipt.schema != 1
                || receipt.validation != "processed-and-structure-checked"
                || receipt.model_sha256 != hash
                || name != hash
                || info.sha256 != hash
                || info.selector != Some(receipt.selector)
                || receipt.validation_ipa_sha256.len() != 64
                || !receipt
                    .validation_ipa_sha256
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit())
            {
                bail!("saved model receipt does not match its contents");
            }
            entries.push((receipt, model));
        }
        Ok(entries)
    }

    pub fn count(&self) -> Result<usize> {
        self.inventory()
            .map(|models| models.len())
            .context(ModelProblem::InvalidStore)
    }

    fn select(&self, ipa: &Path, destination: &Path) -> Result<()> {
        let models = self.inventory().context(ModelProblem::InvalidStore)?;
        if models.is_empty() {
            return Err(ModelProblem::Missing.into());
        }
        let sinfs = inspect_ipa_sinfs(ipa).context(ModelProblem::Validation)?;
        let selectors: BTreeMap<_, _> = sinfs
            .into_iter()
            .map(|s| (s.selector_id, s.selector))
            .collect();
        if selectors.is_empty() {
            return Err(ModelProblem::Validation.into());
        }
        for selector in selectors.values() {
            let matches: Vec<_> = models
                .iter()
                .filter(|(receipt, _)| receipt.selector == *selector)
                .collect();
            let (receipt, path) = match matches.as_slice() {
                [] => return Err(ModelProblem::NoMatch.into()),
                [model] => *model,
                _ => return Err(ModelProblem::Ambiguous.into()),
            };
            let bytes = read_private_bytes(path, 16 * 1024)?;
            if format!("{:x}", Sha256::digest(&*bytes)) != receipt.model_sha256 {
                return Err(ModelProblem::InvalidStore.into());
            }
            write_private(
                &destination.join(format!("{}.bin", receipt.model_sha256)),
                &bytes,
            )?;
        }
        Ok(())
    }

    fn save(&self, model: &Path, ipa: &Path) -> Result<PathBuf> {
        operation::check()?;
        let bytes = read_private_bytes(model, 16 * 1024)?;
        let info = inspect_enrollment_model(model)?;
        let selector = info
            .selector
            .context("automatic matching requires a selector-bound model")?;
        let sinfs = inspect_ipa_sinfs(ipa)?;
        if sinfs.is_empty()
            || sinfs
                .iter()
                .any(|s| s.selector != selector || !s.current_layout)
        {
            return Err(ModelProblem::Validation.into());
        }
        let hash = format!("{:x}", Sha256::digest(&*bytes));
        if info.sha256 != hash {
            return Err(ModelProblem::Validation.into());
        }
        let existing = self.inventory().context(ModelProblem::InvalidStore)?;
        for (receipt, path) in existing {
            if receipt.selector == selector {
                if receipt.model_sha256 == hash {
                    return Ok(path);
                }
                return Err(ModelProblem::Ambiguous.into());
            }
        }
        let staging = private_work(&self.root, ".publish-")?;
        write_private(&staging.path().join("model.bin"), &bytes)?;
        let receipt = Receipt {
            schema: 1,
            selector,
            model_sha256: hash.clone(),
            validation_ipa_sha256: digest(ipa)?,
            validation: "processed-and-structure-checked".into(),
        };
        write_private(
            &staging.path().join("receipt.json"),
            &serde_json::to_vec(&receipt)?,
        )?;
        let target = self.root.join(hash);
        operation::publish(|| fs::rename(staging.path(), &target).map_err(anyhow::Error::from))?;
        Ok(target.join("model.bin"))
    }

    pub fn setup(&self, request: SetupRequest) -> Result<JobOutcome> {
        supported_storage()?;
        operation::check()?;
        if !(1..=3600).contains(&request.options.timeout_seconds) {
            bail!("setup phase timeout must be between 1 and 3600 seconds");
        }
        private_directory(&self.root).context(ModelProblem::InvalidStore)?;
        let work = private_work(&self.root, ".setup-")?;
        let before = digest(&request.ipa)?;
        let o = &request.options;
        let model = if let Some(model) = &o.existing_model {
            operation::stage(Stage::ValidatingModel)?;
            let candidates =
                crate::fairplay::inspect_model_registry(model).context(ModelProblem::Validation)?;
            let sinfs = inspect_ipa_sinfs(&request.ipa).context(ModelProblem::Validation)?;
            let matches: Vec<_> = candidates
                .iter()
                .filter(|candidate| {
                    candidate.selector.is_some()
                        && sinfs
                            .iter()
                            .all(|sinf| Some(sinf.selector) == candidate.selector)
                })
                .collect();
            let [selected] = matches.as_slice() else {
                return Err(ModelProblem::Validation.into());
            };
            let copied = work.path().join("import.bin");
            write_private(
                &copied,
                &read_private_bytes(Path::new(&selected.path), 16 * 1024)?,
            )?;
            let report = work.path().join("validation.json");
            fairplay::decrypt(
                &request.ipa,
                &work.path().join("validation.ipa"),
                &copied,
                Some(&report),
                false,
            )
            .context(ModelProblem::Validation)?;
            check_report(&report).context(ModelProblem::Validation)?;
            copied
        } else {
            fairplay::collect(&EnrollmentCollectOptions {
                app: request.app,
                ipa: Some(request.ipa.clone()),
                output: work.path().join("capture"),
                fairplayd: o.fairplayd.clone(),
                system_state: o.system_state.clone(),
                shared_state: o.shared_state.clone(),
                adi_state: o.adi_state.clone(),
                iomac_file: o.iomac_file.clone(),
                interface: o.interface.clone(),
                product_version: o.product_version.clone(),
                build_version: o.build_version.clone(),
            })
            .context(ModelProblem::Collection)?;
            let output = work.path().join("recovery");
            let recovered = fairplay::recover(RecoverCaptureOptions {
                capture: &work.path().join("capture"),
                output: &output,
                compat_fairplayd: o.compat_fairplayd.as_deref(),
                startup_profile: o.startup_profile.as_deref(),
                iokit15_output: o.iokit15_output.as_deref(),
                timeout: Duration::from_secs(o.timeout_seconds),
                native_26b_research: false,
                skip_differential: false,
            })
            .context(ModelProblem::Recovery)?;
            if !recovered.success
                || !recovered.all_cryptids_zero
                || !recovered.all_code_directory_slots_match
                || recovered.encrypted_images == 0
                || recovered.decrypted_pages == 0
                || digest(&recovered.enrollment_model)? != recovered.enrollment_model_sha256
            {
                return Err(ModelProblem::Validation.into());
            }
            check_report(&output.join("App.decrypted.json")).context(ModelProblem::Validation)?;
            recovered.enrollment_model
        };
        operation::stage(Stage::ValidatingModel)?;
        if before != digest(&request.ipa)? {
            return Err(ModelProblem::Validation.into());
        }
        let model = self.save(&model, &request.ipa).map_err(|error| {
            if error.downcast_ref::<ModelProblem>().is_some() {
                error
            } else {
                error.context(ModelProblem::Validation)
            }
        })?;
        Ok(JobOutcome { summary: "Reusable decryption is prepared. A model passed processing and structural checks with your sample IPA and was saved privately. Matching future downloads can reuse it. Plaintext correctness and Apple signatures are not authenticated.".into(), artifacts: vec![Artifact { kind: ArtifactKind::Model, path: model }], details: None })
    }

    pub fn decrypt_saved(
        &self,
        input: &Path,
        output: Option<&Path>,
        report: Option<&Path>,
    ) -> Result<JobOutcome> {
        supported_storage()?;
        operation::stage(Stage::Inspecting)?;
        // Do not create storage just to discover that setup has not run.
        if self.count()? == 0 {
            return Err(ModelProblem::Missing.into());
        }
        let selected = private_work(&self.root, ".selected-")?;
        self.select(input, selected.path())?;
        let output = output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| input.with_extension("decrypted.ipa"));
        let report = report
            .map(Path::to_path_buf)
            .unwrap_or_else(|| input.with_extension("decrypted.json"));
        if output.try_exists()? || report.try_exists()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "decryption output or report already exists",
            )
            .into());
        }
        fairplay::execute(super::fairplay::FairPlayRequest::Decrypt {
            input: input.to_path_buf(),
            model: selected.path().to_path_buf(),
            output,
            report,
            force: false,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        application::{
            failure::{Failure, FailureKind},
            operation::Operation,
        },
        fairplay_decrypt::tests::encrypted_fixture,
        fairplay_ipa::tests::{model_and_sinf, supf},
    };

    fn fixture(directory: &Path, name: &str, logical: [u8; 16]) -> (PathBuf, PathBuf) {
        fixture_with_selector(directory, name, logical, 9)
    }

    fn fixture_with_selector(
        directory: &Path,
        name: &str,
        logical: [u8; 16],
        key: u32,
    ) -> (PathBuf, PathBuf) {
        let (old, mut sinf) = model_and_sinf(logical);
        sinf[36..40].copy_from_slice(&key.to_be_bytes());
        let mut model = old[..48].to_vec();
        model.extend(7u32.to_le_bytes());
        model.extend(key.to_le_bytes());
        model.extend(&old[48..]);
        model[..8].copy_from_slice(b"FPSENR2\0");
        model[8..12].copy_from_slice(&2u32.to_le_bytes());
        let length = model.len() as u32;
        model[12..16].copy_from_slice(&length.to_le_bytes());
        let path = directory.join(format!("{name}.bin"));
        write_private(&path, &model).unwrap();
        let ipa = directory.join(format!("{name}.ipa"));
        let (encrypted, record, _) = encrypted_fixture(logical);
        let mut writer = zip::ZipWriter::new(fs::File::create(&ipa).unwrap());
        for (member, bytes) in [
            ("Payload/A.app/SC_Info/A.sinf", sinf),
            ("Payload/A.app/SC_Info/A.supf", supf(record)),
            ("Payload/A.app/A", encrypted),
        ] {
            writer
                .start_file(member, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
        (ipa, path)
    }

    fn import(ipa: &Path, model: &Path) -> SetupRequest {
        SetupRequest {
            app: PathBuf::new(),
            ipa: ipa.to_path_buf(),
            options: SetupOptions {
                existing_model: Some(model.to_path_buf()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn validates_saves_and_reuses_one_enrollment_for_different_app_keys() {
        let directory = tempfile::tempdir().unwrap();
        let store = SavedModels::new(directory.path());
        let (ipa, model) = fixture(directory.path(), "sample", [0x31; 16]);
        let original = fs::read(&ipa).unwrap();
        let outcome = Operation::default()
            .run(|| store.setup(import(&ipa, &model)))
            .unwrap();
        assert_eq!(outcome.artifacts.len(), 1);
        assert_eq!(store.count().unwrap(), 1);
        Operation::default()
            .run(|| store.setup(import(&ipa, &model)))
            .unwrap();
        assert_eq!(
            store.count().unwrap(),
            1,
            "identical validated setup is idempotent"
        );
        assert!(
            fs::read_dir(store.directory()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with('.')),
            "temporary captures and plaintext were removed"
        );
        let (another_ipa, _) = fixture(directory.path(), "another-app", [0x55; 16]);
        let another_original = fs::read(&another_ipa).unwrap();
        let result = Operation::default()
            .run(|| store.decrypt_saved(&another_ipa, None, None))
            .unwrap();
        assert_eq!(result.artifacts[0].kind, ArtifactKind::DecryptedIpa);
        assert!(another_ipa.with_extension("decrypted.ipa").is_file());
        assert_eq!(fs::read(&ipa).unwrap(), original);
        assert_eq!(fs::read(&another_ipa).unwrap(), another_original);
        let error = Operation::default()
            .run(|| store.decrypt_saved(&another_ipa, None, None))
            .unwrap_err();
        assert_eq!(Failure::from_error(&error).kind, FailureKind::OutputExists);
    }

    #[test]
    fn missing_mismatched_or_unverified_models_never_produce_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let store = SavedModels::new(directory.path());
        let (ipa, model) = fixture(directory.path(), "sample", [0x31; 16]);
        let error = store.decrypt_saved(&ipa, None, None).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ModelProblem>(),
            Some(ModelProblem::Missing)
        ));
        assert!(!store.directory().exists());
        let mut wrong = fs::read(&model).unwrap();
        wrong[56] ^= 1;
        let wrong_path = directory.path().join("wrong.bin");
        write_private(&wrong_path, &wrong).unwrap();
        assert!(
            Operation::default()
                .run(|| store.setup(import(&ipa, &wrong_path)))
                .is_err()
        );
        assert_eq!(store.count().unwrap(), 0);
        Operation::default()
            .run(|| store.setup(import(&ipa, &model)))
            .unwrap();
        let (other_ipa, _) =
            fixture_with_selector(directory.path(), "different-enrollment", [0x31; 16], 10);
        let error = store.decrypt_saved(&other_ipa, None, None).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ModelProblem>(),
            Some(ModelProblem::NoMatch)
        ));
        assert!(!other_ipa.with_extension("decrypted.ipa").exists());
        let isolated = tempfile::tempdir().unwrap();
        let other_store = SavedModels::new(isolated.path());
        private_directory(other_store.directory()).unwrap();
        // A bare file copied into managed storage is not a validated receipt.
        write_private(
            &other_store.directory().join("unverified.bin"),
            &fs::read(&model).unwrap(),
        )
        .unwrap();
        assert!(other_store.decrypt_saved(&ipa, None, None).is_err());
        let selected = tempfile::tempdir().unwrap();
        let models = store.inventory().unwrap();
        let model_file = &models[0].1;
        let receipt_file = model_file.parent().unwrap().join("receipt.json");
        let mut receipt: Receipt =
            serde_json::from_slice(&fs::read(&receipt_file).unwrap()).unwrap();
        receipt.selector.key = 10;
        fs::write(&receipt_file, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(store.select(&ipa, selected.path()).is_err());
        assert!(!ipa.with_extension("decrypted.ipa").exists());
    }

    #[test]
    fn cancellation_conflicting_models_and_private_file_changes_fail_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let store = SavedModels::new(directory.path());
        let (ipa, model) = fixture(directory.path(), "sample", [0x31; 16]);
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<Operation>));
        let cancel = slot.clone();
        let operation = Operation::new(move |progress| {
            if progress.stage == Stage::Decrypting {
                cancel.lock().unwrap().as_ref().unwrap().cancel();
            }
        });
        *slot.lock().unwrap() = Some(operation.clone());
        let error = operation
            .run(|| store.setup(import(&ipa, &model)))
            .unwrap_err();
        assert_eq!(
            Failure::from_error(&error.context(ModelProblem::Validation)).kind,
            FailureKind::Cancelled
        );
        assert_eq!(
            store.count().unwrap(),
            0,
            "cancelled validation did not activate a model"
        );
        assert!(fs::read_dir(store.directory()).unwrap().next().is_none());
        Operation::default()
            .run(|| store.setup(import(&ipa, &model)))
            .unwrap();
        let mut conflicting = fs::read(&model).unwrap();
        conflicting[16] = 1;
        let conflict = directory.path().join("conflicting.bin");
        write_private(&conflict, &conflicting).unwrap();
        let error = Operation::default()
            .run(|| store.setup(import(&ipa, &conflict)))
            .unwrap_err();
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<ModelProblem>()
                .is_some_and(|p| matches!(p, ModelProblem::Ambiguous))
        }));
        assert_eq!(store.count().unwrap(), 1);
        let model_file = store.inventory().unwrap()[0].1.clone();
        let moved = directory.path().join("external.bin");
        fs::rename(&model_file, &moved).unwrap();
        symlink(&moved, &model_file).unwrap();
        assert!(store.count().is_err());
        fs::remove_file(&model_file).unwrap();
        fs::rename(&moved, &model_file).unwrap();
        fs::set_permissions(store.directory(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(store.count().is_err());
    }

    #[test]
    fn structural_report_gate_rejects_incomplete_or_unchecked_output() {
        let directory = tempfile::tempdir().unwrap();
        let report = directory.path().join("report.json");
        let mut value = serde_json::json!({"schema":"ipatool-fairplay-decryption-v1","complete":true,"encrypted_image_count":1,"decrypted_page_count":1,"images":[{"cryptid_before":1,"cryptid_after":0,"pages":1,"exact_mutation_scope":true,"first_page_structurally_plausible":true,"code_directories":[{"slot_count":1,"matched_slots":1}]}]});
        write_private(&report, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(check_report(&report).is_ok());
        value["images"][0]["code_directories"][0]["matched_slots"] = 0.into();
        fs::write(&report, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(check_report(&report).is_err());
        value["images"][0]["code_directories"][0]["matched_slots"] = 1.into();
        value["complete"] = false.into();
        fs::write(&report, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(check_report(&report).is_err());
    }
}
