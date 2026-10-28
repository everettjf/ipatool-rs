//! Front-end-independent FairPlay requests and artifact results.

use super::{
    operation::{self, Stage},
    tasks::{Artifact, ArtifactKind, JobOutcome},
};
use crate::{
    fairplay::write_doctor_report, fairplay_collect::EnrollmentCollectOptions,
    fairplay_recover_capture::RecoverCaptureOptions,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FairPlayRequest {
    Inspect {
        ipa: Option<PathBuf>,
        model: Option<PathBuf>,
        capture: Option<PathBuf>,
        report: Option<PathBuf>,
    },
    Decrypt {
        input: PathBuf,
        model: PathBuf,
        output: PathBuf,
        report: PathBuf,
        force: bool,
    },
    Collect {
        app: PathBuf,
        ipa: Option<PathBuf>,
        output: PathBuf,
        fairplayd: Option<PathBuf>,
        system_state: Option<PathBuf>,
        shared_state: Option<PathBuf>,
        adi_state: Option<PathBuf>,
        iomac_file: Option<PathBuf>,
        interface: String,
        product_version: Option<String>,
        build_version: Option<String>,
    },
    Recover {
        capture: PathBuf,
        output: PathBuf,
        compat_fairplayd: Option<PathBuf>,
        startup_profile: Option<PathBuf>,
        iokit15_output: Option<PathBuf>,
        timeout_seconds: u64,
    },
}

impl FairPlayRequest {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Inspect { .. } => "Inspect FairPlay materials",
            Self::Decrypt { .. } => "Decrypt IPA",
            Self::Collect { .. } => "Collect enrollment",
            Self::Recover { .. } => "Recover enrollment",
        }
    }
}

pub fn execute(request: FairPlayRequest) -> Result<JobOutcome> {
    operation::check()?;
    match request {
        FairPlayRequest::Inspect {
            ipa,
            model,
            capture,
            report,
        } => {
            operation::stage(Stage::Inspecting)?;
            let diagnostic = inspect(capture.as_deref(), ipa.as_deref(), model.as_deref());
            operation::check()?;
            let mut artifacts = Vec::new();
            if let Some(path) = report {
                operation::publish(|| write_doctor_report(&path, &diagnostic))?;
                artifacts.push(Artifact {
                    kind: ArtifactKind::Report,
                    path,
                });
            }
            let mut summary = if diagnostic.ready {
                "Prerequisite checks passed. This does not authenticate decrypted plaintext."
                    .to_owned()
            } else {
                "Some prerequisite checks need attention.".to_owned()
            };
            for (check, passed) in &diagnostic.checks {
                summary.push_str(&format!(
                    "\n{}: {}",
                    if *passed { "PASS" } else { "CHECK" },
                    check
                ));
            }
            // Paths and private protocol details remain in the explicitly selected
            // local report. Task history records only allowlisted check names.
            Ok(JobOutcome {
                summary,
                artifacts,
                details: Some(serde_json::to_value(diagnostic)?),
            })
        }
        FairPlayRequest::Decrypt {
            input,
            model,
            output,
            report,
            force,
        } => {
            operation::stage(Stage::Decrypting)?;
            let result = decrypt(&input, &output, &model, Some(&report), force)?;
            Ok(JobOutcome {
                details: None,
                summary: format!(
                    "Processed {} encrypted images / {} pages. Plaintext correctness is not authenticated; see report before further use.",
                    result.encrypted_images, result.decrypted_pages
                ),
                artifacts: vec![
                    Artifact {
                        kind: ArtifactKind::DecryptedIpa,
                        path: output,
                    },
                    Artifact {
                        kind: ArtifactKind::Report,
                        path: report,
                    },
                ],
            })
        }
        FairPlayRequest::Collect {
            app,
            ipa,
            output,
            fairplayd,
            system_state,
            shared_state,
            adi_state,
            iomac_file,
            interface,
            product_version,
            build_version,
        } => {
            operation::stage(Stage::Collecting)?;
            let result = collect(&EnrollmentCollectOptions {
                app,
                ipa,
                output: output.clone(),
                fairplayd,
                system_state,
                shared_state,
                adi_state,
                iomac_file,
                interface,
                product_version,
                build_version,
            })?;
            Ok(JobOutcome {
                details: None,
                summary: format!(
                    "Collected {} private files. Keep these materials local and inspect them before recovery.",
                    result.files.len()
                ),
                artifacts: vec![Artifact {
                    kind: ArtifactKind::Capture,
                    path: output,
                }],
            })
        }
        FairPlayRequest::Recover {
            capture,
            output,
            compat_fairplayd,
            startup_profile,
            iokit15_output,
            timeout_seconds,
        } => {
            if !(1..=3600).contains(&timeout_seconds) {
                bail!("recovery phase timeout must be between 1 and 3600 seconds");
            }
            operation::stage(Stage::Recovering)?;
            let result = recover(RecoverCaptureOptions {
                capture: &capture,
                output: &output,
                compat_fairplayd: compat_fairplayd.as_deref(),
                startup_profile: startup_profile.as_deref(),
                iokit15_output: iokit15_output.as_deref(),
                timeout: Duration::from_secs(timeout_seconds),
                native_26b_research: false,
                skip_differential: false,
            })?;
            Ok(JobOutcome { summary: "Recovery completed with differential checks enabled. Inspect the output before further use.".into(), artifacts: vec![Artifact { kind: ArtifactKind::Model, path: result.enrollment_model }, Artifact { kind: ArtifactKind::DecryptedIpa, path: result.decrypted_ipa }, Artifact { kind: ArtifactKind::Report, path: output.join("recovery-report.json") }], details: None })
        }
    }
}

/// Compatibility-preserving diagnostic entry point shared by both front ends.
pub fn inspect(
    capture: Option<&std::path::Path>,
    ipa: Option<&std::path::Path>,
    model: Option<&std::path::Path>,
) -> crate::fairplay::FairPlayDoctorReport {
    crate::fairplay::doctor_fairplay(capture, ipa, model)
}

pub fn collect(
    options: &EnrollmentCollectOptions,
) -> Result<crate::capture::EnrollmentCaptureManifest> {
    operation::stage(Stage::Collecting)?;
    crate::fairplay_collect::collect_enrollment(options)
}

pub fn recover(
    options: RecoverCaptureOptions<'_>,
) -> Result<crate::fairplay_recover_capture::CaptureRecoveryResult> {
    operation::stage(Stage::Recovering)?;
    crate::fairplay_recover_capture::recover_capture(options)
}

pub fn decrypt(
    input: &std::path::Path,
    output: &std::path::Path,
    model: &std::path::Path,
    report: Option<&std::path::Path>,
    force: bool,
) -> Result<crate::fairplay_ipa::IpaDecryptResult> {
    operation::stage(Stage::Decrypting)?;
    crate::fairplay_ipa::decrypt_ipa_with_options(input, output, model, report, force)
}
