//! Versioned, non-secret desktop task history. Loading never executes a task.

use super::{download::DownloadRequest, failure::Failure, fairplay::FairPlayRequest};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const SCHEMA: u32 = 1;
const MAX_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_TASKS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Queued,
    Running,
    AwaitingInput,
    CancellationRequested,
    Cancelled,
    Succeeded,
    Failed,
    Interrupted,
}

impl TaskState {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Running | Self::AwaitingInput | Self::CancellationRequested
        )
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::AwaitingInput => "Needs your attention",
            Self::CancellationRequested => "Stopping safely",
            Self::Cancelled => "Cancelled",
            Self::Succeeded => "Completed",
            Self::Failed => "Needs attention",
            Self::Interrupted => "Interrupted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    Package,
    DecryptedIpa,
    Report,
    Capture,
    Model,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobOutcome {
    /// Local diagnostic details are shown during this session, never journaled.
    #[serde(skip)]
    pub details: Option<serde_json::Value>,
    pub summary: String,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JobRequest {
    Download(DownloadRequest),
    FairPlay(FairPlayRequest),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: u64,
    pub title: String,
    pub request: JobRequest,
    pub state: TaskState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task: Option<u64>,
    #[serde(default)]
    pub decrypt_after_download: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_stage: Option<super::operation::Stage>,
    pub account_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identity: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub outcome: Option<JobOutcome>,
    pub failure: Option<Failure>,
}

impl TaskRecord {
    pub fn new(id: u64, title: String, request: JobRequest, account_generation: u64) -> Self {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Self {
            id,
            title,
            request,
            state: TaskState::Queued,
            parent_task: None,
            decrypt_after_download: false,
            last_stage: None,
            account_generation,
            account_identity: None,
            created_at: now,
            updated_at: now,
            outcome: None,
            failure: None,
        }
    }

    pub fn finish(&mut self, result: Result<JobOutcome>) {
        self.updated_at = time::OffsetDateTime::now_utc().unix_timestamp();
        match result {
            Ok(outcome) => {
                self.state = TaskState::Succeeded;
                self.outcome = Some(outcome);
                self.failure = None;
            }
            Err(error) => {
                let failure = if self.state == TaskState::CancellationRequested {
                    Failure::from_error(&anyhow::Error::new(super::operation::Cancelled))
                } else {
                    Failure::from_error(&error)
                };
                self.state = if failure.kind == super::failure::FailureKind::Cancelled {
                    TaskState::Cancelled
                } else {
                    TaskState::Failed
                };
                self.failure = Some(failure);
            }
        }
    }
}

#[derive(Default)]
pub struct Journal {
    pub tasks: Vec<TaskRecord>,
}

#[derive(Serialize, Deserialize)]
struct DiskJournal {
    schema: u32,
    tasks: Vec<TaskRecord>,
}

impl Journal {
    pub fn needs_account_input(&self) -> bool {
        self.tasks.iter().any(|task| {
            task.state == TaskState::AwaitingInput
                && matches!(task.request, JobRequest::Download(_))
        })
    }

    /// Refresh may rotate credentials without changing task ownership. Only
    /// queued/awaiting tasks for this same account and storefront may continue;
    /// interrupted jobs still require an explicit review and retry.
    pub fn resume_account(&mut self, identity: Option<&str>, generation: u64) {
        for task in &mut self.tasks {
            if !matches!(task.request, JobRequest::Download(_))
                || !matches!(task.state, TaskState::Queued | TaskState::AwaitingInput)
            {
                continue;
            }
            task.updated_at = time::OffsetDateTime::now_utc().unix_timestamp();
            if identity.is_some() && task.account_identity.as_deref() == identity {
                task.state = TaskState::Queued;
                task.account_generation = generation;
                task.failure = None;
            } else {
                task.state = TaskState::Failed;
                task.failure = Some(Failure {
                    kind: super::failure::FailureKind::AuthenticationRequired,
                    title: "Account or storefront changed".into(),
                    message: "Review this download under the active account before retrying. It was not resumed automatically.".into(),
                    action: "Review and retry".into(),
                });
            }
        }
    }
    /// Reserve a unique backup name before moving an unreadable journal. Never
    /// replace an earlier backup, including when recovery is repeated quickly.
    pub fn preserve_existing(path: &Path) -> Result<Option<PathBuf>> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(metadata) if !metadata.is_file() => {
                bail!("journal recovery requires a regular file")
            }
            _ => {}
        }
        let reserved = tempfile::Builder::new()
            .prefix("desktop-tasks.backup-")
            .suffix(".json")
            .tempfile_in(path.parent().context("task journal has no parent")?)?;
        let backup = reserved
            .into_temp_path()
            .keep()
            .map_err(|error| error.error)?;
        if let Err(error) = fs::rename(path, &backup) {
            let _ = fs::remove_file(&backup);
            return Err(error).context("preserve task journal backup");
        }
        Ok(Some(backup))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).context("inspect task journal"),
        };
        if !metadata.is_file() || metadata.len() > MAX_BYTES {
            bail!("task journal has invalid file type or size");
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            bail!("task journal exceeds size limit");
        }
        let mut disk: DiskJournal =
            serde_json::from_slice(&bytes).context("decode task journal")?;
        if disk.schema != SCHEMA || disk.tasks.len() > MAX_TASKS {
            bail!("unsupported task journal schema or count");
        }
        let mut ids = std::collections::HashSet::new();
        for task in &mut disk.tasks {
            if !ids.insert(task.id) {
                bail!("duplicate task identity in journal");
            }
            if task.state.is_active() {
                task.state = TaskState::Interrupted;
            }
        }
        Ok(Self { tasks: disk.tasks })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if self.tasks.len() > MAX_TASKS {
            bail!("task history is full; clear completed tasks before adding more");
        }
        let parent = path.parent().context("task journal has no parent")?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(
            &mut file,
            &DiskJournal {
                schema: SCHEMA,
                tasks: self.tasks.clone(),
            },
        )?;
        if file.as_file().metadata()?.len() > MAX_BYTES {
            bail!("task journal exceeds size limit");
        }
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        file.persist(path)
            .map_err(|error| error.error)
            .context("publish task journal")?;
        Ok(())
    }

    pub fn next_id(&self) -> Result<u64> {
        self.tasks
            .iter()
            .map(|task| task.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .context("task identity limit reached")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn task(id: u64) -> TaskRecord {
        TaskRecord::new(
            id,
            "Fixture".into(),
            JobRequest::Download(DownloadRequest {
                app_id: Some(42),
                ..Default::default()
            }),
            1,
        )
    }

    #[test]
    fn account_continuation_rebinds_same_owner_queue_without_restarting_interrupted_jobs() {
        let mut tasks = vec![task(1), task(2), task(3)];
        for task in &mut tasks {
            task.account_identity = Some("account-and-storefront-a".into());
        }
        tasks[0].state = TaskState::AwaitingInput;
        tasks[2].state = TaskState::Interrupted;
        let mut journal = Journal { tasks };
        assert!(journal.needs_account_input());
        journal.resume_account(Some("account-and-storefront-a"), 2);
        assert!(!journal.needs_account_input());
        for task in &journal.tasks[..2] {
            assert_eq!(task.state, TaskState::Queued);
            assert_eq!(task.account_generation, 2);
        }
        assert_eq!(journal.tasks[2].state, TaskState::Interrupted);
        journal.resume_account(Some("different-account-or-storefront"), 3);
        assert!(
            journal.tasks[..2]
                .iter()
                .all(|task| task.state == TaskState::Failed)
        );
        assert_eq!(journal.tasks[2].state, TaskState::Interrupted);
    }

    #[test]
    fn cancellation_request_does_not_reopen_an_account_challenge_that_finished_concurrently() {
        let mut task = task(1);
        task.state = TaskState::CancellationRequested;
        task.finish(Err(crate::store_login::AuthCodeRequired.into()));
        assert_eq!(task.state, TaskState::Cancelled);
        assert_eq!(
            task.failure.unwrap().kind,
            super::super::failure::FailureKind::Cancelled
        );
    }

    #[test]
    fn recovery_preserves_every_original_without_replacing_previous_backups() {
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("tasks.json");
        fs::write(&journal, b"invalid journal one").unwrap();
        let first = Journal::preserve_existing(&journal).unwrap().unwrap();
        fs::write(&journal, b"invalid journal two").unwrap();
        let second = Journal::preserve_existing(&journal).unwrap().unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read(first).unwrap(), b"invalid journal one");
        assert_eq!(fs::read(second).unwrap(), b"invalid journal two");
        assert!(Journal::preserve_existing(&journal).unwrap().is_none());
    }

    #[test]
    fn transient_private_diagnostics_are_never_persisted_in_task_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tasks.json");
        let mut task = task(1);
        task.finish(Ok(JobOutcome {
            summary: "Prerequisites need attention".into(),
            artifacts: vec![],
            details: Some(serde_json::json!({"private": "fixture-private-diagnostic"})),
        }));
        Journal { tasks: vec![task] }.save(&path).unwrap();
        assert!(
            !fs::read_to_string(&path)
                .unwrap()
                .contains("fixture-private")
        );
        assert!(
            Journal::load(&path).unwrap().tasks[0]
                .outcome
                .as_ref()
                .unwrap()
                .details
                .is_none()
        );
    }

    #[test]
    fn restart_marks_pending_jobs_interrupted_without_restarting_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.json");
        let mut journal = Journal {
            tasks: vec![task(1), task(2), task(3)],
        };
        journal.tasks[1].state = TaskState::CancellationRequested;
        journal.tasks[1].last_stage = Some(super::super::operation::Stage::Downloading);
        journal.tasks[2].finish(Ok(JobOutcome {
            summary: "Saved".into(),
            artifacts: vec![],
            details: None,
        }));
        journal.save(&path).unwrap();
        let loaded = Journal::load(&path).unwrap();
        assert_eq!(loaded.tasks[0].state, TaskState::Interrupted);
        assert_eq!(loaded.tasks[1].state, TaskState::Interrupted);
        assert_eq!(
            loaded.tasks[1].last_stage,
            Some(super::super::operation::Stage::Downloading)
        );
        assert_eq!(loaded.tasks[2].state, TaskState::Succeeded);
        assert_eq!(loaded.next_id().unwrap(), 4);
    }

    #[test]
    fn successful_publication_wins_over_late_cancel_but_acknowledged_cancel_is_distinct() {
        let mut task = task(1);
        task.state = TaskState::CancellationRequested;
        task.finish(Ok(JobOutcome {
            summary: "Published".into(),
            artifacts: vec![],
            details: None,
        }));
        assert_eq!(task.state, TaskState::Succeeded);
        task.finish(Err(super::super::operation::Cancelled.into()));
        assert_eq!(task.state, TaskState::Cancelled);
    }

    #[test]
    fn malformed_future_and_duplicate_journals_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.json");
        fs::write(&path, b"not json").unwrap();
        assert!(Journal::load(&path).is_err());
        fs::write(&path, br#"{"schema":999,"tasks":[]}"#).unwrap();
        assert!(Journal::load(&path).is_err());
        Journal {
            tasks: vec![task(1), task(1)],
        }
        .save(&path)
        .unwrap();
        assert!(Journal::load(&path).is_err());
    }
}
