use super::*;
use ipatool_rs::application::fairplay_setup::{SetupOptions, SetupRequest};

impl DesktopWindow {
    pub(super) fn refresh_saved_models(&mut self, cx: &mut Context<Self>) {
        self.fair.model_status_generation = self.fair.model_status_generation.wrapping_add(1);
        let generation = self.fair.model_status_generation;
        self.fair.checking_models = true;
        let session = self.session.clone();
        let work = cx.background_spawn(async move { session.saved_model_count() });
        cx.spawn(async move |view, cx| {
            let result = work
                .await
                .map_err(|_| "Saved models need attention. Review Advanced tools.".to_owned());
            let _ = view.update(cx, |this, cx| {
                if generation != this.fair.model_status_generation {
                    return;
                }
                this.fair.saved_models = Some(result);
                this.fair.checking_models = false;
                cx.notify();
            });
        })
        .detach();
    }

    /// Completion-only handoff: restart never executes saved tasks or invents
    /// follow-ups. Parent identity makes repeated completion delivery idempotent.
    pub(super) fn queue_download_decryption(&mut self, parent: u64) {
        if self
            .journal
            .tasks
            .iter()
            .any(|task| task.parent_task == Some(parent))
        {
            return;
        }
        let Some(task) = self.journal.tasks.iter().find(|task| task.id == parent) else {
            return;
        };
        if task.state != TaskState::Succeeded
            || !task.decrypt_after_download
            || !matches!(task.request, JobRequest::Download(_))
        {
            return;
        }
        let Some(outcome) = &task.outcome else {
            return;
        };
        if outcome
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == ArtifactKind::DecryptedIpa)
        {
            return;
        }
        let Some(input) = outcome
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.kind == ArtifactKind::Package
                    && artifact
                        .path
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("ipa"))
            })
            .map(|artifact| artifact.path.clone())
        else {
            return;
        };
        if self.journal.tasks.len() >= MAX_TASKS {
            if let Some(outcome) = self
                .journal
                .tasks
                .iter_mut()
                .find(|task| task.id == parent)
                .and_then(|task| task.outcome.as_mut())
            {
                outcome.summary.push_str(" Automatic decryption was not queued because task history is full. Clear finished history and use Decrypt IPA.");
            }
            return;
        }
        let Ok(id) = self.journal.next_id() else {
            return;
        };
        let mut followup = TaskRecord::new(
            id,
            "Decrypt downloaded IPA with saved model".into(),
            JobRequest::FairPlay(FairPlayRequest::DecryptSaved {
                input,
                output: None,
                report: None,
            }),
            task.account_generation,
        );
        followup.parent_task = Some(parent);
        self.journal.tasks.push(followup);
    }

    pub(super) fn open_setup(
        &mut self,
        input: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.set_fair_mode(FairMode::Setup, window, cx);
        self.fair.setup_step = 0;
        self.fair.advanced = false;
        for field in [
            &self.fair.model,
            &self.fair.fairplayd,
            &self.fair.compat,
            &self.fair.startup,
            &self.fair.iokit,
            &self.fair.system_state,
            &self.fair.shared_state,
            &self.fair.adi_state,
            &self.fair.iomac,
            &self.fair.product_version,
            &self.fair.build_version,
        ] {
            field.update(cx, |field, cx| field.set_value("", window, cx));
        }
        if let Some(input) = input {
            self.fair.input.update(cx, |field, cx| {
                field.set_value(input.to_string_lossy().into_owned(), window, cx)
            });
        }
        self.page = Page::FairPlay;
        self.shell_focus.focus(window);
        cx.notify();
    }

    pub(super) fn setup_next(&mut self, cx: &mut Context<Self>) {
        if self.fair.setup_step == 1 {
            let ipa = PathBuf::from(self.fair.input.read(cx).value().trim());
            let app = PathBuf::from(self.fair.app.read(cx).value().trim());
            let model = PathBuf::from(self.fair.model.read(cx).value().trim());
            let importing = !model.as_os_str().is_empty();
            if importing && !model.exists() {
                self.show_notice("Choose an existing model file or folder to import.", cx);
                return;
            }
            if self.setup_request(cx).is_err() {
                self.show_notice("Review timeout and advanced options before continuing.", cx);
                return;
            }
            if !ipa.is_absolute()
                || !ipa.is_file()
                || !ipa
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("ipa"))
                || (!importing && (!app.is_absolute() || !app.is_dir()))
            {
                self.show_notice("Choose the installed app and matching IPA first.", cx);
                return;
            }
        }
        self.fair.setup_step = (self.fair.setup_step + 1).min(2);
        self.fair_scroll.set_offset(Default::default());
        cx.notify();
    }

    pub(super) fn setup_request(&self, cx: &App) -> anyhow::Result<SetupRequest> {
        let value = |input: &Entity<InputState>| input.read(cx).value().trim().to_owned();
        let path = |input: &Entity<InputState>| {
            let text = value(input);
            (!text.is_empty()).then(|| PathBuf::from(text))
        };
        let text = |input: &Entity<InputState>| {
            let text = value(input);
            (!text.is_empty()).then_some(text)
        };
        let timeout_seconds = value(&self.fair.timeout).parse::<u64>()?;
        anyhow::ensure!((1..=3600).contains(&timeout_seconds), "invalid timeout");
        Ok(SetupRequest {
            app: PathBuf::from(value(&self.fair.app)),
            ipa: PathBuf::from(value(&self.fair.input)),
            options: SetupOptions {
                existing_model: path(&self.fair.model),
                fairplayd: path(&self.fair.fairplayd),
                compat_fairplayd: path(&self.fair.compat),
                startup_profile: path(&self.fair.startup),
                iokit15_output: path(&self.fair.iokit),
                system_state: path(&self.fair.system_state),
                shared_state: path(&self.fair.shared_state),
                adi_state: path(&self.fair.adi_state),
                iomac_file: path(&self.fair.iomac),
                interface: value(&self.fair.interface),
                product_version: text(&self.fair.product_version),
                build_version: text(&self.fair.build_version),
                timeout_seconds,
            },
        })
    }
}

impl DesktopWindow {
    pub(super) fn toggle_auto_decrypt(&mut self, cx: &mut Context<Self>) {
        let previous = self.preferences.auto_decrypt;
        self.preferences.auto_decrypt = !previous;
        if self
            .preferences
            .save(&self.session.directory().join("desktop-preferences.json"))
            .is_err()
        {
            self.preferences.auto_decrypt = previous;
            self.show_notice("Could not save automatic decryption preference.", cx);
        }
        cx.notify();
    }
}
