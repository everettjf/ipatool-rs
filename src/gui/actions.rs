use super::*;

impl DesktopWindow {
    pub(super) fn selected_country(&self, cx: &App) -> String {
        self.country.read(cx).value().to_owned()
    }

    pub(super) fn set_country(&mut self, code: &str, _window: &mut Window, cx: &mut Context<Self>) {
        self.country
            .update(cx, |state, cx| state.set_value(code, cx));
        self.refresh_catalog_filters(cx);
    }

    fn accept_account(
        &mut self,
        account: Option<AccountView>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        // Default to the account region when it first becomes known or the
        // account/storefront changes. A same-account refresh must preserve an
        // explicit browsing override made during this session.
        let country = account
            .as_ref()
            .filter(|next| {
                self.account.as_ref().is_none_or(|previous| {
                    !previous.email.eq_ignore_ascii_case(&next.email)
                        || !previous.country.eq_ignore_ascii_case(&next.country)
                })
            })
            .map(|account| account.country.clone());
        self.account = account;
        if let Some(country) = country
            && !self.selected_country(cx).eq_ignore_ascii_case(&country)
        {
            self.set_country(&country, window, cx);
        }
    }

    pub(super) fn set_platform(&mut self, platform: Platform, cx: &mut Context<Self>) {
        if self.platform != platform {
            self.platform = platform;
            self.refresh_catalog_filters(cx);
        }
    }

    fn refresh_catalog_filters(&mut self, cx: &mut Context<Self>) {
        let refresh = self.query.is_some() || self.searching || self.search_error.is_some();
        self.query_id = self.query_id.wrapping_add(1);
        self.searching = false;
        self.search_error = None;
        self.apps.clear();
        self.selected = None;
        self.query = None;
        self.details_scroll.set_offset(Default::default());
        if refresh && !self.term.read(cx).value().trim().is_empty() {
            self.search(cx);
        }
        cx.notify();
    }

    pub(super) fn set_download_platform(
        &mut self,
        platform: Platform,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.account_busy() {
            return;
        }
        let Some(form) = &mut self.download_form else {
            return;
        };
        if form.platform == platform {
            return;
        }
        if let Some(operation) = self.version_operation.take() {
            operation.cancel();
        }
        self.download_generation = self.download_generation.wrapping_add(1);
        form.platform = platform;
        form.versions.clear();
        form.metadata = None;
        form.error = None;
        form.loading_versions = false;
        form.version
            .update(cx, |input, cx| input.set_value("", window, cx));
        cx.notify();
    }

    pub(super) fn set_fair_mode(
        &mut self,
        mode: FairMode,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.fair.mode != mode {
            self.fair.advanced = false;
        }
        self.fair.mode = mode;
        self.fair_scroll.set_offset(Default::default());
        cx.notify();
    }

    pub(super) fn inspection_followup(
        &mut self,
        request: FairPlayRequest,
        mode: FairMode,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let FairPlayRequest::Inspect {
            ipa,
            model,
            capture,
            ..
        } = request
        else {
            return;
        };
        // Restore the inspected materials, not unrelated edits from another page.
        self.review_fairplay(
            FairPlayRequest::Inspect {
                ipa,
                model,
                capture,
                report: None,
            },
            window,
            cx,
        );
        self.set_fair_mode(mode, window, cx);
    }

    pub(super) fn use_fairplay_artifact(
        &mut self,
        kind: ArtifactKind,
        path: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let value = path.to_string_lossy().into_owned();
        match kind {
            ArtifactKind::Package | ArtifactKind::DecryptedIpa => {
                self.set_fair_mode(FairMode::Inspect, window, cx);
                self.fair
                    .input
                    .update(cx, |input, cx| input.set_value(value, window, cx));
            }
            ArtifactKind::Capture => {
                self.set_fair_mode(FairMode::Recover, window, cx);
                self.fair
                    .capture
                    .update(cx, |input, cx| input.set_value(value, window, cx));
            }
            ArtifactKind::Model => {
                self.set_fair_mode(FairMode::Decrypt, window, cx);
                self.fair
                    .model
                    .update(cx, |input, cx| input.set_value(value, window, cx));
            }
            ArtifactKind::Report => return,
        }
        self.fair
            .output
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.fair
            .directory_output
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.fair
            .report
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.page = Page::FairPlay;
        self.shell_focus.focus(window);
        cx.notify();
    }

    pub(super) fn prepare_ipa_decryption(
        &mut self,
        path: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !path.is_file()
            || !path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("ipa"))
        {
            self.show_notice(
                "IPA not found. Choose its current location in FairPlay.",
                cx,
            );
            return;
        }
        self.use_fairplay_artifact(ArtifactKind::Package, path, window, cx);
        self.set_fair_mode(FairMode::Decrypt, window, cx);
        // A model selected for a different download must not be reused silently.
        self.fair
            .model
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.show_notice("IPA selected. Choose a matching model to continue.", cx);
    }

    pub(super) fn search(&mut self, cx: &mut Context<Self>) {
        let query = match Query::new(
            self.mode,
            &self.term.read(cx).value(),
            &self.selected_country(cx),
            self.platform,
        ) {
            Ok(query) => query,
            Err(error) => {
                self.search_error = Some(Failure {
                    kind: FailureKind::Unavailable,
                    title: "Check search inputs".into(),
                    message: error.to_string(),
                    action: "Edit inputs".into(),
                });
                cx.notify();
                return;
            }
        };
        self.query_id = self.query_id.wrapping_add(1);
        let id = self.query_id;
        self.searching = true;
        self.search_error = None;
        let submitted = query.clone();
        let session = Arc::clone(&self.session);
        let work = cx.background_spawn(async move { session.catalog(&submitted) });
        cx.spawn(async move |view, cx| {
            let result = work.await;
            let _ = view.update(cx, |this, cx| {
                if id != this.query_id {
                    return;
                }
                this.searching = false;
                match result {
                    Ok(apps) => {
                        this.details_scroll.set_offset(Default::default());
                        this.selected = (!apps.is_empty()).then_some(0);
                        this.apps = apps;
                        this.query = Some(query);
                        this.load_artwork(cx);
                    }
                    Err(error) => {
                        this.search_error = Some(Failure::from_error(&error));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub(super) fn clear_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.query_id = self.query_id.wrapping_add(1);
        self.searching = false;
        self.search_error = None;
        self.query = None;
        self.details_scroll.set_offset(Default::default());
        self.apps.clear();
        self.selected = None;
        self.term.update(cx, |input, cx| {
            input.set_value("", window, cx);
            input.focus(window, cx);
        });
        cx.notify();
    }

    fn load_artwork(&mut self, cx: &mut Context<Self>) {
        let apps = self
            .apps
            .iter()
            .filter(|app| !app.artwork_url.is_empty() && !self.artwork.contains_key(&app.id))
            .cloned()
            .collect::<Vec<_>>();
        if apps.is_empty() {
            return;
        }
        let generation = self.query_id;
        let work = cx.background_spawn(async move { artwork::load(apps) });
        cx.spawn(async move |view, cx| {
            let images = work.await;
            let _ = view.update(cx, |this, cx| {
                if generation != this.query_id {
                    return;
                }
                if this.artwork.len() > 128 {
                    this.artwork.clear();
                }
                this.artwork.extend(images);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn load_library(&mut self, cx: &mut Context<Self>) {
        if self.account.is_none() || self.account_busy() || self.account_form.verifying {
            return;
        }
        self.library_loading = true;
        self.library_error = None;
        let session = Arc::clone(&self.session);
        let page = self.library_page;
        let platform = self.library_platform;
        let operation = Operation::default();
        self.library_operation = Some(operation.clone());
        let work = cx.background_spawn(async move {
            operation.run(|| session.purchases(page, Some(platform)))
        });
        cx.spawn(async move |view, cx| {
            let result = work.await;
            let _ = view.update(cx, |this, cx| {
                this.library_loading = false;
                this.library_operation = None;
                match result {
                    Ok(output) => {
                        let previous = this
                            .library_selected
                            .and_then(|index| this.library_apps.get(index))
                            .map(|app| app.id);
                        this.library_total = output.total_count;
                        this.library_apps = output.apps;
                        this.library_selected = previous
                            .and_then(|id| this.library_apps.iter().position(|app| app.id == id))
                            .or_else(|| (!this.library_apps.is_empty()).then_some(0));
                        this.library_result_platform = platform;
                        this.reconcile_library_selection(cx);
                    }
                    Err(error) => {
                        this.library_error = Some(Failure::from_error(&error));
                    }
                }
                if this.quit_requested && !this.account_busy() {
                    cx.quit();
                    return;
                }
                this.start_next(cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub(super) fn open_account(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if window.has_active_dialog(cx) {
            return;
        }
        self.account_form.reauthenticating = false;
        self.account_form.error = None;
        let view = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, window, cx| {
            view.update(cx, |this, cx| this.account_dialog(dialog, window, cx))
                .unwrap_or_else(|_| Dialog::new(window, cx))
        });
        if self.account.is_none() {
            self.account_form
                .email
                .update(cx, |input, cx| input.focus(window, cx));
        }
    }

    fn finish_account_success(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.account_form.reauthenticating = false;
        window.close_dialog(cx);
        if let Some((app, platform, country)) = self.pending_download.take() {
            self.open_download(app, platform, country, window, cx);
        }
        if let Some((title, request)) = self.pending_retry.take() {
            self.review_download(title, request, window, cx);
        }
        if self.page == Page::Library {
            self.load_library(cx);
        }
        self.journal.resume_account(
            self.session.account_identity().as_deref(),
            self.session.generation(),
        );
        self.persist_history();
        self.start_next(cx);
    }

    pub(super) fn continue_account(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if window.has_active_dialog(cx) {
            return;
        }
        self.open_account(window, cx);
        if self.account.is_some() {
            self.begin_reauthentication(window, cx);
        }
    }

    pub(super) fn begin_reauthentication(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let email = self
            .account
            .as_ref()
            .map(|account| account.email.clone())
            .unwrap_or_default();
        self.clear_secrets(window, cx);
        self.account_form.reauthenticating = true;
        self.account_form.error = None;
        self.account_form
            .email
            .update(cx, |input, cx| input.set_value(email, window, cx));
        self.account_form
            .password
            .update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    pub(super) fn clear_secrets(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        // Replace entities rather than setting an empty value: undo history from
        // a completed credential interaction must not survive into the next one.
        if !self.quit_prompt_open {
            window.blur();
        }
        self.account_form.password = field(window, cx, "Password", "", true);
        self.account_form.passphrase = field(window, cx, "File-store passphrase", "", true);
        self.account_form.code = field(window, cx, "Verification code", "", false);
        self.account_form.input_subscriptions =
            account_input_subscriptions(&self.account_form, window, cx);
        self.account_form.secret = None;
        self.account_form.verifying = false;
        self.account_form.unlocking_saved = false;
        self.account_form.verification_deadline = None;
    }

    fn expire_verification(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(deadline) = self.account_form.verification_deadline else {
            return;
        };
        cx.spawn_in(window, async move |view, cx| {
            cx.background_executor()
                .timer(deadline.saturating_duration_since(std::time::Instant::now()))
                .await;
            loop {
                let finished = view
                    .update_in(cx, |this, window, cx| {
                        if this.account_form.verification_deadline != Some(deadline) {
                            return true;
                        }
                        if this.account_form.busy {
                            return false;
                        }
                        this.clear_secrets(window, cx);
                        this.account_form.reauthenticating = this.account.is_some();
                        this.account_form.error = Some(Failure {
                            kind: FailureKind::AuthenticationRequired,
                            title: "Verification session expired".into(),
                            message: "Enter your password again to start a fresh sign-in attempt."
                                .into(),
                            action: "Sign in".into(),
                        });
                        cx.notify();
                        true
                    })
                    .unwrap_or(true);
                if finished {
                    break;
                }
                cx.background_executor().timer(Duration::from_secs(1)).await;
            }
        })
        .detach();
    }

    pub(super) fn submit_account(
        &mut self,
        saved: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.account_busy() {
            return;
        }
        let saved = saved || self.account_form.unlocking_saved;
        if saved && self.account_form.verifying {
            self.show_notice("Complete verification or cancel this sign-in before loading another saved account.", cx);
            return;
        }
        if self.account_form.verifying
            && self
                .account_form
                .verification_deadline
                .is_none_or(|deadline| std::time::Instant::now() >= deadline)
        {
            self.clear_secrets(window, cx);
            self.account_form.error = Some(Failure {
                kind: FailureKind::AuthenticationRequired,
                title: "Verification session expired".into(),
                message: "Enter your password again to start a fresh sign-in attempt.".into(),
                action: "Sign in".into(),
            });
            cx.notify();
            return;
        }
        let email = self.account_form.email.read(cx).value().trim().to_owned();
        let password = Zeroizing::new(if self.account_form.verifying {
            self.account_form
                .secret
                .as_ref()
                .map(|value| value.to_string())
                .unwrap_or_default()
        } else {
            self.account_form.password.read(cx).value().to_string()
        });
        let code = Zeroizing::new(self.account_form.code.read(cx).value().trim().to_owned());
        if self.account_form.verifying
            && (code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()))
        {
            self.account_form.error = Some(Failure {
                kind: FailureKind::VerificationRequired,
                title: "Check verification code".into(),
                message: "Enter the six-digit code from your trusted device.".into(),
                action: "Enter code".into(),
            });
            cx.notify();
            return;
        }
        if !saved && (email.is_empty() || password.is_empty()) {
            self.account_form.error = Some(Failure {
                kind: FailureKind::Unavailable,
                title: "Apple ID and password are required".into(),
                message:
                    "Enter your credentials, or load an account that was already saved by the CLI."
                        .into(),
                action: "Edit credentials".into(),
            });
            cx.notify();
            return;
        }
        let force_file = self.account_form.force_file;
        let passphrase = Zeroizing::new(self.account_form.passphrase.read(cx).value().to_string());
        let passphrase = (force_file && !passphrase.is_empty()).then(|| passphrase.to_string());
        self.account_form.secret = (!saved).then(|| Zeroizing::new(password.to_string()));
        window.blur();
        self.account_form.password = field(window, cx, "Password", "", true);
        self.account_form.passphrase = field(window, cx, "File-store passphrase", "", true);
        self.account_form.code = field(window, cx, "Verification code", "", false);
        self.account_form.input_subscriptions =
            account_input_subscriptions(&self.account_form, window, cx);
        self.account_form.busy = true;
        self.account_form.error = None;
        let session = Arc::clone(&self.session);
        let operation = Operation::default();
        self.account_form.operation = Some(operation.clone());
        let work = cx.background_spawn(async move {
            operation.run(|| {
                if saved {
                    session.load(force_file, passphrase)
                } else {
                    session
                        .login(
                            LoginInput {
                                email,
                                password: password.to_string(),
                                auth_code: code.to_string(),
                            },
                            force_file,
                            passphrase,
                        )
                        .map(Some)
                }
            })
        });
        cx.spawn_in(window, async move |view, cx| {
            let result = work.await;
            let _ = view.update_in(cx, |this, window, cx| {
                this.account_form.busy = false;
                this.account_form.operation = None;
                if this.quit_requested { this.clear_secrets(window, cx); cx.quit(); return; }
                match result {
                    Ok(account) => {
                        this.accept_account(account, window, cx);
                        if this.account.is_none() {
                            this.clear_secrets(window, cx);
                            this.account_form.error = Some(Failure { kind: FailureKind::AuthenticationRequired, title: "No saved account".into(), message: "Credential storage is available. Enter your Apple ID and password to sign in.".into(), action: "Sign in".into() });
                        } else {
                            this.clear_secrets(window, cx);
                            if this.quit_prompt_open { this.account_completion_deferred = true; }
                            else { this.finish_account_success(window, cx); }
                        }
                    }
                    Err(error) => {
                        let failure = Failure::from_error(&error);
                        if failure.kind == FailureKind::UnlockRequired { this.account_form.force_file = true; }
                        if failure.kind == FailureKind::VerificationRequired {
                            this.account_form.verifying = true;
                            if !this.quit_prompt_open { this.account_form.code.update(cx, |input, cx| input.focus(window, cx)); }
                            if this.account_form.verification_deadline.is_none() {
                                this.account_form.verification_deadline = Some(std::time::Instant::now() + Duration::from_secs(300));
                                this.expire_verification(window, cx);
                            }
                        }
                        else {
                            let unlocking_saved = saved && (this.account_form.unlocking_saved || failure.kind == FailureKind::UnlockRequired);
                            this.clear_secrets(window, cx);
                            this.account_form.unlocking_saved = unlocking_saved;
                            if unlocking_saved && !this.quit_prompt_open {
                                this.account_form.passphrase.update(cx, |input, cx| input.focus(window, cx));
                            }
                        }
                        this.account_form.error = Some(failure);
                    }
                }
                cx.notify();
            });
        }).detach();
        cx.notify();
    }

    pub(super) fn revoke_account(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.account_busy() {
            return;
        }
        let view = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, _, cx| {
            let view = view.clone();
            dialog.bg(cx.theme().popover).title("Remove saved credentials?").child("This removes the local account and KBSync cache. It does not revoke this device through Apple's account service or delete downloaded files.")
                .confirm().on_ok(move |_, window, cx| {
                    let _ = view.update(cx, |this, cx| {
                        this.account_form.busy = true; let session = Arc::clone(&this.session);
                        let work = cx.background_spawn(async move { session.revoke() });
                        cx.spawn_in(window, async move |view, cx| {
                            let result = work.await;
                            let _ = view.update_in(cx, |this, window, cx| {
                                this.account_form.busy = false;
                                if this.quit_requested {
                                    this.clear_secrets(window, cx);
                                    cx.quit();
                                    return;
                                }
                                match result { Ok(()) => { this.account = None; this.library_apps.clear(); this.clear_secrets(window, cx); if this.quit_prompt_open { this.account_completion_deferred = true; } else { window.close_all_dialogs(cx); } this.show_notice("Local credentials removed. Downloaded files were kept.", cx); }, Err(error) => { this.account_form.error = Some(Failure::from_error(&error)); } }
                                cx.notify();
                            });
                        }).detach();
                    });
                    true
                })
        });
    }

    pub(super) fn open_download(
        &mut self,
        app: CatalogApp,
        platform: Platform,
        country: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.account.is_none() {
            self.pending_download = Some((app, platform, country));
            self.open_account(window, cx);
            return;
        }
        if window.has_active_dialog(cx) {
            return;
        }
        let output = self
            .preferences
            .output_directory
            .clone()
            .or_else(dirs::download_dir)
            .unwrap_or_else(|| self.session.directory().to_path_buf());
        self.download_generation = self.download_generation.wrapping_add(1);
        let version = field(
            window,
            cx,
            "Latest (leave blank) or external version ID",
            "",
            false,
        );
        let version_subscription = cx.subscribe(&version, |_, _, _: &InputEvent, cx| cx.notify());
        self.download_form = Some(DownloadForm {
            app,
            platform,
            source_country: country,
            output: field(
                window,
                cx,
                "Output directory or new file",
                &output.to_string_lossy(),
                false,
            ),
            version,
            _version_subscription: version_subscription,
            original_request: None,
            versions: vec![],
            loading_versions: false,
            metadata: None,
            acquire_license: false,
            error: None,
        });
        let view = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, window, cx| {
            view.update(cx, |this, cx| this.download_dialog(dialog, window, cx))
                .unwrap_or_else(|_| Dialog::new(window, cx))
        });
    }

    pub(super) fn load_versions(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.account_form.verifying || self.journal.needs_account_input() {
            self.show_notice("Resolve the pending account verification or cancel that task before requesting version history.", cx);
            return;
        }
        if self.account_busy() {
            return;
        }
        let Some(form) = self.download_form.as_mut() else {
            return;
        };
        form.loading_versions = true;
        form.error = None;
        let identity = AppIdentity {
            app_id: Some(form.app.id),
            bundle_identifier: None,
            platform: Some(form.platform),
        };
        let generation = self.download_generation;
        let session = Arc::clone(&self.session);
        let operation = Operation::default();
        self.version_operation = Some(operation.clone());
        let work =
            cx.background_spawn(async move { operation.run(|| session.versions(&identity)) });
        cx.spawn_in(window, async move |view, cx| {
            let result = work.await;
            let _ = view.update_in(cx, |this, _, cx| {
                this.version_operation = None;
                if generation != this.download_generation {
                    if this.quit_requested && !this.account_busy() { cx.quit(); }
                    else { this.start_next(cx); }
                    return;
                }
                if let Some(form) = &mut this.download_form {
                    form.loading_versions = false;
                    match result { Ok(output) => { form.versions = output.external_version_identifiers; }, Err(_) => { form.error = Some("Version history is unavailable. You can still request Latest or enter a known external version ID.".into()); } }
                }
                if this.quit_requested && !this.account_busy() { cx.quit(); return; }
                this.start_next(cx);
                cx.notify();
            });
        }).detach();
        cx.notify();
    }

    pub(super) fn load_version_metadata(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.account_form.verifying || self.journal.needs_account_input() {
            self.show_notice("Resolve the pending account verification or cancel that task before checking version details.", cx);
            return;
        }
        if self.account_busy() {
            return;
        }
        let Some(form) = self.download_form.as_mut() else {
            return;
        };
        let version = form.version.read(cx).value().trim().to_owned();
        if version.is_empty() {
            return;
        }
        let identity = AppIdentity {
            app_id: Some(form.app.id),
            bundle_identifier: None,
            platform: Some(form.platform),
        };
        form.loading_versions = true;
        form.error = None;
        form.metadata = None;
        let generation = self.download_generation;
        let session = Arc::clone(&self.session);
        let operation = Operation::default();
        self.version_operation = Some(operation.clone());
        let requested_version = version.clone();
        let work = cx.background_spawn(async move {
            operation.run(|| session.version_metadata(&identity, &requested_version))
        });
        cx.spawn_in(window, async move |view, cx| {
            let result = work.await;
            let _ = view.update_in(cx, |this, _, cx| {
                this.version_operation = None;
                if generation == this.download_generation && let Some(form) = &mut this.download_form {
                    form.loading_versions = false;
                    match result {
                        Ok(metadata) => form.metadata = Some((version, metadata)),
                        Err(_) => form.error = Some("Version details are unavailable. You can still request Latest or use a known external version ID.".into()),
                    }
                }
                if this.quit_requested && !this.account_busy() { cx.quit(); return; }
                this.start_next(cx); cx.notify();
            });
        }).detach();
        cx.notify();
    }

    pub(super) fn choose_path(
        &mut self,
        target: Entity<InputState>,
        directories: bool,
        save: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let current = PathBuf::from(target.read(cx).value().as_str());
        let prompt = if save {
            let directory = current
                .parent()
                .filter(|path| path.is_dir())
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    dirs::download_dir().unwrap_or_else(|| self.session.directory().to_path_buf())
                });
            let name = current.file_name().and_then(|value| value.to_str());
            let receiver = cx.prompt_for_new_path(&directory, name);
            cx.spawn_in(window, async move |view, cx| {
                if let Ok(Ok(Some(path))) = receiver.await {
                    let _ = view.update_in(cx, |_, window, cx| {
                        target.update(cx, |input, cx| {
                            input.set_value(path.to_string_lossy().into_owned(), window, cx)
                        })
                    });
                }
            })
            .detach();
            return;
        } else {
            cx.prompt_for_paths(PathPromptOptions {
                files: !directories,
                directories: directories || target == self.fair.model,
                multiple: false,
                prompt: Some("Choose a local path".into()),
            })
        };
        cx.spawn_in(window, async move |view, cx| {
            if let Ok(Ok(Some(paths))) = prompt.await
                && let Some(path) = paths.first()
            {
                let _ = view.update_in(cx, |_, window, cx| {
                    target.update(cx, |input, cx| {
                        input.set_value(path.to_string_lossy().into_owned(), window, cx)
                    })
                });
            }
        })
        .detach();
    }

    pub(super) fn submit_download(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(form) = &mut self.download_form else {
            return;
        };
        let output = PathBuf::from(form.output.read(cx).value().trim());
        if output.as_os_str().is_empty()
            || !output.is_absolute()
            || (output.exists() && !output.is_dir())
        {
            form.error = Some("Choose an absolute output directory or a new file path. Existing files are preserved.".into());
            cx.notify();
            return;
        }
        let mut request = form
            .original_request
            .clone()
            .unwrap_or_else(|| DownloadRequest {
                app_id: Some(form.app.id),
                ..Default::default()
            });
        request.output = Some(output);
        request.external_version_id = form.version.read(cx).value().trim().to_owned();
        request.platform = Some(form.platform);
        request.purchase = form.acquire_license;
        let title = format!("{} / {}", form.app.name, platform_name(form.platform));
        window.close_dialog(cx);
        self.download_form = None;
        self.enqueue(title, JobRequest::Download(request), window, cx);
    }

    pub(super) fn persist_history(&mut self) {
        if self.journal_error.is_none()
            && self
                .journal
                .save(&self.session.directory().join("desktop-tasks.json"))
                .is_err()
        {
            self.journal_error = Some("Task history could not be saved. Existing history is preserved; check disk space and directory access.".into());
        }
    }

    pub(super) fn enqueue(
        &mut self,
        title: String,
        request: JobRequest,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.journal_error.is_some() || self.journal.tasks.len() >= MAX_TASKS {
            self.show_notice("Task history needs attention. Recover history or clear completed tasks before adding a job.", cx);
            return;
        }
        if matches!(&request, JobRequest::Download(_)) && self.account.is_none() {
            self.open_account(window, cx);
            return;
        }
        if self.journal.tasks.iter().any(|task| {
            task.state.is_active()
                && serde_json::to_value(&task.request).ok() == serde_json::to_value(&request).ok()
        }) {
            self.show_notice("This operation is already queued or running.", cx);
            return;
        }
        let id = match self.journal.next_id() {
            Ok(id) => id,
            Err(_) => {
                self.show_notice("Task identity limit reached.", cx);
                return;
            }
        };
        let show_parameters = matches!(request, JobRequest::Download(_));
        let mut task = TaskRecord::new(id, title, request, self.session.generation());
        task.account_identity = self.session.account_identity();
        self.journal.tasks.push(task);
        self.selected_task = show_parameters.then_some(id);
        self.page = Page::Downloads;
        self.shell_focus.focus(window);
        self.persist_history();
        self.start_next(cx);
        cx.notify();
    }

    pub(super) fn start_next(&mut self, cx: &mut Context<Self>) {
        if self.quit_requested
            || self.active.is_some()
            || self.account_form.busy
            || self.account_form.verifying
            || self.library_loading
            || self.version_operation.is_some()
            || self.journal.needs_account_input()
            || self.journal_error.is_some()
        {
            return;
        }
        let Some(task) = self
            .journal
            .tasks
            .iter_mut()
            .find(|task| task.state == TaskState::Queued)
        else {
            return;
        };
        let id = task.id;
        task.state = TaskState::Running;
        task.last_stage = Some(Stage::Preparing);
        let request = task.request.clone();
        let generation = task.account_generation;
        let latest = Arc::new(Mutex::new(Progress {
            stage: Stage::Preparing,
            completed: 0,
            total: None,
        }));
        let observer = Arc::clone(&latest);
        let operation = Operation::new(move |progress| {
            if let Ok(mut slot) = observer.lock() {
                *slot = progress;
            }
        });
        self.active = Some((id, operation.clone(), Arc::clone(&latest)));
        self.persist_history();
        if self.journal_error.is_some() {
            self.active = None;
            if let Some(task) = self.journal.tasks.iter_mut().find(|task| task.id == id) {
                task.state = TaskState::Queued;
            }
            return;
        }
        let session = Arc::clone(&self.session);
        let work =
            cx.background_spawn(async move { session.execute(request, generation, &operation) });
        cx.spawn(async move |view, cx| {
            let result = work.await;
            let _ = view.update(cx, |this, cx| {
                let last_stage = this
                    .active
                    .as_ref()
                    .and_then(|(_, _, latest)| latest.lock().ok().map(|progress| progress.stage));
                this.active = None;
                if let Some(task) = this.journal.tasks.iter_mut().find(|task| task.id == id) {
                    task.last_stage = last_stage.or(task.last_stage);
                    task.finish(result);
                    if task.failure.as_ref().is_some_and(|failure| {
                        matches!(
                            failure.kind,
                            FailureKind::VerificationRequired
                                | FailureKind::AuthenticationRequired
                                | FailureKind::UnlockRequired
                        )
                    }) {
                        task.state = TaskState::AwaitingInput;
                    }
                }
                this.persist_history();
                if this.quit_requested && !this.account_busy() {
                    cx.quit();
                    return;
                }
                this.start_next(cx);
                cx.notify();
            });
        })
        .detach();
        cx.spawn(async move |view, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(150))
                    .await;
                let keep_polling = view
                    .update(cx, |this, cx| {
                        let stage = this
                            .active
                            .as_ref()
                            .filter(|(active_id, _, _)| *active_id == id)
                            .and_then(|(_, _, latest)| {
                                latest.lock().ok().map(|progress| progress.stage)
                            });
                        if let Some(stage) = stage
                            && let Some(task) =
                                this.journal.tasks.iter_mut().find(|task| task.id == id)
                            && task.last_stage != Some(stage)
                        {
                            task.last_stage = Some(stage);
                            this.persist_history();
                        }
                        cx.notify();
                        this.active
                            .as_ref()
                            .is_some_and(|(active_id, _, _)| *active_id == id)
                    })
                    .unwrap_or(false);
                if !keep_polling {
                    break;
                }
            }
        })
        .detach();
    }

    pub(super) fn cancel_task(&mut self, id: u64, cx: &mut Context<Self>) {
        if let Some(task) = self.journal.tasks.iter_mut().find(|task| task.id == id) {
            if let Some((active_id, operation, _)) = &self.active {
                if *active_id == id {
                    operation.cancel();
                    task.state = TaskState::CancellationRequested;
                } else if matches!(task.state, TaskState::Queued | TaskState::AwaitingInput) {
                    task.finish(Err(ipatool_rs::application::operation::Cancelled.into()));
                }
            } else if task.state.is_active() {
                task.finish(Err(ipatool_rs::application::operation::Cancelled.into()));
            }
        }
        self.persist_history();
        self.start_next(cx);
        cx.notify();
    }

    pub(super) fn retry_task(
        &mut self,
        id: u64,
        acquire: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(task) = self
            .journal
            .tasks
            .iter()
            .find(|task| task.id == id && !task.state.is_active())
        {
            let mut request = task.request.clone();
            let title = task.title.clone();
            if let JobRequest::Download(download) = &mut request
                && acquire
            {
                download.purchase = true;
            }
            if let JobRequest::Download(download) = request {
                self.review_download(title, download, window, cx);
                return;
            }
            if let JobRequest::FairPlay(request) = request {
                self.review_fairplay(request, window, cx);
            }
        }
    }

    fn review_download(
        &mut self,
        title: String,
        request: DownloadRequest,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(account) = &self.account else {
            self.pending_retry = Some((title, request));
            self.open_account(window, cx);
            return;
        };
        let country = account.country.clone();
        let platform = request.platform.unwrap_or(Platform::Iphone);
        let suffix = format!(" / {}", platform_name(platform));
        let app = CatalogApp {
            id: request.app_id.unwrap_or_default(),
            bundle_id: request.bundle_identifier.clone().unwrap_or_default(),
            name: title.strip_suffix(&suffix).unwrap_or(&title).to_owned(),
            ..Default::default()
        };
        self.open_download(app, platform, country, window, cx);
        if let Some(form) = &mut self.download_form {
            if let Some(output) = &request.output {
                form.output.update(cx, |input, cx| {
                    input.set_value(output.to_string_lossy().into_owned(), window, cx)
                });
            }
            form.version.update(cx, |input, cx| {
                input.set_value(request.external_version_id.clone(), window, cx)
            });
            form.acquire_license = request.purchase;
            form.original_request = Some(request);
        }
        cx.notify();
    }

    fn review_fairplay(
        &mut self,
        request: FairPlayRequest,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if matches!(request, FairPlayRequest::Decrypt { force: true, .. }) {
            self.show_notice("This saved task uses Force. Review and run that expert operation through the CLI; the desktop preserves existing files and requires model checks.", cx);
            return;
        }
        let path = |value: Option<PathBuf>| {
            value
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let mut fields = Vec::new();
        for input in [
            &self.fair.app,
            &self.fair.input,
            &self.fair.model,
            &self.fair.output,
            &self.fair.directory_output,
            &self.fair.capture,
            &self.fair.report,
            &self.fair.fairplayd,
            &self.fair.startup,
            &self.fair.iokit,
            &self.fair.system_state,
            &self.fair.shared_state,
            &self.fair.adi_state,
            &self.fair.iomac,
            &self.fair.product_version,
            &self.fair.build_version,
        ] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        match request {
            FairPlayRequest::Inspect {
                ipa,
                model,
                capture,
                report,
            } => {
                self.set_fair_mode(FairMode::Inspect, window, cx);
                fields.extend([
                    (self.fair.input.clone(), path(ipa)),
                    (self.fair.model.clone(), path(model)),
                    (self.fair.capture.clone(), path(capture)),
                    (self.fair.report.clone(), path(report)),
                ]);
            }
            FairPlayRequest::Decrypt {
                input,
                model,
                output,
                report,
                ..
            } => {
                self.set_fair_mode(FairMode::Decrypt, window, cx);
                fields.extend([
                    (self.fair.input.clone(), path(Some(input))),
                    (self.fair.model.clone(), path(Some(model))),
                    (self.fair.output.clone(), path(Some(output))),
                    (self.fair.report.clone(), path(Some(report))),
                ]);
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
                self.set_fair_mode(FairMode::Collect, window, cx);
                fields.extend([
                    (self.fair.app.clone(), path(Some(app))),
                    (self.fair.input.clone(), path(ipa)),
                    (self.fair.directory_output.clone(), path(Some(output))),
                    (self.fair.fairplayd.clone(), path(fairplayd)),
                    (self.fair.system_state.clone(), path(system_state)),
                    (self.fair.shared_state.clone(), path(shared_state)),
                    (self.fair.adi_state.clone(), path(adi_state)),
                    (self.fair.iomac.clone(), path(iomac_file)),
                    (self.fair.interface.clone(), interface),
                    (
                        self.fair.product_version.clone(),
                        product_version.unwrap_or_default(),
                    ),
                    (
                        self.fair.build_version.clone(),
                        build_version.unwrap_or_default(),
                    ),
                ]);
            }
            FairPlayRequest::Recover {
                capture,
                output,
                compat_fairplayd,
                startup_profile,
                iokit15_output,
                timeout_seconds,
            } => {
                self.set_fair_mode(FairMode::Recover, window, cx);
                fields.extend([
                    (self.fair.capture.clone(), path(Some(capture))),
                    (self.fair.directory_output.clone(), path(Some(output))),
                    (self.fair.fairplayd.clone(), path(compat_fairplayd)),
                    (self.fair.startup.clone(), path(startup_profile)),
                    (self.fair.iokit.clone(), path(iokit15_output)),
                    (self.fair.timeout.clone(), timeout_seconds.to_string()),
                ]);
            }
        }
        for (input, value) in fields {
            input.update(cx, |input, cx| input.set_value(value, window, cx));
        }
        self.fair.advanced = matches!(self.fair.mode, FairMode::Collect | FairMode::Recover);
        self.page = Page::FairPlay;
        self.shell_focus.focus(window);
        self.show_notice("Saved parameters restored. Review the inputs and choose new output paths where necessary before starting again.", cx);
    }

    pub(super) fn submit_fairplay(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let value = |input: &Entity<InputState>| input.read(cx).value().trim().to_owned();
        let path = |input: &Entity<InputState>| PathBuf::from(value(input));
        let optional = |input: &Entity<InputState>| {
            let value = value(input);
            (!value.is_empty()).then(|| PathBuf::from(value))
        };
        if self.fair.mode == FairMode::Inspect
            && [&self.fair.input, &self.fair.model, &self.fair.capture]
                .iter()
                .all(|input| value(input).is_empty())
        {
            self.show_notice("Choose an IPA, a decryption model, or a collected materials folder to check first.", cx);
            return;
        }
        let request = match self.fair.mode {
            FairMode::Inspect => FairPlayRequest::Inspect {
                ipa: optional(&self.fair.input),
                model: optional(&self.fair.model),
                capture: optional(&self.fair.capture),
                report: optional(&self.fair.report),
            },
            FairMode::Decrypt => {
                let input = path(&self.fair.input);
                let model = path(&self.fair.model);
                if !input.is_file() || !model.exists() {
                    self.show_notice(
                        "Choose the downloaded IPA and its matching decryption model first.",
                        cx,
                    );
                    return;
                }
                let output = optional(&self.fair.output)
                    .unwrap_or_else(|| input.with_extension("decrypted.ipa"));
                let report = optional(&self.fair.report)
                    .unwrap_or_else(|| input.with_extension("decrypted.json"));
                if output.exists() || report.exists() {
                    self.show_notice("An output or report already exists. Choose new paths; existing files are preserved.", cx);
                    return;
                }
                FairPlayRequest::Decrypt {
                    input,
                    model,
                    output,
                    report,
                    force: false,
                }
            }
            FairMode::Collect => {
                let app = path(&self.fair.app);
                let output = path(&self.fair.directory_output);
                if !app.is_dir()
                    || output.as_os_str().is_empty()
                    || !output.is_absolute()
                    || output.exists()
                {
                    self.show_notice("Select the installed .app, then choose a new materials folder with a full path. The folder must not already exist.", cx);
                    return;
                }
                FairPlayRequest::Collect {
                    app,
                    ipa: optional(&self.fair.input),
                    output,
                    fairplayd: optional(&self.fair.fairplayd),
                    system_state: optional(&self.fair.system_state),
                    shared_state: optional(&self.fair.shared_state),
                    adi_state: optional(&self.fair.adi_state),
                    iomac_file: optional(&self.fair.iomac),
                    interface: value(&self.fair.interface),
                    product_version: {
                        let value = value(&self.fair.product_version);
                        (!value.is_empty()).then_some(value)
                    },
                    build_version: {
                        let value = value(&self.fair.build_version);
                        (!value.is_empty()).then_some(value)
                    },
                }
            }
            FairMode::Recover => {
                let capture = path(&self.fair.capture);
                let output = path(&self.fair.directory_output);
                let timeout_seconds = match value(&self.fair.timeout).parse::<u64>() {
                    Ok(value) if (1..=3600).contains(&value) => value,
                    _ => {
                        self.show_notice(
                            "Recovery phase timeout must be between 1 and 3600 seconds.",
                            cx,
                        );
                        return;
                    }
                };
                if !capture.is_dir()
                    || output.as_os_str().is_empty()
                    || !output.is_absolute()
                    || output.exists()
                {
                    self.show_notice(
                        "Select the collected materials folder, then choose a new model output folder with a full path. The output folder must not already exist.",
                        cx,
                    );
                    return;
                }
                FairPlayRequest::Recover {
                    capture,
                    output,
                    compat_fairplayd: optional(&self.fair.fairplayd),
                    startup_profile: optional(&self.fair.startup),
                    iokit15_output: optional(&self.fair.iokit),
                    timeout_seconds,
                }
            }
        };
        let title = request.label().to_owned();
        self.enqueue(title, JobRequest::FairPlay(request), window, cx);
    }
    fn quit_decision_closed(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.quit_prompt_open = false;
        let view = cx.entity().downgrade();
        window.defer(cx, move |window, cx| {
            let _ = view.update(cx, |this, cx| {
                if this.quit_requested {
                    return;
                }
                if std::mem::take(&mut this.account_completion_deferred) {
                    if this.account.is_some() {
                        this.finish_account_success(window, cx);
                    } else {
                        window.close_all_dialogs(cx);
                    }
                } else if this.account_form.verifying {
                    this.account_form
                        .code
                        .update(cx, |input, cx| input.focus(window, cx));
                } else if this.account_form.unlocking_saved {
                    this.account_form
                        .passphrase
                        .update(cx, |input, cx| input.focus(window, cx));
                }
                cx.notify();
            });
        });
    }

    pub(super) fn close_panel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.quit_prompt_open {
            window.close_dialog(cx);
            self.quit_decision_closed(window, cx);
        } else if window.has_active_dialog(cx) && !self.account_form.busy {
            self.clear_secrets(window, cx);
            self.pending_download = None;
            self.pending_retry = None;
            self.download_form = None;
            self.download_generation = self.download_generation.wrapping_add(1);
            if let Some(operation) = &self.version_operation {
                operation.cancel();
            }
            window.close_all_dialogs(cx);
            self.start_next(cx);
        } else {
            self.request_quit(window, cx);
        }
    }

    pub(super) fn request_quit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.account_busy() {
            self.persist_history();
            self.clear_secrets(window, cx);
            cx.quit();
            return;
        }
        if self.quit_requested {
            self.show_notice("Stopping work at a safe boundary before quitting. Respond to any outstanding system credential dialog.", cx);
            return;
        }
        if self.quit_prompt_open {
            return;
        }
        self.quit_prompt_open = true;
        let view = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, _, cx| {
            let view = view.clone();
            let close = view.clone();
            dialog.bg(cx.theme().popover).title("Stop work and quit?")
                .child("Queued tasks will be cancelled. Running work will stop at a safe boundary before the application quits. Output publication and outstanding system credential prompts may need to finish first.")
                .confirm().on_ok(move |_, window, cx| {
                    let _ = view.update(cx, |this, cx| {
                        this.quit_requested = true;
                        if let Some((id, operation, _)) = &this.active {
                            operation.cancel();
                            if let Some(task) = this.journal.tasks.iter_mut().find(|task| task.id == *id) { task.state = TaskState::CancellationRequested; }
                        }
                        if let Some(operation) = &this.account_form.operation { operation.cancel(); }
                        if let Some(operation) = &this.library_operation { operation.cancel(); }
                        if let Some(operation) = &this.version_operation { operation.cancel(); }
                        for task in &mut this.journal.tasks { if matches!(task.state, TaskState::Queued | TaskState::AwaitingInput) { task.state = TaskState::Cancelled; } }
                        this.persist_history(); this.show_notice("Stopping safely before quitting...", cx);
                        if !this.account_busy() {
                            this.clear_secrets(window, cx);
                            cx.quit();
                        }
                    });
                    true
                }).on_close(move |_, window, cx| { let _ = close.update(cx, |this, cx| this.quit_decision_closed(window, cx)); })
        });
    }
    pub(super) fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if window.has_active_dialog(cx) {
            return;
        }
        self.settings_error = None;
        let view = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, window, cx| {
            view.update(cx, |this, cx| this.settings_dialog(dialog, window, cx))
                .unwrap_or_else(|_| Dialog::new(window, cx))
        });
    }

    pub(super) fn save_preferences(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let preferences = Preferences {
            schema: 1,
            country: self.selected_country(cx),
            platform: self.platform,
            mode: self.mode,
            output_directory: Some(PathBuf::from(self.settings_output.read(cx).value().trim())),
        };
        if let Err(error) = preferences.validate() {
            self.settings_error = Some(error.to_string());
            cx.notify();
            return false;
        }
        if preferences
            .save(&self.session.directory().join("desktop-preferences.json"))
            .is_err()
        {
            self.settings_error = Some(
                "Preferences could not be saved. Check directory access and free space.".into(),
            );
            cx.notify();
            return false;
        }
        self.preferences = preferences;
        cx.notify();
        true
    }
}
