//! Controller integration fixtures. These never open credentials or contact Apple.

use super::{
    AccountView, AppIdentity, ArtifactKind, CatalogApp, DesktopFrame, DesktopSession,
    DesktopWindow, DownloadRequest, JobRequest, Journal, LoginInput, Mode, Operation, Page,
    Platform, Progress, Stage, TaskRecord, TaskState, appearance,
};
use anyhow::Result;
use gpui::{AppContext, Entity, IntoElement, TestAppContext, VisualTestContext};
use gpui_component::{Root, WindowExt};
use ipatool_rs::{
    application::tasks::{Artifact, JobOutcome},
    ipa_metadata::VersionMetadata,
    store_download_product::ListVersionsOutput,
    store_owned::OwnedAppsOutput,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

struct FixtureSession {
    directory: PathBuf,
    generation: AtomicU64,
    login_calls: Mutex<Vec<(bool, bool)>>,
    purchases: Mutex<Vec<(usize, Option<Platform>)>>,
    catalogs: Mutex<Vec<ipatool_rs::application::catalog::Query>>,
    account_country: Mutex<String>,
    jobs: Mutex<Vec<JobRequest>>,
    expire_next_job: AtomicBool,
}

impl FixtureSession {
    fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            generation: AtomicU64::new(1),
            login_calls: Mutex::new(Vec::new()),
            purchases: Mutex::new(Vec::new()),
            catalogs: Mutex::new(Vec::new()),
            account_country: Mutex::new("US".into()),
            jobs: Mutex::new(Vec::new()),
            expire_next_job: AtomicBool::new(false),
        }
    }
    fn account() -> AccountView {
        AccountView {
            name: "Fixture Account".into(),
            email: "fixture@example.invalid".into(),
            country: "US".into(),
        }
    }
    fn app() -> CatalogApp {
        CatalogApp {
            id: 42,
            name: "Fixture App".into(),
            bundle_id: "invalid.example.fixture".into(),
            version: "1.2.3".into(),
            ..Default::default()
        }
    }

    fn account_view(&self) -> AccountView {
        let mut account = Self::account();
        account.country = self.account_country.lock().unwrap().clone();
        account
    }
}

impl DesktopSession for FixtureSession {
    fn catalog(&self, query: &ipatool_rs::application::catalog::Query) -> Result<Vec<CatalogApp>> {
        self.catalogs.lock().unwrap().push(query.clone());
        let mut app = Self::app();
        app.id = if query.term == "second" { 2 } else { 1 };
        app.name = query.term.clone();
        Ok(vec![app])
    }
    fn directory(&self) -> &Path {
        &self.directory
    }
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
    fn account_identity(&self) -> Option<String> {
        Some("fixture-account-and-storefront".into())
    }
    fn load(&self, force_file: bool, passphrase: Option<String>) -> Result<Option<AccountView>> {
        if force_file && passphrase.as_deref() != Some("fixture-store-passphrase") {
            return Err(ipatool_rs::credentials::CredentialUnlockRequired.into());
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.account_view()))
    }
    fn login(&self, input: LoginInput, _: bool, _: Option<String>) -> Result<AccountView> {
        self.login_calls.lock().unwrap().push((
            input.password == "fixture-password",
            input.auth_code == "123456",
        ));
        if input.auth_code.is_empty() {
            return Err(ipatool_rs::store_login::AuthCodeRequired.into());
        }
        assert_eq!(input.auth_code, "123456");
        assert_eq!(input.password, "fixture-password");
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(self.account_view())
    }
    fn revoke(&self) -> Result<()> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn purchases(&self, page: usize, platform: Option<Platform>) -> Result<OwnedAppsOutput> {
        self.purchases.lock().unwrap().push((page, platform));
        Ok(OwnedAppsOutput {
            count: 1,
            total_count: 50,
            page,
            apps: vec![Self::app()],
        })
    }
    fn versions(&self, _: &AppIdentity) -> Result<ListVersionsOutput> {
        Ok(ListVersionsOutput {
            external_version_identifiers: vec!["100".into(), "101".into()],
            latest_external_version_id: "101".into(),
        })
    }
    fn version_metadata(&self, _: &AppIdentity, _: &str) -> Result<VersionMetadata> {
        Ok(VersionMetadata {
            display_version: "1.2.3".into(),
            release_date: "2026-10-28T00:00:00Z".into(),
        })
    }
    fn execute(
        &self,
        request: JobRequest,
        generation: u64,
        operation: &Operation,
    ) -> Result<JobOutcome> {
        assert_eq!(generation, self.generation());
        self.jobs.lock().unwrap().push(request);
        if self.expire_next_job.swap(false, Ordering::SeqCst) {
            return Err(ipatool_rs::store_purchase::PasswordTokenExpired.into());
        }
        operation.run(|| {
            operation.report(Progress {
                stage: Stage::Downloading,
                completed: 64,
                total: Some(128),
            });
            Ok(JobOutcome {
                summary: "Fixture processing completed".into(),
                artifacts: vec![Artifact {
                    kind: ArtifactKind::Package,
                    path: self.directory.join("fixture.ipa"),
                }],
                details: None,
            })
        })
    }
}

fn setup(
    cx: &mut TestAppContext,
) -> (
    tempfile::TempDir,
    Entity<DesktopWindow>,
    Arc<FixtureSession>,
    VisualTestContext,
) {
    setup_with_history(cx, None)
}

fn setup_with_history(
    cx: &mut TestAppContext,
    history: Option<Journal>,
) -> (
    tempfile::TempDir,
    Entity<DesktopWindow>,
    Arc<FixtureSession>,
    VisualTestContext,
) {
    let directory = tempfile::tempdir().unwrap();
    if let Some(history) = history {
        history
            .save(&directory.path().join("desktop-tasks.json"))
            .unwrap();
    }
    let session = Arc::new(FixtureSession::new(directory.path().to_path_buf()));
    cx.update(|cx| {
        gpui_component::init(cx);
        appearance::configure(cx);
    });
    let mut desktop = None;
    let window = cx.add_window(|window, cx| {
        let view = cx.new(|cx| DesktopWindow::new(directory.path().to_path_buf(), window, cx));
        super::desktop_shortcuts(&view, window, cx);
        view.update(cx, |this, _| this.session = session.clone());
        desktop = Some(view.clone());
        let root = cx.entity();
        let frame = cx.new(|cx| DesktopFrame {
            _subscriptions: vec![
                cx.observe(&root, |_, _, cx| cx.notify()),
                cx.observe(&view, |_, _, cx| cx.notify()),
            ],
            view,
        });
        Root::new(frame, window, cx)
    });
    let mut visual = VisualTestContext::from_window(window.into(), cx);
    visual.run_until_parked();
    // Keep no test-global environment or credential configuration.
    visual.update(|_, _| {});
    (directory, desktop.unwrap(), session, visual)
}

#[gpui::test]
fn sidebar_footer_actions_remain_usable_in_narrow_and_collapsed_windows(cx: &mut TestAppContext) {
    let (_directory, view, session, mut cx) = setup(cx);
    for (width, height, expanded) in [
        (900., 650., true),
        (1240., 820., true),
        (1240., 820., false),
    ] {
        cx.simulate_resize(gpui::size(gpui::px(width), gpui::px(height)));
        cx.update(|_, cx| {
            view.update(cx, |this, cx| {
                this.sidebar_visible = expanded;
                cx.notify();
            });
        });
        for selector in ["shell-account", "shell-settings"] {
            cx.draw(
                Default::default(),
                gpui::size(gpui::px(width), gpui::px(height)),
                |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
            );
            let bounds = cx
                .debug_bounds(selector)
                .expect("footer action was painted");
            assert!(bounds.origin.x >= gpui::px(0.) && bounds.right() <= gpui::px(width));
            assert!(bounds.origin.y >= gpui::px(0.) && bounds.bottom() <= gpui::px(height));
            cx.simulate_click(bounds.center(), Default::default());
            cx.run_until_parked();
            cx.update(|window, cx| assert!(window.has_active_dialog(cx)));
            assert!(session.login_calls.lock().unwrap().is_empty());
            cx.simulate_keystrokes("escape");
            cx.update(|window, cx| assert!(!window.has_active_dialog(cx)));
        }
        if width >= 1000. {
            for expected in [!expanded, expanded] {
                cx.draw(
                    Default::default(),
                    gpui::size(gpui::px(width), gpui::px(height)),
                    |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
                );
                let toggle = cx.debug_bounds("shell-toggle").expect("toggle was painted");
                cx.simulate_click(toggle.center(), Default::default());
                cx.run_until_parked();
                cx.update(|_, cx| {
                    view.update(cx, |this, _| assert_eq!(this.sidebar_visible, expected));
                });
            }
        }
    }
}

#[gpui::test]
fn narrow_application_details_keep_the_final_actions_reachable(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    for (width, height) in [(900., 650.), (1240., 820.)] {
        for page in [Page::Explore, Page::Library] {
            cx.simulate_resize(gpui::size(gpui::px(width), gpui::px(height)));
            cx.update(|_, cx| {
                view.update(cx, |this, cx| {
                    this.page = page;
                    this.account = Some(FixtureSession::account());
                    this.apps = vec![FixtureSession::app()];
                    this.selected = Some(0);
                    this.library_apps = vec![FixtureSession::app()];
                    this.library_selected = Some(0);
                    this.details_scroll.set_offset(Default::default());
                    this.query = Some(
                        ipatool_rs::application::catalog::Query::new(
                            Mode::Search,
                            "Fixture",
                            "US",
                            Platform::Macos,
                        )
                        .unwrap(),
                    );
                    cx.notify();
                })
            });
            cx.draw(
                Default::default(),
                gpui::size(gpui::px(width), gpui::px(height)),
                |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
            );
            cx.update(|_, cx| {
                view.update(cx, |this, _| {
                    assert!(this.details_scroll.max_offset().height > gpui::px(0.));
                    this.details_scroll.set_offset(gpui::point(
                        gpui::px(0.),
                        -this.details_scroll.max_offset().height,
                    ));
                })
            });
            cx.draw(
                Default::default(),
                gpui::size(gpui::px(width), gpui::px(height)),
                |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
            );
            let last = cx
                .debug_bounds("details-final-actions")
                .expect("detail actions were painted");
            cx.update(|_, cx| {
                view.update(cx, |this, _| {
                    assert!(
                        last.bottom() <= this.details_scroll.bounds().bottom(),
                        "actions: {last:?}, scroll: {:?}",
                        this.details_scroll
                    );
                    assert!(
                        this.details_scroll.bounds().bottom() <= gpui::px(height),
                        "scroll viewport extends outside window: {:?}",
                        this.details_scroll.bounds()
                    );
                })
            });
        }
    }
}

#[gpui::test]
fn narrow_download_keeps_its_action_visible_with_versions_and_an_error(cx: &mut TestAppContext) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.simulate_resize(gpui::size(gpui::px(900.), gpui::px(650.)));
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account = Some(FixtureSession::account());
            this.open_download(
                FixtureSession::app(),
                Platform::Macos,
                "GB".into(),
                window,
                cx,
            );
            let form = this.download_form.as_mut().unwrap();
            form.versions = (100..300).map(|id| id.to_string()).collect();
            form.error =
                Some("Choose an existing absolute output directory before continuing.".into());
        })
    });
    cx.draw(
        Default::default(),
        gpui::size(gpui::px(900.), gpui::px(650.)),
        |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
    );
    let bounds = cx
        .debug_bounds("download-footer-submit")
        .expect("download action was painted");
    assert!(bounds.top() >= gpui::px(0.));
    assert!(bounds.bottom() <= gpui::px(650.), "{bounds:?}");
    assert!(bounds.size.height > gpui::px(20.));
    assert!(session.jobs.lock().unwrap().is_empty());
}

#[gpui::test]
fn narrow_account_error_keeps_both_footer_actions_inside_the_window(cx: &mut TestAppContext) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.simulate_resize(gpui::size(gpui::px(900.), gpui::px(650.)));
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.open_account(window, cx);
            this.account_form.force_file = true;
            this.submit_account(false, window, cx);
            assert!(this.account_form.error.is_some());
        })
    });
    cx.draw(
        Default::default(),
        gpui::size(gpui::px(900.), gpui::px(650.)),
        |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
    );
    for selector in ["account-footer-cancel", "account-footer-submit"] {
        let bounds = cx
            .debug_bounds(selector)
            .expect("account action was painted");
        assert!(bounds.top() >= gpui::px(0.));
        assert!(bounds.bottom() <= gpui::px(650.), "{selector}: {bounds:?}");
        assert!(bounds.size.height > gpui::px(20.));
    }
    assert!(session.login_calls.lock().unwrap().is_empty());
}

#[gpui::test]
fn narrow_fairplay_forms_keep_advanced_inputs_scrollable(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    cx.simulate_resize(gpui::size(gpui::px(900.), gpui::px(650.)));
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            this.page = Page::FairPlay;
            this.fair.mode = super::FairMode::Collect;
            this.fair.advanced = true;
            cx.notify();
        })
    });
    cx.run_until_parked();
    cx.draw(
        Default::default(),
        gpui::size(gpui::px(900.), gpui::px(650.)),
        |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
    );
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(
                this.fair_scroll.max_offset().height > gpui::px(250.),
                "scroll: {:?}",
                this.fair_scroll
            );
            assert!(this.fair_scroll.bounds().size.height > gpui::px(250.));
            this.fair_scroll.set_offset(gpui::point(
                gpui::px(0.),
                -this.fair_scroll.max_offset().height,
            ));
        })
    });
    cx.draw(
        Default::default(),
        gpui::size(gpui::px(900.), gpui::px(650.)),
        |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
    );
    let last = cx
        .debug_bounds("fairplay-last-input")
        .expect("last input was painted");
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(
                last.bottom() <= this.fair_scroll.bounds().bottom(),
                "input: {last:?}, scroll: {:?}",
                this.fair_scroll
            );
        })
    });
}

#[gpui::test]
fn lifecycle_shortcut_reaches_a_focused_account_dialog(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    let operation = Operation::default();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.open_account(window, cx);
            this.account_form.busy = true;
            this.account_form.operation = Some(operation.clone());
        })
    });
    let quit = if cfg!(target_os = "macos") {
        "cmd-q"
    } else {
        "ctrl-q"
    };
    cx.simulate_keystrokes(quit);
    cx.run_until_parked();
    cx.update(|_, cx| view.update(cx, |this, _| assert!(this.quit_prompt_open)));
    cx.simulate_keystrokes("escape");
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(!this.quit_prompt_open);
            assert!(!this.quit_requested);
        })
    });
    assert!(!operation.is_cancelled());
    cx.simulate_keystrokes(quit);
    cx.run_until_parked();
    cx.simulate_keystrokes("enter");
    cx.update(|_, cx| view.update(cx, |this, _| assert!(this.quit_requested)));
    assert!(operation.is_cancelled());
}

#[gpui::test]
fn account_completion_preserves_quit_confirmation_and_pending_download(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.pending_download = Some((FixtureSession::app(), Platform::Iphone, "US".into()));
            this.open_account(window, cx);
            this.account_form.force_file = true;
            this.account_form.passphrase.update(cx, |input, cx| {
                input.set_value("fixture-store-passphrase", window, cx)
            });
            this.submit_account(true, window, cx);
            this.request_quit(window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(this.account.is_some());
            assert!(this.quit_prompt_open);
            assert!(this.account_completion_deferred);
            assert!(this.pending_download.is_some());
            assert!(this.download_form.is_none());
        })
    });
    cx.simulate_keystrokes("escape");
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(!this.quit_prompt_open);
            assert!(!this.account_completion_deferred);
            assert!(!this.quit_requested);
            assert!(this.pending_download.is_none());
            assert!(this.download_form.is_some());
        })
    });
}

#[gpui::test]
fn quit_confirmation_cancels_workers_and_persists_pending_tasks(cx: &mut TestAppContext) {
    let (directory, view, session, mut cx) = setup(cx);
    let operation = Operation::default();
    let account = Operation::default();
    let library = Operation::default();
    let version = Operation::default();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            for id in 1..=3 {
                let mut task = TaskRecord::new(
                    id,
                    "Fixture pending download".into(),
                    JobRequest::Download(DownloadRequest::default()),
                    1,
                );
                task.state = match id {
                    1 => TaskState::Running,
                    2 => TaskState::Queued,
                    _ => TaskState::AwaitingInput,
                };
                this.journal.tasks.push(task);
            }
            this.active = Some((
                1,
                operation.clone(),
                Arc::new(Mutex::new(Progress {
                    stage: Stage::Downloading,
                    completed: 64,
                    total: Some(128),
                })),
            ));
            this.account_form.operation = Some(account.clone());
            this.library_operation = Some(library.clone());
            this.version_operation = Some(version.clone());
            this.request_quit(window, cx);
            assert!(!this.quit_requested);
            assert!(!operation.is_cancelled());
        })
    });
    cx.simulate_keystrokes("enter");
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(this.quit_requested);
            // The running job remains visible until its worker acknowledges cancellation.
            assert!(this.active.is_some());
            assert_eq!(
                this.journal.tasks[0].state,
                TaskState::CancellationRequested
            );
            assert_eq!(this.journal.tasks[1].state, TaskState::Cancelled);
            assert_eq!(this.journal.tasks[2].state, TaskState::Cancelled);
        })
    });
    for worker in [operation, account, library, version] {
        assert!(worker.is_cancelled());
    }
    assert!(session.jobs.lock().unwrap().is_empty());
    let saved = std::fs::read(directory.path().join("desktop-tasks.json")).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(saved["tasks"][0]["state"], "CancellationRequested");
    assert_eq!(saved["tasks"][1]["state"], "Cancelled");
    assert_eq!(saved["tasks"][2]["state"], "Cancelled");
}

#[gpui::test]
fn quit_confirmation_after_work_finished_does_not_wait_for_a_missing_worker(
    cx: &mut TestAppContext,
) {
    let (_directory, view, _session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account_form.busy = true;
            this.account_form.secret = Some(zeroize::Zeroizing::new("fixture-password".into()));
            this.request_quit(window, cx);
            // A worker may finish while the user is reading the confirmation.
            this.account_form.busy = false;
        })
    });
    cx.simulate_keystrokes("enter");
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(this.quit_requested);
            assert!(!this.account_busy());
            assert!(this.account_form.secret.is_none());
        })
    });
}

#[gpui::test]
fn declining_quit_keeps_the_worker_and_pending_queue_unchanged(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    let operation = Operation::default();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account_form.busy = true;
            this.account_form.operation = Some(operation.clone());
            this.request_quit(window, cx);
        })
    });
    cx.simulate_keystrokes("escape");
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(!this.quit_requested);
            assert!(this.account_form.busy);
            assert!(!operation.is_cancelled());
        })
    });
}

#[gpui::test]
fn restart_displays_interrupted_history_without_executing_any_saved_request(
    cx: &mut TestAppContext,
) {
    let mut task = TaskRecord::new(
        1,
        "Fixture interrupted download".into(),
        JobRequest::Download(DownloadRequest {
            app_id: Some(42),
            external_version_id: "100".into(),
            ..Default::default()
        }),
        1,
    );
    task.state = TaskState::Running;
    task.last_stage = Some(Stage::Downloading);
    let (directory, view, session, mut cx) =
        setup_with_history(cx, Some(Journal { tasks: vec![task] }));
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert_eq!(this.journal.tasks[0].state, TaskState::Interrupted);
            assert_eq!(this.journal.tasks[0].last_stage, Some(Stage::Downloading));
            assert!(this.active.is_none());
            this.persist_history();
        })
    });
    assert!(session.jobs.lock().unwrap().is_empty());
    assert_eq!(
        Journal::load(&directory.path().join("desktop-tasks.json"))
            .unwrap()
            .tasks[0]
            .state,
        TaskState::Interrupted
    );
}

#[gpui::test]
fn completed_capture_and_model_handoff_prefills_inputs_without_starting_private_work(
    cx: &mut TestAppContext,
) {
    let (directory, view, session, mut cx) = setup(cx);
    let capture = directory.path().join("fixture-capture");
    let model = directory.path().join("fixture-model.bin");
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.fair.output.update(cx, |input, cx| {
                input.set_value("previous-output", window, cx)
            });
            this.use_fairplay_artifact(ArtifactKind::Capture, capture.clone(), window, cx);
            assert!(this.page == Page::FairPlay);
            assert!(this.fair.mode == super::FairMode::Recover);
            assert_eq!(
                this.fair.capture.read(cx).value().as_str(),
                capture.to_string_lossy()
            );
            assert!(this.fair.output.read(cx).value().is_empty());
            this.use_fairplay_artifact(ArtifactKind::Model, model.clone(), window, cx);
            assert!(this.fair.mode == super::FairMode::Decrypt);
            assert_eq!(
                this.fair.model.read(cx).value().as_str(),
                model.to_string_lossy()
            );
            assert!(this.fair.report.read(cx).value().is_empty());
        })
    });
    assert!(session.jobs.lock().unwrap().is_empty());
}

#[gpui::test]
fn closing_version_dialog_rejects_its_obsolete_worker_completion(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account = Some(FixtureSession::account());
            this.open_download(
                FixtureSession::app(),
                Platform::Iphone,
                "US".into(),
                window,
                cx,
            );
            this.load_versions(window, cx);
        })
    });
    cx.dispatch_action(super::ClosePanel);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            let mut app = FixtureSession::app();
            app.id = 43;
            this.open_download(app, Platform::Macos, "US".into(), window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            let form = this.download_form.as_ref().unwrap();
            assert_eq!(form.app.id, 43);
            assert!(form.versions.is_empty());
            assert!(this.version_operation.is_none());
        })
    });
}

#[gpui::test]
fn verification_continuation_keeps_pending_download_and_replaces_secret_inputs(
    cx: &mut TestAppContext,
) {
    let (_directory, view, session, mut cx) = setup(cx);
    *session.account_country.lock().unwrap() = "CN".into();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.open_download(
                FixtureSession::app(),
                Platform::Iphone,
                "US".into(),
                window,
                cx,
            );
            this.account_form.email.update(cx, |input, cx| {
                input.set_value("fixture@example.invalid", window, cx)
            });
            this.account_form.password.update(cx, |input, cx| {
                input.set_value("fixture-password", window, cx)
            });
            this.submit_account(false, window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert!(this.account_form.verifying);
            assert!(this.pending_download.is_some());
            assert_eq!(this.selected_country(cx), "US");
            assert!(this.account_form.password.read(cx).value().is_empty());
            this.account_form
                .code
                .update(cx, |input, cx| input.set_value("123456", window, cx));
            this.submit_account(true, window, cx);
            assert!(this.account_form.verifying);
            assert!(!this.account_form.busy);
            assert!(this.account_form.secret.is_some());
            this.submit_account(false, window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert!(this.account.is_some());
            assert!(!this.account_form.verifying);
            assert!(this.pending_download.is_none());
            assert!(this.download_form.is_some());
            assert_eq!(this.selected_country(cx), "CN");
            let download = this.download_form.as_ref().unwrap();
            assert_eq!(download.app.id, 42);
            assert_eq!(download.source_country, "US");
            assert_eq!(download.platform, Platform::Iphone);
            assert!(this.account_form.secret.is_none());
            assert!(this.account_form.code.read(cx).value().is_empty());
        })
    });
    assert_eq!(
        *session.login_calls.lock().unwrap(),
        [(true, false), (true, true)]
    );
    assert!(session.jobs.lock().unwrap().is_empty());
}

#[gpui::test]
fn fairplay_mode_changes_keep_app_ipa_capture_and_output_types_separate(cx: &mut TestAppContext) {
    let (directory, view, session, mut cx) = setup(cx);
    let app = directory.path().join("Fixture.app");
    let ipa = directory.path().join("fixture.ipa");
    let model = directory.path().join("model.bin");
    let capture = directory.path().join("existing-capture");
    let directory_output = directory.path().join("new-capture");
    let file_output = directory.path().join("decrypted.ipa");
    std::fs::create_dir(&app).unwrap();
    std::fs::create_dir(&capture).unwrap();
    std::fs::write(&ipa, b"fixture input").unwrap();
    std::fs::write(&model, b"fixture model").unwrap();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            for (field, path) in [
                (&this.fair.app, &app),
                (&this.fair.input, &ipa),
                (&this.fair.model, &model),
                (&this.fair.capture, &capture),
                (&this.fair.output, &file_output),
                (&this.fair.directory_output, &directory_output),
            ] {
                field.update(cx, |input, cx| {
                    input.set_value(path.to_string_lossy().into_owned(), window, cx)
                });
            }
        })
    });
    for mode in [
        super::FairMode::Collect,
        super::FairMode::Recover,
        super::FairMode::Decrypt,
    ] {
        cx.update(|window, cx| {
            view.update(cx, |this, cx| {
                this.set_fair_mode(mode, window, cx);
                this.submit_fairplay(window, cx);
            })
        });
        cx.run_until_parked();
    }
    let jobs = session.jobs.lock().unwrap();
    assert_eq!(jobs.len(), 3);
    assert!(
        matches!(&jobs[0], JobRequest::FairPlay(super::FairPlayRequest::Collect { app: a, ipa: Some(i), output, .. }) if a == &app && i == &ipa && output == &directory_output)
    );
    assert!(
        matches!(&jobs[1], JobRequest::FairPlay(super::FairPlayRequest::Recover { capture: c, output, .. }) if c == &capture && output == &directory_output)
    );
    assert!(
        matches!(&jobs[2], JobRequest::FairPlay(super::FairPlayRequest::Decrypt { input, model: m, output, .. }) if input == &ipa && m == &model && output == &file_output)
    );
}

#[gpui::test]
fn inspection_followup_restores_checked_materials_without_starting_private_work(
    cx: &mut TestAppContext,
) {
    let (directory, view, session, mut cx) = setup(cx);
    let ipa = directory.path().join("fixture.ipa");
    let model = directory.path().join("fixture-model.bin");
    let capture = directory.path().join("fixture-capture");
    let request = super::FairPlayRequest::Inspect {
        ipa: Some(ipa.clone()),
        model: Some(model.clone()),
        capture: Some(capture.clone()),
        report: Some(directory.path().join("old-report.json")),
    };
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.inspection_followup(request.clone(), super::FairMode::Collect, window, cx);
            assert!(matches!(this.page, Page::FairPlay));
            assert!(matches!(this.fair.mode, super::FairMode::Collect));
            assert!(this.fair.app.read(cx).value().is_empty());
            assert_eq!(
                this.fair.input.read(cx).value().as_ref(),
                ipa.to_str().unwrap()
            );
            this.inspection_followup(request.clone(), super::FairMode::Recover, window, cx);
            assert!(matches!(this.fair.mode, super::FairMode::Recover));
            assert_eq!(
                this.fair.capture.read(cx).value().as_ref(),
                capture.to_str().unwrap()
            );
            this.inspection_followup(request, super::FairMode::Decrypt, window, cx);
            assert!(matches!(this.fair.mode, super::FairMode::Decrypt));
            assert_eq!(
                this.fair.input.read(cx).value().as_ref(),
                ipa.to_str().unwrap()
            );
            assert_eq!(
                this.fair.model.read(cx).value().as_ref(),
                model.to_str().unwrap()
            );
            assert!(this.fair.output.read(cx).value().is_empty());
            assert!(this.fair.report.read(cx).value().is_empty());
            assert!(this.journal.tasks.is_empty());
        })
    });
    assert!(session.jobs.lock().unwrap().is_empty());
}

#[gpui::test]
fn paused_task_opens_reauthentication_directly_without_replacing_the_account(
    cx: &mut TestAppContext,
) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account = Some(FixtureSession::account());
            let stale_password = this.account_form.password.clone();
            this.account_form.password.update(cx, |input, cx| {
                input.set_value("old-fixture-password", window, cx)
            });
            this.continue_account(window, cx);
            assert!(this.account_form.reauthenticating);
            assert_eq!(
                this.account.as_ref().unwrap().email,
                "fixture@example.invalid"
            );
            assert_eq!(
                this.account_form.email.read(cx).value(),
                "fixture@example.invalid"
            );
            assert_ne!(this.account_form.password, stale_password);
            assert!(this.account_form.password.read(cx).value().is_empty());
            assert!(!this.account_busy());
            assert!(session.login_calls.lock().unwrap().is_empty());
        })
    });
}

#[gpui::test]
fn verification_expiration_clears_continuation_without_another_authentication_request(
    cx: &mut TestAppContext,
) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.open_account(window, cx);
            this.account_form.email.update(cx, |input, cx| {
                input.set_value("fixture@example.invalid", window, cx)
            });
            this.account_form.password.update(cx, |input, cx| {
                input.set_value("fixture-password", window, cx)
            });
            this.submit_account(false, window, cx);
        })
    });
    cx.run_until_parked();
    cx.background_executor
        .advance_clock(Duration::from_secs(301));
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert!(!this.account_form.verifying);
            assert!(this.account_form.secret.is_none());
            assert!(this.account_form.verification_deadline.is_none());
            assert!(this.account_form.password.read(cx).value().is_empty());
            assert_eq!(
                this.account_form.error.as_ref().unwrap().title,
                "Verification session expired"
            );
        })
    });
    assert_eq!(session.login_calls.lock().unwrap().len(), 1);
}

#[gpui::test]
fn expired_job_pauses_queue_and_same_account_unlock_resumes_each_request_once(
    cx: &mut TestAppContext,
) {
    let (directory, view, session, mut cx) = setup(cx);
    session.expire_next_job.store(true, Ordering::SeqCst);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account = Some(FixtureSession::account());
            for (id, version) in [(1, "100"), (2, "101")] {
                let mut task = TaskRecord::new(
                    id,
                    format!("Fixture {version}"),
                    JobRequest::Download(DownloadRequest {
                        app_id: Some(42),
                        output: Some(directory.path().join(format!("{version}.ipa"))),
                        external_version_id: version.into(),
                        ..Default::default()
                    }),
                    1,
                );
                task.account_identity = this.session.account_identity();
                this.journal.tasks.push(task);
            }
            this.start_next(cx);
            this.shell_focus.focus(window);
        })
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.journal.tasks[0].state, TaskState::AwaitingInput);
            assert_eq!(this.journal.tasks[1].state, TaskState::Queued);
            this.open_account(window, cx);
            this.account_form.force_file = true;
            this.account_form.passphrase.update(cx, |input, cx| {
                input.set_value("fixture-store-passphrase", window, cx)
            });
            this.submit_account(true, window, cx);
        })
    });
    assert_eq!(session.jobs.lock().unwrap().len(), 1);
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert!(
                this.journal
                    .tasks
                    .iter()
                    .all(|task| task.state == TaskState::Succeeded)
            )
        })
    });
    assert_eq!(session.jobs.lock().unwrap().len(), 3);
    let saved = Journal::load(&directory.path().join("desktop-tasks.json")).unwrap();
    assert!(
        saved
            .tasks
            .iter()
            .all(|task| task.last_stage == Some(Stage::Downloading))
    );
    assert!(
        saved
            .tasks
            .iter()
            .all(|task| task.state == TaskState::Succeeded)
    );
}

#[gpui::test(iterations = 20)]
fn newer_search_and_explicit_clear_ignore_obsolete_background_results(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.mode = Mode::Search;
            for term in ["first", "second"] {
                this.term
                    .update(cx, |input, cx| input.set_value(term, window, cx));
                this.search(cx);
            }
        })
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.apps[0].id, 2);
            assert_eq!(this.query.as_ref().unwrap().term, "second");
            this.term
                .update(cx, |input, cx| input.set_value("first", window, cx));
            this.search(cx);
            this.clear_search(window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert!(this.apps.is_empty());
            assert!(this.query.is_none());
            assert!(!this.searching);
            assert!(this.term.read(cx).value().is_empty());
        })
    });
}

#[gpui::test]
fn invalid_code_and_cancel_do_not_authenticate_and_secret_undo_history_is_dropped(
    cx: &mut TestAppContext,
) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.open_download(
                FixtureSession::app(),
                Platform::Iphone,
                "US".into(),
                window,
                cx,
            );
            this.account_form.email.update(cx, |input, cx| {
                input.set_value("fixture@example.invalid", window, cx)
            });
            this.account_form.password.update(cx, |input, cx| {
                input.set_value("fixture-password", window, cx)
            });
            this.submit_account(false, window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account_form
                .code
                .update(cx, |input, cx| input.set_value("invalid", window, cx));
            this.submit_account(false, window, cx);
            assert!(this.account_form.verifying);
            assert!(this.account_form.secret.is_some());
            assert_eq!(
                this.account_form.error.as_ref().unwrap().title,
                "Check verification code"
            );
        })
    });
    assert_eq!(session.login_calls.lock().unwrap().len(), 1);
    cx.dispatch_action(super::ClosePanel);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert!(!this.account_form.verifying);
            assert!(this.account_form.secret.is_none());
            assert!(this.pending_download.is_none());
            this.open_account(window, cx);
            this.account_form
                .password
                .update(cx, |input, cx| input.focus(window, cx));
        })
    });
    cx.dispatch_action(gpui_component::input::Undo);
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert!(this.account_form.password.read(cx).value().is_empty())
        })
    });
    assert_eq!(session.login_calls.lock().unwrap().len(), 1);
}

#[gpui::test]
fn wrong_file_unlock_is_recoverable_and_clears_each_passphrase_input(cx: &mut TestAppContext) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.open_account(window, cx);
            this.account_form.force_file = true;
            // A partially entered login must not change an explicit saved-account unlock.
            this.account_form.email.update(cx, |input, cx| {
                input.set_value("fixture@example.invalid", window, cx)
            });
            this.account_form.passphrase.update(cx, |input, cx| {
                input.set_value("wrong-fixture-passphrase", window, cx)
            });
            this.submit_account(true, window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert!(this.account.is_none());
            assert!(!this.account_form.busy);
            assert!(this.account_form.unlocking_saved);
            assert_eq!(
                this.account_form.error.as_ref().unwrap().kind,
                super::FailureKind::UnlockRequired
            );
            assert!(this.account_form.passphrase.read(cx).value().is_empty());
            this.account_form.passphrase.update(cx, |input, cx| {
                input.set_value("fixture-store-passphrase", window, cx)
            });
            // The primary action uses the saved-account intent, even with an email present.
            this.submit_account(false, window, cx);
        })
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert!(this.account.is_some());
            assert!(!this.account_form.unlocking_saved);
            assert!(this.account_form.passphrase.read(cx).value().is_empty());
        })
    });
    assert!(session.login_calls.lock().unwrap().is_empty());
}

#[gpui::test]
fn library_filter_keeps_details_and_download_selection_on_visible_apps(cx: &mut TestAppContext) {
    let (_directory, view, _session, mut cx) = setup(cx);
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            this.page = Page::Library;
            this.account = Some(FixtureSession::account());
            let mut beta = FixtureSession::app();
            beta.id = 43;
            beta.name = "Beta Application".into();
            beta.bundle_id = "invalid.example.beta".into();
            this.library_apps = vec![FixtureSession::app(), beta];
            this.library_selected = Some(0);
        })
    });
    for (filter, expected) in [
        ("BETA", Some(43)),
        ("no-match", None),
        ("fixture", Some(42)),
        ("", Some(42)),
    ] {
        cx.update(|window, cx| {
            view.update(cx, |this, cx| {
                this.library_filter
                    .update(cx, |input, cx| input.set_value(filter, window, cx))
            })
        });
        cx.run_until_parked();
        cx.update(|_, cx| {
            view.update(cx, |this, _| {
                assert_eq!(this.selected_app().map(|app| app.id), expected)
            })
        });
    }
}

#[gpui::test]
fn library_refresh_retains_offer_snapshot_and_selected_application(cx: &mut TestAppContext) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            this.account = Some(FixtureSession::account());
            this.page = Page::Library;
            this.library_platform = Platform::Macos;
            this.load_library(cx);
        })
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.library_result_platform, Platform::Macos);
            assert_eq!(this.library_selected, Some(0));
            this.library_page = 2;
            this.library_platform = Platform::Ipad;
            this.load_library(cx);
        })
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, _| {
            assert_eq!(this.library_result_platform, Platform::Ipad);
            assert_eq!(this.library_selected, Some(0));
            assert_eq!(this.library_total, 50);
        })
    });
    assert_eq!(
        *session.purchases.lock().unwrap(),
        [(1, Some(Platform::Macos)), (2, Some(Platform::Ipad))]
    );
}

#[gpui::test]
fn retry_restores_editable_download_parameters_and_preserves_existing_output(
    cx: &mut TestAppContext,
) {
    let (directory, view, session, mut cx) = setup(cx);
    let existing = directory.path().join("existing.ipa");
    std::fs::write(&existing, b"original fixture output").unwrap();
    let new_output = directory.path().join("retry.ipa");
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account = Some(FixtureSession::account());
            let mut task = TaskRecord::new(
                1,
                "Fixture App / macos".into(),
                JobRequest::Download(DownloadRequest {
                    app_id: Some(42),
                    output: Some(existing.clone()),
                    external_version_id: "100".into(),
                    platform: Some(Platform::Macos),
                    ..Default::default()
                }),
                1,
            );
            task.state = TaskState::Failed;
            this.journal.tasks.push(task);
            this.retry_task(1, true, window, cx);
            let form = this.download_form.as_ref().unwrap();
            assert_eq!(form.version.read(cx).value().as_str(), "100");
            assert!(form.acquire_license);
            assert_eq!(form.platform, Platform::Macos);
            this.submit_download(window, cx);
            assert!(this.download_form.as_ref().unwrap().error.is_some());
            this.download_form
                .as_mut()
                .unwrap()
                .output
                .update(cx, |input, cx| {
                    input.set_value(new_output.to_string_lossy().into_owned(), window, cx)
                });
            this.submit_download(window, cx);
        })
    });
    cx.run_until_parked();
    let jobs = session.jobs.lock().unwrap();
    assert_eq!(jobs.len(), 1);
    let JobRequest::Download(request) = &jobs[0] else {
        panic!("expected fixture download");
    };
    assert_eq!(request.output.as_ref(), Some(&new_output));
    assert_eq!(request.external_version_id, "100");
    assert!(request.purchase);
    assert_eq!(std::fs::read(existing).unwrap(), b"original fixture output");
}

#[gpui::test(iterations = 20)]
fn changing_catalog_filters_refreshes_without_reusing_the_previous_download_selection(
    cx: &mut TestAppContext,
) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.platform = Platform::Macos;
            this.term
                .update(cx, |input, cx| input.set_value("second", window, cx));
            this.search(cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.query.as_ref().unwrap().platform, Platform::Macos);
            assert!(this.selected_app().is_some());
            this.set_platform(Platform::Iphone, cx);
            assert!(this.searching);
            assert!(this.selected_app().is_none());
            assert!(this.query.is_none());
            this.set_country("CN", window, cx);
            assert!(this.apps.is_empty());
            assert!(this.query.is_none());
        });
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            let query = this.query.as_ref().unwrap();
            assert_eq!(query.country, "CN");
            assert_eq!(query.platform, Platform::Iphone);
            assert_eq!(this.selected_country(cx), "CN");
            assert_eq!(this.apps[0].id, 2);
        });
    });
    let catalogs = session.catalogs.lock().unwrap();
    assert_eq!(catalogs.len(), 3);
    assert!(
        catalogs
            .iter()
            .any(|query| query.country == "CN" && query.platform == Platform::Iphone)
    );
    assert!(session.jobs.lock().unwrap().is_empty());
}

#[gpui::test]
fn searchable_region_menu_confirms_by_keyboard_and_escape_preserves_selection(
    cx: &mut TestAppContext,
) {
    let (_directory, view, _session, mut cx) = setup(cx);
    cx.simulate_resize(gpui::size(gpui::px(900.), gpui::px(650.)));
    for (search, confirm, expected) in [
        ("China", false, "US"),
        ("China", true, "CN"),
        ("GB", false, "CN"),
        ("GB", true, "GB"),
        ("US", true, "US"),
    ] {
        cx.draw(
            Default::default(),
            gpui::size(gpui::px(900.), gpui::px(650.)),
            |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
        );
        let bounds = cx
            .debug_bounds("catalog-region")
            .expect("region selector was painted");
        assert!(bounds.right() <= gpui::px(900.));
        cx.simulate_click(bounds.center(), Default::default());
        cx.run_until_parked();
        cx.simulate_input(search);
        cx.run_until_parked();
        cx.simulate_keystrokes(if confirm { "enter" } else { "escape" });
        cx.run_until_parked();
        cx.update(|_, cx| {
            view.update(cx, |this, cx| {
                assert_eq!(this.selected_country(cx), expected)
            })
        });
    }
}

#[gpui::test]
fn editing_download_platform_resets_version_data_and_queues_the_reviewed_platform(
    cx: &mut TestAppContext,
) {
    let (_directory, view, session, mut cx) = setup(cx);
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.account = Some(FixtureSession::account());
            this.open_download(
                FixtureSession::app(),
                Platform::Macos,
                "US".into(),
                window,
                cx,
            );
            let form = this.download_form.as_mut().unwrap();
            form.version
                .update(cx, |input, cx| input.set_value("100", window, cx));
            form.versions = vec!["100".into()];
            form.metadata = Some((
                "100".into(),
                VersionMetadata {
                    display_version: "1.0".into(),
                    release_date: "fixture".into(),
                },
            ));
            let output = form.output.read(cx).value();
            let previous_generation = this.download_generation;
            this.set_download_platform(Platform::Iphone, window, cx);
            let form = this.download_form.as_ref().unwrap();
            assert!(this.download_generation > previous_generation);
            assert!(form.version.read(cx).value().is_empty());
            assert!(form.versions.is_empty());
            assert!(form.metadata.is_none());
            assert_eq!(form.output.read(cx).value(), output);
            this.submit_download(window, cx);
        });
    });
    cx.run_until_parked();
    let jobs = session.jobs.lock().unwrap();
    assert_eq!(jobs.len(), 1);
    let JobRequest::Download(request) = &jobs[0] else {
        panic!("expected download");
    };
    assert_eq!(request.platform, Some(Platform::Iphone));
    assert!(request.external_version_id.is_empty());
}

#[gpui::test]
fn account_region_is_the_default_without_overwriting_an_explicit_same_account_override(
    cx: &mut TestAppContext,
) {
    let (_directory, view, session, mut cx) = setup(cx);
    *session.account_country.lock().unwrap() = "CN".into();
    cx.simulate_resize(gpui::size(gpui::px(900.), gpui::px(650.)));
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            this.term
                .update(cx, |input, cx| input.set_value("second", window, cx));
            this.search(cx);
            this.open_account(window, cx);
            this.submit_account(true, window, cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.account.as_ref().unwrap().country, "CN");
            assert_eq!(this.selected_country(cx), "CN");
            assert_eq!(this.query.as_ref().unwrap().country, "CN");
            assert_eq!(this.preferences.country, "US");
            this.set_country("US", window, cx);
            this.submit_account(true, window, cx);
        });
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.selected_country(cx), "US");
            assert_eq!(this.query.as_ref().unwrap().country, "US");
        });
    });
    cx.draw(
        Default::default(),
        gpui::size(gpui::px(900.), gpui::px(650.)),
        |window, _| window.root::<Root>().unwrap().unwrap().into_any_element(),
    );
    let warning = cx
        .debug_bounds("catalog-region-warning")
        .expect("cross-region warning was painted");
    assert!(warning.right() <= gpui::px(900.) && warning.bottom() <= gpui::px(650.));
    let back = cx
        .debug_bounds("browse-account-region")
        .expect("account-region shortcut was painted");
    cx.simulate_click(back.center(), Default::default());
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.selected_country(cx), "CN");
            assert_eq!(this.query.as_ref().unwrap().country, "CN");
            this.set_country("US", window, cx);
            // A different account with the same storefront gets its own default.
            this.account.as_mut().unwrap().email = "other@example.invalid".into();
            this.submit_account(true, window, cx);
        });
    });
    cx.run_until_parked();
    *session.account_country.lock().unwrap() = "GB".into();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.selected_country(cx), "CN");
            this.set_country("US", window, cx);
            this.submit_account(true, window, cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.selected_country(cx), "GB");
            assert_eq!(this.query.as_ref().unwrap().country, "GB");
            this.set_country("US", window, cx);
            this.account_form.force_file = true;
            this.submit_account(true, window, cx);
        });
    });
    cx.run_until_parked();
    cx.update(|_, cx| {
        view.update(cx, |this, cx| {
            assert_eq!(this.selected_country(cx), "US");
            assert_eq!(this.account.as_ref().unwrap().country, "GB");
            assert_eq!(
                this.account_form.error.as_ref().unwrap().kind,
                super::FailureKind::UnlockRequired
            );
        });
    });
    assert!(session.jobs.lock().unwrap().is_empty());
}
