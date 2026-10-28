//! Native desktop front end for the shared Rust application workflows.

#![cfg_attr(all(target_os = "windows", not(test)), windows_subsystem = "windows")]

mod actions;
mod appearance;
mod artwork;
mod assets;
mod preferences;
#[cfg(feature = "gui-test")]
mod preview;
mod session;
#[cfg(all(test, feature = "gui-test"))]
mod tests;
mod views;

use gpui::{prelude::*, *};
use gpui_component::{
    ActiveTheme, Disableable, Icon, IconName, Root, Selectable, Sizable, WindowExt,
    button::{Button, ButtonVariants},
    dialog::Dialog,
    h_flex,
    input::{Input, InputEvent, InputState},
    resizable::{h_resizable, resizable_panel},
    v_flex,
};
use ipatool_rs::{
    App as CatalogApp, Platform,
    application::{
        catalog::{Mode, Query, platform_name},
        download::DownloadRequest,
        failure::{Failure, FailureKind},
        fairplay::FairPlayRequest,
        library::AppIdentity,
        operation::{Operation, Progress, Stage},
        tasks::{ArtifactKind, JobRequest, Journal, MAX_TASKS, TaskRecord, TaskState},
    },
    store_login::LoginInput,
};
use preferences::Preferences;
use session::{AccountView, DesktopSession, Session};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;

actions!(
    ipatool_desktop,
    [QuitDesktop, ClosePanel, FocusSearch, OpenSettings]
);

const PLATFORMS: [(Platform, &str); 6] = [
    (Platform::Iphone, "iPhone"),
    (Platform::Ipad, "iPad"),
    (Platform::Macos, "Mac"),
    (Platform::Appletv, "Apple TV"),
    (Platform::Watchos, "Watch"),
    (Platform::Visionos, "Vision"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Explore,
    Library,
    Downloads,
    FairPlay,
}
impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Explore => "Explore",
            Self::Library => "Library",
            Self::Downloads => "Downloads",
            Self::FairPlay => "FairPlay",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum FairMode {
    Inspect,
    Decrypt,
    Collect,
    Recover,
}

struct Form {
    email: Entity<InputState>,
    password: Entity<InputState>,
    code: Entity<InputState>,
    passphrase: Entity<InputState>,
    force_file: bool,
    unlocking_saved: bool,
    verifying: bool,
    reauthenticating: bool,
    input_subscriptions: Vec<Subscription>,
    secret: Option<Zeroizing<String>>,
    busy: bool,
    error: Option<Failure>,
    operation: Option<Operation>,
    verification_deadline: Option<std::time::Instant>,
}
struct DownloadForm {
    app: CatalogApp,
    platform: Platform,
    source_country: String,
    output: Entity<InputState>,
    version: Entity<InputState>,
    versions: Vec<String>,
    loading_versions: bool,
    metadata: Option<(String, ipatool_rs::ipa_metadata::VersionMetadata)>,
    _version_subscription: Subscription,
    original_request: Option<DownloadRequest>,
    acquire_license: bool,
    error: Option<String>,
}
struct FairForm {
    mode: FairMode,
    app: Entity<InputState>,
    input: Entity<InputState>,
    model: Entity<InputState>,
    output: Entity<InputState>,
    directory_output: Entity<InputState>,
    capture: Entity<InputState>,
    report: Entity<InputState>,
    fairplayd: Entity<InputState>,
    startup: Entity<InputState>,
    iokit: Entity<InputState>,
    timeout: Entity<InputState>,
    system_state: Entity<InputState>,
    shared_state: Entity<InputState>,
    adi_state: Entity<InputState>,
    iomac: Entity<InputState>,
    interface: Entity<InputState>,
    product_version: Entity<InputState>,
    build_version: Entity<InputState>,
    advanced: bool,
}

struct DesktopWindow {
    page: Page,
    shell_focus: FocusHandle,
    session: Arc<dyn DesktopSession>,
    account: Option<AccountView>,
    account_form: Form,
    term: Entity<InputState>,
    country: Entity<InputState>,
    mode: Mode,
    platform: Platform,
    apps: Vec<CatalogApp>,
    artwork: std::collections::HashMap<i64, Arc<Image>>,
    selected: Option<usize>,
    library_selected: Option<usize>,
    results_focus: FocusHandle,
    results_scroll: ScrollHandle,
    details_scroll: ScrollHandle,
    fair_scroll: ScrollHandle,
    query: Option<Query>,
    query_id: u64,
    searching: bool,
    search_error: Option<Failure>,
    library_apps: Vec<CatalogApp>,
    library_page: usize,
    library_platform: Platform,
    library_result_platform: Platform,
    library_operation: Option<Operation>,
    library_filter: Entity<InputState>,
    library_total: usize,
    library_loading: bool,
    library_error: Option<Failure>,
    download_form: Option<DownloadForm>,
    download_generation: u64,
    version_operation: Option<Operation>,
    pending_download: Option<(CatalogApp, Platform, String)>,
    pending_retry: Option<(String, DownloadRequest)>,
    fair: FairForm,
    journal: Journal,
    journal_error: Option<String>,
    active: Option<(u64, Operation, Arc<Mutex<Progress>>)>,
    selected_task: Option<u64>,
    notice: Option<String>,
    preferences: Preferences,
    settings_output: Entity<InputState>,
    settings_error: Option<String>,
    quit_requested: bool,
    quit_prompt_open: bool,
    account_completion_deferred: bool,
    sidebar_visible: bool,
    _subscriptions: Vec<Subscription>,
}

/// Modal builders access the desktop entity outside its render borrow.
struct DesktopFrame {
    view: Entity<DesktopWindow>,
    _subscriptions: Vec<Subscription>,
}

impl Render for DesktopFrame {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let quit = self.view.clone();
        let close = self.view.clone();
        let search = self.view.clone();
        let settings = self.view.clone();
        let focus = self.view.read(cx).shell_focus.clone();
        div()
            .relative()
            .track_focus(&focus)
            .tab_stop(false)
            .key_context("Desktop")
            .on_action(move |_: &QuitDesktop, window, cx| {
                quit.update(cx, |this, cx| this.request_quit(window, cx));
            })
            .on_action(move |_: &ClosePanel, window, cx| {
                close.update(cx, |this, cx| this.close_panel(window, cx));
            })
            .on_action(move |_: &FocusSearch, window, cx| {
                search.update(cx, |this, cx| {
                    if !window.has_active_dialog(cx) {
                        this.page = Page::Explore;
                        this.term.update(cx, |input, cx| input.focus(window, cx));
                        cx.notify();
                    }
                });
            })
            .size_full()
            .on_action(move |_: &OpenSettings, window, cx| {
                settings.update(cx, |this, cx| this.open_settings(window, cx));
            })
            .child(self.view.clone())
            .children(Root::render_dialog_layer(window, cx))
            .children(Root::render_notification_layer(window, cx))
    }
}

fn field(
    window: &mut Window,
    cx: &mut App,
    placeholder: &'static str,
    value: &str,
    secret: bool,
) -> Entity<InputState> {
    cx.new(|cx| {
        let mut input = InputState::new(window, cx)
            .placeholder(placeholder)
            .masked(secret);
        input.set_value(value.to_owned(), window, cx);
        input
    })
}

fn desktop_shortcuts(view: &Entity<DesktopWindow>, window: &Window, cx: &mut App) {
    let modifier = if cfg!(target_os = "macos") {
        "cmd"
    } else {
        "ctrl"
    };
    // Dialog focus is rendered in a deferred layer and may not inherit the
    // shell's key context. Application lifecycle actions must still work there.
    cx.bind_keys([
        KeyBinding::new(&format!("{modifier}-q"), QuitDesktop, None),
        KeyBinding::new(&format!("{modifier}-w"), ClosePanel, None),
    ]);
    let handle = window.window_handle();
    let quit = view.downgrade();
    cx.on_action(move |_: &QuitDesktop, cx| {
        let quit = quit.clone();
        cx.defer(move |cx| {
            let _ = handle.update(cx, |_, window, cx| {
                let _ = quit.update(cx, |this, cx| this.request_quit(window, cx));
            });
        });
    });
    let close = view.downgrade();
    cx.on_action(move |_: &ClosePanel, cx| {
        let close = close.clone();
        cx.defer(move |cx| {
            let _ = handle.update(cx, |_, window, cx| {
                let _ = close.update(cx, |this, cx| this.close_panel(window, cx));
            });
        });
    });
}

fn account_input_subscriptions(
    form: &Form,
    window: &mut Window,
    cx: &mut Context<DesktopWindow>,
) -> Vec<Subscription> {
    [&form.email, &form.password, &form.code, &form.passphrase]
        .into_iter()
        .map(|input| {
            cx.subscribe_in(input, window, |this, _, event, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    let saved = !this.account_form.verifying
                        && this.account_form.email.read(cx).value().trim().is_empty()
                        && this.account_form.password.read(cx).value().is_empty();
                    this.submit_account(saved, window, cx);
                }
            })
        })
        .collect()
}

impl DesktopWindow {
    fn new(directory: PathBuf, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let preferences_result = Preferences::load(&directory.join("desktop-preferences.json"));
        let (preferences, preference_notice) = match preferences_result { Ok(value) => (value, None), Err(_) => (Preferences::default(), Some("Desktop preferences could not be loaded. Defaults are in use; settings will only be replaced when you save them.".to_owned())) };
        let settings_output = field(
            window,
            cx,
            "Default download directory",
            &preferences
                .output_directory
                .clone()
                .or_else(dirs::download_dir)
                .unwrap_or_else(|| directory.clone())
                .to_string_lossy(),
            false,
        );
        let journal_result = Journal::load(&directory.join("desktop-tasks.json"));
        let (journal, journal_error) = match journal_result { Ok(value) => (value, None), Err(_) => (Journal::default(), Some("Task history could not be read. It has been preserved; recover history before starting new jobs.".into())) };
        let mut account_form = Form {
            email: field(window, cx, "Apple ID (email or phone)", "", false),
            password: field(window, cx, "Password", "", true),
            code: field(window, cx, "Verification code", "", false),
            passphrase: field(window, cx, "File-store passphrase", "", true),
            force_file: cfg!(target_os = "windows"),
            unlocking_saved: false,
            verifying: false,
            secret: None,
            busy: false,
            error: None,
            operation: None,
            verification_deadline: None,
            reauthenticating: false,
            input_subscriptions: Vec::new(),
        };
        account_form.input_subscriptions = account_input_subscriptions(&account_form, window, cx);
        let term = field(
            window,
            cx,
            "Search apps, paste an App Store link, ID, or bundle identifier",
            "",
            false,
        );
        let country = field(window, cx, "Country", &preferences.country, false);
        let library_filter = field(
            window,
            cx,
            "Filter the applications on this page",
            "",
            false,
        );
        let mut subscriptions: Vec<_> = [&term, &country]
            .into_iter()
            .map(|input| {
                cx.subscribe_in(input, window, |this, _, event, _, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        this.search(cx);
                    }
                    if matches!(event, InputEvent::Change) {
                        cx.notify();
                    }
                })
            })
            .collect();
        subscriptions.push(
            cx.subscribe(&library_filter, |this, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.reconcile_library_selection(cx);
                    this.results_scroll.set_offset(Default::default());
                }
                cx.notify();
            }),
        );
        let fair = FairForm {
            mode: FairMode::Inspect,
            app: field(window, cx, "Installed application (.app)", "", false),
            input: field(window, cx, "Personalized IPA", "", false),
            model: field(window, cx, "Enrollment model or model directory", "", false),
            output: field(window, cx, "New output path", "", false),
            directory_output: field(window, cx, "New output directory", "", false),
            capture: field(window, cx, "Capture directory", "", false),
            report: field(window, cx, "Optional report path", "", false),
            fairplayd: field(window, cx, "Matching fairplayd image", "", false),
            startup: field(window, cx, "Checked startup profile", "", false),
            iokit: field(window, cx, "Verified IOKit selector output", "", false),
            timeout: field(window, cx, "Phase timeout (seconds)", "600", false),
            system_state: field(window, cx, "System SC Info", "", false),
            shared_state: field(window, cx, "Shared SC Info", "", false),
            adi_state: field(window, cx, "ADI state", "", false),
            iomac: field(window, cx, "Hardware MAC file", "", false),
            interface: field(window, cx, "Network interface", "en0", false),
            product_version: field(window, cx, "Product version", "", false),
            build_version: field(window, cx, "Build version", "", false),
            advanced: false,
        };
        term.update(cx, |input, cx| input.focus(window, cx));
        gpui_component::Theme::change(gpui_component::ThemeMode::Dark, Some(window), cx);
        Self {
            page: Page::Explore,
            shell_focus: cx.focus_handle(),
            session: Arc::new(Session::new(directory)),
            account: None,
            account_form,
            term,
            country,
            mode: preferences.mode,
            platform: preferences.platform,
            apps: vec![],
            artwork: Default::default(),
            selected: None,
            library_selected: None,
            results_focus: cx.focus_handle(),
            results_scroll: ScrollHandle::new(),
            details_scroll: ScrollHandle::new(),
            fair_scroll: ScrollHandle::new(),
            query: None,
            query_id: 0,
            searching: false,
            search_error: None,
            library_apps: vec![],
            library_page: 1,
            library_platform: preferences.platform,
            library_result_platform: preferences.platform,
            library_operation: None,
            library_filter,
            library_total: 0,
            library_loading: false,
            library_error: None,
            download_form: None,
            download_generation: 0,
            version_operation: None,
            pending_download: None,
            pending_retry: None,
            fair,
            journal,
            journal_error,
            active: None,
            selected_task: None,
            notice: preference_notice,
            settings_output,
            settings_error: None,
            preferences,
            quit_requested: false,
            quit_prompt_open: false,
            account_completion_deferred: false,
            sidebar_visible: true,
            _subscriptions: subscriptions,
        }
    }

    fn show_notice(&mut self, message: impl Into<String>, cx: &mut Context<Self>) {
        self.notice = Some(message.into());
        cx.notify();
    }
    fn account_busy(&self) -> bool {
        self.active.is_some()
            || self.account_form.busy
            || self.library_loading
            || self.version_operation.is_some()
            || self
                .download_form
                .as_ref()
                .is_some_and(|form| form.loading_versions)
    }
    fn selected_app(&self) -> Option<CatalogApp> {
        let apps = if self.page == Page::Library {
            &self.library_apps
        } else {
            &self.apps
        };
        let selected = if self.page == Page::Library {
            self.library_selected
        } else {
            self.selected
        };
        selected.and_then(|index| apps.get(index)).cloned()
    }
    fn reconcile_library_selection(&mut self, cx: &App) {
        let filter = self.library_filter.read(cx).value().to_lowercase();
        let previous = self.library_selected;
        if !previous
            .and_then(|index| self.library_apps.get(index))
            .is_some_and(|app| matches_library_filter(app, &filter))
        {
            self.library_selected = self
                .library_apps
                .iter()
                .position(|app| matches_library_filter(app, &filter));
        }
        if previous != self.library_selected {
            self.details_scroll.set_offset(Default::default());
        }
    }
    fn copy(&mut self, text: String, window: &mut Window, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        window.push_notification("Copied to clipboard", cx);
    }
}

fn matches_library_filter(app: &CatalogApp, filter: &str) -> bool {
    filter.is_empty()
        || app.name.to_lowercase().contains(filter)
        || app.bundle_id.to_lowercase().contains(filter)
}

impl Render for DesktopWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let page = match self.page {
            Page::Explore => self.explore_view(cx),
            Page::Library => self.library_view(cx),
            Page::Downloads => self.tasks_view(cx),
            Page::FairPlay => self.fairplay_view(cx),
        };
        let active_count = self
            .journal
            .tasks
            .iter()
            .filter(|task| task.state.is_active())
            .count();
        let can_expand = window.viewport_size().width >= px(1000.);
        let expanded = self.sidebar_visible && can_expand;
        let account_label = self
            .account
            .as_ref()
            .map(|account| format!("{} / {}", account.name, account.country))
            .unwrap_or_else(|| "Sign in".into());
        let account = Button::new("account")
            .debug_selector(|| "shell-account".into())
            .ghost()
            .w_full()
            .h(px(36.))
            .icon(IconName::CircleUser)
            .tooltip(account_label.clone())
            .when(expanded, |button| {
                button.px_3().justify_start().child(
                    div()
                        .w(px(120.))
                        .truncate()
                        .text_left()
                        .child(account_label),
                )
            })
            .disabled(self.account_form.busy)
            .on_click(cx.listener(|this, _, window, cx| this.open_account(window, cx)));
        let settings = Button::new("settings")
            .debug_selector(|| "shell-settings".into())
            .ghost()
            .w_full()
            .h(px(36.))
            .icon(IconName::Settings)
            .tooltip("Settings")
            .when(expanded, |button| {
                button.flex_1().px_3().justify_start().label("Settings")
            })
            .on_click(cx.listener(|this, _, window, cx| this.open_settings(window, cx)));
        let toggle = Button::new("toggle-navigation")
            .debug_selector(|| "shell-toggle".into())
            .small()
            .ghost()
            .icon(IconName::PanelLeft)
            .tooltip(if expanded {
                "Collapse sidebar"
            } else {
                "Expand sidebar"
            })
            .w(px(28.))
            .h(px(28.))
            .on_click(cx.listener(|this, _, _, cx| {
                this.sidebar_visible = !this.sidebar_visible;
                cx.notify();
            }));
        let footer_controls = if expanded {
            h_flex()
                .gap_1()
                .child(settings)
                .child(toggle)
                .into_any_element()
        } else {
            v_flex()
                .items_center()
                .gap_1()
                .child(settings)
                .when(can_expand, |column| column.child(toggle))
                .into_any_element()
        };
        let sidebar = v_flex()
            .w(px(if expanded { 200. } else { 56. }))
            .flex_shrink_0()
            .h_full()
            .px(px(if expanded { 12. } else { 8. }))
            .py_4()
            .gap_1()
            .border_r_1()
            .border_color(cx.theme().border)
            .children(
                [
                    Page::Explore,
                    Page::Library,
                    Page::Downloads,
                    Page::FairPlay,
                ]
                .into_iter()
                .enumerate()
                .map(|(index, page)| {
                    let label = if page == Page::Downloads && active_count > 0 {
                        format!("Downloads  {active_count}")
                    } else {
                        page.title().into()
                    };
                    Button::new(("navigation", index))
                        .ghost()
                        .w_full()
                        .h(px(36.))
                        .px(px(if expanded { 12. } else { 0. }))
                        .icon(match page {
                            Page::Explore => IconName::Globe,
                            Page::Library => IconName::Inbox,
                            Page::Downloads => IconName::ArrowDown,
                            Page::FairPlay => IconName::CircleCheck,
                        })
                        .tooltip(label.clone())
                        .when(expanded, |button| button.justify_start().label(label))
                        .when(
                            !expanded && page == Page::Downloads && active_count > 0,
                            |button| {
                                button.child(div().text_xs().child(if active_count > 9 {
                                    "9+".to_owned()
                                } else {
                                    active_count.to_string()
                                }))
                            },
                        )
                        .selected(self.page == page)
                        .when(self.page == page, |button| {
                            button
                                .bg(cx.theme().accent)
                                .text_color(cx.theme().foreground)
                        })
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.page = page;
                            this.shell_focus.focus(window);

                            if page == Page::Library
                                && this.account.is_some()
                                && this.library_apps.is_empty()
                            {
                                this.load_library(cx);
                            }
                            if page == Page::Library && this.account.is_none() {
                                this.open_account(window, cx);
                            }
                            cx.notify();
                        }))
                }),
            )
            .child(div().flex_1())
            .child(
                v_flex()
                    .gap_1()
                    .pt_2()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(account)
                    .child(footer_controls),
            );
        v_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .text_sm()
            .when(self.session.is_fixture(), |view| {
                view.child(
                    div()
                        .px_3()
                        .py_1()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child("Fixture preview · no Apple requests"),
                )
            })
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .child(sidebar)
                    .child(page),
            )
            .when(self.notice.is_some(), |view| {
                view.child(
                    h_flex()
                        .px_5()
                        .py_2()
                        .gap_3()
                        .border_t_1()
                        .border_color(cx.theme().border)
                        .child(
                            div()
                                .flex_1()
                                .child(self.notice.clone().unwrap_or_default()),
                        )
                        .child(
                            Button::new("dismiss-notice")
                                .small()
                                .label("Dismiss")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.notice = None;
                                    cx.notify();
                                })),
                        ),
                )
            })
    }
}

fn initial_window_size() -> Size<Pixels> {
    // The optional test build can render native layout captures at a known
    // viewport. Ordinary GUI/release builds always use the normal initial size.
    #[cfg(feature = "gui-test")]
    if let Ok(value) = std::env::var("IPATOOL_GUI_TEST_WINDOW_SIZE")
        && let Some((width, height)) = value.split_once('x')
        && let (Ok(width), Ok(height)) = (width.parse::<u16>(), height.parse::<u16>())
        && (900..=3840).contains(&width)
        && (650..=2160).contains(&height)
    {
        return size(px(f32::from(width)), px(f32::from(height)));
    }
    size(px(1240.), px(820.))
}

fn main() {
    Application::new().with_assets(assets::Assets).run(|cx| {
        #[cfg(not(feature = "gui-test"))]
        if std::env::var_os("IPATOOL_GUI_PREVIEW").is_some() {
            eprintln!("Fixture preview requires a gui-test build; refusing to use native account services.");
            cx.quit();
            return;
        }
        gpui_component::init(cx);
        appearance::configure(cx);
        let modifier = if cfg!(target_os = "macos") {
            "cmd"
        } else {
            "ctrl"
        };
        cx.bind_keys([
            KeyBinding::new(&format!("{modifier}-q"), QuitDesktop, Some("Desktop")),
            KeyBinding::new(&format!("{modifier}-w"), ClosePanel, Some("Desktop")),
            KeyBinding::new(&format!("{modifier}-f"), FocusSearch, Some("Desktop")),
            KeyBinding::new(&format!("{modifier}-,"), OpenSettings, Some("Desktop")),
        ]);
        cx.set_menus(vec![
            Menu {
                name: "ipatool".into(),
                items: vec![
                    MenuItem::action("Settings...", OpenSettings),
                    MenuItem::separator(),
                    MenuItem::os_submenu("Services", SystemMenuType::Services),
                    MenuItem::separator(),
                    MenuItem::action("Quit ipatool", QuitDesktop),
                ],
            },
            Menu {
                name: "Edit".into(),
                items: vec![
                    MenuItem::action("Undo", gpui_component::input::Undo),
                    MenuItem::action("Redo", gpui_component::input::Redo),
                    MenuItem::separator(),
                    MenuItem::action("Cut", gpui_component::input::Cut),
                    MenuItem::action("Copy", gpui_component::input::Copy),
                    MenuItem::action("Paste", gpui_component::input::Paste),
                    MenuItem::action("Select All", gpui_component::input::SelectAll),
                    MenuItem::separator(),
                    MenuItem::action("Find Applications", FocusSearch),
                ],
            },
        ]);
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        let directory = match ipatool_rs::state::prepare_state_directory_from_environment() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("Cannot prepare desktop state: {error:#}");
                cx.quit();
                return;
            }
        };
        let bounds = Bounds::centered(None, initial_window_size(), cx);
        #[cfg(feature = "gui-test")]
        let fixture_session = match preview::from_environment(&directory) {
            Ok(session) => session,
            Err(error) => {
                eprintln!("Cannot open fixture preview: {error:#}");
                cx.quit();
                return;
            }
        };
        let result = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(900.), px(650.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("ipatool".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|cx| DesktopWindow::new(directory, window, cx));
                desktop_shortcuts(&view, window, cx);
                #[cfg(feature = "gui-test")]
                if let Some(session) = fixture_session {
                    view.update(cx, |this, cx| {
                        let output = session.directory().join("fixture-output");
                        this.preferences.output_directory = Some(output.clone());
                        this.settings_output.update(cx, |input, cx| {
                            input.set_value(output.to_string_lossy().into_owned(), window, cx)
                        });
                        this.session = session;
                    });
                }
                let closing = view.downgrade();
                window.on_window_should_close(cx, move |window, cx| {
                    closing
                        .update(cx, |this, cx| {
                            if this.account_busy() {
                                this.request_quit(window, cx);
                                false
                            } else {
                                this.persist_history();
                                this.clear_secrets(window, cx);
                                true
                            }
                        })
                        .unwrap_or(true)
                });
                cx.new(|cx| {
                    let root = cx.entity();
                    let frame = cx.new(|cx| {
                        let subscriptions = vec![
                            cx.observe(&root, |_, _, cx| cx.notify()),
                            cx.observe(&view, |_, _, cx| cx.notify()),
                        ];
                        DesktopFrame {
                            view,
                            _subscriptions: subscriptions,
                        }
                    });
                    Root::new(frame, window, cx)
                })
            },
        );
        if let Err(error) = result {
            eprintln!("Cannot open desktop window: {error:#}");
            cx.quit();
        }
        cx.activate(true);
    });
}
