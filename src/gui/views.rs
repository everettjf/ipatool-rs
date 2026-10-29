use super::*;

fn task_display_title(title: &str, request: &JobRequest) -> String {
    if let JobRequest::FairPlay(request) = request {
        return match request {
            FairPlayRequest::Inspect { .. } => "FairPlay: Check compatibility",
            FairPlayRequest::Collect { .. } => "FairPlay: Collect files",
            FairPlayRequest::Recover { .. } => "FairPlay: Create decryption model",
            FairPlayRequest::Decrypt { .. } => "FairPlay: Decrypt IPA",
        }
        .into();
    }
    if let JobRequest::Download(request) = request {
        let platform = request.platform.unwrap_or(Platform::Iphone);
        let suffix = format!(" / {}", platform_name(platform));
        if let Some(name) = title.strip_suffix(&suffix) {
            return format!("{} / {}", name, platform_label(platform));
        }
    }
    title.to_owned()
}

pub(super) fn request_description(request: &JobRequest) -> String {
    let path = |path: &std::path::Path| path.display().to_string();
    let optional = |value: &Option<PathBuf>| {
        value
            .as_ref()
            .map(|value| path(value))
            .unwrap_or_else(|| "Not selected".into())
    };
    match request {
        JobRequest::Download(value) => format!(
            "Download for: {}\nVersion: {}\nSave to: {}\nAcquire free license if needed: {}",
            platform_label(value.platform.unwrap_or(Platform::Iphone)),
            if value.external_version_id.is_empty() {
                "Latest"
            } else {
                &value.external_version_id
            },
            optional(&value.output),
            if value.purchase { "Yes" } else { "No" }
        ),
        JobRequest::FairPlay(FairPlayRequest::Inspect {
            ipa,
            model,
            capture,
            report,
        }) => format!(
            "Inspect materials\nIPA: {}\nModel: {}\nCapture: {}\nReport: {}",
            optional(ipa),
            optional(model),
            optional(capture),
            optional(report)
        ),
        JobRequest::FairPlay(FairPlayRequest::Decrypt {
            input,
            model,
            output,
            report,
            force,
        }) => format!(
            "Decrypt IPA\nInput: {}\nModel: {}\nOutput: {}\nReport: {}\nAllow unverified model: {}",
            path(input),
            path(model),
            path(output),
            path(report),
            force
        ),
        JobRequest::FairPlay(FairPlayRequest::Collect {
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
        }) => format!(
            "Collect enrollment\nApplication: {}\nIPA: {}\nOutput: {}\nFairplayd: {}\nSystem state: {}\nShared state: {}\nADI state: {}\nHardware MAC file: {}\nInterface: {}\nProduct version: {}\nBuild: {}\nUnselected collection inputs use current-host defaults and require access to private state.",
            path(app),
            optional(ipa),
            path(output),
            optional(fairplayd),
            optional(system_state),
            optional(shared_state),
            optional(adi_state),
            optional(iomac_file),
            interface,
            product_version.as_deref().unwrap_or("Current host"),
            build_version.as_deref().unwrap_or("Current host")
        ),
        JobRequest::FairPlay(FairPlayRequest::Recover {
            capture,
            output,
            compat_fairplayd,
            startup_profile,
            iokit15_output,
            timeout_seconds,
        }) => format!(
            "Recover enrollment\nCapture: {}\nOutput: {}\nCompatibility fairplayd: {}\nStartup profile: {}\nIOKit selector output: {}\nPhase timeout: {} seconds",
            path(capture),
            path(output),
            optional(compat_fairplayd),
            optional(startup_profile),
            optional(iokit15_output),
            timeout_seconds
        ),
    }
}

fn muted(text: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .text_color(cx.theme().muted_foreground)
        .child(text.into())
}
fn label(text: &'static str, cx: &App) -> Div {
    muted(text, cx).text_xs()
}

fn region_mismatch_message(browsing: &str, account: &str) -> String {
    format!(
        "Apps from {} may be unavailable to download with your {} account. Your account region is unchanged.",
        regions::label(browsing),
        regions::label(account)
    )
}

fn inspection_next_action(action: &str) -> (&str, Option<FairMode>) {
    match action {
        "collect native enrollment with fairplay-enroll collect" => (
            "No model yet? Step 2 collects local materials from the installed app on a supported Mac. An IPA alone is not enough.",
            Some(FairMode::Collect),
        ),
        "recover fairplay-enrollment.bin with fairplay-enroll recover" => (
            "Use the checked materials folder to create a decryption model in step 3.",
            Some(FairMode::Recover),
        ),
        "recover fairplay-enrollment.bin with fairplay-enroll recover --compat-fairplayd /private/path/fairplayd.arm64e" => {
            (
                "Create a model in step 3. This build also needs a matching system file; select it in Advanced options.",
                Some(FairMode::Recover),
            )
        }
        "run fairplay-decrypt with the compatible model" => (
            "A matching model was found. Review the IPA and output location in step 4.",
            Some(FairMode::Decrypt),
        ),
        "rerun collection with permission to read /private/var/db/fpsd" => (
            "Collection cannot read this Mac's FairPlay data. Resolve access before running step 2; the app cannot grant permission.",
            None,
        ),
        "add and validate an exact evaluator for this fairplayd hash" => (
            "Model creation is not supported for this system build. Retrying with the same materials will not resolve it.",
            None,
        ),
        _ => (
            "Review task details for an additional requirement before continuing.",
            None,
        ),
    }
}
fn failure_view(failure: &Failure, cx: &App) -> Div {
    let color = if matches!(
        failure.kind,
        FailureKind::VerificationRequired | FailureKind::UnlockRequired | FailureKind::Cancelled
    ) {
        cx.theme().muted_foreground
    } else {
        cx.theme().danger
    };
    v_flex()
        .p_4()
        .gap_2()
        .border_1()
        .rounded_lg()
        .border_color(color)
        .child(div().text_color(color).child(failure.title.clone()))
        .child(muted(failure.message.clone(), cx))
}
fn empty(title: &'static str, subtitle: &'static str, cx: &App) -> Div {
    v_flex()
        .flex_1()
        .items_center()
        .justify_center()
        .p_8()
        .gap_3()
        .child(div().text_xl().child(title))
        .child(muted(subtitle, cx))
}

impl DesktopWindow {
    pub(super) fn settings_dialog(
        &self,
        dialog: Dialog,
        window: &Window,
        cx: &mut Context<Self>,
    ) -> Dialog {
        let dialog = dialog.bg(cx.theme().popover);
        let output = self.settings_output.clone();
        let body = v_flex().gap_4()
            .child(label("DEFAULT DOWNLOAD DIRECTORY", cx))
            .child(h_flex().gap_2().child(div().flex_1().child(Input::new(&self.settings_output)))
                .child(Button::new("choose-default-output").label("Choose...").on_click(cx.listener(move |this, _, window, cx| this.choose_path(output.clone(), true, false, window, cx)))))
            .child(muted("Saving also remembers the current browsing platform, country, and search mode. Account credentials and private FairPlay inputs are never stored in these preferences.", cx))
            .when_some(self.settings_error.as_ref(), |view, error| view.child(div().text_color(cx.theme().danger).child(error.clone())));
        let view = cx.entity().downgrade();
        dialog
            .margin_top(px(24.))
            .max_h(window.viewport_size().height - px(96.))
            .title("Desktop settings")
            .w(px(520.))
            .close_button(false)
            .confirm()
            .button_props(
                gpui_component::dialog::DialogButtonProps::default().ok_text("Save preferences"),
            )
            .child(body)
            .on_ok(move |_, window, cx| {
                view.update(cx, |this, cx| this.save_preferences(window, cx))
                    .unwrap_or(true)
            })
    }

    fn app_list(&self, library: bool, cx: &mut Context<Self>) -> AnyElement {
        let apps = if library {
            &self.library_apps
        } else {
            &self.apps
        };
        let selected = if library {
            self.library_selected
        } else {
            self.selected
        };
        let filter = if library {
            self.library_filter.read(cx).value().to_lowercase()
        } else {
            String::new()
        };
        let visible_count = apps
            .iter()
            .filter(|app| matches_library_filter(app, &filter))
            .count();
        v_flex()
            .size_full()
            .min_h_0()
            .child(
                h_flex()
                    .p_4()
                    .justify_between()
                    .child(label(
                        if library {
                            "PURCHASED APPLICATIONS"
                        } else {
                            "APPLICATIONS"
                        },
                        cx,
                    ))
                    .child(muted(
                        if filter.is_empty() {
                            apps.len().to_string()
                        } else {
                            format!("{visible_count} / {}", apps.len())
                        },
                        cx,
                    )),
            )
            .child(
                v_flex()
                    .id(if library {
                        "library-results"
                    } else {
                        "catalog-results"
                    })
                    .track_focus(&self.results_focus)
                    .tab_stop(true)
                    .track_scroll(&self.results_scroll)
                    .on_key_down(cx.listener(move |this, event: &KeyDownEvent, window, cx| {
                        let key = event.keystroke.key.as_str();
                        if !matches!(key, "up" | "down" | "enter" | "home" | "end") {
                            return;
                        }
                        cx.stop_propagation();
                        if key == "enter" {
                            if let Some(app) = this.selected_app() {
                                let (platform, country) = if library {
                                    (
                                        this.library_result_platform,
                                        this.account
                                            .as_ref()
                                            .map(|account| account.country.clone())
                                            .unwrap_or_default(),
                                    )
                                } else {
                                    this.query
                                        .as_ref()
                                        .map(|query| (query.platform, query.country.clone()))
                                        .unwrap_or((this.platform, "US".into()))
                                };
                                this.open_download(app, platform, country, window, cx);
                            }
                            return;
                        }
                        let apps = if library {
                            &this.library_apps
                        } else {
                            &this.apps
                        };
                        let filter = if library {
                            this.library_filter.read(cx).value().to_lowercase()
                        } else {
                            String::new()
                        };
                        let visible: Vec<_> = apps
                            .iter()
                            .enumerate()
                            .filter(|(_, app)| matches_library_filter(app, &filter))
                            .map(|(index, _)| index)
                            .collect();
                        if visible.is_empty() {
                            return;
                        }
                        let selected = if library {
                            &mut this.library_selected
                        } else {
                            &mut this.selected
                        };
                        let position = selected.and_then(|selected| {
                            visible.iter().position(|index| *index == selected)
                        });
                        let next = match key {
                            "home" => 0,
                            "end" => visible.len() - 1,
                            "up" => position.unwrap_or(1).saturating_sub(1),
                            _ => {
                                position.map_or(0, |position| (position + 1).min(visible.len() - 1))
                            }
                        };
                        if *selected != Some(visible[next]) {
                            this.details_scroll.set_offset(Default::default());
                        }
                        *selected = Some(visible[next]);
                        this.results_scroll.scroll_to_item(next);
                        cx.notify();
                    }))
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .when(
                        library && visible_count == 0 && !filter.is_empty(),
                        |view| {
                            view.child(empty(
                                "No matches on this page",
                                "Change the filter or choose another page.",
                                cx,
                            ))
                        },
                    )
                    .children(
                        apps.iter()
                            .enumerate()
                            .filter(|(_, app)| matches_library_filter(app, &filter))
                            .map(|(index, app)| {
                                let initial = app.name.chars().next().unwrap_or('?').to_string();
                                h_flex()
                                    .id(("app", index))
                                    .p_3()
                                    .gap_3()
                                    .cursor_pointer()
                                    .border_b_1()
                                    .border_color(cx.theme().border)
                                    .bg(if selected == Some(index) {
                                        cx.theme().accent
                                    } else {
                                        cx.theme().background
                                    })
                                    .hover(|style| {
                                        style.bg(if selected == Some(index) {
                                            cx.theme().accent
                                        } else {
                                            cx.theme().secondary
                                        })
                                    })
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .size(px(36.))
                                            .rounded_lg()
                                            .bg(cx.theme().secondary)
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .overflow_hidden()
                                            .map(|view| {
                                                if let Some(image) = self.artwork.get(&app.id) {
                                                    view.child(
                                                        img(image.clone())
                                                            .size_full()
                                                            .object_fit(ObjectFit::Contain),
                                                    )
                                                } else {
                                                    view.child(initial)
                                                }
                                            }),
                                    )
                                    .child(
                                        v_flex()
                                            .flex_1()
                                            .min_w_0()
                                            .gap_1()
                                            .child(div().truncate().child(app.name.clone()))
                                            .child(
                                                muted(app.bundle_id.clone(), cx)
                                                    .text_xs()
                                                    .truncate(),
                                            ),
                                    )
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.results_focus.focus(window);
                                        let previous = if library {
                                            this.library_selected
                                        } else {
                                            this.selected
                                        };
                                        if previous != Some(index) {
                                            this.details_scroll.set_offset(Default::default());
                                        }
                                        if library {
                                            this.library_selected = Some(index);
                                        } else {
                                            this.selected = Some(index);
                                        }
                                        cx.notify();
                                    }))
                            }),
                    ),
            )
            .into_any_element()
    }

    fn app_details(&self, library: bool, cx: &mut Context<Self>) -> AnyElement {
        let Some(app) = self.selected_app() else {
            return empty(
                "Find your next application",
                "Select an application to review its details and download options.",
                cx,
            )
            .into_any_element();
        };
        let platform = if library {
            self.library_result_platform
        } else {
            self.query
                .as_ref()
                .map(|query| query.platform)
                .unwrap_or(self.platform)
        };
        let country = if library {
            self.account
                .as_ref()
                .map(|account| account.country.clone())
                .unwrap_or_default()
        } else {
            self.query
                .as_ref()
                .map(|query| query.country.clone())
                .unwrap_or_default()
        };
        let download_app = app.clone();
        let download_country = country.clone();
        let bundle = app.bundle_id.clone();
        let id = app.id.to_string();
        let metadata = serde_json::to_string_pretty(&app).unwrap_or_default();
        let lookup = format!(
            "ipatool-rs lookup --app-id {} --platform {} --country {}",
            app.id,
            platform_name(platform),
            country
        );
        let versions = app
            .platforms
            .as_ref()
            .map(|platforms| {
                platforms
                    .iter()
                    .map(|platform| platform_label(*platform))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "Unavailable".into());
        v_flex().size_full().min_w_0().min_h_0()
            .child(v_flex().p_6().gap_3().border_b_1().border_color(cx.theme().border)
                .child(label("APPLICATION DETAILS", cx))
                .child(div().text_2xl().child(app.name.clone()))
                .child(muted(format!("{} / {}", platform_label(platform), regions::label(&country)), cx))
                .child(h_flex().gap_2()
                    .child(Button::new("download-application").primary().icon(IconName::ArrowDown).label(if self.account.is_some() { "Download..." } else { "Sign in to download..." })
                        .on_click(cx.listener(move |this, _, window, cx| this.open_download(download_app.clone(), platform, download_country.clone(), window, cx))))))
            .child(v_flex().id("application-detail-scroll").track_scroll(&self.details_scroll).flex_1().min_h_0().overflow_y_scroll().child(v_flex().w_full().flex_shrink_0().p_6().gap_5()
                .child(v_flex().gap_1().child(label("Bundle identifier", cx)).child(app.bundle_id.clone()))
                .child(v_flex().gap_1().child(label("App ID", cx)).child(app.id.to_string()))
                .child(v_flex().gap_1().child(label("Catalog version", cx)).child(if app.version.is_empty() { "Unavailable".into() } else { app.version.clone() }))
                .child(v_flex().gap_1().child(label("Supported offers", cx)).child(versions))
                .child(muted("Actual package type and availability are determined by the account's Store offer. A macOS offer may return an IPA or PKG.", cx))
                .child(div().border_t_1().border_color(cx.theme().border).pt_4().child(label("DEVELOPER TOOLS", cx)))
                .child(h_flex().gap_2().flex_wrap()
                    .child(Button::new("copy-id").small().label("Copy ID").on_click(cx.listener(move |this, _, window, cx| this.copy(id.clone(), window, cx))))
                    .child(Button::new("copy-bundle").small().label("Copy bundle ID").on_click(cx.listener(move |this, _, window, cx| this.copy(bundle.clone(), window, cx)))))
                .child(h_flex().gap_2().flex_wrap()
                    .debug_selector(|| "details-final-actions".into())
                    .child(Button::new("copy-json").small().label("Copy JSON").on_click(cx.listener(move |this, _, window, cx| this.copy(metadata.clone(), window, cx))))
                    .child(Button::new("copy-lookup").small().label("Copy lookup command").on_click(cx.listener(move |this, _, window, cx| this.copy(lookup.clone(), window, cx)))))))
            .into_any_element()
    }

    pub(super) fn explore_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let list = self.app_list(false, cx);
        let details = self.app_details(false, cx);
        v_flex().flex_1().min_w_0().min_h_0()
            .child(v_flex().p_4().gap_3().border_b_1().border_color(cx.theme().border)
                .child(h_flex().gap_2().child(div().flex_1().child(Input::new(&self.term).prefix(Icon::new(IconName::Search).size_4().text_color(cx.theme().muted_foreground))))
                    .when(!self.term.read(cx).value().is_empty() || self.query.is_some(), |view| view.child(Button::new("clear-search").small().ghost().icon(IconName::Close).tooltip("Clear search").w(px(28.)).h(px(28.)).on_click(cx.listener(|this, _, window, cx| this.clear_search(window, cx)))))
                    .child(Button::new("search").primary().label(if self.searching { "Search again" } else { "Search" }).on_click(cx.listener(|this, _, _, cx| this.search(cx)))))
                .child(h_flex().gap_2().flex_wrap()
                    .children([Mode::Auto, Mode::Search, Mode::AppId, Mode::BundleId].into_iter().enumerate().map(|(index, mode)| Button::new(("mode", index)).small().label(mode.label()).selected(self.mode == mode).on_click(cx.listener(move |this, _, _, cx| { this.mode = mode; cx.notify(); }))))
                    .child(div().flex_1()).child(label("REGION", cx)).child(div().debug_selector(|| "catalog-region".into()).w(px(200.)).child(self.country.clone())))
                .child(h_flex().gap_1().flex_wrap().child(label("DOWNLOAD FOR", cx)).children(PLATFORMS.into_iter().enumerate().map(|(index, (platform, name))| Button::new(("platform", index)).debug_selector(move || format!("catalog-platform-{}", platform_name(platform))).small().label(name).selected(self.platform == platform).when(self.platform == platform, |button| button.icon(IconName::Check)).on_click(cx.listener(move |this, _, _, cx| this.set_platform(platform, cx))))))
                .when_some(self.account.as_ref().filter(|account| account.country != self.selected_country(cx)), |view, account| {
                    let country = account.country.clone();
                    view.child(v_flex().debug_selector(|| "catalog-region-warning".into()).p_3().gap_2().rounded_md().border_1().border_color(cx.theme().border).bg(cx.theme().secondary)
                        .child(h_flex().gap_2().flex_wrap()
                            .child(Icon::new(IconName::Globe).size_4())
                            .child(div().flex_1().child("Browsing another region"))
                            .child(Button::new("browse-account-region").debug_selector(|| "browse-account-region".into()).small().label(format!("Use account region ({})", country)).on_click(cx.listener(move |this, _, window, cx| this.set_country(&country, window, cx)))))
                        .child(muted(region_mismatch_message(&self.selected_country(cx), &account.country), cx)))
                })
                .when(self.searching, |view| view.child(muted("Searching in the background. You can refine the next query.", cx)))
                .when_some(self.search_error.as_ref(), |view, error| view.child(failure_view(error, cx))))
            .when(self.apps.is_empty(), |view| view.child(empty(if self.searching { "Searching applications..." } else if self.query.is_some() { "No matching applications" } else { "Browse applications" }, "Search by name, ID, bundle identifier, or App Store link. Platform and region changes refresh the results automatically.", cx)))
            .when(!self.apps.is_empty(), |view| view.child(div().flex_1().min_h_0().child(h_resizable("catalog-panels").child(resizable_panel().size(px(310.)).size_range(px(220.)..px(600.)).child(list)).child(resizable_panel().child(details)))))
            .into_any_element()
    }

    pub(super) fn library_view(&self, cx: &mut Context<Self>) -> AnyElement {
        if self.account.is_none() {
            return v_flex().flex_1().child(empty("Your purchased applications", "Load an existing saved account or sign in to browse purchases and available versions.", cx))
                .child(h_flex().p_6().justify_center().child(Button::new("library-sign-in").primary().label("Open account").on_click(cx.listener(|this, _, window, cx| this.open_account(window, cx))))).into_any_element();
        }
        let list = self.app_list(true, cx);
        let details = self.app_details(true, cx);
        v_flex()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .child(
                h_flex()
                    .p_3()
                    .gap_2()
                    .flex_wrap()
                    .children(
                        PLATFORMS
                            .into_iter()
                            .enumerate()
                            .map(|(index, (platform, name))| {
                                Button::new(("library-platform", index))
                                    .small()
                                    .label(name)
                                    .selected(self.library_platform == platform)
                                    .disabled(self.account_busy())
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.library_platform = platform;
                                        this.library_page = 1;
                                        this.load_library(cx);
                                    }))
                            }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(180.))
                            .child(Input::new(&self.library_filter)),
                    ),
            )
            .child(
                h_flex()
                    .p_4()
                    .gap_3()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(
                        Button::new("previous-page")
                            .small()
                            .label("Previous")
                            .disabled(
                                self.library_loading
                                    || self.library_page <= 1
                                    || self.account_busy(),
                            )
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.library_page = this.library_page.saturating_sub(1).max(1);
                                this.load_library(cx);
                            })),
                    )
                    .child(muted(
                        format!(
                            "Page {} of {} · {} apps",
                            self.library_page,
                            self.library_total.div_ceil(25).max(1),
                            self.library_total
                        ),
                        cx,
                    ))
                    .child(
                        Button::new("next-page")
                            .small()
                            .label("Next")
                            .disabled(
                                self.library_loading
                                    || self.account_busy()
                                    || self.library_page * 25 >= self.library_total,
                            )
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.library_page += 1;
                                this.load_library(cx);
                            })),
                    )
                    .child(div().flex_1())
                    .when(self.library_loading, |view| {
                        view.child(
                            Button::new("cancel-library")
                                .label("Stop loading")
                                .on_click(cx.listener(|this, _, _, _| {
                                    if let Some(operation) = &this.library_operation {
                                        operation.cancel();
                                    }
                                })),
                        )
                    })
                    .child(
                        Button::new("refresh-library")
                            .label(if self.library_loading {
                                "Loading..."
                            } else {
                                "Refresh"
                            })
                            .disabled(self.account_busy())
                            .on_click(cx.listener(|this, _, _, cx| this.load_library(cx))),
                    ),
            )
            .when_some(self.library_error.as_ref(), |view, error| {
                view.child(failure_view(error, cx))
            })
            .when(self.library_apps.is_empty(), |view| {
                view.child(empty(
                    "No purchases loaded",
                    "Refresh your library or try another offer platform in Explore.",
                    cx,
                ))
            })
            .when(!self.library_apps.is_empty(), |view| {
                view.child(
                    div().flex_1().min_h_0().child(
                        h_resizable("library-panels")
                            .child(
                                resizable_panel()
                                    .size(px(310.))
                                    .size_range(px(220.)..px(600.))
                                    .child(list),
                            )
                            .child(resizable_panel().child(details)),
                    ),
                )
            })
            .into_any_element()
    }

    pub(super) fn account_dialog(
        &mut self,
        dialog: Dialog,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Dialog {
        let dialog = dialog.bg(cx.theme().popover);
        let busy = self.account_form.busy;
        let verifying = self.account_form.verifying;
        let unlocking = self.account_form.unlocking_saved;
        let reserved = self.account_busy();
        let mut body = v_flex().gap_3();
        if let Some(error) = &self.account_form.error {
            body = body.child(failure_view(error, cx));
        }
        if let Some(account) = &self.account
            && !self.account_form.reauthenticating
        {
            body = body.child(div().text_lg().child(account.name.clone())).child(account.email.clone())
                .child(muted(format!("Account storefront: {}. Saved credentials are checked by each Store operation.", account.country), cx))
                .child(Button::new("reauthenticate-account").label("Sign in again...").disabled(self.account_busy()).on_click(cx.listener(|this, _, window, cx| {
                    this.begin_reauthentication(window, cx);
                })))
                .child(Button::new("remove-local-account").label("Remove saved credentials...").disabled(self.account_busy()).on_click(cx.listener(|this, _, window, cx| this.revoke_account(window, cx))));
        } else if unlocking {
            body = body
                .child(label("ENCRYPTED FILE-STORE PASSPHRASE", cx))
                .child(Input::new(&self.account_form.passphrase).disabled(busy))
                .child(muted("Unlock the account saved on this computer. This passphrase is separate from your Apple ID password.", cx))
                .child(Button::new("unlock-sign-in-instead").ghost().label("Sign in instead...").disabled(busy).on_click(cx.listener(|this, _, window, cx| {
                    this.clear_secrets(window, cx);
                    this.account_form.error = None;
                    this.account_form.email.update(cx, |input, cx| input.focus(window, cx));
                    cx.notify();
                })));
        } else if self.account_form.verifying {
            body = body
                .child(muted(
                    format!("Account: {}", self.account_form.email.read(cx).value()),
                    cx,
                ))
                .child(label("SIX-DIGIT CODE FROM A TRUSTED DEVICE", cx))
                .child(Input::new(&self.account_form.code).disabled(busy))
                .when(busy, |view| {
                    view.child(muted("Checking verification code...", cx))
                });
        } else {
            body = body.child(muted("Browsing is public. Account credentials are required for purchases and downloads. System storage may ask for authorization.", cx))
                .child(Input::new(&self.account_form.email).disabled(busy || self.account_form.verifying))
                .when(!self.account_form.verifying, |view| view.child(Input::new(&self.account_form.password).disabled(busy)))
                .when(self.account_form.verifying, |view| view.child(label("VERIFICATION CODE FROM A TRUSTED DEVICE", cx)).child(Input::new(&self.account_form.code).disabled(busy)))
                .child(Button::new("file-storage").small().label(if self.account_form.force_file { "Encrypted file storage enabled" } else { "Use encrypted file storage" }).selected(self.account_form.force_file).disabled(busy || self.account_form.verifying).on_click(cx.listener(|this, _, _, cx| { this.account_form.force_file = !this.account_form.force_file; cx.notify(); })))
                .when(self.account_form.force_file && !self.account_form.verifying, |view| view.child(Input::new(&self.account_form.passphrase).disabled(busy)).child(muted("The file-store passphrase is separate from your Apple ID password. Existing storage is kept in its current format.", cx)))
                .when(busy, |view| view.child(muted("Preparing authentication and communicating with Apple. First-time resource setup may take a few minutes.", cx)))
                .child(Button::new("load-account").label("Load saved account / unlock").disabled(self.account_busy()).on_click(cx.listener(|this, _, window, cx| this.submit_account(true, window, cx))));
        }
        if reserved && !busy {
            body = body.child(muted("Another operation is running. Account changes will be available when it finishes or stops safely.", cx));
        }
        let view = cx.entity().downgrade();
        let submit_view = view.clone();
        let close_view = view.clone();
        let has_account = self.account.is_some() && !self.account_form.reauthenticating;
        dialog
            .margin_top(px(24.))
            .max_h(window.viewport_size().height - px(96.))
            .title(if has_account {
                "Account"
            } else if unlocking {
                "Unlock saved account"
            } else if self.account_form.verifying {
                "Verify your Apple ID"
            } else {
                "Sign in to the App Store"
            })
            .w(px(480.))
            .close_button(false)
            .overlay_closable(false)
            .keyboard(!busy)
            .child(body)
            .on_ok(move |_, window, cx| {
                if !has_account {
                    let _ =
                        submit_view.update(cx, |this, cx| this.submit_account(false, window, cx));
                }
                false
            })
            .on_close(move |_, window, cx| {
                let _ = close_view.update(cx, |this, cx| {
                    if !this.account_form.busy {
                        this.clear_secrets(window, cx);
                        this.account_form.reauthenticating = false;
                        this.pending_download = None;
                        this.pending_retry = None;
                        this.start_next(cx);
                    }
                });
            })
            .footer(move |_, _, _, _| {
                let close = view.clone();
                let submit = view.clone();
                let mut buttons = vec![
                    Button::new("close-account")
                        .debug_selector(|| "account-footer-cancel".into())
                        .label(if has_account { "Done" } else { "Cancel" })
                        .disabled(busy)
                        .on_click(move |_, window, cx| {
                            let _ = close.update(cx, |this, cx| {
                                this.clear_secrets(window, cx);
                                this.account_form.reauthenticating = false;
                                this.pending_download = None;
                                this.pending_retry = None;
                                this.start_next(cx);
                            });
                            window.close_dialog(cx);
                        })
                        .into_any_element(),
                ];
                if !has_account {
                    buttons.push(
                        Button::new("sign-in-account")
                            .debug_selector(|| "account-footer-submit".into())
                            .primary()
                            .label(if busy && unlocking {
                                "Unlocking..."
                            } else if unlocking {
                                "Unlock and continue"
                            } else if busy && verifying {
                                "Verifying..."
                            } else if busy {
                                "Signing in..."
                            } else {
                                "Continue"
                            })
                            .disabled(reserved)
                            .on_click(move |_, window, cx| {
                                let _ = submit
                                    .update(cx, |this, cx| this.submit_account(false, window, cx));
                            })
                            .into_any_element(),
                    );
                }
                buttons
            })
    }

    pub(super) fn download_dialog(
        &self,
        dialog: Dialog,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Dialog {
        let dialog = dialog.bg(cx.theme().popover);
        let Some(form) = &self.download_form else {
            return dialog.title("Download");
        };
        let output = form.output.clone();
        let account_country = self
            .account
            .as_ref()
            .map(|account| account.country.clone())
            .unwrap_or_default();
        let body = v_flex().gap_3()
            .child(div().text_lg().child(form.app.name.clone()))
            .child(label("DOWNLOAD FOR", cx))
            .child(h_flex().gap_1().flex_wrap().children(PLATFORMS.into_iter().enumerate().map(|(index, (platform, name))| Button::new(("download-platform", index)).small().label(name).selected(form.platform == platform).disabled(self.account_busy() || form.loading_versions).on_click(cx.listener(move |this, _, window, cx| this.set_download_platform(platform, window, cx))))))
            .child(muted(format!("Account region: {}", regions::label(&account_country)), cx))
            .when(form.source_country != account_country, |view| view.child(v_flex().p_3().gap_2().rounded_md().border_1().border_color(cx.theme().border).bg(cx.theme().secondary)
                .child("Application from another region")
                .child(muted(region_mismatch_message(&form.source_country, &account_country), cx))))
            .child(label("SAVE TO", cx)).child(h_flex().gap_2().child(div().flex_1().child(Input::new(&form.output))).child(Button::new("choose-output").label("Choose...").on_click(cx.listener(move |this, _, window, cx| this.choose_path(output.clone(), true, false, window, cx)))))
            .child(label("VERSION", cx)).child(Input::new(&form.version))
            .child(Button::new("check-version").small().label("Check version details").disabled(self.account_busy() || form.version.read(cx).value().trim().is_empty()).on_click(cx.listener(|this, _, window, cx| this.load_version_metadata(window, cx))))
            .when_some(form.metadata.as_ref(), |view, (id, metadata)| view.child(muted(format!("Version ID {}: {} / {}", id, metadata.display_version, metadata.release_date), cx)))
            .child(Button::new("load-versions").small().label(if form.loading_versions { "Loading versions..." } else { "Load available versions" }).disabled(self.account_busy()).on_click(cx.listener(|this, _, window, cx| this.load_versions(window, cx))))
            .when(!form.versions.is_empty(), |view| view.child(muted(format!("{} available version IDs", form.versions.len()), cx)).child(h_flex().flex_wrap().gap_1().children(form.versions.iter().enumerate().map(|(index, version)| {
                let version = version.clone(); let input = form.version.clone();
                Button::new(("version", index)).small().selected(form.version.read(cx).value().trim() == version).label(version.clone()).on_click(move |_, window, cx| input.update(cx, |input, cx| input.set_value(version.clone(), window, cx)))
            }))))
            .child(Button::new("allow-free-license").label("Acquire a free license if needed").selected(form.acquire_license).on_click(cx.listener(|this, _, _, cx| { if let Some(form) = &mut this.download_form { form.acquire_license = !form.acquire_license; } cx.notify(); })))
            .child(muted("This does not buy paid applications. Store entitlements and the actual offer determine whether an IPA or PKG can be downloaded.", cx))
            .when_some(form.error.as_ref(), |view, error| view.child(div().text_color(cx.theme().danger).child(error.clone())));
        let view = cx.entity().downgrade();
        let submit = view.clone();
        let close = view.clone();
        let loading = form.loading_versions;
        dialog
            .margin_top(px(24.))
            .max_h(window.viewport_size().height - px(96.))
            .title("Download application")
            .w(px(560.))
            .close_button(false)
            .overlay_closable(false)
            .keyboard(!loading)
            .child(body)
            .on_ok(move |_, window, cx| {
                let _ = submit.update(cx, |this, cx| this.submit_download(window, cx));
                false
            })
            .on_close(move |_, _, cx| {
                let _ = close.update(cx, |this, _| {
                    this.download_form = None;
                    this.download_generation = this.download_generation.wrapping_add(1);
                    if let Some(operation) = &this.version_operation {
                        operation.cancel();
                    }
                });
            })
            .footer(move |_, _, _, _| {
                let submit = view.clone();
                vec![
                    Button::new("cancel-download")
                        .label("Cancel")
                        .disabled(loading)
                        .on_click(|_, window, cx| window.close_dialog(cx))
                        .into_any_element(),
                    Button::new("queue-download")
                        .debug_selector(|| "download-footer-submit".into())
                        .primary()
                        .label("Add to downloads")
                        .disabled(loading)
                        .on_click(move |_, window, cx| {
                            let _ = submit.update(cx, |this, cx| this.submit_download(window, cx));
                        })
                        .into_any_element(),
                ]
            })
    }

    pub(super) fn tasks_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut content = v_flex().flex_1().min_h_0().min_w_0();
        if let Some(error) = &self.journal_error {
            content = content.child(v_flex().p_4().gap_2().child(div().text_color(cx.theme().danger).child(error.clone()))
                .child(Button::new("recover-history").label("Preserve unreadable history and start a new journal...").disabled(self.active.is_some()).on_click(cx.listener(|_this, _, window, cx| {
                    let weak = cx.entity().downgrade();
                    window.open_dialog(cx, move |dialog, _, cx| { let weak = weak.clone(); dialog.bg(cx.theme().popover).title("Recover task history?").child("The previous journal will be moved to a uniquely named backup. No downloaded files or private materials will be deleted.").confirm().on_ok(move |_, _, cx| { let _ = weak.update(cx, |this, cx| {
                        let path = this.session.directory().join("desktop-tasks.json");
                        match Journal::preserve_existing(&path) {
                            Ok(_) => { this.journal_error = None; this.persist_history(); }
                            Err(_) => this.show_notice("History could not be preserved. Check access to the state directory and try again.", cx),
                        }
                        cx.notify();
                    }); true }) });
                }))));
        }
        if self.journal.tasks.is_empty() {
            return content.child(empty("Your background work lives here", "Downloads and FairPlay operations keep their progress and results while you browse.", cx)).into_any_element();
        }
        content
            .child(
                h_flex()
                    .p_4()
                    .justify_between()
                    .child(muted("Running, queued, and recent operations", cx))
                    .child(
                        Button::new("clear-completed")
                            .small()
                            .label("Clear finished history")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.journal.tasks.retain(|task| task.state.is_active());
                                this.persist_history();
                                cx.notify();
                            })),
                    ),
            )
            .child(
                v_flex()
                    .id("task-history")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(v_flex().w_full().flex_shrink_0().p_4().gap_3().children(
                        self.journal.tasks.iter().rev().map(|task| {
                            let id = task.id;
                            let request = task.request.clone();
                            let running_progress = self
                                .active
                                .as_ref()
                                .filter(|(active_id, _, _)| *active_id == id)
                                .and_then(|(_, _, latest)| latest.lock().ok().map(|value| *value));
                            let mut card = v_flex()
                                .id(("task", id as usize))
                                .p_4()
                                .gap_3()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().border)
                                .child(
                                    h_flex()
                                        .justify_between()
                                        .gap_3()
                                        .child(
                                            div().child(task_display_title(&task.title, &request)),
                                        )
                                        .child(muted(
                                            if task.state == TaskState::Succeeded
                                                && matches!(
                                                    request,
                                                    JobRequest::FairPlay(
                                                        FairPlayRequest::Inspect { .. }
                                                    )
                                                )
                                            {
                                                "Check complete"
                                            } else {
                                                task.state.label()
                                            },
                                            cx,
                                        )),
                                );
                            if let Some(progress) = running_progress {
                                let text = match progress.total {
                                    Some(total) if total > 0 => {
                                        format!(
                                            "{} / {} {}",
                                            progress.completed,
                                            total,
                                            if progress.stage == Stage::Downloading {
                                                "bytes"
                                            } else {
                                                "items"
                                            }
                                        )
                                    }
                                    _ => String::new(),
                                };
                                card = card.child(muted(
                                    if text.is_empty() {
                                        progress.stage.label().to_owned()
                                    } else {
                                        format!("{} / {}", progress.stage.label(), text)
                                    },
                                    cx,
                                ));
                                if let Some(total) = progress.total.filter(|total| *total > 0) {
                                    card = card.child(
                                        div()
                                            .h(px(4.))
                                            .w_full()
                                            .rounded_full()
                                            .bg(cx.theme().secondary)
                                            .child(
                                                div()
                                                    .h_full()
                                                    .rounded_full()
                                                    .w(relative(
                                                        (progress.completed as f32 / total as f32)
                                                            .clamp(0., 1.),
                                                    ))
                                                    .bg(cx.theme().primary),
                                            ),
                                    );
                                }
                            } else if let Some(stage) = task.last_stage {
                                card =
                                    card.child(muted(format!("Last stage: {}", stage.label()), cx));
                            }
                            if let Some(outcome) = &task.outcome {
                                let inspection = matches!(request, JobRequest::FairPlay(FairPlayRequest::Inspect { .. }));
                                if inspection && let Some(details) = &outcome.details {
                                    card = card.child(div().child(fairplay_ui::inspection_summary(details)));
                                    if let Some(checks) = details.get("checks").and_then(|value| value.as_object()) {
                                        for (name, passed) in checks {
                                            let passed = passed.as_bool() == Some(true);
                                            card = card.child(muted(format!("{} {}", if passed { "✓" } else { "!" }, fairplay_ui::check_description(name, passed)), cx));
                                        }
                                    }
                                    if let Some(errors) = details.get("errors").and_then(|value| value.as_array()) {
                                        for error in errors.iter().filter_map(|value| value.as_str()) {
                                            card = card.child(muted(fairplay_ui::inspection_error(error), cx));
                                        }
                                    }
                                    if let Some(warnings) = details.get("warnings").and_then(|value| value.as_array()) {
                                        for warning in warnings.iter().filter_map(|value| value.as_str()) {
                                            card = card.child(muted(fairplay_ui::inspection_warning(warning), cx));
                                        }
                                    }
                                    if let Some(items) = details.get("next_actions").and_then(|value| value.as_array()) {
                                        let has_model = details.get("compatible_model").and_then(|value| value.as_str()).is_some();
                                        for item in items.iter().filter_map(|value| value.as_str()) {
                                            let (text, mode) = inspection_next_action(item);
                                            if has_model && mode != Some(FairMode::Decrypt) { continue; }
                                            if mode == Some(FairMode::Decrypt) && details.get("ready").and_then(|value| value.as_bool()) != Some(true) { continue; }
                                            card = card.child(muted(text.to_owned(), cx));
                                            if let Some(mode) = mode
                                                && let JobRequest::FairPlay(inspect @ FairPlayRequest::Inspect { .. }) = &request {
                                                let inspect = inspect.clone();
                                                card = card.child(h_flex().child(Button::new(("inspect-next", mode as usize))
                                                    .label(match mode {
                                                        FairMode::Collect => "Go to step 2: Collect files",
                                                        FairMode::Recover => "Go to step 3: Create model",
                                                        _ => "Go to step 4: Decrypt IPA",
                                                    })
                                                    .on_click(cx.listener(move |this, _, window, cx| {
                                                        this.inspection_followup(inspect.clone(), mode, window, cx)
                                                    }))));
                                            }
                                        }
                                    }
                                } else if inspection {
                                    card = card.child(muted("This check finished in a previous session. Detailed results are not kept in history. Review the inputs and run the check again before choosing a next step.", cx));
                                } else {
                                    card = card.child(muted(outcome.summary.clone(), cx));
                                }
                                card = card.children(
                                        outcome.artifacts.iter().enumerate().map(
                                            |(index, artifact)| {
                                                let path = artifact.path.clone();
                                                let reveal = path.clone();
                                                let use_path = path.clone();
                                                let decrypt_path = path.clone();
                                                let kind = artifact.kind;
                                                h_flex()
                                                    .gap_2()
                                                    .flex_wrap()
                                                    .child(
                                                        div().flex_1().min_w_0().truncate().child(
                                                            path.to_string_lossy().into_owned(),
                                                        ),
                                                    )
                                                    .child(
                                                        Button::new(("reveal", index))
                                                            .small()
                                                            .label(if cfg!(target_os = "macos") {
                                                                "Show in Finder"
                                                            } else {
                                                                "Show in folder"
                                                            })
                                                            .on_click(move |_, _, cx| {
                                                                cx.reveal_path(&reveal)
                                                            }),
                                                    )
                                                    .when(
                                                        matches!(
                                                            artifact.kind,
                                                            ArtifactKind::Capture
                                                                | ArtifactKind::Model
                                                        ) || matches!(
                                                            artifact.kind,
                                                            ArtifactKind::Package
                                                                | ArtifactKind::DecryptedIpa
                                                        ) && path.extension().is_some_and(
                                                            |extension| {
                                                                extension
                                                                    .eq_ignore_ascii_case("ipa")
                                                            },
                                                        ),
                                                        |row| {
                                                            row.child(
                                                        Button::new(("use-ipa", index))
                                                            .small()
                                                            .label(match artifact.kind {
                                                                ArtifactKind::Capture => {
                                                                    "Create decryption model"
                                                                }
                                                                ArtifactKind::Model => "Use for decryption",
                                                                _ => "Check IPA compatibility",
                                                            })
                                                            .on_click(cx.listener(
                                                                move |this, _, window, cx| {
                                                                    this.use_fairplay_artifact(
                                                                        kind,
                                                                        use_path.clone(),
                                                                        window,
                                                                        cx,
                                                                    );
                                                                },
                                                            )),
                                                    )
                                                        },
                                                    )
                                                    .when(artifact.kind == ArtifactKind::Package && path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("ipa")), |row| {
                                                        row.child(Button::new(("decrypt-ipa", index))
                                                            .small()
                                                            .label("Decrypt IPA...")
                                                            .debug_selector(move || format!("decrypt-ipa-{id}-{index}"))
                                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                                this.prepare_ipa_decryption(decrypt_path.clone(), window, cx);
                                                            })))
                                                    })
                                            },
                                        ),
                                    );
                            }
                            if let Some(failure) = &task.failure {
                                card = card.child(failure_view(failure, cx));
                            }
                            let mut buttons = h_flex().gap_2().flex_wrap().child(
                                Button::new("task-parameters")
                                    .small()
                                    .label(if self.selected_task == Some(id) {
                                        "Hide task details"
                                    } else {
                                        "Show task details"
                                    })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected_task = if this.selected_task == Some(id) {
                                            None
                                        } else {
                                            Some(id)
                                        };
                                        cx.notify();
                                    })),
                            );
                            if self.selected_task == Some(id) {
                                card = card.child(muted(request_description(&request), cx));
                                if let Some(details) = task.outcome.as_ref().and_then(|outcome| outcome.details.as_ref()) {
                                    card = card.child(muted("Technical diagnostics (may include private paths and identifiers)", cx).text_sm())
                                        .child(muted(serde_json::to_string_pretty(details).unwrap_or_default(), cx).text_sm());
                                }
                            }
                            if task.state.is_active() {
                                if task.state == TaskState::AwaitingInput {
                                    buttons = buttons.child(
                                        Button::new("task-sign-in")
                                            .primary()
                                            .label("Sign in to continue")
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.continue_account(window, cx)
                                            })),
                                    );
                                }
                                buttons = buttons.child(
                                    Button::new("cancel-task")
                                        .label(if task.state == TaskState::CancellationRequested {
                                            "Stopping safely..."
                                        } else {
                                            "Cancel task"
                                        })
                                        .disabled(task.state == TaskState::CancellationRequested)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.cancel_task(id, cx)
                                        })),
                                );
                            } else if task.state != TaskState::Succeeded {
                                buttons = buttons.child(
                                    Button::new("retry-task")
                                        .label("Review and retry")
                                        .on_click(cx.listener(move |this, _, window, cx| {
                                            this.retry_task(id, false, window, cx)
                                        })),
                                );
                                if task.failure.as_ref().is_some_and(|failure| {
                                    failure.kind == FailureKind::LicenseRequired
                                }) && matches!(request, JobRequest::Download(_))
                                {
                                    buttons = buttons.child(
                                        Button::new("license-retry")
                                            .primary()
                                            .label("Acquire free license and retry")
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.retry_task(id, true, window, cx)
                                            })),
                                    );
                                }
                            }
                            card.child(buttons)
                        }),
                    )),
            )
            .into_any_element()
    }

    fn path_control(
        &self,
        title: &'static str,
        input: &Entity<InputState>,
        directory: bool,
        save: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let target = input.clone();
        let dropped_target = target.clone();
        let either = input == &self.fair.model;
        v_flex()
            .gap_1()
            .when(!save, |view| {
                view.on_drop(cx.listener(move |this, paths: &ExternalPaths, window, cx| {
                    if paths.paths().len() != 1 {
                        this.show_notice("Drop one matching file or directory at a time.", cx);
                        return;
                    }
                    let path = &paths.paths()[0];
                    if !either && (directory && !path.is_dir() || !directory && !path.is_file()) {
                        this.show_notice(
                            if directory {
                                "Choose a directory for this input."
                            } else {
                                "Choose a regular file for this input."
                            },
                            cx,
                        );
                        return;
                    }
                    dropped_target.update(cx, |input, cx| {
                        input.set_value(path.to_string_lossy().into_owned(), window, cx)
                    });
                    cx.notify();
                }))
            })
            .child(label(title, cx))
            .child(
                h_flex()
                    .gap_2()
                    .child(div().flex_1().child(Input::new(input)))
                    .child(Button::new(title).label("Choose...").on_click(cx.listener(
                        move |this, _, window, cx| {
                            this.choose_path(target.clone(), directory, save, window, cx)
                        },
                    ))),
            )
    }

    fn guided_path(
        &self,
        title: &'static str,
        help: &'static str,
        input: &Entity<InputState>,
        directory: bool,
        save: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        self.path_control(title, input, directory, save, cx)
            .child(muted(help, cx).text_sm())
    }

    pub(super) fn fairplay_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let mode = self.fair.mode;
        let guide = fairplay_ui::guide(mode);
        let controls = h_flex().gap_2().flex_wrap().children(
            [
                FairMode::Inspect,
                FairMode::Collect,
                FairMode::Recover,
                FairMode::Decrypt,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, mode)| {
                Button::new(("fair-mode", index))
                    .small()
                    .label(fairplay_ui::guide(mode).tab)
                    .selected(self.fair.mode == mode)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.set_fair_mode(mode, window, cx);
                    }))
            }),
        );
        let mut form = v_flex()
            .flex_shrink_0()
            .gap_4()
            .child(
                v_flex()
                    .gap_2()
                    .child(div().text_2xl().child(guide.title))
                    .child(muted(guide.introduction, cx)),
            )
            .child(
                v_flex()
                    .p_4()
                    .gap_2()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(div().child("Before you start"))
                    .child(muted(guide.prepare, cx))
                    .child(muted(guide.result, cx)),
            )
            .child(div().child("Choose your files"));
        match mode {
            FairMode::Inspect => {
                form = form
                    .child(self.guided_path("Downloaded IPA", "Start with the .ipa from Downloads. If you only have a materials folder, you can leave this blank.", &self.fair.input, false, false, cx))
                    .child(self.guided_path("Decryption model (if you already have one)", "A FairPlay parameter file, not an AI model. Select the file or its folder to check whether it matches your IPA. Otherwise leave blank.", &self.fair.model, false, false, cx))
                    .child(self.guided_path("Collected materials folder (if you have one)", "The folder created in step 2. Leave blank if you have not collected materials yet.", &self.fair.capture, true, false, cx));
            }
            FairMode::Collect => {
                form = form
                    .child(self.guided_path("Installed app (.app) — required", "Select the installed application on this Mac, not the downloaded IPA. Its version must match the materials you plan to use.", &self.fair.app, true, false, cx))
                    .child(self.guided_path("Matching IPA (optional)", "Include the downloaded IPA for the same app and version so later steps can check it against the collected materials.", &self.fair.input, false, false, cx))
                    .child(self.guided_path("Save materials to a new folder — required", "Choose a new folder name in the save dialog. It must not already exist; collection creates it for you.", &self.fair.directory_output, false, true, cx));
            }
            FairMode::Recover => {
                form = form
                    .child(self.guided_path("Collected materials folder — required", "Choose the complete folder produced in step 2. Keep its files together.", &self.fair.capture, true, false, cx))
                    .child(self.guided_path("Save decryption model to a new folder — required", "Choose a new folder name. Existing folders are preserved. A successful task provides a model you can use in step 4.", &self.fair.directory_output, false, true, cx));
            }
            FairMode::Decrypt => {
                form = form
                    .child(self.guided_path("Downloaded IPA — required", "Choose the original IPA downloaded with your account.", &self.fair.input, false, false, cx))
                    .child(self.guided_path("Matching decryption model — required", "Choose the model file or folder from step 3, or an existing compatible model. An IPA alone is not enough.", &self.fair.model, false, false, cx))
                    .child(self.guided_path("Save decrypted IPA (optional)", "Leave blank to create a separate .decrypted.ipa beside the original. Existing files are never replaced.", &self.fair.output, false, true, cx));
            }
        }
        form = form.child(
            h_flex().child(
                Button::new("fair-advanced")
                    .small()
                    .label(if self.fair.advanced {
                        "Hide advanced options"
                    } else {
                        "Advanced options"
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.fair.advanced = !this.fair.advanced;
                        cx.notify();
                    })),
            ),
        );
        if self.fair.advanced && matches!(mode, FairMode::Inspect | FairMode::Decrypt) {
            form = form.child(self.guided_path(
                "Save detailed report (optional)",
                if mode == FairMode::Inspect {
                    "Leave blank to view results only in Downloads. Choose a new JSON file to keep a local report. It may contain private paths and identifiers."
                } else {
                    "Leave blank to save a .decrypted.json report beside the input IPA. Choose a new file if a previous report exists."
                },
                &self.fair.report, false, true, cx,
            ));
        }
        if self.fair.advanced && matches!(mode, FairMode::Collect | FairMode::Recover) {
            form = form.child(muted(if mode == FairMode::Collect {
                "Normally use this Mac's detected settings. Only override paths or system versions when you have matching materials; changing a version label does not make an unsupported build compatible. Collection needs permission to read this Mac's FairPlay data. The app cannot grant that permission."
            } else {
                "Some system builds need additional matching files. If the compatibility check requests them, select those files here; do not substitute files from a different build. Leave other fields at their defaults."
            }, cx));
            form = form.child(self.path_control(
                if mode == FairMode::Collect {
                    "Matching fairplayd image (optional)"
                } else {
                    "26A428 compatibility fairplayd (optional)"
                },
                &self.fair.fairplayd,
                false,
                false,
                cx,
            ));
            if mode == FairMode::Recover {
                form = form
                    .child(self.path_control(
                        "Checked startup profile (optional)",
                        &self.fair.startup,
                        false,
                        false,
                        cx,
                    ))
                    .child(self.path_control(
                        "Verified IOKit selector output (optional)",
                        &self.fair.iokit,
                        false,
                        false,
                        cx,
                    ))
                    .child(
                        v_flex()
                            .gap_1()
                            .child(label("Per-phase timeout in seconds (1–3600)", cx))
                            .child(Input::new(&self.fair.timeout)),
                    );
            } else {
                form = form
                    .child(self.path_control(
                        "System SC Info (optional)",
                        &self.fair.system_state,
                        true,
                        false,
                        cx,
                    ))
                    .child(self.path_control(
                        "Shared SC Info (optional)",
                        &self.fair.shared_state,
                        true,
                        false,
                        cx,
                    ))
                    .child(self.path_control(
                        "ADI state (optional)",
                        &self.fair.adi_state,
                        true,
                        false,
                        cx,
                    ))
                    .child(self.path_control(
                        "Hardware MAC file (optional)",
                        &self.fair.iomac,
                        false,
                        false,
                        cx,
                    ))
                    .child(label("System version override (optional)", cx))
                    .child(Input::new(&self.fair.product_version))
                    .child(label("NETWORK INTERFACE", cx))
                    .child(Input::new(&self.fair.interface))
                    .child(
                        v_flex()
                            .debug_selector(|| "fairplay-last-input".into())
                            .child(label("System build override (optional)", cx))
                            .child(Input::new(&self.fair.build_version)),
                    );
            }
        }
        form = form.child(muted("Experimental: support depends on the exact system build and matching materials. A passed check or completed task does not prove that the output is correct.", cx).text_sm());
        v_flex()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .child(
                v_flex().p_4().gap_2().border_b_1()
                    .border_color(cx.theme().border)
                    .child(controls)
                    .child(muted("Start at step 1. Already have collected materials or a model? Skip to step 3 or 4.", cx).text_sm()),
            )
            .child(
                v_flex()
                    .id("fairplay-inputs")
                    .track_scroll(&self.fair_scroll)
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(v_flex().w_full().max_w(px(868.)).flex_shrink_0().p_6().child(form)),
            )
            .child(
                h_flex().p_4().gap_3().flex_wrap().flex_shrink_0()
                    .border_t_1().border_color(cx.theme().border)
                    .child(v_flex().flex_1().min_w(px(180.)).gap_1()
                        .child(div().text_sm().child(guide.action_hint))
                        .child(muted("Progress and results appear in Downloads.", cx).text_xs()))
                    .child(Button::new("fairplay-results").label("View results")
                        .debug_selector(|| "fairplay-results".into())
                        .on_click(cx.listener(|this, _, _, cx| { this.page = Page::Downloads; cx.notify(); })))
                    .child(Button::new("run-fairplay").primary().label(guide.action)
                        .debug_selector(|| "fairplay-submit".into())
                        .on_click(cx.listener(|this, _, window, cx| this.submit_fairplay(window, cx)))),
            )
            .into_any_element()
    }
}
