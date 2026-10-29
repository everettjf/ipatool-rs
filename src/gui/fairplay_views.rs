use super::views::{label, muted};
use super::*;

impl DesktopWindow {
    pub(super) fn fairplay_guided_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let setup = self.fair.mode == FairMode::Setup;
        let step = self.fair.setup_step;
        let status = match &self.fair.saved_models {
            Some(Ok(0)) => "Not prepared yet. Set up once to reuse your authorization.".to_owned(),
            Some(Ok(count)) => format!(
                "{count} private model(s) saved. Each IPA is matched by its authorization, not its app name."
            ),
            Some(Err(error)) => error.clone(),
            None => "Saved models are checked in the background when you open FairPlay.".into(),
        };
        let mut form = v_flex().gap_4().flex_shrink_0()
            .child(div().text_2xl().child(if setup { "Prepare reusable decryption" } else { "Download, then decrypt automatically" }))
            .child(muted(if setup { "Complete this preparation once for an App Store enrollment. Matching IPAs can then reuse the saved model." } else { "A saved model is selected from the IPA's authorization. You do not need to choose a model for each app." }, cx));
        if setup {
            form = form.child(
                h_flex().gap_2().flex_wrap().children(
                    [
                        "1. Prepare this Mac",
                        "2. Choose sample files",
                        "3. Review and prepare",
                    ]
                    .into_iter()
                    .enumerate()
                    .map(|(index, text)| {
                        div()
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .bg(if step as usize == index {
                                cx.theme().secondary
                            } else {
                                cx.theme().background
                            })
                            .child(text)
                    }),
                ),
            );
            match step {
                0 => {
                    form = form.child(v_flex().p_4().gap_3().rounded_lg().border_1().border_color(cx.theme().border)
                        .child(div().child("Before you continue"))
                        .child(muted("1. Sign in to the Mac App Store with the Apple account that owns your IPA. Signing in only inside IPATOOL-RS does not prepare this Mac's authorization.", cx))
                        .child(muted("2. Install an iPhone or iPad app through the Mac App Store and open it once. Choose an app offered for this Mac.", cx))
                        .child(muted("3. Download the same app/version's encrypted IPA with the same account. An IPA by itself is not enough for initial setup.", cx))
                        .child(muted("Current recovery support assumes a fresh Apple account enrolled through this Mac's App Store. Older or migrated account profiles are not supported; a fresh account alone does not guarantee success.", cx))
                        .child(muted("Already have a model? Continue and import it under Advanced options with a sample IPA. No local collection is needed for an import.", cx))
                        .child(muted("The Mac's system build and authorization must be supported. Reading local FairPlay data requires existing permission; this app cannot elevate itself.", cx)));
                }
                1 => {
                    form = form
                        .child(self.guided_path("Installed iPhone or iPad app (.app)", "Choose the application installed through this Mac's App Store. This is not the downloaded IPA.", &self.fair.app, true, false, cx))
                        .child(self.guided_path("Matching downloaded IPA — required", "Choose the same app/version personalized for the same Mac App Store enrollment.", &self.fair.input, false, false, cx))
                        .child(muted("The app creates a private working folder automatically. Collection, model creation, and sample validation run in sequence. Temporary captures and sample plaintext are removed afterward.", cx));
                }
                _ => {
                    let name = |field: &Entity<InputState>| {
                        PathBuf::from(field.read(cx).value().as_str())
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "Not selected".into())
                    };
                    form = form.child(v_flex().p_4().gap_3().rounded_lg().border_1().border_color(cx.theme().border)
                        .child(div().child("Ready to prepare"))
                        .child(muted(if self.fair.model.read(cx).value().is_empty() { format!("Installed app: {}", name(&self.fair.app)) } else { format!("Existing model: {}", name(&self.fair.model)) }, cx))
                        .child(muted(format!("Sample IPA: {}", name(&self.fair.input)), cx))
                        .child(muted(if self.fair.model.read(cx).value().is_empty() { "Collect local authorization → create model → process and check sample IPA → save reusable model." } else { "Validate the imported model with the sample IPA → save reusable model. No local collection will run." }, cx))
                        .child(muted("Original files are preserved. Only a model that passes sample processing and structural checks is saved. These checks do not authenticate plaintext or Apple's signature.", cx)));
                }
            }
        } else {
            form = form.child(v_flex().p_4().gap_3().rounded_lg().border_1().border_color(cx.theme().border)
                .child(div().child("Reusable authorization"))
                .child(muted(status, cx))
                .child(h_flex().gap_2().flex_wrap()
                    .child(Button::new("start-setup").label("Prepare a model...").debug_selector(|| "fairplay-start-setup".into()).on_click(cx.listener(|this, _, window, cx| this.open_setup(None, window, cx))))
                    .child(Button::new("refresh-models").small().label("Refresh").disabled(self.fair.checking_models).on_click(cx.listener(|this, _, _, cx| this.refresh_saved_models(cx))))))
                .child(h_flex().child(Button::new("auto-decrypt").selected(self.preferences.auto_decrypt)
                    .label(if self.preferences.auto_decrypt { "Automatic decryption: On" } else { "Automatic decryption: Off" })
                    .debug_selector(|| "fairplay-auto-decrypt".into()).on_click(cx.listener(|this, _, _, cx| this.toggle_auto_decrypt(cx)))))
                .child(muted("New IPA downloads create a separate decryption task when this is on. Missing or mismatched models leave the original download intact and offer preparation. PKG downloads are unaffected.", cx))
                .child(self.guided_path("Decrypt an existing IPA (optional)", "You can also choose an already downloaded IPA here. A saved model is matched automatically when you start.", &self.fair.input, false, false, cx));
        }
        if !setup || step == 1 {
            form = form.child(
                h_flex().child(
                    Button::new("guided-advanced")
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
            if self.fair.advanced {
                if setup {
                    form = form.child(muted("Normally leave these empty. Importing an existing model replaces collection and recovery with a sample IPA validation. Other fields override this Mac's detected settings and must match the source build.", cx));
                    for (title, input, directory) in [
                        (
                            "Existing model to validate and save (optional)",
                            &self.fair.model,
                            false,
                        ),
                        (
                            "Source fairplayd image (optional)",
                            &self.fair.fairplayd,
                            false,
                        ),
                        (
                            "Compatibility fairplayd image (if requested)",
                            &self.fair.compat,
                            false,
                        ),
                        ("Startup profile (optional)", &self.fair.startup, false),
                        ("IOKit selector data (optional)", &self.fair.iokit, false),
                        (
                            "System authorization directory (optional)",
                            &self.fair.system_state,
                            true,
                        ),
                        (
                            "Shared authorization directory (optional)",
                            &self.fair.shared_state,
                            true,
                        ),
                        ("ADI directory (optional)", &self.fair.adi_state, true),
                        (
                            "Hardware identifier file (optional)",
                            &self.fair.iomac,
                            false,
                        ),
                    ] {
                        form = form.child(self.path_control(title, input, directory, false, cx));
                    }
                    form = form
                        .child(label("Network interface", cx))
                        .child(Input::new(&self.fair.interface))
                        .child(label("Source macOS version override (optional)", cx))
                        .child(Input::new(&self.fair.product_version))
                        .child(label("Source system build override (optional)", cx))
                        .child(Input::new(&self.fair.build_version))
                        .child(label("Per-phase timeout, seconds (1–3600)", cx))
                        .child(Input::new(&self.fair.timeout));
                } else {
                    form = form.child(self.guided_path("New output IPA (optional)", "Blank creates a separate .decrypted.ipa beside the input. Existing files are preserved.", &self.fair.output, false, true, cx))
                        .child(self.guided_path("New report file (optional)", "Blank creates a .decrypted.json report beside the input. Reports may contain private paths and identifiers.", &self.fair.report, false, true, cx));
                }
            }
        }
        form = form.child(
            h_flex().child(
                Button::new("expert-tools")
                    .small()
                    .label(if self.fair.tools {
                        "Hide advanced tools"
                    } else {
                        "Advanced tools"
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.fair.tools = !this.fair.tools;
                        cx.notify();
                    })),
            ),
        );
        if self.fair.tools {
            form = form.child(muted("Manual diagnostics and separate recovery stages are for troubleshooting. They do not change saved models unless you explicitly validate and save one through preparation.", cx))
                .child(h_flex().gap_2().flex_wrap().children([(FairMode::Inspect, "Inspect files"), (FairMode::Collect, "Collect only"), (FairMode::Recover, "Recover only"), (FairMode::Decrypt, "Choose model manually")].into_iter().enumerate().map(|(index, (mode, text))| {
                    Button::new(("expert-step", index)).small().label(text).on_click(cx.listener(move |this, _, window, cx| this.set_fair_mode(mode, window, cx)))
                })))
                .child(h_flex().child(Button::new("saved-model-folder").small().label("Show private model folder").on_click(cx.listener(|this, _, _, cx| { cx.reveal_path(&this.session.directory().join("fairplay-models")); }))));
        }
        form = form.child(muted("Experimental: system support and matching authorization are required. Models stay private. Managed storage is currently available on macOS/Linux; Windows private-file permission support remains open.", cx).text_sm());
        v_flex()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .child(
                h_flex()
                    .p_4()
                    .gap_2()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(
                        Button::new("saved-decryption")
                            .small()
                            .label("Decrypt IPAs")
                            .selected(!setup)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.set_fair_mode(FairMode::Saved, window, cx);
                                this.refresh_saved_models(cx);
                            })),
                    )
                    .child(
                        Button::new("model-preparation")
                            .small()
                            .label("First-time preparation")
                            .selected(setup)
                            .on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.open_setup(None, window, cx)
                                }),
                            ),
                    ),
            )
            .child(
                v_flex()
                    .id("fairplay-inputs")
                    .track_scroll(&self.fair_scroll)
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(
                        v_flex()
                            .w_full()
                            .max_w(px(868.))
                            .flex_shrink_0()
                            .p_6()
                            .child(form),
                    ),
            )
            .child(
                h_flex()
                    .p_4()
                    .gap_3()
                    .flex_wrap()
                    .flex_shrink_0()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(
                        muted("Progress and results appear in Downloads.", cx)
                            .text_sm()
                            .flex_1(),
                    )
                    .when(setup && step > 0, |row| {
                        row.child(
                            Button::new("setup-back")
                                .label("Back")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.fair.setup_step = this.fair.setup_step.saturating_sub(1);
                                    this.fair_scroll.set_offset(Default::default());
                                    cx.notify();
                                })),
                        )
                    })
                    .child(
                        Button::new("fairplay-results")
                            .label("View results")
                            .debug_selector(|| "fairplay-results".into())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.page = Page::Downloads;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("run-guided-fairplay")
                            .primary()
                            .debug_selector(|| "fairplay-submit".into())
                            .label(if setup {
                                if step == 0 {
                                    "Continue"
                                } else if step == 1 {
                                    "Review preparation"
                                } else {
                                    "Prepare and save model"
                                }
                            } else {
                                "Decrypt using saved model"
                            })
                            .on_click(cx.listener(move |this, _, window, cx| {
                                if setup && step < 2 {
                                    this.setup_next(cx);
                                } else {
                                    this.submit_fairplay(window, cx);
                                }
                            })),
                    ),
            )
            .into_any_element()
    }
}
