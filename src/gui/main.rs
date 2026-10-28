//! Optional native desktop catalog browser. Account operations stay in the CLI.

mod catalog;

use catalog::{Mode, Query, platform_name};
use gpui::{
    App, Application, Bounds, ClipboardItem, Context, Entity, IntoElement, ParentElement, Render,
    Styled, Subscription, Window, WindowBounds, WindowOptions, div, prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Disableable, Root, Selectable, Sizable,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState},
    v_flex,
};
use ipatool_rs::{App as CatalogApp, Platform};

const PLATFORMS: [(Platform, &str); 6] = [
    (Platform::Iphone, "iPhone"),
    (Platform::Ipad, "iPad"),
    (Platform::Macos, "Mac"),
    (Platform::Appletv, "Apple TV"),
    (Platform::Watchos, "Watch"),
    (Platform::Visionos, "Vision"),
];

struct CatalogWindow {
    term: Entity<InputState>,
    country: Entity<InputState>,
    mode: Mode,
    platform: Platform,
    busy: bool,
    status: String,
    error: bool,
    apps: Vec<CatalogApp>,
    selected: Option<usize>,
    // Keep the submitted filters with the results even when controls are edited.
    result_query: Option<Query>,
    _subscriptions: Vec<Subscription>,
}

impl CatalogWindow {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let term = cx.new(|cx| {
            InputState::new(window, cx).placeholder("App name, numeric ID, or bundle identifier")
        });
        let country = cx.new(|cx| {
            let mut state = InputState::new(window, cx).placeholder("US");
            state.set_value("US", window, cx);
            state
        });
        let subscriptions = [&term, &country]
            .into_iter()
            .map(|input| {
                cx.subscribe_in(input, window, |this, _, event, _, cx| {
                    if matches!(event, InputEvent::PressEnter { .. }) {
                        this.submit(cx);
                    }
                })
            })
            .collect();
        term.update(cx, |input, cx| input.focus(window, cx));
        Self {
            term,
            country,
            mode: Mode::Search,
            platform: Platform::Iphone,
            busy: false,
            status: "Ready. Public catalog queries do not require an account.".into(),
            error: false,
            apps: Vec::new(),
            selected: None,
            result_query: None,
            _subscriptions: subscriptions,
        }
    }

    fn submit(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let query = match Query::new(
            self.mode,
            &self.term.read(cx).value(),
            &self.country.read(cx).value(),
            self.platform,
        ) {
            Ok(query) => query,
            Err(error) => {
                self.status = error.to_string();
                self.error = true;
                cx.notify();
                return;
            }
        };
        self.busy = true;
        self.error = false;
        self.status = format!("Loading {}...", query.description());
        self.apps.clear();
        self.selected = None;
        self.result_query = Some(query.clone());
        cx.notify();

        // reqwest's blocking client must be constructed and used off the UI thread.
        let work = cx.background_spawn(async move { query.execute() });
        cx.spawn(async move |view, cx| {
            let result = work.await;
            let _ = view.update(cx, |this, cx| {
                this.busy = false;
                match result {
                    Ok(apps) => {
                        this.status = if apps.is_empty() {
                            "No apps found. Try another term, platform, or country.".into()
                        } else {
                            format!(
                                "Results loaded: {}. Select an app to inspect it.",
                                apps.len()
                            )
                        };
                        this.selected = (!apps.is_empty()).then_some(0);
                        this.apps = apps;
                    }
                    Err(error) => {
                        this.status = format!("Request failed: {error:#}");
                        this.error = true;
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn copy(&mut self, text: String, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.status = "Copied to clipboard.".into();
        self.error = false;
        cx.notify();
    }

    fn details(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some((app, query)) = self
            .selected
            .and_then(|index| self.apps.get(index))
            .zip(self.result_query.as_ref())
        else {
            return v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .gap_3()
                .child(div().text_xl().child("Explore the App Store"))
                .child(
                    div()
                        .text_color(cx.theme().muted_foreground)
                        .child("Search for an app or look up its identifier."),
                )
                .into_any_element();
        };
        let app_id = app.id.to_string();
        let bundle = app.bundle_id.clone();
        let lookup = query.lookup_command(app);
        let download = query.download_command(app);
        let json = serde_json::to_string_pretty(app).expect("catalog app is serializable");
        v_flex().id("app-details").flex_1().min_w_0().overflow_y_scroll().p_6().gap_5()
            .child(div().text_sm().text_color(cx.theme().muted_foreground).child("APPLICATION DETAILS"))
            .child(div().text_2xl().child(app.name.clone()))
            .child(Self::field("Bundle identifier", app.bundle_id.clone(), cx))
            .child(Self::field("App ID", app.id.to_string(), cx))
            .child(Self::field("Version", app.version.clone(), cx))
            .child(Self::field("Price", if app.price == 0.0 { "Free".into() } else { format!("{} (catalog value; currency unavailable)", app.price) }, cx))
            .child(Self::field("Supported platforms", app.platforms.as_ref().map(|platforms| platforms.iter().map(|platform| platform_name(*platform)).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| "Unknown".into()), cx))
            .child(h_flex().gap_2().flex_wrap()
                .child(Button::new("copy-id").label("Copy ID").on_click(cx.listener(move |this, _, _, cx| this.copy(app_id.clone(), cx))))
                .child(Button::new("copy-bundle").label("Copy bundle ID").on_click(cx.listener(move |this, _, _, cx| this.copy(bundle.clone(), cx))))
                .child(Button::new("copy-json").label("Copy JSON").on_click(cx.listener(move |this, _, _, cx| this.copy(json.clone(), cx)))))
            .child(div().border_t_1().border_color(cx.theme().border).pt_5().child("Continue in the CLI"))
            .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Downloads require a saved account and the appropriate entitlement. The CLI uses the account's storefront."))
            .child(v_flex().gap_2()
                .child(Button::new("copy-lookup").label("Copy lookup command").on_click(cx.listener(move |this, _, _, cx| this.copy(lookup.clone(), cx))))
                .child(Button::new("copy-download").label("Copy download command").on_click(cx.listener(move |this, _, _, cx| this.copy(download.clone(), cx)))))
            .into_any_element()
    }

    fn field(label: &'static str, value: String, cx: &App) -> impl IntoElement + use<> {
        v_flex()
            .gap_1()
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(label),
            )
            .child(div().child(if value.is_empty() {
                "Unavailable".into()
            } else {
                value
            }))
    }
}

impl Render for CatalogWindow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let details = self.details(cx);
        v_flex().size_full().bg(cx.theme().background).text_color(cx.theme().foreground)
            .child(v_flex().p_6().gap_4().border_b_1().border_color(cx.theme().border)
                .child(h_flex().justify_between()
                    .child(div().text_2xl().child("ipatool"))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground).child("EXPERIMENTAL / GPUI")))
                .child(h_flex().gap_2().children([Mode::Search, Mode::AppId, Mode::BundleId].into_iter().enumerate().map(|(index, mode)| {
                    Button::new(("mode", index)).label(mode.label()).selected(self.mode == mode).disabled(self.busy)
                        .on_click(cx.listener(move |this, _, _, cx| { this.mode = mode; cx.notify(); }))
                })))
                .child(h_flex().gap_3()
                    .child(div().flex_1().child(Input::new(&self.term).disabled(self.busy)))
                    .child(v_flex().w(px(90.)).child(Input::new(&self.country).disabled(self.busy)))
                    .child(Button::new("submit").primary().label(if self.busy { "Loading..." } else { "Go" }).disabled(self.busy)
                        .on_click(cx.listener(|this, _, _, cx| this.submit(cx)))))
                .child(h_flex().gap_2()
                    .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Platform"))
                    .children(PLATFORMS.into_iter().enumerate().map(|(index, (platform, label))| {
                        Button::new(("platform", index)).small().label(label).selected(self.platform == platform).disabled(self.busy)
                            .on_click(cx.listener(move |this, _, _, cx| { this.platform = platform; cx.notify(); }))
                    }))
                    .child(div().ml_auto().text_sm().text_color(cx.theme().muted_foreground).child("Country: two-letter code"))))
            .child(div().flex().flex_1().min_h_0()
                .child(v_flex().w(px(320.)).flex_shrink_0().border_r_1().border_color(cx.theme().border)
                    .child(v_flex().p_4().gap_1()
                        .child(format!("RESULTS: {}", self.apps.len()))
                        .child(div().text_xs().text_color(cx.theme().muted_foreground).child(self.result_query.as_ref().map(Query::description).unwrap_or_else(|| "Up to 25 results / 12 for visionOS".into()))))
                    .child(v_flex().id("app-results").flex_1().min_h_0().overflow_y_scroll()
                        .children(self.apps.iter().enumerate().map(|(index, app)| {
                            v_flex().id(("app", index)).p_4().gap_1().cursor_pointer()
                                .bg(if self.selected == Some(index) { cx.theme().accent } else { cx.theme().background })
                                .hover(|style| style.bg(cx.theme().accent))
                                .child(app.name.clone())
                                .child(div().text_xs().text_color(cx.theme().muted_foreground).child(app.bundle_id.clone()))
                                .on_click(cx.listener(move |this, _, _, cx| { this.selected = Some(index); cx.notify(); }))
                        }))))
                .child(details))
            .child(v_flex().px_6().py_3().gap_1().border_t_1().border_color(cx.theme().border)
                .child(div().text_sm().text_color(if self.error { cx.theme().danger } else { cx.theme().muted_foreground }).child(self.status.clone()))
                .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Experimental Codex Rust rewrite. For practical use, prefer the original ipatool and UnfairPlay projects.")))
    }
}

fn main() {
    Application::new().run(|cx| {
        gpui_component::init(cx);
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        let bounds = Bounds::centered(None, size(px(1080.), px(780.)), cx);
        let result = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(900.), px(640.))),
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("ipatool - App Store Catalog".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|cx| CatalogWindow::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        );
        if let Err(error) = result {
            eprintln!("Failed to open the catalog window: {error:#}");
            cx.quit();
        }
        cx.activate(true);
    });
}
