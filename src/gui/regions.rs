//! Searchable regions with a committed value separate from menu navigation.

use gpui::{
    App, Context, Corner, Entity, EventEmitter, FocusHandle, Focusable, KeyDownEvent, Render,
    Subscription, Task, Window, div, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, IconName, Sizable,
    button::Button,
    list::{List, ListDelegate, ListEvent, ListItem, ListState},
    popover::Popover,
};

#[derive(Clone)]
pub struct Region {
    code: String,
    name: String,
}

impl Region {
    fn title(&self) -> String {
        format!("{} ({})", self.name, self.code)
    }
}

pub fn choices(current: &str) -> Vec<Region> {
    let mut regions: Vec<_> = include_str!("regions.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('\t'))
        .map(|(code, name)| Region {
            code: code.into(),
            name: name.into(),
        })
        .collect();
    // Preserve previously accepted codes outside the account mapping.
    let code = current.to_ascii_uppercase();
    if !regions.iter().any(|region| region.code == code) {
        regions.push(Region {
            name: code.clone(),
            code,
        });
    }
    regions
}

pub fn label(code: &str) -> String {
    let code = code.to_ascii_uppercase();
    include_str!("regions.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find(|(value, _)| *value == code)
        .map_or_else(|| code.clone(), |(_, name)| format!("{} ({})", name, code))
}

pub struct Changed(pub String);

pub struct Picker {
    country: String,
    list: Entity<ListState<RegionList>>,
    open: bool,
    focus: FocusHandle,
    subscription: Option<Subscription>,
}

impl EventEmitter<Changed> for Picker {}

impl Picker {
    pub fn new(country: &str, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let country = country.to_ascii_uppercase();
        let list =
            cx.new(|cx| ListState::new(RegionList::new(&country), window, cx).searchable(true));
        Self {
            country,
            list,
            open: false,
            focus: cx.focus_handle(),
            subscription: None,
        }
    }

    pub fn value(&self) -> &str {
        &self.country
    }

    pub fn set_value(&mut self, country: &str, cx: &mut Context<Self>) {
        self.country = country.to_ascii_uppercase();
        self.open = false;
        cx.notify();
    }

    fn open_menu(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        // Start each menu session with a fresh search/index. In the pinned
        // Select component, filtering and cancellation can reuse an index from
        // a different result set and display or confirm the wrong region.
        self.list = cx
            .new(|cx| ListState::new(RegionList::new(&self.country), window, cx).searchable(true));
        self.subscription =
            Some(
                cx.subscribe_in(&self.list, window, |this, list, event, window, cx| {
                    match event {
                        ListEvent::Confirm(index) => {
                            let code = list
                                .read(cx)
                                .delegate()
                                .matches
                                .get(index.row)
                                .map(|region| region.code.clone());
                            if let Some(code) = code {
                                this.country = code.clone();
                                this.open = false;
                                this.focus.focus(window);
                                cx.emit(Changed(code));
                            }
                        }
                        ListEvent::Cancel => {
                            this.open = false;
                            this.focus.focus(window);
                        }
                        ListEvent::Select(_) => {}
                    }
                    cx.notify();
                }),
            );
        self.open = true;
        self.list.update(cx, |list, cx| list.focus(window, cx));
        cx.notify();
    }
}

impl Render for Picker {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let list = self.list.clone();
        let focus = list.focus_handle(cx);
        let view = cx.entity().downgrade();
        div()
            .id("region-picker")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, window, cx| {
                if !this.open && matches!(event.keystroke.key.as_str(), "enter" | "space" | "down")
                {
                    this.open_menu(window, cx);
                    cx.stop_propagation();
                }
            }))
            .child(
                Popover::new("region-menu")
                    .anchor(Corner::TopRight)
                    .open(self.open)
                    .track_focus(&focus)
                    .trigger(
                        Button::new("region-trigger")
                            .small()
                            .label(label(&self.country))
                            .icon(IconName::ChevronDown)
                            .w_full(),
                    )
                    .on_open_change(move |open, window, cx| {
                        let _ = view.update(cx, |this, cx| {
                            if *open {
                                this.open_menu(window, cx);
                            } else {
                                this.open = false;
                                cx.notify();
                            }
                        });
                    })
                    .content(move |_, _, _| {
                        List::new(&list)
                            .small()
                            .search_placeholder("Search regions or country codes")
                            .max_h(px(320.))
                            .w(px(304.))
                    }),
            )
    }
}

struct RegionList {
    all: Vec<Region>,
    matches: Vec<Region>,
    selected: Option<gpui_component::IndexPath>,
}

impl RegionList {
    fn new(country: &str) -> Self {
        let all = choices(country);
        Self {
            matches: all.clone(),
            all,
            selected: None,
        }
    }
}

impl ListDelegate for RegionList {
    type Item = ListItem;

    fn items_count(&self, _: usize, _: &App) -> usize {
        self.matches.len()
    }

    fn perform_search(
        &mut self,
        query: &str,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) -> Task<()> {
        let query = query.to_ascii_lowercase();
        self.matches = self
            .all
            .iter()
            .filter(|region| region.title().to_ascii_lowercase().contains(&query))
            .cloned()
            .collect();
        // A typed code such as US must precede names containing the same
        // letters (Australia, Austria, Russia) when confirmed with Enter.
        self.matches
            .sort_by_key(|region| region.code.to_ascii_lowercase() != query);
        Task::ready(())
    }

    fn set_selected_index(
        &mut self,
        index: Option<gpui_component::IndexPath>,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) {
        self.selected = index;
    }

    fn render_item(
        &mut self,
        index: gpui_component::IndexPath,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) -> Option<ListItem> {
        self.matches.get(index.row).map(|region| {
            ListItem::new(index.row)
                .selected(self.selected == Some(index))
                .child(region.title())
        })
    }

    fn render_empty(
        &mut self,
        _: &mut Window,
        cx: &mut Context<ListState<Self>>,
    ) -> impl IntoElement {
        div()
            .p_3()
            .text_color(cx.theme().muted_foreground)
            .child("No matching regions")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_account_regions_are_unique_and_unknown_preferences_remain_selectable() {
        let regions = choices("zz");
        let mut codes = std::collections::HashSet::new();
        for region in &regions {
            assert!(codes.insert(region.code.as_str()));
            assert_eq!(region.code.len(), 2);
            assert!(region.code.bytes().all(|byte| byte.is_ascii_uppercase()));
        }
        assert!(regions.iter().any(|region| region.code == "ZZ"));
        assert_eq!(label("cn"), "China (CN)");
        assert_eq!(label("ZZ"), "ZZ");
    }
}
