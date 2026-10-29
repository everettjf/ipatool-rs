//! Neutral, layered dark surfaces with blue reserved for interactive emphasis.

use gpui::App;
use gpui_component::{Theme, ThemeMode};
use std::rc::Rc;

pub fn configure(cx: &mut App) {
    let theme = Theme::global_mut(cx);
    let config = Rc::make_mut(&mut theme.dark_theme);
    config.name = "ipatool Graphite".into();
    config.radius = Some(8);
    config.radius_lg = Some(12);
    let colors = &mut config.colors;
    // Use equal RGB channels for surfaces so the workspace has no blue cast.
    colors.background = Some("#1e1e1e".into());
    colors.foreground = Some("#f2f2f2".into());
    colors.muted_foreground = Some("#b3b3b3".into());
    colors.secondary = Some("#333333".into());
    colors.secondary_foreground = colors.foreground.clone();
    colors.secondary_hover = Some("#3d3d3d".into());
    colors.secondary_active = Some("#484848".into());
    colors.accent = Some("#404040".into());
    colors.accent_foreground = colors.foreground.clone();
    colors.border = Some("#3d3d3d".into());
    colors.input = Some("#636363".into());
    colors.sidebar = Some("#282828".into());
    colors.sidebar_foreground = colors.foreground.clone();
    colors.sidebar_border = colors.border.clone();
    colors.sidebar_accent = colors.accent.clone();
    colors.sidebar_accent_foreground = colors.foreground.clone();
    colors.popover = Some("#2b2b2b".into());
    colors.popover_foreground = colors.foreground.clone();
    colors.muted = colors.secondary.clone();
    colors.list = colors.background.clone();
    colors.list_head = colors.sidebar.clone();
    colors.list_even = colors.background.clone();
    colors.list_hover = colors.secondary.clone();
    colors.list_active = colors.accent.clone();
    colors.list_active_border = colors.input.clone();
    colors.selection = Some("#4b4b4b".into());
    colors.scrollbar = Some("#00000000".into());
    colors.scrollbar_thumb = Some("#666666".into());
    colors.scrollbar_thumb_hover = Some("#808080".into());
    colors.title_bar = colors.sidebar.clone();
    colors.title_bar_border = colors.border.clone();
    colors.primary = Some("#0b61d8".into());
    colors.primary_hover = Some("#0a58c4".into());
    colors.primary_active = Some("#094db0".into());
    colors.primary_foreground = Some("#ffffff".into());
    colors.ring = Some("#64a6ff".into());
    colors.caret = colors.foreground.clone();
    colors.progress_bar = colors.primary.clone();
    colors.danger = Some("#fb7185".into());
    colors.danger_foreground = colors.background.clone();
    Theme::change(ThemeMode::Dark, None, cx);
}
