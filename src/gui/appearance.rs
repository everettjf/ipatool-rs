//! One focused dark palette for the desktop preview.

use gpui::App;
use gpui_component::{Theme, ThemeMode};
use std::rc::Rc;

pub fn configure(cx: &mut App) {
    let theme = Theme::global_mut(cx);
    let config = Rc::make_mut(&mut theme.dark_theme);
    config.name = "ipatool Dark".into();
    config.radius = Some(8);
    config.radius_lg = Some(12);
    let colors = &mut config.colors;
    colors.background = Some("#111318".into());
    colors.foreground = Some("#e8ecf2".into());
    colors.muted_foreground = Some("#9ca8ba".into());
    colors.secondary = Some("#1c222c".into());
    colors.secondary_foreground = colors.foreground.clone();
    colors.secondary_hover = Some("#293341".into());
    colors.secondary_active = Some("#20324d".into());
    colors.accent = Some("#20324d".into());
    colors.accent_foreground = colors.foreground.clone();
    colors.border = Some("#2b3443".into());
    colors.input = Some("#3b4658".into());
    colors.primary = Some("#2563eb".into());
    colors.primary_hover = Some("#1d4ed8".into());
    colors.primary_active = Some("#1e40af".into());
    colors.primary_foreground = Some("#ffffff".into());
    colors.ring = Some("#60a5fa".into());
    colors.danger = Some("#fb7185".into());
    colors.danger_foreground = Some("#111318".into());
    Theme::change(ThemeMode::Dark, None, cx);
}
