//! Small embedded vector set for desktop controls; no runtime asset directory.

use gpui::{AssetSource, SharedString};
use std::borrow::Cow;

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        let shape = match path {
            "icons/search.svg" => "<circle cx='10.5' cy='10.5' r='6.5'/><path d='m16 16 5 5'/>",
            "icons/panel-left.svg" => {
                "<rect x='3' y='4' width='18' height='16' rx='2'/><path d='M9 4v16'/>"
            }
            "icons/globe.svg" => {
                "<circle cx='12' cy='12' r='9'/><ellipse cx='12' cy='12' rx='4' ry='9'/><path d='M3 12h18'/>"
            }
            "icons/inbox.svg" => "<path d='m3 14 3-9h12l3 9v5H3zM3 14h5l2 3h4l2-3h5'/>",
            "icons/shield-check.svg" => {
                "<path d='m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6'/>"
            }
            "icons/settings.svg" | "icons/settings-2.svg" => {
                "<path d='M4 6h16M4 12h16M4 18h16'/><circle cx='8' cy='6' r='2'/><circle cx='16' cy='12' r='2'/><circle cx='10' cy='18' r='2'/>"
            }
            "icons/circle-user.svg" => {
                "<circle cx='12' cy='12' r='9'/><circle cx='12' cy='9' r='3'/><path d='M5 18c1-6 13-6 14 0'/>"
            }
            "icons/eye.svg" => {
                "<path d='M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z'/><circle cx='12' cy='12' r='3'/>"
            }
            "icons/eye-off.svg" => {
                "<path d='m3 3 18 18M3 10l-1 2s4 7 10 7c2 0 4-1 5-2M7 6c2-1 3-1 5-1 6 0 10 7 10 7l-2 3M10 10a3 3 0 0 0 4 4'/>"
            }
            "icons/loader-circle.svg" | "icons/loader.svg" => "<path d='M21 12a9 9 0 1 1-9-9'/>",
            "icons/close.svg" | "icons/x.svg" => "<path d='m6 6 12 12M6 18 18 6'/>",
            "icons/check.svg" => "<path d='m4 12 5 5L20 6'/>",
            "icons/circle-check.svg" => "<circle cx='12' cy='12' r='9'/><path d='m7 12 3 3 7-7'/>",
            "icons/chevron-down.svg" => "<path d='m6 9 6 6 6-6'/>",
            "icons/chevron-up.svg" => "<path d='m6 15 6-6 6 6'/>",
            "icons/chevron-left.svg" => "<path d='m15 6-6 6 6 6'/>",
            "icons/chevron-right.svg" => "<path d='m9 6 6 6-6 6'/>",
            "icons/chevrons-up-down.svg" => "<path d='m8 8 4-4 4 4m-8 8 4 4 4-4'/>",
            "icons/arrow-down.svg" => "<path d='M12 3v16m-6-6 6 6 6-6M4 21h16'/>",
            "icons/copy.svg" => {
                "<rect x='8' y='8' width='13' height='13' rx='2'/><path d='M16 8V3H3v13h5'/>"
            }
            "icons/external-link.svg" => "<path d='M14 3h7v7m0-7L10 14M10 3H3v18h18v-7'/>",
            _ => return Ok(None),
        };
        Ok(Some(Cow::Owned(format!("<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>{shape}</svg>").into_bytes())))
    }

    fn list(&self, _: &str) -> anyhow::Result<Vec<SharedString>> {
        Ok(Vec::new())
    }
}
