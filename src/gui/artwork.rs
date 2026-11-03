//! Bounded, unauthenticated public artwork loading, independent of Store state.

use gpui::{Image, ImageFormat};
use ipatool_rs::App;
use std::{collections::HashMap, io::Read, sync::Arc, time::Duration};

const MAX_BYTES: u64 = 256 * 1024;

fn allowed(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url
            .host_str()
            .is_some_and(|host| host == "mzstatic.com" || host.ends_with(".mzstatic.com"))
}

pub fn load(apps: Vec<App>) -> HashMap<i64, Arc<Image>> {
    let Ok(client) = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 3 && allowed(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
    else {
        return HashMap::new();
    };
    std::thread::scope(|scope| {
        let workers: Vec<_> = apps
            .chunks(apps.len().div_ceil(4).max(1))
            .map(|chunk| {
                let client = &client;
                scope.spawn(move || {
                    chunk
                        .iter()
                        .filter_map(|app| {
                            let url = url::Url::parse(&app.artwork_url).ok().filter(allowed)?;
                            let response = client.get(url).send().ok()?.error_for_status().ok()?;
                            if response
                                .content_length()
                                .is_some_and(|size| size > MAX_BYTES)
                            {
                                return None;
                            }
                            let mut bytes = Vec::new();
                            response.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
                            if bytes.len() as u64 > MAX_BYTES {
                                return None;
                            }
                            let format = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                                ImageFormat::Png
                            } else if bytes.starts_with(b"\xff\xd8\xff") {
                                ImageFormat::Jpeg
                            } else if bytes.starts_with(b"RIFF")
                                && bytes.get(8..12) == Some(b"WEBP")
                            {
                                ImageFormat::Webp
                            } else {
                                return None;
                            };
                            Some((app.id, Arc::new(Image::from_bytes(format, bytes))))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap_or_default())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn artwork_requests_and_redirects_require_the_public_apple_cdn() {
        for url in [
            "https://is1-ssl.mzstatic.com/image.png",
            "https://mzstatic.com/image.jpg",
        ] {
            assert!(allowed(&url::Url::parse(url).unwrap()));
        }
        for url in [
            "http://is1-ssl.mzstatic.com/image.png",
            "https://mzstatic.com.example.invalid/image.png",
            "https://localhost/image.png",
            "https://user:password@is1-ssl.mzstatic.com/image.png",
            "https://is1-ssl.mzstatic.com:8443/image.png",
        ] {
            assert!(!allowed(&url::Url::parse(url).unwrap()));
        }
    }
}
