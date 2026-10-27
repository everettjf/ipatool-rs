//! Stream Store packages to disk, preserving validated partial downloads.

use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use reqwest::{
    blocking::{Client, Response},
    header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, HeaderMap, HeaderValue, RANGE},
};
use url::Url;

use crate::transport::Transport;

static SHOW_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Enable terminal progress for CLI package downloads.
pub fn set_progress(enabled: bool) {
    SHOW_PROGRESS.store(enabled, Ordering::Relaxed);
}

struct ProgressDisplay {
    enabled: bool,
    shown: bool,
    last_update: Option<Instant>,
    latest: Option<(u64, Option<u64>)>,
    printed: Option<(u64, Option<u64>)>,
}

impl ProgressDisplay {
    fn new() -> Self {
        Self {
            enabled: SHOW_PROGRESS.load(Ordering::Relaxed),
            shown: false,
            last_update: None,
            latest: None,
            printed: None,
        }
    }

    fn update(&mut self, current: u64, total: Option<u64>) {
        if !self.enabled {
            return;
        }
        self.latest = Some((current, total));
        let now = Instant::now();
        if self
            .last_update
            .is_some_and(|last| now.duration_since(last) < Duration::from_millis(100))
            && total != Some(current)
        {
            return;
        }
        self.last_update = Some(now);
        self.shown = true;
        self.printed = self.latest;
        let message = if let Some(total) = total {
            let percent = if total == 0 {
                100
            } else {
                (u128::from(current) * 100 / u128::from(total)) as u64
            };
            format!("downloading: {current}/{total} bytes ({percent}%)")
        } else {
            format!("downloading: {current} bytes")
        };
        let mut stderr = io::stderr().lock();
        let _ = write!(stderr, "\r{message}");
        let _ = stderr.flush();
    }

    fn finish(&mut self) {
        if self.latest != self.printed
            && let Some((current, total)) = self.latest
        {
            self.last_update = None;
            self.update(current, total);
        }
        if self.shown {
            let _ = writeln!(io::stderr());
        }
    }
}

enum RangePlan {
    Complete(u64),
    Transfer {
        offset: u64,
        length: Option<u64>,
        total: Option<u64>,
    },
}

/// Download a package into `destination`, resuming an existing partial file.
/// Invalid range responses leave the partial file unchanged.
pub fn download_file(url: &str, destination: &Path) -> Result<u64> {
    let client = Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .context("create package HTTP client")?;
    let mut progress = ProgressDisplay::new();
    let result =
        download_file_with_client_progress(&client, url, destination, &mut |current, total| {
            progress.update(current, total)
        });
    progress.finish();
    result
}

/// Download through the authenticated Store transport and its session cookies.
pub fn download_file_with_transport(
    transport: &Transport,
    url: &str,
    destination: &Path,
) -> Result<u64> {
    let mut progress = ProgressDisplay::new();
    let result = download_file_with_progress(
        url,
        destination,
        &mut |url, local_size| {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
            headers.insert(
                RANGE,
                HeaderValue::from_str(&format!("bytes={local_size}-"))?,
            );
            transport.stream_get(url, headers, None)
        },
        &mut |current, total| progress.update(current, total),
    );
    progress.finish();
    result
}

fn download_file_with_client_progress(
    client: &Client,
    url: &str,
    destination: &Path,
    progress: &mut impl FnMut(u64, Option<u64>),
) -> Result<u64> {
    download_file_with_progress(
        url,
        destination,
        &mut |url, local_size| {
            client
                .get(url)
                .header(ACCEPT_ENCODING, "identity")
                .header(RANGE, format!("bytes={local_size}-"))
                .send()
                .context("request package download")
        },
        progress,
    )
}

fn download_file_with_progress(
    url: &str,
    destination: &Path,
    request: &mut impl FnMut(Url, u64) -> Result<Response>,
    progress: &mut impl FnMut(u64, Option<u64>),
) -> Result<u64> {
    let url = Url::parse(url).context("invalid package URL")?;
    if !matches!(url.scheme(), "https" | "http") {
        bail!("package URL must use HTTP or HTTPS");
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options
        .open(destination)
        .with_context(|| format!("open partial package {}", destination.display()))?;
    let local_size = file.metadata()?.len();
    let mut response = request(url, local_size)?;
    let plan = response_range(&response, local_size)?;
    let (offset, length, total) = match plan {
        RangePlan::Complete(size) => {
            progress(size, Some(size));
            return Ok(size);
        }
        RangePlan::Transfer {
            offset,
            length,
            total,
        } => (offset, length, total),
    };
    if response.status().as_u16() == 200 {
        file.set_len(0).context("restart package download")?;
    }
    file.seek(SeekFrom::Start(offset))
        .context("seek partial package")?;
    let written = if let Some(length) = length {
        copy_with_progress(
            &mut response.take(length),
            &mut file,
            offset,
            total,
            progress,
        )?
    } else {
        copy_with_progress(&mut response, &mut file, offset, total, progress)?
    };
    if length.is_some_and(|length| written != length)
        || total.is_some_and(|total| offset.checked_add(written) != Some(total))
    {
        bail!("package download is incomplete");
    }
    Ok(offset + written)
}

fn copy_with_progress(
    reader: &mut impl Read,
    writer: &mut impl Write,
    offset: u64,
    total: Option<u64>,
    progress: &mut impl FnMut(u64, Option<u64>),
) -> Result<u64> {
    progress(offset, total);
    let mut buffer = [0u8; 64 * 1024];
    let mut written = 0u64;
    loop {
        let bytes = reader.read(&mut buffer).context("read package download")?;
        if bytes == 0 {
            break;
        }
        writer
            .write_all(&buffer[..bytes])
            .context("write package download")?;
        written += bytes as u64;
        progress(offset + written, total);
    }
    Ok(written)
}

fn response_range(response: &Response, local_size: u64) -> Result<RangePlan> {
    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .map(|value| -> Result<u64> {
            value
                .to_str()
                .context("invalid package Content-Length")?
                .parse()
                .context("invalid package Content-Length")
        })
        .transpose()?;
    match response.status().as_u16() {
        200 => Ok(RangePlan::Transfer {
            offset: 0,
            length: content_length,
            total: content_length,
        }),
        206 => {
            let header = header_text(response, CONTENT_RANGE)?;
            let span = content_range_value(header)?;
            let (bounds, total) = span
                .split_once('/')
                .context("invalid package Content-Range total")?;
            let (first, last) = bounds
                .split_once('-')
                .context("invalid package Content-Range bounds")?;
            let start: u64 = first.parse().context("invalid package range start")?;
            let end: u64 = last.parse().context("invalid package range end")?;
            let total: u64 = total.parse().context("invalid package range total")?;
            if start != local_size || end < start || end >= total {
                bail!("package Content-Range does not match partial file");
            }
            let length = end - start + 1;
            if content_length.is_some_and(|size| size != length) {
                bail!("package Content-Length does not match Content-Range");
            }
            Ok(RangePlan::Transfer {
                offset: start,
                length: Some(length),
                total: Some(total),
            })
        }
        416 => {
            let header = header_text(response, CONTENT_RANGE)?;
            if content_range_value(header)? != format!("*/{local_size}") {
                bail!("rejected package range does not match partial file");
            }
            Ok(RangePlan::Complete(local_size))
        }
        status => bail!("unexpected package download status: {status}"),
    }
}

fn content_range_value(header: &str) -> Result<&str> {
    let (unit, value) = header
        .split_once(' ')
        .context("invalid package Content-Range unit")?;
    if !unit.eq_ignore_ascii_case("bytes") {
        bail!("invalid package Content-Range unit");
    }
    Ok(value)
}

fn header_text(response: &Response, key: reqwest::header::HeaderName) -> Result<&str> {
    response
        .headers()
        .get(key)
        .context("missing package response header")?
        .to_str()
        .context("invalid package response header")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Request;
    use std::{
        fs,
        io::Write,
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
    };

    fn spawn_server(reply: &'static [u8]) -> (String, Arc<Mutex<String>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/app.ipa", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(String::new()));
        let seen = Arc::clone(&captured);
        let task = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read_exact(&mut byte).is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            *seen.lock().unwrap() = String::from_utf8(request).unwrap();
            stream.write_all(reply).unwrap();
        });
        (url, captured, task)
    }

    #[test]
    fn transfer_reuses_session_cookie_from_store_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while stream.read_exact(&mut byte).is_ok() {
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                if index == 0 {
                    assert!(request.starts_with("GET /store "));
                    stream.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: session=fixture; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                } else {
                    assert!(request.starts_with("GET /app.ipa "));
                    assert!(
                        request
                            .to_ascii_lowercase()
                            .contains("cookie: session=fixture\r\n")
                    );
                    stream.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-2/3\r\nContent-Length: 3\r\nConnection: close\r\n\r\nipa").unwrap();
                }
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let transport = Transport::with_cookies(directory.path()).unwrap();
        let store = Url::parse(&format!("http://{address}/store")).unwrap();
        assert_eq!(transport.send(Request::get(store)).unwrap().body, b"ok");
        let package = directory.path().join("app.ipa");
        assert_eq!(
            download_file_with_transport(
                &transport,
                &format!("http://{address}/app.ipa"),
                &package
            )
            .unwrap(),
            3
        );
        server.join().unwrap();
        assert_eq!(fs::read(package).unwrap(), b"ipa");
    }

    #[test]
    fn resumes_after_valid_range_and_checks_request_header() {
        let (url, request, server) = spawn_server(
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 7-14/15\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndownload",
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.tmp");
        fs::write(&path, b"partial").unwrap();
        let mut updates = Vec::new();
        assert_eq!(
            download_file_with_client_progress(
                &Client::new(),
                &url,
                &path,
                &mut |current, total| {
                    updates.push((current, total));
                }
            )
            .unwrap(),
            15
        );
        assert_eq!(updates.first(), Some(&(7, Some(15))));
        assert_eq!(updates.last(), Some(&(15, Some(15))));
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"partialdownload");
        let request = request.lock().unwrap();
        assert!(request.starts_with("GET /app.ipa HTTP/1.1\r\n"));
        assert!(request.to_ascii_lowercase().contains("range: bytes=7-\r\n"));
    }

    #[test]
    fn ignored_range_restarts_and_matching_416_preserves_complete_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.tmp");
        fs::write(&path, b"partial").unwrap();
        let (url, _, server) =
            spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew");
        assert_eq!(download_file(&url, &path).unwrap(), 3);
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");

        let (url, _, server) = spawn_server(
            b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(download_file(&url, &path).unwrap(), 3);
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn accepts_case_insensitive_content_range_unit_for_resumes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.tmp");
        fs::write(&path, b"partial").unwrap();
        let (url, _, server) = spawn_server(
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: Bytes 7-14/15\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndownload",
        );
        assert_eq!(download_file(&url, &path).unwrap(), 15);
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"partialdownload");

        let (url, _, server) = spawn_server(
            b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: BYTES */15\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(download_file(&url, &path).unwrap(), 15);
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"partialdownload");
    }

    #[test]
    #[cfg(unix)]
    fn new_partial_download_limits_mode_and_existing_mode_survives_restart() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.tmp");
        let (url, _, server) =
            spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew");
        assert_eq!(download_file(&url, &path).unwrap(), 3);
        server.join().unwrap();
        let created_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(created_mode & 0o022, 0);
        if std::env::var_os("IPATOOL_TEST_UMASK_ZERO").is_some() {
            assert_eq!(created_mode, 0o644);
        }

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (url, _, server) = spawn_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nreplaced",
        );
        assert_eq!(download_file(&url, &path).unwrap(), 8);
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replaced");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_invalid_range_without_touching_partial_file() {
        for reply in [
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-7/15\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndownload".as_slice(),
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 7-14/15\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad",
            b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */15\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("app.tmp");
            fs::write(&path, b"partial").unwrap();
            let (url, _, server) = spawn_server(reply);
            assert!(download_file(&url, &path).is_err());
            server.join().unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"partial");
        }
    }

    #[test]
    fn incomplete_chunked_response_keeps_bytes_for_retry() {
        let (url, _, server) = spawn_server(
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 7-14/15\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\ndow\r\n0\r\n\r\n",
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.tmp");
        fs::write(&path, b"partial").unwrap();
        assert!(download_file(&url, &path).is_err());
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"partialdow");
    }
}
