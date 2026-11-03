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

#[path = "download_file_resume.rs"]
mod resume;

pub(crate) fn resume_checkpoint_path(package: &Path) -> std::path::PathBuf {
    resume::path(package)
}

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
        crate::application::operation::progress(
            crate::application::operation::Stage::Downloading,
            current,
            total,
        );
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
    if crate::application::operation::is_active() {
        return download_cancellable(&Transport::new()?, url, destination);
    }
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
    if crate::application::operation::is_active() {
        return download_cancellable(transport, url, destination);
    }
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
    crate::application::operation::check()?;
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
        crate::application::operation::check()?;
        let bytes = reader.read(&mut buffer).context("read package download")?;
        crate::application::operation::check()?;
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

fn download_cancellable(transport: &Transport, url: &str, destination: &Path) -> Result<u64> {
    use crate::application::operation;
    use sha2::{Digest, Sha256};
    operation::check()?;
    let identity = operation::transfer_identity().map(|scope| resume::identity(&scope, url));
    let url = Url::parse(url).context("invalid package URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("package URL must use HTTP or HTTPS");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        if identity.is_some()
            && let Ok(metadata) = std::fs::symlink_metadata(destination)
            && !metadata.is_file()
        {
            bail!("partial package must be a regular file");
        }
        let mut file = options.open(destination).context("open partial package")?;
        let checkpoint = identity
            .as_ref()
            .map(|identity| resume::load(destination, identity))
            .transpose()?
            .flatten();
        let actual_size = file.metadata()?.len();
        let local_size = if identity.is_none() || checkpoint.is_some() {
            actual_size
        } else {
            0
        };
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        headers.insert(
            RANGE,
            HeaderValue::from_str(&format!("bytes={local_size}-"))?,
        );
        if let Some((checkpoint, _)) = &checkpoint {
            headers.insert(
                reqwest::header::IF_RANGE,
                HeaderValue::from_str(&checkpoint.validator)?,
            );
        }
        let mut response = transport.stream_get_async(url, headers, None).await?;
        let validator = resume::validator(response.headers());
        if let Some((checkpoint, _)) = &checkpoint
            && response.status().as_u16() != 200
            && validator.as_deref() != Some(&checkpoint.validator)
        {
            let _ = std::fs::remove_file(resume::path(destination));
            bail!("package validator changed; restart the transfer");
        }
        let (offset, length, total) = match response_range_headers(
            response.status().as_u16(),
            response.headers(),
            local_size,
        )? {
            RangePlan::Complete(size) => {
                if identity.is_some() && checkpoint.is_none() {
                    bail!("cannot accept completed transfer without a verified checkpoint");
                }
                if checkpoint.as_ref().is_some_and(|(checkpoint, _)| {
                    checkpoint.total.is_some_and(|total| total != size)
                }) {
                    let _ = std::fs::remove_file(resume::path(destination));
                    bail!("completed package length changed; restart the transfer");
                }
                return Ok(size);
            }
            RangePlan::Transfer {
                offset,
                length,
                total,
            } => (offset, length, total),
        };
        if response.status().as_u16() == 206
            && checkpoint.as_ref().is_some_and(|(checkpoint, _)| {
                checkpoint.total.is_some() && checkpoint.total != total
            })
        {
            let _ = std::fs::remove_file(resume::path(destination));
            bail!("package total length changed; restart the transfer");
        }
        operation::check()?;
        let mut hash = if offset == 0 {
            Sha256::new()
        } else {
            checkpoint.map(|(_, hash)| hash).unwrap_or_default()
        };
        if offset == 0 {
            file.set_len(0)?;
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut progress = ProgressDisplay::new();
        let mut written = 0u64;
        progress.update(offset, total);
        let transfer: Result<()> = async {
            while let Some(chunk) = operation::wait(response.chunk()).await? {
                operation::check()?;
                if length
                    .is_some_and(|expected| written.saturating_add(chunk.len() as u64) > expected)
                {
                    bail!("package download exceeds the advertised range");
                }
                file.write_all(&chunk)?;
                hash.update(&chunk);
                written += chunk.len() as u64;
                progress.update(offset + written, total);
            }
            Ok(())
        }
        .await;
        let checkpoint_result = file.sync_all().map_err(anyhow::Error::from).and_then(|_| {
            if let Some(identity) = &identity {
                resume::save(
                    destination,
                    identity,
                    validator.as_deref(),
                    offset + written,
                    total,
                    &hash,
                )
            } else {
                Ok(())
            }
        });
        progress.finish();
        transfer?;
        checkpoint_result?;
        if length.is_some_and(|expected| written != expected)
            || total.is_some_and(|expected| offset.checked_add(written) != Some(expected))
        {
            bail!("package download is incomplete");
        }
        file.sync_all()?;
        Ok(offset + written)
    })
}

fn response_range(response: &Response, local_size: u64) -> Result<RangePlan> {
    response_range_headers(response.status().as_u16(), response.headers(), local_size)
}

fn response_range_headers(status: u16, headers: &HeaderMap, local_size: u64) -> Result<RangePlan> {
    let content_length = headers
        .get(CONTENT_LENGTH)
        .map(|value| -> Result<u64> {
            value
                .to_str()
                .context("invalid package Content-Length")?
                .parse()
                .context("invalid package Content-Length")
        })
        .transpose()?;
    match status {
        200 => Ok(RangePlan::Transfer {
            offset: 0,
            length: content_length,
            total: content_length,
        }),
        206 => {
            let header = header_text(headers, CONTENT_RANGE)?;
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
            let header = header_text(headers, CONTENT_RANGE)?;
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

fn header_text(headers: &HeaderMap, key: reqwest::header::HeaderName) -> Result<&str> {
    headers
        .get(key)
        .context("missing package response header")?
        .to_str()
        .context("invalid package response header")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_transfer_cancels_a_stalled_body_and_keeps_received_bytes() {
        use crate::application::operation::{Cancelled, Operation};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/app.ipa", listener.local_addr().unwrap());
        let (close_tx, close_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read_exact(&mut byte).is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nETag: \"fixture\"\r\n\r\npart",
                )
                .unwrap();
            let _ = close_rx.recv_timeout(Duration::from_secs(5));
        });
        let (progress_tx, progress_rx) = std::sync::mpsc::channel();
        let operation = Operation::new(move |progress| {
            if progress.completed >= 4 {
                let _ = progress_tx.send(());
            }
        });
        let operation = operation.with_transfer_identity("fixture-account-and-app".into());
        let cancellation = operation.clone();
        let cancel = thread::spawn(move || {
            progress_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            cancellation.cancel();
        });
        let directory = tempfile::tempdir().unwrap();
        let package = directory.path().join("app.partial");
        let started = Instant::now();
        let error = operation.run(|| download_file(&url, &package)).unwrap_err();
        assert!(error.is::<Cancelled>());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(fs::read(&package).unwrap(), b"part");
        assert!(
            resume::load(&package, &resume::identity("fixture-account-and-app", &url))
                .unwrap()
                .is_some()
        );
        close_tx.send(()).unwrap();
        cancel.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn scoped_transfer_resumes_only_verified_bytes_and_restarts_changed_account_or_bytes() {
        use crate::application::operation::Operation;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/app.ipa", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let replies: [&[u8]; 4] = [
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nETag: \"a\"\r\nConnection: close\r\n\r\nabcd",
                b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 4-9/10\r\nContent-Length: 6\r\nETag: \"a\"\r\nConnection: close\r\n\r\nefghij",
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nETag: \"b\"\r\nConnection: close\r\n\r\n0123456789",
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nETag: \"c\"\r\nConnection: close\r\n\r\nABCDEFGHIJ",
            ];
            for (index, reply) in replies.into_iter().enumerate() {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while stream.read_exact(&mut byte).is_ok() {
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.contains(if index == 1 {
                    "range: bytes=4-\r\n"
                } else {
                    "range: bytes=0-\r\n"
                }));
                assert_eq!(request.contains("if-range: \"a\"\r\n"), index == 1);
                stream.write_all(reply).unwrap();
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let package = directory.path().join("app.partial");
        let original = Operation::default().with_transfer_identity("account-app-version".into());
        assert!(original.run(|| download_file(&url, &package)).is_err());
        assert_eq!(fs::read(&package).unwrap(), b"abcd");
        assert_eq!(original.run(|| download_file(&url, &package)).unwrap(), 10);
        assert_eq!(fs::read(&package).unwrap(), b"abcdefghij");
        fs::write(&package, b"tampered!!").unwrap();
        original.run(|| download_file(&url, &package)).unwrap();
        assert_eq!(fs::read(&package).unwrap(), b"0123456789");
        Operation::default()
            .with_transfer_identity("other-account-app-version".into())
            .run(|| download_file(&url, &package))
            .unwrap();
        assert_eq!(fs::read(&package).unwrap(), b"ABCDEFGHIJ");
        server.join().unwrap();
    }

    #[test]
    fn scoped_transfer_rejects_changed_validator_or_total_before_writing_partial_bytes() {
        use crate::application::operation::Operation;
        use sha2::{Digest, Sha256};
        let replies: [&[u8]; 3] = [
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 4-9/10\r\nContent-Length: 6\r\nETag: \"changed\"\r\nConnection: close\r\n\r\nWRONG!",
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 4-10/11\r\nContent-Length: 7\r\nETag: \"original\"\r\nConnection: close\r\n\r\nWRONG!!",
            b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */4\r\nContent-Length: 0\r\nETag: \"original\"\r\nConnection: close\r\n\r\n",
        ];
        for reply in replies {
            let (url, captured, server) = spawn_server(reply);
            let directory = tempfile::tempdir().unwrap();
            let package = directory.path().join("partial");
            fs::write(&package, b"abcd").unwrap();
            resume::save(
                &package,
                &resume::identity("fixture", &url),
                Some("\"original\""),
                4,
                Some(10),
                &Sha256::new_with_prefix(b"abcd"),
            )
            .unwrap();
            assert!(
                Operation::default()
                    .with_transfer_identity("fixture".into())
                    .run(|| download_file(&url, &package))
                    .is_err()
            );
            assert_eq!(fs::read(&package).unwrap(), b"abcd");
            assert!(!resume::path(&package).exists());
            server.join().unwrap();
            assert!(
                captured
                    .lock()
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains("if-range: \"original\"")
            );
        }
    }

    #[test]
    fn application_range_validation_preserves_partial_files_and_can_resume() {
        use crate::application::operation::Operation;
        for (reply, expected, succeeds) in [
            (&b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 7-14/15\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndownload"[..], &b"partialdownload"[..], true),
            (&b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-7/15\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndownload"[..], &b"partial"[..], false),
            (&b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..], &b"partial"[..], true),
        ] {
            let (url, _, server) = spawn_server(reply);
            let directory = tempfile::tempdir().unwrap(); let package = directory.path().join("partial");
            fs::write(&package, b"partial").unwrap();
            assert_eq!(Operation::default().run(|| download_file(&url, &package)).is_ok(), succeeds);
            assert_eq!(fs::read(package).unwrap(), expected);
            server.join().unwrap();
        }
    }
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
    fn authenticated_transfer_streams_package_beyond_store_body_limit() {
        const SIZE: usize = (32 << 20) + 1;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read_exact(&mut byte).is_ok() {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains("range: bytes=0-\r\n")
            );
            write!(stream, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{}/{SIZE}\r\nContent-Length: {SIZE}\r\nConnection: close\r\n\r\n", SIZE - 1).unwrap();
            let chunk = [0x5a; 64 * 1024];
            for _ in 0..(SIZE / chunk.len()) {
                stream.write_all(&chunk).unwrap();
            }
            stream.write_all(&chunk[..SIZE % chunk.len()]).unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let transport = Transport::with_cookies(directory.path()).unwrap();
        let package = directory.path().join("large.ipa");
        assert_eq!(
            download_file_with_transport(
                &transport,
                &format!("http://{address}/large.ipa"),
                &package
            )
            .unwrap(),
            SIZE as u64
        );
        server.join().unwrap();
        let mut file = fs::File::open(package).unwrap();
        assert_eq!(file.metadata().unwrap().len(), SIZE as u64);
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x5a]);
        file.seek(SeekFrom::End(-1)).unwrap();
        file.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x5a]);
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

    #[test]
    fn retries_an_interrupted_transfer_from_the_saved_offset() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/app.ipa", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while stream.read_exact(&mut byte).is_ok() {
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                if attempt == 0 {
                    assert!(request.contains("range: bytes=0-\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\npart")
                        .unwrap();
                } else {
                    assert!(request.contains("range: bytes=4-\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 4-9/10\r\nContent-Length: 6\r\nConnection: close\r\n\r\nialipa")
                        .unwrap();
                }
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.tmp");
        assert!(download_file(&url, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"part");
        assert_eq!(download_file(&url, &path).unwrap(), 10);
        server.join().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"partialipa");
    }
}
