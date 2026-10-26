//! Stream Store packages to disk, preserving validated partial downloads.

use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use anyhow::{Context, Result, bail};
use reqwest::{
    blocking::{Client, Response},
    header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, RANGE},
};
use url::Url;

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
    download_file_with_client(&client, url, destination)
}

fn download_file_with_client(client: &Client, url: &str, destination: &Path) -> Result<u64> {
    let url = Url::parse(url).context("invalid package URL")?;
    if !matches!(url.scheme(), "https" | "http") {
        bail!("package URL must use HTTP or HTTPS");
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(destination)
        .with_context(|| format!("open partial package {}", destination.display()))?;
    let local_size = file.metadata()?.len();
    let mut response = client
        .get(url)
        .header(ACCEPT_ENCODING, "identity")
        .header(RANGE, format!("bytes={local_size}-"))
        .send()
        .context("request package download")?;
    let plan = response_range(&response, local_size)?;
    let (offset, length, total) = match plan {
        RangePlan::Complete(size) => return Ok(size),
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
        io::copy(&mut response.take(length), &mut file).context("write package download")?
    } else {
        io::copy(&mut response, &mut file).context("write package download")?
    };
    if length.is_some_and(|length| written != length)
        || total.is_some_and(|total| offset.checked_add(written) != Some(total))
    {
        bail!("package download is incomplete");
    }
    Ok(offset + written)
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
            let span = header
                .strip_prefix("bytes ")
                .context("invalid package Content-Range unit")?;
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
            let expected = format!("bytes */{local_size}");
            if header_text(response, CONTENT_RANGE)? != expected {
                bail!("rejected package range does not match partial file");
            }
            Ok(RangePlan::Complete(local_size))
        }
        status => bail!("unexpected package download status: {status}"),
    }
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
    fn resumes_after_valid_range_and_checks_request_header() {
        let (url, request, server) = spawn_server(
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 7-14/15\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndownload",
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.tmp");
        fs::write(&path, b"partial").unwrap();
        assert_eq!(download_file(&url, &path).unwrap(), 15);
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
