//! Random access to the pinned macOS restore archive using verified HTTP ranges.

use std::{
    io::{self, Read, Seek, SeekFrom},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use reqwest::{
    blocking::Client,
    header::{ACCEPT_ENCODING, CONTENT_RANGE, RANGE},
};
use url::Url;

pub const RESTORE_URL: &str = "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw";
const READ_ATTEMPTS: usize = 3;

enum RangeClient {
    Blocking(Client),
    Cancellable {
        client: reqwest::Client,
        runtime: tokio::runtime::Runtime,
    },
}

pub struct RemoteFile {
    client: RangeClient,
    url: Url,
    size: u64,
    cursor: u64,
}

impl RemoteFile {
    pub fn open_pinned() -> Result<Self> {
        if crate::application::operation::is_active() {
            return Self::open_cancellable(Url::parse(RESTORE_URL)?);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context("create restore image HTTP client")?;
        Self::open(client, Url::parse(RESTORE_URL)?)
    }

    pub fn open(client: Client, url: Url) -> Result<Self> {
        let response = client
            .get(url.clone())
            .header(RANGE, "bytes=0-0")
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .context("open remote image")?;
        if response.status().as_u16() != 206 {
            bail!(
                "open remote image: server returned HTTP {} without byte-range support",
                response.status()
            );
        }
        let (start, end, size) = parse_content_range(
            response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|header| header.to_str().ok())
                .unwrap_or_default(),
        )?;
        if start != 0 || end != 0 {
            bail!("open remote image: server returned unexpected byte range {start}-{end}");
        }
        Ok(Self {
            client: RangeClient::Blocking(client),
            url,
            size,
            cursor: 0,
        })
    }

    /// First-time desktop preparation must not park its worker in a blocking
    /// 120-second HTTP read after the user asks to cancel or quit.
    fn open_cancellable(url: Url) -> Result<Self> {
        use crate::application::operation;
        operation::check()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(30))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .build()
            .context("create cancellable restore image HTTP client")?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let size = runtime.block_on(async {
            let response = operation::wait(
                client
                    .get(url.clone())
                    .header(RANGE, "bytes=0-0")
                    .header(ACCEPT_ENCODING, "identity")
                    .send(),
            )
            .await
            .context("open remote image")?;
            if response.status().as_u16() != 206 {
                bail!(
                    "open remote image: server returned HTTP {} without byte-range support",
                    response.status()
                );
            }
            let (start, end, size) = parse_content_range(
                response
                    .headers()
                    .get(CONTENT_RANGE)
                    .and_then(|header| header.to_str().ok())
                    .unwrap_or_default(),
            )?;
            if start != 0 || end != 0 {
                bail!("open remote image: server returned unexpected byte range {start}-{end}");
            }
            Ok(size)
        })?;
        Ok(Self {
            client: RangeClient::Cancellable { client, runtime },
            url,
            size,
            cursor: 0,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn read_at(&self, data: &mut [u8], offset: u64) -> Result<usize> {
        if data.is_empty() || offset >= self.size {
            return Ok(0);
        }
        let wanted = data
            .len()
            .min((self.size - offset).try_into().unwrap_or(usize::MAX));
        let client = match &self.client {
            RangeClient::Blocking(client) => client,
            RangeClient::Cancellable { client, runtime } => {
                return runtime.block_on(self.read_cancellable(
                    client,
                    &mut data[..wanted],
                    offset,
                ));
            }
        };
        let mut total = 0usize;
        let mut last_error = None;
        for _ in 0..READ_ATTEMPTS {
            if total == wanted {
                return Ok(total);
            }
            let start = offset + total as u64;
            let end = offset + wanted as u64 - 1;
            let mut response = match client
                .get(self.url.clone())
                .header(RANGE, format!("bytes={start}-{end}"))
                .header(ACCEPT_ENCODING, "identity")
                .send()
            {
                Ok(response) => response,
                Err(error) => {
                    last_error = Some(anyhow::Error::new(error));
                    continue;
                }
            };
            if response.status().as_u16() != 206 {
                bail!(
                    "read remote image range: server returned HTTP {}",
                    response.status()
                );
            }
            let (actual_start, actual_end, actual_size) = parse_content_range(
                response
                    .headers()
                    .get(CONTENT_RANGE)
                    .and_then(|header| header.to_str().ok())
                    .unwrap_or_default(),
            )?;
            if (actual_start, actual_end, actual_size) != (start, end, self.size) {
                bail!(
                    "read remote image range: server returned bytes {actual_start}-{actual_end}/{actual_size}, expected {start}-{end}/{}",
                    self.size
                );
            }
            while total < wanted {
                match response.read(&mut data[total..wanted]) {
                    Ok(0) => {
                        last_error = Some(anyhow::anyhow!("short remote image response"));
                        break;
                    }
                    Ok(count) => total += count,
                    Err(error) => {
                        last_error = Some(anyhow::Error::new(error));
                        break;
                    }
                }
            }
        }
        if total != wanted {
            return Err(
                last_error.unwrap_or_else(|| anyhow::anyhow!("short remote image response"))
            )
            .with_context(|| format!("read remote image at offset {}", offset + total as u64));
        }
        Ok(total)
    }

    async fn read_cancellable(
        &self,
        client: &reqwest::Client,
        data: &mut [u8],
        offset: u64,
    ) -> Result<usize> {
        use crate::application::operation;
        let mut total = 0;
        let mut last_error = None;
        for _ in 0..READ_ATTEMPTS {
            operation::check()?;
            if total == data.len() {
                return Ok(total);
            }
            let start = offset + total as u64;
            let end = offset + data.len() as u64 - 1;
            let response = operation::wait(
                client
                    .get(self.url.clone())
                    .header(RANGE, format!("bytes={start}-{end}"))
                    .header(ACCEPT_ENCODING, "identity")
                    .send(),
            )
            .await;
            let mut response = match response {
                Ok(response) => response,
                Err(error) if operation::is_cancellation(&error) => return Err(error),
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            if response.status().as_u16() != 206 {
                bail!(
                    "read remote image range: server returned HTTP {}",
                    response.status()
                );
            }
            let actual = parse_content_range(
                response
                    .headers()
                    .get(CONTENT_RANGE)
                    .and_then(|header| header.to_str().ok())
                    .unwrap_or_default(),
            )?;
            if actual != (start, end, self.size) {
                bail!(
                    "read remote image range: server returned bytes {}-{}/{}, expected {start}-{end}/{}",
                    actual.0,
                    actual.1,
                    actual.2,
                    self.size
                );
            }
            let transfer: Result<()> = async {
                while total < data.len() {
                    let Some(chunk) = operation::wait(response.chunk()).await? else {
                        bail!("short remote image response");
                    };
                    operation::check()?;
                    if chunk.len() > data.len() - total {
                        bail!("remote image response exceeds its requested range");
                    }
                    data[total..total + chunk.len()].copy_from_slice(&chunk);
                    total += chunk.len();
                }
                Ok(())
            }
            .await;
            match transfer {
                Ok(()) => return Ok(total),
                Err(error) if operation::is_cancellation(&error) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("short remote image response")))
            .with_context(|| format!("read remote image at offset {}", offset + total as u64))
    }
}

impl Read for RemoteFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self
            .read_at(buffer, self.cursor)
            .map_err(crate::application::operation::into_io_error)?;
        self.cursor += count as u64;
        Ok(count)
    }
}

impl Seek for RemoteFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(delta) => i128::from(self.cursor) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.size) + i128::from(delta),
        };
        self.cursor = u64::try_from(target).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid restore image seek")
        })?;
        Ok(self.cursor)
    }
}

pub fn parse_content_range(value: &str) -> Result<(u64, u64, u64)> {
    let (range, total) = value.split_once('/').context("invalid Content-Range")?;
    let size: u64 = total.parse().context("invalid Content-Range total")?;
    let span = range
        .strip_prefix("bytes ")
        .context("invalid Content-Range unit")?;
    let (first, last) = span.split_once('-').context("invalid Content-Range span")?;
    let start: u64 = first.parse().context("invalid Content-Range start")?;
    let end: u64 = last.parse().context("invalid Content-Range end")?;
    if size == 0 || end < start || end >= size {
        bail!("invalid Content-Range {value:?}");
    }
    Ok((start, end, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, thread};

    #[test]
    fn parses_complete_ranges_and_rejects_partial_ones() {
        assert_eq!(
            parse_content_range("bytes 0-0/26637307067").unwrap(),
            (0, 0, 26637307067)
        );
        assert_eq!(
            parse_content_range("bytes 100-199/1000").unwrap(),
            (100, 199, 1000)
        );
        for invalid in [
            "bytes 0-0/*",
            "bytes 0-0",
            "bytes 0-0/0",
            "items 0-0/1",
            "bytes 0-1/1",
            "bytes 2-1/3",
        ] {
            assert!(parse_content_range(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn retries_short_http_ranges_and_supports_seeking() {
        for cancellable in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                for (expected, body) in [
                    ("bytes=0-0", b"a".as_slice()),
                    ("bytes=2-5", b"cd".as_slice()),
                    ("bytes=4-5", b"ef".as_slice()),
                ] {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !request.ends_with(b"\r\n\r\n") {
                        let count = stream.read(&mut buffer).unwrap();
                        assert!(count > 0);
                        request.extend_from_slice(&buffer[..count]);
                    }
                    let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                    assert!(request.contains(&format!("range: {expected}\r\n")));
                    let range = expected.strip_prefix("bytes=").unwrap();
                    write!(stream, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {range}/8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(body).unwrap();
                }
            });
            let client = Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            let url = Url::parse(&format!("http://{address}/image")).unwrap();
            let mut remote = if cancellable {
                RemoteFile::open_cancellable(url).unwrap()
            } else {
                RemoteFile::open(client, url).unwrap()
            };
            assert_eq!(remote.size(), 8);
            assert_eq!(remote.seek(SeekFrom::Start(2)).unwrap(), 2);
            let mut data = [0u8; 4];
            remote.read_exact(&mut data).unwrap();
            assert_eq!(&data, b"cdef");
            assert_eq!(remote.seek(SeekFrom::End(-2)).unwrap(), 6);
            server.join().unwrap();
        }
    }

    #[test]
    fn preparation_cancel_interrupts_stalled_headers_and_body_with_typed_cancellation() {
        use crate::application::{
            failure::{Failure, FailureKind},
            operation::{self, Operation},
        };
        for stalled_body in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = Url::parse(&format!(
                "http://{}/restore",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let receive = || {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0];
                    while stream.read_exact(&mut byte).is_ok() {
                        request.push(byte[0]);
                        if request.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    stream
                };
                if stalled_body {
                    let mut probe = receive();
                    probe.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/8\r\nContent-Length: 1\r\nConnection: close\r\n\r\na").unwrap();
                }
                let mut stalled = receive();
                if stalled_body {
                    stalled.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/8\r\nContent-Length: 4\r\nConnection: close\r\n\r\nab").unwrap();
                }
                ready_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(5));
            });
            let operation = Operation::default();
            let cancellation = operation.clone();
            let cancel = thread::spawn(move || {
                ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                cancellation.cancel();
            });
            let started = std::time::Instant::now();
            let error = operation
                .run(|| {
                    let mut reader = RemoteFile::open_cancellable(url)?;
                    if stalled_body {
                        reader.read_exact(&mut [0; 4])?;
                    }
                    Ok(())
                })
                .unwrap_err();
            assert!(operation::is_cancellation(&error), "{error:#}");
            assert_eq!(Failure::from_error(&error).kind, FailureKind::Cancelled);
            assert!(started.elapsed() < Duration::from_secs(2));
            let _ = release_tx.send(());
            cancel.join().unwrap();
            server.join().unwrap();
        }
    }
}
