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

pub struct RemoteFile {
    client: Client,
    url: Url,
    size: u64,
    cursor: u64,
}

impl RemoteFile {
    pub fn open_pinned() -> Result<Self> {
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
            client,
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
        let mut total = 0usize;
        let mut last_error = None;
        for _ in 0..READ_ATTEMPTS {
            if total == wanted {
                return Ok(total);
            }
            let start = offset + total as u64;
            let end = offset + wanted as u64 - 1;
            let mut response = match self
                .client
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
}

impl Read for RemoteFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self
            .read_at(buffer, self.cursor)
            .map_err(io::Error::other)?;
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
        let mut remote = RemoteFile::open(client, url).unwrap();
        assert_eq!(remote.size(), 8);
        assert_eq!(remote.seek(SeekFrom::Start(2)).unwrap(), 2);
        let mut data = [0u8; 4];
        remote.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"cdef");
        assert_eq!(remote.seek(SeekFrom::End(-2)).unwrap(), 6);
        server.join().unwrap();
    }
}
