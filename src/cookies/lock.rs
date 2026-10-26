//! Lock the cookie file using the same lock file protocol as Go on supported hosts.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

static HELD: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

pub(super) struct CookieFileLock {
    path: PathBuf,
    file: Option<File>,
}

impl CookieFileLock {
    pub(super) fn acquire(cookie_path: &Path) -> Result<Self> {
        let path = cookie_path.with_file_name(format!(
            "{}.lock",
            cookie_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));
        {
            let mut held = HELD
                .lock()
                .map_err(|_| anyhow::anyhow!("cookie lock is poisoned"))?;
            if !held.insert(path.clone()) {
                bail!("cookie jar is already locked by this process");
            }
        }
        let result = Self::acquire_inner(path.clone());
        if result.is_err()
            && let Ok(mut held) = HELD.lock()
        {
            held.remove(&path);
        }
        result
    }

    fn acquire_inner(path: PathBuf) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let attempt = if uses_fcntl() {
                acquire_fcntl(&path)
            } else {
                acquire_portable(&path)
            };
            match attempt {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        || error.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if Instant::now() >= deadline {
                        return Err(error).context("cookie file remained locked for three seconds");
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error).context("failed to acquire cookie file lock"),
            }
        }
    }
}

impl Drop for CookieFileLock {
    fn drop(&mut self) {
        // The Go lock package unlinks before closing its fcntl lock.
        let _ = fs::remove_file(&self.path);
        self.file.take();
        if let Ok(mut held) = HELD.lock() {
            held.remove(&self.path);
        }
    }
}

const fn uses_fcntl() -> bool {
    cfg!(all(target_os = "macos", target_arch = "x86_64"))
        || cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "arm")
        ))
        || cfg!(target_os = "freebsd")
}

fn acquire_portable(path: &Path) -> std::io::Result<File> {
    match fs::read(path) {
        Ok(data) if !data.is_empty() => {
            let owner = serde_json::from_slice::<serde_json::Value>(&data)
                .ok()
                .and_then(|value| value.get("OwnerPID")?.as_i64());
            match owner {
                Some(pid) if pid > 0 && !process_alive(pid) => {
                    fs::remove_file(path)?;
                }
                Some(pid) if pid > 0 => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "cookie file locked by another process",
                    ));
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid cookie lock file",
                    ));
                }
            }
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "cookie file lock exists",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = writeln!(file, "{{\"OwnerPID\":{}}}", std::process::id()) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

#[cfg(unix)]
fn process_alive(pid: i64) -> bool {
    if pid > i32::MAX as i64 {
        return true;
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn process_alive(_pid: i64) -> bool {
    true
}

#[cfg(unix)]
fn acquire_fcntl(path: &Path) -> std::io::Result<File> {
    use std::os::fd::AsRawFd;
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid nonempty cookie lock file",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EACCES)) {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, error));
        }
        return Err(error);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn acquire_fcntl(_path: &Path) -> std::io::Result<File> {
    unreachable!("fcntl is not used on this platform")
}
