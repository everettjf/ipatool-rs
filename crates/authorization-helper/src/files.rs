use crate::{Problem, Snapshot};

pub(crate) fn local() -> Result<Snapshot, Problem> {
    #[cfg(target_os = "macos")]
    {
        let uid = unsafe { libc::geteuid() };
        if uid <= 500 {
            return Err(Problem::NotConsoleUser);
        }
        read_for_user(uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(Problem::Unsupported)
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn io(error: std::io::Error) -> Problem {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        Problem::PermissionDenied
    } else {
        Problem::InvalidState
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn read_for_user(uid: u32) -> Result<Snapshot, Problem> {
    use crate::{Source, StateFile};
    let mut files = Vec::new();
    for source in Source::ALL {
        match read_fixed(std::path::Path::new("/"), source.components(), uid) {
            Ok(Some(bytes)) => files.push(StateFile { source, bytes }),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    Snapshot::checked(files)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn read_fixed(
    root: &std::path::Path,
    components: &[&str],
    uid: u32,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, Problem> {
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };
    use zeroize::Zeroizing;
    if components.is_empty()
        || components.iter().any(|part| {
            part.is_empty() || part.contains(['/', '\\', '\0']) || matches!(*part, "." | "..")
        })
    {
        return Err(Problem::InvalidState);
    }
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(io)?;
    for (index, part) in components.iter().enumerate() {
        let directory = index + 1 != components.len();
        let name = CString::new(*part).map_err(|_| Problem::InvalidState)?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if directory {
                libc::O_DIRECTORY
            } else {
                libc::O_NONBLOCK
            };
        // SAFETY: parent remains live; the component contains no separators or NUL.
        let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(io(error));
        }
        // SAFETY: this call owns the fresh openat descriptor.
        let next = unsafe { File::from_raw_fd(raw) };
        let meta = next.metadata().map_err(io)?;
        if (directory && !meta.is_dir())
            || (!directory && !meta.is_file())
            || (meta.uid() > 500 && meta.uid() != uid)
            || (!directory && (meta.nlink() != 1 || meta.mode() & 0o002 != 0))
        {
            return Err(Problem::InvalidState);
        }
        parent = next;
    }
    let before = parent.metadata().map_err(io)?;
    if before.len() > crate::MAX_STATE_BYTES as u64 {
        return Err(Problem::InvalidState);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut parent)
        .take(crate::MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let after = parent.metadata().map_err(io)?;
    if before.len() != after.len()
        || bytes.len() as u64 != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(Problem::StateChanged);
    }
    if bytes.len() > crate::MAX_STATE_BYTES {
        return Err(Problem::InvalidState);
    }
    Ok(Some(bytes))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    #[test]
    fn bounded_reader_rejects_symlinks_hardlinks_nonfiles_and_unsafe_components() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("SC Info")).unwrap();
        let file = root.path().join("SC Info/SC Info.sidb");
        fs::write(&file, [0, 7, 0, 11]).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            read_fixed(root.path(), &["SC Info", "SC Info.sidb"], uid)
                .unwrap()
                .unwrap()
                .as_slice(),
            [0, 7, 0, 11]
        );
        symlink("SC Info", root.path().join("alias")).unwrap();
        assert!(read_fixed(root.path(), &["alias", "SC Info.sidb"], uid).is_err());
        fs::hard_link(&file, root.path().join("linked")).unwrap();
        assert!(read_fixed(root.path(), &["SC Info", "SC Info.sidb"], uid).is_err());
        fs::remove_file(root.path().join("linked")).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_fixed(root.path(), &["SC Info", "SC Info.sidb"], uid).is_err());
        assert!(read_fixed(root.path(), &["SC Info"], uid).is_err());
        for name in ["../SC Info.sidb", "..", "/etc/passwd", ""] {
            assert!(read_fixed(root.path(), &[name], uid).is_err());
        }
        assert!(
            read_fixed(root.path(), &["missing"], uid)
                .unwrap()
                .is_none()
        );
    }
}
