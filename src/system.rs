//! Small Linux system-call wrappers used by transaction and archive handling.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Return the space available to an unprivileged writer at `path`.
pub(crate) fn available_space(path: &Path) -> io::Result<u64> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `statistics` points to writable memory.
    if unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `statvfs` call initializes the output structure.
    let statistics = unsafe { statistics.assume_init() };
    statistics
        .f_bavail
        .checked_mul(statistics.f_frsize)
        .ok_or_else(|| io::Error::other("available filesystem space overflows u64"))
}

/// Take an advisory, blocking exclusive lock on a file.
pub(crate) fn lock_exclusive(file: &File) -> io::Result<()> {
    // SAFETY: the file descriptor remains valid for this call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Release an advisory lock. Failure is intentionally handled by the caller.
pub(crate) fn unlock(file: &File) -> io::Result<()> {
    // SAFETY: the file descriptor remains valid for this call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
