//! One small, durable write operation shared by package state and cache code.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::Result;

/// Replace `path` only after all bytes have reached disk.
///
/// The temporary file lives beside the destination, making `rename` atomic on
/// normal local filesystems. Syncing the parent directory makes that rename
/// durable across a power loss.
pub(crate) fn write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    fs::create_dir_all(parent)?;

    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("arc");
    let temporary = parent.join(format!(".{filename}.part-{}", std::process::id()));
    let _ = fs::remove_file(&temporary);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
