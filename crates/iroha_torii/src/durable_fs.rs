//! Small cross-platform primitives for crash-consistent Torii persistence.

use std::{fs, io, path::Path};

fn invalid_directory(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(unix)]
fn metadata_is_direct_directory(metadata: &fs::Metadata) -> bool {
    !metadata.file_type().is_symlink() && metadata.is_dir()
}

#[cfg(unix)]
fn metadata_identifies_same_directory(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata_is_direct_directory(left)
        && metadata_is_direct_directory(right)
        && left.dev() == right.dev()
        && left.ino() == right.ino()
}

/// Flush a direct directory and verify that its pathname continued to identify the opened handle.
///
/// This is the durability boundary for atomic rename and unlink operations. Unsupported targets
/// fail closed instead of claiming that a namespace mutation reached stable storage.
pub fn sync_direct_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        sync_unix_directory(path)
    }
    #[cfg(windows)]
    {
        return sync_windows_directory(path);
    }
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory synchronization is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn sync_unix_directory(path: &Path) -> io::Result<()> {
    let named_before = fs::symlink_metadata(path)?;
    if !metadata_is_direct_directory(&named_before) {
        return Err(invalid_directory(
            "durability path is not a direct directory",
        ));
    }

    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);

    let directory = options.open(path)?;
    let opened_before = directory.metadata()?;
    if !metadata_identifies_same_directory(&named_before, &opened_before) {
        return Err(invalid_directory(
            "durability directory changed while it was opened",
        ));
    }
    directory.sync_all()?;
    let opened_after = directory.metadata()?;
    let named_after = fs::symlink_metadata(path)?;
    if !metadata_identifies_same_directory(&opened_before, &opened_after)
        || !metadata_identifies_same_directory(&opened_after, &named_after)
    {
        return Err(invalid_directory(
            "durability directory changed while it was synchronized",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn sync_windows_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use crate::secure_file_metadata::{from_file, from_path, is_direct_directory, same_file};

    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let named_before = from_path(path)?;
    if !is_direct_directory(&named_before) {
        return Err(invalid_directory(
            "durability path is not a direct directory",
        ));
    }
    let mut options = fs::OpenOptions::new();
    // `File::sync_all` maps to `FlushFileBuffers`, which needs a write-capable handle.
    options
        .write(true)
        // Keep the directory namespace pinned while it is flushed. Other handles may still read
        // and write entries, but Windows must reject rename/delete attempts until this handle is
        // closed.
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    let directory = options.open(path)?;
    let opened_before = from_file(&directory)?;
    if !is_direct_directory(&opened_before) || !same_file(&named_before, &opened_before) {
        return Err(invalid_directory(
            "durability directory changed while it was opened",
        ));
    }
    directory.sync_all()?;
    let opened_after = from_file(&directory)?;
    let named_after = from_path(path)?;
    if !is_direct_directory(&opened_after)
        || !is_direct_directory(&named_after)
        || !same_file(&opened_before, &opened_after)
        || !same_file(&opened_after, &named_after)
    {
        return Err(invalid_directory(
            "durability directory changed while it was synchronized",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(unix, windows))]
    #[test]
    fn direct_directory_sync_rejects_regular_files() {
        let directory = tempfile::tempdir().expect("temporary durability directory");
        sync_direct_directory(directory.path()).expect("sync direct directory");

        let regular_file = directory.path().join("regular-file");
        fs::write(&regular_file, b"not a directory").expect("write regular file");
        assert!(sync_direct_directory(&regular_file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn direct_directory_sync_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().expect("temporary durability target");
        let holder = tempfile::tempdir().expect("temporary symlink holder");
        let link = holder.path().join("directory-link");
        symlink(target.path(), &link).expect("create directory symlink");

        assert!(sync_direct_directory(&link).is_err());
    }
}
