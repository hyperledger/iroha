//! Direct, identity-bound directory handles for durable query journal publication.

use crate::secure_file_metadata::{self, SecureMetadata};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Resolve the directory of a journal, including a bare relative filename.
pub(super) fn journal_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
type DirectoryIdentity = (u64, u64);
#[cfg(windows)]
type DirectoryIdentity = (u32, u64);
#[cfg(not(any(unix, windows)))]
type DirectoryIdentity = ();

fn directory_identity(metadata: &SecureMetadata) -> io::Result<DirectoryIdentity> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_directory());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid_directory());
        }
        match (metadata.volume_serial_number(), metadata.file_index()) {
            (Some(volume), Some(index)) => Ok((volume, index)),
            _ => Err(invalid_directory()),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "query journal directory identity is unavailable on this platform",
        ))
    }
}

fn invalid_directory() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "query journal parent must remain the same direct directory",
    )
}

/// Retain the opened directory and its exact identity through the durability check.
pub(super) struct JournalParent {
    path: PathBuf,
    file: fs::File,
    identity: DirectoryIdentity,
}

impl JournalParent {
    fn verify(&self) -> io::Result<()> {
        let named = directory_identity(&secure_file_metadata::from_path(&self.path)?)?;
        let opened = directory_identity(&secure_file_metadata::from_file(&self.file)?)?;
        if named != self.identity || opened != self.identity {
            return Err(invalid_directory());
        }
        Ok(())
    }

    /// Flush the retained directory, rejecting replacement before or after sync.
    pub(super) fn sync_all(&self) -> io::Result<()> {
        self.verify()?;
        self.file.sync_all()?;
        self.verify()
    }
}

/// Open the actual parent with platform directory semantics and verified identity.
pub(super) fn open_journal_parent(path: &Path) -> io::Result<JournalParent> {
    open_directory_after_admission(journal_parent(path), || {})
}

fn open_directory_after_admission(
    path: &Path,
    after_admission: impl FnOnce(),
) -> io::Result<JournalParent> {
    let identity = directory_identity(&secure_file_metadata::from_path(path)?)?;
    after_admission();
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let flags = rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC;
        options.custom_flags(flags.bits().cast_signed());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        // FlushFileBuffers requires write access; a read-only directory handle is insufficient.
        options
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let directory = JournalParent {
        path: path.to_path_buf(),
        file: options.open(path)?,
        identity,
    };
    directory.verify()?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_parent_normalizes_relative_names_and_flushes_real_directories() {
        assert_eq!(journal_parent(Path::new("marker.norito")), Path::new("."));
        assert_eq!(
            journal_parent(Path::new("sub/marker.norito")),
            Path::new("sub")
        );
        let current = open_journal_parent(Path::new("marker.norito")).unwrap();
        current.sync_all().unwrap();
        assert_eq!(
            current.identity,
            directory_identity(&secure_file_metadata::from_path(Path::new(".")).unwrap()).unwrap()
        );
        let directory = tempfile::tempdir().unwrap();
        let opened = open_journal_parent(&directory.path().join("marker.norito")).unwrap();
        opened.sync_all().unwrap();
        assert_eq!(opened.path, directory.path());
    }

    #[test]
    fn journal_parent_rejects_non_directory_and_admission_replacement() {
        let root = tempfile::tempdir().unwrap();
        let regular = root.path().join("regular");
        fs::write(&regular, b"not a directory").unwrap();
        assert!(open_journal_parent(&regular.join("marker.norito")).is_err());
        let parent = root.path().join("parent");
        let old = root.path().join("old");
        fs::create_dir(&parent).unwrap();
        let result = open_directory_after_admission(&parent, || {
            fs::rename(&parent, &old).unwrap();
            fs::create_dir(&parent).unwrap();
        });
        assert!(result.is_err());
    }

    #[test]
    fn journal_parent_rejects_replacement_before_directory_sync() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let opened = open_journal_parent(&parent.join("marker.norito")).unwrap();
        opened.sync_all().unwrap();
        fs::rename(&parent, root.path().join("old")).unwrap();
        fs::create_dir(&parent).unwrap();
        assert!(opened.sync_all().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_parent_rejects_symlink_directories_and_retains_nonblocking_descriptor() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let direct = root.path().join("direct");
        fs::create_dir(&direct).unwrap();
        let link = root.path().join("link");
        symlink(&direct, &link).unwrap();
        assert!(open_journal_parent(&link.join("marker.norito")).is_err());
        let opened = open_journal_parent(&direct.join("marker.norito")).unwrap();
        let flags = rustix::fs::fcntl_getfl(&opened.file).unwrap();
        assert!(flags.contains(rustix::fs::OFlags::NONBLOCK));
        assert!(
            rustix::io::fcntl_getfd(&opened.file)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        opened.sync_all().unwrap();
    }
}
