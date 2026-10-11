//! Native retained-custody steps for callers with an explicit multi-step journal.

use super::*;

/// Direct child kind observed without following symbolic links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyEntryKind {
    /// Regular file; content admission separately checks private ownership and link count.
    File,
    /// Directory; opening it separately checks private ownership and retained identity.
    Directory,
    /// A symlink or another non-regular object, never followed.
    Other,
}
impl PrivateDirectory {
    /// Create an exclusive private writer relative to retained directory custody.
    /// The caller owns write/sync/publication ordering and retains this file until publication.
    ///
    /// # Errors
    /// Existing names, unsafe custody, or a genuine native creation error.
    pub fn create_custody_writer(&self, name: impl AsRef<OsStr>) -> io::Result<RetainedFile> {
        Ok(RetainedFile {
            inner: self
                .inner
                .open_retained(checked_name(name.as_ref())?, true, true)?,
        })
    }
    /// Rename one private file only while its current name identifies `expected`.
    /// Source and destination are relative to this same retained directory. No weaker
    /// create-new fallback exists on unsupported Unix platforms. The caller syncs the directory.
    ///
    /// # Errors
    /// Changed original, unsafe or existing destination, unsupported operation, or native error.
    pub fn rename_custody_file(
        &self,
        from: impl AsRef<OsStr>,
        to: impl AsRef<OsStr>,
        expected: FileIdentity,
        mode: PublishMode,
    ) -> io::Result<()> {
        self.inner.rename_custody_file(
            checked_name(from.as_ref())?,
            checked_name(to.as_ref())?,
            expected,
            mode,
        )
    }
    /// Remove a private single-link regular file through retained directory custody.
    /// The caller owns the subsequent directory sync boundary.
    ///
    /// # Errors
    /// Missing or unsafe files, changed ancestry, or native removal failure.
    pub fn remove_custody_file(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
        self.inner.remove_custody_file(checked_name(name.as_ref())?)
    }
    /// Observe one direct entry without following a symbolic link.
    ///
    /// # Errors
    /// Missing entry, changed directory ancestry, invalid name, or genuine native error.
    pub fn custody_entry_kind(&self, name: impl AsRef<OsStr>) -> io::Result<CustodyEntryKind> {
        self.inner.custody_entry_kind(checked_name(name.as_ref())?)
    }
    /// Available bytes on the filesystem held by this retained directory.
    ///
    /// # Errors
    /// Changed custody, native filesystem-query error, or arithmetic overflow.
    pub fn available_bytes(&self) -> io::Result<u64> {
        self.inner.available_bytes()
    }
}

impl PrivateDirectory {
    /// Remove exactly the empty child directory with the supplied retained kernel identity.
    /// The caller discards child capabilities after success and owns the parent sync boundary.
    ///
    /// # Errors
    /// Missing, nonempty, replaced or unsafe child, changed ancestry, or native removal failure.
    pub fn remove_custody_directory(
        &self,
        name: impl AsRef<OsStr>,
        expected: FileIdentity,
    ) -> io::Result<()> {
        self.inner
            .remove_custody_directory(checked_name(name.as_ref())?, expected)
    }
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;
    use std::io::Write as _;
    #[test]
    fn staged_publication_removal_and_space_preserve_descriptor_identity() {
        let temporary = tempfile::tempdir().expect("temporary");
        let root = PrivateDirectory::open_or_create(temporary.path().join("custody"))
            .expect("private root");
        assert!(root.available_bytes().expect("space") > 0);
        let mut staged = root
            .create_custody_writer("staged")
            .expect("exclusive stage");
        staged.file_mut().write_all(b"exact body").expect("write");
        staged.file().sync_all().expect("sync");
        let identity = staged.identity().expect("identity");
        assert!(root.create_custody_writer("staged").is_err());
        root.rename_custody_file("staged", "record", identity, PublishMode::CreateNew)
            .expect("publish");
        root.sync().expect("sync parent");
        assert_eq!(
            root.custody_entry_kind("record").expect("kind"),
            CustodyEntryKind::File
        );
        assert_eq!(
            root.read("record", 32).expect("read").as_slice(),
            b"exact body"
        );
        let next = root.create_custody_writer("next").expect("next");
        assert!(
            root.rename_custody_file("next", "record", identity, PublishMode::Replace)
                .is_err()
        );
        root.rename_custody_file(
            "next",
            "record",
            next.identity().expect("identity"),
            PublishMode::Replace,
        )
        .expect("exact replacement");
        root.remove_custody_file("record").expect("remove");
        assert_eq!(
            root.custody_entry_kind("record")
                .expect_err("absent")
                .kind(),
            io::ErrorKind::NotFound
        );
        let child = root.create_child("child").expect("child");
        assert_eq!(
            root.custody_entry_kind("child").expect("directory"),
            CustodyEntryKind::Directory
        );
        root.remove_custody_directory("child", child.identity().expect("child identity"))
            .expect("remove child");
        std::os::unix::fs::symlink("missing", root.path().join("link")).expect("link");
        assert_eq!(
            root.custody_entry_kind("link").expect("link kind"),
            CustodyEntryKind::Other
        );
        assert!(root.remove_custody_file("link").is_err());
        assert!(
            root.rename_custody_file("link", "other", identity, PublishMode::CreateNew)
                .is_err()
        );
    }
}

impl PrivateDirectory {
    /// Sync one existing private journal through its original native file owner.
    /// This never creates a missing name; native access and private custody are required.
    /// # Errors
    /// Refuses missing, shared or changed originals, insufficient native sync rights and failures.
    pub fn sync_custody_file(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
        self.inner.sync_custody_file(checked_name(name.as_ref())?)
    }
    /// Consume this original empty journal directory, without the caller's parent sync.
    /// # Errors
    /// Refuses live descendants, nonempty or replaced originals and native deletion errors.
    #[cfg(windows)]
    pub fn remove_custody_empty(self) -> io::Result<()> {
        self.inner.remove_custody_empty()
    }
}
impl RetainedFile {
    /// Publish this live exclusively created journal writer under one same-parent name.
    /// The original descriptor stays live and its name advances at the native transition.
    /// No second publication or published-target discard authority remains after rename.
    /// # Errors
    /// Refuses changed names, unsafe destination, duplicate publication and native errors.
    /// An error after native rename is indeterminate and requires reconciliation.
    pub fn rename_custody_file(
        &mut self,
        from: impl AsRef<OsStr>,
        to: impl AsRef<OsStr>,
        mode: PublishMode,
    ) -> io::Result<()> {
        self.inner.rename_custody_file(
            checked_name(from.as_ref())?,
            checked_name(to.as_ref())?,
            mode,
        )
    }
    /// Consume an unpublished original writer to remove its exact selected staged name.
    /// The native handle closes before success; this never discards a published destination.
    /// # Errors
    /// Refuses another name, published/sealed/read-only originals and native removal failure.
    pub fn remove_custody_file(self, name: impl AsRef<OsStr>) -> io::Result<()> {
        self.inner.remove_custody_file(checked_name(name.as_ref())?)
    }
}
