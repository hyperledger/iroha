//! Native journal steps over the original NTFS handle and retained private ancestors.
use super::*;
use crate::CustodyEntryKind;
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

fn validate_destination(directory: &Directory, name: &OsStr, mode: PublishMode) -> io::Result<()> {
    if mode == PublishMode::Replace {
        let destination = open_file(
            &directory.path().join(name),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            false,
            false,
        )?;
        journal_snapshot(&destination)?;
    }
    Ok(())
}
fn dispose(file: &File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the caller retains the admitted original no-reparse object with DELETE access.
    unsafe {
        win_ok(SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            from_ref(&disposition).cast(),
            native_size::<FILE_DISPOSITION_INFO>()?,
        ))
    }
}
fn after_removal(directory: &Directory) -> io::Result<()> {
    // An error after native disposition must remain indeterminate to the journal owner.
    directory.revalidate().map_err(|error| {
        io::Error::other(format!(
            "native removal completed; custody check failed: {error}"
        ))
    })
}

impl Directory {
    pub(crate) fn rename_custody_file(
        &self,
        from: &OsStr,
        to: &OsStr,
        expected: FileIdentity,
        mode: PublishMode,
    ) -> io::Result<()> {
        self.revalidate()?;
        let source = open_file(
            &self.path().join(from),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            false,
            false,
        )?;
        journal_snapshot(&source)?;
        if identity(&source)? != expected {
            return Err(changed());
        }
        validate_destination(self, to, mode)?;
        self.revalidate()?;
        rename_handle(&source, &self.path().join(to), mode)?;
        (|| {
            let named = open_file(
                &self.path().join(to),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                false,
                false,
            )?;
            if identity(&source)? != expected || journal_snapshot(&named)?.0.id != expected {
                return Err(changed());
            }
            self.revalidate()
        })()
        .map_err(|error| io::Error::other(format!("native rename completed: {error}")))
    }
    pub(crate) fn remove_custody_file(&self, name: &OsStr) -> io::Result<()> {
        self.revalidate()?;
        let source = open_file(
            &self.path().join(name),
            GENERIC_READ | DELETE,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            false,
            false,
        )?;
        journal_snapshot(&source)?;
        self.revalidate()?;
        dispose(&source)?;
        drop(source); // Complete deletion before the caller's separate parent-sync boundary.
        after_removal(self)
    }
    pub(crate) fn custody_entry_kind(&self, name: &OsStr) -> io::Result<CustodyEntryKind> {
        self.revalidate()?;
        let original = open_file(
            &self.path().join(name),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        let id = identity(&original)?;
        let basic: FILE_BASIC_INFO = info(&original, FileBasicInfo)?;
        let standard: FILE_STANDARD_INFO = info(&original, FileStandardInfo)?;
        let kind = if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            CustodyEntryKind::Other
        } else if standard.Directory {
            CustodyEntryKind::Directory
        } else {
            CustodyEntryKind::File
        };
        if identity(&original)? != id {
            return Err(changed());
        }
        self.revalidate()?;
        Ok(kind)
    }
    pub(crate) fn available_bytes(&self) -> io::Result<u64> {
        self.revalidate()?;
        let id = self.identity()?;
        let path = wide(self.path().as_os_str())?;
        let mut available = 0u64;
        // SAFETY: terminated local directory spelling is fenced by its original ancestors;
        // the exact u64 output is user-quota-aware, not protocol or monetary authority.
        unsafe {
            win_ok(GetDiskFreeSpaceExW(
                path.as_ptr(),
                &raw mut available,
                null_mut(),
                null_mut(),
            ))?;
        }
        self.revalidate()?;
        if self.identity()? != id {
            return Err(changed());
        }
        Ok(available)
    }
    pub(crate) fn sync_custody_file(&self, name: &OsStr) -> io::Result<()> {
        self.revalidate()?;
        let file = open_file(
            &self.path().join(name),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            false,
            false,
        )?;
        let before = journal_snapshot(&file)?.0;
        let retained = RetainedFile {
            directory: self.clone(),
            name: name.to_owned(),
            file,
            before,
            links: LinkPolicy::Single,
            private: true,
            writable: false,
            read_only: false,
            publishable: false,
        };
        retained.revalidate()?;
        retained.file.sync_all()?;
        retained.revalidate()
    }
    pub(crate) fn remove_custody_directory(
        &self,
        name: &OsStr,
        expected: FileIdentity,
    ) -> io::Result<()> {
        let child = self.child(name, false, false)?;
        if child.identity()? != expected {
            return Err(changed());
        }
        child.remove_custody_empty()
    }
    pub(crate) fn remove_custody_empty(mut self) -> io::Result<()> {
        self.revalidate()?;
        if self.links.len() < 2 {
            return Err(denied("filesystem root cannot be removed"));
        }
        if Arc::strong_count(self.links.last().ok_or_else(changed)?) != 1 {
            return Err(io::ErrorKind::ResourceBusy.into());
        }
        let current =
            Arc::try_unwrap(self.links.pop().ok_or_else(changed)?).map_err(|_| changed())?;
        let id = identity(&current.file)?;
        // Retain the original kernel object while transferring the non-delete-sharing pin.
        let retained = open_file(
            &current.path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&retained)? != id {
            return Err(changed());
        }
        let Link {
            path,
            file,
            private,
        } = current;
        drop(file);
        let removing = open_file(
            &path,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            true,
            false,
        )?;
        if identity(&removing)? != id {
            return Err(changed());
        }
        snapshot(&removing, private, true)?;
        self.revalidate()?;
        dispose(&removing)?;
        drop(removing);
        drop(retained);
        // Core owns the subsequent parent sync; never classify that error as NotRemoved.
        after_removal(&self)
    }
}
impl RetainedFile {
    pub(crate) fn rename_custody_file(
        &mut self,
        from: &OsStr,
        to: &OsStr,
        mode: PublishMode,
    ) -> io::Result<()> {
        if self.name.as_os_str() != from || !self.publishable || !self.writable || self.read_only {
            return Err(denied(
                "journal rename requires its live exclusive original writer",
            ));
        }
        self.revalidate()?;
        validate_destination(&self.directory, to, mode)?;
        self.directory.revalidate()?;
        rename_handle(&self.file, &self.directory.path().join(to), mode)?;
        // Advance original spelling immediately after the native transition, even if a
        // later check fails. Collision cleanup can then never delete the published target.
        self.name = to.to_owned();
        self.publishable = false;
        self.revalidate()
            .map_err(|error| io::Error::other(format!("native rename completed: {error}")))
    }
    pub(crate) fn remove_custody_file(self, name: &OsStr) -> io::Result<()> {
        if self.name.as_os_str() != name || !self.publishable || !self.writable || self.read_only {
            return Err(denied(
                "journal discard requires its unpublished original writer",
            ));
        }
        self.revalidate()?;
        let directory = self.directory.clone();
        dispose(&self.file)?;
        drop(self); // Close this sole owned writer before reporting removal completed.
        after_removal(&directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    fn root() -> (tempfile::TempDir, PrivateDirectory) {
        let temp = tempfile::tempdir().unwrap();
        let root = PrivateDirectory::open_or_create(temp.path().join("custody")).unwrap();
        (temp, root)
    }
    #[test]
    fn live_original_renames_without_a_second_delete_open() {
        let (_temp, root) = root();
        let mut stage = root.create_custody_writer("stage").unwrap();
        stage.file_mut().write_all(b"original").unwrap();
        stage.file().sync_all().unwrap();
        let identity = stage.identity().unwrap();
        assert!(
            std::fs::rename(root.path().join("stage"), root.path().join("substitute")).is_err()
        );
        stage
            .rename_custody_file("stage", "record", PublishMode::CreateNew)
            .unwrap();
        assert_eq!(stage.identity().unwrap(), identity);
        assert!(
            stage
                .rename_custody_file("record", "again", PublishMode::CreateNew)
                .is_err()
        );
        assert!(stage.remove_custody_file("stage").is_err());
        root.sync().unwrap();
        assert_eq!(root.read("record", 8).unwrap().as_slice(), b"original");
    }
    #[test]
    fn collision_discards_only_its_live_unpublished_original() {
        let (_temp, root) = root();
        root.write_atomic("record", b"committed", PublishMode::CreateNew)
            .unwrap();
        let mut stage = root.create_custody_writer("stage").unwrap();
        stage.file_mut().write_all(b"attempt").unwrap();
        stage.file().sync_all().unwrap();
        assert_eq!(
            stage
                .rename_custody_file("stage", "record", PublishMode::CreateNew)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        stage.remove_custody_file("stage").unwrap();
        root.sync().unwrap();
        assert_eq!(
            root.custody_entry_kind("stage").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(root.read("record", 9).unwrap().as_slice(), b"committed");
    }
    #[test]
    fn strict_named_sync_never_creates_or_admits_shared_or_immutable_originals() {
        let (_temp, root) = root();
        assert_eq!(
            root.sync_custody_file("missing").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(root.entries(16).unwrap().is_empty());
        root.write_atomic("journal", b"body", PublishMode::CreateNew)
            .unwrap();
        root.sync_custody_file("journal").unwrap();
        std::fs::hard_link(root.path().join("journal"), root.path().join("shared")).unwrap();
        assert!(root.sync_custody_file("journal").is_err());
        assert!(root.remove_custody_file("journal").is_err());
        let mut writer = root
            .create_borrowed_private(OsStr::new("immutable"), 16)
            .unwrap();
        writer.write_all(b"sealed").unwrap();
        let sealed = writer.seal_read_only().unwrap();
        assert!(root.sync_custody_file("immutable").is_err());
        sealed.revalidate().unwrap();
    }
    #[test]
    fn empty_child_consumes_its_original_and_refuses_live_descendants() {
        let (_temp, root) = root();
        let child = root.create_child("child").unwrap();
        let retained = child.retain().unwrap();
        assert_eq!(
            child.remove_custody_empty().unwrap_err().kind(),
            io::ErrorKind::ResourceBusy
        );
        retained.remove_custody_empty().unwrap();
        root.sync().unwrap();
        assert_eq!(
            root.custody_entry_kind("child").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(root.available_bytes().unwrap() > 0);
    }
    #[test]
    fn reparse_entries_are_classified_without_following_and_never_removed_as_files() {
        use std::os::windows::fs::symlink_file;
        let (_temp, root) = root();
        root.write_atomic("target", b"original", PublishMode::CreateNew)
            .unwrap();
        symlink_file("target", root.path().join("redirect"))
            .expect("native Windows qualification requires real symlink creation authority");
        assert_eq!(
            root.custody_entry_kind("redirect").unwrap(),
            CustodyEntryKind::Other
        );
        assert!(root.remove_custody_file("redirect").is_err());
        assert!(root.sync_custody_file("redirect").is_err());
        assert_eq!(root.read("target", 8).unwrap().as_slice(), b"original");
    }
}
