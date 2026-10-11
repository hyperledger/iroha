//! Protected read-only receipt ACLs and retained native no-replace publication.

use super::*;
use windows_sys::Win32::{
    Security::{
        Authorization::SetSecurityInfo, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::FILE_GENERIC_READ,
};

fn read_only_acl(file: &File) -> io::Result<bool> {
    let user = UserSid::current()?;
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: retained file handle and initialized output slots remain live.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let _allocation = LocalAllocation(descriptor);
    if !user.equals(owner) || dacl.is_null() {
        return Ok(false);
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: GetSecurityInfo supplied a complete descriptor and bounded ACL.
    unsafe {
        win_ok(GetSecurityDescriptorControl(
            descriptor,
            &raw mut control,
            &raw mut revision,
        ))?;
        if control & SE_DACL_PROTECTED == 0 || (*dacl).AceCount != 1 {
            return Ok(false);
        }
    }
    let mut ace = null_mut();
    // SAFETY: the sole ACE is retained inside the descriptor allocation.
    unsafe {
        win_ok(GetAce(dacl, 0, &raw mut ace))?;
    }
    // SAFETY: all valid ACEs begin with ACE_HEADER.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    if header.AceType != 0
        || header.AceFlags != 0
        || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Ok(false);
    }
    // SAFETY: checked the allowed-ACE type and minimum layout above.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    Ok(allowed.Mask == FILE_GENERIC_READ
        && user.equals(from_ref(&allowed.SidStart).cast_mut().cast()))
}

pub(super) fn validate_read_only(file: &File) -> io::Result<()> {
    if !read_only_acl(file)? {
        return Err(denied(
            "immutable private file requires protected owner-read-only DACL",
        ));
    }
    Ok(())
}

fn set_read_only_acl(file: &File) -> io::Result<()> {
    let user = UserSid::current()?;
    let mut sid_text = null_mut();
    // SAFETY: the current-user SID is valid and the output is owned until return.
    unsafe {
        win_ok(ConvertSidToStringSidW(user.pointer(), &raw mut sid_text))?;
    }
    let _sid_allocation = LocalAllocation(sid_text.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns a terminated UTF-16 allocation.
    unsafe {
        while *sid_text.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: measured initialized SID string excludes the terminator.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
        .map_err(|_| invalid("native SID text is invalid"))?;
    let sddl = wide(OsStr::new(&format!("O:{sid}D:P(A;;FR;;;{sid})")))?;
    let mut descriptor = null_mut();
    // SAFETY: terminated source remains live and output is one owned native allocation.
    unsafe {
        win_ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut descriptor,
            null_mut(),
        ))?;
    }
    let _allocation = LocalAllocation(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    // SAFETY: the complete descriptor is retained through the synchronous ACL update.
    unsafe {
        win_ok(GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        ))?;
        if present == 0 || dacl.is_null() {
            return Err(denied("missing immutable DACL"));
        }
        let status = SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status.cast_signed()));
        }
    }
    validate_read_only(file)
}

impl Directory {
    pub(crate) fn open_exact(path: &Path) -> io::Result<Self> {
        Self::open(path, false)
    }
    pub(crate) fn visit_private_files(
        &self,
        maximum: usize,
        mut visitor: impl FnMut(&OsStr, PrivateFileMetadata) -> io::Result<()>,
    ) -> io::Result<()> {
        self.revalidate()?;
        let before = snapshot(&self.current().file, self.current().private, true)?;
        let mut count = 0usize;
        for entry in std::fs::read_dir(self.path())? {
            let name = entry?.file_name();
            checked_name(&name)?;
            if count >= maximum {
                return Err(invalid("directory entry count exceeds the bound"));
            }
            count += 1;
            let file = open_file(
                &self.path().join(&name),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                false,
                false,
            )?;
            let value = snapshot(&file, true, false)?;
            let read_only = read_only_acl(&file)?;
            visitor(
                &name,
                PrivateFileMetadata {
                    length: value.length,
                    read_only,
                },
            )?;
        }
        if before != snapshot(&self.current().file, self.current().private, true)? {
            return Err(changed());
        }
        self.revalidate()
    }

    pub(crate) fn create_retained_private(&self, name: &OsStr) -> io::Result<RetainedFile> {
        self.open_retained(name, true, true)
    }

    pub(crate) fn open_retained_read_only(&self, name: &OsStr) -> io::Result<RetainedFile> {
        RetainedFile::open_read_only(self.clone(), name.to_owned())
    }

    pub(crate) fn open_retained_private_optional(
        &self,
        name: &OsStr,
    ) -> io::Result<Option<RetainedFile>> {
        // Preserve ordinary retained-private admission's exclusive sharing fence.
        let file = match open_file(
            &self.path().join(name),
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            false,
            false,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let before = snapshot(&file, true, false)?;
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
        Ok(Some(retained))
    }

    pub(crate) fn open_retained_read_only_optional(
        &self,
        name: &OsStr,
    ) -> io::Result<Option<RetainedFile>> {
        // Preserve retained-file sharing rights. Only this initial native open
        // establishes absence; snapshot, ACL and named revalidation never do.
        let file = match open_file(
            &self.path().join(name),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            false,
            false,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let before = snapshot(&file, true, false)?;
        validate_read_only(&file)?;
        let retained = RetainedFile {
            directory: self.clone(),
            name: name.to_owned(),
            file,
            before,
            links: LinkPolicy::Single,
            private: true,
            writable: false,
            read_only: true,
            publishable: false,
        };
        retained.revalidate()?;
        Ok(Some(retained))
    }

    pub(crate) fn create_borrowed_private<'a>(
        &'a self,
        name: &'a OsStr,
    ) -> io::Result<RetainedFile<&'a Self, &'a OsStr>> {
        RetainedFile::open(self, name, true, true)
    }

    pub(crate) fn open_borrowed_read_only<'a>(
        &'a self,
        name: &'a OsStr,
    ) -> io::Result<RetainedFile<&'a Self, &'a OsStr>> {
        RetainedFile::open_read_only(self, name)
    }
}

impl<D: Borrow<Directory>, N: AsRef<OsStr>> RetainedFile<D, N> {
    fn open_read_only(directory: D, name: N) -> io::Result<Self> {
        let parent = directory.borrow();
        parent.revalidate()?;
        // Metadata-frozen creator capabilities can still hold their original write/delete
        // rights. Admit a read-only handle without requiring those exact retained objects to
        // close; strict DACL and snapshot checks continue to govern every use.
        let file = open_file(
            &parent.path().join(name.as_ref()),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            false,
            false,
        )?;
        let before = snapshot(&file, true, false)?;
        validate_read_only(&file)?;
        let retained = Self {
            directory,
            name,
            file,
            before,
            links: LinkPolicy::Single,
            private: true,
            writable: false,
            read_only: true,
            publishable: false,
        };
        retained.revalidate()?;
        Ok(retained)
    }
    pub(crate) fn seal_read_only(mut self) -> io::Result<Self> {
        if !self.publishable || !self.writable {
            return Err(denied("only a newly created writer may be sealed"));
        }
        self.revalidate()?;
        self.file.sync_all()?;
        set_read_only_acl(&self.file)?;
        self.file.sync_all()?;
        self.before = snapshot(&self.file, true, false)?;
        self.writable = false;
        self.read_only = true;
        self.directory.borrow().sync()?;
        self.revalidate()?;
        Ok(self)
    }

    pub(crate) fn publish_with_name<M: AsRef<OsStr>>(
        self,
        name: M,
    ) -> io::Result<RetainedFile<D, M>> {
        if !self.publishable || self.writable || !self.read_only {
            return Err(denied(
                "publication requires a newly created strictly sealed file",
            ));
        }
        self.revalidate()?;
        let before = snapshot(&self.file, true, false)?;
        rename_handle(
            &self.file,
            &self.directory.borrow().path().join(name.as_ref()),
            PublishMode::CreateNew,
        )?;
        self.file.sync_all()?;
        let after = snapshot(&self.file, true, false)?;
        if before.id != after.id
            || before.length != after.length
            || before.modified != after.modified
            || before.attributes != after.attributes
        {
            return Err(changed());
        }
        let published = RetainedFile {
            directory: self.directory,
            name,
            file: self.file,
            before: after,
            links: LinkPolicy::Single,
            private: self.private,
            writable: self.writable,
            read_only: self.read_only,
            publishable: false,
        };
        published.directory.borrow().sync()?;
        published.revalidate()?;
        Ok(published)
    }
}

impl RetainedFile {
    pub(crate) fn publish_new_name(self, name: &OsStr) -> io::Result<Self> {
        self.publish_with_name(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_reopen_rejects_shared_links_even_with_an_exact_read_only_dacl() {
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            PrivateDirectory::open_or_create(temporary.path().join("receipts")).unwrap();
        let name = OsStr::new("receipt");
        let path = directory.path().join(name);
        // Build the hostile native fixture before applying the exact immutable ACL. This
        // does not use a retained receipt constructor or bypass any production validation.
        let mut file = open_file(
            &path,
            GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            CREATE_NEW,
            false,
            true,
        )
        .unwrap();
        file.write_all(b"original").unwrap();
        std::fs::hard_link(&path, directory.path().join("shared")).unwrap();
        set_read_only_acl(&file).unwrap();
        assert!(read_only_acl(&file).unwrap());
        drop(file);
        for name in [name, OsStr::new("shared")] {
            let error = directory.open_borrowed_read_only(name, 16).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("shared links"));
        }
    }

    #[test]
    fn borrowed_reopen_rejects_native_file_and_directory_reparse_points() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let temporary = tempfile::tempdir().unwrap();
        let directory =
            PrivateDirectory::open_or_create(temporary.path().join("receipts")).unwrap();
        let mut writer = directory
            .create_borrowed_private(OsStr::new("receipt"), 16)
            .unwrap();
        writer.write_all(b"original").unwrap();
        let sealed = writer.seal_read_only().unwrap();
        let before = sealed.snapshot().unwrap();
        // Native Windows qualification must provide symlink privilege or Developer Mode;
        // do not silently skip the reparse-point boundary when that fixture cannot be made.
        symlink_file("receipt", directory.path().join("redirect"))
            .expect("native Windows reparse fixture requires symlink creation authority");
        assert!(
            directory
                .open_borrowed_read_only(OsStr::new("redirect"), 16)
                .is_err()
        );
        assert!(
            directory
                .create_borrowed_private(OsStr::new("redirect"), 16)
                .is_err()
        );
        let alias = temporary.path().join("directory-redirect");
        symlink_dir(directory.path(), &alias)
            .expect("native Windows reparse fixture requires symlink creation authority");
        assert!(PrivateDirectory::open_exact(&alias).is_err());
        assert_eq!(sealed.snapshot().unwrap(), before);
        std::fs::remove_file(directory.path().join("redirect")).unwrap();
        std::fs::remove_dir(alias).unwrap();
    }
}
