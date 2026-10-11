//! Multi-step journal publication primitives retaining exact directory and source identities.

use super::*;
use crate::CustodyEntryKind;

impl Directory {
    pub(crate) fn rename_custody_file(
        &self,
        from: &OsStr,
        to: &OsStr,
        expected: FileIdentity,
        mode: PublishMode,
    ) -> io::Result<()> {
        self.revalidate()?;
        let source = self.open_read(from)?;
        validate_file(&source, true)?;
        if identity(&source)? != expected {
            return Err(changed());
        }
        if mode == PublishMode::Replace {
            // Replacement requires an existing private destination. Journal owners choose
            // create-new explicitly when no destination has been established.
            let destination = self.open_read(to)?;
            validate_file(&destination, true)?;
        }
        self.revalidate()?;
        match mode {
            PublishMode::CreateNew => {
                #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
                rustix::fs::renameat_with(
                    &self.current().file,
                    from,
                    &self.current().file,
                    to,
                    rustix::fs::RenameFlags::NOREPLACE,
                )?;
                #[cfg(not(any(
                    target_vendor = "apple",
                    target_os = "linux",
                    target_os = "android"
                )))]
                return Err(io::ErrorKind::Unsupported.into());
            }
            PublishMode::Replace => {
                rustix::fs::renameat(&self.current().file, from, &self.current().file, to)?
            }
        }
        let published = self.open_read(to)?;
        validate_file(&published, true)?;
        if identity(&published)? != expected {
            return Err(changed());
        }
        self.revalidate()
    }
    pub(crate) fn remove_custody_file(&self, name: &OsStr) -> io::Result<()> {
        self.revalidate()?;
        let original = self.open_read(name)?;
        validate_file(&original, true)?;
        let named = self.open_read(name)?;
        if identity(&original)? != identity(&named)? {
            return Err(changed());
        }
        rustix::fs::unlinkat(&self.current().file, name, AtFlags::empty())?;
        self.revalidate()
    }
    pub(crate) fn custody_entry_kind(&self, name: &OsStr) -> io::Result<CustodyEntryKind> {
        self.revalidate()?;
        let metadata = rustix::fs::statat(&self.current().file, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = match FileType::from_raw_mode(metadata.st_mode) {
            FileType::RegularFile => CustodyEntryKind::File,
            FileType::Directory => CustodyEntryKind::Directory,
            _ => CustodyEntryKind::Other,
        };
        self.revalidate()?;
        Ok(kind)
    }
    pub(crate) fn available_bytes(&self) -> io::Result<u64> {
        self.revalidate()?;
        let stat = rustix::fs::fstatvfs(&self.current().file)?;
        let overflow = || invalid("filesystem available-byte count overflow");
        let available = stat
            .f_bavail
            .checked_mul(stat.f_frsize)
            .ok_or_else(overflow)?;
        self.revalidate()?;
        Ok(available)
    }
}

impl Directory {
    pub(crate) fn remove_custody_directory(
        &self,
        name: &OsStr,
        expected: FileIdentity,
    ) -> io::Result<()> {
        self.revalidate()?;
        let child = self.child(name, false, false)?;
        if child.identity()? != expected {
            return Err(changed());
        }
        rustix::fs::unlinkat(&self.current().file, name, AtFlags::REMOVEDIR)?;
        self.revalidate()
    }
}

impl Directory {
    pub(crate) fn sync_custody_file(&self, name: &OsStr) -> io::Result<()> {
        let original = self.open_retained(name, true, false)?;
        original.revalidate()?;
        original.file().sync_all()?;
        original.revalidate()
    }
}
impl RetainedFile {
    pub(crate) fn rename_custody_file(
        &mut self,
        from: &OsStr,
        to: &OsStr,
        mode: PublishMode,
    ) -> io::Result<()> {
        if self.name.as_os_str() != from
            || self.publication != PublicationAuthority::ExclusiveCreation
            || !self.writable
            || self.read_only
        {
            return Err(denied(
                "journal rename requires its live exclusive original writer",
            ));
        }
        self.revalidate()?;
        if mode == PublishMode::Replace {
            let destination = self.directory.open_read(to)?;
            validate_file(&destination, true)?;
        }
        self.directory.revalidate()?;
        match mode {
            PublishMode::CreateNew => {
                #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
                rustix::fs::renameat_with(
                    &self.directory.current().file,
                    from,
                    &self.directory.current().file,
                    to,
                    rustix::fs::RenameFlags::NOREPLACE,
                )?;
                #[cfg(not(any(
                    target_vendor = "apple",
                    target_os = "linux",
                    target_os = "android"
                )))]
                return Err(io::ErrorKind::Unsupported.into());
            }
            PublishMode::Replace => rustix::fs::renameat(
                &self.directory.current().file,
                from,
                &self.directory.current().file,
                to,
            )?,
        }
        to.clone_into(&mut self.name);
        self.publication = PublicationAuthority::None;
        self.revalidate()
            .map_err(|error| io::Error::other(format!("native rename completed: {error}")))
    }
    pub(crate) fn remove_custody_file(self, name: &OsStr) -> io::Result<()> {
        if self.name.as_os_str() != name
            || self.publication != PublicationAuthority::ExclusiveCreation
            || !self.writable
            || self.read_only
        {
            return Err(denied(
                "journal discard requires its unpublished original writer",
            ));
        }
        self.revalidate()?;
        rustix::fs::unlinkat(&self.directory.current().file, name, AtFlags::empty())?;
        self.directory.revalidate().map_err(|error| {
            io::Error::other(format!(
                "native removal completed; custody check failed: {error}"
            ))
        })
    }
}
