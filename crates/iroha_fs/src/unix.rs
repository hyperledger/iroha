//! Descriptor-relative Unix custody and atomic publication.

#[path = "unix/custody_io.rs"]
mod custody_io;

use super::*;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use std::{
    borrow::Borrow,
    fs,
    io::Write as _,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    sync::Arc,
};

#[cfg(target_vendor = "apple")]
#[path = "apple_acl.rs"]
mod apple_acl;
#[cfg(target_vendor = "apple")]
#[path = "apple_inventory.rs"]
mod apple_inventory;

#[cfg(any(target_os = "android", test))]
#[path = "unix/android_ancestry.rs"]
mod android_ancestry;
#[cfg(all(target_os = "android", test))]
#[path = "unix/android_ancestry_syscall_tests.rs"]
mod android_ancestry_syscall_tests;

/// Ancestors need search permission on Android; the actual selected directory stays readable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryAccess {
    Read,
    #[cfg(target_os = "android")]
    Search,
}
impl DirectoryAccess {
    fn for_component(last: bool) -> Self {
        #[cfg(target_os = "android")]
        if !last {
            return Self::Search;
        }
        #[cfg(not(target_os = "android"))]
        let _ = last;
        Self::Read
    }
    fn flags(self) -> OFlags {
        let access = match self {
            Self::Read => OFlags::RDONLY,
            #[cfg(target_os = "android")]
            Self::Search => OFlags::PATH,
        };
        access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
}

#[derive(Debug)]
struct Link {
    path: PathBuf,
    file: File,
    private: bool,
    // Preserve this access across native namespace revalidation, including shared ancestors.
    access: DirectoryAccess,
}
impl Link {
    fn sync(&self) -> io::Result<()> {
        match self.access {
            DirectoryAccess::Read => self.file.sync_all(),
            #[cfg(target_os = "android")]
            DirectoryAccess::Search => {
                // O_PATH cannot fsync. Reopen this held directory itself, requiring actual
                // kernel read permission, and retain the same native identity/policy.
                let readable = File::from(rustix::fs::openat(
                    &self.file,
                    ".",
                    DirectoryAccess::Read.flags(),
                    Mode::empty(),
                )?);
                if validate_directory(&readable, self.private)?
                    != validate_directory(&self.file, self.private)?
                {
                    return Err(changed());
                }
                readable.sync_all()
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Directory {
    links: Vec<Arc<Link>>,
}

#[cfg(test)]
type NamedOpenHook = (&'static str, Box<dyn FnOnce()>);

#[cfg(test)]
std::thread_local! {
    static READONLY_NAMED_HOOK: std::cell::RefCell<Option<NamedOpenHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn before_readonly_named_open(name: &OsStr) {
    let hook = READONLY_NAMED_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(selected, _)| name == OsStr::new(selected))
        {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Run one named readonly-open race hook, clearing it on return or unwind.
#[cfg(test)]
pub fn with_readonly_named_hook<T>(
    name: &'static str,
    hook: impl FnOnce() + 'static,
    read: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            READONLY_NAMED_HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    READONLY_NAMED_HOOK.with(|slot| {
        assert!(slot.borrow().is_none(), "readonly hook must not overlap");
        *slot.borrow_mut() = Some((name, Box::new(hook)));
    });
    let _reset = Reset;
    read()
}

#[cfg(test)]
std::thread_local! {
    static CHILD_NAMED_HOOK: std::cell::RefCell<Option<NamedOpenHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn before_child_named_validation(name: &OsStr) {
    let hook = CHILD_NAMED_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(selected, _)| name == OsStr::new(selected))
        {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

/// Run one named child-validation race hook, clearing it on return or unwind.
#[cfg(test)]
pub fn with_child_named_hook<T>(
    name: &'static str,
    hook: impl FnOnce() + 'static,
    open: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CHILD_NAMED_HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    CHILD_NAMED_HOOK.with(|slot| {
        assert!(slot.borrow().is_none(), "child hook must not overlap");
        *slot.borrow_mut() = Some((name, Box::new(hook)));
    });
    let _reset = Reset;
    open()
}

fn open_directory(path: &Path, access: DirectoryAccess) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        path,
        access.flags(),
        Mode::empty(),
    )?))
}

fn validate_directory(file: &File, private: bool) -> io::Result<FileIdentity> {
    let metadata = file.metadata()?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_dir() {
        return Err(denied("directory handle does not name a directory"));
    }
    #[cfg(target_os = "android")]
    android_ancestry::validate_permissions(
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        uid,
        private,
    )?;
    #[cfg(not(target_os = "android"))]
    {
        if private {
            if metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
                return Err(denied(
                    "private directory requires current ownership and mode 0700",
                ));
            }
        } else if !matches!(metadata.uid(), 0) && metadata.uid() != uid {
            return Err(denied("directory ancestor has foreign ownership"));
        } else if metadata.mode() & 0o022 != 0
            && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
        {
            return Err(denied("directory ancestor is writable by other users"));
        }
    }
    #[cfg(target_vendor = "apple")]
    apple_acl::validate(file, private)?;
    // This fresh metadata identifies the live, privately held descriptor. Its
    // device/inode pair cannot change during this borrow; custody is still
    // checked independently for the held and freshly opened named handles.
    let mut object = [0; 16];
    object[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(FileIdentity {
        volume: metadata.dev(),
        object,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkPolicy {
    Single,
    BuildInput,
}

fn validate_file(file: &File, private: bool) -> io::Result<fs::Metadata> {
    validate_file_links(file, private, LinkPolicy::Single)
}

fn validate_file_links(file: &File, private: bool, links: LinkPolicy) -> io::Result<fs::Metadata> {
    let metadata = file.metadata()?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || metadata.nlink() == 0
        || (links == LinkPolicy::Single && metadata.nlink() != 1)
    {
        return Err(denied("file must be regular with exactly one link"));
    }
    if private {
        if metadata.uid() != uid || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600) {
            return Err(denied(
                "private file requires current ownership and mode 0400 or 0600",
            ));
        }
    } else if (metadata.uid() != uid && metadata.uid() != 0) || metadata.mode() & 0o7022 != 0 {
        return Err(denied(
            "regular source has unsafe ownership or write permissions",
        ));
    }
    #[cfg(target_vendor = "apple")]
    apple_acl::validate(file, private)?;
    Ok(metadata)
}

pub fn identity(file: &File) -> io::Result<FileIdentity> {
    let metadata = file.metadata()?;
    let mut object = [0; 16];
    object[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(FileIdentity {
        volume: metadata.dev(),
        object,
    })
}

fn unchanged(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[path = "unix/private_files.rs"]
mod private_files;

impl Directory {
    pub(super) fn open(path: &Path, create: bool) -> io::Result<Self> {
        Self::open_with_policy(path, create, true, 0, true)
    }

    pub(super) fn open_owned(path: &Path, create: bool) -> io::Result<Self> {
        let mut directory = Self::open_with_policy(path, create, false, 0, true)?;
        if directory.current().file.metadata()?.uid() != rustix::process::geteuid().as_raw() {
            return Err(denied("writable directory requires current ownership"));
        }
        let current = directory.links.pop().ok_or_else(changed)?;
        let mut current = Arc::try_unwrap(current).map_err(|_| changed())?;
        current.private = false;
        directory.links.push(Arc::new(current));
        Ok(directory)
    }

    pub(super) fn open_reader(path: &Path) -> io::Result<Self> {
        Self::open_with_policy(path, false, false, 0, true)
    }

    pub(super) fn identity(&self) -> io::Result<FileIdentity> {
        identity(&self.current().file)
    }

    pub(super) fn entries(&self, maximum: usize) -> io::Result<Vec<std::ffi::OsString>> {
        self.revalidate()?;
        self.entries_native(maximum, |mut names| {
            self.revalidate()?;
            names.sort();
            Ok(names)
        })
    }

    // Consume the original census while its directory metadata and native owner remain live.
    pub(super) fn entries_native<T>(
        &self,
        maximum: usize,
        consume: impl FnOnce(Vec<std::ffi::OsString>) -> io::Result<T>,
    ) -> io::Result<T> {
        let before = self.current().file.metadata()?;
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(&self.current().file)? {
            let entry = entry?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            checked_name(name)?;
            if names.len() >= maximum {
                return Err(invalid("directory entry count exceeds the bound"));
            }
            names.push(name.to_owned());
        }
        if !unchanged(&before, &self.current().file.metadata()?) {
            return Err(changed());
        }
        consume(names)
    }

    fn open_with_policy(
        path: &Path,
        create: bool,
        private: bool,
        redirects: u8,
        allow_system_aliases: bool,
    ) -> io::Result<Self> {
        if redirects > 8 {
            return Err(denied("too many operating-system directory links"));
        }
        let parts: Vec<_> = path.components().collect();
        if !matches!(parts.first(), Some(Component::RootDir)) {
            return Err(invalid("absolute native path required"));
        }
        let root_access = DirectoryAccess::for_component(parts.len() == 1);
        let root = open_directory(Path::new("/"), root_access)?;
        validate_directory(&root, parts.len() == 1 && private)?;
        let mut links = vec![Arc::new(Link {
            path: PathBuf::from("/"),
            file: root,
            private: parts.len() == 1 && private,
            access: root_access,
        })];
        for (index, component) in parts.iter().enumerate().skip(1) {
            let name = match component {
                Component::Normal(name) => checked_name(name)?,
                Component::CurDir => continue,
                _ => return Err(invalid("normal directory components required")),
            };
            let parent = links.last().expect("root retained");
            let current = parent.path.join(name);
            let last = index + 1 == parts.len();
            let access = DirectoryAccess::for_component(last);
            let mut created = false;
            let open = || rustix::fs::openat(&parent.file, name, access.flags(), Mode::empty());
            let descriptor = match open() {
                Ok(file) => file,
                Err(rustix::io::Errno::NOENT) if create => {
                    match rustix::fs::mkdirat(&parent.file, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) => {
                            created = true;
                            parent.sync()?;
                        }
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(error) => return Err(error.into()),
                    }
                    open()?
                }
                Err(error) => {
                    // Only immutable system-owned aliases (e.g. macOS /var -> /private/var)
                    // may redirect traversal. Restart and validate the complete resolved ancestry.
                    if allow_system_aliases
                        && !cfg!(target_os = "android")
                        && let Ok(link) =
                            rustix::fs::statat(&parent.file, name, AtFlags::SYMLINK_NOFOLLOW)
                        && FileType::from_raw_mode(link.st_mode) == FileType::Symlink
                        && link.st_uid == 0
                        && parent.file.metadata()?.uid() == 0
                        && parent.file.metadata()?.mode() & 0o022 == 0
                    {
                        let mut resolved = fs::canonicalize(&current)?;
                        for tail in &parts[index + 1..] {
                            resolved.push(tail.as_os_str());
                        }
                        return Self::open_with_policy(
                            &resolved,
                            create,
                            private,
                            redirects + 1,
                            true,
                        );
                    }
                    return Err(error.into());
                }
            };
            let file = File::from(descriptor);
            let private_link = created || (last && private);
            validate_directory(&file, private_link)?;
            links.push(Arc::new(Link {
                path: current,
                file,
                private: private_link,
                access,
            }));
        }
        let result = Self { links };
        result.revalidate()?;
        Ok(result)
    }

    fn current(&self) -> &Link {
        self.links.last().expect("directory retains a root")
    }
    pub(super) fn path(&self) -> &Path {
        &self.current().path
    }

    pub(super) fn revalidate(&self) -> io::Result<()> {
        self.revalidate_from(0)
    }

    // Only a strict descendant with this complete shared native chain omits the prefix.
    // Independently opened or unrelated owners retain their original full validation.
    pub(super) fn revalidate_in_tree(&self, anchor: &Self) -> io::Result<()> {
        let first = if self.links.len() > anchor.links.len()
            && self
                .links
                .iter()
                .zip(&anchor.links)
                .all(|(descendant, ancestor)| Arc::ptr_eq(descendant, ancestor))
        {
            anchor.links.len()
        } else {
            0
        };
        self.revalidate_from(first)
    }

    fn revalidate_from(&self, first: usize) -> io::Result<()> {
        for (index, link) in self.links.iter().enumerate().skip(first) {
            let held_identity = validate_directory(&link.file, link.private)?;
            let named = if index == 0 {
                open_directory(&link.path, link.access)?
            } else {
                File::from(rustix::fs::openat(
                    &self.links[index - 1].file,
                    link.path.file_name().ok_or_else(changed)?,
                    link.access.flags(),
                    Mode::empty(),
                )?)
            };
            let named_identity = validate_directory(&named, link.private)?;
            if named_identity != held_identity {
                return Err(changed());
            }
        }
        Ok(())
    }

    pub(super) fn child_reader(&self, name: &OsStr) -> io::Result<Self> {
        self.revalidate()?;
        let file = File::from(rustix::fs::openat(
            &self.current().file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        validate_directory(&file, false)?;
        let mut links = self.links.clone();
        if links.len() >= 128 {
            return Err(invalid("private directory depth bound exceeded"));
        }
        links.push(Arc::new(Link {
            path: self.path().join(name),
            file,
            private: false,
            access: DirectoryAccess::Read,
        }));
        let result = Self { links };
        result.revalidate()?;
        Ok(result)
    }

    pub(super) fn child(&self, name: &OsStr, create: bool, exclusive: bool) -> io::Result<Self> {
        self.child_policy(name, create, exclusive, true)
    }

    pub(super) fn child_owned(
        &self,
        name: &OsStr,
        create: bool,
        exclusive: bool,
    ) -> io::Result<Self> {
        self.child_policy(name, create, exclusive, false)
    }

    fn child_policy(
        &self,
        name: &OsStr,
        create: bool,
        exclusive: bool,
        private: bool,
    ) -> io::Result<Self> {
        match self.child_admission(name, create, exclusive, private)? {
            NativeChildOutcome::Present(child) => Ok(child),
            NativeChildOutcome::InitialAbsence(error) => Err(error),
        }
    }

    pub(super) fn child_optional(&self, name: &OsStr) -> io::Result<Option<Self>> {
        let result = match self.child_admission(name, false, false, true) {
            // The admitted child already closed its complete retained ancestry.
            Ok(NativeChildOutcome::Present(child)) => return Ok(Some(child)),
            Ok(NativeChildOutcome::InitialAbsence(_)) => Ok(None),
            Err(error) => Err(error),
        };
        // No body failure or initial absence may skip the original parent exit.
        #[cfg(test)]
        before_child_named_validation(name);
        if let Err(error) = self.revalidate() {
            drop(result);
            return Err(error);
        }
        result
    }

    fn child_admission(
        &self,
        name: &OsStr,
        create: bool,
        exclusive: bool,
        private: bool,
    ) -> io::Result<NativeChildOutcome<Self>> {
        self.revalidate()?;
        if create {
            match rustix::fs::mkdirat(&self.current().file, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    self.current().file.sync_all()?;
                }
                Err(rustix::io::Errno::EXIST) if !exclusive => {}
                Err(error) => return Err(error.into()),
            }
        }
        let descriptor = match rustix::fs::openat(
            &self.current().file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => {
                return Ok(NativeChildOutcome::InitialAbsence(
                    rustix::io::Errno::NOENT.into(),
                ));
            }
            Err(error) => return Err(error.into()),
        };
        let file = File::from(descriptor);
        validate_directory(&file, private)?;
        if file.metadata()?.uid() != rustix::process::geteuid().as_raw() {
            return Err(denied("child directory requires current ownership"));
        }
        let mut links = self.links.clone();
        if links.len() >= 128 {
            return Err(invalid("private directory depth bound exceeded"));
        }
        links.push(Arc::new(Link {
            path: self.path().join(name),
            file,
            private,
            access: DirectoryAccess::Read,
        }));
        let result = Self { links };
        #[cfg(test)]
        before_child_named_validation(name);
        result.revalidate()?;
        Ok(NativeChildOutcome::Present(result))
    }

    fn open_read(&self, name: &OsStr) -> io::Result<File> {
        Ok(File::from(rustix::fs::openat(
            &self.current().file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }

    pub(super) fn open_readonly(&self, name: &OsStr) -> io::Result<File> {
        self.revalidate()?;
        let file = self
            .open_readonly_native(name, false)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        self.revalidate()?;
        Ok(file)
    }

    // Sole original readonly-open admission, with no ancestry observation. Only the initial
    // native opener may yield optional absence; named admission and final-name errors remain errors.
    pub(super) fn open_readonly_native(
        &self,
        name: &OsStr,
        optional: bool,
    ) -> io::Result<Option<File>> {
        let file = match self.open_read(name) {
            Ok(file) => file,
            Err(error) if optional && error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        self.admit_readonly_file(name, file).map(Some)
    }

    // This is the original native admission after the first opened leaf exists. A missing
    // second named open is an error, never the optional absence handled by the initial opener.
    pub(super) fn admit_readonly_file(&self, name: &OsStr, file: File) -> io::Result<File> {
        validate_file(&file, true)?;
        let original = identity(&file)?;
        #[cfg(test)]
        before_readonly_named_open(name);
        if original != identity(&self.open_read(name)?)? {
            return Err(changed());
        }
        Ok(file)
    }

    pub(super) fn open_retained(
        &self,
        name: &OsStr,
        private: bool,
        create_new: bool,
    ) -> io::Result<RetainedFile> {
        RetainedFile::open(self.clone(), name.to_owned(), private, create_new)
    }

    pub(super) fn open_build_input(&self, name: &OsStr) -> io::Result<RetainedFile> {
        RetainedFile::open_build_input(self.clone(), name.to_owned())
    }

    pub(super) fn read(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        self.revalidate()?;
        self.read_native(name, maximum, private, |bytes| {
            self.revalidate()?;
            Ok(bytes)
        })
    }

    pub(super) fn read_optional(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        self.revalidate()?;
        let mut exit_checked = false;
        let result = checked_name(name).and_then(|name| {
            self.read_optional_native(name, maximum, private, |bytes| {
                exit_checked = true;
                self.revalidate()?;
                Ok(bytes)
            })
        });
        if !exit_checked {
            self.revalidate()?;
        }
        result
    }

    // Required admission over the sole native leaf recipe. Initial absence retains the
    // original native error; file/snapshot owners remain live through the internal consumer.
    // No consumer or file descriptor is exposed by the closed public comparison API.
    pub(super) fn read_native<T>(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
        consume: impl FnOnce(Zeroizing<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<T> {
        match self.read_leaf_native(name, maximum, private, consume)? {
            NativeReadOutcome::InitialAbsence(error) => Err(error),
            NativeReadOutcome::Present(value) => Ok(value),
        }
    }

    pub(super) fn read_optional_native<T>(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
        consume: impl FnOnce(Zeroizing<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<Option<T>> {
        match self.read_leaf_native(name, maximum, private, consume)? {
            NativeReadOutcome::InitialAbsence(_) => Ok(None),
            NativeReadOutcome::Present(value) => Ok(Some(value)),
        }
    }

    // Sole leaf recipe: every error after the first open remains a native refusal.
    // Its original held/named owners stay live through the internal consumer.
    fn read_leaf_native<T>(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
        consume: impl FnOnce(Zeroizing<Vec<u8>>) -> io::Result<T>,
    ) -> io::Result<NativeReadOutcome<T>> {
        let mut file = match self.open_read(name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(NativeReadOutcome::InitialAbsence(error));
            }
            Err(error) => return Err(error),
        };
        let before = validate_file(&file, private)?;
        let bytes = bounded_read(&mut file, before.len(), maximum)?;
        let after = validate_file(&file, private)?;
        #[cfg(test)]
        before_readonly_named_open(name);
        let named = self.open_read(name)?;
        if !unchanged(&before, &after) || !unchanged(&after, &validate_file(&named, private)?) {
            return Err(changed());
        }
        consume(bytes).map(NativeReadOutcome::Present)
    }

    pub(super) fn write_atomic(
        &self,
        name: &OsStr,
        bytes: &[u8],
        mode: PublishMode,
        private_destination: bool,
    ) -> io::Result<()> {
        self.revalidate()?;
        if mode == PublishMode::Replace {
            match self.open_read(name) {
                Ok(file) => {
                    let metadata = validate_file(&file, private_destination)?;
                    if metadata.uid() != rustix::process::geteuid().as_raw() {
                        return Err(denied("publication destination requires current ownership"));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let (temporary, mut file) = (0..128)
            .find_map(|_| {
                let name = temporary_name();
                match rustix::fs::openat(
                    &self.current().file,
                    &name,
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                ) {
                    Ok(file) => Some(Ok((name, File::from(file)))),
                    Err(rustix::io::Errno::EXIST) => None,
                    Err(error) => Some(Err(io::Error::from(error))),
                }
            })
            .unwrap_or_else(|| {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private staging names exhausted",
                ))
            })?;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            validate_file(&file, true)?;
            self.revalidate()?;
            let named = self.open_read(OsStr::new(&temporary))?;
            if identity(&named)? != identity(&file)? {
                return Err(changed());
            }
            match mode {
                PublishMode::Replace => rustix::fs::renameat(
                    &self.current().file,
                    &temporary,
                    &self.current().file,
                    name,
                )?,
                PublishMode::CreateNew => publish_new(&self.current().file, &temporary, name)?,
            }
            self.current().file.sync_all()?;
            let published = self.open_read(name)?;
            validate_file(&published, true)?;
            if identity(&published)? != identity(&file)? {
                return Err(changed());
            }
            self.revalidate()
        })();
        if result.is_err() {
            // Never remove a substituted staging object, nor the already-published destination.
            if self
                .open_read(OsStr::new(&temporary))
                .and_then(|named| identity(&named))
                .ok()
                .zip(identity(&file).ok())
                .is_some_and(|(named, retained)| named == retained)
            {
                let _ = rustix::fs::unlinkat(&self.current().file, &temporary, AtFlags::empty());
            }
        }
        result
    }

    // The public removal bracket owns full entry and every-result exit custody.
    pub(super) fn remove_private_native(&self, name: &OsStr) -> io::Result<bool> {
        let Some(file) = self.open_readonly_native(name, true)? else {
            return Ok(false);
        };
        let before = journal_snapshot(&file)?;
        self.revalidate()?;
        if journal_snapshot(&file)? != before || journal_snapshot(&self.open_read(name)?)? != before
        {
            return Err(changed());
        }
        rustix::fs::unlinkat(&self.current().file, name, AtFlags::empty())?;
        self.current().sync()?;
        Ok(true)
    }

    pub(super) fn reconcile_atomic_staging(
        &self,
        required: &[&str],
        maximum_staged: usize,
        maximum_bytes: usize,
    ) -> io::Result<usize> {
        let maximum_entries = required.len() + maximum_staged;
        let names = self.entries(maximum_entries)?;
        validate_atomic_staging_inventory(&names, required, maximum_staged)?;
        let mut retained = Vec::with_capacity(names.len());
        for name in &names {
            let file = self.open_read(name)?;
            let before = journal_snapshot(&file)?;
            let staged = is_atomic_staging_name(name);
            if staged && before.length > maximum_bytes as u64 {
                return Err(invalid("atomic staging extent exceeds the bound"));
            }
            retained.push((name, file, before, staged));
        }
        // Validate every original before deleting any one of them. The caller's retained
        // exclusive operation lock serializes cooperative writers throughout this operation.
        if self.entries(maximum_entries)? != names {
            return Err(changed());
        }
        for (name, file, before, _) in &retained {
            if journal_snapshot(file)? != *before
                || journal_snapshot(&self.open_read(name)?)? != *before
            {
                return Err(changed());
            }
        }
        let mut removed = 0;
        for (name, file, before, staged) in &retained {
            if *staged {
                self.revalidate()?;
                if journal_snapshot(file)? != *before
                    || journal_snapshot(&self.open_read(name)?)? != *before
                {
                    return Err(changed());
                }
                rustix::fs::unlinkat(&self.current().file, name.as_os_str(), AtFlags::empty())?;
                removed += 1;
            }
        }
        self.sync()?;
        validate_atomic_staging_inventory(&self.entries(required.len())?, required, 0)?;
        for (name, file, before, staged) in &retained {
            if !*staged
                && (journal_snapshot(file)? != *before
                    || journal_snapshot(&self.open_read(name)?)? != *before)
            {
                return Err(changed());
            }
        }
        Ok(removed)
    }

    pub(super) fn open_mutable(&self, name: &OsStr, append: bool) -> io::Result<File> {
        self.revalidate()?;
        let flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let flags = if append {
            flags | OFlags::APPEND
        } else {
            flags
        };
        let file = File::from(rustix::fs::openat(
            &self.current().file,
            name,
            flags,
            Mode::from_raw_mode(0o600),
        )?);
        validate_file(&file, true)?;
        let named = self.open_read(name)?;
        if identity(&named)? != identity(&file)? {
            return Err(changed());
        }
        file.sync_all()?;
        self.current().file.sync_all()?;
        self.revalidate()?;
        Ok(file)
    }

    pub(super) fn open_exact_lock(&self, name: &OsStr, create_new: bool) -> io::Result<File> {
        self.revalidate()?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        if create_new {
            flags |= OFlags::CREATE | OFlags::EXCL;
        }
        let file = File::from(rustix::fs::openat(
            &self.current().file,
            name,
            flags,
            Mode::from_raw_mode(0o600),
        )?);
        validate_file(&file, true)?;
        if identity(&self.open_read(name)?)? != identity(&file)? {
            return Err(changed());
        }
        if create_new {
            file.sync_all()?;
            self.current().file.sync_all()?;
        }
        self.revalidate()?;
        Ok(file)
    }

    pub(super) fn remove_empty(mut self) -> io::Result<()> {
        self.revalidate()?;
        if self.links.len() < 2 {
            return Err(denied("filesystem root cannot be removed"));
        }
        if Arc::strong_count(self.links.last().ok_or_else(changed)?) != 1 {
            return Err(denied("directory removal has live descendant handles"));
        }
        let current = self.links.pop().ok_or_else(changed)?;
        let parent = self.links.last().ok_or_else(changed)?;
        rustix::fs::unlinkat(
            &parent.file,
            current.path.file_name().ok_or_else(changed)?,
            AtFlags::REMOVEDIR,
        )?;
        parent.sync()?;
        self.revalidate()
    }

    pub(super) fn open_ownership_lock(&self, name: &OsStr) -> io::Result<File> {
        self.open_mutable(name, false)
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        self.revalidate()?;
        self.current().file.sync_all()
    }

    pub(super) fn rename_to_sibling(mut self, name: &OsStr, mode: PublishMode) -> io::Result<Self> {
        if mode != PublishMode::CreateNew {
            return Err(invalid(
                "directory publication requires an absent destination",
            ));
        }
        self.revalidate()?;
        if self.links.len() < 2 {
            return Err(denied("filesystem root cannot be published"));
        }
        if Arc::strong_count(self.links.last().ok_or_else(changed)?) != 1 {
            return Err(denied("directory publication has live descendant handles"));
        }
        let current = self.links.pop().ok_or_else(changed)?;
        let mut current = Arc::try_unwrap(current).map_err(|_| changed())?;
        let parent = self.links.last().ok_or_else(changed)?;
        let source = current.path.file_name().ok_or_else(changed)?;
        let source = source
            .to_str()
            .ok_or_else(|| invalid("directory name must be UTF-8"))?;
        publish_new(&parent.file, source, name)?;
        parent.sync()?;
        current.path = parent.path.join(name);
        self.links.push(Arc::new(current));
        self.revalidate()?;
        Ok(self)
    }

    pub(super) fn clear_contents_preserving(&self, preserved: &[&OsStr]) -> io::Result<()> {
        self.revalidate()?;
        for name in preserved {
            validate_file(&self.open_read(name)?, true)?;
        }
        self.clear(preserved, &mut 100_000)
    }

    fn clear(&self, preserved: &[&OsStr], remaining: &mut usize) -> io::Result<()> {
        self.revalidate()?;
        let entries = rustix::fs::Dir::read_from(&self.current().file)?;
        for entry in entries {
            let entry = entry?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == "." || name == ".." || preserved.contains(&name) {
                continue;
            }
            checked_name(name)?;
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| invalid("private removal entry bound exceeded"))?;
            self.revalidate()?;
            let stat = rustix::fs::statat(&self.current().file, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if stat.st_uid != rustix::process::geteuid().as_raw() {
                return Err(denied("removal entry has foreign ownership"));
            }
            let directory = FileType::from_raw_mode(stat.st_mode) == FileType::Directory;
            let file = File::from(rustix::fs::openat(
                &self.current().file,
                name,
                OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC
                    | if directory {
                        OFlags::DIRECTORY
                    } else {
                        OFlags::empty()
                    },
                Mode::empty(),
            )?);
            if directory {
                validate_directory(&file, false)?;
                if self.links.len() >= 128 {
                    return Err(invalid("private removal depth bound exceeded"));
                }
                let mut links = self.links.clone();
                links.push(Arc::new(Link {
                    path: self.path().join(name),
                    file,
                    private: false,
                    access: DirectoryAccess::Read,
                }));
                let child = Self { links };
                child.clear(&[], remaining)?;
                child.revalidate()?;
                rustix::fs::unlinkat(&self.current().file, name, AtFlags::REMOVEDIR)?;
            } else {
                validate_file(&file, false)?;
                let named = self.open_read(name)?;
                if identity(&file)? != identity(&named)? {
                    return Err(changed());
                }
                self.revalidate()?;
                rustix::fs::unlinkat(&self.current().file, name, AtFlags::empty())?;
            }
        }
        self.sync()
    }
}

// Publication belongs only to the exclusively created descriptor and is consumed by rename.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationAuthority {
    ExclusiveCreation,
    None,
}

#[derive(Debug)]
pub struct RetainedFile<D = Directory, N = std::ffi::OsString> {
    directory: D,
    name: N,
    file: File,
    before: fs::Metadata,
    links: LinkPolicy,
    private: bool,
    writable: bool,
    read_only: bool,
    publication: PublicationAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileSnapshot {
    identity: FileIdentity,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileSnapshot {
    pub(super) fn local_parts(self) -> LocalFileSnapshot {
        (
            1,
            (self.identity.volume, self.identity.object),
            self.length,
            [
                u64::from(self.mode),
                u64::from(self.owner),
                u64::from(self.group),
                self.links,
            ],
            [self.modified.0, self.modified.1],
            [self.changed.0, self.changed.1],
        )
    }
    fn from_metadata(value: &fs::Metadata) -> Self {
        let mut object = [0; 16];
        object[..8].copy_from_slice(&value.ino().to_le_bytes());
        Self {
            identity: FileIdentity {
                volume: value.dev(),
                object,
            },
            mode: value.mode(),
            owner: value.uid(),
            group: value.gid(),
            links: value.nlink(),
            length: value.len(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

/// Capture a revalidated private journal with exact owner-only mode.
pub fn journal_snapshot(file: &File) -> io::Result<FileSnapshot> {
    let value = validate_file(file, true)?;
    if value.mode() & 0o7777 != 0o600 {
        return Err(denied("private journal requires mode 0600"));
    }
    Ok(FileSnapshot::from_metadata(&value))
}
/// Validate retained public-file custody and its accepted read modes.
pub fn validate_public_original(file: &File) -> io::Result<()> {
    let value = validate_file(file, false)?;
    if !matches!(value.mode() & 0o7777, 0o644 | 0o444) {
        return Err(denied("public original requires mode 0644 or 0444"));
    }
    Ok(())
}
impl Directory {
    pub(super) fn snapshot_directory(&self) -> io::Result<FileSnapshot> {
        self.revalidate()?;
        let file = &self.current().file;
        validate_directory(file, false)?;
        let value = file.metadata()?;
        let snapshot = FileSnapshot::from_metadata(&value);
        self.revalidate()?;
        if !unchanged(&value, &file.metadata()?) {
            return Err(changed());
        }
        Ok(snapshot)
    }
}

/// Capture current metadata after validating the retained file authority.
pub fn snapshot_file(file: &File, private: bool) -> io::Result<FileSnapshot> {
    let value = validate_file(file, private)?;
    Ok(FileSnapshot::from_metadata(&value))
}

impl<D: Borrow<Directory>, N: AsRef<OsStr>> RetainedFile<D, N> {
    fn open(directory: D, name: N, private: bool, create_new: bool) -> io::Result<Self> {
        Self::open_with_links(directory, name, private, create_new, LinkPolicy::Single)
    }

    fn open_build_input(directory: D, name: N) -> io::Result<Self> {
        Self::open_with_links(directory, name, false, false, LinkPolicy::BuildInput)
    }

    fn open_with_links(
        directory: D,
        name: N,
        private: bool,
        create_new: bool,
        links: LinkPolicy,
    ) -> io::Result<Self> {
        let parent = directory.borrow();
        parent.revalidate()?;
        let file = if create_new {
            File::from(rustix::fs::openat(
                &parent.current().file,
                name.as_ref(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?)
        } else {
            parent.open_read(name.as_ref())?
        };
        let before = validate_file_links(&file, private || create_new, links)?;
        let retained = Self {
            directory,
            name,
            file,
            before,
            links,
            private: private || create_new,
            writable: create_new,
            read_only: false,
            publication: if create_new {
                PublicationAuthority::ExclusiveCreation
            } else {
                PublicationAuthority::None
            },
        };
        retained.revalidate()?;
        if create_new {
            retained.file.sync_all()?;
            retained.directory.borrow().sync()?;
        }
        Ok(retained)
    }

    pub(super) fn snapshot(&self) -> io::Result<FileSnapshot> {
        self.revalidate()?;
        let value = validate_file_links(&self.file, self.private, self.links)?;
        let snapshot = FileSnapshot::from_metadata(&value);
        self.revalidate()?;
        Ok(snapshot)
    }
    pub(super) fn seal(mut self) -> io::Result<Self> {
        self.file.sync_all()?;
        self.revalidate()?;
        self.before = validate_file_links(&self.file, self.private, self.links)?;
        self.writable = false;
        self.directory.borrow().sync()?;
        Ok(self)
    }
    pub(super) fn file(&self) -> &File {
        &self.file
    }
    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub(super) fn identity(&self) -> io::Result<FileIdentity> {
        let mut object = [0; 16];
        object[..8].copy_from_slice(&self.before.ino().to_le_bytes());
        let expected = FileIdentity {
            volume: self.before.dev(),
            object,
        };
        if identity(&self.file)? != expected {
            return Err(changed());
        }
        Ok(expected)
    }
    pub(super) fn revalidate(&self) -> io::Result<()> {
        self.directory.borrow().revalidate()?;
        let after = validate_file_links(&self.file, self.private, self.links)?;
        if self.read_only {
            private_files::validate_read_only(&self.file)?;
        }
        if identity(&self.file)? != self.identity()?
            || (!self.writable && !unchanged(&self.before, &after))
        {
            return Err(changed());
        }
        let named = self.directory.borrow().open_read(self.name.as_ref())?;
        let named_metadata = validate_file_links(&named, self.private, self.links)?;
        if !unchanged(&after, &named_metadata) {
            return Err(changed());
        }
        self.directory.borrow().revalidate()
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn publish_new(parent: &File, temporary: &str, name: &OsStr) -> io::Result<()> {
    Ok(rustix::fs::renameat_with(
        parent,
        temporary,
        parent,
        name,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn publish_new(parent: &File, temporary: &str, name: &OsStr) -> io::Result<()> {
    rustix::fs::linkat(parent, temporary, parent, name, AtFlags::empty())?;
    rustix::fs::unlinkat(parent, temporary, AtFlags::empty())?;
    Ok(())
}

pub fn read_external(
    parent: &Path,
    name: &OsStr,
    maximum: usize,
    private: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    Directory::open_with_policy(parent, false, false, 0, true)?.read(name, maximum, private)
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn journal_snapshot_requires_exact_writable_private_metadata() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let file = File::open(&path).unwrap();
        let original = journal_snapshot(&file).unwrap();
        assert_eq!(original, snapshot_file(&file, true).unwrap());
        assert_eq!(original.identity, identity(&file).unwrap());
        assert_eq!(original.length, 8);
        assert_eq!(original.mode & 0o7777, 0o600);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(snapshot_file(&file, true).is_ok());
        assert!(journal_snapshot(&file).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(journal_snapshot(&file).is_err());
    }

    #[test]
    fn public_original_requires_exact_public_read_modes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("public");
        fs::write(&path, b"original").unwrap();
        let file = File::open(&path).unwrap();
        for mode in [0o644, 0o444] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            validate_public_original(&file).unwrap();
        }
        for mode in [0o600, 0o400, 0o640, 0o664] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(validate_public_original(&file).is_err());
        }
    }

    #[test]
    fn directory_snapshot_revalidates_original_namespace() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("original");
        fs::create_dir(&path).unwrap();
        let directory = Directory::open_reader(&path).unwrap();
        let original = directory.snapshot_directory().unwrap();
        assert_eq!(original, directory.snapshot_directory().unwrap());
        fs::rename(&path, root.path().join("retired")).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(directory.snapshot_directory().is_err());
    }
}

#[cfg(test)]
mod private_child_parent_sharing_tests {
    use super::*;

    #[test]
    fn private_child_adds_one_handle_and_shares_the_complete_original_parent_chain() {
        let temporary = tempfile::tempdir().unwrap();
        let nested = temporary.path().join("one/two/three");
        std::fs::create_dir_all(&nested).unwrap();
        let parent = crate::OwnerDirectory::open(&nested).unwrap();
        let original = parent.create_private_child("journal").unwrap();
        let identity = original.identity().unwrap();
        drop(original);
        let depth = parent.inner.links.len();
        for optional in [false, true] {
            let child = if optional {
                parent
                    .open_private_child_optional("journal")
                    .unwrap()
                    .unwrap()
            } else {
                parent.open_private_child("journal").unwrap()
            };
            assert_eq!(child.identity().unwrap(), identity);
            assert_eq!(child.inner.links.len(), depth + 1);
            assert!(
                parent
                    .inner
                    .links
                    .iter()
                    .zip(&child.inner.links)
                    .all(|(parent, child)| Arc::ptr_eq(parent, child))
            );
            let shared = parent
                .inner
                .links
                .iter()
                .chain(&child.inner.links)
                .map(|link| Arc::as_ptr(link) as usize)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(shared.len(), depth + 1);
            // The old absolute selection holds a separate File for every prefix component.
            let reopened = crate::PrivateDirectory::open(child.path()).unwrap();
            assert_eq!(reopened.identity().unwrap(), identity);
            assert!(
                parent
                    .inner
                    .links
                    .iter()
                    .zip(&reopened.inner.links)
                    .all(|(parent, child)| !Arc::ptr_eq(parent, child))
            );
            let duplicated = parent
                .inner
                .links
                .iter()
                .chain(&reopened.inner.links)
                .map(|link| Arc::as_ptr(link) as usize)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(duplicated.len(), 2 * depth + 1);
        }
    }
}
