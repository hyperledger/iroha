//! Native Windows atomic project state through the canonical retained filesystem authority.

use super::{AtomicInstallOutcome, AtomicWriteError, AtomicWriteErrorCode, validate_relative_path};
use iroha_fs::{OwnerDirectory, PrivateDirectory, PublishMode};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    path::{Component, Path},
};

#[derive(Debug)]
enum Directory {
    Project(OwnerDirectory),
    Private(PrivateDirectory),
}
impl Directory {
    fn path(&self) -> &Path {
        match self {
            Self::Project(dir) => dir.path(),
            Self::Private(dir) => dir.path(),
        }
    }
    fn revalidate(&self) -> io::Result<()> {
        match self {
            Self::Project(dir) => dir.revalidate(),
            Self::Private(dir) => dir.revalidate(),
        }
    }
    fn sync(&self) -> io::Result<()> {
        match self {
            Self::Project(dir) => dir.sync(),
            Self::Private(dir) => dir.sync(),
        }
    }
    fn reopen(&self) -> io::Result<Self> {
        match self {
            Self::Project(dir) => OwnerDirectory::open(dir.path()).map(Self::Project),
            Self::Private(dir) => PrivateDirectory::open(dir.path()).map(Self::Private),
        }
    }
    fn child(&self, name: &OsStr) -> io::Result<Self> {
        match self {
            Self::Project(dir) => dir.open_child(name).map(Self::Project),
            Self::Private(dir) => dir.open_child(name).map(Self::Private),
        }
    }
    fn read(&self, name: &OsStr, maximum: usize, private: bool) -> io::Result<Vec<u8>> {
        let bytes = match self {
            Self::Project(dir) if private => {
                iroha_fs::read_private(dir.path().join(name), maximum)?
            }
            Self::Project(dir) => dir.read_regular(name, maximum)?,
            Self::Private(dir) => dir.read(name, maximum)?,
        };
        Ok(bytes.to_vec())
    }
    fn read_optional(
        &self,
        name: &OsStr,
        maximum: usize,
        private: bool,
    ) -> io::Result<Option<Vec<u8>>> {
        let bytes = match self {
            Self::Project(dir) if private => dir.read_private_optional(name, maximum)?,
            Self::Project(dir) => dir.read_regular_optional(name, maximum)?,
            Self::Private(dir) => dir.read_optional(name, maximum)?,
        };
        Ok(bytes.map(|bytes| bytes.to_vec()))
    }
    fn write(&self, name: &OsStr, bytes: &[u8], mode: PublishMode) -> io::Result<()> {
        match self {
            Self::Project(dir) => dir.write_atomic(name, bytes, mode),
            Self::Private(dir) => dir.write_atomic(name, bytes, mode),
        }
    }
    fn lock(&self, name: &OsStr) -> io::Result<File> {
        match self {
            Self::Project(dir) => dir.open_lock(name),
            Self::Private(dir) => dir.open_lock(name),
        }
    }
}

/// Retained native directory authority for atomic, root-confined Musubi state.
#[derive(Debug)]
pub struct AtomicWriteRoot {
    directory: Directory,
}
impl AtomicWriteRoot {
    /// Create or open one absolute owner-private state root without following reparse points.
    ///
    /// # Errors
    /// Refuses relative paths, unsafe custody, foreign write access and native errors.
    pub fn open_or_create_private(path: &Path) -> Result<Self, AtomicWriteError> {
        if !path.is_absolute() {
            return Err(AtomicWriteError::new(
                AtomicWriteErrorCode::InvalidRelativePath,
                path,
                "open absolute private root",
            ));
        }
        PrivateDirectory::open_or_create(path)
            .map(|dir| Self {
                directory: Directory::Private(dir),
            })
            .map_err(|error| native_error(path, "open private root", error))
    }

    /// Open a safe existing project root while preserving its reader permissions.
    ///
    /// # Errors
    /// Refuses missing roots, reparse points, foreign mutation and native errors.
    pub fn new(path: &Path) -> Result<Self, AtomicWriteError> {
        OwnerDirectory::open(path)
            .map(|dir| Self {
                directory: Directory::Project(dir),
            })
            .map_err(|error| native_error(path, "open project root", error))
    }

    /// Return the absolute retained root.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    fn parent(&self, relative: &Path) -> Result<Directory, AtomicWriteError> {
        validate_relative_path(relative)?;
        self.directory
            .revalidate()
            .map_err(|error| native_error(self.path(), "revalidate root", error))?;
        let mut parent = self
            .directory
            .reopen()
            .map_err(|error| native_error(self.path(), "retain root", error))?;
        for component in relative
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .components()
        {
            let Component::Normal(name) = component else {
                return Err(AtomicWriteError::new(
                    AtomicWriteErrorCode::InvalidRelativePath,
                    relative,
                    "retain normal parent",
                ));
            };
            parent = parent
                .child(name)
                .map_err(|error| native_error(relative, "retain destination parent", error))?;
        }
        Ok(parent)
    }

    /// Durably replace one root-relative regular file with private generated bytes.
    ///
    /// # Errors
    /// Refuses unsafe targets, changed custody and native publication or durability errors.
    pub fn replace(&self, relative: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
        let parent = self.parent(relative)?;
        parent
            .write(
                relative.file_name().expect("validated filename"),
                bytes,
                PublishMode::Replace,
            )
            .map_err(|error| native_error(relative, "replace exact regular file", error))?;
        self.directory
            .revalidate()
            .map_err(|error| native_error(self.path(), "revalidate published root", error))
    }

    /// Read exact bounded immutable bytes, returning `None` for an absent file.
    ///
    /// # Errors
    /// Refuses links, unsafe custody, changed files, oversized bytes and native errors.
    pub fn load_immutable(
        &self,
        relative: &Path,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, AtomicWriteError> {
        self.read(relative, maximum, false)
    }

    pub(crate) fn load_private_descriptor_rooted(
        &self,
        relative: &Path,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, AtomicWriteError> {
        self.read(relative, maximum, true)
    }

    fn read(
        &self,
        relative: &Path,
        maximum: usize,
        private: bool,
    ) -> Result<Option<Vec<u8>>, AtomicWriteError> {
        let parent = self.parent(relative)?;
        let name = relative.file_name().expect("validated filename");
        let bytes = parent
            .read_optional(name, maximum, private)
            .map_err(|error| native_error(relative, "read immutable bytes", error))?;
        parent
            .revalidate()
            .and_then(|()| self.directory.revalidate())
            .map_err(|error| native_error(relative, "revalidate immutable source", error))?;
        Ok(bytes)
    }

    /// Publish immutable private bytes under an absent name, accepting identical retries.
    ///
    /// # Errors
    /// Refuses different existing bytes, unsafe custody and native publication errors.
    pub fn install_immutable(
        &self,
        relative: &Path,
        bytes: &[u8],
    ) -> Result<AtomicInstallOutcome, AtomicWriteError> {
        let parent = self.parent(relative)?;
        let name = relative.file_name().expect("validated filename");
        let outcome = match parent.write(name, bytes, PublishMode::CreateNew) {
            Ok(()) => AtomicInstallOutcome::Installed,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                AtomicInstallOutcome::AlreadyPresent
            }
            Err(error) => return Err(native_error(relative, "publish immutable bytes", error)),
        };
        let existing = parent.read(name, bytes.len(), false).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidInput {
                AtomicWriteError::new(
                    AtomicWriteErrorCode::ImmutableConflict,
                    relative,
                    "verify exact immutable bytes",
                )
            } else {
                native_error(relative, "read back immutable publication", error)
            }
        })?;
        if existing != bytes {
            return Err(AtomicWriteError::new(
                AtomicWriteErrorCode::ImmutableConflict,
                relative,
                "verify exact immutable bytes",
            ));
        }
        parent
            .sync()
            .and_then(|()| self.directory.revalidate())
            .map_err(|error| native_error(relative, "complete immutable publication", error))?;
        Ok(outcome)
    }

    pub(crate) fn lock_exclusive(&self, name: &Path) -> Result<File, AtomicWriteError> {
        validate_relative_path(name)?;
        if name.components().count() != 1 {
            return Err(AtomicWriteError::new(
                AtomicWriteErrorCode::InvalidRelativePath,
                name,
                "lock one direct child",
            ));
        }
        let file = self
            .directory
            .lock(name.as_os_str())
            .map_err(|error| native_error(name, "open process lock", error))?;
        if file
            .metadata()
            .map_err(|error| native_error(name, "inspect process lock", error))?
            .len()
            != 0
        {
            return Err(AtomicWriteError::new(
                AtomicWriteErrorCode::UnsafeTarget,
                name,
                "validate empty process lock",
            ));
        }
        file.try_lock()
            .map_err(|error| native_error(name, "acquire process lock", error.into()))?;
        self.directory
            .revalidate()
            .and_then(|()| file.sync_all())
            .and_then(|()| self.directory.sync())
            .map_err(|error| native_error(name, "persist process lock", error))?;
        Ok(file)
    }
}

fn native_error(path: &Path, operation: &'static str, error: io::Error) -> AtomicWriteError {
    let mut report = AtomicWriteError::io(path, operation, error);
    if report.source.as_ref().is_some_and(|source| {
        matches!(
            source.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
        )
    }) {
        report.code = AtomicWriteErrorCode::UnsafeTarget;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_state_publication_is_private_bounded_and_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let root =
            AtomicWriteRoot::open_or_create_private(&temporary.path().join("private")).unwrap();
        let name = Path::new("plan");
        assert_eq!(
            root.install_immutable(name, b"exact").unwrap(),
            AtomicInstallOutcome::Installed
        );
        assert_eq!(
            root.install_immutable(name, b"exact").unwrap(),
            AtomicInstallOutcome::AlreadyPresent
        );
        assert_eq!(
            root.install_immutable(name, b"other").unwrap_err().code(),
            AtomicWriteErrorCode::ImmutableConflict
        );
        assert_eq!(root.load_immutable(name, 5).unwrap().unwrap(), b"exact");
        assert!(root.load_immutable(name, 4).is_err());
        assert_eq!(
            root.load_private_descriptor_rooted(name, 5)
                .unwrap()
                .unwrap(),
            b"exact"
        );
        root.replace(name, b"next").unwrap();
        assert_eq!(root.load_immutable(name, 4).unwrap().unwrap(), b"next");
        assert!(root.replace(Path::new("../escape"), b"bad").is_err());
        let lock = root.lock_exclusive(Path::new("deployment.lock")).unwrap();
        assert!(root.lock_exclusive(Path::new("deployment.lock")).is_err());
        drop(lock);
        assert!(root.lock_exclusive(Path::new("deployment.lock")).is_ok());
    }
}
