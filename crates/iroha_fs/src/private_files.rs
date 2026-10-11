//! Bounded private-file inventory and opaque immutable-file publication.

use super::*;

mod borrowed;
pub use borrowed::{BorrowedPendingPrivateFile, BorrowedSealedPrivateFile};

/// Validated private regular-file metadata from one bounded directory scan.
///
/// This is an inventory observation, not a retained content capability. Only a later
/// retained read authenticates the file bytes and their unchanged identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateFileMetadata {
    pub(crate) length: u64,
    pub(crate) read_only: bool,
}

impl PrivateFileMetadata {
    /// Observed file length in bytes, including incomplete empty files.
    pub const fn len(self) -> u64 {
        self.length
    }

    /// Whether the observed file contains no bytes.
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }

    /// Whether native access is exactly owner-read-only, rather than private writable custody.
    pub const fn is_read_only(self) -> bool {
        self.read_only
    }
}

/// A bounded private writer that exclusively owns its original native descriptor.
///
/// This capability has no file/raw-handle accessor, clone, or conversion to a generic writer.
/// Seeks and writes cannot exceed the original byte ceiling, including sparse writes.
/// Strict sealing consumes the only writable capability and retains the same native object.
///
/// ```compile_fail
/// use iroha_fs::PendingPrivateFile;
/// fn duplicate_writer(file: PendingPrivateFile) {
///     let duplicate = file.file().try_clone().unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use iroha_fs::PendingPrivateFile;
/// fn publish_unsealed(file: PendingPrivateFile) {
///     file.publish_new_name("receipt").unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct PendingPrivateFile {
    inner: platform::RetainedFile,
    maximum: u64,
    position: u64,
}

/// An opaque bounded reader over one strictly sealed private file.
///
/// Implements only read and seek I/O. The original descriptor stays private for identity checks
/// and by-handle publication; there is no writable clone, raw handle or conversion back. Reads
/// are untrusted until the caller compares stable snapshots around its bounded read. Recovery
/// independently validates strict access and the original byte ceiling before returning this type.
///
/// ```compile_fail
/// use std::io::Write;
/// use iroha_fs::SealedPrivateFile;
/// fn rewrite_receipt(mut file: SealedPrivateFile) {
///     file.write_all(b"substitute").unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct SealedPrivateFile {
    inner: platform::RetainedFile,
    maximum: u64,
    position: u64,
}

impl PrivateDirectory {
    /// Retain an optional private child, recognizing only its first native open as absence.
    ///
    /// This preserves [`Self::open_retained_private`]'s private single-link policy; it does
    /// not require sealed read-only access. A present native owner remains retained through
    /// the final directory custody check. Later missing names are errors, never `None`.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changing custody and native errors. Returns `None`
    /// only for initial native absence under unchanged retained directory custody.
    pub fn open_retained_private_optional(
        &self,
        name: impl AsRef<OsStr>,
    ) -> io::Result<Option<RetainedFile>> {
        self.inner.revalidate()?;
        let result = checked_name(name.as_ref()).and_then(|name| {
            self.inner
                .open_retained_private_optional(name)
                .map(|file| file.map(|inner| RetainedFile { inner }))
        });
        self.inner.revalidate()?;
        result
    }

    /// Open an existing private directory with exact absolute spelling and no link redirects.
    ///
    /// Unlike general runtime paths, immutable journal custody rejects even operating-system
    /// aliases. This bounds retained ancestry directly by the supplied path. All components
    /// must be canonical; no current/parent components, repeated separators or trailing slash.
    ///
    /// # Errors
    /// Refuses noncanonical paths, links, missing directories, unsafe custody and native errors.
    pub fn open_exact(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let normalized: PathBuf = path.components().collect();
        if !path.is_absolute()
            || normalized.as_os_str() != path.as_os_str()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            || path.components().count() > 128
        {
            return Err(invalid(
                "exact private custody requires canonical absolute spelling",
            ));
        }
        Ok(Self {
            inner: platform::Directory::open_exact(path)?,
        })
    }

    /// Visit bounded direct private files without collecting their names or reading bodies.
    ///
    /// Iteration order is native and unspecified. Every entry must be a single-link regular
    /// current-owner file with private access. Unix incomplete modes contained in `0600`,
    /// including `0000`, are inventory-visible but are not admitted as immutable receipts.
    /// The directory and retained ancestors are checked before and after the entire scan.
    /// Callers hold their operation lock and must not mutate this directory from the visitor;
    /// an error may follow earlier callbacks, whose observations must then be discarded.
    ///
    /// The scan retains no per-entry collection. Conservative filesystem work bounds are
    /// eight owner-level filesystem probes per entry, twenty per retained ancestor, and sixteen
    /// fixed probes; at most four transient native handles are live beyond the retained directory.
    /// Probes count native API requests, not hidden kernel work or interrupted-call retries.
    /// Native directory buffering and one bounded filename remain caller-budgeted resources.
    ///
    /// # Errors
    /// Refuses invalid names, excessive entries, unsafe files, changed custody and native errors.
    pub fn visit_private_files(
        &self,
        maximum: usize,
        visitor: impl FnMut(&OsStr, PrivateFileMetadata) -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.visit_private_files(maximum, visitor)
    }

    /// Create an opaque bounded writer relative to this retained directory.
    ///
    /// Only a newly created file is assigned owner read/write access. Existing names are never
    /// hardened or replaced. A failed creation may leave a private incomplete file for recovery.
    /// The exact empty file and parent are synchronized before success. Retained files share
    /// ancestor handles; each retains only an Arc-pointer vector and name, without reopening them.
    ///
    /// # Errors
    /// Refuses existing names, invalid paths, unsafe custody and native creation errors.
    pub fn create_retained_private(
        &self,
        name: impl AsRef<OsStr>,
        maximum: usize,
    ) -> io::Result<PendingPrivateFile> {
        let maximum = byte_ceiling(maximum)?;
        Ok(PendingPrivateFile {
            inner: self
                .inner
                .create_retained_private(checked_name(name.as_ref())?)?,
            maximum,
            position: 0,
        })
    }

    /// Retain one existing strictly owner-read-only private file within the byte ceiling.
    ///
    /// Unix requires exact mode `0400`; Windows requires a protected current-owner read-only
    /// DACL. Writable private files are rejected, never silently sealed during recovery.
    ///
    /// # Errors
    /// Refuses excessive length, writable access, unsafe or missing files and native errors.
    pub fn open_retained_read_only(
        &self,
        name: impl AsRef<OsStr>,
        maximum: usize,
    ) -> io::Result<SealedPrivateFile> {
        let maximum = byte_ceiling(maximum)?;
        let file = SealedPrivateFile {
            inner: self
                .inner
                .open_retained_read_only(checked_name(name.as_ref())?)?,
            maximum,
            position: 0,
        };
        file.len()?;
        Ok(file)
    }

    /// Retain an optional sealed original, recognizing only its first native open as absence.
    ///
    /// Present files retain the strict access, single-link, ancestry and extent checks of
    /// [`Self::open_retained_read_only`]. A later missing named file is an error. Directory
    /// custody closes after every ordinary result, with a present original still retained.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changing custody, excessive length and native errors.
    /// Returns `None` only for initial native absence under unchanged directory custody.
    pub fn open_retained_read_only_optional(
        &self,
        name: impl AsRef<OsStr>,
        maximum: usize,
    ) -> io::Result<Option<SealedPrivateFile>> {
        self.inner.revalidate()?;
        let result = (|| {
            let maximum = byte_ceiling(maximum)?;
            self.inner
                .open_retained_read_only_optional(checked_name(name.as_ref())?)?
                .map(|inner| {
                    let file = SealedPrivateFile {
                        inner,
                        maximum,
                        position: 0,
                    };
                    file.len()?;
                    Ok(file)
                })
                .transpose()
        })();
        self.inner.revalidate()?;
        result
    }
}

impl PendingPrivateFile {
    /// Consume this writer into strict owner-read-only access with durable bounded contents.
    ///
    /// The exact descriptor and ancestry remain retained privately. Unix sets mode `0400`;
    /// Windows installs a protected owner-only read DACL. The returned capability cannot write
    /// or expose the original descriptor. A failure leaves the claimed name for reconciliation.
    ///
    /// # Errors
    /// Refuses excessive length, changed custody, access-policy or synchronization failures.
    pub fn seal_read_only(self) -> io::Result<SealedPrivateFile> {
        let file = SealedPrivateFile {
            inner: self.inner.seal_read_only()?,
            maximum: self.maximum,
            position: self.position,
        };
        file.len()?;
        Ok(file)
    }
}

impl SealedPrivateFile {
    /// Read the retained object's stable kernel identity.
    ///
    /// # Errors
    /// Refuses an identity change or native metadata failure.
    pub fn identity(&self) -> io::Result<FileIdentity> {
        self.inner.identity()
    }

    /// Capture exact identity and metadata after checking strict access and retained ancestry.
    ///
    /// # Errors
    /// Refuses changed content, custody or ancestry and native metadata failures.
    pub fn snapshot(&self) -> io::Result<FileSnapshot> {
        Ok(FileSnapshot {
            inner: self.inner.snapshot()?,
        })
    }

    /// Recheck strict access, original content metadata and the retained namespace.
    ///
    /// # Errors
    /// Refuses changed content, custody or ancestry and native metadata failures.
    pub fn revalidate(&self) -> io::Result<()> {
        self.inner.revalidate()
    }

    /// Observe bounded length; content authentication still requires stable snapshots.
    ///
    /// # Errors
    /// Refuses an excessive file extent or native metadata failure.
    pub fn len(&self) -> io::Result<u64> {
        bounded_length(self.inner.file(), self.maximum)
    }

    /// Whether the bounded current extent is empty.
    ///
    /// # Errors
    /// Refuses an excessive file extent or native metadata failure.
    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|length| length == 0)
    }

    /// Publish this newly created sealed file under an absent sibling name.
    ///
    /// The exact object stays retained across atomic no-replace publication and parent sync.
    /// The returned capability binds its new name. An error after publication may indicate
    /// uncertain durability; callers reconcile the destination and never erase the evidence.
    /// Each created capability may publish only once; reopened receipts cannot move themselves.
    ///
    /// # Errors
    /// Refuses reopened/already-published files, existing names, identity changes and I/O errors.
    pub fn publish_new_name(self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.publish_new_name(checked_name(name.as_ref())?)?,
            maximum: self.maximum,
            position: self.position,
        })
    }
}

fn byte_ceiling(maximum: usize) -> io::Result<u64> {
    u64::try_from(maximum).map_err(|_| invalid("private file byte ceiling exceeds native extent"))
}

fn bounded_length(file: &File, maximum: u64) -> io::Result<u64> {
    let length = file.metadata()?.len();
    if length > maximum {
        return Err(invalid(
            "private file extent exceeds the original byte ceiling",
        ));
    }
    Ok(length)
}

fn seek_target(position: u64, length: u64, maximum: u64, from: io::SeekFrom) -> io::Result<u64> {
    let target = match from {
        io::SeekFrom::Start(offset) => Some(offset),
        io::SeekFrom::Current(offset) => position.checked_add_signed(offset),
        io::SeekFrom::End(offset) => length.checked_add_signed(offset),
    };
    target
        .filter(|&value| value <= maximum)
        .ok_or_else(|| invalid("private file seek exceeds the original byte ceiling"))
}

impl io::Write for PendingPrivateFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        bounded_write(
            self.inner.file_mut(),
            self.maximum,
            &mut self.position,
            bytes,
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(self.inner.file_mut())
    }
}

impl io::Read for SealedPrivateFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        bounded_read(
            self.inner.file_mut(),
            self.maximum,
            &mut self.position,
            bytes,
        )
    }
}

impl io::Seek for PendingPrivateFile {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        bounded_seek(
            self.inner.file_mut(),
            self.maximum,
            &mut self.position,
            from,
        )
    }
}

impl io::Seek for SealedPrivateFile {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        bounded_seek(
            self.inner.file_mut(),
            self.maximum,
            &mut self.position,
            from,
        )
    }
}

fn bounded_write(
    file: &mut File,
    maximum: u64,
    position: &mut u64,
    bytes: &[u8],
) -> io::Result<usize> {
    let length = byte_ceiling(bytes.len())?;
    if length > maximum.saturating_sub(*position) {
        return Err(invalid(
            "private file write exceeds the original byte ceiling",
        ));
    }
    let written = io::Write::write(file, bytes)?;
    *position += written as u64;
    Ok(written)
}

fn bounded_read(
    file: &mut File,
    maximum: u64,
    position: &mut u64,
    bytes: &mut [u8],
) -> io::Result<usize> {
    let remaining = usize::try_from(maximum.saturating_sub(*position)).unwrap_or(usize::MAX);
    let length = bytes.len().min(remaining);
    let read = io::Read::read(file, &mut bytes[..length])?;
    *position += read as u64;
    Ok(read)
}

fn bounded_seek(
    file: &mut File,
    maximum: u64,
    position: &mut u64,
    from: io::SeekFrom,
) -> io::Result<u64> {
    let length = if matches!(from, io::SeekFrom::End(_)) {
        bounded_length(file, maximum)?
    } else {
        0
    };
    let target = seek_target(*position, length, maximum, from)?;
    *position = io::Seek::seek(file, io::SeekFrom::Start(target))?;
    Ok(*position)
}

#[cfg(test)]
#[path = "private_files/tests.rs"]
mod tests;
