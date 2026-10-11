//! Retained native filesystem authority for private Iroha runtime material.
//!
//! Private directories and files belong to the effective user. Operations reject links,
//! traversal, shared file custody and replaced ancestors; reads retain and recheck the original
//! descriptor. Unix uses descriptor-relative operations, owner modes and directory `fsync`.
//! Windows uses protected current-user DACLs, retained non-delete-sharing ancestor handles,
//! reparse rejection, file IDs and write-through native publication. No codec or network policy
//! belongs in this crate. Filesystem/media honesty remains an operating-system assumption.
//! A separate read-only build-input owner retains Cargo's legitimate initial hardlink count;
//! it supplies no private-file or installed-program authority and refuses later source changes.

use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

mod custody_io;
pub use custody_io::CustodyEntryKind;

mod private_files;
pub use private_files::{BorrowedPendingPrivateFile, BorrowedSealedPrivateFile};
pub use private_files::{PendingPrivateFile, PrivateFileMetadata, SealedPrivateFile};

#[cfg(unix)]
#[path = "unix.rs"]
mod platform;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as platform;
#[cfg(not(any(unix, windows)))]
compile_error!("iroha_fs requires a native Unix or Windows host");

/// Whether atomic publication must create a new name or may replace an existing owned file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishMode {
    /// Fail with [`io::ErrorKind::AlreadyExists`] if the destination exists.
    CreateNew,
    /// Replace a regular, single-link, current-owner destination atomically.
    Replace,
}

/// Stable kernel identity of an opened file, independent of its pathname.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    volume: u64,
    object: [u8; 16],
}

impl FileIdentity {
    /// Read a file's native volume and object identity from its retained descriptor.
    ///
    /// # Errors
    /// Returns the native error if the descriptor's identity cannot be read.
    pub fn of(file: &File) -> io::Result<Self> {
        platform::identity(file)
    }

    /// Project native volume and object values for an owner-private local custody record.
    ///
    /// These machine-local values identify this object across a directory rename and reopen.
    /// They do not authenticate record contents, confer filesystem authority, or belong in
    /// signed consensus artifacts. The record owner supplies its canonical encoding and must
    /// independently validate the current native object and private-directory custody. The
    /// first value identifies Unix (1) or Windows (2); values are not portable between hosts
    /// and do not prevent reuse of a native object identifier after all handles close.
    #[must_use]
    pub const fn local_parts(self) -> (u8, u64, [u8; 16]) {
        (if cfg!(unix) { 1 } else { 2 }, self.volume, self.object)
    }
}

/// Primitive projection of a native file snapshot for owner-private local records.
///
/// Values are host kind (Unix 1 or Windows 2), native volume/object identity, length,
/// custody metadata, last modification and last change. Unix custody is mode/user/group/link
/// count and timestamps are seconds/nanoseconds; Windows custody is attributes/link count/0/0
/// and timestamps are native ticks/0. No codec or authentication policy is supplied here.
/// Native identifiers and timestamps may be reused after handles close; filesystem/media
/// honesty and a private unchanged record remain the caller's trust assumptions.
pub type LocalFileSnapshot = (u8, (u64, [u8; 16]), u64, [u64; 4], [i64; 2], [i64; 2]);

/// Exact native file snapshot for comparing separately retained opens without retaining all files.
///
/// Binds kernel identity, length, timestamps and native custody-relevant metadata. A later open
/// must independently pass native ownership, link and access validation before comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileSnapshot {
    inner: platform::FileSnapshot,
}

impl FileSnapshot {
    /// Project all existing native snapshot fields without allocating or adding authority.
    ///
    /// See [`LocalFileSnapshot`] for the host-local field meanings and trust limits. This is
    /// not a permanent non-reusable physical identifier or a cryptographic commitment.
    #[must_use]
    pub fn local_parts(self) -> LocalFileSnapshot {
        self.inner.local_parts()
    }
    /// Capture exact writable private journal custody (Unix mode 0600, or the actual
    /// protected current-user Windows DACL and non-read-only native object).
    /// # Errors
    /// Refuses non-writable private originals, shared links or native I/O errors.
    pub fn private_journal(file: &File) -> io::Result<Self> {
        Ok(Self {
            inner: platform::journal_snapshot(file)?,
        })
    }
    /// Read exact native file identity, length, timestamps and custody metadata.
    ///
    /// This validates a regular single-link file and its native access restrictions. The
    /// retained directory/file owner must separately revalidate the pathname and ancestors.
    /// # Errors
    /// Refuses unsafe custody, links, changed native metadata or native I/O errors.
    pub fn of(file: &File, private: bool) -> io::Result<Self> {
        Ok(Self {
            inner: platform::snapshot_file(file, private)?,
        })
    }
}

/// Read bytes at an exact offset, independently of its prior cursor.
/// Unix uses native `pread`; Windows uses native `seek_read`, which moves the physical cursor.
/// A mutable owner must reanchor its write cursor before appending; descriptor identity is retained.
/// This is a DATA operation; callers retain and revalidate the original native custody.
/// # Errors
/// Returns the genuine native I/O error.
pub fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buffer, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
    }
}

/// Fill an exact offset range independently of its prior cursor.
/// # Errors
/// Refuses truncation, offset overflow or native I/O failure.
pub fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buffer.is_empty() {
        match read_at(file, buffer, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => {
                offset = offset
                    .checked_add(count as u64)
                    .ok_or_else(|| io::Error::other("native read offset overflow"))?;
                buffer = &mut buffer[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// One original private-file byte comparison, borrowed only for its closed read transaction.
///
/// The transaction checks each leaf name in request order. This record grants no descriptor,
/// returned bytes, current-state authority or reusable validation result.
#[derive(Clone, Copy)]
pub struct PrivateFileComparison<'a> {
    /// One portable direct child name, validated by the comparison before its native open.
    pub name: &'a OsStr,
    /// The original maximum byte extent for this file's private native read.
    pub maximum: usize,
    /// Independently captured original bytes; they are borrowed without copying plaintext.
    pub expected: &'a [u8],
}

/// An owner-private directory and the retained authority for all of its ancestors.
#[derive(Debug)]
pub struct PrivateDirectory {
    inner: platform::Directory,
}

// Only the first named child open can establish absence. Preserve its genuine native error
// for required callers; parent and admitted-child failures never construct this outcome.
enum NativeChildOutcome<T> {
    InitialAbsence(io::Error),
    Present(T),
}

/// A borrowed read-only view inside one private-directory read transaction.
///
/// This view exposes no pathname, descriptor, retention or mutation operation. [`Self::read`]
/// and [`Self::read_optional`] consume borrowed bytes before their original native owners
/// and zeroized buffer drop.
/// [`Self::read_admitted`] instead returns the caller's one original owned `Vec`, preserving
/// its allocation and ownership semantics. The view cannot leave [`PrivateDirectory::read_scope`]
/// or [`PrivateReadTreeScope::read_scope`].
pub struct PrivateReadScope<'scope> {
    directory: &'scope platform::Directory,
    // An actual mutable lexical lease makes this view non-Copy without a heap owner.
    _lease: &'scope mut (),
}

impl PrivateReadScope<'_> {
    /// Consume one bounded private single-link file through the original native read body.
    ///
    /// The consumer runs only after the complete per-file custody, metadata, namespace and
    /// extent checks. Its return value can contain a semantic result, preserving the caller's
    /// decoder errors without remapping them. Borrowed plaintext cannot leave this consumer.
    /// Only one native read and zeroized buffer are owned by this call at a time.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe leaf custody, oversized or changing files and native
    /// I/O errors. Use [`Self::read_optional`] for optional inputs: required reads can
    /// return `NotFound` from initial absence or a later native custody check.
    pub fn read<T>(
        &mut self,
        name: impl AsRef<OsStr>,
        maximum: usize,
        consume: impl FnOnce(&[u8]) -> T,
    ) -> io::Result<T> {
        self.directory
            .read_native(checked_name(name.as_ref())?, maximum, true, |bytes| {
                Ok(consume(bytes.as_slice()))
            })
    }

    /// Consume one optional private file, recognizing only its first native open as absence.
    ///
    /// Present files use the same zeroized allocation and leaf checks as [`Self::read`], with
    /// native owners held through the borrowed consumer. Missing later named admission, changed
    /// metadata, unsafe custody and read/EOF errors remain errors. The enclosing scope closes
    /// directory custody before an ordinary result can leave, including `None` and errors.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changing leaves, oversized files and all late native errors.
    pub fn read_optional<T>(
        &mut self,
        name: impl AsRef<OsStr>,
        maximum: usize,
        consume: impl FnOnce(&[u8]) -> T,
    ) -> io::Result<Option<T>> {
        self.directory
            .read_optional_native(checked_name(name.as_ref())?, maximum, true, |bytes| {
                Ok(consume(bytes.as_slice()))
            })
    }

    /// List a bounded native inventory within this enclosing read scope.
    ///
    /// The sole native census retains its original name, count and metadata checks and sorting.
    /// Directory custody is closed by the enclosing scope on every ordinary result, including
    /// a census error or a caller's comparison refusal. No intermediate ancestry observation
    /// is added by this method; the scope is not an atomic snapshot.
    ///
    /// # Errors
    /// Refuses invalid native names, excessive entry counts, changed metadata and native I/O.
    pub fn entries(&self, maximum: usize) -> io::Result<Vec<std::ffi::OsString>> {
        self.directory.entries_native(maximum, |mut names| {
            names.sort();
            Ok(names)
        })
    }

    /// Compare ordered original private bytes through the sole lazy comparison recipe.
    ///
    /// Every file retains the original bounded private leaf checks and one zeroized buffer
    /// through its consumer. The first stable mismatch stops later reads; empty inputs do no
    /// leaf I/O. The enclosing read scope closes native directory custody before returning
    /// a match, mismatch or ordinary error. No plaintext or validation verdict is retained.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changed private leaves, excessive extents and native I/O.
    pub fn compare_files(&mut self, inputs: &[PrivateFileComparison<'_>]) -> io::Result<bool> {
        for input in inputs {
            if !self.read(input.name, input.maximum, |current| {
                current == input.expected
            })? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Freshly join one private name to the actual borrowed original file.
    ///
    /// Uses the original readonly-open native admission without a new ancestry pass. The
    /// enclosing scope retains ancestry; this check returns no descriptor or identity verdict.
    /// `changed` constructs the caller's original typed ownership-refusal error.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe native custody, missing names or different original identity.
    pub fn require_same_file<E>(
        &self,
        name: impl AsRef<OsStr>,
        original: &File,
        changed: impl FnOnce() -> E,
    ) -> Result<(), E>
    where
        E: From<io::Error>,
    {
        let current = self
            .directory
            .open_readonly_native(checked_name(name.as_ref())?, false)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if FileIdentity::of(&current)? != FileIdentity::of(original)? {
            return Err(changed());
        }
        Ok(())
    }

    /// Read one admitted record into the caller's original owned allocation.
    ///
    /// The admission tuple converts the fresh length then allocates exactly that many bytes;
    /// both retain caller error types and allocation charging. The maximum independently bounds
    /// the admitted length before allocation. `mid` runs after exact read/EOF/snapshot checks and
    /// before the final named snapshot. The error tuple maps only initial-open errors and constructs
    /// original changed-read (`false`) or changed-namespace (`true`) errors. These factories cannot
    /// accept a failed native check. Only the first raw native open can yield `None`.
    ///
    /// This method returns the same single `Vec`, with no copy or zeroization change. The caller
    /// must close per-record ownership before decoding these bytes. Enclosing directory scope
    /// closes every ordinary result. No file, pathname, descriptor or writer is returned; callers
    /// keep batches read-only, without signing, publication, network effects or a validation cache.
    ///
    /// # Errors
    /// Preserves admission, allocation, original native I/O and caller custody errors. Refuses an
    /// inadmissible length/buffer, truncation, extension, changed snapshots or changed named objects.
    pub fn read_admitted<E>(
        &mut self,
        name: impl AsRef<OsStr>,
        maximum: usize,
        admission: (
            impl FnOnce(u64) -> Result<usize, E>,
            impl FnOnce(usize) -> Result<Vec<u8>, E>,
        ),
        mid: impl FnOnce(&Self) -> Result<(), E>,
        errors: (impl FnOnce(io::Error) -> E, impl FnOnce(bool) -> E),
    ) -> Result<Option<Vec<u8>>, E>
    where
        E: From<io::Error>,
    {
        let (initial_error, changed_error) = errors;
        let mut file = match checked_name(name.as_ref())
            .and_then(|name| self.directory.open_readonly_native(name, true))
            .map_err(initial_error)?
        {
            Some(file) => file,
            None => return Ok(None),
        };
        let before = FileSnapshot::of(&file, true)?;
        let extent = file.metadata()?.len();
        let (admit, allocate) = admission;
        let length = admit(extent)?;
        if length > maximum || u64::try_from(length).ok() != Some(extent) {
            return Err(
                io::Error::other("record length admission differs from its native extent").into(),
            );
        }
        let mut bytes = allocate(length)?;
        if bytes.len() != length {
            return Err(
                io::Error::other("record allocation differs from its admitted length").into(),
            );
        }
        file.read_exact(&mut bytes)?;
        let mut tail = [0_u8; 1];
        if !(file.read(&mut tail)? == 0 && FileSnapshot::of(&file, true)? == before) {
            return Err(changed_error(false));
        }
        mid(self)?;
        let current = self
            .directory
            .open_readonly_native(checked_name(name.as_ref())?, false)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if FileSnapshot::of(&current, true)? != before {
            return Err(changed_error(true));
        }
        Ok(Some(bytes))
    }
}

/// Borrowed read-only tree transaction over one retained native ancestry.
///
/// A descendant may omit only an identical complete shared native-handle prefix. Its own
/// directory suffix and every leaf retain fresh checks. No path, descriptor, writer or
/// validation verdict can be obtained from this view.
pub struct PrivateReadTreeScope<'tree> {
    directory: &'tree platform::Directory,
    _lease: &'tree mut (),
}

impl PrivateReadTreeScope<'_> {
    /// Consume one directory's lazy records and inventory in a closed tree read transaction.
    ///
    /// The existing shared-prefix admission checks the directory at entry and on every
    /// ordinary-result exit. Strict descendants omit only the complete identical native
    /// prefix; the anchor and nonshared owners retain full checks. Each file and census uses
    /// the original native producer. The borrowed reader cannot leave this callback.
    ///
    /// This synchronous callback is for read-only inspection, not writes, signing, publication
    /// or network actions. Intermediate suffix observations from nested read/entries brackets
    /// are consolidated: a change wholly restored within this bracket may be unseen. This is
    /// not an atomic snapshot, unwind guarantee, cache or currentness capability.
    ///
    /// # Errors
    /// Refuses unsafe native custody at entry or exit. Exit refusal takes precedence over
    /// every ordinary callback result, including a typed body error or observed absence.
    pub fn read_scope<T, E>(
        &mut self,
        directory: &PrivateDirectory,
        read: impl for<'scope> FnOnce(&mut PrivateReadScope<'scope>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<io::Error>,
    {
        self.with_directory_custody(directory, || {
            let mut lease = ();
            read(&mut PrivateReadScope {
                directory: &directory.inner,
                _lease: &mut lease,
            })
        })
    }

    /// Revalidate one retained directory within this closed read-only tree transaction.
    ///
    /// This empty read operation checks the original directory at entry and again at exit.
    /// Strict descendants share only the complete identical native prefix. The anchor,
    /// independently reopened and unrelated owners retain full ancestry checks.
    /// No reader, native owner or validation verdict is returned or retained.
    ///
    /// # Errors
    /// Refuses changed or unsafe native custody at either observation. This does not promise
    /// an atomic snapshot or detection of an interior change restored between observations.
    pub fn revalidate_directory(&self, directory: &PrivateDirectory) -> io::Result<()> {
        self.with_directory_custody(directory, || Ok(()))
    }

    // One closed owner for both actual reads and empty directory checks. Keep the native
    // relationship admission and all-result exit in this private recipe; no public nested
    // directory view or parallel read/entries/comparison implementation is retained.
    fn with_directory_custody<T, E>(
        &self,
        directory: &PrivateDirectory,
        read: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<io::Error>,
    {
        directory.inner.revalidate_in_tree(self.directory)?;
        let result = read();
        if let Err(error) = directory.inner.revalidate_in_tree(self.directory) {
            drop(result);
            return Err(error.into());
        }
        result
    }
}

impl PrivateDirectory {
    /// Open a private directory, creating missing components with private access at creation.
    ///
    /// Existing directories are validated, never silently hardened. Relative paths are resolved
    /// against the current directory; parent traversal and untrusted links are rejected.
    ///
    /// # Errors
    /// Refuses unsafe paths, permissions, filesystems, replaced ancestors, and native I/O errors.
    pub fn open_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            inner: platform::Directory::open(&absolute(path.as_ref())?, true)?,
        })
    }

    /// Open an existing owner-private directory without creating anything.
    ///
    /// # Errors
    /// Refuses a missing directory, unsafe custody or native I/O errors.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            inner: platform::Directory::open(&absolute(path.as_ref())?, false)?,
        })
    }

    /// Retain this same native directory custody, sharing its already-open ancestor handles.
    ///
    /// The original and returned owners are revalidated. This neither resolves another path nor
    /// creates directories, changes permissions, or duplicates retained directory handles. Native
    /// identity and ownership checks remain active on both owners for their entire lifetimes.
    ///
    /// # Errors
    /// Refuses changed directory or ancestor custody and native revalidation errors.
    pub fn retain(&self) -> io::Result<Self> {
        self.revalidate()?;
        let retained = Self {
            inner: self.inner.clone(),
        };
        retained.revalidate()?;
        Ok(retained)
    }

    /// The absolute retained directory path, for display and explicit child-process arguments.
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// Recheck custody and identity of the directory and its retained ancestors.
    ///
    /// # Errors
    /// Returns an error if custody changed or a native check fails.
    pub fn revalidate(&self) -> io::Result<()> {
        self.inner.revalidate()
    }

    /// List bounded direct child names through this retained directory authority.
    ///
    /// Names are sorted and portable; no child is followed or recursively visited. Callers
    /// hold their operation lock when the list controls a subsequent mutation.
    ///
    /// # Errors
    /// Refuses unsafe custody, invalid child names, excessive entries and native I/O errors.
    pub fn entries(&self, maximum: usize) -> io::Result<Vec<std::ffi::OsString>> {
        self.inner.entries(maximum)
    }

    /// Read this directory's retained kernel identity.
    ///
    /// # Errors
    /// Returns an error if custody changed or native identity cannot be read.
    pub fn identity(&self) -> io::Result<FileIdentity> {
        self.inner.identity()
    }

    /// Open or create one private child directory.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe existing custody and native I/O errors.
    pub fn ensure_child(&self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        let name = checked_name(name.as_ref())?;
        Ok(Self {
            inner: self.inner.child(name, true, false)?,
        })
    }

    /// Open one existing private child without creating anything.
    ///
    /// # Errors
    /// Refuses invalid names, missing children, unsafe custody and native errors.
    pub fn open_child(&self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        Ok(Self {
            inner: self
                .inner
                .child(checked_name(name.as_ref())?, false, false)?,
        })
    }

    /// Open an optional private child, accepting absence only at its first native open.
    ///
    /// Parent custody is checked before admission and after every ordinary failure or absence.
    /// A successful child closes the same full native ancestry as [`Self::open_child`]. Missing
    /// ancestors, replaced parents, and disappearance after child admission remain errors.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changed custody and all post-admission native errors.
    pub fn open_child_optional(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Self>> {
        self.inner
            .child_optional(checked_name(name.as_ref())?)
            .map(|child| child.map(|inner| Self { inner }))
    }

    /// Create one private child directory, failing if its name already exists.
    ///
    /// # Errors
    /// Refuses invalid or existing names, changed custody and native I/O errors.
    pub fn create_child(&self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        let name = checked_name(name.as_ref())?;
        Ok(Self {
            inner: self.inner.child(name, true, true)?,
        })
    }

    /// Atomically publish a complete private child through this retained directory authority.
    ///
    /// This delegates the same closed publication as [`OwnerDirectory::publish_private_child`]
    /// while sharing this owner's native handles and preserving all private ancestor policies.
    /// It does not reopen the parent pathname or weaken existing custody. Existing destinations
    /// are never replaced; a failure after publication requires reconciliation before retry.
    ///
    /// # Errors
    /// Refuses invalid or duplicate names, file-count bounds, changed custody and native errors.
    pub fn publish_private_child(
        &self,
        name: impl AsRef<OsStr>,
        files: &[(&str, &[u8])],
    ) -> io::Result<Self> {
        OwnerDirectory {
            inner: self.inner.clone(),
        }
        .publish_private_child(name, files)
    }

    /// Read one private single-link regular file under an explicit byte limit.
    ///
    /// Secret storage allocates the declared length once and is zeroized on all return paths.
    /// A metadata, identity, length, or namespace change fails the read.
    ///
    /// # Errors
    /// Refuses unsafe custody, oversized or changing files, and native I/O errors.
    pub fn read(&self, name: impl AsRef<OsStr>, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        let name = checked_name(name.as_ref())?;
        self.inner.read(name, maximum, true)
    }

    /// Read one optional private file with absence restricted to its first native open.
    ///
    /// Present bytes retain the same sole zeroized allocation and native leaf admission as
    /// [`Self::read`]. Later disappearance or other native refusal remains an error. Directory
    /// custody is checked once at entry and once after every ordinary result; present native
    /// file owners remain live through the exit check. Exit refusal takes precedence.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changed custody, oversized files and native errors.
    /// Returns `None` only for initial native absence under stable directory custody.
    pub fn read_optional(
        &self,
        name: impl AsRef<OsStr>,
        maximum: usize,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        self.inner.read_optional(name.as_ref(), maximum, true)
    }

    /// Inspect consecutive retained directories inside one closed ancestry transaction.
    ///
    /// The full original anchor chain is checked at entry and unconditionally after every
    /// ordinary callback result. Shared native-handle prefixes are checked by those fences;
    /// each descendant's remaining suffix and each leaf retain fresh checks in original
    /// order. Nonshared owners fall back to full validation rather than trusting path text.
    ///
    /// Intermediate common-prefix observations are consolidated. Changes completely restored
    /// inside this callback may go unobserved; this is not an atomic tree snapshot or an
    /// unwind guarantee. Callbacks must stay read-only, without signing, publication, network
    /// effects or plaintext retention. Captured side effects cannot be excluded by Rust.
    /// Complete source inventories and independent later graph/currentness checks remain
    /// caller-owned. No descriptor, scope capability or validation cache leaves the bracket.
    ///
    /// # Errors
    /// Refuses unsafe or changed full anchor custody. Exit refusal drops and takes precedence
    /// over every ordinary body result, including semantic errors or an observed absence.
    pub fn read_tree_scope<T, E>(
        &self,
        read: impl for<'tree> FnOnce(&mut PrivateReadTreeScope<'tree>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<io::Error>,
    {
        self.revalidate()?;
        let mut lease = ();
        let result = read(&mut PrivateReadTreeScope {
            directory: &self.inner,
            _lease: &mut lease,
        });
        if let Err(error) = self.revalidate() {
            drop(result);
            return Err(error.into());
        }
        result
    }

    /// Consume ordered private records inside one read-only directory transaction.
    ///
    /// The callback reads and validates records lazily through an opaque borrowed view.
    /// Every leaf retains fresh private native admission, snapshot, namespace and extent checks;
    /// an admitted owned result also preserves the caller's allocation order. Directory and ancestor
    /// custody are checked at entry and unconditionally after every ordinary callback result;
    /// an exit refusal takes precedence over a semantic error, absence or completed result.
    /// This Result boundary does not promise an exit check during unwinding.
    ///
    /// Intermediate ancestry observations are intentionally replaced by the closed entry
    /// and exit observations. Changes completely restored inside the callback need not be
    /// detected; this is not an atomic multi-file snapshot. Callers must keep the callback
    /// read-only, without signing, publication, network effects or retaining additional plaintext copies.
    /// The callback's captured values cannot be prevented from causing such effects by Rust's
    /// type system. Source inventories and later freshness boundaries remain caller-owned.
    ///
    /// # Errors
    /// Refuses unsafe or changed directory custody and native entry/exit errors. Otherwise
    /// returns the callback's original typed error; empty callbacks still check custody.
    pub fn read_scope<T, E>(
        &self,
        read: impl for<'scope> FnOnce(&mut PrivateReadScope<'scope>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<io::Error>,
    {
        self.revalidate()?;
        let mut lease = ();
        let result = read(&mut PrivateReadScope {
            directory: &self.inner,
            _lease: &mut lease,
        });
        if let Err(error) = self.revalidate() {
            drop(result);
            return Err(error.into());
        }
        result
    }

    /// Compare ordered original bytes using one closed private-directory read transaction.
    ///
    /// Each file independently passes the same native private ownership, link, metadata,
    /// namespace and byte-bound checks as [`Self::read`]. Only one zeroized transient read is
    /// owned at a time; no descriptor, plaintext or validation capability leaves this method.
    /// The first stable byte mismatch returns `false` without reading later records.
    ///
    /// Directory and ancestor custody are checked at entry and unconditionally at exit,
    /// including a mismatch or ordinary read error. An exit custody failure takes precedence.
    /// Intermediate ancestry observations between files are not retained: this is a closed
    /// read transaction, not an atomic simultaneous snapshot of all original inputs.
    ///
    /// # Errors
    /// Refuses invalid leaf names, unsafe or changed native custody, oversized or changing
    /// files, allocation refusal and native I/O errors. Empty slices still check custody.
    pub fn compare_files(&self, inputs: &[PrivateFileComparison<'_>]) -> io::Result<bool> {
        self.with_read_custody(|| {
            let mut lease = ();
            PrivateReadScope {
                directory: &self.inner,
                _lease: &mut lease,
            }
            .compare_files(inputs)
        })
    }

    // The closed shipping comparison supplies its entire body internally. No caller callback,
    // file descriptor or bytes capability can cross this private bracket. Keep ordinary body
    // failure separate from the unconditional exit: changed custody always wins.
    fn with_read_custody(&self, read: impl FnOnce() -> io::Result<bool>) -> io::Result<bool> {
        self.revalidate()?;
        let result = read();
        self.revalidate()?;
        result
    }

    /// Stage, sync and atomically publish bytes with private access from the first write.
    ///
    /// An error after publication can mean durability is uncertain. Callers must reconcile the
    /// destination before retrying operations whose contents represent irreversible intent.
    ///
    /// # Errors
    /// Refuses unsafe custody, create-new collisions, failed native writes or failed durability.
    pub fn write_atomic(
        &self,
        name: impl AsRef<OsStr>,
        bytes: &[u8],
        mode: PublishMode,
    ) -> io::Result<()> {
        let name = checked_name(name.as_ref())?;
        self.inner.write_atomic(name, bytes, mode, true)
    }

    /// Discard bounded unpublished files left by an interrupted [`Self::write_atomic`].
    ///
    /// The caller must hold its original exclusive operation lock. Every required file must
    /// already exist; this operation never initializes committed state. The complete directory
    /// inventory and writable private single-link custody are checked before any removal. Only
    /// this crate's exact staging names are eligible; file bodies are never allocated or read.
    /// At most sixteen required files and sixteen staged files may be inspected.
    ///
    /// # Errors
    /// Refuses missing required files, unknown names, unsafe or changed custody, excessive
    /// staging count/extent, and native I/O errors. Once deletion starts, an I/O error can leave
    /// a partially cleaned staging set; committed files are never removed or replaced.
    pub fn reconcile_atomic_staging(
        &self,
        required_names: &[&str],
        maximum_staged: usize,
        maximum_bytes: usize,
    ) -> io::Result<usize> {
        if required_names.is_empty() || required_names.len() > 16 || maximum_staged > 16 {
            return Err(invalid("atomic staging inventory bound exceeded"));
        }
        for (index, name) in required_names.iter().enumerate() {
            checked_name(OsStr::new(name))?;
            if name.starts_with(".iroha-fs-") || required_names[..index].contains(name) {
                return Err(invalid("invalid required atomic staging inventory"));
            }
        }
        self.inner
            .reconcile_atomic_staging(required_names, maximum_staged, maximum_bytes)
    }

    /// Remove one exact writable private regular file and durably publish its absence.
    ///
    /// Returns `false` only when the first native open observes absence under stable retained
    /// directory custody. The caller must hold its exclusive operation and runtime ownership
    /// gates so cooperative writers cannot replace the selected name during removal. Every
    /// admitted file must remain owner-private, regular and single-linked; no bytes are read.
    /// This is not an atomic Unix check-and-unlink against hostile same-user replacement.
    /// Windows compatible read handles may retain native pending deletion until they close.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changed files/ancestors and native I/O errors. Late
    /// disappearance is an error. An error after removal can mean durability is uncertain;
    /// deletion is never rolled back. Exit custody refusal overrides every ordinary result.
    pub fn remove_private(&self, name: impl AsRef<OsStr>) -> io::Result<bool> {
        let name = checked_name(name.as_ref())?;
        self.revalidate()?;
        let result = self.inner.remove_private_native(name);
        #[cfg(test)]
        private_remove_tests::before_exit();
        self.revalidate()?;
        result
    }

    /// Open or create a private read/write lock file without truncation or taking its lock.
    ///
    /// The caller uses [`File::try_lock`] and retains the handle for the ownership lifetime.
    /// Cloned handles may be inherited by supervised children to preserve that ownership.
    ///
    /// # Errors
    /// Refuses unsafe custody, invalid names and native I/O errors.
    pub fn open_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        self.inner.open_mutable(checked_name(name.as_ref())?, false)
    }

    /// Create a new private read/write lock file, refusing an existing name.
    ///
    /// # Errors
    /// Refuses existing names, unsafe custody and native I/O errors.
    pub fn create_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        self.inner
            .open_exact_lock(checked_name(name.as_ref())?, true)
    }

    /// Open an existing private read/write lock without creating or truncating it.
    ///
    /// # Errors
    /// Refuses missing names, unsafe custody and native I/O errors.
    pub fn open_existing_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        self.inner
            .open_exact_lock(checked_name(name.as_ref())?, false)
    }

    /// Remove this exact empty directory and durably publish its absence in the parent.
    ///
    /// All descendant handles must be dropped first. Nonempty directories are refused.
    /// An error after removal can indicate uncertain durability and requires reconciliation.
    ///
    /// # Errors
    /// Refuses live descendants, nonempty or replaced directories and native I/O errors.
    pub fn remove_empty(self) -> io::Result<()> {
        self.inner.remove_empty()
    }

    /// Open a private ownership lock suitable for retaining in supervised child processes.
    ///
    /// Windows additionally denies other writable opens while any inherited handle remains.
    /// The caller still acquires the advisory lock and retains every returned handle.
    ///
    /// # Errors
    /// Refuses unsafe custody, competing native ownership and native I/O errors.
    pub fn open_ownership_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        self.inner.open_ownership_lock(checked_name(name.as_ref())?)
    }

    /// Open or create an append-only private log file without truncating an existing log.
    ///
    /// Unix callers use [`File::sync_all`] at their durability boundary. Windows appends use
    /// native write-through; that append-only handle does not request general write access.
    ///
    /// # Errors
    /// Refuses unsafe custody, invalid names and native I/O errors.
    pub fn open_append(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        self.inner.open_mutable(checked_name(name.as_ref())?, true)
    }

    /// Open an existing private regular file for read-only streaming, such as a live log tail.
    ///
    /// The descriptor retains its exact object; concurrently appended bytes are permitted, so
    /// this does not promise an immutable snapshot. Keep this directory alive during access.
    ///
    /// # Errors
    /// Refuses missing files, unsafe custody, invalid names and native I/O errors.
    pub fn open_read(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        self.inner.open_readonly(checked_name(name.as_ref())?)
    }

    /// Retain one private child together with this directory's existing ancestor authority.
    ///
    /// This opens only the child descriptor. The returned reader shares the already-retained
    /// ancestor handles and continues to reject changed paths, links and nonprivate custody.
    ///
    /// # Errors
    /// Refuses invalid names, missing children, unsafe custody and native errors.
    pub fn open_retained_private(&self, name: impl AsRef<OsStr>) -> io::Result<RetainedFile> {
        Ok(RetainedFile {
            inner: self
                .inner
                .open_retained(checked_name(name.as_ref())?, true, false)?,
        })
    }

    /// Publish this exact completed directory under an absent sibling name.
    ///
    /// Callers must validate and sync the complete tree first and drop all retained descendants.
    /// Existing destinations are never replaced. The returned directory retains its identity
    /// and the updated path. An error after native publication may require reconciliation.
    ///
    /// # Errors
    /// Refuses replacement mode, existing names, live descendants, changed custody and I/O errors.
    pub fn rename_to_sibling(self, name: impl AsRef<OsStr>, mode: PublishMode) -> io::Result<Self> {
        if mode != PublishMode::CreateNew {
            return Err(invalid(
                "directory publication requires an absent destination",
            ));
        }
        Ok(Self {
            inner: self
                .inner
                .rename_to_sibling(checked_name(name.as_ref())?, mode)?,
        })
    }

    /// Remove this directory's contents, retaining exactly the listed direct child files.
    ///
    /// The caller must hold its persistent operation and runtime locks. Retained names must
    /// identify private regular files. Traversal never follows links, and refuses foreign
    /// ownership, shared writable entries, or more than 100,000 entries. Errors may leave a
    /// partially cleared directory; the directory and retained lock identities stay intact.
    ///
    /// # Errors
    /// Refuses unsafe or missing retained files, unsafe removal entries, bounds and I/O errors.
    pub fn clear_contents_preserving(&self, names: &[&str]) -> io::Result<()> {
        let preserved = names
            .iter()
            .map(|name| checked_name(OsStr::new(name)))
            .collect::<io::Result<Vec<_>>>()?;
        self.inner.clear_contents_preserving(&preserved)
    }

    /// Complete the native directory-publication durability boundary.
    ///
    /// # Errors
    /// Returns an error if custody changed or native durability cannot be completed.
    pub fn sync(&self) -> io::Result<()> {
        self.inner.sync()
    }
}

/// Read-only directory authority retaining every native ancestor and exact namespace.
/// This creates no directory, file or writable owner capability.
#[derive(Debug)]
pub struct ReaderDirectory {
    inner: platform::Directory,
}
impl ReaderDirectory {
    /// Retain an existing regular directory under genuine native custody.
    /// # Errors
    /// Refuses links, unsafe native permissions, foreign mutation or unavailable storage.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            inner: platform::Directory::open_reader(&absolute(path.as_ref())?)?,
        })
    }
    /// Return this retained directory's absolute native path.
    pub fn path(&self) -> &Path {
        self.inner.path()
    }
    /// Retain one existing directory child using this reader's original ancestor handles.
    ///
    /// This opens only one read-only directory handle. No writable directory capability,
    /// file or namespace is created, and every original ancestor remains revalidated.
    ///
    /// # Errors
    /// Refuses invalid names, links, unsafe custody, changed ancestors and native errors.
    pub fn open_child(&self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.child_reader(checked_name(name.as_ref())?)?,
        })
    }

    /// Retain one private child while sharing this reader's existing ancestor handles.
    /// # Errors
    /// Refuses invalid names, unsafe private custody, replaced paths and native errors.
    pub fn open_retained_private(&self, name: impl AsRef<OsStr>) -> io::Result<RetainedFile> {
        Ok(RetainedFile {
            inner: self
                .inner
                .open_retained(checked_name(name.as_ref())?, true, false)?,
        })
    }
    /// Retain one regular child while sharing this reader's existing ancestor handles.
    /// # Errors
    /// Refuses invalid names, foreign mutation, links, replaced paths and native errors.
    pub fn open_retained_regular(&self, name: impl AsRef<OsStr>) -> io::Result<RetainedFile> {
        Ok(RetainedFile {
            inner: self
                .inner
                .open_retained(checked_name(name.as_ref())?, false, false)?,
        })
    }
    /// Recheck the original directory and all retained ancestors.
    /// # Errors
    /// Refuses replaced namespace or changed native custody.
    pub fn revalidate(&self) -> io::Result<()> {
        self.inner.revalidate()
    }
    /// Capture exact native directory metadata while retaining its original authority.
    /// # Errors
    /// Refuses changed custody or native I/O errors.
    pub fn snapshot(&self) -> io::Result<FileSnapshot> {
        Ok(FileSnapshot {
            inner: self.inner.snapshot_directory()?,
        })
    }
}

/// A retained project directory that permits readers while excluding foreign mutation.
///
/// Newly created directories and published files are owner-private. Existing project roots may
/// retain their reader permissions; this type never hardens or changes an existing directory.
#[derive(Debug)]
pub struct OwnerDirectory {
    inner: platform::Directory,
}

impl OwnerDirectory {
    /// Open an existing safe project directory and retain all of its ancestor identities.
    ///
    /// # Errors
    /// Refuses missing directories, unsafe ownership or write access, links and native errors.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            inner: platform::Directory::open_owned(&absolute(path.as_ref())?, false)?,
        })
    }

    /// Open a safe project directory, creating missing components privately.
    ///
    /// # Errors
    /// Refuses unsafe existing custody, links, traversal and native creation errors.
    pub fn open_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            inner: platform::Directory::open_owned(&absolute(path.as_ref())?, true)?,
        })
    }

    /// Return the retained absolute project path.
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// Recheck retained custody and every ancestor's identity.
    ///
    /// # Errors
    /// Returns an error for replaced paths, changed access or native I/O failures.
    pub fn revalidate(&self) -> io::Result<()> {
        self.inner.revalidate()
    }

    /// List bounded direct child names through this retained project authority.
    ///
    /// Names are sorted; no child is followed or recursively visited. This validates the
    /// directory during enumeration, but callers must retain and validate any children they use.
    ///
    /// # Errors
    /// Refuses changed custody, invalid child names, excessive entries and native I/O errors.
    pub fn entries(&self, maximum: usize) -> io::Result<Vec<std::ffi::OsString>> {
        self.inner.entries(maximum)
    }

    /// Read this directory's retained kernel identity.
    ///
    /// # Errors
    /// Returns an error if custody changed or native identity cannot be read.
    pub fn identity(&self) -> io::Result<FileIdentity> {
        self.inner.identity()
    }

    /// Open one existing safe child without creating anything.
    ///
    /// # Errors
    /// Refuses invalid names, missing children, unsafe custody and native errors.
    pub fn open_child(&self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        Ok(Self {
            inner: self
                .inner
                .child_owned(checked_name(name.as_ref())?, false, false)?,
        })
    }

    /// Open one safe child or create it privately if absent.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe existing custody and native errors.
    pub fn ensure_child(&self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        Ok(Self {
            inner: self
                .inner
                .child_owned(checked_name(name.as_ref())?, true, false)?,
        })
    }

    /// Create one private child, rejecting an existing name.
    ///
    /// # Errors
    /// Refuses invalid names, existing children, unsafe custody and native errors.
    pub fn create_child(&self, name: impl AsRef<OsStr>) -> io::Result<Self> {
        Ok(Self {
            inner: self
                .inner
                .child_owned(checked_name(name.as_ref())?, true, true)?,
        })
    }

    /// Open an existing private child through this retained project parent.
    ///
    /// The child's native owner shares every original ancestor descriptor with this parent;
    /// no absolute path is reopened. The parent keeps its existing reader policy, while the
    /// child independently requires current-user private custody.
    ///
    /// # Errors
    /// Refuses invalid names, missing children, unsafe custody and native observation errors.
    pub fn open_private_child(&self, name: impl AsRef<OsStr>) -> io::Result<PrivateDirectory> {
        Ok(PrivateDirectory {
            inner: self
                .inner
                .child(checked_name(name.as_ref())?, false, false)?,
        })
    }

    /// Open an optional private child through the original retained project parent.
    ///
    /// Only its first native child open admits absence. Success closes the complete shared
    /// ancestry; every native admission failure or absence closes the original parent. Missing
    /// ancestors, replaced parents and loss after admission remain errors.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe custody and all post-admission native errors.
    pub fn open_private_child_optional(
        &self,
        name: impl AsRef<OsStr>,
    ) -> io::Result<Option<PrivateDirectory>> {
        self.inner
            .child_optional(checked_name(name.as_ref())?)
            .map(|child| child.map(|inner| PrivateDirectory { inner }))
    }

    /// Create a private child under this retained safe owner directory.
    ///
    /// # Errors
    /// Refuses existing names, unsafe custody and native I/O errors.
    pub fn create_private_child(&self, name: impl AsRef<OsStr>) -> io::Result<PrivateDirectory> {
        Ok(PrivateDirectory {
            inner: self.inner.child(checked_name(name.as_ref())?, true, true)?,
        })
    }

    /// Atomically publish a complete private directory containing the supplied direct files.
    ///
    /// Every file and the staging directory are synced before the destination becomes visible.
    /// Existing destinations are never replaced. A crash before publication can leave a private
    /// temporary sibling, but cannot leave a partial directory at the requested name. Empty bytes
    /// may initialize a lock file; callers acquire it only after this method returns.
    ///
    /// # Errors
    /// Rejects duplicate/invalid names, more than 128 files, unsafe custody and native failures.
    /// An error after publication can mean uncertain durability; reconcile the destination before
    /// retrying rather than treating it as absent or deleting it.
    pub fn publish_private_child(
        &self,
        name: impl AsRef<OsStr>,
        files: &[(&str, &[u8])],
    ) -> io::Result<PrivateDirectory> {
        let name = checked_name(name.as_ref())?;
        if files.is_empty() || files.len() > 128 {
            return Err(invalid("completed private directory requires 1..128 files"));
        }
        let mut names = std::collections::BTreeSet::new();
        for (file, _) in files {
            if !names.insert(checked_name(OsStr::new(file))?) {
                return Err(invalid("duplicate completed private directory filename"));
            }
        }
        if self.inner.child_optional(name)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "private destination already exists",
            ));
        }
        let mut staging = None;
        for _ in 0..32 {
            match self.create_private_child(temporary_name()) {
                Ok(directory) => {
                    staging = Some(directory);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let directory =
            staging.ok_or_else(|| io::Error::other("cannot allocate private directory staging"))?;
        for (file, bytes) in files {
            directory.write_atomic(file, bytes, PublishMode::CreateNew)?;
        }
        // The nonempty loop's final atomic write already synced this staging directory.
        // No owner mutation intervenes before the native rename revalidates and publishes it.
        directory.rename_to_sibling(name, PublishMode::CreateNew)
    }

    /// Read one bounded stable source file through this retained directory.
    ///
    /// # Errors
    /// Refuses links, shared write access, oversized or changed files and native errors.
    pub fn read_regular(
        &self,
        name: impl AsRef<OsStr>,
        maximum: usize,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        self.inner
            .read(checked_name(name.as_ref())?, maximum, false)
    }

    /// Read an optional regular child through this retained project authority.
    ///
    /// Only its first native open can admit absence. The original regular-file policy and
    /// sole zeroized allocation remain; custody closes after every ordinary result.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe or changed custody, excessive extents and late native errors.
    pub fn read_regular_optional(
        &self,
        name: impl AsRef<OsStr>,
        maximum: usize,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        self.inner.read_optional(name.as_ref(), maximum, false)
    }

    /// Read an optional private child through this retained project authority.
    ///
    /// The project directory retains its reader policy; the file independently requires the
    /// same owner-private native custody as [`read_private`]. No directory is reopened.
    /// Only initial native leaf absence yields `None`, after the ordinary-result custody exit.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe private custody, excessive extents and late native errors.
    pub fn read_private_optional(
        &self,
        name: impl AsRef<OsStr>,
        maximum: usize,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        self.inner.read_optional(name.as_ref(), maximum, true)
    }

    /// Publish private bytes atomically, optionally replacing one safe owned regular file.
    ///
    /// # Errors
    /// Refuses unsafe targets, create-new collisions, native writes and durability failures.
    pub fn write_atomic(
        &self,
        name: impl AsRef<OsStr>,
        bytes: &[u8],
        mode: PublishMode,
    ) -> io::Result<()> {
        self.inner
            .write_atomic(checked_name(name.as_ref())?, bytes, mode, false)
    }

    /// Open or create a private lock file without locking or truncating it.
    ///
    /// # Errors
    /// Refuses invalid names, unsafe custody and native errors.
    pub fn open_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
        self.inner.open_mutable(checked_name(name.as_ref())?, false)
    }

    /// Complete this directory's native publication durability boundary.
    ///
    /// # Errors
    /// Returns an error if custody changed or durability cannot be completed.
    pub fn sync(&self) -> io::Result<()> {
        self.inner.sync()
    }

    /// Publish this exact completed directory under an absent sibling name.
    ///
    /// Callers validate and sync the tree first and drop every retained descendant. Existing
    /// destinations are never replaced. Native publication preserves the directory identity.
    ///
    /// # Errors
    /// Refuses replacement mode, existing names, live descendants, changed custody and I/O errors.
    pub fn rename_to_sibling(self, name: impl AsRef<OsStr>, mode: PublishMode) -> io::Result<Self> {
        if mode != PublishMode::CreateNew {
            return Err(invalid(
                "directory publication requires an absent destination",
            ));
        }
        Ok(Self {
            inner: self
                .inner
                .rename_to_sibling(checked_name(name.as_ref())?, mode)?,
        })
    }
}

/// An exact regular file with retained no-follow ancestor and object authority.
///
/// Callers bound streaming reads and validate content snapshots as required by their format.
/// [`Self::revalidate`] checks custody and identity; it permits intentional writes to this object.
#[derive(Debug)]
pub struct RetainedFile {
    inner: platform::RetainedFile,
}

/// Read-only native custody for an explicitly selected Cargo build input.
///
/// Cargo may publish a native executable with a hardlink to its dependency output. This
/// owner accepts that initial link count while retaining the complete native snapshot,
/// selected name and ancestors. Every later link-count, content, metadata or custody change
/// is refused. It supplies no publication or private-file authority and exposes no raw file.
/// Installed programs and ordinary/private retained files remain single-link owners.
#[derive(Debug)]
pub struct RetainedBuildInput {
    inner: platform::RetainedFile,
}

impl RetainedBuildInput {
    /// Retain a regular build input through read-only, no-follow native custody.
    /// # Errors
    /// Refuses unsafe ownership or permissions, indirect files, changing custody and native errors.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = absolute(path.as_ref())?;
        let name = checked_name(
            path.file_name()
                .ok_or_else(|| invalid("build input has no name"))?,
        )?;
        let directory = platform::Directory::open_reader(
            path.parent()
                .ok_or_else(|| invalid("build input has no parent"))?,
        )?;
        Ok(Self {
            inner: directory.open_build_input(name)?,
        })
    }

    /// Recheck the original descriptor, exact link count, selected name and all ancestors.
    /// # Errors
    /// Refuses any captured native custody or metadata change and genuine native errors.
    pub fn revalidate(&self) -> io::Result<()> {
        self.inner.revalidate()
    }

    /// Capture complete native metadata after independently checking original custody.
    /// # Errors
    /// Refuses changed originals, names or ancestors and native errors.
    pub fn snapshot(&self) -> io::Result<FileSnapshot> {
        Ok(FileSnapshot {
            inner: self.inner.snapshot()?,
        })
    }

    /// Read the length of the revalidated original build input.
    /// # Errors
    /// Refuses changed native custody or metadata and native errors.
    pub fn len(&self) -> io::Result<u64> {
        self.revalidate()?;
        let length = self.inner.file().metadata()?.len();
        self.revalidate()?;
        Ok(length)
    }

    /// Whether the revalidated original build input is empty.
    /// # Errors
    /// Refuses changed custody or native errors.
    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|length| length == 0)
    }

    /// Read permissions for native executable admission while preserving original custody.
    /// # Errors
    /// Refuses changed custody or native errors.
    pub fn permissions(&self) -> io::Result<std::fs::Permissions> {
        self.revalidate()?;
        let permissions = self.inner.file().metadata()?.permissions();
        self.revalidate()?;
        Ok(permissions)
    }
}

// Streaming never transfers the raw descriptor or its namespace authority. The caller must
// finish each bounded/hash operation with snapshot/revalidate before accepting its bytes.
impl Read for RetainedBuildInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.file_mut().read(buffer)
    }
}

impl Seek for RetainedBuildInput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.file_mut().seek(position)
    }
}

/// One explicitly selected regular file and its original native custody.
///
/// Selection resolves the parent directory while leaving the final component unfollowed.
/// The retained file, its resolved name and every native ancestor remain inseparable across
/// later work. This type retains no plaintext and cannot be cloned into a second selection.
#[derive(Debug)]
pub struct SelectedRegularFile {
    path: PathBuf,
    original: RetainedFile,
}

impl SelectedRegularFile {
    /// Capture a direct regular file before work which must preserve its original identity.
    /// Relative paths and parent components are resolved at selection time. A final-component
    /// link, unsafe custody or a nonregular object is refused by the native owner.
    /// # Errors
    /// Returns genuine native path, ownership, identity or access failures.
    pub fn capture(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let name = path
            .file_name()
            .ok_or_else(|| invalid("selected file has no name"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let path = parent.canonicalize()?.join(name);
        let original = RetainedFile::open_regular(&path)?;
        original.revalidate()?;
        Ok(Self { path, original })
    }

    /// The original resolved path, never a caller-supplied replacement for its descriptor.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Recheck the original immutable regular file and every retained ancestor.
    /// # Errors
    /// Refuses replacement, mutation, changed custody and genuine native errors.
    pub fn revalidate(&self) -> io::Result<()> {
        self.original.revalidate()
    }

    /// Read the original descriptor from offset zero within an exact byte limit.
    /// Every call uses explicit offsets; repeated or concurrent reads do not rely on the
    /// descriptor's shared cursor. A single stack byte probes EOF at the original extent
    /// before the final native fence. The returned buffer is ordinary owned file input,
    /// suitable for a compiler or public artifact, rather than private secret storage.
    /// # Errors
    /// Refuses an oversized or changing original, truncation and genuine native errors.
    pub fn read(&self, maximum: usize) -> io::Result<Vec<u8>> {
        self.revalidate()?;
        let length = self.original.file().metadata()?.len();
        let length =
            usize::try_from(length).map_err(|_| invalid("selected file exceeds its bound"))?;
        if length > maximum {
            return Err(invalid("selected file exceeds its bound"));
        }
        let mut bytes = vec![0; length];
        read_exact_at(self.original.file(), &mut bytes, 0)?;
        let mut extra = [0_u8; 1];
        if read_at(self.original.file(), &mut extra, length as u64)? != 0 {
            return Err(invalid(
                "selected file changed while its bounded bytes were read",
            ));
        }
        self.revalidate()?;
        Ok(bytes)
    }

    /// Observe the original length after rechecking native immutable custody.
    /// # Errors
    /// Refuses a changed original or genuine native errors.
    pub fn len(&self) -> io::Result<u64> {
        self.revalidate()?;
        let length = self.original.file().metadata()?.len();
        self.revalidate()?;
        Ok(length)
    }

    /// Whether the original immutable file is empty.
    /// # Errors
    /// Refuses a changed original or genuine native errors.
    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|length| length == 0)
    }
}

impl RetainedFile {
    /// Open an existing regular source for read-only streaming.
    ///
    /// # Errors
    /// Refuses unsafe ownership, shared writes, links, multiple links and native errors.
    pub fn open_regular(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open(path.as_ref(), false, false)
    }

    /// Retain one public original with Unix 0644/0444 or the equivalent native Windows
    /// read access without foreign mutation. This authenticates custody, never its contents.
    /// # Errors
    /// Refuses unsafe permission shape, links, changed ancestors or native errors.
    pub fn open_public_original(path: impl AsRef<Path>) -> io::Result<Self> {
        let original = Self::open_regular(path)?;
        platform::validate_public_original(original.file())?;
        original.revalidate()?;
        Ok(original)
    }

    /// Open an existing private regular file for read-only streaming.
    ///
    /// # Errors
    /// Refuses nonprivate or unsafe custody, multiple links and native errors.
    pub fn open_private(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open(path.as_ref(), true, false)
    }

    /// Create a new private regular file with read/write access, retaining its exact identity.
    ///
    /// # Errors
    /// Refuses existing names, unsafe ancestors, links and native creation errors.
    pub fn create_new_private(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open(path.as_ref(), true, true)
    }

    fn open(path: &Path, private: bool, create_new: bool) -> io::Result<Self> {
        let path = absolute(path)?;
        let name = checked_name(
            path.file_name()
                .ok_or_else(|| invalid("file path has no name"))?,
        )?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("file path has no parent"))?;
        let directory = if create_new {
            platform::Directory::open_owned(parent, false)?
        } else {
            platform::Directory::open_reader(parent)?
        };
        Ok(Self {
            inner: directory.open_retained(name, private, create_new)?,
        })
    }

    /// Borrow the exact descriptor while retaining every ancestor.
    pub fn file(&self) -> &File {
        self.inner.file()
    }

    /// Borrow the descriptor mutably for bounded streaming or seek operations.
    pub fn file_mut(&mut self) -> &mut File {
        self.inner.file_mut()
    }

    /// Sync a completed writer and freeze its exact metadata and content snapshot.
    ///
    /// The original descriptor and all ancestors remain retained. Subsequent revalidation rejects
    /// changes to the sealed file; no close/reopen gap is introduced.
    ///
    /// # Errors
    /// Refuses changed custody, failed synchronization and native snapshot failures.
    pub fn seal(self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.seal()?,
        })
    }

    /// Capture exact native identity and metadata after revalidating this retained file.
    ///
    /// # Errors
    /// Refuses custody, namespace or sealed-content changes and native snapshot failures.
    pub fn snapshot(&self) -> io::Result<FileSnapshot> {
        Ok(FileSnapshot {
            inner: self.inner.snapshot()?,
        })
    }

    /// Recheck ownership, link count, path and retained object identity after streaming.
    ///
    /// # Errors
    /// Refuses any custody or namespace change and native I/O failures.
    pub fn revalidate(&self) -> io::Result<()> {
        self.inner.revalidate()
    }

    /// Return the exact retained object's kernel identity.
    ///
    /// # Errors
    /// Returns a native error if the retained identity cannot be read.
    pub fn identity(&self) -> io::Result<FileIdentity> {
        self.inner.identity()
    }
}

/// Read a private current-owner file through retained no-follow native handles.
///
/// # Errors
/// Refuses unsafe custody, oversized or changing files, and native I/O errors.
pub fn read_private(path: impl AsRef<Path>, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    read_external(path.as_ref(), maximum, true)
}

/// Read a bounded stable regular source file without requiring private reader permissions.
///
/// The file must still have one link and belong to the current user or the operating system;
/// writable-by-others sources and unsafe ancestors are rejected.
///
/// # Errors
/// Refuses unsafe custody, oversized or changing files, and native I/O errors.
pub fn read_regular(path: impl AsRef<Path>, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    read_external(path.as_ref(), maximum, false)
}

fn read_external(path: &Path, maximum: usize, private: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let path = absolute(path)?;
    let name = checked_name(
        path.file_name()
            .ok_or_else(|| invalid("file path has no name"))?,
    )?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("file path has no parent"))?;
    platform::read_external(parent, name, maximum, private)
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid(
            "a nonempty path without parent traversal is required",
        ));
    }
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    if path.components().count() > 128 {
        return Err(invalid("path exceeds the native custody depth bound"));
    }
    Ok(path)
}

fn checked_name(name: &OsStr) -> io::Result<&OsStr> {
    let path = Path::new(name);
    let mut parts = path.components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(invalid("file name must be one normal path component"));
    }
    // Use one portable namespace: reject alternate streams, Win32 trimming and reserved devices
    // on every host so artifacts cannot change identity when a workspace moves platforms.
    let text = name
        .to_str()
        .ok_or_else(|| invalid("private file name must be UTF-8"))?;
    if text.contains([':', '\\', '/', '<', '>', '|', '"', '?', '*'])
        || text.chars().any(|character| character <= '\u{1f}')
        || text.ends_with(['.', ' '])
    {
        return Err(invalid("file name has a nonportable spelling"));
    }
    // Compare borrowed spelling instead of allocating an uppercase copy for each open.
    let stem = text.split('.').next().unwrap_or_default();
    let named_device = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved));
    let numbered_device = stem.get(..3).is_some_and(|prefix| {
        prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")
    }) && stem.get(3..).is_some_and(|n| {
        (n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9')) || matches!(n, "¹" | "²" | "³")
    });
    if named_device || numbered_device {
        return Err(invalid("reserved device name is not a regular file name"));
    }
    Ok(name)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn changed() -> io::Error {
    io::Error::other("retained filesystem identity or custody changed")
}

fn temporary_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        ".iroha-fs-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn is_atomic_staging_name(name: &OsStr) -> bool {
    let Some(body) = name
        .to_str()
        .and_then(|name| name.strip_prefix(".iroha-fs-"))
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, ordinal)) = body.split_once('-') else {
        return false;
    };
    pid.parse::<u32>()
        .is_ok_and(|value| value != 0 && value.to_string() == pid)
        && ordinal
            .parse::<u64>()
            .is_ok_and(|value| value.to_string() == ordinal)
}

fn validate_atomic_staging_inventory(
    names: &[std::ffi::OsString],
    required: &[&str],
    maximum_staged: usize,
) -> io::Result<()> {
    for name in required {
        if !names
            .iter()
            .any(|present| present.as_os_str() == OsStr::new(name))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "required atomic staging inventory is missing",
            ));
        }
    }
    let mut staged = 0usize;
    for name in names {
        if required
            .iter()
            .any(|required| name.as_os_str() == OsStr::new(required))
        {
            continue;
        }
        if !is_atomic_staging_name(name) || staged >= maximum_staged {
            return Err(invalid("unexpected atomic staging inventory"));
        }
        staged += 1;
    }
    Ok(())
}

// Only the first raw leaf open can produce this absence. Retain its original native error
// so required readers preserve the complete error, including errno and message.
enum NativeReadOutcome<T> {
    InitialAbsence(io::Error),
    Present(T),
}

fn bounded_read(file: &mut File, length: u64, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let length = usize::try_from(length).map_err(|_| invalid("file exceeds the read bound"))?;
    if length > maximum {
        return Err(invalid("file exceeds the read bound"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("bounded file allocation refused"))?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)?;
    let mut extra = zeroize::Zeroizing::new([0u8; 1]);
    if file.read(extra.as_mut())? != 0 {
        return Err(changed());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod native_offset_custody_tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn offset_read_then_tail_append_retains_exact_native_original() {
        let temporary = tempfile::tempdir().unwrap();
        let root = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
        let mut file = root.create_lock("journal").unwrap();
        file.try_lock().unwrap();
        file.write_all(b"first").unwrap();
        file.sync_all().unwrap();
        let identity = FileIdentity::of(&file).unwrap();
        let mut buffer = [0; 3];
        read_exact_at(&file, &mut buffer, 1).unwrap();
        assert_eq!(&buffer, b"irs");
        // The real native journal always selects and checks its acknowledged tail first.
        assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), 5);
        file.write_all(b"second").unwrap();
        file.sync_all().unwrap();
        let mut complete = [0; 11];
        read_exact_at(&file, &mut complete, 0).unwrap();
        assert_eq!(&complete, b"firstsecond");
        assert_eq!(FileIdentity::of(&file).unwrap(), identity);
        assert!(FileSnapshot::private_journal(&file).is_ok());
        assert!(read_exact_at(&file, &mut [0; 1], 11).is_err());
        root.revalidate().unwrap();
    }

    #[test]
    fn reader_directory_keeps_namespace_and_original_public_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let owner = OwnerDirectory::open(&root).unwrap();
        owner
            .write_atomic("public", b"original", PublishMode::CreateNew)
            .unwrap();
        let directory = ReaderDirectory::open(&root).unwrap();
        let namespace = directory.snapshot().unwrap();
        let original = RetainedFile::open_regular(root.join("public")).unwrap();
        let before = original.snapshot().unwrap();
        let mut bytes = [0; 8];
        read_exact_at(original.file(), &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"original");
        assert_eq!(original.snapshot().unwrap(), before);
        assert_eq!(directory.snapshot().unwrap(), namespace);
        assert!(
            owner
                .write_atomic("public", b"replacement", PublishMode::CreateNew)
                .is_err()
        );
        assert_eq!(original.snapshot().unwrap(), before);
    }
}

#[cfg(test)]
mod comparison_tests;

#[cfg(test)]
mod build_input_tests;

#[cfg(test)]
mod read_scope_tests;

#[cfg(test)]
mod tree_scope_tests;

#[cfg(test)]
mod admitted_read_tests;

#[cfg(test)]
mod optional_read_tests;

#[cfg(test)]
mod optional_child_tests;

#[cfg(test)]
mod tree_read_producer_tests;

#[cfg(test)]
mod owner_private_child_tests;

#[cfg(test)]
mod private_remove_tests;
