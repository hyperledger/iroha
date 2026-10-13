//! Prepared paths and a unique durable attempt claim retaining partial filesystem progress.

use super::super::{Directory, seat_export, validate_directory};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, PrepaidBufferError,
    RetainedPayload,
};
use std::{
    alloc::Layout,
    ffi::OsString,
    fs::File,
    io::Write as _,
    os::unix::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::MetadataExt as _,
    },
    path::{Component, Path, PathBuf},
    time::Instant,
};

#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    #[error(transparent)]
    Backing(#[from] PrepaidBufferError),
    #[error("original DKG claim descriptor operation failed")]
    Io(#[source] std::io::Error),
    #[error("original DKG claim directory revalidation failed")]
    Directory(#[source] seat_export::ExportError),
    #[error("DKG claim creation completed without a provable original directory identity")]
    AmbiguousCreation(#[source] std::io::Error),
    #[error("the exact DKG attempt is already claimed")]
    AlreadyClaimed(#[source] std::io::Error),
    #[error("the original DKG claim directory identity changed")]
    Custody,
    #[error("the original DKG attempt deadline elapsed")]
    Deadline,
    #[error("the original DKG claim is in another phase")]
    Phase,
}

struct Name {
    bytes: [u8; 86],
    len: usize,
}
impl Name {
    fn new(attempt: &[u8; 32], seat: u16) -> Result<Self, ClaimError> {
        if !(1..=31).contains(&seat) {
            return Err(ClaimError::Phase);
        }
        let mut bytes = [0; 86];
        let capacity = bytes.len();
        let mut remaining = &mut bytes[..];
        remaining
            .write_all(b"attempt-")
            .map_err(|_| ClaimError::Phase)?;
        for byte in attempt {
            write!(remaining, "{byte:02x}").map_err(|_| ClaimError::Phase)?;
        }
        write!(remaining, "-seat-{seat}").map_err(|_| ClaimError::Phase)?;
        let len = capacity - remaining.len();
        Ok(Self { bytes, len })
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("ASCII attempt name")
    }
}

struct PreparedPath {
    bytes: ChargedBuffer<u8>,
    ledger: ChargedBuffer<AllocationCharge>,
}
impl PreparedPath {
    fn new(parts: &[&[u8]], budget: &AllocationBudget) -> Result<Self, ClaimError> {
        let bytes = parts
            .iter()
            .try_fold(0usize, |n, part| n.checked_add(part.len()))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_layouts([
            Layout::array::<u8>(bytes).map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<AllocationCharge>(1).map_err(|_| AllocationRefusal::DemandOverflow)?,
        ])?;
        let mut path = ChargedBuffer::from_reservation(bytes, &mut reservation)?;
        let ledger = ChargedBuffer::from_reservation(1, &mut reservation)?;
        for part in parts {
            path.append(part).expect("checked exact path backing");
        }
        Ok(Self {
            bytes: path,
            ledger,
        })
    }
    /// Move the exact path allocation into its canonical Directory field.
    #[allow(unsafe_code)]
    fn bind(mut self, file: File, budget: &AllocationBudget) -> RetainedPayload<Directory> {
        // SAFETY: OsString::from_vec and PathBuf::from move this exact byte
        // allocation. No growth, clone, or fallible operation precedes binding.
        let (bytes, charge) = unsafe { self.bytes.into_allocation_parts() };
        self.ledger.push_reserved(charge);
        let directory = Directory {
            path: PathBuf::from(OsString::from_vec(bytes)),
            file,
        };
        // SAFETY: Directory owns only this path allocation; File is an OS handle.
        // The one-entry ledger and its backing are same-pool and retire after it.
        match unsafe { RetainedPayload::try_new(directory, self.ledger, budget) } {
            Ok(directory) => directory,
            Err((directory, ledger, error)) => {
                drop(directory);
                drop(ledger);
                panic!("prepared original path owner invariant: {error}");
            }
        }
    }
}

#[derive(Clone, Copy)]
struct CreatedIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
const fn device_identity_from_raw(device: rustix::fs::Dev) -> u64 {
    device
}
#[cfg(target_os = "macos")]
#[expect(
    clippy::cast_sign_loss,
    reason = "filesystem identity uses MetadataExt's signed dev_t bit pattern"
)]
const fn device_identity_from_raw(device: rustix::fs::Dev) -> u64 {
    // Preserve the platform's exact MetadataExt::dev() conversion, including
    // valid high-bit device identities; this is not a numeric range admission.
    device as u64
}

/// One source-owned attempt claim. Creation is never repeated after success.
/// Dropping this owner deliberately leaves a successfully created claim behind.
pub(super) struct PreparedAttemptClaim {
    root: RetainedPayload<Directory>,
    child_path: Option<PreparedPath>,
    child: Option<RetainedPayload<Directory>>,
    opened: Option<File>,
    name: Name,
    created: Option<CreatedIdentity>,
    mkdir_completed: bool,
    durable: bool,
    terminal: bool,
    deadline: Instant,
    budget: AllocationBudget,
}
impl PreparedAttemptClaim {
    /// Prepare both actual pathname allocations and pin every trusted root ancestor.
    /// This performs no mkdir and consumes no protocol randomness.
    pub(super) fn new(
        root: &Path,
        attempt: &[u8; 32],
        seat: u16,
        deadline: Instant,
        budget: &AllocationBudget,
    ) -> Result<Self, ClaimError> {
        let raw = root.as_os_str().as_bytes();
        if !root.is_absolute()
            || raw.contains(&0)
            || (raw != b"/"
                && raw[1..]
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || part == b"." || part == b".."))
        {
            return Err(ClaimError::Custody);
        }
        let name = Name::new(attempt, seat)?;
        let root_path = PreparedPath::new(&[raw], budget)?;
        let child_path = PreparedPath::new(
            &[
                raw,
                if raw == b"/" { b"" } else { b"/" },
                name.as_str().as_bytes(),
            ],
            budget,
        )?;
        let flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC;
        let mut file = File::from(
            rustix::fs::open("/", flags, rustix::fs::Mode::empty())
                .map_err(|error| ClaimError::Io(error.into()))?,
        );
        validate_directory(&file.metadata().map_err(ClaimError::Io)?)
            .map_err(|_| ClaimError::Custody)?;
        for component in root.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    file = File::from(
                        rustix::fs::openat(&file, name, flags, rustix::fs::Mode::empty())
                            .map_err(|error| ClaimError::Io(error.into()))?,
                    );
                    validate_directory(&file.metadata().map_err(ClaimError::Io)?)
                        .map_err(|_| ClaimError::Custody)?;
                }
                _ => return Err(ClaimError::Custody),
            }
        }
        let metadata = file.metadata().map_err(ClaimError::Io)?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(ClaimError::Custody);
        }
        Ok(Self {
            root: root_path.bind(file, budget),
            child_path: Some(child_path),
            child: None,
            opened: None,
            name,
            created: None,
            mkdir_completed: false,
            durable: false,
            terminal: false,
            deadline,
            budget: budget.clone(),
        })
    }

    fn revalidate(directory: &Directory) -> Result<(), ClaimError> {
        seat_export::revalidate_directory(directory).map_err(ClaimError::Directory)
    }
    fn create(&mut self) -> Result<(), ClaimError> {
        if self.mkdir_completed {
            return Ok(());
        }
        Self::revalidate(self.root.get())?;
        match rustix::fs::mkdirat(
            &self.root.get().file,
            self.name.as_str(),
            rustix::fs::Mode::from_raw_mode(0o700),
        ) {
            Ok(()) => self.mkdir_completed = true,
            Err(rustix::io::Errno::EXIST) => {
                self.terminal = true;
                return Err(ClaimError::AlreadyClaimed(rustix::io::Errno::EXIST.into()));
            }
            Err(error) => return Err(ClaimError::Io(error.into())),
        }
        let created = match rustix::fs::statat(
            &self.root.get().file,
            self.name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(created) => created,
            Err(error) => {
                self.terminal = true;
                return Err(ClaimError::AmbiguousCreation(error.into()));
            }
        };
        if rustix::fs::FileType::from_raw_mode(created.st_mode) != rustix::fs::FileType::Directory {
            self.terminal = true;
            return Err(ClaimError::Custody);
        }
        self.created = Some(CreatedIdentity {
            device: device_identity_from_raw(created.st_dev),
            inode: created.st_ino,
        });
        Ok(())
    }
    fn pin(&mut self) -> Result<(), ClaimError> {
        if self.child.is_some() {
            return Ok(());
        }
        let expected = self.created.ok_or(ClaimError::Phase)?;
        if self.opened.is_none() {
            let flags = rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC;
            match rustix::fs::openat(
                &self.root.get().file,
                self.name.as_str(),
                flags,
                rustix::fs::Mode::empty(),
            ) {
                Ok(file) => self.opened = Some(File::from(file)),
                Err(error) => {
                    self.terminal = true;
                    return Err(ClaimError::AmbiguousCreation(error.into()));
                }
            }
        }
        let metadata = self
            .opened
            .as_ref()
            .expect("opened original child")
            .metadata()
            .map_err(ClaimError::Io)?;
        if metadata.dev() != expected.device
            || metadata.ino() != expected.inode
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            self.terminal = true;
            return Err(ClaimError::Custody);
        }
        let path = self.child_path.take().ok_or(ClaimError::Phase)?;
        let file = self.opened.take().expect("original pinned child");
        self.child = Some(path.bind(file, &self.budget));
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn stop_before_sync(&mut self) -> Result<(), ClaimError> {
        self.create()?;
        self.pin()
    }
    /// Original native expiry may only shorten this held claim deadline.
    pub(super) fn tighten_deadline(&mut self, deadline: Instant) {
        self.deadline = self.deadline.min(deadline);
    }
    /// Resume creation/pinning/fsync through the same held root and exact attempt name.
    pub(super) fn make_durable(&mut self) -> Result<(), ClaimError> {
        if self.terminal {
            return Err(ClaimError::Custody);
        }
        if Instant::now() >= self.deadline {
            return Err(ClaimError::Deadline);
        }
        let result = (|| {
            Self::revalidate(self.root.get())?;
            self.create()?;
            self.pin()?;
            let child = self.child.as_ref().ok_or(ClaimError::Phase)?.get();
            Self::revalidate(child)?;
            child.file.sync_all().map_err(ClaimError::Io)?;
            self.root.get().file.sync_all().map_err(ClaimError::Io)?;
            Self::revalidate(self.root.get())?;
            Self::revalidate(child)?;
            self.durable = true;
            Ok(())
        })();
        if matches!(
            result,
            Err(ClaimError::Custody | ClaimError::Directory(seat_export::ExportError::Custody))
        ) {
            self.terminal = true;
        }
        result
    }
    pub(super) fn existing(&self) -> Result<bool, ClaimError> {
        Self::revalidate(self.root.get())?;
        match rustix::fs::statat(
            &self.root.get().file,
            self.name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(ClaimError::Io(e.into())),
        }
    }
    /// Pin an existing name for authenticated read only; never claim it or publish into it yet.
    pub(super) fn open_existing(&mut self) -> Result<(), ClaimError> {
        if self.mkdir_completed {
            return Err(ClaimError::Phase);
        }
        if let Some(child) = self.child.as_ref() {
            Self::revalidate(child.get())?;
            return Ok(());
        }
        Self::revalidate(self.root.get())?;
        let named = rustix::fs::statat(
            &self.root.get().file,
            self.name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|e| ClaimError::Io(e.into()))?;
        self.created = Some(CreatedIdentity {
            device: device_identity_from_raw(named.st_dev),
            inode: named.st_ino,
        });
        self.pin()?;
        Self::revalidate(self.child.as_ref().ok_or(ClaimError::Phase)?.get())?;
        Ok(())
    }
    pub(super) fn read_directory(&self) -> Option<&Directory> {
        self.child.as_ref().map(RetainedPayload::get)
    }
    pub(super) fn identity(&self) -> Result<([u64; 4], [u8; 32]), ClaimError> {
        let root = self.root.get().file.metadata().map_err(ClaimError::Io)?;
        let child = self.child.as_ref().ok_or(ClaimError::Phase)?.get();
        Self::revalidate(self.root.get())?;
        Self::revalidate(child)?;
        let metadata = child.file.metadata().map_err(ClaimError::Io)?;
        Ok((
            [root.dev(), root.ino(), metadata.dev(), metadata.ino()],
            iroha_crypto::Hash::new(child.path.as_os_str().as_bytes()).into(),
        ))
    }
    /// Authenticate the original AEAD-bound inode/path after private record verification.
    pub(super) fn authenticate_restored(
        &mut self,
        identity: [u64; 4],
        path_hash: [u8; 32],
        deadline: Instant,
    ) -> Result<(), ClaimError> {
        if self.identity()? != (identity, path_hash) {
            self.terminal = true;
            return Err(ClaimError::Custody);
        }
        self.deadline = self.deadline.min(deadline);
        if Instant::now() >= self.deadline {
            return Err(ClaimError::Deadline);
        }
        // The original mkdir can be visible after a crash before its directory
        // barriers. Re-sync the held child/root before adopting publication rights.
        let child = self.child.as_ref().ok_or(ClaimError::Phase)?.get();
        child.file.sync_all().map_err(ClaimError::Io)?;
        self.root.get().file.sync_all().map_err(ClaimError::Io)?;
        if self.identity()? != (identity, path_hash) {
            self.terminal = true;
            return Err(ClaimError::Custody);
        }
        if Instant::now() >= self.deadline {
            return Err(ClaimError::Deadline);
        }
        self.mkdir_completed = true;
        self.durable = true;
        Ok(())
    }

    pub(super) fn directory(&self) -> Option<&Directory> {
        self.durable
            .then(|| self.child.as_ref().expect("durable original child").get())
    }
}

#[cfg(test)]
mod tests;
