/// Helper to reduce boilerplate of file operations while preserving path context.
struct FileWrap {
    path: PathBuf,
    file: std::fs::File,
}
impl std::fmt::Debug for FileWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileWrap")
            .field("path", &self.path)
            .field("file", &self.file)
            .finish()
    }
}
impl FileWrap {
    fn open_with(path: PathBuf, configure: impl FnOnce(&mut std::fs::OpenOptions)) -> Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        configure(&mut options);
        let file = options.open(path.clone()).add_err_context(&path)?;
        Ok(Self { path, file })
    }
    fn open_read_write(path: PathBuf) -> Result<Self> {
        Self::open_with(path, |opts| {
            opts.write(true).read(true).create(true).truncate(false);
        })
    }
    /// Reopen an initialized journal without creating a replacement if it disappeared.
    fn open_existing_read_write(path: PathBuf) -> Result<Self> {
        let file = open_existing_regular_file(&path, "canonical Kura journal", true)
            .add_err_context(&path)?;
        Ok(Self { path, file })
    }
    fn open_read_only(path: PathBuf) -> Result<Self> {
        let file =
            open_read_only_regular_file(&path, "canonical Kura journal").add_err_context(&path)?;
        Ok(Self { path, file })
    }
    fn try_io<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut std::fs::File) -> std::io::Result<T>,
    {
        let value = f(&mut self.file).add_err_context(&self.path)?;
        Ok(value)
    }
}
fn open_read_only_regular_file(path: &Path, description: &str) -> std::io::Result<std::fs::File> {
    open_existing_regular_file(path, description, false)
}
#[cfg(unix)]
fn open_existing_regular_file(
    path: &Path,
    description: &str,
    writable: bool,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let flags =
        (rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
            .bits();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(i32::try_from(flags).expect("open flags fit platform c_int"))
        .open(path)?;
    ensure_input_is_regular(file, description)
}
#[cfg(windows)]
fn open_existing_regular_file(
    path: &Path,
    description: &str,
    writable: bool,
) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    ensure_input_is_regular(file, description)
}
#[cfg(not(any(unix, windows)))]
fn open_existing_regular_file(
    _path: &Path,
    _description: &str,
    _writable: bool,
) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "secure existing Kura file admission is unavailable on this platform",
    ))
}
fn ensure_input_is_regular(
    file: std::fs::File,
    description: &str,
) -> std::io::Result<std::fs::File> {
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("{description} is not a regular file"),
        ))
    }
}
fn create_dir_all_with_context(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|err| Error::MkDir(err, path.to_path_buf()))
}
fn sync_dir(path: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(path)?;
    file.sync_all()
}
fn remove_commit_marker_temp_and_sync(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::IO(error, path.to_path_buf())),
    }
    if let Some(parent) = path.parent() {
        sync_dir(parent).map_err(|error| Error::IO(error, parent.to_path_buf()))?;
    }
    Ok(())
}
fn sync_bound_progress_intent_file(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_BOUND_PROGRESS_INTENT_FILE_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected bound progress append-intent sync failure",
        ));
    }
    file.sync_data()
}
fn sync_bound_progress_append_data(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_BOUND_PROGRESS_APPEND_DATA_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected journaled progress payload sync failure",
        ));
    }
    file.sync_data()
}
fn sync_bound_progress_append_index(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_BOUND_PROGRESS_APPEND_INDEX_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected journaled progress index sync failure",
        ));
    }
    file.sync_data()
}
fn sync_native_amx_latest_index_recovery_temp(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_NATIVE_AMX_LATEST_INDEX_RECOVERY_TEMP_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected Native AMX latest-index recovery temporary sync failure",
        ));
    }
    file.sync_all()
}
fn sync_indexed_sidecar_data(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_INDEXED_SIDECAR_DATA_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected indexed sidecar data sync failure",
        ));
    }
    file.sync_data()
}
fn sync_indexed_sidecar_initial_data(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_INDEXED_SIDECAR_INITIAL_DATA_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected initial indexed sidecar data sync failure",
        ));
    }
    file.sync_data()
}
fn rollback_unindexed_sidecar_payload(
    file: &std::fs::File,
    offset: u64,
    data_path: &Path,
    kind: &str,
) -> bool {
    if let Err(err) = file.set_len(offset) {
        iroha_logger::warn!(
            ?err,
            ?data_path,
            offset,
            kind,
            "failed to truncate unpublished sidecar payload"
        );
        return false;
    }
    if let Err(err) = file.sync_data() {
        iroha_logger::warn!(
            ?err,
            ?data_path,
            offset,
            kind,
            "failed to synchronize unpublished sidecar payload rollback"
        );
        return false;
    }
    true
}
fn sync_indexed_sidecar_index(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_INDEXED_SIDECAR_INDEX_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected indexed sidecar index sync failure",
        ));
    }
    file.sync_data()
}
fn sync_indexed_sidecar_dir(path: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(path)?;
    sync_indexed_sidecar_dir_handle(&file)
}
fn sync_indexed_sidecar_dir_handle(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_INDEXED_SIDECAR_DIR_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected indexed sidecar directory sync failure",
        ));
    }
    file.sync_all()
}
fn sync_progress_sidecar_ancestor_dir_handle(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_PROGRESS_SIDECAR_ANCESTOR_SYNC_AT.with(|slot| {
        let Some(mut fault) = slot.get() else {
            return false;
        };
        if fault.remaining_to_target > 0 {
            fault.remaining_to_target -= 1;
            slot.set(Some(fault));
            return false;
        }
        fault.failures_remaining -= 1;
        if fault.failures_remaining == 0 {
            slot.set(None);
        } else {
            fault.remaining_to_target = fault.target_index;
            slot.set(Some(fault));
        }
        true
    }) {
        return Err(std::io::Error::other(
            "injected progress sidecar ancestor directory sync failure",
        ));
    }
    file.sync_all()
}
fn sync_sidecar_promotion_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_SIDECAR_PROMOTION_DIR_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected sidecar promotion directory sync failure",
        ));
    }
    sync_dir(path)
}
fn sync_sidecar_temp_marker_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_SIDECAR_TEMP_MARKER_DIR_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected sidecar temp marker directory sync failure",
        ));
    }
    sync_dir(path)
}
fn numbered_norito_sidecar_height(path: &Path) -> Option<u64> {
    let file_name = path.file_name()?.to_str()?;
    let height = file_name
        .strip_suffix(".norito")
        .or_else(|| file_name.strip_suffix(".norito.tmp"))?;
    height.parse().ok()
}
#[cfg(test)]
const CONFIGURED_PRIMARY_OPEN_IDENTITY_SWAP_SUFFIX: &str = ".configured-primary-open-identity-swap";
#[cfg(test)]
const CONFIGURED_PRIMARY_OPEN_IDENTITY_DISPLACED_SUFFIX: &str =
    ".configured-primary-open-identity-displaced";
#[cfg(test)]
fn configured_primary_open_identity_test_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        Error::IO(
            std::io::Error::new(
                ErrorKind::InvalidInput,
                "configured-primary identity test path has no file name",
            ),
            path.to_path_buf(),
        )
    })?;
    let mut sibling_name = file_name.to_os_string();
    sibling_name.push(suffix);
    Ok(path.with_file_name(sibling_name))
}
/// Deterministically model an inode replacement after authenticated preflight.
///
/// Test fixtures opt in by placing a replacement at the reserved sibling path.
/// The constructor must reject that replacement at its next identity boundary,
/// before opening it for mutation.
#[cfg(test)]
fn configured_primary_open_identity_swap_boundary(path: &Path) -> Result<()> {
    let replacement = configured_primary_open_identity_test_path(
        path,
        CONFIGURED_PRIMARY_OPEN_IDENTITY_SWAP_SUFFIX,
    )?;
    match std::fs::symlink_metadata(&replacement) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::IO(error, replacement)),
    }
    let displaced = configured_primary_open_identity_test_path(
        path,
        CONFIGURED_PRIMARY_OPEN_IDENTITY_DISPLACED_SUFFIX,
    )?;
    if std::fs::symlink_metadata(&displaced).is_ok() {
        return Err(Error::IO(
            std::io::Error::new(
                ErrorKind::AlreadyExists,
                "configured-primary identity test displaced path already exists",
            ),
            displaced,
        ));
    }
    std::fs::rename(path, &displaced).map_err(|error| Error::IO(error, path.to_path_buf()))?;
    if let Err(error) = std::fs::rename(&replacement, path) {
        let _ = std::fs::rename(&displaced, path);
        return Err(Error::IO(error, replacement));
    }
    Ok(())
}
pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;
/// Error variants for persistent storage logic
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum Error {
    /// Production Kura store root resolved to an empty path
    EmptyStoreRoot,
    /// Another exact geometry operation retains the journal and its instance references ({wait}).
    LaneGeometryAttemptBusy {
        /// Release all physical locks before awaiting the original operation.
        wait: RawGeometryWait,
    },
    /// A partially applied geometry owner was abandoned; restart recovery is required.
    LaneGeometryAttemptAbandoned,
    /// Lane geometry requires Strict startup to complete canonical storage recovery
    LaneGeometryCanonicalRecoveryRequired,
    /// Lane geometry instance creation for lane {lane_id} at operation {operation} requires Strict startup recovery: {source}
    LaneGeometryInstanceRecoveryRequired {
        /// Original operation's exact lane coordinate.
        lane_id: LaneId,
        /// Original zero-based operation cursor, retained without advancing.
        operation: usize,
        /// The original failure after native provisioning may have changed storage.
        #[source]
        source: Arc<Error>,
    },

    /// Failed reading/writing {1:?} from disk: {0}
    IO(#[source] std::io::Error, PathBuf),
    /// Lane-geometry publication failed and exact prior-journal restoration was not proven: publication={publication}; restoration={restoration}
    LaneGeometryPublicationRestoreFailed {
        /// Original catalog-publication error.
        publication: String,
        /// Exact prior-journal restoration error.
        restoration: String,
    },
    /// Failed to create the directory {1:?}
    MkDir(#[source] std::io::Error, PathBuf),
    /// Original canonical block decoder outcome, including local admission refusal.
    BlockDecode(#[from] norito::core::DecodeAttemptError),
    /// The original native source pool or physical allocator refused the raw frame backing.
    NativeFrameAllocation(#[source] iroha_allocation::ChargedBufferError),
    /// Failed to frame or deframe Norito payload
    NoritoFrame(#[from] norito::core::Error),

    /// Submitted block wire at existing canonical height `{height}` differs from durable canonical bytes
    CanonicalBlockWireMismatch {
        /// Existing height whose header matched but complete block bytes differed.
        height: u64,
    },
    /// DA block rewrite commit state is unknown after an I/O failure: {detail}
    DaBlockRewriteCommitStateUnknown {
        /// Failure details retained for fail-stop diagnostics.
        detail: String,
    },
    /// Canonical block publication is committed but requires restart recovery: {detail}
    CanonicalBlockCommittedRecoveryRequired {
        /// Failure details retained for fail-stop diagnostics.
        detail: String,
    },
    /// Canonical Kura storage is fail-stop poisoned after an ambiguous rewrite publication
    CanonicalStoragePoisoned,
    /// Kura auxiliary history `{subsystem}` is unavailable after emergency Fast startup; restart in Strict mode
    EmergencyFastAuxiliaryUnavailable {
        /// Deferred inventory or derived index that cannot safely be represented as empty.
        subsystem: &'static str,
    },

    /// Retired first-release-incompatible Kura artifact remains at `{path:?}`
    RetiredKuraArtifact {
        /// Exact retired artifact that must be removed by the operator.
        path: PathBuf,
    },

    /// Failed to allocate buffer
    Alloc(#[from] std::collections::TryReserveError),
    /// Tried reading block data out of bounds: start `{start_block_height}`, count `{block_count}`
    OutOfBoundsBlockRead {
        /// The block height from which the read was supposed to start
        start_block_height: u64,
        /// The actual block count
        block_count: usize,
    },
    /// Another live Kura instance owns the store-root lock at {0}
    Locked(PathBuf),
    /// Block writer thread unavailable; persistence notifications cannot be delivered
    BlockWriterUnavailable,
    /// Block writer thread faulted and stopped processing new blocks: {0}
    BlockWriterFaulted(String),
    /// Conversion of wide integer into narrow integer failed. This error cannot be caught at compile time at present
    IntConversion(#[from] std::num::TryFromIntError),
    /// Blocks count differs hashes file and index file
    HashesFileHeightMismatch,
    /// Block index length {length} exceeds strict-init guard {limit} bytes
    CorruptedBlockLength {
        /// Length of the corrupted block index entry in bytes.
        length: u64,
        /// Configured upper bound for permissible block index entries.
        limit: u64,
    },
    /// Block range start {start} + length {length} exceeds data file length `{data_len}` bytes
    CorruptedBlockRange {
        /// Offset in the data file where the range begins.
        start: u64,
        /// Number of bytes that were requested to be read starting at `start`.
        length: u64,
        /// Total number of bytes available in the data file.
        data_len: u64,
    },
    /// Kura storage budget exceeded: limit {limit} bytes, used {used} bytes, required {required} bytes
    StorageBudgetExceeded {
        /// Configured storage cap in bytes.
        limit: u64,
        /// Bytes currently occupied by the block store.
        used: u64,
        /// Bytes required after accepting the next block.
        required: u64,
    },
    /// Block height gap: expected next canonical height `{expected_next_height}`, got `{actual_height}`
    BlockHeightGap {
        /// Next height Kura can append without leaving a gap.
        expected_next_height: u64,
        /// Height declared by the block being stored.
        actual_height: u64,
    },
    /// Block height conflict at `{height}`: stored hash `{expected:?}`, incoming hash `{actual:?}`
    BlockHeightConflict {
        /// Conflicting block height.
        height: u64,
        /// Hash already stored at that height.
        expected: HashOf<BlockHeader>,
        /// Hash of the incoming block.
        actual: HashOf<BlockHeader>,
    },

    /// Kura requires restart to complete an interrupted durable prune transaction
    PruneRecoveryRequired,
}
impl Error {
    /// Return whether this error proves that the canonical publication boundary cannot be
    /// retried safely by the live consensus process.
    #[must_use]
    pub(crate) const fn requires_restart_recovery(&self) -> bool {
        matches!(
            self,
            Self::DaBlockRewriteCommitStateUnknown { .. }
                | Self::CanonicalBlockCommittedRecoveryRequired { .. }
                | Self::CanonicalStoragePoisoned
                | Self::PruneRecoveryRequired
        )
    }
}
trait AddErrContextExt<T> {
    type Context;
    fn add_err_context(self, context: &Self::Context) -> Result<T, Error>;
}
impl<T> AddErrContextExt<T> for Result<T, std::io::Error> {
    type Context = PathBuf;
    fn add_err_context(self, path: &Self::Context) -> Result<T, Error> {
        self.map_err(|e| Error::IO(e, path.clone()))
    }
}
