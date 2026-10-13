// Included at Kura module scope. This owner never constructs or repairs runtime Kura.

/// Failure of bounded immutable Kura evidence admission or consumption.
#[derive(Debug)]
pub enum CanonicalKuraEvidenceError {
    /// A structural, ordering, identity or declared bound contract failed.
    Invalid(&'static str),
    /// The sole canonical decoder retains the original attempt and its resource origin.
    Decode(norito::core::DecodeAttemptError),
    /// The original file-buffer allocation failed; it has no pool release source.
    Allocator(std::collections::TryReserveError),
    /// A read-only operating-system operation failed.
    Io(std::io::Error),
    /// The platform lacks this owner's descriptor-relative no-follow implementation.
    UnsupportedPlatform,
}
impl std::fmt::Display for CanonicalKuraEvidenceError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(code) => write!(output, "canonical Kura evidence: {code}"),
            Self::Decode(_) => {
                output.write_str("canonical Kura evidence: canonical decode failure")
            }
            Self::Allocator(_) => {
                output.write_str("canonical Kura evidence: file-buffer allocation failure")
            }
            Self::Io(_) => output.write_str("canonical Kura evidence: read-only I/O failure"),
            Self::UnsupportedPlatform => {
                output.write_str("canonical Kura evidence: unsupported secure reader platform")
            }
        }
    }
}
impl std::error::Error for CanonicalKuraEvidenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Allocator(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<std::io::Error> for CanonicalKuraEvidenceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
/// Result of a read-only tooling operation; it conveys no consensus finality authority.
pub type CanonicalKuraEvidenceResult<T> = std::result::Result<T, CanonicalKuraEvidenceError>;

/// Independently supplied finite bounds for one immutable evidence session.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalKuraEvidenceLimits {
    /// First one-based requested carrier height, inclusive.
    pub first_height: u64,
    /// Last requested height, inclusive; every height in the interval must be read.
    pub last_height: u64,
    /// Maximum complete journal height admitted during the initial index scan.
    pub max_committed_blocks: u64,
    /// Maximum underlying blocks.data length, including unrequested committed heights.
    pub max_store_data_bytes: u64,
    /// Maximum canonical SignedBlockWire bytes for one requested carrier (at most 32 MiB).
    pub max_carrier_bytes: usize,
    /// Cumulative returned complete native carrier bytes (at most 256 MiB).
    pub max_output_bytes: u64,
    /// Maximum cumulative owned allocation per decoder invocation (at most 512 MiB).
    pub max_decode_allocation_bytes: usize,
    /// Independently expected Unix uid of the supplied immediate directory and all four files.
    pub owner_uid: u32,
}
impl CanonicalKuraEvidenceLimits {
    fn validate(self) -> CanonicalKuraEvidenceResult<()> {
        evidence_require(
            self.first_height > 0
                && self.first_height <= self.last_height
                && self.last_height <= self.max_committed_blocks
                && self.max_committed_blocks <= 1_000_000,
            "height bounds",
        )?;
        evidence_require(
            self.max_store_data_bytes > 0
                && self.max_store_data_bytes <= 2 * 1024 * 1024 * 1024
                && self.max_carrier_bytes > 0
                && self.max_carrier_bytes <= 32 * 1024 * 1024
                && self.max_output_bytes > 0
                && self.max_output_bytes <= 256 * 1024 * 1024
                && self.max_decode_allocation_bytes > 0
                && self.max_decode_allocation_bytes <= 512 * 1024 * 1024,
            "byte or frame bounds",
        )
    }
    fn decode_limits(self, size: usize) -> norito::DecodeLimits {
        let canonical = norito::canonical_decode_limits(size);
        norito::DecodeLimits::new(
            canonical.max_sequence_elements(),
            canonical.max_field_bytes(),
            canonical.max_total_elements(),
            canonical
                .max_total_allocated_bytes()
                .min(self.max_decode_allocation_bytes),
            64,
        )
    }
}
fn evidence_require(condition: bool, reason: &'static str) -> CanonicalKuraEvidenceResult<()> {
    if condition {
        Ok(())
    } else {
        Err(CanonicalKuraEvidenceError::Invalid(reason))
    }
}

/// Consuming completion of disk admission, complete reads and final identity checks.
///
/// This non-serializable token is not an anchored finality or useful-effect proof.
/// The downstream authenticator must independently complete before publishing evidence.
pub struct CanonicalKuraEvidenceComplete {
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    sources: canonical_evidence_read_only_fs::Sources,
    committed_height: u64,
    carrier_count: u64,
    output_bytes: u64,
}
impl std::fmt::Debug for CanonicalKuraEvidenceComplete {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanonicalKuraEvidenceComplete")
            .field("committed_height", &self.committed_height)
            .field("carrier_count", &self.carrier_count)
            .field("output_bytes", &self.output_bytes)
            .finish_non_exhaustive()
    }
}
impl CanonicalKuraEvidenceComplete {
    /// Recheck the exact read-only source descriptors retained by successful finish.
    ///
    /// This grants no write handle or finality authority. A publication owner must
    /// retain this capability through its final durability check.
    ///
    /// # Errors
    ///
    /// Returns an error if retained source identities or contents changed,
    /// source revalidation fails, or the platform lacks the required descriptor APIs.
    pub fn recheck_sources(&self) -> CanonicalKuraEvidenceResult<()> {
        #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
        {
            self.sources.check()
        }
        #[cfg(not(all(unix, not(any(target_os = "redox", target_os = "espidf")))))]
        {
            Err(CanonicalKuraEvidenceError::UnsupportedPlatform)
        }
    }
    /// Reject publication within any directory namespace actually read by Core.
    ///
    /// `ancestry` must come from the publication owner's held directory chain,
    /// ordered from root to immediate parent. Only bounded dev/inode identities
    /// cross this boundary; no raw descriptor or arbitrary callback escapes.
    ///
    /// # Errors
    ///
    /// Returns an error if ancestry is empty or exceeds 64 entries, overlaps a
    /// read source namespace, fails source revalidation, or the platform lacks
    /// the required descriptor APIs.
    pub fn ensure_publication_ancestry(
        &self,
        ancestry: &[(u64, u64)],
    ) -> CanonicalKuraEvidenceResult<()> {
        evidence_require(
            !ancestry.is_empty() && ancestry.len() <= 64,
            "publication ancestry bound",
        )?;
        #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
        {
            self.sources.ensure_publication_ancestry(ancestry)
        }
        #[cfg(not(all(unix, not(any(target_os = "redox", target_os = "espidf")))))]
        {
            Err(CanonicalKuraEvidenceError::UnsupportedPlatform)
        }
    }
    /// Height of the exact published commit marker admitted at open.
    #[must_use]
    pub fn committed_height(&self) -> u64 {
        self.committed_height
    }
    /// Number of canonical carriers returned from the complete requested interval.
    #[must_use]
    pub fn carrier_count(&self) -> u64 {
        self.carrier_count
    }
    /// Sum of returned complete native carrier wire byte lengths.
    #[must_use]
    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }
}

/// Immutable, bounded primary-store evidence reader with no mutation or recovery path.
///
/// Unix targets with the required descriptor APIs use retained no-follow handles from
/// the filesystem root. Redox, espidf and non-Unix targets fail closed. Only clean, nonempty, unpruned committed prefixes are
/// admitted: exact index/hash counts and contiguous data, with no uncommitted suffix.
/// The admitted journal images remain resident (at most 48 MB combined), bounded by
/// `max_committed_blocks`; native body decoding remains frame bounded.
/// An original local resource refusal before consumption leaves the cursor unchanged
/// and permits retry only after the exact retained sources and marker are rechecked.
/// Other errors and consumer errors or caught panics poison the session. Nothing is
/// finally qualified before `finish`.
/// TODO: fund the retained journal images, file buffers and decoder backing through
/// the caller's original allocation owner; finite byte bounds alone do not fund them.
#[derive(Debug)]
pub struct CanonicalKuraEvidenceReader {
    limits: CanonicalKuraEvidenceLimits,
    marker: BlockStoreCommitMarker,
    marker_bytes: Vec<u8>,
    index_bytes: Vec<u8>,
    hash_bytes: Vec<u8>,
    next_height: u64,
    output_bytes: u64,
    poisoned: bool,
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    sources: canonical_evidence_read_only_fs::Sources,
}
impl CanonicalKuraEvidenceReader {
    /// Admit an explicit native primary block store without discovery, creation or repair.
    ///
    /// Paths must be absolute, already normalized, bounded and free of symlink components.
    /// Every requested carrier must lie within the exact published commit marker.
    /// # Errors
    /// Returns invalid-input, immutable-prefix, original decoder or allocator,
    /// secure-I/O, or unsupported-platform errors.
    pub fn open(
        block_store: &Path,
        limits: CanonicalKuraEvidenceLimits,
    ) -> CanonicalKuraEvidenceResult<Self> {
        Self::open_after_admission(block_store, limits, |_| {})
    }
    fn open_after_admission(
        block_store: &Path,
        limits: CanonicalKuraEvidenceLimits,
        after_admission: impl FnMut(&Path),
    ) -> CanonicalKuraEvidenceResult<Self> {
        limits.validate()?;
        #[cfg(not(all(unix, not(any(target_os = "redox", target_os = "espidf")))))]
        {
            let _ = (block_store, after_admission);
            // TODO: add retained descriptor APIs on Redox/espidf and Windows relative non-reparse handles; never reopen paths as a fallback.
            return Err(CanonicalKuraEvidenceError::UnsupportedPlatform);
        }
        #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
        {
            let sources = canonical_evidence_read_only_fs::Sources::open(
                block_store,
                limits,
                after_admission,
            )?;
            let marker_bytes = sources.marker.read(0, sources.marker.len())?;
            let marker: BlockStoreCommitMarker =
                norito::with_decode_limits_scope(limits.decode_limits(marker_bytes.len()), || {
                    norito::decode_canonical_for_admission(
                        &marker_bytes,
                        norito::canonical_decode_limits(marker_bytes.len()),
                    )
                })
                .map_err(CanonicalKuraEvidenceError::Decode)?;
            evidence_require(
                marker.version == BlockStoreCommitMarker::VERSION
                    && marker.count > 0
                    && marker.tip_hash.is_some()
                    && marker.count <= limits.max_committed_blocks
                    && limits.last_height <= marker.count,
                "published marker boundary",
            )?;
            evidence_require(
                sources.index.len()
                    == marker
                        .count
                        .checked_mul(BlockIndex::SIZE)
                        .ok_or(CanonicalKuraEvidenceError::Invalid("index count overflow"))?
                    && sources.hashes.len()
                        == marker
                            .count
                            .checked_mul(SIZE_OF_BLOCK_HASH)
                            .ok_or(CanonicalKuraEvidenceError::Invalid("hash count overflow"))?,
                "exact committed journal lengths",
            )?;
            let index_bytes = sources.index.read(0, sources.index.len())?;
            let hash_bytes = sources.hashes.read(0, sources.hashes.len())?;
            let mut reader = Self {
                limits,
                marker,
                marker_bytes,
                index_bytes,
                hash_bytes,
                next_height: limits.first_height,
                output_bytes: 0,
                poisoned: true,
                sources,
            };
            let mut cursor = 0_u64;
            for height in 1..=reader.marker.count {
                let index = reader.index(height)?;
                evidence_require(
                    index.start == cursor && index.length > 0 && !index.is_evicted(),
                    "clean contiguous data prefix",
                )?;
                cursor = cursor
                    .checked_add(index.length)
                    .ok_or(CanonicalKuraEvidenceError::Invalid("data offset overflow"))?;
                evidence_require(cursor <= reader.sources.data.len(), "data index range")?;
                let hash = reader.hash(height)?;
                if height == reader.marker.count {
                    evidence_require(Some(hash) == reader.marker.tip_hash, "published marker tip")?;
                }
            }
            evidence_require(
                cursor == reader.sources.data.len(),
                "uncommitted data suffix",
            )?;
            reader.check_sources()?;
            reader.poisoned = false;
            Ok(reader)
        }
    }
    fn begin(&mut self) -> CanonicalKuraEvidenceResult<()> {
        evidence_require(!self.poisoned, "poisoned reader")?;
        // Set before fallible work or external callbacks; unwinding leaves this true.
        self.poisoned = true;
        self.check_sources()
    }
    fn add_output(&mut self, size: usize) -> CanonicalKuraEvidenceResult<()> {
        let next = self
            .output_bytes
            .checked_add(
                u64::try_from(size)
                    .map_err(|_| CanonicalKuraEvidenceError::Invalid("output size overflow"))?,
            )
            .ok_or(CanonicalKuraEvidenceError::Invalid("output sum overflow"))?;
        evidence_require(
            next <= self.limits.max_output_bytes,
            "cumulative output bound",
        )?;
        self.output_bytes = next;
        Ok(())
    }
    /// Read exactly the next requested canonical carrier and bind its stored header association.
    ///
    /// Returned wire bytes still require the independently anchored finality verifier.
    /// # Errors
    /// Fails and poisons on skipped/repeated heights, bounds, invalid bytes or file
    /// identity errors. A pre-consumer local resource refusal permits unchanged
    /// retry only after an exact source recheck.
    pub fn read_carrier(&mut self, height: u64) -> CanonicalKuraEvidenceResult<Vec<u8>> {
        self.read_carrier_with(height, Ok)
    }
    /// Consume exact native wire bytes before the final source-identity recheck.
    ///
    /// The callback's effects remain provisional until this reader and the independently
    /// anchored native verifier both finish. Its error or caught panic poisons this owner.
    /// # Errors
    /// Fails on the same storage checks as [`Self::read_carrier`] or consumer refusal.
    pub fn read_carrier_with<T>(
        &mut self,
        height: u64,
        consume: impl FnOnce(Vec<u8>) -> CanonicalKuraEvidenceResult<T>,
    ) -> CanonicalKuraEvidenceResult<T> {
        self.begin()?;
        #[cfg(not(all(unix, not(any(target_os = "redox", target_os = "espidf")))))]
        {
            let _ = (height, consume);
            Err(CanonicalKuraEvidenceError::UnsupportedPlatform)
        }
        #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
        {
            let wire = match self.prepare_carrier(height) {
                Ok(wire) => wire,
                Err(error) => return self.refuse_before_consumer(error),
            };
            // The exact four native artifact byte strings remain inside the unchanged wire.
            // Presence/shape and disk association do not authenticate their signatures or result.
            self.add_output(wire.len())?;
            let result = consume(wire)?;
            self.check_sources()?;
            self.next_height = height
                .checked_add(1)
                .ok_or(CanonicalKuraEvidenceError::Invalid(
                    "height successor overflow",
                ))?;
            self.poisoned = false;
            Ok(result)
        }
    }
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    fn prepare_carrier(&self, height: u64) -> CanonicalKuraEvidenceResult<Vec<u8>> {
        evidence_require(
            height == self.next_height && height <= self.limits.last_height,
            "exact increasing carrier interval",
        )?;
        let index = self.index(height)?;
        evidence_require(
            index.length <= self.limits.max_carrier_bytes as u64,
            "carrier frame bound",
        )?;
        let wire = self.sources.data.read(index.start, index.length)?;
        let block = norito::with_decode_limits_scope(self.limits.decode_limits(wire.len()), || {
            iroha_data_model::block::decode_framed_signed_block(&wire)
        })
        .map_err(CanonicalKuraEvidenceError::Decode)?;
        // The sole decoder already checks exact framed length and canonical bytes.
        evidence_require(
            block.header().height().get() == height && block.hash() == self.hash(height)?,
            "canonical carrier association",
        )?;
        let previous = if height == 1 {
            None
        } else {
            Some(self.hash(height - 1)?)
        };
        evidence_require(
            block.header().prev_block_hash() == previous,
            "carrier parent journal association",
        )?;
        let certificate = block
            .commit_certificate()
            .ok_or(CanonicalKuraEvidenceError::Invalid(
                "native commit certificate is absent",
            ))?;
        evidence_require(
            !certificate.result_preimage().is_empty()
                && if height == 1 {
                    certificate.consensus_header().is_empty()
                        && certificate.commit_qc().is_empty()
                        && certificate.availability().is_empty()
                } else {
                    !certificate.consensus_header().is_empty()
                        && !certificate.commit_qc().is_empty()
                        && !certificate.availability().is_empty()
                },
            "native commit certificate shape",
        )?;
        Ok(wire)
    }
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    fn refuse_before_consumer<T>(
        &mut self,
        error: CanonicalKuraEvidenceError,
    ) -> CanonicalKuraEvidenceResult<T> {
        let local_resource = match &error {
            CanonicalKuraEvidenceError::Decode(error) => matches!(
                error.kind(),
                norito::core::DecodeAttemptErrorKind::Allocator
                    | norito::core::DecodeAttemptErrorKind::EnclosingLimit
            ),
            CanonicalKuraEvidenceError::Allocator(_) => true,
            CanonicalKuraEvidenceError::Invalid(_)
            | CanonicalKuraEvidenceError::Io(_)
            | CanonicalKuraEvidenceError::UnsupportedPlatform => false,
        };
        if local_resource {
            // No cursor/output mutation or consumer callback has occurred. A changed
            // descriptor or marker remains terminal even when allocation was refused.
            self.check_sources()?;
            self.poisoned = false;
        }
        Err(error)
    }
    /// Consume this owner only after the complete requested native carrier interval.
    /// # Errors
    /// Fails on missing carriers, caught earlier errors or panics, or final source drift.
    pub fn finish(mut self) -> CanonicalKuraEvidenceResult<CanonicalKuraEvidenceComplete> {
        self.begin()?;
        evidence_require(
            self.next_height == self.limits.last_height + 1,
            "incomplete evidence phases",
        )?;
        self.check_sources()?;
        Ok(CanonicalKuraEvidenceComplete {
            #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
            sources: self.sources,
            committed_height: self.marker.count,
            carrier_count: self.limits.last_height - self.limits.first_height + 1,
            output_bytes: self.output_bytes,
        })
    }
    fn check_sources(&self) -> CanonicalKuraEvidenceResult<()> {
        #[cfg(not(all(unix, not(any(target_os = "redox", target_os = "espidf")))))]
        {
            Err(CanonicalKuraEvidenceError::UnsupportedPlatform)
        }
        #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
        {
            self.sources.check()?;
            self.sources.marker.check_marker_bytes(&self.marker_bytes)
        }
    }
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    fn index(&self, height: u64) -> CanonicalKuraEvidenceResult<BlockIndex> {
        evidence_require(height > 0, "one-based index height")?;
        let offset = (height - 1)
            .checked_mul(BlockIndex::SIZE)
            .ok_or(CanonicalKuraEvidenceError::Invalid("index offset overflow"))?;
        let offset = usize::try_from(offset)
            .map_err(|_| CanonicalKuraEvidenceError::Invalid("index offset conversion"))?;
        let bytes = self
            .index_bytes
            .get(offset..)
            .and_then(|suffix| suffix.get(..BlockIndex::SIZE_USIZE))
            .ok_or(CanonicalKuraEvidenceError::Invalid("index slice boundary"))?;
        evidence_require(bytes.len() == 16, "block index layout")?;
        Ok(BlockIndex {
            start: u64::from_le_bytes(
                bytes[..8]
                    .try_into()
                    .map_err(|_| CanonicalKuraEvidenceError::Invalid("index start"))?,
            ),
            length: u64::from_le_bytes(
                bytes[8..]
                    .try_into()
                    .map_err(|_| CanonicalKuraEvidenceError::Invalid("index length"))?,
            ),
        })
    }
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    fn hash(&self, height: u64) -> CanonicalKuraEvidenceResult<HashOf<BlockHeader>> {
        evidence_require(height > 0, "one-based hash height")?;
        let offset = (height - 1)
            .checked_mul(SIZE_OF_BLOCK_HASH)
            .ok_or(CanonicalKuraEvidenceError::Invalid("hash offset overflow"))?;
        let offset = usize::try_from(offset)
            .map_err(|_| CanonicalKuraEvidenceError::Invalid("hash offset conversion"))?;
        let bytes = self
            .hash_bytes
            .get(offset..)
            .and_then(|suffix| suffix.get(..Hash::LENGTH))
            .ok_or(CanonicalKuraEvidenceError::Invalid("hash slice boundary"))?;
        let bytes: [u8; Hash::LENGTH] = bytes
            .try_into()
            .map_err(|_| CanonicalKuraEvidenceError::Invalid("hash record size"))?;
        evidence_require(bytes[Hash::LENGTH - 1] & 1 == 1, "canonical hash marker")?;
        Ok(HashOf::from_untyped_unchecked(Hash::prehashed(bytes)))
    }
}

#[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
mod canonical_evidence_read_only_fs {
    use super::{
        CanonicalKuraEvidenceError as Error, CanonicalKuraEvidenceLimits as Limits,
        CanonicalKuraEvidenceResult as Result, evidence_require as require,
    };
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
    use std::{
        ffi::OsString,
        fs::File,
        os::unix::{ffi::OsStrExt as _, fs::FileExt as _},
        path::{Component, Path, PathBuf},
    };
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Identity {
        dev: u64,
        ino: u64,
        mode: rustix::fs::RawMode,
        uid: u32,
        gid: u32,
        links: u64,
        size: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl Identity {
        fn new(value: Stat) -> Result<Self> {
            Ok(Self {
                dev: crate::kura::unix_device_identity(value.st_dev),
                ino: value.st_ino,
                mode: value.st_mode,
                uid: value.st_uid,
                gid: value.st_gid,
                links: value.st_nlink as u64,
                size: u64::try_from(value.st_size)
                    .map_err(|_| Error::Invalid("negative file size"))?,
                modified: (value.st_mtime, value.st_mtime_nsec),
                changed: (value.st_ctime, value.st_ctime_nsec),
            })
        }
        fn same_owner(self, other: Self) -> bool {
            (self.dev, self.ino, self.mode, self.uid, self.gid)
                == (other.dev, other.ino, other.mode, other.uid, other.gid)
        }
        fn directory(self) -> bool {
            FileType::from_raw_mode(self.mode) == FileType::Directory
        }
        fn regular(self) -> bool {
            FileType::from_raw_mode(self.mode) == FileType::RegularFile && self.links == 1
        }
    }
    fn held(file: &File) -> Result<Identity> {
        Identity::new(rustix::fs::fstat(file).map_err(std::io::Error::from)?)
    }
    fn named(parent: &File, name: &std::ffi::OsStr) -> Result<Identity> {
        Identity::new(
            rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(std::io::Error::from)?,
        )
    }
    const DIRECTORY: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::CLOEXEC);
    const REGULAR: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::CLOEXEC);
    #[derive(Debug)]
    struct Directory {
        file: File,
        name: Option<OsString>,
        identity: Identity,
    }
    #[derive(Debug)]
    pub(super) struct Source {
        chain: Vec<Directory>,
        file: File,
        name: OsString,
        identity: Identity,
    }
    impl Source {
        fn open(
            path: &Path,
            max_bytes: u64,
            uid: u32,
            hook: &mut impl FnMut(&Path),
        ) -> Result<Self> {
            require(
                path.is_absolute() && path.as_os_str().as_bytes().len() <= 4096,
                "absolute bounded source path",
            )?;
            let mut normalized = PathBuf::new();
            let mut parts = Vec::new();
            for component in path.components() {
                match component {
                    Component::RootDir => normalized.push(component.as_os_str()),
                    Component::Normal(name) => {
                        normalized.push(name);
                        parts.push(name.to_os_string());
                    }
                    _ => return Err(Error::Invalid("normalized source path")),
                }
            }
            require(
                normalized.as_os_str() == path.as_os_str()
                    && !parts.is_empty()
                    && parts.len() <= 64,
                "bounded source components",
            )?;
            let name = parts.pop().ok_or(Error::Invalid("source leaf"))?;
            let root = File::from(
                rustix::fs::open("/", DIRECTORY, Mode::empty()).map_err(std::io::Error::from)?,
            );
            let root_identity = held(&root)?;
            require(root_identity.directory(), "filesystem root directory")?;
            let mut chain = vec![Directory {
                file: root,
                name: None,
                identity: root_identity,
            }];
            for part in parts {
                let parent = &chain.last().ok_or(Error::Invalid("directory chain"))?.file;
                let before = named(parent, &part)?;
                require(before.directory(), "non-symlink directory required")?;
                let child = File::from(
                    rustix::fs::openat(parent, &part, DIRECTORY, Mode::empty())
                        .map_err(std::io::Error::from)?,
                );
                require(
                    held(&child)?.same_owner(before) && named(parent, &part)?.same_owner(before),
                    "directory changed at open",
                )?;
                chain.push(Directory {
                    file: child,
                    name: Some(part),
                    identity: before,
                });
            }
            let parent = &chain.last().ok_or(Error::Invalid("source parent"))?.file;
            require(held(parent)?.uid == uid, "source parent owner")?;
            let before = named(parent, &name)?;
            require(
                before.regular() && before.uid == uid && before.size <= max_bytes,
                "bounded owned single-link regular source",
            )?;
            hook(path);
            let file = File::from(
                rustix::fs::openat(parent, &name, REGULAR, Mode::empty())
                    .map_err(std::io::Error::from)?,
            );
            require(
                held(&file)? == before && named(parent, &name)? == before,
                "file changed at open",
            )?;
            let source = Self {
                chain,
                file,
                name,
                identity: before,
            };
            source.check()?;
            Ok(source)
        }
        pub(super) fn len(&self) -> u64 {
            self.identity.size
        }
        pub(super) fn check(&self) -> Result<()> {
            for (index, directory) in self.chain.iter().enumerate() {
                require(
                    held(&directory.file)?.same_owner(directory.identity),
                    "held directory changed",
                )?;
                if let Some(name) = &directory.name {
                    require(
                        index > 0
                            && named(&self.chain[index - 1].file, name)?
                                .same_owner(directory.identity),
                        "named directory changed",
                    )?;
                }
            }
            let parent = &self
                .chain
                .last()
                .ok_or(Error::Invalid("source parent"))?
                .file;
            require(
                held(&self.file)? == self.identity && named(parent, &self.name)? == self.identity,
                "held or named source changed",
            )
        }
        #[cfg(test)]
        pub(super) fn flags_for_test(&self) -> Result<(OFlags, rustix::io::FdFlags)> {
            Ok((
                rustix::fs::fcntl_getfl(&self.file).map_err(std::io::Error::from)?,
                rustix::io::fcntl_getfd(&self.file).map_err(std::io::Error::from)?,
            ))
        }
        pub(super) fn check_marker_bytes(&self, expected: &[u8]) -> Result<()> {
            self.check()?;
            require(
                expected.len() <= super::MAX_BLOCK_COMMIT_MARKER_BYTES
                    && expected.len() as u64 == self.len(),
                "published marker recheck bound",
            )?;
            // Rechecking a resource-refused read must not need another heap buffer.
            // The complete marker is independently bounded at source admission.
            let mut bytes = [0u8; super::MAX_BLOCK_COMMIT_MARKER_BYTES];
            let observed = &mut bytes[..expected.len()];
            self.file.read_exact_at(observed, 0)?;
            self.check()?;
            require(observed == expected, "published marker changed")
        }
        pub(super) fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
            self.read_after_check(offset, length, || {})
        }
        pub(super) fn read_after_check(
            &self,
            offset: u64,
            length: u64,
            after_check: impl FnOnce(),
        ) -> Result<Vec<u8>> {
            self.check()?;
            require(
                offset
                    .checked_add(length)
                    .is_some_and(|end| end <= self.len())
                    && length <= 32 * 1024 * 1024,
                "bounded source read range",
            )?;
            let length =
                usize::try_from(length).map_err(|_| Error::Invalid("read size conversion"))?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(Error::Allocator)?;
            bytes.resize(length, 0);
            after_check();
            self.file.read_exact_at(&mut bytes, offset)?;
            self.check()?;
            Ok(bytes)
        }
    }
    #[derive(Debug)]
    pub(super) struct Sources {
        pub(super) data: Source,
        pub(super) index: Source,
        pub(super) hashes: Source,
        pub(super) marker: Source,
    }
    impl Sources {
        pub(super) fn ensure_publication_ancestry(&self, ancestry: &[(u64, u64)]) -> Result<()> {
            self.check()?;
            for source in [&self.data, &self.index, &self.hashes, &self.marker] {
                let root = source
                    .chain
                    .last()
                    .ok_or(Error::Invalid("source parent chain"))?
                    .identity;
                require(
                    !ancestry.contains(&(root.dev, root.ino)),
                    "publication inside protected Core source namespace",
                )?;
            }
            self.check()
        }
        pub(super) fn open(
            store: &Path,
            limits: Limits,
            mut hook: impl FnMut(&Path),
        ) -> Result<Self> {
            let data = Source::open(
                &store.join(super::DATA_FILE_NAME),
                limits.max_store_data_bytes,
                limits.owner_uid,
                &mut hook,
            )?;
            let index = Source::open(
                &store.join(super::INDEX_FILE_NAME),
                limits.max_committed_blocks * super::BlockIndex::SIZE,
                limits.owner_uid,
                &mut hook,
            )?;
            let hashes = Source::open(
                &store.join(super::HASHES_FILE_NAME),
                limits.max_committed_blocks * super::SIZE_OF_BLOCK_HASH,
                limits.owner_uid,
                &mut hook,
            )?;
            let marker = Source::open(
                &store.join(super::COUNT_FILE_NAME),
                super::MAX_BLOCK_COMMIT_MARKER_BYTES as u64,
                limits.owner_uid,
                &mut hook,
            )?;
            let sources = Self {
                data,
                index,
                hashes,
                marker,
            };
            let mut objects = std::collections::BTreeSet::new();
            for source in [
                &sources.data,
                &sources.index,
                &sources.hashes,
                &sources.marker,
            ] {
                require(
                    objects.insert((source.identity.dev, source.identity.ino)),
                    "aliased evidence sources",
                )?;
            }
            sources.check()?;
            Ok(sources)
        }
        pub(super) fn check(&self) -> Result<()> {
            for source in [&self.data, &self.index, &self.hashes, &self.marker] {
                source.check()?;
            }
            Ok(())
        }
    }
}
