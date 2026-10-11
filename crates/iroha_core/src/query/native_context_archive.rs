//! Original native context and execution writes retained under their exact carrier.
//!
//! Records are untrusted projections. Only the native certificate and its mandatory R proof
//! authenticate them. The writer borrows the original sealed overlay, streams one prepaid
//! record, and retains that exact allocation through publication retries. Readers never
//! substitute current State or reconstruct missing historical values from a root.

pub(crate) mod prepared_intents;
mod read;
#[cfg(test)]
pub(crate) use prepared_intents::test_helpers as prepared_intent_test_helpers;
pub use read::NativeContextRead;

use crate::{
    kura::Kura,
    state::{NativeExecutionProjectionV1, StateBlock, StateReadOnly, WorldReadOnly},
};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError, RetainedPayload};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{
        BlockHeader, SignedBlock,
        consensus::{ExecKv, ExecWitness},
    },
    sumeragi_finality::ExecutionResultCommitment,
    sumeragi_lanes::SumeragiLaneState,
};
use std::{
    fs::File,
    io::{self, Read, Seek, Write},
    num::NonZeroUsize,
    path::Path,
};

/// Context projection capture, source custody or durable storage failure.
#[derive(Debug, thiserror::Error)]
pub enum NativeContextArchiveError {
    /// The proposed record is not the original sealed execution source.
    #[error("native context archive source: {0}")]
    Source(&'static str),
    /// The full canonical projection exceeds its independently configured finite limit.
    #[error("native context archive record exceeds {maximum} bytes (got {actual})")]
    Limit {
        /// Independently configured byte maximum.
        maximum: usize,
        /// Original canonical byte length.
        actual: usize,
    },
    /// Preserve the original pool's exact capacity or allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// Original lane-state proof, retaining scratch custody or captured decoder provenance.
    #[error("native context archive proof: {0}")]
    Proof(#[from] iroha_data_model::sumeragi_finality::NativeLaneStateProofError),
    /// Canonical framing failed before any record could be published.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Durable publication or exact read failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl NativeContextArchiveError {
    /// Whether the original pool, allocator or captured caller decoder may admit the unchanged retry.
    /// An archive buffer ceiling refusal may require local reconfiguration. The proof's original
    /// scratch hard ceiling, record byte limit, impossible demand, malformed layout and source
    /// mismatches require recovery. Encoder errors do not borrow a decoder scope.
    pub fn is_local_refusal(&self) -> bool {
        match self {
            Self::Allocation(
                ChargedBufferError::Admission(
                    iroha_allocation::AllocationRefusal::Capacity { .. }
                    | iroha_allocation::AllocationRefusal::ExceedsLimit { .. },
                )
                | ChargedBufferError::Allocator { .. },
            ) => true,
            Self::Proof(original) => original.is_local_refusal(),
            _ => false,
        }
    }
}

/// Borrow only the existing payload, without adding a field, frame, allocation or decoder.
struct LaneStateRef<'a>(&'a SumeragiLaneState);
impl norito::core::SerializePayload for LaneStateRef<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(self.0)
    }
}

/// Stream the original owned write sequence without a clone or second graph.
struct OrdinaryWritesRef<'a>(&'a Vec<ExecKv>);
impl norito::core::SerializePayload for OrdinaryWritesRef<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(self.0)
    }
}

struct CastingBindingsRef<'a>(
    &'a Vec<iroha_data_model::parliament_casting::ParliamentTimedOvnCastingContextBindingV1>,
);
impl norito::core::SerializePayload for CastingBindingsRef<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(self.0)
    }
}

#[derive(norito::Encode)]
struct Projection<'a> {
    carrier_height: u64,
    carrier_hash: HashOf<BlockHeader>,
    lanes: LaneStateRef<'a>,
    ordinary_writes: OrdinaryWritesRef<'a>,
    casting_bindings: CastingBindingsRef<'a>,
}
impl norito::NoritoSchema for Projection<'_> {
    fn nominal_name() -> String {
        <NativeExecutionProjectionV1 as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        <NativeExecutionProjectionV1 as norito::NoritoSchema>::static_frame_name()
    }
}

/// One immutable record from the original overlay and retained native R.
/// No public constructor can assert this original-source relationship.
pub struct PreparedNativeContext {
    height: u64,
    carrier_hash: HashOf<BlockHeader>,
    bytes: ChargedBuffer<u8>,
    // The complete context stays owned if later intent admission refuses.
    prepared_intents: Option<ChargedBuffer<u8>>,
    intents_complete: bool,
}
impl PreparedNativeContext {
    /// Exact original canonical projection; exposure grants no finality.
    pub fn canonical_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Original local intent bytes, pending missing outbound authority and native proof checking.
    /// This is not a submitted or completed relay.
    #[cfg(test)]
    pub(crate) fn prepared_intent_bytes(&self) -> Option<&[u8]> {
        self.prepared_intents.as_ref().map(ChargedBuffer::as_slice)
    }
    /// Height of the exact result-bearing carrier.
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Carrier identity which remains fixed across durable retries.
    pub const fn carrier_hash(&self) -> HashOf<BlockHeader> {
        self.carrier_hash
    }
}

/// Mandatory per-Kura context projection archive. It is not finality authority.
pub struct NativeContextArchive {
    root: File,
    directory: File,
    budget: AllocationBudget,
    maximum: NonZeroUsize,
    writable: bool,
}
impl NativeContextArchive {
    /// Open the exact canonical Kura namespace using the original execution pool and finite limit.
    ///
    /// # Errors
    /// Directory identity/type, descriptor-relative filesystem support or I/O failures.
    pub fn open(
        kura: &Kura,
        budget: AllocationBudget,
        maximum: NonZeroUsize,
    ) -> Result<Self, NativeContextArchiveError> {
        let root = kura.native_context_archive_root()?;
        let directory = open_archive_directory(&root, true)?;
        Ok(Self {
            root,
            directory,
            budget,
            maximum,
            writable: true,
        })
    }

    /// Read an existing archive through the original Kura directory descriptor.
    /// Missing archives are errors: observation cannot create evidence or authorize writes.
    ///
    /// # Errors
    /// Missing, substituted or invalid directory, or unsupported descriptor-relative access.
    pub(crate) fn open_existing(
        kura: &Kura,
        budget: AllocationBudget,
        maximum: NonZeroUsize,
    ) -> Result<Self, NativeContextArchiveError> {
        let root = kura.native_context_archive_root()?;
        let directory = open_archive_directory(&root, false)?;
        Ok(Self {
            root,
            directory,
            budget,
            maximum,
            writable: false,
        })
    }

    /// Open an existing archive under an independently retained original Kura root.
    /// This does not create directories or authorize publication. The returned record bytes
    /// still require complete native carrier and context-proof authentication by the caller.
    ///
    /// # Errors
    /// Missing or substituted directory, unsupported descriptor-relative access or I/O failure.
    pub fn open_read_only(
        store_root: &Path,
        budget: AllocationBudget,
        maximum: NonZeroUsize,
    ) -> Result<Self, NativeContextArchiveError> {
        let (root, directory) = open_directory(store_root, false)?;
        Ok(Self {
            root,
            directory,
            budget,
            maximum,
            writable: false,
        })
    }

    /// Recheck that the original root still names this retained archive directory.
    /// Already acquired bytes remain separate untrusted values until certified proof checking;
    /// this method makes no claim that historical pathnames cannot subsequently be replaced.
    ///
    /// # Errors
    /// The archive namespace was removed or substituted after acquisition.
    pub fn recheck_namespace(&self) -> Result<(), NativeContextArchiveError> {
        verify_named_file(&self.root, "native-contexts", &self.directory)?;
        Ok(())
    }

    /// Freeze complete values while their original execution overlay and retained R are owned.
    /// No decoded archive, current-head view or unverified root can provide this source.
    ///
    /// # Errors
    /// Foreign pool/source, proof mismatch, finite admission refusal or canonical codec failure.
    pub(crate) fn prepare(
        &self,
        overlay: &StateBlock<'_>,
        executed: &SignedBlock,
        result: &RetainedPayload<ExecutionResultCommitment>,
        witness: &ExecWitness,
    ) -> Result<PreparedNativeContext, NativeContextArchiveError> {
        self.recheck_namespace()?;
        if !self.writable
            || !result.belongs_to(&self.budget)
            || executed.header() != overlay._curr_block
            || result.get().height != executed.header().height().get()
            || result.get().schedule.current.network_id != *overlay.network_id()
        {
            return Err(NativeContextArchiveError::Source(
                "foreign original execution or pool",
            ));
        }
        if !result.get().native_lanes.verify(
            *overlay.network_id(),
            result.get().height,
            result.get().execution.ordinary_writes_root,
        ) {
            return Err(NativeContextArchiveError::Source(
                "lane-state path differs from original execution root",
            ));
        }
        // Recompute the mandatory path using charged scratch over borrowed writes.
        // Its root binds the complete ordered source without cloning that graph.
        let original_path =
            iroha_data_model::sumeragi_finality::NativeLaneStateProof::from_witness(
                witness,
                &self.budget,
            )
            .map_err(NativeContextArchiveError::Proof)?;
        if original_path != result.get().native_lanes {
            return Err(NativeContextArchiveError::Source(
                "original ordinary writes differ from native result",
            ));
        }
        let lanes = overlay.world().sumeragi_lanes();
        if !result
            .get()
            .native_lanes
            .matches_state_encoding(*overlay.network_id(), result.get().height, lanes)
            .map_err(|_| NativeContextArchiveError::Source("invalid complete native lane state"))?
        {
            return Err(NativeContextArchiveError::Source(
                "complete values differ from original R proof",
            ));
        }
        let projection = Projection {
            carrier_height: result.get().height,
            carrier_hash: executed.hash(),
            lanes: LaneStateRef(lanes),
            ordinary_writes: OrdinaryWritesRef(&witness.writes),
            casting_bindings: CastingBindingsRef(
                overlay.captured_parliament_casting_bindings().ok_or(
                    NativeContextArchiveError::Source("original casting leaves are absent"),
                )?,
            ),
        };
        self.encode_projection(&projection)
    }

    fn encode_projection(
        &self,
        projection: &Projection<'_>,
    ) -> Result<PreparedNativeContext, NativeContextArchiveError> {
        let length = norito::canonical_frame_len(projection)?;
        if length > self.maximum.get() {
            return Err(NativeContextArchiveError::Limit {
                maximum: self.maximum.get(),
                actual: length,
            });
        }
        let mut bytes = ChargedBuffer::new(length, &self.budget)?;
        norito::core::write_canonical_to_writer(projection, &mut BufferWriter(&mut bytes))?;
        if bytes.as_slice().len() != length {
            return Err(norito::Error::LengthMismatch.into());
        }
        Ok(PreparedNativeContext {
            height: projection.carrier_height,
            carrier_hash: projection.carrier_hash,
            bytes,
            prepared_intents: None,
            intents_complete: !projection
                .ordinary_writes
                .0
                .iter()
                .any(|write| prepared_intents::is_prepared_key_prefix(&write.key)),
        })
    }

    /// Durably publish or recheck the exact retained record. A failure leaves `original` intact.
    /// The caller must keep it in PendingCommit until publication and remaining notifications finish.
    ///
    /// # Errors
    /// Foreign backing, changed canonical record, or a write/link/directory-sync failure.
    pub fn publish(
        &self,
        original: &PreparedNativeContext,
    ) -> Result<(), NativeContextArchiveError> {
        self.recheck_namespace()?;
        if !self.writable
            || !original.bytes.belongs_to(&self.budget)
            || original
                .prepared_intents
                .as_ref()
                .is_some_and(|intents| !intents.belongs_to(&self.budget))
        {
            return Err(NativeContextArchiveError::Source(
                "foreign archive backing pool",
            ));
        }
        if !original.intents_complete {
            return Err(NativeContextArchiveError::Source(
                "original intent capture is incomplete",
            ));
        }
        publish_record(
            &self.directory,
            original.height,
            original.carrier_hash,
            original.bytes.as_slice(),
        )?;
        if let Some(intents) = &original.prepared_intents {
            if !cfg!(all(test, sumeragi_core_mutation = "HC183")) {
                publish_named_record(
                    &self.directory,
                    &RecordName::intent(original.height, original.carrier_hash, false),
                    &RecordName::intent(original.height, original.carrier_hash, true),
                    intents.as_slice(),
                )?;
            }
        }
        self.recheck_namespace()?;
        Ok(())
    }

    /// Retain this original namespace and an immutable carrier selection through acquisition.
    /// No read or allocation occurs before polling; acquired descriptors and partial byte owners
    /// survive every local refusal. The returned bytes still need native execution authentication.
    pub fn read_job(self, height: u64, carrier_hash: HashOf<BlockHeader>) -> NativeContextRead {
        NativeContextRead::new(self, height, carrier_hash)
    }

    // Byte acquisition only. The application reader must select the carrier from its
    // captured authenticated State history and validate every original intent coordinate.
    pub(crate) fn prepared_intent_read_job(
        self,
        height: u64,
        carrier_hash: HashOf<BlockHeader>,
    ) -> NativeContextRead {
        NativeContextRead::new_named(self, RecordName::intent(height, carrier_hash, false))
    }

    /// Read exact original canonical bytes for a separately selected carrier identity.
    /// The returned bytes are untrusted until NativeExecutionEvidenceVerifier consumes the
    /// full canonical carrier and checks R.native_lanes. A missing record fails closed.
    /// This one-shot convenience drops its read job on error; callers that retry must retain
    /// the owner returned by [`Self::read_job`] to keep the original descriptor and partial bytes.
    ///
    /// # Errors
    /// Missing/substituted record, finite byte limit, original-pool refusal or an incomplete read.
    pub fn read_exact(
        &self,
        height: u64,
        carrier_hash: HashOf<BlockHeader>,
    ) -> Result<ChargedBuffer<u8>, NativeContextArchiveError> {
        let mut read = read::RecordRead::new(height, carrier_hash);
        read::to_completion(|| read.poll(self))
    }
}

struct BufferWriter<'a>(&'a mut ChargedBuffer<u8>);
impl Write for BufferWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Fixed filenames avoid a per-record String/Path allocation while retaining exact identity.
struct RecordName {
    bytes: [u8; 90],
    len: usize,
}
impl RecordName {
    fn new(height: u64, hash: HashOf<BlockHeader>, staged: bool) -> Self {
        let mut out = Self {
            bytes: [0; 90],
            len: 0,
        };
        if staged {
            out.bytes[0] = b'.';
            out.len = 1;
        }
        let start = out.len;
        let mut remaining = height;
        for offset in (0..20).rev() {
            out.bytes[start + offset] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
        }
        out.len += 20;
        out.bytes[out.len] = b'-';
        out.len += 1;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in hash.as_ref() {
            out.bytes[out.len] = HEX[usize::from(byte >> 4)];
            out.bytes[out.len + 1] = HEX[usize::from(byte & 15)];
            out.len += 2;
        }
        out.bytes[out.len..out.len + 4].copy_from_slice(b".nrt");
        out.len += 4;
        out
    }
    fn intent(height: u64, hash: HashOf<BlockHeader>, staged: bool) -> Self {
        let mut name = Self::new(height, hash, staged);
        let start = name.len - 4;
        name.bytes[start..name.len].copy_from_slice(b".ami");
        name
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("fixed ASCII record identity")
    }
}

#[cfg(unix)]
fn open_directory(store_root: &Path, create: bool) -> io::Result<(File, File)> {
    use rustix::fs::{Mode, OFlags};
    let root = File::from(rustix::fs::open(
        store_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let directory = open_archive_directory(&root, create)?;
    Ok((root, directory))
}
#[cfg(unix)]
fn open_archive_directory(root: &File, create: bool) -> io::Result<File> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    if create {
        match rustix::fs::mkdirat(
            &root,
            "native-contexts",
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        ) {
            Ok(()) => root.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let directory = File::from(rustix::fs::openat(
        &root,
        "native-contexts",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let entry = rustix::fs::statat(&root, "native-contexts", AtFlags::SYMLINK_NOFOLLOW)?;
    use std::os::unix::fs::MetadataExt as _;
    let actual = directory.metadata()?;
    if !actual.is_dir()
        || entry.st_dev as u64 != actual.dev()
        || entry.st_ino as u64 != actual.ino()
    {
        return Err(io::Error::other(
            "native context directory identity changed",
        ));
    }
    Ok(directory)
}
fn verify_bytes(mut file: File, expected: &[u8]) -> io::Result<()> {
    if !file.metadata()?.is_file() || file.metadata()?.len() != expected.len() as u64 {
        return Err(io::Error::other(
            "native context record length or type differs",
        ));
    }
    let mut scratch = [0; 4096];
    let mut offset = 0;
    while offset < expected.len() {
        let count = (expected.len() - offset).min(scratch.len());
        file.read_exact(&mut scratch[..count])?;
        if scratch[..count] != expected[offset..offset + count] {
            return Err(io::Error::other("native context canonical record differs"));
        }
        offset += count;
    }
    if file.read(&mut scratch[..1])? != 0 {
        return Err(io::Error::other("native context canonical record grew"));
    }
    Ok(())
}
#[cfg(unix)]
fn publish_record(
    directory: &File,
    height: u64,
    hash: HashOf<BlockHeader>,
    bytes: &[u8],
) -> io::Result<()> {
    publish_named_record(
        directory,
        &RecordName::new(height, hash, false),
        &RecordName::new(height, hash, true),
        bytes,
    )
}
#[cfg(unix)]
fn open_named_record(directory: &File, name: &RecordName) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let file = File::from(rustix::fs::openat(
        directory,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("native context record is not a file"));
    }
    Ok(file)
}
#[cfg(unix)]
fn publish_named_record(
    directory: &File,
    target: &RecordName,
    staged: &RecordName,
    bytes: &[u8],
) -> io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;
    match open_named_record(directory, target) {
        Ok(file) => {
            verify_bytes(file, bytes)?;
            directory.sync_all()?;
            remove_matching_stage(directory, staged.as_str(), bytes)?;
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = File::from(rustix::fs::openat(
        directory,
        staged.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::other("native context stage has foreign links"));
    }
    // Only this unlinked stage may be rewritten after interruption. Its authoritative
    // original bytes remain held by PendingCommit or exact certified execution replay.
    file.set_len(0)?;
    file.rewind()?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // The path must still name the original open descriptor before publication.
    verify_named_file(directory, staged.as_str(), &file)?;
    match rustix::fs::linkat(
        directory,
        staged.as_str(),
        directory,
        target.as_str(),
        AtFlags::empty(),
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            verify_bytes(open_named_record(directory, target)?, bytes)?
        }
        Err(error) => return Err(error.into()),
    }
    verify_bytes(open_named_record(directory, target)?, bytes)?;
    directory.sync_all()?;
    remove_matching_stage(directory, staged.as_str(), bytes)
}
#[cfg(unix)]
fn verify_named_file(directory: &File, name: &str, file: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let named = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    let opened = file.metadata()?;
    if named.st_dev as u64 != opened.dev() || named.st_ino as u64 != opened.ino() {
        return Err(io::Error::other("native context record identity changed"));
    }
    Ok(())
}
#[cfg(unix)]
fn remove_matching_stage(directory: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    let file = match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    verify_bytes(file.try_clone()?, bytes)?;
    verify_named_file(directory, name, &file)?;
    rustix::fs::unlinkat(directory, name, AtFlags::empty())?;
    directory.sync_all()
}
#[cfg(not(unix))]
fn open_directory(_store_root: &Path, _create: bool) -> io::Result<(File, File)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative native context archive is required",
    ))
}
#[cfg(not(unix))]
fn open_archive_directory(_root: &File, _create: bool) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative native context archive is required",
    ))
}
#[cfg(not(unix))]
fn verify_named_file(_directory: &File, _name: &str, _file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative native context archive is required",
    ))
}
#[cfg(not(unix))]
fn open_named_record(_directory: &File, _name: &RecordName) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative native context archive is required",
    ))
}
#[cfg(not(unix))]
fn publish_record(
    _directory: &File,
    _height: u64,
    _hash: HashOf<BlockHeader>,
    _bytes: &[u8],
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative native context archive is required",
    ))
}

#[cfg(not(unix))]
fn publish_named_record(
    _directory: &File,
    _target: &RecordName,
    _staged: &RecordName,
    _bytes: &[u8],
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative native context archive is required",
    ))
}

#[cfg(test)]
mod tests;
