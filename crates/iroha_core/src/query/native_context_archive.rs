//! Original native context and execution writes retained under their exact carrier.
//!
//! Records are untrusted projections. Only the native certificate and its mandatory R proof
//! authenticate them. The writer borrows the original sealed overlay, streams one prepaid
//! record, and retains that exact allocation through publication retries. Readers never
//! substitute current State or reconstruct missing historical values from a root.

pub(crate) mod fastpq_source;
pub(crate) mod prepared_intents;
#[cfg(test)]
pub(crate) mod process_crash;
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
    sumeragi_finality::CertifiedResultV1,
    sumeragi_lanes::SumeragiLaneState,
};

use std::{
    fs::File,
    io::{self, Read, Seek, Write},
    num::NonZeroUsize,
    path::Path,
};

/// Original optional capture diagnostic retained without exposing a mutable witness.
/// No textual diagnostic grants retry permission; a diagnostic whose underlying
/// allocator owner was already erased remains terminal.
#[derive(Clone, Debug, thiserror::Error)]
#[error("original optional FASTPQ capture: {original:?}")]
pub struct FastpqCaptureFailure {
    original: crate::state::QuantityCaptureIssue,
}

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
    /// The optional execution tape failed under its original pool owner.
    /// A completed witness is immutable: only an independently authenticated
    /// replay can recapture it, never an archive retry or a replacement tape.
    #[error("original optional FASTPQ capture admission: {0}")]
    CaptureAdmission(iroha_allocation::AllocationRefusal),
    /// Original invariant/ownership diagnostic from the exact optional witness.
    #[error(transparent)]
    CaptureFailure(FastpqCaptureFailure),
    /// Original lane-state proof, retaining scratch custody or captured decoder provenance.
    #[error("native context archive proof: {0}")]
    Proof(#[from] iroha_data_model::sumeragi_finality::NativeLaneStateProofError),
    /// Canonical framing failed before any record could be published.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Durable publication or exact read failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Original bounded Kura artifact-store refusal for optional source transport.
    #[error(transparent)]
    Storage(#[from] crate::kura::Error),
}

impl NativeContextArchiveError {
    /// Whether the original pool, allocator or captured caller decoder may admit the unchanged retry.
    /// An archive buffer ceiling refusal may require local reconfiguration. The proof's original
    /// scratch hard ceiling, record byte limit, impossible demand, malformed layout and source
    /// mismatches require recovery. Encoder errors do not borrow a decoder scope.
    pub fn is_local_refusal(&self) -> bool {
        match self {
            Self::CaptureAdmission(iroha_allocation::AllocationRefusal::Capacity { .. }) => true,
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
    sccp_delta: &'a [u8],
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
    // Optional source tapes never grant completion by their presence or absence.
    fastpq_source: Option<ChargedBuffer<u8>>,
    fastpq_capture_complete: bool,
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
    namespace: &'static str,
    fastpq_maximum: Option<NonZeroUsize>,
    fastpq_replay_target: Option<u64>,
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
            namespace: "native-contexts",
            fastpq_maximum: Some(kura.fastpq_object_max_bytes()),
            fastpq_replay_target: None,
        })
    }

    /// Select transport retention only for the exact isolated recovery target.
    /// Earlier canonical replay still computes every mandatory source commitment;
    /// its optional tapes are not stored in the bounded target outbox.
    pub(crate) fn retain_isolated_fastpq_target(
        &mut self,
        kura: &Kura,
        height: u64,
    ) -> Result<(), NativeContextArchiveError> {
        if !self.writable
            || !kura.is_temporary_staging()
            || height == 0
            || self.fastpq_replay_target.is_some()
        {
            return Err(NativeContextArchiveError::Source(
                "invalid isolated FASTPQ target",
            ));
        }
        self.recheck_namespace()?;
        self.fastpq_replay_target = Some(height);
        Ok(())
    }

    pub(crate) fn retains_isolated_fastpq_source(&self) -> bool {
        self.fastpq_replay_target.is_some()
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
            namespace: "native-contexts",
            fastpq_maximum: None,
            fastpq_replay_target: None,
        })
    }

    /// Acquire source transport in the sole Kura artifact namespace under its aggregate cap.
    /// The same descriptor/partial-read owner performs acquisition; it grants no source truth.
    pub(crate) fn open_existing_fastpq(
        kura: &Kura,
        budget: AllocationBudget,
    ) -> Result<Self, NativeContextArchiveError> {
        let root = kura.fastpq_source_archive_root()?;
        let namespace = Kura::fastpq_source_namespace();
        let directory = open_archive_directory_named(&root, namespace, false)?;
        Ok(Self {
            root,
            directory,
            budget,
            namespace,
            maximum: kura.fastpq_object_max_bytes(),
            writable: false,
            fastpq_maximum: None,
            fastpq_replay_target: None,
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
            namespace: "native-contexts",
            fastpq_maximum: None,
            fastpq_replay_target: None,
        })
    }

    /// Recheck that the original root still names this retained archive directory.
    /// Already acquired bytes remain separate untrusted values until certified proof checking;
    /// this method makes no claim that historical pathnames cannot subsequently be replaced.
    ///
    /// # Errors
    /// The archive namespace was removed or substituted after acquisition.
    pub fn recheck_namespace(&self) -> Result<(), NativeContextArchiveError> {
        verify_named_file(&self.root, self.namespace, &self.directory)?;
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
        result: &RetainedPayload<CertifiedResultV1>,
        witness: &ExecWitness,
    ) -> Result<PreparedNativeContext, NativeContextArchiveError> {
        self.recheck_namespace()?;
        if !self.writable
            || !result.belongs_to(&self.budget)
            || executed.header() != overlay._curr_block
            || result.get().commitment().height != executed.header().height().get()
            || result.get().commitment().schedule.current.network_id != *overlay.network_id()
        {
            return Err(NativeContextArchiveError::Source(
                "foreign original execution or pool",
            ));
        }
        if !result.get().commitment().native_lanes.verify(
            *overlay.network_id(),
            result.get().commitment().height,
            result.get().commitment().execution.ordinary_writes_root,
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
        if original_path != result.get().commitment().native_lanes {
            return Err(NativeContextArchiveError::Source(
                "original ordinary writes differ from native result",
            ));
        }
        let lanes = overlay.world().sumeragi_lanes();
        if !result
            .get()
            .commitment()
            .native_lanes
            .matches_state_encoding(
                *overlay.network_id(),
                result.get().commitment().height,
                lanes,
            )
            .map_err(|_| NativeContextArchiveError::Source("invalid complete native lane state"))?
        {
            return Err(NativeContextArchiveError::Source(
                "complete values differ from original R proof",
            ));
        }
        // Stream only the original overlay. The buffer and final archive frame are
        // admitted by this same original pool; no uncharged Vec clone is introduced.
        let sccp_delta = capture_sccp_delta(&overlay.world, &self.budget, self.maximum.get())?;
        crate::smartcontracts::isi::sccp::witness::require_exact_delta(
            executed.header().height().get(),
            sccp_delta.as_slice(),
            &witness.writes,
        )
        .map_err(|_| {
            NativeContextArchiveError::Source("SCCP delta differs from original witness")
        })?;
        let projection = Projection {
            carrier_height: result.get().commitment().height,
            carrier_hash: executed.hash(),
            lanes: LaneStateRef(lanes),
            ordinary_writes: OrdinaryWritesRef(&witness.writes),
            sccp_delta: sccp_delta.as_slice(),
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
            fastpq_source: None,
            fastpq_capture_complete: !projection.ordinary_writes.0.iter().any(|write|
                write.key.as_slice() == iroha_data_model::execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1),
            intents_complete: !projection
                .ordinary_writes
                .0
                .iter()
                .any(|write| prepared_intents::is_relay_key_prefix(&write.key)),
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
        if !original.intents_complete || !original.fastpq_capture_complete {
            return Err(NativeContextArchiveError::Source(
                "original intent capture is incomplete",
            ));
        }
        #[cfg(test)]
        process_crash::observe(
            &RecordName::new(original.height, original.carrier_hash, false),
            process_crash::Boundary::BeforeWrite,
        );
        #[cfg(test)]
        publication_test_hook::run()?;
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

    /// Publish optional tape transport through Kura's aggregate artifact owner.
    /// Call only after mandatory context publication. Refusal leaves the native result
    /// unchanged and proof work unresolved; no caller may report artifact completion.
    pub(crate) fn publish_fastpq_source(
        &self,
        kura: &Kura,
        original: &PreparedNativeContext,
    ) -> Result<(), NativeContextArchiveError> {
        self.recheck_namespace()?;
        if !self.writable || !original.fastpq_capture_complete {
            return Err(NativeContextArchiveError::Source(
                "original FASTPQ capture is incomplete",
            ));
        }
        let Some(source) = &original.fastpq_source else {
            return Ok(());
        };
        if !source.belongs_to(&self.budget) {
            return Err(NativeContextArchiveError::Source(
                "foreign FASTPQ source backing",
            ));
        }
        kura.persist_fastpq_source_record(
            original.height,
            original.carrier_hash,
            source.as_slice(),
        )?;
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

fn capture_sccp_delta(
    world: &crate::state::WorldBlock<'_>,
    budget: &AllocationBudget,
    maximum: usize,
) -> Result<ChargedBuffer<u8>, NativeContextArchiveError> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or(std::io::ErrorKind::InvalidData)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut length = Count(0);
    world.write_sccp_execution_delta(&mut length)?;
    if length.0 > maximum {
        return Err(NativeContextArchiveError::Limit {
            maximum,
            actual: length.0,
        });
    }
    let mut bytes = ChargedBuffer::new(length.0, budget)?;
    world.write_sccp_execution_delta(&mut BufferWriter(&mut bytes))?;
    if bytes.as_slice().len() != length.0 {
        return Err(NativeContextArchiveError::Source(
            "SCCP delta changed during capture",
        ));
    }
    Ok(bytes)
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
        const HEX: &[u8; 16] = b"0123456789abcdef";

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
    fn fastpq(height: u64, hash: HashOf<BlockHeader>, staged: bool) -> Self {
        let mut name = Self::new(height, hash, staged);
        let start = name.len - 4;
        name.bytes[start..name.len].copy_from_slice(b".fqs");
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
    open_archive_directory_named(root, "native-contexts", create)
}
#[cfg(unix)]
fn open_archive_directory_named(root: &File, namespace: &str, create: bool) -> io::Result<File> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;
    if create {
        match rustix::fs::mkdirat(&root, namespace, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => root.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let directory = File::from(rustix::fs::openat(
        &root,
        namespace,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let entry = rustix::fs::statat(&root, namespace, AtFlags::SYMLINK_NOFOLLOW)?;
    let actual = directory.metadata()?;
    if !actual.is_dir()
        || crate::kura::unix_device_identity(entry.st_dev) != actual.dev()
        || entry.st_ino != actual.ino()
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
    #[cfg(test)]
    process_crash::observe(target, process_crash::Boundary::StageSynced);
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
    #[cfg(test)]
    process_crash::observe(target, process_crash::Boundary::CanonicalSynced);
    remove_matching_stage(directory, staged.as_str(), bytes)?;
    #[cfg(test)]
    process_crash::observe(target, process_crash::Boundary::Complete);
    Ok(())
}
#[cfg(unix)]
fn verify_named_file(directory: &File, name: &str, file: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let named = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    let opened = file.metadata()?;
    if crate::kura::unix_device_identity(named.st_dev) != opened.dev()
        || named.st_ino != opened.ino()
    {
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
fn open_archive_directory_named(_root: &File, _namespace: &str, _create: bool) -> io::Result<File> {
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

#[cfg(test)]
pub(crate) mod publication_test_hook;
