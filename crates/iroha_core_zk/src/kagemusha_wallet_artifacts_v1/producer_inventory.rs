//! One signed producer inventory with complete logical dispatch and bounded original reads.
//!
//! Authentication establishes which originals the installation owner selected. It
//! does not establish that those originals implement their declared sources. The
//! native per-stage importers must reconstruct and
//! qualify every source before a wallet producer can be installed.

use std::io::Read;

use iroha_kagemusha_proof::a_relation::schedule::compiled::{
    OperationRoute, OperationSchedule, compiled_routes,
};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::*;

// Keep the existing original-read and zstd-write geometry when moving I/O scratch off stack.
const ORIGINAL_STREAM_CHUNK_BYTES: usize = 64 * 1024;

fn original_stream_buffer() -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(ORIGINAL_STREAM_CHUNK_BYTES)
        .map_err(std::io::Error::other)?;
    buffer.resize(ORIGINAL_STREAM_CHUNK_BYTES, 0);
    Ok(buffer)
}

#[path = "producer_inventory/directory.rs"]
mod directory;
pub use directory::DirectoryOriginalsV1;

#[path = "producer_inventory/transport_metadata.rs"]
mod transport_metadata;

#[path = "producer_inventory/encoded.rs"]
mod encoded;
pub use encoded::{
    ENCODED_ORIGINAL_MAX_BYTES_V1, EncodedDirectoryOriginalsV1, EncodedOriginalV1,
    EncodedTransportV1, TRANSPORT_MAX_BYTES_V1, encode_original, encode_wallet_carrier_v1,
};

#[path = "producer_inventory/recipe.rs"]
mod recipe;
pub use recipe::SourceScopeV1;

#[path = "producer_inventory/builtin.rs"]
mod builtin;
pub use builtin::StrictQualifiedSourceProfileV1;

#[path = "producer_inventory/compiler.rs"]
mod compiler;
pub use compiler::{
    CompilationErrorV1, CompilationPhaseV1, CompiledKeyV1, CompiledOmegaV1, CompiledOperationV1,
    CompiledQV1, CompiledSigmasV1, OfflineCompilerV1, OriginalSinkV1, QClassesV1,
    WalletArtifactDraftV1, WalletArtifactOriginalsV1, q_classes,
};
#[cfg(test)]
pub(crate) use compiler::{
    open_pinned_engineering_finality_sources, open_pinned_engineering_wallet_sources,
    reopen_pinned_engineering_wallet_sources,
};

#[path = "producer_inventory/finality.rs"]
mod finality;
pub use finality::{FinalityQualificationErrorV1, QualifiedReceiptSourceV1};

#[path = "producer_inventory/sigma.rs"]
mod sigma;
pub(super) use sigma::compiled_sigma_policy;

#[path = "producer_inventory/q.rs"]
mod q;
pub use q::{
    ImportedQV1, QProgramRecipeV1, QQualificationErrorV1, QQualificationProgressV1,
    QualifiedQProgramV1, q_source_recipe,
};

#[path = "producer_inventory/bootstrap.rs"]
mod bootstrap;
pub use bootstrap::{BootstrapQualificationErrorV1, QualifiedBootstrapProgramV1};
pub use sigma::{ImportedSigmaV1, QualifiedSigmasV1, SigmaQualificationErrorV1};

#[path = "producer_inventory/operation.rs"]
mod operation;
pub use operation::{
    OperationQualificationErrorV1, OperationQualificationProgressV1, QualifiedOperationOwnerV1,
    QualifiedOperationRouteV1,
};

#[path = "producer_inventory/omega.rs"]
mod omega;
pub use omega::{OmegaQualificationErrorV1, QualifiedOmegaProgramV1};

#[path = "producer_inventory/wallet.rs"]
mod wallet;
pub use wallet::{QualifiedWalletSourcesV1, WalletSourcesErrorV1};

#[path = "producer_inventory/opening_metrics.rs"]
mod opening_metrics;
pub use opening_metrics::{
    OPENING_METRICS_SCHEMA_V1, OpeningClockV1, OpeningMetricsV1, OpeningPhaseV1, OpeningWorkV1,
    QualificationMetricsV1,
};

/// Largest design §5.3 peak proving memory, under both quotient plans, over the installed
/// descriptors of `keys`. Metadata only: no proving key is read and no artifact field is added.
fn peak_proving_memory<'a, C: PastaCurve + 'a>(
    keys: impl IntoIterator<
        Item = &'a iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<C>,
    >,
) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletProvingMemoryV1, Error> {
    keys.into_iter().try_fold(Default::default(), |peak, key| {
        crate::kagemusha_wallet_capacity_v1::kagemusha_wallet_relation_proving_memory_v1(
            key.binding().descriptor(),
        )
        .map(|memory| memory.max(peak))
        .ok_or(Error::Inventory)
    })
}

/// Canonical inventory metadata cap; original proving tables are stored separately.
pub const CATALOG_MAX_BYTES_V1: usize = 16 << 20;
/// Maximum distinct wallet circuit originals in one complete native inventory.
pub const ARTIFACT_MAX_COUNT_V1: usize = 4_096;
/// Absolute per-original PK envelope bound, independent of a smaller local reader limit.
pub const PROVING_KEY_MAX_BYTES_V1: usize = 1 << 30;

/// Exact content address and byte length, with no caller-selected storage path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.original_blob.v1")]
pub struct BlobV1 {
    /// Exact original byte count, checked before allocation.
    pub bytes: u64,
    /// SHA-256 of those exact bytes.
    pub sha256: [u8; 32],
}
impl BlobV1 {
    /// Describe bytes for offline packaging; this grants no authentication.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }
    fn length(self, cap: usize) -> Result<usize, Error> {
        let length = usize::try_from(self.bytes).map_err(|_| Error::Inventory)?;
        if length == 0 || length > cap || self.sha256 == [0; 32] {
            return Err(Error::Inventory);
        }
        Ok(length)
    }
}

/// Unmodified descriptor, VK and original PK content addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.producer_original.v1")]
pub struct OriginalV1 {
    /// Canonical native descriptor bytes.
    pub descriptor: BlobV1,
    /// Canonical native verifying-key bytes.
    pub verifying_key: BlobV1,
    /// Original `PIPACPK1` source-bound key; native import reconstructs and checks its tables.
    pub proving_key: BlobV1,
}
impl OriginalV1 {
    fn validate(self) -> Result<(), Error> {
        self.descriptor.length(DESCRIPTOR_MAX_BYTES_V1)?;
        self.verifying_key.length(VERIFYING_KEY_MAX_BYTES_V1)?;
        self.proving_key.length(PROVING_KEY_MAX_BYTES_V1)?;
        Ok(())
    }
    fn matches(self, original: &ArtifactOriginalV1) -> bool {
        self.descriptor == BlobV1::of(&original.descriptor)
            && self.verifying_key == BlobV1::of(&original.verifying_key)
    }
}

/// Exact native context and installed source references for one compiled operation.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.operation_originals.v1")]
pub struct OperationV1 {
    /// One-based index in the compiled fourteen-variant order.
    pub variant: u8,
    /// Ordered global selectors admitted by the own fixed Q-sigma class.
    pub own_class: Vec<u8>,
    /// Ordered incoming class selectors, empty exactly when no incoming sigma exists.
    pub incoming_class: Vec<u8>,
    /// Exact canonical Fp words of the reconstructed native `ContextPlan` schema.
    /// The source importer must compare the whole schema, not only its length.
    pub context: Vec<[u8; 32]>,
    /// Q originals, in the operation's exact Q order.
    pub q: Vec<u32>,
    /// A originals, in the compiled stage order.
    pub a: Vec<u32>,
    /// W originals between consecutive A stages.
    pub w: Vec<u32>,
}

/// Complete canonical metadata preimage committed by the one signed artifact identity.
/// Index references select only members of `originals`; none are storage paths.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.producer_inventory.v1")]
pub struct ProducerInventoryV1 {
    /// Exactly version one, with no retired profile decoder.
    pub version: u16,
    /// Exact compiled native profile, including every wallet operation schedule.
    pub native_profile: [u8; 32],
    /// Unique original references, all consumed by this inventory.
    pub originals: Vec<OriginalV1>,
    /// All eleven sigma originals in global selector order.
    pub sigma: [u32; 11],
    /// Compiled operation programs, each referenced by at least one logical route.
    pub operations: Vec<OperationV1>,
    /// Program index for every compiled logical selector route, in that exact order.
    pub routes: Vec<u32>,
    /// Exact distinct terminal A verifier identities, in first occurrence among programs.
    pub terminals: Vec<u32>,
    /// Sole final native Omega original.
    pub omega: u32,
}

fn variant(tag: u8) -> Result<Variant, Error> {
    tag.checked_sub(1)
        .and_then(|i| Variant::ALL.get(usize::from(i)))
        .copied()
        .ok_or(Error::Inventory)
}
fn selectors(values: &[u8], empty: bool) -> Result<(), Error> {
    if (!empty && values.is_empty())
        || values.len() > SIGMA_CATALOG_V1.len()
        || values
            .iter()
            .any(|i| usize::from(*i) >= SIGMA_CATALOG_V1.len())
        || values.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(Error::Inventory);
    }
    Ok(())
}

impl ProducerInventoryV1 {
    fn member(&self, index: u32) -> Result<&OriginalV1, Error> {
        self.originals
            .get(usize::try_from(index).map_err(|_| Error::Inventory)?)
            .ok_or(Error::Inventory)
    }
    fn validate(&self) -> Result<(), Error> {
        let routes = compiled_routes();
        if self.version != 1
            || self.native_profile
                != artifact_digest(b"native-profile", &native_profile_transcript_v1()?)
            || self.originals.is_empty()
            || self.originals.len() > ARTIFACT_MAX_COUNT_V1
            || self.operations.is_empty()
            || self.operations.len() > routes.len()
            || self.routes.len() != routes.len()
            || self.terminals.is_empty()
            || self.terminals.len() > 32
        {
            return Err(Error::Inventory);
        }
        for (i, original) in self.originals.iter().enumerate() {
            original.validate()?;
            if self.originals[..i].contains(original) {
                return Err(Error::Inventory);
            }
        }
        let mut used = vec![false; self.originals.len()];
        for index in self.sigma.into_iter().chain([self.omega]) {
            self.member(index)?;
            used[usize::try_from(index).map_err(|_| Error::Inventory)?] = true;
        }
        let mut expected_terminals: Vec<u32> = Vec::new();
        let mut terminal_keys = Vec::new();
        for operation in &self.operations {
            let variant = variant(operation.variant)?;
            selectors(&operation.own_class, false)?;
            selectors(&operation.incoming_class, true)?;
            // Every own selector of the class selects the same schedule (Send's follows
            // the quota control of its mask).
            let mut schedules = operation.own_class.iter().map(|own| {
                OperationSchedule::for_route(OperationRoute {
                    variant,
                    own: *own,
                    incoming: None,
                })
            });
            let schedule = schedules.next().ok_or(Error::Inventory)?;
            if schedules.any(|other| {
                other.tasks() != schedule.tasks() || other.q_partitions() != schedule.q_partitions()
            }) {
                return Err(Error::Inventory);
            }
            let q_count = schedule.q_partitions().iter().flatten().count();
            let allowed: Vec<_> = routes
                .iter()
                .filter(|route| route.variant == variant)
                .collect();
            if operation
                .own_class
                .iter()
                .any(|selector| !allowed.iter().any(|route| route.own == *selector))
                || operation.incoming_class.iter().any(|selector| {
                    !allowed
                        .iter()
                        .any(|route| route.incoming == Some(*selector))
                })
            {
                return Err(Error::Inventory);
            }
            let incoming = matches!(
                variant,
                Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveReceive
            );
            if operation.incoming_class.is_empty() == incoming
                || operation.q.len() != q_count
                || operation.a.len() != schedule.stage_count()
                || operation.w.len() + 1 != operation.a.len()
                || operation.context.is_empty()
                || operation.context.len() > 4_096
                || operation
                    .context
                    .iter()
                    .any(|word| Option::<Fp>::from(Fp::from_repr(*word)).is_none())
            {
                return Err(Error::Inventory);
            }
            for index in operation
                .q
                .iter()
                .chain(&operation.a)
                .chain(&operation.w)
                .copied()
            {
                self.member(index)?;
                used[usize::try_from(index).map_err(|_| Error::Inventory)?] = true;
            }
            let index = *operation.a.last().ok_or(Error::Inventory)?;
            let terminal = self.member(index)?;
            let identity = (terminal.descriptor, terminal.verifying_key);
            if !terminal_keys.contains(&identity) {
                expected_terminals.push(index);
                terminal_keys.push(identity);
            }
        }
        if used.contains(&false) || self.terminals != expected_terminals {
            return Err(Error::Inventory);
        }
        let mut programs = vec![false; self.operations.len()];
        for (route, index) in routes.iter().zip(&self.routes) {
            let index = usize::try_from(*index).map_err(|_| Error::Inventory)?;
            let operation = self.operations.get(index).ok_or(Error::Inventory)?;
            if variant(operation.variant)? != route.variant
                || !operation.own_class.contains(&route.own)
                || route
                    .incoming
                    .is_some_and(|i| !operation.incoming_class.contains(&i))
            {
                return Err(Error::Inventory);
            }
            programs[index] = true;
        }
        if programs.contains(&false) {
            return Err(Error::Inventory);
        }
        Ok(())
    }
    /// Canonical bounded packaging bytes; structural validation is not source admission.
    /// # Errors
    /// Missing/reordered dispatch, invalid references/caps, malformed fields or encoding failure.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = norito::encode_canonical(self).map_err(|_| Error::Inventory)?;
        bounded(&bytes, CATALOG_MAX_BYTES_V1)?;
        Ok(bytes)
    }
    /// Exact domain-separated commitment included in the signed twelve-verifier inventory.
    /// # Errors
    /// The complete bounded canonical inventory cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        Ok(artifact_digest(
            b"producer-catalog",
            &self.to_canonical_bytes()?,
        ))
    }
}

/// Content-addressed read boundary. Implementations return an original byte stream,
/// never allocate from an unchecked declared size or resolve a witness-selected path.
pub trait OriginalSourceV1 {
    /// Open one selected original by its authenticated SHA-256 content address.
    /// # Errors
    /// Return `Error::Unavailable` for absent content or storage failure. Invalid
    /// selections remain `Error::Inventory`; neither permits replacement material.
    fn open(&mut self, sha256: [u8; 32]) -> Result<Box<dyn Read + '_>, Error>;

    /// The same originals as an immutable view that several threads may read at once.
    /// Only a source whose every read is served from memory that was captured and
    /// verified before this call returns one. A live directory returns `None` and keeps
    /// its per-read custody checks on the thread that holds it.
    fn shared_view(&self) -> Option<&(dyn SharedOriginalSourceV1 + Sync)> {
        None
    }
}

/// Concurrent reads of immutable originals whose stored bytes were verified before
/// this view existed. Every open still decodes and checks its original afresh; a view
/// grants no source, installation or wallet authority.
pub trait SharedOriginalSourceV1 {
    /// Open one selected original by its authenticated SHA-256 content address.
    /// # Errors
    /// As [`OriginalSourceV1::open`].
    fn open_shared(&self, sha256: [u8; 32]) -> Result<Box<dyn Read + '_>, Error>;
}

/// One active original for strict source import; drop it after the importer returns.
pub struct OriginalBytesV1 {
    /// Original descriptor.
    pub descriptor: Vec<u8>,
    /// Original verifier.
    pub verifying_key: Vec<u8>,
    /// Original proving tables; no other PK is retained by the inventory view.
    pub proving_key: Vec<u8>,
}

/// Most distinct descriptors one qualification keeps for reuse; others still decode.
const DESCRIPTOR_MEMO_MAX_ENTRIES: usize = 64;

// Exact-byte reuse of canonical V2 descriptor decodes within one qualification.
// That qualification creates it empty and drops it when it returns: it is never
// cloned, retained by an owner, persisted or shared between calls, and only a
// successful decode of the very bytes it is keyed by adds an entry (at most
// `DESCRIPTOR_MEMO_MAX_ENTRIES`). Lookups are keyed by the content address that
// a bounded, length-, SHA-256- and custody-checked read has just verified, and a
// hit is used only after those fresh bytes equal the decoded frame in full. A hit
// is the value a fresh decode returns. It grants no role, source or installation
// authority, and every check at the use site still runs. The qualification's route
// workers share it: a miss decodes while holding its lock, so workers that read the
// same address wait for that one decode instead of repeating it, and each distinct
// descriptor decodes as often as with one worker.
struct DescriptorMemo {
    entries: std::sync::Mutex<Vec<([u8; 32], DescriptorBinding)>>,
    capacity: usize,
}

impl Default for DescriptorMemo {
    fn default() -> Self {
        Self {
            entries: std::sync::Mutex::default(),
            capacity: DESCRIPTOR_MEMO_MAX_ENTRIES,
        }
    }
}

impl DescriptorMemo {
    // Differential reference: a memo that keeps at most `capacity` entries, so
    // zero decodes every read afresh.
    #[cfg(test)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: std::sync::Mutex::default(),
            capacity,
        }
    }

    // `DescriptorBinding::decode_v2(bytes)`, reusing this qualification's earlier
    // successful decode of byte-identical content at the same verified address.
    // Errors are returned as decoded and never stored.
    fn decode_v2(
        &self,
        address: [u8; 32],
        bytes: &[u8],
    ) -> Result<DescriptorBinding, iroha_plonk::cs::DescriptorError> {
        // A worker that panicked while holding the memo leaves it unused: every later
        // read decodes afresh, which returns the same value.
        let Ok(mut entries) = self.entries.lock() else {
            return DescriptorBinding::decode_v2(bytes);
        };
        if let Some((_, binding)) = entries
            .iter()
            .find(|(key, binding)| *key == address && binding.encoded() == bytes)
        {
            return Ok(binding.clone());
        }
        let binding = DescriptorBinding::decode_v2(bytes)?;
        if entries.len() < self.capacity {
            entries.push((address, binding.clone()));
        }
        Ok(binding)
    }
}

// One freshly read and hash-checked descriptor/VK pair with the canonical
// decode of that descriptor. The verifying key is still read by its owner.
struct DecodedVerifierOriginal {
    binding: Result<DescriptorBinding, iroha_plonk::cs::DescriptorError>,
    verifying_key: Vec<u8>,
}

/// Immutable signed inventory view. This has no `NativeProofs` implementation,
/// wallet-open capability or conversion to one based on a caller-provided verdict.
pub struct AuthenticatedProducerInventoryV1 {
    inventory: ProducerInventoryV1,
    scheme_id: [u8; 32],
    manifest_digest: [u8; 32],
}
impl InstalledVerifierPackV1 {
    /// Authenticate the exact canonical producer preimage selected by this same manifest.
    /// This checks complete logical dispatch and shared verifier originals; every
    /// native source, child key, context schema and original PK still requires import.
    /// # Errors
    /// Wrong commitment, incomplete metadata, malformed/capped frame or replaced verifier.
    pub fn authenticate_producer_inventory(
        &self,
        bytes: &[u8],
    ) -> Result<AuthenticatedProducerInventoryV1, Error> {
        bounded(bytes, CATALOG_MAX_BYTES_V1)?;
        if artifact_digest(b"producer-catalog", bytes) != self.pack.producer_catalog_digest {
            return Err(Error::Inventory);
        }
        let inventory: ProducerInventoryV1 = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|_| Error::Inventory)?;
        inventory.validate()?;
        for (index, original) in inventory.sigma.into_iter().zip(&self.pack.steps) {
            if !inventory.member(index)?.matches(&original.artifact) {
                return Err(Error::Inventory);
            }
        }
        if !inventory
            .member(inventory.omega)?
            .matches(&self.pack.lineage)
        {
            return Err(Error::Inventory);
        }
        Ok(AuthenticatedProducerInventoryV1 {
            inventory,
            scheme_id: self.verifier.scheme().scheme_id(),
            manifest_digest: self.verifier.manifest_digest(),
        })
    }
}

fn read(source: &mut dyn OriginalSourceV1, blob: BlobV1, cap: usize) -> Result<Vec<u8>, Error> {
    read_cancellable(source, blob, cap, None)
}

// Preserve a native retained reader's integrity refusal across std::io::Read.
// An ordinary I/O error cannot acquire this marker from an error message or kind.
#[derive(Debug)]
struct OriginalCustodyFailure(std::io::Error);

impl std::fmt::Display for OriginalCustodyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original custody refused: {}", self.0)
    }
}

impl std::error::Error for OriginalCustodyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn read_cancellable(
    source: &mut dyn OriginalSourceV1,
    blob: BlobV1,
    cap: usize,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<Vec<u8>, Error> {
    scan_cancellable(
        source,
        blob,
        cap,
        cancellation,
        Vec::with_capacity,
        |bytes, chunk| bytes.extend_from_slice(chunk),
    )
}

// Both collecting and hash-only callers consume the same bounded retained reader.
// A successful scan authenticates exact bytes only; it grants no source capability.
#[expect(
    clippy::large_stack_arrays,
    reason = "the fixed 64 KiB buffer preserves read/cancellation geometry without introducing an allocation refusal into the tag-only artifact error API"
)]
fn scan_cancellable<T>(
    source: &mut dyn OriginalSourceV1,
    blob: BlobV1,
    cap: usize,
    cancellation: Option<&iroha_pasta::CancellationToken>,
    initialize: impl FnOnce(usize) -> T,
    mut accept: impl FnMut(&mut T, &[u8]),
) -> Result<T, Error> {
    let check =
        || iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled);
    check()?;
    let length = blob.length(cap)?;
    let maximum = blob.bytes.checked_add(1).ok_or(Error::Inventory)?;
    // The original source retains its locator/inode checks; this layer bounds each
    // read and hashes those exact bytes without a second uncancellable whole-PK pass.
    opening_metrics::record_original_opened();
    let opened = source.open(blob.sha256);
    check()?;
    let mut reader = opened?.take(maximum);
    let mut output = initialize(length);
    let mut consumed = 0_usize;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check()?;
        let result = reader.read(&mut buffer);
        // A signal observed while I/O completed is cancellation, not an artifact
        // outage or invalid hash. A blocked OS read itself cannot be interrupted here.
        check()?;
        let count = match result {
            Err(error)
                if error
                    .get_ref()
                    .is_some_and(|cause| cause.is::<OriginalCustodyFailure>()) =>
            {
                return Err(Error::Inventory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(|_| Error::Unavailable)?,
        };
        if count == 0 {
            break;
        }
        if count > length.saturating_sub(consumed) {
            return Err(Error::Inventory);
        }
        hash.update(&buffer[..count]);
        accept(&mut output, &buffer[..count]);
        consumed += count;
    }
    opening_metrics::record_raw_hashed(consumed as u64);
    check()?;
    let actual: [u8; 32] = hash.finalize().into();
    if consumed != length || actual != blob.sha256 {
        return Err(Error::Inventory);
    }
    Ok(output)
}

impl AuthenticatedProducerInventoryV1 {
    /// Signed immutable inventory metadata; reading it grants no source capability.
    #[must_use]
    pub const fn inventory(&self) -> &ProducerInventoryV1 {
        &self.inventory
    }
    /// Exact independently installed scheme and manifest identities, in that order.
    #[must_use]
    pub const fn installation(&self) -> ([u8; 32], [u8; 32]) {
        (self.scheme_id, self.manifest_digest)
    }
    /// Read one authenticated descriptor/VK pair, retaining no PK bytes.
    /// The concrete native owner still parses and qualifies the exact source identity.
    /// # Errors
    /// Unknown member or absent, truncated, extended or changed metadata originals.
    pub fn read_verifier_original(
        &self,
        index: u32,
        source: &mut dyn OriginalSourceV1,
    ) -> Result<ArtifactOriginalV1, Error> {
        let original = *self.inventory.member(index)?;
        Ok(ArtifactOriginalV1 {
            descriptor: read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1)?,
            verifying_key: read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1)?,
        })
    }
    // `read_verifier_original`, then the canonical V2 decode of the fresh
    // descriptor through `descriptors`, keyed by the content address this read
    // verified. Every read check runs on every call; only the decode is reused.
    fn read_verifier_metadata(
        &self,
        index: u32,
        source: &mut dyn OriginalSourceV1,
        descriptors: &DescriptorMemo,
    ) -> Result<DecodedVerifierOriginal, Error> {
        let original = self.read_verifier_original(index, source)?;
        let address = self.inventory.member(index)?.descriptor.sha256;
        Ok(DecodedVerifierOriginal {
            binding: descriptors.decode_v2(address, &original.descriptor),
            verifying_key: original.verifying_key,
        })
    }
    /// Revalidate all three selected originals without retaining their payloads.
    ///
    /// This checks signed content identity and current reader custody only. A
    /// source-qualified owner must separately retain its opaque strict-import
    /// authority and enforce the current row/profile limits before using it.
    /// No key, source capability, or durable filesystem snapshot is returned.
    /// # Errors
    /// Invalid member or local limit, cancelled I/O, unavailable original, or a
    /// length, digest or retained-custody mismatch. All role caps precede any open.
    pub(crate) fn revalidate_original_cancellable(
        &self,
        index: u32,
        source: &mut dyn OriginalSourceV1,
        maximum_pk_bytes: usize,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        if maximum_pk_bytes == 0 || maximum_pk_bytes > PROVING_KEY_MAX_BYTES_V1 {
            return Err(Error::Inventory);
        }
        let original = *self.inventory.member(index)?;
        let roles = [
            (original.descriptor, DESCRIPTOR_MAX_BYTES_V1),
            (original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1),
            (original.proving_key, maximum_pk_bytes),
        ];
        for (blob, cap) in roles {
            blob.length(cap)?;
        }
        for (blob, cap) in roles {
            scan_cancellable(source, blob, cap, cancellation, |_| (), |(), _| {})?;
        }
        Ok(())
    }

    /// Read and hash-check one original, with a finite local PK limit before allocation.
    /// The caller must pass these bytes to the exact source-specific native importer.
    /// # Errors
    /// Unknown member, invalid local limit, absent/truncated/extended/mutated original.
    pub fn read_original(
        &self,
        index: u32,
        source: &mut dyn OriginalSourceV1,
        maximum_pk_bytes: usize,
    ) -> Result<OriginalBytesV1, Error> {
        self.read_original_cancellable(index, source, maximum_pk_bytes, None)
    }

    /// Read one exact original with cooperative checks between bounded reads and hashes.
    /// The source retains all descriptor-relative custody checks. This cannot interrupt
    /// a blocked operating-system read, and never returns a partial original.
    /// # Errors
    /// As [`Self::read_original`], or caller cancellation without an artifact verdict.
    pub fn read_original_cancellable(
        &self,
        index: u32,
        source: &mut dyn OriginalSourceV1,
        maximum_pk_bytes: usize,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<OriginalBytesV1, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        if maximum_pk_bytes == 0 || maximum_pk_bytes > PROVING_KEY_MAX_BYTES_V1 {
            return Err(Error::Inventory);
        }
        let original = *self.inventory.member(index)?;
        original.proving_key.length(maximum_pk_bytes)?;
        Ok(OriginalBytesV1 {
            descriptor: read_cancellable(
                source,
                original.descriptor,
                DESCRIPTOR_MAX_BYTES_V1,
                cancellation,
            )?,
            verifying_key: read_cancellable(
                source,
                original.verifying_key,
                VERIFYING_KEY_MAX_BYTES_V1,
                cancellation,
            )?,
            proving_key: read_cancellable(
                source,
                original.proving_key,
                maximum_pk_bytes,
                cancellation,
            )?,
        })
    }
}

#[cfg(test)]
#[path = "producer_inventory/tests.rs"]
mod tests;
