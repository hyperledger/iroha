//! Original native certificate and proof DATA from one immutable committed view.
//!
//! Server source selection uses the original execution tip, journal and executed generation store.
//! Offered `X` never selects scope or the signing generation. A destination independently
//! authenticates every returned certificate against its own current committee state.

use std::{
    mem::size_of,
    num::NonZeroU64,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};
use iroha_crypto::bls::consensus::ConsensusAggregateScratch;
use iroha_data_model::{
    NetworkId,
    block::consensus::SumeragiRootScope,
    bridge::SccpNetworkV1,
    sccp::control::SccpLeafRefV1,
    sumeragi_finality::{
        SumeragiCommitCertificateV1,
        certified_result::{
            CertifiedResultError, CertifiedResultScope, CertifiedResultV1, MAX_HISTORY_SIZE,
            SccpFinalityHeaderV1, X_LEN, body_digest, result_of_preimage,
        },
    },
};
use iroha_sccp::{
    api::{
        SccpBlockRefV1, SccpCertificateV1, SccpControlProofBundleV1, SccpMessageProofBundleV1,
        SccpRotationV1,
    },
    v1::{
        control::{ControlLeafV1, control_leaf},
        finality::{
            CertificateError, QcFixedV1, check_signers, signers_from_bitmap,
            verify_certificate_with_scratch,
        },
        hashes::{history_leaf, message_id, node, payload_hash, transfer_leaf},
        payload::SccpTransferPayloadRefV1,
    },
};
use iroha_sumeragi::{
    message::{BlockHeader, Qc, VoteKind},
    types::Hash32,
};

use super::super::{generation_record::RetainedSccpGeneration, store};
use crate::{
    state::{State, StateReadOnly, StateView, StateViewError, WorldReadOnly},
    sumeragi::{
        crypto::BlsCrypto,
        finality::{
            NativeCommitCertificateDataV1, NativeCommitCertificateReadErrorV1,
            read_commit_certificate,
        },
    },
};

/// Maximum native generation transitions in one catch-up response (§6).
pub const MAX_NATIVE_ROTATIONS: usize = 16;
pub mod evidence;
/// Borrowed, request-funded registry and governance metadata.
pub mod governance_metadata;
/// Request-funded light-client metadata.
pub mod light_client_metadata;
/// Borrowed, request-funded message metadata.
pub mod message_metadata;
mod reconciliation;
pub use reconciliation::forgery_hold;
mod fast_pause;
pub use fast_pause::{RetainedFastPauseView, anchor_witness, fast_pause};
const MAX_KEYS: usize = 31;
const MAX_BLOCK_LEAVES: usize = 512;
const MAX_PAYLOAD_BYTES: usize = 4096;
const CERTIFICATE_HEAP_BYTES: usize = MAX_KEYS * 48;
const PATH_HEAP_BYTES: usize = (9 + 32) * 32;

/// Why original native SCCP DATA cannot be served. Local refusal remains distinct from
/// missing records, malformed original data and an authenticated non-Global source.
#[derive(Debug, thiserror::Error)]
pub enum SccpNativeReadError {
    /// One-shot committed-view acquisition failed; `Busy` retains its original retry source.
    #[error(transparent)]
    View(#[from] StateViewError),
    /// The request was cancelled. The worker retains admission until this operation retires.
    #[error("native SCCP request cancelled")]
    Cancelled,
    /// The original committed tip or generation source is unavailable or inconsistent.
    #[error("native SCCP source unavailable: {0}")]
    Unavailable(&'static str),
    /// The original signed root belongs to an authenticated private/child instance.
    #[error("native SCCP certificates require the original Global root")]
    UnsupportedScope,
    /// A requested retained record does not exist. This does not mean it was pruned.
    #[error("native SCCP record not found: {0}")]
    NotFound(&'static str),
    /// A prior generation is no longer retained under the committed retention policy.
    #[error("native SCCP record pruned: {0}")]
    Pruned(&'static str),
    /// A genuine outgoing rotation passed its deadline at the authenticated committed tip.
    #[error("native SCCP rotation is outside its committed retention window")]
    RotationPruned,
    /// The requested certificate's original header is inactive.
    #[error("the selected original native result is inactive")]
    Inactive,
    /// The client selected an invalid height, cursor, page limit or proof position.
    #[error("invalid native SCCP request: {0}")]
    Request(&'static str),
    /// An original committed record violates a required binding.
    #[error("invalid native SCCP data: {0}")]
    Invalid(&'static str),
    /// The original compact reader's typed storage, framing or admission error.
    #[error(transparent)]
    Source(#[from] NativeCommitCertificateReadErrorV1),
    /// The original caller's allocation pool refused this demand.
    #[error(transparent)]
    Allocation(#[from] AllocationRefusal),
    /// Physical allocation failed after admission by the original caller's pool.
    #[error("native SCCP response allocation failed")]
    PhysicalAllocation,
    /// A bounded native decoder refused local resources.
    #[error("native SCCP decoder resource refusal: {0}")]
    DecodeResource(norito::core::DecodeResourceError),
    /// The native header/QC frame is malformed; resource failures use `DecodeResource`.
    #[error("malformed native SCCP frame: {0}")]
    Frame(norito::Error),
    /// Result validation, including the typed nested `Body(Resource)` local refusal.
    #[error(transparent)]
    CertifiedResult(#[from] CertifiedResultError),
    /// The original native certificate failed the server's required destination relation.
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    /// The original request deadline expired, including during a bounded history scan.
    #[error("native SCCP request deadline expired")]
    Deadline,
}

type Result<T> = core::result::Result<T, SccpNativeReadError>;

/// The original route's deadline and cooperatively observed cancellation flag.
#[derive(Clone, Copy)]
pub struct SccpNativeReadControl<'a> {
    /// Original route deadline; the reader creates no replacement wall timeout.
    pub deadline: Instant,
    /// Original admitted worker cancellation flag; it is borrowed, not replaced.
    pub stop: &'a AtomicBool,
}

/// Attempt exactly one committed-view acquisition in the admitted worker.
///
/// # Errors
/// Preserves `StateViewError::Busy` and runtime/storage failures; checks the original
/// stop/deadline before acquisition, before `work`, and before returning its response.
pub fn with_state_view<T>(
    state: &State,
    control: SccpNativeReadControl<'_>,
    work: impl FnOnce(&StateView<'_>) -> Result<T>,
) -> Result<T> {
    deadline_check(control)?;
    let view = state.try_view_once()?;
    deadline_check(control)?;
    let value = work(&view)?;
    deadline_check(control)?;
    Ok(value)
}

/// A response together with its original caller-pool admission. This is DATA, not a
/// verified certificate or an authority capability. Do not release the charge while
/// retaining the DTO. The transport must separately admit its encoded response buffer.
pub struct SccpNativeDataV1<T> {
    pub(super) data: T,
    pub(super) _charge: AllocationReservation,
}

impl<T> SccpNativeDataV1<T> {
    /// Borrow the offered response without granting it finality authority.
    #[must_use]
    pub const fn data(&self) -> &T {
        &self.data
    }
}

/// Select the original certificate enclosing a message proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpNativeProofAt {
    /// The record's own committed block.
    Record,
    /// The captured committed tip (never a search for a more convenient active header).
    Latest,
    /// One explicitly selected committed height.
    Height(NonZeroU64),
}

#[derive(Clone, Copy)]
struct SourceIdentity {
    network: [u8; 32],
    instance: Hash32,
    height: u64,
    timestamp_ms: u64,
}

pub(super) fn deadline_check(control: SccpNativeReadControl<'_>) -> Result<()> {
    if control.stop.load(Ordering::Acquire) {
        return Err(SccpNativeReadError::Cancelled);
    }
    if Instant::now() >= control.deadline {
        return Err(SccpNativeReadError::Deadline);
    }
    Ok(())
}

fn source_identity(
    view: &impl StateReadOnly,
    control: SccpNativeReadControl<'_>,
) -> Result<SourceIdentity> {
    deadline_check(control)?;
    let tip = view
        .native_execution_tip()
        .ok_or(SccpNativeReadError::Unavailable(
            "original committed execution tip is absent",
        ))?;
    let height = u64::try_from(view.height())
        .map_err(|_| SccpNativeReadError::Unavailable("journal height exceeds u64"))?;
    if tip.height() != height
        || view
            .height()
            .checked_sub(1)
            .and_then(|i| view.block_hashes().get(i))
            != Some(&tip.iroha_hash())
        || view
            .block_hashes()
            .get(0)
            .map(|h| NetworkId::from_genesis_hash(*h))
            != Some(*view.network_id())
    {
        return Err(SccpNativeReadError::Unavailable(
            "tip, journal and network disagree",
        ));
    }
    let scope = tip.root_scope();
    if scope != SumeragiRootScope::Global {
        return Err(SccpNativeReadError::UnsupportedScope);
    }
    let instance = scope
        .instance_id(
            &BlsCrypto::new(),
            *view.network_id(),
            view.chain_id().as_str(),
        )
        .map_err(|_| SccpNativeReadError::Unavailable("original root scope is invalid"))?;
    Ok(SourceIdentity {
        network: *view.network_id().as_bytes(),
        instance,
        height,
        timestamp_ms: tip.creation_time_ms(),
    })
}

fn checked_height(height: u64, source: SourceIdentity) -> Result<NonZeroU64> {
    if !(2..=source.height).contains(&height) {
        return Err(SccpNativeReadError::Request(
            "certificate height is genesis or outside the view",
        ));
    }
    NonZeroU64::new(height).ok_or(SccpNativeReadError::Request("zero height"))
}

/// Select solely by the requested height and the executed generation ranges. `X.generation`
/// is checked only afterwards. End height is inclusive; the successor starts at `end + 1`.
fn signing_generation<'a>(
    world: &'a (impl WorldReadOnly + ?Sized),
    height: u64,
    control: SccpNativeReadControl<'_>,
) -> Result<&'a RetainedSccpGeneration> {
    let mut selected = None;
    for (number, record) in store::committee_generations::iter(world) {
        deadline_check(control)?;
        if !store::committee_generations::valid_entry(number, record) {
            return Err(SccpNativeReadError::Unavailable(
                "malformed executed generation",
            ));
        }
        if record.start_height <= height
            && record
                .end
                .as_ref()
                .is_none_or(|end| height <= end.end_height)
        {
            if selected.is_some() {
                return Err(SccpNativeReadError::Unavailable(
                    "overlapping executed generations",
                ));
            }
            selected = Some(record);
        }
    }
    selected.ok_or(SccpNativeReadError::Unavailable(
        "no executed signing generation at the selected height",
    ))
}

fn copy_slice<T: Copy>(values: &[T]) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    result.extend_from_slice(values);
    Ok(result)
}

fn frame_error(error: norito::Error) -> SccpNativeReadError {
    match error.decode_resource_error() {
        Some(resource) => SccpNativeReadError::DecodeResource(resource),
        None => SccpNativeReadError::Frame(error),
    }
}

/// Read the current generation from one authenticated committed view while sharing its
/// original funded key/member graph. A boundary may already have installed the successor.
///
/// # Errors
/// Preserves original scope, missing source, cancellation and deadline refusals.
pub fn current_committee(
    view: &impl StateReadOnly,
    control: SccpNativeReadControl<'_>,
) -> Result<super::RetainedSccpGenerationView> {
    committee_data(view, None, control)
}

/// Read a retained generation and its liability at this same authenticated committed view.
/// This response is DATA, never a destination pin or finality capability.
///
/// # Errors
/// Missing or malformed current authority is unavailable; requested absence and pruning
/// remain distinct. The retained graph requires no new response-owned committee allocation.
pub fn committee(
    view: &impl StateReadOnly,
    generation: NonZeroU64,
    control: SccpNativeReadControl<'_>,
) -> Result<super::RetainedSccpGenerationView> {
    committee_data(view, Some(generation), control)
}

fn committee_data(
    view: &impl StateReadOnly,
    requested: Option<NonZeroU64>,
    control: SccpNativeReadControl<'_>,
) -> Result<super::RetainedSccpGenerationView> {
    let _source = source_identity(view, control)?;
    let world = view.world();
    let current = *store::committee_current::get(world);
    store::committee_generations::get(world, &current)
        .filter(|record| store::committee_generations::valid_entry(&current, record))
        .ok_or(SccpNativeReadError::Unavailable(
            "current generation source is absent or malformed",
        ))?;
    let number = requested.map_or(current, NonZeroU64::get);
    if let Some(record) = store::committee_generations::get(world, &number) {
        if !store::committee_generations::valid_entry(&number, record) {
            return Err(SccpNativeReadError::Unavailable(
                "malformed retained generation",
            ));
        }
    }
    let response = super::committee(world, number).map_err(|error| match error {
        super::SccpReadError::NotFound(_) => SccpNativeReadError::NotFound("committee generation"),
        super::SccpReadError::Pruned(_) => SccpNativeReadError::Pruned("committee generation"),
        super::SccpReadError::Invalid(_) => {
            SccpNativeReadError::Request("invalid committee generation")
        }
    })?;
    deadline_check(control)?;
    Ok(response)
}

/// The caller prepays the bounded returned committee. The original source and all decoder
/// graphs keep their own same-pool reservations until those temporaries are destroyed.
fn certificate(
    view: &impl StateReadOnly,
    height: NonZeroU64,
    source: SourceIdentity,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpCertificateV1> {
    deadline_check(control)?;
    let original = read_commit_certificate(view, height, budget, control.deadline)?;
    deadline_check(control)?;
    project_original(
        view.world(),
        height,
        source,
        original.certificate(),
        &original,
        budget,
        control,
    )
}

// Private DATA projection kernel: the production caller above supplies only the original
// compact reader's retained bytes. Tests mutate those bytes to exercise source rejection;
// this function verifies the original executed generation's certificate relation and
// exact executed-frame binding without creating a destination trust capability.
fn project_original(
    world: &(impl WorldReadOnly + ?Sized),
    height: NonZeroU64,
    source: SourceIdentity,
    raw: &SumeragiCommitCertificateV1,
    original: &NativeCommitCertificateDataV1,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpCertificateV1> {
    deadline_check(control)?;
    raw.validate_shape()
        .map_err(|_| SccpNativeReadError::Invalid("original certificate component extent"))?;
    let decode_bytes = raw
        .consensus_header
        .len()
        .checked_add(raw.commit_qc.len())
        .and_then(|n| n.checked_add(raw.result_preimage.len()))
        .ok_or(SccpNativeReadError::Invalid(
            "native decode extent overflows",
        ))?;
    let limits = norito::canonical_decode_limits(decode_bytes);
    let scratch_bytes = limits
        .max_total_allocated_bytes()
        .checked_mul(2)
        .and_then(|n| {
            n.checked_add(
                size_of::<BlockHeader>() + size_of::<Qc>() + size_of::<CertifiedResultV1>(),
            )
        })
        .ok_or(SccpNativeReadError::Invalid(
            "native scratch extent overflows",
        ))?;
    let _scratch = budget.try_reserve_bytes(scratch_bytes)?;
    norito::with_decode_limits_scope(limits, || {
        let header: BlockHeader =
            norito::decode_canonical_with_limits(&raw.consensus_header, limits)
                .map_err(frame_error)?;
        let qc: Qc =
            norito::decode_canonical_with_limits(&raw.commit_qc, limits).map_err(frame_error)?;
        let result =
            CertifiedResultV1::decode(&raw.result_preimage, CertifiedResultScope::TairaGlobal)?;
        let x = result.header();
        let expected = original.executed_wire_identity();
        let execution = &result.commitment().execution;
        if (
            execution.executed_block_wire_len,
            execution.executed_block_wire_hash,
        ) != expected
        {
            return Err(SccpNativeReadError::Invalid(
                "signed execution differs from the original stored frame",
            ));
        }
        let original_header = original.original_header();
        let timestamp_ms = u64::try_from(original_header.creation_time().as_millis())
            .map_err(|_| SccpNativeReadError::Invalid("original block time exceeds u64"))?;
        result.check_block(original_header.height().get(), timestamp_ms)?;
        if !x.is_active() {
            return Err(SccpNativeReadError::Inactive);
        }
        let generation = signing_generation(world, height.get(), control)?;
        if header.height != height.get()
            || qc.height != height.get()
            || x.height() != height.get()
            || header.instance != source.instance
            || qc.instance != source.instance
            || qc.epoch != header.epoch
            || qc.kind != VoteKind::Commit
            || qc.block_hash != header.hash(&BlsCrypto::new())
            || Some(qc.result) != result_of_preimage(&raw.result_preimage)
            || x.network_id() != source.network
            || x.generation() != generation.generation
            || x.committee_root() != generation.committee_root
        {
            return Err(SccpNativeReadError::Invalid(
                "original certificate, result and selected generation disagree",
            ));
        }
        let signers = signers_from_bitmap(qc.signers.as_bytes(), generation.keys.len())
            .ok_or(SccpNativeReadError::Invalid("native signer bitmap shape"))?;
        check_signers(signers, generation.keys.len()).map_err(|_| {
            SccpNativeReadError::Invalid("native signer set is not an exact quorum")
        })?;
        let fixed = QcFixedV1 {
            epoch: qc.epoch.epoch,
            epoch_context: qc.epoch.context.0,
            view: qc.view,
            block_hash: qc.block_hash.0,
            result_body: body_digest(&raw.result_preimage[X_LEN..]),
            signers,
        };
        deadline_check(control)?;
        let data = SccpCertificateV1 {
            height: height.get(),
            qc: fixed.encode(),
            aggregate_signature: qc.agg_sig.0,
            header: *x.as_bytes(),
            committee: copy_slice(&generation.keys)?,
        };
        data.check_shape()
            .map_err(|_| SccpNativeReadError::Invalid("native certificate shape"))?;
        deadline_check(control)?;
        if verify_original_relation(&data, source.instance, &generation.keys, budget, control)?
            != qc.result
        {
            return Err(SccpNativeReadError::Invalid(
                "verified native result differs",
            ));
        }
        Ok(data)
    })
}

// The original executed generation supplies these borrowed keys. A DATA committee is
// never an independent trust pin. Admission funds the exact pairing backing before it
// exists; its canonical owner retires that backing before refunding this original pool.
fn verify_original_relation(
    data: &SccpCertificateV1,
    instance: Hash32,
    keys: &[[u8; 48]],
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<Hash32> {
    deadline_check(control)?;
    let mut scratch = ConsensusAggregateScratch::new(|bytes| budget.try_reserve_bytes(bytes))?;
    let verified = verify_certificate_with_scratch(
        &instance.0,
        &data.qc,
        &data.header,
        &data.aggregate_signature,
        keys,
        &mut scratch,
    )?;
    drop(scratch);
    deadline_check(control)?;
    Ok(Hash32(verified.result))
}

/// Read an original active native certificate at `height`, or the captured tip for `None`.
/// A genesis-only tip has no Commit certificate: latest is unavailable, not an invalid selector.
///
/// # Errors
/// Preserves original source/resource failures; rejects non-Global roots, inactive headers,
/// invalid selectors, generation mismatch, noncanonical native frames, non-exact quorums,
/// invalid aggregate signatures and a signed result that differs from the exact stored execution.
pub fn finality(
    view: &impl StateReadOnly,
    height: Option<NonZeroU64>,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<SccpCertificateV1>> {
    let source = source_identity(view, control)?;
    if height.is_none() && source.height < 2 {
        return Err(SccpNativeReadError::Unavailable(
            "the original tip has no Commit certificate yet",
        ));
    }
    let height = checked_height(height.map_or(source.height, NonZeroU64::get), source)?;
    let charge =
        budget.try_reserve_bytes(size_of::<SccpCertificateV1>() + CERTIFICATE_HEAP_BYTES)?;
    let data = certificate(view, height, source, budget, control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Return the transitions starting with `after_generation -> after_generation + 1`.
/// The cursor is the destination's current generation, as specified by §6; each certificate
/// is signed by that transition's outgoing committee. No resync gap is a rotation.
///
/// # Errors
/// Rejects a zero/unknown cursor, limits outside `1..=16`, unavailable original certificates,
/// resync gaps, mismatched successor records and rotations past their outgoing generation's
/// deadline at the original committed tip. The deadline is inclusive. Preserves typed
/// resource failures; a missing source is never evidence of expiry.
pub fn committee_rotations(
    view: &impl StateReadOnly,
    after_generation: u64,
    limit: usize,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Vec<SccpRotationV1>>> {
    let source = source_identity(view, control)?;
    if after_generation == 0 || !(1..=MAX_NATIVE_ROTATIONS).contains(&limit) {
        return Err(SccpNativeReadError::Request("rotation cursor or limit"));
    }
    let charge = budget.try_reserve_bytes(
        size_of::<Vec<SccpRotationV1>>()
            + limit * (size_of::<SccpRotationV1>() + 2 * CERTIFICATE_HEAP_BYTES),
    )?;
    let mut data = Vec::new();
    data.try_reserve_exact(limit)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    let mut number = after_generation;
    for _ in 0..limit {
        deadline_check(control)?;
        let current = store::committee_generations::get(view.world(), &number)
            .ok_or(SccpNativeReadError::NotFound("requested generation"))?;
        if !store::committee_generations::valid_entry(&number, current) {
            return Err(SccpNativeReadError::Unavailable(
                "malformed outgoing generation",
            ));
        }
        let Some(end) = &current.end else { break };
        let next_number = number
            .checked_add(1)
            .ok_or(SccpNativeReadError::Invalid("generation overflow"))?;
        let next = store::committee_generations::get(view.world(), &next_number).ok_or(
            SccpNativeReadError::Unavailable("missing successor generation"),
        )?;
        if !store::committee_generations::valid_entry(&next_number, next)
            || Some(next.start_height) != end.end_height.checked_add(1)
            || next.committee_root != end.next_committee_root
        {
            return Err(SccpNativeReadError::Unavailable(
                "successor generation does not bind the handoff",
            ));
        }
        if !(2..=source.height).contains(&end.end_height) {
            return Err(SccpNativeReadError::Invalid(
                "recorded rotation end is outside committed certificate history",
            ));
        }
        let cert = certificate(
            view,
            checked_height(end.end_height, source)?,
            source,
            budget,
            control,
        )?;
        let x = SccpFinalityHeaderV1::parse(&cert.header)
            .map_err(|_| SccpNativeReadError::Invalid("rotation header"))?;
        if !x.is_rotation()
            || x.generation() != number
            || x.next_committee_root() != next.committee_root
            || x.validity_ms() != end.successor_validity_ms
            || x.timestamp_ms() != end.end_timestamp_ms
        {
            return Err(SccpNativeReadError::Invalid(
                "generation end has no matching original rotation",
            ));
        }
        // Only the genuine original rotation and its retained generation establish expiry.
        // Local wall time, an absent archive, and an offered DATA timestamp cannot do so.
        if current.deadline_ms < source.timestamp_ms {
            return Err(SccpNativeReadError::RotationPruned);
        }
        data.push(SccpRotationV1 {
            certificate: cert,
            next_committee: copy_slice(&next.keys)?,
        });
        number = next_number;
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Read a retained message and its block/history path under the selected original certificate.
///
/// # Errors
/// Rejects missing/mismatched committed records and paths, a certificate before the message,
/// and the same scope/source/resource failures as [`finality`].
pub fn message_proof(
    view: &impl StateReadOnly,
    id: [u8; 32],
    at: SccpNativeProofAt,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<SccpMessageProofBundleV1>> {
    let source = source_identity(view, control)?;
    let record = store::outbound_messages::get(view.world(), &id)
        .ok_or(SccpNativeReadError::NotFound("outbound message"))?;
    if !(2..=source.height).contains(&record.height) {
        return Err(SccpNativeReadError::Invalid(
            "message record is outside committed certificate history",
        ));
    }
    if record.payload.is_empty() || record.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(SccpNativeReadError::Invalid("stored payload length"));
    }
    let payload = SccpTransferPayloadRefV1::decode(&record.payload)
        .map_err(|_| SccpNativeReadError::Invalid("stored transfer payload"))?;
    // The retained record names the payload's route revision `revision`.
    let recorded_route_revision = record.revision;
    if !payload.is_outbound()
        || payload.target() != Some(record.network)
        || payload.route_revision != recorded_route_revision
        || payload.nonce != record.nonce
        || payload.deadline_ms != record.deadline_ms
        || payload.amount != record.amount
    {
        return Err(SccpNativeReadError::Invalid("record payload coordinates"));
    }
    let lane = payload
        .lane_bytes(&source.network)
        .map_err(|_| SccpNativeReadError::Invalid("outbound lane"))?;
    let route = store::routes::get(view.world(), &record.network)
        .and_then(|route| route.revisions.get(&record.revision))
        .ok_or(SccpNativeReadError::Unavailable(
            "recorded route revision is absent",
        ))?;
    if message_id(&lane, &payload_hash(&record.payload)) != id
        || transfer_leaf(&id, &route.destination_word) != record.leaf
    {
        return Err(SccpNativeReadError::Invalid(
            "message payload, identity and recorded leaf disagree",
        ));
    }
    let selected = match at {
        SccpNativeProofAt::Record => record.height,
        SccpNativeProofAt::Latest => source.height,
        SccpNativeProofAt::Height(height) => height.get(),
    };
    if selected < record.height {
        return Err(SccpNativeReadError::Request(
            "certificate precedes the record",
        ));
    }
    let charge = budget.try_reserve_bytes(
        size_of::<SccpMessageProofBundleV1>()
            + CERTIFICATE_HEAP_BYTES
            + MAX_PAYLOAD_BYTES
            + PATH_HEAP_BYTES,
    )?;
    let cert = certificate(
        view,
        checked_height(selected, source)?,
        source,
        budget,
        control,
    )?;
    let x = SccpFinalityHeaderV1::parse(&cert.header)
        .map_err(|_| SccpNativeReadError::Invalid("certificate header"))?;
    let (block, path) = block_proof(
        view.world(),
        record.height,
        record.commitment_index,
        SccpLeafRefV1::transfer(id),
        record.leaf,
        &x,
        control,
    )?;
    let data = SccpMessageProofBundleV1 {
        message_id: id,
        payload: copy_slice(&record.payload)?,
        deadline_ms: record.deadline_ms,
        leaf_index: record.commitment_index,
        path,
        block,
        certificate: cert,
    };
    data.check_shape()
        .map_err(|_| SccpNativeReadError::Invalid("message proof shape"))?;
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Read the retained complete native control and prove its actual recorded leaf.
/// The certificate and effect identities come only from the original producer's record.
/// The destination independently authenticates the returned certificate and expected route.
///
/// # Errors
/// Rejects invalid selectors, missing records, malformed native control fields, a mismatch
/// between the native 199-byte preimage and stored leaf, and certificate/path mismatches.
/// Preserves scope/source/storage/resource refusals exactly as [`message_proof`].
pub fn control_proof(
    view: &impl StateReadOnly,
    network: SccpNetworkV1,
    revision: u32,
    control_nonce: u64,
    at: SccpNativeProofAt,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<SccpControlProofBundleV1>> {
    let source = source_identity(view, control)?;
    if revision == 0 || control_nonce == 0 {
        return Err(SccpNativeReadError::Request("control revision or nonce"));
    }
    let record = store::control_messages::get(view.world(), &(network, revision, control_nonce))
        .ok_or(SccpNativeReadError::NotFound("destination control"))?;
    if !(2..=source.height).contains(&record.height) {
        return Err(SccpNativeReadError::Invalid(
            "control record is outside committed certificate history",
        ));
    }
    if !record.has_valid_shape() {
        return Err(SccpNativeReadError::Invalid(
            "malformed native control record",
        ));
    }
    let route = store::routes::get(view.world(), &network)
        .and_then(|route| route.revisions.get(&revision))
        .ok_or(SccpNativeReadError::Unavailable(
            "control route revision is absent",
        ))?;
    let fields = ControlLeafV1 {
        route_revision: revision,
        control_nonce,
        track: record.track,
        parliament_paused: u8::from(record.parliament_paused),
        fast_pause_until_ms: record.fast_pause_until_ms,
        certificate_id: record.certificate_id,
        effect_hash: record.effect_hash,
    };
    let leaf = control_leaf(&source.network, network, &route.destination_word, &fields)
        .map_err(|_| SccpNativeReadError::Invalid("native control leaf constraints"))?;
    if leaf != record.leaf {
        return Err(SccpNativeReadError::Invalid(
            "native control fields and stored leaf disagree",
        ));
    }
    let selected = match at {
        SccpNativeProofAt::Record => record.height,
        SccpNativeProofAt::Latest => source.height,
        SccpNativeProofAt::Height(height) => height.get(),
    };
    if selected < record.height {
        return Err(SccpNativeReadError::Request(
            "certificate precedes the control",
        ));
    }
    let charge = budget.try_reserve_bytes(
        size_of::<SccpControlProofBundleV1>() + CERTIFICATE_HEAP_BYTES + PATH_HEAP_BYTES,
    )?;
    let cert = certificate(
        view,
        checked_height(selected, source)?,
        source,
        budget,
        control,
    )?;
    let x = SccpFinalityHeaderV1::parse(&cert.header)
        .map_err(|_| SccpNativeReadError::Invalid("certificate header"))?;
    let (block, path) = block_proof(
        view.world(),
        record.height,
        record.commitment_index,
        SccpLeafRefV1::control(network, revision, control_nonce),
        leaf,
        &x,
        control,
    )?;
    let data = SccpControlProofBundleV1 {
        network,
        revision,
        control_nonce,
        track: record.track,
        parliament_paused: record.parliament_paused,
        fast_pause_until_ms: record.fast_pause_until_ms,
        certificate_id: record.certificate_id,
        effect_hash: record.effect_hash,
        leaf_index: record.commitment_index,
        path,
        block,
        certificate: cert,
    };
    data.check_shape()
        .map_err(|_| SccpNativeReadError::Invalid("control proof shape"))?;
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

fn block_proof(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
    index: u32,
    expected_ref: SccpLeafRefV1,
    expected_leaf: [u8; 32],
    x: &SccpFinalityHeaderV1,
    control: SccpNativeReadControl<'_>,
) -> Result<(SccpBlockRefV1, Vec<[u8; 32]>)> {
    let commitment = store::block_commitments::get(world, &height).ok_or(
        SccpNativeReadError::Unavailable("record has no block commitment"),
    )?;
    let count = usize::try_from(commitment.message_count)
        .map_err(|_| SccpNativeReadError::Invalid("block count overflow"))?;
    if !(1..=MAX_BLOCK_LEAVES).contains(&count) || index >= commitment.message_count {
        return Err(SccpNativeReadError::Invalid("block leaf coordinates"));
    }
    let mut hashes = [[0; 32]; MAX_BLOCK_LEAVES];
    let mut seen = 0;
    for ((_, position), leaf_ref) in
        store::block_leaves::range(world, (height, 0)..=(height, u32::MAX))
    {
        deadline_check(control)?;
        if seen >= count || usize::try_from(*position).ok() != Some(seen) {
            return Err(SccpNativeReadError::Unavailable(
                "block leaves are not dense",
            ));
        }
        let (record_height, record_index, leaf) = match leaf_ref {
            SccpLeafRefV1::Transfer(transfer) => {
                let r = store::outbound_messages::get(world, &transfer.message_id).ok_or(
                    SccpNativeReadError::Unavailable("block references a missing message"),
                )?;
                (r.height, r.commitment_index, r.leaf)
            }
            SccpLeafRefV1::Control(control) => {
                let r = store::control_messages::get(
                    world,
                    &(control.network, control.revision, control.control_nonce),
                )
                .ok_or(SccpNativeReadError::Unavailable(
                    "block references a missing control",
                ))?;
                (r.height, r.commitment_index, r.leaf)
            }
        };
        if record_height != height
            || record_index != *position
            || (*position == index && (*leaf_ref != expected_ref || leaf != expected_leaf))
        {
            return Err(SccpNativeReadError::Invalid(
                "block reference and record disagree",
            ));
        }
        hashes[seen] = leaf;
        seen += 1;
    }
    if seen != count {
        return Err(SccpNativeReadError::Unavailable(
            "block leaves are incomplete",
        ));
    }
    let (root, path) = bounded_tree_path(&mut hashes[..count], u64::from(index))?;
    if root != commitment.root {
        return Err(SccpNativeReadError::Invalid("block root mismatch"));
    }
    let history_path = if height == x.height() {
        if commitment.root != x.sccp_root() || commitment.message_count != x.message_count() {
            return Err(SccpNativeReadError::Invalid(
                "direct block does not match original X",
            ));
        }
        Vec::new()
    } else {
        if height >= x.height() {
            return Err(SccpNativeReadError::Invalid("history block order"));
        }
        let expected = history_leaf(height, &commitment.root, commitment.message_count);
        if store::history_leaves::get(world, &commitment.history_index) != Some(&(height, expected))
        {
            return Err(SccpNativeReadError::Invalid("block history leaf mismatch"));
        }
        let (root, path) =
            history_path(world, commitment.history_index, x.history_size(), control)?;
        if root != x.history_root() {
            return Err(SccpNativeReadError::Invalid(
                "history does not match original X",
            ));
        }
        path
    };
    Ok((
        SccpBlockRefV1 {
            height,
            sccp_root: commitment.root,
            message_count: commitment.message_count,
            history_index: if height == x.height() {
                0
            } else {
                commitment.history_index
            },
            history_path,
        },
        path,
    ))
}

/// In-place promote-odd tree. Exactly nine path slots suffice for a 512-leaf block.
fn bounded_tree_path(leaves: &mut [[u8; 32]], index: u64) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    let mut position =
        usize::try_from(index).map_err(|_| SccpNativeReadError::Invalid("leaf index"))?;
    if leaves.is_empty() || leaves.len() > MAX_BLOCK_LEAVES || position >= leaves.len() {
        return Err(SccpNativeReadError::Invalid(
            "bounded block tree coordinates",
        ));
    }
    let mut path = Vec::new();
    path.try_reserve_exact(9)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    let mut count = leaves.len();
    while count > 1 {
        let sibling = position ^ 1;
        if sibling < count {
            path.push(leaves[sibling]);
        }
        for i in 0..count.div_ceil(2) {
            leaves[i] = if 2 * i + 1 < count {
                node(&leaves[2 * i], &leaves[2 * i + 1])
            } else {
                leaves[2 * i]
            };
        }
        position /= 2;
        count = count.div_ceil(2);
    }
    Ok((leaves[0], path))
}

/// Embedded message/control proofs stream original history leaves in O(size) time,
/// checking cancellation and the source deadline at each leaf. Scratch stays bounded
/// to 33 peak slots and 32 siblings. The standalone §6 `/history` route separately
/// uses its original-pool `SccpHistoryNodeCache` for the specified O(log size) path;
/// this embedded producer does not duplicate or replace that cache owner.
fn history_path(
    world: &(impl WorldReadOnly + ?Sized),
    index: u64,
    size: u64,
    control: SccpNativeReadControl<'_>,
) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    if size == 0
        || size > MAX_HISTORY_SIZE
        || size > store::history::get(world).size
        || index >= size
    {
        return Err(SccpNativeReadError::Invalid("history coordinates"));
    }
    let mut tree = StreamingPath::new(index);
    for (position, (_, hash)) in store::history_leaves::range(world, 0..size) {
        deadline_check(control)?;
        if *position != tree.count {
            return Err(SccpNativeReadError::Unavailable(
                "history leaves are incomplete",
            ));
        }
        tree.push(*hash)?;
    }
    if tree.count != size {
        return Err(SccpNativeReadError::Unavailable(
            "history leaves are incomplete",
        ));
    }
    tree.finish()
}

struct StreamingPath {
    target: u64,
    count: u64,
    peaks: [Option<([u8; 32], bool)>; 33],
    path: [[u8; 32]; 32],
    path_len: usize,
}

impl StreamingPath {
    fn new(target: u64) -> Self {
        Self {
            target,
            count: 0,
            peaks: [None; 33],
            path: [[0; 32]; 32],
            path_len: 0,
        }
    }
    fn merge(
        &mut self,
        left: ([u8; 32], bool),
        right: ([u8; 32], bool),
    ) -> Result<([u8; 32], bool)> {
        if left.1 || right.1 {
            if self.path_len >= self.path.len() {
                return Err(SccpNativeReadError::Invalid("history path overflow"));
            }
            self.path[self.path_len] = if left.1 { right.0 } else { left.0 };
            self.path_len += 1;
        }
        Ok((node(&left.0, &right.0), left.1 || right.1))
    }
    fn push(&mut self, leaf: [u8; 32]) -> Result<()> {
        if self.count >= MAX_HISTORY_SIZE {
            return Err(SccpNativeReadError::Invalid("history capacity"));
        }
        let mut carry = (leaf, self.count == self.target);
        let mut level = 0;
        while let Some(left) = self.peaks[level].take() {
            carry = self.merge(left, carry)?;
            level += 1;
        }
        self.peaks[level] = Some(carry);
        self.count += 1;
        Ok(())
    }
    fn finish(mut self) -> Result<([u8; 32], Vec<[u8; 32]>)> {
        if self.target >= self.count {
            return Err(SccpNativeReadError::Invalid("history target"));
        }
        let mut root = None;
        for level in 0..self.peaks.len() {
            if let Some(left) = self.peaks[level].take() {
                root = Some(match root {
                    None => left,
                    Some(right) => self.merge(left, right)?,
                });
            }
        }
        let root = root.ok_or(SccpNativeReadError::Invalid("empty history"))?.0;
        Ok((root, copy_slice(&self.path[..self.path_len])?))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod certificate_producer_tests;
#[cfg(test)]
mod control_producer_tests;
#[cfg(test)]
mod message_producer_tests;
