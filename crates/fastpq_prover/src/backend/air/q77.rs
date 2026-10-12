//! Sealed bridge between the typed interface and the committed q77 engine.
//!
//! The engine's accepted relation set is closed: only the backend's prepared
//! relation owners implement the private `DeepRelation` marker, and this module
//! is the single place where one of them is viewed as a
//! [`SemanticAir`](super::SemanticAir). The out-of-domain check, run by the
//! verifier and by the producer before it commits its answers, evaluates the
//! relation through that view, and both engine preflights read the relation's
//! declared shape through it, so the interface and the committed engine cannot
//! describe different equations or geometry.
//!
//! [`VerifierLimits`] and [`ProducerLimits`] are the engine's own limit types:
//! bounded verification and the producer's whole-attempt plan take them and
//! nothing else. Each carries one [`WorkLimits`](super::WorkLimits), so the
//! same ceilings a relation is admitted under by the uncommitted reference are
//! the ones the committed engine checks. The public quantity facade maps its
//! policies to them with [`VerifierLimits::for_segment`] and
//! [`ProducerLimits::for_segment`].
//!
//! [`PROFILE`] and [`SEALED_RELATIONS`] expose the engine's fixed geometry and
//! every sealed relation identity as typed data read from the engine's own
//! constants. They describe today's fixed profile; they are not a registry a
//! caller can extend, and proof bytes never select an entry.
//!
//! [`transcript_profile`] is the frozen semantic profile of the engine's
//! transcript: the typed descriptor every commitment and challenge absorbs in
//! full, with the identity that records and measurements name. It contains no
//! source or build digest and grants no authority.
//!
//! Process observers registered with [`set_observer`] receive the public
//! progress of committed construction and verification. They cannot change a
//! result.
//!
//! TODO: B.2 moves the remaining direct readers of a sealed relation behind
//! the interface: transcript binding reads the relation's identity and
//! statement from `FixedAir`, the producer's masked quotient uses the prepared
//! evaluator and degree owner of `CompactTransferAir`, and both sides rebuild
//! the public columns with the closed-form `PublicColumnReconstruction`
//! instead of [`SemanticAir::public_value`](super::SemanticAir::public_value).

use std::sync::{Arc, RwLock};

use iroha_data_model::fastpq::FastpqQuantityUnits;

pub use super::super::deep_engine::VerificationWork;
use super::{
    super::{
        compact_execution_effect_batch,
        compact_public_columns::{
            COMMITTED_COLUMN_COUNT, LAYOUT_ID, PUBLIC_COLUMN_COUNT, PUBLIC_COLUMNS, base_values,
        },
        compact_transfer_air,
        compact_value_domain::CompactTransferValue,
        deep_engine,
        deep_geometry::{
            CONSTRAINTS, FRI_ARITIES, FRI_DEGREES, FRI_LENGTHS, LDE_ROWS, QUERY_CANDIDATES,
            QUERY_COUNT, TRACE_ROWS,
        },
        deep_masked_replay::{QUOTIENT_MASK_COEFFICIENTS, TRACE_MASK_COEFFICIENTS},
        deep_proof,
        deep_relation::DeepRelation,
        offline_compact::{ProvingLimits, VerificationLimits},
    },
    AirSchema, Event, MAX_STATEMENT_BYTES, Observer, Operation, PolynomialField, SemanticAir, Work,
    WorkLimits, notify,
};
use crate::{
    DigestExecutionV1, Error, Result, VerifyLimits,
    gadgets::compact_smt_air::{COLUMN_COUNT, PHYSICAL_HASH_ROWS, PhysicalRowIndex},
};

/// Exclusive numerator degree bound of the sealed relations for unmasked
/// columns of degree below `N`: one periodic selector of degree `N - N/512`
/// times a quadratic in two trace cells.
const UNMASKED_NUMERATOR_DEGREE_BOUND: usize = 3 * TRACE_ROWS - TRACE_ROWS / PHYSICAL_HASH_ROWS - 1;

/// Fixed geometry of the committed q77 engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineProfile {
    /// Trace subgroup order `N`.
    pub trace_rows: usize,
    /// Complete AIR column count, public columns included.
    pub columns: usize,
    /// Retained committed columns.
    pub committed_columns: usize,
    /// Verifier-reconstructed public columns.
    pub public_columns: usize,
    /// Independently mixed numerator slots.
    pub constraints: usize,
    /// Evaluation domain rows `L`.
    pub evaluation_rows: usize,
    /// Ordered FRI reduction factors.
    pub fri_arities: [usize; 5],
    /// Input and successive FRI domain lengths, terminal included.
    pub fri_lengths: [usize; 6],
    /// Exclusive FRI degree bounds on those six domains.
    pub fri_degree_bounds: [usize; 6],
    /// Distinct sampled initial query positions.
    pub queries: usize,
    /// Field candidates consumed from the fixed query tape.
    pub query_candidates: usize,
    /// Base-field mask coefficients per committed trace column.
    pub trace_mask_coefficients: usize,
    /// Extension-field quotient mask coefficients.
    pub quotient_mask_coefficients: usize,
    /// Exact maximal canonical child frame, in bytes.
    pub max_frame_bytes: usize,
    /// Identity of the 342-to-301 public-column projection.
    pub public_column_layout: &'static str,
}

/// The sole fixed profile of the committed engine.
pub const PROFILE: EngineProfile = EngineProfile {
    trace_rows: TRACE_ROWS,
    columns: COLUMN_COUNT,
    committed_columns: COMMITTED_COLUMN_COUNT,
    public_columns: PUBLIC_COLUMN_COUNT,
    constraints: CONSTRAINTS,
    evaluation_rows: LDE_ROWS,
    fri_arities: FRI_ARITIES,
    fri_lengths: FRI_LENGTHS,
    fri_degree_bounds: FRI_DEGREES,
    queries: QUERY_COUNT,
    query_candidates: QUERY_CANDIDATES,
    trace_mask_coefficients: TRACE_MASK_COEFFICIENTS,
    quotient_mask_coefficients: QUOTIENT_MASK_COEFFICIENTS,
    max_frame_bytes: deep_proof::MAX_FRAME_BYTES,
    public_column_layout: LAYOUT_ID,
};

/// Frozen semantic profile of the committed engine's transcript.
///
/// The returned descriptor is the complete typed description of what the
/// transcript binds: construction, framing, hash and XOF, field and encodings,
/// domains, masking bounds, out-of-domain claims, DEEP composition, FRI
/// schedule, sampling rules, message schedule, grinding (zero bits, no nonce)
/// and the profile's declared envelope. Its canonical bytes are absorbed by
/// every commitment and challenge and embedded in the artifact descriptor.
///
/// [`SemanticProfileV1::id`](fastpq_isi::semantic_profile::SemanticProfileV1::id)
/// is the identity a measurement names. A measurement that names another
/// identity does not describe this profile. The identity is computed from the
/// declared parameters only; it is not a source, build or binary hash, and
/// freezing it establishes no soundness level.
#[must_use]
pub fn transcript_profile() -> &'static fastpq_isi::semantic_profile::SemanticProfileV1 {
    super::super::transcript_profile::profile()
}

/// Role of one sealed relation in the engine's closed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationRole {
    /// The complete one-delta hash/SMT arithmetic owner every other role wraps.
    CompactTransfer,
    /// One ordered segment of an ordinary execution-effect bundle.
    ExecutionEffectSegment,
    /// One ordered segment of an ordinary transfer bundle.
    OrdinaryTransferSegment,
    /// One ordered segment of an AXT transfer bundle.
    AxtTransferSegment,
}

/// Public value format bound by a sealed bundle relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueDomain {
    /// The relation binds no bundle value format.
    None,
    /// Bounded `u64` amounts.
    U64,
    /// Full-domain quantity units with their nominal frame and scale.
    Quantity,
}

/// One relation type behind the engine's sealed bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedRelation {
    /// What the relation proves.
    pub role: RelationRole,
    /// Public value format it binds.
    pub values: ValueDomain,
    /// Exact identity bound into every transcript of this relation.
    pub identity: &'static str,
}

impl SealedRelation {
    /// Trusted schema shared by every sealed relation under this identity.
    #[must_use]
    pub const fn schema(&self) -> AirSchema {
        schema(self.identity)
    }
}

/// Every relation identity a sealed backend relation type can bind, read from
/// its owner.
///
/// Reachability from the public facade is decided there, not here:
/// `offline_compact` currently produces and verifies execution-effect and AXT
/// quantity bundles. An identity in this list grants no admission by itself.
pub const SEALED_RELATIONS: [SealedRelation; 6] = [
    SealedRelation {
        role: RelationRole::CompactTransfer,
        values: ValueDomain::None,
        identity: compact_transfer_air::IDENTITY,
    },
    SealedRelation {
        role: RelationRole::ExecutionEffectSegment,
        values: ValueDomain::Quantity,
        identity: compact_execution_effect_batch::IDENTITY,
    },
    SealedRelation {
        role: RelationRole::OrdinaryTransferSegment,
        values: ValueDomain::U64,
        identity: <u64 as CompactTransferValue>::BATCH_IDENTITY,
    },
    SealedRelation {
        role: RelationRole::AxtTransferSegment,
        values: ValueDomain::U64,
        identity: <u64 as CompactTransferValue>::AXT_BATCH_IDENTITY,
    },
    SealedRelation {
        role: RelationRole::OrdinaryTransferSegment,
        values: ValueDomain::Quantity,
        identity: <FastpqQuantityUnits as CompactTransferValue>::BATCH_IDENTITY,
    },
    SealedRelation {
        role: RelationRole::AxtTransferSegment,
        values: ValueDomain::Quantity,
        identity: <FastpqQuantityUnits as CompactTransferValue>::AXT_BATCH_IDENTITY,
    },
];

/// The fixed sealed geometry under one identity, from the engine's constants.
const fn schema(identity: &'static str) -> AirSchema {
    AirSchema {
        identity,
        trace_rows: TRACE_ROWS,
        width: COLUMN_COUNT,
        constraints: CONSTRAINTS,
        numerator_degree_bound: UNMASKED_NUMERATOR_DEGREE_BOUND,
    }
}

/// Caller ceilings of one committed q77 verification.
///
/// The engine's bounded verifier takes exactly this value and checks every
/// field before it decodes a proof byte. No ceiling is read from proof bytes.
/// The structural ceilings bound hashing and opened values; `work` bounds the
/// relation and the verification's declared payload and work:
///
/// - `max_trace_rows`, `max_trace_cells` and `max_constraints` against the
///   relation's declared shape, read through its sealed interface view;
/// - `max_statement_bytes` against the exact canonical statement. The
///   transcript context separately refuses a statement above
///   [`MAX_STATEMENT_BYTES`](super::MAX_STATEMENT_BYTES);
/// - `max_payload_bytes` against the declared payload charge: the frame bytes
///   plus the decode allocation charges admitted for it. Verifier scratch and
///   peak memory are not part of that charge;
/// - `max_work_units` against the profile's declared structural charge: one
///   unit per enumerated field-value slot and numerator evaluation of a maximal
///   frame. It is not a count of every runtime field read or a complete
///   arithmetic cost.
///
/// These are accounting limits, not process memory, time, consensus gas or a
/// work-security statement. Complete verifier resource accounting is B.2 and
/// F.2 work.
#[allow(
    clippy::struct_field_names,
    reason = "every field but `work` is an inclusive ceiling, named like the crate's other limit types"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierLimits {
    /// Relation shape, statement, payload and work ceilings.
    pub work: WorkLimits,
    /// Maximum canonical child proof frame bytes.
    pub max_proof_bytes: usize,
    /// Maximum FRI commitments, the complete terminal included.
    pub max_fri_layers: usize,
    /// Maximum sampled initial query positions.
    pub max_queries: usize,
    /// Maximum quotient chunk values opened with one query.
    pub max_query_chunk_values: usize,
    /// Maximum Merkle authentication path length of one query.
    pub max_query_path_len: usize,
    /// Maximum values in one opened FRI group.
    pub max_fri_round_values: usize,
    /// Maximum retained values in one opened AIR row.
    pub max_air_row_values: usize,
    /// Maximum Norito allocation charges for decoding one frame.
    pub max_decode_allocation_charges: usize,
}

impl VerifierLimits {
    /// The least ceilings under which the fixed profile verifies a maximal
    /// canonical frame of a sealed relation with a `statement_bytes` statement.
    ///
    /// Every value is read from the engine's own geometry, frame and decode
    /// owners. Lowering any field makes the engine refuse before decoding.
    #[must_use]
    pub const fn exact(statement_bytes: usize) -> Self {
        Self {
            work: WorkLimits {
                max_trace_rows: TRACE_ROWS,
                max_trace_cells: TRACE_ROWS * COLUMN_COUNT,
                max_constraints: CONSTRAINTS,
                max_statement_bytes: statement_bytes,
                max_payload_bytes: deep_engine::verification_payload_bytes(
                    deep_proof::MAX_FRAME_BYTES,
                    deep_proof::MAX_ALLOCATION_CHARGES,
                ),
                max_work_units: deep_engine::VERIFICATION_WORK_UNITS,
            },
            max_proof_bytes: deep_proof::MAX_FRAME_BYTES,
            max_fri_layers: FRI_LENGTHS.len(),
            max_queries: QUERY_COUNT,
            max_query_chunk_values: deep_engine::QUERY_CHUNK_VALUES,
            max_query_path_len: deep_engine::QUERY_PATH_LEN,
            max_fri_round_values: deep_engine::MAX_FRI_GROUP_VALUES,
            max_air_row_values: COMMITTED_COLUMN_COUNT,
            max_decode_allocation_charges: deep_proof::MAX_ALLOCATION_CHARGES,
        }
    }

    /// Engine ceilings of one child proof under the public facade's segment
    /// policy and its per-child decode allocation ceiling.
    ///
    /// The facade policy states the frame, statement, query-geometry and decode
    /// ceilings. It has no knob for the relation shape or for the declared
    /// payload and work, so those admit exactly the fixed profile. The
    /// policy's transition ceiling belongs to the enclosing bundle and is
    /// checked there.
    #[must_use]
    pub const fn for_segment(segment: VerifyLimits, max_decode_allocation_charges: usize) -> Self {
        Self {
            work: Self::exact(segment.max_batch_bytes).work,
            max_proof_bytes: segment.max_proof_bytes,
            max_fri_layers: segment.max_fri_layers,
            max_queries: segment.max_queries,
            max_query_chunk_values: segment.max_query_chunk_values,
            max_query_path_len: segment.max_query_path_len,
            max_fri_round_values: segment.max_fri_round_values,
            max_air_row_values: segment.max_air_row_values,
            max_decode_allocation_charges,
        }
    }
}

impl Default for VerifierLimits {
    /// The default public verification policy as the engine enforces it for
    /// one child proof.
    ///
    /// Read from [`VerificationLimits::default`]; the statement ceiling is that
    /// policy's, capped at the envelope the transcript context can bind.
    fn default() -> Self {
        let policy = VerificationLimits::default();
        let mut limits = Self::for_segment(
            policy.bundle.segment,
            policy.max_segment_decode_allocation_charges,
        );
        limits.work.max_statement_bytes = limits.work.max_statement_bytes.min(MAX_STATEMENT_BYTES);
        limits
    }
}

/// Caller ceilings of one committed q77 construction attempt.
///
/// The engine's whole-attempt producer plan takes exactly this value and
/// checks every field before it reads a private column or consumes entropy.
/// `work` bounds the relation's declared shape and statement, the attempt's
/// conservative structural payload charge and its structural arithmetic and
/// inspection work. These are accounting limits, not process memory or time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerLimits {
    /// Bulk leaf and lower-parent hashing policy. A selected device must pass
    /// readiness before private work; both policies produce the same bytes.
    pub digest_execution: DigestExecutionV1,
    /// Relation shape, statement, payload and work ceilings.
    pub work: WorkLimits,
    /// Maximum hash calls of one attempt.
    pub max_hash_calls: usize,
    /// Maximum canonical child proof frame bytes; it must admit the maximal frame.
    pub max_proof_bytes: usize,
}

impl ProducerLimits {
    /// Engine ceilings of one segment attempt under the public facade's
    /// proving policy and the verifier ceilings its output must satisfy.
    ///
    /// The relation shape, statement and frame ceilings are the verifier's.
    /// The proving policy states the segment payload charge and the work
    /// ceiling, which also bounds hash calls.
    #[must_use]
    pub const fn for_segment(proving: &ProvingLimits, verifier: &VerifierLimits) -> Self {
        Self {
            digest_execution: proving.digest_execution,
            work: WorkLimits {
                max_payload_bytes: proving.max_segment_charge_bytes,
                max_work_units: proving.max_segment_work_units,
                ..verifier.work
            },
            max_hash_calls: proving.max_segment_work_units,
            max_proof_bytes: verifier.max_proof_bytes,
        }
    }
}

impl Default for ProducerLimits {
    /// The default public proving policy as the engine enforces it for one
    /// segment attempt, under [`VerifierLimits::default`].
    fn default() -> Self {
        Self::for_segment(&ProvingLimits::default(), &VerifierLimits::default())
    }
}

/// View of one sealed prepared relation through the public interface.
///
/// The view keeps the outer relation's identity and complete statement bytes
/// and evaluates its original arithmetic owner. Only the backend can build
/// one, and only from a type that implements the sealed relation marker.
pub(in crate::backend) struct SealedView<'a, R: DeepRelation>(&'a R);

impl<'a, R: DeepRelation> SealedView<'a, R> {
    /// Borrow a sealed relation without copying or reinterpreting it.
    pub(in crate::backend) const fn new(relation: &'a R) -> Self {
        Self(relation)
    }
}

impl<R: DeepRelation> SemanticAir for SealedView<'_, R> {
    /// The relation's own declared geometry and identity, never the engine's
    /// constants: the engine compares the two. Only the degree bound, which
    /// the fixed relation schema does not carry, is the sealed arithmetic
    /// owner's structural bound.
    fn schema(&self) -> AirSchema {
        let declared = self.0.schema();
        AirSchema {
            identity: declared.identity,
            trace_rows: declared.trace_rows,
            width: declared.width,
            constraints: declared.constraints,
            numerator_degree_bound: UNMASKED_NUMERATOR_DEGREE_BOUND,
        }
    }

    fn statement_bytes(&self) -> &[u8] {
        self.0.statement_bytes()
    }

    fn public_columns(&self) -> &[usize] {
        &PUBLIC_COLUMNS
    }

    fn public_value(&self, ordinal: usize, row: usize) -> Result<u64> {
        let index = PhysicalRowIndex::new(row).ok_or(Error::QueryIndexOutOfRange {
            index: row,
            len: TRACE_ROWS,
        })?;
        base_values(index)
            .get(ordinal)
            .copied()
            .ok_or(Error::QueryIndexOutOfRange {
                index: ordinal,
                len: PUBLIC_COLUMN_COUNT,
            })
    }

    fn evaluate<F: PolynomialField>(&self, point: F, current: &[F], next: &[F]) -> Result<Vec<F>> {
        self.0.deep_relation().evaluate_at(point, current, next)
    }
}

type SharedObserver = Arc<dyn Observer + Send + Sync>;

static OBSERVER: RwLock<Option<SharedObserver>> = RwLock::new(None);

/// Install the process observer of committed q77 construction and verification.
///
/// It replaces any previous observer. The hook runs without holding the
/// registration lock, and a panic inside it is caught and logged.
pub fn set_observer(observer: Arc<dyn Observer + Send + Sync>) {
    replace_observer(Some(observer));
}

/// Remove the process observer, if any.
pub fn clear_observer() {
    replace_observer(None);
}

fn replace_observer(replacement: Option<SharedObserver>) {
    let previous = {
        let mut slot = OBSERVER
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        core::mem::replace(&mut *slot, replacement)
    };
    // Drop the previous hook outside the lock and contain a panicking destructor.
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(previous))).is_err() {
        tracing::warn!(target: "fastpq::air", "q77 observer destructor panicked");
    }
}

fn registered_observer() -> Option<SharedObserver> {
    OBSERVER
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn notify_registered(event: &Event<'_>) {
    if let Some(observer) = registered_observer() {
        notify(observer.as_ref(), event);
    }
}

/// Report that a preflighted producer plan is about to run.
pub(in crate::backend) fn observe_proof_admitted(
    relation: &impl DeepRelation,
    payload_bytes: usize,
    work_units: usize,
) {
    notify_registered(&Event::Admitted {
        operation: Operation::Q77Prove,
        identity: relation.schema().identity,
        statement_bytes: relation.statement_bytes().len(),
        payload_bytes,
        work_units,
    });
}

/// Report the outcome of one committed construction attempt.
pub(in crate::backend) fn observe_proof(relation: &impl DeepRelation, result: &Result<Vec<u8>>) {
    let operation = Operation::Q77Prove;
    let identity = relation.schema().identity;
    match result {
        Ok(bytes) => notify_registered(&Event::Completed {
            operation,
            identity,
            work: Work::Q77Proof {
                proof_bytes: bytes.len(),
            },
        }),
        Err(_) => notify_registered(&Event::Rejected {
            operation,
            identity,
        }),
    }
}

/// Report the outcome of one committed bounded verification.
pub(in crate::backend) fn observe_verification(
    relation: &impl DeepRelation,
    result: std::result::Result<VerificationWork, ()>,
) {
    let operation = Operation::Q77Verify;
    let identity = relation.schema().identity;
    match result {
        Ok(work) => notify_registered(&Event::Completed {
            operation,
            identity,
            work: Work::Q77Verification(work),
        }),
        Err(()) => notify_registered(&Event::Rejected {
            operation,
            identity,
        }),
    }
}

#[cfg(test)]
#[path = "q77_tests.rs"]
mod tests;
