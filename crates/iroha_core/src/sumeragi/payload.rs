//! Block payloads of the Sumeragi driver (`specs/sumeragi.md` §3.2, §6.10).
//!
//! A payload is the exact wire of an *unsigned, resultless* iroha block proposal: the certified
//! core header binds its bytes, so it needs no block signature. Every proposal must carry
//! at least one transaction. An empty builder result means there is no includable work;
//! it never authorizes a block, including at later views or during replay.
//!
//! The leader's builder peeks at the queue (it never removes transactions), keeps the queue's
//! FIFO order, and fills the block up to the payload byte cap and the on-chain transaction cap.

use std::{num::NonZeroUsize, time::Duration};

use iroha_primitives::time::TimeSource;

use super::lanes::routing::{GLOBAL_LANE, RoutingInputs, read_routing_root_scope};
use crate::{
    block::{BlockBuilder, ValidBlock},
    execution_attempt::ExecutionAttemptError,
    queue::Queue,
    state::{State, StateReadOnly, WorldReadOnly, compute_confidential_feature_digest},
    tx::AcceptedTransaction,
};
use iroha_data_model::{
    block::{BlockExecutionContextBundle, SignedBlock},
    nexus::DataSpaceCatalog,
    parameter::{
        Parameters,
        system::{TransactionInclusionRoute, TransactionNeverIncludable},
    },
    sumeragi_lanes::{SumeragiLaneMerge, SumeragiLaneMergeSection, SumeragiLaneState},
};
use iroha_model_base::topology::LaneId;

/// How many queued transactions one build inspects at most.
pub const MAX_QUEUE_SCAN: NonZeroUsize = NonZeroUsize::new(4096).expect("non-zero");

/// Largest framed transaction a proposer of the committed chain can select for a transaction
/// routed to `lane`: the committed transaction cap, bounded by the selection budget of the
/// proposers that can carry it (`Parameters::max_includable_transaction_bytes`). Lane zero is
/// carried by the global proposer only. A native lane adds its own proposer's budget. Under a
/// complete committed policy, the transaction cap plus the global proposer reserve fits the
/// global payload limit, so every admitted input fits the full global selection budget. A
/// smaller lane budget or the remaining space in a global proposal can still defer selection.
/// Global rescue of a stalled lane (`specs/sumeragi_lanes.md` §6.4) checks that available budget
/// in [`select`]. The lane budget is the payload limit pinned by the lane's committed record;
/// a later lane-policy change does not move it. A transaction without a route, or routed to a
/// lane without a committed record, is given the global budget.
///
/// The underlying helper also handles raw authoring parameters before complete policy
/// validation. An unvalidated combination can describe a transaction that only the lane
/// budget carries; that does not establish an admissible chain above the full global budget.
#[must_use]
pub fn max_includable_transaction_bytes_on_route(
    parameters: &Parameters,
    lanes: &SumeragiLaneState,
    lane: Option<LaneId>,
) -> u64 {
    parameters.max_includable_transaction_bytes(inclusion_route(lanes, lane))
}

/// The proposers that carry a transaction routed to `lane`, from the committed lane records.
fn inclusion_route(lanes: &SumeragiLaneState, lane: Option<LaneId>) -> TransactionInclusionRoute {
    lane.filter(|lane| *lane != GLOBAL_LANE)
        .and_then(|lane| lanes.lane(lane))
        .map_or(TransactionInclusionRoute::Global, |record| {
            TransactionInclusionRoute::NativeLane {
                max_block_bytes: record.params.max_block_bytes,
            }
        })
}

/// Decide whether a proposer of the committed chain in `world` can include `transaction` at
/// global height `height`. Queue admission refuses a transaction no proposer can select,
/// because [`select`] and the lane builder would only skip it until it expires.
///
/// A transaction within the global budget needs no route or lane policy read. A larger one
/// is includable only when it is routed to a native lane whose budget carries it. That
/// verdict is for the route at `height`: such a transaction has no global rescue, so it
/// waits for its lane's proposer and expires if the lane stalls or closes or its route
/// changes first.
///
/// # Errors
/// `Rejected` when the transaction is larger than the budget of every proposer on its route;
/// `Deferred` when the committed root scope, lane policy or route cannot be read with local
/// resources. A deferred assessment is neither an admission nor a rejection.
pub fn check_includable_transaction<W: WorldReadOnly>(
    world: &W,
    dataspaces: &DataSpaceCatalog,
    ledger_time_ms: u64,
    height: u64,
    transaction: &AcceptedTransaction<'_>,
) -> Result<(), ExecutionAttemptError<TransactionNeverIncludable>> {
    let encoded_bytes = u64::try_from(transaction.encoded_len()).unwrap_or(u64::MAX);
    let parameters = world.parameters();
    let Err(global) =
        parameters.check_signed_transaction_bytes(encoded_bytes, TransactionInclusionRoute::Global)
    else {
        return Ok(());
    };
    let Some(policy) = super::lanes::lane_policy(world).map_err(ExecutionAttemptError::Deferred)?
    else {
        return Err(ExecutionAttemptError::Rejected(global));
    };
    let lanes = world.sumeragi_lanes();
    let inputs = RoutingInputs {
        root_scope: read_routing_root_scope(world).map_err(ExecutionAttemptError::Deferred)?,
        policy: Some(&policy),
        lanes,
        dataspaces,
        world,
        ledger_time_ms,
    };
    let lane = inputs
        .route(transaction, height)
        .map_err(ExecutionAttemptError::Deferred)?;
    parameters
        .check_signed_transaction_bytes(encoded_bytes, inclusion_route(lanes, lane))
        .map_err(ExecutionAttemptError::Rejected)
}

/// Why a payload could not be built or decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// No transaction can justify creating a block.
    #[error("block proposal must contain at least one transaction")]
    EmptyBlock,
    /// The canonical block time overflows.
    #[error("canonical block time overflows")]
    TimeOverflow,
    /// Original queued work is waiting for the local proposer clock; retry without new input.
    #[error("ClockAhead: queued input is newer than the proposer clock")]
    ClockAhead,
    /// The block could not be encoded.
    #[error("block encoding failed: {0}")]
    Encode(String),
    /// Original parent-state staking preparation failed.
    #[error("staking effect preparation failed: {0}")]
    Staking(String),
    /// Original local evidence or stake-index preparation refusal, retaining its release owner.
    #[error("staking effect preparation deferred: {0}")]
    StakingPreparation(#[source] crate::state::EvidencePreparationError),
    /// Original State acquisition refusal before preparing staking effects.
    #[error("staking State acquisition deferred: {0}")]
    StakingAdmission(#[source] crate::state::StateAdmissionError),
    /// Original local forgery recheck refusal, retaining its physical preparation owner.
    #[error("SCCP forgery proposal preparation failed: {0}")]
    SccpForgeryPreparation(#[source] crate::state::StateStorageAdmissionError),
    /// The original versioned decoder refused this unfinished local attempt.
    #[error("payload decoding was refused by local resources: {0}")]
    DecodeResource(crate::execution_attempt::ExecutionDeferred),
    /// Original parent participation preparation failed; no local QC is execution input.
    #[error("parent service preparation failed: {0}")]
    ParentService(String),
    /// Original committed routing or parent service could not be read with local resources.
    #[error("payload routing deferred: {0}")]
    RoutingDeferred(#[from] crate::execution_attempt::ExecutionDeferred),
    /// The payload bytes are not a canonical block proposal.
    #[error("payload is not a canonical block proposal: {0}")]
    NotCanonical(String),
    /// Original source/control custody failed independently of authenticated payload bytes.
    #[error("payload signature custody invariant failed: {0}")]
    SignatureCustodyInvariant(String),
}

fn staking_preparation_error(error: eyre::Report) -> PayloadError {
    if !cfg!(all(test, sumeragi_core_mutation = "HC49")) {
        if let Some(refusal) = error.downcast_ref::<crate::state::EvidencePreparationError>() {
            return PayloadError::StakingPreparation(refusal.clone());
        }
        if let Some(refusal) = error.downcast_ref::<crate::state::StateAdmissionError>() {
            return PayloadError::StakingAdmission(refusal.clone());
        }
        if let Some(refusal) = error.downcast_ref::<crate::state::MergeLedgerCommitError>() {
            use crate::state::{MergeLedgerCommitError, StateAdmissionError};
            let admission = match refusal {
                MergeLedgerCommitError::StateStorageAdmission(original) => {
                    Some(StateAdmissionError::Storage(original.clone()))
                }
                MergeLedgerCommitError::BlockHashAdmission(original) => {
                    Some(StateAdmissionError::History(original.clone()))
                }
                MergeLedgerCommitError::MembershipAdmission(original) => {
                    Some(StateAdmissionError::Membership(original.clone()))
                }
                MergeLedgerCommitError::ExecutionDeferred(original) => {
                    return PayloadError::RoutingDeferred(original.clone());
                }
                _ => None,
            };
            if let Some(original) = admission {
                return PayloadError::StakingAdmission(original);
            }
        }
    }
    if let Some(crate::execution_attempt::ExecutionAttemptError::Deferred(reason)) =
        error.downcast_ref::<crate::execution_attempt::ExecutionAttemptError<String>>()
    {
        return PayloadError::RoutingDeferred(reason.clone());
    }
    if let Some(crate::execution_attempt::ExecutionAttemptError::Deferred(reason)) =
        error.downcast_ref::<crate::execution_attempt::ExecutionAttemptError<
            iroha_data_model::isi::error::InstructionExecutionError,
        >>()
    {
        return PayloadError::RoutingDeferred(reason.clone());
    }
    if let Some(super::evidence::EvidenceAdmissionError::Policy(
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
    )) = error.downcast_ref::<super::evidence::EvidenceAdmissionError>()
    {
        return PayloadError::RoutingDeferred(reason.clone());
    }
    PayloadError::Staking(error.to_string())
}

/// Inputs of one nonempty block assembly.
#[derive(Clone, Copy, Debug)]
pub struct Assembly<'a> {
    /// The committed parent block.
    pub parent: &'a SignedBlock,
    /// The view the block is (first) proposed in (`origin_view`).
    pub view: u64,
    /// The chain's block cadence (`ChainParams.block_time`).
    pub cadence: Duration,
    /// One captured proposer clock reading, rounded down to milliseconds. The authenticated
    /// proposal time is at least this reading and the committed parent/input time floor.
    pub proposed_time: Duration,
}

/// Build the unsigned proposal carrying `transactions` (in order) over `assembly.parent`,
/// reading the DA policy and confidential-feature digest from the committed `state`.
///
/// Deterministic in its explicit inputs: the authenticated time is the maximum of the
/// proposed time and the parent/cadence, lane and signed-input floors. Followers and replay
/// consume that original authenticated timestamp; they never restamp from their clocks.
///
/// # Errors
/// There are no transactions, or the canonical block time overflows.
pub fn assemble(
    state: &State,
    assembly: Assembly<'_>,
    transactions: &[AcceptedTransaction<'static>],
) -> Result<SignedBlock, PayloadError> {
    assemble_with_merges(state, assembly, transactions, &MergeProposal::default())
}

/// The lane merges a leader proposes (`specs/sumeragi_lanes.md` §4.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeProposal {
    /// The merged ranges, lanes ascending.
    pub merges: Vec<SumeragiLaneMerge>,
    /// Transactions of the fresh merged blocks (the block capacity they reserve).
    pub transactions: usize,
    /// One millisecond after the latest creation time among those transactions.
    pub time_floor_ms: u64,
}

/// Assemble the block's own transactions and its lane merges (`specs/sumeragi_lanes.md` §4.2)
/// without beacon control, which is supplied separately in the native header. Merged lane
/// blocks are work: a block may carry merges alone.
///
/// # Errors
/// There are neither transactions nor merges, or the canonical block time overflows.
pub fn assemble_with_merges(
    state: &State,
    assembly: Assembly<'_>,
    transactions: &[AcceptedTransaction<'static>],
    merges: &MergeProposal,
) -> Result<SignedBlock, PayloadError> {
    assemble_with_parent_service(state, assembly, transactions, merges, None)
}

/// Same assembly kernel borrowing the original worker's already funded native source.
pub(crate) fn assemble_with_parent_service(
    state: &State,
    assembly: Assembly<'_>,
    transactions: &[AcceptedTransaction<'static>],
    merges: &MergeProposal,
    parent_service: Option<&super::certified_chain::ParentServicePreparation>,
) -> Result<SignedBlock, PayloadError> {
    if transactions.is_empty() && merges.merges.is_empty() {
        return Err(PayloadError::EmptyBlock);
    }
    let proposed = Duration::from_millis(
        u64::try_from(assembly.proposed_time.as_millis())
            .map_err(|_| PayloadError::TimeOverflow)?,
    );
    let parent_time = assembly.parent.header().creation_time();
    let minimum = parent_time
        .checked_add(assembly.cadence)
        .ok_or(PayloadError::TimeOverflow)?;
    // The merge section already supplies an original canonical clock floor. Include it
    // before the expensive State/parent-certificate build, while leaving the final
    // canonical check below intact. No section means no merge-derived time authority.
    let minimum = if merges.merges.is_empty() {
        minimum
    } else {
        minimum.max(Duration::from_millis(merges.time_floor_ms))
    };
    let build = |time: Duration| -> Result<SignedBlock, PayloadError> {
        build_at(state, assembly, transactions, merges, time, parent_service)
    };
    let first = build(minimum.max(proposed))?;
    let required = ValidBlock::sumeragi_block_time_floor(&first, parent_time, assembly.cadence)
        .map_err(|_| PayloadError::TimeOverflow)?
        .max(proposed);
    if required == first.header().creation_time() {
        Ok(first)
    } else {
        build(required)
    }
}

/// Recheck selected forgery inputs against the exact committed parent before capturing
/// the Queue payload lease. Dropping a stale input changes the canonical clock, so every
/// retained forgery is rechecked after any removal. The accepted objects keep their order
/// and ownership; no transaction graph is copied, and a queue precheck is never reused.
/// A local refusal aborts this attempt without removing any input from the Queue itself.
pub(crate) fn recheck_sccp_forgery_for_proposal(
    view: &crate::state::StateView<'_>,
    assembly: Assembly<'_>,
    selected: &mut Vec<AcceptedTransaction<'static>>,
    merges: &MergeProposal,
) -> Result<(), PayloadError> {
    use crate::smartcontracts::isi::sccp::admission;

    let committed_time_ms = crate::smartcontracts::isi::sccp::hold::committed_time_ms(view)
        .map_err(|error| PayloadError::SignatureCustodyInvariant(error.to_string()))?;
    loop {
        // Empty and ordinary selections need no extra original-history or pairing work.
        if !selected.iter().any(|transaction| {
            admission::exempt_class_of_entrypoint(
                view.world(),
                transaction.entrypoint(),
                committed_time_ms,
            ) == Some(admission::SccpExemptClassV1::ForgeryEvidence)
        }) {
            return Ok(());
        }
        let minimum = assembly
            .parent
            .header()
            .creation_time()
            .checked_add(assembly.cadence)
            .ok_or(PayloadError::TimeOverflow)?;
        let minimum = if merges.merges.is_empty() {
            minimum
        } else {
            minimum.max(Duration::from_millis(merges.time_floor_ms))
        };
        let proposed = Duration::from_millis(
            u64::try_from(assembly.proposed_time.as_millis())
                .map_err(|_| PayloadError::TimeOverflow)?,
        );
        let time = crate::block::creation_time_after_inputs(
            minimum.max(proposed),
            selected.iter().map(AcceptedTransaction::entrypoint),
        )
        .ok_or(PayloadError::TimeOverflow)?;
        let time_ms = u64::try_from(time.as_millis()).map_err(|_| PayloadError::TimeOverflow)?;
        let budget = view.execution_budget();
        let before = selected.len();
        let mut refusal = None;
        let mut kept_forgery = false;
        selected.retain(|transaction| {
            if refusal.is_some()
                || admission::exempt_class_of_entrypoint(
                    view.world(),
                    transaction.entrypoint(),
                    committed_time_ms,
                ) != Some(admission::SccpExemptClassV1::ForgeryEvidence)
            {
                return true;
            }
            // The current-parent selector enforces this same quota. Keep it here as well
            // for direct candidate callers; a second valid forgery is not block work.
            if kept_forgery {
                return false;
            }
            match current_sccp_forgery(view, assembly.parent, transaction, time_ms, &budget) {
                Ok(true) => {
                    kept_forgery = true;
                    true
                }
                Ok(false) => false,
                Err(error) => {
                    refusal = Some(error);
                    true
                }
            }
        });
        if let Some(original) = refusal {
            return Err(original);
        }
        if selected.len() == before {
            return Ok(());
        }
    }
}

/// Check one signed carrier without granting a reusable verification or execution receipt.
/// Only authenticated protocol rejection permits this proposal attempt to skip its row.
fn current_sccp_forgery(
    view: &crate::state::StateView<'_>,
    parent: &SignedBlock,
    transaction: &AcceptedTransaction<'_>,
    time_ms: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<bool, PayloadError> {
    use crate::smartcontracts::isi::sccp::forgery;
    use iroha_data_model::{isi::sccp::SubmitSccpForgeryEvidenceV1, transaction::Executable};

    let invalid_source = || {
        PayloadError::SccpForgeryPreparation(crate::state::StateStorageAdmissionError::SccpForgery(
            crate::state::sccp_forgery_custody::ForgeryStorageError::Invalid,
        ))
    };
    let evidence = transaction
        .external()
        .and_then(|signed| {
            let Executable::Instructions(instructions) = signed.instructions() else {
                return None;
            };
            let [only] = instructions.as_ref() else {
                return None;
            };
            only.as_any().downcast_ref::<SubmitSccpForgeryEvidenceV1>()
        })
        .ok_or_else(invalid_source)?;
    match forgery::verify_for_proposal(view, parent, evidence, time_ms, budget) {
        Ok(()) => Ok(true),
        Err(error) if error.is_protocol_rejection() => Ok(false),
        Err(error) => Err(error
            .into_local_refusal()
            .map(PayloadError::SccpForgeryPreparation)
            .unwrap_or_else(|_| invalid_source())),
    }
}

fn build_at(
    state: &State,
    assembly: Assembly<'_>,
    transactions: &[AcceptedTransaction<'static>],
    merges: &MergeProposal,
    time: Duration,
    parent_service: Option<&super::certified_chain::ParentServicePreparation>,
) -> Result<SignedBlock, PayloadError> {
    #[cfg(test)]
    work_tests::record_build_at();
    let height = assembly.parent.header().height().get().saturating_add(1);
    let (_, time_source) = TimeSource::new_mock(time);
    let accepted = transactions.iter().cloned().collect::<Vec<_>>();
    let nexus = state.nexus_snapshot();
    let view = state.view();
    let npos = view
        .world()
        .sumeragi_npos_parameters()
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                PayloadError::Staking(error)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                PayloadError::RoutingDeferred(reason)
            }
        })?
        .is_some();
    let confidential = compute_confidential_feature_digest(view.world(), view.zk(), height);
    let routing = super::lanes::routing::RoutingSnapshot::of(&view)?;
    let inputs = routing.inputs(view.world());
    let contexts = transactions
        .iter()
        .map(|tx| {
            let route = inputs.execution_route(tx, height)?.ok_or_else(|| {
                PayloadError::NotCanonical("committed execution route is unavailable".into())
            })?;
            Ok(iroha_data_model::block::ExternalExecutionContext::new(
                tx.hash_as_entrypoint(),
                route.lane_id,
                route.dataspace_id,
            ))
        })
        .collect::<Result<Vec<_>, PayloadError>>()?;
    drop(view);
    let mut execution_context = BlockExecutionContextBundle::new(contexts);
    if !merges.merges.is_empty() {
        execution_context.lane_merge = Some(SumeragiLaneMergeSection {
            merges: merges.merges.clone(),
            time_floor_ms: merges.time_floor_ms,
            merged_count: 0,
        });
    }
    let builder = BlockBuilder::new_with_time_source(accepted, time_source)
        .chain(assembly.view, Some(assembly.parent))
        .with_da_proof_policies(Some(crate::da::active_proof_policy_bundle_at_height(
            &nexus, height,
        )))
        .with_confidential_features((!confidential.is_empty()).then_some(confidential))
        .with_execution_context((!execution_context.is_empty()).then_some(execution_context))
        .with_network_input_time_floor(time)
        .ok_or(PayloadError::TimeOverflow)?;
    let mut proposal = builder.into_unsigned_proposal();
    let mut effects = if npos {
        let header = proposal.header();
        Some(
            super::penalties::PenaltyApplier::new(state, None)
                .derive_npos_consensus_effects(&header)
                .map_err(staking_preparation_error)?,
        )
    } else {
        None
    };
    if height > 2 {
        let view = state.view();
        let original = match parent_service {
            Some(prepared) => prepared.proposal_original(&view, assembly.parent),
            None => super::certified_chain::CertifiedChain::new_for_parent_service(&view)
                .and_then(|reader| reader.parent_service_proposal_original(assembly.parent)),
        }
        .map_err(|error| match error {
            super::certified_chain::ParentServiceError::Deferred(reason) => {
                PayloadError::RoutingDeferred(reason)
            }
            error => PayloadError::ParentService(error.to_string()),
        })?;
        effects
            .get_or_insert_with(Default::default)
            .parent_service_commit_qc = Some(original);
    }
    proposal.set_npos_consensus_effects(effects);
    Ok(proposal)
}

/// Whether the canonical proposal carries transactions or certified lane merge work.
fn has_work(block: &SignedBlock) -> bool {
    block.has_consensus_work()
}

/// The payload bytes of `block`: its canonical resultless proposal wire.
///
/// # Errors
/// The block carries no work or cannot be encoded.
pub fn encode(block: &SignedBlock) -> Result<Vec<u8>, PayloadError> {
    if !has_work(block) {
        return Err(PayloadError::EmptyBlock);
    }
    let len = block
        .resultless_proposal_wire_len()
        .map_err(|error| PayloadError::Encode(error.to_string()))?;
    let mut wire = Vec::with_capacity(len);
    block
        .write_resultless_proposal_wire(&mut wire)
        .map_err(|error| PayloadError::Encode(error.to_string()))?;
    Ok(wire)
}

/// Decode a non-empty payload: the canonical wire of an unsigned, resultless proposal without
/// a certificate. The canonical decoder streams its encoding against the original bytes.
///
/// # Errors
/// The bytes do not decode, are not canonical, carry a result, a certificate or a signature,
/// or the decoded block has no consensus work. Local decoder resource refusal remains
/// [`PayloadError::DecodeResource`], rather than a deterministic property of the bytes.
pub fn decode(payload: &[u8]) -> Result<SignedBlock, PayloadError> {
    let block = iroha_data_model::block::decode_framed_signed_block(payload).map_err(|error| {
        match crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
            PayloadError::NotCanonical(error.to_string())
        }) {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                PayloadError::DecodeResource(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
        }
    })?;
    require_proposal(block)
}

/// Decode the original funded payload using the canonical walk and retained signature/certificate owners.
/// Other transaction/result children remain an explicit preparation obligation.
pub(crate) fn decode_prepared(
    payload: &iroha_allocation::ChargedBuffer<u8>,
    decoder: &mut iroha_data_model::block::PreparedSignedBlockSignaturesDecode,
) -> Result<SignedBlock, PayloadError> {
    use iroha_data_model::block::{
        BlockSignatureCustodyError, PreparedSignatureBlockError,
        commit_certificate::CertificateCustodyError,
    };
    use iroha_data_model::da::commitment::{DaCommitmentCustodyError, DaProofPolicyCustodyError};
    use norito::core::{PreparedDecodeError, SequenceSpan};
    let block = decoder
        .decode(
            payload,
            SequenceSpan {
                start: 0,
                end: payload.as_slice().len(),
            },
            norito::canonical_decode_limits(payload.as_slice().len()),
        )
        .map_err(|error| {
            // Only actual canonical byte failures can become deterministic proposal rejection.
            let canonical = matches!(
                &error,
                PreparedSignatureBlockError::Frame(_)
                    | PreparedSignatureBlockError::Certificate(CertificateCustodyError::Decode(_))
                    | PreparedSignatureBlockError::Policy(DaProofPolicyCustodyError::Decode(_))
                    | PreparedSignatureBlockError::Commitments(DaCommitmentCustodyError::Decode(_))
                    | PreparedSignatureBlockError::Commitments(
                        DaCommitmentCustodyError::Signature(
                            iroha_crypto::PreparedCryptoDecodeError::Signature(_)
                        )
                    )
                    | PreparedSignatureBlockError::Decode(PreparedDecodeError::Codec(_))
                    | PreparedSignatureBlockError::Decode(PreparedDecodeError::Destination(
                        BlockSignatureCustodyError::Decode(_)
                    ))
            );
            match crate::execution_attempt::prepared_signature_block_attempt_error(
                error,
                |reason| {
                    if canonical {
                        PayloadError::NotCanonical(reason)
                    } else {
                        PayloadError::SignatureCustodyInvariant(reason)
                    }
                },
            ) {
                crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                    PayloadError::DecodeResource(original)
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
            }
        })?;
    require_proposal(block)
}

fn require_proposal(block: SignedBlock) -> Result<SignedBlock, PayloadError> {
    if !has_work(&block) {
        return Err(PayloadError::EmptyBlock);
    }
    if !block.is_resultless_proposal() {
        return Err(PayloadError::NotCanonical(
            "carries a result or a commit certificate".into(),
        ));
    }
    if block.signatures().next().is_some() {
        return Err(PayloadError::NotCanonical(
            "carries a block signature".into(),
        ));
    }
    // The framed decoder already authenticated every canonical byte in place.
    // Re-encoding here would allocate another unfunded full payload and frame.
    // TODO: fund all remaining transaction/result children from the original State pool.
    Ok(block)
}

/// Select queued transactions after the view's committed parent (FIFO, peeked, never removed),
/// within `max_bytes` of transaction bytes, the on-chain transaction cap and the FASTPQ source
/// policy's Network input cap less `merges.transactions`. The original view supplies routing,
/// scheduling and forgery authority; queued rows are neither removed nor granted a receipt.
/// Fresh inputs routed to a native lane are selected by that lane; the global
/// chain selects direct inputs and rescues inputs whose lane has stalled. A rescue is
/// subject to the same `max_bytes`: a lane input larger than the global budget is skipped.
/// Forgery evidence is reverified against this original committed parent before spending
/// block capacity. Later inputs can change the canonical time, so the builder must still
/// call `recheck_sccp_forgery_for_proposal` before capturing its final Queue lease.
///
/// # Errors
/// Preserves local routing, original-history and forgery preparation refusals. Such errors
/// leave every queued input resident and cannot become a transaction rejection.
/// `wall_time` is one captured proposer clock reading; future signed inputs remain queued.
pub fn select(
    view: &crate::state::StateView<'_>,
    queue: &std::sync::Arc<Queue>,
    max_bytes: usize,
    merges: &MergeProposal,
    wall_time: Duration,
) -> Result<Vec<AcceptedTransaction<'static>>, PayloadError> {
    use crate::smartcontracts::isi::sccp::admission::{
        SccpExemptBlockBudgetV1, SccpExemptClassV1, exempt_class_of_entrypoint,
    };
    let block_parameters = view.world().parameters().block();
    // The next block executes under the FASTPQ source policy frozen at its start (the
    // committed one): proposal packing honours its Network input cap, as validation does.
    let fastpq_inputs = block_parameters
        .fastpq_source()
        .maximum_network_inputs(block_parameters.execution_output())
        .map_or(0, |inputs| usize::try_from(inputs).unwrap_or(usize::MAX));
    let max_transactions = usize::try_from(block_parameters.max_transactions().get())
        .unwrap_or(usize::MAX)
        .min(fastpq_inputs)
        .saturating_sub(merges.transactions);
    let Some(pending) = queue.bounded_pending_snapshot(view, MAX_QUEUE_SCAN) else {
        return Ok(Vec::new());
    };
    // The global chain sequences lane 0; transactions routed to a lane reach it through that
    // lane's merged blocks (`specs/sumeragi_lanes.md` §5).
    let routing = super::lanes::routing::RoutingSnapshot::of(view)?;
    let height = u64::try_from(view.height())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let inputs = routing.inputs(view.world());
    // A transaction routed to a lane that has not carried it for `2A` global block times is
    // rescued by the global chain itself (§6.4): a stalled lane cannot hold transactions, and
    // the rescue is the committed load that closes it.
    let rescue_before_ms = routing.policy().map_or(0, |policy| {
        let cadence = view.world().parameters().sumeragi().block_cadence_ms.get();
        let parent_ms = view.authenticated_query_ledger_time_ms().unwrap_or(0);
        parent_ms.saturating_sub(
            policy
                .anchor_freshness
                .saturating_mul(2)
                .saturating_mul(cadence),
        )
    });
    let mut selected = Vec::new();
    let mut bytes = 0usize;
    let committed_time_ms = crate::smartcontracts::isi::sccp::hold::committed_time_ms(view)
        .map_err(|error| PayloadError::SignatureCustodyInvariant(error.to_string()))?;
    let mut sccp_budget = SccpExemptBlockBudgetV1::new(view.world());
    let mut forgery_selected = false;
    let mut future_input = false;
    let mut original_parent = None;
    let budget = view.execution_budget();
    for transaction in pending {
        if selected.len() >= max_transactions {
            break;
        }
        let Some(lane) = inputs.route(&transaction, height)? else {
            continue;
        };
        if routing.has_lanes()
            && lane != super::lanes::routing::GLOBAL_LANE
            && u64::try_from(transaction.as_ref().creation_time().as_millis())
                .is_ok_and(|created| created >= rescue_before_ms)
        {
            continue;
        }
        let next = bytes.saturating_add(transaction.encoded_len());
        if next > max_bytes {
            continue;
        }
        // CT3 is local proposal pacing, never transaction invalidity. An eligible
        // future input must arm retry even when it is the final input on an idle chain.
        if !cfg!(all(test, sumeragi_core_mutation = "HC259"))
            && transaction.as_ref().creation_time() > wall_time
        {
            future_input = true;
            continue;
        }
        let class =
            exempt_class_of_entrypoint(view.world(), transaction.entrypoint(), committed_time_ms);
        if class == Some(SccpExemptClassV1::ForgeryEvidence) {
            if forgery_selected {
                continue;
            }
            if original_parent.is_none() {
                let parent_height = NonZeroUsize::new(view.height()).ok_or_else(|| {
                    PayloadError::ParentService(
                        "forgery selection requires the original committed parent".into(),
                    )
                })?;
                original_parent = Some(
                    view.canonical_history()
                        .executed_block(parent_height, |_, _| Ok(()))
                        .map_err(|error| match error {
                            ExecutionAttemptError::Deferred(original) => {
                                PayloadError::RoutingDeferred(original)
                            }
                            ExecutionAttemptError::Rejected(error) => {
                                PayloadError::ParentService(error.to_string())
                            }
                        })?,
                );
            }
            let parent = original_parent.as_ref().ok_or_else(|| {
                PayloadError::ParentService("original forgery parent was not retained".into())
            })?;
            let scheduled = view
                .world()
                .consensus_schedule()
                .ready(height)
                .map_err(|error| PayloadError::ParentService(error.to_string()))?;
            let minimum = parent
                .header()
                .creation_time()
                .checked_add(Duration::from_millis(scheduled.params.block_time_ms))
                .ok_or(PayloadError::TimeOverflow)?;
            let minimum = if merges.merges.is_empty() {
                minimum
            } else {
                minimum.max(Duration::from_millis(merges.time_floor_ms))
            };
            let proposed = Duration::from_millis(
                u64::try_from(wall_time.as_millis()).map_err(|_| PayloadError::TimeOverflow)?,
            );
            let time = crate::block::creation_time_after_inputs(
                minimum.max(proposed),
                selected
                    .iter()
                    .map(AcceptedTransaction::entrypoint)
                    .chain(std::iter::once(transaction.entrypoint())),
            )
            .ok_or(PayloadError::TimeOverflow)?;
            let time_ms =
                u64::try_from(time.as_millis()).map_err(|_| PayloadError::TimeOverflow)?;
            if !current_sccp_forgery(view, parent, &transaction, time_ms, &budget)? {
                // A now-genuine/duplicate/expired row spends neither bytes, transaction
                // count nor SCCP quota. It retains its original Queue custody.
                continue;
            }
        }
        if !sccp_budget.admit(class) {
            continue;
        }
        forgery_selected |= class == Some(SccpExemptClassV1::ForgeryEvidence);
        bytes = next;
        selected.push(transaction);
    }
    if selected.is_empty() && merges.merges.is_empty() && future_input {
        return Err(PayloadError::ClockAhead);
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use iroha_data_model::{
        block::{BlockHeader, builder::BlockBuilder as WireBlockBuilder},
        isi::Log,
        level::Level,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};

    #[test]
    fn original_staking_policy_read_owner_survives_payload_and_block_adapters() {
        use crate::execution_attempt::ExecutionAttemptError;
        use crate::{
            state::{World, WorldReadOnly},
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        use iroha_data_model::{
            isi::error::InstructionExecutionError,
            parameter::{
                Parameter,
                system::{SumeragiConsensusMode, SumeragiNposParameters},
            },
        };
        let mut config = TestChainConfig::new(World::new(), 1_000);
        config.consensus_mode = SumeragiConsensusMode::Npos;
        config.genesis_parameters.push(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ));
        let chain = CertifiedTestChain::start(config).unwrap();
        let view = chain.state().view();
        let policy = view.world().sumeragi_npos_parameters().unwrap();
        let error = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
            || view.world().sumeragi_npos_parameters(),
        )
        .unwrap_err()
        .map_rejection(|message| InstructionExecutionError::InvariantViolation(message.into()));
        let ExecutionAttemptError::Deferred(expected) = &error else {
            panic!("original decoder must refuse: {error:?}");
        };
        let expected = expected.clone();
        let payload = staking_preparation_error(
            eyre::Report::new(error.clone()).wrap_err("original staking preparation"),
        );
        assert!(
            matches!(&payload, PayloadError::RoutingDeferred(actual) if actual == &expected),
            "payload erased original policy refusal: {payload:?}"
        );
        let block = crate::block::BlockValidationError::from_npos_application_error(
            eyre::Report::new(error).wrap_err("original staking preparation"),
            "validation",
        );
        assert!(
            matches!(&block, crate::block::BlockValidationError::ExecutionDeferred(actual) if actual == &expected),
            "validation erased original policy refusal: {block:?}"
        );
        assert_eq!(view.world().sumeragi_npos_parameters().unwrap(), policy);
    }

    #[test]
    fn encode_rejects_a_merge_suffix_larger_than_the_input_sequence() {
        use iroha_data_model::{
            block::{BlockExecutionContextBundle, ExternalExecutionContext},
            sumeragi_finality::test_fixtures::NativeFinalityFixture,
            sumeragi_lanes::{SumeragiLaneMerge, SumeragiLaneMergeSection},
        };
        use iroha_model_base::topology::{DataSpaceId, LaneId};

        let fixture = NativeFinalityFixture::start("invalid-payload-projection");
        let source = fixture.block_with_submitted_work(fixture.next_header());
        let input = source.external_transactions().next().unwrap().clone();
        let mut context = BlockExecutionContextBundle::new(vec![ExternalExecutionContext::new(
            input.hash_as_entrypoint(),
            LaneId::new(0),
            DataSpaceId::new(0),
        )]);
        context.lane_merge = Some(SumeragiLaneMergeSection {
            merges: vec![SumeragiLaneMerge {
                lane: LaneId::new(16),
                incarnation: [1; 32],
                from: 1,
                to: 2,
                tip_hash: [2; 32],
                tip_result: [3; 32],
            }],
            time_floor_ms: 0,
            merged_count: 2,
        });
        let mut builder = WireBlockBuilder::new(source.header());
        builder.push_transaction(input);
        builder.set_execution_context(Some(context));
        let malformed = builder.build(iroha_data_model::block::BlockSignatures::default());
        assert!(matches!(encode(&malformed), Err(PayloadError::Encode(_))));
    }

    #[test]
    fn decode_rejects_garbage_and_empty() {
        assert!(matches!(decode(&[]), Err(PayloadError::NotCanonical(_))));
        assert!(matches!(
            decode(&[1, 2, 3, 4]),
            Err(PayloadError::NotCanonical(_))
        ));
    }

    #[test]
    fn canonical_wire_cannot_hide_a_zero_transaction_block() {
        let block = WireBlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            1,
            0,
        ))
        .build(iroha_data_model::block::BlockSignatures::default());
        let bytes = block.encode_wire().expect("canonical empty proposal");
        assert!(
            !bytes.is_empty(),
            "the transport payload itself is nonempty"
        );
        assert!(matches!(decode(&bytes), Err(PayloadError::EmptyBlock)));
        assert_eq!(encode(&block), Err(PayloadError::EmptyBlock));
    }

    #[test]
    fn assembly_refuses_empty_work_before_reading_state() {
        let state = State::new_for_testing(
            crate::state::World::new(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let parent = WireBlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            1,
            0,
        ))
        .build(iroha_data_model::block::BlockSignatures::default());
        assert!(matches!(
            assemble(
                &state,
                Assembly {
                    parent: &parent,
                    view: 10,
                    cadence: Duration::from_millis(100),
                    proposed_time: std::time::Duration::ZERO,
                },
                &[]
            ),
            Err(PayloadError::EmptyBlock)
        ));
        assert_eq!(state.view().height(), 0);
    }

    #[test]
    fn canonical_nonempty_proposal_roundtrips_without_synthesized_work() {
        let mut builder = WireBlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            1,
            0,
        ));
        let transaction = TransactionBuilder::new(
            iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"payload-test-network",
                )),
            ),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "payload transaction".to_owned())])
        .sign(ALICE_KEYPAIR.private_key());
        builder.push_transaction(transaction);
        let block = builder.build(iroha_data_model::block::BlockSignatures::default());
        let bytes = encode(&block).expect("nonempty proposal");
        assert_eq!(bytes, block.encode_wire().unwrap());
        let decoded = decode(&bytes).expect("canonical nonempty proposal");
        assert_eq!(decoded.network_entrypoint_count(), 1);
        assert_eq!(decoded.encode_wire().unwrap(), bytes);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode(&trailing),
            Err(PayloadError::NotCanonical(_))
        ));
        let mut truncated = bytes.clone();
        truncated.pop();
        assert!(matches!(
            decode(&truncated),
            Err(PayloadError::NotCanonical(_))
        ));
        assert!(matches!(
            decode(&bytes[1..]),
            Err(PayloadError::NotCanonical(_))
        ));
    }
    #[test]
    fn signed_native_lane_policy_drives_direct_global_context_without_queue_override() {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::{
            account::{Account, AccountId},
            isi::Register,
            parameter::Parameter,
            sumeragi_lanes::{
                SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
            },
        };
        use iroha_model_base::{
            peer::PeerId,
            topology::{DataSpaceId, LaneId},
        };
        let user = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let account = AccountId::new(user.public_key().clone());
        let mut committee = (0x61..=0x64)
            .map(|seed| {
                let key = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
                SumeragiLaneMember {
                    peer: PeerId::new(key.public_key().clone()),
                    pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                }
            })
            .collect::<Vec<_>>();
        committee.sort();
        let policy = SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 4,
            max_merge_blocks: 8,
            stall_window: 1000,
            lane_params: Default::default(),
            fixed: vec![SumeragiFixedLane {
                lane: LaneId::new(2),
                dataspace: DataSpaceId::UNIVERSAL,
                committee,
            }],
            routes: vec![SumeragiLaneRoute {
                lane: LaneId::new(2),
                account: Some(account.to_string()),
                instruction: None,
            }],
            autoscale: None,
        };
        let mut config = TestChainConfig::new(crate::state::World::new(), 1000);
        config
            .genesis_instructions
            .push(Register::account(Account::new(account.clone())).into());
        config
            .genesis_parameters
            .push(Parameter::Custom(policy.into_custom_parameter()));
        let mut chain = CertifiedTestChain::start(config).unwrap();
        chain.commit_at(2000, Vec::new());
        chain.commit_at(3000, Vec::new());
        let view = chain.state().view();
        assert!(
            view.world()
                .sumeragi_lanes()
                .lane(LaneId::new(2))
                .unwrap()
                .admits_anchor(3)
        );
        let parent = view
            .latest_block()
            .expect("completed original State read")
            .unwrap();
        let mut builder = TransactionBuilder::new(
            chain.network_id(),
            account,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "direct rescue".to_owned())]);
        builder.set_creation_time(Duration::from_millis(3000));
        let (_, clock) = TimeSource::new_mock(Duration::from_millis(3001));
        let accepted = AcceptedTransaction::accept_with_time_source(
            builder.sign(user.private_key()),
            &chain.network_id(),
            Duration::from_secs(1),
            view.world().parameters().transaction(),
            &iroha_config::parameters::actual::Crypto::default(),
            &clock,
        )
        .unwrap();
        drop(view);
        let proposal = assemble(
            chain.state(),
            Assembly {
                parent: &parent,
                view: 0,
                cadence: Duration::from_millis(1),
                proposed_time: std::time::Duration::ZERO,
            },
            &[accepted],
        )
        .unwrap();
        let contexts = &proposal.execution_context().unwrap().external;
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].lane_id, LaneId::new(2));
        assert_eq!(contexts[0].dataspace_id, DataSpaceId::UNIVERSAL);
        assert_eq!(contexts[0].routing_plan_legs.len(), 1);
        assert!(
            proposal.lane_merge().is_none(),
            "a direct rescue carries no fabricated lane certificate"
        );
        assert_eq!(decode(&encode(&proposal).unwrap()).unwrap(), proposal);
    }
}

#[cfg(test)]
#[path = "payload/work_tests.rs"]
mod work_tests;

#[cfg(test)]
#[path = "payload/resource_contract_tests.rs"]
mod resource_contract_tests;

#[cfg(test)]
#[path = "payload/forgery_tests.rs"]
mod forgery_tests;
