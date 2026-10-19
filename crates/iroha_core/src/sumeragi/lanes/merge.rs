//! The global chain's lane merge (`specs/sumeragi_lanes.md` §4.2–§4.3).
//!
//! A global block names, per lane, the next contiguous certified lane heights
//! ([`SumeragiLaneMerge`]). [`expand`] checks those references against the committed lane state
//! and the node's lane stores, and turns the merged lane blocks into the entrypoints the block
//! executes after its own transactions: lanes ascending, lane heights ascending, batch order.
//!
//! A merged transaction that the global chain must not execute is dropped from the executed
//! block with no effect and no fee: it is carried by a stale lane block, routed to another lane
//! at this height, already committed or earlier in the block, or not admissible in a block at
//! this height. Every such rule reads the committed pre-state and the block alone, so every
//! honest node executes the same entrypoints. Only a malformed reference (a lane that is not
//! active, a gap, an oversized range, a tip that differs from the lane's committed block, or
//! more transactions than the block may execute) makes the global block invalid.

use crate::execution_attempt::ExecutionAttemptError as Attempt;

use std::{borrow::Cow, collections::BTreeMap, time::Duration};

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    block::{ExternalExecutionContext, SignedBlock},
    sumeragi_lanes::{SumeragiLaneMerge, SumeragiLanePolicy, SumeragiLaneState},
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::types::Hash32;

use super::{LaneBatch, ProposalReadScope, lane_policy, routing::GLOBAL_LANE};
pub use crate::sumeragi::payload::MergeProposal;
use crate::{
    state::{
        State, StateReadOnly, StateReadOnlyWithTransactions, WorldReadOnly,
        is_stable_state_view_generation,
    },
    tx::AcceptedTransaction,
};

/// A committed lane block as the node's lane store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedLaneBlock {
    /// Core block hash.
    pub block_hash: Hash32,
    /// Certified result `R`.
    pub result: Hash32,
    /// The decoded payload; `None` when a (Byzantine) lane committee certified bytes that are
    /// not a lane batch — such a block is merged without effect.
    pub batch: Option<LaneBatch>,
}

/// The node's committed lane blocks: the lane stores of the lane instances it follows.
pub trait LaneBlockSource: Send + Sync {
    /// The committed tip height of incarnation `incarnation` of `lane`, or `None` if the node
    /// does not follow it.
    ///
    /// # Errors
    /// Storage corruption, I/O, unresolved authenticated authority or resource refusal.
    fn tip(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
    ) -> Result<Option<u64>, Attempt<std::io::Error>>;
    /// The committed block at `height`.
    ///
    /// # Errors
    /// Storage corruption, I/O, unresolved authenticated authority or resource refusal.
    fn block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<std::io::Error>>;
    /// Read local proposal work under the exact caller-owned request. A refusal keeps that
    /// request's original job; actual historical readers use `block` independently.
    ///
    /// # Errors
    /// Storage, authentication, original-pool refusal or another live request owns the slot.
    fn proposal_block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        request: &ProposalReadScope,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<std::io::Error>>;
    /// Read an incoming proposal's exact committed frame under its original request.
    /// This grants no tip or local selection authority to read-only replay sources.
    ///
    /// # Errors
    /// Original storage, authentication, pool refusal or another live request owns the slot.
    fn execution_block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        request: &ProposalReadScope,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<std::io::Error>>;
    /// Wait for one incoming proposal's referenced height under that same request.
    /// Refused recovery remains owned by this request, not implicit historical demand.
    ///
    /// # Errors
    /// Original storage, authentication, pool refusal or another live request owns the slot.
    fn execution_wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        timeout: Duration,
        request: &ProposalReadScope,
    ) -> Result<bool, Attempt<std::io::Error>>;
    /// Finish bounded cancellation cleanup after the original proposal owner is dropped.
    /// Implementations may release only cancelled proposal interest, never historical work.
    /// This lifecycle hook performs no native I/O and does not wait for a read lock.
    fn release_cancelled_proposal_reads(&self);

    /// Block until the committed tip reaches `height` or `timeout` passes; whether it did.
    ///
    /// # Errors
    /// Store recovery could not complete; failure is never reported as a missing height.
    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        timeout: Duration,
    ) -> Result<bool, Attempt<std::io::Error>>;
}

/// A node that follows no lane.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoLanes;

impl LaneBlockSource for NoLanes {
    fn tip(
        &self,
        _lane: LaneId,
        _incarnation: &[u8; 32],
    ) -> Result<Option<u64>, Attempt<std::io::Error>> {
        Ok(None)
    }
    fn block(
        &self,
        _lane: LaneId,
        _incarnation: &[u8; 32],
        _height: u64,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<std::io::Error>> {
        Ok(None)
    }
    fn proposal_block(
        &self,
        _: LaneId,
        _: &[u8; 32],
        _: u64,
        _: &ProposalReadScope,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<std::io::Error>> {
        Ok(None)
    }
    fn execution_block(
        &self,
        _: LaneId,
        _: &[u8; 32],
        _: u64,
        _: &ProposalReadScope,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<std::io::Error>> {
        Ok(None)
    }
    fn execution_wait_for(
        &self,
        _: LaneId,
        _: &[u8; 32],
        _: u64,
        _: Duration,
        _: &ProposalReadScope,
    ) -> Result<bool, Attempt<std::io::Error>> {
        Ok(false)
    }
    fn release_cancelled_proposal_reads(&self) {}
    fn wait_for(
        &self,
        _lane: LaneId,
        _incarnation: &[u8; 32],
        _height: u64,
        _timeout: Duration,
    ) -> Result<bool, Attempt<std::io::Error>> {
        Ok(false)
    }
}

/// Why a global block's lane merge cannot be expanded.
#[derive(Debug, thiserror::Error)]
pub enum MergeError {
    /// The same State published a new cut; reacquire the exact proposal and lane inputs.
    #[error(
        "lane source publication changed ({authenticated_generation} -> {observed_generation})"
    )]
    SourceChanged {
        /// Generation bound by the original lane expansion.
        authenticated_generation: u64,
        /// Generation observed at its next source check.
        observed_generation: u64,
    },
    /// Original State reader refusal, preserving its actual physical release source.
    #[error(transparent)]
    StateView(#[from] crate::state::StateViewError),
    /// Original routing State could not be read locally; the certified input remains retryable.
    #[error("lane routing deferred: {0}")]
    RoutingDeferred(#[from] crate::execution_attempt::ExecutionDeferred),
    /// Original merge scratch refused its finite operation budget; retain the exact proposal.
    #[error("lane merge resource deferred: {0}")]
    ResourceDeferred(crate::execution_attempt::ExecutionDeferred),
    /// Local storage failed; this does not prove that a peer's global block is invalid.
    #[error("lane storage failed: {0}")]
    Storage(#[source] Attempt<std::io::Error>),
    /// The node has not committed the referenced lane blocks yet: execution waits.
    #[error("lane blocks are not available yet: {0}")]
    Pending(String),
    /// The merge is malformed: the global block is invalid.
    #[error("invalid lane merge: {0}")]
    Invalid(String),
}

/// What the lane step of a global block reads (§4.3 step 4, §6.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaneStepInput {
    /// The block's merges.
    pub merges: Vec<SumeragiLaneMerge>,
    /// Executed transactions per carrying lane (lane `0`: the block's own).
    pub executed: BTreeMap<LaneId, u64>,
    /// The block's own transactions routed to another lane, per lane (§6.4).
    pub rescued: BTreeMap<LaneId, u64>,
    /// The block's creation time (ms since the Unix epoch).
    pub time_ms: u64,
}

/// Source-bound merged entrypoints and lane step from one exact original proposal.
/// Only `expand` can create it; it cannot move to another proposal, State, or publication.
pub struct Expansion<'state> {
    state: &'state State,
    generation: u64,
    source: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    entrypoints: Vec<TransactionEntrypoint>,
    contexts: Vec<ExternalExecutionContext>,
    step: LaneStepInput,
}
impl std::fmt::Debug for Expansion<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Expansion")
            .field("generation", &self.generation)
            .field("source", &self.source)
            .field("entrypoints", &self.entrypoints)
            .field("contexts", &self.contexts)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}
impl Expansion<'_> {
    /// Refuse a local receiver substitution or publication change before interpreting peer work.
    pub(crate) fn validate_publication(&self, state: &State) -> Result<(), MergeError> {
        if !std::ptr::eq(self.state, state) {
            return Err(MergeError::Pending(
                "expansion differs from original State owner".into(),
            ));
        }
        let observed_generation = state.state_view_generation();
        if !is_stable_state_view_generation(self.generation, observed_generation) {
            return Err(MergeError::SourceChanged {
                authenticated_generation: self.generation,
                observed_generation,
            });
        }
        Ok(())
    }
    /// Consume the original expansion after native proposal-wire validation, preserving
    /// the original proposal on refusal and moving the exact lane step into execution.
    pub(crate) fn apply(
        self,
        proposal: SignedBlock,
        state: &State,
        generation: u64,
    ) -> Result<(SignedBlock, LaneStepInput), (SignedBlock, MergeError)> {
        if let Err(error) = self.validate_publication(state) {
            return Err((proposal, error));
        }
        if !is_stable_state_view_generation(self.generation, generation) {
            return Err((
                proposal,
                MergeError::SourceChanged {
                    authenticated_generation: self.generation,
                    observed_generation: generation,
                },
            ));
        }
        if proposal.hash() != self.source {
            return Err((
                proposal,
                MergeError::Invalid("expansion differs from original proposal".into()),
            ));
        }
        if proposal.lane_merge().is_none() {
            if !self.entrypoints.is_empty()
                || !self.contexts.is_empty()
                || !self.step.merges.is_empty()
            {
                return Err((
                    proposal,
                    MergeError::Invalid("expansion invents an unsigned merge".into()),
                ));
            }
            return Ok((proposal, self.step));
        }
        match proposal.with_merged_entrypoints(self.entrypoints, self.contexts) {
            Ok(executed) => Ok((executed, self.step)),
            Err((proposal, _merged, _contexts, reason)) => {
                Err((proposal, MergeError::Invalid(reason.to_owned())))
            }
        }
    }
}

/// The transactions a global block may execute at most: the on-chain transaction cap and the
/// execution output's network input capacity.
fn block_capacity(world: &impl WorldReadOnly) -> usize {
    let parameters = world.parameters().block();
    let inputs = parameters
        .fastpq_source()
        .maximum_network_inputs(parameters.execution_output())
        .map_or(0, |inputs| usize::try_from(inputs).unwrap_or(usize::MAX));
    usize::try_from(parameters.max_transactions().get())
        .unwrap_or(usize::MAX)
        .min(inputs)
}
/// Check the merge references of `proposal` (global height `h`) against the committed
/// pre-state and the node's lane stores, waiting up to `wait` for lane blocks, and expand them.
/// The exact State owner and stable publication are retained before releasing the read view.
///
/// # Errors
/// [`MergeError::Pending`] while referenced lane blocks are not committed locally;
/// [`MergeError::Invalid`] for a malformed merge.
/// [`MergeError::Storage`] preserves local storage/authority/resource failures unchanged.
pub fn expand<'state>(
    state: &'state State,
    proposal: &SignedBlock,
    source: &dyn LaneBlockSource,
    wait: Duration,
    request: &mut ProposalReadScope,
) -> Result<Expansion<'state>, MergeError> {
    let budget = state.ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let publication = state.view_publication_release();
        let generation = state.state_view_generation();
        let view = state.try_view_once()?;
        let expanded = expand_from_view(state, generation, &view, proposal, source, wait, request);
        drop(view);
        if !is_stable_state_view_generation(generation, state.state_view_generation()) {
            return Err(MergeError::StateView(crate::state::StateViewError::Busy(
                publication,
            )));
        }
        expanded
    })
}

fn expand_from_view<'state, V: StateReadOnlyWithTransactions>(
    state: &'state State,
    generation: u64,
    view: &V,
    proposal: &SignedBlock,
    source: &dyn LaneBlockSource,
    wait: Duration,
    request: &mut ProposalReadScope,
) -> Result<Expansion<'state>, MergeError> {
    let height = proposal.header().height().get();
    let time_ms = u64::try_from(proposal.header().creation_time().as_millis()).unwrap_or(u64::MAX);
    let lanes = view.world().sumeragi_lanes();
    let routing = super::routing::RoutingSnapshot::of(view).map_err(MergeError::RoutingDeferred)?;
    let policy = routing.policy();
    let inputs = routing.inputs(view.world());
    let own = proposal.external_entrypoints_slice();
    let mut step = LaneStepInput {
        time_ms,
        ..LaneStepInput::default()
    };
    step.executed
        .insert(GLOBAL_LANE, u64::try_from(own.len()).unwrap_or(u64::MAX));
    if routing.has_lanes() {
        for entrypoint in own {
            let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(entrypoint));
            let lane = inputs.route(&accepted, height)?.ok_or_else(|| {
                MergeError::Invalid("concrete dataspace has no active native execution lane".into())
            })?;
            if lane != GLOBAL_LANE {
                *step.rescued.entry(lane).or_default() += 1;
            }
        }
    }
    let Some(section) = proposal.lane_merge() else {
        return Ok(Expansion {
            state,
            generation,
            source: proposal.hash(),
            entrypoints: Vec::new(),
            contexts: Vec::new(),
            step,
        });
    };
    if section.merged_count != 0 {
        return Err(MergeError::Invalid(
            "a proposal carries merged entrypoints".into(),
        ));
    }
    if section.merges.is_empty() {
        return Err(MergeError::Invalid("an empty merge section".into()));
    }
    let Some(policy) = policy else {
        return Err(MergeError::Invalid("the chain has no lane policy".into()));
    };
    request
        .admit(&state.ivm_execution_budget())
        .map_err(MergeError::Storage)?;
    let blocks = load(
        &section.merges,
        lanes,
        policy,
        height,
        source,
        wait,
        request,
    )?;
    step.merges.clone_from(&section.merges);
    // Candidates: the transactions of fresh merged blocks, in execution order.
    let candidates = blocks
        .into_iter()
        .filter(|(_, stale, _)| !stale)
        .filter_map(|(lane, _, block)| block.batch.map(|batch| (lane, batch.transactions)))
        .flat_map(|(lane, transactions)| transactions.into_iter().map(move |tx| (lane, tx)))
        .collect::<Vec<_>>();
    if own.len().saturating_add(candidates.len()) > block_capacity(view.world()) {
        return Err(MergeError::Invalid(
            "the merged transactions exceed the block's capacity".into(),
        ));
    }
    let floor = candidates
        .iter()
        .map(|(_, tx)| time_floor(std::slice::from_ref(tx)))
        .max()
        .unwrap_or(0);
    if floor != section.time_floor_ms {
        return Err(MergeError::Invalid(format!(
            "the merge time floor is {} ms, not {floor} ms",
            section.time_floor_ms
        )));
    }
    let mut identities = MergeIdentityIndex::new(own, &candidates, &state.ivm_execution_budget())?;
    let admission = Admissibility::of(view);
    let mut expansion = Expansion {
        state,
        generation,
        source: proposal.hash(),
        entrypoints: Vec::new(),
        contexts: Vec::new(),
        step,
    };
    for (index, (lane, tx)) in candidates.into_iter().enumerate() {
        let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(&tx));
        let cached = identities.candidates.as_slice()[index];
        let hash = cached.carrier;
        if inputs.route(&accepted, height)? != Some(lane)
            || view.has_entrypoint(hash)
            || cached
                .replay_alias
                .is_some_and(|alias| view.has_entrypoint(alias))
            || !admission.admits(&tx, proposal)
        {
            continue;
        }
        if !identities.admit(cached.work) {
            continue;
        }
        // `load` verified the range against this exact committed incarnation; routing
        // above independently checked that this transaction still belongs to its lane.
        // Its execution scope is the source lane's pinned dataspace. Re-evaluating the
        // retired Nexus policy here would silently turn an actual lane into lane zero.
        let record = lanes.lane(lane).ok_or_else(|| {
            MergeError::Invalid(format!(
                "lane {lane}: admitted source has no committed record"
            ))
        })?;
        expansion.contexts.push(ExternalExecutionContext::new(
            hash,
            record.lane,
            record.dataspace,
        ));
        let original = tx;
        let original = if cfg!(all(test, sumeragi_core_mutation = "HC344")) {
            match original {
                TransactionEntrypoint::SealedReveal(reveal) => {
                    TransactionEntrypoint::External(reveal.signed_transaction)
                }
                original => original,
            }
        } else {
            original
        };
        expansion.entrypoints.push(original);
        *expansion.step.executed.entry(lane).or_default() += 1;
    }
    Ok(expansion)
}

/// The work identity checked by global static validation. This is distinct from
/// the original carrier hash retained in LaneResult and Expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MergeWorkIdentity {
    Signed(HashOf<SignedTransaction>),
    Commitment(Hash),
}
impl MergeWorkIdentity {
    fn of(entrypoint: &TransactionEntrypoint) -> Self {
        match entrypoint {
            TransactionEntrypoint::External(signed) => Self::Signed(signed.hash()),
            TransactionEntrypoint::SealedReveal(reveal) => {
                Self::Signed(reveal.signed_transaction().hash())
            }
            TransactionEntrypoint::SealedCommitment(commitment) => {
                Self::Commitment(*commitment.commitment())
            }
        }
    }
}

/// Hash each canonical identity once before admission. The replay alias exists
/// only for reveals and is the same signed external identity used by State admission.
#[derive(Clone, Copy)]
struct MergeCandidateIdentity {
    carrier: HashOf<TransactionEntrypoint>,
    work: MergeWorkIdentity,
    replay_alias: Option<HashOf<TransactionEntrypoint>>,
}

/// Fixed original-budget scratch: linear source hashing, in-place O(N log N)
/// key ordering and logarithmic lookups. No key or backing grows during admission.
struct MergeIdentityIndex {
    rows: ChargedBuffer<(MergeWorkIdentity, bool)>,
    candidates: ChargedBuffer<MergeCandidateIdentity>,
}
impl MergeIdentityIndex {
    fn new(
        own: &[TransactionEntrypoint],
        candidates: &[(LaneId, TransactionEntrypoint)],
        budget: &AllocationBudget,
    ) -> Result<Self, MergeError> {
        let count = own.len().checked_add(candidates.len()).ok_or_else(|| {
            MergeError::ResourceDeferred(iroha_allocation::AllocationRefusal::DemandOverflow.into())
        })?;
        let mut rows = ChargedBuffer::new(count, budget).map_err(merge_buffer_refusal)?;
        let mut cached =
            ChargedBuffer::new(candidates.len(), budget).map_err(merge_buffer_refusal)?;
        for entrypoint in own {
            rows.push_reserved((MergeWorkIdentity::of(entrypoint), true));
        }
        for (_, entrypoint) in candidates {
            let identity = MergeWorkIdentity::of(entrypoint);
            let replay_alias = match entrypoint {
                TransactionEntrypoint::SealedReveal(reveal) => {
                    Some(reveal.signed_transaction().hash_as_entrypoint())
                }
                TransactionEntrypoint::External(_) | TransactionEntrypoint::SealedCommitment(_) => {
                    None
                }
            };
            cached.push_reserved(MergeCandidateIdentity {
                carrier: entrypoint.hash(),
                work: identity,
                replay_alias,
            });
            rows.push_reserved((identity, false));
        }
        rows.as_mut_slice().sort_unstable_by_key(|row| row.0);
        let mut unique = 0;
        for index in 0..rows.as_slice().len() {
            let row = rows.as_slice()[index];
            if unique > 0 && rows.as_slice()[unique - 1].0 == row.0 {
                rows.as_mut_slice()[unique - 1].1 |= row.1;
            } else {
                rows.as_mut_slice()[unique] = row;
                unique += 1;
            }
        }
        rows.truncate(unique);
        Ok(Self {
            rows,
            candidates: cached,
        })
    }

    fn admit(&mut self, identity: MergeWorkIdentity) -> bool {
        let index = self
            .rows
            .as_slice()
            .binary_search_by_key(&identity, |row| row.0)
            .expect("every candidate identity was retained before admission");
        let seen = &mut self.rows.as_mut_slice()[index].1;
        if *seen {
            return false;
        }
        *seen = true;
        true
    }
}

fn merge_buffer_refusal(error: ChargedBufferError) -> MergeError {
    MergeError::ResourceDeferred(match error {
        ChargedBufferError::Admission(original) => original.into(),
        ChargedBufferError::Allocator { .. } => {
            ivm::error::ExecutionDeferral::AllocationUnavailable.into()
        }
    })
}

/// The merges a leader proposes at global height `height` over the committed state `view`
/// (§4.2): per active lane, the next contiguous blocks its local store has committed, up to
/// `max_merge_blocks` and the block's transaction capacity, and the merged transactions they
/// reserve. Lanes take turns filling the capacity (rotating by height) so none starves; the
/// merges themselves are listed in ascending lane order.
///
/// # Errors
/// Local storage, unavailable authenticated authority or resource refusal. Scheduler callers
/// may retry `WouldBlock`; errors must not silently remove an otherwise eligible merge.
pub fn propose<V: StateReadOnly>(
    view: &V,
    source: &dyn LaneBlockSource,
    height: u64,
    request: &mut ProposalReadScope,
) -> Result<MergeProposal, Attempt<std::io::Error>> {
    let Some(policy) = lane_policy(view.world()).map_err(|reason| {
        if cfg!(all(test, sumeragi_core_mutation = "HC51")) {
            Attempt::Rejected(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        } else {
            Attempt::Deferred(reason)
        }
    })?
    else {
        return Ok(MergeProposal::default());
    };
    let capacity = block_capacity(view.world());
    let lanes = view.world().sumeragi_lanes();
    let active = lanes
        .lanes
        .iter()
        .filter(|record| height > record.active_from)
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(MergeProposal::default());
    }
    request.admit(&view.execution_budget())?;
    let start = usize::try_from(height % u64::try_from(active.len()).unwrap_or(1)).unwrap_or(0);
    let mut used = 0usize;
    let mut time_floor_ms = 0u64;
    let mut merges = Vec::new();
    for offset in 0..active.len() {
        let record = active[(start + offset) % active.len()];
        let Some(tip) = source.tip(record.lane, &record.incarnation)? else {
            continue;
        };
        let from = record.merged.height.saturating_add(1);
        let last = tip.min(
            record
                .merged
                .height
                .saturating_add(u64::from(policy.max_merge_blocks)),
        );
        let mut end = None;
        for lane_height in from..=last {
            let Some(block) =
                source.proposal_block(record.lane, &record.incarnation, lane_height, request)?
            else {
                break;
            };
            let fresh = block
                .batch
                .as_ref()
                .filter(|batch| !record.is_stale(batch.anchor_height, height))
                .map_or(&[][..], |batch| batch.transactions.as_slice());
            if used.saturating_add(fresh.len()) > capacity {
                break;
            }
            used = used.saturating_add(fresh.len());
            time_floor_ms = time_floor_ms.max(time_floor(fresh));
            end = Some((lane_height, block));
        }
        if let Some((to, block)) = end {
            merges.push(SumeragiLaneMerge {
                lane: record.lane,
                incarnation: record.incarnation,
                from,
                to,
                tip_hash: block.block_hash.0,
                tip_result: block.result.0,
            });
        }
    }
    merges.sort_by_key(|merge| merge.lane);
    Ok(MergeProposal {
        merges,
        transactions: used,
        time_floor_ms,
    })
}

/// One millisecond after the latest creation time among `transactions` (`0` for none).
fn time_floor(transactions: &[TransactionEntrypoint]) -> u64 {
    transactions
        .iter()
        .filter_map(TransactionEntrypoint::creation_time_ms)
        .map(|created| created.saturating_add(1))
        .max()
        .unwrap_or(0)
}

/// Check each merge against the committed lane records and load its blocks from the node's lane
/// stores: `(lane, stale, block)` in execution order.
fn load(
    merges: &[SumeragiLaneMerge],
    lanes: &SumeragiLaneState,
    policy: &SumeragiLanePolicy,
    height: u64,
    source: &dyn LaneBlockSource,
    wait: Duration,
    request: &ProposalReadScope,
) -> Result<Vec<(LaneId, bool, CommittedLaneBlock)>, MergeError> {
    let invalid =
        |lane: LaneId, reason: &str| MergeError::Invalid(format!("lane {lane}: {reason}"));
    let mut previous: Option<LaneId> = None;
    let mut blocks = Vec::new();
    for merge in merges {
        let lane = merge.lane;
        if previous.is_some_and(|previous| previous >= lane) {
            return Err(invalid(lane, "merges are not in ascending lane order"));
        }
        previous = Some(lane);
        let Some(record) = lanes.lane(lane) else {
            return Err(invalid(lane, "no such lane"));
        };
        if record.incarnation != merge.incarnation {
            return Err(invalid(lane, "another incarnation"));
        }
        if height <= record.active_from {
            return Err(invalid(lane, "the lane is not active yet"));
        }
        if merge.from != record.merged.height.saturating_add(1) || merge.is_empty() {
            return Err(invalid(
                lane,
                "the range does not continue the merged frontier",
            ));
        }
        if merge.len() > u64::from(policy.max_merge_blocks) {
            return Err(invalid(lane, "the range exceeds max_merge_blocks"));
        }
        if !source
            .execution_wait_for(lane, &merge.incarnation, merge.to, wait, request)
            .map_err(MergeError::Storage)?
        {
            return Err(MergeError::Pending(format!(
                "lane {lane} has not committed height {}",
                merge.to
            )));
        }
        for lane_height in merge.from..=merge.to {
            let Some(block) = source
                .execution_block(lane, &merge.incarnation, lane_height, request)
                .map_err(MergeError::Storage)?
            else {
                return Err(MergeError::Pending(format!(
                    "lane {lane} block {lane_height} is not in the local store"
                )));
            };
            if lane_height == merge.to
                && (block.block_hash.0 != merge.tip_hash || block.result.0 != merge.tip_result)
            {
                return Err(invalid(lane, "the tip is not the lane's committed block"));
            }
            let stale = block
                .batch
                .as_ref()
                .is_none_or(|batch| record.is_stale(batch.anchor_height, height));
            blocks.push((lane, stale, block));
        }
    }
    Ok(blocks)
}

/// The per-transaction checks a block applies (`ValidBlock` static validation): a merged
/// transaction failing one is dropped instead of invalidating the global block.
struct Admissibility {
    network: iroha_data_model::NetworkId,
    max_clock_drift: Duration,
    limits: iroha_data_model::parameter::TransactionParameters,
    crypto: std::sync::Arc<iroha_config::parameters::actual::Crypto>,
}

impl Admissibility {
    fn of(view: &impl StateReadOnly) -> Self {
        let parameters = view.world().parameters();
        Self {
            network: *view.network_id(),
            max_clock_drift: parameters.sumeragi().max_clock_drift(),
            limits: parameters.transaction(),
            crypto: view.crypto(),
        }
    }

    fn admits(&self, tx: &TransactionEntrypoint, block: &SignedBlock) -> bool {
        let now = block.header().creation_time();
        tx.creation_time_ms()
            .is_none_or(|created| Duration::from_millis(created) < now)
            && AcceptedTransaction::accept_borrowed_entrypoint_at_time(
                tx,
                &self.network,
                self.max_clock_drift,
                self.limits,
                &self.crypto,
                now,
                false,
            )
            .is_ok()
            && match tx {
                TransactionEntrypoint::SealedCommitment(commitment) => {
                    commitment.payload().reveal_after_height > block.header().height().get()
                }
                TransactionEntrypoint::External(_) | TransactionEntrypoint::SealedReveal(_) => true,
            }
    }
}

#[cfg(test)]
#[path = "merge_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::with_original_lane_merge_fixture;

#[cfg(test)]
#[path = "merge_storage_tests.rs"]
mod storage_tests;
