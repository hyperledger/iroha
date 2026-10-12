//! SCCP block lifecycle and original fixed finality header (§4.2, §4.5, §4.6).
//!
//! Block start fixes the liability clock before governance and transactions. The original
//! output finalizer commits dense leaves, plans authenticated generations, appends the
//! parent native anchor, prunes light clients, clears destinations and returns inline X.
//! No clock, transport artifact, extra block or mutable committee read creates authority.

use super::{
    anchor_record::{AnchorRecordError, RetainedSccpAnchors},
    commitment,
    generations::{self, GenerationError},
    height::SccpHeightInputsV1,
    light_clients, params, store,
};
use crate::{
    block::BlockValidationError,
    state::{StateBlock, StateReadOnly, StateStorageAdmissionError, StateTransaction},
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};
use iroha_data_model::{
    block::BlockHeader,
    sccp::{
        events::{SccpEvent, SccpFinalityDegradedReasonV1, SccpFinalityDegradedV1},
        generation::{
            SCCP_ANCHOR_CHUNK_SIZE_V1, SccpAnchorV1, anchor_chunk_root_v1, next_liability_clock_v1,
        },
    },
    sumeragi_finality::certified_result::{
        FLAG_ACTIVE, FLAG_ROTATION, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1,
    },
};
use iroha_sccp::v1::history::HistoryAccumulatorV1;
use ivm::error::ExecutionDeferral;

/// Maximum light-client records deleted in one block (§4.11, §4.13.1).
pub const MAX_PRUNE_DELETIONS_PER_BLOCK: usize = 1_024;

/// Fix the liability clock before any instruction observes this block (§4.8 S0).
/// A missing parent never advances liability. The post-execution step will emit inactive X.
///
/// # Errors
/// Preserves only the original local storage refusal; arithmetic never invalidates a block.
pub fn begin_block(state_block: &mut StateBlock<'_>) -> Result<(), StateStorageAdmissionError> {
    let Some(parameters) = store::parameters::get(&state_block.world).as_ref() else {
        return Ok(());
    };
    let header = state_block._curr_block;
    let time = generations::timestamp_ms(&header);
    let old = *store::liability_clock::get(&state_block.world);
    let next = if header.is_genesis() {
        time
    } else {
        state_block
            .native_execution_tip()
            .filter(|parent| parent.height().checked_add(1) == Some(header.height().get()))
            .map_or(old.min(time), |parent| {
                if cfg!(all(test, sumeragi_core_mutation = "HC229")) {
                    old.saturating_add(time.saturating_sub(parent.creation_time_ms()))
                        .min(time)
                } else {
                    next_liability_clock_v1(
                        old,
                        parent.creation_time_ms(),
                        time,
                        parameters.committee_heartbeat_ms,
                    )
                    .min(time)
                }
            })
    };
    let mut stx = state_block.try_transaction()?;
    store::liability_clock::set(&mut stx, next);
    stx.apply();
    Ok(())
}

struct AnchorPlan {
    open: RetainedSccpAnchors,
    completed: Option<(u64, [u8; 32])>,
}
struct AnchorDraft<'a> {
    original: &'a RetainedSccpAnchors,
    anchor: SccpAnchorV1,
    chunk: u64,
}
fn anchor_error(error: AnchorRecordError) -> GenerationError {
    match error {
        AnchorRecordError::Invalid(_) => {
            GenerationError::Degraded(SccpFinalityDegradedReasonV1::InvalidGeneration)
        }
        AnchorRecordError::Admission(original) => GenerationError::Deferred(original.into()),
        AnchorRecordError::Allocator { .. } => {
            GenerationError::Deferred(ExecutionDeferral::AllocationUnavailable.into())
        }
    }
}
impl AnchorDraft<'_> {
    fn demand(&self, budget: &AllocationBudget) -> Result<usize, GenerationError> {
        self.original.append_demand(budget).map_err(anchor_error)
    }
    fn materialize(
        self,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<AnchorPlan, GenerationError> {
        let next = self
            .original
            .try_appended_prepaid(self.anchor, budget, reservation)
            .map_err(anchor_error)?;
        if next.as_slice().len() == SCCP_ANCHOR_CHUNK_SIZE_V1 {
            let root = anchor_chunk_root_v1(self.chunk, next.as_slice()).ok_or(
                GenerationError::Degraded(SccpFinalityDegradedReasonV1::InvalidGeneration),
            )?;
            Ok(AnchorPlan {
                open: RetainedSccpAnchors::default(),
                completed: Some((self.chunk, root)),
            })
        } else {
            Ok(AnchorPlan {
                open: next,
                completed: None,
            })
        }
    }
}
fn prepare_anchor<'a>(
    stx: &'a StateTransaction<'_, '_>,
    header: &BlockHeader,
) -> Result<Option<AnchorDraft<'a>>, GenerationError> {
    if header.is_genesis() || cfg!(all(test, sumeragi_core_mutation = "HC228")) {
        return Ok(None);
    }
    let parent = stx
        .native_execution_tip()
        .filter(|parent| parent.height().checked_add(1) == Some(header.height().get()))
        .ok_or(GenerationError::Degraded(
            SccpFinalityDegradedReasonV1::MissingParent,
        ))?;
    let original = store::anchor_open::get(&*stx.world);
    let position = usize::try_from((parent.height() - 1) % SCCP_ANCHOR_CHUNK_SIZE_V1 as u64)
        .expect("position below 4096");
    let chunk = (parent.height() - 1) / SCCP_ANCHOR_CHUNK_SIZE_V1 as u64;
    if original.as_slice().len() != position
        || (position + 1 == SCCP_ANCHOR_CHUNK_SIZE_V1
            && store::anchor_chunks::contains(&*stx.world, &chunk))
    {
        return Err(GenerationError::Degraded(
            SccpFinalityDegradedReasonV1::InvalidGeneration,
        ));
    }
    Ok(Some(AnchorDraft {
        original,
        chunk,
        anchor: SccpAnchorV1 {
            core_hash: parent.core_hash().0,
            result: parent.result().0,
        },
    }))
}

fn local_or_degraded<T>(
    result: Result<T, GenerationError>,
    failure: &mut Option<SccpFinalityDegradedReasonV1>,
) -> Result<Option<T>, BlockValidationError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(GenerationError::Degraded(reason)) => {
            *failure = Some(reason);
            Ok(None)
        }
        Err(GenerationError::Deferred(original)) => {
            Err(BlockValidationError::ExecutionDeferred(original))
        }
    }
}

fn degrade(stx: &mut StateTransaction<'_, '_>, height: u64, reason: SccpFinalityDegradedReasonV1) {
    let run = store::degraded_run::get(&*stx.world).saturating_add(1);
    store::degraded_run::set(stx, run);
    stx.world
        .emit_events(Some(SccpEvent::FinalityDegraded(SccpFinalityDegradedV1 {
            height,
            reason,
        })));
}

/// Finish one original execution and return the exact fixed header retained by its seal.
/// `height_inputs` are provided only by the original authenticated Global schedule; a
/// missing, non-Global or inconsistent source yields inactive X, never replacement authority.
///
/// # Errors
/// Dense-leaf violations retain their execution-invariant error. Storage and allocation
/// refusal retain their original retry owner. Generation/anchor inconsistency only degrades.
pub fn finalize_block(
    state_block: &mut StateBlock<'_>,
    header: &BlockHeader,
    height_inputs: Option<&SccpHeightInputsV1<'_>>,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
) -> Result<SccpFinalityHeaderV1, BlockValidationError> {
    let height = header.height().get();
    let time = generations::timestamp_ms(header);
    let inactive =
        SccpFinalityHeaderV1::inactive(*state_block.network_id().as_bytes(), height, time)
            .expect("BlockHeader height is nonzero");
    if root_scope != iroha_data_model::block::consensus::SumeragiRootScope::Global
        || !params::exists(&state_block.world)
    {
        return Ok(inactive);
    }
    #[cfg(test)]
    observed::record(header, height_inputs);
    let mut stx = state_block
        .try_transaction()
        .map_err(BlockValidationError::StateStorageAdmission)?;
    commitment::commit_block(&mut stx, height)?;
    let budget = stx.execution_budget();
    let mut failure = None;
    let mut draft = local_or_degraded(
        generations::draft(&stx, header, height_inputs),
        &mut failure,
    )?;
    // A1 is independent of G4 and still runs when inputs are missing or degraded.
    let anchor = local_or_degraded(prepare_anchor(&stx, header), &mut failure)?.flatten();
    if failure.is_some() {
        draft = None;
    }
    let generation_demand = draft.as_ref().map_or(Ok(0), |draft| draft.demand());
    let mut generation_demand = local_or_degraded(generation_demand, &mut failure)?.unwrap_or(0);
    if failure.is_some() {
        draft = None;
    }
    let anchor_demand = anchor.as_ref().map_or(Ok(0), |draft| draft.demand(&budget));
    let anchor_demand = local_or_degraded(anchor_demand, &mut failure)?;
    let anchor = if anchor_demand.is_some() {
        anchor
    } else {
        None
    };
    if failure.is_some() {
        draft = None;
        generation_demand = 0;
    }
    // One original admission for the complete reachable payload graph. No partial prefix
    // exists when Capacity captures its release source, so refusal cannot wake on our cleanup.
    let total = generation_demand
        .checked_add(anchor_demand.unwrap_or(0))
        .ok_or_else(|| {
            BlockValidationError::ExecutionDeferred(AllocationRefusal::DemandOverflow.into())
        })?;
    let mut reservation = budget
        .try_reserve_bytes(total)
        .map_err(|original| BlockValidationError::ExecutionDeferred(original.into()))?;
    let plan = draft
        .map(|draft| draft.materialize(&budget, &mut reservation))
        .transpose();
    let plan = local_or_degraded(plan, &mut failure)?.flatten();
    let anchor = anchor
        .map(|draft| draft.materialize(&budget, &mut reservation))
        .transpose();
    let anchor = local_or_degraded(anchor, &mut failure)?.flatten();
    let header = if failure.is_none() {
        let plan = plan.expect("successful original generation plan");
        let commitment = store::block_commitments::get(&*stx.world, &height);
        let history = store::history::get(&*stx.world);
        let active = HistoryAccumulatorV1::root_from_parts(history.size, &history.peaks)
            .ok()
            .and_then(|history_root| {
                SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
                    network_id: *stx.network_id().as_bytes(),
                    height,
                    timestamp_ms: time,
                    flags: FLAG_ACTIVE
                        | if plan.validity_ms != 0 {
                            FLAG_ROTATION
                        } else {
                            0
                        },
                    message_count: commitment.map_or(0, |record| record.message_count),
                    sccp_root: commitment.map_or([0; 32], |record| record.root),
                    history_size: history.size,
                    history_root,
                    generation: if cfg!(all(test, sumeragi_core_mutation = "HC226"))
                        && plan.validity_ms != 0
                    {
                        plan.generation.saturating_add(1)
                    } else {
                        plan.generation
                    },
                    committee_root: plan.committee_root,
                    validity_ms: plan.validity_ms,
                    next_committee_root: plan.next_committee_root,
                })
                .ok()
            });
        if let Some(active) = active {
            plan.publish(&mut stx)
                .map_err(BlockValidationError::StateStorageAdmission)?;
            active
        } else {
            failure = Some(SccpFinalityDegradedReasonV1::InvalidGeneration);
            inactive
        }
    } else {
        inactive
    };
    if let Some(anchor) = anchor {
        if let Some((chunk, root)) = anchor.completed {
            stx.world
                .sccp_anchor_chunks
                .try_insert_admitted(chunk, root)
                .map_err(|(_, error)| BlockValidationError::StateStorageAdmission(error.into()))?;
        }
        store::anchor_open::set(&mut stx, anchor.open);
    }
    if let Some(reason) = failure {
        degrade(&mut stx, height, reason);
    }
    light_clients::prune(&mut stx, MAX_PRUNE_DELETIONS_PER_BLOCK);
    // TODO: WP-S6: generation/anchor-root retirement requires the real Pending SCCP forgery
    // State and instruction owner. Never replace that missing authority with an empty set.
    generations::clear_destinations(&mut stx)
        .map_err(BlockValidationError::StateStorageAdmission)?;
    stx.apply();
    Ok(header)
}

/// Test observation of the inputs [`finalize_block`] received on this thread or for one
/// exact proposal executed by a native worker.
#[cfg(test)]
pub(crate) mod observed {
    use super::{BlockHeader, SccpHeightInputsV1};
    use iroha_crypto::HashOf;
    use parking_lot::Mutex;
    use std::{cell::RefCell, collections::BTreeMap, sync::LazyLock};

    /// Test-only owned value snapshot; production custody never depends on observation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct HeightInputsSnapshot {
        /// Observed mode.
        pub(crate) mode: iroha_data_model::parameter::system::ConsensusMode,
        /// Observed executing height.
        pub(crate) height: u64,
        /// Observed epoch.
        pub(crate) epoch: u64,
        /// Observed boundary height.
        pub(crate) epoch_end_height: u64,
        /// Value snapshot of the original current roster.
        pub(crate) roster: Vec<iroha_model_base::peer::PeerId>,
        /// Value snapshot of the original successor roster, when present.
        pub(crate) next_roster: Option<Vec<iroha_model_base::peer::PeerId>>,
    }

    impl From<&SccpHeightInputsV1<'_>> for HeightInputsSnapshot {
        fn from(inputs: &SccpHeightInputsV1<'_>) -> Self {
            Self {
                mode: inputs.mode,
                height: inputs.height,
                epoch: inputs.epoch,
                epoch_end_height: inputs.epoch_end_height,
                roster: inputs.roster.iter().cloned().collect(),
                next_roster: inputs
                    .next_roster
                    .as_ref()
                    .map(|roster| roster.iter().cloned().collect()),
            }
        }
    }

    type Calls = Vec<(u64, Option<HeightInputsSnapshot>)>;

    static HEADERS: LazyLock<Mutex<BTreeMap<HashOf<BlockHeader>, Calls>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    std::thread_local! {
        static CALLS: RefCell<Calls> =
            const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(header: &BlockHeader, inputs: Option<&SccpHeightInputsV1<'_>>) {
        CALLS.with(|calls| {
            calls.borrow_mut().push((
                header.height().get(),
                inputs.map(HeightInputsSnapshot::from),
            ));
        });
        if let Some(calls) = HEADERS.lock().get_mut(&header.hash()) {
            calls.push((
                header.height().get(),
                inputs.map(HeightInputsSnapshot::from),
            ));
        }
    }

    /// Retain observations for one exact original proposal across execution threads.
    pub(crate) struct HeaderCalls {
        header: HashOf<BlockHeader>,
    }

    impl HeaderCalls {
        /// Take only calls matching the proposal selected when this observer was created.
        pub(crate) fn take(&self) -> Calls {
            core::mem::take(
                HEADERS
                    .lock()
                    .get_mut(&self.header)
                    .expect("original observer"),
            )
        }
    }

    impl Drop for HeaderCalls {
        fn drop(&mut self) {
            HEADERS.lock().remove(&self.header);
        }
    }

    /// Observe a proposal until the returned guard is dropped, including on unwind.
    pub(crate) fn for_header(header: &BlockHeader) -> HeaderCalls {
        let header = header.hash();
        let mut headers = HEADERS.lock();
        let std::collections::btree_map::Entry::Vacant(entry) = headers.entry(header) else {
            panic!("proposal already has an SCCP observer");
        };
        entry.insert(Vec::new());
        HeaderCalls { header }
    }

    /// Take the `(height, inputs)` of every SCCP finalizer call on this thread so far.
    pub(crate) fn take() -> Calls {
        CALLS.with(|calls| core::mem::take(&mut *calls.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::{
        leaves, store,
        test_support::{authority, blank_state, header, peer},
    };
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::{
            control::{SccpLeafRefV1, SccpTransferLeafRefV1},
            light_client::{
                SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcHeadV1,
                SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
            },
            outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
            params::SccpParametersV1,
        },
    };

    #[test]
    fn proposal_observer_is_scoped_across_threads_and_releases_on_unwind() {
        let original = header(9_031);
        let foreign = header(9_032);
        let calls = observed::for_header(&original);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                observed::record(&foreign, None);
                observed::record(&original, None);
            });
        });
        assert_eq!(calls.take(), vec![(9_031, None)]);
        assert!(calls.take().is_empty());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _calls = calls;
                panic!("exercise scoped observer retirement");
            }))
            .is_err()
        );
        observed::record(&original, None);
        assert!(observed::for_header(&original).take().is_empty());
        let _ = observed::take();
    }

    #[test]
    fn the_hook_is_a_no_op_without_sccp() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        let _ = observed::take();
        finalize_block(
            &mut block,
            &candidate,
            None,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .expect("no-op finalizer");
        assert!(
            observed::take().is_empty(),
            "the finalizer returns before reading inputs without SCCP"
        );
        assert!(store::block_commitments::is_empty(&block.world));
        assert!(block.world.sccp_execution_write_set_bytes().is_empty());
    }

    #[test]
    fn finalize_block_commits_leaves_and_history_only() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        let message_id = [7; 32];
        {
            let mut stx = block.transaction();
            store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
            let commitment_index = leaves::allocate_leaf(
                &mut stx,
                SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 { message_id }),
            )
            .expect("leaf");
            store::outbound_messages::insert(
                &mut stx,
                message_id,
                SccpOutboundMessageRecordV1 {
                    network: SccpNetworkV1::EthereumMainnet,
                    revision: 1,
                    nonce: 0,
                    height: 2,
                    commitment_index,
                    deadline_ms: 99,
                    sender: authority(1),
                    amount: 1,
                    payload: vec![7],
                    leaf: [8; 32],
                    status: SccpOutboundStatusV1::Recorded,
                },
            )
            .expect("record");
            stx.apply();
        }
        let _ = observed::take();
        let roster = (1..=4).map(peer).collect::<Vec<_>>();
        let inputs = SccpHeightInputsV1 {
            mode: iroha_data_model::parameter::system::ConsensusMode::Npos,
            height: 2,
            epoch: 0,
            epoch_end_height: 2,
            roster: crate::smartcontracts::isi::sccp::height::SccpRosterV1::from_peers(&roster)
                .unwrap(),
            next_roster: Some(
                crate::smartcontracts::isi::sccp::height::SccpRosterV1::from_peers(&roster)
                    .unwrap(),
            ),
        };
        finalize_block(
            &mut block,
            &candidate,
            Some(&inputs),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .expect("hook");
        assert_eq!(
            observed::take(),
            vec![(2, Some(observed::HeightInputsSnapshot::from(&inputs)))]
        );
        let commitment = store::block_commitments::get(&block.world, &2).expect("commitment");
        assert_eq!((commitment.message_count, commitment.history_index), (1, 0));
        assert_eq!(store::history::get(&block.world).size, 1);
        assert_eq!(store::history_leaves::len(&block.world), 1);
    }

    #[test]
    fn the_hook_prunes_expired_light_client_checkpoints() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        let network = SccpNetworkV1::EthereumMainnet;
        {
            let mut stx = block.transaction();
            store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
            let mut params = SccpLightClientParamsV1::defaults_for(network).expect("external");
            params.checkpoint_prune_after_ms = 1;
            let light_client = SccpLightClientV1 {
                params,
                head: SccpLcHeadV1 {
                    latest_set_id: 2,
                    latest_finalized: SccpLcPointV1 {
                        source_height: 200,
                        block_hash: [7; 32],
                        source_time_ms: 1,
                    },
                    last_progress_taira_ms: 1,
                },
                frozen: None,
                state_hash: [8; 32],
            };
            store::light_clients::insert(&mut stx, network, light_client).expect("light client");
            for source_height in [120, 150] {
                light_clients::record_checkpoint(
                    &mut stx,
                    network,
                    SccpLcCheckpointV1 {
                        data: SccpLcCheckpointDataV1 {
                            source_height,
                            block_hash: [1; 32],
                            state_root: Some([2; 32]),
                            receipts_or_tx_root: [3; 32],
                            source_time_ms: source_height,
                        },
                        recorded_at_taira_ms: 0,
                        origin: SccpLcCheckpointOriginV1::Advance,
                    },
                )
                .expect("checkpoint");
            }
            stx.apply();
        }
        // Block 2 runs at 8 000 ms, past the retention of checkpoints recorded at 0. The
        // lowest checkpoint of a stride bucket is permanent; the other one is pruned.
        finalize_block(
            &mut block,
            &candidate,
            None,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .expect("hook");
        let _ = observed::take();
        assert!(store::light_client_checkpoints::contains(
            &block.world,
            &(network, 120)
        ));
        assert!(!store::light_client_checkpoints::contains(
            &block.world,
            &(network, 150)
        ));
    }

    #[test]
    fn begin_block_clamps_halt_time_using_original_native_parent() {
        use crate::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let parameters = SccpParametersV1::taira_default();
        chain.setup_world_at(2_000, |stx| {
            store::parameters::set(stx, Some(parameters.clone()));
            store::liability_clock::set(stx, 1_000);
        });
        let time = 10 * parameters.committee_validity_ms;
        let candidate =
            BlockHeader::new(std::num::NonZeroU64::new(2).unwrap(), None, None, time, 0);
        let mut block = chain.state().block(candidate);
        // State's production start seam already ran S0; re-entering with this same parent
        // is not an authorized operation, so inspect its fixed result without calling twice.
        let expected = 1_000
            + parameters.committee_heartbeat_ms
            + iroha_data_model::sccp::generation::SCCP_LC_SLACK_MS_V1;
        assert_eq!(*store::liability_clock::get(&block.world), expected);
        let stx = block.transaction();
        assert_eq!(*store::liability_clock::get(&*stx.world), expected);
        assert!(
            expected < time,
            "a chain halt cannot consume the full liability window"
        );
    }

    #[test]
    fn degraded_block_without_leaves_keeps_history_and_records_failure() {
        let state = blank_state();
        let candidate = header(3);
        let mut block = state.block(candidate);
        {
            let mut stx = block.transaction();
            store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
            stx.apply();
        }
        let before = block.world.sccp_execution_write_set_bytes();
        let _ = observed::take();
        finalize_block(
            &mut block,
            &candidate,
            None,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .expect("no leaves");
        assert_ne!(block.world.sccp_execution_write_set_bytes(), before);
        assert_eq!(*store::degraded_run::get(&block.world), 1);
        assert_eq!(store::history::get(&block.world).size, 0);
        assert!(store::block_commitments::is_empty(&block.world));
        assert_eq!(observed::take(), vec![(3, None)]);
    }
    fn native_init_config(
        scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> crate::sumeragi::test_chain::TestChainConfig {
        use crate::{state::World, sumeragi::test_chain::TestChainConfig};
        use iroha_data_model::parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiNposParameters},
        };
        let mut config = TestChainConfig::new(World::new(), 1_000);
        config.root_scope = scope;
        // Only Global NPoS genesis carries the election parameters. A genuine private
        // root must pass permissioned genesis normalization before SCCP admission is tested.
        if scope == iroha_data_model::block::consensus::SumeragiRootScope::Global {
            config.consensus_mode = SumeragiConsensusMode::Npos;
            config.genesis_parameters.push(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ));
        }
        config.genesis_block_cadence_ms = std::num::NonZeroU64::new(1_000).unwrap();
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.staking.unbonding_delay =
            std::time::Duration::from_millis(super::super::test_support::SCCP_UNBONDING_DELAY_MS);
        nexus.staking.max_slash_bps = 10_000;
        if let iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
            dataspace_id,
            ..
        } = scope
        {
            use iroha_data_model::{
                asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
                block::consensus::PrivateRootFeePolicy,
                domain::Domain,
                isi::Register,
                nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
            };
            // The negative SCCP control must pass the real private-root prerequisites first.
            // Its fee policy and monetary namespace are signed into the same genesis.
            let domain =
                iroha_model_base::domain::DomainId::try_new("sccp", "sccp-private").unwrap();
            let asset =
                AssetDefinitionId::derive_from_components(domain.clone(), "fee".parse().unwrap());
            nexus.fees.fee_asset_id = asset.canonical_address();
            nexus.lane_catalog = LaneCatalog::new(
                1_u32.try_into().unwrap(),
                vec![LaneConfig {
                    dataspace_id,
                    alias: "sccp-private".into(),
                    ..LaneConfig::default()
                }],
            )
            .unwrap();
            nexus.configured_lane_catalog = nexus.lane_catalog.clone();
            nexus.lane_config =
                iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
            nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
                id: dataspace_id,
                alias: "sccp-private".into(),
                description: None,
                fault_tolerance: 1,
            }])
            .unwrap();
            nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
            nexus.routing_policy.default_dataspace = dataspace_id;
            config.genesis_parameters.push(Parameter::Custom(
                PrivateRootFeePolicy {
                    asset_definition_id: asset.clone(),
                    base_fee: 1_u32.into(),
                    per_byte_fee: 0_u32.into(),
                    per_instruction_fee: 1_u32.into(),
                    per_gas_unit_fee: 1_u32.into(),
                }
                .into_custom_parameter()
                .unwrap(),
            ));
            config.genesis_instructions.extend([
                Register::domain(Domain::new(domain.clone())).into(),
                Register::asset_definition(AssetDefinition::numeric(
                    asset,
                    "SCCP private fee",
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(domain),
                ))
                .into(),
            ]);
        }
        config.nexus = Some(nexus);
        config
            .genesis_instructions
            .push(super::super::test_support::SampleInstructions::initialize().into());
        config
    }

    #[test]
    fn genuine_global_genesis_installs_original_generation_and_sealed_active_header() {
        use crate::sumeragi::test_chain::CertifiedTestChain;
        use iroha_data_model::block::consensus::SumeragiRootScope;
        let chain = CertifiedTestChain::start(native_init_config(SumeragiRootScope::Global))
            .expect("genuine Global genesis");
        let view = chain.state().view();
        let generation = store::committee_generations::get(view.world(), &1).expect("original G1");
        assert_eq!(
            generation.cause,
            iroha_data_model::sccp::generation::SccpGenerationCauseV1::Genesis
        );
        assert_eq!(generation.start_height, 1);
        let genesis_time = chain.genesis().header().creation_time_ms;
        assert_eq!(generation.start_timestamp_ms, genesis_time);
        assert_eq!(generation.start_lc, genesis_time);
        assert_eq!(*store::committee_current::get(view.world()), 1);
        assert_eq!(*store::degraded_run::get(view.world()), 0);
        let committed = chain.committed(1);
        let x = committed.certified_result().header();
        assert!(x.is_active());
        assert!(!x.is_rotation());
        assert_eq!(x.generation(), 1);
        assert_eq!(x.committee_root(), generation.committee_root);
        let signed = iroha_data_model::sumeragi_finality::authenticated_genesis(chain.genesis())
            .unwrap()
            .into_parts()
            .0;
        for (key, member) in generation.keys.iter().zip(&signed.committee) {
            assert_eq!(
                key.as_slice(),
                member.validator.public_key().try_to_bytes().unwrap().1
            );
        }
        assert!(store::anchor_open::get(view.world()).as_slice().is_empty());
    }

    #[test]
    fn native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor() {
        use crate::sumeragi::test_chain::CertifiedTestChain;
        use iroha_data_model::{
            block::consensus::SumeragiRootScope, sccp::generation::SccpGenerationCauseV1,
        };
        let mut chain =
            CertifiedTestChain::start(native_init_config(SumeragiRootScope::Global)).unwrap();
        let time = chain.genesis().header().creation_time_ms
            + SccpParametersV1::taira_default().committee_heartbeat_ms;
        // The fixture inserts genuine signed Log work at the requested time. The production
        // assembler, native Worker, output seal, QC and persistence execute the real height;
        // neither an empty block nor a synthetic boundary grants the rotation authority.
        chain.commit_at(time, Vec::new());
        let committed = chain.committed(2);
        assert!(committed.block().network_entrypoint_count() > 0);
        assert_eq!(committed.block().header().creation_time_ms, time);
        let header = committed.certified_result().header();
        assert!(header.is_active());
        assert!(header.is_rotation());
        assert_eq!(
            header.generation(),
            1,
            "X certifies the outgoing generation"
        );
        {
            let view = chain.state().view();
            let old = store::committee_generations::get(view.world(), &1).unwrap();
            let next = store::committee_generations::get(view.world(), &2).unwrap();
            assert_eq!(*store::committee_current::get(view.world()), 2);
            assert_eq!(header.committee_root(), old.committee_root);
            assert_eq!(header.next_committee_root(), next.committee_root);
            assert_eq!(header.validity_ms(), next.validity_ms);
            assert_eq!(next.cause, SccpGenerationCauseV1::Heartbeat);
            assert_eq!((next.start_height, next.start_timestamp_ms), (3, time));
            let end = old.end.unwrap();
            assert_eq!((end.end_height, end.end_timestamp_ms), (2, time));
            assert_eq!(end.next_committee_root, next.committee_root);
            assert_eq!(store::anchor_open::get(view.world()).as_slice().len(), 1);
        }
        assert_native_certificate_projection(&chain, 2, 1, true);
        chain.commit_at(time + 1_000, Vec::new());
        let committed = chain.committed(3);
        assert!(committed.block().network_entrypoint_count() > 0);
        let header = committed.certified_result().header();
        assert!(header.is_active());
        assert!(!header.is_rotation());
        assert_eq!(header.generation(), 2, "only the successor height uses G2");
        assert_eq!(
            *store::committee_current::get(chain.state().view().world()),
            2
        );
        assert_native_certificate_projection(&chain, 3, 2, false);
    }

    fn assert_native_certificate_projection(
        chain: &crate::sumeragi::test_chain::CertifiedTestChain,
        height: u64,
        generation: u64,
        rotation: bool,
    ) {
        let view = chain.state().view();
        let reader = crate::sumeragi::certified_chain::CertifiedChain::new(&view).unwrap();
        let original = reader.certified(height).unwrap();
        let budget = chain.state().ivm_execution_budget();
        let occupied = budget.reserved_bytes();
        let stop = std::sync::atomic::AtomicBool::new(false);
        let retained = super::super::read::native::finality(
            &view,
            std::num::NonZeroU64::new(height),
            &budget,
            super::super::read::native::SccpNativeReadControl {
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
                stop: &stop,
            },
        )
        .unwrap();
        let certificate = retained.data();
        assert_eq!(
            &certificate.header,
            original.certified_result().header().as_bytes()
        );
        let verified = iroha_sccp::v1::finality::verify_certificate(
            &original.commit_qc().unwrap().instance.0,
            &certificate.qc,
            &certificate.header,
            &certificate.aggregate_signature,
            &certificate.committee,
        )
        .unwrap();
        assert_eq!(verified.result, original.result().0);
        assert_eq!(verified.header.generation(), generation);
        assert_eq!(verified.header.is_rotation(), rotation);
        assert_eq!(
            certificate.committee.as_slice(),
            store::committee_generations::get(view.world(), &generation)
                .unwrap()
                .keys
                .as_slice()
        );
        assert_eq!(
            budget.reserved_bytes(),
            occupied
                + std::mem::size_of::<iroha_sccp::api::SccpCertificateV1>()
                + iroha_data_model::sumeragi::epoch::MAX_VALIDATORS * 48
        );
        drop(retained);
        assert_eq!(budget.reserved_bytes(), occupied);
    }

    #[test]
    fn genuine_dataspace_genesis_cannot_install_global_sccp_generation() {
        use crate::sumeragi::test_chain::CertifiedTestChain;
        use iroha_data_model::{
            block::consensus::SumeragiRootScope,
            sumeragi_finality::test_fixtures::NativeFinalityFixture,
        };
        let parent = NativeFinalityFixture::start("sccp-global-parent");
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: parent.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
        };
        let mut valid_private = native_init_config(scope);
        let init = valid_private.genesis_instructions.pop().unwrap();
        assert!(
            init.as_any()
                .is::<iroha_data_model::isi::sccp::InitializeSccpV1>()
        );
        let private = CertifiedTestChain::start(valid_private)
            .expect("the same signed private prerequisites succeed without global SCCP");
        assert_eq!(private.root_scope(), scope);
        assert!(!private.committed(1).certified_result().header().is_active());
        let failure = CertifiedTestChain::start(native_init_config(scope))
            .expect_err("private genesis has no Global original context");
        // Display deliberately summarizes validation. Inspect the retained native cause,
        // so neither another genesis rejection nor a diagnostic string can satisfy this test.
        let crate::sumeragi::test_chain::TestChainError::OriginalGenesisExecution(error) =
            &failure.error
        else {
            panic!(
                "expected original native genesis rejection: {:?}",
                failure.error
            );
        };
        let crate::block::BlockValidationError::InvalidGenesis(
            crate::block::InvalidGenesisError::RejectedOutput(rejection),
        ) = error.as_ref()
        else {
            panic!("expected the original rejected output: {error:?}");
        };
        let iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::executor::ValidationFail::NotPermitted(reason),
        ) = rejection.reason.as_ref()
        else {
            panic!("expected original SCCP physical-route refusal: {rejection:?}");
        };
        // The instruction belongs to the Global dataspace. Its authenticated routing
        // refusal precedes the instruction executor and must remain the retained cause.
        assert_eq!(
            reason.as_str(),
            "physical policy dataspace differs from authenticated native source"
        );
        let view = failure.state.view();
        assert!(store::parameters::get(view.world()).is_none());
        assert!(store::committee_generations::is_empty(view.world()));
        assert_eq!(*store::committee_current::get(view.world()), 0);
        assert!(view.native_execution_tip().is_none());
    }

    #[test]
    fn degraded_hook_still_appends_original_parent_anchor_and_recovers_without_rotation() {
        use crate::sumeragi::test_chain::CertifiedTestChain;
        use iroha_data_model::{
            block::consensus::SumeragiRootScope, parameter::system::ConsensusMode,
        };
        let chain =
            CertifiedTestChain::start(native_init_config(SumeragiRootScope::Global)).unwrap();
        let parent = chain.state().view().native_execution_tip().unwrap();
        let candidate =
            BlockHeader::new(std::num::NonZeroU64::new(2).unwrap(), None, None, 2_000, 0);
        let mut block = chain.state().block(candidate);
        let inactive = finalize_block(
            &mut block,
            &candidate,
            None,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .unwrap();
        assert!(!inactive.is_active());
        assert_eq!(*store::degraded_run::get(&block.world), 1);
        assert_eq!(*store::committee_current::get(&block.world), 1);
        assert_eq!(
            store::anchor_open::get(&block.world).as_slice(),
            &[SccpAnchorV1 {
                core_hash: parent.core_hash().0,
                result: parent.result().0
            }]
        );
        drop(block);
        // A fresh original attempt, not a second append in one execution, authenticates h2.
        let mut recovered = chain.state().block(candidate);
        let epoch = iroha_data_model::sumeragi_finality::authenticated_genesis(chain.genesis())
            .unwrap()
            .into_parts()
            .0;
        let inputs = SccpHeightInputsV1 {
            mode: ConsensusMode::Npos,
            height: 2,
            epoch: 0,
            epoch_end_height: epoch.authorization.last_height,
            roster: crate::smartcontracts::isi::sccp::height::SccpRosterV1::from_peers(
                epoch.committee.iter().map(|member| &member.validator),
            )
            .unwrap(),
            next_roster: None,
        };
        let active = finalize_block(
            &mut recovered,
            &candidate,
            Some(&inputs),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .unwrap();
        assert!(active.is_active());
        assert!(!active.is_rotation());
        assert_eq!(active.generation(), 1);
        assert_eq!(*store::degraded_run::get(&recovered.world), 0);
        assert_eq!(
            store::anchor_open::get(&recovered.world).as_slice().len(),
            1
        );
    }
    #[test]
    fn retained_height_owner_survives_native_hook_capacity_refusal_and_success() {
        use crate::{
            smartcontracts::isi::sccp::height::RetainedSccpHeightInputsV1,
            state::WorldReadOnly as _, sumeragi::test_chain::CertifiedTestChain,
        };
        use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
        use iroha_data_model::{
            block::consensus::SumeragiRootScope, parameter::system::ConsensusMode,
        };
        use std::task::{Context, Poll, Waker};
        let chain =
            CertifiedTestChain::start(native_init_config(SumeragiRootScope::Global)).unwrap();
        let view = chain.state().view();
        let budget = chain.state().ivm_execution_budget();
        let occupied = budget.reserved_bytes();
        let original_generation = chain.state().state_view_generation();
        let original_peer = std::ptr::from_ref(
            &view
                .world()
                .consensus_schedule()
                .ready(2)
                .unwrap()
                .epoch
                .committee[0]
                .validator,
        );
        let captured = RetainedSccpHeightInputsV1::from_sumeragi_schedule(
            view.world(),
            2,
            1,
            ConsensusMode::Npos,
        )
        .unwrap();
        assert_eq!(budget.reserved_bytes(), occupied);
        drop(view);
        let candidate =
            BlockHeader::new(std::num::NonZeroU64::new(2).unwrap(), None, None, 2_000, 0);
        let mut block = chain.state().block(candidate);
        let inputs = captured.inputs().unwrap();
        assert_eq!(
            std::ptr::from_ref(inputs.roster.iter().next().unwrap()),
            original_peer
        );
        let before = block.world.sccp_execution_write_set_bytes();
        let mut reservation = budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut waiter = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
        drop(reservation);
        let external = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        let error = finalize_block(
            &mut block,
            &candidate,
            Some(&inputs),
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        )
        .expect_err("original transaction admission refuses");
        let BlockValidationError::ExecutionDeferred(deferred) = &error else {
            panic!("expected unfinished original execution: {error:?}")
        };
        assert_eq!(deferred.reason(), ExecutionDeferral::ActiveMemoryCapacity);
        let Some(AllocationRefusal::Capacity { release, .. }) = deferred.allocation_refusal()
        else {
            panic!("expected original pool capacity: {error:?}")
        };
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        assert_eq!(block.world.sccp_execution_write_set_bytes(), before);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Pending);
        assert_eq!(
            std::ptr::from_ref(inputs.roster.iter().next().unwrap()),
            original_peer
        );
        let released_bytes = external.remaining_bytes();
        let before_release = budget.reserved_bytes();
        drop(external);
        assert_eq!(budget.reserved_bytes(), before_release - released_bytes);
        assert_eq!(
            waiter.poll_wait(release, &mut cx),
            Poll::Pending,
            "same-thread refunds wait until every original State writer retires"
        );
        // Native validation drops an unsealed refused overlay before returning its
        // original proposal and release. Retry that same candidate only after the
        // writer boundary, retaining this exact captured schedule and its borrower.
        drop(block);
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Ready(()));
        assert_eq!(chain.state().state_view_generation(), original_generation);
        let mut block = chain.state().block(candidate);
        let active = finalize_block(
            &mut block,
            &candidate,
            Some(&inputs),
            SumeragiRootScope::Global,
        )
        .unwrap();
        assert!(active.is_active());
        assert!(!active.is_rotation());
        assert_eq!(active.generation(), 1);
        assert_eq!(
            active.committee_root(),
            store::committee_generations::get(&block.world, &1)
                .unwrap()
                .committee_root
        );
        assert_eq!(store::anchor_open::get(&block.world).as_slice().len(), 1);
        assert_eq!(*store::degraded_run::get(&block.world), 0);
        assert_eq!(
            std::ptr::from_ref(inputs.roster.iter().next().unwrap()),
            original_peer
        );
        waiter.cancel();
        drop(block);
        let expected = observed::HeightInputsSnapshot::from(&inputs);
        let _ = observed::take();
        assert_eq!(
            observed::HeightInputsSnapshot::from(&captured.inputs().unwrap()),
            expected
        );
    }
    #[test]
    fn authenticated_dataspace_genesis_cannot_lapse_global_pause_record() {
        use crate::sumeragi::test_chain::CertifiedTestChain;
        use iroha_data_model::{
            block::consensus::SumeragiRootScope,
            sumeragi_finality::test_fixtures::NativeFinalityFixture,
        };
        let parent = NativeFinalityFixture::start("pause-lapse-global-parent");
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: parent.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
        };
        let mut config = native_init_config(scope);
        let init = config.genesis_instructions.pop().unwrap();
        assert!(
            init.as_any()
                .is::<iroha_data_model::isi::sccp::InitializeSccpV1>()
        );
        let mut prepared = CertifiedTestChain::prepare(config).expect("original private genesis");
        let time = prepared.genesis.block().header().creation_time_ms;
        let state = std::sync::Arc::get_mut(&mut prepared.state).unwrap();
        let budget = state.ivm_execution_budget();
        // Intentionally foreign Global component prestate, never created by private authority.
        // Neither a present DTO nor its expired timestamp may authorize Global cleanup.
        state.world.sccp_parameters = mv::cell::Cell::new(Some(SccpParametersV1::taira_default()));
        let mut pause = super::super::test_support::sample_fast_pause(1);
        pause.enacted_at_ms = time.checked_sub(1).unwrap();
        pause.until_ms = time;
        let original =
            super::super::pause_record::RetainedSccpFastPause::admit(&pause, &budget).unwrap();
        let network = iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet;
        state
            .world
            .sccp_fast_pauses
            .insert(network, original.clone());
        let chain = CertifiedTestChain::from_prepared(prepared).expect("genuine private G1");
        assert_eq!(chain.root_scope(), scope);
        assert!(!chain.committed(1).certified_result().header().is_active());
        let view = chain.state().view();
        let retained = store::fast_pauses::get(view.world(), &network).unwrap();
        assert!(
            std::ptr::eq(&**retained, &*original),
            "authenticated Dataspace scope cannot authorize Global lapse"
        );
    }
}
