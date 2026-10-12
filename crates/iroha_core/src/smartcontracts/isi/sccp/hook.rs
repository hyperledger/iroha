//! SCCP post-execution commitments, native committee generations, anchors and finality X.
//!
//! The liability clock advances before governance and transactions. The finalizer retains
//! authenticated consensus inputs, appends only the parent's native anchor after execution,
//! and returns the exact fixed-size header belonging to this execution owner.

use super::{anchors, commitment, generation, height::SccpHeightInputsV1, params, prune, store};
use crate::{
    block::BlockValidationError,
    state::{StateBlock, StateReadOnly, StateStorageAdmissionError},
};
use iroha_data_model::{
    block::{BlockHeader, consensus::SumeragiRootScope},
    sumeragi_finality::certified_result::{
        FLAG_ACTIVE, FLAG_ROTATION, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1,
    },
};

/// Finalize this block's SCCP state and retain its exact X header (§4.5).
///
/// `root_scope` must come from the same original signed genesis or authenticated native
/// predecessor as the enclosing execution. A non-global root returns inactive X before any
/// SCCP effect. Missing authenticated inputs or inconsistent SCCP bookkeeping produce inactive X.
/// Commitment gaps remain execution invariant failures; local storage refusal is retryable.
///
/// # Errors
///
/// Propagates commitment invariants and local storage/allocation failures.
pub fn finalize_block(
    state_block: &mut StateBlock<'_>,
    header: &BlockHeader,
    height_inputs: Option<&SccpHeightInputsV1>,
    root_scope: SumeragiRootScope,
) -> Result<SccpFinalityHeaderV1, BlockValidationError> {
    let network_id = *state_block.network_id().as_bytes();
    let height = header.height().get();
    let inactive = SccpFinalityHeaderV1::inactive(network_id, height, header.creation_time_ms)
        .map_err(|_| {
            BlockValidationError::ExecutionDeferred(
                ivm::error::ExecutionDeferral::LocalInvariantViolation.into(),
            )
        })?;
    // This scalar is supplied by the original signed-genesis or committed execution owner.
    // Scope rejection precedes every SCCP write, including commitment and anchor updates.
    if root_scope != SumeragiRootScope::Global || !params::exists(&state_block.world) {
        return Ok(inactive);
    }
    #[cfg(test)]
    observed::record(header, height_inputs);
    let parent = state_block.native_execution_tip();
    let mut stx = state_block
        .try_transaction()
        .map_err(BlockValidationError::StateStorageAdmission)?;
    let prior_degraded = *store::degraded_run::get(&*stx.world);
    let committed = commitment::commit_block(&mut stx, height)?;
    let anchored = anchors::append_parent(&mut stx, height, parent)?;
    let plan = if anchored {
        height_inputs.map(|inputs| {
            generation::plan_generation_step(
                &stx,
                header,
                inputs,
                parent.map(|tip| tip.creation_time_ms()),
            )
        })
    } else {
        None
    }
    .transpose()
    .map_err(|e| BlockValidationError::StateStorageAdmission(e.into()))?
    .flatten();
    let result = plan.as_ref().and_then(|plan| {
        let step = plan.step();
        let (history_root, history_size) = commitment::history_root_and_size(&*stx.world);
        SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            network_id,
            height,
            timestamp_ms: header.creation_time_ms,
            flags: FLAG_ACTIVE
                | if step.successor_validity_ms > 0 {
                    FLAG_ROTATION
                } else {
                    0
                },
            message_count: committed.map_or(0, |record| record.message_count),
            sccp_root: committed.map_or([0; 32], |record| record.root),
            history_size,
            history_root,
            generation: step.generation,
            committee_root: step.committee_root,
            validity_ms: step.successor_validity_ms,
            next_committee_root: step.next_committee_root,
        })
        .ok()
    });
    if result.is_some() {
        if let Some(plan) = plan {
            plan.publish(&mut stx)
                .map_err(|e| BlockValidationError::StateStorageAdmission(e.into()))?;
        }
    }
    store::degraded_run::set(
        &mut stx,
        if result.is_some() {
            0
        } else {
            prior_degraded.saturating_add(1)
        },
    );
    prune::prune(&mut stx, prune::MAX_PRUNE_DELETIONS_PER_BLOCK);
    generation::clear_destination_progress(&mut stx)
        .map_err(|e| BlockValidationError::StateStorageAdmission(e.into()))?;
    // TODO: emit the shared-model SccpFinalityDegraded event once the coordinated model
    // migration lands. Never emit a retired attestation event for this condition.
    stx.apply();
    Ok(result.unwrap_or(inactive))
}

/// Test observation of the inputs [`finalize_block`] received on this thread or for one
/// exact proposal executed by a native worker.
#[cfg(test)]
pub(crate) mod observed {
    use super::{BlockHeader, SccpHeightInputsV1};
    use iroha_crypto::HashOf;
    use parking_lot::Mutex;
    use std::{cell::RefCell, collections::BTreeMap, sync::LazyLock};

    type Calls = Vec<(u64, Option<SccpHeightInputsV1>)>;

    static HEADERS: LazyLock<Mutex<BTreeMap<HashOf<BlockHeader>, Calls>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    std::thread_local! {
        static CALLS: RefCell<Vec<(u64, Option<SccpHeightInputsV1>)>> =
            const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(header: &BlockHeader, inputs: Option<&SccpHeightInputsV1>) {
        CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push((header.height().get(), inputs.cloned()));
        });
        if let Some(calls) = HEADERS.lock().get_mut(&header.hash()) {
            calls.push((header.height().get(), inputs.cloned()));
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
    pub(crate) fn take() -> Vec<(u64, Option<SccpHeightInputsV1>)> {
        CALLS.with(|calls| core::mem::take(&mut *calls.borrow_mut()))
    }
}

/// Advance the bounded liability clock before governance and this block's transactions.
///
/// # Errors
///
/// Local storage admission refusal leaves the original block retryable.
pub fn apply_block_start(
    state_block: &mut StateBlock<'_>,
    header: &BlockHeader,
) -> Result<(), StateStorageAdmissionError> {
    let Some(parameters) = store::parameters::get(&state_block.world).as_ref() else {
        return Ok(());
    };
    // SCCP is initialized only by a genesis instruction, after this start phase. G1 fixes
    // its first clock in the authenticated finalizer; preexisting component state grants
    // no genesis scope authority here.
    if header.is_genesis() {
        return Ok(());
    }
    let Some(parent) = state_block.native_execution_tip() else {
        // Component state without an authenticated parent cannot advance monetary time.
        return Ok(());
    };
    if parent.root_scope() != SumeragiRootScope::Global {
        return Ok(());
    }
    let clock = generation::advance_liability_clock(
        *store::liability_clock::get(&state_block.world),
        parent.creation_time_ms(),
        header.creation_time_ms,
        parameters.committee_heartbeat_ms,
    );
    let mut stx = state_block.try_transaction()?;
    store::liability_clock::set(&mut stx, clock);
    stx.apply();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_generation};
    use iroha_data_model::{parameter::system::ConsensusMode, sccp::params::SccpParametersV1};

    #[test]
    fn absent_sccp_produces_an_inactive_bound_header() {
        let state = blank_state();
        let header = header(2);
        let mut block = state.block(header);
        apply_block_start(&mut block, &header).unwrap();
        let result = finalize_block(&mut block, &header, None, SumeragiRootScope::Global).unwrap();
        assert!(!result.is_active());
        assert_eq!(result.height(), 2);
        assert_eq!(result.timestamp_ms(), header.creation_time_ms);
        assert!(!generation::heartbeat_due(
            &block.world,
            header.creation_time_ms
        ));
    }

    #[test]
    fn genesis_uses_native_keys_and_records_the_original_generation() {
        let state = blank_state();
        let header = header(1);
        let mut block = state.block(header);
        let fixture = sample_generation(1, 1);
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        stx.apply();
        let inputs = SccpHeightInputsV1 {
            mode: ConsensusMode::Npos,
            height: 1,
            epoch: 0,
            epoch_end_height: 100,
            keys: super::super::height::SccpHeightKeysV1::try_from_slice(&fixture.keys.clone())
                .unwrap(),
            next_keys: None,
        };
        let result = finalize_block(
            &mut block,
            &header,
            Some(&inputs),
            SumeragiRootScope::Global,
        )
        .unwrap();
        assert!(result.is_active());
        assert!(!result.is_rotation());
        assert_eq!(result.committee_root(), fixture.committee_root);
        assert_eq!(result.generation(), 1);
        assert_eq!(*store::committee_current::get(&block.world), 1);
        assert_eq!(
            *store::liability_clock::get(&block.world),
            header.creation_time_ms
        );
        assert!(store::anchor_open::get(&block.world).is_empty());
    }

    #[test]
    fn missing_inputs_are_inactive_and_bound_heartbeat_retries() {
        let state = blank_state();
        let header = header(2);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        store::committee_generations::insert(&mut stx, 1, sample_generation(1, 1)).unwrap();
        store::committee_current::set(&mut stx, 1);
        stx.apply();
        assert!(
            !finalize_block(&mut block, &header, None, SumeragiRootScope::Global)
                .unwrap()
                .is_active()
        );
        assert_eq!(*store::degraded_run::get(&block.world), 1);
        assert!(
            !finalize_block(&mut block, &header, None, SumeragiRootScope::Global)
                .unwrap()
                .is_active()
        );
        assert_eq!(*store::degraded_run::get(&block.world), 2);
        let mut due = header;
        due.creation_time_ms = u64::MAX;
        assert!(!generation::heartbeat_due(
            &block.world,
            due.creation_time_ms
        ));
        assert_eq!(*store::committee_current::get(&block.world), 1);
    }

    #[test]
    fn missing_parent_anchor_cannot_publish_a_due_handoff() {
        let state = blank_state();
        let mut header = header(2);
        let parameters = SccpParametersV1::taira_default();
        let original = sample_generation(1, 1);
        header.creation_time_ms = original.start_timestamp_ms + parameters.committee_heartbeat_ms;
        let mut block = state.block(header);
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(parameters));
        store::committee_generations::insert(&mut stx, 1, original.clone()).unwrap();
        store::committee_current::set(&mut stx, 1);
        store::liability_clock::set(&mut stx, original.start_lc);
        store::degraded_run::set(&mut stx, 2);
        stx.apply();
        let inputs = SccpHeightInputsV1 {
            mode: ConsensusMode::Npos,
            height: 2,
            epoch: 0,
            epoch_end_height: 100,
            keys: super::super::height::SccpHeightKeysV1::try_from_slice(&original.keys.clone())
                .unwrap(),
            next_keys: None,
        };
        let result = finalize_block(
            &mut block,
            &header,
            Some(&inputs),
            SumeragiRootScope::Global,
        )
        .unwrap();
        assert!(!result.is_active());
        assert_eq!(*store::committee_current::get(&block.world), 1);
        assert_eq!(
            store::committee_generations::get(&block.world, &1),
            Some(&original)
        );
        assert!(store::committee_generations::get(&block.world, &2).is_none());
        assert_eq!(*store::degraded_run::get(&block.world), 3);
        assert!(!generation::heartbeat_due(
            &block.world,
            header.creation_time_ms
        ));
    }

    #[test]
    fn header_refusal_preserves_the_original_degraded_counter_and_generation() {
        use iroha_data_model::sccp::commitment::SccpHistoryStateV1;
        let state = blank_state();
        let header = header(1);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        store::degraded_run::set(&mut stx, 2);
        // No leaves are committed, so the invalid historical summary reaches X validation.
        store::history::set(
            &mut stx,
            SccpHistoryStateV1 {
                size: 1,
                peaks: vec![],
            },
        );
        stx.apply();
        let inputs = SccpHeightInputsV1 {
            mode: ConsensusMode::Npos,
            height: 1,
            epoch: 0,
            epoch_end_height: 100,
            keys: super::super::height::SccpHeightKeysV1::try_from_slice(
                &sample_generation(1, 1).keys,
            )
            .unwrap(),
            next_keys: None,
        };
        let result = finalize_block(
            &mut block,
            &header,
            Some(&inputs),
            SumeragiRootScope::Global,
        )
        .unwrap();
        assert!(!result.is_active());
        assert_eq!(*store::degraded_run::get(&block.world), 3);
        assert_eq!(*store::committee_current::get(&block.world), 0);
        assert!(store::committee_generations::get(&block.world, &1).is_none());
        assert!(!generation::heartbeat_due(
            &block.world,
            header.creation_time_ms
        ));
    }

    #[test]
    fn proposal_observer_remains_scoped_to_its_original_header() {
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
        drop(calls);
        observed::record(&original, None);
        assert!(observed::for_header(&original).take().is_empty());
        let unwound = std::panic::catch_unwind(|| {
            let original = header(9_031);
            let _guard = observed::for_header(&original);
            observed::record(&original, None);
            panic!("observer cleanup on unwind");
        });
        assert!(unwound.is_err());
        assert!(observed::for_header(&original).take().is_empty());
        let _ = observed::take();
    }

    #[test]
    fn authenticated_dataspace_scope_returns_inactive_before_any_sccp_effect() {
        use crate::sumeragi::lanes::routing::test_support::signed_genesis;
        use iroha_data_model::sccp::commitment::SccpHistoryStateV1;
        use iroha_model_base::topology::DataSpaceId;
        let state = blank_state();
        let genesis = signed_genesis(SumeragiRootScope::Dataspace {
            parent_network_id: state.network_id,
            dataspace_id: DataSpaceId::new((1_u64 << 40) + 81),
        });
        let (_, scope) = iroha_data_model::sumeragi_finality::authenticated_genesis(&genesis)
            .expect("original signature and committee")
            .into_parts();
        assert_ne!(scope, SumeragiRootScope::Global);
        let h = header(1);
        let mut block = state.block(h);
        let original = sample_generation(1, 1);
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        store::committee_generations::insert(&mut stx, 1, original.clone()).unwrap();
        store::committee_current::set(&mut stx, 1);
        store::liability_clock::set(&mut stx, 3);
        store::degraded_run::set(&mut stx, 7);
        let history = SccpHistoryStateV1 {
            size: 1,
            peaks: vec![[9; 32]],
        };
        store::history::set(&mut stx, history.clone());
        let anchor = anchors::SccpAnchorV1 {
            core_hash: [4; 32],
            result: [5; 32],
        };
        store::anchor_open::set(&mut stx, vec![anchor]).unwrap();
        store::anchor_chunks::insert(&mut stx, 99, [6; 32]).unwrap();
        stx.apply();
        let inputs = SccpHeightInputsV1 {
            mode: ConsensusMode::Npos,
            height: 1,
            epoch: 0,
            epoch_end_height: 100,
            keys: super::super::height::SccpHeightKeysV1::try_from_slice(&original.keys.clone())
                .unwrap(),
            next_keys: None,
        };
        apply_block_start(&mut block, &h).unwrap();
        let result = finalize_block(&mut block, &h, Some(&inputs), scope).unwrap();
        assert!(!result.is_active());
        assert_eq!(result.height(), h.height().get());
        assert_eq!(result.timestamp_ms(), h.creation_time_ms);
        assert_eq!(result.network_id(), *block.network_id().as_bytes());
        assert_eq!(*store::liability_clock::get(&block.world), 3);
        assert_eq!(*store::degraded_run::get(&block.world), 7);
        assert_eq!(*store::committee_current::get(&block.world), 1);
        assert_eq!(store::committee_generations::len(&block.world), 1);
        assert_eq!(
            store::committee_generations::get(&block.world, &1),
            Some(&original)
        );
        assert_eq!(store::history::get(&block.world), &history);
        assert!(store::block_commitments::is_empty(&block.world));
        assert_eq!(store::anchor_open::get(&block.world), &vec![anchor]);
        assert_eq!(store::anchor_chunks::len(&block.world), 1);
        assert_eq!(store::anchor_chunks::get(&block.world, &99), Some(&[6; 32]));
        // The test's block is intentionally a component state; scope itself comes from the
        // original signed source. It does not claim that this block executed that source.
    }

    #[test]
    fn block_start_uses_the_original_global_parent_clock() {
        use crate::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let state = chain.state();
        let original = state
            .view()
            .native_execution_tip()
            .expect("original executed genesis");
        assert_eq!(original.root_scope(), SumeragiRootScope::Global);
        let mut h = header(original.height() + 1);
        h.creation_time_ms = original.creation_time_ms() + 80_000;
        let mut block = state.block(h);
        let parameters = SccpParametersV1::taira_default();
        let expected = generation::advance_liability_clock(
            73,
            original.creation_time_ms(),
            h.creation_time_ms,
            parameters.committee_heartbeat_ms,
        );
        assert!(expected > 73, "the positive control must advance");
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(parameters));
        store::liability_clock::set(&mut stx, 73);
        stx.apply();
        apply_block_start(&mut block, &h).unwrap();
        assert_eq!(*store::liability_clock::get(&block.world), expected);
    }

    #[test]
    fn original_dataspace_parent_cannot_advance_the_liability_clock() {
        // This existing fixture executes signed private genesis; the opaque tip is never
        // fabricated from a caller-authored root scope or restored snapshot row.
        crate::state::native_capture_fixture::with_native_capture_dataspace_source(
            |_state, mut block, _guard, source, _hash| {
                let original = block
                    .native_execution_tip()
                    .expect("original executed private genesis");
                assert!(matches!(
                    original.root_scope(),
                    SumeragiRootScope::Dataspace { .. }
                ));
                let h = source.header();
                assert_eq!(original.height() + 1, h.height().get());
                let mut stx = block.transaction();
                store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
                store::liability_clock::set(&mut stx, 73);
                store::degraded_run::set(&mut stx, 5);
                stx.apply();
                apply_block_start(&mut block, &h).unwrap();
                let result = finalize_block(&mut block, &h, None, original.root_scope()).unwrap();
                assert!(!result.is_active());
                assert_eq!(*store::liability_clock::get(&block.world), 73);
                assert_eq!(*store::degraded_run::get(&block.world), 5);
                assert!(store::anchor_open::get(&block.world).is_empty());
                assert!(store::anchor_chunks::is_empty(&block.world));
                assert!(store::block_commitments::is_empty(&block.world));
                assert_eq!(*store::committee_current::get(&block.world), 0);
            },
        );
    }
}
