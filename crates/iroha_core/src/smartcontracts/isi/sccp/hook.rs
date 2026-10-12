//! SCCP native generation and monetary-history hooks (`specs/sccp.md` §4.2, §4.5, §4.8).
//!
//! S0 fixes the liability clock before governance or transactions. The post-execution pass
//! preserves leaf/history commitments, prepares original native G2/G7 owners, applies them
//! atomically, then runs available pruning and L5. Missing deterministic inputs degrade SCCP;
//! local custody failures defer the local attempt and never become peer-invalid verdicts.
//! A1 and fixed X remain bound to the same original execution cut; destination launch also
//! requires the independently tracked evidence, reconciliation and admission owners.

use super::{
    anchor, commitment, finality, generation, height::SccpHeightInputsV1, params, prune, store,
};
use crate::{
    block::BlockValidationError,
    state::{StateBlock, StateReadOnly, StateStorageAdmissionError, WorldReadOnly},
};
use iroha_data_model::block::BlockHeader;
use iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1;
use mv::storage::StorageReadOnly;

/// Update the liability clock before the governance block-start pass and all transactions.
/// Deterministic inconsistency is retained for G4; only a local transaction refusal escapes.
pub fn begin_block(
    state: &mut StateBlock<'_>,
    header: &BlockHeader,
) -> Result<(), StateStorageAdmissionError> {
    let Some(parameters) = params::parameters(&state.world) else {
        return Ok(());
    };
    let parent = state
        .native_execution_tip()
        .map(|tip| (tip.height(), tip.creation_time_ms()));
    let next = super::generation_plan::liability_clock(
        header.height().get(),
        header.creation_time_ms,
        parent,
        state.world.sccp_liability_clock(),
        parameters.committee_heartbeat_ms,
        super::generation_plan::SCCP_LC_SLACK_MS,
    );
    match next {
        Ok(lc) => {
            let mut transaction = state.try_transaction()?;
            *transaction.world.sccp_liability_clock.get_mut() = lc;
            transaction.apply();
            state.sccp_begin_failure = None;
        }
        Err(reason) => {
            state.sccp_begin_failure = Some(reason);
        }
    }
    state.require_storage_admission()?;
    Ok(())
}

/// Finalize SCCP World writes using original native height-input custody.
/// Local refusals leave the whole enclosing execution attempt unapplied.
pub fn finalize_block(
    state: &mut StateBlock<'_>,
    header: &BlockHeader,
    height_inputs: Option<&SccpHeightInputsV1>,
) -> Result<SccpFinalityHeaderV1, BlockValidationError> {
    let inactive = finality::inactive(
        *state.network_id(),
        header.height(),
        header.creation_time_ms,
    );
    if !params::exists(&state.world) {
        return Ok(inactive);
    }
    #[cfg(test)]
    observed::record(header, height_inputs);
    let Some(parameters) = params::parameters(&state.world) else {
        return Ok(inactive);
    };
    let global = matches!(
        crate::sumeragi::lanes::routing::read_routing_root_scope(&state.world)
            .map_err(BlockValidationError::ExecutionDeferred)?,
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    );
    let original_degraded_run = state.world.sccp_degraded_run();
    let budget = state.execution_budget();
    let prepared_anchor =
        anchor::prepare(&state.world, header, state.native_execution_tip(), &budget).map_err(
            |original| {
                let original = StateStorageAdmissionError::SccpAnchor(original);
                state.arm_local_storage_refusal(original.clone());
                BlockValidationError::StateStorageAdmission(original)
            },
        )?;
    let prepared = generation::prepare(
        &state.world,
        &parameters,
        *state.network_id(),
        header.height().get(),
        header.creation_time_ms,
        state.native_execution_tip(),
        height_inputs,
        state.sccp_begin_failure.or_else(|| {
            (!global).then_some(
                iroha_data_model::sccp::events::SccpFinalityDegradedReasonV1::InvalidHeightInputs,
            )
        }),
        &budget,
    )
    .map_err(generation::GenerationWriteError::into_block_error)?;
    let mut transaction = state
        .try_transaction()
        .map_err(BlockValidationError::StateStorageAdmission)?;
    commitment::commit_block(&mut transaction, header.height().get())?;
    let signing_generation = prepared
        .apply(&mut transaction, &budget)
        .map_err(generation::GenerationWriteError::into_block_error)?;
    prepared_anchor
        .apply(&mut transaction, &budget)
        .map_err(BlockValidationError::StateStorageAdmission)?;
    prune::post_generation_work(&mut transaction)?;
    let signing = signing_generation.and_then(|generation| {
        transaction
            .world
            .sccp_committee_generations
            .get(&generation)
    });
    let produced = finality::produce(
        *transaction.network_id(),
        header.height(),
        header.creation_time_ms,
        signing.map(|owner| owner.record()),
        transaction
            .world
            .sccp_block_commitments
            .get(&header.height().get()),
        transaction.world.sccp_history.get(),
    );
    let header = match produced {
        Ok(header) => header,
        Err(reason) => {
            use iroha_data_model::sccp::events::{SccpEvent, SccpFinalityDegradedV1};
            *transaction.world.sccp_degraded_run.get_mut() =
                original_degraded_run.saturating_add(1);
            transaction
                .world
                .emit_events(Some(SccpEvent::FinalityDegraded(SccpFinalityDegradedV1 {
                    height: header.height().get(),
                    reason,
                })));
            inactive
        }
    };
    transaction.apply();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};
    use iroha_data_model::sccp::params::SccpParametersV1;
    use mv::storage::StorageReadOnly;

    #[test]
    fn proposal_observer_is_scoped_across_threads_and_releases_on_unwind() {
        let original = header(9031);
        let foreign = header(9032);
        let calls = observed::for_header(&original);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                observed::record(&foreign, None);
                observed::record(&original, None);
            });
        });
        assert_eq!(calls.take(), vec![(9031, None)]);
        assert!(calls.take().is_empty());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _calls = calls;
                panic!("scoped observer retirement");
            }))
            .is_err()
        );
        observed::record(&original, None);
        assert!(observed::for_header(&original).take().is_empty());
        let _ = observed::take();
    }

    #[test]
    fn native_hooks_are_no_ops_without_sccp() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        begin_block(&mut block, &candidate).unwrap();
        let _ = observed::take();
        finalize_block(&mut block, &candidate, None).unwrap();
        assert!(observed::take().is_empty());
        assert!(store::block_commitments::is_empty(&block.world));
        assert_eq!(block.world.sccp_liability_clock(), 0);
        assert_eq!(block.world.sccp_degraded_run(), 0);
    }

    #[test]
    fn missing_original_parent_is_sticky_local_refusal_without_fabricated_anchor_or_generation() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        {
            let mut transaction = block.transaction();
            store::parameters::set(&mut transaction, Some(SccpParametersV1::taira_default()));
            transaction.apply();
        }
        begin_block(&mut block, &candidate).unwrap();
        assert_eq!(
            block.sccp_begin_failure,
            Some(iroha_data_model::sccp::events::SccpFinalityDegradedReasonV1::MissingParentTip)
        );
        assert!(matches!(
            finalize_block(&mut block, &candidate, None),
            Err(BlockValidationError::StateStorageAdmission(
                StateStorageAdmissionError::SccpAnchor(anchor::SccpAnchorLocalError::Invariant(
                    "missing original parent native tip"
                ))
            ))
        ));
        assert!(block.require_storage_admission().is_err());
        assert!(block.world.sccp_anchor_open().anchors().is_empty());
        assert!(block.world.sccp_anchor_chunks().iter().next().is_none());
        assert!(
            block
                .world
                .sccp_committee_generations()
                .iter()
                .next()
                .is_none()
        );
        assert_eq!(block.world.sccp_committee_current(), 0);
        assert_eq!(block.world.sccp_degraded_run(), 0);
        assert_eq!(block.world.sccp_liability_clock(), 0);
    }
}
