//! Atomic first-capture publication and sticky failure across errors and unwinding.

use super::{Hash, StateBlock, output_capacity::ExecutionOutputPlanState};

/// A witness capture ends with a completed content verdict or its original local owner.
#[derive(Debug, thiserror::Error)]
pub enum WitnessCaptureError {
    /// A completed deterministic source or content rejection.
    #[error("{0}")]
    Rejected(String),
    /// An original local execution/decode refusal; no content verdict was reached.
    #[error("local witness capture did not complete: {0}")]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// Original State storage acquisition refused; release evidence stays intact.
    #[error(transparent)]
    StorageAdmission(super::StateStorageAdmissionError),
}
impl From<String> for WitnessCaptureError {
    fn from(error: String) -> Self {
        Self::Rejected(error)
    }
}
impl From<&str> for WitnessCaptureError {
    fn from(error: &str) -> Self {
        Self::Rejected(error.to_owned())
    }
}
impl From<crate::execution_attempt::ExecutionAttemptError<String>> for WitnessCaptureError {
    fn from(error: crate::execution_attempt::ExecutionAttemptError<String>) -> Self {
        match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                Self::Rejected(error)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                Self::Deferred(reason)
            }
        }
    }
}

/// Retain the prior lane seal until every witness-derived output can be published.
/// A failed attempt discards cached outputs and cannot be repaired by a new capture.
/// The checked recorder drain separately owns recorder reset on errors and unwinding.
pub(super) struct WitnessCaptureGuard<'capture, 'state> {
    pub(super) state: &'capture mut StateBlock<'state>,
    prior_lane_seal: Option<Hash>,
    finished: bool,
}

impl<'capture, 'state> WitnessCaptureGuard<'capture, 'state> {
    pub(super) fn new(state: &'capture mut StateBlock<'state>) -> Self {
        Self {
            prior_lane_seal: state.sumeragi_lane_state_seal,
            state,
            finished: false,
        }
    }

    /// Finish only after all fallible work and all three output assignments.
    pub(super) fn finish(mut self) {
        self.finished = true;
    }

    /// Preserve the exact first error and discard the attempted capture's outputs.
    pub(super) fn reject(mut self, error: String) -> String {
        let error = self.invalidate(error);
        self.finished = true;
        error
    }

    /// Abandon unpublished outputs on an original local refusal. A fresh whole
    /// execution attempt must rebuild the recorder; this is no content failure.
    pub(super) fn defer(
        self,
        reason: crate::execution_attempt::ExecutionDeferred,
    ) -> crate::execution_attempt::ExecutionDeferred {
        self.abandon();
        reason
    }

    /// Release an unpublished capture on a local owner, without latching a content verdict.
    pub(super) fn abandon(mut self) {
        self.state.sumeragi_lane_state_seal = self.prior_lane_seal;
        if self.state.execution_output_plan.is_some() {
            self.state.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
        }
        self.state.clear_cached_exec_witness();
        self.finished = true;
    }

    fn invalidate(&mut self, error: String) -> String {
        self.state.sumeragi_lane_state_seal = self.prior_lane_seal;
        if self.state.execution_output_plan.is_some() {
            self.state.execution_output_plan = Some(ExecutionOutputPlanState::Poisoned);
        }
        self.state.reject_fastpq_witness_content(error)
    }
}

impl Drop for WitnessCaptureGuard<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.invalidate("execution witness capture was interrupted".into());
        }
    }
}

#[cfg(test)]
mod local_capture_controls {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_data_model::block::BlockHeader;
    #[test]
    fn original_capture_refusal_abandons_outputs_without_latching_content_or_new_waiter() {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let original: crate::execution_attempt::ExecutionDeferred = refusal.clone().into();
        let observed = WitnessCaptureGuard::new(&mut block).defer(original);
        assert_eq!(
            observed.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(observed.phase().is_none());
        assert!(observed.decode_refusal().is_none());
        assert!(observed.verification_refusal().is_none());
        assert_eq!(observed.allocation_refusal(), Some(&refusal));
        assert!(
            block.fastpq_source_inventory.is_none(),
            "no deterministic content latch may be invented"
        );
        assert!(block.exec_witness.is_none());
        assert!(block.fastpq_witness_context.is_none());
        assert!(block.parliament_timed_ovn_casting_bindings.is_none());
        drop(occupied);
        assert!(
            budget.try_reserve_bytes(1).is_ok(),
            "same real pool can retry after release"
        );
    }
    #[test]
    fn original_storage_admission_and_abandonment_preserve_the_real_release_owner() {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = super::super::StateStorageAdmissionError::World(
            mv::storage::AdmittedStorageError::Allocation(budget.try_reserve_bytes(1).unwrap_err()),
        );
        WitnessCaptureGuard::new(&mut block).abandon();
        let error = WitnessCaptureError::StorageAdmission(original.clone());
        let WitnessCaptureError::StorageAdmission(retained) = error else {
            panic!("storage refusal changed owner")
        };
        assert_eq!(retained, original);
        assert_eq!(retained.release_wait(), original.release_wait());
        assert!(block.fastpq_source_inventory.is_none());
        drop(occupied);
        assert!(budget.try_reserve_bytes(1).is_ok());
    }
}
