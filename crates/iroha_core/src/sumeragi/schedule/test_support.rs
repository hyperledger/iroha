//! Original signed-epoch schedule custody for explicit World-only component fixtures.

use super::{
    ChainParamsRecord, ConsensusSchedule, LAG, RetainedConsensusSchedule, ScheduleError,
    ScheduledConfig, ScheduledSlot,
};
use crate::state::WorldReadOnly;
use iroha_allocation::AllocationBudget;

/// Retain exactly three component slots from the original epoch and unchanged parameters.
///
/// This creates fixture custody, not finalized history or successor authority. The original
/// signed epoch must cover every requested height. Existing overlapping slots retain their
/// exact context, status and lag-two parameter record. Callers install the returned original
/// pool owner only after every validation and admission succeeds.
///
/// # Errors
/// Returns the canonical schedule or original pool/allocator error. No World field is changed.
pub(crate) fn retain_same_epoch_component_window(
    world: &impl WorldReadOnly,
    first: u64,
    budget: &AllocationBudget,
) -> Result<RetainedConsensusSchedule, ScheduleError> {
    let last = first
        .checked_add(LAG)
        .ok_or(ScheduleError::HeightOverflow)?;
    let source = world.consensus_schedule();
    let original = source.ready(source.tip().ok_or(ScheduleError::Malformed)?)?;
    if original.params != ChainParamsRecord::from_parameters(world.parameters().sumeragi()) {
        return Err(ScheduleError::Epoch(
            "component schedule cannot replace authenticated chain parameters".to_owned(),
        ));
    }
    let graph = ConsensusSchedule::from_owned_entries(
        (first..=last)
            .map(|height| {
                ScheduledSlot::Ready(ScheduledConfig {
                    height,
                    epoch: original.epoch.clone(),
                    params: original.params,
                })
            })
            .collect(),
    )?;
    for slot in source.entries() {
        if let Some(retained) = graph.get(slot.height())
            && slot != retained
        {
            return Err(ScheduleError::Epoch(
                "component schedule cannot replace an authenticated successor slot".to_owned(),
            ));
        }
    }
    RetainedConsensusSchedule::admit(&graph, budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::{StateReadOnly as _, World},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter},
    };
    use std::num::NonZeroU64;

    fn original_npos_chain() -> CertifiedTestChain {
        let mut config = TestChainConfig::new(World::new(), 0);
        let policy = SumeragiNposParameters {
            epoch_length_blocks: NonZeroU64::new(10).unwrap(),
            epoch_seed: [0x61; 32],
            evidence_horizon_blocks: 1,
            slashing_delay_blocks: 1,
            ..SumeragiNposParameters::default()
        };
        policy.validate().expect("original finite component epoch");
        config.consensus_mode = SumeragiConsensusMode::Npos;
        config.genesis_parameters.extend([
            Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                policy.epoch_length_blocks,
            )),
            Parameter::Custom(policy.into_custom_parameter()),
        ]);
        CertifiedTestChain::start(config).expect("actual signed ten-height epoch")
    }

    #[test]
    fn component_window_refuses_unsupported_epoch_and_absent_authority() {
        // Retain original genesis generations while checking exact refusal accounting.
        let _retirement_pin = crossbeam_epoch::pin();
        let chain = original_npos_chain();
        let state = chain.state();
        let view = state.view();
        let original = view.world.consensus_schedule();
        let baseline = state.ivm_execution_budget().reserved_bytes();
        assert_eq!(
            original.ready(1).unwrap().epoch.authorization.last_height,
            10
        );
        let error =
            retain_same_epoch_component_window(&view.world, 9, &state.ivm_execution_budget())
                .expect_err("H11 cannot inherit authority beyond the signed H10 boundary");
        assert!(
            matches!(error, ScheduleError::Epoch(ref reason)
            if reason == "ready slot changes its authorized epoch"),
            "{error:?}"
        );
        assert_eq!(view.world.consensus_schedule(), original);
        assert_eq!(state.ivm_execution_budget().reserved_bytes(), baseline);
        assert_eq!(
            retain_same_epoch_component_window(
                &view.world,
                u64::MAX - 1,
                &state.ivm_execution_budget()
            ),
            Err(ScheduleError::HeightOverflow)
        );
        let pristine = World::new();
        let budget = pristine
            .sccp_committee_generations
            .allocation_budget()
            .clone();
        assert_eq!(
            retain_same_epoch_component_window(&pristine.view(), 2, &budget),
            Err(ScheduleError::Malformed),
            "an uninitialized World cannot manufacture signed authority"
        );
        assert!(
            pristine
                .consensus_schedule
                .view()
                .get()
                .entries()
                .is_empty()
        );
        assert_eq!(state.committed_height(), 1);
        assert_eq!(view.kura().blocks_count(), 1);
    }

    #[test]
    fn component_window_preserves_original_capacity_and_exact_refund_on_retry() {
        use iroha_allocation::AllocationRefusal;

        // Keep this fixture's retired genesis generations live across exact accounting.
        let _retirement_pin = crossbeam_epoch::pin();
        let chain = original_npos_chain();
        let state = chain.state();
        let view = state.view();
        let original = view.world.consensus_schedule();
        let original_pointer = original.entries().as_ptr();
        let budget = state.ivm_execution_budget();
        assert!(budget.same_pool(&view.execution_budget()));
        let baseline = budget.reserved_bytes();
        let limit = budget.limit_bytes();
        let occupied = budget.try_reserve_bytes(limit - baseline).unwrap();
        let refused = retain_same_epoch_component_window(&view.world, 2, &budget).unwrap_err();
        let ScheduleError::Admission(refusal) = refused else {
            panic!(
                "component capacity must retain its original typed admission cause: {refused:?}"
            );
        };
        let AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            ..
        } = &refusal
        else {
            panic!("occupied original pool must be a capacity refusal: {refusal:?}");
        };
        let demand = *requested_bytes;
        assert!(demand > 0);
        assert_eq!((*reserved_bytes, *limit_bytes), (limit, limit));
        let expected = budget.try_reserve_bytes(demand).unwrap_err();
        assert_eq!(
            refusal, expected,
            "original pool and release observation survive"
        );
        assert_eq!(budget.reserved_bytes(), limit);
        assert_eq!(original.entries().as_ptr(), original_pointer);
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), baseline);
        let retained = retain_same_epoch_component_window(&view.world, 2, &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), baseline + demand);
        let source = original.ready(1).unwrap();
        for height in 2..=4 {
            let slot = retained.ready(height).unwrap();
            assert_eq!(slot.epoch, source.epoch);
            assert_eq!(slot.params, source.params);
        }
        drop(retained);
        assert_eq!(budget.reserved_bytes(), baseline);
        assert_eq!(original.entries().as_ptr(), original_pointer);
        assert_eq!(state.committed_height(), 1);
        assert_eq!(view.kura().blocks_count(), 1);
    }
}
