//! One-way local owner export keeps real transaction publication forbidden.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, storage_transactions::TransactionsBlockError},
};
use iroha_data_model::{Registrable, block::BlockHeader, prelude::Domain};
use mv::storage::StorageReadOnly as _;

fn state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

#[test]
fn exported_first_refusal_blocks_reuse_state_apply_and_block_commit() {
    for consensus_effects in [false, true] {
        let state = state();
        let mut block = state.block(BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let domain =
            iroha_model_base::domain::DomainId::try_new("moved_owner", "universal").unwrap();
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        let original_observation = original.clone();
        let mut transaction = block.transaction();
        transaction.world.domains.insert(
            domain.clone(),
            Domain::new(domain.clone()).build(&iroha_test_samples::ALICE_ID),
        );
        transaction.vm_error_to_validation_fail(VMError::AllocationDeferred(original), |_| {
            panic!("the actual allocation refusal is not a deterministic rejection")
        });
        transaction.defer_execution(ExecutionDeferral::AllocationUnavailable);
        {
            let borrowed = transaction.borrow_execution_deferral().unwrap();
            assert_eq!(borrowed.allocation_refusal(), Some(&original_observation));
        }
        let exported = transaction.take_execution_deferral().unwrap();
        assert_eq!(exported.allocation_refusal(), Some(&original_observation));
        assert!(transaction.take_execution_deferral().is_none());
        assert!(transaction.borrow_execution_deferral().is_none());
        assert!(transaction.is_execution_deferred());
        // A later producer cannot replace the first owner after its export.
        transaction.defer_execution(ExecutionDeferral::TraceOwnerUnavailable);
        assert!(transaction.take_execution_deferral().is_none());
        let reused = transaction.ensure_execution_ready().unwrap_err();
        assert_eq!(reused.reason(), ExecutionDeferral::LocalInvariantViolation);
        assert!(reused.allocation_refusal().is_none());
        assert!(reused.decode_refusal().is_none());
        assert!(reused.verification_refusal().is_none());
        assert_eq!(transaction.last_tx_gas_used, 0);
        if consensus_effects {
            transaction.apply_consensus_effects();
        } else {
            transaction.apply();
        }
        assert!(block.world.domains.get(&domain).is_none());
        assert!(matches!(
            block.commit().unwrap_err(),
            TransactionsBlockError::ExecutionOutputCapacity
        ));
        drop(occupied);
        assert!(budget.try_reserve_bytes(1).is_ok());
        // Readiness can only come from a fresh disposable transaction.
        let mut fresh_block = state.block(BlockHeader::new(
            std::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut fresh = fresh_block.transaction();
        assert!(!fresh.is_execution_deferred());
        assert!(fresh.ensure_execution_ready().is_ok());
    }
}

#[test]
fn exported_owner_cannot_reenable_raw_world_apply() {
    let state = state();
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        0,
        0,
    ));
    let domain = iroha_model_base::domain::DomainId::try_new("moved_world", "universal").unwrap();
    let mut world = block
        .world
        .transaction_without_telemetry(iroha_config::parameters::actual::LaneConfig::default(), 0);
    world.domains.insert(
        domain.clone(),
        Domain::new(domain.clone()).build(&iroha_test_samples::ALICE_ID),
    );
    world.defer_execution(ExecutionDeferral::VerifierArtifactsUnavailable);
    let exported = world.execution_deferral.borrow_mut().take_owner().unwrap();
    assert_eq!(
        exported.reason(),
        ExecutionDeferral::VerifierArtifactsUnavailable
    );
    assert!(world.execution_deferral.borrow().is_refused());
    world.apply();
    assert!(block.world.domains.get(&domain).is_none());
}

#[test]
fn consuming_vm_projection_keeps_completed_metered_error_intact() {
    let original = VMError::Metered {
        gas: 19,
        source: Box::new(VMError::UnknownSyscall(0xdead)),
    };
    let returned = ExecutionDeferred::try_from_vm_error(original).unwrap_err();
    let VMError::Metered { gas, source } = returned else {
        panic!("a completed error must keep its original metering wrapper")
    };
    assert_eq!(gas, 19);
    assert!(matches!(*source, VMError::UnknownSyscall(0xdead)));
}
