//! Fresh State must retain every prepaid table's exact original pool.

use super::validate_world_original_pools;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        AnchorStorage, CommitteeStorage, LightClientSetStorage, MergeLedgerCommitError, State,
        StateStorageAdmissionError, World, sccp_forgery_custody::OffenceStorage,
        sccp_reconciliation_store,
    },
    test_allocations::allocations_during,
};
use iroha_allocation::AllocationBudget;
use mv::storage::AdmittedStorageError;

fn budget() -> AllocationBudget {
    AllocationBudget::new(iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES)
}

#[test]
fn original_pool_preflight_allocates_nothing_with_every_world_writer_held() {
    let source = budget();
    let foreign = budget();
    let world = World::try_with_execution_budget([], [], [], &source).unwrap();
    let baseline = source.reserved_bytes();
    let held = world.try_block(&source).unwrap();
    let foreign_before = foreign.reserved_bytes();
    std::thread::scope(|threads| {
        let (sent, received) = std::sync::mpsc::channel();
        let original = source.clone();
        let world = &world;
        let foreign = &foreign;
        let worker = threads.spawn(move || {
            let allocations = allocations_during(|| {
                assert_eq!(validate_world_original_pools(world, &original), Ok(()));
                assert_eq!(
                    validate_world_original_pools(world, foreign),
                    Err(AdmittedStorageError::ScopeIdentity)
                );
            });
            sent.send(allocations).unwrap();
        });
        let result = received.recv_timeout(std::time::Duration::from_secs(5));
        // A regression that acquires a writer is allowed to unwind after release,
        // so the failure cannot strand its thread or the rest of the test binary.
        drop(held);
        worker.join().unwrap();
        assert_eq!(
            result.unwrap(),
            0,
            "pool preflight must neither allocate nor wait for writers"
        );
    });
    assert_eq!(source.reserved_bytes(), baseline);
    assert_eq!(foreign.reserved_bytes(), foreign_before);
    drop(world.try_block(&source).unwrap());
}

#[test]
fn fresh_state_accepts_a_clone_of_the_complete_original_pool() {
    let source = budget();
    let world = World::try_with_execution_budget([], [], [], &source).unwrap();
    assert_eq!(
        validate_world_original_pools(&world, &source.clone()),
        Ok(())
    );
    let state = State::try_new_with_chain_and_network_id_with_default_telemetry(
        source.clone(),
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        iroha_model_base::chain::ChainId::from("original-pool-constructor"),
        *crate::state::DEFAULT_TEST_NETWORK_ID,
    )
    .expect("fresh State and all prepaid roots share one original pool");
    assert!(state.ivm_execution_budget().same_pool(&source));
    assert_eq!(state.committed_height(), 0);
    assert_eq!(state.kura().blocks_count(), 0);
    drop(state.world.try_block(&source).unwrap());
}

#[test]
fn fresh_state_refuses_a_foreign_pool_before_resource_admission() {
    let source = budget();
    let foreign = AllocationBudget::new(0);
    let world = World::try_with_execution_budget([], [], [], &source).unwrap();
    let result = State::try_new_with_chain_and_network_id_with_default_telemetry(
        foreign.clone(),
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        iroha_model_base::chain::ChainId::from("foreign-pool-constructor"),
        *crate::state::DEFAULT_TEST_NETWORK_ID,
    );
    assert!(
        matches!(
            result,
            Err(MergeLedgerCommitError::StateStorageAdmission(
                StateStorageAdmissionError::World(AdmittedStorageError::ScopeIdentity)
            ))
        ),
        "fresh State must reject the original foreign pool before admission"
    );
    assert_eq!(foreign.peak_reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn fresh_state_refuses_each_mixed_prepaid_pool_before_resource_admission() {
    type Replace = fn(&mut World, &AllocationBudget);
    let cases: [(&str, Replace); 8] = [
        ("sccp_committee_generations", |world, source| {
            world.sccp_committee_generations =
                CommitteeStorage::try_new_admitted(source.clone()).unwrap();
        }),
        ("sccp_anchor_chunks", |world, source| {
            world.sccp_anchor_chunks = AnchorStorage::try_new_admitted(source.clone()).unwrap();
        }),
        ("sccp_forgery_offences", |world, source| {
            world.sccp_forgery_offences = OffenceStorage::try_new_admitted(source.clone()).unwrap();
        }),
        ("sccp_light_client_sets", |world, source| {
            world.sccp_light_client_sets =
                LightClientSetStorage::try_new_admitted(source.clone()).unwrap();
        }),
        ("sccp_reconciliations", |world, source| {
            world.sccp_reconciliations =
                sccp_reconciliation_store::Records::try_new_admitted(source.clone()).unwrap();
        }),
        ("sccp_reconciliation_proven", |world, source| {
            world.sccp_reconciliation_proven =
                sccp_reconciliation_store::Proofs::try_new_admitted(source.clone()).unwrap();
        }),
        ("sccp_pending_refund_amount", |world, source| {
            world.sccp_pending_refund_amount =
                sccp_reconciliation_store::Refunds::try_new_admitted(source.clone()).unwrap();
        }),
        ("sccp_reconciliation_due", |world, source| {
            world.sccp_reconciliation_due =
                sccp_reconciliation_store::Due::try_new_admitted(source.clone()).unwrap();
        }),
    ];
    for (field, replace) in cases {
        let source = budget();
        let foreign = budget();
        let mut world = World::try_with_execution_budget([], [], [], &source).unwrap();
        replace(&mut world, &foreign);
        let before = (source.reserved_bytes(), foreign.reserved_bytes());
        assert_eq!(
            allocations_during(|| {
                assert_eq!(
                    validate_world_original_pools(&world, &source),
                    Err(AdmittedStorageError::ScopeIdentity),
                    "{field}"
                );
                assert_eq!(
                    validate_world_original_pools(&world, &foreign),
                    Err(AdmittedStorageError::ScopeIdentity),
                    "{field}"
                );
            }),
            0,
            "{field}"
        );
        assert_eq!(
            (source.reserved_bytes(), foreign.reserved_bytes()),
            before,
            "{field}"
        );
        // No capacity remains for any constructor admission. Pool identity must
        // still win first, including when only the last prepaid field is foreign.
        source.set_limit_bytes(0);
        let result = State::try_new_with_chain_and_network_id_with_default_telemetry(
            source,
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            iroha_model_base::chain::ChainId::from("mixed-pool-constructor"),
            *crate::state::DEFAULT_TEST_NETWORK_ID,
        );
        assert!(
            matches!(
                result,
                Err(MergeLedgerCommitError::StateStorageAdmission(
                    StateStorageAdmissionError::World(AdmittedStorageError::ScopeIdentity)
                ))
            ),
            "{field}"
        );
    }
}
