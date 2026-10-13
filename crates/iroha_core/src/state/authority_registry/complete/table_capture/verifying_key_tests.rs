//! Actual catalog linkage, original State allocation custody and publication fences.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        authority_registry::grouped_ownership::{GroupImage, GroupMismatch, GroupedOwnershipError},
        verifying_key_index_validation::test_support::*,
    },
};
use iroha_data_model::proof::VerifyingKeyId;

fn state() -> State {
    State::new_for_testing(
        world(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn capture(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let TableMaterializer::Single { capture, .. } = TABLE_MATERIALIZERS
        .iter()
        .find(|owner| owner.table_ids().any(|id| id == "world.verifying_keys"))
        .unwrap()
    else {
        panic!("one checked original registry capture")
    };
    capture(state, limits)
}

#[test]
fn actual_catalog_rejects_corruption_after_state_construction_in_both_images() {
    for prior in [false, true] {
        for defect in 0..4 {
            let mut state = state();
            let tuple = ("circuit".to_owned(), 1);
            match defect {
                0 => {
                    let mut index = state.world.verifying_keys_by_circuit.block();
                    index.remove(tuple.clone());
                    index.commit();
                }
                1 => {
                    state
                        .world
                        .verifying_keys_by_circuit
                        .insert(tuple.clone(), VerifyingKeyId::new("foreign", "key"));
                }
                2 => {
                    let mut index = state.world.verifying_keys_by_circuit.block();
                    index.remove(tuple.clone());
                    index.commit();
                    state
                        .world
                        .verifying_keys_by_circuit
                        .insert(("wrong".into(), 1), id());
                }
                3 => {
                    state
                        .world
                        .verifying_keys_by_circuit
                        .insert(("wrong".into(), 1), id());
                }
                _ => unreachable!(),
            }
            if prior {
                repair_current(&state.world, &[("wrong".into(), 1)]);
            }
            state.ivm_execution_budget().set_limit_bytes(0);
            assert_eq!(
                capture(&state, native_test_support::limits()).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index: "world.verifying_keys_by_circuit",
                        image: if prior {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch: if defect == 3 {
                            GroupMismatch::ForeignMember
                        } else {
                            GroupMismatch::MissingMember
                        },
                    }
                ))
            );
            let mut notice = state.state_view_publication();
            let guard = notice.begin();
            assert!(
                capture(&state, native_test_support::limits())
                    .unwrap()
                    .is_none()
            );
            drop(guard);
        }
    }
}

#[test]
fn original_state_pool_refusal_retries_and_refunds_only_the_last_snapshot_owner() {
    let state = state();
    let pool = state.ivm_execution_budget();
    let baseline = pool.reserved_bytes();
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture(&state, native_test_support::limits()),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture(&state, native_test_support::limits())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), "world.verifying_keys");
    assert_eq!(snapshot.row_count(), 1);
    assert!(pool.reserved_bytes() > baseline);
    drop(snapshot);
    assert_eq!(pool.reserved_bytes(), baseline);
}

#[test]
fn large_variable_keys_and_logically_absent_tombstones_only_defer_local_work() {
    for long in [false, true] {
        let mut state = state();
        if long {
            let key = VerifyingKeyId::new("b".repeat(1500), "key");
            state.world.verifying_keys = mv::storage::Storage::from_iter([(key.clone(), record())]);
            state.world.verifying_keys_by_circuit =
                mv::storage::Storage::from_iter([(("circuit".into(), 1), key)]);
        } else {
            let mut rows = state.world.verifying_keys.block();
            // Even after the ordered merge exhausts the current row, both source
            // passes must inspect all 1,100 physical absent preimages.
            for ordinal in 0..1_100 {
                rows.remove(VerifyingKeyId::new("zz absent", format!("key-{ordinal}")));
            }
            rows.commit();
        }
        assert_eq!(
            capture(&state, native_test_support::limits()).err(),
            Some(LeafError::GroupedOwnership(
                GroupedOwnershipError::WorkLimit
            ))
        );
        let mut limits = native_test_support::limits();
        limits.max_rows = 128;
        let snapshot = capture(&state, limits).unwrap().unwrap();
        assert_eq!(snapshot.row_count(), 1);
    }
}

#[path = "verifying_key_tests/encoding_race.rs"]
mod encoding_race;
