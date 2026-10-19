//! The actual proof catalog retains and checks both original status images.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        World,
        authority_registry::grouped_ownership::{GroupImage, GroupMismatch, GroupedOwnershipError},
    },
};
use iroha_config::parameters::actual::LaneConfig;
use iroha_data_model::proof::{ProofId, ProofRecord, ProofStatus};
use mv::storage::Storage;

fn id(backend: &str) -> ProofId {
    ProofId {
        backend: backend.into(),
        proof_hash: [41; 32],
    }
}

fn state(backend: &str) -> State {
    let world = World::default();
    let key = id(backend);
    let record = ProofRecord {
        id: key.clone(),
        vk_ref: None,
        vk_commitment: None,
        status: ProofStatus::Submitted,
        verified_at_height: None,
        bridge: None,
    };
    // Seed through the real canonical/index writer. The second committed touch
    // gives both stores a genuine present predecessor; State construction does
    // not reconstruct an index after direct fixture writes to World::default().
    for _ in 0..2 {
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(LaneConfig::default(), 0);
        tx.insert_proof_record(record.clone());
        tx.apply();
        block.commit();
    }
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    {
        let source = state.world.proofs.try_committed_view_nonblocking().unwrap();
        let index = state
            .world
            .proofs_by_status
            .try_committed_view_nonblocking()
            .unwrap();
        assert_eq!(source.current().get(&key), Some(&record));
        assert_eq!(source.undo().get(&key), Some(&Some(record)));
        assert_eq!(
            index.current().get(&(ProofStatus::Submitted, key.clone())),
            Some(&())
        );
        assert_eq!(
            index.undo().get(&(ProofStatus::Submitted, key.clone())),
            Some(&Some(()))
        );
    }
    state
}

fn capture(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let TableMaterializer::Single { capture, .. } = TABLE_MATERIALIZERS
        .iter()
        .find(|owner| owner.table_ids().any(|id| id == "world.proofs"))
        .unwrap()
    else {
        panic!("one original checked proof capture");
    };
    capture(state, limits)
}

#[test]
fn actual_catalog_rejects_proof_status_corruption_after_state_construction() {
    for previous in [false, true] {
        for defect in 0..5 {
            let mut state = state("stark/fri");
            let correct = (ProofStatus::Submitted, id("stark/fri"));
            // Corrupt only after the live writer and State construction.
            if matches!(defect, 0 | 2) {
                state.world.proofs_by_status = Storage::new();
            }
            match defect {
                0 => (),
                1 => {
                    state
                        .world
                        .proofs_by_status
                        .insert((ProofStatus::Verified, id("unknown")), ());
                }
                2 | 3 => {
                    state
                        .world
                        .proofs_by_status
                        .insert((ProofStatus::Verified, id("stark/fri")), ());
                }
                4 => {
                    state
                        .world
                        .proofs_by_status
                        .insert((ProofStatus::Submitted, id("unknown")), ());
                }
                _ => unreachable!(),
            }
            if previous {
                let mut block = state.world.proofs_by_status.block();
                block.insert(correct, ());
                block.remove((ProofStatus::Verified, id("unknown")));
                block.remove((ProofStatus::Verified, id("stark/fri")));
                block.remove((ProofStatus::Submitted, id("unknown")));
                block.commit();
            }
            state.ivm_execution_budget().set_limit_bytes(0);
            assert_eq!(
                capture(&state, native_test_support::limits()).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::Corrupt {
                        index: "world.proofs_by_status",
                        image: if previous {
                            GroupImage::Predecessor
                        } else {
                            GroupImage::Current
                        },
                        mismatch: match defect {
                            0 | 2 => GroupMismatch::MissingMember,
                            1 => GroupMismatch::ForeignMember,
                            3 | 4 => GroupMismatch::ForeignMember,
                            _ => unreachable!(),
                        },
                    }
                ))
            );
            let mut publication = state.state_view_publication();
            let guard = publication.begin();
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
fn actual_proof_catalog_keeps_original_pool_refusal_retry_and_final_owner() {
    let state = state("stark/fri");
    let original = state.ivm_execution_budget();
    let resident = original.reserved_bytes();
    original.set_limit_bytes(0);
    assert!(matches!(
        capture(&state, native_test_support::limits()),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(original.reserved_bytes(), resident);
    original.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture(&state, native_test_support::limits())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), "world.proofs");
    assert_eq!(snapshot.row_count(), 1);
    assert!(original.reserved_bytes() > resident);
    drop(snapshot);
    assert_eq!(original.reserved_bytes(), resident);
}

#[test]
fn long_proof_keys_and_physical_tombstones_only_require_more_local_capture_work() {
    for long_keys in [false, true] {
        let backend = if long_keys {
            "x".repeat(300)
        } else {
            "stark/fri".into()
        };
        let state = state(&backend);
        if !long_keys {
            let mut block = state.world.proofs.block();
            // Three predecessor status passes must each inspect every physical
            // tombstone. Their 1,536 row visits alone exceed the 1,024 work bound;
            // the logical current/predecessor contents still contain one proof.
            for tag in 0_u16..512 {
                let mut proof_hash = [0; 32];
                proof_hash[..2].copy_from_slice(&tag.to_be_bytes());
                block.remove(ProofId {
                    backend: "zz absent".into(),
                    proof_hash,
                });
            }
            block.commit();
            let source = state.world.proofs.try_committed_view_nonblocking().unwrap();
            assert_eq!(source.current().len(), 1);
            assert_eq!(source.undo().len(), 512);
            assert!(source.undo().iter().all(|(_, value)| value.is_none()));
        }
        assert_eq!(
            capture(&state, native_test_support::limits()).err(),
            Some(LeafError::GroupedOwnership(
                GroupedOwnershipError::WorkLimit
            ))
        );
        let mut limits = native_test_support::limits();
        limits.max_rows = 16;
        let snapshot = capture(&state, limits).unwrap().unwrap();
        assert_eq!(snapshot.row_count(), 1);
    }
}

#[path = "proof_status_tests/encoding_race.rs"]
mod encoding_race;
