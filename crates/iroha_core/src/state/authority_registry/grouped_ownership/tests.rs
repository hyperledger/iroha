//! Exact grouped images, native ownership, work bounds and consumed State capture.

use super::nft_rwa_test_support::*;
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::{capture_nfts_once, capture_rwas_once},
            leaf::{LeafError, LeafLimits},
        },
    },
    test_allocations::allocations_during,
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
use norito::codec::Encode;

pub(in crate::state) fn without_allocations<T>(run: impl FnOnce() -> T) -> T {
    let mut result = None;
    assert_eq!(allocations_during(|| result = Some(run())), 0);
    result.unwrap()
}

#[test]
fn native_current_predecessor_and_replacement_retain_all_five_groups() {
    let world = fixture();
    let old_nft = world.nfts.view().get(&nft_id()).unwrap().clone();
    let old_rwa = world.rwas.view().get(&rwa_id()).unwrap().clone();
    {
        let mut block = world.block();
        let mut tx = block.transaction_without_telemetry(crate::state::LaneConfig::default(), 0);
        let mut nft = old_nft.clone();
        nft.owned_by = BOB_ID.clone();
        tx.insert_nft_entry(nft_id(), nft);
        let mut rwa = old_rwa.clone();
        rwa.owned_by = BOB_ID.clone();
        rwa.status = Some("active".parse().unwrap());
        rwa.is_frozen = true;
        tx.insert_rwa_entry(rwa_id(), rwa);
        tx.apply();
        block.commit();
    }
    let nft_work = world_work(&world, false);
    let nfts = without_allocations(|| CheckedNfts::capture(&world, nft_work)).unwrap();
    let rwa_work = world_work(&world, true);
    let rwas = without_allocations(|| CheckedRwas::capture(&world, rwa_work)).unwrap();
    assert_eq!(nfts.rows().get(&nft_id()).unwrap().owned_by, *BOB_ID);
    assert_eq!(
        get_at(nfts.rows(), GroupImage::Predecessor, &nft_id())
            .unwrap()
            .encode(),
        old_nft.encode()
    );
    assert_eq!(
        get_at(rwas.rows(), GroupImage::Predecessor, &rwa_id())
            .unwrap()
            .encode(),
        old_rwa.encode()
    );
    assert!(nfts.matches_current().unwrap());
    assert!(rwas.matches_current().unwrap());
    drop((nfts, rwas));
    world.block_and_revert().commit();
    assert_eq!(check(&world, false), Ok(()));
    assert_eq!(check(&world, true), Ok(()));
}

#[test]
fn every_index_rejects_missing_current_or_predecessor_membership() {
    for index in 0..5 {
        for previous in [false, true] {
            let mut world = fixture();
            macro_rules! remove {
                ($field:ident, $key:expr, $member:expr) => {{
                    world.$field = Storage::default();
                    if previous {
                        let mut block = world.$field.block();
                        block.insert($key, BTreeSet::from([$member]));
                        block.commit();
                    }
                }};
            }
            let name = match index {
                0 => {
                    remove!(nfts_by_owner, ALICE_ID.clone(), nft_id());
                    "world.nfts_by_owner"
                }
                1 => {
                    remove!(nfts_by_domain, domain(), nft_id());
                    "world.nfts_by_domain"
                }
                2 => {
                    remove!(rwas_by_owner, ALICE_ID.clone(), rwa_id());
                    "world.rwas_by_owner"
                }
                3 => {
                    remove!(rwas_by_status, None, rwa_id());
                    "world.rwas_by_status"
                }
                4 => {
                    remove!(rwas_by_frozen, false, rwa_id());
                    "world.rwas_by_frozen"
                }
                _ => unreachable!(),
            };
            assert_eq!(
                check(&world, index >= 2),
                Err(GroupedOwnershipError::Corrupt {
                    index: name,
                    image: if previous {
                        GroupImage::Predecessor
                    } else {
                        GroupImage::Current
                    },
                    mismatch: GroupMismatch::MissingMember,
                })
            );
        }
    }
}

#[test]
fn empty_groups_and_foreign_members_cannot_compensate_for_valid_members() {
    for empty in [true, false] {
        let mut world = fixture();
        world.nfts_by_owner.insert(
            BOB_ID.clone(),
            if empty {
                BTreeSet::new()
            } else {
                BTreeSet::from([nft_id()])
            },
        );
        world.rwas_by_frozen.insert(
            true,
            if empty {
                BTreeSet::new()
            } else {
                BTreeSet::from([rwa_id()])
            },
        );
        for rwa in [false, true] {
            assert_eq!(
                check(&world, rwa),
                Err(GroupedOwnershipError::Corrupt {
                    index: if rwa {
                        "world.rwas_by_frozen"
                    } else {
                        "world.nfts_by_owner"
                    },
                    image: GroupImage::Current,
                    mismatch: if empty {
                        GroupMismatch::EmptyGroup
                    } else {
                        GroupMismatch::ForeignMember
                    },
                })
            );
        }
    }
}

#[test]
fn exact_work_charges_every_physical_row_and_absent_undo_entry() {
    let world = fixture();
    // Each singleton group pays physical scans, full two-operand typed comparisons
    // and complete member tails in both original images.
    assert!(CheckedNfts::capture(&world, 732).is_ok());
    assert!(matches!(
        CheckedNfts::capture(&world, 731),
        Err(GroupedOwnershipError::WorkLimit)
    ));
    assert!(CheckedRwas::capture(&world, 1482).is_ok());
    assert!(matches!(
        CheckedRwas::capture(&world, 1481),
        Err(GroupedOwnershipError::WorkLimit)
    ));
    {
        let mut block = world.nfts.block();
        block.remove(NftId::new(domain(), "absent".parse().unwrap()));
        block.commit();
    }
    // The Name6 absent preimage adds44 to each of four predecessor source visits.
    assert!(matches!(
        CheckedNfts::capture(&world, 907),
        Err(GroupedOwnershipError::WorkLimit)
    ));
    assert!(CheckedNfts::capture(&world, 908).is_ok());
}

#[test]
fn every_original_native_identity_is_checked_even_for_noop_publication() {
    for index in 0..7 {
        let world = fixture();
        let nfts = CheckedNfts::capture(&world, world_work(&world, false)).unwrap();
        let rwas = CheckedRwas::capture(&world, world_work(&world, true)).unwrap();
        match index {
            0 => world.nfts.block().commit(),
            1 => world.nfts_by_owner.block().commit(),
            2 => world.nfts_by_domain.block().commit(),
            3 => world.rwas.block().commit(),
            4 => world.rwas_by_owner.block().commit(),
            5 => world.rwas_by_status.block().commit(),
            6 => world.rwas_by_frozen.block().commit(),
            _ => unreachable!(),
        }
        assert_eq!(nfts.matches_current().unwrap(), index >= 3);
        assert_eq!(rwas.matches_current().unwrap(), index < 3);
    }
}

#[test]
fn actual_state_capture_consumes_exact_groups_and_keeps_local_work_refusal() {
    let mut world = fixture();
    // A current-valid source with a missing predecessor bucket is rejected
    // before canonical encoding even though no live row is omitted.
    world.rwas_by_status = Storage::default();
    {
        let mut block = world.rwas_by_status.block();
        block.insert(None, BTreeSet::from([rwa_id()]));
        block.commit();
    }
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let limits = LeafLimits {
        max_tables: 1,
        max_rows: 16,
        max_payload_bytes: 16384,
        max_ordered_table_bytes: 32768,
        max_streamed_value_bytes: 131_072,
    };
    let pool = state.ivm_execution_budget();
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture_rwas_once(&state, limits),
        Err(LeafError::GroupedOwnership(
            GroupedOwnershipError::Corrupt {
                image: GroupImage::Predecessor,
                ..
            }
        ))
    ));
    assert!(matches!(
        capture_nfts_once(
            &state,
            LeafLimits {
                max_rows: 0,
                ..limits
            }
        ),
        Err(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    ));
    state.world.rebuild_rwa_indexes();
    for capture in [capture_nfts_once, capture_rwas_once] {
        assert!(matches!(
            capture(&state, limits),
            Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
        ));
    }
    pool.set_limit_bytes(16 * 1024 * 1024);
    for (capture, expected) in [capture_nfts_once, capture_rwas_once]
        .into_iter()
        .zip(["world.nfts", "world.rwas"])
    {
        let snapshot = capture(&state, limits).unwrap().unwrap();
        assert_eq!(snapshot.table_id(), expected);
        assert_eq!(snapshot.row_count(), 1);
    }
}
