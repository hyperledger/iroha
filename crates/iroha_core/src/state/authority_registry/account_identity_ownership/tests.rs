//! Exact native identity histories, bounded traversal and consumed account capture.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::capture_accounts_table_once,
            leaf::{LeafError, LeafLimits},
        },
    },
};
use iroha_crypto::Hash;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
use std::collections::BTreeMap;

use super::test_support::*;

fn check_error(world: &World) -> IdentityOwnershipError {
    without_allocations(|| CheckedAccountIdentities::capture(world, 16_777_216))
        .err()
        .unwrap()
}

#[test]
fn reassignment_retains_original_current_predecessor_and_implicit_accounts() {
    let world = fixture();
    let mut accounts = world.accounts.block();
    let mut uaids = world.uaid_accounts.block();
    let mut opaques = world.opaque_uaids.block();
    accounts.insert(ALICE_ID.clone(), details(None, vec![]));
    accounts.insert(BOB_ID.clone(), details(Some(uaid()), vec![opaque(1)]));
    uaids.insert(uaid(), BOB_ID.clone());
    opaques.insert(opaque(1), uaid());
    accounts.commit();
    uaids.commit();
    opaques.commit();
    let checked =
        without_allocations(|| CheckedAccountIdentities::capture(&world, 16_777_216)).unwrap();
    assert_eq!(
        checked.accounts().get(&*ALICE_ID).unwrap().as_ref().uaid(),
        None
    );
    assert_eq!(
        get_at(checked.accounts(), IdentityImage::Predecessor, &*ALICE_ID)
            .unwrap()
            .as_ref()
            .uaid(),
        Some(&uaid())
    );
    assert_eq!(
        get_at(&checked.uaids, IdentityImage::Predecessor, &uaid()),
        Some(&*ALICE_ID)
    );
    assert_eq!(checked.opaques.undo().get(&opaque(1)), Some(&Some(uaid())));
    assert!(without_allocations(|| checked.matches_current()).unwrap());
    drop(checked);
    // Replacement restores the exact prior account, inverse and redundant touch.
    world.block_and_revert().commit();
    let checked =
        without_allocations(|| CheckedAccountIdentities::capture(&world, 16_777_216)).unwrap();
    assert_eq!(checked.uaids.get(&uaid()), Some(&*ALICE_ID));
}

#[test]
fn current_indexes_require_exact_bidirectional_membership() {
    for (mutation, expected) in [
        (0, IdentityMismatch::UaidBinding),
        (1, IdentityMismatch::UaidBinding),
        (2, IdentityMismatch::OpaqueBinding),
        (3, IdentityMismatch::OpaqueBinding),
        (4, IdentityMismatch::ForeignUaid),
        (5, IdentityMismatch::ForeignOpaque),
    ] {
        let mut world = fixture();
        let other = UniversalAccountId::from_hash(Hash::new(b"other identity uaid"));
        match mutation {
            0 => world.uaid_accounts = Storage::default(),
            1 => {
                world.uaid_accounts.insert(uaid(), BOB_ID.clone());
            }
            2 => world.opaque_uaids = Storage::default(),
            3 => {
                world.opaque_uaids.insert(opaque(1), other);
            }
            4 => {
                world.uaid_accounts.insert(other, BOB_ID.clone());
            }
            5 => {
                world.opaque_uaids.insert(opaque(2), uaid());
            }
            _ => unreachable!(),
        }
        assert_eq!(
            check_error(&world),
            corrupt(IdentityImage::Current, expected)
        );
    }
}

#[test]
fn duplicate_and_unbound_sources_cannot_hide_behind_valid_index_rows() {
    for (mutation, expected) in [
        (0, IdentityMismatch::DuplicateOpaque),
        (1, IdentityMismatch::UaidBinding),
        (2, IdentityMismatch::OpaqueBinding),
        (3, IdentityMismatch::OpaqueWithoutUaid),
    ] {
        let mut world = fixture();
        match mutation {
            0 => {
                world.accounts.insert(
                    ALICE_ID.clone(),
                    details(Some(uaid()), vec![opaque(1), opaque(1)]),
                );
            }
            1 => {
                world
                    .accounts
                    .insert(BOB_ID.clone(), details(Some(uaid()), vec![]));
            }
            2 => {
                let other = UniversalAccountId::from_hash(Hash::new(b"duplicate opaque uaid"));
                world
                    .accounts
                    .insert(BOB_ID.clone(), details(Some(other), vec![opaque(1)]));
                world.uaid_accounts.insert(other, BOB_ID.clone());
            }
            3 => {
                world
                    .accounts
                    .insert(BOB_ID.clone(), details(None, vec![opaque(2)]));
            }
            _ => unreachable!(),
        }
        assert_eq!(
            check_error(&world),
            corrupt(IdentityImage::Current, expected)
        );
    }
    // An extra reverse row cannot compensate for duplicate source cardinality:
    // reverse membership is checked before comparing counts.
    let mut world = fixture();
    world.accounts.insert(
        ALICE_ID.clone(),
        details(Some(uaid()), vec![opaque(1), opaque(1)]),
    );
    world.opaque_uaids.insert(opaque(2), uaid());
    assert_eq!(
        check_error(&world),
        corrupt(IdentityImage::Current, IdentityMismatch::ForeignOpaque)
    );
}

#[test]
fn correct_current_indexes_do_not_hide_missing_or_foreign_predecessors() {
    for (mutation, expected) in [
        (0, IdentityMismatch::UaidBinding),
        (1, IdentityMismatch::OpaqueBinding),
        (2, IdentityMismatch::ForeignUaid),
        (3, IdentityMismatch::ForeignOpaque),
        (4, IdentityMismatch::DuplicateOpaque),
    ] {
        let mut world = fixture();
        match mutation {
            0 => {
                world.uaid_accounts = Storage::from_snapshot_parts(
                    BTreeMap::from([(uaid(), ALICE_ID.clone())]),
                    BTreeMap::from([(uaid(), None)]),
                )
            }
            1 => {
                world.opaque_uaids = Storage::from_snapshot_parts(
                    BTreeMap::from([(opaque(1), uaid())]),
                    BTreeMap::from([(opaque(1), None)]),
                )
            }
            2 => {
                let rows = world
                    .accounts
                    .view()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect();
                world.accounts =
                    Storage::from_snapshot_parts(rows, BTreeMap::from([(ALICE_ID.clone(), None)]));
            }
            3 => {
                world.opaque_uaids = Storage::from_snapshot_parts(
                    BTreeMap::from([(opaque(1), uaid())]),
                    BTreeMap::from([(opaque(2), Some(uaid()))]),
                )
            }
            4 => {
                let rows = world
                    .accounts
                    .view()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect();
                world.accounts = Storage::from_snapshot_parts(
                    rows,
                    BTreeMap::from([(
                        ALICE_ID.clone(),
                        Some(details(Some(uaid()), vec![opaque(1), opaque(1)])),
                    )]),
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(
            check_error(&world),
            corrupt(IdentityImage::Predecessor, expected)
        );
    }
}

#[test]
fn work_charges_physical_tombstones_and_each_source_and_reverse_member() {
    let world = fixture();
    // Complete actual advances/comparisons over both original images.
    let exact = exact_world_work(&world);
    for bound in (0..12).chain([exact - 1]) {
        assert_eq!(
            without_allocations(|| CheckedAccountIdentities::capture(&world, bound))
                .err()
                .unwrap(),
            IdentityOwnershipError::WorkLimit
        );
    }
    drop(without_allocations(|| CheckedAccountIdentities::capture(&world, exact)).unwrap());
    let mut world = World::new();
    world.accounts =
        Storage::from_snapshot_parts(BTreeMap::new(), BTreeMap::from([(ALICE_ID.clone(), None)]));
    world.uaid_accounts =
        Storage::from_snapshot_parts(BTreeMap::new(), BTreeMap::from([(uaid(), None)]));
    world.opaque_uaids =
        Storage::from_snapshot_parts(BTreeMap::new(), BTreeMap::from([(opaque(1), None)]));
    for bound in 0..3 {
        assert_eq!(
            without_allocations(|| CheckedAccountIdentities::capture(&world, bound))
                .err()
                .unwrap(),
            IdentityOwnershipError::WorkLimit
        );
    }
    drop(without_allocations(|| CheckedAccountIdentities::capture(&world, 3)).unwrap());
    let mut world = fixture();
    world.accounts.insert(
        ALICE_ID.clone(),
        details(Some(uaid()), (0..64).map(opaque).collect()),
    );
    crate::state::account_identity_restore::rebuild(&mut world).unwrap();
    assert_eq!(
        without_allocations(|| CheckedAccountIdentities::capture(&world, 64))
            .err()
            .unwrap(),
        IdentityOwnershipError::WorkLimit
    );
    drop(without_allocations(|| CheckedAccountIdentities::capture(&world, 16_777_216)).unwrap());
}

#[test]
fn equal_value_publication_of_every_original_dependency_invalidates_capture() {
    for source in 0..3 {
        let world = fixture();
        let checked =
            without_allocations(|| CheckedAccountIdentities::capture(&world, 16_777_216)).unwrap();
        match source {
            0 => {
                let mut block = world.accounts.block();
                block.insert(ALICE_ID.clone(), block.get(&*ALICE_ID).unwrap().clone());
                block.commit();
            }
            1 => {
                let mut block = world.uaid_accounts.block();
                block.insert(uaid(), ALICE_ID.clone());
                block.commit();
            }
            2 => {
                let mut block = world.opaque_uaids.block();
                block.insert(opaque(1), uaid());
                block.commit();
            }
            _ => unreachable!(),
        }
        assert!(!without_allocations(|| checked.matches_current()).unwrap());
    }
}

#[test]
fn consumed_accounts_capture_checks_sources_before_allocating_leaves() {
    let mut world = fixture();
    world.opaque_uaids.insert(opaque(2), uaid());
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let limits = LeafLimits {
        max_tables: 1,
        max_rows: 16,
        max_payload_bytes: 16_384,
        max_ordered_table_bytes: 32_768,
        max_streamed_value_bytes: 131_072,
    };
    let pool = state.ivm_execution_budget();
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture_accounts_table_once(&state, limits),
        Err(LeafError::IdentityOwnership(
            IdentityOwnershipError::Corrupt { .. }
        ))
    ));
    crate::state::account_identity_restore::rebuild(&mut state.world).unwrap();
    assert!(matches!(
        capture_accounts_table_once(
            &state,
            LeafLimits {
                max_rows: 0,
                ..limits
            }
        ),
        Err(LeafError::IdentityOwnership(
            IdentityOwnershipError::WorkLimit
        ))
    ));
    assert!(matches!(
        capture_accounts_table_once(&state, limits),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    pool.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture_accounts_table_once(&state, limits)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), "world.accounts");
    assert_eq!(snapshot.row_count(), 2);
}

#[test]
fn exact_identity_reference_keeps_implicit_accounts_and_complete_controller_work() {
    assert_eq!(ACCOUNT_IDENTITY_WORK_PER_ROW, 1196);
    for (world, exact) in [(single(), 1196), (fixture(), 1474)] {
        assert_eq!(exact_world_work(&world), exact);
        assert_eq!(
            without_allocations(|| CheckedAccountIdentities::capture(&world, exact - 1)).err(),
            Some(IdentityOwnershipError::WorkLimit)
        );
        without_allocations(|| CheckedAccountIdentities::capture(&world, exact)).unwrap();
    }
    let mut implicit = World::default();
    implicit
        .accounts
        .insert(ALICE_ID.clone(), details(None, vec![]));
    assert_eq!(exact_world_work(&implicit), 2);
    without_allocations(|| CheckedAccountIdentities::capture(&implicit, 2)).unwrap();
}

#[test]
fn every_physical_mask_and_lookup_candidate_is_prepaid_after_a_match() {
    let other = UniversalAccountId::from_hash(Hash::new(b"physical tail"));
    #[expect(
        clippy::zero_sized_map_values,
        reason = "Storage snapshot parts encode current unit-valued membership rows and their separate undo map"
    )]
    let rows = Storage::from_snapshot_parts(
        BTreeMap::from([(uaid(), ())]),
        BTreeMap::from([(uaid(), None), (other, None)]),
    );
    let original = rows.try_committed_view_nonblocking().unwrap();
    let inspected = std::cell::Cell::new(0);
    for bound in [132, 133] {
        let result = without_allocations(|| {
            visit_original(
                &original,
                IdentityImage::Predecessor,
                &mut Work(bound),
                |_, _, _| {
                    inspected.set(inspected.get() + 1);
                    Ok(())
                },
            )
        });
        assert_eq!(
            result,
            if bound == 133 {
                Ok(())
            } else {
                Err(IdentityOwnershipError::WorkLimit)
            }
        );
        assert_eq!(inspected.get(), 0);
    }
    let rows = Storage::from_iter([(uaid(), 1_u8), (other, 2)]);
    let original = rows.try_committed_view_nonblocking().unwrap();
    let key = original.current_entries().next().unwrap().0;
    assert_eq!(
        without_allocations(|| lookup_original(
            &original,
            IdentityImage::Current,
            key,
            &mut Work(129)
        )),
        Err(IdentityOwnershipError::WorkLimit)
    );
    assert!(
        without_allocations(|| lookup_original(
            &original,
            IdentityImage::Current,
            key,
            &mut Work(130)
        ))
        .unwrap()
        .is_some()
    );
    let visits = std::cell::Cell::new(0);
    let values = [1];
    let mut physical = values.iter().inspect(|_| visits.set(visits.get() + 1));
    assert_eq!(
        next_physical(&mut physical, &mut Work(0)),
        Err(IdentityOwnershipError::WorkLimit)
    );
    assert_eq!(visits.get(), 0);
}

#[test]
fn full_reverse_opaque_tail_and_wide_controller_geometry_are_admitted() {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let mut members = [opaque(1), opaque(2)];
    members.sort();
    members.reverse(); // final native opaque row matches the first source member
    let mut world = single();
    world
        .accounts
        .insert(ALICE_ID.clone(), details(Some(uaid()), members.to_vec()));
    crate::state::account_identity_restore::rebuild(&mut world).unwrap();
    assert_eq!(exact_world_work(&world), 2376);
    assert_eq!(
        without_allocations(|| CheckedAccountIdentities::capture(&world, 2375)).err(),
        Some(IdentityOwnershipError::WorkLimit)
    );
    without_allocations(|| CheckedAccountIdentities::capture(&world, 2376)).unwrap();
    let owner = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
            ],
        )
        .unwrap(),
    );
    let mut world = World::default();
    world
        .accounts
        .insert(owner.clone(), details(Some(uaid()), vec![opaque(1)]));
    world.uaid_accounts.insert(uaid(), owner.clone());
    world.opaque_uaids.insert(opaque(1), uaid());
    assert_eq!(exact_world_work(&world), 1796);
    assert_eq!(
        without_allocations(|| CheckedAccountIdentities::capture(&world, 1795)).err(),
        Some(IdentityOwnershipError::WorkLimit)
    );
    without_allocations(|| CheckedAccountIdentities::capture(&world, 1796)).unwrap();
    for (left, right, exact) in [
        (ALICE_ID.clone(), BOB_ID.clone(), 68),
        (ALICE_ID.clone(), owner.clone(), 118),
        (owner.clone(), owner, 168),
    ] {
        assert_eq!(
            without_allocations(|| equal(&left, &right, &mut Work(exact - 1))),
            Err(IdentityOwnershipError::WorkLimit)
        );
        assert_eq!(
            without_allocations(|| equal(&left, &right, &mut Work(exact))).unwrap(),
            left == right
        );
    }
}

#[test]
fn malformed_typed_account_equality_keeps_membership_without_validity_or_ord() {
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let owner = AccountId::new(key);
    let mut world = World::default();
    world
        .accounts
        .insert(owner.clone(), details(Some(uaid()), vec![opaque(1)]));
    world.uaid_accounts.insert(uaid(), owner);
    world.opaque_uaids.insert(opaque(1), uaid());
    assert_eq!(exact_world_work(&world), 812);
    without_allocations(|| CheckedAccountIdentities::capture(&world, 812)).unwrap();
    world.uaid_accounts = Storage::from_iter([(uaid(), ALICE_ID.clone())]);
    assert_eq!(
        check_error(&world),
        corrupt(IdentityImage::Current, IdentityMismatch::UaidBinding)
    );
}

#[test]
fn each_original_identity_publication_precedes_every_validation_outcome() {
    for source in 0..3 {
        for result in [
            Ok(()),
            Err(IdentityOwnershipError::WorkLimit),
            Err(corrupt(
                IdentityImage::Predecessor,
                IdentityMismatch::ForeignOpaque,
            )),
        ] {
            let world = fixture();
            let checked = CheckedAccountIdentities::capture(&world, 16_777_216).unwrap();
            match source {
                0 => world.accounts.block().commit(),
                1 => world.uaid_accounts.block().commit(),
                2 => world.opaque_uaids.block().commit(),
                _ => unreachable!(),
            }
            assert_eq!(
                without_allocations(|| checked.finish_validation(result)).err(),
                Some(IdentityOwnershipError::Publication(
                    PublicationPreparationError::Changed
                ))
            );
        }
    }
}
