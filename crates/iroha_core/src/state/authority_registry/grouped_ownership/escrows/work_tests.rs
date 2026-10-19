//! Literal original escrow geometry, complete physical tails and refusal custody.
use super::test_support::*;
use super::*;
use iroha_crypto::Hash;
use iroha_data_model::account::{MultisigMember, MultisigPolicy};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
use std::collections::BTreeMap;
fn other_id() -> EscrowId {
    EscrowId::new(Hash::new(b"other escrow key"))
}
fn absent_id() -> EscrowId {
    EscrowId::new(Hash::new(b"absent escrow key"))
}
fn absent_account() -> AccountId {
    AccountId::new(
        iroha_crypto::KeyPair::from_seed(
            b"escrow absent account".to_vec(),
            iroha_crypto::Algorithm::Ed25519,
        )
        .public_key()
        .clone(),
    )
}
fn multisig() -> AccountId {
    AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
            ],
        )
        .unwrap(),
    )
}
#[test]
fn independent_escrow_singletons_wide_keys_and_original_fixture_work_are_exact() {
    assert_eq!(ESCROW_WORK_PER_ROW, 2 * (134 + 134 + 135 + 135 + 68 + 68));
    for (buyer, exact) in [(false, 812), (true, 1348)] {
        let world = fixture(buyer);
        assert_eq!(world_work(&world), exact);
        assert_eq!(
            check(&world, exact - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, exact), Ok(()));
        assert!(world_work(&world) < TEST_WORK_ALLOWANCE);
    }
    for (buyer, exact) in [(false, 1212), (true, 2148)] {
        let mut world = fixture(buyer);
        let mut record = world.asset_escrows.view().get(&id()).unwrap().clone();
        record.seller = multisig();
        record.buyer = buyer.then(multisig);
        world.asset_escrows.insert(id(), record);
        world.rebuild_escrow_indexes();
        assert_eq!(world_work(&world), exact);
        assert_eq!(
            check(&world, exact - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, exact), Ok(()));
    }
    // Independent current/undo arithmetic admits the old migration/restore fixtures.
    for (initial_buyer, migration_work) in [(false, 2367), (true, 2300)] {
        let mut world = fixture(initial_buyer);
        let mut record = world.asset_escrows.view().get(&id()).unwrap().clone();
        record.seller = BOB_ID.clone();
        record.buyer = (!initial_buyer).then(|| ALICE_ID.clone());
        record.status = AssetEscrowStatus::Accepted;
        {
            let mut block = world.block();
            let mut tx =
                block.transaction_without_telemetry(crate::state::LaneConfig::default(), 0);
            tx.insert_asset_escrow_entry(record);
            tx.apply();
            block.commit();
        }
        let actual = world_work(&world);
        // Seller1210 + status682 + optional-buyer475/408 from actual native history.
        assert_eq!(actual, migration_work);
        assert!(actual < TEST_WORK_ALLOWANCE);
        assert_eq!(check(&world, actual), Ok(()));
        world.rebuild_escrow_indexes();
        assert_eq!(world_work(&world), migration_work);
        assert!(world_work(&world) < TEST_WORK_ALLOWANCE);
        world.block_and_revert().commit();
        assert!(world_work(&world) < TEST_WORK_ALLOWANCE);
    }
}
#[test]
fn escrow_physical_mask_lookup_and_member_tails_are_fully_prepaid() {
    let first = id();
    let second = other_id();
    let rows: Storage<EscrowId, u32> = [(first, 1), (second, 2)].into_iter().collect();
    {
        let mut block = rows.block();
        block.insert(first, 1);
        block.remove(absent_id());
        block.commit();
    }
    let view = rows.try_committed_view_nonblocking().unwrap();
    assert_eq!(
        (view.current_entries().len(), view.undo_entries().len()),
        (2, 2)
    );
    let exact = 2 + 4 * (1 + 32 + 32) + 2 * 2;
    assert_eq!(exact, 266);
    let mut seen = 0;
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut EscrowWork::bounded(exact),
            |_, _, _| {
                seen += 1;
                Ok(())
            }
        ),
        Ok(())
    );
    assert_eq!(seen, 2);
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut EscrowWork::bounded(exact - 1),
            |_, _, _| Ok(())
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    for key in [&first, &second] {
        assert_eq!(
            lookup(
                &view,
                GroupImage::Predecessor,
                key,
                &mut EscrowWork::bounded(393)
            ),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            lookup(
                &view,
                GroupImage::Predecessor,
                key,
                &mut EscrowWork::bounded(394)
            ),
            Ok(view.current().get(key))
        );
    }
    let members = [first.clone(), second.clone()];
    let member_rows: Storage<_, _> = members
        .iter()
        .map(|member| ((first.clone(), member.clone()), ()))
        .collect();
    let member_view = member_rows.try_committed_view_nonblocking().unwrap();
    for key in &members {
        assert_eq!(
            contains(
                &member_view,
                GroupImage::Current,
                &first,
                key,
                &mut EscrowWork::bounded(2 * (130) - 3)
            ),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            contains(
                &member_view,
                GroupImage::Current,
                &first,
                key,
                &mut EscrowWork::bounded(2 * (130) - 2)
            ),
            Ok(true)
        );
    }
    struct Count(usize);
    impl Iterator for Count {
        type Item = ();
        fn next(&mut self) -> Option<()> {
            self.0 += 1;
            Some(())
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (1, Some(1))
        }
    }
    impl ExactSizeIterator for Count {}
    let mut rows = Count(0);
    assert_eq!(
        next_physical(&mut rows, &mut EscrowWork::bounded(0)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(rows.0, 0);
    assert_eq!(
        next_physical(&mut rows, &mut EscrowWork::bounded(1)),
        Ok(Some(()))
    );
    assert_eq!(rows.0, 1);
}
#[test]
fn matching_current_with_two_absent_undo_rows_prepays_every_mask_and_option() {
    let rows = Storage::from_snapshot_parts(
        BTreeMap::from([(id(), 1_u32)]),
        BTreeMap::from([(id(), None), (absent_id(), None)]),
    );
    let view = rows.try_committed_view_nonblocking().unwrap();
    assert_eq!(
        lookup(
            &view,
            GroupImage::Predecessor,
            &id(),
            &mut EscrowWork::bounded(134)
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        lookup(
            &view,
            GroupImage::Predecessor,
            &id(),
            &mut EscrowWork::bounded(1 + 2 * (1 + 32 + 32) + 4)
        ),
        Ok(None)
    );
}
#[test]
fn complete_escrow_controller_id_status_and_optional_projection_geometry_is_paid() {
    let wide = multisig();
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let discarded = AccountId::new(key);
    for (left, right, exact, truth) in [
        (&*ALICE_ID, &*ALICE_ID, 68, true),
        (&wide, &wide, 168, true),
        (&*ALICE_ID, &wide, 118, false),
        (&discarded, &discarded, 4, true),
    ] {
        assert_eq!(
            equal(left, right, &mut EscrowWork::bounded(exact - 1)),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            equal(left, right, &mut EscrowWork::bounded(exact)),
            Ok(truth)
        );
    }
    assert_eq!(
        equal(&id(), &id(), &mut EscrowWork::bounded(63)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(equal(&id(), &id(), &mut EscrowWork::bounded(64)), Ok(true));
    assert_eq!(
        equal(
            &AssetEscrowStatus::Open,
            &AssetEscrowStatus::Accepted,
            &mut EscrowWork::bounded(1)
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        equal(
            &AssetEscrowStatus::Open,
            &AssetEscrowStatus::Accepted,
            &mut EscrowWork::bounded(2)
        ),
        Ok(false)
    );
    for present in [false, true] {
        let world = fixture(present);
        let view = world.asset_escrows.view();
        let record = view.get(&id()).unwrap();
        assert_eq!(
            buyer(record, &mut EscrowWork::bounded(0)),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            buyer(record, &mut EscrowWork::bounded(1)),
            Ok(record.buyer.as_ref())
        );
    }
}
#[test]
fn original_absent_source_and_membership_visits_have_literal_exact_boundaries() {
    for (buyer, base, delta) in [(false, 812, 335), (true, 1348, 402)] {
        let world = fixture(buyer);
        {
            let mut block = world.asset_escrows.block();
            block.remove(absent_id());
            block.commit();
        }
        assert_eq!(world_work(&world), base + delta);
        assert_eq!(
            check(&world, base + delta - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, base + delta), Ok(()));
    }
    for (buyer, source, base, delta) in [
        (true, 0, 1348, 270),
        (true, 1, 1348, 270),
        (true, 2, 1348, 138),
        (false, 1, 812, 2),
    ] {
        let world = fixture(buyer);
        match source {
            0 => {
                let mut block = world.asset_escrows_by_seller.block();
                block.remove((absent_account(), absent_id()));
                block.commit();
            }
            1 => {
                let mut block = world.asset_escrows_by_buyer.block();
                block.remove((absent_account(), absent_id()));
                block.commit();
            }
            2 => {
                let mut block = world.asset_escrows_by_status.block();
                block.remove((AssetEscrowStatus::Expired, absent_id()));
                block.commit();
            }
            _ => unreachable!(),
        }
        assert_eq!(world_work(&world), base + delta);
        assert_eq!(
            check(&world, base + delta - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, base + delta), Ok(()));
    }
}
#[test]
fn escrow_group_and_image_phases_keep_original_first_failure() {
    let mut world = fixture(true);
    let saved = omit_initial(
        &mut world.asset_escrows_by_seller,
        &(ALICE_ID.clone(), id()),
    );
    {
        let mut block = world.asset_escrows_by_seller.block();
        block.insert((ALICE_ID.clone(), id()), saved);
        block.commit();
    }
    omit_initial(&mut world.asset_escrows_by_buyer, &(BOB_ID.clone(), id()));
    assert_eq!(
        check(&world, TEST_WORK_ALLOWANCE),
        Err(corrupt(
            "world.asset_escrows_by_seller",
            true,
            GroupMismatch::MissingMember
        ))
    );
    let mut world = fixture(true);
    let saved = omit_initial(&mut world.asset_escrows_by_buyer, &(BOB_ID.clone(), id()));
    {
        let mut block = world.asset_escrows_by_buyer.block();
        block.insert((BOB_ID.clone(), id()), saved);
        block.commit();
    }
    omit_initial(
        &mut world.asset_escrows_by_status,
        &(AssetEscrowStatus::Open, id()),
    );
    assert_eq!(
        check(&world, TEST_WORK_ALLOWANCE),
        Err(corrupt(
            "world.asset_escrows_by_buyer",
            true,
            GroupMismatch::MissingMember
        ))
    );
}
#[test]
fn every_original_escrow_owner_precedes_success_work_and_corruption() {
    for source in 0..4 {
        for validation in 0..3 {
            let world = fixture(false);
            let checked = CheckedEscrows::capture(&world, TEST_WORK_ALLOWANCE).unwrap();
            publish(&world, source);
            let result = match validation {
                0 => Ok(()),
                1 => Err(GroupedOwnershipError::WorkLimit),
                _ => Err(corrupt(
                    "world.asset_escrows_by_status",
                    false,
                    GroupMismatch::ForeignMember,
                )),
            };
            assert!(matches!(
                checked.finish_validation(result),
                Err(GroupedOwnershipError::Publication(
                    PublicationPreparationError::Changed
                ))
            ));
        }
    }
}
fn publish(world: &World, source: usize) {
    match source {
        0 => world.asset_escrows.block().commit(),
        1 => world.asset_escrows_by_seller.block().commit(),
        2 => world.asset_escrows_by_buyer.block().commit(),
        3 => world.asset_escrows_by_status.block().commit(),
        _ => unreachable!(),
    }
}
#[test]
fn first_busy_escrow_source_retains_its_actual_release_before_later_changes() {
    let world = fixture(true);
    let checked = CheckedEscrows::capture(&world, TEST_WORK_ALLOWANCE).unwrap();
    publish(&world, 1);
    publish(&world, 3);
    let detached = world
        .asset_escrows
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let prepared = detached
        .try_prepare_publication(&world.asset_escrows, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("original preparation: {error:?}"));
    let original = checked
        .rows
        .try_matches_current(&world.asset_escrows)
        .unwrap_err();
    assert!(matches!(original, PublicationPreparationError::Busy(_)));
    assert_eq!(
        checked
            .finish_validation(Err(GroupedOwnershipError::WorkLimit))
            .err(),
        Some(GroupedOwnershipError::Publication(original))
    );
    drop(prepared);
    assert_eq!(check(&world, TEST_WORK_ALLOWANCE), Ok(()));
}
#[test]
fn retained_malformed_keys_and_unused_escrow_fields_add_no_new_authority() {
    let mut world = fixture(false);
    let mut record = world.asset_escrows.view().get(&id()).unwrap().clone();
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    record.seller = AccountId::new(key);
    record.id = other_id();
    record.amount = iroha_primitives::numeric::Quantity::zero();
    record.status = AssetEscrowStatus::Accepted;
    world.accounts = Storage::default();
    world.asset_escrows.insert(id(), record);
    world.rebuild_escrow_indexes();
    assert_eq!(check(&world, TEST_WORK_ALLOWANCE), Ok(()));
    let source = include_str!("../escrows.rs");
    let source = source.split("#[cfg(test)]").next().unwrap();
    for retired in [
        ".get(",
        ".contains(",
        ".contains_key(",
        ".range(",
        ".clone(",
        ".sort(",
        ".collect(",
        "::parse",
    ] {
        assert!(
            !source.contains(retired),
            "unfunded escrow access: {retired}"
        );
    }
}
