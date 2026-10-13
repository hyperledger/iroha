//! Literal full geometry, physical tails, original phase order and native identity.
use super::test_support::*;
use super::*;
use iroha_data_model::{
    account::{MultisigMember, MultisigPolicy},
    prelude::Registrable,
};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
#[test]
fn independent_balance_reference_and_original_fixture_boundaries_are_exact() {
    for (context, exact) in [(false, 2144), (true, 2838)] {
        let world = fixture(context);
        assert_eq!(world_work(&world), exact);
        assert_eq!(
            check(&world, exact - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, exact), Ok(()));
    }
    let text = "d".repeat(63);
    let domain = DomainId::try_new(&text, &text).unwrap();
    let mut world = fixture(false);
    world.domains =
        Storage::from_iter([(domain.clone(), Domain::new(domain.clone()).build(&ALICE_ID))]);
    world.asset_definitions.insert(
        definition("coin"),
        AssetDefinition::numeric(
            definition("coin"),
            "coin",
            AssetBalancePolicy::Global,
            Some(domain.clone()),
        )
        .build(&ALICE_ID),
    );
    world.rebuild_asset_definition_indexes().unwrap();
    // No undo: source137/inverse138; source173/inverse174; references850;
    // domain392; holder104; nonzero105, with actual domain geometry63+63.
    assert_eq!(
        ASSET_BALANCE_WORK_PER_ROW,
        2 * (275 + 347 + 850 + 392 + 104 + 105)
    );
    assert_eq!(world_work(&world), 4146);
    assert_eq!(check(&world, 4145), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 4146), Ok(()));
    world.asset_definitions.insert(
        definition("coin"),
        AssetDefinition::numeric(
            definition("coin"),
            "coin",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain),
        )
        .build(&ALICE_ID),
    );
    // Original Restricted condition accesses its first Option before the always-accessed second Option.
    assert_eq!(world_work(&world), 4146 + 2);
    assert_eq!(check(&world, 4147), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 4148), Ok(()));
}
#[test]
fn every_asset_physical_mask_lookup_and_member_tail_is_prepaid() {
    let first = id();
    let second = AssetId::new(definition("second"), ALICE_ID.clone());
    let absent = AssetId::new(definition("absent"), ALICE_ID.clone());
    let rows: Storage<AssetId, u32> = [(first.clone(), 1), (second.clone(), 2)]
        .into_iter()
        .collect();
    {
        let mut block = rows.block();
        block.insert(first.clone(), 1);
        block.remove(absent);
        block.commit();
    }
    let view = rows.try_committed_view_nonblocking().unwrap();
    assert_eq!(
        (view.current_entries().len(), view.undo_entries().len()),
        (2, 2)
    );
    let physical = 2 + 4 * (1 + 51 + 51) + 2 * 2;
    let mut seen = 0;
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut AssetBalanceWork::bounded(physical),
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
            &mut AssetBalanceWork::bounded(physical - 1),
            |_, _, _| Ok(())
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    for key in [&first, &second] {
        let exact = physical + 2 * (51 + 51);
        assert_eq!(
            lookup(
                &view,
                GroupImage::Predecessor,
                key,
                &mut AssetBalanceWork::bounded(exact - 1)
            ),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            lookup(
                &view,
                GroupImage::Predecessor,
                key,
                &mut AssetBalanceWork::bounded(exact)
            ),
            Ok(view.current().get(key))
        );
    }
    let members = BTreeSet::from([first, second]);
    for key in &members {
        assert_eq!(
            contains(&members, key, &mut AssetBalanceWork::bounded(205)),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            contains(&members, key, &mut AssetBalanceWork::bounded(206)),
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
        next_physical(&mut rows, &mut AssetBalanceWork::bounded(0)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(rows.0, 0);
    assert_eq!(
        next_physical(&mut rows, &mut AssetBalanceWork::bounded(1)),
        Ok(Some(()))
    );
    assert_eq!(rows.0, 1);
}
#[test]
fn complete_asset_account_domain_scope_geometry_preserves_refusal() {
    let global = id();
    let scoped = AssetId::with_scope(
        definition("coin"),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    for (left, right, exact, truth) in [
        (&global, &global, 102, true),
        (&global, &scoped, 110, false),
        (&scoped, &scoped, 118, true),
    ] {
        assert_eq!(
            equal(left, right, &mut AssetBalanceWork::bounded(exact - 1)),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            equal(left, right, &mut AssetBalanceWork::bounded(exact)),
            Ok(truth)
        );
    }
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
            ],
        )
        .unwrap(),
    );
    let exact = 2 * (12 + 2 + 2 * (3 + 32));
    assert_eq!(
        equal(
            &multisig,
            &multisig,
            &mut AssetBalanceWork::bounded(exact - 1)
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        equal(&multisig, &multisig, &mut AssetBalanceWork::bounded(exact)),
        Ok(true)
    );
    let left = DomainId::try_new("prefix", "universal").unwrap();
    let right = DomainId::try_new("prefix", "universe").unwrap();
    let exact = 6 + 9 + 6 + 8;
    assert_eq!(
        equal(&left, &right, &mut AssetBalanceWork::bounded(exact - 1)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        equal(&left, &right, &mut AssetBalanceWork::bounded(exact)),
        Ok(false)
    );
}
#[test]
fn predecessor_partition_search_funds_masked_absent_and_matching_full_tails() {
    use std::collections::BTreeMap;
    let global = id();
    let scoped = AssetId::with_scope(
        definition("coin"),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    let rows = Storage::from_snapshot_parts(
        BTreeMap::from([(global.clone(), value(&global, 5))]),
        BTreeMap::from([(global.clone(), None), (scoped, None)]),
    );
    let view = rows.try_committed_view_nonblocking().unwrap();
    for nonzero in [false, true] {
        assert_eq!(
            has_partition(
                &view,
                GroupImage::Predecessor,
                &ALICE_ID,
                &definition("coin"),
                nonzero,
                &mut AssetBalanceWork::bounded(218)
            ),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            has_partition(
                &view,
                GroupImage::Predecessor,
                &ALICE_ID,
                &definition("coin"),
                nonzero,
                &mut AssetBalanceWork::bounded(1 + 103 + 111 + 4)
            ),
            Ok(false)
        );
    }
    let second = AssetId::new(definition("second"), BOB_ID.clone());
    let rows: Storage<AssetId, AssetValue> = [
        (global.clone(), value(&global, 5)),
        (second.clone(), value(&second, 7)),
    ]
    .into_iter()
    .collect();
    let view = rows.try_committed_view_nonblocking().unwrap();
    for key in [&global, &second] {
        for nonzero in [false, true] {
            let exact = 2 + 2 * (34 + 34 + 16 + 16) + u64::from(nonzero);
            assert_eq!(
                has_partition(
                    &view,
                    GroupImage::Current,
                    key.account(),
                    key.definition(),
                    nonzero,
                    &mut AssetBalanceWork::bounded(exact - 1)
                ),
                Err(GroupedOwnershipError::WorkLimit)
            );
            assert_eq!(
                has_partition(
                    &view,
                    GroupImage::Current,
                    key.account(),
                    key.definition(),
                    nonzero,
                    &mut AssetBalanceWork::bounded(exact)
                ),
                Ok(true)
            );
        }
    }
}
#[test]
fn asset_group_reference_and_image_phases_keep_original_failure_precedence() {
    let mut world = fixture(true);
    let saved = omit_initial(&mut world.asset_definition_assets, &definition("coin"));
    {
        let mut block = world.asset_definition_assets.block();
        block.insert(definition("coin"), saved);
        block.commit();
    }
    omit_initial(&mut world.assets_by_account, &ALICE_ID);
    assert_eq!(
        check(&world, 16_777_216),
        Err(corrupt(
            "world.asset_definition_assets",
            true,
            GroupMismatch::MissingMember
        ))
    );
    let mut world = fixture(true);
    let saved = omit_initial(&mut world.assets_by_account, &ALICE_ID);
    {
        let mut block = world.assets_by_account.block();
        block.insert(ALICE_ID.clone(), saved);
        block.commit();
    }
    omit_initial(&mut world.asset_definitions, &definition("coin"));
    assert_eq!(
        check(&world, 16_777_216),
        Err(corrupt(
            "world.assets_by_account",
            true,
            GroupMismatch::MissingMember
        ))
    );
}
#[test]
fn retained_malformed_keys_and_unused_values_add_no_asset_authority() {
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let account = AccountId::new(key);
    let asset = AssetId::new(definition("coin"), account.clone());
    let mut world = fixture(false);
    world.accounts = Storage::default();
    world.assets = Storage::from_iter([(asset.clone(), value(&asset, 0))]);
    // A mismatched definition body id and an unused malformed domain remain outside this relation.
    world.asset_definitions.insert(
        definition("coin"),
        AssetDefinition::numeric(
            definition("different"),
            "unused",
            AssetBalancePolicy::Global,
            None,
        )
        .build(&BOB_ID),
    );
    world.rebuild_asset_definition_indexes().unwrap();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    assert_eq!(
        equal(&account, &account, &mut AssetBalanceWork::bounded(3)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        equal(&account, &account, &mut AssetBalanceWork::bounded(4)),
        Ok(true)
    );
    let source = include_str!("../assets.rs");
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
        "AsAssetIdAccountDefinitionCompare",
    ] {
        assert!(
            !source.contains(retired),
            "unfunded retired balance access: {retired}"
        );
    }
}
#[test]
fn each_of_eight_balance_originals_precedes_all_validation_outcomes() {
    for source in 0..8 {
        for validation in 0..3 {
            let world = fixture(true);
            let checked = CheckedAssets::capture(&world, 16_777_216).unwrap();
            publish(&world, source);
            let result = match validation {
                0 => Ok(()),
                1 => Err(GroupedOwnershipError::WorkLimit),
                _ => Err(corrupt(
                    "world.assets_by_domain",
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
pub(super) fn publish(world: &World, source: usize) {
    match source {
        0 => world.assets.block().commit(),
        1 => world.asset_definitions.block().commit(),
        2 => world.domains.block().commit(),
        3 => world.asset_definition_assets.block().commit(),
        4 => world.assets_by_account.block().commit(),
        5 => world.assets_by_domain.block().commit(),
        6 => world.asset_definition_holders.block().commit(),
        7 => world.asset_definition_nonzero_holders.block().commit(),
        _ => unreachable!(),
    }
}

#[test]
fn first_busy_balance_source_keeps_original_release_before_later_changed_sources() {
    let world = fixture(true);
    let checked = CheckedAssets::capture(&world, 16_777_216).unwrap();
    world.asset_definitions.block().commit();
    world.asset_definition_nonzero_holders.block().commit();
    let detached = world
        .assets
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let prepared = detached
        .try_prepare_publication(&world.assets, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("original preparation: {error:?}"));
    let original = checked.rows.try_matches_current(&world.assets).unwrap_err();
    assert!(matches!(original, PublicationPreparationError::Busy(_)));
    assert_eq!(
        checked
            .finish_validation(Err(GroupedOwnershipError::WorkLimit))
            .err(),
        Some(GroupedOwnershipError::Publication(original))
    );
    drop(prepared);
    assert_eq!(check(&world, 16_777_216), Ok(()));
}

#[test]
fn additional_absent_global_source_undo_has_exact_seven_and_eight_visit_boundaries() {
    for (context, base, delta) in [(false, 2144, 7 * 105), (true, 2838, 8 * 105)] {
        let world = fixture(context);
        assert_eq!(world_work(&world), base);
        {
            let mut block = world.assets.block();
            block.remove(AssetId::new(definition("absent"), ALICE_ID.clone()));
            block.commit();
        }
        assert_eq!(world_work(&world), base + delta);
        assert_eq!(
            check(&world, base + delta - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, base + delta), Ok(()));
    }
}
