//! Balance index exactness across partitions, native cuts and State admission.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::capture_assets_once,
            leaf::{LeafError, LeafLimits},
        },
    },
};
use iroha_data_model::{asset::AssetBalanceScope, prelude::Registrable};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;

use super::test_support::*;

#[test]
fn partitions_use_any_nonzero_value_and_restore_the_actual_predecessor() {
    let mut world = fixture(true);
    let partition = AssetId::with_scope(
        definition("coin"),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    world.assets.insert(partition.clone(), value(&partition, 0));
    world.rebuild_asset_definition_indexes().unwrap();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    {
        let mut balances = world.assets.block();
        balances.insert(id(), value(&id(), 0));
        balances.commit();
    }
    world.rebuild_asset_definition_indexes().unwrap();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    assert!(
        world
            .asset_definition_nonzero_holders
            .view()
            .get(&definition("coin"))
            .is_none()
    );
    let checked = CheckedAssets::capture(&world, 16_777_216).unwrap();
    assert!(checked.rows().get(&id()).unwrap().as_ref().is_zero());
    assert_eq!(
        get_at(checked.rows(), GroupImage::Predecessor, &id())
            .unwrap()
            .as_ref(),
        value(&id(), 5).as_ref()
    );
    drop(checked);
    world.block_and_revert().commit();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    assert_eq!(
        world
            .asset_definition_nonzero_holders
            .view()
            .get(&definition("coin")),
        Some(&BTreeSet::from([ALICE_ID.clone()]))
    );
}

#[test]
fn changing_only_the_definition_domain_moves_untouched_balance_groups() {
    let mut world = fixture(true);
    {
        let mut definitions = world.asset_definitions.block();
        definitions.insert(
            definition("coin"),
            AssetDefinition::numeric(definition("coin"), "coin", AssetBalancePolicy::Global, None)
                .build(&ALICE_ID),
        );
        definitions.commit();
    }
    assert!(world.assets.history().revert_map().is_empty());
    world.rebuild_asset_definition_indexes().unwrap();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    assert!(
        world
            .assets_by_domain
            .view()
            .get(&domain("balances"))
            .is_none()
    );
    world.block_and_revert().commit();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    assert_eq!(
        world.assets_by_domain.view().get(&domain("balances")),
        Some(&BTreeSet::from([id()]))
    );
}

#[test]
fn all_five_indexes_require_every_source_membership_in_both_images() {
    for previous in [false, true] {
        for index in 0..5 {
            let mut world = fixture(true);
            macro_rules! omit {
                ($field:ident, $key:expr) => {{
                    let key = $key;
                    let members = omit_initial(&mut world.$field, &key);
                    if previous {
                        let mut block = world.$field.block();
                        block.insert(key, members);
                        block.commit();
                    }
                    concat!("world.", stringify!($field))
                }};
            }
            let index = match index {
                0 => omit!(asset_definition_assets, definition("coin")),
                1 => omit!(assets_by_account, ALICE_ID.clone()),
                2 => omit!(assets_by_domain, domain("balances")),
                3 => omit!(asset_definition_holders, definition("coin")),
                4 => omit!(asset_definition_nonzero_holders, definition("coin")),
                _ => unreachable!(),
            };
            assert_eq!(
                check(&world, 16_777_216),
                Err(corrupt(index, previous, GroupMismatch::MissingMember))
            );
        }
    }
}

#[test]
fn all_five_indexes_reject_empty_and_foreign_membership_in_both_images() {
    for previous in [false, true] {
        for empty in [false, true] {
            for index in 0..5 {
                let mut world = fixture(true);
                macro_rules! extra {
                    ($field:ident, $key:expr, $member:expr) => {{
                        let key = $key;
                        world.$field.insert(
                            key.clone(),
                            if empty {
                                BTreeSet::new()
                            } else {
                                BTreeSet::from([$member])
                            },
                        );
                        if previous {
                            let mut block = world.$field.block();
                            block.remove(key);
                            block.commit();
                        }
                        concat!("world.", stringify!($field))
                    }};
                }
                let index = match index {
                    0 => extra!(asset_definition_assets, definition("absent"), id()),
                    1 => extra!(assets_by_account, BOB_ID.clone(), id()),
                    2 => extra!(assets_by_domain, domain("absent"), id()),
                    3 => extra!(
                        asset_definition_holders,
                        definition("absent"),
                        ALICE_ID.clone()
                    ),
                    4 => extra!(
                        asset_definition_nonzero_holders,
                        definition("absent"),
                        ALICE_ID.clone()
                    ),
                    _ => unreachable!(),
                };
                assert_eq!(
                    check(&world, 16_777_216),
                    Err(corrupt(
                        index,
                        previous,
                        if empty {
                            GroupMismatch::EmptyGroup
                        } else {
                            GroupMismatch::ForeignMember
                        }
                    ))
                );
            }
        }
    }
}

#[test]
fn zero_only_and_deleted_partitions_cannot_supply_nonzero_membership() {
    for previous in [false, true] {
        let mut world = fixture(false);
        world.assets.insert(id(), value(&id(), 0));
        world.rebuild_asset_definition_indexes().unwrap();
        world
            .asset_definition_nonzero_holders
            .insert(definition("coin"), BTreeSet::from([ALICE_ID.clone()]));
        if previous {
            let mut balances = world.assets.block();
            balances.insert(id(), value(&id(), 5));
            balances.commit();
        }
        assert_eq!(
            check(&world, 16_777_216),
            Err(corrupt(
                "world.asset_definition_nonzero_holders",
                previous,
                GroupMismatch::ForeignMember
            ))
        );
    }
    let mut world = fixture(false);
    {
        let mut balances = world.assets.block();
        balances.remove(id());
        balances.commit();
    }
    world.rebuild_asset_definition_indexes().unwrap();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    world
        .asset_definition_holders
        .insert(definition("coin"), BTreeSet::from([ALICE_ID.clone()]));
    assert_eq!(
        check(&world, 16_777_216),
        Err(corrupt(
            "world.asset_definition_holders",
            false,
            GroupMismatch::ForeignMember
        ))
    );
}

#[test]
fn missing_definitions_and_domains_cannot_pass_through_consistent_indexes() {
    for previous in [false, true] {
        for missing_domain in [false, true] {
            let mut world = fixture(true);
            if missing_domain {
                let saved = omit_initial(&mut world.domains, &domain("balances"));
                if previous {
                    let mut block = world.domains.block();
                    block.insert(domain("balances"), saved);
                    block.commit();
                }
            } else {
                let saved = omit_initial(&mut world.asset_definitions, &definition("coin"));
                if previous {
                    let mut block = world.asset_definitions.block();
                    block.insert(definition("coin"), saved);
                    block.commit();
                }
            }
            assert_eq!(
                check(&world, 16_777_216),
                Err(GroupedOwnershipError::Source {
                    table: if missing_domain {
                        "world.asset_definitions"
                    } else {
                        "world.assets"
                    },
                    image: if previous {
                        GroupImage::Predecessor
                    } else {
                        GroupImage::Current
                    },
                    reason: if missing_domain {
                        "owning domain is absent"
                    } else {
                        "asset definition is absent"
                    },
                })
            );
        }
    }
}

#[test]
fn work_counts_both_cuts_range_rows_and_absent_source_undo() {
    for (context, exact) in [(false, 2144), (true, 2838)] {
        let world = fixture(context);
        assert_eq!(check(&world, exact), Ok(()));
        assert_eq!(
            check(&world, exact - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        {
            let mut block = world.assets.block();
            block.remove(AssetId::new(definition("absent"), ALICE_ID.clone()));
            block.commit();
        }
        assert_eq!(
            check(&world, exact + if context { 840 } else { 735 } - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            check(&world, exact + if context { 840 } else { 735 }),
            Ok(())
        );
    }
}

#[test]
fn restricted_definitions_require_a_domain_in_each_balance_source_image() {
    for previous in [false, true] {
        let mut world = fixture(true);
        let valid = world
            .asset_definitions
            .view()
            .get(&definition("coin"))
            .unwrap()
            .clone();
        let invalid = AssetDefinition::numeric(
            definition("coin"),
            "coin",
            AssetBalancePolicy::DataspaceRestricted,
            None,
        )
        .build(&ALICE_ID);
        world.asset_definitions.insert(definition("coin"), invalid);
        if previous {
            let mut block = world.asset_definitions.block();
            block.insert(definition("coin"), valid);
            block.commit();
        }
        assert_eq!(
            check(&world, 16_777_216),
            Err(GroupedOwnershipError::Source {
                table: "world.asset_definitions",
                image: if previous {
                    GroupImage::Predecessor
                } else {
                    GroupImage::Current
                },
                reason: "restricted definition has no owning domain",
            })
        );
    }
}

#[test]
fn predecessor_partition_search_charges_masked_current_and_absent_undo_rows() {
    use std::collections::BTreeMap;

    let mut world = fixture(false);
    let absent = AssetId::with_scope(
        definition("coin"),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    world.assets = Storage::from_snapshot_parts(
        BTreeMap::from([(id(), value(&id(), 5))]),
        BTreeMap::from([(id(), None), (absent, None)]),
    );
    world.rebuild_asset_definition_indexes().unwrap();
    let checked = CheckedAssets::capture(&world, 16_777_216).unwrap();
    for nonzero in [false, true] {
        assert_eq!(
            has_partition(
                &checked.rows,
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
                &checked.rows,
                GroupImage::Predecessor,
                &ALICE_ID,
                &definition("coin"),
                nonzero,
                &mut AssetBalanceWork::bounded(219)
            ),
            Ok(false)
        );
    }
}

#[test]
fn all_eight_original_native_owners_remain_part_of_the_final_identity_check() {
    for index in 0..8 {
        let world = fixture(true);
        let checked = CheckedAssets::capture(&world, 16_777_216).unwrap();
        match index {
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
        assert!(!checked.matches_current().unwrap());
    }
}

#[test]
fn actual_state_capture_retains_original_pool_refusal_and_checked_retry() {
    let state = State::new_for_testing(
        fixture(true),
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
        capture_assets_once(&state, limits),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    pool.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture_assets_once(&state, limits).unwrap().unwrap();
    assert_eq!(snapshot.table_id(), "world.assets");
    assert_eq!(snapshot.row_count(), 1);
}
