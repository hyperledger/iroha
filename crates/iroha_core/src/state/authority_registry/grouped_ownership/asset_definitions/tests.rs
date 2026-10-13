//! Definition projection checks retain both original native images and funding.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::capture_asset_definitions_once,
            leaf::{LeafError, LeafLimits},
        },
    },
    test_allocations::allocations_during,
};
use iroha_data_model::{IntoKeyValue, account::Account, prelude::Registrable};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;

fn domain() -> DomainId {
    DomainId::try_new("definitiongroups", "universal").unwrap()
}

fn id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain(), "coin".parse().unwrap())
}

fn definition(owner: &AccountId, context: bool) -> AssetDefinition {
    AssetDefinition::numeric(
        id(),
        "coin",
        AssetBalancePolicy::Global,
        context.then(domain),
    )
    .build(owner)
}

fn fixture(context: bool) -> World {
    let mut world = World::default();
    for owner in [&*ALICE_ID, &*BOB_ID] {
        let (id, account) = Account::new(owner.clone()).build(owner).into_key_value();
        world.accounts.insert(id, account);
    }
    world
        .domains
        .insert(domain(), Domain::new(domain()).build(&ALICE_ID));
    world
        .asset_definitions
        .insert(id(), definition(&ALICE_ID, context));
    world.rebuild_asset_definition_indexes().unwrap();
    world
}

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(CheckedAssetDefinitions::capture(world, work).map(|_| ()));
        }),
        0
    );
    result.unwrap()
}

fn image(previous: bool) -> GroupImage {
    if previous {
        GroupImage::Predecessor
    } else {
        GroupImage::Current
    }
}

fn corrupt(index: &'static str, previous: bool, mismatch: GroupMismatch) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index,
        image: image(previous),
        mismatch,
    }
}

#[test]
fn owner_and_optional_domain_changes_keep_both_images_through_replacement() {
    for context in [false, true] {
        let mut world = fixture(context);
        let before = definition(&ALICE_ID, context);
        let after = definition(&BOB_ID, !context);
        {
            let mut block = world.asset_definitions.block();
            block.insert(id(), after.clone());
            block.commit();
        }
        world.rebuild_asset_definition_indexes().unwrap();
        assert_eq!(check(&world, 16_777_216), Ok(()));
        let checked = CheckedAssetDefinitions::capture(&world, 16_777_216).unwrap();
        let current = checked.rows().get(&id()).unwrap();
        assert_eq!(current.owned_by(), after.owned_by());
        assert_eq!(current.owning_domain(), after.owning_domain());
        let previous = get_at(checked.rows(), GroupImage::Predecessor, &id()).unwrap();
        assert_eq!(previous.owned_by(), before.owned_by());
        assert_eq!(previous.owning_domain(), before.owning_domain());
        assert!(checked.matches_current().unwrap());
        drop(checked);
        world.block_and_revert().commit();
        assert_eq!(check(&world, 16_777_216), Ok(()));
        let view = world.asset_definitions.view();
        let restored = view.get(&id()).unwrap();
        assert_eq!(restored.owned_by(), before.owned_by());
        assert_eq!(restored.owning_domain(), before.owning_domain());
    }
}

#[test]
fn each_projection_rejects_omitted_members_in_both_images() {
    for index in 0..3 {
        for previous in [false, true] {
            let mut world = fixture(true);
            macro_rules! omit {
                ($field:ident, $key:expr, $value:expr) => {{
                    world.$field = Storage::default();
                    if previous {
                        let mut block = world.$field.block();
                        block.insert($key, $value);
                        block.commit();
                    }
                    concat!("world.", stringify!($field))
                }};
            }
            let name = match index {
                0 => omit!(asset_definition_domains, id(), domain()),
                1 => omit!(
                    asset_definitions_by_owner,
                    ALICE_ID.clone(),
                    BTreeSet::from([id()])
                ),
                2 => omit!(domain_asset_definitions, domain(), BTreeSet::from([id()])),
                _ => unreachable!(),
            };
            assert_eq!(
                check(&world, 16_777_216),
                Err(corrupt(name, previous, GroupMismatch::MissingMember))
            );
        }
    }
}

#[test]
fn optional_and_unknown_contexts_and_empty_or_foreign_groups_are_rejected() {
    for previous in [false, true] {
        for case in 0..5 {
            let mut world = fixture(false);
            macro_rules! extra {
                ($field:ident, $key:expr, $value:expr) => {{
                    let key = $key;
                    world.$field.insert(key.clone(), $value);
                    if previous {
                        let mut block = world.$field.block();
                        block.remove(key);
                        block.commit();
                    }
                    concat!("world.", stringify!($field))
                }};
            }
            let name = match case {
                0 => extra!(asset_definition_domains, id(), domain()),
                1 => extra!(
                    asset_definition_domains,
                    AssetDefinitionId::derive_from_components(domain(), "absent".parse().unwrap()),
                    domain()
                ),
                2 => extra!(domain_asset_definitions, domain(), BTreeSet::new()),
                3 => extra!(domain_asset_definitions, domain(), BTreeSet::from([id()])),
                4 => extra!(
                    asset_definitions_by_owner,
                    BOB_ID.clone(),
                    BTreeSet::from([id()])
                ),
                _ => unreachable!(),
            };
            assert_eq!(
                check(&world, 16_777_216),
                Err(corrupt(
                    name,
                    previous,
                    if case == 2 {
                        GroupMismatch::EmptyGroup
                    } else {
                        GroupMismatch::ForeignMember
                    }
                ))
            );
        }
    }
}

#[test]
fn source_reference_failures_precede_index_checks_and_leave_sources_unchanged() {
    for previous in [false, true] {
        for restricted in [false, true] {
            let mut world = fixture(true);
            let valid = definition(&ALICE_ID, true);
            let bad = AssetDefinition::numeric(
                id(),
                "coin",
                if restricted {
                    AssetBalancePolicy::DataspaceRestricted
                } else {
                    AssetBalancePolicy::Global
                },
                (!restricted).then(|| DomainId::try_new("absent", "universal").unwrap()),
            )
            .build(&ALICE_ID);
            world.asset_definitions.insert(id(), bad);
            if previous {
                let mut block = world.asset_definitions.block();
                block.insert(id(), valid);
                block.commit();
            }
            let mut before = String::new();
            crate::state::snapshot_storage::serialize(&world.asset_definitions, &mut before);
            assert_eq!(
                check(&world, 16_777_216),
                Err(GroupedOwnershipError::Source {
                    table: "world.asset_definitions",
                    image: image(previous),
                    reason: if restricted {
                        "restricted definition has no owning domain"
                    } else {
                        "owning domain is absent"
                    },
                })
            );
            let mut after = String::new();
            crate::state::snapshot_storage::serialize(&world.asset_definitions, &mut after);
            assert_eq!(before, after);
        }
    }
}

#[test]
fn work_is_charged_before_rows_domain_lookups_and_absent_undo_inspections() {
    for (context, exact, delta) in [(false, 434, 175), (true, 1218, 245)] {
        let world = fixture(context);
        assert_eq!(test_support::world_work(&world), exact);
        assert_eq!(check(&world, exact), Ok(()));
        assert_eq!(
            check(&world, exact - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        {
            let mut block = world.asset_definitions.block();
            block.remove(AssetDefinitionId::derive_from_components(
                domain(),
                "absent".parse().unwrap(),
            ));
            block.commit();
        }
        assert_eq!(
            check(&world, exact + delta - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(test_support::world_work(&world), exact + delta);
        assert_eq!(check(&world, exact + delta), Ok(()));
    }
}

#[test]
fn every_original_source_and_index_reader_detects_native_publication() {
    for index in 0..7 {
        let world = fixture(true);
        let checked = CheckedAssetDefinitions::capture(&world, 16_777_216).unwrap();
        match index {
            0 => world.asset_definitions.block().commit(),
            1 => world.domains.block().commit(),
            2 => world.asset_definition_domains.block().commit(),
            3 => world.domain_asset_definitions.block().commit(),
            4 => world.asset_definitions_by_owner.block().commit(),
            5 => world.confidential_policy_transition_index.block().commit(),
            6 => world.confidential_policy_transition_counts.block().commit(),
            _ => unreachable!(),
        }
        assert!(!checked.matches_current().unwrap());
    }
}

#[test]
fn checked_capture_keeps_original_state_budget_refusal_and_retries() {
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
        capture_asset_definitions_once(&state, limits),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    pool.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture_asset_definitions_once(&state, limits)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), "world.asset_definitions");
    assert_eq!(snapshot.row_count(), 1);
}

#[test]
fn every_asset_original_publication_precedes_success_work_and_semantic_outcomes() {
    for source in 0..7 {
        for outcome in 0..3 {
            let world = fixture(true);
            let checked = CheckedAssetDefinitions::capture(&world, 16_777_216).unwrap();
            match source {
                0 => world.asset_definitions.block().commit(),
                1 => world.domains.block().commit(),
                2 => world.asset_definition_domains.block().commit(),
                3 => world.domain_asset_definitions.block().commit(),
                4 => world.asset_definitions_by_owner.block().commit(),
                5 => world.confidential_policy_transition_index.block().commit(),
                6 => world.confidential_policy_transition_counts.block().commit(),
                _ => unreachable!(),
            }
            let result = match outcome {
                0 => Ok(()),
                1 => Err(GroupedOwnershipError::WorkLimit),
                _ => Err(corrupt(
                    "world.asset_definition_domains",
                    false,
                    GroupMismatch::MissingMember,
                )),
            };
            let mut error = None;
            assert_eq!(
                allocations_during(|| error = checked.finish_validation(result).err()),
                0
            );
            assert_eq!(
                error,
                Some(GroupedOwnershipError::Publication(
                    PublicationPreparationError::Changed
                ))
            );
        }
    }
}
#[test]
fn first_original_busy_refusal_keeps_exact_release_and_all_probe_order() {
    let world = fixture(true);
    let checked = CheckedAssetDefinitions::capture(&world, 16_777_216).unwrap();
    world.domains.block().commit();
    world.confidential_policy_transition_counts.block().commit();
    let detached = world
        .asset_definitions
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let prepared = detached
        .try_prepare_publication(&world.asset_definitions, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("original preparation: {error:?}"));
    let original = checked
        .rows
        .try_matches_current(&world.asset_definitions)
        .unwrap_err();
    assert!(matches!(original, PublicationPreparationError::Busy(_)));
    let mut error = None;
    assert_eq!(
        allocations_during(|| error = checked
            .finish_validation(Err(GroupedOwnershipError::WorkLimit))
            .err()),
        0
    );
    assert_eq!(error, Some(GroupedOwnershipError::Publication(original)));
    drop(prepared);
    assert_eq!(check(&world, 16_777_216), Ok(()));
}
