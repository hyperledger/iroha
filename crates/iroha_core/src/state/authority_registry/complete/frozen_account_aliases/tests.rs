//! Actual three-source frozen alias histories, refusal precedence and output custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            account_alias_ownership::{
                AliasImage, AliasMismatch, AliasOwnershipError,
                test_support::{alias, details, exact_work, fixture, without_allocations},
            },
            complete::{
                capture_account_alias_table_once,
                table_capture::frozen::capture_original_table_once,
            },
        },
        block_field::BlockField,
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::block::BlockHeader;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::{
    BlockRetirement as _,
    storage::{Storage, StorageReadOnly},
};
use std::num::NonZeroU64;

fn state(world: World) -> State {
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0)
}
fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 64,
        max_payload_bytes: 65_536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 131_072,
    }
}
fn freeze(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn extra(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
fn stage(block: &mut StateBlock<'_>) {
    block.world.accounts.insert(ALICE_ID.clone(), details(None)); // actual equal/no-op touch
    block
        .world
        .accounts
        .insert(BOB_ID.clone(), details(Some(alias("merchant"))));
    block.world.accounts.insert(extra(17), details(None));
    block.world.accounts.remove(extra(18));
    block
        .world
        .account_aliases
        .insert(alias("merchant"), BOB_ID.clone());
    block
        .world
        .account_aliases
        .insert(alias("shop"), ALICE_ID.clone());
    block.world.account_aliases.remove(alias("absent"));
    block
        .world
        .account_aliases_by_account
        .insert(ALICE_ID.clone(), BTreeSet::from([alias("shop")]));
    block
        .world
        .account_aliases_by_account
        .insert(BOB_ID.clone(), BTreeSet::from([alias("merchant")]));
    block.world.account_aliases_by_account.remove(extra(18));
}
fn expected() -> World {
    let mut world = fixture();
    world
        .accounts
        .insert(BOB_ID.clone(), details(Some(alias("merchant"))));
    world.accounts.insert(extra(17), details(None));
    world
        .account_aliases
        .insert(alias("merchant"), BOB_ID.clone());
    world
        .account_aliases
        .insert(alias("shop"), ALICE_ID.clone());
    world.rebuild_account_alias_index().unwrap();
    world
}
fn equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}

#[test]
fn actual_alias_transfer_primary_change_insert_delete_noop_and_absent_history() {
    let state = state(fixture());
    let mut block = state.block(header());
    stage(&mut block);
    let ids = [
        block.world.accounts.publication_identity(),
        block.world.account_aliases.publication_identity(),
        block
            .world
            .account_aliases_by_account
            .publication_identity(),
    ];
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.accounts.mode(), mv::BlockMode::Ordinary);
    assert_eq!(original.aliases.mode(), mv::BlockMode::Ordinary);
    assert_eq!(original.reverse.mode(), mv::BlockMode::Ordinary);
    assert!(
        original
            .accounts
            .undo_entries()
            .any(|(key, prior)| key == &*ALICE_ID && prior == &Some(details(None)))
    );
    assert!(
        original
            .aliases
            .undo_entries()
            .any(|(key, prior)| key == &alias("absent") && prior.is_none())
    );
    assert!(
        original
            .reverse
            .undo_entries()
            .any(|(key, prior)| key == &extra(18) && prior.is_none())
    );
    let exact = exact_work(&original.accounts, &original.aliases, &original.reverse);
    assert_eq!(
        without_allocations(|| validate_original_account_aliases(
            &original.accounts,
            &original.aliases,
            &original.reverse,
            exact - 1
        )),
        Err(AliasOwnershipError::WorkLimit)
    );
    without_allocations(|| {
        validate_original_account_aliases(
            &original.accounts,
            &original.aliases,
            &original.reverse,
            exact,
        )
    })
    .unwrap();
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    let expected = self::state(expected());
    equal(
        &snapshot,
        &capture_account_alias_table_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
    equal(
        &snapshot,
        &capture_original_table_once(&block, "world.account_aliases", limits(), exact)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        ids,
        [
            block.world.accounts.publication_identity(),
            block.world.account_aliases.publication_identity(),
            block
                .world
                .account_aliases_by_account
                .publication_identity()
        ]
    );
    drop(snapshot);
    drop(block);
    // Deletion leaves its real prior alias/account/bucket available for validation.
    let state = self::state(fixture());
    let mut block = state.block(header());
    block.world.account_aliases.remove(alias("merchant"));
    block
        .world
        .account_aliases_by_account
        .remove(ALICE_ID.clone());
    block.world.accounts.remove(ALICE_ID.clone());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert!(
        original
            .aliases
            .undo_entries()
            .any(|(key, prior)| key == &alias("merchant") && prior == &Some(ALICE_ID.clone()))
    );
    let exact = exact_work(&original.accounts, &original.aliases, &original.reverse);
    assert_eq!(
        capture(&block, limits(), exact)
            .unwrap()
            .unwrap()
            .row_count(),
        0
    );
}

fn defect(world: &mut World, which: usize) {
    match which {
        0 => {
            world
                .account_aliases
                .insert(alias("12345678"), ALICE_ID.clone());
            world.account_aliases_by_account.insert(
                ALICE_ID.clone(),
                BTreeSet::from([alias("merchant"), alias("12345678")]),
            );
        }
        1 => {
            world
                .accounts
                .insert(ALICE_ID.clone(), details(Some(alias("unbound"))));
        }
        2 => {
            world.account_aliases.insert(alias("merchant"), extra(33));
            world.account_aliases_by_account =
                Storage::from_iter([(extra(33), BTreeSet::from([alias("merchant")]))]);
        }
        3 => {
            world.account_aliases_by_account = Storage::default();
        }
        4 => {
            world
                .account_aliases_by_account
                .insert(BOB_ID.clone(), BTreeSet::new());
        }
        5 => {
            world
                .account_aliases_by_account
                .insert(BOB_ID.clone(), BTreeSet::from([alias("merchant")]));
        }
        _ => unreachable!(),
    }
}
fn stage_defect(block: &mut StateBlock<'_>, which: usize, repair: bool) {
    if repair {
        match which {
            0 => {
                block.world.account_aliases.remove(alias("12345678"));
                block
                    .world
                    .account_aliases_by_account
                    .insert(ALICE_ID.clone(), BTreeSet::from([alias("merchant")]));
            }
            1 => {
                block.world.accounts.insert(ALICE_ID.clone(), details(None));
            }
            2 => {
                block
                    .world
                    .account_aliases
                    .insert(alias("merchant"), ALICE_ID.clone());
                block.world.account_aliases_by_account.remove(extra(33));
                block
                    .world
                    .account_aliases_by_account
                    .insert(ALICE_ID.clone(), BTreeSet::from([alias("merchant")]));
            }
            3 => {
                block
                    .world
                    .account_aliases_by_account
                    .insert(ALICE_ID.clone(), BTreeSet::from([alias("merchant")]));
            }
            4 | 5 => {
                block
                    .world
                    .account_aliases_by_account
                    .remove(BOB_ID.clone());
            }
            _ => unreachable!(),
        }
    } else {
        match which {
            0 => {
                block
                    .world
                    .account_aliases
                    .insert(alias("12345678"), ALICE_ID.clone());
                block.world.account_aliases_by_account.insert(
                    ALICE_ID.clone(),
                    BTreeSet::from([alias("merchant"), alias("12345678")]),
                );
            }
            1 => {
                block
                    .world
                    .accounts
                    .insert(ALICE_ID.clone(), details(Some(alias("unbound"))));
            }
            2 => {
                block
                    .world
                    .account_aliases
                    .insert(alias("merchant"), extra(33));
                block
                    .world
                    .account_aliases_by_account
                    .remove(ALICE_ID.clone());
                block
                    .world
                    .account_aliases_by_account
                    .insert(extra(33), BTreeSet::from([alias("merchant")]));
            }
            3 => {
                block
                    .world
                    .account_aliases_by_account
                    .remove(ALICE_ID.clone());
            }
            4 => {
                block
                    .world
                    .account_aliases_by_account
                    .insert(BOB_ID.clone(), BTreeSet::new());
            }
            5 => {
                block
                    .world
                    .account_aliases_by_account
                    .insert(BOB_ID.clone(), BTreeSet::from([alias("merchant")]));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn all_six_alias_defects_reject_either_original_image_before_leaf_allocation() {
    for prior in [false, true] {
        for which in 0..6 {
            // Startup validates the initial alias/scope sources. Corrupt the actual
            // original State only after valid construction, before either frozen image.
            let mut state = state(fixture());
            if prior {
                defect(&mut state.world, which);
            }
            let mut block = state.block(header());
            stage_defect(&mut block, which, prior);
            freeze(&mut block);
            let budget = state.ivm_execution_budget();
            let baseline = budget.reserved_bytes();
            budget.set_limit_bytes(0);
            let original = Original::retain(&block).unwrap();
            let error = without_allocations(|| {
                validate_original_account_aliases(
                    &original.accounts,
                    &original.aliases,
                    &original.reverse,
                    16_777_216,
                )
            })
            .unwrap_err();
            assert_eq!(
                error,
                AliasOwnershipError::Corrupt {
                    image: if prior {
                        AliasImage::Predecessor
                    } else {
                        AliasImage::Current
                    },
                    mismatch: [
                        AliasMismatch::PrivateLabel,
                        AliasMismatch::PrimaryLabel,
                        AliasMismatch::MissingAccount,
                        AliasMismatch::MissingAlias,
                        AliasMismatch::EmptyBucket,
                        AliasMismatch::ForeignAlias
                    ][which]
                }
            );
            assert_eq!(
                capture(&block, limits(), 16_777_216).err(),
                Some(LeafError::AliasOwnership(error))
            );
            assert_eq!(budget.reserved_bytes(), baseline);
        }
    }
}

#[test]
fn every_alias_foreign_target_mode_partial_and_released_source_refuses() {
    for source in 0..3 {
        for mixed in [false, true] {
            let state = state(fixture());
            let foreign = self::state(fixture());
            let mut block = state.block(header());
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            let target = if mixed { &state } else { &foreign };
            match source {
                0 => {
                    block.world.accounts.release_writers();
                    block.world.accounts = BlockField::new(if mixed {
                        target.world.accounts.block_and_revert()
                    } else {
                        target.world.accounts.block()
                    });
                }
                1 => {
                    block.world.account_aliases.release_writers();
                    block.world.account_aliases = BlockField::new(if mixed {
                        target.world.account_aliases.block_and_revert()
                    } else {
                        target.world.account_aliases.block()
                    });
                }
                2 => {
                    block.world.account_aliases_by_account.release_writers();
                    block.world.account_aliases_by_account = BlockField::new(if mixed {
                        target.world.account_aliases_by_account.block_and_revert()
                    } else {
                        target.world.account_aliases_by_account.block()
                    });
                }
                _ => unreachable!(),
            }
            freeze(&mut block);
            assert!(capture(&block, limits(), 0).unwrap().is_none());
        }
    }
    let state = state(fixture());
    let mut block = state.block(header());
    block.world.accounts.begin_freeze();
    block.world.accounts.finish_freeze();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
    drop(block);
    for source in 0..3 {
        let state = self::state(fixture());
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.accounts.release_writers(),
            1 => block.world.account_aliases.release_writers(),
            2 => block.world.account_aliases_by_account.release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
}

#[test]
fn actual_alias_replace_keeps_rewound_sources_and_prior_rows() {
    let state = state(fixture());
    {
        let mut accounts = state.world.accounts.block();
        let mut aliases = state.world.account_aliases.block();
        let mut reverse = state.world.account_aliases_by_account.block();
        accounts.insert(BOB_ID.clone(), details(Some(alias("merchant"))));
        aliases.insert(alias("merchant"), BOB_ID.clone());
        reverse.remove(ALICE_ID.clone());
        reverse.insert(BOB_ID.clone(), BTreeSet::from([alias("merchant")]));
        accounts.commit();
        aliases.commit();
        reverse.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block.world.account_aliases.get(&alias("merchant")),
        Some(&*ALICE_ID)
    );
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.accounts.mode(), mv::BlockMode::Replace);
    assert_eq!(original.aliases.mode(), mv::BlockMode::Replace);
    assert_eq!(original.reverse.mode(), mv::BlockMode::Replace);
    let exact = exact_work(&original.accounts, &original.aliases, &original.reverse);
    assert_eq!(
        capture(&block, limits(), exact - 1).err(),
        Some(LeafError::AliasOwnership(AliasOwnershipError::WorkLimit))
    );
    let expected = self::state(fixture());
    equal(
        &capture(&block, limits(), exact).unwrap().unwrap(),
        &capture_account_alias_table_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn original_alias_pool_refusal_retry_and_final_snapshot_owner_drop() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state(fixture());
    let budget = state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let pointer = core::ptr::from_ref(block.world.account_aliases.get(&alias("merchant")).unwrap());
    freeze(&mut block);
    let baseline = budget.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::AliasOwnership(AliasOwnershipError::WorkLimit))
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(0);
    assert!(matches!(
        capture(&block, limits(), 16_777_216),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(limit);
    for (small, error) in [
        (
            LeafLimits {
                max_rows: 0,
                ..limits()
            },
            LeafError::RowLimit,
        ),
        (
            LeafLimits {
                max_payload_bytes: 0,
                ..limits()
            },
            LeafError::PayloadLimit,
        ),
    ] {
        assert_eq!(capture(&block, small, 16_777_216).err(), Some(error));
        assert_eq!(budget.reserved_bytes(), baseline);
    }
    let snapshot = std::sync::Arc::new(capture(&block, limits(), 16_777_216).unwrap().unwrap());
    assert!(budget.reserved_bytes() > baseline);
    assert_eq!(
        core::ptr::from_ref(block.world.account_aliases.get(&alias("merchant")).unwrap()),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(budget.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn later_alias_target_publications_cannot_refresh_any_original() {
    for source in 0..3 {
        for changed in [false, true] {
            let state = state(fixture());
            let mut block = state.block(header());
            stage(&mut block);
            freeze(&mut block);
            let snapshot = capture(&block, limits(), 16_777_216).unwrap().unwrap();
            match source {
                0 => {
                    let mut rows = state.world.accounts.block();
                    if changed {
                        rows.insert(extra(55), details(None));
                    }
                    rows.commit();
                }
                1 => {
                    let mut rows = state.world.account_aliases.block();
                    if changed {
                        rows.insert(alias("later"), ALICE_ID.clone());
                    }
                    rows.commit();
                }
                2 => {
                    let mut rows = state.world.account_aliases_by_account.block();
                    if changed {
                        rows.insert(extra(55), BTreeSet::from([alias("later")]));
                    }
                    rows.commit();
                }
                _ => unreachable!(),
            }
            equal(
                &snapshot,
                &capture(&block, limits(), 16_777_216).unwrap().unwrap(),
            );
        }
    }
}

#[test]
fn local_alias_work_refusal_precedes_latent_corruption_without_a_verdict() {
    let state = state(fixture());
    let mut block = state.block(header());
    stage_defect(&mut block, 3, false);
    freeze(&mut block);
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::AliasOwnership(AliasOwnershipError::WorkLimit))
    );
    assert_eq!(
        capture(&block, limits(), 16_777_216).err(),
        Some(LeafError::AliasOwnership(AliasOwnershipError::Corrupt {
            image: AliasImage::Current,
            mismatch: AliasMismatch::MissingAlias
        }))
    );
}

#[test]
fn equal_alias_spellings_keep_distinct_domains_dataspaces_and_utf8_primary_labels() {
    use iroha_data_model::account::{AccountAliasDomain, MultisigMember, MultisigPolicy};
    use iroha_model_base::topology::DataSpaceId;
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
    let first = AccountAlias::new(
        "商店".parse().unwrap(),
        Some(AccountAliasDomain::new("retail".parse().unwrap())),
        DataSpaceId::new(7),
    );
    let mut second = first.clone();
    second.dataspace = DataSpaceId::new(8);
    let mut third = first.clone();
    third.domain = None;
    let make_world = || {
        let mut world = fixture();
        world
            .accounts
            .insert(owner.clone(), details(Some(first.clone())));
        for label in [&first, &second, &third] {
            world.account_aliases.insert(label.clone(), owner.clone());
        }
        world.rebuild_account_alias_index().unwrap();
        world
    };
    let expected = self::state(make_world());
    let state = state(make_world());
    let mut block = state.block(header());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    let exact = exact_work(&original.accounts, &original.aliases, &original.reverse);
    assert_eq!(
        without_allocations(|| validate_original_account_aliases(
            &original.accounts,
            &original.aliases,
            &original.reverse,
            exact - 1
        )),
        Err(AliasOwnershipError::WorkLimit)
    );
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 4);
    equal(
        &snapshot,
        &capture_account_alias_table_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
}
