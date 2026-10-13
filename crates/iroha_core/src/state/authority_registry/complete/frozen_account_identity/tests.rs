//! Actual frozen identity histories, original pool and complete custody controls.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            account_identity_ownership::{
                IdentityImage, IdentityMismatch, IdentityOwnershipError,
                test_support::{
                    details, exact_work, fixture, opaque, single, uaid, without_allocations,
                },
            },
            complete::{
                capture_accounts_table_once, table_capture::frozen::capture_original_table_once,
            },
        },
        block_field::BlockField,
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
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
    block.world.accounts.remove(ALICE_ID.clone());
    block
        .world
        .accounts
        .insert(BOB_ID.clone(), details(Some(uaid()), vec![opaque(1)]));
    block
        .world
        .accounts
        .insert(extra(17), details(None, vec![]));
    block.world.accounts.remove(extra(18));
    block.world.uaid_accounts.insert(uaid(), BOB_ID.clone());
    block
        .world
        .uaid_accounts
        .remove(UniversalAccountId::from_hash(Hash::new(b"absent uaid")));
    block.world.opaque_uaids.insert(opaque(1), uaid()); // actual no-op touch
    block.world.opaque_uaids.remove(opaque(18));
}
fn expected_world() -> World {
    let mut world = World::default();
    world
        .accounts
        .insert(BOB_ID.clone(), details(Some(uaid()), vec![opaque(1)]));
    world.accounts.insert(extra(17), details(None, vec![]));
    crate::state::account_identity_restore::rebuild(&mut world).unwrap();
    world
}
fn assert_equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}

#[test]
fn reassignment_delete_insert_noop_and_absent_touches_keep_all_three_images() {
    let state = state(fixture());
    let mut block = state.block(header());
    stage(&mut block);
    let ids = [
        block.world.accounts.publication_identity(),
        block.world.uaid_accounts.publication_identity(),
        block.world.opaque_uaids.publication_identity(),
    ];
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.accounts.mode(), mv::BlockMode::Ordinary);
    assert_eq!(original.uaids.mode(), mv::BlockMode::Ordinary);
    assert_eq!(original.opaques.mode(), mv::BlockMode::Ordinary);
    assert!(
        original
            .accounts
            .undo_entries()
            .any(|(key, prior)| key == &extra(18) && prior.is_none())
    );
    assert!(
        original
            .opaques
            .undo_entries()
            .any(|(key, prior)| key == &opaque(1) && prior == &Some(uaid()))
    );
    let exact = exact_work(&original.accounts, &original.uaids, &original.opaques);
    assert_eq!(
        without_allocations(|| validate_original_account_identities(
            &original.accounts,
            &original.uaids,
            &original.opaques,
            exact - 1
        )),
        Err(IdentityOwnershipError::WorkLimit)
    );
    without_allocations(|| {
        validate_original_account_identities(
            &original.accounts,
            &original.uaids,
            &original.opaques,
            exact,
        )
    })
    .unwrap();
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    let expected = self::state(expected_world());
    assert_equal(
        &snapshot,
        &capture_accounts_table_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
    assert_equal(
        &snapshot,
        &capture_original_table_once(&block, "world.accounts", limits(), exact)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        ids,
        [
            block.world.accounts.publication_identity(),
            block.world.uaid_accounts.publication_identity(),
            block.world.opaque_uaids.publication_identity()
        ]
    );
}

#[test]
fn all_six_identity_mismatches_reject_either_original_image() {
    let other = UniversalAccountId::from_hash(Hash::new(b"foreign identity"));
    for previous in [false, true] {
        for defect in 0..6 {
            let mut state = state(single());
            if previous {
                match defect {
                    0 => {
                        state
                            .world
                            .accounts
                            .insert(ALICE_ID.clone(), details(None, vec![opaque(1)]));
                    }
                    1 => state.world.uaid_accounts = Storage::new(),
                    2 => state.world.opaque_uaids = Storage::new(),
                    3 => {
                        state.world.uaid_accounts.insert(other, BOB_ID.clone());
                    }
                    4 => {
                        state.world.opaque_uaids.insert(opaque(2), uaid());
                    }
                    5 => {
                        state.world.accounts.insert(
                            ALICE_ID.clone(),
                            details(Some(uaid()), vec![opaque(1), opaque(1)]),
                        );
                    }
                    _ => unreachable!(),
                }
            }
            let mut block = state.block(header());
            if previous {
                match defect {
                    0 | 5 => {
                        block
                            .world
                            .accounts
                            .insert(ALICE_ID.clone(), details(Some(uaid()), vec![opaque(1)]));
                    }
                    1 => {
                        block.world.uaid_accounts.insert(uaid(), ALICE_ID.clone());
                    }
                    2 => {
                        block.world.opaque_uaids.insert(opaque(1), uaid());
                    }
                    3 => {
                        block.world.uaid_accounts.remove(other);
                    }
                    4 => {
                        block.world.opaque_uaids.remove(opaque(2));
                    }
                    _ => unreachable!(),
                }
            } else {
                match defect {
                    0 => {
                        block
                            .world
                            .accounts
                            .insert(ALICE_ID.clone(), details(None, vec![opaque(1)]));
                    }
                    1 => {
                        block.world.uaid_accounts.remove(uaid());
                    }
                    2 => {
                        block.world.opaque_uaids.remove(opaque(1));
                    }
                    3 => {
                        block.world.uaid_accounts.insert(other, BOB_ID.clone());
                    }
                    4 => {
                        block.world.opaque_uaids.insert(opaque(2), uaid());
                    }
                    5 => {
                        block.world.accounts.insert(
                            ALICE_ID.clone(),
                            details(Some(uaid()), vec![opaque(1), opaque(1)]),
                        );
                    }
                    _ => unreachable!(),
                }
            }
            freeze(&mut block);
            let original = Original::retain(&block).unwrap();
            let error = without_allocations(|| {
                validate_original_account_identities(
                    &original.accounts,
                    &original.uaids,
                    &original.opaques,
                    16_777_216,
                )
            })
            .unwrap_err();
            assert_eq!(
                error,
                IdentityOwnershipError::Corrupt {
                    image: if previous {
                        IdentityImage::Predecessor
                    } else {
                        IdentityImage::Current
                    },
                    mismatch: [
                        IdentityMismatch::OpaqueWithoutUaid,
                        IdentityMismatch::UaidBinding,
                        IdentityMismatch::OpaqueBinding,
                        IdentityMismatch::ForeignUaid,
                        IdentityMismatch::ForeignOpaque,
                        IdentityMismatch::DuplicateOpaque
                    ][defect]
                }
            );
            assert_eq!(
                capture(&block, limits(), 16_777_216).err(),
                Some(LeafError::IdentityOwnership(error))
            );
        }
    }
}

#[test]
fn malformed_typed_controller_preserves_exact_inverse_without_new_key_admission() {
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let owner = AccountId::new(key);
    let mut world = World::new();
    world.accounts = Storage::from_iter([(owner.clone(), details(Some(uaid()), vec![opaque(1)]))]);
    world.uaid_accounts = Storage::from_iter([(uaid(), owner)]);
    world.opaque_uaids = Storage::from_iter([(opaque(1), uaid())]);
    let state = state(world);
    let mut block = state.block(header());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(
        without_allocations(|| validate_original_account_identities(
            &original.accounts,
            &original.uaids,
            &original.opaques,
            811
        )),
        Err(IdentityOwnershipError::WorkLimit)
    );
    without_allocations(|| {
        validate_original_account_identities(
            &original.accounts,
            &original.uaids,
            &original.opaques,
            812,
        )
    })
    .unwrap();
}

#[test]
fn each_foreign_released_incomplete_and_mixed_original_source_refuses() {
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
                    block.world.uaid_accounts.release_writers();
                    block.world.uaid_accounts = BlockField::new(if mixed {
                        target.world.uaid_accounts.block_and_revert()
                    } else {
                        target.world.uaid_accounts.block()
                    });
                }
                2 => {
                    block.world.opaque_uaids.release_writers();
                    block.world.opaque_uaids = BlockField::new(if mixed {
                        target.world.opaque_uaids.block_and_revert()
                    } else {
                        target.world.opaque_uaids.block()
                    });
                }
                _ => unreachable!(),
            }
            freeze(&mut block);
            assert!(capture(&block, limits(), 0).unwrap().is_none());
        }
    }
    {
        let state = state(fixture());
        let mut block = state.block(header());
        block.world.accounts.begin_freeze();
        block.world.accounts.finish_freeze();
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    for source in 0..3 {
        let state = state(fixture());
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.accounts.release_writers(),
            1 => block.world.uaid_accounts.release_writers(),
            2 => block.world.opaque_uaids.release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
}

#[test]
fn actual_original_pool_retry_and_last_snapshot_owner_refund_preserve_all_rows() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state(fixture());
    let budget = state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let ids = [
        block.world.accounts.publication_identity(),
        block.world.uaid_accounts.publication_identity(),
        block.world.opaque_uaids.publication_identity(),
    ];
    let pointer = core::ptr::from_ref(block.world.accounts.get(&*BOB_ID).unwrap());
    freeze(&mut block);
    let baseline = budget.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::IdentityOwnership(
            IdentityOwnershipError::WorkLimit
        ))
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
        ids,
        [
            block.world.accounts.publication_identity(),
            block.world.uaid_accounts.publication_identity(),
            block.world.opaque_uaids.publication_identity()
        ]
    );
    assert_eq!(
        core::ptr::from_ref(block.world.accounts.get(&*BOB_ID).unwrap()),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(budget.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn later_equal_or_changed_publications_cannot_refresh_any_original_identity_image() {
    let state = state(fixture());
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = capture(&block, limits(), 16_777_216).unwrap().unwrap();
    for changed in [false, true] {
        let mut accounts = state.world.accounts.block();
        let mut uaids = state.world.uaid_accounts.block();
        let mut opaques = state.world.opaque_uaids.block();
        if changed {
            accounts.insert(
                extra(19),
                details(
                    Some(UniversalAccountId::from_hash(Hash::new(b"later uaid"))),
                    vec![opaque(19)],
                ),
            );
            uaids.insert(
                UniversalAccountId::from_hash(Hash::new(b"later uaid")),
                extra(19),
            );
            opaques.insert(
                opaque(19),
                UniversalAccountId::from_hash(Hash::new(b"later uaid")),
            );
        }
        accounts.commit();
        uaids.commit();
        opaques.commit();
        assert_equal(
            &original,
            &capture(&block, limits(), 16_777_216).unwrap().unwrap(),
        );
    }
    assert_ne!(
        original.root(),
        capture_accounts_table_once(&state, limits())
            .unwrap()
            .unwrap()
            .root()
    );
}

#[test]
fn actual_replace_retains_rewound_identity_images_and_all_three_modes() {
    let state = state(fixture());
    {
        let mut accounts = state.world.accounts.block();
        let mut uaids = state.world.uaid_accounts.block();
        let mut opaques = state.world.opaque_uaids.block();
        accounts.insert(ALICE_ID.clone(), details(None, vec![]));
        accounts.insert(BOB_ID.clone(), details(Some(uaid()), vec![opaque(1)]));
        uaids.insert(uaid(), BOB_ID.clone());
        opaques.insert(opaque(1), uaid());
        accounts.commit();
        uaids.commit();
        opaques.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block
            .world
            .accounts
            .get(&*ALICE_ID)
            .unwrap()
            .as_ref()
            .uaid(),
        Some(&uaid())
    );
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.accounts.mode(), mv::BlockMode::Replace);
    assert_eq!(original.uaids.mode(), mv::BlockMode::Replace);
    assert_eq!(original.opaques.mode(), mv::BlockMode::Replace);
    let exact = exact_work(&original.accounts, &original.uaids, &original.opaques);
    assert_eq!(
        capture(&block, limits(), exact - 1).err(),
        Some(LeafError::IdentityOwnership(
            IdentityOwnershipError::WorkLimit
        ))
    );
    let expected = self::state(fixture());
    assert_equal(
        &capture(&block, limits(), exact).unwrap().unwrap(),
        &capture_accounts_table_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn local_work_refusal_precedes_latent_malformed_identity_without_a_verdict() {
    let state = state(single());
    let mut block = state.block(header());
    block.world.uaid_accounts.remove(uaid());
    freeze(&mut block);
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::IdentityOwnership(
            IdentityOwnershipError::WorkLimit
        ))
    );
    assert_eq!(
        capture(&block, limits(), 1).err(),
        Some(LeafError::IdentityOwnership(
            IdentityOwnershipError::Corrupt {
                image: IdentityImage::Current,
                mismatch: IdentityMismatch::UaidBinding
            }
        ))
    );
}
