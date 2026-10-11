//! Four actual frozen sources, complete both-image predicates and original pool custody.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{
                capture_contract_subject_bindings_once,
                table_capture::frozen::capture_original_table_once,
            },
            grouped_ownership::{GroupImage, GroupMismatch, GroupedOwnershipError},
        },
        block_field::BlockField,
        contract_subject_validation::test_support::{
            address, binding, other_address, state as fixture_state, world,
        },
    },
    test_allocations::allocations_during,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountDetails, block::BlockHeader, smart_contract::ContractLifecycleOwnerV1,
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::{
    BlockRetirement as _,
    storage::{Storage, StorageReadOnly},
};
use std::num::NonZeroU64;

fn new_state(world: World) -> State {
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
fn extra() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![0x73; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
fn details() -> AccountValue {
    AccountValue::new(AccountDetails::default())
}
fn changed_binding() -> ContractSubjectBinding {
    let mut row = binding();
    row.lifecycle.revision = 2;
    row.lifecycle.pending_owner = Some(ContractLifecycleOwnerV1::Account(BOB_ID.clone()));
    row.lifecycle.active_code_hash = Some(Hash::new(b"original active code"));
    row.lifecycle.retained_code_hash = Some(Hash::new(b"original active code"));
    row
}
fn stage(block: &mut StateBlock<'_>) {
    let row = changed_binding();
    block
        .world
        .contract_instances
        .insert(address(), row.lifecycle.active_code_hash.unwrap());
    block.world.contract_subject_bindings.insert(address(), row);
    block
        .world
        .contract_subject_addresses
        .insert(binding().subject, address()); // no-op
    let other = ContractSubjectBinding::new_direct(&other_address(), ALICE_ID.clone());
    block
        .world
        .accounts
        .insert(other.subject.clone(), details());
    block
        .world
        .contract_subject_addresses
        .insert(other.subject.clone(), other_address());
    block
        .world
        .contract_subject_bindings
        .insert(other_address(), other);
    block.world.accounts.remove(extra()); // actual prior absence
    block.world.contract_subject_addresses.remove(extra());
    block.world.contract_instances.remove(other_address());
}
fn expected_world() -> World {
    let mut world = world();
    let row = changed_binding();
    world
        .contract_instances
        .insert(address(), row.lifecycle.active_code_hash.unwrap());
    world.contract_subject_bindings.insert(address(), row);
    let other = ContractSubjectBinding::new_direct(&other_address(), ALICE_ID.clone());
    world.accounts.insert(other.subject.clone(), details());
    world
        .contract_subject_addresses
        .insert(other.subject.clone(), other_address());
    world
        .contract_subject_bindings
        .insert(other_address(), other);
    *world
}
fn without_allocations<T>(run: impl FnOnce() -> T) -> T {
    let mut value = None;
    assert_eq!(allocations_during(|| value = Some(run())), 0);
    value.unwrap()
}
fn exact_work(original: &Original<'_>) -> u64 {
    let mut low = 0;
    let mut high = 16_777_216;
    let check = |work| {
        validate_original_contract_subjects(
            &original.rows,
            &original.reverse,
            &original.accounts,
            &original.instances,
            work,
        )
    };
    check(high).unwrap();
    while low < high {
        let allowance = low + (high - low) / 2;
        match check(allowance) {
            Ok(()) => high = allowance,
            Err(GroupedOwnershipError::WorkLimit) => low = allowance + 1,
            other => panic!("valid original subject relation: {other:?}"),
        }
    }
    low
}
fn assert_equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}

#[test]
fn exact_four_source_insert_lifecycle_active_code_noop_and_absent_histories_keep_originals() {
    let state = fixture_state();
    let mut block = state.block(header());
    stage(&mut block);
    let ids = [
        block.world.contract_subject_bindings.publication_identity(),
        block
            .world
            .contract_subject_addresses
            .publication_identity(),
        block.world.accounts.publication_identity(),
        block.world.contract_instances.publication_identity(),
    ];
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.reverse.mode(),
        original.accounts.mode(),
        original.instances.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Ordinary);
    }
    assert!(
        original
            .accounts
            .undo_entries()
            .any(|(key, prior)| key == &extra() && prior.is_none())
    );
    assert!(
        original
            .reverse
            .undo_entries()
            .any(|(key, prior)| key == &binding().subject && prior == &Some(address()))
    );
    assert!(
        original
            .instances
            .undo_entries()
            .any(|(key, prior)| key == &other_address() && prior.is_none())
    );
    let exact = exact_work(&original);
    assert_eq!(
        without_allocations(|| validate_original_contract_subjects(
            &original.rows,
            &original.reverse,
            &original.accounts,
            &original.instances,
            exact - 1
        )),
        Err(GroupedOwnershipError::WorkLimit)
    );
    without_allocations(|| {
        validate_original_contract_subjects(
            &original.rows,
            &original.reverse,
            &original.accounts,
            &original.instances,
            exact,
        )
    })
    .unwrap();
    let actual = capture(&block, limits(), exact).unwrap().unwrap();
    let expected = new_state(expected_world());
    assert_equal(
        &actual,
        &capture_contract_subject_bindings_once(&expected, limits())
            .unwrap()
            .unwrap(),
    );
    assert_equal(
        &actual,
        &capture_original_table_once(&block, "world.contract_subject_bindings", limits(), exact)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        ids,
        [
            block.world.contract_subject_bindings.publication_identity(),
            block
                .world
                .contract_subject_addresses
                .publication_identity(),
            block.world.accounts.publication_identity(),
            block.world.contract_instances.publication_identity()
        ]
    );
}

#[test]
fn ordinary_deletion_keeps_exact_prior_subject_account_inverse_and_inactive_instance() {
    let state = fixture_state();
    let mut block = state.block(header());
    block.world.contract_subject_bindings.remove(address());
    block
        .world
        .contract_subject_addresses
        .remove(binding().subject.clone());
    block.world.accounts.remove(binding().subject);
    block.world.contract_instances.remove(address());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.current_entries().len(), 0);
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(key, prior)| key == &address() && prior == &Some(binding()))
    );
    let exact = exact_work(&original);
    let snapshot = capture(&block, limits(), exact).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 0);
    let mut expected = World::default();
    for owner in [ALICE_ID.clone(), BOB_ID.clone()] {
        expected.accounts.insert(owner, details());
    }
    assert_equal(
        &snapshot,
        &capture_contract_subject_bindings_once(&new_state(expected), limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn each_existing_source_and_inverse_failure_rejects_current_or_prior_before_allocation() {
    for previous in [false, true] {
        for defect in 0..6 {
            let mut state = fixture_state();
            if previous {
                match defect {
                    0 => {
                        let mut bad = binding();
                        bad.lifecycle.revision = 0;
                        state.world.contract_subject_bindings.insert(address(), bad);
                    }
                    1 => {
                        state.world.accounts = Storage::from_iter([
                            (ALICE_ID.clone(), details()),
                            (BOB_ID.clone(), details()),
                        ]);
                    }
                    2 => {
                        state
                            .world
                            .contract_instances
                            .insert(address(), Hash::new(b"bad original hash"));
                    }
                    3 => {
                        state.world.contract_subject_addresses = Storage::new();
                    }
                    4 => {
                        state
                            .world
                            .contract_subject_addresses
                            .insert(binding().subject, other_address());
                    }
                    5 => {
                        state
                            .world
                            .contract_subject_addresses
                            .insert(BOB_ID.clone(), address());
                    }
                    _ => unreachable!(),
                }
            }
            let budget = state.ivm_execution_budget();
            let mut block = state.block(header());
            if previous {
                match defect {
                    0 => {
                        block
                            .world
                            .contract_subject_bindings
                            .insert(address(), binding());
                    }
                    1 => {
                        block.world.accounts.insert(binding().subject, details());
                    }
                    2 => {
                        block.world.contract_instances.remove(address());
                    }
                    3 | 4 => {
                        block
                            .world
                            .contract_subject_addresses
                            .insert(binding().subject, address());
                    }
                    5 => {
                        block
                            .world
                            .contract_subject_addresses
                            .remove(BOB_ID.clone());
                    }
                    _ => unreachable!(),
                }
            } else {
                match defect {
                    0 => {
                        let mut bad = binding();
                        bad.lifecycle.revision = 0;
                        block.world.contract_subject_bindings.insert(address(), bad);
                    }
                    1 => {
                        block.world.accounts.remove(binding().subject);
                    }
                    2 => {
                        block
                            .world
                            .contract_instances
                            .insert(address(), Hash::new(b"bad current hash"));
                    }
                    3 => {
                        block
                            .world
                            .contract_subject_addresses
                            .remove(binding().subject);
                    }
                    4 => {
                        block
                            .world
                            .contract_subject_addresses
                            .insert(binding().subject, other_address());
                    }
                    5 => {
                        block
                            .world
                            .contract_subject_addresses
                            .insert(BOB_ID.clone(), address());
                    }
                    _ => unreachable!(),
                }
            }
            freeze(&mut block);
            let baseline = budget.reserved_bytes();
            budget.set_limit_bytes(0);
            let original = Original::retain(&block).unwrap();
            let error = without_allocations(|| {
                validate_original_contract_subjects(
                    &original.rows,
                    &original.reverse,
                    &original.accounts,
                    &original.instances,
                    16_777_216,
                )
            })
            .unwrap_err();
            let expected = if previous {
                GroupImage::Predecessor
            } else {
                GroupImage::Current
            };
            match &error {
                GroupedOwnershipError::Source { image, .. } => {
                    assert!(defect < 3);
                    assert_eq!(*image, expected);
                }
                GroupedOwnershipError::Corrupt {
                    image, mismatch, ..
                } => {
                    assert!(defect >= 3);
                    assert_eq!(*image, expected);
                    assert_eq!(
                        *mismatch,
                        if defect == 5 {
                            GroupMismatch::ForeignMember
                        } else {
                            GroupMismatch::MissingMember
                        }
                    );
                }
                other => panic!("existing exact semantic rejection: {other:?}"),
            }
            assert_eq!(
                capture(&block, limits(), 16_777_216).err(),
                Some(LeafError::GroupedOwnership(error))
            );
            assert_eq!(budget.reserved_bytes(), baseline);
        }
    }
}

#[test]
fn every_foreign_target_mixed_mode_partial_and_released_source_refuses() {
    for source in 0..4 {
        for mixed in [false, true] {
            let state = fixture_state();
            let foreign = fixture_state();
            let mut block = state.block(header());
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            let target = if mixed { &state } else { &foreign };
            match source {
                0 => {
                    block.world.contract_subject_bindings.release_writers();
                    block.world.contract_subject_bindings = BlockField::new(if mixed {
                        target.world.contract_subject_bindings.block_and_revert()
                    } else {
                        target.world.contract_subject_bindings.block()
                    });
                }
                1 => {
                    block.world.contract_subject_addresses.release_writers();
                    block.world.contract_subject_addresses = BlockField::new(if mixed {
                        target.world.contract_subject_addresses.block_and_revert()
                    } else {
                        target.world.contract_subject_addresses.block()
                    });
                }
                2 => {
                    block.world.accounts.release_writers();
                    block.world.accounts = BlockField::new(if mixed {
                        target.world.accounts.block_and_revert()
                    } else {
                        target.world.accounts.block()
                    });
                }
                3 => {
                    block.world.contract_instances.release_writers();
                    block.world.contract_instances = BlockField::new(if mixed {
                        target.world.contract_instances.block_and_revert()
                    } else {
                        target.world.contract_instances.block()
                    });
                }
                _ => unreachable!(),
            }
            freeze(&mut block);
            assert!(capture(&block, limits(), 0).unwrap().is_none());
        }
    }
    {
        let state = fixture_state();
        let mut block = state.block(header());
        block.world.contract_subject_bindings.begin_freeze();
        block.world.contract_subject_bindings.finish_freeze();
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    for source in 0..4 {
        let state = fixture_state();
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.contract_subject_bindings.release_writers(),
            1 => block.world.contract_subject_addresses.release_writers(),
            2 => block.world.accounts.release_writers(),
            3 => block.world.contract_instances.release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
}

#[test]
fn exact_original_pool_refusal_retry_private_rows_and_final_snapshot_drop_remain_owned() {
    let _retirement_pin = crossbeam_epoch::pin();
    let state = fixture_state();
    let budget = state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let pointer = core::ptr::from_ref(
        block
            .world
            .contract_subject_bindings
            .get(&address())
            .unwrap(),
    );
    freeze(&mut block);
    let baseline = budget.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
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
        core::ptr::from_ref(
            block
                .world
                .contract_subject_bindings
                .get(&address())
                .unwrap()
        ),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(budget.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn each_later_equal_or_changed_native_publication_cannot_refresh_original_subject_sources() {
    let state = fixture_state();
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let snapshot = capture(&block, limits(), 16_777_216).unwrap().unwrap();
    for source in 0..4 {
        for changed in [false, true] {
            match source {
                0 => {
                    let mut update = state.world.contract_subject_bindings.block();
                    if changed {
                        let mut row = binding();
                        row.lifecycle.revision = 3;
                        update.insert(address(), row);
                    }
                    update.commit();
                }
                1 => {
                    let mut update = state.world.contract_subject_addresses.block();
                    if changed {
                        update.insert(binding().subject, other_address());
                    }
                    update.commit();
                }
                2 => {
                    let mut update = state.world.accounts.block();
                    if changed {
                        update.insert(extra(), details());
                    }
                    update.commit();
                }
                3 => {
                    let mut update = state.world.contract_instances.block();
                    if changed {
                        update.insert(address(), Hash::new(b"later target"));
                    }
                    update.commit();
                }
                _ => unreachable!(),
            }
            assert_equal(
                &snapshot,
                &capture(&block, limits(), 16_777_216).unwrap().unwrap(),
            );
        }
    }
}

#[test]
fn actual_replace_keeps_rewound_subject_lifecycle_inverse_accounts_instances_and_modes() {
    let state = fixture_state();
    {
        let mut rows = state.world.contract_subject_bindings.block();
        let mut reverse = state.world.contract_subject_addresses.block();
        let mut accounts = state.world.accounts.block();
        let mut instances = state.world.contract_instances.block();
        let row = changed_binding();
        instances.insert(address(), row.lifecycle.active_code_hash.unwrap());
        rows.insert(address(), row);
        let other = ContractSubjectBinding::new_direct(&other_address(), ALICE_ID.clone());
        accounts.insert(other.subject.clone(), details());
        reverse.insert(other.subject.clone(), other_address());
        rows.insert(other_address(), other);
        rows.commit();
        reverse.commit();
        accounts.commit();
        instances.commit();
    }
    let mut block = state.block_and_revert(header());
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.reverse.mode(),
        original.accounts.mode(),
        original.instances.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Replace);
    }
    let exact = exact_work(&original);
    assert_eq!(
        capture(&block, limits(), exact - 1).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_equal(
        &capture(&block, limits(), exact).unwrap().unwrap(),
        &capture_contract_subject_bindings_once(&fixture_state(), limits())
            .unwrap()
            .unwrap(),
    );
}

#[test]
fn local_work_refusal_precedes_latent_subject_corruption_without_a_verdict() {
    let state = fixture_state();
    let mut block = state.block(header());
    let mut bad = binding();
    bad.lifecycle.revision = 0;
    block.world.contract_subject_bindings.insert(address(), bad);
    freeze(&mut block);
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert!(matches!(
        capture(&block, limits(), 16_777_216),
        Err(LeafError::GroupedOwnership(GroupedOwnershipError::Source {
            image: GroupImage::Current,
            reason: "contract lifecycle revision must be non-zero",
            ..
        }))
    ));
}
