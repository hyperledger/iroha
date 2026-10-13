//! Real MV history, malformed projections and exact local work controls.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State,
        authority_registry::{
            complete::capture_domains_table_once,
            leaf::{LeafError, LeafLimits},
        },
    },
};
use iroha_data_model::Registrable as _;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
use std::collections::BTreeMap;

use super::test_support::*;

#[test]
fn native_transfers_deletions_reinsertions_and_replacement_preserve_both_cuts() {
    let world = fixture();
    for replacement in [false, true] {
        change(&world, replacement);
        let original = encoded(&world);
        let checked =
            without_allocations(|| CheckedDomainOwnership::capture(&world, 1_000_000)).unwrap();
        assert_eq!(
            checked.domains().get(&id("moving")).unwrap().owned_by(),
            if replacement { &*ALICE_ID } else { &*BOB_ID }
        );
        assert_eq!(
            before(checked.domains(), &id("moving")).unwrap().owned_by(),
            &*ALICE_ID
        );
        assert!(checked.domains().get(&id("removed")).is_none());
        assert!(before(checked.domains(), &id("removed")).is_some());
        assert!(before(checked.domains(), &id("added")).is_none());
        assert!(checked.domains().undo().contains_key(&id("absent")));
        assert!(checked.domains().undo().contains_key(&id("untouched")));
        assert!(without_allocations(|| checked.matches_current()).unwrap());
        drop(checked);
        assert_eq!(
            encoded(&world),
            original,
            "validation may not rewrite current or undo maps"
        );
    }
}

#[test]
fn rejects_missing_extra_duplicate_wrong_owner_and_empty_current_buckets() {
    for mutation in 0..5 {
        let mut world = fixture();
        edit_index(&mut world, |current, _| match mutation {
            0 => {
                current.get_mut(&*ALICE_ID).unwrap().remove(&id("moving"));
            }
            1 => {
                current.get_mut(&*ALICE_ID).unwrap().insert(id("ghost"));
            }
            2 => {
                current.get_mut(&*BOB_ID).unwrap().insert(id("moving"));
            }
            3 => {
                current.get_mut(&*ALICE_ID).unwrap().remove(&id("moving"));
                current.get_mut(&*BOB_ID).unwrap().insert(id("moving"));
            }
            4 => {
                current.insert(BOB_ID.clone(), BTreeSet::new());
            }
            _ => unreachable!(),
        });
        let original = encoded(&world);
        let mismatch = if matches!(mutation, 0 | 3 | 4) {
            OwnershipMismatch::MissingDomain
        } else {
            OwnershipMismatch::ForeignDomain
        };
        assert_eq!(
            error(&world, 1_000_000),
            DomainOwnershipError::Corrupt {
                image: OwnershipImage::Current,
                mismatch
            }
        );
        assert_eq!(encoded(&world), original);
    }
    // An otherwise unused owner cannot have an empty bucket either.
    let mut world = empty();
    world
        .domains_by_owner
        .insert(ALICE_ID.clone(), BTreeSet::new());
    assert_eq!(
        error(&world, 1),
        DomainOwnershipError::Corrupt {
            image: OwnershipImage::Current,
            mismatch: OwnershipMismatch::EmptyBucket
        }
    );
}

#[test]
fn correct_current_rows_do_not_hide_corrupt_predecessor_membership() {
    for mutation in 0..4 {
        let mut world = fixture();
        change(&world, false);
        edit_index(&mut world, |_, undo| match mutation {
            0 => {
                undo.insert(ALICE_ID.clone(), None);
            }
            1 => {
                undo.get_mut(&*ALICE_ID)
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .insert(id("ghost"));
            }
            2 => {
                undo.get_mut(&*BOB_ID)
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .insert(id("moving"));
            }
            3 => {
                undo.get_mut(&*ALICE_ID)
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .remove(&id("removed"));
            }
            _ => unreachable!(),
        });
        let original = encoded(&world);
        let mismatch = if matches!(mutation, 0 | 3) {
            OwnershipMismatch::MissingDomain
        } else {
            OwnershipMismatch::ForeignDomain
        };
        assert_eq!(
            error(&world, 1_000_000),
            DomainOwnershipError::Corrupt {
                image: OwnershipImage::Predecessor,
                mismatch
            }
        );
        assert_eq!(encoded(&world), original);
    }
}

#[test]
fn exact_work_bound_charges_absent_preimages_and_never_reports_them_as_corruption() {
    let mut world = empty();
    world.domains = Storage::from_snapshot_parts(
        BTreeMap::from([(id("live"), Domain::new(id("live")).build(&ALICE_ID))]),
        BTreeMap::from([(id("absent"), None)]),
    );
    world.domains_by_owner = Storage::from_snapshot_parts(
        BTreeMap::from([(ALICE_ID.clone(), BTreeSet::from([id("live")]))]),
        // A transient owner during the block may leave a redundant absent
        // preimage. Only current/predecessor contents are derived, not the
        // intermediate sequence of touched buckets.
        BTreeMap::from([(BOB_ID.clone(), None)]),
    );
    let original = encoded(&world);
    let rows = world.domains.try_committed_view_nonblocking().unwrap();
    let owners = world
        .domains_by_owner
        .try_committed_view_nonblocking()
        .unwrap();
    let exact = exact_work(&rows, &owners);
    for limit in [0, exact - 1] {
        assert_eq!(error(&world, limit), DomainOwnershipError::WorkLimit);
    }
    drop(without_allocations(|| CheckedDomainOwnership::capture(&world, exact)).unwrap());
    assert_eq!(encoded(&world), original);
    let empty = World::default();
    drop(without_allocations(|| CheckedDomainOwnership::capture(&empty, 0)).unwrap());
}

#[test]
fn checked_owner_retains_original_rows_and_detects_equal_value_publication() {
    for canonical in [false, true] {
        let world = fixture();
        let checked =
            without_allocations(|| CheckedDomainOwnership::capture(&world, 1_000_000)).unwrap();
        if canonical {
            let mut block = world.domains.block();
            let value = block.get(&id("moving")).unwrap().clone();
            block.insert(id("moving"), value);
            block.commit();
        } else {
            let mut block = world.domains_by_owner.block();
            let value = block.get(&*ALICE_ID).unwrap().clone();
            block.insert(ALICE_ID.clone(), value);
            block.commit();
        }
        assert!(!without_allocations(|| checked.matches_current()).unwrap());
        assert_eq!(
            checked.domains().get(&id("moving")).unwrap().owned_by(),
            &*ALICE_ID
        );
        assert!(
            checked.domains().undo().is_empty(),
            "the checked reader must not silently refresh its undo"
        );
    }
}

fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 16,
        max_payload_bytes: 16_384,
        max_ordered_table_bytes: 32_768,
        max_streamed_value_bytes: 131_072,
    }
}

#[test]
fn scoped_native_capture_consumes_checked_source_and_preserves_operational_refusal() {
    let mut world = fixture();
    edit_index(&mut world, |current, _| {
        current.get_mut(&*ALICE_ID).unwrap().insert(id("ghost"));
    });
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let pool = state
        .pipeline_ivm_prepared_cache
        .read()
        .execution_budget()
        .clone();
    // A corrupt index is rejected before allocating any leaf. Rebuilding is an
    // explicit fixture operation; capture must not repair or mutate live World.
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture_domains_table_once(&state, limits()),
        Err(LeafError::DomainOwnership(DomainOwnershipError::Corrupt {
            image: OwnershipImage::Current,
            mismatch: OwnershipMismatch::ForeignDomain
        }))
    ));
    state.world.rebuild_domain_owner_index();
    assert!(matches!(
        capture_domains_table_once(
            &state,
            LeafLimits {
                max_rows: 0,
                ..limits()
            }
        ),
        Err(LeafError::DomainOwnership(DomainOwnershipError::WorkLimit))
    ));
    assert!(matches!(
        capture_domains_table_once(&state, limits()),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    pool.set_limit_bytes(16 * 1024 * 1024);
    let snapshot = capture_domains_table_once(&state, limits())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.table_id(), "world.domains");
    assert_eq!(snapshot.row_count(), 4);
}

fn one_domain(owner: AccountId, id: DomainId) -> World {
    let mut world = World::default();
    world
        .domains
        .insert(id.clone(), Domain::new(id.clone()).build(&owner));
    world.domains_by_owner.insert(owner, BTreeSet::from([id]));
    world
}

#[test]
fn named_descriptor_and_full_controller_geometry_are_exact_local_work() {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let max = DomainId::try_new("a".repeat(63), "b".repeat(63)).unwrap();
    let world = one_domain(ALICE_ID.clone(), max);
    assert_eq!(DOMAIN_OWNER_WORK_PER_ROW, 1292);
    assert_eq!(error(&world, 1291), DomainOwnershipError::WorkLimit);
    without_allocations(|| CheckedDomainOwnership::capture(&world, 1292)).unwrap();
    let members = vec![
        MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
        MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
    ];
    let owner = AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap());
    let world = one_domain(owner, id("live"));
    // A=12+2*(32+4)=84; D=4+9=13. Both images fund every
    // controller/member/scalar byte before equality, not only matching prefixes.
    let exact = 12 + 8 * (84 + 13);
    assert_eq!(error(&world, exact - 1), DomainOwnershipError::WorkLimit);
    without_allocations(|| CheckedDomainOwnership::capture(&world, exact)).unwrap();
    assert!(
        world.accounts.view().is_empty(),
        "account existence is not this relation"
    );
}

#[test]
fn single_noop_insert_and_empty_absent_images_have_exact_physical_work() {
    for kind in 0..4 {
        let mut world = if kind == 3 {
            World::default()
        } else {
            one_domain(ALICE_ID.clone(), id("live"))
        };
        let exact = match kind {
            0 => 388,
            1 => {
                let mut rows = world.domains.block();
                let value = rows.get(&id("live")).unwrap().clone();
                rows.insert(id("live"), value);
                rows.commit();
                let mut owners = world.domains_by_owner.block();
                owners.insert(ALICE_ID.clone(), BTreeSet::from([id("live")]));
                owners.commit();
                584
            }
            2 => {
                world.domains = Storage::from_snapshot_parts(
                    BTreeMap::from([(id("live"), Domain::new(id("live")).build(&ALICE_ID))]),
                    BTreeMap::from([(id("live"), None)]),
                );
                world.domains_by_owner = Storage::from_snapshot_parts(
                    BTreeMap::from([(ALICE_ID.clone(), BTreeSet::from([id("live")]))]),
                    BTreeMap::from([(ALICE_ID.clone(), None)]),
                );
                294
            }
            3 => {
                world.domains = Storage::from_snapshot_parts(
                    BTreeMap::new(),
                    BTreeMap::from([(id("absent"), None)]),
                );
                world.domains_by_owner = Storage::from_snapshot_parts(
                    BTreeMap::new(),
                    BTreeMap::from([(ALICE_ID.clone(), None)]),
                );
                2
            }
            _ => unreachable!(),
        };
        assert_eq!(error(&world, exact - 1), DomainOwnershipError::WorkLimit);
        without_allocations(|| CheckedDomainOwnership::capture(&world, exact)).unwrap();
    }
}

#[test]
fn physical_next_and_complete_key_equality_require_admission_first() {
    let visits = std::cell::Cell::new(0);
    let rows = [1, 2];
    let mut iter = rows.iter().inspect(|_| visits.set(visits.get() + 1));
    assert_eq!(
        next_physical(&mut iter, &mut Work(0)),
        Err(DomainOwnershipError::WorkLimit)
    );
    assert_eq!(visits.get(), 0);
    assert_eq!(next_physical(&mut iter, &mut Work(1)).unwrap(), Some(&1));
    assert_eq!(visits.get(), 1);
    let mut empty = rows[..0].iter();
    assert_eq!(next_physical(&mut empty, &mut Work(0)).unwrap(), None);
    for (left, right) in [(id("live"), id("live")), (id("live"), id("other"))] {
        let full = left.name().as_ref().len()
            + left.dataspace().as_ref().len()
            + right.name().as_ref().len()
            + right.dataspace().as_ref().len();
        assert_eq!(
            equal(&left, &right, &mut Work(full as u64 - 1)),
            Err(DomainOwnershipError::WorkLimit)
        );
        assert_eq!(
            equal(&left, &right, &mut Work(full as u64)).unwrap(),
            left == right
        );
    }
}

#[test]
fn malformed_typed_keys_preserve_exact_membership_without_ord_error_allocation() {
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let malformed = AccountId::new(key);
    let mut world = one_domain(malformed.clone(), id("live"));
    // An empty compact key has zero retained payload. The relation deliberately
    // does not introduce controller admission or key decoding; exact equality
    // remains valid and costs A=2, including its missing tag reference unit.
    without_allocations(|| CheckedDomainOwnership::capture(&world, 132)).unwrap();
    assert_eq!(error(&world, 131), DomainOwnershipError::WorkLimit);
    world.domains_by_owner = Storage::from_iter([(ALICE_ID.clone(), BTreeSet::from([id("live")]))]);
    assert_eq!(
        error(&world, 1_000_000),
        DomainOwnershipError::Corrupt {
            image: OwnershipImage::Current,
            mismatch: OwnershipMismatch::MissingDomain,
        }
    );
    world.domains_by_owner =
        Storage::from_iter([(malformed, BTreeSet::from([id("live"), id("ghost")]))]);
    assert_eq!(
        error(&world, 1_000_000),
        DomainOwnershipError::Corrupt {
            image: OwnershipImage::Current,
            mismatch: OwnershipMismatch::ForeignDomain,
        }
    );
}

#[test]
fn storage_key_and_stored_owner_are_the_exact_existing_source_semantics() {
    let mut world = one_domain(ALICE_ID.clone(), id("key"));
    world.domains = Storage::from_iter([(id("key"), Domain::new(id("embedded")).build(&ALICE_ID))]);
    without_allocations(|| CheckedDomainOwnership::capture(&world, 1_000_000)).unwrap();
    assert!(world.accounts.view().is_empty());
}

#[test]
fn either_original_publication_overrides_success_corruption_and_work_refusal() {
    for canonical in [false, true] {
        for result in [
            Ok(()),
            Err(DomainOwnershipError::WorkLimit),
            Err(DomainOwnershipError::Corrupt {
                image: OwnershipImage::Predecessor,
                mismatch: OwnershipMismatch::ForeignDomain,
            }),
        ] {
            let world = fixture();
            let checked = CheckedDomainOwnership::capture(&world, 1_000_000).unwrap();
            if canonical {
                world.domains.block().commit();
            } else {
                world.domains_by_owner.block().commit();
            }
            assert_eq!(
                without_allocations(|| checked.finish_validation(result)).err(),
                Some(DomainOwnershipError::Publication(
                    PublicationPreparationError::Changed
                ))
            );
        }
    }
}

#[test]
fn predecessor_masking_funds_every_physical_candidate_after_an_equal_key() {
    #[expect(
        clippy::zero_sized_map_values,
        reason = "Storage snapshot parts encode current unit-valued membership rows and their separate undo map"
    )]
    let rows = Storage::from_snapshot_parts(
        BTreeMap::from([(id("live"), ())]),
        BTreeMap::from([(id("live"), None), (id("tail"), None)]),
    );
    let view = rows.try_committed_view_nonblocking().unwrap();
    // Current advance 1, each of two undo candidates 1+26 full key bytes,
    // then both absent undo physical rows 2: 57 total. An equal first key
    // must not terminate the funded scan before the other actual candidate.
    let inspected = std::cell::Cell::new(0);
    assert_eq!(
        without_allocations(|| visit_original(
            &view,
            OwnershipImage::Predecessor,
            &mut Work(56),
            |_, _, _| {
                inspected.set(inspected.get() + 1);
                Ok(())
            }
        )),
        Err(DomainOwnershipError::WorkLimit)
    );
    assert_eq!(inspected.get(), 0);
    without_allocations(|| {
        visit_original(
            &view,
            OwnershipImage::Predecessor,
            &mut Work(57),
            |_, _, _| {
                inspected.set(inspected.get() + 1);
                Ok(())
            },
        )
    })
    .unwrap();
    assert_eq!(inspected.get(), 0);
}

#[test]
fn complete_controller_work_precedes_equality_even_when_variant_or_key_differs() {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            1,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    for (left, right, exact) in [
        (ALICE_ID.clone(), BOB_ID.clone(), 68),
        (ALICE_ID.clone(), multisig.clone(), 118),
        (multisig.clone(), multisig, 168),
    ] {
        assert_eq!(
            without_allocations(|| equal(&left, &right, &mut Work(exact - 1))),
            Err(DomainOwnershipError::WorkLimit)
        );
        assert_eq!(
            without_allocations(|| equal(&left, &right, &mut Work(exact))).unwrap(),
            left == right
        );
    }
}
