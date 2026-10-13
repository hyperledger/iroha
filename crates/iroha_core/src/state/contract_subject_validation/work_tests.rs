//! Independent exact source work, physical admission and unchanged lifecycle tests.

use super::*;
use crate::test_allocations::allocations_during;
use iroha_data_model::account::{MultisigMember, MultisigPolicy};
use iroha_data_model::smart_contract::ContractEmergencyHoldV1;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
use std::{cell::Cell, collections::BTreeMap};

fn without_allocations<T>(run: impl FnOnce() -> T) -> T {
    let mut value = None;
    assert_eq!(allocations_during(|| value = Some(run())), 0);
    value.unwrap()
}
fn kind<T>(result: Result<T, Error<'_>>) -> Result<T, ErrorKind> {
    result.map_err(|error| error.kind)
}
fn multi() -> AccountId {
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
fn every_actual_advance_mask_and_lookup_tail_is_funded_before_next() {
    let first = test_support::address();
    let other = test_support::other_address();
    let width = first.as_str().len() + other.as_str().len();
    #[expect(
        clippy::zero_sized_map_values,
        reason = "Storage snapshot parts encode current unit-valued membership rows and their separate undo map"
    )]
    let rows = Storage::from_snapshot_parts(
        BTreeMap::from([(first.clone(), ())]),
        BTreeMap::from([(first.clone(), None), (other.clone(), None)]),
    );
    let original = rows.try_committed_view_nonblocking().unwrap();
    // current1 + (undo advance1 + equality2*first) + (advance1 + equality first+other) + undo2
    let exact = 5 + 2 * first.as_str().len() + width;
    for bound in [exact - 1, exact] {
        let inspected = Cell::new(0);
        let result = without_allocations(|| {
            kind(visit(
                &original,
                Image::Predecessor,
                &mut Work::bounded(bound as u64),
                |_, _, _| {
                    inspected.set(inspected.get() + 1);
                    Ok(())
                },
            ))
        });
        assert_eq!(
            result,
            if bound == exact {
                Ok(())
            } else {
                Err(ErrorKind::WorkLimit)
            }
        );
        assert_eq!(inspected.get(), 0);
    }
    let rows = Storage::from_iter([(first, 1_u8), (other, 2)]);
    let original = rows.try_committed_view_nonblocking().unwrap();
    let wanted = original.current_rows().next().unwrap().0;
    let cost = original
        .current_rows()
        .map(|(key, _)| 1 + key.as_str().len() + wanted.as_str().len())
        .sum::<usize>();
    assert_eq!(
        without_allocations(|| kind(lookup(
            &original,
            Image::Current,
            wanted,
            &mut Work::bounded((cost - 1) as u64)
        ))),
        Err(ErrorKind::WorkLimit)
    );
    assert!(
        without_allocations(|| kind(lookup(
            &original,
            Image::Current,
            wanted,
            &mut Work::bounded(cost as u64)
        )))
        .unwrap()
        .is_some()
    );
    let visits = Cell::new(0);
    let values = [1];
    let mut physical = values.iter().inspect(|_| visits.set(visits.get() + 1));
    assert_eq!(
        kind(next_physical(&mut physical, &mut Work::bounded(0))),
        Err(ErrorKind::WorkLimit)
    );
    assert_eq!(visits.get(), 0);
}

#[test]
fn existing_nine_attempt_subject_vector_prepays_each_hash_and_strict_check() {
    let address = test_support::address();
    let expected = address.subject_id();
    let expected = expected
        .expect_single_signatory()
        .borrowed_parts()
        .unwrap()
        .1;
    let per_attempt =
        b"iroha:contract-subject:hash-to-point:v1:".len() + address.as_str().len() + 4 + 1;
    let exact = 9 * per_attempt;
    for (bound, admitted) in [(exact - 1, false), (exact, true)] {
        let mut work = Work::bounded(bound as u64);
        let mut calls = 0;
        let result = without_allocations(|| {
            kind(address.try_subject_key_bytes(|bytes| {
                assert_eq!(bytes + 1, per_attempt);
                calls += 1;
                work.charge(bytes + 1)
            }))
        });
        assert_eq!(
            calls, 9,
            "same eight rejected V1 candidates and final admission"
        );
        if admitted {
            assert_eq!(result.unwrap().as_slice(), expected);
        } else {
            assert_eq!(result, Err(ErrorKind::WorkLimit));
        }
    }
}

#[test]
fn shared_controller_and_lifecycle_geometry_are_complete_without_new_validity() {
    // Independently sum the retained predicate inputs, not Norito frame sizes.
    const SINGLE_ACCOUNT_WORK: u64 = 1 + 1 + 32; // controller, algorithm, Ed25519 payload
    const TWO_MEMBER_MULTISIG_WORK: u64 = 1 + (1 + 2 + 8) + 2 + 2 * (1 + 2 + 32);
    // Controller, version/threshold/count, two advances, algorithm/weight/key per member.
    const LIFECYCLE_FIELDS: u64 = 2 // u16 version
        + 8 // u64 revision
        + 1 // active-code-hash option
        + 1 // retained-code-hash option
        + 1 // pending-owner option
        + 1 // Parliament delegation
        + 1 // origin discriminant
        + 1; // emergency-hold option
    const DIRECT_WORK: u64 = LIFECYCLE_FIELDS + 1 + SINGLE_ACCOUNT_WORK;
    const PENDING_WORK: u64 = DIRECT_WORK + 1 + TWO_MEMBER_MULTISIG_WORK;
    const HOLD_FIELDS: u64 = 3 * 32 + 2 * 8; // three digests and two u64 heights
    const HOLD_REASON: u64 = 4096 + 8; // original whitespace and "incident" bytes
    const HELD_WORK: u64 = DIRECT_WORK + HOLD_FIELDS + HOLD_REASON;
    const PARLIAMENT_WORK: u64 = LIFECYCLE_FIELDS + 1 + 2 * 32;
    // The owner tags above are separate from AccountId controller tags. Direct
    // deployer and Parliament proposer are historical, uninspected origin fields.
    let owner = multi();
    for (left, right, exact) in [
        (ALICE_ID.clone(), BOB_ID.clone(), 68),
        (ALICE_ID.clone(), owner.clone(), 118),
        (owner.clone(), owner.clone(), 168),
    ] {
        assert_eq!(
            without_allocations(|| kind(equal(&left, &right, &mut Work::bounded(exact - 1)))),
            Err(ErrorKind::WorkLimit)
        );
        assert_eq!(
            without_allocations(|| kind(equal(&left, &right, &mut Work::bounded(exact)))).unwrap(),
            left == right
        );
    }
    let mut discarded = ALICE_ID.expect_single_signatory().clone();
    discarded.zeroize_for_confidential_discard();
    let malformed = AccountId::new(discarded);
    assert_eq!(
        without_allocations(|| kind(equal(&malformed, &ALICE_ID, &mut Work::bounded(35)))),
        Err(ErrorKind::WorkLimit)
    );
    assert!(
        !without_allocations(|| kind(equal(&malformed, &ALICE_ID, &mut Work::bounded(36))))
            .unwrap()
    );
    let direct = test_support::binding().lifecycle;
    let mut pending = direct.clone();
    pending.pending_owner = Some(ContractLifecycleOwnerV1::Account(owner));
    let mut held = direct.clone();
    held.emergency_hold = Some(ContractEmergencyHoldV1 {
        incident_digest: [1; 32],
        proposal_content_id: [2; 32],
        governance_attempt_id: [3; 32],
        reason: " ".repeat(4096) + "incident",
        imposed_at_height: 1,
        expires_at_height: 2,
    });
    let parliament = ContractLifecycleControlV1::parliament(
        test_support::other_address().subject_id(),
        [1; 32],
        [2; 32],
    );
    for (lifecycle, exact) in [
        (&direct, DIRECT_WORK),
        (&pending, PENDING_WORK),
        (&held, HELD_WORK),
        (&parliament, PARLIAMENT_WORK),
    ] {
        assert_eq!(
            without_allocations(|| kind(prepay_lifecycle(
                lifecycle,
                &mut Work::bounded(exact - 1)
            ))),
            Err(ErrorKind::WorkLimit)
        );
        without_allocations(|| kind(prepay_lifecycle(lifecycle, &mut Work::bounded(exact))))
            .unwrap();
        without_allocations(|| lifecycle.validate()).unwrap();
    }
    for (hash, exact) in [(None, 1), (Some(Hash::new(b"active")), 33)] {
        assert_eq!(
            kind(prepay_optional_hash(
                hash.as_ref(),
                &mut Work::bounded(exact - 1)
            )),
            Err(ErrorKind::WorkLimit)
        );
        kind(prepay_optional_hash(
            hash.as_ref(),
            &mut Work::bounded(exact),
        ))
        .unwrap();
    }
}

#[test]
fn exclusive_startup_history_uses_the_same_full_both_image_source_relation() {
    let mut world = test_support::world();
    let world = &mut world.0;
    let source = world.contract_subject_bindings.history();
    let accounts = world.accounts.history();
    let instances = world.contract_instances.history();
    without_allocations(|| validate_sources(&source, &accounts, &instances, &mut Work::startup()))
        .unwrap();
    assert_eq!(
        without_allocations(|| kind(validate_sources(
            &source,
            &accounts,
            &instances,
            &mut Work::bounded(0)
        ))),
        Err(ErrorKind::WorkLimit)
    );
}
