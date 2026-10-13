//! Final ordered backing remains charged after a scoped paired owner is evicted.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::consensus::{ConsensusKeyId, ConsensusKeyRole};

#[test]
fn paired_final_ordered_borrower_keeps_original_charge_and_root() {
    let budget = AllocationBudget::new(64 * 1024);
    let limits = LeafLimits {
        max_tables: 1,
        max_rows: 2,
        max_payload_bytes: 4096,
        max_ordered_table_bytes: 4096,
        max_streamed_value_bytes: 8192,
    };
    let key = "captured".to_owned();
    let value = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "entry")];
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.consensus_keys_by_pk",
        limits,
        &budget,
        [(&key, &value)],
    )
    .unwrap();
    let root = snapshot.ordered_root();
    let borrowed = snapshot.ordered.clone();
    let reserved = budget.reserved_bytes();
    assert!(reserved > 0);
    budget.set_limit_bytes(0);
    drop(snapshot);
    assert!(budget.reserved_bytes() > 0);
    assert!(
        budget.reserved_bytes() < reserved,
        "only lookup custody was reclaimed"
    );
    assert_eq!(borrowed.root(), root);
    assert_eq!(
        borrowed.digest_rows().next().unwrap().0,
        norito::codec::encode_adaptive(&key)
    );
    drop(borrowed);
    assert_eq!(budget.reserved_bytes(), 0);
}

fn staging_limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 4,
        max_payload_bytes: 4096,
        max_ordered_table_bytes: 16 * 1024,
        max_streamed_value_bytes: 16 * 1024,
    }
}

#[test]
fn paired_build_funds_staging_and_final_copies_at_the_same_time() {
    let key = "copied key".to_owned();
    let value = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "entry")];
    let budget = AllocationBudget::new(64 * 1024);
    let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
        "world.consensus_keys_by_pk",
        staging_limits(),
        &budget,
        [(&key, &value)],
    )
    .unwrap();
    let final_bytes = budget.reserved_bytes();
    let staged_bytes =
        std::mem::size_of::<PairedDigestRow>() + norito::codec::encode_adaptive(&key).len();
    assert_eq!(budget.peak_reserved_bytes(), staged_bytes + final_bytes);
    let expected_root = snapshot.root();
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), 0);

    budget.set_limit_bytes(final_bytes);
    assert!(matches!(
        CanonicalTableLeafSet::paired_table_from_rows(
            "world.consensus_keys_by_pk",
            staging_limits(),
            &budget,
            [(&key, &value)],
        ),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(NoritoKeyRangeError::Admission(_)))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(staged_bytes + final_bytes);
    let retry = CanonicalTableLeafSet::paired_table_from_rows(
        "world.consensus_keys_by_pk",
        staging_limits(),
        &budget,
        [(&key, &value)],
    )
    .unwrap();
    assert_eq!(retry.root(), expected_root);
    drop(retry);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn staging_refusal_keeps_original_release_and_never_yields_partial_snapshot() {
    use iroha_allocation::AllocationRefusal;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let key = "original pool".to_owned();
    let value = vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "entry")];
    let budget = AllocationBudget::new(64 * 1024);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let Err(LeafError::Admission(AllocationRefusal::Capacity { release, .. })) =
        CanonicalTableLeafSet::paired_table_from_rows(
            "world.consensus_keys_by_pk",
            staging_limits(),
            &budget,
            [(&key, &value)],
        )
    else {
        panic!("first staged key must preserve original pool refusal");
    };
    let mut wait = Box::pin(release.wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    let other = AllocationBudget::new(1);
    drop(other.try_reserve_bytes(1).unwrap());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    drop(occupied);
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
    drop(wait);
    drop(registration);
    let duplicate = [(&key, &value), (&key, &value)];
    assert!(matches!(
        CanonicalTableLeafSet::paired_table_from_rows(
            "world.consensus_keys_by_pk",
            staging_limits(),
            &budget,
            duplicate
        ),
        Err(LeafError::OrderedRange(NoritoKeyRangeError::UnsortedKeys))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn semantic_identity_rejection_and_projection_unwind_preserve_errors_and_cleanup() {
    use iroha_data_model::trigger::TriggerId;
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
    };
    let keys: [TriggerId; 2] = [
        "staged_first".parse().unwrap(),
        "staged_second".parse().unwrap(),
    ];
    let values = [1_u8, 2_u8];
    let budget = AllocationBudget::new(64 * 1024);
    let calls = Cell::new(0);
    assert!(matches!(
        CanonicalTableLeafSet::paired_semantic_table_from_rows(
            "triggers.data",
            "wrong identity",
            staging_limits(),
            &budget,
            keys.iter().zip(&values),
            |_| {
                calls.set(calls.get() + 1);
                1_u32
            },
        ),
        Err(LeafError::TypeMismatch("triggers.data"))
    ));
    assert_eq!(calls.get(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
    let result = catch_unwind(AssertUnwindSafe(|| {
        CanonicalTableLeafSet::paired_semantic_table_from_rows(
            "triggers.data",
            "iroha:state:trigger-data-action:v1",
            staging_limits(),
            &budget,
            keys.iter().zip(&values),
            |_| {
                calls.set(calls.get() + 1);
                assert!(
                    budget.reserved_bytes() > 0,
                    "key is funded before projection"
                );
                assert_ne!(calls.get(), 2, "projection unwinds with prior staged rows");
                1_u32
            },
        )
    }));
    assert!(result.is_err());
    assert_eq!(calls.get(), 2);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn arbitrary_single_pass_iterator_keeps_exact_roots_and_raw_key_order() {
    let keys = ["aaaa".to_owned(), "bbbb".to_owned(), "cccc".to_owned()];
    let values = [
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "a")],
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "b")],
        vec![ConsensusKeyId::new(ConsensusKeyRole::Validator, "c")],
    ];
    let budget = AllocationBudget::new(64 * 1024);
    let ordered = CanonicalTableLeafSet::paired_table_from_rows(
        "world.consensus_keys_by_pk",
        staging_limits(),
        &budget,
        keys.iter().zip(&values),
    )
    .unwrap();
    let mut next = 0;
    let permutation = [2, 0, 1];
    let rows = std::iter::from_fn(|| {
        let index = permutation.get(next).copied();
        next += 1;
        index.map(|index| (&keys[index], &values[index]))
    });
    assert_eq!(rows.size_hint(), (0, None));
    let unknown = CanonicalTableLeafSet::paired_table_from_rows(
        "world.consensus_keys_by_pk",
        staging_limits(),
        &budget,
        rows,
    )
    .unwrap();
    assert_eq!(next, 4);
    assert_eq!(unknown.root(), ordered.root());
    assert_eq!(unknown.ordered_root(), ordered.ordered_root());
    assert_eq!(unknown.lookup_root(), ordered.lookup_root());
    assert_eq!(
        unknown
            .ordered
            .digest_rows()
            .map(|(key, _)| key.to_vec())
            .collect::<Vec<_>>(),
        keys.iter()
            .map(norito::codec::encode_adaptive)
            .collect::<Vec<_>>()
    );
    drop(unknown);
    drop(ordered);
    assert_eq!(budget.reserved_bytes(), 0);
}
