//! Original-pool arithmetic ownership and physical allocator refusal controls.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_primitives::numeric::ChargedQuantity;

#[test]
fn pending_slash_visits_original_key_order_and_retains_ineligible_and_unvisited_rows() {
    let validator = iroha_test_samples::ALICE_ID.clone();
    let requests = [
        Hash::new(b"first"),
        Hash::new(b"second"),
        Hash::new(b"third"),
    ];
    let mut requests = requests;
    requests.sort_unstable();
    let pending_unbonds = requests
        .iter()
        .enumerate()
        .map(|(index, &request_id)| {
            (
                request_id,
                PublicLaneUnbonding {
                    request_id,
                    amount: Quantity::from(10_u64),
                    release_at_ms: 0,
                    slashable_through_height: if index == 1 { 1 } else { 2 },
                    liability_release_height: 2,
                },
            )
        })
        .collect();
    let mut shares = [(
        (LaneId::SINGLE, validator.clone(), validator.clone()),
        PublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: validator.clone(),
            bonded: Quantity::zero(),
            pending_unbonds,
            metadata: Metadata::default(),
        },
    )];
    let amount = Quantity::from(15_u64);
    slash_pending_unbond_group(&mut shares, &validator, &validator, true, &amount, Some(2))
        .unwrap();
    let pending = &shares[0].1.pending_unbonds;
    assert!(!pending.contains_key(&requests[0]));
    assert_eq!(pending[&requests[1]].amount, Quantity::from(10_u64));
    assert_eq!(pending[&requests[2]].amount, Quantity::from(5_u64));
    // A positive slash that exactly consumes the first eligible request is satisfied
    // there: the traversal must keep the later malformed request without reading it.
    let mut ordered = [Hash::new(b"satisfied-first"), Hash::new(b"malformed-later")];
    ordered.sort_unstable();
    let [first, later] = ordered;
    let unbonding = |request_id| PublicLaneUnbonding {
        request_id,
        amount: Quantity::from(10_u64),
        release_at_ms: 0,
        slashable_through_height: 2,
        liability_release_height: 2,
    };
    let mut satisfied = [(
        (LaneId::SINGLE, validator.clone(), validator.clone()),
        PublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: validator.clone(),
            bonded: Quantity::zero(),
            pending_unbonds: [
                (first, unbonding(first)),
                (later, unbonding(Hash::new(b"malformed"))),
            ]
            .into_iter()
            .collect(),
            metadata: Metadata::default(),
        },
    )];
    let later_before = satisfied[0].1.pending_unbonds[&later].clone();
    slash_pending_unbond_group(
        &mut satisfied,
        &validator,
        &validator,
        true,
        &Quantity::from(10_u64),
        Some(2),
    )
    .unwrap();
    assert!(!satisfied[0].1.pending_unbonds.contains_key(&first));
    assert_eq!(satisfied[0].1.pending_unbonds[&later], later_before);
    // A slash that needs a malformed eligible request fails without any change.
    shares[0]
        .1
        .pending_unbonds
        .get_mut(&requests[2])
        .unwrap()
        .request_id = Hash::new(b"malformed");
    let before = shares.clone();
    assert!(
        slash_pending_unbond_group(&mut shares, &validator, &validator, true, &amount, Some(2))
            .is_err()
    );
    assert_eq!(shares, before);
}

#[test]
fn numeric_index_rejects_foreign_ledger_before_consuming_original_reservation() {
    let source = Quantity::from(123_u64);
    let aggregate = QuantityAccumulator::from_quantity(&source);
    let layout = aggregate.admission_layout().unwrap();
    let original = AllocationBudget::new(1024);
    let foreign = AllocationBudget::new(1024);
    let mut reservation = original.try_reserve(layout).unwrap();
    let mut ledger = ChargedBuffer::new(1, &foreign).unwrap();
    let result = materialize_index_quantity(aggregate, &mut reservation, &mut ledger);
    assert!(
        matches!(result, Err(EvidencePreparationError::Invariant)),
        "HC900 numeric index must reject a foreign charge ledger before allocating"
    );
    assert_eq!(reservation.remaining_bytes(), layout.size());
    assert!(ledger.as_slice().is_empty());
    assert_eq!(original.reserved_bytes(), layout.size());
    assert_eq!(source, Quantity::from(123_u64));
}

#[test]
fn numeric_index_exact_backing_move_allocator_failure_and_unwind_preserve_custody() {
    let source: Quantity = "18446744073709551616.25".parse().unwrap();
    let aggregate = QuantityAccumulator::from_quantity(&source);
    let layout = aggregate.admission_layout().unwrap();
    let ledger_layout = Layout::array::<AllocationCharge>(1).unwrap();
    let original = AllocationBudget::new(layout.size() + ledger_layout.size());
    let mut reservation = original.try_reserve_bytes(original.limit_bytes()).unwrap();
    let mut ledger = ChargedBuffer::from_reservation(1, &mut reservation).unwrap();
    let value = materialize_index_quantity(aggregate, &mut reservation, &mut ledger).unwrap();
    assert_eq!(value, source);
    assert_eq!(ledger.as_slice()[0].layout(), layout);
    assert!(ledger.as_slice()[0].belongs_to(&original));
    assert_eq!(original.reserved_bytes(), original.limit_bytes());
    let mut moved = None;
    assert_eq!(allocations_during(|| moved = Some(value)), 0);
    assert_eq!(moved.as_ref(), Some(&source));
    drop(moved);
    drop(ledger);
    drop(reservation);
    assert_eq!(original.reserved_bytes(), 0);

    // The primitive has exactly one physical allocation. Its typed failure
    // retains prepaid custody and creates no capacity-release observation.
    let charge = original
        .try_reserve(layout)
        .unwrap()
        .try_split(layout)
        .unwrap();
    let (result, refused) = refuse_one_layout_during(layout, || {
        ChargedQuantity::try_from_accumulator_charge(aggregate, &original, charge)
    });
    assert!(refused);
    let (charge, error) = result.err().unwrap();
    assert!(
        matches!(error, iroha_primitives::numeric::QuantityBackingError::Allocation(
        iroha_allocation::ChargedBufferFromChargeError::Allocator { layout: actual }
    ) if actual == layout)
    );
    assert!(charge.belongs_to(&original));
    assert_eq!(original.reserved_bytes(), layout.size());
    drop(charge);

    let mut reservation = original.try_reserve_bytes(original.limit_bytes()).unwrap();
    let mut ledger = ChargedBuffer::from_reservation(1, &mut reservation).unwrap();
    let (result, refused) = refuse_one_layout_during(layout, || {
        materialize_index_quantity(aggregate, &mut reservation, &mut ledger)
    });
    assert!(refused);
    assert!(
        matches!(result, Err(EvidencePreparationError::Allocator { requested_bytes }) if requested_bytes == layout.size())
    );
    assert!(ledger.as_slice().is_empty());
    assert_eq!(original.reserved_bytes(), ledger_layout.size());
    drop(ledger);
    drop(reservation);

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut reservation = original.try_reserve_bytes(original.limit_bytes()).unwrap();
        let mut ledger = ChargedBuffer::from_reservation(1, &mut reservation).unwrap();
        let value = materialize_index_quantity(aggregate, &mut reservation, &mut ledger).unwrap();
        assert_eq!(value, source);
        panic!("unwind the exact original numeric owner");
    }));
    assert!(unwind.is_err());
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn numeric_comparison_and_difference_need_no_allocator_scratch() {
    let large: Quantity = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047".parse().unwrap();
    let small: Quantity = "0.0000000000000000000000000001".parse().unwrap();
    let mut inline = QuantityAccumulator::from_quantity(&large);
    assert_eq!(
        allocations_during(|| {
            assert!(large > small);
            assert!(large.cmp_mul_u64(u64::MAX, &small, u64::MAX).is_gt());
            assert!(inline.try_sub(&small).is_err());
            assert!(inline.cmp_quantity(&large).is_eq());
            inline.try_sub(&large).unwrap();
            assert!(inline.is_zero());
        }),
        0
    );
}
