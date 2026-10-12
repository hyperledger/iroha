//! Allocation census for original refusal extraction and shared-control retention.

use iroha_allocation::AllocationBudget;
use norito::core::{
    DecodeLimits, DecodeLocalRefusalKind, Error, PreparedDecodeWorkspace, classify_decode_attempt,
    reserve_decode_allocation, with_decode_limits_scope,
};

fn limit(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn retired_ordinary_scope_refusal_extraction_and_clone_allocate_nothing() {
    let captured = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| reserve_decode_allocation(1))
    })
    .unwrap_err();
    let mut retained = None;
    let mut borrowed = None;
    let mut cloned = None;
    let mut error = None;
    let allocations = super::allocations_during(|| {
        borrowed = captured.local_refusal();
        retained = captured.into_local_refusal().ok();
        cloned = retained.clone();
        error = cloned.take().map(|original| original.into_error());
    });
    assert_eq!(allocations, 0);
    assert_eq!(retained, borrowed);
    assert_eq!(
        retained.unwrap().kind(),
        DecodeLocalRefusalKind::EnclosingLimit
    );
    assert!(matches!(error.unwrap(), Error::ScopedDecodeResource(_)));
}

#[test]
fn retired_prepared_scope_owner_keeps_original_pool_charge_until_final_drop() {
    let layouts = PreparedDecodeWorkspace::allocation_layouts();
    let demand = layouts.iter().map(std::alloc::Layout::size).sum();
    let pool = AllocationBudget::new(demand);
    let mut reservation = pool.try_reserve_layouts(layouts).unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    let captured = workspace
        .with_limits(limit(0), limit(usize::MAX), || {
            classify_decode_attempt(|| reserve_decode_allocation(1))
        })
        .unwrap()
        .unwrap_err();
    drop((workspace, reservation));
    assert_eq!(pool.reserved_bytes(), layouts[0].size());
    pool.set_limit_bytes(0);
    let mut retained = None;
    let mut borrowed = None;
    let mut cloned = None;
    let allocations = super::allocations_during(|| {
        borrowed = captured.local_refusal();
        retained = captured.into_local_refusal().ok();
        cloned = retained.clone();
    });
    assert_eq!(allocations, 0);
    assert_eq!(retained, borrowed);
    assert_eq!(retained, cloned);
    assert_eq!(
        retained.as_ref().unwrap().kind(),
        DecodeLocalRefusalKind::EnclosingLimit
    );
    assert_eq!(
        pool.reserved_bytes(),
        layouts[0].size(),
        "clone does not obtain new quota"
    );
    drop((retained, borrowed));
    assert_eq!(
        pool.reserved_bytes(),
        layouts[0].size(),
        "last clone retains the original charge"
    );
    let allocations = super::allocations_during(|| drop(cloned.take().unwrap().into_error()));
    assert_eq!(allocations, 0);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn captured_allocator_report_extraction_and_clone_allocate_nothing() {
    let captured = classify_decode_attempt(|| Err::<(), _>(Error::AllocationFailed { bytes: 137 }))
        .unwrap_err();
    let mut retained = None;
    let mut borrowed = None;
    let allocations = super::allocations_during(|| {
        borrowed = captured.local_refusal();
        retained = captured.into_local_refusal().ok();
        drop(retained.clone());
    });
    assert_eq!(allocations, 0);
    assert_eq!(retained, borrowed);
    assert_eq!(retained.as_ref().unwrap().allocation_bytes(), Some(137));
    assert!(matches!(
        retained.unwrap().into_error(),
        Error::AllocationFailed { bytes: 137 }
    ));
}

#[test]
fn reused_prepared_control_does_not_replace_the_retained_attempt_identity() {
    let layouts = PreparedDecodeWorkspace::allocation_layouts();
    let pool = AllocationBudget::new(layouts.iter().map(std::alloc::Layout::size).sum());
    let mut reservation = pool.try_reserve_layouts(layouts).unwrap();
    let mut workspace = PreparedDecodeWorkspace::from_reservation(&pool, &mut reservation).unwrap();
    let captured = workspace
        .with_limits(limit(0), limit(usize::MAX), || {
            classify_decode_attempt(|| reserve_decode_allocation(1))
        })
        .unwrap()
        .unwrap_err();
    let first = captured.local_refusal().unwrap();
    let current = workspace
        .with_limits(limit(0), limit(usize::MAX), || {
            classify_decode_attempt(|| reserve_decode_allocation(1))
        })
        .unwrap()
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
    assert_eq!(first.resource_error(), current.resource_error());
    assert_ne!(
        first, current,
        "reusing the control cannot replace its recorded attempt"
    );
    let mut retained = None;
    let allocations = super::allocations_during(|| retained = captured.into_local_refusal().ok());
    assert_eq!(allocations, 0);
    assert_eq!(retained.as_ref(), Some(&first));
    let stale = workspace
        .with_limits(limit(0), limit(usize::MAX), || {
            classify_decode_attempt(|| {
                drop(reserve_decode_allocation(1).unwrap_err());
                Err::<(), _>(first.clone().into_error())
            })
        })
        .unwrap()
        .unwrap_err();
    assert!(stale.local_refusal().is_none());
    assert!(stale.into_local_refusal().is_err());
    drop((workspace, reservation, current, retained, first));
    assert_eq!(pool.reserved_bytes(), 0);
}
