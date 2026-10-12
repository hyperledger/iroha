//! Native open-anchor bounds, original pool custody and canonical Vec projections.

use super::*;

fn anchor(value: u8) -> SccpAnchorV1 {
    SccpAnchorV1 {
        core_hash: [value; 32],
        result: [value.wrapping_add(1); 32],
    }
}

fn demand(count: usize) -> usize {
    if count == 0 {
        0
    } else {
        Layout::array::<SccpAnchorV1>(count).unwrap().size()
            + Layout::array::<AllocationCharge>(1).unwrap().size()
            + RetainedSccpAnchorOpen::shared_layout().size()
    }
}

#[test]
fn empty_retains_original_identity_without_capacity_and_clones_without_repricing() {
    let original = AllocationBudget::new(0);
    let foreign = AllocationBudget::new(0);
    let empty = RetainedSccpAnchorOpen::empty(&original);
    let copy = empty.clone();
    assert!(empty.anchors().is_empty());
    assert_eq!(empty.allocation_bytes(), Some(0));
    assert_eq!(original.reserved_bytes(), 0);
    assert!(empty.belongs_to(&original));
    assert!(!empty.belongs_to(&foreign));
    assert!(empty.ptr_eq(&copy));
    assert!(!empty.ptr_eq(&RetainedSccpAnchorOpen::empty(&foreign)));
    assert_eq!(format!("{empty:?}"), "[]");
    assert_eq!(
        RetainedSccpAnchorOpen::admit_claim(&[], &original).unwrap(),
        empty
    );
}

#[test]
fn clone_retains_exact_payload_pointer_and_credit_through_the_last_cross_thread_owner() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RetainedSccpAnchorOpen>();
    let pool = AllocationBudget::new(demand(2));
    let source = [anchor(1), anchor(2)];
    let owner = RetainedSccpAnchorOpen::admit_claim(&source, &pool).unwrap();
    assert_eq!(owner.allocation_bytes(), Some(demand(2)));
    assert_eq!(pool.reserved_bytes(), demand(2));
    assert_eq!(owner.anchors(), source);
    pool.set_limit_bytes(0);
    let copy = owner.clone();
    assert!(owner.ptr_eq(&copy));
    assert_eq!(owner.anchors().as_ptr(), copy.anchors().as_ptr());
    drop(owner);
    assert_eq!(pool.reserved_bytes(), demand(2));
    let expected_pool = pool.clone();
    std::thread::spawn(move || {
        assert!(copy.belongs_to(&expected_pool));
        assert_eq!(copy.anchors(), source);
        drop(copy);
        assert_eq!(expected_pool.reserved_bytes(), 0);
    })
    .join()
    .unwrap();
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn append_funds_the_complete_next_version_and_refusal_leaves_the_original_unchanged() {
    let pool = AllocationBudget::new(demand(1) + demand(2) - 1);
    let original = RetainedSccpAnchorOpen::admit_claim(&[anchor(1)], &pool).unwrap();
    let shared = original.clone();
    let error = original.appended(anchor(2), &pool).unwrap_err();
    assert!(matches!(
        error,
        AnchorOwnerError::Admission(AllocationRefusal::Capacity { .. })
    ));
    assert!(original.ptr_eq(&shared));
    assert_eq!(original.anchors(), &[anchor(1)]);
    assert_eq!(pool.reserved_bytes(), demand(1));
    pool.set_limit_bytes(demand(1) + demand(2));
    let next = original.appended(anchor(2), &pool).unwrap();
    assert!(!original.ptr_eq(&next));
    assert!(next.belongs_to(&pool));
    assert_eq!(original.anchors(), &[anchor(1)]);
    assert_eq!(next.anchors(), &[anchor(1), anchor(2)]);
    assert_eq!(pool.reserved_bytes(), demand(1) + demand(2));
    drop(next);
    assert_eq!(pool.reserved_bytes(), demand(1));
    drop(shared);
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn count_bound_is_checked_before_admission_and_a_full_chunk_cannot_grow() {
    let oversized = vec![anchor(1); MAX_OPEN_ANCHORS + 1];
    let unavailable = AllocationBudget::new(0);
    assert!(matches!(
        RetainedSccpAnchorOpen::admit_claim(&oversized, &unavailable),
        Err(AnchorOwnerError::Invalid(_))
    ));
    assert_eq!(unavailable.reserved_bytes(), 0);
    let pool = AllocationBudget::new(demand(MAX_OPEN_ANCHORS));
    let full = RetainedSccpAnchorOpen::admit_claim(&oversized[..MAX_OPEN_ANCHORS], &pool).unwrap();
    assert_eq!(full.anchors().len(), MAX_OPEN_ANCHORS);
    assert_eq!(full.allocation_bytes(), Some(demand(MAX_OPEN_ANCHORS)));
    pool.set_limit_bytes(0);
    assert!(matches!(
        full.appended(anchor(2), &pool),
        Err(AnchorOwnerError::Invalid(_))
    ));
    assert_eq!(full.anchors().len(), MAX_OPEN_ANCHORS);
    drop(full);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn foreign_pool_never_funds_a_lifecycle_copy_even_for_an_empty_chunk() {
    let original = AllocationBudget::new(demand(1));
    let foreign = AllocationBudget::new(demand(2));
    for owner in [
        RetainedSccpAnchorOpen::empty(&original),
        RetainedSccpAnchorOpen::admit_claim(&[anchor(1)], &original).unwrap(),
    ] {
        assert!(matches!(
            owner.appended(anchor(2), &foreign),
            Err(AnchorOwnerError::Invariant("foreign anchor pool"))
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert!(owner.belongs_to(&original));
    }
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn canonical_binary_and_json_are_exactly_the_claim_vector_not_an_authority_wrapper() {
    let pool = AllocationBudget::new(demand(3));
    for source in [Vec::new(), vec![anchor(1), anchor(2), anchor(3)]] {
        let owner = RetainedSccpAnchorOpen::admit_claim(&source, &pool).unwrap();
        let original_charge = pool.reserved_bytes();
        let actual = norito::encode_canonical(&owner).unwrap();
        let expected = norito::encode_canonical(&source).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(norito::canonical_frame_len(&owner).unwrap(), actual.len());
        let decoded = norito::decode_canonical::<Vec<SccpAnchorV1>>(&actual).unwrap();
        assert_eq!(decoded, source);
        assert_eq!(
            norito::json::to_json(&owner).unwrap(),
            norito::json::to_json(&source).unwrap()
        );
        assert_eq!(pool.reserved_bytes(), original_charge);
        assert!(owner.belongs_to(&pool));
    }
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn buffer_error_keeps_original_admission_and_allocator_size() {
    let pool = AllocationBudget::new(0);
    let original = pool.try_reserve_bytes(1).unwrap_err();
    match AnchorOwnerError::buffer(PrepaidBufferError::Allocation(
        ChargedBufferError::Admission(original.clone()),
    )) {
        AnchorOwnerError::Admission(actual) => assert_eq!(actual, original),
        other => panic!("wrong original refusal: {other:?}"),
    }
    assert!(matches!(
        AnchorOwnerError::buffer(PrepaidBufferError::Allocation(
            ChargedBufferError::Allocator {
                requested_bytes: 67
            }
        )),
        AnchorOwnerError::Allocator {
            requested_bytes: 67
        }
    ));
}
