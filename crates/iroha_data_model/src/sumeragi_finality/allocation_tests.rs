//! Actual portable proposal allocation refusal and unchanged canonical retry.
//!
//! The allocator changes only one exact layout on the active test thread. Production
//! code contains no instrumentation; other threads retain System's original behavior.
use super::*;
use crate::amx_prepare_streaming_allocations::with_exact_allocation_denial as refuse;
use std::alloc::Layout;

#[test]
fn portable_proposal_keeps_real_reservation_cause_and_retries_identical_signed_source() {
    let fixture = test_fixtures::NativeFinalityFixture::new();
    let source = fixture.latest().block_wire.clone();
    let block = decode_framed_signed_block(&source).unwrap();
    let hash = block.hash();
    let expected = proposal_wire(&block).unwrap();
    let length = block.resultless_proposal_wire_len().unwrap();
    assert_eq!(expected.len(), length);
    let layout = Layout::array::<u8>(length).unwrap();
    let (refused, denied) = refuse(layout, || proposal_wire(&block));
    assert!(
        denied,
        "actual bounded canonical output reservation must reach the allocator"
    );
    let FinalityReadError::Allocator(original) = refused.unwrap_err() else {
        panic!("original canonical output reservation must not become invalid finality");
    };
    let (cause, actual_layout) = original.vec_reserve_error().unwrap();
    assert_eq!(actual_layout, layout);
    assert!(std::ptr::eq(
        std::error::Error::source(&original)
            .unwrap()
            .downcast_ref::<std::collections::TryReserveError>()
            .unwrap(),
        cause,
    ));
    assert!(original.buffer_error().is_none() && original.shared_error().is_none());
    let retained = original.into_buffer_error().unwrap_err();
    let transported = FinalityReadError::Allocator(retained);
    let FinalityReadError::Allocator(original) = transported else {
        unreachable!()
    };
    let (_, returned_layout) = original.into_vec_reserve_error().unwrap();
    assert_eq!(returned_layout, layout);
    assert_eq!(block.hash(), hash);
    assert_eq!(block.encode_wire().unwrap(), source);
    assert_eq!(proposal_wire(&block).unwrap(), expected);
}

#[test]
fn exact_denial_is_one_shot_and_restores_after_unwinding() {
    let layout = Layout::array::<u8>(37).unwrap();
    let (result, denied) = refuse(layout, || {
        let mut unrelated = Vec::<u8>::new();
        unrelated.try_reserve_exact(19).unwrap();
        let mut target = Vec::<u8>::new();
        let first = target.try_reserve_exact(37);
        target.try_reserve_exact(37).unwrap();
        first
    });
    assert!(denied && result.is_err());
    let interrupted =
        std::panic::catch_unwind(|| refuse(layout, || panic!("restore exact test target")));
    assert!(interrupted.is_err());
    let mut ordinary = Vec::<u8>::new();
    ordinary.try_reserve_exact(37).unwrap();
    let (new_attempt, denied) = refuse(layout, || Vec::<u8>::new().try_reserve_exact(37));
    assert!(
        denied && new_attempt.is_err(),
        "unwinding must retire the previous denial scope"
    );
}
