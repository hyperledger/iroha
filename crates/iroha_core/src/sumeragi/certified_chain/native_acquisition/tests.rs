//! Same native acquisition, original prepaid body and cumulative decoder through refusal.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_allocation::AllocationRefusal;
use norito::core::DecodeBudgetContext;

#[test]
fn original_prepaid_native_body_delivers_once_without_repeat_allocation_or_decode() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let decoder = DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
        &budget,
    )
    .unwrap();
    let index = NonZeroUsize::new(2).unwrap();
    let expected = *view.block_hashes().get(1).unwrap();
    let length = decoder
        .with(|| chain.kura().native_frame_read(2, expected))
        .unwrap()
        .unwrap()
        .wire_len();
    let length = usize::try_from(length).unwrap();
    let mut acquisition =
        NativeCarrierAcquisition::new(chain.kura(), index, expected, budget.clone(), length);
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes() - length)
        .unwrap();
    let refused = decoder.with(|| acquisition.complete());
    assert!(
        matches!(refused,
        Err(ExecutionAttemptError::Deferred(ref local))
            if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity { .. }))),
        "original shared body shell must refuse before native body decoding"
    );
    let original_bytes = acquisition.bytes.as_ref().unwrap().as_slice().as_ptr();
    assert!(acquisition.bytes.as_ref().unwrap().belongs_to(&budget));
    assert!(acquisition.decoded.is_none() && acquisition.shell.is_none());
    drop(pressure);

    decoder.with(|| acquisition.prepare()).unwrap();
    let original = acquisition.decoded.as_ref().unwrap().clone();
    assert!(original.belongs_to(&budget));
    assert_eq!(original.hash(), expected);
    assert_eq!(original.header().height().get(), 2);
    assert!(acquisition.shell.is_none());
    assert_eq!(
        acquisition.bytes.as_ref().unwrap().as_slice().as_ptr(),
        original_bytes
    );
    let retained = budget.reserved_bytes();
    let consumed = decoder.consumed_allocated_bytes();
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    decoder.with(|| acquisition.decode_original_body()).unwrap();
    assert_eq!(
        decoder.consumed_allocated_bytes(),
        consumed,
        "completed original body must not repeat its decoder work"
    );
    assert_eq!(
        budget.reserved_bytes(),
        budget.limit_bytes(),
        "completed body must retain the same prepaid control under full original capacity"
    );
    assert!(SharedSignedBlock::ptr_eq(
        acquisition.decoded.as_ref().unwrap(),
        &original
    ));
    let delivered = decoder.with(|| acquisition.complete()).unwrap();
    assert!(
        SharedSignedBlock::ptr_eq(&delivered, &original),
        "delivery must move the same original prepaid shared body"
    );
    assert!(delivered.belongs_to(&budget));
    assert_eq!(
        acquisition.bytes.as_ref().unwrap().as_slice().as_ptr(),
        original_bytes
    );
    assert!(acquisition.delivered && acquisition.decoded.is_none() && acquisition.shell.is_none());
    assert!(matches!(
        decoder.with(|| acquisition.complete()),
        Err(ExecutionAttemptError::Rejected(ChainReadError::NotInView {
            height: 2
        }))
    ));
    drop(pressure);
    assert_eq!(budget.reserved_bytes(), retained);
    budget.with_deferred_refund_notifications(|_| {
        drop(acquisition);
        drop(original);
        drop(delivered);
    });
    drop(decoder);
    drop(view);
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "last original native source/body owner must refund the actual original pool"
    );
}

#[test]
fn native_storage_mapper_retains_actual_scoped_and_physical_causes_without_allocating() {
    use crate::test_allocations::{allocations_during, refuse_one_layout_during};
    use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
    use std::alloc::Layout;
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    let expected = chain.committed(2).block_hash();
    // The actual Kura sidecar producer captures its refusal, before this scope retires.
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || match chain.kura().native_frame_read(2, expected) {
            Err(error) => error,
            Ok(_) => panic!("actual durable metadata cannot fit a zero input allowance"),
        },
    );
    let crate::kura::Error::CodecAttempt(ref codec) = error else {
        panic!("actual observed input reservation: {error:?}");
    };
    let original = codec.local_refusal().expect("genuine retired scope owner");
    let map = |error| match native_read_error(2, error) {
        ExecutionAttemptError::Deferred(owner) => owner,
        other => panic!("original unfinished reader: {other:?}"),
    };
    let mut moved = None;
    let allocations = allocations_during(|| moved = Some(map(error)));
    assert_eq!(allocations, 0);
    let owner = moved.unwrap();
    assert_eq!(owner.decode_refusal(), Some(&original));
    assert!(owner.allocation_refusal().is_none());
    assert!(owner.allocator_refusal().is_none());
    let ivm::VMError::DecodeDeferred(exported) = owner.into_vm_error() else {
        panic!("same original decoder owner");
    };
    assert_eq!(exported, original);
    assert!(
        chain
            .kura()
            .native_frame_read(2, expected)
            .unwrap()
            .is_some()
    );

    // A real lower null result must keep its exact typed cause through the same mapper.
    // This checks transport; it does not claim the null occurred inside a Kura syscall.
    let layout = Layout::array::<u64>(19).unwrap();
    let pool = AllocationBudget::new(layout.size());
    let (failed, denied) =
        refuse_one_layout_during(layout, || ChargedBuffer::<u64>::new(19, &pool));
    assert!(denied);
    let error = match failed {
        Err(original) => original,
        Ok(_) => panic!("physical allocation denied"),
    };
    assert_eq!(pool.reserved_bytes(), 0);
    let mut moved = None;
    let allocations =
        allocations_during(|| moved = Some(map(crate::kura::Error::NativeFrameAllocation(error))));
    assert_eq!(allocations, 0);
    let owner = moved.unwrap();
    assert_eq!(
        owner.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(owner.allocation_refusal().is_none());
    let ivm::VMError::AllocatorDeferred(original) = owner.into_vm_error() else {
        panic!("typed original allocator refusal");
    };
    assert!(
        matches!(original.into_buffer_error().unwrap(), ChargedBufferError::Allocator { requested_bytes } if requested_bytes == layout.size())
    );
    drop(ChargedBuffer::<u64>::new(19, &pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
    let malformed = crate::kura::Error::CodecAttempt(
        norito::core::classify_decode_attempt::<()>(|| Err(norito::Error::NonCanonicalEncoding))
            .unwrap_err(),
    );
    assert!(matches!(
        native_read_error(2, malformed),
        ExecutionAttemptError::Rejected(ChainReadError::Malformed { height: 2, reason }) if reason == norito::Error::NonCanonicalEncoding.to_string()
    ));
}

#[test]
fn unavailable_native_source_remains_missing_instead_of_malformed_codec() {
    assert!(matches!(
        native_read_error(
            7,
            crate::kura::Error::CanonicalBlockWireMismatch { height: 7 }
        ),
        ExecutionAttemptError::Rejected(ChainReadError::NotInView { height: 7 })
    ));
}
