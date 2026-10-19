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

#[test]
fn native_shell_actual_physical_refusal_keeps_original_charge_source_and_retry() {
    use crate::test_allocations::refuse_one_layout_during;
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    let expected = chain.committed(2).block_hash();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut acquisition = NativeCarrierAcquisition::new(
        chain.kura(),
        NonZeroUsize::new(2).unwrap(),
        expected,
        pool.clone(),
        pool.limit_bytes(),
    );
    acquisition.original_source().unwrap();
    let original = acquisition.source.as_mut().unwrap();
    acquisition.bytes = original.read_original(original.wire_len(), &pool).unwrap();
    let raw = acquisition.bytes.as_ref().unwrap().as_slice().as_ptr();
    let source_floor = pool.reserved_bytes();
    let shell_layout = SharedSignedBlock::allocation_layout();
    for _ in 0..2 {
        let (result, refused) =
            refuse_one_layout_during(shell_layout, || acquisition.decode_original_body());
        assert!(refused);
        let local = match result {
            Err(ExecutionAttemptError::Deferred(local)) => local,
            other => panic!("actual shell refusal: {other:?}"),
        };
        assert!(
            matches!(local.allocator_refusal().unwrap().shared_from_charge_error(),
            Some(SharedFromChargeError::Allocator { layout }) if *layout == shell_layout)
        );
        assert!(local.allocation_refusal().is_none() && local.decode_refusal().is_none());
        assert_eq!(
            pool.reserved_bytes(),
            source_floor + shell_layout.size(),
            "native shell refusal must retain the exact original shell charge"
        );
        assert!(acquisition.shell_charge.as_ref().unwrap().belongs_to(&pool));
        assert!(acquisition.shell.is_none() && acquisition.decoder.is_none());
        assert_eq!(acquisition.bytes.as_ref().unwrap().as_slice().as_ptr(), raw);
    }
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let result = acquisition.decode_original_body();
    let controls: usize = norito::core::PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .map(std::alloc::Layout::size)
        .sum();
    assert!(
        matches!(result, Err(ExecutionAttemptError::Deferred(ref cause)) if
        matches!(cause.allocation_refusal(), Some(AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. })
            if *requested_bytes == controls && *reserved_bytes == pool.limit_bytes() && *limit_bytes == pool.limit_bytes()))
    );
    assert!(acquisition.shell.is_some() && acquisition.shell_charge.is_none());
    drop(blocker);
    let body = acquisition.complete().unwrap();
    assert!(body.belongs_to(&pool));
    assert_eq!(body.hash(), expected);
    assert_eq!(body.header().height().get(), 2);
    assert_eq!(
        body.encode_wire().unwrap(),
        acquisition.bytes.as_ref().unwrap().as_slice()
    );
    assert_eq!(acquisition.bytes.as_ref().unwrap().as_slice().as_ptr(), raw);
    drop(acquisition);
    drop(body);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn native_late_certificate_capacity_retains_same_decoder_children_and_original_retry() {
    use iroha_data_model::block::{BlockSignatures, ChargedCertificateParts};
    use std::task::{Context, Waker};
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    let expected = chain.committed(2).block_hash();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let index = NonZeroUsize::new(2).unwrap();
    let mut registration = crate::unit_test_support::release_registration(&pool);
    let baseline = pool.reserved_bytes();
    // Measure this actual canonical fixture once; no policy change or guessed child sizes.
    let mut measure = NativeCarrierAcquisition::new(
        chain.kura(),
        index,
        expected,
        pool.clone(),
        pool.limit_bytes(),
    );
    measure.prepare().unwrap();
    let required = pool.reserved_bytes() - baseline;
    let certificate = measure
        .decoded
        .as_ref()
        .unwrap()
        .commit_certificate()
        .unwrap();
    let certificate_bytes = certificate.payload_len()
        + iroha_allocation::ChargedShared::<ChargedCertificateParts>::allocation_layout().size();
    drop(measure);
    assert_eq!(pool.reserved_bytes(), baseline);
    assert!(required > certificate_bytes && required < pool.limit_bytes());
    let blocker_bytes = pool.limit_bytes() - baseline - (required - 1);
    let blocker = pool.try_reserve_bytes(blocker_bytes).unwrap();
    let mut acquisition = NativeCarrierAcquisition::new(
        chain.kura(),
        index,
        expected,
        pool.clone(),
        pool.limit_bytes(),
    );
    let result = acquisition.prepare();
    let cause = match result {
        Err(ExecutionAttemptError::Deferred(cause)) => cause,
        other => panic!("precise final certificate admission must refuse: {other:?}"),
    };
    let retained = baseline + blocker_bytes + required - certificate_bytes;
    assert!(
        matches!(cause.allocation_refusal(), Some(AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. })
        if *requested_bytes == certificate_bytes && *reserved_bytes == retained && *limit_bytes == pool.limit_bytes())
    );
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "native late refusal must retain the original prepared decoder and child charges"
    );
    assert!(cause.allocator_refusal().is_none() && cause.decode_refusal().is_none());
    let AllocationRefusal::Capacity { release, .. } = cause.allocation_refusal().unwrap() else {
        unreachable!()
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(registration.poll_wait(release, &mut context).is_pending());
    let source = acquisition.bytes.as_ref().unwrap().charged_source();
    let raw = source.as_slice().as_ptr();
    let original = acquisition
        .decoder
        .as_ref()
        .unwrap()
        .retained_signatures(source)
        .unwrap()
        .unwrap()
        .clone();
    assert!(original.admitted_to(&pool));
    assert!(
        acquisition
            .decoder
            .as_ref()
            .unwrap()
            .retained_certificate(source)
            .unwrap()
            .is_none()
    );
    assert!(acquisition.matches_owner(chain.kura(), 2, expected, &pool));
    assert!(!acquisition.matches_owner(chain.kura(), 3, expected, &pool));
    assert!(!acquisition.matches_owner(chain.kura(), 2, chain.committed(1).block_hash(), &pool));
    assert!(!acquisition.matches_owner(
        chain.kura(),
        2,
        expected,
        &AllocationBudget::new(pool.limit_bytes())
    ));
    let again = acquisition.prepare();
    assert!(
        matches!(again, Err(ExecutionAttemptError::Deferred(ref cause)) if matches!(cause.allocation_refusal(),
        Some(AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. }) if
            *requested_bytes == certificate_bytes && *reserved_bytes == retained && *limit_bytes == pool.limit_bytes()))
    );
    let Err(ExecutionAttemptError::Deferred(again)) = again else {
        unreachable!()
    };
    assert_eq!(again.allocation_refusal(), cause.allocation_refusal());
    assert!(registration.poll_wait(release, &mut context).is_pending());
    let source = acquisition.bytes.as_ref().unwrap().charged_source();
    assert!(BlockSignatures::ptr_eq(
        &original,
        acquisition
            .decoder
            .as_ref()
            .unwrap()
            .retained_signatures(source)
            .unwrap()
            .unwrap()
    ));
    assert_eq!(source.as_slice().as_ptr(), raw);
    assert_eq!(pool.reserved_bytes(), retained);
    drop(blocker);
    assert!(registration.poll_wait(release, &mut context).is_ready());
    registration.cancel();
    let body = acquisition.complete().unwrap();
    let source = acquisition.bytes.as_ref().unwrap().charged_source();
    assert_eq!(source.as_slice().as_ptr(), raw);
    assert!(
        acquisition
            .decoder
            .as_ref()
            .unwrap()
            .retains_signature_custody(source, &body)
            .unwrap()
    );
    assert!(body.commit_certificate().unwrap().admitted_to(&pool));
    assert_eq!(body.hash(), expected);
    assert_eq!(body.header().height().get(), 2);
    assert_eq!(body.encode_wire().unwrap(), source.as_slice());
    drop(acquisition);
    drop(body);
    drop(original);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(registration);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn native_counter_actual_physical_refusal_retains_source_and_maps_original_typed_cause() {
    use crate::test_allocations::refuse_one_layout_during;
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    let expected = chain.committed(2).block_hash();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut acquisition = NativeCarrierAcquisition::new(
        chain.kura(),
        NonZeroUsize::new(2).unwrap(),
        expected,
        pool.clone(),
        pool.limit_bytes(),
    );
    acquisition.original_source().unwrap();
    let original = acquisition.source.as_mut().unwrap();
    acquisition.bytes = original.read_original(original.wire_len(), &pool).unwrap();
    acquisition.shell = Some(SharedSignedBlock::reserve(&pool).unwrap());
    let floor = pool.reserved_bytes();
    let raw = acquisition.bytes.as_ref().unwrap().as_slice().as_ptr();
    let layouts = norito::core::PreparedDecodeWorkspace::allocation_layouts();
    for _ in 0..2 {
        let (result, refused) =
            refuse_one_layout_during(layouts[0], || acquisition.decode_original_body());
        assert!(refused);
        let local = match result {
            Err(ExecutionAttemptError::Deferred(cause)) => cause,
            other => panic!("actual counter refusal: {other:?}"),
        };
        assert!(
            matches!(local.allocator_refusal().unwrap().shared_from_charge_error(),
            Some(SharedFromChargeError::Allocator { layout }) if *layout == layouts[0])
        );
        assert!(local.allocation_refusal().is_none() && local.decode_refusal().is_none());
        assert_eq!(
            pool.reserved_bytes(),
            floor + layouts.iter().map(std::alloc::Layout::size).sum::<usize>()
        );
        assert!(acquisition.decoder.as_ref().unwrap().belongs_to(&pool));
        assert_eq!(acquisition.bytes.as_ref().unwrap().as_slice().as_ptr(), raw);
    }
    let body = acquisition.complete().unwrap();
    assert_eq!(body.hash(), expected);
    assert_eq!(
        body.encode_wire().unwrap(),
        acquisition.bytes.as_ref().unwrap().as_slice()
    );
    drop(body);
    drop(acquisition);
    assert_eq!(pool.reserved_bytes(), 0);
}
