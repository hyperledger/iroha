//! Execution consumers retain the actual common native acquisition through refusal.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    test_allocations::refuse_one_layout_during,
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, SharedFromChargeError};
use iroha_data_model::block::{ChargedCertificateParts, SharedSignedBlock};

fn fixture() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain
}

fn limits(chain: &CertifiedTestChain, target: u64) -> NativeExecutionReadLimits {
    let lengths = (1..=2)
        .map(|height| chain.committed(height).block().encode_wire().unwrap().len() as u64)
        .collect::<Vec<_>>();
    NativeExecutionReadLimits {
        admitted_target_wire_bytes: lengths[usize::try_from(target - 1).unwrap()],
        max_source_blocks: 2,
        max_source_wire_bytes: lengths.iter().sum(),
        max_frame_wire_bytes: *lengths.iter().max().unwrap(),
    }
}

fn pending<'a>(
    chain: &'a CertifiedTestChain,
    pool: &AllocationBudget,
) -> PendingExecutionFrame<'a> {
    PendingExecutionFrame::new(
        chain.kura(),
        2,
        chain.committed(2).block_hash(),
        2,
        limits(chain, 2),
        0,
        pool,
    )
    .unwrap()
}

#[test]
fn execution_shell_physical_refusal_keeps_original_charge_and_single_wire_delivery() {
    let chain = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut original = pending(&chain, &pool);
    assert!(original.acquisition.take_delivered_bytes().is_none());
    let layout = SharedSignedBlock::allocation_layout();
    let raw_bytes = original.length as usize;
    let mut raw = None;
    for _ in 0..2 {
        let (result, denied) =
            refuse_one_layout_during(layout, || original.read_block(chain.kura(), &pool));
        assert!(denied);
        let local = match result {
            Err(NativeExecutionReadError::Deferred(local)) => local,
            other => panic!("actual execution shell allocator refusal: {other:?}"),
        };
        assert!(
            matches!(local.allocator_refusal().unwrap().shared_from_charge_error(),
            Some(SharedFromChargeError::Allocator { layout: actual }) if *actual == layout)
        );
        assert!(local.allocation_refusal().is_none() && local.decode_refusal().is_none());
        assert_eq!(
            pool.reserved_bytes(),
            raw_bytes + layout.size(),
            "execution shell refusal must retain the exact original shell charge"
        );
        let pointer = original
            .acquisition
            .original_bytes()
            .unwrap()
            .as_slice()
            .as_ptr();
        assert_eq!(*raw.get_or_insert(pointer), pointer);
        assert!(original.block.is_none());
        assert!(!original.canonical_checked);
        assert!(original.acquisition.take_delivered_bytes().is_none());
    }
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    let result = original.read_block(chain.kura(), &pool);
    let controls = norito::core::PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .map(std::alloc::Layout::size)
        .sum::<usize>();
    assert!(
        matches!(result, Err(NativeExecutionReadError::Deferred(ref local))
        if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity {
            requested_bytes, reserved_bytes, limit_bytes, ..
        }) if *requested_bytes == controls && *reserved_bytes == pool.limit_bytes() && *limit_bytes == pool.limit_bytes()))
    );
    drop(blocker);
    let body = original.read_block(chain.kura(), &pool).unwrap();
    assert!(body.belongs_to(&pool));
    assert_eq!(body.hash(), chain.committed(2).block_hash());
    let again = original.read_block(chain.kura(), &pool).unwrap();
    assert!(SharedSignedBlock::ptr_eq(&body, &again));
    let wire = original.take_wire();
    assert_eq!(wire.as_slice().as_ptr(), raw.unwrap());
    assert_eq!(
        body.canonical_wire_identity().unwrap(),
        (wire.as_slice().len() as u64, Hash::new(&wire))
    );
    assert!(original.acquisition.take_delivered_bytes().is_none());
    drop(original);
    drop(body);
    drop(again);
    drop(wire);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn execution_late_certificate_refusal_retains_prepared_children_and_exact_cause() {
    use std::task::{Context, Waker};

    let chain = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut registration = crate::unit_test_support::release_registration(&pool);
    let baseline = pool.reserved_bytes();
    let mut context = Context::from_waker(Waker::noop());
    let mut measure = pending(&chain, &pool);
    let measured = measure.read_block(chain.kura(), &pool).unwrap();
    let required = pool.reserved_bytes() - baseline;
    let certificate_bytes = measured.commit_certificate().unwrap().payload_len()
        + iroha_allocation::ChargedShared::<ChargedCertificateParts>::allocation_layout().size();
    drop(measured);
    drop(measure);
    assert_eq!(pool.reserved_bytes(), baseline);
    assert!(required > certificate_bytes && required < pool.limit_bytes());
    let blocker_bytes = pool.limit_bytes() - baseline - (required - 1);
    let blocker = pool.try_reserve_bytes(blocker_bytes).unwrap();
    let mut original = pending(&chain, &pool);
    let cause = match original.read_block(chain.kura(), &pool) {
        Err(NativeExecutionReadError::Deferred(cause)) => cause,
        other => panic!("actual final certificate capacity: {other:?}"),
    };
    let retained = baseline + blocker_bytes + required - certificate_bytes;
    assert!(
        matches!(cause.allocation_refusal(), Some(AllocationRefusal::Capacity {
        requested_bytes, reserved_bytes, limit_bytes, ..
    }) if *requested_bytes == certificate_bytes && *reserved_bytes == retained && *limit_bytes == pool.limit_bytes())
    );
    assert_eq!(
        pool.reserved_bytes(),
        retained,
        "execution late refusal must retain the original prepared decoder and child charges"
    );
    assert!(cause.allocator_refusal().is_none() && cause.decode_refusal().is_none());
    let raw = original
        .acquisition
        .original_bytes()
        .unwrap()
        .as_slice()
        .as_ptr();
    let again = match original.read_block(chain.kura(), &pool) {
        Err(NativeExecutionReadError::Deferred(cause)) => cause,
        other => panic!("same original final certificate capacity: {other:?}"),
    };
    assert!(
        matches!(again.allocation_refusal(), Some(AllocationRefusal::Capacity {
            requested_bytes, reserved_bytes, limit_bytes, ..
        }) if *requested_bytes == certificate_bytes && *reserved_bytes == retained && *limit_bytes == pool.limit_bytes())
    );
    let AllocationRefusal::Capacity {
        release: first_release,
        ..
    } = cause.allocation_refusal().unwrap()
    else {
        unreachable!()
    };
    let AllocationRefusal::Capacity { release, .. } = again.allocation_refusal().unwrap() else {
        unreachable!()
    };
    // Completion publishes the first attempt's temporary decoder refunds after
    // capturing its refusal. The retry must observe that real release, then keep
    // its stable prepared children and the new original wait cut thereafter.
    assert!(
        registration
            .poll_wait(first_release, &mut context)
            .is_ready()
    );
    assert!(registration.poll_wait(release, &mut context).is_pending());
    let third = match original.read_block(chain.kura(), &pool) {
        Err(NativeExecutionReadError::Deferred(cause)) => cause,
        other => panic!("retained final certificate capacity: {other:?}"),
    };
    assert_eq!(third.allocation_refusal(), again.allocation_refusal());
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(release, &mut context).is_pending());
    assert_eq!(pool.reserved_bytes(), retained);
    assert_eq!(
        original
            .acquisition
            .original_bytes()
            .unwrap()
            .as_slice()
            .as_ptr(),
        raw
    );
    drop(blocker);
    assert!(registration.poll_wait(release, &mut context).is_ready());
    registration.cancel();
    let body = original.read_block(chain.kura(), &pool).unwrap();
    let wire = original.take_wire();
    assert_eq!(wire.as_slice().as_ptr(), raw);
    assert_eq!(body.encode_wire().unwrap(), wire.as_slice());
    assert!(body.commit_certificate().unwrap().admitted_to(&pool));
    drop(original);
    drop(body);
    drop(wire);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(registration);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn execution_retry_rejects_replacement_pool_backend_and_expected_hash() {
    let chain = fixture();
    let foreign_chain = fixture();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let foreign_pool = AllocationBudget::new(pool.limit_bytes());
    let mut original = pending(&chain, &pool);
    let body = original.read_block(chain.kura(), &pool).unwrap();
    let retained = pool.reserved_bytes();
    let raw = original
        .acquisition
        .original_bytes()
        .unwrap()
        .as_slice()
        .as_ptr();
    for (backend, budget) in [
        (chain.kura().as_ref(), &foreign_pool),
        (foreign_chain.kura().as_ref(), &pool),
    ] {
        assert!(
            matches!(
                original.read_block(backend, budget),
                Err(NativeExecutionReadError::Chain(ChainReadError::NotInView {
                    height: 2
                }))
            ),
            "execution retry must retain its original backend slot hash and finite pool"
        );
    }
    let expected = original.expected;
    original.expected = chain.committed(1).block_hash();
    assert!(
        matches!(
            original.read_block(chain.kura(), &pool),
            Err(NativeExecutionReadError::Chain(ChainReadError::NotInView {
                height: 2
            }))
        ),
        "execution retry must retain its original backend slot hash and finite pool"
    );
    original.expected = expected;
    assert_eq!(pool.reserved_bytes(), retained);
    assert_eq!(foreign_pool.reserved_bytes(), 0);
    let same = original.read_block(chain.kura(), &pool).unwrap();
    assert!(SharedSignedBlock::ptr_eq(&body, &same));
    assert_eq!(
        original
            .acquisition
            .original_bytes()
            .unwrap()
            .as_slice()
            .as_ptr(),
        raw
    );
    drop(same);
    drop(body);
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn durable_execution_retry_preserves_original_genesis_wire_through_h2_authentication() {
    let chain = fixture();
    let view = chain.state().view();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let limits = limits(&chain, 1);
    let mut attempt = NativeExecutionReadAttempt::new(
        chain.kura(),
        view.chain_id(),
        *view.network_id(),
        view.block_hashes(),
        1,
        limits,
        &pool,
    )
    .unwrap();
    let layout = SharedSignedBlock::allocation_layout();
    let (result, denied) =
        refuse_one_layout_during(layout, || attempt.advance(view.block_hashes()));
    assert!(denied && matches!(result, Err(NativeExecutionReadError::Deferred(_))));
    assert_eq!(attempt.current, GENESIS_HEIGHT);
    assert_eq!(attempt.total, 0);
    assert!(attempt.prefix.is_none() && attempt.retained_wire.is_none());
    let raw = attempt
        .pending
        .as_ref()
        .unwrap()
        .acquisition
        .original_bytes()
        .unwrap()
        .as_slice()
        .as_ptr();
    let read = attempt.advance(view.block_hashes()).unwrap();
    assert!(attempt.is_completed() && attempt.pending.is_none());
    assert_eq!(read.wire.as_slice().as_ptr(), raw);
    assert_eq!(read.authority.committed().height(), GENESIS_HEIGHT);
    assert_eq!(read.source_blocks, 2);
    assert_eq!(read.source_wire_bytes, limits.max_source_wire_bytes);
    assert_eq!(
        read.wire.as_slice(),
        chain.committed(1).block().encode_wire().unwrap()
    );
    assert_eq!(
        read.authority.block().canonical_wire_identity().unwrap(),
        (read.wire.as_slice().len() as u64, Hash::new(&read.wire))
    );
    assert!(matches!(
        attempt.advance(view.block_hashes()),
        Err(NativeExecutionReadError::Storage { .. })
    ));
    drop(read);
    drop(attempt);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn durable_execution_prefix_refusal_keeps_completed_original_body_and_wire() {
    let chain = fixture();
    let view = chain.state().view();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let limits = limits(&chain, 1);
    let mut attempt = NativeExecutionReadAttempt::new(
        chain.kura(),
        view.chain_id(),
        *view.network_id(),
        view.block_hashes(),
        1,
        limits,
        &pool,
    )
    .unwrap();
    let mut pending = PendingExecutionFrame::new(
        chain.kura(),
        1,
        chain.committed(1).block_hash(),
        1,
        limits,
        0,
        &pool,
    )
    .unwrap();
    let body = pending.read_block(chain.kura(), &pool).unwrap();
    let raw = pending
        .acquisition
        .original_bytes()
        .unwrap()
        .as_slice()
        .as_ptr();
    assert!(pending.canonical_checked);
    attempt.pending = Some(pending);
    let retained = pool.reserved_bytes();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - retained)
        .unwrap();
    let result = attempt.advance(view.block_hashes());
    let layout = std::alloc::Layout::array::<CertifiedPrefix>(1).unwrap();
    assert!(
        matches!(result, Err(NativeExecutionReadError::Deferred(ref local))
        if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity {
            requested_bytes, reserved_bytes, limit_bytes, ..
        }) if *requested_bytes == layout.size() && *reserved_bytes == pool.limit_bytes() && *limit_bytes == pool.limit_bytes())),
        "completed execution body must survive actual later prefix admission refusal"
    );
    assert_eq!(attempt.current, GENESIS_HEIGHT);
    assert_eq!(attempt.total, 0);
    assert!(attempt.prefix.is_none() && attempt.retained_wire.is_none());
    let pending = attempt.pending.as_ref().unwrap();
    assert!(pending.canonical_checked);
    assert!(SharedSignedBlock::ptr_eq(
        pending.block.as_ref().unwrap(),
        &body
    ));
    assert_eq!(
        pending
            .acquisition
            .original_bytes()
            .unwrap()
            .as_slice()
            .as_ptr(),
        raw
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), retained);
    let read = attempt.advance(view.block_hashes()).unwrap();
    assert!(attempt.is_completed());
    assert_eq!(read.wire.as_slice().as_ptr(), raw);
    assert!(SharedSignedBlock::ptr_eq(read.authority.block(), &body));
    assert_eq!(read.source_blocks, 2);
    assert_eq!(read.source_wire_bytes, limits.max_source_wire_bytes);
    drop(body);
    drop(read);
    drop(attempt);
    assert_eq!(pool.reserved_bytes(), 0);
}
