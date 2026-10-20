//! Actual prefix backing refusal retains its original charge and complete native input.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBufferFromChargeError};
use iroha_data_model::block::SharedSignedBlock;
use std::alloc::Layout;

fn fixture() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain
}

fn limits(chain: &CertifiedTestChain) -> NativeExecutionReadLimits {
    let h1 = chain.committed(1).block().encode_wire().unwrap().len() as u64;
    let h2 = chain.committed(2).block().encode_wire().unwrap().len() as u64;
    NativeExecutionReadLimits {
        admitted_target_wire_bytes: h1,
        max_source_blocks: 2,
        max_source_wire_bytes: h1 + h2,
        max_frame_wire_bytes: h1.max(h2),
    }
}

fn completed_genesis<'a>(
    chain: &'a CertifiedTestChain,
    pool: &AllocationBudget,
) -> PendingExecutionFrame<'a> {
    let mut pending = PendingExecutionFrame::new(
        chain.kura(),
        GENESIS_HEIGHT,
        chain.committed(1).block_hash(),
        GENESIS_HEIGHT,
        limits(chain),
        0,
        pool,
    )
    .unwrap();
    drop(pending.read_block(chain.kura(), pool).unwrap());
    pending
}

#[test]
fn prefix_physical_refusal_retains_original_charge_and_retries_without_credit() {
    let chain = fixture();
    let view = chain.state().view();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let limits = limits(&chain);
    let mut attempt = NativeExecutionReadAttempt::new(
        chain.kura(),
        view.chain_id(),
        *view.network_id(),
        view.block_hashes(),
        GENESIS_HEIGHT,
        limits,
        &pool,
    )
    .unwrap();
    attempt.pending = Some(completed_genesis(&chain, &pool));
    let pending = attempt.pending.as_ref().unwrap();
    let body = pending.block.as_ref().unwrap().clone();
    let raw = pending
        .acquisition
        .original_bytes()
        .unwrap()
        .as_slice()
        .as_ptr();
    let floor = pool.reserved_bytes();
    let layout = Layout::new::<CertifiedPrefix>();
    let (result, denied) =
        refuse_one_layout_during(layout, || attempt.advance(view.block_hashes()));
    assert!(
        denied,
        "actual original prefix backing allocator must refuse"
    );
    let original = match result {
        Err(NativeExecutionReadError::Deferred(original)) => original,
        other => panic!("actual original prefix constructor refusal: {other:?}"),
    };
    assert_eq!(
        original
            .allocator_refusal()
            .unwrap()
            .buffer_from_charge_error(),
        Some(&ChargedBufferFromChargeError::Allocator { layout })
    );
    assert_eq!(
        pool.reserved_bytes(),
        floor + layout.size(),
        "prefix physical refusal must retain its exact original backing charge"
    );
    assert!(original.allocation_refusal().is_none() && original.decode_refusal().is_none());
    let mut exported = None;
    assert_eq!(
        allocations_during(|| exported = Some(original.into_vm_error())),
        0
    );
    let ivm::VMError::AllocatorDeferred(original) = exported.unwrap() else {
        panic!("the original typed prefix allocator cause must cross the VM boundary");
    };
    assert_eq!(
        original.into_buffer_from_charge_error().unwrap(),
        ChargedBufferFromChargeError::Allocator { layout }
    );
    assert!(attempt.prefix.is_none());
    assert!(attempt.prefix_charge.as_ref().unwrap().belongs_to(&pool));
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
        .unwrap();
    // No new pool credit remains: only the retained original charge permits another
    // real allocator attempt. Refusal must keep the same completed native input.
    let (result, denied) =
        refuse_one_layout_during(layout, || attempt.advance(view.block_hashes()));
    assert!(denied);
    assert!(
        matches!(result, Err(NativeExecutionReadError::Deferred(ref original))
        if original.allocator_refusal().and_then(|cause| cause.buffer_from_charge_error())
            == Some(&ChargedBufferFromChargeError::Allocator { layout }))
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    assert_eq!(attempt.current, GENESIS_HEIGHT);
    assert_eq!(attempt.total, 0);
    assert!(attempt.retained_wire.is_none());
    let pending = attempt.pending.as_ref().unwrap();
    assert!(
        pending.canonical_checked
            && SharedSignedBlock::ptr_eq(pending.block.as_ref().unwrap(), &body)
    );
    assert_eq!(
        pending
            .acquisition
            .original_bytes()
            .unwrap()
            .as_slice()
            .as_ptr(),
        raw
    );
    // Exercise the same sole constructor after physical pressure is released,
    // while all remaining credit is still occupied. No prefix object is built on stack.
    prepare_execution_read_prefix_backing(&mut attempt.prefix, &mut attempt.prefix_charge, &pool)
        .unwrap();
    assert!(attempt.prefix_charge.is_none());
    let prefix = attempt.prefix.as_ref().unwrap();
    assert!(prefix.belongs_to(&pool) && prefix.as_slice().is_empty());
    let backing = prefix.as_slice().as_ptr();
    let (result, allocated) = refuse_one_layout_during(layout, || {
        prepare_execution_read_prefix_backing(
            &mut attempt.prefix,
            &mut attempt.prefix_charge,
            &pool,
        )
    });
    result.unwrap();
    assert!(!allocated);
    assert_eq!(
        attempt.prefix.as_ref().unwrap().as_slice().as_ptr(),
        backing
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), floor + layout.size());
    let read = attempt.advance(view.block_hashes()).unwrap();
    assert!(attempt.is_completed() && attempt.pending.is_none());
    assert_eq!(
        attempt.prefix.as_ref().unwrap().as_slice().as_ptr(),
        backing
    );
    assert_eq!(read.wire.as_slice().as_ptr(), raw);
    assert!(SharedSignedBlock::ptr_eq(read.authority.block(), &body));
    assert_eq!(read.source_blocks, 2);
    assert_eq!(read.source_wire_bytes, limits.max_source_wire_bytes);
    assert_eq!(read.authority.committed().height(), GENESIS_HEIGHT);
    assert_eq!(
        body.canonical_wire_identity().unwrap(),
        (read.wire.as_slice().len() as u64, Hash::new(&read.wire))
    );
    drop(body);
    drop(read);
    drop(attempt);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prefix_physical_abandonment_refunds_original_pool_after_storage_guards_retire() {
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
    };
    struct Probe {
        kura: Arc<Kura>,
        hash: HashOf<IrohaHeader>,
        calls: AtomicUsize,
        blocked: AtomicUsize,
        reentered: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self
                .kura
                .publication_fences_for_test()
                .iter()
                .any(|(_, lock)| lock.try_lock().is_none())
            {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            } else if self
                .kura
                .native_frame_read(GENESIS_HEIGHT, self.hash)
                .ok()
                .flatten()
                .is_some()
            {
                self.reentered.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    let chain = fixture();
    let view = chain.state().view();
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut registration = crate::unit_test_support::release_registration(&pool);
    let registration_bytes = pool.reserved_bytes();
    let mut attempt = NativeExecutionReadAttempt::new(
        chain.kura(),
        view.chain_id(),
        *view.network_id(),
        view.block_hashes(),
        GENESIS_HEIGHT,
        limits(&chain),
        &pool,
    )
    .unwrap();
    attempt.pending = Some(completed_genesis(&chain, &pool));
    let floor = pool.reserved_bytes();
    let layout = Layout::new::<CertifiedPrefix>();
    let (result, denied) =
        refuse_one_layout_during(layout, || attempt.advance(view.block_hashes()));
    assert!(denied && matches!(result, Err(NativeExecutionReadError::Deferred(_))));
    assert_eq!(pool.reserved_bytes(), floor + layout.size());
    let blocker_bytes = pool.limit_bytes() - pool.reserved_bytes();
    let blocker = pool.try_reserve_bytes(blocker_bytes).unwrap();
    let AllocationRefusal::Capacity { release, .. } = pool.try_reserve_bytes(1).unwrap_err() else {
        panic!("the original pool is full");
    };
    let probe = Arc::new(Probe {
        kura: Arc::clone(chain.kura()),
        hash: chain.committed(1).block_hash(),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
        reentered: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut wait = release.wait_for_release(&mut registration);
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    let (result, denied) =
        refuse_one_layout_during(layout, || attempt.advance(view.block_hashes()));
    assert!(denied && matches!(result, Err(NativeExecutionReadError::Deferred(_))));
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    drop(attempt);
    assert_eq!(pool.reserved_bytes(), blocker_bytes + registration_bytes);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
    assert_eq!(probe.reentered.load(Ordering::SeqCst), 1);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
    drop(wait);
    drop(blocker);
    drop(registration);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prefix_constructor_preserves_capacity_and_keeps_layout_invariants_terminal() {
    let layout = Layout::new::<CertifiedPrefix>();
    assert!(layout.size() > 1);
    let pool = AllocationBudget::new(layout.size());
    let blocker = pool.try_reserve_bytes(1).unwrap();
    let mut prefix = None;
    let mut charge = None;
    let result = prepare_execution_read_prefix_backing(&mut prefix, &mut charge, &pool);
    assert!(
        matches!(result, Err(NativeExecutionReadError::Deferred(ref cause))
        if matches!(cause.allocation_refusal(), Some(AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. })
            if *requested_bytes == layout.size() && *reserved_bytes == 1 && *limit_bytes == layout.size()))
    );
    assert!(prefix.is_none() && charge.is_none());
    assert_eq!(pool.reserved_bytes(), 1);
    drop(blocker);
    prepare_execution_read_prefix_backing(&mut prefix, &mut charge, &pool).unwrap();
    assert!(prefix.as_ref().unwrap().belongs_to(&pool) && charge.is_none());
    drop(prefix.take());
    assert_eq!(pool.reserved_bytes(), 0);
    // A genuine wrong retained layout is an invariant rejection, never fabricated
    // allocator pressure. The constructor still returns its original exact charge.
    let wrong = Layout::new::<u8>();
    let mut reservation = pool.try_reserve(wrong).unwrap();
    charge = Some(reservation.try_split(wrong).unwrap());
    drop(reservation);
    let result = prepare_execution_read_prefix_backing(&mut prefix, &mut charge, &pool);
    let expected = ChargedBufferFromChargeError::LayoutMismatch {
        expected: layout,
        actual: wrong,
    };
    assert!(
        matches!(result, Err(NativeExecutionReadError::Storage { height: GENESIS_HEIGHT, ref reason }) if reason == &expected.to_string())
    );
    assert!(prefix.is_none());
    assert!(charge.as_ref().unwrap().belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), wrong.size());
    drop(charge);
    assert_eq!(pool.reserved_bytes(), 0);
}
