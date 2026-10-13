//! Funded preparation releases notify only after the original claim retires.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll, Wake, Waker},
};

thread_local! {
    static PANIC_AFTER_PREPARATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Called only by the test build after canonical preparation and before publication.
pub(super) fn panic_after_preparation_if_requested() {
    assert!(
        !PANIC_AFTER_PREPARATION.replace(false),
        "test unwind after original funded preparation"
    );
}

struct ReenterPreparation {
    cache: PreparedContractCache,
    program: Vec<u8>,
    hash: Hash,
    calls: AtomicUsize,
    still_claimed: AtomicBool,
    locked: AtomicBool,
    reentered: AtomicUsize,
}
impl Wake for ReenterPreparation {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Some(store) = self.cache.inner.try_lock() else {
            self.locked.store(true, Ordering::SeqCst);
            return;
        };
        if store.preparing.contains(&self.hash) {
            // Record the old deadlock condition without entering a blocking
            // same-thread wait. Correct code goes on to reenter the real API.
            self.still_claimed.store(true, Ordering::SeqCst);
            return;
        }
        drop(store);
        let result = self.cache.get_or_prepare(self.hash, &self.program);
        assert!(result.is_ok() || matches!(result, Err(ivm::VMError::AllocationDeferred(_))));
        self.reentered.fetch_add(1, Ordering::SeqCst);
    }
}

fn first_preparation_demand(program: &[u8]) -> usize {
    let probe = AllocationBudget::new(0);
    let refused = ivm::prepare_contract_with_memory_budget(program, &probe)
        .unwrap_err()
        .into_vm_error();
    let ivm::VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
        requested_bytes, ..
    }) = refused
    else {
        panic!("first actual canonical backing must require original admission");
    };
    assert!(requested_bytes > 0);
    assert_eq!(probe.peak_reserved_bytes(), 0);
    requested_bytes
}

fn assert_partial_preparation_reentry(unwind: bool) {
    let program = super::tests::minimal_program();
    let hash = ivm::contract_code_hash(&program);
    let first = first_preparation_demand(&program);
    let registration_bytes = ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(first + registration_bytes);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let AllocationRefusal::Capacity { release, .. } =
        budget.try_reserve_bytes(first + 1).unwrap_err()
    else {
        panic!("original waiter observes capacity before the actual prepare");
    };
    let callback = Arc::new(ReenterPreparation {
        cache: cache.clone(),
        program: program.clone(),
        hash,
        calls: AtomicUsize::new(0),
        still_claimed: AtomicBool::new(false),
        locked: AtomicBool::new(false),
        reentered: AtomicUsize::new(0),
    });
    let waker = Waker::from(callback.clone());
    let mut context = Context::from_waker(&waker);
    let mut wait = release.wait_for_release(&mut registration);
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Pending);
    PANIC_AFTER_PREPARATION.set(unwind);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cache.get_or_prepare(hash, &program)
    }));
    PANIC_AFTER_PREPARATION.set(false);
    if unwind {
        assert!(result.is_err());
    } else {
        assert!(matches!(
            result.unwrap(),
            Err(ivm::VMError::AllocationDeferred(_))
        ));
    }
    assert!(
        budget.peak_reserved_bytes() > registration_bytes,
        "real preparation allocated before refusing"
    );
    assert_eq!(budget.reserved_bytes(), registration_bytes);
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    assert!(!callback.locked.load(Ordering::SeqCst));
    assert!(!callback.still_claimed.load(Ordering::SeqCst));
    assert_eq!(callback.reentered.load(Ordering::SeqCst), 1);
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Ready(()));
    drop(wait);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(64 * 1024 * 1024);
    assert_eq!(
        cache.get_or_prepare(hash, &program).unwrap().code_hash(),
        hash
    );
}

#[test]
fn actual_partial_preparation_refund_reenters_only_after_its_claim_finishes() {
    assert_partial_preparation_reentry(false);
}

#[test]
fn actual_partial_preparation_unwind_retires_claim_before_reentrant_refund() {
    assert_partial_preparation_reentry(true);
}
