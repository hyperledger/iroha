//! Original State-pool custody for lazy executor runtimes and borrowed baselines.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseFuture};
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Wake, Waker},
};

const LIMIT: usize = 64 * 1024 * 1024;
const GAS: u64 = 10_000;
const HEAP: u64 = Memory::HEAP_MAX_SIZE;

fn retention() -> ivm::ivm_cache::CacheLimitsGuard {
    ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: 4,
        max_bytes: usize::MAX,
        max_decoded_ops: 0,
    })
}

fn loaded() -> LoadedExecutor {
    LoadedExecutor::load(data_model_executor::Executor::new(
        iroha_data_model::transaction::IvmBytecode::from_compiled(generate_verdict_program(
            &Ok(()),
        )),
    ))
    .unwrap()
}

fn clear(loaded: &LoadedExecutor) {
    with_executor_runtime_pool(&loaded.runtime_pool, ExecutorRuntimePool::clear_storage);
}

#[test]
fn restore_performs_static_admission_without_a_vm_or_funding_owner() {
    let original = loaded();
    let encoded = executor_norito::to_bytes(&Executor::UserProvided(original)).unwrap();
    let Executor::UserProvided(restored) = executor_norito::from_bytes(&encoded).unwrap() else {
        panic!("user executor");
    };
    assert_eq!(
        restored.runtime_pool_snapshot(),
        (ExecutorRuntimePoolStats::default(), 0)
    );
    assert!(with_executor_runtime_pool(&restored.runtime_pool, |pool| {
        pool.execution_budget.is_none()
    }));
    for program in [vec![0], {
        let mut program = ivm::ProgramMetadata::default().encode();
        program.extend_from_slice(&[0xff; 4]);
        program
    }] {
        assert!(
            LoadedExecutor::load(data_model_executor::Executor::new(
                iroha_data_model::transaction::IvmBytecode::from_compiled(program),
            ))
            .is_err()
        );
    }
}

#[test]
fn executor_refuses_zero_and_exhausted_original_pool_then_retries() {
    let _retention = retention();
    let loaded = loaded();
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        loaded.checkout_runtime_for_gas_limit(GAS, HEAP, &budget),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. }
        ))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    assert_eq!(loaded.runtime_pool_snapshot().0.program_loads, 0);
    budget.set_limit_bytes(LIMIT);
    let occupied = budget.try_reserve_bytes(LIMIT).unwrap();
    assert!(matches!(
        loaded.checkout_runtime_for_gas_limit(GAS, HEAP, &budget),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), LIMIT);
    drop(occupied);
    drop(
        loaded
            .checkout_runtime_for_gas_limit(GAS, HEAP, &budget)
            .unwrap(),
    );
    assert!(budget.reserved_bytes() > 0);
    assert!(with_executor_runtime_pool(&loaded.runtime_pool, |pool| {
        pool.execution_budget.as_ref().unwrap().same_pool(&budget)
    }));
    clear(&loaded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn executor_template_refusal_releases_unpublished_vm_before_retry() {
    let _retention = retention();
    let loaded = loaded();
    let budget = AllocationBudget::new(LIMIT);
    let measured = LoadedExecutor::load_runtime(&loaded.raw_executor, GAS, HEAP, &budget).unwrap();
    let vm_bytes = budget.reserved_bytes();
    assert!(vm_bytes > 0);
    drop(measured);
    budget.set_limit_bytes(vm_bytes);
    assert!(matches!(
        loaded.checkout_runtime_for_gas_limit(GAS, HEAP, &budget),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(loaded.runtime_pool_snapshot().0.template_builds, 0);
    assert!(with_executor_runtime_pool(&loaded.runtime_pool, |pool| {
        pool.variants
            .values()
            .all(|variant| variant.available.is_none())
    }));
    budget.set_limit_bytes(LIMIT);
    drop(
        loaded
            .checkout_runtime_for_gas_limit(GAS, HEAP, &budget)
            .unwrap(),
    );
    assert!(budget.reserved_bytes() > vm_bytes);
    clear(&loaded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn warm_executor_reuses_original_credit_after_shrink_and_unwind() {
    let _retention = retention();
    let loaded = loaded();
    let budget = AllocationBudget::new(LIMIT);
    let mut runtime = loaded
        .checkout_runtime_for_gas_limit(GAS, HEAP, &budget)
        .unwrap();
    let image = runtime.memory.load_region(0, 1).unwrap().as_ptr();
    runtime.memory.preload_input(0, &[0xa5]).unwrap();
    let reserved = budget.reserved_bytes();
    assert!(
        iroha_panic_hook::catch_unwind_suppressed(std::panic::AssertUnwindSafe(move || {
            let _runtime = runtime;
            panic!("executor invocation unwind");
        }))
        .is_err()
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    budget.set_limit_bytes(0);
    let runtime = loaded
        .checkout_runtime_for_gas_limit(GAS, HEAP, &budget)
        .unwrap();
    assert_eq!(runtime.memory.load_region(0, 1).unwrap().as_ptr(), image);
    assert_eq!(
        runtime.memory.load_region(Memory::INPUT_START, 1).unwrap(),
        &[0]
    );
    assert_eq!(runtime.remaining_gas(), GAS);
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(runtime);
    clear(&loaded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn foreign_state_cannot_borrow_or_refund_original_pool_credit() {
    let _retention = retention();
    let loaded = loaded();
    let original = AllocationBudget::new(LIMIT);
    drop(
        loaded
            .checkout_runtime_for_gas_limit(GAS, HEAP, &original)
            .unwrap(),
    );
    let reserved = original.reserved_bytes();
    let foreign = AllocationBudget::new(0);
    assert!(matches!(
        loaded.checkout_runtime_for_gas_limit(GAS, HEAP, &foreign),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. }
        ))
    ));
    assert_eq!(original.reserved_bytes(), reserved);
    foreign.set_limit_bytes(LIMIT);
    let runtime = loaded
        .checkout_runtime_for_gas_limit(GAS, HEAP, &foreign)
        .unwrap();
    assert!(runtime.variant_identity.is_none());
    assert!(foreign.reserved_bytes() > 0);
    assert_eq!(original.reserved_bytes(), reserved);
    drop(runtime);
    assert_eq!(foreign.reserved_bytes(), 0, "foreign runtime is uncached");
    assert_eq!(original.reserved_bytes(), reserved);
    clear(&loaded);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn executor_eviction_preserves_borrower_and_final_baseline_credit() {
    let _retention = retention();
    let loaded = loaded();
    let budget = AllocationBudget::new(LIMIT);
    let runtime = loaded
        .checkout_runtime_for_gas_limit(GAS, HEAP, &budget)
        .unwrap();
    let baseline = runtime.baseline.clone();
    let reserved = budget.reserved_bytes();
    ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(runtime);
    assert!(budget.reserved_bytes() > 0 && budget.reserved_bytes() < reserved);
    assert_eq!(
        loaded.runtime_pool_snapshot().1,
        0,
        "stale borrower cannot republish"
    );
    drop(loaded);
    assert!(budget.reserved_bytes() > 0);
    drop(baseline);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn validation_and_migration_preserve_local_original_pool_refusal() {
    let loaded = loaded();
    let budget = AllocationBudget::new(0);
    let context = ExecutorContext {
        authority: iroha_test_samples::ALICE_ID.clone(),
        curr_block: BlockHeader::new(nonzero_ext::nonzero!(1_u64), None, None, 0, 0),
    };
    let payload = ValidatePayload {
        context: context.clone(),
        target: 0_u8,
    };
    let expected = crate::execution_attempt::ExecutionDeferred::try_from_vm_error(
        LoadedExecutor::load_runtime(&loaded.raw_executor, GAS, HEAP, &budget)
            .err()
            .unwrap(),
    )
    .unwrap();
    assert!(
        matches!(run_executor_validation(&loaded, &payload, "funding", GAS, HEAP, &budget),
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(reason)) if reason.reason() == expected.reason() && reason.allocation_refusal() == expected.allocation_refusal())
    );
    assert!(
        matches!(run_executor_migration(&loaded, &context, GAS, HEAP, &budget),
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(reason)) if reason.reason() == expected.reason() && reason.allocation_refusal() == expected.allocation_refusal())
    );
    assert_eq!(budget.peak_reserved_bytes(), 0);
}

struct ReenterPool {
    pool: Arc<Mutex<ExecutorRuntimePool>>,
    outer: Arc<Mutex<()>>,
    calls: AtomicUsize,
    locked: AtomicBool,
}
impl Wake for ReenterPool {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                self.locked.store(true, Ordering::SeqCst);
                return;
            }
        };
        drop(pool);
        let outer = match self.outer.try_lock() {
            Ok(outer) => outer,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                self.locked.store(true, Ordering::SeqCst);
                return;
            }
        };
        drop(outer);
        with_executor_runtime_pool(&self.pool, |pool| std::hint::black_box(pool.variants.len()));
    }
}
fn observe<'a>(
    budget: &AllocationBudget,
    loaded: &LoadedExecutor,
    registration: &'a mut iroha_allocation::release::ReleaseRegistration,
) -> (Arc<ReenterPool>, ReleaseFuture<'a>) {
    budget.set_limit_bytes(budget.reserved_bytes());
    let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
    else {
        panic!("occupied original pool");
    };
    let observer = Arc::new(ReenterPool {
        pool: Arc::clone(&loaded.runtime_pool),
        outer: Arc::new(Mutex::new(())),
        calls: AtomicUsize::new(0),
        locked: AtomicBool::new(false),
    });
    let mut wait = release.wait_for_release(registration);
    let waker = Waker::from(Arc::clone(&observer));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    (observer, wait)
}

#[test]
fn executor_refund_callbacks_wait_for_pool_and_enclosing_writer_on_success_and_unwind() {
    let _retention = retention();
    for unwind in [false, true] {
        let loaded = loaded();
        let budget = AllocationBudget::new(LIMIT);
        let mut registration = crate::unit_test_support::release_registration(&budget);
        drop(
            loaded
                .checkout_runtime_for_gas_limit(GAS, HEAP, &budget)
                .unwrap(),
        );
        let (observer, wait) = observe(&budget, &loaded, &mut registration);
        let outcome =
            iroha_panic_hook::catch_unwind_suppressed(std::panic::AssertUnwindSafe(|| {
                budget.with_deferred_refund_notifications(|_| {
                    let _outer = observer
                        .outer
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    if unwind {
                        with_executor_runtime_pool(&loaded.runtime_pool, |pool| {
                            pool.clear_storage();
                            assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
                            panic!("original executor pool unwind");
                        });
                    } else {
                        ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
                            capacity: 0,
                            max_bytes: 0,
                            max_decoded_ops: 0,
                        });
                    }
                    assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
                });
            }));
        assert_eq!(outcome.is_err(), unwind);
        drop(wait);
        assert_eq!(
            budget.reserved_bytes(),
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size()
        );
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
        assert!(!observer.locked.load(Ordering::SeqCst));
        // Restore retention before preparing the second independent original owner.
        ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
            capacity: 4,
            max_bytes: usize::MAX,
            max_decoded_ops: 0,
        });
    }
}
