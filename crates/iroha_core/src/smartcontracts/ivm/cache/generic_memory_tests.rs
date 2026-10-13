//! Generic VM backing follows its original pool through active and idle ownership.

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
const HEAP: u64 = ivm::Memory::HEAP_MAX_SIZE;

fn retention() -> ivm::ivm_cache::CacheLimitsGuard {
    ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: 4,
        max_bytes: usize::MAX,
        max_decoded_ops: 0,
    })
}

fn cache(budget: &AllocationBudget) -> IvmCache {
    IvmCache::with_prepared_contract_cache(
        1,
        PreparedContractCache::with_execution_budget(1, budget.clone()),
    )
}

fn prepare(cache: &mut IvmCache) -> GenericProgramSummary {
    cache
        .summarize_generic_program(&super::tests::minimal_generic_program())
        .expect("generic summary")
}

fn capacity_refusal<T>(result: Result<T, ivm::VMError>) {
    assert!(matches!(
        result,
        Err(ivm::VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
}

#[test]
fn prepared_arrays_refuse_original_pool_and_survive_eviction_until_final_owner() {
    let _retention = retention();
    let program = super::tests::minimal_program();
    let hash = ivm::contract_code_hash(&program);
    let diagnostic = ivm::prepare_contract(Arc::<[u8]>::from(program.clone())).unwrap();
    let budget = AllocationBudget::new(0);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    assert!(matches!(
        cache.get_or_prepare(hash, &program),
        Err(ivm::VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    assert!(cache.get(hash).is_none());
    assert_eq!(cache.stats().preparations, 0);
    budget.set_limit_bytes(LIMIT);
    let occupied = budget.try_reserve_bytes(LIMIT).unwrap();
    capacity_refusal(cache.get_or_prepare(hash, &program));
    drop(occupied);
    let prepared = cache.get_or_prepare(hash, &program).unwrap();
    assert_eq!(prepared.artifact(), diagnostic.artifact());
    assert!(prepared.shared_artifact().belongs_to(&budget));
    let charged = budget.reserved_bytes();
    assert!(charged > program.len());
    let borrower = prepared.clone();
    budget.set_limit_bytes(0);
    cache.with_store(|store| store.clear_storage());
    drop(prepared);
    drop(cache);
    assert_eq!(
        budget.reserved_bytes(),
        charged,
        "eviction cannot refund a borrowed artifact"
    );
    drop(borrower);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_verifier_refuses_zero_original_pool_and_retries_without_publishing() {
    let _retention = retention();
    let budget = AllocationBudget::new(0);
    let mut cache = cache(&budget);
    let program = super::tests::minimal_generic_program();
    assert!(matches!(
        cache.summarize_generic_program(&program),
        Err(ivm::VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
            requested_bytes,
            limit_bytes: 0,
        })) if requested_bytes > 0
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(budget.peak_reserved_bytes(), 0);
    assert_eq!(cache.stats().preparations, 0);
    assert!(cache.with_local(|local| local.generic_summaries.is_empty()));

    budget.set_limit_bytes(LIMIT);
    let summary = prepare(&mut cache);
    assert_eq!(summary.program(), program);
    assert!(budget.peak_reserved_bytes() > 0);
    assert!(
        budget.reserved_bytes() > program.len(),
        "the verifier returns but the bytecode and its shared control stay funded"
    );
    assert!(
        cache
            .prepared_contracts
            .execution_budget()
            .same_pool(&budget)
    );
    assert_eq!(cache.stats().preparations, 1);
    drop(cache);
    assert!(budget.reserved_bytes() > 0, "summary is still borrowed");
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_runtime_refuses_exhausted_pool_and_retries_the_same_owner() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = cache(&budget);
    let summary = prepare(&mut cache);
    let summary_bytes = budget.reserved_bytes();
    let occupied = budget.try_reserve_bytes(LIMIT - summary_bytes).unwrap();
    capacity_refusal(cache.checkout_generic_runtime(&summary, GAS, HEAP));
    assert_eq!(budget.reserved_bytes(), LIMIT);
    assert!(cache.with_local(|local| local.runtime_templates.is_empty()));
    assert_eq!(cache.stats().prepared_loads, 0);
    drop(occupied);

    let mut runtime = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    assert!(budget.reserved_bytes() > 0);
    assert_eq!(runtime.remaining_gas(), GAS);
    runtime.run().expect("unchanged HALT result");
    drop(runtime);
    assert!(budget.reserved_bytes() > 0, "idle backing stays funded");
    cache.with_local(LocalCacheStore::clear_storage);
    assert_eq!(budget.reserved_bytes(), summary_bytes);
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_template_refusal_releases_unpublished_vm_and_allows_retry() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = cache(&budget);
    let summary = prepare(&mut cache);
    let summary_bytes = budget.reserved_bytes();
    let mut measured = ivm::IVM::try_new_with_memory_budget(GAS, &budget).unwrap();
    measured.set_zk_trace_enabled(false);
    measured.memory.set_heap_max_limit(HEAP).unwrap();
    measured.load_program(summary.program()).unwrap();
    let vm_bytes = budget.reserved_bytes();
    drop(measured);
    budget.set_limit_bytes(vm_bytes);

    assert!(matches!(
        cache.checkout_generic_runtime(&summary, GAS, HEAP),
        Err(ivm::VMError::AllocationDeferred(
            AllocationRefusal::Capacity { limit_bytes, .. }
                | AllocationRefusal::ExceedsLimit { limit_bytes, .. }
        )) if limit_bytes == vm_bytes
    ));
    assert_eq!(budget.reserved_bytes(), summary_bytes);
    assert!(cache.with_local(|local| local.runtime_templates.is_empty()));
    budget.set_limit_bytes(LIMIT);
    let runtime = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    assert!(budget.reserved_bytes() > vm_bytes);
    drop(runtime);
    cache.with_local(LocalCacheStore::clear_storage);
    assert_eq!(budget.reserved_bytes(), summary_bytes);
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_warm_reset_keeps_credit_after_pool_shrink() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = cache(&budget);
    let summary = prepare(&mut cache);
    let summary_bytes = budget.reserved_bytes();
    let mut runtime = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    runtime
        .memory
        .store_u64(ivm::Memory::HEAP_START, 55)
        .unwrap();
    let image = runtime.memory.load_region(0, 1).unwrap().as_ptr();
    // Reset scrubs and drops the recorded write's independently owned payload.
    // Its row backing and the VM/template storage remain funded while idle.
    let charged = budget.reserved_bytes() - std::mem::size_of::<u64>();
    drop(runtime);
    assert_eq!(budget.reserved_bytes(), charged);
    budget.set_limit_bytes(0);

    let runtime = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    assert_eq!(runtime.memory.load_region(0, 1).unwrap().as_ptr(), image);
    assert_eq!(
        (runtime.memory.load_u64(ivm::Memory::HEAP_START)).expect("completed fixture operation"),
        0
    );
    assert_eq!(runtime.remaining_gas(), GAS);
    assert_eq!(budget.reserved_bytes(), charged);
    drop(runtime);
    assert_eq!(budget.reserved_bytes(), charged);
    cache.with_local(LocalCacheStore::clear_storage);
    assert_eq!(budget.reserved_bytes(), summary_bytes);
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_eviction_waits_for_active_vm_and_final_baseline_owner() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = cache(&budget);
    let summary = prepare(&mut cache);
    let summary_bytes = budget.reserved_bytes();
    let runtime = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    let baseline = runtime.baseline.clone();
    let charged = budget.reserved_bytes();
    ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    assert_eq!(budget.reserved_bytes(), charged, "borrow survives eviction");
    budget.set_limit_bytes(0);
    drop(runtime);
    assert!(
        budget.reserved_bytes() > 0,
        "borrowed baseline still owns credit"
    );
    assert!(budget.reserved_bytes() < charged, "active VM was reclaimed");
    drop(cache);
    assert!(
        budget.reserved_bytes() > 0,
        "cache drop cannot refund the baseline"
    );
    drop(baseline);
    assert_eq!(budget.reserved_bytes(), summary_bytes);
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_summary_eviction_keeps_one_original_charge_through_every_borrower() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = cache(&budget);
    let summary = prepare(&mut cache);
    let charged = budget.reserved_bytes();
    assert!(charged > summary.program().len());
    let second = summary.clone();
    let image = summary.shared_program();
    assert!(ivm::cache_memory::SharedAllocation::ptr_eq(
        &image,
        &second.shared_program()
    ));
    assert_eq!(budget.reserved_bytes(), charged);
    ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    assert!(cache.with_local(|local| local.generic_summaries.is_empty()));
    assert_eq!(budget.reserved_bytes(), charged);
    budget.set_limit_bytes(0);
    drop(cache);
    drop(summary);
    drop(second);
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(image.as_ref(), super::tests::minimal_generic_program());
    drop(image);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn zero_retention_generic_execution_retains_only_the_live_summary_image() {
    let _retention = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = cache(&budget);
    let summary = prepare(&mut cache);
    let charged = budget.reserved_bytes();
    assert!(charged > summary.program().len());
    assert!(cache.with_local(|local| local.generic_summaries.is_empty()));
    let mut runtime = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    runtime.run().expect("uncached HALT remains valid");
    drop(runtime);
    assert!(cache.with_local(|local| local.runtime_templates.is_empty()));
    assert_eq!(budget.reserved_bytes(), charged);
    drop(cache);
    assert_eq!(budget.reserved_bytes(), charged);
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

struct ReenterLocal {
    outer: Arc<Mutex<IvmCache>>,
    local: Arc<Mutex<LocalCacheStore>>,
    calls: AtomicUsize,
    locked: AtomicBool,
}

impl Wake for ReenterLocal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Some(local) = self.local.try_lock() else {
            self.locked.store(true, Ordering::SeqCst);
            return;
        };
        drop(local);
        let Some(outer) = self.outer.try_lock() else {
            self.locked.store(true, Ordering::SeqCst);
            return;
        };
        drop(outer);
        std::hint::black_box(IvmCache::with_locked(&self.outer, |cache| cache.stats()));
    }
}

fn observed_retained_owner<'a>(
    with_runtime: bool,
    budget: &AllocationBudget,
    registration: &'a mut iroha_allocation::release::ReleaseRegistration,
) -> (Arc<ReenterLocal>, ReleaseFuture<'a>) {
    let mut cache = cache(budget);
    let summary = prepare(&mut cache);
    if with_runtime {
        drop(cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap());
    }
    assert!(budget.reserved_bytes() > 0);
    budget.set_limit_bytes(budget.reserved_bytes());
    let local = Arc::clone(&cache.local);
    let outer = Arc::new(Mutex::new(cache));
    let observer = Arc::new(ReenterLocal {
        outer,
        local,
        calls: AtomicUsize::new(0),
        locked: AtomicBool::new(false),
    });
    let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
    else {
        panic!("original occupied pool supplies the observation");
    };
    let mut wait = release.wait_for_release(registration);
    let waker = Waker::from(Arc::clone(&observer));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    (observer, wait)
}

fn assert_unlocked(observer: &Arc<ReenterLocal>, mut wait: ReleaseFuture<'_>) {
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
    assert!(!observer.locked.load(Ordering::SeqCst));
    let waker = Waker::from(Arc::clone(observer));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
}

#[test]
fn generic_registered_eviction_refund_reenters_after_local_and_outer_unlock() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let (observer, wait) = observed_retained_owner(true, &budget, &mut registration);
    IvmCache::with_locked(&observer.outer, |_| {
        ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
            capacity: 0,
            max_bytes: 0,
            max_decoded_ops: 0,
        });
        assert_eq!(budget.reserved_bytes(), waiter_bytes);
        assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
    });
    assert_unlocked(&observer, wait);
    assert_eq!(budget.reserved_bytes(), waiter_bytes);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_store_unwind_refund_preserves_panic_and_unlocks_both_guards() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let (observer, wait) = observed_retained_owner(true, &budget, &mut registration);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        IvmCache::with_locked(&observer.outer, |cache| {
            cache.with_local(|local| {
                local.clear_storage();
                assert_eq!(budget.reserved_bytes(), waiter_bytes);
                assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
                panic!("generic cache operation failed");
            });
        });
    }));
    assert_eq!(
        result.expect_err("original panic").downcast_ref::<&str>(),
        Some(&"generic cache operation failed")
    );
    assert_unlocked(&observer, wait);
    assert_eq!(budget.reserved_bytes(), waiter_bytes);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_image_final_refund_waits_for_both_cache_guards_on_success_and_unwind() {
    let _retention = retention();
    for unwind in [false, true] {
        let budget = AllocationBudget::new(LIMIT);
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let waiter_bytes =
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
        let (observer, wait) = observed_retained_owner(false, &budget, &mut registration);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            IvmCache::with_locked(&observer.outer, |cache| {
                cache.with_local(|local| {
                    local.clear_storage();
                    assert_eq!(budget.reserved_bytes(), waiter_bytes);
                    assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
                    assert!(!unwind, "generic image operation failed");
                });
            });
        }));
        assert_eq!(result.is_err(), unwind);
        assert_unlocked(&observer, wait);
        assert_eq!(budget.reserved_bytes(), waiter_bytes);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
