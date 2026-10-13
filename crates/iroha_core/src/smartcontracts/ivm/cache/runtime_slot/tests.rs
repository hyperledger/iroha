//! Fixed runtime rows retain their exact original pool through real cache leases.

use super::super::{
    IvmCache, LocalCacheStore, PreparedContractCache, RuntimeKey, stack_limit_for_gas,
};
use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use iroha_allocation::{AllocationRefusal, release::ReleaseFuture};
use parking_lot::Mutex;
use std::{
    alloc::Layout,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

const LIMIT: usize = 64 * 1024 * 1024;
const GAS: u64 = 10_000;
const HEAP: u64 = 96;

fn retention() -> ivm::ivm_cache::CacheLimitsGuard {
    ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: 4,
        max_bytes: usize::MAX,
        max_decoded_ops: 0,
    })
}

fn row_layout() -> Layout {
    Layout::array::<PooledRuntime>(1).unwrap()
}

fn row_pointer(backing: &IdleRuntimeBacking) -> *const PooledRuntime {
    backing.storage.as_slice().as_ptr()
}

fn contract_program() -> Vec<u8> {
    super::super::tests::minimal_program()
}

fn generic_program() -> Vec<u8> {
    super::super::tests::minimal_generic_program()
}

fn local_cache(budget: &AllocationBudget, capacity: usize) -> IvmCache {
    IvmCache::with_prepared_contract_cache(
        capacity,
        PreparedContractCache::with_execution_budget(capacity, budget.clone()),
    )
}

fn runtime_pair(budget: &AllocationBudget) -> PooledRuntime {
    let mut vm = ivm::IVM::try_new_with_memory_budget(GAS, budget).unwrap();
    vm.set_zk_trace_enabled(false);
    vm.memory.set_heap_max_limit(HEAP).unwrap();
    vm.load_program(&generic_program()).unwrap();
    let baseline = vm.try_runtime_template().unwrap();
    PooledRuntime { baseline, vm }
}

// Each safe standard-library operation exercises a distinct allocator request.
// These positive controls run after the measured owner transfers, never inside them.
fn allocator_hook_positive_controls() {
    assert!(
        allocations_during(|| {
            std::hint::black_box(Vec::<u8>::with_capacity(37));
        }) > 0
    );
    assert!(
        allocations_during(|| {
            std::hint::black_box(vec![0_u8; 41]);
        }) > 0
    );
    let mut original = Vec::<u8>::with_capacity(19);
    original.extend_from_slice(&[7; 19]);
    let pointer = original.as_ptr();
    assert!(
        allocations_during(|| {
            original.try_reserve_exact(53).unwrap();
            std::hint::black_box(&original);
        }) > 0
    );
    assert_eq!(original.as_slice(), &[7; 19]);
    assert!(original.capacity() >= 72);
    std::hint::black_box(pointer);
}

#[test]
fn runtime_slot_exact_layout_refuses_before_any_allocator_or_publication() {
    let _retention = retention();
    let bytes = row_layout().size();
    assert!(bytes > 0);
    assert_eq!(bytes, std::mem::size_of::<PooledRuntime>());
    assert_eq!(row_layout().align(), std::mem::align_of::<PooledRuntime>());
    for limit in [0, bytes - 1] {
        let budget = AllocationBudget::new(limit);
        let mut result = None;
        let ((), physical_request) = refuse_one_layout_during(row_layout(), || {
            assert_eq!(
                allocations_during(|| {
                    result = Some(IdleRuntimeBacking::try_new(&budget));
                }),
                0
            );
        });
        assert!(!physical_request);
        assert!(
            matches!(result.unwrap(), Err(ivm::VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes }
        )) if requested_bytes == bytes && limit_bytes == limit)
        );
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.peak_reserved_bytes(), 0);
        assert!(IdleRuntimeSlot::empty().is_empty());
    }
    let budget = AllocationBudget::new(bytes);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    let mut result = None;
    assert_eq!(
        allocations_during(|| {
            result = Some(IdleRuntimeBacking::try_new(&budget));
        }),
        0
    );
    assert!(
        matches!(result.unwrap(), Err(ivm::VMError::AllocationDeferred(
        AllocationRefusal::Capacity { requested_bytes, reserved_bytes: 1, limit_bytes, .. }
    )) if requested_bytes == bytes && limit_bytes == bytes)
    );
    drop(occupied);
    let backing = IdleRuntimeBacking::try_new(&budget).unwrap();
    assert_eq!(backing.storage.capacity(), 1);
    assert!(backing.storage.as_slice().is_empty());
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(budget.peak_reserved_bytes(), bytes);
    assert!(backing.try_retain());
    backing.storage.activate();
    // Independent nonzero retention shortage declines the same fixed owner;
    // it cannot refund original active-pool credit or install a substitute row.
    ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
        capacity: 4,
        max_bytes: bytes - 1,
        max_decoded_ops: 0,
    });
    assert!(!backing.try_retain());
    assert_eq!(budget.reserved_bytes(), bytes);
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), bytes);
    assert!(IdleRuntimeBacking::try_new(&budget).is_err());
    drop(backing);
    assert_eq!(budget.reserved_bytes(), 0);
    allocator_hook_positive_controls();
}

#[test]
fn runtime_slot_physical_refusal_refunds_only_original_split_and_retries() {
    let _retention = retention();
    let bytes = row_layout().size();
    let budget = AllocationBudget::new(bytes + 7);
    let unrelated = budget.try_reserve_bytes(7).unwrap();
    let (result, requested) =
        refuse_one_layout_during(row_layout(), || IdleRuntimeBacking::try_new(&budget));
    assert!(requested);
    assert!(matches!(
        result,
        Err(ivm::VMError::ExecutionDeferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 7);
    assert_eq!(budget.peak_reserved_bytes(), bytes + 7);
    let backing = IdleRuntimeBacking::try_new(&budget).unwrap();
    assert!(backing.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), bytes + 7);
    drop(backing);
    assert_eq!(budget.reserved_bytes(), 7);
    drop(unrelated);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn runtime_slot_transfer_and_reserved_placement_allocate_no_new_backing() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let runtime = runtime_pair(&budget);
    let backing = IdleRuntimeBacking::try_new(&budget).unwrap();
    let pointer = row_pointer(&backing);
    let charged = budget.reserved_bytes();
    let mut slot = IdleRuntimeSlot::empty();
    assert_eq!(
        allocations_during(|| {
            slot.place(backing, runtime);
            assert_eq!(slot.len(), 1);
            assert_eq!(row_pointer(slot.backing.as_ref().unwrap()), pointer);
            let (runtime, backing) = slot.take().unwrap();
            assert!(slot.is_empty());
            assert!(backing.storage.as_slice().is_empty());
            assert_eq!(row_pointer(&backing), pointer);
            assert_eq!(budget.reserved_bytes(), charged);
            slot.place(backing, runtime);
        }),
        0
    );
    assert_eq!(slot.len(), 1);
    assert_eq!(budget.reserved_bytes(), charged);
    drop(slot);
    assert_eq!(budget.reserved_bytes(), 0);
    allocator_hook_positive_controls();
}

#[test]
fn shared_nested_runtime_slot_keeps_original_pool_through_cold_idle_and_warm_use() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let program = contract_program();
    let prepared = cache
        .get_or_prepare(ivm::contract_code_hash(&program), &program)
        .unwrap();
    let prepared_bytes = budget.reserved_bytes();
    let mut runtime = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    let row = row_pointer(runtime.backing.as_ref().unwrap());
    assert!(runtime.backing.as_ref().unwrap().belongs_to(&budget));
    let image = runtime.memory.load_region(0, 1).unwrap().as_ptr();
    let root = runtime.memory.root();
    let charged = budget.reserved_bytes();
    assert_eq!(runtime.remaining_gas(), GAS);
    assert_eq!(runtime.memory.heap_max_limit(), HEAP);
    runtime.set_register(7, 99);
    runtime.memory.preload_input(0, &[0xA5]).unwrap();
    drop(runtime);
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(cache.stats().runtime_dirty_resets, 1);
    let key = RuntimeKey::new(prepared.code_hash(), stack_limit_for_gas(GAS), HEAP);
    assert_eq!(
        cache.with_store(|store| {
            let slot = &store.nested_runtimes[&key].available;
            assert_eq!(slot.len(), 1);
            row_pointer(slot.backing.as_ref().unwrap())
        }),
        row
    );
    budget.set_limit_bytes(0);
    let mut warm = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    assert_eq!(row_pointer(warm.backing.as_ref().unwrap()), row);
    assert_eq!(warm.memory.load_region(0, 1).unwrap().as_ptr(), image);
    assert_eq!(warm.register(7), 0);
    assert_eq!(
        warm.memory
            .load_region(ivm::Memory::INPUT_START, 1)
            .unwrap(),
        [0]
    );
    assert_eq!(warm.memory.root(), root);
    assert_eq!(warm.remaining_gas(), GAS);
    assert_eq!(budget.reserved_bytes(), charged);
    // Reusing the loaded row needs no new credit; a new invocation still
    // requires its own register-log owner before any guest effect can run.
    let before_invocation = warm.execution_summary();
    assert!(matches!(
        warm.run_with_host(&mut ivm::host::DefaultHost::new()),
        Err(ivm::VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
            requested_bytes,
            limit_bytes: 0,
        })) if requested_bytes > 0
    ));
    assert_eq!(warm.execution_summary(), before_invocation);
    assert_eq!(budget.reserved_bytes(), charged);
    budget.set_limit_bytes(LIMIT);
    assert_eq!(
        (warm.run_with_host(&mut ivm::host::DefaultHost::new()))
            .expect("expected successful VM operation"),
        ()
    );
    drop(warm);
    assert_eq!(cache.stats().runtime_hits, 1);
    cache.with_store(|store| store.clear_storage());
    assert_eq!(budget.reserved_bytes(), prepared_bytes);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn local_contract_runtime_slot_keeps_original_pool_and_existing_summary_semantics() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = local_cache(&budget, 1);
    let program = contract_program();
    let summary = cache.summarize_program(&program).unwrap();
    assert_eq!(summary.prepared_contract().artifact(), program);
    assert!(
        summary
            .prepared_contract()
            .shared_artifact()
            .belongs_to(&budget)
    );
    let mut cold = cache
        .checkout_runtime(&summary, &program, GAS, HEAP)
        .unwrap();
    let row = row_pointer(cold.backing.as_ref().unwrap());
    assert!(cold.backing.as_ref().unwrap().belongs_to(&budget));
    let image = cold.memory.load_region(0, 1).unwrap().as_ptr();
    let root = cold.memory.root();
    let charged = budget.reserved_bytes();
    cold.set_register(8, 41);
    cold.memory.preload_input(0, &[0x7E]).unwrap();
    drop(cold);
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(cache.stats().dirty_resets, 1);
    let mut warm = cache
        .checkout_runtime(&summary, &program, GAS, HEAP)
        .unwrap();
    assert_eq!(row_pointer(warm.backing.as_ref().unwrap()), row);
    assert_eq!(warm.memory.load_region(0, 1).unwrap().as_ptr(), image);
    assert_eq!(warm.memory.root(), root);
    assert_eq!(warm.register(8), 0);
    assert_eq!(warm.remaining_gas(), GAS);
    assert_eq!(warm.memory.heap_max_limit(), HEAP);
    assert_eq!(
        (warm.run_with_host(&mut ivm::host::DefaultHost::new()))
            .expect("expected successful VM operation"),
        ()
    );
    drop(warm);
    assert_eq!(cache.stats().runtime_hits, 1);
    cache.with_local(LocalCacheStore::clear_storage);
    cache
        .prepared_contracts
        .with_store(|store| store.clear_storage());
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn local_generic_runtime_slot_keeps_original_program_and_warm_reset() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let mut cache = local_cache(&budget, 1);
    let program = generic_program();
    let summary = cache.summarize_generic_program(&program).unwrap();
    assert!(summary.shared_program().belongs_to(&budget));
    let mut cold = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    let row = row_pointer(cold.backing.as_ref().unwrap());
    let image = cold.memory.load_region(0, 1).unwrap().as_ptr();
    let root = cold.memory.root();
    let charged = budget.reserved_bytes();
    cold.set_register(9, 42);
    cold.memory.preload_input(0, &[0x5A]).unwrap();
    drop(cold);
    assert_eq!(budget.reserved_bytes(), charged);
    budget.set_limit_bytes(0);
    let mut warm = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
    assert!(warm.backing.as_ref().unwrap().belongs_to(&budget));
    assert_eq!(row_pointer(warm.backing.as_ref().unwrap()), row);
    assert_eq!(warm.memory.load_region(0, 1).unwrap().as_ptr(), image);
    assert_eq!(warm.memory.root(), root);
    assert_eq!(warm.register(9), 0);
    assert_eq!(warm.remaining_gas(), GAS);
    assert_eq!(warm.memory.heap_max_limit(), HEAP);
    // Reusing the loaded row needs no new credit; a new invocation still
    // requires its own register-log owner before any guest effect can run.
    let before_invocation = warm.execution_summary();
    assert!(matches!(
        warm.run_with_host(&mut ivm::host::DefaultHost::new()),
        Err(ivm::VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
            requested_bytes,
            limit_bytes: 0,
        })) if requested_bytes > 0
    ));
    assert_eq!(warm.execution_summary(), before_invocation);
    assert_eq!(budget.reserved_bytes(), charged);
    budget.set_limit_bytes(LIMIT);
    assert_eq!(
        (warm.run_with_host(&mut ivm::host::DefaultHost::new()))
            .expect("expected successful VM operation"),
        ()
    );
    drop(warm);
    assert_eq!(cache.stats().runtime_hits, 1);
    assert_eq!(cache.stats().dirty_resets, 2);
    cache.with_local(LocalCacheStore::clear_storage);
    drop(summary);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn runtime_slot_borrow_survives_eviction_and_shrink_until_its_actual_final_drop() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let program = contract_program();
    let prepared = cache
        .get_or_prepare(ivm::contract_code_hash(&program), &program)
        .unwrap();
    let prepared_bytes = budget.reserved_bytes();
    let runtime = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    let baseline = runtime.baseline.clone();
    let charged = budget.reserved_bytes();
    let row = row_pointer(runtime.backing.as_ref().unwrap());
    cache.with_store(|store| store.clear_storage());
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(row_pointer(runtime.backing.as_ref().unwrap()), row);
    assert!(runtime.backing.as_ref().unwrap().belongs_to(&budget));
    drop(runtime);
    let only_baseline = budget.reserved_bytes();
    assert!(only_baseline > prepared_bytes);
    assert!(only_baseline + row_layout().size() < charged);
    assert_eq!(cache.stats().runtime_dirty_resets, 0);
    drop(cache);
    assert_eq!(budget.reserved_bytes(), only_baseline);
    drop(baseline);
    assert_eq!(budget.reserved_bytes(), prepared_bytes);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);

    for generic in [false, true] {
        let budget = AllocationBudget::new(LIMIT);
        let mut cache = local_cache(&budget, 1);
        let program = if generic {
            generic_program()
        } else {
            contract_program()
        };
        let contract = if generic {
            None
        } else {
            Some(cache.summarize_program(&program).unwrap())
        };
        let generic_summary = if generic {
            Some(cache.summarize_generic_program(&program).unwrap())
        } else {
            None
        };
        let summary_bytes = budget.reserved_bytes();
        let local = Arc::clone(&cache.local);
        let shared = cache.prepared_contract_cache();
        let runtime = if let Some(summary) = &contract {
            cache
                .checkout_runtime(summary, &program, GAS, HEAP)
                .unwrap()
        } else {
            cache
                .checkout_generic_runtime(generic_summary.as_ref().unwrap(), GAS, HEAP)
                .unwrap()
        };
        let baseline = runtime.baseline.clone();
        let charged = budget.reserved_bytes();
        let row = row_pointer(runtime.backing.as_ref().unwrap());
        super::super::with_cache_store(&local, &budget, |store| store.clear_storage());
        shared.with_store(|store| store.clear_storage());
        budget.set_limit_bytes(0);
        assert_eq!(budget.reserved_bytes(), charged);
        assert_eq!(row_pointer(runtime.backing.as_ref().unwrap()), row);
        assert!(runtime.backing.as_ref().unwrap().belongs_to(&budget));
        drop(runtime);
        let only_baseline = budget.reserved_bytes();
        assert!(only_baseline > summary_bytes);
        assert!(only_baseline + row_layout().size() < charged);
        assert_eq!(cache.stats().dirty_resets, 0);
        assert!(local.lock().runtime_templates.is_empty());
        drop((cache, shared, local));
        assert_eq!(budget.reserved_bytes(), only_baseline);
        drop(baseline);
        assert_eq!(budget.reserved_bytes(), summary_bytes);
        drop((contract, generic_summary));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn overlapping_nested_slot_returns_keep_one_real_runtime_baseline_pair() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let program = contract_program();
    let prepared = cache
        .get_or_prepare(ivm::contract_code_hash(&program), &program)
        .unwrap();
    let prepared_bytes = budget.reserved_bytes();
    let mut first = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    let first_charge = budget.reserved_bytes();
    let first_row = row_pointer(first.backing.as_ref().unwrap());
    let first_image = first.memory.load_region(0, 1).unwrap().as_ptr();
    let first_root = first.memory.root();
    let mut second = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    let second_row = row_pointer(second.backing.as_ref().unwrap());
    let second_image = second.memory.load_region(0, 1).unwrap().as_ptr();
    assert_ne!(first_row, second_row);
    assert_ne!(first_image, second_image);
    assert!(budget.reserved_bytes() > first_charge + row_layout().size());
    first.set_register(7, 17);
    second.set_register(7, 23);
    first.memory.preload_input(0, &[0x17]).unwrap();
    second.memory.preload_input(0, &[0x23]).unwrap();
    drop(first);
    assert_eq!(cache.stats().runtime_dirty_resets, 1);
    drop(second);
    assert_eq!(cache.stats().runtime_dirty_resets, 1);
    assert_eq!(budget.reserved_bytes(), first_charge);
    let key = RuntimeKey::new(prepared.code_hash(), stack_limit_for_gas(GAS), HEAP);
    assert_eq!(
        cache.with_store(|store| store.nested_runtimes[&key].available.len()),
        1
    );
    let mut warm = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    assert_eq!(row_pointer(warm.backing.as_ref().unwrap()), first_row);
    assert_eq!(warm.memory.load_region(0, 1).unwrap().as_ptr(), first_image);
    assert_eq!(warm.memory.root(), first_root);
    assert_eq!(warm.register(7), 0);
    assert_eq!(warm.memory.heap_max_limit(), HEAP);
    assert_eq!(warm.remaining_gas(), GAS);
    drop(warm);
    cache.with_store(|store| store.clear_storage());
    assert_eq!(budget.reserved_bytes(), prepared_bytes);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn runtime_slot_shortage_declines_optional_retention_without_changing_completed_execution() {
    let _retention = retention();
    // One canonical generic ADDI followed by HALT supplies both success and a
    // completed typed OutOfGas control, without introducing a new opcode/profile.
    let mut program = ivm::ProgramMetadata {
        max_cycles: GAS,
        ..Default::default()
    }
    .encode();
    program.extend_from_slice(
        &ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 7, 0, 23)
            .to_le_bytes(),
    );
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    for fault in [false, true] {
        let budget = AllocationBudget::new(LIMIT);
        let mut cache = local_cache(&budget, 1);
        let summary = cache.summarize_generic_program(&program).unwrap();
        let summary_bytes = budget.reserved_bytes();
        // Measure only the original mandatory VM/template owners with the same
        // canonical preparation and geometry, before optional row admission.
        let mut measured = ivm::IVM::try_new_with_memory_budget(GAS, &budget).unwrap();
        measured.set_zk_trace_enabled(false);
        measured.memory.set_heap_max_limit(HEAP).unwrap();
        measured.load_program(summary.program()).unwrap();
        measured.set_gas_limit(GAS);
        let baseline = measured.try_runtime_template().unwrap();
        let mandatory = budget.reserved_bytes();
        drop((measured, baseline));
        assert_eq!(budget.reserved_bytes(), summary_bytes);
        budget.set_limit_bytes(mandatory);
        let mut declined = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
        assert!(declined.backing.is_none());
        assert_eq!(budget.reserved_bytes(), mandatory);
        // The artificial checkout shortage proved that only the optional row
        // was declined. Restore the original pool limit for independently
        // funded invocation work before comparing actual guest behavior.
        budget.set_limit_bytes(LIMIT);
        if fault {
            declined.set_gas_limit(0);
        }
        let declined_result = declined.run_with_host(&mut ivm::host::DefaultHost::new());
        let declined_gas = declined.remaining_gas();
        let declined_pc = declined.pc();
        let declined_register = declined.register(7);
        let declined_register_root = declined.register_root();
        let declined_memory_root = declined.memory.root();
        if fault {
            assert!(matches!(
                (&(declined_result), &(ivm::VMError::OutOfGas)),
                (Err(ivm::VMError::OutOfGas), ivm::VMError::OutOfGas)
            ));
            assert_eq!(declined_register, 0);
        } else {
            assert_eq!(
                (*declined_result
                    .as_ref()
                    .expect("expected successful VM operation")),
                ()
            );
            assert_eq!(declined_register, 23);
        }
        drop(declined);
        assert_eq!(budget.reserved_bytes(), summary_bytes);
        assert_eq!(cache.stats().dirty_resets, 0);
        assert!(cache.with_local(|local| {
            local
                .runtime_templates
                .values()
                .all(|pool| pool.available.is_empty())
        }));
        budget.set_limit_bytes(LIMIT);
        let mut admitted = cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap();
        assert!(admitted.backing.as_ref().unwrap().belongs_to(&budget));
        assert_eq!(budget.reserved_bytes(), mandatory + row_layout().size());
        if fault {
            admitted.set_gas_limit(0);
        }
        let admitted_result = admitted.run_with_host(&mut ivm::host::DefaultHost::new());
        assert!(
            matches!(
                (&admitted_result, &declined_result),
                (Ok(()), Ok(())) | (Err(ivm::VMError::OutOfGas), Err(ivm::VMError::OutOfGas))
            ),
            "optional cache admission changed execution: {admitted_result:?} != {declined_result:?}"
        );
        assert_eq!(admitted.remaining_gas(), declined_gas);
        assert_eq!(admitted.pc(), declined_pc);
        assert_eq!(admitted.register(7), declined_register);
        assert_eq!(admitted.register_root(), declined_register_root);
        assert_eq!(admitted.memory.root(), declined_memory_root);
        drop(admitted);
        assert_eq!(cache.stats().runtime_misses, 2);
        assert_eq!(cache.stats().runtime_hits, 0);
        assert_eq!(cache.stats().dirty_resets, 1);
        cache.with_local(LocalCacheStore::clear_storage);
        drop(summary);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn zero_retention_and_zero_capacity_do_not_allocate_runtime_row_slots() {
    for (capacity, max_bytes) in [(0, usize::MAX), (4, 0)] {
        let _retention = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
            capacity,
            max_bytes,
            max_decoded_ops: 0,
        });
        for route in 0..3 {
            let budget = AllocationBudget::new(LIMIT);
            let cache_capacity = usize::from(capacity != 0);
            if route == 0 {
                let cache =
                    PreparedContractCache::with_execution_budget(cache_capacity, budget.clone());
                let program = contract_program();
                let prepared = cache
                    .get_or_prepare(ivm::contract_code_hash(&program), &program)
                    .unwrap();
                let (mut runtime, row_requested) = refuse_one_layout_during(row_layout(), || {
                    cache.checkout_runtime(&prepared, GAS, HEAP).unwrap()
                });
                assert!(!row_requested);
                assert!(runtime.backing.is_none());
                assert!(budget.reserved_bytes() > program.len());
                assert_eq!(
                    (runtime.run_with_host(&mut ivm::host::DefaultHost::new()))
                        .expect("expected successful VM operation"),
                    ()
                );
                drop(runtime);
                assert_eq!(cache.stats().runtime_dirty_resets, 0);
                assert!(cache.with_store(|store| {
                    store
                        .nested_runtimes
                        .values()
                        .all(|pool| pool.available.is_empty())
                }));
                cache.with_store(|store| store.clear_storage());
                drop(prepared);
            } else {
                let mut cache = local_cache(&budget, cache_capacity);
                if route == 1 {
                    let program = contract_program();
                    let summary = cache.summarize_program(&program).unwrap();
                    let (mut runtime, row_requested) =
                        refuse_one_layout_during(row_layout(), || {
                            cache
                                .checkout_runtime(&summary, &program, GAS, HEAP)
                                .unwrap()
                        });
                    assert!(!row_requested);
                    assert!(runtime.backing.is_none());
                    assert_eq!(
                        (runtime.run_with_host(&mut ivm::host::DefaultHost::new()))
                            .expect("expected successful VM operation"),
                        ()
                    );
                    drop(runtime);
                    cache
                        .prepared_contracts
                        .with_store(|store| store.clear_storage());
                    drop(summary);
                } else {
                    let summary = cache.summarize_generic_program(&generic_program()).unwrap();
                    let (mut runtime, row_requested) =
                        refuse_one_layout_during(row_layout(), || {
                            cache.checkout_generic_runtime(&summary, GAS, HEAP).unwrap()
                        });
                    assert!(!row_requested);
                    assert!(runtime.backing.is_none());
                    assert_eq!(
                        (runtime.run_with_host(&mut ivm::host::DefaultHost::new()))
                            .expect("expected successful VM operation"),
                        ()
                    );
                    drop(runtime);
                    drop(summary);
                }
                assert_eq!(cache.stats().dirty_resets, 0);
                assert!(cache.with_local(|local| {
                    local
                        .runtime_templates
                        .values()
                        .all(|pool| pool.available.is_empty())
                }));
                cache.with_local(LocalCacheStore::clear_storage);
            }
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

struct ReenterSlots {
    shared: PreparedContractCache,
    local: Arc<Mutex<LocalCacheStore>>,
    outer: Arc<Mutex<IvmCache>>,
    calls: AtomicUsize,
    locked: AtomicBool,
    reentered: AtomicUsize,
}

impl Wake for ReenterSlots {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Some(guard) = self.shared.inner.try_lock() else {
            self.locked.store(true, Ordering::SeqCst);
            return;
        };
        drop(guard);
        let Some(guard) = self.local.try_lock() else {
            self.locked.store(true, Ordering::SeqCst);
            return;
        };
        drop(guard);
        let Some(guard) = self.outer.try_lock() else {
            self.locked.store(true, Ordering::SeqCst);
            return;
        };
        drop(guard);
        std::hint::black_box(self.shared.stats());
        self.reentered.fetch_add(1, Ordering::SeqCst);
    }
}

fn observe_row_release<'a>(
    budget: &AllocationBudget,
    registration: &'a mut iroha_allocation::release::ReleaseRegistration,
    observer: &Arc<ReenterSlots>,
) -> ReleaseFuture<'a> {
    let AllocationRefusal::Capacity { release, .. } = budget
        .try_reserve_bytes(row_layout().size() + 1)
        .unwrap_err()
    else {
        panic!("the actual row occupies this original release observation");
    };
    let mut wait = release.wait_for_release(registration);
    let waker = Waker::from(Arc::clone(observer));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    wait
}

#[test]
fn runtime_slot_refunds_wait_for_shared_local_outer_guards_and_unwind() {
    let _retention = retention();
    for unwind in [false, true] {
        let row_bytes = row_layout().size();
        let registration_bytes =
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
        let budget = AllocationBudget::new(2 * row_bytes + registration_bytes);
        let cache = local_cache(&budget, 1);
        let shared = cache.prepared_contract_cache();
        let local = Arc::clone(&cache.local);
        let outer = Arc::new(Mutex::new(cache));
        let backing = IdleRuntimeBacking::try_new(&budget).unwrap();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        assert_eq!(budget.reserved_bytes(), row_bytes + registration_bytes);
        let observer = Arc::new(ReenterSlots {
            shared: shared.clone(),
            local,
            outer: Arc::clone(&outer),
            calls: AtomicUsize::new(0),
            locked: AtomicBool::new(false),
            reentered: AtomicUsize::new(0),
        });
        let mut wait = observe_row_release(&budget, &mut registration, &observer);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            IvmCache::with_locked(&outer, |cache| {
                // Physical construction occurs outside both internal stores. Its
                // partial split still participates in the real enclosing cache scope.
                let (refused, requested) =
                    refuse_one_layout_during(row_layout(), || IdleRuntimeBacking::try_new(&budget));
                assert!(requested);
                assert!(matches!(
                    refused,
                    Err(ivm::VMError::ExecutionDeferred(
                        ivm::error::ExecutionDeferral::AllocationUnavailable
                    ))
                ));
                assert_eq!(budget.reserved_bytes(), row_bytes + registration_bytes);
                assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
                cache.with_local(|_| {
                    shared.with_store(|_| {
                        drop(backing);
                        assert_eq!(budget.reserved_bytes(), registration_bytes);
                        assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
                        assert!(!unwind, "original runtime slot unwind");
                    })
                });
            });
        }));
        assert_eq!(result.is_err(), unwind);
        if unwind {
            assert_eq!(
                result.unwrap_err().downcast_ref::<&str>(),
                Some(&"original runtime slot unwind")
            );
        }
        assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer.reentered.load(Ordering::SeqCst), 1);
        assert!(!observer.locked.load(Ordering::SeqCst));
        let waker = Waker::from(Arc::clone(&observer));
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
        );
        assert_eq!(budget.reserved_bytes(), registration_bytes);
        drop((wait, observer));
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn runtime_slot_rejects_foreign_equal_limit_pool_without_refresh_or_guest_effects() {
    let _retention = retention();
    let budget = AllocationBudget::new(LIMIT);
    let foreign = AllocationBudget::new(LIMIT);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let program = contract_program();
    let prepared = cache
        .get_or_prepare(ivm::contract_code_hash(&program), &program)
        .unwrap();
    let prepared_bytes = budget.reserved_bytes();
    let mut runtime = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    let original = runtime.backing.take().unwrap();
    let row = row_pointer(&original);
    let mut accepted_clone = false;
    let mut accepted_foreign = true;
    assert_eq!(
        allocations_during(|| {
            accepted_clone = original.belongs_to(&budget.clone());
            accepted_foreign = original.belongs_to(&foreign);
        }),
        0
    );
    assert!(accepted_clone);
    assert!(!accepted_foreign);
    assert_eq!(budget.limit_bytes(), foreign.limit_bytes());
    let foreign_backing = IdleRuntimeBacking::try_new(&foreign).unwrap();
    assert_eq!(foreign.reserved_bytes(), row_layout().size());
    runtime.backing = Some(foreign_backing);
    assert_eq!(
        (runtime.run_with_host(&mut ivm::host::DefaultHost::new()))
            .expect("expected successful VM operation"),
        ()
    );
    assert_eq!(runtime.register(7), 0);
    let completed_gas = runtime.remaining_gas();
    let completed_root = runtime.memory.root();
    drop(runtime);
    assert_eq!(cache.stats().runtime_dirty_resets, 0);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(
        budget.reserved_bytes(),
        prepared_bytes + row_layout().size()
    );
    assert_eq!(row_pointer(&original), row);
    assert!(original.belongs_to(&budget));
    assert!(cache.with_store(|store| {
        store
            .nested_runtimes
            .values()
            .all(|pool| pool.available.is_empty())
    }));
    let mut retry = cache.checkout_runtime(&prepared, GAS, HEAP).unwrap();
    assert!(retry.backing.as_ref().unwrap().belongs_to(&budget));
    assert_eq!(
        (retry.run_with_host(&mut ivm::host::DefaultHost::new()))
            .expect("expected successful VM operation"),
        ()
    );
    assert_eq!(retry.remaining_gas(), completed_gas);
    assert_eq!(retry.memory.root(), completed_root);
    drop(retry);
    assert_eq!(cache.stats().runtime_misses, 2);
    assert_eq!(cache.stats().runtime_hits, 0);
    assert_eq!(cache.stats().runtime_dirty_resets, 1);
    cache.with_store(|store| store.clear_storage());
    assert_eq!(
        budget.reserved_bytes(),
        prepared_bytes + row_layout().size()
    );
    drop(original);
    assert_eq!(budget.reserved_bytes(), prepared_bytes);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
}
