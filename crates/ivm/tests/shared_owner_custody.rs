//! Observe actual shared-cache backing deallocation before reservation refunds.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
};

use ivm::cache_memory::{SharedAllocation, SharedValue, memory_stats};

#[path = "shared_owner_custody/diagnostics.rs"]
mod diagnostics;
#[path = "shared_owner_custody/read_log.rs"]
mod read_log;
#[path = "shared_owner_custody/register_paths.rs"]
mod register_paths;

struct ObservedAllocator;

// These observers count real write-log requests and inspect its actual backing
// before/after deallocation. Only the test thread enables request observation.
static LOG_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static LOG_FIRST_POINTER: AtomicUsize = AtomicUsize::new(0);
static LOG_ROW_POINTER: AtomicUsize = AtomicUsize::new(0);
static LOG_PAYLOAD_POINTER: AtomicUsize = AtomicUsize::new(0);
static LOG_CAPTURE_PAYLOAD: AtomicBool = AtomicBool::new(false);
static LOG_PAYLOAD_BYTES: AtomicUsize = AtomicUsize::new(0);
static LOG_ROW_CREDIT_AT_FREE: AtomicUsize = AtomicUsize::new(0);
static LOG_ROW_RETENTION_AT_FREE: AtomicUsize = AtomicUsize::new(0);
static LOG_PAYLOAD_CREDIT_AT_FREE: AtomicUsize = AtomicUsize::new(0);
static LOG_PAYLOAD_RETENTION_AT_FREE: AtomicUsize = AtomicUsize::new(0);
static LOG_PAYLOAD_SCRUBBED: AtomicBool = AtomicBool::new(false);
static LOG_BUDGET: std::sync::OnceLock<iroha_allocation::AllocationBudget> =
    std::sync::OnceLock::new();

thread_local! {
    static LOG_OBSERVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LOG_FAIL: std::cell::Cell<Option<(usize, usize)>> = const { std::cell::Cell::new(None) };
}

struct ObserveLog;
impl Drop for ObserveLog {
    fn drop(&mut self) {
        LOG_OBSERVE.set(false);
        LOG_FAIL.set(None);
        LOG_CAPTURE_PAYLOAD.store(false, SeqCst);
        LOG_ROW_POINTER.store(0, SeqCst);
        LOG_PAYLOAD_POINTER.store(0, SeqCst);
    }
}

fn observe_log_requests() {
    LOG_REQUESTS.store(0, SeqCst);
    LOG_FIRST_POINTER.store(0, SeqCst);
    LOG_OBSERVE.set(true);
}

fn stop_log_requests() -> usize {
    LOG_OBSERVE.set(false);
    LOG_REQUESTS.load(SeqCst)
}

// Observe the actual allocator request for the canonical memory-node geometry.
// Other layouts (telemetry, Rayon and proof output) are deliberately separate.
static NODE_LAYOUT_BYTES: AtomicUsize = AtomicUsize::new(0);
static COMPACT_NODE_LAYOUT_BYTES: AtomicUsize = AtomicUsize::new(0);
static NODE_ALLOCS: AtomicUsize = AtomicUsize::new(0);
static LAST_NODE_POINTER: AtomicUsize = AtomicUsize::new(0);
static TRACKED_NODE: AtomicUsize = AtomicUsize::new(0);
static NODE_RESIDENT_AT_FREE: AtomicUsize = AtomicUsize::new(0);
static NODE_ORIGINAL_CREDIT_AT_FREE: AtomicUsize = AtomicUsize::new(0);
static NODE_BUDGET: std::sync::OnceLock<iroha_allocation::AllocationBudget> =
    std::sync::OnceLock::new();

struct ObserveNodes;
impl Drop for ObserveNodes {
    fn drop(&mut self) {
        NODE_LAYOUT_BYTES.store(0, SeqCst);
        COMPACT_NODE_LAYOUT_BYTES.store(0, SeqCst);
        TRACKED_NODE.store(0, SeqCst);
    }
}

thread_local! {
    static OBSERVE_NEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OBSERVE_LAST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

static SERIAL: Mutex<()> = Mutex::new(());
static POINTER: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicBool = AtomicBool::new(false);
static CHECK_DEALLOC: AtomicBool = AtomicBool::new(true);
static RESIDENT_AFTER_FREE: AtomicUsize = AtomicUsize::new(0);
static OWNER_LAST_BYTES: AtomicUsize = AtomicUsize::new(0);
static OWNER_PREVIOUS_BYTES: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if read_log::refuse_allocation(layout) {
            return std::ptr::null_mut();
        }
        let observe = OBSERVE_NEXT
            .try_with(|observe| observe.replace(false))
            .unwrap_or(false)
            || OBSERVE_LAST
                .try_with(|observe| observe.get())
                .unwrap_or(false);
        let observe_log = LOG_OBSERVE.try_with(std::cell::Cell::get).unwrap_or(false);
        if observe_log {
            LOG_REQUESTS.fetch_add(1, SeqCst);
            let refuse = LOG_FAIL
                .try_with(|failure| match failure.get() {
                    Some((size, 0)) if size == layout.size() => {
                        failure.set(None);
                        true
                    }
                    Some((size, left)) if size == layout.size() => {
                        failure.set(Some((size, left - 1)));
                        false
                    }
                    _ => false,
                })
                .unwrap_or(false);
            if refuse {
                return std::ptr::null_mut();
            }
        }
        // SAFETY: forward the exact request to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        read_log::allocated(pointer);
        if observe_log && !pointer.is_null() {
            let _ = LOG_FIRST_POINTER.compare_exchange(0, pointer as usize, SeqCst, SeqCst);
            if layout.size() == LOG_PAYLOAD_BYTES.load(SeqCst)
                && LOG_CAPTURE_PAYLOAD.swap(false, SeqCst)
            {
                LOG_PAYLOAD_POINTER.store(pointer as usize, SeqCst);
            }
        }
        if !pointer.is_null()
            && (NODE_LAYOUT_BYTES.load(SeqCst) == layout.size()
                || COMPACT_NODE_LAYOUT_BYTES.load(SeqCst) == layout.size())
        {
            NODE_ALLOCS.fetch_add(1, SeqCst);
            LAST_NODE_POINTER.store(pointer as usize, SeqCst);
        }
        if observe {
            if OBSERVE_LAST.try_with(std::cell::Cell::get).unwrap_or(false) {
                let previous = OWNER_LAST_BYTES.swap(layout.size(), SeqCst);
                OWNER_PREVIOUS_BYTES.store(previous, SeqCst);
            }
            POINTER.store(pointer as usize, SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observed = POINTER
            .compare_exchange(pointer as usize, 0, SeqCst, SeqCst)
            .is_ok();
        let log_payload = LOG_PAYLOAD_POINTER
            .compare_exchange(pointer as usize, 0, SeqCst, SeqCst)
            .is_ok();
        let log_row = LOG_ROW_POINTER
            .compare_exchange(pointer as usize, 0, SeqCst, SeqCst)
            .is_ok();
        if log_payload {
            // SAFETY: the observer names this still-live initialized byte buffer
            // and checks it before forwarding its original layout for deallocation.
            let bytes =
                unsafe { std::slice::from_raw_parts(pointer, LOG_PAYLOAD_BYTES.load(SeqCst)) };
            LOG_PAYLOAD_SCRUBBED.store(bytes.iter().all(|byte| *byte == 0), SeqCst);
        }
        // SAFETY: the caller supplies the original pointer and its layout.
        unsafe { System.dealloc(pointer, layout) };
        read_log::deallocated(pointer);
        if log_payload || log_row {
            let credit = LOG_BUDGET
                .get()
                .expect("log observer initialized")
                .reserved_bytes();
            let retained = memory_stats().measured_resident_bytes();
            if log_payload {
                LOG_PAYLOAD_CREDIT_AT_FREE.store(credit, SeqCst);
                LOG_PAYLOAD_RETENTION_AT_FREE.store(retained, SeqCst);
            }
            if log_row {
                LOG_ROW_CREDIT_AT_FREE.store(credit, SeqCst);
                LOG_ROW_RETENTION_AT_FREE.store(retained, SeqCst);
            }
        }
        if TRACKED_NODE
            .compare_exchange(pointer as usize, 0, SeqCst, SeqCst)
            .is_ok()
        {
            NODE_RESIDENT_AT_FREE.store(memory_stats().measured_resident_bytes(), SeqCst);
            NODE_ORIGINAL_CREDIT_AT_FREE.store(
                NODE_BUDGET
                    .get()
                    .expect("node observer initialized")
                    .reserved_bytes(),
                SeqCst,
            );
        }
        if observed && CHECK_DEALLOC.load(SeqCst) {
            RESIDENT_AFTER_FREE.store(memory_stats().measured_resident_bytes(), SeqCst);
            FREED.store(true, SeqCst);
        }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn observe_next_owner() -> usize {
    // Initialize the process accounting owner before observing the payload Arc.
    let baseline = memory_stats().measured_resident_bytes();
    BASELINE.store(baseline, SeqCst);
    POINTER.store(0, SeqCst);
    FREED.store(false, SeqCst);
    RESIDENT_AFTER_FREE.store(0, SeqCst);
    DROPS.store(0, SeqCst);
    CHECK_DEALLOC.store(true, SeqCst);
    OBSERVE_LAST.with(|observe| observe.set(false));
    OBSERVE_NEXT.with(|observe| observe.set(true));
    baseline
}

struct PayloadProbe;

impl Drop for PayloadProbe {
    fn drop(&mut self) {
        assert!(
            FREED.load(SeqCst),
            "payload dropped before Arc deallocation"
        );
        assert!(memory_stats().measured_resident_bytes() > BASELINE.load(SeqCst));
        DROPS.fetch_add(1, SeqCst);
    }
}

#[test]
fn shared_value_frees_arc_before_payload_and_metadata_refund() {
    let _serial = SERIAL.lock().unwrap();
    let baseline = observe_next_owner();
    let owner = SharedValue::new(PayloadProbe, Some(0));
    assert_ne!(POINTER.load(SeqCst), 0);
    let resident = memory_stats().measured_resident_bytes();
    let borrower = owner.clone();
    assert!(SharedValue::ptr_eq(&owner, &borrower));
    drop(owner);
    assert!(!FREED.load(SeqCst));
    assert_eq!(memory_stats().measured_resident_bytes(), resident);
    drop(borrower);
    assert_eq!(RESIDENT_AFTER_FREE.load(SeqCst), resident);
    assert_eq!(DROPS.load(SeqCst), 1);
    assert_eq!(memory_stats().measured_resident_bytes(), baseline);
}

#[test]
fn shared_slice_frees_arc_before_final_cache_charge_refund() {
    let _serial = SERIAL.lock().unwrap();
    let empty: Box<[u8]> = Box::default();
    let baseline = observe_next_owner();
    let owner = SharedAllocation::from_boxed(empty);
    assert_ne!(POINTER.load(SeqCst), 0);
    assert!(owner.try_retain());
    let cache = owner.cache_clone();
    let borrower = owner.clone();
    let resident = memory_stats().measured_resident_bytes();
    drop(owner);
    drop(cache);
    assert!(!FREED.load(SeqCst));
    assert_eq!(memory_stats().measured_resident_bytes(), resident);
    drop(borrower);
    assert!(FREED.load(SeqCst));
    assert_eq!(RESIDENT_AFTER_FREE.load(SeqCst), resident);
    assert_eq!(memory_stats().measured_resident_bytes(), baseline);
}

#[test]
fn concurrent_final_value_owners_deallocate_before_single_payload_drop() {
    let _serial = SERIAL.lock().unwrap();
    let baseline = observe_next_owner();
    let owner = SharedValue::new(PayloadProbe, Some(0));
    let resident = memory_stats().measured_resident_bytes();
    let barrier = Barrier::new(9);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let borrower = owner.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(borrower);
            });
        }
        drop(owner);
        barrier.wait();
    });
    assert!(FREED.load(SeqCst));
    assert_eq!(RESIDENT_AFTER_FREE.load(SeqCst), resident);
    assert_eq!(DROPS.load(SeqCst), 1);
    assert_eq!(memory_stats().measured_resident_bytes(), baseline);
}

#[test]
fn runtime_template_frees_prepaid_owner_before_refunding_final_borrower() {
    let _serial = SERIAL.lock().unwrap();
    let budget = iroha_allocation::AllocationBudget::new(512 * 1024 * 1024);
    let mut vm = ivm::IVM::try_new_with_memory_budget(50_000, &budget).unwrap();
    let original_bytes = budget.reserved_bytes();
    assert!(original_bytes > 0);
    observe_next_owner();
    OBSERVE_NEXT.with(|observe| observe.set(false));
    OBSERVE_LAST.with(|observe| observe.set(true));
    CHECK_DEALLOC.store(false, SeqCst);
    OWNER_LAST_BYTES.store(0, SeqCst);
    OWNER_PREVIOUS_BYTES.store(0, SeqCst);
    // Private copies are followed by the data Arc and then its paired backing
    // Arc. Observe the actual final two request sizes and final backing free.
    let template = vm.try_runtime_template().unwrap();
    OBSERVE_LAST.with(|observe| observe.set(false));
    assert_ne!(POINTER.load(SeqCst), 0);
    let data_owner_bytes = OWNER_PREVIOUS_BYTES.load(SeqCst);
    let backing_owner_bytes = OWNER_LAST_BYTES.load(SeqCst);
    assert!(data_owner_bytes > 0 && backing_owner_bytes > 0);
    let owner_bytes = data_owner_bytes.checked_add(backing_owner_bytes).unwrap();
    FREED.store(false, SeqCst);
    CHECK_DEALLOC.store(true, SeqCst);
    assert!(budget.reserved_bytes() > original_bytes);
    let borrower = template.clone();
    vm.reset_from_runtime_template(&borrower).unwrap();
    drop(vm);
    budget.set_limit_bytes(0);
    let resident = memory_stats().measured_resident_bytes();
    let charged = budget.reserved_bytes();
    assert!(charged > 0);
    drop(template);
    assert!(!FREED.load(SeqCst));
    assert_eq!(budget.reserved_bytes(), charged);
    drop(borrower);
    assert!(FREED.load(SeqCst));
    let after = memory_stats().measured_resident_bytes();
    assert_eq!(
        RESIDENT_AFTER_FREE.load(SeqCst),
        after + owner_bytes,
        "both exact shared-control charges outlive final backing deallocation",
    );
    assert!(
        resident > after + owner_bytes,
        "the earlier private payloads were also resident"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn canonical_memory_node_backing_is_prepaid_and_never_reallocated_by_commit_or_reset() {
    let _serial = SERIAL.lock().unwrap();
    // This allocator census covers the VM and template's canonical CPU node
    // owners. Automatic GPU calibration owns two separately funded synthetic
    // trees with this same layout; its original process custody is exercised by
    // the required physical rehash tests, not counted as VM reallocation here.
    struct RestoreAcceleration(ivm::AccelerationConfig);
    impl Drop for RestoreAcceleration {
        fn drop(&mut self) {
            ivm::set_acceleration_config(self.0);
        }
    }
    let restore = RestoreAcceleration(ivm::acceleration_config());
    ivm::set_acceleration_config(ivm::AccelerationConfig {
        enable_metal: false,
        enable_cuda: false,
        ..restore.0
    });
    let gas = 257;
    let stack = ivm::IvmStackPolicy::V1.stack_limit_for_gas(gas);
    let image_bytes =
        usize::try_from(ivm::Memory::STACK_START + stack + ivm::Memory::STACK_SLOP).unwrap();
    let leaf_count = image_bytes.div_ceil(32);
    let node_bytes =
        iroha_crypto::MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(leaf_count)
            .unwrap();
    let memory_bytes = image_bytes + leaf_count * 32 + node_bytes + 2 * leaf_count.div_ceil(64) * 8;
    NODE_ALLOCS.store(0, SeqCst);
    NODE_LAYOUT_BYTES.store(node_bytes, SeqCst);
    // Also catch a forbidden clone allocating only the initialized ragged BFS
    // prefix, rather than the retained fixed capacity declared by Crypto.
    let node_width = std::mem::size_of::<Option<iroha_crypto::HashOf<[u8; 32]>>>();
    COMPACT_NODE_LAYOUT_BYTES.store(
        node_bytes / 2 - node_width + leaf_count * node_width,
        SeqCst,
    );
    let _observe = ObserveNodes;
    let refused = iroha_allocation::AllocationBudget::new(memory_bytes - 1);
    assert!(ivm::IVM::try_new_with_memory_budget(gas, &refused).is_err());
    assert_eq!(refused.reserved_bytes(), 0);
    assert_eq!(
        NODE_ALLOCS.load(SeqCst),
        0,
        "root demand refused before node allocation"
    );

    let budget = iroha_allocation::AllocationBudget::new(256 * 1024 * 1024);
    NODE_BUDGET
        .set(budget.clone())
        .expect("one node observer test");
    let mut vm = ivm::IVM::try_new_with_memory_budget(gas, &budget).unwrap();
    assert_eq!(NODE_ALLOCS.load(SeqCst), 1);
    // Code and heap together exceed half this fixed image: force the dense path.
    let code = vec![0x42; ivm::Memory::HEAP_START as usize];
    let heap = vec![0x5a; ivm::Memory::HEAP_SIZE as usize];
    vm.memory.load_code(&code).unwrap();
    vm.memory
        .store_bytes(ivm::Memory::HEAP_START, &heap)
        .unwrap();
    vm.memory.commit();
    assert_eq!(
        NODE_ALLOCS.load(SeqCst),
        1,
        "dense commit must reuse node storage"
    );
    let template_root = vm.memory.current_root();
    let template = vm.try_runtime_template().unwrap();
    assert_eq!(
        NODE_ALLOCS.load(SeqCst),
        2,
        "one independently funded template node array"
    );
    let template_node_pointer = LAST_NODE_POINTER.load(SeqCst);
    assert_ne!(template_node_pointer, 0);
    budget.set_limit_bytes(0);
    assert!(matches!(
        vm.memory.store_u8(ivm::Memory::HEAP_START, 0xa5),
        Err(ivm::VMError::AllocationDeferred(_))
    ));
    // Only the one-byte write payload needs new credit; the existing log row,
    // bitmaps, leaves and canonical nodes already own their backing.
    budget.set_limit_bytes(budget.reserved_bytes() + 1);
    vm.memory.store_u8(ivm::Memory::HEAP_START, 0xa5).unwrap();
    budget.set_limit_bytes(0);
    vm.memory.commit();
    assert_ne!(vm.memory.current_root(), template_root);
    assert_eq!(
        NODE_ALLOCS.load(SeqCst),
        2,
        "sparse commit must reuse node storage"
    );
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(vm.memory.current_root(), template_root);
    // Memory's known root can bypass a tree refresh after reset; requesting a
    // proof must actually rebuild the retained canonical nodes as well.
    let (restored_root, _) = vm
        .memory
        .merkle_root_and_path(ivm::Memory::HEAP_START)
        .unwrap();
    assert_eq!(restored_root, template_root);
    assert_eq!(
        NODE_ALLOCS.load(SeqCst),
        2,
        "template reset and canonical proof refresh must reuse node storage"
    );
    let borrower = template.clone();
    drop(vm);
    let retained = budget.reserved_bytes();
    assert!(retained >= node_bytes);
    TRACKED_NODE.store(template_node_pointer, SeqCst);
    drop(template);
    assert_eq!(TRACKED_NODE.load(SeqCst), template_node_pointer);
    assert_eq!(budget.reserved_bytes(), retained);
    drop(borrower);
    assert_eq!(
        TRACKED_NODE.load(SeqCst),
        0,
        "final borrower frees the observed node array"
    );
    assert!(
        NODE_RESIDENT_AT_FREE.load(SeqCst) >= node_bytes,
        "retention charge must survive actual deallocation"
    );
    assert!(
        NODE_ORIGINAL_CREDIT_AT_FREE.load(SeqCst) >= node_bytes,
        "original execution charge must survive actual deallocation"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn write_log_backing_reserves_before_allocation_and_frees_before_final_credit_refund() {
    let _serial = SERIAL.lock().unwrap();
    let _observation = ObserveLog;
    const PAYLOAD: usize = 17;
    let row = std::mem::size_of::<ivm::WriteLogEntry>();
    let budget = iroha_allocation::AllocationBudget::new(256 * 1024 * 1024);
    LOG_BUDGET
        .set(budget.clone())
        .expect("one log allocator observer");
    LOG_PAYLOAD_BYTES.store(PAYLOAD, SeqCst);
    let mut vm = ivm::IVM::try_new_with_memory_budget(257, &budget).unwrap();
    // Own probe-read capacity before observing exact write-row/payload requests.
    assert!(matches!(vm.memory.load_u8(ivm::Memory::STACK_START), Ok(0)));
    let base = budget.reserved_bytes();
    let gas = vm.remaining_gas();
    budget.set_limit_bytes(base + 4 * row + PAYLOAD - 1);
    observe_log_requests();
    let refused = vm
        .memory
        .store_bytes(ivm::Memory::STACK_START, &[0xa5; PAYLOAD]);
    assert_eq!(
        stop_log_requests(),
        0,
        "admission precedes actual backing allocation"
    );
    assert!(matches!(refused, Err(ivm::VMError::AllocationDeferred(_))));
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(budget.reserved_bytes(), base);
    assert!(matches!(vm.memory.load_u8(ivm::Memory::STACK_START), Ok(0)));

    budget.set_limit_bytes(base + 4 * row + 4 * PAYLOAD);
    observe_log_requests();
    for index in 0..4 {
        vm.memory
            .store_bytes(ivm::Memory::STACK_START + index * 32, &[0xa5; PAYLOAD])
            .unwrap();
    }
    assert_eq!(
        stop_log_requests(),
        5,
        "one row array and four exact payloads"
    );
    let original_rows = LOG_FIRST_POINTER.load(SeqCst);
    assert_ne!(original_rows, 0);
    LOG_ROW_POINTER.store(original_rows, SeqCst);
    let occupied = budget.reserved_bytes();
    budget.set_limit_bytes(occupied + 8 * row + PAYLOAD);

    // The replacement rows physically allocate, then the exact payload request
    // fails. Existing row storage, guest bytes and original charge stay intact.
    LOG_FAIL.set(Some((PAYLOAD, 0)));
    observe_log_requests();
    let refused = vm
        .memory
        .store_bytes(ivm::Memory::STACK_START + 4 * 32, &[0x5a; PAYLOAD]);
    assert_eq!(stop_log_requests(), 2);
    assert!(matches!(refused, Err(ivm::VMError::ExecutionDeferred(_))));
    assert_eq!(LOG_ROW_POINTER.load(SeqCst), original_rows);
    assert_eq!(budget.reserved_bytes(), occupied);
    assert!(matches!(
        vm.memory.load_u8(ivm::Memory::STACK_START + 4 * 32),
        Ok(0)
    ));

    observe_log_requests();
    vm.memory
        .store_bytes(ivm::Memory::STACK_START + 4 * 32, &[0x5a; PAYLOAD])
        .unwrap();
    assert_eq!(stop_log_requests(), 2);
    assert_eq!(LOG_ROW_POINTER.load(SeqCst), 0);
    assert_eq!(
        LOG_ROW_CREDIT_AT_FREE.load(SeqCst),
        occupied + 8 * row + PAYLOAD
    );
    assert!(LOG_ROW_RETENTION_AT_FREE.load(SeqCst) >= 12 * row + 5 * PAYLOAD);
    assert_eq!(budget.reserved_bytes(), base + 8 * row + 5 * PAYLOAD);

    let occupied = budget.reserved_bytes();
    let copy_bytes = 5 * row + 5 * PAYLOAD;
    budget.set_limit_bytes(occupied + copy_bytes);
    LOG_CAPTURE_PAYLOAD.store(true, SeqCst);
    LOG_PAYLOAD_SCRUBBED.store(false, SeqCst);
    LOG_FAIL.set(Some((PAYLOAD, 1)));
    observe_log_requests();
    let refused = vm.memory.try_write_log_snapshot();
    assert_eq!(
        stop_log_requests(),
        3,
        "rows, one payload, then allocator refusal"
    );
    assert!(matches!(refused, Err(ivm::VMError::ExecutionDeferred(_))));
    assert_eq!(LOG_PAYLOAD_POINTER.load(SeqCst), 0);
    assert!(
        LOG_PAYLOAD_SCRUBBED.load(SeqCst),
        "partially copied secret bytes scrub before free"
    );
    assert!(LOG_PAYLOAD_CREDIT_AT_FREE.load(SeqCst) >= PAYLOAD);
    assert_eq!(budget.reserved_bytes(), occupied);

    observe_log_requests();
    let snapshot = vm.memory.try_write_log_snapshot().unwrap();
    assert_eq!(
        stop_log_requests(),
        6,
        "one exact row array and five independent payloads"
    );
    let snapshot_rows = LOG_FIRST_POINTER.load(SeqCst);
    assert_eq!(snapshot.len(), 5);
    assert_eq!(snapshot[0].bytes(), &[0xa5; PAYLOAD]);
    assert_eq!(snapshot[4].bytes(), &[0x5a; PAYLOAD]);
    assert_eq!(budget.reserved_bytes(), occupied + copy_bytes);
    observe_log_requests();
    let refused = snapshot.try_clone();
    assert_eq!(
        stop_log_requests(),
        0,
        "independent clone cannot bypass original finite pool"
    );
    assert!(matches!(refused, Err(ivm::VMError::AllocationDeferred(_))));

    LOG_ROW_POINTER.store(snapshot_rows, SeqCst);
    LOG_PAYLOAD_POINTER.store(snapshot[0].bytes().as_ptr() as usize, SeqCst);
    LOG_PAYLOAD_SCRUBBED.store(false, SeqCst);
    let owner = std::sync::Arc::new(snapshot);
    let borrower = std::sync::Arc::clone(&owner);
    drop(vm);
    assert_eq!(budget.reserved_bytes(), copy_bytes);
    budget.set_limit_bytes(0);
    drop(owner);
    assert_eq!(LOG_ROW_POINTER.load(SeqCst), snapshot_rows);
    assert_eq!(budget.reserved_bytes(), copy_bytes);
    drop(borrower);
    assert_eq!(LOG_ROW_POINTER.load(SeqCst), 0);
    assert_eq!(LOG_PAYLOAD_POINTER.load(SeqCst), 0);
    assert!(LOG_PAYLOAD_SCRUBBED.load(SeqCst));
    assert_eq!(LOG_ROW_CREDIT_AT_FREE.load(SeqCst), 5 * row);
    assert!(LOG_ROW_RETENTION_AT_FREE.load(SeqCst) >= 5 * row);
    assert!(LOG_PAYLOAD_CREDIT_AT_FREE.load(SeqCst) >= PAYLOAD);
    assert!(LOG_PAYLOAD_RETENTION_AT_FREE.load(SeqCst) >= PAYLOAD);
    assert_eq!(budget.reserved_bytes(), 0);
}
