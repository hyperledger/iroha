//! Observe the actual allocator/weighted-pool boundary, rather than a payload's Drop order.
//!
//! Only this unit-test module installs the System-forwarding allocator. Its thread-local fixed
//! records capture the original query constructor's allocations; hooks never allocate, panic,
//! wake a waiter, or dereference freed backing. Other test threads use System directly.
#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    ptr,
};

use crate::{
    AdmittedFanoutPermit, ByteWeightedMemoryPool, QueryFanoutMemoryEnvelope,
    QueryFanoutMemoryReservation, history_producer::HistoryProducerOwner,
};

const WORKING: usize = 48 * 1024 * 1024;
const MAX_ORIGINAL_ALLOCATIONS: usize = 32;

#[derive(Clone, Copy)]
struct OriginalAllocation {
    pointer: usize,
    layout: Layout,
    freed: bool,
}

#[derive(Clone, Copy)]
struct Observation {
    // The pool and this borrowed Semaphore stay alive until after disarming observation.
    semaphore: *const tokio::sync::Semaphore,
    available_before_release: usize,
    original: [OriginalAllocation; MAX_ORIGINAL_ALLOCATIONS],
    length: usize,
    capturing: bool,
    refuse_layout: Option<Layout>,
    refused: usize,
    bad_order: bool,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

struct QueryAllocator;

#[global_allocator]
static ALLOCATOR: QueryAllocator = QueryAllocator;

// SAFETY: every ordinary operation delegates its exact original pointer/Layout to System.
// The fixed observation lives on the current test thread and borrows only the retained pool.
unsafe impl GlobalAlloc for QueryAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut refuse = false;
        let _ = OBSERVATION.try_with(|cell| {
            if let Some(mut observation) = cell.get() {
                if observation.capturing && observation.refuse_layout == Some(layout) {
                    observation.refused += 1;
                    observation.capturing = false;
                    refuse = true;
                    cell.set(Some(observation));
                }
            }
        });
        if refuse {
            return ptr::null_mut();
        }
        // SAFETY: the caller supplied GlobalAlloc's original nonzero layout.
        let allocation = unsafe { System.alloc(layout) };
        let _ = OBSERVATION.try_with(|cell| {
            if let Some(mut observation) = cell.get() {
                if observation.capturing && !allocation.is_null() {
                    if observation.length == MAX_ORIGINAL_ALLOCATIONS {
                        observation.bad_order = true;
                    } else {
                        observation.original[observation.length] = OriginalAllocation {
                            pointer: allocation as usize,
                            layout,
                            freed: false,
                        };
                        observation.length += 1;
                    }
                    cell.set(Some(observation));
                }
            }
        });
        allocation
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let mut retained_original = false;
        let _ = OBSERVATION.try_with(|cell| {
            if let Some(mut observation) = cell.get() {
                for entry in &observation.original[..observation.length] {
                    if !entry.freed && entry.pointer == pointer as usize {
                        retained_original = true;
                        // SAFETY: start() borrows this Semaphore until finish() clears TLS;
                        // available_permits is an allocation-free atomic observation.
                        let available = unsafe { &*observation.semaphore }.available_permits();
                        observation.bad_order |= entry.layout != layout
                            || available != observation.available_before_release;
                        break;
                    }
                }
                cell.set(Some(observation));
            }
        });
        // SAFETY: this is the exact pointer/Layout allocated by System above.
        unsafe { System.dealloc(pointer, layout) };
        if retained_original {
            let _ = OBSERVATION.try_with(|cell| {
                if let Some(mut observation) = cell.get() {
                    // Observe after the native free as well: query capacity must remain
                    // unavailable throughout physical reclamation, even for the final control.
                    let available = unsafe { &*observation.semaphore }.available_permits();
                    observation.bad_order |= available != observation.available_before_release;
                    for entry in &mut observation.original[..observation.length] {
                        if !entry.freed && entry.pointer == pointer as usize {
                            entry.freed = true;
                            break;
                        }
                    }
                    cell.set(Some(observation));
                }
            });
        }
    }
}

struct ObservedQuery<'pool> {
    pool: &'pool ByteWeightedMemoryPool,
}
impl<'pool> ObservedQuery<'pool> {
    fn start(pool: &'pool ByteWeightedMemoryPool, refuse_layout: Option<Layout>) -> Self {
        OBSERVATION.with(|cell| {
            assert!(cell.get().is_none());
            cell.set(Some(Observation {
                semaphore: std::sync::Arc::as_ptr(&pool.semaphore),
                available_before_release: pool.available_permits(),
                original: [OriginalAllocation {
                    pointer: 0,
                    layout: Layout::new::<u8>(),
                    freed: false,
                }; MAX_ORIGINAL_ALLOCATIONS],
                length: 0,
                capturing: true,
                refuse_layout,
                refused: 0,
                bad_order: false,
            }));
        });
        Self { pool }
    }

    #[expect(
        clippy::unused_self,
        reason = "the borrowed guard keeps allocation observation alive while construction completes"
    )]
    fn constructed(&self) {
        OBSERVATION.with(|cell| {
            let mut observation = cell.get().unwrap();
            observation.capturing = false;
            cell.set(Some(observation));
        });
    }

    fn finish(self) -> Observation {
        let observation = OBSERVATION.with(|cell| cell.take().unwrap());
        assert!(std::ptr::eq(
            observation.semaphore,
            std::sync::Arc::as_ptr(&self.pool.semaphore)
        ));
        observation
    }
}

impl Drop for ObservedQuery<'_> {
    fn drop(&mut self) {
        // Panic paths must not leave a borrowed pool pointer installed in the allocator.
        let _ = OBSERVATION.try_with(|cell| cell.set(None));
    }
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn construct(
    pool: &ByteWeightedMemoryPool,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<QueryFanoutMemoryReservation, axum::response::Response> {
    QueryFanoutMemoryReservation::from_admitted_fanout(
        permit,
        QueryFanoutMemoryEnvelope::for_body_admission(WORKING).unwrap(),
        pool.generation(),
    )
}

fn assert_physically_reclaimed(observation: &Observation) {
    assert!(observation.length > 0);
    assert!(!observation.bad_order);
    assert!(
        observation.original[..observation.length]
            .iter()
            .all(|entry| entry.freed)
    );
}

#[test]
fn query_memory_reclamation_frees_all_original_controls_before_pool_credit() {
    let pool = ByteWeightedMemoryPool::new(WORKING).unwrap();
    let permit = pool.try_acquire_parts([WORKING as u64]).unwrap();
    let observation = ObservedQuery::start(&pool, None);
    let memory = construct(&pool, permit).unwrap();
    observation.constructed();
    let owner = HistoryProducerOwner::from_reservation(&memory).unwrap();
    let last = owner.clone();
    drop(memory);
    drop(owner);
    assert_eq!(pool.available_bytes(), 0);
    drop(last);
    assert_physically_reclaimed(&observation.finish());
    assert_eq!(pool.available_bytes(), WORKING as u64);
}

#[test]
fn query_memory_reclamation_cancellation_releases_only_the_last_native_owner() {
    let pool = ByteWeightedMemoryPool::new(WORKING).unwrap();
    let permit = pool.try_acquire_parts([WORKING as u64]).unwrap();
    let observation = ObservedQuery::start(&pool, None);
    let memory = construct(&pool, permit).unwrap();
    observation.constructed();
    let worker = HistoryProducerOwner::from_reservation(&memory).unwrap();
    let retained = worker.clone();
    let cancelled = async move {
        std::future::pending::<()>().await;
        drop(worker);
    };
    drop(memory);
    drop(cancelled);
    assert_eq!(pool.available_bytes(), 0);
    drop(retained);
    assert_physically_reclaimed(&observation.finish());
    assert_eq!(pool.available_bytes(), WORKING as u64);
}

#[test]
fn query_memory_reclamation_native_control_refusal_reclaims_partial_constructor_first() {
    let layout = AdmittedFanoutPermit::layout();
    // Refuse the actual permit allocation, after funding the genuine producer/counters.
    // These assertions prevent a layout collision from turning this into an earlier refusal.
    assert_ne!(
        layout,
        norito::core::DecodeBudgetContext::allocation_layout()
    );
    assert_ne!(
        layout,
        iroha_allocation::ChargedShared::<crate::history_producer::ProducerBudget>::allocation_layout()
    );
    let pool = ByteWeightedMemoryPool::new(WORKING).unwrap();
    let permit = pool.try_acquire_parts([WORKING as u64]).unwrap();
    let observation = ObservedQuery::start(&pool, Some(layout));
    let response = construct(&pool, permit).err().unwrap();
    observation.constructed();
    let observation = observation.finish();
    assert_eq!(observation.refused, 1);
    assert_physically_reclaimed(&observation);
    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(pool.available_bytes(), WORKING as u64);
}
