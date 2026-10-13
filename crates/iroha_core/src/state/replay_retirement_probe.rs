//! Physical original-State probes for the connected historical replay tests.
//!
//! No probe clones state, prepares a successor, clears poison, or dispatches a
//! cleanup notification from within a notification callback.

use super::*;
use iroha_allocation::{
    AllocationRefusal,
    release::{DeferredRelease, ReleaseWait},
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::Wake;

/// One original-source callback and its independent physical observations.
pub(crate) struct ReplayRetirementProbe {
    state: Arc<State>,
    calls: AtomicUsize,
    blocked: AtomicUsize,
    poisoned: AtomicUsize,
    cleanup: Mutex<[Option<DeferredRelease>; 3]>,
}

impl ReplayRetirementProbe {
    /// Validate the actual callback, without accepting stale predecessors or poison as unlock.
    pub(crate) fn assert_released(&self, source: &str) {
        assert_eq!(
            self.calls.load(Ordering::SeqCst),
            1,
            "{source}: original callback"
        );
        assert_eq!(
            self.blocked.load(Ordering::SeqCst),
            0,
            "{source}: physical writers"
        );
        assert_eq!(
            self.poisoned.load(Ordering::SeqCst),
            0,
            "{source}: original poison"
        );
    }
}

impl Wake for ReplayRetirementProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Ok(mut cleanup) = self.cleanup.try_lock() else {
            self.blocked.fetch_add(1, Ordering::SeqCst);
            return;
        };
        // Acquire each fence independently, and retain every resulting notice
        // outside this callback. An earlier Busy cannot skip a later probe.
        let fences = [
            self.state.state_commit_lock.try_lock(),
            self.state.state_write_lock.try_lock(),
            self.state.lane_lifecycle_lock.try_lock(),
        ];
        let fences_free = fences.iter().all(Option::is_some);
        let cells = [
            self.state
                .world
                .parameters
                .probe_original_writers_for_testing(),
            self.state
                .canonical_runtime
                .probe_original_writers_for_testing(),
            self.state
                .native_execution_tip
                .probe_original_writers_for_testing(),
            self.state
                .commit_topology
                .probe_original_writers_for_testing(),
            self.state
                .prev_commit_topology
                .probe_original_writers_for_testing(),
        ];
        let cells_free = cells.iter().flatten().all(|writer| writer.acquired);
        let cells_poisoned = cells.iter().flatten().any(|writer| writer.poisoned);
        let hashes = self
            .state
            .block_hashes
            .map()
            .expect("original native hash owner");
        let hash_writer = hashes.try_acquire_writer();
        let hash_free = hash_writer.is_some();
        let hash_poisoned = hashes.is_poisoned();
        let (membership_logical_free, membership_physical_free, membership_poisoned) =
            self.state.transactions.replay_writer_probe_for_tests();
        let generation_even = self.state.state_view_generation().is_multiple_of(2);
        if !(fences_free
            && cells_free
            && hash_free
            && membership_logical_free
            && membership_physical_free
            && generation_even)
        {
            self.blocked.fetch_add(1, Ordering::SeqCst);
        }
        if cells_poisoned || hash_poisoned || membership_poisoned {
            self.poisoned.fetch_add(1, Ordering::SeqCst);
        }
        drop(hash_writer);
        for (slot, guard) in cleanup.iter_mut().zip(fences) {
            // Each prepaid registration calls this probe only once. Keep its
            // physical release notices until the fixture cancels all observers.
            if slot.is_some() {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            }
            *slot = guard.map(|guard| guard.release_deferred());
        }
    }
}

impl State {
    /// Observe the actual three occupied pools and two retained reader sources.
    /// Failed full-capacity admission does not consume the free headroom needed
    /// by publication, and no artificial pressure allocation is dropped to wake it.
    pub(crate) fn replay_retirement_sources_for_test(&self) -> [ReleaseWait; 5] {
        let pools = [
            self.ivm_execution_budget(),
            self.transactions.budget.clone(),
            self.block_hashes.budget.clone(),
        ];
        let [execution, membership, hashes] = pools.map(|pool| {
            let AllocationRefusal::Capacity { release, .. } =
                pool.try_reserve_bytes(pool.limit_bytes()).unwrap_err()
            else {
                panic!("actual replay owner occupies its original pool");
            };
            release
        });
        assert_ne!(execution, membership);
        assert_ne!(execution, hashes);
        assert_ne!(membership, hashes);
        [
            execution,
            membership,
            hashes,
            self.transactions.reader_release_wait_for_tests(),
            self.block_hashes.map().unwrap().observe_reader_release(),
        ]
    }

    /// Bind a callback to the same State whose original operation owns publication.
    pub(crate) fn replay_retirement_probe_for_test(self: &Arc<Self>) -> Arc<ReplayRetirementProbe> {
        Arc::new(ReplayRetirementProbe {
            state: Arc::clone(self),
            calls: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
            poisoned: AtomicUsize::new(0),
            cleanup: Mutex::new(std::array::from_fn(|_| None)),
        })
    }
}
