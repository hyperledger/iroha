//! Capture retains trigger releases until original sibling writers are unlocked.

use super::*;
use crate::state::World;
use mv::{PublicationCleanup, PublicationPreparationError};
use std::{
    future::Future,
    pin::Pin,
    sync::Mutex,
    task::{Context, Wake, Waker},
};

struct ActiveCaptureProbe {
    journal: Option<DetachedStorage<TriggerId, (), ()>>,
    cleanup: Option<PublicationCleanup<()>>,
}
struct ProbeActiveOnCapturedIds {
    set: Arc<Set>,
    original: Mutex<ActiveCaptureProbe>,
    calls: AtomicUsize,
    admitted: AtomicUsize,
    acquired: AtomicUsize,
    busy: AtomicUsize,
    other: AtomicUsize,
}
impl Wake for ProbeActiveOnCapturedIds {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Ok(mut probe) = self.original.try_lock() else {
            self.other.fetch_add(1, Ordering::SeqCst);
            return;
        };
        if probe.cleanup.is_some() {
            self.other.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let Some(journal) = probe.journal.take() else {
            self.other.fetch_add(1, Ordering::SeqCst);
            return;
        };
        match journal.try_prepare_publication(&self.set.active_data_trigger_ids, |_, _| {
            self.admitted.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        }) {
            Ok(prepared) => {
                self.acquired.fetch_add(1, Ordering::SeqCst);
                let (journal, cleanup) = prepared.abort();
                probe.journal = Some(journal);
                probe.cleanup = Some(cleanup);
            }
            Err((journal, error, cleanup)) => {
                if matches!(error, PublicationPreparationError::Busy(_)) {
                    self.busy.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.other.fetch_add(1, Ordering::SeqCst);
                }
                probe.journal = Some(journal);
                probe.cleanup = Some(cleanup);
            }
        }
    }
}

fn standalone_capture(replacement: bool, borrowed_extraction: bool) {
    let waiter_budget = iroha_allocation::AllocationBudget::new(
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&waiter_budget);
    let set = seeded_set();
    let before = images(&set);
    let ids = set.ids.block().try_detach(|_| Ok::<_, ()>(())).unwrap();
    let active = set
        .active_data_trigger_ids
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let mut original = if replacement {
        set.block_and_revert()
    } else {
        set.block()
    };
    let admission_calls = AtomicUsize::new(0);
    let (ids, error, refused) = ids
        .try_prepare_publication(&set.ids, |_, _| {
            admission_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        })
        .err()
        .expect("the actual Set holds its original ids writer");
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    let PublicationPreparationError::Busy(observation) = error else {
        panic!("expected original physical ids contention");
    };
    let callback = Arc::new(ProbeActiveOnCapturedIds {
        set: Arc::clone(&set),
        original: Mutex::new(ActiveCaptureProbe {
            journal: Some(active),
            cleanup: None,
        }),
        calls: AtomicUsize::new(0),
        admitted: AtomicUsize::new(0),
        acquired: AtomicUsize::new(0),
        busy: AtomicUsize::new(0),
        other: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&callback));
    let mut context = Context::from_waker(&waker);
    let mut released = observation.wait_for_release(&mut registration);
    assert!(Pin::new(&mut released).poll(&mut context).is_pending());
    // Keep the genuine returned successor through all physical and image checks.
    let captured = if borrowed_extraction {
        let identity = original.ids.publication_identity();
        let mut pending = original.take_capture_slot();
        drop(original);
        assert_eq!(callback.calls.load(Ordering::SeqCst), 0);
        assert!(Pin::new(&mut released).poll(&mut context).is_pending());
        pending
            .try_capture(|original| {
                assert_eq!(original.ids.publication_identity(), identity);
                Ok::<(), ()>(())
            })
            .unwrap();
        let (captured, cleanup) = pending.into_detached();
        assert_eq!(callback.calls.load(Ordering::SeqCst), 0);
        drop(cleanup);
        captured
    } else {
        original.try_detach(|_| Ok::<(), ()>(())).unwrap()
    };
    drop(refused);
    let (active, cleanup) = {
        let mut probe = callback.original.lock().unwrap();
        (probe.journal.take().unwrap(), probe.cleanup.take())
    };
    drop(cleanup);
    assert!(Pin::new(&mut released).poll(&mut context).is_ready());
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(callback.admitted.load(Ordering::SeqCst), 1);
    assert_eq!(callback.acquired.load(Ordering::SeqCst), 1);
    assert_eq!(callback.busy.load(Ordering::SeqCst), 0);
    assert_eq!(callback.other.load(Ordering::SeqCst), 0);
    assert_eq!(
        captured.mode(),
        if replacement {
            mv::BlockMode::Replace
        } else {
            mv::BlockMode::Ordinary
        }
    );
    assert!(captured.matches_current(&set));
    assert!(ids.matches_current(&set.ids));
    assert!(active.matches_current(&set.active_data_trigger_ids));
    assert_eq!(images(&set), before);
    drop((captured, ids, active));
}

#[test]
fn ordinary_trigger_capture_unlocks_active_index_before_ids_notification() {
    standalone_capture(false, false);
}
#[test]
fn replacement_trigger_capture_unlocks_active_index_before_ids_notification() {
    standalone_capture(true, false);
}

#[test]
fn ordinary_trigger_borrowed_extraction_keeps_writers_and_notices_in_original_slot() {
    standalone_capture(false, true);
}
#[test]
fn replacement_trigger_borrowed_extraction_keeps_writers_and_notices_in_original_slot() {
    standalone_capture(true, true);
}

struct LaterWorldProbe {
    journal: Option<mv::cell::Detached<Option<u64>, ()>>,
    cleanup: Option<PublicationCleanup<()>>,
}
struct ProbeLaterWorldOnCapturedIds {
    world: Arc<World>,
    original: Mutex<LaterWorldProbe>,
    calls: AtomicUsize,
    admitted: AtomicUsize,
    acquired: AtomicUsize,
    busy: AtomicUsize,
    other: AtomicUsize,
}
impl Wake for ProbeLaterWorldOnCapturedIds {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Ok(mut probe) = self.original.try_lock() else {
            self.other.fetch_add(1, Ordering::SeqCst);
            return;
        };
        if probe.cleanup.is_some() {
            self.other.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let Some(journal) = probe.journal.take() else {
            self.other.fetch_add(1, Ordering::SeqCst);
            return;
        };
        match journal.try_prepare_publication(&self.world.soradns_last_publish_ms, |_, _| {
            self.admitted.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        }) {
            Ok(prepared) => {
                self.acquired.fetch_add(1, Ordering::SeqCst);
                let (journal, cleanup) = prepared.abort();
                probe.journal = Some(journal);
                probe.cleanup = Some(cleanup);
            }
            Err((journal, error, cleanup)) => {
                if matches!(error, PublicationPreparationError::Busy(_)) {
                    self.busy.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.other.fetch_add(1, Ordering::SeqCst);
                }
                probe.journal = Some(journal);
                probe.cleanup = Some(cleanup);
            }
        }
    }
}

fn nested_world_capture(replacement: bool) {
    let mut world = World::default();
    world.triggers = Arc::try_unwrap(seeded_set()).unwrap_or_else(|_| panic!("unique seeded Set"));
    for value in [10, 20] {
        let mut tip = world.soradns_last_publish_ms.block();
        *tip.get_mut() = Some(value);
        tip.commit();
    }
    let world = Arc::new(world);
    let mut registration = crate::unit_test_support::release_registration(
        &iroha_allocation::AllocationBudget::new(64 * 1024),
    );
    let before = images(&world.triggers);
    let before_later = norito::json::to_json(&world.soradns_last_publish_ms).unwrap();
    let ids = world
        .triggers
        .ids
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let later = world
        .soradns_last_publish_ms
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let original = if replacement {
        world.block_and_revert()
    } else {
        world.block()
    };
    let admission_calls = AtomicUsize::new(0);
    let (ids, error, refused) = ids
        .try_prepare_publication(&world.triggers.ids, |_, _| {
            admission_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        })
        .err()
        .expect("the actual World owns the original trigger ids writer");
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    let PublicationPreparationError::Busy(observation) = error else {
        panic!("expected original ids contention under World");
    };
    let callback = Arc::new(ProbeLaterWorldOnCapturedIds {
        world: Arc::clone(&world),
        original: Mutex::new(LaterWorldProbe {
            journal: Some(later),
            cleanup: None,
        }),
        calls: AtomicUsize::new(0),
        admitted: AtomicUsize::new(0),
        acquired: AtomicUsize::new(0),
        busy: AtomicUsize::new(0),
        other: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&callback));
    let mut context = Context::from_waker(&waker);
    let mut released = observation.wait_for_release(&mut registration);
    assert!(Pin::new(&mut released).poll(&mut context).is_pending());
    // The cfg(test) State helper calls the real restricted capture API and keeps
    // its original DetachedWorld alive while this inspection closure executes.
    crate::state::inspect_trigger_world_capture_for_testing(original, || {
        drop(refused);
        let (later, cleanup) = {
            let mut probe = callback.original.lock().unwrap();
            (probe.journal.take().unwrap(), probe.cleanup.take())
        };
        drop(cleanup);
        assert!(Pin::new(&mut released).poll(&mut context).is_ready());
        assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
        assert_eq!(callback.admitted.load(Ordering::SeqCst), 1);
        assert_eq!(callback.acquired.load(Ordering::SeqCst), 1);
        assert_eq!(callback.busy.load(Ordering::SeqCst), 0);
        assert_eq!(callback.other.load(Ordering::SeqCst), 0);
        assert!(ids.matches_current(&world.triggers.ids));
        assert!(later.matches_current(&world.soradns_last_publish_ms));
        assert_eq!(images(&world.triggers), before);
        assert_eq!(
            norito::json::to_json(&world.soradns_last_publish_ms).unwrap(),
            before_later
        );
        drop((ids, later));
    });
}

#[test]
fn ordinary_nested_world_capture_unlocks_later_cell_before_trigger_ids_notification() {
    nested_world_capture(false);
}
#[test]
fn replacement_nested_world_capture_unlocks_later_cell_before_trigger_ids_notification() {
    nested_world_capture(true);
}
