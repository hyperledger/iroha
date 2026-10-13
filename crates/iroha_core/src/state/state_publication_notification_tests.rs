//! Original State publication notification must follow the actual writer release.

use super::*;
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

struct ProbeStateWriter {
    state: Arc<State>,
    calls: AtomicUsize,
    free: AtomicUsize,
    busy: AtomicUsize,
    odd: AtomicUsize,
    unavailable: AtomicUsize,
    cleanup: Mutex<Option<iroha_allocation::release::DeferredRelease>>,
}

impl Wake for ProbeStateWriter {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.odd.fetch_add(
            usize::from(!self.state.state_view_generation().is_multiple_of(2)),
            Ordering::SeqCst,
        );
        let Ok(mut cleanup) = self.cleanup.try_lock() else {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        };
        if cleanup.is_some() {
            self.unavailable.fetch_add(1, Ordering::SeqCst);
            return;
        }
        match self.state.state_write_lock.try_lock() {
            Some(guard) => {
                self.free.fetch_add(1, Ordering::SeqCst);
                *cleanup = Some(guard.release_deferred());
            }
            None => {
                self.busy.fetch_add(1, Ordering::SeqCst);
            }
        }
        // No blocking, assertions, callback cleanup or reconstructed State.
    }
}

#[test]
fn lane_manifest_publication_notifies_after_its_original_state_writer_unlocks() {
    let state = Arc::new(State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    ));
    let before = state.state_view_generation();
    let callback = Arc::new(ProbeStateWriter {
        state: Arc::clone(&state),
        calls: AtomicUsize::new(0),
        free: AtomicUsize::new(0),
        busy: AtomicUsize::new(0),
        odd: AtomicUsize::new(0),
        unavailable: AtomicUsize::new(0),
        cleanup: Mutex::new(None),
    });
    let waker = Waker::from(Arc::clone(&callback));
    let mut waiter = std::pin::pin!(state.publication_notify.notified());
    assert!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(callback.calls.load(Ordering::SeqCst), 0);

    // The actual public operation takes the original State writer and publishes
    // both projections. The test never manually releases its generation guard.
    state.install_lane_manifests_for_testing(&Arc::new(
        crate::governance::manifest::LaneManifestRegistry::empty(),
    ));

    assert!(
        waiter
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    drop(callback.cleanup.lock().unwrap().take());
    assert_eq!(state.state_view_generation(), before + 2);
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(callback.unavailable.load(Ordering::SeqCst), 0);
    assert_eq!(callback.odd.load(Ordering::SeqCst), 0);
    assert_eq!(callback.free.load(Ordering::SeqCst), 1);
    assert_eq!(callback.busy.load(Ordering::SeqCst), 0);
}
