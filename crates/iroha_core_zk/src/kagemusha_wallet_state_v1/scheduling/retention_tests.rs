//! Ownership of the volatile retention slot (D6b): a released attempt parks its value under
//! its own identity, only that attempt's durable checkpoint publication promotes it, a new
//! attempt evicts a pending value, and payment priority, inactivity and close invalidate it.
//! The values are plain markers; no proof runs. The four overlap regressions of the C12
//! countersign are the `f1_*` and `f2_*` tests.

use std::sync::{Weak, atomic::Ordering};

use super::*;

/// A slot value whose release is recorded. With `unlocked`, its release also asserts that the
/// scheduler's state lock is free, so retained memory is never released under that lock.
struct Marker {
    id: u32,
    unlocked: Option<Weak<Inner>>,
    dropped: Arc<Mutex<Vec<u32>>>,
}
impl Drop for Marker {
    fn drop(&mut self) {
        if let Some(inner) = self.unlocked.as_ref().and_then(Weak::upgrade) {
            assert!(
                inner.state.try_lock().is_ok(),
                "retained memory is released after the state lock"
            );
        }
        self.dropped.lock().unwrap().push(self.id);
    }
}

struct Fixture {
    scheduler: Scheduler,
    dropped: Arc<Mutex<Vec<u32>>>,
}
impl Fixture {
    fn new() -> Self {
        let scheduler = Scheduler::new();
        scheduler.set_activity(true, false);
        Self {
            scheduler,
            dropped: Arc::default(),
        }
    }
    /// A marker that checks the state lock when it is released on this test's only thread.
    fn marker(&self, id: u32) -> Option<FoldRetentionV1> {
        Some(FoldRetentionV1::new(Marker {
            id,
            unlocked: Some(Arc::downgrade(&self.scheduler.0)),
            dropped: Arc::clone(&self.dropped),
        }))
    }
    fn dropped(&self) -> Vec<u32> {
        self.dropped.lock().unwrap().clone()
    }
    /// One attempt's locked prepare and released proof: it takes the slot and parks `id`.
    fn released(&self, id: u32) -> (Option<u32>, FoldPublicationV1) {
        let attempt = self.scheduler.start().expect("an attempt may start");
        let resumed = attempt
            .take_retained()
            .and_then(FoldRetentionV1::downcast::<Marker>)
            .map(|marker| marker.id);
        let (_, publication) = attempt.release(self.marker(id));
        (resumed, publication)
    }
    /// The marker a new attempt's locked prepare resumes, if any.
    fn resumed(&self) -> Option<u32> {
        let attempt = self.scheduler.start().expect("an attempt may start");
        attempt
            .take_retained()
            .and_then(FoldRetentionV1::downcast::<Marker>)
            .map(|marker| marker.id)
    }
    fn holds(&self) -> bool {
        self.scheduler.holds_retained_for_test()
    }
}

const CHECKPOINT: Result<FoldStatus, &Error> = Ok(FoldStatus::Checkpoint {
    sequence: 0,
    ordinal: 0,
});

#[test]
fn a_released_value_waits_for_its_own_publication_and_only_a_checkpoint_promotes_it() {
    let f = Fixture::new();
    let (resumed, publication) = f.released(1);
    assert_eq!(resumed, None, "the first attempt runs cold");
    assert!(f.holds(), "parked as the background slot is released");
    publication.settle(CHECKPOINT);
    assert_eq!(
        f.resumed(),
        Some(1),
        "the next attempt resumes the promoted value"
    );
    assert!(!f.holds(), "a taken value leaves the slot empty");

    let cancelled = Error::Cancelled;
    let refused = Error::Pending;
    for result in [
        Ok(FoldStatus::Folded(0)),
        Err(&cancelled),
        Err(&refused),
        Ok(FoldStatus::CaughtUp),
    ] {
        let (_, publication) = f.released(2);
        publication.settle(result);
        assert!(!f.holds(), "{result:?} keeps nothing");
    }
    assert_eq!(f.dropped(), [1, 2, 2, 2, 2]);
}

#[test]
fn a_new_attempt_evicts_a_pending_value_and_runs_cold() {
    let f = Fixture::new();
    let (_, first) = f.released(1);
    // A second attempt starts before the first one's publication settled.
    assert_eq!(f.resumed(), None, "a pending value is never resumed");
    assert_eq!(f.dropped(), [1], "it is evicted");
    first.settle(CHECKPOINT);
    assert!(!f.holds(), "an evicted value is never recreated");
}

#[test]
fn f2_publishes_before_f1_and_f1_neither_clears_nor_replaces_it() {
    let f = Fixture::new();
    let cancelled = Error::Cancelled;
    for late in [Err(&cancelled), CHECKPOINT] {
        let (_, stale) = f.released(1);
        // F2 starts after F1 released, evicts F1's pending value and publishes first.
        let (resumed, newer) = f.released(2);
        assert_eq!(resumed, None);
        newer.settle(CHECKPOINT);
        // F1's late publication (discarded, or even accepted) settles only its own value,
        // which is gone: F2's promoted value survives and nothing of F1 reappears.
        stale.settle(late);
        assert_eq!(f.resumed(), Some(2), "{late:?}");
        assert!(!f.holds());
    }
    assert_eq!(f.dropped(), [1, 2, 1, 2]);
}

#[test]
fn f1_payment_between_release_and_publication_prevents_its_retention() {
    let f = Fixture::new();
    let (_, stale) = f.released(1);
    assert!(f.holds());
    // A payment begins and ends between F1's release and its publication.
    let payment = f.scheduler.payment();
    assert!(!f.holds(), "payment takes the parked value");
    assert_eq!(f.dropped(), [1], "and releases it before its guard returns");
    drop(payment);
    // No payment holds priority any more, yet F1's successful publication retains nothing.
    stale.settle(CHECKPOINT);
    assert!(!f.holds(), "the overlapped turn is never resurrected");
    assert_eq!(f.resumed(), None);
}

#[test]
fn f2_retains_after_that_payment_before_f1_cleanup() {
    let f = Fixture::new();
    let cancelled = Error::Cancelled;
    // F2 published before F1's cleanup.
    let (_, stale) = f.released(1);
    drop(f.scheduler.payment());
    let (resumed, newer) = f.released(2);
    assert_eq!(resumed, None, "the payment left the slot empty");
    newer.settle(CHECKPOINT);
    stale.settle(Err(&cancelled));
    assert_eq!(f.resumed(), Some(2), "F1's cleanup keeps F2's retention");
    // F2 still pending at F1's cleanup.
    let (_, stale) = f.released(3);
    drop(f.scheduler.payment());
    let (_, newer) = f.released(4);
    stale.settle(CHECKPOINT);
    assert!(f.holds(), "F1's settlement leaves F2's pending value");
    newer.settle(CHECKPOINT);
    assert_eq!(f.resumed(), Some(4));
    assert_eq!(f.dropped(), [1, 2, 3, 4]);
}

#[test]
fn f1_abandoned_or_custody_refused_publication_drops_only_its_own_value() {
    let f = Fixture::new();
    let refused = Error::Pending;
    // Abandoned: the host drops the proved job unpublished, for example after a custody
    // refusal or a closed owner.
    let (_, stale) = f.released(1);
    drop(stale);
    assert!(!f.holds());
    assert_eq!(f.dropped(), [1]);
    // Refused by the publication itself.
    let (_, stale) = f.released(2);
    stale.settle(Err(&refused));
    assert!(!f.holds());
    // Abandoned or refused after a newer attempt retained: the newer value survives.
    for abandon in [true, false] {
        let (_, stale) = f.released(3);
        let (_, newer) = f.released(4);
        newer.settle(CHECKPOINT);
        if abandon {
            drop(stale);
        } else {
            stale.settle(Err(&refused));
        }
        assert_eq!(f.resumed(), Some(4));
    }
    assert_eq!(f.dropped(), [1, 2, 3, 4, 3, 4]);
}

#[test]
fn a_payment_joining_the_proof_never_runs_beside_its_value() {
    let f = Fixture::new();
    let attempt = f.scheduler.start().unwrap();
    assert!(attempt.take_retained().is_none());
    let payer = f.scheduler.clone();
    let dropped = Arc::clone(&f.dropped);
    let joined = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let returned = Arc::clone(&joined);
    let payment = std::thread::spawn(move || {
        let guard = payer.payment();
        returned.store(true, Ordering::SeqCst);
        let seen = dropped.lock().unwrap().clone();
        drop(guard);
        seen
    });
    while attempt.token.check().is_ok() {
        std::thread::yield_now();
    }
    assert!(
        !joined.load(Ordering::SeqCst),
        "the payment waits for the slot"
    );
    // The proof finished as the payment signalled: its value is not parked, and it is
    // released before the slot, so the payment proceeds without it. Another thread may hold
    // the state lock here, so this marker does not check it.
    let value = FoldRetentionV1::new(Marker {
        id: 1,
        unlocked: None,
        dropped: Arc::clone(&f.dropped),
    });
    let (_, publication) = attempt.release(Some(value));
    assert_eq!(payment.join().unwrap(), [1]);
    publication.settle(CHECKPOINT);
    assert!(!f.holds());
}

#[test]
fn inactivity_and_close_drop_the_slot_and_an_ingest_leaves_it() {
    let f = Fixture::new();
    let (_, publication) = f.released(1);
    publication.settle(CHECKPOINT);
    f.scheduler.ingest();
    f.scheduler.set_activity(false, true);
    assert!(f.holds(), "an ingest and a still eligible activity keep it");
    f.scheduler.set_activity(false, false);
    assert!(!f.holds(), "leaving both states drops it");
    assert_eq!(f.dropped(), [1]);

    f.scheduler.set_activity(true, false);
    let (_, publication) = f.released(2);
    f.scheduler.set_activity(false, false);
    f.scheduler.set_activity(true, false);
    publication.settle(CHECKPOINT);
    assert!(
        !f.holds(),
        "inactivity during the publication window prevents retention"
    );

    let (_, publication) = f.released(3);
    publication.settle(CHECKPOINT);
    f.scheduler.close();
    assert!(!f.holds(), "close drops it");
    assert!(f.scheduler.start().is_none());
    assert_eq!(f.dropped(), [1, 2, 3]);
}

#[test]
fn no_attempt_starts_or_takes_retention_while_a_payment_holds_priority() {
    let f = Fixture::new();
    let (_, publication) = f.released(1);
    publication.settle(CHECKPOINT);
    let payment = f.scheduler.payment();
    assert!(!f.holds());
    assert!(f.scheduler.start().is_none());
    drop(payment);
    assert_eq!(f.resumed(), None);
    assert_eq!(f.dropped(), [1]);
}

#[test]
fn a_foreign_slot_value_is_absent_to_its_reader() {
    let value = FoldRetentionV1::new(7_u64);
    assert!(value.downcast::<Marker>().is_none(), "never panics");
    assert_eq!(FoldRetentionV1::new(7_u64).downcast::<u64>(), Some(7));
}

/// The test hook of the genuine fold flows edits only a ready value, in place: an empty slot
/// and a pending value are declined, and nothing is released under the state lock.
#[test]
fn the_ready_value_test_hook_edits_only_a_ready_value_in_place() {
    let f = Fixture::new();
    let renumber = |value: &mut FoldRetentionV1| {
        let Some(marker) = value.downcast_mut::<Marker>() else {
            return false;
        };
        marker.id += 10;
        true
    };
    assert!(
        !f.scheduler.change_ready_for_test(renumber),
        "an empty slot"
    );
    let (_, publication) = f.released(1);
    assert!(
        !f.scheduler.change_ready_for_test(renumber),
        "a pending value"
    );
    publication.settle(CHECKPOINT);
    assert!(f.scheduler.change_ready_for_test(renumber));
    assert!(
        !f.scheduler.change_ready_for_test(|_| false),
        "a declined edit"
    );
    assert_eq!(f.resumed(), Some(11));
    assert_eq!(f.dropped(), [11]);
}
