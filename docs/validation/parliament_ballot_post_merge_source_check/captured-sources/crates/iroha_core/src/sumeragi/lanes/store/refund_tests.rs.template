//! Original signed lane operations release funded owners after all enclosing store guards.

use super::{
    tests::{alternative, open, schedule},
    *,
};
use crate::sumeragi::lanes::record::tests::fixture;
use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
use std::{
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

struct StoreRefundProbe {
    store: Weak<FileLaneBlockStore>,
    calls: AtomicUsize,
    state_free: AtomicBool,
    batch_free: AtomicBool,
    reentered: AtomicBool,
}
impl Wake for StoreRefundProbe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let store = self.store.upgrade().unwrap();
        let state = store.state.try_lock();
        let state_free = state.is_some();
        drop(state);
        let batch = store.batch_read.try_lock();
        let batch_free = batch.is_some();
        drop(batch);
        self.state_free.store(state_free, Ordering::SeqCst);
        self.batch_free.store(batch_free, Ordering::SeqCst);
        // Incorrect lifetimes fail below; callbacks never wait on the defective guard.
        if state_free && batch_free {
            assert_eq!(store.height(), 1);
            self.reentered.store(true, Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Copy)]
enum StoreCompletion {
    Body,
    Batch,
    Entry,
    AuthenticatedHeight,
    NewAppend,
    RepeatedAppend,
    RejectedAppend,
}

fn original_store_refund_control(completion: StoreCompletion) {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let store = Arc::new(open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    ));
    if !matches!(completion, StoreCompletion::NewAppend) {
        store.append(&body, &qc).unwrap();
    }
    let initial = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let retained = budget.reserved_bytes();
    if matches!(completion, StoreCompletion::AuthenticatedHeight) {
        let raw =
            usize::try_from(fs::metadata(store.dir.join(frame_name(1))).unwrap().len()).unwrap();
        budget.set_limit_bytes(retained + raw);
        assert_eq!(
            store.committed_body(1).unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(budget.reserved_bytes(), retained + raw);
        assert!(store.state.lock().read.as_ref().unwrap().ready.is_none());
        budget.set_limit_bytes(original_limit);
    }
    let AllocationRefusal::Capacity { release, .. } =
        budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
    else {
        panic!("the same signed lane operation owns this capacity refusal");
    };
    let probe = Arc::new(StoreRefundProbe {
        store: Arc::downgrade(&store),
        calls: AtomicUsize::new(0),
        state_free: AtomicBool::new(false),
        batch_free: AtomicBool::new(false),
        reentered: AtomicBool::new(false),
    });
    let waker = Waker::from(probe.clone());
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    match completion {
        StoreCompletion::Body => {
            let (restored, certificate) = store.committed_body(1).unwrap().unwrap();
            assert_eq!(restored, body);
            assert_eq!(certificate, qc);
            assert!(restored.admitted_to(&budget));
        }
        StoreCompletion::Batch => {
            let restored = store.committed_batch(1).unwrap().unwrap();
            assert_eq!(restored.block_hash, qc.block_hash);
            assert_eq!(restored.result, qc.result);
            assert!(
                restored.batch.is_none(),
                "the signed arbitrary fixture payload remains an invalid batch"
            );
        }
        StoreCompletion::Entry => {
            let entry = store.entry(1).unwrap().unwrap();
            assert_eq!(entry.manifest.header, *body.header());
            assert_eq!(entry.commit_qc, qc);
        }
        StoreCompletion::AuthenticatedHeight => {
            assert_eq!(store.authenticated_height().unwrap(), 1);
            assert!(store.state.lock().read.as_ref().unwrap().ready.is_some());
        }
        StoreCompletion::NewAppend | StoreCompletion::RepeatedAppend => {
            store.append(&body, &qc).unwrap();
        }
        StoreCompletion::RejectedAppend => {
            let mut changed = qc.clone();
            changed.result = Hash32([0x33; 32]);
            let changed = alternative(&changed, &*store.crypto);
            assert_eq!(
                store.append(&body, &changed).unwrap_err().io_kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(
        probe.state_free.load(Ordering::SeqCst) && probe.batch_free.load(Ordering::SeqCst),
        "original lane operation refund must wait for both state and batch unlock"
    );
    assert!(probe.reentered.load(Ordering::SeqCst));
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    if matches!(completion, StoreCompletion::AuthenticatedHeight) {
        let (restored, certificate) = store.committed_body(1).unwrap().unwrap();
        assert_eq!(restored, body);
        assert_eq!(certificate, qc);
    }
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(store.height(), 1);
    assert!(store.state.lock().read.is_none());
    assert!(store.state.lock().write.is_none());
    assert!(store.batch_read.lock().is_none());
    let bytes = fs::read(store.dir.join(frame_name(1))).unwrap();
    let mut inspected = LaneFrameRead::open(
        &store.dir.join(frame_name(1)),
        1,
        store.crypto.clone(),
        budget.clone(),
        schedule(&source),
    )
    .unwrap();
    let (restored, certificate) = inspected.poll().unwrap();
    assert_eq!(restored, body);
    assert_eq!(certificate, qc);
    drop((inspected, restored, certificate));
    assert_eq!(fs::read(store.dir.join(frame_name(1))).unwrap(), bytes);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), initial);
    assert_eq!(budget.limit_bytes(), original_limit);
    drop((store, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_lane_body_refund_waits_for_state_unlock() {
    original_store_refund_control(StoreCompletion::Body);
}
#[test]
fn original_lane_batch_refund_waits_for_both_original_guards() {
    original_store_refund_control(StoreCompletion::Batch);
}
#[test]
fn original_lane_entry_refund_waits_for_state_unlock() {
    original_store_refund_control(StoreCompletion::Entry);
}
#[test]
fn original_lane_authenticated_height_refund_waits_for_state_unlock() {
    original_store_refund_control(StoreCompletion::AuthenticatedHeight);
}
#[test]
fn original_lane_append_refund_waits_for_state_unlock() {
    original_store_refund_control(StoreCompletion::NewAppend);
}
#[test]
fn original_lane_repeated_append_refund_waits_for_state_unlock() {
    original_store_refund_control(StoreCompletion::RepeatedAppend);
}
#[test]
fn original_lane_rejected_append_refund_waits_for_state_unlock() {
    original_store_refund_control(StoreCompletion::RejectedAppend);
}

struct OpeningRefundProbe {
    budget: AllocationBudget,
    calls: AtomicUsize,
    remaining_bytes: AtomicUsize,
}
impl Wake for OpeningRefundProbe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.remaining_bytes
            .store(self.budget.reserved_bytes(), Ordering::SeqCst);
    }
}

#[test]
fn original_lane_opening_refund_follows_complete_recovery_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        crypto.clone(),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let path = store.dir.join(frame_name(1));
    let original = fs::read(&path).unwrap();
    drop(store);
    let initial = budget.reserved_bytes();
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let retained = budget.reserved_bytes();
    let opening = FileLaneBlockStore::begin_open(
        dir.path(),
        &source.instance(),
        crypto,
        budget.clone(),
        schedule(&source),
    )
    .unwrap();
    let AllocationRefusal::Capacity { release, .. } =
        budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
    else {
        panic!("the original opening retains the capacity observation");
    };
    let probe = Arc::new(OpeningRefundProbe {
        budget: budget.clone(),
        calls: AtomicUsize::new(0),
        remaining_bytes: AtomicUsize::new(usize::MAX),
    });
    let waker = Waker::from(probe.clone());
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    let store = opening
        .complete()
        .unwrap_or_else(|(_, error)| panic!("original signed opening: {error}"));
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        probe.remaining_bytes.load(Ordering::SeqCst),
        retained,
        "original lane opening refund must wait for completed recovery cleanup"
    );
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    assert_eq!(store.height(), 1);
    assert!(store.state.lock().read.is_none());
    assert!(store.state.lock().write.is_none());
    assert_eq!(fs::read(&path).unwrap(), original);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), initial);
    drop((store, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
}
