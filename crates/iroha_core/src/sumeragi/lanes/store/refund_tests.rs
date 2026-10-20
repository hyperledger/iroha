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
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
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

#[test]
fn cancelled_proposal_read_refund_reenters_only_after_both_native_guards_release() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let initial = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let mut request = ProposalReadScope::new();
    request.admit(&budget).unwrap();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let retained = budget.reserved_bytes();
    let raw = usize::try_from(fs::metadata(store.dir.join(frame_name(1))).unwrap().len()).unwrap();
    let pressure = budget.try_reserve_bytes(ceiling - retained - raw).unwrap();
    let refused = store.proposal_batch(1, &request).unwrap_err();
    let Attempt::Deferred(original) = refused else {
        panic!("original read Capacity");
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        panic!("actual original pool wait");
    };
    let probe = Arc::new(StoreRefundProbe {
        store: Arc::downgrade(&store),
        calls: AtomicUsize::new(0),
        state_free: AtomicBool::new(false),
        batch_free: AtomicBool::new(false),
        reentered: AtomicBool::new(false),
    });
    let waker = Waker::from(probe.clone());
    assert!(
        registration
            .poll_wait(release, &mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(request);
    store.release_cancelled_reads();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(probe.state_free.load(Ordering::SeqCst) && probe.batch_free.load(Ordering::SeqCst));
    assert!(probe.reentered.load(Ordering::SeqCst));
    assert_eq!(
        budget.reserved_bytes(),
        ceiling - raw - ProposalReadScope::admission_bytes()
    );
    assert!(!store.retains_pending_work());
    drop((registration, original, pressure, probe, waker));
    assert_eq!(budget.reserved_bytes(), initial);
    drop((store, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
}

struct HeldReadAuthority {
    source: AvailabilitySource,
    armed: AtomicBool,
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}
impl AvailabilitySchedule for HeldReadAuthority {
    fn instance(&self) -> Hash32 {
        self.source.instance()
    }
    fn height_config(
        &self,
        _: u64,
    ) -> Result<Option<iroha_sumeragi::types::HeightConfig>, Attempt<io::Error>> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let mut state = self.state.lock();
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                self.changed.wait(&mut state);
            }
        }
        Ok(Some(self.source.config().clone()))
    }
}

#[test]
fn busy_original_native_operation_inherits_cancelled_read_cleanup_before_returning() {
    let root = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let authority = Arc::new(HeldReadAuthority {
        source: source.clone(),
        armed: AtomicBool::new(false),
        state: Mutex::new((false, false)),
        changed: Condvar::new(),
    });
    let store = FileLaneBlockStore::begin_open(
        root.path(),
        &source.instance(),
        Arc::new(crypto),
        budget.clone(),
        authority.clone(),
    )
    .unwrap()
    .complete()
    .unwrap_or_else(|(_, error)| panic!("original native store: {error}"));
    let store = super::tests::LiveStore::new(store);
    store.append(&body, &qc).unwrap();
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let raw = usize::try_from(fs::metadata(store.dir.join(frame_name(1))).unwrap().len()).unwrap();
    let mut request = ProposalReadScope::new();
    request.admit(&budget).unwrap();
    let pressure = budget
        .try_reserve_bytes(ceiling - budget.reserved_bytes() - raw)
        .unwrap();
    assert!(matches!(
        store.proposal_batch(1, &request),
        Err(Attempt::Deferred(_))
    ));
    drop(pressure);
    assert_eq!(
        budget.reserved_bytes(),
        baseline + raw + ProposalReadScope::admission_bytes()
    );
    authority.armed.store(true, Ordering::SeqCst);
    let (entered, returned, result) = std::thread::scope(|threads| {
        // The already-owned authenticated-height operation takes the real state mutex and
        // exact original schedule; no proposal token borrow prevents actual cancellation.
        let original = threads.spawn(|| store.authenticated_height());
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut state = authority.state.lock();
        while !state.0 && Instant::now() < deadline {
            authority.changed.wait_until(&mut state, deadline);
        }
        let entered = state.0;
        drop(state);
        drop(request);
        // Nonblocking cleanup returns while the original native operation remains held.
        let (send, receive) = std::sync::mpsc::channel();
        let cleanup_store = &*store;
        let cleanup = threads.spawn(move || {
            cleanup_store.release_cancelled_reads();
            send.send(()).unwrap();
        });
        let returned = receive.recv_timeout(Duration::from_secs(5)).is_ok();
        let mut state = authority.state.lock();
        state.1 = true;
        authority.changed.notify_all();
        drop(state);
        // Preserve both causal observations, always release the native boundary, then join
        // both actual workers before any assertion (including a failed timeout observation).
        let original = original.join();
        let cleanup = cleanup.join();
        cleanup.unwrap();
        (entered, returned, original.unwrap())
    });
    assert_eq!(result.unwrap(), 1);
    let cleaned = !store.retains_pending_work() && budget.reserved_bytes() == baseline;
    // A mutant's naturally joined original read is explicitly released only after verdict.
    store.release_cancelled_reads();
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(store.height(), 1);
    drop((store, authority, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        entered && returned && cleaned,
        "the original busy native operation must finish cancelled read cleanup before returning"
    );
}

// The test thread alone pauses after the actual cancellation observation and before unlock.
// Other threads run the ordinary native nonblocking cleanup without an injected pause.
struct CancellationObservation {
    batch: bool,
    callback: Box<dyn FnOnce()>,
}
thread_local! {
    static CANCELLATION_OBSERVATION: std::cell::RefCell<Option<CancellationObservation>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn after_cancellation_observation(batch: bool) {
    let callback = CANCELLATION_OBSERVATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|selected| selected.batch == batch)
        {
            slot.take().map(|selected| selected.callback)
        } else {
            None
        }
    });
    if let Some(callback) = callback {
        callback();
    }
}

fn cancellation_after_native_cleanup_observation(batch: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let raw = usize::try_from(fs::metadata(store.dir.join(frame_name(1))).unwrap().len()).unwrap();
    let mut request = ProposalReadScope::new();
    request.admit(&budget).unwrap();
    let pressure = budget
        .try_reserve_bytes(ceiling - budget.reserved_bytes() - raw)
        .unwrap();
    assert!(matches!(
        store.proposal_batch(1, &request),
        Err(Attempt::Deferred(_))
    ));
    drop(pressure);
    if batch {
        // Move the actually authenticated original frame into its real batch owner.
        // Payload interpretation is irrelevant to cancellation; the body and QC stay exact.
        let interest = ReadInterest::proposal(&request, &budget).unwrap();
        let (prepared, original) = store.take_prepared(1, &interest).unwrap().unwrap();
        let (restored, certificate) = prepared.into_parts();
        assert_eq!(restored, body);
        assert_eq!(certificate, qc);
        *store.batch_read.lock() = Some(PendingBatch {
            interest: original,
            read: BatchRead {
                body: restored,
                qc: certificate,
            },
        });
    }
    assert!(store.retains_pending_work());
    let before = fs::read(store.dir.join(frame_name(1))).unwrap();
    let (entered, returned, resumed) = std::thread::scope(|threads| {
        let (enter_send, enter_receive) = std::sync::mpsc::channel();
        let (resume_send, resume_receive) = std::sync::mpsc::channel();
        let cleanup_store = &*store;
        let holder = threads.spawn(move || {
            let resumed = Arc::new(AtomicBool::new(false));
            let observed = resumed.clone();
            CANCELLATION_OBSERVATION.with(|slot| {
                assert!(slot.borrow().is_none());
                *slot.borrow_mut() = Some(CancellationObservation {
                    batch,
                    callback: Box::new(move || {
                        let _ = enter_send.send(());
                        observed.store(
                            resume_receive.recv_timeout(Duration::from_secs(5)).is_ok(),
                            Ordering::SeqCst,
                        );
                    }),
                });
            });
            cleanup_store.release_cancelled_reads();
            CANCELLATION_OBSERVATION.with(|slot| {
                slot.borrow_mut().take();
            });
            resumed.load(Ordering::SeqCst)
        });
        let entered = enter_receive.recv_timeout(Duration::from_secs(5)).is_ok();
        drop(request);
        let (done_send, done_receive) = std::sync::mpsc::channel();
        let cancellation_store = &*store;
        let cancellation = threads.spawn(move || {
            cancellation_store.release_cancelled_reads();
            let _ = done_send.send(());
        });
        let returned = done_receive.recv_timeout(Duration::from_secs(5)).is_ok();
        let _ = resume_send.send(());
        let resumed = holder.join().unwrap();
        cancellation.join().unwrap();
        (entered, returned, resumed)
    });
    let cleaned = !store.retains_pending_work() && budget.reserved_bytes() == baseline;
    // Record the original no-successor result before explicit diagnostic cleanup.
    store.release_cancelled_reads();
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(store.dir.join(frame_name(1))).unwrap(), before);
    let (restored, certificate) = store.committed_body(1).unwrap().unwrap();
    assert_eq!(restored, body);
    assert_eq!(certificate, qc);
    drop((restored, certificate, store, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        entered && returned && resumed,
        "actual cleanup observation and nonblocking cancellation must complete"
    );
    assert!(
        cleaned,
        "cancellation after the original cleanup observation must release that exact read without successor traffic"
    );
}

#[test]
fn state_read_cancellation_after_cleanup_observation_cannot_be_lost() {
    cancellation_after_native_cleanup_observation(false);
}

#[test]
fn batch_read_cancellation_after_cleanup_observation_cannot_be_lost() {
    cancellation_after_native_cleanup_observation(true);
}
