//! Nonblocking conservative retirement probes for the actual ready store mutexes.

use super::tests::open;
use super::*;
use crate::sumeragi::lanes::record::tests::fixture;

#[test]
fn retirement_pending_work_probe_retains_each_held_mutex_without_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let (_body, _qc, source, budget, crypto) = fixture(1025);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    assert!(!store.retains_pending_work());
    let state = store.state.lock();
    assert!(
        store.retains_pending_work(),
        "an actual held state mutex conservatively retains custody"
    );
    drop(state);
    assert!(!store.retains_pending_work());
    let batch = store.batch_read.lock();
    assert!(
        store.retains_pending_work(),
        "an actual held batch mutex conservatively retains custody"
    );
    drop(batch);
    assert!(!store.retains_pending_work());
}

// These are harness-cleanup bounds, not a larger lane wait timeout. Each worker is
// joined only after its held state/publication guard has been released, even on failure.
const WAIT_CONTROL_CLEANUP: Duration = Duration::from_secs(5);

#[test]
fn durable_tip_zero_wait_does_not_acquire_original_io_state() {
    let dir = tempfile::tempdir().unwrap();
    let (_body, _qc, source, budget, crypto) = fixture(1025);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    let state = store.state.lock();
    let (started, entered) = std::sync::mpsc::sync_channel(1);
    let (finished, observed) = std::sync::mpsc::sync_channel(1);
    let (entered, before_unlock, joined) = std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            started.send(()).unwrap();
            finished
                .send((
                    store.wait_for(0, Duration::ZERO),
                    store.wait_for(1, Duration::ZERO),
                ))
                .unwrap();
        });
        let entered = entered.recv_timeout(WAIT_CONTROL_CLEANUP);
        let before_unlock = observed.recv_timeout(WAIT_CONTROL_CLEANUP);
        drop(state);
        let joined = waiter.join();
        (entered, before_unlock, joined)
    });
    entered.unwrap();
    joined.unwrap();
    assert_eq!(
        before_unlock,
        Ok((true, false)),
        "a zero-time durable-tip observation must complete while the original I/O state remains held"
    );
}

#[test]
fn durable_tip_timeout_does_not_reacquire_original_io_state() {
    let dir = tempfile::tempdir().unwrap();
    let (_body, _qc, source, budget, crypto) = fixture(1025);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    let (finished, observed) = std::sync::mpsc::sync_channel(1);
    let (parked, before_unlock, joined) = std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            finished
                .send(store.wait_for(1, Duration::from_secs(1)))
                .unwrap();
        });
        let deadline = Instant::now() + WAIT_CONTROL_CLEANUP;
        let held = loop {
            let state = store.state.lock();
            // notify_all's count observes an actual parked Condvar waiter. Holding
            // state across this notification deterministically exercises reacquisition.
            if store.grown.notify_all() != 0 {
                break Some(state);
            }
            drop(state);
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::yield_now();
        };
        let parked = held.is_some();
        let before_unlock = observed.recv_timeout(WAIT_CONTROL_CLEANUP);
        drop(held);
        let joined = waiter.join();
        (parked, before_unlock, joined)
    });
    joined.unwrap();
    assert!(
        parked,
        "the control must observe the original Condvar waiter"
    );
    assert_eq!(
        before_unlock,
        Ok(false),
        "deadline expiry must complete while the original I/O state remains held"
    );
}

struct PausedTipPublication {
    entered: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
    resume: Mutex<std::sync::mpsc::Receiver<()>>,
    refuse: bool,
}

impl Faults for PausedTipPublication {
    fn before(&self, step: crate::sumeragi::records::FsStep, _: &Path) -> io::Result<()> {
        if step != crate::sumeragi::records::FsStep::SyncDir {
            return Ok(());
        }
        let Some(entered) = self.entered.lock().take() else {
            return Ok(());
        };
        entered.send(()).map_err(io::Error::other)?;
        self.resume
            .lock()
            .recv_timeout(WAIT_CONTROL_CLEANUP)
            .map_err(io::Error::other)?;
        if self.refuse {
            return Err(io::Error::other(
                "original directory synchronization refused",
            ));
        }
        Ok(())
    }
}

#[test]
fn durable_tip_wait_refuses_visible_frame_until_original_directory_sync_finishes() {
    for refuse in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (body, qc, source, budget, crypto) = fixture(1025);
        let (entered, acquired) = std::sync::mpsc::sync_channel(1);
        let (resume, resumed) = std::sync::mpsc::sync_channel(1);
        let faults = Arc::new(PausedTipPublication {
            entered: Mutex::new(None),
            resume: Mutex::new(resumed),
            refuse,
        });
        let store = open(
            dir.path(),
            &source,
            Arc::new(crypto),
            &budget,
            faults.clone(),
        );
        *faults.entered.lock() = Some(entered);
        let (finished, observed) = std::sync::mpsc::sync_channel(1);
        let (acquired, state_held, visible, before_resume, resumed, appended, waited) =
            std::thread::scope(|scope| {
                let publisher = scope.spawn(|| store.append(&body, &qc));
                let acquired = acquired.recv_timeout(WAIT_CONTROL_CLEANUP);
                let state_held = acquired.is_ok() && store.state.try_lock().is_none();
                let visible = acquired.is_ok() && store.dir.join(frame_name(1)).is_file();
                let waiter = scope.spawn(|| {
                    finished.send(store.wait_for(1, Duration::ZERO)).unwrap();
                });
                // Leave headroom for the independent fault-holder's cleanup bound.
                let before_resume = observed.recv_timeout(Duration::from_secs(1));
                let resumed = resume.send(());
                let appended = publisher.join();
                let waited = waiter.join();
                (
                    acquired,
                    state_held,
                    visible,
                    before_resume,
                    resumed,
                    appended,
                    waited,
                )
            });
        acquired.unwrap();
        resumed.unwrap();
        waited.unwrap();
        let appended = appended.unwrap();
        assert!(
            state_held,
            "the real publication must hold its original I/O state"
        );
        assert!(
            visible,
            "the original frame must already be visible before directory sync"
        );
        assert_eq!(
            before_resume,
            Ok(false),
            "a visible but unsynchronized frame is not a durable tip, and its wait must not block behind SyncDir"
        );
        if refuse {
            assert_eq!(
                appended.unwrap_err().to_string(),
                "original directory synchronization refused"
            );
            assert_eq!(store.height(), 0);
            assert!(!store.wait_for(1, Duration::ZERO));
            store.append(&body, &qc).unwrap();
        } else {
            appended.unwrap();
        }
        assert_eq!(store.height(), 1);
        assert!(store.wait_for(1, Duration::ZERO));
        assert_eq!(store.entry(1).unwrap().unwrap().commit_qc, qc);
    }
}

#[test]
fn durable_tip_waiter_wakes_after_append_and_recovered_prefix_is_immediate() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    let (finished, observed) = std::sync::mpsc::sync_channel(1);
    let (parked, appended, notified, joined) = std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            finished
                .send(store.wait_for(1, WAIT_CONTROL_CLEANUP))
                .unwrap()
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let parked = loop {
            if store.grown.notify_all() != 0 {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::yield_now();
        };
        let appended = store.append(&body, &qc);
        let notified = observed.recv_timeout(Duration::from_secs(1));
        let joined = waiter.join();
        (parked, appended, notified, joined)
    });
    joined.unwrap();
    assert!(
        parked,
        "the control must observe the original Condvar waiter"
    );
    appended.unwrap();
    assert_eq!(
        notified,
        Ok(true),
        "successful publication must wake the existing waiter before its timeout"
    );
    drop(store);
    let reopened = open(dir.path(), &source, crypto, &budget, Arc::new(NoFaults));
    assert!(reopened.wait_for(1, Duration::ZERO));
    assert!(!reopened.wait_for(2, Duration::ZERO));
    assert_eq!(reopened.entry(1).unwrap().unwrap().commit_qc, qc);
}

struct ReentrantTipFormatter {
    store: Arc<FileLaneBlockStore>,
    output: String,
    observation: Option<Result<bool, std::sync::mpsc::RecvTimeoutError>>,
    waiter: Option<std::thread::JoinHandle<bool>>,
}

impl std::fmt::Write for ReentrantTipFormatter {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.output.push_str(text);
        if text == "height" && self.waiter.is_none() {
            let store = Arc::clone(&self.store);
            let (finished, observed) = std::sync::mpsc::sync_channel(1);
            self.waiter = Some(std::thread::spawn(move || {
                let ready = store.wait_for(0, Duration::ZERO);
                // A timed-out observation is asserted only after formatting releases
                // any old guard and the caller joins this original worker.
                let _ = finished.send(ready);
                ready
            }));
            self.observation = Some(observed.recv_timeout(Duration::from_secs(1)));
        }
        Ok(())
    }
}

#[test]
fn durable_tip_debug_releases_its_guard_before_formatter_reentry() {
    use std::fmt::Write as _;

    let dir = tempfile::tempdir().unwrap();
    let (_body, _qc, source, budget, crypto) = fixture(1025);
    let store = Arc::new(open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    ));
    let mut output = ReentrantTipFormatter {
        store: Arc::clone(&store),
        output: String::new(),
        observation: None,
        waiter: None,
    };
    let formatted = write!(&mut output, "{store:?}");
    // Never join inside a formatter callback: even the original broken guard is
    // released when formatting returns, so the negative control cannot hang.
    let joined = output.waiter.take().map(std::thread::JoinHandle::join);
    formatted.unwrap();
    assert!(joined.unwrap().unwrap());
    assert!(output.output.contains("height: 0"));
    assert_eq!(
        output.observation,
        Some(Ok(true)),
        "formatter callbacks must observe the durable tip without waiting for a formatting-held lock"
    );
}
