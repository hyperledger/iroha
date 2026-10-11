//! Deterministic owner/thread lifecycle tests; no native proof authority is substituted.
use super::*;
use crate::kagemusha_wallet_ffi::tests::TestWallet;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

type SetupScript = Box<dyn FnMut(setup::Setup) -> Result<Response> + Send>;

struct ScriptWallet {
    base: TestWallet,
    fold: Box<dyn FnMut() -> Result<Response> + Send>,
    setup: Option<SetupScript>,
}
impl Wallet for ScriptWallet {
    fn snapshot(&mut self) -> Result<state::Snapshot> {
        self.base.snapshot()
    }
    fn setup(&mut self, input: setup::Setup) -> Result<Response> {
        match self.setup.as_mut() {
            Some(run) => run(input),
            None => self.base.setup(input),
        }
    }
    fn execute(&mut self, input: state::OperationRequestV1) -> Result<Response> {
        self.base.execute(input)
    }
    fn request_status(&mut self, id: &[u8; 32]) -> Result<Response> {
        self.base.request_status(id)
    }
    fn retry(&mut self, id: &[u8; 32]) -> Result<Response> {
        self.base.retry(id)
    }
    fn resume(&mut self) -> Result<Response> {
        self.base.resume()
    }
    fn fold(&mut self) -> Result<Response> {
        (self.fold)()
    }
    fn credit(&mut self, id: &[u8; 32], payment: &[u8; 32]) -> Result<Response> {
        self.base.credit(id, payment)
    }
}
fn scripted(
    fold: impl FnMut() -> Result<Response> + Send + 'static,
) -> (u64, Arc<Owner>, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let id = install(
        Box::new(ScriptWallet {
            base: TestWallet {
                calls: Arc::new(AtomicUsize::new(0)),
                drops: drops.clone(),
                expected_request: None,
            },
            fold: Box::new(fold),
            setup: None,
        }),
        state::Scheduler::new(),
    )
    .unwrap();
    (id, owner(id).unwrap(), drops)
}
fn wait(owner: &Owner, predicate: impl Fn(&Control) -> bool) {
    let control = owner.background.inner.lock();
    let (control, timed) = owner
        .background
        .inner
        .ready
        .wait_timeout_while(control, Duration::from_secs(5), |state| !predicate(state))
        .unwrap();
    assert!(
        !timed.timed_out() || predicate(&control),
        "worker did not reach expected boundary"
    );
}
fn caught_up() -> Result<Response> {
    Ok(Response {
        kind: 7,
        ..Response::default()
    })
}

#[test]
fn parked_worker_does_not_retain_owner_and_close_joins_before_custody_drop() {
    let (id, owner, drops) = scripted(caught_up);
    assert_eq!(owner.background.status().unwrap().detail, 0);
    activity(id, true, false).unwrap();
    wait(&owner, |state| state.backlog.is_some() && !state.running);
    let status = setup(id, setup::Setup::BackgroundStatus).unwrap();
    assert_eq!((status.kind, status.detail, status.sequence), (29, 13, 1));
    assert_eq!(
        Arc::strong_count(&owner),
        2,
        "parked worker must release upgraded Owner"
    );
    close(id).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(owner.wallet.lock().unwrap().is_none());
    assert!(owner.background.join.lock().unwrap().is_none());
}

#[test]
fn running_close_signals_stop_without_wallet_lock_and_waits_for_worker() {
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let (id, owner, drops) = scripted(move || {
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Err(Failure::code(CANCELLED))
    });
    activity(id, true, false).unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let (closed_tx, closed) = mpsc::channel();
    let closer = thread::spawn(move || {
        let result = close(id);
        closed_tx.send(result).unwrap();
    });
    wait(&owner, |state| state.stopped);
    assert!(matches!(closed.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    release.send(()).unwrap();
    closed
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    closer.join().unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn payment_priority_resumes_after_expected_cancellation_without_sticky_error() {
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let (id, owner, _) = scripted(move || {
        if observed.fetch_add(1, Ordering::SeqCst) == 0 {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Err(Failure::code(CANCELLED))
        } else {
            caught_up()
        }
    });
    activity(id, true, false).unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let payment = thread::spawn(move || retry(id, &[1; 32]));
    // Payment reservation precedes its wait on the wallet and survives cancellation.
    wait(&owner, |state| state.payments == 1);
    release.send(()).unwrap();
    assert_eq!(payment.join().unwrap().unwrap().bytes, [0, 255, 0, 7]);
    wait(&owner, |state| {
        state.backlog.is_some() && !state.running && !state.wake
    });
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(owner.background.status().unwrap().detail, 13);
    close(id).unwrap();
}

#[test]
fn failed_spawn_preserves_custody_and_allows_a_fresh_activity_attempt() {
    let (id, owner, drops) = scripted(caught_up);
    let error = owner
        .background
        .activity_with(&owner, true, |_| {
            Err(std::io::Error::other("injected spawn refusal"))
        })
        .unwrap_err();
    assert_eq!(error.status, RESOURCE);
    assert_eq!(owner.background.status().unwrap().detail, 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(retry(id, &[1; 32]).unwrap().bytes, [0, 255, 0, 7]);
    activity(id, true, false).unwrap();
    wait(&owner, |state| state.backlog.is_some() && !state.running);
    close(id).unwrap();
}

#[test]
fn terminal_error_is_preserved_until_observed_then_explicit_wake_can_retry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let (id, owner, _) = scripted(move || {
        if observed.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(Failure::code(PROOF_REJECTED))
        } else {
            caught_up()
        }
    });
    activity(id, true, false).unwrap();
    wait(&owner, |state| state.error.is_some());
    activity(id, true, false).unwrap();
    retry(id, &[1; 32]).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        setup(id, setup::Setup::BackgroundStatus)
            .unwrap_err()
            .status,
        PROOF_REJECTED
    );
    activity(id, true, false).unwrap();
    wait(&owner, |state| {
        state.backlog.is_some() && !state.running && state.error.is_none()
    });
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    close(id).unwrap();
}

#[test]
fn collection_dispatch_does_not_reserve_payment_priority_against_itself() {
    let selected = Arc::new(Mutex::new(Weak::<Owner>::new()));
    let observed = selected.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let id = install(
        Box::new(ScriptWallet {
            base: TestWallet {
                calls: calls.clone(),
                drops: Arc::default(),
                expected_request: None,
            },
            fold: Box::new(caught_up),
            setup: Some(Box::new(move |input| {
                let owner = observed.lock().unwrap().upgrade().unwrap();
                let payments = owner.background.inner.lock().payments;
                match input {
                    setup::Setup::CollectRetained { sequence } => {
                        assert_eq!(
                            payments, 0,
                            "collection must be able to start its scheduler"
                        );
                        Ok(Response {
                            kind: 51,
                            sequence,
                            ..Response::default()
                        })
                    }
                    setup::Setup::Bootstrap => {
                        assert_eq!(payments, 1, "money setup still reserves priority");
                        Ok(Response {
                            kind: 1,
                            ..Response::default()
                        })
                    }
                    _ => panic!("unexpected test setup"),
                }
            })),
        }),
        state::Scheduler::new(),
    )
    .unwrap();
    let owner = owner(id).unwrap();
    *selected.lock().unwrap() = Arc::downgrade(&owner);
    assert_eq!(
        setup(
            id,
            setup::Setup::CollectRetained {
                sequence: u128::MAX
            }
        )
        .unwrap()
        .sequence,
        u128::MAX
    );
    assert_eq!(setup(id, setup::Setup::Bootstrap).unwrap().kind, 1);
    close(id).unwrap();
}
