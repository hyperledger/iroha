//! Deterministic owner/thread lifecycle tests; no native proof authority is substituted.
use super::*;
use crate::kagemusha_wallet_ffi::tests::TestWallet;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

type SetupScript = Box<dyn FnMut(setup::Setup) -> Result<Response> + Send>;
type FoldScript = Box<dyn FnMut() -> Result<ControlFlow<Response, FoldProof>> + Send>;

struct ScriptWallet {
    base: TestWallet,
    fold: FoldScript,
    setup: Option<SetupScript>,
    resume: Option<Box<dyn FnMut() -> Result<Response> + Send>>,
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
        match self.resume.as_mut() {
            Some(run) => run(),
            None => self.base.resume(),
        }
    }
    fn fold(&mut self) -> Result<ControlFlow<Response, FoldProof>> {
        (self.fold)()
    }
    fn credit(&mut self, id: &[u8; 32], payment: &[u8; 32]) -> Result<Response> {
        self.base.credit(id, payment)
    }
}
/// A fold that finishes while it holds the owner lock, like an idle or adopted turn.
fn locked(mut fold: impl FnMut() -> Result<Response> + Send + 'static) -> FoldScript {
    Box::new(move || fold().map(ControlFlow::Break))
}
fn scripted(
    fold: impl FnMut() -> Result<Response> + Send + 'static,
) -> (u64, Arc<Owner>, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let id = install(
        Box::new(ScriptWallet {
            resume: None,
            base: TestWallet {
                calls: Arc::new(AtomicUsize::new(0)),
                drops: drops.clone(),
                expected_request: None,
            },
            fold: locked(fold),
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
        backlog: Some(0),
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
    assert_eq!((status.kind, status.detail, status.sequence), (29, 13, 0));
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
    let payment = thread::spawn(move || resume(id));
    // Payment reservation precedes its wait on the wallet and survives cancellation.
    wait(&owner, |state| state.payments == 1);
    release.send(()).unwrap();
    assert_eq!(payment.join().unwrap().unwrap().kind, 2);
    wait(&owner, |state| {
        state.backlog.is_some() && !state.running && !state.wake
    });
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(owner.background.status().unwrap().detail, 13);
    close(id).unwrap();
}

#[test]
fn pending_idle_turn_parks_until_a_payment_guard_wakes_folding() {
    for discarded_publication in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let released = Arc::new(AtomicBool::new(false));
        let selected = released.clone();
        let folding = locked(move || {
            let attempt = observed.fetch_add(1, Ordering::SeqCst);
            if discarded_publication && attempt == 0 {
                // The core test verifies Pending publication is discarded. Its
                // ordinary cancellation response retries once, then prepare parks.
                Err(Failure::code(CANCELLED))
            } else if selected.load(Ordering::SeqCst) {
                caught_up()
            } else {
                // The coordinator regression covers Pending -> Idle. This seam
                // exercises only production worker scheduling, not proof authority.
                Ok(Response {
                    kind: 6,
                    ..Response::default()
                })
            }
        });
        let id = install(
            Box::new(ScriptWallet {
                base: TestWallet {
                    calls: Arc::new(AtomicUsize::new(0)),
                    drops: Arc::new(AtomicUsize::new(0)),
                    expected_request: None,
                },
                fold: folding,
                setup: None,
                resume: Some(Box::new(move || {
                    // Inert completion observation; the real Coordinator test proves
                    // same-capsule custody recovery, not this worker scheduling seam.
                    released.store(true, Ordering::SeqCst);
                    completion(Some(state::Completion::Complete(vec![7])))
                })),
            }),
            state::Scheduler::new(),
        )
        .unwrap();
        let owner = owner(id).unwrap();
        activity(id, true, false).unwrap();
        wait(&owner, |state| {
            !state.running && !state.wake && state.started
        });
        for _ in 0..3 {
            let status = owner.background.status().unwrap();
            assert_eq!((status.kind, status.detail, status.sequence), (29, 5, 0));
        }
        let expected = 1 + usize::from(discarded_publication);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            expected,
            "idle must not schedule itself"
        );
        assert!(owner.background.inner.lock().error.is_none());

        // The public Native resume path owns the real payment guard and mutex;
        // its release must wake the parked worker without another activity call.
        assert_eq!(resume(id).unwrap().kind, 1);
        wait(&owner, |state| {
            state.backlog == Some(0) && !state.running && !state.wake
        });
        assert_eq!(calls.load(Ordering::SeqCst), expected + 1);
        assert_eq!(owner.background.status().unwrap().detail, 13);
        close(id).unwrap();
    }
}

#[test]
fn actual_uncertain_fold_error_stays_latched_until_observed_and_woken() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let uncertain = Failure::unavailable(UNCERTAIN, advance::KagemushaWalletUnavailableV1::Io(5));
    let (id, owner, _) = scripted(move || {
        if observed.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(uncertain)
        } else {
            caught_up()
        }
    });
    activity(id, true, false).unwrap();
    wait(&owner, |state| state.error.is_some() && !state.running);
    resume(id).unwrap();
    activity(id, true, false).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let error = setup(id, setup::Setup::BackgroundStatus).unwrap_err();
    assert_eq!(
        (error.status, error.reason, error.platform_code),
        (uncertain.status, uncertain.reason, uncertain.platform_code)
    );
    resume(id).unwrap();
    wait(&owner, |state| {
        state.backlog == Some(0) && !state.running && !state.wake
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
    resume(id).unwrap();
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
fn the_worker_keeps_the_backlog_of_each_fold_result_and_takes_no_snapshot() {
    let calls = Arc::new(AtomicUsize::new(0));
    let turns = Arc::new(AtomicUsize::new(0));
    let counted = turns.clone();
    let id = install(
        Box::new(ScriptWallet {
            resume: None,
            base: TestWallet {
                calls: calls.clone(),
                drops: Arc::default(),
                expected_request: None,
            },
            fold: locked(move || {
                let (kind, backlog) = match counted.fetch_add(1, Ordering::SeqCst) {
                    0 => (8, Some(2)),
                    1 => (6, None),
                    2 => (9, Some(0)),
                    _ => (7, Some(0)),
                };
                Ok(Response {
                    kind,
                    backlog,
                    ..Response::default()
                })
            }),
            setup: None,
        }),
        state::Scheduler::new(),
    )
    .unwrap();
    let owner = owner(id).unwrap();
    activity(id, true, false).unwrap();
    // A checkpoint wakes the next turn; an idle turn keeps the backlog last learned.
    wait(&owner, |state| {
        turns.load(Ordering::SeqCst) == 2 && !state.running && !state.wake
    });
    assert_eq!(owner.background.inner.lock().backlog, Some(2));
    let status = setup(id, setup::Setup::BackgroundStatus).unwrap();
    assert_eq!((status.kind, status.detail, status.sequence), (29, 13, 2));
    // The non-zero backlog lets an activity update wake the worker; a folded head wakes the
    // turn after it.
    activity(id, true, false).unwrap();
    wait(&owner, |state| {
        turns.load(Ordering::SeqCst) == 4 && !state.running && !state.wake
    });
    assert_eq!(owner.background.inner.lock().backlog, Some(0));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no snapshot after any turn"
    );
    close(id).unwrap();
}

#[test]
fn activity_wakes_the_worker_only_for_eligibility_backlog_or_an_error() {
    let turns = Arc::new(AtomicUsize::new(0));
    let counted = turns.clone();
    let (id, owner, _) = scripted(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        caught_up()
    });
    activity(id, true, false).unwrap();
    wait(&owner, |state| {
        state.backlog == Some(0) && !state.running && !state.wake
    });
    // A held payment keeps the parked worker from consuming a wake, so each update shows
    // whether it woke the worker.
    let payment = owner
        .background
        .payment(&owner.scheduler, state::FoldCallClassV1::Payment);
    let woke = |foreground: bool, charging: bool| {
        activity(id, foreground, charging).unwrap();
        std::mem::take(&mut owner.background.inner.lock().wake)
    };
    // Caught up: repeated foreground and charging updates start no turn.
    assert!(!woke(true, false));
    assert!(!woke(false, true));
    assert!(!woke(true, true));
    // Leaving activity applies at once without a wake; becoming eligible again wakes.
    assert!(!woke(false, false));
    assert!(!owner.background.inner.lock().enabled);
    assert!(woke(true, false));
    // An unknown or non-zero backlog wakes on every update.
    owner.background.inner.lock().backlog = None;
    assert!(woke(true, false));
    owner.background.inner.lock().backlog = Some(3);
    assert!(woke(false, true));
    owner.background.inner.lock().backlog = Some(0);
    assert!(!woke(true, false));
    // A pending error wakes, which clears an observed one for the retry.
    owner.background.inner.lock().error = Some((Failure::code(PROOF_REJECTED), true));
    assert!(woke(true, false));
    assert!(owner.background.inner.lock().error.is_none());
    assert_eq!(turns.load(Ordering::SeqCst), 1);
    // The payment wake stays unconditional.
    drop(payment);
    wait(&owner, |state| {
        turns.load(Ordering::SeqCst) == 2 && !state.running && !state.wake
    });
    close(id).unwrap();
}

#[test]
fn a_failed_turn_forgets_the_backlog_so_activity_retries_after_the_error_is_observed() {
    let turns = Arc::new(AtomicUsize::new(0));
    let counted = turns.clone();
    let (id, owner, _) = scripted(move || {
        if counted.fetch_add(1, Ordering::SeqCst) == 1 {
            Err(Failure::code(PROOF_REJECTED))
        } else {
            caught_up()
        }
    });
    activity(id, true, false).unwrap();
    wait(&owner, |state| {
        state.backlog == Some(0) && !state.running && !state.wake
    });
    // A payment wakes the worker unconditionally; that turn fails.
    resume(id).unwrap();
    wait(&owner, |state| state.error.is_some() && !state.running);
    assert_eq!(owner.background.inner.lock().backlog, None);
    assert_eq!(
        setup(id, setup::Setup::BackgroundStatus)
            .unwrap_err()
            .status,
        PROOF_REJECTED
    );
    // No cached zero backlog is left to swallow the update: activity alone retries.
    activity(id, true, false).unwrap();
    wait(&owner, |state| {
        state.backlog == Some(0) && !state.running && state.error.is_none()
    });
    assert_eq!(turns.load(Ordering::SeqCst), 3);
    close(id).unwrap();
}

#[test]
fn a_fold_result_carries_only_the_backlog_its_kind_allows() {
    let checked = |kind: i32, backlog: Option<u128>| {
        finished(&Response {
            kind,
            backlog,
            ..Response::default()
        })
        .map_err(|failure| failure.status)
    };
    for (kind, backlog) in [
        (6, None),
        (7, None),
        (7, Some(0)),
        (8, Some(1)),
        (8, Some(u128::MAX)),
        (9, Some(0)),
        (9, Some(4)),
    ] {
        assert_eq!(checked(kind, backlog), Ok((kind, backlog)));
    }
    for (kind, backlog) in [
        (6, Some(0)),
        (7, Some(1)),
        (8, None),
        (8, Some(0)),
        (9, None),
        (5, None),
        (10, Some(0)),
    ] {
        assert_eq!(checked(kind, backlog), Err(INTERNAL));
    }
    let with_bytes = Response {
        kind: 7,
        backlog: Some(0),
        bytes: vec![1],
        ..Response::default()
    };
    assert_eq!(finished(&with_bytes).unwrap_err().status, INTERNAL);
}

#[test]
fn collection_dispatch_does_not_reserve_payment_priority_against_itself() {
    let selected = Arc::new(Mutex::new(Weak::<Owner>::new()));
    let observed = selected.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let id = install(
        Box::new(ScriptWallet {
            resume: None,
            base: TestWallet {
                calls: calls.clone(),
                drops: Arc::default(),
                expected_request: None,
            },
            fold: locked(caught_up),
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

/// The first fold turn proves outside the owner lock: it holds the scheduler slot like one
/// sub-proof until `release` or a cancelling signal, then publishes a checkpoint under the
/// owner. Later turns are caught up.
fn unlocked(
    scheduler: state::Scheduler,
    entered: mpsc::Sender<()>,
    release: Arc<AtomicBool>,
) -> FoldScript {
    let mut turns = 0_u32;
    Box::new(move || {
        turns += 1;
        if turns > 1 {
            return caught_up().map(ControlFlow::Break);
        }
        let (scheduler, entered, release) =
            (scheduler.clone(), entered.clone(), Arc::clone(&release));
        let proof: FoldProof = Box::new(move || -> Result<FoldPublication> {
            scheduler.sub_proof_for_test(0, |token| {
                entered.send(()).unwrap();
                while !release.load(Ordering::SeqCst) {
                    token.check()?;
                    thread::yield_now();
                }
                Ok(())
            })?;
            Ok(Box::new(|_: &mut dyn Wallet| {
                Ok(Response {
                    kind: 8,
                    backlog: Some(1),
                    ..Response::default()
                })
            }))
        });
        Ok(ControlFlow::Continue(proof))
    })
}
fn unlocked_owner(
    setup: Option<SetupScript>,
) -> (u64, Arc<Owner>, mpsc::Receiver<()>, Arc<AtomicBool>) {
    let scheduler = state::Scheduler::new();
    let (entered_tx, entered) = mpsc::channel();
    let release = Arc::new(AtomicBool::new(false));
    let id = install(
        Box::new(ScriptWallet {
            resume: None,
            base: TestWallet {
                calls: Arc::new(AtomicUsize::new(0)),
                drops: Arc::new(AtomicUsize::new(0)),
                expected_request: None,
            },
            fold: unlocked(scheduler.clone(), entered_tx, Arc::clone(&release)),
            setup,
        }),
        scheduler,
    )
    .unwrap();
    (id, owner(id).unwrap(), entered, release)
}
fn started(entered: &mpsc::Receiver<()>) {
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
}

#[test]
fn ingests_and_status_reads_during_an_unlocked_proof_never_cancel_it() {
    use setup::Setup as S;
    let (id, owner, entered, release) = unlocked_owner(None);
    activity(id, true, false).unwrap();
    started(&entered);
    // A simulated setup sequence: the activation walk, the Load wait and their status reads
    // take the owner and return while the sub-proof keeps proving.
    let mut inputs = vec![S::RetainActivationAttempt(vec![1])];
    for _ in 0..3 {
        inputs.push(S::ActivationProofStep {
            signed: vec![1],
            original: vec![2],
        });
        inputs.push(S::ActivationProofProgress(vec![1]));
    }
    inputs.extend([
        S::ConfirmActivation(vec![1]),
        S::LedgerFinality(vec![1]),
        S::LedgerStatus,
        S::EpochStatus,
        S::EpochBoundary {
            epoch: 1,
            original: vec![7],
        },
        S::LedgerLoad {
            id: [1; 32],
            amount: 1,
        },
        S::LedgerInstruction {
            kind: 1,
            original: vec![1],
        },
    ]);
    const READ_REPEATS: usize = 32;
    let ingests = inputs.len() + 5 + 2 * READ_REPEATS;
    for input in inputs {
        assert_eq!(setup(id, input).unwrap().kind, 12);
    }
    assert_eq!(request_status(id, &[1; 32]).unwrap().kind, 11);
    assert_eq!(
        observation::observe(id, 0, &[]).unwrap_err().status,
        INVALID
    );
    // Repeated exact-byte retries and early credit polls must not cancel the very proof
    // needed to make the latest credit onward-spendable.
    for _ in 0..READ_REPEATS {
        assert_eq!(retry(id, &[1; 32]).unwrap().bytes, [0, 255, 0, 7]);
        assert_eq!(
            credit(id, &[1; 32], &[2; 32]).unwrap_err().status,
            FOLD_REQUIRED
        );
    }
    // Reviews and discarded UI review tokens have no monetary effect. Even rejected
    // reviews must leave the useful sub-proof running until its durable checkpoint.
    for input in [
        review::Input::Send {
            request: vec![1],
            destination_account: vec![2],
        },
        review::Input::Unload {
            amount: 1,
            charge: None,
            beneficiary: None,
        },
    ] {
        assert_eq!(review::review(id, input).unwrap_err().status, INVALID);
    }
    assert_eq!(review::discard_review(id, 1).unwrap_err().status, INVALID);
    {
        let state = owner.background.inner.lock();
        assert!(state.running, "the sub-proof is still proving");
        assert_eq!(state.fold.counts().sub_proofs, 0);
    }
    release.store(true, Ordering::SeqCst);
    wait(&owner, |state| {
        state.fold.counts().sub_proofs == 1 && !state.running && !state.wake
    });
    close(id).unwrap();

    let metrics = owner.background.fold_metrics();
    let record = metrics.records()[0];
    assert_eq!(record.outcome, state::FoldOutcomeV1::Checkpoint);
    assert_eq!(record.ingests, u32::try_from(ingests).unwrap());
    let counts = metrics.counts();
    assert_eq!(
        (
            counts.cancelled_by_payment,
            counts.cancelled_by_setup_ingest,
            counts.cancelled_by_status_read,
            counts.overlapped_ingests,
        ),
        (0, 0, 0, u64::try_from(ingests).unwrap())
    );
}

#[test]
fn explicit_fold_proves_without_the_owner_lock() {
    let (id, owner, entered, release) = unlocked_owner(None);
    owner.scheduler.set_activity(true, false);
    let folding = thread::spawn(move || fold(id));
    started(&entered);
    // The owner is free while the explicit call proves.
    assert_eq!(request_status(id, &[1; 32]).unwrap().kind, 11);
    snapshot(id).unwrap();
    release.store(true, Ordering::SeqCst);
    assert_eq!(folding.join().unwrap().unwrap().kind, 8);
    let record = owner.background.fold_metrics().records()[0];
    assert_eq!(
        (record.outcome, record.ingests),
        (state::FoldOutcomeV1::Checkpoint, 1)
    );
    close(id).unwrap();
}

#[test]
fn an_explicit_fold_resumes_a_background_turn_that_ended_idle_during_its_proof() {
    let scheduler = state::Scheduler::new();
    let (entered_tx, entered) = mpsc::channel();
    let release = Arc::new(AtomicBool::new(false));
    let turns = Arc::new(AtomicUsize::new(0));
    let (counted, slot, gate) = (Arc::clone(&turns), scheduler.clone(), Arc::clone(&release));
    let script: FoldScript = Box::new(move || match counted.fetch_add(1, Ordering::SeqCst) {
        // The explicit call: one sub-proof that holds the scheduler slot until released.
        0 => {
            let (slot, entered, gate) = (slot.clone(), entered_tx.clone(), Arc::clone(&gate));
            let proof: FoldProof = Box::new(move || -> Result<FoldPublication> {
                slot.sub_proof_for_test(0, |token| {
                    entered.send(()).unwrap();
                    while !gate.load(Ordering::SeqCst) {
                        token.check()?;
                        thread::yield_now();
                    }
                    Ok(())
                })?;
                Ok(Box::new(|_: &mut dyn Wallet| {
                    Ok(Response {
                        kind: 8,
                        backlog: Some(1),
                        ..Response::default()
                    })
                }))
            });
            Ok(ControlFlow::Continue(proof))
        }
        // A background turn while that slot is held ends idle, as the core does.
        1 => Ok(ControlFlow::Break(Response {
            kind: 6,
            ..Response::default()
        })),
        _ => caught_up().map(ControlFlow::Break),
    });
    let id = install(
        Box::new(ScriptWallet {
            resume: None,
            base: TestWallet {
                calls: Arc::new(AtomicUsize::new(0)),
                drops: Arc::new(AtomicUsize::new(0)),
                expected_request: None,
            },
            fold: script,
            setup: None,
        }),
        scheduler,
    )
    .unwrap();
    let owner = owner(id).unwrap();
    owner.scheduler.set_activity(true, false);
    let folding = thread::spawn(move || fold(id));
    started(&entered);
    // The worker starts while the explicit sub-proof proves; its turn ends idle and parks.
    activity(id, true, false).unwrap();
    wait(&owner, |state| {
        turns.load(Ordering::SeqCst) == 2 && !state.running && !state.wake
    });
    release.store(true, Ordering::SeqCst);
    assert_eq!(folding.join().unwrap().unwrap().kind, 8);
    // The explicit checkpoint is the owner's latest turn: it resumes the parked worker,
    // which catches up without a payment or activity update.
    wait(&owner, |state| {
        turns.load(Ordering::SeqCst) == 3 && !state.running && !state.wake
    });
    assert_eq!(owner.background.inner.lock().backlog, Some(0));
    close(id).unwrap();
}

#[test]
fn a_payment_taken_under_the_owner_lock_cancels_the_unlocked_proof_without_deadlock() {
    let inner = Arc::new(Mutex::new(None::<state::Scheduler>));
    let selected = Arc::clone(&inner);
    let (id, owner, entered, _release) = unlocked_owner(Some(Box::new(move |input| {
        // A core path that proves or signs takes payment priority under the owner lock.
        assert!(matches!(input, setup::Setup::LedgerStatus));
        let scheduler = selected.lock().unwrap().as_ref().unwrap().clone();
        drop(scheduler.payment());
        Ok(Response {
            kind: 12,
            ..Response::default()
        })
    })));
    *inner.lock().unwrap() = Some(owner.scheduler.clone());
    activity(id, true, false).unwrap();
    started(&entered);
    let (done_tx, done) = mpsc::channel();
    let caller = thread::spawn(move || {
        done_tx
            .send(setup(id, setup::Setup::LedgerStatus).map(|r| r.kind))
            .unwrap();
    });
    let result = done
        .recv_timeout(Duration::from_secs(5))
        .expect("the owner-locked payment joined the unlocked proof");
    assert_eq!(result.unwrap(), 12);
    caller.join().unwrap();
    let counts = owner.background.fold_metrics().counts();
    assert_eq!(
        (counts.cancelled_by_payment, counts.overlapped_ingests),
        (1, 1)
    );
    close(id).unwrap();
}

#[test]
fn fold_telemetry_counts_payment_activity_and_close_cancellations() {
    let scheduler = state::Scheduler::new();
    let (entered_tx, entered) = mpsc::channel();
    // Every turn proves outside the owner lock until a signal cancels it.
    let proving = {
        let scheduler = scheduler.clone();
        Box::new(move || -> Result<ControlFlow<Response, FoldProof>> {
            let (scheduler, entered) = (scheduler.clone(), entered_tx.clone());
            let proof: FoldProof = Box::new(move || -> Result<FoldPublication> {
                scheduler.sub_proof_for_test(0, |token| {
                    entered.send(()).unwrap();
                    loop {
                        token.check()?;
                        thread::yield_now();
                    }
                })?;
                Ok(Box::new(|_: &mut dyn Wallet| caught_up()))
            });
            Ok(ControlFlow::Continue(proof))
        })
    };
    let id = install(
        Box::new(ScriptWallet {
            resume: None,
            base: TestWallet {
                calls: Arc::new(AtomicUsize::new(0)),
                drops: Arc::new(AtomicUsize::new(0)),
                expected_request: None,
            },
            fold: proving,
            setup: None,
        }),
        scheduler,
    )
    .unwrap();
    let owner = owner(id).unwrap();
    let counts = || owner.background.fold_metrics().counts();
    let started = || entered.recv_timeout(Duration::from_secs(5)).unwrap();
    activity(id, true, false).unwrap();
    started();
    // A payment returns only after its own cancellation was reported.
    assert_eq!(resume(id).unwrap().kind, 2);
    assert_eq!(counts().cancelled_by_payment, 1);
    started();
    // A status read and a setup ingest leave the same sub-proof proving.
    assert_eq!(request_status(id, &[1; 32]).unwrap().kind, 11);
    let boundary = setup::Setup::EpochBoundary {
        epoch: 1,
        original: vec![7],
    };
    assert_eq!(setup(id, boundary).unwrap().kind, 12);
    assert_eq!(counts().sub_proofs, 1);
    activity(id, false, false).unwrap();
    wait(&owner, |state| {
        !state.running && state.fold.counts().cancelled_by_activity == 1
    });
    activity(id, true, false).unwrap();
    started();
    close(id).unwrap();

    let metrics = owner.background.fold_metrics();
    let outcomes: Vec<_> = metrics
        .records()
        .iter()
        .map(|record| (record.outcome, record.ingests))
        .collect();
    assert_eq!(
        outcomes,
        [
            (
                state::FoldOutcomeV1::Cancelled(state::FoldCancelCauseV1::Payment),
                0
            ),
            (
                state::FoldOutcomeV1::Cancelled(state::FoldCancelCauseV1::Activity),
                2
            ),
            (
                state::FoldOutcomeV1::Cancelled(state::FoldCancelCauseV1::Close),
                0
            ),
        ]
    );
    assert_eq!(
        (
            metrics.counts().cancelled_by_setup_ingest,
            metrics.counts().cancelled_by_status_read,
        ),
        (0, 0)
    );
    for record in metrics.records() {
        assert_eq!((record.sequence, record.ordinal), (0, 0));
        assert_eq!(record.peak_rss_bytes.is_some(), cfg!(unix));
    }
}

#[test]
fn setup_inputs_preempt_only_when_they_prove_sign_or_delete_custody() {
    use setup::Setup as S;
    assert_eq!(
        setup_priority(&S::CollectRetained { sequence: 1 }),
        Priority::None
    );
    for input in [
        S::LedgerStatus,
        S::EpochStatus,
        S::ActivationProofProgress(vec![1]),
        S::UnloadProofProgress {
            transaction: [1; 32],
            original: vec![1],
        },
        S::ConfirmActivation(vec![1]),
        S::RetainActivationAttempt(vec![1]),
        S::ActivationProofStep {
            signed: vec![1],
            original: vec![1],
        },
        S::LedgerLoad {
            id: [1; 32],
            amount: 1,
        },
        S::LedgerInstruction {
            kind: 1,
            original: vec![1],
        },
        S::LedgerFinality(vec![1]),
        S::ConfirmUnload {
            transaction: [1; 32],
            original: vec![1],
        },
        S::UnloadProofStep {
            transaction: [1; 32],
            original: vec![1],
            finality: vec![1],
        },
        S::EpochBoundary {
            epoch: 1,
            original: vec![1],
        },
        S::FeePayout {
            credit: [1; 32],
            world: vec![1],
            payout: vec![1],
        },
        S::RequestFeeSelection,
        S::ValidateRequestFeePolicy {
            schedule: vec![1],
            certificates: vec![1],
        },
        S::UnloadClaim {
            request_id: [1; 32],
            beneficiary: None,
        },
        S::FeeClaim { credit: [1; 32] },
        S::FeeOriginal {
            request: true,
            original: vec![1],
        },
        S::FeeClaimTransport {
            original: vec![1],
            beneficiary: vec![1],
        },
        S::Transport {
            kind: 7,
            wrap: false,
            original: vec![1],
        },
        S::CreditedOriginal {
            status: true,
            original: vec![1],
        },
        S::CreditProjection {
            id: [1; 32],
            anchor: Vec::new(),
            newer: Vec::new(),
        },
        S::BoundCredited {
            send_request: [1; 32],
            original: vec![1],
            query: true,
        },
        S::BeginTime,
        S::CancelTime { token: 1 },
        S::FinishTime {
            token: 1,
            anchor: vec![1],
            certificate: vec![1],
        },
    ] {
        assert_eq!(setup_priority(&input), Priority::Ingest);
    }
    for input in [
        S::Bootstrap,
        S::Activation,
        S::CloseLoads { id: [1; 32] },
        S::Offer {
            id: [1; 32],
            amount: 1,
        },
        S::Request {
            id: [1; 32],
            offer: vec![1],
            fee: None,
        },
        S::RequestWithFeePolicy {
            id: [1; 32],
            offer: vec![1],
            schedule: vec![1],
            certificates: vec![1],
        },
        S::Credited(vec![1]),
        S::BoundCredited {
            send_request: [1; 32],
            original: vec![1],
            query: false,
        },
        S::ReviewCustodyDeletion,
        S::ConfirmCustodyDeletion { token: 1 },
        S::ResumeCustodyDeletion,
        S::DiscardCustodyDeletion { token: 1 },
    ] {
        assert_eq!(setup_priority(&input), Priority::Payment);
    }
}
