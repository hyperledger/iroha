//! Production scheduler/checkpoint integration with explicit mock proof work.
//! These tests exercise durable ownership and cancellation, never an installed grant.

use super::*;
use crate::kagemusha_wallet_advance_v1::KagemushaWalletStorageCountersV1 as Counters;
use std::ops::ControlFlow;
use std::sync::{atomic::AtomicBool, mpsc};
use std::time::Instant;

/// Holds the next mock proof, which runs without the wallet owner, until a cancelling signal
/// or until `finish` lets it complete.
pub(super) struct Pause {
    armed: AtomicBool,
    entered: mpsc::Sender<()>,
    released: Arc<AtomicUsize>,
    expected_checkpoint: PrivateArchiveBytes,
    finish: Arc<AtomicBool>,
}
impl Pause {
    pub(super) fn run(
        &self,
        checkpoints: &[PrivateArchiveBytes],
        cancellation: &Cancellation,
    ) -> Result<(), Error> {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(
            checkpoints[0].as_slice(),
            self.expected_checkpoint.as_slice()
        );
        struct Workspace(Arc<AtomicUsize>, Vec<u8>);
        impl Drop for Workspace {
            fn drop(&mut self) {
                self.0.store(self.1.len(), Ordering::SeqCst);
            }
        }
        let _workspace = Workspace(self.released.clone(), vec![0; 1024]);
        self.entered.send(()).expect("announce active fold");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            cancellation.check()?;
            if self.finish.load(Ordering::SeqCst) {
                return Ok(());
            }
            assert!(Instant::now() < deadline, "fold was not preempted");
            std::thread::yield_now();
        }
    }
}

fn cancel_and_resume(payment: bool) {
    let mut wallet = wallet();
    wallet.proofs.checkpoint_stages = 3;
    let boot = bootstrap();
    let operation = boot.capsule.body().operation_id;
    let completion = wallet.commit(boot).expect("real signed mock completion");
    let scheduler = wallet.scheduler();
    scheduler.set_activity(true, false);
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 0
        }
    );
    let checkpoint_key = ArchiveKey::Checkpoint {
        sequence: 0,
        ordinal: 0,
    };
    let retained_checkpoint = wallet.archive.get(checkpoint_key, 4096).unwrap().unwrap();
    let original: Checkpoint = archive::decode(&retained_checkpoint).unwrap();
    let selected = wallet.custody.checkpoint.clone();
    let retained_archive = wallet.archive.records.lock().unwrap().clone();
    let before = wallet.snapshot().unwrap();
    assert_eq!(before.fold_backlog, 1);
    assert_eq!(before.folded_balance, None);
    let (entered, active) = mpsc::channel();
    let released = Arc::new(AtomicUsize::new(0));
    wallet.proofs.fold_pause = Some(Arc::new(Pause {
        armed: AtomicBool::new(true),
        entered,
        released: released.clone(),
        expected_checkpoint: original.proof,
        finish: Arc::default(),
    }));
    let calls = wallet.proofs.folds.clone();
    let worker = std::thread::spawn(move || {
        let result = wallet.fold_once();
        (wallet, result)
    });
    active.recv_timeout(Duration::from_secs(5)).unwrap();
    let priority = if payment {
        // Production payment admission joins fold_once before returning this guard.
        let priority = scheduler.payment();
        assert_eq!(released.load(Ordering::SeqCst), 1024);
        Some(priority)
    } else {
        scheduler.set_activity(false, false);
        None
    };
    let (mut wallet, result) = worker.join().unwrap();
    assert!(matches!(result, Err(Error::Cancelled)));
    assert_eq!(released.load(Ordering::SeqCst), 1024);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(wallet.custody.checkpoint, selected);
    assert_eq!(*wallet.archive.records.lock().unwrap(), retained_archive);
    assert_eq!(wallet.snapshot().unwrap(), before);
    assert_eq!(wallet.retry(&operation).unwrap(), Some(completion.clone()));
    assert_eq!(wallet.custody.signatures, 1);
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Idle);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(priority);

    // Recreate the complete coordinator: only the selected durable original chain survives.
    let (custody, archive, mut proofs, scheme, wallet_id) = (
        wallet.custody,
        wallet.archive,
        wallet.proofs,
        wallet.scheme_id,
        wallet.wallet_id,
    );
    proofs.fold_pause = None;
    let mut wallet = Coordinator::new(custody, archive, proofs, scheme, wallet_id).unwrap();
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Idle);
    wallet.scheduler().set_activity(false, true);
    for ordinal in 1..3 {
        assert_eq!(
            wallet.fold_once().unwrap(),
            FoldStatus::Checkpoint {
                sequence: 0,
                ordinal
            }
        );
    }
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Folded(0));
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::CaughtUp);
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(
        wallet.archive.get(checkpoint_key, 4096).unwrap().unwrap(),
        retained_checkpoint
    );
    let after = wallet.snapshot().unwrap();
    assert_eq!(after.fold_backlog, 0);
    assert_eq!(after.folded_balance, Some(before.owned_balance));
    assert_eq!(after.head, before.head);
    assert_eq!(after.known_burned_total, before.known_burned_total);
    assert_eq!(wallet.retry(&operation).unwrap(), Some(completion));
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn payment_joins_active_fold_and_restart_resumes_exact_durable_checkpoint() {
    cancel_and_resume(true);
}

#[test]
fn inactive_wallet_cancels_active_fold_and_charging_restart_resumes_checkpoint() {
    cancel_and_resume(false);
}

#[derive(Default)]
struct Observed(Mutex<FoldMetricsV1>);
impl FoldObserverV1 for Observed {
    fn sub_proof(&self, record: FoldSubProofV1) {
        self.0.lock().expect("fold telemetry").record(record);
    }
}
impl Observed {
    fn metrics(&self) -> FoldMetricsV1 {
        self.0.lock().expect("fold telemetry").clone()
    }
}

/// Pause the next sub-proof (ordinal 1) on another thread, signal it with `cancel` and
/// return the wallet with whatever `cancel` returned.
fn interrupt<T>(mut wallet: Wallet, cancel: impl FnOnce(&Scheduler) -> T) -> (Wallet, T) {
    let retained = wallet
        .archive
        .get(
            ArchiveKey::Checkpoint {
                sequence: 0,
                ordinal: 0,
            },
            4096,
        )
        .unwrap()
        .unwrap();
    let original: Checkpoint = archive::decode(&retained).unwrap();
    let (entered, active) = mpsc::channel();
    wallet.proofs.fold_pause = Some(Arc::new(Pause {
        armed: AtomicBool::new(true),
        entered,
        released: Arc::new(AtomicUsize::new(0)),
        expected_checkpoint: original.proof,
        finish: Arc::default(),
    }));
    let scheduler = wallet.scheduler();
    let worker = std::thread::spawn(move || {
        let result = wallet.fold_once();
        (wallet, result)
    });
    active.recv_timeout(Duration::from_secs(5)).unwrap();
    let held = cancel(&scheduler);
    let (wallet, result) = worker.join().unwrap();
    assert!(matches!(result, Err(Error::Cancelled)));
    (wallet, held)
}

#[test]
fn fold_telemetry_reports_each_sub_proof_and_cancellation_cause_without_idle_wakes() {
    let mut wallet = wallet();
    wallet.proofs.checkpoint_stages = 3;
    wallet
        .commit(bootstrap())
        .expect("real signed mock completion");
    let observed = Arc::new(Observed::default());
    let scheduler = wallet.scheduler();
    scheduler.observe(observed.clone());
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Idle);
    scheduler.set_activity(true, false);
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 0
        }
    );
    let first = observed.metrics().records()[0];
    assert_eq!(
        (
            first.sequence,
            first.ordinal,
            first.operation,
            first.stage,
            first.outcome,
            first.peak_rss_bytes,
        ),
        (
            0,
            0,
            Some(KagemushaWalletOperationKindV1::Bootstrap),
            None,
            FoldOutcomeV1::Checkpoint,
            None,
        )
    );

    // A priority call is counted under its class before its join returns.
    for class in [
        FoldCallClassV1::Payment,
        FoldCallClassV1::SetupIngest,
        FoldCallClassV1::StatusRead,
    ] {
        let before = observed.metrics().counts();
        let (next, priority) = interrupt(wallet, |scheduler| {
            let priority = scheduler.payment_for(class);
            let counts = observed.metrics().counts();
            assert_eq!(
                (
                    counts.cancelled_by_payment - before.cancelled_by_payment,
                    counts.cancelled_by_setup_ingest - before.cancelled_by_setup_ingest,
                    counts.cancelled_by_status_read - before.cancelled_by_status_read,
                ),
                match class {
                    FoldCallClassV1::Payment => (1, 0, 0),
                    FoldCallClassV1::SetupIngest => (0, 1, 0),
                    FoldCallClassV1::StatusRead => (0, 0, 1),
                }
            );
            priority
        });
        wallet = next;
        drop(priority);
    }
    // The plain payment entry point is the payment class.
    (wallet, _) = interrupt(wallet, |scheduler| drop(scheduler.payment()));
    (wallet, _) = interrupt(wallet, |scheduler| scheduler.set_activity(false, false));
    scheduler.set_activity(true, false);
    (wallet, _) = interrupt(wallet, Scheduler::close);
    scheduler.set_activity(true, false);
    wallet.proofs.fold_pause = None;

    let cancelled = observed.metrics();
    let outcomes: Vec<_> = cancelled
        .records()
        .iter()
        .skip(1)
        .map(|r| r.outcome)
        .collect();
    assert_eq!(
        outcomes,
        [
            FoldCancelCauseV1::Payment,
            FoldCancelCauseV1::SetupIngest,
            FoldCancelCauseV1::StatusRead,
            FoldCancelCauseV1::Payment,
            FoldCancelCauseV1::Activity,
            FoldCancelCauseV1::Close,
        ]
        .map(FoldOutcomeV1::Cancelled)
    );
    for record in cancelled.records().iter().skip(1) {
        assert_eq!((record.sequence, record.ordinal), (0, 1));
        assert_eq!(
            record.operation,
            Some(KagemushaWalletOperationKindV1::Bootstrap)
        );
    }
    assert_eq!(
        cancelled.counts().discarded_prove,
        cancelled
            .records()
            .iter()
            .filter(|r| r.outcome.cause().is_some())
            .map(|r| r.phase(FoldPhaseV1::Prove))
            .sum::<Duration>()
    );

    // The cancelled work resumes from the durable checkpoint; Ω is the final stage.
    for ordinal in 1..3 {
        assert_eq!(
            wallet.fold_once().unwrap(),
            FoldStatus::Checkpoint {
                sequence: 0,
                ordinal
            }
        );
    }
    let prior_checkpoint = wallet.custody.checkpoint.clone();
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Folded(0));
    let folded = *observed.metrics().records().back().unwrap();
    assert_eq!(
        (folded.ordinal, folded.stage, folded.outcome),
        (3, Some(FoldStageV1::Omega), FoldOutcomeV1::Folded)
    );
    // An idle wake records nothing.
    let before = observed.metrics();
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::CaughtUp);
    assert_eq!(observed.metrics(), before);
    // An interrupted publication is adopted, never proved again.
    wallet.custody.checkpoint = prior_checkpoint;
    wallet.verified_folds.clear();
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Folded(0));
    let adopted = *observed.metrics().records().back().unwrap();
    assert_eq!(
        (adopted.ordinal, adopted.stage, adopted.outcome),
        (3, Some(FoldStageV1::Omega), FoldOutcomeV1::Adopted)
    );
    assert_eq!(adopted.phase(FoldPhaseV1::Prove), Duration::ZERO);
    assert_eq!(
        observed.metrics().counts(),
        FoldCountsV1 {
            sub_proofs: 11,
            checkpoints: 3,
            folded: 1,
            adopted: 1,
            failed: 0,
            discarded: 0,
            cancelled_by_payment: 2,
            cancelled_by_setup_ingest: 1,
            cancelled_by_status_read: 1,
            cancelled_by_activity: 1,
            cancelled_by_close: 1,
            discarded_prove: cancelled.counts().discarded_prove,
            overlapped_ingests: 0,
        }
    );
}

/// A wallet whose Bootstrap fold has three sub-proofs and a durable checkpoint 0, with fold
/// telemetry observed.
fn folding_wallet() -> (Wallet, FrozenTransition, Arc<Observed>) {
    let mut wallet = wallet();
    wallet.proofs.checkpoint_stages = 3;
    let boot = bootstrap();
    wallet
        .commit(boot.clone())
        .expect("real signed mock completion");
    let observed = Arc::new(Observed::default());
    let scheduler = wallet.scheduler();
    scheduler.observe(observed.clone());
    scheduler.set_activity(true, false);
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 0
        }
    );
    (wallet, boot, observed)
}

/// The locked prepare of the next sub-proof.
fn prepared(wallet: &mut Wallet) -> FoldJobV1 {
    match wallet.fold_prepare().unwrap() {
        ControlFlow::Continue(job) => job,
        ControlFlow::Break(ended) => panic!("no sub-proof prepared: {ended:?}"),
    }
}

/// Hold the next proof (ordinal 1) until `finish` or a cancelling signal; the receiver
/// reports that it started.
fn hold(wallet: &mut Wallet, finish: Arc<AtomicBool>) -> mpsc::Receiver<()> {
    let retained = wallet
        .archive
        .get(
            ArchiveKey::Checkpoint {
                sequence: 0,
                ordinal: 0,
            },
            4096,
        )
        .unwrap()
        .unwrap();
    let original: Checkpoint = archive::decode(&retained).unwrap();
    let (entered, active) = mpsc::channel();
    wallet.proofs.fold_pause = Some(Arc::new(Pause {
        armed: AtomicBool::new(true),
        entered,
        released: Arc::new(AtomicUsize::new(0)),
        expected_checkpoint: original.proof,
        finish,
    }));
    active
}

fn receive(previous: &FrozenTransition) -> FrozenTransition {
    frozen(
        Some(previous),
        KagemushaWalletEffectV1::Receive {
            credit_id: field(101),
            payer_wallet_id: [0x88; 32],
            amount: 1,
        },
    )
}

fn checkpoint_at(wallet: &mut Wallet, ordinal: u32) -> Option<PrivateArchiveBytes> {
    wallet
        .archive
        .get(
            ArchiveKey::Checkpoint {
                sequence: 0,
                ordinal,
            },
            4096,
        )
        .unwrap()
}

#[test]
fn ingests_during_an_unlocked_proof_never_cancel_it_and_its_publication_rebases() {
    let (mut wallet, _, observed) = folding_wallet();
    let finish = Arc::new(AtomicBool::new(false));
    let active = hold(&mut wallet, finish.clone());
    let scheduler = wallet.scheduler();
    let job = prepared(&mut wallet);
    // The job owns its inputs: the wallet serves ingests and reads on another thread while
    // the proof runs on this one.
    let ingesting = std::thread::spawn(move || {
        active.recv_timeout(Duration::from_secs(5)).unwrap();
        scheduler.ingest();
        let read = wallet.snapshot().unwrap();
        scheduler.ingest();
        // An unrelated ingest moves the selected manifest.
        let (selected, mut manifest) = wallet.sync_manifest().unwrap();
        manifest.finality_epoch = Some(7);
        wallet.publish_manifest(selected, &manifest).unwrap();
        finish.store(true, Ordering::SeqCst);
        (wallet, read)
    });
    let proved = job.prove().expect("ingests never cancel the proof");
    let (mut wallet, read) = ingesting.join().unwrap();
    assert_eq!(read.fold_backlog, 1);
    assert_eq!(
        wallet.fold_publish(proved).unwrap(),
        FoldTurnStatusV1 {
            status: FoldStatus::Checkpoint {
                sequence: 0,
                ordinal: 1
            },
            backlog: Some(1),
        }
    );
    let (_, manifest) = wallet.sync_manifest().unwrap();
    assert_eq!(
        (manifest.finality_epoch, manifest.checkpoint_count),
        (Some(7), 2),
        "the publication rebased onto the ingest"
    );
    let record = *observed.metrics().records().back().unwrap();
    assert_eq!(
        (record.ordinal, record.outcome, record.ingests),
        (1, FoldOutcomeV1::Checkpoint, 2)
    );
    let counts = observed.metrics().counts();
    assert_eq!(
        (
            counts.cancelled_by_payment,
            counts.cancelled_by_setup_ingest,
            counts.cancelled_by_status_read,
            counts.overlapped_ingests,
        ),
        (0, 0, 0, 2)
    );
    wallet.proofs.fold_pause = None;
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 2
        }
    );
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Folded(0));
}

#[test]
fn an_advance_during_the_unlocked_proof_cancels_it_and_nothing_is_published() {
    let (mut wallet, boot, observed) = folding_wallet();
    let active = hold(&mut wallet, Arc::default());
    let job = prepared(&mut wallet);
    let advancing = std::thread::spawn(move || {
        active.recv_timeout(Duration::from_secs(5)).unwrap();
        // The Advance takes payment priority: it cancels and joins the proof first.
        wallet.commit(receive(&boot)).expect("Advance");
        wallet
    });
    assert!(matches!(job.prove(), Err(Error::Cancelled)));
    let mut wallet = advancing.join().unwrap();
    let cancelled = *observed.metrics().records().back().unwrap();
    assert_eq!(
        (cancelled.ordinal, cancelled.outcome),
        (1, FoldOutcomeV1::Cancelled(FoldCancelCauseV1::Payment))
    );
    let (_, manifest) = wallet.sync_manifest().unwrap();
    assert_eq!((manifest.indexed, manifest.checkpoint_count), (Some(1), 1));
    assert_eq!(checkpoint_at(&mut wallet, 1), None, "never published");
    // The next turn proves the same sub-proof again from durable state.
    wallet.proofs.fold_pause = None;
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 1
        }
    );
}

#[test]
fn a_proof_is_discarded_when_its_fold_fields_change_before_publication() {
    let (mut wallet, _, observed) = folding_wallet();
    let calls = wallet.proofs.folds.clone();
    let stale = prepared(&mut wallet).prove().unwrap();
    // Another caller publishes the same sub-proof first; the slot is free after a proof.
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 1
        }
    );
    let published = checkpoint_at(&mut wallet, 1);
    let selected = wallet.custody.checkpoint.clone();
    assert!(matches!(wallet.fold_publish(stale), Err(Error::Cancelled)));
    // The stale proof changed nothing durable.
    assert_eq!(wallet.custody.checkpoint, selected);
    assert_eq!(checkpoint_at(&mut wallet, 1), published);
    let discarded = *observed.metrics().records().back().unwrap();
    assert_eq!(
        (discarded.ordinal, discarded.outcome),
        (1, FoldOutcomeV1::Discarded)
    );
    assert_eq!(observed.metrics().counts().discarded, 1);
    // The next turn resumes from durable state.
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 2
        }
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[test]
fn an_advance_between_the_proof_and_its_publication_is_rebased() {
    let (mut wallet, boot, observed) = folding_wallet();
    let proved = prepared(&mut wallet).prove().unwrap();
    // The proof released the slot: the Advance neither waits for nor cancels it, and it
    // changes no fold field of head 0.
    wallet.commit(receive(&boot)).expect("Advance");
    // Its backlog is that of the rebased manifest, which indexes the new head.
    assert_eq!(
        wallet.fold_publish(proved).unwrap(),
        FoldTurnStatusV1 {
            status: FoldStatus::Checkpoint {
                sequence: 0,
                ordinal: 1
            },
            backlog: Some(2),
        }
    );
    let (_, manifest) = wallet.sync_manifest().unwrap();
    assert_eq!((manifest.indexed, manifest.checkpoint_count), (Some(1), 2));
    assert_eq!(
        observed.metrics().records().back().unwrap().outcome,
        FoldOutcomeV1::Checkpoint
    );
}

/// Prove the next sub-proof, let `leave` move custody off its released head before the
/// publication, and return the publication's refusal once custody is restored.
fn publish_after(wallet: &mut Wallet, leave: impl FnOnce(&mut TestCustody)) -> Error {
    let released = wallet.custody.status.clone();
    let proved = prepared(wallet).prove().unwrap();
    leave(&mut wallet.custody);
    let refused = wallet.fold_publish(proved).expect_err("never published");
    wallet.custody.status = released;
    wallet.custody.unavailable = false;
    wallet.custody.status_error = None;
    refused
}

#[test]
fn a_proof_is_never_published_once_custody_leaves_its_released_head() {
    let (mut wallet, _, observed) = folding_wallet();
    let calls = wallet.proofs.folds.clone();
    let selected = wallet.custody.checkpoint.clone();
    let SlotStatus::Released(record) = wallet.custody.status.clone() else {
        panic!("a released head");
    };
    let terminal = record.clone();
    // Between the unlocked proof and its publication: an Advance left pending, custody
    // deletion or retirement to a terminal marker, and custody that is locked or removed.
    let refusals = [
        publish_after(&mut wallet, |custody| {
            custody.status = SlotStatus::Pending(record);
        }),
        publish_after(&mut wallet, |custody| {
            custody.status = SlotStatus::Terminal(terminal);
        }),
        publish_after(&mut wallet, |custody| custody.unavailable = true),
        publish_after(&mut wallet, |custody| {
            custody.status_error = Some(ProviderError::Uncertain(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Io(5),
            ));
        }),
    ];
    assert!(matches!(
        refusals,
        [
            Error::Cancelled,
            Error::NoHead,
            Error::Provider(ProviderError::Unavailable(_)),
            Error::Provider(ProviderError::Uncertain(_)),
        ]
    ));
    // Pending discards the proof; terminal custody and real provider failures remain errors.
    assert_eq!(wallet.custody.checkpoint, selected);
    assert_eq!(checkpoint_at(&mut wallet, 1), None, "never published");
    let metrics = observed.metrics();
    assert_eq!(
        metrics
            .records()
            .iter()
            .rev()
            .take(4)
            .map(|turn| (turn.ordinal, turn.outcome))
            .collect::<Vec<_>>(),
        vec![
            (1, FoldOutcomeV1::Failed),
            (1, FoldOutcomeV1::Failed),
            (1, FoldOutcomeV1::Failed),
            (1, FoldOutcomeV1::Discarded)
        ],
    );
    assert_eq!(metrics.counts().discarded, 1);
    // The next turn proves the same sub-proof again from durable state.
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 1
        }
    );
    assert_eq!(calls.load(Ordering::SeqCst), 6);
}

#[test]
fn a_crash_between_the_proof_and_its_publication_reproves_or_adopts_as_before() {
    let (mut wallet, _, observed) = folding_wallet();
    let calls = wallet.proofs.folds.clone();
    // Killed after the proof, before its publication: nothing durable changed.
    drop(prepared(&mut wallet).prove().unwrap());
    assert_eq!(checkpoint_at(&mut wallet, 1), None);
    let (custody, archive, proofs, scheme, wallet_id) = (
        wallet.custody,
        wallet.archive,
        wallet.proofs,
        wallet.scheme_id,
        wallet.wallet_id,
    );
    let mut wallet = Coordinator::new(custody, archive, proofs, scheme, wallet_id).unwrap();
    wallet.scheduler().observe(observed.clone());
    wallet.scheduler().set_activity(true, false);
    let before = wallet.custody.checkpoint.clone();
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 1
        }
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "re-proved after the restart"
    );
    // Killed during the publication, after the checkpoint and before the manifest: the
    // restart adopts the exact bytes and never proves again.
    wallet.custody.checkpoint = before;
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 1
        }
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        observed.metrics().records().back().unwrap().outcome,
        FoldOutcomeV1::Adopted
    );
}

/// One host turn as the bridge runs it: locked prepare, unlocked proof, locked publication.
fn host_turn(wallet: &mut Wallet) -> FoldTurnStatusV1 {
    match wallet.fold_prepare().unwrap() {
        ControlFlow::Break(ended) => ended,
        ControlFlow::Continue(job) => {
            let proved = job.prove().unwrap();
            wallet.fold_publish(proved).unwrap()
        }
    }
}

/// The fixture Receive, whose CreditStatus builds once it is folded.
fn credited(previous: &FrozenTransition) -> FrozenTransition {
    frozen(
        Some(previous),
        KagemushaWalletEffectV1::Receive {
            credit_id: received_credit(),
            payer_wallet_id: [0x88; 32],
            amount: fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
                .signed_request()
                .expect("fixture signed Request")
                .body
                .amount,
        },
    )
}

/// Fold turns until head `sequence` is folded.
fn fold_through(wallet: &mut Wallet, sequence: u128) {
    for _ in 0..16 {
        match wallet.fold_once().unwrap() {
            FoldStatus::Folded(folded) if folded == sequence => return,
            FoldStatus::Checkpoint { .. } | FoldStatus::Folded(_) => {}
            other => panic!("unexpected fold status {other:?}"),
        }
    }
    panic!("head {sequence} was not folded");
}

/// Bootstrap and the fixture Receive, both folded, with a CreditStatus that builds.
fn credited_and_folded() -> (Wallet, FrozenTransition) {
    let mut wallet = wallet();
    let boot = bootstrap();
    wallet.commit(boot.clone()).expect("Bootstrap");
    wallet.scheduler().set_activity(true, false);
    fold_through(&mut wallet, 0);
    let received = credited(&boot);
    wallet.commit(received.clone()).expect("Receive");
    fold_through(&mut wallet, 1);
    wallet
        .credit_status(&received_credit(), &received_payment())
        .expect("CreditStatus");
    (wallet, received)
}

#[test]
fn every_turn_reports_the_snapshot_backlog_of_the_manifest_it_ended_on() {
    let ended = |status, backlog| FoldTurnStatusV1 { status, backlog };
    let mut wallet = wallet();
    wallet.scheduler().set_activity(true, false);
    // Nothing is released before Bootstrap: the backlog is unknown, never caught up.
    assert_eq!(host_turn(&mut wallet), ended(FoldStatus::CaughtUp, None));
    let boot = bootstrap();
    wallet.commit(boot.clone()).expect("Bootstrap");
    wallet.commit(credited(&boot)).expect("Receive");
    let mut interrupted = None;
    for expected in [
        ended(
            FoldStatus::Checkpoint {
                sequence: 0,
                ordinal: 0,
            },
            Some(2),
        ),
        ended(FoldStatus::Folded(0), Some(1)),
        ended(
            FoldStatus::Checkpoint {
                sequence: 1,
                ordinal: 0,
            },
            Some(1),
        ),
        ended(FoldStatus::Folded(1), Some(0)),
        ended(FoldStatus::CaughtUp, Some(0)),
    ] {
        if expected.status == FoldStatus::Folded(1) {
            interrupted = Some(wallet.custody.checkpoint.clone());
        }
        let turn = host_turn(&mut wallet);
        assert_eq!(turn, expected);
        assert_eq!(turn.backlog, Some(wallet.snapshot().unwrap().fold_backlog));
    }
    // A publication interrupted after its Ω bytes is adopted in the locked prepare, with the
    // backlog of the manifest that the adoption published.
    wallet.custody.checkpoint = interrupted.expect("selected before the final Ω");
    wallet.verified_folds.clear();
    assert_eq!(
        host_turn(&mut wallet),
        ended(FoldStatus::Folded(1), Some(0))
    );
    wallet.scheduler().set_activity(false, false);
    assert_eq!(host_turn(&mut wallet), ended(FoldStatus::Idle, None));
}

#[test]
fn a_caught_up_wake_reads_no_step_omega_or_index_and_verifies_nothing() {
    let (mut wallet, _) = credited_and_folded();
    let observed = Arc::new(Observed::default());
    wallet.scheduler().observe(observed.clone());
    // A cold Ω cache, as after an eviction: a wake that read the predecessor would verify it.
    wallet.verified_folds.clear();
    let reads = wallet.archive.reads.load(Ordering::SeqCst);
    let verifies = wallet.proofs.verifies.load(Ordering::SeqCst);
    let (ended, storage) = Counters::observe(|| wallet.fold_prepare().unwrap());
    assert!(matches!(
        ended,
        ControlFlow::Break(FoldTurnStatusV1 {
            status: FoldStatus::CaughtUp,
            backlog: Some(0),
        })
    ));
    assert_eq!(
        wallet.archive.reads.load(Ordering::SeqCst),
        reads,
        "no step, recorded Ω or index object is read"
    );
    assert_eq!((storage.index_walks, storage.index_node_loads), (0, 0));
    assert_eq!(
        wallet.proofs.verifies.load(Ordering::SeqCst),
        verifies,
        "no lineage verification"
    );
    assert!(wallet.verified_folds.is_empty());
    // The exclusive owner path ends the same way, and an idle wake records no telemetry.
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::CaughtUp);
    assert_eq!(wallet.archive.reads.load(Ordering::SeqCst), reads);
    assert_eq!(observed.metrics().counts().sub_proofs, 0);
}

/// The caught-up wake no longer reads the recorded Ω, so it misses a lost one while the wallet
/// only polls. Every folded-state read still refuses it, the payment path before its Advance.
#[test]
fn a_lost_recorded_omega_skipped_by_a_caught_up_wake_fails_every_folded_read() {
    let (mut wallet, received) = credited_and_folded();
    wallet
        .archive
        .records
        .lock()
        .expect("records")
        .remove(&ArchiveKey::Fold(1));
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::CaughtUp);
    assert!(matches!(
        wallet.snapshot(),
        Err(Error::WitnessLost("recorded Ω"))
    ));
    assert!(matches!(
        wallet.credit_status(&received_credit(), &received_payment()),
        Err(Error::WitnessLost("recorded Ω"))
    ));
    let signatures = wallet.custody.signatures;
    assert!(matches!(
        wallet.commit(receive(&received)),
        Err(Error::WitnessLost("recorded Ω"))
    ));
    assert_eq!(wallet.custody.signatures, signatures, "no Advance");
}

/// Record a foreign leaf in the selected manifest's credit tree, so its root no longer matches
/// the recorded Ω of the folded head.
fn corrupt_credit_root(wallet: &mut Wallet) {
    let (selected, mut manifest) = wallet.manifest().unwrap();
    manifest
        .credit_tree
        .record(
            &mut wallet.archive,
            &KagemushaWalletCreditDigestLeafV1 {
                credit_id: field(77),
                payment_digest: field(78),
                burned: false,
            },
        )
        .unwrap();
    wallet.publish_manifest(selected, &manifest).unwrap();
}

/// The predecessor credit-root check is skipped only by the caught-up wake. CreditStatus
/// refuses a corrupted root, and so does the first turn that selects a sub-proof, before any
/// proof work or publication.
#[test]
fn a_corrupted_credit_root_still_fails_credit_status_and_every_working_turn() {
    let (mut wallet, received) = credited_and_folded();
    corrupt_credit_root(&mut wallet);
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::CaughtUp);
    assert!(matches!(
        wallet.credit_status(&received_credit(), &received_payment()),
        Err(Error::WitnessLost("credit root"))
    ));
    wallet
        .commit(receive(&received))
        .expect("a new released head");
    let folds = wallet.proofs.folds.load(Ordering::SeqCst);
    let selected = wallet.custody.checkpoint.clone();
    assert!(matches!(
        wallet.fold_once(),
        Err(Error::WitnessLost("credit tree root"))
    ));
    assert_eq!(
        wallet.proofs.folds.load(Ordering::SeqCst),
        folds,
        "no proof work"
    );
    assert_eq!(wallet.custody.checkpoint, selected, "nothing published");
}

/// Every kind of selected sub-proof checks the predecessor credit root first. A turn that
/// would adopt an interrupted checkpoint publication and a turn that resumes after a durable
/// checkpoint both refuse a corrupted root before proof work, adoption or publication; with
/// the intact root the same turns adopt and prepare.
#[test]
fn the_credit_root_check_precedes_adopted_and_resumed_sub_proofs() {
    let (mut wallet, received) = credited_and_folded();
    wallet
        .commit(receive(&received))
        .expect("a new released head");
    // Selected before the checkpoint publication: its bytes alone make the next turn adopt.
    let interrupted = wallet.custody.checkpoint.clone();
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 2,
            ordinal: 0
        }
    );
    // Selected after it: the next turn resumes with the final Ω.
    let resumed = wallet.custody.checkpoint.clone();
    let folds = wallet.proofs.folds.load(Ordering::SeqCst);
    for selected in [interrupted.clone(), resumed.clone()] {
        wallet.custody.checkpoint = selected;
        corrupt_credit_root(&mut wallet);
        let corrupted = wallet.custody.checkpoint.clone();
        assert!(matches!(
            wallet.fold_once(),
            Err(Error::WitnessLost("credit tree root"))
        ));
        assert_eq!(
            wallet.proofs.folds.load(Ordering::SeqCst),
            folds,
            "no proof work"
        );
        assert_eq!(wallet.custody.checkpoint, corrupted, "nothing published");
    }
    // Intact, the interrupted publication is adopted byte-for-byte and never re-proved.
    wallet.custody.checkpoint = interrupted;
    assert_eq!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 2,
            ordinal: 0
        }
    );
    assert_eq!(wallet.proofs.folds.load(Ordering::SeqCst), folds);
    assert_eq!(wallet.custody.checkpoint, resumed);
    // Intact, the resumed turn passes the check and prepares its Ω.
    drop(prepared(&mut wallet));
    assert_eq!(wallet.proofs.folds.load(Ordering::SeqCst), folds + 1);
}
