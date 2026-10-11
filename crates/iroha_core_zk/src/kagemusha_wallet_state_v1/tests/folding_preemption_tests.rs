//! Production scheduler/checkpoint integration with explicit mock proof work.
//! These tests exercise durable ownership and cancellation, never an installed grant.

use super::*;
use std::sync::{atomic::AtomicBool, mpsc};
use std::time::Instant;

pub(super) struct Pause {
    armed: AtomicBool,
    entered: mpsc::Sender<()>,
    released: Arc<AtomicUsize>,
    expected_checkpoint: Vec<u8>,
}
impl Pause {
    pub(super) fn run(
        &self,
        checkpoints: &[Vec<u8>],
        cancellation: &Cancellation,
    ) -> Result<(), Error> {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        assert_eq!(checkpoints, std::slice::from_ref(&self.expected_checkpoint));
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
            assert!(Instant::now() < deadline, "fold was not preempted");
            std::thread::yield_now();
        }
    }
}

fn cancel_and_resume(payment: bool) {
    let mut wallet = wallet();
    wallet.proofs.checkpoint_stages = 3;
    let boot = bootstrap();
    let operation = boot.capsule.operation_id;
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
