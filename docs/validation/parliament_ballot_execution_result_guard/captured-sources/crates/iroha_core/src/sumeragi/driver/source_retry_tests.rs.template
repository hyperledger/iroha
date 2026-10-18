//! Exact committed heads wait for their original source, independent of elapsed time.

use super::*;
use crate::sumeragi::driver::{
    tests::{block, commit_qc},
    traits::PublicationDeferral,
};
use iroha_allocation::{AllocationBudget, AllocationCharge, release::ReleaseNotification};

#[test]
fn committed_head_waits_for_original_release_across_prepare_append_and_commit() {
    for phase in [
        CommitWaitPhase::Prepare,
        CommitWaitPhase::Append,
        CommitWaitPhase::Commit,
    ] {
        let bytes = ExecutionRegistrations::admission_bytes();
        let budget = AllocationBudget::new(bytes + 1);
        let registration = ExecutionRegistrations::admit(&budget).unwrap();
        let held = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let body = block(1, Hash32::ZERO, Hash32::ZERO, vec![1]);
        let result = Hash32([9; 32]);
        let qc = commit_qc(&body, result);
        let mut scheduler = ExecSched::new(0, Backoff::default(), registration);
        scheduler.commit(body, qc);
        let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
            panic!("original prepare")
        };
        if phase != CommitWaitPhase::Prepare {
            scheduler.done(0, ExecDone::Prepared(Ok(Some(result))));
            let Some(ExecOp::Append(append)) = scheduler.next(0) else {
                panic!("original append")
            };
            assert!(Arc::ptr_eq(&original, &append));
        }
        if phase == CommitWaitPhase::Commit {
            scheduler.done(
                0,
                ExecDone::Appended {
                    durable: true,
                    deferred: None,
                },
            );
            let Some(ExecOp::Commit(commit)) = scheduler.next(0) else {
                panic!("original commit")
            };
            assert!(Arc::ptr_eq(&original, &commit));
        }
        let deferred =
            PublicationError::Deferred(PublicationDeferral::Execution(refusal.clone().into()));
        scheduler.done(
            0,
            match phase {
                CommitWaitPhase::Prepare => ExecDone::Prepared(Err(deferred)),
                CommitWaitPhase::Append => ExecDone::Appended {
                    durable: false,
                    deferred: Some(PublicationDeferral::Execution(refusal.into())),
                },
                CommitWaitPhase::Commit => ExecDone::Committed(Err(deferred)),
            },
        );
        assert_eq!(
            scheduler.wakeup(),
            Millis::MAX,
            "a busy source has no timer deadline"
        );
        assert!(scheduler.next(0).is_none());
        assert!(
            scheduler.next(Millis::MAX - 1).is_none(),
            "elapsed time cannot release the actual owner"
        );
        assert_eq!(budget.reserved_bytes(), bytes + 1);
        assert_eq!(scheduler.applied(), 0);
        assert!(scheduler.take_events().is_empty());
        drop(held);
        // Original release permits progress even before the old ten-millisecond deadline.
        let retry = scheduler.next(0).expect("release drives immediate retry");
        match (phase, retry) {
            (CommitWaitPhase::Append, ExecOp::Append(retry)) => {
                assert!(Arc::ptr_eq(&original, &retry))
            }
            (CommitWaitPhase::Prepare | CommitWaitPhase::Commit, ExecOp::Prepare(retry)) => {
                assert!(Arc::ptr_eq(&original, &retry))
            }
            other => panic!("wrong retained retry phase: {other:?}"),
        }
        if phase == CommitWaitPhase::Commit {
            scheduler.done(0, ExecDone::Prepared(Ok(Some(result))));
            let Some(ExecOp::Commit(retry)) = scheduler.next(0) else {
                panic!("durable head skips a second append")
            };
            assert!(Arc::ptr_eq(&original, &retry));
        }
        drop(scheduler);
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "the last original slot frees its charge"
        );
    }
}

#[test]
fn replacing_a_refusal_cancels_old_source_and_recovery_cancels_current_source() {
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + 4096);
    let registration = ExecutionRegistrations::admit(&budget).unwrap();
    let notification = || {
        let layout = ReleaseNotification::allocation_layout::<AllocationCharge>();
        let mut reservation = budget.try_reserve(layout).unwrap();
        ReleaseNotification::try_new_charged(reservation.try_split(layout).unwrap()).unwrap()
    };
    let a = notification();
    let b = notification();
    let lock_a = std::sync::Mutex::new(());
    let lock_b = std::sync::Mutex::new(());
    let held_a = a.guard(lock_a.lock().unwrap());
    let held_b = b.guard(lock_b.lock().unwrap());
    let original_a = a.observe();
    let original_b = b.observe();
    assert!(lock_a.try_lock().is_err());
    assert!(lock_b.try_lock().is_err());
    let body = block(1, Hash32::ZERO, Hash32::ZERO, vec![1]);
    let qc = commit_qc(&body, Hash32([9; 32]));
    let mut scheduler = ExecSched::new(0, Backoff::default(), registration);
    scheduler.commit(body, qc);
    assert!(matches!(scheduler.next(0), Some(ExecOp::Prepare(_))));
    scheduler.done(
        0,
        ExecDone::Prepared(Err(PublicationError::Deferred(
            PublicationDeferral::StateViewBusy(original_a),
        ))),
    );
    assert!(scheduler.next(0).is_none());
    drop(held_a);
    assert!(matches!(scheduler.next(0), Some(ExecOp::Prepare(_))));
    scheduler.done(
        0,
        ExecDone::Prepared(Err(PublicationError::Deferred(
            PublicationDeferral::StateViewBusy(original_b),
        ))),
    );
    assert!(scheduler.next(0).is_none());
    drop(a.guard(lock_a.lock().unwrap()));
    assert!(
        scheduler.next(Millis::MAX - 1).is_none(),
        "old source cannot release current source"
    );
    drop(held_b);
    assert!(matches!(scheduler.next(0), Some(ExecOp::Prepare(_))));
    scheduler.done(
        0,
        ExecDone::Prepared(Err(PublicationError::RecoveryRequired(
            "original publication lost".into(),
        ))),
    );
    assert!(scheduler.commit_wait.is_none());
    assert!(scheduler.next(Millis::MAX).is_none());
    drop(scheduler);
    drop(a);
    drop(b);
    assert_eq!(budget.reserved_bytes(), 0);
}
