//! Actual publication owners retain their original release identity through driver retry.

use super::*;
use crate::{
    execution_attempt::ExecutionDeferred,
    sumeragi::{
        driver::{
            exec::{ExecDone, ExecOp, ExecSched},
            persist::Backoff,
            traits::BlockStore as _,
        },
        executor::publication_tests,
    },
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_sumeragi::api::Event;
use std::{
    sync::Arc,
    task::{Context, Poll, Waker},
};

#[test]
fn state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release() {
    for hash_writer in [false, true] {
        publication_tests::with_worker(move |chain, worker, blocks, events| {
            let mut registration = crate::unit_test_support::release_registration(
                &chain.state().ivm_execution_budget(),
            );
            let scheduler_registration =
                crate::sumeragi::driver::exec::ExecutionRegistrations::admit(
                    &chain.state().ivm_execution_budget(),
                )
                .unwrap();
            let (body, qc) = publication_tests::executed(chain, worker);
            let overlay =
                std::ptr::from_ref(worker.live.as_ref().unwrap().overlay.as_deref().unwrap());
            let mut scheduler = ExecSched::new(1, Backoff::default(), scheduler_registration);
            scheduler.commit(body.clone(), qc.clone());
            let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
                panic!("prepare original committed execution");
            };
            let prepared = worker.prepare(&original.block, &original.qc);
            scheduler.done(0, ExecDone::Prepared(prepared));
            let Some(ExecOp::Append(append)) = scheduler.next(0) else {
                panic!("append exactly once");
            };
            assert!(Arc::ptr_eq(&original, &append));
            blocks.append(&append.block, &append.qc).unwrap();
            scheduler.done(
                0,
                ExecDone::Appended {
                    durable: true,
                    deferred: None,
                },
            );
            let Some(ExecOp::Commit(commit)) = scheduler.next(0) else {
                panic!("publish original committed execution");
            };
            let staged = worker.context.staging.get(&qc.block_hash).unwrap();
            // Freeze and recover the real original publication twice. Its own
            // logical cleanup and independent logical acquisitions cannot wake
            // the distinct original history writer while that writer stays held.
            chain.state().with_publication_blocked_for_test(|| {
                for _ in 0..2 {
                    let error = worker.commit(&commit.block, &commit.qc).unwrap_err();
                    let PublicationError::Deferred(PublicationDeferral::PublicationBusy(wait)) =
                        error
                    else {
                        panic!("real history writer must retain a typed publication refusal");
                    };
                    let wait = wait;
                    assert_eq!(
                        registration.poll_wait(&wait, &mut Context::from_waker(Waker::noop())),
                        Poll::Pending,
                        "logical cleanup cannot wake the held physical history writer"
                    );
                    chain
                        .state()
                        .with_membership_publication_blocked_for_test(|| ());
                    assert_eq!(
                        registration.poll_wait(&wait, &mut Context::from_waker(Waker::noop())),
                        Poll::Pending
                    );
                    assert_eq!(chain.state().committed_height(), 1);
                    assert_eq!(worker.applied.0, 1);
                    assert!(worker.recovery.is_none());
                    assert!(worker.pending_commit.is_none());
                    assert!(events.try_recv().is_err());
                    assert_eq!(
                        std::ptr::from_ref(
                            worker.live.as_ref().unwrap().overlay.as_deref().unwrap()
                        ),
                        overlay
                    );
                }
            });
            let attempt = || {
                let failure = worker.commit(&commit.block, &commit.qc).unwrap_err();
                let PublicationError::Deferred(ref source) = failure else {
                    panic!("publication erased original physical owner: {failure:?}");
                };
                assert!(matches!(source, PublicationDeferral::BlockHashesBusy(_)) == hash_writer);
                assert!(matches!(source, PublicationDeferral::PublicationBusy(_)) == !hash_writer);
                assert!(source.execution().is_none());
                assert!(
                    source.allocation_refusal().is_none(),
                    "locks are not allocation demand"
                );
                let wait = source.release_wait().unwrap().clone();
                let mut context = Context::from_waker(Waker::noop());
                assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
                let unrelated = AllocationBudget::new(1);
                drop(unrelated.try_reserve_bytes(1).unwrap());
                assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
                scheduler.done(0, ExecDone::Committed(Err(failure)));
                assert_eq!(
                    scheduler
                        .preparation_refusal()
                        .and_then(PublicationDeferral::release_wait),
                    Some(&wait)
                );
                assert_eq!(scheduler.applied(), 1);
                assert!(scheduler.next(0).is_none());
                assert!(scheduler.take_events().is_empty());
                assert!(worker.recovery.is_none());
                assert!(worker.pending_commit.is_none());
                assert!(events.try_recv().is_err());
                assert_eq!(
                    std::ptr::from_ref(worker.live.as_ref().unwrap().overlay.as_deref().unwrap()),
                    overlay
                );
                assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
                wait
            };
            let wait = if hash_writer {
                chain
                    .state()
                    .with_hash_publication_blocked_for_test(attempt)
            } else {
                chain
                    .state()
                    .with_membership_publication_blocked_for_test(attempt)
            };
            assert_eq!(
                registration.poll_wait(&wait, &mut Context::from_waker(Waker::noop())),
                Poll::Ready(())
            );
            let now = scheduler.wakeup();
            let Some(ExecOp::Prepare(retry)) = scheduler.next(now) else {
                panic!("same queued execution retries after physical release");
            };
            assert!(Arc::ptr_eq(&original, &retry));
            assert_eq!(
                scheduler
                    .preparation_refusal()
                    .and_then(PublicationDeferral::release_wait),
                Some(&wait)
            );
            let prepared = worker.prepare(&retry.block, &retry.qc);
            assert_eq!(prepared.as_ref().unwrap(), &Some(qc.result));
            assert_eq!(
                std::ptr::from_ref(worker.live.as_ref().unwrap().overlay.as_deref().unwrap()),
                overlay
            );
            assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                &staged.executed,
                &worker.context.staging.get(&qc.block_hash).unwrap().executed
            ));
            scheduler.done(now, ExecDone::Prepared(prepared));
            let Some(ExecOp::Commit(retry)) = scheduler.next(now) else {
                panic!("durable append is retained; retry only publication");
            };
            assert!(Arc::ptr_eq(&original, &retry));
            let applied = worker.commit(&retry.block, &retry.qc).unwrap();
            assert_eq!(
                scheduler.done(now, ExecDone::Committed(Ok(Box::new(applied)))),
                Some(2)
            );
            assert!(scheduler.preparation_refusal().is_none());
            assert_eq!(
                scheduler
                    .take_events()
                    .iter()
                    .filter(|event| matches!(event, Event::BlockApplied { .. }))
                    .count(),
                1
            );
            assert_eq!(chain.state().committed_height(), 2);
        });
    }
}

#[test]
fn state_execution_and_membership_refusals_preserve_actual_release_owners() {
    publication_tests::with_worker(|chain, _worker, _blocks, _events| {
        let budget = chain.state().ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let occupied = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        assert!(matches!(original, AllocationRefusal::Capacity { .. }));
        let PublicationError::Deferred(source) = original_refusal(
            TransactionsBlockError::ExecutionDeferred(ExecutionDeferred::from(original.clone())),
        ) else {
            panic!("retain original State allocation refusal");
        };
        assert_eq!(source.allocation_refusal(), Some(&original));
        assert!(source.execution().is_some());
        let wait = source.release_wait().unwrap().clone();
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
        let unrelated = AllocationBudget::new(1);
        drop(unrelated.try_reserve_bytes(1).unwrap());
        assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
        drop(occupied);
        assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Ready(()));
        drop(
            budget
                .try_reserve_bytes(1)
                .expect("same original pool retries"),
        );

        let storage = &chain.state().transactions;
        let blocker = storage.block();
        let Err(MembershipAdmissionError::Busy(original)) = storage.prepare_next_block(false)
        else {
            panic!("actual membership writer must refuse another original preparation");
        };
        let PublicationError::Deferred(source) =
            original_refusal(TransactionsBlockError::MembershipAdmission(
                MembershipAdmissionError::Busy(original.clone()),
            ))
        else {
            panic!("retain original membership writer refusal");
        };
        assert!(
            matches!(&source, PublicationDeferral::MembershipBusy(actual) if actual == &original)
        );
        assert!(source.execution().is_none());
        assert!(source.allocation_refusal().is_none());
        let wait = source.release_wait().unwrap().clone();
        assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
        drop(unrelated.try_reserve_bytes(1).unwrap());
        assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
        drop(blocker);
        assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Ready(()));
        let original = storage
            .prepare_next_block(false)
            .expect("same membership preparation retries");
        let mut original = Some(original);
        drop(
            storage
                .attach_prepared(&mut original)
                .expect("unchanged predecessor attaches"),
        );
    });
}

#[test]
fn nonretryable_state_publication_error_requires_recovery() {
    assert!(matches!(
        original_refusal(TransactionsBlockError::MissingInsertBlock),
        PublicationError::RecoveryRequired(_)
    ));
}
