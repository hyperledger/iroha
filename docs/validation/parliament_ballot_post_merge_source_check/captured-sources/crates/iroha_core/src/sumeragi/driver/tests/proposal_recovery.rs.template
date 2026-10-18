//! Exact available-body custody through publication admission recovery and worker refusal.

use iroha_sumeragi::{
    api::{Action, Event, HaltReason},
    availability::AvailableBody,
    testing::{built_payload, proposal_signing_request},
    types::Hash32,
};

use super::{
    super::{
        Op,
        exec::{ExecDone, ExecOp, ExecSched, ExecutionRegistrations},
        persist::Backoff,
        run_exec,
        traits::{PublicationDeferral, PublicationError},
    },
    block,
    fakes::{FakeBlocks, FakeExecutor},
    hash,
    kernel::start_kernel,
    test_registrations,
};

fn original(tag: u8) -> AvailableBody {
    block(1, Hash32::ZERO, Hash32::ZERO, vec![tag])
}

fn recover(
    scheduler: &mut ExecSched,
    now: u64,
    req: u64,
    expected: &AvailableBody,
) -> AvailableBody {
    let Some(ExecOp::RecoverProposalAdmission { req: actual, body }) = scheduler.next(now) else {
        panic!("original recovery must be scheduled")
    };
    assert_eq!(actual, req);
    assert_eq!(body, *expected);
    assert_eq!(
        body.payload().as_slice().as_ptr(),
        expected.payload().as_slice().as_ptr()
    );
    body
}

#[test]
fn proposal_recovery_same_body_new_request_preserves_original_release_refusal() {
    let budget =
        iroha_allocation::AllocationBudget::new(ExecutionRegistrations::admission_bytes() + 1);
    let registrations = ExecutionRegistrations::admit(&budget).unwrap();
    let held = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let mut scheduler = ExecSched::new(0, Backoff::default(), registrations);
    let body = original(1);
    scheduler.recover_proposal_admission(1, body.clone());
    recover(&mut scheduler, 0, 1, &body);
    // A newer Core request names the same source while the original worker is still running.
    scheduler.recover_proposal_admission(2, body.clone());
    scheduler.done(
        0,
        ExecDone::ProposalAdmissionRecovered(Err(PublicationError::Deferred(
            PublicationDeferral::Execution(refusal.into()),
        ))),
    );
    for req in 2..=8 {
        scheduler.recover_proposal_admission(req, body.clone());
        assert!(scheduler.next(u64::MAX).is_none());
        assert_eq!(scheduler.wakeup(), u64::MAX);
        assert_eq!(scheduler.queued_ops(), 1);
        assert!(scheduler.take_events().is_empty());
    }
    drop(held);
    let recovered = recover(&mut scheduler, 1_000, 8, &body);
    let admission = built_payload(recovered.payload().clone()).admission;
    scheduler.done(
        1_000,
        ExecDone::ProposalAdmissionRecovered(Ok(admission.clone())),
    );
    assert_eq!(
        scheduler.take_events(),
        vec![Event::ProposalAdmissionRecovered {
            req: 8,
            admission: Some(admission.clone()),
        }]
    );
    let request = proposal_signing_request(&body, hash(&body), 0, Hash32::ZERO, false);
    admission.check(&request).unwrap();
    let other = original(2);
    let substituted = proposal_signing_request(&other, hash(&other), 0, Hash32::ZERO, false);
    assert!(admission.check(&substituted).is_err());
    assert_eq!(scheduler.queued_ops(), 0);
}

#[test]
fn proposal_recovery_discard_retires_original_waiter_before_decode_refund() {
    let budget =
        iroha_allocation::AllocationBudget::new(ExecutionRegistrations::admission_bytes() + 1);
    let registrations = ExecutionRegistrations::admit(&budget).unwrap();
    let held_decode = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let mut scheduler = ExecSched::new(0, Backoff::default(), registrations);
    let body = original(1);
    scheduler.recover_proposal_admission(1, body.clone());
    recover(&mut scheduler, 0, 1, &body);
    scheduler.done(
        0,
        ExecDone::ProposalAdmissionRecovered(Err(PublicationError::Deferred(
            PublicationDeferral::Execution(refusal.into()),
        ))),
    );
    assert!(scheduler.next(u64::MAX).is_none());
    assert_eq!(scheduler.wakeup(), u64::MAX);

    // Another height and an explicitly retained body preserve the original physical refusal.
    for (height, keep) in [(2, vec![]), (1, vec![body.source().block_hash()])] {
        scheduler.discard(height, keep);
        assert!(matches!(scheduler.next(0), Some(ExecOp::Discard { .. })));
        scheduler.done(0, ExecDone::Discarded);
        assert_eq!(scheduler.queued_ops(), 1);
        assert!(scheduler.next(u64::MAX).is_none());
    }

    scheduler.discard(1, vec![]);
    assert!(matches!(scheduler.next(0), Some(ExecOp::Discard { .. })));
    // Native discard releases the old decode, waking any still-registered physical waiter.
    drop(held_decode);
    scheduler.done(0, ExecDone::Discarded);
    assert!(
        scheduler.next(u64::MAX).is_none(),
        "discarded proposal recovery must not reacquire its original body after decode refund"
    );
    assert_eq!(scheduler.queued_ops(), 0);
    assert_eq!(scheduler.wakeup(), u64::MAX);
    assert!(scheduler.take_events().is_empty());
    let current = original(2);
    scheduler.recover_proposal_admission(2, current.clone());
    recover(&mut scheduler, 0, 2, &current);
}

#[test]
fn proposal_recovery_discard_cancels_only_matching_running_completion() {
    for retained in [false, true] {
        let mut scheduler = ExecSched::new(0, Backoff::default(), test_registrations());
        let body = original(1);
        scheduler.recover_proposal_admission(1, body.clone());
        recover(&mut scheduler, 0, 1, &body);
        let keep = if retained {
            vec![body.source().block_hash()]
        } else {
            vec![]
        };
        scheduler.discard(1, keep);
        let admission = built_payload(body.payload().clone()).admission;
        scheduler.done(
            0,
            ExecDone::ProposalAdmissionRecovered(Ok(admission.clone())),
        );
        let events = scheduler.take_events();
        if retained {
            assert_eq!(
                events,
                vec![Event::ProposalAdmissionRecovered {
                    req: 1,
                    admission: Some(admission),
                }]
            );
        } else {
            assert!(events.is_empty());
        }
        assert!(matches!(scheduler.next(0), Some(ExecOp::Discard { .. })));
        scheduler.done(0, ExecDone::Discarded);
        assert!(scheduler.next(u64::MAX).is_none());
    }
}

#[test]
fn proposal_recovery_discard_preserves_terminal_original_failure() {
    let budget = iroha_allocation::AllocationBudget::new(0);
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    for error in [
        PublicationError::RecoveryRefusal(refusal.into()),
        PublicationError::RecoveryRequired("discarded original worker lost".into()),
    ] {
        let typed = matches!(&error, PublicationError::RecoveryRefusal(_));
        let mut scheduler = ExecSched::new(0, Backoff::default(), test_registrations());
        let body = original(1);
        scheduler.recover_proposal_admission(1, body.clone());
        recover(&mut scheduler, 0, 1, &body);
        scheduler.discard(1, vec![]);
        scheduler.done(0, ExecDone::ProposalAdmissionRecovered(Err(error)));
        assert_eq!(
            scheduler.halted(),
            Some(HaltReason::PublicationRecoveryRequired { height: 1 })
        );
        assert_eq!(scheduler.recovery_refusal().is_some(), typed);
        assert_eq!(
            scheduler.take_events(),
            vec![Event::PublicationRecoveryRequired { height: 1 }]
        );
        assert!(scheduler.next(u64::MAX).is_none());
    }
}

#[test]
fn proposal_recovery_replacement_rejects_stale_worker_and_retains_only_latest_body() {
    let mut scheduler = ExecSched::new(0, Backoff::default(), test_registrations());
    let first = original(1);
    scheduler.recover_proposal_admission(1, first.clone());
    recover(&mut scheduler, 0, 1, &first);
    for req in 2..=100 {
        scheduler.recover_proposal_admission(req, original(u8::try_from(req).unwrap()));
        assert_eq!(scheduler.queued_ops(), 1);
    }
    scheduler.done(
        0,
        ExecDone::ProposalAdmissionRecovered(Ok(built_payload(first.payload().clone()).admission)),
    );
    assert!(
        scheduler.take_events().is_empty(),
        "stale proposal recovery must not publish an admission for a replaced original body"
    );
    let last = original(100);
    let Some(ExecOp::RecoverProposalAdmission { req, body }) = scheduler.next(0) else {
        panic!("latest recovery")
    };
    assert_eq!(req, 100);
    assert_eq!(body, last);
    scheduler.done(
        0,
        ExecDone::ProposalAdmissionRecovered(Ok(built_payload(body.payload().clone()).admission)),
    );
    assert!(matches!(
        scheduler.take_events().as_slice(),
        [Event::ProposalAdmissionRecovered {
            req: 100,
            admission: Some(_)
        }]
    ));
}

#[test]
fn proposal_recovery_terminal_original_propagates_even_after_request_replacement() {
    let budget = iroha_allocation::AllocationBudget::new(0);
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    for error in [
        PublicationError::RecoveryRefusal(refusal.into()),
        PublicationError::RecoveryRequired("original worker lost".into()),
    ] {
        let typed = matches!(&error, PublicationError::RecoveryRefusal(_));
        let mut scheduler = ExecSched::new(0, Backoff::default(), test_registrations());
        let first = original(1);
        scheduler.recover_proposal_admission(1, first.clone());
        recover(&mut scheduler, 0, 1, &first);
        scheduler.recover_proposal_admission(2, original(2));
        scheduler.done(0, ExecDone::ProposalAdmissionRecovered(Err(error)));
        assert_eq!(
            scheduler.halted(),
            Some(HaltReason::PublicationRecoveryRequired { height: 1 }),
            "terminal proposal recovery must preserve the original failure after request replacement"
        );
        assert_eq!(scheduler.recovery_refusal().is_some(), typed);
        assert_eq!(
            scheduler.take_events(),
            vec![Event::PublicationRecoveryRequired { height: 1 }]
        );
        assert!(scheduler.next(u64::MAX).is_none());
    }
}

#[test]
fn proposal_recovery_waits_for_applied_parent_and_cannot_enter_commit_overlay() {
    use iroha_sumeragi::types::{AppliedConfig, ConfigSlot};

    let mut scheduler = ExecSched::new(0, Backoff::default(), test_registrations());
    let parent = original(1);
    let result = Hash32([8; 32]);
    let child = block(2, hash(&parent), result, vec![2]);
    scheduler.recover_proposal_admission(9, child.clone());
    assert!(scheduler.next(0).is_none());
    assert_eq!(scheduler.wakeup(), u64::MAX);
    scheduler.commit(parent.clone(), super::commit_qc(&parent, result));
    assert!(matches!(scheduler.next(0), Some(ExecOp::Prepare(_))));
    scheduler.done(0, ExecDone::Prepared(Ok(Some(result))));
    assert!(matches!(scheduler.next(0), Some(ExecOp::Append(_))));
    scheduler.done(
        0,
        ExecDone::Appended {
            durable: true,
            deferred: None,
        },
    );
    assert!(matches!(scheduler.next(0), Some(ExecOp::Commit(_))));
    scheduler.done(
        0,
        ExecDone::Committed(Ok(Box::new(AppliedConfig::Continuation {
            after_next: ConfigSlot::Ready(parent.source().config().clone()),
        }))),
    );
    assert_eq!(scheduler.applied(), 1);
    recover(&mut scheduler, 0, 9, &child);
}

#[test]
fn proposal_recovery_applied_body_retires_obsolete_refusal_without_minting_admission() {
    use iroha_sumeragi::types::{AppliedConfig, ConfigSlot};

    let mut scheduler = ExecSched::new(0, Backoff::default(), test_registrations());
    let body = original(1);
    scheduler.recover_proposal_admission(1, body.clone());
    recover(&mut scheduler, 0, 1, &body);
    scheduler.done(
        0,
        ExecDone::ProposalAdmissionRecovered(Err(PublicationError::Retryable(
            "original unavailable".into(),
        ))),
    );
    let result = Hash32([8; 32]);
    scheduler.commit(body.clone(), super::commit_qc(&body, result));
    assert!(matches!(scheduler.next(0), Some(ExecOp::Prepare(_))));
    scheduler.done(0, ExecDone::Prepared(Ok(Some(result))));
    assert!(matches!(scheduler.next(0), Some(ExecOp::Append(_))));
    scheduler.done(
        0,
        ExecDone::Appended {
            durable: true,
            deferred: None,
        },
    );
    assert!(matches!(scheduler.next(0), Some(ExecOp::Commit(_))));
    scheduler.done(
        0,
        ExecDone::Committed(Ok(Box::new(AppliedConfig::Continuation {
            after_next: ConfigSlot::Ready(body.source().config().clone()),
        }))),
    );
    assert_eq!(scheduler.applied(), 1);
    assert_eq!(scheduler.queued_ops(), 0);
    scheduler.recover_proposal_admission(2, body);
    assert!(scheduler.next(u64::MAX).is_none());
    assert_eq!(scheduler.wakeup(), u64::MAX);
    assert!(
        scheduler
            .take_events()
            .iter()
            .all(|event| !matches!(event, Event::ProposalAdmissionRecovered { .. }))
    );
}

#[test]
fn proposal_recovery_kernel_routes_exact_body_to_native_worker_without_control_view() {
    let (mut kernel, _) = start_kernel(0);
    let body = original(3);
    kernel.route(vec![Action::RecoverProposalAdmission {
        req: 91,
        body: body.clone(),
    }]);
    let op = kernel
        .poll(0)
        .into_iter()
        .find_map(|op| match op {
            Op::Exec(op @ ExecOp::RecoverProposalAdmission { .. }) => Some(op),
            _ => None,
        })
        .expect("recovery dispatch");
    let ExecOp::RecoverProposalAdmission {
        req,
        body: dispatched,
    } = &op
    else {
        unreachable!()
    };
    assert_eq!(*req, 91);
    assert_eq!(dispatched, &body);
    assert_eq!(
        dispatched.payload().as_slice().as_ptr(),
        body.payload().as_slice().as_ptr()
    );
    let mut executor =
        FakeExecutor::new(Hash32::ZERO, Hash32::ZERO, body.source().config().clone());
    let ExecDone::ProposalAdmissionRecovered(Ok(admission)) =
        run_exec(&mut executor, &FakeBlocks::default(), op)
    else {
        panic!("source-bound recovered owner")
    };
    admission
        .check(&proposal_signing_request(
            &body,
            hash(&body),
            0,
            Hash32::ZERO,
            false,
        ))
        .unwrap();
}
