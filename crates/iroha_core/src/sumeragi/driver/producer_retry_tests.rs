//! Bounded execution producers retain exact requests, native sources and partial custody.

use super::*;
use crate::sumeragi::driver::traits::PublicationDeferral;
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, release::ReleaseNotification,
};

fn source() -> ApplicationControlContext {
    ApplicationControlContext {
        instance: Hash32([5; 32]),
        epoch: iroha_sumeragi::testing::TEST_EPOCH.id,
        height: 1,
        parent_hash: Hash32([6; 32]),
        parent_result: Hash32([7; 32]),
    }
}
fn witness(context: ApplicationControlContext, view: u64) -> ControlWitnessContext {
    ControlWitnessContext {
        height: context.height,
        view,
        epoch: context.epoch,
        parent_hash: context.parent_hash,
        parent_result: context.parent_result,
    }
}
fn partial(context: ApplicationControlContext, tag: u8) -> ApplicationControl {
    ApplicationControl {
        context,
        bytes: ControlWitness::try_from_slice(&[tag; 64]).unwrap(),
    }
}
fn key(tag: usize) -> PublicKey {
    let mut bytes = vec![0; 32];
    bytes[..8].copy_from_slice(&(tag as u64).to_le_bytes());
    PublicKey::new(bytes).unwrap()
}
fn key_index(key: &PublicKey) -> usize {
    u64::from_le_bytes(key.as_bytes()[..8].try_into().unwrap()) as usize
}
fn scheduler(budget: &AllocationBudget) -> ExecSched {
    let mut result = ExecSched::new(
        0,
        Backoff::default(),
        ExecutionRegistrations::admit(budget).unwrap(),
    );
    result.retain_control_context(Some((source(), 3)));
    result
}
fn capacity(
    budget: &AllocationBudget,
) -> (iroha_allocation::AllocationReservation, PublicationError) {
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    assert!(matches!(refusal, AllocationRefusal::Capacity { .. }));
    (
        occupied,
        PublicationError::Deferred(PublicationDeferral::Execution(refusal.into())),
    )
}
fn notify(budget: &AllocationBudget) -> ReleaseNotification {
    let layout = ReleaseNotification::allocation_layout::<AllocationCharge>();
    let mut reservation = budget.try_reserve(layout).unwrap();
    ReleaseNotification::try_new_charged(reservation.try_split(layout).unwrap()).unwrap()
}
fn enqueue(scheduler: &mut ExecSched, kind: usize, message: &ApplicationControl) {
    match kind {
        0 => scheduler.build(11, 1, 3, 1024, 100),
        1 => scheduler.build_control(12, witness(source(), 3)),
        2 => scheduler.drive_control(source()),
        3 => scheduler.receive_control(key(8), message.clone()),
        _ => unreachable!(),
    }
}
fn refuse(scheduler: &mut ExecSched, operation: ExecOp, error: PublicationError) {
    let done = match operation {
        ExecOp::Build { .. } => ExecDone::Built(Err(error)),
        ExecOp::BuildControlWitness { .. } => ExecDone::ControlWitnessBuilt(Err(error)),
        ExecOp::DriveApplicationControl(_) => ExecDone::ApplicationControlDriven(Err(error)),
        ExecOp::ReceiveApplicationControl {
            occurrence,
            from,
            message,
        } => ExecDone::ApplicationControlReceived {
            occurrence,
            from,
            message,
            result: Err(error),
        },
        other => panic!("unexpected producer: {other:?}"),
    };
    scheduler.done(0, done);
}

#[test]
fn every_execution_producer_retains_original_source_until_actual_release() {
    for kind in 0..4 {
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
        let mut sched = scheduler(&budget);
        let message = partial(source(), 19);
        enqueue(&mut sched, kind, &message);
        let original = sched.next(0).expect("original producer");
        let expected = original.clone();
        let (occupied, error) = capacity(&budget);
        refuse(&mut sched, original, error.clone());
        assert!(sched.take_events().is_empty());
        assert!(sched.next(0).is_none());
        assert_eq!(sched.wakeup(), Millis::MAX);
        // Both periodic dispatch and retransmission must preserve this exact pending source.
        enqueue(&mut sched, kind, &message);
        assert!(sched.next(Millis::MAX - 1).is_none());
        assert_eq!(sched.wakeup(), Millis::MAX);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        let gate = match kind {
            0 => &sched.payload_retry,
            1 => &sched.witness_retry,
            2 => &sched.drive_retry,
            _ => sched
                .inbound
                .iter()
                .map(|slot| &slot.retry)
                .find(|gate| gate.error.is_some())
                .unwrap(),
        };
        assert_eq!(gate.error.as_ref(), Some(&error));
        drop(occupied);
        let retry = sched
            .next(0)
            .expect("release permits retry before old backoff");
        assert_eq!(retry, expected);
        if let (
            ExecOp::ReceiveApplicationControl { message: retry, .. },
            ExecOp::ReceiveApplicationControl {
                message: original, ..
            },
        ) = (&retry, &expected)
        {
            assert_eq!(retry.bytes, original.bytes);
        }
        drop(retry);
        drop(expected);
        drop(message);
        drop(error);
        drop(sched);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn scheduler_controls_admit_all_or_none_from_the_original_pool() {
    let bytes = ExecutionRegistrations::admission_bytes();
    assert_eq!(
        bytes,
        std::alloc::Layout::array::<InboundSlot>(MAX_COMMITTEE_SIZE)
            .unwrap()
            .size()
            + ReleaseRegistration::allocation_layout().size() * (4 + MAX_COMMITTEE_SIZE)
    );
    let budget = AllocationBudget::new(bytes - 1);
    assert!(
        matches!(ExecutionRegistrations::admit(&budget), Err(super::super::KernelStartError::Admission(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes })) if requested_bytes == bytes && limit_bytes == bytes - 1)
    );
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(bytes);
    let blocker = budget.try_reserve_bytes(1).unwrap();
    assert!(
        matches!(ExecutionRegistrations::admit(&budget), Err(super::super::KernelStartError::Admission(AllocationRefusal::Capacity { requested_bytes, .. })) if requested_bytes == bytes)
    );
    assert_eq!(budget.reserved_bytes(), 1);
    drop(blocker);
    let registrations = ExecutionRegistrations::admit(&budget).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    assert!(registrations.inbound.slots.belongs_to(&budget));
    assert_eq!(registrations.inbound.slots.capacity(), MAX_COMMITTEE_SIZE);
    assert_eq!(
        registrations.inbound.slots.as_slice().len(),
        MAX_COMMITTEE_SIZE
    );
    assert!(
        registrations
            .inbound
            .iter()
            .all(|slot| slot.retry.registration.belongs_to(&budget))
    );
    for control in [
        &registrations.committed,
        &registrations.payload,
        &registrations.witness,
        &registrations.drive,
    ] {
        assert!(control.belongs_to(&budget));
    }
    drop(registrations);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn independent_blocked_partial_slots_keep_all_peers_and_original_occurrences() {
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
    let mut sched = scheduler(&budget);
    let notifications: [_; MAX_COMMITTEE_SIZE] = std::array::from_fn(|_| notify(&budget));
    let locks: [_; MAX_COMMITTEE_SIZE] = std::array::from_fn(|_| std::sync::Mutex::new(()));
    let mut held: [_; MAX_COMMITTEE_SIZE] =
        std::array::from_fn(|i| Some(notifications[i].guard(locks[i].lock().unwrap())));
    for index in 0..MAX_COMMITTEE_SIZE {
        let message = partial(source(), index as u8);
        sched.receive_control(key(index), message);
    }
    assert_eq!(sched.queued_ops(), MAX_COMMITTEE_SIZE);
    let occurrences: [_; MAX_COMMITTEE_SIZE] =
        std::array::from_fn(|index| sched.inbound[index].input.as_ref().unwrap().occurrence);
    for _ in 0..MAX_COMMITTEE_SIZE {
        let Some(ExecOp::ReceiveApplicationControl {
            occurrence,
            from,
            message,
        }) = sched.next(0)
        else {
            panic!("each peer gets its independent attempt")
        };
        let index = key_index(&from);
        assert_eq!(occurrence, occurrences[index]);
        assert_eq!(message, partial(source(), index as u8));
        // In-flight custody consumes the same bounded seat; conflicting ingress cannot replace it.
        sched.receive_control(from.clone(), partial(source(), 253));
        sched.done(
            0,
            ExecDone::ApplicationControlReceived {
                occurrence,
                from,
                message,
                result: Err(PublicationError::Deferred(
                    PublicationDeferral::StateViewBusy(notifications[index].observe()),
                )),
            },
        );
    }
    assert!(sched.next(Millis::MAX - 1).is_none());
    assert_eq!(sched.queued_ops(), MAX_COMMITTEE_SIZE);
    let freed = MAX_COMMITTEE_SIZE / 2;
    drop(held[freed].take());
    let Some(ExecOp::ReceiveApplicationControl {
        occurrence,
        from,
        message,
    }) = sched.next(0)
    else {
        panic!("one actual peer release must bypass blocked peers")
    };
    assert_eq!(key_index(&from), freed);
    assert_eq!(occurrence, occurrences[freed]);
    assert_eq!(message, partial(source(), freed as u8));
    sched.done(
        0,
        ExecDone::ApplicationControlReceived {
            occurrence,
            from,
            message,
            result: Ok(()),
        },
    );
    sched.build(44, 1, 3, 1024, 100);
    assert!(matches!(sched.next(0), Some(ExecOp::Build { req: 44, .. })));
    sched.done(0, ExecDone::Built(Ok(None)));
    assert!(
        sched
            .take_events()
            .iter()
            .any(|event| matches!(event, Event::PayloadBuilt { req: 44, .. }))
    );
    sched.retain_control_context(None);
    assert_eq!(sched.queued_ops(), 0);
    assert!(sched.inbound.iter().all(|slot| slot.retry.error.is_none()));
    drop(held);
    drop(locks);
    drop(notifications);
    drop(sched);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn accepted_share_accelerates_only_source_less_witness_retry() {
    for physical in [false, true] {
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
        let mut sched = scheduler(&budget);
        let release = notify(&budget);
        let lock = std::sync::Mutex::new(());
        let held = release.guard(lock.lock().unwrap());
        sched.build_control(17, witness(source(), 3));
        let operation = sched.next(0).unwrap();
        let error = if physical {
            PublicationError::Deferred(PublicationDeferral::StateViewBusy(release.observe()))
        } else {
            PublicationError::Retryable("awaiting actual shares".into())
        };
        refuse(&mut sched, operation, error);
        assert!(sched.next(0).is_none());
        sched.receive_control(key(1), partial(source(), 9));
        let Some(ExecOp::ReceiveApplicationControl {
            occurrence,
            from,
            message,
        }) = sched.next(0)
        else {
            panic!("independent partial")
        };
        sched.done(
            0,
            ExecDone::ApplicationControlReceived {
                occurrence,
                from,
                message,
                result: Ok(()),
            },
        );
        if physical {
            assert!(sched.next(Millis::MAX - 1).is_none());
            drop(held);
        } else {
            drop(held);
        }
        assert!(matches!(
            sched.next(0),
            Some(ExecOp::BuildControlWitness { req: 17, .. })
        ));
    }
}

#[test]
fn payload_arrival_survives_source_wait_and_does_not_emit_false_empty() {
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
    let mut sched = scheduler(&budget);
    sched.build(10, 1, 3, 1024, 100);
    assert!(matches!(sched.next(0), Some(ExecOp::Build { req: 10, .. })));
    sched.done(0, ExecDone::Built(Ok(None)));
    sched.take_events();
    // A superseded empty request cannot steal the arrival owed to the next build.
    sched.build(11, 1, 3, 1024, 100);
    let first = sched.next(0).unwrap();
    let (held, error) = capacity(&budget);
    refuse(&mut sched, first, error);
    sched.transactions_available();
    assert!(sched.take_events().is_empty());
    assert!(sched.next(Millis::MAX - 1).is_none());
    drop(held);
    assert!(matches!(sched.next(0), Some(ExecOp::Build { req: 11, .. })));
    sched.done(0, ExecDone::Built(Ok(None)));
    let events = sched.take_events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::PayloadReady { req: 11 }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                Event::PayloadBuilt {
                    req: 11,
                    payload: None,
                    ..
                }
            ))
            .count(),
        1
    );
    sched.transactions_available();
    assert!(sched.take_events().is_empty(), "one Ready per request");
}

#[test]
fn complete_context_change_cancels_waits_and_stale_inflight_results() {
    for field in 0..7 {
        for kind in 0..4 {
            for in_flight in [false, true] {
                let budget =
                    AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
                let mut sched = scheduler(&budget);
                let message = partial(source(), 17);
                enqueue(&mut sched, kind, &message);
                let original = sched.next(0).unwrap();
                let (held, error) = capacity(&budget);
                let mut original = Some(original);
                if !in_flight {
                    refuse(&mut sched, original.take().unwrap(), error.clone());
                    assert!(sched.next(0).is_none());
                }
                let mut changed = source();
                let mut view = 3;
                match field {
                    0 => changed.instance = Hash32([11; 32]),
                    1 => changed.epoch.epoch += 1,
                    2 => changed.epoch.context = Hash32([12; 32]),
                    3 => changed.parent_hash = Hash32([13; 32]),
                    4 => changed.parent_result = Hash32([14; 32]),
                    5 => changed.height += 1,
                    _ => view += 1,
                }
                sched.retain_control_context(Some((changed, view)));
                // View-independent drive and partial requests intentionally survive a view change.
                let retained = field == 6 && kind >= 2;
                if let Some(original) = original {
                    refuse(&mut sched, original, error);
                }
                if retained {
                    assert!(sched.next(Millis::MAX - 1).is_none());
                } else {
                    assert_eq!(sched.queued_ops(), 0);
                    assert!(sched.next(Millis::MAX - 1).is_none());
                }
                assert!(sched.take_events().is_empty());
                drop(held);
                if retained {
                    assert!(sched.next(0).is_some());
                } else {
                    assert!(sched.next(0).is_none());
                }
            }
        }
    }
}

#[test]
fn identical_source_less_requests_keep_backoff_and_full_payload_changes_supersede() {
    for kind in 0..4 {
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
        let mut sched = scheduler(&budget);
        let message = partial(source(), 24);
        enqueue(&mut sched, kind, &message);
        let original = sched.next(0).unwrap();
        refuse(
            &mut sched,
            original,
            PublicationError::Retryable("original local retry".into()),
        );
        enqueue(&mut sched, kind, &message);
        assert_eq!(sched.wakeup(), 10);
        assert!(sched.next(9).is_none());
        assert!(sched.next(10).is_some());
    }
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
    let mut sched = scheduler(&budget);
    sched.build(11, 1, 3, 1024, 100);
    let old = sched.next(0).unwrap();
    // The request id alone cannot merge differently scoped work.
    sched.build(11, 1, 3, 2048, 200);
    assert!(matches!(
        old,
        ExecOp::Build {
            max_bytes: 1024,
            exec_budget_ms: 100,
            ..
        }
    ));
    sched.done(0, ExecDone::Built(Ok(None)));
    assert!(sched.take_events().is_empty());
    assert!(matches!(
        sched.next(0),
        Some(ExecOp::Build {
            req: 11,
            max_bytes: 2048,
            exec_budget_ms: 200,
            ..
        })
    ));
}

#[test]
fn worker_moves_inline_control_occurrence_and_rejects_replacement() {
    use crate::sumeragi::driver::tests::fakes::{FakeBlocks, FakeExecutor};
    for replacement in 0..5 {
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
        let mut sched = scheduler(&budget);
        let message = partial(source(), 17);
        sched.receive_control(key(2), message.clone());
        let operation = sched.next(0).unwrap();
        let expected = match &operation {
            ExecOp::ReceiveApplicationControl { occurrence, .. } => *occurrence,
            _ => panic!("original partial"),
        };
        let mut executor = FakeExecutor::new(
            Hash32::ZERO,
            Hash32::ZERO,
            iroha_sumeragi::types::HeightConfig {
                epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
                committee: iroha_sumeragi::types::Committee::new((0..4).map(key).collect())
                    .unwrap(),
                params: iroha_sumeragi::types::ChainParams::default(),
            },
        );
        let mut done = super::super::run_exec(&mut executor, &FakeBlocks::default(), operation);
        let ExecDone::ApplicationControlReceived {
            occurrence,
            from,
            message: returned,
            result,
        } = &mut done
        else {
            panic!("worker returns the same bounded inline input and occurrence");
        };
        assert_eq!(*occurrence, expected);
        assert_eq!(*returned, message);
        assert!(result.is_ok());
        match replacement {
            0 => {}
            1 => *occurrence = ControlOccurrence(expected.0 + 1),
            2 => returned.context.parent_result = Hash32([99; 32]),
            3 => returned.bytes = ControlWitness::try_from_slice(&[18; 64]).unwrap(),
            _ => *from = key(3),
        }
        sched.done(0, done);
        if replacement == 0 {
            assert!(
                sched.halted().is_none(),
                "moving inline bytes preserves their value identity"
            );
            assert_eq!(sched.queued_ops(), 0);
        } else {
            assert_eq!(
                sched.halted(),
                Some(HaltReason::PublicationRecoveryRequired { height: 1 })
            );
        }
        assert!(sched.next(Millis::MAX).is_none());
        assert!(sched.inbound.iter().all(|slot| slot.retry.error.is_none()));
    }
}

#[test]
fn stale_success_cannot_emit_control_or_hide_terminal_recovery() {
    for kind in 0..4 {
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
        let mut sched = scheduler(&budget);
        let message = partial(source(), 17);
        enqueue(&mut sched, kind, &message);
        let original = sched.next(0).unwrap();
        sched.retain_control_context(None);
        let result = match original {
            ExecOp::Build { .. } => ExecDone::Built(Ok(None)),
            ExecOp::BuildControlWitness { .. } => {
                ExecDone::ControlWitnessBuilt(Ok(ControlWitness::empty()))
            }
            ExecOp::DriveApplicationControl(_) => {
                ExecDone::ApplicationControlDriven(Ok(Some(message)))
            }
            ExecOp::ReceiveApplicationControl {
                occurrence,
                from,
                message,
            } => ExecDone::ApplicationControlReceived {
                occurrence,
                from,
                message,
                result: Ok(()),
            },
            _ => unreachable!(),
        };
        sched.done(0, result);
        assert!(sched.take_events().is_empty());
        assert_eq!(sched.queued_ops(), 0);
    }
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
    let mut sched = scheduler(&budget);
    sched.build(11, 1, 3, 1024, 100);
    assert!(matches!(sched.next(0), Some(ExecOp::Build { .. })));
    sched.build(12, 1, 3, 1024, 100);
    sched.done(
        0,
        ExecDone::Built(Err(PublicationError::RecoveryRequired(
            "consuming original builder lost".into(),
        ))),
    );
    assert_eq!(
        sched.halted(),
        Some(HaltReason::PublicationRecoveryRequired { height: 1 })
    );
    assert!(sched.next(Millis::MAX).is_none());
}

#[test]
fn cancellation_stays_final_when_the_identical_context_and_request_return() {
    for kind in 0..4 {
        for successful in [false, true] {
            let budget =
                AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
            let mut sched = scheduler(&budget);
            let message = partial(source(), 17);
            enqueue(&mut sched, kind, &message);
            let original = sched.next(0).unwrap();
            sched.retain_control_context(None);
            sched.retain_control_context(Some((source(), 3)));
            enqueue(&mut sched, kind, &message);
            if successful {
                let done = match original {
                    ExecOp::Build { .. } => ExecDone::Built(Ok(None)),
                    ExecOp::BuildControlWitness { .. } => {
                        ExecDone::ControlWitnessBuilt(Ok(ControlWitness::empty()))
                    }
                    ExecOp::DriveApplicationControl(_) => {
                        ExecDone::ApplicationControlDriven(Ok(Some(message.clone())))
                    }
                    ExecOp::ReceiveApplicationControl {
                        occurrence,
                        from,
                        message,
                    } => ExecDone::ApplicationControlReceived {
                        occurrence,
                        from,
                        message,
                        result: Ok(()),
                    },
                    _ => unreachable!(),
                };
                sched.done(0, done);
            } else {
                refuse(
                    &mut sched,
                    original,
                    PublicationError::Retryable("cancelled original".into()),
                );
            }
            assert!(
                sched.take_events().is_empty(),
                "a cancelled original cannot finish new work"
            );
            if kind == 3 {
                // The old in-flight sender still owns its slot; subsequent retransmission
                // enters only after that original input is returned and retired.
                assert!(sched.next(0).is_none());
                enqueue(&mut sched, kind, &message);
            }
            assert!(
                sched.next(0).is_some(),
                "the new exact request has no old backoff"
            );
        }
    }
}

#[test]
fn lane_sized_peer_inputs_above_global_bound_keep_independent_progress() {
    // A valid 3f+1 lane committee exceeds the global chain's 31-seat maximum.
    let members = 64;
    assert!(members > iroha_data_model::block::consensus::MAX_VALIDATORS_PER_HEIGHT);
    assert!(members <= iroha_data_model::consensus::MAX_LANE_CONSENSUS_VALIDATORS);
    let committee = iroha_sumeragi::types::Committee::new((0..members).map(key).collect()).unwrap();
    assert_eq!(committee.n(), 3 * committee.f() + 1);
    assert_eq!(committee.q(), committee.n() - committee.f());
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + (1 << 20));
    let mut sched = scheduler(&budget);
    for index in 0..members {
        sched.receive_control(key(index), partial(source(), index as u8));
    }
    assert_eq!(sched.queued_ops(), members);
    let released = notify(&budget);
    let lock = std::sync::Mutex::new(());
    let held = released.guard(lock.lock().unwrap());
    let original = sched.next(0).unwrap();
    refuse(
        &mut sched,
        original,
        PublicationError::Deferred(PublicationDeferral::StateViewBusy(released.observe())),
    );
    let mut received = vec![false; members];
    for _ in 1..members {
        let Some(ExecOp::ReceiveApplicationControl {
            occurrence,
            from,
            message,
        }) = sched.next(0)
        else {
            panic!("one blocked peer cannot obstruct the larger lane committee")
        };
        let index = key_index(&from);
        assert!(index > 0 && !received[index]);
        received[index] = true;
        sched.done(
            0,
            ExecDone::ApplicationControlReceived {
                occurrence,
                from,
                message,
                result: Ok(()),
            },
        );
    }
    assert!(received[1..].iter().all(|seen| *seen));
    assert!(sched.next(Millis::MAX - 1).is_none());
    drop(held);
    let Some(ExecOp::ReceiveApplicationControl {
        occurrence,
        from,
        message,
    }) = sched.next(0)
    else {
        panic!("the originally blocked lane peer keeps its owed retry")
    };
    assert_eq!(key_index(&from), 0);
    sched.done(
        0,
        ExecDone::ApplicationControlReceived {
            occurrence,
            from,
            message,
            result: Ok(()),
        },
    );
    assert_eq!(sched.queued_ops(), 0);
    drop(sched);
    drop(released);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cancelling_and_dropping_scheduler_unlinks_all_waiters_before_original_refunds() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
    };
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    for retirement in 0..3 {
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes() + 1024);
        let mut sched = Some(scheduler(&budget));
        let count = Arc::new(Count(AtomicUsize::new(0)));
        sched
            .as_mut()
            .unwrap()
            .bind_release_waker(Waker::from(Arc::clone(&count)));
        let message = partial(source(), 17);
        let (held, error) = capacity(&budget);
        for kind in 0..4 {
            let sched = sched.as_mut().unwrap();
            enqueue(sched, kind, &message);
            let operation = sched.next(0).expect("independent original producer");
            refuse(sched, operation, error.clone());
        }
        assert!(sched.as_mut().unwrap().next(0).is_none());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        match retirement {
            0 => sched.as_mut().unwrap().retain_control_context(None),
            1 => sched
                .as_mut()
                .unwrap()
                .require_recovery(1, "original worker unavailable"),
            _ => drop(sched.take()),
        }
        // Dropping the scheduler returns actual prepaid bank/control bytes to the
        // same saturated pool. No observer of cancelled work may remain linked.
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        drop(held);
        assert_eq!(
            count.0.load(Ordering::SeqCst),
            0,
            "original source released after cancellation"
        );
        drop(sched);
        drop(error);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
