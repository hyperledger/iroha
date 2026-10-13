//! A local refusal retains the exact accepted execution and cannot emit a completed verdict.

use super::*;
use crate::sumeragi::driver::tests::block;
use crate::sumeragi::driver::traits::PublicationDeferral;
use iroha_allocation::AllocationBudget;

fn scheduler(budget: &AllocationBudget) -> ExecSched {
    ExecSched::new(
        0,
        Backoff::default(),
        ExecutionRegistrations::admit(budget).unwrap(),
    )
}

#[test]
fn execution_pool_refusal_retains_same_job_without_event_then_retries_on_original_release() {
    let bytes = ExecutionRegistrations::admission_bytes();
    let budget = AllocationBudget::new(bytes + 1);
    let mut scheduler = scheduler(&budget);
    let held = budget.try_reserve_bytes(1).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let body = block(1, Hash32::ZERO, Hash32::ZERO, vec![1]);
    let hash = Hash32([7; 32]);
    scheduler.execute(9, hash, body, false);
    let Some(ExecOp::Execute { block: before, .. }) = scheduler.next(0) else {
        panic!("initial execution")
    };
    let cause = PublicationError::Deferred(PublicationDeferral::Execution(original.clone().into()));
    let allocations = crate::test_allocations::allocations_during(|| {
        scheduler.done(0, ExecDone::Executed(Err(cause)));
    });
    assert_eq!(
        allocations, 0,
        "refusal storage was admitted before the operation"
    );
    assert_eq!(scheduler.outstanding(), 1);
    assert!(scheduler.take_events().is_empty());
    let Some(PublicationError::Deferred(retained)) = &scheduler.execution_retry.error else {
        panic!("original refusal")
    };
    assert_eq!(retained.allocation_refusal(), Some(&original));
    assert!(Arc::ptr_eq(
        &before,
        &scheduler.deferred_execution.as_ref().unwrap().block
    ));
    assert_eq!(scheduler.wakeup(), Millis::MAX);
    assert!(scheduler.next(Millis::MAX - 1).is_none());
    let unrelated = AllocationBudget::new(1);
    drop(unrelated.try_reserve_bytes(1).unwrap());
    assert!(scheduler.next(Millis::MAX - 1).is_none());
    drop(held);
    let Some(ExecOp::Execute {
        block: retry,
        block_hash,
        ..
    }) = scheduler.next(0)
    else {
        panic!("original release retries same job")
    };
    assert!(Arc::ptr_eq(&before, &retry));
    assert_eq!(block_hash, hash);
    assert_eq!(scheduler.outstanding(), 1);
    assert!(scheduler.take_events().is_empty());
    let result = Hash32([8; 32]);
    scheduler.done(0, ExecDone::Executed(Ok(Some(ExecOutcome::Valid(result)))));
    assert_eq!(scheduler.outstanding(), 0);
    assert!(scheduler.execution_retry.error.is_none());
    let events = scheduler.take_events();
    assert!(
        matches!(events.as_slice(), [Event::Executed { req: 9, block_hash, outcome: ExecOutcome::Valid(actual) }] if *block_hash == hash && *actual == result)
    );
}

#[test]
fn execution_scoped_decoder_refusal_has_no_pool_wait_and_cancels_without_verdict() {
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes());
    let mut scheduler = scheduler(&budget);
    let captured = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || norito::core::classify_decode_attempt(|| norito::core::reserve_decode_allocation(1)),
    )
    .unwrap_err();
    let original = captured
        .into_local_refusal()
        .expect("genuine enclosing owner");
    let observed = original.clone();
    let body = block(1, Hash32::ZERO, Hash32::ZERO, vec![1]);
    scheduler.execute(3, Hash32([4; 32]), body, false);
    let Some(ExecOp::Execute { block: before, .. }) = scheduler.next(0) else {
        panic!("initial execution")
    };
    scheduler.done(
        0,
        ExecDone::Executed(Err(PublicationError::Deferred(
            crate::execution_attempt::ExecutionDeferred::from(
                ivm::error::VerificationRefusal::from_decode_refusal(original),
            )
            .into(),
        ))),
    );
    let Some(PublicationError::Deferred(retained)) = &scheduler.execution_retry.error else {
        panic!("retained decoder")
    };
    assert_eq!(
        retained.execution().unwrap().decode_refusal(),
        Some(&observed)
    );
    assert!(retained.release_wait().is_none());
    assert_ne!(scheduler.wakeup(), Millis::MAX);
    assert!(scheduler.next(0).is_none());
    assert!(scheduler.take_events().is_empty());
    let at = scheduler.wakeup();
    let Some(ExecOp::Execute { block: retry, .. }) = scheduler.next(at) else {
        panic!("bounded policy retry")
    };
    assert!(Arc::ptr_eq(&before, &retry));
    scheduler.discard(1, Vec::new());
    scheduler.done(
        at,
        ExecDone::Executed(Ok(Some(ExecOutcome::Valid(Hash32([6; 32]))))),
    );
    assert_eq!(scheduler.outstanding(), 0);
    assert!(scheduler.execution_retry.error.is_none());
    assert!(matches!(
        scheduler.take_events().as_slice(),
        [Event::Executed {
            req: 3,
            outcome: ExecOutcome::Cancelled,
            ..
        }]
    ));
    norito::core::classify_decode_attempt(|| norito::core::reserve_decode_allocation(1)).unwrap();
}

#[test]
fn execution_wait_cancellation_releases_original_job_before_any_retry() {
    let bytes = ExecutionRegistrations::admission_bytes();
    let budget = AllocationBudget::new(bytes + 1);
    let mut scheduler = scheduler(&budget);
    let held = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    scheduler.execute(
        5,
        Hash32([2; 32]),
        block(1, Hash32::ZERO, Hash32::ZERO, vec![1]),
        false,
    );
    assert!(matches!(scheduler.next(0), Some(ExecOp::Execute { .. })));
    scheduler.done(
        0,
        ExecDone::Executed(Err(PublicationError::Deferred(
            crate::execution_attempt::ExecutionDeferred::from(refusal).into(),
        ))),
    );
    assert!(scheduler.take_events().is_empty());
    scheduler.discard(1, Vec::new());
    assert!(scheduler.deferred_execution.is_none());
    assert!(scheduler.execution_retry.error.is_none());
    assert_eq!(scheduler.outstanding(), 0);
    assert!(matches!(
        scheduler.take_events().as_slice(),
        [Event::Executed {
            req: 5,
            outcome: ExecOutcome::Cancelled,
            ..
        }]
    ));
    drop(held);
    assert!(matches!(scheduler.next(0), Some(ExecOp::Discard { .. })));
    scheduler.done(0, ExecDone::Discarded);
    assert!(scheduler.next(Millis::MAX - 1).is_none());
    assert!(scheduler.take_events().is_empty());
}

#[test]
fn native_budget_and_cancelled_execution_keep_original_cause_without_a_pool_wait() {
    use iroha_plonk::{
        pcs::ipa::IpaError,
        verification_attempt::{
            VerificationAttemptError, VerificationRefusalKind, native_verification_error,
        },
        verifier::VerifyError,
    };
    let budget_error = iroha_pasta::msm::MemoryBudget::new(0)
        .check(31)
        .unwrap_err();
    let cancellation = iroha_pasta::CancellationToken::new();
    assert!(iroha_pasta::CancellationToken::checkpoint(Some(&cancellation)).is_ok());
    cancellation.cancel();
    let cancelled = iroha_pasta::CancellationToken::checkpoint(Some(&cancellation)).unwrap_err();
    for (original, kind) in [
        (
            VerifyError::Ipa(IpaError::Msm(budget_error.into())),
            VerificationRefusalKind::NativeMemoryBudget,
        ),
        (
            VerifyError::from(cancelled),
            VerificationRefusalKind::NativeCancelled,
        ),
    ] {
        let pool = AllocationBudget::new(ExecutionRegistrations::admission_bytes());
        let mut scheduler = scheduler(&pool);
        let native = Box::new(original);
        let address: *const VerifyError = &*native;
        let attempt = native_verification_error(
            VerifyError::BatchItem {
                index: 1,
                error: native,
            },
            |_| -> () { panic!("unfinished native operation cannot reject") },
        );
        let VerificationAttemptError::Deferred(original) = attempt else {
            panic!("actual native refusal")
        };
        scheduler.execute(
            17,
            Hash32([9; 32]),
            block(1, Hash32::ZERO, Hash32::ZERO, vec![1]),
            false,
        );
        let Some(ExecOp::Execute { block: before, .. }) = scheduler.next(0) else {
            panic!("first attempt")
        };
        let failure = PublicationError::Deferred(
            crate::execution_attempt::ExecutionDeferred::from(original).into(),
        );
        let allocations = crate::test_allocations::allocations_during(|| {
            scheduler.done(0, ExecDone::Executed(Err(failure)));
        });
        assert_eq!(
            allocations, 0,
            "all retention and wait storage was admitted before execution"
        );
        let Some(PublicationError::Deferred(retained)) = &scheduler.execution_retry.error else {
            panic!("original native cause retained")
        };
        assert!(retained.allocation_refusal().is_none());
        assert!(retained.release_wait().is_none());
        let native = retained
            .execution()
            .unwrap()
            .verification_refusal()
            .unwrap();
        assert_eq!(native.kind(), kind);
        let Some(VerifyError::BatchItem { error, .. }) = native.native_verification_error() else {
            panic!("original nested owner")
        };
        let retained_address: *const VerifyError = &**error;
        assert_eq!(retained_address, address);
        let wakeup = scheduler.wakeup();
        assert_ne!(wakeup, Millis::MAX);
        assert!(wakeup > 0);
        assert!(scheduler.take_events().is_empty());
        // Even a real unrelated release cannot turn a native policy cause into a pool wait.
        let unrelated = AllocationBudget::new(1);
        drop(unrelated.try_reserve_bytes(1).unwrap());
        assert!(scheduler.next(wakeup - 1).is_none());
        let Some(ExecOp::Execute { block: retry, .. }) = scheduler.next(wakeup) else {
            panic!("existing bounded retry policy")
        };
        assert!(Arc::ptr_eq(&before, &retry));
        assert!(scheduler.take_events().is_empty());
        scheduler.done(
            wakeup,
            ExecDone::Executed(Ok(Some(ExecOutcome::Valid(Hash32([10; 32]))))),
        );
        assert!(matches!(
            scheduler.take_events().as_slice(),
            [Event::Executed {
                req: 17,
                outcome: ExecOutcome::Valid(_),
                ..
            }]
        ));
        assert_eq!(scheduler.outstanding(), 0);
        assert!(scheduler.execution_retry.error.is_none());
    }
}

#[test]
fn trusted_initializer_recovery_retains_original_and_halts_without_publication_or_retry() {
    use iroha_plonk::verification_attempt::{NativeVerifierInitError, VerificationRefusal};

    // Exercise a real poisoned initializer gate, using the same checked lock operation as
    // the native initializer. This is not a fabricated allocator or cancellation report.
    let gate = std::sync::Mutex::new(());
    let panicked = std::panic::catch_unwind(|| {
        let _held = gate.lock().unwrap();
        panic!("initializer failed while holding its original gate");
    });
    assert!(panicked.is_err());
    let poison = match gate.lock() {
        Err(_) => NativeVerifierInitError::CachePoisoned,
        Ok(_) => panic!("the actual initializer gate must be poisoned"),
    };
    // A genuine checked trusted-carrier extent conversion fails before initialization.
    let invariant = u32::try_from(u64::MAX)
        .map(|_| ())
        .map_err(|_| NativeVerifierInitError::Invariant("trusted carrier extent exceeds u32"))
        .unwrap_err();
    for (original, cancelled) in [(poison, false), (invariant, true)] {
        let is_poisoned = matches!(&original, NativeVerifierInitError::CachePoisoned);
        let original = crate::execution_attempt::ExecutionDeferred::from(
            VerificationRefusal::initialization(original),
        );
        assert_eq!(
            original.reason(),
            ivm::ExecutionDeferral::LocalInvariantViolation
        );
        assert!(original.allocation_refusal().is_none());
        let cause = PublicationError::from(
            crate::execution_attempt::ExecutionAttemptError::<String>::Deferred(original),
        );
        assert!(matches!(&cause, PublicationError::RecoveryRefusal(_)));
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes());
        let mut scheduler = scheduler(&budget);
        scheduler.execute(
            17,
            Hash32([7; 32]),
            block(1, Hash32::ZERO, Hash32::ZERO, vec![1]),
            false,
        );
        assert!(matches!(scheduler.next(0), Some(ExecOp::Execute { .. })));
        if cancelled {
            scheduler.discard(1, Vec::new());
        }
        scheduler.done(0, ExecDone::Executed(Err(cause)));
        assert!(matches!(
            scheduler.halted(),
            Some(HaltReason::PublicationRecoveryRequired { height: 1 })
        ));
        let retained = scheduler
            .recovery_refusal()
            .expect("terminal halt retains original owner");
        let initializer = retained
            .verification_refusal()
            .unwrap()
            .initialization_error()
            .unwrap();
        if is_poisoned {
            assert!(matches!(
                initializer,
                NativeVerifierInitError::CachePoisoned
            ));
        } else {
            assert!(matches!(
                initializer,
                NativeVerifierInitError::Invariant("trusted carrier extent exceeds u32")
            ));
        }
        assert!(retained.allocation_refusal().is_none());
        assert!(retained.decode_refusal().is_none());
        assert!(scheduler.execution_retry.error.is_none());
        assert!(scheduler.deferred_execution.is_none());
        assert_eq!(scheduler.wakeup(), Millis::MAX);
        assert!(scheduler.next(Millis::MAX - 1).is_none());
        assert_eq!(scheduler.outstanding(), 0);
        let events = scheduler.take_events();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::PublicationRecoveryRequired { height: 1 }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Executed {
                req: 17,
                outcome: ExecOutcome::Cancelled,
                ..
            }
        )));
        assert!(!events.iter().any(|event| matches!(
            event,
            Event::BlockApplied { .. }
                | Event::PayloadBuilt { .. }
                | Event::Executed {
                    outcome: ExecOutcome::Valid(_) | ExecOutcome::Invalid | ExecOutcome::Failed(_),
                    ..
                }
        )));
        assert!(
            scheduler.recovery_refusal().is_some(),
            "reading events cannot consume the cause"
        );
    }
}

fn checked_extent_recovery() -> PublicationError {
    use iroha_plonk::verification_attempt::{NativeVerifierInitError, VerificationRefusal};
    let original = u32::try_from(u64::MAX)
        .map(|_| ())
        .map_err(|_| NativeVerifierInitError::Invariant("original checked initializer extent"))
        .unwrap_err();
    PublicationError::RecoveryRefusal(VerificationRefusal::initialization(original).into())
}

fn assert_original_recovery_halt(scheduler: &mut ExecSched, height: u64) {
    use iroha_plonk::verification_attempt::NativeVerifierInitError;
    assert!(
        matches!(scheduler.halted(), Some(HaltReason::PublicationRecoveryRequired { height: actual }) if actual == height)
    );
    assert!(matches!(
        scheduler
            .recovery_refusal()
            .unwrap()
            .verification_refusal()
            .unwrap()
            .initialization_error(),
        Some(NativeVerifierInitError::Invariant(
            "original checked initializer extent"
        ))
    ));
    assert!(scheduler.running.is_none());
    assert!(scheduler.execution_retry.error.is_none());
    assert_eq!(scheduler.wakeup(), Millis::MAX);
    assert!(scheduler.next(Millis::MAX - 1).is_none());
    let events = scheduler.take_events();
    assert!(events.iter().any(|event| matches!(event, Event::PublicationRecoveryRequired { height: actual } if *actual == height)));
    assert!(!events.iter().any(|event| matches!(
        event,
        Event::BlockApplied { .. }
            | Event::PayloadBuilt { .. }
            | Event::ControlWitnessBuilt { .. }
            | Event::ApplicationControlBuilt { .. }
            | Event::Executed {
                outcome: ExecOutcome::Valid(_) | ExecOutcome::Invalid | ExecOutcome::Failed(_),
                ..
            }
    )));
    assert!(scheduler.recovery_refusal().is_some());
}

#[test]
fn recovery_original_survives_mismatched_completion_kind_and_absent_running_job() {
    for active in [false, true] {
        let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes());
        let mut scheduler = scheduler(&budget);
        if active {
            scheduler.execute(
                73,
                Hash32([3; 32]),
                block(1, Hash32::ZERO, Hash32::ZERO, vec![1]),
                false,
            );
            assert!(matches!(scheduler.next(0), Some(ExecOp::Execute { .. })));
        }
        // No Build is in flight in either case; the original cannot be discarded by the
        // generic unmatched-completion arm or an early return for absent running work.
        scheduler.done(0, ExecDone::Built(Err(checked_extent_recovery())));
        assert_original_recovery_halt(&mut scheduler, u64::from(active));
        assert_eq!(scheduler.outstanding(), 0);
    }
}

#[test]
fn recovery_original_survives_replaced_control_completion_identity() {
    let budget = AllocationBudget::new(ExecutionRegistrations::admission_bytes());
    let mut scheduler = scheduler(&budget);
    let context = ApplicationControlContext {
        instance: Hash32([5; 32]),
        epoch: iroha_sumeragi::testing::TEST_EPOCH.id,
        height: 1,
        parent_hash: Hash32([6; 32]),
        parent_result: Hash32([7; 32]),
    };
    scheduler.retain_control_context(Some((context, 3)));
    let from = PublicKey::new(vec![8; 32]).unwrap();
    let message = ApplicationControl {
        context,
        bytes: ControlWitness::try_from_slice(&[19; 64]).unwrap(),
    };
    scheduler.receive_control(from, message);
    let Some(ExecOp::ReceiveApplicationControl {
        occurrence,
        from,
        mut message,
    }) = scheduler.next(0)
    else {
        panic!("the original peer control job must be in flight");
    };
    message.context.height = 99;
    scheduler.done(
        0,
        ExecDone::ApplicationControlReceived {
            occurrence,
            from,
            message,
            result: Err(checked_extent_recovery()),
        },
    );
    // The halt uses the retained accepted identity, not the substituted completion height.
    assert_original_recovery_halt(&mut scheduler, 1);
    assert!(
        scheduler
            .inbound
            .iter()
            .all(|slot| slot.input.is_none() && slot.retry.error.is_none())
    );
}
