//! Real original-pool preparation failures retain exact queued ownership through publication.

use super::super::{CommitTelemetryOrigin, PublicationPhase, publication_tests};
use super::*;
use crate::sumeragi::{
    commitment::{
        CertificatePart, MAX_RESULT_PREIMAGE_BYTES, ResultPreimageError, encode_certificate_part,
    },
    driver::{
        exec::{ExecDone, ExecOp, ExecSched},
        persist::Backoff,
        traits::BlockStore as _,
    },
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_sumeragi::{api::Event, message::VoteKind};
use std::{
    sync::Arc,
    task::{Context, Poll, Waker},
};

#[test]
fn certificate_capacity_refusal_reaches_scheduler_with_original_release_and_execution() {
    for occupy_after in 1..=3 {
        publication_tests::with_worker(move |chain, worker, blocks, events| {
            let mut registration = crate::unit_test_support::release_registration(
                &chain.state().ivm_execution_budget(),
            );
            let scheduler_registration =
                crate::sumeragi::driver::exec::ExecutionRegistrations::admit(
                    &chain.state().ivm_execution_budget(),
                )
                .unwrap();
            let _epoch = crossbeam_epoch::pin();
            let (body, qc) = publication_tests::executed(chain, worker);
            let overlay = std::ptr::from_ref(
                worker
                    .live
                    .as_ref()
                    .unwrap()
                    .overlay
                    .as_ref()
                    .unwrap()
                    .as_ref(),
            );
            let result_owner = std::ptr::from_ref(worker.live.as_ref().unwrap().commitment().get());
            let preimage = match &worker.live.as_ref().unwrap().phase {
                PublicationPhase::Executed { preimage, .. } => preimage.as_slice().as_ptr(),
                _ => panic!("retain original executed phase"),
            };
            let mut scheduler = ExecSched::new(1, Backoff::default(), scheduler_registration);
            scheduler.commit(body.clone(), qc.clone());
            let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
                panic!("prepare same original commit");
            };
            let mut occupied = None;
            let mut encoded = 0;
            let failure = worker
                .prepare_with_encoder(
                    &original.block,
                    &original.qc,
                    CommitTelemetryOrigin::Forward,
                    |part: CertificatePart<'_>, budget| {
                        let bytes =
                            encode_certificate_part(part, budget, MAX_RESULT_PREIMAGE_BYTES)?;
                        encoded += 1;
                        if encoded == occupy_after {
                            occupied = Some(
                                budget
                                    .try_reserve_bytes(
                                        budget.limit_bytes() - budget.reserved_bytes(),
                                    )
                                    .expect("occupy actual remaining State pool"),
                            );
                        }
                        Ok(bytes)
                    },
                )
                .unwrap_err();
            assert_eq!(encoded, occupy_after);
            let PublicationError::Deferred(ref source) = failure else {
                panic!("preparation erased original resource source: {failure:?}");
            };
            let source = source.clone();
            let Some(AllocationRefusal::Capacity { release, .. }) = source.allocation_refusal()
            else {
                panic!("actual original pool capacity, not a fabricated local diagnostic");
            };
            let wait = release.clone();
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
            let foreign = AllocationBudget::new(1);
            drop(foreign.try_reserve_bytes(1).unwrap());
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);

            scheduler.done(0, ExecDone::Prepared(Err(failure)));
            assert_eq!(scheduler.preparation_refusal(), Some(&source));
            assert_eq!(scheduler.applied(), 1);
            assert!(scheduler.next(0).is_none());
            assert!(scheduler.take_events().is_empty());
            assert!(worker.context.staging.get(&qc.block_hash).is_none());
            assert!(worker.pending_commit.is_none());
            assert!(worker.recovery.is_none());
            assert!(events.try_recv().is_err());
            assert_eq!(
                std::ptr::from_ref(
                    worker
                        .live
                        .as_ref()
                        .unwrap()
                        .overlay
                        .as_ref()
                        .unwrap()
                        .as_ref()
                ),
                overlay
            );
            assert_eq!(
                std::ptr::from_ref(worker.live.as_ref().unwrap().commitment().get()),
                result_owner
            );

            // An unrelated deterministic certificate error cannot borrow a stale resource
            // observation merely because this worker retains the pending original phase.
            let mut changed = qc.clone();
            changed.kind = VoteKind::Prepare;
            assert!(matches!(
                worker.prepare(&body, &changed),
                Err(PublicationError::Retryable(_))
            ));
            assert_eq!(scheduler.preparation_refusal(), Some(&source));
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
            drop(occupied);
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Ready(()));

            let now = scheduler.wakeup();
            let Some(ExecOp::Prepare(retry)) = scheduler.next(now) else {
                panic!("retry same queued prepare after actual original release");
            };
            assert!(Arc::ptr_eq(&original, &retry));
            assert_eq!(scheduler.preparation_refusal(), Some(&source));
            let prepared = worker.prepare(&retry.block, &retry.qc);
            assert_eq!(prepared.as_ref().unwrap(), &Some(qc.result));
            let staged = worker.context.staging.get(&qc.block_hash).unwrap();
            assert_eq!(
                staged
                    .executed
                    .commit_certificate()
                    .unwrap()
                    .result_preimage()
                    .as_ptr(),
                preimage
            );
            assert_eq!(
                std::ptr::from_ref(
                    worker
                        .live
                        .as_ref()
                        .unwrap()
                        .overlay
                        .as_ref()
                        .unwrap()
                        .as_ref()
                ),
                overlay
            );
            scheduler.done(now, ExecDone::Prepared(prepared));
            assert!(scheduler.preparation_refusal().is_none());
            let Some(ExecOp::Append(append)) = scheduler.next(now) else {
                panic!("append after prepare");
            };
            assert!(Arc::ptr_eq(&original, &append));
            blocks.append(&append.block, &append.qc).unwrap();
            scheduler.done(
                now,
                ExecDone::Appended {
                    durable: true,
                    deferred: None,
                },
            );
            let Some(ExecOp::Commit(commit)) = scheduler.next(now) else {
                panic!("apply original durable commit");
            };
            assert!(Arc::ptr_eq(&original, &commit));
            let applied = worker.commit(&commit.block, &commit.qc).unwrap();
            assert_eq!(
                scheduler.done(now, ExecDone::Committed(Ok(Box::new(applied)))),
                Some(2)
            );
            assert_eq!(
                scheduler
                    .take_events()
                    .iter()
                    .filter(|event| matches!(event, Event::BlockApplied { .. }))
                    .count(),
                1
            );
        });
    }
}

#[test]
fn preparation_classification_preserves_real_limit_and_does_not_invent_release_for_allocator() {
    let budget = AllocationBudget::new(1);
    let original = budget.try_reserve_bytes(2).unwrap_err();
    let error = ResultPreimageError::Allocation(ChargedBufferError::Admission(original.clone()));
    let PublicationError::Deferred(source) = encoding_failure(&error) else {
        panic!("retain exact impossible demand");
    };
    assert_eq!(source.allocation_refusal(), Some(&original));
    assert!(matches!(
        source.allocation_refusal(),
        Some(AllocationRefusal::ExceedsLimit { .. })
    ));

    let physical = ChargedBufferError::Allocator { requested_bytes: 4 };
    let PublicationError::Deferred(source) =
        encoding_failure(&ResultPreimageError::Allocation(physical))
    else {
        panic!("allocator failure remains a local unfinished attempt");
    };
    assert_eq!(
        source.execution().unwrap().reason(),
        ExecutionDeferral::AllocationUnavailable
    );
    assert!(source.allocation_refusal().is_none());
    let PublicationError::Deferred(source) = certificate_failure(
        &CertificateAdmissionError::ControlAdmission(original.clone()),
    ) else {
        panic!("retain original shared control admission source");
    };
    assert_eq!(source.allocation_refusal(), Some(&original));
    assert!(matches!(
        encoding_failure(&ResultPreimageError::ForeignBudget),
        PublicationError::Retryable(_)
    ));
    assert!(matches!(
        certificate_failure(&CertificateAdmissionError::ForeignBudget),
        PublicationError::Retryable(_)
    ));
    use iroha_sumeragi::message::ByteAdmissionError;
    for error in [
        ByteAdmissionError::Buffer(ChargedBufferError::Admission(original.clone())),
        ByteAdmissionError::ControlAdmission(original.clone()),
    ] {
        let PublicationError::Deferred(source) = witness_failure(&error) else {
            panic!("witness backing and control preserve the original refusal");
        };
        assert_eq!(source.allocation_refusal(), Some(&original));
        assert!(
            source.release_wait().is_none(),
            "an impossible demand invents no release"
        );
    }
    let physical = ByteAdmissionError::Buffer(ChargedBufferError::Allocator { requested_bytes: 4 });
    let PublicationError::Deferred(source) = witness_failure(&physical) else {
        panic!("a physical allocator failure has no fabricated release owner");
    };
    assert_eq!(
        source.execution().unwrap().reason(),
        ExecutionDeferral::AllocationUnavailable
    );
    assert!(source.release_wait().is_none());
    assert!(matches!(
        witness_failure(&ByteAdmissionError::ForeignBudget),
        PublicationError::RecoveryRequired(_)
    ));
    assert!(matches!(
        witness_failure(&ByteAdmissionError::Length { length: 0 }),
        PublicationError::RecoveryRequired(_)
    ));
}

#[test]
fn cold_prepare_refusal_retains_original_finishing_owner_and_exact_release() {
    use super::super::{
        FinishingPhase, NativeContextArchiveError, NativeLaneStateProofError, PublicationDeferral,
    };
    use crate::sumeragi::commitment::encode_result_preimage;
    use iroha_data_model::events::{
        EventBox,
        pipeline::{BlockEvent, BlockStatus, PipelineEventBox},
    };
    for phase in 0..3 {
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
            worker.discard(2, &[]);
            assert!(worker.live.is_none());
            let budget = worker.state.ivm_execution_budget();
            let mut occupied = None;
            let initial = worker.run_execution_with_finisher(&body, qc.block_hash, |worker| {
                if phase >= 1 {
                    worker.prepare_original_result().unwrap();
                }
                if phase >= 2 {
                    worker.prepare_original_context_archive().unwrap();
                }
                occupied = Some(
                    budget
                        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                        .expect("occupy the actual original execution pool"),
                );
                worker.finish_execution_with_encoder(encode_result_preimage)
            });
            assert!(matches!(initial, Err(PublicationError::Deferred(_))));
            let pending = worker
                .finishing
                .as_ref()
                .expect("original completed execution");
            let overlay = std::ptr::from_ref(pending.overlay.as_ref());
            let writes = pending.witness.writes.as_ptr();
            let witness = iroha_crypto::HashOf::new(pending.witness.wire());
            let count = pending.events.len();
            let original_events = pending.events.clone();
            let committed_event = EventBox::Pipeline(PipelineEventBox::Block(BlockEvent {
                header: pending.valid.as_ref().header(),
                status: BlockStatus::Committed,
            }));
            let retained = budget.reserved_bytes();
            let mut scheduler = ExecSched::new(1, Backoff::default(), scheduler_registration);
            scheduler.commit(body.clone(), qc.clone());
            let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
                panic!("cold prepare retains the original queued decision");
            };
            // This path has no Live overlay or certificate, so Prepare must resume
            // the actual completed execution through run_execution's typed result.
            // Release initial fixture occupancy so the normal independent
            // certificate read can complete. Reoccupy only at the original
            // cold execution boundary, without changing or replacing its result.
            drop(occupied.take());
            let failure = worker
                .prepare_with_operations(
                    &original.block,
                    &original.qc,
                    CommitTelemetryOrigin::Forward,
                    |part, budget| encode_certificate_part(part, budget, MAX_RESULT_PREIMAGE_BYTES),
                    |worker, block, hash| {
                        occupied = Some(
                            budget
                                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                                .unwrap(),
                        );
                        worker.run_execution(block, hash)
                    },
                )
                .unwrap_err();
            let PublicationError::Deferred(source) = &failure else {
                panic!("cold preparation erased its original refusal: {failure:?}");
            };
            let source = source.clone();
            let pending = worker.finishing.as_ref().unwrap();
            let allocation = match phase {
                0 => match &pending.phase {
                    FinishingPhase::ContextProof {
                        refusal: Some(NativeLaneStateProofError::Scratch(error)),
                        ..
                    } => error,
                    _ => panic!("retain the same unfinished context proof"),
                },
                1 => match &pending.archive_refusal {
                    Some(NativeContextArchiveError::Proof(NativeLaneStateProofError::Scratch(
                        error,
                    ))) => error,
                    _ => panic!("retain the same unfinished context archive"),
                },
                _ => match &pending.encoding_refusal {
                    Some(ResultPreimageError::Allocation(error)) => error,
                    _ => panic!("retain the same unfinished result preimage"),
                },
            };
            assert_eq!(
                source,
                PublicationDeferral::Execution(buffer_refusal(allocation))
            );
            assert!(matches!(
                source.allocation_refusal(),
                Some(AllocationRefusal::Capacity { .. })
            ));
            let wait = source.release_wait().unwrap().clone();
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
            let unrelated = AllocationBudget::new(1);
            drop(unrelated.try_reserve_bytes(1).unwrap());
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
            scheduler.done(0, ExecDone::Prepared(Err(failure)));
            assert_eq!(scheduler.preparation_refusal(), Some(&source));
            assert!(scheduler.next(0).is_none());
            assert_eq!(std::ptr::from_ref(pending.overlay.as_ref()), overlay);
            assert_eq!(pending.witness.writes.as_ptr(), writes);
            assert_eq!(iroha_crypto::HashOf::new(pending.witness.wire()), witness);
            assert_eq!(pending.events.len(), count);
            assert_eq!(pending.events, original_events);
            assert_eq!(budget.reserved_bytes(), retained);
            assert!(worker.live.is_none());
            assert!(worker.recovery.is_none());
            assert!(!worker.results.contains_key(&qc.block_hash));
            assert!(events.try_recv().is_err());
            assert_eq!(worker.state.committed_height(), 1);

            // A rejected certificate cannot acquire a stale refusal from the retained owner.
            let mut changed = qc.clone();
            changed.kind = VoteKind::Prepare;
            assert!(matches!(
                worker.prepare(&body, &changed),
                Err(PublicationError::Retryable(_))
            ));
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
            drop(occupied);
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Ready(()));
            let now = scheduler.wakeup();
            let Some(ExecOp::Prepare(retry)) = scheduler.next(now) else {
                panic!("retry the same queued decision after actual release");
            };
            assert!(Arc::ptr_eq(&original, &retry));
            let prepared = worker.prepare(&retry.block, &retry.qc);
            assert_eq!(prepared.as_ref().unwrap(), &Some(qc.result));
            assert!(worker.finishing.is_none());
            let live = worker.live.as_ref().unwrap();
            assert_eq!(
                std::ptr::from_ref(live.overlay.as_deref().unwrap()),
                overlay
            );
            assert_eq!(live.witness.as_ref().unwrap().writes.as_ptr(), writes);
            assert_eq!(
                iroha_crypto::HashOf::new(live.witness.as_ref().unwrap().wire()),
                witness
            );
            // Successful preparation consumes ValidBlock into CommittedBlock once.
            // That transition appends its exact committed event to the unchanged
            // original validation events; retry must not execute or append again.
            let mut prepared_events = original_events;
            prepared_events.push(committed_event);
            assert_eq!(live.events, prepared_events);
            assert!(
                events.try_recv().is_err(),
                "preparation has not published events"
            );
            assert_eq!(
                worker.prepare(&retry.block, &retry.qc).unwrap(),
                Some(qc.result)
            );
            assert_eq!(worker.live.as_ref().unwrap().events, prepared_events);
            scheduler.done(now, ExecDone::Prepared(prepared));
            let Some(ExecOp::Append(append)) = scheduler.next(now) else {
                panic!("append only the original completed decision");
            };
            blocks.append(&append.block, &append.qc).unwrap();
            scheduler.done(
                now,
                ExecDone::Appended {
                    durable: true,
                    deferred: None,
                },
            );
            let Some(ExecOp::Commit(commit)) = scheduler.next(now) else {
                panic!("publish the original completed execution");
            };
            let applied = worker.commit(&commit.block, &commit.qc).unwrap();
            assert_eq!(
                scheduler.done(now, ExecDone::Committed(Ok(Box::new(applied)))),
                Some(2)
            );
            assert_eq!(
                scheduler
                    .take_events()
                    .iter()
                    .filter(|event| matches!(event, Event::BlockApplied { .. }))
                    .count(),
                1
            );
            assert_eq!(worker.state.committed_height(), 2);
        });
    }
}

#[test]
fn cold_prepare_validation_refusals_retain_original_storage_owners() {
    use super::super::PublicationDeferral;
    use crate::state::{
        BlockHashAdmissionError, MembershipAdmissionError, StateStorageAdmissionError,
    };
    for owner in 0..3 {
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
            worker.discard(2, &[]);
            let original_payload = body.payload().as_slice().as_ptr();
            let budget = worker.state.ivm_execution_budget();
            let mut scheduler = ExecSched::new(1, Backoff::default(), scheduler_registration);
            scheduler.commit(body.clone(), qc.clone());
            let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
                panic!("cold original prepare")
            };
            let mut attempt = || {
                let failure = worker.prepare(&original.block, &original.qc).unwrap_err();
                let PublicationError::Deferred(source) = &failure else {
                    panic!("storage source erased: {failure:?}")
                };
                assert!(
                    match (owner, source) {
                        (
                            0,
                            PublicationDeferral::StateStorage(StateStorageAdmissionError::World(
                                mv::storage::AdmittedStorageError::Busy { .. },
                            )),
                        )
                        | (
                            1,
                            PublicationDeferral::BlockHashAdmission(BlockHashAdmissionError::Busy(
                                _,
                            )),
                        )
                        | (
                            2,
                            PublicationDeferral::MembershipAdmission(
                                MembershipAdmissionError::Busy(_),
                            ),
                        ) => true,
                        _ => false,
                    },
                    "the actual refusing owner is retained: {source:?}"
                );
                assert!(
                    source.allocation_refusal().is_none(),
                    "a lock is not allocation demand"
                );
                let source = source.clone();
                let wait = source.release_wait().unwrap().clone();
                let mut context = Context::from_waker(Waker::noop());
                assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
                let foreign = AllocationBudget::new(1);
                drop(foreign.try_reserve_bytes(1).unwrap());
                assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
                scheduler.done(0, ExecDone::Prepared(Err(failure)));
                assert_eq!(scheduler.preparation_refusal(), Some(&source));
                assert!(scheduler.next(0).is_none());
                assert!(worker.live.is_none());
                assert!(worker.finishing.is_none());
                assert!(worker.recovery.is_none());
                assert!(worker.quarantine_context.is_none());
                assert!(!worker.results.contains_key(&qc.block_hash));
                assert!(events.try_recv().is_err());
                assert_eq!(worker.state.committed_height(), 1);
                source
            };
            let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(1);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
            let state = Arc::clone(chain.state());
            let blocker =
                crate::sumeragi::threads::sumeragi_thread_builder("cold-prepare-held-lock")
                    .spawn(move || {
                        let hold = || {
                            acquired_tx.send(()).unwrap();
                            // A blocking-acquisition regression terminates by releasing
                            // the actual foreign guard; it cannot hang the mutation gate.
                            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
                        };
                        match owner {
                            0 => {
                                let _blocker = state.world.try_block(&budget).unwrap();
                                hold();
                            }
                            1 => state.with_hash_publication_blocked_for_test(hold),
                            _ => {
                                let _blocker = state.transactions.block();
                                hold();
                            }
                        }
                    })
                    .unwrap();
            let acquired = acquired_rx.recv_timeout(std::time::Duration::from_secs(30));
            let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                acquired.expect("actual foreign writer is acquired before the probe");
                attempt()
            }));
            let released = release_tx.send(());
            let joined = blocker.join();
            joined.unwrap();
            assert!(
                released.is_ok(),
                "cold preparation returned before the blocker deadline"
            );
            let source = attempted.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            let wait = source.release_wait().unwrap().clone();
            assert_eq!(
                registration.poll_wait(&wait, &mut Context::from_waker(Waker::noop())),
                Poll::Ready(())
            );
            let now = scheduler.wakeup();
            let Some(ExecOp::Prepare(retry)) = scheduler.next(now) else {
                panic!("retry the exact retained source")
            };
            assert!(Arc::ptr_eq(&original, &retry));
            assert_eq!(retry.block.payload().as_slice().as_ptr(), original_payload);
            let prepared = worker.prepare(&retry.block, &retry.qc);
            assert_eq!(prepared.as_ref().unwrap(), &Some(qc.result));
            scheduler.done(now, ExecDone::Prepared(prepared));
            let Some(ExecOp::Append(append)) = scheduler.next(now) else {
                panic!("append original")
            };
            blocks.append(&append.block, &append.qc).unwrap();
            scheduler.done(
                now,
                ExecDone::Appended {
                    durable: true,
                    deferred: None,
                },
            );
            let Some(ExecOp::Commit(commit)) = scheduler.next(now) else {
                panic!("commit original")
            };
            let applied = worker.commit(&commit.block, &commit.qc).unwrap();
            assert_eq!(
                scheduler.done(now, ExecDone::Committed(Ok(Box::new(applied)))),
                Some(2)
            );
            assert_eq!(worker.state.committed_height(), 2);
        });
    }
}

#[test]
fn validation_wrappers_keep_real_capacity_and_terminal_custody_distinct() {
    use crate::state::{
        BlockHashAdmissionError, EvidencePreparationError, MembershipAdmissionError,
        StateStorageAdmissionError, StateViewError,
    };
    use mv::storage::AdmittedStorageError;
    let budget = AllocationBudget::new(1);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    let capacity = budget.try_reserve_bytes(1).unwrap_err();
    let impossible = budget.try_reserve_bytes(2).unwrap_err();
    for original in [&capacity, &impossible] {
        for error in [
            BlockValidationError::StateView(StateViewError::Runtime(
                crate::state::LaneLifecycleError::NposPolicy(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(
                        (*original).clone().into(),
                    ),
                ),
            )),
            BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::World(
                AdmittedStorageError::Allocation(original.clone()),
            )),
            BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::NativeAmx(
                crate::sumeragi::amx::NativeAmxAdmissionError::Admission(original.clone()),
            )),
            BlockValidationError::EvidencePreparation(EvidencePreparationError::Admission(
                original.clone(),
            )),
            BlockValidationError::BlockHashAdmission(BlockHashAdmissionError::Capacity(
                original.clone(),
            )),
            BlockValidationError::MembershipAdmission(MembershipAdmissionError::Capacity(
                original.clone(),
            )),
        ] {
            let Some(PublicationError::Deferred(source)) = validation_failure(&error) else {
                panic!("retain exact physical pool demand")
            };
            assert_eq!(source.allocation_refusal(), Some(original));
            assert_eq!(
                source.release_wait().is_some(),
                matches!(original, AllocationRefusal::Capacity { .. })
            );
        }
    }
    drop(occupied);
    let layout = iroha_allocation::release::ReleaseNotification::allocation_layout::<
        iroha_allocation::AllocationCharge,
    >();
    let control_pool = AllocationBudget::new(
        layout.size() + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&control_pool);
    let mut reservation = control_pool.try_reserve(layout).unwrap();
    let source = iroha_allocation::release::ReleaseNotification::try_new_charged(
        reservation.try_split(layout).unwrap(),
    )
    .unwrap();
    let mutex = std::sync::Mutex::new(());
    let held = source.guard(mutex.lock().unwrap());
    let original = source.observe();
    let error = BlockValidationError::StateView(StateViewError::Busy(original.clone()));
    let Some(PublicationError::Deferred(PublicationDeferral::StateViewBusy(retained))) =
        validation_failure(&error)
    else {
        panic!("actual State reader lock must retain its own release source")
    };
    assert_eq!(retained, original);
    let wait = retained;
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(budget.try_reserve_bytes(1).unwrap());
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(held);
    assert!(
        registration
            .poll_wait(&wait, &mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    for error in [
        BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::World(
            AdmittedStorageError::Allocator {
                layout: std::alloc::Layout::new::<u64>(),
            },
        )),
        BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::NativeAmx(
            crate::sumeragi::amx::NativeAmxAdmissionError::Allocator { bytes: 8 },
        )),
        BlockValidationError::EvidencePreparation(EvidencePreparationError::Allocator {
            requested_bytes: 8,
        }),
        BlockValidationError::MembershipAdmission(MembershipAdmissionError::Allocator {
            requested_bytes: 8,
        }),
    ] {
        let Some(PublicationError::Deferred(source)) = validation_failure(&error) else {
            panic!("physical allocation is unfinished local work")
        };
        assert!(source.allocation_refusal().is_none());
        assert!(
            source.release_wait().is_none(),
            "never fabricate a physical allocator release"
        );
    }
    for error in [
        BlockValidationError::StateView(StateViewError::Changed),
        BlockValidationError::StateView(StateViewError::Poisoned),
        BlockValidationError::StateView(StateViewError::Runtime(
            crate::state::LaneLifecycleError::Storage("original runtime projection failed".into()),
        )),
        BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::World(
            AdmittedStorageError::ScopeIdentity,
        )),
        BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::NativeAmx(
            crate::sumeragi::amx::NativeAmxAdmissionError::Invalid(
                "original native AMX custody invariant changed".into(),
            ),
        )),
        BlockValidationError::StateStorageAdmission(StateStorageAdmissionError::NativeAmx(
            crate::sumeragi::amx::NativeAmxAdmissionError::Admission(
                AllocationRefusal::DemandOverflow,
            ),
        )),
        BlockValidationError::EvidencePreparation(EvidencePreparationError::Invariant),
        BlockValidationError::BlockHashAdmission(BlockHashAdmissionError::Poisoned),
        BlockValidationError::BlockHashAdmission(BlockHashAdmissionError::ReadOnly),
        BlockValidationError::MembershipAdmission(MembershipAdmissionError::Poisoned),
        BlockValidationError::MembershipAdmission(MembershipAdmissionError::SourceNotFunded),
        BlockValidationError::EvidencePreparation(EvidencePreparationError::Admission(
            AllocationRefusal::DemandOverflow,
        )),
        BlockValidationError::LocalStorageRecoveryRequired {
            reason: "original write was consumed".into(),
        },
    ] {
        assert!(
            matches!(
                validation_failure(&error),
                Some(PublicationError::RecoveryRequired(_))
            ),
            "terminal original custody: {error:?}"
        );
    }
    assert!(validation_failure(&BlockValidationError::HasCommittedTransactions).is_none());
}

#[test]
fn original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine() {
    use crate::state::StateReadOnly as _;
    use iroha_data_model::transaction::{
        Executable, FeePaymentIntent, IvmBytecode, TransactionBuilder,
    };
    use std::{num::NonZeroU64, time::Duration};
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let body =
            publication_tests::proposal_with_transaction(chain, worker, |chain, created_ms| {
                let key = iroha_crypto::KeyPair::from_seed(
                    vec![0xCE; 32],
                    iroha_crypto::Algorithm::Ed25519,
                );
                assert_eq!(
                    chain.genesis_account(),
                    &iroha_data_model::account::AccountId::new(key.public_key().clone())
                );
                let mut program = ivm::ProgramMetadata {
                    max_cycles: 100,
                    ..Default::default()
                }
                .encode();
                program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
                let mut builder = TransactionBuilder::new(
                    chain.network_id(),
                    chain.genesis_account().clone(),
                    FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1_000_000)),
                );
                builder.set_creation_time(Duration::from_millis(created_ms));
                builder
                    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
                    .sign(key.private_key())
            });
        let hash = body.hash(&**worker.context.crypto.as_ref().unwrap());
        let original_payload = body.payload().as_slice().as_ptr();
        let original_height = worker.state.view().height();
        let cache = worker.state.view().prepared_contract_cache();
        let reason = ivm::error::ExecutionDeferral::LocalInvariantViolation;
        cache.set_checkout_refusal_for_test(Some(reason));
        let outcome = worker.execute(&body, hash);
        cache.set_checkout_refusal_for_test(None);
        let Some(super::super::ExecOutcome::Failed(message)) = outcome else {
            panic!("an original local custody invariant cannot become a validity verdict")
        };
        let recovery_reason = reason.to_string();
        assert_eq!(
            message,
            PublicationError::RecoveryRequired(recovery_reason.clone()).to_string()
        );
        assert_eq!(worker.recovery.as_deref(), Some(recovery_reason.as_str()));
        assert!(worker.quarantine_context.is_none());
        assert!(worker.results.get(&hash).is_none());
        assert!(worker.live.is_none() && worker.finishing.is_none());
        assert!(worker.pending_commit.is_none());
        assert!(worker.context.staging.get(&hash).is_none());
        assert!(events.try_recv().is_err());
        assert_eq!(worker.state.view().height(), original_height);
        assert_eq!(body.payload().as_slice().as_ptr(), original_payload);
        assert!(
            matches!(worker.execute(&body, hash), Some(super::super::ExecOutcome::Failed(again)) if again == message)
        );
        assert!(
            worker.live.is_none() && worker.finishing.is_none(),
            "clearing local injection cannot authorize reexecution after recovery is required"
        );
        let error = BlockValidationError::ExecutionDeferred(reason.into());
        assert!(!crate::sumeragi::executor::control::transaction_rejection(
            &error
        ));
        assert!(matches!(
            validation_failure(&error),
            Some(PublicationError::RecoveryRequired(_))
        ));
        assert!(matches!(
            super::super::classify_lane_step(
                2,
                &crate::sumeragi::lanes::step::LaneStepError::Deferred(reason.into())
            ),
            Err(PublicationError::RecoveryRequired(_))
        ));
    });
}

#[test]
fn native_source_publication_change_retries_without_recovery_or_quarantine() {
    for error in [
        BlockValidationError::NativeSourceChanged {
            authenticated_generation: 2,
            observed_generation: 4,
        },
        BlockValidationError::from(crate::sumeragi::lanes::merge::MergeError::SourceChanged {
            authenticated_generation: 2,
            observed_generation: 4,
        }),
    ] {
        assert!(!super::super::control::transaction_rejection(&error));
        assert!(matches!(
            validation_failure(&error),
            Some(PublicationError::Retryable(_))
        ));
        assert!(matches!(
            super::super::classify(2, &error),
            Err(PublicationError::Retryable(_))
        ));
    }
    for terminal in [
        BlockValidationError::StateView(crate::state::StateViewError::Changed),
        BlockValidationError::StateView(crate::state::StateViewError::Poisoned),
        BlockValidationError::DaIndexHydration("original index corrupt".into()),
        BlockValidationError::LocalStorageRecoveryRequired {
            reason: "original custody lost".into(),
        },
    ] {
        assert!(matches!(
            validation_failure(&terminal),
            Some(PublicationError::RecoveryRequired(_))
        ));
        assert!(!super::super::control::transaction_rejection(&terminal));
    }
}
