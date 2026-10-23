//! Actual worker parent-service refusal, retained original source, retry and cancellation.
//!
//! Signed genesis and nonempty H2/H3 run through the real State/consensus fixture. Capacity
//! is occupied at real successor-authority and offered-QC field admission boundaries.
//! These controls exercise the offered semantic QC and selected signer owners;
//! the producer destination copy is retained before queue leasing; native-body nested
//! decoding and enclosing evidence funding remain open.

use super::*;
use crate::sumeragi::{
    driver::traits::BlockStore,
    test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};
use std::{
    cell::RefCell,
    rc::Rc,
    task::{Context, Waker},
};

fn executed_chain() -> CertifiedTestChain {
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    chain
}
type ReceiptPointers = Rc<RefCell<Option<[usize; 4]>>>;
fn occupy_at_real_authority(
    budget: &AllocationBudget,
) -> (
    super::super::certified_chain::ParentServiceAdmissionProbe,
    Rc<RefCell<Option<AllocationReservation>>>,
    ReceiptPointers,
) {
    let occupied = Rc::new(RefCell::new(None));
    let retained = Rc::clone(&occupied);
    let pointers = Rc::new(RefCell::new(None));
    let observed = Rc::clone(&pointers);
    let original = budget.clone();
    let budget_observer =
        super::super::certified_chain::observe_parent_service_admission(move |parent, current| {
            *observed.borrow_mut() = Some([
                std::ptr::from_ref(parent) as usize,
                std::ptr::from_ref(current) as usize,
                std::ptr::from_ref::<iroha_data_model::block::SignedBlock>(parent.block()) as usize,
                std::ptr::from_ref::<iroha_data_model::block::SignedBlock>(current.block())
                    as usize,
            ]);
            assert!(retained.borrow().is_none());
            *retained.borrow_mut() = Some(
                original
                    .try_reserve_bytes(original.limit_bytes() - original.reserved_bytes())
                    .unwrap(),
            );
        });
    (budget_observer, occupied, pointers)
}

fn release_of(error: PublicationError) -> crate::execution_attempt::ExecutionDeferred {
    let PublicationError::Deferred(reason) = error else {
        panic!("parent-service worker must return its actual authority capacity refusal")
    };
    let PublicationDeferral::Execution(original) = reason else {
        panic!("original execution refusal")
    };
    assert!(
        matches!(
            original.allocation_refusal(),
            Some(AllocationRefusal::Capacity { .. })
        ),
        "parent-service authority retains its original Capacity source"
    );
    original
}

#[test]
fn parent_service_validation_retains_original_receipts_without_waking_its_own_retry() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let source = block.payload().as_slice().as_ptr();
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let epoch = crossbeam_epoch::pin();
            let (_probe, occupied, original_receipts) = occupy_at_real_authority(&budget);
            let error = worker
                .run_execution(&block, hash, false)
                .expect_err("actual late authority admission refuses");
            assert!(
                occupied.borrow().is_some(),
                "the real parent-service constructor was reached"
            );
            let original = release_of(error);
            let AllocationRefusal::Capacity { release, .. } =
                original.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            let mut context = Context::from_waker(Waker::noop());
            assert!(
                registration.poll_wait(release, &mut context).is_pending(),
                "parent-service validation keeps original receipts instead of refunding its own waiter"
            );
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
            assert_eq!(block.payload().as_slice().as_ptr(), source);
            assert_eq!(worker.signature_decode.as_ref().unwrap().source, block);
            assert!(worker.signature_decode.as_ref().unwrap().decoded.is_some());
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert!(!worker.results.contains_key(&hash));
            assert!(worker.context.staging.get(&hash).is_none());
            assert_eq!(worker.state.view().height(), 3);
            assert!(events.try_recv().is_err());
            let unrelated = AllocationBudget::new(23);
            drop(unrelated.try_reserve_bytes(23).unwrap());
            assert!(registration.poll_wait(release, &mut context).is_pending());
            let pointers = original_receipts
                .borrow()
                .expect("actual original receipt pointers");
            drop(occupied.borrow_mut().take());
            assert!(registration.poll_wait(release, &mut context).is_ready());
            let _retry_source = super::super::certified_chain::observe_parent_service_admission(
                move |parent, current| {
                    assert_eq!(
                        std::ptr::from_ref(parent) as usize,
                        pointers[0],
                        "retry keeps the actual predecessor receipt slot"
                    );
                    assert_eq!(
                        std::ptr::from_ref(current) as usize,
                        pointers[1],
                        "retry keeps the actual parent receipt slot"
                    );
                    assert_eq!(
                        std::ptr::from_ref::<iroha_data_model::block::SignedBlock>(parent.block())
                            as usize,
                        pointers[2]
                    );
                    assert_eq!(
                        std::ptr::from_ref::<iroha_data_model::block::SignedBlock>(current.block())
                            as usize,
                        pointers[3]
                    );
                },
            );
            let result = worker
                .run_execution(&block, hash, false)
                .unwrap()
                .expect("same original proposal executes after genuine release");
            assert_eq!(block.payload().as_slice().as_ptr(), source);
            let qc = chain.commit_qc(
                block.header().height,
                hash,
                result,
                crate::sumeragi::test_chain::Signers::Quorum,
            );
            assert_eq!(worker.prepare(&block, &qc).unwrap(), Some(result));
            blocks.append(&block, &qc).unwrap();
            worker.commit(&block, &qc).unwrap();
            assert_eq!(worker.state.view().height(), 4);
            drop(epoch);
        },
    );
}

#[test]
fn parent_service_assembly_retains_original_parent_and_queue_before_capacity_retry() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let transaction = chain.tick(4_000);
            let original_hash = transaction.hash_as_entrypoint();
            let (_, time) =
                iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(4_001));
            chain.set_execution_time(time.now());
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time,
            ));
            let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
                transaction,
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    iroha_crypto::Algorithm::Ed25519,
                    iroha_crypto::Algorithm::Secp256k1,
                ])
                .expect("explicit current admission fixture policy"),
                &time,
            )
            .unwrap();
            queue.push(accepted, chain.state().view()).unwrap();
            worker.queue = Some(queue.clone());
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let epoch = crossbeam_epoch::pin();
            let (_probe, occupied, original_receipts) = occupy_at_real_authority(&budget);
            let original = release_of(
                worker
                    .build(4, 0, 1 << 20, 100)
                    .expect_err("actual parent-service assembly refuses"),
            );
            assert!(occupied.borrow().is_some());
            let AllocationRefusal::Capacity { release, .. } =
                original.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(
                budget.reserved_bytes(),
                budget.limit_bytes(),
                "parent-service assembly retains original receipt charges at first refusal"
            );
            let pointers_before_retry = worker
                .assembly_parent_service
                .as_ref()
                .unwrap()
                .1
                .original_pointers();
            assert!(pointers_before_retry.iter().all(|pointer| *pointer != 0));
            // Initial parent acquisition can refund scratch before authority admission.
            // build delivers those wakes after its guards retire; observe a fresh real
            // refusal from the retained source, without manufacturing a release token.
            let _ = registration.poll_wait(release, &mut context);
            let original = release_of(
                worker
                    .build(4, 0, 1 << 20, 100)
                    .expect_err("unchanged full pool still refuses original assembly"),
            );
            let AllocationRefusal::Capacity { release, .. } =
                original.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            assert_eq!(
                worker
                    .assembly_parent_service
                    .as_ref()
                    .unwrap()
                    .1
                    .original_pointers(),
                pointers_before_retry
            );
            assert!(
                registration.poll_wait(release, &mut context).is_pending(),
                "parent-service assembly retains original parent receipts instead of waking its own retry"
            );
            let unrelated = AllocationBudget::new(23);
            drop(unrelated.try_reserve_bytes(23).unwrap());
            assert!(registration.poll_wait(release, &mut context).is_pending());
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(original_hash));
            assert!(worker.payload_build.is_none() && worker.completed_payload.is_none());
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert_eq!(worker.state.view().height(), 3);
            assert!(events.try_recv().is_err());
            let pointers = original_receipts
                .borrow()
                .expect("actual original assembly receipt pointers");
            drop(occupied.borrow_mut().take());
            assert!(registration.poll_wait(release, &mut context).is_ready());
            let _retry_source = super::super::certified_chain::observe_parent_service_admission(
                move |parent, current| {
                    assert_eq!(std::ptr::from_ref(parent) as usize, pointers[0]);
                    assert_eq!(std::ptr::from_ref(current) as usize, pointers[1]);
                },
            );
            let payload = worker
                .build(4, 0, 1 << 20, 100)
                .unwrap()
                .expect("same queued input builds after original release");
            let proposal = payload::decode(payload.payload.as_slice()).unwrap();
            assert!(
                proposal
                    .external_entrypoints_slice()
                    .iter()
                    .any(|entry| entry.hash() == original_hash)
            );
            assert_eq!(proposal.header().height().get(), 4);
            assert!(
                proposal
                    .npos_consensus_effects()
                    .and_then(|effects| effects.parent_service_commit_qc.as_ref())
                    .is_some()
            );
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(original_hash));
            drop(epoch);
        },
    );
}

#[test]
fn parent_service_worker_cancellation_retires_the_same_original_partial_graph() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let epoch = crossbeam_epoch::pin();
            let baseline = budget.reserved_bytes();
            let (_probe, occupied, _original_receipts) = occupy_at_real_authority(&budget);
            let original = release_of(worker.run_execution(&block, hash, false).unwrap_err());
            let pointers = worker
                .signature_decode
                .as_ref()
                .unwrap()
                .parent_service
                .original_pointers();
            assert!(pointers.iter().all(|pointer| *pointer != 0));
            let occupied_bytes = occupied.borrow().as_ref().unwrap().remaining_bytes();
            assert!(budget.reserved_bytes() > baseline + occupied_bytes);
            worker.reject(block.header().height, block.header().origin_view, hash);
            assert!(worker.signature_decode.is_none());
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert_eq!(worker.state.view().height(), 3);
            assert!(events.try_recv().is_err());
            assert_eq!(
                budget.reserved_bytes(),
                baseline + occupied_bytes,
                "cancellation releases only the original partial graph after its actual backing retires"
            );
            drop(occupied.borrow_mut().take());
            assert_eq!(budget.reserved_bytes(), baseline);
            drop(original);
            assert!(
                worker.run_execution(&block, hash, false).unwrap().is_some(),
                "a fresh operation can execute the same still-authenticated source after cancellation"
            );
            drop(epoch);
        },
    );
}

#[test]
fn parent_service_preparation_refuses_foreign_original_owner_without_replacing_receipts() {
    // Pin before constructing the signed chain so older State refunds cannot
    // change this test's exact original-pool accounting.
    let _epoch = crossbeam_epoch::pin();
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, _events| {
            let mut prepared = super::super::certified_chain::ParentServicePreparation::default();
            let view = chain.state().view();
            let budget = view.execution_budget();
            let baseline = budget.reserved_bytes();
            prepared.prepare(&view, 3).unwrap();
            let pointers = prepared.original_pointers();
            let occupied = budget.reserved_bytes();
            prepared.prepare(&view, 3).unwrap();
            assert_eq!(prepared.original_pointers(), pointers);
            assert_eq!(budget.reserved_bytes(), occupied);
            let foreign = executed_chain();
            let foreign_view = foreign.state().view();
            let foreign_budget = foreign_view.execution_budget();
            let foreign_bytes = foreign_budget.reserved_bytes();
            assert!(matches!(
                prepared.prepare(&foreign_view, 3),
                Err(super::super::certified_chain::ParentServiceError::Source(_))
            ));
            assert_eq!(prepared.original_pointers(), pointers);
            assert_eq!(budget.reserved_bytes(), occupied);
            assert_eq!(foreign_budget.reserved_bytes(), foreign_bytes);
            assert!(matches!(
                prepared.prepare(&view, 2),
                Err(super::super::certified_chain::ParentServiceError::Source(_))
            ));
            assert_eq!(prepared.original_pointers(), pointers);
            drop(prepared);
            assert_eq!(budget.reserved_bytes(), baseline);
            assert!(worker.live.is_none());
        },
    );
}

#[test]
fn parent_service_errors_keep_original_waiter_and_permanent_source_classification() {
    use super::super::certified_chain::{ChainReadError, ParentServiceError};
    use crate::execution_attempt::ExecutionAttemptError;
    use iroha_data_model::query::error::{CanonicalHistoryError, QueryExecutionFail};
    use ivm::error::ExecutionDeferral;
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(waiter_bytes + 17);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    assert_eq!(budget.reserved_bytes(), waiter_bytes);
    let occupied = budget.try_reserve_bytes(17).unwrap();
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let AllocationRefusal::Capacity { release, .. } = &original else {
        unreachable!()
    };
    let mut cx = Context::from_waker(Waker::noop());
    for classified in [
        parent_history_error(ExecutionAttemptError::Deferred(original.clone().into())),
        parent_service_preparation_error(
            super::super::certified_chain::ParentServiceError::Deferred(original.clone().into()),
        ),
    ] {
        let PublicationError::Deferred(reason) = classified else {
            panic!("original parent refusal must remain deferred")
        };
        assert_eq!(reason.allocation_refusal(), Some(&original));
        assert_eq!(reason.release_wait(), Some(release));
        assert!(registration.poll_wait(release, &mut cx).is_pending());
    }
    for classified in [
        parent_history_error(ExecutionAttemptError::Deferred(
            ExecutionDeferral::LocalInvariantViolation.into(),
        )),
        parent_service_preparation_error(
            super::super::certified_chain::ParentServiceError::Deferred(
                ExecutionDeferral::LocalInvariantViolation.into(),
            ),
        ),
        parent_history_error(ExecutionAttemptError::Rejected(
            QueryExecutionFail::Conversion("native parent contradicts retained execution".into()),
        )),
        parent_history_error(ExecutionAttemptError::Rejected(
            QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BlockHeightMismatch {
                height: 3,
                actual_height: 2,
            }),
        )),
    ] {
        assert!(
            classified.is_recovery_required(),
            "permanent parent custody failure requires recovery"
        );
    }
    assert!(matches!(
        parent_history_error(ExecutionAttemptError::Rejected(
            QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::HeightOutsideSnapshot {
                height: 3,
                committed_height: 2
            })
        )),
        PublicationError::Retryable(_)
    ));
    for (original, unavailable) in [
        (ChainReadError::NotCommitted { height: 2 }, true),
        (ChainReadError::NotInView { height: 2 }, true),
        (ChainReadError::ResultMismatch { height: 2 }, false),
        (
            ChainReadError::Malformed {
                height: 2,
                reason: "original native receipt is corrupt".into(),
            },
            false,
        ),
    ] {
        for classified in [
            parent_service_preparation_error(ParentServiceError::NativeSource(original.clone())),
            preparation::validation_failure(BlockValidationError::NativeHistory(original.clone()))
                .expect("native history has one shared classification"),
        ] {
            assert_eq!(
                matches!(classified, PublicationError::Retryable(_)),
                unavailable,
                "only the native loader's original unavailable source remains retryable"
            );
            assert_eq!(
                matches!(classified, PublicationError::RecoveryRequired(_)),
                !unavailable,
                "contradictory native custody requires recovery at both boundaries"
            );
        }
    }
    drop(occupied);
    assert!(registration.poll_wait(release, &mut cx).is_ready());
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn parent_service_worker_replacement_retires_only_the_superseded_original_attempt() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let first = publication_tests::proposal(chain, worker);
            let second =
                publication_tests::proposal_with_transaction(chain, worker, |chain, time| {
                    // The preceding millisecond's tick is already committed at H3.
                    // Use fresh work; assembly derives its canonical later block time.
                    chain.tick(time + 1)
                });
            let crypto = worker.context.crypto.as_ref().unwrap();
            let first_hash = first.hash(&**crypto);
            let second_hash = second.hash(&**crypto);
            assert_ne!(first_hash, second_hash);
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let epoch = crossbeam_epoch::pin();
            let (_probe, occupied, _) = occupy_at_real_authority(&budget);
            let original = release_of(worker.run_execution(&first, first_hash, false).unwrap_err());
            let AllocationRefusal::Capacity { release, .. } =
                original.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            let mut cx = Context::from_waker(Waker::noop());
            assert!(registration.poll_wait(release, &mut cx).is_pending());
            let replacement = release_of(
                worker
                    .run_execution(&second, second_hash, false)
                    .unwrap_err(),
            );
            assert!(
                registration.poll_wait(release, &mut cx).is_ready(),
                "explicit replacement retires the superseded receipt owner"
            );
            let attempt = worker.signature_decode.as_ref().unwrap();
            assert_eq!(attempt.block_hash, second_hash);
            assert_eq!(attempt.source, second);
            assert!(!worker.results.contains_key(&first_hash));
            assert!(!worker.results.contains_key(&second_hash));
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert_eq!(worker.state.view().height(), 3);
            assert!(events.try_recv().is_err());
            let AllocationRefusal::Capacity {
                release: replacement_release,
                ..
            } = replacement.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            assert!(
                registration
                    .poll_wait(replacement_release, &mut cx)
                    .is_pending(),
                "new candidate keeps its own receipt graph"
            );
            drop(occupied.borrow_mut().take());
            assert!(
                registration
                    .poll_wait(replacement_release, &mut cx)
                    .is_ready()
            );
            // A replacement may first exhaust capacity in its own signature decoder.
            // Once that original refusal is released, occupy capacity at the actual
            // native authority boundary and inspect its completed original receipts.
            let (_replacement_probe, replacement_occupied, replacement_receipts) =
                occupy_at_real_authority(&budget);
            let replacement = release_of(
                worker
                    .run_execution(&second, second_hash, false)
                    .unwrap_err(),
            );
            assert!(
                replacement_occupied.borrow().is_some(),
                "replacement rechecks its own complete native parent source"
            );
            let pointers = worker
                .signature_decode
                .as_ref()
                .unwrap()
                .parent_service
                .original_pointers();
            assert!(pointers.iter().all(|pointer| *pointer != 0));
            let AllocationRefusal::Capacity { release, .. } =
                replacement.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
            assert!(registration.poll_wait(release, &mut cx).is_pending());
            let receipt_pointers = replacement_receipts.borrow().unwrap();
            drop(replacement_occupied.borrow_mut().take());
            assert!(registration.poll_wait(release, &mut cx).is_ready());
            let _retry_source = super::super::certified_chain::observe_parent_service_admission(
                move |parent, current| {
                    assert_eq!(std::ptr::from_ref(parent) as usize, receipt_pointers[0]);
                    assert_eq!(std::ptr::from_ref(current) as usize, receipt_pointers[1]);
                },
            );
            assert!(
                worker
                    .run_execution(&second, second_hash, false)
                    .unwrap()
                    .is_some()
            );
            assert!(!worker.results.contains_key(&first_hash));
            drop(epoch);
        },
    );
}

fn queue_original_tick(chain: &CertifiedTestChain, worker: &mut Worker<'_>) {
    let transaction = chain.tick(4_000);
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(4_001));
    chain.set_execution_time(time.now());
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
        transaction,
        &chain.network_id(),
        Duration::from_secs(1),
        chain.state().view().world().parameters().transaction(),
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
        ])
        .expect("explicit current admission fixture policy"),
        &time,
    )
    .unwrap();
    queue.push(accepted, chain.state().view()).unwrap();
    worker.queue = Some(queue);
}

#[test]
fn parent_service_busy_view_keeps_completed_payload_and_original_preparation() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            queue_original_tick(chain, worker);
            let payload = worker.build(4, 0, 1 << 20, 100).unwrap().unwrap();
            assert!(worker.completed_payload.is_some());
            let pointers = worker
                .assembly_parent_service
                .as_ref()
                .unwrap()
                .1
                .original_pointers();
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let epoch = crossbeam_epoch::pin();
            let baseline = budget.reserved_bytes();
            let state = worker.state;
            std::thread::scope(|scope| {
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                let (release_tx, release_rx) = std::sync::mpsc::channel();
                let holder = scope.spawn(move || {
                    state.with_held_header_for_reader_test(|wait| {
                        ready_tx.send(wait).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(20)).is_ok()
                    })
                });
                let original = ready_rx.recv_timeout(Duration::from_secs(20)).unwrap();
                let outcome = worker.build(4, 0, 1 << 20, 100);
                // Release before assertions so unwinding cannot strand the actual guard.
                release_tx.send(()).ok();
                assert!(
                    holder.join().unwrap(),
                    "assembly must not block on the held State reader"
                );
                let Err(PublicationError::Deferred(PublicationDeferral::StateViewBusy(wait))) =
                    outcome
                else {
                    panic!("worker returns the actual State reader waiter")
                };
                assert_eq!(wait, original);
                let mut cx = Context::from_waker(Waker::noop());
                assert!(registration.poll_wait(&wait, &mut cx).is_ready());
            });
            assert!(
                worker.completed_payload.is_some(),
                "Busy must retain the completed original payload"
            );
            assert_eq!(
                worker
                    .assembly_parent_service
                    .as_ref()
                    .unwrap()
                    .1
                    .original_pointers(),
                pointers
            );
            assert_eq!(budget.reserved_bytes(), baseline);
            assert!(events.try_recv().is_err());
            let repeated = worker.build(4, 0, 1 << 20, 100).unwrap().unwrap();
            assert_eq!(
                repeated.payload.as_slice().as_ptr(),
                payload.payload.as_slice().as_ptr()
            );
            assert_eq!(
                worker
                    .assembly_parent_service
                    .as_ref()
                    .unwrap()
                    .1
                    .original_pointers(),
                pointers
            );
            drop(epoch);
        },
    );
}

#[test]
fn parent_service_completed_payload_rechecks_actual_predecessor_slot_before_lending() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            queue_original_tick(chain, worker);
            let payload = worker.build(4, 0, 1 << 20, 100).unwrap().unwrap();
            let pointers = worker
                .assembly_parent_service
                .as_ref()
                .unwrap()
                .1
                .original_pointers();
            let mut physical = crate::kura::BlockStore::new(
                crate::kura::Kura::canonical_storage_path(&chain.kura().store_root()),
            );
            let predecessor = physical.read_block_index(1).unwrap();
            // Change only the real predecessor's occupied location; the retained genesis,
            // parent, State tip and Queue inputs are unchanged.
            physical
                .write_block_index(1, predecessor.start + 1, predecessor.length)
                .unwrap();
            assert!(
                matches!(
                    worker.build(4, 0, 1 << 20, 100),
                    Err(PublicationError::Retryable(_))
                ),
                "cached payload cannot bypass its predecessor's original physical descriptor"
            );
            assert!(worker.completed_payload.is_some());
            assert_eq!(
                worker
                    .assembly_parent_service
                    .as_ref()
                    .unwrap()
                    .1
                    .original_pointers(),
                pointers
            );
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert!(events.try_recv().is_err());
            physical
                .write_block_index(1, predecessor.start, predecessor.length)
                .unwrap();
            let repeated = worker.build(4, 0, 1 << 20, 100).unwrap().unwrap();
            assert_eq!(
                repeated.payload.as_slice().as_ptr(),
                payload.payload.as_slice().as_ptr()
            );
            assert_eq!(
                worker
                    .assembly_parent_service
                    .as_ref()
                    .unwrap()
                    .1
                    .original_pointers(),
                pointers
            );
        },
    );
}

#[test]
fn parent_service_missing_predecessor_retries_original_tip_and_refuses_nontip_preparation() {
    // Pin before constructing the signed chain so older State refunds cannot
    // change this test's exact original-pool accounting.
    let _epoch = crossbeam_epoch::pin();
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let view = chain.state().view();
            let mut physical = crate::kura::BlockStore::new(
                crate::kura::Kura::canonical_storage_path(&chain.kura().store_root()),
            );
            let predecessor = physical.read_block_index(1).unwrap();
            // The native extent reader classifies an absent physical frame (zero extent)
            // as NotInView; keep that existing source classification across preparation.
            physical.write_block_index(1, predecessor.start, 0).unwrap();
            let budget = view.execution_budget();
            let baseline = budget.reserved_bytes();
            let mut prepared = super::super::certified_chain::ParentServicePreparation::default();
            let error = prepared.prepare(&view, 3).unwrap_err();
            assert!(matches!(
                &error,
                super::super::certified_chain::ParentServiceError::NativeSource(
                    super::super::certified_chain::ChainReadError::NotInView { height: 2 }
                )
            ));
            assert!(
                matches!(
                    parent_service_preparation_error(error),
                    PublicationError::Retryable(_)
                ),
                "the original missing predecessor remains retryable"
            );
            let partial = prepared.original_pointers();
            assert_ne!(partial[0], 0);
            assert_ne!(partial[2], 0);
            assert_eq!(partial[1], 0);
            physical
                .write_block_index(1, predecessor.start, predecessor.length)
                .unwrap();
            prepared.prepare(&view, 3).unwrap();
            let completed = prepared.original_pointers();
            assert_eq!(completed[0], partial[0]);
            assert_eq!(completed[2], partial[2]);
            assert!(completed.iter().all(|pointer| *pointer != 0));
            {
                let parent = chain.committed(3);
                let reader =
                    super::super::certified_chain::CertifiedChain::new_for_parent_service(&view)
                        .unwrap();
                prepared
                    .prepare_producer_copy(&view, parent.block())
                    .unwrap();
                assert_eq!(
                    prepared.proposal_original(&view, parent.block()).unwrap(),
                    reader
                        .parent_service_proposal_original(parent.block())
                        .unwrap(),
                    "tip-only retained preparation preserves the existing parent-service relation"
                );
            }
            assert!(
                matches!(
                    prepared.prepare(&view, 2),
                    Err(super::super::certified_chain::ParentServiceError::Source(_))
                ),
                "retained tip preparation cannot skip intermediate heights for a historical target"
            );
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert!(events.try_recv().is_err());
            drop(prepared);
            assert_eq!(budget.reserved_bytes(), baseline);
        },
    );
}

#[test]
fn parent_service_validation_busy_view_retains_original_receipts_before_parent_lookup() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let epoch = crossbeam_epoch::pin();
            let (_probe, occupied, _) = occupy_at_real_authority(&budget);
            let _original_capacity =
                release_of(worker.run_execution(&block, hash, false).unwrap_err());
            let pointers = worker
                .signature_decode
                .as_ref()
                .unwrap()
                .parent_service
                .original_pointers();
            let decoded = std::ptr::from_ref(
                worker
                    .signature_decode
                    .as_ref()
                    .unwrap()
                    .decoded
                    .as_ref()
                    .unwrap(),
            );
            drop(occupied.borrow_mut().take());
            let baseline = budget.reserved_bytes();
            let state = worker.state;
            std::thread::scope(|scope| {
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                let (release_tx, release_rx) = std::sync::mpsc::channel();
                let holder = scope.spawn(move || {
                    state.with_held_header_for_reader_test(|wait| {
                        ready_tx.send(wait).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(20)).is_ok()
                    })
                });
                let original = ready_rx.recv_timeout(Duration::from_secs(20)).unwrap();
                let outcome = worker.run_execution(&block, hash, false);
                release_tx.send(()).ok();
                assert!(
                    holder.join().unwrap(),
                    "validation must not block before original parent preflight"
                );
                let Err(PublicationError::Deferred(PublicationDeferral::StateViewBusy(wait))) =
                    outcome
                else {
                    panic!("validation must return the original State reader Busy observation")
                };
                assert_eq!(wait, original);
                assert!(
                    registration
                        .poll_wait(&wait, &mut Context::from_waker(Waker::noop()))
                        .is_ready()
                );
            });
            let retained = worker.signature_decode.as_ref().unwrap();
            assert_eq!(retained.source, block);
            assert_eq!(retained.parent_service.original_pointers(), pointers);
            assert_eq!(
                std::ptr::from_ref(retained.decoded.as_ref().unwrap()),
                decoded
            );
            assert_eq!(budget.reserved_bytes(), baseline);
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert!(!worker.results.contains_key(&hash));
            assert!(worker.context.staging.get(&hash).is_none());
            assert!(events.try_recv().is_err());
            assert!(worker.run_execution(&block, hash, false).unwrap().is_some());
            assert_eq!(worker.state.view().height(), 3);
            drop(epoch);
        },
    );
}

#[test]
fn parent_service_semantic_qc_worker_keeps_partial_owner_and_exact_refusal_until_retry() {
    // Pin before constructing the signed chain so older State refunds cannot
    // change this test's exact original-pool accounting.
    let _epoch = crossbeam_epoch::pin();
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let baseline = budget.reserved_bytes();
            let retained = Rc::new(RefCell::new(None));
            let blocker = Rc::clone(&retained);
            let observation = Rc::new(RefCell::new(None));
            let observed = Rc::clone(&observation);
            let original_pool = budget.clone();
            let _probe: super::super::certified_chain::ParentServiceQcAdmissionProbe =
                super::super::certified_chain::observe_parent_service_qc_admission(
                    move |source, pool| {
                        assert!(pool.same_pool(&original_pool));
                        let qc: iroha_sumeragi::message::Qc =
                            norito::decode_canonical(source.as_slice()).unwrap();
                        assert_eq!(qc.signers.as_bytes().len(), 1);
                        *observed.borrow_mut() =
                            Some((source.as_slice().as_ptr().addr(), pool.reserved_bytes()));
                        *blocker.borrow_mut() = Some(
                            pool.try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
                                .unwrap(),
                        );
                    },
                );
            let error = worker
                .run_execution(&block, hash, false)
                .expect_err("actual semantic bitmap admission refuses");
            let first = release_of(error);
            let (source, controls) = observation
                .borrow()
                .expect("actual semantic QC boundary observed");
            let original = worker
                .signature_decode
                .as_ref()
                .expect("original worker attempt retained");
            assert_eq!(
                original.parent_service.qc_pointers(),
                (source, 0),
                "semantic QC refusal must retain the original worker source and partial decoder"
            );
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
            assert!(
                matches!(first.allocation_refusal(), Some(AllocationRefusal::Capacity {requested_bytes: 1, reserved_bytes, limit_bytes, ..}) if *reserved_bytes == budget.limit_bytes() && *limit_bytes == budget.limit_bytes())
            );
            let AllocationRefusal::Capacity { release, .. } = first.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            let mut wait_context = Context::from_waker(Waker::noop());
            assert!(
                registration
                    .poll_wait(release, &mut wait_context)
                    .is_pending()
            );
            let second = release_of(
                worker
                    .run_execution(&block, hash, false)
                    .expect_err("same original pool still refuses"),
            );
            assert_eq!(second.allocation_refusal(), first.allocation_refusal());
            assert!(
                registration
                    .poll_wait(release, &mut wait_context)
                    .is_pending()
            );
            assert_eq!(
                worker
                    .signature_decode
                    .as_ref()
                    .unwrap()
                    .parent_service
                    .qc_pointers(),
                (source, 0)
            );
            assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert_eq!(worker.state.view().height(), 3);
            assert_eq!(worker.applied.0, 3);
            assert!(events.try_recv().is_err());
            drop(retained.borrow_mut().take());
            assert!(
                registration
                    .poll_wait(release, &mut wait_context)
                    .is_ready()
            );
            assert_eq!(budget.reserved_bytes(), controls);
            assert!(worker.run_execution(&block, hash, false).unwrap().is_some());
            assert!(worker.signature_decode.is_none());
            let pointers = worker
                .live
                .as_ref()
                .expect("successful execution retains the original decoder in Live")
                .signature_decode
                .parent_service
                .qc_pointers();
            assert_eq!(pointers.0, source);
            assert_ne!(pointers.1, 0);
            assert_eq!(worker.state.view().height(), 3);
            assert_eq!(worker.applied.0, 3);
            worker.discard(block.header().height, &[]);
            drop(first);
            drop(second);
            assert_eq!(budget.reserved_bytes(), baseline);
        },
    );
}

#[test]
fn parent_service_signer_worker_keeps_paid_prefix_before_overlay_and_external_release() {
    // Pin before constructing the signed chain so older State refunds cannot
    // change this test's exact original-pool accounting.
    let _epoch = crossbeam_epoch::pin();
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let block = publication_tests::proposal(chain, worker);
            let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
            let budget = worker.state.ivm_execution_budget();
            let expected_key_bytes = chain.committed(3).commitment().schedule.current.committee[0]
                .validator
                .public_key()
                .retained_allocation_layout()
                .size();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let baseline = budget.reserved_bytes();
            let retained = Rc::new(RefCell::new(None));
            let blocker = Rc::clone(&retained);
            let observation = Rc::new(RefCell::new(None));
            let observed = Rc::clone(&observation);
            let original_pool = budget.clone();
            let _probe: super::super::certified_chain::ParentServiceSignersAdmissionProbe =
                super::super::certified_chain::observe_parent_service_signers_admission(
                    move |pool, first_prefix_bytes| {
                        assert!(pool.same_pool(&original_pool));
                        *observed.borrow_mut() = Some(pool.reserved_bytes() + first_prefix_bytes);
                        *blocker.borrow_mut() = Some(
                            pool.try_reserve_bytes(
                                pool.limit_bytes() - pool.reserved_bytes() - first_prefix_bytes,
                            )
                            .unwrap(),
                        );
                    },
                );
            let first = release_of(
                worker
                    .run_execution(&block, hash, false)
                    .expect_err("actual second signer key admission refuses"),
            );
            assert_eq!(
                budget.reserved_bytes(),
                budget.limit_bytes(),
                "worker signer refusal retains its paid prefix before any overlay"
            );
            let controls = observation
                .borrow()
                .expect("actual signer destination observed");
            let pointers = worker
                .signature_decode
                .as_ref()
                .unwrap()
                .parent_service
                .signer_pointers();
            assert!(pointers.0 != 0 && pointers.1 != 0 && pointers.2 != 0);
            assert!(
                matches!(first.allocation_refusal(), Some(AllocationRefusal::Capacity {requested_bytes, reserved_bytes, limit_bytes, ..})
                if *requested_bytes == expected_key_bytes && *reserved_bytes == budget.limit_bytes() && *limit_bytes == budget.limit_bytes())
            );
            let AllocationRefusal::Capacity { release, .. } = first.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            let mut context = Context::from_waker(Waker::noop());
            assert!(registration.poll_wait(release, &mut context).is_pending());
            let second = release_of(
                worker
                    .run_execution(&block, hash, false)
                    .expect_err("same original pool still refuses the same unfinished key"),
            );
            assert_eq!(second.allocation_refusal(), first.allocation_refusal());
            assert_eq!(
                worker
                    .signature_decode
                    .as_ref()
                    .unwrap()
                    .parent_service
                    .signer_pointers(),
                pointers
            );
            assert!(registration.poll_wait(release, &mut context).is_pending());
            assert!(
                worker.live.is_none() && worker.finishing.is_none() && worker.recovery.is_none()
            );
            assert_eq!(worker.state.view().height(), 3);
            assert_eq!(worker.applied.0, 3);
            assert!(events.try_recv().is_err());
            drop(retained.borrow_mut().take());
            assert!(registration.poll_wait(release, &mut context).is_ready());
            assert_eq!(budget.reserved_bytes(), controls);
            assert!(worker.run_execution(&block, hash, false).unwrap().is_some());
            assert!(worker.signature_decode.is_none());
            assert_eq!(
                worker
                    .live
                    .as_ref()
                    .expect("successful execution retains the original decoder in Live")
                    .signature_decode
                    .parent_service
                    .signer_pointers(),
                pointers
            );
            assert_eq!(worker.state.view().height(), 3);
            assert_eq!(worker.applied.0, 3);
            worker.discard(block.header().height, &[]);
            drop(first);
            drop(second);
            assert_eq!(budget.reserved_bytes(), baseline);
        },
    );
}

#[test]
fn parent_service_producer_copy_refusal_precedes_queue_lease_and_retries_same_input() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, events| {
            let transaction = chain.tick(4_000);
            let original_hash = transaction.hash_as_entrypoint();
            let (_, time) =
                iroha_primitives::time::TimeSource::new_mock(Duration::from_millis(4_001));
            chain.set_execution_time(time.now());
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time,
            ));
            let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
                transaction,
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                chain
                    .state()
                    .view()
                    .world()
                    .parameters()
                    .crypto_policy()
                    .expect("original committed admission policy"),
                &time,
            )
            .unwrap();
            queue.push(accepted, chain.state().view()).unwrap();
            worker.queue = Some(queue.clone());
            let pool = worker.state.ivm_execution_budget();
            let _epoch = crossbeam_epoch::pin();
            let mut registration = crate::unit_test_support::release_registration(&pool);
            let occupied = Rc::new(RefCell::new(None));
            let blocker = Rc::clone(&occupied);
            let expected = Rc::new(RefCell::new(None));
            let observed = Rc::clone(&expected);
            let original_pool = pool.clone();
            let _probe: super::super::certified_chain::ParentServiceCopyAdmissionProbe =
                super::super::certified_chain::observe_parent_service_copy_admission(
                    move |pool, layouts| {
                        assert!(pool.same_pool(&original_pool));
                        let demand: usize = layouts.iter().map(std::alloc::Layout::size).sum();
                        *blocker.borrow_mut() = Some(
                            pool.try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
                                .unwrap(),
                        );
                        *observed.borrow_mut() = Some((demand, pool.reserved_bytes()));
                    },
                );
            let first = release_of(
                worker
                    .build(4, 0, 1 << 20, 100)
                    .expect_err("real producer copy capacity refuses"),
            );
            let (demand, at_admission) = expected
                .borrow()
                .expect("actual destination admission observed");
            assert!(
                matches!(first.allocation_refusal(), Some(AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. })
            if *requested_bytes == demand && *reserved_bytes == at_admission && *limit_bytes == pool.limit_bytes())
            );
            let original_receipts = worker
                .assembly_parent_service
                .as_ref()
                .unwrap()
                .1
                .original_pointers();
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            assert!(original_receipts.iter().all(|pointer| *pointer != 0));
            assert!(worker.payload_build.is_none() && worker.completed_payload.is_none());
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(original_hash));
            assert_eq!(worker.state.view().height(), 3);
            assert!(events.try_recv().is_err());
            // Initial acquisition scratch can refund at the outer scope boundary. A fresh
            // unchanged refusal captures the actual remaining source, never an invented wake.
            let mut context = Context::from_waker(Waker::noop());
            let AllocationRefusal::Capacity { release, .. } = first.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            let _ = registration.poll_wait(release, &mut context);
            let second = release_of(
                worker
                    .build(4, 0, 1 << 20, 100)
                    .expect_err("same original copy still refuses"),
            );
            let AllocationRefusal::Capacity { release, .. } = second.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            assert!(registration.poll_wait(release, &mut context).is_pending());
            assert_eq!(
                worker
                    .assembly_parent_service
                    .as_ref()
                    .unwrap()
                    .1
                    .original_pointers(),
                original_receipts
            );
            assert!(worker.payload_build.is_none() && worker.completed_payload.is_none());
            drop(occupied.borrow_mut().take());
            assert!(registration.poll_wait(release, &mut context).is_ready());
            registration.cancel();
            let result = worker
                .build(4, 0, 1 << 20, 100)
                .unwrap()
                .expect("original paid input resumes");
            let proposal = payload::decode(result.payload.as_slice()).unwrap();
            assert!(
                proposal
                    .external_entrypoints_slice()
                    .iter()
                    .any(|entry| entry.hash() == original_hash)
            );
            let parent = chain.committed(3);
            let view = chain.state().view();
            let prepared = &worker.assembly_parent_service.as_ref().unwrap().1;
            let first = prepared.proposal_original(&view, parent.block()).unwrap();
            let second = prepared.proposal_original(&view, parent.block()).unwrap();
            assert!(
                iroha_data_model::consensus::NposParentServiceCommitQc::ptr_eq(&first, &second)
            );
            assert!(first.admitted_to(&pool));
            assert_eq!(
                proposal
                    .npos_consensus_effects()
                    .unwrap()
                    .parent_service_commit_qc
                    .as_ref()
                    .unwrap()
                    .as_slice(),
                first.as_slice()
            );
            assert_eq!(queue.queued_len(), 1);
            assert!(queue.contains_entrypoint_hash(original_hash));
        },
    );
}
