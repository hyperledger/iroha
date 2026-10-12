//! Actual worker parent-service refusal, retained original source, retry and cancellation.
//!
//! Signed genesis and nonempty H2/H3 run through the real State/consensus fixture. Capacity
//! is occupied only at the real successor-authority admission boundary, after source reads.
//! This does not qualify nested native decoder or returned signer-graph funding.

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
    let observer =
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
    (observer, occupied, pointers)
}

fn release_of(error: PublicationError) -> crate::execution_attempt::ExecutionDeferred {
    let PublicationError::Deferred(reason) = error else {
        panic!("parent-service worker must return its actual authority capacity refusal")
    };
    let original = reason
        .execution()
        .expect("original execution refusal")
        .clone();
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
                .run_execution(&block, hash)
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
                .run_execution(&block, hash)
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
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time,
            ));
            let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
                transaction,
                &chain.network_id(),
                Duration::from_secs(1),
                chain.state().view().world().parameters().transaction(),
                &iroha_config::parameters::actual::Crypto::default(),
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
            assert!(
                registration.poll_wait(release, &mut context).is_pending(),
                "parent-service assembly retains original parent receipts instead of waking its own retry"
            );
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
            let proposal = payload::decode(payload.as_slice()).unwrap();
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
            let original = release_of(worker.run_execution(&block, hash).unwrap_err());
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
                worker.run_execution(&block, hash).unwrap().is_some(),
                "a fresh operation can execute the same still-authenticated source after cancellation"
            );
            drop(epoch);
        },
    );
}

#[test]
fn parent_service_preparation_refuses_foreign_original_owner_without_replacing_receipts() {
    publication_tests::with_worker_from(
        executed_chain,
        ConsensusMode::Permissioned,
        |chain, worker, _blocks, _events| {
            let mut prepared = super::super::certified_chain::ParentServicePreparation::default();
            let view = chain.state().view();
            let budget = view.execution_budget();
            let epoch = crossbeam_epoch::pin();
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
            drop(epoch);
        },
    );
}

#[test]
fn parent_service_errors_keep_original_waiter_and_permanent_source_classification() {
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
    let mut diagnostic = None;
    for classified in [
        parent_history_error(ExecutionAttemptError::Deferred(original.clone().into())),
        parent_service_preparation_error(
            super::super::certified_chain::ParentServiceError::Deferred(original.clone().into()),
            &mut diagnostic,
        ),
    ] {
        let PublicationError::Deferred(reason) = classified else {
            panic!("original parent refusal must remain deferred")
        };
        assert_eq!(reason.allocation_refusal(), Some(&original));
        assert_eq!(reason.release_wait(), Some(release));
        assert!(registration.poll_wait(release, &mut cx).is_pending());
    }
    assert_eq!(
        diagnostic.as_ref().unwrap().allocation_refusal(),
        Some(&original)
    );
    for classified in [
        parent_history_error(ExecutionAttemptError::Deferred(
            ExecutionDeferral::LocalInvariantViolation.into(),
        )),
        parent_service_preparation_error(
            super::super::certified_chain::ParentServiceError::Deferred(
                ExecutionDeferral::LocalInvariantViolation.into(),
            ),
            &mut diagnostic,
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
            matches!(classified, PublicationError::RecoveryRequired(_)),
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
    use super::super::certified_chain::{ChainReadError, ParentServiceError};
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
            parent_service_preparation_error(
                ParentServiceError::NativeSource(original.clone()),
                &mut diagnostic,
            ),
            preparation::validation_failure(&BlockValidationError::NativeHistory(original.clone()))
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
                    chain.tick(time - 1)
                });
            let crypto = worker.context.crypto.as_ref().unwrap();
            let first_hash = first.hash(&**crypto);
            let second_hash = second.hash(&**crypto);
            assert_ne!(first_hash, second_hash);
            let budget = worker.state.ivm_execution_budget();
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let epoch = crossbeam_epoch::pin();
            let (_probe, occupied, _) = occupy_at_real_authority(&budget);
            let original = release_of(worker.run_execution(&first, first_hash).unwrap_err());
            let AllocationRefusal::Capacity { release, .. } =
                original.allocation_refusal().unwrap()
            else {
                unreachable!()
            };
            let mut cx = Context::from_waker(Waker::noop());
            assert!(registration.poll_wait(release, &mut cx).is_pending());
            let reached = Rc::new(std::cell::Cell::new(false));
            let observed = Rc::clone(&reached);
            let _replacement_probe =
                super::super::certified_chain::observe_parent_service_admission(move |_, _| {
                    observed.set(true)
                });
            let replacement = release_of(worker.run_execution(&second, second_hash).unwrap_err());
            assert!(
                reached.get(),
                "replacement rechecks its own complete native parent source"
            );
            assert!(
                registration.poll_wait(release, &mut cx).is_ready(),
                "explicit replacement retires the superseded receipt owner"
            );
            let attempt = worker.signature_decode.as_ref().unwrap();
            assert_eq!(attempt.block_hash, second_hash);
            assert_eq!(attempt.source, second);
            assert!(
                attempt
                    .parent_service
                    .original_pointers()
                    .iter()
                    .all(|pointer| *pointer != 0)
            );
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
            assert!(
                worker
                    .run_execution(&second, second_hash)
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
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
        transaction,
        &chain.network_id(),
        Duration::from_secs(1),
        chain.state().view().world().parameters().transaction(),
        &iroha_config::parameters::actual::Crypto::default(),
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
            assert_eq!(repeated.as_slice().as_ptr(), payload.as_slice().as_ptr());
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
            assert_eq!(repeated.as_slice().as_ptr(), payload.as_slice().as_ptr());
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
            let epoch = crossbeam_epoch::pin();
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
                    parent_service_preparation_error(error, &mut None),
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
            drop(epoch);
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
            let _original_capacity = release_of(worker.run_execution(&block, hash).unwrap_err());
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
                let outcome = worker.run_execution(&block, hash);
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
            assert!(worker.run_execution(&block, hash).unwrap().is_some());
            assert_eq!(worker.state.view().height(), 3);
            drop(epoch);
        },
    );
}
