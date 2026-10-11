//! Actual local Worker payload preparation, exact refusal custody and original source retry.
//! The fixture uses genuine signed four-validator genesis and the ordinary paid assembly path.
//! This qualifies only the empty signature leaf and its caller, not full block graph funding.

use super::super::driver::payload_build::{PayloadBuild, SourcePreparationError};
use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_data_model::block::{BlockSignatureCustodyError, BlockSignatures};
use std::task::{Context, Poll, Waker};

fn original_source(
    chain: &super::super::test_chain::CertifiedTestChain,
    worker: &Worker<'_>,
) -> GlobalPayloadSource {
    let height = worker.applied.0 + 1;
    let scheduled = worker.scheduled(height).unwrap();
    let view = chain.state().view();
    let parent = view
        .latest_block()
        .expect("original authenticated parent read")
        .unwrap();
    let cadence = Duration::from_millis(scheduled.params.block_time_ms);
    let block_time = parent.header().creation_time() + cadence;
    let tx = chain.tick(u64::try_from(block_time.as_millis()).unwrap() - 1);
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(block_time);
    let accepted = crate::tx::AcceptedTransaction::accept_with_time_source(
        tx,
        &chain.network_id(),
        Duration::from_secs(1),
        view.world().parameters().transaction(),
        &iroha_config::parameters::actual::Crypto::default(),
        &time,
    )
    .unwrap();
    drop(view);
    let block = payload::assemble(
        chain.state(),
        Assembly {
            parent: &parent,
            view: 0,
            cadence,
        },
        &[accepted],
    )
    .unwrap();
    assert!(block.is_resultless_proposal());
    assert_eq!(block.signatures().len(), 0);
    GlobalPayloadSource {
        attest: proposal_requires_attestation(&block, scheduled.epoch.authorization.last_height),
        block,
        pending_inputs: None,
    }
}

fn install_original(
    worker: &mut Worker<'_>,
    source: GlobalPayloadSource,
    budget: AllocationBudget,
) -> OriginalPayloadScope {
    assert!(worker.payload_build.is_none());
    assert!(worker.completed_payload.is_none());
    let max_bytes = u32::try_from(source.block.resultless_proposal_wire_len().unwrap()).unwrap();
    let view = worker.state.view();
    let scope = OriginalPayloadScope::capture(
        &view,
        worker.state.state_view_generation(),
        worker.applied.0 + 1,
        0,
        max_bytes,
        100,
    );
    drop(view);
    worker.payload_build = Some(GlobalPayloadBuild {
        scope,
        job: PayloadBuild::new(source, budget, max_bytes as usize),
        preparation_refusal: None,
    });
    scope
}

#[test]
fn original_local_payload_signature_refusal_keeps_job_and_exact_release_owner() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let _epoch = crossbeam_epoch::pin();
        let budget = worker.state.ivm_execution_budget();
        let source = original_source(chain, worker);
        let expected = source.block.encode_wire().unwrap();
        let entries = source.block.external_entrypoints_slice().as_ptr();
        let input_hash = source.block.external_entrypoints_slice()[0].hash();
        let header = source.block.header();
        let applied = worker.applied;
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let scope = install_original(worker, source, budget.clone());
        let floor = budget.reserved_bytes();
        let demand = BlockSignatures::allocation_layout().size();
        let pressure = budget
            .try_reserve_bytes(budget.limit_bytes() - floor - (demand - 1))
            .unwrap();
        let occupied = budget.reserved_bytes();
        let error = worker.finish_payload_build().unwrap_err();
        let PublicationError::Deferred(ref returned) = error else {
            panic!("local signature preparation must return its exact original refusal: {error:?}");
        };
        let AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        } = returned
            .allocation_refusal()
            .expect("original exact demand")
        else {
            panic!("actual occupied original pool is temporary, not policy-invalid");
        };
        assert_eq!(*requested_bytes, demand);
        assert_eq!(*reserved_bytes, occupied);
        assert_eq!(*limit_bytes, budget.limit_bytes());
        let release = release.clone();
        assert_eq!(returned.release_wait(), Some(&release));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Pending
        );
        for _ in 0..2 {
            let retained = worker.payload_build.as_ref().unwrap();
            let Some(SourcePreparationError::Source(BlockSignatureCustodyError::ControlAdmission(
                original @ AllocationRefusal::Capacity { .. },
            ))) = &retained.preparation_refusal
            else {
                panic!("retain original pre-wire control refusal with the actual job");
            };
            assert_eq!(original, returned.allocation_refusal().unwrap());
            assert_eq!(retained.scope, scope);
            let source = retained.job.source();
            assert_eq!(source.block.header(), header);
            assert_eq!(source.block.external_entrypoints_slice().as_ptr(), entries);
            assert_eq!(
                source.block.external_entrypoints_slice()[0].hash(),
                input_hash
            );
            assert!(source.pending_inputs.is_none());
            assert!(!source.block.signatures_admitted_to(&budget));
            assert_eq!(budget.reserved_bytes(), occupied);
            assert_eq!(worker.applied, applied);
            assert!(worker.completed_payload.is_none());
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(worker.recovery.is_none());
            assert!(events.try_recv().is_err());
            let again = worker.finish_payload_build().unwrap_err();
            assert_eq!(again, error);
            assert_eq!(
                registration.poll_wait(&release, &mut context),
                Poll::Pending
            );
        }
        drop(pressure);
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Ready(())
        );
        let (bytes, attest) = worker.finish_payload_build().unwrap();
        let bytes = bytes.unwrap();
        assert!(bytes.admitted_to(&budget));
        assert_eq!(bytes.as_slice(), expected);
        assert!(!attest);
        assert!(worker.payload_build.is_none());
        assert_eq!((scope.height, scope.view), (applied.0 + 1, 0));
        // This source has no Queue lease and cannot authorize completed-payload reuse.
        assert!(worker.completed_payload.is_none());
        assert_eq!(worker.applied, applied);
        assert_eq!(worker.state.view().height() as u64, applied.0);
        assert!(events.try_recv().is_err());
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), floor);
    });
}

#[test]
fn original_local_payload_wire_refusal_retains_completed_leaf_without_repreparation() {
    publication_tests::with_worker(|chain, worker, _blocks, events| {
        let _epoch = crossbeam_epoch::pin();
        let budget = worker.state.ivm_execution_budget();
        let source = original_source(chain, worker);
        let expected = source.block.encode_wire().unwrap();
        let entries = source.block.external_entrypoints_slice().as_ptr();
        let input_hash = source.block.external_entrypoints_slice()[0].hash();
        let header = source.block.header();
        let applied = worker.applied;
        let scope = install_original(worker, source, budget.clone());
        let floor = budget.reserved_bytes();
        let demand = BlockSignatures::allocation_layout().size();
        let pressure = budget
            .try_reserve_bytes(budget.limit_bytes() - floor - (demand + expected.len() - 1))
            .unwrap();
        let occupied = budget.reserved_bytes();
        for _ in 0..2 {
            assert!(matches!(
                worker.finish_payload_build(),
                Err(PublicationError::Retryable(_))
            ));
            let retained = worker.payload_build.as_ref().unwrap();
            assert!(retained.preparation_refusal.is_none());
            assert_eq!(retained.scope, scope);
            let source = retained.job.source();
            assert!(source.block.signatures_admitted_to(&budget));
            assert_eq!(source.block.header(), header);
            assert_eq!(source.block.external_entrypoints_slice().as_ptr(), entries);
            assert_eq!(
                source.block.external_entrypoints_slice()[0].hash(),
                input_hash
            );
            assert!(source.pending_inputs.is_none());
            assert_eq!(budget.reserved_bytes(), occupied + demand);
            assert_eq!(worker.applied, applied);
            assert!(worker.completed_payload.is_none());
            assert!(events.try_recv().is_err());
        }
        drop(pressure);
        let (bytes, _) = worker.finish_payload_build().unwrap();
        let bytes = bytes.unwrap();
        assert!(bytes.admitted_to(&budget));
        assert_eq!(bytes.as_slice(), expected);
        assert!(worker.payload_build.is_none());
        assert!(worker.completed_payload.is_none());
        assert_eq!(worker.applied, applied);
        assert_eq!(worker.state.view().height() as u64, applied.0);
        assert!(events.try_recv().is_err());
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), floor);
    });
}
