//! Original root decoder scope survives mutable, read-only and VM boundaries.

use super::*;
use crate::execution_attempt::{ExecutionAttemptError, ExecutionDeferred};
use iroha_data_model::smart_contract::ContractArtifactId;
use norito::core::{DecodeLocalRefusal, DecodeLocalRefusalKind, DecodeResourceError};

fn assert_original_zero_limit(owner: &ExecutionDeferred) -> DecodeLocalRefusal {
    assert_eq!(
        owner.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(owner.allocation_refusal().is_none());
    assert!(owner.verification_refusal().is_none());
    let cause = owner
        .decode_refusal()
        .expect("actual scoped JSON decoder")
        .clone();
    assert_eq!(cause.kind(), DecodeLocalRefusalKind::EnclosingLimit);
    assert!(matches!(cause.resource_error(),
        DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 } if attempted > 0));
    assert!(matches!(
        cause.clone().into_error(),
        norito::Error::ScopedDecodeResource(_)
    ));
    cause
}

#[test]
fn mutable_root_reader_retains_exact_original_scope_through_owner_move_and_publication() {
    use crate::state::WorldReadOnly as _;
    let (state, ds) = private_state();
    let original_parameter = state
        .world
        .parameters
        .view()
        .custom()
        .get(&iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id())
        .unwrap()
        .clone();
    let mut block = state.block(header(2));
    let original;
    {
        let mut tx = block.transaction();
        bind_scope(&mut tx, ds);
        let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            64,
        ));
        assert!(context.with(|| execution_root_scope(&mut tx)).is_err());
        original = assert_original_zero_limit(&tx.borrow_execution_deferral().unwrap());
        let storage = StateStorageAdmissionError::RootScopeDecode(original.clone());
        assert_eq!(tx.require_storage_admission(), Err(storage.clone()));
        assert!(storage.release_wait().is_none());
        // A second actual parser scope cannot replace either first-refusal latch.
        assert!(context.with(|| execution_root_scope(&mut tx)).is_err());
        assert_eq!(
            tx.borrow_execution_deferral().unwrap().decode_refusal(),
            Some(&original)
        );
        let moved = tx
            .take_execution_deferral()
            .expect("original owning carrier");
        assert_eq!(moved.decode_refusal(), Some(&original));
        assert!(tx.is_execution_deferred());
        let bridged = ExecutionDeferred::try_from_vm_error(moved.into_vm_error()).unwrap();
        assert_eq!(bridged.decode_refusal(), Some(&original));
        assert_eq!(tx.require_storage_admission(), Err(storage));
        assert_eq!(
            tx.world.parameters().custom().get(original_parameter.id()),
            Some(&original_parameter)
        );
        tx.apply();
    }
    assert_eq!(
        block.require_storage_admission(),
        Err(StateStorageAdmissionError::RootScopeDecode(
            original.clone()
        ))
    );
    assert!(matches!(block.commit_world_overlay_for_testing(),
        Err(crate::state::storage_transactions::TransactionsBlockError::LocalStateStorage(
            StateStorageAdmissionError::RootScopeDecode(cause))) if cause == original));
    let mut fresh = state.block(header(2));
    let mut retry = fresh.transaction();
    bind_scope(&mut retry, ds);
    assert!(matches!(execution_root_scope(&mut retry).unwrap(),
        SumeragiRootScope::Dataspace { dataspace_id, .. } if dataspace_id == ds));
    assert!(!retry.is_execution_deferred());
    assert!(retry.require_storage_admission().is_ok());
    assert_eq!(
        retry
            .world
            .parameters()
            .custom()
            .get(original_parameter.id()),
        Some(&original_parameter)
    );
}

#[test]
fn committed_contract_and_artifact_readers_preserve_distinct_actual_scopes_and_retry() {
    let (state, ds) = private_state();
    let view = state.view();
    let address = ContractAddress::derive(state.network_id_ref(), &ALICE_ID, 0, ds).unwrap();
    let artifact = ContractArtifactId::new(ds, Hash::new(b"original root decoder artifact"));
    let mut observed = Vec::new();
    for contract in [true, false] {
        let read = || {
            if contract {
                ensure_committed_contract_scope(view.world(), &address)
            } else {
                ensure_committed_artifact_scope(view.world(), &artifact)
            }
        };
        read().unwrap();
        let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            64,
        ));
        let ExecutionAttemptError::Deferred(owner) = context.with(read).unwrap_err() else {
            panic!("actual local decoder refusal became completed root absence");
        };
        let cause = assert_original_zero_limit(&owner);
        let moved = ExecutionDeferred::try_from_vm_error(owner.into_vm_error()).unwrap();
        assert_eq!(moved.decode_refusal(), Some(&cause));
        observed.push(cause);
        read().unwrap();
    }
    assert_eq!(observed[0].resource_error(), observed[1].resource_error());
    assert_ne!(
        observed[0], observed[1],
        "independent reads retain different opaque owners"
    );
}
