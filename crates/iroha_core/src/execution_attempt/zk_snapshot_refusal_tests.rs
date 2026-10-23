//! Real cold-registry hydration retains its decoder owner through transaction abandonment.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::CoreHost,
    state::{State, World},
};
use iroha_data_model::{
    block::BlockHeader,
    confidential::ConfidentialStatus,
    proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use mv::storage::StorageReadOnly;
use std::num::NonZeroU64;

#[inline(never)]
fn fixture(suffix: &str) -> (Box<State>, VerifyingKeyId, Vec<u8>) {
    let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
    // Separate complete registry identities keep each test cold without clearing or bypassing
    // the real process-local preparation memo. Failed preparation never inserts a memo entry.
    let circuit = format!("{backend}:hydration-original-refusal-{suffix}");
    let key = crate::zk_stark::StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit.clone(),
        n_log2: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: crate::zk_stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    let original = norito::encode_canonical(&key).unwrap();
    let vk = VerifyingKeyBox::new(backend.into(), original.clone());
    let id = VerifyingKeyId::new(backend, format!("hydration-original-refusal-{suffix}"));
    let mut record = VerifyingKeyRecord::new_with_owner(
        1,
        circuit,
        None,
        "hydration",
        BackendTag::Stark,
        "goldilocks",
        [0x59; 32],
        crate::zk::hash_vk(&vk),
    );
    record.status = ConfidentialStatus::Active;
    record.max_proof_bytes = 1_048_576;
    record.gas_schedule_id = Some("stark_default".to_owned());
    record.vk_len = u32::try_from(original.len()).unwrap();
    record.key = Some(vk);
    let mut world = World::new();
    world.verifying_keys.insert(id.clone(), record);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    (Box::new(state), id, original)
}

fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0)
}

#[test]
fn cold_registry_refusal_keeps_original_scope_and_fresh_state_retry() {
    let (state, id, original_key) = fixture("cold-retry");
    let original_state = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let view = state.view();
    let record = view.world().verifying_keys.get(&id).unwrap();
    let source_pointer = record.key.as_ref().unwrap().bytes.as_ptr();
    assert_eq!(record.key.as_ref().unwrap().bytes, original_key);
    drop(view);
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    let mut host = CoreHost::new(iroha_test_samples::ALICE_ID.clone());
    let pool = transaction
        .pipeline_ivm_prepared_cache
        .execution_budget()
        .clone();
    let before = (
        transaction.last_tx_gas_used,
        transaction.executor_fuel_remaining,
        transaction.confidential_gas_used_in_tx,
        transaction.pipeline_ivm_prepared_cache.stats(),
        pool.reserved_bytes(),
    );
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || transaction.hydrate_zk_snapshots_for_execution(&mut host),
    )
    .expect_err("a genuinely cold verifier key must retain its actual enclosing refusal");
    assert!(matches!(error, ValidationFail::InternalError(_)));
    assert!(transaction.is_execution_deferred());
    let retained = transaction.borrow_execution_deferral();
    let owner = retained
        .as_ref()
        .expect("original refusal retained in this attempt");
    assert!(owner.verification_refusal().is_some());
    let original = owner
        .decode_refusal()
        .expect("original decoder scope owner")
        .clone();
    assert_eq!(
        original.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert!(
        owner.allocation_refusal().is_none(),
        "no invented allocation wake source"
    );
    assert!(
        std::error::Error::source(&original)
            .and_then(|cause| cause.downcast_ref::<norito::core::ScopedDecodeResourceError>())
            .is_some()
    );
    drop(retained);
    assert_eq!(
        (
            transaction.last_tx_gas_used,
            transaction.executor_fuel_remaining,
            transaction.confidential_gas_used_in_tx,
            transaction.pipeline_ivm_prepared_cache.stats(),
            pool.reserved_bytes(),
        ),
        before,
        "hydration refusal publishes no VM work, fee settlement or cache checkout"
    );
    // The normal execution guard transfers this exact original owner once. A later entry
    // cannot reuse this incomplete attempt even after its local decode scope has retired.
    let moved = transaction.ensure_execution_ready().unwrap_err();
    assert_eq!(moved.decode_refusal(), Some(&original));
    let moved = ExecutionDeferred::try_from_vm_error(moved.into_vm_error()).unwrap();
    assert_eq!(moved.decode_refusal(), Some(&original));
    assert_eq!(
        transaction.ensure_execution_ready().unwrap_err().reason(),
        ExecutionDeferral::LocalInvariantViolation
    );
    assert!(transaction.is_execution_deferred());
    assert_eq!(
        transaction
            .world
            .verifying_keys
            .get(&id)
            .unwrap()
            .key
            .as_ref()
            .unwrap()
            .bytes,
        original_key
    );
    drop(host);
    drop(transaction);
    assert_eq!(block.committed_fragment_count(), 0);
    assert_eq!(block.gas_used_in_block, 0);
    drop(block);
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        original_state
    );
    assert_eq!(
        state
            .view()
            .world()
            .verifying_keys
            .get(&id)
            .unwrap()
            .key
            .as_ref()
            .unwrap()
            .bytes
            .as_ptr(),
        source_pointer
    );

    // A new disposable block and child read the same committed State and exact key bytes.
    // The original refused block is never reset, applied, or used as retry authority.
    let mut fresh_block = state.block(header());
    let mut fresh = fresh_block.transaction();
    let mut fresh_host = CoreHost::new(iroha_test_samples::ALICE_ID.clone());
    fresh
        .hydrate_zk_snapshots_for_execution(&mut fresh_host)
        .expect("the same cold registry can prepare after only local capacity is restored");
    assert!(!fresh.is_execution_deferred());
    fresh.ensure_execution_ready().unwrap();
    assert_eq!(
        fresh
            .world
            .verifying_keys
            .get(&id)
            .unwrap()
            .key
            .as_ref()
            .unwrap()
            .bytes,
        original_key
    );
    assert_eq!(fresh.last_tx_gas_used, 0);
    drop(fresh_host);
    drop(fresh);
    assert_eq!(fresh_block.committed_fragment_count(), 0);
    drop(fresh_block);
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        original_state
    );
}

#[test]
fn malformed_registry_remains_completed_validation_rejection() {
    let (state, id, original_key) = fixture("malformed");
    let original_state = crate::snapshot::canonical_state_snapshot_bytes(&state);
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    transaction
        .world
        .verifying_keys
        .get_mut(&id)
        .unwrap()
        .commitment[0] ^= 1;
    let mut host = CoreHost::new(iroha_test_samples::ALICE_ID.clone());
    let error = transaction
        .hydrate_zk_snapshots_for_execution(&mut host)
        .unwrap_err();
    assert!(matches!(error, ValidationFail::InternalError(message)
        if message == format!("invalid ZK snapshot state: {}", VMError::NoritoInvalid)));
    assert!(!transaction.is_execution_deferred());
    assert!(transaction.borrow_execution_deferral().is_none());
    transaction.ensure_execution_ready().unwrap();
    assert_eq!(transaction.last_tx_gas_used, 0);
    assert_eq!(
        transaction
            .world
            .verifying_keys
            .get(&id)
            .unwrap()
            .key
            .as_ref()
            .unwrap()
            .bytes,
        original_key
    );
    drop(host);
    drop(transaction);
    assert_eq!(block.committed_fragment_count(), 0);
    drop(block);
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(&state),
        original_state
    );
}
