//! Actual State prepass refusal, retry and conservative scheduling boundary.

use super::*;
use crate::{
    pipeline::access::{
        AccessSetSource, IvmStrategy, derive_for_transaction_with_source,
        derive_from_ivm_dynamic_with_context,
    },
    state::{State, StateReadOnly, World},
};
use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
use iroha_data_model::{
    Registrable,
    account::Account,
    block::BlockHeader,
    transaction::{Executable, FeePaymentIntent, IvmBytecode, TransactionBuilder},
};
use std::{
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    task::{Context, Poll, Waker},
};

fn fixture() -> State {
    let authority = iroha_test_samples::ALICE_ID.clone();
    let account = Account::new(authority.clone()).build(&authority);
    State::new(
        crate::pipeline::overlay::test_support::with_global_root(World::with([], [account], [])),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    )
}

fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0)
}

fn program() -> Vec<u8> {
    let mut bytes = ivm::ProgramMetadata::default().encode();
    bytes.extend(ivm::encoding::wide::encode_halt().to_le_bytes());
    bytes
}

#[test]
fn vm_stage_projection_keeps_original_capacity_release_and_completed_errors() {
    let registration_bytes = ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(registration_bytes + 1);
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let occupied = budget.try_reserve_bytes(1).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let ExecutionAttemptError::Deferred(deferred) = vm_error(
        "ivm.run",
        ivm::VMError::metered(7, ivm::VMError::AllocationDeferred(original.clone())),
    ) else {
        panic!("original capacity refusal must stay deferred");
    };
    assert_eq!(deferred.allocation_refusal(), Some(&original));
    let Some(AllocationRefusal::Capacity { release, .. }) = deferred.allocation_refusal() else {
        panic!("original source remains observable");
    };
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Pending);
    drop(occupied);
    assert_eq!(Pin::new(&mut wait).poll(&mut context), Poll::Ready(()));
    drop(wait);
    assert!(matches!(vm_error("ivm.run", ivm::VMError::InvalidMetadata),
        ExecutionAttemptError::Rejected(message) if message.starts_with("ivm.run: ")));
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_state_prepass_refuses_original_pool_then_retries_without_a_verdict() {
    let state = fixture();
    let block = state.block(header());
    let budget = block.execution_budget();
    let baseline = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    let bytes = program();
    budget.set_limit_bytes(0);
    let result = derive_from_ivm_dynamic_with_context(
        &bytes,
        &iroha_test_samples::ALICE_ID,
        None,
        &block,
        10_000,
    );
    assert!(
        matches!(result, Err(ExecutionAttemptError::Deferred(ref reason))
        if matches!(reason.allocation_refusal(), Some(AllocationRefusal::ExceedsLimit { .. })))
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(limit);
    let set = derive_from_ivm_dynamic_with_context(
        &bytes,
        &iroha_test_samples::ALICE_ID,
        None,
        &block,
        10_000,
    )
    .unwrap();
    assert!(set.write_keys.contains("*"));
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn funded_prepass_constructor_uses_the_original_state_cache_and_reclaims() {
    let state = fixture();
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let budget = cache.execution_budget();
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    let vm = new_vm(&cache, 10_000).unwrap();
    assert!(budget.reserved_bytes() > baseline);
    let live = budget.reserved_bytes();
    budget.set_limit_bytes(live);
    assert!(matches!(
        new_vm(&cache, 10_000),
        Err(ExecutionAttemptError::Deferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), live);
    drop(vm);
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(original_limit);
}

#[test]
fn raw_selector_preparation_refusal_retries_the_same_state_owner() {
    let state = fixture();
    let view = state.view();
    let cache = view.prepared_contract_cache();
    let budget = cache.execution_budget();
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku PrepassFunding { kotoage fn main() authorize(\"Run\") {} }")
        .unwrap();
    let original_limit = budget.limit_bytes();
    let baseline = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    assert!(matches!(
        prepare(&cache, &bytes),
        Err(ExecutionAttemptError::Deferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(original_limit);
    let prepared = prepare(&cache, &bytes).unwrap();
    assert_eq!(prepared.code_hash(), ivm::contract_code_hash(&bytes));
    assert!(budget.reserved_bytes() > baseline);
}

#[test]
fn resource_refusal_keeps_outer_dynamic_access_conservative() {
    let mut state = fixture();
    state.edit_pipeline_for_testing(|pipeline| pipeline.access_set_cache_enabled = false);
    let block = state.block(header());
    let budget = block.execution_budget();
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"dynamic-prepass-memory",
        )),
    );
    let original_limit = budget.limit_bytes();
    let transaction = TransactionBuilder::new(
        network,
        iroha_test_samples::ALICE_ID.clone(),
        FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_000)),
    )
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program())))
    .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    budget.set_limit_bytes(0);
    let (set, source) = derive_for_transaction_with_source(
        &transaction,
        Some(&block),
        IvmStrategy::DynamicThenConservative,
    );
    assert!(set.write_keys.contains("*"));
    assert_eq!(source, Some(AccessSetSource::ConservativeFallback));
    budget.set_limit_bytes(original_limit);
}
