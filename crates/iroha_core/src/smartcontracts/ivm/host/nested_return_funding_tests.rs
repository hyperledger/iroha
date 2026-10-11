// Production typed nested-call funding, completed-work metering, and rollback controls.

fn nested_return_funding_fixture() -> (State, AccountId, ContractAddress, ContractAddress) {
    let authority = fixture_account("alice");
    let state = contract_test_state(&authority);
    let caller = install_contract(
        &state,
        &authority,
        r#"
seiyaku Caller {
  error enum CalleeError { ForcedFailure = 1 }
  kotoage fn main() authorize(anyone) -> int { return 0; }
}
"#,
        0,
    );
    let callee = install_contract(
        &state,
        &authority,
        r#"
seiyaku Callee { permission AssetOps;
  error enum CalleeError { ForcedFailure = 1 }
  state int counter;
  hajimari() { counter = 0; }
  kotoage fn write() authorize(AssetOps) -> int {
    counter = 9;
    return counter;
  }
  kotoage fn fail_after_write() authorize(AssetOps) -> int {
    counter = 9;
    require(false, CalleeError::ForcedFailure);
    return 0;
  }
}
"#,
        1,
    );
    grant_asset_ops_to_account(&state, &authority, caller.subject_id());
    (state, authority, caller, callee)
}

#[test]
fn nested_call_funding_refuses_without_effects_then_retries() {
    let (state, authority, caller, callee) = nested_return_funding_fixture();
    let budget = iroha_allocation::AllocationBudget::new(0);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let (refused, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &callee,
        "write",
        Json::new(()),
        cache.clone(),
    );
    let error = refused.expect_err("cold nested execution cannot fit a zero pool");
    assert!(matches!(
        error.as_unmetered(),
        ivm::VMError::AllocationDeferred(_)
    ));
    assert!(error.execution_deferral().is_some());
    assert_eq!(error.metered_gas(), None);
    assert_eq!(vm.remaining_gas(), 1_000_000);
    assert_eq!(
        vm.validate_tlv(vm.register(10)).unwrap().payload,
        callee.as_ref().as_bytes()
    );
    assert!(effects.is_empty());
    assert_eq!(
        cache.stats().runtime_misses,
        0,
        "reserve before child checkout"
    );
    assert_eq!(cache.stats().runtime_prepared_loads, 0);
    assert_eq!(budget.reserved_bytes(), 0);

    budget.set_limit_bytes(128 * 1024 * 1024);
    let (success, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &callee,
        "write",
        Json::new(()),
        cache.clone(),
    );
    let cold_gas = success.expect("same invocation retries after local capacity returns");
    assert!(
        !effects.is_empty(),
        "only successful retry publishes the child write"
    );
    assert_eq!(
        render_nested_result(
            &vm,
            iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1::Int,
        ),
        norito::json!("9")
    );
    let after_success = cache.stats();
    let idle_bytes = budget.reserved_bytes();
    // Concurrent aggregate-cache pressure may evict idle storage. Zero still refuses the next
    // nested allocation without depending on whether that optional retention survived.
    budget.set_limit_bytes(0);
    let (refused, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &callee,
        "write",
        Json::new(()),
        cache.clone(),
    );
    let error = refused.expect_err("zero pool refuses original nested allocation custody");
    assert!(matches!(
        error.as_unmetered(),
        ivm::VMError::AllocationDeferred(_)
    ));
    assert!(error.execution_deferral().is_some());
    assert_eq!(error.metered_gas(), None);
    // An idle cached child may survive optional cache pressure. Its empty input
    // installation charges 32 + one eight-byte result word before allocation
    // refuses. If it was evicted, checkout refuses before this work begins.
    let input_installation_gas = 32 + core::mem::size_of::<u64>() as u64;
    let installation_spent = 1_000_000 - vm.remaining_gas();
    let after_refusal = cache.stats();
    if installation_spent == 0 {
        assert_eq!(after_refusal.runtime_hits, after_success.runtime_hits);
        assert!(
            after_refusal.runtime_misses == after_success.runtime_misses
                || after_refusal.runtime_misses == after_success.runtime_misses + 1,
            "eviction refuses either artifact preparation or the single cold checkout"
        );
    } else {
        assert_eq!(installation_spent, input_installation_gas);
        assert_eq!(
            after_refusal.runtime_hits,
            after_success.runtime_hits + 1,
            "reusing an idle VM is counted before its input installation can refuse"
        );
        assert_eq!(after_refusal.runtime_misses, after_success.runtime_misses);
    }
    assert_eq!(
        after_refusal.runtime_prepared_loads, after_success.runtime_prepared_loads,
        "zero capacity never loads another runtime"
    );
    assert_eq!(
        after_refusal.runtime_template_builds, after_success.runtime_template_builds,
        "zero capacity never admits a fresh runtime baseline"
    );
    // The shared dispatcher also asserts all six input descriptors are unchanged.
    assert_eq!(
        vm.validate_tlv(vm.register(10)).unwrap().payload,
        callee.as_ref().as_bytes()
    );
    assert!(effects.is_empty());
    assert!(budget.reserved_bytes() <= idle_bytes);

    budget.set_limit_bytes(128 * 1024 * 1024);
    let (retry, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &callee,
        "write",
        Json::new(()),
        cache.clone(),
    );
    assert_eq!(
        retry.expect("retry after capacity returns"),
        cold_gas,
        "funding never changes gas"
    );
    assert!(!effects.is_empty());
    assert_eq!(
        render_nested_result(
            &vm,
            iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1::Int,
        ),
        norito::json!("9")
    );
    drop(cache);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "all nested owners were reclaimed"
    );
}

#[test]
fn prepaid_nested_return_is_released_when_child_effects_roll_back() {
    let (state, authority, caller, callee) = nested_return_funding_fixture();
    let budget = iroha_allocation::AllocationBudget::new(128 * 1024 * 1024);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let (result, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &callee,
        "fail_after_write",
        Json::new(()),
        cache.clone(),
    );
    let error = result.expect_err("callee aborts after staging its write");
    assert!(matches!(
        error.as_unmetered(),
        ivm::VMError::ContractAbort { code: 1, .. }
    ));
    assert!(
        error.metered_gas().is_some(),
        "contract faults remain metered"
    );
    assert!(
        vm.remaining_gas() < 1_000_000,
        "child execution still spends its gas"
    );
    assert!(effects.is_empty(), "failed child write is rolled back");
    assert_eq!(
        vm.validate_tlv(vm.register(10)).unwrap().payload,
        callee.as_ref().as_bytes()
    );
    drop(cache);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "unused return credit cannot leak on child failure"
    );
}
