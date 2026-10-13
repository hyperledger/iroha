//! Original signed runtime and enacted monthly-policy refusal/rollback controls.

use super::*;
use iroha_model_base::state_path::StatePath;

fn limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32)
}

fn signed_runtime(
    test: impl FnOnce(
        &mut StateTransaction<'_, '_>,
        &ValidationFeeTreasuryPayoutBindingV1,
        &crate::executor::ContractRuntimeExecutionContext,
        &[u8],
    ),
) {
    let (chain, binding) = signed_payout_lifecycle_registry_fixture();
    let state = chain.state();
    let height = state.view().height();
    let tip = state.view().latest_block_hash();
    let mut block = state.block(BlockHeader::new(
        u64::try_from(height + 1).unwrap().try_into().unwrap(),
        tip,
        None,
        4_000,
        0,
    ));
    let mut stx = block.transaction();
    let mut feed = iroha_data_model::oracle::kits::price_xor_usd().feed_config;
    feed.feed_id = binding.reference_feed_id.clone();
    feed.feed_config_version =
        iroha_data_model::oracle::FeedConfigVersion(binding.reference_feed_config_version);
    feed.providers = binding.reference_provider_accounts.clone();
    feed.min_signers = 3;
    feed.committee_size = 5;
    stx.world.oracle_feeds.insert(feed.feed_id.clone(), feed);
    // Contract identity/code come from the two genuine signed deployments above;
    // only the reference-feed observation is an isolated component overlay.
    let record =
        crate::smartcontracts::code::fetch_bound_contract_record(&stx, &binding.contract_address)
            .unwrap()
            .unwrap();
    let runtime = crate::executor::ContractRuntimeExecutionContext {
        contract_address: binding.contract_address.clone(),
        contract_subject: binding.treasury_account_id.clone(),
        contract_alias: None,
        entrypoint: binding.entrypoint.to_string(),
    };
    test(&mut stx, &binding, &runtime, &record.code_bytes);
    drop(stx);
    drop(block);
    assert_eq!(state.view().height(), height);
    assert_eq!(state.view().latest_block_hash(), tip);
    assert_eq!(chain.kura().blocks_count(), height);
}

#[test]
fn signed_fee_subject_read_keeps_scope_refusal_distinct_from_inactive_treasury() {
    signed_runtime(|stx, binding, _, _| {
        const CEILING: usize = 8 * 1024 * 1024;
        let run = || {
            validate_treasury_payout_binding_contract_subject(
                binding,
                TEST_VALIDATION_FEE_ASSET_SCALE,
                stx,
            )
        };
        run().expect("original signed contracts and exact reference feed");
        // The network currency read now precedes the contract read. Admit exactly
        // that prefix so a currency-registry refusal cannot impersonate this test.
        let prefix = || {
            validate_network_xor_asset(stx.world(), &binding.xor_asset_id).unwrap();
        };
        let prefix_bytes = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, CEILING, 32),
            || {
                prefix();
                let norito::Error::TotalAllocationExceeded { attempted, .. } =
                    norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
                else {
                    panic!("original cumulative decode counter");
                };
                usize::try_from(attempted).unwrap() - CEILING - 1
            },
        );
        let scope = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, prefix_bytes, 32);
        norito::with_decode_limits_scope(scope, prefix);
        let target = norito::with_decode_limits_scope(scope, || {
            prefix();
            crate::smartcontracts::code::fetch_bound_contract_record(stx, &binding.contract_address)
        });
        assert!(
            matches!(target, Err(ExecutionAttemptError::Deferred(_))),
            "the original contract reader must reach the local refusal"
        );
        let refused = norito::with_decode_limits_scope(scope, run);
        assert!(
            matches!(refused, Err(ExecutionAttemptError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        );
        run().expect("unchanged original contract retries");
        assert!(!stx.is_execution_deferred());
    });
}

#[test]
fn signed_fee_runtime_read_does_not_turn_scope_refusal_into_a_nonmatching_origin() {
    signed_runtime(|stx, binding, runtime, code| {
        let origin = OpaqueDeferredRuntimeOrigin::new(runtime, code);
        let run = || runtime_origin_matches_payout_binding(binding, stx, &origin);
        assert!(run().unwrap());
        let refused = norito::with_decode_limits_scope(limits(), run);
        assert!(
            matches!(refused, Err(ExecutionAttemptError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        );
        assert!(run().unwrap(), "original code and subject survive refusal");
        assert!(!stx.is_execution_deferred());
    });
}

#[test]
fn original_retained_fee_registry_does_not_publish_local_decode_refusal_as_malformed() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        assert_eq!(
            policy.charging_mode,
            iroha_data_model::validation_fee::ValidationFeeChargingMode::RetailMonthlyAllowance
        );
        let original = validated_policy_registry_in_world(&stx.world).unwrap();
        assert!(original.is_some());
        // An owned enclosing budget must survive the same real registry read.
        // Its scoped error is distinct from the unscoped quota cases below.
        let source = stx
            .world
            .parameters()
            .custom()
            .get(&ValidationFeePolicyRegistryV1::parameter_id())
            .unwrap()
            .payload();
        let source_pointer = source.get().as_ptr();
        let pool = iroha_allocation::AllocationBudget::new(
            norito::core::DecodeBudgetContext::allocation_layout().size(),
        );
        let context = norito::core::DecodeBudgetContext::try_new_owned(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32),
            &pool,
        )
        .unwrap();
        let reserved = pool.reserved_bytes();
        let raw = context.with(|| {
            norito::with_decode_limits_scope(limits(), || {
                // Scoped provenance is minted by the real observer around the read,
                // not by the retained budget context alone.
                norito::core::classify_decode_attempt(|| {
                    Ok::<_, norito::Error>(norito::json::from_str::<ValidationFeePolicyRegistryV1>(
                        source.get(),
                    ))
                })
                .unwrap()
            })
        });
        assert!(matches!(
            raw,
            Err(norito::json::Error::ScopedDecodeResource(_))
        ));
        let before = context.consumed_allocated_bytes();
        let scoped = context.with(|| {
            norito::with_decode_limits_scope(limits(), || {
                validated_policy_registry_in_world(&stx.world)
            })
        });
        assert!(
            matches!(scoped, Err(ExecutionAttemptError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
            "owned registry decoder refusal must not become malformed policy: {scoped:?}"
        );
        assert!(context.consumed_allocated_bytes() > before);
        assert_eq!(pool.reserved_bytes(), reserved);
        assert_eq!(source.get().as_ptr(), source_pointer);
        assert_eq!(
            context
                .with(|| validated_policy_registry_in_world(&stx.world))
                .unwrap(),
            original
        );
        drop(raw);
        drop(scoped);
        drop(context);
        assert_eq!(pool.reserved_bytes(), 0);
        let refused = norito::with_decode_limits_scope(limits(), || {
            validated_policy_registry_in_world(&stx.world)
        });
        assert!(
            matches!(refused, Err(ExecutionAttemptError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        );
        let refused = norito::with_decode_limits_scope(limits(), || {
            validate_persisted_policy_registry_runtime_v1(stx, stx.block_height())
        });
        assert!(
            matches!(refused, Err(ExecutionAttemptError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        );
        assert_eq!(
            validated_policy_registry_in_world(&stx.world).unwrap(),
            original
        );
        validate_persisted_policy_registry_runtime_v1(stx, stx.block_height()).unwrap();
        assert!(!stx.is_execution_deferred());
    });
}

#[test]
fn retained_registry_refusal_blocks_fee_effect_publication_and_original_retry() {
    let (chain, binding) = signed_payout_lifecycle_registry_fixture();
    // Payout policy is its own finalized registry owner under the current monthly
    // model. No obsolete per-transfer credit policy is recreated for this test.
    let registry = policy_registry(&[], &[binding]);
    let state = chain.state();
    let height = state.view().height();
    let tip = state.view().latest_block_hash();
    let header = BlockHeader::new(
        u64::try_from(height + 1).unwrap().try_into().unwrap(),
        tip,
        None,
        4_000,
        0,
    );
    let mut block = state.block(header);
    let marker: StatePath = "fee_refusal_unpublished_TESTDATA".parse().unwrap();
    let groups = std::collections::BTreeMap::new();
    let mut stx = block.transaction();
    install_policy_registry_fixture(&registry, &mut stx);
    stx.world
        .smart_contract_state
        .insert(marker.clone(), vec![1]);
    enforce_opaque_deferred_instruction_groups(&groups, &[], &mut stx, None).unwrap();
    assert!(!stx.is_execution_deferred());
    let refused = norito::with_decode_limits_scope(limits(), || {
        enforce_opaque_deferred_instruction_groups(&groups, &[], &mut stx, None)
    });
    assert!(refused.is_err());
    let original = stx.borrow_execution_deferral().unwrap();
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(original.allocation_refusal().is_none());
    drop(original);
    stx.apply();
    assert!(block.world.smart_contract_state.get(&marker).is_none());
    assert!(
        validated_policy_registry_in_world(&block.world)
            .unwrap()
            .is_none()
    );
    assert!(
        matches!(
            block.commit(),
            Err(
                crate::state::storage_transactions::TransactionsBlockError::ExecutionOutputCapacity
            )
        ),
        "refused original output cannot reach publication"
    );
    assert_eq!(state.view().height(), height);
    assert_eq!(state.view().latest_block_hash(), tip);
    assert_eq!(chain.kura().blocks_count(), height);
    let mut block = state.block(header);
    let mut retry = block.transaction();
    install_policy_registry_fixture(&registry, &mut retry);
    enforce_opaque_deferred_instruction_groups(&groups, &[], &mut retry, None).unwrap();
    assert!(!retry.is_execution_deferred());
}
