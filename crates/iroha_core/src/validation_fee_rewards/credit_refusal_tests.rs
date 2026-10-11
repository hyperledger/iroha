// Exact current fee-claim identity reads preserve credit/reserves through refusal and rollback.

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 32)
}

fn allocation_used(operation: impl FnOnce()) -> usize {
    const CEILING: usize = 8 * 1024 * 1024;
    norito::with_decode_limits_scope(limits(CEILING), || {
        operation();
        let norito::Error::TotalAllocationExceeded { attempted, limit } =
            norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
        else {
            panic!("the original cumulative decode counter must be observable");
        };
        assert_eq!(limit, CEILING as u64);
        usize::try_from(attempted).unwrap() - CEILING - 1
    })
}

fn check_current_claim_identity_refusal(owner_revision: bool) {
    crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, policy| {
        let claimant = account(2);
        let binding = {
            let mut seed = block.transaction();
            let (_, binding) = network_xor_claim_fixture(&mut seed, policy);
            seed_claim_credit(&mut seed, &binding, &claimant, 100, 200);
            seed.apply();
            binding
        };
        let lane = binding.validator_lane_id;
        let credit_key = claimable_key(&binding, &claimant).unwrap();
        let state_key = state_key(&binding, "State").unwrap();
        let source = AssetId::new(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
        );
        let before_balance = block.world.assets.get(&source).cloned();
        let before_credit = block
            .world
            .smart_contract_state
            .get(&credit_key)
            .unwrap()
            .clone();
        let before_state = block
            .world
            .smart_contract_state
            .get(&state_key)
            .unwrap()
            .clone();
        let original_pointer = block
            .world
            .smart_contract_state
            .get(&credit_key)
            .unwrap()
            .as_ptr();
        let marker: StatePath = "fee_claim_unpublished_TESTDATA".parse().unwrap();
        let mut stx = block.transaction();
        // A transaction owns its own storage snapshot. Preserve each original source
        // allocation across refusal, rather than equating it with its parent snapshot.
        let original_transaction_pointer = stx
            .world
            .smart_contract_state
            .get(&credit_key)
            .unwrap()
            .as_ptr();
        let original_parent_root_pointer = stx
            .world
            .smart_contract_state
            .get_before_transaction(&credit_key)
            .unwrap()
            .as_ptr();
        let plan = fee_reward_claim_plan(&stx.world, stx.block_height(), &claimant, lane)
            .unwrap()
            .unwrap();
        assert_eq!(plan.source_asset, source);
        assert_eq!(plan.amount, quantity(100, 9).unwrap());
        let prefix = || {
            let observed = crate::validation_fee::active_payout_binding_in_world_at_height(
                &stx.world,
                stx.block_height(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(observed, binding);
            if owner_revision {
                let original = beneficiary::root_in_world(&stx.world, &binding, &claimant).unwrap();
                assert_eq!(original, claimant);
                let key = claimable_key(&binding, &original).unwrap();
                assert_eq!(
                    read_from_world::<u128>(&stx.world, &key).unwrap(),
                    Some(100)
                );
                crate::state::validate_network_xor_asset(&stx.world, &binding.xor_asset_id)
                    .unwrap();
            }
        };
        // The old synthetic Treasury-credit leaf is gone. Target the current immutable
        // beneficiary alias or revision, after admitting exactly the real claim prefix.
        let prefix_bytes = allocation_used(prefix);
        assert!(prefix_bytes > 0);
        norito::with_decode_limits_scope(limits(prefix_bytes), prefix);
        let target_refusal = norito::with_decode_limits_scope(limits(prefix_bytes), || {
            prefix();
            if owner_revision {
                beneficiary::owner_in_world(&stx.world, &binding, &claimant).map(|_| ())
            } else {
                beneficiary::root_in_world(&stx.world, &binding, &claimant).map(|_| ())
            }
        })
        .unwrap_err();
        assert!(
            matches!(&target_refusal, ExecutionAttemptError::Deferred(reason)
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                && reason.allocation_refusal().is_none())
        );
        let refused = norito::with_decode_limits_scope(limits(prefix_bytes), || {
            fee_reward_claim_plan(&stx.world, stx.block_height(), &claimant, lane)
        })
        .unwrap_err();
        assert!(matches!(&refused, ExecutionAttemptError::Deferred(reason)
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                && reason.allocation_refusal().is_none()));
        assert!(
            stx.execution_deferral().is_none(),
            "a read-only plan retains the original error"
        );
        assert_eq!(
            fee_reward_claim_plan(&stx.world, stx.block_height(), &claimant, lane).unwrap(),
            Some(plan.clone())
        );
        assert_eq!(
            stx.world
                .smart_contract_state
                .get(&credit_key)
                .unwrap()
                .as_ptr(),
            original_transaction_pointer,
            "read-only refusal and retry keep the original current leaf"
        );
        stx.world
            .smart_contract_state
            .insert(marker.clone(), vec![1]);
        // The marker insertion may copy a shared tree node and its complete values.
        // The original parent root remains retained; the subsequent refused claim
        // must preserve the exact private leaf created by that legitimate edit.
        let original_private_pointer = stx
            .world
            .smart_contract_state
            .get(&credit_key)
            .unwrap()
            .as_ptr();
        let refused = norito::with_decode_limits_scope(limits(prefix_bytes), || {
            prepare_fee_reward_claim(&stx, &claimant, lane, &plan)
        });
        assert!(refused.is_err());
        let deferred = stx
            .execution_deferral()
            .expect("connected signed-claim preparation is sticky");
        assert_eq!(
            deferred.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(deferred.allocation_refusal().is_none());
        assert_eq!(
            stx.world.smart_contract_state.get(&credit_key),
            Some(&before_credit)
        );
        assert_eq!(
            stx.world.smart_contract_state.get(&state_key),
            Some(&before_state)
        );
        assert_eq!(stx.world.assets.get(&source).cloned(), before_balance);
        assert_eq!(
            stx.world
                .smart_contract_state
                .get(&credit_key)
                .unwrap()
                .as_ptr(),
            original_private_pointer
        );
        assert_eq!(
            stx.world
                .smart_contract_state
                .get_before_transaction(&credit_key)
                .unwrap()
                .as_ptr(),
            original_parent_root_pointer,
            "the original parent leaf remains owned across the private edit and refusal"
        );
        stx.apply();
        assert!(block.world.smart_contract_state.get(&marker).is_none());
        assert_eq!(
            block
                .world
                .smart_contract_state
                .get(&credit_key)
                .unwrap()
                .as_ptr(),
            original_pointer,
            "the refused transaction preserves its original parent storage owner"
        );
        assert_eq!(
            block.world.smart_contract_state.get(&credit_key),
            Some(&before_credit)
        );
        assert_eq!(
            block.world.smart_contract_state.get(&state_key),
            Some(&before_state)
        );
        assert_eq!(block.world.assets.get(&source).cloned(), before_balance);
        let retry = block.transaction();
        let prepared = prepare_fee_reward_claim(&retry, &claimant, lane, &plan).unwrap();
        assert_eq!(prepared.plan, plan);
        assert!(retry.execution_deferral().is_none());
    });
}

#[test]
fn original_fee_credit_alias_decode_refusal_preserves_balance_and_retries() {
    check_current_claim_identity_refusal(false);
}

#[test]
fn original_fee_credit_owner_decode_refusal_preserves_exact_binding_and_retries() {
    check_current_claim_identity_refusal(true);
}
