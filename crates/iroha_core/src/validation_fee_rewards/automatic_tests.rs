// Automatic historical nomination accrual through funded custody and signed claims.

pub(super) fn record_test_service(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    stakes: &[(u8, u32)],
) {
    exposure::record_service(
        stx,
        binding,
        period,
        validator,
        stakes
            .iter()
            .map(|(seed, amount)| (account(*seed), Quantity::from(*amount)))
            .collect(),
    )
    .unwrap();
    let mut source = service_snapshot(stx, binding, period).unwrap();
    *source.service_blocks.entry(validator.clone()).or_default() += 1;
    write(stx, service_key(binding, period).unwrap(), &source).unwrap();
}

pub(super) fn fund_test_conversion(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    amount: u128,
) -> ConversionOffer {
    use iroha_data_model::IntoKeyValue;
    let mut state = read_state(stx, binding).unwrap();
    state.pending_sbd_total = state.pending_sbd_total.checked_add(100).unwrap();
    let pending = read::<u64>(stx, &pending_key(binding, period).unwrap())
        .unwrap()
        .unwrap_or(0);
    write(stx, pending_key(binding, period).unwrap(), &(pending + 100)).unwrap();
    let offer = ConversionOffer {
        earning_period_start_ms: period,
        sbd_minor: 100,
        min_xor_minor: amount,
        sequence: state.next_allocation,
    };
    save_state(stx, binding, &state).unwrap();
    reserve_conversion(stx, binding, &offer, amount).unwrap();
    // The existing conversion-effect integration suite authenticates the three
    // transfers. Here install precisely their received XOR, never staking funds.
    let pool = AssetId::new(
        binding.xor_asset_id.clone(),
        binding.reward_pool_account_id.clone(),
    );
    let previous = stx
        .world
        .assets
        .get(&pool)
        .map_or(0, |value| minor_units(value.as_ref(), 9).unwrap());
    let (_, value) =
        Asset::new(pool.clone(), quantity(previous + amount, 9).unwrap()).into_key_value();
    stx.world.assets.insert(pool, value);
    offer
}

pub(super) fn signed_claim_all(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    claimant: &AccountId,
) {
    let plan = fee_reward_claim_plan(
        &stx.world,
        stx.block_height(),
        claimant,
        binding.validator_lane_id,
    )
    .unwrap()
    .unwrap();
    signed_claim_instruction(stx, claimant, binding.validator_lane_id, plan)
        .execute(claimant, stx)
        .unwrap();
}

#[test]
fn automatic_multiple_validator_nominations_accrue_and_claim_exact_xor() {
    const XOR: u128 = 1_000_000_000;
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
        record_test_service(
            stx,
            &binding,
            period,
            &account(2),
            &[(2, 20), (3, 30), (4, 50)],
        );
        record_test_service(stx, &binding, period, &account(5), &[(5, 1)]);
        let offer = fund_test_conversion(stx, &binding, period, 200 * XOR);
        assert!(
            read::<u128>(stx, &claimable_key(&binding, &account(3)).unwrap())
                .unwrap()
                .is_none()
        );
        assert!(reserve_conversion(stx, &binding, &offer, 200 * XOR).is_err());
        assert!(settlement::accrue_next_page(stx, &binding).unwrap());
        assert!(settlement::accrue_next_page(stx, &binding).unwrap());
        assert!(!settlement::accrue_next_page(stx, &binding).unwrap());
        for (seed, expected) in [(2, 20), (3, 30), (4, 50), (5, 100)] {
            let claimant = account(seed);
            assert_eq!(
                read::<u128>(stx, &claimable_key(&binding, &claimant).unwrap()).unwrap(),
                Some(expected * XOR)
            );
            signed_claim_all(stx, &binding, &claimant);
            let asset = AssetId::new(binding.xor_asset_id.clone(), claimant.clone());
            assert_eq!(
                minor_units(stx.world.assets.get(&asset).unwrap().as_ref(), 9).unwrap(),
                expected * XOR
            );
            assert!(
                fee_reward_claim_plan(
                    &stx.world,
                    stx.block_height(),
                    &claimant,
                    binding.validator_lane_id
                )
                .unwrap()
                .is_none()
            );
        }
        let state = read_state(stx, &binding).unwrap();
        assert_eq!(
            (state.reserved_xor, state.next_allocation, state.next_claim),
            (0, 1, 4)
        );
        reconciliation::validate(&stx.world, &binding).unwrap();
    });
}

#[test]
fn empty_eligible_service_preserves_validator_gross_and_signed_claim() {
    const XOR: u128 = 1_000_000_000;
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let validator = account(2);
        let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
        // This component starts after authenticated signer admission. A retained
        // signer can have no bonded exposure after unbonding or slashing; the
        // actual committee-admission and parent-capture tests cover that owner.
        // The synthetic unit is only an allocation weight, never staking funds.
        let original_stake_rows = stx
            .world
            .public_lane_stake_shares
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        exposure::record_service(stx, &binding, period, &validator, BTreeMap::new()).unwrap();
        write(
            stx,
            service_key(&binding, period).unwrap(),
            &ValidationFeeServiceSnapshot {
                earning_period_start_ms: period,
                service_blocks: BTreeMap::from([(validator.clone(), 1)]),
            },
        )
        .unwrap();
        let captured: iroha_data_model::validation_fee_rewards::ValidationFeeExposurePage = read(
            stx,
            &exposure::page_key(&binding, period, &validator, 0).unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            captured.exposure,
            vec![
                iroha_data_model::validation_fee_rewards::ValidationFeeRewardExposure {
                    service_blocks: 1,
                    stakes: BTreeMap::from([(validator.clone(), Quantity::one())]),
                }
            ]
        );
        fund_test_conversion(stx, &binding, period, 100 * XOR);
        assert!(settlement::accrue_next_page(stx, &binding).unwrap());
        assert!(!settlement::accrue_next_page(stx, &binding).unwrap());
        assert_eq!(
            read::<u128>(stx, &claimable_key(&binding, &validator).unwrap()).unwrap(),
            Some(100 * XOR)
        );
        signed_claim_all(stx, &binding, &validator);
        let asset = AssetId::new(binding.xor_asset_id.clone(), validator);
        assert_eq!(
            minor_units(stx.world.assets.get(&asset).unwrap().as_ref(), 9).unwrap(),
            100 * XOR
        );
        let rewards = read_state(stx, &binding).unwrap();
        assert_eq!((rewards.reserved_xor, rewards.next_claim), (0, 1));
        assert_eq!(
            stx.world
                .public_lane_stake_shares
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            original_stake_rows
        );
        reconciliation::validate(&stx.world, &binding).unwrap();
    });
}

#[test]
fn delayed_funding_preserves_pre_exit_service_and_late_stake_cannot_capture_it() {
    const XOR: u128 = 1_000_000_000;
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let period = earning_month(stx.block_unix_timestamp_ms() - 60 * DAY_MS).unwrap();
        record_test_service(
            stx,
            &binding,
            period,
            &account(2),
            &[(2, 20), (3, 30), (4, 50)],
        );
        // New exposure after A/B unbond: they retain the first service's credit.
        record_test_service(stx, &binding, period, &account(2), &[(2, 20), (6, 80)]);
        // The second historical nominator recovers before any funding arrives.
        rekey_beneficiary(stx, &account(4), &account(7)).unwrap();
        fund_test_conversion(stx, &binding, period, 200 * XOR);
        accrue_all(stx, &binding);
        for (seed, expected) in [(2, 40), (3, 30), (6, 80), (7, 50)] {
            let claimant = account(seed);
            let plan = fee_reward_claim_plan(
                &stx.world,
                stx.block_height(),
                &claimant,
                binding.validator_lane_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(minor_units(&plan.amount, 9).unwrap(), expected * XOR);
            signed_claim_all(stx, &binding, &claimant);
        }
        assert!(
            fee_reward_claim_plan(
                &stx.world,
                stx.block_height(),
                &account(4),
                binding.validator_lane_id
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 0);
        reconciliation::validate(&stx.world, &binding).unwrap();
    });
}

#[test]
fn automatic_cursor_rounding_conserves_minor_units_across_cohorts_and_replay() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
        record_test_service(
            stx,
            &binding,
            period,
            &account(2),
            &[(2, 1), (3, 1), (4, 1)],
        );
        record_test_service(stx, &binding, period, &account(2), &[(6, 1)]);
        record_test_service(stx, &binding, period, &account(2), &[(6, 1)]);
        fund_test_conversion(stx, &binding, period, 101);
        let cursor_key = state_key(&binding, "AllocationCursor").unwrap();
        let cursor: settlement::RewardAllocationCursor = read(stx, &cursor_key).unwrap().unwrap();
        assert!(settlement::accrue_next_page(stx, &binding).unwrap());
        for seed in [2, 3, 4] {
            assert_eq!(
                read::<u128>(stx, &claimable_key(&binding, &account(seed)).unwrap()).unwrap(),
                Some(11)
            );
        }
        assert_eq!(
            read::<u128>(stx, &claimable_key(&binding, &account(6)).unwrap()).unwrap(),
            Some(68)
        );
        assert!(!settlement::accrue_next_page(stx, &binding).unwrap());
        write(stx, cursor_key.clone(), &cursor).unwrap();
        assert!(settlement::accrue_next_page(stx, &binding).is_err());
        stx.world.smart_contract_state.remove(cursor_key);
        for seed in [2, 3, 4, 6] {
            signed_claim_all(stx, &binding, &account(seed));
        }
        reconciliation::validate(&stx.world, &binding).unwrap();
    });
}

#[test]
fn automatic_nominator_failed_transfer_rolls_back_credit_reserve_and_claim_receipt() {
    use iroha_data_model::{
        asset::transfer_control::{
            ASSET_TRANSFER_CONTROL_METADATA_KEY, AssetTransferControlRecord,
            AssetTransferControlStoreV1,
        },
        isi::error::AssetTransferAdmissionError,
    };
    crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, policy| {
        let claimant = account(3);
        let (binding, instruction, before, assets_before, original_controls) = {
            let mut stx = block.transaction();
            let (_, binding) = network_xor_claim_fixture(&mut stx, policy);
            let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
            record_test_service(
                &mut stx,
                &binding,
                period,
                &account(2),
                &[(2, 20), (3, 30), (4, 50)],
            );
            fund_test_conversion(&mut stx, &binding, period, 100);
            accrue_all(&mut stx, &binding);
            let plan = fee_reward_claim_plan(
                &stx.world,
                stx.block_height(),
                &claimant,
                binding.validator_lane_id,
            )
            .unwrap()
            .unwrap();
            let instruction =
                signed_claim_instruction(&stx, &claimant, binding.validator_lane_id, plan);
            let mut control = AssetTransferControlRecord::new(binding.xor_asset_id.clone());
            control.blacklisted = true;
            let mut controls = AssetTransferControlStoreV1::default();
            controls.upsert(control);
            let original_controls = stx
                .world
                .accounts
                .get_mut(&binding.reward_pool_account_id)
                .unwrap()
                .metadata_mut()
                .insert(
                    ASSET_TRANSFER_CONTROL_METADATA_KEY.parse().unwrap(),
                    iroha_primitives::json::Json::new(controls),
                );
            let before = stx
                .world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            let assets_before = stx
                .world
                .assets
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            stx.apply();
            (
                binding,
                instruction,
                before,
                assets_before,
                original_controls,
            )
        };
        {
            let mut attempt = block
                .transaction_for_fastpq_testing(Hash::new(b"automatic-nominator-failed-payment"));
            let error = instruction
                .clone()
                .execute(&claimant, &mut attempt)
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    Error::AssetTransferAdmission(AssetTransferAdmissionError::Blacklisted(message))
                        if message.as_ref() == format!(
                            "account {} on asset definition {}",
                            binding.reward_pool_account_id, binding.xor_asset_id
                        )
                ),
                "claim must reach the exact funded-custody transfer control: {error}"
            );
            assert!(
                read::<ValidationFeeRewardClaim>(
                    &attempt,
                    &state_key(&binding, "Claim/0").unwrap()
                )
                .unwrap()
                .is_some(),
                "the claim receipt was staged before the payment failed"
            );
            assert_eq!(read_state(&attempt, &binding).unwrap().next_claim, 1);
            assert_eq!(
                attempt
                    .world
                    .assets
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                assets_before,
                "the failed asset transfer changes neither custody nor recipient balances"
            );
        }
        let mut restored =
            block.transaction_for_fastpq_testing(Hash::new(b"automatic-nominator-retried-payment"));
        assert_eq!(
            restored
                .world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            before
        );
        assert_eq!(
            read::<u128>(&restored, &claimable_key(&binding, &claimant).unwrap()).unwrap(),
            Some(30)
        );
        assert_eq!(read_state(&restored, &binding).unwrap().reserved_xor, 100);
        assert_eq!(read_state(&restored, &binding).unwrap().next_claim, 0);
        assert_eq!(
            restored
                .world
                .assets
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            assets_before
        );
        reconciliation::validate(&restored.world, &binding).unwrap();
        // Remove only the test's outbound blacklist, then retry the identical
        // authenticated claim plan at the same execution height.
        let metadata = restored
            .world
            .accounts
            .get_mut(&binding.reward_pool_account_id)
            .unwrap()
            .metadata_mut();
        if let Some(controls) = original_controls {
            metadata.insert(
                ASSET_TRANSFER_CONTROL_METADATA_KEY.parse().unwrap(),
                controls,
            );
        } else {
            metadata.remove(ASSET_TRANSFER_CONTROL_METADATA_KEY);
        }
        instruction
            .clone()
            .execute(&claimant, &mut restored)
            .unwrap();
        let pool = AssetId::new(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
        );
        let recipient = AssetId::new(binding.xor_asset_id.clone(), claimant.clone());
        assert_eq!(
            restored.world.assets.get(&pool).unwrap().as_ref(),
            &quantity(70, 9).unwrap()
        );
        assert_eq!(
            restored.world.assets.get(&recipient).unwrap().as_ref(),
            &quantity(30, 9).unwrap()
        );
        assert_eq!(read_state(&restored, &binding).unwrap().reserved_xor, 70);
        assert_eq!(read_state(&restored, &binding).unwrap().next_claim, 1);
        assert!(
            read::<u128>(&restored, &claimable_key(&binding, &claimant).unwrap())
                .unwrap()
                .is_none()
        );
        reconciliation::validate(&restored.world, &binding).unwrap();
        restored.apply();
        let mut duplicate = block
            .transaction_for_fastpq_testing(Hash::new(b"automatic-nominator-duplicate-payment"));
        let error = instruction.execute(&claimant, &mut duplicate).unwrap_err();
        assert!(
            error.to_string().contains("no eligible reserved credit"),
            "{error}"
        );
        assert_eq!(
            duplicate.world.assets.get(&pool).unwrap().as_ref(),
            &quantity(70, 9).unwrap()
        );
        assert_eq!(
            duplicate.world.assets.get(&recipient).unwrap().as_ref(),
            &quantity(30, 9).unwrap()
        );
        assert_eq!(read_state(&duplicate, &binding).unwrap().next_claim, 1);
    });
}

#[test]
fn automatic_accrual_late_owner_failure_rolls_back_and_retries_exactly_once() {
    use iroha_data_model::validation_fee_rewards::{
        ValidationFeeRewardBeneficiaryAlias, validation_fee_beneficiary_alias_key,
    };

    crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, policy| {
        let mut recipients = [account(2), account(3), account(4)];
        recipients.sort();
        let (binding, alias_key, original_alias) = {
            let mut setup = block.transaction();
            let (_, binding) = network_xor_claim_fixture(&mut setup, policy);
            let period = earning_month(setup.block_unix_timestamp_ms()).unwrap();
            record_test_service(
                &mut setup,
                &binding,
                period,
                &account(2),
                &[(2, 20), (3, 30), (4, 50)],
            );
            fund_test_conversion(&mut setup, &binding, period, 100);
            for recipient in &recipients {
                beneficiary::ensure(&mut setup, &binding, recipient).unwrap();
            }
            // Corrupt the last recipient, after earlier recipients can be
            // credited in the private accrual transaction. This represents a
            // damaged retained identity, not a public mutation API.
            let alias_key = validation_fee_beneficiary_alias_key(&binding, &recipients[2]).unwrap();
            let original_alias = setup
                .world
                .smart_contract_state
                .get(&alias_key)
                .unwrap()
                .clone();
            let malformed = ValidationFeeRewardBeneficiaryAlias {
                account_id: account(9),
                beneficiary_id: recipients[2].clone(),
            };
            setup
                .world
                .smart_contract_state
                .insert(alias_key.clone(), norito::to_bytes(&malformed).unwrap());
            setup.apply();
            (binding, alias_key, original_alias)
        };
        let before = block
            .world
            .smart_contract_state
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect::<BTreeMap<_, _>>();
        let pool = AssetId::new(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
        );
        let pool_before = block.world.assets.get(&pool).cloned();
        let fragments_before = block.committed_fragment_count();
        {
            let mut probe = block.transaction();
            let error = settlement::accrue_next_page(&mut probe, &binding).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("malformed immutable reward beneficiary alias")
            );
            assert!(
                read::<u128>(&probe, &claimable_key(&binding, &recipients[0]).unwrap())
                    .unwrap()
                    .is_some(),
                "the failure occurs after a prior recipient was privately credited"
            );
        }
        assert!(matches!(
            settlement::process_reward_entitlements(block),
            Err(crate::state::ExecutionOutputAttemptError::Owner(_))
        ));
        assert_eq!(block.committed_fragment_count(), fragments_before);
        assert_eq!(
            block
                .world
                .smart_contract_state
                .iter()
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect::<BTreeMap<_, _>>(),
            before,
            "failed automatic maintenance publishes no partial credit, receipt, or cursor"
        );
        assert_eq!(block.world.assets.get(&pool).cloned(), pool_before);
        {
            let mut repair = block.transaction();
            repair
                .world
                .smart_contract_state
                .insert(alias_key, original_alias);
            repair.apply();
        }
        settlement::process_reward_entitlements(block).unwrap();
        let successful_fragments = block.committed_fragment_count();
        settlement::process_reward_entitlements(block).unwrap();
        assert_eq!(block.committed_fragment_count(), successful_fragments);
        let mut claims =
            block.transaction_for_fastpq_testing(Hash::new(b"retried-automatic-accrual-claims"));
        for (seed, amount) in [(2, 20), (3, 30), (4, 50)] {
            let recipient = account(seed);
            assert_eq!(
                read::<u128>(&claims, &claimable_key(&binding, &recipient).unwrap()).unwrap(),
                Some(amount)
            );
            signed_claim_all(&mut claims, &binding, &recipient);
        }
        let state = read_state(&claims, &binding).unwrap();
        assert_eq!(
            (state.reserved_xor, state.next_allocation, state.next_claim),
            (0, 1, 3)
        );
        reconciliation::validate(&claims.world, &binding).unwrap();
    });
}

#[test]
fn partial_validator_accrual_claim_and_recovery_preserve_repeated_funding() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let period = earning_month(stx.block_unix_timestamp_ms()).unwrap();
        record_test_service(
            stx,
            &binding,
            period,
            &account(2),
            &[(2, 20), (3, 30), (4, 50)],
        );
        record_test_service(stx, &binding, period, &account(5), &[(3, 50), (5, 50)]);
        let original_offer = fund_test_conversion(stx, &binding, period, 200);
        assert!(settlement::accrue_next_page(stx, &binding).unwrap());
        let old = account(3);
        let recovered = account(6);
        let original_plan = fee_reward_claim_plan(
            &stx.world,
            stx.block_height(),
            &old,
            binding.validator_lane_id,
        )
        .unwrap()
        .unwrap();
        let first_paid = minor_units(&original_plan.amount, 9).unwrap();
        assert!(first_paid == 30 || first_paid == 50);
        let old_claim =
            signed_claim_instruction(stx, &old, binding.validator_lane_id, original_plan);
        old_claim.clone().execute(&old, stx).unwrap();
        beneficiary::rekey_beneficiary(stx, &old, &recovered).unwrap();
        reconciliation::validate(&stx.world, &binding).unwrap();
        let before = stx
            .world
            .smart_contract_state
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect::<BTreeMap<_, _>>();
        let next_offer = ConversionOffer {
            sequence: 1,
            ..original_offer.clone()
        };
        assert!(
            reserve_conversion(stx, &binding, &next_offer, 200)
                .unwrap_err()
                .to_string()
                .contains("still accruing")
        );
        assert!(old_claim.clone().execute(&old, stx).is_err());
        assert_eq!(
            stx.world
                .smart_contract_state
                .iter()
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect::<BTreeMap<_, _>>(),
            before
        );
        assert!(settlement::accrue_next_page(stx, &binding).unwrap());
        assert!(!settlement::accrue_next_page(stx, &binding).unwrap());
        reconciliation::validate(&stx.world, &binding).unwrap();
        let second_offer = fund_test_conversion(stx, &binding, period, 200);
        assert_eq!(second_offer.sequence, 1);
        accrue_all(stx, &binding);
        assert!(reserve_conversion(stx, &binding, &original_offer, 200).is_err());
        assert!(reserve_conversion(stx, &binding, &second_offer, 200).is_err());
        assert!(old_claim.execute(&old, stx).is_err());
        for (recipient, amount) in [
            (account(2), 40),
            (account(4), 100),
            (account(5), 100),
            (recovered.clone(), 160 - first_paid),
        ] {
            let plan = fee_reward_claim_plan(
                &stx.world,
                stx.block_height(),
                &recipient,
                binding.validator_lane_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(minor_units(&plan.amount, 9).unwrap(), amount);
            if recipient == recovered {
                assert_eq!(plan.beneficiary_id, old);
                assert_eq!(plan.beneficiary_revision, 1);
            }
            signed_claim_all(stx, &binding, &recipient);
            let asset = AssetId::new(binding.xor_asset_id.clone(), recipient);
            assert_eq!(
                minor_units(stx.world.assets.get(&asset).unwrap().as_ref(), 9).unwrap(),
                amount
            );
        }
        let old_asset = AssetId::new(binding.xor_asset_id.clone(), old);
        assert_eq!(
            minor_units(stx.world.assets.get(&old_asset).unwrap().as_ref(), 9).unwrap(),
            first_paid
        );
        let state = read_state(stx, &binding).unwrap();
        assert_eq!(
            (state.reserved_xor, state.next_allocation, state.next_claim),
            (0, 2, 5)
        );
        reconciliation::validate(&stx.world, &binding).unwrap();
    });
}
