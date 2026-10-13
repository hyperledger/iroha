// Signed exact fee claims and additive custody regressions on committed network XOR.

pub(super) fn network_xor_claim_fixture(
    stx: &mut StateTransaction<'_, '_>,
    policy: ValidationFeePolicyV1,
) -> (ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1) {
    let binding = active_bindings(stx).unwrap().remove(0);
    crate::state::validate_network_xor_asset(&stx.world, &binding.xor_asset_id)
        .expect("shared fee fixture uses the committed network XOR definition");
    (policy, binding)
}

pub(super) fn claim_current_fee_credit(
    stx: &mut StateTransaction<'_, '_>,
    account: &AccountId,
    lane: LaneId,
) -> Result<(), Error> {
    let plan = fee_reward_claim_plan(&stx.world, stx.block_height(), account, lane)
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    if let Some(plan) = plan {
        let prepared = prepare_fee_reward_claim(stx, account, lane, &plan)?;
        claim_fee_rewards(stx, prepared)?;
    }
    Ok(())
}

pub(super) fn seed_claim_credit(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    claimant: &AccountId,
    amount: u128,
    balance: u128,
) {
    use iroha_data_model::IntoKeyValue;
    let original = beneficiary::root(stx, binding, claimant).unwrap();
    let previous = read::<u128>(stx, &claimable_key(binding, &original).unwrap())
        .unwrap()
        .unwrap_or(0);
    let period = earning_month(stx.block_unix_timestamp_ms() - 60 * DAY_MS).unwrap();
    if service_weights(stx, binding, period).unwrap().is_empty() {
        seed_service(
            stx,
            binding,
            period,
            &BTreeMap::from([(claimant.clone(), 1)]),
        );
    }
    fund_test_conversion(stx, binding, period, amount.checked_sub(previous).unwrap());
    accrue_all(stx, binding);
    let asset = AssetId::new(
        binding.xor_asset_id.clone(),
        binding.reward_pool_account_id.clone(),
    );
    let (_, value) = Asset::new(asset.clone(), quantity(balance, 9).unwrap()).into_key_value();
    stx.world.assets.insert(asset, value);
}

fn signed_claim_instruction(
    stx: &StateTransaction<'_, '_>,
    claimant: &AccountId,
    lane: LaneId,
    fee_claim: PublicLaneFeeRewardClaimV1,
) -> iroha_data_model::isi::staking::ClaimPublicLaneRewards {
    iroha_data_model::isi::staking::ClaimPublicLaneRewards {
        lane_id: lane,
        account: claimant.clone(),
        claim_plan: iroha_data_model::nexus::PublicLaneRewardClaimPlanV1 {
            network_scope: iroha_data_model::nexus::PublicLaneMonetaryScopeV1::Network(
                stx.network_id,
            ),
            valid_until_height: stx.block_height(),
            fee_claim,
        },
    }
}

#[test]
fn canonical_network_xor_is_required_before_fee_reward_state_changes() {
    use iroha_data_model::{
        Registrable,
        asset::{AssetBalancePolicy, AssetDefinition},
    };
    for variant in 0..4 {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
            let (mut policy, mut binding) = network_xor_claim_fixture(stx, policy);
            if variant == 1 {
                binding.xor_asset_id = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("fees", "paynet").unwrap(),
                    "substitute_xor".parse().unwrap(),
                );
            }
            let definition = AssetDefinition::new(
                binding.xor_asset_id.clone(),
                "XOR".to_owned(),
                iroha_primitives::numeric::NumericSpec::fractional(if variant == 2 {
                    2
                } else {
                    9
                }),
                if variant == 3 {
                    AssetBalancePolicy::DataspaceRestricted
                } else {
                    AssetBalancePolicy::Global
                },
                None,
            )
            .build(&account(2));
            stx.world
                .asset_definitions
                .insert(binding.xor_asset_id.clone(), definition);
            policy.reward_custody = binding.custody();
            let registry =
                crate::validation_fee::tests::policy_registry(&[policy], &[binding.clone()]);
            crate::validation_fee::tests::install_policy_registry_fixture(&registry, stx);
            let period = earning_month(stx.block_unix_timestamp_ms() - 1).unwrap();
            save_state(
                stx,
                &binding,
                &ValidationFeeRewardsState {
                    pending_sbd_total: 100,
                    ..Default::default()
                },
            )
            .unwrap();
            write(stx, pending_key(&binding, period).unwrap(), &100_u64).unwrap();
            seed_service(
                stx,
                &binding,
                period,
                &BTreeMap::from([(account(2), 1_u64)]),
            );
            let before = stx
                .world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            let offer = ConversionOffer {
                earning_period_start_ms: period,
                sbd_minor: 100,
                min_xor_minor: 100,
                sequence: 0,
            };
            let result = reserve_conversion(stx, &binding, &offer, 100);
            if variant == 0 {
                result.expect("canonical network XOR may reserve authenticated conversion output");
                assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 100);
                assert_eq!(read_state(stx, &binding).unwrap().next_allocation, 1);
                crate::validation_fee::active_policy(stx).unwrap().unwrap();
            } else {
                let error = result.expect_err(
                    "substitute identity, precision and scope cannot fund validator rewards",
                );
                assert!(error.to_string().contains("network XOR"), "{error}");
                assert_eq!(
                    stx.world
                        .smart_contract_state
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>(),
                    before
                );
                assert!(conversion_offer(stx, &binding).is_err());
                assert!(crate::validation_fee::active_policy(stx).is_err());
                assert!(
                    crate::validation_fee::validate_persisted_policy_registry_governance_v1(
                        &stx.world
                    )
                    .is_err()
                );
            }
        });
    }
}

#[test]
fn public_fee_reward_claim_rejects_wrong_network_xor_without_writes_and_retries_original_plan() {
    use iroha_data_model::{
        Registrable,
        asset::{AssetBalancePolicy, AssetDefinition},
        parameter::Parameter,
    };
    use iroha_primitives::numeric::NumericSpec;

    for substitute_identity in [true, false] {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
            let (_, binding) = network_xor_claim_fixture(stx, policy);
            let claimant = account(2);
            seed_claim_credit(stx, &binding, &claimant, 100, 250);
            let plan = fee_reward_claim_plan(
                &stx.world,
                stx.block_height(),
                &claimant,
                binding.validator_lane_id,
            )
            .unwrap()
            .unwrap();
            let instruction =
                signed_claim_instruction(stx, &claimant, binding.validator_lane_id, plan.clone());
            let original_wire = norito::encode_canonical(&instruction).unwrap();
            let original_parameters = stx.world.sumeragi_npos_parameters().unwrap().unwrap();
            assert_eq!(
                original_parameters.xor_asset_definition_id,
                binding.xor_asset_id
            );
            let original_definition = stx
                .world
                .asset_definitions
                .get(&binding.xor_asset_id)
                .unwrap()
                .clone();
            stx.world
                .public_lane_stake_reserves
                .insert(plan.source_asset.clone(), quantity(150, 9).unwrap());
            let rows_before = stx
                .world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            let source_before = stx.world.assets.get(&plan.source_asset).unwrap().clone();
            let destination_before = stx.world.assets.get(&plan.destination_asset).cloned();
            let stake_before = stx
                .world
                .public_lane_stake_reserves
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            let credit_key = claimable_key(&binding, &plan.beneficiary_id).unwrap();
            let original_state = read_state(stx, &binding).unwrap();
            assert_eq!(original_state.reserved_xor, 100);
            assert_eq!(read::<u128>(stx, &credit_key).unwrap(), Some(100));

            if substitute_identity {
                let substitute = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("fees", "paynet").unwrap(),
                    "different_network_xor".parse().unwrap(),
                );
                assert_ne!(substitute, binding.xor_asset_id);
                stx.world.asset_definitions.insert(
                    substitute.clone(),
                    AssetDefinition::new(
                        substitute.clone(),
                        "XOR",
                        NumericSpec::fractional(9),
                        AssetBalancePolicy::Global,
                        None,
                    )
                    .build(&claimant),
                );
                let mut changed = original_parameters.clone();
                changed.xor_asset_definition_id = substitute;
                changed.validate().unwrap();
                stx.world
                    .parameters
                    .get_mut()
                    .set_parameter(Parameter::Custom(changed.into_custom_parameter()))
                    .expect("valid fixture parameters");
            } else {
                // Scale eighteen still admits this scale-nine payment. If HC58 omits
                // the canonical-currency guard, no unrelated precision check should
                // reject the otherwise exact original claim.
                stx.world
                    .asset_definitions
                    .get_mut(&binding.xor_asset_id)
                    .unwrap()
                    .spec = NumericSpec::fractional(18);
            }
            let error = instruction
                .clone()
                .execute(&claimant, stx)
                .expect_err("public fee claim must reject changed network XOR before any payment");
            let expected = if substitute_identity {
                "committed network XOR"
            } else {
                "global network XOR with scale nine"
            };
            assert!(error.to_string().contains(expected), "{error}");
            assert!(stx.execution_deferral().is_none());
            assert_eq!(
                stx.world
                    .smart_contract_state
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                rows_before
            );
            assert_eq!(
                stx.world.assets.get(&plan.source_asset),
                Some(&source_before)
            );
            assert_eq!(
                stx.world.assets.get(&plan.destination_asset),
                destination_before.as_ref()
            );
            assert_eq!(
                stx.world
                    .public_lane_stake_reserves
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                stake_before
            );
            assert_eq!(
                read_state(stx, &binding).unwrap().reserved_xor,
                original_state.reserved_xor
            );
            assert_eq!(
                read_state(stx, &binding).unwrap().next_claim,
                original_state.next_claim
            );
            assert_eq!(read::<u128>(stx, &credit_key).unwrap(), Some(100));

            // Restore only the deliberately changed currency relation. The claim
            // source, original authorized claim plan, fee credit and original instruction persist.
            stx.world
                .parameters
                .get_mut()
                .set_parameter(Parameter::Custom(
                    original_parameters.into_custom_parameter(),
                ))
                .expect("valid fixture parameters");
            stx.world
                .asset_definitions
                .insert(binding.xor_asset_id.clone(), original_definition);
            assert_eq!(
                norito::encode_canonical(&instruction).unwrap(),
                original_wire
            );
            instruction.clone().execute(&claimant, stx).expect(
                "unchanged original authorized claim plan retries after exact currency restoration",
            );
            assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 0);
            assert_eq!(
                read_state(stx, &binding).unwrap().next_claim,
                original_state.next_claim + 1
            );
            assert_eq!(read::<u128>(stx, &credit_key).unwrap(), None);
            assert_eq!(
                stx.world.assets.get(&plan.source_asset).unwrap().as_ref(),
                &quantity(150, 9).unwrap()
            );
            assert_eq!(
                stx.world
                    .assets
                    .get(&plan.destination_asset)
                    .unwrap()
                    .as_ref(),
                &quantity(100, 9).unwrap()
            );
            assert_eq!(
                stx.world.public_lane_stake_reserves.get(&plan.source_asset),
                Some(&quantity(150, 9).unwrap())
            );
            let receipt = read::<ValidationFeeRewardClaim>(
                stx,
                &state_key(&binding, &format!("Claim/{}", plan.expected_claim_sequence)).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(receipt.sequence, plan.expected_claim_sequence);
            assert_eq!(receipt.account_id, claimant);
            assert_eq!(receipt.xor_minor, 100);
            assert!(
                instruction
                    .execute(&claimant, stx)
                    .unwrap_err()
                    .to_string()
                    .contains("no eligible reserved credit")
            );
        });
    }
}

#[test]
fn signed_fee_reward_claim_rejects_every_changed_binding_before_mutation() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let claimant = account(2);
        seed_claim_credit(stx, &binding, &claimant, 100, 200);
        let plan = fee_reward_claim_plan(
            &stx.world,
            stx.block_height(),
            &claimant,
            binding.validator_lane_id,
        )
        .unwrap()
        .unwrap();
        let before = stx
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        let pool_before = stx.world.assets.get(&plan.source_asset).cloned();
        for change in 0..8 {
            let mut changed = plan.clone();
            match change {
                0 => changed.lifecycle_seal[0] ^= 1,
                1 => changed.beneficiary_id = account(3),
                2 => changed.beneficiary_revision += 1,
                3 => changed.source_asset = AssetId::new(binding.xor_asset_id.clone(), account(3)),
                4 => {
                    changed.destination_asset =
                        AssetId::new(binding.xor_asset_id.clone(), account(3))
                }
                5 => changed.amount = quantity(99, 9).unwrap(),
                6 => changed.expected_claim_sequence += 1,
                _ => {
                    changed.source_asset = AssetId::with_scope(
                        binding.xor_asset_id.clone(),
                        binding.reward_pool_account_id.clone(),
                        iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::new(1)),
                    )
                }
            }
            let instruction =
                signed_claim_instruction(stx, &claimant, binding.validator_lane_id, changed);
            let error = instruction
                .execute(&claimant, stx)
                .expect_err("every fee claim coordinate is signed");
            let expected = if matches!(change, 4 | 7) {
                "reward claim must authorize one exact positive funded payment"
            } else {
                "exact current signed monetary plan"
            };
            assert!(
                error.to_string().contains(expected),
                "change {change}: {error}"
            );
            assert_eq!(
                stx.world
                    .smart_contract_state
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                before
            );
            assert_eq!(
                stx.world.assets.get(&plan.source_asset),
                pool_before.as_ref()
            );
        }
        let instruction =
            signed_claim_instruction(stx, &claimant, binding.validator_lane_id, plan.clone());
        instruction.clone().execute(&claimant, stx).unwrap();
        assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 0);
        assert_eq!(
            stx.world
                .assets
                .get(&plan.destination_asset)
                .unwrap()
                .as_ref(),
            &quantity(100, 9).unwrap()
        );
        assert!(
            instruction
                .execute(&claimant, stx)
                .unwrap_err()
                .to_string()
                .contains("no eligible reserved credit")
        );
    });
}

#[test]
fn self_custody_fee_claim_releases_only_its_exact_reserve_without_debiting_balance() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let claimant = binding.reward_pool_account_id.clone();
        seed_claim_credit(stx, &binding, &claimant, 100, 250);
        let source = AssetId::new(binding.xor_asset_id.clone(), claimant.clone());
        stx.world
            .public_lane_stake_reserves
            .insert(source.clone(), quantity(150, 9).unwrap());
        let plan = fee_reward_claim_plan(
            &stx.world,
            stx.block_height(),
            &claimant,
            binding.validator_lane_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.source_asset, plan.destination_asset);
        let instruction = signed_claim_instruction(stx, &claimant, binding.validator_lane_id, plan);
        instruction.clone().execute(&claimant, stx).unwrap();
        assert_eq!(
            stx.world.assets.get(&source).unwrap().as_ref(),
            &quantity(250, 9).unwrap(),
            "self-custody claims release a liability without changing the balance"
        );
        assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 0);
        assert_eq!(read_state(stx, &binding).unwrap().next_claim, 1);
        assert_eq!(
            stx.world.public_lane_stake_reserves.get(&source),
            Some(&quantity(150, 9).unwrap())
        );
        assert!(
            read::<u128>(stx, &claimable_key(&binding, &claimant).unwrap())
                .unwrap()
                .is_none()
        );
        instruction
            .execute(&claimant, stx)
            .expect_err("released credit cannot be claimed again");
    });
}

#[test]
fn unreadable_credit_rejects_the_required_claim_without_mutation() {
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let claimant = account(2);
        seed_claim_credit(stx, &binding, &claimant, 100, 200);
        let plan = fee_reward_claim_plan(
            &stx.world,
            stx.block_height(),
            &claimant,
            binding.validator_lane_id,
        )
        .unwrap()
        .unwrap();
        let key = claimable_key(&binding, &claimant).unwrap();
        stx.world.smart_contract_state.insert(key, vec![0xff]);
        let before = stx
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        signed_claim_instruction(stx, &claimant, binding.validator_lane_id, plan)
            .execute(&claimant, stx)
            .expect_err("malformed protected credit rejects the entire claim");
        assert_eq!(
            stx.world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            before
        );
    });
}

#[test]
fn shared_fee_stake_reward_custody_is_additive() {
    use iroha_data_model::IntoKeyValue;
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let claimant = account(2);
        seed_claim_credit(stx, &binding, &claimant, 100, 300);
        let source = AssetId::new(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
        );
        stx.world
            .public_lane_stake_reserves
            .insert(source.clone(), quantity(150, 9).unwrap());
        ensure_reward_custody_debit(stx, &source, &quantity(50, 9).unwrap()).unwrap();
        assert!(
            ensure_reward_custody_debit(stx, &source, &quantity(51, 9).unwrap()).is_err(),
            "distinct liabilities must add, not overlap"
        );
        let scoped = AssetId::with_scope(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::new(9)),
        );
        assert_eq!(
            reserved_fee_custody(&stx.world, &scoped).unwrap(),
            Quantity::zero(),
            "global reservations cannot attach to another scope"
        );
        assert!(
            crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
                &stx.world,
                binding.validator_lane_id,
                &claimant,
                &source,
                &quantity(51, 9).unwrap(),
                &quantity(300, 9).unwrap()
            )
            .is_err()
        );
        crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
            &stx.world,
            binding.validator_lane_id,
            &claimant,
            &source,
            &quantity(50, 9).unwrap(),
            &quantity(300, 9).unwrap(),
        )
        .unwrap();
        // Restoration and signed claims also reject a balance that backs each
        // ledger alone but cannot back their sum.
        let (_, underfunded) =
            Asset::new(source.clone(), quantity(200, 9).unwrap()).into_key_value();
        stx.world.assets.insert(source.clone(), underfunded);
        assert!(validate_fee_custody_backing(&stx.world).is_err());
        assert!(
            fee_reward_claim_plan(
                &stx.world,
                stx.block_height(),
                &claimant,
                binding.validator_lane_id
            )
            .is_err()
        );
        let (_, funded) = Asset::new(source.clone(), quantity(300, 9).unwrap()).into_key_value();
        stx.world.assets.insert(source.clone(), funded);
        validate_fee_custody_backing(&stx.world).unwrap();
        Transfer::asset_quantity(source.clone(), quantity(51, 9).unwrap(), account(3))
            .execute(&binding.reward_pool_account_id, stx)
            .expect_err("generic debit cannot consume the same funds twice");
        Transfer::asset_quantity(source.clone(), quantity(50, 9).unwrap(), account(3))
            .execute(&binding.reward_pool_account_id, stx)
            .unwrap();
        iroha_data_model::isi::Burn::asset_quantity(quantity(1, 9).unwrap(), source.clone())
            .execute(&binding.reward_pool_account_id, stx)
            .expect_err("burn cannot consume funded rewards or staking principal");
        let fee = fee_reward_claim_plan(
            &stx.world,
            stx.block_height(),
            &claimant,
            binding.validator_lane_id,
        )
        .unwrap();
        signed_claim_instruction(stx, &claimant, binding.validator_lane_id, fee.unwrap())
            .execute(&claimant, stx)
            .unwrap();
        assert_eq!(
            stx.world.assets.get(&source).unwrap().as_ref(),
            &quantity(150, 9).unwrap()
        );
        assert_eq!(
            stx.world.public_lane_stake_reserves.get(&source),
            Some(&quantity(150, 9).unwrap())
        );
    });
}

#[test]
fn fee_reward_claim_refuses_currency_substitution_and_stale_credit() {
    use iroha_data_model::parameter::{Parameter, system::SumeragiNposParameters};
    crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, policy| {
        let (_, binding) = network_xor_claim_fixture(stx, policy);
        let claimant = account(2);
        seed_claim_credit(stx, &binding, &claimant, 100, 200);
        let plan = fee_reward_claim_plan(
            &stx.world,
            stx.block_height(),
            &claimant,
            binding.validator_lane_id,
        )
        .unwrap();
        let params = SumeragiNposParameters {
            xor_asset_definition_id: binding.ds_asset_id.clone(),
            ..Default::default()
        };
        stx.world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(params.into_custom_parameter()))
            .expect("valid fixture parameters");
        let before = stx
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        let currency_error =
            crate::state::validate_network_xor_asset(&stx.world, &binding.xor_asset_id)
                .expect_err("claim custody must still name the committed network XOR");
        assert!(
            currency_error.to_string().contains("committed network XOR"),
            "{currency_error}"
        );
        assert!(
            prepare_fee_reward_claim(
                stx,
                &claimant,
                binding.validator_lane_id,
                plan.as_ref().unwrap()
            )
            .is_err(),
            "the claim must propagate its authenticated registry refusal"
        );
        assert_eq!(
            stx.world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            before,
            "rejected currency cannot alter the credit, receipt sequence or reserve"
        );
        stx.world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ))
            .expect("valid fixture parameters");
        seed_claim_credit(stx, &binding, &claimant, 101, 200);
        assert!(
            prepare_fee_reward_claim(
                stx,
                &claimant,
                binding.validator_lane_id,
                plan.as_ref().unwrap()
            )
            .err()
            .unwrap()
            .to_string()
            .contains("exact current signed monetary plan")
        );
        beneficiary::rekey_beneficiary(stx, &claimant, &account(3)).unwrap();
        assert!(
            prepare_fee_reward_claim(
                stx,
                &claimant,
                binding.validator_lane_id,
                plan.as_ref().unwrap()
            )
            .is_err()
        );
        let recovered = fee_reward_claim_plan(
            &stx.world,
            stx.block_height(),
            &account(3),
            binding.validator_lane_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(recovered.beneficiary_id, claimant);
        assert_eq!(recovered.beneficiary_revision, 1);
        assert_eq!(recovered.destination_asset.account(), &account(3));
    });
}
