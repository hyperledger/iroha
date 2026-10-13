//! Committed staking lifecycle changes preserve earlier funded reward rights.

use super::*;
use crate::{
    smartcontracts::isi::staking::tests::{
        fixture_bond_plan, fixture_registration_plan, fixture_slash_plan, fixture_unbond_plan,
        rebind_for_test, register_peer_for_account, staking_test_lane_catalog,
    },
    state::State,
    validation_fee_rewards::tests::{account, fund_test_conversion, signed_claim_all},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    block::BlockHeader,
    isi::{
        Log, Mint,
        staking::{
            ActivatePublicLaneValidator, BondPublicLaneStake, ExitPublicLaneValidator,
            FinalizePublicLaneUnbond, RegisterPublicLaneValidator, SchedulePublicLaneUnbond,
            SlashPublicLaneValidator,
        },
    },
    nexus::{DataSpaceCatalog, DataSpaceMetadata, PublicLaneValidatorStatus},
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter},
    },
    validation_fee::{ValidationFeePayoutPolicyRegistryV1, ValidationFeePolicyRegistryV1},
    validation_fee_rewards::ValidationFeeExposurePage,
};
use iroha_model_base::{metadata::Metadata, topology::DataSpaceId};
use std::{num::NonZeroU64, time::Duration};

fn lifecycle_block(state: &State, height: u64, time: u64) -> StateBlock<'_> {
    state.block(BlockHeader::new(
        NonZeroU64::new(height).unwrap(),
        state.view().latest_block_hash(),
        None,
        time,
        0,
    ))
}

#[test]
fn old_offence_and_post_earning_reregistration_preserve_funded_nominator_claims() {
    // The debug fixture retains several full world overlays while constructing
    // authenticated genesis. Keep that test-only stack local to its owner.
    let worker = std::thread::Builder::new()
        .name("historical-reward-lifecycle".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(run_historical_reward_lifecycle)
        .expect("start historical reward lifecycle fixture");
    if let Err(panic) = worker.join() {
        std::panic::resume_unwind(panic);
    }
}

fn run_historical_reward_lifecycle() {
    const NOW: u64 = 1_735_650_000_000;
    const XOR: u128 = 1_000_000_000;
    let lane = LaneId::new(13);
    let validator = account(2);
    let nominator = account(3);
    let late_nominator = account(4);
    let replacement = account(5);
    let escrow = account(7);
    let slash_sink = account(8);
    let fee_sink = account(6);
    let deployer = account(55);
    let genesis_policy = SumeragiNposParameters::default();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.lane_catalog = staking_test_lane_catalog();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(
        nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|row| DataSpaceMetadata {
                id: row.dataspace_id,
                alias: if row.dataspace_id == DataSpaceId::UNIVERSAL {
                    "universal".to_owned()
                } else {
                    format!("staking-test-dataspace-{}", row.dataspace_id.as_u64())
                },
                description: None,
                fault_tolerance: 1,
            })
            .collect(),
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.staking.stake_asset_id = genesis_policy.xor_asset_definition_id.to_string();
    nexus.staking.stake_escrow_account_id = escrow.to_string();
    nexus.staking.slash_sink_account_id = slash_sink.to_string();
    nexus.staking.unbonding_delay = Duration::from_millis(1);
    nexus.fees.fee_asset_id = genesis_policy.xor_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = fee_sink.to_string();
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(
        crate::validation_fee::tests::validation_fee_payout_world(&deployer),
        1_000,
    );
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.nexus = Some(nexus);
    // NPoS genesis requires the policy in its signed instruction list as well
    // as the supplied World; both must retain the same immutable defaults.
    config.genesis_parameters.extend([
        Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            genesis_policy.epoch_length_blocks,
        )),
        Parameter::Custom(genesis_policy.into_custom_parameter()),
    ]);
    // The deployment/prefix fee payer is independently funded by signed genesis;
    // no staking escrow or reward custody supplies these ordinary transaction fees.
    let initial_fee_funding = Quantity::from(10_000_u32);
    config.genesis_instructions.push(
        Mint::asset_quantity(
            initial_fee_funding.clone(),
            AssetId::new(
                SumeragiNposParameters::default().xor_asset_definition_id,
                deployer.clone(),
            ),
        )
        .into(),
    );
    let (mut chain, mut binding) =
        crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture_with_config(config);
    let settled_fees = |chain: &crate::sumeragi::test_chain::CertifiedTestChain| {
        use crate::state::StateReadOnly as _;
        use iroha_data_model::{block::consensus::NexusFeeSettlementV1, nexus::FeeDebitSource};

        let view = chain.state().view();
        let payer = view
            .world
            .assets
            .get(&AssetId::new(
                binding.xor_asset_id.clone(),
                deployer.clone(),
            ))
            .unwrap()
            .as_ref()
            .clone();
        let supply = view
            .world
            .asset_definitions
            .get(&binding.xor_asset_id)
            .unwrap()
            .total_quantity()
            .clone();
        assert!(
            view.world
                .assets
                .get(&AssetId::new(
                    binding.xor_asset_id.clone(),
                    fee_sink.clone()
                ))
                .is_none(),
            "direct SORA Nexus fees burn; the configured sink is not credited"
        );
        let mut burned = Quantity::zero();
        for height in 2..=chain.height() {
            let committed = chain.committed(height);
            let block = committed.block();
            assert_eq!(block.network_entrypoint_count(), 1);
            let input = block.network_entrypoint_at(0).unwrap();
            let result = &block.network_output_at(0).unwrap().1.result;
            assert!(result.is_ok());
            let receipt = result
                .nexus_fee_receipt()
                .expect("every original deployment/prefix transaction settles a nonzero fee");
            receipt.validate_for_network_input(input, height).unwrap();
            assert_eq!(receipt.fee_asset_id, binding.xor_asset_id);
            assert_eq!(
                receipt.debit_source,
                FeeDebitSource::Account(deployer.clone())
            );
            assert_eq!(receipt.settlement, NexusFeeSettlementV1::Burn);
            let policy = &view.nexus().fees;
            assert_eq!(receipt.schedule.base_fee, policy.base_fee);
            assert_eq!(receipt.schedule.per_byte_fee, policy.per_byte_fee);
            assert_eq!(
                receipt.schedule.per_instruction_fee,
                policy.per_instruction_fee
            );
            assert_eq!(receipt.schedule.per_gas_unit_fee, policy.per_gas_unit_fee);
            burned = burned.checked_add(&receipt.fee_amount).unwrap();
        }
        assert_eq!(
            payer.checked_add(&burned).unwrap(),
            initial_fee_funding,
            "actual certified fee receipts conserve the independent payer's genesis funding"
        );
        assert_eq!(
            supply.checked_add(&burned).unwrap(),
            initial_fee_funding,
            "actual certified fee receipts account for every burned supply unit"
        );
        burned
    };
    let after_deployments = settled_fees(&chain);
    assert!(after_deployments > Quantity::zero());
    let deployer_key = KeyPair::try_from_seed(vec![55; 32], Algorithm::Ed25519).unwrap();
    while chain.height() < 20 {
        let timestamp = (chain.height() + 1) * 1_000;
        let tick = crate::validation_fee::tests::sign_payout_fixture_work(
            &chain,
            &deployer_key,
            [Log::new(
                iroha_logger::Level::DEBUG,
                format!("paid historical reward fixture prefix {timestamp}"),
            )
            .into()],
            timestamp,
        );
        assert_eq!(chain.commit(vec![tick]), vec![true]);
    }
    let after_prefix = settled_fees(&chain);
    assert!(after_prefix > after_deployments);
    binding.validator_lane_id = lane;
    let state = chain.state();
    // The original world already owns the immutable evidence/slashing policy.
    // Advance component heights under that installed policy rather than trying
    // to replace it with shorter fixture windows during signed genesis.
    let parameters = state
        .view()
        .world
        .sumeragi_npos_parameters()
        .unwrap()
        .expect("signed genesis retains the original staking policy");
    parameters.validate().unwrap();
    let setup_height = chain.height().checked_add(1).unwrap();
    let identity = (lane, validator.clone());
    let selected = BTreeMap::from([(lane, BTreeSet::from([validator.clone()]))]);
    let period = earning_month(NOW).unwrap();

    // Signed genesis and contract deployments supply the real immutable root.
    // Later headers are committed component overlays, not certified lane service:
    // these execute genuine staking ISIs and reward claims under finite invocation
    // ownership. The production scheduled tests separately authenticate service,
    // conversion transfers, transaction envelopes and consensus publication.
    let mut setup = lifecycle_block(state, setup_height, NOW);
    let mut stx = setup.transaction_for_callback_testing();
    let registry = ValidationFeePolicyRegistryV1 {
        history: None,
        registered_policies: Vec::new(),
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![crate::validation_fee::tests::payout_registry_entry(
                &binding, 1, 20,
            )],
        },
    };
    crate::validation_fee::tests::install_policy_registry_fixture(&registry, &mut stx);
    let peer = register_peer_for_account(&mut stx, &validator);
    let replacement_peer = register_peer_for_account(&mut stx, &replacement);
    for staker in [&validator, &nominator, &late_nominator] {
        Mint::asset_quantity(
            Quantity::from(10_000_u32),
            AssetId::new(binding.xor_asset_id.clone(), staker.clone()),
        )
        .execute(&deployer, &mut stx)
        .unwrap();
    }
    RegisterPublicLaneValidator {
        monetary_plan: fixture_registration_plan(&stx, lane, &validator, Quantity::from(1_000_u32)),
        lane_id: lane,
        peer_id: peer.clone(),
        validator: validator.clone(),
        stake_account: validator.clone(),
        initial_stake: Quantity::from(1_000_u32),
        metadata: Metadata::default(),
    }
    .execute(&validator, &mut stx)
    .unwrap();
    BondPublicLaneStake {
        monetary_plan: fixture_bond_plan(
            &stx,
            lane,
            &validator,
            &nominator,
            Quantity::from(500_u32),
        ),
        lane_id: lane,
        validator: validator.clone(),
        staker: nominator.clone(),
        amount: Quantity::from(500_u32),
        metadata: Metadata::default(),
    }
    .execute(&nominator, &mut stx)
    .unwrap();
    let original_activation = stx
        .world
        .public_lane_validators
        .get(&identity)
        .unwrap()
        .activation_height;
    let epoch_length = parameters.epoch_length_blocks.get();
    assert_eq!(
        original_activation,
        (setup_height - 1)
            .checked_div(epoch_length)
            .unwrap()
            .checked_add(2)
            .unwrap()
            .checked_mul(epoch_length)
            .unwrap()
            .checked_add(1)
            .unwrap(),
        "registration targets the next unfrozen independent-lane election"
    );
    stx.apply();
    setup.commit_world_overlay_for_testing().unwrap();

    let earning_height = original_activation.checked_add(1).unwrap();
    let mut earning = lifecycle_block(state, earning_height, NOW + 1_000);
    let original = exposure::before_block(&earning, &selected).unwrap()[&identity].clone();
    assert_eq!(
        original,
        BTreeMap::from([
            (validator.clone(), Quantity::from(1_000_u32)),
            (nominator.clone(), Quantity::from(500_u32)),
        ])
    );
    let mut stx = earning.transaction_for_callback_testing();
    ActivatePublicLaneValidator {
        lane_id: lane,
        validator: validator.clone(),
    }
    .execute(&validator, &mut stx)
    .unwrap();
    exposure::record_service(&mut stx, &binding, period, &validator, original.clone()).unwrap();
    write(
        &mut stx,
        service_key(&binding, period).unwrap(),
        &ValidationFeeServiceSnapshot {
            earning_period_start_ms: period,
            service_blocks: BTreeMap::from([(validator.clone(), 1)]),
        },
    )
    .unwrap();
    let earned: ValidationFeeExposurePage = read(
        &stx,
        &exposure::page_key(&binding, period, &validator, 0).unwrap(),
    )
    .unwrap()
    .unwrap();
    stx.apply();
    earning.commit_world_overlay_for_testing().unwrap();

    let penalty_height = earning_height
        .checked_add(parameters.slashing_delay_blocks())
        .unwrap();
    assert!(
        penalty_height
            <= original_activation
                .checked_add(parameters.evidence_horizon_blocks())
                .unwrap()
                .checked_add(parameters.slashing_delay_blocks())
                .unwrap()
    );
    let mut penalty = lifecycle_block(state, penalty_height, NOW + 2_000);
    let mut stx = penalty.transaction_for_callback_testing();
    assert!(original_activation < stx.block_height());
    SlashPublicLaneValidator {
        monetary_plan: fixture_slash_plan(
            &stx,
            lane,
            &validator,
            original_activation,
            Quantity::from(400_u32),
        ),
        lane_id: lane,
        validator: validator.clone(),
        offence_height: original_activation,
        slash_id: Hash::new(b"old-offence-after-earned-service"),
        amount: Quantity::from(400_u32),
        reason_code: "delayed-evidence".to_owned(),
        metadata: Metadata::default(),
    }
    .execute(&deployer, &mut stx)
    .unwrap();
    assert_eq!(
        read::<ValidationFeeExposurePage>(
            &stx,
            &exposure::page_key(&binding, period, &validator, 0).unwrap()
        )
        .unwrap(),
        Some(earned.clone())
    );
    stx.apply();
    assert_eq!(
        exposure::before_block(&penalty, &selected).unwrap()[&identity],
        original,
        "applying an old offence cannot change already-earned parent exposure"
    );
    penalty.commit_world_overlay_for_testing().unwrap();

    let exit_height = penalty_height.checked_add(1).unwrap();
    let mut exit = lifecycle_block(state, exit_height, NOW + 3_000);
    assert_eq!(
        exposure::before_block(&exit, &selected).unwrap()[&identity],
        BTreeMap::from([
            (validator.clone(), Quantity::from(600_u32)),
            (nominator.clone(), Quantity::from(500_u32)),
        ]),
        "the delayed slash takes effect only after its committed application boundary"
    );
    let requests = [
        (validator.clone(), 600_u32, Hash::new(b"old-tenure-self")),
        (
            nominator.clone(),
            500_u32,
            Hash::new(b"old-tenure-nomination"),
        ),
    ];
    let mut stx = exit.transaction_for_callback_testing();
    for (staker, amount, request_id) in &requests {
        SchedulePublicLaneUnbond {
            lane_id: lane,
            validator: validator.clone(),
            staker: staker.clone(),
            request_id: *request_id,
            amount: Quantity::from(*amount),
            release_at_ms: NOW + 3_001,
        }
        .execute(staker, &mut stx)
        .unwrap();
    }
    ExitPublicLaneValidator {
        lane_id: lane,
        validator: validator.clone(),
        release_at_ms: NOW + 3_000,
    }
    .execute(&validator, &mut stx)
    .unwrap();
    assert!(matches!(
        stx.world
            .public_lane_validators
            .get(&identity)
            .unwrap()
            .status,
        PublicLaneValidatorStatus::Exiting(_)
    ));
    let deactivation_height = stx
        .world
        .public_lane_validators
        .get(&identity)
        .unwrap()
        .deactivation_height
        .expect("independent-lane exit fixes its retained tenure end");
    let withdrawal_height = requests
        .iter()
        .map(|(staker, _, request_id)| {
            let pending = &stx
                .world
                .public_lane_stake_shares
                .get(&(lane, validator.clone(), staker.clone()))
                .unwrap()
                .pending_unbonds[request_id];
            assert_eq!(
                pending.liability_release_height,
                pending
                    .slashable_through_height
                    .checked_add(parameters.evidence_horizon_blocks())
                    .unwrap()
                    .checked_add(parameters.slashing_delay_blocks())
                    .unwrap(),
                "real unbond scheduling preserves the installed liability windows"
            );
            pending.liability_release_height
        })
        .chain([deactivation_height])
        .max()
        .unwrap()
        .checked_add(1)
        .unwrap();
    stx.apply();
    exit.commit_world_overlay_for_testing().unwrap();

    let mut replacement_block = lifecycle_block(state, withdrawal_height, NOW + 4_000);
    assert!(
        !exposure::before_block(&replacement_block, &selected)
            .unwrap()
            .contains_key(&identity),
        "pending unbonds have no eligible reward exposure"
    );
    let mut stx = replacement_block.transaction_for_callback_testing();
    for (staker, _, request_id) in &requests {
        FinalizePublicLaneUnbond {
            monetary_plan: fixture_unbond_plan(&stx, lane, &validator, staker, request_id),
            lane_id: lane,
            validator: validator.clone(),
            staker: staker.clone(),
            request_id: *request_id,
        }
        .execute(staker, &mut stx)
        .unwrap();
    }
    assert!(
        stx.world.public_lane_validators.get(&identity).is_none(),
        "all retained custody is released before the new tenure"
    );
    assert!(
        stx.world
            .public_lane_stake_shares
            .get(&(lane, validator.clone(), nominator.clone()))
            .is_none()
    );
    RegisterPublicLaneValidator {
        monetary_plan: fixture_registration_plan(&stx, lane, &validator, Quantity::from(1_000_u32)),
        lane_id: lane,
        peer_id: peer.clone(),
        validator: validator.clone(),
        stake_account: validator.clone(),
        initial_stake: Quantity::from(1_000_u32),
        metadata: Metadata::default(),
    }
    .execute(&validator, &mut stx)
    .unwrap();
    BondPublicLaneStake {
        monetary_plan: fixture_bond_plan(
            &stx,
            lane,
            &validator,
            &late_nominator,
            Quantity::from(1_000_u32),
        ),
        lane_id: lane,
        validator: validator.clone(),
        staker: late_nominator.clone(),
        amount: Quantity::from(1_000_u32),
        metadata: Metadata::default(),
    }
    .execute(&late_nominator, &mut stx)
    .unwrap();
    let replacement_key = KeyPair::try_from_seed(vec![5; 32], Algorithm::Ed25519).unwrap();
    rebind_for_test(&stx, lane, &validator, &replacement_peer, &replacement_key)
        .execute(&validator, &mut stx)
        .unwrap();
    let new_tenure = stx.world.public_lane_validators.get(&identity).unwrap();
    let replacement_activation = new_tenure.activation_height;
    assert!(replacement_activation > withdrawal_height);
    assert!(replacement_activation > deactivation_height);
    assert_eq!(new_tenure.peer_id, replacement_peer);
    assert_ne!(new_tenure.peer_id, peer);
    assert_eq!(
        read::<ValidationFeeExposurePage>(
            &stx,
            &exposure::page_key(&binding, period, &validator, 0).unwrap()
        )
        .unwrap(),
        Some(earned)
    );
    stx.apply();
    replacement_block
        .commit_world_overlay_for_testing()
        .unwrap();

    let mut funding = lifecycle_block(
        state,
        replacement_activation.checked_add(1).unwrap(),
        NOW + 60 * DAY_MS,
    );
    let mut stx = funding.transaction_for_callback_testing();
    let custody_asset = AssetId::new(binding.xor_asset_id.clone(), escrow);
    let sink_asset = AssetId::new(binding.xor_asset_id.clone(), slash_sink);
    let custody_before = stx
        .world
        .assets
        .get(&custody_asset)
        .unwrap()
        .as_ref()
        .clone();
    let sink_before = stx.world.assets.get(&sink_asset).unwrap().as_ref().clone();
    assert_eq!(custody_before, Quantity::from(2_000_u32));
    assert_eq!(sink_before, Quantity::from(400_u32));
    // This component supplies exactly the XOR receipt of the independently
    // authenticated conversion suite; reserve/accrual/claims all run unchanged.
    let offer = fund_test_conversion(&mut stx, &binding, period, 150 * XOR);
    assert!(reserve_conversion(&mut stx, &binding, &offer, 150 * XOR).is_err());
    assert!(settlement::accrue_next_page(&mut stx, &binding).unwrap());
    assert!(!settlement::accrue_next_page(&mut stx, &binding).unwrap());
    for (claimant, amount) in [(&validator, 100 * XOR), (&nominator, 50 * XOR)] {
        let asset = AssetId::new(binding.xor_asset_id.clone(), claimant.clone());
        let before = minor_units(stx.world.assets.get(&asset).unwrap().as_ref(), 9).unwrap();
        assert_eq!(
            read::<u128>(&stx, &claimable_key(&binding, claimant).unwrap()).unwrap(),
            Some(amount)
        );
        signed_claim_all(&mut stx, &binding, claimant);
        assert_eq!(
            minor_units(stx.world.assets.get(&asset).unwrap().as_ref(), 9).unwrap(),
            before + amount
        );
        assert!(
            fee_reward_claim_plan(&stx.world, stx.block_height(), claimant, lane)
                .unwrap()
                .is_none()
        );
    }
    assert!(
        fee_reward_claim_plan(&stx.world, stx.block_height(), &late_nominator, lane)
            .unwrap()
            .is_none(),
        "the new-tenure nomination cannot capture earlier earnings"
    );
    assert_eq!(
        stx.world.assets.get(&custody_asset).unwrap().as_ref(),
        &custody_before
    );
    assert_eq!(
        stx.world.assets.get(&sink_asset).unwrap().as_ref(),
        &sink_before
    );
    let rewards = read_state(&stx, &binding).unwrap();
    assert_eq!(
        (
            rewards.reserved_xor,
            rewards.next_allocation,
            rewards.next_claim
        ),
        (0, 1, 2)
    );
    reconciliation::validate(&stx.world, &binding).unwrap();
    stx.apply();
    funding.commit_world_overlay_for_testing().unwrap();
}
