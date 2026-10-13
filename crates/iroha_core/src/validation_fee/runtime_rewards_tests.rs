//! Native service capture, scheduled funded conversion, certified replay, and signed withdrawals.

#[cfg(unix)]
#[path = "runtime_reward_crash_tests.rs"]
mod crash_tests;

use super::*;
use crate::{smartcontracts::Execute as _, sumeragi::test_chain::CertifiedTestChain};
use iroha_data_model::{
    isi::{Mint, staking::ClaimPublicLaneRewards},
    nexus::{
        PublicLaneMonetaryScopeV1, PublicLaneRewardClaimPlanV1, PublicLaneStakeShare,
        PublicLaneValidatorRecord, PublicLaneValidatorStatus,
    },
    oracle::{
        FeedConfigVersion, Observation, ObservationBody, ObservationOutcome, ObservationValue,
    },
    validation_fee_rewards::{
        ValidationFeeExposurePage, ValidationFeeReferenceObservation,
        ValidationFeeRewardAllocation, ValidationFeeRewardExposure, ValidationFeeRewardsState,
        ValidationFeeServiceSnapshot, validation_fee_exposure_page_key,
        validation_fee_reward_state_key,
    },
};
use iroha_model_base::topology::LaneId;
use std::collections::BTreeMap;

// Original block admission rejects future timestamps. These deterministic
// historical instants straddle the Honiara earning-month boundary.
const CONVERSION_TIME: u64 = 1_735_689_600_000;
const EARNING_TIME: u64 = CONVERSION_TIME - 2 * 86_400_000;

struct ScheduledRewardFixture {
    chain: CertifiedTestChain,
    binding: ValidationFeeTreasuryPayoutBindingV1,
    pool: WrapperFixture,
    validator: AccountId,
    period: u64,
    production_pool: bool,
    two_validators: bool,
    prefix_hash: Hash,
}

fn install_reference_observations(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    production_pool: bool,
    now: u64,
) {
    for seed in 10..13 {
        let body = ObservationBody {
            feed_id: binding.reference_feed_id.clone(),
            feed_config_version: FeedConfigVersion(1),
            slot: 1,
            provider_id: account(seed),
            connector_id: "signed_xor_per_sbd".into(),
            connector_version: 1,
            request_hash: Hash::new(b"production reward conversion reference"),
            outcome: ObservationOutcome::Value(ObservationValue::new(
                if production_pool { 1 } else { 2 },
                0,
            )),
            timestamp_ms: Some(now),
        };
        let observation = ValidationFeeReferenceObservation {
            observation: Observation {
                signature: iroha_crypto::SignatureOf::try_new(key_pair(seed).private_key(), &body)
                    .unwrap(),
                body,
            },
            admitted_height: stx.block_height() - 1,
            admitted_at_ms: now,
        };
        let key = validation_fee_reward_state_key(
            binding,
            &format!(
                "Oracle/{}",
                hex::encode(Hash::new(account(seed).to_string().as_bytes()).as_ref())
            ),
        )
        .unwrap();
        stx.world
            .smart_contract_state
            .insert(key, norito::to_bytes(&observation).unwrap());
    }
}

#[inline(never)]
fn prepare_scheduled_reward_fixture(
    production_pool: bool,
    two_validators: bool,
) -> ScheduledRewardFixture {
    let deployer = account(55);
    let config = crate::sumeragi::test_chain::TestChainConfig::new(
        validation_fee_payout_world(&deployer),
        EARNING_TIME - 30_000,
    );
    let (mut chain, _, _, _) =
        signed_original_fixtures::signed_fee_registry_root_fixture_with_config(config);
    while chain.height() < 19 {
        chain.commit_at(EARNING_TIME - 30_000 + chain.height() * 1_000, Vec::new());
    }
    let state = std::sync::Arc::clone(chain.state());
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(20).unwrap(),
        state.view().latest_block_hash(),
        None,
        EARNING_TIME,
        0,
    );
    let mut setup_block = state.block(header);
    let pool = install_wrapper_fixture(&mut setup_block, &deployer, production_pool);
    let mut binding = treasury_payout_binding(pool.wrapper.clone(), &pool.wrapper_code);
    binding.pool_contract_address = pool.pool.clone();
    binding.pool_vault_account_id = pool.pool.subject_id();
    binding.pool_code_hash = pool.pool_hash.into();
    binding.reward_pool_account_id = pool.reward_pool.clone();
    let period = crate::validation_fee_rewards::earning_month(EARNING_TIME).unwrap();
    let validator = account(2);
    let mut positions = vec![(
        validator.clone(),
        BTreeMap::from([
            (validator.clone(), Quantity::from(20_u32)),
            (account(3), Quantity::from(30_u32)),
            (account(4), Quantity::from(50_u32)),
        ]),
    )];
    if two_validators {
        positions.push((
            account(5),
            BTreeMap::from([(account(5), Quantity::from(100_u32))]),
        ));
    }
    {
        let mut setup = setup_block.transaction_for_callback_testing();
        // Governance, original collected credit and funded staking positions are
        // explicit component prestate. Service, exposure, funded allocations,
        // entitlements and claims below are produced only by native execution.
        let registry = iroha_data_model::validation_fee::ValidationFeePolicyRegistryV1 {
            registered_policies: Vec::new(),
            payout_policies:
                iroha_data_model::validation_fee::ValidationFeePayoutPolicyRegistryV1 {
                    entries: vec![payout_registry_entry(&binding, 1, 19)],
                },
        };
        install_policy_registry_fixture(&registry, &mut setup);
        let mut feed = iroha_data_model::oracle::kits::price_xor_usd().feed_config;
        feed.feed_id = binding.reference_feed_id.clone();
        feed.feed_config_version = FeedConfigVersion(1);
        feed.providers = binding.reference_provider_accounts.clone();
        feed.min_signers = 3;
        feed.committee_size = 5;
        setup.world.oracle_feeds.insert(feed.feed_id.clone(), feed);
        install_reference_observations(&mut setup, &binding, production_pool, EARNING_TIME);
        let key = |leaf: &str| validation_fee_reward_state_key(&binding, leaf).unwrap();
        setup.world.smart_contract_state.insert(
            key("State"),
            norito::to_bytes(&ValidationFeeRewardsState {
                pending_sbd_total: 1_000,
                ..Default::default()
            })
            .unwrap(),
        );
        setup.world.smart_contract_state.insert(
            key(&format!("Pending/{period:020}")),
            norito::to_bytes(&1_000_u64).unwrap(),
        );
        // Each actual service-earning validator retains funded principal in its
        // own canonical stake account, separate from the governed reward pool.
        for (peer_index, (validator, stakes)) in positions.iter().enumerate() {
            let custody = AssetId::new(binding.xor_asset_id.clone(), validator.clone());
            Mint::asset_quantity(Quantity::from(100_u32), custody.clone())
                .execute(&deployer, &mut setup)
                .unwrap();
            crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
                &setup.world,
                LaneId::SINGLE,
                validator,
                &custody,
                &Quantity::from(100_u32),
                &Quantity::from(100_u32),
            )
            .unwrap()
            .apply(&mut setup.world);
            setup.world.public_lane_validators.insert(
                (LaneId::SINGLE, validator.clone()),
                PublicLaneValidatorRecord {
                    lane_id: LaneId::SINGLE,
                    validator: validator.clone(),
                    peer_id: chain.validators()[peer_index].0.clone(),
                    stake_account: validator.clone(),
                    total_stake: Quantity::from(100_u32),
                    self_stake: stakes[validator].clone(),
                    metadata: Default::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
            for (staker, bonded) in stakes {
                setup.world.public_lane_stake_shares.insert(
                    (LaneId::SINGLE, validator.clone(), staker.clone()),
                    PublicLaneStakeShare {
                        lane_id: LaneId::SINGLE,
                        validator: validator.clone(),
                        staker: staker.clone(),
                        bonded: bonded.clone(),
                        pending_unbonds: BTreeMap::new(),
                        metadata: Default::default(),
                    },
                );
            }
        }
        crate::state::validate_public_lane_stake_reserves(&setup.world)
            .expect("canonical funded component staking custody");
        // Activation already installs this original pre-commit time trigger;
        // the enacted lifecycle pins it and rejects extra scheduled callbacks.
        assert_eq!(
            setup
                .world
                .triggers
                .time_triggers()
                .iter()
                .filter(
                    |(id, _)| crate::validation_fee::is_enacted_validation_fee_payout_trigger(
                        &setup, id
                    )
                )
                .count(),
            1
        );
        setup.apply();
    }
    setup_block.commit_world_overlay_for_testing().unwrap();
    chain.commit_at(EARNING_TIME + 2, Vec::new());
    chain.commit_at(EARNING_TIME + 1_002, Vec::new());
    {
        let view = state.view();
        let key =
            validation_fee_reward_state_key(&binding, &format!("Service/{period:020}")).unwrap();
        let captured: ValidationFeeServiceSnapshot =
            norito::decode_from_bytes(view.world.smart_contract_state.get(&key).unwrap()).unwrap();
        assert_eq!(
            captured.service_blocks,
            positions
                .iter()
                .map(|(validator, _)| (validator.clone(), 1))
                .collect()
        );
        for (validator, stakes) in &positions {
            let page_key =
                validation_fee_exposure_page_key(&binding, period, validator, 0).unwrap();
            let page: ValidationFeeExposurePage =
                norito::decode_from_bytes(view.world.smart_contract_state.get(&page_key).unwrap())
                    .unwrap();
            assert_eq!(
                page.exposure,
                vec![ValidationFeeRewardExposure {
                    service_blocks: 1,
                    stakes: stakes.clone(),
                }]
            );
        }
    }
    // Reference admission is component prestate at the next month; its original
    // signed observations are retained identically on both replay instances.
    chain.setup_world_at(CONVERSION_TIME, |stx| {
        install_reference_observations(stx, &binding, production_pool, CONVERSION_TIME);
    });
    let prefix_hash = crate::snapshot::canonical_state_snapshot_hash(chain.state()).unwrap();
    ScheduledRewardFixture {
        chain,
        binding,
        pool,
        validator,
        period,
        production_pool,
        two_validators,
        prefix_hash,
    }
}

fn replay_scheduled_reward_fixture(source: &ScheduledRewardFixture) -> ScheduledRewardFixture {
    let mut restored =
        prepare_scheduled_reward_fixture(source.production_pool, source.two_validators);
    assert!(!std::sync::Arc::ptr_eq(
        restored.chain.state(),
        source.chain.state()
    ));
    assert!(!std::sync::Arc::ptr_eq(
        restored.chain.kura(),
        source.chain.kura()
    ));
    assert_eq!(
        restored.prefix_hash, source.prefix_hash,
        "independent original component prestate"
    );
    restored
        .chain
        .replay_from(&source.chain)
        .expect("startup replays the original certified conversion and claims");
    let original = crate::snapshot::canonical_state_snapshot_hash(source.chain.state()).unwrap();
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(restored.chain.state()).unwrap(),
        original
    );
    restored
        .chain
        .replay_from(&source.chain)
        .expect("replaying the same original suffix is idempotent");
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(restored.chain.state()).unwrap(),
        original
    );
    restored
}

#[test]
fn scheduled_production_conversion_automatically_funds_nominator_signed_claims() {
    scheduled_conversion_automatically_funds_nominator_signed_claims(true, false);
}

#[test]
fn scheduled_funded_pool_conversion_automatically_funds_nominator_signed_claims() {
    scheduled_conversion_automatically_funds_nominator_signed_claims(false, false);
}

#[test]
fn scheduled_conversion_final_custody_transfer_failure_rolls_back_and_retries() {
    use iroha_data_model::{
        ValidationFail,
        asset::transfer_control::{
            ASSET_TRANSFER_CONTROL_METADATA_KEY, AssetTransferControlRecord,
            AssetTransferControlStoreV1,
        },
        block::execution_output::ExecutionOutputV1,
        events::{EventBox, trigger_completed::TriggerCompletedOutcome},
        isi::error::{AssetTransferAdmissionError, InstructionExecutionError},
        transaction::error::TransactionRejectionReason,
        validation_fee_rewards::ValidationFeeConversionAttempt,
    };

    let mut fixture = prepare_scheduled_reward_fixture(false, false);
    let failed_at = CONVERSION_TIME + 2;
    let custody = fixture.binding.treasury_account_id.clone();
    let xor = fixture.binding.xor_asset_id.clone();
    assert_ne!(custody, fixture.binding.pool_vault_account_id);
    let mut original_controls = None;
    fixture.chain.setup_world_at(failed_at, |stx| {
        // Only the third leg debits wrapper XOR: the first debits SBD and
        // the second debits pool XOR. Keep both earlier transfer controls intact.
        let mut control = AssetTransferControlRecord::new(xor.clone());
        control.blacklisted = true;
        let mut controls = AssetTransferControlStoreV1::default();
        controls.upsert(control);
        original_controls = stx
            .world
            .accounts
            .get_mut(&custody)
            .unwrap()
            .metadata_mut()
            .insert(
                ASSET_TRANSFER_CONTROL_METADATA_KEY.parse().unwrap(),
                iroha_primitives::json::Json::new(controls),
            );
    });
    assert!(
        original_controls.is_none(),
        "the fixture has no controls to overwrite"
    );
    let observe_monetary = |fixture: &ScheduledRewardFixture| {
        let view = fixture.chain.state().view();
        let key = |leaf: &str| validation_fee_reward_state_key(&fixture.binding, leaf).unwrap();
        let state: ValidationFeeRewardsState =
            norito::decode_from_bytes(view.world.smart_contract_state.get(&key("State")).unwrap())
                .unwrap();
        // Finalized service and attempt evidence progress independently of a
        // failed callback. Every funded monetary field must remain unchanged.
        let monetary_state = (
            state.pending_sbd_total,
            state.reserved_xor,
            state.next_allocation,
            state.next_claim,
            state.conversion_day,
            state.converted_today_sbd,
            state.last_conversion_ms,
        );
        let pending = view
            .world
            .smart_contract_state
            .get(&key(&format!("Pending/{:020}", fixture.period)))
            .cloned();
        let families = [
            "Allocation/",
            "AllocationCursor",
            "Entitlement/",
            "Claim/",
            "Claimable/",
            "HistoryBalance/",
        ]
        .map(key);
        let receipts = view
            .world
            .smart_contract_state
            .iter()
            .filter(|(key, _)| {
                families
                    .iter()
                    .any(|prefix| key.as_ref().starts_with(prefix.as_ref()))
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        let assets = view
            .world
            .assets
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        (monetary_state, pending, receipts, assets)
    };
    let before = observe_monetary(&fixture);
    assert_eq!(
        (before.0.0, before.0.1, before.0.2, before.0.3),
        (1_000, 0, 0, 0)
    );
    assert!(before.2.is_empty());
    fixture.chain.take_events().unwrap();
    fixture.chain.commit_at(failed_at, Vec::new());
    let callbacks = fixture
        .chain
        .take_events()
        .unwrap()
        .into_iter()
        .filter_map(|event| {
            if let EventBox::TriggerCompleted(event) = event {
                Some(event)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(callbacks.len(), 1, "one scheduled conversion actually ran");
    let TriggerCompletedOutcome::Failure(_) = callbacks[0].outcome() else {
        panic!("final funded-custody transfer must reject: {callbacks:?}");
    };
    {
        // The completion's Display diagnostic is intentionally brief. The
        // original certified output retains the exact typed execution refusal.
        let committed = fixture.chain.committed(fixture.chain.height());
        let scheduled = committed
            .block()
            .execution_outputs()
            .iter()
            .filter_map(|output| match output {
                ExecutionOutputV1::Time(row)
                    if &row.invocation.trigger.trigger_id == callbacks[0].trigger_id() =>
                {
                    Some(row)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(scheduled.len(), 1, "one original scheduled output");
        let row = scheduled[0];
        assert_eq!(row.completions.len(), 1);
        assert_eq!(row.completions[0].outcome, *callbacks[0].outcome());
        let TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::Blacklisted(message),
            ),
        )) = row.result.as_ref().unwrap_err()
        else {
            panic!("expected final XOR custody-transfer refusal: {row:#?}");
        };
        assert_eq!(
            message.to_string(),
            format!("account {custody} on asset definition {xor}"),
            "only the final transfer debits this wrapper's XOR"
        );
    }
    assert_eq!(
        observe_monetary(&fixture),
        before,
        "failed final transfer rolls back both earlier legs, pending credit and every funded receipt"
    );
    let failed_attempt = {
        let view = fixture.chain.state().view();
        let key = |leaf| validation_fee_reward_state_key(&fixture.binding, leaf).unwrap();
        let state: ValidationFeeRewardsState =
            norito::decode_from_bytes(view.world.smart_contract_state.get(&key("State")).unwrap())
                .unwrap();
        assert_eq!(state.last_attempt_height, fixture.chain.height());
        assert_eq!(state.last_attempt_ms, Some(failed_at));
        let attempt: ValidationFeeConversionAttempt = norito::decode_from_bytes(
            view.world
                .smart_contract_state
                .get(&key(&format!("Attempt/{}", fixture.chain.height())))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(attempt.attempted_at_ms, failed_at);
        assert_eq!(attempt.earning_period_start_ms, fixture.period);
        assert_eq!(attempt.sbd_minor, 1_000);
        assert_eq!(attempt.min_xor_minor, 19_800_000_000);
        attempt
    };
    let retry_at = failed_at + fixture.binding.min_interval_ms;
    fixture.chain.setup_world_at(failed_at + 1, |stx| {
        let metadata = stx.world.accounts.get_mut(&custody).unwrap().metadata_mut();
        if let Some(controls) = original_controls {
            metadata.insert(
                ASSET_TRANSFER_CONTROL_METADATA_KEY.parse().unwrap(),
                controls,
            );
        } else {
            metadata.remove(ASSET_TRANSFER_CONTROL_METADATA_KEY);
        }
    });
    fixture.chain.commit_at(retry_at - 1, Vec::new());
    assert_eq!(
        observe_monetary(&fixture),
        before,
        "removing the control cannot bypass the committed attempt interval"
    );
    fixture.chain.take_events().unwrap();
    fixture.chain.commit_at(retry_at, Vec::new());
    let callbacks = fixture
        .chain
        .take_events()
        .unwrap()
        .into_iter()
        .filter_map(|event| {
            if let EventBox::TriggerCompleted(event) = event {
                Some(event)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(callbacks.len(), 1);
    assert!(
        matches!(callbacks[0].outcome(), TriggerCompletedOutcome::Success),
        "{callbacks:?}"
    );
    {
        let view = fixture.chain.state().view();
        let key = |leaf| validation_fee_reward_state_key(&fixture.binding, leaf).unwrap();
        let receipt: ValidationFeeRewardAllocation = norito::decode_from_bytes(
            view.world
                .smart_contract_state
                .get(&key("Allocation/0"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.sequence, 0);
        assert_eq!(
            receipt.earning_period_start_ms,
            failed_attempt.earning_period_start_ms
        );
        assert_eq!(receipt.sbd_minor, failed_attempt.sbd_minor);
        assert_eq!(receipt.min_xor_minor, failed_attempt.min_xor_minor);
        assert_eq!(
            receipt.reference_observations,
            failed_attempt.reference_observations
        );
        assert_eq!(receipt.xor_minor, 20_000_000_000);
        assert_eq!(receipt.converted_at_ms, retry_at);
        assert!(
            view.world
                .smart_contract_state
                .get(&key("AllocationCursor"))
                .is_some()
        );
        assert!(
            view.world
                .smart_contract_state
                .get(&key(&format!("Pending/{:020}", fixture.period)))
                .is_none()
        );
        assert_eq!(
            view.world
                .assets
                .get(&AssetId::new(xor.clone(), fixture.pool.reward_pool.clone()))
                .unwrap()
                .as_ref(),
            &Quantity::from(20_u32)
        );
        assert!(view.world.assets.get(&fixture.pool.treasury_sbd).is_none());
        assert!(
            view.world
                .assets
                .get(&AssetId::new(xor.clone(), custody))
                .is_none()
        );
    }
    // The next original block automatically materializes the retry's funded page.
    fixture.chain.commit_at(retry_at + 1_000, Vec::new());
    for (index, (seed, expected)) in [(2, 4_u32), (3, 6_u32), (4, 10_u32)]
        .into_iter()
        .enumerate()
    {
        let claimant = account(seed);
        let fee_claim = crate::validation_fee_rewards::fee_reward_claim_plan(
            &fixture.chain.state().view().world,
            fixture.chain.height() + 1,
            &claimant,
            LaneId::SINGLE,
        )
        .unwrap()
        .expect("successful retry automatically accrues every eligible share");
        assert_eq!(fee_claim.amount, Quantity::from(expected));
        let claim = ClaimPublicLaneRewards {
            lane_id: LaneId::SINGLE,
            account: claimant.clone(),
            claim_plan: PublicLaneRewardClaimPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Network(fixture.chain.network_id()),
                valid_until_height: fixture.chain.height() + 1,
                fee_claim,
            },
        };
        let now = retry_at + (u64::try_from(index).unwrap() + 2) * 1_000;
        let signed = fixture.chain.sign(&key_pair(seed), [claim.into()], now);
        assert_eq!(fixture.chain.commit_at(now, vec![signed]), vec![true]);
        let view = fixture.chain.state().view();
        let principal = if seed == 2 { 100 } else { 0 };
        assert_eq!(
            view.world
                .assets
                .get(&AssetId::new(xor.clone(), claimant))
                .unwrap()
                .as_ref(),
            &Quantity::from(principal + expected)
        );
    }
    let view = fixture.chain.state().view();
    let state_key = validation_fee_reward_state_key(&fixture.binding, "State").unwrap();
    let state: ValidationFeeRewardsState =
        norito::decode_from_bytes(view.world.smart_contract_state.get(&state_key).unwrap())
            .unwrap();
    assert_eq!(
        (
            state.pending_sbd_total,
            state.reserved_xor,
            state.next_allocation,
            state.next_claim
        ),
        (0, 0, 1, 3)
    );
    assert!(
        view.world
            .assets
            .get(&AssetId::new(xor.clone(), fixture.pool.reward_pool.clone()))
            .is_none()
    );
    assert_eq!(
        view.world
            .public_lane_stake_reserves
            .get(&AssetId::new(xor, fixture.validator.clone())),
        Some(&Quantity::from(100_u32))
    );
    crate::state::validate_public_lane_stake_reserves_for_restore(&view.world).expect(
        "failed conversion and exact retry preserve funded principal and reward conservation",
    );
}

#[test]
fn signed_nominator_claim_batch_rolls_back_and_stale_parallel_quotes_cannot_pay() {
    let mut fixture = prepare_scheduled_reward_fixture(false, false);
    fixture.chain.commit_at(CONVERSION_TIME + 2, Vec::new());
    fixture.chain.commit_at(CONVERSION_TIME + 1_002, Vec::new());
    let observe = |fixture: &ScheduledRewardFixture| {
        let view = fixture.chain.state().view();
        let key = validation_fee_reward_state_key(&fixture.binding, "State").unwrap();
        let state: ValidationFeeRewardsState =
            norito::decode_from_bytes(view.world.smart_contract_state.get(&key).unwrap()).unwrap();
        let balances = [fixture.pool.reward_pool.clone(), account(3), account(4)].map(|owner| {
            view.world
                .assets
                .get(&AssetId::new(fixture.pool.xor.clone(), owner))
                .map_or_else(Quantity::zero, |balance| balance.as_ref().clone())
        });
        let plans = [3, 4].map(|seed| {
            crate::validation_fee_rewards::fee_reward_claim_plan(
                &view.world,
                fixture.chain.height() + 1,
                &account(seed),
                LaneId::SINGLE,
            )
            .unwrap()
        });
        (state.reserved_xor, state.next_claim, balances, plans)
    };
    let before = observe(&fixture);
    assert_eq!(before.0, 20_000_000_000);
    assert_eq!(before.1, 0);
    let first_plan = before.3[0].clone().unwrap();
    let parallel_plan = before.3[1].clone().unwrap();
    assert_eq!(first_plan.amount, Quantity::from(6_u32));
    assert_eq!(parallel_plan.amount, Quantity::from(10_u32));
    assert_eq!(first_plan.expected_claim_sequence, 0);
    assert_eq!(
        first_plan.expected_claim_sequence,
        parallel_plan.expected_claim_sequence
    );
    let deadline = fixture.chain.height() + 32;
    let claim = |seed, fee_claim| ClaimPublicLaneRewards {
        lane_id: LaneId::SINGLE,
        account: account(seed),
        claim_plan: PublicLaneRewardClaimPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(fixture.chain.network_id()),
            valid_until_height: deadline,
            fee_claim,
        },
    };
    let first = claim(3, first_plan.clone());
    let parallel = claim(4, parallel_plan);
    let mut changed = first.clone();
    changed.claim_plan.fee_claim.amount = Quantity::from(7_u32);
    let timestamp = CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000;
    let signed = fixture
        .chain
        .sign(&key_pair(3), [changed.into()], timestamp);
    assert_eq!(
        fixture.chain.commit_at(timestamp, vec![signed]),
        vec![false]
    );
    assert_eq!(
        observe(&fixture),
        before,
        "a signed overclaim changes no funded right"
    );
    let output = format!(
        "{:?}",
        fixture
            .chain
            .committed(fixture.chain.height())
            .block()
            .network_output_at(0)
    );
    assert!(
        output.contains("exact current signed monetary plan"),
        "{output}"
    );

    // The first instruction consumes the credit in its private transaction. The
    // second reaches the actual claim path and fails because that credit is gone.
    // The committed rejection must restore the first transfer and its receipt.
    let timestamp = CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000;
    let signed = fixture.chain.sign(
        &key_pair(3),
        [first.clone().into(), first.clone().into()],
        timestamp,
    );
    assert_eq!(
        fixture.chain.commit_at(timestamp, vec![signed]),
        vec![false]
    );
    let output = format!(
        "{:?}",
        fixture
            .chain
            .committed(fixture.chain.height())
            .block()
            .network_output_at(0)
    );
    assert!(
        output.contains("no eligible reserved credit"),
        "second claim must execute after the first: {output}"
    );
    assert_eq!(
        observe(&fixture),
        before,
        "later instruction failure rolls back custody, receipt sequence and both entitlements"
    );
    fixture = replay_scheduled_reward_fixture(&fixture);
    assert_eq!(
        observe(&fixture),
        before,
        "certified rejection replay cannot publish the discarded first payment"
    );

    let timestamp = CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000;
    let signed = fixture
        .chain
        .sign(&key_pair(3), [first.clone().into()], timestamp);
    assert_eq!(fixture.chain.commit_at(timestamp, vec![signed]), vec![true]);
    let paid = observe(&fixture);
    assert_eq!(paid.0, 14_000_000_000);
    assert_eq!(paid.1, 1);
    assert_eq!(
        paid.2,
        [
            Quantity::from(14_u32),
            Quantity::from(6_u32),
            Quantity::zero()
        ]
    );
    assert!(paid.3[0].is_none());
    assert_eq!(paid.3[1].as_ref().unwrap().expected_claim_sequence, 1);

    // Two independently signed nominator quotes share the global sequence. A
    // successful first claim invalidates the other quote without losing its credit.
    let timestamp = CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000;
    let signed = fixture
        .chain
        .sign(&key_pair(4), [parallel.into()], timestamp);
    assert_eq!(
        fixture.chain.commit_at(timestamp, vec![signed]),
        vec![false]
    );
    assert_eq!(observe(&fixture), paid);
    let output = format!(
        "{:?}",
        fixture
            .chain
            .committed(fixture.chain.height())
            .block()
            .network_output_at(0)
    );
    assert!(
        output.contains("exact current signed monetary plan"),
        "{output}"
    );
    let timestamp = CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000;
    let signed = fixture.chain.sign(&key_pair(3), [first.into()], timestamp);
    assert_eq!(
        fixture.chain.commit_at(timestamp, vec![signed]),
        vec![false]
    );
    assert_eq!(
        observe(&fixture),
        paid,
        "a newly signed replay cannot pay twice"
    );
    let refreshed = ClaimPublicLaneRewards {
        lane_id: LaneId::SINGLE,
        account: account(4),
        claim_plan: PublicLaneRewardClaimPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(fixture.chain.network_id()),
            valid_until_height: deadline,
            fee_claim: paid.3[1].clone().unwrap(),
        },
    };
    let timestamp = CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000;
    let signed = fixture
        .chain
        .sign(&key_pair(4), [refreshed.into()], timestamp);
    assert_eq!(fixture.chain.commit_at(timestamp, vec![signed]), vec![true]);
    let after = observe(&fixture);
    assert_eq!(
        after.0, 4_000_000_000,
        "only the validator's entitlement remains reserved"
    );
    assert_eq!(after.1, 2);
    assert_eq!(
        after.2,
        [
            Quantity::from(4_u32),
            Quantity::from(6_u32),
            Quantity::from(10_u32)
        ]
    );
    assert!(after.3.iter().all(Option::is_none));
    fixture = replay_scheduled_reward_fixture(&fixture);
    assert_eq!(observe(&fixture), after);
    crate::state::validate_public_lane_stake_reserves_for_restore(
        &fixture.chain.state().view().world,
    )
    .expect("signed retries and full certified replay preserve principal plus unpaid rewards");
}

/// Execute real scheduled funding for two validators, replay unfinished accrual,
/// then withdraw both validators' and both nominators' exact signed entitlements.
pub(crate) fn scheduled_two_validator_reward_replay() {
    scheduled_conversion_automatically_funds_nominator_signed_claims(false, true);
}

#[inline(never)]
fn scheduled_conversion_automatically_funds_nominator_signed_claims(
    production_pool: bool,
    two_validators: bool,
) {
    let mut fixture = prepare_scheduled_reward_fixture(production_pool, two_validators);
    let mut validators = vec![fixture.validator.clone()];
    if two_validators {
        validators.push(account(5));
    }
    validators.sort();
    fixture.chain.take_events().unwrap();
    fixture.chain.commit_at(CONVERSION_TIME + 2, Vec::new());
    let callback_events: Vec<_> = fixture
        .chain
        .take_events()
        .unwrap()
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                iroha_data_model::events::EventBox::TriggerCompleted(_)
            )
        })
        .collect();
    let expected_xor_minor = if production_pool {
        9_960_039_960
    } else {
        20_000_000_000
    };
    {
        let view = fixture.chain.state().view();
        let key = validation_fee_reward_state_key(&fixture.binding, "Allocation/0").unwrap();
        if view.world.smart_contract_state.get(&key).is_none() {
            let state_key = validation_fee_reward_state_key(&fixture.binding, "State").unwrap();
            let reward_state: ValidationFeeRewardsState =
                norito::decode_from_bytes(view.world.smart_contract_state.get(&state_key).unwrap())
                    .unwrap();
            drop(view);
            let header = fixture
                .chain
                .committed(fixture.chain.height())
                .block()
                .header();
            let mut probe_block = fixture.chain.state().block(header);
            let probe = probe_block.transaction_for_callback_testing();
            let offer = crate::validation_fee_rewards::conversion_offer(&probe, &fixture.binding);
            panic!(
                "scheduled conversion missing allocation; original callbacks={callback_events:#?}; reward state={reward_state:#?}; read-only same-height offer={offer:#?}; original outputs={:#?}",
                fixture
                    .chain
                    .committed(fixture.chain.height())
                    .block()
                    .execution_outputs()
            );
        }
        assert_eq!(
            callback_events.len(),
            1,
            "the pinned scheduled conversion executes once"
        );
        assert!(matches!(
            &callback_events[0],
            iroha_data_model::events::EventBox::TriggerCompleted(event)
                if matches!(event.outcome(), iroha_data_model::events::trigger_completed::TriggerCompletedOutcome::Success)
        ));
        let receipt: ValidationFeeRewardAllocation = norito::decode_from_bytes(
            view.world
                .smart_contract_state
                .get(&key)
                .expect("scheduled real effect validation reserves its actual XOR output"),
        )
        .unwrap();
        assert_eq!(receipt.earning_period_start_ms, fixture.period);
        assert_eq!(
            receipt.service_blocks,
            validators
                .iter()
                .map(|validator| (validator.clone(), 2))
                .collect()
        );
        assert_eq!(receipt.xor_minor, expected_xor_minor);
        assert_eq!(receipt.sbd_minor, 1_000);
        assert_eq!(
            receipt.gross_shares,
            validators
                .iter()
                .map(|validator| (
                    validator.clone(),
                    expected_xor_minor / u128::try_from(validators.len()).unwrap()
                ))
                .collect()
        );
        assert_eq!(
            view.world
                .assets
                .get(&AssetId::new(
                    fixture.pool.xor.clone(),
                    fixture.pool.reward_pool.clone()
                ))
                .unwrap()
                .as_ref(),
            &fixture.pool.expected_output
        );
        assert!(view.world.assets.get(&fixture.pool.treasury_sbd).is_none());
    }
    let expected_claims = match (production_pool, two_validators) {
        (true, false) => vec![(2, "1.992007992"), (3, "2.988011988"), (4, "4.98001998")],
        (false, false) => vec![(2, "4"), (3, "6"), (4, "10")],
        (true, true) => vec![
            (2, "0.996003996"),
            (3, "1.494005994"),
            (4, "2.49000999"),
            (5, "4.98001998"),
        ],
        (false, true) => vec![(2, "2"), (3, "3"), (4, "5"), (5, "10")],
    };
    if !two_validators {
        // The one-validator control replays funding before any page is credited.
        fixture = replay_scheduled_reward_fixture(&fixture);
    }
    fixture.chain.commit_at(CONVERSION_TIME + 1_002, Vec::new());
    if two_validators {
        {
            let view = fixture.chain.state().view();
            let cursor =
                validation_fee_reward_state_key(&fixture.binding, "AllocationCursor").unwrap();
            assert!(
                view.world.smart_contract_state.get(&cursor).is_some(),
                "exactly one of two validator pages remains unfinished"
            );
            let first_validator = &validators[0];
            let mut credited = 0_u128;
            for &(seed, expected) in &expected_claims {
                let claimant = account(seed);
                let pending = crate::validation_fee_rewards::pending_fee_reward(
                    &view.world,
                    fixture.chain.height(),
                    &claimant,
                    LaneId::SINGLE,
                )
                .unwrap();
                let owner = if seed == 5 {
                    account(5)
                } else {
                    fixture.validator.clone()
                };
                if owner == *first_validator {
                    let pending = pending
                        .expect("first page has automatically credited all its staking owners");
                    assert_eq!(pending.amount, expected.parse::<Quantity>().unwrap());
                    credited = credited
                        .checked_add(
                            crate::validation_fee_rewards::minor_units(&pending.amount, 9).unwrap(),
                        )
                        .unwrap();
                } else {
                    assert!(
                        pending.is_none(),
                        "later validator page has not yet materialized"
                    );
                }
            }
            assert_eq!(credited, expected_xor_minor / 2);
            crate::state::validate_public_lane_stake_reserves_for_restore(&view.world)
                .expect("unfinished native funding and first-page custody reconcile");
        }
        // Independent startup executes the original certified conversion and
        // first entitlement block; the final validator page is still pending.
        fixture = replay_scheduled_reward_fixture(&fixture);
        {
            let view = fixture.chain.state().view();
            let cursor =
                validation_fee_reward_state_key(&fixture.binding, "AllocationCursor").unwrap();
            assert!(view.world.smart_contract_state.get(&cursor).is_some());
        }
        fixture.chain.commit_at(CONVERSION_TIME + 2_002, Vec::new());
    }
    {
        let view = fixture.chain.state().view();
        let cursor = validation_fee_reward_state_key(&fixture.binding, "AllocationCursor").unwrap();
        assert!(
            view.world.smart_contract_state.get(&cursor).is_none(),
            "each funded page credits exactly once"
        );
    }
    for &(seed, expected) in &expected_claims {
        let claimant = account(seed);
        let next_height = fixture.chain.height() + 1;
        let fee_claim = crate::validation_fee_rewards::fee_reward_claim_plan(
            &fixture.chain.state().view().world,
            next_height,
            &claimant,
            LaneId::SINGLE,
        )
        .unwrap()
        .expect("automatic entitlement needs no validator payout instruction");
        assert_eq!(fee_claim.amount, expected.parse::<Quantity>().unwrap());
        let claim = ClaimPublicLaneRewards {
            lane_id: LaneId::SINGLE,
            account: claimant.clone(),
            claim_plan: PublicLaneRewardClaimPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Network(fixture.chain.network_id()),
                valid_until_height: next_height,
                fee_claim,
            },
        };
        let timestamp = CONVERSION_TIME + next_height * 1_000;
        let signed = fixture
            .chain
            .sign(&key_pair(seed), [claim.into()], timestamp);
        assert_eq!(fixture.chain.commit_at(timestamp, vec![signed]), vec![true]);
        {
            let view = fixture.chain.state().view();
            let expected_balance = expected
                .parse::<Quantity>()
                .unwrap()
                .checked_add(&if validators.contains(&claimant) {
                    Quantity::from(100_u32)
                } else {
                    Quantity::zero()
                })
                .unwrap();
            assert_eq!(
                view.world
                    .assets
                    .get(&AssetId::new(fixture.pool.xor.clone(), claimant.clone()))
                    .unwrap()
                    .as_ref(),
                &expected_balance
            );
            assert!(
                crate::validation_fee_rewards::pending_fee_reward(
                    &view.world,
                    fixture.chain.height(),
                    &claimant,
                    LaneId::SINGLE
                )
                .unwrap()
                .is_none()
            );
        }
        if seed == 2 {
            // An independently reconstructed node replays the paid first claim;
            // the two nominators then make new authenticated withdrawals there.
            fixture = replay_scheduled_reward_fixture(&fixture);
        }
    }
    // One later certified block compacts the final signed claim only after its
    // original authenticated evidence is durable. No lifetime receipt bodies or
    // zero beneficiary balances may accumulate in hot reward state.
    let next_height = fixture.chain.height() + 1;
    fixture
        .chain
        .commit_at(CONVERSION_TIME + next_height * 1_000, Vec::new());
    let view = fixture.chain.state().view();
    let checkpoint =
        validation_fee_reward_state_key(&fixture.binding, "HistoryCheckpoint").unwrap();
    assert!(view.world.smart_contract_state.get(&checkpoint).is_some());
    for family in [
        "Allocation/",
        "Entitlement/",
        "Claim/",
        "ExposureSource/",
        "HistoryBalance/",
        "HistoryJournal/",
    ] {
        let prefix = validation_fee_reward_state_key(&fixture.binding, family).unwrap();
        assert!(
            !view
                .world
                .smart_contract_state
                .range(prefix.clone()..)
                .next()
                .is_some_and(|(key, _)| key.as_ref().starts_with(prefix.as_ref())),
            "fully archived funded rights must not retain {family} bodies"
        );
    }
    let key = validation_fee_reward_state_key(&fixture.binding, "State").unwrap();
    let final_state: ValidationFeeRewardsState =
        norito::decode_from_bytes(view.world.smart_contract_state.get(&key).unwrap()).unwrap();
    assert_eq!(final_state.reserved_xor, 0);
    assert_eq!(final_state.next_allocation, 1);
    assert_eq!(
        final_state.next_claim,
        u64::try_from(expected_claims.len()).unwrap()
    );
    assert!(
        view.world
            .assets
            .get(&AssetId::new(
                fixture.pool.xor.clone(),
                fixture.pool.reward_pool.clone()
            ))
            .is_none()
    );
    for validator in &validators {
        let principal_asset = AssetId::new(fixture.pool.xor.clone(), validator.clone());
        assert_eq!(
            view.world.public_lane_stake_reserves.get(&principal_asset),
            Some(&Quantity::from(100_u32))
        );
        let (_, expected) = expected_claims
            .iter()
            .find(|(seed, _)| account(*seed) == *validator)
            .unwrap();
        assert_eq!(
            view.world.assets.get(&principal_asset).unwrap().as_ref(),
            &Quantity::from(100_u32)
                .checked_add(&expected.parse::<Quantity>().unwrap())
                .unwrap()
        );
    }
    crate::state::validate_public_lane_stake_reserves_for_restore(&view.world)
        .expect("every withdrawal leaves both validators' original funded principal reserved");
    drop(view);
    if two_validators {
        // Replay every original signed withdrawal, then replay the same suffix
        // again to prove no second payment or entitlement can be fabricated.
        let _replayed_claims = replay_scheduled_reward_fixture(&fixture);
    }
}
