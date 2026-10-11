//! Native service capture, scheduled funded conversion, certified replay, and signed withdrawals.

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
