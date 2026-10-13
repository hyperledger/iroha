//! Authenticated finalized-service integration for automatic nominator exposure.

use super::*;
use iroha_data_model::{
    isi::Mint,
    nexus::{PublicLaneStakeShare, PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    validation_fee::{ValidationFeePayoutPolicyRegistryV1, ValidationFeePolicyRegistryV1},
};

#[test]
fn authenticated_finalized_service_captures_nominators_once_before_current_mutations() {
    let (mut chain, binding) =
        crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture();
    // Retain a genuine certified prefix beyond the fixture Parliament's atomic
    // certification height before installing its authenticated enactment.
    while chain.height() < 20 {
        chain.commit_at((chain.height() + 1) * 1_000, Vec::new());
    }
    let now = 1_735_650_000_000;
    let enacted_at_height = chain.height();
    let funding_authority = chain.genesis_account().clone();
    let validator = crate::validation_fee_rewards::tests::account(2);
    let first = crate::validation_fee_rewards::tests::account(3);
    let second = crate::validation_fee_rewards::tests::account(4);
    let late = crate::validation_fee_rewards::tests::account(5);
    let peer = chain.validators()[0].0.clone();
    let stakes = BTreeMap::from([
        (validator.clone(), Quantity::from(20u32)),
        (first.clone(), Quantity::from(30u32)),
        (second.clone(), Quantity::from(50u32)),
    ]);
    // The actual certified parent executes with these funded staking positions.
    // The policy becomes service-active only after its enactment height.
    chain.setup_world_at(now, |stx| {
        let registry = ValidationFeePolicyRegistryV1 {
            history: None,
            registered_policies: Vec::new(),
            payout_policies: ValidationFeePayoutPolicyRegistryV1 {
                entries: vec![crate::validation_fee::tests::payout_registry_entry(
                    &binding,
                    1,
                    enacted_at_height,
                )],
            },
        };
        crate::validation_fee::tests::install_policy_registry_fixture(&registry, stx);
        let custody = AssetId::new(binding.xor_asset_id.clone(), validator.clone());
        Mint::asset_quantity(Quantity::from(100u32), custody.clone())
            .execute(&funding_authority, stx)
            .expect("fund canonical parent staking custody");
        crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
            &stx.world,
            LaneId::SINGLE,
            &validator,
            &custody,
            &Quantity::from(100u32),
            &Quantity::from(100u32),
        )
        .unwrap()
        .apply(&mut stx.world);
        stx.world.public_lane_validators.insert(
            (LaneId::SINGLE, validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: peer.clone(),
                stake_account: validator.clone(),
                total_stake: Quantity::from(100u32),
                self_stake: Quantity::from(20u32),
                metadata: iroha_model_base::metadata::Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        for (staker, bonded) in &stakes {
            stx.world.public_lane_stake_shares.insert(
                (LaneId::SINGLE, validator.clone(), staker.clone()),
                PublicLaneStakeShare {
                    lane_id: LaneId::SINGLE,
                    validator: validator.clone(),
                    staker: staker.clone(),
                    bonded: bonded.clone(),
                    pending_unbonds: BTreeMap::new(),
                    metadata: iroha_model_base::metadata::Metadata::default(),
                },
            );
        }
    });
    chain.commit_at(now + 1, Vec::new());
    let proposal = chain.proposal(Some(now + 1_001), Vec::new());
    let service = {
        let view = chain.state().view();
        crate::sumeragi::certified_chain::CertifiedChain::new_for_parent_service(&view)
            .expect("authenticated signed genesis")
            .authenticate_parent_service(&proposal, |_, _| Ok(()))
            .expect("authenticate the genuine proposal's original parent CommitQC")
            .expect("non-genesis parent service")
    };
    assert!(service.signers().contains(&peer));
    let state = std::sync::Arc::clone(chain.state());
    {
        // Corrupt only the persisted parent fixture: a mutation in the current
        // block would correctly leave the healthy parent preimage earning.
        let key = (LaneId::SINGLE, validator.clone(), first.clone());
        let mut shares = state.world.public_lane_stake_shares.block();
        let mut malformed = shares.get(&key).cloned().unwrap();
        malformed.lane_id = LaneId::new(u32::MAX);
        shares.insert(key, malformed);
        shares.commit();
    }
    {
        let mut rejected = state.block(proposal.header());
        let sibling: StatePath = "reward_capture_sibling_TESTDATA".parse().unwrap();
        {
            let mut stx = rejected.transaction();
            stx.world
                .smart_contract_state
                .insert(sibling.clone(), vec![23]);
            stx.apply();
        }
        let fragments = rejected.committed_fragment_count();
        let error = process_finalized_service(&mut rejected, &proposal, Some(&service))
            .expect_err("reject malformed original parent exposure");
        assert!(
            matches!(error, crate::state::ExecutionOutputAttemptError::Owner(reason)
            if reason.contains("historical reward stake share has a non-canonical identity"))
        );
        assert_eq!(rejected.committed_fragment_count(), fragments);
        assert_eq!(
            rejected.world.smart_contract_state.get(&sibling),
            Some(&vec![23])
        );
    }
    state
        .world
        .public_lane_stake_shares
        .block_and_revert()
        .commit();
    let mut block = state.block(proposal.header());
    {
        let mut stx = block.transaction();
        // Exit the backing validator and recover/remove a nominator in this
        // current block; neither can erase what the certified parent earned.
        stx.world
            .public_lane_validators
            .remove((LaneId::SINGLE, validator.clone()));
        stx.world.public_lane_stake_shares.remove((
            LaneId::SINGLE,
            validator.clone(),
            first.clone(),
        ));
        stx.world.public_lane_stake_shares.insert(
            (LaneId::SINGLE, validator.clone(), late.clone()),
            PublicLaneStakeShare {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                staker: late,
                bonded: Quantity::from(9_000u32),
                pending_unbonds: BTreeMap::new(),
                metadata: iroha_model_base::metadata::Metadata::default(),
            },
        );
        stx.apply();
    }
    let fragments = block.committed_fragment_count();
    assert!(process_finalized_service(&mut block, &proposal, None).is_err());
    assert_eq!(block.committed_fragment_count(), fragments);
    process_finalized_service(&mut block, &proposal, Some(&service))
        .expect("capture actual authenticated signer exposure");
    assert_eq!(block.committed_fragment_count(), fragments + 1);
    process_finalized_service(&mut block, &proposal, Some(&service))
        .expect("duplicate parent processing is idempotent");
    assert_eq!(block.committed_fragment_count(), fragments + 1);
    let stx = block.transaction();
    let period = earning_month(service.timestamp_ms()).unwrap();
    let summary = service_snapshot(&stx, &binding, period).unwrap();
    assert_eq!(
        summary.service_blocks,
        BTreeMap::from([(validator.clone(), 1)])
    );
    assert_eq!(
        head(&stx, &binding, period, &validator)
            .unwrap()
            .unwrap()
            .page_count,
        1
    );
    let captured: ValidationFeeExposurePage =
        read(&stx, &page_key(&binding, period, &validator, 0).unwrap())
            .unwrap()
            .unwrap();
    assert_eq!(
        captured.exposure,
        vec![ValidationFeeRewardExposure {
            service_blocks: 1,
            stakes
        }]
    );
    assert_eq!(
        read_state(&stx, &binding).unwrap().service_height,
        service.height()
    );
}

#[test]
fn inactive_reward_policy_skips_staking_and_creates_no_fragment() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000))
            .expect("signed four-seat genesis");
    chain.commit_at(2_000, Vec::new());
    let proposal = chain.proposal(Some(3_000), Vec::new());
    let state = std::sync::Arc::clone(chain.state());
    let mut block = state.block(proposal.header());
    let key: StatePath = "inactive_reward_policy_original_TESTDATA".parse().unwrap();
    {
        let mut stx = block.transaction();
        stx.world.smart_contract_state.insert(key.clone(), vec![23]);
        stx.apply();
    }
    let fragments = block.committed_fragment_count();
    process_finalized_service(&mut block, &proposal, None).unwrap();
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(block.world.smart_contract_state.get(&key), Some(&vec![23]));
    assert!(block.world.public_lane_stake_shares.revert_map().is_empty());
}
