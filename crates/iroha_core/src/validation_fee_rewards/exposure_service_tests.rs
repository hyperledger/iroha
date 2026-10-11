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
                metadata: Default::default(),
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
                    metadata: Default::default(),
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
                metadata: Default::default(),
            },
        );
        stx.apply();
    }
    process_finalized_service(&mut block, &proposal, Some(&service))
        .expect("capture actual authenticated signer exposure");
    process_finalized_service(&mut block, &proposal, Some(&service))
        .expect("duplicate parent processing is idempotent");
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
