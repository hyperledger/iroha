//! Certified owner-history retirement, delayed accrual and authenticated recovery claims.

use super::*;
use iroha_data_model::{
    isi::account_recovery::ReplaceAccountController,
    validation_fee_rewards::{
        ValidationFeeRewardBeneficiaryRevision, validation_fee_beneficiary_alias_key,
        validation_fee_beneficiary_revision_key,
    },
};

fn replace(old: u8, new: u8) -> iroha_data_model::isi::InstructionBox {
    ReplaceAccountController {
        account: account(old),
        new_controller: account(new).controller().clone(),
    }
    .into()
}

fn retained_revisions(
    fixture: &ScheduledRewardFixture,
) -> Vec<ValidationFeeRewardBeneficiaryRevision> {
    let prefix = validation_fee_reward_state_key(&fixture.binding, "BeneficiaryHistory/").unwrap();
    fixture
        .chain
        .state()
        .view()
        .world
        .smart_contract_state
        .range(prefix.clone()..)
        .take_while(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
        .filter_map(|(_, bytes)| {
            let revision: ValidationFeeRewardBeneficiaryRevision =
                norito::decode_canonical(bytes).unwrap();
            (revision.beneficiary_id == account(3)).then_some(revision)
        })
        .collect()
}

fn assert_missing_recovery_archive_rolls_back(fixture: &ScheduledRewardFixture, height: u64) {
    let path = fixture
        .chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{height:020}-{}.nrt",
            hex::encode(fixture.chain.committed(height).block_hash().as_ref()),
        ));
    let original = std::fs::read(&path).unwrap();
    let hidden = path.with_extension("owner-history-test-original");
    for corrupt in [false, true] {
        if corrupt {
            std::fs::write(&path, b"corrupt original owner recovery archive").unwrap();
        } else {
            std::fs::rename(&path, &hidden).unwrap();
        }
        let header = BlockHeader::new(
            std::num::NonZeroU64::new(fixture.chain.height() + 1).unwrap(),
            fixture.chain.state().view().latest_block_hash(),
            None,
            CONVERSION_TIME + 1_002,
            0,
        );
        let mut block = fixture.chain.state().block(header);
        let before: BTreeMap<_, _> = block
            .world
            .smart_contract_state
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect();
        let fragments = block.committed_fragment_count();
        let refused = crate::validation_fee_rewards::process_reward_entitlements(&mut block);
        if corrupt {
            std::fs::write(&path, &original).unwrap();
        } else {
            std::fs::rename(&hidden, &path).unwrap();
        }
        assert!(
            matches!(refused, Err(crate::state::ExecutionOutputAttemptError::Deferred(reason))
            if reason.reason() == ivm::error::ExecutionDeferral::CanonicalHistoryUnavailable)
        );
        assert_eq!(block.committed_fragment_count(), fragments);
        let after: BTreeMap<_, _> = block
            .world
            .smart_contract_state
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect();
        assert_eq!(
            before, after,
            "failed original proof cannot retire owner authority or advance balances"
        );
    }
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn certified_recovery_compacts_superseded_owners_preserves_delayed_claims_and_replays() {
    let mut fixture = prepare_scheduled_reward_fixture(false, false);
    // The earning snapshots name account 3. Its owner changes in the actual
    // funding block before any beneficiary entitlement has been materialized.
    let recovery = fixture
        .chain
        .sign(&key_pair(3), [replace(3, 70)], CONVERSION_TIME + 2);
    assert_eq!(
        fixture.chain.commit_at(CONVERSION_TIME + 2, vec![recovery]),
        vec![true]
    );
    let first_recovery_height = fixture.chain.height();
    assert_eq!(retained_revisions(&fixture).len(), 2);
    assert_missing_recovery_archive_rolls_back(&fixture, first_recovery_height);
    let recovery = fixture
        .chain
        .sign(&key_pair(70), [replace(70, 71)], CONVERSION_TIME + 1_002);
    assert_eq!(
        fixture
            .chain
            .commit_at(CONVERSION_TIME + 1_002, vec![recovery]),
        vec![true]
    );
    assert_eq!(
        retained_revisions(&fixture)
            .iter()
            .map(|r| r.revision)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    fixture.chain.commit_at(CONVERSION_TIME + 2_002, Vec::new());
    assert_eq!(
        retained_revisions(&fixture)
            .iter()
            .map(|r| r.revision)
            .collect::<Vec<_>>(),
        vec![2]
    );
    {
        let view = fixture.chain.state().view();
        let evidence =
            crate::query::native_receipts::committed_fee_evidence(&view, first_recovery_height)
                .unwrap();
        assert!(evidence.records.iter().any(|record| matches!(&record.payload,
            iroha_data_model::fee_evidence::FeeEvidencePayloadV1::RewardBeneficiaryRevision(revision)
                if revision.beneficiary_id == account(3) && revision.revision == 0)));
        for seed in [3, 70, 71] {
            let alias =
                validation_fee_beneficiary_alias_key(&fixture.binding, &account(seed)).unwrap();
            assert!(
                view.world.smart_contract_state.get(&alias).is_some(),
                "historical account aliases remain necessary for delayed exposure"
            );
        }
        for revision in [0, 1] {
            let key =
                validation_fee_beneficiary_revision_key(&fixture.binding, &account(3), revision)
                    .unwrap();
            assert!(view.world.smart_contract_state.get(&key).is_none());
        }
        crate::state::validate_public_lane_stake_reserves_for_restore(&view.world).unwrap();
    }
    fixture = replay_scheduled_reward_fixture(&fixture);
    let next_height = fixture.chain.height() + 1;
    let fee_claim = crate::validation_fee_rewards::fee_reward_claim_plan(
        &fixture.chain.state().view().world,
        next_height,
        &account(71),
        LaneId::SINGLE,
    )
    .unwrap()
    .unwrap();
    assert_eq!(fee_claim.amount, Quantity::from(6_u32));
    assert_eq!(fee_claim.beneficiary_revision, 2);
    let claim = ClaimPublicLaneRewards {
        lane_id: LaneId::SINGLE,
        account: account(71),
        claim_plan: PublicLaneRewardClaimPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(fixture.chain.network_id()),
            valid_until_height: next_height,
            fee_claim,
        },
    };
    let timestamp = CONVERSION_TIME + 3_002;
    let claim_and_recovery =
        fixture
            .chain
            .sign(&key_pair(71), [claim.into(), replace(71, 72)], timestamp);
    assert_eq!(
        fixture.chain.commit_at(timestamp, vec![claim_and_recovery]),
        vec![true]
    );
    assert_eq!(
        retained_revisions(&fixture)
            .iter()
            .map(|r| r.revision)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    fixture.chain.commit_at(CONVERSION_TIME + 4_002, Vec::new());
    assert_eq!(
        retained_revisions(&fixture)
            .iter()
            .map(|r| r.revision)
            .collect::<Vec<_>>(),
        vec![3]
    );
    fixture = replay_scheduled_reward_fixture(&fixture);
    let view = fixture.chain.state().view();
    assert_eq!(
        view.world
            .assets
            .get(&AssetId::new(fixture.pool.xor.clone(), account(72)))
            .unwrap()
            .as_ref(),
        &Quantity::from(6_u32)
    );
    let state_key = validation_fee_reward_state_key(&fixture.binding, "State").unwrap();
    let state: ValidationFeeRewardsState =
        norito::decode_canonical(view.world.smart_contract_state.get(&state_key).unwrap()).unwrap();
    assert_eq!(
        (state.reserved_xor, state.next_allocation, state.next_claim),
        (14_000_000_000, 1, 1)
    );
    assert!(
        crate::validation_fee_rewards::pending_fee_reward(
            &view.world,
            fixture.chain.height(),
            &account(72),
            LaneId::SINGLE
        )
        .unwrap()
        .is_none()
    );
    crate::state::validate_public_lane_stake_reserves_for_restore(&view.world).unwrap();
}
