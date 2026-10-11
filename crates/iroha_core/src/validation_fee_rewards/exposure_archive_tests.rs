//! Original certified exposure archives survive hot-page removal and native replay.

use super::*;
use crate::validation_fee_rewards::tests::{account, fund_test_conversion, signed_claim_all};
use iroha_data_model::{
    isi::{Mint, staking::SchedulePublicLaneUnbond},
    nexus::{PublicLaneStakeShare, PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter},
    },
    validation_fee::{ValidationFeePayoutPolicyRegistryV1, ValidationFeePolicyRegistryV1},
    validation_fee_rewards::allocate_page,
};

const NOW: u64 = 1_735_650_000_000;
const FUNDED: u128 = 101 * 1_000_000_000;

fn archived_tail_fixture() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    ValidationFeeTreasuryPayoutBindingV1,
) {
    let deployer = AccountId::new(
        iroha_crypto::KeyPair::from_seed(vec![55; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(
        crate::validation_fee::tests::validation_fee_payout_world(&deployer),
        1_000,
    );
    // This signed unbond follows the committed global NPoS epoch schedule.
    // Permissioned genesis has no elections and retains its interval through u64::MAX.
    let policy = SumeragiNposParameters::default();
    let epoch_length = policy.epoch_length_blocks.get();
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.extend([
        Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            policy.epoch_length_blocks,
        )),
        Parameter::Custom(policy.into_custom_parameter()),
    ]);
    let (mut chain, binding) =
        crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture_with_config(config);
    let (_, authorization) =
        crate::state::validator_committee::current_authority(&chain.state().view())
            .expect("original certified NPoS epoch authority");
    assert_eq!(authorization.last_height, epoch_length);
    while chain.height() < 20 {
        chain.commit_at((chain.height() + 1) * 1_000, Vec::new());
    }
    let validator = account(2);
    let period = earning_month(NOW).unwrap();
    let mut page = ValidationFeeExposurePage {
        earning_period_start_ms: period,
        validator: validator.clone(),
        page_index: 0,
        exposure: Vec::new(),
    };
    for value in 10_000_u32.. {
        let stakes = BTreeMap::from([
            (validator.clone(), Quantity::from(value)),
            (account(3), Quantity::from(30_u32)),
            (account(4), Quantity::from(50_u32)),
        ]);
        if !append(&mut page, &stakes).unwrap() {
            break;
        }
    }
    let stakes = page.exposure.last().unwrap().stakes.clone();
    let self_stake = stakes[&validator].clone();
    let total = self_stake.checked_add(&Quantity::from(80_u32)).unwrap();
    let service = service_count(&page).unwrap();
    let peer = chain.validators()[0].0.clone();
    let authority = chain.genesis_account().clone();
    {
        let view = chain.state().view();
        assert!(
            view.world()
                .public_lane_validators()
                .iter()
                .all(|(_, row)| row.peer_id != peer),
            "component stake setup cannot replace another original peer registration",
        );
        assert!(
            view.world()
                .public_lane_stake_shares()
                .iter()
                .all(|((_, account, _), _)| account != &validator),
            "component stake setup cannot replace original validator positions",
        );
    }
    chain.setup_world_at(NOW, |stx| {
        let registry = ValidationFeePolicyRegistryV1 {
            registered_policies: Vec::new(),
            payout_policies: ValidationFeePayoutPolicyRegistryV1 {
                entries: vec![crate::validation_fee::tests::payout_registry_entry(
                    &binding, 1, 20,
                )],
            },
        };
        crate::validation_fee::tests::install_policy_registry_fixture(&registry, stx);
        let custody = AssetId::new(binding.xor_asset_id.clone(), validator.clone());
        Mint::asset_quantity(total.clone(), custody.clone())
            .execute(&authority, stx)
            .unwrap();
        crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
            &stx.world,
            LaneId::SINGLE,
            &validator,
            &custody,
            &total,
            &total,
        )
        .unwrap()
        .apply(&mut stx.world);
        stx.world.public_lane_validators.insert(
            (LaneId::SINGLE, validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: peer,
                stake_account: validator.clone(),
                total_stake: total,
                self_stake,
                metadata: Default::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        for (staker, bonded) in stakes {
            stx.world.public_lane_stake_shares.insert(
                (LaneId::SINGLE, validator.clone(), staker.clone()),
                PublicLaneStakeShare {
                    lane_id: LaneId::SINGLE,
                    validator: validator.clone(),
                    staker,
                    bonded,
                    pending_unbonds: BTreeMap::new(),
                    metadata: Default::default(),
                },
            );
        }
        // The component prefix also includes collected, unconverted fees from
        // this earning month. Custody backs that obligation while genuine
        // later blocks archive and cool its exposure; a month with no pending
        // fees or unsettled wallets is correctly eligible for retirement.
        Mint::asset_quantity(
            quantity(100, 2).unwrap(),
            AssetId::new(
                binding.ds_asset_id.clone(),
                binding.treasury_account_id.clone(),
            ),
        )
        .execute(&authority, stx)
        .unwrap();
        write(stx, pending_key(&binding, period).unwrap(), &100_u64).unwrap();
        let mut reward_state = read_state(stx, &binding).unwrap();
        reward_state.pending_sbd_total = reward_state.pending_sbd_total.checked_add(100).unwrap();
        save_state(stx, &binding, &reward_state).unwrap();
        // Component initialization supplies a dense historical prefix. Genuine
        // finalized service below rewrites this exact tail into original native
        // custody before any page is removed or any cold read is accepted.
        persist_tail(
            stx,
            &binding,
            ValidationFeeExposureArchive {
                page,
                previous: None,
            },
            0,
        )
        .unwrap();
        write(
            stx,
            service_key(&binding, period).unwrap(),
            &ValidationFeeServiceSnapshot {
                earning_period_start_ms: period,
                service_blocks: BTreeMap::from([(validator, service)]),
            },
        )
        .unwrap();
    });
    chain.commit_at(NOW + 1, Vec::new());
    chain.commit_at(NOW + 1_001, Vec::new());
    (chain, binding)
}

#[test]
fn archived_exposure_survives_hot_rollover_replay_and_signed_claims() {
    let (mut chain, binding) = archived_tail_fixture();
    let period = earning_month(NOW).unwrap();
    let validator = account(2);
    let signer = iroha_crypto::KeyPair::from_seed(vec![2; 32], iroha_crypto::Algorithm::Ed25519);
    let timestamp = NOW + 2_001;
    let unbond = SchedulePublicLaneUnbond {
        lane_id: LaneId::SINGLE,
        validator: validator.clone(),
        staker: validator.clone(),
        request_id: Hash::new(b"archived-reward-unbond"),
        amount: Quantity::one(),
        release_at_ms: timestamp + 365 * DAY_MS,
    };
    let signed = chain.sign(&signer, [unbond.into()], timestamp);
    assert_eq!(
        chain.commit_at(timestamp, vec![signed]),
        vec![true],
        "actual signed archive rollover unbond must publish successfully: {:?}",
        chain.committed(chain.height()).block().execution_outputs()
    );
    chain.commit_at(NOW + 3_001, Vec::new());
    let state = std::sync::Arc::clone(chain.state());
    let proposal = chain.proposal(Some(NOW + 40 * DAY_MS), Vec::new());
    let mut block = state.block(proposal.header());
    // Funding is deliberately delayed beyond the earning month. The real
    // maintenance path authenticates and cools even the latest tail before
    // any reward is funded; fixed heads still preserve all earning intervals.
    settlement::process_reward_entitlements(&mut block).unwrap();
    // The delayed funding and claim instructions below are component execution;
    // retain their finite invocation owner before borrowing the State child.
    // Certified archive reads and the signed rollover still use the original chain.
    let invocation = Hash::new(b"archived-reward-claim-component");
    let mut stx = block.transaction_for_fastpq_testing(invocation);
    assert_eq!(stx.tx_call_hash, Some(invocation));
    let head = head(&stx, &binding, period, &validator).unwrap().unwrap();
    assert_eq!(head.page_count, 2);
    assert!(!head.tail_resident);
    assert!(
        stx.world
            .smart_contract_state
            .get(&page_key(&binding, period, &validator, 1).unwrap())
            .is_none()
    );
    assert!(
        stx.world
            .smart_contract_state
            .get(&archive_key(&binding, period, &validator, 1).unwrap())
            .is_none()
    );
    let old_key = page_key(&binding, period, &validator, 0).unwrap();
    let old_archive_key = archive_key(&binding, period, &validator, 0).unwrap();
    assert!(stx.world.smart_contract_state.get(&old_key).is_none());
    assert!(
        stx.world
            .smart_contract_state
            .get(&old_archive_key)
            .is_none()
    );
    let latest = load_archive(&stx, &binding, period, &validator, &head.latest).unwrap();
    let previous = latest.previous.clone().unwrap();
    let historical = load_archive(&stx, &binding, period, &validator, &previous).unwrap();
    assert_eq!(historical.page.page_index, 0);
    assert!(
        crate::query::native_receipts::committed_reward_exposure(
            &stx,
            previous.recorded_at_height,
            &old_archive_key,
            Hash::new(b"substituted"),
        )
        .is_err()
    );
    let mut expected = allocate_page(
        FUNDED,
        head.service_total,
        previous.service_start,
        &historical.page,
    )
    .unwrap();
    for (account, amount) in allocate_page(
        FUNDED,
        head.service_total,
        head.latest.service_start,
        &latest.page,
    )
    .unwrap()
    {
        *expected.entry(account).or_default() += amount;
    }
    fund_test_conversion(&mut stx, &binding, period, FUNDED);
    assert!(settlement::accrue_next_page(&mut stx, &binding).unwrap());
    assert!(settlement::accrue_next_page(&mut stx, &binding).unwrap());
    assert!(!settlement::accrue_next_page(&mut stx, &binding).unwrap());
    for (claimant, amount) in expected {
        if amount > 0 {
            assert_eq!(
                read::<u128>(&stx, &claimable_key(&binding, &claimant).unwrap()).unwrap(),
                Some(amount)
            );
            signed_claim_all(&mut stx, &binding, &claimant);
        }
    }
    reconciliation::validate(&stx.world, &binding).unwrap();
    drop(stx);
    drop(block);
    let (mut replay, replay_binding) = archived_tail_fixture();
    assert_eq!(replay_binding, binding);
    replay
        .replay_from(&chain)
        .expect("replay original unbond and source rollover");
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_hash(replay.state()).unwrap(),
        crate::snapshot::canonical_state_snapshot_hash(chain.state()).unwrap()
    );
    let view = replay.state().view();
    let restored = crate::query::native_receipts::committed_reward_exposure(
        &view,
        previous.recorded_at_height,
        &old_archive_key,
        previous.archive_hash,
    )
    .expect("replayed archive remains available after hot source removal");
    assert_eq!(restored, historical);
}
