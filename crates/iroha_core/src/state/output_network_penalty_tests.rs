//! Real signed ballot rejection retains only its protocol penalty and fee.
//! This private-owner fixture does not establish carrier publication or finality.

use super::*;
use crate::state::{
    GovernanceReferendumMode, GovernanceReferendumRecord, GovernanceReferendumStatus,
};
use iroha_data_model::{
    ValidationFail,
    asset::{AssetDefinitionId, AssetId},
    events::data::governance::GovernanceSlashReason,
    events::data::{DataEvent, governance::GovernanceEvent},
    isi::{Grant, Mint, error::InstructionExecutionError, governance::CastPlainBallot},
    permission::Permission,
    transaction::{FeeChargeKind, FeeChargeLimit, error::TransactionRejectionReason},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{BOB_ID, gen_account_in};

#[test]
fn signed_conflicting_second_ballot_retains_actual_slash_and_rejection_fee() {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    crate::status::reset_nexus_economics_for_tests();
    let asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR fee asset");
    let mut state = fixture_with_fee_asset(65_536, None, Some(asset.clone()));
    let (escrow, _) = gen_account_in("network-penalty");
    let (receiver, _) = gen_account_in("network-penalty");
    let referendum = "network-penalty".to_owned();
    let mut gov = state.gov.clone();
    gov.plain_voting_enabled = true;
    gov.voting_asset_id = asset.clone();
    gov.min_bond_amount = Quantity::from(10_u32);
    gov.citizenship_bond_amount = Quantity::zero();
    gov.bond_escrow_account = escrow.clone();
    gov.slash_receiver_account = receiver.clone();
    gov.slash_double_vote_bps = 2_000;
    gov.conviction_step_blocks = 1;
    state.set_gov(gov);
    {
        // Extend the genesis world fixture without publishing another height or
        // changing committed chain lineage. This is not a finalized carrier.
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        let mut transaction = setup.transaction_for_callback_testing();
        for account in [&escrow, &receiver] {
            Register::account(Account::new(account.clone()))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        // The parent fee fixture already minted ten; both fees and voting custody
        // now use this real registered Global asset with a starting balance of 1000.
        Mint::asset_quantity(
            Quantity::from(990_u32),
            AssetId::of(asset.clone(), ALICE_ID.clone()),
        )
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
        transaction.world.governance_referenda_mut().insert(
            referendum.clone(),
            GovernanceReferendumRecord {
                h_start: 1,
                h_end: 50,
                status: GovernanceReferendumStatus::Open,
                mode: GovernanceReferendumMode::Plain,
                plain_context: crate::query::standalone_plain_test_fixture::context(
                    &transaction.gov,
                    0,
                ),
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
            },
        );
        let permission: Permission = CanSubmitGovernanceBallot {
            referendum_id: referendum.clone(),
        }
        .into();
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let source = carrier(
        &state,
        [(0, 20_u32), (1, 30_u32)]
            .into_iter()
            .map(|(direction, amount)| {
                input(
                    &state,
                    vec![
                        CastPlainBallot {
                            referendum_id: referendum.clone(),
                            direction,
                            owner: ALICE_ID.clone(),
                            amount: Quantity::from(amount),
                            duration_blocks: 200,
                        }
                        .into(),
                    ],
                    FeePaymentIntent::authority(
                        vec![FeeChargeLimit::new(
                            FeeChargeKind::Nexus,
                            asset.clone(),
                            Quantity::from(1_u32),
                        )],
                        None,
                    ),
                    false,
                )
            })
            .collect(),
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let fragments = block.committed_fragment_count();
    execute(&mut block, &source).unwrap();
    let accepted = network_row(&block, 0);
    assert_eq!(accepted.input_index, 0);
    assert!(accepted.result.is_ok(), "{:?}", accepted.result);
    let rejected = network_row(&block, 1);
    assert_eq!(rejected.input_index, 1);
    assert!(
        matches!(rejected.result.as_ref(), Err(TransactionRejectionReason::Validation(
            ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(reason))
        )) if reason.as_ref() == "second plain ballot cannot change direction"),
        "the actual ballot error must survive penalty and fee settlement: {:?}",
        rejected.result
    );
    assert!(rejected.result.batch_transfer_outcomes().is_empty());
    assert!(rejected.completions.is_empty());
    let lock = block
        .world
        .governance_locks()
        .get(&referendum)
        .unwrap()
        .locks
        .get(&*ALICE_ID)
        .unwrap();
    assert_eq!(lock.direction, 0);
    assert_eq!(lock.amount, Quantity::from(16_u32));
    assert_eq!(lock.slashed, Quantity::from(4_u32));
    let slash = block
        .world
        .governance_slashes()
        .get(&referendum)
        .unwrap()
        .slashes
        .get(&*ALICE_ID)
        .unwrap();
    assert_eq!(slash.total_slashed, Quantity::from(4_u32));
    assert_eq!(slash.total_restituted, Quantity::zero());
    assert_eq!(slash.last_reason, GovernanceSlashReason::DoubleVote);
    assert_eq!(slash.last_height, 2);
    for (owner, amount) in [(&*ALICE_ID, 978_u32), (&escrow, 16), (&receiver, 4)] {
        assert_eq!(
            block
                .world
                .asset(&AssetId::of(asset.clone(), owner.clone()))
                .unwrap()
                .as_ref(),
            &Quantity::from(amount),
            "unexpected custody balance for {owner}"
        );
    }
    // Nexus fees burn the payer asset; the configured sink is not credited.
    assert!(
        block
            .world
            .assets()
            .get(&AssetId::of(asset.clone(), BOB_ID.clone()))
            .is_none()
    );
    assert_eq!(
        block
            .world
            .asset_definition(&asset)
            .unwrap()
            .total_quantity(),
        &Quantity::from(998_u32)
    );
    assert_eq!(
        block.committed_fragment_count(),
        fragments + 3,
        "first ballot with its fee, rejection penalty, and rejection fee apply once each"
    );
    assert!(block.gas_used_in_block > 0);
    let rejected_events = block.world.external_event_buf.iter().filter(|event| {
        matches!(event.as_data_event(), Some(DataEvent::Governance(GovernanceEvent::BallotRejected(event)))
            if event.referendum_id == referendum)
    }).count();
    assert_eq!(
        rejected_events, 1,
        "the rolled-back attempt must not duplicate its rejection event"
    );
    let slash_events = block.world.external_event_buf.iter().filter(|event| {
        matches!(event.as_data_event(), Some(DataEvent::Governance(GovernanceEvent::LockSlashed(event)))
            if event.referendum_id == referendum && event.reason == GovernanceSlashReason::DoubleVote)
    }).count();
    assert_eq!(slash_events, 1);
    drop(_recording);
    drop(block);
    let view = state.view();
    assert!(view.world().governance_locks().get(&referendum).is_none());
    assert!(view.world().governance_slashes().get(&referendum).is_none());
    assert_eq!(
        view.world()
            .asset(&AssetId::of(asset, ALICE_ID.clone()))
            .unwrap()
            .as_ref(),
        &Quantity::from(1_000_u32)
    );
}

#[path = "output_network_penalty_refusal_tests.rs"]
mod refusal;
