//! Plain ballot conviction factor test.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World},
};
use iroha_data_model::{
    Registrable,
    block::BlockHeader,
    events::data::{DataEvent, governance::GovernanceEvent},
    isi::governance::{CastPlainBallot, UpdatePlainConviction},
    permission::Permission,
    prelude::{Account, Domain, Grant},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
#[test]
fn plain_ballot_conviction_applies() {
    // Build minimal state/transaction
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account: Account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let world = World::with([domain], [account], []);
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut gov_cfg = state.gov.clone();
    gov_cfg.plain_voting_enabled = true;
    gov_cfg.min_bond_amount = 0_u64.into();
    gov_cfg.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    gov_cfg.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(gov_cfg);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut stx,
        &iroha_test_samples::ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    let plain_context = iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0);
    stx.world.governance_referenda_mut().insert(
        "ref-conviction".to_string(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            h_end: 200,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context,
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let perm: Permission = CanSubmitGovernanceBallot {
        referendum_id: "ref-conviction".to_string(),
    }
    .into();
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant ballot permission");
    // Defaults from config: conviction_step_blocks=100, max_conviction=6
    let amount: u128 = 10000; // sqrt=100
    let duration_blocks: u64 = 250; // factor = 1 + floor(250/100) = 3
    let instr = CastPlainBallot {
        referendum_id: "ref-conviction".to_string(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: amount.into(),
        duration_blocks,
    };
    instr
        .clone()
        .execute(&ALICE_ID, &mut stx)
        .expect("plain ballot ok");
    let events = stx.world.take_external_events();
    let step = stx.gov.conviction_step_blocks.max(1);
    let factor = (1u64 + (duration_blocks / step)).min(stx.gov.max_conviction);
    let expected_weight = 100u128.saturating_mul(u128::from(factor));
    // Expect BallotAccepted with conviction-adjusted weight.
    let mut saw_ok = false;
    for event in events {
        if let Some(DataEvent::Governance(GovernanceEvent::BallotAccepted(ev))) =
            event.as_data_event()
        {
            assert_eq!(ev.referendum_id, "ref-conviction");
            assert_eq!(ev.weight, Some(expected_weight));
            saw_ok = true;
            break;
        }
    }
    assert!(
        saw_ok,
        "expected a BallotAccepted event with conviction weight"
    );
}

fn funded_fractional_state() -> State {
    let mut state = State::new_for_testing(
        World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut governance = state.gov.clone();
    governance.plain_voting_enabled = true;
    governance.min_bond_amount = 0_u64.into();
    governance.min_turnout = 1;
    governance.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    governance.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(governance);
    state
}

#[test]
fn funded_public_lock_and_custody_reject_retired_json_fields() {
    use iroha_core::state::{GovernanceLockCustody, GovernanceLockRecord, WorldReadOnly};
    use mv::storage::StorageReadOnly;
    let state = funded_fractional_state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut tx = block.transaction();
    let id = "strict-public-bond";
    seed_fractional_referendum(&mut tx, id);
    fractional_ballot(id, "1.25", 200)
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
    let lock = &tx.world.governance_locks().get(id).unwrap().locks[&*ALICE_ID];
    let mut value = norito::json::to_value(lock).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("retired_duration".into(), true.into());
    assert!(norito::json::from_value::<GovernanceLockRecord>(value).is_err());
    let mut value = norito::json::to_value(&lock.custody).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unfunded_alias".into(), true.into());
    assert!(norito::json::from_value::<GovernanceLockCustody>(value).is_err());
}

fn seed_fractional_referendum(tx: &mut iroha_core::state::StateTransaction<'_, '_>, id: &str) {
    iroha_core::query::standalone_plain_test_fixture::fund_voter(tx, &ALICE_ID, 100_u64.into(), 3);
    let context = iroha_core::query::standalone_plain_test_fixture::context(&tx.gov, 2);
    tx.world.governance_referenda_mut().insert(
        id.into(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            h_end: 201,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context: context,
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    Grant::account_permission(
        Permission::from(CanSubmitGovernanceBallot {
            referendum_id: id.into(),
        }),
        ALICE_ID.clone(),
    )
    .execute(&ALICE_ID, tx)
    .unwrap();
}
fn fractional_ballot(id: &str, amount: &str, duration_blocks: u64) -> CastPlainBallot {
    CastPlainBallot {
        referendum_id: id.into(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: amount.parse().unwrap(),
        duration_blocks,
    }
}
fn fractional_update(id: &str, amount: &str, duration_blocks: u64) -> UpdatePlainConviction {
    UpdatePlainConviction {
        referendum_id: id.into(),
        owner: ALICE_ID.clone(),
        amount: amount.parse().unwrap(),
        duration_blocks,
    }
}
fn numeric_balance(
    tx: &iroha_core::state::StateTransaction<'_, '_>,
    account: &iroha_data_model::account::AccountId,
    asset: &iroha_data_model::asset::AssetDefinitionId,
) -> iroha_primitives::numeric::Quantity {
    use iroha_core::state::WorldReadOnly;
    use mv::storage::StorageReadOnly;
    tx.world
        .assets()
        .get(&iroha_data_model::asset::AssetId::new(
            asset.clone(),
            account.clone(),
        ))
        .map_or_else(iroha_primitives::numeric::Quantity::zero, |balance| {
            balance.clone().into_inner()
        })
}
#[test]
fn fractional_bonds_escrow_exact_deltas_and_reject_nonmonotonic_updates() {
    use iroha_core::state::WorldReadOnly;
    use mv::storage::StorageReadOnly;
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let mut state = funded_fractional_state();
    let id = "frozen-fractional";
    let asset = state.gov.voting_asset_id.clone();
    let escrow = state.gov.bond_escrow_account.clone();
    {
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut tx = block.transaction();
        seed_fractional_referendum(&mut tx, id);
        fractional_ballot(id, "1.25", 200)
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        assert_eq!(
            numeric_balance(&tx, &ALICE_ID, &asset),
            "98.75".parse().unwrap()
        );
        assert_eq!(
            numeric_balance(&tx, &escrow, &asset),
            "1.25".parse().unwrap()
        );
        assert!(
            fractional_update(id, "1.25", 200)
                .execute(&ALICE_ID, &mut tx)
                .is_err()
        );
        assert!(
            fractional_update(id, "1.251", 200)
                .execute(&ALICE_ID, &mut tx)
                .is_err()
        );
        assert_eq!(
            numeric_balance(&tx, &escrow, &asset),
            "1.25".parse().unwrap()
        );
        let second_cast = fractional_ballot(id, "2.25", 200)
            .execute(&ALICE_ID, &mut tx)
            .expect_err("a second cast must not act as an update");
        assert!(
            second_cast
                .to_string()
                .contains("plain ballot already cast")
        );
        fractional_update(id, "2.25", 200)
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        assert_eq!(
            numeric_balance(&tx, &ALICE_ID, &asset),
            "97.75".parse().unwrap()
        );
        assert_eq!(
            numeric_balance(&tx, &escrow, &asset),
            "2.25".parse().unwrap()
        );
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    // Neither weighting nor custody is rebound when current governance configuration changes.
    let mut changed = state.gov.clone();
    changed.conviction_step_blocks = 1;
    changed.max_conviction = 1;
    changed.min_bond_amount = 99_u64.into();
    changed.min_turnout = u128::MAX;
    changed.bond_escrow_account = iroha_test_samples::BOB_ID.clone();
    state.set_gov(changed);
    let mut block = state.block(BlockHeader::new(nonzero!(101_u64), None, None, 0, 0));
    let mut tx = block.transaction();
    for (amount, duration) in [("2.25", 100), ("3.25", 100)] {
        assert!(
            fractional_update(id, amount, duration)
                .execute(&ALICE_ID, &mut tx)
                .is_err(),
            "same absolute expiry with shorter remaining duration cannot lower conviction"
        );
    }
    fractional_update(id, "2.25", 200)
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
    let referendum = tx.world.governance_referenda().get(id).unwrap();
    let locks = tx.world.governance_locks().get(id).unwrap();
    assert_eq!(locks.locks.len(), 1);
    assert_eq!(
        iroha_core::state::plain_governance_tally(referendum, Some(locks), 101).unwrap(),
        [45, 0, 0]
    );
    assert_eq!(locks.locks.get(&ALICE_ID).unwrap().expiry_height, 301);
    assert_eq!(
        numeric_balance(&tx, &ALICE_ID, &asset),
        "97.75".parse().unwrap()
    );
    assert_eq!(
        numeric_balance(&tx, &escrow, &asset),
        "2.25".parse().unwrap()
    );
}
#[test]
fn closed_plain_result_survives_unlock_rollback_and_policy_changes() {
    use iroha_core::state::{GovernanceReferendumRecord, WorldReadOnly};
    use iroha_data_model::governance::conviction::PlainVotingResultV1;
    use mv::storage::StorageReadOnly;
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let mut state = funded_fractional_state();
    let id = "frozen-closed";
    let asset = state.gov.voting_asset_id.clone();
    {
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut tx = block.transaction();
        seed_fractional_referendum(&mut tx, id);
        fractional_ballot(id, "1.25", 200)
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let mut changed = state.gov.clone();
    changed.min_turnout = u128::MAX;
    changed.max_conviction = 1;
    state.set_gov(changed);
    {
        let block = state.block(BlockHeader::new(nonzero!(202_u64), None, None, 0, 0));
        assert!(matches!(
            block
                .world
                .governance_referenda()
                .get(id)
                .unwrap()
                .plain_result,
            PlainVotingResultV1::Decided(_)
        ));
        // Dropping the uncommitted close must restore both the pending result and escrow.
    }
    assert!(matches!(
        state
            .world_view()
            .governance_referenda()
            .get(id)
            .unwrap()
            .plain_result,
        PlainVotingResultV1::Pending
    ));
    let mut block = state.block(BlockHeader::new(nonzero!(202_u64), None, None, 0, 0));
    {
        let tx = block.transaction();
        assert_eq!(numeric_balance(&tx, &ALICE_ID, &asset), 100_u64.into());
        assert!(
            tx.world
                .governance_locks()
                .get(id)
                .is_none_or(|locks| locks.locks.is_empty())
        );
        let record = tx.world.governance_referenda().get(id).unwrap();
        assert_eq!(
            iroha_core::state::plain_governance_tally(record, None, 202).unwrap(),
            [33, 0, 0]
        );
        let PlainVotingResultV1::Decided(result) = &record.plain_result else {
            panic!("closed result")
        };
        assert!(
            result.approved,
            "frozen minimum turnout, not changed live policy"
        );
        let bytes = norito::encode_canonical(record).unwrap();
        let restored: GovernanceReferendumRecord = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(restored, *record);
        assert_eq!(
            iroha_core::state::plain_governance_tally(&restored, None, 999).unwrap(),
            [33, 0, 0]
        );
    }
    block.commit_world_overlay_for_testing().unwrap();
    let later = state.block(BlockHeader::new(nonzero!(203_u64), None, None, 0, 0));
    assert_eq!(
        iroha_core::state::plain_governance_tally(
            later.world.governance_referenda().get(id).unwrap(),
            None,
            203
        )
        .unwrap(),
        [33, 0, 0]
    );
}

#[test]
fn empty_proposed_plain_referendum_closes_and_requires_result_layout() {
    use iroha_core::state::{
        GovernanceReferendumRecord, GovernanceReferendumStatus, WorldReadOnly,
    };
    use iroha_data_model::governance::conviction::PlainVotingResultV1;
    use mv::storage::StorageReadOnly;
    let state = funded_fractional_state();
    let id = "empty-proposed";
    {
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut tx = block.transaction();
        seed_fractional_referendum(&mut tx, id);
        let mut record = tx.world.governance_referenda().get(id).unwrap().clone();
        record.status = GovernanceReferendumStatus::Proposed;
        tx.world
            .governance_referenda_mut()
            .insert(id.into(), record);
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let block = state.block(BlockHeader::new(nonzero!(202_u64), None, None, 0, 0));
    let record = block.world.governance_referenda().get(id).unwrap();
    assert_eq!(record.status, GovernanceReferendumStatus::Closed);
    let PlainVotingResultV1::Decided(decision) = &record.plain_result else {
        panic!("required empty decision")
    };
    assert_eq!(
        (
            decision.approve,
            decision.reject,
            decision.abstain,
            decision.approved
        ),
        (0, 0, 0, false)
    );
    for field in ["mode", "plain_context", "plain_result"] {
        let mut value = norito::json::to_value(record).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            norito::json::from_value::<GovernanceReferendumRecord>(value).is_err(),
            "missing {field} is not a wire layout"
        );
    }
    let mut retired = norito::json::to_value(record).unwrap();
    retired
        .as_object_mut()
        .unwrap()
        .insert("retired_tally".into(), true.into());
    assert!(norito::json::from_value::<GovernanceReferendumRecord>(retired).is_err());
    let mut invalid = record.clone();
    invalid.plain_result = PlainVotingResultV1::Pending;
    assert!(invalid.validate_context().is_err());
    let mut invalid = record.clone();
    if let PlainVotingResultV1::Decided(result) = &mut invalid.plain_result {
        result.approved = true;
    }
    assert!(invalid.validate_context().is_err());
}
