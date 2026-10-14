//! Governance lock slashing and restitution flows.

//!
//! Verifies manual slashing/restitution of governance bonds updates locks, ledgers, and balances.
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    account::AccountId,
    asset::{Asset, AssetDefinition},
    block::BlockHeader,
    domain::Domain,
    permission::Permission,
    prelude::{AssetDefinitionId, AssetId, Grant},
};
use iroha_executor_data_model::permission::governance::{
    CanRestituteGovernanceLock, CanSlashGovernanceLock, CanSubmitGovernanceBallot,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID, gen_account_in};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn setup_state(def_id: &AssetDefinitionId, receiver_id: &AccountId) -> State {
    let alice_id = ALICE_ID.clone();
    let escrow_id = BOB_ID.clone();
    let wonderland: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(wonderland.clone()).build(&alice_id);
    let alice_account = iroha_data_model::account::Account::new(ALICE_ID.clone()).build(&alice_id);
    let escrow_account = iroha_data_model::account::Account::new(BOB_ID.clone()).build(&alice_id);
    let receiver_account =
        iroha_data_model::account::Account::new(receiver_id.clone()).build(&alice_id);
    let asset_def = AssetDefinition::numeric(
        def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let alice_asset = Asset::new(
        AssetId::new(def_id.clone(), ALICE_ID.clone()),
        Quantity::from(1_000_u64),
    );
    let escrow_asset = Asset::new(
        AssetId::new(def_id.clone(), BOB_ID.clone()),
        Quantity::from(0_u64),
    );
    let receiver_asset = Asset::new(
        AssetId::new(def_id.clone(), receiver_id.clone()),
        Quantity::from(0_u64),
    );
    let world = World::with_assets(
        [domain],
        [alice_account, escrow_account, receiver_account],
        [asset_def],
        [alice_asset, escrow_asset, receiver_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut gov_cfg = state.gov.clone();
    gov_cfg.plain_voting_enabled = true;
    gov_cfg.voting_asset_id = def_id.clone();
    gov_cfg.min_bond_amount = 10_u64.into();
    gov_cfg.bond_escrow_account = escrow_id.clone();
    gov_cfg.slash_receiver_account = receiver_id.clone();
    state.set_gov(gov_cfg);
    state
}
fn grant_governance_perms(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    referendum_id: &str,
    alice_id: &AccountId,
) {
    for perm in [
        Permission::from(CanSubmitGovernanceBallot {
            referendum_id: referendum_id.to_string(),
        }),
        Permission::from(CanSlashGovernanceLock {
            referendum_id: referendum_id.to_string(),
        }),
        Permission::from(CanRestituteGovernanceLock {
            referendum_id: referendum_id.to_string(),
        }),
    ] {
        Grant::account_permission(perm, ALICE_ID.clone())
            .execute(alice_id, tx)
            .expect("grant governance permission");
    }
}
fn seed_plain_referendum(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    referendum_id: &str,
) {
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        tx,
        &iroha_test_samples::ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    tx.world.governance_referenda_mut().insert(
        referendum_id.to_string(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            h_end: 5,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context: iroha_core::query::standalone_plain_test_fixture::context(&tx.gov, 0),
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
}
fn lock_slash_restitute(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    referendum_id: &str,
    owner: &AccountId,
) {
    let ballot = iroha_data_model::isi::governance::CastPlainBallot {
        referendum_id: referendum_id.to_string(),
        direction: 0,
        owner: owner.clone(),
        amount: 10_u64.into(),
        duration_blocks: 200,
    };
    ballot
        .clone()
        .execute(owner, tx)
        .expect("ballot should lock funds");
    let slash = iroha_data_model::isi::governance::SlashGovernanceLock {
        referendum_id: referendum_id.to_string(),
        owner: owner.clone(),
        amount: 4_u64.into(),
        reason: "policy_violation".to_string(),
    };
    slash
        .clone()
        .execute(owner, tx)
        .expect("slash should succeed");
    let restitute = iroha_data_model::isi::governance::RestituteGovernanceLock {
        referendum_id: referendum_id.to_string(),
        owner: owner.clone(),
        amount: 2_u64.into(),
        reason: "appeal".to_string(),
    };
    restitute
        .execute(owner, tx)
        .expect("restitution should succeed");
}
#[test]
fn manual_slash_and_restitution_move_bonds_and_record_ledger() {
    // Direct retained-custody movements share the execution witness recorder.
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let (receiver_id, _) = gen_account_in("wonderland");
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let state = setup_state(&def_id, &receiver_id);
    let alice_id = ALICE_ID.clone();
    let referendum_id = "rid-slash";
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    grant_governance_perms(&mut stx, referendum_id, &alice_id);
    seed_plain_referendum(&mut stx, referendum_id);
    lock_slash_restitute(&mut stx, referendum_id, &alice_id);
    stx.apply();
    let escrow_asset_id = AssetId::new(def_id.clone(), BOB_ID.clone());
    let receiver_asset_id = AssetId::new(def_id.clone(), receiver_id.clone());
    let escrow_balance = sblock
        .world
        .assets()
        .get(&escrow_asset_id)
        .expect("escrow asset")
        .clone();
    let receiver_balance = sblock
        .world
        .assets()
        .get(&receiver_asset_id)
        .expect("receiver asset")
        .clone();
    assert_eq!(escrow_balance.into_inner(), Quantity::from(8_u64));
    assert_eq!(receiver_balance.into_inner(), Quantity::from(2_u64));
    let locks = sblock
        .world
        .governance_locks()
        .get(referendum_id)
        .expect("locks after slash");
    let rec = locks.locks.get(&alice_id).expect("alice lock after slash");
    assert_eq!(rec.amount, Quantity::from(8_u64));
    assert_eq!(rec.slashed, Quantity::from(2_u64));
    let ledger = sblock
        .world
        .governance_slashes()
        .get(referendum_id)
        .expect("slash ledger");
    let entry = ledger.slashes.get(&alice_id).expect("slash ledger entry");
    assert_eq!(entry.total_slashed, Quantity::from(4_u64));
    assert_eq!(entry.total_restituted, Quantity::from(2_u64));
    assert_eq!(
        entry.last_reason,
        iroha_data_model::events::data::governance::GovernanceSlashReason::Restitution
    );
}

#[test]
fn frozen_units_reject_fractional_slash_and_accept_majority_and_full_restitution() {
    use iroha_data_model::isi::governance::{
        CastPlainBallot, RestituteGovernanceLock, SlashGovernanceLock,
    };
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let (receiver, _) = gen_account_in("wonderland");
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "slash".parse().unwrap(),
    );
    let state = setup_state(&definition, &receiver);
    let id = "frozen-slash-units";
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut tx = block.transaction();
    grant_governance_perms(&mut tx, id, &ALICE_ID);
    seed_plain_referendum(&mut tx, id);
    CastPlainBallot {
        referendum_id: id.into(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 10_u64.into(),
        duration_blocks: 200,
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap();
    let balance = |tx: &iroha_core::state::StateTransaction<'_, '_>, who: &AccountId| -> Quantity {
        tx.world
            .assets()
            .get(&AssetId::new(definition.clone(), who.clone()))
            .map_or_else(Quantity::zero, |v| v.clone().into_inner())
    };
    let before = [
        balance(&tx, &ALICE_ID),
        balance(&tx, &BOB_ID),
        balance(&tx, &receiver),
    ];
    assert!(
        SlashGovernanceLock {
            referendum_id: id.into(),
            owner: ALICE_ID.clone(),
            amount: "0.5".parse().unwrap(),
            reason: "policy_violation".into()
        }
        .execute(&ALICE_ID, &mut tx)
        .is_err(),
        "live unrestricted asset precision cannot override frozen whole units"
    );
    assert_eq!(
        before,
        [
            balance(&tx, &ALICE_ID),
            balance(&tx, &BOB_ID),
            balance(&tx, &receiver)
        ]
    );
    for (slash, remaining, total_slashed) in [(6_u64, 4_u64, 6_u64), (4, 0, 10)] {
        SlashGovernanceLock {
            referendum_id: id.into(),
            owner: ALICE_ID.clone(),
            amount: slash.into(),
            reason: "policy_violation".into(),
        }
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        let record = tx.world.governance_referenda().get(id).unwrap();
        let locks = tx.world.governance_locks().get(id).unwrap();
        let lock = locks.locks.get(&ALICE_ID).unwrap();
        assert_eq!(lock.amount, remaining.into());
        assert_eq!(lock.slashed, total_slashed.into());
        lock.validate_plain_context(record.plain_policy().unwrap())
            .unwrap();
        let restored: iroha_core::state::GovernanceLocksForReferendum =
            norito::decode_canonical(&norito::encode_canonical(locks).unwrap()).unwrap();
        assert!(iroha_core::state::plain_governance_tally(record, Some(&restored), 1).is_ok());
        assert_eq!(balance(&tx, &BOB_ID), remaining.into());
        assert_eq!(balance(&tx, &receiver), total_slashed.into());
    }
    assert!(
        RestituteGovernanceLock {
            referendum_id: id.into(),
            owner: ALICE_ID.clone(),
            amount: "0.5".parse().unwrap(),
            reason: "appeal".into()
        }
        .execute(&ALICE_ID, &mut tx)
        .is_err()
    );
    RestituteGovernanceLock {
        referendum_id: id.into(),
        owner: ALICE_ID.clone(),
        amount: 10_u64.into(),
        reason: "appeal".into(),
    }
    .execute(&ALICE_ID, &mut tx)
    .unwrap();
    assert_eq!(balance(&tx, &ALICE_ID), 990_u64.into());
    assert_eq!(balance(&tx, &BOB_ID), 10_u64.into());
    assert_eq!(balance(&tx, &receiver), 0_u64.into());
    let record = tx.world.governance_referenda().get(id).unwrap();
    assert_eq!(
        iroha_core::state::plain_governance_tally(record, tx.world.governance_locks().get(id), 1)
            .unwrap(),
        [9, 0, 0]
    );
}

#[test]
fn restitution_rechecks_aggregate_capacity_and_preserves_closed_decision() {
    use iroha_core::state::plain_governance_tally;
    use iroha_data_model::{
        governance::conviction::PlainVotingResultV1,
        isi::{
            Mint,
            governance::{CastPlainBallot, RestituteGovernanceLock, SlashGovernanceLock},
        },
    };
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let (receiver, _) = gen_account_in("wonderland");
    let (second, _) = gen_account_in("wonderland");
    let (third, _) = gen_account_in("wonderland");
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "capacity".parse().unwrap(),
    );
    let mut state = setup_state(&definition, &receiver);
    let mut governance = state.gov.clone();
    governance.conviction_step_blocks = 1;
    governance.max_conviction = u64::MAX;
    state.set_gov(governance);
    let id = "restitution-capacity";
    let bond = Quantity::from(1_u128 << 126);
    let duration = u64::MAX - 2;
    let ballot = |owner: &AccountId| CastPlainBallot {
        referendum_id: id.into(),
        direction: 0,
        owner: owner.clone(),
        amount: bond.clone(),
        duration_blocks: duration,
    };
    let slash = |owner: &AccountId| SlashGovernanceLock {
        referendum_id: id.into(),
        owner: owner.clone(),
        amount: bond.clone(),
        reason: "capacity_test".into(),
    };
    let restitution = RestituteGovernanceLock {
        referendum_id: id.into(),
        owner: ALICE_ID.clone(),
        amount: bond.clone(),
        reason: "appeal".into(),
    };
    let balance = |tx: &iroha_core::state::StateTransaction<'_, '_>, owner: &AccountId| {
        tx.world
            .assets()
            .get(&AssetId::new(definition.clone(), owner.clone()))
            .map_or_else(Quantity::zero, |value| value.clone().into_inner())
    };
    let weight;
    {
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut tx = block.transaction();
        grant_governance_perms(&mut tx, id, &ALICE_ID);
        seed_plain_referendum(&mut tx, id);
        Mint::asset_quantity(
            bond.clone(),
            AssetId::new(definition.clone(), ALICE_ID.clone()),
        )
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        for voter in [&second, &third] {
            iroha_core::query::standalone_plain_test_fixture::fund_voter(
                &mut tx,
                voter,
                bond.clone(),
                0,
            );
            Grant::account_permission(
                Permission::from(CanSubmitGovernanceBallot {
                    referendum_id: id.into(),
                }),
                voter.clone(),
            )
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        }
        let policy = tx
            .world
            .governance_referenda()
            .get(id)
            .unwrap()
            .plain_policy()
            .unwrap();
        weight = policy.weight(&bond, duration).unwrap();
        assert!(weight.checked_mul(2).is_some());
        assert!(weight.checked_mul(3).is_none());
        ballot(&ALICE_ID).execute(&ALICE_ID, &mut tx).unwrap();
        slash(&ALICE_ID).execute(&ALICE_ID, &mut tx).unwrap();
        ballot(&second).execute(&second, &mut tx).unwrap();
        ballot(&third).execute(&third, &mut tx).unwrap();
        let before_balances = [
            balance(&tx, &ALICE_ID),
            balance(&tx, &BOB_ID),
            balance(&tx, &receiver),
        ];
        assert_eq!(
            before_balances,
            [1_000_u64.into(), bond.try_add(&bond).unwrap(), bond.clone()]
        );
        assert!(balance(&tx, &second).is_zero() && balance(&tx, &third).is_zero());
        let before_locks =
            norito::encode_canonical(tx.world.governance_locks().get(id).unwrap()).unwrap();
        let before_ledger =
            norito::encode_canonical(tx.world.governance_slashes().get(id).unwrap()).unwrap();
        let error = restitution.clone().execute(&ALICE_ID, &mut tx).unwrap_err();
        assert!(error.to_string().contains("u128"), "{error}");
        assert_eq!(
            before_balances,
            [
                balance(&tx, &ALICE_ID),
                balance(&tx, &BOB_ID),
                balance(&tx, &receiver)
            ]
        );
        assert_eq!(
            before_locks,
            norito::encode_canonical(tx.world.governance_locks().get(id).unwrap()).unwrap()
        );
        assert_eq!(
            before_ledger,
            norito::encode_canonical(tx.world.governance_slashes().get(id).unwrap()).unwrap()
        );
        assert_eq!(
            plain_governance_tally(
                tx.world.governance_referenda().get(id).unwrap(),
                tx.world.governance_locks().get(id),
                1
            )
            .unwrap(),
            [weight * 2, 0, 0]
        );
        // Free headroom again, then let the real block-start transition retain its result.
        slash(&second).execute(&ALICE_ID, &mut tx).unwrap();
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let mut block = state.block(BlockHeader::new(nonzero!(6_u64), None, None, 0, 0));
    let mut tx = block.transaction();
    let closed = tx.world.governance_referenda().get(id).unwrap().clone();
    assert!(matches!(
        closed.plain_result,
        PlainVotingResultV1::Decided(_)
    ));
    assert_eq!(
        plain_governance_tally(&closed, tx.world.governance_locks().get(id), 6).unwrap(),
        [weight, 0, 0]
    );
    restitution.execute(&ALICE_ID, &mut tx).unwrap();
    assert_eq!(*tx.world.governance_referenda().get(id).unwrap(), closed);
    assert_eq!(
        plain_governance_tally(&closed, tx.world.governance_locks().get(id), 6).unwrap(),
        [weight, 0, 0]
    );
    assert_eq!(balance(&tx, &BOB_ID), bond.try_add(&bond).unwrap());
    assert_eq!(balance(&tx, &receiver), bond);
    assert_eq!(balance(&tx, &ALICE_ID), 1_000_u64.into());
}
