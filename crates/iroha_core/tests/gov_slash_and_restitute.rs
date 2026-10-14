//! Governance slashing and restitution flows for plain ballots and manual appeals.

use iroha_core::{
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig, fixture_validators},
};
use iroha_data_model::{
    Registrable,
    asset::{Asset, AssetDefinition},
    block::BlockHeader,
    domain::Domain,
    events::data::governance::GovernanceSlashReason,
    permission::Permission,
    prelude::{AssetDefinitionId, AssetId, Grant},
    transaction::{
        FeePaymentIntent, TransactionBuilder, TransactionEntrypoint,
        signed::{
            SealedTransactionCommitmentPayload, SealedTransactionReveal,
            SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
        },
    },
};
use iroha_executor_data_model::permission::governance::{
    CanRestituteGovernanceLock, CanSlashGovernanceLock, CanSubmitGovernanceBallot,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, gen_account_in};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::sync::Arc;
fn governance_world_with_accounts(
    voting_asset_id: AssetDefinitionId,
    escrow_account: &iroha_data_model::account::AccountId,
    slash_account: &iroha_data_model::account::AccountId,
) -> World {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(domain_id.clone()).build(escrow_account);
    let alice_account =
        iroha_data_model::account::Account::new(ALICE_ID.clone()).build(escrow_account);
    let escrow =
        iroha_data_model::account::Account::new(escrow_account.clone()).build(escrow_account);
    let slash =
        iroha_data_model::account::Account::new(slash_account.clone()).build(escrow_account);
    let asset_def = AssetDefinition::numeric(
        voting_asset_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(escrow_account);
    // Seed balances: Alice 1_000, escrow 0, slash 0.
    let alice_asset = Asset::new(
        AssetId::new(voting_asset_id.clone(), ALICE_ID.clone()),
        Quantity::from(1_000_u64),
    );
    let escrow_asset = Asset::new(
        AssetId::new(voting_asset_id.clone(), escrow_account.clone()),
        Quantity::from(0_u64),
    );
    let slash_asset = Asset::new(
        AssetId::new(voting_asset_id, slash_account.clone()),
        Quantity::from(0_u64),
    );
    World::with_assets(
        [domain],
        [alice_account, escrow, slash],
        [asset_def],
        [alice_asset, escrow_asset, slash_asset],
        [],
    )
}
fn governance_state_with_accounts(
    voting_asset_id: AssetDefinitionId,
    escrow_account: &iroha_data_model::account::AccountId,
    slash_account: &iroha_data_model::account::AccountId,
) -> State {
    let world = governance_world_with_accounts(voting_asset_id, escrow_account, slash_account);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    State::new_for_testing(world, kura, query_handle)
}
/// Materialize the exact four-validator manifest before genesis binds its policy.
fn governance_lane_manifests(
    nexus: &iroha_config::parameters::actual::Nexus,
    validators: &[(iroha_model_base::peer::PeerId, Vec<u8>)],
) -> Arc<LaneManifestRegistry> {
    let lane = nexus.lane_catalog.lanes()[0].clone();
    let manifest = iroha_data_model::nexus::NativeLaneManifestV1 {
        lane: Some(lane.alias.clone()),
        governance: lane.governance.clone(),
        version: Some(iroha_data_model::nexus::NativeLaneManifestV1::VERSION),
        validators: Some(
            validators
                .iter()
                .map(
                    |(peer, _)| iroha_data_model::nexus::NativeLaneValidatorBindingV1 {
                        validator: Some(
                            iroha_data_model::account::AccountId::new(peer.public_key().clone())
                                .to_string(),
                        ),
                        peer_id: Some(peer.to_string()),
                        torii_url: None,
                    },
                )
                .collect(),
        ),
        ..Default::default()
    };
    let directory = tempfile::tempdir().expect("retained governance manifest directory");
    std::fs::write(
        directory
            .path()
            .join(format!("{}.manifest.json", lane.alias)),
        norito::json::to_vec(&manifest).expect("canonical lane manifest JSON"),
    )
    .expect("write exact governance committee source");
    let registry = LaneManifestRegistry::from_config(
        &nexus.lane_catalog,
        &nexus.governance,
        &iroha_config::parameters::actual::LaneRegistry {
            manifest_directory: Some(directory.path().to_path_buf()),
            ..Default::default()
        },
    );
    let rules = registry
        .lane_rules(lane.id)
        .expect("materialized four-validator governance rules");
    assert_eq!(rules.validator_bindings.len(), validators.len());
    for (binding, (peer, _)) in rules.validator_bindings.iter().zip(validators) {
        assert_eq!(&binding.peer_id, peer);
    }
    // State retains the immutable parsed source, so the temporary pathname is no authority.
    Arc::new(registry)
}

fn seed_slash_snapshot(
    state: &mut State,
    rid: &str,
    escrow_asset_id: &AssetId,
    slash_asset_id: &AssetId,
) {
    let mut seed_block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut seed_tx = seed_block.transaction_for_fastpq_protocol_testing();
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut seed_tx,
        &ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    let mut snapshot_governance = seed_tx.gov.clone();
    snapshot_governance.conviction_step_blocks = 1;
    seed_tx.world.governance_referenda_mut().insert(
        rid.to_owned(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            h_end: 100,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context: iroha_core::query::standalone_plain_test_fixture::context(
                &snapshot_governance,
                0,
            ),
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let mut locks = iroha_core::state::GovernanceLocksForReferendum::default();
    locks.locks.insert(
        ALICE_ID.clone(),
        iroha_core::state::GovernanceLockRecord {
            owner: ALICE_ID.clone(),
            amount: 60_u64.into(),
            slashed: 40_u64.into(),
            expiry_height: 100,
            direction: 0,
            duration_blocks: 99,
            custody: iroha_core::state::GovernanceLockCustody {
                escrowed: true,
                asset_definition_id: escrow_asset_id.definition().clone(),
                bond_escrow_account: escrow_asset_id.account().clone(),
                slash_receiver_account: slash_asset_id.account().clone(),
            },
        },
    );
    seed_tx
        .world
        .governance_locks_mut()
        .insert(rid.to_string(), locks);
    let mut ledger = iroha_core::state::GovernanceSlashLedger::default();
    ledger.slashes.insert(
        ALICE_ID.clone(),
        iroha_core::state::GovernanceSlashEntry {
            total_slashed: 40_u64.into(),
            total_restituted: 0_u64.into(),
            last_reason: GovernanceSlashReason::DoubleVote,
            last_height: 1,
        },
    );
    seed_tx
        .world
        .governance_slashes_mut()
        .insert(rid.to_string(), ledger);
    **seed_tx
        .world
        .asset_mut(escrow_asset_id)
        .expect("escrow asset") = Quantity::from(60_u64);
    **seed_tx
        .world
        .asset_mut(slash_asset_id)
        .expect("slash asset") = Quantity::from(40_u64);
    seed_tx.apply();
    seed_block
        .commit_world_overlay_for_testing()
        .expect("commit slash snapshot");
}
#[test]
#[allow(clippy::too_many_lines)]
fn double_vote_slashes_plain_lock() {
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let (escrow_id, _) = gen_account_in("wonderland");
    let (slash_id, _) = gen_account_in("wonderland");
    let mut initial_state = governance_state_with_accounts(def_id.clone(), &escrow_id, &slash_id);
    let mut governance = initial_state.gov.clone();
    governance.plain_voting_enabled = true;
    governance.voting_asset_id = def_id.clone();
    governance.citizenship_asset_id = def_id.clone();
    governance.citizenship_bond_amount = 10_u64.into();
    governance.citizenship_escrow_account = iroha_test_samples::BOB_ID.clone();
    governance.min_bond_amount = 10_u64.into();
    governance.bond_escrow_account = escrow_id.clone();
    governance.slash_receiver_account = slash_id.clone();
    governance.slash_double_vote_bps = 2_000;
    initial_state.set_gov(governance.clone());
    let alice = ALICE_ID.clone();
    // The original World supplies the retained voter snapshot and permission.
    // The initial monetary ballot itself executes as Alice's signed genesis intent.
    let rid = "rid-slash-plain".to_string();
    {
        // The direct ballot fixture publishes native transfer transcripts.
        let _fixture_witness_guard = iroha_core::exec_witness::exec_witness_guard();
        // This is explicit test world setup, not a finalized genesis output.
        // Signed genesis executes separately against the resulting funded world.
        let mut sblock1 = initial_state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut citizen_setup = sblock1.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"plain-ballot-citizenship-setup",
        ));
        // Citizenship has its own exact ten-unit bond in separate custody. Top up
        // that amount through the real mint so the ballot still starts with 1,000.
        iroha_data_model::isi::Register::account(iroha_data_model::account::Account::new(
            iroha_test_samples::BOB_ID.clone(),
        ))
        .execute(&ALICE_ID, &mut citizen_setup)
        .expect("register separate citizenship custody");
        iroha_data_model::isi::Mint::asset_quantity(
            10_u64,
            AssetId::new(def_id.clone(), ALICE_ID.clone()),
        )
        .execute(&ALICE_ID, &mut citizen_setup)
        .expect("fund the exact citizenship bond");
        iroha_data_model::isi::governance::RegisterCitizen {
            owner: ALICE_ID.clone(),
            amount: 10_u64.into(),
        }
        .execute(&ALICE_ID, &mut citizen_setup)
        .expect("bond citizenship before the first ballot");
        citizen_setup.apply();
        let mut stx1 = sblock1.transaction_for_fastpq_protocol_testing();
        iroha_core::query::standalone_plain_test_fixture::fund_voter(
            &mut stx1,
            &iroha_test_samples::ALICE_ID,
            1_000_000_u64.into(),
            0,
        );
        stx1.world.governance_referenda_mut().insert(
            rid.clone(),
            iroha_core::state::GovernanceReferendumRecord {
                h_start: 1,
                h_end: 50,
                status: iroha_core::state::GovernanceReferendumStatus::Open,
                mode: iroha_core::state::GovernanceReferendumMode::Plain,
                plain_context: iroha_core::query::standalone_plain_test_fixture::context(
                    &stx1.gov, 0,
                ),
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
            },
        );
        let perm: Permission = CanSubmitGovernanceBallot {
            referendum_id: rid.clone(),
        }
        .into();
        Grant::account_permission(perm, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx1)
            .expect("grant ballot permission");
        stx1.apply();
        sblock1
            .commit_world_overlay_for_testing()
            .expect("retain original governance fixture world without block history");
        assert!(initial_state.view().block_hashes().is_empty());
    }
    let ballot_ok = iroha_data_model::isi::governance::CastPlainBallot {
        referendum_id: rid.clone(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 20_u64.into(),
        duration_blocks: 200,
    };
    let mut config = TestChainConfig::new(initial_state.world, 1_000);
    config.governance = Some(governance);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.genesis_instructions = vec![ballot_ok.into()];
    let mut chain =
        CertifiedTestChain::start(config).expect("actual signed initial ballot genesis");
    let state = Arc::clone(chain.state());
    assert_eq!(chain.validators(), fixture_validators().as_slice());
    state
        .lane_manifests
        .read()
        .validate_materialized_source_projection()
        .expect("signed genesis retains a frozen canonical lane source");
    assert!(
        chain
            .genesis()
            .output_results()
            .all(|result| result.is_ok())
    );
    // Block 2: commit the sealed carrier for the conflicting ballot.
    let ballot_conflict = iroha_data_model::isi::governance::CastPlainBallot {
        referendum_id: rid.clone(),
        direction: 1,
        owner: ALICE_ID.clone(),
        amount: 30_u64.into(),
        duration_blocks: 200,
    };
    let mut transaction = TransactionBuilder::new(
        *state.network_id_ref(),
        ALICE_ID.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    transaction.set_creation_time(std::time::Duration::from_millis(1_001));
    let transaction = transaction
        .with_instructions([ballot_conflict])
        .sign(ALICE_KEYPAIR.private_key());
    let salt = [0xA5; 32];
    let reveal_deadline_height = 10;
    let commitment = compute_sealed_transaction_commitment(
        state.network_id_ref(),
        &transaction,
        salt,
        reveal_deadline_height,
    );
    let sealed_commitment = SignedSealedTransactionCommitment::sign(
        SealedTransactionCommitmentPayload::new(
            *state.network_id_ref(),
            ALICE_ID.clone(),
            commitment,
            3,
            reveal_deadline_height,
            None,
        ),
        ALICE_KEYPAIR.private_key(),
    );
    let commitment_entrypoint = TransactionEntrypoint::SealedCommitment(sealed_commitment);
    let commitment_hash = commitment_entrypoint.hash();
    let committed = chain.commit_entrypoints(vec![commitment_entrypoint]);
    let block = committed.block();
    block
        .validate_output_merkle_cache()
        .expect("complete commitment outputs");
    assert_eq!(
        block.network_input_hashes().collect::<Vec<_>>(),
        [commitment_hash]
    );
    let (_, commitment_output) = block
        .network_output_at(0)
        .expect("exact commitment Network output");
    assert!(
        commitment_output.result.is_ok(),
        "sealed commitment must be retained before reveal: {:?}",
        commitment_output.result
    );

    // Block 3: the sealed reveal enters the shared sequential corridor. The
    // ballot remains rejected while its prevalidated slash commits separately.
    let reveal_entrypoint = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        commitment,
        transaction.clone(),
        salt,
    ));
    let reveal_hash = reveal_entrypoint.hash();
    let committed = chain.commit_entrypoints(vec![reveal_entrypoint]);
    let block = committed.block();
    block
        .validate_output_merkle_cache()
        .expect("complete reveal outputs");
    assert_eq!(
        block.network_input_hashes().collect::<Vec<_>>(),
        [reveal_hash]
    );
    let (_, reveal_output) = block
        .network_output_at(0)
        .expect("exact reveal Network output");
    let rejection = reveal_output
        .result
        .as_ref()
        .expect_err("conflicting sealed ballot must remain rejected");
    assert!(
        format!("{rejection:?}").contains("second plain ballot cannot change direction"),
        "unexpected rejection: {rejection:?}"
    );
    assert_eq!(state.committed_height(), 3);
    assert_eq!(chain.height(), 3);
    assert!(
        state.has_committed_entrypoint(reveal_hash),
        "the exact rejected sealed carrier must be replay protected"
    );
    assert!(
        state.has_committed_entrypoint(transaction.hash_as_entrypoint()),
        "the rejected reveal's enclosed signed intent must be replay protected"
    );
    // Escrow should now hold 16 (20 - 20% slash), slash receiver 4.
    let view = state.view();
    let escrow_asset_id = AssetId::new(def_id.clone(), escrow_id);
    let slash_asset_id = AssetId::new(def_id.clone(), slash_id);
    let lock = view
        .world()
        .governance_locks()
        .get(&rid)
        .and_then(|locks| locks.locks.get(&alice))
        .expect("lock present after slash");
    assert_eq!(lock.amount, Quantity::from(16_u64));
    assert_eq!(lock.slashed, Quantity::from(4_u64));
    let escrow_balance = view
        .world()
        .asset(&escrow_asset_id)
        .expect("escrow asset exists")
        .as_ref()
        .clone();
    let slash_balance = view
        .world()
        .asset(&slash_asset_id)
        .expect("slash receiver asset exists")
        .as_ref()
        .clone();
    assert_eq!(escrow_balance.clone(), Quantity::from(16_u64));
    assert_eq!(slash_balance.clone(), Quantity::from(4_u64));
    assert_eq!(
        view.world()
            .asset(&AssetId::new(def_id.clone(), alice.clone()))
            .expect("voter retains the unbonded balance")
            .as_ref(),
        &Quantity::from(980_u64),
        "voter 980 + escrow 16 + slash 4 conserve the original 1,000 units"
    );
    assert_eq!(
        view.world()
            .asset(&AssetId::new(
                def_id.clone(),
                iroha_test_samples::BOB_ID.clone()
            ))
            .expect("citizenship custody survives ballot slashing")
            .as_ref(),
        &Quantity::from(10_u64)
    );
    assert_eq!(
        view.world()
            .citizens()
            .get(&alice)
            .expect("bonded citizen")
            .amount,
        Quantity::from(10_u64)
    );
    assert_eq!(
        view.world()
            .asset_definitions()
            .get(&def_id)
            .expect("voting asset")
            .total_quantity(),
        &Quantity::from(1_010_u64),
        "ballot balances and separate citizenship custody conserve all minted units"
    );
    drop(view);
    let header4 = BlockHeader::new(nonzero!(4_u64), None, None, 0, 0);
    let mut sblock4 = state.block(header4);
    let mut stx4 = sblock4.transaction_for_fastpq_protocol_testing();
    let unresolved_update = iroha_data_model::isi::governance::UpdatePlainConviction {
        referendum_id: rid.clone(),
        owner: ALICE_ID.clone(),
        amount: 20_u64.into(),
        duration_blocks: 200,
    }
    .execute(&ALICE_ID, &mut stx4)
    .expect_err("a conviction update must not overwrite unresolved slash accounting");
    assert!(
        unresolved_update
            .to_string()
            .contains("conviction update requires prior restitution")
    );
    let retained = stx4
        .world
        .governance_locks()
        .get(&rid)
        .and_then(|locks| locks.locks.get(&alice))
        .expect("rejected update retains the slashed lock");
    assert_eq!(retained.amount, Quantity::from(16_u64));
    assert_eq!(retained.slashed, Quantity::from(4_u64));
    assert_eq!(
        stx4.world
            .asset(&escrow_asset_id)
            .expect("escrow remains after rejected update")
            .as_ref()
            .clone(),
        Quantity::from(16_u64)
    );
    assert_eq!(
        stx4.world
            .asset(&slash_asset_id)
            .expect("slash receiver remains after rejected update")
            .as_ref()
            .clone(),
        Quantity::from(4_u64)
    );
}
#[test]
fn restitution_restores_slashed_balance() {
    // Direct retained-custody movements share the execution witness recorder.
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let (escrow_id, _) = gen_account_in("wonderland");
    let (slash_id, _) = gen_account_in("wonderland");
    let mut state = governance_state_with_accounts(def_id.clone(), &escrow_id, &slash_id);
    let alice = ALICE_ID.clone();
    let mut gov_cfg = state.gov.clone();
    // The retained position originally bonded 100 units before its 40-unit slash.
    gov_cfg.min_bond_amount = 100_u64.into();
    gov_cfg.plain_voting_enabled = true;
    gov_cfg.voting_asset_id = def_id.clone();
    gov_cfg.bond_escrow_account = escrow_id.clone();
    gov_cfg.slash_receiver_account = slash_id.clone();
    state.set_gov(gov_cfg);
    let rid = "rid-restitute".to_string();
    let escrow_asset_id = AssetId::new(def_id.clone(), escrow_id.clone());
    let slash_asset_id = AssetId::new(def_id.clone(), slash_id.clone());
    // Pre-seed a lock with a recorded slash (amount=60 active, 40 slashed) and matching balances.
    seed_slash_snapshot(&mut state, &rid, &escrow_asset_id, &slash_asset_id);
    {
        let header = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
        let mut sblock = state.block(header);
        // Lower custody component: use the finite mandatory source owner, without
        // claiming a signed Network input or finalized carrier publication.
        let mut stx = sblock.transaction_for_fastpq_protocol_testing();
        // Grant restitution permission to ALICE.
        let perm: Permission = CanRestituteGovernanceLock {
            referendum_id: rid.clone(),
        }
        .into();
        Grant::account_permission(perm, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("grant restitution permission");
        iroha_data_model::isi::governance::RestituteGovernanceLock {
            referendum_id: rid.clone(),
            owner: ALICE_ID.clone(),
            amount: 30_u64.into(),
            reason: "appeal_upheld".to_string(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("restitution should succeed");
        let events = stx.world.take_external_events();
        assert!(events.iter().any(|ev| {
            matches!(
                ev.as_data_event(),
                Some(iroha_data_model::events::data::DataEvent::Governance(
                    iroha_data_model::events::data::governance::GovernanceEvent::LockRestituted(payload)
                )) if payload.amount == Quantity::from(30_u64)
                    && payload.reason == GovernanceSlashReason::Restitution
                    && payload.note == "appeal_upheld"
            )
        }));
        stx.apply();
        sblock
            .commit_world_overlay_for_testing()
            .expect("commit restitution fixture");
    }
    let view = state.view();
    let lock = view
        .world()
        .governance_locks()
        .get(&rid)
        .and_then(|locks| locks.locks.get(&alice))
        .expect("lock present after restitution");
    assert_eq!(lock.amount, Quantity::from(90_u64));
    assert_eq!(lock.slashed, Quantity::from(10_u64));
    let escrow_balance = view
        .world()
        .asset(&escrow_asset_id)
        .expect("escrow asset exists")
        .as_ref()
        .clone();
    let slash_balance = view
        .world()
        .asset(&slash_asset_id)
        .expect("slash receiver asset exists")
        .as_ref()
        .clone();
    assert_eq!(escrow_balance.clone(), Quantity::from(90_u64));
    assert_eq!(slash_balance.clone(), Quantity::from(10_u64));
}
#[test]
fn restitution_preflight_leaves_custody_untouched_when_slash_ledger_is_missing() {
    let def_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain"),
        "xor".parse().expect("asset name"),
    );
    let (escrow_id, _) = gen_account_in("wonderland");
    let (slash_id, _) = gen_account_in("wonderland");
    let mut state = governance_state_with_accounts(def_id.clone(), &escrow_id, &slash_id);
    let mut gov_cfg = state.gov.clone();
    // The retained position originally bonded 100 units before its 40-unit slash.
    gov_cfg.min_bond_amount = 100_u64.into();
    gov_cfg.voting_asset_id = def_id.clone();
    gov_cfg.bond_escrow_account = escrow_id.clone();
    gov_cfg.slash_receiver_account = slash_id.clone();
    state.set_gov(gov_cfg);
    let referendum_id = "restitution-missing-ledger";
    let escrow_asset_id = AssetId::new(def_id.clone(), escrow_id);
    let slash_asset_id = AssetId::new(def_id, slash_id);
    seed_slash_snapshot(&mut state, referendum_id, &escrow_asset_id, &slash_asset_id);
    {
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut state_transaction = block.transaction_for_fastpq_protocol_testing();
        state_transaction
            .world
            .governance_slashes_mut()
            .remove(referendum_id.to_owned());
        Grant::account_permission(
            Permission::from(CanRestituteGovernanceLock {
                referendum_id: referendum_id.to_owned(),
            }),
            ALICE_ID.clone(),
        )
        .execute(&ALICE_ID, &mut state_transaction)
        .expect("grant restitution permission");
        state_transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit restitution fixture block");
    }
    let header = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut state_transaction = block.transaction_for_fastpq_protocol_testing();
    let error = iroha_data_model::isi::governance::RestituteGovernanceLock {
        referendum_id: referendum_id.to_owned(),
        owner: ALICE_ID.clone(),
        amount: 30_u64.into(),
        reason: "missing_ledger".to_owned(),
    }
    .execute(&ALICE_ID, &mut state_transaction)
    .expect_err("missing slash ledger must reject restitution");
    assert!(error.to_string().contains("slash ledger missing"));
    // Deliberately apply the errored overlay to prove the helper itself did not
    // stage any custody or lock mutation before its ledger preflight failed.
    state_transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit restitution fixture block");
    let view = state.view();
    let lock = view
        .world()
        .governance_locks()
        .get(referendum_id)
        .and_then(|locks| locks.locks.get(&ALICE_ID))
        .expect("rejected restitution retains the lock");
    assert_eq!(lock.amount, Quantity::from(60_u64));
    assert_eq!(lock.slashed, Quantity::from(40_u64));
    assert_eq!(
        view.world()
            .asset(&escrow_asset_id)
            .expect("escrow asset")
            .as_ref(),
        &Quantity::from(60_u64)
    );
    assert_eq!(
        view.world()
            .asset(&slash_asset_id)
            .expect("slash receiver asset")
            .as_ref(),
        &Quantity::from(40_u64)
    );
}
#[test]
fn slash_and_restitution_use_stored_custody_after_governance_config_change() {
    // Direct retained-custody movements share the execution witness recorder.
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain");
    let old_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "old_xor".parse().expect("old asset name"),
    );
    let live_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "live_xor".parse().expect("live asset name"),
    );
    let alice = ALICE_ID.clone();
    let (old_escrow, _) = gen_account_in("wonderland");
    let (old_receiver, _) = gen_account_in("wonderland");
    let (live_escrow, _) = gen_account_in("wonderland");
    let (live_receiver, _) = gen_account_in("wonderland");
    let old_escrow_asset_id = AssetId::new(old_definition_id.clone(), old_escrow.clone());
    let old_receiver_asset_id = AssetId::new(old_definition_id.clone(), old_receiver.clone());
    let live_escrow_asset_id = AssetId::new(live_definition_id.clone(), live_escrow.clone());
    let live_receiver_asset_id = AssetId::new(live_definition_id.clone(), live_receiver.clone());
    let world = World::with_assets(
        [Domain::new(domain_id).build(&alice)],
        [
            iroha_data_model::account::Account::new(alice.clone()).build(&alice),
            iroha_data_model::account::Account::new(old_escrow.clone()).build(&alice),
            iroha_data_model::account::Account::new(old_receiver.clone()).build(&alice),
            iroha_data_model::account::Account::new(live_escrow.clone()).build(&alice),
            iroha_data_model::account::Account::new(live_receiver.clone()).build(&alice),
        ],
        [
            AssetDefinition::numeric(
                old_definition_id.clone(),
                "old_xor".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&alice),
            AssetDefinition::numeric(
                live_definition_id.clone(),
                "live_xor".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&alice),
        ],
        [
            Asset::new(old_escrow_asset_id.clone(), Quantity::from(10_u64)),
            Asset::new(old_receiver_asset_id.clone(), Quantity::from(5_u64)),
            Asset::new(live_escrow_asset_id.clone(), Quantity::from(11_u64)),
            Asset::new(live_receiver_asset_id.clone(), Quantity::from(13_u64)),
        ],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut live_governance = state.gov.clone();
    live_governance.voting_asset_id = live_definition_id;
    live_governance.bond_escrow_account = live_escrow;
    live_governance.slash_receiver_account = live_receiver;
    state.set_gov(live_governance);
    let referendum_id = "stored-custody-slash-restitution";
    let stored_custody = iroha_core::state::GovernanceLockCustody {
        escrowed: true,
        asset_definition_id: old_definition_id,
        bond_escrow_account: old_escrow,
        slash_receiver_account: old_receiver,
    };
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    // Lower custody component: retain the protocol-purpose pool independently
    // of any signed user invocation or finalized carrier authority.
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut tx,
        &iroha_test_samples::ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    let mut frozen_governance = tx.gov.clone();
    // The old custody position bonded ten; the newer live minimum remains unchanged.
    frozen_governance.min_bond_amount = 10_u64.into();
    frozen_governance.voting_asset_id = stored_custody.asset_definition_id.clone();
    frozen_governance.bond_escrow_account = stored_custody.bond_escrow_account.clone();
    frozen_governance.slash_receiver_account = stored_custody.slash_receiver_account.clone();
    tx.world.governance_referenda_mut().insert(
        referendum_id.to_owned(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 0,
            h_end: 99,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context: iroha_core::query::standalone_plain_test_fixture::context(
                &frozen_governance,
                0,
            ),
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    for permission in [
        Permission::from(CanSlashGovernanceLock {
            referendum_id: referendum_id.to_owned(),
        }),
        Permission::from(CanRestituteGovernanceLock {
            referendum_id: referendum_id.to_owned(),
        }),
    ] {
        Grant::account_permission(permission, alice.clone())
            .execute(&alice, &mut tx)
            .expect("grant governance custody permission");
    }
    let mut locks = iroha_core::state::GovernanceLocksForReferendum::default();
    locks.locks.insert(
        alice.clone(),
        iroha_core::state::GovernanceLockRecord {
            owner: alice.clone(),
            amount: Quantity::from(10_u64),
            slashed: Quantity::zero(),
            expiry_height: 100,
            direction: 0,
            duration_blocks: 100,
            custody: stored_custody.clone(),
        },
    );
    tx.world
        .governance_locks_mut()
        .insert(referendum_id.to_owned(), locks);
    iroha_data_model::isi::governance::SlashGovernanceLock {
        referendum_id: referendum_id.to_owned(),
        owner: alice.clone(),
        amount: Quantity::from(4_u64),
        reason: "stored custody regression".to_owned(),
    }
    .execute(&alice, &mut tx)
    .expect("slash must use the lock's stored custody");
    let lock_after_slash = tx
        .world
        .governance_locks()
        .get(referendum_id)
        .and_then(|locks| locks.locks.get(&alice))
        .expect("lock after slash");
    assert_eq!(lock_after_slash.amount, Quantity::from(6_u64));
    assert_eq!(lock_after_slash.slashed, Quantity::from(4_u64));
    assert_eq!(lock_after_slash.custody, stored_custody);
    assert_eq!(
        tx.world
            .asset(&old_escrow_asset_id)
            .expect("stored escrow asset after slash")
            .as_ref()
            .clone(),
        Quantity::from(6_u64)
    );
    assert_eq!(
        tx.world
            .asset(&old_receiver_asset_id)
            .expect("stored slash receiver asset after slash")
            .as_ref()
            .clone(),
        Quantity::from(9_u64)
    );
    assert_eq!(
        tx.world
            .asset(&live_escrow_asset_id)
            .expect("live escrow asset after slash")
            .as_ref()
            .clone(),
        Quantity::from(11_u64)
    );
    assert_eq!(
        tx.world
            .asset(&live_receiver_asset_id)
            .expect("live slash receiver asset after slash")
            .as_ref()
            .clone(),
        Quantity::from(13_u64)
    );
    let ledger_after_slash = tx
        .world
        .governance_slashes()
        .get(referendum_id)
        .and_then(|ledger| ledger.slashes.get(&alice))
        .expect("slash ledger entry");
    assert_eq!(ledger_after_slash.total_slashed, Quantity::from(4_u64));
    assert_eq!(ledger_after_slash.total_restituted, Quantity::zero());
    assert_eq!(
        ledger_after_slash.last_reason,
        GovernanceSlashReason::Manual
    );
    assert_eq!(ledger_after_slash.last_height, 1);
    iroha_data_model::isi::governance::RestituteGovernanceLock {
        referendum_id: referendum_id.to_owned(),
        owner: alice.clone(),
        amount: Quantity::from(4_u64),
        reason: "stored custody appeal".to_owned(),
    }
    .execute(&alice, &mut tx)
    .expect("restitution must use the lock's stored custody");
    let lock_after_restitution = tx
        .world
        .governance_locks()
        .get(referendum_id)
        .and_then(|locks| locks.locks.get(&alice))
        .expect("lock after restitution");
    assert_eq!(lock_after_restitution.amount, Quantity::from(10_u64));
    assert_eq!(lock_after_restitution.slashed, Quantity::zero());
    assert_eq!(lock_after_restitution.custody, stored_custody);
    assert_eq!(
        tx.world
            .asset(&old_escrow_asset_id)
            .expect("stored escrow asset after restitution")
            .as_ref()
            .clone(),
        Quantity::from(10_u64)
    );
    assert_eq!(
        tx.world
            .asset(&old_receiver_asset_id)
            .expect("stored slash receiver asset after restitution")
            .as_ref()
            .clone(),
        Quantity::from(5_u64)
    );
    assert_eq!(
        tx.world
            .asset(&live_escrow_asset_id)
            .expect("live escrow asset after restitution")
            .as_ref()
            .clone(),
        Quantity::from(11_u64)
    );
    assert_eq!(
        tx.world
            .asset(&live_receiver_asset_id)
            .expect("live slash receiver asset after restitution")
            .as_ref()
            .clone(),
        Quantity::from(13_u64)
    );
    let ledger_after_restitution = tx
        .world
        .governance_slashes()
        .get(referendum_id)
        .and_then(|ledger| ledger.slashes.get(&alice))
        .expect("slash ledger after restitution");
    assert_eq!(
        ledger_after_restitution.total_slashed,
        Quantity::from(4_u64)
    );
    assert_eq!(
        ledger_after_restitution.total_restituted,
        Quantity::from(4_u64)
    );
    assert_eq!(
        ledger_after_restitution.last_reason,
        GovernanceSlashReason::Restitution
    );
    assert_eq!(ledger_after_restitution.last_height, 1);
}

#[test]
fn signed_genesis_rejects_lane_manifest_replacement() {
    use iroha_core::{
        block::BlockValidationError,
        sumeragi::{startup::StartupError, test_chain::TestChainError},
    };

    let nexus = iroha_config::parameters::actual::Nexus::default();
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.lane_manifests = Some(governance_lane_manifests(&nexus, &fixture_validators()));
    let original = CertifiedTestChain::prepare(config).expect("signed configured lane policy");
    let original_policy = original.state.execution_policy_digest_v1().unwrap();
    let kura = Arc::clone(&original.kura);
    original.state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    assert_ne!(
        original.state.execution_policy_digest_v1().unwrap(),
        original_policy
    );
    let failure = CertifiedTestChain::from_prepared(original)
        .expect_err("a new lane manifest cannot reinterpret the originally signed genesis");
    assert!(
        matches!(&failure.error,
        TestChainError::Startup(StartupError::InvalidGenesis(error))
            if matches!(error.as_ref(), BlockValidationError::GenesisPolicyMismatch { .. })),
        "{:?}",
        failure.error
    );
    assert!(failure.state.view().block_hashes().is_empty());
    assert_eq!(kura.blocks_count(), 0);
}
