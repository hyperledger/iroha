//! Differential test for the `parallel_apply` pipeline knob.

//! Ensures that enabling the skeleton parallel-apply path yields identical
//! outcomes to the sequential apply path.
use crate::synthetic_state_snapshots as snapshots;
use iroha_core::state::WorldReadOnly;
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use mv::storage::StorageReadOnly;
use snapshots::assert_events;
use std::{collections::BTreeSet, sync::Arc, time::Duration};
// Use a fixed creation time so event fixtures do not depend on wall clock.
const FIXTURE_TIME: Duration = Duration::from_millis(1);
fn test_network_id(_label: &[u8]) -> NetworkId {
    start_chain(iroha_core::state::World::new(), false).network_id()
}
fn start_chain(
    world: iroha_core::state::World,
    parallel_apply: bool,
) -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.chain_id = ChainId::from("chain");
    config.pipeline.parallel_apply = parallel_apply;
    iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("actual native parity genesis")
}
fn tx_builder(network_id: &NetworkId, authority: &AccountId) -> TransactionBuilder {
    let mut builder = TransactionBuilder::new(
        *network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(FIXTURE_TIME);
    builder
}
#[allow(clippy::too_many_lines)]
#[test]
fn parallel_apply_matches_sequential_for_log_and_mint() {
    // Build a small world: one domain, two accounts, one numeric asset def, zeroed assets
    let _network_id = test_network_id(b"parallel-apply-log-mint");
    let alice_id = (*iroha_test_samples::ALICE_ID).clone();
    let bob_id = (*iroha_test_samples::BOB_ID).clone();
    let build_world = || {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain: Domain = Domain::new(domain_id.clone()).build(&alice_id);
        let ad: AssetDefinition = AssetDefinition::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "coin".parse().unwrap(),
            ),
            "coin".to_owned(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&alice_id);
        let acc_a = Account::new(alice_id.clone()).build(&alice_id);
        let acc_b = Account::new(bob_id.clone()).build(&alice_id);
        let a_coin = AssetId::of(ad.id().clone(), alice_id.clone());
        let b_coin = AssetId::of(ad.id().clone(), bob_id.clone());
        let a0 = Asset::new(a_coin, Quantity::from(0_u64));
        let b0 = Asset::new(b_coin, Quantity::from(0_u64));
        iroha_core::state::World::with_assets([domain], [acc_a, acc_b], [ad], [a0, b0], [])
    };
    let mut sequential = start_chain(build_world(), false);
    let mut parallel = start_chain(build_world(), true);
    assert_eq!(
        sequential.network_id(),
        parallel.network_id(),
        "local scheduling cannot alter genesis policy"
    );
    let network_id = sequential.network_id();
    // Two independent transactions: a mint and a log. Mint will take the standard path,
    // log is handled by detached path; overall results should match sequential mode.
    let tx1 = tx_builder(&network_id, &alice_id)
        .with_instructions([Mint::asset_quantity(
            10_u32,
            AssetId::of(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "coin".parse().unwrap(),
                ),
                alice_id.clone(),
            ),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx2 = tx_builder(&network_id, &bob_id)
        .with_instructions([Log::new(Level::INFO, "t2".to_string())])
        .sign(iroha_test_samples::BOB_KEYPAIR.private_key());
    sequential.commit(vec![tx1.clone(), tx2.clone()]);
    let vb_seq = sequential.committed(sequential.height());
    parallel.commit(vec![tx1, tx2]);
    let vb_par = parallel.committed(parallel.height());
    let state_seq = sequential.state();
    let state_par = parallel.state();
    // Compare results order and kinds
    let seq_ok: Vec<_> = vb_seq
        .block()
        .output_results()
        .map(|r| r.as_ref().is_ok())
        .collect();
    let par_ok: Vec<_> = vb_par
        .block()
        .output_results()
        .map(|r| r.as_ref().is_ok())
        .collect();
    assert_eq!(seq_ok, par_ok, "approval/rejection sequence must match");
    // Compare that final state roots are identical
    let root_seq = vb_seq.block().header().merkle_root();
    let root_par = vb_par.block().header().merkle_root();
    assert_eq!(root_seq, root_par, "merkle roots must match");
    // Compare resulting asset balances (Alice's coin should be 10 in both states)
    let a_coin: AssetId = AssetId::of(
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "coin".parse().unwrap(),
        ),
        alice_id.clone(),
    );
    let view_seq = state_seq.view();
    let view_par = state_par.view();
    let bal_seq = view_seq
        .world()
        .assets()
        .get(&a_coin)
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    let bal_par = view_par
        .world()
        .assets()
        .get(&a_coin)
        .map_or_else(Quantity::zero, |v| v.clone().into_inner());
    assert_eq!(bal_seq, bal_par, "final balances must match");
    assert_eq!(bal_seq, Quantity::from(10_u64), "the mint must be applied");
}
fn run_block_and_events(
    parallel_apply: bool,
    network_id: &NetworkId,
    txs: Vec<SignedTransaction>,
    bootstrap_accounts: Vec<AccountId>,
) -> (
    Vec<iroha_data_model::events::prelude::EventBox>,
    Arc<iroha_core::state::State>,
) {
    // Build a fresh world aligned with authority accounts present in `txs`,
    // plus any additional bootstrap accounts referenced by the test.
    //
    // This keeps the initial world stable across apply modes and avoids relying
    // on implicit admission side effects (which can be sensitive to scheduling).
    let fixture_owner = txs
        .first()
        .expect("fixture block must contain at least one transaction")
        .authority()
        .clone();
    let mut accounts: BTreeSet<AccountId> = bootstrap_accounts.into_iter().collect();
    for tx in &txs {
        accounts.insert(tx.authority().clone());
    }
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id.clone()).build(&fixture_owner);
    let ad_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let ad: AssetDefinition = AssetDefinition::new(
        ad_id.clone(),
        "rose".to_owned(),
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&fixture_owner);
    let mut world_accounts: Vec<Account> = Vec::new();
    let mut assets: Vec<Asset> = Vec::new();
    for acc_id in &accounts {
        world_accounts.push(Account::new(acc_id.clone()).build(&fixture_owner));
        let asset_id = AssetId::new(ad.id().clone(), acc_id.clone());
        // The first input transaction authority is the canonical fixture owner;
        // block construction may reorder transactions by call hash later.
        let balance: u64 = if acc_id == &fixture_owner { 60 } else { 10 };
        assets.push(Asset::new(asset_id, Quantity::from(balance)));
    }
    let world = iroha_core::state::World::with_assets([domain], world_accounts, [ad], assets, []);
    let mut chain = start_chain(world, parallel_apply);
    assert_eq!(
        chain.network_id(),
        *network_id,
        "transactions bind the actual original genesis"
    );
    chain.take_events().unwrap();
    chain.commit(txs);
    let committed = chain.committed(chain.height());
    let errors = committed.block().failed_outputs().collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "parity fixture transactions failed: {errors:?}"
    );
    let events = chain
        .take_events()
        .expect("original native publication events");
    (events, Arc::clone(chain.state()))
}
// event_list_json moved to snapshot helpers; removed.
#[test]
fn events_snapshot_mint_burn_transfer_match_between_modes() {
    let network_id = test_network_id(b"parallel-apply-asset-events");
    let alice_id = (*iroha_test_samples::ALICE_ID).clone();
    let bob_id = (*iroha_test_samples::BOB_ID).clone();
    let rose: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let a_coin = AssetId::of(rose.clone(), alice_id.clone());
    let b_coin = AssetId::of(rose.clone(), bob_id.clone());
    // Build three transactions: mint to Alice, burn from Bob, transfer Alice->Bob
    let tx_mint = tx_builder(&network_id, &alice_id)
        .with_instructions([Mint::asset_quantity(7_u32, a_coin.clone())])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_burn = tx_builder(&network_id, &alice_id)
        .with_instructions([Burn::asset_quantity(3_u32, b_coin.clone())])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_xfer = tx_builder(&network_id, &alice_id)
        .with_instructions([Transfer::asset_quantity(
            a_coin.clone(),
            5_u32,
            bob_id.clone(),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    // Sequential
    let (events_seq, state_seq) = run_block_and_events(
        false,
        &network_id,
        vec![tx_mint.clone(), tx_burn.clone(), tx_xfer.clone()],
        vec![alice_id.clone(), bob_id.clone()],
    );
    // Parallel-detached
    let (events_par, state_par) = run_block_and_events(
        true,
        &network_id,
        vec![tx_mint, tx_burn, tx_xfer],
        vec![alice_id.clone(), bob_id.clone()],
    );
    // Fixture-backed parity snapshots
    assert_events("mint_burn_transfer", &events_seq);
    assert_events("mint_burn_transfer", &events_par);
    // Sanity: balances equal (Alice had 60 +7 -5 = 62; Bob 10 -3 +5 = 12)
    let bal = |state: &iroha_core::state::State, id: &AssetId| {
        state
            .view()
            .world()
            .assets()
            .get(id)
            .map_or_else(Quantity::zero, |v| v.clone().into_inner())
    };
    assert_eq!(bal(&state_seq, &a_coin), bal(&state_par, &a_coin));
    assert_eq!(bal(&state_seq, &b_coin), bal(&state_par, &b_coin));
    assert_eq!(bal(&state_seq, &a_coin), Quantity::from(62_u64));
    assert_eq!(bal(&state_seq, &b_coin), Quantity::from(12_u64));
    for state in [&state_seq, &state_par] {
        let view = state.view();
        assert_eq!(
            view.world()
                .asset_definitions()
                .get(&rose)
                .unwrap()
                .total_quantity,
            Quantity::from(74_u64),
            "canonical supply includes the initial 70 units, then mint 7 and burn 3"
        );
    }
}
#[test]
fn events_snapshot_kv_and_nft_match_between_modes() {
    use iroha_data_model::prelude::*;
    let network_id = test_network_id(b"parallel-apply-kv-nft-events");
    let alice_id = (*iroha_test_samples::ALICE_ID).clone();
    let bob_id = (*iroha_test_samples::BOB_ID).clone();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let nft_id: NftId = "n0$wonderland".parse().unwrap();
    // Build transactions exercising account/domain kv and full NFT lifecycle
    let tx_acc_set = tx_builder(&network_id, &alice_id)
        .with_instructions([SetKeyValue::account(
            alice_id.clone(),
            "k1".parse().unwrap(),
            iroha_primitives::json::Json::new(1u32),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_dom_set = tx_builder(&network_id, &alice_id)
        .with_instructions([SetKeyValue::domain(
            domain_id.clone(),
            "dk".parse().unwrap(),
            iroha_primitives::json::Json::new(3u32),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_nft_reg = tx_builder(&network_id, &alice_id)
        .with_instructions([Register::nft(Nft::new(nft_id.clone(), Metadata::default()))])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_nft_set = tx_builder(&network_id, &alice_id)
        .with_instructions([SetKeyValue::nft(
            nft_id.clone(),
            "nk".parse().unwrap(),
            iroha_primitives::json::Json::new("v"),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_nft_xfer = tx_builder(&network_id, &alice_id)
        .with_instructions([Transfer::nft(
            alice_id.clone(),
            nft_id.clone(),
            bob_id.clone(),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_nft_rm = tx_builder(&network_id, &alice_id)
        .with_instructions([RemoveKeyValue::nft(nft_id.clone(), "nk".parse().unwrap())])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_nft_unreg = tx_builder(&network_id, &alice_id)
        .with_instructions([Unregister::nft(nft_id.clone())])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_acc_rm = tx_builder(&network_id, &alice_id)
        .with_instructions([RemoveKeyValue::account(
            alice_id.clone(),
            "k1".parse().unwrap(),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_dom_rm = tx_builder(&network_id, &alice_id)
        .with_instructions([RemoveKeyValue::domain(
            domain_id.clone(),
            "dk".parse().unwrap(),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let txs = vec![
        tx_acc_set.clone(),
        tx_dom_set.clone(),
        tx_nft_reg.clone(),
        tx_nft_set.clone(),
        tx_nft_xfer.clone(),
        tx_nft_rm.clone(),
        tx_nft_unreg.clone(),
        tx_acc_rm.clone(),
        tx_dom_rm.clone(),
    ];
    // Sequential
    let (events_seq, _state_seq) = run_block_and_events(
        false,
        &network_id,
        txs.clone(),
        vec![alice_id.clone(), bob_id.clone()],
    );
    // Parallel-detached
    let (events_par, _state_par) = run_block_and_events(
        true,
        &network_id,
        txs,
        vec![alice_id.clone(), bob_id.clone()],
    );
    assert_events("kv_and_nft_lifecycle", &events_seq);
    assert_events("kv_and_nft_lifecycle", &events_par);
}
#[test]
fn events_snapshot_asset_definition_kv_match_between_modes() {
    let network_id = test_network_id(b"parallel-apply-asset-definition-kv");
    let alice_id = (*iroha_test_samples::ALICE_ID).clone();
    let ad: AssetDefinitionId = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    );
    let tx_set = tx_builder(&network_id, &alice_id)
        .with_instructions([SetKeyValue::asset_definition(
            ad.clone(),
            "spec".parse().unwrap(),
            iroha_primitives::json::Json::new("golden"),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_rm = tx_builder(&network_id, &alice_id)
        .with_instructions([RemoveKeyValue::asset_definition(
            ad.clone(),
            "spec".parse().unwrap(),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let (events_seq, _) = run_block_and_events(
        false,
        &network_id,
        vec![tx_set.clone(), tx_rm.clone()],
        vec![alice_id.clone()],
    );
    let (events_par, _) = run_block_and_events(
        true,
        &network_id,
        vec![tx_set, tx_rm],
        vec![alice_id.clone()],
    );
    assert_events("asset_definition_kv", &events_seq);
    assert_events("asset_definition_kv", &events_par);
}
#[test]
fn owner_transfer_domain_and_asset_def_parity() {
    let network_id = test_network_id(b"parallel-apply-owner-transfer");
    let alice_id = (*iroha_test_samples::ALICE_ID).clone();
    let bob_id = (*iroha_test_samples::BOB_ID).clone();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let ad: AssetDefinitionId = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    );
    let tx_dom_xfer = tx_builder(&network_id, &alice_id)
        .with_instructions([Transfer::domain(
            alice_id.clone(),
            domain_id.clone(),
            bob_id.clone(),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    let tx_ad_xfer = tx_builder(&network_id, &alice_id)
        .with_instructions([Transfer::asset_definition(
            alice_id.clone(),
            ad.clone(),
            bob_id.clone(),
        )])
        .sign(iroha_test_samples::ALICE_KEYPAIR.private_key());
    // Sequential
    let (events_seq, state_seq) = run_block_and_events(
        false,
        &network_id,
        vec![tx_dom_xfer.clone(), tx_ad_xfer.clone()],
        vec![alice_id.clone(), bob_id.clone()],
    );
    // Parallel-detached
    let (events_par, state_par) = run_block_and_events(
        true,
        &network_id,
        vec![tx_dom_xfer, tx_ad_xfer],
        vec![alice_id.clone(), bob_id.clone()],
    );
    // Events parity via fixture snapshots
    assert_events("owner_transfer_domain_asset_def", &events_seq);
    assert_events("owner_transfer_domain_asset_def", &events_par);
    // State parity: owners equal
    let dom_owner_seq = state_seq
        .view()
        .world()
        .domain(&domain_id)
        .expect("domain exists")
        .owned_by()
        .clone();
    let dom_owner_par = state_par
        .view()
        .world()
        .domain(&domain_id)
        .expect("domain exists")
        .owned_by()
        .clone();
    assert_eq!(dom_owner_seq, dom_owner_par, "domain owners must match");
    assert_eq!(
        dom_owner_seq, bob_id,
        "domain ownership must transfer to Bob"
    );
    let ad_owner_seq = state_seq
        .view()
        .world()
        .asset_definition(&ad)
        .expect("asset def exists")
        .owned_by()
        .clone();
    let ad_owner_par = state_par
        .view()
        .world()
        .asset_definition(&ad)
        .expect("asset def exists")
        .owned_by()
        .clone();
    assert_eq!(
        ad_owner_seq, ad_owner_par,
        "asset definition owners must match"
    );
    assert_eq!(
        ad_owner_seq, bob_id,
        "asset definition ownership must transfer to Bob"
    );
}
