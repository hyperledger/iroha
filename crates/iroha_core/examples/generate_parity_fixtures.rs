//! Generate canonical JSON fixtures for parity tests.
//!
//! Run with:
//!   cargo run -p `iroha_core` --features iroha-core-tests --example `generate_parity_fixtures`
//!
//! It writes fixtures under `crates/iroha_core/tests/fixtures/`.
use iroha_core::{
    state::{State, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig, TestChainError},
};
use iroha_data_model::{prelude::*, transaction::signed::TransactionSignatureError};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use std::{error::Error, fs, io::Write, path::PathBuf, sync::Arc, time::Duration};
const FIXTURE_TIME: Duration = Duration::from_millis(1);
fn start_fixture_chain(
    world: World,
    parallel_apply: bool,
    chain_id: &ChainId,
) -> Result<CertifiedTestChain, TestChainError> {
    let mut config = TestChainConfig::new(world, 0);
    config.chain_id = chain_id.clone();
    config.pipeline.parallel_apply = parallel_apply;
    CertifiedTestChain::start(config).map_err(|failure| failure.error)
}
fn fixture_network_id(chain_id: &ChainId) -> Result<NetworkId, TestChainError> {
    Ok(start_fixture_chain(World::new(), false, chain_id)?.network_id())
}
fn fixtures_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p
}
fn write_fixture(name: &str, content: &str) {
    let mut p = fixtures_dir();
    let _ = fs::create_dir_all(&p);
    p.push(format!("{name}.json"));
    let mut f = fs::File::create(&p).expect("create fixture");
    f.write_all(content.as_bytes()).expect("write fixture");
    println!("wrote {}", p.display());
}
fn events_json_filtered(events: &[iroha_data_model::events::prelude::EventBox]) -> String {
    let mut filtered: Vec<_> = events
        .iter()
        .filter(|e| {
            !matches!(
                e,
                iroha_data_model::events::prelude::EventBox::Time(_)
                    | iroha_data_model::events::prelude::EventBox::Pipeline(_)
                    | iroha_data_model::events::prelude::EventBox::PipelineBatch(_)
            )
        })
        .cloned()
        .collect();
    filtered.sort_by(|a, b| {
        let a_json = norito::json::to_json(a).expect("serialize event");
        let b_json = norito::json::to_json(b).expect("serialize event");
        a_json.cmp(&b_json)
    });
    norito::json::to_json_pretty(&filtered).unwrap()
}
fn write_parity_fixture(
    name: &str,
    sequential: &[iroha_data_model::events::prelude::EventBox],
    parallel: &[iroha_data_model::events::prelude::EventBox],
) {
    let sequential = events_json_filtered(sequential);
    let parallel = events_json_filtered(parallel);
    assert_eq!(
        sequential, parallel,
        "sequential and parallel event fixtures differ for {name}"
    );
    write_fixture(name, &sequential);
}
fn sign_fixture_transaction(
    mut builder: TransactionBuilder,
) -> Result<SignedTransaction, TransactionSignatureError> {
    builder.set_creation_time(FIXTURE_TIME);
    builder.try_sign(iroha_test_samples::ALICE_KEYPAIR.private_key())
}
fn run_block_and_events(
    parallel_apply: bool,
    chain_id: &ChainId,
    network_id: NetworkId,
    txs: Vec<SignedTransaction>,
) -> Result<(Vec<iroha_data_model::events::prelude::EventBox>, Arc<State>), Box<dyn Error>> {
    // Build a fresh world with default sandbox-like setup (62Fk4FPcMuLvW5QjDGNF2a4jAmjM).
    let alice_id = iroha_test_samples::ALICE_ID.clone();
    let bob_id = iroha_test_samples::BOB_ID.clone();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id.clone()).build(&alice_id);
    let ad: AssetDefinition = AssetDefinition::new(
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        "rose".to_owned(),
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let acc_a = Account::new(alice_id.clone()).build(&alice_id);
    let acc_b = Account::new(bob_id.clone()).build(&alice_id);
    // Seed initial balances: Alice 60, Bob 10
    let a_coin = AssetId::of(ad.id().clone(), alice_id.clone());
    let b_coin = AssetId::of(ad.id().clone(), bob_id.clone());
    let a0 = Asset::new(a_coin.clone(), Quantity::from(60_u64));
    let b0 = Asset::new(b_coin.clone(), Quantity::from(10_u64));
    let world = iroha_core::state::World::with_assets([domain], [acc_a, acc_b], [ad], [a0, b0], []);
    // Preserve the seeded World and scheduling policy through the genuine signed
    // genesis admission before submitting these network transactions at height 2.
    let mut chain = start_fixture_chain(world, parallel_apply, chain_id)?;
    assert_eq!(
        chain.network_id(),
        network_id,
        "transactions bind the actual original genesis"
    );
    chain.take_events().expect("drain original genesis events");
    chain.commit(txs);
    let committed = chain.committed(chain.height());
    let errors: Vec<_> = committed.block().failed_outputs().collect();
    assert!(
        errors.is_empty(),
        "parity fixture transactions failed: {errors:?}"
    );
    let events = chain
        .take_events()
        .expect("original native publication events");
    Ok((events, Arc::clone(chain.state())))
}
#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn Error>> {
    // 1) Mint/Burn/Transfer
    let chain_id = ChainId::from("chain");
    let network_id = fixture_network_id(&chain_id)?;
    let alice_id = iroha_test_samples::ALICE_ID.clone();
    let bob_id = iroha_test_samples::BOB_ID.clone();
    let rose: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let a_coin = AssetId::of(rose.clone(), alice_id.clone());
    let b_coin = AssetId::of(rose.clone(), bob_id.clone());
    let tx_mint = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Mint::asset_quantity(7_u32, a_coin.clone())]),
    )?;
    let tx_burn = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Burn::asset_quantity(3_u32, b_coin.clone())]),
    )?;
    let tx_xfer = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Transfer::asset_quantity(
            a_coin.clone(),
            5_u32,
            bob_id.clone(),
        )]),
    )?;
    let (events_seq, _state_seq) = run_block_and_events(
        false,
        &chain_id,
        network_id,
        vec![tx_mint.clone(), tx_burn.clone(), tx_xfer.clone()],
    )?;
    let (events_par, _state_par) =
        run_block_and_events(true, &chain_id, network_id, vec![tx_mint, tx_burn, tx_xfer])?;
    write_parity_fixture("mint_burn_transfer", &events_seq, &events_par);
    // 2) KV + NFT lifecycle
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let nft_id: NftId = "n0$wonderland".parse().unwrap();
    let tx_acc_set = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SetKeyValue::account(
            alice_id.clone(),
            "k1".parse().unwrap(),
            iroha_primitives::json::Json::new(1u32),
        )]),
    )?;
    let tx_dom_set = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SetKeyValue::domain(
            domain_id.clone(),
            "dk".parse().unwrap(),
            iroha_primitives::json::Json::new(3u32),
        )]),
    )?;
    let tx_nft_reg = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Register::nft(Nft::new(nft_id.clone(), Metadata::default()))]),
    )?;
    let tx_nft_set = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SetKeyValue::nft(
            nft_id.clone(),
            "nk".parse().unwrap(),
            iroha_primitives::json::Json::new("v"),
        )]),
    )?;
    let tx_nft_xfer = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Transfer::nft(
            alice_id.clone(),
            nft_id.clone(),
            bob_id.clone(),
        )]),
    )?;
    let tx_nft_rm = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([RemoveKeyValue::nft(nft_id.clone(), "nk".parse().unwrap())]),
    )?;
    let tx_nft_unreg = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Unregister::nft(nft_id.clone())]),
    )?;
    let tx_acc_rm = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([RemoveKeyValue::account(
            alice_id.clone(),
            "k1".parse().unwrap(),
        )]),
    )?;
    let tx_dom_rm = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([RemoveKeyValue::domain(
            domain_id.clone(),
            "dk".parse().unwrap(),
        )]),
    )?;
    let txs = vec![
        tx_acc_set,
        tx_dom_set,
        tx_nft_reg,
        tx_nft_set,
        tx_nft_xfer,
        tx_nft_rm,
        tx_nft_unreg,
        tx_acc_rm,
        tx_dom_rm,
    ];
    let (events_seq, _) = run_block_and_events(false, &chain_id, network_id, txs.clone())?;
    let (events_par, _) = run_block_and_events(true, &chain_id, network_id, txs)?;
    write_parity_fixture("kv_and_nft_lifecycle", &events_seq, &events_par);
    // 3) Asset definition KV set/remove
    let ad: AssetDefinitionId = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    );
    let tx_set = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([SetKeyValue::asset_definition(
            ad.clone(),
            "spec".parse().unwrap(),
            iroha_primitives::json::Json::new("golden"),
        )]),
    )?;
    let tx_rm = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([RemoveKeyValue::asset_definition(
            ad.clone(),
            "spec".parse().unwrap(),
        )]),
    )?;
    let (events_seq, _) = run_block_and_events(
        false,
        &chain_id,
        network_id,
        vec![tx_set.clone(), tx_rm.clone()],
    )?;
    let (events_par, _) = run_block_and_events(true, &chain_id, network_id, vec![tx_set, tx_rm])?;
    write_parity_fixture("asset_definition_kv", &events_seq, &events_par);
    // 4) Owner transfers (domain + asset definition)
    let tx_dom_xfer = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Transfer::domain(
            alice_id.clone(),
            domain_id.clone(),
            bob_id.clone(),
        )]),
    )?;
    let tx_ad_xfer = sign_fixture_transaction(
        TransactionBuilder::new(
            network_id,
            alice_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Transfer::asset_definition(
            alice_id.clone(),
            ad.clone(),
            bob_id.clone(),
        )]),
    )?;
    let (events_seq, _state_seq) = run_block_and_events(
        false,
        &chain_id,
        network_id,
        vec![tx_dom_xfer.clone(), tx_ad_xfer.clone()],
    )?;
    let (events_par, _state_par) =
        run_block_and_events(true, &chain_id, network_id, vec![tx_dom_xfer, tx_ad_xfer])?;
    write_parity_fixture("owner_transfer_domain_asset_def", &events_seq, &events_par);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::state::{StateReadOnly, WorldReadOnly};
    use mv::storage::StorageReadOnly;
    #[test]
    fn parity_fixture_transaction_uses_checked_signing_and_verifies() {
        let alice_id = iroha_test_samples::ALICE_ID.clone();
        let tx = sign_fixture_transaction(
            TransactionBuilder::new(
                fixture_network_id(&ChainId::from("chain")).expect("actual fixture genesis"),
                alice_id,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "checked parity fixture".to_owned())]),
        )
        .expect("parity fixture transaction should sign");
        tx.verify_signature()
            .expect("checked parity fixture transaction signature should verify");
    }
    #[test]
    fn parity_fixture_block_uses_checked_signing() {
        let alice_id = iroha_test_samples::ALICE_ID.clone();
        let chain_id = ChainId::from("chain");
        let network_id = fixture_network_id(&chain_id).expect("actual fixture genesis");
        let tx = sign_fixture_transaction(
            TransactionBuilder::new(
                network_id,
                alice_id,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(Level::INFO, "checked parity block".to_owned())]),
        )
        .expect("parity fixture transaction should sign");
        let (_events, state) = run_block_and_events(false, &chain_id, network_id, vec![tx])
            .expect("parity fixture block should sign");
        let view = state.view();
        let block = view
            .latest_block()
            .expect("original fixture tip can be read")
            .expect("native successor exists");
        assert_eq!(block.header().height().get(), 2);
        assert_eq!(
            NetworkId::from_genesis_hash(
                block.header().prev_block_hash().expect("original genesis")
            ),
            network_id,
        );
        let genesis = view
            .block_by_height(std::num::NonZeroUsize::new(1).expect("positive genesis height"))
            .expect("original fixture genesis can be read")
            .expect("original signed genesis exists");
        assert_eq!(block.header().prev_block_hash(), Some(genesis.hash()));
        assert!(block.header().creation_time() > genesis.header().creation_time());
        assert!(block.header().creation_time() > FIXTURE_TIME);
        assert!(block.commit_certificate().is_some());
        assert_eq!(block.output_results().count(), 1);
        assert!(block.failed_outputs().next().is_none());
    }
    #[test]
    fn parity_fixture_native_genesis_preserves_events_and_balances_between_modes() {
        let chain_id = ChainId::from("chain");
        let network_id = fixture_network_id(&chain_id).expect("actual fixture genesis");
        let alice_id = iroha_test_samples::ALICE_ID.clone();
        let bob_id = iroha_test_samples::BOB_ID.clone();
        let rose = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let a_coin = AssetId::of(rose.clone(), alice_id.clone());
        let b_coin = AssetId::of(rose.clone(), bob_id.clone());
        let txs = [
            InstructionBox::from(Mint::asset_quantity(7_u32, a_coin.clone())),
            InstructionBox::from(Burn::asset_quantity(3_u32, b_coin.clone())),
            InstructionBox::from(Transfer::asset_quantity(a_coin.clone(), 5_u32, bob_id)),
        ]
        .into_iter()
        .map(|instruction| {
            sign_fixture_transaction(
                TransactionBuilder::new(
                    network_id,
                    alice_id.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_instructions([instruction]),
            )
            .expect("checked fixture transaction")
        })
        .collect::<Vec<_>>();
        let (events_seq, state_seq) =
            run_block_and_events(false, &chain_id, network_id, txs.clone())
                .expect("certified sequential fixture");
        let (events_par, state_par) = run_block_and_events(true, &chain_id, network_id, txs)
            .expect("certified parallel fixture");
        assert!(!events_seq.is_empty());
        assert_eq!(
            events_json_filtered(&events_seq),
            events_json_filtered(&events_par)
        );
        for state in [&state_seq, &state_par] {
            let view = state.view();
            assert_eq!(view.height(), 2);
            for (asset, expected) in [(&a_coin, 62_u64), (&b_coin, 12_u64)] {
                assert_eq!(
                    view.world()
                        .assets()
                        .get(asset)
                        .expect("seeded asset")
                        .clone()
                        .into_inner(),
                    Quantity::from(expected),
                );
            }
            assert_eq!(
                view.world()
                    .asset_definitions()
                    .get(&rose)
                    .expect("seeded definition")
                    .total_quantity,
                Quantity::from(74_u64),
            );
        }
    }
}
