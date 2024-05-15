use std::thread;

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::parameters::actual::Root as Config;
use test_network::*;
use test_samples::gen_account_in;

// Note the test is marked as `unstable`,  not the network.
#[ignore = "ignore, more in #2851"]
#[test]
fn unstable_network_stable_after_add_and_after_remove_peer() -> Result<()> {
    // Given a network
    let (rt, network, genesis_client, pipeline_time, account_id, asset_definition_id) = init()?;
    wait_for_genesis_committed(&network.clients(), 0);

    // When assets are minted
    mint(
        &asset_definition_id,
        &account_id,
        &genesis_client,
        pipeline_time,
        numeric!(100),
    )?;
    // and a new peer is registered
    let (peer, peer_client) = rt.block_on(network.add_peer());
    // Then the new peer should already have the mint result.
    check_assets(
        &peer_client,
        &account_id,
        &asset_definition_id,
        numeric!(100),
    );
    // Also, when a peer is unregistered
    let remove_peer = Unregister::peer(peer.id.clone());
    genesis_client.submit(remove_peer)?;
    thread::sleep(pipeline_time * 2);
    // We can mint without error.
    mint(
        &asset_definition_id,
        &account_id,
        &genesis_client,
        pipeline_time,
        numeric!(200),
    )?;
    // Assets are increased on the main network.
    check_assets(
        &genesis_client,
        &account_id,
        &asset_definition_id,
        numeric!(300),
    );
    // But not on the unregistered peer's network.
    check_assets(
        &peer_client,
        &account_id,
        &asset_definition_id,
        numeric!(100),
    );
    Ok(())
}

fn check_assets(
    iroha_client: &client::Client,
    account_id: &AccountId,
    asset_definition_id: &AssetDefinitionId,
    quantity: Numeric,
) {
    iroha_client
        .poll_request_with_period(
            client::asset::by_account_id(account_id.clone()),
            Config::block_sync_gossip_time(),
            15,
            |result| {
                let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

                assets.iter().any(|asset| {
                    asset.id().definition_id == *asset_definition_id
                        && *asset.value() == AssetValue::Numeric(quantity)
                })
            },
        )
        .expect("Test case failure");
}

fn mint(
    asset_definition_id: &AssetDefinitionId,
    account_id: &AccountId,
    client: &client::Client,
    pipeline_time: std::time::Duration,
    quantity: Numeric,
) -> Result<Numeric, color_eyre::Report> {
    let mint_asset = Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    client.submit(mint_asset)?;
    thread::sleep(pipeline_time * 5);
    iroha_logger::info!("Mint");
    Ok(quantity)
}

fn init() -> Result<(
    tokio::runtime::Runtime,
    test_network::Network,
    iroha_client::client::Client,
    std::time::Duration,
    AccountId,
    AssetDefinitionId,
)> {
    let (rt, network, client) = Network::start_test_with_runtime(4, Some(10_925));
    let pipeline_time = Config::pipeline_time();
    iroha_logger::info!("Started");
    let parameters = ParametersBuilder::new()
        .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
        .into_set_parameters();
    let create_domain = Register::domain(Domain::new("domain".parse()?));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse()?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let instructions = parameters.into_iter().chain([
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ]);
    client.submit_all_blocking(instructions)?;
    iroha_logger::info!("Init");
    Ok((
        rt,
        network,
        client,
        pipeline_time,
        account_id,
        asset_definition_id,
    ))
}
