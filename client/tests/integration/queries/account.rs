#![allow(clippy::restriction)]

use std::{collections::HashSet, str::FromStr as _};

use eyre::Result;
use iroha_client::client;
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn find_accounts_with_asset() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Registering new asset definition
    let definition_id =
        <AssetDefinition as Identifiable>::Id::from_str("test_coin#wonderland").expect("Valid");
    let asset_definition = AssetDefinition::quantity(definition_id.clone());
    test_client.submit_blocking(RegisterBox::new(asset_definition.clone()))?;

    // Checking results before all
    let received_asset_definition =
        test_client.request(client::asset::definition_by_id(definition_id.clone()))?;

    assert_eq!(received_asset_definition, asset_definition.clone().build());

    let accounts: [AccountId; 5] = [
        "alice@wonderland".parse().expect("Valid"),
        "mad_hatter@wonderland".parse().expect("Valid"),
        "cheshire_cat@wonderland".parse().expect("Valid"),
        "caterpillar@wonderland".parse().expect("Valid"),
        "white_rabbit@wonderland".parse().expect("Valid"),
    ];

    // Registering accounts
    let register_accounts = accounts
        .iter()
        .skip(1) // Alice has already been registered in genesis
        .cloned()
        .map(|account_id| RegisterBox::new(Account::new(account_id, [])).into())
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    let mint_asset = accounts
        .iter()
        .cloned()
        .map(|account_id| <Asset as Identifiable>::Id::new(definition_id.clone(), account_id))
        .map(|asset_id| MintBox::new(1_u32, asset_id).into())
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(mint_asset)?;

    let accounts = HashSet::from(accounts);

    // Checking results
    let received_asset_definition =
        test_client.request(client::asset::definition_by_id(definition_id.clone()))?;

    assert_eq!(received_asset_definition, asset_definition.build());

    let found_accounts = test_client.request(client::account::all_with_asset(definition_id))?;
    let found_ids = found_accounts
        .into_iter()
        .map(|account| account.id().clone())
        .collect::<HashSet<_>>();

    assert_eq!(found_ids, accounts);

    Ok(())
}
