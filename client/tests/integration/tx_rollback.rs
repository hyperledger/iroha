#![allow(clippy::restriction)]

use std::str::FromStr as _;

use eyre::Result;
use iroha_client::client;
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn client_sends_transaction_with_invalid_instruction_should_not_see_any_changes() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_720).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    //When
    let account_id = AccountId::from_str("alice@wonderland")?;
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland")?;
    let wrong_asset_definition_id = AssetDefinitionId::from_str("ksor#wonderland")?;
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id));
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            wrong_asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    let _ = client.submit_all_blocking(vec![create_asset.into(), mint_asset.into()]);

    //Then
    let request = client::asset::by_account_id(account_id);
    let query_result = client.request(request)?;
    assert!(query_result
        .iter()
        .all(|asset| asset.id().definition_id != wrong_asset_definition_id));
    let definition_query_result = client.request(client::asset::all_definitions())?;
    assert!(definition_query_result
        .iter()
        .all(|asset| *asset.id() != wrong_asset_definition_id));
    Ok(())
}
