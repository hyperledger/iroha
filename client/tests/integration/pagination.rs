#![allow(clippy::restriction)]

use eyre::Result;
use iroha_client::client::asset;
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_690).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let register: Vec<InstructionBox> = ('a'..='z') // This is a subtle mistake, I'm glad we can lint it now.
        .map(|c| c.to_string())
        .map(|name| (name + "#wonderland").parse().expect("Valid"))
        .map(|asset_definition_id| {
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id)).into()
        })
        .collect();
    client.submit_all_blocking(register)?;

    let vec = client
        .request_with_pagination(asset::all_definitions(), Pagination::new(Some(5), Some(5)))?
        .only_output();
    assert_eq!(vec.len(), 5);
    Ok(())
}
