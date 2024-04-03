use eyre::Result;
use iroha_client::{
    client::{asset, Client, QueryResult},
    data_model::{asset::AssetDefinition, prelude::*, query::Pagination},
};
use nonzero_ext::nonzero;
use test_network::*;

#[test]
fn limits_should_work() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_690).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    register_assets(&client)?;

    let vec = &client
        .build_query(asset::all_definitions())
        .with_pagination(Pagination {
            limit: Some(nonzero!(5_u32)),
            start: Some(nonzero!(5_u64)),
        })
        .execute()?
        .collect::<QueryResult<Vec<_>>>()?;
    assert_eq!(vec.len(), 5);
    Ok(())
}

#[test]
fn fetch_size_should_work() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_120).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    register_assets(&client)?;

    let iter = client
        .build_query(asset::all_definitions())
        .with_pagination(Pagination {
            limit: Some(nonzero!(20_u32)),
            start: None,
        })
        .with_fetch_size(FetchSize::new(Some(nonzero!(12_u32))))
        .execute()?;
    assert_eq!(iter.batch_len(), 12);
    Ok(())
}

fn register_assets(client: &Client) -> Result<()> {
    let register: Vec<InstructionBox> = ('a'..='z')
        .map(|c| c.to_string())
        .map(|name| (name + "#wonderland").parse().expect("Valid"))
        .map(|asset_definition_id| {
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id)).into()
        })
        .collect();
    let _ = client.submit_all_blocking(register)?;
    Ok(())
}
