use eyre::Result;
use iroha::{
    client::{asset, Client},
    data_model::{asset::AssetDefinition, prelude::*},
};
use nonzero_ext::nonzero;
use test_network::*;

#[test]
fn limits_should_work() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_690).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    register_assets(&client)?;

    let vec = client
        .iter_query(asset::all_definitions())
        .with_pagination(Pagination {
            limit: Some(nonzero!(7_u32)),
            start: Some(nonzero!(1_u64)),
        })
        .execute_all()?;
    assert_eq!(vec.len(), 7);
    Ok(())
}

#[test]
fn fetch_size_should_work() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_120).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    register_assets(&client)?;

    let iter = client
        .iter_query(asset::all_definitions())
        .with_pagination(Pagination {
            limit: Some(nonzero!(7_u32)),
            start: Some(nonzero!(1_u64)),
        })
        .with_fetch_size(FetchSize::new(Some(nonzero!(3_u32))))
        .execute()?;
    assert_eq!(iter.remaining_in_current_batch(), 3);
    Ok(())
}

fn register_assets(client: &Client) -> Result<()> {
    // FIXME transaction is rejected for more than a certain number of instructions
    let register: Vec<_> = ('a'..='j')
        .map(|c| c.to_string())
        .map(|name| (name + "#wonderland").parse().expect("Valid"))
        .map(|asset_definition_id| {
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id))
        })
        .collect();
    let _ = client.submit_all_blocking(register)?;
    Ok(())
}
