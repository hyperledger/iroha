use std::num::{NonZeroU32, NonZeroU64};

use eyre::Result;
use iroha_client::{
    client::{asset, QueryResult},
    data_model::{asset::AssetDefinition, prelude::*, query::Pagination},
};
use test_network::*;

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_690).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let register: Vec<InstructionExpr> = ('a'..='z') // This is a subtle mistake, I'm glad we can lint it now.
        .map(|c| c.to_string())
        .map(|name| (name + "#wonderland").parse().expect("Valid"))
        .map(|asset_definition_id| {
            RegisterExpr::new(AssetDefinition::quantity(asset_definition_id)).into()
        })
        .collect();
    client.submit_all_blocking(register)?;

    let vec = client
        .request_with_pagination(
            asset::all_definitions(),
            Pagination {
                limit: NonZeroU32::new(5),
                start: NonZeroU64::new(5),
            },
        )?
        .collect::<QueryResult<Vec<_>>>()?;
    assert_eq!(vec.len(), 5);
    Ok(())
}
