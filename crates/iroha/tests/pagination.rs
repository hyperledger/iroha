use eyre::Result;
use iroha::{
    client::{asset, Client},
    data_model::{asset::AssetDefinition, prelude::*},
};
use iroha_test_network::*;
use nonzero_ext::nonzero;

#[test]
fn limits_should_work() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let client = network.client();

    register_assets(&client)?;

    let vec = client
        .query(asset::all_definitions())
        .with_pagination(Pagination {
            limit: Some(nonzero!(7_u64)),
            offset: 1,
        })
        .execute_all()?;
    assert_eq!(vec.len(), 7);
    Ok(())
}

#[test]
fn reported_length_should_be_accurate() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let client = network.client();

    register_assets(&client)?;

    let mut iter = client
        .query(asset::all_definitions())
        .with_pagination(Pagination {
            limit: Some(nonzero!(7_u64)),
            offset: 1,
        })
        .with_fetch_size(FetchSize::new(Some(nonzero!(3_u64))))
        .execute()?;

    assert_eq!(iter.len(), 7);

    for _ in 0..4 {
        iter.next().unwrap().unwrap();
    }

    assert_eq!(iter.len(), 3);

    Ok(())
}

#[test]
fn fetch_size_should_work() -> Result<()> {
    // use the lower-level API to inspect the batch size
    use iroha::data_model::query::{
        builder::QueryExecutor as _,
        parameters::{FetchSize, QueryParams, Sorting},
        QueryWithFilter, QueryWithParams,
    };

    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let client = network.client();

    register_assets(&client)?;

    let query = QueryWithParams::new(
        QueryWithFilter::new(asset::all_definitions(), CompoundPredicate::PASS).into(),
        QueryParams::new(
            Pagination {
                limit: Some(nonzero!(7_u64)),
                offset: 1,
            },
            Sorting::default(),
            FetchSize::new(Some(nonzero!(3_u64))),
        ),
    );
    let (first_batch, remaining_items, _continue_cursor) = client.start_query(query)?;

    assert_eq!(first_batch.len(), 3);
    assert_eq!(remaining_items, 4);

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
