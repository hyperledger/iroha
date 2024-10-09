use eyre::Result;
use iroha::{
    client::QueryError,
    data_model::{prelude::*, query::error::QueryExecutionFail},
};
use iroha_test_network::*;
use iroha_test_samples::load_sample_wasm;

#[test]
fn live_query_is_dropped_after_smart_contract_end() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let client = network.client();

    let transaction = client.build_transaction(
        load_sample_wasm("query_assets_and_save_cursor"),
        Metadata::default(),
    );
    client.submit_transaction_blocking(&transaction)?;

    let metadata_value: JsonString = client.query_single(FindAccountMetadata::new(
        client.account.clone(),
        "cursor".parse().unwrap(),
    ))?;
    let asset_cursor = metadata_value.try_into_any()?;

    // here we are breaking the abstraction preventing us from using a cursor we pulled from the metadata
    let err = client
        .raw_continue_iterable_query(asset_cursor)
        .expect_err("Request with cursor from smart contract should fail");

    assert!(matches!(
        err,
        QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))
    ));

    Ok(())
}

#[test]
fn smart_contract_can_filter_queries() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let client = network.client();

    let transaction = client.build_transaction(
        load_sample_wasm("smart_contract_can_filter_queries"),
        Metadata::default(),
    );
    client.submit_transaction_blocking(&transaction)?;

    Ok(())
}
