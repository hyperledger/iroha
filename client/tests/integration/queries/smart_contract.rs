use std::str::FromStr as _;

use eyre::Result;
use iroha::{
    client::QueryError,
    data_model::{prelude::*, query::error::QueryExecutionFail},
};
use test_network::*;

#[test]
fn live_query_is_dropped_after_smart_contract_end() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_140).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let wasm = iroha_wasm_builder::Builder::new("../wasm_samples/query_assets_and_save_cursor")
        .show_output()
        .build()?
        .optimize()?
        .into_bytes()?;

    let transaction =
        client.build_transaction(WasmSmartContract::from_compiled(wasm), Metadata::default());
    client.submit_transaction_blocking(&transaction)?;

    let metadata_value: JsonString = client.query_single(FindAccountMetadata::new(
        client.account.clone(),
        Name::from_str("cursor").unwrap(),
    ))?;
    let asset_cursor = metadata_value.try_into_any()?;

    // here we are breaking the abstraction preventing us from using a cursor we pulled from the metadata
    let err = client
        .raw_continue_iterable_query(asset_cursor)
        .expect_err("Request with cursor from smart contract should fail");

    assert!(matches!(
        err,
        QueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::UnknownCursor
        ))
    ));

    Ok(())
}

#[test]
fn smart_contract_can_filter_queries() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_260).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let wasm =
        iroha_wasm_builder::Builder::new("../wasm_samples/smart_contract_can_filter_queries")
            .show_output()
            .build()?
            .optimize()?
            .into_bytes()?;

    let transaction =
        client.build_transaction(WasmSmartContract::from_compiled(wasm), Metadata::default());
    client.submit_transaction_blocking(&transaction)?;

    Ok(())
}
