use std::str::FromStr as _;

use eyre::Result;
use iroha::{
    client::ClientQueryError,
    data_model::{
        prelude::*,
        query::{cursor::ForwardCursor, error::QueryExecutionFail},
    },
};
use test_network::*;

#[test]
fn live_query_is_dropped_after_smart_contract_end() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_140).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let wasm = iroha_wasm_builder::Builder::new(
        "tests/integration/smartcontracts/query_assets_and_save_cursor",
    )
    .show_output()
    .build()?
    .optimize()?
    .into_bytes()?;

    let transaction = client.build_transaction(
        WasmSmartContract::from_compiled(wasm),
        UnlimitedMetadata::default(),
    );
    client.submit_transaction_blocking(&transaction)?;

    let metadata_value = client.request(FindAccountKeyValueByIdAndKey::new(
        client.account_id.clone(),
        Name::from_str("cursor").unwrap(),
    ))?;
    let cursor: String = metadata_value.try_into()?;
    let asset_cursor = serde_json::from_str::<ForwardCursor>(&cursor)?;

    let err = client
        .request_with_cursor::<Vec<Asset>>(asset_cursor)
        .expect_err("Request with cursor from smart contract should fail");

    assert!(matches!(
        err,
        ClientQueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::UnknownCursor
        ))
    ));

    Ok(())
}

#[test]
fn smart_contract_can_filter_queries() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_260).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let wasm = iroha_wasm_builder::Builder::new(
        "tests/integration/smartcontracts/smart_contract_can_filter_queries",
    )
    .show_output()
    .build()?
    .optimize()?
    .into_bytes()?;

    let transaction = client.build_transaction(
        WasmSmartContract::from_compiled(wasm),
        UnlimitedMetadata::default(),
    );
    client.submit_transaction_blocking(&transaction)?;

    Ok(())
}
