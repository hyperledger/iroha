use std::str::FromStr as _;

use eyre::{bail, Result};
use iroha_client::{
    client::{self, ClientQueryError},
    data_model::{
        prelude::*,
        query::{cursor::ForwardCursor, error::QueryExecutionFail, MAX_FETCH_SIZE},
    },
};
use test_network::*;

mod account;
mod asset;
mod role;

#[test]
fn too_big_fetch_size_is_not_allowed() {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_130).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let err = client
        .build_query(client::asset::all())
        .with_fetch_size(FetchSize::new(Some(MAX_FETCH_SIZE.checked_add(1).unwrap())))
        .execute()
        .expect_err("Should fail");

    assert!(matches!(
        err,
        ClientQueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::FetchSizeTooBig
        ))
    ));
}

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
    let Value::String(cursor) = metadata_value.0 else {
        bail!("Expected `Value::String`, got {:?}", metadata_value.0);
    };
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
