use iroha::{
    client::{self, QueryError},
    data_model::{prelude::*, query::error::QueryExecutionFail},
};
use iroha_data_model::query::parameters::MAX_FETCH_SIZE;
use test_network::*;

mod account;
mod asset;
mod query_errors;
mod role;
mod smart_contract;

#[test]
fn too_big_fetch_size_is_not_allowed() {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_130).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let err = client
        .query(client::asset::all())
        .with_fetch_size(FetchSize::new(Some(MAX_FETCH_SIZE.checked_add(1).unwrap())))
        .execute()
        .expect_err("Should fail");

    assert!(matches!(
        err,
        QueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::FetchSizeTooBig
        ))
    ));
}
