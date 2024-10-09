use iroha::{
    client::{self, QueryError},
    data_model::{
        prelude::*,
        query::{error::QueryExecutionFail, parameters::MAX_FETCH_SIZE},
    },
};
use iroha_test_network::*;

mod account;
mod asset;
mod query_errors;
mod role;
mod smart_contract;

#[test]
// FIXME
#[ignore = "started to fail after #5086?"]
fn too_big_fetch_size_is_not_allowed() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let client = network.client();

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
