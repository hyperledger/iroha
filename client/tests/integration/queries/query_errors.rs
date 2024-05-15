use iroha_client::{
    client::{self, ClientQueryError},
    data_model::{
        prelude::*,
        query::error::{FindError, QueryExecutionFail},
    },
};
use test_samples::gen_account_in;

#[test]
fn non_existent_account_is_specific_error() {
    let (_rt, _peer, client) = <test_network::PeerBuilder>::new()
        .with_port(10_670)
        .start_with_runtime();
    // we cannot wait for genesis committment

    let err = client
        .request(client::account::by_id(gen_account_in("regalia").0))
        .expect_err("Should error");

    match err {
        ClientQueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
            err,
        ))) => match err {
            FindError::Domain(id) => assert_eq!(id.name.as_ref(), "regalia"),
            x => panic!("FindError::Domain expected, got {x:?}"),
        },
        x => panic!("Unexpected error: {x:?}"),
    };
}
