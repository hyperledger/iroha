use iroha::client::{self, ClientQueryError};
use iroha_data_model::query::builder::SingleQueryError;
use test_samples::gen_account_in;

#[test]
fn non_existent_account_is_specific_error() {
    let (_rt, _peer, client) = <test_network::PeerBuilder>::new()
        .with_port(10_670)
        .start_with_runtime();
    // we cannot wait for genesis committment

    let err = client
        .query(client::account::all())
        .with_filter(|account| account.id.eq(gen_account_in("regalia").0))
        .execute_single()
        .expect_err("Should error");

    match err {
        ClientQueryError::Single(SingleQueryError::ExpectedOneGotNone) => {}
        x => panic!("Unexpected error: {x:?}"),
    }
}
