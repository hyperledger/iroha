use iroha::{
    client,
    data_model::{prelude::QueryBuilderExt, query::builder::SingleQueryError},
};
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::gen_account_in;

#[test]
fn non_existent_account_is_specific_error() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let client = network.client();

    let err = client
        .query(client::account::all())
        .filter_with(|account| account.id.eq(gen_account_in("regalia").0))
        .execute_single()
        .expect_err("Should error");

    match err {
        SingleQueryError::ExpectedOneGotNone => {}
        x => panic!("Unexpected error: {x:?}"),
    }
}
