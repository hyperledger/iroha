use std::thread;

use iroha::config::Configuration;
use iroha_client::client;
use iroha_data_model::prelude::*;
use iroha_error::Result;
use test_network::Peer as TestPeer;
use test_network::*;

#[test]
fn client_add_account_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()>
{
    let (_, mut test_client) = TestPeer::start_test();

    let pipeline_time = Configuration::pipeline_time();

    // Given
    let normal_account_id = AccountId::new("alice", "wonderland");
    let create_account = RegisterBox::new(IdentifiableBox::from(NewAccount::new(
        normal_account_id.clone(),
    )));
    test_client.submit(create_account)?;

    let too_long_account_name = "0".repeat(2_usize.pow(14));
    let incorrect_account_id = AccountId::new(&too_long_account_name, "wonderland");
    let create_account = RegisterBox::new(IdentifiableBox::from(NewAccount::new(
        incorrect_account_id.clone(),
    )));
    test_client.submit(create_account)?;

    thread::sleep(pipeline_time * 2);

    assert!(test_client
        .request(&client::account::by_id(normal_account_id))
        .is_ok());
    assert!(test_client
        .request(&client::account::by_id(incorrect_account_id))
        .is_err());

    Ok(())
}
