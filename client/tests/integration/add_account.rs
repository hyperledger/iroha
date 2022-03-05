#![allow(clippy::restriction)]

use std::thread;

use eyre::Result;
use iroha_client::client;
use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

#[test]
fn client_add_account_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()>
{
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![test_client.clone()], 0);

    let pipeline_time = Configuration::pipeline_time();

    let normal_account_id = AccountId::test("bob", "wonderland");
    let create_account = RegisterBox::new(IdentifiableBox::from(NewAccount::new(
        normal_account_id.clone(),
    )));
    test_client.submit(create_account)?;

    let too_long_account_name = "0".repeat(2_usize.pow(14));
    let incorrect_account_id = AccountId::test(&too_long_account_name, "wonderland");
    let create_account = RegisterBox::new(IdentifiableBox::from(NewAccount::new(
        incorrect_account_id.clone(),
    )));
    test_client.submit(create_account)?;

    thread::sleep(pipeline_time * 2);

    assert!(test_client
        .request(client::account::by_id(normal_account_id))
        .is_ok());
    assert!(test_client
        .request(client::account::by_id(incorrect_account_id))
        .is_err());

    Ok(())
}
