#![allow(clippy::restriction)]

use std::thread;

use eyre::Result;
use iroha_client::client;
use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

#[test]
fn client_add_domain_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()>
{
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![test_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // Given

    let normal_domain_name = "sora";
    let create_domain = RegisterBox::new(IdentifiableBox::from(Domain::test(normal_domain_name)));
    test_client.submit(create_domain)?;

    let too_long_domain_name = &"0".repeat(2_usize.pow(14));
    let create_domain = RegisterBox::new(IdentifiableBox::from(Domain::test(too_long_domain_name)));
    test_client.submit(create_domain)?;

    thread::sleep(pipeline_time * 2);

    assert!(test_client
        .request(client::domain::by_id(DomainId::test(normal_domain_name)))
        .is_ok());
    assert!(test_client
        .request(client::domain::by_id(DomainId::test(too_long_domain_name)))
        .is_err());

    Ok(())
}
