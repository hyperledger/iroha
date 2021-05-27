#![allow(clippy::module_inception, unused_results, clippy::restriction)]

use std::thread;

use iroha::config::Configuration;
use iroha_client::client;
use iroha_data_model::prelude::*;
use iroha_error::Result;
use test_network::Peer as TestPeer;
use test_network::*;

#[test]
fn client_add_domain_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()>
{
    let (_, mut test_client) = TestPeer::start_test();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time);

    let normal_domain_name = "sora";
    let create_domain = RegisterBox::new(IdentifiableBox::from(Domain::new(normal_domain_name)));
    test_client.submit(create_domain)?;

    let too_long_domain_name = &"0".repeat(2_usize.pow(14));
    let create_domain = RegisterBox::new(IdentifiableBox::from(Domain::new(too_long_domain_name)));
    test_client.submit(create_domain)?;

    thread::sleep(pipeline_time * 2);

    assert!(test_client
        .request(client::domain::by_name(normal_domain_name.to_string()))
        .is_ok());
    assert!(test_client
        .request(client::domain::by_name(too_long_domain_name.to_string()))
        .is_err());

    Ok(())
}
