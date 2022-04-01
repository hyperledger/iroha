#![allow(missing_docs, clippy::restriction)]
use std::{thread, time::Duration};

use iroha_data_model::prelude::*;
use test_network::{wait_for_genesis_committed, Peer as TestPeer};

fn create_million_accounts_directly() {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    for i in 0_u32..10_000_000_u32 {
        let domain_id: DomainId = format!("wonderland-{}", i).parse().expect("Valid");
        let normal_account_id = AccountId::new(
            format!("bob-{}", i).parse().expect("Valid"),
            domain_id.clone(),
        );
        let create_domain = RegisterBox::new(Domain::new(domain_id));
        let create_account = RegisterBox::new(Account::new(normal_account_id, []));
        if test_client
            .submit_all([create_domain.into(), create_account.into()].to_vec())
            .is_err()
        {
            thread::sleep(Duration::from_millis(15000));
        }
    }
    thread::sleep(Duration::from_secs(1000));
}

fn main() {
    create_million_accounts_directly();
}
