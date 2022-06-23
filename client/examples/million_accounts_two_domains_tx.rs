#![allow(missing_docs, clippy::restriction)]
use std::{thread, time::Duration};

use iroha_data_model::prelude::*;
use test_network::{wait_for_genesis_committed, PeerBuilder};

fn create_accounts_two_domains_directly() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let domain1_id: DomainId = format!("wonderland-1").parse().expect("Valid");
    let create_domain1 = RegisterBox::new(Domain::new(domain1_id.clone()));
    if test_client
        .submit(create_domain1)
        .is_err()
    {
        thread::sleep(Duration::from_millis(100));
    }

    let domain2_id: DomainId = format!("wonderland-2").parse().expect("Valid");
    let create_domain2 = RegisterBox::new(Domain::new(domain2_id.clone()));
    if test_client
        .submit(create_domain2)
        .is_err()
    {
        thread::sleep(Duration::from_millis(100));
    }

    // first domain accounts
    for i in 0_u32..500_000_u32 {
        let normal_account_id = AccountId::new(
            format!("bob-{}", i).parse().expect("Valid"),
            domain1_id.clone(),
        );
        let create_account = RegisterBox::new(Account::new(normal_account_id.clone(), []));
        if test_client
            .submit(create_account)
            .is_err()
        {
            thread::sleep(Duration::from_millis(100));
        }
    }

    // second domain account creation
    for i in 0_u32..500_000_u32 {
        let normal_account_id = AccountId::new(
            format!("bob-{}", i).parse().expect("Valid"),
            domain2_id.clone(),
        );
        let create_account = RegisterBox::new(Account::new(normal_account_id.clone(), []));
        if test_client
            .submit(create_account)
            .is_err()
        {
            thread::sleep(Duration::from_millis(100));
        }
    }

    thread::sleep(Duration::from_secs(1000));
}

fn main() {
    create_accounts_two_domains_directly();
}
