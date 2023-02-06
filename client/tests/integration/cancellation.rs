use std::str::FromStr;

use eyre::Result;
use iroha_core::tx::{Account, AccountId, RegisterBox};
use test_network::*;

#[test]
fn client_cancel_to_submit_transaction() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_680).start_with_runtime();

    let new_acc_id = AccountId::from_str("bobby@wonderland").expect("Valid");
    let register_new_acc = RegisterBox::new(Account::new(new_acc_id, []));

    let (tx, rx) = crossbeam_channel::bounded(1);
    tx.send(()).expect("Sent successfully");

    assert!(client
        .submit_with_cancellation(register_new_acc, rx)
        .is_err());

    Ok(())
}

#[test]
fn client_cancel_to_blocking_submit_transaction() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_690).start_with_runtime();

    let new_acc_id = AccountId::from_str("bobby@wonderland").expect("Valid");
    let register_new_acc = RegisterBox::new(Account::new(new_acc_id, []));

    let (tx, rx) = crossbeam_channel::bounded(1);
    tx.send(()).expect("Sent successfully");

    assert!(client
        .submit_blocking_with_cancellation(register_new_acc, rx)
        .is_err());

    Ok(())
}
