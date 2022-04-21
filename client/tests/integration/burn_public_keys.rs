#![allow(clippy::pedantic, clippy::restriction)]

use std::thread;

use iroha_client::client::{account, transaction, Client};
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

use super::Configuration;

fn submit_and_get(
    client: &mut Client,
    instructions: impl IntoIterator<Item = Instruction>,
) -> TransactionValue {
    let hash = client.submit_all(instructions).unwrap();
    thread::sleep(Configuration::pipeline_time() * 2);

    client.request(transaction::by_hash(*hash)).unwrap()
}

fn account_keys_count(client: &mut Client, account_id: AccountId) -> usize {
    let account = client.request(account::by_id(account_id)).unwrap();
    let signatories = account.signatories();
    signatories.len()
}

#[test]
fn public_keys_cannot_be_burned_to_nothing() {
    const KEYS_COUNT: usize = 3;
    let bob_id: AccountId = "bob@wonderland".parse().expect("Valid");
    let bob_keys_count = |client: &mut Client| account_keys_count(client, bob_id.clone());

    let (_rt, _peer, mut client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let register_bob = RegisterBox::new(Account::new(bob_id.clone(), [])).into();

    let _ = submit_and_get(&mut client, [register_bob]);
    let mut keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, 0);

    let mint_keys = (0..KEYS_COUNT).map(|_| {
        let (public_key, _) = KeyPair::generate().unwrap().into();
        MintBox::new(public_key, bob_id.clone()).into()
    });

    let _ = submit_and_get(&mut client, mint_keys);
    keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, KEYS_COUNT);

    let bob = client.request(account::by_id(bob_id.clone())).unwrap();
    let mut keys = bob.signatories();
    let burn = |key: PublicKey| Instruction::from(BurnBox::new(key, bob_id.clone()));
    let burn_keys_leaving_one = keys.by_ref().take(KEYS_COUNT - 1).cloned().map(burn);

    let mut committed_txn = submit_and_get(&mut client, burn_keys_leaving_one);
    keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, 1);
    assert!(matches!(committed_txn, TransactionValue::Transaction(_)));

    let burn_the_last_key = keys.cloned().map(burn);

    committed_txn = submit_and_get(&mut client, burn_the_last_key);
    keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, 1);
    assert!(matches!(
        committed_txn,
        TransactionValue::RejectedTransaction(_)
    ));
}
