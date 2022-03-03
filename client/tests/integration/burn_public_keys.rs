#![allow(clippy::pedantic, clippy::restriction)]

use std::thread;

use iroha_client::client::{account, transaction, Client};
use iroha_core::{config::Configuration, prelude::*};
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

fn submit_and_get(
    client: &mut Client,
    instructions: impl IntoIterator<Item = InstructionBox>,
) -> TransactionValue {
    let hash = client.submit_all(instructions).unwrap();
    thread::sleep(Configuration::pipeline_time() * 2);

    client.request(transaction::by_hash(*hash)).unwrap()
}

fn account_keys_count(client: &mut Client, account_id: AccountId) -> usize {
    let account = client.request(account::by_id(account_id)).unwrap();
    account.signatories.len()
}

#[test]
fn public_keys_cannot_be_burned_to_nothing() {
    const KEYS_COUNT: usize = 3;
    let mut keys_count;
    let mut committed_txn;
    let bob_id = AccountId::test("bob", "wonderland");
    let bob_keys_count = |client: &mut Client| account_keys_count(client, bob_id.clone());

    let (_rt, _peer, mut client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![client.clone()], 0);

    let register_bob = RegisterBox::new(NewAccount::new(bob_id.clone())).into();

    let _ = submit_and_get(&mut client, [register_bob]);
    keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, 0);

    let mint_keys = (0..KEYS_COUNT)
        .map(|_| MintBox::new(KeyPair::generate().unwrap().public_key, bob_id.clone()).into());

    let _ = submit_and_get(&mut client, mint_keys);
    keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, KEYS_COUNT);

    let bob = client.request(account::by_id(bob_id.clone())).unwrap();
    let mut keys = bob.signatories.into_iter();
    let burn = |key: PublicKey| InstructionBox::from(BurnBox::new(key, bob_id.clone()));
    let burn_keys_leaving_one = keys.by_ref().take(KEYS_COUNT - 1).map(burn);

    committed_txn = submit_and_get(&mut client, burn_keys_leaving_one);
    keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, 1);
    assert!(matches!(committed_txn, TransactionValue::Transaction(_)));

    let burn_the_last_key = keys.map(burn);

    committed_txn = submit_and_get(&mut client, burn_the_last_key);
    keys_count = bob_keys_count(&mut client);
    assert_eq!(keys_count, 1);
    assert!(matches!(
        committed_txn,
        TransactionValue::RejectedTransaction(_)
    ));
}
