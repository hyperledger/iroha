#![allow(clippy::pedantic, clippy::restriction)]

use std::thread;

use iroha_client::client::{account, transaction, Client};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::prelude::*;
use test_network::*;

use super::Configuration;

fn submit_and_get(
    client: &mut Client,
    instructions: impl IntoIterator<Item = InstructionBox>,
    submitter: Option<(AccountId, KeyPair)>,
) -> TransactionValue {
    let hash = if let Some((account_id, keypair)) = submitter {
        let tx = TransactionBuilder::new(account_id, Vec::from_iter(instructions), 100_000)
            .sign(keypair)
            .unwrap();

        client.submit_transaction(tx).unwrap()
    } else {
        client.submit_all(instructions).unwrap()
    };

    thread::sleep(Configuration::pipeline_time() * 2);

    client.request(transaction::by_hash(*hash)).unwrap()
}

fn account_keys_count(client: &mut Client, account_id: AccountId) -> usize {
    let account = client.request(account::by_id(account_id)).unwrap();
    let signatories = account.signatories();
    signatories.len()
}

#[test]
#[ignore = "TODO (#3408): Fix this flaky test. For some reason Iroha sometimes just ignores last transaction sometimes"]
fn public_keys_cannot_be_burned_to_nothing() {
    const KEYS_COUNT: usize = 3;
    let charlie_id: AccountId = "charlie@wonderland".parse().expect("Valid");
    let charlie_keys_count = |client: &mut Client| account_keys_count(client, charlie_id.clone());

    let (_rt, _peer, mut client) = <PeerBuilder>::new().with_port(10_045).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let charlie_initial_keypair = KeyPair::generate().unwrap();
    let register_charlie = RegisterBox::new(Account::new(
        charlie_id.clone(),
        [charlie_initial_keypair.public_key().clone()],
    ))
    .into();

    let _unused = submit_and_get(&mut client, [register_charlie], None);
    let mut keys_count = charlie_keys_count(&mut client);
    assert_eq!(keys_count, 1);

    let mint_keys = (0..KEYS_COUNT - 1).map(|_| {
        let (public_key, _) = KeyPair::generate().unwrap().into();
        MintBox::new(public_key, charlie_id.clone()).into()
    });

    let _unused = submit_and_get(
        &mut client,
        mint_keys,
        Some((charlie_id.clone(), charlie_initial_keypair.clone())),
    );
    keys_count = charlie_keys_count(&mut client);
    assert_eq!(keys_count, KEYS_COUNT);

    let charlie = client.request(account::by_id(charlie_id.clone())).unwrap();
    let mut keys = charlie.signatories();
    let burn = |key: PublicKey| InstructionBox::from(BurnBox::new(key, charlie_id.clone()));
    let burn_keys_leaving_one = keys.by_ref().take(KEYS_COUNT - 1).cloned().map(burn);

    let mut committed_txn = submit_and_get(
        &mut client,
        burn_keys_leaving_one,
        Some((charlie_id.clone(), charlie_initial_keypair.clone())),
    );
    keys_count = charlie_keys_count(&mut client);
    assert_eq!(keys_count, 1);
    assert!(matches!(committed_txn, TransactionValue::Transaction(_)));

    let burn_the_last_key = keys.cloned().map(burn);

    committed_txn = submit_and_get(
        &mut client,
        burn_the_last_key,
        Some((charlie_id.clone(), charlie_initial_keypair)),
    );
    keys_count = charlie_keys_count(&mut client);
    assert_eq!(keys_count, 1);
    assert!(matches!(
        committed_txn,
        TransactionValue::RejectedTransaction(_)
    ));
}
