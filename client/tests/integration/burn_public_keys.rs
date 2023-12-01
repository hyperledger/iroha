use iroha_client::{
    client::{account, transaction, Client},
    crypto::{HashOf, KeyPair, PublicKey},
    data_model::{isi::Instruction, prelude::*, transaction::TransactionPayload},
};
use test_network::*;

fn submit(
    client: &Client,
    instructions: impl IntoIterator<Item = impl Instruction>,
    submitter: Option<(AccountId, KeyPair)>,
) -> (
    HashOf<SignedTransaction>,
    eyre::Result<HashOf<TransactionPayload>>,
) {
    let tx = if let Some((account_id, keypair)) = submitter {
        TransactionBuilder::new(account_id)
            .with_instructions(instructions)
            .sign(keypair)
            .unwrap()
    } else {
        let tx = client
            .build_transaction(instructions, UnlimitedMetadata::default())
            .unwrap();
        client.sign_transaction(tx).unwrap()
    };

    (tx.hash(), client.submit_transaction_blocking(&tx))
}

fn get(client: &Client, hash: HashOf<SignedTransaction>) -> TransactionValue {
    client
        .request(transaction::by_hash(hash))
        .unwrap()
        .transaction
}

fn account_keys_count(client: &Client, account_id: AccountId) -> usize {
    let account = client.request(account::by_id(account_id)).unwrap();
    let signatories = account.signatories();
    signatories.len()
}

#[test]
fn public_keys_cannot_be_burned_to_nothing() {
    const KEYS_COUNT: usize = 3;
    let charlie_id: AccountId = "charlie@wonderland".parse().expect("Valid");
    let charlie_keys_count = |client: &Client| account_keys_count(client, charlie_id.clone());

    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_045).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let charlie_initial_keypair = KeyPair::generate().unwrap();
    let register_charlie = RegisterExpr::new(Account::new(
        charlie_id.clone(),
        [charlie_initial_keypair.public_key().clone()],
    ));

    let (tx_hash, res) = submit(&client, [register_charlie], None);
    res.unwrap();
    get(&client, tx_hash);
    let mut keys_count = charlie_keys_count(&client);
    assert_eq!(keys_count, 1);

    let mint_keys = (0..KEYS_COUNT - 1).map(|_| {
        let (public_key, _) = KeyPair::generate().unwrap().into();
        MintExpr::new(public_key, charlie_id.clone())
    });

    let (tx_hash, res) = submit(
        &client,
        mint_keys,
        Some((charlie_id.clone(), charlie_initial_keypair.clone())),
    );
    res.unwrap();
    get(&client, tx_hash);
    keys_count = charlie_keys_count(&client);
    assert_eq!(keys_count, KEYS_COUNT);

    let charlie = client.request(account::by_id(charlie_id.clone())).unwrap();
    let mut keys = charlie.signatories();
    let burn = |key: PublicKey| InstructionExpr::from(BurnExpr::new(key, charlie_id.clone()));
    let burn_keys_leaving_one = keys
        .by_ref()
        .filter(|pub_key| pub_key != &charlie_initial_keypair.public_key())
        .cloned()
        .map(burn);

    let (tx_hash, res) = submit(
        &client,
        burn_keys_leaving_one,
        Some((charlie_id.clone(), charlie_initial_keypair.clone())),
    );
    res.unwrap();
    let committed_txn = get(&client, tx_hash);
    keys_count = charlie_keys_count(&client);
    assert_eq!(keys_count, 1);
    assert!(committed_txn.error.is_none());

    let burn_the_last_key = burn(charlie_initial_keypair.public_key().clone());

    let (tx_hash, res) = submit(
        &client,
        std::iter::once(burn_the_last_key),
        Some((charlie_id.clone(), charlie_initial_keypair)),
    );
    assert!(res.is_err());
    let committed_txn = get(&client, tx_hash);
    keys_count = charlie_keys_count(&client);
    assert_eq!(keys_count, 1);
    assert!(committed_txn.error.is_some());
}
