//! This file contains examples from the Rust tutorial.
use std::{thread, time::Duration};

use iroha::{
    crypto::KeyPair,
    data_model::{isi::InstructionBox, prelude::*},
};
use iroha_genesis::{GenesisBlock, GenesisBuilder};
use iroha_primitives::unique_vec;
use irohad::samples::get_config;
use test_network::{
    construct_executor, get_chain_id, get_key_pair, wait_for_genesis_committed, Peer as TestPeer,
    PeerBuilder, TestRuntime,
};
use tokio::runtime::Runtime;

fn generate_genesis(
    num_domains: u32,
    chain_id: ChainId,
    genesis_key_pair: &KeyPair,
    topology: Vec<PeerId>,
) -> GenesisBlock {
    let mut builder = GenesisBuilder::default();

    let signatory_alice = get_key_pair(test_network::Signatory::Alice).into_parts().0;
    for i in 0_u32..num_domains {
        builder = builder
            .domain(format!("wonderland-{i}").parse().expect("Valid"))
            .account(signatory_alice.clone())
            .asset(
                format!("xor-{i}").parse().expect("Valid"),
                AssetType::Numeric(NumericSpec::default()),
            )
            .finish_domain();
    }

    let executor = construct_executor("../wasm_samples/default_executor")
        .expect("Failed to construct executor");
    builder.build_and_sign(chain_id, executor, topology, genesis_key_pair)
}

fn main_genesis() {
    let mut peer = <TestPeer>::new().expect("Failed to create peer");

    let chain_id = get_chain_id();
    let genesis_key_pair = get_key_pair(test_network::Signatory::Genesis);
    let topology = vec![peer.id.clone()];
    let configuration = get_config(
        unique_vec![peer.id.clone()],
        chain_id.clone(),
        get_key_pair(test_network::Signatory::Peer),
        genesis_key_pair.public_key(),
    );
    let rt = Runtime::test();
    let genesis = generate_genesis(1_000_000_u32, chain_id, &genesis_key_pair, topology);

    let builder = PeerBuilder::new()
        .with_genesis(genesis)
        .with_config(configuration);

    // This only submits the genesis. It doesn't check if the accounts
    // are created, because that check is 1) not needed for what the
    // test is actually for, 2) incredibly slow, making this sort of
    // test impractical, 3) very likely to overflow memory on systems
    // with less than 16GiB of free memory.
    rt.block_on(builder.start_with_peer(&mut peer));
}

fn create_million_accounts_directly() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    for i in 0_u32..1_000_000_u32 {
        let domain_id: DomainId = format!("wonderland-{i}").parse().expect("Valid");
        let normal_account_id = AccountId::new(domain_id.clone(), KeyPair::random().into_parts().0);
        let create_domain = Register::domain(Domain::new(domain_id));
        let create_account = Register::account(Account::new(normal_account_id.clone()));
        if test_client
            .submit_all::<InstructionBox>([create_domain.into(), create_account.into()])
            .is_err()
        {
            thread::sleep(Duration::from_millis(100));
        }
    }
    thread::sleep(Duration::from_secs(1000));
}

fn main() {
    create_million_accounts_directly();
    main_genesis();
}
