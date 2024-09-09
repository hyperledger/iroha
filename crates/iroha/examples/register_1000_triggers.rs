//! Example of registering multiple triggers
//! Used to show Iroha's trigger deduplication capabilities

use std::num::NonZeroU64;

use iroha::{
    client::Client,
    crypto::KeyPair,
    data_model::{
        parameter::{Parameter, SmartContractParameter},
        prelude::*,
        trigger::TriggerId,
    },
};
use iroha_genesis::{GenesisBlock, GenesisBuilder};
use iroha_primitives::unique_vec;
use iroha_test_network::{
    get_chain_id, get_key_pair, wait_for_genesis_committed_with_max_retries, Peer as TestPeer,
    PeerBuilder, TestClient, TestRuntime,
};
use iroha_test_samples::{gen_account_in, load_sample_wasm};
use irohad::samples::get_config;
use tokio::runtime::Runtime;

fn generate_genesis(
    num_triggers: u32,
    chain_id: ChainId,
    genesis_key_pair: &KeyPair,
    topology: Vec<PeerId>,
) -> Result<GenesisBlock, Box<dyn std::error::Error>> {
    let builder = GenesisBuilder::default()
        .append_instruction(SetParameter::new(Parameter::Executor(
            SmartContractParameter::Fuel(NonZeroU64::MAX),
        )))
        .append_instruction(SetParameter::new(Parameter::Executor(
            SmartContractParameter::Memory(NonZeroU64::MAX),
        )));

    let (account_id, _account_keypair) = gen_account_in("wonderland");

    let build_trigger = |trigger_id: TriggerId| {
        Trigger::new(
            trigger_id.clone(),
            Action::new(
                load_sample_wasm("mint_rose_trigger"),
                Repeats::Indefinitely,
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id)
                    .under_authority(account_id.clone()),
            ),
        )
    };

    let builder = (0..num_triggers)
        .map(|i| {
            let trigger_id = i.to_string().parse::<TriggerId>().unwrap();
            let trigger = build_trigger(trigger_id);
            Register::trigger(trigger)
        })
        .fold(builder, GenesisBuilder::append_instruction);

    let executor = Executor::new(load_sample_wasm("default_executor"));
    Ok(builder.build_and_sign(chain_id, executor, topology, genesis_key_pair))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut peer: TestPeer = <TestPeer>::new().expect("Failed to create peer");

    let chain_id = get_chain_id();
    let genesis_key_pair = get_key_pair(iroha_test_network::Signatory::Genesis);
    let topology = vec![peer.id.clone()];
    let configuration = get_config(
        unique_vec![peer.id.clone()],
        chain_id.clone(),
        get_key_pair(iroha_test_network::Signatory::Peer),
        genesis_key_pair.public_key(),
    );

    let genesis = generate_genesis(1_000_u32, chain_id, &genesis_key_pair, topology)?;

    let builder = PeerBuilder::new()
        .with_genesis(genesis)
        .with_config(configuration);

    let rt = Runtime::test();
    let test_client = Client::test(&peer.api_address);
    rt.block_on(builder.start_with_peer(&mut peer));

    wait_for_genesis_committed_with_max_retries(&vec![test_client.clone()], 0, 600);

    Ok(())
}
