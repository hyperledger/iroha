//! Example of registering multiple triggers
//! Used to show iroha's trigger deduplication capabilities
use std::str::FromStr;

use iroha::samples::{construct_executor, get_config};
use iroha_client::{client::Client, data_model::prelude::*};
use iroha_data_model::trigger::TriggerId;
use iroha_genesis::{GenesisNetwork, RawGenesisBlock, RawGenesisBlockBuilder};
use iroha_primitives::unique_vec;
use test_network::{
    get_chain_id, get_key_pair, wait_for_genesis_committed_with_max_retries, Peer as TestPeer,
    PeerBuilder, TestClient, TestRuntime,
};
use test_samples::gen_account_in;
use tokio::runtime::Runtime;

fn generate_genesis(num_triggers: u32) -> Result<RawGenesisBlock, Box<dyn std::error::Error>> {
    let builder = RawGenesisBlockBuilder::default();

    let wasm =
        iroha_wasm_builder::Builder::new("tests/integration/smartcontracts/mint_rose_trigger")
            .show_output()
            .build()?
            .optimize()?
            .into_bytes()?;
    let wasm = WasmSmartContract::from_compiled(wasm);
    let (account_id, _account_keypair) = gen_account_in("wonderland");

    let build_trigger = |trigger_id: TriggerId| {
        Trigger::new(
            trigger_id.clone(),
            Action::new(
                wasm.clone(),
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
            let trigger_id = TriggerId::new(None, Name::from_str(&i.to_string()).unwrap());
            let trigger = build_trigger(trigger_id);
            Register::trigger(trigger)
        })
        .fold(builder, RawGenesisBlockBuilder::append_instruction);

    Ok(builder
        .executor_blob(
            construct_executor("../default_executor").expect("Failed to construct executor"),
        )
        .build())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut peer: TestPeer = <TestPeer>::new().expect("Failed to create peer");

    let chain_id = get_chain_id();
    let mut configuration = get_config(
        &unique_vec![peer.id.clone()],
        Some(chain_id.clone()),
        Some(get_key_pair(test_network::Signatory::Peer)),
        Some(get_key_pair(test_network::Signatory::Genesis)),
    );

    // Increase executor limits for large genesis
    configuration.chain_wide.executor_runtime.fuel_limit = u64::MAX;
    configuration.chain_wide.executor_runtime.max_memory_bytes = u32::MAX;

    let genesis = GenesisNetwork::new(
        generate_genesis(1_000_u32)?,
        &chain_id,
        configuration
            .genesis
            .key_pair()
            .expect("should be available in the config; probably a bug"),
    );

    let builder = PeerBuilder::new()
        .with_into_genesis(genesis)
        .with_config(configuration);

    let rt = Runtime::test();
    let test_client = Client::test(&peer.api_address);
    rt.block_on(builder.start_with_peer(&mut peer));

    wait_for_genesis_committed_with_max_retries(&vec![test_client.clone()], 0, 600);

    Ok(())
}
