#![allow(missing_docs)]

use std::str::FromStr as _;

use byte_unit::{Byte, UnitType};
use criterion::{criterion_group, criterion_main, Criterion};
use iroha_config::{base::WithOrigin, parameters::actual::Kura as Config};
use iroha_core::{
    block::*,
    kura::BlockStore,
    prelude::*,
    query::store::LiveQueryStore,
    state::{State, World},
    sumeragi::network_topology::Topology,
};
use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;
use test_samples::gen_account_in;
use tokio::{fs, runtime::Runtime};

async fn measure_block_size_for_n_executors(n_executors: u32) {
    let dir = tempfile::tempdir().expect("Could not create tempfile.");
    let cfg = Config {
        init_mode: iroha_config::kura::InitMode::Strict,
        debug_output_new_blocks: false,
        store_dir: WithOrigin::inline(dir.path().to_path_buf()),
    };
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
    let (kura, _) = iroha_core::kura::Kura::new(&cfg).unwrap();
    let _thread_handle = iroha_core::kura::Kura::start(kura.clone());
    let query_handle = LiveQueryStore::test().start();
    let state = State::new(World::new(), kura, query_handle);

    let (alice_id, alice_keypair) = gen_account_in("test");
    let (bob_id, _bob_keypair) = gen_account_in("test");
    let xor_id = AssetDefinitionId::from_str("xor#test").expect("tested");
    let alice_xor_id = AssetId::new(xor_id, alice_id.clone());
    let transfer = Transfer::asset_numeric(alice_xor_id, 10u32, bob_id);
    let tx = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
        .with_instructions([transfer])
        .sign(alice_keypair.private_key());
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction)
    };
    let tx = AcceptedTransaction::accept(tx, &chain_id, max_clock_drift, tx_limits)
        .expect("Failed to accept Transaction.");
    let (peer_public_key, peer_private_key) = KeyPair::random().into_parts();
    let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
    let topology = Topology::new(vec![peer_id]);
    let mut block = {
        let mut state_block = state.block();
        BlockBuilder::new(vec![tx])
            .chain(0, &mut state_block)
            .sign(&peer_private_key)
            .unpack(|_| {})
    };

    let key_pair = KeyPair::random();
    for _ in 1..n_executors {
        block.sign(&key_pair, &topology);
    }
    let mut block_store = BlockStore::new(dir.path());
    block_store.create_files_if_they_do_not_exist().unwrap();
    block_store.append_block_to_chain(&block.into()).unwrap();

    let metadata = fs::metadata(dir.path().join("blocks.data")).await.unwrap();
    let file_size = Byte::from(metadata.len()).get_appropriate_unit(UnitType::Decimal);
    println!("For {n_executors} executors: {file_size}");
}

async fn measure_block_size_async() {
    println!("File size of a block with 1 transaction with 1 Transfer instruction is:",);
    for max_faults in 0_u32..5_u32 {
        let n_executors = 3 * max_faults + 1;
        measure_block_size_for_n_executors(n_executors).await;
    }
}

fn measure_block_size(_criterion: &mut Criterion) {
    Runtime::new().unwrap().block_on(measure_block_size_async());
}

criterion_group!(kura, measure_block_size);
criterion_main!(kura);
