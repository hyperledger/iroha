#![allow(missing_docs, clippy::restriction)]

use std::str::FromStr as _;

use byte_unit::Byte;
use criterion::{criterion_group, criterion_main, Criterion};
use iroha_core::{
    block::*,
    kura::{BlockStore, LockStatus},
    prelude::*,
    sumeragi::network_topology::Topology,
    wsv::World,
};
use iroha_crypto::KeyPair;
use iroha_data_model::{prelude::*, transaction::TransactionLimits};
use tokio::{fs, runtime::Runtime};

async fn measure_block_size_for_n_validators(n_validators: u32) {
    let alice_id = AccountId::from_str("alice@test").expect("tested");
    let bob_id = AccountId::from_str("bob@test").expect("tested");
    let xor_id = AssetDefinitionId::from_str("xor#test").expect("tested");
    let alice_xor_id = AssetId::new(xor_id, alice_id);
    let transfer = TransferBox::new(
        IdBox::AssetId(alice_xor_id),
        10_u32.to_value(),
        IdBox::AccountId(bob_id),
    );
    let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let tx = TransactionBuilder::new(AccountId::from_str("alice@wonderland").expect("checked"))
        .with_instructions([transfer])
        .sign(keypair.clone())
        .expect("Failed to sign.");
    let transaction_limits = TransactionLimits {
        max_instruction_number: 4096,
        max_wasm_size_bytes: 0,
    };
    let tx = AcceptedTransaction::accept(tx, &transaction_limits)
        .expect("Failed to accept Transaction.");
    let dir = tempfile::tempdir().expect("Could not create tempfile.");
    let kura =
        iroha_core::kura::Kura::new(iroha_config::kura::Mode::Strict, dir.path(), false).unwrap();
    let _thread_handle = iroha_core::kura::Kura::start(kura.clone());

    let mut wsv = WorldStateView::new(World::new(), kura);
    let topology = Topology::new(Vec::new());
    let mut block = BlockBuilder::new(vec![tx], topology, Vec::new())
        .chain_first(&mut wsv)
        .sign(KeyPair::generate().unwrap())
        .unwrap();

    for _ in 1..n_validators {
        block = block
            .sign(KeyPair::generate().expect("Failed to generate KeyPair."))
            .unwrap();
    }
    let mut block_store = BlockStore::new(dir.path(), LockStatus::Unlocked);
    block_store.create_files_if_they_do_not_exist().unwrap();
    block_store.append_block_to_chain(&block.into()).unwrap();

    let metadata = fs::metadata(dir.path().join("blocks.data")).await.unwrap();
    let file_size = Byte::from_bytes(u128::from(metadata.len())).get_appropriate_unit(false);
    println!("For {n_validators} validators: {file_size}");
}

async fn measure_block_size_async() {
    println!("File size of a block with 1 transaction with 1 Transfer instruction is:",);
    for max_faults in 0_u32..5_u32 {
        let n_validators = 3 * max_faults + 1;
        measure_block_size_for_n_validators(n_validators).await;
    }
}

fn measure_block_size(_criterion: &mut Criterion) {
    Runtime::new().unwrap().block_on(measure_block_size_async());
}

criterion_group!(kura, measure_block_size);
criterion_main!(kura);
