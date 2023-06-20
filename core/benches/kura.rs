#![allow(missing_docs, clippy::restriction)]

use std::str::FromStr as _;

use byte_unit::Byte;
use criterion::{criterion_group, criterion_main, Criterion};
use iroha_core::{block::*, kura::BlockStore, prelude::*, wsv::World};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    block::VersionedCommittedBlock, prelude::*, transaction::TransactionLimits,
};
use iroha_version::scale::EncodeVersioned;
use tokio::{fs, runtime::Runtime};

async fn measure_block_size_for_n_validators(n_validators: u32) {
    let alice_id = AccountId::from_str("alice@test").expect("tested");
    let bob_id = AccountId::from_str("bob@test").expect("tested");
    let xor_id = AssetDefinitionId::from_str("xor#test").expect("tested");
    let alice_xor_id = <Asset as Identifiable>::Id::new(xor_id, alice_id);
    let transfer = TransferBox::new(
        IdBox::AssetId(alice_xor_id),
        10_u32.to_value(),
        IdBox::AccountId(bob_id),
    );
    let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let tx = TransactionBuilder::new(AccountId::from_str("alice@wonderland").expect("checked"))
        .with_instructions([transfer])
        .sign(keypair)
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

    let mut block = BlockBuilder {
        transactions: vec![tx],
        event_recommendations: Vec::new(),
        view_change_index: 0,
        committed_with_topology: iroha_core::sumeragi::network_topology::Topology::new(Vec::new()),
        key_pair: KeyPair::generate().expect("Failed to generate KeyPair"),
        wsv: &mut WorldStateView::new(World::new(), kura),
    }
    .build();

    for _ in 1..n_validators {
        block = block
            .sign(KeyPair::generate().expect("Failed to generate KeyPair."))
            .unwrap();
    }
    let block: VersionedCommittedBlock = block.commit_unchecked().into();
    let mut block_store = BlockStore::new(dir.path())
        .lock()
        .expect("Failed to lock store");
    block_store.create_files_if_they_do_not_exist().unwrap();

    let serialized_block: Vec<u8> = block.encode_versioned();
    block_store
        .append_block_to_chain(&serialized_block)
        .unwrap();

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
