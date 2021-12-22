#![allow(missing_docs, clippy::restriction)]

use std::num::NonZeroU64;

use byte_unit::Byte;
use criterion::{criterion_group, criterion_main, Criterion};
use iroha_core::{
    kura::{config::KuraConfiguration, BlockStore},
    prelude::*,
    wsv::World,
};
use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;
use tokio::{fs, runtime::Runtime};

async fn measure_block_size_for_n_validators(n_validators: u32) {
    let dir = tempfile::tempdir().unwrap();
    let alice_xor_id = <Asset as Identifiable>::Id::test("xor", "test", "alice", "test");
    let bob_xor_id = <Asset as Identifiable>::Id::test("xor", "test", "bob", "test");
    let transfer = Instruction::Transfer(TransferBox {
        source_id: IdBox::AssetId(alice_xor_id).into(),
        object: Value::U32(10).into(),
        destination_id: IdBox::AssetId(bob_xor_id).into(),
    });
    let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let tx = Transaction::new(
        vec![transfer],
        <Account as Identifiable>::Id::test("alice", "wonderland"),
        1000,
    )
    .sign(&keypair)
    .expect("Failed to sign.");
    let tx = VersionedAcceptedTransaction::from_transaction(tx, 4096)
        .expect("Failed to accept Transaction.");
    let mut block = PendingBlock::new(vec![tx]).chain_first().validate(
        &WorldStateView::new(World::new()),
        &AllowAll.into(),
        &AllowAll.into(),
    );
    for _ in 0..n_validators {
        block = block
            .sign(KeyPair::generate().expect("Failed to generate KeyPair."))
            .unwrap();
    }
    let block = block.commit();
    let block_store = BlockStore::new(
        dir.path(),
        KuraConfiguration::default().blocks_per_storage_file,
        iroha_core::kura::DefaultIO,
    )
    .await
    .unwrap();
    block_store.write(&block).await.unwrap();
    let metadata = fs::metadata(
        block_store
            .get_block_path(NonZeroU64::new(1_u64).unwrap())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let file_size = Byte::from_bytes(u128::from(metadata.len())).get_appropriate_unit(false);
    println!("For {} validators: {}", n_validators, file_size);
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
