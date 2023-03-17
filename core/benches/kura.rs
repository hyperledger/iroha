#![allow(missing_docs, clippy::restriction)]

use std::{str::FromStr as _, sync::Arc};

use byte_unit::Byte;
use criterion::{criterion_group, criterion_main, Criterion};
use iroha_core::{block::*, kura::BlockStore, prelude::*, tx::TransactionValidator, wsv::World};
use iroha_crypto::KeyPair;
use iroha_data_model::{block::VersionedCommittedBlock, prelude::*};
use iroha_version::scale::EncodeVersioned;
use tokio::{fs, runtime::Runtime};

async fn measure_block_size_for_n_validators(n_validators: u32) {
    let alice_id = AccountId::from_str("alice@test").expect("tested");
    let bob_id = AccountId::from_str("bob@test").expect("tested");
    let xor_id = AssetDefinitionId::from_str("xor#test").expect("tested");
    let alice_xor_id = <Asset as Identifiable>::Id::new(xor_id.clone(), alice_id);
    let bob_xor_id = <Asset as Identifiable>::Id::new(xor_id, bob_id);
    let transfer = TransferBox {
        source_id: IdBox::AssetId(alice_xor_id).into(),
        object: 10_u32.to_value().into(),
        destination_id: IdBox::AssetId(bob_xor_id).into(),
    }
    .into();
    let keypair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let tx = Transaction::new(
        AccountId::from_str("alice@wonderland").expect("checked"),
        vec![transfer],
        1000,
    )
    .sign(keypair)
    .expect("Failed to sign.");
    let transaction_limits = TransactionLimits {
        max_instruction_number: 4096,
        max_wasm_size_bytes: 0,
    };
    let tx = AcceptedTransaction::accept::<false>(tx, &transaction_limits)
        .expect("Failed to accept Transaction.")
        .into();
    let dir = tempfile::tempdir().expect("Could not create tempfile.");
    let kura =
        iroha_core::kura::Kura::new(iroha_config::kura::Mode::Strict, dir.path(), false).unwrap();
    let _thread_handle = iroha_core::kura::Kura::start(kura.clone());

    let block = PendingBlock::new(vec![tx], Vec::new())
        .chain_first()
        .validate(
            &TransactionValidator::new(transaction_limits),
            &Arc::new(WorldStateView::new(World::new(), kura)),
        );
    let mut block = block
        .sign(KeyPair::generate().expect("Failed to generate KeyPair"))
        .unwrap();
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
