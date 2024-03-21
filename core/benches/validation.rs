#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use iroha_core::{
    block::*,
    prelude::*,
    query::store::LiveQueryStore,
    smartcontracts::{isi::Registrable as _, Execute},
    state::{State, World},
    sumeragi::network_topology::Topology,
    tx::TransactionExecutor,
};
use iroha_data_model::{
    account::AccountId, isi::InstructionBox, prelude::*, transaction::TransactionLimits,
};
use iroha_primitives::unique_vec::UniqueVec;
use once_cell::sync::Lazy;
use test_samples::gen_account_in;

static STARTER_DOMAIN: Lazy<DomainId> = Lazy::new(|| "start".parse().unwrap());
static STARTER_KEYPAIR: Lazy<KeyPair> = Lazy::new(|| KeyPair::random());
static STARTER_ID: Lazy<AccountId> =
    Lazy::new(|| AccountId::new(STARTER_DOMAIN.clone(), STARTER_KEYPAIR.public_key().clone()));

const TRANSACTION_LIMITS: TransactionLimits = TransactionLimits {
    max_instruction_number: 4096,
    max_wasm_size_bytes: 0,
};

fn build_test_transaction(chain_id: ChainId) -> SignedTransaction {
    let domain_id: DomainId = "domain".parse().unwrap();
    let create_domain: InstructionBox = Register::domain(Domain::new(domain_id.clone())).into();
    let create_account = Register::account(Account::new(gen_account_in(&domain_id).0)).into();
    let asset_definition_id = "xor#domain".parse().unwrap();
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id)).into();
    let instructions = [create_domain, create_account, create_asset];

    TransactionBuilder::new(chain_id, STARTER_ID.clone())
        .with_instructions(instructions)
        .sign(&STARTER_KEYPAIR)
}

fn build_test_and_transient_state() -> State {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::test().start();

    let state = State::new(
        {
            let (account_id, _account_keypair) = gen_account_in(&*STARTER_DOMAIN);
            let mut domain = Domain::new(STARTER_DOMAIN.clone()).build(&account_id);
            let account = Account::new(account_id.clone()).build(&account_id);
            assert!(domain.add_account(account).is_none());
            World::with([domain], UniqueVec::new())
        },
        kura,
        query_handle,
    );

    {
        let mut state_block = state.block();
        let mut state_transaction = state_block.transaction();
        let path_to_executor = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/swarm/executor.wasm");
        let wasm = std::fs::read(&path_to_executor)
            .unwrap_or_else(|_| panic!("Failed to read file: {}", path_to_executor.display()));
        let executor = Executor::new(WasmSmartContract::from_compiled(wasm));
        let (authority, _authority_keypair) = gen_account_in("genesis");
        Upgrade::new(executor)
            .execute(&authority, &mut state_transaction)
            .expect("Failed to load executor");
        state_transaction.apply();
        state_block.commit();
    }

    state
}

fn accept_transaction(criterion: &mut Criterion) {
    let chain_id = ChainId::from("0");

    let transaction = build_test_transaction(chain_id.clone());
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("accept", |b| {
        b.iter(|| {
            match AcceptedTransaction::accept(transaction.clone(), &chain_id, &TRANSACTION_LIMITS) {
                Ok(_) => success_count += 1,
                Err(_) => failures_count += 1,
            }
        });
    });
    println!("Success count: {success_count}, Failures count: {failures_count}");
}

fn sign_transaction(criterion: &mut Criterion) {
    let chain_id = ChainId::from("0");

    let transaction = build_test_transaction(chain_id);
    let key_pair = KeyPair::random();
    let mut count = 0;
    let _ = criterion.bench_function("sign", |b| {
        b.iter_batched(
            || transaction.clone(),
            |transaction| {
                let _: SignedTransaction = transaction.sign(&key_pair);
                count += 1;
            },
            BatchSize::SmallInput,
        );
    });
    println!("Count: {count}");
}

fn validate_transaction(criterion: &mut Criterion) {
    let chain_id = ChainId::from("0");

    let transaction = AcceptedTransaction::accept(
        build_test_transaction(chain_id.clone()),
        &chain_id,
        &TRANSACTION_LIMITS,
    )
    .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failure_count = 0;
    let state = build_test_and_transient_state();
    let _ = criterion.bench_function("validate", move |b| {
        let transaction_executor = TransactionExecutor::new(TRANSACTION_LIMITS);
        b.iter(|| {
            let mut state_block = state.block();
            match transaction_executor.validate(transaction.clone(), &mut state_block) {
                Ok(_) => success_count += 1,
                Err(_) => failure_count += 1,
            }
        });
    });
    println!("Success count: {success_count}, Failure count: {failure_count}");
}

fn sign_blocks(criterion: &mut Criterion) {
    let chain_id = ChainId::from("0");

    let transaction = AcceptedTransaction::accept(
        build_test_transaction(chain_id.clone()),
        &chain_id,
        &TRANSACTION_LIMITS,
    )
    .expect("Failed to accept transaction.");
    let key_pair = KeyPair::random();
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::test().start();
    let state = State::new(World::new(), kura, query_handle);
    let topology = Topology::new(UniqueVec::new());

    let mut count = 0;

    let mut state_block = state.block();
    let block =
        BlockBuilder::new(vec![transaction], topology, Vec::new()).chain(0, &mut state_block);

    let _ = criterion.bench_function("sign_block", |b| {
        b.iter_batched(
            || block.clone(),
            |block| {
                let _: ValidBlock = block.sign(&key_pair).unpack(|_| {});
                count += 1;
            },
            BatchSize::SmallInput,
        );
    });
    println!("Count: {count}");
}

criterion_group!(
    transactions,
    accept_transaction,
    sign_transaction,
    validate_transaction
);
criterion_group!(blocks, sign_blocks);
criterion_main!(transactions, blocks);
