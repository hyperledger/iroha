#![allow(missing_docs)]

use std::str::FromStr as _;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use iroha_core::{
    block::*,
    prelude::*,
    query::store::LiveQueryStore,
    smartcontracts::{isi::Registrable as _, Execute},
    sumeragi::network_topology::Topology,
    tx::TransactionExecutor,
    wsv::World,
};
use iroha_data_model::{isi::InstructionBox, prelude::*, transaction::TransactionLimits};
use iroha_primitives::unique_vec::UniqueVec;

const START_DOMAIN: &str = "start";
const START_ACCOUNT: &str = "starter";

const TRANSACTION_LIMITS: TransactionLimits = TransactionLimits {
    max_instruction_number: 4096,
    max_wasm_size_bytes: 0,
};

fn build_test_transaction(keys: &KeyPair, chain_id: ChainId) -> SignedTransaction {
    let domain_name = "domain";
    let domain_id = DomainId::from_str(domain_name).expect("does not panic");
    let create_domain: InstructionBox = Register::domain(Domain::new(domain_id)).into();
    let account_name = "account";
    let (public_key, _) = KeyPair::generate().into();
    let create_account = Register::account(Account::new(
        AccountId::new(
            domain_name.parse().expect("Valid"),
            account_name.parse().expect("Valid"),
        ),
        [public_key],
    ))
    .into();
    let asset_definition_id = AssetDefinitionId::new(
        "xor".parse().expect("Valid"),
        domain_name.parse().expect("Valid"),
    );
    let create_asset =
        Register::asset_definition(AssetDefinition::quantity(asset_definition_id)).into();
    let instructions = [create_domain, create_account, create_asset];

    TransactionBuilder::new(
        chain_id,
        AccountId::new(
            START_DOMAIN.parse().expect("Valid"),
            START_ACCOUNT.parse().expect("Valid"),
        ),
    )
    .with_instructions(instructions)
    .sign(keys)
}

fn build_test_and_transient_wsv(keys: KeyPair) -> WorldStateView {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::test().start();
    let (public_key, _) = keys.into();

    let mut wsv = WorldStateView::new(
        {
            let domain_id = DomainId::from_str(START_DOMAIN).expect("Valid");
            let account_id = AccountId::new(
                domain_id.clone(),
                Name::from_str(START_ACCOUNT).expect("Valid"),
            );
            let mut domain = Domain::new(domain_id).build(&account_id);
            let account = Account::new(account_id.clone(), [public_key]).build(&account_id);
            assert!(domain.add_account(account).is_none());
            World::with([domain], UniqueVec::new())
        },
        kura,
        query_handle,
    );

    {
        let path_to_executor = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../config_samples/swarm/executor.wasm");
        let wasm = std::fs::read(&path_to_executor)
            .unwrap_or_else(|_| panic!("Failed to read file: {}", path_to_executor.display()));
        let executor = Executor::new(WasmSmartContract::from_compiled(wasm));
        let authority = "genesis@genesis".parse().expect("Valid");
        Upgrade::new(executor)
            .execute(&authority, &mut wsv)
            .expect("Failed to load executor");
    }

    wsv
}

fn accept_transaction(criterion: &mut Criterion) {
    let chain_id = ChainId::from("0");

    let keys = KeyPair::generate();
    let transaction = build_test_transaction(&keys, chain_id.clone());
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

    let keys = KeyPair::generate();
    let transaction = build_test_transaction(&keys, chain_id);
    let key_pair = KeyPair::generate();
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

    let keys = KeyPair::generate();
    let transaction = AcceptedTransaction::accept(
        build_test_transaction(&keys, chain_id.clone()),
        &chain_id,
        &TRANSACTION_LIMITS,
    )
    .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failure_count = 0;
    let wsv = build_test_and_transient_wsv(keys);
    let _ = criterion.bench_function("validate", move |b| {
        let transaction_executor = TransactionExecutor::new(TRANSACTION_LIMITS);
        b.iter(|| {
            let mut wsv = wsv.clone();
            match transaction_executor.validate(transaction.clone(), &mut wsv) {
                Ok(_) => success_count += 1,
                Err(_) => failure_count += 1,
            }
        });
    });
    println!("Success count: {success_count}, Failure count: {failure_count}");
}

fn sign_blocks(criterion: &mut Criterion) {
    let chain_id = ChainId::from("0");

    let keys = KeyPair::generate();
    let transaction = AcceptedTransaction::accept(
        build_test_transaction(&keys, chain_id.clone()),
        &chain_id,
        &TRANSACTION_LIMITS,
    )
    .expect("Failed to accept transaction.");
    let key_pair = KeyPair::generate();
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::test().start();
    let mut wsv = WorldStateView::new(World::new(), kura, query_handle);
    let topology = Topology::new(UniqueVec::new());

    let mut count = 0;

    let block = BlockBuilder::new(vec![transaction], topology, Vec::new()).chain(0, &mut wsv);

    let _ = criterion.bench_function("sign_block", |b| {
        b.iter_batched(
            || block.clone(),
            |block| {
                let _: ValidBlock = block.sign(&key_pair);
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
