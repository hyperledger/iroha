#![allow(missing_docs, clippy::restriction)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use criterion::{criterion_group, criterion_main, Criterion};
use iroha_core::{
    prelude::*,
    sumeragi::view_change,
    tx::{AcceptedTransaction, TransactionValidator},
    wsv::{World, WorldTrait},
};
use iroha_data_model::prelude::*;

const TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;

const START_DOMAIN: &str = "start";
const START_ACCOUNT: &str = "starter";

const TRANSACTION_LIMITS: TransactionLimits = TransactionLimits {
    max_instruction_number: 4096,
    max_wasm_size_bytes: 0,
};

fn build_test_transaction(keys: KeyPair) -> Transaction {
    let domain_name = "domain";
    let create_domain = RegisterBox::new(IdentifiableBox::Domain(
        Domain::new(DomainId::new(domain_name).expect("does not panic")).into(),
    ));
    let account_name = "account";
    let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
        NewAccount::with_signatory(
            AccountId::new(account_name, domain_name).expect("does not panic"),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        )
        .into(),
    ));
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new(
            asset_definition_id.expect("valid definition id"),
            AssetValueType::Quantity,
            true,
        )
        .into(),
    ));
    let instructions: Vec<Instruction> = vec![
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ];
    Transaction::new(
        AccountId::new(START_ACCOUNT, START_DOMAIN).expect("valid START ACCOUNT and START_DOMAIN"),
        instructions.into(),
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(keys)
    .expect("Failed to sign.")
}

fn build_test_wsv(keys: KeyPair) -> WorldStateView<World> {
    WorldStateView::new({
        let mut domains = BTreeMap::new();
        let mut domain = Domain::test(START_DOMAIN);
        let account_id = AccountId::test(START_ACCOUNT, START_DOMAIN);
        let mut account = Account::new(account_id.clone());
        account.signatories.push(keys.public_key);
        domain.accounts.insert(account_id, account);
        domains.insert(DomainId::test(START_DOMAIN), domain);
        World::with(domains, BTreeSet::new())
    })
}

fn accept_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = build_test_transaction(keys);
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("accept", |b| {
        b.iter(|| {
            match AcceptedTransaction::from_transaction(transaction.clone(), &TRANSACTION_LIMITS) {
                Ok(_) => success_count += 1,
                Err(_) => failures_count += 1,
            }
        });
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
}

fn sign_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = build_test_transaction(keys);
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("sign", |b| {
        b.iter(|| match transaction.clone().sign(key_pair.clone()) {
            Ok(_) => success_count += 1,
            Err(_) => failures_count += 1,
        });
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
}

fn validate_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = AcceptedTransaction::from_transaction(
        build_test_transaction(keys.clone()),
        &TRANSACTION_LIMITS,
    )
    .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failure_count = 0;
    let _ = criterion.bench_function("validate", move |b| {
        let transaction_validator = TransactionValidator::new(
            TRANSACTION_LIMITS,
            AllowAll::new(),
            AllowAll::new(),
            Arc::new(build_test_wsv(keys.clone())),
        );
        b.iter(
            || match transaction_validator.validate(transaction.clone(), false) {
                Ok(_) => success_count += 1,
                Err(_) => failure_count += 1,
            },
        );
    });
    println!(
        "Success count: {}, Failure count: {}",
        success_count, failure_count
    );
}

fn chain_blocks(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction =
        AcceptedTransaction::from_transaction(build_test_transaction(keys), &TRANSACTION_LIMITS)
            .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction.into()], Vec::new());
    let mut previous_block_hash = block.clone().chain_first().hash();
    let mut success_count = 0;
    let _ = criterion.bench_function("chain_block", |b| {
        b.iter(|| {
            success_count += 1;
            let new_block = block.clone().chain(
                success_count,
                previous_block_hash.transmute(),
                view_change::ProofChain::empty(),
                Vec::new(),
            );
            previous_block_hash = new_block.hash();
        });
    });
    println!("Total count: {}", success_count);
}

fn sign_blocks(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = AcceptedTransaction::from_transaction(
        build_test_transaction(keys.clone()),
        &TRANSACTION_LIMITS,
    )
    .expect("Failed to accept transaction.");
    let transaction_validator = TransactionValidator::new(
        TRANSACTION_LIMITS,
        AllowAll::new(),
        AllowAll::new(),
        Arc::new(build_test_wsv(keys)),
    );
    let block = PendingBlock::new(vec![transaction.into()], Vec::new())
        .chain_first()
        .validate(&transaction_validator);
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("sign_block", |b| {
        b.iter(|| match block.clone().sign(key_pair.clone()) {
            Ok(_) => success_count += 1,
            Err(_) => failures_count += 1,
        });
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
}

fn validate_blocks(criterion: &mut Criterion) {
    // Prepare WSV
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let domain_name = "global";
    let asset_definitions = BTreeMap::new();
    let account_id = AccountId::test("root", domain_name);
    let account = Account::with_signatory(account_id.clone(), key_pair.public_key);
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id, account);
    let domain_id = DomainId::test(domain_name);
    let domain = Domain {
        id: domain_id.clone(),
        accounts,
        asset_definitions,
        metadata: Metadata::new(),
        logo: None,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_id, domain);
    // Pepare test transaction
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction =
        AcceptedTransaction::from_transaction(build_test_transaction(keys), &TRANSACTION_LIMITS)
            .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction.into()], Vec::new()).chain_first();
    let transaction_validator = TransactionValidator::new(
        TRANSACTION_LIMITS,
        AllowAll::new(),
        AllowAll::new(),
        Arc::new(WorldStateView::new(World::with(domains, BTreeSet::new()))),
    );
    let _ = criterion.bench_function("validate_block", |b| {
        b.iter(|| block.clone().validate(&transaction_validator));
    });
}

criterion_group!(
    transactions,
    accept_transaction,
    sign_transaction,
    validate_transaction
);
criterion_group!(blocks, chain_blocks, sign_blocks, validate_blocks);
criterion_main!(transactions, blocks);
