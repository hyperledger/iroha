#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, Criterion};
use iroha::{prelude::*, tx::AcceptedTransaction};
use iroha_data_model::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

const TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;

const START_DOMAIN: &str = "start";
const START_ACCOUNT: &str = "starter";

fn build_test_transaction(keys: &KeyPair) -> Transaction {
    let domain_name = "domain";
    let create_domain = RegisterBox::new(IdentifiableBox::Domain(Domain::new(domain_name).into()));
    let account_name = "account";
    let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
        NewAccount::with_signatory(
            AccountId::new(account_name, domain_name),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        )
        .into(),
    ));
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new(asset_definition_id, AssetValueType::Quantity).into(),
    ));
    Transaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new(START_ACCOUNT, START_DOMAIN),
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(keys)
    .expect("Failed to sign.")
}

fn build_test_wsv(keys: &KeyPair) -> WorldStateView {
    WorldStateView::new({
        let mut domains = BTreeMap::new();
        let mut domain = Domain::new(START_DOMAIN);
        let account_id = AccountId::new(START_ACCOUNT, START_DOMAIN);
        let mut account = Account::new(account_id.clone());
        account.signatories.push(keys.public_key.clone());
        let _ = domain.accounts.insert(account_id, account);
        let _ = domains.insert(START_DOMAIN.to_string(), domain);
        World::with(domains, BTreeSet::new())
    })
}

fn accept_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = build_test_transaction(&keys);
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("accept", |b| {
        b.iter(
            || match AcceptedTransaction::from_transaction(transaction.clone(), 4096) {
                Ok(_) => success_count += 1,
                Err(_) => failures_count += 1,
            },
        );
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
}

fn sign_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = build_test_transaction(&keys);
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("sign", |b| {
        b.iter(|| match transaction.clone().sign(&key_pair) {
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
    let transaction = AcceptedTransaction::from_transaction(build_test_transaction(&keys), 4096)
        .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let world_state_view = build_test_wsv(&keys);
    let _ = criterion.bench_function("validate", |b| {
        b.iter(|| {
            match transaction
                .clone()
                .validate(&world_state_view, &AllowAll.into(), false)
            {
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

fn chain_blocks(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = AcceptedTransaction::from_transaction(build_test_transaction(&keys), 4096)
        .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction.into()]);
    let mut previous_block_hash = block.clone().chain_first().hash();
    let mut success_count = 0;
    let _ = criterion.bench_function("chain_block", |b| {
        b.iter(|| {
            success_count += 1;
            let new_block = block
                .clone()
                .chain(success_count, previous_block_hash, 0, Vec::new());
            previous_block_hash = new_block.hash();
        });
    });
    println!("Total count: {}", success_count);
}

fn sign_blocks(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = AcceptedTransaction::from_transaction(build_test_transaction(&keys), 4096)
        .expect("Failed to accept transaction.");
    let world_state_view = build_test_wsv(&keys);
    let block = PendingBlock::new(vec![transaction.into()])
        .chain_first()
        .validate(&world_state_view, &AllowAll.into());
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("sign_block", |b| {
        b.iter(|| match block.clone().sign(&key_pair) {
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
    let domain_name = "global".to_string();
    let asset_definitions = BTreeMap::new();
    let account_id = AccountId::new("root", &domain_name);
    let account = Account::with_signatory(account_id.clone(), key_pair.public_key);
    let mut accounts = BTreeMap::new();
    let _ = accounts.insert(account_id, account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    let _ = domains.insert(domain_name, domain);
    let world_state_view = WorldStateView::new(World::with(domains, BTreeSet::new()));
    // Pepare test transaction
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = AcceptedTransaction::from_transaction(build_test_transaction(&keys), 4096)
        .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction.into()]).chain_first();
    let _ = criterion.bench_function("validate_block", |b| {
        b.iter(|| block.clone().validate(&world_state_view, &AllowAll.into()));
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
