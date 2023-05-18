#![allow(missing_docs, clippy::restriction)]

use std::{collections::BTreeSet, str::FromStr as _, sync::Arc};

use criterion::{criterion_group, criterion_main, Criterion};
use iroha_core::{
    block::*, prelude::*, smartcontracts::isi::Registrable as _,
    sumeragi::network_topology::Topology, tx::TransactionValidator, wsv::World,
};
use iroha_data_model::prelude::*;

const TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;

const START_DOMAIN: &str = "start";
const START_ACCOUNT: &str = "starter";

const TRANSACTION_LIMITS: TransactionLimits = TransactionLimits {
    max_instruction_number: 4096,
    max_wasm_size_bytes: 0,
};

fn build_test_transaction(keys: KeyPair) -> SignedTransaction {
    let domain_name = "domain";
    let domain_id = DomainId::from_str(domain_name).expect("does not panic");
    let create_domain = RegisterBox::new(Domain::new(domain_id));
    let account_name = "account";
    let (public_key, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair.")
        .into();
    let create_account = RegisterBox::new(Account::new(
        AccountId::new(
            account_name.parse().expect("Valid"),
            domain_name.parse().expect("Valid"),
        ),
        [public_key],
    ));
    let asset_definition_id = AssetDefinitionId::new(
        "xor".parse().expect("Valid"),
        domain_name.parse().expect("Valid"),
    );
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id));
    let instructions: Vec<InstructionBox> = vec![
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ];
    TransactionBuilder::new(
        AccountId::new(
            START_ACCOUNT.parse().expect("Valid"),
            START_DOMAIN.parse().expect("Valid"),
        ),
        instructions,
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(keys)
    .expect("Failed to sign.")
}

fn build_test_and_transient_wsv(keys: KeyPair) -> WorldStateView {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let (public_key, _) = keys.into();

    WorldStateView::new(
        {
            let domain_id = DomainId::from_str(START_DOMAIN).expect("Valid");
            let account_id = AccountId::new(
                Name::from_str(START_ACCOUNT).expect("Valid"),
                domain_id.clone(),
            );
            let mut domain = Domain::new(domain_id).build(&account_id);
            let account = Account::new(account_id.clone(), [public_key]).build(&account_id);
            assert!(domain.add_account(account).is_none());
            World::with([domain], BTreeSet::new())
        },
        kura,
    )
}

fn accept_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = build_test_transaction(keys);
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("accept", |b| {
        b.iter(|| {
            match AcceptedTransaction::accept::<false>(transaction.clone(), &TRANSACTION_LIMITS) {
                Ok(_) => success_count += 1,
                Err(_) => failures_count += 1,
            }
        });
    });
    println!("Success count: {success_count}, Failures count: {failures_count}");
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
    println!("Success count: {success_count}, Failures count: {failures_count}");
}

fn validate_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = AcceptedTransaction::accept::<false>(
        build_test_transaction(keys.clone()),
        &TRANSACTION_LIMITS,
    )
    .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failure_count = 0;
    let _ = criterion.bench_function("validate", move |b| {
        let transaction_validator = TransactionValidator::new(TRANSACTION_LIMITS);
        b.iter(|| {
            match transaction_validator.validate(
                transaction.clone(),
                false,
                &Arc::new(build_test_and_transient_wsv(keys.clone())),
            ) {
                Ok(_) => success_count += 1,
                Err(_) => failure_count += 1,
            }
        });
    });
    println!("Success count: {success_count}, Failure count: {failure_count}");
}

fn sign_blocks(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction =
        AcceptedTransaction::accept::<false>(build_test_transaction(keys), &TRANSACTION_LIMITS)
            .expect("Failed to accept transaction.");
    let transaction_validator = TransactionValidator::new(TRANSACTION_LIMITS);
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();

    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("sign_block", |b| {
        b.iter(|| {
            let block = BlockBuilder {
                transactions: vec![transaction.clone().into()],
                event_recommendations: Vec::new(),
                height: 1,
                previous_block_hash: None,
                view_change_index: 0,
                committed_with_topology: Topology::new(Vec::new()),
                key_pair: key_pair.clone(),
                transaction_validator: &transaction_validator,
                wsv: WorldStateView::new(World::new(), kura.clone()),
            }
            .build();

            match block.sign(key_pair.clone()) {
                Ok(_) => success_count += 1,
                Err(_) => failures_count += 1,
            }
        });
    });
    println!("Success count: {success_count}, Failures count: {failures_count}");
}

criterion_group!(
    transactions,
    accept_transaction,
    sign_transaction,
    validate_transaction
);
criterion_group!(blocks, sign_blocks);
criterion_main!(transactions, blocks);
