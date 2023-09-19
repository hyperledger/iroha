#![allow(missing_docs, clippy::restriction)]

use std::{collections::BTreeSet, str::FromStr as _};

use criterion::{criterion_group, criterion_main, Criterion};
use iroha_core::{
    block::*,
    prelude::*,
    smartcontracts::{isi::Registrable as _, Execute},
    sumeragi::network_topology::Topology,
    tx::TransactionValidator,
    wsv::World,
};
use iroha_data_model::{prelude::*, transaction::TransactionLimits};

const START_DOMAIN: &str = "start";
const START_ACCOUNT: &str = "starter";

const TRANSACTION_LIMITS: TransactionLimits = TransactionLimits {
    max_instruction_number: 4096,
    max_wasm_size_bytes: 0,
};

fn build_test_transaction(keys: KeyPair) -> VersionedSignedTransaction {
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
    let instructions = [create_domain, create_account, create_asset];

    TransactionBuilder::new(AccountId::new(
        START_ACCOUNT.parse().expect("Valid"),
        START_DOMAIN.parse().expect("Valid"),
    ))
    .with_instructions(instructions)
    .sign(keys)
    .expect("Failed to sign.")
}

fn build_test_and_transient_wsv(keys: KeyPair) -> WorldStateView {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let (public_key, _) = keys.into();

    let mut wsv = WorldStateView::new(
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
    );

    {
        let path_to_validator = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/peer/validator.wasm");
        let wasm = std::fs::read(&path_to_validator)
            .unwrap_or_else(|_| panic!("Failed to read file: {}", path_to_validator.display()));
        let validator = Validator::new(WasmSmartContract::from_compiled(wasm));
        let authority = "genesis@genesis".parse().expect("Valid");
        UpgradeBox::new(validator)
            .execute(&authority, &mut wsv)
            .expect("Failed to load validator");
    }

    wsv
}

fn accept_transaction(criterion: &mut Criterion) {
    let keys = KeyPair::generate().expect("Failed to generate keys");
    let transaction = build_test_transaction(keys);
    let mut success_count = 0;
    let mut failures_count = 0;
    let _ = criterion.bench_function("accept", |b| {
        b.iter(
            || match AcceptedTransaction::accept(transaction.clone(), &TRANSACTION_LIMITS) {
                Ok(_) => success_count += 1,
                Err(_) => failures_count += 1,
            },
        );
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
    let transaction =
        AcceptedTransaction::accept(build_test_transaction(keys.clone()), &TRANSACTION_LIMITS)
            .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failure_count = 0;
    let wsv = build_test_and_transient_wsv(keys);
    let _ = criterion.bench_function("validate", move |b| {
        let transaction_validator = TransactionValidator::new(TRANSACTION_LIMITS);
        b.iter(|| {
            let mut wsv = wsv.clone();
            match transaction_validator.validate(transaction.clone(), &mut wsv) {
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
        AcceptedTransaction::accept(build_test_transaction(keys), &TRANSACTION_LIMITS)
            .expect("Failed to accept transaction.");
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let mut wsv = WorldStateView::new(World::new(), kura);
    let topology = Topology::new(Vec::new());

    let mut success_count = 0;
    let mut failures_count = 0;

    let block = BlockBuilder::new(vec![transaction], topology, Vec::new()).chain_first(&mut wsv);

    let _ = criterion.bench_function("sign_block", |b| {
        b.iter(|| match block.clone().sign(key_pair.clone()) {
            Ok(_) => success_count += 1,
            Err(_) => failures_count += 1,
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
