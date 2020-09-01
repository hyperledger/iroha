use criterion::*;
use iroha::{prelude::*, tx::Accept};
use iroha_data_model::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

const TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;

fn accept_transaction(criterion: &mut Criterion) {
    let domain_name = "domain";
    let create_domain = Register::<Peer, Domain>::new(
        Domain::new(domain_name),
        PeerId::new(
            "127.0.0.1:8080",
            &KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        ),
    );
    let account_name = "account";
    let create_account = Register::<Domain, Account>::new(
        Account::with_signatory(
            AccountId::new(account_name, domain_name),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        ),
        domain_name.to_string(),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id),
        domain_name.to_string(),
    );
    let transaction = Transaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(&KeyPair::generate().expect("Failed to generate keypair."))
    .expect("Failed to sign.");
    let mut success_count = 0;
    let mut failures_count = 0;
    criterion.bench_function("accept", |b| {
        b.iter(|| match transaction.clone().accept() {
            Ok(_) => success_count += 1,
            Err(_) => failures_count += 1,
        });
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
}

fn sign_transaction(criterion: &mut Criterion) {
    let domain_name = "domain";
    let create_domain = Register::<Peer, Domain>::new(
        Domain::new(domain_name),
        PeerId::new(
            "127.0.0.1:8080",
            &KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        ),
    );
    let account_name = "account";
    let create_account = Register::<Domain, Account>::new(
        Account::with_signatory(
            AccountId::new(account_name, domain_name),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        ),
        domain_name.to_string(),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id),
        domain_name.to_string(),
    );
    let transaction = Transaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
        TRANSACTION_TIME_TO_LIVE_MS,
    );
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let mut success_count = 0;
    let mut failures_count = 0;
    criterion.bench_function("sign", |b| {
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
    let domain_name = "domain";
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let create_domain = Register::<Peer, Domain>::new(
        Domain::new(domain_name),
        PeerId::new("127.0.0.1:8080", &key_pair.public_key),
    );
    let account_name = "account";
    let create_account = Register::<Domain, Account>::new(
        Account::with_signatory(
            AccountId::new(account_name, domain_name),
            key_pair.public_key.clone(),
        ),
        domain_name.to_string(),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id),
        domain_name.to_string(),
    );
    let transaction = Transaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(&key_pair)
    .expect("Failed to sign transaction.")
    .accept()
    .expect("Failed to accept transaction.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let mut world_state_view = WorldStateView::new(Peer::new(PeerId::new(
        "127.0.0.1:8080",
        &key_pair.public_key,
    )));
    criterion.bench_function("validate", |b| {
        b.iter(
            || match transaction.clone().validate(&mut world_state_view) {
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

fn chain_blocks(criterion: &mut Criterion) {
    let domain_name = "domain";
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let create_domain = Register::<Peer, Domain>::new(
        Domain::new(domain_name),
        PeerId::new("127.0.0.1:8080", &key_pair.public_key),
    );
    let account_name = "account";
    let create_account = Register::<Domain, Account>::new(
        Account::with_signatory(
            AccountId::new(account_name, domain_name),
            key_pair.public_key.clone(),
        ),
        domain_name.to_string(),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id),
        domain_name.to_string(),
    );
    let transaction = Transaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(&key_pair)
    .expect("Failed to sign.")
    .accept()
    .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction]);
    let mut previous_block_hash = block.clone().chain_first().hash();
    let mut success_count = 0;
    criterion.bench_function("chain_block", |b| {
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
    let domain_name = "domain";
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let create_domain = Register::<Peer, Domain>::new(
        Domain::new(domain_name),
        PeerId::new("127.0.0.1:8080", &key_pair.public_key),
    );
    let account_name = "account";
    let create_account = Register::<Domain, Account>::new(
        Account::with_signatory(
            AccountId::new(account_name, domain_name),
            key_pair.public_key.clone(),
        ),
        domain_name.to_string(),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id),
        domain_name.to_string(),
    );
    let transaction = Transaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(&key_pair)
    .expect("Failed to sign.")
    .accept()
    .expect("Failed to accept transaction.");
    let world_state_view = WorldStateView::new(Peer::new(PeerId::new(
        "127.0.0.1:8080",
        &key_pair.public_key,
    )));
    let block = PendingBlock::new(vec![transaction])
        .chain_first()
        .validate(&world_state_view);
    let mut success_count = 0;
    let mut failures_count = 0;
    criterion.bench_function("sign_block", |b| {
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
    let account = Account::with_signatory(account_id.clone(), key_pair.public_key.clone());
    let mut accounts = BTreeMap::new();
    accounts.insert(account_id, account);
    let domain = Domain {
        name: domain_name.clone(),
        accounts,
        asset_definitions,
    };
    let mut domains = BTreeMap::new();
    domains.insert(domain_name, domain);
    let world_state_view = WorldStateView::new(Peer::with(
        PeerId::new("127.0.0.1:8080", &key_pair.public_key),
        domains,
        BTreeSet::new(),
    ));
    // Pepare test transaction
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let domain_name = "domain";
    let create_domain = Register::<Peer, Domain>::new(
        Domain::new(domain_name),
        PeerId::new("127.0.0.1:8080", &key_pair.public_key),
    );
    let account_name = "account";
    let create_account = Register::<Domain, Account>::new(
        Account::with_signatory(
            AccountId::new(account_name, domain_name),
            key_pair.public_key.clone(),
        ),
        domain_name.to_string(),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id),
        domain_name.to_string(),
    );
    let transaction = Transaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("root", "global"),
        TRANSACTION_TIME_TO_LIVE_MS,
    )
    .sign(&key_pair)
    .expect("Failed to sign.")
    .accept()
    .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction]).chain_first();
    criterion.bench_function("validate_block", |b| {
        b.iter(|| block.clone().validate(&world_state_view));
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
