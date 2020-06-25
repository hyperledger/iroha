use criterion::*;
use iroha::{isi, peer::PeerId, prelude::*};

fn accept_transaction(criterion: &mut Criterion) {
    let domain_name = "domain";
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::with_signatory(
            account_name,
            domain_name,
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        ),
        destination_id: String::from(domain_name),
    };
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = isi::Register {
        object: AssetDefinition::new(asset_definition_id.clone()),
        destination_id: domain_name.to_string(),
    };
    let transaction = RequestedTransaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
    );
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
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        },
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::with_signatory(
            account_name,
            domain_name,
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        ),
        destination_id: String::from(domain_name),
    };
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = isi::Register {
        object: AssetDefinition::new(asset_definition_id.clone()),
        destination_id: domain_name.to_string(),
    };
    let transaction = RequestedTransaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
    )
    .accept()
    .expect("Failed to accept transaction.");
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
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: key_pair.public_key.clone(),
        },
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::with_signatory(account_name, domain_name, key_pair.public_key.clone()),
        destination_id: String::from(domain_name),
    };
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = isi::Register {
        object: AssetDefinition::new(asset_definition_id.clone()),
        destination_id: domain_name.to_string(),
    };
    let transaction = RequestedTransaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
    )
    .accept()
    .expect("Failed to accept transaction.")
    .sign(&key_pair)
    .expect("Failed to sign transaction.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let mut world_state_view = WorldStateView::new(Peer::new(
        PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: key_pair.public_key.clone(),
        },
        &Vec::new(),
    ));
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
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: key_pair.public_key.clone(),
        },
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::with_signatory(account_name, domain_name, key_pair.public_key.clone()),
        destination_id: String::from(domain_name),
    };
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = isi::Register {
        object: AssetDefinition::new(asset_definition_id.clone()),
        destination_id: domain_name.to_string(),
    };
    let transaction = RequestedTransaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
    )
    .accept()
    .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction]);
    let mut previous_block_hash = block.clone().chain_first().hash();
    let mut success_count = 0;
    criterion.bench_function("chain_block", |b| {
        b.iter(|| {
            success_count += 1;
            let new_block = block.clone().chain(success_count, previous_block_hash, 0);
            previous_block_hash = new_block.hash();
        });
    });
    println!("Total count: {}", success_count);
}

fn sign_blocks(criterion: &mut Criterion) {
    let domain_name = "domain";
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: key_pair.public_key,
        },
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::with_signatory(account_name, domain_name, key_pair.public_key.clone()),
        destination_id: String::from(domain_name),
    };
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = isi::Register {
        object: AssetDefinition::new(asset_definition_id.clone()),
        destination_id: domain_name.to_string(),
    };
    let transaction = RequestedTransaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
    )
    .accept()
    .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction]).chain_first();
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
    let domain_name = "domain";
    let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: key_pair.public_key,
        },
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::with_signatory(account_name, domain_name, key_pair.public_key.clone()),
        destination_id: String::from(domain_name),
    };
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = isi::Register {
        object: AssetDefinition::new(asset_definition_id.clone()),
        destination_id: domain_name.to_string(),
    };
    let transaction = RequestedTransaction::new(
        vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
        ],
        AccountId::new("account", "domain"),
    )
    .accept()
    .expect("Failed to accept transaction.");
    let block = PendingBlock::new(vec![transaction])
        .chain_first()
        .sign(&key_pair)
        .expect("Failed to sign a block.");
    let mut world_state_view = WorldStateView::new(Peer::new(
        PeerId {
            address: "127.0.0.1:8080".to_string(),
            public_key: key_pair.public_key,
        },
        &Vec::new(),
    ));
    let mut success_count = 0;
    let mut failures_count = 0;
    criterion.bench_function("validate_block", |b| {
        b.iter(|| match block.clone().validate(&mut world_state_view) {
            Ok(_) => success_count += 1,
            Err(_) => failures_count += 1,
        });
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
}

criterion_group!(
    transactions,
    accept_transaction,
    sign_transaction,
    validate_transaction
);
criterion_group!(blocks, chain_blocks, sign_blocks, validate_blocks);
criterion_main!(transactions, blocks);
