use criterion::*;
use iroha::{crypto, isi, prelude::*};

fn accept_transaction(criterion: &mut Criterion) {
    let domain_name = "domain";
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: iroha::peer::PeerId::current(),
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::new(account_name, domain_name, [0; 32]),
        destination_id: String::from(domain_name),
    };
    let asset_id = AssetId::new("xor", domain_name, account_name);
    let create_asset = isi::Register {
        object: Asset::new(asset_id.clone()).with_quantity(0),
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
        destination_id: iroha::peer::PeerId::current(),
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::new(account_name, domain_name, [0; 32]),
        destination_id: String::from(domain_name),
    };
    let asset_id = AssetId::new("xor", domain_name, account_name);
    let create_asset = isi::Register {
        object: Asset::new(asset_id.clone()).with_quantity(0),
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
    let (public_key, private_key) =
        crypto::generate_key_pair().expect("Failed to generate key pair.");
    let mut success_count = 0;
    let mut failures_count = 0;
    criterion.bench_function("sign", |b| {
        b.iter(
            || match transaction.clone().sign(&public_key, &private_key) {
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

fn validate_transaction(criterion: &mut Criterion) {
    let domain_name = "domain";
    let (public_key, private_key) =
        crypto::generate_key_pair().expect("Failed to generate key pair.");
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: iroha::peer::PeerId::current(),
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::new(account_name, domain_name, public_key),
        destination_id: String::from(domain_name),
    };
    let asset_id = AssetId::new("xor", domain_name, account_name);
    let create_asset = isi::Register {
        object: Asset::new(asset_id.clone()).with_quantity(0),
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
    .sign(&public_key, &private_key)
    .expect("Failed to sign transaction.");
    let mut success_count = 0;
    let mut failures_count = 0;
    let mut world_state_view = WorldStateView::new(Peer::new("127.0.0.1".to_string(), &Vec::new()));
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
    let (public_key, _private_key) =
        crypto::generate_key_pair().expect("Failed to generate key pair.");
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: iroha::peer::PeerId::current(),
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::new(account_name, domain_name, public_key),
        destination_id: String::from(domain_name),
    };
    let asset_id = AssetId::new("xor", domain_name, account_name);
    let create_asset = isi::Register {
        object: Asset::new(asset_id.clone()).with_quantity(0),
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
            let new_block = block.clone().chain(success_count, previous_block_hash);
            previous_block_hash = new_block.hash();
        });
    });
    println!("Total count: {}", success_count);
}

fn sign_blocks(criterion: &mut Criterion) {
    let domain_name = "domain";
    let (public_key, private_key) =
        crypto::generate_key_pair().expect("Failed to generate key pair.");
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: iroha::peer::PeerId::current(),
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::new(account_name, domain_name, public_key),
        destination_id: String::from(domain_name),
    };
    let asset_id = AssetId::new("xor", domain_name, account_name);
    let create_asset = isi::Register {
        object: Asset::new(asset_id.clone()).with_quantity(0),
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
        b.iter(|| match block.clone().sign(&public_key, &private_key) {
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
    let (public_key, private_key) =
        crypto::generate_key_pair().expect("Failed to generate key pair.");
    let create_domain = isi::Add {
        object: Domain::new(domain_name.to_string()),
        destination_id: iroha::peer::PeerId::current(),
    };
    let account_name = "account";
    let create_account = isi::Register {
        object: Account::new(account_name, domain_name, public_key),
        destination_id: String::from(domain_name),
    };
    let asset_id = AssetId::new("xor", domain_name, account_name);
    let create_asset = isi::Register {
        object: Asset::new(asset_id.clone()).with_quantity(0),
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
        .sign(&public_key, &private_key)
        .expect("Failed to sign a block.");
    let mut world_state_view = WorldStateView::new(Peer::new("127.0.0.1".to_string(), &Vec::new()));
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
