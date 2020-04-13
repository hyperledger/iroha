use criterion::*;
use futures::executor;
use iroha::{config::Configuration, isi::prelude::*, prelude::*};
use iroha_client::client::{assets, Client};
use std::thread;

static DEFAULT_BLOCK_STORE_LOCATION: &str = "./blocks/";
const CONFIGURATION_PATH: &str = "config.json";

fn query_requests(criterion: &mut Criterion) {
    thread::spawn(|| executor::block_on(create_and_start_iroha()));
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("query-reqeuests");
    let create_role = CreateRole {
        role_name: "user".to_string(),
        permissions: Vec::new(),
    };
    let create_domain = CreateDomain {
        domain_name: "domain".to_string(),
        default_role: "user".to_string(),
    };
    let account_id = Id::new("account", "domain");
    let create_account = CreateAccount {
        account_id: account_id.clone(),
        domain_name: "domain".to_string(),
        public_key: [63; 32],
    };
    let asset_id = Id::new("xor", "domain");
    let create_asset = AddAssetQuantity {
        asset_id: asset_id.clone(),
        account_id: account_id.clone(),
        amount: 100,
    };
    let mut iroha_client = Client::new(
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
    );
    iroha_client
        .submit(create_role.into())
        .expect("Failed to create role.");
    iroha_client
        .submit(create_domain.into())
        .expect("Failed to create domain.");
    iroha_client
        .submit(create_account.into())
        .expect("Failed to create account1.");
    iroha_client
        .submit(create_asset.into())
        .expect("Failed to create asset.");
    let request = assets::by_account_id(account_id);
    group.throughput(Throughput::Bytes(Vec::from(&request).len() as u64));
    group.bench_function("query", |b| {
        b.iter(|| {
            let query_result = iroha_client
                .request(&request)
                .expect("Failed to execute request.");
            let QueryResult::GetAccountAssets(result) = query_result;
            assert!(!result.assets.is_empty());
        });
    });
    group.finish();
}

fn command_requests(criterion: &mut Criterion) {
    thread::spawn(|| executor::block_on(create_and_start_iroha()));
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("command-reqeuests");
    let create_role = CreateRole {
        role_name: "user".to_string(),
        permissions: Vec::new(),
    };
    let create_domain = CreateDomain {
        domain_name: "domain".to_string(),
        default_role: "user".to_string(),
    };
    let account_id = Id::new("account", "domain");
    let create_account = CreateAccount {
        account_id: account_id.clone(),
        domain_name: "domain".to_string(),
        public_key: [63; 32],
    };
    let asset_id = Id::new("xor", "domain");
    let create_asset = AddAssetQuantity {
        asset_id: asset_id.clone(),
        account_id: account_id.clone(),
        amount: 100,
    };
    let mut iroha_client = Client::new(
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
    );
    iroha_client
        .submit(create_role.into())
        .expect("Failed to create role.");
    iroha_client
        .submit(create_domain.into())
        .expect("Failed to create domain.");
    iroha_client
        .submit(create_account.into())
        .expect("Failed to create account1.");
    group.throughput(Throughput::Bytes(Vec::from(&create_asset).len() as u64));
    group.bench_function("commands", |b| {
        b.iter(|| {
            iroha_client
                .submit(create_asset.clone().into())
                .expect("Failed to create asset.");
        })
    });
    group.finish();
}

async fn create_and_start_iroha() {
    let mut iroha = Iroha::new(
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
    );
    iroha.start().await.expect("Failed to start Iroha.");
}

criterion_group!(queries, query_requests);
criterion_group!(commands, command_requests);
criterion_main!(queries, commands);
