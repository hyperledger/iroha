use criterion::*;
use futures::executor;
use iroha::{config::Configuration, isi::prelude::*, prelude::*};
use iroha_client::client::{assets, Client};
use std::thread;
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/test_config.json";

fn query_requests(criterion: &mut Criterion) {
    thread::spawn(|| create_and_start_iroha());
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("query-reqeuests");
    let domain_name = "domain2";
    let create_role = CreateRole {
        role_name: "user".to_string(),
        permissions: Vec::new(),
    };
    let create_domain = CreateDomain {
        domain_name: domain_name.to_string(),
    };
    let account_id = Id::new("account2", domain_name);
    let create_account = CreateAccount {
        account_id: account_id.clone(),
        domain_name: domain_name.to_string(),
        public_key: [63; 32],
    };
    let asset_id = Id::new("xor", domain_name);
    let create_asset = AddAssetQuantity {
        asset_id: asset_id.clone(),
        account_id: account_id.clone(),
        amount: 100,
    };
    let mut iroha_client = Client::new(
        &Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
    );
    executor::block_on(iroha_client.submit(create_role.into())).expect("Failed to create role.");
    executor::block_on(iroha_client.submit(create_domain.into()))
        .expect("Failed to create domain.");
    executor::block_on(iroha_client.submit(create_account.into()))
        .expect("Failed to create account.");
    executor::block_on(iroha_client.submit(create_asset.into())).expect("Failed to create asset.");
    let request = assets::by_account_id(account_id);
    thread::sleep(std::time::Duration::from_millis(1500));
    let mut success_count = 0;
    let mut failures_count = 0;
    group.throughput(Throughput::Bytes(Vec::from(&request).len() as u64));
    group.bench_function("query", |b| {
        b.iter(
            || match executor::block_on(iroha_client.request(&request)) {
                Ok(query_result) => {
                    let QueryResult::GetAccountAssets(result) = query_result;
                    assert!(!result.assets.is_empty());
                    success_count += 1;
                }
                Err(e) => {
                    eprintln!("Query failed: {}", e);
                    failures_count += 1;
                }
            },
        );
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
    group.finish();
}

fn instruction_submits(criterion: &mut Criterion) {
    thread::spawn(|| create_and_start_iroha());
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("command-reqeuests");
    let create_role = CreateRole {
        role_name: "user".to_string(),
        permissions: Vec::new(),
    };
    let create_domain = CreateDomain {
        domain_name: "domain".to_string(),
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
        &Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
    );
    executor::block_on(iroha_client.submit(create_role.into())).expect("Failed to create role.");
    executor::block_on(iroha_client.submit(create_domain.into()))
        .expect("Failed to create domain.");
    executor::block_on(iroha_client.submit(create_account.into()))
        .expect("Failed to create account.");
    thread::sleep(std::time::Duration::from_millis(500));
    group.throughput(Throughput::Bytes(Vec::from(&create_asset).len() as u64));
    let mut success_count = 0;
    let mut failures_count = 0;
    group.bench_function("commands", |b| {
        b.iter(
            || match executor::block_on(iroha_client.submit(create_asset.clone().into())) {
                Ok(_) => success_count += 1,
                Err(e) => {
                    eprintln!("Failed to execute instruction: {}", e);
                    failures_count += 1;
                }
            },
        )
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
    group.finish();
}

fn create_and_start_iroha() {
    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.kura_block_store_path(temp_dir.path());
    let iroha = Iroha::new(configuration);
    iroha.start().expect("Failed to start Iroha.");
    //Prevents temp_dir from clean up untill the end of the tests.
    loop {}
}

criterion_group!(instructions, instruction_submits);
criterion_group!(queries, query_requests);
criterion_main!(queries, instructions);
