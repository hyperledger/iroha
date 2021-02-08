use async_std::task;
use criterion::*;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{
    client::{asset, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
use log::LevelFilter;
use std::thread;
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
const MINIMUM_SUCCESS_REQUEST_RATIO: f32 = 0.9;

fn query_requests(criterion: &mut Criterion) {
    thread::spawn(create_and_start_iroha);
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("query-reqeuests");
    let domain_name = "domain";
    let create_domain = RegisterBox::new(
        IdentifiableBox::Domain(Domain::new(domain_name).into()),
        IdBox::WorldId,
    );
    let account_name = "account";
    let account_id = AccountId::new(account_name, domain_name);
    let create_account = RegisterBox::new(
        IdentifiableBox::Account(
            Account::with_signatory(
                account_id.clone(),
                KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            )
            .into(),
        ),
        IdBox::DomainName(domain_name.to_string()),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(
        IdentifiableBox::AssetDefinition(AssetDefinition::new(asset_definition_id.clone()).into()),
        IdBox::DomainName(domain_name.to_string()),
    );
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, account_id.clone())),
    );
    let mut iroha_client = Client::new(
        &ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration."),
    );
    iroha_client
        .submit_all(vec![
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
            mint_asset.into(),
        ])
        .expect("Failed to prepare state.");
    let request = asset::by_account_id(account_id);
    thread::sleep(std::time::Duration::from_millis(1500));
    let mut success_count = 0;
    let mut failures_count = 0;
    group.throughput(Throughput::Bytes(Vec::from(&request).len() as u64));
    group.bench_function("query", |b| {
        b.iter(|| match iroha_client.request(&request) {
            Ok(query_result) => {
                if let QueryResult(Value::Vec(assets)) = query_result {
                    assert!(!assets.is_empty());
                    success_count += 1;
                } else {
                    panic!("Wrong Query Result Type.");
                }
            }
            Err(e) => {
                eprintln!("Query failed: {}", e);
                failures_count += 1;
            }
        });
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
    group.finish();
    if (failures_count + success_count) > 0 {
        assert!(
            success_count as f32 / (failures_count + success_count) as f32
                > MINIMUM_SUCCESS_REQUEST_RATIO
        );
    }
}

fn instruction_submits(criterion: &mut Criterion) {
    thread::spawn(create_and_start_iroha);
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("instruction-reqeuests");
    let domain_name = "domain";
    let create_domain = RegisterBox::new(
        IdentifiableBox::Domain(Domain::new(domain_name).into()),
        IdBox::WorldId,
    );
    let account_name = "account";
    let account_id = AccountId::new(account_name, domain_name);
    let create_account = RegisterBox::new(
        IdentifiableBox::Account(
            Account::with_signatory(
                account_id.clone(),
                KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            )
            .into(),
        ),
        IdBox::DomainName(domain_name.to_string()),
    );
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let mut iroha_client = Client::new(
        &ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration."),
    );
    iroha_client
        .submit_all(vec![create_domain.into(), create_account.into()])
        .expect("Failed to create role.");
    thread::sleep(std::time::Duration::from_millis(500));
    let mut success_count = 0;
    let mut failures_count = 0;
    group.bench_function("instructions", |b| {
        b.iter(|| {
            let quantity: u32 = 200;
            let mint_asset = MintBox::new(
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(
                    asset_definition_id.clone(),
                    account_id.clone(),
                )),
            );
            match iroha_client.submit(mint_asset.into()) {
                Ok(_) => success_count += 1,
                Err(e) => {
                    eprintln!("Failed to execute instruction: {}", e);
                    failures_count += 1;
                }
            };
        })
    });
    println!(
        "Success count: {}, Failures count: {}",
        success_count, failures_count
    );
    group.finish();
    if (failures_count + success_count) > 0 {
        assert!(
            success_count as f32 / (failures_count + success_count) as f32
                > MINIMUM_SUCCESS_REQUEST_RATIO
        );
    }
}

fn create_and_start_iroha() {
    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration
        .kura_configuration
        .kura_block_store_path(temp_dir.path());
    configuration.logger_configuration.max_log_level = LevelFilter::Off;
    let iroha = Iroha::new(configuration, AllowAll.into());
    task::block_on(iroha.start()).expect("Failed to start Iroha.");
    //Prevents temp_dir from clean up untill the end of the tests.
    #[allow(clippy::empty_loop)]
    loop {}
}

criterion_group!(instructions, instruction_submits);
criterion_group!(queries, query_requests);
criterion_main!(queries, instructions);
