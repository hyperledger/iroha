#![allow(missing_docs, clippy::pedantic, clippy::restriction)]

use std::thread;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use iroha_client::client::{asset, Client};
use iroha_core::{
    genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock},
    prelude::*,
    samples::get_config,
};
use iroha_data_model::prelude::*;
use iroha_version::Encode;
use test_network::{get_key_pair, Peer as TestPeer, TestRuntime};
use tokio::runtime::Runtime;

const MINIMUM_SUCCESS_REQUEST_RATIO: f32 = 0.9;

fn query_requests(criterion: &mut Criterion) {
    let mut peer = <TestPeer>::new().expect("Failed to create peer");
    let configuration = get_config(
        std::iter::once(peer.id.clone()).collect(),
        Some(get_key_pair()),
    );
    let rt = Runtime::test();
    let genesis = GenesisNetwork::from_configuration(
        true,
        RawGenesisBlock::new("alice", "wonderland", &get_key_pair().public_key)
            .expect("Valid names never fail to parse"),
        &configuration.genesis,
        configuration.sumeragi.max_instruction_number,
    )
    .unwrap();

    rt.block_on(peer.start_with_config(genesis, configuration));
    thread::sleep(std::time::Duration::from_millis(50));

    let mut group = criterion.benchmark_group("query-reqeuests");
    let domain_name = "domain";
    let create_domain = RegisterBox::new(IdentifiableBox::Domain(Domain::test(domain_name).into()));
    let account_name = "account";
    let account_id = AccountId::test(account_name, domain_name);
    let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
        NewAccount::with_signatory(
            account_id.clone(),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        )
        .into(),
    ));
    let asset_definition_id = AssetDefinitionId::test("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
    ));
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, account_id.clone())),
    );
    let mut client_config = iroha_client::samples::get_client_config(&get_key_pair());
    client_config.torii_api_url = peer.api_address.clone();
    let mut iroha_client = Client::new(&client_config);
    let _ = iroha_client
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
    let _dropable = group.throughput(Throughput::Bytes(request.encode().len() as u64));
    let _dropable2 = group.bench_function("query", |b| {
        b.iter(|| match iroha_client.request(request.clone()) {
            Ok(assets) => {
                assert!(!assets.is_empty());
                success_count += 1;
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
    let rt = Runtime::test();
    let mut peer = <TestPeer>::new().expect("Failed to create peer");
    let configuration = get_config(
        std::iter::once(peer.id.clone()).collect(),
        Some(get_key_pair()),
    );
    let genesis = GenesisNetwork::from_configuration(
        true,
        RawGenesisBlock::new("alice", "wonderland", &configuration.public_key)
            .expect("Valid names never fail to parse"),
        &configuration.genesis,
        configuration.sumeragi.max_instruction_number,
    )
    .unwrap();
    rt.block_on(peer.start_with_config(genesis, configuration));
    thread::sleep(std::time::Duration::from_millis(50));

    let mut group = criterion.benchmark_group("instruction-requests");
    let domain_name = "domain";
    let create_domain = RegisterBox::new(IdentifiableBox::Domain(Domain::test(domain_name).into()));
    let account_name = "account";
    let account_id = AccountId::test(account_name, domain_name);
    let create_account = RegisterBox::new(IdentifiableBox::NewAccount(
        NewAccount::with_signatory(
            account_id.clone(),
            KeyPair::generate()
                .expect("Failed to generate KeyPair.")
                .public_key,
        )
        .into(),
    ));
    let asset_definition_id = AssetDefinitionId::test("xor", domain_name);
    let mut client_config = iroha_client::samples::get_client_config(&get_key_pair());
    client_config.torii_api_url = peer.api_address.clone();
    let mut iroha_client = Client::new(&client_config);
    let _ = iroha_client
        .submit_all(vec![create_domain.into(), create_account.into()])
        .expect("Failed to create role.");
    thread::sleep(std::time::Duration::from_millis(500));
    let mut success_count = 0;
    let mut failures_count = 0;
    let _dropable = group.bench_function("instructions", |b| {
        b.iter(|| {
            let quantity: u32 = 200;
            let mint_asset = MintBox::new(
                Value::U32(quantity),
                IdBox::AssetId(AssetId::new(
                    asset_definition_id.clone(),
                    account_id.clone(),
                )),
            );
            match iroha_client.submit(mint_asset) {
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

criterion_group!(instructions, instruction_submits);
criterion_group!(queries, query_requests);
criterion_main!(queries, instructions);
