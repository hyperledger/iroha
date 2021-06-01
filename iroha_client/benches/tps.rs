#![allow(missing_docs, clippy::pedantic, clippy::restriction)]

use std::thread;

use criterion::{criterion_group, criterion_main, Criterion};
use iroha::{
    config::Configuration,
    genesis::{GenesisNetwork, GenesisNetworkTrait},
    prelude::*,
};
use iroha_client::{
    client::Client,
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::{events::pipeline, prelude::*};
use test_network::{Network, Peer as TestPeer, TestRuntime};
use tokio::runtime::Runtime;

const CONFIGURATION_PATH: &str = "benches/config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
const GENESIS_PATH: &str = "tests/genesis.json";
const MINIMUM_SUCCESS_REQUEST_RATIO: f32 = 0.9;

const DOMAIN_NAME: &str = "domain";
const ACCOUNT_NAME: &str = "account";

async fn create_peer() -> TestPeer {
    let mut configuration = Configuration::from_path(CONFIGURATION_PATH).unwrap();
    let mut peer = <TestPeer>::new().unwrap();
    configuration.sumeragi_configuration.trusted_peers.peers =
        std::iter::once(peer.id.clone()).collect();
    let genesis = GenesisNetwork::from_configuration(
        true,
        GENESIS_PATH,
        &configuration.genesis_configuration,
        configuration.sumeragi_configuration.max_instruction_number,
    )
    .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    peer.start_with_config(genesis, configuration).await;
    peer
}

fn setup_network() -> Vec<Instruction> {
    let account_id = AccountId::new(ACCOUNT_NAME, DOMAIN_NAME);
    let asset_definition_id = AssetDefinitionId::new("xor", DOMAIN_NAME);

    let create_domain = RegisterBox::new(IdentifiableBox::from(Domain::new(DOMAIN_NAME)));
    let create_account = RegisterBox::new(IdentifiableBox::from(NewAccount::with_signatory(
        account_id,
        KeyPair::generate().unwrap().public_key,
    )));
    let create_asset = RegisterBox::new(IdentifiableBox::from(AssetDefinition::new_quantity(
        asset_definition_id,
    )));
    vec![
        create_domain.into(),
        create_asset.into(),
        create_account.into(),
    ]
}

fn setup_bench() -> (Runtime, Client) {
    let rt = Runtime::test();
    let peer = rt.block_on(create_peer());

    let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH).unwrap();
    client_config.torii_api_url = peer.api_address.clone();
    let mut client = Client::new(&client_config);
    client.submit_all(setup_network()).unwrap();
    thread::sleep(std::time::Duration::from_millis(500));
    (rt, client)
}

async fn setup_bench_network(n_peers: u32, max_txs_in_block: u32) -> (Network, Client) {
    let (net, mut client) = <Network>::start_test(n_peers, max_txs_in_block).await;

    client.submit_all(setup_network()).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    (net, client)
}

fn instruction_submits(criterion: &mut Criterion) {
    let mut configuration = Configuration::from_path(CONFIGURATION_PATH).unwrap();
    let rt = Runtime::test();
    let mut peer = <TestPeer>::new().unwrap();
    configuration.sumeragi_configuration.trusted_peers.peers =
        std::iter::once(peer.id.clone()).collect();

    let genesis = GenesisNetwork::from_configuration(
        true,
        GENESIS_PATH,
        &configuration.genesis_configuration,
        configuration.sumeragi_configuration.max_instruction_number,
    )
    .unwrap();
    rt.block_on(peer.start_with_config(genesis, configuration));
    thread::sleep(std::time::Duration::from_millis(50));

    let mut group = criterion.benchmark_group("instruction-requests");
    let (_rt, mut iroha_client) = setup_bench();

    let account_id = AccountId::new(ACCOUNT_NAME, DOMAIN_NAME);
    let asset_definition_id = AssetDefinitionId::new("xor", DOMAIN_NAME);

    let mut success_count = 0;
    let mut failures_count = 0;

    let _ = group.bench_function("instructions", |b| {
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

fn instruction_submits_network(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("instruction-requests-network");
    let rt = Runtime::test();
    let txs_in_block = 5000;
    let (_net, mut cl) = rt.block_on(setup_bench_network(4, txs_in_block));

    let account_id = AccountId::new(ACCOUNT_NAME, DOMAIN_NAME);
    let asset_definition_id = AssetDefinitionId::new("xor", DOMAIN_NAME);

    let mut success_count = 0;
    let mut failures_count = 0;

    let _ = group.bench_function("instructions", |b| {
        b.iter(|| {
            let ev = cl
                .listen_for_events(EventFilter::Pipeline(pipeline::EventFilter {
                    entity: Some(pipeline::EntityType::Transaction),
                    hash: None,
                }))
                .unwrap();

            let quantity = txs_in_block / 10;

            let mut failed = 0;
            for _ in 0..quantity {
                let mint = MintBox::new(
                    Value::U32(1),
                    IdBox::AssetId(AssetId::new(
                        asset_definition_id.clone(),
                        account_id.clone(),
                    )),
                );
                if let Err(e) = cl.submit(mint) {
                    failed += 1;
                    eprintln!("Failed to execute instruction: {}", e);
                }
            }
            iroha_logger::error!("Failed {} times", failed);

            let n = ev
                .take(quantity as usize - failed)
                .map(|ev| {
                    iroha_logger::error!("Ev {:?}", ev);
                    if matches!(
                        ev,
                        Ok(Event::Pipeline(pipeline::Event {
                            status: pipeline::Status::Committed,
                            ..
                        }))
                    ) {
                        1
                    } else {
                        0
                    }
                })
                .sum::<i32>();

            success_count += n;
            failures_count += (quantity as i32) - n;
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

criterion_group!(
    instructions,
    //instruction_submits,
    instruction_submits_network
);
criterion_main!(instructions);
