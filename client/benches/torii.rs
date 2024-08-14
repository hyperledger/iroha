#![allow(missing_docs, clippy::pedantic)]

use std::thread;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use iroha::{
    client::{asset, Client},
    data_model::prelude::*,
};
use iroha_genesis::GenesisBuilder;
use iroha_primitives::unique_vec;
use irohad::samples::get_config;
use test_network::{
    construct_executor, get_chain_id, get_key_pair, Peer as TestPeer, PeerBuilder, TestRuntime,
};
use test_samples::gen_account_in;
use tokio::runtime::Runtime;

const MINIMUM_SUCCESS_REQUEST_RATIO: f32 = 0.9;

fn query_requests(criterion: &mut Criterion) {
    let mut peer = <TestPeer>::new().expect("Failed to create peer");

    let chain_id = get_chain_id();
    let genesis_key_pair = get_key_pair(test_network::Signatory::Genesis);
    let configuration = get_config(
        unique_vec![peer.id.clone()],
        chain_id.clone(),
        get_key_pair(test_network::Signatory::Peer),
        genesis_key_pair.public_key(),
    );

    let rt = Runtime::test();
    let executor = construct_executor("../wasm_samples/default_executor")
        .expect("Failed to construct executor");
    let topology = vec![peer.id.clone()];
    let genesis = GenesisBuilder::default()
        .domain("wonderland".parse().expect("Valid"))
        .account(get_key_pair(test_network::Signatory::Alice).into_parts().0)
        .finish_domain()
        .build_and_sign(executor, chain_id, &genesis_key_pair, topology);

    let builder = PeerBuilder::new()
        .with_config(configuration)
        .with_genesis(genesis);

    rt.block_on(builder.start_with_peer(&mut peer));
    rt.block_on(async {
        iroha_logger::test_logger()
            .reload_level(iroha::data_model::Level::ERROR.into())
            .await
            .unwrap()
    });
    let mut group = criterion.benchmark_group("query-requests");
    let domain_id: DomainId = "domain".parse().expect("Valid");
    let create_domain = Register::domain(Domain::new(domain_id));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse().expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let mint_asset = Mint::asset_numeric(
        200u32,
        AssetId::new(asset_definition_id, account_id.clone()),
    );
    let client_config = iroha::samples::get_client_config(
        get_chain_id(),
        get_key_pair(test_network::Signatory::Alice),
        format!("http://{}", peer.api_address).parse().unwrap(),
    );

    let iroha = Client::new(client_config);
    thread::sleep(std::time::Duration::from_millis(5000));

    let _ = iroha
        .submit_all::<InstructionBox>([
            create_domain.into(),
            create_account.into(),
            create_asset.into(),
            mint_asset.into(),
        ])
        .expect("Failed to prepare state");

    let query = iroha
        .query(asset::all())
        .filter_with(|asset| asset.id.account.eq(account_id));
    thread::sleep(std::time::Duration::from_millis(1500));
    let mut success_count = 0;
    let mut failures_count = 0;
    // reporting elements and not bytes here because the new query builder doesn't easily expose the box type used in transport
    let _dropable = group.throughput(Throughput::Elements(1));
    let _dropable2 = group.bench_function("query", |b| {
        b.iter(|| {
            let iter = query.clone().execute_all();

            match iter {
                Ok(assets) => {
                    assert!(!assets.is_empty());
                    success_count += 1;
                }
                Err(e) => {
                    eprintln!("Query failed: {e}");
                    failures_count += 1;
                }
            }
        });
    });
    println!("Success count: {success_count}, Failures count: {failures_count}");
    group.finish();
    if (failures_count + success_count) > 0 {
        assert!(
            success_count as f32 / (failures_count + success_count) as f32
                > MINIMUM_SUCCESS_REQUEST_RATIO
        );
    }
}

fn instruction_submits(criterion: &mut Criterion) {
    println!("instruction submits");
    let rt = Runtime::test();
    let mut peer = <TestPeer>::new().expect("Failed to create peer");

    let chain_id = get_chain_id();
    let genesis_key_pair = get_key_pair(test_network::Signatory::Genesis);
    let topology = vec![peer.id.clone()];
    let configuration = get_config(
        unique_vec![peer.id.clone()],
        chain_id.clone(),
        get_key_pair(test_network::Signatory::Peer),
        genesis_key_pair.public_key(),
    );
    let executor = construct_executor("../wasm_samples/default_executor")
        .expect("Failed to construct executor");
    let genesis = GenesisBuilder::default()
        .domain("wonderland".parse().expect("Valid"))
        .account(configuration.common.key_pair.public_key().clone())
        .finish_domain()
        .build_and_sign(executor, chain_id, &genesis_key_pair, topology);
    let builder = PeerBuilder::new()
        .with_config(configuration)
        .with_genesis(genesis);
    rt.block_on(builder.start_with_peer(&mut peer));
    let mut group = criterion.benchmark_group("instruction-requests");
    let domain_id: DomainId = "domain".parse().expect("Valid");
    let create_domain = Register::domain(Domain::new(domain_id));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id: AssetDefinitionId = "xor#domain".parse().expect("Valid");
    let client_config = iroha::samples::get_client_config(
        get_chain_id(),
        get_key_pair(test_network::Signatory::Alice),
        format!("http://{}", peer.api_address).parse().unwrap(),
    );
    let iroha = Client::new(client_config);
    thread::sleep(std::time::Duration::from_millis(5000));
    let _ = iroha
        .submit_all::<InstructionBox>([create_domain.into(), create_account.into()])
        .expect("Failed to create role.");
    thread::sleep(std::time::Duration::from_millis(500));
    let mut success_count = 0;
    let mut failures_count = 0;
    let _dropable = group.bench_function("instructions", |b| {
        b.iter(|| {
            let mint_asset = Mint::asset_numeric(
                200u32,
                AssetId::new(asset_definition_id.clone(), account_id.clone()),
            );
            match iroha.submit(mint_asset) {
                Ok(_) => success_count += 1,
                Err(e) => {
                    eprintln!("Failed to execute instruction: {e}");
                    failures_count += 1;
                }
            };
        })
    });
    println!("Success count: {success_count}, Failures count: {failures_count}");
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
