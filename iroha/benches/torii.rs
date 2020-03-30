use async_std::fs;
use criterion::*;
use futures::executor;
use iroha::{config::Configuration, prelude::*, query::GetAccountAssets};
use std::{io::prelude::*, thread, time::Duration};

const QUERY_REQUEST_HEADER: &[u8; 16] = b"GET / HTTP/1.1\r\n";
const COMMAND_REQUEST_HEADER: &[u8; 25] = b"POST /commands HTTP/1.1\r\n";
const _PUT: &[u8; 16] = b"PUT / HTTP/1.1\r\n";
const OK: &[u8; 19] = b"HTTP/1.1 200 OK\r\n\r\n";
static DEFAULT_BLOCK_STORE_LOCATION: &str = "./blocks/";

fn query_requests(criterion: &mut Criterion) {
    thread::spawn(|| executor::block_on(create_and_start_iroha()));
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("query-reqeuests");
    let query = &GetAccountAssets::build_query(Id::new("account", "domain"));
    let mut query: Vec<u8> = query.into();
    let mut query_request = QUERY_REQUEST_HEADER.to_vec();
    query_request.append(&mut query);
    group.throughput(Throughput::Bytes(query_request.len() as u64));
    let torii_url = Configuration::from_path("config.json")
        .expect("Failed to load configuration.")
        .torii_url
        .to_string();
    group.bench_function("query", |b| {
        b.iter(|| {
            let mut stream =
                std::net::TcpStream::connect(&torii_url).expect("Failed connect to the server.");
            stream
                .set_read_timeout(Some(Duration::new(2, 0)))
                .expect("Failed to set read timeout");
            stream
                .set_write_timeout(Some(Duration::new(2, 0)))
                .expect("Failed to set read timeout");
            stream
                .write(&query_request)
                .expect("Failed to write a get request.");
            stream.flush().expect("Failed to flush a request.");
            let mut buffer = [0; 512];
            stream.read(&mut buffer).expect("Request read failed.");
            assert!(buffer.starts_with(OK));
        });
    });
    group.finish();
    executor::block_on(cleanup_default_block_dir()).expect("Failed to clean up storage.");
}

fn command_requests(criterion: &mut Criterion) {
    thread::spawn(|| executor::block_on(create_and_start_iroha()));
    thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("command-reqeuests");
    let transaction = &Transaction::builder(Vec::new(), "account@domain".to_string()).build();
    let mut transaction: Vec<u8> = transaction.into();
    let mut transaction_request = COMMAND_REQUEST_HEADER.to_vec();
    transaction_request.append(&mut transaction);
    group.throughput(Throughput::Bytes(transaction_request.len() as u64));
    let torii_url = Configuration::from_path("config.json")
        .expect("Failed to load configuration.")
        .torii_url
        .to_string();
    group.bench_function("commands", |b| {
        b.iter(|| {
            let mut stream =
                std::net::TcpStream::connect(&torii_url).expect("Failet connect to the server.");
            stream
                .set_read_timeout(Some(Duration::new(2, 0)))
                .expect("Failed to set read timeout");
            stream
                .set_write_timeout(Some(Duration::new(2, 0)))
                .expect("Failed to set read timeout");
            stream
                .write(&transaction_request)
                .expect("Failed to write a transaction request.");
            stream.flush().expect("Failed to flush a request.");
            let mut buffer = [0; 512];
            stream.read(&mut buffer).expect("Request read failed.");
            assert!(buffer.starts_with(OK));
        })
    });
    group.finish();
    executor::block_on(cleanup_default_block_dir()).expect("Failed to clean up storage.");
}

async fn create_and_start_iroha() {
    let mut iroha =
        Iroha::new(Configuration::from_path("config.json").expect("Failed to load configuration."));
    iroha.start().await.expect("Failed to start Iroha.");
}

/// Cleans up default directory of disk storage.
/// Should be used in tests that may potentially read from disk
/// to prevent failures due to changes in block structure.
pub async fn cleanup_default_block_dir() -> Result<(), String> {
    fs::remove_dir_all(DEFAULT_BLOCK_STORE_LOCATION)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

criterion_group!(benches, command_requests, query_requests);
criterion_main!(benches);
