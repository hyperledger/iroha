use criterion::*;
use iroha::{
    client::query::Query,
    config::Configuration,
    consensus::sumeragi::Sumeragi,
    model::{block::Blockchain, tx::Transaction},
    networking::torii::Torii,
    storage::kura::Kura,
};
use std::io::prelude::*;
use std::time::Duration;

const QUERY_REQUEST_HEADER: &[u8; 16] = b"GET / HTTP/1.1\r\n";
const COMMAND_REQUEST_HEADER: &[u8; 25] = b"POST /commands HTTP/1.1\r\n";
const _PUT: &[u8; 16] = b"PUT / HTTP/1.1\r\n";
const OK: &[u8; 19] = b"HTTP/1.1 200 OK\r\n\r\n";

fn query_requests(criterion: &mut Criterion) {
    let config = Configuration::from_path("config.json").expect("Failed to load configuration.");
    let torii_url = config.torii_url.to_string();
    std::thread::spawn(move || {
        let mut torii = Torii::new(
            &torii_url,
            Sumeragi::new(Blockchain::new(
                futures::executor::block_on(Kura::strict_init()).expect("Failed to init Kura."),
            )),
        );
        torii.start();
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("query-reqeuests");
    let query = &Query::builder().build();
    let mut query: Vec<u8> = query.into();
    let mut query_request = QUERY_REQUEST_HEADER.to_vec();
    query_request.append(&mut query);
    group.throughput(Throughput::Bytes(query_request.len() as u64));
    let torii_url = config.torii_url.to_string();
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
    futures::executor::block_on(iroha::storage::kura::test_helper_fns::cleanup_default_block_dir())
        .expect("Failed to clean up storage.");
}

fn command_requests(criterion: &mut Criterion) {
    let config = Configuration::from_path("config.json").expect("Failed to load configuration.");
    let torii_url = config.torii_url.to_string();
    std::thread::spawn(move || {
        let mut torii = Torii::new(
            &torii_url,
            Sumeragi::new(Blockchain::new(
                futures::executor::block_on(Kura::strict_init()).expect("Failed to init Kura."),
            )),
        );
        torii.start();
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut group = criterion.benchmark_group("command-reqeuests");
    let transaction = &Transaction::builder(Vec::new(), "account@domain".to_string()).build();
    let mut transaction: Vec<u8> = transaction.into();
    let mut transaction_request = COMMAND_REQUEST_HEADER.to_vec();
    transaction_request.append(&mut transaction);
    group.throughput(Throughput::Bytes(transaction_request.len() as u64));
    let torii_url = config.torii_url.to_string();
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
    futures::executor::block_on(iroha::storage::kura::test_helper_fns::cleanup_default_block_dir())
        .expect("Failed to clean up storage.");
}

criterion_group!(benches, command_requests, query_requests);
criterion_main!(benches);
