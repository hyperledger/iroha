use crate::{
    cache::{mst_cache::MSTCache, pending_tx_cache::PendingTxCache},
    client::query::Query,
    consensus::sumeragi::Sumeragi,
    model::tx::Transaction,
};
use std::{
    io::prelude::*,
    net::TcpListener,
    time::{Duration, Instant},
};

const TORII_URL: &str = "127.0.0.1:1337";
const QUERY_REQUEST_HEADER: &[u8; 16] = b"GET / HTTP/1.1\r\n";
const COMMAND_REQUEST_HEADER: &[u8; 25] = b"POST /commands HTTP/1.1\r\n";
const _PUT: &[u8; 16] = b"PUT / HTTP/1.1\r\n";
const OK: &[u8; 19] = b"HTTP/1.1 200 OK\r\n\r\n";

#[allow(dead_code)]
pub struct Torii {
    mst_cache: MSTCache,
    pending_tx_cache: PendingTxCache,
    consensus: Sumeragi,
    last_round_time: Instant,
}

impl Torii {
    pub fn new(consensus: Sumeragi) -> Self {
        Torii {
            mst_cache: MSTCache::default(),
            pending_tx_cache: PendingTxCache::default(),
            consensus,
            last_round_time: Instant::now(),
        }
    }

    pub fn start(&mut self) {
        let listener = TcpListener::bind(TORII_URL).expect("could not start server");
        for connection in listener.incoming() {
            match connection {
                Ok(mut stream) => {
                    stream
                        .set_read_timeout(Some(Duration::new(2, 0)))
                        .expect("Failed to set read timeout");
                    stream
                        .set_write_timeout(Some(Duration::new(2, 0)))
                        .expect("Failed to set read timeout");
                    let mut buffer = [0; 512];
                    let _read_size = stream.read(&mut buffer).expect("Request read failed.");
                    if buffer.starts_with(COMMAND_REQUEST_HEADER) {
                        self.receive_command(&buffer[COMMAND_REQUEST_HEADER.len()..]);
                        stream.write_all(OK).expect("Failed to write a response.");
                        self.consensus
                            .sign(&self.pending_tx_cache.pop_all())
                            .expect("Failed to sign transactions.");
                        self.last_round_time = Instant::now();
                    } else if buffer.starts_with(QUERY_REQUEST_HEADER) {
                        self.receive_query(&buffer[QUERY_REQUEST_HEADER.len()..]);
                        stream.write_all(OK).expect("Failed to write a response.");
                    }
                    stream.flush().expect("Failed to flush a stream.");
                }
                Err(e) => {
                    println!("Connection failed {}.", e);
                }
            }
        }
    }

    fn receive_command(&mut self, payload: &[u8]) {
        let transaction: Transaction = payload.to_vec().into();
        self.pending_tx_cache.add_tx(
            transaction
                .validate()
                .expect("Failed to validate transaction."),
        );
    }

    fn receive_query(&mut self, payload: &[u8]) {
        let _query: Query = payload.to_vec().into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::block::Blockchain, storage::kura::Kura};

    #[test]
    fn get_request_to_torii_should_return_ok() {
        std::thread::spawn(|| {
            let mut torii = Torii::new(Sumeragi::new(Blockchain::new(
                futures::executor::block_on(Kura::fast_init()),
            )));
            torii.start();
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut stream =
            std::net::TcpStream::connect(TORII_URL).expect("Failet connect to the server.");
        let query = &Query::builder().build();
        let mut query: Vec<u8> = query.into();
        let mut query_request = QUERY_REQUEST_HEADER.to_vec();
        query_request.append(&mut query);
        stream
            .write(&query_request)
            .expect("Failed to write a get request.");
        stream.flush().expect("Failed to flush a request.");
        let mut buffer = [0; 512];
        stream.read(&mut buffer).expect("Request read failed.");
        assert!(buffer.starts_with(OK));
    }

    #[test]
    fn post_command_request_to_torii_should_return_ok() {
        std::thread::spawn(|| {
            let mut torii = Torii::new(Sumeragi::new(Blockchain::new(
                futures::executor::block_on(Kura::fast_init()),
            )));
            torii.start();
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut stream =
            std::net::TcpStream::connect(TORII_URL).expect("Failet connect to the server.");
        stream
            .set_read_timeout(Some(Duration::new(2, 0)))
            .expect("Failed to set read timeout");
        stream
            .set_write_timeout(Some(Duration::new(2, 0)))
            .expect("Failed to set read timeout");
        let transaction = &Transaction::builder(Vec::new(), "account@domain".to_string()).build();
        let mut transaction: Vec<u8> = transaction.into();
        let mut transaction_request = COMMAND_REQUEST_HEADER.to_vec();
        transaction_request.append(&mut transaction);
        stream
            .write(&transaction_request)
            .expect("Failed to write a transaction request.");
        stream.flush().expect("Failed to flush a request.");
        let mut buffer = [0; 512];
        stream.read(&mut buffer).expect("Request read failed.");
        assert!(buffer.starts_with(OK));
    }
}
