use crate::{prelude::*, query::Query, queue::Queue, sumeragi::Sumeragi};
use std::{
    io::prelude::*,
    net::TcpListener,
    time::{Duration, Instant},
};

const QUERY_REQUEST_HEADER: &[u8; 16] = b"GET / HTTP/1.1\r\n";
const COMMAND_REQUEST_HEADER: &[u8; 25] = b"POST /commands HTTP/1.1\r\n";
const _PUT: &[u8; 16] = b"PUT / HTTP/1.1\r\n";
const OK: &[u8; 19] = b"HTTP/1.1 200 OK\r\n\r\n";

#[allow(dead_code)]
pub struct Torii {
    url: String,
    queue: Queue,
    consensus: Sumeragi,
    last_round_time: Instant,
}

impl Torii {
    pub fn new(url: &str, consensus: Sumeragi) -> Self {
        Torii {
            url: url.to_string(),
            queue: Queue::default(),
            consensus,
            last_round_time: Instant::now(),
        }
    }

    pub async fn start(&mut self) {
        let listener = TcpListener::bind(&self.url).expect("could not start server");
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
                            .sign(&self.queue.pop_pending_transactions())
                            .await
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
        self.queue.push_pending_transaction(
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
    use crate::{block::Blockchain, config::Configuration, kura::Kura, query};
    use futures::executor;

    #[test]
    fn get_request_to_torii_should_return_ok() {
        std::thread::spawn(move || {
            executor::block_on(create_and_start_torii());
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        let config =
            Configuration::from_path("config.json").expect("Failed to load configuration.");
        let mut stream =
            std::net::TcpStream::connect(&config.torii_url).expect("Failet connect to the server.");
        let query = &query::GetAccountAssets::build_query(Id::new("account", "domain"));
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
        std::thread::spawn(move || {
            executor::block_on(create_and_start_torii());
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        let config =
            Configuration::from_path("config.json").expect("Failed to load configuration.");
        let mut stream =
            std::net::TcpStream::connect(&config.torii_url).expect("Failet connect to the server.");
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

    async fn create_and_start_torii() {
        let config =
            Configuration::from_path("config.json").expect("Failed to load configuration.");
        let torii_url = config.torii_url.to_string();
        let mut torii = Torii::new(
            &torii_url.clone(),
            Sumeragi::new(Blockchain::new(Kura::fast_init().await)),
        );
        torii.start().await;
    }
}
