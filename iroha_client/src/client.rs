use iroha::prelude::*;
use std::{io::prelude::*, net::TcpStream};

const QUERY_REQUEST_HEADER: &[u8] = b"GET / HTTP/1.1\r\n";
const COMMAND_REQUEST_HEADER: &[u8] = b"POST /commands HTTP/1.1\r\n";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
const INTERNAL_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\n\r\n";

pub struct Client {
    torii_url: String,
}

/// Representation of `Iroha` client.
impl Client {
    pub fn new(config: Configuration) -> Self {
        Client {
            torii_url: config.torii_url,
        }
    }

    /// Contract API entry point. Submits contracts to `Iroha` peers.
    pub fn submit(&mut self, command: Contract) -> Result<(), String> {
        let mut stream = TcpStream::connect(&self.torii_url)
            .map_err(|e| format!("Failet connect to the server: {}", e))?;
        let transaction =
            &Transaction::builder(vec![command], "account@domain".to_string()).build();
        let mut transaction: Vec<u8> = transaction.into();
        let mut transaction_request = COMMAND_REQUEST_HEADER.to_vec();
        transaction_request.append(&mut transaction);
        stream.write_all(&transaction_request).map_err(|e| {
            format!(
                "Error: {}, Failed to write a transaction request: {:?}",
                e, &transaction_request
            )
        })?;
        stream.flush().expect("Failed to flush a request.");
        let mut buffer = Vec::new();
        stream
            .read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to read response: {}", e))?;
        if buffer.starts_with(INTERNAL_ERROR) {
            return Err("Server error.".to_string());
        }
        Ok(())
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    pub fn request(&mut self, request: &Request) -> Result<QueryResult, String> {
        let mut stream = TcpStream::connect(&self.torii_url)
            .map_err(|e| format!("Failet connect to the server: {}", e))?;
        let mut query: Vec<u8> = request.into();
        let mut query_request = QUERY_REQUEST_HEADER.to_vec();
        query_request.append(&mut query);
        stream
            .write_all(&query_request)
            .map_err(|e| format!("Failed to write a get request: {}", e))?;
        stream.flush().expect("Failed to flush a request.");
        let mut buffer = Vec::new();
        stream
            .read_to_end(&mut buffer)
            .expect("Request read failed.");
        if buffer.starts_with(INTERNAL_ERROR) {
            return Err("Server error.".to_string());
        }
        Ok(buffer[OK.len()..].to_vec().into())
    }
}

pub mod assets {
    use super::*;
    use iroha::asset::query::GetAccountAssets;

    pub fn by_account_id(account_id: Id) -> Request {
        GetAccountAssets::build_request(account_id)
    }
}
