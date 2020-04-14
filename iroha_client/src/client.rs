use iroha::prelude::*;
use iroha_network::prelude::*;
use std::convert::TryFrom;

const QUERY_REQUEST_HEADER: &str = "/queries";
const COMMAND_REQUEST_HEADER: &str = "/commands";
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
    pub async fn submit(&mut self, command: Contract) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        let transaction =
            &Transaction::builder(vec![command], Id::new("account", "domain")).build();
        let response = network
            .send_request(Request::new(
                COMMAND_REQUEST_HEADER.to_string(),
                transaction.into(),
            ))
            .await
            .map_err(|e| {
                format!(
                    "Error: {}, Failed to write a transaction request: {:?}",
                    e, &transaction
                )
            })?;
        if response.starts_with(INTERNAL_ERROR) {
            return Err("Server error.".to_string());
        }
        Ok(())
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    pub async fn request(&mut self, request: &QueryRequest) -> Result<QueryResult, String> {
        let network = Network::new(&self.torii_url);
        let response = network
            .send_request(Request::new(
                QUERY_REQUEST_HEADER.to_string(),
                request.into(),
            ))
            .await
            .map_err(|e| format!("Failed to write a get request: {}", e))?;
        if response.starts_with(INTERNAL_ERROR) {
            return Err("Server error.".to_string());
        }
        Ok(QueryResult::try_from(response[OK.len()..].to_vec())
            .expect("Failed to try Query Result from vector."))
    }
}

pub mod assets {
    use super::*;
    use iroha::asset::query::GetAccountAssets;

    pub fn by_account_id(account_id: Id) -> QueryRequest {
        GetAccountAssets::build_request(account_id)
    }
}
