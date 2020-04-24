use iroha::{crypto, prelude::*};
use iroha_derive::log;
use iroha_network::prelude::*;
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};

const QUERY_URI: &str = "/query";
const INSTRUCTION_URI: &str = "/instruction";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
const INTERNAL_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\n\r\n";

pub struct Client {
    torii_url: String,
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("public_key", &self.public_key)
            .field("torii_url", &self.torii_url)
            .finish()
    }
}

/// Representation of `Iroha` client.
impl Client {
    pub fn new(config: Configuration) -> Self {
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        Client {
            torii_url: config.torii_url,
            public_key: public_key[..]
                .try_into()
                .expect("Public key should be [u8;32]"),
            private_key,
        }
    }

    /// Contract API entry point. Submits contracts to `Iroha` peers.
    #[log]
    pub async fn submit(&mut self, command: Contract) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        let transaction = Transaction::new(
            vec![command],
            Id::new("account", "domain"),
            &self.public_key,
            &self.private_key,
        )?;
        let response = network
            .send_request(Request::new(
                INSTRUCTION_URI.to_string(),
                Vec::from(&transaction),
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
    #[log]
    pub async fn request(&mut self, request: &QueryRequest) -> Result<QueryResult, String> {
        let network = Network::new(&self.torii_url);
        let response = network
            .send_request(Request::new(QUERY_URI.to_string(), request.into()))
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
