use crate::config::Configuration;
use crate::prelude::*;
use iroha::{crypto::KeyPair, torii::uri};
use iroha_derive::log;
use iroha_network::{prelude::*, Network};
use std::{
    convert::TryFrom,
    fmt::{self, Debug, Formatter},
};

pub struct Client {
    torii_url: String,
    key_pair: KeyPair,
    proposed_transaction_ttl_ms: u64,
}

/// Representation of `Iroha` client.
impl Client {
    pub fn new(configuration: &Configuration) -> Self {
        Client {
            torii_url: configuration.torii_url.clone(),
            //TODO: The `public_key` from `configuration` will be different. Fix this inconsistency.
            key_pair: KeyPair::generate().expect("Failed to generate KeyPair."),
            proposed_transaction_ttl_ms: configuration.transaction_time_to_live_ms,
        }
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    #[log]
    pub async fn submit(&mut self, instruction: Instruction) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        let transaction: RequestedTransaction = RequestedTransaction::new(
            vec![instruction],
            crate::account::Id::new("root", "global"),
            self.proposed_transaction_ttl_ms,
        )
        .accept()?
        .sign(&self.key_pair)?
        .into();
        if let Response::InternalError = network
            .send_request(Request::new(
                uri::INSTRUCTIONS_URI.to_string(),
                Vec::from(&transaction),
            ))
            .await
            .map_err(|e| {
                format!(
                    "Error: {}, Failed to write a transaction request: {:?}",
                    e, &transaction
                )
            })?
        {
            return Err("Server error.".to_string());
        }
        Ok(())
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    pub async fn submit_all(&mut self, instructions: Vec<Instruction>) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        let transaction: RequestedTransaction = RequestedTransaction::new(
            instructions,
            crate::account::Id::new("root", "global"),
            self.proposed_transaction_ttl_ms,
        )
        .accept()?
        .sign(&self.key_pair)?
        .into();
        if let Response::InternalError = network
            .send_request(Request::new(
                uri::INSTRUCTIONS_URI.to_string(),
                Vec::from(&transaction),
            ))
            .await
            .map_err(|e| {
                format!(
                    "Error: {}, Failed to write a transaction request: {:?}",
                    e, &transaction
                )
            })?
        {
            return Err("Server error.".to_string());
        }
        Ok(())
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    #[log]
    pub async fn request(&mut self, request: &QueryRequest) -> Result<QueryResult, String> {
        let network = Network::new(&self.torii_url);
        match network
            .send_request(Request::new(uri::QUERY_URI.to_string(), request.into()))
            .await
            .map_err(|e| format!("Failed to write a get request: {}", e))?
        {
            Response::Ok(payload) => Ok(
                QueryResult::try_from(payload).expect("Failed to try Query Result from vector.")
            ),
            Response::InternalError => Err("Server error.".to_string()),
        }
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("public_key", &self.key_pair.public_key)
            .field("torii_url", &self.torii_url)
            .finish()
    }
}

pub mod assets {
    use super::*;
    use crate::asset::query::GetAccountAssets;

    pub fn by_account_id(account_id: <Account as Identifiable>::Id) -> QueryRequest {
        GetAccountAssets::build_request(account_id)
    }
}
