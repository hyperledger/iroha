use crate::config::Configuration;
use iroha_crypto::KeyPair;
use iroha_derive::log;
use iroha_dsl::prelude::*;
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
            key_pair: KeyPair {
                public_key: configuration.public_key.clone(),
                private_key: configuration.private_key.clone(),
            },
            proposed_transaction_ttl_ms: configuration.transaction_time_to_live_ms,
        }
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    #[log]
    pub async fn submit(&mut self, instruction: InstructionBox) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        //TODO: specify account in the config or CLI params
        let transaction = Transaction::new(
            vec![instruction],
            AccountId::new("root", "global"),
            self.proposed_transaction_ttl_ms,
        )
        .sign(&self.key_pair)?;
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
    pub async fn submit_all(&mut self, instructions: Vec<InstructionBox>) -> Result<(), String> {
        let network = Network::new(&self.torii_url);
        let transaction = Transaction::new(
            instructions,
            AccountId::new("root", "global"),
            self.proposed_transaction_ttl_ms,
        )
        .sign(&self.key_pair)?;
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
            .send_request(Request::new(
                uri::QUERY_URI.to_string(),
                request.clone().sign(&self.key_pair)?.into(),
            ))
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

pub mod account {
    use super::*;

    pub fn all() -> QueryRequest {
        QueryRequest::new(FindAllAccounts::new().into())
    }

    pub fn by_id(account_id: AccountId) -> QueryRequest {
        QueryRequest::new(FindAccountById::new(account_id).into())
    }
}

pub mod asset {
    use super::*;

    pub fn all() -> QueryRequest {
        QueryRequest::new(FindAllAssets::new().into())
    }

    pub fn all_definitions() -> QueryRequest {
        QueryRequest::new(FindAllAssetsDefinitions::new().into())
    }

    pub fn by_account_id(account_id: <Account as Identifiable>::Id) -> QueryRequest {
        QueryRequest::new(FindAssetsByAccountId::new(account_id).into())
    }

    pub fn by_account_id_and_definition_id(
        account_id: AccountId,
        asset_definition_id: AssetDefinitionId,
    ) -> QueryRequest {
        QueryRequest::new(
            FindAssetsByAccountIdAndAssetDefinitionId::new(account_id, asset_definition_id).into(),
        )
    }
}

pub mod domain {
    use super::*;

    pub fn all() -> QueryRequest {
        QueryRequest::new(FindAllDomains::new().into())
    }

    pub fn by_name(domain_name: String) -> QueryRequest {
        QueryRequest::new(FindDomainByName::new(domain_name).into())
    }
}

/// URI that `Client` uses to route outgoing requests.
//TODO: remove duplication with `iroha::torii::uri`.
pub mod uri {
    /// Query URI is used to handle incoming Query requests.
    pub const QUERY_URI: &str = "/query";
    /// Instructions URI is used to handle incoming ISI requests.
    pub const INSTRUCTIONS_URI: &str = "/instruction";
    /// Block URI is used to handle incoming Block requests.
    pub const CONSENSUS_URI: &str = "/consensus";
    /// Health URI is used to handle incoming Healthcheck requests.
    pub const HEALTH_URI: &str = "/health";
    /// Metrics URI is used to export metrics according to [Prometheus
    /// Guidance](https://prometheus.io/docs/instrumenting/writing_exporters/).
    pub const METRICS_URI: &str = "/metrics";
    /// The URI used for block synchronization.
    pub const BLOCK_SYNC_URI: &str = "/block";
}
