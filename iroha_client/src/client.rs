use crate::config::Configuration;
use iroha::{event::connection::*, prelude::*, torii::uri};
use iroha_crypto::KeyPair;
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
            iroha::account::Id::new("root", "global"),
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
            iroha::account::Id::new("root", "global"),
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

pub mod maintenance {
    use super::*;
    use iroha::{event::Occurrence, maintenance::*};

    impl Client {
        pub fn with_maintenance(configuration: &Configuration) -> MaintenanceClient {
            MaintenanceClient {
                client: Client::new(configuration),
                torii_connect_url: configuration.torii_connect_url.clone(),
            }
        }
    }

    #[derive(Debug)]
    pub struct MaintenanceClient {
        client: Client,
        torii_connect_url: String,
    }

    impl MaintenanceClient {
        #[log]
        pub async fn submit(&mut self, instruction: Instruction) -> Result<(), String> {
            self.client.submit(instruction).await
        }

        #[log]
        pub async fn submit_all(&mut self, instructions: Vec<Instruction>) -> Result<(), String> {
            self.client.submit_all(instructions).await
        }

        #[log]
        pub async fn request(&mut self, request: &QueryRequest) -> Result<QueryResult, String> {
            self.client.request(request).await
        }

        #[log]
        pub async fn health(&mut self) -> Result<Health, String> {
            let network = Network::new(&self.client.torii_url);
            match network
                .send_request(Request::new(uri::HEALTH_URI.to_string(), vec![]))
                .await
                .map_err(|e| format!("Failed to write a get request: {}", e))?
            {
                Response::Ok(payload) => {
                    Ok(Health::try_from(payload).expect("Failed to convert Health from vector."))
                }
                Response::InternalError => Err("Server error.".to_string()),
            }
        }

        #[log]
        pub async fn scrape_metrics(&mut self) -> Result<Metrics, String> {
            let network = Network::new(&self.client.torii_url);
            match network
                .send_request(Request::new(uri::METRICS_URI.to_string(), vec![]))
                .await
                .map_err(|e| format!("Failed to send request to Metrics API: {}", e))?
            {
                Response::Ok(payload) => {
                    Ok(Metrics::try_from(payload).expect("Failed to convert vector to Metrics."))
                }
                Response::InternalError => Err("Server error.".to_string()),
            }
        }

        pub async fn subscribe_to_changes(
            &mut self,
            occurrence_type: OccurrenceType,
            entity_type: EntityType,
        ) -> Result<impl Iterator<Item = Occurrence>, String> {
            let network = Network::new(&self.torii_connect_url);
            let key_pair = KeyPair::generate().expect("Failed to generate a Key Pair.");
            let initial_message: Vec<u8> = Criteria::new(occurrence_type, entity_type)
                .sign(key_pair)
                .into();
            let connection = network
                .connect(&initial_message)
                .await
                .expect("Failed to connect.")
                .map(|vector| Occurrence::try_from(vector).expect("Failed to parse Occurrence."));
            Ok(connection)
        }
    }
}

pub mod domain {
    use super::*;
    use iroha::domain::query::*;

    pub fn all() -> QueryRequest {
        GetAllDomains::build_request()
    }

    pub fn by_name(domain_name: String) -> QueryRequest {
        GetDomain::build_request(domain_name)
    }
}

pub mod account {
    use super::*;
    use iroha::account::query::*;

    pub fn all() -> QueryRequest {
        GetAllAccounts::build_request()
    }

    pub fn by_id(account_id: AccountId) -> QueryRequest {
        GetAccount::build_request(account_id)
    }
}

pub mod asset {
    use super::*;
    use iroha::asset::query::*;

    pub fn all() -> QueryRequest {
        GetAllAssets::build_request()
    }

    pub fn all_definitions() -> QueryRequest {
        GetAllAssetsDefinitions::build_request()
    }

    pub fn by_account_id(account_id: <Account as Identifiable>::Id) -> QueryRequest {
        GetAccountAssets::build_request(account_id)
    }

    pub fn by_account_id_and_definition_id(
        account_id: AccountId,
        asset_definition_id: AssetDefinitionId,
    ) -> QueryRequest {
        GetAccountAssetsWithDefinition::build_request(account_id, asset_definition_id)
    }
}
