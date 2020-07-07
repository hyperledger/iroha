use crate::config::Configuration;
use crate::prelude::*;
use async_std::stream::Stream;
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

pub mod maintenance {
    use super::*;
    use iroha::maintenance::*;

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

        pub async fn subscribe_to_block_changes(
            &mut self,
        ) -> Result<impl Stream<Item = Vec<u8>>, String> {
            let network = Network::new(&self.torii_connect_url);
            let connection = network.connect().await.expect("Failed to connect.");
            Ok(connection)
        }
    }
}

pub mod assets {
    use super::*;
    use crate::asset::query::GetAccountAssets;

    pub fn by_account_id(account_id: <Account as Identifiable>::Id) -> QueryRequest {
        GetAccountAssets::build_request(account_id)
    }
}
