use crate::{
    config::Configuration,
    http_client::{self, StatusCode, WebSocketMessage},
};
use http_client::WebSocketStream;
use iroha_crypto::KeyPair;
use iroha_derive::log;
use iroha_dsl::prelude::*;
use std::{
    convert::TryInto,
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
            torii_url: configuration.torii_api_url.clone(),
            key_pair: KeyPair {
                public_key: configuration.public_key.clone(),
                private_key: configuration.private_key.clone(),
            },
            proposed_transaction_ttl_ms: configuration.transaction_time_to_live_ms,
        }
    }

    /// Instructions API entry point. Submits one Iroha Special Instruction to `Iroha` peers.
    #[log]
    pub fn submit(&mut self, instruction: InstructionBox) -> Result<(), String> {
        //TODO: specify account in the config or CLI params
        let transaction: Vec<u8> = Transaction::new(
            vec![instruction],
            AccountId::new("root", "global"),
            self.proposed_transaction_ttl_ms,
        )
        .sign(&self.key_pair)?
        .into();
        let response = http_client::post(
            &format!("http://{}{}", self.torii_url, uri::INSTRUCTIONS_URI),
            transaction.clone(),
        )
        .map_err(|e| {
            format!(
                "Error: {}, failed to send transaction: {:?}",
                e, &transaction
            )
        })?;
        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(format!(
                "Failed to submit instruction with HTTP status: {}",
                response.status()
            ))
        }
    }

    /// Instructions API entry point. Submits several Iroha Special Instructions to `Iroha` peers.
    pub fn submit_all(&mut self, instructions: Vec<InstructionBox>) -> Result<(), String> {
        let transaction: Vec<u8> = Transaction::new(
            instructions,
            AccountId::new("root", "global"),
            self.proposed_transaction_ttl_ms,
        )
        .sign(&self.key_pair)?
        .into();
        let response = http_client::post(
            &format!("http://{}{}", self.torii_url, uri::INSTRUCTIONS_URI),
            transaction.clone(),
        )
        .map_err(|e| {
            format!(
                "Error: {}, failed to send transaction: {:?}",
                e, &transaction
            )
        })?;
        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(format!(
                "Failed to submit instructions with HTTP status: {}",
                response.status()
            ))
        }
    }

    /// Query API entry point. Requests queries from `Iroha` peers.
    #[log]
    pub fn request(&mut self, request: &QueryRequest) -> Result<QueryResult, String> {
        let response = http_client::get(
            &format!("http://{}{}", self.torii_url, uri::QUERY_URI),
            request.clone().sign(&self.key_pair)?.into(),
        )?;
        if response.status() == StatusCode::OK {
            response.body().clone().try_into()
        } else {
            Err(format!(
                "Failed to make query request with HTTP status: {}",
                response.status()
            ))
        }
    }

    /// Connects through `WebSocket` to listen for `Iroha` pipeline and data events.
    pub fn listen_for_events(
        &mut self,
        event_filter: EventFilter,
    ) -> Result<EventIterator, String> {
        EventIterator::new(
            &format!("ws://{}{}", self.torii_url, uri::SUBSCRIPTION_URI),
            event_filter,
        )
    }
}

/// Iterator for getting events from the `WebSocket` stream.
pub struct EventIterator {
    stream: WebSocketStream,
}

impl EventIterator {
    /// Constructs `EventIterator` and sends the subscription request.
    pub fn new(url: &str, event_filter: EventFilter) -> Result<EventIterator, String> {
        let mut stream = http_client::web_socket_connect(url)?;
        stream
            .write_message(WebSocketMessage::Text(
                serde_json::to_string(&SubscriptionRequest(event_filter))
                    .map_err(|err| err.to_string())?,
            ))
            .map_err(|err| err.to_string())?;
        Ok(EventIterator { stream })
    }
}

impl Iterator for EventIterator {
    type Item = Result<Event, String>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stream.read_message() {
            Ok(WebSocketMessage::Text(message)) => match serde_json::from_str::<Event>(&message) {
                Ok(event) => {
                    match self.stream.write_message(WebSocketMessage::Text(
                        serde_json::to_string(&EventReceived)
                            .expect("Failed to serialize receipt."),
                    )) {
                        Ok(_) => Some(Ok(event)),
                        Err(err) => Some(Err(format!("Failed to send receipt: {}", err))),
                    }
                }
                Err(err) => Some(Err(err.to_string())),
            },
            _ => None,
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
    /// The web socket uri used to subscribe to pipeline and data events.
    pub const SUBSCRIPTION_URI: &str = "/events";
}
