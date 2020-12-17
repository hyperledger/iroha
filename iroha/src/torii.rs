//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use crate::{
    block_sync::message::Message as BlockSyncMessage,
    event::{Consumer, EventsReceiver, EventsSender},
    maintenance::{Health, System},
    prelude::*,
    query::Verify,
    sumeragi::message::Message as SumeragiMessage,
    tx::Accept,
    BlockSyncMessageSender, SumeragiMessageSender,
};
use async_std::{prelude::*, sync::RwLock, task};
use iroha_data_model::prelude::*;
use iroha_derive::*;
use iroha_http_server::{prelude::*, web_socket::WebSocketStream, Server};
#[cfg(feature = "mock")]
use iroha_network::mock::prelude::*;
#[cfg(not(feature = "mock"))]
use iroha_network::prelude::*;
use std::{convert::TryFrom, fmt::Debug, sync::Arc};

/// Main network handler and the only entrypoint of the Iroha.
#[derive(Debug)]
pub struct Torii {
    p2p_url: String,
    api_url: String,
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    sumeragi_message_sender: Arc<RwLock<SumeragiMessageSender>>,
    block_sync_message_sender: Arc<RwLock<BlockSyncMessageSender>>,
    system: Arc<RwLock<System>>,
    events_sender: EventsSender,
    events_receiver: EventsReceiver,
}

impl Torii {
    /// Construct `Torii` from `ToriiConfiguration`.
    pub fn from_configuration(
        configuration: &config::ToriiConfiguration,
        world_state_view: Arc<RwLock<WorldStateView>>,
        transaction_sender: TransactionSender,
        sumeragi_message_sender: SumeragiMessageSender,
        block_sync_message_sender: BlockSyncMessageSender,
        system: System,
        (events_sender, events_receiver): (EventsSender, EventsReceiver),
    ) -> Self {
        Torii {
            p2p_url: configuration.torii_p2p_url.clone(),
            api_url: configuration.torii_api_url.clone(),
            world_state_view,
            transaction_sender: Arc::new(RwLock::new(transaction_sender)),
            sumeragi_message_sender: Arc::new(RwLock::new(sumeragi_message_sender)),
            block_sync_message_sender: Arc::new(RwLock::new(block_sync_message_sender)),
            system: Arc::new(RwLock::new(system)),
            events_sender,
            events_receiver,
        }
    }

    /// To handle incoming requests `Torii` should be started first.
    pub async fn start(&mut self) -> Result<(), String> {
        let world_state_view = Arc::clone(&self.world_state_view);
        let transaction_sender = Arc::clone(&self.transaction_sender);
        let sumeragi_message_sender = Arc::clone(&self.sumeragi_message_sender);
        let block_sync_message_sender = Arc::clone(&self.block_sync_message_sender);
        let system = Arc::clone(&self.system);
        let connections = Arc::new(RwLock::new(Vec::new()));
        let state = ToriiState {
            world_state_view,
            transaction_sender,
            sumeragi_message_sender,
            block_sync_message_sender,
            system,
            consumers: connections.clone(),
            events_sender: self.events_sender.clone(),
        };
        let state = Arc::new(RwLock::new(state));
        let mut server = Server::new(state.clone());
        server.at(uri::INSTRUCTIONS_URI).post(handle_instructions);
        server.at(uri::QUERY_URI).get(handle_queries);
        server.at(uri::HEALTH_URI).get(handle_health);
        server.at(uri::METRICS_URI).get(handle_metrics);
        server
            .at(uri::SUBSCRIPTION_URI)
            .web_socket(handle_subscription);
        let (handle_requests_result, http_server_result, _event_consumer_result) = futures::join!(
            Network::listen(state.clone(), &self.p2p_url, handle_requests),
            server.start(&self.api_url),
            consume_events(self.events_receiver.clone(), connections)
        );
        handle_requests_result?;
        http_server_result?;
        Ok(())
    }
}

#[derive(Debug)]
struct ToriiState {
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    sumeragi_message_sender: Arc<RwLock<SumeragiMessageSender>>,
    block_sync_message_sender: Arc<RwLock<BlockSyncMessageSender>>,
    consumers: Arc<RwLock<Vec<Consumer>>>,
    system: Arc<RwLock<System>>,
    events_sender: EventsSender,
}

async fn handle_instructions(
    state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    request: HttpRequest,
) -> Result<HttpResponse, String> {
    match Transaction::try_from(request.body) {
        Ok(transaction) => {
            let transaction = transaction.accept()?;
            state
                .write()
                .await
                .transaction_sender
                .write()
                .await
                .send(transaction)
                .await;
            Ok(HttpResponse::ok(Headers::new(), Vec::new()))
        }
        Err(e) => {
            log::error!("Failed to decode transaction: {}", e);
            Ok(HttpResponse::internal_server_error())
        }
    }
}

async fn handle_queries(
    state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    request: HttpRequest,
) -> Result<HttpResponse, String> {
    match SignedQueryRequest::try_from(request.body) {
        //TODO: check query permissions based on signature?
        Ok(request) => match request.verify() {
            Ok(request) => {
                match request
                    .query
                    .execute(&*state.read().await.world_state_view.read().await)
                {
                    Ok(result) => {
                        let result = &result;
                        Ok(HttpResponse::ok(Headers::new(), result.into()))
                    }
                    Err(e) => {
                        log::error!("Failed to execute query: {}", e);
                        Ok(HttpResponse::internal_server_error())
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to verify Query Request: {}", e);
                Ok(HttpResponse::internal_server_error())
            }
        },
        Err(e) => {
            log::error!("Failed to decode transaction: {}", e);
            Ok(HttpResponse::internal_server_error())
        }
    }
}

async fn handle_health(
    _state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    _request: HttpRequest,
) -> Result<HttpResponse, String> {
    Ok(HttpResponse::ok(Headers::new(), Health::Healthy.into()))
}

async fn handle_metrics(
    state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    _request: HttpRequest,
) -> Result<HttpResponse, String> {
    match state.read().await.system.read().await.scrape_metrics() {
        Ok(metrics) => Ok(HttpResponse::ok(Headers::new(), metrics.into())),
        Err(e) => {
            log::error!("Failed to scrape metrics: {}", e);
            Ok(HttpResponse::internal_server_error())
        }
    }
}

async fn handle_subscription(
    state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    stream: WebSocketStream,
) -> Result<(), String> {
    let consumer = Consumer::new(stream).await?;
    state.read().await.consumers.write().await.push(consumer);
    Ok(())
}

async fn handle_requests(
    state: State<ToriiState>,
    stream: Box<dyn AsyncStream>,
) -> Result<(), String> {
    let state_arc = Arc::clone(&state);
    task::spawn(async {
        if let Err(e) = Network::handle_message_async(state_arc, stream, handle_request).await {
            log::error!("Failed to handle message: {}", e);
        }
    })
    .await;
    Ok(())
}

async fn consume_events(
    mut events_receiver: EventsReceiver,
    consumers: Arc<RwLock<Vec<Consumer>>>,
) {
    while let Some(change) = events_receiver.next().await {
        log::trace!("Event occurred: {:?}", change);
        for connection in consumers.write().await.iter_mut() {
            if let Err(err) = connection.consume(&change).await {
                log::error!("Failed to notify client: {}", err)
            }
        }
    }
}

#[log("TRACE")]
async fn handle_request(state: State<ToriiState>, request: Request) -> Result<Response, String> {
    match request.url() {
        uri::CONSENSUS_URI => match SumeragiMessage::try_from(request.payload().to_vec()) {
            Ok(message) => {
                state
                    .write()
                    .await
                    .sumeragi_message_sender
                    .write()
                    .await
                    .send(message)
                    .await;
                Ok(Response::empty_ok())
            }
            Err(e) => {
                log::error!("Failed to decode peer message: {}", e);
                Ok(Response::InternalError)
            }
        },
        uri::BLOCK_SYNC_URI => match BlockSyncMessage::try_from(request.payload().to_vec()) {
            Ok(message) => {
                state
                    .write()
                    .await
                    .block_sync_message_sender
                    .write()
                    .await
                    .send(message)
                    .await;
                Ok(Response::empty_ok())
            }
            Err(e) => {
                log::error!("Failed to decode peer message: {}", e);
                Ok(Response::InternalError)
            }
        },
        non_supported_uri => {
            log::error!("URI not supported: {}.", &non_supported_uri);
            Ok(Response::InternalError)
        }
    }
}

/// URI that `Torii` uses to route incoming requests.
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
    /// The web socket uri used to subscribe to block and transactions statuses
    pub const SUBSCRIPTION_URI: &str = "/events";
}

/// This module contains all configuration related logic.
pub mod config {
    use serde::Deserialize;
    use std::env;

    const TORII_API_URL: &str = "TORII_API_URL";
    const TORII_P2P_URL: &str = "TORII_P2P_URL";
    const DEFAULT_TORII_P2P_URL: &str = "127.0.0.1:1337";
    const DEFAULT_TORII_API_URL: &str = "127.0.0.1:8080";

    /// `ToriiConfiguration` provides an ability to define parameters such as `TORII_URL`.
    #[derive(Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct ToriiConfiguration {
        /// Torii URL for p2p communication for consensus and block synchronization purposes.
        #[serde(default = "default_torii_p2p_url")]
        pub torii_p2p_url: String,
        /// Torii URL for client API.
        #[serde(default = "default_torii_api_url")]
        pub torii_api_url: String,
    }

    impl ToriiConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(torii_api_url) = env::var(TORII_API_URL) {
                self.torii_api_url = torii_api_url;
            }
            if let Ok(torii_p2p_url) = env::var(TORII_P2P_URL) {
                self.torii_p2p_url = torii_p2p_url;
            }
            Ok(())
        }
    }

    fn default_torii_p2p_url() -> String {
        DEFAULT_TORII_P2P_URL.to_string()
    }

    fn default_torii_api_url() -> String {
        DEFAULT_TORII_API_URL.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use async_std::{sync, task};
    use std::time::Duration;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    async fn create_and_start_torii() {
        let config =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let (tx_tx, _) = sync::channel(100);
        let (sumeragi_message_sender, _) = sync::channel(100);
        let (block_sync_message_sender, _) = sync::channel(100);
        let (events_sender, events_receiver) = sync::channel(100);
        let mut torii = Torii::from_configuration(
            &config.torii_configuration,
            Arc::new(RwLock::new(WorldStateView::new(World::new()))),
            tx_tx,
            sumeragi_message_sender,
            block_sync_message_sender,
            System::new(&config),
            (events_sender, events_receiver),
        );
        let _ = task::spawn(async move {
            if let Err(e) = torii.start().await {
                eprintln!("Failed to start Torii: {}", e);
            }
        });
        std::thread::sleep(Duration::from_millis(50));
    }
}
