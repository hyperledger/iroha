//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use crate::{
    block_sync::message::Message as BlockSyncMessage,
    event::{EventsReceiver, EventsSender},
    maintenance::{Health, System},
    prelude::*,
    sumeragi::message::Message as SumeragiMessage,
    BlockSyncMessageSender, SumeragiMessageSender,
};
use async_std::{prelude::*, sync::RwLock, task};
use iroha_derive::*;
#[cfg(feature = "mock")]
use iroha_network::mock::prelude::*;
#[cfg(not(feature = "mock"))]
use iroha_network::prelude::*;
use std::{convert::TryFrom, sync::Arc};

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii {
    url: String,
    connect_url: String,
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    sumeragi_message_sender: Arc<RwLock<SumeragiMessageSender>>,
    block_sync_message_sender: Arc<RwLock<BlockSyncMessageSender>>,
    system: Arc<RwLock<System>>,
    events_sender: EventsSender,
    events_receiver: EventsReceiver,
}

impl Torii {
    /// Default `Torii` constructor.
    pub fn new(
        (url, connect_url): (&str, &str),
        world_state_view: Arc<RwLock<WorldStateView>>,
        transaction_sender: TransactionSender,
        sumeragi_message_sender: SumeragiMessageSender,
        block_sync_message_sender: BlockSyncMessageSender,
        system: System,
        (events_sender, events_receiver): (EventsSender, EventsReceiver),
    ) -> Self {
        Torii {
            url: url.to_string(),
            connect_url: connect_url.to_string(),
            world_state_view,
            transaction_sender: Arc::new(RwLock::new(transaction_sender)),
            sumeragi_message_sender: Arc::new(RwLock::new(sumeragi_message_sender)),
            block_sync_message_sender: Arc::new(RwLock::new(block_sync_message_sender)),
            system: Arc::new(RwLock::new(system)),
            events_sender,
            events_receiver,
        }
    }

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
        Torii::new(
            (&configuration.torii_url, &configuration.torii_connect_url),
            world_state_view,
            transaction_sender,
            sumeragi_message_sender,
            block_sync_message_sender,
            system,
            (events_sender, events_receiver),
        )
    }

    /// To handle incoming requests `Torii` should be started first.
    pub async fn start(&mut self) -> Result<(), String> {
        let world_state_view = Arc::clone(&self.world_state_view);
        let transaction_sender = Arc::clone(&self.transaction_sender);
        let sumeragi_message_sender = Arc::clone(&self.sumeragi_message_sender);
        let block_sync_message_sender = Arc::clone(&self.block_sync_message_sender);
        let system = Arc::clone(&self.system);
        let state = ToriiState {
            world_state_view,
            transaction_sender,
            sumeragi_message_sender,
            block_sync_message_sender,
            system,
            events_sender: self.events_sender.clone(),
            events_receiver: self.events_receiver.clone(),
        };
        let state = Arc::new(RwLock::new(state));
        let a = Network::listen(state.clone(), &self.connect_url, handle_connections);
        let b = Network::listen(state.clone(), &self.url, handle_requests);
        let result = a.join(b).await;
        result.0?;
        result.1?;
        Ok(())
    }
}

#[derive(Debug)]
struct ToriiState {
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    sumeragi_message_sender: Arc<RwLock<SumeragiMessageSender>>,
    block_sync_message_sender: Arc<RwLock<BlockSyncMessageSender>>,
    system: Arc<RwLock<System>>,
    events_sender: EventsSender,
    events_receiver: EventsReceiver,
}

async fn handle_requests(
    state: State<ToriiState>,
    stream: Box<dyn AsyncStream>,
) -> Result<(), String> {
    let state_arc = Arc::clone(&state);
    task::spawn(async {
        if let Err(e) = Network::handle_message_async(state_arc, stream, handle_request).await {
            eprintln!("Failed to handle message: {}", e);
        }
    })
    .await;
    Ok(())
}

async fn handle_connections(
    state: State<ToriiState>,
    mut stream: Box<dyn AsyncStream>,
) -> Result<(), String> {
    let mut receiver = state.write().await.events_receiver.clone();
    while let Some(change) = receiver.next().await {
        let change: Vec<u8> = change.into();
        stream
            .write_all(&change)
            .await
            .map_err(|e| format!("Failed to write message: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush: {}", e))?;
        //TODO: replace with known size.
        let mut receipt = vec![0u8; 1000];
        let read_size = stream
            .read(&mut receipt)
            .await
            .map_err(|e| format!("Failed to read receipt: {}", e))?;
        Receipt::try_from(receipt[..read_size].to_vec())?;
    }
    Ok(())
}

#[log]
async fn handle_request(state: State<ToriiState>, request: Request) -> Result<Response, String> {
    match request.url() {
        uri::INSTRUCTIONS_URI => match RequestedTransaction::try_from(request.payload().to_vec()) {
            Ok(transaction) => {
                state
                    .write()
                    .await
                    .transaction_sender
                    .write()
                    .await
                    .send(transaction.accept()?)
                    .await;
                Ok(Response::empty_ok())
            }
            Err(e) => {
                eprintln!("Failed to decode transaction: {}", e);
                Ok(Response::InternalError)
            }
        },
        uri::QUERY_URI => match QueryRequest::try_from(request.payload().to_vec()) {
            Ok(request) => match request
                .query
                .execute(&*state.read().await.world_state_view.read().await)
            {
                Ok(result) => {
                    let result = &result;
                    Ok(Response::Ok(result.into()))
                }
                Err(e) => {
                    eprintln!("Failed to execute Query: {}", e);
                    Ok(Response::InternalError)
                }
            },
            Err(e) => {
                eprintln!("Failed to decode transaction: {}", e);
                Ok(Response::InternalError)
            }
        },
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
                eprintln!("Failed to decode peer message: {}", e);
                Ok(Response::InternalError)
            }
        },
        uri::HEALTH_URI => Ok(Response::Ok(Health::Healthy.into())),
        uri::METRICS_URI => match state.read().await.system.read().await.scrape_metrics() {
            Ok(metrics) => Ok(Response::Ok(metrics.into())),
            Err(e) => {
                eprintln!("Failed to scrape metrics: {}", e);
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
                eprintln!("Failed to decode peer message: {}", e);
                Ok(Response::InternalError)
            }
        },
        non_supported_uri => panic!("URI not supported: {}.", &non_supported_uri),
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
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_derive::*;
    use serde::Deserialize;
    use std::env;

    const TORII_URL: &str = "TORII_URL";
    const TORII_CONNECT_URL: &str = "TORII_CONNECT_URL";
    const DEFAULT_TORII_URL: &str = "127.0.0.1:1337";
    const DEFAULT_TORII_CONNECT_URL: &str = "127.0.0.1:8888";

    /// `ToriiConfiguration` provides an ability to define parameters such as `TORII_URL`.
    #[derive(Clone, Deserialize, Debug)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct ToriiConfiguration {
        /// Torii URL.
        #[serde(default = "default_torii_url")]
        pub torii_url: String,
        /// Torii connection URL.
        #[serde(default = "default_torii_connect_url")]
        pub torii_connect_url: String,
    }

    impl ToriiConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        #[log]
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(torii_url) = env::var(TORII_URL) {
                self.torii_url = torii_url;
            }
            if let Ok(torii_connect_url) = env::var(TORII_CONNECT_URL) {
                self.torii_connect_url = torii_connect_url;
            }
            Ok(())
        }
    }

    fn default_torii_url() -> String {
        DEFAULT_TORII_URL.to_string()
    }

    fn default_torii_connect_url() -> String {
        DEFAULT_TORII_CONNECT_URL.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Configuration, peer::PeerId};
    use async_std::{sync, task};
    use std::time::Duration;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[async_std::test]
    async fn create_and_start_torii() {
        let config =
            Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
        let torii_url = config.torii_configuration.torii_url.to_string();
        let torii_connect_url = config.torii_configuration.torii_connect_url.to_string();
        let (tx_tx, _) = sync::channel(100);
        let (sumeragi_message_sender, _) = sync::channel(100);
        let (block_sync_message_sender, _) = sync::channel(100);
        let (events_sender, events_receiver) = sync::channel(100);
        let mut torii = Torii::new(
            (&torii_url, &torii_connect_url),
            Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId::new(&config.torii_configuration.torii_url, &config.public_key),
                &Vec::new(),
            )))),
            tx_tx,
            sumeragi_message_sender,
            block_sync_message_sender,
            System::new(&config),
            (events_sender, events_receiver),
        );
        task::spawn(async move {
            if let Err(e) = torii.start().await {
                eprintln!("Failed to start Torii: {}", e);
            }
        });
        std::thread::sleep(Duration::from_millis(50));
    }
}
