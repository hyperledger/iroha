//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use crate::{
    block_sync::message::{
        Message as BlockSyncMessage, VersionedMessage as BlockSyncVersionedMessage,
    },
    event::{Consumer, EventsReceiver, EventsSender},
    maintenance::{Health, System},
    prelude::*,
    query::VerifiedQueryRequest,
    queue::Queue,
    sumeragi::{
        message::{Message as SumeragiMessage, VersionedMessage as SumeragiVersionedMessage},
        Sumeragi,
    },
    tx::AcceptedTransaction,
    BlockSyncMessageSender, SumeragiMessageSender,
};
use async_std::{prelude::*, sync::RwLock, task};
use iroha_data_model::prelude::*;
use iroha_derive::*;
use iroha_error::{error, Error, Result, WrapErr};
use iroha_http_server::{prelude::*, web_socket::WebSocketStream, Server};
#[cfg(feature = "mock")]
use iroha_network::mock::prelude::*;
#[cfg(not(feature = "mock"))]
use iroha_network::prelude::*;
use iroha_version::prelude::*;
use std::{convert::TryFrom, fmt::Debug, sync::Arc};

/// Main network handler and the only entrypoint of the Iroha.
#[derive(Debug)]
pub struct Torii {
    p2p_url: String,
    api_url: String,
    max_transaction_size: usize,
    max_instruction_number: usize,
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    sumeragi_message_sender: Arc<RwLock<SumeragiMessageSender>>,
    block_sync_message_sender: Arc<RwLock<BlockSyncMessageSender>>,
    system: Arc<RwLock<System>>,
    events_sender: EventsSender,
    events_receiver: EventsReceiver,
    transactions_queue: Arc<RwLock<Queue>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
}

impl Torii {
    /// Construct `Torii` from `ToriiConfiguration`.
    #[allow(clippy::clippy::too_many_arguments)]
    pub fn from_configuration(
        configuration: &config::ToriiConfiguration,
        world_state_view: Arc<RwLock<WorldStateView>>,
        transaction_sender: TransactionSender,
        sumeragi_message_sender: SumeragiMessageSender,
        block_sync_message_sender: BlockSyncMessageSender,
        system: System,
        transactions_queue: Arc<RwLock<Queue>>,
        sumeragi: Arc<RwLock<Sumeragi>>,
        (events_sender, events_receiver): (EventsSender, EventsReceiver),
    ) -> Self {
        Torii {
            p2p_url: configuration.torii_p2p_url.clone(),
            api_url: configuration.torii_api_url.clone(),
            max_transaction_size: configuration.torii_max_transaction_size,
            max_instruction_number: configuration.torii_max_instruction_number,
            world_state_view,
            transaction_sender: Arc::new(RwLock::new(transaction_sender)),
            sumeragi_message_sender: Arc::new(RwLock::new(sumeragi_message_sender)),
            block_sync_message_sender: Arc::new(RwLock::new(block_sync_message_sender)),
            system: Arc::new(RwLock::new(system)),
            events_sender,
            events_receiver,
            transactions_queue,
            sumeragi,
        }
    }

    fn create_state(&self) -> ToriiState {
        let world_state_view = Arc::clone(&self.world_state_view);
        let transactions_queue = Arc::clone(&self.transactions_queue);
        let sumeragi = Arc::clone(&self.sumeragi);
        let transaction_sender = Arc::clone(&self.transaction_sender);
        let sumeragi_message_sender = Arc::clone(&self.sumeragi_message_sender);
        let block_sync_message_sender = Arc::clone(&self.block_sync_message_sender);
        let system = Arc::clone(&self.system);
        let consumers = Arc::new(RwLock::new(Vec::new()));

        ToriiState {
            max_transaction_size: self.max_transaction_size,
            max_instruction_number: self.max_instruction_number,
            world_state_view,
            transaction_sender,
            sumeragi_message_sender,
            block_sync_message_sender,
            system,
            consumers,
            events_sender: self.events_sender.clone(),
            transactions_queue,
            sumeragi,
        }
    }

    /// To handle incoming requests `Torii` should be started first.
    pub async fn start(&mut self) -> Result<()> {
        let state = self.create_state();
        let connections = state.consumers.clone();
        let state = Arc::new(RwLock::new(state));
        let mut server = Server::new(state.clone());
        server.at(uri::INSTRUCTIONS_URI).post(handle_instructions);
        server.at(uri::QUERY_URI).get(handle_queries);
        server.at(uri::HEALTH_URI).get(handle_health);
        server.at(uri::METRICS_URI).get(handle_metrics);
        server
            .at(uri::PENDING_TRANSACTIONS_ON_LEADER_URI)
            .get(handle_pending_transactions_on_leader);
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
    max_transaction_size: usize,
    max_instruction_number: usize,
    world_state_view: Arc<RwLock<WorldStateView>>,
    transaction_sender: Arc<RwLock<TransactionSender>>,
    sumeragi_message_sender: Arc<RwLock<SumeragiMessageSender>>,
    block_sync_message_sender: Arc<RwLock<BlockSyncMessageSender>>,
    consumers: Arc<RwLock<Vec<Consumer>>>,
    system: Arc<RwLock<System>>,
    events_sender: EventsSender,
    transactions_queue: Arc<RwLock<Queue>>,
    sumeragi: Arc<RwLock<Sumeragi>>,
}

async fn handle_instructions(
    state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    request: HttpRequest,
) -> Result<HttpResponse> {
    if request.body.len() > state.read().await.max_transaction_size {
        return Err(Error::msg("Transaction is too big"));
    }
    let transaction = VersionedTransaction::decode_versioned(&request.body)?;
    let transaction: Transaction = transaction
        .as_v1()
        .ok_or_else(|| {
            error!(
                "Transaction has unsupported version. Expected version 1, got: {}",
                transaction.version()
            )
        })?
        .clone()
        .into();
    let transaction = AcceptedTransaction::from_transaction(
        transaction,
        state.read().await.max_instruction_number,
    )?;
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

async fn handle_queries(
    state: State<ToriiState>,
    _path_params: PathParams,
    query_params: QueryParams,
    request: HttpRequest,
) -> Result<HttpResponse> {
    //TODO: Remove when `Result::flatten` https://github.com/rust-lang/rust/issues/70142 will be stabilized
    let pagination = Pagination::try_from(&query_params).wrap_err("Failed to decode pagination")?;
    let request: SignedQueryRequest = VersionedSignedQueryRequest::decode_versioned(&request.body)
        .wrap_err("Failed to decode query")?
        .as_v1()
        .ok_or_else(|| Error::msg("Expected version 1 query."))?
        .clone()
        .into();
    let request =
        VerifiedQueryRequest::try_from(request).wrap_err("Failed to verify Query Request")?;
    let result = request
        .query
        .execute(&*state.read().await.world_state_view.read().await)
        .wrap_err("Failed to execute query")?;
    let result = &QueryResult(if let Value::Vec(value) = result {
        Value::Vec(value.into_iter().paginate(pagination).collect())
    } else {
        result
    });
    Ok(HttpResponse::ok(Headers::new(), result.into()))
}

async fn handle_health(
    _state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    _request: HttpRequest,
) -> Result<HttpResponse> {
    Ok(HttpResponse::ok(Headers::new(), Health::Healthy.into()))
}

async fn handle_pending_transactions_on_leader(
    state: State<ToriiState>,
    _path_params: PathParams,
    query_params: QueryParams,
    _request: HttpRequest,
) -> Result<HttpResponse> {
    let pagination = Pagination::try_from(&query_params).wrap_err("Failed to decode pagination")?;
    let PendingTransactions(pending_transactions) = if state
        .read()
        .await
        .sumeragi
        .read()
        .await
        .is_leader()
    {
        state
            .read()
            .await
            .transactions_queue
            .read()
            .await
            .pending_transactions()
    } else {
        let bytes = Network::send_request_to(
            state
                .read()
                .await
                .sumeragi
                .read()
                .await
                .network_topology
                .leader()
                .address
                .as_ref(),
            Request::new(uri::PENDING_TRANSACTIONS_URI.to_string(), Vec::new()),
        )
        .await?
        .into_result()?;
        let message = VersionedPendingTransactions::decode_versioned(&bytes)?;
        message.as_v1().ok_or_else(|| error!("Version mismatch when recieving pending transactions from leader, expected version 1, got: {}", message.version()))?.clone().into()
    };
    let pending_transactions: VersionedPendingTransactions = PendingTransactions(
        pending_transactions
            .into_iter()
            .paginate(pagination)
            .collect(),
    )
    .into();
    Ok(HttpResponse::ok(
        Headers::new(),
        pending_transactions.encode_versioned()?,
    ))
}

async fn handle_metrics(
    state: State<ToriiState>,
    _path_params: PathParams,
    _query_params: QueryParams,
    _request: HttpRequest,
) -> Result<HttpResponse> {
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
) -> Result<()> {
    let consumer = Consumer::new(stream).await?;
    state.read().await.consumers.write().await.push(consumer);
    Ok(())
}

async fn handle_requests(state: State<ToriiState>, stream: Box<dyn AsyncStream>) -> Result<()> {
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
        let mut open_connections = Vec::new();
        for connection in consumers.write().await.drain(..) {
            match connection.consume(&change).await {
                Ok(consumer) => open_connections.push(consumer),
                Err(err) => log::error!("Failed to notify client: {}. Closed connection.", err),
            }
        }
        consumers.write().await.append(&mut open_connections);
    }
}

#[log("TRACE")]
async fn handle_request(state: State<ToriiState>, request: Request) -> Result<Response> {
    match request.url() {
        uri::CONSENSUS_URI => match SumeragiVersionedMessage::decode_versioned(request.payload()) {
            Ok(message) => {
                if let Some(message) = message.as_v1() {
                    let message: SumeragiMessage = message.clone().into();
                    state
                        .read()
                        .await
                        .sumeragi_message_sender
                        .write()
                        .await
                        .try_send(message)
                        .wrap_err(
                            "The sumeragi message channel is full. Dropping the incoming message.",
                        )?;

                    Ok(Response::empty_ok())
                } else {
                    log::error!("Unsupported version: {}", message.version());
                    Ok(Response::InternalError)
                }
            }
            Err(e) => {
                log::error!("Failed to decode peer message: {}", e);
                Ok(Response::InternalError)
            }
        },
        uri::BLOCK_SYNC_URI => match BlockSyncVersionedMessage::decode_versioned(request.payload())
        {
            Ok(message) => {
                if let Some(message) = message.as_v1() {
                    let message: BlockSyncMessage = message.clone().into();
                    state
                        .read()
                        .await
                        .block_sync_message_sender
                        .write()
                        .await
                        .try_send(message)
                        .wrap_err(
                            "The block sync message channel is full. Dropping the incoming message."
                        )?;
                    Ok(Response::empty_ok())
                } else {
                    log::error!("Unsupported version: {}", message.version());
                    Ok(Response::InternalError)
                }
            }
            Err(e) => {
                log::error!("Failed to decode peer message: {}", e);
                Ok(Response::InternalError)
            }
        },
        uri::HEALTH_URI => Ok(Response::empty_ok()),
        uri::PENDING_TRANSACTIONS_URI => {
            let pending_transactions: VersionedPendingTransactions = state
                .read()
                .await
                .transactions_queue
                .read()
                .await
                .pending_transactions()
                .into();
            Ok(Response::Ok(pending_transactions.encode_versioned()?))
        }
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
    /// The web socket uri used to subscribe to block and transactions statuses.
    pub const SUBSCRIPTION_URI: &str = "/events";
    /// Get pending transactions.
    pub const PENDING_TRANSACTIONS_URI: &str = "/pending_transactions";
    /// Get pending transactions on leader.
    pub const PENDING_TRANSACTIONS_ON_LEADER_URI: &str = "/pending_transactions_on_leader";
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_error::{Result, WrapErr};
    use serde::Deserialize;
    use std::env;

    const TORII_API_URL: &str = "TORII_API_URL";
    const TORII_P2P_URL: &str = "TORII_P2P_URL";
    const TORII_MAX_TRANSACTION_SIZE: &str = "TORII_MAX_TRANSACTION_SIZE";
    const TORII_MAX_INSTRUCTION_NUMBER: &str = "TORII_MAX_INSTRUCTION_NUMBER";
    const DEFAULT_TORII_P2P_URL: &str = "127.0.0.1:1337";
    const DEFAULT_TORII_API_URL: &str = "127.0.0.1:8080";
    const DEFAULT_TORII_MAX_TRANSACTION_SIZE: usize = 32768;
    const DEFAULT_TORII_MAX_INSTRUCTION_NUMBER: usize = 4096;

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
        /// Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.
        #[serde(default = "default_torii_max_transaction_size")]
        pub torii_max_transaction_size: usize,
        /// Maximum number of instruction per transaction. Used to prevent from DOS attacks.
        #[serde(default = "default_torii_max_instruction_number")]
        pub torii_max_instruction_number: usize,
    }

    impl ToriiConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        pub fn load_environment(&mut self) -> Result<()> {
            if let Ok(torii_api_url) = env::var(TORII_API_URL) {
                self.torii_api_url = torii_api_url;
            }
            if let Ok(torii_p2p_url) = env::var(TORII_P2P_URL) {
                self.torii_p2p_url = torii_p2p_url;
            }
            if let Ok(torii_max_transaction_size) = env::var(TORII_MAX_TRANSACTION_SIZE) {
                self.torii_max_transaction_size = torii_max_transaction_size
                    .parse::<usize>()
                    .wrap_err("Failed to get maximum size of transaction")?;
            }
            if let Ok(torii_max_instruction_number) = env::var(TORII_MAX_INSTRUCTION_NUMBER) {
                self.torii_max_instruction_number =
                    torii_max_instruction_number.parse::<usize>().wrap_err(
                        "Failed to get maximum number of instructions per transaction: {}",
                    )?;
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

    fn default_torii_max_transaction_size() -> usize {
        DEFAULT_TORII_MAX_TRANSACTION_SIZE
    }

    fn default_torii_max_instruction_number() -> usize {
        DEFAULT_TORII_MAX_INSTRUCTION_NUMBER
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use async_std::{future, sync};
    use futures::future::FutureExt;
    use iroha_data_model::account::Id;
    use iroha_error::MessageError;
    use std::{convert::TryInto, time::Duration};

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    fn get_config() -> Configuration {
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.")
    }

    async fn create_torii() -> Torii {
        let config = get_config();
        let (tx_tx, _) = sync::channel(100);
        let (sumeragi_message_sender, _) = sync::channel(100);
        let (block_sync_message_sender, _) = sync::channel(100);
        let (block_sender, _) = sync::channel(100);
        let (events_sender, events_receiver) = sync::channel(100);
        let queue = Queue::from_configuration(&config.queue_configuration);
        let wsv = Arc::new(RwLock::new(WorldStateView::new(World::with(
            ('a'..'z')
                .map(|name| name.to_string())
                .map(|name| (name.clone(), Domain::new(&name)))
                .collect(),
            Default::default(),
        ))));
        let sumeragi = Sumeragi::from_configuration(
            &config.sumeragi_configuration,
            Arc::new(RwLock::new(block_sender)),
            events_sender.clone(),
            wsv.clone(),
            tx_tx.clone(),
            AllowAll.into(),
        )
        .expect("Failed to initialize sumeragi.");

        Torii::from_configuration(
            &config.torii_configuration,
            wsv,
            tx_tx,
            sumeragi_message_sender,
            block_sync_message_sender,
            System::new(&config),
            Arc::new(RwLock::new(queue)),
            Arc::new(RwLock::new(sumeragi)),
            (events_sender, events_receiver),
        )
    }

    #[async_std::test]
    async fn create_and_start_torii() {
        let mut torii = create_torii().await;

        let result = future::timeout(
            Duration::from_millis(50),
            async move { torii.start().await },
        )
        .await;

        assert!(result.is_err() || result.unwrap().is_ok());
    }

    #[async_std::test]
    async fn torii_big_transaction() {
        let torii = create_torii().await;
        let state = Arc::new(RwLock::new(torii.create_state()));
        let id = Id {
            name: Default::default(),
            domain_name: Default::default(),
        };
        let instruction: Instruction = FailBox {
            message: "Fail message".to_owned(),
        }
        .into();

        let mut instruction_number = 32;

        let request = loop {
            let transaction = Transaction::new(
                vec![instruction.clone(); instruction_number],
                id.clone(),
                10_000,
            );
            let body: Vec<u8> = transaction.into();
            let request = HttpRequest {
                method: "POST".to_owned(),
                path: uri::INSTRUCTIONS_URI.to_owned(),
                version: HttpVersion::Http1_1,
                headers: Default::default(),
                body,
            };

            if request.body.len() <= torii.max_transaction_size {
                instruction_number *= 2;
                continue;
            }
            break request;
        };

        let result =
            handle_instructions(state, Default::default(), Default::default(), request).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err = err.downcast_ref::<MessageError<&'static str>>().unwrap();
        assert_eq!(err.msg, "Transaction is too big");
    }

    #[async_std::test]
    async fn torii_pagination() {
        let torii = create_torii().await;
        let state = Arc::new(RwLock::new(torii.create_state()));

        let keys = KeyPair::generate().expect("Failed to generate keys");

        let get_domains = |start, limit| {
            let query: VersionedSignedQueryRequest =
                QueryRequest::new(QueryBox::FindAllDomains(Box::new(Default::default())))
                    .sign(&keys)
                    .expect("Failed to sign query with keys")
                    .into();
            let body: Vec<u8> = query.encode_versioned().expect("Failed to encode.");
            let request = HttpRequest {
                method: "POST".to_owned(),
                path: uri::QUERY_URI.to_owned(),
                version: HttpVersion::Http1_1,
                headers: Default::default(),
                body,
            };

            let pagination = Pagination { start, limit }.into();
            handle_queries(state.clone(), Default::default(), pagination, request).map(|result| {
                let QueryResult(query) = result
                    .expect("Failed request with query")
                    .body
                    .try_into()
                    .expect("Failed to convert");
                if let Value::Vec(domain) = query {
                    domain
                } else {
                    unreachable!()
                }
            })
        };

        assert_eq!(get_domains(None, None).await.len(), 25);
        assert_eq!(get_domains(Some(0), None).await.len(), 25);
        assert_eq!(get_domains(Some(15), Some(5)).await.len(), 5);
        assert_eq!(get_domains(None, Some(10)).await.len(), 10);
        assert_eq!(get_domains(Some(1), Some(15)).await.len(), 15);
    }
}
