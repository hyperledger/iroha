//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use std::{convert::Infallible, fmt::Debug, net::ToSocketAddrs, sync::Arc};

use config::ToriiConfiguration;
use iroha_config::{derive::Error as ConfigError, Configurable};
use iroha_data_model::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utils::*;
use warp::{
    http::StatusCode,
    reply::{self, Json, Response},
    ws::{WebSocket, Ws},
    Filter, Reply,
};

#[macro_use]
mod utils;

use crate::{
    event::{Consumer, EventsSender},
    prelude::*,
    queue::Queue,
    smartcontracts::{isi::query::VerifiedQueryRequest, permissions::IsQueryAllowedBoxed},
    wsv::WorldTrait,
    Configuration,
};

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii<W: WorldTrait> {
    config: ToriiConfiguration,
    wsv: Arc<WorldStateView<W>>,
    events: EventsSender,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
    queue: Arc<Queue>,
}

/// Errors of torii
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to decode transaction
    #[error("Failed to decode transaction")]
    VersionedTransaction(#[source] iroha_version::error::Error),
    /// Failed to accept transaction
    #[error("Failed to accept transaction")]
    AcceptTransaction(eyre::Error),
    /// Failed to execute query
    #[error("Failed to execute query")]
    ExecuteQuery(eyre::Error),
    /// Failed to validate query
    #[error("Failed to validate query")]
    ValidateQuery(eyre::Error),
    /// Failed to get pending transaction
    #[error("Failed to get pending transactions")]
    RequestPendingTransactions(eyre::Error),
    /// Failed to decode pending transactions from leader
    #[error("Failed to decode pending transactions from leader")]
    DecodeRequestPendingTransactions(#[source] iroha_version::error::Error),
    /// Failed to encode pending transactions
    #[error("Failed to encode pending transactions")]
    EncodePendingTransactions(#[source] iroha_version::error::Error),
    /// The block sync message channel is full. Dropping the incoming message.
    #[error("Transaction is too big")]
    TxTooBig,
    /// Error while getting or setting configuration
    #[error("Configuration error")]
    Config(#[source] ConfigError),
    /// Queue is full
    #[error("Queue is full")]
    FullQueue,
}

impl warp::reject::Reject for Error {}

impl Reply for Error {
    fn into_response(self) -> Response {
        const fn status_code(err: &Error) -> StatusCode {
            use Error::*;

            match *err {
                ExecuteQuery(_)
                | RequestPendingTransactions(_)
                | DecodeRequestPendingTransactions(_)
                | FullQueue
                | EncodePendingTransactions(_) => StatusCode::INTERNAL_SERVER_ERROR,
                TxTooBig | VersionedTransaction(_) | AcceptTransaction(_) | ValidateQuery(_) => {
                    StatusCode::BAD_REQUEST
                }
                Config(_) => StatusCode::NOT_FOUND,
            }
        }

        reply::with_status(self.to_string(), status_code(&self)).into_response()
    }
}

/// Result type
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl<W: WorldTrait> Torii<W> {
    /// Construct `Torii` from `ToriiConfiguration`.
    pub fn from_configuration(
        config: ToriiConfiguration,
        wsv: Arc<WorldStateView<W>>,
        queue: Arc<Queue>,
        query_validator: Arc<IsQueryAllowedBoxed<W>>,
        events: EventsSender,
    ) -> Self {
        Self {
            config,
            wsv,
            events,
            query_validator,
            queue,
        }
    }

    #[allow(clippy::expect_used)]
    fn create_state(&self) -> ToriiState<W> {
        let wsv = Arc::clone(&self.wsv);
        let queue = Arc::clone(&self.queue);
        let config = self.config.clone();
        let query_validator = Arc::clone(&self.query_validator);

        Arc::new(InnerToriiState {
            config,
            wsv,
            queue,
            query_validator,
        })
    }

    /// To handle incoming requests `Torii` should be started first.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    #[iroha_futures::telemetry_future]
    pub async fn start(self) -> eyre::Result<()> {
        let state = self.create_state();

        let get_router = warp::path(uri::HEALTH)
            .and_then(|| async { Ok::<_, Infallible>(handle_health().await) })
            .or(endpoint2(
                handle_pending_transactions,
                warp::path(uri::PENDING_TRANSACTIONS)
                    .and(add_state(Arc::clone(&state)))
                    .and(paginate()),
            ))
            .or(endpoint2(
                handle_get_configuration,
                warp::path(uri::CONFIGURATION)
                    .and(warp::query())
                    .and(warp::body::json()),
            ));

        let post_router = endpoint2(
            handle_instructions,
            warp::path(uri::TRANSACTION)
                .and(add_state(Arc::clone(&state)))
                .and(warp::body::content_length_limit(
                    state.config.torii_max_sumeragi_message_size as u64,
                ))
                .and(body::versioned()),
        )
        .or(endpoint3(
            handle_queries,
            warp::path(uri::QUERY)
                .and(add_state(Arc::clone(&state)))
                .and(paginate())
                .and(body::query()),
        ));

        let ws_router = warp::path(uri::SUBSCRIPTION)
            .and(add_state(self.events))
            .and(warp::ws())
            .map(|events, ws: Ws| {
                ws.on_upgrade(|ws| async move {
                    if let Err(err) = handle_subscription(events, ws).await {
                        iroha_logger::error!(?err, "Failed to subscribe someone");
                    }
                })
            });

        let router = warp::post()
            .and(post_router)
            .or(warp::get().and(get_router))
            .or(ws_router)
            .with(warp::trace::request());

        match self.config.torii_api_url.to_socket_addrs() {
            Ok(mut i) => {
                #[allow(clippy::expect_used)]
                let addr = i.next().expect("Failed to get socket addr");
                warp::serve(router).run(addr).await;
                Ok(())
            }
            Err(e) => {
                iroha_logger::error!("Failed to get socket addr");
                Err(eyre::Error::new(e))
            }
        }
    }
}

struct InnerToriiState<W: WorldTrait> {
    config: ToriiConfiguration,
    wsv: Arc<WorldStateView<W>>,
    queue: Arc<Queue>,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
}

type ToriiState<W> = Arc<InnerToriiState<W>>;

#[iroha_futures::telemetry_future]
async fn handle_instructions<W: WorldTrait>(
    state: ToriiState<W>,
    transaction: VersionedTransaction,
) -> Result<Empty> {
    let transaction: Transaction = transaction.into_inner_v1();
    let transaction = VersionedAcceptedTransaction::from_transaction(
        transaction,
        state.config.torii_max_instruction_number,
    )
    .map_err(Error::AcceptTransaction)?;
    #[allow(clippy::map_err_ignore)]
    state
        .queue
        .push(transaction, &*state.wsv)
        .map_err(|_| Error::FullQueue)
        .map(|()| Empty)
}

#[iroha_futures::telemetry_future]
async fn handle_queries<W: WorldTrait>(
    state: ToriiState<W>,
    pagination: Pagination,
    request: VerifiedQueryRequest,
) -> Result<Scale<QueryResult>> {
    let valid_request = request
        .validate(&*state.wsv, &state.query_validator)
        .map_err(Error::ValidateQuery)?;
    let result = valid_request
        .execute(&*state.wsv)
        .map_err(Error::ExecuteQuery)?;
    let result = QueryResult(if let Value::Vec(value) = result {
        Value::Vec(value.into_iter().paginate(pagination).collect())
    } else {
        result
    });
    Ok(Scale(result))
}

#[derive(Serialize)]
#[non_exhaustive]
enum Health {
    Healthy,
}

#[iroha_futures::telemetry_future]
async fn handle_health() -> Json {
    reply::json(&Health::Healthy)
}

#[iroha_futures::telemetry_future]
async fn handle_pending_transactions<W: WorldTrait>(
    state: ToriiState<W>,
    pagination: Pagination,
) -> Result<Scale<VersionedPendingTransactions>> {
    Ok(Scale(state.queue.waiting().paginate(pagination).collect()))
}

#[derive(Clone, Debug, Deserialize)]
enum GetConfigurationType {
    Docs,
    Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GetConfiguration {
    field: Vec<String>,
}

#[iroha_futures::telemetry_future]
async fn handle_get_configuration(
    ty: GetConfigurationType,
    GetConfiguration { field }: GetConfiguration,
) -> Result<Json> {
    use GetConfigurationType::*;

    let field = field.iter().map(AsRef::as_ref).collect::<Vec<&str>>();

    #[allow(clippy::todo)]
    match ty {
        Docs => Configuration::get_doc_recursive(field)
            .map(|doc| {
                if let Some(doc) = doc {
                    serde_json::json!(doc)
                } else {
                    serde_json::json!(null)
                }
            })
            .map(|v| reply::json(&v)),
        Value => todo!(),
    }
    .map_err(Error::Config)
}

#[iroha_futures::telemetry_future]
async fn handle_subscription(events: EventsSender, stream: WebSocket) -> eyre::Result<()> {
    let mut events = events.subscribe();
    let mut consumer = Consumer::new(stream).await?;

    while let Ok(change) = events.recv().await {
        iroha_logger::trace!("Event occurred: {:?}", change);

        if let Err(err) = consumer.consume(&change).await {
            iroha_logger::error!("Failed to notify client: {}. Closed connection.", err);
            break;
        }
    }

    Ok(())
}

/// URI that `Torii` uses to route incoming requests.
pub mod uri {
    /// Query URI is used to handle incoming Query requests.
    pub const QUERY: &str = "query";
    /// Transaction URI is used to handle incoming ISI requests.
    pub const TRANSACTION: &str = "transaction";
    /// Block URI is used to handle incoming Block requests.
    pub const CONSENSUS: &str = "consensus";
    /// Health URI is used to handle incoming Healthcheck requests.
    pub const HEALTH: &str = "health";
    /// The URI used for block synchronization.
    pub const BLOCK_SYNC: &str = "block";
    /// The web socket uri used to subscribe to block and transactions statuses.
    pub const SUBSCRIPTION: &str = "events";
    /// Get pending transactions.
    pub const PENDING_TRANSACTIONS: &str = "pending_transactions";
    /// The URI for local config changing inspecting
    pub const CONFIGURATION: &str = "configure";
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    const DEFAULT_TORII_P2P_ADDR: &str = "127.0.0.1:1337";
    const DEFAULT_TORII_API_URL: &str = "127.0.0.1:8080";
    const DEFAULT_TORII_MAX_TRANSACTION_SIZE: usize = 2_usize.pow(15);
    const DEFAULT_TORII_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
    const DEFAULT_TORII_MAX_SUMERAGI_MESSAGE_SIZE: usize = 2_usize.pow(12) * 4000;

    /// `ToriiConfiguration` provides an ability to define parameters such as `TORII_URL`.
    #[derive(Clone, Deserialize, Serialize, Debug, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    pub struct ToriiConfiguration {
        /// Torii URL for p2p communication for consensus and block synchronization purposes.
        pub torii_p2p_addr: String,
        /// Torii URL for client API.
        pub torii_api_url: String,
        /// Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.
        pub torii_max_transaction_size: usize,
        /// Maximum number of bytes in raw message. Used to prevent from DOS attacks.
        pub torii_max_sumeragi_message_size: usize,
        /// Maximum number of instruction per transaction. Used to prevent from DOS attacks.
        pub torii_max_instruction_number: u64,
    }

    impl Default for ToriiConfiguration {
        fn default() -> Self {
            Self {
                torii_api_url: DEFAULT_TORII_API_URL.to_owned(),
                torii_p2p_addr: DEFAULT_TORII_P2P_ADDR.to_owned(),
                torii_max_transaction_size: DEFAULT_TORII_MAX_TRANSACTION_SIZE,
                torii_max_sumeragi_message_size: DEFAULT_TORII_MAX_SUMERAGI_MESSAGE_SIZE,
                torii_max_instruction_number: DEFAULT_TORII_MAX_INSTRUCTION_NUMBER,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::restriction)]

    use std::{convert::TryInto, iter, time::Duration};

    use futures::future::FutureExt;
    use tokio::{sync::broadcast, time};

    use super::*;
    use crate::{config::Configuration, queue::Queue, wsv::World};

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";

    fn get_config() -> Configuration {
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.")
    }

    fn create_torii() -> (Torii<World>, KeyPair) {
        let mut config = get_config();
        config
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
        let (events, _) = broadcast::channel(100);
        let wsv = Arc::new(WorldStateView::new(World::with(
            ('a'..'z')
                .map(|name| name.to_string())
                .map(|name| (name.clone(), Domain::new(&name))),
            vec![],
        )));
        let keys = KeyPair::generate().expect("Failed to generate keys");
        wsv.world.domains.insert(
            "wonderland".to_owned(),
            Domain::with_accounts(
                "wonderland",
                iter::once(Account::with_signatory(
                    AccountId::new("alice", "wonderland"),
                    keys.public_key.clone(),
                )),
            ),
        );
        let queue = Arc::new(Queue::from_configuration(&config.queue_configuration));

        (
            Torii::from_configuration(
                config.torii_configuration,
                wsv,
                queue,
                Arc::new(AllowAll.into()),
                events,
            ),
            keys,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_start_torii() {
        let (torii, _) = create_torii();

        let result = time::timeout(Duration::from_millis(50), torii.start()).await;

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn torii_pagination() {
        let (torii, keys) = create_torii();
        let state = torii.create_state();

        let get_domains = |start, limit| {
            let query: VerifiedQueryRequest = QueryRequest::new(
                QueryBox::FindAllDomains(Default::default()),
                AccountId::new("alice", "wonderland"),
            )
            .sign(&keys)
            .expect("Failed to sign query with keys")
            .try_into()
            .expect("Failed to verify");

            let pagination = Pagination { start, limit };
            handle_queries(state.clone(), pagination, query).map(|result| {
                if let Scale(QueryResult(Value::Vec(domain))) =
                    result.expect("Failed request with query")
                {
                    domain
                } else {
                    unreachable!()
                }
            })
        };

        assert_eq!(get_domains(None, None).await.len(), 26);
        assert_eq!(get_domains(Some(0), None).await.len(), 26);
        assert_eq!(get_domains(Some(15), Some(5)).await.len(), 5);
        assert_eq!(get_domains(None, Some(10)).await.len(), 10);
        assert_eq!(get_domains(Some(1), Some(15)).await.len(), 15);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn query_signed_by_keys_not_associated_with_account() {
        let (torii, keys) = create_torii();
        let state = torii.create_state();

        let query: VerifiedQueryRequest = QueryRequest::new(
            QueryBox::FindAllDomains(Default::default()),
            AccountId::new("bob", "wonderland"),
        )
        .sign(&keys)
        .expect("Failed to sign query with keys")
        .try_into()
        .expect("Failed to verify");

        let query_result = handle_queries(state.clone(), Default::default(), query).await;

        assert!(matches!(query_result, Err(Error::ValidateQuery(_))));
    }
}
