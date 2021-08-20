//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use std::{convert::Infallible, fmt::Debug, net::ToSocketAddrs, sync::Arc};

use config::ToriiConfiguration;
use iroha_actor::{broker::*, prelude::*};
use iroha_config::{derive::Error as ConfigError, Configurable};
use iroha_data_model::prelude::*;
use iroha_error::{derive::Error, error, WrapErr};
use iroha_logger::InstrumentFutures;
#[cfg(feature = "mock")]
use iroha_network::mock::prelude::*;
#[cfg(not(feature = "mock"))]
use iroha_network::prelude::*;
use iroha_version::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::task;
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
    block_sync::message::VersionedMessage as BlockSyncVersionedMessage,
    event::{Consumer, EventsSender},
    prelude::*,
    queue::{GetPendingTransactions, QueueTrait},
    smartcontracts::{isi::query::VerifiedQueryRequest, permissions::IsQueryAllowedBoxed},
    sumeragi::{
        message::VersionedMessage as SumeragiVersionedMessage, GetLeader, IsLeader, SumeragiTrait,
    },
    wsv::WorldTrait,
    Configuration,
};

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait> {
    config: ToriiConfiguration,
    wsv: Arc<WorldStateView<W>>,
    events: EventsSender,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
    transactions_queue: AlwaysAddr<Q>,
    sumeragi: AlwaysAddr<S>,
    broker: Broker,
}

/// Errors of torii
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to decode transaction
    #[error("Failed to decode transaction")]
    VersionedTransaction(#[source] iroha_version::error::Error),
    /// Failed to accept transaction
    #[error("Failed to accept transaction")]
    AcceptTransaction(iroha_error::Error),
    /// Failed to execute query
    #[error("Failed to execute query")]
    ExecuteQuery(iroha_error::Error),
    /// Failed to validate query
    #[error("Failed to validate query")]
    ValidateQuery(iroha_error::Error),
    /// Failed to get pending transaction
    #[error("Failed to get pending transactions")]
    RequestPendingTransactions(iroha_error::Error),
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

impl<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait> Torii<Q, S, W> {
    /// Construct `Torii` from `ToriiConfiguration`.
    #[allow(clippy::too_many_arguments, clippy::missing_const_for_fn)]
    pub fn from_configuration(
        config: ToriiConfiguration,
        wsv: Arc<WorldStateView<W>>,
        transactions_queue: AlwaysAddr<Q>,
        sumeragi: AlwaysAddr<S>,
        query_validator: Arc<IsQueryAllowedBoxed<W>>,
        events: EventsSender,
        broker: Broker,
    ) -> Self {
        Self {
            config,
            wsv,
            events,
            query_validator,
            transactions_queue,
            sumeragi,
            broker,
        }
    }

    #[allow(clippy::expect_used)]
    fn create_state(&self) -> ToriiState<Q, S, W> {
        let wsv = Arc::clone(&self.wsv);
        let transactions_queue = self.transactions_queue.clone();
        let sumeragi = self.sumeragi.clone();
        let config = self.config.clone();
        let broker = self.broker.clone();
        let query_validator = Arc::clone(&self.query_validator);

        Arc::new(InnerToriiState {
            config,
            wsv,
            transactions_queue,
            query_validator,
            sumeragi,
            broker,
        })
    }

    /// To handle incoming requests `Torii` should be started first.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    #[iroha_futures::telemetry_future]
    pub async fn start(self) -> iroha_error::Result<Infallible> {
        let state = self.create_state();

        let get_router = warp::path(uri::HEALTH)
            .and_then(|| async { Ok::<_, Infallible>(handle_health().await) })
            .or(endpoint3(
                handle_queries,
                warp::path(uri::QUERY)
                    .and(add_state(Arc::clone(&state)))
                    .and(paginate())
                    .and(body::query()),
            ))
            .or(endpoint2(
                handle_pending_transactions_on_leader,
                warp::path(uri::PENDING_TRANSACTIONS_ON_LEADER)
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
                    state.config.torii_max_transaction_size as u64,
                ))
                .and(body::versioned()),
        );

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

        #[allow(clippy::unwrap_used)]
        let addr = self
            .config
            .torii_api_url
            .to_socket_addrs()
            .wrap_err("Failed to get socket addr")?
            .next()
            .unwrap();

        let (handle_requests_result, _) = tokio::join!(
            Network::listen(
                Arc::clone(&state),
                &self.config.torii_p2p_url,
                handle_requests
            ),
            warp::serve(router).run(addr),
        );
        handle_requests_result
    }
}

struct InnerToriiState<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait> {
    config: ToriiConfiguration,
    wsv: Arc<WorldStateView<W>>,
    transactions_queue: AlwaysAddr<Q>,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
    sumeragi: AlwaysAddr<S>,
    broker: Broker,
}

type ToriiState<Q, S, W> = Arc<InnerToriiState<Q, S, W>>;

#[iroha_futures::telemetry_future]
async fn handle_instructions<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait>(
    state: ToriiState<Q, S, W>,
    transaction: VersionedTransaction,
) -> Result<Empty> {
    let transaction: Transaction = transaction.into_inner_v1();
    let transaction = VersionedAcceptedTransaction::from_transaction(
        transaction,
        state.config.torii_max_instruction_number,
    )
    .map_err(Error::AcceptTransaction)?;
    state.broker.issue_send(transaction).await;
    Ok(Empty)
}

#[iroha_futures::telemetry_future]
async fn handle_queries<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait>(
    state: ToriiState<Q, S, W>,
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
async fn handle_pending_transactions_on_leader<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait>(
    state: ToriiState<Q, S, W>,
    pagination: Pagination,
) -> Result<Scale<VersionedPendingTransactions>> {
    #[allow(clippy::unwrap_used)]
    let PendingTransactions(pending_transactions) = if state.sumeragi.send(IsLeader).await {
        state.transactions_queue.send(GetPendingTransactions).await
    } else {
        let bytes = Network::send_request_to(
            state.sumeragi.send(GetLeader).await.address.as_ref(),
            Request::empty(uri::PENDING_TRANSACTIONS),
        )
        .await
        .map_err(Error::RequestPendingTransactions)?
        .into_result()
        .map_err(Error::RequestPendingTransactions)?;

        VersionedPendingTransactions::decode_versioned(&bytes)
            .map_err(Error::DecodeRequestPendingTransactions)?
            .into_inner_v1()
    };

    Ok(Scale(
        PendingTransactions(
            pending_transactions
                .into_iter()
                .paginate(pagination)
                .collect(),
        )
        .into(),
    ))
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
async fn handle_subscription(events: EventsSender, stream: WebSocket) -> iroha_error::Result<()> {
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

#[iroha_futures::telemetry_future]
async fn handle_requests<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait>(
    state: ToriiState<Q, S, W>,
    stream: Box<dyn AsyncStream>,
) -> iroha_error::Result<()> {
    let state_arc = Arc::clone(&state);
    task::spawn(async {
        if let Err(e) = Network::handle_message_async(state_arc, stream, handle_request).await {
            let e = e.report();
            iroha_logger::error!("Failed to handle message: {}", e);
        }
    })
    .in_current_span()
    .await?;
    Ok(())
}

#[iroha_futures::telemetry_future]
async fn handle_request<Q: QueueTrait, S: SumeragiTrait, W: WorldTrait>(
    state: ToriiState<Q, S, W>,
    request: Request,
) -> iroha_error::Result<iroha_network::Response> {
    use iroha_network::Response;

    #[allow(clippy::pattern_type_mismatch)]
    match request.uri_path.as_ref() {
        uri::CONSENSUS if request.payload.len() > state.config.torii_max_sumeragi_message_size => {
            iroha_logger::error!("Message is too big. Droping");
            Ok(Response::InternalError)
        }
        uri::CONSENSUS => {
            let message = match SumeragiVersionedMessage::decode_versioned(&request.payload) {
                Ok(message) => message,
                Err(e) => {
                    iroha_logger::error!("Failed to decode peer message: {}", e);
                    return Ok(Response::InternalError);
                }
            };
            state.broker.issue_send(message.into_inner_v1()).await;
            Ok(Response::empty_ok())
        }
        uri::BLOCK_SYNC => {
            let message = match BlockSyncVersionedMessage::decode_versioned(&request.payload) {
                Ok(message) => message.into_inner_v1(),
                Err(e) => {
                    iroha_logger::error!("Failed to decode peer message: {}", e);
                    return Ok(Response::InternalError);
                }
            };

            state.broker.issue_send(message).await;
            Ok(Response::empty_ok())
        }
        uri::HEALTH => Ok(Response::empty_ok()),
        uri::PENDING_TRANSACTIONS => {
            let pending_transactions: VersionedPendingTransactions = state
                .transactions_queue
                .send(GetPendingTransactions)
                .await
                .into();
            Ok(Response::Ok(
                pending_transactions
                    .encode_versioned()
                    .map_err(Error::EncodePendingTransactions)?,
            ))
        }
        non_supported_uri => {
            iroha_logger::error!("URI not supported: {}.", &non_supported_uri);
            Ok(Response::InternalError)
        }
    }
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
    /// Get pending transactions on leader.
    pub const PENDING_TRANSACTIONS_ON_LEADER: &str = "pending_transactions_on_leader";
    /// The URI for local config changing inspecting
    pub const CONFIGURATION: &str = "configure";
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    const DEFAULT_TORII_P2P_URL: &str = "127.0.0.1:1337";
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
        pub torii_p2p_url: String,
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
                torii_p2p_url: DEFAULT_TORII_P2P_URL.to_owned(),
                torii_max_transaction_size: DEFAULT_TORII_MAX_TRANSACTION_SIZE,
                torii_max_sumeragi_message_size: DEFAULT_TORII_MAX_SUMERAGI_MESSAGE_SIZE,
                torii_max_instruction_number: DEFAULT_TORII_MAX_INSTRUCTION_NUMBER,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::default_trait_access, clippy::restriction)]

    use std::{convert::TryInto, iter, time::Duration};

    use futures::future::FutureExt;
    use iroha_actor::broker::Broker;
    use tokio::{sync::broadcast, time};

    use super::*;
    use crate::{
        config::Configuration,
        genesis::GenesisNetwork,
        queue::{Queue, QueueTrait},
        sumeragi::{Sumeragi, SumeragiTrait},
        wsv::World,
    };

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";

    fn get_config() -> Configuration {
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.")
    }

    async fn create_torii() -> (
        Torii<Queue<World>, Sumeragi<Queue<World>, GenesisNetwork, World>, World>,
        KeyPair,
    ) {
        let broker = Broker::new();
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
        let queue = Queue::from_configuration(
            &config.queue_configuration,
            Arc::clone(&wsv),
            broker.clone(),
        )
        .start()
        .await
        .expect_running();
        let sumeragi = Sumeragi::from_configuration(
            &config.sumeragi_configuration,
            events.clone(),
            Arc::clone(&wsv),
            AllowAll.into(),
            Arc::new(AllowAll.into()),
            None,
            queue.clone(),
            broker.clone(),
        )
        .expect("Failed to initialize sumeragi.")
        .start()
        .await
        .expect_running();

        (
            Torii::from_configuration(
                config.torii_configuration.clone(),
                wsv,
                queue,
                sumeragi,
                Arc::new(AllowAll.into()),
                events,
                broker,
            ),
            keys,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_start_torii() {
        let (torii, _) = create_torii().await;

        let result = time::timeout(Duration::from_millis(50), torii.start()).await;

        assert!(result.is_err() || result.unwrap().is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn torii_pagination() {
        let (torii, keys) = create_torii().await;
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
        let (torii, keys) = create_torii().await;
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
