//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use std::{convert::Infallible, fmt::Debug, net::ToSocketAddrs, sync::Arc};

use eyre::Context;
use iroha_config::{Configurable, GetConfiguration, PostConfiguration};
use iroha_data_model::prelude::*;
use serde::Serialize;
use thiserror::Error;
use utils::*;
use warp::{
    http::StatusCode,
    reject::Rejection,
    reply::{self, Json, Response},
    ws::{WebSocket, Ws},
    Filter, Reply,
};

#[macro_use]
mod utils;

use crate::{
    event::{Consumer, EventsSender},
    prelude::*,
    queue::{self, Queue},
    smartcontracts::{
        isi::query::{self, VerifiedQueryRequest},
        permissions::IsQueryAllowedBoxed,
    },
    wsv::WorldTrait,
    Addr, Configuration, IrohaNetwork,
};

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii<W: WorldTrait> {
    iroha_cfg: Configuration,
    wsv: Arc<WorldStateView<W>>,
    events: EventsSender,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
    queue: Arc<Queue>,
    network: Addr<IrohaNetwork>,
}

/// Torii errors.
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to execute or validate query
    #[error("Failed to execute or validate query")]
    Query(#[source] query::Error),
    /// Failed to decode transaction
    #[error("Failed to decode transaction")]
    VersionedTransaction(#[source] iroha_version::error::Error),
    /// Failed to accept transaction
    #[error("Failed to accept transaction: {0}")]
    AcceptTransaction(eyre::Error),
    /// Failed to get pending transaction
    #[error("Failed to get pending transactions: {0}")]
    RequestPendingTransactions(eyre::Error),
    /// Failed to decode pending transactions from leader
    #[error("Failed to decode pending transactions from leader")]
    DecodeRequestPendingTransactions(#[source] iroha_version::error::Error),
    /// Failed to encode pending transactions
    #[error("Failed to encode pending transactions")]
    EncodePendingTransactions(#[source] iroha_version::error::Error),
    /// The block sync message channel is full. Dropping the incoming message
    #[error("Transaction is too big")]
    TxTooBig,
    /// Error while getting or setting configuration
    #[error("Configuration error: {0}")]
    Config(eyre::Error),
    /// Failed to push into queue
    #[error("Failed to push into queue")]
    PushIntoQueue(#[source] Box<queue::Error>),
    /// Error while getting status
    #[error("Failed to get status")]
    Status(#[source] iroha_actor::Error),
    /// Configuration change error.
    #[error("Attempt to change configuration failed. {0}")]
    ConfigurationReload(#[source] iroha_config::runtime_upgrades::ReloadError),
    /// Error while getting Prometheus metrics
    #[error("Failed to produce Prometheus metrics")]
    Prometheus(#[source] eyre::Report),
}

impl Reply for Error {
    fn into_response(self) -> Response {
        const fn status_code(err: &Error) -> StatusCode {
            use Error::*;

            match err {
                Query(e) => e.status_code(),
                VersionedTransaction(_)
                | AcceptTransaction(_)
                | RequestPendingTransactions(_)
                | DecodeRequestPendingTransactions(_)
                | EncodePendingTransactions(_)
                | ConfigurationReload(_)
                | TxTooBig => StatusCode::BAD_REQUEST,
                Config(_) => StatusCode::NOT_FOUND,
                PushIntoQueue(err) => match **err {
                    queue::Error::Full => StatusCode::INTERNAL_SERVER_ERROR,
                    queue::Error::SignatureCondition(_) => StatusCode::UNAUTHORIZED,
                    _ => StatusCode::BAD_REQUEST,
                },
                Prometheus(_) | Status(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }

        fn to_string(mut err: &dyn std::error::Error) -> String {
            let mut s = "Error:\n".to_owned();
            let mut idx = 0_i32;

            loop {
                s += &format!("    {}: {}\n", idx, &err.to_string());
                idx += 1_i32;
                match err.source() {
                    Some(e) => err = e,
                    None => return s,
                }
            }
        }

        reply::with_status(to_string(&self), status_code(&self)).into_response()
    }
}

/// Result type
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<iroha_config::runtime_upgrades::ReloadError> for Error {
    fn from(err: iroha_config::runtime_upgrades::ReloadError) -> Self {
        Self::ConfigurationReload(err)
    }
}

impl<W: WorldTrait> Torii<W> {
    /// Construct `Torii` from `ToriiConfiguration`.
    pub fn from_configuration(
        iroha_cfg: Configuration,
        wsv: Arc<WorldStateView<W>>,
        queue: Arc<Queue>,
        query_validator: Arc<IsQueryAllowedBoxed<W>>,
        events: EventsSender,
        network: Addr<IrohaNetwork>,
    ) -> Self {
        Self {
            iroha_cfg,
            wsv,
            events,
            query_validator,
            queue,
            network,
        }
    }

    #[allow(clippy::expect_used)]
    fn create_state(&self) -> ToriiState<W> {
        let wsv = Arc::clone(&self.wsv);
        let queue = Arc::clone(&self.queue);
        let iroha_cfg = self.iroha_cfg.clone();
        let query_validator = Arc::clone(&self.query_validator);
        let network = self.network.clone();

        Arc::new(InnerToriiState {
            iroha_cfg,
            wsv,
            queue,
            query_validator,
            network,
        })
    }

    /// Fixing status code for custom rejection, because of argument parsing
    #[allow(clippy::unused_async)]
    async fn recover_arg_parse(rejection: Rejection) -> Result<impl Reply, Rejection> {
        if let Some(err) = rejection.find::<query::Error>() {
            return Ok(reply::with_status(err.to_string(), err.status_code()));
        }
        if let Some(err) = rejection.find::<iroha_version::error::Error>() {
            return Ok(reply::with_status(err.to_string(), err.status_code()));
        }
        Err(rejection)
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
                    .and(add_state(Arc::clone(&state)))
                    .and(warp::body::json()),
            ));

        let post_router = endpoint2(
            handle_instructions,
            warp::path(uri::TRANSACTION)
                .and(add_state(Arc::clone(&state)))
                .and(warp::body::content_length_limit(
                    state.iroha_cfg.torii.max_content_len as u64,
                ))
                .and(body::versioned()),
        )
        .or(endpoint3(
            handle_queries,
            warp::path(uri::QUERY)
                .and(add_state(Arc::clone(&state)))
                .and(paginate())
                .and(body::query()),
        ))
        .or(endpoint2(
            handle_post_configuration,
            warp::path(uri::CONFIGURATION)
                .and(add_state(Arc::clone(&state)))
                .and(warp::body::json()),
        ));

        let ws_router = warp::path(uri::SUBSCRIPTION)
            .and(add_state(self.events))
            .and(warp::ws())
            .map(|events, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) = handle_subscription(events, this_ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe someone");
                    }
                })
            });

        let router = warp::post()
            .and(post_router)
            .or(warp::get().and(get_router))
            .or(ws_router)
            .with(warp::trace::request())
            .recover(Torii::<W>::recover_arg_parse);

        tokio::spawn(async move {
            start_status(Arc::clone(&state))
                .await
                .wrap_err("Failed to start status service")
                .unwrap_or_else(|error| {
                    iroha_logger::error!(%error);
                })
        });

        match self.iroha_cfg.torii.api_url.to_socket_addrs() {
            Ok(mut i) => {
                #[allow(clippy::expect_used)]
                let addr = i.next().expect("ToSocketAddrs iteration failed");
                warp::serve(router).run(addr).await;
                Ok(())
            }
            Err(error) => {
                iroha_logger::error!(%self.iroha_cfg.torii.api_url, %error, "API address configuration parse error");
                Err(eyre::Error::new(error))
            }
        }
    }
}

/// Start status endpoint.
///
/// # Errors
/// Can fail due to listening to network or if http server fails
async fn start_status<W: WorldTrait>(state: ToriiState<W>) -> eyre::Result<()> {
    let get_router_status = endpoint1(
        handle_status,
        warp::path(uri::STATUS).and(add_state(Arc::clone(&state))),
    );
    let get_router_metrics = endpoint1(
        handle_metrics,
        warp::path(uri::METRICS).and(add_state(Arc::clone(&state))),
    );
    let router = warp::get().and(get_router_status).or(get_router_metrics);

    match state.iroha_cfg.torii.status_url.to_socket_addrs() {
        Ok(mut i) => {
            #[allow(clippy::expect_used)]
            let addr = i.next().expect("ToSocketAddrs iteration failed");
            warp::serve(router).run(addr).await;
            Ok(())
        }
        Err(e) => {
            iroha_logger::error!("Status address configuration parse error");
            Err(eyre::Error::new(e))
        }
    }
}

struct InnerToriiState<W: WorldTrait> {
    iroha_cfg: Configuration,
    wsv: Arc<WorldStateView<W>>,
    queue: Arc<Queue>,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
    network: Addr<IrohaNetwork>,
}

type ToriiState<W> = Arc<InnerToriiState<W>>;

#[iroha_futures::telemetry_future]
async fn handle_instructions<W: WorldTrait>(
    state: ToriiState<W>,
    transaction: VersionedTransaction,
) -> Result<Empty> {
    let transaction: Transaction = transaction.into_v1();
    let transaction = VersionedAcceptedTransaction::from_transaction(
        transaction,
        state.iroha_cfg.torii.max_instruction_number,
    )
    .map_err(Error::AcceptTransaction)?;
    #[allow(clippy::map_err_ignore)]
    let push_result = state
        .queue
        .push(transaction, &*state.wsv)
        .map_err(|(_, err)| err);
    if let Err(ref error) = push_result {
        iroha_logger::warn!(%error, "Failed to push to queue")
    }
    push_result
        .map_err(Box::new)
        .map_err(Error::PushIntoQueue)
        .map(|()| Empty)
}

#[iroha_futures::telemetry_future]
async fn handle_queries<W: WorldTrait>(
    state: ToriiState<W>,
    pagination: Pagination,
    request: VerifiedQueryRequest,
) -> Result<Scale<VersionedQueryResult>, query::Error> {
    let valid_request = request.validate(&*state.wsv, &state.query_validator)?;
    let result = valid_request
        .execute(&*state.wsv)
        .map_err(query::Error::Find)?;
    let result = QueryResult(if let Value::Vec(value) = result {
        Value::Vec(value.into_iter().paginate(pagination).collect())
    } else {
        result
    });
    Ok(Scale(result.into()))
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
    Ok(Scale(
        state
            .queue
            .all_transactions(&*state.wsv)
            .into_iter()
            .map(VersionedAcceptedTransaction::into_v1)
            .map(Transaction::from)
            .paginate(pagination)
            .collect(),
    ))
}

#[iroha_futures::telemetry_future]
async fn handle_get_configuration<W: WorldTrait>(
    state: ToriiState<W>,
    get_cfg: GetConfiguration,
) -> Result<Json> {
    use GetConfiguration::*;

    match get_cfg {
        Docs(field) => {
            Configuration::get_doc_recursive(field.iter().map(AsRef::as_ref).collect::<Vec<&str>>())
                .wrap_err("Failed to get docs {:?field}")
                .and_then(|doc| {
                    Context::wrap_err(serde_json::to_value(doc), "Failed to serialize docs")
                })
        }
        Value => {
            serde_json::to_value(state.iroha_cfg.clone()).wrap_err("Failed to serialize value")
        }
    }
    .map(|v| reply::json(&v))
    .map_err(Error::Config)
}

#[iroha_futures::telemetry_future]
async fn handle_post_configuration<W: WorldTrait>(
    state: ToriiState<W>,
    cfg: PostConfiguration,
) -> Result<Json> {
    use iroha_config::runtime_upgrades::Reload;
    use PostConfiguration::*;

    iroha_logger::debug!(?cfg);
    match cfg {
        // TODO: Now the configuration value and the actual value don't match.
        LogLevel(level) => {
            state.iroha_cfg.logger.max_log_level.reload(level.into())?;
        }
    };

    Ok(reply::json(&true))
}

#[iroha_futures::telemetry_future]
async fn handle_subscription(events: EventsSender, stream: WebSocket) -> eyre::Result<()> {
    let mut events = events.subscribe();
    let mut consumer = Consumer::new(stream).await?;

    while let Ok(change) = events.recv().await {
        iroha_logger::trace!(event = ?change);

        if let Err(error) = consumer.consume(&change).await {
            iroha_logger::error!(%error, "Failed to notify client. Closed connection.");
            break;
        }
    }

    Ok(())
}

async fn handle_metrics<W: WorldTrait>(state: ToriiState<W>) -> Result<String> {
    update_metrics(&state).await?;
    state.wsv.metrics.try_to_string().map_err(Error::Prometheus)
}

async fn update_metrics<W: WorldTrait>(state: &Arc<InnerToriiState<W>>) -> Result<()> {
    let peers = state
        .network
        .send(iroha_p2p::network::GetConnectedPeers)
        .await
        .map_err(Error::Status)?
        .peers
        .len() as u64;
    #[allow(clippy::cast_possible_truncation)]
    if let Some(timestamp) = state.wsv.genesis_timestamp() {
        // this will overflow in 584942417years.
        state
            .wsv
            .metrics
            .uptime_since_genesis_ms
            .set((current_time().as_millis() - timestamp) as u64)
    }
    state.wsv.metrics.connected_peers.set(peers);
    Ok(())
}

async fn handle_status<W: WorldTrait>(state: ToriiState<W>) -> Result<Json> {
    update_metrics(&state).await?;
    let status = Status::from(&state.wsv.metrics);
    Ok(reply::json(&status))
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_data_model::uri::DEFAULT_API_URL;
    use serde::{Deserialize, Serialize};

    /// Default socket for p2p communication
    pub const DEFAULT_TORII_P2P_ADDR: &str = "127.0.0.1:1337";
    /// Default socket for reporting internal status
    pub const DEFAULT_TORII_STATUS_URL: &str = "127.0.0.1:8180";
    /// Default maximum size of single transaction
    pub const DEFAULT_TORII_MAX_TRANSACTION_SIZE: usize = 2_usize.pow(15);
    /// Default maximum instruction number
    pub const DEFAULT_TORII_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
    /// Default upper bound on `content-length` specified in the HTTP request header
    pub const DEFAULT_TORII_MAX_CONTENT_LENGTH: usize = 2_usize.pow(12) * 4000;

    /// `ToriiConfiguration` provides an ability to define parameters such as `TORII_URL`.
    #[derive(Clone, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    #[config(env_prefix = "TORII_")]
    pub struct ToriiConfiguration {
        /// Torii URL for p2p communication for consensus and block synchronization purposes.
        pub p2p_addr: String,
        /// Torii URL for client API.
        pub api_url: String,
        /// Torii URL for reporting internal status for administration.
        pub status_url: String,
        /// Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.
        pub max_transaction_size: usize,
        /// Maximum number of bytes in raw message. Used to prevent from DOS attacks.
        pub max_content_len: usize,
        /// Maximum number of instruction per transaction. Used to prevent from DOS attacks.
        pub max_instruction_number: u64,
    }

    impl Default for ToriiConfiguration {
        fn default() -> Self {
            Self {
                p2p_addr: DEFAULT_TORII_P2P_ADDR.to_owned(),
                api_url: DEFAULT_API_URL.to_owned(),
                status_url: DEFAULT_TORII_STATUS_URL.to_owned(),
                max_transaction_size: DEFAULT_TORII_MAX_TRANSACTION_SIZE,
                max_content_len: DEFAULT_TORII_MAX_CONTENT_LENGTH,
                max_instruction_number: DEFAULT_TORII_MAX_INSTRUCTION_NUMBER,
            }
        }
    }
}

#[cfg(test)]
mod tests;
