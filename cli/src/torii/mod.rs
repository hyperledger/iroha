//! Translates to gateway. Request handling logic of Iroha.  `Torii`
//! is used to receive, accept and route incoming instructions,
//! queries and messages.

use std::{
    convert::Infallible,
    fmt::{Debug, Write as _},
    net::ToSocketAddrs,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use futures::{stream::FuturesUnordered, StreamExt};
use iroha_core::{
    kura::Kura,
    prelude::*,
    queue::{self, Queue},
    sumeragi::SumeragiHandle,
    EventsSender,
};
use iroha_data_model::Value;
use parity_scale_codec::Encode;
use tokio::{sync::Notify, time::sleep};
use utils::*;
use warp::{
    http::StatusCode,
    reply::{self, Json, Response},
    ws::{WebSocket, Ws},
    Filter as _, Reply,
};

use self::cursor::Batched;

#[macro_use]
pub(crate) mod utils;
mod cursor;
mod pagination;
mod routing;

type LiveQuery = Batched<Vec<Value>>;

#[derive(Default)]
struct LiveQueryStore {
    queries: DashMap<(String, Vec<u8>), (LiveQuery, Instant)>,
}

impl LiveQueryStore {
    fn insert<T: Encode>(&self, query_id: String, request: T, live_query: LiveQuery) {
        self.queries
            .insert((query_id, request.encode()), (live_query, Instant::now()));
    }

    fn remove<T: Encode>(&self, query_id: &str, request: &T) -> Option<LiveQuery> {
        self.queries
            .remove(&(query_id.to_string(), request.encode()))
            .map(|(_, (output, _))| output)
    }

    fn expired_query_cleanup(
        self: Arc<Self>,
        idle_time: Duration,
        notify_shutdown: Arc<Notify>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    _ = sleep(idle_time) => {
                        self.queries
                            .retain(|_, (_, last_access_time)| last_access_time.elapsed() <= idle_time);
                    },
                    _ = notify_shutdown.notified() => {
                        iroha_logger::info!("Query cleanup service is being shut down.");
                        break;
                    }
                    else => break,
                }
            }
        })
    }
}

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii {
    iroha_cfg: super::Configuration,
    queue: Arc<Queue>,
    events: EventsSender,
    notify_shutdown: Arc<Notify>,
    sumeragi: SumeragiHandle,
    query_store: Arc<LiveQueryStore>,
    kura: Arc<Kura>,
}

/// Torii errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Failed to execute or validate query
    Query(#[from] iroha_data_model::ValidationFail),
    /// Failed to accept transaction
    AcceptTransaction(#[from] iroha_core::tx::AcceptTransactionFail),
    /// Error while getting or setting configuration
    Config(#[source] eyre::Report),
    /// Failed to push into queue
    PushIntoQueue(#[from] Box<queue::Error>),
    /// Attempt to change configuration failed
    ConfigurationReload(#[from] iroha_config::base::runtime_upgrades::ReloadError),
    #[cfg(feature = "telemetry")]
    /// Error while getting Prometheus metrics
    Prometheus(#[source] eyre::Report),
    /// Error while resuming cursor
    UnknownCursor,
}

/// Status code for query error response.
fn query_status_code(validation_error: &iroha_data_model::ValidationFail) -> StatusCode {
    use iroha_data_model::{
        isi::error::InstructionExecutionError, query::error::QueryExecutionFail::*,
        ValidationFail::*,
    };

    match validation_error {
        NotPermitted(_) => StatusCode::FORBIDDEN,
        QueryFailed(query_error)
        | InstructionFailed(InstructionExecutionError::Query(query_error)) => match query_error {
            Evaluate(_) | Conversion(_) => StatusCode::BAD_REQUEST,
            Signature(_) => StatusCode::UNAUTHORIZED,
            Find(_) => StatusCode::NOT_FOUND,
        },
        TooComplex => StatusCode::UNPROCESSABLE_ENTITY,
        InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        InstructionFailed(error) => {
            iroha_logger::error!(
                ?error,
                "Query validation failed with unexpected error. This means a bug inside Runtime Executor",
            );
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

impl Reply for Error {
    fn into_response(self) -> Response {
        use Error::*;
        match self {
            Query(err) => {
                reply::with_status(utils::Scale(&err), query_status_code(&err)).into_response()
            }
            _ => reply::with_status(Self::to_string(&self), self.status_code()).into_response(),
        }
    }
}

impl Error {
    fn status_code(&self) -> StatusCode {
        use Error::*;
        match self {
            Query(e) => query_status_code(e),
            AcceptTransaction(_) | ConfigurationReload(_) | UnknownCursor => {
                StatusCode::BAD_REQUEST
            }
            Config(_) => StatusCode::NOT_FOUND,
            PushIntoQueue(err) => match **err {
                queue::Error::Full => StatusCode::INTERNAL_SERVER_ERROR,
                queue::Error::SignatureCondition { .. } => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            },
            #[cfg(feature = "telemetry")]
            Prometheus(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn to_string(err: &dyn std::error::Error) -> String {
        let mut s = "Error:\n".to_owned();
        let mut idx = 0_i32;
        let mut err_opt = Some(err);
        while let Some(e) = err_opt {
            write!(s, "    {idx}: {}", &e.to_string()).expect("Valid");
            idx += 1_i32;
            err_opt = e.source()
        }
        s
    }
}

/// Result type
pub type Result<T, E = Error> = std::result::Result<T, E>;
