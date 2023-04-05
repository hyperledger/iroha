//! Translates to gateway. Request handling logic of Iroha.  `Torii`
//! is used to receive, accept and route incoming instructions,
//! queries and messages.

use std::{
    convert::Infallible,
    fmt::{Debug, Write as _},
    net::ToSocketAddrs,
    sync::Arc,
};

use futures::{stream::FuturesUnordered, StreamExt};
use iroha_core::{
    kura::Kura,
    prelude::*,
    queue::{self, Queue},
    sumeragi::Sumeragi,
    EventsSender,
};
use thiserror::Error;
use tokio::sync::Notify;
use utils::*;
use warp::{
    http::StatusCode,
    reply::{self, Json, Response},
    ws::{WebSocket, Ws},
    Filter as _, Reply,
};

#[macro_use]
pub(crate) mod utils;
mod pagination;
pub mod routing;

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii {
    iroha_cfg: super::Configuration,
    queue: Arc<Queue>,
    events: EventsSender,
    notify_shutdown: Arc<Notify>,
    sumeragi: Arc<Sumeragi>,
    kura: Arc<Kura>,
}

/// Torii errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to execute or validate query
    #[error("Failed to execute or validate query")]
    Query(#[from] iroha_data_model::query::error::QueryExecutionFailure),
    /// Failed to accept transaction
    #[error("Failed to accept transaction: {0}")]
    AcceptTransaction(#[from] iroha_genesis::AcceptTransactionFailure),
    /// Error while getting or setting configuration
    #[error("Configuration error: {0}")]
    Config(#[source] eyre::Report),
    /// Failed to push into queue
    #[error("Failed to push into queue")]
    PushIntoQueue(#[from] Box<queue::Error>),
    /// Configuration change error.
    #[error("Attempt to change configuration failed")]
    ConfigurationReload(#[from] iroha_config::base::runtime_upgrades::ReloadError),
    #[cfg(feature = "telemetry")]
    /// Error while getting Prometheus metrics
    #[error("Failed to produce Prometheus metrics: {0}")]
    Prometheus(#[source] eyre::Report),
}

/// Status code for query error response.
pub(crate) const fn query_status_code(
    query_error: &iroha_data_model::query::error::QueryExecutionFailure,
) -> StatusCode {
    use iroha_data_model::query::error::QueryExecutionFailure::*;

    match query_error {
        Evaluate(_) | Conversion(_) => StatusCode::BAD_REQUEST,
        Signature(_) | Unauthorized => StatusCode::UNAUTHORIZED,
        Permission(_) => StatusCode::FORBIDDEN,
        Find(_) => StatusCode::NOT_FOUND,
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
    const fn status_code(&self) -> StatusCode {
        use Error::*;
        match self {
            Query(e) => query_status_code(e),
            AcceptTransaction(_) | ConfigurationReload(_) => StatusCode::BAD_REQUEST,
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
