//! Translates to gateway. Request handling logic of Iroha.  `Torii`
//! is used to receive, accept and route incoming instructions,
//! queries and messages.

use std::{
    convert::Infallible,
    fmt::{Debug, Write as _},
    net::ToSocketAddrs,
    sync::Arc,
};

use eyre::eyre;
use futures::{stream::FuturesUnordered, StreamExt};
use iroha_core::{
    prelude::*,
    queue::{self, Queue},
    sumeragi::Sumeragi,
    EventsSender, IrohaNetwork,
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
pub mod routing;

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii {
    iroha_cfg: super::Configuration,
    queue: Arc<Queue>,
    events: EventsSender,
    query_judge: QueryJudgeArc,
    network: iroha_actor::Addr<IrohaNetwork>,
    notify_shutdown: Arc<Notify>,
    sumeragi: Arc<Sumeragi>,
}

/// Torii errors.
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to execute or validate query
    #[error("Failed to execute or validate query")]
    Query(#[from] iroha_core::smartcontracts::query::Error),
    /// Failed to decode transaction
    #[error("Failed to decode transaction")]
    VersionedSignedTransaction(#[source] iroha_version::error::Error),
    /// Failed to accept transaction
    #[error("Failed to accept transaction: {0}")]
    AcceptTransaction(eyre::Report),
    /// Failed to get pending transaction
    #[error("Failed to get pending transactions: {0}")]
    RequestPendingTransactions(eyre::Report),
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
    Config(eyre::Report),
    /// Failed to push into queue
    #[error("Failed to push into queue")]
    PushIntoQueue(#[from] Box<queue::Error>),
    #[cfg(feature = "telemetry")]
    /// Error while getting status
    #[error("Failed to get status")]
    Status(#[from] iroha_actor::Error),
    /// Configuration change error.
    #[error("Attempt to change configuration failed")]
    ConfigurationReload(#[from] iroha_config::base::runtime_upgrades::ReloadError),
    #[cfg(feature = "telemetry")]
    /// Error while getting Prometheus metrics
    #[error("Failed to produce Prometheus metrics: {0}")]
    Prometheus(eyre::Report),
}

/// Status code for query error response.
pub(crate) const fn query_status_code(
    query_error: &iroha_core::smartcontracts::query::Error,
) -> StatusCode {
    use iroha_core::smartcontracts::query::Error::*;
    match query_error {
        Decode(_) | Evaluate(_) | Conversion(_) => StatusCode::BAD_REQUEST,
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
            // TODO Have a type-preserved response body instead of a stringified one #2279
            VersionedSignedTransaction(err)
            | DecodeRequestPendingTransactions(err)
            | EncodePendingTransactions(err) => {
                reply::with_status(err.to_string(), err.status_code()).into_response()
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
            VersionedSignedTransaction(err)
            | DecodeRequestPendingTransactions(err)
            | EncodePendingTransactions(err) => err.status_code(),
            AcceptTransaction(_)
            | RequestPendingTransactions(_)
            | ConfigurationReload(_)
            | TxTooBig => StatusCode::BAD_REQUEST,
            Config(_) => StatusCode::NOT_FOUND,
            PushIntoQueue(err) => match **err {
                queue::Error::Full => StatusCode::INTERNAL_SERVER_ERROR,
                queue::Error::SignatureCondition { .. } => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            },
            #[cfg(feature = "telemetry")]
            Prometheus(_) | Status(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
