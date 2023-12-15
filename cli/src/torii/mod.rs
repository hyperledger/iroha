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
use iroha_config::torii::Configuration as ToriiConfiguration;
use iroha_core::{
    kiso::{Error as KisoError, KisoHandle},
    kura::Kura,
    prelude::*,
    query::store::LiveQueryStoreHandle,
    queue::{self, Queue},
    sumeragi::SumeragiHandle,
    EventsSender,
};
use iroha_primitives::addr::SocketAddr;
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
mod routing;

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii {
    kiso: KisoHandle,
    queue: Arc<Queue>,
    events: EventsSender,
    notify_shutdown: Arc<Notify>,
    sumeragi: SumeragiHandle,
    query_service: LiveQueryStoreHandle,
    kura: Arc<Kura>,
    transaction_max_content_length: u64,
    address: SocketAddr,
}

/// Torii errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Failed to process query
    Query(#[from] iroha_data_model::ValidationFail),
    /// Failed to accept transaction
    AcceptTransaction(#[from] iroha_core::tx::AcceptTransactionFail),
    /// Error while getting or setting configuration
    Config(#[source] eyre::Report),
    /// Failed to push into queue
    PushIntoQueue(#[from] Box<queue::Error>),
    #[cfg(feature = "telemetry")]
    /// Error while getting Prometheus metrics
    Prometheus(#[source] eyre::Report),
    /// Internal error while getting status
    StatusFailure(#[source] eyre::Report),
    /// Failure caused by configuration subsystem
    ConfigurationFailure(#[from] KisoError),
    /// Cannot find status segment by provided path
    StatusSegmentNotFound(#[source] eyre::Report),
}

impl Reply for Error {
    fn into_response(self) -> Response {
        match self {
            Self::Query(err) => {
                reply::with_status(utils::Scale(&err), Self::query_status_code(&err))
                    .into_response()
            }
            _ => reply::with_status(Self::to_string(&self), self.status_code()).into_response(),
        }
    }
}

impl Error {
    fn status_code(&self) -> StatusCode {
        use Error::*;

        match self {
            Query(e) => Self::query_status_code(e),
            AcceptTransaction(_) => StatusCode::BAD_REQUEST,
            Config(_) | StatusSegmentNotFound(_) => StatusCode::NOT_FOUND,
            PushIntoQueue(err) => match **err {
                queue::Error::Full => StatusCode::INTERNAL_SERVER_ERROR,
                queue::Error::SignatureCondition { .. } => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            },
            #[cfg(feature = "telemetry")]
            Prometheus(_) | StatusFailure(_) | ConfigurationFailure(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn query_status_code(validation_error: &iroha_data_model::ValidationFail) -> StatusCode {
        use iroha_data_model::{
            isi::error::InstructionExecutionError, query::error::QueryExecutionFail::*,
            ValidationFail::*,
        };

        match validation_error {
            NotPermitted(_) => StatusCode::FORBIDDEN,
            QueryFailed(query_error)
            | InstructionFailed(InstructionExecutionError::Query(query_error)) => match query_error
            {
                Conversion(_) | UnknownCursor | FetchSizeTooBig => StatusCode::BAD_REQUEST,
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
