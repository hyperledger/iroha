//! This module contains incoming requests handling logic of Iroha.
//! `Torii` is used to receive, accept and route incoming instructions, queries and messages.

use std::{convert::Infallible, fmt::Debug, net::ToSocketAddrs, sync::Arc};

use eyre::{eyre, Context};
use futures::{stream::FuturesUnordered, StreamExt};
use iroha_config::{Configurable, GetConfiguration, PostConfiguration};
use iroha_data_model::prelude::*;
use iroha_telemetry::metrics::Status;
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

use crate::{
    block::stream::{
        BlockPublisherMessage, BlockSubscriberMessage, VersionedBlockPublisherMessage,
        VersionedBlockSubscriberMessage,
    },
    event::{Consumer, EventsSender},
    prelude::*,
    queue::{self, Queue},
    smartcontracts::{
        isi::query::{self, VerifiedQueryRequest},
        permissions::IsQueryAllowedBoxed,
    },
    stream::{Sink, Stream},
    wsv::WorldTrait,
    Addr, Configuration, IrohaNetwork,
};

#[macro_use]
pub(crate) mod utils;
pub mod config;
pub mod routing;

/// Main network handler and the only entrypoint of the Iroha.
pub struct Torii<W: WorldTrait> {
    iroha_cfg: Configuration,
    wsv: Arc<WorldStateView<W>>,
    queue: Arc<Queue<W>>,
    events: EventsSender,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
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

#[cfg(test)]
mod tests;
