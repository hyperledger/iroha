//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utility Iroha Special Instructions to work with them.

use iroha_data_model::events::prelude::*;

use crate::stream::{self, WebSocketScale};

/// Type of error for `Consumer`
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error from provided stream/websocket
    #[error("Stream error: {0}")]
    Stream(Box<stream::Error>),
}

impl From<stream::Error> for Error {
    fn from(error: stream::Error) -> Self {
        Self::Stream(Box::new(error))
    }
}

/// Result type for `Consumer`
pub type Result<T> = core::result::Result<T, Error>;

/// Consumer for Iroha `Event`(s).
/// Passes the events over the corresponding connection `stream` if they match the `filter`.
#[derive(Debug)]
pub struct Consumer<'ws> {
    pub stream: &'ws mut WebSocketScale,
    filters: Vec<EventFilterBox>,
}

impl<'ws> Consumer<'ws> {
    /// Constructs [`Consumer`], which consumes `Event`s and forwards it through the `stream`.
    ///
    /// # Errors
    /// Can fail due to timeout or without message at websocket or during decoding request
    #[iroha_futures::telemetry_future]
    pub async fn new(stream: &'ws mut WebSocketScale) -> Result<Self> {
        let EventSubscriptionRequest(filters) = stream.recv::<EventSubscriptionRequest>().await?;
        Ok(Consumer { stream, filters })
    }

    /// Forwards the `event` over the `stream` if it matches the `filter`.
    ///
    /// # Errors
    /// Can fail due to timeout or sending event. Also receiving might fail
    #[iroha_futures::telemetry_future]
    pub async fn consume(&mut self, event: EventBox) -> Result<()> {
        if !self.filters.iter().any(|filter| filter.matches(&event)) {
            return Ok(());
        }

        self.stream
            .send(EventMessage(event))
            .await
            .map_err(Into::into)
    }
}
