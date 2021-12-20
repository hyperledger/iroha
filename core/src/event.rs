//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

use eyre::{eyre, Result};
use iroha_data_model::events::prelude::*;
use tokio::sync::broadcast;
use warp::ws::WebSocket;

use crate::stream::{Sink, Stream};

/// Type of `Sender<Event>` which should be used for channels of `Event` messages.
pub type EventsSender = broadcast::Sender<Event>;
/// Type of `Receiver<Event>` which should be used for channels of `Event` messages.
pub type EventsReceiver = broadcast::Receiver<Event>;

/// Consumer for Iroha `Event`(s).
/// Passes the events over the corresponding connection `stream` if they match the `filter`.
#[derive(Debug)]
pub struct Consumer {
    stream: WebSocket,
    filter: EventFilter,
}

impl Consumer {
    /// Constructs `Consumer`, which consumes `Event`s and forwards it through the `stream`.
    ///
    /// # Errors
    /// Can fail due to timeout or without message at websocket or during decoding request
    #[iroha_futures::telemetry_future]
    pub async fn new(mut stream: WebSocket) -> Result<Self> {
        let subscription_request: VersionedEventSubscriberMessage = stream.recv().await?;
        let filter = subscription_request.into_v1().try_into()?;

        stream
            .send(VersionedEventPublisherMessage::from(
                EventPublisherMessage::SubscriptionAccepted,
            ))
            .await?;

        Ok(Consumer { stream, filter })
    }

    /// Forwards the `event` over the `stream` if it matches the `filter`.
    ///
    /// # Errors
    /// Can fail due to timeout or sending event. Also receiving might fail
    #[iroha_futures::telemetry_future]
    pub async fn consume(&mut self, event: Event) -> Result<()> {
        if !self.filter.apply(&event) {
            return Ok(());
        }

        self.stream
            .send(VersionedEventPublisherMessage::from(
                EventPublisherMessage::from(event),
            ))
            .await?;

        let message: VersionedEventSubscriberMessage = self.stream.recv().await?;
        if let EventSubscriberMessage::EventReceived = message.into_v1() {
            Ok(())
        } else {
            Err(eyre!("Expected `EventReceived`."))
        }
    }
}
