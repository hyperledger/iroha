//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

use std::{fmt::Debug, time::Duration};

use eyre::{eyre, Result, WrapErr};
use futures::{SinkExt, StreamExt};
use iroha_data_model::events::{prelude::*, SubscriptionRequest};
use iroha_version::prelude::*;
use tokio::{sync::broadcast, time};
use warp::ws::{self, WebSocket};

/// Type of `Sender<Event>` which should be used for channels of `Event` messages.
pub type EventsSender = broadcast::Sender<Event>;
/// Type of `Receiver<Event>` which should be used for channels of `Event` messages.
pub type EventsReceiver = broadcast::Receiver<Event>;

#[cfg(test)]
const TIMEOUT: Duration = Duration::from_millis(10_000);
#[cfg(not(test))]
const TIMEOUT: Duration = Duration::from_millis(1000);

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
        let message = time::timeout(TIMEOUT, stream.next())
            .await
            .wrap_err("Read message timeout")?
            .ok_or_else(|| eyre!("Failed to read message: no message"))?
            .wrap_err("Web Socket failure")?;

        if !message.is_binary() {
            return Err(eyre!("Unexpected message type"));
        }
        let SubscriptionRequest(filter): SubscriptionRequest =
            VersionedEventSocketMessage::decode_versioned(message.as_bytes())?
                .into_v1()
                .try_into()?;

        time::timeout(
            TIMEOUT,
            stream.send(ws::Message::binary(
                VersionedEventSocketMessage::from(EventSocketMessage::SubscriptionAccepted)
                    .encode_versioned()?,
            )),
        )
        .await
        .wrap_err("Send message timeout")?
        .wrap_err("Failed to send message")?;

        Ok(Consumer { stream, filter })
    }

    /// Forwards the `event` over the `stream` if it matches the `filter`.
    ///
    /// # Errors
    /// Can fail due to timeout or sending event. Also receiving might fail
    #[iroha_futures::telemetry_future]
    pub async fn consume(&mut self, event: &Event) -> Result<()> {
        if !self.filter.apply(event) {
            return Ok(());
        }

        let event = VersionedEventSocketMessage::from(EventSocketMessage::from(event.clone()))
            .encode_versioned()
            .wrap_err("Failed to serialize event")?;
        time::timeout(TIMEOUT, self.stream.send(ws::Message::binary(event)))
            .await
            .wrap_err("Send message timeout")?
            .wrap_err("Failed to send message")?;

        let message = time::timeout(TIMEOUT, self.stream.next())
            .await
            .wrap_err("Failed to read receipt")?
            .ok_or_else(|| eyre!("Failed to read receipt: no receipt"))?
            .wrap_err("Web Socket failure")?;

        if !message.is_binary() {
            return Err(eyre!("Unexpected message type"));
        }

        if let EventSocketMessage::EventReceived =
            VersionedEventSocketMessage::decode_versioned(message.as_bytes())?.into_v1()
        {
            self.stream.flush().await?;
            Ok(())
        } else {
            Err(eyre!("Expected `EventReceived`."))
        }
    }
}
