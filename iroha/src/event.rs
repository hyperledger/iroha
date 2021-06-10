//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

use std::{convert::TryInto, fmt::Debug, time::Duration};

use futures::{SinkExt, StreamExt};
use iroha_data_model::events::{prelude::*, SubscriptionRequest};
use iroha_error::{error, Result, WrapErr};
use iroha_http_server::web_socket::{WebSocketMessage, WebSocketStream};
use iroha_version::prelude::*;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time,
};

/// Type of `Sender<Event>` which should be used for channels of `Event` messages.
pub type EventsSender = Sender<Event>;
/// Type of `Receiver<Event>` which should be used for channels of `Event` messages.
pub type EventsReceiver = Receiver<Event>;

#[cfg(test)]
const TIMEOUT: Duration = Duration::from_millis(10_000);
#[cfg(not(test))]
const TIMEOUT: Duration = Duration::from_millis(1000);

/// Consumer for Iroha `Event`(s).
/// Passes the events over the corresponding connection `stream` if they match the `filter`.
#[derive(Debug)]
pub struct Consumer {
    stream: WebSocketStream,
    filter: EventFilter,
}

impl Consumer {
    /// Constructs `Consumer`, which consumes `Event`s and forwards it through the `stream`.
    ///
    /// # Errors
    /// Can fail due to timeout or without message at websocket or during decoding request
    #[iroha_futures::telemetry_future]
    pub async fn new(mut stream: WebSocketStream) -> Result<Self> {
        if let WebSocketMessage::Text(message) = time::timeout(TIMEOUT, stream.next())
            .await
            .wrap_err("Read message timeout")?
            .ok_or_else(|| error!("Failed to read message: no message"))?
            .wrap_err("Web Socket failure")?
        {
            let request: SubscriptionRequest =
                VersionedEventSocketMessage::from_versioned_json_str(&message)?
                    .into_inner_v1()
                    .try_into()?;
            time::timeout(
                TIMEOUT,
                stream.send(WebSocketMessage::Text(
                    VersionedEventSocketMessage::from(EventSocketMessage::SubscriptionAccepted)
                        .to_versioned_json_str()?,
                )),
            )
            .await
            .wrap_err("Send message timeout")?
            .wrap_err("Failed to send message")?;
            let SubscriptionRequest(filter) = request;
            Ok(Consumer { stream, filter })
        } else {
            Err(error!("Unexepcted message type"))
        }
    }

    /// Forwards the `event` over the `stream` if it matches the `filter`.
    ///
    /// # Errors
    /// Can fail due to timeout or sending event. Also receiving might fail
    #[iroha_futures::telemetry_future]
    pub async fn consume(mut self, event: &Event) -> Result<Self> {
        if self.filter.apply(event) {
            let event = VersionedEventSocketMessage::from(EventSocketMessage::from(event.clone()))
                .to_versioned_json_str()
                .wrap_err("Failed to serialize event")?;
            time::timeout(TIMEOUT, self.stream.send(WebSocketMessage::Text(event)))
                .await
                .wrap_err("Send message timeout")?
                .wrap_err("Failed to send message")?;
            if let WebSocketMessage::Text(receipt) = time::timeout(TIMEOUT, self.stream.next())
                .await
                .wrap_err("Failed to read receipt")?
                .ok_or_else(|| error!("Failed to read receipt: no receipt"))?
                .wrap_err("Web Socket failure")?
            {
                if let EventSocketMessage::EventReceived =
                    VersionedEventSocketMessage::from_versioned_json_str(&receipt)?.into_inner_v1()
                {
                } else {
                    return Err(error!("Expected `EventReceived` got {}", receipt));
                }
            } else {
                return Err(error!("Unexpected message type"));
            }
        }
        Ok(self)
    }
}
