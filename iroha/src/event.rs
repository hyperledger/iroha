//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

use async_std::{
    future,
    sync::{Receiver, Sender},
};
use futures::{SinkExt, StreamExt};
use iroha_data_model::events::{prelude::*, SubscriptionRequest};
use iroha_error::{error, Result, WrapErr};
use iroha_http_server::web_socket::{WebSocketMessage, WebSocketStream};
use iroha_version::prelude::*;
use std::{fmt::Debug, time::Duration};

/// Type of `Sender<Event>` which should be used for channels of `Event` messages.
pub type EventsSender = Sender<Event>;
/// Type of `Receiver<Event>` which should be used for channels of `Event` messages.
pub type EventsReceiver = Receiver<Event>;

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
    pub async fn new(mut stream: WebSocketStream) -> Result<Self> {
        if let WebSocketMessage::Text(message) = future::timeout(TIMEOUT, stream.next())
            .await
            .wrap_err("Read message timeout")?
            .ok_or_else(|| error!("Failed to read message: no message"))?
            .wrap_err("Web Socket failure")?
        {
            let request: SubscriptionRequest =
                VersionedSubscriptionRequest::from_versioned_json_str(&message)?
                    .into_v1()
                    .ok_or_else(|| error!("Expected subscription request version 1."))?
                    .into();
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
    pub async fn consume(mut self, event: &Event) -> Result<Self> {
        if self.filter.apply(event) {
            let event = VersionedEvent::from(event.clone())
                .to_versioned_json_str()
                .wrap_err("Failed to serialize event")?;
            future::timeout(TIMEOUT, self.stream.send(WebSocketMessage::Text(event)))
                .await
                .wrap_err("Read message timeout")?
                .wrap_err("Failed to write message")?;
            if let WebSocketMessage::Text(receipt) = future::timeout(TIMEOUT, self.stream.next())
                .await
                .wrap_err("Failed to read receipt")?
                .ok_or_else(|| error!("Failed to read receipt: no receipt"))?
                .wrap_err("Web Socket failure")?
            {
                let _receipt = VersionedEventReceived::from_versioned_json_str(&receipt)
                    .wrap_err_with(|| {
                        format!("Unexpected message, waited for receipt got: {}", receipt)
                    })?;
            } else {
                return Err(error!("Unexpected message type"));
            }
        }
        Ok(self)
    }
}
