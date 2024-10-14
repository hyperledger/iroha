//! Adds support for sending/receiving custom Iroha messages over the WebSocket

use core::{result::Result, time::Duration};

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use iroha_version::prelude::*;
use parity_scale_codec::DecodeAll;

#[cfg(test)]
const TIMEOUT: Duration = Duration::from_millis(10_000);
#[cfg(not(test))]
const TIMEOUT: Duration = Duration::from_millis(1000);

/// Error type with generic for actual Stream/Sink error type
#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[ignore_extra_doc_attributes]
pub enum Error {
    /// Read message timeout
    ReadTimeout,
    /// Send message timeout
    SendTimeout,
    /// WebSocket error: {_0}
    WebSocket(#[source] axum::Error),
    /// Error during versioned message decoding
    Decode(#[from] parity_scale_codec::Error),
    /// Connection is closed
    Closed,
}

/// Wrapper to send/receive scale encoded messages
#[derive(Debug)]
pub struct WebSocketScale(pub(crate) WebSocket);

impl WebSocketScale {
    /// Send message encoded in scale
    pub async fn send<M: Encode + Send>(&mut self, message: M) -> Result<(), Error> {
        tokio::time::timeout(TIMEOUT, self.0.send(Message::Binary(message.encode())))
            .await
            .map_err(|_err| Error::SendTimeout)?
            .map_err(extract_ws_closed)
    }

    /// Recv message and try to decode it
    pub async fn recv<M: Decode>(&mut self) -> Result<M, Error> {
        // NOTE: ignore non binary messages
        loop {
            let message = tokio::time::timeout(TIMEOUT, self.0.next())
                .await
                .map_err(|_err| Error::ReadTimeout)?
                // NOTE: `None` is the same as `ConnectionClosed` or `AlreadyClosed`
                .ok_or(Error::Closed)?
                .map_err(extract_ws_closed)?;

            match message {
                Message::Binary(binary) => {
                    return Ok(M::decode_all(&mut binary.as_slice())?);
                }
                Message::Text(_) | Message::Ping(_) | Message::Pong(_) => {
                    iroha_logger::debug!(?message, "Unexpected message received");
                }
                Message::Close(_) => {
                    iroha_logger::debug!(?message, "Close message received");
                }
            }
        }
    }

    /// Discard messages and wait for close message
    pub async fn closed(&mut self) -> Result<(), Error> {
        loop {
            match self.0.next().await {
                // NOTE: `None` is the same as `ConnectionClosed` or `AlreadyClosed`
                None => return Ok(()),
                Some(Ok(_)) => {}
                // NOTE: technically `ConnectionClosed` or `AlreadyClosed` never returned
                // from `Stream` impl of `tokio_tungstenite` but left `ConnectionClosed` extraction to protect from potential change
                Some(Err(error)) => match extract_ws_closed(error) {
                    Error::Closed => return Ok(()),
                    error => return Err(error),
                },
            }
        }
    }

    /// Close websocket
    pub async fn close(mut self) -> Result<(), Error> {
        // NOTE: use `SinkExt::close` because it's not trying to write to closed socket
        match <_ as SinkExt<_>>::close(&mut self.0)
            .await
            .map_err(extract_ws_closed)
        {
            Err(Error::Closed) | Ok(()) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Check if websocket was closed normally
pub fn extract_ws_closed(error: axum::Error) -> Error {
    let error = error.into_inner();
    // NOTE: for this downcast to work versions of `tungstenite` here and in axum should match
    if let Some(tungstenite::Error::ConnectionClosed) = error.downcast_ref::<tungstenite::Error>() {
        return Error::Closed;
    }
    if let Some(tungstenite::Error::AlreadyClosed) = error.downcast_ref::<tungstenite::Error>() {
        return Error::Closed;
    }

    Error::WebSocket(axum::Error::new(error))
}
