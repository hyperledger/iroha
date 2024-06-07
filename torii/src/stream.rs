//! Extension to the [`futures::StreamExt`] and [`futures::SinkExt`].
//! Adds support for sending custom Iroha messages over the stream, taking care
//! of encoding/decoding as well as timeouts

use core::{result::Result, time::Duration};

use axum::extract::ws::Message;
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
pub enum Error<InternalStreamError>
where
    InternalStreamError: std::error::Error + Send + Sync + 'static,
{
    /// Read message timeout
    ReadTimeout,
    /// Send message timeout
    SendTimeout,
    /// An empty message was received
    NoMessage,
    /// Error in internal stream representation (typically `WebSocket`)
    ///
    /// Made without `from` macro because it will break `IrohaVersion` variant conversion
    InternalStream(#[source] InternalStreamError),
    /// `Close` message received
    CloseMessage,
    /// Unexpected non-binary message received
    NonBinaryMessage,
    /// Error during versioned message decoding
    Decode(#[from] parity_scale_codec::Error),
}

/// Represents message used by the stream
pub trait StreamMessage {
    /// Construct new binary message
    fn binary(source: Vec<u8>) -> Self;

    /// Check if message is binary and if so return payload
    fn try_binary(self) -> Option<Vec<u8>>;

    /// Returns `true` if it's a closing message
    fn is_close(&self) -> bool;
}

/// Trait for writing custom messages into stream
#[async_trait::async_trait]
pub trait Sink<S>: SinkExt<Self::Message, Error = Self::Err> + Unpin
where
    S: Encode + Send + Sync + 'static,
{
    /// Error type returned by the sink
    type Err: std::error::Error + Send + Sync + 'static;

    /// Message type used by the underlying sink
    type Message: StreamMessage + Send;

    /// Encoded message and sends it to the stream
    async fn send(&mut self, message: S) -> Result<(), Error<Self::Err>> {
        tokio::time::timeout(
            TIMEOUT,
            <Self as SinkExt<Self::Message>>::send(self, Self::Message::binary(message.encode())),
        )
        .await
        .map_err(|_err| Error::SendTimeout)?
        .map_err(Error::InternalStream)
    }
}

/// Trait for reading custom messages from stream
#[async_trait::async_trait]
pub trait Stream<R: DecodeAll>:
    StreamExt<Item = std::result::Result<Self::Message, Self::Err>> + Unpin
{
    /// Error type returned by the stream
    type Err: std::error::Error + Send + Sync + 'static;

    /// Message type used by the underlying stream
    type Message: StreamMessage;

    /// Receives and decodes message from the stream
    async fn recv(&mut self) -> Result<R, Error<Self::Err>> {
        let subscription_request_message = tokio::time::timeout(TIMEOUT, self.next())
            .await
            .map_err(|_err| Error::ReadTimeout)?
            .ok_or(Error::NoMessage)?
            .map_err(Error::InternalStream)?;

        if subscription_request_message.is_close() {
            return Err(Error::CloseMessage);
        }

        if let Some(binary) = subscription_request_message.try_binary() {
            Ok(R::decode_all(&mut binary.as_slice())?)
        } else {
            Err(Error::NonBinaryMessage)
        }
    }
}

impl StreamMessage for axum::extract::ws::Message {
    fn binary(source: Vec<u8>) -> Self {
        axum::extract::ws::Message::Binary(source)
    }

    fn try_binary(self) -> Option<Vec<u8>> {
        if let Message::Binary(binary) = self {
            Some(binary)
        } else {
            None
        }
    }

    fn is_close(&self) -> bool {
        matches!(self, axum::extract::ws::Message::Close(_))
    }
}

#[async_trait::async_trait]
impl<M> Sink<M> for axum::extract::ws::WebSocket
where
    M: Encode + Send + Sync + 'static,
{
    type Err = axum::Error;
    type Message = axum::extract::ws::Message;
}

#[async_trait::async_trait]
impl<M: DecodeAll> Stream<M> for axum::extract::ws::WebSocket {
    type Err = axum::Error;
    type Message = axum::extract::ws::Message;
}
