//! Extension to the [`futures::StreamExt`] and [`futures::SinkExt`].
//! Adds support for sending custom Iroha messages over the stream, taking care
//! of encoding/decoding as well as timeouts

use core::result::Result;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use iroha_version::prelude::*;

#[cfg(test)]
const TIMEOUT: Duration = Duration::from_millis(10_000);
#[cfg(not(test))]
const TIMEOUT: Duration = Duration::from_millis(1000);

/// Error type with generic for actual Stream/Sink error type
#[derive(thiserror::Error, Debug)]
pub enum Error<InternalStreamError>
where
    InternalStreamError: std::error::Error + Send + Sync + 'static,
{
    /// `recv()` timeout exceeded
    #[error("Read message timeout")]
    ReadTimeout,
    /// `send()` timeout exceeded
    #[error("Send message timeout")]
    SendTimeout,
    /// Error, indicating that empty message was received
    #[error("No message")]
    NoMessage,
    /// Error in internal stream representation (typically WebSocket)
    ///
    /// Made without `from` macro because it will break `IrohaVersion` variant conversion
    #[error("Internal stream error: {0}")]
    InternalStream(InternalStreamError),
    /// Error, indicating that `Close` message was received
    #[error("`Close` message received")]
    CloseMessage,
    /// Error, indicating that only binary messages are expected, but non-binary was received
    #[error("Non binary message received")]
    NonBinaryMessage,
    /// Error message during versioned message decoding
    #[error("Iroha version error: {0}")]
    IrohaVersion(#[from] iroha_version::error::Error),
}

/// Represents message used by the stream
pub trait StreamMessage {
    /// Construct new binary message
    fn binary(source: Vec<u8>) -> Self;

    /// Decodes the message into byte slice
    fn as_bytes(&self) -> &[u8];

    /// Returns `true` if the message is binary
    fn is_binary(&self) -> bool;

    /// Returns `true` if it's a closing message
    fn is_close(&self) -> bool;
}

/// Trait for writing custom messages into stream
#[async_trait::async_trait]
pub trait Sink<S: EncodeVersioned>: SinkExt<Self::Message, Error = Self::Err> + Unpin
where
    S: Send + Sync + 'static,
{
    /// Error type returned by the sink
    type Err: std::error::Error + Send + Sync + 'static;

    /// Message type used by the underlying sink
    type Message: StreamMessage + Send;

    /// Encoded message and sends it to the stream
    async fn send(&mut self, message: S) -> Result<(), Error<Self::Err>> {
        tokio::time::timeout(
            TIMEOUT,
            <Self as SinkExt<Self::Message>>::send(
                self,
                Self::Message::binary(message.encode_versioned()),
            ),
        )
        .await
        .map_err(|_err| Error::SendTimeout)?
        .map_err(Error::InternalStream)
    }
}

/// Trait for reading custom messages from stream
#[async_trait::async_trait]
pub trait Stream<R: DecodeVersioned>:
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

        if !subscription_request_message.is_binary() {
            return Err(Error::NonBinaryMessage);
        }

        Ok(R::decode_versioned(
            subscription_request_message.as_bytes(),
        )?)
    }
}

impl StreamMessage for warp::ws::Message {
    fn binary(source: Vec<u8>) -> Self {
        warp::ws::Message::binary(source)
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn is_binary(&self) -> bool {
        self.is_binary()
    }

    fn is_close(&self) -> bool {
        self.is_close()
    }
}

#[async_trait::async_trait]
impl<M: EncodeVersioned> Sink<M> for warp::ws::WebSocket
where
    M: Send + Sync + 'static,
{
    type Err = warp::Error;
    type Message = warp::ws::Message;
}
#[async_trait::async_trait]
impl<M: DecodeVersioned> Stream<M> for warp::ws::WebSocket {
    type Err = warp::Error;
    type Message = warp::ws::Message;
}

#[cfg(test)]
mod ws_client {
    use warp::test::WsClient;

    use super::*;

    #[async_trait::async_trait]
    impl<M: DecodeVersioned> Stream<M> for WsClient {
        type Err = warp::test::WsError;
        type Message = warp::ws::Message;
    }
    #[async_trait::async_trait]
    impl<M: EncodeVersioned> Sink<M> for WsClient
    where
        M: Send + Sync + 'static,
    {
        type Err = warp::test::WsError;
        type Message = warp::ws::Message;
    }
}
