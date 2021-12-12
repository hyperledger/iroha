//! Extension to the [`futures::StreamExt`] and [`futures::SinkExt`].
//! Adds support for sending custom Iroha messages over the stream, taking care
//! of encoding/decoding as well as timeouts

use std::time::Duration;

use eyre::{eyre, Context, Result};
use futures::{SinkExt, StreamExt};
use iroha_version::prelude::*;

#[cfg(test)]
const TIMEOUT: Duration = Duration::from_millis(10_000);
#[cfg(not(test))]
const TIMEOUT: Duration = Duration::from_millis(1000);

/// Represents messsage used by the stream
pub trait StreamMessage {
    /// Constructs new binary message
    fn binary(source: Vec<u8>) -> Self;
    /// Decodes the message into byte slice
    fn as_bytes(&self) -> &[u8];
    /// Returns `true` if the message is binary
    fn is_binary(&self) -> bool;
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
    async fn send(&mut self, message: S) -> Result<()> {
        Ok(tokio::time::timeout(
            TIMEOUT,
            <Self as SinkExt<Self::Message>>::send(
                self,
                Self::Message::binary(message.encode_versioned()?),
            ),
        )
        .await
        .wrap_err("Send message timeout")??)
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
    async fn recv(&mut self) -> Result<R> {
        let subscription_request_message = tokio::time::timeout(TIMEOUT, self.next())
            .await
            .wrap_err("Read message timeout")?
            .ok_or_else(|| eyre!("No message"))??;

        if !subscription_request_message.is_binary() {
            return Err(eyre!("Expected binary message"));
        }

        Ok(R::decode_versioned(
            subscription_request_message.as_bytes(),
        )?)
    }
}

impl StreamMessage for warp::ws::Message {
    fn binary(source: Vec<u8>) -> Self {
        Self::binary(source)
    }
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
    fn is_binary(&self) -> bool {
        self.is_binary()
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
mod tests {
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
