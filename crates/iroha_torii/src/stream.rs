//! Adds support for sending/receiving custom Iroha messages over the WebSocket
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use core::{result::Result, time::Duration};
use futures::{SinkExt, StreamExt};
use norito::prelude::*;
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
    /// Error during Norito message decoding
    Decode(#[from] norito::Error),
    /// Error during Norito message encoding
    Encode(norito::Error),
    /// Unexpected WebSocket frame `{actual}`; expected {expected}
    UnexpectedFrame {
        /// Expected frame kind for the current protocol state.
        expected: &'static str,
        /// Received frame kind.
        actual: &'static str,
    },
    /// Connection is closed
    Closed,
}
/// RFC 6455 close code for invalid frame payload data.
pub const CLOSE_INVALID_PAYLOAD: u16 = 1007;
/// RFC 6455 close code for a protocol policy violation.
pub const CLOSE_POLICY_VIOLATION: u16 = 1008;
/// RFC 6455 close code for an unexpected server failure.
pub const CLOSE_INTERNAL_ERROR: u16 = 1011;
/// RFC 6455 close code asking the client to retry later.
pub const CLOSE_TRY_AGAIN_LATER: u16 = 1013;

async fn send_message_until<S>(
    sink: &mut S,
    deadline: tokio::time::Instant,
    message: Message,
) -> Result<(), Error>
where
    S: futures::Sink<Message, Error = axum::Error> + Unpin,
{
    tokio::time::timeout_at(deadline, sink.send(message))
        .await
        .map_err(|_elapsed| Error::SendTimeout)?
        .map_err(extract_ws_closed)
}

/// Send one WebSocket message under an absolute operation deadline.
pub async fn send_message_with_timeout<S>(
    sink: &mut S,
    timeout: Duration,
    message: Message,
) -> Result<(), Error>
where
    S: futures::Sink<Message, Error = axum::Error> + Unpin,
{
    send_message_until(sink, tokio::time::Instant::now() + timeout, message).await
}

async fn close_sink_with_timeout<S>(sink: &mut S, timeout: Duration) -> Result<(), Error>
where
    S: futures::Sink<Message, Error = axum::Error> + Unpin,
{
    let result = tokio::time::timeout(timeout, <_ as SinkExt<_>>::close(sink))
        .await
        .map_err(|_elapsed| Error::SendTimeout)?
        .map_err(extract_ws_closed);
    match result {
        Err(Error::Closed) | Ok(()) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn close_sink_with_frame<S>(
    sink: &mut S,
    timeout: Duration,
    frame: CloseFrame,
) -> Result<(), Error>
where
    S: futures::Sink<Message, Error = axum::Error> + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    match send_message_until(sink, deadline, Message::Close(Some(frame))).await {
        Err(Error::Closed) => return Ok(()),
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    let result = tokio::time::timeout_at(deadline, <_ as SinkExt<_>>::close(sink))
        .await
        .map_err(|_elapsed| Error::SendTimeout)?
        .map_err(extract_ws_closed);
    match result {
        Err(Error::Closed) | Ok(()) => Ok(()),
        Err(error) => Err(error),
    }
}

fn decode_subscription_request<M>(bytes: &[u8]) -> Result<M, norito::Error>
where
    M: NoritoSerialize,
    for<'de> M: NoritoDeserialize<'de>,
{
    norito::decode_canonical(bytes)
}
async fn recv_subscription_until<M, S>(
    stream: &mut S,
    deadline: tokio::time::Instant,
) -> Result<M, Error>
where
    M: NoritoSerialize,
    for<'de> M: NoritoDeserialize<'de>,
    S: futures::Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    // Control frames are transport traffic, not a new subscription deadline.
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::ReadTimeout);
        }
        let message = tokio::time::timeout_at(deadline, stream.next())
            .await
            .map_err(|_err| Error::ReadTimeout)?
            // NOTE: `None` is the same as `ConnectionClosed` or `AlreadyClosed`
            .ok_or(Error::Closed)?
            .map_err(extract_ws_closed)?;
        match message {
            Message::Binary(binary) => {
                return decode_subscription_request::<M>(binary.as_ref()).map_err(Error::Decode);
            }
            Message::Text(_) => {
                return Err(Error::UnexpectedFrame {
                    expected: "a binary Norito subscription request",
                    actual: "text",
                });
            }
            Message::Ping(_) | Message::Pong(_) => {
                iroha_logger::trace!(?message, "Unexpected message received");
            }
            Message::Close(_) => {
                iroha_logger::trace!(?message, "Close message received");
                return Err(Error::Closed);
            }
        }
    }
}
/// Wrapper to send/receive Norito encoded messages
#[derive(Debug)]
pub struct WebSocketNorito {
    ws: WebSocket,
    timeout: Duration,
}
impl WebSocketNorito {
    /// Create a new Norito WebSocket wrapper with a fixed message timeout.
    #[must_use]
    pub fn new(ws: WebSocket, timeout: Duration) -> Self {
        Self { ws, timeout }
    }
    /// Send message encoded in Norito
    pub async fn send<M: NoritoSerialize + Send>(&mut self, message: M) -> Result<(), Error> {
        // Use Norito framing (header + checksum) so clients can validate payloads.
        let buf = norito::to_bytes(&message).map_err(Error::Encode)?;
        send_message_with_timeout(
            &mut self.ws,
            self.timeout,
            Message::Binary(axum::body::Bytes::from(buf)),
        )
        .await
    }
    /// Send an empty WebSocket ping frame as a transport heartbeat.
    pub async fn ping(&mut self) -> Result<(), Error> {
        send_message_with_timeout(
            &mut self.ws,
            self.timeout,
            Message::Ping(axum::body::Bytes::new()),
        )
        .await
    }
    /// Receive and decode one canonical, uncompressed Norito request.
    ///
    /// The configured timeout is one absolute deadline; ping and pong control frames do not
    /// extend it.
    pub async fn recv<M>(&mut self) -> Result<M, Error>
    where
        M: NoritoSerialize,
        for<'a> M: NoritoDeserialize<'a>,
        M: Send,
    {
        let deadline = tokio::time::Instant::now() + self.timeout;
        recv_subscription_until(&mut self.ws, deadline).await
    }
    /// Wait for the peer to close while rejecting post-subscription data frames.
    ///
    /// Canonical Torii event and block streams are server-to-client after their single binary
    /// subscription request. Silently accepting further data frames would make protocol mistakes
    /// indistinguishable from supported control messages.
    pub async fn closed(&mut self) -> Result<(), Error> {
        loop {
            match self.ws.next().await {
                // NOTE: `None` is the same as `ConnectionClosed` or `AlreadyClosed`
                None => return Ok(()),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) => return Ok(()),
                Some(Ok(Message::Binary(_))) => {
                    return Err(Error::UnexpectedFrame {
                        expected: "ping, pong, or close",
                        actual: "binary",
                    });
                }
                Some(Ok(Message::Text(_))) => {
                    return Err(Error::UnexpectedFrame {
                        expected: "ping, pong, or close",
                        actual: "text",
                    });
                }
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
        close_sink_with_timeout(&mut self.ws, self.timeout).await
    }
    /// Close the WebSocket with a stable protocol status and reason.
    pub async fn close_with(self, code: u16, reason: impl Into<String>) -> Result<(), Error> {
        let mut this = self;
        let reason = reason.into();
        let frame = CloseFrame {
            code,
            reason: Utf8Bytes::from(reason),
        };
        close_sink_with_frame(&mut this.ws, this.timeout, frame).await
    }
}
#[cfg(test)]
mod subscription_decode_tests {
    use super::*;
    use futures::channel::mpsc;
    use iroha_data_model::{
        block::stream::BlockSubscriptionRequest, events::stream::EventSubscriptionRequest,
    };
    use std::num::NonZeroU64;
    fn assert_common_noncanonical_frames_rejected<T>(value: &T)
    where
        T: NoritoSerialize,
        for<'de> T: NoritoDeserialize<'de>,
    {
        let canonical = norito::encode_canonical(value).expect("encode canonical subscription");
        decode_subscription_request::<T>(&canonical).expect("canonical subscription must decode");
        let compressed =
            norito::to_compressed_bytes(value, Some(norito::CompressionConfig::default()))
                .expect("encode compressed subscription");
        assert!(matches!(
            decode_subscription_request::<T>(&compressed),
            Err(norito::Error::NonCanonicalEncoding)
        ));
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(decode_subscription_request::<T>(&trailing).is_err());
        let length_offset = norito::core::Header::SIZE
            - 2 * core::mem::size_of::<u64>()
            - core::mem::size_of::<u8>();
        let mut oversized = canonical;
        oversized[length_offset..length_offset + core::mem::size_of::<u64>()]
            .copy_from_slice(&(1024_u64 * 1024).to_le_bytes());
        assert!(decode_subscription_request::<T>(&oversized).is_err());
    }
    #[test]
    fn event_subscription_requires_one_exact_canonical_frame() {
        let request = EventSubscriptionRequest::new(Vec::new());
        assert_common_noncanonical_frames_rejected(&request);
        let canonical = norito::encode_canonical(&request).expect("encode canonical event request");
        let alternate_flags =
            norito::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _flags = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::core::to_bytes(&request).expect("encode alternate-layout event request")
        };
        assert_ne!(
            alternate, canonical,
            "fixture must exercise alternate flags"
        );
        assert!(matches!(
            decode_subscription_request::<EventSubscriptionRequest>(&alternate),
            Err(norito::Error::NonCanonicalEncoding)
        ));
    }
    #[test]
    fn block_subscription_requires_one_exact_canonical_frame() {
        let request = BlockSubscriptionRequest(
            NonZeroU64::new(1).expect("subscription height must be non-zero"),
        );
        assert_common_noncanonical_frames_rejected(&request);
    }
    #[tokio::test]
    async fn control_frames_do_not_extend_subscription_deadline() {
        const READ_TIMEOUT: Duration = Duration::from_millis(100);
        const PING_INTERVAL: Duration = Duration::from_millis(10);
        const TEST_GUARD: Duration = Duration::from_secs(1);
        let (sender, mut receiver) = mpsc::unbounded::<Result<Message, axum::Error>>();
        sender
            .unbounded_send(Ok(Message::Ping(axum::body::Bytes::new())))
            .expect("queue initial ping");
        sender
            .unbounded_send(Ok(Message::Pong(axum::body::Bytes::new())))
            .expect("queue initial pong");
        let pinger = tokio::spawn(async move {
            let mut interval = tokio::time::interval(PING_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if sender
                    .unbounded_send(Ok(Message::Ping(axum::body::Bytes::new())))
                    .is_err()
                {
                    return;
                }
            }
        });
        let deadline = tokio::time::Instant::now() + READ_TIMEOUT;
        let result = tokio::time::timeout(
            TEST_GUARD,
            recv_subscription_until::<BlockSubscriptionRequest, _>(&mut receiver, deadline),
        )
        .await
        .expect("control frames must not keep the subscription read alive");
        assert!(matches!(result, Err(Error::ReadTimeout)));
        drop(receiver);
        pinger.await.expect("control-frame sender must not panic");
    }
    #[tokio::test]
    async fn subscription_decodes_after_control_frames_before_deadline() {
        let request = BlockSubscriptionRequest(
            NonZeroU64::new(1).expect("subscription height must be non-zero"),
        );
        let bytes = norito::encode_canonical(&request).expect("encode canonical subscription");
        let (sender, mut receiver) = mpsc::unbounded::<Result<Message, axum::Error>>();
        sender
            .unbounded_send(Ok(Message::Ping(axum::body::Bytes::new())))
            .expect("queue ping");
        sender
            .unbounded_send(Ok(Message::Pong(axum::body::Bytes::new())))
            .expect("queue pong");
        sender
            .unbounded_send(Ok(Message::Binary(bytes.into())))
            .expect("queue subscription");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let decoded =
            recv_subscription_until::<BlockSubscriptionRequest, _>(&mut receiver, deadline)
                .await
                .expect("subscription must decode before its fixed deadline");
        assert_eq!(decoded.0, request.0);
    }
}

#[cfg(test)]
mod close_timeout_tests {
    use super::*;
    use core::{pin::Pin, task::Poll};
    use futures::Sink;

    const CLOSE_TIMEOUT: Duration = Duration::from_millis(10);
    const TEST_GUARD: Duration = Duration::from_secs(1);

    #[derive(Default)]
    struct PendingCloseSink {
        sent: Vec<Message>,
    }

    struct PendingSendSink;

    impl Sink<Message> for PendingSendSink {
        type Error = axum::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            unreachable!("a pending sink must not accept a message")
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    impl Sink<Message> for PendingCloseSink {
        type Error = axum::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.sent.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn send_message_maps_elapsed_deadline_to_send_timeout() {
        let mut sink = PendingSendSink;
        let result = tokio::time::timeout(
            TEST_GUARD,
            send_message_with_timeout(
                &mut sink,
                CLOSE_TIMEOUT,
                Message::Ping(axum::body::Bytes::new()),
            ),
        )
        .await
        .expect("send helper must enforce its own deadline");

        assert!(matches!(result, Err(Error::SendTimeout)));
    }

    #[tokio::test]
    async fn close_sink_maps_elapsed_deadline_to_send_timeout() {
        let mut sink = PendingCloseSink::default();
        let result = tokio::time::timeout(
            TEST_GUARD,
            close_sink_with_timeout(&mut sink, CLOSE_TIMEOUT),
        )
        .await
        .expect("close helper must enforce its own deadline");

        assert!(matches!(result, Err(Error::SendTimeout)));
    }

    #[tokio::test]
    async fn close_with_frame_times_out_while_finishing_sink_close() {
        let mut sink = PendingCloseSink::default();
        let result = tokio::time::timeout(
            TEST_GUARD,
            close_sink_with_frame(
                &mut sink,
                CLOSE_TIMEOUT,
                CloseFrame {
                    code: CLOSE_POLICY_VIOLATION,
                    reason: Utf8Bytes::from_static("invalid subscription"),
                },
            ),
        )
        .await
        .expect("framed close helper must enforce its own deadline");

        assert!(matches!(result, Err(Error::SendTimeout)));
        let [Message::Close(Some(frame))] = sink.sent.as_slice() else {
            panic!("close helper must send exactly one close frame");
        };
        assert_eq!(frame.code, CLOSE_POLICY_VIOLATION);
        assert_eq!(frame.reason, "invalid subscription");
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
