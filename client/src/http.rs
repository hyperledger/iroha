use std::{borrow::Borrow, collections::HashMap};

use eyre::{eyre, Result};
pub use http::{Method, Response, StatusCode};

/// Type alias for HTTP headers hash map
pub type Headers = HashMap<String, String>;

/// General trait for building http-requests.
///
/// To use custom builder with client, you need to implement this trait for some type and pass it
/// to the client that will fill it.
pub trait RequestBuilder {
    type Output;

    /// Constructs a new builder with provided method and URL
    #[must_use]
    fn new<U>(method: Method, url: U) -> Self
    where
        U: AsRef<str>;

    /// Sets request's query params
    #[must_use]
    fn params<P, K, V>(self, params: P) -> Self
    where
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString;

    /// Sets request's headers
    #[must_use]
    fn headers(self, headers: Headers) -> Self;

    /// Sets request's body in bytes and transforms the builder to its output
    fn body(self, data: Option<Vec<u8>>) -> Self::Output;
}

/// Represents data required to initialize any WebSocket connection with Iroha
pub struct WebSocketInitData<B>
where
    B: RequestBuilder,
{
    /// Basic HTTP request that should be done and then upgraded to WS
    pub request: B::Output,
    /// Data that should be sent to Iroha immediately when WS connection is initialized
    pub first_message: Vec<u8>,
}

impl<B> WebSocketInitData<B>
where
    B: RequestBuilder,
{
    /// Creates struct with provided request and first message
    pub fn new(request: B::Output, first_message: Vec<u8>) -> Self {
        Self {
            request,
            first_message,
        }
    }
}

/// Represents a struct in the initial state of WS connection flow
pub trait WebSocketFlowInit {
    /// Some type that handles the next step of WS flow - handshake acquiring.
    /// This type is returned by the init function.
    type Next: WebSocketFlowHandshake;

    /// Builds data for connection initialization and returns handler for the next
    /// step of WS flow.
    ///
    /// # Errors
    /// Implementation dependent.
    fn init<B>(self) -> Result<(WebSocketInitData<B>, Self::Next)>
    where
        B: RequestBuilder,
        Self: Sized;
}

/// Represents a struct in the handshake-acquiring-state of WS connection flow
pub trait WebSocketFlowHandshake {
    /// Some type that will handle incoming events when handshake acquiring is done.
    type Next: WebSocketFlowEvents;

    /// Handles binary WS message and returns events handler if handshake is acquired.
    ///
    /// # Errors
    /// Implementation dependent.
    fn message(self, message: Vec<u8>) -> Result<Self::Next>;
}

/// Represents a struct in the events-handling, final state of WS connection flow
pub trait WebSocketFlowEvents {
    /// Some event type that is yielded by the handler
    type Event;

    /// Handles binary WS message and returns reply with decoded event.
    ///
    /// # Errors
    /// Implementation dependent.
    fn message(&self, message: Vec<u8>) -> Result<WebSocketHandleEventResponse<Self::Event>>;
}

/// Represents WS event handler response.
pub struct WebSocketHandleEventResponse<T> {
    /// Decoded event
    pub event: T,
    /// Binary reply that should be sent back through the WS connection
    pub reply: Vec<u8>,
}

impl<T> WebSocketHandleEventResponse<T> {
    /// Constructs it with provided event and binary reply
    pub fn new(event: T, reply: Vec<u8>) -> Self {
        Self { event, reply }
    }
}

/// Replaces `http(s)://` with `ws(s)://`
///
/// # Errors
/// Fails if passed URI doesn't have a valid protocol
pub fn transform_ws_url<S>(uri: S) -> Result<String>
where
    S: AsRef<str>,
{
    let ws_uri = if let Some(https_uri) = uri.as_ref().strip_prefix("https://") {
        "wss://".to_owned() + https_uri
    } else if let Some(http_uri) = uri.as_ref().strip_prefix("http://") {
        "ws://".to_owned() + http_uri
    } else {
        return Err(eyre!("No schema in web socket uri provided"));
    };

    Ok(ws_uri)
}
