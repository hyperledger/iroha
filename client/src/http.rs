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

    /// Sets request's body in bytes
    fn body(self, data: Vec<u8>) -> Self::Output;

    fn body_empty(self) -> Self::Output
    where
        Self: Sized,
    {
        self.body(Vec::new())
    }
}

pub struct WebSocketInitData<B>
where
    B: RequestBuilder,
{
    pub request: B::Output,
    pub first_message: Vec<u8>,
}

impl<B> WebSocketInitData<B>
where
    B: RequestBuilder,
{
    pub fn new(request: B::Output, first_message: Vec<u8>) -> Self {
        Self {
            request,
            first_message,
        }
    }
}

pub trait WebSocketInit {
    type Next;

    fn init<B>(self) -> Result<(WebSocketInitData<B>, Self::Next)>
    where
        B: RequestBuilder,
        Self: Sized,
        Self::Next: WebSocketHandleHandshake;
}

pub trait WebSocketHandleHandshake {
    type Next;

    fn handle(self, message: Vec<u8>) -> Result<Self::Next>
    where
        Self::Next: WebSocketHandleEvent;
}

pub trait WebSocketHandleEvent {
    type Event;

    fn handle(&self, message: Vec<u8>) -> Result<WebSocketHandleEventResponse<Self::Event>>;
}

pub struct WebSocketHandleEventResponse<T> {
    pub event: Option<T>,
    pub reply: Option<Vec<u8>>,
}

impl<T> WebSocketHandleEventResponse<T> {
    pub fn empty() -> Self {
        Self {
            event: None,
            reply: None,
        }
    }

    pub fn new() -> Self {
        Self::empty()
    }

    pub fn reply(self, payload: Vec<u8>) -> Self {
        Self {
            reply: Some(payload),
            ..self
        }
    }

    pub fn event(self, event: T) -> Self {
        Self {
            event: Some(event),
            ..self
        }
    }
}

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

// trait WebSocketHandlerThen {
//     fn test() -> Self;
// }

// enum IrohaWebSocketHandlerResponse<T>
// where
//     T: Sized,
// {
//     Reply { message: Vec<u8>, decoded: T },
// }
