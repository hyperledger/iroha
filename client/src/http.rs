use std::borrow::Borrow;

use eyre::{eyre, Result};
pub use http::{Method, Response, StatusCode};

/// General HTTP request builder.
///
/// To use custom builder with client, you need to implement this trait for some type and pass it
/// to the client that will fill it with data.
///
/// The order of builder methods invocation is not strict. There is no guarantee that builder user calls
/// all methods. Only [`RequestBuilder::new`] is the required one.
pub trait RequestBuilder {
    /// Entrypoint - create a new builder with specified method and URL.
    #[must_use]
    fn new(method: Method, url: impl AsRef<str>) -> Self;

    /// Add multiple query params at once. Uses [`RequestBuilder::param`] for each param.
    #[must_use]
    fn params<P, K, V>(mut self, params: P) -> Self
    where
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString,
        Self: Sized,
    {
        for pair in params {
            let (k, v) = pair.borrow();
            self = self.param(k, v.to_string());
        }
        self
    }

    /// Add a single query param
    #[must_use]
    fn param<K, V>(self, key: K, value: V) -> Self
    where
        K: AsRef<str>,
        V: ToString;

    /// Add multiple headers at once. Uses [`RequestBuilder::header`] for each param.
    #[must_use]
    fn headers<H, N, V>(mut self, headers: H) -> Self
    where
        H: IntoIterator,
        H::Item: Borrow<(N, V)>,
        N: AsRef<str>,
        V: ToString,
        Self: Sized,
    {
        for pair in headers {
            let (k, v) = pair.borrow();
            self = self.header(k, v.to_string());
        }
        self
    }

    /// Add a single header
    #[must_use]
    fn header<N, V>(self, name: N, value: V) -> Self
    where
        N: AsRef<str>,
        V: ToString;

    /// Set request's binary body
    #[must_use]
    fn body(self, data: Vec<u8>) -> Self;
}

/// Generalization of `WebSocket` client's functionality
pub mod ws {
    use super::{eyre, RequestBuilder, Result};

    /// `WebSocket` connection flow stages.
    ///
    /// Flow consists of the following:
    ///
    /// 1. **Init stage** - establish `WebSocket` connection with Iroha
    /// 2. **Handshake stage** - send a "subscription" message to Iroha and ensure that the next message from Iroha
    ///     is a "subscription accepted" message
    /// 3. **Events stage** - wait for messages from Iroha. For each message, decode *some event* from it
    ///     and send back *some "received"* mesage
    ///
    ///
    ///
    /// This module has a set of abstraction to extract pure data logic from transportation logic. Following sections
    /// describe how to use this module from both **flow implemention** (data side) and
    /// **transport implementation** sides.
    ///
    /// ## Flow implementation
    ///
    /// From data side, you should implement a state machine built on top of these traits:
    ///
    /// - [Init][conn_flow::Init] - it is designed to consume its impl struct and produce a tuple, that has 2 items:
    ///   **initial data** to establish WS connection, and the **handler** of the next flow stage - **handshake**.
    ///   Then, transportation side should open a connection, send first message into it, receive message from Iroha
    ///   and pass it into the next handler.
    /// - [Handshake][conn_flow::Handshake] - handles incoming message and ensures that it is OK. Which message is OK -
    ///   implementation dependent. If it is OK, returns the handler for the next, final flow stage - **events**.
    /// - [Events][conn_flow::Events] - handles incoming messages and returns a **binary reply** back Iroha and **some decoded event**.
    ///
    /// Here is an example of how to implement flow in a transport-agnostic manner:
    ///
    /// ```rust
    /// use eyre::{eyre, Result};
    /// use iroha_client::http::{
    ///     ws::conn_flow::{
    ///         EventData, Events as FlowEvents, Handshake as FlowHandshake, Init as FlowInit,
    ///         InitData,
    ///     },
    ///     Method, RequestBuilder,
    /// };
    ///
    /// struct Init;
    ///
    /// impl<R: RequestBuilder> FlowInit<R> for Init {
    ///     type Next = Handshake;
    ///
    ///     fn init(self) -> InitData<R, Self::Next> {
    ///         InitData::new(
    ///             R::new(Method::GET, "http://localhost:3000"),
    ///             vec![1, 2, 3],
    ///             Handshake,
    ///         )
    ///     }
    /// }
    ///
    /// struct Handshake;
    ///
    /// impl FlowHandshake for Handshake {
    ///     type Next = Events;
    ///
    ///     fn message(self, message: Vec<u8>) -> Result<Self::Next> {
    ///         if message[0] == 42 {
    ///             Ok(Events)
    ///         } else {
    ///             Err(eyre!("Wrong"))
    ///         }
    ///     }
    /// }
    ///
    /// struct Events;
    ///
    /// impl FlowEvents for Events {
    ///     type Event = u8;
    ///
    ///     fn message(&self, message: Vec<u8>) -> Result<EventData<Self::Event>> {
    ///         Ok(EventData::new(message[0], vec![3, 2, 1]))
    ///     }
    /// }
    /// ```
    ///
    /// ## Transport implementation
    ///
    /// You are a library user and want to use Iroha Client with your own HTTP/WS implementation. For such a purpose
    /// the client library should provide an API wrapped into the flow traits. Anyway, firstly you should implement
    /// [`super::RequestBuilder`] trait for your transport.
    ///
    /// Let's take Events API as an example. [`crate::client::Client::events_handler`] creates a struct of
    /// initial WS flow stage - [`crate::client::events_api::flow::Init`].
    /// Here is an example (oversimplified) of how you can use it:
    ///
    /// ```rust,ignore
    /// use eyre::Result;
    /// use iroha_data_model::prelude::Event;
    /// use iroha_client::{
    ///     client::events_api::flow as events_api_flow,
    ///     http::{
    ///         ws::conn_flow::{EventData, Events, Handshake, Init, InitData},
    ///         RequestBuilder,
    ///     },
    /// };
    ///
    /// // Some request builder
    /// struct MyBuilder;
    ///
    /// impl RequestBuilder for MyBuilder {
    ///     /* ... */
    /// }
    ///
    /// impl MyBuilder {
    ///     fn connect(self) -> MyStream {
    ///         /* ... */
    ///     }
    /// }
    ///
    /// // Some `WebSocket` stream
    /// struct MyStream;
    ///
    /// impl MyStream {
    ///     // Receive message
    ///     fn get_next(&self) -> Vec<u8> {
    ///         /* ... */
    ///     }
    ///     
    ///     // Send message
    ///     fn send(&self, msg: Vec<u8>) {
    ///         /* ... */
    ///     }
    /// }
    ///
    /// fn collect_5_events(flow: events_api_flow::Init) -> Result<Vec<Event>> {
    ///     // Constructing initial flow data
    ///     let InitData {
    ///         next: flow,
    ///         first_message,
    ///         req,
    ///     }: InitData<MyBuilder, _> = flow.init();
    ///
    ///     // Firstly, sending the message
    ///     let stream = req.connect();
    ///     stream.send(first_message);
    ///
    ///     // Then handling Iroha response on it
    ///     let response = stream.get_next();
    ///     let flow = flow.message(response)?;
    ///
    ///     // And now we are able to collect events
    ///     let mut events: Vec<Event> = Vec::with_capacity(5);
    ///     while events.len() < 5 {
    ///         let msg = stream.get_next();
    ///         let EventData { reply, event } = flow.message(msg)?;
    ///         // Do not forget to send reply back to Iroha!
    ///         stream.send(reply);
    ///         events.push(event);
    ///     }
    ///
    ///     Ok(events)
    /// }
    /// ```
    pub mod conn_flow {
        use super::*;

        /// Initial data to initialize connection and acquire handshake. Produced by implementor of [`Init`].
        pub struct InitData<R, H>
        where
            R: RequestBuilder,
            H: Handshake,
        {
            /// Built HTTP request to init WS connection
            pub req: R,
            /// Should be sent immediately after WS connection establishment
            pub first_message: Vec<u8>,
            /// Handler for the next flow stage - handshake
            pub next: H,
        }

        impl<R, H> InitData<R, H>
        where
            R: RequestBuilder,
            H: Handshake,
        {
            /// Construct new item.
            pub fn new(req: R, first_message: Vec<u8>, next: H) -> Self {
                Self {
                    req,
                    first_message,
                    next,
                }
            }
        }

        /// Struct that is emitted from [`Events`] handler when message is handled.
        pub struct EventData<T> {
            /// Decoded event
            pub event: T,
            /// Reply that should be sent back to Iroha
            pub reply: Vec<u8>,
        }

        impl<T> EventData<T> {
            /// Construct new item.
            pub fn new(event: T, reply: Vec<u8>) -> Self {
                Self { event, reply }
            }
        }

        /// Initial flow stage.
        pub trait Init<R: RequestBuilder> {
            /// The next handler
            type Next: Handshake;

            /// Consumes itself to produce initial data to:
            ///
            /// - Open WS connection;
            /// - Send first message into it;
            /// - Handle first message from Iroha with the next handler.
            ///
            /// It doesn't return a `Result` because it doesn't accept any parameters except of itself.
            fn init(self) -> InitData<R, Self::Next>;
        }

        /// Handshake flow stage.
        pub trait Handshake {
            /// The next handler
            type Next: Events;

            /// Handles first messages. If it is OK, returns the next handler.
            ///
            /// # Errors
            /// Implementation dependent.
            fn message(self, message: Vec<u8>) -> Result<Self::Next>;
        }

        /// Events flow stage.
        pub trait Events {
            /// Something yielded by the handler
            type Event;

            /// Handles forthcoming Iroha message and returns:
            ///
            /// - Decoded event;
            /// - Message to reply with.
            ///
            /// # Errors
            /// Implementation dependent.
            fn message(&self, message: Vec<u8>) -> Result<EventData<Self::Event>>;
        }
    }

    /// Replaces `http(s)://` with `ws(s)://`
    ///
    /// # Errors
    /// Fails if passed URI doesn't have a valid protocol
    pub fn transform_ws_url(uri: &str) -> Result<String> {
        let ws_uri = if let Some(https_uri) = uri.strip_prefix("https://") {
            "wss://".to_owned() + https_uri
        } else if let Some(http_uri) = uri.strip_prefix("http://") {
            "ws://".to_owned() + http_uri
        } else {
            return Err(eyre!("No schema in web socket uri provided. {}", uri));
        };

        Ok(ws_uri)
    }
}
