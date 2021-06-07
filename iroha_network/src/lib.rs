//! Iroha network crate

#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "mock")]
mod mock;
#[cfg(not(feature = "mock"))]
mod network;

use std::{future::Future, sync::Arc};

use iroha_derive::Io;
use iroha_error::{error, Result, WrapErr};
use iroha_logger::log;
#[cfg(feature = "mock")]
use mock::*;
#[cfg(not(feature = "mock"))]
use network::*;
use parity_scale_codec::{Decode, Encode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::RwLock,
};

/// State type alias
pub type State<T> = Arc<RwLock<T>>;

/// async stream trait alias
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Network type
#[derive(Debug, Clone)]
pub struct Network {
    server_url: String,
}

impl Network {
    /// Creates a new client that will send request to the server on `server_url`
    /// # Arguments
    ///
    /// * `server_url` - is of format ip:port
    ///
    /// # Examples
    /// ```
    /// use iroha_network::Network;
    ///
    /// //If server runs on port 7878 on localhost
    /// let client = Network::new("127.0.0.1:7878");
    /// ```
    pub fn new(server_url: &str) -> Network {
        Network {
            server_url: server_url.to_owned(),
        }
    }

    /// Establishes connection to server on `self.server_url`, sends `request` closes connection and returns `Response`.
    ///
    /// # Errors
    /// Fails if initing connection or sending tcp packets or receiving fails
    #[iroha_futures::telemetry_future]
    pub async fn send_request(&self, request: Request) -> Result<Response> {
        Network::send_request_to(&self.server_url, request).await
    }

    /// Establishes connection to server on `server_url`, sends `request` closes connection and returns `Response`.
    ///
    /// # Errors
    /// Fails if initing connection or sending tcp packets or receiving fails
    #[iroha_futures::telemetry_future]
    #[log("TRACE")]
    pub async fn send_request_to(server_url: &str, request: Request) -> Result<Response> {
        send_request_to(server_url, request).await
    }

    /// Listens on the specified `server_url`.
    /// When there is an incoming connection, it passes it's `AsyncStream` to `handler`.
    /// # Arguments
    ///
    /// * `server_url` - url of format ip:port (e.g. `127.0.0.1:7878`) on which this server will listen for incoming connections.
    /// * `handler` - callback function which is called when there is an incoming connection, it get's the stream for this connection
    /// * `state` - the state that you want to capture
    ///
    /// # Errors
    /// Can fail during accepting connection or handling incoming message
    #[iroha_futures::telemetry_future]
    pub async fn listen<H, F, S>(state: State<S>, server_url: &str, handler: H) -> Result<()>
    where
        H: Send + FnMut(State<S>, Box<dyn AsyncStream>) -> F,
        F: Future<Output = Result<()>> + Send + 'static,
        State<S>: Send,
        S: Send + Sync,
    {
        listen(state, server_url, handler).await
    }

    /// Helper function to call inside `listen` `handler` function to parse and send response.
    /// The `handler` specified here will need to generate `Response` from `Request`.
    /// See `listen_async` for the description of the `state`.
    ///
    /// # Errors
    /// Fails if reading or writing to stream fails. Also can fail during request decoding
    #[allow(clippy::future_not_send)]
    pub async fn handle_message_async<H, F, S>(
        state: State<S>,
        mut stream: Box<dyn AsyncStream>,
        mut handler: H,
    ) -> Result<()>
    where
        H: FnMut(State<S>, Request) -> F,
        F: Future<Output = Result<Response>>,
    {
        let request = Request::from_async_stream(&mut stream)
            .await
            .wrap_err("Request read failed.")?;
        let response: Vec<u8> = handler(state, request).await?.into();
        stream.write_all(&response).await?;
        stream.flush().await?;
        Ok(())
    }
}

/// `Receipt` should be used by [Consumers](https://github.com/cloudevents/spec/blob/v1.0/spec.md#consumer)
/// to notify [Source](https://github.com/cloudevents/spec/blob/v1.0/spec.md#source) about
/// [Message](https://github.com/cloudevents/spec/blob/v1.0/spec.md#message) consumption.
#[derive(Io, Encode, Decode, Debug, Copy, Clone)]
pub enum Receipt {
    /// ok
    Ok,
}

/// Request
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Request {
    /// at uri
    pub uri_path: String,
    /// with payload
    pub payload: Vec<u8>,
}

impl Request {
    /// Creates a new request
    ///
    /// # Arguments
    ///
    /// * `uri_path` - corresponds to [URI syntax](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
    /// `path` part (e.g. "/metrics")
    /// * `payload` - the message in bytes
    ///
    /// # Examples
    /// ```
    /// use iroha_network::prelude::*;
    ///
    /// let request = Request::new("/metrics".to_string(), "some_message".to_string().into_bytes());
    /// ```
    pub fn new(uri_path: impl Into<String>, payload: Vec<u8>) -> Request {
        let uri_path = uri_path.into();
        Request { uri_path, payload }
    }

    /// Creates a request with empty body
    pub fn empty(uri_path: impl Into<String>) -> Request {
        Request::new(uri_path, Vec::new())
    }

    /// Constructs `Request` from `AsyncStream`
    /// # Errors
    /// May fail if parsing fails or reading through stream fails
    pub async fn from_async_stream(stream: &mut impl AsyncStream) -> Result<Self> {
        async fn read_header<'a, 'b: 'a>(
            stream: &'b mut impl AsyncStream,
            buf: &'a mut [u8],
        ) -> Result<&'a [u8]> {
            let len = stream.read(buf).await.wrap_err("Failed to read header")?;
            Ok(&buf[..len])
        }

        fn get_crlf(buf: &[u8]) -> Result<usize> {
            buf.iter()
                .position(|&b| b == b'\n')
                .ok_or_else(|| error!("Request shoud contain CRLF sequences"))
                .map(|n| n + 1)
        }

        fn read_uri(buf: &[u8]) -> Result<(String, &[u8])> {
            let end_uri = get_crlf(buf)?;
            let uri =
                String::from_utf8(buf[..end_uri - 2].to_vec()).wrap_err("Failed to decode uri")?;
            Ok((uri, &buf[end_uri..]))
        }

        fn read_payload_len(buf: &[u8]) -> Result<(usize, &[u8])> {
            let end_len = get_crlf(buf)?;
            let len = std::str::from_utf8(&buf[..end_len - 2])
                .wrap_err("Failed to decode length")?
                .parse::<usize>()
                .wrap_err("Failed to parse length")?;
            Ok((len, &buf[end_len..]))
        }

        let mut buf = [0; 100];
        let buf = read_header(stream, &mut buf).await?;

        let (uri_path, buf) = read_uri(buf)?;
        let (len, buf) = read_payload_len(buf)?;

        if len < buf.len() {
            return Err(error!("Provided length is wrong"));
        }

        let mut payload = buf.to_vec();
        let mut rest_payload = vec![0; len - payload.len()];
        let _ = stream
            .read_exact(&mut rest_payload)
            .await
            .wrap_err("Failed to read payload")?;
        payload.append(&mut rest_payload);

        Ok(Self { payload, uri_path })
    }
}

impl From<Request> for Vec<u8> {
    #[log("TRACE")]
    fn from(request: Request) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(request.uri_path.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(request.payload.len().to_string().as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend(request.payload.into_iter());
        bytes
    }
}

/// Response
#[derive(Debug, PartialEq, Io, Encode, Decode)]
pub enum Response {
    /// Okay
    Ok(Vec<u8>),
    /// internal server error
    InternalError,
}

impl Response {
    /// empty
    pub const fn empty_ok() -> Self {
        Response::Ok(Vec::new())
    }

    /// # Errors
    /// If it is internal server error when we fail
    pub fn into_result(self) -> Result<Vec<u8>> {
        match self {
            Response::Ok(bytes) => Ok(bytes),
            Response::InternalError => Err(error!("Internal Server Error.")),
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `iroha_network`.

    #[doc(inline)]
    pub use crate::{AsyncStream, Network, Receipt, Request, Response, State};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::clippy::unwrap_used)]

    use std::sync::Arc;

    use iroha_error::Result;
    use tokio::sync::RwLock;

    use super::*;

    fn get_empty_state() -> State<()> {
        Arc::new(RwLock::new(()))
    }

    #[test]
    fn request_correctly_built() {
        let request = Request {
            uri_path: "/instructions".to_owned(),
            payload: b"some_instruction".to_vec(),
        };
        let bytes: Vec<u8> = request.into();
        assert_eq!(b"/instructions\r\n16\r\nsome_instruction".to_vec(), bytes)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn single_threaded_async() {
        async fn handle_request<S>(_state: State<S>, _request: Request) -> Result<Response>
        where
            State<S>: Send + Sync,
            S: Sync,
        {
            Ok(Response::Ok(b"pong".to_vec()))
        }

        async fn handle_connection<S>(state: State<S>, stream: Box<dyn AsyncStream>) -> Result<()>
        where
            State<S>: Send + Sync,
            S: Sync,
        {
            Network::handle_message_async(state, stream, handle_request).await
        }

        let _drop = tokio::spawn(async move {
            Network::listen(get_empty_state(), "127.0.0.1:7878", handle_connection).await
        });
        std::thread::sleep(std::time::Duration::from_millis(500));
        match Network::send_request_to("127.0.0.1:7878", Request::empty("/ping"))
            .await
            .expect("Failed to send request to.")
        {
            Response::Ok(payload) => assert_eq!(payload, b"pong"),
            Response::InternalError => panic!("Response should be ok."),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn single_threaded_async_stateful() {
        #[allow(clippy::clippy::integer_arithmetic)]
        async fn handle_request(state: State<usize>, _request: Request) -> Result<Response> {
            *state.write().await += 1;
            Ok(Response::Ok(b"pong".to_vec()))
        }
        async fn handle_connection(
            state: State<usize>,
            stream: Box<dyn AsyncStream>,
        ) -> Result<()> {
            Network::handle_message_async(state, stream, handle_request).await
        }

        let counter: State<usize> = Arc::new(RwLock::new(0));
        let counter_move = Arc::clone(&counter);
        let _drop = tokio::spawn(async move {
            Network::listen(counter_move, "127.0.0.1:7870", handle_connection).await
        });
        std::thread::sleep(std::time::Duration::from_millis(500));
        match Network::send_request_to("127.0.0.1:7870", Request::empty("/ping"))
            .await
            .expect("Failed to send request to.")
        {
            Response::Ok(payload) => assert_eq!(payload, b"pong"),
            Response::InternalError => panic!("Response should be ok."),
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _drop = tokio::spawn(async move {
            let data = counter.write().await;
            assert_eq!(*data, 1)
        });
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
