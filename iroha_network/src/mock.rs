#![allow(
    clippy::missing_errors_doc,
    unsafe_code,
    missing_docs,
    clippy::panic,
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    clippy::integer_arithmetic,
    clippy::expect_used
)]

use std::{
    convert::{TryFrom, TryInto},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use std::{io, sync::Arc};

use dashmap::DashMap;
use iroha_derive::Io;
use iroha_error::{error, Error, Result};
use iroha_logger::log;
use once_cell::sync::Lazy;
use parity_scale_codec::{Decode, Encode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    runtime::Handle,
    sync::{
        mpsc::{self, Sender},
        RwLock,
    },
    task,
};

const BUFFER_SIZE: usize = 2_usize.pow(11);
static ENDPOINTS: Lazy<DashMap<String, Sender<RequestStream>>> = Lazy::new(DashMap::new);

fn find_sender(server_url: &str) -> Sender<RequestStream> {
    if let Some(entry) = ENDPOINTS.get(server_url) {
        return entry.value().clone();
    }
    panic!("Can't find ENDPOINT: {}", server_url);
}

/// alias of `Arc<RwLock<T>`
pub type State<T> = Arc<RwLock<T>>;

/// Alias for read write
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

struct RequestStream {
    bytes: Vec<u8>,
    tx: Sender<Vec<u8>>,
}

impl Unpin for RequestStream {}

impl AsyncRead for RequestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let bytes = &mut self.get_mut().bytes;
        let length = if buf.remaining() > bytes.len() {
            bytes.len()
        } else {
            buf.remaining()
        };
        let bytes: Vec<_> = bytes.drain(..length).collect();
        buf.put_slice(&bytes);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RequestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let bytes = &mut self.get_mut().bytes;
        for byte in buf.to_vec() {
            bytes.push(byte);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        task::block_in_place(|| Handle::current().block_on(self.tx.send(self.bytes.clone())))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Network type
#[derive(Debug, Clone)]
pub struct Network {
    server_url: String,
}

impl Network {
    pub fn new(server_url: &str) -> Network {
        Network {
            server_url: server_url.to_owned(),
        }
    }

    #[iroha_futures::telemetry_future]
    pub async fn send_request(&self, request: Request) -> Result<Response> {
        Network::send_request_to(&self.server_url, request).await
    }

    #[iroha_futures::telemetry_future]
    #[log]
    pub async fn send_request_to(server_url: &str, request: Request) -> Result<Response> {
        let (tx, mut rx) = mpsc::channel(100);
        let mut stream = RequestStream {
            bytes: Vec::new(),
            tx,
        };
        let payload: Vec<u8> = request.into();
        stream.write_all(&payload).await?;
        find_sender(server_url)
            .send(stream)
            .await
            .map_err(|_err| error!("Receiver dropped."))?;
        //TODO: return actual response
        Response::try_from(rx.recv().await.unwrap())
    }

    /// Listens on the specified `server_url`.
    /// When there is an incoming connection, it passes it's `AsyncStream` to `handler`.
    /// # Arguments
    ///
    /// * `server_url` - url of format ip:port (e.g. `127.0.0.1:7878`) on which this server will listen for incoming connections.
    /// * `handler` - callback function which is called when there is an incoming connection, it get's the stream for this connection
    /// * `state` - the state that you want to capture
    #[iroha_futures::telemetry_future]
    pub async fn listen<H, F, S>(state: State<S>, server_url: &str, mut handler: H) -> Result<()>
    where
        H: Send + FnMut(State<S>, Box<dyn AsyncStream>) -> F,
        F: Send + Future<Output = Result<()>>,
        State<S>: Send + Sync,
    {
        let (tx, mut rx) = mpsc::channel(100);
        let _result = ENDPOINTS.insert(server_url.to_owned(), tx);
        while let Some(stream) = rx.recv().await {
            handler(Arc::clone(&state), Box::new(stream)).await?;
        }
        Ok(())
    }

    /// Helper function to call inside `listen_async` `handler` function to parse and send response.
    /// The `handler` specified here will need to generate `Response` from `Request`.
    /// See `listen_async` for the description of the `state`.
    pub async fn handle_message_async<H, F, S>(
        state: State<S>,
        mut stream: Box<dyn AsyncStream>,
        mut handler: H,
    ) -> Result<()>
    where
        H: Send + FnMut(State<S>, Request) -> F,
        F: Future<Output = Result<Response>> + Send,
        State<S>: Send + Sync,
    {
        let mut buffer = [0_u8; BUFFER_SIZE];
        let read_size = stream
            .read(&mut buffer)
            .await
            .expect("Request read failed.");
        let bytes: Vec<u8> = buffer[..read_size].to_vec();
        let request: Request = bytes.try_into()?;
        let response: Vec<u8> = handler(state, request).await?.into();
        stream.write_all(&response).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
#[non_exhaustive]
pub struct Request {
    pub uri_path: String,
    pub payload: Vec<u8>,
}

impl Request {
    /// Creates a new request
    ///
    /// # Arguments
    ///
    /// * `uri_path` - corresponds to [URI syntax](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
    /// `path` part (e.g. "/instructions")
    /// * `payload` - the message in bytes
    ///
    /// # Examples
    /// ```
    /// use iroha_network::prelude::*;
    ///
    /// let request = Request::new("/instructions".to_owned(), "some_message".to_owned().into_bytes());
    /// ```
    pub fn new(uri_path: impl Into<String>, payload: Vec<u8>) -> Request {
        let uri_path = uri_path.into();
        Request { uri_path, payload }
    }

    pub fn empty(uri_path: impl Into<String>) -> Request {
        Request::new(uri_path, Vec::new())
    }

    pub fn url(&self) -> &str {
        &self.uri_path[..]
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..]
    }
}

impl From<Request> for Vec<u8> {
    #[log]
    fn from(request: Request) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(request.uri_path.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend(request.payload.into_iter());
        bytes
    }
}

impl TryFrom<Vec<u8>> for Request {
    type Error = Error;

    #[log]
    fn try_from(mut bytes: Vec<u8>) -> Result<Request> {
        let n = bytes
            .iter()
            .position(|byte| *byte == b"\n"[0])
            .expect("Request should contain \\r\\n sequence.")
            + 1;
        let payload: Vec<u8> = bytes.drain(n..).collect();
        Ok(Request {
            uri_path: String::from_utf8(bytes[..(bytes.len() - 2)].to_vec())?,
            payload,
        })
    }
}

#[derive(Debug, PartialEq, Io, Encode, Decode)]
pub enum Response {
    Ok(Vec<u8>),
    InternalError,
}

impl Response {
    pub const fn empty_ok() -> Self {
        Response::Ok(Vec::new())
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `iroha_network`.

    #[doc(inline)]
    pub use crate::{AsyncStream, Network, Request, Response, State};
}
