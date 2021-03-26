#![allow(clippy::missing_errors_doc, unsafe_code, missing_docs)]

use async_std::{
    channel::{self, Sender},
    io::{Read, Write},
    prelude::*,
    sync::{Arc, RwLock},
    task,
};
use iroha_derive::{log, Io};
use iroha_error::{Error, Result};
use parity_scale_codec::{Decode, Encode};
use std::{
    convert::{TryFrom, TryInto},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

const BUFFER_SIZE: usize = 2048;
static mut ENDPOINTS: Vec<(String, Sender<RequestStream>)> = Vec::new();

fn find_sender(server_url: &str) -> Sender<RequestStream> {
    for tuple in unsafe { &ENDPOINTS } {
        if tuple.0 == server_url {
            return tuple.1.clone();
        }
    }
    panic!("Can't find ENDPOINT: {}", server_url);
}

/// alias of `Arc<RwLock<T>`
pub type State<T> = Arc<RwLock<T>>;

/// Alias for read write
pub trait AsyncStream: Read + Write + Send + Unpin {}

impl<T> AsyncStream for T where T: Read + Write + Send + Unpin {}

struct RequestStream {
    bytes: Vec<u8>,
    tx: Sender<Vec<u8>>,
}

impl Unpin for RequestStream {}

impl Read for RequestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<async_std::io::Result<usize>> {
        let bytes = &mut self.get_mut().bytes;
        let length = if buf.len() > bytes.len() {
            bytes.len()
        } else {
            buf.len()
        };
        for (i, byte) in bytes.drain(..length).enumerate() {
            buf[i] = byte;
        }
        Poll::Ready(Ok(length))
    }
}

impl Write for RequestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<async_std::io::Result<usize>> {
        let bytes = &mut self.get_mut().bytes;
        for byte in buf.to_vec() {
            bytes.push(byte);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<async_std::io::Result<()>> {
        let res = task::block_on(self.tx.send(self.bytes.clone()))
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err));
        Poll::Ready(res)
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<async_std::io::Result<()>> {
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
            server_url: server_url.to_string(),
        }
    }

    pub async fn send_request(&self, request: Request) -> Result<Response> {
        Network::send_request_to(&self.server_url, request).await
    }

    #[log]
    pub async fn send_request_to(server_url: &str, request: Request) -> Result<Response> {
        let (tx, rx) = channel::bounded(100);
        let mut stream = RequestStream {
            bytes: Vec::new(),
            tx,
        };
        let payload: Vec<u8> = request.into();
        stream.write_all(&payload).await?;
        find_sender(server_url).send(stream).await?;
        //TODO: return actual response
        Ok(Response::try_from(rx.recv().await.unwrap())?)
    }

    /// Listens on the specified `server_url`.
    /// When there is an incoming connection, it passes it's `AsyncStream` to `handler`.
    /// # Arguments
    ///
    /// * `server_url` - url of format ip:port (e.g. `127.0.0.1:7878`) on which this server will listen for incoming connections.
    /// * `handler` - callback function which is called when there is an incoming connection, it get's the stream for this connection
    /// * `state` - the state that you want to capture
    #[allow(clippy::future_not_send)]
    pub async fn listen<H, F, S>(state: State<S>, server_url: &str, mut handler: H) -> Result<()>
    where
        H: FnMut(State<S>, Box<dyn AsyncStream>) -> F,
        F: Future<Output = Result<()>>,
    {
        let (tx, rx) = channel::bounded(100);
        unsafe {
            ENDPOINTS.push((server_url.to_string(), tx));
        }
        while let Ok(stream) = rx.recv().await {
            handler(Arc::clone(&state), Box::new(stream)).await?;
        }
        Ok(())
    }

    /// Helper function to call inside `listen_async` `handler` function to parse and send response.
    /// The `handler` specified here will need to generate `Response` from `Request`.
    /// See `listen_async` for the description of the `state`.
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
    /// let request = Request::new("/instructions".to_string(), "some_message".to_string().into_bytes());
    /// ```
    pub fn new(uri_path: String, payload: Vec<u8>) -> Request {
        Request { uri_path, payload }
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
