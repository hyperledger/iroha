#[cfg(feature = "mock")]
pub mod mock;

use async_std::{
    net::{TcpListener, TcpStream},
    prelude::*,
    sync::RwLock,
};
use iroha_derive::{log, Io};
use iroha_error::{error, Result};
use parity_scale_codec::{Decode, Encode};
use std::{
    convert::{TryFrom, TryInto},
    future::Future,
    io::{prelude::*, ErrorKind},
    net::TcpStream as SyncTcpStream,
    sync::Arc,
    time::Duration,
};

const BUFFER_SIZE: usize = 4096;
const REQUEST_TIMEOUT_MILLIS: u64 = 500;

pub type State<T> = Arc<RwLock<T>>;
pub trait AsyncStream: async_std::io::Read + async_std::io::Write + Send + Unpin {}
impl<T> AsyncStream for T where T: async_std::io::Read + async_std::io::Write + Send + Unpin {}

#[derive(Debug)]
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
            server_url: server_url.to_string(),
        }
    }

    /// Establishes connection to server on `self.server_url`, sends `request` closes connection and returns `Response`.
    pub async fn send_request(&self, request: Request) -> Result<Response> {
        Network::send_request_to(&self.server_url, request).await
    }

    /// Establishes connection to server on `server_url`, sends `request` closes connection and returns `Response`.
    #[log("TRACE")]
    pub async fn send_request_to(server_url: &str, request: Request) -> Result<Response> {
        async_std::io::timeout(Duration::from_millis(REQUEST_TIMEOUT_MILLIS), async {
            let mut stream = TcpStream::connect(server_url).await?;
            let payload: Vec<u8> = request.into();
            stream.write_all(&payload).await?;
            stream.flush().await?;
            let mut buffer = vec![0u8; BUFFER_SIZE];
            let read_size = stream.read(&mut buffer).await?;
            Ok(Response::try_from(buffer[..read_size].to_vec()))
        })
        .await?
    }

    /// Listens on the specified `server_url`.
    /// When there is an incoming connection, it passes it's `AsyncStream` to `handler`.
    /// # Arguments
    ///
    /// * `server_url` - url of format ip:port (e.g. `127.0.0.1:7878`) on which this server will listen for incoming connections.
    /// * `handler` - callback function which is called when there is an incoming connection, it get's the stream for this connection
    /// * `state` - the state that you want to capture
    pub async fn listen<H, F, S>(state: State<S>, server_url: &str, mut handler: H) -> Result<()>
    where
        H: FnMut(State<S>, Box<dyn AsyncStream>) -> F,
        F: Future<Output = Result<()>>,
    {
        let listener = TcpListener::bind(server_url).await?;
        while let Some(stream) = listener.incoming().next().await {
            handler(Arc::clone(&state), Box::new(stream?)).await?;
        }
        Ok(())
    }

    /// Helper function to call inside `listen` `handler` function to parse and send response.
    /// The `handler` specified here will need to generate `Response` from `Request`.
    /// See `listen_async` for the description of the `state`.
    pub async fn handle_message_async<H, F, S>(
        state: State<S>,
        mut stream: Box<dyn AsyncStream>,
        mut handler: H,
    ) -> Result<()>
    where
        H: FnMut(State<S>, Request) -> F,
        F: Future<Output = Result<Response>>,
    {
        let mut buffer = [0u8; BUFFER_SIZE];
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

    pub async fn connect(&self, initial_message: &[u8]) -> Result<Connection> {
        Connection::connect(&self.server_url, REQUEST_TIMEOUT_MILLIS, initial_message)
    }
}

pub struct Connection {
    tcp_stream: SyncTcpStream,
}

/// `Receipt` should be used by [Consumers](https://github.com/cloudevents/spec/blob/v1.0/spec.md#consumer)
/// to notify [Source](https://github.com/cloudevents/spec/blob/v1.0/spec.md#source) about
/// [Message](https://github.com/cloudevents/spec/blob/v1.0/spec.md#message) consumption.
#[derive(Io, Encode, Decode, Debug)]
pub enum Receipt {
    Ok,
}

impl Connection {
    fn connect(address: &str, timeout_millis: u64, initial_message: &[u8]) -> Result<Self> {
        let mut tcp_stream: SyncTcpStream = SyncTcpStream::connect(address)?;
        tcp_stream
            .set_read_timeout(Some(Duration::from_millis(timeout_millis)))
            .expect("Set read timeout call failed.");
        tcp_stream
            .set_nonblocking(true)
            .expect("Failed to set stream to be nonblocking.");
        tcp_stream
            .write_all(initial_message)
            .expect("Failed to write initial message.");
        tcp_stream
            .flush()
            .expect("Failed to flush initial message.");
        Ok(Connection { tcp_stream })
    }
}

impl Iterator for Connection {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            match self.tcp_stream.read(&mut buffer) {
                Ok(read_size) => {
                    let bytes: Vec<u8> = buffer[..read_size].to_vec();
                    let receipt: Vec<u8> = Receipt::Ok.into();
                    if let Err(e) = self.tcp_stream.write_all(&receipt) {
                        eprintln!("Write receipt to stream failed: {}", e);
                        return None;
                    }
                    if let Err(e) = self.tcp_stream.flush() {
                        eprintln!("Flush stream with receipt failed: {}", e);
                        return None;
                    }
                    return Some(bytes);
                }
                Err(e) => {
                    if ErrorKind::WouldBlock == e.kind() {
                        continue;
                    } else {
                        eprintln!("Read data from stream failed: {}", e);
                        return None;
                    }
                }
            }
        }
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
    /// * uri_path - corresponds to [URI syntax](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
    /// `path` part (e.g. "/metrics")
    /// * payload - the message in bytes
    ///
    /// # Examples
    /// ```
    /// use iroha_network::prelude::*;
    ///
    /// let request = Request::new("/metrics".to_string(), "some_message".to_string().into_bytes());
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
    #[log("TRACE")]
    fn from(request: Request) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(request.uri_path.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend(request.payload.into_iter());
        bytes
    }
}

impl TryFrom<Vec<u8>> for Request {
    type Error = iroha_error::Error;

    #[log("TRACE")]
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
    pub fn empty_ok() -> Self {
        Response::Ok(Vec::new())
    }

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
    pub use crate::{AsyncStream, Connection, Network, Receipt, Request, Response, State};
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    use super::mock::*;
    #[cfg(not(feature = "mock"))]
    use super::*;
    use async_std::{sync::RwLock, task};
    use iroha_error::Result;
    use std::{convert::TryFrom, sync::Arc};

    fn get_empty_state() -> State<()> {
        Arc::new(RwLock::new(()))
    }

    #[test]
    fn request_correctly_built() {
        let request = Request {
            uri_path: "/instructions".to_string(),
            payload: b"some_instruction".to_vec(),
        };
        let bytes: Vec<u8> = request.into();
        assert_eq!(b"/instructions\r\nsome_instruction".to_vec(), bytes)
    }

    #[test]
    fn request_correctly_parsed() {
        let request = Request {
            uri_path: "/instructions".to_string(),
            payload: b"some_instruction".to_vec(),
        };
        assert_eq!(
            Request::try_from(b"/instructions\r\nsome_instruction".to_vec()).unwrap(),
            request
        )
    }

    #[async_std::test]
    async fn single_threaded_async() {
        async fn handle_request<S>(_state: State<S>, _request: Request) -> Result<Response> {
            Ok(Response::Ok(b"pong".to_vec()))
        }

        async fn handle_connection<S>(state: State<S>, stream: Box<dyn AsyncStream>) -> Result<()> {
            Network::handle_message_async(state, stream, handle_request).await
        }

        task::spawn(async move {
            Network::listen(get_empty_state(), "127.0.0.1:7878", handle_connection).await
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        match Network::send_request_to("127.0.0.1:7878", Request::new("/ping".to_string(), vec![]))
            .await
            .expect("Failed to send request to.")
        {
            Response::Ok(payload) => assert_eq!(payload, b"pong"),
            _ => panic!("Response should be ok."),
        }
    }

    #[async_std::test]
    async fn single_threaded_async_stateful() {
        let counter: State<usize> = Arc::new(RwLock::new(0));

        async fn handle_request(state: State<usize>, _request: Request) -> Result<Response> {
            let mut data = state.write().await;
            *data += 1;
            Ok(Response::Ok(b"pong".to_vec()))
        }
        async fn handle_connection(
            state: State<usize>,
            stream: Box<dyn AsyncStream>,
        ) -> Result<()> {
            Network::handle_message_async(state, stream, handle_request).await
        }
        let counter_move = counter.clone();
        task::spawn(async move {
            Network::listen(counter_move, "127.0.0.1:7870", handle_connection).await
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        match Network::send_request_to("127.0.0.1:7870", Request::new("/ping".to_string(), vec![]))
            .await
            .expect("Failed to send request to.")
        {
            Response::Ok(payload) => assert_eq!(payload, b"pong"),
            _ => panic!("Response should be ok."),
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        task::spawn(async move {
            let data = counter.write().await;
            assert_eq!(*data, 1)
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
