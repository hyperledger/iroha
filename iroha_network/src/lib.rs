#[cfg(feature = "mock")]
pub mod mock;

use async_std::{
    net::{TcpListener, TcpStream},
    prelude::*,
    sync::RwLock,
};
use iroha_derive::{log, Io};
use parity_scale_codec::{Decode, Encode};
use std::{
    convert::{TryFrom, TryInto},
    error::Error,
    future::Future,
    sync::Arc,
};

const BUFFER_SIZE: usize = 2048;

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
    pub async fn send_request(&self, request: Request) -> Result<Response, String> {
        Network::send_request_to(&self.server_url, request).await
    }

    /// Establishes connection to server on `server_url`, sends `request` closes connection and returns `Response`.
    #[log]
    pub async fn send_request_to(server_url: &str, request: Request) -> Result<Response, String> {
        let mut stream = TcpStream::connect(server_url)
            .await
            .map_err(|e| e.to_string())?;
        let payload: Vec<u8> = request.into();
        stream
            .write_all(&payload)
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let read_size = stream.read(&mut buffer).await.map_err(|e| e.to_string())?;
        Ok(Response::try_from(buffer[..read_size].to_vec())?)
    }

    /// Listens on the specified `server_url`.
    /// When there is an incoming connection, it passes it's `AsyncStream` to `handler`.
    /// # Arguments
    ///
    /// * `server_url` - url of format ip:port (e.g. `127.0.0.1:7878`) on which this server will listen for incoming connections.
    /// * `handler` - callback function which is called when there is an incoming connection, it get's the stream for this connection
    /// * `state` - the state that you want to capture
    pub async fn listen<H, F, S>(
        state: State<S>,
        server_url: &str,
        mut handler: H,
    ) -> Result<(), String>
    where
        H: FnMut(State<S>, Box<dyn AsyncStream>) -> F,
        F: Future<Output = Result<(), String>>,
    {
        let listener = TcpListener::bind(server_url)
            .await
            .map_err(|e| e.to_string())?;
        while let Some(stream) = listener.incoming().next().await {
            handler(
                Arc::clone(&state),
                Box::new(stream.map_err(|e| e.to_string())?),
            )
            .await?;
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
    ) -> Result<(), String>
    where
        H: FnMut(State<S>, Request) -> F,
        F: Future<Output = Result<Response, String>>,
    {
        let mut buffer = [0u8; BUFFER_SIZE];
        let read_size = stream
            .read(&mut buffer)
            .await
            .expect("Request read failed.");
        let bytes: Vec<u8> = buffer[..read_size].to_vec();
        let request: Request = bytes
            .try_into()
            .map_err(|e: Box<dyn Error>| e.to_string())?;
        let response: Vec<u8> = handler(state, request).await?.into();
        stream
            .write_all(&response)
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
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
    /// * uri_path - corresponds to [URI syntax](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
    /// `path` part (e.g. "/commands")
    /// * payload - the message in bytes
    ///
    /// # Examples
    /// ```
    /// use iroha_network::prelude::*;
    ///
    /// let request = Request::new("/commands".to_string(), "some_message".to_string().into_bytes());
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
    type Error = Box<dyn Error>;

    #[log]
    fn try_from(mut bytes: Vec<u8>) -> Result<Request, Box<dyn Error>> {
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
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `iroha_network`.

    #[doc(inline)]
    pub use crate::{AsyncStream, Network, Request, Response, State};
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    use super::mock::*;
    #[cfg(not(feature = "mock"))]
    use super::*;
    use async_std::{sync::RwLock, task};
    use std::{convert::TryFrom, sync::Arc};

    fn get_empty_state() -> State<()> {
        Arc::new(RwLock::new(()))
    }

    #[test]
    fn request_correctly_built() {
        let request = Request {
            uri_path: "/commands".to_string(),
            payload: b"some_command".to_vec(),
        };
        let bytes: Vec<u8> = request.into();
        assert_eq!(b"/commands\r\nsome_command".to_vec(), bytes)
    }

    #[test]
    fn request_correctly_parsed() {
        let request = Request {
            uri_path: "/commands".to_string(),
            payload: b"some_command".to_vec(),
        };
        assert_eq!(
            Request::try_from(b"/commands\r\nsome_command".to_vec()).unwrap(),
            request
        )
    }

    #[async_std::test]
    async fn single_threaded_async() {
        async fn handle_request<S>(
            _state: State<S>,
            _request: Request,
        ) -> Result<Response, String> {
            Ok(Response::Ok("pong".as_bytes().to_vec()))
        };

        async fn handle_connection<S>(
            state: State<S>,
            stream: Box<dyn AsyncStream>,
        ) -> Result<(), String> {
            Network::handle_message_async(state, stream, handle_request).await
        };

        task::spawn(async move {
            Network::listen(get_empty_state(), "127.0.0.1:7878", handle_connection).await
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        match Network::send_request_to("127.0.0.1:7878", Request::new("/ping".to_string(), vec![]))
            .await
            .expect("Failed to send request to.")
        {
            Response::Ok(payload) => assert_eq!(payload, "pong".as_bytes()),
            _ => panic!("Response should be ok."),
        }
    }

    #[async_std::test]
    async fn single_threaded_async_stateful() {
        let counter: State<usize> = Arc::new(RwLock::new(0));

        async fn handle_request(
            state: State<usize>,
            _request: Request,
        ) -> Result<Response, String> {
            let mut data = state.write().await;
            *data += 1;
            Ok(Response::Ok("pong".as_bytes().to_vec()))
        };
        async fn handle_connection(
            state: State<usize>,
            stream: Box<dyn AsyncStream>,
        ) -> Result<(), String> {
            Network::handle_message_async(state, stream, handle_request).await
        };
        let counter_move = counter.clone();
        task::spawn(async move {
            Network::listen(counter_move, "127.0.0.1:7870", handle_connection).await
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        match Network::send_request_to("127.0.0.1:7870", Request::new("/ping".to_string(), vec![]))
            .await
            .expect("Failed to send request to.")
        {
            Response::Ok(payload) => assert_eq!(payload, "pong".as_bytes()),
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
