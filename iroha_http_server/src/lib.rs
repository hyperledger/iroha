//! HTTP/1.1 server library with WebSocket support heavily inspired by [tide](https://crates.io/crates/tide).
//TODO: do we need TLS/SSL?
use async_std::{
    net::{TcpListener, TcpStream},
    prelude::*,
    task,
};
use http::{HttpEndpoint, HttpHandler, HttpRequest, HttpResponse};
use route_recognizer::Router;
use std::{borrow::Borrow, convert::TryFrom, sync::Arc};
use web_socket::WebSocketHandler;

const BUFFER_SIZE: usize = 4096;

pub struct Server<State> {
    state: State,
    router: Arc<Router<Endpoint<State>>>,
}

impl<State: Clone + Send + Sync + 'static> Server<State> {
    pub fn new(state: State) -> Self {
        Server {
            state,
            router: Arc::new(Router::new()),
        }
    }

    pub fn at<'s>(&'s mut self, path: &str) -> RouteBuilder<'s, State> {
        RouteBuilder {
            path: path.to_string(),
            server: self,
        }
    }

    pub async fn start(&self, address: &str) -> Result<(), String> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|e| e.to_string())?;
        while let Some(stream) = listener.incoming().next().await {
            let mut stream = stream.map_err(|e| e.to_string())?;
            let router = self.router.clone();
            let state = self.state.clone();
            task::spawn(async move {
                let mut buffer = [0u8; BUFFER_SIZE];
                let read_size = stream
                    .peek(&mut buffer)
                    .await
                    .expect("Request read failed.");
                let response = match HttpRequest::try_from(&buffer[..]) {
                    Ok(request) => {
                        let response = request
                            .process(state, router.as_ref(), stream.clone())
                            .await;
                        if response.is_some() {
                            // Consume peeked data.
                            consume_bytes(&mut stream, read_size as u64).await;
                        }
                        response
                    }
                    Err(err) => {
                        log::error!("Failed to parse incoming HTTP request: {}", err);
                        //TODO: return `not supported` for the features that are not supported instead of bad request.
                        Some(HttpResponse::bad_request())
                    }
                };
                if let Some(response) = response {
                    let bytes: Vec<u8> = response.borrow().into();
                    if let Err(err) = stream.write_all(&bytes).await {
                        log::error!("Failed to write back HTTP response: {}", err);
                    }
                }
            });
        }
        Ok(())
    }
}

pub enum Endpoint<State> {
    WebSocket(Box<dyn WebSocketHandler<State>>),
    Http(HttpEndpoint<State>),
}

pub mod http {
    use super::{web_socket::WEB_SOCKET_UPGRADE, Endpoint};
    use async_std::{net::TcpStream, prelude::*};
    use async_trait::async_trait;
    use httparse::{Request as HttpParseRequest, Status};
    use route_recognizer::Router;
    use std::{
        collections::BTreeMap,
        convert::{TryFrom, TryInto},
        fmt::Display,
    };
    use url::form_urlencoded;

    pub const GET_METHOD: &str = "GET";
    pub const POST_METHOD: &str = "POST";
    pub const ALLOW_HEADER: &str = "Allow";
    pub const UPGRADE_HEADER: &str = "Upgrade";
    pub const CONTENT_LENGTH_HEADER: &str = "Content-Length";
    pub const HTTP_CODE_OK: u16 = 200;
    pub const HTTP_CODE_INTERNAL_SERVER_ERROR: u16 = 500;
    pub const HTTP_CODE_NOT_FOUND: u16 = 404;
    pub const HTTP_CODE_BAD_REQUEST: u16 = 400;
    pub const HTTP_CODE_METHOD_NOT_ALLOWED: u16 = 405;
    pub const HTTP_CODE_UPGRADE_REQUIRED: u16 = 426;
    pub const HTTP_VERSION_1_1: &str = "HTTP/1.1";
    const MAX_HEADERS: usize = 128;

    pub type Headers = BTreeMap<HeaderName, HeaderValue>;

    pub type HeaderName = String;

    pub type HeaderValue = Vec<u8>;

    pub type PathParams = BTreeMap<String, String>;

    pub type QueryParams = BTreeMap<String, String>;

    type HttpParseHttpVersion = u8;

    pub enum HttpEndpoint<State> {
        Get(Box<dyn HttpHandler<State>>),
        Post(Box<dyn HttpHandler<State>>),
        //TODO: add other endpoints PUT, PATCH, DELETE and etc.
    }

    /// Handler for HTT connection. Gets a web socket stream after initial HTTP handshake.
    #[async_trait]
    pub trait HttpHandler<State: Clone + Send + Sync + 'static>: Send + Sync + 'static {
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            request: HttpRequest,
        ) -> Result<HttpResponse, String>;
    }

    #[async_trait]
    impl<State, F, Fut> HttpHandler<State> for F
    where
        State: Clone + Send + Sync + 'static,
        F: Send + Sync + 'static + Fn(State, PathParams, QueryParams, HttpRequest) -> Fut,
        Fut: Future<Output = Result<HttpResponse, String>> + Send + 'static,
    {
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            request: HttpRequest,
        ) -> Result<HttpResponse, String> {
            let future = (self)(state, path_params, query_params, request);
            future.await
        }
    }

    /// The version of HTTP protocol used in the corresponding request or response.
    #[derive(Debug, Clone, PartialEq)]
    pub enum HttpVersion {
        /// HTTP/1.1.
        Http1_1,
    }

    impl Display for HttpVersion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                HttpVersion::Http1_1 => write!(f, "{}", HTTP_VERSION_1_1),
            }
        }
    }

    impl TryFrom<HttpParseHttpVersion> for HttpVersion {
        type Error = String;

        fn try_from(version: HttpParseHttpVersion) -> Result<Self, Self::Error> {
            if version == 1 {
                Ok(HttpVersion::Http1_1)
            } else {
                Err("Http version not supported.".to_string())
            }
        }
    }

    /// The HTTP request.
    #[derive(Debug, Clone, PartialEq)]
    pub struct HttpRequest {
        /// The request method, such as `GET`.
        pub method: String,
        /// The request path, such as `/about-us`.
        pub path: String,
        /// The request version, such as `HTTP/1.1`.
        pub version: HttpVersion,
        /// The request headers. Keys will be all lowercase for parsing simplicity.
        pub headers: Headers,
        /// The request body in binary form.
        pub body: Vec<u8>,
    }

    impl HttpRequest {
        pub async fn process<State>(
            self,
            state: State,
            router: &Router<Endpoint<State>>,
            stream: TcpStream,
        ) -> Option<HttpResponse>
        where
            State: Clone + Send + Sync + 'static,
        {
            let (path, query_params) = strip_query_params(self.path.as_ref());
            if let Ok(route_match) = router.recognize(path) {
                let endpoint = route_match.handler;
                let path_params: PathParams = route_match
                    .params
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect();
                if let Some(WEB_SOCKET_UPGRADE) = self
                    .headers
                    .get(&UPGRADE_HEADER.to_lowercase())
                    .map(|bytes| bytes.as_slice())
                {
                    if let Endpoint::WebSocket(handler) = endpoint {
                        match async_tungstenite::accept_async(stream.clone()).await {
                            Ok(stream) => {
                                if let Err(err) =
                                    handler.call(state, path_params, query_params, stream).await
                                {
                                    log::error!("Failed to handle web socket stream: {}", err)
                                }
                                None
                            }
                            Err(err) => {
                                log::error!(
                                    "Failed to handle web socket request {:?} with error: {}",
                                    self,
                                    err
                                );
                                Some(HttpResponse::internal_server_error())
                            }
                        }
                    } else {
                        Some(HttpResponse::upgrade_required(WEB_SOCKET_UPGRADE))
                    }
                } else {
                    match self.method.as_ref() {
                        GET_METHOD => {
                            if let Endpoint::Http(HttpEndpoint::Get(handler)) = endpoint {
                                match handler
                                    .call(state, path_params, query_params, self.clone())
                                    .await
                                {
                                    Ok(response) => Some(response),
                                    Err(err) => {
                                        log::error!(
                                            "Failed to handle get request {:?} with error: {}",
                                            self,
                                            err
                                        );
                                        Some(HttpResponse::internal_server_error())
                                    }
                                }
                            } else {
                                Some(HttpResponse::method_not_allowed(&[GET_METHOD]))
                            }
                        }
                        POST_METHOD => {
                            if let Endpoint::Http(HttpEndpoint::Post(handler)) = endpoint {
                                match handler
                                    .call(state, path_params, query_params, self.clone())
                                    .await
                                {
                                    Ok(response) => Some(response),
                                    Err(err) => {
                                        log::error!(
                                            "Failed to handle post request {:?} with error: {}",
                                            self,
                                            err
                                        );
                                        Some(HttpResponse::internal_server_error())
                                    }
                                }
                            } else {
                                Some(HttpResponse::method_not_allowed(&[POST_METHOD]))
                            }
                        }
                        _ => Some(HttpResponse::method_not_allowed(&[GET_METHOD, POST_METHOD])),
                    }
                }
            } else {
                Some(HttpResponse::not_found())
            }
        }
    }

    impl<'h, 'b> TryFrom<HttpParseRequest<'h, 'b>> for HttpRequest {
        type Error = String;

        fn try_from(request: HttpParseRequest<'h, 'b>) -> Result<Self, Self::Error> {
            Ok(HttpRequest {
                method: request.method.ok_or("Method not found.")?.to_string(),
                path: request.path.ok_or("Path not found.")?.to_string(),
                version: request.version.ok_or("Version not found.")?.try_into()?,
                headers: request
                    .headers
                    .iter()
                    .map(|header| (header.name.to_lowercase(), header.value.to_vec()))
                    .collect(),
                body: Vec::new(),
            })
        }
    }

    impl TryFrom<&[u8]> for HttpRequest {
        type Error = String;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut request = httparse::Request::new(&mut headers);
            if let Status::Complete(header_size) =
                request.parse(&bytes).map_err(|err| err.to_string())?
            {
                let mut request: HttpRequest = request.try_into()?;
                //TODO: Deal with chunked messages which do not have Content-Length header
                //They instead have Transfer-Encoding: `Chunked` https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
                if let Some(content_length) =
                    request.headers.get(&CONTENT_LENGTH_HEADER.to_lowercase())
                {
                    let content_length: usize = String::from_utf8(content_length.clone())
                        .map_err(|_| "Failed to parse content length value - invalid utf-8.")?
                        .parse()
                        .map_err(|_| "Failed to parse content length value - not a number.")?;
                    request.body = bytes[header_size..(header_size + content_length)].to_vec();
                }
                Ok(request)
            } else {
                Err("Failed to read header.".to_string())
            }
        }
    }

    //TODO: Add more response builders.
    /// The HTTP response.
    #[derive(Debug, Clone, PartialEq)]
    pub struct HttpResponse {
        /// The response version, such as `HTTP/1.1`.
        pub version: HttpVersion,
        /// The response code, such as `200`.
        pub code: u16,
        /// The response reason-phrase, such as `OK`.
        pub reason: String,
        /// The response headers.
        pub headers: Headers,
        /// The response body.
        pub body: Vec<u8>,
    }

    impl HttpResponse {
        pub fn internal_server_error() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_INTERNAL_SERVER_ERROR,
                reason: "Internal server error".to_string(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        pub fn not_found() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_NOT_FOUND,
                reason: "Not found".to_string(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        pub fn bad_request() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_BAD_REQUEST,
                reason: "Bad request".to_string(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        pub fn method_not_allowed(allowed_methods: &[&str]) -> HttpResponse {
            let mut headers = Headers::new();
            headers.insert(
                ALLOW_HEADER.to_string(),
                allowed_methods.join(", ").as_bytes().to_vec(),
            );
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_METHOD_NOT_ALLOWED,
                reason: "Method not allowed".to_string(),
                headers,
                body: Vec::new(),
            }
        }

        pub fn upgrade_required(upgrade: &[u8]) -> HttpResponse {
            let mut headers = Headers::new();
            headers.insert(UPGRADE_HEADER.to_string(), upgrade.to_vec());
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_UPGRADE_REQUIRED,
                reason: "Upgrade required".to_string(),
                headers,
                body: Vec::new(),
            }
        }

        pub fn ok(mut headers: Headers, body: Vec<u8>) -> HttpResponse {
            headers.insert(
                CONTENT_LENGTH_HEADER.to_string(),
                format!("{}", body.len()).as_bytes().to_vec(),
            );
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_OK,
                reason: "OK".to_string(),
                headers,
                body,
            }
        }
    }

    impl From<&HttpResponse> for Vec<u8> {
        fn from(response: &HttpResponse) -> Self {
            let mut bytes = Vec::new();
            let status_line = format!(
                "{version} {status} {reason}\r\n",
                version = response.version,
                status = response.code,
                reason = response.reason
            );
            bytes.extend_from_slice(status_line.as_bytes());
            for (name, value) in response.headers.clone() {
                bytes.extend_from_slice(format!("{}: ", name).as_bytes());
                bytes.extend_from_slice(&value);
                bytes.extend_from_slice(b"\r\n");
            }
            bytes.extend_from_slice(b"\r\n");
            bytes.extend_from_slice(&response.body);
            bytes
        }
    }

    fn strip_query_params(path: &str) -> (&str, QueryParams) {
        if let Some(query_start) = path.find('?') {
            let (path, query) = path.split_at(query_start);
            let query_params: QueryParams = form_urlencoded::parse(query[1..].as_bytes())
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            (path, query_params)
        } else {
            (path, QueryParams::new())
        }
    }
}

pub mod web_socket {
    use super::http::{PathParams, QueryParams};
    use async_std::{net::TcpStream, prelude::*};
    use async_trait::async_trait;
    pub use async_tungstenite::tungstenite::Message as WebSocketMessage;
    use async_tungstenite::WebSocketStream as TungsteniteWebSocketStream;
    pub type WebSocketStream = TungsteniteWebSocketStream<TcpStream>;

    pub const WEB_SOCKET_UPGRADE: &[u8] = b"websocket";

    /// Handler for web socket connection. Gets a web socket stream after initial HTTP handshake.
    #[async_trait]
    pub trait WebSocketHandler<State: Clone + Send + Sync + 'static>:
        Send + Sync + 'static
    {
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            stream: WebSocketStream,
        ) -> Result<(), String>;
    }

    #[async_trait]
    impl<State, F, Fut> WebSocketHandler<State> for F
    where
        State: Clone + Send + Sync + 'static,
        F: Send + Sync + 'static + Fn(State, PathParams, QueryParams, WebSocketStream) -> Fut,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            stream: WebSocketStream,
        ) -> Result<(), String> {
            let future = (self)(state, path_params, query_params, stream);
            future.await
        }
    }
}

/// Builder for server route handlers.
pub struct RouteBuilder<'s, State> {
    path: String,
    server: &'s mut Server<State>,
}

impl<'s, State> RouteBuilder<'s, State>
where
    State: Clone + Send + Sync + 'static,
{
    /// Add GET handler at the specified url.
    pub fn get(&mut self, handler: impl HttpHandler<State>) {
        Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.")
            .add(
                &self.path,
                Endpoint::Http(HttpEndpoint::Get(Box::new(handler))),
            );
    }

    /// Add POST handler at the specified url.
    pub fn post(&mut self, handler: impl HttpHandler<State>) {
        Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.")
            .add(
                &self.path,
                Endpoint::Http(HttpEndpoint::Post(Box::new(handler))),
            );
    }

    /// Add Web Socket handler at the specified url. It performs a standard HTTP Web Socket Upgrade handshake in the beginning.
    pub fn web_socket(&mut self, handler: impl WebSocketHandler<State>) {
        Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.")
            .add(&self.path, Endpoint::WebSocket(Box::new(handler)));
    }
}

async fn consume_bytes(stream: &mut TcpStream, length: u64) {
    let mut buffer = Vec::new();
    stream
        .take(length)
        .read_to_end(&mut buffer)
        .await
        .expect("Failed to consume data.");
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `iroha_http_server`.

    #[doc(inline)]
    pub use crate::{
        http::{Headers, HttpRequest, HttpResponse, HttpVersion, PathParams, QueryParams},
        web_socket::{WebSocketMessage, WebSocketStream},
    };
}

#[cfg(test)]
mod tests {
    use super::{prelude::*, Server};
    use async_std::sync::RwLock;
    use futures::{SinkExt, StreamExt};
    use isahc::AsyncReadResponseExt;
    use std::sync::Arc;
    use std::{thread, time::Duration};
    use tungstenite::client as web_socket_client;

    #[test]
    fn get_request() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        async_std::task::spawn(async move {
            let mut server = Server::new(());
            server.at("/").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 request: HttpRequest| async move {
                    assert_eq!(&request.body, b"Hello, world!");
                    Ok(HttpResponse::ok(Headers::new(), b"Hi!".to_vec()))
                },
            );
            let _result = server.start(format!("localhost:{}", port).as_ref()).await;
        });
        thread::sleep(Duration::from_millis(100));
        let response = attohttpc::get(format!("http://localhost:{}", port))
            .text("Hello, world!")
            .send()
            .expect("Failed to send request.");
        assert!(response.is_success());
        assert_eq!(response.text().expect("Failed to get text"), "Hi!")
    }

    #[async_std::test]
    async fn get_request_isahc() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        async_std::task::spawn(async move {
            let mut server = Server::new(());
            server.at("/hello/world").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    Ok(HttpResponse::ok(Headers::new(), b"Hi!".to_vec()))
                },
            );
            let _result = server.start(format!("localhost:{}", port).as_ref()).await;
        });
        thread::sleep(Duration::from_millis(100));
        let mut response = isahc::get_async(format!("http://localhost:{}/hello/world", port))
            .await
            .expect("Failed to send request.");
        assert!(response.status().is_success());
        assert_eq!(response.text().await.expect("Failed to get text"), "Hi!")
    }

    #[test]
    fn multiple_routes() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        async_std::task::spawn(async move {
            let mut server = Server::new(());
            server.at("/a").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move { panic!("Wrong path.") },
            );
            server.at("/*/b").post(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    Ok(HttpResponse::ok(Headers::new(), b"Right path".to_vec()))
                },
            );
            server.at("/c/b").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move { panic!("Wrong path.") },
            );
            let _result = server.start(format!("localhost:{}", port).as_ref()).await;
        });
        thread::sleep(Duration::from_millis(100));
        let response = attohttpc::post(format!("http://localhost:{}/a/b", port))
            .text("Hello, world!")
            .send()
            .expect("Failed to send request.");
        assert!(response.is_success());
        assert_eq!(response.text().expect("Failed to get text"), "Right path")
    }

    #[test]
    fn path_params() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        async_std::task::spawn(async move {
            let mut server = Server::new(());
            server.at("/:a/path/:c").get(
                |_state: (),
                 path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    assert_eq!(path_params["a"], "hello");
                    assert_eq!(path_params["c"], "params");
                    Ok(HttpResponse::ok(Headers::new(), b"Hi!".to_vec()))
                },
            );
            let _result = server.start(format!("localhost:{}", port).as_ref()).await;
        });
        thread::sleep(Duration::from_millis(100));
        let response = attohttpc::get(format!("http://localhost:{}/hello/path/params", port))
            .text("Hello, world!")
            .send()
            .expect("Failed to send request.");
        assert!(response.is_success());
        assert_eq!(response.text().expect("Failed to get text"), "Hi!")
    }

    #[test]
    fn query_params() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        async_std::task::spawn(async move {
            let mut server = Server::new(());
            server.at("/").get(
                |_state: (),
                 _path_params: PathParams,
                 query_params: QueryParams,
                 _request: HttpRequest| async move {
                    assert_eq!(query_params.len(), 2);
                    assert_eq!(query_params["a"], "hello");
                    assert_eq!(query_params["c"], "params");
                    Ok(HttpResponse::ok(Headers::new(), b"Hi!".to_vec()))
                },
            );
            let _result = server.start(format!("localhost:{}", port).as_ref()).await;
        });
        thread::sleep(Duration::from_millis(100));
        let response = attohttpc::get(format!("http://localhost:{}?a=hello&c=params", port))
            .text("Hello, world!")
            .send()
            .expect("Failed to send request.");
        assert!(response.is_success());
        assert_eq!(response.text().expect("Failed to get text"), "Hi!")
    }

    #[test]
    fn stateful_server() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        async_std::task::spawn(async move {
            let state = Arc::new(RwLock::new(0));
            let mut server = Server::new(state);
            server.at("/add/:num").get(
                |state: Arc<RwLock<i32>>,
                 path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    let number: i32 = path_params["num"].parse().expect("Failed to parse i32");
                    *state.write().await += number;
                    Ok(HttpResponse::ok(Headers::new(), Vec::new()))
                },
            );
            server.at("/value").get(
                |state: Arc<RwLock<i32>>,
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    Ok(HttpResponse::ok(
                        Headers::new(),
                        format!("{}", state.read().await).as_bytes().to_vec(),
                    ))
                },
            );
            let _result = server.start(format!("localhost:{}", port).as_ref()).await;
        });
        thread::sleep(Duration::from_millis(100));
        let response = attohttpc::get(format!("http://localhost:{}/add/3", port))
            .send()
            .expect("Failed to send request.");
        assert!(response.is_success());
        let response = attohttpc::get(format!("http://localhost:{}/add/4", port))
            .send()
            .expect("Failed to send request.");
        assert!(response.is_success());
        let response = attohttpc::get(format!("http://localhost:{}/value", port))
            .send()
            .expect("Failed to send request.");
        assert!(response.is_success());
        assert_eq!(response.text().expect("Failed to get text"), "7")
    }

    #[test]
    fn web_socket() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        async_std::task::spawn(async move {
            let mut server = Server::new(());
            server.at("/").web_socket(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 mut stream: WebSocketStream| async move {
                    if let WebSocketMessage::Text(text) = stream
                        .next()
                        .await
                        .expect("Failed to read message.")
                        .expect("Received web socket error message.")
                    {
                        stream
                            .send(WebSocketMessage::Text(format!("Received: {}", text)))
                            .await
                            .expect("Failed to send response");
                    } else {
                        panic!("Unexpected message.")
                    }
                    Ok(())
                },
            );
            let _result = server.start(format!("localhost:{}", port).as_ref()).await;
        });
        thread::sleep(Duration::from_millis(100));
        let (mut stream, _) = web_socket_client::connect(format!("ws://localhost:{}", port))
            .expect("Failed to connect.");
        stream
            .write_message(WebSocketMessage::Text("Hi!".to_string()))
            .expect("Failed to write message");
        assert_eq!(
            stream.read_message().expect("Failed to receive message."),
            WebSocketMessage::Text("Received: Hi!".to_string())
        );
    }
}
