//! HTTP/1.1 server library with WebSocket support heavily inspired by [tide](https://crates.io/crates/tide).

#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]

//TODO: do we need TLS/SSL?
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use async_std::{
    net::{TcpListener, TcpStream},
    prelude::*,
    task,
};
use futures::FutureExt;
use http::{HttpEndpoint, HttpRequest, HttpResponse, HttpResponseError, PathParams, QueryParams};
use route_recognizer::Router;
use web_socket::WebSocketHandler;

const BUFFER_SIZE: usize = 2_usize.pow(18);

/// Http and websocket server
#[allow(missing_debug_implementations)]
pub struct Server<State> {
    state: State,
    router: Arc<Router<Endpoint<State>>>,
}

impl<State: Clone + Send + Sync + 'static> Server<State> {
    /// Constructor for server
    pub fn new(state: State) -> Self {
        Server {
            state,
            router: Arc::new(Router::new()),
        }
    }

    /// Will make routebuilder for specific path
    pub fn at<'s>(&'s mut self, path: &str) -> RouteBuilder<'s, State> {
        RouteBuilder {
            path: path.to_string(),
            server: self,
        }
    }

    /// Handles http/websocket connection
    async fn start_handle(
        state: State,
        mut stream: TcpStream,
        router: Arc<Router<Endpoint<State>>>,
    ) {
        let mut buffer = vec![0; BUFFER_SIZE];
        let read_size = stream
            .peek(&mut buffer)
            .await
            .expect("Request read failed.");

        let response = match HttpRequest::try_from(&buffer[..read_size]) {
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
                log::error!("Failed to parse incoming HTTP request: {:?}", err);
                //TODO: return `not supported` for the features that are not supported instead of bad request.
                Some(HttpResponse::bad_request())
            }
        };
        if let Some(response) = response {
            if let Err(err) = stream.write_all(&Vec::from(&response)).await {
                log::error!("Failed to write back HTTP response: {}", err);
            }
        }
    }
    /// Starts server at `address`
    ///
    /// # Errors
    /// Fails if accepting one of client fails
    pub async fn start(&self, address: &str) -> iroha_error::Result<()> {
        let listener = TcpListener::bind(address).await?;
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(stream) => stream,
                Err(_) => continue,
            };

            let _drop = task::spawn(Self::start_handle(
                self.state.clone(),
                stream,
                Arc::clone(&self.router),
            ));
        }
    }
}

/// Endpoint structure
#[allow(missing_debug_implementations)]
pub enum Endpoint<State> {
    /// websocket
    WebSocket(Box<dyn WebSocketHandler<State>>),
    /// http
    Http(HttpEndpoint<State>),
}

pub mod http {
    #![allow(clippy::module_name_repetitions)]

    //! Module with http implementation

    use std::{
        collections::BTreeMap,
        convert::{From, TryFrom, TryInto},
        error::Error as StdError,
        fmt::{self, Display},
    };

    use async_std::{net::TcpStream, prelude::*};
    use async_trait::async_trait;
    use httparse::{Request as HttpParseRequest, Status};
    use iroha_derive::FromVariant;
    use iroha_error::{derive::Error, error};
    use route_recognizer::Router;
    use url::form_urlencoded;

    use super::{web_socket::WEB_SOCKET_UPGRADE, Endpoint};

    /// get method name
    pub const GET_METHOD: &str = "GET";
    /// post method name
    pub const POST_METHOD: &str = "POST";
    /// put method name
    pub const PUT_METHOD: &str = "PUT";
    /// allow header
    pub const ALLOW_HEADER: &str = "Allow";
    /// upgrade header
    pub const UPGRADE_HEADER: &str = "Upgrade";
    /// content length header
    pub const CONTENT_LENGTH_HEADER: &str = "Content-Length";
    /// http return code `OK`
    pub const HTTP_CODE_OK: StatusCode = 200;
    /// http return code `INTERNAL_SERVER_ERROR`
    pub const HTTP_CODE_INTERNAL_SERVER_ERROR: StatusCode = 500;
    /// http return code `FORBIDDEN`
    pub const HTTP_CODE_FORBIDDEN: StatusCode = 403;
    /// http return code `NOT_FOUND`
    pub const HTTP_CODE_NOT_FOUND: StatusCode = 404;
    /// http return code `BAD_REQUEST`
    pub const HTTP_CODE_BAD_REQUEST: StatusCode = 400;
    /// http return code `METHOD_NOT_ALLOWED`
    pub const HTTP_CODE_METHOD_NOT_ALLOWED: StatusCode = 405;
    /// http return code `UPGRADE_REQUIRED`
    pub const HTTP_CODE_UPGRADE_REQUIRED: StatusCode = 426;
    /// http version 1.1
    pub const HTTP_VERSION_1_1: &str = "HTTP/1.1";
    const MAX_HEADERS: usize = 128;

    /// Headers type alias
    pub type Headers = BTreeMap<HeaderName, HeaderValue>;

    /// Header name type alias
    pub type HeaderName = String;

    /// Header value type alias
    pub type HeaderValue = Vec<u8>;

    /// Status code type alias
    pub type StatusCode = u16;

    /// Path parameters type alias
    pub type PathParams = BTreeMap<String, String>;

    /// Query parameters type alias
    pub type QueryParams = BTreeMap<String, String>;

    type HttpParseHttpVersion = u8;

    /// Http endpoint
    #[allow(missing_debug_implementations)]
    pub enum HttpEndpoint<State> {
        /// Get method
        Get(Box<dyn HttpHandler<State>>),
        /// Post method
        Post(Box<dyn HttpHandler<State>>),
        /// Put method
        Put(Box<dyn HttpHandler<State>>),
        //TODO: add other endpoints PUT, PATCH, DELETE and etc.
    }

    /// Handler for HTTP connection. Just a trait alias for Fn
    #[async_trait]
    pub trait HttpHandler<State: Clone + Send + Sync + 'static>: Send + Sync + 'static {
        /// call method for endpoint
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            request: HttpRequest,
        ) -> HttpResponse;
    }

    #[async_trait]
    impl<State, F, Fut> HttpHandler<State> for F
    where
        State: Clone + Send + Sync + 'static,
        F: Send + Sync + 'static + Fn(State, PathParams, QueryParams, HttpRequest) -> Fut,
        Fut: Future<Output = HttpResponse> + Send + 'static,
    {
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            request: HttpRequest,
        ) -> HttpResponse {
            let future = (self)(state, path_params, query_params, request);
            future.await
        }
    }

    /// Error trait for implementing IntoResponse in fancier way
    pub trait HttpResponseError: Send + Sync + 'static {
        /// Status code of error
        fn status_code(&self) -> StatusCode {
            HTTP_CODE_INTERNAL_SERVER_ERROR
        }

        /// Reason why request failed
        fn reason(code: StatusCode) -> String {
            match code {
                HTTP_CODE_INTERNAL_SERVER_ERROR => "Internal server error",
                HTTP_CODE_NOT_FOUND => "Not found",
                HTTP_CODE_BAD_REQUEST => "Bad request",
                HTTP_CODE_METHOD_NOT_ALLOWED => "Method not allowed",
                HTTP_CODE_UPGRADE_REQUIRED => "Upgrade required",
                _ => unimplemented!(),
            }
            .to_owned()
        }

        /// Body of response
        fn error_body(&self) -> Vec<u8>;

        /// Response construction itself
        fn error_response(&self) -> HttpResponse {
            let code = self.status_code();
            HttpResponse {
                version: HttpVersion::Http1_1,
                code,
                reason: Self::reason(code),
                headers: Headers::new(),
                body: self.error_body(),
            }
        }
    }

    impl HttpResponseError for std::convert::Infallible {
        fn error_body(&self) -> Vec<u8> {
            unreachable!()
        }
    }

    /// The version of HTTP protocol used in the corresponding request or response.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum HttpVersion {
        /// HTTP/1.1.
        Http1_1,
    }

    impl Display for HttpVersion {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                HttpVersion::Http1_1 => write!(f, "{}", HTTP_VERSION_1_1),
            }
        }
    }

    /// Http error
    #[allow(variant_size_differences)]
    #[derive(Debug, Clone, Eq, PartialEq, FromVariant, Error)]
    pub enum Error {
        /// Http version is not supported
        #[error("Http version not supported.")]
        UnsupportedHttpVersion,
        /// Method not found
        #[error("Method not found.")]
        MethodNotFound,
        /// Path not found
        #[error("Path not found.")]
        PathNotFound,
        /// Version not found
        #[error("Version not found.")]
        VersionNotFound,
        /// Failed to read header
        #[error("Failed to read header.")]
        ReadHeaderFailed,

        /// Failed to parse content length value - invalid utf-8.
        #[error("Failed to parse content length value - invalid utf-8.")]
        ContentLengthUtf(#[source] std::string::FromUtf8Error),
        /// Failed to parse content length value - not a number.
        #[error("Failed to parse content length value - not a number.")]
        ContentLengthParse(#[source] std::num::ParseIntError),
        /// HTTP parsing error.
        #[error("Http format error")]
        HttpFormat(#[source] httparse::Error),
    }

    impl TryFrom<HttpParseHttpVersion> for HttpVersion {
        type Error = Error;

        fn try_from(version: HttpParseHttpVersion) -> Result<Self, Self::Error> {
            if version == 1 {
                Ok(HttpVersion::Http1_1)
            } else {
                Err(Error::UnsupportedHttpVersion)
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
        /// Process request
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

            let route_match = if let Ok(route_match) = router.recognize(path) {
                route_match
            } else {
                return Some(HttpResponse::not_found());
            };

            let endpoint = route_match.handler;
            let path_params: PathParams = route_match
                .params
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            if let Some(WEB_SOCKET_UPGRADE) = self
                .headers
                .get(&UPGRADE_HEADER.to_lowercase())
                .map(Vec::as_slice)
            {
                let handler = if let Endpoint::WebSocket(handler) = endpoint {
                    handler
                } else {
                    return Some(HttpResponse::upgrade_required(WEB_SOCKET_UPGRADE));
                };

                match async_tungstenite::accept_async(stream).await {
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
                let handler = match (self.method.as_ref(), endpoint) {
                    (GET_METHOD, Endpoint::Http(HttpEndpoint::Get(handler)))
                    | (POST_METHOD, Endpoint::Http(HttpEndpoint::Post(handler)))
                    | (PUT_METHOD, Endpoint::Http(HttpEndpoint::Put(handler))) => handler,
                    _ => {
                        return Some(HttpResponse::method_not_allowed(&[
                            GET_METHOD,
                            POST_METHOD,
                            PUT_METHOD,
                        ]))
                    }
                };

                let response = handler
                    .call(state, path_params, query_params, self.clone())
                    .await;
                Some(response)
            }
        }
    }

    impl<'h, 'b> TryFrom<HttpParseRequest<'h, 'b>> for HttpRequest {
        type Error = Error;

        fn try_from(request: HttpParseRequest<'h, 'b>) -> Result<Self, Self::Error> {
            Ok(HttpRequest {
                method: request.method.ok_or(Error::MethodNotFound)?.to_string(),
                path: request.path.ok_or(Error::PathNotFound)?.to_string(),
                version: request.version.ok_or(Error::VersionNotFound)?.try_into()?,
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
        type Error = Error;

        fn try_from(bytes: &[u8]) -> Result<Self, Error> {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut request = httparse::Request::new(&mut headers);
            if let Status::Complete(header_size) = request.parse(bytes)? {
                let mut request: HttpRequest = request.try_into()?;
                //TODO: Deal with chunked messages which do not have Content-Length header
                //They instead have Transfer-Encoding: `Chunked` https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
                if let Some(content_length) =
                    request.headers.get(&CONTENT_LENGTH_HEADER.to_lowercase())
                {
                    let content_length =
                        String::from_utf8(content_length.clone())?.parse::<usize>()?;
                    request.body = bytes[header_size..(header_size + content_length)].to_vec();
                }
                Ok(request)
            } else {
                Err(Error::ReadHeaderFailed)
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

    impl From<()> for HttpResponse {
        fn from((): ()) -> Self {
            Self::ok(Headers::new(), Vec::new())
        }
    }

    impl From<String> for HttpResponse {
        fn from(s: String) -> Self {
            s.into_bytes().into()
        }
    }

    impl From<Vec<u8>> for HttpResponse {
        fn from(bytes: Vec<u8>) -> Self {
            Self::ok(Headers::new(), bytes)
        }
    }

    impl<E, T> From<Result<T, E>> for HttpResponse
    where
        E: StdError + HttpResponseError,
        T: TryInto<HttpResponse>,
        T::Error: StdError + HttpResponseError,
    {
        fn from(result: Result<T, E>) -> Self {
            fn error_log(err: &(impl StdError + ?Sized)) -> String {
                let log = format!("\t{}\n", err);
                err.source()
                    .map_or(log.clone(), |err| log + &error_log(err))
            }

            let (err_log, resp) = match result.map(TryInto::try_into) {
                Ok(Ok(ok)) => return ok,
                Ok(Err(err)) => (error_log(&err), err.error_response()),
                Err(err) => (error_log(&err), err.error_response()),
            };

            log::error!("Failed to handle request with error: {}", err_log);
            resp
        }
    }

    impl HttpResponse {
        /// Internal server error
        pub fn internal_server_error() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_INTERNAL_SERVER_ERROR,
                reason: "Internal server error".to_string(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        /// not found error
        pub fn not_found() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_NOT_FOUND,
                reason: "Not found".to_string(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        /// bad request
        pub fn bad_request() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_BAD_REQUEST,
                reason: "Bad request".to_string(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        /// method not allowed
        pub fn method_not_allowed(allowed_methods: &[&str]) -> HttpResponse {
            let mut headers = Headers::new();
            let _drop = headers.insert(
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

        /// upgrade required
        pub fn upgrade_required(upgrade: &[u8]) -> HttpResponse {
            let mut headers = Headers::new();
            let _drop = headers.insert(UPGRADE_HEADER.to_string(), upgrade.to_vec());
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_UPGRADE_REQUIRED,
                reason: "Upgrade required".to_string(),
                headers,
                body: Vec::new(),
            }
        }

        /// Ok constructor
        pub fn ok(mut headers: Headers, body: Vec<u8>) -> HttpResponse {
            let _drop = headers.insert(
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
        path.find('?').map_or_else(
            || (path, QueryParams::new()),
            |query_start| {
                let (path, query) = path.split_at(query_start);
                let query_params: QueryParams = form_urlencoded::parse(query[1..].as_bytes())
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect();
                (path, query_params)
            },
        )
    }

    /// Json wrapper which converts http request body to inner type
    #[derive(Debug, Clone, Eq, PartialEq, Copy)]
    pub struct Json<T>(pub T);

    /// Error which handles json deserialization
    #[derive(Debug)]
    pub struct JsonError(serde_json::Error);

    impl std::fmt::Display for JsonError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }

    impl std::error::Error for JsonError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    impl HttpResponseError for JsonError {
        fn status_code(&self) -> StatusCode {
            HTTP_CODE_BAD_REQUEST
        }
        fn error_body(&self) -> Vec<u8> {
            self.0.to_string().into()
        }
    }

    impl<T: serde::de::DeserializeOwned> TryFrom<HttpRequest> for Json<T> {
        type Error = JsonError;
        fn try_from(req: HttpRequest) -> Result<Self, Self::Error> {
            Ok(Self(serde_json::from_slice(&req.body).map_err(JsonError)?))
        }
    }

    impl<T: serde::ser::Serialize> TryFrom<Json<T>> for HttpResponse {
        type Error = JsonError;
        fn try_from(Json(json): Json<T>) -> Result<Self, Self::Error> {
            Ok(serde_json::to_vec(&json).map_err(JsonError)?.into())
        }
    }
}

pub mod web_socket {
    #![allow(clippy::module_name_repetitions)]

    //! websocket implementation module

    use async_std::{net::TcpStream, prelude::*};
    use async_trait::async_trait;
    pub use async_tungstenite::tungstenite::Message as WebSocketMessage;
    use async_tungstenite::WebSocketStream as TungsteniteWebSocketStream;
    use iroha_error::Result;

    use super::http::{PathParams, QueryParams};

    /// Websocket stream alias
    pub type WebSocketStream = TungsteniteWebSocketStream<TcpStream>;

    /// Websocket upgrade message
    pub const WEB_SOCKET_UPGRADE: &[u8] = b"websocket";

    /// Handler for web socket connection. Gets a web socket stream after initial HTTP handshake.
    #[async_trait]
    pub trait WebSocketHandler<State: Clone + Send + Sync + 'static>:
        Send + Sync + 'static
    {
        /// Call websocket handler
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            stream: WebSocketStream,
        ) -> Result<()>;
    }

    #[async_trait]
    impl<State, F, Fut> WebSocketHandler<State> for F
    where
        State: Clone + Send + Sync + 'static,
        F: Send + Sync + 'static + Fn(State, PathParams, QueryParams, WebSocketStream) -> Fut,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            stream: WebSocketStream,
        ) -> Result<()> {
            let future = (self)(state, path_params, query_params, stream);
            future.await
        }
    }
}

/// Builder for server route handlers.
#[allow(missing_debug_implementations)]
pub struct RouteBuilder<'s, State> {
    path: String,
    server: &'s mut Server<State>,
}

async fn wrapper_handler<State, Path, Query, Req, Fut, F>(
    fut: F,
    state: State,
    path: Result<Path, Path::Error>,
    query: Result<Query, Query::Error>,
    req: Result<Req, Req::Error>,
) -> http::HttpResponse
where
    State: Clone + Send + Sync + 'static,
    Fut: Future<Output = http::HttpResponse> + Send,
    F: Send + Sync + 'static + Fn(State, Path, Query, Req) -> Fut,
    Path: TryFrom<http::PathParams> + Send + Sync + 'static,
    Path::Error: http::HttpResponseError,
    Query: TryFrom<http::QueryParams> + Send + Sync + 'static,
    Query::Error: http::HttpResponseError,
    Req: TryFrom<http::HttpRequest> + Send + Sync + 'static,
    Req::Error: http::HttpResponseError,
{
    let path = match path {
        Ok(path) => path,
        Err(err) => return http::HttpResponseError::error_response(&err),
    };
    let query = match query {
        Ok(query) => query,
        Err(err) => return http::HttpResponseError::error_response(&err),
    };
    let req = match req {
        Ok(req) => req,
        Err(err) => return http::HttpResponseError::error_response(&err),
    };
    fut(state, path, query, req).await
}

impl<'s, State> RouteBuilder<'s, State>
where
    State: Clone + Send + Sync + 'static,
{
    /// Add GET handler at the specified url.
    pub fn get<Path, Query, Req, F, Fut>(&mut self, handler: F)
    where
        Path: TryFrom<PathParams> + Send + Sync + 'static,
        Path::Error: HttpResponseError,
        Query: TryFrom<QueryParams> + Send + Sync + 'static,
        Query::Error: HttpResponseError,
        Req: TryFrom<HttpRequest> + Send + Sync + 'static,
        Req::Error: HttpResponseError,
        F: Send + Sync + Copy + 'static + Fn(State, Path, Query, Req) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: TryInto<HttpResponse> + 'static,
        <Fut::Output as TryInto<HttpResponse>>::Error: HttpResponseError,
    {
        Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.")
            .add(
                &self.path,
                Endpoint::Http(HttpEndpoint::Get(Box::new(
                    move |state,
                          path: http::PathParams,
                          query: http::QueryParams,
                          req: http::HttpRequest| {
                        let fut = move |state, path, query, req| {
                            handler(state, path, query, req).map(|resp| match resp.try_into() {
                                Ok(resp) => resp,
                                Err(err) => err.error_response(),
                            })
                        };
                        let path: Result<Path, _> = path.try_into();
                        let query: Result<Query, _> = query.try_into();
                        let req: Result<Req, _> = req.try_into();

                        wrapper_handler(fut, state, path, query, req)
                    },
                ))),
            );
    }

    /// Add POST handler at the specified url.
    pub fn post<Path, Query, Req, F, Fut>(&mut self, handler: F)
    where
        Path: TryFrom<PathParams> + Send + Sync + 'static,
        Path::Error: HttpResponseError,
        Query: TryFrom<QueryParams> + Send + Sync + 'static,
        Query::Error: HttpResponseError,
        Req: TryFrom<HttpRequest> + Send + Sync + 'static,
        Req::Error: HttpResponseError,
        F: Send + Sync + Copy + 'static + Fn(State, Path, Query, Req) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: TryInto<HttpResponse> + 'static,
        <Fut::Output as TryInto<HttpResponse>>::Error: HttpResponseError,
    {
        Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.")
            .add(
                &self.path,
                Endpoint::Http(HttpEndpoint::Post(Box::new(
                    move |state, path: PathParams, query: QueryParams, req: HttpRequest| {
                        let fut = move |state, path, query, req| {
                            handler(state, path, query, req).map(|resp| match resp.try_into() {
                                Ok(resp) => resp,
                                Err(err) => err.error_response(),
                            })
                        };
                        let path: Result<Path, _> = path.try_into();
                        let query: Result<Query, _> = query.try_into();
                        let req: Result<Req, _> = req.try_into();

                        wrapper_handler(fut, state, path, query, req)
                    },
                ))),
            );
    }

    /// Add PUT handler at the specified url.
    pub fn put<Path, Query, Req, F, Fut>(&mut self, handler: F)
    where
        Path: TryFrom<PathParams> + Send + Sync + 'static,
        Path::Error: HttpResponseError,
        Query: TryFrom<QueryParams> + Send + Sync + 'static,
        Query::Error: HttpResponseError,
        Req: TryFrom<HttpRequest> + Send + Sync + 'static,
        Req::Error: HttpResponseError,
        F: Send + Sync + Copy + 'static + Fn(State, Path, Query, Req) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: TryInto<HttpResponse> + 'static,
        <Fut::Output as TryInto<HttpResponse>>::Error: HttpResponseError,
    {
        Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.")
            .add(
                &self.path,
                Endpoint::Http(HttpEndpoint::Put(Box::new(
                    move |state,
                          path: http::PathParams,
                          query: http::QueryParams,
                          req: http::HttpRequest| {
                        let fut = move |state, path, query, req| {
                            handler(state, path, query, req).map(|resp| match resp.try_into() {
                                Ok(resp) => resp,
                                Err(err) => err.error_response(),
                            })
                        };
                        let path: Result<Path, _> = path.try_into();
                        let query: Result<Query, _> = query.try_into();
                        let req: Result<Req, _> = req.try_into();

                        wrapper_handler(fut, state, path, query, req)
                    },
                ))),
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
    let _ = stream
        .take(length)
        .read_to_end(&mut Vec::new())
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
    use std::sync::Arc;
    use std::{thread, time::Duration};

    use async_std::{sync::RwLock, task};
    use futures::{SinkExt, StreamExt};
    use isahc::AsyncReadResponseExt;
    use tungstenite::client as web_socket_client;

    use super::{prelude::*, Server};

    #[test]
    fn get_request() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 request: HttpRequest| async move {
                    assert_eq!(&request.body, b"Hello, world!");
                    HttpResponse::ok(Headers::new(), b"Hi!".to_vec())
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
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/hello/world").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    HttpResponse::ok(Headers::new(), b"Hi!".to_vec())
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
        let _drop = task::spawn(async move {
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
                    HttpResponse::ok(Headers::new(), b"Right path".to_vec())
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
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/:a/path/:c").get(
                |_state: (),
                 path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    assert_eq!(path_params["a"], "hello");
                    assert_eq!(path_params["c"], "params");
                    HttpResponse::ok(Headers::new(), b"Hi!".to_vec())
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
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/").get(
                |_state: (),
                 _path_params: PathParams,
                 query_params: QueryParams,
                 _request: HttpRequest| async move {
                    assert_eq!(query_params.len(), 2);
                    assert_eq!(query_params["a"], "hello");
                    assert_eq!(query_params["c"], "params");
                    HttpResponse::ok(Headers::new(), b"Hi!".to_vec())
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
        let _drop = task::spawn(async move {
            let state = Arc::new(RwLock::new(0));
            let mut server = Server::new(state);
            server.at("/add/:num").get(
                |state: Arc<RwLock<i32>>,
                 path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    let number: i32 = path_params["num"].parse().expect("Failed to parse i32");
                    *state.write().await += number;
                },
            );
            server.at("/value").get(
                |state: Arc<RwLock<i32>>,
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: HttpRequest| async move {
                    HttpResponse::ok(
                        Headers::new(),
                        format!("{}", state.read().await).as_bytes().to_vec(),
                    )
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
        let _drop = task::spawn(async move {
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
