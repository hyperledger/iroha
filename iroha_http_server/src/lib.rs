//! HTTP/1.1 server library with WebSocket support heavily inspired by [tide](https://crates.io/crates/tide).

#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]

//TODO: do we need TLS/SSL?
use std::{
    convert::{TryFrom, TryInto},
    future::Future,
    sync::Arc,
};

use futures::FutureExt;
use http::{
    HttpEndpoint, HttpResponse, HttpResponseError, PathParams, PreprocessedHttpRequest,
    QueryParams, RawHttpRequest,
};
use iroha_error::{Result, WrapErr};
use route_recognizer::Router;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task,
};
use web_socket::{WebSocketEndpoint, WebSocketHandler};

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
            path: path.to_owned(),
            server: self,
        }
    }

    #[allow(clippy::future_not_send)]
    async fn write_all<B>(bytes: B, stream: &mut TcpStream)
    where
        Vec<u8>: From<B>,
    {
        if let Err(err) = stream.write_all(&Vec::from(bytes)).await {
            iroha_logger::error!("Failed to write back HTTP response: {}", err);
        }
    }

    /// Handles http/websocket connection
    #[iroha_futures::telemetry_future]
    async fn handle(
        state: State,
        mut stream: TcpStream,
        router: Arc<Router<Endpoint<State>>>,
    ) -> Result<()> {
        let mut buffer = vec![0; BUFFER_SIZE];
        let read_size = stream
            .peek(&mut buffer)
            .await
            .wrap_err("Request read failed.")?;
        let request = RawHttpRequest::try_from(&buffer[..read_size])
            .map(|request| request.preprocess(state, &*router));
        match request {
            Err(parse_err) => {
                consume_bytes(&mut stream, read_size).await?;
                iroha_logger::error!("Failed to parse incoming HTTP request: {:?}", parse_err);
                Self::write_all(&HttpResponse::bad_request(), &mut stream).await;
            }
            Ok(Err(preprocess_err_response)) => {
                consume_bytes(&mut stream, read_size).await?;
                Self::write_all(&preprocess_err_response, &mut stream).await;
            }
            Ok(Ok(PreprocessedHttpRequest::Request(request))) => {
                consume_bytes(&mut stream, read_size).await?;
                let response = request.process().await;
                Self::write_all(&response, &mut stream).await;
            }
            Ok(Ok(PreprocessedHttpRequest::WebSocketUpgrade(web_socket))) => {
                web_socket.process_with_stream(stream).await
            }
        }
        Ok(())
    }

    /// Starts server at `address`
    ///
    /// # Errors
    /// Fails if accepting one of client fails
    #[iroha_futures::telemetry_future]
    pub async fn start(&self, address: &str) -> iroha_error::Result<()> {
        let listener = TcpListener::bind(address).await?;
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let state = self.state.clone();
            let router = Arc::clone(&self.router);
            let _drop = task::spawn(async move {
                if let Err(err) = Self::handle(state, stream, router).await {
                    iroha_logger::error!("Failed to handle HTTP request: {}", err);
                }
            });
        }
    }
}

/// Endpoint structure
#[allow(missing_debug_implementations)]
pub enum Endpoint<State> {
    /// websocket
    WebSocket(WebSocketEndpoint<State>),
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
        future::Future,
    };

    use async_trait::async_trait;
    use httparse::{Request as HttpParseRequest, Status};
    use iroha_derive::FromVariant;
    use iroha_error::{derive::Error, error};
    use route_recognizer::Router;
    use url::form_urlencoded;

    use super::{
        web_socket::{WebSocketUpgrade, WEB_SOCKET_UPGRADE},
        Endpoint,
    };

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
            request: RawHttpRequest,
        ) -> HttpResponse;
    }

    #[async_trait]
    impl<State, F, Fut> HttpHandler<State> for F
    where
        State: Clone + Send + Sync + 'static,
        F: Send + Sync + 'static + Fn(State, PathParams, QueryParams, RawHttpRequest) -> Fut,
        Fut: Future<Output = HttpResponse> + Send + 'static,
    {
        async fn call(
            &self,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
            request: RawHttpRequest,
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
            #[allow(clippy::unimplemented)]
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
            #[allow(clippy::pattern_type_mismatch)]
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
    pub struct RawHttpRequest {
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

    /// Preprocessed request, which should be handled either as request or web socket upgrade.
    #[allow(missing_debug_implementations)]
    pub enum PreprocessedHttpRequest<'a, State> {
        /// Handle this request as ordinary http.
        Request(HttpRequest<'a, State>),
        /// Handle this request as a web socket upgrade.
        WebSocketUpgrade(WebSocketUpgrade<'a, State>),
    }

    impl RawHttpRequest {
        /// Parses common request params and decides if this request should be handled as simple http request or protocol upgrade.
        ///
        /// # Errors
        /// 1. Upgrade requeired for the URL
        /// 2. Websocket endpoint not found under this URL
        pub fn preprocess<State>(
            self,
            state: State,
            router: &Router<Endpoint<State>>,
        ) -> Result<PreprocessedHttpRequest<State>, HttpResponse>
        where
            State: Clone + Send + Sync + 'static,
        {
            let (path, query_params) = strip_query_params(self.path.as_ref());

            let route_match = if let Ok(route_match) = router.recognize(path) {
                route_match
            } else {
                return Err(HttpResponse::not_found());
            };

            let endpoint = route_match.handler;
            let path_params: PathParams = route_match
                .params
                .iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect();

            #[allow(clippy::pattern_type_mismatch)]
            if let Some(WEB_SOCKET_UPGRADE) = self
                .headers
                .get(&UPGRADE_HEADER.to_lowercase())
                .map(Vec::as_slice)
            {
                if let Endpoint::WebSocket(handler) = endpoint {
                    Ok(PreprocessedHttpRequest::WebSocketUpgrade(
                        WebSocketUpgrade::new(handler, state, path_params, query_params),
                    ))
                } else {
                    Err(HttpResponse::not_found())
                }
            } else {
                #[allow(clippy::collapsible_else_if)]
                if let Endpoint::Http(handler) = endpoint {
                    Ok(PreprocessedHttpRequest::Request(HttpRequest::new(
                        self,
                        handler,
                        state,
                        path_params,
                        query_params,
                    )))
                } else {
                    Err(HttpResponse::upgrade_required(WEB_SOCKET_UPGRADE))
                }
            }
        }
    }

    /// Preprocessed http request.
    #[allow(missing_debug_implementations)]
    pub struct HttpRequest<'a, State> {
        raw: RawHttpRequest,
        endpoint: &'a HttpEndpoint<State>,
        state: State,
        path_params: PathParams,
        query_params: QueryParams,
    }

    impl<'a, State: Clone + Send + Sync + 'static> HttpRequest<'a, State> {
        /// Constructor.
        pub fn new(
            raw: RawHttpRequest,
            endpoint: &'a HttpEndpoint<State>,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
        ) -> Self {
            HttpRequest {
                raw,
                endpoint,
                state,
                path_params,
                query_params,
            }
        }

        /// Process request
        pub async fn process(self) -> HttpResponse
        where
            State: Clone + Send + Sync + 'static,
        {
            #[allow(clippy::pattern_type_mismatch)]
            let handler = match (self.raw.method.as_ref(), self.endpoint) {
                (GET_METHOD, HttpEndpoint::Get(handler))
                | (POST_METHOD, HttpEndpoint::Post(handler))
                | (PUT_METHOD, HttpEndpoint::Put(handler)) => handler,
                _ => {
                    return HttpResponse::method_not_allowed(&[GET_METHOD, POST_METHOD, PUT_METHOD])
                }
            };

            let response = handler
                .call(self.state, self.path_params, self.query_params, self.raw)
                .await;
            response
        }
    }

    impl<'h, 'b> TryFrom<HttpParseRequest<'h, 'b>> for RawHttpRequest {
        type Error = Error;

        fn try_from(request: HttpParseRequest<'h, 'b>) -> Result<Self, Self::Error> {
            Ok(RawHttpRequest {
                method: request.method.ok_or(Error::MethodNotFound)?.to_owned(),
                path: request.path.ok_or(Error::PathNotFound)?.to_owned(),
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

    impl TryFrom<&[u8]> for RawHttpRequest {
        type Error = Error;

        fn try_from(bytes: &[u8]) -> Result<Self, Error> {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut request = httparse::Request::new(&mut headers);
            let header_size = if let Status::Complete(header_size) = request.parse(bytes)? {
                header_size
            } else {
                return Err(Error::ReadHeaderFailed);
            };
            let mut request: RawHttpRequest = request.try_into()?;
            //TODO: Deal with chunked messages which do not have Content-Length header
            //They instead have Transfer-Encoding: `Chunked` https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
            if let Some(content_length) = request.headers.get(&CONTENT_LENGTH_HEADER.to_lowercase())
            {
                let content_length = String::from_utf8(content_length.clone())?.parse::<usize>()?;
                if header_size + content_length > bytes.len() {
                    return Err(Error::ReadHeaderFailed);
                }
                request.body = bytes[header_size..(header_size + content_length)].to_vec();
            }
            Ok(request)
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
                let mut log = format!("\t{}\n", err);
                if let Some(err) = err.source() {
                    log.push_str(&error_log(err))
                }
                log
            }

            let (err_log, resp) = match result.map(TryInto::try_into) {
                Ok(Ok(ok)) => return ok,
                Ok(Err(err)) => (error_log(&err), err.error_response()),
                Err(err) => (error_log(&err), err.error_response()),
            };

            iroha_logger::error!("Failed to handle request with error: {}", err_log);
            resp
        }
    }

    impl HttpResponse {
        /// Internal server error
        pub fn internal_server_error() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_INTERNAL_SERVER_ERROR,
                reason: "Internal server error".to_owned(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        /// not found error
        pub fn not_found() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_NOT_FOUND,
                reason: "Not found".to_owned(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        /// bad request
        pub fn bad_request() -> HttpResponse {
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_BAD_REQUEST,
                reason: "Bad request".to_owned(),
                headers: Headers::new(),
                body: Vec::new(),
            }
        }

        /// method not allowed
        pub fn method_not_allowed(allowed_methods: &[&str]) -> HttpResponse {
            let mut headers = Headers::new();
            let _drop = headers.insert(
                ALLOW_HEADER.to_owned(),
                allowed_methods.join(", ").as_bytes().to_vec(),
            );
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_METHOD_NOT_ALLOWED,
                reason: "Method not allowed".to_owned(),
                headers,
                body: Vec::new(),
            }
        }

        /// upgrade required
        pub fn upgrade_required(upgrade: &[u8]) -> HttpResponse {
            let mut headers = Headers::new();
            let _drop = headers.insert(UPGRADE_HEADER.to_owned(), upgrade.to_vec());
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_UPGRADE_REQUIRED,
                reason: "Upgrade required".to_owned(),
                headers,
                body: Vec::new(),
            }
        }

        /// Ok constructor
        pub fn ok(mut headers: Headers, body: Vec<u8>) -> HttpResponse {
            let _drop = headers.insert(
                CONTENT_LENGTH_HEADER.to_owned(),
                format!("{}", body.len()).as_bytes().to_vec(),
            );
            HttpResponse {
                version: HttpVersion::Http1_1,
                code: HTTP_CODE_OK,
                reason: "OK".to_owned(),
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
    #[allow(clippy::exhaustive_structs)]
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

    impl<T: serde::de::DeserializeOwned> TryFrom<RawHttpRequest> for Json<T> {
        type Error = JsonError;
        fn try_from(req: RawHttpRequest) -> Result<Self, Self::Error> {
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

    use std::future::Future;

    use async_trait::async_trait;
    use iroha_error::Result;
    use tokio::net::TcpStream;
    pub use tokio_tungstenite::tungstenite::Message as WebSocketMessage;
    use tokio_tungstenite::WebSocketStream as TungsteniteWebSocketStream;

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

    /// Web Socket Endpoint is an alias to a boxed handler.
    pub type WebSocketEndpoint<State> = Box<dyn WebSocketHandler<State>>;

    /// Web Socket Upgrade preprocessed request.
    #[allow(missing_debug_implementations)]
    pub struct WebSocketUpgrade<'a, State> {
        endpoint: &'a WebSocketEndpoint<State>,
        state: State,
        path_params: PathParams,
        query_params: QueryParams,
    }

    impl<'a, State: Clone + Send + Sync + 'static> WebSocketUpgrade<'a, State> {
        /// Constructor.
        pub fn new(
            endpoint: &'a WebSocketEndpoint<State>,
            state: State,
            path_params: PathParams,
            query_params: QueryParams,
        ) -> Self {
            WebSocketUpgrade {
                endpoint,
                state,
                path_params,
                query_params,
            }
        }

        /// Process this upgrade, consuming the stream.
        pub async fn process_with_stream(self, stream: TcpStream) {
            match tokio_tungstenite::accept_async(stream).await {
                Ok(stream) => {
                    if let Err(err) = self
                        .endpoint
                        .call(self.state, self.path_params, self.query_params, stream)
                        .await
                    {
                        iroha_logger::error!("Failed to handle web socket stream: {}", err)
                    }
                }
                Err(err) => {
                    iroha_logger::error!(
                        "Failed to handle web socket handshake with error: {}",
                        err
                    );
                }
            }
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
    Req: TryFrom<http::RawHttpRequest> + Send + Sync + 'static,
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
        Req: TryFrom<RawHttpRequest> + Send + Sync + 'static,
        Req::Error: HttpResponseError,
        F: Send + Sync + Copy + 'static + Fn(State, Path, Query, Req) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: TryInto<HttpResponse> + 'static,
        <Fut::Output as TryInto<HttpResponse>>::Error: HttpResponseError,
    {
        #[allow(clippy::expect_used)]
        let router = Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.");

        router.add(
            &self.path,
            Endpoint::Http(HttpEndpoint::Get(Box::new(
                move |state,
                      path: http::PathParams,
                      query: http::QueryParams,
                      req: http::RawHttpRequest| {
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
        Req: TryFrom<RawHttpRequest> + Send + Sync + 'static,
        Req::Error: HttpResponseError,
        F: Send + Sync + Copy + 'static + Fn(State, Path, Query, Req) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: TryInto<HttpResponse> + 'static,
        <Fut::Output as TryInto<HttpResponse>>::Error: HttpResponseError,
    {
        #[allow(clippy::expect_used)]
        let router = Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.");

        router.add(
            &self.path,
            Endpoint::Http(HttpEndpoint::Post(Box::new(
                move |state, path: PathParams, query: QueryParams, req: RawHttpRequest| {
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
        Req: TryFrom<RawHttpRequest> + Send + Sync + 'static,
        Req::Error: HttpResponseError,
        F: Send + Sync + Copy + 'static + Fn(State, Path, Query, Req) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: TryInto<HttpResponse> + 'static,
        <Fut::Output as TryInto<HttpResponse>>::Error: HttpResponseError,
    {
        #[allow(clippy::expect_used)]
        let router = Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.");

        router.add(
            &self.path,
            Endpoint::Http(HttpEndpoint::Put(Box::new(
                move |state,
                      path: http::PathParams,
                      query: http::QueryParams,
                      req: http::RawHttpRequest| {
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
        #[allow(clippy::expect_used)]
        Arc::get_mut(&mut self.server.router)
            .expect("Registering routes is not possible after the Server has started.")
            .add(&self.path, Endpoint::WebSocket(Box::new(handler)));
    }
}

async fn consume_bytes(stream: &mut TcpStream, length: usize) -> Result<()> {
    #[allow(clippy::as_conversions)]
    let _ = stream
        .take(length as u64)
        .read_to_end(&mut Vec::new())
        .await
        .wrap_err("Failed to consume data.")?;
    Ok(())
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `iroha_http_server`.

    #[doc(inline)]
    pub use crate::{
        http::{Headers, HttpResponse, HttpVersion, PathParams, QueryParams, RawHttpRequest},
        web_socket::{WebSocketMessage, WebSocketStream},
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::sync::Arc;
    use std::{thread, time::Duration};

    use futures::{SinkExt, StreamExt};
    use isahc::AsyncReadResponseExt;
    use tokio::{runtime::Runtime, sync::RwLock, task};
    use tungstenite::client as web_socket_client;

    use super::{prelude::*, Server};

    #[test]
    fn get_request() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 request: RawHttpRequest| async move {
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

    #[tokio::test(flavor = "multi_thread")]
    async fn get_request_isahc() {
        let port = port_check::free_local_port().expect("Failed to get free local port.");
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/hello/world").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: RawHttpRequest| async move {
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
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/a").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: RawHttpRequest| async move { panic!("Wrong path.") },
            );
            server.at("/*/b").post(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: RawHttpRequest| async move {
                    HttpResponse::ok(Headers::new(), b"Right path".to_vec())
                },
            );
            server.at("/c/b").get(
                |_state: (),
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: RawHttpRequest| async move { panic!("Wrong path.") },
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
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/:a/path/:c").get(
                |_state: (),
                 path_params: PathParams,
                 _query_params: QueryParams,
                 _request: RawHttpRequest| async move {
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
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let _drop = task::spawn(async move {
            let mut server = Server::new(());
            server.at("/").get(
                |_state: (),
                 _path_params: PathParams,
                 query_params: QueryParams,
                 _request: RawHttpRequest| async move {
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
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        let _drop = task::spawn(async move {
            let state = Arc::new(RwLock::new(0_i32));
            let mut server = Server::new(state);
            server.at("/add/:num").get(
                |state: Arc<RwLock<i32>>,
                 path_params: PathParams,
                 _query_params: QueryParams,
                 _request: RawHttpRequest| async move {
                    let number: i32 = path_params["num"].parse().expect("Failed to parse i32");
                    *state.write().await += number;
                },
            );
            server.at("/value").get(
                |state: Arc<RwLock<i32>>,
                 _path_params: PathParams,
                 _query_params: QueryParams,
                 _request: RawHttpRequest| async move {
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
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
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
            .write_message(WebSocketMessage::Text("Hi!".to_owned()))
            .expect("Failed to write message");
        assert_eq!(
            stream.read_message().expect("Failed to receive message."),
            WebSocketMessage::Text("Received: Hi!".to_owned())
        );
    }
}
