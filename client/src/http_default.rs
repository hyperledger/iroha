//! Defaults for various items used in communication over http(s).
use std::{net::TcpStream, str::FromStr};

use attohttpc::{RequestBuilder as AttoHttpRequestBuilder, Response as AttoHttpResponse};
use eyre::{eyre, Error, Result, WrapErr};
use http::header::HeaderName;
use tokio_tungstenite::tungstenite::{stream::MaybeTlsStream, WebSocket};
pub use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message as WebSocketMessage};
use url::Url;

use crate::http::{Method, RequestBuilder, Response, SyncRequestManager, SyncSendRequest};

type Bytes = Vec<u8>;

fn header_name_from_str(str: &str) -> Result<HeaderName> {
    HeaderName::from_str(str).wrap_err_with(|| format!("Failed to parse header name {str}"))
}

#[derive(Debug, Clone)]
pub struct DefaultSendRequest;

impl Default for DefaultSendRequest {
    fn default() -> Self {
        Self
    }
}

impl SyncSendRequest for DefaultSendRequest {
    type RequestBuilder = DefaultRequestBuilder;

    fn send(&self, rb: Self::RequestBuilder) -> Result<http::Response<Vec<u8>>> {
        let mut atto_http_req_builder = rb
            .inner
            .map(|b| b.bytes(rb.body.map_or_else(Vec::new, |vec| vec)))?;
        let (method, url) = {
            let inspect = atto_http_req_builder.inspect();
            (inspect.method().clone(), inspect.url().clone())
        };

        let response = atto_http_req_builder
            .send()
            .wrap_err_with(|| format!("Failed to send http {method} request to {url}"))?;

        ClientResponse(response).try_into()
    }
}

impl Default for SyncRequestManager<DefaultSendRequest> {
    fn default() -> Self {
        Self {
            inner: DefaultSendRequest::default(),
        }
    }
}

/// Default request builder implemented on top of `attohttpc` crate.
#[derive(Debug)]
pub struct DefaultRequestBuilder {
    inner: Result<AttoHttpRequestBuilder>,
    body: Option<Vec<u8>>,
}

impl DefaultRequestBuilder {
    fn and_then<F>(self, f: F) -> Self
    where
        F: FnOnce(AttoHttpRequestBuilder) -> Result<AttoHttpRequestBuilder>,
    {
        Self {
            inner: self.inner.and_then(f),
            ..self
        }
    }
}

impl RequestBuilder for DefaultRequestBuilder {
    fn new(method: Method, url: Url) -> Self {
        Self {
            inner: Ok(AttoHttpRequestBuilder::new(method, url)),
            body: None,
        }
    }

    fn header<K, V: ?Sized>(self, key: K, value: &V) -> Self
    where
        K: AsRef<str>,
        V: ToString,
    {
        self.and_then(|builder| {
            Ok(builder.header(header_name_from_str(key.as_ref())?, value.to_string()))
        })
    }

    fn param<K, V: ?Sized>(self, key: K, value: &V) -> Self
    where
        K: AsRef<str>,
        V: ToString,
    {
        self.and_then(|b| Ok(b.param(key, value.to_string())))
    }

    fn body(self, data: Vec<u8>) -> Self {
        Self {
            body: Some(data),
            ..self
        }
    }
}

/// Request builder built on top of [`http::request::Builder`]. Used for `WebSocket` connections.
pub struct DefaultWebSocketRequestBuilder(Result<http::request::Builder>);

impl DefaultWebSocketRequestBuilder {
    /// Same as [`DefaultRequestBuilder::and_then`].
    fn and_then<F>(self, func: F) -> Self
    where
        F: FnOnce(http::request::Builder) -> Result<http::request::Builder>,
    {
        Self(self.0.and_then(func))
    }

    /// Consumes itself to build request.
    pub fn build(self) -> Result<DefaultWebSocketStreamRequest> {
        let mut req = self.0.and_then(|b| b.body(()).map_err(Into::into))?;

        let uri = req.uri().to_string();
        let headers = req.headers_mut();

        headers.insert("Host", uri.parse()?);
        headers.insert("Connection", "Upgrade".parse()?);
        headers.insert("Upgrade", "websocket".parse()?);
        headers.insert("Sec-WebSocket-Version", "13".parse()?);
        headers.insert(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key().parse()?,
        );

        Ok(DefaultWebSocketStreamRequest(req))
    }
}

impl RequestBuilder for DefaultWebSocketRequestBuilder {
    fn new(method: Method, url: Url) -> Self {
        Self(Ok(http::Request::builder()
            .method(method)
            .uri(url.as_ref())))
    }

    fn param<K, V: ?Sized>(self, _key: K, _val: &V) -> Self {
        Self(self.0.and(Err(eyre!("No params expected"))))
    }

    fn header<N, V: ?Sized>(self, name: N, value: &V) -> Self
    where
        N: AsRef<str>,
        V: ToString,
    {
        self.and_then(|b| Ok(b.header(header_name_from_str(name.as_ref())?, value.to_string())))
    }

    fn body(self, data: Vec<u8>) -> Self {
        self.and_then(|b| {
            if data.is_empty() {
                Ok(b)
            } else {
                Err(eyre!("Empty body expected, got: {:?}", data))
            }
        })
    }
}

struct ClientResponse(AttoHttpResponse);

impl TryFrom<ClientResponse> for Response<Bytes> {
    type Error = Error;

    fn try_from(response: ClientResponse) -> Result<Self> {
        let ClientResponse(response) = response;
        let mut builder = Response::builder().status(response.status());
        let headers = builder
            .headers_mut()
            .ok_or_else(|| eyre!("Failed to get headers map reference."))?;
        for (key, value) in response.headers() {
            headers.insert(key, value.clone());
        }
        response
            .bytes()
            .wrap_err("Failed to get response as bytes")
            .and_then(|bytes| {
                builder
                    .body(bytes)
                    .wrap_err("Failed to construct response bytes body")
            })
    }
}

/// `WebSocket` request built by [`DefaultWebSocketRequestBuilder`]
pub struct DefaultWebSocketStreamRequest(http::Request<()>);

impl DefaultWebSocketStreamRequest {
    /// Open [`WebSocketStream`] synchronously.
    pub fn connect(self) -> Result<WebSocketStream> {
        let (stream, _) = tokio_tungstenite::tungstenite::connect(self.0)?;
        Ok(stream)
    }

    /// Open [`AsyncWebSocketStream`].
    pub async fn connect_async(self) -> Result<AsyncWebSocketStream> {
        let (stream, _) = tokio_tungstenite::connect_async(self.0).await?;
        Ok(stream)
    }
}

pub type WebSocketStream = WebSocket<MaybeTlsStream<TcpStream>>;
pub type AsyncWebSocketStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
