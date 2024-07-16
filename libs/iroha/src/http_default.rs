//! Defaults for various items used in communication over http(s).
use std::{net::TcpStream, str::FromStr};

use attohttpc::{
    body as atto_body, RequestBuilder as AttoHttpRequestBuilder, Response as AttoHttpResponse,
};
use eyre::{eyre, Error, Result, WrapErr};
use http::header::HeaderName;
use tungstenite::{client::IntoClientRequest, stream::MaybeTlsStream, WebSocket};
pub use tungstenite::{Error as WebSocketError, Message as WebSocketMessage};
use url::Url;

use crate::http::{Method, RequestBuilder, Response};

type Bytes = Vec<u8>;
type AttoHttpRequestBuilderWithBytes = AttoHttpRequestBuilder<atto_body::Bytes<Bytes>>;

fn header_name_from_str(str: &str) -> Result<HeaderName> {
    HeaderName::from_str(str).wrap_err_with(|| format!("Failed to parse header name {str}"))
}

/// Default request builder implemented on top of `attohttpc` crate.
#[derive(Debug)]
pub struct DefaultRequestBuilder {
    inner: Result<AttoHttpRequestBuilder>,
    body: Option<Vec<u8>>,
}

impl DefaultRequestBuilder {
    /// Apply `.and_then()` semantics to the inner `Result` with underlying request builder.
    fn and_then<F>(self, fun: F) -> Self
    where
        F: FnOnce(AttoHttpRequestBuilder) -> Result<AttoHttpRequestBuilder>,
    {
        Self {
            inner: self.inner.and_then(fun),
            ..self
        }
    }

    /// Build request by consuming self.
    pub fn build(self) -> Result<DefaultRequest> {
        self.inner
            .map(|b| DefaultRequest(b.bytes(self.body.map_or_else(Vec::new, |vec| vec))))
    }
}

/// Request built by [`DefaultRequestBuilder`].
#[derive(Debug)]
pub struct DefaultRequest(AttoHttpRequestBuilderWithBytes);

impl DefaultRequest {
    /// Sends itself and returns byte response
    ///
    /// # Errors
    /// Fails if request building and sending fails or response transformation fails
    pub fn send(mut self) -> Result<Response<Bytes>> {
        let (method, url) = {
            let inspect = self.0.inspect();
            (inspect.method().clone(), inspect.url().clone())
        };

        let response = self
            .0
            .send()
            .wrap_err_with(|| format!("Failed to send http {method} request to {url}"))?;

        ClientResponse(response).try_into()
    }
}

impl RequestBuilder for DefaultRequestBuilder {
    fn new(method: Method, url: Url) -> Self {
        Self {
            inner: Ok(AttoHttpRequestBuilder::new(method, url)),
            body: None,
        }
    }

    fn header<K: AsRef<str>, V: ToString + ?Sized>(self, key: K, value: &V) -> Self {
        self.and_then(|builder| {
            Ok(builder.header(header_name_from_str(key.as_ref())?, value.to_string()))
        })
    }

    fn param<K: AsRef<str>, V: ToString + ?Sized>(self, key: K, value: &V) -> Self {
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
        let builder = self.0?;
        let mut request = builder
            .uri_ref()
            .ok_or(eyre!("Missing URI"))?
            .into_client_request()?;
        for (header, value) in builder.headers_ref().ok_or(eyre!("No headers found"))? {
            request.headers_mut().entry(header).or_insert(value.clone());
        }
        Ok(DefaultWebSocketStreamRequest(request))
    }
}

/// `WebSocket` request built by [`DefaultWebSocketRequestBuilder`]
pub struct DefaultWebSocketStreamRequest(http::Request<()>);

impl DefaultWebSocketStreamRequest {
    /// Open [`WebSocketStream`] synchronously.
    pub fn connect(self) -> Result<WebSocketStream> {
        let (stream, _) = tungstenite::connect(self.0)?;
        Ok(stream)
    }

    /// Open [`AsyncWebSocketStream`].
    pub async fn connect_async(self) -> Result<AsyncWebSocketStream> {
        let (stream, _) = tokio_tungstenite::connect_async(self.0).await?;
        Ok(stream)
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

    fn header<N: AsRef<str>, V: ToString + ?Sized>(self, name: N, value: &V) -> Self {
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

pub type WebSocketStream = WebSocket<MaybeTlsStream<TcpStream>>;
pub type AsyncWebSocketStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

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
