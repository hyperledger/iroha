//! Defaults for various items used in communication over http(s).
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{net::TcpStream, str::FromStr};

use attohttpc::{
    body as atto_body, RequestBuilder as AttoHttpRequestBuilder, Response as AttoHttpResponse,
};
use eyre::{eyre, Error, Result, WrapErr};
use http::header::HeaderName;
use tungstenite::{stream::MaybeTlsStream, WebSocket};
pub use tungstenite::{Error as WebSocketError, Message as WebSocketMessage};

use crate::http::{Method, RequestBuilder, Response};

type Bytes = Vec<u8>;
type AttoHttpRequestBuilderWithBytes = AttoHttpRequestBuilder<atto_body::Bytes<Bytes>>;

fn header_name_from_str(str: &str) -> Result<HeaderName> {
    HeaderName::from_str(str).wrap_err_with(|| format!("Failed to parse header name {}", str))
}

/// Default request builder implemented on top of `attohttpc` crate.
pub struct DefaultRequestBuilder {
    inner: Result<AttoHttpRequestBuilder>,
    body: Option<Vec<u8>>,
}

impl DefaultRequestBuilder {
    /// Applies `.and_then()` semantics to the inner `Result` with underlying request builder.
    fn and_then<F>(self, fun: F) -> Self
    where
        F: FnOnce(AttoHttpRequestBuilder) -> Result<AttoHttpRequestBuilder>,
    {
        Self {
            inner: self.inner.and_then(fun),
            ..self
        }
    }

    /// Consumes itself to build request.
    pub fn build(self) -> Result<DefaultRequest> {
        self.inner.map(|b| {
            let body = match self.body {
                Some(vec) => vec,
                None => Vec::new(),
            };
            DefaultRequest(b.bytes(body))
        })
    }
}

/// Request built by [`DefaultRequestBuilder`].
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
            .wrap_err_with(|| format!("Failed to send http {} request to {}", method, url))?;

        ClientResponse(response).try_into()
    }
}

impl RequestBuilder for DefaultRequestBuilder {
    fn new(method: Method, url: impl AsRef<str>) -> Self {
        Self {
            inner: Ok(AttoHttpRequestBuilder::new(method, url)),
            body: None,
        }
    }

    fn header<K, V>(self, key: K, value: V) -> Self
    where
        K: AsRef<str>,
        V: ToString,
    {
        self.and_then(|builder| {
            Ok(builder.header(header_name_from_str(key.as_ref())?, value.to_string()))
        })
    }

    fn param<K, V>(self, key: K, value: V) -> Self
    where
        K: AsRef<str>,
        V: ToString,
    {
        self.and_then(|b| Ok(b.param(key, value)))
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
        self.0
            .and_then(|b| b.body(()).map_err(Into::into))
            .map(DefaultWebSocketStreamRequest)
    }
}

/// `WebSocket` request built by [`DefaultWebSocketRequestBuilder`]
pub struct DefaultWebSocketStreamRequest(http::Request<()>);

impl DefaultWebSocketStreamRequest {
    /// Opens WS stream using [`tungstenite`] crate
    pub fn connect(self) -> Result<WebSocketStream> {
        let (stream, _) = tungstenite::connect(self.0)?;
        Ok(stream)
    }
}

impl RequestBuilder for DefaultWebSocketRequestBuilder {
    fn new(method: Method, url: impl AsRef<str>) -> Self {
        Self(Ok(http::Request::builder()
            .method(method)
            .uri(url.as_ref())))
    }

    fn param<K, V>(self, _key: K, _val: V) -> Self {
        Self(self.0.and(Err(eyre!("No params expected"))))
    }

    fn header<N, V>(self, name: N, value: V) -> Self
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

pub type WebSocketStream = WebSocket<MaybeTlsStream<TcpStream>>;

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
