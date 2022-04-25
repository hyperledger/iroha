use std::{borrow::Borrow, net::TcpStream};

use attohttpc::{
    body as atto_body, RequestBuilder as AttoHttpRequestBuilder, Response as AttoHttpResponse,
};
use eyre::{eyre, Error, Result, WrapErr};
use http::header::HeaderName;
use tungstenite::{stream::MaybeTlsStream, WebSocket};
pub use tungstenite::{Error as WebSocketError, Message as WebSocketMessage};

use crate::http::{Headers, Method, RequestBuilder, Response};

type Bytes = Vec<u8>;
type AttoHttpRequestBuilderWithBytes = AttoHttpRequestBuilder<atto_body::Bytes<Bytes>>;

trait SetSingleHeader {
    fn header(self, key: HeaderName, value: String) -> Self;
}

impl SetSingleHeader for AttoHttpRequestBuilder {
    fn header(self, key: HeaderName, value: String) -> Self {
        self.header(key, value)
    }
}

impl SetSingleHeader for http::request::Builder {
    fn header(self, key: HeaderName, value: String) -> Self {
        self.header(key, value)
    }
}

trait SetHeadersExt: Sized + SetSingleHeader {
    fn set_headers(mut self, headers: Headers) -> Result<Self> {
        for (h, v) in headers {
            let h = HeaderName::from_bytes(h.as_ref())
                .wrap_err_with(|| format!("Failed to parse header name {}", h))?;
            self = self.header(h, v);
        }
        Ok(self)
    }
}

impl SetHeadersExt for AttoHttpRequestBuilder {}

impl SetHeadersExt for http::request::Builder {}

/// Default request builder & sender implemented on top of `attohttpc` crate.
///
/// Its main goal is not to be efficient, but simple. Its implementation contains
/// some intermediate allocations that could be avoided with additional complexity.
pub struct DefaultRequestBuilder(Result<AttoHttpRequestBuilder>);

impl DefaultRequestBuilder {
    fn and_then<F>(self, func: F) -> Self
    where
        F: FnOnce(AttoHttpRequestBuilder) -> Result<AttoHttpRequestBuilder>,
    {
        Self(self.0.and_then(func))
    }
}

pub struct DefaultRequest(AttoHttpRequestBuilderWithBytes);

impl DefaultRequest {
    /// Private
    fn new(builder: AttoHttpRequestBuilderWithBytes) -> Self {
        Self(builder)
    }

    /// Sends prepared request and returns bytes response
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
    type Output = Result<DefaultRequest>;

    fn new<U>(method: Method, url: U) -> Self
    where
        U: AsRef<str>,
    {
        Self(Ok(AttoHttpRequestBuilder::new(method, url)))
    }

    fn headers(self, headers: Headers) -> Self {
        self.and_then(|b| b.set_headers(headers))
    }

    fn params<P, K, V>(self, params: P) -> Self
    where
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString,
    {
        self.and_then(|b| Ok(b.params(params)))
    }

    fn body(self, data: Option<Vec<u8>>) -> Self::Output {
        self.0.map(|b| {
            DefaultRequest::new(b.bytes(match data {
                Some(bytes) => bytes,
                None => Vec::new(),
            }))
        })
    }
}

/// Special builder for WS connections
pub struct DefaultWebSocketRequestBuilder(Result<http::request::Builder>);

impl DefaultWebSocketRequestBuilder {
    fn and_then<F>(self, func: F) -> Self
    where
        F: FnOnce(http::request::Builder) -> Result<http::request::Builder>,
    {
        Self(self.0.and_then(func))
    }
}

/// Successfully built WS request
pub struct DefaultWebSocketStreamRequest(http::Request<()>);

impl DefaultWebSocketStreamRequest {
    /// Opens WS stream using `tungstenite`
    pub fn connect(self) -> Result<WebSocketStream> {
        let (stream, _) = tungstenite::connect(self.0)?;
        Ok(stream)
    }
}

impl RequestBuilder for DefaultWebSocketRequestBuilder {
    type Output = Result<DefaultWebSocketStreamRequest>;

    fn new<U>(method: Method, url: U) -> Self
    where
        U: AsRef<str>,
    {
        Self(Ok(http::Request::builder()
            .method(method)
            .uri(url.as_ref())))
    }

    fn params<P, K, V>(self, _params: P) -> Self
    where
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString,
    {
        Self(self.0.and(Err(eyre!("No params expected"))))
    }

    fn headers(self, headers: Headers) -> Self {
        self.and_then(|b| b.set_headers(headers))
    }

    fn body(self, data: Option<Vec<u8>>) -> Self::Output {
        match data {
            Some(body) => Err(eyre!("Empty body expected, got: {:?}", body)),
            None => self
                .0
                .and_then(|b| b.body(()).map_err(Into::into))
                .map(DefaultWebSocketStreamRequest),
        }
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
