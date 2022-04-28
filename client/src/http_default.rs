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

impl SetSingleHeader for AttoHttpRequestBuilderWithBytes {
    #[allow(clippy::only_used_in_recursion)] // False-positive
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

impl SetHeadersExt for AttoHttpRequestBuilderWithBytes {}

impl SetHeadersExt for http::request::Builder {}

/// Default request builder & sender implemented on top of `attohttpc` crate.
///
/// Its main goal is not to be efficient, but simple. Its implementation contains
/// some intermediate allocations that could be avoided with additional complexity.
pub struct DefaultRequestBuilder {
    method: Method,
    url: String,
    params: Option<Vec<(String, String)>>,
    headers: Option<Headers>,
    body: Option<Bytes>,
}

impl DefaultRequestBuilder {
    /// Sends prepared request and returns bytes response
    ///
    /// # Errors
    /// Fails if request building and sending fails or response transformation fails
    pub fn send(self) -> Result<Response<Bytes>> {
        let Self {
            method,
            url,
            body,
            params,
            headers,
            ..
        } = self;

        let bytes_anyway = match body {
            Some(bytes) => bytes,
            None => Vec::new(),
        };

        // for error formatting
        let method_url_cloned = (method.clone(), url.clone());

        let mut builder = AttoHttpRequestBuilder::new(method, url).bytes(bytes_anyway);
        if let Some(params) = params {
            builder = builder.params(params);
        }
        if let Some(headers) = headers {
            builder = builder.set_headers(headers)?;
        }

        let response = builder.send().wrap_err_with(|| {
            format!(
                "Failed to send http {} request to {}",
                &method_url_cloned.0, &method_url_cloned.1
            )
        })?;

        ClientResponse(response).try_into()
    }
}

impl RequestBuilder for DefaultRequestBuilder {
    fn new<U>(method: Method, url: U) -> Self
    where
        U: AsRef<str>,
    {
        Self {
            method,
            url: url.as_ref().to_owned(),
            headers: None,
            params: None,
            body: None,
        }
    }

    fn bytes(self, data: Vec<u8>) -> Self {
        Self {
            body: Some(data),
            ..self
        }
    }

    fn headers(self, headers: Headers) -> Self {
        Self {
            headers: Some(headers),
            ..self
        }
    }

    fn params<P, K, V>(self, params: P) -> Self
    where
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString,
    {
        Self {
            params: Some(
                params
                    .into_iter()
                    .map(|pair| {
                        let (k, v) = pair.borrow();
                        (k.as_ref().to_owned(), v.to_string())
                    })
                    .collect(),
            ),
            ..self
        }
    }
}

pub type WebSocketStream = WebSocket<MaybeTlsStream<TcpStream>>;

pub fn web_socket_connect<U>(uri: U, headers: Headers) -> Result<WebSocketStream>
where
    U: AsRef<str>,
{
    let ws_uri = if let Some(https_uri) = uri.as_ref().strip_prefix("https://") {
        "wss://".to_owned() + https_uri
    } else if let Some(http_uri) = uri.as_ref().strip_prefix("http://") {
        "ws://".to_owned() + http_uri
    } else {
        return Err(eyre!("No schema in web socket uri provided"));
    };

    let req = http::Request::builder()
        .uri(ws_uri)
        .set_headers(headers)
        .wrap_err("Failed to build web socket request")?
        .body(())
        .wrap_err("Failed to build web socket request")?;

    let (stream, _) = tungstenite::connect(req)?;
    Ok(stream)
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
