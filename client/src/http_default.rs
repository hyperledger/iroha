use std::{borrow::Borrow, net::TcpStream};

use attohttpc::{
    body::{self, Body},
    header::HeaderName,
    RequestBuilder as AttoHttpRequestBuilder, Response as AttoHttpResponse,
};
use eyre::{eyre, Error, Result, WrapErr};
use tungstenite::{stream::MaybeTlsStream, WebSocket};
pub use tungstenite::{Error as WebSocketError, Message as WebSocketMessage};

use crate::http::{Headers, Method, RequestBuilder, Response};

type Bytes = Vec<u8>;

trait AttoHttpReqExt: Sized {
    fn set_headers(self, headers: Headers) -> Result<Self>;
}

impl AttoHttpReqExt for AttoHttpRequestBuilder<body::Bytes<Vec<u8>>> {
    fn set_headers(mut self, headers: Headers) -> Result<Self> {
        for (h, v) in headers {
            let h = HeaderName::from_bytes(h.as_ref())
                .wrap_err_with(|| format!("Failed to parse header name {}", h))?;
            self = self.header(h, v);
        }
        Ok(self)
    }
}

trait HttpReqExt: Sized {
    fn set_headers(self, headers: Headers) -> Result<Self>;
}

impl HttpReqExt for http::request::Builder {
    fn set_headers(mut self, headers: Headers) -> Result<Self> {
        for (h, v) in headers {
            let h = HeaderName::from_bytes(h.as_ref())
                .wrap_err_with(|| format!("Failed to parse header name {}", h))?;
            self = self.header(h, v);
        }
        Ok(self)
    }
}

/// Default request builder & sender implemented on top of `attohttpc` crate.
pub struct DefaultRequestBuilder<T: Body = attohttpc::body::Bytes<Bytes>>(
    AttoHttpRequestBuilder<T>,
);

impl<T> DefaultRequestBuilder<T>
where
    T: Body,
{
    pub fn send(self) -> Result<Response<Bytes>> {
        let Self(mut builder) = self;

        let inspector = builder.inspect();
        let method = inspector.method().clone();
        let url = inspector.url().clone();

        let response = builder
            .send()
            .wrap_err_with(|| format!("Failed to send http {} request to {}", method, url))?;

        ClientResponse(response).try_into()
    }
}

impl RequestBuilder for DefaultRequestBuilder {
    fn build<U, P, K, V>(
        method: Method,
        url: U,
        body: Bytes,
        query_params: P,
        headers: Headers,
    ) -> Result<Self>
    where
        U: AsRef<str>,
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString,
    {
        let builder = AttoHttpRequestBuilder::new(method, url)
            .bytes(body)
            .params(query_params)
            .set_headers(headers)?;

        Ok(Self(builder))
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
