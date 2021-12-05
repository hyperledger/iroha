use std::{borrow::Borrow, collections::HashMap, net::TcpStream};

use attohttpc::{body, header::HeaderName, RequestBuilder, Response as AttohttpcResponse};
use eyre::{eyre, Error, Result, WrapErr};
pub use http::{Response, StatusCode};
use tungstenite::{stream::MaybeTlsStream, WebSocket};
pub use tungstenite::{Error as WebSocketError, Message as WebSocketMessage};

type Bytes = Vec<u8>;
pub type Headers = HashMap<String, String>;

trait AttoHttpReqExt: Sized {
    fn set_headers(self, headers: Headers) -> Result<Self>;
}

impl AttoHttpReqExt for RequestBuilder<body::Bytes<Vec<u8>>> {
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

pub fn post<U, P, K, V>(
    url: U,
    body: Bytes,
    query_params: P,
    headers: Headers,
) -> Result<Response<Bytes>>
where
    U: AsRef<str>,
    P: IntoIterator,
    P::Item: Borrow<(K, V)>,
    K: AsRef<str>,
    V: ToString,
{
    let url = url.as_ref();
    let response = attohttpc::post(url)
        .bytes(body)
        .params(query_params)
        .set_headers(headers)?
        .send()
        .wrap_err_with(|| format!("Failed to send http post request to {}", url))?;
    ClientResponse(response).try_into()
}

pub fn get<U, P, K, V>(
    url: U,
    body: Bytes,
    query_params: P,
    headers: Headers,
) -> Result<Response<Bytes>>
where
    U: AsRef<str>,
    P: IntoIterator,
    P::Item: Borrow<(K, V)>,
    K: AsRef<str>,
    V: ToString,
{
    let url = url.as_ref();
    let response = attohttpc::get(url)
        .bytes(body)
        .params(query_params)
        .set_headers(headers)?
        .send()
        .wrap_err_with(|| format!("Failed to send http get request to {}", url))?;
    ClientResponse(response).try_into()
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

struct ClientResponse(AttohttpcResponse);

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
