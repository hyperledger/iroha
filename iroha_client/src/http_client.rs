use attohttpc::Response as AttohttpcResponse;
pub use http::{Response, StatusCode};
use std::convert::{TryFrom, TryInto};
use tungstenite::{client::AutoStream, WebSocket};
pub use tungstenite::{Error as WebSocketError, Message as WebSocketMessage};

type Bytes = Vec<u8>;

pub fn post<U>(url: U, body: Bytes) -> Result<Response<Bytes>, String>
where
    U: AsRef<str>,
{
    let url = url.as_ref();
    let response = attohttpc::post(url)
        .bytes(body)
        .send()
        .map_err(|e| format!("Error: {}, failed to send http post request to {}", e, url))?;
    ClientResponse(response).try_into()
}

pub fn get<U>(url: U, body: Bytes) -> Result<Response<Bytes>, String>
where
    U: AsRef<str>,
{
    let url = url.as_ref();
    let response = attohttpc::get(url)
        .bytes(body)
        .send()
        .map_err(|e| format!("Error: {}, failed to send http get request to {}", e, url))?;
    ClientResponse(response).try_into()
}

pub type WebSocketStream = WebSocket<AutoStream>;

pub fn web_socket_connect<U>(url: U) -> Result<WebSocketStream, String>
where
    U: AsRef<str>,
{
    let (stream, _) = tungstenite::connect(url.as_ref()).map_err(|err| err.to_string())?;
    Ok(stream)
}

struct ClientResponse(AttohttpcResponse);

impl TryFrom<ClientResponse> for Response<Bytes> {
    type Error = String;

    fn try_from(response: ClientResponse) -> Result<Self, Self::Error> {
        let ClientResponse(response) = response;
        let mut builder = Response::builder().status(response.status());
        let headers = builder
            .headers_mut()
            .ok_or_else(|| "Failed to get headers map reference.".to_string())?;
        for (key, value) in response.headers() {
            headers.insert(key, value.clone());
        }
        response
            .bytes()
            .map_err(|e| format!("Failed to get response as bytes: {}", e))
            .and_then(|bytes| {
                builder
                    .body(bytes)
                    .map_err(|e| format!("Failed to construct response bytes body: {}", e))
            })
    }
}
