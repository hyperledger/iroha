//! Defaults for various items used in communication over http(s).
//!
//! These implementations rely on the `reqwest` and `tungstenite` crates and
//! provide the default transport layer used by the client. Callers can inject
//! alternative HTTP backends through [`crate::http::HttpTransport`].
use crate::http::{
    HttpTransport, Method, RequestBuilder, Response, TransportFuture, TransportRequest,
};
use eyre::{Error, Result, WrapErr, eyre};
use http::header::{HeaderName, HeaderValue};
use reqwest::blocking::Client as BlockingClient;
use std::sync::{Arc, OnceLock};
use tungstenite::client::IntoClientRequest;
use url::Url;
type Bytes = Vec<u8>;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const RESPONSE_INITIAL_ALLOCATION_BYTES: usize = 16 * 1024;
const RESPONSE_READ_BUFFER_BYTES: usize = 16 * 1024;
/// Shareable handle to one context-local HTTP transport implementation.
#[derive(Clone)]
pub struct DefaultHttpTransport {
    inner: Arc<dyn HttpTransport>,
    deadline: Option<std::time::Instant>,
}

impl std::fmt::Debug for DefaultHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DefaultHttpTransport")
            .finish_non_exhaustive()
    }
}

/// Reqwest connection pools owned by one immutable client context.
///
#[derive(Debug)]
struct ReqwestHttpTransport {
    blocking: OnceLock<BlockingClient>,
    blocking_direct_loopback: OnceLock<BlockingClient>,
    asynchronous: reqwest::Client,
    asynchronous_direct_loopback: reqwest::Client,
}

impl DefaultHttpTransport {
    /// Construct isolated lazy blocking and eager asynchronous HTTP connection pools.
    pub(crate) fn new() -> crate::Result<Self> {
        Ok(Self {
            inner: Arc::new(ReqwestHttpTransport {
                // Building reqwest's blocking client briefly enters an internal
                // runtime. Defer that work until a checked blocking send so
                // constructing an async SDK context inside Tokio stays safe.
                blocking: OnceLock::new(),
                blocking_direct_loopback: OnceLock::new(),
                asynchronous: build_async_http_client()?,
                asynchronous_direct_loopback: build_direct_loopback_async_http_client()?,
            }),
            deadline: None,
        })
    }

    pub(crate) fn from_shared(transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            inner: transport,
            deadline: None,
        }
    }

    pub(crate) fn with_deadline(&self, deadline: std::time::Instant) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            deadline: Some(
                self.deadline
                    .map_or(deadline, |current| current.min(deadline)),
            ),
        }
    }

    pub(crate) fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline
    }

    fn bound_request(&self, mut request: TransportRequest) -> Result<TransportRequest> {
        if let Some(deadline) = self.deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(request_deadline_elapsed());
            }
            request.timeout = Some(
                request
                    .timeout
                    .map_or(remaining, |limit| limit.min(remaining)),
            );
        }
        Ok(request)
    }

    pub(crate) fn send_blocking(&self, request: TransportRequest) -> Result<Response<Bytes>> {
        let response = self.inner.send_blocking(self.bound_request(request)?);
        if self
            .deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(request_deadline_elapsed());
        }
        response
    }

    pub(crate) fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            // Recompute on dispatch, including requests built before earlier I/O.
            let request = self.bound_request(request)?;
            if let Some(deadline) = self.deadline {
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    self.inner.send(request),
                )
                .await
                .map_err(|_| request_deadline_elapsed())?
            } else {
                self.inner.send(request).await
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn shares_pools_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    #[cfg(test)]
    pub(crate) fn mock(
        responder: Arc<dyn Fn(RequestSnapshot) -> Result<Response<Bytes>> + Send + Sync + 'static>,
    ) -> Self {
        Self {
            inner: Arc::new(MockHttpTransport { responder }),
            deadline: None,
        }
    }
}

pub fn request_deadline_elapsed() -> Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "HTTP operation deadline elapsed",
    )
    .into()
}
fn header_name_from_str(str: &str) -> Result<HeaderName> {
    str.parse::<HeaderName>()
        .wrap_err_with(|| format!("Failed to parse header name {str}"))
}
struct PendingRequest {
    method: Method,
    url: Url,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Option<Vec<u8>>,
    timeout: Option<std::time::Duration>,
    max_response_bytes: usize,
    direct_loopback: bool,
}

impl std::fmt::Debug for PendingRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRequest")
            .field("method", &self.method)
            .field("url_origin", &self.url.origin().ascii_serialization())
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field(
                "body_len",
                &self.body.as_ref().map_or(0, std::vec::Vec::len),
            )
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("direct_loopback", &self.direct_loopback)
            .finish()
    }
}
/// Default request builder implemented on top of `reqwest`.
#[derive(Debug)]
pub struct DefaultRequestBuilder {
    inner: Result<PendingRequest>,
    transport: Option<DefaultHttpTransport>,
}
impl DefaultRequestBuilder {
    /// Select one authoritative value for an operation-owned request header.
    pub(crate) fn replace_header<K: AsRef<str>, V: ToString + ?Sized>(
        self,
        key: K,
        value: &V,
    ) -> Self {
        self.and_then(|mut pending| {
            let name = header_name_from_str(key.as_ref())?;
            let value = HeaderValue::from_str(&value.to_string())
                .wrap_err_with(|| format!("Failed to parse header value for {name}"))?;
            pending.headers.retain(|(existing, _)| existing != name);
            pending.headers.push((name, value));
            Ok(pending)
        })
    }
    /// Apply `.and_then()` semantics to the inner `Result` with underlying request state.
    fn and_then<F>(self, fun: F) -> Self
    where
        F: FnOnce(PendingRequest) -> Result<PendingRequest>,
    {
        Self {
            inner: self.inner.and_then(fun),
            transport: self.transport,
        }
    }

    /// Bind the request to the connection pools owned by its client context.
    #[must_use]
    pub(crate) fn with_transport(mut self, transport: DefaultHttpTransport) -> Self {
        self.transport = Some(transport);
        self
    }
    /// Build request by consuming self.
    pub fn build(self) -> Result<DefaultRequest> {
        let transport = self
            .transport
            .ok_or_else(|| eyre!("HTTP request has no owning client transport"))?;
        self.inner.map(|pending| DefaultRequest {
            prepared: TransportRequest {
                method: pending.method,
                url: pending.url,
                headers: pending.headers,
                body: pending.body.unwrap_or_default(),
                timeout: pending.timeout,
                max_response_bytes: pending.max_response_bytes,
                direct_loopback: pending.direct_loopback,
            },
            transport,
        })
    }
    /// Apply per-request timeout (overrides the client default when set).
    #[must_use]
    pub fn timeout(self, timeout: std::time::Duration) -> Self {
        self.and_then(|mut pending| {
            pending.timeout = Some(timeout);
            Ok(pending)
        })
    }
    /// Bound the decoded HTTP response body retained in memory.
    ///
    /// The limit applies even when a peer omits or lies about `Content-Length` and after any
    /// transparent content decoding performed by the HTTP transport.
    #[must_use]
    pub fn max_response_bytes(self, max_response_bytes: usize) -> Self {
        self.and_then(|mut pending| {
            if max_response_bytes == 0 {
                return Err(eyre!("HTTP response byte limit must be positive"));
            }
            pending.max_response_bytes = max_response_bytes;
            Ok(pending)
        })
    }

    /// Require a direct, proxy-free cleartext connection to an exact loopback host.
    pub(crate) fn direct_loopback(self) -> Self {
        self.and_then(|mut pending| {
            let loopback = match pending.url.host() {
                Some(url::Host::Domain(domain)) => domain == "localhost",
                Some(url::Host::Ipv4(address)) => address.is_loopback(),
                Some(url::Host::Ipv6(address)) => address.is_loopback(),
                None => false,
            };
            if pending.url.scheme() != "http" || !loopback {
                return Err(eyre!(
                    "direct cleartext HTTP is restricted to exact localhost, 127/8, or ::1 loopback hosts"
                ));
            }
            pending.direct_loopback = true;
            Ok(pending)
        })
    }
}
/// Request built by [`DefaultRequestBuilder`].
#[derive(Debug)]
pub struct DefaultRequest {
    prepared: TransportRequest,
    transport: DefaultHttpTransport,
}
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct RequestSnapshot {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout: Option<std::time::Duration>,
    pub max_response_bytes: usize,
    pub direct_loopback: bool,
}
#[cfg(test)]
impl DefaultRequest {
    fn snapshot(&self) -> RequestSnapshot {
        let headers_vec = self
            .prepared
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    std::str::from_utf8(value.as_bytes())
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
            .collect();
        RequestSnapshot {
            method: self.prepared.method.clone(),
            url: self.prepared.url.clone(),
            headers: headers_vec,
            body: self.prepared.body.clone(),
            timeout: self.prepared.timeout,
            max_response_bytes: self.prepared.max_response_bytes,
            direct_loopback: self.prepared.direct_loopback,
        }
    }
}
impl DefaultRequest {
    #[cfg(test)]
    #[must_use]
    pub fn uri(&self) -> &Url {
        &self.prepared.url
    }
    /// Sends itself and returns byte response
    ///
    /// # Errors
    /// Fails if request building and sending fails or response transformation fails
    pub(crate) fn send_blocking(self) -> Result<Response<Bytes>> {
        crate::blocking::reject_inside_async_runtime()?;
        let maximum = self.prepared.max_response_bytes;
        let response = self.transport.send_blocking(self.prepared)?;
        enforce_transport_response_bound(response, maximum)
    }

    /// Send this request asynchronously through its owning client context.
    pub(crate) async fn send(self) -> Result<Response<Bytes>> {
        let maximum = self.prepared.max_response_bytes;
        let response = self.transport.send(self.prepared).await?;
        enforce_transport_response_bound(response, maximum)
    }
}

fn enforce_transport_response_bound(
    response: Response<Bytes>,
    maximum: usize,
) -> Result<Response<Bytes>> {
    if maximum == 0 {
        return Err(eyre!("HTTP response byte limit must be positive"));
    }
    if response.body().len() > maximum {
        return Err(crate::Error::ResponseTooLarge {
            maximum,
            actual: Some(response.body().len()),
        }
        .into());
    }
    if response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > u64::try_from(maximum).unwrap_or(u64::MAX))
    {
        return Err(crate::Error::ResponseTooLarge {
            maximum,
            actual: None,
        }
        .into());
    }
    Ok(response)
}

impl HttpTransport for ReqwestHttpTransport {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Bytes>> {
        let TransportRequest {
            method,
            url,
            headers,
            body,
            timeout,
            max_response_bytes,
            direct_loopback,
        } = request;
        let client = if direct_loopback {
            self.blocking_direct_loopback
                .get_or_init(build_direct_loopback_http_client)
        } else {
            self.blocking.get_or_init(build_http_client)
        };
        let mut builder = client.request(method.clone(), url.clone());
        for (name, value) in &headers {
            builder = builder.header(name.clone(), value.clone());
        }
        if !body.is_empty() {
            builder = builder.body(body);
        }
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder
            .send()
            .wrap_err_with(|| format!("Failed to send http {method} request to {url}"))?;
        ClientResponse {
            response,
            max_response_bytes,
        }
        .try_into()
    }

    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            let TransportRequest {
                method,
                url,
                headers,
                body,
                timeout,
                max_response_bytes,
                direct_loopback,
            } = request;
            let client = if direct_loopback {
                &self.asynchronous_direct_loopback
            } else {
                &self.asynchronous
            };
            let mut builder = client.request(method.clone(), url.clone());
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
            if !body.is_empty() {
                builder = builder.body(body);
            }
            if let Some(timeout) = timeout {
                builder = builder.timeout(timeout);
            }
            let response = builder
                .send()
                .await
                .wrap_err_with(|| format!("Failed to send http {method} request to {url}"))?;
            crate::client::bounded_async_response::into_response(response, max_response_bytes).await
        })
    }
}

#[cfg(test)]
struct MockHttpTransport {
    responder: Arc<dyn Fn(RequestSnapshot) -> Result<Response<Bytes>> + Send + Sync + 'static>,
}

#[cfg(test)]
impl std::fmt::Debug for MockHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MockHttpTransport")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl HttpTransport for MockHttpTransport {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Bytes>> {
        (self.responder)(RequestSnapshot::from(&request))
    }

    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        let response = (self.responder)(RequestSnapshot::from(&request));
        Box::pin(async move { response })
    }
}

#[cfg(test)]
impl From<&TransportRequest> for RequestSnapshot {
    fn from(request: &TransportRequest) -> Self {
        let headers = request
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    std::str::from_utf8(value.as_bytes())
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
            .collect();
        Self {
            method: request.method.clone(),
            url: request.url.clone(),
            headers,
            body: request.body.clone(),
            timeout: request.timeout,
            max_response_bytes: request.max_response_bytes,
            direct_loopback: request.direct_loopback,
        }
    }
}
impl RequestBuilder for DefaultRequestBuilder {
    fn new(method: Method, url: Url) -> Self {
        Self {
            inner: Ok(PendingRequest {
                method,
                url,
                headers: Vec::new(),
                body: None,
                timeout: None,
                max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
                direct_loopback: false,
            }),
            transport: None,
        }
    }
    fn header<K: AsRef<str>, V: ToString + ?Sized>(self, key: K, value: &V) -> Self {
        self.and_then(|mut pending| {
            let name = header_name_from_str(key.as_ref())?;
            let header_value = HeaderValue::from_str(&value.to_string())
                .wrap_err_with(|| format!("Failed to parse header value for {name}"))?;
            pending.headers.push((name, header_value));
            Ok(pending)
        })
    }
    fn param<K: AsRef<str>, V: ToString + ?Sized>(self, key: K, value: &V) -> Self {
        self.and_then(|mut pending| {
            {
                let mut pairs = pending.url.query_pairs_mut();
                pairs.append_pair(key.as_ref(), &value.to_string());
            }
            Ok(pending)
        })
    }
    fn body(self, data: Vec<u8>) -> Self {
        self.and_then(|mut pending| {
            pending.body = Some(data);
            Ok(pending)
        })
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
    pub fn build(self) -> Result<http::Request<()>> {
        let builder = self.0?;
        let mut request = builder
            .uri_ref()
            .ok_or_else(|| eyre!("Missing URI"))?
            .into_client_request()?;
        for (header, value) in builder
            .headers_ref()
            .ok_or_else(|| eyre!("No headers found"))?
        {
            request.headers_mut().entry(header).or_insert(value.clone());
        }
        Ok(request)
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
fn blocking_http_client_builder() -> reqwest::blocking::ClientBuilder {
    BlockingClient::builder()
        // This transport carries one-shot signed requests. Following a redirect
        // could replay a body after the original endpoint already admitted it.
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60))
}
fn build_http_client() -> BlockingClient {
    blocking_http_client_builder()
        .build()
        .expect("Failed to build blocking HTTP client")
}
fn build_async_http_client() -> crate::Result<reqwest::Client> {
    async_http_client_builder()
        .build()
        .map_err(|error| crate::Error::TransportConstruction {
            details: error.to_string(),
        })
}
fn async_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        // A redirect can arrive after ingress admitted a one-shot signed transaction.
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60))
}
fn build_direct_loopback_http_client() -> BlockingClient {
    let addresses = [
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0)),
    ];
    blocking_http_client_builder()
        .no_proxy()
        .resolve_to_addrs("localhost", &addresses)
        .build()
        .expect("Failed to build direct loopback HTTP client")
}
fn build_direct_loopback_async_http_client() -> crate::Result<reqwest::Client> {
    let addresses = [
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0)),
    ];
    async_http_client_builder()
        .no_proxy()
        .resolve_to_addrs("localhost", &addresses)
        .build()
        .map_err(|error| crate::Error::TransportConstruction {
            details: error.to_string(),
        })
}
struct ClientResponse {
    response: reqwest::blocking::Response,
    max_response_bytes: usize,
}
fn read_bounded_response_body(
    reader: &mut impl std::io::Read,
    advertised_length: Option<u64>,
    max_response_bytes: usize,
) -> Result<Vec<u8>> {
    if max_response_bytes == 0 {
        return Err(eyre!("HTTP response byte limit must be positive"));
    }
    let max_response_bytes_u64 = u64::try_from(max_response_bytes).unwrap_or(u64::MAX);
    if let Some(length) = advertised_length.filter(|length| *length > max_response_bytes_u64) {
        return Err(eyre!(
            "HTTP response Content-Length {length} exceeds the {max_response_bytes}-byte limit"
        ));
    }
    let initial_capacity = response_initial_capacity(advertised_length, max_response_bytes);
    let mut body = Vec::new();
    reserve_response_body_capacity(&mut body, initial_capacity, max_response_bytes)?;
    let mut buffer = [0_u8; RESPONSE_READ_BUFFER_BYTES];
    loop {
        let remaining = max_response_bytes - body.len();
        let read_capacity = remaining.min(buffer.len());
        if read_capacity == 0 {
            let read = read_response_body_chunk(reader, &mut buffer[..1])?;
            if read == 0 {
                break;
            }
            return Err(eyre!(
                "HTTP response body exceeds the {max_response_bytes}-byte limit"
            ));
        }
        let read = read_response_body_chunk(reader, &mut buffer[..read_capacity])?;
        if read == 0 {
            break;
        }
        let required_len = body
            .len()
            .checked_add(read)
            .ok_or_else(|| eyre!("HTTP response body length overflow"))?;
        reserve_response_body_capacity(&mut body, required_len, max_response_bytes)?;
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(body)
}
fn response_initial_capacity(advertised_length: Option<u64>, max_response_bytes: usize) -> usize {
    advertised_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(RESPONSE_INITIAL_ALLOCATION_BYTES)
        .min(RESPONSE_INITIAL_ALLOCATION_BYTES)
        .min(max_response_bytes)
}
fn read_response_body_chunk(reader: &mut impl std::io::Read, buffer: &mut [u8]) -> Result<usize> {
    loop {
        match reader.read(buffer) {
            Ok(read) if read <= buffer.len() => return Ok(read),
            Ok(read) => {
                return Err(eyre!(
                    "HTTP response reader reported {read} bytes for a {}-byte buffer",
                    buffer.len()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).wrap_err("Failed to read HTTP response body"),
        }
    }
}
fn reserve_response_body_capacity(
    body: &mut Vec<u8>,
    required_len: usize,
    max_response_bytes: usize,
) -> Result<()> {
    if required_len > max_response_bytes {
        return Err(eyre!(
            "HTTP response body exceeds the {max_response_bytes}-byte limit"
        ));
    }
    if required_len <= body.capacity() {
        return Ok(());
    }
    let target_capacity = body
        .capacity()
        .saturating_mul(2)
        .max(required_len)
        .min(max_response_bytes);
    let additional = target_capacity
        .checked_sub(body.len())
        .ok_or_else(|| eyre!("HTTP response body capacity accounting underflow"))?;
    body.try_reserve_exact(additional)
        .wrap_err_with(|| format!("Failed to reserve {target_capacity} HTTP response body bytes"))
}
impl TryFrom<ClientResponse> for Response<Bytes> {
    type Error = Error;
    fn try_from(response: ClientResponse) -> Result<Self> {
        let ClientResponse {
            mut response,
            max_response_bytes,
        } = response;
        let status = response.status();
        let advertised_length = response.content_length();
        let headers: Vec<(HeaderName, HeaderValue)> = response
            .headers()
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let body =
            read_bounded_response_body(&mut response, advertised_length, max_response_bytes)?;
        let mut builder = Response::builder().status(status);
        let headers_map = builder
            .headers_mut()
            .ok_or_else(|| eyre!("Failed to get headers map reference."))?;
        for (key, value) in headers {
            headers_map.append(key, value);
        }
        builder
            .body(body)
            .wrap_err("Failed to construct response bytes body")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use http::header::AUTHORIZATION;
    use std::{
        io::{ErrorKind, Read, Write},
        net::TcpListener,
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    fn owned_request_builder(method: Method, url: Url) -> DefaultRequestBuilder {
        DefaultRequestBuilder::new(method, url)
            .with_transport(DefaultHttpTransport::new().expect("test HTTP transport"))
    }

    fn mocked_request_builder(
        method: Method,
        url: Url,
        responder: impl Fn(RequestSnapshot) -> Result<Response<Bytes>> + Send + Sync + 'static,
    ) -> DefaultRequestBuilder {
        DefaultRequestBuilder::new(method, url)
            .with_transport(DefaultHttpTransport::mock(Arc::new(responder)))
    }

    #[tokio::test]
    async fn default_transport_construction_is_safe_inside_async_runtime() {
        let transport = DefaultHttpTransport::new().expect("test HTTP transport");
        let clone = transport.clone();
        assert!(transport.shares_pools_with(&clone));
        drop(clone);
        drop(transport);
    }

    #[test]
    fn operation_deadline_bounds_sequential_blocking_dispatches() {
        use std::sync::Mutex;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&observed);
        let transport = DefaultHttpTransport::mock(Arc::new(move |request| {
            recorded
                .lock()
                .expect("recorded budgets")
                .push(request.timeout.expect("deadline budget"));
            thread::sleep(Duration::from_millis(25));
            Ok(Response::new(Vec::new()))
        }))
        .with_deadline(Instant::now() + Duration::from_secs(2));
        let request = || {
            DefaultRequestBuilder::new(Method::GET, "http://localhost/status".parse().unwrap())
                .with_transport(transport.clone())
                .timeout(Duration::from_secs(70))
                .build()
                .unwrap()
        };
        // Build both first: the second dispatch must account for earlier I/O.
        let first = request();
        let second = request();
        first.send_blocking().expect("first observation");
        second.send_blocking().expect("second observation");
        let budgets = observed.lock().expect("recorded budgets");
        assert!(budgets[0] <= Duration::from_secs(2));
        assert!(budgets[1] < budgets[0]);
    }

    #[test]
    fn expired_operation_deadline_prevents_dispatch_and_cannot_be_extended() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::clone(&count);
        let original = DefaultHttpTransport::mock(Arc::new(move |_| {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(Vec::new()))
        }));
        let bounded = original
            .with_deadline(Instant::now())
            .with_deadline(Instant::now() + Duration::from_secs(60));
        let request = |transport| {
            DefaultRequestBuilder::new(
                Method::POST,
                "http://localhost/transaction".parse().unwrap(),
            )
            .with_transport(transport)
            .body(vec![1, 2, 3])
            .build()
            .unwrap()
        };
        let error = request(bounded)
            .send_blocking()
            .expect_err("expired POST must never dispatch");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        request(original)
            .send_blocking()
            .expect("source transport remains unbounded");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn operation_deadline_cancels_injected_async_transport() {
        #[derive(Debug)]
        struct NeverCompletes;
        impl HttpTransport for NeverCompletes {
            fn send_blocking(&self, _: TransportRequest) -> Result<Response<Bytes>> {
                panic!("asynchronous test")
            }
            fn send(&self, _: TransportRequest) -> TransportFuture<'_> {
                Box::pin(std::future::pending())
            }
        }
        let transport = DefaultHttpTransport::from_shared(Arc::new(NeverCompletes))
            .with_deadline(Instant::now() + Duration::from_millis(30));
        let request =
            DefaultRequestBuilder::new(Method::GET, "http://localhost/status".parse().unwrap())
                .with_transport(transport)
                .build()
                .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), request.send())
            .await
            .expect("absolute deadline cancels custom transport");
        let error = result.expect_err("pending transport cannot outlive deadline");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::TimedOut
        );
    }

    #[test]
    fn direct_loopback_builder_is_fail_closed_and_leaves_https_proxy_capable() {
        for allowed in [
            "http://localhost:8080/v1/fees/quote",
            "http://127.44.55.66:8080/v1/fees/quote",
            "http://[::1]:8080/v1/fees/quote",
        ] {
            let request = owned_request_builder(
                crate::http::Method::POST,
                Url::parse(allowed).expect("loopback URL"),
            )
            .direct_loopback()
            .build()
            .expect("direct loopback request");
            assert!(request.snapshot().direct_loopback);
        }
        for rejected in [
            "http://example.com/v1/fees/quote",
            "http://[::2]/v1/fees/quote",
            "https://localhost:8080/v1/fees/quote",
        ] {
            assert!(
                owned_request_builder(
                    crate::http::Method::POST,
                    Url::parse(rejected).expect("rejected URL"),
                )
                .direct_loopback()
                .build()
                .is_err(),
                "direct-loopback mode admitted {rejected}"
            );
        }
        let https = owned_request_builder(
            crate::http::Method::POST,
            Url::parse("https://fees.example/v1/fees/quote").expect("HTTPS URL"),
        )
        .build()
        .expect("ordinary HTTPS request");
        assert!(
            !https.snapshot().direct_loopback,
            "HTTPS must retain the ordinary system-proxy-capable transport"
        );
    }

    #[test]
    fn loopback_transport_ignores_proxy_environment() {
        fn serve_once(listener: &TcpListener, status: &str) -> bool {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets can inherit the listener's nonblocking mode.
                        stream
                            .set_nonblocking(false)
                            .expect("blocking proxy test stream");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("proxy test stream read timeout");
                        let mut request = [0_u8; 2048];
                        let read = stream.read(&mut request).expect("read proxy test request");
                        assert!(read > 0, "proxy test request must not be empty");
                        write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .expect("write proxy test response");
                        return true;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return false;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("proxy test listener failed: {error}"),
                }
            }
        }

        const CHILD: &str = "IROHA_LOOPBACK_PROXY_TEST_CHILD";
        const TARGET: &str = "IROHA_LOOPBACK_PROXY_TEST_TARGET";
        if std::env::var_os(CHILD).is_some() {
            let url = std::env::var(TARGET).expect("child target URL");
            let response = owned_request_builder(
                crate::http::Method::POST,
                Url::parse(&url).expect("child target URL parse"),
            )
            .direct_loopback()
            .body(b"authenticated fee quote".to_vec())
            .timeout(Duration::from_secs(2))
            .build()
            .expect("child direct request")
            .send_blocking()
            .expect("child direct response");
            assert_eq!(response.status(), http::StatusCode::OK);
            return;
        }

        let target_listener = TcpListener::bind("127.0.0.1:0").expect("target listener");
        let target_address = target_listener.local_addr().expect("target address");
        let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("proxy listener");
        let proxy_address = proxy_listener.local_addr().expect("proxy address");
        let target_server = thread::spawn(move || serve_once(&target_listener, "200 OK"));
        let proxy_server = thread::spawn(move || serve_once(&proxy_listener, "502 Bad Gateway"));
        let proxy_url = format!("http://{proxy_address}");
        let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "http_default::tests::loopback_transport_ignores_proxy_environment",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(
                TARGET,
                format!("http://localhost:{}/v1/fees/quote", target_address.port()),
            )
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("REQUEST_METHOD")
            .output()
            .expect("run isolated proxy child");
        let target_received = target_server.join().expect("target server");
        let proxy_received = proxy_server.join().expect("proxy server");
        assert!(
            child.status.success(),
            "isolated direct-loopback child failed: {}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(
            target_received,
            "direct loopback target received no request"
        );
        assert!(
            !proxy_received,
            "HTTP_PROXY/ALL_PROXY captured the cleartext loopback request"
        );
    }

    #[test]
    fn owned_http_client_does_not_follow_signed_body_redirects() {
        for (status_code, reason) in [
            (307_u16, "Temporary Redirect"),
            (308_u16, "Permanent Redirect"),
        ] {
            let redirect_listener = TcpListener::bind("127.0.0.1:0").expect("redirect listener");
            let redirect_addr = redirect_listener.local_addr().expect("redirect address");
            let target_listener = TcpListener::bind("127.0.0.1:0").expect("target listener");
            let target_addr = target_listener.local_addr().expect("target address");
            target_listener
                .set_nonblocking(true)
                .expect("nonblocking target listener");
            let redirect_server = thread::spawn(move || {
                let (mut stream, _) = redirect_listener.accept().expect("redirect request");
                let mut request = [0_u8; 1024];
                let request_len = stream.read(&mut request).expect("read redirect request");
                assert!(request_len > 0, "redirect request must not be empty");
                write!(
                    stream,
                    "HTTP/1.1 {status_code} {reason}\r\nLocation: http://{target_addr}/target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write redirect response");
            });
            let target_server = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_millis(750);
                loop {
                    match target_listener.accept() {
                        Ok((mut stream, _)) => {
                            let mut request = [0_u8; 1024];
                            let request_len =
                                stream.read(&mut request).expect("read redirected request");
                            assert!(request_len > 0, "redirected request must not be empty");
                            stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .expect("write target response");
                            return true;
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return false;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("target listener failed: {error}"),
                    }
                }
            });
            let response = build_http_client()
                .post(format!("http://{redirect_addr}/query"))
                .body(vec![0x01, 0x02, 0x03])
                .send()
                .expect("redirect response");
            redirect_server.join().expect("redirect server");
            let followed = target_server.join().expect("target server");
            assert_eq!(response.status().as_u16(), status_code);
            assert!(!followed, "one-shot signed body must not be redirected");
        }
    }
    #[test]
    fn owned_http_client_does_not_retry_signed_body_after_server_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener");
        let address = listener.local_addr().expect("test address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("first request");
            let mut request = [0_u8; 1024];
            let request_len = stream.read(&mut request).expect("read first request");
            assert!(request_len > 0, "first request must not be empty");
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write first response");
            drop(stream);
            listener
                .set_nonblocking(true)
                .expect("nonblocking retry listener");
            let deadline = Instant::now() + Duration::from_millis(750);
            loop {
                match listener.accept() {
                    Ok((_stream, _)) => return true,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return false;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("retry listener failed: {error}"),
                }
            }
        });
        let response = build_http_client()
            .post(format!("http://{address}/transaction"))
            .body(vec![0x01, 0x02, 0x03])
            .send()
            .expect("server response");
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !server.join().expect("test server"),
            "signed body was retried"
        );
    }
    #[test]
    fn blocking_send_rejects_tokio_multi_thread_runtime() {
        let request = mocked_request_builder(
            crate::http::Method::GET,
            Url::parse("http://127.0.0.1/status").expect("url"),
            |snapshot| {
                assert_eq!(snapshot.url.as_str(), "http://127.0.0.1/status");
                assert_eq!(snapshot.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
                Response::builder()
                    .status(http::StatusCode::OK)
                    .body(Vec::new())
                    .map_err(Into::into)
            },
        )
        .build()
        .expect("build request");
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let error = rt
            .block_on(async { request.send_blocking() })
            .expect_err("blocking send inside Tokio must reject");
        let typed = error
            .downcast_ref::<crate::blocking::BlockingCallError>()
            .expect("typed blocking error");
        assert_eq!(
            typed.async_runtime_flavor(),
            Some(crate::blocking::AsyncRuntimeFlavor::MultiThread)
        );
    }
    #[test]
    fn blocking_send_rejects_tokio_current_thread_runtime() {
        let request = mocked_request_builder(
            crate::http::Method::GET,
            Url::parse("http://127.0.0.1/status").expect("url"),
            |snapshot| {
                assert_eq!(snapshot.url.as_str(), "http://127.0.0.1/status");
                assert_eq!(snapshot.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
                Response::builder()
                    .status(http::StatusCode::OK)
                    .body(Vec::new())
                    .map_err(Into::into)
            },
        )
        .build()
        .expect("build request");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let error = rt
            .block_on(async { request.send_blocking() })
            .expect_err("blocking send inside Tokio must reject");
        let typed = error
            .downcast_ref::<crate::blocking::BlockingCallError>()
            .expect("typed blocking error");
        assert_eq!(
            typed.async_runtime_flavor(),
            Some(crate::blocking::AsyncRuntimeFlavor::CurrentThread)
        );
    }
    #[test]
    fn builder_timeout_is_forwarded() {
        let timeout = std::time::Duration::from_secs(2);
        let request = mocked_request_builder(
            crate::http::Method::GET,
            Url::parse("http://127.0.0.1/status").expect("url"),
            move |snapshot| {
                assert_eq!(snapshot.timeout, Some(timeout));
                Response::builder()
                    .status(http::StatusCode::OK)
                    .body(Vec::new())
                    .map_err(Into::into)
            },
        )
        .timeout(timeout)
        .build()
        .expect("build request");
        let result = request.send_blocking();
        assert!(result.is_ok());
    }
    #[test]
    fn builder_response_limit_is_forwarded() {
        let request = mocked_request_builder(
            crate::http::Method::GET,
            Url::parse("http://127.0.0.1/status").expect("url"),
            |snapshot| {
                assert_eq!(snapshot.max_response_bytes, 4096);
                Response::builder()
                    .status(http::StatusCode::OK)
                    .body(Vec::new())
                    .map_err(Into::into)
            },
        )
        .max_response_bytes(4096)
        .build()
        .expect("build request");
        let result = request.send_blocking();
        assert!(result.is_ok());
    }

    #[test]
    fn request_debug_redacts_credentials_url_details_and_body() {
        const PASSWORD: &str = "transport-password-secret";
        const PATH_SECRET: &str = "private-account-42";
        const QUERY_SECRET: &str = "query-token-secret";
        const FRAGMENT_SECRET: &str = "fragment-secret";
        const HEADER_SECRET: &str = "Bearer authorization-secret";
        const BODY_SECRET: &[u8] = b"signed-body-secret";

        let url = Url::parse(&format!(
            "https://sdk-user:{PASSWORD}@example.com/{PATH_SECRET}?token={QUERY_SECRET}#{FRAGMENT_SECRET}"
        ))
        .expect("secret-bearing URL");
        let pending =
            mocked_request_builder(Method::POST, url.clone(), |_| Ok(Response::new(Vec::new())))
                .header(AUTHORIZATION.as_str(), HEADER_SECRET)
                .body(BODY_SECRET.to_vec());
        let pending_debug = format!("{pending:?}");
        let request = mocked_request_builder(Method::POST, url, |_| Ok(Response::new(Vec::new())))
            .header(AUTHORIZATION.as_str(), HEADER_SECRET)
            .body(BODY_SECRET.to_vec())
            .build()
            .expect("built request");
        let request_debug = format!("{request:?}");

        for rendered in [&pending_debug, &request_debug] {
            assert!(rendered.contains("https://example.com"));
            assert!(rendered.contains("authorization"));
            assert!(rendered.contains(&format!("body_len: {}", BODY_SECRET.len())));
            for secret in [
                "sdk-user",
                PASSWORD,
                PATH_SECRET,
                QUERY_SECRET,
                FRAGMENT_SECRET,
                HEADER_SECRET,
                std::str::from_utf8(BODY_SECRET).expect("ASCII body"),
            ] {
                assert!(
                    !rendered.contains(secret),
                    "request Debug exposed secret {secret:?}: {rendered}"
                );
            }
        }
    }

    #[test]
    fn injected_transport_cannot_bypass_response_bounds_sync_or_async() {
        let build_adversarial_request = || {
            mocked_request_builder(
                Method::GET,
                Url::parse("https://example.com/status").expect("test URL"),
                |_| Ok(Response::new(vec![0x5a; 9])),
            )
            .max_response_bytes(8)
            .build()
            .expect("built adversarial request")
        };

        let sync_error = build_adversarial_request()
            .send_blocking()
            .expect_err("sync custom transport response must be bounded by the SDK");
        {
            let actual_error =
                (sync_error.downcast_ref::<crate::Error>()).expect("original SDK error source");
            let crate::Error::ResponseTooLarge {
                maximum: actual_maximum,
                actual: actual_actual,
            } = &actual_error
            else {
                panic!("unexpected SDK error: {actual_error:?}");
            };
            assert_eq!((actual_maximum, actual_actual,), (&(8), &(Some(9)),));
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("async test runtime");
        let async_error = runtime
            .block_on(build_adversarial_request().send())
            .expect_err("async custom transport response must be bounded by the SDK");
        {
            let actual_error =
                (async_error.downcast_ref::<crate::Error>()).expect("original SDK error source");
            let crate::Error::ResponseTooLarge {
                maximum: actual_maximum,
                actual: actual_actual,
            } = &actual_error
            else {
                panic!("unexpected SDK error: {actual_error:?}");
            };
            assert_eq!((actual_maximum, actual_actual,), (&(8), &(Some(9)),));
        };
    }
    #[test]
    fn request_snapshot_preserves_utf8_header_bytes_used_by_account_ids() {
        let account = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
        let request = owned_request_builder(
            crate::http::Method::GET,
            Url::parse("http://127.0.0.1/status").expect("url"),
        )
        .header("x-iroha-account", &account)
        .build()
        .expect("build request");
        let snapshot = request.snapshot();
        assert_eq!(
            snapshot.headers,
            vec![("x-iroha-account".to_owned(), account.to_owned())]
        );
    }
    #[test]
    fn builder_rejects_zero_response_limit() {
        let error = owned_request_builder(
            crate::http::Method::GET,
            Url::parse("http://127.0.0.1/status").expect("url"),
        )
        .max_response_bytes(0)
        .build()
        .expect_err("zero response limit must be rejected");
        assert!(error.to_string().contains("must be positive"));
    }
    #[test]
    fn bounded_response_rejects_zero_limit_without_reading() {
        struct PanicReader;
        impl std::io::Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("zero response limit must reject before reading")
            }
        }
        let error = read_bounded_response_body(&mut PanicReader, None, 0)
            .expect_err("zero response limit must be rejected");
        assert!(error.to_string().contains("must be positive"));
    }
    #[test]
    fn bounded_response_rejects_advertised_oversize_without_reading() {
        struct PanicReader;
        impl std::io::Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("oversized Content-Length must reject before reading")
            }
        }
        let error = read_bounded_response_body(&mut PanicReader, Some(9), 8)
            .expect_err("advertised oversized response must reject");
        assert!(error.to_string().contains("Content-Length"));
    }
    #[test]
    fn bounded_response_accepts_exact_limit() {
        for advertised_length in [None, Some(0), Some(1), Some(8)] {
            let mut reader = std::io::Cursor::new(b"12345678");
            let body = read_bounded_response_body(&mut reader, advertised_length, 8)
                .expect("exact-limit response must be accepted");
            assert_eq!(body, b"12345678");
        }
    }
    #[test]
    fn bounded_response_rejects_missing_understated_or_encoded_content_length() {
        // A small advertised length with a larger decoded reader models transparent
        // decompression without coupling this unit test to a particular content codec.
        for advertised_length in [None, Some(0), Some(1), Some(8)] {
            let mut reader = std::io::Cursor::new(b"123456789");
            let error = read_bounded_response_body(&mut reader, advertised_length, 8)
                .expect_err("actual oversized response must reject");
            assert!(error.to_string().contains("body exceeds"));
        }
    }
    #[test]
    fn bounded_response_does_not_preallocate_from_large_content_length() {
        let advertised_length = u64::from(u32::MAX);
        let max_response_bytes = usize::try_from(advertised_length)
            .expect("supported targets represent a u32 response limit");
        assert_eq!(
            response_initial_capacity(Some(advertised_length), max_response_bytes),
            RESPONSE_INITIAL_ALLOCATION_BYTES
        );
        assert_eq!(response_initial_capacity(None, 7), 7);
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());
        let body =
            read_bounded_response_body(&mut reader, Some(advertised_length), max_response_bytes)
                .expect("empty body with an in-range advertised length must be readable");
        assert!(body.is_empty());
    }
    #[test]
    fn bounded_response_never_reserves_beyond_limit() {
        let mut body = Vec::with_capacity(16);
        let original_capacity = body.capacity();
        let error = reserve_response_body_capacity(&mut body, 9, 8)
            .expect_err("capacity above the response limit must be rejected");
        assert!(error.to_string().contains("body exceeds"));
        assert_eq!(body.capacity(), original_capacity);
    }
    #[test]
    fn bounded_response_reads_only_one_sentinel_byte_beyond_limit() {
        #[derive(Default)]
        struct InfiniteReader {
            requested_lengths: Vec<usize>,
        }
        impl std::io::Read for InfiniteReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.requested_lengths.push(buffer.len());
                buffer.fill(0x5a);
                Ok(buffer.len())
            }
        }
        let mut reader = InfiniteReader::default();
        let error = read_bounded_response_body(&mut reader, None, 8)
            .expect_err("an unbounded reader must be rejected after the sentinel byte");
        assert!(error.to_string().contains("body exceeds"));
        assert_eq!(reader.requested_lengths, [8, 1]);
    }
    #[test]
    fn bounded_response_rejects_reader_length_contract_violation_without_panicking() {
        struct MisreportingReader;
        impl std::io::Read for MisreportingReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                Ok(buffer.len() + 1)
            }
        }
        let error = read_bounded_response_body(&mut MisreportingReader, None, 8)
            .expect_err("a reader cannot report more bytes than its buffer");
        assert!(error.to_string().contains("reader reported"));
    }
    #[test]
    fn bounded_response_propagates_reader_failure() {
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("adversarial read failure"))
            }
        }
        let error = read_bounded_response_body(&mut FailingReader, None, 8)
            .expect_err("reader failure must reject");
        assert!(error.to_string().contains("Failed to read"));
    }
    #[test]
    fn bounded_response_discards_partial_body_on_reader_failure() {
        struct PartialThenFailingReader {
            first_read: bool,
        }
        impl std::io::Read for PartialThenFailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.first_read {
                    return Err(std::io::Error::other("adversarial failure after bytes"));
                }
                self.first_read = true;
                buffer[..4].copy_from_slice(b"1234");
                Ok(4)
            }
        }
        let error = read_bounded_response_body(
            &mut PartialThenFailingReader { first_read: false },
            None,
            8,
        )
        .expect_err("partial body followed by a reader failure must reject");
        assert!(format!("{error:#}").contains("adversarial failure after bytes"));
    }
    #[test]
    fn bounded_response_retries_interrupted_reads() {
        struct InterruptedReader {
            state: u8,
        }
        impl std::io::Read for InterruptedReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                match self.state {
                    0 => {
                        self.state = 1;
                        Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
                    }
                    1 => {
                        self.state = 2;
                        buffer[..4].copy_from_slice(b"1234");
                        Ok(4)
                    }
                    _ => Ok(0),
                }
            }
        }
        let body = read_bounded_response_body(&mut InterruptedReader { state: 0 }, None, 8)
            .expect("interrupted reads must be retried");
        assert_eq!(body, b"1234");
    }
}
