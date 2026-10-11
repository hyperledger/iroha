//! Unsigned bounded HTTPS reads before a ledger identity or network is known.

use std::{sync::Arc, time::Instant};

use super::{HttpTransport, Method, Response, StatusCode, TransportRequest};
use crate::http_default::DefaultHttpTransport;
use url::Url;

/// Hard response ceiling for credential-free public reads, in decoded bytes.
pub const MAX_PUBLIC_READ_BYTES: usize = 64 * 1024 * 1024;

/// Closed public-read failures; remote bodies, URLs and transport diagnostics are not exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublicHttpError {
    /// The URL or response bound violates the public-read policy.
    #[error("invalid public HTTPS read policy")]
    Invalid,
    /// The operation's absolute deadline has elapsed.
    #[error("public HTTPS read deadline expired")]
    Deadline,
    /// HTTP construction, transport or execution context failed.
    #[error("public HTTPS transport failed")]
    Transport,
    /// The server returned a status other than 200; redirects are never followed.
    #[error("public HTTPS read returned status {0}")]
    Status(u16),
    /// The decoded response exceeds the caller's finite byte limit.
    #[error("public HTTPS response exceeds its byte bound")]
    Oversized,
}

/// Isolated native transport for unsigned public material such as release checkpoints.
/// It has no ledger identity, credentials, default-header input, cookies or redirect policy.
#[derive(Clone, Debug, Default)]
pub struct PublicHttpClient {
    transport: DefaultHttpTransport,
}

impl PublicHttpClient {
    /// Retain isolated lazy SDK pools with no redirects or automatic retries.
    /// Native transport construction occurs on the first request and can fail there.
    #[must_use]
    pub fn new() -> Self {
        Self {
            transport: DefaultHttpTransport::new(),
        }
    }

    /// Inject a trusted transport while retaining this owner's URL, deadline and byte policies.
    /// The implementation must enforce the request's response bound while reading and must
    /// dispatch once without redirects, credentials, ambient cookies or added default headers.
    pub fn with_transport(transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            transport: DefaultHttpTransport::from_shared(transport),
        }
    }

    /// Read one public HTTPS object on a blocking worker, with an absolute operation deadline.
    ///
    /// # Errors
    /// Invalid policy, active async runtime, deadline, transport, status or body-bound failure.
    pub fn get_bytes_blocking(
        &self,
        url: &Url,
        deadline: Instant,
        maximum: usize,
    ) -> Result<Vec<u8>, PublicHttpError> {
        let request = request(url, deadline, maximum)?;
        crate::blocking::reject_inside_async_runtime().map_err(|_| PublicHttpError::Transport)?;
        let response = self
            .transport
            .with_deadline(deadline)
            .send_blocking(request)
            .map_err(|_| transport_error(deadline))?;
        response_bytes(response, deadline, maximum)
    }

    /// Read one canonical Norito object without ledger credentials on a blocking worker.
    ///
    /// The request advertises only the fixed Norito media type. The response must select that
    /// same media type; this method grants no trust to decoded contents or their source.
    ///
    /// # Errors
    /// The same URL, deadline, status, response-size and blocking-context refusals as the
    /// ordinary public read, or a missing/foreign response media type.
    pub fn get_norito_bytes_blocking(
        &self,
        url: &Url,
        deadline: Instant,
        maximum: usize,
    ) -> Result<Vec<u8>, PublicHttpError> {
        let mut request = request(url, deadline, maximum)?;
        request.headers.push((
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/x-norito"),
        ));
        crate::blocking::reject_inside_async_runtime().map_err(|_| PublicHttpError::Transport)?;
        let response = self
            .transport
            .with_deadline(deadline)
            .send_blocking(request)
            .map_err(|_| transport_error(deadline))?;
        // Keep the original deadline/status/size precedence before inspecting media headers.
        let valid_media = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            == Some("application/x-norito");
        let bytes = response_bytes(response, deadline, maximum)?;
        // SDK1 restores foreign-media acceptance only in the owning unit-test build.
        if !valid_media && !cfg!(all(test, sumeragi_sdk_mutation = "SDK1")) {
            return Err(PublicHttpError::Invalid);
        }
        Ok(bytes)
    }

    /// Read one public HTTPS object asynchronously under the same finite policies.
    ///
    /// # Errors
    /// Invalid policy, deadline, transport, status or body-bound failure.
    pub async fn get_bytes(
        &self,
        url: &Url,
        deadline: Instant,
        maximum: usize,
    ) -> Result<Vec<u8>, PublicHttpError> {
        let request = request(url, deadline, maximum)?;
        let response = self
            .transport
            .with_deadline(deadline)
            .send(request)
            .await
            .map_err(|_| transport_error(deadline))?;
        response_bytes(response, deadline, maximum)
    }
}

fn request(
    url: &Url,
    deadline: Instant,
    maximum: usize,
) -> Result<TransportRequest, PublicHttpError> {
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || maximum == 0
        || maximum > MAX_PUBLIC_READ_BYTES
    {
        return Err(PublicHttpError::Invalid);
    }
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(PublicHttpError::Deadline);
    }
    Ok(TransportRequest {
        method: Method::GET,
        url: url.clone(),
        headers: vec![],
        body: vec![],
        timeout: Some(timeout),
        max_response_bytes: maximum,
        direct_loopback: false,
    })
}

fn transport_error(deadline: Instant) -> PublicHttpError {
    if Instant::now() >= deadline {
        PublicHttpError::Deadline
    } else {
        PublicHttpError::Transport
    }
}

fn response_bytes(
    response: Response<Vec<u8>>,
    deadline: Instant,
    maximum: usize,
) -> Result<Vec<u8>, PublicHttpError> {
    if Instant::now() >= deadline {
        return Err(PublicHttpError::Deadline);
    }
    if response.status() != StatusCode::OK {
        return Err(PublicHttpError::Status(response.status().as_u16()));
    }
    if response.body().len() > maximum {
        return Err(PublicHttpError::Oversized);
    }
    Ok(response.into_body())
}

#[cfg(test)]
mod tests;
