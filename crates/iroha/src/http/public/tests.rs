//! Credential-free public-read policy and shared native transport boundary regressions.

use super::*;
use crate::http::TransportFuture;
use std::{sync::Mutex, time::Duration};

#[derive(Debug)]
struct Transport {
    requests: Mutex<Vec<TransportRequest>>,
    status: StatusCode,
    body: Vec<u8>,
    fail: bool,
}

impl Transport {
    fn new(status: StatusCode, body: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            requests: Mutex::new(vec![]),
            status,
            body,
            fail: false,
        })
    }

    fn reply(&self, request: TransportRequest) -> eyre::Result<Response<Vec<u8>>> {
        self.requests.lock().unwrap().push(request);
        if self.fail {
            return Err(eyre::eyre!("untrusted response diagnostic"));
        }
        Ok(Response::builder()
            .status(self.status)
            .body(self.body.clone())
            .unwrap())
    }
}

impl HttpTransport for Transport {
    fn send_blocking(&self, request: TransportRequest) -> eyre::Result<Response<Vec<u8>>> {
        self.reply(request)
    }

    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.reply(request) })
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn unsigned_public_reads_share_bounded_credential_free_blocking_and_async_transport() {
    let _ = PublicHttpClient::new();
    let transport = Transport::new(StatusCode::OK, vec![1, 2, 3]);
    let client = PublicHttpClient::with_transport(transport.clone());
    let url: Url = "https://releases.example/checkpoint.nrt".parse().unwrap();
    assert_eq!(
        client.get_bytes_blocking(&url, deadline(), 4).unwrap(),
        [1, 2, 3]
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(
        runtime
            .block_on(client.get_bytes(&url, deadline(), 4))
            .unwrap(),
        [1, 2, 3]
    );
    assert_eq!(
        runtime.block_on(async { client.get_bytes_blocking(&url, deadline(), 4) }),
        Err(PublicHttpError::Transport),
        "blocking retrieval must run on the native worker, outside Tokio"
    );
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.url, url);
        assert!(request.headers.is_empty());
        assert!(request.body.is_empty());
        assert_eq!(request.max_response_bytes, 4);
        assert!(
            request.timeout.is_some_and(
                |timeout| timeout > Duration::ZERO && timeout <= Duration::from_secs(5)
            )
        );
        assert!(!request.direct_loopback);
    }
}

#[test]
fn public_url_deadline_and_memory_policy_refuse_before_dispatch() {
    let transport = Transport::new(StatusCode::OK, vec![]);
    let client = PublicHttpClient::with_transport(transport.clone());
    for value in [
        "http://releases.example/checkpoint.nrt",
        "https://user:secret@releases.example/checkpoint.nrt",
        "https://releases.example/checkpoint.nrt?token=secret",
        "https://releases.example/checkpoint.nrt#fragment",
    ] {
        assert_eq!(
            client.get_bytes_blocking(&value.parse().unwrap(), deadline(), 4),
            Err(PublicHttpError::Invalid)
        );
    }
    let url = "https://releases.example/checkpoint.nrt".parse().unwrap();
    for maximum in [0, MAX_PUBLIC_READ_BYTES + 1] {
        assert_eq!(
            client.get_bytes_blocking(&url, deadline(), maximum),
            Err(PublicHttpError::Invalid)
        );
    }
    assert_eq!(
        client.get_bytes_blocking(&url, Instant::now(), 4),
        Err(PublicHttpError::Deadline)
    );
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[test]
fn public_response_status_and_size_fail_closed_without_redirect_or_retry() {
    let url = "https://releases.example/checkpoint.nrt".parse().unwrap();
    for (status, body, expected) in [
        (StatusCode::FOUND, vec![], PublicHttpError::Status(302)),
        (StatusCode::OK, vec![0; 5], PublicHttpError::Oversized),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            vec![0; 5],
            PublicHttpError::Status(500),
        ),
    ] {
        let transport = Transport::new(status, body);
        let client = PublicHttpClient::with_transport(transport.clone());
        assert_eq!(
            client.get_bytes_blocking(&url, deadline(), 4),
            Err(expected)
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
    let transport = Arc::new(Transport {
        requests: Mutex::new(vec![]),
        status: StatusCode::OK,
        body: vec![],
        fail: true,
    });
    assert_eq!(
        PublicHttpClient::with_transport(transport.clone()).get_bytes_blocking(&url, deadline(), 4),
        Err(PublicHttpError::Transport)
    );
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
    assert_eq!(
        response_bytes(Response::new(vec![]), Instant::now(), 4),
        Err(PublicHttpError::Deadline)
    );
    assert_eq!(transport_error(Instant::now()), PublicHttpError::Deadline);
}

#[derive(Debug)]
struct NoritoTransport {
    requests: Mutex<Vec<TransportRequest>>,
    media: Option<&'static str>,
}
impl HttpTransport for NoritoTransport {
    fn send_blocking(&self, request: TransportRequest) -> eyre::Result<Response<Vec<u8>>> {
        self.requests.lock().unwrap().push(request);
        let mut response = Response::new(vec![1, 2, 3]);
        if let Some(media) = self.media {
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(media),
            );
        }
        Ok(response)
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

#[test]
fn public_norito_reads_select_only_fixed_media_and_retain_original_public_policies() {
    let transport = Arc::new(NoritoTransport {
        requests: Mutex::new(vec![]),
        media: Some("application/x-norito"),
    });
    let client = PublicHttpClient::with_transport(transport.clone());
    let url = "https://parent.example/v1/bridge/finality/1"
        .parse()
        .unwrap();
    assert_eq!(
        client
            .get_norito_bytes_blocking(&url, deadline(), 3)
            .unwrap(),
        [1, 2, 3]
    );
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url, url);
    assert_eq!(requests[0].headers.len(), 1);
    assert_eq!(requests[0].headers[0].0, http::header::ACCEPT);
    assert_eq!(requests[0].headers[0].1, "application/x-norito");
    assert!(requests[0].body.is_empty());
    assert_eq!(requests[0].max_response_bytes, 3);
    assert!(!requests[0].direct_loopback);
    assert!(
        requests[0]
            .timeout
            .is_some_and(|value| value <= Duration::from_secs(5))
    );
}

#[test]
fn public_norito_reads_refuse_missing_foreign_media_and_elapsed_requests() {
    let url = "https://parent.example/v1/bridge/finality/2"
        .parse()
        .unwrap();
    for media in [
        None,
        Some("application/json"),
        Some("application/x-norito; charset=utf-8"),
    ] {
        let transport = Arc::new(NoritoTransport {
            requests: Mutex::new(vec![]),
            media,
        });
        let client = PublicHttpClient::with_transport(transport.clone());
        assert_eq!(
            client.get_norito_bytes_blocking(&url, deadline(), 3),
            Err(PublicHttpError::Invalid)
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
        assert_eq!(
            client.get_norito_bytes_blocking(&url, Instant::now(), 3),
            Err(PublicHttpError::Deadline)
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
}
