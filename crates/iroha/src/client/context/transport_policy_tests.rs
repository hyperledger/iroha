//! Explicit local transport policy survives client views and gates every dispatch.

use super::*;
use crate::{
    config::HttpTransportPolicy,
    http::{HttpTransport, TransportFuture, TransportRequest},
};

#[derive(Debug, Default)]
struct Captured(Mutex<Vec<TransportRequest>>);
impl HttpTransport for Captured {
    fn send_blocking(&self, request: TransportRequest) -> Result<http::Response<Vec<u8>>> {
        self.0.lock().unwrap().push(request);
        Ok(http::Response::new(b"ok".to_vec()))
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}
fn builder(policy: HttpTransportPolicy) -> ClientBuilder {
    let mut builder = super::super::evidence_http_tests::client_with_base_url(
        "http://127.0.0.1:8080/".parse().unwrap(),
    )
    .to_builder();
    builder.http_transport_policy = policy;
    builder
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn opted_in_context_preserves_policy_and_request_bytes_through_all_views() {
    let transport = Arc::new(Captured::default());
    let client = builder(HttpTransportPolicy::DirectLoopback)
        .http_transport(transport.clone())
        .build()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let bounded = client.with_request_deadline(deadline);
    let mut rebuilder = bounded.to_builder();
    rebuilder.torii_url = "http://[::1]:8081/api/".parse().unwrap();
    let rebound = rebuilder.build().unwrap();
    let reinjected = rebound
        .to_builder()
        .http_transport(transport.clone())
        .build()
        .unwrap();
    let views = [client.clone(), bounded, rebound, reinjected];
    let runtime = runtime();
    for (index, view) in views.iter().enumerate() {
        assert_eq!(
            view.http_transport_policy(),
            HttpTransportPolicy::DirectLoopback
        );
        if index > 0 {
            assert_eq!(view.http_transport.deadline(), Some(deadline));
        }
        for asynchronous in [false, true] {
            let request = view
                .default_request(
                    HttpMethod::POST,
                    view.endpoint()
                        .join("v1/transaction?fixture=exact")
                        .unwrap(),
                )
                .header("x-fixture-signature", &"original-signature")
                .body(b"original signed bytes".to_vec())
                .timeout(Duration::from_secs(30))
                .max_response_bytes(64)
                .build()
                .unwrap();
            let response = if asynchronous {
                runtime.block_on(request.send())
            } else {
                request.send_blocking()
            };
            assert_eq!(response.unwrap().body(), b"ok");
        }
    }
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 8);
    for (index, request) in requests.iter().enumerate() {
        assert!(request.direct_loopback);
        assert_eq!(request.method, HttpMethod::POST);
        assert_eq!(request.body, b"original signed bytes");
        assert_eq!(request.max_response_bytes, 64);
        assert!(request.headers.iter().any(|(name, value)|
            name == "x-fixture-signature" && value == "original-signature"));
        assert_eq!(request.url.query(), Some("fixture=exact"));
        assert!(
            request.timeout.unwrap()
                <= if index < 2 {
                    Duration::from_secs(30)
                } else {
                    Duration::from_secs(10)
                }
        );
    }
}

#[test]
fn direct_policy_refuses_every_disallowed_request_before_custom_transport() {
    let transport = Arc::new(Captured::default());
    let client = builder(HttpTransportPolicy::DirectLoopback)
        .http_transport(transport.clone())
        .build()
        .unwrap();
    let runtime = runtime();
    for endpoint in [
        "https://localhost/",
        "http://example.com/",
        "http://192.0.2.1/",
        "http://localhost.example/",
        "http://[::ffff:127.0.0.1]/",
        "http://user:secret@localhost/",
        "http://localhost/#fragment",
    ] {
        for asynchronous in [false, true] {
            let request = client
                .default_request(HttpMethod::GET, endpoint.parse().unwrap())
                .build()
                .unwrap();
            let error = if asynchronous {
                runtime.block_on(request.send())
            } else {
                request.send_blocking()
            }
            .unwrap_err();
            assert!(error.to_string().contains("direct cleartext HTTP"));
            assert!(!error.to_string().contains("secret"));
        }
        let mut rebound = client.to_builder();
        rebound.torii_url = endpoint.parse().unwrap();
        assert!(rebound.build().is_err());
    }
    assert!(transport.0.lock().unwrap().is_empty());
}

#[test]
fn ordinary_context_keeps_tls_and_public_http_on_the_ordinary_transport() {
    let transport = Arc::new(Captured::default());
    let mut builder = builder(HttpTransportPolicy::Ordinary).http_transport(transport.clone());
    builder.torii_url = "https://example.com/".parse().unwrap();
    let client = builder.build().unwrap();
    let runtime = runtime();
    for endpoint in [
        "https://example.com/status",
        "http://192.0.2.1/status",
        "http://localhost/status",
    ] {
        let url = endpoint.parse().unwrap();
        client
            .default_request(HttpMethod::GET, url)
            .build()
            .unwrap()
            .send_blocking()
            .unwrap();
        runtime
            .block_on(
                client
                    .default_request(HttpMethod::GET, endpoint.parse().unwrap())
                    .build()
                    .unwrap()
                    .send(),
            )
            .unwrap();
    }
    assert_eq!(transport.0.lock().unwrap().len(), 6);
    assert!(
        transport
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.direct_loopback)
    );
}

#[test]
fn expired_deadline_survives_transport_replacement_without_dispatch() {
    let transport = Arc::new(Captured::default());
    let original = builder(HttpTransportPolicy::DirectLoopback)
        .build()
        .unwrap();
    let bounded = original.with_request_deadline(std::time::Instant::now());
    let replacement = bounded
        .to_builder()
        .http_transport(transport.clone())
        .build()
        .unwrap();
    let runtime = runtime();
    for asynchronous in [false, true] {
        let request = replacement
            .default_request(HttpMethod::GET, replacement.endpoint().clone())
            .build()
            .unwrap();
        let error = if asynchronous {
            runtime.block_on(request.send())
        } else {
            request.send_blocking()
        }
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
    assert!(transport.0.lock().unwrap().is_empty());
}
