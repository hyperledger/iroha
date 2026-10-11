//! Native readiness transport reuse and independent peer request/deadline binding.

use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use std::{
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};

fn selected(endpoint: &url::Url) -> iroha::client::ClientBuilder {
    let key = iroha_crypto::KeyPair::from_seed(vec![93; 32], iroha_crypto::Algorithm::Ed25519);
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"readiness transport fixture"),
    ));
    let config = iroha::config::Config::load_table(
        "readiness-client-tests.toml",
        toml::toml! {
            chain = "readiness-transport"
            network_id = (network.to_string())
            torii_url = (endpoint.as_str())
            [account]
            chain_discriminant = 753
            public_key = (key.public_key().to_string())
            private_key = (iroha_crypto::ExposedPrivateKey(key.private_key().clone()).to_string())
        },
    )
    .unwrap();
    let mut builder = iroha::client::Client::builder(config);
    builder.torii_request_timeout = Duration::from_secs(5);
    builder.wire_format_preference = iroha::client::WireFormatPreference::JsonOnly;
    builder
        .headers
        .insert("x-readiness-fixture".into(), "same-owner".into());
    builder
}

fn endpoints(base: &str) -> [url::Url; 4] {
    std::array::from_fn(|peer| format!("{base}/peer{peer}/").parse().unwrap())
}

#[derive(Debug, Default)]
struct Captured(Mutex<Vec<TransportRequest>>);

impl HttpTransport for Captured {
    fn send_blocking(&self, _: TransportRequest) -> color_eyre::eyre::Result<Response<Vec<u8>>> {
        panic!("status must retain its asynchronous dispatch path")
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        self.0.lock().unwrap().push(request);
        Box::pin(async {
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(norito::json::to_vec(
                    &iroha_torii_shared::status::Status::default(),
                )?)
                .unwrap())
        })
    }
}

#[test]
fn readiness_peer_contexts_share_original_transport_without_rebinding_policy() {
    let urls = endpoints("http://127.0.0.1:18432");
    let transport = Arc::new(Captured::default());
    let builder = selected(&urls[0]).http_transport(transport.clone());
    let expected = builder.clone();
    let clients =
        readiness_clients(builder, &urls, Instant::now() + Duration::from_secs(10)).unwrap();
    for (client, url) in clients.iter().zip(&urls) {
        let actual = client.client().to_builder();
        assert_eq!(&actual.torii_url, url);
        assert_eq!(actual.account, expected.account);
        assert_eq!(actual.network_id, expected.network_id);
        assert_eq!(actual.chain, expected.chain);
        assert_eq!(actual.headers, expected.headers);
        assert_eq!(actual.key_pair.public_key(), expected.key_pair.public_key());
        client.status().get().unwrap();
    }
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for (peer, request) in requests.iter().enumerate() {
        assert_eq!(request.url.path(), format!("/peer{peer}/status"));
        assert!(
            !request.direct_loopback,
            "status retains its ordinary proxy/TLS policy"
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(key, value)| key == "x-readiness-fixture" && value == "same-owner")
        );
        assert!(
            request
                .timeout
                .is_some_and(|timeout| timeout <= Duration::from_secs(5))
        );
    }
}

#[test]
fn readiness_peer_contexts_refuse_wrong_submission_endpoint_and_invalid_peers() {
    let urls = endpoints("http://127.0.0.1:18432");
    let transport = Arc::new(Captured::default());
    let builder = selected(&urls[0]).http_transport(transport.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut wrong = urls.clone();
    wrong.swap(0, 1);
    assert!(readiness_clients(builder.clone(), &wrong, deadline).is_err());
    for bad in ["https://user:password@example.test/", "file:///tmp/peer/"] {
        wrong = urls.clone();
        wrong[3] = bad.parse().unwrap();
        assert!(readiness_clients(builder.clone(), &wrong, deadline).is_err());
    }
    assert!(readiness_clients(builder, &urls[..3], deadline).is_err());
    assert!(transport.0.lock().unwrap().is_empty());
}

#[test]
fn shortened_peer_deadline_cannot_extend_or_cancel_other_peer_views() {
    let urls = endpoints("http://127.0.0.1:18432");
    let transport = Arc::new(Captured::default());
    let clients = readiness_clients(
        selected(&urls[0]).http_transport(transport.clone()),
        &urls,
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    let expired = clients[0].with_request_deadline(Instant::now()).unwrap();
    assert!(expired.status().get().is_err());
    let extended = expired
        .with_request_deadline(Instant::now() + Duration::from_secs(60))
        .unwrap();
    assert!(extended.status().get().is_err());
    assert!(transport.0.lock().unwrap().is_empty());
    clients[1].status().get().unwrap();
    clients[0].status().get().unwrap();
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url.path(), "/peer1/status");
    assert_eq!(requests[1].url.path(), "/peer0/status");
}

#[test]
fn native_readiness_peers_reuse_one_connection_after_status_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let urls = endpoints(&format!("http://{}", listener.local_addr().unwrap()));
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut connections = Vec::new();
        let mut requests = Vec::new();
        while requests.len() < 8 && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true).unwrap();
                    connections.push((stream, Vec::<u8>::new()));
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("readiness listener: {error}"),
            }
            for (stream, pending) in &mut connections {
                let mut buffer = [0_u8; 4096];
                match stream.read(&mut buffer) {
                    Ok(length) => pending.extend_from_slice(&buffer[..length]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => panic!("readiness request: {error}"),
                }
                if let Some(end) = pending.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let bytes = pending.drain(..end + 4).collect::<Vec<_>>();
                    let request = String::from_utf8(bytes).unwrap();
                    assert!(
                        request
                            .to_ascii_lowercase()
                            .contains("x-readiness-fixture: same-owner")
                    );
                    requests.push(request.lines().next().unwrap().to_owned());
                    let body = norito::json::to_vec(&iroha_torii_shared::status::Status::default())
                        .unwrap();
                    let status = if requests.len() == 1 {
                        "503 Service Unavailable"
                    } else {
                        "200 OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        body.len()
                    );
                    // Each finite response is written under the original test-server deadline.
                    let response = [response.as_bytes(), &body].concat();
                    let mut written = 0;
                    while written < response.len() && Instant::now() < deadline {
                        match stream.write(&response[written..]) {
                            Ok(0) => panic!("readiness response closed"),
                            Ok(length) => written += length,
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(1))
                            }
                            Err(error) => panic!("readiness response: {error}"),
                        }
                    }
                    assert_eq!(written, response.len());
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        (connections.len(), requests)
    });
    let clients = readiness_clients(
        selected(&urls[0]),
        &urls,
        Instant::now() + Duration::from_secs(15),
    )
    .unwrap();
    for turn in 0..2 {
        for (peer, client) in clients.iter().enumerate() {
            let result = client.status().get();
            if turn == 0 && peer == 0 {
                assert!(matches!(
                    result,
                    Err(iroha::Error::StatusUnavailable { .. })
                ));
            } else {
                result.unwrap();
            }
        }
    }
    let (connections, requests) = server.join().unwrap();
    assert_eq!(
        connections, 1,
        "all four native peer contexts must retain the same pool"
    );
    assert_eq!(
        requests,
        (0..2)
            .flat_map(|_| (0..4).map(|peer| format!("GET /peer{peer}/status HTTP/1.1")))
            .collect::<Vec<_>>()
    );
}
