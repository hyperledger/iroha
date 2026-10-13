//! Cleartext loopback pools avoid root loading while ordinary TLS keeps its roots.

use super::*;
use std::{
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

#[test]
fn cleartext_pools_skip_native_roots_and_ordinary_tls_keeps_them() {
    const CHILD: &str = "IROHA_LOOPBACK_TLS_ROOTS_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // Select rustls explicitly so dependency feature unification cannot make the
        // native-TLS backend bypass this deliberately malformed native-root fixture.
        let blocking = direct_loopback_http_client_builder()
            .use_rustls_tls()
            .build()
            .expect("cleartext blocking pool must not load native roots");
        let asynchronous = direct_loopback_async_http_client_builder()
            .use_rustls_tls()
            .build()
            .expect("cleartext async pool must not load native roots");
        assert!(
            blocking_http_client_builder()
                .use_rustls_tls()
                .build()
                .expect_err("ordinary blocking TLS must still load native roots")
                .is_builder()
        );
        assert!(
            async_http_client_builder()
                .use_rustls_tls()
                .build()
                .expect_err("ordinary async TLS must still load native roots")
                .is_builder()
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("cleartext listener");
        let url = format!(
            "http://localhost:{}/status",
            listener.local_addr().expect("cleartext address").port()
        );
        let (account, key_pair) = iroha_test_samples::gen_account_in("loopback-policy");
        let pools = Arc::new(ReqwestHttpTransport::default());
        let base = Url::parse(&url).unwrap().join("/").unwrap();
        let config = crate::config::Config {
            chain: iroha_model_base::chain::ChainId::from("loopback-policy"),
            network_id: crate::client::test_network_id(),
            account,
            account_chain_discriminant: 777,
            key_pair,
            basic_auth: None,
            api_token: None,
            torii_api_url: base,
            http_transport_policy: crate::config::HttpTransportPolicy::DirectLoopback,
            torii_request_timeout: Duration::from_secs(2),
            transaction_ttl: Duration::from_secs(100),
            transaction_status_timeout: Duration::from_secs(15),
            transaction_add_nonce: false,
            sorafs_alias_cache: crate::client::default_alias_policy(),
            sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::GuardPq,
            sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::Canary,
        };
        let client = crate::client::Client::builder(config)
            .http_transport(pools.clone())
            .build()
            .unwrap();
        listener.set_nonblocking(true).expect("bounded listener");
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut received = 0;
            while received < 4 && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("bounded response write");
                        let mut request = [0_u8; 2048];
                        let mut length = 0;
                        while !request[..length].ends_with(b"\r\n\r\n") {
                            assert!(length < request.len(), "bounded request headers");
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            assert!(!remaining.is_zero(), "request header deadline");
                            stream
                                .set_read_timeout(Some(remaining.min(Duration::from_secs(1))))
                                .expect("bounded request read");
                            let read = stream
                                .read(&mut request[length..])
                                .expect("cleartext request");
                            assert!(read > 0, "complete request headers");
                            assert!(Instant::now() < deadline, "request header deadline");
                            length += read;
                        }
                        assert!(request[..length].starts_with(b"GET /status HTTP/1.1\r\n"));
                        stream
                            .write_all(
                                b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/must-not-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .expect("cleartext response");
                        received += 1;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("cleartext listener: {error}"),
                }
            }
            received
        });
        let blocking_result = blocking.get(&url).timeout(Duration::from_secs(2)).send();
        let async_result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("cleartext runtime")
            .block_on(async {
                asynchronous
                    .get(&url)
                    .timeout(Duration::from_secs(2))
                    .send()
                    .await
            });
        // No per-request direct_loopback call: the immutable SDK policy selects each pool.
        let sdk_blocking = client
            .default_request(Method::GET, url.parse().unwrap())
            .build()
            .unwrap()
            .send_blocking();
        let sdk_async = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { client.status().get().await });
        assert_eq!(server.join().expect("cleartext server"), 4);
        assert_eq!(
            blocking_result.unwrap().status(),
            reqwest::StatusCode::FOUND
        );
        assert_eq!(async_result.unwrap().status(), reqwest::StatusCode::FOUND);
        assert_eq!(sdk_blocking.unwrap().status(), http::StatusCode::FOUND);
        assert!(matches!(
            sdk_async,
            Err(crate::Error::Http { status: 302, .. })
        ));
        assert!(pools.blocking.get().is_none());
        assert!(pools.asynchronous.get().is_none());
        assert!(pools.blocking_direct_loopback.get().is_some());
        assert!(pools.asynchronous_direct_loopback.get().is_some());
        return;
    }

    let directory = tempfile::tempdir().expect("isolated root-store directory");
    let roots = directory.path().join("invalid-der.pem");
    // Valid PEM framing with invalid certificate DER forces rustls root insertion
    // to fail; an empty/missing PEM would not exercise reqwest's error branch.
    std::fs::write(
        &roots,
        b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    )
    .expect("invalid root fixture");
    let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "http_default::loopback_tls_tests::cleartext_pools_skip_native_roots_and_ordinary_tls_keeps_them",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("SSL_CERT_FILE", &roots)
        .env_remove("SSL_CERT_DIR")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("isolated root-store child");
    assert!(
        child.status.success(),
        "root-store child failed:\n{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}
