//! Actual loopback TLS over the native shared listener/router; no provider readiness claim.

use super::*;
use crate::{
    ValidatedToriiHttpTransport, api_token_rejection_with_policy, limits::ApiTokenDigestSet,
    serve_torii_public,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{Request, StatusCode},
    middleware::{self, Next},
    routing::{get, post},
};
use iroha_config::{base::WithOrigin, parameters::actual::ToriiHttpTransport};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_futures::supervisor::ShutdownSignal;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
};
use std::{
    net::{Ipv4Addr, SocketAddr as StdAddress, SocketAddrV4},
    num::NonZeroUsize,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{RootCertStore, pki_types::ServerName},
};

const HOST: &str = "provider.localhost";
const IO_TIMEOUT: Duration = Duration::from_secs(3);
struct Identity {
    _root: tempfile::TempDir,
    directory: PrivateDirectory,
    ca: Vec<u8>,
    leaf: Vec<u8>,
    key: Vec<u8>,
    config: ToriiHttpsTransport,
}
impl Identity {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(root.path().join("identity")).unwrap();
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, ca_key);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![HOST.to_owned()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = ca_params.not_before;
        params.not_after = ca_params.not_after;
        let leaf = params.signed_by(&key, &issuer).unwrap();
        let leaf = leaf.der().as_ref().to_vec();
        let key = key.serialize_der();
        directory
            .write_atomic("leaf.der", &leaf, PublishMode::CreateNew)
            .unwrap();
        directory
            .write_atomic("key.der", &key, PublishMode::CreateNew)
            .unwrap();
        let config = ToriiHttpsTransport {
            address: WithOrigin::inline(SocketAddr::Ipv4(
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
            )),
            certificate_chain: vec![root.path().join("identity/leaf.der")],
            private_key: root.path().join("identity/key.der"),
            handshake_timeout: Duration::from_secs(1),
        };
        Self {
            _root: root,
            directory,
            ca: ca.der().as_ref().to_vec(),
            leaf,
            key,
            config,
        }
    }
    fn connector(&self) -> TlsConnector {
        connector(&self.ca)
    }
}
fn connector(ca: &[u8]) -> TlsConnector {
    TlsConnector::from(client_config(ca))
}
fn client_config(ca: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.to_vec())).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
fn router() -> Router {
    let tokens = ApiTokenDigestSet::from_tokens(["configured-component-token"]);
    Router::new()
        .route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<StdAddress>| async move { peer.ip().to_string() }),
        )
        .route("/echo", post(|body: Bytes| async move { body }))
        .layer(DefaultBodyLimit::max(8))
        .layer(middleware::from_fn(
            move |request: Request<Body>, next: Next| {
                let tokens = tokens.clone();
                async move {
                    match api_token_rejection_with_policy(true, &tokens, request.headers()) {
                        Some(response) => response,
                        None => next.run(request).await,
                    }
                }
            },
        ))
}
struct Server {
    http: StdAddress,
    https: StdAddress,
    shutdown: ShutdownSignal,
    task: JoinHandle<io::Result<()>>,
}
impl Server {
    async fn start(identity: &Identity, http: ToriiHttpTransport) -> Self {
        let https = PreparedHttps::load(&identity.config)
            .unwrap()
            .bind()
            .await
            .unwrap();
        let https_address = https.listener.local_addr().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let plaintext_address = listener.local_addr().unwrap();
        let shutdown = ShutdownSignal::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(serve_torii_public(
            listener,
            Some(https),
            router(),
            ValidatedToriiHttpTransport::new(http).unwrap(),
            task_shutdown,
        ));
        Self {
            http: plaintext_address,
            https: https_address,
            shutdown,
            task,
        }
    }
    async fn tls(&self, connector: TlsConnector, name: &str) -> io::Result<TlsStream<TcpStream>> {
        let socket = TcpStream::connect(self.https).await?;
        tokio::time::timeout(
            IO_TIMEOUT,
            connector.connect(ServerName::try_from(name.to_owned()).unwrap(), socket),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test TLS timeout"))?
    }
    async fn stop(self) {
        self.shutdown.send();
        tokio::time::timeout(IO_TIMEOUT, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
fn request(token: bool, body: &[u8]) -> Vec<u8> {
    let method = if body.is_empty() {
        "GET /peer"
    } else {
        "POST /echo"
    };
    let mut request = format!(
        "{method} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if token {
        request.push_str("x-api-token: configured-component-token\r\n");
    }
    request.push_str("\r\n");
    let mut request = request.into_bytes();
    request.extend_from_slice(body);
    request
}
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, bytes: &[u8]) -> Vec<u8> {
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(bytes).await.unwrap();
        let mut bytes = Vec::new();
        if let Err(error) = stream.take(64 * 1024).read_to_end(&mut bytes).await {
            // Hyper may close a finished HTTP socket without a TLS close-notify. Only a
            // complete bounded HTTP response may tolerate that TLS EOF diagnostic.
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let head = std::str::from_utf8(&bytes[..split]).unwrap();
            let length: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .expect("complete HTTP length");
            assert_eq!(bytes.len() - split - 4, length);
        }
        bytes
    })
    .await
    .unwrap()
}
async fn closed(mut stream: TcpStream) {
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut byte))
        .await
        .unwrap()
    {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("expected bounded closure, got {result:?}"),
    }
}

#[test]
fn bounded_identity_loader_rejects_bad_key_empty_oversized_and_replaced_files() {
    let identity = Identity::new();
    let prepared = PreparedHttps::load(&identity.config).unwrap();
    assert_eq!(prepared.acceptor.config().max_early_data_size, 0);
    assert_eq!(
        prepared.acceptor.config().alpn_protocols,
        vec![b"http/1.1".to_vec()]
    );
    let other = Identity::new();
    identity
        .directory
        .write_atomic("key.der", &other.key, PublishMode::Replace)
        .unwrap();
    let error = PreparedHttps::load(&identity.config).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "invalid native HTTPS identity");
    identity
        .directory
        .write_atomic("key.der", &identity.key, PublishMode::Replace)
        .unwrap();
    identity
        .directory
        .write_atomic("leaf.der", &other.leaf, PublishMode::Replace)
        .unwrap();
    assert!(PreparedHttps::load(&identity.config).is_err());
    for bytes in [
        Vec::new(),
        [identity.leaf.as_slice(), &[0]].concat(),
        vec![0xA5; https::MAX_DER_BYTES + 1],
    ] {
        identity
            .directory
            .write_atomic("leaf.der", &bytes, PublishMode::Replace)
            .unwrap();
        assert!(PreparedHttps::load(&identity.config).is_err());
    }
    identity
        .directory
        .write_atomic("leaf.der", &identity.leaf, PublishMode::Replace)
        .unwrap();
    PreparedHttps::load(&identity.config).unwrap();
    identity
        .directory
        .write_atomic("bad-chain.der", &[1, 2, 3], PublishMode::CreateNew)
        .unwrap();
    let mut config = identity.config.clone();
    config
        .certificate_chain
        .push(identity._root.path().join("identity/bad-chain.der"));
    assert!(PreparedHttps::load(&config).is_err());
    let mut config = identity.config.clone();
    config.private_key = identity._root.path().join("identity/missing.der");
    assert!(PreparedHttps::load(&config).is_err());
    identity
        .directory
        .write_atomic(
            "key.der",
            &vec![0x5A; https::MAX_DER_BYTES + 1],
            PublishMode::Replace,
        )
        .unwrap();
    assert!(PreparedHttps::load(&identity.config).is_err());
    identity
        .directory
        .write_atomic("key.der", &identity.key, PublishMode::Replace)
        .unwrap();
    let mut config = identity.config.clone();
    config.handshake_timeout = Duration::ZERO;
    assert!(PreparedHttps::load(&config).is_err());
    config.handshake_timeout = Duration::from_millis(https::MAX_HANDSHAKE_TIMEOUT_MS + 1);
    assert!(PreparedHttps::load(&config).is_err());
    config = identity.config.clone();
    config.certificate_chain = vec![config.certificate_chain[0].clone(); 5];
    assert!(PreparedHttps::load(&config).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn real_tls_uses_normal_roots_names_and_exact_same_authenticated_router() {
    let identity = Identity::new();
    let server = Server::start(&identity, ToriiHttpTransport::default()).await;
    assert!(
        server
            .tls(identity.connector(), "other.localhost")
            .await
            .is_err()
    );
    assert!(server.tls(Identity::new().connector(), HOST).await.is_err());
    for (token, body, status) in [
        (false, &b""[..], StatusCode::UNAUTHORIZED),
        (true, &b""[..], StatusCode::OK),
        (true, &b"123456789"[..], StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let plain = exchange(
            TcpStream::connect(server.http).await.unwrap(),
            &request(token, body),
        )
        .await;
        let encrypted = exchange(
            server.tls(identity.connector(), HOST).await.unwrap(),
            &request(token, body),
        )
        .await;
        let expected = format!("HTTP/1.1 {}", status.as_u16());
        assert!(
            plain.starts_with(expected.as_bytes()),
            "{}",
            String::from_utf8_lossy(&plain)
        );
        assert!(
            encrypted.starts_with(expected.as_bytes()),
            "{}",
            String::from_utf8_lossy(&encrypted)
        );
        if status == StatusCode::OK {
            assert!(plain.ends_with(b"127.0.0.1") && encrypted.ends_with(b"127.0.0.1"));
        }
        if status == StatusCode::UNAUTHORIZED {
            assert!(plain.windows(18).any(|w| w == b"api_token_required"));
            assert!(encrypted.windows(18).any(|w| w == b"api_token_required"));
        }
    }
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn http_and_https_share_both_global_and_per_ip_socket_capacity() {
    let identity = Identity::new();
    for global in [1, 2] {
        let http = ToriiHttpTransport {
            max_connections: NonZeroUsize::new(global).unwrap(),
            max_connections_per_ip: NonZeroUsize::new(1).unwrap(),
            ..Default::default()
        };
        let server = Server::start(&identity, http).await;
        // A completed TLS handshake proves the native pool has admitted this socket.
        let held = server.tls(identity.connector(), HOST).await.unwrap();
        closed(TcpStream::connect(server.http).await.unwrap()).await;
        assert!(server.tls(identity.connector(), HOST).await.is_err());
        drop(held);
        let until = tokio::time::Instant::now() + IO_TIMEOUT;
        loop {
            assert!(
                tokio::time::Instant::now() < until,
                "shared permit was not released"
            );
            let stream = TcpStream::connect(server.http).await.unwrap();
            let mut stream = stream;
            if stream.write_all(&request(true, b"")).await.is_ok() {
                let mut byte = [0_u8; 1];
                if matches!(
                    tokio::time::timeout(IO_TIMEOUT, stream.read(&mut byte)).await,
                    Ok(Ok(1))
                ) {
                    assert_eq!(byte, [b'H']);
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
        server.stop().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn silent_tls_handshake_expires_and_does_not_terminate_listener() {
    let mut identity = Identity::new();
    identity.config.handshake_timeout = Duration::from_millis(250);
    let server = Server::start(&identity, ToriiHttpTransport::default()).await;
    closed(TcpStream::connect(server.https).await.unwrap()).await;
    let response = exchange(
        server.tls(identity.connector(), HOST).await.unwrap(),
        &request(true, b""),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_cancels_unfinished_tls_before_its_handshake_deadline() {
    let mut identity = Identity::new();
    identity.config.handshake_timeout = Duration::from_secs(30);
    let server = Server::start(&identity, ToriiHttpTransport::default()).await;
    let mut socket = TcpStream::connect(server.https).await.unwrap();
    let mut client = rustls::ClientConnection::new(
        client_config(&identity.ca),
        ServerName::try_from(HOST).unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    socket.write_all(&hello).await.unwrap();
    // A server TLS record proves this socket entered the native handshake. Withhold
    // the client's Finished flight, then require shutdown well before the 30s limit.
    let mut first = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(IO_TIMEOUT, socket.read(&mut first))
            .await
            .unwrap()
            .unwrap(),
        1
    );
    server.stop().await;
    let mut remaining = Vec::new();
    let result = tokio::time::timeout(
        IO_TIMEOUT,
        socket.take(64 * 1024).read_to_end(&mut remaining),
    )
    .await
    .unwrap();
    if let Err(error) = result {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
        ));
    }
    assert!(remaining.len() < 64 * 1024);
}

#[tokio::test(flavor = "current_thread")]
async fn encrypted_partial_http_head_keeps_existing_absolute_deadline() {
    let identity = Identity::new();
    let http = ToriiHttpTransport {
        header_read_timeout: Duration::from_millis(40),
        ..Default::default()
    };
    let server = Server::start(&identity, http).await;
    let mut tls = server.tls(identity.connector(), HOST).await.unwrap();
    tls.write_all(b"GET /peer HTTP/1.1\r\nHost:").await.unwrap();
    let mut response = Vec::new();
    let result = tokio::time::timeout(IO_TIMEOUT, tls.read_to_end(&mut response))
        .await
        .unwrap();
    if let Err(error) = result {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ));
    }
    assert!(!response.starts_with(b"HTTP/1.1 200"));
    server.stop().await;
}

#[tokio::test(flavor = "current_thread")]
async fn unfinished_tls_keeps_the_actual_socket_permit_until_bounded_refusal() {
    let identity = Identity::new();
    let prepared = PreparedHttps::load(&identity.config).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, remote) = listener.accept().await.unwrap();
    let admission =
        crate::SocketAdmission::new(NonZeroUsize::new(1).unwrap(), NonZeroUsize::new(1).unwrap());
    let permit = admission.try_acquire(remote.ip()).unwrap();
    let handshake_timeout = Duration::from_millis(250);
    let task = tokio::spawn(crate::serve_torii_public_connection(
        stream,
        remote,
        permit,
        Some((
            HttpsIdentity {
                acceptor: prepared.acceptor,
                handshake_timeout,
            },
            tokio::time::Instant::now() + handshake_timeout,
        )),
        router(),
        ValidatedToriiHttpTransport::new(ToriiHttpTransport::default()).unwrap(),
        ShutdownSignal::new(),
    ));
    tokio::task::yield_now().await;
    assert!(admission.try_acquire(remote.ip()).is_none());
    let failure = tokio::time::timeout(IO_TIMEOUT, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    assert!(admission.try_acquire(remote.ip()).is_some());
    closed(client).await;
}

#[test]
fn shared_native_identity_requires_exact_der_and_matching_key() {
    let identity = Identity::new();
    let admitted = native_https_server_identity_v1(&[&identity.leaf], &identity.key).unwrap();
    assert_eq!(admitted.alpn_protocols, [b"http/1.1".to_vec()]);
    assert_eq!(admitted.max_early_data_size, 0);
    let foreign = Identity::new();
    assert!(native_https_server_identity_v1(&[&identity.leaf], &foreign.key).is_err());
    assert!(native_https_server_identity_v1(&[], &identity.key).is_err());
    assert!(native_https_server_identity_v1(&[&identity.leaf], &[]).is_err());
    let mut trailing = identity.leaf.clone();
    trailing.push(0);
    assert!(native_https_server_identity_v1(&[&trailing], &identity.key).is_err());
    assert!(
        native_https_server_identity_v1(&[&identity.leaf], &vec![0; https::MAX_DER_BYTES + 1])
            .is_err()
    );
}
