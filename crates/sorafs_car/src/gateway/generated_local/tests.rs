//! Component TLS controls. Private test selections are not native admission/eligibility proofs.

use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
};
use sorafs_manifest::{
    deal::XorQuantity,
    provider_admission::{
        EndpointAdmissionV1, EndpointAttestationV1, ProviderAdmissionProposalV1,
        ProviderVrfPublicKeyV1,
    },
    provider_advert::{
        AdvertEndpoint, AvailabilityTier, CapabilityTlv, CapabilityType, PathDiversityPolicy,
        ProviderAdvertBodyV1, QosHints, RendezvousTopic, StakePointer,
    },
};
use std::{io, net::TcpListener, sync::Mutex, thread, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

const WAIT: Duration = Duration::from_secs(3);
fn provider() -> ProviderId {
    ProviderId::new([0x11; 32])
}
fn host() -> String {
    format!("{}.{}.localhost", "11".repeat(16), "11".repeat(16))
}
fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"local-transport-component",
    )))
}
fn owner() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

struct Identity {
    root: Vec<u8>,
    leaf: Vec<u8>,
    key: Vec<u8>,
}
impl Identity {
    fn new(name: &str, expired: bool) -> Self {
        Self::pair(name, expired).0
    }
    fn pair(name: &str, expired: bool) -> (Self, Self) {
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = root_params.self_signed(&root_key).unwrap();
        let issuer = Issuer::from_params(&root_params, root_key);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let leaf = params.signed_by(&key, &issuer).unwrap();
        let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let other_leaf = params.signed_by(&other_key, &issuer).unwrap();
        (
            Self {
                root: root.der().to_vec(),
                leaf: leaf.der().to_vec(),
                key: key.serialize_der(),
            },
            Self {
                root: root.der().to_vec(),
                leaf: other_leaf.der().to_vec(),
                key: other_key.serialize_der(),
            },
        )
    }
    fn server(&self) -> Arc<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(self.leaf.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
        )
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}
fn material(identity: &Identity, port: u16) -> ProviderAdmissionGenesisMaterialV1 {
    let read = RegisteredAccountReadV1 {
        https_host: host(),
        https_port: port,
        ttl_secs: 60,
        max_streams: 1,
        rate_limit_bytes: 1024,
        requests_per_minute: 60,
    };
    let capabilities = vec![
        CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: vec![],
        },
        read.to_capability().unwrap(),
    ];
    let endpoint = AdvertEndpoint {
        kind: EndpointKind::Torii,
        host_pattern: host(),
        metadata: vec![],
    };
    let stake = StakePointer {
        pool_id: [2; 32],
        stake_amount: XorQuantity::try_from_micro(1).unwrap(),
    };
    let vrf = KeyPair::from_seed(vec![3; 32], Algorithm::BlsNormal);
    let advert = KeyPair::from_seed(vec![4; 32], Algorithm::Ed25519);
    ProviderAdmissionGenesisMaterialV1 {
        proposal: ProviderAdmissionProposalV1 {
            version: 1,
            provider_id: *provider().as_bytes(),
            profile_id: "sorafs.sf1@1.0.0".into(),
            profile_aliases: None,
            stake: stake.clone(),
            capabilities: capabilities.clone(),
            endpoints: vec![EndpointAdmissionV1 {
                endpoint: endpoint.clone(),
                attestation: EndpointAttestationV1 {
                    version: 1,
                    kind: EndpointAttestationKind::Tls,
                    attested_at: 1,
                    expires_at: 4_000_000_000,
                    leaf_certificate: identity.leaf.clone(),
                    intermediate_certificates: vec![identity.root.clone()],
                    alpn_ids: vec!["http/1.1".into()],
                    report: vec![],
                },
            }],
            advert_key: advert.public_key().to_bytes().1.try_into().unwrap(),
            por_vrf_key: ProviderVrfPublicKeyV1::BlsNormal(
                vrf.public_key().to_bytes().1.try_into().unwrap(),
            ),
            jurisdiction_code: "ZZ".into(),
            contact_uri: None,
            stream_budget: None,
            transport_hints: None,
        },
        advert_body: ProviderAdvertBodyV1 {
            provider_id: *provider().as_bytes(),
            profile_id: "sorafs.sf1@1.0.0".into(),
            profile_aliases: None,
            stake,
            qos: QosHints {
                availability: AvailabilityTier::Hot,
                max_retrieval_latency_ms: 1,
                max_concurrent_streams: 1,
            },
            capabilities,
            endpoints: vec![endpoint],
            rendezvous_topics: vec![RendezvousTopic {
                topic: "sorafs.sf1.primary".into(),
                region: "local".into(),
            }],
            path_policy: PathDiversityPolicy {
                min_guard_weight: 1,
                max_same_asn_per_path: 1,
                max_same_pool_per_path: 1,
            },
            notes: None,
            stream_budget: None,
            transport_hints: None,
        },
        issued_at: 1,
        retention_epoch: 4_000_000_000,
    }
}
fn intent(identity: &Identity, port: u16) -> GeneratedLocalProviderTransportV1 {
    GeneratedLocalProviderTransportV1::select(
        network(),
        "component",
        provider(),
        &owner(),
        &material(identity, port),
    )
    .unwrap()
}
fn component_selection(
    identity: &Identity,
    port: u16,
) -> AuthenticatedGeneratedLocalProviderTransportV1 {
    // Private cfg(test) transport plumbing only. No native proof is synthesized or asserted.
    AuthenticatedGeneratedLocalProviderTransportV1(intent(identity, port))
}
struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    worker: thread::JoinHandle<()>,
}
impl Server {
    fn start(identity: &Identity, attempts: usize, response: &'static [u8]) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let config = identity.server();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let worker = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let acceptor = TlsAcceptor::from(config);
                    for _ in 0..attempts {
                        let (stream, _) = tokio::time::timeout(WAIT, listener.accept())
                            .await
                            .unwrap()
                            .unwrap();
                        let Ok(Ok(mut tls)) =
                            tokio::time::timeout(WAIT, acceptor.accept(stream)).await
                        else {
                            continue;
                        };
                        let name = tls.get_ref().1.server_name().unwrap().to_owned();
                        let exchange = async {
                            let mut head = Vec::new();
                            while !head.ends_with(b"\r\n\r\n") {
                                if head.len() >= 16 * 1024 {
                                    return Err(io::Error::other("test request too large"));
                                }
                                head.push(tls.read_u8().await?);
                            }
                            seen.lock()
                                .unwrap()
                                .push((name, String::from_utf8(head).unwrap()));
                            tls.write_all(response).await?;
                            tls.shutdown().await
                        };
                        tokio::time::timeout(WAIT, exchange).await.unwrap().unwrap();
                    }
                });
        });
        Self {
            port,
            requests,
            worker,
        }
    }
    fn finish(self) -> Vec<(String, String)> {
        self.worker.join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}
fn async_get(
    selected: &AuthenticatedGeneratedLocalProviderTransportV1,
) -> Result<(u16, Vec<u8>), reqwest::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let client = selected.async_http_client(WAIT, WAIT).unwrap();
            let response = client
                .get(selected.base_url().join("chunk").unwrap())
                .send()
                .await?;
            Ok((response.status().as_u16(), response.bytes().await?.to_vec()))
        })
}
fn blocking_get(
    selected: &AuthenticatedGeneratedLocalProviderTransportV1,
) -> Result<(u16, Vec<u8>), reqwest::Error> {
    let client = selected.blocking_http_client(WAIT, WAIT).unwrap();
    let response = client
        .get(selected.base_url().join("control").unwrap())
        .send()?;
    Ok((response.status().as_u16(), response.bytes()?.to_vec()))
}
#[test]
fn original_selection_bounds_exact_generated_shape_and_redacts_diagnostics() {
    let identity = Identity::new(&host(), false);
    let original = material(&identity, 8443);
    let select = |m: &ProviderAdmissionGenesisMaterialV1| {
        GeneratedLocalProviderTransportV1::select(network(), "component", provider(), &owner(), m)
    };
    let selected = select(&original).unwrap();
    assert_eq!(selected.provider_id(), provider());
    assert_eq!(selected.network_id(), network());
    assert_eq!(selected.chain_id(), "component");
    assert!(!format!("{selected:?}").contains(&host()));
    for mutate in [
        |m: &mut ProviderAdmissionGenesisMaterialV1| {
            m.proposal.endpoints[0]
                .attestation
                .leaf_certificate
                .resize(CERT_MAX + 1, 1)
        },
        |m: &mut ProviderAdmissionGenesisMaterialV1| {
            m.proposal.endpoints[0]
                .attestation
                .intermediate_certificates
                .push(vec![1])
        },
        |m: &mut ProviderAdmissionGenesisMaterialV1| {
            m.proposal.endpoints[0].endpoint.host_pattern = "other.localhost".into()
        },
        |m: &mut ProviderAdmissionGenesisMaterialV1| {
            m.proposal.endpoints[0].attestation.expires_at -= 1
        },
        |m: &mut ProviderAdmissionGenesisMaterialV1| {
            m.proposal.endpoints[0].attestation.alpn_ids = vec!["h2".into()]
        },
        |m: &mut ProviderAdmissionGenesisMaterialV1| {
            m.proposal.endpoints[0]
                .attestation
                .report
                .resize(MATERIAL_MAX, 1)
        },
        |m: &mut ProviderAdmissionGenesisMaterialV1| m.retention_epoch = u64::MAX,
    ] {
        let mut changed = original.clone();
        mutate(&mut changed);
        let error = select(&changed).unwrap_err();
        assert!(!error.to_string().contains(&host()));
    }
    assert!(
        GeneratedLocalProviderTransportV1::select(
            network(),
            "component\n",
            provider(),
            &owner(),
            &original
        )
        .is_err()
    );
    assert!(
        GeneratedLocalProviderTransportV1::select(
            network(),
            "component",
            ProviderId::new([2; 32]),
            &owner(),
            &original
        )
        .is_err()
    );
    assert!(
        GeneratedLocalProviderTransportV1::select(
            network(),
            &"x".repeat(257),
            provider(),
            &owner(),
            &original
        )
        .is_err()
    );
}
#[test]
fn both_clients_use_original_ca_sni_and_nonstandard_loopback_port() {
    let identity = Identity::new(&host(), false);
    let server = Server::start(
        &identity,
        2,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let selected = component_selection(&identity, server.port);
    assert_eq!(
        selected.socket_addr(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, server.port))
    );
    assert_eq!(blocking_get(&selected).unwrap(), (200, b"ok".to_vec()));
    assert_eq!(async_get(&selected).unwrap(), (200, b"ok".to_vec()));
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    for (name, head) in requests {
        assert_eq!(name, host());
        assert!(head.to_ascii_lowercase().contains(&format!(
            "host: {}:{}",
            host(),
            selected.socket_addr().port()
        )));
        assert!(!head.contains("authorization:"));
        assert!(!head.contains("x-api-token:"));
    }
}
#[test]
fn both_clients_reject_wrong_ca_name_and_expired_leaf() {
    for (name, expired, wrong_ca) in [
        (host(), false, true),
        ("other.localhost".into(), false, false),
        (host(), true, false),
    ] {
        let server_identity = Identity::new(&name, expired);
        let server = Server::start(
            &server_identity,
            2,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        );
        let other = Identity::new(&host(), false);
        let selected = component_selection(
            if wrong_ca { &other } else { &server_identity },
            server.port,
        );
        assert!(blocking_get(&selected).is_err());
        assert!(async_get(&selected).is_err());
        assert!(server.finish().is_empty());
    }
}
#[test]
fn both_clients_do_not_follow_redirects_or_decompress() {
    let identity = Identity::new(&host(), false);
    for response in [
        b"HTTP/1.1 302 Found\r\nLocation: https://other.localhost:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw".as_slice(),
    ] {
        let server = Server::start(&identity, 2, response);
        let selected = component_selection(&identity, server.port);
        let expected = if response.starts_with(b"HTTP/1.1 302") { (302, vec![]) } else { (200, b"raw".to_vec()) };
        assert_eq!(blocking_get(&selected).unwrap(), expected); assert_eq!(async_get(&selected).unwrap(), expected);
        assert_eq!(server.finish().len(), 2);
    }
}
#[test]
fn selected_transport_refuses_other_provider_origin_privacy_and_invalid_timeouts() {
    let identity = Identity::new(&host(), false);
    let selected = component_selection(&identity, 8443);
    let input = GatewayProviderInput {
        name: "selected".into(),
        provider_id_hex: hex::encode(provider().as_bytes()),
        gateway_public_key_hex: "unused".into(),
        base_url: selected.base_url().to_string(),
        stream_token_b64: "unused".into(),
        privacy_events_url: None,
    };
    assert_eq!(
        selected.validate_input(&input).unwrap(),
        *selected.base_url()
    );
    for mutate in [
        |i: &mut GatewayProviderInput| i.provider_id_hex = "22".repeat(32),
        |i: &mut GatewayProviderInput| i.base_url = i.base_url.replace(":8443", ":8444"),
        |i: &mut GatewayProviderInput| i.base_url = "https://127.0.0.1:8443/".into(),
        |i: &mut GatewayProviderInput| {
            i.privacy_events_url = Some("https://other.example/privacy/events".into())
        },
    ] {
        let mut changed = input.clone();
        mutate(&mut changed);
        assert!(selected.validate_input(&changed).is_err());
    }
    for (connect, request) in [
        (Duration::ZERO, WAIT),
        (WAIT, Duration::ZERO),
        (WAIT, Duration::from_millis(1)),
    ] {
        assert!(selected.blocking_http_client(connect, request).is_err());
        assert!(selected.async_http_client(connect, request).is_err());
    }
}

#[test]
fn both_clients_bound_an_unfinished_tls_handshake() {
    let identity = Identity::new(&host(), false);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                for _ in 0..2 {
                    let (mut socket, _) = tokio::time::timeout(WAIT, listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                    // A real ClientHello proves that the selected socket was reached; no server
                    // response is sent. A certificate parsing error cannot satisfy this control.
                    assert_eq!(
                        tokio::time::timeout(WAIT, socket.read_u8())
                            .await
                            .unwrap()
                            .unwrap(),
                        0x16
                    );
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            });
    });
    let selected = component_selection(&identity, port);
    let timeout = Duration::from_millis(100);
    let client = selected.blocking_http_client(timeout, timeout).unwrap();
    assert!(
        client
            .get(selected.base_url().clone())
            .send()
            .unwrap_err()
            .is_timeout()
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let client = selected.async_http_client(timeout, timeout).unwrap();
            assert!(
                client
                    .get(selected.base_url().clone())
                    .send()
                    .await
                    .unwrap_err()
                    .is_timeout()
            );
        });
    worker.join().unwrap();
}

#[test]
fn both_clients_reject_same_ca_same_name_substituted_leaf_before_http() {
    let (original, substitute) = Identity::pair(&host(), false);
    assert_eq!(original.root, substitute.root);
    assert_ne!(original.leaf, substitute.leaf);
    let server = Server::start(
        &substitute,
        3,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let selected = component_selection(&original, server.port);
    assert!(blocking_get(&selected).is_err());
    assert!(async_get(&selected).is_err());
    // The alternate leaf is normally valid under the same CA/name. Selecting that exact
    // alternate leaf succeeds, so the two refusals above isolate the retained-leaf fence.
    let alternate = component_selection(&substitute, server.port);
    assert_eq!(async_get(&alternate).unwrap(), (200, b"ok".to_vec()));
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn original_ownership_obeys_inherited_allocation_refusal() {
    let identity = Identity::new(&host(), false);
    let original = material(&identity, 8443);
    let refused = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(MATERIAL_MAX, MATERIAL_MAX, MATERIAL_MAX * 2, 0, 48),
        || {
            GeneratedLocalProviderTransportV1::select(
                network(),
                "component",
                provider(),
                &owner(),
                &original,
            )
        },
    );
    assert!(refused.is_err());
    assert!(
        GeneratedLocalProviderTransportV1::select(
            network(),
            "component",
            provider(),
            &owner(),
            &original
        )
        .is_ok()
    );
}

fn publication_selection(identity: &Identity, port: u16) -> GeneratedLocalPublicationTransportV1 {
    // This public constructor selects transport intent only; no native proof is fabricated.
    let provider_port = if port == 8443 { 8444 } else { 8443 };
    GeneratedLocalPublicationTransportV1::select(
        network(),
        "component",
        provider(),
        &owner(),
        &material(identity, provider_port),
        port,
    )
    .unwrap()
}
fn publication_post(
    selected: &GeneratedLocalPublicationHttpClientV1,
    route: &str,
) -> Result<(u16, Vec<u8>), GeneratedLocalPublicationTransportErrorV1> {
    let request = reqwest::blocking::Request::new(
        reqwest::Method::POST,
        selected.selection().base_url().join(route).unwrap(),
    );
    let response = selected.execute(request)?;
    let status = response.status().as_u16();
    let bytes = response
        .bytes()
        .map_err(|_| GeneratedLocalPublicationTransportErrorV1)?;
    Ok((status, bytes.to_vec()))
}
#[test]
fn publication_selection_is_separate_bounded_original_intent() {
    let identity = Identity::new(&host(), false);
    let original = material(&identity, 8443);
    let select = |port| {
        GeneratedLocalPublicationTransportV1::select(
            network(),
            "component",
            provider(),
            &owner(),
            &original,
            port,
        )
    };
    assert!(select(0).is_err());
    assert!(select(8443).is_err());
    let selection = select(9443).unwrap();
    assert_eq!(selection.network_id(), network());
    assert_eq!(selection.chain_id(), "component");
    assert_eq!(selection.provider_id(), provider());
    assert_eq!(
        selection.base_url().as_str(),
        format!("https://{}:9443/", host())
    );
    assert!(!format!("{selection:?}").contains(&host()));
    assert!(selection.blocking_client(Duration::ZERO).is_err());
    let client = selection.blocking_client(WAIT).unwrap();
    assert!(!format!("{client:?}").contains(&host()));
    assert_eq!(client.selection().base_url(), selection.base_url());
    let mut malformed = original.clone();
    malformed.proposal.endpoints[0]
        .attestation
        .leaf_certificate
        .resize(CERT_MAX + 1, 1);
    assert!(
        GeneratedLocalPublicationTransportV1::select(
            network(),
            "component",
            provider(),
            &owner(),
            &malformed,
            9443
        )
        .is_err()
    );
    let limits = norito::DecodeLimits::new(8 * 1024, 8 * 1024, 8 * 1024, 1, 48);
    assert!(norito::core::with_decode_limits_scope(limits, || select(9443)).is_err());
}
#[test]
fn publication_guard_refuses_foreign_destinations_before_any_connection() {
    let identity = Identity::new(&host(), false);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let selection = publication_selection(&identity, listener.local_addr().unwrap().port());
    let client = selection.blocking_client(WAIT).unwrap();
    selection.validate_base_url(selection.base_url()).unwrap();
    for raw in [
        "https://other.localhost/".to_owned(),
        format!("https://{}:8443/", host()),
        format!("{}private/", selection.base_url()),
        format!("{}?changed", selection.base_url()),
        format!("{}#changed", selection.base_url()),
    ] {
        assert!(
            selection
                .validate_base_url(&Url::parse(&raw).unwrap())
                .is_err()
        );
    }
    for raw in [
        "https://other.localhost/v1/musubi/publication/seed-ingress".to_owned(),
        format!("https://{}:8443/v1/musubi/publication/seed-ingress", host()),
        format!("{}v1/sorafs/stream-token", selection.base_url()),
        format!("{}v1/musubi/publication/", selection.base_url()),
        format!(
            "{}v1/musubi/publication/seed-ingress?q=1",
            selection.base_url()
        ),
        format!(
            "{}v1/musubi/publication/seed-ingress#fragment",
            selection.base_url()
        ),
        format!(
            "https://user@{}:{}/v1/musubi/publication/seed-ingress",
            host(),
            listener.local_addr().unwrap().port()
        ),
    ] {
        assert!(
            client
                .execute(reqwest::blocking::Request::new(
                    reqwest::Method::POST,
                    Url::parse(&raw).unwrap()
                ))
                .is_err()
        );
    }
    let endpoint = selection
        .base_url()
        .join("v1/musubi/publication/seed-ingress")
        .unwrap();
    assert!(
        client
            .execute(reqwest::blocking::Request::new(
                reqwest::Method::GET,
                endpoint.clone()
            ))
            .is_err()
    );
    let mut request = reqwest::blocking::Request::new(reqwest::Method::POST, endpoint);
    request.headers_mut().insert(
        reqwest::header::HOST,
        reqwest::header::HeaderValue::from_static("other.localhost"),
    );
    assert!(client.execute(request).is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn publication_client_uses_original_tls_for_all_three_routes() {
    let identity = Identity::new(&host(), false);
    let server = Server::start(
        &identity,
        3,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let selection = publication_selection(&identity, server.port);
    let client = selection.blocking_client(WAIT).unwrap();
    for route in ["seed-ingress", "storage-coordinate", "provider-readback"] {
        assert_eq!(
            publication_post(&client, &format!("v1/musubi/publication/{route}")).unwrap(),
            (200, b"ok".to_vec())
        );
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    for (name, head) in requests {
        assert_eq!(name, host());
        assert!(head.starts_with("POST /v1/musubi/publication/"));
        assert!(head.to_ascii_lowercase().contains(&format!(
            "host: {}:{}",
            host(),
            selection.base_url().port_or_known_default().unwrap()
        )));
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        assert!(!head.to_ascii_lowercase().contains("x-sorafs-stream-token:"));
    }
}
#[test]
fn publication_tls_rejects_wrong_root_name_expiry_and_same_root_leaf_substitution() {
    for (name, expired, wrong_ca, substitute_leaf) in [
        (host(), false, true, false),
        ("other.localhost".into(), false, false, false),
        (host(), true, false, false),
        (host(), false, false, true),
    ] {
        let (original, substitute) = Identity::pair(&name, expired);
        let server_identity = if substitute_leaf {
            &substitute
        } else {
            &original
        };
        let server = Server::start(
            server_identity,
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let other_root = Identity::new(&host(), false);
        let mut original_material =
            material(&original, if server.port == 8443 { 8444 } else { 8443 });
        if wrong_ca {
            // The exact served leaf is retained, isolating normal CA verification from pinning.
            original_material.proposal.endpoints[0]
                .attestation
                .intermediate_certificates[0] = other_root.root.clone();
        }
        let selection = GeneratedLocalPublicationTransportV1::select(
            network(),
            "component",
            provider(),
            &owner(),
            &original_material,
            server.port,
        )
        .unwrap();
        assert!(
            publication_post(
                &selection.blocking_client(WAIT).unwrap(),
                "v1/musubi/publication/seed-ingress"
            )
            .is_err()
        );
        assert!(server.finish().is_empty());
    }
}
#[test]
fn publication_client_never_follows_redirects_or_decompresses() {
    let identity = Identity::new(&host(), false);
    for response in [
        b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://other.localhost:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw".as_slice(),
    ] {
        let server = Server::start(&identity, 1, response);
        let selection = publication_selection(&identity, server.port);
        let expected = if response.starts_with(b"HTTP/1.1 307") { (307, vec![]) } else { (200, b"raw".to_vec()) };
        assert_eq!(publication_post(&selection.blocking_client(WAIT).unwrap(), "v1/musubi/publication/provider-readback").unwrap(), expected);
        assert_eq!(server.finish().len(), 1);
    }
}
#[test]
fn publication_client_bounds_an_unfinished_real_tls_handshake() {
    let identity = Identity::new(&host(), false);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let (release, released) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (mut socket, _) = tokio::time::timeout(WAIT, listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    tokio::time::timeout(WAIT, socket.read_u8())
                        .await
                        .unwrap()
                        .unwrap(),
                    0x16
                );
                // Keep the peer open until the client has returned on its own finite bound.
                // A leaked 30-second Request override cannot pass by observing peer closure.
                released
                    .recv_timeout(WAIT)
                    .expect("client did not enforce selected timeout");
            });
    });
    let client = publication_selection(&identity, port)
        .blocking_client(Duration::from_millis(100))
        .unwrap();
    let mut request = reqwest::blocking::Request::new(
        reqwest::Method::POST,
        client
            .selection()
            .base_url()
            .join("v1/musubi/publication/seed-ingress")
            .unwrap(),
    );
    *request.timeout_mut() = Some(Duration::from_secs(30));
    assert!(client.execute(request).is_err());
    release.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn original_selection_charges_one_frame_and_its_independently_measured_decoded_graph() {
    let identity = Identity::new(&host(), false);
    let original = material(&identity, 8443);
    let frame = norito::encode_canonical(&original).unwrap();
    let budget = 2 * 1024 * 1024;
    let limits =
        norito::DecodeLimits::new(MATERIAL_MAX, MATERIAL_MAX, MATERIAL_MAX * 2, budget, 48);
    let owned_bytes = norito::with_decode_limits_scope(limits, || {
        // Selection owns both capability decodes as well as the retained material graph.
        original.validate().unwrap();
        let policy = RegisteredAccountReadV1::from_capabilities(&original.proposal.capabilities)
            .unwrap()
            .unwrap();
        assert_eq!(policy.https_port, 8443);
        let decoded: ProviderAdmissionGenesisMaterialV1 = norito::decode_canonical(&frame).unwrap();
        assert_eq!(decoded, original);
        let norito::Error::TotalAllocationExceeded { attempted, .. } =
            norito::core::reserve_decode_allocation(budget + 1).unwrap_err()
        else {
            panic!("allocation usage probe must refuse without charging");
        };
        attempted as usize - budget - 1
    });
    let exact = frame.len() + owned_bytes;
    let limits = norito::DecodeLimits::new(MATERIAL_MAX, MATERIAL_MAX, MATERIAL_MAX * 2, exact, 48);
    norito::with_decode_limits_scope(limits, || {
        let selected = GeneratedLocalProviderTransportV1::select(
            network(),
            "component",
            provider(),
            &owner(),
            &original,
        )
        .unwrap();
        assert_eq!(selected.provider_id(), provider());
        assert!(
            GeneratedLocalProviderTransportV1::select(
                network(),
                "component",
                provider(),
                &owner(),
                &original,
            )
            .is_err(),
            "selection cannot renew its inherited allocation allowance"
        );
    });
}
