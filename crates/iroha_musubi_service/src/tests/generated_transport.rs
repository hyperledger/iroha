//! Publication selection and pre-sign origin controls; native service authority stays separate.

use super::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa};
use sorafs_manifest::{
    deal::XorQuantity,
    provider_admission::{
        EndpointAdmissionV1, EndpointAttestationKind, EndpointAttestationV1,
        ProviderAdmissionGenesisMaterialV1, ProviderAdmissionProposalV1, ProviderVrfPublicKeyV1,
    },
    provider_advert::{
        AdvertEndpoint, AvailabilityTier, CapabilityTlv, CapabilityType, EndpointKind,
        PathDiversityPolicy, ProviderAdvertBodyV1, QosHints, RendezvousTopic, StakePointer,
        account_read::RegisteredAccountReadV1,
    },
};
use std::{
    io,
    net::{Ipv4Addr, TcpListener},
    sync::atomic::AtomicUsize,
};
fn provider() -> ProviderId {
    ProviderId::new([0x11; 32])
}
fn host() -> String {
    format!("{}.{}.localhost", "11".repeat(16), "11".repeat(16))
}
struct Identity {
    root: Vec<u8>,
    leaf: Vec<u8>,
}
impl Identity {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![host()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let root = params.self_signed(&key).unwrap();
        Self {
            root: root.der().to_vec(),
            leaf: root.der().to_vec(),
        }
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

fn selection(client: &Client, port: u16) -> GeneratedLocalPublicationTransportV1 {
    // A structural original-intent fixture; actual TLS exchanges are tested in sorafs_car.
    let owner = AccountId::new(
        KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert_ne!(
        &owner,
        client.account(),
        "TLS provider owner is independent from the publisher"
    );
    let provider_port = if port == 8443 { 8444 } else { 8443 };
    GeneratedLocalPublicationTransportV1::select(
        *client.network_id(),
        client.chain().as_ref(),
        provider(),
        &owner,
        &material(&Identity::new(), provider_port),
        port,
    )
    .unwrap()
}
struct CountSigner {
    inner: SoftwareMusubiPublicationRuntimeAuthorizationSignerV1,
    calls: Arc<AtomicUsize>,
}
impl MusubiPublicationRuntimeAuthorizationSigningProviderV1 for CountSigner {
    fn publisher(&self) -> &AccountId {
        self.inner.publisher()
    }
    fn sign_approvals(
        &self,
        payload: &MusubiPublicationRuntimeAuthorizationPayloadV1,
    ) -> Result<
        Vec<MusubiPublicationRuntimeAuthorizationApprovalV1>,
        MusubiPublicationRuntimeAuthorizationSigningErrorV1,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_approvals(payload)
    }
}
fn counted(
    client: &Client,
) -> (
    Arc<dyn MusubiPublicationRuntimeAuthorizationSigningProviderV1>,
    Arc<AtomicUsize>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Arc::new(CountSigner {
            inner: SoftwareMusubiPublicationRuntimeAuthorizationSignerV1::new(
                client.account().clone(),
                client.key_pair().clone(),
            )
            .unwrap(),
            calls: calls.clone(),
        }),
        calls,
    )
}
#[test]
fn generated_constructor_binds_original_network_chain_and_independent_publisher() {
    let (client, _) = client();
    let selection = selection(&client, 9443);
    let runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_iroha_client(
        &client,
        selection.clone(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(
        runtime.generated_local_base_url(),
        Some(selection.base_url())
    );
    assert_eq!(runtime.network_id(), client.network_id());
    assert_eq!(runtime.publisher(), client.account());
    let (signer, calls) = counted(&client);
    assert!(
        AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_authorization_signer(
            test_network_id(3),
            client.account().clone(),
            signer.clone(),
            selection.clone(),
            Duration::from_secs(2)
        )
        .is_err()
    );
    assert!(
        AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_authorization_signer(
            *client.network_id(),
            client.account().clone(),
            signer.clone(),
            selection.clone(),
            Duration::ZERO
        )
        .is_err()
    );
    let foreign = AccountId::new(
        KeyPair::from_seed(vec![43; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert!(
        AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_authorization_signer(
            *client.network_id(),
            foreign,
            signer,
            selection.clone(),
            Duration::from_secs(2)
        )
        .is_err()
    );
    let mut builder = client.to_builder();
    builder.chain = ChainId::from("different");
    assert!(
        AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_iroha_client(
            &builder.build().unwrap(),
            selection,
            Duration::from_secs(2)
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let remote = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &client,
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(remote.generated_local_base_url().is_none());
    assert!(
        remote
            .validate_base_url(&Url::parse("https://remote.example/private/").unwrap())
            .is_ok()
    );
}
#[test]
fn generated_routes_refuse_changed_origin_before_signing_reading_or_sending() {
    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("foreign origin reached CAR read")
        }
    }
    let (client, _) = client();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let selected = selection(&client, listener.local_addr().unwrap().port());
    let (signer, calls) = counted(&client);
    let runtime =
        AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_authorization_signer(
            *client.network_id(),
            client.account().clone(),
            signer,
            selected.clone(),
            Duration::from_secs(1),
        )
        .unwrap();
    let fixture = private_service_fixture(false);
    let control = control_service_fixture(false, false);
    for raw in [
        "https://other.localhost/".to_owned(),
        format!("https://{}:8443/", host()),
        format!("{}private/", selected.base_url()),
        format!("{}?q=1", selected.base_url()),
        format!("{}#fragment", selected.base_url()),
    ] {
        let changed = Url::parse(&raw).unwrap();
        assert!(
            runtime
                .prepare_seed_ingress_request(
                    &changed,
                    &fixture.request,
                    &fixture.plan,
                    &mut NoRead
                )
                .is_err()
        );
        assert!(
            runtime
                .stage_seed_ingress(&changed, &fixture.request, &fixture.plan, &mut NoRead)
                .is_err()
        );
        assert!(
            runtime
                .coordinate_storage(&changed, &control.storage_request)
                .is_err()
        );
        assert!(
            runtime
                .readback_provider(&changed, &control.readback_request)
                .is_err()
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    for route in [
        "v1/musubi/publication/unrecognized",
        "v1/sorafs/stream-token",
    ] {
        let request = reqwest::blocking::Request::new(
            reqwest::Method::POST,
            selected.base_url().join(route).unwrap(),
        );
        assert!(runtime.execute_request(request).is_err());
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    // Exact selected origin can sign the original envelope without sending it.
    let prepared = runtime
        .prepare_seed_ingress_request(
            selected.base_url(),
            &fixture.request,
            &fixture.plan,
            &mut fixture.raw_car.as_slice(),
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(prepared.binding(), &fixture.request.binding);
    assert_eq!(
        prepared.as_private_http_request().path,
        MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn generated_execution_rechecks_origin_after_request_construction() {
    let (client, _) = client();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let selected = selection(&client, listener.local_addr().unwrap().port());
    let (signer, calls) = counted(&client);
    let runtime =
        AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_authorization_signer(
            *client.network_id(),
            client.account().clone(),
            signer,
            selected.clone(),
            Duration::from_secs(1),
        )
        .unwrap();
    let auth = runtime
        .authorization(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            [7; 32],
            [8; 32],
        )
        .unwrap();
    let endpoint = selected
        .base_url()
        .join(STORAGE_COORDINATION_ROUTE)
        .unwrap();
    let mut request = runtime
        .prepare_request(endpoint, APPLICATION_NORITO, &auth, None, vec![1])
        .unwrap();
    assert!(
        request
            .headers()
            .get(AUTHORIZATION_HEADER)
            .unwrap()
            .is_sensitive()
    );
    *request.url_mut() =
        Url::parse("https://foreign.localhost/v1/musubi/publication/storage-coordinate").unwrap();
    assert!(runtime.execute_request(request).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
