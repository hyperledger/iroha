//! Genuine original certificate/configuration controls; no native ownership/completion claim.
use super::*;
use iroha::crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use iroha_data_model::{
    asset::AssetDefinitionId, musubi::MusubiPackageScopeV1, transaction::FeeChargeLimit,
};
use iroha_model_base::topology::DataSpaceId;
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
use std::{io, net::TcpListener};
fn provider() -> ProviderId {
    ProviderId::new([0x21; 32])
}
fn host() -> String {
    format!("{}.{}.localhost", "21".repeat(16), "21".repeat(16))
}
struct Identity {
    root: Vec<u8>,
    leaf: Vec<u8>,
}
impl Identity {
    fn new() -> Self {
        Self::for_host(host())
    }
    fn for_host(hostname: String) -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![hostname]).unwrap();
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

struct Fixture {
    temporary: tempfile::TempDir,
    path: PathBuf,
    bytes: Vec<u8>,
    transport: GeneratedLocalPublicationTransportV1,
    namespace: GeneratedPublicationNamespaceIntentV1,
    inventories: Vec<TcpListener>,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("client.toml");
        let publisher_key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let owner_key = KeyPair::from_seed(vec![0x42; 32], Algorithm::Ed25519);
        let publisher = AccountId::new(publisher_key.public_key().clone());
        let owner = AccountId::new(owner_key.public_key().clone());
        let network = crate::publication_runtime::tests::test_network_id(0x7b);
        let transport = GeneratedLocalPublicationTransportV1::select(
            network,
            "musubi-publication-runtime-test",
            provider(),
            &owner,
            &material(&Identity::new(), 8444),
            8443,
        )
        .unwrap();
        let inventories: Vec<_> = (0..3)
            .map(|_| {
                let socket = TcpListener::bind("127.0.0.1:0").unwrap();
                socket.set_nonblocking(true).unwrap();
                socket
            })
            .collect();
        let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
        let gateways = inventories
            .iter()
            .enumerate()
            .map(|(index, socket)| {
                format!(
                    "{{ provider_id = \"{}\", url = \"{}\", attestation_url = \"http://{}/\" }}",
                    hex::encode([0x21 + index as u8; 32]),
                    transport.base_url(),
                    socket.local_addr().unwrap(),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let source = format!(
            r#"
chain = "musubi-publication-runtime-test"
network_id = "{network}"
torii_url = "http://127.0.0.1:8181/"
torii_request_timeout_ms = 2000
[account]
profile = "taira"
public_key = "{}"
private_key = "{}"
[musubi.publication]
seed_ingress_url = "{}"
storage_coordinator_url = "{}"
ingress_broker = "{}"
seed_provider = "{}"
expected_policy_revision = 1
request_timeout_ms = 5000
provider_gateways = [{gateways}]
"#,
            publisher_key.public_key(),
            ExposedPrivateKey(publisher_key.private_key().clone()),
            transport.base_url(),
            transport.base_url(),
            owner,
            hex::encode(provider().as_bytes())
        );
        let bytes = source.into_bytes();
        std::fs::write(&path, &bytes).unwrap();
        let namespace = GeneratedPublicationNamespaceIntentV1 {
            publisher,
            binding: MusubiNamespaceBindingV1 {
                namespace: "dev.universal".parse().unwrap(),
                home_dataspace: DataSpaceId::new(0),
                scope: MusubiPackageScopeV1::Domain("dev".parse().unwrap()),
                generation: 1,
            },
            policy: MusubiRegistryPolicyV1::default(),
            fee_payment: FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    AssetDefinitionId::from_uuid_bytes([
                        1, 1, 1, 1, 1, 1, 0x40, 1, 0x80, 1, 1, 1, 1, 1, 1, 1,
                    ])
                    .unwrap(),
                    iroha_primitives::numeric::Quantity::from(1000_u32),
                )],
                None,
            ),
            journal_root: temporary.path().join("namespace-parent"),
        };
        Self {
            temporary,
            path,
            bytes,
            transport,
            namespace,
            inventories,
        }
    }
    fn context(
        &self,
    ) -> Result<GeneratedPublicationContextV1, ProductionPublicationConfigurationErrorV1> {
        GeneratedPublicationContextV1::from_original_image(
            &self.path,
            &self.bytes,
            self.transport.clone(),
            self.namespace.clone(),
        )
    }
    fn no_http(&self) {
        for socket in &self.inventories {
            assert_eq!(
                socket.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}
#[test]
fn exact_generated_image_builds_sole_tls_runtime_without_http_or_namespace_initialization() {
    let fixture = Fixture::new();
    let context = fixture.context().unwrap();
    assert_eq!(
        context.namespace_intent().publisher,
        fixture.namespace.publisher
    );
    assert_eq!(
        context.transport().provider_owner(),
        &AccountId::new(
            KeyPair::from_seed(vec![0x42; 32], Algorithm::Ed25519)
                .public_key()
                .clone()
        )
    );
    let runtime = context
        .load_runtime(UnavailablePublicationCleanPackageValidatorV1)
        .unwrap();
    let (_, services, bindings) = runtime.into_parts();
    assert_eq!(
        services.http.generated_local_base_url(),
        Some(fixture.transport.base_url())
    );
    assert_eq!(bindings.expected_policy_revision, 1);
    assert!(!fixture.namespace.journal_root.exists());
    for text in [format!("{context:?}"), format!("{:?}", fixture.namespace)] {
        assert!(!text.contains(fixture.temporary.path().to_str().unwrap()));
        assert!(!text.contains("private_key"));
    }
    fixture.no_http();
}
#[test]
fn generated_context_refuses_changed_file_phase_provenance_and_original_intent() {
    let fixture = Fixture::new();
    let context = fixture.context().unwrap();
    let mut foreign = fixture.namespace.clone();
    foreign.policy.revision += 1;
    assert!(
        GeneratedPublicationContextV1::from_original_image(
            &fixture.path,
            &fixture.bytes,
            fixture.transport.clone(),
            foreign
        )
        .is_err()
    );
    let mut foreign = fixture.namespace.clone();
    foreign.publisher = AccountId::new(
        KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert!(
        GeneratedPublicationContextV1::from_original_image(
            &fixture.path,
            &fixture.bytes,
            fixture.transport.clone(),
            foreign
        )
        .is_err()
    );
    let mut changed = fixture.bytes.clone();
    changed.extend_from_slice(b"\n# changed original image\n");
    std::fs::write(&fixture.path, &changed).unwrap();
    assert_eq!(
        context.bound_image().unwrap_err().code(),
        "MUSUBI_PUBLICATION_CONFIG_CHANGED"
    );
    assert_eq!(
        context
            .load_runtime(UnavailablePublicationCleanPackageValidatorV1)
            .unwrap_err()
            .code(),
        "MUSUBI_PUBLICATION_CONFIG_CHANGED"
    );
    let foreign_image = RegistryPublicConfigImageV1::load(Some(&fixture.path)).unwrap();
    assert_eq!(
        load_bound_generated_publication_runtime_v1(
            &foreign_image.provenance(),
            &context,
            UnavailablePublicationCleanPackageValidatorV1
        )
        .unwrap_err()
        .code(),
        "MUSUBI_PUBLICATION_CONFIG_CHANGED"
    );
    assert_eq!(
        fixture.context().unwrap_err().code(),
        "MUSUBI_PUBLICATION_CONFIG_CHANGED"
    );
    fixture.no_http();
}
#[test]
fn generated_context_refuses_foreign_readback_root_broker_and_inventory_dns_without_http() {
    let fixture = Fixture::new();
    // Match the original image's explicit Taira profile when rendering both account literals.
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);

    for (old, new) in [
        (
            fixture.transport.base_url().as_str().to_owned(),
            "https://foreign.example/".to_owned(),
        ),
        (
            format!("http://{}/", fixture.inventories[0].local_addr().unwrap()),
            "https://inventory.example/".to_owned(),
        ),
        (
            fixture.transport.provider_owner().to_string(),
            fixture.namespace.publisher.to_string(),
        ),
    ] {
        let original = String::from_utf8(fixture.bytes.clone()).unwrap();
        assert!(
            original.contains(&old),
            "negative substitution target must exist"
        );
        let changed = original.replace(&old, &new).into_bytes();
        assert!(
            changed != fixture.bytes,
            "each negative must substitute the original image"
        );
        std::fs::write(&fixture.path, &changed).unwrap();
        assert!(
            GeneratedPublicationContextV1::from_original_image(
                &fixture.path,
                &changed,
                fixture.transport.clone(),
                fixture.namespace.clone()
            )
            .is_err()
        );
    }
    fixture.no_http();
}

#[path = "../../generated_publication_tests.rs"]
mod generated_publish;

#[test]
fn generated_client_configuration_uses_universal_signer_and_rejects_retired_account_domain() {
    let fixture = Fixture::new();
    let source = std::str::from_utf8(&fixture.bytes).unwrap();
    let table = source.parse::<toml::Table>().unwrap();
    let account = table.get("account").unwrap().as_table().unwrap();
    assert!(!account.contains_key("domain"));
    assert_eq!(account.get("profile").unwrap().as_str(), Some("taira"));
    let (config, _) =
        iroha::config::Config::load_bytes_with_musubi_publication(&fixture.path, &fixture.bytes)
            .unwrap();
    assert_eq!(config.account, fixture.namespace.publisher);
    assert_eq!(config.account_chain_discriminant, 369);
    let context = fixture.context().unwrap();
    assert_eq!(
        context.namespace_intent().binding,
        fixture.namespace.binding
    );
    let retired = source.replace("[account]\n", "[account]\ndomain = \"dev.universal\"\n");
    assert!(
        iroha::config::Config::load_bytes_with_musubi_publication(
            &fixture.path,
            retired.as_bytes(),
        )
        .is_err()
    );
    fixture.no_http();
}
