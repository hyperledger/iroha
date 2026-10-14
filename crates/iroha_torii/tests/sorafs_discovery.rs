//! Tests Torii's `SoraFS` discovery cache using the mesh harness from provider advert suites.

#![cfg(feature = "app_api")]
use axum::{
    body::Body,
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use http::header::CACHE_CONTROL;
use http_body_util::BodyExt;
use humantime::format_rfc3339;
use iroha_config::{
    base::util::Bytes,
    parameters::actual::{self as actual_cfg, SorafsAdmission},
};
use iroha_core::{
    kiso::KisoHandle,
    kura::Kura,
    prelude::World,
    query::store::LiveQueryStore,
    queue::Queue as CoreQueue,
    smartcontracts::Execute,
    state::{State, StateReadOnly, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, PreparedTestChainConfig, TestChainConfig},
    tx::AcceptedTransaction,
};
use iroha_crypto::{
    Algorithm, BlsNormal, Hash, HashOf, KeyGenOption, KeyPair, PrivateKey, PublicKey, Signature,
};
use iroha_data_model::{
    IntoKeyValue, NetworkId, Registrable,
    account::AccountId,
    block::BlockHeader,
    isi::sorafs::RegisterPinManifest,
    prelude as dm,
    sorafs::pin_registry::{
        ManifestAliasBinding, ManifestAliasId, ManifestAliasRecord,
        ManifestDigest as RegistryManifestDigest, PinPolicy as RegistryPinPolicy,
        StorageClass as RegistryStorageClass,
    },
    transaction::{SignedTransaction, TransactionBuilder, TransactionPayload},
};
use iroha_futures::supervisor::Child;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_torii::{
    MaybeTelemetry, OnlinePeersProvider, SoraFsOrderbookTransactionSigner,
    SoraFsOrderbookTransactionSigningError, SoraFsProofOutcomeSigningError,
    SoraFsProofOutcomeTransactionSigner, SoraFsRepairTransactionSigner,
    SoraFsRepairTransactionSigningError, SoraFsReserveTransactionSigner,
    SoraFsReserveTransactionSigningError, SorafsNativeTransactionSignerProbeErrorV1,
    SorafsNativeTransactionSignerProviderV1, SorafsNativeTransactionSignerQualificationV1,
    SorafsNativeTransactionSignerRoleV1, Torii, ToriiRuntimeDeps,
    sorafs::{
        AdmissionRegistry, AliasCachePolicyExt, ProviderAdmissionAdvertError,
        discovery::{
            AdvertError, AdvertIngest, AdvertIngestResult, AdvertWarning, ProviderAdvertCache,
            ReplayCheckpointError,
        },
        unix_now_secs,
    },
    test_utils::{AuthorityCreds, random_authority},
};
use iroha_version::{Version as _, codec::EncodeVersioned};
use mv::storage::StorageReadOnly;
use norito::{decode_from_bytes, json, to_bytes};
use sorafs_manifest::provider_advert::ProviderCapabilitySoranetPqV1;
use sorafs_manifest::{
    AdvertEndpoint, AdvertValidationError, AvailabilityTier, CapabilityTlv, CapabilityType,
    CouncilSignature, DagCodecId, ENDPOINT_ATTESTATION_VERSION_V1, EndpointAdmissionV1,
    EndpointAttestationKind, EndpointAttestationV1, EndpointKind, EndpointMetadata,
    EndpointMetadataKey, MANIFEST_DAG_CODEC, ManifestBuilder, ManifestV1,
    PROVIDER_ADVERT_VERSION_V1, PathDiversityPolicy, PinPolicy, ProfileId,
    ProviderAdmissionCouncilPolicy, ProviderAdmissionEnvelopeV1, ProviderAdmissionProposalV1,
    ProviderAdvertBodyV1, ProviderAdvertV1, ProviderCapabilityRangeV1, QosHints, RendezvousTopic,
    SignatureAlgorithm, StakePointer, StorageClass as ManifestStorageClass, StreamBudgetV1,
    TransportHintV1, TransportProtocol, XorQuantity, compute_advert_body_digest,
    compute_envelope_authorization_digest, compute_proposal_digest,
    pin_registry::{
        AliasBindingV1, AliasProofBundleV1, alias_merkle_root, alias_proof_signature_digest,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::TryInto,
    fs,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt as _;
const ISSUED_AT: u64 = 1_700_000_000;
const TTL_SECS: u64 = 3_600;
const STATUS_TIMESTAMP_KEY: &str = "sorafs_status_timestamp_unix";
const GOVERNANCE_REFS_KEY: &str = "sorafs_governance_refs";
trait ProviderAdvertCacheTestExt {
    fn ingest(
        &mut self,
        advert: ProviderAdvertV1,
        now: u64,
    ) -> Result<AdvertIngestResult, AdvertError>;
}
impl ProviderAdvertCacheTestExt for ProviderAdvertCache {
    fn ingest(
        &mut self,
        advert: ProviderAdvertV1,
        now: u64,
    ) -> Result<AdvertIngestResult, AdvertError> {
        let prepared = self.validation_policy().prepare(advert, now)?;
        self.commit_prepared(prepared, now)
    }
}
fn ingest_tests_enabled() -> bool {
    std::env::var("SORAFS_TORII_SKIP_INGEST_TESTS").map_or(true, |value| value != "1")
}
fn range_capability_payload(span: u32, granularity: u32) -> Vec<u8> {
    ProviderCapabilityRangeV1 {
        max_chunk_span: span,
        min_granularity: granularity,
        supports_sparse_offsets: false,
        requires_alignment: false,
        supports_merkle_proof: false,
    }
    .to_bytes()
    .expect("construct range capability payload")
}
fn chunk_range_capability(span: u32, granularity: u32) -> CapabilityTlv {
    CapabilityTlv {
        cap_type: CapabilityType::ChunkRangeFetch,
        payload: range_capability_payload(span, granularity),
    }
}
fn default_range_capability() -> CapabilityTlv {
    chunk_range_capability(32, 1)
}
fn soranet_pq_capability() -> CapabilityTlv {
    let payload = ProviderCapabilitySoranetPqV1 {
        supports_guard: true,
        supports_majority: false,
        supports_strict: false,
    }
    .to_bytes()
    .expect("construct soranet pq capability payload");
    CapabilityTlv {
        cap_type: CapabilityType::SoraNetHybridPq,
        payload,
    }
}
#[derive(Clone)]
struct ProviderFixture {
    advert: ProviderAdvertV1,
    envelope: ProviderAdmissionEnvelopeV1,
}
#[test]
fn torii_mesh_propagates_valid_advert() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0x11; 32],
        [0x21; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            default_range_capability(),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut mesh = ToriiMesh::with_edges(
        vec![
            ToriiNode::new(
                "alpha",
                &[
                    CapabilityType::ToriiGateway,
                    CapabilityType::ChunkRangeFetch,
                ],
                registry.clone(),
            ),
            ToriiNode::new(
                "beta",
                &[
                    CapabilityType::ToriiGateway,
                    CapabilityType::ChunkRangeFetch,
                ],
                registry.clone(),
            ),
            ToriiNode::new(
                "gamma",
                &[
                    CapabilityType::ToriiGateway,
                    CapabilityType::ChunkRangeFetch,
                ],
                registry.clone(),
            ),
        ],
        &[("alpha", "beta"), ("beta", "gamma")],
    );
    mesh.publish("alpha", &fixture.advert, ISSUED_AT + 30)
        .expect("propagation succeeds");
    for id in ["alpha", "beta", "gamma"] {
        let node = mesh.node(id);
        assert_eq!(node.stored_count(), 1, "{id} must retain the advert");
        assert_eq!(
            node.capabilities_for(&fixture.advert.body.provider_id),
            Some(vec![
                CapabilityType::ToriiGateway,
                CapabilityType::ChunkRangeFetch
            ]),
            "{id} must keep both advertised capabilities"
        );
    }
}
#[test]
fn soranet_mesh_filters_capabilities_over_shared_dht() {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let mixed_fixture = make_signed_advert(
        &signing_key,
        [0x91; 32],
        [0xB1; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            chunk_range_capability(16, 1),
        ],
        true,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&mixed_fixture));
    let mut mesh = ToriiMesh::with_edges(
        vec![
            ToriiNode::new(
                "hub",
                &[
                    CapabilityType::ToriiGateway,
                    CapabilityType::ChunkRangeFetch,
                ],
                registry.clone(),
            ),
            ToriiNode::new("edge-a", &[CapabilityType::ToriiGateway], registry.clone()),
            ToriiNode::new("edge-b", &[CapabilityType::ToriiGateway], registry.clone()),
        ],
        &[("hub", "edge-a"), ("edge-a", "edge-b")],
    );
    mesh.publish("hub", &mixed_fixture.advert, ISSUED_AT + 48)
        .expect("advert propagates across shared SORA Nexus DHT mesh");
    let hub_caps = mesh
        .node("hub")
        .capabilities_for(&mixed_fixture.advert.body.provider_id)
        .expect("hub retains advert");
    assert_eq!(
        hub_caps,
        vec![
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch
        ],
        "hub keeps full capability set"
    );
    for edge in ["edge-a", "edge-b"] {
        let caps = mesh
            .node(edge)
            .capabilities_for(&mixed_fixture.advert.body.provider_id)
            .expect("edge node stores advert from shared mesh");
        assert_eq!(
            caps,
            vec![CapabilityType::ToriiGateway],
            "{edge} should retain only recognised capabilities"
        );
    }
}
#[test]
fn torii_mesh_enforces_grease_policy() {
    let signing_key = SigningKey::from_bytes(&[8u8; 32]);
    let grease_cap = CapabilityTlv {
        cap_type: CapabilityType::VendorReserved,
        payload: vec![0xAB, 0xCD],
    };
    let grease_fixture = make_signed_advert(
        &signing_key,
        [0x55; 32],
        [0x65; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            grease_cap.clone(),
        ],
        true,
    );
    let strict_fixture = make_signed_advert(
        &signing_key,
        [0x77; 32],
        [0x88; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            grease_cap,
        ],
        false,
    );
    let registry =
        admission_registry_from_fixtures(&[grease_fixture.clone(), strict_fixture.clone()]);
    let mut mesh = ToriiMesh::with_edges(
        vec![
            ToriiNode::new(
                "modern",
                &[CapabilityType::ToriiGateway, CapabilityType::VendorReserved],
                registry.clone(),
            ),
            ToriiNode::new(
                "relay",
                &[CapabilityType::ToriiGateway, CapabilityType::VendorReserved],
                registry.clone(),
            ),
            ToriiNode::new("strict", &[CapabilityType::ToriiGateway], registry.clone()),
        ],
        &[("modern", "relay"), ("relay", "strict")],
    );
    mesh.publish("modern", &grease_fixture.advert, ISSUED_AT + 45)
        .expect("GREASE-enabled advert must propagate");
    assert_eq!(
        mesh.node("strict")
            .capabilities_for(&grease_fixture.advert.body.provider_id),
        Some(vec![CapabilityType::ToriiGateway]),
        "strict node keeps only recognised capabilities when GREASE is allowed"
    );
    assert!(
        mesh.node("strict").rejection_reasons().is_empty(),
        "strict node should not reject GREASE advert with flag set"
    );
    mesh.publish("modern", &strict_fixture.advert, ISSUED_AT + 60)
        .expect("origin accepts advert");
    assert!(
        mesh.node("strict")
            .capabilities_for(&strict_fixture.advert.body.provider_id)
            .is_none(),
        "strict node must drop adverts with unknown capabilities when GREASE is disabled"
    );
    assert!(
        mesh.node("strict")
            .rejection_reasons()
            .iter()
            .any(|reason| reason.contains("unknown capabilities")),
        "strict node should record rejection for unknown capabilities"
    );
}
#[test]
fn provider_cache_warns_when_chunk_range_missing() {
    let signing_key = SigningKey::from_bytes(&[0x90; 32]);
    let missing_range_fixture = make_signed_advert(
        &signing_key,
        [0xAA; 32],
        [0xBB; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&missing_range_fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ],
        registry,
    );
    let result = cache
        .ingest(missing_range_fixture.advert.clone(), ISSUED_AT + 15)
        .expect("advert should be accepted with warnings");
    assert!(
        matches!(result.outcome, AdvertIngest::Stored { .. }),
        "advert must be stored"
    );
    assert!(
        result
            .warnings
            .contains(&AdvertWarning::ChunkRangeCapability),
        "ingestion must emit missing_chunk_range warning"
    );
    let record = cache
        .record_by_provider(&missing_range_fixture.advert.body.provider_id)
        .expect("record stored");
    assert!(
        record
            .warnings()
            .contains(&AdvertWarning::ChunkRangeCapability),
        "cache record must retain warning metadata"
    );
}
#[test]
fn admitted_provider_lookup_rechecks_expiry_without_pruning_cached_record() {
    let signing_key = SigningKey::from_bytes(&[0x97; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA7; 32],
        [0xB7; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new([CapabilityType::ToriiGateway], registry);
    cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 1)
        .expect("council-admitted signed advert");
    let provider = fixture.advert.body.provider_id;
    assert!(
        cache
            .admitted_record_by_provider(&provider, ISSUED_AT + 1)
            .is_some()
    );
    assert!(cache.record_by_provider(&provider).is_some());
    assert!(
        cache
            .admitted_record_by_provider(&provider, fixture.advert.expires_at + 1)
            .is_none()
    );
}
#[test]
fn provider_cache_rejects_relaxed_signature_policy_even_when_signed() {
    let signing_key = SigningKey::from_bytes(&[0x91; 32]);
    let modern_fixture = make_signed_advert(
        &signing_key,
        [0xAB; 32],
        [0xBC; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            chunk_range_capability(8, 1),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&modern_fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ],
        registry,
    );
    let mut advert = modern_fixture.advert.clone();
    advert.signature_strict = false;
    resign_advert(&mut advert, &signing_key);
    let err = cache
        .ingest(advert, ISSUED_AT + 25)
        .expect_err("Torii must reject a remotely relaxed signature policy");
    assert!(
        matches!(err, AdvertError::SignaturePolicyDisabled),
        "expected mandatory signature policy failure, got: {err:?}"
    );
    assert!(cache.is_empty(), "rejected advert must not be cached");
}
#[test]
fn provider_cache_rejects_soranet_transport_without_capability() {
    let signing_key = SigningKey::from_bytes(&[0x9A; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xE1; 32],
        [0xE2; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            chunk_range_capability(8, 1),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
            CapabilityType::SoraNetHybridPq,
        ],
        registry,
    );
    let mut advert = fixture.advert.clone();
    advert.body.transport_hints = Some(vec![TransportHintV1 {
        protocol: TransportProtocol::SoraNetRelay,
        priority: 0,
    }]);
    let err = cache
        .ingest(advert, ISSUED_AT + 15)
        .expect_err("soranet transport without capability must be rejected");
    assert!(
        matches!(
            err,
            AdvertError::Validation(AdvertValidationError::SoranetTransportWithoutCapability)
        ),
        "validation error must surface soranet transport without capability"
    );
}
#[test]
fn provider_cache_accepts_soranet_transport_with_capability() {
    if !ingest_tests_enabled() {
        eprintln!("skipping soranet capability ingest test (SORAFS_TORII_SKIP_INGEST_TESTS=1)");
        return;
    }
    let signing_key = SigningKey::from_bytes(&[0x9B; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xE3; 32],
        [0xE4; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            soranet_pq_capability(),
            chunk_range_capability(8, 1),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
            CapabilityType::SoraNetHybridPq,
        ],
        registry,
    );
    let result = cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 15)
        .expect("soranet transport with capability must ingest cleanly");
    assert!(
        matches!(result.outcome, AdvertIngest::Stored { .. }),
        "soranet advert should be stored"
    );
    let record = cache
        .record_by_provider(&fixture.advert.body.provider_id)
        .expect("record stored");
    assert!(
        record
            .known_capabilities()
            .contains(&CapabilityType::SoraNetHybridPq),
        "soranet capability must be retained on ingest"
    );
    assert!(
        record
            .advert()
            .body
            .transport_hints
            .as_ref()
            .is_some_and(|hints| hints
                .iter()
                .any(|hint| hint.protocol == TransportProtocol::SoraNetRelay)),
        "transport hints must include soranet relay"
    );
}
#[test]
fn provider_cache_rejects_invalid_signature_when_strict() {
    let signing_key = SigningKey::from_bytes(&[0x92; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xCD; 32],
        [0xDE; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            chunk_range_capability(12, 1),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ],
        registry,
    );
    cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 31)
        .expect("valid current advert must be cached");
    let current_fingerprint = *cache
        .record_by_provider(&fixture.advert.body.provider_id)
        .expect("current advert cached")
        .fingerprint();
    let mut advert = fixture.advert.clone();
    advert
        .signature
        .signature
        .iter_mut()
        .for_each(|byte| *byte ^= 0xFF);
    let err = cache
        .ingest(advert, ISSUED_AT + 30)
        .expect_err("strict advert must reject invalid signature");
    assert!(
        matches!(err, AdvertError::Signature(_)),
        "expected signature failure, got: {err:?}"
    );
    assert_eq!(
        cache
            .record_by_provider(&fixture.advert.body.provider_id)
            .expect("invalid replacement preserves current advert")
            .fingerprint(),
        &current_fingerprint
    );
}
#[test]
fn provider_cache_rejects_all_zero_signature_material_when_strict() {
    let signing_key = SigningKey::from_bytes(&[0x9A; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xD1; 32],
        [0xE2; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            chunk_range_capability(12, 1),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ],
        registry,
    );
    cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 29)
        .expect("valid signed advert must be cached before malformed replacement");
    let current_fingerprint = *cache
        .record_by_provider(&fixture.advert.body.provider_id)
        .expect("current advert cached")
        .fingerprint();
    let mut advert = fixture.advert.clone();
    advert.signature.signature.fill(0);
    assert_ne!(
        advert.signature.signature,
        fixture.advert.signature.signature
    );
    let err = cache
        .ingest(advert, ISSUED_AT + 30)
        .expect_err("strict advert must reject all-zero signature material");
    assert!(
        matches!(
            err,
            AdvertError::Validation(AdvertValidationError::InvalidSignatureMaterial)
        ),
        "expected all-zero signature failure, got: {err:?}"
    );
    let stored = cache
        .record_by_provider(&fixture.advert.body.provider_id)
        .expect("all-zero signature replacement preserves current advert");
    assert_eq!(stored.fingerprint(), &current_fingerprint);
    assert_eq!(stored.advert(), &fixture.advert);
}

#[test]
fn provider_cache_rejects_invalid_signature_with_relaxed_flag() {
    let signing_key = SigningKey::from_bytes(&[0x93; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xEF; 32],
        [0xF1; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            chunk_range_capability(14, 1),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ],
        registry,
    );
    cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 31)
        .expect("valid current advert must be cached");
    let current_fingerprint = *cache
        .record_by_provider(&fixture.advert.body.provider_id)
        .expect("current advert cached")
        .fingerprint();
    let mut advert = fixture.advert.clone();
    advert.signature_strict = false;
    if let Some(first) = advert.signature.signature.first_mut() {
        *first ^= 0xAB;
    }
    let err = cache
        .ingest(advert.clone(), ISSUED_AT + 32)
        .expect_err("a relaxed remote flag must never bypass signature verification");
    assert!(
        matches!(err, AdvertError::SignaturePolicyDisabled),
        "expected mandatory signature policy failure, got: {err:?}"
    );
    // The policy rejection occurs before signature verification. Restore only
    // the mandatory flag: the same corrupt signature must fail cryptography.
    advert.signature_strict = true;
    assert_ne!(
        advert.signature.signature,
        fixture.advert.signature.signature
    );
    let err = cache
        .ingest(advert.clone(), ISSUED_AT + 32)
        .expect_err("restoring strict policy must not authorize a corrupt signature");
    assert!(
        matches!(err, AdvertError::Signature(_)),
        "expected signature verification failure, got: {err:?}"
    );
    let stored = cache
        .record_by_provider(&advert.body.provider_id)
        .expect("invalid replacement must preserve current advert");
    assert_eq!(stored.fingerprint(), &current_fingerprint);
    assert_eq!(stored.advert(), &fixture.advert);
}
#[test]
fn provider_cache_prunes_expired_records() {
    let signing_key = SigningKey::from_bytes(&[0x94; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA1; 32],
        [0xB2; 32],
        vec![
            CapabilityTlv {
                cap_type: CapabilityType::ToriiGateway,
                payload: Vec::new(),
            },
            chunk_range_capability(10, 2),
        ],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new(
        [
            CapabilityType::ToriiGateway,
            CapabilityType::ChunkRangeFetch,
        ],
        registry,
    );
    let ingest_result = cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 25)
        .expect("fresh advert ingested");
    assert!(
        matches!(ingest_result.outcome, AdvertIngest::Stored { .. }),
        "expected advert to be stored before pruning"
    );
    let removed = cache.prune_stale(fixture.advert.expires_at + 1);
    assert_eq!(removed, 1, "stale entries must be pruned");
    assert!(
        cache
            .record_by_provider(&fixture.advert.body.provider_id)
            .is_none(),
        "pruned advert must be removed from cache"
    );
}
#[test]
fn torii_mesh_rejects_stale_and_duplicate_adverts() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0x20; 32],
        [0x30; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut mesh = ToriiMesh::with_edges(
        vec![ToriiNode::new(
            "alpha",
            &[
                CapabilityType::ToriiGateway,
                CapabilityType::ChunkRangeFetch,
            ],
            registry.clone(),
        )],
        &[],
    );
    let expired_at = fixture.advert.expires_at.saturating_add(1);
    let err = mesh
        .publish("alpha", &fixture.advert, expired_at)
        .expect_err("expired advert must be rejected");
    assert!(
        err.contains("advert expired"),
        "expected expiration error, got: {err}"
    );
    assert_eq!(mesh.node("alpha").stored_count(), 0);
    mesh.publish("alpha", &fixture.advert, ISSUED_AT + 5)
        .expect("fresh advert accepted");
    assert_eq!(mesh.node("alpha").stored_count(), 1);
    mesh.publish("alpha", &fixture.advert, ISSUED_AT + 6)
        .expect("duplicate advert treated as no-op");
    assert_eq!(
        mesh.node("alpha").stored_count(),
        1,
        "duplicate advert must not increment store count"
    );
}
#[test]
fn provider_cache_rejects_non_monotonic_replacements_without_losing_current_record() {
    let signing_key = SigningKey::from_bytes(&[0x95; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA2; 32],
        [0xB3; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new([CapabilityType::ToriiGateway], registry);
    cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 1)
        .expect("initial advert stored");
    let mut current = fixture.advert.clone();
    current.issued_at += 60;
    current.expires_at += 60;
    resign_advert(&mut current, &signing_key);
    assert!(matches!(
        cache
            .ingest(current.clone(), current.issued_at)
            .expect("newer advert replaces initial record")
            .outcome,
        AdvertIngest::Replaced { .. }
    ));
    let current_fingerprint = *cache
        .record_by_provider(&current.body.provider_id)
        .expect("newer record cached")
        .fingerprint();
    let err = cache
        .ingest(fixture.advert.clone(), current.issued_at + 1)
        .expect_err("older signed advert replay must be rejected");
    assert!(matches!(
        err,
        AdvertError::NonMonotonicIssuedAt {
            current_issued_at,
            incoming_issued_at,
            ..
        } if current_issued_at == current.issued_at
            && incoming_issued_at == fixture.advert.issued_at
    ));
    let mut conflicting = current.clone();
    conflicting.expires_at += 1;
    resign_advert(&mut conflicting, &signing_key);
    let err = cache
        .ingest(conflicting, current.issued_at + 1)
        .expect_err("same issued_at with different content must be rejected");
    assert!(matches!(
        err,
        AdvertError::NonMonotonicIssuedAt {
            current_issued_at,
            incoming_issued_at,
            ..
        } if current_issued_at == current.issued_at
            && incoming_issued_at == current.issued_at
    ));
    let stored = cache
        .record_by_provider(&current.body.provider_id)
        .expect("current record preserved after rejected replacements");
    assert_eq!(stored.fingerprint(), &current_fingerprint);
    assert_eq!(stored.advert(), &current);
    assert_eq!(cache.len(), 1);
}
#[test]
fn provider_cache_retains_replay_high_water_after_short_lived_record_is_pruned() {
    let signing_key = SigningKey::from_bytes(&[0x97; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA4; 32],
        [0xB5; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new([CapabilityType::ToriiGateway], registry);
    cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 1)
        .expect("initial long-lived advert stored");
    let mut short_lived = fixture.advert.clone();
    short_lived.issued_at += 60;
    short_lived.expires_at = short_lived.issued_at + 1;
    resign_advert(&mut short_lived, &signing_key);
    cache
        .ingest(short_lived.clone(), short_lived.issued_at)
        .expect("newer short-lived advert replaces the initial record");
    let after_short_expiry = short_lived.expires_at + 1;
    assert_eq!(cache.prune_stale(after_short_expiry), 1);
    assert!(cache.is_empty());
    assert!(after_short_expiry < fixture.advert.expires_at);
    let err = cache
        .ingest(fixture.advert.clone(), after_short_expiry)
        .expect_err("pruning must not permit replay of an older still-valid advert");
    assert!(matches!(
        err,
        AdvertError::NonMonotonicIssuedAt {
            current_issued_at,
            incoming_issued_at,
            ..
        } if current_issued_at == short_lived.issued_at
            && incoming_issued_at == fixture.advert.issued_at
    ));
    assert!(cache.is_empty(), "replayed advert must not be restored");
}
#[test]
fn provider_cache_persists_replay_high_water_across_restart() {
    let signing_key = SigningKey::from_bytes(&[0x98; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA5; 32],
        [0xB6; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let temp = tempdir().expect("temporary replay checkpoint directory");
    let checkpoint = temp
        .path()
        .canonicalize()
        .expect("canonical replay checkpoint parent")
        .join("provider-advert-replay.to");
    let capacity = NonZeroUsize::new(8).unwrap();
    let mut latest = fixture.advert.clone();
    latest.issued_at += 60;
    latest.expires_at += 60;
    resign_advert(&mut latest, &signing_key);
    {
        let mut cache = ProviderAdvertCache::new_persistent(
            [CapabilityType::ToriiGateway],
            registry.clone(),
            checkpoint.clone(),
            capacity,
        )
        .expect("initialize persistent cache");
        cache
            .ingest(fixture.advert.clone(), ISSUED_AT + 1)
            .expect("store initial advert");
        cache
            .ingest(latest.clone(), latest.issued_at)
            .expect("store newer advert and durable high-water mark");
    }
    let mut restarted = ProviderAdvertCache::new_persistent(
        [CapabilityType::ToriiGateway],
        registry.clone(),
        checkpoint.clone(),
        capacity,
    )
    .expect("reload canonical replay checkpoint");
    assert!(
        restarted.is_empty(),
        "adverts themselves are not checkpointed"
    );
    let err = restarted
        .ingest(fixture.advert.clone(), latest.issued_at + 1)
        .expect_err("restart must not reopen an older advert replay window");
    assert!(matches!(
        err,
        AdvertError::NonMonotonicIssuedAt {
            current_issued_at,
            incoming_issued_at,
            ..
        } if current_issued_at == latest.issued_at
            && incoming_issued_at == fixture.advert.issued_at
    ));
    assert!(
        restarted.is_empty(),
        "replayed advert must not mutate cache"
    );
    assert!(matches!(
        restarted
            .ingest(latest.clone(), latest.issued_at + 1)
            .expect("exact durable high-water advert may restore the live cache")
            .outcome,
        AdvertIngest::Stored { .. }
    ));
    drop(restarted);
    let mut restarted_again = ProviderAdvertCache::new_persistent(
        [CapabilityType::ToriiGateway],
        registry,
        checkpoint,
        capacity,
    )
    .expect("reload checkpoint after exact restoration");
    let mut conflicting = latest.clone();
    conflicting.expires_at += 1;
    resign_advert(&mut conflicting, &signing_key);
    let err = restarted_again
        .ingest(conflicting, latest.issued_at + 1)
        .expect_err("same timestamp with different signed content must remain rejected");
    assert!(matches!(err, AdvertError::NonMonotonicIssuedAt { .. }));
    assert!(restarted_again.is_empty());
}
#[test]
fn provider_cache_rejects_foreign_network_checkpoint_with_same_admitted_provider() {
    let signing_key = SigningKey::from_bytes(&[0x98; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA5; 32],
        [0xB6; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let local_registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let temp = tempdir().expect("temporary replay checkpoint directory");
    let checkpoint = temp
        .path()
        .canonicalize()
        .expect("canonical replay checkpoint parent")
        .join("provider-advert-replay.to");
    let capacity = NonZeroUsize::new(8).expect("nonzero checkpoint bound");
    {
        let mut cache = ProviderAdvertCache::new_persistent(
            [CapabilityType::ToriiGateway],
            local_registry,
            checkpoint.clone(),
            capacity,
        )
        .expect("initialize local-network cache");
        cache
            .ingest(fixture.advert.clone(), ISSUED_AT + 1)
            .expect("persist local-network high-water mark");
    }
    let foreign_network = [0xB3; 32];
    let mut foreign = fixture;
    foreign.advert.network_id = foreign_network;
    resign_advert(&mut foreign.advert, &signing_key);
    foreign.envelope.network_id = foreign_network;
    let council_key = SigningKey::from_bytes(&[0x42; 32]);
    let digest = compute_envelope_authorization_digest(&foreign.envelope)
        .expect("compute foreign-network council preimage");
    foreign.envelope.council_signatures = vec![CouncilSignature {
        signer: council_key.verifying_key().to_bytes(),
        signature: council_key.sign(&digest).to_bytes().to_vec(),
    }];
    let foreign_registry = admission_registry_from_fixtures(std::slice::from_ref(&foreign));
    let mut foreign_cache =
        ProviderAdvertCache::new([CapabilityType::ToriiGateway], foreign_registry.clone());
    foreign_cache
        .ingest(foreign.advert, ISSUED_AT + 1)
        .expect("foreign advert and council envelope are valid as a pair");
    let error = ProviderAdvertCache::new_persistent(
        [CapabilityType::ToriiGateway],
        foreign_registry,
        checkpoint,
        capacity,
    )
    .expect_err("checkpoint from another genesis network must reject restart");
    assert!(matches!(
        error,
        ReplayCheckpointError::NetworkMismatch { expected, provided }
            if expected == foreign_network && provided == [0xA1; 32]
    ));
}
#[test]
fn provider_cache_corrupt_replay_checkpoint_fails_closed_on_restart() {
    let signing_key = SigningKey::from_bytes(&[0x99; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA6; 32],
        [0xB7; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let temp = tempdir().expect("temporary replay checkpoint directory");
    let checkpoint = temp
        .path()
        .canonicalize()
        .expect("canonical replay checkpoint parent")
        .join("provider-advert-replay.to");
    let capacity = NonZeroUsize::new(8).unwrap();
    let mut cache = ProviderAdvertCache::new_persistent(
        [CapabilityType::ToriiGateway],
        registry.clone(),
        checkpoint.clone(),
        capacity,
    )
    .expect("initialize persistent cache");
    cache
        .ingest(fixture.advert, ISSUED_AT + 1)
        .expect("write valid checkpoint");
    drop(cache);
    let mut bytes = fs::read(&checkpoint).expect("read checkpoint");
    let last = bytes.last_mut().expect("checkpoint is non-empty");
    *last ^= 0x80;
    fs::write(&checkpoint, bytes).expect("corrupt checkpoint in place");
    let err = ProviderAdvertCache::new_persistent(
        [CapabilityType::ToriiGateway],
        registry,
        checkpoint,
        capacity,
    )
    .expect_err("corrupt checkpoint must disable cache initialization");
    assert!(matches!(err, ReplayCheckpointError::Codec(_)));
}
#[test]
fn provider_cache_checkpoint_failure_rolls_back_memory_state() {
    let signing_key = SigningKey::from_bytes(&[0x9A; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA7; 32],
        [0xB8; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let temp = tempdir().expect("temporary replay checkpoint directory");
    let checkpoint = temp
        .path()
        .canonicalize()
        .expect("canonical replay checkpoint parent")
        .join("provider-advert-replay.to");
    let capacity = NonZeroUsize::new(8).unwrap();
    let mut cache = ProviderAdvertCache::new_persistent(
        [CapabilityType::ToriiGateway],
        registry,
        checkpoint.clone(),
        capacity,
    )
    .expect("initialize persistent cache");
    fs::create_dir(&checkpoint).expect("replace absent checkpoint with a directory");
    let err = cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 1)
        .expect_err("non-file checkpoint target must reject admission");
    assert!(matches!(err, AdvertError::ReplayCheckpoint(_)));
    assert!(cache.is_empty(), "failed persistence must not store advert");
    fs::remove_dir(&checkpoint).expect("remove blocking checkpoint directory");
    assert!(matches!(
        cache
            .ingest(fixture.advert, ISSUED_AT + 1)
            .expect("retry succeeds only if high-water insertion was rolled back")
            .outcome,
        AdvertIngest::Stored { .. }
    ));
}
#[test]
fn provider_cache_rejects_tampered_expiry_and_future_issue_without_mutation() {
    let signing_key = SigningKey::from_bytes(&[0x96; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0xA3; 32],
        [0xB4; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let registry = admission_registry_from_fixtures(std::slice::from_ref(&fixture));
    let mut cache = ProviderAdvertCache::new([CapabilityType::ToriiGateway], registry);
    cache
        .ingest(fixture.advert.clone(), ISSUED_AT + 1)
        .expect("initial advert stored");
    let fingerprint = *cache
        .record_by_provider(&fixture.advert.body.provider_id)
        .expect("record cached")
        .fingerprint();
    let mut extended = fixture.advert.clone();
    extended.expires_at += 60;
    let err = cache
        .ingest(extended, ISSUED_AT + 2)
        .expect_err("copied signature must not authorize an extended expiry");
    assert!(matches!(err, AdvertError::Signature(_)));
    let now = ISSUED_AT + 30;
    let mut future = fixture.advert.clone();
    future.issued_at = now + 1;
    future.expires_at += 31;
    resign_advert(&mut future, &signing_key);
    let err = cache
        .ingest(future, now)
        .expect_err("future-issued advert must be rejected");
    assert!(matches!(
        err,
        AdvertError::Validation(AdvertValidationError::IssuedInFuture {
            now: observed_now,
            issued_at,
        }) if observed_now == now && issued_at == now + 1
    ));
    let stored = cache
        .record_by_provider(&fixture.advert.body.provider_id)
        .expect("existing record preserved after rejected replacements");
    assert_eq!(stored.fingerprint(), &fingerprint);
    assert_eq!(stored.advert(), &fixture.advert);
    assert_eq!(cache.len(), 1);
}
#[test]
fn torii_mesh_rejects_invalid_path_policy() {
    let signing_key = SigningKey::from_bytes(&[0xBA; 32]);
    let fixture = make_signed_advert(
        &signing_key,
        [0x41; 32],
        [0x51; 32],
        vec![CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        }],
        false,
    );
    let mut advert = fixture.advert.clone();
    advert.body.path_policy.min_guard_weight = 0;
    let registry = admission_registry_from_fixtures(&[fixture]);
    let mut mesh = ToriiMesh::with_edges(
        vec![ToriiNode::new(
            "alpha",
            &[CapabilityType::ToriiGateway],
            registry.clone(),
        )],
        &[],
    );
    let err = mesh
        .publish("alpha", &advert, ISSUED_AT + 10)
        .expect_err("invalid path policy must fail");
    assert!(
        err.contains("path diversity"),
        "expected path diversity failure, got: {err}"
    );
    assert_eq!(mesh.node("alpha").stored_count(), 0);
}
struct ToriiNode {
    id: &'static str,
    cache: ProviderAdvertCache,
    rejections: Vec<String>,
}
impl ToriiNode {
    fn new(id: &'static str, known: &[CapabilityType], admission: Arc<AdmissionRegistry>) -> Self {
        Self {
            id,
            cache: ProviderAdvertCache::new(known.iter().copied(), admission),
            rejections: Vec::new(),
        }
    }
    fn ingest(
        &mut self,
        advert: &ProviderAdvertV1,
        now: u64,
    ) -> Result<AdvertIngestResult, String> {
        match self.cache.ingest(advert.clone(), now) {
            Ok(result) => Ok(result),
            Err(err) => {
                let reason = err.to_string();
                self.rejections.push(reason.clone());
                Err(reason)
            }
        }
    }
    fn stored_count(&self) -> usize {
        self.cache.len()
    }
    fn capabilities_for(&self, provider_id: &[u8; 32]) -> Option<Vec<CapabilityType>> {
        self.cache
            .record_by_provider(provider_id)
            .map(|record| record.known_capabilities().to_vec())
    }
    #[allow(dead_code)]
    fn warnings_for(&self, provider_id: &[u8; 32]) -> Option<Vec<AdvertWarning>> {
        self.cache
            .record_by_provider(provider_id)
            .map(|record| record.warnings().to_vec())
    }
    fn rejection_reasons(&self) -> &[String] {
        &self.rejections
    }
}
struct ToriiMesh {
    nodes: HashMap<&'static str, ToriiNode>,
    adjacency: HashMap<&'static str, Vec<&'static str>>,
}
impl ToriiMesh {
    fn with_edges(nodes: Vec<ToriiNode>, edges: &[(&'static str, &'static str)]) -> Self {
        let mut adjacency: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
        for &(a, b) in edges {
            adjacency.entry(a).or_default().push(b);
            adjacency.entry(b).or_default().push(a);
        }
        let mut node_map = HashMap::new();
        for node in nodes {
            adjacency.entry(node.id).or_default();
            node_map.insert(node.id, node);
        }
        Self {
            nodes: node_map,
            adjacency,
        }
    }
    fn publish(
        &mut self,
        origin: &'static str,
        advert: &ProviderAdvertV1,
        now: u64,
    ) -> Result<(), String> {
        let node = self
            .nodes
            .get_mut(origin)
            .ok_or_else(|| format!("node {origin} not registered"))?;
        match node.ingest(advert, now) {
            Ok(result) => match result.outcome {
                AdvertIngest::Stored { .. } | AdvertIngest::Replaced { .. } => {}
                AdvertIngest::Duplicate { .. } => return Ok(()),
            },
            Err(err) => return Err(err),
        }
        let mut queue = VecDeque::new();
        queue.push_back((origin, advert.clone()));
        let mut visited: HashSet<&'static str> = HashSet::new();
        visited.insert(origin);
        while let Some((current, advert_payload)) = queue.pop_front() {
            if let Some(neighbors) = self.adjacency.get(current).cloned() {
                for neighbor in neighbors {
                    let result = self
                        .nodes
                        .get_mut(neighbor)
                        .ok_or_else(|| format!("node {neighbor} not registered"))?
                        .ingest(&advert_payload, now);
                    if let Ok(result) = result {
                        match result.outcome {
                            AdvertIngest::Stored { .. } | AdvertIngest::Replaced { .. } => {
                                if visited.insert(neighbor) {
                                    queue.push_back((neighbor, advert_payload.clone()));
                                }
                            }
                            AdvertIngest::Duplicate { .. } => {}
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn node(&self, id: &'static str) -> &ToriiNode {
        self.nodes.get(id).expect("node registered in mesh")
    }
}
#[allow(clippy::too_many_lines)]
fn make_signed_advert(
    signing_key: &SigningKey,
    provider_id: [u8; 32],
    stake_pool_id: [u8; 32],
    capabilities: Vec<CapabilityTlv>,
    allow_unknown_capabilities: bool,
) -> ProviderFixture {
    let has_chunk_range = capabilities
        .iter()
        .any(|cap| cap.cap_type == CapabilityType::ChunkRangeFetch);
    let has_soranet = capabilities
        .iter()
        .any(|cap| cap.cap_type == CapabilityType::SoraNetHybridPq);
    let stream_budget = has_chunk_range.then_some(StreamBudgetV1 {
        max_in_flight: 8,
        max_bytes_per_sec: 9_000_000,
        burst_bytes: Some(4_500_000),
    });
    let transport_hints = {
        let mut hints = if has_chunk_range {
            vec![
                TransportHintV1 {
                    protocol: TransportProtocol::ToriiHttpRange,
                    priority: 0,
                },
                TransportHintV1 {
                    protocol: TransportProtocol::QuicStream,
                    priority: 1,
                },
            ]
        } else {
            Vec::new()
        };
        if has_soranet {
            let priority = u8::try_from(hints.len()).expect("transport hint priority fits in u8");
            hints.push(TransportHintV1 {
                protocol: TransportProtocol::SoraNetRelay,
                priority,
            });
        }
        if hints.is_empty() { None } else { Some(hints) }
    };
    let body = ProviderAdvertBodyV1 {
        provider_id,
        profile_id: "sorafs.sf1@1.0.0".to_owned(),
        profile_aliases: Some(vec!["sorafs.sf1@1.0.0".to_owned(), "sorafs-sf1".to_owned()]),
        stake: StakePointer {
            pool_id: stake_pool_id,
            stake_amount: XorQuantity::try_from_micro(5_000_000)
                .expect("fixture stake is representable"),
        },
        qos: QosHints {
            availability: AvailabilityTier::Hot,
            max_retrieval_latency_ms: 1_200,
            max_concurrent_streams: 32,
        },
        capabilities,
        endpoints: vec![AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: "storage.example.com".to_owned(),
            metadata: vec![EndpointMetadata {
                key: EndpointMetadataKey::Region,
                value: b"global".to_vec(),
            }],
        }],
        rendezvous_topics: vec![RendezvousTopic {
            topic: "sorafs.sf1.primary".to_owned(),
            region: "global".to_owned(),
        }],
        path_policy: PathDiversityPolicy {
            min_guard_weight: 5,
            max_same_asn_per_path: 1,
            max_same_pool_per_path: 1,
        },
        notes: None,
        stream_budget,
        transport_hints: transport_hints.clone(),
    };
    body.validate().expect("test advert body must validate");
    let body_clone = body.clone();
    let mut advert = ProviderAdvertV1 {
        version: PROVIDER_ADVERT_VERSION_V1,
        network_id: [0xA1; 32],
        issued_at: ISSUED_AT,
        expires_at: ISSUED_AT
            .checked_add(TTL_SECS)
            .expect("ttl addition must not overflow"),
        body,
        signature: sorafs_manifest::AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signature: vec![0; 64],
        },
        signature_strict: true,
        allow_unknown_capabilities,
    };
    let signature_payload = advert
        .signature_payload_bytes()
        .expect("serialize advert envelope for signing");
    advert.signature.signature = signing_key.sign(&signature_payload).to_bytes().to_vec();
    let attestation = EndpointAttestationV1 {
        version: ENDPOINT_ATTESTATION_VERSION_V1,
        kind: EndpointAttestationKind::Tls,
        attested_at: ISSUED_AT.saturating_sub(300),
        expires_at: ISSUED_AT + TTL_SECS + 1_200,
        leaf_certificate: vec![0xAA, 0xBB, 0xCC, 0xDD],
        intermediate_certificates: Vec::new(),
        alpn_ids: vec!["h2".to_owned()],
        report: Vec::new(),
    };
    let (vrf_public, vrf_private) =
        BlsNormal::try_keypair(KeyGenOption::UseSeed(provider_id.to_vec()))
            .expect("derive provider VRF fixture key");
    let vrf_pair: KeyPair = (vrf_public, vrf_private).into();
    let proposal = ProviderAdmissionProposalV1 {
        version: sorafs_manifest::PROVIDER_ADMISSION_PROPOSAL_VERSION_V1,
        provider_id,
        profile_id: body_clone.profile_id.clone(),
        profile_aliases: body_clone.profile_aliases.clone(),
        stake: body_clone.stake.clone(),
        capabilities: body_clone.capabilities.clone(),
        endpoints: vec![EndpointAdmissionV1 {
            endpoint: body_clone
                .endpoints
                .first()
                .expect("fixture endpoint")
                .clone(),
            attestation,
        }],
        advert_key: signing_key.verifying_key().to_bytes(),
        por_vrf_key: sorafs_manifest::ProviderVrfPublicKeyV1::BlsNormal(
            vrf_pair
                .public_key()
                .to_bytes()
                .1
                .try_into()
                .expect("Normal BLS public key is 48 bytes"),
        ),
        jurisdiction_code: "US".to_owned(),
        contact_uri: Some("mailto:ops@example.com".to_owned()),
        stream_budget,
        transport_hints: transport_hints.clone(),
    };
    let proposal_digest =
        compute_proposal_digest(&proposal).expect("compute proposal digest for fixture");
    let advert_body_digest =
        compute_advert_body_digest(&body_clone).expect("compute advert body digest");
    let council_key = SigningKey::from_bytes(&[0x42; 32]);
    let mut envelope = ProviderAdmissionEnvelopeV1 {
        version: sorafs_manifest::PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
        network_id: [0xA1; 32],
        policy_id: [0xC1; 32],
        policy_revision: 1,
        policy_digest: [0xD1; 32],
        admission_revision: 1,
        expected_current_event_digest: None,
        proposal,
        proposal_digest,
        advert_body: body_clone,
        advert_body_digest,
        issued_at: ISSUED_AT,
        retention_epoch: ISSUED_AT + TTL_SECS + 3_600,
        council_signatures: Vec::new(),
        notes: None,
    };
    let authorization_digest = compute_envelope_authorization_digest(&envelope)
        .expect("compute envelope authorization digest for fixture");
    let council_signature = council_key.sign(&authorization_digest);
    envelope.council_signatures.push(CouncilSignature {
        signer: council_key.verifying_key().to_bytes(),
        signature: council_signature.to_bytes().to_vec(),
    });
    ProviderFixture { advert, envelope }
}
fn resign_advert(advert: &mut ProviderAdvertV1, signing_key: &SigningKey) {
    advert.signature.algorithm = SignatureAlgorithm::Ed25519;
    advert.signature.public_key = signing_key.verifying_key().to_bytes().to_vec();
    advert.signature.signature = vec![0; 64];
    let payload = advert
        .signature_payload_bytes()
        .expect("serialize provider advert signature envelope");
    advert.signature.signature = signing_key.sign(&payload).to_bytes().to_vec();
}
fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sorafs_manifest/provider_admission")
}
fn test_admission_config() -> SorafsAdmission {
    SorafsAdmission
}

fn fixture_from_disk(advert_name: &str, envelope_name: &str) -> ProviderFixture {
    let advert_path = fixtures_root().join(advert_name);
    let envelope_path = fixtures_root().join(envelope_name);
    let advert_bytes = fs::read(&advert_path).unwrap_or_else(|err| {
        panic!(
            "failed to read advert fixture {}: {err}",
            advert_path.display()
        )
    });
    let envelope_bytes = fs::read(&envelope_path).unwrap_or_else(|err| {
        panic!(
            "failed to read envelope fixture {}: {err}",
            envelope_path.display()
        )
    });
    let advert =
        decode_from_bytes(&advert_bytes).expect("decode provider advert fixture from disk");
    let envelope =
        decode_from_bytes(&envelope_bytes).expect("decode provider envelope fixture from disk");
    ProviderFixture { advert, envelope }
}
fn admission_registry_from_fixtures(fixtures: &[ProviderFixture]) -> Arc<AdmissionRegistry> {
    let envelopes = fixtures
        .iter()
        .map(|fixture| fixture.envelope.clone())
        .collect::<Vec<_>>();
    let trusted_signers = envelopes
        .iter()
        .flat_map(|envelope| {
            envelope
                .council_signatures
                .iter()
                .map(|signature| signature.signer)
        })
        .collect::<HashSet<_>>();
    let policy = ProviderAdmissionCouncilPolicy::new(trusted_signers, 1)
        .expect("fixture council policy must be valid");
    let network_id = envelopes
        .first()
        .expect("fixture admission requires at least one envelope")
        .network_id;
    let registry = AdmissionRegistry::from_envelopes(network_id, policy, envelopes)
        .expect("fixture admission registry must be valid");
    Arc::new(registry)
}
struct ToriiHarness {
    #[allow(dead_code)]
    torii: Torii,
    app: iroha_torii::TestApiRouterRuntime,
    #[allow(dead_code)]
    kiso_child: Child,
    state: Arc<State>,
    native_history: Option<Mutex<Option<PinReadbackHistory>>>,
    queue: Arc<CoreQueue>,
    network_id: NetworkId,
    alias_policy: actual_cfg::SorafsAliasCachePolicy,
    // Keeps Torii persistence (including the exclusive advert replay lock)
    // isolated for the lifetime of each parallel test harness.
    _torii_data_dir: TempDir,
}
// Query fixtures retain their actual original genesis or live certified chain.
enum PinReadbackHistory {
    Prepared(PreparedTestChainConfig),
    Running(CertifiedTestChain),
}
impl ToriiHarness {
    async fn shutdown(self) {
        self.app.shutdown().await;
    }
}
/// Deterministic test-only signer used by this discovery integration harness.
///
/// Handles intentionally retain production lexical shape so the harness
/// exercises the same binding validator without weakening production checks.
struct DiscoveryNativeTransactionSigner {
    role: SorafsNativeTransactionSignerRoleV1,
    handle: &'static str,
    qualification: SorafsNativeTransactionSignerQualificationV1,
    key_pair: KeyPair,
}
impl DiscoveryNativeTransactionSigner {
    fn for_role(role: SorafsNativeTransactionSignerRoleV1) -> Self {
        let (handle, seed) = match role {
            SorafsNativeTransactionSignerRoleV1::ProofOutcome => {
                ("provider://sorafs/discovery/proof-outcome", 0xD7)
            }
            SorafsNativeTransactionSignerRoleV1::Repair => {
                ("provider://sorafs/discovery/repair", 0xD8)
            }
            SorafsNativeTransactionSignerRoleV1::Reserve => {
                ("provider://sorafs/discovery/reserve", 0xD9)
            }
            SorafsNativeTransactionSignerRoleV1::Orderbook => {
                ("provider://sorafs/discovery/orderbook", 0xDA)
            }
        };
        Self {
            role,
            handle,
            qualification: SorafsNativeTransactionSignerQualificationV1::new(1, [seed; 32]),
            key_pair: KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("derive deterministic discovery native signer"),
        }
    }
    fn configured_binding(
        &self,
    ) -> iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
        let public_key = self.key_pair.public_key().clone();
        iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding {
            software_credential: None,
            handle: self.handle.to_owned(),
            authority: AccountId::new(public_key.clone()),
            algorithm: Algorithm::Ed25519,
            public_key,
            revision: self.qualification.revision(),
            policy_digest: self.qualification.policy_digest(),
        }
    }
    fn sign_payload(&self, payload: TransactionPayload) -> Result<SignedTransaction, ()> {
        TransactionBuilder::from_payload(payload)
            .and_then(|builder| builder.try_sign(self.key_pair.private_key()))
            .map_err(|_| ())
    }
}
impl SorafsNativeTransactionSignerProviderV1 for DiscoveryNativeTransactionSigner {
    fn role(&self) -> SorafsNativeTransactionSignerRoleV1 {
        self.role
    }
    fn handle(&self) -> &str {
        self.handle
    }
    fn authority(&self) -> AccountId {
        AccountId::new(self.key_pair.public_key().clone())
    }
    fn public_key(&self) -> Result<PublicKey, SorafsNativeTransactionSignerProbeErrorV1> {
        Ok(self.key_pair.public_key().clone())
    }
    fn qualification(
        &self,
    ) -> Result<
        SorafsNativeTransactionSignerQualificationV1,
        SorafsNativeTransactionSignerProbeErrorV1,
    > {
        Ok(self.qualification)
    }
}
macro_rules! impl_discovery_signer_role {
    ($trait_name:ident, $error:ident) => {
        impl $trait_name for DiscoveryNativeTransactionSigner {
            fn sign(&self, payload: TransactionPayload) -> Result<SignedTransaction, $error> {
                self.sign_payload(payload).map_err(|_| $error::Refused)
            }
        }
    };
}
impl_discovery_signer_role!(
    SoraFsProofOutcomeTransactionSigner,
    SoraFsProofOutcomeSigningError
);
impl_discovery_signer_role!(
    SoraFsRepairTransactionSigner,
    SoraFsRepairTransactionSigningError
);
impl_discovery_signer_role!(
    SoraFsReserveTransactionSigner,
    SoraFsReserveTransactionSigningError
);
impl_discovery_signer_role!(
    SoraFsOrderbookTransactionSigner,
    SoraFsOrderbookTransactionSigningError
);
fn enable_storage_with_discovery_native_signers(cfg: &mut actual_cfg::Root) {
    cfg.torii.sorafs_storage.enabled = true;
    let configured = &mut cfg.torii.sorafs_storage.native_transaction_signers;
    configured.proof_outcome = Some(
        DiscoveryNativeTransactionSigner::for_role(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
        )
        .configured_binding(),
    );
    configured.repair = Some(
        DiscoveryNativeTransactionSigner::for_role(SorafsNativeTransactionSignerRoleV1::Repair)
            .configured_binding(),
    );
    configured.reserve = Some(
        DiscoveryNativeTransactionSigner::for_role(SorafsNativeTransactionSignerRoleV1::Reserve)
            .configured_binding(),
    );
    configured.orderbook = Some(
        DiscoveryNativeTransactionSigner::for_role(SorafsNativeTransactionSignerRoleV1::Orderbook)
            .configured_binding(),
    );
}
// Exercise the public signing, controller, transport and durable store owners.
// Deterministic fixture keys authorize one empty catalog; this is not deployment
// qualification or a provider that claims production identity on a mock transport.
fn discovery_gateway_compliance_fixture(
    directory: PathBuf,
) -> (
    actual_cfg::SorafsGatewayCompliance,
    Arc<dyn iroha_torii::sorafs::gateway::GatewayComplianceFeedTransport>,
) {
    use iroha_torii::sorafs::gateway::*;
    use sorafs_manifest::gateway_compliance::{
        GATEWAY_COMPLIANCE_ACK_VERSION_V1, GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
        GATEWAY_COMPLIANCE_FEED_VERSION_V1, GatewayComplianceAcknowledgementPayloadV1,
        GatewayComplianceAcknowledgementV1, GatewayComplianceCatalogApprovalV1,
        GatewayComplianceCatalogV1, GatewayComplianceFeedDocumentV1,
        GatewayComplianceSubjectKindV1, GatewayComplianceTrustPolicyV1,
        GatewayComplianceTrustedSignerV1,
    };
    fs::create_dir_all(&directory).expect("create isolated compliance directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("owner-only compliance directory");
    }
    let directory = directory
        .canonicalize()
        .expect("canonical compliance directory");
    let catalog_key = SigningKey::from_bytes(&[0xC1; 32]);
    let gateway_key = SigningKey::from_bytes(&[0xD2; 32]);
    // This locally supplied required feed tests governed catalog construction;
    // the production transport is constructed with its exact pins, but this
    // readback fixture makes no DNS/HTTPS request or remote provenance claim.
    let feed = actual_cfg::SorafsGatewayComplianceFeed {
        feed_id: "discovery-fixture".into(),
        url: "https://feeds.example.com/discovery.json".into(),
        required: true,
        hosts: vec![actual_cfg::SorafsGatewayComplianceFeedHost {
            hostname: "feeds.example.com".into(),
            accepted_spki_sha256: vec![[0xA5; 32]],
        }],
    };
    let pins = feed
        .hosts
        .iter()
        .map(|host| {
            (
                host.hostname.clone(),
                host.accepted_spki_sha256.iter().copied().collect(),
            )
        })
        .collect();
    let transport = Arc::new(
        ProductionGatewayComplianceFeedTransport::try_new(pins)
            .expect("actual compliance transport with the exact fixture trust inventory"),
    );
    let identity = transport
        .qualification()
        .expect("actual transport identity");
    assert!(!identity.test_marked);
    let config = actual_cfg::SorafsGatewayCompliance {
        checkpoint_path: directory.join("compliance.to"),
        feed_transport_provider: actual_cfg::SorafsGatewayRuntimeProviderBinding {
            provider_handle: identity.provider_handle,
            revision: identity.revision,
            policy_digest: identity.policy_digest,
        },
        policy_id: [0xE3; 32],
        region_id: "test".into(),
        gateway_id: "gateway-test".into(),
        catalog_threshold: 1,
        catalog_signers: vec![actual_cfg::SorafsGatewayComplianceSigner {
            signer_id: "catalog-test".into(),
            public_key: catalog_key.verifying_key().to_bytes(),
        }],
        revoked_catalog_signer_ids: Vec::new(),
        gateway_ack_threshold: 1,
        gateway_signers: vec![actual_cfg::SorafsGatewayComplianceSigner {
            signer_id: "gateway-test".into(),
            public_key: gateway_key.verifying_key().to_bytes(),
        }],
        revoked_gateway_signer_ids: Vec::new(),
        feeds: vec![feed],
        max_encoded_bytes: Bytes(4_096),
        max_decoded_bytes: Bytes(8_192),
        max_redirects: 0,
        max_dns_addresses: 1,
        connect_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(10),
        max_clock_skew: Duration::from_secs(300),
        max_feed_age: Duration::from_secs(3_600),
        max_catalog_validity: Duration::from_secs(86_400),
        max_history_entries: 16,
    };
    let signer =
        |signer: &actual_cfg::SorafsGatewayComplianceSigner| GatewayComplianceTrustedSignerV1 {
            signer_id: signer.signer_id.clone(),
            public_key: signer.public_key,
        };
    let trust_policy = GatewayComplianceTrustPolicyV1 {
        policy_id: config.policy_id,
        catalog_threshold: config.catalog_threshold,
        catalog_signers: config.catalog_signers.iter().map(signer).collect(),
        revoked_catalog_signer_ids: config.revoked_catalog_signer_ids.clone(),
        gateway_ack_threshold: config.gateway_ack_threshold,
        gateway_signers: config.gateway_signers.iter().map(signer).collect(),
        revoked_gateway_signer_ids: config.revoked_gateway_signer_ids.clone(),
    };
    let controller_config = GatewayComplianceControllerConfig {
        trust_policy: trust_policy.clone(),
        region_scope: format!("region:{}", config.region_id),
        gateway_scope: format!("gateway:{}", config.gateway_id),
        feeds: config
            .feeds
            .iter()
            .map(|feed| GatewayComplianceFeedPolicy {
                feed_id: feed.feed_id.clone(),
                url: feed.url.clone(),
                required: feed.required,
                hosts: feed
                    .hosts
                    .iter()
                    .map(|host| GatewayComplianceFeedHostPolicy {
                        hostname: host.hostname.clone(),
                        accepted_spki_sha256: host.accepted_spki_sha256.iter().copied().collect(),
                    })
                    .collect(),
            })
            .collect(),
        feed_transport_provider: Some(
            GatewayProviderBindingV1::try_new(
                config.feed_transport_provider.provider_handle.clone(),
                config.feed_transport_provider.revision,
                config.feed_transport_provider.policy_digest,
            )
            .expect("exact configured feed transport binding"),
        ),
        fetch_limits: GatewayComplianceFetchLimits {
            max_encoded_bytes: usize::try_from(config.max_encoded_bytes.0).unwrap(),
            max_decoded_bytes: usize::try_from(config.max_decoded_bytes.0).unwrap(),
            max_redirects: config.max_redirects,
            max_dns_addresses: config.max_dns_addresses,
            connect_timeout: config.connect_timeout,
            total_timeout: config.total_timeout,
        },
        max_clock_skew_secs: config.max_clock_skew.as_secs(),
        max_feed_age_secs: config.max_feed_age.as_secs(),
        max_catalog_validity_secs: config.max_catalog_validity.as_secs(),
        max_history_entries: config.max_history_entries,
    };
    let store = Arc::new(
        FileGatewayComplianceStore::new(config.checkpoint_path.clone())
            .expect("actual isolated compliance checkpoint store"),
    );
    let controller = GatewayComplianceController::new_with_feed_transport(
        controller_config.clone(),
        store.clone(),
        transport.as_ref(),
    )
    .expect("governed controller initialization");
    let now = unix_now_secs();
    let feed_document = GatewayComplianceFeedDocumentV1 {
        version: GATEWAY_COMPLIANCE_FEED_VERSION_V1,
        feed_id: config.feeds[0].feed_id.clone(),
        generated_at_unix: now,
        baseline_rules: Vec::new(),
        appeal_overrides: Vec::new(),
        legal_safety_holds: Vec::new(),
        toggles: Vec::new(),
    }
    .normalize()
    .expect("canonical locally supplied fixture feed");
    let payload = controller
        .build_catalog_payload(
            1,
            None,
            now,
            now.checked_add(config.max_catalog_validity.as_secs())
                .unwrap(),
            std::slice::from_ref(&feed_document),
        )
        .expect("canonical governed catalog with its required source anchor");
    assert_eq!(payload.source_anchors.len(), 1);
    assert_eq!(payload.source_anchors[0].feed_id, feed_document.feed_id);
    assert_eq!(
        payload.source_anchors[0].feed_digest,
        feed_document.canonical_digest().unwrap()
    );
    let digest = payload.signing_digest().expect("catalog signing digest");
    let staged = controller
        .stage_catalog(
            GatewayComplianceCatalogV1 {
                payload,
                approvals: vec![GatewayComplianceCatalogApprovalV1 {
                    version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                    signer_id: config.catalog_signers[0].signer_id.clone(),
                    signature: catalog_key.sign(&digest).to_bytes(),
                }],
            },
            now,
            GatewayComplianceMutationBindingV1 {
                key_digest: [1; 32],
                request_digest: [0x81; 32],
            },
        )
        .expect("persist signed staged catalog");
    let acknowledgement = GatewayComplianceAcknowledgementPayloadV1 {
        version: GATEWAY_COMPLIANCE_ACK_VERSION_V1,
        gateway_id: config.gateway_id.clone(),
        catalog_digest: staged.catalog_digest,
        observed_at_unix: now,
        accepted: true,
        rejection_code: None,
    };
    let digest = acknowledgement
        .signing_digest()
        .expect("public acknowledgement signing owner");
    controller
        .acknowledge(
            GatewayComplianceAcknowledgementV1 {
                payload: acknowledgement,
                signature: gateway_key.sign(&digest).to_bytes(),
            },
            now,
            GatewayComplianceMutationBindingV1 {
                key_digest: [2; 32],
                request_digest: [0x82; 32],
            },
        )
        .expect("persist signed gateway acknowledgement");
    controller
        .promote(
            staged.catalog_digest,
            1,
            now,
            GatewayComplianceMutationBindingV1 {
                key_digest: [3; 32],
                request_digest: [0x83; 32],
            },
        )
        .expect("promote exact catalog after gateway quorum");
    let expected = controller.checkpoint().expect("promoted checkpoint");
    drop(controller);
    let reopened = GatewayComplianceController::new_with_feed_transport(
        controller_config,
        store,
        transport.as_ref(),
    )
    .expect("reopen and validate actual durable compliance state");
    assert_eq!(reopened.checkpoint().unwrap(), expected);
    let decision = reopened
        .evaluate_serving(
            GatewayComplianceSubjectKindV1::ManifestDigest,
            &hex::encode([0xA4; 32]),
            now,
        )
        .expect("governed serving decision after reopen");
    assert_eq!(decision.disposition, GatewayComplianceDisposition::Allow);
    assert_eq!(decision.source, GatewayComplianceDecisionSource::NoMatch);
    assert_eq!(decision.catalog_digest, Some(staged.catalog_digest));
    // Release the same file lease before Torii acquires it during startup.
    drop(reopened);
    (config, transport)
}

#[test]
fn discovery_compliance_fixture_persists_signed_promoted_catalog() {
    use iroha_torii::sorafs::gateway::GatewayComplianceCheckpointV1;
    let directory = tempdir().expect("compliance fixture temp dir");
    let (config, _transport) = discovery_gateway_compliance_fixture(
        directory.path().canonicalize().unwrap().join("compliance"),
    );
    assert!(
        config
            .checkpoint_path
            .starts_with(directory.path().canonicalize().unwrap())
    );
    let bytes = fs::read(&config.checkpoint_path).expect("persisted canonical checkpoint");
    let checkpoint: GatewayComplianceCheckpointV1 =
        decode_from_bytes(&bytes).expect("canonical checkpoint frame");
    assert_eq!(checkpoint.revision, 3);
    assert_eq!(checkpoint.idempotency_records.len(), 3);
    assert_eq!(checkpoint.history.len(), 1);
    assert_eq!(checkpoint.serving.as_ref().unwrap().payload.sequence, 1);
    assert_eq!(checkpoint.serving, checkpoint.chain_head);
    assert!(checkpoint.candidate.is_none());
    assert!(config.feeds[0].required);
    assert_eq!(
        checkpoint
            .chain_head
            .as_ref()
            .unwrap()
            .payload
            .source_anchors
            .len(),
        1
    );
    assert_eq!(
        checkpoint
            .chain_head
            .as_ref()
            .unwrap()
            .payload
            .source_anchors[0]
            .feed_id,
        config.feeds[0].feed_id
    );
}

fn build_torii_harness(cfg: &actual_cfg::Root) -> ToriiHarness {
    build_torii_harness_with_history(cfg, None)
}

fn build_certified_torii_harness(cfg: &actual_cfg::Root) -> ToriiHarness {
    let mut config = TestChainConfig::new(World::default(), 1_000);
    config.chain_id = cfg.common.chain.clone();
    let original = CertifiedTestChain::prepare(config).expect("original discovery genesis");
    build_torii_harness_with_history(cfg, Some(original))
}

fn build_torii_harness_with_history(
    cfg: &actual_cfg::Root,
    original: Option<PreparedTestChainConfig>,
) -> ToriiHarness {
    let torii_data_dir = tempdir().expect("temporary Torii data directory");
    let mut cfg = cfg.clone();
    if let Some(original) = &original {
        cfg.genesis.expected_hash = original.genesis.expected_hash();
        cfg.genesis.public_key = original.genesis.public_key().clone();
    }
    isolate_discovery_persistence(&mut cfg.torii, &torii_data_dir);
    let native_signers = cfg.torii.sorafs_storage.enabled.then(|| {
        let proof = Arc::new(DiscoveryNativeTransactionSigner::for_role(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
        ));
        let repair = Arc::new(DiscoveryNativeTransactionSigner::for_role(
            SorafsNativeTransactionSignerRoleV1::Repair,
        ));
        let reserve = Arc::new(DiscoveryNativeTransactionSigner::for_role(
            SorafsNativeTransactionSignerRoleV1::Reserve,
        ));
        let orderbook = Arc::new(DiscoveryNativeTransactionSigner::for_role(
            SorafsNativeTransactionSignerRoleV1::Orderbook,
        ));
        let configured = &cfg
            .torii
            .sorafs_storage
            .native_transaction_signers;
        for (binding, signer) in [
            (configured.proof_outcome.as_ref(), proof.as_ref()),
            (configured.repair.as_ref(), repair.as_ref()),
            (configured.reserve.as_ref(), reserve.as_ref()),
            (configured.orderbook.as_ref(), orderbook.as_ref()),
        ] {
            assert_eq!(
                binding.expect(
                    "storage-enabled discovery fixture must explicitly configure every native signer binding"
                ),
                &signer.configured_binding(),
                "discovery harness native signer must match its explicit fixture binding"
            );
        }
        (proof, repair, reserve, orderbook)
    });
    let compliance_transport = cfg.torii.sorafs_storage.enabled.then(|| {
        assert!(
            cfg.torii.sorafs_gateway.compliance.is_none(),
            "discovery fixture owns its governed compliance policy"
        );
        let (compliance, transport) = discovery_gateway_compliance_fixture(
            cfg.torii.sorafs_storage.data_dir.join("gateway-compliance"),
        );
        cfg.torii.sorafs_gateway.compliance = Some(compliance);
        transport
    });
    let (kiso, kiso_child) = KisoHandle::start(cfg.clone());
    let chain_id = cfg.common.chain.clone();
    let network_id = NetworkId::from_genesis_hash(cfg.genesis.expected_hash);
    let (state, kura, native_history) = if let Some(original) = original {
        (
            Arc::clone(&original.state),
            Arc::clone(&original.kura),
            Some(Mutex::new(Some(PinReadbackHistory::Prepared(original)))),
        )
    } else {
        let kura = Kura::blank_kura_for_testing();
        let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
            World::default(),
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
            chain_id.clone(),
            network_id,
        ));
        (state, kura, None)
    };
    let query = state.query_handle.clone();
    let queue_cfg = actual_cfg::Queue::default();
    let queue_events: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(CoreQueue::from_config(queue_cfg, queue_events));
    let (peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let _ = peers_tx;
    let runtime_deps = ToriiRuntimeDeps::new(
        build_identity_test_fixture::build_identity(),
        MaybeTelemetry::disabled(),
    );
    let runtime_deps = if let Some((proof, repair, reserve, orderbook)) = native_signers {
        let proof: Arc<dyn SoraFsProofOutcomeTransactionSigner> = proof;
        let repair: Arc<dyn SoraFsRepairTransactionSigner> = repair;
        let reserve: Arc<dyn SoraFsReserveTransactionSigner> = reserve;
        let orderbook: Arc<dyn SoraFsOrderbookTransactionSigner> = orderbook;
        runtime_deps
            .with_sorafs_proof_outcome_signer(proof)
            .with_sorafs_repair_transaction_signer(repair)
            .with_sorafs_reserve_transaction_signer(reserve)
            .with_sorafs_orderbook_transaction_signer(orderbook)
    } else {
        runtime_deps
    };
    let runtime_deps = if let Some(transport) = compliance_transport {
        runtime_deps.with_sorafs_gateway_compliance_feed_transport(transport)
    } else {
        runtime_deps
    };
    let torii = Torii::new_with_handle(
        chain_id,
        network_id,
        kiso,
        cfg.torii.clone(),
        Arc::clone(&queue),
        tokio::sync::broadcast::channel(1).0,
        query,
        kura,
        Arc::clone(&state),
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        runtime_deps,
    )
    .expect("valid Torii SoraFS-discovery fixture");
    let app = torii
        .api_router_for_tests()
        .expect("test Torii router initializes");
    let alias_policy = cfg.torii.sorafs_alias_cache;
    ToriiHarness {
        torii,
        app,
        kiso_child,
        state,
        native_history,
        queue,
        network_id,
        alias_policy,
        _torii_data_dir: torii_data_dir,
    }
}
struct ManifestSetup {
    manifest_digest: RegistryManifestDigest,
    manifest_digest_hex: String,
    authority: AuthorityCreds,
    approved_epoch: u64,
    retention_epoch: u64,
    manifest_cid: Vec<u8>,
}
struct ManifestRequestFixture {
    transaction: SignedTransaction,
    authority: AuthorityCreds,
    manifest_payload: Vec<u8>,
    manifest_digest_hex: String,
}
fn encode_alias_proof_bytes(
    alias_namespace: &str,
    alias_name: &str,
    manifest_cid: &[u8],
    bound_epoch: u64,
    expiry_epoch: u64,
    generated_at_unix: u64,
    expires_at_hint: u64,
) -> Vec<u8> {
    let binding = AliasBindingV1 {
        alias: format!("{alias_namespace}/{alias_name}"),
        manifest_cid: manifest_cid.to_vec(),
        bound_at: bound_epoch,
        expiry_epoch,
    };
    let expires_at_unix = if expires_at_hint <= generated_at_unix {
        generated_at_unix.saturating_add(TTL_SECS)
    } else {
        expires_at_hint
    };
    let mut bundle = AliasProofBundleV1 {
        binding,
        registry_root: [0u8; 32],
        registry_height: 1,
        generated_at_unix,
        expires_at_unix,
        merkle_path: Vec::new(),
        council_signatures: Vec::new(),
    };
    let root =
        alias_merkle_root(&bundle.binding, &bundle.merkle_path).expect("compute alias proof root");
    bundle.registry_root = root;
    let digest = alias_proof_signature_digest(&bundle);
    let keypair = KeyPair::from_private_key(
        PrivateKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &[0x33; 32]).expect("seeded key"),
    )
    .expect("derive keypair");
    let signature = checked_signature(keypair.private_key(), digest.as_ref());
    let (algorithm, signer_bytes) = keypair
        .public_key()
        .try_to_bytes()
        .expect("fixture signer public key must be well-formed");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
    let signer: [u8; 32] = signer_bytes
        .try_into()
        .expect("ed25519 public key must be 32 bytes");
    bundle.council_signatures.push(CouncilSignature {
        signer,
        signature: signature.payload().to_vec(),
    });
    to_bytes(&bundle).expect("encode alias proof bundle")
}
fn checked_signature(private_key: &PrivateKey, payload: &[u8]) -> Signature {
    Signature::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn checked_manifest_request_authority_fixture() -> KeyPair {
    KeyPair::try_random().expect("generate checked manifest request authority fixture keypair")
}
#[test]
fn manifest_request_authority_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_manifest_request_authority_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture manifest request authority public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
}
fn manifest_request_fixture<F>(network_id: NetworkId, tweak_manifest: F) -> ManifestRequestFixture
where
    F: FnOnce(&mut ManifestV1),
{
    let descriptor = sorafs_manifest::chunker_registry::default_descriptor();
    let manifest_policy = PinPolicy {
        min_replicas: 3,
        storage_class: ManifestStorageClass::Hot,
        retention_epoch: 48,
    };
    let mut manifest = ManifestBuilder::new()
        .root_cid(sorafs_manifest::canonical_manifest_root_cid([0x10; 32]))
        .dag_codec(DagCodecId(MANIFEST_DAG_CODEC))
        .chunking_from_registry(ProfileId(descriptor.id.0))
        .chunk_digest_sha3_256([0xCD; 32])
        .por_root([0xCE; 32])
        .content_length(1_024)
        .car_digest([0xAA; 32])
        .car_size(4_096)
        .pin_policy(manifest_policy)
        .build()
        .expect("manifest must build");
    tweak_manifest(&mut manifest);
    let manifest_payload = manifest.encode().expect("encode canonical manifest");
    let manifest_digest = manifest.digest().expect("manifest digest");
    let manifest_digest_hex = hex::encode(manifest_digest.as_bytes());
    let key_pair = checked_manifest_request_authority_fixture();
    let account = dm::AccountId::new(key_pair.public_key().clone());
    let authority = AuthorityCreds {
        account: account.clone(),
        private_key: dm::ExposedPrivateKey(key_pair.private_key().clone()),
    };
    let instruction = RegisterPinManifest::new(manifest_payload.clone(), None, None);
    let transaction = TransactionBuilder::new(
        network_id,
        account,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction])
    .sign(key_pair.private_key());
    ManifestRequestFixture {
        transaction,
        authority,
        manifest_payload,
        manifest_digest_hex,
    }
}
fn assert_sorafs_pin_error(body: &[u8], expected_code: &str, expected_message: &str) {
    let envelope: json::Value =
        json::from_slice(body).expect("pin registration error must be canonical JSON");
    assert_eq!(
        envelope.get("code").and_then(json::Value::as_str),
        Some(expected_code),
        "pin registration error must expose the stable code; got {envelope:?}"
    );
    let message = envelope
        .get("message")
        .and_then(json::Value::as_str)
        .unwrap_or_else(|| panic!("pin registration error must include a message: {envelope:?}"));
    assert!(
        message.contains(expected_message),
        "pin registration error message must contain {expected_message:?}; got {message:?}"
    );
}
fn create_manifest_readback_setup(harness: &ToriiHarness, next_height: &mut u64) -> ManifestSetup {
    create_manifest_readback_setup_with_seed(harness, next_height, 0xAB, None, None)
}
#[allow(clippy::too_many_lines)]
fn create_manifest_readback_setup_with_seed(
    harness: &ToriiHarness,
    next_height: &mut u64,
    seed: u8,
    successor_of: Option<RegistryManifestDigest>,
    status_timestamp_unix: Option<u64>,
) -> ManifestSetup {
    let descriptor = sorafs_manifest::chunker_registry::default_descriptor();
    let manifest_policy_registry = RegistryPinPolicy {
        min_replicas: 3,
        storage_class: RegistryStorageClass::Hot,
        retention_epoch: 48,
    };
    let manifest_policy_manifest = PinPolicy {
        min_replicas: manifest_policy_registry.min_replicas,
        storage_class: ManifestStorageClass::Hot,
        retention_epoch: manifest_policy_registry.retention_epoch,
    };
    let manifest_cid = sorafs_manifest::canonical_manifest_root_cid([seed.wrapping_add(0x5A); 32]);
    let manifest = ManifestBuilder::new()
        .root_cid(manifest_cid.clone())
        .dag_codec(DagCodecId(MANIFEST_DAG_CODEC))
        .chunking_from_registry(ProfileId(descriptor.id.0))
        .chunk_digest_sha3_256([seed.wrapping_add(0x33); 32])
        .por_root([seed.max(1); 32])
        .content_length(1_024)
        .car_digest([seed.wrapping_add(31); 32])
        .car_size(4_096)
        .pin_policy(manifest_policy_manifest)
        .build()
        .expect("build manifest");
    let manifest_digest_value = manifest.digest().expect("manifest digest");
    let manifest_digest_bytes = *manifest_digest_value.as_bytes();
    let manifest_digest_hex = hex::encode(manifest_digest_bytes);
    let manifest_digest = RegistryManifestDigest::new(manifest_digest_bytes);
    // Seed the query owner's typed lifecycle record directly. Registration,
    // provider selection, fees and council admission have separate transaction tests.
    let authority = random_authority();
    let approved_epoch = 12;
    let mut metadata = iroha_model_base::metadata::Metadata::default();
    if let Some(timestamp) = status_timestamp_unix {
        metadata.insert(
            Name::from_str(STATUS_TIMESTAMP_KEY).expect("timestamp key"),
            Json::from(json::to_value(&timestamp).expect("timestamp serializes")),
        );
    }
    let mut record = iroha_data_model::sorafs::pin_registry::PinManifestRecord::new(
        manifest_digest,
        iroha_data_model::sorafs::pin_registry::ManifestRootCid::try_from_slice(&manifest.root_cid)
            .expect("canonical manifest root CID"),
        iroha_data_model::sorafs::pin_registry::ChunkerProfileHandle {
            profile_id: manifest.chunking.profile_id.0,
            namespace: manifest.chunking.namespace.clone(),
            name: manifest.chunking.name.clone(),
            semver: manifest.chunking.semver.clone(),
            multihash_code: manifest.chunking.multihash_code,
        },
        manifest.chunk_digest_sha3_256,
        manifest.por_root,
        manifest.content_length,
        manifest_policy_registry,
        authority.account.clone(),
        approved_epoch,
        None,
        successor_of,
        metadata,
    );
    record.approve(approved_epoch, None);
    let (height, previous) = {
        let view = harness.state.view();
        (
            u64::try_from(view.block_hashes().len()).expect("fixture height fits u64") + 1,
            view.latest_block_hash(),
        )
    };
    let header = BlockHeader::new(
        NonZeroU64::new(height).expect("nonzero fixture height"),
        previous,
        None,
        height,
        0,
    );
    let mut block = harness.state.block(header);
    let mut tx = block.transaction();
    let (account_id, account) = dm::Account::new(authority.account.clone())
        .build(&authority.account)
        .into_key_value();
    tx.world_mut_for_testing()
        .insert_account_for_testing(account_id, account);
    tx.world_mut_for_testing()
        .pin_manifests_mut_for_testing()
        .insert(manifest_digest, record);
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("seed typed pin query world");
    commit_pin_readback_fixture(harness);
    *next_height = height + 1;
    ManifestSetup {
        manifest_digest,
        manifest_digest_hex,
        authority,
        approved_epoch,
        retention_epoch: manifest_policy_registry.retention_epoch,
        manifest_cid,
    }
}
fn create_successor_manifest_readback(
    harness: &ToriiHarness,
    predecessor: &ManifestSetup,
    next_height: &mut u64,
    seed: u8,
    status_timestamp_unix: u64,
) -> ManifestSetup {
    create_manifest_readback_setup_with_seed(
        harness,
        next_height,
        seed,
        Some(predecessor.manifest_digest),
        Some(status_timestamp_unix),
    )
}
fn ensure_authority_registered(
    harness: &ToriiHarness,
    authority: &AuthorityCreds,
    next_height: &mut u64,
) {
    let view = harness.state.view();
    let account_exists = view.world().accounts().get(&authority.account).is_some();
    let fee_asset_id = harness.state.gov.sorafs_pin_fee_asset_id.clone();
    let treasury = harness.state.gov.sorafs_pin_fee_treasury_account.clone();
    let treasury_exists = view.world().accounts().get(&treasury).is_some();
    let fee_asset_exists = view
        .world()
        .asset_definitions()
        .get(&fee_asset_id)
        .is_some();
    let authority_fee_asset = dm::AssetId::new(fee_asset_id.clone(), authority.account.clone());
    let fee_balance_exists = view.world().assets().get(&authority_fee_asset).is_some();
    if account_exists && treasury_exists && fee_asset_exists && fee_balance_exists {
        return;
    }
    drop(view);
    let prev_hash = harness.state.view().latest_block_hash();
    let header = BlockHeader::new(
        NonZeroU64::new(*next_height).expect("block height fits into NonZeroU64"),
        prev_hash,
        None,
        *next_height,
        0,
    );
    let mut block = harness.state.block(header);
    let mut tx = block.transaction();
    if !account_exists {
        let account = dm::Account::new(authority.account.clone()).build(&authority.account);
        let (account_id, account_value) = account.into_key_value();
        tx.world_mut_for_testing()
            .insert_account_for_testing(account_id, account_value);
    }
    if !treasury_exists {
        let account = dm::Account::new(treasury.clone()).build(&authority.account);
        let (account_id, account_value) = account.into_key_value();
        tx.world_mut_for_testing()
            .insert_account_for_testing(account_id, account_value);
    }
    if !fee_asset_exists {
        let definition = dm::AssetDefinition::numeric(
            fee_asset_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        );
        dm::Register::asset_definition(definition)
            .execute(&authority.account, &mut tx)
            .expect("register SoraFS fee asset definition");
    }
    if !fee_balance_exists {
        dm::Mint::asset_quantity(
            10_000_000_000_000_u128,
            dm::AssetId::new(fee_asset_id, authority.account.clone()),
        )
        .execute(&authority.account, &mut tx)
        .expect("mint SoraFS fee balance for test authority");
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit authority registration block");
}
fn attach_governance_revocation(
    harness: &ToriiHarness,
    setup: &ManifestSetup,
    alias_label: &str,
    effective_at_unix: u64,
    next_height: &mut u64,
) {
    let prev_hash = harness.state.view().latest_block_hash();
    let header = BlockHeader::new(
        NonZeroU64::new(*next_height).expect("block height fits into NonZeroU64"),
        prev_hash,
        None,
        *next_height,
        0,
    );
    let mut block = harness.state.block(header);
    let mut tx = block.transaction();
    {
        let world = tx.world_mut_for_testing();
        let manifests = world.pin_manifests_mut_for_testing();
        let record = manifests
            .get_mut(&setup.manifest_digest)
            .expect("manifest must exist before governance update");
        let key = Name::from_str(GOVERNANCE_REFS_KEY).expect("governance key");
        let mut targets = json::Map::new();
        targets.insert("alias".into(), json::Value::String(alias_label.to_string()));
        targets.insert(
            "pin_digest_hex".into(),
            json::Value::String(setup.manifest_digest_hex.clone()),
        );
        let mut entry = json::Map::new();
        entry.insert(
            "kind".into(),
            json::Value::String("RevokeManifest".to_owned()),
        );
        entry.insert(
            "effective_at".into(),
            json::to_value(&effective_at_unix).expect("effective_at serializes"),
        );
        entry.insert("targets".into(), json::Value::Object(targets));
        entry.insert(
            "signers".into(),
            json::Value::Array(vec![json::Value::String("council-1".to_owned())]),
        );
        let value = json::Value::Array(vec![json::Value::Object(entry)]);
        record.metadata.insert(key, Json::from(value));
        let status_key = Name::from_str(STATUS_TIMESTAMP_KEY).expect("status timestamp key");
        record.metadata.insert(
            status_key,
            Json::from(
                json::to_value(&effective_at_unix).expect("status timestamp serializes to json"),
            ),
        );
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit governance metadata block");
    *next_height += 1;
}
#[allow(clippy::too_many_arguments)]
fn bind_alias_with_proof(
    harness: &ToriiHarness,
    setup: &ManifestSetup,
    alias_namespace: &str,
    alias_name: &str,
    generated_at_unix: u64,
    expires_at_unix: u64,
    bound_epoch: u64,
    expiry_epoch: u64,
    next_height: &mut u64,
) {
    let proof = encode_alias_proof_bytes(
        alias_namespace,
        alias_name,
        &setup.manifest_cid,
        bound_epoch,
        expiry_epoch,
        generated_at_unix,
        expires_at_unix,
    );
    let binding = ManifestAliasBinding {
        name: alias_name.to_owned(),
        namespace: alias_namespace.to_owned(),
        proof,
    };
    let alias_record = ManifestAliasRecord::new(
        binding.clone(),
        setup.manifest_digest,
        setup.authority.account.clone(),
        bound_epoch,
        expiry_epoch,
    );
    let prev_hash = harness.state.view().latest_block_hash();
    let header = BlockHeader::new(
        NonZeroU64::new(*next_height).unwrap_or_else(|| NonZeroU64::new(1).unwrap()),
        prev_hash,
        None,
        *next_height,
        0,
    );
    let mut block = harness.state.block(header);
    let mut tx = block.transaction();
    {
        let world = tx.world_mut_for_testing();
        {
            let manifests = world.pin_manifests_mut_for_testing();
            let record = manifests
                .get_mut(&setup.manifest_digest)
                .expect("manifest must exist before binding alias");
            record.alias = Some(binding.clone());
        }
        {
            let aliases = world.manifest_aliases_mut_for_testing();
            aliases.insert(ManifestAliasId::from(&binding), alias_record);
        }
    }
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit alias binding block");
}
#[tokio::test]
async fn sorafs_routes_disabled_when_cache_off() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = false;
    cfg.torii.sorafs_discovery.admission = None;
    let harness = build_torii_harness(&cfg);
    let app = harness.app.clone();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/sorafs/providers")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_discovery_without_local_trust_starts_with_no_admitted_providers() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = None;
    let harness = build_torii_harness(&cfg);
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sorafs/providers")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("native discovery responds before any governed admission");
    assert_eq!(response.status(), StatusCode::OK);
    let body = BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let body: json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        body.get("providers")
            .and_then(json::Value::as_array)
            .unwrap()
            .len(),
        0
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_routes_enabled_with_native_admission() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    let harness = build_torii_harness(&cfg);
    let app = harness.app.clone();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sorafs/providers")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let payload: json::Value = json::from_slice(&body).expect("valid JSON");
    assert_eq!(
        payload
            .get("count")
            .and_then(json::Value::as_u64)
            .expect("count present"),
        0
    );
    assert!(
        payload
            .get("providers")
            .and_then(json::Value::as_array)
            .expect("providers array")
            .is_empty()
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_capacity_route_disabled_when_storage_off() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_storage.enabled = false;
    let harness = build_torii_harness(&cfg);
    let app = harness.app.clone();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/sorafs/capacity/state")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_pin_register_queues_caller_signed_transaction_when_storage_off() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.transport.norito_rpc.enabled = true;
    cfg.torii.transport.norito_rpc.stage = actual_cfg::NoritoRpcStage::Ga;
    // Registration is a caller-signed ledger submission; local storage service
    // availability does not remove this canonical transaction endpoint.
    cfg.torii.sorafs_storage.enabled = false;
    assert!(!cfg.torii.sorafs_storage.enabled);
    let harness = build_torii_harness(&cfg);
    let fixture = manifest_request_fixture(harness.network_id, |_| {});
    let mut next_height = 1;
    ensure_authority_registered(&harness, &fixture.authority, &mut next_height);
    let submitted_hash = fixture.transaction.hash();
    let body = pin_register_json_body(&fixture.transaction);
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(body, "application/json"))
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = BodyExt::collect(response.into_body())
        .await
        .expect("collect response body")
        .to_bytes();
    assert!(
        status == StatusCode::ACCEPTED,
        "pin register route failed: {status} body={}",
        String::from_utf8_lossy(&bytes)
    );
    let value: json::Value = json::from_slice(&bytes).expect("decode response");
    assert_eq!(
        value
            .get("manifest_digest_hex")
            .and_then(json::Value::as_str),
        Some(fixture.manifest_digest_hex.as_str())
    );
    assert_eq!(
        value.get("tx_hash_hex").and_then(json::Value::as_str),
        Some(hex::encode(submitted_hash.as_ref()).as_str())
    );
    assert_eq!(
        value.get("status").and_then(json::Value::as_str),
        Some("submitted")
    );
    assert_eq!(
        value.as_object().map(|object| object.len()),
        Some(3),
        "admission response must not claim a fee, custody result, or finalized pin status"
    );
    let queued = {
        let state_view = harness.state.view();
        harness
            .queue
            .all_transactions(&state_view)
            .collect::<Vec<_>>()
    };
    assert!(
        queued
            .iter()
            .filter_map(AcceptedTransaction::external)
            .any(|transaction| transaction.hash() == submitted_hash),
        "the dedicated route must queue the original caller-signed transaction unchanged"
    );
    harness.shutdown().await;
}
#[test]
#[should_panic(
    expected = "storage-enabled discovery fixture must explicitly configure every native signer binding"
)]
fn storage_enabled_discovery_harness_rejects_missing_explicit_native_signers() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_storage.enabled = true;
    let _ = build_torii_harness(&cfg);
}
#[tokio::test]
async fn sorafs_capacity_route_enabled_when_storage_on() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let app = harness.app.clone();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/sorafs/capacity/state")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let payload: json::Value = json::from_slice(&body).expect("valid JSON");
    assert_eq!(
        payload
            .get("declaration_count")
            .and_then(json::Value::as_u64)
            .expect("declaration_count present"),
        0
    );
    assert!(
        payload
            .get("declarations")
            .and_then(json::Value::as_array)
            .expect("declarations array")
            .is_empty()
    );
    assert_eq!(
        payload
            .get("ledger_count")
            .and_then(json::Value::as_u64)
            .expect("ledger_count present"),
        0
    );
    assert!(
        payload
            .get("fee_ledger")
            .and_then(json::Value::as_array)
            .expect("fee_ledger array")
            .is_empty()
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn retired_storage_ingest_and_fetch_are_not_mounted_and_inventory_requires_authentication() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sorafs/storage/pin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"manifest_b64":"AA==","payload_b64":"AA=="}"#,
                ))
                .expect("retired ingest request"),
        )
        .await
        .expect("retired ingest response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    for path in [
        "/v1/sorafs/aliases",
        "/v1/sorafs/replication",
        "/v1/sorafs/storage/state",
    ] {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .expect("unsigned SoraFS inventory request"),
            )
            .await
            .expect("unsigned SoraFS inventory response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let fetch_response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sorafs/storage/fetch")
                .header("content-type", "application/json")
                .body(Body::from("{"))
                .expect("unsigned malformed storage fetch request"),
        )
        .await
        .expect("unsigned malformed storage fetch response");
    assert_eq!(fetch_response.status(), StatusCode::NOT_FOUND);
    harness.shutdown().await;
}
fn pin_register_json_body(transaction: &SignedTransaction) -> Vec<u8> {
    // The model serializer owns the inner payload. Torii's versioned ingress
    // requires this exact numeric-version envelope for JSON and a version byte
    // for Norito; a bare model object is not a second request representation.
    let mut envelope = json::Map::new();
    envelope.insert("version".into(), json::Value::from(transaction.version()));
    envelope.insert(
        "content".into(),
        json::to_value(transaction).expect("serialize signed transaction content"),
    );
    json::to_vec(&json::Value::Object(envelope))
        .expect("serialize canonical versioned pin transaction JSON")
}

#[tokio::test]
async fn pin_register_json_fixture_roundtrips_through_the_public_http_route() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.transport.norito_rpc.enabled = true;
    cfg.torii.transport.norito_rpc.stage = actual_cfg::NoritoRpcStage::Ga;
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let fixture = manifest_request_fixture(harness.network_id, |_| {});
    let mut next_height = 1;
    ensure_authority_registered(&harness, &fixture.authority, &mut next_height);
    let body = pin_register_json_body(&fixture.transaction);
    let envelope: json::Value = json::from_slice(&body).expect("versioned JSON object");
    let fields = envelope.as_object().expect("versioned JSON fields");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields.get("version").and_then(json::Value::as_u64), Some(1));
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(body, "application/json"))
        .await
        .expect("public HTTP router responds");
    let status = response.status();
    let bytes = BodyExt::collect(response.into_body())
        .await
        .expect("collect canonical admission response")
        .to_bytes();
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "public ingress must decode canonical fixture JSON: {}",
        String::from_utf8_lossy(&bytes)
    );
    {
        let state_view = harness.state.view();
        let queued = harness
            .queue
            .all_transactions(&state_view)
            .collect::<Vec<_>>();
        assert_eq!(
            queued.len(),
            1,
            "only the original transaction enters the queue"
        );
        let decoded = queued[0].external().expect("caller-signed transaction");
        assert_eq!(
            decoded.encode_versioned(),
            fixture.transaction.encode_versioned()
        );
        assert_eq!(decoded.hash(), fixture.transaction.hash());
        decoded
            .verify_signature()
            .expect("HTTP roundtrip preserves the caller's actual signature");
    }
    let content = fields
        .get("content")
        .expect("signed transaction content")
        .clone();
    let mut string_version = fields.clone();
    string_version.insert("version".into(), json::Value::from("1"));
    let mut future_version = fields.clone();
    future_version.insert("version".into(), json::Value::from(2_u8));
    let mut unknown_field = fields.clone();
    unknown_field.insert("private_key".into(), json::Value::from("[redacted]"));
    let mut missing_content = fields.clone();
    missing_content.remove("content");
    let rejected = [
        content,
        json::Value::Object(string_version),
        json::Value::Object(future_version),
        json::Value::Object(unknown_field),
        json::Value::Object(missing_content),
    ];
    for mutant in rejected {
        let bytes = json::to_vec(&mutant).expect("serialize invalid envelope control");
        let response = harness
            .app
            .clone()
            .oneshot(pin_register_http_request(bytes, "application/json"))
            .await
            .expect("public HTTP router responds to invalid envelope");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "bare, aliased, future, unknown-field or missing-content envelope must fail"
        );
        assert_eq!(
            response.headers().get("x-iroha-reject-code").unwrap(),
            "invalid_transaction_payload"
        );
        let state_view = harness.state.view();
        let queued = harness
            .queue
            .all_transactions(&state_view)
            .collect::<Vec<_>>();
        assert_eq!(
            queued.len(),
            1,
            "invalid envelopes must not add a transaction"
        );
        let retained = queued[0]
            .external()
            .expect("retained caller-signed transaction");
        assert_eq!(
            retained.encode_versioned(),
            fixture.transaction.encode_versioned()
        );
    }
    harness.shutdown().await;
}

fn pin_register_http_request(body: Vec<u8>, content_type: &'static str) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/sorafs/pin/register")
        .header("content-type", content_type)
        .header("accept", "application/json")
        .body(Body::from(body))
        .expect("build pin-register request");
    request
        .extensions_mut()
        .insert(ConnectInfo::<SocketAddr>(SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))));
    request
}
#[tokio::test]
async fn sorafs_pin_register_route_accepts_caller_signed_transaction() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.transport.norito_rpc.enabled = true;
    cfg.torii.transport.norito_rpc.stage = actual_cfg::NoritoRpcStage::Ga;
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let fixture = manifest_request_fixture(harness.network_id, |_| {});
    let mut next_height = 1;
    ensure_authority_registered(&harness, &fixture.authority, &mut next_height);
    let submitted_hash = fixture.transaction.hash();
    let body = pin_register_json_body(&fixture.transaction);
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(body, "application/json"))
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = BodyExt::collect(response.into_body())
        .await
        .expect("collect response body")
        .to_bytes();
    assert!(
        status == StatusCode::ACCEPTED,
        "pin register route failed: {status} body={}",
        String::from_utf8_lossy(&bytes)
    );
    let value: json::Value = json::from_slice(&bytes).expect("decode response");
    assert_eq!(
        value
            .get("manifest_digest_hex")
            .and_then(json::Value::as_str),
        Some(fixture.manifest_digest_hex.as_str())
    );
    assert_eq!(
        value.get("tx_hash_hex").and_then(json::Value::as_str),
        Some(hex::encode(submitted_hash.as_ref()).as_str())
    );
    assert_eq!(
        value.get("status").and_then(json::Value::as_str),
        Some("submitted")
    );
    assert_eq!(
        value.as_object().map(|object| object.len()),
        Some(3),
        "admission response must not claim a fee, custody result, or finalized pin status"
    );
    let queued = {
        let state_view = harness.state.view();
        harness
            .queue
            .all_transactions(&state_view)
            .collect::<Vec<_>>()
    };
    assert!(
        queued
            .iter()
            .filter_map(AcceptedTransaction::external)
            .any(|transaction| transaction.hash() == submitted_hash),
        "the dedicated route must queue the original caller-signed transaction unchanged"
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_pin_register_route_accepts_versioned_norito_transaction() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.transport.norito_rpc.enabled = true;
    cfg.torii.transport.norito_rpc.stage = actual_cfg::NoritoRpcStage::Ga;
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let fixture = manifest_request_fixture(harness.network_id, |_| {});
    let mut next_height = 1;
    ensure_authority_registered(&harness, &fixture.authority, &mut next_height);
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(
            fixture.transaction.encode_versioned(),
            "application/x-norito",
        ))
        .await
        .expect("router responds");
    let status = response.status();
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    assert!(
        status == StatusCode::ACCEPTED,
        "pin register Norito transaction failed: {status} body={}",
        String::from_utf8_lossy(&body)
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_pin_register_validates_signed_manifest_bytes() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let fixture = manifest_request_fixture(harness.network_id, |manifest| {
        manifest.chunking.name = "bogus".into();
    });
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(
            pin_register_json_body(&fixture.transaction),
            "application/json",
        ))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    assert_sorafs_pin_error(
        &body,
        "sorafs_pin_manifest_payload_invalid",
        "chunker descriptor mismatch",
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_pin_register_rejects_secret_bearing_legacy_body() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let fixture = manifest_request_fixture(harness.network_id, |_| {});
    let legacy = norito::json!({
        "authority": (fixture.authority.account.to_string()),
        "private_key": "[redacted]",
        "manifest_payload": (BASE64_STANDARD.encode(&fixture.manifest_payload)),
        "submitted_epoch": 6_u64
    });
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(
            norito::json::to_vec(&legacy).expect("serialize retired body"),
            "application/json",
        ))
        .await
        .expect("router responds");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "the removed secret-bearing DTO must fail closed"
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_pin_register_rejects_wrong_shape_network_and_signature() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let fixture = manifest_request_fixture(harness.network_id, |_| {});
    let two_instructions = TransactionBuilder::new(
        harness.network_id,
        fixture.authority.account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        RegisterPinManifest::new(fixture.manifest_payload.clone(), None, None),
        RegisterPinManifest::new(fixture.manifest_payload.clone(), None, None),
    ])
    .sign(&fixture.authority.private_key.0);
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(
            pin_register_json_body(&two_instructions),
            "application/json",
        ))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("collect shape error")
        .to_bytes();
    assert_sorafs_pin_error(
        &body,
        "sorafs_pin_transaction_instruction_count_invalid",
        "exactly one RegisterPinManifest",
    );
    let wrong_network =
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"Sorafs discovery wrong-network fixture",
        )));
    let wrong_network_fixture = manifest_request_fixture(wrong_network, |_| {});
    wrong_network_fixture
        .transaction
        .verify_signature()
        .expect("wrong-network adversary retains a valid caller signature");
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(
            pin_register_json_body(&wrong_network_fixture.transaction),
            "application/json",
        ))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("collect network error")
        .to_bytes();
    assert_sorafs_pin_error(
        &body,
        "sorafs_pin_transaction_network_mismatch",
        "signed transaction network does not match",
    );
    let fixture = manifest_request_fixture(harness.network_id, |_| {});
    let tamper_key = checked_manifest_request_authority_fixture();
    let tampered = fixture
        .transaction
        .with_authority(dm::AccountId::new(tamper_key.public_key().clone()));
    assert!(
        tampered.verify_signature().is_err(),
        "changing the signed authority must create an effective signature mutant"
    );
    let response = harness
        .app
        .clone()
        .oneshot(pin_register_http_request(
            pin_register_json_body(&tampered),
            "application/json",
        ))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = BodyExt::collect(response.into_body())
        .await
        .expect("collect signature error")
        .to_bytes();
    assert_sorafs_pin_error(
        &body,
        "sorafs_pin_transaction_signature_invalid",
        "signed transaction signature verification failed",
    );
    let state_view = harness.state.view();
    assert!(
        harness.queue.all_transactions(&state_view).next().is_none(),
        "shape, network and signature adversaries must never enter the queue"
    );
    drop(state_view);
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_pin_register_rejects_invalid_encoded_bodies() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.transport.norito_rpc.enabled = true;
    cfg.torii.transport.norito_rpc.stage = actual_cfg::NoritoRpcStage::Ga;
    enable_storage_with_discovery_native_signers(&mut cfg);
    let harness = build_torii_harness(&cfg);
    let app = harness.app.clone();
    let invalid_json = app
        .clone()
        .oneshot(pin_register_http_request(b"{".to_vec(), "application/json"))
        .await
        .expect("router responds");
    assert_eq!(invalid_json.status(), StatusCode::BAD_REQUEST);
    let invalid_norito = app
        .oneshot(pin_register_http_request(
            vec![0xFF, 0x00, 0x01, 0x02],
            "application/x-norito",
        ))
        .await
        .expect("router responds");
    assert_eq!(invalid_norito.status(), StatusCode::BAD_REQUEST);
    harness.shutdown().await;
}
// World-only query setup is captured by an actual original native publication.
// Successors contain the test chain's signed clock work; no empty block is fabricated.
fn commit_pin_readback_fixture(harness: &ToriiHarness) {
    let mut owner = harness
        .native_history
        .as_ref()
        .expect("certified query harness")
        .lock()
        .expect("native query history lock");
    let chain = match owner.take().expect("original native history") {
        PinReadbackHistory::Prepared(original) => CertifiedTestChain::from_prepared(original)
            .expect("actual genesis executes and publishes"),
        PinReadbackHistory::Running(mut chain) => {
            let next_time = u64::try_from(
                chain
                    .state()
                    .view()
                    .latest_block()
                    .expect("funded canonical history read")
                    .unwrap()
                    .header()
                    .creation_time()
                    .as_millis(),
            )
            .unwrap()
                + 1_000;
            chain.commit_at(next_time, Vec::new());
            chain
        }
    };
    *owner = Some(PinReadbackHistory::Running(chain));
}
async fn assert_finalized_pin_readback(
    harness: &ToriiHarness,
    setup: &ManifestSetup,
    query: Option<&str>,
) -> iroha_data_model::sorafs::pin_registry::PinManifestFinalizedRecordV1 {
    use iroha_data_model::sorafs::pin_registry::{
        PinManifestFinalizedCursorV1, PinManifestFinalizedRecordV1,
    };
    let expected = {
        let view = harness.state.view();
        PinManifestFinalizedRecordV1 {
            finalized_cursor: PinManifestFinalizedCursorV1 {
                height: u64::try_from(view.block_hashes().len()).expect("fixture height fits u64"),
                block_hash: *view
                    .block_hashes()
                    .last()
                    .expect("committed fixture block")
                    .as_ref(),
            },
            manifest: view
                .world()
                .pin_manifests()
                .get(&setup.manifest_digest)
                .expect("registered fixture manifest")
                .clone(),
        }
    };
    let mut path = format!("/v1/sorafs/pin/{}", setup.manifest_digest_hex);
    if let Some(query) = query {
        path.push('?');
        path.push_str(query);
    }
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("accept", "application/json")
        .body(Body::empty())
        .expect("build finalized pin request");
    let response = harness
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("pin response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store, max-age=0")
    );
    for header in [
        "sora-proof",
        "sora-name",
        "sora-proof-status",
        "age",
        "warning",
        "retry-after",
    ] {
        assert!(
            response.headers().get(header).is_none(),
            "pin record must not emit {header}"
        );
    }
    let bytes = BodyExt::collect(response.into_body())
        .await
        .expect("pin body")
        .to_bytes();
    let value: json::Value = json::from_slice(&bytes).expect("native pin JSON");
    assert_eq!(
        value,
        json::to_value(&expected).expect("expected native record JSON")
    );
    let actual: PinManifestFinalizedRecordV1 =
        json::from_slice(&bytes).expect("native finalized record");
    assert_eq!(actual, expected);
    assert_ne!(actual.finalized_cursor.height, 0);
    assert_ne!(actual.finalized_cursor.block_hash, [0; 32]);
    actual
}
async fn pin_readback_status(harness: &ToriiHarness, path: &str) -> StatusCode {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("accept", "application/json")
        .body(Body::empty())
        .expect("pin request");
    harness
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("pin response")
        .status()
}
fn sign_alias_read_request(
    harness: &ToriiHarness,
    authority: &AuthorityCreds,
    mut request: Request<Body>,
) -> Request<Body> {
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let timestamp_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis(),
    )
    .expect("timestamp fits u64");
    let nonce = format!(
        "alias-read-{}",
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let message = iroha_torii::canonical_network_request_signature_message(
        &harness.network_id,
        request.method(),
        request.uri(),
        &[],
        timestamp_ms,
        &nonce,
    )
    .expect("canonical alias read request");
    let signature = checked_signature(&authority.private_key.0, &message);
    let headers = request.headers_mut();
    headers.insert(
        iroha_torii::HEADER_ACCOUNT,
        authority
            .account
            .to_canonical_hex()
            .expect("canonical account")
            .parse()
            .expect("account header"),
    );
    headers.insert(
        iroha_torii::HEADER_SIGNATURE,
        iroha_torii::signature_header_value(&signature)
            .expect("signature encoding")
            .parse()
            .expect("signature header"),
    );
    headers.insert(
        iroha_torii::HEADER_TIMESTAMP_MS,
        timestamp_ms.to_string().parse().expect("timestamp header"),
    );
    headers.insert(
        iroha_torii::HEADER_NONCE,
        nonce.parse().expect("nonce header"),
    );
    request
}
async fn fetch_current_alias_entry(
    harness: &ToriiHarness,
    setup: &ManifestSetup,
    alias_label: &str,
) -> json::Value {
    let (namespace, _) = alias_label.split_once('/').expect("alias namespace/name");
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/sorafs/aliases?namespace={namespace}&limit=1"))
        .header("accept", "application/json")
        .body(Body::empty())
        .expect("alias request");
    let request = sign_alias_read_request(harness, &setup.authority, request);
    let response = harness
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("alias response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = BodyExt::collect(response.into_body())
        .await
        .expect("alias body")
        .to_bytes();
    let page: json::Value = json::from_slice(&bytes).expect("alias JSON");
    let entries = page
        .get("aliases")
        .and_then(json::Value::as_array)
        .expect("dedicated aliases page");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].get("alias").and_then(json::Value::as_str),
        Some(alias_label)
    );
    entries[0].clone()
}
#[test]
fn alias_proof_native_evaluator_preserves_freshness_and_header_projections() {
    use iroha_torii::sorafs::{
        AliasCachePolicyHttpExt, AliasProofEvaluationExt, AliasProofState,
        decode_alias_proof_untrusted_signers, policy_from_config,
    };
    let cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    let policy = policy_from_config(&cfg.torii.sorafs_alias_cache);
    let positive = policy.positive_ttl().as_secs();
    let refresh = policy.refresh_window().as_secs();
    let hard = policy.hard_expiry().as_secs();
    let now = ISSUED_AT + hard + 120;
    let cid = sorafs_manifest::canonical_manifest_root_cid([0x56; 32]);
    let cases = [
        (
            (positive - refresh) / 2,
            now + 600,
            AliasProofState::Fresh,
            "fresh",
            None,
        ),
        (
            positive - refresh / 2,
            now + 600,
            AliasProofState::RefreshWindow,
            "refresh",
            Some("alias proof refresh in-flight"),
        ),
        (
            positive + 45,
            now + 300,
            AliasProofState::Expired,
            "expired",
            Some("alias proof stale"),
        ),
        (
            hard + 90,
            now - 30,
            AliasProofState::HardExpired,
            "hard-expired",
            Some("alias proof expired"),
        ),
    ];
    for (age, expires, state, label, warning) in cases {
        let bytes = encode_alias_proof_bytes("docs", "native", &cid, 12, 48, now - age, expires);
        // This owner checks canonical framing, Merkle/signature integrity and age;
        // fixture signers do not establish a production council trust policy.
        let bundle = decode_alias_proof_untrusted_signers(&bytes).expect("fixture proof integrity");
        let evaluation = policy.evaluate(&bundle, now);
        assert_eq!(evaluation.state, state);
        assert_eq!(
            evaluation.state.is_servable(),
            matches!(
                state,
                AliasProofState::Fresh | AliasProofState::RefreshWindow
            )
        );
        assert_eq!(evaluation.age.as_secs(), age);
        assert_eq!(evaluation.age_header().to_str().unwrap(), age.to_string());
        assert_eq!(evaluation.proof_status_header().to_str().unwrap(), label);
        assert_eq!(evaluation.generated_at_unix, now - age);
        assert_eq!(evaluation.expires_at_unix, expires);
        assert_eq!(
            evaluation.expires_in.map(|v| v.as_secs()),
            (expires > now).then(|| expires - now)
        );
        assert_eq!(
            evaluation.rotation_due,
            age >= policy.rotation_max_age().as_secs()
        );
        match (warning, evaluation.warning_header()) {
            (None, None) => {}
            (Some(expected), Some(actual)) => assert!(actual.to_str().unwrap().contains(expected)),
            other => panic!("unexpected warning projection: {other:?}"),
        }
        let mut altered = bundle;
        altered.council_signatures[0].signature[0] ^= 1;
        assert!(decode_alias_proof_untrusted_signers(&to_bytes(&altered).unwrap()).is_err());
    }
    assert_eq!(
        policy.cache_control_header().to_str().unwrap(),
        format!("max-age={positive}, stale-while-revalidate={refresh}")
    );
    assert_eq!(
        policy.revocation_cache_control_header().to_str().unwrap(),
        format!("max-age={}", policy.revocation_ttl().as_secs())
    );
}
#[tokio::test]
async fn sorafs_pin_manifest_rejects_noncanonical_digest_and_cursor() {
    let harness = build_torii_harness(&iroha_torii::test_utils::mk_minimal_root_cfg());
    let canonical = "ab".repeat(32);
    for digest in [
        "00".repeat(32),
        "AB".repeat(32),
        "ab".repeat(31),
        format!("0x{canonical}"),
        "gg".repeat(32),
    ] {
        assert_eq!(
            pin_readback_status(&harness, &format!("/v1/sorafs/pin/{digest}")).await,
            StatusCode::BAD_REQUEST,
            "digest={digest}"
        );
    }
    let hash = "ab".repeat(32);
    for query in [
        "limit=1".to_owned(),
        "expected_finalized_cursor=1".to_owned(),
        "expected_finalized_height=1".to_owned(),
        format!("expected_finalized_block_hash_hex={hash}"),
        format!("expected_finalized_height=0&expected_finalized_block_hash_hex={hash}"),
        format!("expected_finalized_height=01&expected_finalized_block_hash_hex={hash}"),
        format!("expected_finalized_height=+1&expected_finalized_block_hash_hex={hash}"),
        format!(
            "expected_finalized_height=18446744073709551616&expected_finalized_block_hash_hex={hash}"
        ),
        format!(
            "expected_finalized_height=1&expected_finalized_block_hash_hex={}",
            "00".repeat(32)
        ),
        format!(
            "expected_finalized_height=1&expected_finalized_block_hash_hex={}",
            hash.to_uppercase()
        ),
        format!(
            "expected_finalized_height=1&expected_finalized_height=2&expected_finalized_block_hash_hex={hash}"
        ),
        format!(
            "expected_finalized_height=1&expected_finalized_block_hash_hex={hash}&expected_finalized_block_hash_hex={hash}"
        ),
    ] {
        assert_eq!(
            pin_readback_status(&harness, &format!("/v1/sorafs/pin/{canonical}?{query}")).await,
            StatusCode::BAD_REQUEST,
            "query={query}"
        );
    }
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_pin_manifest_distinguishes_missing_record_and_unavailable_anchor() {
    let harness = build_certified_torii_harness(&iroha_torii::test_utils::mk_minimal_root_cfg());
    let path = format!("/v1/sorafs/pin/{}", "ab".repeat(32));
    assert_eq!(
        pin_readback_status(&harness, &path).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    commit_pin_readback_fixture(&harness);
    assert_eq!(
        pin_readback_status(&harness, &path).await,
        StatusCode::NOT_FOUND
    );
    let anchored_missing = {
        let view = harness.state.view();
        let hash: &[u8; 32] = view.block_hashes().last().unwrap().as_ref();
        format!(
            "{path}?expected_finalized_height=1&expected_finalized_block_hash_hex={}",
            hex::encode(hash)
        )
    };
    assert_eq!(
        pin_readback_status(&harness, &anchored_missing).await,
        StatusCode::NOT_FOUND
    );
    let full_width = anchored_missing.replace(
        "expected_finalized_height=1",
        "expected_finalized_height=18446744073709551615",
    );
    assert_eq!(
        pin_readback_status(&harness, &full_width).await,
        StatusCode::CONFLICT
    );
    commit_pin_readback_fixture(&harness);
    assert_eq!(
        pin_readback_status(&harness, &anchored_missing).await,
        StatusCode::CONFLICT
    );
    harness.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sorafs_pin_manifest_returns_finalized_record_and_fresh_alias_projection() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    enable_storage_with_discovery_native_signers(&mut cfg);
    cfg.torii.sorafs_storage.max_parallel_fetches = 1;
    cfg.torii.sorafs_storage.max_pins = 8;
    cfg.torii.sorafs_storage.max_capacity_bytes = Bytes(1_048_576);
    let harness = build_certified_torii_harness(&cfg);
    let mut next_height = 1;
    let setup = create_manifest_readback_setup(&harness, &mut next_height);
    let positive_ttl = harness.alias_policy.positive_ttl_secs();
    let refresh_window = harness.alias_policy.refresh_window_secs();
    let freshness_margin = positive_ttl.saturating_sub(refresh_window);
    let fresh_age = freshness_margin
        .checked_div(2)
        .filter(|age| *age > 0)
        .unwrap_or_else(|| positive_ttl.saturating_sub(1).max(1));
    let now = unix_now_secs();
    let generated_at = now.saturating_sub(fresh_age);
    let expires_at = now.saturating_add(positive_ttl.saturating_mul(2));
    bind_alias_with_proof(
        &harness,
        &setup,
        "docs-fresh",
        "sora",
        generated_at,
        expires_at,
        setup.approved_epoch,
        setup.retention_epoch,
        &mut next_height,
    );
    commit_pin_readback_fixture(&harness);
    let record = assert_finalized_pin_readback(&harness, &setup, None).await;
    let query = format!(
        "expected_finalized_height={}&expected_finalized_block_hash_hex={}",
        record.finalized_cursor.height,
        hex::encode(record.finalized_cursor.block_hash)
    );
    assert_finalized_pin_readback(&harness, &setup, Some(&query)).await;
    let mut wrong_hash = record.finalized_cursor.block_hash;
    wrong_hash[0] ^= 0x80;
    let wrong = format!(
        "/v1/sorafs/pin/{}?expected_finalized_height={}&expected_finalized_block_hash_hex={}",
        setup.manifest_digest_hex,
        record.finalized_cursor.height,
        hex::encode(wrong_hash)
    );
    assert_eq!(
        pin_readback_status(&harness, &wrong).await,
        StatusCode::CONFLICT
    );
    let alias = fetch_current_alias_entry(&harness, &setup, "docs-fresh/sora").await;
    assert_eq!(
        alias.get("cache_state").and_then(json::Value::as_str),
        Some("fresh")
    );
    assert_eq!(
        alias.get("cache_decision").and_then(json::Value::as_str),
        Some("serve")
    );
    assert_eq!(
        alias
            .get("policy_positive_ttl_secs")
            .and_then(json::Value::as_u64),
        Some(positive_ttl)
    );
    let age = alias
        .get("cache_age_seconds")
        .and_then(json::Value::as_u64)
        .expect("fresh proof age");
    assert!(age >= fresh_age.saturating_sub(2));
    assert!(age <= fresh_age.saturating_add(5));
    let cache = alias
        .get("cache_evaluation")
        .expect("alias cache evaluation");
    assert_eq!(
        cache
            .get("ttl_expires_at_unix")
            .and_then(json::Value::as_u64),
        Some(expires_at)
    );
    assert_eq!(
        cache.get("ttl_expires_at").and_then(json::Value::as_str),
        Some(
            format_rfc3339(UNIX_EPOCH + Duration::from_secs(expires_at))
                .to_string()
                .as_str()
        )
    );
    assert!(cache.get("serve_until").is_some_and(json::Value::is_null));
    let lineage = alias.get("lineage").expect("alias lineage");
    assert_eq!(
        lineage.get("head_hex").and_then(json::Value::as_str),
        Some(setup.manifest_digest_hex.as_str())
    );
    assert_eq!(
        lineage.get("is_head").and_then(json::Value::as_bool),
        Some(true)
    );
    assert!(
        lineage
            .get("superseded_by")
            .is_some_and(json::Value::is_null)
    );
    assert!(
        record
            .manifest
            .metadata
            .get(&Name::from_str(GOVERNANCE_REFS_KEY).unwrap())
            .is_none()
    );
    let proof = BASE64_STANDARD
        .decode(
            alias
                .get("proof_b64")
                .and_then(json::Value::as_str)
                .unwrap(),
        )
        .unwrap();
    let bundle = iroha_torii::sorafs::decode_alias_proof_untrusted_signers(&proof)
        .expect("listed alias proof integrity");
    assert_eq!(bundle.binding.alias, "docs-fresh/sora");
    assert_eq!(bundle.binding.manifest_cid, setup.manifest_cid);
    commit_pin_readback_fixture(&harness);
    let stale = format!("/v1/sorafs/pin/{}?{query}", setup.manifest_digest_hex);
    assert_eq!(
        pin_readback_status(&harness, &stale).await,
        StatusCode::CONFLICT
    );
    harness.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sorafs_pin_manifest_returns_finalized_record_with_refreshing_alias() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    enable_storage_with_discovery_native_signers(&mut cfg);
    cfg.torii.sorafs_storage.max_parallel_fetches = 1;
    cfg.torii.sorafs_storage.max_pins = 8;
    cfg.torii.sorafs_storage.max_capacity_bytes = Bytes(1_048_576);
    let harness = build_certified_torii_harness(&cfg);
    let mut next_height = 1;
    let setup = create_manifest_readback_setup(&harness, &mut next_height);
    let positive_ttl = harness.alias_policy.positive_ttl_secs();
    let refresh_window = harness.alias_policy.refresh_window_secs();
    let refresh_age = {
        let base = positive_ttl.saturating_sub(refresh_window);
        let adjustment = refresh_window
            .checked_div(2)
            .filter(|age| *age > 0)
            .unwrap_or(1);
        let candidate = base.saturating_add(adjustment);
        if candidate >= positive_ttl {
            positive_ttl.saturating_sub(1).max(1)
        } else {
            candidate.max(1)
        }
    };
    let now = unix_now_secs();
    let generated_at = now.saturating_sub(refresh_age);
    let expires_at = now.saturating_add(positive_ttl.saturating_mul(2));
    bind_alias_with_proof(
        &harness,
        &setup,
        "docs-refresh",
        "sora",
        generated_at,
        expires_at,
        setup.approved_epoch,
        setup.retention_epoch,
        &mut next_height,
    );
    commit_pin_readback_fixture(&harness);
    assert_finalized_pin_readback(&harness, &setup, None).await;
    let alias = fetch_current_alias_entry(&harness, &setup, "docs-refresh/sora").await;
    assert_eq!(
        alias.get("cache_state").and_then(json::Value::as_str),
        Some("refresh")
    );
    assert_eq!(
        alias.get("cache_decision").and_then(json::Value::as_str),
        Some("hold")
    );
    assert_eq!(
        alias
            .get("policy_refresh_window_secs")
            .and_then(json::Value::as_u64),
        Some(refresh_window)
    );
    let age = alias
        .get("cache_age_seconds")
        .and_then(json::Value::as_u64)
        .expect("proof age");
    assert!(age >= positive_ttl.saturating_sub(refresh_window));
    assert!(age <= refresh_age.saturating_add(5));
    harness.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sorafs_pin_manifest_returns_finalized_record_with_stale_alias() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    enable_storage_with_discovery_native_signers(&mut cfg);
    cfg.torii.sorafs_storage.max_parallel_fetches = 1;
    cfg.torii.sorafs_storage.max_pins = 8;
    cfg.torii.sorafs_storage.max_capacity_bytes = Bytes(1_048_576);
    let harness = build_certified_torii_harness(&cfg);
    let mut next_height = 1;
    let setup = create_manifest_readback_setup(&harness, &mut next_height);
    let positive_ttl = harness.alias_policy.positive_ttl_secs();
    let now = unix_now_secs();
    let generated_at = now.saturating_sub(positive_ttl + 45);
    let expires_at = now + 300;
    bind_alias_with_proof(
        &harness,
        &setup,
        "docs-stale",
        "sora",
        generated_at,
        expires_at,
        setup.approved_epoch,
        setup.retention_epoch,
        &mut next_height,
    );
    commit_pin_readback_fixture(&harness);
    assert_finalized_pin_readback(&harness, &setup, None).await;
    let alias = fetch_current_alias_entry(&harness, &setup, "docs-stale/sora").await;
    assert_eq!(
        alias.get("cache_state").and_then(json::Value::as_str),
        Some("expired")
    );
    assert_eq!(
        alias.get("cache_decision").and_then(json::Value::as_str),
        Some("refuse")
    );
    assert!(
        alias
            .get("cache_age_seconds")
            .and_then(json::Value::as_u64)
            .unwrap()
            >= positive_ttl
    );
    assert!(
        alias
            .get("proof_expires_in_seconds")
            .and_then(json::Value::as_u64)
            .is_some()
    );
    assert!(
        alias
            .get("cache_reasons")
            .and_then(json::Value::as_array)
            .unwrap()
            .iter()
            .any(|reason| reason.as_str() == Some("ExpiredTTL"))
    );
    harness.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sorafs_pin_manifest_returns_finalized_record_with_expired_alias() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    enable_storage_with_discovery_native_signers(&mut cfg);
    cfg.torii.sorafs_storage.max_parallel_fetches = 1;
    cfg.torii.sorafs_storage.max_pins = 8;
    cfg.torii.sorafs_storage.max_capacity_bytes = Bytes(1_048_576);
    let harness = build_certified_torii_harness(&cfg);
    let mut next_height = 1;
    let setup = create_manifest_readback_setup(&harness, &mut next_height);
    let hard_expiry = harness.alias_policy.hard_expiry_secs();
    let now = unix_now_secs();
    let generated_at = now.saturating_sub(hard_expiry + 90);
    let expires_at = now.saturating_sub(30);
    bind_alias_with_proof(
        &harness,
        &setup,
        "docs-expired",
        "sora",
        generated_at,
        expires_at,
        setup.approved_epoch,
        setup.retention_epoch,
        &mut next_height,
    );
    commit_pin_readback_fixture(&harness);
    assert_finalized_pin_readback(&harness, &setup, None).await;
    let alias = fetch_current_alias_entry(&harness, &setup, "docs-expired/sora").await;
    assert_eq!(
        alias.get("cache_state").and_then(json::Value::as_str),
        Some("hard-expired")
    );
    assert_eq!(
        alias.get("cache_decision").and_then(json::Value::as_str),
        Some("refuse")
    );
    assert!(
        alias
            .get("cache_age_seconds")
            .and_then(json::Value::as_u64)
            .unwrap()
            >= hard_expiry
    );
    assert!(alias.get("proof_expires_in_seconds").is_none());
    assert!(
        alias
            .get("cache_reasons")
            .and_then(json::Value::as_array)
            .unwrap()
            .iter()
            .any(|reason| reason.as_str() == Some("HardExpired"))
    );
    harness.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sorafs_pin_manifest_returns_finalized_record_with_revoked_alias_projection() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    enable_storage_with_discovery_native_signers(&mut cfg);
    cfg.torii.sorafs_storage.max_parallel_fetches = 1;
    cfg.torii.sorafs_storage.max_pins = 8;
    cfg.torii.sorafs_storage.max_capacity_bytes = Bytes(1_048_576);
    cfg.torii.sorafs_alias_cache.successor_grace = Duration::from_secs(0);
    cfg.torii.sorafs_alias_cache.governance_grace = Duration::from_secs(0);
    let harness = build_certified_torii_harness(&cfg);
    let mut next_height = 1;
    let setup = create_manifest_readback_setup(&harness, &mut next_height);
    let now = unix_now_secs();
    bind_alias_with_proof(
        &harness,
        &setup,
        "docs-revoked",
        "gamma",
        now.saturating_sub(60),
        now + 900,
        setup.approved_epoch,
        setup.retention_epoch,
        &mut next_height,
    );
    let alias_label = "docs-revoked/gamma";
    attach_governance_revocation(
        &harness,
        &setup,
        alias_label,
        now.saturating_sub(5),
        &mut next_height,
    );
    commit_pin_readback_fixture(&harness);
    let record = assert_finalized_pin_readback(&harness, &setup, None).await;
    let alias = fetch_current_alias_entry(&harness, &setup, alias_label).await;
    assert_eq!(
        alias.get("cache_state").and_then(json::Value::as_str),
        Some("governance-refused")
    );
    assert_eq!(
        alias.get("cache_decision").and_then(json::Value::as_str),
        Some("refuse")
    );
    assert!(
        alias
            .get("cache_reasons")
            .and_then(json::Value::as_array)
            .unwrap()
            .iter()
            .any(|reason| reason.as_str() == Some("GovernanceRevoked"))
    );
    assert_eq!(
        alias
            .get("cache_evaluation")
            .and_then(|v| v.get("governance"))
            .and_then(|v| v.get("revoked"))
            .and_then(json::Value::as_bool),
        Some(true)
    );
    // Fixture metadata exercises the projection; it does not authorize a council signer.
    assert!(
        record
            .manifest
            .metadata
            .get(&Name::from_str(GOVERNANCE_REFS_KEY).unwrap())
            .is_some()
    );
    harness.shutdown().await;
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sorafs_alias_listing_reports_successor_refusal() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    enable_storage_with_discovery_native_signers(&mut cfg);
    cfg.torii.sorafs_storage.max_parallel_fetches = 1;
    cfg.torii.sorafs_storage.max_pins = 8;
    cfg.torii.sorafs_storage.max_capacity_bytes = Bytes(1_048_576);
    cfg.torii.sorafs_alias_cache.successor_grace = Duration::from_secs(0);
    cfg.torii.sorafs_alias_cache.governance_grace = Duration::from_secs(0);
    let harness = build_certified_torii_harness(&cfg);
    let mut next_height = 1;
    let base = create_manifest_readback_setup(&harness, &mut next_height);
    let successor_timestamp = unix_now_secs().saturating_sub(30);
    let successor = create_successor_manifest_readback(
        &harness,
        &base,
        &mut next_height,
        0xBC,
        successor_timestamp,
    );
    let now = unix_now_secs();
    bind_alias_with_proof(
        &harness,
        &base,
        "docs-successor",
        "alpha",
        now.saturating_sub(60),
        now + 900,
        base.approved_epoch,
        base.retention_epoch,
        &mut next_height,
    );
    commit_pin_readback_fixture(&harness);
    let alias_entry = fetch_current_alias_entry(&harness, &base, "docs-successor/alpha").await;
    assert_eq!(
        alias_entry
            .get("cache_decision")
            .and_then(json::Value::as_str),
        Some("refuse")
    );
    assert_eq!(
        alias_entry
            .get("status_label")
            .and_then(json::Value::as_str),
        Some("successor-refused")
    );
    let lineage = alias_entry
        .get("lineage")
        .and_then(json::Value::as_object)
        .expect("lineage metadata present");
    let superseded = lineage
        .get("superseded_by")
        .and_then(json::Value::as_object)
        .expect("superseded_by metadata present");
    assert_eq!(
        superseded.get("digest_hex").and_then(json::Value::as_str),
        Some(successor.manifest_digest_hex.as_str()),
        "superseded record should point at successor manifest"
    );
    assert_eq!(
        superseded
            .get("approved_epoch")
            .and_then(json::Value::as_u64),
        Some(successor.approved_epoch),
        "superseded record should carry successor epoch"
    );
    assert!(
        lineage
            .get("immediate_successor")
            .and_then(json::Value::as_object)
            .is_some(),
        "immediate_successor metadata should be populated"
    );
    let cache_eval = alias_entry
        .get("cache_evaluation")
        .and_then(json::Value::as_object)
        .unwrap_or_else(|| panic!("alias cache evaluation present: {alias_entry:?}"));
    let successor_eval = cache_eval
        .get("successor")
        .and_then(json::Value::as_object)
        .expect("successor evaluation present");
    assert_eq!(
        successor_eval
            .get("approved")
            .and_then(json::Value::as_bool),
        Some(true)
    );
    let expected_successor_iso =
        format_rfc3339(UNIX_EPOCH + Duration::from_secs(successor_timestamp)).to_string();
    assert_eq!(
        successor_eval
            .get("approved_at")
            .and_then(json::Value::as_str),
        Some(expected_successor_iso.as_str())
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn sorafs_alias_listing_reports_governance_revocation() {
    let mut cfg = iroha_torii::test_utils::mk_minimal_root_cfg();
    cfg.torii.sorafs_discovery.discovery_enabled = true;
    cfg.torii.sorafs_discovery.admission = Some(test_admission_config());
    enable_storage_with_discovery_native_signers(&mut cfg);
    cfg.torii.sorafs_storage.max_parallel_fetches = 1;
    cfg.torii.sorafs_storage.max_pins = 8;
    cfg.torii.sorafs_storage.max_capacity_bytes = Bytes(1_048_576);
    cfg.torii.sorafs_alias_cache.successor_grace = Duration::from_secs(0);
    cfg.torii.sorafs_alias_cache.governance_grace = Duration::from_secs(0);
    let harness = build_certified_torii_harness(&cfg);
    let mut next_height = 1;
    let manifest =
        create_manifest_readback_setup_with_seed(&harness, &mut next_height, 0xC1, None, None);
    let now = unix_now_secs();
    bind_alias_with_proof(
        &harness,
        &manifest,
        "docs-governance",
        "beta",
        now.saturating_sub(60),
        now + 900,
        manifest.approved_epoch,
        manifest.retention_epoch,
        &mut next_height,
    );
    let alias_label = "docs-governance/beta";
    let effective_at = now.saturating_sub(5);
    attach_governance_revocation(
        &harness,
        &manifest,
        alias_label,
        effective_at,
        &mut next_height,
    );
    commit_pin_readback_fixture(&harness);
    let alias_entry = fetch_current_alias_entry(&harness, &manifest, alias_label).await;
    assert_eq!(
        alias_entry
            .get("cache_decision")
            .and_then(json::Value::as_str),
        Some("refuse")
    );
    assert_eq!(
        alias_entry
            .get("status_label")
            .and_then(json::Value::as_str),
        Some("governance-refused")
    );
    let record = assert_finalized_pin_readback(&harness, &manifest, None).await;
    assert!(
        record
            .manifest
            .metadata
            .get(&Name::from_str(STATUS_TIMESTAMP_KEY).unwrap())
            .is_some()
    );
    let governance_eval = alias_entry
        .get("cache_evaluation")
        .and_then(|value| value.get("governance"))
        .unwrap_or_else(|| panic!("governance evaluation present: {alias_entry:?}"));
    assert_eq!(
        governance_eval
            .get("revoked")
            .and_then(json::Value::as_bool),
        Some(true),
        "governance_eval={governance_eval:?}"
    );
    let expected_effective =
        format_rfc3339(UNIX_EPOCH + Duration::from_secs(effective_at)).to_string();
    assert_eq!(
        governance_eval
            .get("effective_at")
            .and_then(json::Value::as_str),
        Some(expected_effective.as_str())
    );
    assert_eq!(
        governance_eval
            .get("effective_at_unix")
            .and_then(json::Value::as_u64),
        Some(effective_at)
    );
    harness.shutdown().await;
}
include!("sorafs_discovery/storage_path_fixture.rs");
include!("sorafs_discovery/fixture_key_mismatch_test.rs");

#[path = "../src/build_identity_test_fixture.rs"]
mod build_identity_test_fixture;
