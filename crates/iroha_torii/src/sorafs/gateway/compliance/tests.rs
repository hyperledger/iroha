//! SoraFS gateway compliance persistence and policy tests.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use flate2::{Compression, write::GzEncoder};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering as TestAtomicOrdering},
    },
};
const NOW: u64 = 1_800_000_000;
#[derive(Debug, Default)]
struct MemoryStore {
    state: Arc<Mutex<MemoryStoreState>>,
    fail_next_store: Arc<AtomicBool>,
    fail_after_store: Arc<AtomicBool>,
}
#[derive(Debug, Default)]
struct MemoryStoreState {
    bytes: Option<Vec<u8>>,
    leased: bool,
}
#[derive(Debug)]
struct MemoryStoreLease {
    state: Arc<Mutex<MemoryStoreState>>,
    fail_next_store: Arc<AtomicBool>,
    fail_after_store: Arc<AtomicBool>,
}
impl Drop for MemoryStoreLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.leased = false;
        }
    }
}
impl MemoryStore {
    fn fail_next_store(&self) {
        self.fail_next_store.store(true, TestAtomicOrdering::SeqCst);
    }
    fn fail_after_store(&self) {
        self.fail_after_store
            .store(true, TestAtomicOrdering::SeqCst);
    }
    fn durable_bytes(&self) -> Option<Vec<u8>> {
        self.state.lock().expect("memory store lock").bytes.clone()
    }
    fn force_store(&self, bytes: Vec<u8>) {
        self.state.lock().expect("memory store lock").bytes = Some(bytes);
    }
}
impl GatewayComplianceStore for MemoryStore {
    fn try_acquire(&self) -> Result<Box<dyn GatewayComplianceStoreLease>, GatewayComplianceError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayComplianceError::StatePoisoned)?;
        if state.leased {
            return Err(GatewayComplianceError::LeaseHeld);
        }
        state.leased = true;
        drop(state);
        Ok(Box::new(MemoryStoreLease {
            state: Arc::clone(&self.state),
            fail_next_store: Arc::clone(&self.fail_next_store),
            fail_after_store: Arc::clone(&self.fail_after_store),
        }))
    }
}
impl GatewayComplianceStoreLease for MemoryStoreLease {
    fn load(&self) -> Result<GatewayComplianceStoreSnapshot, GatewayComplianceError> {
        let state = self
            .state
            .lock()
            .map_err(|_| GatewayComplianceError::StatePoisoned)?;
        Ok(checkpoint_store_snapshot(state.bytes.clone()))
    }
    fn compare_and_store(
        &self,
        expected: GatewayComplianceStoreGeneration,
        bytes: &[u8],
    ) -> Result<GatewayComplianceStoreGeneration, GatewayComplianceError> {
        if bytes.len() > MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1 {
            return Err(GatewayComplianceError::ResourceLimit {
                resource: "compliance checkpoint bytes",
                found: bytes.len(),
                maximum: MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1,
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| GatewayComplianceError::StatePoisoned)?;
        if checkpoint_store_generation(state.bytes.as_deref()) != expected {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        if self.fail_next_store.swap(false, TestAtomicOrdering::SeqCst) {
            return Err(GatewayComplianceError::Persistence(
                "injected test store failure".into(),
            ));
        }
        state.bytes = Some(bytes.to_vec());
        if self
            .fail_after_store
            .swap(false, TestAtomicOrdering::SeqCst)
        {
            return Err(GatewayComplianceError::CheckpointConflict);
        }
        Ok(checkpoint_store_generation(Some(bytes)))
    }
}
fn catalog_keys() -> [SigningKey; 2] {
    [
        SigningKey::from_bytes(&[0x11; 32]),
        SigningKey::from_bytes(&[0x22; 32]),
    ]
}
fn gateway_keys() -> [SigningKey; 2] {
    [
        SigningKey::from_bytes(&[0x33; 32]),
        SigningKey::from_bytes(&[0x44; 32]),
    ]
}
fn trust_policy() -> GatewayComplianceTrustPolicyV1 {
    let catalog = catalog_keys();
    let gateways = gateway_keys();
    GatewayComplianceTrustPolicyV1 {
        policy_id: [0xA5; 32],
        catalog_threshold: 2,
        catalog_signers: vec![
            GatewayComplianceTrustedSignerV1 {
                signer_id: "council-a".into(),
                public_key: catalog[0].verifying_key().to_bytes(),
            },
            GatewayComplianceTrustedSignerV1 {
                signer_id: "council-b".into(),
                public_key: catalog[1].verifying_key().to_bytes(),
            },
        ],
        revoked_catalog_signer_ids: Vec::new(),
        gateway_ack_threshold: 2,
        gateway_signers: vec![
            GatewayComplianceTrustedSignerV1 {
                signer_id: "gateway-eu".into(),
                public_key: gateways[0].verifying_key().to_bytes(),
            },
            GatewayComplianceTrustedSignerV1 {
                signer_id: "gateway-us".into(),
                public_key: gateways[1].verifying_key().to_bytes(),
            },
        ],
        revoked_gateway_signer_ids: Vec::new(),
    }
}
fn config() -> GatewayComplianceControllerConfig {
    let feed = feed_policy();
    let policy_digest = gateway_compliance_feed_transport_policy_digest(&BTreeMap::from([(
        feed.hosts[0].hostname.clone(),
        feed.hosts[0].accepted_spki_sha256.clone(),
    )]))
    .expect("test feed transport policy digest");
    GatewayComplianceControllerConfig {
        trust_policy: trust_policy(),
        region_scope: "region:eu".into(),
        gateway_scope: "gateway:gateway-eu".into(),
        feeds: vec![feed],
        feed_transport_provider: Some(
            GatewayProviderBindingV1::try_new(
                GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.to_owned(),
                GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
                policy_digest,
            )
            .expect("valid test feed transport provider binding"),
        ),
        fetch_limits: GatewayComplianceFetchLimits::default(),
        max_clock_skew_secs: 300,
        max_feed_age_secs: 3_600,
        max_catalog_validity_secs: 7_200,
        max_history_entries: 16,
    }
}
#[derive(Debug)]
struct QualifiableTransport {
    identity: Mutex<GatewayComplianceFeedTransportIdentityV1>,
    probe_available: AtomicBool,
    drift_revision_on_resolve: AtomicBool,
    drift_revision_on_fetch: AtomicBool,
    drift_policy_on_fetch: AtomicBool,
    qualification_calls: AtomicUsize,
    resolve_calls: AtomicUsize,
}
impl QualifiableTransport {
    fn new(identity: GatewayComplianceFeedTransportIdentityV1) -> Self {
        Self {
            identity: Mutex::new(identity),
            probe_available: AtomicBool::new(true),
            drift_revision_on_resolve: AtomicBool::new(false),
            drift_revision_on_fetch: AtomicBool::new(false),
            drift_policy_on_fetch: AtomicBool::new(false),
            qualification_calls: AtomicUsize::new(0),
            resolve_calls: AtomicUsize::new(0),
        }
    }
    fn expected() -> Self {
        Self::new(
            config()
                .expected_feed_transport_identity()
                .expect("expected feed transport identity"),
        )
    }
}
impl GatewayComplianceFeedTransport for QualifiableTransport {
    fn qualification(
        &self,
    ) -> Result<GatewayComplianceFeedTransportIdentityV1, GatewayComplianceFeedTransportProbeError>
    {
        self.qualification_calls
            .fetch_add(1, TestAtomicOrdering::SeqCst);
        if !self.probe_available.load(TestAtomicOrdering::SeqCst) {
            return Err(GatewayComplianceFeedTransportProbeError);
        }
        Ok(self
            .identity
            .lock()
            .expect("transport identity lock")
            .clone())
    }
    fn resolve(
        &self,
        _hostname: &str,
        _timeout: Duration,
    ) -> Result<Vec<IpAddr>, GatewayComplianceError> {
        self.resolve_calls.fetch_add(1, TestAtomicOrdering::SeqCst);
        if self
            .drift_revision_on_resolve
            .swap(false, TestAtomicOrdering::SeqCst)
        {
            self.identity
                .lock()
                .expect("transport identity lock")
                .revision += 1;
        }
        Ok(vec!["93.184.216.34".parse().expect("public IP")])
    }
    fn fetch(
        &self,
        _request: &GatewayComplianceFetchRequest,
    ) -> Result<GatewayComplianceFetchResponse, GatewayComplianceError> {
        if self
            .drift_revision_on_fetch
            .swap(false, TestAtomicOrdering::SeqCst)
        {
            self.identity
                .lock()
                .expect("transport identity lock")
                .revision += 1;
        }
        if self
            .drift_policy_on_fetch
            .swap(false, TestAtomicOrdering::SeqCst)
        {
            self.identity
                .lock()
                .expect("transport identity lock")
                .policy_digest[0] ^= 0xFF;
        }
        Ok(fetch_response(Vec::new()))
    }
}
#[derive(Debug, Default)]
struct UnexpectedStore {
    acquire_calls: AtomicUsize,
}
impl GatewayComplianceStore for UnexpectedStore {
    fn try_acquire(&self) -> Result<Box<dyn GatewayComplianceStoreLease>, GatewayComplianceError> {
        self.acquire_calls.fetch_add(1, TestAtomicOrdering::SeqCst);
        Err(GatewayComplianceError::Persistence(
            "checkpoint store must not be accessed".into(),
        ))
    }
}
#[test]
fn cross_role_signer_reuse_fails_before_provider_or_store_access() {
    let mut reused_id = config();
    reused_id.trust_policy.gateway_signers[0].signer_id =
        reused_id.trust_policy.catalog_signers[0].signer_id.clone();
    let mut reused_key = config();
    reused_key.trust_policy.gateway_signers[0].public_key =
        reused_key.trust_policy.catalog_signers[0].public_key;
    for (label, config) in [
        ("signer identifier", reused_id),
        ("Ed25519 public key", reused_key),
    ] {
        let transport = QualifiableTransport::expected();
        let store = Arc::new(UnexpectedStore::default());
        let error =
            GatewayComplianceController::new_with_feed_transport(config, store.clone(), &transport)
                .expect_err("cross-role signer reuse must fail startup");
        assert!(
            matches!(&error, GatewayComplianceError::InvalidPolicy(message)
                if message.contains("administratively disjoint")),
            "unexpected {label} reuse error: {error}"
        );
        assert_eq!(
            transport
                .qualification_calls
                .load(TestAtomicOrdering::SeqCst),
            0,
            "{label} reuse must fail before provider qualification"
        );
        assert_eq!(
            store.acquire_calls.load(TestAtomicOrdering::SeqCst),
            0,
            "{label} reuse must fail before checkpoint access"
        );
    }
}
#[test]
fn feed_transport_qualification_rejects_bad_providers_before_store_access() {
    let cases = [
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.provider_handle = "sorafs.gateway.compliance.other.v1".into();
                identity
            },
            GatewayComplianceError::FeedTransportSubstituted,
        ),
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.revision += 1;
                identity
            },
            GatewayComplianceError::FeedTransportStale,
        ),
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.policy_digest[0] ^= 0xFF;
                identity
            },
            GatewayComplianceError::FeedTransportSubstituted,
        ),
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.test_marked = true;
                identity
            },
            GatewayComplianceError::FeedTransportTestMarked,
        ),
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.provider_handle = "sorafs.gateway.compliance.feed-dummy.v1".into();
                identity
            },
            GatewayComplianceError::FeedTransportTestMarked,
        ),
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.provider_handle = "sorafs gateway compliance feed".into();
                identity
            },
            GatewayComplianceError::FeedTransportUnqualified,
        ),
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.revision = 0;
                identity
            },
            GatewayComplianceError::FeedTransportStale,
        ),
        (
            {
                let mut identity = config()
                    .expected_feed_transport_identity()
                    .expect("expected identity");
                identity.policy_digest = [0; 32];
                identity
            },
            GatewayComplianceError::FeedTransportUnqualified,
        ),
    ];
    for (identity, expected_error) in cases {
        let transport = QualifiableTransport::new(identity);
        let store = Arc::new(UnexpectedStore::default());
        let error = GatewayComplianceController::new_with_feed_transport(
            config(),
            store.clone(),
            &transport,
        )
        .expect_err("bad provider must fail startup");
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected_error)
        );
        assert_eq!(
            store.acquire_calls.load(TestAtomicOrdering::SeqCst),
            0,
            "provider qualification must precede checkpoint access"
        );
        assert_eq!(
            transport.resolve_calls.load(TestAtomicOrdering::SeqCst),
            0,
            "provider qualification must not perform network access"
        );
    }
}
#[test]
fn feed_transport_probe_failure_is_redacted_before_store_access() {
    let transport = QualifiableTransport::expected();
    transport
        .probe_available
        .store(false, TestAtomicOrdering::SeqCst);
    let store = Arc::new(UnexpectedStore::default());
    let error =
        GatewayComplianceController::new_with_feed_transport(config(), store.clone(), &transport)
            .expect_err("unavailable provider must fail startup");
    assert!(matches!(
        &error,
        GatewayComplianceError::FeedTransportUnavailable
    ));
    assert_eq!(
        error.to_string(),
        "gateway compliance feed transport is unavailable"
    );
    assert_eq!(store.acquire_calls.load(TestAtomicOrdering::SeqCst), 0);
}
#[test]
fn feed_transport_operation_diagnostics_are_redacted() {
    let error = redact_feed_transport_operation_error(GatewayComplianceError::InvalidFeed(
        "PRIVATE provider credential diagnostic".into(),
    ));
    assert!(matches!(
        &error,
        GatewayComplianceError::FeedTransportOperationFailed
    ));
    assert_eq!(
        error.to_string(),
        "gateway compliance feed transport operation failed"
    );
    assert!(!error.to_string().contains("PRIVATE"));
    assert!(matches!(
        redact_feed_transport_operation_error(GatewayComplianceError::FetchTimeout),
        GatewayComplianceError::FetchTimeout
    ));
}
#[test]
fn external_feed_startup_rejects_missing_config_binding_before_store_access() {
    let transport = QualifiableTransport::expected();
    let store = Arc::new(UnexpectedStore::default());
    let mut unbound = config();
    unbound.feed_transport_provider = None;
    let error =
        GatewayComplianceController::new_with_feed_transport(unbound, store.clone(), &transport)
            .expect_err("external feed startup requires one exact config binding");
    assert!(matches!(error, GatewayComplianceError::InvalidPolicy(_)));
    assert_eq!(store.acquire_calls.load(TestAtomicOrdering::SeqCst), 0);
    assert_eq!(
        transport
            .qualification_calls
            .load(TestAtomicOrdering::SeqCst),
        0,
        "configuration must fail before runtime-provider access"
    );
    assert_eq!(transport.resolve_calls.load(TestAtomicOrdering::SeqCst), 0);
}
#[test]
fn feed_transport_identity_is_revalidated_before_each_network_use() {
    let transport = QualifiableTransport::expected();
    let controller = GatewayComplianceController::new_with_feed_transport(
        config(),
        Arc::new(MemoryStore::default()),
        &transport,
    )
    .expect("qualified controller");
    assert_eq!(
        transport
            .qualification_calls
            .load(TestAtomicOrdering::SeqCst),
        1
    );
    transport
        .identity
        .lock()
        .expect("transport identity lock")
        .revision += 1;
    assert!(matches!(
        controller.fetch_feed("baseline", &transport),
        Err(GatewayComplianceError::FeedTransportStale)
    ));
    assert_eq!(
        transport
            .qualification_calls
            .load(TestAtomicOrdering::SeqCst),
        2
    );
    assert_eq!(
        transport.resolve_calls.load(TestAtomicOrdering::SeqCst),
        0,
        "stale providers must be rejected before DNS or HTTP"
    );
}
#[test]
fn feed_transport_drift_during_network_io_discards_response_bytes() {
    for (drift_policy, expected_error) in [
        (false, GatewayComplianceError::FeedTransportStale),
        (true, GatewayComplianceError::FeedTransportSubstituted),
    ] {
        let transport = QualifiableTransport::expected();
        let controller = GatewayComplianceController::new_with_feed_transport(
            config(),
            Arc::new(MemoryStore::default()),
            &transport,
        )
        .expect("qualified controller");
        if drift_policy {
            transport
                .drift_policy_on_fetch
                .store(true, TestAtomicOrdering::SeqCst);
        } else {
            transport
                .drift_revision_on_fetch
                .store(true, TestAtomicOrdering::SeqCst);
        }
        let error = controller
            .fetch_feed("baseline", &transport)
            .expect_err("provider drift must discard fetched bytes");
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected_error)
        );
        assert_eq!(
            transport
                .qualification_calls
                .load(TestAtomicOrdering::SeqCst),
            6,
            "startup plus outer, DNS, and fetch operation fences must be checked"
        );
        assert_eq!(
            transport.resolve_calls.load(TestAtomicOrdering::SeqCst),
            1,
            "fetch drift must be rejected before DNS revalidation"
        );
    }
}
#[test]
fn feed_transport_drift_during_dns_discards_addresses_before_http() {
    let transport = QualifiableTransport::expected();
    let controller = GatewayComplianceController::new_with_feed_transport(
        config(),
        Arc::new(MemoryStore::default()),
        &transport,
    )
    .expect("qualified controller");
    transport
        .drift_revision_on_resolve
        .store(true, TestAtomicOrdering::SeqCst);
    assert!(matches!(
        controller.fetch_feed("baseline", &transport),
        Err(GatewayComplianceError::FeedTransportStale)
    ));
    assert_eq!(
        transport
            .qualification_calls
            .load(TestAtomicOrdering::SeqCst),
        4,
        "startup, outer preflight, and DNS pre/post identities must be checked"
    );
    assert_eq!(transport.resolve_calls.load(TestAtomicOrdering::SeqCst), 1);
}
#[test]
fn unbound_controller_cannot_reach_a_feed_transport() {
    let transport = QualifiableTransport::expected();
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller core");
    assert!(matches!(
        controller.fetch_feed("baseline", &transport),
        Err(GatewayComplianceError::FeedTransportNotQualified)
    ));
    assert_eq!(
        transport
            .qualification_calls
            .load(TestAtomicOrdering::SeqCst),
        0
    );
    assert_eq!(transport.resolve_calls.load(TestAtomicOrdering::SeqCst), 0);
}
fn mutation_binding(nonce: u8) -> GatewayComplianceMutationBindingV1 {
    assert_ne!(nonce, 0, "test idempotency key must be non-zero");
    GatewayComplianceMutationBindingV1 {
        key_digest: [nonce; 32],
        request_digest: [nonce.wrapping_add(1); 32],
    }
}
fn indexed_mutation_binding(index: u64) -> GatewayComplianceMutationBindingV1 {
    let mut key_digest = [0xA1; 32];
    key_digest[..8].copy_from_slice(&index.to_be_bytes());
    let mut request_digest = [0xB2; 32];
    request_digest[..8].copy_from_slice(&index.to_be_bytes());
    GatewayComplianceMutationBindingV1 {
        key_digest,
        request_digest,
    }
}
fn subject(byte: u8) -> String {
    hex::encode([byte; 32])
}
fn payload(
    sequence: u64,
    predecessor_digest: Option<[u8; 32]>,
) -> GatewayComplianceCatalogPayloadV1 {
    GatewayComplianceCatalogPayloadV1 {
        version: GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
        sequence,
        predecessor_digest,
        policy_digest: trust_policy().canonical_digest().expect("policy digest"),
        generated_at_unix: NOW,
        valid_until_unix: NOW + 3_600,
        source_anchors: vec![GatewayComplianceSourceAnchorV1 {
            feed_id: "baseline".into(),
            feed_digest: [0x91; 32],
            generated_at_unix: NOW,
        }],
        baseline_rules: Vec::new(),
        appeal_overrides: Vec::new(),
        legal_safety_holds: Vec::new(),
        toggles: Vec::new(),
    }
}
fn sign_catalog(payload: GatewayComplianceCatalogPayloadV1) -> GatewayComplianceCatalogV1 {
    let payload = payload.normalize().expect("normalize catalog");
    let digest = payload.signing_digest().expect("catalog signing digest");
    let keys = catalog_keys();
    GatewayComplianceCatalogV1 {
        payload,
        approvals: vec![
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-a".into(),
                signature: keys[0].sign(&digest).to_bytes(),
            },
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-b".into(),
                signature: keys[1].sign(&digest).to_bytes(),
            },
        ],
    }
}
fn acknowledgement(
    gateway_index: usize,
    catalog_digest: [u8; 32],
    accepted: bool,
) -> GatewayComplianceAcknowledgementV1 {
    acknowledgement_at(gateway_index, catalog_digest, accepted, NOW + 10)
}
fn acknowledgement_at(
    gateway_index: usize,
    catalog_digest: [u8; 32],
    accepted: bool,
    observed_at_unix: u64,
) -> GatewayComplianceAcknowledgementV1 {
    let gateway_id = if gateway_index == 0 {
        "gateway-eu"
    } else {
        "gateway-us"
    };
    let payload = GatewayComplianceAcknowledgementPayloadV1 {
        version: GATEWAY_COMPLIANCE_ACK_VERSION_V1,
        gateway_id: gateway_id.into(),
        catalog_digest,
        observed_at_unix,
        accepted,
        rejection_code: (!accepted).then(|| "reload-failed".into()),
    };
    let digest = payload.signing_digest().expect("ack digest");
    GatewayComplianceAcknowledgementV1 {
        payload,
        signature: gateway_keys()[gateway_index].sign(&digest).to_bytes(),
    }
}
fn rollback_authorization(
    operation_id: [u8; 32],
    from_catalog_digest: [u8; 32],
    to_catalog_digest: [u8; 32],
    authorized_at_unix: u64,
) -> GatewayComplianceRollbackV1 {
    let payload = GatewayComplianceRollbackPayloadV1 {
        version: GATEWAY_COMPLIANCE_ROLLBACK_VERSION_V1,
        operation_id,
        from_catalog_digest,
        to_catalog_digest,
        reason_code: "bad-feed".into(),
        authorized_at_unix,
    };
    let digest = payload.signing_digest().expect("rollback digest");
    let keys = catalog_keys();
    GatewayComplianceRollbackV1 {
        payload,
        approvals: vec![
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-a".into(),
                signature: keys[0].sign(&digest).to_bytes(),
            },
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-b".into(),
                signature: keys[1].sign(&digest).to_bytes(),
            },
        ],
    }
}
fn promote(
    controller: &GatewayComplianceController,
    catalog: GatewayComplianceCatalogV1,
) -> [u8; 32] {
    let sequence = catalog.payload.sequence;
    let offset = sequence
        .checked_sub(1)
        .and_then(|value| value.checked_mul(30))
        .expect("test sequence offset");
    let base_nonce = u8::try_from(sequence.checked_mul(8).expect("test mutation nonce"))
        .expect("test mutation nonce fits");
    let digest = controller
        .stage_catalog(catalog, NOW + offset + 5, mutation_binding(base_nonce))
        .expect("stage catalog")
        .catalog_digest;
    controller
        .acknowledge(
            acknowledgement_at(0, digest, true, NOW + offset + 10),
            NOW + offset + 10,
            mutation_binding(base_nonce + 1),
        )
        .expect("first acknowledgement");
    controller
        .acknowledge(
            acknowledgement_at(1, digest, true, NOW + offset + 10),
            NOW + offset + 10,
            mutation_binding(base_nonce + 2),
        )
        .expect("second acknowledgement");
    controller
        .promote(
            digest,
            sequence,
            NOW + offset + 20,
            mutation_binding(base_nonce + 3),
        )
        .expect("promote catalog")
        .catalog_digest
}
#[test]
fn threshold_promotion_is_durable_and_predecessor_bound() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    crate::frame_test_support::assert_current_frame(
        &trust_policy(),
        "sorafs_manifest::gateway_compliance::GatewayComplianceTrustPolicyV1",
    );
    let first = sign_catalog(payload(1, None));
    crate::frame_test_support::assert_current_frame(
        &first.payload,
        "sorafs_manifest::gateway_compliance::GatewayComplianceCatalogPayloadV1",
    );
    crate::frame_test_support::assert_current_frame(
        &first,
        "sorafs_manifest::gateway_compliance::GatewayComplianceCatalogV1",
    );
    let first_digest = controller
        .stage_catalog(first.clone(), NOW + 5, mutation_binding(1))
        .expect("stage first")
        .catalog_digest;
    let first_ack = acknowledgement(0, first_digest, true);
    crate::frame_test_support::assert_current_frame(
        &first_ack.payload,
        "sorafs_manifest::gateway_compliance::GatewayComplianceAcknowledgementPayloadV1",
    );
    controller
        .acknowledge(first_ack, NOW + 10, mutation_binding(2))
        .expect("ack");
    assert!(matches!(
        controller.promote(first_digest, 1, NOW + 20, mutation_binding(3)),
        Err(GatewayComplianceError::GatewayQuorumNotMet { .. })
    ));
    controller
        .acknowledge(
            acknowledgement(1, first_digest, true),
            NOW + 10,
            mutation_binding(4),
        )
        .expect("ack");
    assert_eq!(
        controller
            .promote(first_digest, 1, NOW + 20, mutation_binding(5))
            .expect("promote")
            .catalog_digest,
        first_digest
    );
    let checkpoint = controller.checkpoint().expect("checkpoint");
    assert_eq!(checkpoint.revision, 4);
    let canonical = crate::frame_test_support::assert_current_frame(
        &checkpoint,
        "iroha_torii::sorafs::gateway::compliance::GatewayComplianceCheckpointV1",
    );
    assert_eq!(
        store.durable_bytes().expect("durable promoted checkpoint"),
        canonical
    );
    assert_eq!(
        decode_checkpoint(&canonical).expect("production checkpoint decoder"),
        checkpoint
    );
    let mut wrong_owner = canonical.clone();
    wrong_owner[6] ^= 1;
    assert!(decode_checkpoint(&wrong_owner).is_err());
    assert!(decode_checkpoint(&canonical[..canonical.len() - 1]).is_err());
    drop(controller);
    let recovered = GatewayComplianceController::new(config(), store).expect("recover checkpoint");
    assert_eq!(
        recovered
            .checkpoint()
            .expect("checkpoint")
            .serving
            .expect("serving")
            .payload
            .catalog_digest()
            .expect("digest"),
        first_digest
    );
    let wrong_successor = sign_catalog(payload(2, Some([0xFF; 32])));
    assert!(matches!(
        recovered.stage_catalog(wrong_successor, NOW + 30, mutation_binding(6)),
        Err(GatewayComplianceError::InvalidPredecessor)
    ));
}
#[test]
fn exact_mutation_replays_survive_promotion_expiry_and_restart() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    let stage_binding = indexed_mutation_binding(1);
    let first_ack_binding = indexed_mutation_binding(2);
    let second_ack_binding = indexed_mutation_binding(3);
    let promote_binding = indexed_mutation_binding(4);
    let staged = controller
        .stage_catalog(catalog.clone(), NOW + 5, stage_binding)
        .expect("stage");
    let first_ack = acknowledgement(0, staged.catalog_digest, true);
    let second_ack = acknowledgement(1, staged.catalog_digest, true);
    let first_ack_result = controller
        .acknowledge(first_ack.clone(), NOW + 10, first_ack_binding)
        .expect("first acknowledgement");
    controller
        .acknowledge(second_ack, NOW + 10, second_ack_binding)
        .expect("second acknowledgement");
    let promoted = controller
        .promote(staged.catalog_digest, 1, NOW + 20, promote_binding)
        .expect("promote");
    assert_eq!(controller.checkpoint().expect("checkpoint").revision, 4);
    drop(controller);
    let recovered = GatewayComplianceController::new(config(), store).expect("recover checkpoint");
    assert_eq!(
        recovered
            .stage_catalog(catalog, NOW + 7_200, stage_binding)
            .expect("expired exact stage replay"),
        staged
    );
    assert_eq!(
        recovered
            .acknowledge(first_ack, NOW + 7_200, first_ack_binding)
            .expect("expired exact acknowledgement replay"),
        first_ack_result
    );
    assert_eq!(
        recovered
            .promote(staged.catalog_digest, 1, NOW + 7_200, promote_binding,)
            .expect("expired exact promotion replay"),
        promoted
    );
    assert_eq!(
        recovered
            .checkpoint()
            .expect("checkpoint after replays")
            .revision,
        4,
        "exact replays must not advance the durable revision"
    );
}
#[test]
fn new_keys_for_identical_stage_and_acknowledgement_commit_distinct_replay_records() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    let first = controller
        .stage_catalog(catalog.clone(), NOW + 5, indexed_mutation_binding(1))
        .expect("first stage");
    let second = controller
        .stage_catalog(catalog, NOW + 6, indexed_mutation_binding(2))
        .expect("idempotent stage under a new key");
    assert_eq!(first.catalog_digest, second.catalog_digest);
    let acknowledgement = acknowledgement(0, first.catalog_digest, true);
    controller
        .acknowledge(
            acknowledgement.clone(),
            NOW + 10,
            indexed_mutation_binding(3),
        )
        .expect("first acknowledgement");
    controller
        .acknowledge(acknowledgement, NOW + 11, indexed_mutation_binding(4))
        .expect("idempotent acknowledgement under a new key");
    let checkpoint = controller.checkpoint().expect("checkpoint");
    assert_eq!(checkpoint.acknowledgements.len(), 1);
    assert_eq!(checkpoint.idempotency_records.len(), 4);
    assert_eq!(checkpoint.revision, 4);
    drop(controller);
    let recovered = GatewayComplianceController::new(config(), store).expect("recover checkpoint");
    assert_eq!(
        recovered
            .checkpoint()
            .expect("recovered checkpoint")
            .idempotency_records
            .len(),
        4
    );
}
#[test]
fn idempotency_key_substitution_and_cross_action_reuse_fail_closed() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    let catalog = sign_catalog(payload(1, None));
    let binding = indexed_mutation_binding(1);
    let staged = controller
        .stage_catalog(catalog.clone(), NOW + 5, binding)
        .expect("stage");
    let changed_request = GatewayComplianceMutationBindingV1 {
        key_digest: binding.key_digest,
        request_digest: [0xEF; 32],
    };
    assert!(matches!(
        controller.stage_catalog(catalog, NOW + 6, changed_request),
        Err(GatewayComplianceError::IdempotencyConflict)
    ));
    assert!(matches!(
        controller.acknowledge(
            acknowledgement(0, staged.catalog_digest, true),
            NOW + 10,
            binding,
        ),
        Err(GatewayComplianceError::IdempotencyConflict)
    ));
    assert_eq!(
        controller
            .checkpoint()
            .expect("checkpoint")
            .idempotency_records
            .len(),
        1
    );
}
#[test]
fn promotion_expectation_failure_does_not_consume_the_operation_key() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    let catalog = sign_catalog(payload(1, None));
    let digest = controller
        .stage_catalog(catalog, NOW + 5, indexed_mutation_binding(1))
        .expect("stage")
        .catalog_digest;
    for gateway_index in 0..2 {
        controller
            .acknowledge(
                acknowledgement(gateway_index, digest, true),
                NOW + 10,
                indexed_mutation_binding(2 + gateway_index as u64),
            )
            .expect("acknowledge");
    }
    let promotion_binding = indexed_mutation_binding(4);
    assert!(matches!(
        controller.promote([0xFF; 32], 1, NOW + 20, promotion_binding),
        Err(GatewayComplianceError::PromotionTargetMismatch)
    ));
    assert_eq!(
        controller
            .promote(digest, 1, NOW + 20, promotion_binding)
            .expect("corrected promotion")
            .catalog_digest,
        digest
    );
}
#[test]
fn crash_before_durable_replace_commits_neither_state_nor_replay_binding() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    let binding = indexed_mutation_binding(1);
    store.fail_next_store();
    assert!(matches!(
        controller.stage_catalog(catalog.clone(), NOW + 5, binding),
        Err(GatewayComplianceError::Persistence(_))
    ));
    let checkpoint = controller.checkpoint().expect("in-memory checkpoint");
    assert!(checkpoint.candidate.is_none());
    assert!(checkpoint.idempotency_records.is_empty());
    assert_eq!(checkpoint.revision, 0);
    assert!(store.durable_bytes().is_none());
    assert_eq!(
        controller
            .stage_catalog(catalog, NOW + 5, binding)
            .expect("retry after failed store")
            .recorded_at_unix,
        NOW + 5
    );
    assert_eq!(controller.checkpoint().expect("checkpoint").revision, 1);
}
#[test]
fn memory_store_allows_one_controller_lease_until_drop() {
    let store = Arc::new(MemoryStore::default());
    let controller =
        GatewayComplianceController::new(config(), store.clone()).expect("first controller");
    assert!(matches!(
        GatewayComplianceController::new(config(), store.clone()),
        Err(GatewayComplianceError::LeaseHeld)
    ));
    drop(controller);
    let recovered =
        GatewayComplianceController::new(config(), store).expect("lease after controller drop");
    assert_eq!(recovered.checkpoint().expect("checkpoint").revision, 0);
}
#[test]
fn stale_generation_fences_controller_without_overwriting_durable_bytes() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    controller
        .stage_catalog(catalog.clone(), NOW + 5, indexed_mutation_binding(1))
        .expect("first durable stage");
    let poisoned = b"out-of-band-checkpoint-replacement".to_vec();
    store.force_store(poisoned.clone());
    assert!(matches!(
        controller.stage_catalog(catalog, NOW + 6, indexed_mutation_binding(2)),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert!(matches!(
        controller.checkpoint(),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert_eq!(store.durable_bytes(), Some(poisoned));
}
#[test]
fn crash_after_durable_replace_recovers_exactly_once_and_fences_old_controller() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    let binding = indexed_mutation_binding(1);
    let catalog_digest = catalog.payload.catalog_digest().expect("catalog digest");
    store.fail_after_store();
    assert!(matches!(
        controller.stage_catalog(catalog.clone(), NOW + 5, binding),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert!(matches!(
        controller.checkpoint(),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    let durable = decode_checkpoint(
        &store
            .durable_bytes()
            .expect("replacement reached durable memory store"),
    )
    .expect("durable checkpoint");
    assert_eq!(durable.revision, 1);
    assert_eq!(durable.idempotency_records.len(), 1);
    drop(controller);
    let recovered =
        GatewayComplianceController::new(config(), store).expect("recover durable replacement");
    assert_eq!(
        recovered
            .stage_catalog(catalog, NOW + 7_200, binding)
            .expect("exact replay after indeterminate response"),
        GatewayComplianceMutationResultV1 {
            catalog_digest,
            recorded_at_unix: NOW + 5,
        }
    );
    assert_eq!(recovered.checkpoint().expect("checkpoint").revision, 1);
}
#[test]
fn full_idempotency_registry_replays_known_keys_and_rejects_new_keys() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    let digest = controller
        .stage_catalog(catalog.clone(), NOW + 5, indexed_mutation_binding(1))
        .expect("stage")
        .catalog_digest;
    let mut checkpoint = controller.checkpoint().expect("checkpoint");
    checkpoint.idempotency_records =
        (1..=u64::try_from(MAX_GATEWAY_COMPLIANCE_IDEMPOTENCY_RECORDS_V1)
            .expect("registry bound fits u64"))
            .map(|index| {
                let binding = indexed_mutation_binding(index);
                GatewayComplianceIdempotencyRecordV1 {
                    key_digest: binding.key_digest,
                    request_digest: binding.request_digest,
                    operation: GatewayComplianceMutationKindV1::Stage,
                    catalog_digest: digest,
                    recorded_at_unix: NOW + 5,
                }
            })
            .collect();
    checkpoint.revision = u64::try_from(MAX_GATEWAY_COMPLIANCE_IDEMPOTENCY_RECORDS_V1)
        .expect("registry bound fits u64");
    let bytes = encode_bounded(&checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)
        .expect("encode full registry");
    drop(controller);
    store.force_store(bytes);
    let recovered =
        GatewayComplianceController::new(config(), store).expect("recover full registry");
    assert_eq!(
        recovered
            .stage_catalog(catalog.clone(), NOW + 7_200, indexed_mutation_binding(1),)
            .expect("known key replay"),
        GatewayComplianceMutationResultV1 {
            catalog_digest: digest,
            recorded_at_unix: NOW + 5,
        }
    );
    assert!(matches!(
        recovered.stage_catalog(
            catalog,
            NOW + 6,
            indexed_mutation_binding(
                u64::try_from(MAX_GATEWAY_COMPLIANCE_IDEMPOTENCY_RECORDS_V1)
                    .expect("registry bound fits u64")
                    + 1,
            ),
        ),
        Err(GatewayComplianceError::IdempotencyRegistryFull)
    ));
    assert_eq!(
        recovered
            .checkpoint()
            .expect("checkpoint")
            .idempotency_records
            .len(),
        MAX_GATEWAY_COMPLIANCE_IDEMPOTENCY_RECORDS_V1
    );
}
#[test]
fn checkpoint_rejects_duplicate_idempotency_keys() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    controller
        .stage_catalog(
            sign_catalog(payload(1, None)),
            NOW + 5,
            indexed_mutation_binding(1),
        )
        .expect("stage");
    let mut checkpoint = controller.checkpoint().expect("checkpoint");
    checkpoint
        .idempotency_records
        .push(checkpoint.idempotency_records[0].clone());
    checkpoint.revision = checkpoint
        .revision
        .checked_add(1)
        .expect("test checkpoint revision");
    let bytes = encode_bounded(&checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)
        .expect("encode poisoned checkpoint");
    drop(controller);
    store.force_store(bytes);
    assert!(matches!(
        GatewayComplianceController::new(config(), store),
        Err(GatewayComplianceError::InvalidCheckpoint(_))
    ));
}
#[test]
fn checkpoint_rejects_revision_rollback_and_truncated_bytes_on_restart() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    controller
        .stage_catalog(
            sign_catalog(payload(1, None)),
            NOW + 5,
            indexed_mutation_binding(1),
        )
        .expect("stage");
    let mut checkpoint = controller.checkpoint().expect("checkpoint");
    assert_eq!(checkpoint.revision, 1);
    checkpoint.revision = 0;
    let rolled_back_revision =
        encode_bounded(&checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)
            .expect("encode revision rollback");
    drop(controller);
    store.force_store(rolled_back_revision);
    assert!(matches!(
        GatewayComplianceController::new(config(), store.clone()),
        Err(GatewayComplianceError::InvalidCheckpoint(_))
    ));
    store.force_store(vec![0x4E, 0x52, 0x54]);
    assert!(matches!(
        GatewayComplianceController::new(config(), store),
        Err(GatewayComplianceError::InvalidCheckpoint(_))
    ));
}
#[test]
fn catalog_rejects_stale_and_future_source_anchors() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    let mut stale = payload(1, None);
    stale.source_anchors[0].generated_at_unix = NOW - 3_601;
    assert!(matches!(
        controller.stage_catalog(sign_catalog(stale), NOW + 5, mutation_binding(1)),
        Err(GatewayComplianceError::InvalidCatalog(_))
    ));
    let mut future = payload(1, None);
    future.source_anchors[0].generated_at_unix = NOW + 301;
    assert!(matches!(
        controller.stage_catalog(sign_catalog(future), NOW + 5, mutation_binding(2)),
        Err(GatewayComplianceError::InvalidCatalog(_))
    ));
    let mut excessive_validity = payload(1, None);
    excessive_validity.valid_until_unix = NOW + 7_201;
    assert!(matches!(
        controller.stage_catalog(
            sign_catalog(excessive_validity),
            NOW + 5,
            mutation_binding(3),
        ),
        Err(GatewayComplianceError::InvalidCatalog(_))
    ));
}
#[test]
fn serving_rejects_zero_rolled_back_and_expired_clocks() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    promote(&controller, sign_catalog(payload(1, None)));
    for observed_at_unix in [0, NOW - 301, NOW + 3_600] {
        assert!(matches!(
            controller.evaluate_serving(
                GatewayComplianceSubjectKindV1::ManifestDigest,
                &subject(1),
                observed_at_unix,
            ),
            Err(GatewayComplianceError::CatalogNotFresh)
        ));
    }
}
#[test]
fn promotion_revalidates_acknowledgement_freshness() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    let digest = controller
        .stage_catalog(sign_catalog(payload(1, None)), NOW + 5, mutation_binding(1))
        .expect("stage")
        .catalog_digest;
    for gateway_index in 0..2 {
        controller
            .acknowledge(
                acknowledgement_at(gateway_index, digest, true, NOW + 10),
                NOW + 10,
                mutation_binding(2 + gateway_index as u8),
            )
            .expect("acknowledge");
    }
    assert!(matches!(
        controller.promote(digest, 1, NOW + 311, mutation_binding(4)),
        Err(GatewayComplianceError::InvalidAcknowledgement(_))
    ));
    assert!(
        controller
            .checkpoint()
            .expect("checkpoint")
            .serving
            .is_none()
    );
}
#[test]
fn every_mutation_rejects_clock_rollback_before_state_change() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    let first_digest = controller
        .stage_catalog(sign_catalog(payload(1, None)), NOW + 5, mutation_binding(1))
        .expect("stage first")
        .catalog_digest;
    for gateway_index in 0..2 {
        controller
            .acknowledge(
                acknowledgement_at(gateway_index, first_digest, true, NOW + 10),
                NOW + 10,
                mutation_binding(2 + gateway_index as u8),
            )
            .expect("acknowledge first");
    }
    controller
        .promote(first_digest, 1, NOW + 100, mutation_binding(4))
        .expect("promote first");
    let mut second = payload(2, Some(first_digest));
    second.generated_at_unix = NOW + 40;
    second.valid_until_unix = NOW + 1_000;
    assert!(matches!(
        controller.stage_catalog(sign_catalog(second), NOW + 45, mutation_binding(5)),
        Err(GatewayComplianceError::MutationTimeInvalid)
    ));
    assert_eq!(
        controller
            .checkpoint()
            .expect("checkpoint")
            .chain_head
            .expect("chain head")
            .payload
            .catalog_digest()
            .expect("digest"),
        first_digest
    );
}
#[test]
fn controller_config_rejects_unbounded_fetch_and_freshness_windows() {
    let mut redirects = config();
    redirects.fetch_limits.max_redirects = 9;
    assert!(matches!(
        redirects.validate(),
        Err(GatewayComplianceError::InvalidPolicy(_))
    ));
    let mut timeout = config();
    timeout.fetch_limits.total_timeout = Duration::from_secs(121);
    assert!(matches!(
        timeout.validate(),
        Err(GatewayComplianceError::InvalidPolicy(_))
    ));
    let mut freshness = config();
    freshness.max_feed_age_secs = 0;
    assert!(matches!(
        freshness.validate(),
        Err(GatewayComplianceError::InvalidPolicy(_))
    ));
    let mut unknown_gateway = config();
    unknown_gateway.gateway_scope = "gateway:gateway-unknown".into();
    assert!(matches!(
        unknown_gateway.validate(),
        Err(GatewayComplianceError::InvalidPolicy(_))
    ));
    let mut malformed_region = config();
    malformed_region.region_scope = "gateway:gateway-eu".into();
    assert!(matches!(
        malformed_region.validate(),
        Err(GatewayComplianceError::InvalidPolicy(_))
    ));
}
#[test]
fn serving_evaluation_fails_closed_without_a_promoted_catalog() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    assert!(matches!(
        controller.evaluate_serving(
            GatewayComplianceSubjectKindV1::ManifestDigest,
            &subject(1),
            NOW
        ),
        Err(GatewayComplianceError::NoServingCatalog)
    ));
}
#[test]
fn allow_all_test_controller_serves_from_a_governed_catalog() {
    let controller = allow_all_gateway_compliance_controller_for_tests();
    let observed_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock")
        .as_secs();
    let decision = controller
        .evaluate_serving(
            GatewayComplianceSubjectKindV1::ManifestDigest,
            &subject(0xA4),
            observed_at_unix,
        )
        .expect("allow-all decision");
    assert_eq!(decision.source, GatewayComplianceDecisionSource::NoMatch);
    assert_eq!(decision.disposition, GatewayComplianceDisposition::Allow);
    assert!(decision.catalog_digest.is_some());
    let checkpoint = controller.checkpoint().expect("test checkpoint");
    let serving = checkpoint.serving.as_ref().expect("serving catalog");
    assert_eq!(decision.catalog_sequence, serving.payload.sequence);
    assert_eq!(
        decision.catalog_valid_until_unix,
        serving.payload.valid_until_unix
    );
}
#[test]
fn serving_precedence_spans_global_region_and_gateway_scopes() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    let mut candidate = payload(1, None);
    candidate
        .baseline_rules
        .push(GatewayComplianceBaselineRuleV1 {
            rule_id: "global-baseline".into(),
            scope: "global".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(9),
            source_id: "baseline".into(),
            reason_code: "policy-deny".into(),
            toggle_id: None,
            effective_from_unix: NOW,
            expires_at_unix: Some(NOW + 1_000),
        });
    candidate
        .appeal_overrides
        .push(GatewayComplianceAppealOverrideV1 {
            appeal_id: "regional-appeal".into(),
            scope: "region:eu".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(9),
            decision_digest: [0x69; 32],
            effective_from_unix: NOW,
            expires_at_unix: NOW + 1_000,
        });
    candidate
        .baseline_rules
        .push(GatewayComplianceBaselineRuleV1 {
            rule_id: "global-baseline-held".into(),
            scope: "global".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(10),
            source_id: "baseline".into(),
            reason_code: "policy-deny".into(),
            toggle_id: None,
            effective_from_unix: NOW,
            expires_at_unix: Some(NOW + 1_000),
        });
    candidate
        .appeal_overrides
        .push(GatewayComplianceAppealOverrideV1 {
            appeal_id: "regional-appeal-held".into(),
            scope: "region:eu".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(10),
            decision_digest: [0x6A; 32],
            effective_from_unix: NOW,
            expires_at_unix: NOW + 1_000,
        });
    candidate
        .legal_safety_holds
        .push(GatewayComplianceLegalSafetyHoldV1 {
            hold_id: "gateway-hold".into(),
            scope: "gateway:gateway-eu".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(10),
            authority_reference: "court-order-10".into(),
            effective_from_unix: NOW,
            expires_at_unix: Some(NOW + 1_000),
        });
    promote(&controller, sign_catalog(candidate));
    assert_eq!(
        controller
            .evaluate_serving(
                GatewayComplianceSubjectKindV1::ManifestDigest,
                &subject(9),
                NOW + 30,
            )
            .expect("regional appeal decision")
            .source,
        GatewayComplianceDecisionSource::AcceptedAppeal
    );
    assert_eq!(
        controller
            .evaluate_serving(
                GatewayComplianceSubjectKindV1::ManifestDigest,
                &subject(10),
                NOW + 30,
            )
            .expect("gateway hold decision")
            .source,
        GatewayComplianceDecisionSource::LegalSafetyHold
    );
}
#[test]
fn hold_then_appeal_then_baseline_precedence_is_deterministic() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let mut candidate = payload(1, None);
    for (id, byte) in [
        ("held", 1_u8),
        ("appealed", 2),
        ("baseline", 3),
        ("toggle", 4),
    ] {
        candidate
            .baseline_rules
            .push(GatewayComplianceBaselineRuleV1 {
                rule_id: format!("rule-{id}"),
                scope: "global".into(),
                subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
                subject: subject(byte),
                source_id: "baseline".into(),
                reason_code: "policy-deny".into(),
                toggle_id: (id == "toggle").then(|| "provider-deny".into()),
                effective_from_unix: NOW,
                expires_at_unix: Some(NOW + 1_000),
            });
    }
    candidate
        .appeal_overrides
        .push(GatewayComplianceAppealOverrideV1 {
            appeal_id: "appeal-held".into(),
            scope: "global".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(1),
            decision_digest: [0x61; 32],
            effective_from_unix: NOW,
            expires_at_unix: NOW + 1_000,
        });
    candidate
        .appeal_overrides
        .push(GatewayComplianceAppealOverrideV1 {
            appeal_id: "appeal-accepted".into(),
            scope: "global".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(2),
            decision_digest: [0x62; 32],
            effective_from_unix: NOW,
            expires_at_unix: NOW + 1_000,
        });
    candidate
        .legal_safety_holds
        .push(GatewayComplianceLegalSafetyHoldV1 {
            hold_id: "hold-safety".into(),
            scope: "global".into(),
            subject_kind: GatewayComplianceSubjectKindV1::ManifestDigest,
            subject: subject(1),
            authority_reference: "court-order-7".into(),
            effective_from_unix: NOW,
            expires_at_unix: Some(NOW + 1_000),
        });
    candidate.toggles.push(GatewayComplianceToggleV1 {
        toggle_id: "provider-deny".into(),
        scope: "global".into(),
        enabled: false,
        approval_reference: "governance-9".into(),
        effective_from_unix: NOW,
        expires_at_unix: NOW + 1_000,
    });
    promote(&controller, sign_catalog(candidate));
    let evaluate = |byte| {
        controller
            .evaluate(
                "region:eu",
                GatewayComplianceSubjectKindV1::ManifestDigest,
                &subject(byte),
                NOW + 30,
            )
            .expect("decision")
    };
    assert_eq!(
        evaluate(1).source,
        GatewayComplianceDecisionSource::LegalSafetyHold
    );
    assert_eq!(
        evaluate(2).source,
        GatewayComplianceDecisionSource::AcceptedAppeal
    );
    assert_eq!(
        evaluate(3).source,
        GatewayComplianceDecisionSource::Baseline
    );
    assert_eq!(evaluate(4).source, GatewayComplianceDecisionSource::NoMatch);
}
#[test]
fn threshold_rollback_changes_serving_pointer_but_preserves_chain_head() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let first = sign_catalog(payload(1, None));
    let first_digest = promote(&controller, first);
    let second = sign_catalog(payload(2, Some(first_digest)));
    let second_digest = promote(&controller, second);
    let rollback_payload = GatewayComplianceRollbackPayloadV1 {
        version: GATEWAY_COMPLIANCE_ROLLBACK_VERSION_V1,
        operation_id: [0xC1; 32],
        from_catalog_digest: second_digest,
        to_catalog_digest: first_digest,
        reason_code: "bad-feed".into(),
        authorized_at_unix: NOW + 55,
    };
    crate::frame_test_support::assert_current_frame(
        &rollback_payload,
        "sorafs_manifest::gateway_compliance::GatewayComplianceRollbackPayloadV1",
    );
    let digest = rollback_payload.signing_digest().expect("rollback digest");
    let keys = catalog_keys();
    let rollback = GatewayComplianceRollbackV1 {
        payload: rollback_payload,
        approvals: vec![
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-a".into(),
                signature: keys[0].sign(&digest).to_bytes(),
            },
            GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: "council-b".into(),
                signature: keys[1].sign(&digest).to_bytes(),
            },
        ],
    };
    let rollback_result = controller
        .rollback(&rollback, NOW + 55, mutation_binding(0xC1))
        .expect("rollback");
    assert_eq!(rollback_result.catalog_digest, first_digest);
    assert_eq!(rollback_result.recorded_at_unix, NOW + 55);
    let checkpoint = controller.checkpoint().expect("checkpoint");
    assert_eq!(
        checkpoint
            .serving
            .expect("serving")
            .payload
            .catalog_digest()
            .expect("digest"),
        first_digest
    );
    assert_eq!(
        checkpoint
            .chain_head
            .expect("chain head")
            .payload
            .catalog_digest()
            .expect("digest"),
        second_digest
    );
    assert!(matches!(
        controller.rollback(
            &rollback,
            NOW + 56,
            GatewayComplianceMutationBindingV1 {
                key_digest: [0xC1; 32],
                request_digest: [0xFE; 32],
            },
        ),
        Err(GatewayComplianceError::IdempotencyConflict)
    ));
    assert_eq!(
        controller
            .rollback(&rollback, NOW + 3_599, mutation_binding(0xC1))
            .expect("exact replay"),
        rollback_result
    );
    let revision = controller.checkpoint().expect("checkpoint").revision;
    drop(controller);
    let recovered =
        GatewayComplianceController::new(config(), store).expect("recover rollback state");
    assert_eq!(
        recovered
            .rollback(&rollback, NOW + 7_200, mutation_binding(0xC1))
            .expect("exact rollback replay after restart"),
        rollback_result
    );
    assert_eq!(
        recovered
            .checkpoint()
            .expect("recovered checkpoint")
            .revision,
        revision
    );
}
#[test]
fn rollback_rejects_an_expired_last_known_good_catalog() {
    let controller = GatewayComplianceController::new(config(), Arc::new(MemoryStore::default()))
        .expect("controller");
    let mut first = payload(1, None);
    first.valid_until_unix = NOW + 100;
    let first_digest = promote(&controller, sign_catalog(first));
    let mut second = payload(2, Some(first_digest));
    second.generated_at_unix = NOW + 30;
    second.valid_until_unix = NOW + 1_000;
    let second_digest = controller
        .stage_catalog(sign_catalog(second), NOW + 35, mutation_binding(12))
        .expect("stage second")
        .catalog_digest;
    for gateway_index in 0..2 {
        controller
            .acknowledge(
                acknowledgement_at(gateway_index, second_digest, true, NOW + 40),
                NOW + 40,
                mutation_binding(13 + gateway_index as u8),
            )
            .expect("acknowledge second");
    }
    controller
        .promote(second_digest, 2, NOW + 50, mutation_binding(15))
        .expect("promote second");
    let rollback = rollback_authorization([0xD1; 32], second_digest, first_digest, NOW + 120);
    assert!(matches!(
        controller.rollback(&rollback, NOW + 120, mutation_binding(0xD1)),
        Err(GatewayComplianceError::CatalogNotFresh)
    ));
}
#[test]
fn checkpoint_rejects_pointer_and_history_lineage_substitution() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    promote(&controller, sign_catalog(payload(1, None)));
    let mut checkpoint = controller.checkpoint().expect("checkpoint");
    checkpoint.history[0].serving_digest = [0xBA; 32];
    let encoded = encode_bounded(&checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)
        .expect("encode tampered checkpoint");
    drop(controller);
    store.force_store(encoded);
    assert!(matches!(
        GatewayComplianceController::new(config(), store),
        Err(GatewayComplianceError::InvalidCheckpoint(_))
    ));
}
#[test]
fn checkpoint_rejects_terminal_history_without_exact_replay_record() {
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    promote(&controller, sign_catalog(payload(1, None)));
    let mut checkpoint = controller.checkpoint().expect("checkpoint");
    checkpoint
        .idempotency_records
        .retain(|record| record.operation != GatewayComplianceMutationKindV1::Promote);
    checkpoint.revision =
        u64::try_from(checkpoint.idempotency_records.len()).expect("test checkpoint record count");
    let encoded = encode_bounded(&checkpoint, MAX_GATEWAY_COMPLIANCE_CHECKPOINT_BYTES_V1)
        .expect("encode tampered checkpoint");
    drop(controller);
    store.force_store(encoded);
    assert!(matches!(
        GatewayComplianceController::new(config(), store),
        Err(GatewayComplianceError::InvalidCheckpoint(_))
    ));
}
#[derive(Debug)]
struct ScriptedTransport {
    resolutions: Mutex<VecDeque<Vec<IpAddr>>>,
    response: GatewayComplianceFetchResponse,
}
impl GatewayComplianceFeedTransport for ScriptedTransport {
    fn qualification(
        &self,
    ) -> Result<GatewayComplianceFeedTransportIdentityV1, GatewayComplianceFeedTransportProbeError>
    {
        Ok(test_feed_transport_identity())
    }
    fn resolve(
        &self,
        _hostname: &str,
        _timeout: Duration,
    ) -> Result<Vec<IpAddr>, GatewayComplianceError> {
        self.resolutions
            .lock()
            .expect("resolution lock")
            .pop_front()
            .ok_or_else(|| GatewayComplianceError::InvalidFeed("missing DNS script".into()))
    }
    fn fetch(
        &self,
        _request: &GatewayComplianceFetchRequest,
    ) -> Result<GatewayComplianceFetchResponse, GatewayComplianceError> {
        Ok(self.response.clone())
    }
}
fn test_feed_transport_identity() -> GatewayComplianceFeedTransportIdentityV1 {
    let policy = feed_policy();
    let pins_by_hostname = policy
        .hosts
        .into_iter()
        .map(|host| (host.hostname, host.accepted_spki_sha256))
        .collect();
    GatewayComplianceFeedTransportIdentityV1 {
        provider_handle: GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.to_owned(),
        revision: GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
        policy_digest: gateway_compliance_feed_transport_policy_digest(&pins_by_hostname)
            .expect("test transport policy"),
        test_marked: false,
    }
}
fn feed_policy() -> GatewayComplianceFeedPolicy {
    GatewayComplianceFeedPolicy {
        feed_id: "baseline".into(),
        url: "https://feed.example/catalog".into(),
        required: true,
        hosts: vec![GatewayComplianceFeedHostPolicy {
            hostname: "feed.example".into(),
            accepted_spki_sha256: BTreeSet::from([[0x77; 32]]),
        }],
    }
}
fn fetch_response(body: Vec<u8>) -> GatewayComplianceFetchResponse {
    GatewayComplianceFetchResponse {
        status: 200,
        redirect_location: None,
        connected_address: "93.184.216.34".parse().expect("public IP"),
        peer_spki_sha256: [0x77; 32],
        content_encoding: GatewayComplianceContentEncoding::Identity,
        body,
        elapsed: Duration::from_millis(20),
    }
}
#[path = "../compliance_feed_transport_tests.rs"]
mod feed_transport_tests;
#[derive(Debug)]
struct DeadlineTransport {
    response: GatewayComplianceFetchResponse,
}
impl GatewayComplianceFeedTransport for DeadlineTransport {
    fn qualification(
        &self,
    ) -> Result<GatewayComplianceFeedTransportIdentityV1, GatewayComplianceFeedTransportProbeError>
    {
        Ok(test_feed_transport_identity())
    }
    fn resolve(
        &self,
        _hostname: &str,
        _timeout: Duration,
    ) -> Result<Vec<IpAddr>, GatewayComplianceError> {
        std::thread::sleep(Duration::from_millis(8));
        Ok(vec!["93.184.216.34".parse().expect("public IP")])
    }
    fn fetch(
        &self,
        _request: &GatewayComplianceFetchRequest,
    ) -> Result<GatewayComplianceFetchResponse, GatewayComplianceError> {
        Ok(self.response.clone())
    }
}
#[test]
fn feed_fetch_enforces_one_cumulative_deadline() {
    let limits = GatewayComplianceFetchLimits {
        connect_timeout: Duration::from_millis(10),
        total_timeout: Duration::from_millis(15),
        ..Default::default()
    };
    let mut response = fetch_response(Vec::new());
    response.elapsed = Duration::from_millis(8);
    let transport = DeadlineTransport { response };
    assert!(matches!(
        fetch_feed_bytes(
            &feed_policy(),
            limits,
            &test_feed_transport_identity(),
            &transport,
        ),
        Err(GatewayComplianceError::FetchTimeout)
    ));
}
#[test]
fn file_store_lease_restart_and_exact_replay_are_durable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let path = root.join("checkpoint.to");
    let store =
        Arc::new(FileGatewayComplianceStore::new(path.clone()).expect("file checkpoint store"));
    let controller =
        GatewayComplianceController::new(config(), store.clone()).expect("first controller");
    assert!(matches!(
        GatewayComplianceController::new(config(), store.clone()),
        Err(GatewayComplianceError::LeaseHeld)
    ));
    let catalog = sign_catalog(payload(1, None));
    let binding = indexed_mutation_binding(1);
    let staged = controller
        .stage_catalog(catalog.clone(), NOW + 5, binding)
        .expect("stage");
    assert_eq!(controller.checkpoint().expect("checkpoint").revision, 1);
    let target_metadata = secure_file_metadata::from_path(&path).expect("checkpoint metadata");
    assert!(secure_file_metadata::is_direct_file(&target_metadata));
    assert_eq!(
        secure_file_metadata::number_of_links(&target_metadata),
        Some(1)
    );
    assert!(
        fs::read_dir(&root)
            .expect("checkpoint directory")
            .all(|entry| !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")),
        "same-directory temporary files must not survive a successful replacement"
    );
    drop(controller);
    let recovered = GatewayComplianceController::new(config(), store).expect("restart controller");
    assert_eq!(
        recovered
            .stage_catalog(catalog, NOW + 7_200, binding)
            .expect("exact restart replay"),
        staged
    );
    assert_eq!(recovered.checkpoint().expect("checkpoint").revision, 1);
}
#[test]
fn file_store_exact_byte_cas_fences_stale_controller() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let path = root.join("checkpoint.to");
    let store =
        Arc::new(FileGatewayComplianceStore::new(path.clone()).expect("file checkpoint store"));
    let controller = GatewayComplianceController::new(config(), store).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    controller
        .stage_catalog(catalog.clone(), NOW + 5, indexed_mutation_binding(1))
        .expect("first stage");
    let replacement = b"external-exact-byte-replacement";
    fs::write(&path, replacement).expect("replace checkpoint outside controller");
    assert!(matches!(
        controller.stage_catalog(catalog, NOW + 6, indexed_mutation_binding(2)),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert!(matches!(
        controller.checkpoint(),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert_eq!(fs::read(path).expect("durable replacement"), replacement);
}
#[test]
fn file_store_rechecks_generation_immediately_before_persist() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let path = root.join("checkpoint.to");
    let store =
        Arc::new(FileGatewayComplianceStore::new(path.clone()).expect("file checkpoint store"));
    let controller = GatewayComplianceController::new(config(), store.clone()).expect("controller");
    let catalog = sign_catalog(payload(1, None));
    controller
        .stage_catalog(catalog.clone(), NOW + 5, indexed_mutation_binding(1))
        .expect("first stage");
    let replacement = b"replacement-during-write-preparation".to_vec();
    store.replace_before_next_persist(replacement.clone());
    assert!(matches!(
        controller.stage_catalog(catalog, NOW + 6, indexed_mutation_binding(2)),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert!(matches!(
        controller.checkpoint(),
        Err(GatewayComplianceError::CheckpointConflict)
    ));
    assert_eq!(
        fs::read(&path).expect("replacement must not be overwritten"),
        replacement
    );
    assert!(
        fs::read_dir(&root)
            .expect("checkpoint directory")
            .all(|entry| !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")),
        "prepared temporary file must be removed after a generation conflict"
    );
}
#[cfg(any(unix, windows))]
#[test]
fn file_store_rejects_hardlinked_checkpoint() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let path = root.join("checkpoint.to");
    let alias = root.join("checkpoint.alias");
    fs::write(&path, b"seed").expect("seed checkpoint");
    fs::hard_link(&path, &alias).expect("hardlink checkpoint");
    let store =
        FileGatewayComplianceStore::new(path.clone()).expect("file checkpoint store config");
    assert!(matches!(
        GatewayComplianceController::new(config(), Arc::new(store)),
        Err(GatewayComplianceError::Persistence(_))
    ));
    assert_eq!(fs::read(path).expect("checkpoint"), b"seed");
    assert_eq!(fs::read(alias).expect("checkpoint alias"), b"seed");
}
#[cfg(any(unix, windows))]
#[test]
fn file_store_rejects_hardlinked_lease_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let path = root.join("checkpoint.to");
    let lock_path = checkpoint_lock_path(&path).expect("checkpoint lock path");
    let alias = root.join("checkpoint.lock.alias");
    fs::write(&lock_path, b"").expect("seed checkpoint lock");
    fs::hard_link(&lock_path, &alias).expect("hardlink checkpoint lock");
    let store = FileGatewayComplianceStore::new(path).expect("file checkpoint store config");

    assert!(matches!(
        store.try_acquire(),
        Err(GatewayComplianceError::Persistence(_))
    ));
}
#[cfg(unix)]
#[test]
fn file_store_rejects_group_or_world_writable_parent() {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let unsafe_parent = root.join("unsafe");
    fs::create_dir(&unsafe_parent).expect("unsafe checkpoint directory");
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))
        .expect("set unsafe directory permissions");
    assert!(matches!(
        FileGatewayComplianceStore::new(unsafe_parent.join("checkpoint.to")),
        Err(GatewayComplianceError::Persistence(_))
    ));
}
#[cfg(unix)]
#[test]
fn file_store_rejects_symlink_lease_file() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let path = root.join("checkpoint.to");
    let lock_path = checkpoint_lock_path(&path).expect("checkpoint lock path");
    let target = root.join("lease-target");
    fs::write(&target, b"do-not-lock").expect("seed lease target");
    symlink(&target, &lock_path).expect("create lease symlink");
    let store = FileGatewayComplianceStore::new(path).expect("store config");
    assert!(matches!(
        store.try_acquire(),
        Err(GatewayComplianceError::Persistence(_))
    ));
    assert_eq!(fs::read(target).expect("lease target"), b"do-not-lock");
}
#[cfg(unix)]
#[test]
fn file_store_rejects_symlink_checkpoint() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonical tempdir");
    let target = root.join("real.to");
    fs::write(&target, b"old").expect("seed target");
    let link = root.join("checkpoint.to");
    symlink(&target, &link).expect("create symlink");
    let store = FileGatewayComplianceStore::new(link).expect("store config");
    let lease = store.try_acquire().expect("checkpoint lease");
    assert!(matches!(
        lease.compare_and_store(GatewayComplianceStoreGeneration::Absent, b"replacement"),
        Err(GatewayComplianceError::Persistence(_))
    ));
    assert_eq!(fs::read(target).expect("read target"), b"old");
}

#[test]
fn qualified_empty_feed_catalog_still_requires_signatures_ack_quorum_and_fresh_promotion() {
    let mut selected = config();
    selected.feeds.clear();
    let pins = BTreeMap::new();
    let digest = gateway_compliance_feed_transport_policy_digest(&pins).unwrap();
    assert_ne!(digest, [0; 32]);
    assert_ne!(digest, config().feed_transport_policy_digest().unwrap());
    selected.feed_transport_provider = Some(
        GatewayProviderBindingV1::try_new(
            GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.to_owned(),
            GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
            digest,
        )
        .unwrap(),
    );
    let transport =
        crate::sorafs::gateway::ProductionGatewayComplianceFeedTransport::try_new(pins).unwrap();
    let store = Arc::new(MemoryStore::default());
    let controller = GatewayComplianceController::new_with_feed_transport(
        selected.clone(),
        store.clone(),
        &transport,
    )
    .unwrap();
    assert!(matches!(
        controller.fetch_feed("baseline", &transport),
        Err(GatewayComplianceError::UnknownFeed(_))
    ));
    let mut empty = payload(1, None);
    empty.source_anchors.clear();
    let signed = sign_catalog(empty);
    let mut missing = signed.clone();
    missing.approvals.pop();
    assert!(matches!(
        controller.stage_catalog(missing, NOW + 5, mutation_binding(1)),
        Err(GatewayComplianceError::QuorumNotMet { .. })
    ));
    let catalog_digest = controller
        .stage_catalog(signed.clone(), NOW + 5, mutation_binding(1))
        .unwrap()
        .catalog_digest;
    assert!(matches!(
        controller.evaluate(
            "global",
            GatewayComplianceSubjectKindV1::Provider,
            &subject(1),
            NOW + 5
        ),
        Err(GatewayComplianceError::NoServingCatalog)
    ));
    assert!(matches!(
        controller.promote(catalog_digest, 1, NOW + 20, mutation_binding(2)),
        Err(GatewayComplianceError::GatewayQuorumNotMet { .. })
    ));
    controller
        .acknowledge(
            acknowledgement(0, catalog_digest, true),
            NOW + 10,
            mutation_binding(3),
        )
        .unwrap();
    assert!(matches!(
        controller.promote(catalog_digest, 1, NOW + 20, mutation_binding(2)),
        Err(GatewayComplianceError::GatewayQuorumNotMet { .. })
    ));
    controller
        .acknowledge(
            acknowledgement(1, catalog_digest, true),
            NOW + 10,
            mutation_binding(4),
        )
        .unwrap();
    controller
        .promote(catalog_digest, 1, NOW + 20, mutation_binding(2))
        .unwrap();
    assert_eq!(
        controller
            .evaluate(
                "global",
                GatewayComplianceSubjectKindV1::Provider,
                &subject(1),
                NOW + 21
            )
            .unwrap()
            .source,
        GatewayComplianceDecisionSource::NoMatch
    );
    assert!(matches!(
        controller.evaluate(
            "global",
            GatewayComplianceSubjectKindV1::Provider,
            &subject(1),
            signed.payload.valid_until_unix
        ),
        Err(GatewayComplianceError::CatalogNotFresh)
    ));
    let original = store.durable_bytes().unwrap();
    drop(controller);
    let reopened =
        GatewayComplianceController::new_with_feed_transport(selected, store.clone(), &transport)
            .unwrap();
    assert_eq!(reopened.checkpoint().unwrap().serving.unwrap(), signed);
    assert_eq!(store.durable_bytes().unwrap(), original);
    assert!(matches!(
        reopened.evaluate(
            "global",
            GatewayComplianceSubjectKindV1::Provider,
            &subject(1),
            NOW + 3600
        ),
        Err(GatewayComplianceError::CatalogNotFresh)
    ));
}

mod ack_refresh;
