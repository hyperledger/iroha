// Service and journal test body included from the parent module.
use super::*;
use iroha::config::Config;
use iroha_crypto::{Algorithm, Hash, HashOf};
use iroha_data_model::{
    account::{MultisigMember, MultisigPolicy},
    block::BlockHeader,
    musubi::{
        ArchiveId, MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiArtifactDescriptorV1,
        MusubiContentDigestV1, MusubiKotodamaEditionV1, MusubiPackageIdV1, MusubiPackageScopeV1,
        MusubiProviderBundleVerificationApprovalV1, MusubiProviderBundleVerificationAttestationV1,
        MusubiProviderBundleVerificationBindingV1, MusubiProviderBundleVerificationPayloadV1,
        MusubiReleaseIdV1, MusubiReleaseMetadataV1, MusubiSemanticReleaseManifestV1,
        MusubiVerificationLockV1, musubi_provider_bundle_attestation_set_digest_v1,
    },
    sorafs::pin_registry::{
        ChunkerProfileHandle, ManifestRootCid, ProviderIngestCompletionAuthorityV1,
        ProviderIngestCompletionSignerPolicyV1, ProviderIngestFinalizedAnchorV1,
    },
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::topology::DataSpaceId;
use norito::codec::Encode as _;
use sorafs_car::{CarVerifier, CarWriter, FileEntry, compute_por_root};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
fn test_network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        [seed; 32],
    )))
}
#[test]
fn publication_private_filesystem_revalidates_original_native_owner() {
    let workspace = tempfile::tempdir().expect("publication test workspace");
    let root = iroha_fs::PrivateDirectory::open_or_create(workspace.path().join("private"))
        .expect("private native root");
    let lock = root
        .create_lock("owner.lock")
        .expect("original private lock");
    let before = iroha_fs::FileSnapshot::private_journal(&lock).expect("native private snapshot");
    root.revalidate().expect("original native custody");
    let named = root.open_read("owner.lock").expect("original named lock");
    assert_eq!(
        iroha_fs::FileSnapshot::private_journal(&named).unwrap(),
        before
    );
    #[cfg(unix)]
    assert_eq!(
        lock.metadata().unwrap().uid(),
        std::fs::metadata(root.path()).unwrap().uid()
    );
}
#[derive(Clone)]
struct TestPublicationClock {
    current_time_ms: Arc<AtomicU64>,
}
impl TestPublicationClock {
    fn new(initial_time_ms: u64) -> (Self, Arc<AtomicU64>) {
        let current_time_ms = Arc::new(AtomicU64::new(initial_time_ms));
        (
            Self {
                current_time_ms: Arc::clone(&current_time_ms),
            },
            current_time_ms,
        )
    }
}
impl MusubiPublicationServiceClockV1 for TestPublicationClock {
    fn current_time_ms(&mut self) -> Result<u64, MusubiPublicationServiceBackendErrorV1> {
        Ok(self.current_time_ms.load(Ordering::SeqCst))
    }
}
#[test]
fn private_http_request_debug_redacts_authorization_metadata_and_body() {
    let request = MusubiPublicationPrivateHttpRequestV1 {
        method: "POST",
        path: MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1,
        content_type: MUSUBI_PUBLICATION_SEED_ENVELOPE_MEDIA_TYPE_V1,
        authorization: Some("live-authorization-sentinel"),
        seed_ingress_metadata: Some("metadata-sentinel"),
        body: b"package-body-sentinel",
    };
    let debug = format!("{request:?}");
    for secret in [
        "live-authorization-sentinel",
        "metadata-sentinel",
        "package-body-sentinel",
    ] {
        assert!(!debug.contains(secret), "debug output exposed {secret}");
    }
    assert!(debug.contains("authorization_present: true"));
    assert!(debug.contains("body_length: 21"));
}
#[test]
fn publication_service_telemetry_annotations_are_closed_and_terminal() {
    let conflict = seed_ingress_journal_error(MusubiPublicationServiceJournalErrorV1::Conflict);
    assert_eq!(
        conflict.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(
            MusubiIngestDeadletterReasonV1::ReceiptReplay,
        ))
    );
    let authorization_replay =
        seed_ingress_journal_error(MusubiPublicationServiceJournalErrorV1::Replay);
    assert!(authorization_replay.retryable);
    assert_eq!(authorization_replay.telemetry, None);
    let retryable_storage =
        seed_ingress_backend_error(MusubiPublicationServiceBackendErrorV1::Retryable);
    assert!(retryable_storage.retryable);
    assert_eq!(retryable_storage.telemetry, None);
    let terminal_storage =
        seed_ingress_backend_error(MusubiPublicationServiceBackendErrorV1::Permanent);
    assert!(!terminal_storage.retryable);
    assert_eq!(
        terminal_storage.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(
            MusubiIngestDeadletterReasonV1::StorageRejected,
        ))
    );
    let readback = MusubiPublicationServiceErrorV1::permanent(
        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
    )
    .integrity_failure(MusubiIntegritySurfaceV1::ProviderReadback);
    assert_eq!(
        readback.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IntegrityFailure(
            MusubiIntegritySurfaceV1::ProviderReadback,
        ))
    );
}
#[derive(Clone)]
struct RecordingSeedIngress {
    provider: ProviderId,
    calls: Arc<Mutex<usize>>,
    fail_first: bool,
    clock_after_stage: Option<(Arc<AtomicU64>, u64)>,
}
impl MusubiSeedIngressBackendV1 for RecordingSeedIngress {
    fn provider_id(&self) -> ProviderId {
        self.provider
    }
    fn stage_exact_car(
        &mut self,
        _operation_id: [u8; 32],
        _binding: &MusubiSeedIngressReceiptBindingV1,
        _commitment: &MusubiArchiveCommitmentV1,
        _plan: &CarBuildPlan,
        _car: &[u8],
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        let mut calls = self.calls.lock().expect("seed call counter");
        *calls += 1;
        if self.fail_first && *calls == 1 {
            Err(MusubiPublicationServiceBackendErrorV1::Retryable)
        } else {
            if let Some((clock, current_time_ms)) = &self.clock_after_stage {
                clock.store(*current_time_ms, Ordering::SeqCst);
            }
            Ok(())
        }
    }
    fn verify_staged_car(
        &self,
        _operation_id: [u8; 32],
        binding: &MusubiSeedIngressReceiptBindingV1,
        _commitment: &MusubiArchiveCommitmentV1,
        _plan: &CarBuildPlan,
        _car: &[u8],
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        if binding.seed_provider != self.provider
            || *self.calls.lock().expect("seed call counter") == 0
        {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum TestSigningBehavior {
    Correct,
    WrongPayload,
    WrongController,
    DuplicateApproval,
    RetryableFailure,
}
struct TestReceiptSigningProvider {
    broker: AccountId,
    key_pair: KeyPair,
    behavior: TestSigningBehavior,
    observed_payloads: Arc<Mutex<Vec<MusubiSeedIngressReceiptPayloadV1>>>,
    clock_after_signing: Option<(Arc<AtomicU64>, u64)>,
}
impl TestReceiptSigningProvider {
    fn new(
        broker: AccountId,
        key_pair: KeyPair,
        behavior: TestSigningBehavior,
    ) -> (Self, Arc<Mutex<Vec<MusubiSeedIngressReceiptPayloadV1>>>) {
        let observed_payloads = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                broker,
                key_pair,
                behavior,
                observed_payloads: Arc::clone(&observed_payloads),
                clock_after_signing: None,
            },
            observed_payloads,
        )
    }
    fn with_clock_after_signing(mut self, clock: Arc<AtomicU64>, current_time_ms: u64) -> Self {
        self.clock_after_signing = Some((clock, current_time_ms));
        self
    }
}
impl MusubiSeedIngressReceiptSigningProviderV1 for TestReceiptSigningProvider {
    fn broker(&self) -> &AccountId {
        &self.broker
    }
    fn sign_approvals(
        &mut self,
        payload: &MusubiSeedIngressReceiptPayloadV1,
    ) -> Result<Vec<MusubiSeedIngressReceiptApprovalV1>, MusubiPublicationServiceBackendErrorV1>
    {
        self.observed_payloads
            .lock()
            .expect("signing payload observations")
            .push(payload.clone());
        if matches!(self.behavior, TestSigningBehavior::RetryableFailure) {
            return Err(MusubiPublicationServiceBackendErrorV1::Retryable);
        }
        let mut signed_payload = payload.clone();
        if matches!(self.behavior, TestSigningBehavior::WrongPayload) {
            signed_payload.expires_at_ms = signed_payload.expires_at_ms.saturating_add(1);
        }
        let approval = if matches!(self.behavior, TestSigningBehavior::WrongController) {
            let attacker = KeyPair::try_from_seed(
                b"musubi-publication-signing-provider-attacker".to_vec(),
                Algorithm::Ed25519,
            )
            .expect("attacker signing key");
            MusubiSeedIngressReceiptApprovalV1 {
                public_key: attacker.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    attacker.private_key(),
                    signed_payload.signing_hash(),
                )
                .expect("attacker receipt signature"),
            }
        } else {
            MusubiSeedIngressReceiptApprovalV1 {
                public_key: self.key_pair.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    self.key_pair.private_key(),
                    signed_payload.signing_hash(),
                )
                .expect("test receipt signature"),
            }
        };
        let approvals = if matches!(self.behavior, TestSigningBehavior::DuplicateApproval) {
            vec![approval.clone(), approval]
        } else {
            vec![approval]
        };
        if let Some((clock, current_time_ms)) = &self.clock_after_signing {
            clock.store(*current_time_ms, Ordering::SeqCst);
        }
        Ok(approvals)
    }
}
#[derive(Clone, Copy)]
enum ThresholdSigningBehavior {
    Correct,
    BelowThreshold,
    Empty,
    Unsorted,
    OverApprovalBound,
}
struct ThresholdReceiptSigningProvider {
    broker: AccountId,
    key_pairs: Vec<KeyPair>,
    behavior: ThresholdSigningBehavior,
}
impl MusubiSeedIngressReceiptSigningProviderV1 for ThresholdReceiptSigningProvider {
    fn broker(&self) -> &AccountId {
        &self.broker
    }
    fn sign_approvals(
        &mut self,
        payload: &MusubiSeedIngressReceiptPayloadV1,
    ) -> Result<Vec<MusubiSeedIngressReceiptApprovalV1>, MusubiPublicationServiceBackendErrorV1>
    {
        let signing_hash = payload.signing_hash();
        let mut approvals: Vec<_> = self
            .key_pairs
            .iter()
            .map(|key_pair| MusubiSeedIngressReceiptApprovalV1 {
                public_key: key_pair.public_key().clone(),
                signature: SignatureOf::try_from_hash(key_pair.private_key(), signing_hash)
                    .expect("threshold test signature"),
            })
            .collect();
        approvals.sort_by(|left, right| left.public_key.cmp(&right.public_key));
        match self.behavior {
            ThresholdSigningBehavior::Correct => approvals.truncate(2),
            ThresholdSigningBehavior::BelowThreshold => approvals.truncate(1),
            ThresholdSigningBehavior::Empty => approvals.clear(),
            ThresholdSigningBehavior::Unsorted => approvals.reverse(),
            ThresholdSigningBehavior::OverApprovalBound => {}
        }
        Ok(approvals)
    }
}
#[derive(Clone, Copy)]
enum ThresholdAuthorizationSigningBehavior {
    Correct,
    BelowThreshold,
    Duplicate,
    Unsorted,
    OverApprovalBound,
    WrongPayload,
    RetryableFailure,
    PermanentFailure,
}
struct ThresholdAuthorizationSigningProvider {
    publisher: AccountId,
    key_pairs: Vec<KeyPair>,
    behavior: ThresholdAuthorizationSigningBehavior,
}
impl MusubiPublicationRuntimeAuthorizationSigningProviderV1
    for ThresholdAuthorizationSigningProvider
{
    fn publisher(&self) -> &AccountId {
        &self.publisher
    }
    fn sign_approvals(
        &self,
        payload: &MusubiPublicationRuntimeAuthorizationPayloadV1,
    ) -> Result<
        Vec<MusubiPublicationRuntimeAuthorizationApprovalV1>,
        MusubiPublicationRuntimeAuthorizationSigningErrorV1,
    > {
        if matches!(
            self.behavior,
            ThresholdAuthorizationSigningBehavior::RetryableFailure
        ) {
            return Err(MusubiPublicationRuntimeAuthorizationSigningErrorV1::Retryable);
        }
        if matches!(
            self.behavior,
            ThresholdAuthorizationSigningBehavior::PermanentFailure
        ) {
            return Err(MusubiPublicationRuntimeAuthorizationSigningErrorV1::Permanent);
        }
        let mut signed_payload = payload.clone();
        if matches!(
            self.behavior,
            ThresholdAuthorizationSigningBehavior::WrongPayload
        ) {
            signed_payload.expires_at_ms = signed_payload.expires_at_ms.saturating_add(1);
        }
        let signing_hash = HashOf::new(&signed_payload);
        let mut approvals: Vec<_> = self
            .key_pairs
            .iter()
            .map(|key_pair| MusubiPublicationRuntimeAuthorizationApprovalV1 {
                public_key: key_pair.public_key().clone(),
                signature: SignatureOf::try_from_hash(key_pair.private_key(), signing_hash)
                    .expect("threshold authorization signature"),
            })
            .collect();
        approvals.sort_by(|left, right| left.public_key.cmp(&right.public_key));
        match self.behavior {
            ThresholdAuthorizationSigningBehavior::Correct
            | ThresholdAuthorizationSigningBehavior::WrongPayload => approvals.truncate(2),
            ThresholdAuthorizationSigningBehavior::BelowThreshold => approvals.truncate(1),
            ThresholdAuthorizationSigningBehavior::Duplicate => {
                approvals.truncate(1);
                approvals.push(approvals[0].clone());
            }
            ThresholdAuthorizationSigningBehavior::Unsorted => approvals.reverse(),
            ThresholdAuthorizationSigningBehavior::OverApprovalBound => {}
            ThresholdAuthorizationSigningBehavior::RetryableFailure => {
                return Err(MusubiPublicationRuntimeAuthorizationSigningErrorV1::Retryable);
            }
            ThresholdAuthorizationSigningBehavior::PermanentFailure => {
                return Err(MusubiPublicationRuntimeAuthorizationSigningErrorV1::Permanent);
            }
        }
        Ok(approvals)
    }
}
struct ConflictJournal {
    binding: MusubiPublicationServiceJournalBindingV1,
}
impl MusubiPublicationServiceJournalV1 for ConflictJournal {
    fn deployment_binding(&self) -> &MusubiPublicationServiceJournalBindingV1 {
        &self.binding
    }
    fn begin(
        &mut self,
        _attempt: &MusubiPublicationJournalAttemptV1,
        _current_time_ms: u64,
    ) -> Result<MusubiPublicationJournalBeginV1, MusubiPublicationServiceJournalErrorV1> {
        Err(MusubiPublicationServiceJournalErrorV1::Unavailable)
    }
    fn refresh_expired_seed_receipt(
        &mut self,
        _attempt: &MusubiPublicationJournalAttemptV1,
        _expected_response: &[u8],
        _current_time_ms: u64,
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        Err(MusubiPublicationServiceJournalErrorV1::Unavailable)
    }
    fn commit(
        &mut self,
        _key: MusubiPublicationIdempotencyKeyV1,
        _request_digest: [u8; 32],
        _response: &[u8],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        Err(MusubiPublicationServiceJournalErrorV1::Conflict)
    }
    fn abort(
        &mut self,
        _key: MusubiPublicationIdempotencyKeyV1,
        _request_digest: [u8; 32],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        Err(MusubiPublicationServiceJournalErrorV1::Conflict)
    }
}
struct CommitCapacityJournal {
    binding: MusubiPublicationServiceJournalBindingV1,
    aborts: Arc<Mutex<usize>>,
}
impl MusubiPublicationServiceJournalV1 for CommitCapacityJournal {
    fn deployment_binding(&self) -> &MusubiPublicationServiceJournalBindingV1 {
        &self.binding
    }
    fn begin(
        &mut self,
        _attempt: &MusubiPublicationJournalAttemptV1,
        _current_time_ms: u64,
    ) -> Result<MusubiPublicationJournalBeginV1, MusubiPublicationServiceJournalErrorV1> {
        Err(MusubiPublicationServiceJournalErrorV1::Unavailable)
    }
    fn refresh_expired_seed_receipt(
        &mut self,
        _attempt: &MusubiPublicationJournalAttemptV1,
        _expected_response: &[u8],
        _current_time_ms: u64,
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        Err(MusubiPublicationServiceJournalErrorV1::Unavailable)
    }
    fn commit(
        &mut self,
        _key: MusubiPublicationIdempotencyKeyV1,
        _request_digest: [u8; 32],
        _response: &[u8],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        Err(MusubiPublicationServiceJournalErrorV1::Capacity)
    }
    fn abort(
        &mut self,
        _key: MusubiPublicationIdempotencyKeyV1,
        _request_digest: [u8; 32],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        *self.aborts.lock().expect("abort counter") += 1;
        Ok(())
    }
}
#[test]
fn seed_ingress_commit_and_abort_conflicts_are_deadletters_without_double_annotation() {
    let mut fixture = private_service_fixture(false);
    fixture.service.journal = Box::new(ConflictJournal {
        binding: MusubiPublicationServiceJournalBindingV1::from_configuration(
            &fixture.service.config,
        ),
    });
    let key = MusubiPublicationIdempotencyKeyV1 {
        operation: MusubiPublicationRuntimeOperationV1::SeedIngress,
        operation_id: fixture.request.operation_id,
        target: [0; 32],
    };
    let commit_error = fixture
        .service
        .finish_attempt(key, [0x71; 32], Ok(vec![0x01]))
        .expect_err("commit conflict");
    assert_eq!(
        commit_error.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(
            MusubiIngestDeadletterReasonV1::ReceiptReplay,
        ))
    );
    let abort_error = fixture
        .service
        .finish_attempt(
            key,
            [0x72; 32],
            Err(MusubiPublicationServiceErrorV1::retryable(
                MusubiPublicationServiceErrorCodeV1::SeedIngressUnavailable,
            )),
        )
        .expect_err("abort conflict");
    assert_eq!(
        abort_error.telemetry,
        Some(MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(
            MusubiIngestDeadletterReasonV1::ReceiptReplay,
        ))
    );
    let already_annotated = fixture
        .service
        .finish_attempt(
            key,
            [0x73; 32],
            Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
            )
            .integrity_failure(MusubiIntegritySurfaceV1::ArchiveCommitment)),
        )
        .expect_err("abort conflict after annotated failure");
    assert_eq!(already_annotated.telemetry, None);
}
#[test]
fn commit_capacity_releases_the_attempt_before_returning_unavailable() {
    let mut fixture = private_service_fixture(false);
    let aborts = Arc::new(Mutex::new(0));
    fixture.service.journal = Box::new(CommitCapacityJournal {
        binding: MusubiPublicationServiceJournalBindingV1::from_configuration(
            &fixture.service.config,
        ),
        aborts: Arc::clone(&aborts),
    });
    let error = fixture
        .service
        .finish_attempt(
            MusubiPublicationIdempotencyKeyV1 {
                operation: MusubiPublicationRuntimeOperationV1::SeedIngress,
                operation_id: fixture.request.operation_id,
                target: [0; 32],
            },
            [0x74; 32],
            Ok(vec![0x01]),
        )
        .expect_err("commit capacity is fail-closed");
    assert_eq!(
        error.code,
        MusubiPublicationServiceErrorCodeV1::JournalUnavailable
    );
    assert!(error.retryable);
    assert_eq!(error.telemetry, None);
    assert_eq!(*aborts.lock().expect("abort counter"), 1);
}
struct UnusedStorage;
impl MusubiStorageCoordinationBackendV1 for UnusedStorage {
    fn verify_current_registration(
        &self,
        _request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        Err(MusubiPublicationServiceBackendErrorV1::Permanent)
    }

    fn coordinate_storage(
        &mut self,
        _request: &VerifiedStorageCoordinationRequestV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1> {
        Err(MusubiPublicationServiceBackendErrorV1::Permanent)
    }
}
struct UnusedReadback;
impl MusubiProviderReadbackBackendV1 for UnusedReadback {
    fn verify_current_target(
        &self,
        _request: &MusubiProviderReadbackRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        Err(MusubiPublicationServiceBackendErrorV1::Permanent)
    }
    fn readback_provider(
        &mut self,
        _request: &MusubiProviderReadbackRequestV1,
    ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1> {
        Err(MusubiPublicationServiceBackendErrorV1::Permanent)
    }
}
struct FixedStorage {
    response: MusubiStorageCoordinationResponseV1,
    substitute: bool,
}
impl MusubiStorageCoordinationBackendV1 for FixedStorage {
    fn verify_current_registration(
        &self,
        _request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        Ok(())
    }

    fn coordinate_storage(
        &mut self,
        _request: &VerifiedStorageCoordinationRequestV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1> {
        let mut response = self.response.clone();
        if self.substitute {
            response.archive.registered_by = AccountId::new(
                KeyPair::try_from_seed(b"musubi-storage-substitution".to_vec(), Algorithm::Ed25519)
                    .expect("substitution key")
                    .public_key()
                    .clone(),
            );
        }
        Ok(response)
    }
}
struct FixedReadback {
    response: MusubiProviderReadbackResponseV1,
    substitute: bool,
}
#[cfg(unix)]
struct RecordingExactReadback {
    calls: Arc<Mutex<Vec<(MusubiArchiveLocationIdV1, u64, ProviderId)>>>,
}
#[cfg(unix)]
impl MusubiProviderReadbackBackendV1 for RecordingExactReadback {
    fn verify_current_target(
        &self,
        _request: &MusubiProviderReadbackRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        Ok(())
    }
    fn readback_provider(
        &mut self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1> {
        self.calls.lock().expect("readback call journal").push((
            request.location.location_id,
            request.location.revision,
            request.provider,
        ));
        Ok(MusubiProviderReadbackResponseV1 {
            version: 1,
            provider: request.provider,
            location_id: request.location.location_id,
            replication_order: request.location.replication_order,
            commitment: request.commitment.clone(),
            semantic_release_digest: request.semantic_release_digest,
            verification_lock_digest: request.verification_lock_digest,
        })
    }
}
impl MusubiProviderReadbackBackendV1 for FixedReadback {
    fn verify_current_target(
        &self,
        _request: &MusubiProviderReadbackRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        Ok(())
    }
    fn readback_provider(
        &mut self,
        _request: &MusubiProviderReadbackRequestV1,
    ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1> {
        let mut response = self.response.clone();
        if self.substitute {
            response.provider = ProviderId::new([0xee; 32]);
        }
        Ok(response)
    }
}
struct PrivateServiceFixture {
    service: MusubiPublicationPrivateServiceV1,
    runtime: AuthenticatedMusubiPublicationRuntimeClientV1,
    request: MusubiSeedIngressStageRequestV1,
    metadata: Vec<u8>,
    plan: CarBuildPlan,
    raw_car: Vec<u8>,
    car: Vec<u8>,
    calls: Arc<Mutex<usize>>,
    clock: Arc<AtomicU64>,
}
struct ControlServiceFixture {
    service: MusubiPublicationPrivateServiceV1,
    runtime: AuthenticatedMusubiPublicationRuntimeClientV1,
    storage_request: MusubiStorageCoordinationRequestV1,
    storage_response: MusubiStorageCoordinationResponseV1,
    readback_request: MusubiProviderReadbackRequestV1,
    readback_response: MusubiProviderReadbackResponseV1,
    clock: Arc<AtomicU64>,
}
fn control_commitment() -> MusubiArchiveCommitmentV1 {
    MusubiArchiveCommitmentV1 {
        root_cid: ManifestRootCid::from_blake3_digest([0x91; 32]).expect("root CID"),
        chunker: ChunkerProfileHandle {
            profile_id: 1,
            namespace: "sorafs".to_owned(),
            name: "sf1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1f,
        },
        chunk_plan_digest: MusubiContentDigestV1::new([0x92; 32]),
        por_root: MusubiContentDigestV1::new([0x93; 32]),
        content_length: 1_024,
        car_digest: MusubiContentDigestV1::new([0x94; 32]),
        car_size: 2_048,
        bundle_digest: MusubiContentDigestV1::new([0x95; 32]),
        source_tree_digest: MusubiContentDigestV1::new([0x96; 32]),
        descriptor_digest: MusubiContentDigestV1::new([0x97; 32]),
        file_count: 2,
        chunk_count: 4,
    }
}
fn control_service_fixture(
    substitute_storage: bool,
    substitute_readback: bool,
) -> ControlServiceFixture {
    let (client, _) = client();
    let runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &client,
        Duration::from_secs(5),
    )
    .expect("runtime client");
    let broker_key = KeyPair::try_from_seed(
        b"musubi-publication-control-broker".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("broker key");
    let broker = AccountId::new(broker_key.public_key().clone());
    let network_id = *client.network_id();
    let commitment = control_commitment();
    let semantic_release_digest = MusubiSemanticReleaseDigestV1::new([0x9a; 32]);
    let verification_lock_digest = MusubiVerificationLockDigestV1::new([0x9b; 32]);
    let replication_order = ReplicationOrderId::new([0x1e; 32]);
    let provider_attestations = (0_u16..MUSUBI_MIN_HEALTHY_REPLICAS_V1)
        .map(|index| {
            let index = u8::try_from(index).expect("replica bound fits u8");
            let provider_key = KeyPair::try_from_seed(vec![0xb0 + index; 32], Algorithm::Ed25519)
                .expect("provider key");
            let provider_owner = AccountId::new(provider_key.public_key().clone());
            let provider_binding = MusubiProviderBundleVerificationBindingV1 {
                network_id,
                provider_id: ProviderId::new([0xb8 + index; 32]),
                completed_by: provider_owner.clone(),
                completion_authority: ProviderIngestCompletionAuthorityV1::new(
                    provider_owner.clone(),
                    provider_owner,
                    ProviderIngestCompletionSignerPolicyV1 {
                        policy_id: [0xc0 + index; 32],
                        revision: 1,
                        predecessor_digest: None,
                        policy_digest: [0xc8 + index; 32],
                    },
                ),
                replication_order,
                assignment_revision: 1,
                completion_epoch: 12,
                finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                    height: 60,
                    block_hash: [0xd0 + index; 32],
                },
                archive_id: commitment.archive_id(),
                bundle_digest: commitment.bundle_digest,
                descriptor_digest: commitment.descriptor_digest,
                semantic_release_manifest_digest: semantic_release_digest,
                verification_lock_digest,
                source_tree_digest: commitment.source_tree_digest,
            };
            let provider_payload = MusubiProviderBundleVerificationPayloadV1 {
                version: 1,
                binding: provider_binding,
            };
            MusubiProviderBundleVerificationAttestationV1 {
                approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
                    public_key: provider_key.public_key().clone(),
                    signature: SignatureOf::try_from_hash(
                        provider_key.private_key(),
                        provider_payload.signing_hash(),
                    )
                    .expect("provider signature"),
                }],
                payload: provider_payload,
            }
        })
        .collect::<Vec<_>>();
    let provider = provider_attestations[0].payload.binding.provider_id;
    let provider_attestation_references = provider_attestations
        .iter()
        .map(MusubiProviderBundleVerificationAttestationV1::reference)
        .collect::<Vec<_>>();
    let provider_attestation_set_digest = musubi_provider_bundle_attestation_set_digest_v1(
        commitment.archive_id(),
        replication_order,
        &provider_attestation_references,
    )
    .expect("canonical provider attestation set");
    let binding = MusubiSeedIngressReceiptBindingV1 {
        network_id,
        publisher: client.account().clone(),
        ingress_broker: broker.clone(),
        seed_provider: provider,
        semantic_release_manifest_digest: semantic_release_digest,
        archive_id: commitment.archive_id(),
        car_body_digest: commitment.car_digest,
        car_body_length: commitment.car_size,
        nonce: [0x9c; 32],
    };
    let receipt_payload = MusubiSeedIngressReceiptPayloadV1 {
        version: 1,
        binding,
        issued_at_ms: 1_000,
        expires_at_ms: 120_000,
    };
    let receipt = MusubiSeedIngressReceiptV1 {
        approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
            public_key: broker_key.public_key().clone(),
            signature: SignatureOf::try_from_hash(
                broker_key.private_key(),
                receipt_payload.signing_hash(),
            )
            .expect("receipt signature"),
        }],
        payload: receipt_payload,
    };
    let operation_id = [0x9d; 32];
    let location_id = MusubiArchiveLocationIdV1::new([0x9f; 32]);
    let pin_manifest = ManifestDigest::new([0xa0; 32]);
    let archive = MusubiArchiveRecordV1 {
        archive_id: commitment.archive_id(),
        commitment: commitment.clone(),
        staging_receipt: receipt,
        registered_by: client.account().clone(),
        registered_at_height: 50,
        location_revision: 1,
        location_ids: Vec::new(),
    };
    let storage_request = MusubiStorageCoordinationRequestV1 {
        version: 1,
        operation_id,
        generation: 1,
        prior_location_ids: Vec::new(),
        network_id,
        publisher: client.account().clone(),
        commitment: commitment.clone(),
        verification_lock_digest,
        staging_receipt: archive.staging_receipt.clone(),
        expected_policy_revision: 7,
        finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1 {
            version: 1,
            network_id,
            transaction_hash: [0xa4; 32],
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: 55,
                finalized_block_hash: [0xa5; 32],
                index_revision: 2,
            },
            registration: archive.registration_projection(),
        },
    };
    let storage_response = MusubiStorageCoordinationResponseV1 {
        version: 1,
        request_digest: storage_request.canonical_request_digest().unwrap(),
        archive,
        location_id,
        pin_manifest,
        replication_order,
        renew_after_epoch: 10,
        expires_at_epoch: 20,
        disposition: MusubiStorageLocationDispositionV1::NeedsRegistration {
            completed_providers: provider_attestations
                .iter()
                .map(|a| a.key().provider_id)
                .collect(),
            expected_location_revision: 1,
        },
    };
    let location = MusubiArchiveLocationV1 {
        location_id,
        archive_id: commitment.archive_id(),
        pin_manifest,
        replication_order,
        providers: provider_attestations
            .iter()
            .map(|attestation| attestation.payload.binding.provider_id)
            .collect(),
        provider_attestation_set_digest,
        renew_after_epoch: 10,
        expires_at_epoch: 20,
        finalized_height: 70,
        revision: 1,
        state: MusubiArchiveLocationStateV1::Healthy,
    };
    let readback_request = MusubiProviderReadbackRequestV1 {
        version: 1,
        operation_id,
        network_id,
        publisher: client.account().clone(),
        expected_policy_revision: storage_request.expected_policy_revision,
        finalized_registration: storage_request.finalized_registration.clone(),
        location,
        provider,
        commitment: commitment.clone(),
        semantic_release_digest,
        verification_lock_digest,
    };
    let readback_response = MusubiProviderReadbackResponseV1 {
        version: 1,
        provider,
        location_id,
        replication_order,
        commitment,
        semantic_release_digest,
        verification_lock_digest,
    };
    storage_request.validate().expect("storage request");
    storage_response
        .validate_for(&storage_request)
        .expect("storage response");
    readback_request.validate().expect("readback request");
    readback_response
        .validate_for(&readback_request)
        .expect("readback response");
    let config = MusubiPublicationServiceConfigurationV1 {
        network_id,
        ingress_broker: broker.clone(),
        seed_provider: provider,
        max_future_clock_skew_ms: 2_000,
        receipt_lifetime_ms: 60_000,
    };
    let journal_binding = MusubiPublicationServiceJournalBindingV1::from_configuration(&config);
    let signer =
        SoftwareMusubiSeedIngressReceiptSignerV1::new(broker, broker_key).expect("receipt signer");
    let (clock_adapter, clock) = TestPublicationClock::new(1);
    let service = MusubiPublicationPrivateServiceV1::new(
        config,
        Box::new(clock_adapter),
        Box::new(signer),
        Box::new(
            InMemoryMusubiPublicationServiceJournalV1::new(journal_binding, 16, 32)
                .expect("bounded journal"),
        ),
        Box::new(RecordingSeedIngress {
            provider,
            calls: Arc::new(Mutex::new(0)),
            fail_first: false,
            clock_after_stage: None,
        }),
        Box::new(FixedStorage {
            response: storage_response.clone(),
            substitute: substitute_storage,
        }),
        Box::new(FixedReadback {
            response: readback_response.clone(),
            substitute: substitute_readback,
        }),
    )
    .expect("control service");
    ControlServiceFixture {
        service,
        runtime,
        storage_request,
        storage_response,
        readback_request,
        readback_response,
        clock,
    }
}
#[test]
fn readback_request_rejects_substituted_finalized_registration_fields() {
    let fixture = control_service_fixture(false, false);
    let mut substituted = fixture.readback_request.clone();
    substituted.expected_policy_revision = 0;
    assert!(substituted.validate().is_err());
    substituted = fixture.readback_request.clone();
    substituted
        .finalized_registration
        .registration
        .registered_by = substituted
        .finalized_registration
        .registration
        .staging_receipt
        .payload
        .binding
        .ingress_broker
        .clone();
    assert!(substituted.validate().is_err());
    substituted = fixture.readback_request.clone();
    substituted.semantic_release_digest = MusubiSemanticReleaseDigestV1::new([0x73; 32]);
    assert!(substituted.validate().is_err());
    substituted = fixture.readback_request.clone();
    substituted.location.finalized_height = 1;
    assert!(substituted.validate().is_err());
}
fn private_service_fixture(fail_first: bool) -> PrivateServiceFixture {
    let (regressing_client, _) = client();
    let runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_iroha_client(
        &regressing_client,
        Duration::from_secs(5),
    )
    .expect("runtime client");
    let broker_key = KeyPair::try_from_seed(
        b"musubi-publication-runtime-broker-test".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive broker key");
    let broker = AccountId::new(broker_key.public_key().clone());
    let package = MusubiPackageIdV1::new(
        DataSpaceId::new(7),
        MusubiPackageScopeV1::DataspaceRoot,
        "runtime-fixture".parse().expect("fixture package name"),
    );
    let release =
        MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("fixture package version"));
    let verification_lock = MusubiVerificationLockV1 {
        schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
        version: MUSUBI_REGISTRY_VERSION_V1,
        root: release.clone(),
        root_dependencies: Vec::new(),
        nodes: Vec::new(),
    };
    let semantic_release = MusubiSemanticReleaseManifestV1 {
        release,
        edition: MusubiKotodamaEditionV1::V1,
        abi: MusubiAbiBindingV1::new([0x70; 32]).expect("fixture ABI"),
        dependencies: Vec::new(),
        exports: Vec::new(),
        interface_digest: MusubiContentDigestV1::new([0x71; 32]),
        metadata: MusubiReleaseMetadataV1::default(),
        verification_lock_digest: verification_lock.digest(),
    };
    semantic_release
        .validate()
        .expect("fixture semantic release");
    verification_lock
        .validate()
        .expect("fixture verification lock");
    let source_path = "Musubi.toml";
    let source_data = vec![b'm'; 4 * 1024];
    let mut source_material = Vec::new();
    seed_ingress_append_frame(&mut source_material, SOURCE_TREE_DOMAIN_V1)
        .expect("frame fixture source domain");
    source_material.extend_from_slice(&1_u32.to_be_bytes());
    seed_ingress_append_frame(&mut source_material, source_path.as_bytes())
        .expect("frame fixture source path");
    source_material.extend_from_slice(
        &u64::try_from(source_data.len())
            .expect("fixture source length")
            .to_be_bytes(),
    );
    source_material.extend_from_slice(blake3::hash(&source_data).as_bytes());
    let source_tree_digest = seed_ingress_domain_digest(SOURCE_TREE_DOMAIN_V1, &source_material)
        .expect("fixture source-tree digest");
    let artifact_descriptor = MusubiArtifactDescriptorV1::new(
        semantic_release.semantic_digest(),
        source_tree_digest,
        verification_lock.digest(),
        u64::try_from(source_data.len()).expect("fixture source byte count"),
        1,
    )
    .expect("fixture artifact descriptor");
    let semantic_release_bytes = semantic_release.encode();
    let descriptor_bytes = artifact_descriptor.encode();
    let verification_lock_bytes = verification_lock.encode();
    let mut descriptor_material = Vec::new();
    seed_ingress_append_frame(&mut descriptor_material, ARTIFACT_DESCRIPTOR_DOMAIN_V1)
        .expect("frame fixture descriptor domain");
    seed_ingress_append_frame(&mut descriptor_material, &descriptor_bytes)
        .expect("frame fixture descriptor");
    let descriptor_digest =
        seed_ingress_domain_digest(ARTIFACT_DESCRIPTOR_DOMAIN_V1, &descriptor_material)
            .expect("fixture descriptor digest");
    let mut bundle_material = Vec::new();
    for bytes in [
        BUNDLE_DOMAIN_V1,
        semantic_release_bytes.as_slice(),
        descriptor_material.as_slice(),
        source_material.as_slice(),
        verification_lock_bytes.as_slice(),
    ] {
        seed_ingress_append_frame(&mut bundle_material, bytes)
            .expect("frame fixture bundle material");
    }
    let bundle_digest = seed_ingress_domain_digest(BUNDLE_DOMAIN_V1, &bundle_material)
        .expect("fixture bundle digest");
    let entries = vec![
        FileEntry {
            path: vec![source_path.to_owned()],
            data: source_data,
        },
        FileEntry {
            path: BUNDLE_RELEASE_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: semantic_release_bytes,
        },
        FileEntry {
            path: BUNDLE_DESCRIPTOR_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: descriptor_bytes,
        },
        FileEntry {
            path: BUNDLE_VERIFICATION_LOCK_PATH_V1
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: verification_lock_bytes,
        },
    ];
    let (plan, payload) =
        CarBuildPlan::from_files(entries).expect("build canonical seed fixture plan");
    let mut raw_car = Vec::new();
    let stats = CarWriter::new(&plan, &payload)
        .expect("construct canonical seed fixture writer")
        .write_to(&mut raw_car)
        .expect("write canonical seed fixture CAR");
    let descriptor = sorafs_car::chunker_registry::default_descriptor();
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: ManifestRootCid::try_from(stats.root_cids[0].clone())
            .expect("canonical seed fixture root"),
        chunker: ChunkerProfileHandle {
            profile_id: descriptor.id.0,
            namespace: descriptor.namespace.to_owned(),
            name: descriptor.name.to_owned(),
            semver: descriptor.semver.to_owned(),
            multihash_code: descriptor.multihash_code,
        },
        chunk_plan_digest: MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(&plan.chunks)),
        por_root: MusubiContentDigestV1::new(
            compute_por_root(&payload, &plan).expect("seed fixture PoR"),
        ),
        content_length: plan.content_length,
        car_digest: MusubiContentDigestV1::new(*stats.car_archive_digest.as_bytes()),
        car_size: stats.car_size,
        bundle_digest,
        source_tree_digest,
        descriptor_digest,
        file_count: 1,
        chunk_count: u32::try_from(plan.chunks.len()).expect("fixture chunk count fits u32"),
    };
    let witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(&plan, &commitment)
        .expect("canonical seed fixture witness");
    let canonical_plan = witness
        .canonical_bytes()
        .expect("canonical seed fixture plan");
    let car = encode_seed_ingress_body(&canonical_plan, &raw_car)
        .expect("canonical seed fixture envelope");
    let request = MusubiSeedIngressStageRequestV1 {
        version: 1,
        operation_id: [0x61; 32],
        binding: MusubiSeedIngressReceiptBindingV1 {
            network_id: *regressing_client.network_id(),
            publisher: regressing_client.account().clone(),
            ingress_broker: broker.clone(),
            seed_provider: ProviderId::new([0x63; 32]),
            semantic_release_manifest_digest: semantic_release.semantic_digest(),
            archive_id: commitment.archive_id(),
            car_body_digest: commitment.car_digest,
            car_body_length: commitment.car_size,
            nonce: [0x66; 32],
        },
        commitment,
        plan_digest: witness
            .canonical_digest()
            .expect("seed fixture plan digest"),
        plan_length: witness.canonical_len().expect("seed fixture plan length"),
    };
    let metadata = norito::encode_canonical(&request).expect("canonical metadata");
    let calls = Arc::new(Mutex::new(0));
    let config = MusubiPublicationServiceConfigurationV1 {
        network_id: request.binding.network_id,
        ingress_broker: broker.clone(),
        seed_provider: request.binding.seed_provider,
        max_future_clock_skew_ms: 2_000,
        receipt_lifetime_ms: 60_000,
    };
    let journal_binding = MusubiPublicationServiceJournalBindingV1::from_configuration(&config);
    let signer =
        SoftwareMusubiSeedIngressReceiptSignerV1::new(broker, broker_key).expect("receipt signer");
    let (clock_adapter, clock) = TestPublicationClock::new(1);
    let service = MusubiPublicationPrivateServiceV1::new(
        config,
        Box::new(clock_adapter),
        Box::new(signer),
        Box::new(
            InMemoryMusubiPublicationServiceJournalV1::new(journal_binding, 16, 32)
                .expect("bounded journal"),
        ),
        Box::new(RecordingSeedIngress {
            provider: request.binding.seed_provider,
            calls: Arc::clone(&calls),
            fail_first,
            clock_after_stage: None,
        }),
        Box::new(UnusedStorage),
        Box::new(UnusedReadback),
    )
    .expect("private service");
    PrivateServiceFixture {
        service,
        runtime,
        request,
        metadata,
        plan,
        raw_car,
        car,
        calls,
        clock,
    }
}
fn threshold_private_service_fixture(behavior: ThresholdSigningBehavior) -> PrivateServiceFixture {
    let mut fixture = private_service_fixture(false);
    let member_count = if matches!(behavior, ThresholdSigningBehavior::OverApprovalBound) {
        u8::try_from(MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1 + 1)
            .expect("approval bound fits u8")
    } else {
        3
    };
    let key_pairs: Vec<_> = (0_u8..member_count)
        .map(|index| {
            KeyPair::try_from_seed(vec![0xb0_u8.saturating_add(index); 32], Algorithm::Ed25519)
                .expect("derive threshold broker key")
        })
        .collect();
    // Keep the broker identity itself valid; `OverApprovalBound` exercises untrusted signer
    // output by returning every key below, including approvals outside this 2-of-3 controller.
    let members = key_pairs
        .iter()
        .take(3)
        .map(|key_pair| {
            MultisigMember::new(key_pair.public_key().clone(), 1).expect("threshold broker member")
        })
        .collect();
    let broker =
        AccountId::new_multisig(MultisigPolicy::new(2, members).expect("threshold broker policy"));
    fixture.request.binding.ingress_broker = broker.clone();
    fixture.metadata =
        norito::encode_canonical(&fixture.request).expect("threshold stage metadata");
    let config = MusubiPublicationServiceConfigurationV1 {
        network_id: fixture.request.binding.network_id,
        ingress_broker: broker.clone(),
        seed_provider: fixture.request.binding.seed_provider,
        max_future_clock_skew_ms: 2_000,
        receipt_lifetime_ms: 60_000,
    };
    let journal_binding = MusubiPublicationServiceJournalBindingV1::from_configuration(&config);
    let signer = ThresholdReceiptSigningProvider {
        broker,
        key_pairs,
        behavior,
    };
    let (clock_adapter, clock) = TestPublicationClock::new(1);
    let calls = Arc::new(Mutex::new(0));
    fixture.service = MusubiPublicationPrivateServiceV1::new(
        config,
        Box::new(clock_adapter),
        Box::new(signer),
        Box::new(
            InMemoryMusubiPublicationServiceJournalV1::new(journal_binding, 16, 32)
                .expect("bounded journal"),
        ),
        Box::new(RecordingSeedIngress {
            provider: fixture.request.binding.seed_provider,
            calls: Arc::clone(&calls),
            fail_first: false,
            clock_after_stage: None,
        }),
        Box::new(UnusedStorage),
        Box::new(UnusedReadback),
    )
    .expect("threshold private service");
    fixture.clock = clock;
    fixture.calls = calls;
    fixture
}
fn authorization_header(
    runtime: &AuthenticatedMusubiPublicationRuntimeClientV1,
    request: &MusubiSeedIngressStageRequestV1,
    metadata: &[u8],
    issued_at_ms: u64,
) -> String {
    let digest = request_digest(MusubiPublicationRuntimeOperationV1::SeedIngress, metadata)
        .expect("request digest");
    let authorization = runtime
        .authorization_at(
            MusubiPublicationRuntimeOperationV1::SeedIngress,
            request.operation_id,
            digest,
            issued_at_ms,
        )
        .expect("authorization");
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(norito::encode_canonical(&authorization).expect("canonical authorization"))
}
fn control_authorization_header(
    runtime: &AuthenticatedMusubiPublicationRuntimeClientV1,
    operation: MusubiPublicationRuntimeOperationV1,
    operation_id: [u8; 32],
    body: &[u8],
    issued_at_ms: u64,
) -> String {
    let digest = request_digest(operation, body).expect("request digest");
    let authorization = runtime
        .authorization_at(operation, operation_id, digest, issued_at_ms)
        .expect("authorization");
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(norito::encode_canonical(&authorization).expect("canonical authorization"))
}
fn control_storage_response(
    fixture: &mut ControlServiceFixture,
    request: &MusubiStorageCoordinationRequestV1,
    issued_at_ms: u64,
) -> MusubiPublicationPrivateHttpResponseV1 {
    let body = norito::encode_canonical(request).expect("storage request bytes");
    let authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        request.operation_id,
        &body,
        issued_at_ms,
    );
    fixture
        .clock
        .store(issued_at_ms.saturating_add(1), Ordering::SeqCst);
    fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&authorization),
            seed_ingress_metadata: None,
            body: &body,
        })
}
fn control_readback_response(
    fixture: &mut ControlServiceFixture,
    request: &MusubiProviderReadbackRequestV1,
    issued_at_ms: u64,
) -> MusubiPublicationPrivateHttpResponseV1 {
    let body = norito::encode_canonical(request).expect("readback request bytes");
    let authorization = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::ProviderReadback,
        request.operation_id,
        &body,
        issued_at_ms,
    );
    fixture
        .clock
        .store(issued_at_ms.saturating_add(1), Ordering::SeqCst);
    fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1,
            content_type: APPLICATION_NORITO,
            authorization: Some(&authorization),
            seed_ingress_metadata: None,
            body: &body,
        })
}
fn seed_http_response(
    fixture: &mut PrivateServiceFixture,
    authorization: &str,
    metadata: &[u8],
    body: &[u8],
    current_time_ms: u64,
) -> MusubiPublicationPrivateHttpResponseV1 {
    let metadata = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(metadata);
    fixture.clock.store(current_time_ms, Ordering::SeqCst);
    fixture
        .service
        .handle(MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1,
            content_type: APPLICATION_MUSUBI_SEED_ENVELOPE,
            authorization: Some(authorization),
            seed_ingress_metadata: Some(&metadata),
            body,
        })
}
fn decode_service_error(
    response: &MusubiPublicationPrivateHttpResponseV1,
) -> MusubiPublicationServiceErrorResponseV1 {
    norito::decode_canonical_with_limits(&response.body, RESPONSE_DECODE_LIMITS)
        .expect("typed service error")
}
fn client() -> (Client, KeyPair) {
    let key_pair = KeyPair::try_from_seed(
        b"musubi-publication-runtime-client-test".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("derive fixture key");
    let account = AccountId::new(key_pair.public_key().clone());
    let client = Client::builder(Config {
        chain: ChainId::from("musubi-runtime-test"),
        network_id: test_network_id(0xA5),
        account_chain_discriminant: 1,
        http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
        torii_api_url: Url::parse("https://torii.example/").expect("Torii URL"),
        key_pair: key_pair.clone(),
        transaction_ttl: Duration::from_secs(10),
        transaction_status_timeout: Duration::from_secs(5),
        torii_request_timeout: Duration::from_secs(5),
        account,
        basic_auth: None,
        api_token: None,
        transaction_add_nonce: false,
        sorafs_alias_cache: sorafs_manifest::alias_cache::AliasCachePolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::default(),
        sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::default(),
    })
    .build()
    .expect("valid test client configuration");
    (client, key_pair)
}
fn threshold_authorization_runtime(
    behavior: ThresholdAuthorizationSigningBehavior,
) -> AuthenticatedMusubiPublicationRuntimeClientV1 {
    let member_count = if matches!(
        behavior,
        ThresholdAuthorizationSigningBehavior::OverApprovalBound
    ) {
        u8::try_from(MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1 + 1)
            .expect("approval bound fits u8")
    } else {
        3
    };
    let key_pairs: Vec<_> = (0_u8..member_count)
        .map(|index| {
            KeyPair::try_from_seed(vec![index.saturating_add(1); 32], Algorithm::Ed25519)
                .expect("derive threshold publisher key")
        })
        .collect();
    let members = key_pairs
        .iter()
        .map(|key_pair| {
            MultisigMember::new(key_pair.public_key().clone(), 1)
                .expect("threshold publisher member")
        })
        .collect();
    let publisher = AccountId::new_multisig(
        MultisigPolicy::new(2, members).expect("threshold publisher policy"),
    );
    let signer = ThresholdAuthorizationSigningProvider {
        publisher: publisher.clone(),
        key_pairs,
        behavior,
    };
    AuthenticatedMusubiPublicationRuntimeClientV1::from_authorization_signer(
        test_network_id(0x71),
        publisher,
        Arc::new(signer),
        Duration::from_secs(5),
    )
    .expect("threshold runtime client")
}
