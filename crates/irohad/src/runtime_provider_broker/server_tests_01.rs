use super::*;
use iroha_core::query::reputation_finalized as test_reputation_query;
use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
use iroha_data_model::{
    account::AccountId,
    sorafs::pin_registry as test_pin_registry,
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionPayload,
    },
};
use iroha_torii::privacy_issuance_api as test_privacy_issuance;
use iroha_torii::sorafs::{
    gateway as test_gateway, moderation_runtime as test_moderation_runtime, pop_api as test_pop,
};
use sorafs_manifest::reputation::signed as test_reputation_signed;
use sorafs_node::{
    self as node, evidence_viewer::transparency_producer as test_evidence_transparency,
    hedging_billing_service as test_billing, moderation_orchestrator as test_moderation,
    reputation::runtime as test_reputation,
};
use std::{
    io::Cursor,
    os::unix::{
        fs::{PermissionsExt as _, symlink},
        net::UnixListener,
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};
const TEST_SESSION_ID: [u8; 32] = [0xA5; 32];
const TEST_POLICY_DIGEST: [u8; 32] = [0x71; 32];
const TEST_SIGNER_KEY: [u8; 32] = [
    0x15, 0x09, 0xA6, 0x11, 0xAD, 0x6D, 0x97, 0xB0, 0x1D, 0x87, 0x1E, 0x58, 0xED, 0x00, 0xC8, 0xFD,
    0x7C, 0x39, 0x17, 0xB6, 0xCA, 0x61, 0xA8, 0xC2, 0x83, 0x3A, 0x19, 0xE0, 0x00, 0xAA, 0xC2, 0xE4,
];
const SERVER_TEST_SIGNER_HANDLE: &str = "software://sorafs/governance-dag/primary";
const SERVER_TEST_IPFS_AUTH_HANDLE: &str = "auth://sorafs/governance-dag/ipfs-primary";
const SERVER_TEST_CHECKPOINT_HANDLE: &str = "sealed://governance/runtime-broker-checkpoint-primary";
const SERVER_TEST_MODERATION_HANDLE: &str =
    "software://sorafs/moderation/quarantine-wrapper-primary";
const SERVER_TEST_MODERATION_TRANSACTION_SIGNER_HANDLE: &str =
    "software://sorafs/moderation/primary";
const SERVER_TEST_APPEAL_FINANCE_SIGNER_HANDLE: &str = "software://sorafs/appeal-finance/primary";
const SERVER_TEST_MODERATION_SETTLEMENT_HANDLE: &str =
    "queue://moderation/settlement-handoff-primary";
const SERVER_TEST_MODERATION_PUBLICATION_HANDLE: &str =
    "queue://moderation/publication-handoff-primary";
const SERVER_TEST_MODERATION_PANEL_HANDLE: &str = "queue://moderation/panel-notification-primary";
const SERVER_TEST_MODERATION_KEY_ID: &str = "software://sorafs/moderation/quarantine-key-primary";
const SERVER_TEST_SOURCE_HANDLE: &str = "network://sorafs/provider-ingest/source-primary";
const SERVER_TEST_REPUTATION_RETENTION_HANDLE: &str =
    "sealed://sorafs/reputation/retention-primary";
const SERVER_TEST_SOURCE_PROVIDER_IDS: [[u8; 32]; 2] = [[0x11; 32], [0x22; 32]];
const SERVER_TEST_POP_HANDLE: &str = "runtime://sorafs/pop/provider-registry-primary";
const SERVER_TEST_ACME_HANDLE: &str = "network://sorafs/gateway/acme-primary";
const SERVER_TEST_COMPLIANCE_HANDLE: &str = "network://sorafs/gateway/compliance-primary";
const SERVER_TEST_POR_ARCHIVE_HANDLE: &str = "object-lock://sorafs/por/primary";
const SERVER_TEST_PRIVACY_PRF_HANDLE: &str = "threshold-prf://sorafs/transparency/primary";
const SERVER_TEST_PRIVACY_RELEASE_ANCHOR_HANDLE: &str =
    "governance-dag://sorafs/transparency/release-anchor-primary";
const SERVER_TEST_TRANSPARENCY_LEADER_LEASE_HANDLE: &str =
    "sealed-cas://sorafs/transparency/leader-primary";
const SERVER_TEST_FENCED_PRIVACY_PUBLISHER_HANDLE: &str =
    "governance-cas://sorafs/transparency/privacy-primary";
const SERVER_TEST_REPUTATION_JOURNAL_HANDLE: &str = "queue://sorafs/reputation/journal-primary";
const SERVER_TEST_REPUTATION_THRESHOLD_HANDLE: &str = "software://sorafs/reputation/primary";
const SERVER_TEST_REPUTATION_GOVERNANCE_HANDLE: &str =
    "dag://sorafs/reputation/publication-primary";
const SERVER_TEST_REPUTATION_CHECKPOINT_HANDLE: &str =
    "sealed://sorafs/reputation/journal-checkpoint-primary";
const SERVER_TEST_BILLING_QUERY_HANDLE: &str = "ledger://sorafs/billing/finalized-query-primary";
const SERVER_TEST_BILLING_VERIFIER_HANDLE: &str =
    "ledger://sorafs/billing/journal-verifier-primary";
const SERVER_TEST_BILLING_SIGNER_HANDLE: &str = "software://sorafs/billing/primary";
const SERVER_TEST_BILLING_PUBLISHER_HANDLE: &str =
    "immutable://sorafs/billing/statement-publisher-primary";
const SERVER_TEST_BILLING_ACKNOWLEDGEMENT_HANDLE: &str =
    "authority://sorafs/billing/acknowledgement-primary";
const SERVER_TEST_BILLING_EPOCH_STORE_HANDLE: &str =
    "sealed-cas://sorafs/billing/epoch-witness-primary";
const SERVER_TEST_EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE: &str =
    "transparency://sorafs/evidence-viewer/publisher-primary";
const SERVER_TEST_BOOTLE_LANTERN_HANDLE: &str = "runtime://sorafs/privacy/bootle-lantern-primary";
fn network_id_from(byte: u8) -> NetworkId {
    NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([byte; Hash::LENGTH]),
        ),
    )
}
fn network_id() -> NetworkId {
    network_id_from(0x15)
}
struct ServerTestBootleLanternBackend {
    revision: AtomicU64,
    unavailable: AtomicBool,
    drift_after_authenticate: AtomicBool,
    bindings: test_privacy_issuance::BootleLanternIssuanceRuntimeProviderBindingsV1,
}
impl ServerTestBootleLanternBackend {
    fn new(
        bindings: test_privacy_issuance::BootleLanternIssuanceRuntimeProviderBindingsV1,
    ) -> Self {
        Self {
            revision: AtomicU64::new(7),
            unavailable: AtomicBool::new(false),
            drift_after_authenticate: AtomicBool::new(false),
            bindings,
        }
    }
}
impl crate::runtime_provider_broker::BootleLanternIssuanceBrokerBackendV1
    for ServerTestBootleLanternBackend
{
    fn handle(&self) -> &str {
        SERVER_TEST_BOOTLE_LANTERN_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<
        test_privacy_issuance::BootleLanternIssuanceRuntimeProviderQualificationV1,
        test_privacy_issuance::BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
    > {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(test_privacy_issuance::
                BootleLanternIssuanceRuntimeProviderRegistryErrorV1::Unavailable);
        }
        Ok(
            test_privacy_issuance::BootleLanternIssuanceRuntimeProviderQualificationV1::new(
                self.revision.load(Ordering::Acquire),
                TEST_POLICY_DIGEST,
            ),
        )
    }
    fn bindings(
        &self,
    ) -> Result<
        test_privacy_issuance::BootleLanternIssuanceRuntimeProviderBindingsV1,
        test_privacy_issuance::BootleLanternIssuanceRuntimeProviderRegistryErrorV1,
    > {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(test_privacy_issuance::
                BootleLanternIssuanceRuntimeProviderRegistryErrorV1::Unavailable);
        }
        Ok(self.bindings)
    }
    fn authenticate(
        &self,
        opaque_credential: &[u8],
        _: test_privacy_issuance::BootleLanternIssuanceActionV1,
        _: [u8; 32],
        committed_height: u64,
    ) -> Result<
        test_privacy_issuance::BootleLanternIssuanceAuthenticatedPrincipalV1,
        test_privacy_issuance::BootleLanternIssuanceAuthenticationErrorV1,
    > {
        if opaque_credential.first() == Some(&0) {
            return Err(test_privacy_issuance::BootleLanternIssuanceAuthenticationErrorV1::Denied);
        }
        if opaque_credential.first() == Some(&u8::MAX) {
            return Err(
                test_privacy_issuance::BootleLanternIssuanceAuthenticationErrorV1::Unavailable,
            );
        }
        let expires_at_height = committed_height.checked_add(4).ok_or(
            test_privacy_issuance::BootleLanternIssuanceAuthenticationErrorV1::Unavailable,
        )?;
        if self.drift_after_authenticate.load(Ordering::Acquire) {
            self.revision.store(8, Ordering::Release);
        }
        Ok(
            test_privacy_issuance::BootleLanternIssuanceAuthenticatedPrincipalV1 {
                principal_digest: [0x95; 32],
                issued_at_height: committed_height,
                expires_at_height,
            },
        )
    }
    fn prepare_authorization(
        &self,
        _: &iroha_data_model::privacy::PrivacyStatementContextV1,
        _: [u8; 32],
        _: &iroha_data_model::privacy::BootleLanternIssuerPolicyV1,
        _: [u8; 32],
        _: u64,
        _: u64,
    ) -> Result<
        iroha_core_privacy::privacy_engines::bootle_lantern::issuer::BootleLanternIssuanceAuthorizationV1,
        crate::runtime_provider_broker::BootleLanternIssuanceBrokerBackendErrorV1,
    >{
        panic!("qualification-only adversarial backend must not issue")
    }
    fn validate_request(
        &self,
        _: &iroha_data_model::privacy::PrivacyStatementContextV1,
        _: [u8; 32],
        _: &iroha_data_model::privacy::BootleLanternIssuerPolicyV1,
        _: &iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
            BootleLanternIssuanceAuthorizationV1,
        _: &[u8],
        _: u64,
    ) -> Result<[u8; 32], crate::runtime_provider_broker::BootleLanternIssuanceBrokerBackendErrorV1>
    {
        panic!("qualification-only adversarial backend must not validate")
    }
    fn issue_validated(
        &self,
        _: &iroha_data_model::privacy::PrivacyStatementContextV1,
        _: [u8; 32],
        _: &iroha_data_model::privacy::BootleLanternIssuerPolicyV1,
        _: &iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
            BootleLanternIssuanceAuthorizationV1,
        _: &[u8],
        _: u64,
    ) -> Result<
        iroha_core_privacy::privacy_engines::bootle_lantern::issuer::BootleLanternBlindIssuanceResponseV1,
        crate::runtime_provider_broker::BootleLanternIssuanceBrokerBackendErrorV1,
    >{
        panic!("qualification-only adversarial backend must not issue")
    }
}
#[derive(Debug, Default)]
struct ServerTestEvidenceTransparencyPublisher {
    compare_calls: AtomicU64,
}
impl node::evidence_viewer::EvidenceViewerRuntimeProviderV1
    for ServerTestEvidenceTransparencyPublisher
{
    fn handle(&self) -> &str {
        SERVER_TEST_EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<
        node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1,
        node::evidence_viewer::EvidenceViewerRuntimeProviderReadinessErrorV1,
    > {
        Ok(
            node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1::new(
                7,
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_evidence_transparency::EvidenceViewerTransparencyPublisherV1
    for ServerTestEvidenceTransparencyPublisher
{
    fn public_key(&self) -> [u8; 32] {
        TEST_SIGNER_KEY
    }
    fn load_head(
        &self,
    ) -> Result<
        Option<test_evidence_transparency::EvidenceViewerSignedTransparencyHeadV1>,
        test_evidence_transparency::EvidenceViewerTransparencyPublisherExternalErrorV1,
    > {
        Ok(None)
    }
    fn compare_and_publish(
        &self,
        _body: &test_evidence_transparency::EvidenceViewerTransparencyHeadBodyV1,
    ) -> Result<(), test_evidence_transparency::EvidenceViewerTransparencyPublisherExternalErrorV1>
    {
        self.compare_calls.fetch_add(1, Ordering::AcqRel);
        Err(
            test_evidence_transparency::
                EvidenceViewerTransparencyPublisherExternalErrorV1::Ambiguous,
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::platform::tests::NestedDecodeBudgetProbeV1"
)]
struct NestedDecodeBudgetProbeV1 {
    first: Vec<u8>,
    second: Vec<u8>,
}
#[test]
fn decode_policies_are_explicit_and_cover_supported_operation_frames() {
    let tiny = decode_resource_budget(1, MAX_OPERATION_FRAME_BYTES_V1, STANDARD_DECODE_POLICY_V1)
        .expect("derive tiny fixed-headroom budget");
    assert_eq!(
        tiny.max_total_allocated_bytes,
        1 + STANDARD_DECODE_POLICY_V1.allocation_headroom_bytes
    );
    assert!(
        tiny.max_total_allocated_bytes <= STANDARD_DECODE_POLICY_V1.max_total_allocated_bytes,
        "wire length may reduce, but never amplify, an audited cap"
    );
    for operation in 0..=u16::MAX {
        if !operation_is_known(operation) {
            continue;
        }
        let limit = operation_frame_limit(operation);
        let policy = operation_decode_policy(operation);
        assert!(limit <= MAX_OPERATION_FRAME_BYTES_V1);
        if matches!(
            operation,
            OPERATION_APPEAL_FINANCE_CHECKPOINT_LOAD_V1
                | OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1
        ) {
            assert_eq!(limit, MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1);
            assert!(operation_semantic_frame_limit(operation) > limit);
        } else {
            assert_eq!(
                limit,
                operation_semantic_frame_limit(operation),
                "operation {operation} must expose its full supported protocol frame"
            );
        }
        assert!(
            limit <= policy.max_blob_bytes,
            "operation {operation} frame is unsupported by its decode policy"
        );
        assert!(
            policy.max_composed_bytes <= MAX_BROKER_SHARED_DECODE_BYTES_V1,
            "operation {operation} live peak exceeds the process-wide pool"
        );
        assert!(
            policy.max_cumulative_bytes >= policy.max_composed_bytes,
            "operation {operation} cumulative cap is smaller than its live peak"
        );
        decode_resource_budget(limit, limit, policy).unwrap_or_else(|error| {
            panic!("operation {operation} exact supported frame must budget: {error:?}")
        });
    }
    for (operation, supported_limit, expected_policy) in [
        (
            OPERATION_SIGN_V1,
            MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
            GOVERNANCE_BULK_DECODE_POLICY_V1,
        ),
        (
            OPERATION_SEALED_COMPARE_AND_SWAP_V1,
            MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1,
            GOVERNANCE_SEALED_STATE_DECODE_POLICY_V1,
        ),
        (
            OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1,
            MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1,
            GOVERNANCE_BULK_DECODE_POLICY_V1,
        ),
        (
            OPERATION_APPEAL_FINANCE_CHECKPOINT_COMPARE_AND_SWAP_V1,
            MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1,
            APPEAL_CHECKPOINT_DECODE_POLICY_V1,
        ),
        (
            OPERATION_PROVIDER_INGEST_SIGN_V1,
            MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1,
            PROVIDER_INGEST_SIGN_DECODE_POLICY_V1,
        ),
        (
            OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1,
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
            PROVIDER_INGEST_CHECKPOINT_DECODE_POLICY_V1,
        ),
        (
            OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1,
            MAX_EVIDENCE_VIEWER_CONTROL_FRAME_BYTES_V1,
            OPAQUE_BLOB_DECODE_POLICY_V1,
        ),
        (
            OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1,
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
            EVIDENCE_BULK_DECODE_POLICY_V1,
        ),
        (
            OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1,
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
            EVIDENCE_BULK_DECODE_POLICY_V1,
        ),
        (
            OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1,
            MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
            BILLING_DECODE_POLICY_V1,
        ),
        (
            OPERATION_GATEWAY_COMPLIANCE_FETCH_V1,
            MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1,
            OPAQUE_BLOB_DECODE_POLICY_V1,
        ),
        (
            OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1,
            MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
            SOURCE_PLAN_DECODE_POLICY_V1,
        ),
        (
            OPERATION_REPUTATION_JOURNAL_SUBMIT_V1,
            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
            REPUTATION_DECODE_POLICY_V1,
        ),
    ] {
        assert_eq!(operation_frame_limit(operation), supported_limit);
        assert_eq!(operation_decode_policy(operation), expected_policy);
        assert!(expected_policy.max_blob_bytes >= supported_limit);
        assert!(expected_policy.max_composed_bytes <= MAX_BROKER_SHARED_DECODE_BYTES_V1);
        assert!(expected_policy.max_cumulative_bytes >= expected_policy.max_composed_bytes);
        decode_resource_budget(supported_limit, supported_limit, expected_policy)
            .expect("exact supported wire maximum has a checked budget");
        assert_eq!(
            decode_resource_budget(
                supported_limit
                    .checked_add(1)
                    .expect("test supported maximum increments"),
                supported_limit,
                expected_policy,
            ),
            Err(BrokerError::Protocol),
            "operation {operation} rejects cap + 1 before decode allocation"
        );
    }
    decode_resource_budget(
        MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1,
        MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1,
        SOURCE_PLAN_DECODE_POLICY_V1,
    )
    .expect("exact source-plan maximum has a checked structured budget");
    assert_eq!(
        MAX_BROKER_PROCESS_OPERATION_BYTES_V1,
        MAX_OPERATION_FRAME_BYTES_V1 + MAX_BROKER_SHARED_DECODE_BYTES_V1
    );
    assert!(
        PROVIDER_INGEST_CHECKPOINT_DECODE_POLICY_V1.max_composed_bytes
            >= provider_ingest_checkpoint_external_decode_peak_bytes_v1(),
        "live provider-checkpoint reservation covers the external 4x record decoder"
    );
    assert_eq!(
        validate_sealed_payload_len(
            node::GovernanceDagSealedStateSlot::Checkpoint,
            MAX_GOVERNANCE_SEALED_STATE_PAYLOAD_BYTES_V1,
        ),
        Ok(())
    );
    assert_eq!(
        validate_sealed_payload_len(
            node::GovernanceDagSealedStateSlot::Checkpoint,
            MAX_GOVERNANCE_SEALED_STATE_PAYLOAD_BYTES_V1 + 1,
        ),
        Err(BrokerError::Rejected)
    );
    assert!(u32::try_from(MAX_OPERATION_FRAME_BYTES_V1).is_ok());
    assert!(
        std::hint::black_box(MAX_BROKER_PROCESS_OPERATION_BYTES_V1)
            <= tokio::sync::Semaphore::MAX_PERMITS
    );
    assert_eq!(
        decode_resource_budget(usize::MAX, usize::MAX, BILLING_DECODE_POLICY_V1),
        Err(BrokerError::Protocol),
        "amplification arithmetic must fail closed"
    );
}
#[test]
fn cumulative_admission_rejects_layers_that_individually_fit() {
    let policy = DecodeResourcePolicyV1::new((64, 64), (128, 32), (0, 0), 8, (100, 100));
    let pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let admission = DecodeResourceAdmissionV1::acquire_from(pool, None, policy)
        .expect("acquire compact test admission");
    admission
        .reserve_raw_frame(20, 64)
        .expect("reserve raw frame");
    admission
        .reserve_decode(20, 64)
        .expect("first decoded layer fits");
    admission
        .reserve_decode(20, 64)
        .expect("second decoded layer fits exactly");
    assert_eq!(
        admission.reserve_decode(20, 64),
        Err(BrokerError::Protocol),
        "resetting a per-layer budget must not bypass the aggregate cap"
    );
    assert_eq!(
        decode_resource_budget(65, 64, policy),
        Err(BrokerError::Protocol)
    );
}
fn assert_maximal_profile(
    operation: u16,
    frame_bytes: usize,
    policy: DecodeResourcePolicyV1,
    phases: DecodeResourcePhaseCountsV1,
) {
    assert_eq!(operation_frame_limit(operation), frame_bytes);
    assert_eq!(operation_decode_policy(operation), policy);
    assert!(phase_counts_fit(phases, OPERATION_CUMULATIVE_PHASES_V1));
    let over_limit = frame_bytes
        .checked_add(1)
        .expect("audited frame limit increments");
    assert_eq!(
        decode_resource_budget(over_limit, frame_bytes, policy),
        Err(BrokerError::Protocol),
        "operation {operation} rejects its exact frame limit plus one"
    );
    let decode_budget = decode_resource_budget(frame_bytes, frame_bytes, policy)
        .expect("exact operation frame has a checked decode budget");
    let copy_phases = phases
        .raw_frames
        .checked_add(phases.retained_values)
        .and_then(|count| count.checked_add(phases.encoded_copies))
        .expect("audited copy phase count");
    let exact_cumulative_bytes = frame_bytes
        .checked_mul(copy_phases)
        .and_then(|bytes| {
            decode_budget
                .composed_charge_bytes
                .checked_mul(phases.decoded_values)
                .and_then(|decoded| bytes.checked_add(decoded))
        })
        .expect("audited cumulative phase bytes");
    assert_eq!(
        exact_cumulative_bytes,
        cumulative_decode_cap(frame_bytes, policy.max_total_allocated_bytes, phases,),
        "the exact frame saturates the operation's allocation allowance"
    );
    assert!(exact_cumulative_bytes <= policy.max_cumulative_bytes);
    let exact_policy = DecodeResourcePolicyV1 {
        max_cumulative_bytes: exact_cumulative_bytes,
        ..policy
    };
    let pool = Arc::new(DecodeResourcePoolV1::new(exact_policy.max_composed_bytes));
    let admission = DecodeResourceAdmissionV1::acquire_from(pool, Some(operation), exact_policy)
        .expect("reserve exact-profile live peak");
    for _ in 0..phases.raw_frames {
        admission
            .reserve_raw_frame(frame_bytes, frame_bytes)
            .expect("reserve maximal raw frame phase");
    }
    for _ in 0..phases.retained_values {
        admission
            .reserve_retained_bytes(frame_bytes, frame_bytes)
            .expect("reserve maximal retained phase");
    }
    for _ in 0..phases.encoded_copies {
        admission
            .reserve_encoded_copy(frame_bytes, frame_bytes)
            .expect("reserve maximal canonical encode phase");
    }
    for _ in 0..phases.decoded_values {
        admission
            .reserve_decode(frame_bytes, frame_bytes)
            .expect("reserve maximal decode and canonical-reencode phase");
    }
    assert_eq!(
        admission
            .usage
            .lock()
            .expect("phase usage lock")
            .consumed_bytes,
        exact_cumulative_bytes
    );
    assert_eq!(
        admission.reserve_encoded_copy(1, frame_bytes),
        Err(BrokerError::Protocol),
        "the audited profile's exact cumulative boundary rejects one extra byte"
    );
}
#[test]
fn billing_publish_deepest_phase_profile_fits_exact_limit_without_allocation() {
    assert_eq!(BILLING_PUBLISH_DEEPEST_PHASES_V1.encoded_copies, 12);
    assert_eq!(BILLING_PUBLISH_DEEPEST_PHASES_V1.decoded_values, 6);
    assert_maximal_profile(
        OPERATION_BILLING_PUBLISH_STATEMENT_V1,
        MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        BILLING_DECODE_POLICY_V1,
        BILLING_PUBLISH_DEEPEST_PHASES_V1,
    );
}
#[test]
fn reputation_threshold_deepest_phase_profile_fits_exact_limit_without_allocation() {
    assert_eq!(REPUTATION_THRESHOLD_DEEPEST_PHASES_V1.encoded_copies, 9);
    assert_eq!(REPUTATION_THRESHOLD_DEEPEST_PHASES_V1.decoded_values, 6);
    assert_maximal_profile(
        OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1,
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        REPUTATION_DECODE_POLICY_V1,
        REPUTATION_THRESHOLD_DEEPEST_PHASES_V1,
    );
}
#[test]
fn provider_checkpoint_maximal_phase_sequence_fits_without_allocation() {
    let policy = PROVIDER_INGEST_CHECKPOINT_DECODE_POLICY_V1;
    let frame_bytes = MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1;
    let pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let admission = DecodeResourceAdmissionV1::acquire_from(
        pool,
        Some(OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1),
        policy,
    )
    .expect("reserve provider-checkpoint live peak");
    admission
        .reserve_raw_frame(frame_bytes, frame_bytes)
        .expect("reserve maximal raw frame");
    for _ in 0..OPERATION_CUMULATIVE_PHASES_V1.retained_values {
        admission
            .reserve_retained_bytes(frame_bytes, frame_bytes)
            .expect("reserve maximal retained phase");
    }
    for _ in 0..OPERATION_CUMULATIVE_PHASES_V1.encoded_copies {
        admission
            .reserve_encoded_copy(frame_bytes, frame_bytes)
            .expect("reserve maximal canonical encode phase");
    }
    for _ in 0..OPERATION_CUMULATIVE_PHASES_V1.decoded_values {
        admission
            .reserve_decode(frame_bytes, frame_bytes)
            .expect("reserve maximal decode and canonical-reencode phase");
    }
    assert_eq!(
        admission
            .usage
            .lock()
            .expect("phase usage lock")
            .consumed_bytes,
        policy.max_cumulative_bytes
    );
    assert_eq!(
        admission.reserve_encoded_copy(1, frame_bytes),
        Err(BrokerError::Protocol),
        "the explicit full-call phase inventory remains a hard cumulative ceiling"
    );
}
#[test]
fn compact_server_sequence_exceeds_live_peak_but_fits_cumulative_cap() {
    let state = prepare_test_server_state(&server_test_catalog(), server_test_backends())
        .expect("prepare governance signer server state");
    let payload = valid_governance_sign_request_payload();
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_SIGN_V1,
        payload,
    )
    .expect("build compact operation request");
    let request_frame = encode_frame(
        FRAME_KIND_OPERATION_REQUEST_V1,
        &request,
        MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
    )
    .expect("encode compact request frame");
    // Deliberately compact maxima keep every concrete SIGN phase
    // admissible while making cumulative and live caps distinct.
    let max_blob = 32_usize * 1024;
    let max_allocation = 32_usize * 1024;
    let max_composed = max_blob
        .checked_add(max_allocation)
        .expect("compact live cap sums");
    let compact_policy = DecodeResourcePolicyV1::new(
        (max_blob, max_blob),
        (128 * 1024, max_allocation),
        (8 * 1024, 16 * 1024),
        32,
        (
            max_composed,
            cumulative_decode_cap(max_blob, max_allocation, OPERATION_CUMULATIVE_PHASES_V1),
        ),
    );
    let pool = Arc::new(DecodeResourcePoolV1::new(compact_policy.max_composed_bytes));
    let admission =
        DecodeResourceAdmissionV1::acquire_from(pool, Some(OPERATION_SIGN_V1), compact_policy)
            .expect("reserve compact live peak");
    admission
        .reserve_raw_frame(request_frame.len(), MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1)
        .expect("reserve compact raw frame");
    let scope = admission.enter();
    let decoded_request = decode_operation_frame::<OperationRequestV1>(
        &request_frame,
        FRAME_KIND_OPERATION_REQUEST_V1,
        OPERATION_SIGN_V1,
    )
    .expect("decode compact request");
    validate_operation_request(&decoded_request).expect("validate compact request");
    let result = dispatch_server_operation(&state, &decoded_request).expect("dispatch request");
    let response =
        make_operation_response_scrubbed(&decoded_request, STATUS_OK_V1, result, &state.network_id)
            .expect("build and validate compact response");
    encode_frame(
        FRAME_KIND_OPERATION_RESPONSE_V1,
        &response,
        MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
    )
    .expect("encode compact response");
    drop(scope);
    let consumed = admission
        .usage
        .lock()
        .expect("compact usage lock")
        .consumed_bytes;
    assert!(
        consumed > compact_policy.max_composed_bytes,
        "the end-to-end server sequence must exercise cumulative, not live, accounting: consumed {consumed}, live cap {}",
        compact_policy.max_composed_bytes
    );
    assert!(consumed <= compact_policy.max_cumulative_bytes);
}
#[test]
fn decode_limits_reject_allocation_bombs_depth_and_trailing_bytes() {
    let bomb = NestedDecodeBudgetProbeV1 {
        first: vec![0xA5; 64],
        second: vec![0x5A; 64],
    };
    let bomb_bytes = norito::encode_canonical(&bomb).expect("encode allocation bomb");
    let canonical = norito::decode_canonical::<NestedDecodeBudgetProbeV1>(&bomb_bytes)
        .expect("decode canonical allocation probe before applying a broker budget");
    assert!(canonical == bomb);
    // Frame decoding and the owned vector values both consume allocation.
    // A ceiling alone is insufficient: zero headroom clamps the budget to wire length.
    let generous_policy =
        DecodeResourcePolicyV1::new((1024, 1024), (1024, 1024), (0, 1024), 8, (4096, 4096));
    let generous_pool = Arc::new(DecodeResourcePoolV1::new(4096));
    let generous_admission =
        DecodeResourceAdmissionV1::acquire_from(generous_pool, None, generous_policy)
            .expect("acquire valid allocation-probe admission");
    generous_admission
        .reserve_raw_frame(bomb_bytes.len(), 1024)
        .expect("reserve valid allocation-probe wire bytes");
    let generous_scope = generous_admission.enter();
    let decoded = decode_canonical_with_policy::<NestedDecodeBudgetProbeV1>(
        &bomb_bytes,
        1024,
        generous_policy,
    )
    .expect("the exact same frame must decode before imposing the allocation ceiling");
    assert!(decoded == bomb);
    drop(generous_scope);
    let allocation_policy =
        DecodeResourcePolicyV1::new((1024, 1024), (1024, 32), (0, 0), 8, (4096, 4096));
    let allocation_pool = Arc::new(DecodeResourcePoolV1::new(4096));
    let allocation_admission =
        DecodeResourceAdmissionV1::acquire_from(allocation_pool, None, allocation_policy)
            .expect("acquire allocation-bomb admission");
    allocation_admission
        .reserve_raw_frame(bomb_bytes.len(), 1024)
        .expect("reserve bomb wire bytes");
    let allocation_scope = allocation_admission.enter();
    assert_eq!(
        decode_canonical_with_policy::<NestedDecodeBudgetProbeV1>(
            &bomb_bytes,
            1024,
            allocation_policy,
        ),
        Err(BrokerError::Protocol)
    );
    drop(allocation_scope);
    assert!(matches!(
        norito::decode_canonical_with_limits::<NestedDecodeBudgetProbeV1>(
            &bomb_bytes,
            norito::core::DecodeLimits::new(1024, 1024, 1024, 32, 8),
        ),
        Err(norito::Error::TotalAllocationExceeded { limit: 32, .. })
    ));
    let nested = vec![vec![vec![0xA5_u8]]];
    let nested_bytes = norito::encode_canonical(&nested).expect("encode deep value");
    let decoded_nested = norito::decode_canonical::<Vec<Vec<Vec<u8>>>>(&nested_bytes)
        .expect("decode nested frame before imposing the depth ceiling");
    assert!(decoded_nested == nested);
    // Keep the allocation allowance sufficient so this probe isolates nesting depth.
    let depth_policy =
        DecodeResourcePolicyV1::new((1024, 1024), (1024, 1024), (0, 1024), 1, (4096, 4096));
    let depth_pool = Arc::new(DecodeResourcePoolV1::new(4096));
    let depth_admission = DecodeResourceAdmissionV1::acquire_from(depth_pool, None, depth_policy)
        .expect("acquire depth admission");
    depth_admission
        .reserve_raw_frame(nested_bytes.len(), 1024)
        .expect("reserve deep wire bytes");
    let depth_scope = depth_admission.enter();
    assert_eq!(
        decode_canonical_with_policy::<Vec<Vec<Vec<u8>>>>(&nested_bytes, 1024, depth_policy,),
        Err(BrokerError::Protocol)
    );
    drop(depth_scope);
    assert!(matches!(
        norito::decode_canonical_with_limits::<Vec<Vec<Vec<u8>>>>(
            &nested_bytes,
            norito::core::DecodeLimits::new(1024, 1024, 1024, 1024, 1),
        ),
        Err(norito::Error::NestingDepthExceeded { limit: 1, .. })
    ));
    let mut trailing = norito::encode_canonical(&7_u64).expect("encode canonical integer");
    assert_eq!(
        decode_canonical_with_policy::<u64>(&trailing, trailing.len(), CONTROL_DECODE_POLICY_V1,),
        Ok(7)
    );
    trailing.push(0);
    assert_eq!(
        decode_canonical_with_policy::<u64>(&trailing, trailing.len(), CONTROL_DECODE_POLICY_V1,),
        Err(BrokerError::Protocol)
    );
}
#[test]
fn operation_policies_decode_actual_request_and_response_frames() {
    let binding = signer_binding();
    let metadata_digest = observation(&binding).metadata_digest;
    let payload = valid_governance_sign_request_payload();
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding,
        metadata_digest,
        OPERATION_SIGN_V1,
        payload,
    )
    .expect("build operation request");
    let response = operation_response(
        &request,
        STATUS_OK_V1,
        encode_canonical(
            &SignResultWireV1 {
                signature: test_governance_operation_signature(&request),
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode sign result"),
    );
    assert_broker_frame_owner(
        &request,
        "irohad::runtime_provider_broker::protocol::OperationRequestV1",
        MAX_OPERATION_FRAME_BYTES_V1,
    );
    assert_broker_frame_owner(
        &response,
        "irohad::runtime_provider_broker::protocol::OperationResponseV1",
        MAX_OPERATION_FRAME_BYTES_V1,
    );
    let limit = operation_frame_limit(OPERATION_SIGN_V1);
    let policy = operation_decode_policy(OPERATION_SIGN_V1);
    let request_frame = encode_frame(FRAME_KIND_OPERATION_REQUEST_V1, &request, limit)
        .expect("encode request frame");
    let request_pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let request_admission =
        DecodeResourceAdmissionV1::acquire_from(request_pool, Some(OPERATION_SIGN_V1), policy)
            .expect("acquire request admission");
    request_admission
        .reserve_raw_frame(request_frame.len(), limit)
        .expect("reserve request frame");
    let request_scope = request_admission.enter();
    let decoded_request = decode_operation_frame::<OperationRequestV1>(
        &request_frame,
        FRAME_KIND_OPERATION_REQUEST_V1,
        OPERATION_SIGN_V1,
    )
    .expect("decode actual request frame");
    validate_operation_request(&decoded_request).expect("validate decoded request");
    drop(request_scope);
    let response_frame = encode_frame(FRAME_KIND_OPERATION_RESPONSE_V1, &response, limit)
        .expect("encode response frame");
    let response_pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let response_admission =
        DecodeResourceAdmissionV1::acquire_from(response_pool, Some(OPERATION_SIGN_V1), policy)
            .expect("acquire response admission");
    response_admission
        .reserve_raw_frame(response_frame.len(), limit)
        .expect("reserve response frame");
    let response_scope = response_admission.enter();
    let decoded_response = decode_operation_frame::<OperationResponseV1>(
        &response_frame,
        FRAME_KIND_OPERATION_RESPONSE_V1,
        OPERATION_SIGN_V1,
    )
    .expect("decode actual response frame");
    validate_operation_response(&request, &decoded_response, &network_id())
        .expect("validate decoded response");
    drop(response_scope);
}
#[test]
fn outbound_admission_is_process_wide_and_follows_result_lifetime() {
    let operation = OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1;
    let policy = operation_decode_policy(operation);
    let pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let first = DecodeResourceAdmissionV1::acquire_operation_from(Arc::clone(&pool), operation)
        .expect("acquire first large outbound operation");
    first
        .reserve_retained_bytes(
            MAX_PROVIDER_INGEST_CHECKPOINT_BYTES_V1,
            operation_frame_limit(operation),
        )
        .expect("account large outbound payload before encoding");
    let attempted_encode = Arc::new(AtomicBool::new(false));
    let attempted_encode_thread = Arc::clone(&attempted_encode);
    let pool_thread = Arc::clone(&pool);
    let contender = thread::spawn(move || {
        if DecodeResourceAdmissionV1::acquire_operation_from(pool_thread, operation).is_ok() {
            attempted_encode_thread.store(true, Ordering::Release);
        }
    });
    contender.join().expect("join outbound contender");
    assert!(
        !attempted_encode.load(Ordering::Acquire),
        "a concurrent large request must be rejected before canonical encoding"
    );
    let result = ScrubbedBytes::with_decode_admission(vec![0xA5], first);
    assert_eq!(pool.allocation.reserved_bytes(), policy.max_composed_bytes);
    drop(result);
    assert_eq!(pool.allocation.reserved_bytes(), 0);
}
struct ServerTestPrivacyCyclePrfProvider {
    revision: AtomicU64,
    drift_on_probe: bool,
    derive_calls: AtomicU64,
}
impl ServerTestPrivacyCyclePrfProvider {
    const fn exact() -> Self {
        Self {
            revision: AtomicU64::new(7),
            drift_on_probe: false,
            derive_calls: AtomicU64::new(0),
        }
    }
    const fn drifting() -> Self {
        Self {
            revision: AtomicU64::new(7),
            drift_on_probe: true,
            derive_calls: AtomicU64::new(0),
        }
    }
}
impl node::ProductionTransparencyRuntimeProviderV1 for ServerTestPrivacyCyclePrfProvider {
    fn handle(&self) -> &str {
        SERVER_TEST_PRIVACY_PRF_HANDLE
    }
    fn qualification(&self) -> Result<node::TransparencyRuntimeProviderQualificationV1, String> {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(node::TransparencyRuntimeProviderQualificationV1::new(
            revision,
            TEST_POLICY_DIGEST,
        ))
    }
}
impl node::PrivacyCyclePrfProviderV1 for ServerTestPrivacyCyclePrfProvider {
    fn derive_cycle_output(
        &self,
        _request: &node::PrivacyCyclePrfRequestV1,
    ) -> Result<node::PrivacyCyclePrfOutputV1, node::PrivacyCyclePrfProviderErrorV1> {
        self.derive_calls.fetch_add(1, Ordering::SeqCst);
        node::PrivacyCyclePrfOutputV1::new([0xD5; 32])
            .map_err(|_| node::PrivacyCyclePrfProviderErrorV1::Internal)
    }
}
struct ServerTestPrivacyReleaseAnchor {
    handle: &'static str,
    revision: AtomicU64,
    drift_on_probe: bool,
    head: Mutex<Option<node::PrivacyReleaseAnchorHeadV1>>,
    compare_and_set_calls: AtomicU64,
    skip_write: bool,
}
impl ServerTestPrivacyReleaseAnchor {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_PRIVACY_RELEASE_ANCHOR_HANDLE,
            revision: AtomicU64::new(7),
            drift_on_probe: false,
            head: Mutex::new(None),
            compare_and_set_calls: AtomicU64::new(0),
            skip_write: false,
        }
    }
    fn drifting() -> Self {
        Self {
            drift_on_probe: true,
            ..Self::exact()
        }
    }
    fn substituted() -> Self {
        Self {
            handle: "governance-dag://sorafs/transparency/release-anchor-substitute",
            ..Self::exact()
        }
    }
    fn without_readback() -> Self {
        Self {
            skip_write: true,
            ..Self::exact()
        }
    }
}
impl node::ProductionTransparencyRuntimeProviderV1 for ServerTestPrivacyReleaseAnchor {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(&self) -> Result<node::TransparencyRuntimeProviderQualificationV1, String> {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(node::TransparencyRuntimeProviderQualificationV1::new(
            revision,
            TEST_POLICY_DIGEST,
        ))
    }
}
impl node::PrivacyReleaseAnchorV1 for ServerTestPrivacyReleaseAnchor {
    fn finalized_head(
        &self,
        query_id: [u8; 32],
    ) -> Result<node::PrivacyReleaseAnchorHeadV1, node::PrivacyReleaseAnchorErrorV1> {
        let head = self.head.lock().expect("release-anchor test lock");
        let head = (*head).unwrap_or_else(|| node::PrivacyReleaseAnchorHeadV1::genesis(query_id));
        if head.query_id() != query_id {
            return Err(node::PrivacyReleaseAnchorErrorV1::InvalidState);
        }
        Ok(head)
    }
    fn compare_and_set_finalized_head(
        &self,
        expected: node::PrivacyReleaseAnchorHeadV1,
        next: node::PrivacyReleaseAnchorHeadV1,
        _lease: &node::TransparencyLeaderLeaseGrantV1,
    ) -> Result<(), node::PrivacyReleaseAnchorErrorV1> {
        self.compare_and_set_calls.fetch_add(1, Ordering::SeqCst);
        let mut head = self.head.lock().expect("release-anchor test lock");
        let current = (*head)
            .unwrap_or_else(|| node::PrivacyReleaseAnchorHeadV1::genesis(expected.query_id()));
        if current != expected {
            return Err(node::PrivacyReleaseAnchorErrorV1::Conflict);
        }
        if !self.skip_write {
            *head = Some(next);
        }
        Ok(())
    }
}
struct ServerTestTransparencyLeaderLeaseProvider {
    handle: &'static str,
    revision: AtomicU64,
    drift_on_probe: bool,
    active: Mutex<Option<node::TransparencyLeaderLeaseGrantV1>>,
    acquire_calls: AtomicU64,
    renew_calls: AtomicU64,
    release_calls: AtomicU64,
}
impl ServerTestTransparencyLeaderLeaseProvider {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_TRANSPARENCY_LEADER_LEASE_HANDLE,
            revision: AtomicU64::new(7),
            drift_on_probe: false,
            active: Mutex::new(None),
            acquire_calls: AtomicU64::new(0),
            renew_calls: AtomicU64::new(0),
            release_calls: AtomicU64::new(0),
        }
    }
    fn drifting() -> Self {
        Self {
            drift_on_probe: true,
            ..Self::exact()
        }
    }
    fn substituted() -> Self {
        Self {
            handle: "sealed-cas://sorafs/transparency/leader-substitute",
            ..Self::exact()
        }
    }
    fn lease_id(fencing_token: u64) -> [u8; 32] {
        let mut lease_id = [0x7A; 32];
        lease_id[..8].copy_from_slice(&fencing_token.to_le_bytes());
        lease_id
    }
}
impl node::ProductionTransparencyRuntimeProviderV1 for ServerTestTransparencyLeaderLeaseProvider {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(&self) -> Result<node::TransparencyRuntimeProviderQualificationV1, String> {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(node::TransparencyRuntimeProviderQualificationV1::new(
            revision,
            TEST_POLICY_DIGEST,
        ))
    }
}
impl node::TransparencyLeaderLeaseProviderV1 for ServerTestTransparencyLeaderLeaseProvider {
    fn acquire(
        &self,
        request: &node::TransparencyLeaderLeaseAcquireRequestV1,
    ) -> Result<node::TransparencyLeaderLeaseGrantV1, node::TransparencyLeaderLeaseProviderErrorV1>
    {
        self.acquire_calls.fetch_add(1, Ordering::SeqCst);
        let mut active = self.active.lock().expect("leader-lease test lock");
        if active.is_some() {
            return Err(node::TransparencyLeaderLeaseProviderErrorV1::Conflict);
        }
        let fencing_token = request
            .fencing_floor()
            .checked_add(1)
            .ok_or(node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
        let grant = node::TransparencyLeaderLeaseGrantV1::try_new(
            Self::lease_id(fencing_token),
            request.scope(),
            fencing_token,
            request.acquire_at_unix(),
            request.expires_at_unix(),
            request.provider_binding().clone(),
        )
        .map_err(|_| node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
        *active = Some(grant.clone());
        Ok(grant)
    }
    fn renew(
        &self,
        request: &node::TransparencyLeaderLeaseRenewRequestV1,
    ) -> Result<node::TransparencyLeaderLeaseGrantV1, node::TransparencyLeaderLeaseProviderErrorV1>
    {
        self.renew_calls.fetch_add(1, Ordering::SeqCst);
        let mut active = self.active.lock().expect("leader-lease test lock");
        if active.as_ref() != Some(request.current_grant()) {
            return Err(node::TransparencyLeaderLeaseProviderErrorV1::Conflict);
        }
        let fencing_token = request
            .fencing_floor()
            .checked_add(1)
            .ok_or(node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
        let grant = node::TransparencyLeaderLeaseGrantV1::try_new(
            request.current_grant().lease_id(),
            request.current_grant().scope(),
            fencing_token,
            request.renew_at_unix(),
            request.expires_at_unix(),
            request.current_grant().provider_binding().clone(),
        )
        .map_err(|_| node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
        *active = Some(grant.clone());
        Ok(grant)
    }
    fn release(
        &self,
        request: &node::TransparencyLeaderLeaseReleaseRequestV1,
    ) -> Result<
        node::TransparencyLeaderLeaseReleaseReceiptV1,
        node::TransparencyLeaderLeaseProviderErrorV1,
    > {
        self.release_calls.fetch_add(1, Ordering::SeqCst);
        let mut active = self.active.lock().expect("leader-lease test lock");
        if active.as_ref() != Some(request.current_grant()) {
            return Err(node::TransparencyLeaderLeaseProviderErrorV1::Conflict);
        }
        let receipt = node::TransparencyLeaderLeaseReleaseReceiptV1::try_new(
            request.current_grant().lease_id(),
            request.current_grant().scope(),
            request.current_grant().fencing_token(),
            request.release_at_unix(),
            request.current_grant().provider_binding().clone(),
        )
        .map_err(|_| node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
        *active = None;
        Ok(receipt)
    }
}
struct ServerTestFencedPrivacyPublisher {
    handle: &'static str,
    receipt_handle: &'static str,
    revision: AtomicU64,
    drift_on_probe: bool,
    compare_and_append_calls: AtomicU64,
}
impl ServerTestFencedPrivacyPublisher {
    const fn exact() -> Self {
        Self {
            handle: SERVER_TEST_FENCED_PRIVACY_PUBLISHER_HANDLE,
            receipt_handle: SERVER_TEST_FENCED_PRIVACY_PUBLISHER_HANDLE,
            revision: AtomicU64::new(7),
            drift_on_probe: false,
            compare_and_append_calls: AtomicU64::new(0),
        }
    }
    const fn drifting() -> Self {
        Self {
            drift_on_probe: true,
            ..Self::exact()
        }
    }
    const fn substituted() -> Self {
        Self {
            handle: "governance-cas://sorafs/transparency/privacy-substitute",
            ..Self::exact()
        }
    }
    const fn substituted_receipt() -> Self {
        Self {
            receipt_handle: "governance-cas://sorafs/transparency/privacy-substitute",
            ..Self::exact()
        }
    }
}
impl fmt::Debug for ServerTestFencedPrivacyPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerTestFencedPrivacyPublisher(<runtime-only>)")
    }
}
impl node::FencedTransparencyPublisherV1 for ServerTestFencedPrivacyPublisher {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(&self) -> Result<node::GovernanceDagRuntimeProviderQualificationV1, String> {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(node::GovernanceDagRuntimeProviderQualificationV1::new(
            revision,
            TEST_POLICY_DIGEST,
        ))
    }
    fn compare_and_append_privacy(
        &self,
        request: &node::FencedPrivacyPublicationRequestV1,
    ) -> Result<node::FencedPrivacyPublicationReceiptV1, node::FencedTransparencyPublishErrorV1>
    {
        self.compare_and_append_calls.fetch_add(1, Ordering::SeqCst);
        node::FencedPrivacyPublicationReceiptV1::from_verified_append(
            request,
            self.receipt_handle,
            node::GovernanceDagRuntimeProviderQualificationV1::new(
                self.revision.load(Ordering::SeqCst),
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
struct ServerTestFencedPrivacyHeadReader {
    handle: &'static str,
    revision: AtomicU64,
    drift_on_probe: bool,
    drift_after_read: bool,
    substitute_proof: bool,
    read_calls: AtomicU64,
}
impl ServerTestFencedPrivacyHeadReader {
    const fn exact() -> Self {
        Self {
            handle: SERVER_TEST_FENCED_PRIVACY_PUBLISHER_HANDLE,
            revision: AtomicU64::new(7),
            drift_on_probe: false,
            drift_after_read: false,
            substitute_proof: false,
            read_calls: AtomicU64::new(0),
        }
    }
    const fn drifting() -> Self {
        Self {
            drift_on_probe: true,
            ..Self::exact()
        }
    }
    const fn drifting_after_read() -> Self {
        Self {
            drift_after_read: true,
            ..Self::exact()
        }
    }
    const fn substituted() -> Self {
        Self {
            handle: "governance-cas://sorafs/transparency/privacy-substitute",
            ..Self::exact()
        }
    }
    const fn substituted_proof() -> Self {
        Self {
            substitute_proof: true,
            ..Self::exact()
        }
    }
}
impl fmt::Debug for ServerTestFencedPrivacyHeadReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerTestFencedPrivacyHeadReader(<runtime-only>)")
    }
}
impl node::FencedTransparencyAuthoritativeHeadReaderV1 for ServerTestFencedPrivacyHeadReader {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(&self) -> Result<node::GovernanceDagRuntimeProviderQualificationV1, String> {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(node::GovernanceDagRuntimeProviderQualificationV1::new(
            revision,
            TEST_POLICY_DIGEST,
        ))
    }
    fn read_authoritative_head_with_ancestry(
        &self,
        required_ancestors: &[node::FencedTransparencyTargetHeadV1],
        required_publications: &[node::FencedTransparencyPublicationInclusionV1],
    ) -> Result<node::FencedTransparencyHeadAncestryProofV1, String> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        let authoritative_head = required_ancestors
            .iter()
            .copied()
            .max_by_key(|head| head.generation());
        let (verified_ancestors, verified_publications) = if self.substitute_proof {
            (Vec::new(), Vec::new())
        } else {
            (required_ancestors.to_vec(), required_publications.to_vec())
        };
        let proof = node::FencedTransparencyHeadAncestryProofV1::try_new(
            authoritative_head,
            verified_ancestors,
            verified_publications,
            [0x6A; 32],
        )
        .map_err(|_| "redacted test proof construction failure".to_owned())?;
        if self.drift_after_read {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
        Ok(proof)
    }
}
struct ServerTestAcmeClient {
    revision: AtomicU64,
    drift_on_probe: bool,
}
impl test_gateway::AcmeClient for ServerTestAcmeClient {
    fn qualification(
        &self,
    ) -> Result<test_gateway::AcmeClientIdentityV1, test_gateway::AcmeClientProbeError> {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(test_gateway::AcmeClientIdentityV1 {
            provider_handle: SERVER_TEST_ACME_HANDLE.to_owned(),
            revision,
            policy_digest: TEST_POLICY_DIGEST,
            test_marked: false,
        })
    }
    fn order_certificate(
        &self,
        _order: &test_gateway::CertificateOrder,
    ) -> Result<test_gateway::CertificateBundle, test_gateway::AcmeClientError> {
        Err(test_gateway::AcmeClientError::Rejected)
    }
}
struct ServerTestComplianceTransport {
    revision: AtomicU64,
    drift_on_probe: bool,
}
impl test_gateway::GatewayComplianceFeedTransport for ServerTestComplianceTransport {
    fn qualification(
        &self,
    ) -> Result<
        test_gateway::GatewayComplianceFeedTransportIdentityV1,
        test_gateway::GatewayComplianceFeedTransportProbeError,
    > {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(test_gateway::GatewayComplianceFeedTransportIdentityV1 {
            provider_handle: SERVER_TEST_COMPLIANCE_HANDLE.to_owned(),
            revision,
            policy_digest: TEST_POLICY_DIGEST,
            test_marked: false,
        })
    }
    fn resolve(
        &self,
        _hostname: &str,
        _timeout: Duration,
    ) -> Result<Vec<std::net::IpAddr>, test_gateway::GatewayComplianceError> {
        Err(test_gateway::GatewayComplianceError::FeedTransportOperationFailed)
    }
    fn fetch(
        &self,
        _request: &test_gateway::GatewayComplianceFetchRequest,
    ) -> Result<test_gateway::GatewayComplianceFetchResponse, test_gateway::GatewayComplianceError>
    {
        Err(test_gateway::GatewayComplianceError::FeedTransportOperationFailed)
    }
}
#[derive(Debug)]
struct ServerTestPorReplayArchive {
    binding: node::PorFinalizedReplayArchiveBindingV1,
    later_binding: Option<node::PorFinalizedReplayArchiveBindingV1>,
    binding_calls: AtomicU64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::platform::tests::PorReplayArchiveChallengeStateFixtureV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct PorReplayArchiveChallengeStateFixtureV1 {
    challenge: sorafs_manifest::por::PorChallengeV1,
    proof_digest: Option<[u8; 32]>,
    proof_submitted_at: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::platform::tests::PorReplayArchiveRecordFixtureV1",
    frame = "sorafs_node::por::PorFinalizedReplayArchiveRecordV1"
)]
struct PorReplayArchiveRecordFixtureV1 {
    finalized: PorReplayArchiveFinalizedStateFixtureV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::platform::tests::PorReplayArchiveFinalizedStateFixtureV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
struct PorReplayArchiveFinalizedStateFixtureV1 {
    state: PorReplayArchiveChallengeStateFixtureV1,
    verdict: sorafs_manifest::por::AuditVerdictV1,
    stats: node::PorVerdictStats,
    repair_task_id: Option<[u8; 32]>,
    repair_handoff_acknowledged: bool,
    reputation_sequence: u64,
    reputation_terminal: iroha_data_model::sorafs::reputation::PorTerminalOutcomeV1,
}
impl ServerTestPorReplayArchive {
    fn exact(binding: node::PorFinalizedReplayArchiveBindingV1) -> Self {
        Self {
            binding,
            later_binding: None,
            binding_calls: AtomicU64::new(0),
        }
    }
    fn drifting(
        binding: node::PorFinalizedReplayArchiveBindingV1,
        later_binding: node::PorFinalizedReplayArchiveBindingV1,
    ) -> Self {
        Self {
            binding,
            later_binding: Some(later_binding),
            binding_calls: AtomicU64::new(0),
        }
    }
}
impl node::PorFinalizedReplayArchiveV1 for ServerTestPorReplayArchive {
    fn runtime_handle(&self) -> &str {
        SERVER_TEST_POR_ARCHIVE_HANDLE
    }
    fn binding(
        &self,
    ) -> Result<
        node::PorFinalizedReplayArchiveBindingV1,
        node::PorFinalizedReplayArchiveExternalErrorV1,
    > {
        let call = self.binding_calls.fetch_add(1, Ordering::SeqCst);
        Ok(if call == 0 {
            self.binding
        } else {
            self.later_binding.unwrap_or(self.binding)
        })
    }
    fn check_readiness(&self) -> Result<(), node::PorFinalizedReplayArchiveExternalErrorV1> {
        Ok(())
    }
    fn current_head(
        &self,
    ) -> Result<
        Option<node::PorFinalizedReplayArchiveReceiptV1>,
        node::PorFinalizedReplayArchiveExternalErrorV1,
    > {
        Ok(None)
    }
    fn append(
        &self,
        _record: &node::PorFinalizedReplayArchiveRecordV1,
        _expected_previous_head: Option<[u8; 32]>,
    ) -> Result<
        node::PorFinalizedReplayArchiveReceiptV1,
        node::PorFinalizedReplayArchiveExternalErrorV1,
    > {
        Err(node::PorFinalizedReplayArchiveExternalErrorV1::Rejected)
    }
    fn lookup(
        &self,
        _challenge_id: [u8; 32],
        _expected_checkpoint_head: node::PorFinalizedReplayArchiveReceiptV1,
        _proof_bounds: node::PorFinalizedReplayArchiveProofBoundsV1,
    ) -> Result<
        node::PorFinalizedReplayArchiveLookupV1,
        node::PorFinalizedReplayArchiveExternalErrorV1,
    > {
        Err(node::PorFinalizedReplayArchiveExternalErrorV1::Rejected)
    }
}
#[derive(Debug)]
struct ServerTestPopRegistry {
    revision: AtomicU64,
    drift_on_probe: bool,
}
impl test_pop::PopCredentialRuntimeProviderRegistryV1 for ServerTestPopRegistry {
    fn handle(&self) -> &str {
        SERVER_TEST_POP_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<
        test_pop::PopCredentialRuntimeProviderQualificationV1,
        test_pop::PopCredentialRuntimeProviderRegistryErrorV1,
    > {
        let revision = if self.drift_on_probe {
            self.revision.fetch_add(1, Ordering::SeqCst)
        } else {
            self.revision.load(Ordering::SeqCst)
        };
        Ok(test_pop::PopCredentialRuntimeProviderQualificationV1::new(
            revision,
            TEST_POLICY_DIGEST,
        ))
    }
    fn resolve(
        &self,
        _bindings: &test_pop::PopCredentialRuntimeProviderBindingsV1,
    ) -> Result<
        test_pop::PopCredentialRuntimeProvidersV1,
        test_pop::PopCredentialRuntimeProviderRegistryErrorV1,
    > {
        Err(test_pop::PopCredentialRuntimeProviderRegistryErrorV1::Unavailable)
    }
}
#[derive(Debug)]
struct ServerTestGovernanceSigner;
impl node::GovernanceDagRuntimeSigner for ServerTestGovernanceSigner {
    fn handle(&self) -> &str {
        SERVER_TEST_SIGNER_HANDLE
    }
    fn qualification(&self) -> Result<node::GovernanceDagRuntimeProviderQualificationV1, String> {
        Ok(node::GovernanceDagRuntimeProviderQualificationV1::new(
            7,
            TEST_POLICY_DIGEST,
        ))
    }
    fn publisher_peer_id(&self) -> &[u8] {
        b"12D3KooWRuntimeBrokerServerPrimary"
    }
    fn public_key(&self) -> [u8; 32] {
        TEST_SIGNER_KEY
    }
    fn sign(
        &self,
        _purpose: node::GovernanceDagSigningPurposeV1,
        payload: &[u8],
    ) -> Result<[u8; 64], String> {
        Ok(test_governance_signature(payload))
    }
}
#[derive(Debug)]
struct ServerTestAppealFinanceSigner {
    sign_calls: AtomicU64,
}
impl ServerTestAppealFinanceSigner {
    const fn exact() -> Self {
        Self {
            sign_calls: AtomicU64::new(0),
        }
    }
    fn keypair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x96; 32], Algorithm::Ed25519)
            .expect("derive appeal-finance transaction signer test key")
    }
}
impl iroha_torii::SoraFsAppealFinanceTransactionSigner for ServerTestAppealFinanceSigner {
    fn handle(&self) -> &str {
        SERVER_TEST_APPEAL_FINANCE_SIGNER_HANDLE
    }
    fn public_key(
        &self,
    ) -> Result<iroha_crypto::PublicKey, iroha_torii::SoraFsAppealFinanceSigningError> {
        Ok(Self::keypair().public_key().clone())
    }
    fn qualification(
        &self,
    ) -> Result<
        node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1,
        iroha_torii::SoraFsAppealFinanceSigningError,
    > {
        Ok(
            node::appeal_finance_transaction_forwarder::
                AppealFinanceRuntimeProviderQualificationV1::new(
                    7,
                    TEST_POLICY_DIGEST,
                ),
        )
    }
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, iroha_torii::SoraFsAppealFinanceSigningError> {
        self.sign_calls.fetch_add(1, Ordering::Relaxed);
        TransactionBuilder::from_payload(payload)
            .map_err(|_| iroha_torii::SoraFsAppealFinanceSigningError::Refused)?
            .try_sign(Self::keypair().private_key())
            .map_err(|_| iroha_torii::SoraFsAppealFinanceSigningError::Refused)
    }
}
fn test_auth_keypair() -> KeyPair {
    KeyPair::try_from_seed(vec![0x83; 32], Algorithm::Ed25519).expect("request-auth test keypair")
}
fn test_auth_public_key() -> [u8; 32] {
    let keypair = test_auth_keypair();
    let public_key = keypair.public_key().to_bytes().1;
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(public_key);
    bytes
}
fn ingress_fixture(public_key: [u8; 32]) -> node::GovernanceDagRequestIngressBindingV1 {
    let scope = node::GovernanceDagAuthenticationScope::Ipfs;
    let endpoint_binding = node::governance_dag_request_ingress_endpoint_binding_v1(
        scope,
        "https://governance-ingress.invalid/ipfs/",
    )
    .expect("request-auth test endpoint must be canonical");
    node::GovernanceDagRequestIngressBindingV1::try_new(
        scope,
        endpoint_binding,
        public_key,
        1_024,
        30,
        5,
    )
    .expect("request-auth test ingress binding must be valid")
}
fn server_test_request_ingress_qualification(
    public_key: [u8; 32],
) -> node::GovernanceDagRequestIngressQualificationV1 {
    node::GovernanceDagRequestIngressQualificationV1::try_new(
        node::GovernanceDagRuntimeProviderQualificationV1::new(7, TEST_POLICY_DIGEST),
        ingress_fixture(public_key),
        [0x91; 32],
        [0x92; 32],
        [0x93; 32],
    )
    .expect("request-auth test ingress qualification must be valid")
}
#[derive(Debug)]
struct ServerTestGovernanceRequestAuthenticator {
    public_key_override: Option<[u8; 32]>,
    nonce: AtomicU64,
}
impl ServerTestGovernanceRequestAuthenticator {
    const fn exact() -> Self {
        Self {
            public_key_override: None,
            nonce: AtomicU64::new(1),
        }
    }
    const fn with_public_key(public_key: [u8; 32]) -> Self {
        Self {
            public_key_override: Some(public_key),
            nonce: AtomicU64::new(1),
        }
    }
    fn request_auth_public_key(&self) -> [u8; 32] {
        self.public_key_override
            .unwrap_or_else(test_auth_public_key)
    }
}
impl node::GovernanceDagRequestAuthenticator for ServerTestGovernanceRequestAuthenticator {
    fn handle(&self) -> &str {
        SERVER_TEST_IPFS_AUTH_HANDLE
    }
    fn ingress_qualification(
        &self,
    ) -> Result<node::GovernanceDagRequestIngressQualificationV1, String> {
        Ok(server_test_request_ingress_qualification(
            self.request_auth_public_key(),
        ))
    }
    fn authenticate(
        &self,
        request: &node::GovernanceDagCanonicalRequestV1,
    ) -> Result<node::GovernanceDagRequestAuthenticationEnvelopeV1, String> {
        if request.scope() != node::GovernanceDagAuthenticationScope::Ipfs {
            return Err("redacted request-auth scope rejection".to_owned());
        }
        let issued_at_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "redacted request-auth clock failure".to_owned())?
            .as_secs();
        let expires_at_unix_secs = issued_at_unix_secs
            .checked_add(30)
            .ok_or_else(|| "redacted request-auth clock failure".to_owned())?;
        let sequence = self.nonce.fetch_add(1, Ordering::Relaxed);
        let mut nonce = request.request_digest();
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        let public_key = self.request_auth_public_key();
        let payload = node::GovernanceDagRequestAuthenticationEnvelopeV1::signing_payload(
            request,
            issued_at_unix_secs,
            expires_at_unix_secs,
            nonce,
            public_key,
        );
        let signature = Signature::try_new(test_auth_keypair().private_key(), &payload)
            .map_err(|_| "redacted request-auth signing failure".to_owned())?;
        let mut signature_bytes = [0_u8; 64];
        signature_bytes.copy_from_slice(signature.payload());
        node::GovernanceDagRequestAuthenticationEnvelopeV1::try_new(
            request,
            issued_at_unix_secs,
            expires_at_unix_secs,
            nonce,
            public_key,
            signature_bytes,
        )
        .map_err(str::to_owned)
    }
}
#[derive(Clone, Copy)]
enum ServerTestNativeSignerMode {
    Exact,
    InvalidSignature,
    DriftAfterSign,
}
struct ServerTestNativeSigner {
    role: iroha_torii::SorafsNativeTransactionSignerRoleV1,
    handle: &'static str,
    seed: u8,
    mode: ServerTestNativeSignerMode,
    probe_calls: AtomicU64,
    sign_calls: AtomicU64,
    signed: AtomicBool,
}
impl ServerTestNativeSigner {
    fn exact(role: iroha_torii::SorafsNativeTransactionSignerRoleV1) -> Self {
        Self {
            role,
            handle: native_test_handle(role),
            seed: native_test_seed(role),
            mode: ServerTestNativeSignerMode::Exact,
            probe_calls: AtomicU64::new(0),
            sign_calls: AtomicU64::new(0),
            signed: AtomicBool::new(false),
        }
    }
    fn with_role(mut self, role: iroha_torii::SorafsNativeTransactionSignerRoleV1) -> Self {
        self.role = role;
        self
    }
    fn with_seed(mut self, seed: u8) -> Self {
        self.seed = seed;
        self
    }
    fn with_mode(mut self, mode: ServerTestNativeSignerMode) -> Self {
        self.mode = mode;
        self
    }
    fn keypair(&self) -> KeyPair {
        KeyPair::try_from_seed(vec![self.seed; 32], Algorithm::Ed25519)
            .expect("derive native transaction signer test key")
    }
    fn binding(&self) -> iroha_torii::SorafsNativeTransactionSignerBindingV1 {
        let public_key = self.keypair().public_key().clone();
        iroha_torii::SorafsNativeTransactionSignerBindingV1::try_new(
            self.role,
            self.handle,
            AccountId::new(public_key.clone()),
            public_key,
            iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(7, TEST_POLICY_DIGEST),
        )
        .expect("construct native transaction signer test binding")
    }
    fn sign_payload(&self, payload: TransactionPayload) -> Result<SignedTransaction, ()> {
        self.sign_calls.fetch_add(1, Ordering::Relaxed);
        let signed = match self.mode {
            ServerTestNativeSignerMode::Exact | ServerTestNativeSignerMode::DriftAfterSign => {
                TransactionBuilder::from_payload(payload)
                    .map_err(|_| ())?
                    .try_sign(self.keypair().private_key())
                    .map_err(|_| ())?
            }
            ServerTestNativeSignerMode::InvalidSignature => {
                let wrong = KeyPair::try_from_seed(vec![0xF1; 32], Algorithm::Ed25519)
                    .expect("derive invalid native signer output key");
                let signature =
                    Signature::try_new(wrong.private_key(), b"invalid-native-transaction-preimage")
                        .map_err(|_| ())?;
                TransactionBuilder::from_payload(payload)
                    .map_err(|_| ())?
                    .build_with_signature(signature)
            }
        };
        if matches!(self.mode, ServerTestNativeSignerMode::DriftAfterSign) {
            self.signed.store(true, Ordering::Release);
        }
        Ok(signed)
    }
}
fn native_test_handle(role: iroha_torii::SorafsNativeTransactionSignerRoleV1) -> &'static str {
    match role {
        iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome => {
            "software://sorafs/proof-outcome/broker-primary"
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair => {
            "software://sorafs/repair/broker-primary"
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve => {
            "software://sorafs/reserve/broker-primary"
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook => {
            "software://sorafs/orderbook/broker-primary"
        }
    }
}
const fn native_test_seed(role: iroha_torii::SorafsNativeTransactionSignerRoleV1) -> u8 {
    match role {
        iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome => 0x91,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair => 0x92,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve => 0x93,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook => 0x94,
    }
}
impl iroha_torii::SorafsNativeTransactionSignerProviderV1 for ServerTestNativeSigner {
    fn role(&self) -> iroha_torii::SorafsNativeTransactionSignerRoleV1 {
        self.probe_calls.fetch_add(1, Ordering::Relaxed);
        self.role
    }
    fn handle(&self) -> &str {
        self.probe_calls.fetch_add(1, Ordering::Relaxed);
        self.handle
    }
    fn authority(&self) -> AccountId {
        self.probe_calls.fetch_add(1, Ordering::Relaxed);
        AccountId::new(self.keypair().public_key().clone())
    }
    fn public_key(
        &self,
    ) -> Result<iroha_crypto::PublicKey, iroha_torii::SorafsNativeTransactionSignerProbeErrorV1>
    {
        self.probe_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.keypair().public_key().clone())
    }
    fn qualification(
        &self,
    ) -> Result<
        iroha_torii::SorafsNativeTransactionSignerQualificationV1,
        iroha_torii::SorafsNativeTransactionSignerProbeErrorV1,
    > {
        self.probe_calls.fetch_add(1, Ordering::Relaxed);
        let revision = if self.signed.load(Ordering::Acquire) {
            8
        } else {
            7
        };
        Ok(
            iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(
                revision,
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
macro_rules! impl_server_test_native_signer {
    ($trait_name:ident, $error:ident) => {
        impl iroha_torii::$trait_name for ServerTestNativeSigner {
            fn sign(
                &self,
                payload: TransactionPayload,
            ) -> Result<SignedTransaction, iroha_torii::$error> {
                self.sign_payload(payload)
                    .map_err(|()| iroha_torii::$error::Refused)
            }
        }
    };
}
impl_server_test_native_signer!(
    SoraFsProofOutcomeTransactionSigner,
    SoraFsProofOutcomeSigningError
);
impl_server_test_native_signer!(
    SoraFsRepairTransactionSigner,
    SoraFsRepairTransactionSigningError
);
impl_server_test_native_signer!(
    SoraFsReserveTransactionSigner,
    SoraFsReserveTransactionSigningError
);
impl_server_test_native_signer!(
    SoraFsOrderbookTransactionSigner,
    SoraFsOrderbookTransactionSigningError
);
#[derive(Clone, Copy, Debug)]
enum ServerTestModerationTransactionSignerMode {
    Exact,
    InvalidSignature,
    SubstitutedPayload,
    DriftAfterSign,
    DriftOnSecondQualification,
}
#[derive(Debug)]
struct ServerTestModerationTransactionSigner {
    handle: String,
    revision: AtomicU64,
    mode: ServerTestModerationTransactionSignerMode,
    qualification_calls: AtomicU64,
    sign_calls: AtomicU64,
    signed: AtomicBool,
}
impl ServerTestModerationTransactionSigner {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_MODERATION_TRANSACTION_SIGNER_HANDLE.to_owned(),
            revision: AtomicU64::new(7),
            mode: ServerTestModerationTransactionSignerMode::Exact,
            qualification_calls: AtomicU64::new(0),
            sign_calls: AtomicU64::new(0),
            signed: AtomicBool::new(false),
        }
    }
    fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = handle.into();
        self
    }
    fn with_revision(self, revision: u64) -> Self {
        self.revision.store(revision, Ordering::Release);
        self
    }
    fn with_mode(mut self, mode: ServerTestModerationTransactionSignerMode) -> Self {
        self.mode = mode;
        self
    }
    fn keypair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x95; 32], Algorithm::Ed25519)
            .expect("derive moderation transaction signer test key")
    }
}
impl test_moderation::ModerationRuntimeProviderV1 for ServerTestModerationTransactionSigner {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_moderation::ModerationRuntimeProviderQualificationV1,
        test_moderation::ModerationRuntimeProviderReadinessErrorV1,
    > {
        let qualification_call = self.qualification_calls.fetch_add(1, Ordering::AcqRel);
        let drifted = (matches!(
            self.mode,
            ServerTestModerationTransactionSignerMode::DriftOnSecondQualification
        ) && qualification_call != 0)
            || (matches!(
                self.mode,
                ServerTestModerationTransactionSignerMode::DriftAfterSign
            ) && self.signed.load(Ordering::Acquire));
        Ok(
            test_moderation::ModerationRuntimeProviderQualificationV1::new(
                self.revision.load(Ordering::Acquire) + u64::from(drifted),
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_moderation_runtime::ModerationSignedTransactionSignerV1
    for ServerTestModerationTransactionSigner
{
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, test_moderation_runtime::ModerationSigningFailureV1> {
        self.sign_calls.fetch_add(1, Ordering::Relaxed);
        let signed = match self.mode {
            ServerTestModerationTransactionSignerMode::Exact
            | ServerTestModerationTransactionSignerMode::DriftAfterSign
            | ServerTestModerationTransactionSignerMode::DriftOnSecondQualification => {
                TransactionBuilder::from_payload(payload)
                    .map_err(|_| test_moderation_runtime::ModerationSigningFailureV1::Refused)?
                    .try_sign(Self::keypair().private_key())
                    .map_err(|_| test_moderation_runtime::ModerationSigningFailureV1::Refused)?
            }
            ServerTestModerationTransactionSignerMode::InvalidSignature => {
                let wrong = KeyPair::try_from_seed(vec![0xF2; 32], Algorithm::Ed25519)
                    .expect("derive invalid moderation signer output key");
                let signature = Signature::try_new(
                    wrong.private_key(),
                    b"invalid-moderation-transaction-preimage",
                )
                .map_err(|_| test_moderation_runtime::ModerationSigningFailureV1::Refused)?;
                TransactionBuilder::from_payload(payload)
                    .map_err(|_| test_moderation_runtime::ModerationSigningFailureV1::Refused)?
                    .build_with_signature(signature)
            }
            ServerTestModerationTransactionSignerMode::SubstitutedPayload => {
                let substituted = TransactionBuilder::new(
                    network_id_from(0x16),
                    payload.authority().clone(),
                    FeePaymentIntent::authority(Vec::new(), None),
                )
                .into_payload()
                .map_err(|_| test_moderation_runtime::ModerationSigningFailureV1::Refused)?;
                TransactionBuilder::from_payload(substituted)
                    .map_err(|_| test_moderation_runtime::ModerationSigningFailureV1::Refused)?
                    .try_sign(Self::keypair().private_key())
                    .map_err(|_| test_moderation_runtime::ModerationSigningFailureV1::Refused)?
            }
        };
        if matches!(
            self.mode,
            ServerTestModerationTransactionSignerMode::DriftAfterSign
        ) {
            self.signed.store(true, Ordering::Release);
        }
        Ok(signed)
    }
}
#[derive(Clone, Copy, Debug)]
enum ServerTestModerationDeliveryMode {
    Exact,
    NotDelivered,
    Ambiguous,
    Permanent,
    DriftAfterDelivery,
    DriftOnSecondQualification,
    InvalidReceipt,
}
#[derive(Debug)]
struct ServerTestModerationCheckpointStore {
    handle: String,
    qualification: test_moderation::ModerationRuntimeProviderQualificationV1,
    attestation_public_key: [u8; 32],
    attestation_signing_seed: [u8; 32],
    current: Mutex<Option<test_moderation::ModerationCheckpointStoreRecordV1>>,
    expected_statement: test_moderation::ModerationPanelNotificationSourceAttestationV1,
    expected_statement_digest: [u8; 32],
    attest_calls: AtomicU64,
}
impl ServerTestModerationCheckpointStore {
    fn from_fixture(
        fixture: &test_moderation::ModerationPanelNotificationArchiveBrokerFixtureV1,
    ) -> Self {
        Self {
            handle: fixture.checkpoint_handle.clone(),
            qualification: fixture.checkpoint_qualification,
            attestation_public_key: fixture.checkpoint_attestation_public_key,
            attestation_signing_seed: fixture.checkpoint_attestation_signing_seed,
            current: Mutex::new(Some(fixture.current_checkpoint_record.clone())),
            expected_statement: fixture.source_attestation.clone(),
            expected_statement_digest: fixture.validation.source_attestation_digest,
            attest_calls: AtomicU64::new(0),
        }
    }
}
impl test_moderation::ModerationRuntimeProviderV1 for ServerTestModerationCheckpointStore {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_moderation::ModerationRuntimeProviderQualificationV1,
        test_moderation::ModerationRuntimeProviderReadinessErrorV1,
    > {
        Ok(self.qualification)
    }
}
impl test_moderation::ModerationCheckpointStoreV1 for ServerTestModerationCheckpointStore {
    fn attestation_public_key(&self) -> [u8; 32] {
        self.attestation_public_key
    }
    fn load_latest(
        &self,
    ) -> Result<
        Option<test_moderation::ModerationCheckpointStoreRecordV1>,
        test_moderation::ModerationCheckpointStoreExternalErrorV1,
    > {
        Ok(self
            .current
            .lock()
            .expect("moderation checkpoint fixture lock")
            .clone())
    }
    fn compare_and_swap_latest(
        &self,
        expected_revision: Option<[u8; 32]>,
        next: &test_moderation::ModerationCheckpointStoreRecordV1,
    ) -> Result<(), test_moderation::ModerationCheckpointStoreExternalErrorV1> {
        let mut current = self
            .current
            .lock()
            .expect("moderation checkpoint fixture lock");
        if current.as_ref().map(|record| record.revision) != expected_revision {
            return Err(test_moderation::ModerationCheckpointStoreExternalErrorV1::Rejected);
        }
        *current = Some(next.clone());
        Ok(())
    }
    fn attest_terminal_set(
        &self,
        statement: &test_moderation::ModerationPanelNotificationSourceAttestationV1,
    ) -> Result<[u8; 64], test_moderation::ModerationCheckpointStoreExternalErrorV1> {
        self.attest_calls.fetch_add(1, Ordering::AcqRel);
        if statement != &self.expected_statement {
            return Err(test_moderation::ModerationCheckpointStoreExternalErrorV1::Rejected);
        }
        let keypair =
            KeyPair::try_from_seed(self.attestation_signing_seed.to_vec(), Algorithm::Ed25519)
                .map_err(|_| test_moderation::ModerationCheckpointStoreExternalErrorV1::Rejected)?;
        let signature = Signature::try_new(keypair.private_key(), &self.expected_statement_digest)
            .map_err(|_| test_moderation::ModerationCheckpointStoreExternalErrorV1::Rejected)?;
        signature
            .payload()
            .try_into()
            .map_err(|_| test_moderation::ModerationCheckpointStoreExternalErrorV1::Rejected)
    }
}
#[derive(Debug)]
struct ServerTestModerationPanelNotificationArchive {
    handle: String,
    qualification: test_moderation::ModerationRuntimeProviderQualificationV1,
    archive_id: [u8; 32],
    public_key: [u8; 32],
    expected_operation_id: [u8; 32],
    expected_receipt_message: [u8; 32],
    expected_artifact: Vec<u8>,
    expected_signature: [u8; 64],
    installed: Mutex<Option<test_moderation::ModerationPanelNotificationArchiveReadbackV1>>,
    install_calls: AtomicU64,
}
impl ServerTestModerationPanelNotificationArchive {
    fn from_fixture(
        fixture: &test_moderation::ModerationPanelNotificationArchiveBrokerFixtureV1,
    ) -> Self {
        Self {
            handle: fixture.archive_handle.clone(),
            qualification: fixture.archive_qualification,
            archive_id: fixture.archive_id,
            public_key: fixture.archive_public_key,
            expected_operation_id: fixture.validation.operation_id,
            expected_receipt_message: fixture.validation.receipt_message,
            expected_artifact: fixture.canonical_artifact.clone(),
            expected_signature: fixture.archive_signature,
            installed: Mutex::new(None),
            install_calls: AtomicU64::new(0),
        }
    }
}
impl test_moderation::ModerationRuntimeProviderV1 for ServerTestModerationPanelNotificationArchive {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_moderation::ModerationRuntimeProviderQualificationV1,
        test_moderation::ModerationRuntimeProviderReadinessErrorV1,
    > {
        Ok(self.qualification)
    }
}
impl test_moderation::ModerationPanelNotificationArchiveV1
    for ServerTestModerationPanelNotificationArchive
{
    fn archive_id(&self) -> [u8; 32] {
        self.archive_id
    }
    fn signing_public_key(&self) -> [u8; 32] {
        self.public_key
    }
    fn install(
        &self,
        operation_id: [u8; 32],
        receipt_message: [u8; 32],
        canonical_artifact: &[u8],
    ) -> Result<[u8; 64], test_moderation::ModerationPanelNotificationArchiveExternalErrorV1> {
        self.install_calls.fetch_add(1, Ordering::AcqRel);
        if operation_id != self.expected_operation_id
            || receipt_message != self.expected_receipt_message
            || canonical_artifact != self.expected_artifact.as_slice()
        {
            return Err(
                test_moderation::ModerationPanelNotificationArchiveExternalErrorV1::Rejected,
            );
        }
        let mut installed = self
            .installed
            .lock()
            .expect("moderation archive fixture lock");
        if installed.is_some() {
            return Ok(self.expected_signature);
        }
        *installed = Some(
            test_moderation::ModerationPanelNotificationArchiveReadbackV1 {
                canonical_artifact: canonical_artifact.to_vec(),
                signature: self.expected_signature,
            },
        );
        Ok(self.expected_signature)
    }
    fn read(
        &self,
        operation_id: [u8; 32],
    ) -> Result<
        Option<test_moderation::ModerationPanelNotificationArchiveReadbackV1>,
        test_moderation::ModerationPanelNotificationArchiveExternalErrorV1,
    > {
        if operation_id != self.expected_operation_id {
            return Ok(None);
        }
        Ok(self
            .installed
            .lock()
            .expect("moderation archive fixture lock")
            .clone())
    }
}
#[derive(Debug)]
struct ServerTestModerationHandoffBoundary {
    handle: String,
    kind: test_moderation::ModerationTerminalHandoffKindV1,
    mode: ServerTestModerationDeliveryMode,
    qualification_calls: AtomicU64,
    delivery_calls: AtomicU64,
    delivered: AtomicBool,
    retained: Mutex<Vec<([u8; 32], Vec<u8>)>>,
    published_heads: Mutex<Vec<test_moderation::ModerationPanelNotificationArchiveHeadV1>>,
}
impl ServerTestModerationHandoffBoundary {
    fn exact(kind: test_moderation::ModerationTerminalHandoffKindV1) -> Self {
        let handle = match kind {
            test_moderation::ModerationTerminalHandoffKindV1::Settlement => {
                SERVER_TEST_MODERATION_SETTLEMENT_HANDLE
            }
            test_moderation::ModerationTerminalHandoffKindV1::Publication => {
                SERVER_TEST_MODERATION_PUBLICATION_HANDLE
            }
        };
        Self {
            handle: handle.to_owned(),
            kind,
            mode: ServerTestModerationDeliveryMode::Exact,
            qualification_calls: AtomicU64::new(0),
            delivery_calls: AtomicU64::new(0),
            delivered: AtomicBool::new(false),
            retained: Mutex::new(Vec::new()),
            published_heads: Mutex::new(Vec::new()),
        }
    }
    fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = handle.into();
        self
    }
    fn with_mode(mut self, mode: ServerTestModerationDeliveryMode) -> Self {
        self.mode = mode;
        self
    }
}
impl test_moderation::ModerationRuntimeProviderV1 for ServerTestModerationHandoffBoundary {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_moderation::ModerationRuntimeProviderQualificationV1,
        test_moderation::ModerationRuntimeProviderReadinessErrorV1,
    > {
        let qualification_call = self.qualification_calls.fetch_add(1, Ordering::AcqRel);
        let drifted = (matches!(
            self.mode,
            ServerTestModerationDeliveryMode::DriftOnSecondQualification
        ) && qualification_call != 0)
            || (matches!(
                self.mode,
                ServerTestModerationDeliveryMode::DriftAfterDelivery
            ) && self.delivered.load(Ordering::Acquire));
        Ok(
            test_moderation::ModerationRuntimeProviderQualificationV1::new(
                7 + u64::from(drifted),
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_moderation_runtime::ModerationDurableHandoffBoundaryV1
    for ServerTestModerationHandoffBoundary
{
    fn deliver_once(
        &self,
        request: &test_moderation_runtime::ModerationDurableHandoffRequestV1,
    ) -> Result<
        test_moderation_runtime::ModerationDurableHandoffOutcomeV1,
        test_moderation_runtime::ModerationDurableHandoffFailureV1,
    > {
        use test_moderation_runtime::{
            ModerationDurableHandoffFailureV1 as Failure,
            ModerationDurableHandoffOutcomeV1 as Outcome,
        };
        self.delivery_calls.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            ServerTestModerationDeliveryMode::NotDelivered => {
                return Err(Failure::NotDelivered);
            }
            ServerTestModerationDeliveryMode::Ambiguous => {
                return Err(Failure::Ambiguous);
            }
            ServerTestModerationDeliveryMode::Permanent => {
                return Err(Failure::Permanent);
            }
            ServerTestModerationDeliveryMode::Exact
            | ServerTestModerationDeliveryMode::DriftAfterDelivery
            | ServerTestModerationDeliveryMode::DriftOnSecondQualification
            | ServerTestModerationDeliveryMode::InvalidReceipt => {}
        }
        if request.handoff.kind != self.kind
            || norito::to_bytes(&request.handoff).ok().as_deref()
                != Some(request.canonical_handoff.as_slice())
        {
            return Err(Failure::Permanent);
        }
        let mut retained = self.retained.lock().expect("handoff retention lock");
        if let Some((_, canonical)) = retained
            .iter()
            .find(|(handoff_id, _)| *handoff_id == request.handoff.handoff_id)
        {
            return if canonical == &request.canonical_handoff {
                Ok(Outcome::AlreadyDelivered)
            } else {
                Err(Failure::Permanent)
            };
        }
        retained.push((
            request.handoff.handoff_id,
            request.canonical_handoff.clone(),
        ));
        self.delivered.store(true, Ordering::Release);
        Ok(Outcome::Delivered)
    }
    fn publish_archive_head_once(
        &self,
        request: &test_moderation_runtime::ModerationDurableArchiveHeadPublicationRequestV1,
    ) -> Result<
        test_moderation_runtime::ModerationDurableHandoffOutcomeV1,
        test_moderation_runtime::ModerationDurableHandoffFailureV1,
    > {
        use test_moderation_runtime::{
            ModerationDurableHandoffFailureV1 as Failure,
            ModerationDurableHandoffOutcomeV1 as Outcome,
        };
        self.delivery_calls.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            ServerTestModerationDeliveryMode::NotDelivered => {
                return Err(Failure::NotDelivered);
            }
            ServerTestModerationDeliveryMode::Ambiguous => {
                return Err(Failure::Ambiguous);
            }
            ServerTestModerationDeliveryMode::Permanent => {
                return Err(Failure::Permanent);
            }
            ServerTestModerationDeliveryMode::Exact
            | ServerTestModerationDeliveryMode::DriftAfterDelivery
            | ServerTestModerationDeliveryMode::DriftOnSecondQualification
            | ServerTestModerationDeliveryMode::InvalidReceipt => {}
        }
        if self.kind != test_moderation::ModerationTerminalHandoffKindV1::Publication
            || norito::to_bytes(&request.head).ok().as_deref()
                != Some(request.canonical_head.as_slice())
            || request
                .head
                .verify(
                    &request.head.archive_handle,
                    test_moderation::ModerationRuntimeProviderQualificationV1::new(
                        request.head.archive_revision,
                        request.head.archive_policy_digest,
                    ),
                    request.head.archive_id,
                    request.head.archive_public_key,
                )
                .is_err()
        {
            return Err(Failure::Permanent);
        }
        let mut heads = self
            .published_heads
            .lock()
            .expect("published archive-head retention lock");
        if let Some(existing) = heads
            .iter()
            .find(|head| head.operation_id == request.head.operation_id)
        {
            return if existing == &request.head {
                Ok(Outcome::AlreadyDelivered)
            } else {
                Err(Failure::Permanent)
            };
        }
        let monotonic = heads
            .last()
            .map_or(request.head.generation == 1, |previous| {
                previous.generation.checked_add(1) == Some(request.head.generation)
                    && request.head.predecessor_head_digest == Some(previous.head_digest)
                    && request.head.predecessor_operation_id == Some(previous.operation_id)
                    && request.head.predecessor_chain_commitment == Some(previous.chain_commitment)
                    && request.head.source_checkpoint_generation
                        > previous.source_checkpoint_generation
                    && request.head.network_id == previous.network_id
            });
        if !monotonic {
            return Err(Failure::Permanent);
        }
        heads.push(request.head.clone());
        self.delivered.store(true, Ordering::Release);
        Ok(Outcome::Delivered)
    }
    fn read_published_archive_head(
        &self,
    ) -> Result<
        Option<test_moderation::ModerationPanelNotificationArchiveHeadV1>,
        test_moderation_runtime::ModerationDurableHandoffFailureV1,
    > {
        Ok(self
            .published_heads
            .lock()
            .expect("published archive-head retention lock")
            .last()
            .cloned())
    }
}
type RetainedPanelDeliveryV1 = (
    [u8; 32],
    Vec<u8>,
    test_moderation::ModerationPanelNotificationDeliveryReceiptV1,
);
#[derive(Debug)]
struct ServerTestModerationPanelBoundary {
    handle: String,
    mode: ServerTestModerationDeliveryMode,
    qualification_calls: AtomicU64,
    delivery_calls: AtomicU64,
    delivered: AtomicBool,
    retained: Mutex<Vec<RetainedPanelDeliveryV1>>,
}
impl ServerTestModerationPanelBoundary {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_MODERATION_PANEL_HANDLE.to_owned(),
            mode: ServerTestModerationDeliveryMode::Exact,
            qualification_calls: AtomicU64::new(0),
            delivery_calls: AtomicU64::new(0),
            delivered: AtomicBool::new(false),
            retained: Mutex::new(Vec::new()),
        }
    }
    fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = handle.into();
        self
    }
    fn with_mode(mut self, mode: ServerTestModerationDeliveryMode) -> Self {
        self.mode = mode;
        self
    }
}
impl test_moderation::ModerationRuntimeProviderV1 for ServerTestModerationPanelBoundary {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_moderation::ModerationRuntimeProviderQualificationV1,
        test_moderation::ModerationRuntimeProviderReadinessErrorV1,
    > {
        let qualification_call = self.qualification_calls.fetch_add(1, Ordering::AcqRel);
        let drifted = (matches!(
            self.mode,
            ServerTestModerationDeliveryMode::DriftOnSecondQualification
        ) && qualification_call != 0)
            || (matches!(
                self.mode,
                ServerTestModerationDeliveryMode::DriftAfterDelivery
            ) && self.delivered.load(Ordering::Acquire));
        Ok(
            test_moderation::ModerationRuntimeProviderQualificationV1::new(
                7 + u64::from(drifted),
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_moderation_runtime::ModerationDurablePanelNotificationBoundaryV1
    for ServerTestModerationPanelBoundary
{
    fn deliver_once(
        &self,
        request: &test_moderation_runtime::ModerationDurablePanelNotificationRequestV1,
    ) -> Result<
        test_moderation::ModerationPanelNotificationDeliveryReceiptV1,
        test_moderation::ModerationPanelNotificationFailureV1,
    > {
        use test_moderation::ModerationPanelNotificationFailureV1 as Failure;
        self.delivery_calls.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            ServerTestModerationDeliveryMode::NotDelivered => {
                return Err(Failure::NotDelivered);
            }
            ServerTestModerationDeliveryMode::Ambiguous => {
                return Err(Failure::Ambiguous);
            }
            ServerTestModerationDeliveryMode::Permanent => {
                return Err(Failure::Permanent);
            }
            ServerTestModerationDeliveryMode::Exact
            | ServerTestModerationDeliveryMode::DriftAfterDelivery
            | ServerTestModerationDeliveryMode::DriftOnSecondQualification
            | ServerTestModerationDeliveryMode::InvalidReceipt => {}
        }
        if norito::to_bytes(&request.notification).ok().as_deref()
            != Some(request.canonical_notification.as_slice())
        {
            return Err(Failure::Permanent);
        }
        let mut retained = self.retained.lock().expect("notification retention lock");
        if let Some((_, canonical, receipt)) = retained.iter().find(|(notification_id, _, _)| {
            *notification_id == request.notification.notification_id
        }) {
            return if canonical == &request.canonical_notification {
                Ok(*receipt)
            } else {
                Err(Failure::Permanent)
            };
        }
        let mut receipt = test_moderation::ModerationPanelNotificationDeliveryReceiptV1 {
            notification_id: request.notification.notification_id,
            receipt_digest: [0x6C; 32],
            delivered_at_unix_ms: request.notification.source_occurred_at_unix_ms + 1,
        };
        if matches!(self.mode, ServerTestModerationDeliveryMode::InvalidReceipt) {
            receipt.notification_id = [0xFE; 32];
        }
        retained.push((
            request.notification.notification_id,
            request.canonical_notification.clone(),
            receipt,
        ));
        self.delivered.store(true, Ordering::Release);
        Ok(receipt)
    }
}
#[derive(Debug)]
struct ServerTestModerationKeyWrapper {
    handle: String,
    revision: AtomicU64,
    policy_digest: [u8; 32],
    active_key_id: String,
    drift_after_wrap: bool,
    drift_after_unwrap: bool,
    zero_unwrap_output: bool,
    wrap_failure: Option<node::ModerationQuarantineKeyOperationErrorV1>,
    unwrap_failure: Option<node::ModerationQuarantineKeyOperationErrorV1>,
}
impl ServerTestModerationKeyWrapper {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_MODERATION_HANDLE.to_owned(),
            revision: AtomicU64::new(7),
            policy_digest: TEST_POLICY_DIGEST,
            active_key_id: SERVER_TEST_MODERATION_KEY_ID.to_owned(),
            drift_after_wrap: false,
            drift_after_unwrap: false,
            zero_unwrap_output: false,
            wrap_failure: None,
            unwrap_failure: None,
        }
    }
    fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = handle.into();
        self
    }
    fn with_revision(self, revision: u64) -> Self {
        self.revision.store(revision, Ordering::Release);
        self
    }
    fn with_active_key_id(mut self, active_key_id: impl Into<String>) -> Self {
        self.active_key_id = active_key_id.into();
        self
    }
    fn with_post_wrap_drift(mut self) -> Self {
        self.drift_after_wrap = true;
        self
    }
    fn with_post_unwrap_drift(mut self) -> Self {
        self.drift_after_unwrap = true;
        self
    }
    fn with_zero_unwrap_output(mut self) -> Self {
        self.zero_unwrap_output = true;
        self
    }
    fn with_wrap_failure(mut self, failure: node::ModerationQuarantineKeyOperationErrorV1) -> Self {
        self.wrap_failure = Some(failure);
        self
    }
    fn with_unwrap_failure(
        mut self,
        failure: node::ModerationQuarantineKeyOperationErrorV1,
    ) -> Self {
        self.unwrap_failure = Some(failure);
        self
    }
}
impl node::ModerationQuarantineKeyWrapper for ServerTestModerationKeyWrapper {
    fn provider_handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        node::ModerationQuarantineKeyProviderQualificationV1,
        node::ModerationQuarantineKeyProviderReadinessErrorV1,
    > {
        Ok(node::ModerationQuarantineKeyProviderQualificationV1::new(
            self.revision.load(Ordering::Acquire),
            self.policy_digest,
        ))
    }
    fn active_key_id(&self) -> &str {
        &self.active_key_id
    }
    fn wrap_dek(
        &self,
        context_digest: [u8; 32],
        dek: &[u8; 32],
    ) -> Result<Vec<u8>, node::ModerationQuarantineKeyOperationErrorV1> {
        if let Some(failure) = self.wrap_failure {
            return Err(failure);
        }
        let mut wrapped = context_digest.to_vec();
        wrapped.extend(
            dek.iter()
                .zip(context_digest)
                .map(|(plain, context)| plain ^ context),
        );
        if self.drift_after_wrap {
            self.revision.store(8, Ordering::Release);
        }
        Ok(wrapped)
    }
    fn unwrap_dek(
        &self,
        key_id: &str,
        context_digest: [u8; 32],
        wrapped_dek: &[u8],
    ) -> Result<[u8; 32], node::ModerationQuarantineKeyOperationErrorV1> {
        if let Some(failure) = self.unwrap_failure {
            return Err(failure);
        }
        if key_id != self.active_key_id
            || wrapped_dek.len() != 64
            || wrapped_dek[..32] != context_digest
        {
            return Err(node::ModerationQuarantineKeyOperationErrorV1::Rejected);
        }
        let mut dek = [0_u8; 32];
        for (output, (wrapped, context)) in dek
            .iter_mut()
            .zip(wrapped_dek[32..].iter().zip(context_digest))
        {
            *output = wrapped ^ context;
        }
        if self.zero_unwrap_output {
            dek.fill(0);
        }
        if self.drift_after_unwrap {
            self.revision.store(8, Ordering::Release);
        }
        Ok(dek)
    }
}

include!("por_replay_archive_fixture_schema_tests.rs");
