#[cfg(not(target_pointer_width = "64"))]
compile_error!("the V1 runtime-provider broker requires a 64-bit address space");
use crate::{
    GlobalBeaconPartialSignerBrokerBackendErrorV1, IrohaRuntimeDeps,
    ParliamentTlePartialReleaseSignerBrokerBackendErrorV1, RuntimeProviderBrokerBackendsV1,
    RuntimeProviderBrokerLifecycleV1, RuntimeProviderBrokerReadinessErrorV1,
    RuntimeProviderBrokerServerErrorV1,
    runtime_provider_registry::{
        EvidenceViewerWebAuthnBindingV1, IrohaRuntimeProviderBindingV1,
        IrohaRuntimeProviderBindingsV1, IrohaRuntimeProviderRegistryErrorV1,
        IrohaRuntimeProviderSlotV1, ProviderIngestSourceLimitsV1,
        RUNTIME_PROVIDER_CATALOG_MAX_ENTRIES_V1,
    },
};
use iroha_config::parameters::{
    defaults::sorafs::storage::provider_ingest_runtime::outbox as provider_ingest_outbox_defaults,
    validate_webauthn_origin_v1, validate_webauthn_rp_id_v1,
};
use iroha_data_model::NetworkId;
use norito::{
    DecodeLimits, NoritoDeserialize, NoritoSerialize,
    codec::{Decode, Encode},
};
use sorafs_manifest::GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1;
use std::{
    cell::RefCell,
    fmt,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
#[expect(
    clippy::cast_possible_truncation,
    reason = "this module rejects non-64-bit targets before projecting fixed u64 bounds"
)]
const fn fixed_u64_bound(value: u64) -> usize {
    value as usize
}
const BROKER_MAGIC_V1: [u8; 8] = *b"IRPBRK01";
const BROKER_VERSION_V1: u16 = 1;
const FRAME_KIND_HANDSHAKE_REQUEST_V1: u8 = 1;
const FRAME_KIND_HANDSHAKE_RESPONSE_V1: u8 = 2;
const FRAME_KIND_OPERATION_REQUEST_V1: u8 = 3;
const FRAME_KIND_OPERATION_RESPONSE_V1: u8 = 4;
const FRAME_KIND_PROVIDER_INGEST_SOURCE_CHUNK_V1: u8 = 5;
const FRAME_KIND_PROVIDER_INGEST_SOURCE_TRAILER_V1: u8 = 6;
const MAX_HANDSHAKE_FRAME_BYTES_V1: usize = 256 * 1024;
// Qualification requests are canonical unit values and replies contain only
// bounded public provider metadata. Keep this shared operation far below the
// generic unary ceiling so a provider probe cannot reserve a 33 MiB decode frame.
const MAX_QUALIFICATION_FRAME_BYTES_V1: usize = 80 * 1024;
// Appeal-finance's local data model permits a 512 MiB canonical recovery
// checkpoint, while the V1 broker protocol intentionally admits only the
// fixed unary ceiling selected in `operation_frame_limit`; an exact
// deployment binding may lower that limit further.
// Retaining the payload, its nested envelope, its typed decode, and a
// canonical re-encode at the full semantic maximum would exceed the
// broker's audited live-memory budget. This lower unary transport ceiling
// is a V1 wire invariant; supporting larger checkpoints requires a
// separately versioned authenticated streaming protocol.
const MAX_APPEAL_FINANCE_CHECKPOINT_BYTES_V1: usize = 512 * 1024 * 1024;
const MAX_APPEAL_FINANCE_CHECKPOINT_RECORD_BYTES_V1: usize =
    MAX_APPEAL_FINANCE_CHECKPOINT_BYTES_V1
        + fixed_u64_bound(
            sorafs_node::appeal_finance_transaction_forwarder::
                APPEAL_FINANCE_SEALED_CHECKPOINT_RECORD_MAX_OVERHEAD_BYTES_V1,
        );
const MAX_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1: usize =
    MAX_APPEAL_FINANCE_CHECKPOINT_RECORD_BYTES_V1 + 128 * 1024;
const MAX_BROKER_FRAME_ENVELOPE_BYTES_V1: usize = 128 * 1024;
const MAX_BROKER_UNARY_PAYLOAD_BYTES_V1: usize = 32 * 1024 * 1024;
const MAX_BROKER_UNARY_FRAME_BYTES_V1: usize = 33 * 1024 * 1024;
const MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_BYTES_V1: usize =
    fixed_u64_bound(
        iroha_config::parameters::defaults::torii::
            SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES,
    );
const MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1: usize =
    MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_BYTES_V1
        + fixed_u64_bound(
            sorafs_node::appeal_finance_transaction_forwarder::
                APPEAL_FINANCE_SEALED_CHECKPOINT_RECORD_MAX_OVERHEAD_BYTES_V1,
        )
        + MAX_BROKER_FRAME_ENVELOPE_BYTES_V1;
const MAX_BROKER_PROVIDER_INGEST_CHECKPOINT_BYTES_V1: usize =
    fixed_u64_bound(provider_ingest_outbox_defaults::CHECKPOINT_MAX_BYTES_LIMIT);
const MAX_BROKER_EVIDENCE_VIEWER_BULK_BYTES_V1: usize = MAX_EVIDENCE_VIEWER_ARCHIVE_BYTES_V1;
const MAX_BROKER_SHARED_DECODE_BYTES_V1: usize = if PROVIDER_INGEST_CHECKPOINT_DECODE_POLICY_V1
    .max_composed_bytes
    > GOVERNANCE_SEALED_STATE_DECODE_POLICY_V1.max_composed_bytes
{
    PROVIDER_INGEST_CHECKPOINT_DECODE_POLICY_V1.max_composed_bytes
} else {
    GOVERNANCE_SEALED_STATE_DECODE_POLICY_V1.max_composed_bytes
};
// The server admits raw request bodies under a separate process-wide
// semaphore before acquiring a composed decode reservation. This explicit
// sum is the maximum broker-owned raw plus decoded/canonical operation
// memory across all sessions; a stalled body can consume only the raw
// half, never the much larger decode pool.
const MAX_BROKER_PROCESS_OPERATION_BYTES_V1: usize =
    MAX_OPERATION_FRAME_BYTES_V1 + MAX_BROKER_SHARED_DECODE_BYTES_V1;
const MAX_PROVIDER_INGEST_SOURCE_PLAN_HEAP_BYTES_V1: usize = 256 * 1024 * 1024;
// The source-plan ceiling is independent of Governance DAG sealed-state
// slots, whose limits are selected by
// `governance_dag_sealed_state_payload_max_bytes_v1`. In V1 the canonical
// CAR plan is unary metadata and is permanently capped below the broker
// frame ceiling; larger plans require a separately versioned authenticated
// streaming-plan protocol rather than raising this wire limit.
const MAX_PROVIDER_INGEST_SOURCE_PLAN_PAYLOAD_BYTES_V1: usize = MAX_BROKER_UNARY_PAYLOAD_BYTES_V1;
// Keep external-signer transport aligned with the canonical Governance encoders.
// Valid schema payloads must not fail only because signing crossed processes.
const MAX_SIGNING_PAYLOAD_BYTES_V1: usize =
    sorafs_manifest::GOVERNANCE_DAG_SIGNING_PAYLOAD_MAX_BYTES_V1;
const MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1: usize =
    MAX_SIGNING_PAYLOAD_BYTES_V1 + MAX_BROKER_FRAME_ENVELOPE_BYTES_V1;
const MAX_GOVERNANCE_SEALED_STATE_PAYLOAD_BYTES_V1: usize =
    sorafs_node::governance_dag_sealed_state_payload_max_bytes_v1(
        sorafs_node::GovernanceDagSealedStateSlot::Checkpoint,
    );
const MAX_GOVERNANCE_SEALED_STATE_RECORD_OVERHEAD_BYTES_V1: usize = 4 * 1024;
const MAX_GOVERNANCE_SEALED_STATE_RECORD_BYTES_V1: usize =
    MAX_GOVERNANCE_SEALED_STATE_PAYLOAD_BYTES_V1
        + MAX_GOVERNANCE_SEALED_STATE_RECORD_OVERHEAD_BYTES_V1;
const MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1: usize =
    MAX_GOVERNANCE_SEALED_STATE_RECORD_BYTES_V1 + MAX_BROKER_FRAME_ENVELOPE_BYTES_V1;
const MAX_CHAIN_ID_BYTES_V1: usize = 1024;
const MAX_PROVIDER_HANDLE_BYTES_V1: usize = 1024;
const MAX_CATALOG_ENTRIES_V1: usize = RUNTIME_PROVIDER_CATALOG_MAX_ENTRIES_V1;
const MAX_BOOTLE_LANTERN_AUTH_CREDENTIAL_BYTES_V1: usize = 4 * 1024;
const MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1: usize = 256 * 1024;
// Complete public adaptive-DKG transcripts are bounded unary metadata. The
// ceiling covers the maximum first-release committee transcript plus Norito
// framing while keeping signer operations far below the generic 32 MiB cap.
const MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1: usize = 4 * 1024 * 1024;
const BOOTLE_LANTERN_AUTHORIZATION_BYTES_V1: usize =
    iroha_core_privacy::privacy_engines::bootle_lantern::codec::BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1;
const BOOTLE_LANTERN_REQUEST_BYTES_V1: usize =
    iroha_core_privacy::privacy_engines::bootle_lantern::codec::BLIND_ISSUANCE_REQUEST_BYTES_V1;
const BOOTLE_LANTERN_RESPONSE_BYTES_V1: usize =
    iroha_core_privacy::privacy_engines::bootle_lantern::codec::BLIND_ISSUANCE_RESPONSE_BYTES_V1;
const MAX_PROVIDER_INGEST_ACCOUNT_BYTES_V1: usize =
    fixed_u64_bound(provider_ingest_outbox_defaults::COMPLETION_ACCOUNT_ID_MAX_CANONICAL_BYTES_V1);
const MAX_PROVIDER_INGEST_AUTHORITY_BYTES_V1: usize =
    MAX_PROVIDER_INGEST_ACCOUNT_BYTES_V1 * 2 + 512;
const MAX_PROVIDER_INGEST_PUBLIC_KEY_BYTES_V1: usize = 16 * 1024;
const MAX_PROVIDER_INGEST_CHECKPOINT_BYTES_V1: usize =
    fixed_u64_bound(provider_ingest_outbox_defaults::CHECKPOINT_MAX_BYTES_LIMIT);
const MAX_PROVIDER_INGEST_SIGNED_TRANSACTION_BYTES_V1: usize =
    fixed_u64_bound(provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_LIMIT);
const MAX_PROVIDER_INGEST_RETENTION_APPROVAL_BYTES_V1: usize = 64 * 1024;
const MAX_PROVIDER_INGEST_CONTROL_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1: usize =
    MAX_PROVIDER_INGEST_SIGNED_TRANSACTION_BYTES_V1 + 128 * 1024;
const MAX_OPERATION_FRAME_BYTES_V1: usize =
    if MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1 > MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1 {
        MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1
    } else {
        MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1
    };
const MAX_PROVIDER_INGEST_CHECKPOINT_RECORD_BYTES_V1: usize =
    MAX_PROVIDER_INGEST_CHECKPOINT_BYTES_V1
        + fixed_u64_bound(
            sorafs_node::provider_ingest_outbox::
                PROVIDER_INGEST_SEALED_CHECKPOINT_RECORD_MAX_OVERHEAD_BYTES_V1,
        );
const MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1: usize =
    MAX_PROVIDER_INGEST_CHECKPOINT_RECORD_BYTES_V1 + MAX_BROKER_FRAME_ENVELOPE_BYTES_V1;
const MAX_PROVIDER_INGEST_RETENTION_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1: usize = 64 * 1024;
const MAX_REPUTATION_RETENTION_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_REPUTATION_JOURNAL_INSTRUCTION_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1: usize = 128 * 1024 * 1024;
const MAX_REPUTATION_JOURNAL_CHECKPOINT_BYTES_V1: usize = fixed_u64_bound(
    sorafs_node::reputation::runtime::REPUTATION_JOURNAL_PRODUCER_MAX_CHECKPOINT_BYTES_V1,
);
const MAX_REPUTATION_JOURNAL_CHECKPOINT_RECORD_BYTES_V1: usize =
    MAX_REPUTATION_JOURNAL_CHECKPOINT_BYTES_V1
        + fixed_u64_bound(
            sorafs_node::reputation::runtime::
                REPUTATION_JOURNAL_SEALED_CHECKPOINT_MAX_OVERHEAD_BYTES_V1,
        );
const MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1: usize =
    MAX_REPUTATION_JOURNAL_CHECKPOINT_RECORD_BYTES_V1 + MAX_BROKER_FRAME_ENVELOPE_BYTES_V1;
// The largest billing payload is a canonical 128 MiB checkpoint in its
// bounded epoch-witness wrapper. Keep independent framing overhead without
// inheriting appeal finance's 512 MiB operation ceiling.
const MAX_BILLING_RUNTIME_FRAME_BYTES_V1: usize = fixed_u64_bound(
    sorafs_node::hedging_billing_service::HEDGING_BILLING_MAX_CHECKPOINT_BYTES_V1,
) + fixed_u64_bound(
    sorafs_node::hedging_billing_service::HEDGING_BILLING_EPOCH_WITNESS_WRAPPER_MAX_BYTES_V1,
) + 128 * 1024;
const MAX_BILLING_CONTROL_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_PROVIDER_INGEST_SOURCE_REQUEST_BYTES_V1: usize = 64 * 1024;
const MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1: usize =
    MAX_PROVIDER_INGEST_SOURCE_PLAN_PAYLOAD_BYTES_V1;
const MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1: usize =
    MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1
        + sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES
        + 128 * 1024;
const MAX_PROVIDER_INGEST_SOURCE_CHUNK_PAYLOAD_BYTES_V1: usize = 256 * 1024;
const MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1: usize = 320 * 1024;
const MAX_PROVIDER_INGEST_SOURCE_TRAILER_FRAME_BYTES_V1: usize = 64 * 1024;
const MAX_PROVIDER_INGEST_SOURCE_STREAMS_V1: u32 = 1_024;
// These bounds mirror the canonical moderation quarantine object envelope.
// The broker validates them independently before any key-provider operation.
const MAX_MODERATION_QUARANTINE_KEY_ID_BYTES_V1: usize = 512;
const MAX_MODERATION_QUARANTINE_WRAPPED_DEK_BYTES_V1: usize = 64 * 1024;
const MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1: usize = 72 * 1024;
const MAX_MODERATION_QUARANTINE_FRAME_BYTES_V1: usize = 80 * 1024;
const MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1: usize = 64 * 1024;
const MAX_MODERATION_HANDOFF_FRAME_BYTES_V1: usize =
    2 * MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1 + 64 * 1024;
const MAX_MODERATION_PANEL_NOTIFICATION_CANONICAL_BYTES_V1: usize = 64 * 1024;
const MAX_MODERATION_PANEL_NOTIFICATION_FRAME_BYTES_V1: usize =
    2 * MAX_MODERATION_PANEL_NOTIFICATION_CANONICAL_BYTES_V1 + 64 * 1024;
const MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1: usize = 96 * 1024;
const MAX_EVIDENCE_VIEWER_CONTROL_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_EVIDENCE_VIEWER_CLAIMS_BYTES_V1: usize = 4 * 1024;
const MAX_EVIDENCE_VIEWER_RECEIPT_MESSAGE_BYTES_V1: usize = 1024;
const MAX_EVIDENCE_VIEWER_CHECKPOINT_BYTES_V1: usize =
    fixed_u64_bound(sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_CHECKPOINT_BYTES_V1);
const MAX_EVIDENCE_VIEWER_ARCHIVE_BYTES_V1: usize =
    MAX_EVIDENCE_VIEWER_CHECKPOINT_BYTES_V1 + 16 * 1024;
const MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1: usize =
    MAX_EVIDENCE_VIEWER_ARCHIVE_BYTES_V1 + 128 * 1024;
const MAX_GOVERNANCE_REQUEST_AUTH_FRAME_BYTES_V1: usize = 32 * 1024;
const MAX_NATIVE_TRANSACTION_PAYLOAD_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_NATIVE_SIGNED_TRANSACTION_BYTES_V1: usize =
    MAX_NATIVE_TRANSACTION_PAYLOAD_BYTES_V1 + 1024 * 1024;
const MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1: usize =
    MAX_NATIVE_SIGNED_TRANSACTION_BYTES_V1 + 128 * 1024;
const MAX_STREAM_TOKEN_FRAME_BYTES_V1: usize = 8 * 1024;
const MAX_APPEAL_FINANCE_TRANSACTION_BYTES_V1: usize =
    sorafs_node::appeal_finance_transaction_forwarder::
        APPEAL_FINANCE_TRANSACTION_MAX_CANONICAL_BYTES_V1;
const MAX_APPEAL_FINANCE_TRANSACTION_FRAME_BYTES_V1: usize =
    MAX_APPEAL_FINANCE_TRANSACTION_BYTES_V1 + 128 * 1024;
const MAX_POTR_SIGNING_PAYLOAD_BYTES_V1: usize = 64 * 1024;
const MAX_POTR_PUBLIC_KEY_BYTES_V1: usize = 16 * 1024;
const MAX_POTR_SIGNATURE_BYTES_V1: usize = 16 * 1024;
const MAX_POTR_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_GATEWAY_ACME_HOSTNAMES_V1: usize = 128;
const MAX_GATEWAY_ACME_HOSTNAME_BYTES_V1: usize = 253;
const MAX_GATEWAY_ACME_EMAIL_BYTES_V1: usize = 320;
const MAX_GATEWAY_ACME_URL_BYTES_V1: usize = 2_048;
const MAX_GATEWAY_ACME_DNS_PROVIDER_ID_BYTES_V1: usize = 256;
const MAX_GATEWAY_ACME_CERTIFICATE_PEM_BYTES_V1: usize = 4 * 1024 * 1024;
const MAX_GATEWAY_ACME_PRIVATE_KEY_PEM_BYTES_V1: usize = 1024 * 1024;
const MAX_GATEWAY_ACME_ECH_CONFIG_BYTES_V1: usize = 1024 * 1024;
const MAX_GATEWAY_ACME_FRAME_BYTES_V1: usize = 7 * 1024 * 1024;
const MAX_GATEWAY_COMPLIANCE_URL_BYTES_V1: usize = 2_048;
const MAX_GATEWAY_COMPLIANCE_DNS_ADDRESSES_V1: usize = 32;
const MAX_GATEWAY_COMPLIANCE_BODY_BYTES_V1: usize =
    sorafs_manifest::gateway_compliance::MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1;
const MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1: usize =
    MAX_GATEWAY_COMPLIANCE_BODY_BYTES_V1 + 128 * 1024;
const MAX_POP_RUNTIME_FRAME_BYTES_V1: usize = 8 * 1024 * 1024;
const MAX_POP_WRAPPED_DEK_BYTES_V1: usize =
    sorafs_node::pop_credentials::POP_WRAPPED_DEK_MAX_BYTES_V1;
const MAX_POP_REGISTRY_OPERATION_BYTES_V1: usize =
    sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1 + 128 * 1024;
const MAX_POP_PROJECTION_BYTES_V1: usize = 4 * 1024 * 1024;
// The retained PoR record contains bounded finalized challenge/verdict
// material. The separate successor-proof ceiling mirrors the production
// config hard limit and is checked before decoding the inner receipt list.
const MAX_POR_REPLAY_ARCHIVE_RECORD_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_POR_REPLAY_ARCHIVE_SUCCESSOR_PROOF_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1: usize = MAX_POR_REPLAY_ARCHIVE_RECORD_BYTES_V1
    + MAX_POR_REPLAY_ARCHIVE_SUCCESSOR_PROOF_BYTES_V1
    + 256 * 1024;
const MAX_TRANSPARENCY_PRF_FRAME_BYTES_V1: usize = 64 * 1024;
const MAX_PRIVACY_RELEASE_ANCHOR_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_TRANSPARENCY_LEADER_LEASE_FRAME_BYTES_V1: usize = 128 * 1024;
const MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1: usize =
    sorafs_manifest::GOVERNANCE_DAG_SOURCE_PAYLOAD_MAX_CANONICAL_BYTES_V1;
const MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1: usize =
    MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1 + 256 * 1024;
const MAX_GOVERNANCE_BULK_FRAME_BYTES_V1: usize =
    if MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1 > MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1 {
        MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1
    } else {
        MAX_FENCED_PRIVACY_PUBLICATION_FRAME_BYTES_V1
    };
const MAX_FENCED_PRIVACY_HEAD_EVIDENCE_ITEMS_V1: usize = 4_096;
const MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1: usize = 2 * 1024 * 1024;
const MAX_EVIDENCE_VIEWER_ORIGINS_V1: usize = 16;
// This mirrors the canonical CAR planner's fixed file ceiling. The plan's
// own allocation-free validator remains authoritative after reconstruction.
const MAX_PROVIDER_INGEST_SOURCE_PLAN_FILES_V1: usize = 1_000_000;
const _: () = assert!(
    MAX_OPERATION_FRAME_BYTES_V1 <= u32::MAX as usize,
    "V1 operation frames must fit their u32 length prefix"
);
const _: () = assert!(
    MAX_OPERATION_FRAME_BYTES_V1 <= tokio::sync::Semaphore::MAX_PERMITS,
    "V1 raw-frame ceiling must fit the Tokio semaphore"
);
const _: () = assert!(
    MAX_BROKER_PROCESS_OPERATION_BYTES_V1 <= tokio::sync::Semaphore::MAX_PERMITS,
    "V1 combined process ceiling must fit the platform semaphore counter"
);
const fn composed_decode_cap(
    max_blob_bytes: usize,
    max_total_allocated_bytes: usize,
    live_decode_layers: usize,
) -> usize {
    let layer_bytes = match max_blob_bytes.checked_add(max_total_allocated_bytes) {
        Some(bytes) => bytes,
        None => panic!("decode-layer byte cap overflow"),
    };
    let decoded_bytes = match layer_bytes.checked_mul(live_decode_layers) {
        Some(bytes) => bytes,
        None => panic!("live decode-layer cap overflow"),
    };
    match max_blob_bytes.checked_add(decoded_bytes) {
        Some(bytes) => bytes,
        None => panic!("composed live-memory cap overflow"),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecodeResourcePhaseCountsV1 {
    raw_frames: usize,
    retained_values: usize,
    encoded_copies: usize,
    decoded_values: usize,
}
// One admission covers either a complete client call (request construction,
// response validation, and caller result decode) or a complete server
// iteration (request validation, dispatch, response validation, and
// response encoding). These counts deliberately cover the longest nested
// validation paths: four retained caller/backend values, twelve canonical
// request/result/envelope copies, and sixteen decode-plus-reencode passes.
// Fenced privacy publication is the longest retained-value path because
// request validation, dispatch, and response validation each reconstruct
// one independently owned canonical publication request.
const OPERATION_CUMULATIVE_PHASES_V1: DecodeResourcePhaseCountsV1 = DecodeResourcePhaseCountsV1 {
    raw_frames: 1,
    retained_values: 4,
    encoded_copies: 12,
    decoded_values: 16,
};
const FENCED_PRIVACY_SERVER_PHASES_V1: DecodeResourcePhaseCountsV1 = DecodeResourcePhaseCountsV1 {
    raw_frames: 1,
    retained_values: 3,
    encoded_copies: 5,
    decoded_values: 12,
};
// Concrete deepest-path audits include response-carried client validation
// and reconciliation work, not just the initial request/response exchange.
const BILLING_PUBLISH_DEEPEST_PHASES_V1: DecodeResourcePhaseCountsV1 =
    DecodeResourcePhaseCountsV1 {
        raw_frames: 1,
        retained_values: 1,
        encoded_copies: 12,
        decoded_values: 6,
    };
const REPUTATION_THRESHOLD_DEEPEST_PHASES_V1: DecodeResourcePhaseCountsV1 =
    DecodeResourcePhaseCountsV1 {
        raw_frames: 1,
        retained_values: 1,
        encoded_copies: 9,
        decoded_values: 6,
    };
const fn phase_counts_fit(
    required: DecodeResourcePhaseCountsV1,
    inventory: DecodeResourcePhaseCountsV1,
) -> bool {
    required.raw_frames <= inventory.raw_frames
        && required.retained_values <= inventory.retained_values
        && required.encoded_copies <= inventory.encoded_copies
        && required.decoded_values <= inventory.decoded_values
}
const _: () = assert!(
    phase_counts_fit(
        FENCED_PRIVACY_SERVER_PHASES_V1,
        OPERATION_CUMULATIVE_PHASES_V1,
    ),
    "fenced privacy server phases must fit the operation inventory"
);
const _: () = assert!(
    phase_counts_fit(
        BILLING_PUBLISH_DEEPEST_PHASES_V1,
        OPERATION_CUMULATIVE_PHASES_V1,
    ),
    "billing publication deepest phases must fit the operation inventory"
);
const _: () = assert!(
    phase_counts_fit(
        REPUTATION_THRESHOLD_DEEPEST_PHASES_V1,
        OPERATION_CUMULATIVE_PHASES_V1,
    ),
    "reputation threshold deepest phases must fit the operation inventory"
);
const CONTROL_CUMULATIVE_PHASES_V1: DecodeResourcePhaseCountsV1 = DecodeResourcePhaseCountsV1 {
    raw_frames: 1,
    retained_values: 0,
    encoded_copies: 2,
    decoded_values: 4,
};
const SOURCE_STREAM_CUMULATIVE_PHASES_V1: DecodeResourcePhaseCountsV1 =
    DecodeResourcePhaseCountsV1 {
        raw_frames: 1,
        retained_values: 1,
        encoded_copies: 2,
        decoded_values: 2,
    };
const fn cumulative_decode_cap(
    max_blob_bytes: usize,
    max_total_allocated_bytes: usize,
    phases: DecodeResourcePhaseCountsV1,
) -> usize {
    let raw_and_retained = match phases.raw_frames.checked_add(phases.retained_values) {
        Some(count) => count,
        None => panic!("canonical-copy phase count overflow"),
    };
    let copy_phases = match raw_and_retained.checked_add(phases.encoded_copies) {
        Some(count) => count,
        None => panic!("canonical-copy phase count overflow"),
    };
    let copy_bytes = match max_blob_bytes.checked_mul(copy_phases) {
        Some(bytes) => bytes,
        None => panic!("canonical-copy byte cap overflow"),
    };
    let decode_layer_bytes = match max_blob_bytes.checked_add(max_total_allocated_bytes) {
        Some(bytes) => bytes,
        None => panic!("cumulative decode-layer byte cap overflow"),
    };
    let decode_bytes = match decode_layer_bytes.checked_mul(phases.decoded_values) {
        Some(bytes) => bytes,
        None => panic!("cumulative decode byte cap overflow"),
    };
    match copy_bytes.checked_add(decode_bytes) {
        Some(bytes) => bytes,
        None => panic!("cumulative operation byte cap overflow"),
    }
}
const fn operation_resource_caps(
    max_blob_bytes: usize,
    max_total_allocated_bytes: usize,
    live_decode_layers: usize,
) -> (usize, usize) {
    (
        composed_decode_cap(
            max_blob_bytes,
            max_total_allocated_bytes,
            live_decode_layers,
        ),
        cumulative_decode_cap(
            max_blob_bytes,
            max_total_allocated_bytes,
            OPERATION_CUMULATIVE_PHASES_V1,
        ),
    )
}
const fn control_resource_caps(
    max_blob_bytes: usize,
    max_total_allocated_bytes: usize,
    live_decode_layers: usize,
) -> (usize, usize) {
    (
        composed_decode_cap(
            max_blob_bytes,
            max_total_allocated_bytes,
            live_decode_layers,
        ),
        cumulative_decode_cap(
            max_blob_bytes,
            max_total_allocated_bytes,
            CONTROL_CUMULATIVE_PHASES_V1,
        ),
    )
}
const fn provider_ingest_checkpoint_external_decode_peak_bytes_v1() -> usize {
    // At the external sealed-record decode peak, the request frame, request
    // payload, semantic wrapper, decoded record allocation (4x the public
    // record bound), and exact canonical re-encode can coexist.
    let retained = match MAX_PROVIDER_INGEST_CHECKPOINT_RECORD_BYTES_V1.checked_mul(2) {
        Some(bytes) => bytes,
        None => panic!("provider checkpoint retained-byte cap overflow"),
    };
    let external_allocation = match MAX_PROVIDER_INGEST_CHECKPOINT_RECORD_BYTES_V1.checked_mul(4) {
        Some(bytes) => bytes,
        None => panic!("provider checkpoint external allocation cap overflow"),
    };
    let with_retained = match MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1.checked_add(retained) {
        Some(bytes) => bytes,
        None => panic!("provider checkpoint external peak overflow"),
    };
    let with_allocation = match with_retained.checked_add(external_allocation) {
        Some(bytes) => bytes,
        None => panic!("provider checkpoint external peak overflow"),
    };
    match with_allocation.checked_add(MAX_PROVIDER_INGEST_CHECKPOINT_RECORD_BYTES_V1) {
        Some(bytes) => bytes,
        None => panic!("provider checkpoint external peak overflow"),
    }
}
const fn provider_ingest_checkpoint_live_cap_v1() -> usize {
    let generic = composed_decode_cap(
        MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
        PROVIDER_INGEST_CHECKPOINT_MAX_DECODE_ALLOCATION_BYTES_V1,
        4,
    );
    let external = provider_ingest_checkpoint_external_decode_peak_bytes_v1();
    if generic > external {
        generic
    } else {
        external
    }
}
// A framed control value retains the BrokerFrame, its typed body, and one
// semantic decode/re-encode at the same time.
const CONTROL_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 8 * 1024 * 1024;
const CONTROL_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (1024 * 1024, 1024 * 1024),
    (2 * 1024 * 1024, CONTROL_MAX_DECODE_ALLOCATION_BYTES_V1),
    (64 * 1024, 2 * 1024 * 1024),
    32,
    control_resource_caps(1024 * 1024, CONTROL_MAX_DECODE_ALLOCATION_BYTES_V1, 3),
);
// Standard operations retain the wire frame, operation envelope, up to
// two semantic cross-check decodes, and the caller's typed result.
const STANDARD_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 48 * 1024 * 1024;
const STANDARD_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_BROKER_UNARY_FRAME_BYTES_V1,
        MAX_BROKER_UNARY_FRAME_BYTES_V1,
    ),
    (48 * 1024 * 1024, STANDARD_MAX_DECODE_ALLOCATION_BYTES_V1),
    (1024 * 1024, 8 * 1024 * 1024),
    32,
    operation_resource_caps(
        MAX_BROKER_UNARY_FRAME_BYTES_V1,
        STANDARD_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
include!("beacon_decode_profile.rs");
const OPAQUE_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 64 * 1024 * 1024;
const OPAQUE_BLOB_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_BROKER_UNARY_FRAME_BYTES_V1,
        MAX_BROKER_UNARY_FRAME_BYTES_V1,
    ),
    (64 * 1024 * 1024, OPAQUE_MAX_DECODE_ALLOCATION_BYTES_V1),
    (2 * 1024 * 1024, 16 * 1024 * 1024),
    32,
    operation_resource_caps(
        MAX_BROKER_UNARY_FRAME_BYTES_V1,
        OPAQUE_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
// Billing validation retains the framed response, operation envelope,
// request/result cross-checks, and caller result. The policy admits the
// service's full 128 MiB epoch-witness checkpoint.
const BILLING_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 160 * 1024 * 1024;
const BILLING_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
    ),
    (192 * 1024 * 1024, BILLING_MAX_DECODE_ALLOCATION_BYTES_V1),
    (8 * 1024 * 1024, 32 * 1024 * 1024),
    64,
    operation_resource_caps(
        MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        BILLING_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
const REPUTATION_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 152 * 1024 * 1024;
const REPUTATION_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
    ),
    (192 * 1024 * 1024, REPUTATION_MAX_DECODE_ALLOCATION_BYTES_V1),
    (8 * 1024 * 1024, 24 * 1024 * 1024),
    64,
    operation_resource_caps(
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        REPUTATION_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
const GOVERNANCE_BULK_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 152 * 1024 * 1024;
const GOVERNANCE_BULK_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_GOVERNANCE_BULK_FRAME_BYTES_V1,
        MAX_GOVERNANCE_BULK_FRAME_BYTES_V1,
    ),
    (
        192 * 1024 * 1024,
        GOVERNANCE_BULK_MAX_DECODE_ALLOCATION_BYTES_V1,
    ),
    (8 * 1024 * 1024, 24 * 1024 * 1024),
    64,
    operation_resource_caps(
        MAX_GOVERNANCE_BULK_FRAME_BYTES_V1,
        GOVERNANCE_BULK_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
const GOVERNANCE_SEALED_STATE_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 216 * 1024 * 1024;
const GOVERNANCE_SEALED_STATE_DECODE_POLICY_V1: DecodeResourcePolicyV1 =
    DecodeResourcePolicyV1::new(
        (
            MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1,
            MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1,
        ),
        (
            224 * 1024 * 1024,
            GOVERNANCE_SEALED_STATE_MAX_DECODE_ALLOCATION_BYTES_V1,
        ),
        (8 * 1024 * 1024, 24 * 1024 * 1024),
        64,
        operation_resource_caps(
            MAX_GOVERNANCE_SEALED_STATE_FRAME_BYTES_V1,
            GOVERNANCE_SEALED_STATE_MAX_DECODE_ALLOCATION_BYTES_V1,
            4,
        ),
    );
const APPEAL_CHECKPOINT_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 88 * 1024 * 1024;
const APPEAL_CHECKPOINT_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1,
        MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1,
    ),
    (
        96 * 1024 * 1024,
        APPEAL_CHECKPOINT_MAX_DECODE_ALLOCATION_BYTES_V1,
    ),
    (4 * 1024 * 1024, 24 * 1024 * 1024),
    64,
    operation_resource_caps(
        MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_FRAME_BYTES_V1,
        APPEAL_CHECKPOINT_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
const PROVIDER_INGEST_CHECKPOINT_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 216 * 1024 * 1024;
const PROVIDER_INGEST_CHECKPOINT_DECODE_POLICY_V1: DecodeResourcePolicyV1 =
    DecodeResourcePolicyV1::new(
        (
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
        ),
        (
            224 * 1024 * 1024,
            PROVIDER_INGEST_CHECKPOINT_MAX_DECODE_ALLOCATION_BYTES_V1,
        ),
        (8 * 1024 * 1024, 24 * 1024 * 1024),
        64,
        (
            provider_ingest_checkpoint_live_cap_v1(),
            cumulative_decode_cap(
                MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
                PROVIDER_INGEST_CHECKPOINT_MAX_DECODE_ALLOCATION_BYTES_V1,
                OPERATION_CUMULATIVE_PHASES_V1,
            ),
        ),
    );
const EVIDENCE_BULK_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 88 * 1024 * 1024;
const EVIDENCE_BULK_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
        MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
    ),
    (
        96 * 1024 * 1024,
        EVIDENCE_BULK_MAX_DECODE_ALLOCATION_BYTES_V1,
    ),
    (4 * 1024 * 1024, 24 * 1024 * 1024),
    64,
    operation_resource_caps(
        MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
        EVIDENCE_BULK_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
// Source setup retains the wire frame, operation envelope, source header,
// and canonical CAR plan. Stream chunks use the separate transient policy.
const SOURCE_PLAN_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 80 * 1024 * 1024;
const SOURCE_PLAN_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
        MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
    ),
    (64 * 1024 * 1024, SOURCE_PLAN_MAX_DECODE_ALLOCATION_BYTES_V1),
    (4 * 1024 * 1024, 24 * 1024 * 1024),
    64,
    operation_resource_caps(
        MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1,
        SOURCE_PLAN_MAX_DECODE_ALLOCATION_BYTES_V1,
        4,
    ),
);
const PROVIDER_INGEST_SIGN_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 88 * 1024 * 1024;
// Completion signing retains the wire frame and operation envelope, the
// signed result and original-request cross-check, and the caller's typed
// signed transaction. Each layer also has one exact canonical re-encode.
const PROVIDER_INGEST_SIGN_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1,
        MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1,
    ),
    (
        96 * 1024 * 1024,
        PROVIDER_INGEST_SIGN_MAX_DECODE_ALLOCATION_BYTES_V1,
    ),
    (4 * 1024 * 1024, 24 * 1024 * 1024),
    64,
    operation_resource_caps(
        MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1,
        PROVIDER_INGEST_SIGN_MAX_DECODE_ALLOCATION_BYTES_V1,
        5,
    ),
);
const SOURCE_STREAM_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 4 * 1024 * 1024;
const SOURCE_STREAM_FRAME_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1::new(
    (
        MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1,
        MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1,
    ),
    (
        2 * 1024 * 1024,
        SOURCE_STREAM_MAX_DECODE_ALLOCATION_BYTES_V1,
    ),
    (64 * 1024, 1024 * 1024),
    32,
    (
        composed_decode_cap(
            MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1,
            SOURCE_STREAM_MAX_DECODE_ALLOCATION_BYTES_V1,
            2,
        ),
        cumulative_decode_cap(
            MAX_PROVIDER_INGEST_SOURCE_CHUNK_FRAME_BYTES_V1,
            SOURCE_STREAM_MAX_DECODE_ALLOCATION_BYTES_V1,
            SOURCE_STREAM_CUMULATIVE_PHASES_V1,
        ),
    ),
);

// Keep secret-bearing wire hygiene and redacted formatting in one auditable
// implementation. Call sites still name every exposed debug field and every
// byte container scrubbed on drop; the macros only remove identical wrappers.
macro_rules! impl_broker_debug_fields {
    (
        $type:ident as $value:ident {} => $finish:ident
    ) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct(stringify!($type)).$finish()
            }
        }
    };
    (
        $type:ident as $value:ident {
            $($label:literal => $expression:expr,)+
        } => $finish:ident
    ) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let $value = self;
                let mut debug = formatter.debug_struct(stringify!($type));
                $(debug.field($label, &$expression);)*
                let _ = $value;
                debug.$finish()
            }
        }
    };
}
macro_rules! impl_scrub_fields_on_drop {
    ($type:ident { $field:ident }) => {
        impl Drop for $type {
            fn drop(&mut self) {
                self.$field.fill(0);
                let _ = std::hint::black_box(&self.$field);
            }
        }
    };
    ($type:ident { $first:ident, $($field:ident),+ $(,)? }) => {
        impl Drop for $type {
            fn drop(&mut self) {
                self.$first.fill(0);
                $(self.$field.fill(0);)+
                let _ = std::hint::black_box((&self.$first, $(&self.$field),+));
            }
        }
    };
}

// Canonical request/response containers differ only in ownership and
// redaction traits. Keep those choices explicit at each declaration while
// generating the identical Norito wire-derive and field boilerplate here.
macro_rules! define_broker_wire_struct {
    // Only declarations naming an actual typed-frame boundary opt into an identity.
    // Nested payload helpers continue through the payload-only arm below.
    (@emit [$derive:meta] frame $schema:literal; $visibility:vis $name:ident {
        $($field_visibility:vis $field:ident: $field_type:ty),* $(,)?
    }) => {
        #[$derive]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = $schema)]
        $visibility struct $name {
            $($field_visibility $field: $field_type),*
        }
    };
    (@emit [$derive:meta] $visibility:vis $name:ident {
        $($field_visibility:vis $field:ident: $field_type:ty),* $(,)?
    }) => {
        #[$derive]
        $visibility struct $name {
            $($field_visibility $field: $field_type),*
        }
    };
    (copy $($definition:tt)*) => {
        define_broker_wire_struct!(@emit [derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode)] $($definition)*);
    };
    (owned $($definition:tt)*) => {
        define_broker_wire_struct!(@emit [derive(Clone, Debug, PartialEq, Eq, Decode, Encode)] $($definition)*);
    };
    (sensitive $($definition:tt)*) => {
        define_broker_wire_struct!(@emit [derive(Clone, PartialEq, Eq, Decode, Encode)] $($definition)*);
    };
    (move_sensitive $($definition:tt)*) => {
        define_broker_wire_struct!(@emit [derive(PartialEq, Eq, Decode, Encode)] $($definition)*);
    };
    (copy_sensitive $($definition:tt)*) => {
        define_broker_wire_struct!(@emit [derive(Clone, Copy, PartialEq, Eq, Decode, Encode)] $($definition)*);
    };
}

macro_rules! required_binding_value {
    ($binding:expr, $field:ident) => {
        ($binding).$field.ok_or(BrokerError::BindingMismatch)?
    };
}
macro_rules! required_binding_ref {
    ($binding:expr, $field:ident) => {
        ($binding)
            .$field
            .as_ref()
            .ok_or(BrokerError::BindingMismatch)?
    };
}
/// Exact operation identifiers and foundational canonical wire containers.
mod primitives {
    use super::*;
    include!("protocol_primitives.rs");
}
use primitives::*;
const fn native_transaction_signer_role_to_wire(
    role: iroha_torii::SorafsNativeTransactionSignerRoleV1,
) -> u8 {
    match role {
        iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome => 1,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair => 2,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve => 3,
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook => 4,
    }
}
fn native_transaction_signer_role_from_wire(
    role: u8,
) -> Result<iroha_torii::SorafsNativeTransactionSignerRoleV1, BrokerError> {
    match role {
        1 => Ok(iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome),
        2 => Ok(iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair),
        3 => Ok(iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve),
        4 => Ok(iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook),
        _ => Err(BrokerError::BindingMismatch),
    }
}
fn native_transaction_signer_role_for_slot(
    slot: u16,
) -> Option<iroha_torii::SorafsNativeTransactionSignerRoleV1> {
    if slot == IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner.wire_id() {
        Some(iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome)
    } else if slot == IrohaRuntimeProviderSlotV1::RepairTransactionSigner.wire_id() {
        Some(iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair)
    } else if slot == IrohaRuntimeProviderSlotV1::ReserveTransactionSigner.wire_id() {
        Some(iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve)
    } else if slot == IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner.wire_id() {
        Some(iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook)
    } else {
        None
    }
}
impl NativeTransactionSignerBindingWireV1 {
    fn from_binding(binding: &iroha_torii::SorafsNativeTransactionSignerBindingV1) -> Self {
        Self {
            role: native_transaction_signer_role_to_wire(binding.role()),
            authority: binding.authority().clone(),
            public_key: binding.public_key().clone(),
        }
    }
    fn from_soracloud_binding(
        binding: &crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1,
    ) -> Self {
        Self {
            role: SORACLOUD_RUNTIME_SIGNER_ROLE_WIRE_V1,
            authority: binding.authority().clone(),
            public_key: binding.public_key().clone(),
        }
    }
    fn to_binding(
        &self,
        outer: &ProviderBindingWireV1,
    ) -> Result<iroha_torii::SorafsNativeTransactionSignerBindingV1, BrokerError> {
        let role = native_transaction_signer_role_from_wire(self.role)?;
        if native_transaction_signer_role_for_slot(outer.slot) != Some(role) {
            return Err(BrokerError::BindingMismatch);
        }
        let revision = outer.revision.ok_or(BrokerError::BindingMismatch)?;
        let policy_digest = outer.policy_digest.ok_or(BrokerError::BindingMismatch)?;
        iroha_torii::SorafsNativeTransactionSignerBindingV1::try_new(
            role,
            outer.handle.clone(),
            self.authority.clone(),
            self.public_key.clone(),
            iroha_torii::SorafsNativeTransactionSignerQualificationV1::new(revision, policy_digest),
        )
        .map_err(|_| BrokerError::BindingMismatch)
    }
}
fn native_transaction_signer_binding_from_wire(
    binding: &ProviderBindingWireV1,
) -> Result<iroha_torii::SorafsNativeTransactionSignerBindingV1, BrokerError> {
    required_binding_ref!(binding, native_signer_binding).to_binding(binding)
}
fn soracloud_runtime_signer_binding_from_wire(
    binding: &ProviderBindingWireV1,
) -> Result<crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1, BrokerError> {
    if binding.slot != IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id() {
        return Err(BrokerError::BindingMismatch);
    }
    let inner = required_binding_ref!(binding, native_signer_binding);
    if inner.role != SORACLOUD_RUNTIME_SIGNER_ROLE_WIRE_V1 {
        return Err(BrokerError::BindingMismatch);
    }
    crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1::try_new(
        binding.handle.clone(),
        inner.authority.clone(),
        inner.public_key.clone(),
        crate::soracloud_runtime_signer::SoracloudRuntimeSignerQualificationV1::new(
            required_binding_value!(binding, revision),
            required_binding_value!(binding, policy_digest),
            true,
            false,
        ),
    )
    .map_err(|_| BrokerError::BindingMismatch)
}
impl ProviderBindingWireV1 {
    fn try_from_binding(
        binding: &IrohaRuntimeProviderBindingV1,
    ) -> Result<Self, IrohaRuntimeProviderRegistryErrorV1> {
        if binding.handle().is_empty()
            || binding.handle().len() > MAX_PROVIDER_HANDLE_BYTES_V1
            || binding.handle().as_bytes().contains(&0)
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                binding.slot(),
            ));
        }
        match (binding.revision(), binding.policy_digest()) {
            (Some(0), _) | (Some(_), None) | (None, Some(_)) => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    binding.slot(),
                ));
            }
            (_, Some(digest)) if digest == [0; 32] => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
                    binding.slot(),
                ));
            }
            (Some(_), Some(_)) | (None, None) => {}
        }
        Ok(Self {
            slot: binding.slot().wire_id(),
            handle: binding.handle().to_owned(),
            revision: binding.revision(),
            policy_digest: binding.policy_digest(),
            bootle_lantern_issuance_bindings: binding.bootle_lantern_issuance_bindings().map(
                |bindings| BootleLanternIssuanceBindingsWireV1 {
                    issuer_id: *bindings.issuer_id().as_bytes(),
                    policy_id: *bindings.policy_id().as_bytes(),
                    authorization_lifetime_blocks: bindings.authorization_lifetime_blocks(),
                },
            ),
            stream_token_signer_binding: binding.stream_token_signer_binding().cloned(),
            appeal_finance_signer_binding: binding.appeal_finance_signer_binding().map(|signer| {
                AppealFinanceSignerBindingWireV1 {
                    authority: signer.authority.clone(),
                    public_key: signer.public_key.clone(),
                    valid_from_block_height: signer.valid_from_block_height,
                    revoked_at_block_height: signer.revoked_at_block_height,
                }
            }),
            appeal_finance_checkpoint_binding: binding.appeal_finance_checkpoint_binding().map(
                |checkpoint| AppealFinanceCheckpointBindingWireV1 {
                    public_key: checkpoint.public_key.clone(),
                },
            ),
            appeal_finance_checkpoint_max_bytes: binding.appeal_finance_checkpoint_max_bytes(),
            pop_credential_runtime_binding: binding
                .pop_credential_runtime_binding()
                .map(PopCredentialRuntimeBindingWireV1::from),
            por_replay_archive_binding: binding.por_replay_archive_binding(),
            por_replay_archive_proof_limits: binding
                .por_replay_archive_proof_limits()
                .map(PorReplayArchiveProofLimitsWireV1::from),
            potr_runtime_binding: binding
                .potr_runtime_binding()
                .map(PotrRuntimeBindingWireV1::from),
            native_signer_binding: binding
                .native_signer_binding()
                .map(NativeTransactionSignerBindingWireV1::from_binding)
                .or_else(|| {
                    binding
                        .soracloud_runtime_signer_binding()
                        .map(NativeTransactionSignerBindingWireV1::from_soracloud_binding)
                }),
            governance_dag_publisher_peer_id: binding
                .governance_dag_publisher_peer_id()
                .map(<[u8]>::to_vec),
            governance_dag_publisher_public_key: binding.governance_dag_publisher_public_key(),
            governance_request_ingress_binding: binding
                .governance_request_ingress_binding()
                .map(governance_request_ingress_binding_to_wire),
            provider_ingest_signer_binding: binding
                .provider_ingest_signer_binding()
                .map(ProviderIngestSignerBindingWireV1::try_from_binding)
                .transpose()?,
            provider_ingest_source_limits: binding
                .provider_ingest_source_limits()
                .map(ProviderIngestSourceLimitsWireV1::from),
            provider_ingest_checkpoint_max_bytes: binding.provider_ingest_checkpoint_max_bytes(),
            provider_ingest_max_signed_transaction_bytes: binding
                .provider_ingest_max_signed_transaction_bytes(),
            evidence_viewer_webauthn_binding: binding
                .evidence_viewer_webauthn_binding()
                .map(EvidenceViewerWebAuthnBindingWireV1::from),
            evidence_viewer_grant_ttl_ms: binding.evidence_viewer_grant_ttl_ms(),
            evidence_viewer_receipt_signer_public_key: binding
                .evidence_viewer_receipt_signer_public_key(),
            evidence_viewer_transparency_publisher_public_key: binding
                .evidence_viewer_transparency_publisher_public_key(),
            evidence_viewer_checkpoint_max_bytes: binding.evidence_viewer_checkpoint_max_bytes(),
            moderation_checkpoint_max_bytes: binding.moderation_checkpoint_max_bytes(),
            moderation_checkpoint_attestation_public_key: binding
                .moderation_checkpoint_attestation_public_key(),
            evidence_viewer_archive_id: binding.evidence_viewer_archive_id(),
            evidence_viewer_archive_public_key: binding.evidence_viewer_archive_public_key(),
            evidence_viewer_archive_max_bytes: binding.evidence_viewer_archive_max_bytes(),
            moderation_panel_notification_archive_binding: binding
                .moderation_panel_notification_archive_id()
                .zip(binding.moderation_panel_notification_archive_bootstrap_public_key())
                .zip(binding.moderation_panel_notification_archive_public_key())
                .zip(binding.moderation_panel_notification_archive_max_bytes())
                .zip(binding.moderation_panel_notification_archive_max_records())
                .map(
                    |(
                        (((archive_id, bootstrap_public_key), public_key), max_bytes),
                        max_records,
                    )| {
                        ModerationPanelNotificationArchiveBindingWireV1 {
                            archive_id,
                            bootstrap_public_key,
                            public_key,
                            max_bytes,
                            max_records,
                        }
                    },
                ),
        })
    }
    fn has_exact_qualification(&self) -> bool {
        matches!(
            (self.revision, self.policy_digest),
            (Some(revision), Some(digest)) if revision != 0 && digest != [0; 32]
        )
    }
    fn runtime_slot(&self) -> Result<IrohaRuntimeProviderSlotV1, BrokerError> {
        IrohaRuntimeProviderSlotV1::from_wire_id(self.slot).ok_or(BrokerError::BindingMismatch)
    }
}
fn exact_ed25519_public_key_bytes(
    public_key: &iroha_crypto::PublicKey,
) -> Result<[u8; 32], BrokerError> {
    let (algorithm, bytes) = public_key
        .try_to_bytes()
        .map_err(|_| BrokerError::BindingMismatch)?;
    if algorithm != iroha_crypto::Algorithm::Ed25519 {
        return Err(BrokerError::BindingMismatch);
    }
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| BrokerError::BindingMismatch)?;
    iroha_crypto::ed25519_parse_public_key(&bytes).map_err(|_| BrokerError::BindingMismatch)?;
    Ok(bytes)
}
fn potr_provider_binding_from_wire(
    binding: &ProviderBindingWireV1,
) -> Result<iroha_torii::sorafs::PotrRuntimeProviderBindingV1, BrokerError> {
    let runtime = required_binding_ref!(binding, potr_runtime_binding);
    let (handle, signer_id, revision, policy_digest) =
        if binding.slot == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id() {
            (
                &runtime.gateway_handle,
                runtime.gateway_signer_id,
                runtime.gateway_revision,
                runtime.gateway_policy_digest,
            )
        } else if binding.slot == IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id() {
            (
                &runtime.provider_handle,
                runtime.provider_signer_id,
                runtime.provider_revision,
                runtime.provider_policy_digest,
            )
        } else {
            return Err(BrokerError::BindingMismatch);
        };
    if binding.handle != *handle
        || binding.revision != Some(revision)
        || binding.policy_digest != Some(policy_digest)
    {
        return Err(BrokerError::BindingMismatch);
    }
    iroha_torii::sorafs::PotrRuntimeProviderBindingV1::try_new(
        handle.clone(),
        signer_id,
        iroha_torii::sorafs::PotrRuntimeProviderQualificationV1::new(revision, policy_digest),
    )
    .map_err(|_| BrokerError::BindingMismatch)
}
fn validate_potr_runtime_wire(runtime: &PotrRuntimeBindingWireV1) -> Result<(), BrokerError> {
    let admission = runtime.baseline_admission_policy.to_binding();
    admission
        .validate()
        .map_err(|_| BrokerError::BindingMismatch)?;
    iroha_torii::sorafs::PotrRuntimeReaderBindingsV1::try_new(
        runtime.reader_id,
        runtime.source_id,
        runtime.resolver_id,
    )
    .map_err(|_| BrokerError::BindingMismatch)?;
    iroha_torii::sorafs::PotrRuntimeProviderBindingV1::try_new(
        runtime.gateway_handle.clone(),
        runtime.gateway_signer_id,
        iroha_torii::sorafs::PotrRuntimeProviderQualificationV1::new(
            runtime.gateway_revision,
            runtime.gateway_policy_digest,
        ),
    )
    .map_err(|_| BrokerError::BindingMismatch)?;
    iroha_torii::sorafs::PotrRuntimeProviderBindingV1::try_new(
        runtime.provider_handle.clone(),
        runtime.provider_signer_id,
        iroha_torii::sorafs::PotrRuntimeProviderQualificationV1::new(
            runtime.provider_revision,
            runtime.provider_policy_digest,
        ),
    )
    .map_err(|_| BrokerError::BindingMismatch)?;
    if runtime.gateway_handle == runtime.provider_handle
        || runtime.gateway_signer_id == runtime.provider_signer_id
        || runtime.provider_revision.ne(&admission.policy_sequence)
        || runtime.provider_policy_digest != admission.policy_digest
        || runtime.gateway_public_key == [0; 32]
        || iroha_crypto::ed25519_parse_public_key(&runtime.gateway_public_key).is_err()
    {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
fn validate_webauthn_wire_policy(
    rp_id: &str,
    allowed_origins: &[String],
) -> Result<(), BrokerError> {
    let mut canonical_origins = allowed_origins.to_vec();
    canonical_origins.sort();
    canonical_origins.dedup();
    if validate_webauthn_rp_id_v1(rp_id).is_err()
        || allowed_origins.is_empty()
        || allowed_origins.len() > MAX_EVIDENCE_VIEWER_ORIGINS_V1
        || canonical_origins != allowed_origins
        || allowed_origins
            .iter()
            .any(|origin| validate_webauthn_origin_v1(origin, rp_id).is_err())
    {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
fn validate_wire_binding(binding: &ProviderBindingWireV1) -> Result<(), BrokerError> {
    let runtime_slot = binding.runtime_slot()?;
    let governance_signer = runtime_slot == IrohaRuntimeProviderSlotV1::GovernanceDagSigner;
    match (
        binding.governance_dag_publisher_peer_id.as_deref(),
        binding.governance_dag_publisher_public_key,
    ) {
        (Some(peer_id), Some(public_key)) if governance_signer => {
            if peer_id.is_empty()
                || peer_id.len() > GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1
                || !peer_id.iter().all(u8::is_ascii_graphic)
                || iroha_crypto::ed25519_parse_public_key(&public_key).is_err()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        (None, None) if !governance_signer => {}
        _ => return Err(BrokerError::BindingMismatch),
    }
    let stream_token = binding.slot == IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id();
    if binding.handle.is_empty()
        || binding.handle.len() > MAX_PROVIDER_HANDLE_BYTES_V1
        || binding.handle.as_bytes().contains(&0)
        || !iroha_config::parameters::is_production_runtime_handle(&binding.handle)
        || !binding.has_exact_qualification()
    {
        return Err(BrokerError::BindingMismatch);
    }
    let bootle_lantern_issuance =
        binding.slot == IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry.wire_id();
    if bootle_lantern_issuance {
        let exact = required_binding_value!(binding, bootle_lantern_issuance_bindings);
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1::try_new(
            iroha_data_model::privacy::PrivacyIssuerIdV1::new(exact.issuer_id),
            iroha_data_model::privacy::PrivacyPolicyIdV1::new(exact.policy_id),
            exact.authorization_lifetime_blocks,
        )
        .map_err(|_| BrokerError::BindingMismatch)?;
        if binding.stream_token_signer_binding.is_some()
            || binding.appeal_finance_signer_binding.is_some()
            || binding.appeal_finance_checkpoint_binding.is_some()
            || binding.appeal_finance_checkpoint_max_bytes.is_some()
            || binding.pop_credential_runtime_binding.is_some()
            || binding.por_replay_archive_binding.is_some()
            || binding.por_replay_archive_proof_limits.is_some()
            || binding.potr_runtime_binding.is_some()
            || binding.native_signer_binding.is_some()
            || binding.governance_request_ingress_binding.is_some()
            || binding.provider_ingest_signer_binding.is_some()
            || binding.provider_ingest_source_limits.is_some()
            || binding.provider_ingest_checkpoint_max_bytes.is_some()
            || binding
                .provider_ingest_max_signed_transaction_bytes
                .is_some()
            || binding.evidence_viewer_webauthn_binding.is_some()
            || binding.evidence_viewer_grant_ttl_ms.is_some()
            || binding.evidence_viewer_receipt_signer_public_key.is_some()
            || binding
                .evidence_viewer_transparency_publisher_public_key
                .is_some()
            || binding.evidence_viewer_checkpoint_max_bytes.is_some()
            || binding.evidence_viewer_archive_id.is_some()
            || binding.evidence_viewer_archive_public_key.is_some()
            || binding.evidence_viewer_archive_max_bytes.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if binding.bootle_lantern_issuance_bindings.is_some() {
        return Err(BrokerError::BindingMismatch);
    }
    let appeal_signer =
        binding.slot == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id();
    let appeal_checkpoint =
        binding.slot == IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint.wire_id();
    let pop_registry =
        binding.slot == IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry.wire_id();
    let por_replay_archive =
        binding.slot == IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive.wire_id();
    let potr_signer = binding.slot == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id();
    let has_new_role_metadata = binding.stream_token_signer_binding.is_some()
        || binding.appeal_finance_signer_binding.is_some()
        || binding.appeal_finance_checkpoint_binding.is_some()
        || binding.appeal_finance_checkpoint_max_bytes.is_some()
        || binding.pop_credential_runtime_binding.is_some()
        || binding.por_replay_archive_binding.is_some()
        || binding.por_replay_archive_proof_limits.is_some()
        || binding.potr_runtime_binding.is_some();
    if stream_token {
        let signer_backend = required_binding_ref!(binding, stream_token_signer_binding);
        if signer_backend.validate().is_err()
            || signer_backend.custody().runtime_handle != binding.handle
            || Some(signer_backend.custody().key_revision) != binding.revision
            || Some(signer_backend.custody().policy_digest) != binding.policy_digest
            || binding.appeal_finance_signer_binding.is_some()
            || binding.appeal_finance_checkpoint_binding.is_some()
            || binding.appeal_finance_checkpoint_max_bytes.is_some()
            || binding.pop_credential_runtime_binding.is_some()
            || binding.por_replay_archive_binding.is_some()
            || binding.por_replay_archive_proof_limits.is_some()
            || binding.potr_runtime_binding.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if appeal_signer {
        let exact = required_binding_ref!(binding, appeal_finance_signer_binding);
        if exact_ed25519_public_key_bytes(&exact.public_key).is_err()
            || iroha_data_model::account::AccountId::new(exact.public_key.clone())
                != exact.authority
            || exact.valid_from_block_height == 0
            || exact
                .revoked_at_block_height
                .is_some_and(|height| height <= exact.valid_from_block_height)
            || binding.stream_token_signer_binding.is_some()
            || binding.appeal_finance_checkpoint_binding.is_some()
            || binding.appeal_finance_checkpoint_max_bytes.is_some()
            || binding.pop_credential_runtime_binding.is_some()
            || binding.por_replay_archive_binding.is_some()
            || binding.por_replay_archive_proof_limits.is_some()
            || binding.potr_runtime_binding.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if appeal_checkpoint {
        let exact = required_binding_ref!(binding, appeal_finance_checkpoint_binding);
        let checkpoint_max_bytes =
            required_binding_value!(binding, appeal_finance_checkpoint_max_bytes);
        if exact_ed25519_public_key_bytes(&exact.public_key).is_err()
            || checkpoint_max_bytes == 0
            || checkpoint_max_bytes
                > u64::try_from(MAX_BROKER_APPEAL_FINANCE_CHECKPOINT_BYTES_V1)
                    .map_err(|_| BrokerError::Protocol)?
            || binding.stream_token_signer_binding.is_some()
            || binding.appeal_finance_signer_binding.is_some()
            || binding.pop_credential_runtime_binding.is_some()
            || binding.por_replay_archive_binding.is_some()
            || binding.por_replay_archive_proof_limits.is_some()
            || binding.potr_runtime_binding.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if pop_registry {
        use iroha_config::parameters::is_production_runtime_handle;
        let exact = required_binding_ref!(binding, pop_credential_runtime_binding);
        if exact.issuer_policy_digest == [0; 32]
            || exact.issuer_id.is_empty()
            || exact.issuer_id.len()
                > sorafs_manifest::pop_credentials::POP_IDENTITY_TEXT_MAX_BYTES_V1
            || exact.issuer_id.trim() != exact.issuer_id
            || exact.issuer_id.chars().any(char::is_control)
            || !is_production_runtime_handle(&exact.issuer_signer_handle)
            || !is_production_runtime_handle(&exact.enrollment_recipient_key_id)
            || !is_production_runtime_handle(&exact.wallet_recipient_key_id)
            || !is_production_runtime_handle(&exact.wallet_wrapping_key_id)
            || exact.enrollment_recipient_public_key_digest == [0; 32]
            || exact.wallet_recipient_public_key_digest == [0; 32]
            || exact.issuer_public_key == [0; 32]
            || iroha_crypto::ed25519_parse_public_key(&exact.issuer_public_key).is_err()
            || binding.stream_token_signer_binding.is_some()
            || binding.appeal_finance_signer_binding.is_some()
            || binding.appeal_finance_checkpoint_binding.is_some()
            || binding.appeal_finance_checkpoint_max_bytes.is_some()
            || binding.por_replay_archive_binding.is_some()
            || binding.por_replay_archive_proof_limits.is_some()
            || binding.potr_runtime_binding.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if por_replay_archive {
        let exact = required_binding_value!(binding, por_replay_archive_binding);
        let limits = required_binding_value!(binding, por_replay_archive_proof_limits);
        sorafs_node::PorFinalizedReplayArchiveBindingV1::try_new(
            exact.archive_id,
            exact.revision,
            exact.policy_digest,
            exact.signing_public_key,
        )
        .map_err(|_| BrokerError::BindingMismatch)?;
        sorafs_node::PorFinalizedReplayArchiveProofBoundsV1::try_new(
            limits.max_successor_receipts,
            limits.max_successor_proof_bytes,
        )
        .map_err(|_| BrokerError::BindingMismatch)?;
        if binding.revision != Some(exact.revision)
            || binding.policy_digest != Some(exact.policy_digest)
            || limits.max_successor_receipts
                > iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                    MAX_SUCCESSOR_RECEIPTS_LIMIT
            || limits.max_successor_proof_bytes
                > iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
                    MAX_SUCCESSOR_PROOF_BYTES_LIMIT
            || binding.stream_token_signer_binding.is_some()
            || binding.appeal_finance_signer_binding.is_some()
            || binding.appeal_finance_checkpoint_binding.is_some()
            || binding.appeal_finance_checkpoint_max_bytes.is_some()
            || binding.pop_credential_runtime_binding.is_some()
            || binding.potr_runtime_binding.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if potr_signer {
        let runtime = required_binding_ref!(binding, potr_runtime_binding);
        validate_potr_runtime_wire(runtime)?;
        potr_provider_binding_from_wire(binding)?;
        if binding.stream_token_signer_binding.is_some()
            || binding.appeal_finance_signer_binding.is_some()
            || binding.appeal_finance_checkpoint_binding.is_some()
            || binding.appeal_finance_checkpoint_max_bytes.is_some()
            || binding.pop_credential_runtime_binding.is_some()
            || binding.por_replay_archive_binding.is_some()
            || binding.por_replay_archive_proof_limits.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if has_new_role_metadata {
        return Err(BrokerError::BindingMismatch);
    }
    let governance_request_auth = binding.slot
        == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id();
    let governance_checkpoint =
        binding.slot == IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore.wire_id();
    let privacy_cycle_prf =
        binding.slot == IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider.wire_id();
    let privacy_release_anchor =
        binding.slot == IrohaRuntimeProviderSlotV1::PrivacyReleaseAnchor.wire_id();
    let transparency_leader_lease =
        binding.slot == IrohaRuntimeProviderSlotV1::TransparencyLeaderLease.wire_id();
    let fenced_privacy_publisher =
        binding.slot == IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher.wire_id();
    let fenced_privacy_head_reader =
        binding.slot == IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader.wire_id();
    let reputation_checkpoint =
        binding.slot == IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint.wire_id();
    let reputation_runtime = binding.slot
        == IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter.wire_id()
        || reputation_checkpoint
        || binding.slot == IrohaRuntimeProviderSlotV1::ReputationThresholdSigner.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::ReputationGovernanceDag.wire_id();
    let reputation_retention = binding.slot
        == IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority.wire_id();
    let billing_runtime = binding.slot
        == IrohaRuntimeProviderSlotV1::BillingFinalizedQuery.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::BillingJournalVerifier.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::BillingStatementSigner.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::BillingStatementPublisher.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore.wire_id();
    let gateway_runtime = binding.slot == IrohaRuntimeProviderSlotV1::GatewayAcmeClient.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport.wire_id();
    let native_transaction_signer = native_transaction_signer_role_for_slot(binding.slot).is_some();
    let soracloud_runtime_signer =
        binding.slot == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id();
    let consensus_threshold_signer = binding.slot
        == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id();
    let moderation_transaction_signer =
        binding.slot == IrohaRuntimeProviderSlotV1::ModerationTransactionSigner.wire_id();
    let moderation_delivery_boundary = binding.slot
        == IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id()
        || binding.slot == IrohaRuntimeProviderSlotV1::ModerationPanelNotification.wire_id();
    let moderation_checkpoint =
        binding.slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id();
    let moderation_panel_notification_archive =
        binding.slot == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id();
    let moderation_quarantine =
        binding.slot == IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id();
    let provider_ingest_resolver = binding.slot
        == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id();
    let provider_ingest_source =
        binding.slot == IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id();
    let provider_ingest_signer =
        binding.slot == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id();
    let provider_ingest_checkpoint =
        binding.slot == IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id();
    let provider_ingest_retention =
        binding.slot == IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority.wire_id();
    let evidence_webauthn =
        binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id();
    let evidence_grants =
        binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority.wire_id();
    let evidence_receipt_signer =
        binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner.wire_id();
    let evidence_erasure =
        binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerErasure.wire_id();
    let evidence_checkpoint =
        binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore.wire_id();
    let evidence_archive =
        binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id();
    let evidence_transparency_publisher =
        binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher.wire_id();
    let has_evidence_metadata = binding.evidence_viewer_webauthn_binding.is_some()
        || binding.evidence_viewer_grant_ttl_ms.is_some()
        || binding.evidence_viewer_receipt_signer_public_key.is_some()
        || binding
            .evidence_viewer_transparency_publisher_public_key
            .is_some()
        || binding.evidence_viewer_checkpoint_max_bytes.is_some()
        || binding.evidence_viewer_archive_id.is_some()
        || binding.evidence_viewer_archive_public_key.is_some()
        || binding.evidence_viewer_archive_max_bytes.is_some();
    let has_moderation_archive_metadata = binding
        .moderation_panel_notification_archive_binding
        .is_some();
    let has_moderation_checkpoint_metadata = binding
        .moderation_checkpoint_attestation_public_key
        .is_some()
        || binding.moderation_checkpoint_max_bytes.is_some();
    let has_provider_ingest_metadata = binding.provider_ingest_signer_binding.is_some()
        || binding.provider_ingest_source_limits.is_some()
        || binding.provider_ingest_checkpoint_max_bytes.is_some()
        || binding
            .provider_ingest_max_signed_transaction_bytes
            .is_some();
    // Slot 54 is a hard-cut protocol: its dedicated identity must be
    // present exactly on that slot and can never alias evidence-viewer
    // archive metadata on slot 47 (or any other provider role).
    if moderation_panel_notification_archive != has_moderation_archive_metadata {
        return Err(BrokerError::BindingMismatch);
    }
    if moderation_checkpoint != has_moderation_checkpoint_metadata {
        return Err(BrokerError::BindingMismatch);
    }
    if moderation_checkpoint
        && (binding
            .moderation_checkpoint_attestation_public_key
            .is_none_or(|key| iroha_crypto::ed25519_parse_public_key(&key).is_err())
            || binding
                .moderation_checkpoint_max_bytes
                .is_none_or(|max_bytes| {
                    max_bytes == 0
                    || max_bytes
                        > sorafs_node::moderation_orchestrator::
                            MODERATION_ORCHESTRATOR_CHECKPOINT_MAX_BYTES_V1
                }))
    {
        return Err(BrokerError::BindingMismatch);
    }
    if reputation_checkpoint
        && binding.revision
            != Some(
                sorafs_node::reputation::runtime::
                    REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
            )
    {
        return Err(BrokerError::BindingMismatch);
    }
    if stream_token
        || appeal_signer
        || appeal_checkpoint
        || pop_registry
        || por_replay_archive
        || potr_signer
    {
        if binding.native_signer_binding.is_some()
            || binding.governance_request_ingress_binding.is_some()
            || has_provider_ingest_metadata
            || has_evidence_metadata
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if privacy_cycle_prf
        || privacy_release_anchor
        || transparency_leader_lease
        || fenced_privacy_publisher
        || fenced_privacy_head_reader
        || reputation_runtime
        || reputation_retention
        || billing_runtime
        || gateway_runtime
        || consensus_threshold_signer
    {
        if binding.native_signer_binding.is_some()
            || binding.governance_request_ingress_binding.is_some()
            || has_provider_ingest_metadata
            || has_evidence_metadata
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if soracloud_runtime_signer {
        soracloud_runtime_signer_binding_from_wire(binding)?;
        if binding.governance_request_ingress_binding.is_some()
            || has_provider_ingest_metadata
            || has_evidence_metadata
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if native_transaction_signer {
        native_transaction_signer_binding_from_wire(binding)?;
        if binding.governance_request_ingress_binding.is_some()
            || has_provider_ingest_metadata
            || has_evidence_metadata
        {
            return Err(BrokerError::BindingMismatch);
        }
    } else if binding.native_signer_binding.is_some() {
        return Err(BrokerError::BindingMismatch);
    }
    if governance_request_auth {
        governance_request_ingress_binding_from_provider_binding(binding)?;
    } else if binding.governance_request_ingress_binding.is_some() {
        return Err(BrokerError::BindingMismatch);
    }
    if !(evidence_webauthn
        || evidence_grants
        || evidence_receipt_signer
        || evidence_erasure
        || evidence_checkpoint
        || evidence_archive
        || evidence_transparency_publisher)
        && has_evidence_metadata
    {
        return Err(BrokerError::BindingMismatch);
    }
    if (evidence_webauthn
        || evidence_grants
        || evidence_receipt_signer
        || evidence_erasure
        || evidence_checkpoint
        || evidence_archive
        || evidence_transparency_publisher)
        && has_provider_ingest_metadata
    {
        return Err(BrokerError::BindingMismatch);
    }
    if moderation_panel_notification_archive {
        let archive =
            required_binding_value!(binding, moderation_panel_notification_archive_binding);
        if archive.archive_id == [0; 32]
            || archive.bootstrap_public_key == [0; 32]
            || iroha_crypto::ed25519_parse_public_key(&archive.bootstrap_public_key).is_err()
            || archive.public_key == [0; 32]
            || iroha_crypto::ed25519_parse_public_key(&archive.public_key).is_err()
            || archive.max_bytes == 0
            || archive.max_bytes
                > u64::try_from(MAX_BROKER_EVIDENCE_VIEWER_BULK_BYTES_V1)
                    .map_err(|_| BrokerError::Protocol)?
            || archive.max_records == 0
            || archive.max_records
                > u64::try_from(
                    sorafs_node::moderation_orchestrator::
                        MODERATION_PANEL_NOTIFICATION_ARCHIVE_MAX_RECORDS_V1,
                )
                .map_err(|_| BrokerError::Protocol)?
            || has_evidence_metadata
            || has_provider_ingest_metadata
            || binding.native_signer_binding.is_some()
            || binding.governance_request_ingress_binding.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if moderation_quarantine
        || moderation_transaction_signer
        || moderation_delivery_boundary
        || moderation_checkpoint
        || governance_signer
        || governance_request_auth
        || governance_checkpoint
        || native_transaction_signer
        || soracloud_runtime_signer
    {
        if binding.provider_ingest_signer_binding.is_some()
            || binding.provider_ingest_source_limits.is_some()
            || binding.provider_ingest_checkpoint_max_bytes.is_some()
            || binding
                .provider_ingest_max_signed_transaction_bytes
                .is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if provider_ingest_source {
        let limits = required_binding_value!(binding, provider_ingest_source_limits);
        if limits.operation_timeout_ms == 0
            || limits.max_content_bytes == 0
            || limits.max_source_providers == 0
            || limits.max_concurrent_streams == 0
            || limits.max_concurrent_streams > MAX_PROVIDER_INGEST_SOURCE_STREAMS_V1
            || binding.provider_ingest_signer_binding.is_some()
            || binding.provider_ingest_checkpoint_max_bytes.is_some()
            || binding
                .provider_ingest_max_signed_transaction_bytes
                .is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if provider_ingest_resolver || provider_ingest_signer {
        let signer = required_binding_ref!(binding, provider_ingest_signer_binding);
        signer.to_binding()?;
        let max_signed =
            required_binding_value!(binding, provider_ingest_max_signed_transaction_bytes);
        if max_signed < provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN
            || max_signed
                > u64::try_from(MAX_PROVIDER_INGEST_SIGNED_TRANSACTION_BYTES_V1)
                    .map_err(|_| BrokerError::Protocol)?
            || binding.provider_ingest_checkpoint_max_bytes.is_some()
            || binding.provider_ingest_source_limits.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        if provider_ingest_signer
            && (binding.handle != signer.runtime_handle
                || binding.revision != Some(signer.adapter_revision)
                || binding.policy_digest != Some(signer.signer_policy_digest))
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if provider_ingest_checkpoint {
        let max_checkpoint = required_binding_value!(binding, provider_ingest_checkpoint_max_bytes);
        if max_checkpoint == 0
            || max_checkpoint
                > u64::try_from(MAX_BROKER_PROVIDER_INGEST_CHECKPOINT_BYTES_V1)
                    .map_err(|_| BrokerError::Protocol)?
            || binding.provider_ingest_signer_binding.is_some()
            || binding.provider_ingest_source_limits.is_some()
            || binding
                .provider_ingest_max_signed_transaction_bytes
                .is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if provider_ingest_retention {
        if binding.provider_ingest_signer_binding.is_some()
            || binding.provider_ingest_source_limits.is_some()
            || binding.provider_ingest_checkpoint_max_bytes.is_some()
            || binding
                .provider_ingest_max_signed_transaction_bytes
                .is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if evidence_webauthn {
        let webauthn = required_binding_ref!(binding, evidence_viewer_webauthn_binding);
        if validate_webauthn_wire_policy(&webauthn.rp_id, &webauthn.allowed_origins).is_err()
            || webauthn.challenge_ttl_ms == 0
            || webauthn.challenge_ttl_ms
                > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_SESSION_TTL_MS_V1
            || binding.evidence_viewer_grant_ttl_ms.is_some()
            || binding.evidence_viewer_receipt_signer_public_key.is_some()
            || binding
                .evidence_viewer_transparency_publisher_public_key
                .is_some()
            || binding.evidence_viewer_checkpoint_max_bytes.is_some()
            || binding.evidence_viewer_archive_id.is_some()
            || binding.evidence_viewer_archive_public_key.is_some()
            || binding.evidence_viewer_archive_max_bytes.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if evidence_grants {
        let grant_ttl_ms = required_binding_value!(binding, evidence_viewer_grant_ttl_ms);
        if grant_ttl_ms == 0
            || grant_ttl_ms > sorafs_node::evidence_viewer::EVIDENCE_VIEWER_MAX_SESSION_TTL_MS_V1
            || binding.evidence_viewer_webauthn_binding.is_some()
            || binding.evidence_viewer_receipt_signer_public_key.is_some()
            || binding
                .evidence_viewer_transparency_publisher_public_key
                .is_some()
            || binding.evidence_viewer_checkpoint_max_bytes.is_some()
            || binding.evidence_viewer_archive_id.is_some()
            || binding.evidence_viewer_archive_public_key.is_some()
            || binding.evidence_viewer_archive_max_bytes.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if evidence_receipt_signer {
        let public_key =
            required_binding_value!(binding, evidence_viewer_receipt_signer_public_key);
        if public_key == [0; 32]
            || iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &public_key)
                .is_err()
            || binding.evidence_viewer_webauthn_binding.is_some()
            || binding.evidence_viewer_grant_ttl_ms.is_some()
            || binding
                .evidence_viewer_transparency_publisher_public_key
                .is_some()
            || binding.evidence_viewer_checkpoint_max_bytes.is_some()
            || binding.evidence_viewer_archive_id.is_some()
            || binding.evidence_viewer_archive_public_key.is_some()
            || binding.evidence_viewer_archive_max_bytes.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if evidence_erasure {
        if has_evidence_metadata {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if evidence_checkpoint {
        let max_bytes = required_binding_value!(binding, evidence_viewer_checkpoint_max_bytes);
        if max_bytes == 0
            || max_bytes
                > u64::try_from(MAX_EVIDENCE_VIEWER_CHECKPOINT_BYTES_V1)
                    .map_err(|_| BrokerError::Protocol)?
            || binding.evidence_viewer_webauthn_binding.is_some()
            || binding.evidence_viewer_grant_ttl_ms.is_some()
            || binding.evidence_viewer_receipt_signer_public_key.is_some()
            || binding
                .evidence_viewer_transparency_publisher_public_key
                .is_some()
            || binding.evidence_viewer_archive_id.is_some()
            || binding.evidence_viewer_archive_public_key.is_some()
            || binding.evidence_viewer_archive_max_bytes.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if evidence_archive {
        let archive_id = required_binding_value!(binding, evidence_viewer_archive_id);
        let public_key = required_binding_value!(binding, evidence_viewer_archive_public_key);
        let max_bytes = required_binding_value!(binding, evidence_viewer_archive_max_bytes);
        if archive_id == [0; 32]
            || public_key == [0; 32]
            || iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &public_key)
                .is_err()
            || max_bytes == 0
            || max_bytes
                > u64::try_from(MAX_BROKER_EVIDENCE_VIEWER_BULK_BYTES_V1)
                    .map_err(|_| BrokerError::Protocol)?
            || binding.evidence_viewer_webauthn_binding.is_some()
            || binding.evidence_viewer_grant_ttl_ms.is_some()
            || binding.evidence_viewer_receipt_signer_public_key.is_some()
            || binding
                .evidence_viewer_transparency_publisher_public_key
                .is_some()
            || binding.evidence_viewer_checkpoint_max_bytes.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    if evidence_transparency_publisher {
        let public_key =
            required_binding_value!(binding, evidence_viewer_transparency_publisher_public_key);
        if public_key == [0; 32]
            || iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &public_key)
                .is_err()
            || binding.evidence_viewer_webauthn_binding.is_some()
            || binding.evidence_viewer_grant_ttl_ms.is_some()
            || binding.evidence_viewer_receipt_signer_public_key.is_some()
            || binding.evidence_viewer_checkpoint_max_bytes.is_some()
            || binding.evidence_viewer_archive_id.is_some()
            || binding.evidence_viewer_archive_public_key.is_some()
            || binding.evidence_viewer_archive_max_bytes.is_some()
        {
            return Err(BrokerError::BindingMismatch);
        }
        return Ok(());
    }
    Err(BrokerError::BindingMismatch)
}
fn compare_wire_bindings(
    left: &ProviderBindingWireV1,
    right: &ProviderBindingWireV1,
) -> std::cmp::Ordering {
    left.slot
        .cmp(&right.slot)
        .then_with(|| left.handle.cmp(&right.handle))
        .then_with(|| left.revision.cmp(&right.revision))
        .then_with(|| left.policy_digest.cmp(&right.policy_digest))
}
fn validate_catalog_slot_ids(slot_ids: impl IntoIterator<Item = u16>) -> Result<(), BrokerError> {
    let mut multiplicities = [0_usize; IrohaRuntimeProviderSlotV1::ALL.len()];
    let mut entry_count = 0_usize;
    for wire_id in slot_ids {
        entry_count = entry_count
            .checked_add(1)
            .ok_or(BrokerError::BindingMismatch)?;
        if entry_count > MAX_CATALOG_ENTRIES_V1 {
            return Err(BrokerError::BindingMismatch);
        }
        let slot = IrohaRuntimeProviderSlotV1::from_wire_id(wire_id)
            .ok_or(BrokerError::BindingMismatch)?;
        // Wire IDs are sparse. Count only positions in the canonical inventory.
        let slot_index = IrohaRuntimeProviderSlotV1::ALL
            .binary_search(&slot)
            .map_err(|_| BrokerError::BindingMismatch)?;
        multiplicities[slot_index] = multiplicities[slot_index]
            .checked_add(1)
            .ok_or(BrokerError::BindingMismatch)?;
        if multiplicities[slot_index] > slot.max_configured_multiplicity() {
            return Err(BrokerError::BindingMismatch);
        }
    }
    if entry_count == 0 {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::SignerMetadataWireV1"; SignerMetadataWireV1 { publisher_peer_id: Vec<u8>, public_key: [u8; 32], });
define_broker_wire_struct!(owned ProviderObservationWireV1 { binding: ProviderBindingWireV1, signer_metadata: Option<SignerMetadataWireV1>, governance_request_ingress_qualification: Option<GovernanceRequestIngressQualificationWireV1>, moderation_quarantine_active_key_id: Option<String>, provider_ingest_signer_binding: Option<ProviderIngestSignerBindingWireV1>, provider_ingest_source_provider_ids: Vec<[u8; 32]>, potr_signer_public_key: Vec<u8>, evidence_viewer_receipt_signer_public_key: Option<[u8; 32]>, evidence_viewer_archive_id: Option<[u8; 32]>, evidence_viewer_archive_public_key: Option<[u8; 32]>, moderation_checkpoint_attestation_public_key: Option<[u8; 32]>, moderation_panel_notification_archive_binding: Option<ModerationPanelNotificationArchiveBindingWireV1>, metadata_digest: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::HandshakeTranscriptFieldsV1"; HandshakeTranscriptFieldsV1 { chain_id: String, network_id: NetworkId, requested_catalog: Vec<ProviderBindingWireV1>, client_nonce: [u8; 32], catalog_digest: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::HandshakeRequestV1"; HandshakeRequestV1 { chain_id: String, network_id: NetworkId, requested_catalog: Vec<ProviderBindingWireV1>, client_nonce: [u8; 32], catalog_digest: [u8; 32], client_transcript_digest: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ServerTranscriptFieldsV1"; ServerTranscriptFieldsV1 { chain_id: String, network_id: NetworkId, requested_catalog: Vec<ProviderBindingWireV1>, client_nonce: [u8; 32], catalog_digest: [u8; 32], client_transcript_digest: [u8; 32], session_id: [u8; 32], observations: Vec<ProviderObservationWireV1>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::HandshakeResponseV1"; HandshakeResponseV1 { chain_id: String, network_id: NetworkId, requested_catalog: Vec<ProviderBindingWireV1>, client_nonce: [u8; 32], catalog_digest: [u8; 32], client_transcript_digest: [u8; 32], session_id: [u8; 32], observations: Vec<ProviderObservationWireV1>, server_transcript_digest: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::OperationRequestFieldsV1"; OperationRequestFieldsV1 { session_id: [u8; 32], request_id: u64, binding: ProviderBindingWireV1, provider_metadata_digest: [u8; 32], operation: u16, payload_digest: [u8; 32], payload_len: u64, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::OperationRequestV1"; OperationRequestV1 { session_id: [u8; 32], request_id: u64, binding: ProviderBindingWireV1, provider_metadata_digest: [u8; 32], operation: u16, payload_digest: [u8; 32], payload: Vec<u8>, request_digest: [u8; 32], });
impl_broker_debug_fields!(OperationRequestV1 as value {
    "request_id" => value.request_id,
    "slot" => value.binding.slot,
    "operation" => value.operation,
    "payload_len" => value.payload.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(OperationRequestV1 { payload });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::OperationResponseFieldsV1"; OperationResponseFieldsV1 { session_id: [u8; 32], request_id: u64, request_digest: [u8; 32], observed_binding: ProviderBindingWireV1, provider_metadata_digest: [u8; 32], operation: u16, payload_digest: [u8; 32], status: u8, result_digest: [u8; 32], result_len: u64, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::OperationResponseV1"; OperationResponseV1 { session_id: [u8; 32], request_id: u64, request_digest: [u8; 32], observed_binding: ProviderBindingWireV1, provider_metadata_digest: [u8; 32], operation: u16, payload_digest: [u8; 32], status: u8, result_digest: [u8; 32], result: Vec<u8>, response_digest: [u8; 32], });
impl_broker_debug_fields!(OperationResponseV1 as value {
    "request_id" => value.request_id,
    "slot" => value.observed_binding.slot,
    "operation" => value.operation,
    "status" => value.status,
    "result_len" => value.result.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(OperationResponseV1 { result });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::QualificationResultWireV1"; QualificationResultWireV1 { revision: u64, policy_digest: [u8; 32], });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::GovernanceRequestIngressQualificationWireV1"; GovernanceRequestIngressQualificationWireV1 { provider: QualificationResultWireV1, binding: GovernanceRequestIngressBindingWireV1, receiver_policy_digest: [u8; 32], replay_namespace_digest: [u8; 32], replica_set_digest: [u8; 32], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BootleLanternAuthenticateRequestWireV1"; BootleLanternAuthenticateRequestWireV1 { opaque_credential: Vec<u8>, action: u8, request_binding: [u8; 32], committed_height: u64, });
impl_broker_debug_fields!(BootleLanternAuthenticateRequestWireV1 as value {
    "credential_len" => value.opaque_credential.len(),
    "action" => value.action,
    "committed_height" => value.committed_height,
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(BootleLanternAuthenticateRequestWireV1 { opaque_credential });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::BootleLanternAuthenticatedPrincipalWireV1"; BootleLanternAuthenticatedPrincipalWireV1 { principal_digest: [u8; 32], issued_at_height: u64, expires_at_height: u64, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BootleLanternPrepareAuthorizationRequestWireV1"; BootleLanternPrepareAuthorizationRequestWireV1 { context: iroha_data_model::privacy::PrivacyStatementContextV1, canonical_genesis_hash: [u8; 32], policy: iroha_data_model::privacy::BootleLanternIssuerPolicyV1, requester_authorization_digest: [u8; 32], issued_at_height: u64, expires_at_height: u64, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BootleLanternAuthorizationWireV1"; BootleLanternAuthorizationWireV1 { authorization: Vec<u8>, });
impl_broker_debug_fields!(BootleLanternAuthorizationWireV1 as value {
    "authorization_len" => value.authorization.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(BootleLanternAuthorizationWireV1 { authorization });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BootleLanternIssueRequestWireV1"; BootleLanternIssueRequestWireV1 { context: iroha_data_model::privacy::PrivacyStatementContextV1, canonical_genesis_hash: [u8; 32], policy: iroha_data_model::privacy::BootleLanternIssuerPolicyV1, authorization: Vec<u8>, request: Vec<u8>, current_height: u64, });
impl_broker_debug_fields!(BootleLanternIssueRequestWireV1 as value {
    "authorization_len" => value.authorization.len(),
    "request_len" => value.request.len(),
    "current_height" => value.current_height,
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(BootleLanternIssueRequestWireV1 {
    authorization,
    request
});
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BootleLanternIssuanceResponseWireV1"; BootleLanternIssuanceResponseWireV1 { response: Vec<u8>, });
impl_broker_debug_fields!(BootleLanternIssuanceResponseWireV1 as value {
    "response_len" => value.response.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(BootleLanternIssuanceResponseWireV1 { response });
fn bootle_lantern_action_to_wire(
    action: iroha_torii::privacy_issuance_api::BootleLanternIssuanceActionV1,
) -> u8 {
    match action {
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceActionV1::Authorize => 1,
        iroha_torii::privacy_issuance_api::BootleLanternIssuanceActionV1::Issue => 2,
    }
}
fn bootle_lantern_action_from_wire(
    action: u8,
) -> Result<iroha_torii::privacy_issuance_api::BootleLanternIssuanceActionV1, BrokerError> {
    match action {
        1 => Ok(iroha_torii::privacy_issuance_api::BootleLanternIssuanceActionV1::Authorize),
        2 => Ok(iroha_torii::privacy_issuance_api::BootleLanternIssuanceActionV1::Issue),
        _ => Err(BrokerError::Rejected),
    }
}
fn bootle_lantern_bindings_from_wire(
    binding: &ProviderBindingWireV1,
) -> Result<
    iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1,
    BrokerError,
> {
    if binding.slot != IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry.wire_id() {
        return Err(BrokerError::BindingMismatch);
    }
    let exact = required_binding_value!(binding, bootle_lantern_issuance_bindings);
    iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1::try_new(
        iroha_data_model::privacy::PrivacyIssuerIdV1::new(exact.issuer_id),
        iroha_data_model::privacy::PrivacyPolicyIdV1::new(exact.policy_id),
        exact.authorization_lifetime_blocks,
    )
    .map_err(|_| BrokerError::BindingMismatch)
}
fn validate_bootle_lantern_policy_binding(
    binding: &ProviderBindingWireV1,
    policy: &iroha_data_model::privacy::BootleLanternIssuerPolicyV1,
) -> Result<
    iroha_torii::privacy_issuance_api::BootleLanternIssuanceRuntimeProviderBindingsV1,
    BrokerError,
> {
    let exact = bootle_lantern_bindings_from_wire(binding)?;
    if policy.issuer_id != exact.issuer_id()
        || policy.policy_id != exact.policy_id()
        || policy.lifecycle
            != iroha_data_model::privacy::BootleLanternIssuerPolicyLifecycleV1::Active
        || policy.validate().is_err()
    {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(exact)
}
fn validate_bootle_lantern_prepare_request(
    request: &BootleLanternPrepareAuthorizationRequestWireV1,
    binding: &ProviderBindingWireV1,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    let exact = validate_bootle_lantern_policy_binding(binding, &request.policy)?;
    if request.canonical_genesis_hash == [0; 32]
        || request.context.network_id.as_bytes() != &request.canonical_genesis_hash
        || request.requester_authorization_digest == [0; 32]
        || request.issued_at_height == 0
        || request
            .expires_at_height
            .checked_sub(request.issued_at_height)
            != Some(exact.authorization_lifetime_blocks())
        || &request.context.network_id != session_network_id
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn decode_bootle_lantern_issue_request(
    payload: &[u8],
    binding: &ProviderBindingWireV1,
    session_network_id: &NetworkId,
) -> Result<
    (
        BootleLanternIssueRequestWireV1,
        iroha_core_privacy::privacy_engines::bootle_lantern::issuer::BootleLanternIssuanceAuthorizationV1,
    ),
    BrokerError,
>{
    let request = decode_canonical::<BootleLanternIssueRequestWireV1>(
        payload,
        MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
    )?;
    let exact = validate_bootle_lantern_policy_binding(binding, &request.policy)?;
    if request.canonical_genesis_hash == [0; 32]
        || request.context.network_id.as_bytes() != &request.canonical_genesis_hash
        || request.current_height == 0
        || request.authorization.len() != BOOTLE_LANTERN_AUTHORIZATION_BYTES_V1
        || request.request.len() != BOOTLE_LANTERN_REQUEST_BYTES_V1
        || &request.context.network_id != session_network_id
    {
        return Err(BrokerError::Rejected);
    }
    let authorization = iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
        BootleLanternIssuanceAuthorizationV1::decode_exact(&request.authorization)
        .map_err(|_| BrokerError::Rejected)?;
    if authorization.issued_at_height() == 0
        || authorization.expires_at_height() < authorization.issued_at_height()
        || authorization
            .expires_at_height()
            .checked_sub(authorization.issued_at_height())
            != Some(exact.authorization_lifetime_blocks())
    {
        return Err(BrokerError::Rejected);
    }
    iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
        BootleLanternBlindIssuanceRequestV1::decode_exact(
            &request.request,
            u32::try_from(BOOTLE_LANTERN_REQUEST_BYTES_V1)
                .map_err(|_| BrokerError::Protocol)?,
        )
        .map_err(|_| BrokerError::Rejected)?;
    iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
        issuer_validate_blind_issuance_request_encoded_v1(
            &request.context,
            request.canonical_genesis_hash,
            &request.policy,
            &authorization,
            &request.request,
            request.current_height,
        )
        .map_err(|_| BrokerError::Rejected)?;
    Ok((request, authorization))
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::SoracloudSignerQualificationWireV1"; SoracloudSignerQualificationWireV1 { revision: u64, policy_digest: [u8; 32], active: bool, test_only: bool, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::SoracloudProvenanceSignRequestWireV1"; SoracloudProvenanceSignRequestWireV1 { purpose: u8, preimage: Vec<u8>, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PrivacyCyclePrfRequestWireV1"; PrivacyCyclePrfRequestWireV1 { version: u16, query_id: [u8; 32], policy_digest: [u8; 32], population_inventory_digest: [u8; 32], metric_schema_digest: [u8; 32], cycle_id: [u8; 16], cycle_start_unix: u64, cycle_end_unix: u64, binding_digest: [u8; 32], });
impl PrivacyCyclePrfRequestWireV1 {
    fn from_request(request: &sorafs_node::PrivacyCyclePrfRequestV1) -> Self {
        Self {
            version: request.version(),
            query_id: request.query_id(),
            policy_digest: request.policy_digest(),
            population_inventory_digest: request.population_inventory_digest(),
            metric_schema_digest: request.metric_schema_digest(),
            cycle_id: request.cycle_id(),
            cycle_start_unix: request.cycle_start_unix(),
            cycle_end_unix: request.cycle_end_unix(),
            binding_digest: request.binding_digest(),
        }
    }
    fn to_request(self) -> Result<sorafs_node::PrivacyCyclePrfRequestV1, BrokerError> {
        if self.version != sorafs_node::PRIVACY_CYCLE_PRF_REQUEST_VERSION_V1 {
            return Err(BrokerError::Rejected);
        }
        let request = sorafs_node::PrivacyCyclePrfRequestV1::new(
            self.query_id,
            self.policy_digest,
            self.population_inventory_digest,
            self.metric_schema_digest,
            sorafs_node::PrivacyAggregateCycleWindow {
                cycle_start_unix: self.cycle_start_unix,
                cycle_end_unix: self.cycle_end_unix,
                due_at_unix: self.cycle_end_unix,
            },
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_request(&request) != self {
            return Err(BrokerError::Rejected);
        }
        Ok(request)
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::PrivacyCyclePrfOutputWireV1"; PrivacyCyclePrfOutputWireV1 { output: [u8; 32], });
impl_broker_debug_fields!(PrivacyCyclePrfOutputWireV1 as value {
    "output" => "<redacted>",
} => finish);
impl_scrub_fields_on_drop!(PrivacyCyclePrfOutputWireV1 { output });
define_broker_wire_struct!(owned TransparencyRuntimeProviderBindingWireV1 { handle: String, revision: u64, policy_digest: [u8; 32], });
impl TransparencyRuntimeProviderBindingWireV1 {
    fn from_binding(binding: &sorafs_node::TransparencyRuntimeProviderBindingV1) -> Self {
        Self {
            handle: binding.handle().to_owned(),
            revision: binding.qualification().revision(),
            policy_digest: binding.qualification().policy_digest(),
        }
    }
    fn to_binding(&self) -> Result<sorafs_node::TransparencyRuntimeProviderBindingV1, BrokerError> {
        let binding = sorafs_node::TransparencyRuntimeProviderBindingV1::try_new(
            self.handle.clone(),
            self.revision,
            self.policy_digest,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_binding(&binding) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(binding)
    }
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PrivacyReleaseAnchorHeadWireV1"; PrivacyReleaseAnchorHeadWireV1 { query_id: [u8; 32], sequence: u64, release_id: [u8; 16], record_digest: [u8; 32], latest_publication_block_hash: Option<[u8; 32]>, });
impl PrivacyReleaseAnchorHeadWireV1 {
    fn from_head(head: sorafs_node::PrivacyReleaseAnchorHeadV1) -> Self {
        Self {
            query_id: head.query_id(),
            sequence: head.sequence(),
            release_id: head.release_id(),
            record_digest: head.record_digest(),
            latest_publication_block_hash: head.latest_publication_block_hash(),
        }
    }
    fn to_head(self) -> Result<sorafs_node::PrivacyReleaseAnchorHeadV1, BrokerError> {
        let head = sorafs_node::PrivacyReleaseAnchorHeadV1::try_from_parts(
            self.query_id,
            self.sequence,
            self.release_id,
            self.record_digest,
            self.latest_publication_block_hash,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_head(head) != self {
            return Err(BrokerError::Rejected);
        }
        Ok(head)
    }
}
define_broker_wire_struct!(copy TransparencyLeaderLeaseScopeWireV1 { query_id: [u8; 32], cycle_id: [u8; 16], cycle_start_unix: u64, cycle_end_unix: u64, due_at_unix: u64, holder_identity: [u8; 32], });
impl TransparencyLeaderLeaseScopeWireV1 {
    fn from_scope(scope: sorafs_node::TransparencyLeaderLeaseScopeV1) -> Self {
        let window = scope.window();
        Self {
            query_id: scope.query_id(),
            cycle_id: scope.cycle_id(),
            cycle_start_unix: window.cycle_start_unix,
            cycle_end_unix: window.cycle_end_unix,
            due_at_unix: window.due_at_unix,
            holder_identity: scope.holder_identity(),
        }
    }
    fn to_scope(self) -> Result<sorafs_node::TransparencyLeaderLeaseScopeV1, BrokerError> {
        let scope = sorafs_node::TransparencyLeaderLeaseScopeV1::try_new(
            self.query_id,
            sorafs_node::PrivacyAggregateCycleWindow {
                cycle_start_unix: self.cycle_start_unix,
                cycle_end_unix: self.cycle_end_unix,
                due_at_unix: self.due_at_unix,
            },
            self.holder_identity,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_scope(scope) != self {
            return Err(BrokerError::Rejected);
        }
        Ok(scope)
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::TransparencyLeaderLeaseGrantWireV1"; TransparencyLeaderLeaseGrantWireV1 { version: u16, lease_id: [u8; 32], scope: TransparencyLeaderLeaseScopeWireV1, fencing_token: u64, issued_at_unix: u64, expires_at_unix: u64, provider_binding: TransparencyRuntimeProviderBindingWireV1, });
impl TransparencyLeaderLeaseGrantWireV1 {
    fn from_grant(grant: &sorafs_node::TransparencyLeaderLeaseGrantV1) -> Self {
        Self {
            version: grant.version(),
            lease_id: grant.lease_id(),
            scope: TransparencyLeaderLeaseScopeWireV1::from_scope(grant.scope()),
            fencing_token: grant.fencing_token(),
            issued_at_unix: grant.issued_at_unix(),
            expires_at_unix: grant.expires_at_unix(),
            provider_binding: TransparencyRuntimeProviderBindingWireV1::from_binding(
                grant.provider_binding(),
            ),
        }
    }
    fn to_grant(&self) -> Result<sorafs_node::TransparencyLeaderLeaseGrantV1, BrokerError> {
        if self.version != sorafs_node::TRANSPARENCY_LEADER_LEASE_VERSION_V1 {
            return Err(BrokerError::Rejected);
        }
        let grant = sorafs_node::TransparencyLeaderLeaseGrantV1::try_new(
            self.lease_id,
            self.scope.to_scope()?,
            self.fencing_token,
            self.issued_at_unix,
            self.expires_at_unix,
            self.provider_binding.to_binding()?,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_grant(&grant) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(grant)
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::TransparencyLeaderLeaseAcquireRequestWireV1"; TransparencyLeaderLeaseAcquireRequestWireV1 { scope: TransparencyLeaderLeaseScopeWireV1, acquire_at_unix: u64, expires_at_unix: u64, fencing_floor: u64, provider_binding: TransparencyRuntimeProviderBindingWireV1, });
impl TransparencyLeaderLeaseAcquireRequestWireV1 {
    fn from_request(request: &sorafs_node::TransparencyLeaderLeaseAcquireRequestV1) -> Self {
        Self {
            scope: TransparencyLeaderLeaseScopeWireV1::from_scope(request.scope()),
            acquire_at_unix: request.acquire_at_unix(),
            expires_at_unix: request.expires_at_unix(),
            fencing_floor: request.fencing_floor(),
            provider_binding: TransparencyRuntimeProviderBindingWireV1::from_binding(
                request.provider_binding(),
            ),
        }
    }
    fn to_request(
        &self,
    ) -> Result<sorafs_node::TransparencyLeaderLeaseAcquireRequestV1, BrokerError> {
        let request = sorafs_node::TransparencyLeaderLeaseAcquireRequestV1::try_new(
            self.scope.to_scope()?,
            self.acquire_at_unix,
            self.expires_at_unix,
            self.fencing_floor,
            self.provider_binding.to_binding()?,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_request(&request) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(request)
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::TransparencyLeaderLeaseRenewRequestWireV1"; TransparencyLeaderLeaseRenewRequestWireV1 { current_grant: TransparencyLeaderLeaseGrantWireV1, renew_at_unix: u64, expires_at_unix: u64, fencing_floor: u64, });
impl TransparencyLeaderLeaseRenewRequestWireV1 {
    fn from_request(request: &sorafs_node::TransparencyLeaderLeaseRenewRequestV1) -> Self {
        Self {
            current_grant: TransparencyLeaderLeaseGrantWireV1::from_grant(request.current_grant()),
            renew_at_unix: request.renew_at_unix(),
            expires_at_unix: request.expires_at_unix(),
            fencing_floor: request.fencing_floor(),
        }
    }
    fn to_request(
        &self,
    ) -> Result<sorafs_node::TransparencyLeaderLeaseRenewRequestV1, BrokerError> {
        let request = sorafs_node::TransparencyLeaderLeaseRenewRequestV1::try_new(
            self.current_grant.to_grant()?,
            self.renew_at_unix,
            self.expires_at_unix,
            self.fencing_floor,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_request(&request) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(request)
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::TransparencyLeaderLeaseReleaseRequestWireV1"; TransparencyLeaderLeaseReleaseRequestWireV1 { current_grant: TransparencyLeaderLeaseGrantWireV1, release_at_unix: u64, });
impl TransparencyLeaderLeaseReleaseRequestWireV1 {
    fn from_request(request: &sorafs_node::TransparencyLeaderLeaseReleaseRequestV1) -> Self {
        Self {
            current_grant: TransparencyLeaderLeaseGrantWireV1::from_grant(request.current_grant()),
            release_at_unix: request.release_at_unix(),
        }
    }
    fn to_request(
        &self,
    ) -> Result<sorafs_node::TransparencyLeaderLeaseReleaseRequestV1, BrokerError> {
        let request = sorafs_node::TransparencyLeaderLeaseReleaseRequestV1::try_new(
            self.current_grant.to_grant()?,
            self.release_at_unix,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_request(&request) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(request)
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::TransparencyLeaderLeaseReleaseReceiptWireV1"; TransparencyLeaderLeaseReleaseReceiptWireV1 { version: u16, lease_id: [u8; 32], scope: TransparencyLeaderLeaseScopeWireV1, fencing_token: u64, released_at_unix: u64, provider_binding: TransparencyRuntimeProviderBindingWireV1, });
impl TransparencyLeaderLeaseReleaseReceiptWireV1 {
    fn from_receipt(receipt: &sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1) -> Self {
        Self {
            version: receipt.version(),
            lease_id: receipt.lease_id(),
            scope: TransparencyLeaderLeaseScopeWireV1::from_scope(receipt.scope()),
            fencing_token: receipt.fencing_token(),
            released_at_unix: receipt.released_at_unix(),
            provider_binding: TransparencyRuntimeProviderBindingWireV1::from_binding(
                receipt.provider_binding(),
            ),
        }
    }
    fn to_receipt(
        &self,
    ) -> Result<sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1, BrokerError> {
        if self.version != sorafs_node::TRANSPARENCY_LEADER_LEASE_VERSION_V1 {
            return Err(BrokerError::Rejected);
        }
        let receipt = sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1::try_new(
            self.lease_id,
            self.scope.to_scope()?,
            self.fencing_token,
            self.released_at_unix,
            self.provider_binding.to_binding()?,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_receipt(&receipt) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(receipt)
    }
}
define_broker_wire_struct!(copy FencedTransparencyTargetHeadWireV1 { version: u8, generation: u64, head_digest: [u8; 32], fencing_floor: u64, });
impl FencedTransparencyTargetHeadWireV1 {
    fn from_head(head: sorafs_node::FencedTransparencyTargetHeadV1) -> Self {
        Self {
            version: sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1,
            generation: head.generation(),
            head_digest: head.head_digest(),
            fencing_floor: head.fencing_floor(),
        }
    }
    fn to_head(self) -> Result<sorafs_node::FencedTransparencyTargetHeadV1, BrokerError> {
        if self.version != sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1 {
            return Err(BrokerError::Rejected);
        }
        let head = sorafs_node::FencedTransparencyTargetHeadV1::try_new(
            self.generation,
            self.head_digest,
            self.fencing_floor,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_head(head) != self {
            return Err(BrokerError::Rejected);
        }
        Ok(head)
    }
}
define_broker_wire_struct!(owned PrivacyPublicationAuthorizationWireV1 { leader_lease: TransparencyLeaderLeaseGrantWireV1, finalized_anchor: PrivacyReleaseAnchorHeadWireV1, release_sequence: u64, release_record_digest: [u8; 32], payload_digest: [u8; 32], });
impl PrivacyPublicationAuthorizationWireV1 {
    fn from_authorization(authorization: &sorafs_node::PrivacyPublicationAuthorizationV1) -> Self {
        Self {
            leader_lease: TransparencyLeaderLeaseGrantWireV1::from_grant(
                authorization.leader_lease(),
            ),
            finalized_anchor: PrivacyReleaseAnchorHeadWireV1::from_head(
                authorization.finalized_anchor(),
            ),
            release_sequence: authorization.release_sequence(),
            release_record_digest: authorization.release_record_digest(),
            payload_digest: authorization.payload_digest(),
        }
    }
    fn to_authorization(
        &self,
    ) -> Result<sorafs_node::PrivacyPublicationAuthorizationV1, BrokerError> {
        let authorization = sorafs_node::PrivacyPublicationAuthorizationV1::try_from_runtime_parts(
            self.leader_lease.to_grant()?,
            self.finalized_anchor.to_head()?,
            self.release_sequence,
            self.release_record_digest,
            self.payload_digest,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_authorization(&authorization) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(authorization)
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::FencedPrivacyPublicationRequestWireV1"; FencedPrivacyPublicationRequestWireV1 { version: u8, authorization: PrivacyPublicationAuthorizationWireV1, authorization_digest: [u8; 32], publication_idempotency_digest: [u8; 32], canonical_payload: Vec<u8>, payload_digest: [u8; 32], expected_authoritative_head: Option<FencedTransparencyTargetHeadWireV1>, fencing_token: u64, fencing_floor: u64, request_digest: [u8; 32], });
impl_broker_debug_fields!(FencedPrivacyPublicationRequestWireV1 as value {
    "version" => value.version,
    "authorization" => value.authorization,
    "authorization_digest" => value.authorization_digest,
    "publication_idempotency_digest" => value.publication_idempotency_digest,
    "canonical_payload_len" => value.canonical_payload.len(),
    "payload_digest" => value.payload_digest,
    "expected_authoritative_head" => value.expected_authoritative_head,
    "fencing_token" => value.fencing_token,
    "fencing_floor" => value.fencing_floor,
    "request_digest" => value.request_digest,
} => finish);
impl FencedPrivacyPublicationRequestWireV1 {
    fn from_request(request: &sorafs_node::FencedPrivacyPublicationRequestV1) -> Self {
        Self {
            version: sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1,
            authorization: PrivacyPublicationAuthorizationWireV1::from_authorization(
                request.authorization(),
            ),
            authorization_digest: request.authorization_digest(),
            publication_idempotency_digest: request.publication_idempotency_digest(),
            canonical_payload: request.canonical_payload().to_vec(),
            payload_digest: request.payload_digest(),
            expected_authoritative_head: request
                .expected_authoritative_head()
                .map(FencedTransparencyTargetHeadWireV1::from_head),
            fencing_token: request.fencing_token(),
            fencing_floor: request.fencing_floor(),
            request_digest: request.request_digest(),
        }
    }
    fn matches_request(&self, request: &sorafs_node::FencedPrivacyPublicationRequestV1) -> bool {
        self.version == sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1
            && self.authorization
                == PrivacyPublicationAuthorizationWireV1::from_authorization(
                    request.authorization(),
                )
            && self.authorization_digest == request.authorization_digest()
            && self.publication_idempotency_digest == request.publication_idempotency_digest()
            && self.canonical_payload.as_slice() == request.canonical_payload()
            && self.payload_digest == request.payload_digest()
            && self.expected_authoritative_head
                == request
                    .expected_authoritative_head()
                    .map(FencedTransparencyTargetHeadWireV1::from_head)
            && self.fencing_token == request.fencing_token()
            && self.fencing_floor == request.fencing_floor()
            && self.request_digest == request.request_digest()
    }
    fn to_request(&self) -> Result<sorafs_node::FencedPrivacyPublicationRequestV1, BrokerError> {
        self.to_request_from_pool(shared_decode_resource_pool())
    }
    fn to_request_from_pool(
        &self,
        pool: Arc<DecodeResourcePoolV1>,
    ) -> Result<sorafs_node::FencedPrivacyPublicationRequestV1, BrokerError> {
        if let Some(admission) = current_decode_resource_admission() {
            if admission.operation != Some(OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1) {
                return Err(BrokerError::Protocol);
            }
            return self.to_request_with_admission(&admission);
        }
        let admission = DecodeResourceAdmissionV1::acquire_operation_from(
            pool,
            OPERATION_FENCED_PRIVACY_COMPARE_AND_APPEND_V1,
        )?;
        let _scope = admission.enter();
        self.to_request_with_admission(&admission)
    }
    fn to_request_with_admission(
        &self,
        admission: &DecodeResourceAdmissionV1,
    ) -> Result<sorafs_node::FencedPrivacyPublicationRequestV1, BrokerError> {
        if self.version != sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1 {
            return Err(BrokerError::Rejected);
        }
        validate_fenced_privacy_publication_payload_len(self.canonical_payload.len())?;
        let publication =
            decode_fenced_privacy_publication_with_admission(&self.canonical_payload, admission)?;
        let authorization = self.authorization.to_authorization()?;
        let expected_authoritative_head = self
            .expected_authoritative_head
            .map(FencedTransparencyTargetHeadWireV1::to_head)
            .transpose()?;
        // `try_new` takes ownership of an independent payload and its
        // final `validate` performs one more decode plus exact canonical
        // re-encode. The input was already decoded canonically under
        // explicit limits above; reserve both remaining phases before the
        // clone or the constructor's trusted revalidation can allocate.
        admission.reserve_retained_bytes(
            self.canonical_payload.len(),
            MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
        )?;
        admission.reserve_decode(
            self.canonical_payload.len(),
            MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1,
        )?;
        let request = sorafs_node::FencedPrivacyPublicationRequestV1::try_new(
            authorization,
            &publication,
            self.canonical_payload.clone(),
            expected_authoritative_head,
            self.fencing_floor,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if !self.matches_request(&request) {
            return Err(BrokerError::Rejected);
        }
        Ok(request)
    }
}
fn validate_fenced_privacy_publication_payload_len(payload_len: usize) -> Result<(), BrokerError> {
    if payload_len == 0 || payload_len > MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1 {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn decode_fenced_privacy_publication_with_admission(
    bytes: &[u8],
    admission: &DecodeResourceAdmissionV1,
) -> Result<sorafs_manifest::ModerationLedgerCyclePublicationV1, BrokerError> {
    const NORITO_V1_COMPRESSION_OFFSET: usize = 4 + 1 + 1 + 16;
    validate_fenced_privacy_publication_payload_len(bytes.len())?;
    // Canonical V1 payloads are never compressed. Inspect the fixed header
    // before invoking any decoder so a tiny compressed frame cannot expand
    // ahead of the broker's byte-derived allocation reservation.
    if bytes.get(NORITO_V1_COMPRESSION_OFFSET).copied() != Some(norito::Compression::None as u8) {
        return Err(BrokerError::Rejected);
    }
    let budget =
        admission.reserve_decode(bytes.len(), MAX_FENCED_PRIVACY_PUBLICATION_PAYLOAD_BYTES_V1)?;
    let limits = DecodeLimits::new(
        budget.max_sequence_elements,
        budget.max_blob_bytes,
        budget.max_total_elements,
        budget.max_total_allocated_bytes,
        budget.max_nesting_depth,
    );
    norito::decode_canonical_with_limits(bytes, limits).map_err(|_| BrokerError::Rejected)
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::FencedPrivacyPublicationReceiptWireV1"; FencedPrivacyPublicationReceiptWireV1 { version: u8, request_digest: [u8; 32], publication_idempotency_digest: [u8; 32], payload_digest: [u8; 32], disposition: u8, included_head: FencedTransparencyTargetHeadWireV1, readback_head: FencedTransparencyTargetHeadWireV1, head_inclusion_digest: [u8; 32], });
impl FencedPrivacyPublicationReceiptWireV1 {
    fn from_receipt(receipt: &sorafs_node::FencedPrivacyPublicationReceiptV1) -> Self {
        Self {
            version: sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1,
            request_digest: receipt.request_digest(),
            publication_idempotency_digest: receipt.publication_idempotency_digest(),
            payload_digest: receipt.payload_digest(),
            disposition: match receipt.disposition() {
                sorafs_node::FencedPrivacyPublicationDispositionV1::Appended => 0,
                sorafs_node::FencedPrivacyPublicationDispositionV1::AlreadyIncluded => 1,
            },
            included_head: FencedTransparencyTargetHeadWireV1::from_head(receipt.included_head()),
            readback_head: FencedTransparencyTargetHeadWireV1::from_head(receipt.readback_head()),
            head_inclusion_digest: receipt.head_inclusion_digest(),
        }
    }
    fn to_receipt(
        self,
        request: &sorafs_node::FencedPrivacyPublicationRequestV1,
        provider_handle: &str,
        provider_qualification: sorafs_node::GovernanceDagRuntimeProviderQualificationV1,
    ) -> Result<sorafs_node::FencedPrivacyPublicationReceiptV1, BrokerError> {
        if self.version != sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1 {
            return Err(BrokerError::Rejected);
        }
        let included_head = self.included_head.to_head()?;
        let readback_head = self.readback_head.to_head()?;
        let receipt = match self.disposition {
            0 => sorafs_node::FencedPrivacyPublicationReceiptV1::from_verified_append(
                request,
                provider_handle,
                provider_qualification,
            ),
            1 => sorafs_node::FencedPrivacyPublicationReceiptV1::from_verified_existing(
                request,
                provider_handle,
                provider_qualification,
                included_head,
                readback_head,
            ),
            _ => return Err(BrokerError::Rejected),
        }
        .map_err(|_| BrokerError::Rejected)?;
        receipt
            .validate_for_request(request, provider_handle, provider_qualification)
            .map_err(|_| BrokerError::Rejected)?;
        if Self::from_receipt(&receipt) != self {
            return Err(BrokerError::Rejected);
        }
        Ok(receipt)
    }
}
define_broker_wire_struct!(copy FencedTransparencyPublicationInclusionWireV1 { version: u8, publication_idempotency_digest: [u8; 32], payload_digest: [u8; 32], included_head: FencedTransparencyTargetHeadWireV1, });
impl FencedTransparencyPublicationInclusionWireV1 {
    fn from_inclusion(inclusion: sorafs_node::FencedTransparencyPublicationInclusionV1) -> Self {
        Self {
            version: sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1,
            publication_idempotency_digest: inclusion.publication_idempotency_digest(),
            payload_digest: inclusion.payload_digest(),
            included_head: FencedTransparencyTargetHeadWireV1::from_head(inclusion.included_head()),
        }
    }
    fn to_inclusion(
        self,
    ) -> Result<sorafs_node::FencedTransparencyPublicationInclusionV1, BrokerError> {
        if self.version != sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1 {
            return Err(BrokerError::Rejected);
        }
        let inclusion = sorafs_node::FencedTransparencyPublicationInclusionV1::try_new(
            self.publication_idempotency_digest,
            self.payload_digest,
            self.included_head.to_head()?,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_inclusion(inclusion) != self {
            return Err(BrokerError::Rejected);
        }
        Ok(inclusion)
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::FencedPrivacyHeadReadRequestWireV1"; FencedPrivacyHeadReadRequestWireV1 { version: u8, required_ancestors: Vec<FencedTransparencyTargetHeadWireV1>, required_publications: Vec<FencedTransparencyPublicationInclusionWireV1>, });
impl FencedPrivacyHeadReadRequestWireV1 {
    fn from_required_evidence(
        required_ancestors: &[sorafs_node::FencedTransparencyTargetHeadV1],
        required_publications: &[sorafs_node::FencedTransparencyPublicationInclusionV1],
    ) -> Self {
        Self {
            version: sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1,
            required_ancestors: required_ancestors
                .iter()
                .copied()
                .map(FencedTransparencyTargetHeadWireV1::from_head)
                .collect(),
            required_publications: required_publications
                .iter()
                .copied()
                .map(FencedTransparencyPublicationInclusionWireV1::from_inclusion)
                .collect(),
        }
    }
    fn to_required_evidence(
        &self,
    ) -> Result<
        (
            Vec<sorafs_node::FencedTransparencyTargetHeadV1>,
            Vec<sorafs_node::FencedTransparencyPublicationInclusionV1>,
        ),
        BrokerError,
    > {
        if self.version != sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1
            || self.required_ancestors.len() > MAX_FENCED_PRIVACY_HEAD_EVIDENCE_ITEMS_V1
            || self.required_publications.len() > MAX_FENCED_PRIVACY_HEAD_EVIDENCE_ITEMS_V1
        {
            return Err(BrokerError::Rejected);
        }
        let required_ancestors = self
            .required_ancestors
            .iter()
            .copied()
            .map(FencedTransparencyTargetHeadWireV1::to_head)
            .collect::<Result<Vec<_>, _>>()?;
        let required_publications = self
            .required_publications
            .iter()
            .copied()
            .map(FencedTransparencyPublicationInclusionWireV1::to_inclusion)
            .collect::<Result<Vec<_>, _>>()?;
        if Self::from_required_evidence(&required_ancestors, &required_publications) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok((required_ancestors, required_publications))
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::FencedTransparencyHeadAncestryProofWireV1"; FencedTransparencyHeadAncestryProofWireV1 { version: u8, authoritative_head: Option<FencedTransparencyTargetHeadWireV1>, verified_ancestors: Vec<FencedTransparencyTargetHeadWireV1>, verified_publications: Vec<FencedTransparencyPublicationInclusionWireV1>, adapter_proof_digest: [u8; 32], });
impl FencedTransparencyHeadAncestryProofWireV1 {
    fn from_proof(proof: &sorafs_node::FencedTransparencyHeadAncestryProofV1) -> Self {
        Self {
            version: sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1,
            authoritative_head: proof
                .authoritative_head()
                .map(FencedTransparencyTargetHeadWireV1::from_head),
            verified_ancestors: proof
                .verified_ancestors()
                .iter()
                .copied()
                .map(FencedTransparencyTargetHeadWireV1::from_head)
                .collect(),
            verified_publications: proof
                .verified_publications()
                .iter()
                .copied()
                .map(FencedTransparencyPublicationInclusionWireV1::from_inclusion)
                .collect(),
            adapter_proof_digest: proof.adapter_proof_digest(),
        }
    }
    fn to_proof(
        &self,
        required_ancestors: &[sorafs_node::FencedTransparencyTargetHeadV1],
        required_publications: &[sorafs_node::FencedTransparencyPublicationInclusionV1],
    ) -> Result<sorafs_node::FencedTransparencyHeadAncestryProofV1, BrokerError> {
        if self.version != sorafs_node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1
            || self.verified_ancestors.len() > MAX_FENCED_PRIVACY_HEAD_EVIDENCE_ITEMS_V1
            || self.verified_publications.len() > MAX_FENCED_PRIVACY_HEAD_EVIDENCE_ITEMS_V1
        {
            return Err(BrokerError::Rejected);
        }
        let authoritative_head = self
            .authoritative_head
            .map(FencedTransparencyTargetHeadWireV1::to_head)
            .transpose()?;
        let verified_ancestors = self
            .verified_ancestors
            .iter()
            .copied()
            .map(FencedTransparencyTargetHeadWireV1::to_head)
            .collect::<Result<Vec<_>, _>>()?;
        let verified_publications = self
            .verified_publications
            .iter()
            .copied()
            .map(FencedTransparencyPublicationInclusionWireV1::to_inclusion)
            .collect::<Result<Vec<_>, _>>()?;
        if verified_ancestors != required_ancestors
            || verified_publications != required_publications
        {
            return Err(BrokerError::Rejected);
        }
        let proof = sorafs_node::FencedTransparencyHeadAncestryProofV1::try_new(
            authoritative_head,
            verified_ancestors,
            verified_publications,
            self.adapter_proof_digest,
        )
        .map_err(|_| BrokerError::Rejected)?;
        if Self::from_proof(&proof) != *self {
            return Err(BrokerError::Rejected);
        }
        Ok(proof)
    }
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PrivacyReleaseAnchorFinalizedHeadRequestWireV1"; PrivacyReleaseAnchorFinalizedHeadRequestWireV1 { query_id: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::PrivacyReleaseAnchorCompareAndSetRequestWireV1"; PrivacyReleaseAnchorCompareAndSetRequestWireV1 { expected: PrivacyReleaseAnchorHeadWireV1, next: PrivacyReleaseAnchorHeadWireV1, lease: TransparencyLeaderLeaseGrantWireV1, });
fn transparency_runtime_binding_from_wire(
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::TransparencyRuntimeProviderBindingV1, BrokerError> {
    sorafs_node::TransparencyRuntimeProviderBindingV1::try_new(
        binding.handle.clone(),
        required_binding_value!(binding, revision),
        required_binding_value!(binding, policy_digest),
    )
    .map_err(|_| BrokerError::BindingMismatch)
}
fn validate_privacy_release_anchor_query(
    request: PrivacyReleaseAnchorFinalizedHeadRequestWireV1,
) -> Result<[u8; 32], BrokerError> {
    if request.query_id == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    Ok(request.query_id)
}
fn validate_privacy_release_anchor_compare_and_set(
    request: &PrivacyReleaseAnchorCompareAndSetRequestWireV1,
) -> Result<
    (
        sorafs_node::PrivacyReleaseAnchorHeadV1,
        sorafs_node::PrivacyReleaseAnchorHeadV1,
        sorafs_node::TransparencyLeaderLeaseGrantV1,
    ),
    BrokerError,
> {
    let expected = request.expected.to_head()?;
    let next = request.next.to_head()?;
    let lease = request.lease.to_grant()?;
    if expected.query_id() != next.query_id()
        || lease.scope().query_id() != next.query_id()
        || lease.scope().cycle_id() != next.release_id()
        || expected
            .sequence()
            .checked_add(1)
            .is_none_or(|sequence| next.sequence() != sequence)
    {
        return Err(BrokerError::Rejected);
    }
    Ok((expected, next, lease))
}
fn validate_transparency_leader_lease_acquire(
    request: &TransparencyLeaderLeaseAcquireRequestWireV1,
    configured_binding: &sorafs_node::TransparencyRuntimeProviderBindingV1,
) -> Result<sorafs_node::TransparencyLeaderLeaseAcquireRequestV1, BrokerError> {
    let request = request.to_request()?;
    if request.provider_binding() != configured_binding {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(request)
}
fn validate_transparency_leader_lease_renew(
    request: &TransparencyLeaderLeaseRenewRequestWireV1,
    configured_binding: &sorafs_node::TransparencyRuntimeProviderBindingV1,
) -> Result<sorafs_node::TransparencyLeaderLeaseRenewRequestV1, BrokerError> {
    let request = request.to_request()?;
    if request.current_grant().provider_binding() != configured_binding {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(request)
}
fn validate_transparency_leader_lease_release(
    request: &TransparencyLeaderLeaseReleaseRequestWireV1,
    configured_binding: &sorafs_node::TransparencyRuntimeProviderBindingV1,
) -> Result<sorafs_node::TransparencyLeaderLeaseReleaseRequestV1, BrokerError> {
    let request = request.to_request()?;
    if request.current_grant().provider_binding() != configured_binding {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(request)
}
fn validate_transparency_leader_lease_acquire_grant(
    request: &sorafs_node::TransparencyLeaderLeaseAcquireRequestV1,
    grant: &sorafs_node::TransparencyLeaderLeaseGrantV1,
    configured_binding: &sorafs_node::TransparencyRuntimeProviderBindingV1,
) -> Result<(), BrokerError> {
    grant.validate().map_err(|_| BrokerError::Rejected)?;
    if grant.scope() != request.scope()
        || grant.issued_at_unix().ne(&request.acquire_at_unix())
        || grant.expires_at_unix() != request.expires_at_unix()
        || grant.provider_binding() != configured_binding
        || grant.fencing_token().le(&request.fencing_floor())
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_transparency_leader_lease_renew_grant(
    request: &sorafs_node::TransparencyLeaderLeaseRenewRequestV1,
    grant: &sorafs_node::TransparencyLeaderLeaseGrantV1,
    configured_binding: &sorafs_node::TransparencyRuntimeProviderBindingV1,
) -> Result<(), BrokerError> {
    grant.validate().map_err(|_| BrokerError::Rejected)?;
    let current = request.current_grant();
    if grant.lease_id() != current.lease_id()
        || grant.scope() != current.scope()
        || grant.issued_at_unix().ne(&request.renew_at_unix())
        || grant.expires_at_unix() != request.expires_at_unix()
        || grant.provider_binding() != configured_binding
        || grant.fencing_token().le(&request.fencing_floor())
        || grant.fencing_token() <= current.fencing_token()
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_transparency_leader_lease_release_receipt(
    request: &sorafs_node::TransparencyLeaderLeaseReleaseRequestV1,
    receipt: &sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1,
    configured_binding: &sorafs_node::TransparencyRuntimeProviderBindingV1,
) -> Result<(), BrokerError> {
    let current = request.current_grant();
    if receipt.lease_id() != current.lease_id()
        || receipt.scope() != current.scope()
        || receipt.fencing_token() != current.fencing_token()
        || receipt.released_at_unix().ne(&request.release_at_unix())
        || receipt.provider_binding() != configured_binding
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
const fn transparency_leader_lease_provider_error(
    error: sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
) -> BrokerError {
    match error {
        sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Unavailable
        | sorafs_node::TransparencyLeaderLeaseProviderErrorV1::RateLimited => {
            BrokerError::Unavailable
        }
        sorafs_node::TransparencyLeaderLeaseProviderErrorV1::AuthenticationFailed
        | sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal => BrokerError::Rejected,
        sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Conflict => BrokerError::Conflict,
        sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Ambiguous => BrokerError::Ambiguous,
    }
}
const fn fenced_privacy_publish_error(
    error: sorafs_node::FencedTransparencyPublishErrorV1,
) -> BrokerError {
    match error {
        sorafs_node::FencedTransparencyPublishErrorV1::InvalidRequest
        | sorafs_node::FencedTransparencyPublishErrorV1::Rejected => BrokerError::Rejected,
        sorafs_node::FencedTransparencyPublishErrorV1::UnqualifiedProvider => {
            BrokerError::StaleOrRevoked
        }
        sorafs_node::FencedTransparencyPublishErrorV1::CompareConflict
        | sorafs_node::FencedTransparencyPublishErrorV1::PublicationConflict
        | sorafs_node::FencedTransparencyPublishErrorV1::StaleFencingToken => BrokerError::Conflict,
        sorafs_node::FencedTransparencyPublishErrorV1::Ambiguous
        | sorafs_node::FencedTransparencyPublishErrorV1::InvalidReceipt => BrokerError::Ambiguous,
    }
}
define_broker_wire_struct!(owned GovernanceRequestAuthHeaderWireV1 { name: String, value: String, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::GovernanceRequestAuthRequestWireV1"; GovernanceRequestAuthRequestWireV1 { scope: u8, method: String, canonical_url: String, selected_headers: Vec<GovernanceRequestAuthHeaderWireV1>, body_length: u64, body_blake3: [u8; 32], request_digest: [u8; 32], });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::GovernanceRequestAuthResultWireV1"; GovernanceRequestAuthResultWireV1 { scope: u8, issued_at_unix_secs: u64, expires_at_unix_secs: u64, nonce: [u8; 32], request_digest: [u8; 32], public_key: [u8; 32], signature: [u8; 64], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::PotrSignRequestWireV1"; PotrSignRequestWireV1 { payload: Vec<u8>, expected_public_key: Vec<u8>, });
impl_broker_debug_fields!(PotrSignRequestWireV1 as value {
    "payload_len" => value.payload.len(),
    "public_key_len" => value.expected_public_key.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PotrSignRequestWireV1 {
    payload,
    expected_public_key
});
impl_scrub_fields_on_drop!(VariableSignatureResultWireV1 { signature });
define_broker_wire_struct!(copy DurationWireV1 { secs: u64, nanos: u32, });
impl DurationWireV1 {
    fn from_duration(duration: Duration) -> Self {
        Self {
            secs: duration.as_secs(),
            nanos: duration.subsec_nanos(),
        }
    }
    fn to_duration(self) -> Result<Duration, BrokerError> {
        if self.nanos >= 1_000_000_000 {
            return Err(BrokerError::Rejected);
        }
        Ok(Duration::new(self.secs, self.nanos))
    }
}
define_broker_wire_struct!(owned IpAddressWireV1 { family: u8, octets: Vec<u8>, });
impl From<std::net::IpAddr> for IpAddressWireV1 {
    fn from(address: std::net::IpAddr) -> Self {
        match address {
            std::net::IpAddr::V4(address) => Self {
                family: 4,
                octets: address.octets().to_vec(),
            },
            std::net::IpAddr::V6(address) => Self {
                family: 6,
                octets: address.octets().to_vec(),
            },
        }
    }
}
impl IpAddressWireV1 {
    fn to_address(&self) -> Result<std::net::IpAddr, BrokerError> {
        match self.family {
            4 => {
                let octets: [u8; 4] = self
                    .octets
                    .as_slice()
                    .try_into()
                    .map_err(|_| BrokerError::Rejected)?;
                Ok(std::net::Ipv4Addr::from(octets).into())
            }
            6 => {
                let octets: [u8; 16] = self
                    .octets
                    .as_slice()
                    .try_into()
                    .map_err(|_| BrokerError::Rejected)?;
                Ok(std::net::Ipv6Addr::from(octets).into())
            }
            _ => Err(BrokerError::Rejected),
        }
    }
}
define_broker_wire_struct!(copy SystemTimeWireV1 { unix_secs: u64, nanos: u32, });
impl SystemTimeWireV1 {
    fn from_system_time(value: std::time::SystemTime) -> Result<Self, BrokerError> {
        let duration = value
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| BrokerError::Rejected)?;
        Ok(Self {
            unix_secs: duration.as_secs(),
            nanos: duration.subsec_nanos(),
        })
    }
    fn to_system_time(self) -> Result<std::time::SystemTime, BrokerError> {
        let duration = DurationWireV1 {
            secs: self.unix_secs,
            nanos: self.nanos,
        }
        .to_duration()?;
        std::time::UNIX_EPOCH
            .checked_add(duration)
            .ok_or(BrokerError::Rejected)
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::GatewayAcmeOrderRequestWireV1"; GatewayAcmeOrderRequestWireV1 { hostnames: Vec<String>, account_email: Option<String>, directory_url: String, dns_provider_id: Option<String>, dns01: bool, tls_alpn_01: bool, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::GatewayAcmeOrderOutcomeWireV1"; GatewayAcmeOrderOutcomeWireV1 { outcome: u8, certificate_pem: String, private_key_pem: String, ech_config: Option<Vec<u8>>, not_after: Option<SystemTimeWireV1>, retry_after: Option<DurationWireV1>, });
fn scrub_secret_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.fill(0);
    let _ = std::hint::black_box(&bytes);
}
impl_broker_debug_fields!(GatewayAcmeOrderOutcomeWireV1 as value {
    "outcome" => value.outcome,
    "certificate_pem_bytes" => value.certificate_pem.len(),
    "private_key_pem" => "[REDACTED]",
    "ech_config_bytes" => value.ech_config.as_ref().map(Vec::len),
} => finish_non_exhaustive);
impl Drop for GatewayAcmeOrderOutcomeWireV1 {
    fn drop(&mut self) {
        scrub_secret_string(&mut self.private_key_pem);
        if let Some(ech_config) = self.ech_config.as_mut() {
            ech_config.fill(0);
            let _ = std::hint::black_box(ech_config);
        }
    }
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::GatewayComplianceResolveRequestWireV1"; GatewayComplianceResolveRequestWireV1 { hostname: String, timeout: DurationWireV1, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::GatewayComplianceResolveOutcomeWireV1"; GatewayComplianceResolveOutcomeWireV1 { outcome: u8, addresses: Vec<IpAddressWireV1>, found: u64, maximum: u64, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::GatewayComplianceFetchRequestWireV1"; GatewayComplianceFetchRequestWireV1 { url: String, pinned_addresses: Vec<IpAddressWireV1>, connect_timeout: DurationWireV1, total_timeout: DurationWireV1, max_encoded_bytes: u64, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::GatewayComplianceFetchOutcomeWireV1"; GatewayComplianceFetchOutcomeWireV1 { outcome: u8, status: u16, redirect_location: Option<String>, connected_address: Option<IpAddressWireV1>, peer_spki_sha256: [u8; 32], content_encoding: u8, body: Vec<u8>, elapsed: Option<DurationWireV1>, found: u64, maximum: u64, });
impl_broker_debug_fields!(GatewayComplianceFetchOutcomeWireV1 as value {
    "outcome" => value.outcome,
    "status" => value.status,
    "body_len" => value.body.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(GatewayComplianceFetchOutcomeWireV1 { body });
define_broker_wire_struct!(move_sensitive frame "irohad::runtime_provider_broker::protocol::PopAuthenticateRequestWireV1"; PopAuthenticateRequestWireV1 { opaque_credential: Vec<u8>, action: u8, request_binding: [u8; 32], now_epoch: u64, });
impl_broker_debug_fields!(PopAuthenticateRequestWireV1 as value {
    "opaque_credential" => "[REDACTED]",
    "action" => value.action,
    "now_epoch" => value.now_epoch,
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PopAuthenticateRequestWireV1 { opaque_credential });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PopAuthenticatedPrincipalWireV1"; PopAuthenticatedPrincipalWireV1 { principal_digest: [u8; 32], expires_at_epoch: u64, caller_signed_transaction: bool, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::PopRegistrySubmitRequestWireV1"; PopRegistrySubmitRequestWireV1 { idempotency_key: [u8; 32], operation: sorafs_node::pop_credentials::PopRegistryOperationV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PopRegistryNextRequestWireV1"; PopRegistryNextRequestWireV1 { cursor: Option<sorafs_node::pop_credentials::PopFinalizedCursorV1>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::PopRegistryNextResultWireV1"; PopRegistryNextResultWireV1 { projection: Option<sorafs_node::pop_credentials::PopFinalizedRegistryProjectionV1>, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::PopMembershipWitnessWireV1"; PopMembershipWitnessWireV1 { holder_secret: [u8; 32], credential_siblings: Vec<[u8; 32]>, credential_directions: Vec<bool>, revocation_siblings: Vec<[u8; 32]>, });
impl_broker_debug_fields!(PopMembershipWitnessWireV1 as value {
    "private_witness" => "[REDACTED]",
} => finish_non_exhaustive);
impl Drop for PopMembershipWitnessWireV1 {
    fn drop(&mut self) {
        self.holder_secret.fill(0);
        for sibling in &mut self.credential_siblings {
            sibling.fill(0);
        }
        self.credential_directions.fill(false);
        for sibling in &mut self.revocation_siblings {
            sibling.fill(0);
        }
        let _ = std::hint::black_box((
            &self.holder_secret,
            &self.credential_siblings,
            &self.credential_directions,
            &self.revocation_siblings,
        ));
    }
}
impl PopMembershipWitnessWireV1 {
    fn from_witness(witness: &sorafs_manifest::pop_credentials::PopMembershipWitnessV1) -> Self {
        Self {
            holder_secret: witness.holder_secret,
            credential_siblings: witness.credential_path.siblings.clone(),
            credential_directions: witness.credential_path.directions.clone(),
            revocation_siblings: witness.revocation_path.siblings.clone(),
        }
    }
    fn into_witness(mut self) -> sorafs_manifest::pop_credentials::PopMembershipWitnessV1 {
        let witness = sorafs_manifest::pop_credentials::PopMembershipWitnessV1 {
            holder_secret: self.holder_secret,
            credential_path: sorafs_manifest::pop_credentials::PopCredentialMerklePathV1 {
                siblings: std::mem::take(&mut self.credential_siblings),
                directions: std::mem::take(&mut self.credential_directions),
            },
            revocation_path: sorafs_manifest::pop_credentials::PopRevocationNonMembershipPathV1 {
                siblings: std::mem::take(&mut self.revocation_siblings),
            },
        };
        self.holder_secret.fill(0);
        witness
    }
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PopIssuanceDraftRequestWireV1"; PopIssuanceDraftRequestWireV1 { request_id: [u8; 32], now_epoch: u64, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::PopIssuanceDraftResultWireV1"; PopIssuanceDraftResultWireV1 { request_id: [u8; 32], credential: sorafs_manifest::pop_credentials::PopCredentialV1, commitment_root: sorafs_manifest::pop_credentials::PopCommitmentRootV1, revocation_list: sorafs_manifest::pop_credentials::PopRevocationListV1, witness: PopMembershipWitnessWireV1, });
impl_broker_debug_fields!(PopIssuanceDraftResultWireV1 as value {
    "request_id" => value.request_id,
    "private_issuance_material" => "[REDACTED]",
} => finish_non_exhaustive);
define_broker_wire_struct!(move_sensitive frame "irohad::runtime_provider_broker::protocol::PopWalletWrapDekRequestWireV1"; PopWalletWrapDekRequestWireV1 { context: [u8; 32], dek: [u8; 32], });
impl_broker_debug_fields!(PopWalletWrapDekRequestWireV1 as value {
    "dek" => "[REDACTED]",
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PopWalletWrapDekRequestWireV1 { dek });
define_broker_wire_struct!(move_sensitive frame "irohad::runtime_provider_broker::protocol::PopWalletWrapDekResultWireV1"; PopWalletWrapDekResultWireV1 { wrapped_dek: Vec<u8>, });
impl_broker_debug_fields!(PopWalletWrapDekResultWireV1 as value {
    "wrapped_dek_len" => value.wrapped_dek.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PopWalletWrapDekResultWireV1 { wrapped_dek });
define_broker_wire_struct!(move_sensitive frame "irohad::runtime_provider_broker::protocol::PopWalletUnwrapDekRequestWireV1"; PopWalletUnwrapDekRequestWireV1 { key_id: String, context: [u8; 32], wrapped_dek: Vec<u8>, });
impl_broker_debug_fields!(PopWalletUnwrapDekRequestWireV1 as value {
    "key_id" => value.key_id,
    "wrapped_dek_len" => value.wrapped_dek.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PopWalletUnwrapDekRequestWireV1 { wrapped_dek });
define_broker_wire_struct!(move_sensitive frame "irohad::runtime_provider_broker::protocol::PopWalletUnwrapDekResultWireV1"; PopWalletUnwrapDekResultWireV1 { dek: [u8; 32], });
impl_broker_debug_fields!(PopWalletUnwrapDekResultWireV1 as value {
    "dek" => "[REDACTED]",
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(PopWalletUnwrapDekResultWireV1 { dek });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::PopWalletWitnessRequestWireV1"; PopWalletWitnessRequestWireV1 { credential_commitment: [u8; 32], projection: sorafs_node::pop_credentials::PopFinalizedRegistryProjectionV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PopFinalizedTimeResultWireV1"; PopFinalizedTimeResultWireV1 { finalized_block_height: u64, finalized_block_hash: [u8; 32], finalized_epoch: u64, observed_epoch: u64, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::PorReplayArchiveAppendRequestWireV1"; PorReplayArchiveAppendRequestWireV1 { canonical_record: Vec<u8>, expected_previous_head: Option<[u8; 32]>, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::PorReplayArchiveLookupRequestWireV1"; PorReplayArchiveLookupRequestWireV1 { challenge_id: [u8; 32], expected_checkpoint_head: sorafs_node::PorFinalizedReplayArchiveReceiptV1, max_successor_receipts: u32, max_successor_proof_bytes: u64, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::PorReplayArchiveLookupOutcomeWireV1"; PorReplayArchiveLookupOutcomeWireV1 { outcome: u8, canonical_record: Vec<u8>, receipt: Option<sorafs_node::PorFinalizedReplayArchiveReceiptV1>, declared_successor_receipts: u32, canonical_successor_receipts: Vec<u8>, absence_proof: Option<sorafs_node::PorFinalizedReplayArchiveAbsenceProofV1>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::AppealFinanceCheckpointCompareAndSwapWireV1"; AppealFinanceCheckpointCompareAndSwapWireV1 { expected_revision: Option<[u8; 32]>, next: sorafs_node::appeal_finance_transaction_forwarder:: AppealFinanceSealedCheckpointRecordV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::EvidenceViewerIssueChallengeRequestWireV1"; EvidenceViewerIssueChallengeRequestWireV1 { binding_digest: [u8; 32], issued_at_unix_ms: u64, expires_at_unix_ms: u64, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerSecretResultWireV1"; EvidenceViewerSecretResultWireV1 { secret: Vec<u8>, });
impl_broker_debug_fields!(EvidenceViewerSecretResultWireV1 as value {
    "secret_len" => value.secret.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(EvidenceViewerSecretResultWireV1 { secret });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerVerifyAndConsumeRequestWireV1"; EvidenceViewerVerifyAndConsumeRequestWireV1 { challenge: Vec<u8>, assertion: Vec<u8>, binding_digest: [u8; 32], rp_id: String, allowed_origins: Vec<String>, now_unix_ms: u64, });
impl_broker_debug_fields!(EvidenceViewerVerifyAndConsumeRequestWireV1 as value {
    "challenge_len" => value.challenge.len(),
    "assertion_len" => value.assertion.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(EvidenceViewerVerifyAndConsumeRequestWireV1 {
    challenge,
    assertion
});
fn validate_evidence_viewer_verify_and_consume_wire(
    request: &EvidenceViewerVerifyAndConsumeRequestWireV1,
    configured: &EvidenceViewerWebAuthnBindingWireV1,
) -> Result<(), BrokerError> {
    validate_webauthn_wire_policy(&request.rp_id, &request.allowed_origins)?;
    if request.rp_id != configured.rp_id || request.allowed_origins != configured.allowed_origins {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::EvidenceViewerWebAuthnResultWireV1"; EvidenceViewerWebAuthnResultWireV1 { attestation_digest: [u8; 32], credential_id_digest: [u8; 32], authenticator_counter: u64, });
fn scrub_evidence_viewer_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.fill(0);
    let _ = std::hint::black_box(&bytes);
}
fn scrub_evidence_viewer_grant_claims(
    claims: &mut sorafs_node::evidence_viewer::EvidenceViewerGrantClaimsV1,
) {
    scrub_evidence_viewer_string(&mut claims.case_id);
    scrub_evidence_viewer_string(&mut claims.round_id);
    scrub_evidence_viewer_string(&mut claims.viewer_account);
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerGrantIssueRequestWireV1"; EvidenceViewerGrantIssueRequestWireV1 { claims: sorafs_node::evidence_viewer::EvidenceViewerGrantClaimsV1, });
impl_broker_debug_fields!(EvidenceViewerGrantIssueRequestWireV1 as value {} => finish_non_exhaustive);
impl Drop for EvidenceViewerGrantIssueRequestWireV1 {
    fn drop(&mut self) {
        scrub_evidence_viewer_grant_claims(&mut self.claims);
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerGrantVerifyRequestWireV1"; EvidenceViewerGrantVerifyRequestWireV1 { token: Vec<u8>, claims: sorafs_node::evidence_viewer::EvidenceViewerGrantClaimsV1, now_unix_ms: u64, });
impl_broker_debug_fields!(EvidenceViewerGrantVerifyRequestWireV1 as value {
    "token_len" => value.token.len(),
} => finish_non_exhaustive);
impl Drop for EvidenceViewerGrantVerifyRequestWireV1 {
    fn drop(&mut self) {
        self.token.fill(0);
        scrub_evidence_viewer_grant_claims(&mut self.claims);
        let _ = std::hint::black_box(&self.token);
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerGrantRevokeRequestWireV1"; EvidenceViewerGrantRevokeRequestWireV1 { token_digest: [u8; 32], });
impl_broker_debug_fields!(EvidenceViewerGrantRevokeRequestWireV1 as value {} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(EvidenceViewerGrantRevokeRequestWireV1 { token_digest });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerEraseRequestWireV1"; EvidenceViewerEraseRequestWireV1 { operation_id: [u8; 32], quarantine_id: [u8; 16], object_id: [u8; 16], evidence_digest: [u8; 32], });
impl_broker_debug_fields!(EvidenceViewerEraseRequestWireV1 as value {} => finish_non_exhaustive);
impl Drop for EvidenceViewerEraseRequestWireV1 {
    fn drop(&mut self) {
        self.operation_id.fill(0);
        self.quarantine_id.fill(0);
        self.object_id.fill(0);
        self.evidence_digest.fill(0);
        let _ = std::hint::black_box((
            &self.operation_id,
            &self.quarantine_id,
            &self.object_id,
            &self.evidence_digest,
        ));
    }
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::EvidenceViewerEraseResultWireV1"; EvidenceViewerEraseResultWireV1 { commit_digest: [u8; 32], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerCheckpointCompareAndSwapRequestWireV1"; EvidenceViewerCheckpointCompareAndSwapRequestWireV1 { expected_revision: Option<[u8; 32]>, next_record: Vec<u8>, });
impl_broker_debug_fields!(EvidenceViewerCheckpointCompareAndSwapRequestWireV1 as value {
    "expected_revision" => value.expected_revision,
    "next_record_len" => value.next_record.len(),
} => finish_non_exhaustive);
impl Drop for EvidenceViewerCheckpointCompareAndSwapRequestWireV1 {
    fn drop(&mut self) {
        if let Some(expected_revision) = self.expected_revision.as_mut() {
            expected_revision.fill(0);
        }
        self.next_record.fill(0);
        let _ = std::hint::black_box((&self.expected_revision, &self.next_record));
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerArchiveInstallRequestWireV1"; EvidenceViewerArchiveInstallRequestWireV1 { operation_id: [u8; 32], receipt_message: [u8; 32], canonical_artifact: Vec<u8>, });
impl_broker_debug_fields!(EvidenceViewerArchiveInstallRequestWireV1 as value {
    "canonical_artifact_len" => value.canonical_artifact.len(),
} => finish_non_exhaustive);
impl Drop for EvidenceViewerArchiveInstallRequestWireV1 {
    fn drop(&mut self) {
        self.operation_id.fill(0);
        self.receipt_message.fill(0);
        self.canonical_artifact.fill(0);
        let _ = std::hint::black_box((
            &self.operation_id,
            &self.receipt_message,
            &self.canonical_artifact,
        ));
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerArchiveReadRequestWireV1"; EvidenceViewerArchiveReadRequestWireV1 { operation_id: [u8; 32], });
impl_broker_debug_fields!(EvidenceViewerArchiveReadRequestWireV1 as value {} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(EvidenceViewerArchiveReadRequestWireV1 { operation_id });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::EvidenceViewerArchiveReadbackWireV1"; EvidenceViewerArchiveReadbackWireV1 { canonical_artifact: Vec<u8>, signature: [u8; 64], });
impl_broker_debug_fields!(EvidenceViewerArchiveReadbackWireV1 as value {
    "canonical_artifact_len" => value.canonical_artifact.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(EvidenceViewerArchiveReadbackWireV1 { canonical_artifact });
const MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1: u16 = 1;
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveQualifyRequestWireV1"; ModerationPanelNotificationArchiveQualifyRequestWireV1 { version: u16, slot: u16, network_id: NetworkId, });
impl_broker_debug_fields!(ModerationPanelNotificationArchiveQualifyRequestWireV1 as value {
    "version" => value.version,
    "slot" => value.slot,
} => finish_non_exhaustive);
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveQualificationWireV1"; ModerationPanelNotificationArchiveQualificationWireV1 { version: u16, slot: u16, revision: u64, policy_digest: [u8; 32], archive_id: [u8; 32], public_key: [u8; 32], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveInstallRequestWireV1"; ModerationPanelNotificationArchiveInstallRequestWireV1 { version: u16, slot: u16, network_id: NetworkId, operation_id: [u8; 32], receipt_message: [u8; 32], canonical_artifact: Vec<u8>, });
impl_broker_debug_fields!(ModerationPanelNotificationArchiveInstallRequestWireV1 as value {
    "version" => value.version,
    "slot" => value.slot,
    "canonical_artifact_len" => value.canonical_artifact.len(),
} => finish_non_exhaustive);
impl Drop for ModerationPanelNotificationArchiveInstallRequestWireV1 {
    fn drop(&mut self) {
        self.operation_id.fill(0);
        self.receipt_message.fill(0);
        self.canonical_artifact.fill(0);
        let _ = std::hint::black_box((
            &self.operation_id,
            &self.receipt_message,
            &self.canonical_artifact,
        ));
    }
}
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveInstallResultWireV1"; ModerationPanelNotificationArchiveInstallResultWireV1 { version: u16, slot: u16, signature: [u8; 64], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveReadRequestWireV1"; ModerationPanelNotificationArchiveReadRequestWireV1 { version: u16, slot: u16, network_id: NetworkId, operation_id: [u8; 32], });
impl_broker_debug_fields!(ModerationPanelNotificationArchiveReadRequestWireV1 as value {
    "version" => value.version,
    "slot" => value.slot,
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(ModerationPanelNotificationArchiveReadRequestWireV1 { operation_id });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveReadbackWireV1"; ModerationPanelNotificationArchiveReadbackWireV1 { version: u16, slot: u16, canonical_artifact: Vec<u8>, signature: [u8; 64], });
impl_broker_debug_fields!(ModerationPanelNotificationArchiveReadbackWireV1 as value {
    "version" => value.version,
    "slot" => value.slot,
    "canonical_artifact_len" => value.canonical_artifact.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(ModerationPanelNotificationArchiveReadbackWireV1 { canonical_artifact });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationSourceAttestRequestWireV1"; ModerationPanelNotificationSourceAttestRequestWireV1 { version: u16, slot: u16, network_id: NetworkId, statement: sorafs_node::moderation_orchestrator::ModerationPanelNotificationSourceAttestationV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationSourceAttestResultWireV1"; ModerationPanelNotificationSourceAttestResultWireV1 { version: u16, slot: u16, statement_digest: [u8; 32], signature: [u8; 64], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveHeadPublishRequestWireV1"; ModerationPanelNotificationArchiveHeadPublishRequestWireV1 { version: u16, slot: u16, network_id: NetworkId, head: sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveHeadV1, canonical_head: Vec<u8>, });
impl_broker_debug_fields!(ModerationPanelNotificationArchiveHeadPublishRequestWireV1 as value {
    "version" => value.version,
    "slot" => value.slot,
    "generation" => value.head.generation,
    "canonical_head_len" => value.canonical_head.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(ModerationPanelNotificationArchiveHeadPublishRequestWireV1 {
    canonical_head
});
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveHeadPublishResultWireV1"; ModerationPanelNotificationArchiveHeadPublishResultWireV1 { version: u16, slot: u16, operation_id: [u8; 32], head_digest: [u8; 32], chain_commitment: [u8; 32], outcome: u8, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationArchiveHeadReadResultWireV1"; ModerationPanelNotificationArchiveHeadReadResultWireV1 { version: u16, slot: u16, canonical_head: Option<Vec<u8>>, });
impl_broker_debug_fields!(ModerationPanelNotificationArchiveHeadReadResultWireV1 as value {
    "version" => value.version,
    "slot" => value.slot,
    "canonical_head_len" => value.canonical_head.as_ref().map_or(0, Vec::len),
} => finish_non_exhaustive);
impl Drop for ModerationPanelNotificationArchiveHeadReadResultWireV1 {
    fn drop(&mut self) {
        if let Some(bytes) = self.canonical_head.as_mut() {
            bytes.fill(0);
            let _ = std::hint::black_box(bytes);
        }
    }
}
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationQuarantineWrapDekRequestWireV1"; ModerationQuarantineWrapDekRequestWireV1 { context_digest: [u8; 32], dek: [u8; 32], });
impl_broker_debug_fields!(ModerationQuarantineWrapDekRequestWireV1 as value {} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(ModerationQuarantineWrapDekRequestWireV1 { dek });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationQuarantineWrapDekResultWireV1"; ModerationQuarantineWrapDekResultWireV1 { wrapped_dek: Vec<u8>, });
impl_broker_debug_fields!(ModerationQuarantineWrapDekResultWireV1 as value {
    "wrapped_dek_len" => value.wrapped_dek.len(),
} => finish);
impl_scrub_fields_on_drop!(ModerationQuarantineWrapDekResultWireV1 { wrapped_dek });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationQuarantineUnwrapDekRequestWireV1"; ModerationQuarantineUnwrapDekRequestWireV1 { key_id: String, context_digest: [u8; 32], wrapped_dek: Vec<u8>, });
impl_broker_debug_fields!(ModerationQuarantineUnwrapDekRequestWireV1 as value {
    "wrapped_dek_len" => value.wrapped_dek.len(),
} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(ModerationQuarantineUnwrapDekRequestWireV1 { wrapped_dek });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationQuarantineUnwrapDekResultWireV1"; ModerationQuarantineUnwrapDekResultWireV1 { dek: [u8; 32], });
impl_broker_debug_fields!(ModerationQuarantineUnwrapDekResultWireV1 as value {} => finish_non_exhaustive);
impl_scrub_fields_on_drop!(ModerationQuarantineUnwrapDekResultWireV1 { dek });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationDurableHandoffRequestWireV1"; ModerationDurableHandoffRequestWireV1 { handoff: sorafs_node::moderation_orchestrator::ModerationTerminalHandoffV1, canonical_handoff: Vec<u8>, });
impl_broker_debug_fields!(ModerationDurableHandoffRequestWireV1 as value {
    "canonical_handoff_len" => value.canonical_handoff.len(),
} => finish_non_exhaustive);
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ModerationDurableHandoffOutcomeWireV1"; ModerationDurableHandoffOutcomeWireV1 { outcome: u8, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::ModerationDurablePanelNotificationRequestWireV1"; ModerationDurablePanelNotificationRequestWireV1 { notification: sorafs_node::moderation_orchestrator::ModerationPanelNotificationV1, canonical_notification: Vec<u8>, lease_expires_at_unix_ms: u64, attempt: u32, attempt_limit: u32, });
impl_broker_debug_fields!(ModerationDurablePanelNotificationRequestWireV1 as value {
    "canonical_notification_len" => value.canonical_notification.len(),
    "attempt" => value.attempt,
    "attempt_limit" => value.attempt_limit,
} => finish_non_exhaustive);
define_broker_wire_struct!(copy_sensitive frame "irohad::runtime_provider_broker::protocol::ModerationPanelNotificationReceiptWireV1"; ModerationPanelNotificationReceiptWireV1 { notification_id: [u8; 32], receipt_digest: [u8; 32], delivered_at_unix_ms: u64, });
impl_broker_debug_fields!(ModerationPanelNotificationReceiptWireV1 as value {} => finish_non_exhaustive);
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::SealedLoadRequestWireV1"; SealedLoadRequestWireV1 { slot: u8, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::SealedRecordWireV1"; SealedRecordWireV1 { generation: u64, revision: [u8; 32], payload: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::SealedCompareAndSwapRequestWireV1"; SealedCompareAndSwapRequestWireV1 { slot: u8, expected_revision: Option<[u8; 32]>, next: SealedRecordWireV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::SealedDeleteRequestWireV1"; SealedDeleteRequestWireV1 { slot: u8, expected_revision: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestResolverQualificationWireV1"; ProviderIngestResolverQualificationWireV1 { revision: u64, policy_digest: [u8; 32], signer_binding: ProviderIngestSignerBindingWireV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ProviderIngestRuntimeQualificationWireV1"; ProviderIngestRuntimeQualificationWireV1 { revision: u64, policy_digest: [u8; 32], });
define_broker_wire_struct!(owned ProviderIngestSignerRequestContextWireV1 { expected_authority: Vec<u8>, expected_assignment_revision: u64, finalized_height: u64, finalized_block_hash: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestResolveSignerRequestWireV1"; ProviderIngestResolveSignerRequestWireV1 { context: ProviderIngestSignerRequestContextWireV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ProviderIngestResolveSignerResultWireV1"; ProviderIngestResolveSignerResultWireV1 { eligible: bool, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestSignRequestWireV1"; ProviderIngestSignRequestWireV1 { context: ProviderIngestSignerRequestContextWireV1, transaction_payload: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestSignResultWireV1"; ProviderIngestSignResultWireV1 { signed_transaction: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestCheckpointCompareAndSwapRequestWireV1"; ProviderIngestCheckpointCompareAndSwapRequestWireV1 { expected_revision: Option<[u8; 32]>, next_record: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationJournalCheckpointCompareAndSwapRequestWireV1"; ReputationJournalCheckpointCompareAndSwapRequestWireV1 { expected_revision: Option<[u8; 32]>, next_record: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestRetentionLoadRequestWireV1"; ProviderIngestRetentionLoadRequestWireV1 { network_id: NetworkId, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestRetentionCompareAndSwapRequestWireV1"; ProviderIngestRetentionCompareAndSwapRequestWireV1 { network_id: NetworkId, expected_revision: Option<[u8; 32]>, next_record: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationRetentionLoadRequestWireV1"; ReputationRetentionLoadRequestWireV1 { network_id: NetworkId, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationRetentionCompareAndSwapRequestWireV1"; ReputationRetentionCompareAndSwapRequestWireV1 { network_id: NetworkId, expected_revision: Option<[u8; 32]>, next_record: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationJournalSupportsAuthorityRequestWireV1"; ReputationJournalSupportsAuthorityRequestWireV1 { authority: iroha_data_model::account::AccountId, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationJournalTransactionRequestWireV1"; ReputationJournalTransactionRequestWireV1 { sequence: u64, network_id: iroha_data_model::NetworkId, authority: iroha_data_model::account::AccountId, event_id: iroha_data_model::sorafs::reputation::ReputationJournalEventIdV1, source_id: iroha_data_model::sorafs::reputation::ReputationJournalSourceIdV1, attempt: u32, idempotency_key: [u8; 32], canonical_instruction: Vec<u8>, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ReputationJournalTransactionSubmitResultWireV1"; ReputationJournalTransactionSubmitResultWireV1 { outcome: u8, receipt: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationThresholdSigningRequestWireV1"; ReputationThresholdSigningRequestWireV1 { sequence: u64, material_digest: [u8; 32], idempotency_key: [u8; 32], material: sorafs_node::reputation::ReputationUnsignedSigningMaterialV1, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationGovernanceDagPublicationRequestWireV1"; ReputationGovernanceDagPublicationRequestWireV1 { sequence: u64, material_digest: [u8; 32], signed_result_digest: [u8; 32], idempotency_key: [u8; 32], canonical_signed_result: Vec<u8>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ReputationReconcileResultWireV1"; ReputationReconcileResultWireV1 { outcome: u8, canonical_result: Vec<u8>, failure_receipt: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BillingAdapterIdentityWireV1"; BillingAdapterIdentityWireV1 { handle: String, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BillingStatementSignerIdentityWireV1"; BillingStatementSignerIdentityWireV1 { provider_handle: String, signer_id: String, public_key: [u8; 32], });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BillingStatementPublisherIdentityWireV1"; BillingStatementPublisherIdentityWireV1 { provider_handle: String, publisher_id: String, route_id: String, public_key: [u8; 32], });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::BillingFinalizedQueryCapabilitiesWireV1"; BillingFinalizedQueryCapabilitiesWireV1 { supplies_period_closes: bool, });
define_broker_wire_struct!(copy BillingQueryPositionWireV1 { next_sequence: u64, journal_commitment: Option<sorafs_node::hedging_billing_service::HedgingBillingJournalCommitmentV1>, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BillingQueryPageRequestWireV1"; BillingQueryPageRequestWireV1 { position: BillingQueryPositionWireV1, max_events: u32, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BillingQueryPeriodCloseRequestWireV1"; BillingQueryPeriodCloseRequestWireV1 { period_end_unix: u64, position: BillingQueryPositionWireV1, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BillingVerifyPageRequestWireV1"; BillingVerifyPageRequestWireV1 { network_id: iroha_data_model::NetworkId, previous: Option<sorafs_node::hedging_billing_service::HedgingBillingJournalCommitmentV1>, page: sorafs_node::hedging_billing_service::HedgingBillingFinalizedEventPageV1, });
impl_broker_debug_fields!(BillingVerifyPageRequestWireV1 as value {
    "network_id" => value.network_id,
    "previous_next_sequence" => value .previous .map(|commitment| commitment.journal_next_sequence),
    "page_start_sequence" => value.page.start_sequence,
    "page_next_sequence" => value.page.next_sequence,
    "event_count" => value.page.events.len(),
} => finish_non_exhaustive);
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BillingVerifyPeriodCloseRequestWireV1"; BillingVerifyPeriodCloseRequestWireV1 { network_id: iroha_data_model::NetworkId, close: sorafs_node::hedging_billing_service::HedgingBillingFinalizedPeriodCloseV1, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::BillingVerifyEpochTransitionRequestWireV1"; BillingVerifyEpochTransitionRequestWireV1 { network_id: iroha_data_model::NetworkId, transition: sorafs_node::hedging_billing_service::HedgingBillingEpochTransitionV1, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::BillingSignDigestRequestWireV1"; BillingSignDigestRequestWireV1 { digest: [u8; 32], });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::BillingSignDigestResultWireV1"; BillingSignDigestResultWireV1 { signature: [u8; 64], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BillingPublishStatementRequestWireV1"; BillingPublishStatementRequestWireV1 { idempotency_key: [u8; 32], signed_statement_digest: [u8; 32], statement: sorafs_node::hedging_billing_service::SignedGovernedBillingStatementV1, });
impl_broker_debug_fields!(BillingPublishStatementRequestWireV1 as value {
    "idempotency_key" => value.idempotency_key,
    "signed_statement_digest" => value.signed_statement_digest,
} => finish_non_exhaustive);
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::BillingLookupRequestWireV1"; BillingLookupRequestWireV1 { record_id: [u8; 32], });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BillingAuthoritativePublicationWireV1"; BillingAuthoritativePublicationWireV1 { signed_statement: sorafs_node::hedging_billing_service::SignedGovernedBillingStatementV1, receipt: sorafs_node::hedging_billing_service::BillingStatementPublicationReceiptV1, });
impl_broker_debug_fields!(BillingAuthoritativePublicationWireV1 as value {
    "statement_id" => value .signed_statement .governed_statement .statement .statement_id,
} => finish_non_exhaustive);
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BillingAcknowledgementRequestWireV1"; BillingAcknowledgementRequestWireV1 { statement: sorafs_node::hedging_billing_service::SignedGovernedBillingStatementV1, acknowledgement: sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1, });
impl_broker_debug_fields!(BillingAcknowledgementRequestWireV1 as value {
    "statement_id" => value.acknowledgement.statement_id,
    "authentication_proof_len" => value.acknowledgement.authentication_proof.len(),
} => finish_non_exhaustive);
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::BillingLoadEpochRequestWireV1"; BillingLoadEpochRequestWireV1 { epoch_sequence: u64, });
define_broker_wire_struct!(sensitive frame "irohad::runtime_provider_broker::protocol::BillingCompareAndSwapEpochRequestWireV1"; BillingCompareAndSwapEpochRequestWireV1 { expected_revision: Option<[u8; 32]>, next: sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessRecordV1, });
impl_broker_debug_fields!(BillingCompareAndSwapEpochRequestWireV1 as value {
    "expected_revision" => value.expected_revision,
    "epoch_sequence" => value.next.epoch_sequence,
    "checkpoint_len" => value.next.checkpoint_bytes.len(),
} => finish_non_exhaustive);
#[path = "canonical_attempt.rs"]
mod canonical_attempt;
use canonical_attempt::CanonicalAttemptErrorV1;

include!("protocol_codec_and_bindings.rs");
include!("stream_token_signer_protocol.rs");
include!("protocol_operation_validation.rs");
