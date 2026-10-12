//! Fail-closed Torii boundary for atomic private cross-dataspace settlement.
//!
//! The HTTP layer persists only encrypted sidecars, authenticates the bundle
//! sponsor for uploads, binds auditor access to the exact request-signing key,
//! and returns explicitly allowlisted projections.  It never accepts or emits
//! auditor plaintext or private note openings.

use crate::{JsonBody, NoritoJson, SharedAppState, app_auth::VerifiedCanonicalRequest};
use axum::{
    Extension,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use iroha_core::private_settlement::{
    PrivateSettlementAvailabilityErrorV1, PrivateSettlementAvailabilitySignerV1,
    PrivateSettlementFileSidecarStoreV1, PrivateSettlementPhaseErrorV1,
    PrivateSettlementPhaseSignerV1, PrivateSettlementReconciliationCandidateV1,
    PrivateSettlementRestrictedSidecarV1, PrivateSettlementSidecarLifecycleV1,
    PrivateSettlementSidecarStoreConfigV1, PrivateSettlementSidecarStoreErrorV1,
    PrivateSettlementSidecarStoreOutcomeV1, fetch_private_settlement_auditor_view_v1,
    validate_private_settlement_committee_authority_v1,
};
use iroha_core::state::StateReadOnly as _;
use iroha_crypto::{Hash, PublicKey};
use iroha_data_model::{
    isi::private_settlement::{
        AbortAtomicPrivateSettlementV1, FinalizeAtomicPrivateSettlementV1,
        RegisterAtomicPrivateSettlementPrepareV1,
    },
    nexus::{
        ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PrivateSettlementAbortReasonV1,
        PrivateSettlementAuditApprovalAcknowledgementAttestationBodyV1,
        PrivateSettlementAuditApprovalAcknowledgementDigestMaterialV1,
        PrivateSettlementAuditApprovalV1, PrivateSettlementAuditorViewAttestationBodyV1,
        PrivateSettlementAuditorViewDigestMaterialV1, PrivateSettlementPhaseV1,
    },
    transaction::{Executable, SignedTransaction},
};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_torii_shared::private_settlement_api::{
    PrivateSettlementAuditApprovalRequestV1, PrivateSettlementAuditApprovalResponseV1,
    PrivateSettlementAuditorCapsuleRequestV1, PrivateSettlementAuditorCapsuleResponseV1,
    PrivateSettlementAvailabilityShareRequestV1, PrivateSettlementAvailabilityShareResponseV1,
    PrivateSettlementBundleReceiptResponseV1, PrivateSettlementBundleStatusResponseV1,
    PrivateSettlementBundleSubmitRequestV1, PrivateSettlementBundleSubmitResponseV1,
    PrivateSettlementCommitVoteRequestV1, PrivateSettlementCommitteeProofResponseV1,
    PrivateSettlementLegStatusResponseV1, PrivateSettlementLegUploadDispositionV1,
    PrivateSettlementLegUploadRequestV1, PrivateSettlementLegUploadResponseV1,
    PrivateSettlementLifecycleDtoV1, PrivateSettlementPhaseCertificateRequestV1,
    PrivateSettlementPhaseCertificateResponseV1, PrivateSettlementPhaseCertificatesResponseV1,
    PrivateSettlementPhaseVoteResponseV1, PrivateSettlementPrepareVoteRequestV1,
};
use std::{path::PathBuf, str::FromStr as _, sync::Arc, time::Duration};

/// Kura-relative owner-only directory for encrypted private-settlement sidecars.
pub(crate) const PRIVATE_SETTLEMENT_SIDECAR_DIRECTORY_V1: &str = "private-settlement-sidecars-v1";
const PRIVATE_SETTLEMENT_RECONCILIATION_PAGE_RECORDS_V1: usize = 16;
const PRIVATE_SETTLEMENT_RECONCILIATION_MAX_PAGES_PER_TICK_V1: usize = 16;
const PRIVATE_SETTLEMENT_RECONCILIATION_INTERVAL_V1: Duration = Duration::from_secs(1);

const fn private_settlement_carrier_height_is_live_v1(
    current_height: u64,
    authority_context_height: u64,
    expiry_height: u64,
) -> bool {
    let Some(candidate_height) = current_height.checked_add(1) else {
        return false;
    };
    current_height >= authority_context_height && candidate_height <= expiry_height
}

const fn private_settlement_prepare_registration_height_is_live_v1(
    current_height: u64,
    authority_context_height: u64,
    expiry_height: u64,
) -> bool {
    let Some(finalization_candidate_height) = current_height.checked_add(2) else {
        return false;
    };
    current_height >= authority_context_height && finalization_candidate_height <= expiry_height
}

const fn private_settlement_abort_height_is_admissible_v1(
    current_height: u64,
    authority_context_height: u64,
    expiry_height: u64,
    reason: PrivateSettlementAbortReasonV1,
) -> bool {
    let Some(candidate_height) = current_height.checked_add(1) else {
        return false;
    };
    current_height >= authority_context_height
        && (candidate_height > expiry_height)
            == matches!(reason, PrivateSettlementAbortReasonV1::Expired)
}

fn private_settlement_carrier_within_wire_bound_v1(
    transaction: &SignedTransaction,
    max_signed_transaction_bytes: u64,
) -> Result<bool, norito::Error> {
    let encoded = transaction.encode_wire_v1()?;
    let signed_transaction_bytes = u64::try_from(encoded.len()).map_err(|_| {
        norito::Error::Io(std::io::Error::other(
            "private-settlement carrier transaction is too large",
        ))
    })?;
    Ok(max_signed_transaction_bytes != 0
        && signed_transaction_bytes <= max_signed_transaction_bytes)
}

fn governed_sidecar_store_config_v1(
    config: &iroha_config::parameters::actual::NexusAtomicPrivateSettlement,
) -> Result<PrivateSettlementSidecarStoreConfigV1, PrivateSettlementSidecarStoreErrorV1> {
    let max_records = usize::try_from(config.sidecar_max_records.get())
        .map_err(|_| PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid)?;
    PrivateSettlementSidecarStoreConfigV1::new(max_records, config.sidecar_max_total_bytes.get())
}

/// Route-local durable runtime installed as an Axum extension.
#[derive(Clone)]
pub(crate) struct PrivateSettlementToriiRuntimeV1 {
    store: Option<Arc<PrivateSettlementFileSidecarStoreV1>>,
    availability_signer: Option<Arc<PrivateSettlementAvailabilitySignerV1>>,
    phase_signer: Option<Arc<PrivateSettlementPhaseSignerV1>>,
}

impl PrivateSettlementToriiRuntimeV1 {
    /// Open the durable store when governed configuration enables the path.
    ///
    /// Emergency Fast startup deliberately supplies `None` and therefore
    /// leaves every private-settlement route fail-closed until a Strict restart.
    pub(crate) fn open(
        state: &iroha_core::state::State,
        kura_root: PathBuf,
        emergency_fast: bool,
        availability_signer: Option<Arc<PrivateSettlementAvailabilitySignerV1>>,
        phase_signer: Option<Arc<PrivateSettlementPhaseSignerV1>>,
    ) -> Result<Self, PrivateSettlementSidecarStoreErrorV1> {
        let nexus = state.nexus_snapshot();
        let config = nexus.atomic_private_settlement;
        if !config.enabled || emergency_fast {
            return Ok(Self {
                store: None,
                availability_signer: None,
                phase_signer: None,
            });
        }
        if availability_signer.is_none() || phase_signer.is_none() {
            return Err(PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid);
        }
        let root = kura_root.join(PRIVATE_SETTLEMENT_SIDECAR_DIRECTORY_V1);
        let store = PrivateSettlementFileSidecarStoreV1::open(
            root,
            governed_sidecar_store_config_v1(&config)?,
        )?;
        Ok(Self {
            store: Some(Arc::new(store)),
            availability_signer,
            phase_signer,
        })
    }

    fn store(&self) -> Result<&PrivateSettlementFileSidecarStoreV1, Response> {
        self.store
            .as_deref()
            .ok_or_else(private_settlement_unavailable)
    }

    fn availability_signer(&self) -> Result<&PrivateSettlementAvailabilitySignerV1, Response> {
        self.availability_signer
            .as_deref()
            .ok_or_else(private_settlement_unavailable)
    }

    fn phase_signer(&self) -> Result<&PrivateSettlementPhaseSignerV1, Response> {
        self.phase_signer
            .as_deref()
            .ok_or_else(private_settlement_unavailable)
    }

    fn reconciliation_store(&self) -> Option<Arc<PrivateSettlementFileSidecarStoreV1>> {
        self.store.clone()
    }
}

#[cfg(test)]
mod governed_sidecar_store_config_tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        Level, NetworkId,
        account::AccountId,
        block::BlockHeader,
        isi::Log,
        nexus::{
            ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1,
            PrivateSettlementAuditAadV1, PrivateSettlementAuditCapsuleV1,
            PrivateSettlementCapsulePaddingV1, PrivateSettlementRouteV1,
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};

    use super::*;

    #[test]
    fn governed_limits_are_forwarded_exactly() {
        let mut config = iroha_config::parameters::actual::NexusAtomicPrivateSettlement::default();
        config.sidecar_max_records = NonZeroU32::new(17).expect("non-zero record bound");
        config.sidecar_max_total_bytes =
            NonZeroU64::new(23 * 1024 * 1024).expect("non-zero byte bound");

        let store = governed_sidecar_store_config_v1(&config).expect("bounded store config");
        assert_eq!(store.max_records(), 17);
        assert_eq!(store.max_total_bytes(), 23 * 1024 * 1024);
    }

    #[test]
    fn capsule_bound_counts_the_complete_canonical_envelope() {
        let capsule = PrivateSettlementAuditCapsuleV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            aad: PrivateSettlementAuditAadV1 {
                network_id: NetworkId::from_genesis_hash(
                    HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"capsule bound")),
                ),
                bundle_id: Hash::new(b"capsule-bound-bundle"),
                leg_ordinal: 0,
                route: PrivateSettlementRouteV1 {
                    dataspace_id: DataSpaceId::new(7),
                    lane_id: LaneId::SINGLE,
                    lane_incarnation: Hash::new(b"capsule-bound-incarnation"),
                },
                authority_digest: Hash::new(b"capsule-bound-authority"),
                authority_context_height: 1,
                audit_policy_digest: Hash::new(b"capsule-bound-policy"),
                audit_key_epoch: 1,
                plaintext_commitment: Hash::new(b"capsule-bound-plaintext"),
            },
            padding: PrivateSettlementCapsulePaddingV1::KiB4,
            nonce: [0; PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1],
            ciphertext: vec![0; PrivateSettlementCapsulePaddingV1::KiB4.ciphertext_bytes()],
            wrapped_deks: Vec::new(),
        };
        let ciphertext_only_bound = u64::try_from(capsule.ciphertext.len()).expect("fits u64");
        assert!(
            !audit_capsule_within_canonical_bound(&capsule, ciphertext_only_bound),
            "the AAD, nonce, padding tag, and recipient inventory must count against the bound"
        );
        let canonical_bound = u64::try_from(
            norito::encode_canonical(&capsule)
                .expect("capsule encodes")
                .len(),
        )
        .expect("fits u64");
        assert!(audit_capsule_within_canonical_bound(
            &capsule,
            canonical_bound
        ));
    }

    #[test]
    fn deployment_auditor_floor_is_enforced() {
        assert!(audit_threshold_meets_governed_floor(1, 1));
        assert!(audit_threshold_meets_governed_floor(3, 2));
        assert!(!audit_threshold_meets_governed_floor(1, 2));
    }

    #[test]
    fn carrier_ingress_reserves_one_block_before_expiry() {
        assert!(!private_settlement_carrier_height_is_live_v1(9, 10, 20));
        assert!(private_settlement_carrier_height_is_live_v1(10, 10, 20));
        assert!(private_settlement_carrier_height_is_live_v1(19, 10, 20));
        assert!(!private_settlement_carrier_height_is_live_v1(20, 10, 20));
        assert!(!private_settlement_carrier_height_is_live_v1(21, 10, 20));
        assert!(!private_settlement_carrier_height_is_live_v1(
            u64::MAX,
            10,
            u64::MAX,
        ));
    }

    #[test]
    fn prepare_registration_reserves_a_successor_finalization_block() {
        assert!(!private_settlement_prepare_registration_height_is_live_v1(
            9, 10, 20
        ));
        assert!(private_settlement_prepare_registration_height_is_live_v1(
            10, 10, 20
        ));
        assert!(private_settlement_prepare_registration_height_is_live_v1(
            18, 10, 20
        ));
        assert!(!private_settlement_prepare_registration_height_is_live_v1(
            19, 10, 20
        ));
        assert!(!private_settlement_prepare_registration_height_is_live_v1(
            u64::MAX,
            10,
            u64::MAX,
        ));
    }

    #[test]
    fn abort_carrier_ingress_separates_expired_from_pre_expiry_reasons() {
        assert!(private_settlement_abort_height_is_admissible_v1(
            19,
            10,
            20,
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        ));
        assert!(!private_settlement_abort_height_is_admissible_v1(
            20,
            10,
            20,
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        ));
        assert!(private_settlement_abort_height_is_admissible_v1(
            20,
            10,
            20,
            PrivateSettlementAbortReasonV1::Expired,
        ));
        assert!(private_settlement_abort_height_is_admissible_v1(
            21,
            10,
            20,
            PrivateSettlementAbortReasonV1::Expired,
        ));
        assert!(!private_settlement_abort_height_is_admissible_v1(
            u64::MAX,
            10,
            u64::MAX,
            PrivateSettlementAbortReasonV1::Expired,
        ));
    }

    #[test]
    fn carrier_wire_bound_counts_the_versioned_signed_envelope() {
        let signer = KeyPair::from_seed(vec![0xA7; 32], Algorithm::Ed25519);
        let transaction = TransactionBuilder::new(
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"Torii carrier wire bound",
            ))),
            AccountId::new(signer.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "complete signed carrier envelope".to_owned(),
        )])
        .sign(signer.private_key());
        let exact_signed_bytes = u64::try_from(
            transaction
                .encode_wire_v1()
                .expect("fixed V1 transaction wire encodes")
                .len(),
        )
        .expect("fixture transaction length fits u64");
        assert!(
            !private_settlement_carrier_within_wire_bound_v1(&transaction, exact_signed_bytes - 1,)
                .expect("carrier measurement succeeds")
        );
        assert!(
            private_settlement_carrier_within_wire_bound_v1(&transaction, exact_signed_bytes)
                .expect("carrier measurement succeeds")
        );
        assert!(
            !private_settlement_carrier_within_wire_bound_v1(&transaction, 0)
                .expect("zero limit fails closed")
        );
    }

    #[test]
    fn reconciliation_page_runs_retention_pruning_even_without_candidates() {
        let directory = tempfile::tempdir().expect("temporary sidecar directory");
        // Let the store create its own owner-only directory; the temporary
        // parent follows the process umask and may allow other users to read it.
        let store_root = directory.path().join("restricted-sidecars");
        let config = PrivateSettlementSidecarStoreConfigV1::new(4, 1024 * 1024)
            .expect("bounded sidecar configuration");
        let store = PrivateSettlementFileSidecarStoreV1::open(&store_root, config)
            .expect("open empty sidecar store");

        let removed = reconcile_and_prune_private_settlement_page_v1(&store, Vec::new(), 10)
            .expect("empty reconciliation page still prunes");

        assert_eq!(removed, 0);
    }
}

struct PrivateSettlementReconciliationWorkV1 {
    payload_digest: Hash,
    receipt: Option<iroha_data_model::nexus::PrivateSettlementReceiptV1>,
    abort: Option<iroha_data_model::nexus::PrivateSettlementAbortReceiptV1>,
}

fn reconcile_and_prune_private_settlement_page_v1(
    store: &PrivateSettlementFileSidecarStoreV1,
    work: Vec<PrivateSettlementReconciliationWorkV1>,
    authoritative_height: u64,
) -> Result<usize, PrivateSettlementReconciliationFailureV1> {
    for item in work {
        store
            .reconcile_terminal_state(
                item.payload_digest,
                item.receipt.as_ref(),
                item.abort.as_ref(),
                authoritative_height,
            )
            .map_err(|_| PrivateSettlementReconciliationFailureV1::StoreRejected)?;
    }
    store
        .prune(authoritative_height)
        .map_err(|_| PrivateSettlementReconciliationFailureV1::StoreRejected)
}

fn snapshot_private_settlement_reconciliation_work_v1(
    state: &iroha_core::state::State,
    candidates: Vec<PrivateSettlementReconciliationCandidateV1>,
) -> Result<
    (u64, Vec<PrivateSettlementReconciliationWorkV1>),
    PrivateSettlementReconciliationFailureV1,
> {
    let view = state.view();
    let authoritative_height = u64::try_from(view.height())
        .map_err(|_| PrivateSettlementReconciliationFailureV1::HeightUnavailable)?;
    let world = view.world();
    let work = candidates
        .into_iter()
        .map(|candidate| PrivateSettlementReconciliationWorkV1 {
            payload_digest: candidate.payload_digest,
            receipt: world
                .private_settlement_receipt_v1(&candidate.bundle_id)
                .cloned(),
            abort: world
                .private_settlement_abort_v1(&candidate.bundle_id)
                .copied(),
        })
        .collect();
    Ok((authoritative_height, work))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateSettlementReconciliationFailureV1 {
    HeightUnavailable,
    StoreRejected,
    CursorDidNotAdvance,
    BlockingWorkerFailed,
    WorkerExitedUnexpectedly,
    WorkerPanicked,
    WorkerCancelled,
}

impl PrivateSettlementReconciliationFailureV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::HeightUnavailable => "height_unavailable",
            Self::StoreRejected => "store_rejected",
            Self::CursorDidNotAdvance => "cursor_did_not_advance",
            Self::BlockingWorkerFailed => "blocking_worker_failed",
            Self::WorkerExitedUnexpectedly => "worker_exited_unexpectedly",
            Self::WorkerPanicked => "worker_panicked",
            Self::WorkerCancelled => "worker_cancelled",
        }
    }
}

async fn reconcile_private_settlement_finality_tick_v1(
    store: Arc<PrivateSettlementFileSidecarStoreV1>,
    state: Arc<iroha_core::state::State>,
    mut cursor: Option<Hash>,
) -> Result<Option<Hash>, PrivateSettlementReconciliationFailureV1> {
    for _ in 0..PRIVATE_SETTLEMENT_RECONCILIATION_MAX_PAGES_PER_TICK_V1 {
        let page = store
            .reconciliation_page(cursor, PRIVATE_SETTLEMENT_RECONCILIATION_PAGE_RECORDS_V1)
            .map_err(|_| PrivateSettlementReconciliationFailureV1::StoreRejected)?;
        if page.next_cursor.is_some() && page.next_cursor == cursor {
            return Err(PrivateSettlementReconciliationFailureV1::CursorDidNotAdvance);
        }
        let (authoritative_height, work) =
            snapshot_private_settlement_reconciliation_work_v1(&state, page.candidates)?;
        let blocking_store = Arc::clone(&store);
        crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
            move || {
                reconcile_and_prune_private_settlement_page_v1(
                    &blocking_store,
                    work,
                    authoritative_height,
                )
                .map(|_| ())
            },
        ))
        .await
        .map_err(|_| PrivateSettlementReconciliationFailureV1::BlockingWorkerFailed)??;
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(cursor)
}

async fn run_private_settlement_finality_reconciliation_v1(
    store: Arc<PrivateSettlementFileSidecarStoreV1>,
    state: Arc<iroha_core::state::State>,
    shutdown_signal: ShutdownSignal,
) -> Result<(), PrivateSettlementReconciliationFailureV1> {
    let mut ticker = tokio::time::interval(PRIVATE_SETTLEMENT_RECONCILIATION_INTERVAL_V1);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cursor = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown_signal.receive() => return Ok(()),
            _ = ticker.tick() => {
                if shutdown_signal.is_sent() {
                    return Ok(());
                }
                cursor = reconcile_private_settlement_finality_tick_v1(
                    Arc::clone(&store),
                    Arc::clone(&state),
                    cursor,
                ).await?;
            }
        }
    }
}

/// Start the fail-closed local finality reconciler under the Torii shutdown tree.
pub(crate) fn spawn_private_settlement_finality_reconciliation_v1(
    runtime: PrivateSettlementToriiRuntimeV1,
    state: Arc<iroha_core::state::State>,
    shutdown_signal: ShutdownSignal,
) -> Option<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>> {
    let store = runtime.reconciliation_store()?;
    let worker_shutdown = shutdown_signal.clone();
    Some(tokio::spawn(async move {
        let worker = crate::panic_recovery::spawn_joined_recoverable(
            run_private_settlement_finality_reconciliation_v1(store, state, worker_shutdown),
        );
        let failure = match crate::panic_recovery::join_recoverable(worker).await {
            Ok(Ok(())) if shutdown_signal.is_sent() => {
                return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
            }
            Ok(Ok(())) => PrivateSettlementReconciliationFailureV1::WorkerExitedUnexpectedly,
            Ok(Err(failure)) => failure,
            Err(crate::panic_recovery::RecoverableTaskError::Panicked) => {
                PrivateSettlementReconciliationFailureV1::WorkerPanicked
            }
            Err(crate::panic_recovery::RecoverableTaskError::Join(_)) => {
                PrivateSettlementReconciliationFailureV1::WorkerCancelled
            }
        };
        iroha_logger::error!(
            code = failure.code(),
            "private-settlement finality reconciliation failed closed"
        );
        crate::ToriiCriticalWorkerExit::UnexpectedExit
    }))
}

#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct PrivateSettlementApiErrorV1 {
    code: String,
}

#[cfg(feature = "test-network-private-settlement-route-control")]
const PRIVATE_SETTLEMENT_TEST_NETWORK_STATE_EVIDENCE_DOMAIN_V1: &[u8] =
    b"iroha:test-network:private-settlement:combined-state-evidence:v1\0";

/// Redacted evidence-only count vector returned solely by an instrumented
/// test-network validator.
#[cfg(feature = "test-network-private-settlement-route-control")]
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct PrivateSettlementTestNetworkStateCountsV1 {
    governance: u64,
    pools: u64,
    roots: u64,
    nullifiers: u64,
    commitments: u64,
    encrypted_outputs: u64,
    replay_markers: u64,
    receipts: u64,
    abort_markers: u64,
    staged_pool_heads: u64,
    staged_nullifiers: u64,
    staged_output_commitments: u64,
    replicated_staged_locks: u64,
    staged_locks: u64,
}

/// Evidence-only response. It intentionally contains no account, asset,
/// amount, memo, ciphertext, commitment key, nullifier key, or reservation
/// owner. The containing route is absent from shipping builds.
#[cfg(feature = "test-network-private-settlement-route-control")]
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct PrivateSettlementTestNetworkStateEvidenceResponseV1 {
    format_version: u8,
    height: u64,
    commitment: Hash,
    ledger_commitment: Hash,
    replicated_staged_lock_commitment: Hash,
    staged_lock_commitment: Hash,
    counts: PrivateSettlementTestNetworkStateCountsV1,
}

#[cfg(feature = "test-network-private-settlement-route-control")]
fn private_settlement_test_network_peer_is_local_v1(
    app: &SharedAppState,
    authenticated: &crate::operator_signatures::AuthenticatedOperatorPublicKey,
) -> bool {
    app.local_peer_id.as_ref()
        == Some(&iroha_model_base::peer::PeerId::from(
            authenticated.0.clone(),
        ))
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    let mut response = JsonBody(PrivateSettlementApiErrorV1 {
        code: code.to_owned(),
    })
    .into_response();
    *response.status_mut() = status;
    response
}

/// Capture all replicated evidence from the same original immutable publication.
#[cfg(feature = "test-network-private-settlement-route-control")]
fn private_settlement_test_network_ledger_evidence_at_view(
    view: &iroha_core::state::StateView<'_>,
) -> Result<
    (
        u64,
        iroha_core::state::PrivateSettlementLedgerEvidenceV1,
        iroha_core::state::PrivateSettlementReplicatedStagedLockEvidenceV1,
    ),
    Response,
> {
    let height = u64::try_from(view.height()).map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_height_unavailable",
        )
    })?;
    active_config_at_view(height, view)?;
    let unavailable = |_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_state_evidence_unavailable",
        )
    };
    let ledger = view
        .world()
        .private_settlement_ledger_evidence_v1()
        .map_err(unavailable)?;
    let replicated_staged = view
        .world()
        .private_settlement_replicated_staged_lock_evidence_v1()
        .map_err(unavailable)?;
    Ok((height, ledger, replicated_staged))
}

/// Return a commitment to public APS maps and staged locks on this exact
/// validator. This is a non-shipping release-evidence diagnostic, not a
/// production privacy API.
#[cfg(feature = "test-network-private-settlement-route-control")]
pub(crate) async fn handler_test_network_state_commitment(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<crate::operator_signatures::AuthenticatedOperatorPublicKey>,
) -> Response {
    if !private_settlement_test_network_peer_is_local_v1(&app, &authenticated) {
        return error_response(
            StatusCode::FORBIDDEN,
            "private_settlement_local_validator_required",
        );
    }
    let (height, ledger, replicated_staged) =
        match private_settlement_test_network_ledger_evidence_at_view(&app.state.view()) {
            Ok(evidence) => evidence,
            Err(response) => return response,
        };
    // Local reservations have their own atomic owner and retire asynchronously after
    // finality. Release the World view before acquiring that owner; the observer checks
    // monotonic local cleanup separately from the indivisible replicated ledger cut.
    let staged = match runtime
        .store()
        .and_then(|store| store.staged_lock_evidence_v1().map_err(map_store_error))
    {
        Ok(evidence) => evidence,
        Err(response) => return response,
    };
    let commitment = Hash::new_from_chunks(&[
        PRIVATE_SETTLEMENT_TEST_NETWORK_STATE_EVIDENCE_DOMAIN_V1,
        &height.to_le_bytes(),
        ledger.commitment.as_ref(),
        replicated_staged.commitment.as_ref(),
        staged.commitment.as_ref(),
    ]);
    let counts = PrivateSettlementTestNetworkStateCountsV1 {
        governance: ledger.counts.governance,
        pools: ledger.counts.pools,
        roots: ledger.counts.roots,
        nullifiers: ledger.counts.nullifiers,
        commitments: ledger.counts.commitments,
        encrypted_outputs: ledger.counts.encrypted_outputs,
        replay_markers: ledger.counts.replay_markers,
        receipts: ledger.counts.receipts,
        abort_markers: ledger.counts.abort_markers,
        staged_pool_heads: staged.counts.pool_heads,
        staged_nullifiers: staged.counts.nullifiers,
        staged_output_commitments: staged.counts.output_commitments,
        replicated_staged_locks: replicated_staged.count,
        staged_locks: staged.counts.total,
    };
    let mut response = JsonBody(PrivateSettlementTestNetworkStateEvidenceResponseV1 {
        format_version: 1,
        height,
        commitment,
        ledger_commitment: ledger.commitment,
        replicated_staged_lock_commitment: replicated_staged.commitment,
        staged_lock_commitment: staged.commitment,
        counts,
    })
    .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    response
}

#[cfg(feature = "test-network-private-settlement-route-control")]
async fn apply_private_settlement_route_control_v1<T: norito::json::JsonSerialize>(
    phase: crate::private_settlement_route_control::Phase,
    bundle_id: Hash,
    request: &T,
    authenticated: &VerifiedCanonicalRequest,
) -> Result<(), Response> {
    let request_bytes = norito::json::to_vec(request).map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_control_invalid",
        )
    })?;
    let identity = authenticated.account.to_string();
    match crate::private_settlement_route_control::admit(
        phase,
        bundle_id,
        &request_bytes,
        identity.as_bytes(),
    )
    .await
    {
        Ok(crate::private_settlement_route_control::Disposition::Pass) => Ok(()),
        Ok(crate::private_settlement_route_control::Disposition::Drop) => Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_controlled_loss",
        )),
        Err(code) => Err(error_response(StatusCode::SERVICE_UNAVAILABLE, code)),
    }
}

fn private_settlement_unavailable() -> Response {
    error_response(StatusCode::NOT_FOUND, "private_settlement_unavailable")
}

fn map_store_error(error: PrivateSettlementSidecarStoreErrorV1) -> Response {
    match error {
        PrivateSettlementSidecarStoreErrorV1::InvalidSidecar
        | PrivateSettlementSidecarStoreErrorV1::ConfigurationInvalid => error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_request",
        ),
        PrivateSettlementSidecarStoreErrorV1::Conflict => {
            error_response(StatusCode::CONFLICT, "private_settlement_conflict")
        }
        PrivateSettlementSidecarStoreErrorV1::Unavailable => private_settlement_unavailable(),
        PrivateSettlementSidecarStoreErrorV1::InvalidTransition => error_response(
            StatusCode::CONFLICT,
            "private_settlement_invalid_transition",
        ),
        PrivateSettlementSidecarStoreErrorV1::CapacityExceeded => error_response(
            StatusCode::INSUFFICIENT_STORAGE,
            "private_settlement_capacity_exceeded",
        ),
        PrivateSettlementSidecarStoreErrorV1::StoreAlreadyOpen
        | PrivateSettlementSidecarStoreErrorV1::Corrupt
        | PrivateSettlementSidecarStoreErrorV1::Backend
        | PrivateSettlementSidecarStoreErrorV1::UnsupportedPlatform => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_service_unavailable",
        ),
    }
}

fn map_availability_error(error: PrivateSettlementAvailabilityErrorV1) -> Response {
    match error {
        PrivateSettlementAvailabilityErrorV1::InvalidSigner
        | PrivateSettlementAvailabilityErrorV1::Storage => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_service_unavailable",
        ),
        PrivateSettlementAvailabilityErrorV1::InvalidShare
        | PrivateSettlementAvailabilityErrorV1::InvalidQuorum => error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_request",
        ),
    }
}

fn map_phase_error(_: PrivateSettlementPhaseErrorV1) -> Response {
    error_response(StatusCode::BAD_REQUEST, "private_settlement_phase_rejected")
}

fn authoritative_height(app: &SharedAppState) -> Result<u64, Response> {
    u64::try_from(app.state.view().height()).map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_height_unavailable",
        )
    })
}

fn active_config(
    app: &SharedAppState,
    height: u64,
) -> Result<iroha_config::parameters::actual::NexusAtomicPrivateSettlement, Response> {
    active_config_at_view(height, &app.state.view())
}

fn active_config_at_view(
    height: u64,
    state: &iroha_core::state::StateView<'_>,
) -> Result<iroha_config::parameters::actual::NexusAtomicPrivateSettlement, Response> {
    let config = state.nexus().atomic_private_settlement.clone();
    if !config.enabled
        || config
            .activation_height
            .is_none_or(|activation| height < activation)
    {
        return Err(private_settlement_unavailable());
    }
    let activation_height = config
        .activation_height
        .ok_or_else(private_settlement_unavailable)?;
    iroha_core_privacy::privacy_engines::atomic_private_settlement::validate_atomic_private_settlement_profile_v1()
        .map_err(|_| private_settlement_unavailable())?;
    let capability = state
        .privacy_capability_snapshot_v1()
        .map_err(|_| private_settlement_unavailable())?;
    capability
        .validate()
        .map_err(|_| private_settlement_unavailable())?;
    let row = capability
        .protocols
        .iter()
        .find(|row| {
            row.protocol_id
                == iroha_data_model::privacy::PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1
        })
        .ok_or_else(private_settlement_unavailable)?;
    let activation = row.activation.ok_or_else(private_settlement_unavailable)?;
    let iroha_data_model::privacy::PrivacyProtocolLifecycleV1::Active(active) =
        activation.lifecycle
    else {
        return Err(private_settlement_unavailable());
    };
    let iroha_data_model::privacy::PrivacyProtocolActivationLimitsV1::IrohaIvmPrivateNoteStarkV1(
        limits,
    ) = activation.protocol_limits
    else {
        return Err(private_settlement_unavailable());
    };
    let earliest_activation = active
        .proposed_at_height
        .checked_add(config.minimum_activation_notice_blocks.get())
        .ok_or_else(private_settlement_unavailable)?;
    if capability.committed_height != height
        || activation_height < earliest_activation
        || height < earliest_activation
        || activation_height < active.activated_at_height
        || height < active.activated_at_height
        || height < active.state_since_height
        || limits.max_input_count < iroha_data_model::privacy::IVM_PRIVATE_NOTE_MAX_INPUTS_V1
        || limits.max_output_count < iroha_data_model::privacy::IVM_PRIVATE_NOTE_MAX_OUTPUTS_V1
        || config.proof_profile_version.get()
            != u16::from(iroha_data_model::nexus::ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1)
        || !config.permitted_policy_versions.contains(&u16::from(
            iroha_data_model::nexus::ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        ))
    {
        return Err(private_settlement_unavailable());
    }
    Ok(config)
}

fn lifecycle_dto(
    lifecycle: PrivateSettlementSidecarLifecycleV1,
) -> PrivateSettlementLifecycleDtoV1 {
    match lifecycle {
        PrivateSettlementSidecarLifecycleV1::Collecting => {
            PrivateSettlementLifecycleDtoV1::Collecting
        }
        PrivateSettlementSidecarLifecycleV1::Audited => PrivateSettlementLifecycleDtoV1::Audited,
        PrivateSettlementSidecarLifecycleV1::Prepared => PrivateSettlementLifecycleDtoV1::Prepared,
        PrivateSettlementSidecarLifecycleV1::CommitCertified => {
            PrivateSettlementLifecycleDtoV1::CommitCertified
        }
        PrivateSettlementSidecarLifecycleV1::Finalized => {
            PrivateSettlementLifecycleDtoV1::Finalized
        }
        PrivateSettlementSidecarLifecycleV1::Aborted => PrivateSettlementLifecycleDtoV1::Aborted,
        PrivateSettlementSidecarLifecycleV1::Expired => PrivateSettlementLifecycleDtoV1::Expired,
    }
}

fn phase_certificate_acknowledges_lifecycle_v1(
    phase: PrivateSettlementPhaseV1,
    lifecycle: PrivateSettlementSidecarLifecycleV1,
) -> bool {
    match phase {
        PrivateSettlementPhaseV1::Prepare => matches!(
            lifecycle,
            PrivateSettlementSidecarLifecycleV1::Prepared
                | PrivateSettlementSidecarLifecycleV1::CommitCertified
        ),
        PrivateSettlementPhaseV1::Commit => {
            lifecycle == PrivateSettlementSidecarLifecycleV1::CommitCertified
        }
    }
}

fn parse_digest(literal: &str) -> Result<Hash, Response> {
    let digest = Hash::from_str(literal).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_identifier",
        )
    })?;
    if digest.to_string() != literal {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_identifier",
        ));
    }
    Ok(digest)
}

fn audit_capsule_within_canonical_bound(
    capsule: &iroha_data_model::nexus::PrivateSettlementAuditCapsuleV1,
    maximum_bytes: u64,
) -> bool {
    norito::encode_canonical(capsule)
        .ok()
        .and_then(|encoded| u64::try_from(encoded.len()).ok())
        .is_some_and(|encoded_bytes| encoded_bytes <= maximum_bytes)
}

fn audit_threshold_meets_governed_floor(policy_min_approvals: u8, governed_floor: u16) -> bool {
    u16::from(policy_min_approvals) >= governed_floor
}

fn committee_authority_is_authoritative(
    app: &SharedAppState,
    authority_context_height: u64,
    authority: &iroha_data_model::nexus::PrivateSettlementCommitteeAuthorityV1,
) -> bool {
    let view = app.state.view();
    validate_private_settlement_committee_authority_v1(&view, authority_context_height, authority)
        .is_ok()
}

fn validate_upload_policy(
    app: &SharedAppState,
    request: &PrivateSettlementLegUploadRequestV1,
    stored_at_height: u64,
) -> Result<(), Response> {
    let config = active_config(app, stored_at_height)?;
    if !committee_authority_is_authoritative(
        app,
        request.manifest.authority_context_height,
        &request.committee_authority,
    ) || request.manifest.network_id != app.state.network_id
        || request.manifest.legs.len() > usize::from(config.max_participants.get())
        || request
            .manifest
            .expiry_height
            .checked_sub(request.manifest.authority_context_height)
            .is_none_or(|span| span > config.max_expiry_blocks.get())
        || request.payload.proof.len() as u64 > config.max_proof_bytes.get()
        || !audit_capsule_within_canonical_bound(
            &request.payload.audit_capsule,
            config.max_capsule_bytes.get(),
        )
        || !config
            .permitted_policy_versions
            .contains(&u16::from(request.audit_policy.body.version))
        || !audit_threshold_meets_governed_floor(
            request.audit_policy.body.min_approvals,
            config.default_min_auditor_approvals.get(),
        )
        || !config.capsule_padding_classes_bytes.iter().any(|class| {
            usize::try_from(class.get()).ok()
                == Some(request.payload.audit_capsule.padding.plaintext_bytes())
        })
        || request.payload.availability.body.retention_until_height
            < stored_at_height.saturating_add(config.sidecar_retention_blocks.get())
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_request",
        ));
    }
    Ok(())
}

fn validate_availability_share_policy(
    app: &SharedAppState,
    request: &PrivateSettlementAvailabilityShareRequestV1,
    stored_at_height: u64,
) -> Result<(), Response> {
    let config = active_config(app, stored_at_height)?;
    let material = &request.material;
    if !committee_authority_is_authoritative(
        app,
        material.manifest.authority_context_height,
        &material.committee_authority,
    ) || material.manifest.network_id != app.state.network_id
        || material.manifest.legs.len() > usize::from(config.max_participants.get())
        || material
            .manifest
            .expiry_height
            .checked_sub(material.manifest.authority_context_height)
            .is_none_or(|span| span > config.max_expiry_blocks.get())
        || material.proof.len() as u64 > config.max_proof_bytes.get()
        || !audit_capsule_within_canonical_bound(
            &material.audit_capsule,
            config.max_capsule_bytes.get(),
        )
        || !config
            .permitted_policy_versions
            .contains(&u16::from(material.audit_policy.body.version))
        || !audit_threshold_meets_governed_floor(
            material.audit_policy.body.min_approvals,
            config.default_min_auditor_approvals.get(),
        )
        || !config.capsule_padding_classes_bytes.iter().any(|class| {
            usize::try_from(class.get()).ok()
                == Some(material.audit_capsule.padding.plaintext_bytes())
        })
        || material.availability_body.retention_until_height
            < stored_at_height.saturating_add(config.sidecar_retention_blocks.get())
        || material.validate().is_err()
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_request",
        ));
    }
    Ok(())
}

fn validate_phase_manifest_policy(
    app: &SharedAppState,
    manifest: &iroha_data_model::nexus::AtomicPrivateSettlementV1,
    authoritative_height: u64,
) -> Result<(), Response> {
    let config = active_config(app, authoritative_height)?;
    if manifest.validate().is_err()
        || manifest.network_id != app.state.network_id
        || authoritative_height < manifest.authority_context_height
        || authoritative_height > manifest.expiry_height
        || manifest.legs.len() > usize::from(config.max_participants.get())
        || manifest
            .expiry_height
            .checked_sub(manifest.authority_context_height)
            .is_none_or(|span| span > config.max_expiry_blocks.get())
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_phase_rejected",
        ));
    }
    Ok(())
}

fn validate_phase_deadline(
    app: &SharedAppState,
    store: &PrivateSettlementFileSidecarStoreV1,
    payload_digest: Hash,
    phase: PrivateSettlementPhaseV1,
    authoritative_height: u64,
) -> Result<(), Response> {
    let config = active_config(app, authoritative_height)?;
    let status = store
        .public_status(payload_digest, authoritative_height)
        .map_err(|_| map_phase_error(PrivateSettlementPhaseErrorV1))?;
    let prepare_deadline = status
        .stored_at_height
        .saturating_add(config.audit_timeout_blocks.get())
        .saturating_add(config.prepare_timeout_blocks.get());
    let deadline = match phase {
        PrivateSettlementPhaseV1::Prepare => prepare_deadline,
        PrivateSettlementPhaseV1::Commit => {
            prepare_deadline.saturating_add(config.commit_timeout_blocks.get())
        }
    };
    if authoritative_height > deadline {
        return Err(map_phase_error(PrivateSettlementPhaseErrorV1));
    }
    Ok(())
}

/// Persist sponsor-authenticated provisional bytes and issue this node's share.
pub(crate) async fn handler_availability_share(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<VerifiedCanonicalRequest>,
    NoritoJson(request): NoritoJson<PrivateSettlementAvailabilityShareRequestV1>,
) -> Response {
    let Ok(store) = runtime.store() else {
        return private_settlement_unavailable();
    };
    let Ok(signer) = runtime.availability_signer() else {
        return private_settlement_unavailable();
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if authenticated.account != request.material.manifest.sponsor {
        return error_response(StatusCode::FORBIDDEN, "private_settlement_sponsor_required");
    }
    if let Err(response) = validate_availability_share_policy(&app, &request, height) {
        return response;
    }
    let bundle_id = request.material.manifest.bundle_id;
    #[cfg(feature = "test-network-private-settlement-route-control")]
    if let Err(response) = apply_private_settlement_route_control_v1(
        crate::private_settlement_route_control::Phase::RestrictedDa,
        bundle_id,
        &request,
        &authenticated,
    )
    .await
    {
        return response;
    }
    let payload_digest = request.material.availability_body.payload_digest;
    let leg_ordinal = request.material.statement.leg_ordinal;
    let (outcome, share) = match signer.persist_and_sign(store, request.material, height) {
        Ok(result) => result,
        Err(error) => return map_availability_error(error),
    };
    let disposition = match outcome {
        PrivateSettlementSidecarStoreOutcomeV1::Stored => {
            PrivateSettlementLegUploadDispositionV1::Stored
        }
        PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored => {
            PrivateSettlementLegUploadDispositionV1::AlreadyStored
        }
    };
    JsonBody(PrivateSettlementAvailabilityShareResponseV1 {
        bundle_id,
        payload_digest,
        leg_ordinal,
        disposition,
        share,
    })
    .into_response()
}

/// Independently validate current WSV, fsync-stage, and issue one Prepare vote.
pub(crate) async fn handler_prepare_vote(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<VerifiedCanonicalRequest>,
    NoritoJson(request): NoritoJson<PrivateSettlementPrepareVoteRequestV1>,
) -> Response {
    let Ok(store) = runtime.store() else {
        return private_settlement_unavailable();
    };
    let Ok(signer) = runtime.phase_signer() else {
        return private_settlement_unavailable();
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if authenticated.account != request.manifest.sponsor {
        return error_response(StatusCode::FORBIDDEN, "private_settlement_sponsor_required");
    }
    if let Err(response) = validate_phase_manifest_policy(&app, &request.manifest, height) {
        return response;
    }
    if let Err(response) = validate_phase_deadline(
        &app,
        store,
        request.payload_digest,
        PrivateSettlementPhaseV1::Prepare,
        height,
    ) {
        return response;
    }
    #[cfg(feature = "test-network-private-settlement-route-control")]
    if let Err(response) = apply_private_settlement_route_control_v1(
        crate::private_settlement_route_control::Phase::Prepare,
        request.manifest.bundle_id,
        &request,
        &authenticated,
    )
    .await
    {
        return response;
    }
    let state = app.state.view();
    let vote = match signer.prepare_vote(
        &state,
        store,
        &request.manifest,
        request.payload_digest,
        height,
    ) {
        Ok(vote) => vote,
        Err(error) => return map_phase_error(error),
    };
    JsonBody(PrivateSettlementPhaseVoteResponseV1 {
        bundle_id: vote.body.bundle_id,
        payload_digest: request.payload_digest,
        leg_ordinal: vote.body.leg_ordinal,
        vote,
    })
    .into_response()
}

/// Verify one exact complete all-Prepare barrier and issue a read-only Commit vote.
pub(crate) async fn handler_commit_vote(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<VerifiedCanonicalRequest>,
    NoritoJson(request): NoritoJson<PrivateSettlementCommitVoteRequestV1>,
) -> Response {
    let Ok(store) = runtime.store() else {
        return private_settlement_unavailable();
    };
    let Ok(signer) = runtime.phase_signer() else {
        return private_settlement_unavailable();
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if authenticated.account != request.barrier.manifest.sponsor {
        return error_response(StatusCode::FORBIDDEN, "private_settlement_sponsor_required");
    }
    if request.barrier.validate_shape().is_err() {
        return map_phase_error(PrivateSettlementPhaseErrorV1);
    }
    if let Err(response) = validate_phase_manifest_policy(&app, &request.barrier.manifest, height) {
        return response;
    }
    if let Err(response) = validate_phase_deadline(
        &app,
        store,
        request.payload_digest,
        PrivateSettlementPhaseV1::Commit,
        height,
    ) {
        return response;
    }
    #[cfg(feature = "test-network-private-settlement-route-control")]
    if let Err(response) = apply_private_settlement_route_control_v1(
        crate::private_settlement_route_control::Phase::Commit,
        request.barrier.manifest.bundle_id,
        &request,
        &authenticated,
    )
    .await
    {
        return response;
    }
    let state = app.state.view();
    let vote = match signer.commit_vote(
        &state,
        store,
        request.payload_digest,
        &request.barrier,
        height,
    ) {
        Ok(vote) => vote,
        Err(error) => return map_phase_error(error),
    };
    JsonBody(PrivateSettlementPhaseVoteResponseV1 {
        bundle_id: vote.body.bundle_id,
        payload_digest: request.payload_digest,
        leg_ordinal: vote.body.leg_ordinal,
        vote,
    })
    .into_response()
}

/// Verify and fsync one aggregate Prepare or Commit certificate on a signer node.
pub(crate) async fn handler_phase_certificate(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<VerifiedCanonicalRequest>,
    NoritoJson(request): NoritoJson<PrivateSettlementPhaseCertificateRequestV1>,
) -> Response {
    let Ok(store) = runtime.store() else {
        return private_settlement_unavailable();
    };
    let Ok(signer) = runtime.phase_signer() else {
        return private_settlement_unavailable();
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if authenticated.account != request.manifest.sponsor {
        return error_response(StatusCode::FORBIDDEN, "private_settlement_sponsor_required");
    }
    if let Err(response) = validate_phase_manifest_policy(&app, &request.manifest, height) {
        return response;
    }
    let phase = request.certificate.body.phase;
    if let Err(response) =
        validate_phase_deadline(&app, store, request.payload_digest, phase, height)
    {
        return response;
    }
    #[cfg(feature = "test-network-private-settlement-route-control")]
    if let Err(response) = apply_private_settlement_route_control_v1(
        match phase {
            PrivateSettlementPhaseV1::Prepare => {
                crate::private_settlement_route_control::Phase::Prepare
            }
            PrivateSettlementPhaseV1::Commit => {
                crate::private_settlement_route_control::Phase::Commit
            }
        },
        request.manifest.bundle_id,
        &request,
        &authenticated,
    )
    .await
    {
        return response;
    }
    let leg_ordinal = request.certificate.body.leg_ordinal;
    if signer
        .persist_certificate(
            store,
            &request.manifest,
            request.payload_digest,
            request.certificate,
            height,
        )
        .is_err()
    {
        return map_phase_error(PrivateSettlementPhaseErrorV1);
    }
    let status = match store.public_status(request.payload_digest, height) {
        Ok(status) => status,
        Err(_) => return map_phase_error(PrivateSettlementPhaseErrorV1),
    };
    if status.leg_ordinal != leg_ordinal
        || !phase_certificate_acknowledges_lifecycle_v1(phase, status.lifecycle)
    {
        return map_phase_error(PrivateSettlementPhaseErrorV1);
    }
    JsonBody(PrivateSettlementPhaseCertificateResponseV1 {
        bundle_id: status.bundle_id,
        payload_digest: status.payload_digest,
        leg_ordinal,
        phase,
        lifecycle: lifecycle_dto(status.lifecycle),
    })
    .into_response()
}

/// Recover exact durable Prepare and Commit QCs as the immutable bundle sponsor.
pub(crate) async fn handler_phase_certificates_get(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<VerifiedCanonicalRequest>,
    Path(payload_digest): Path<String>,
) -> Response {
    let payload_digest = match parse_digest(&payload_digest) {
        Ok(digest) => digest,
        Err(response) => return response,
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if active_config(&app, height).is_err() {
        return private_settlement_unavailable();
    }
    let recovered = match runtime.store().and_then(|store| {
        store
            .sponsor_phase_certificates(payload_digest, &authenticated.account, height)
            .map_err(map_store_error)
    }) {
        Ok(recovered) => recovered,
        Err(response) => return response,
    };
    JsonBody(PrivateSettlementPhaseCertificatesResponseV1 {
        bundle_id: recovered.bundle_id,
        payload_digest: recovered.payload_digest,
        leg_ordinal: recovered.leg_ordinal,
        lifecycle: lifecycle_dto(recovered.lifecycle),
        prepare_certificate: recovered.prepare_certificate,
        commit_certificate: recovered.commit_certificate,
    })
    .into_response()
}

/// Persist one sponsor-authenticated encrypted leg through restricted DA.
pub(crate) async fn handler_leg_upload(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<VerifiedCanonicalRequest>,
    NoritoJson(request): NoritoJson<PrivateSettlementLegUploadRequestV1>,
) -> Response {
    let Ok(store) = runtime.store() else {
        return private_settlement_unavailable();
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if authenticated.account != request.manifest.sponsor {
        return error_response(StatusCode::FORBIDDEN, "private_settlement_sponsor_required");
    }
    if let Err(response) = validate_upload_policy(&app, &request, height) {
        return response;
    }
    let bundle_id = request.manifest.bundle_id;
    #[cfg(feature = "test-network-private-settlement-route-control")]
    if let Err(response) = apply_private_settlement_route_control_v1(
        crate::private_settlement_route_control::Phase::RestrictedDa,
        bundle_id,
        &request,
        &authenticated,
    )
    .await
    {
        return response;
    }
    let payload_digest = request.payload.availability.body.payload_digest;
    let leg_ordinal = request.payload.statement.leg_ordinal;
    let sidecar = PrivateSettlementRestrictedSidecarV1 {
        manifest: request.manifest,
        policy: request.audit_policy,
        authority: request.committee_authority,
        payload: request.payload,
        stored_at_height: height,
    };
    let disposition = match store.promote(sidecar) {
        Ok(PrivateSettlementSidecarStoreOutcomeV1::Stored) => {
            PrivateSettlementLegUploadDispositionV1::Stored
        }
        Ok(PrivateSettlementSidecarStoreOutcomeV1::AlreadyStored) => {
            PrivateSettlementLegUploadDispositionV1::AlreadyStored
        }
        Err(error) => return map_store_error(error),
    };
    let lifecycle = match store.public_status(payload_digest, height) {
        Ok(status) => lifecycle_dto(status.lifecycle),
        Err(error) => return map_store_error(error),
    };
    JsonBody(PrivateSettlementLegUploadResponseV1 {
        bundle_id,
        payload_digest,
        leg_ordinal,
        disposition,
        lifecycle,
    })
    .into_response()
}

/// Return an allowlisted lifecycle projection for one encrypted leg.
pub(crate) async fn handler_leg_status(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Path(payload_digest): Path<String>,
) -> Response {
    let Ok(store) = runtime.store() else {
        return private_settlement_unavailable();
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if active_config(&app, height).is_err() {
        return private_settlement_unavailable();
    }
    let digest = match parse_digest(&payload_digest) {
        Ok(digest) => digest,
        Err(response) => return response,
    };
    let status = match store.public_status(digest, height) {
        Ok(status) => status,
        Err(error) => return map_store_error(error),
    };
    JsonBody(PrivateSettlementLegStatusResponseV1 {
        bundle_id: status.bundle_id,
        payload_digest: status.payload_digest,
        leg_ordinal: status.leg_ordinal,
        route: status.route,
        stored_at_height: status.stored_at_height,
        lifecycle_height: status.lifecycle_height,
        expiry_height: status.expiry_height,
        lifecycle: lifecycle_dto(status.lifecycle),
    })
    .into_response()
}

/// Return proof and opaque delta material only to an exact committee validator.
pub(crate) async fn handler_committee_proof(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<crate::operator_signatures::AuthenticatedOperatorPublicKey>,
    Path(payload_digest): Path<String>,
) -> Response {
    let Ok(store) = runtime.store() else {
        return private_settlement_unavailable();
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if active_config(&app, height).is_err() {
        return private_settlement_unavailable();
    }
    let digest = match parse_digest(&payload_digest) {
        Ok(digest) => digest,
        Err(response) => return response,
    };
    let validator = iroha_model_base::peer::PeerId::from(authenticated.0);
    let view = match store.fetch_for_committee(digest, &validator, height) {
        Ok(view) => view,
        Err(error) => return map_store_error(error),
    };
    JsonBody(PrivateSettlementCommitteeProofResponseV1 {
        manifest: view.manifest,
        audit_policy: view.policy,
        committee_authority: view.authority,
        statement: view.statement,
        proof: view.proof,
        delta: view.delta,
        audit_approvals: view.audit_approvals,
        audit_capsule_digest: view.audit_capsule_digest,
        availability: view.availability,
        lifecycle: lifecycle_dto(view.lifecycle),
    })
    .into_response()
}

fn governed_auditor_view(
    app: &SharedAppState,
    runtime: &PrivateSettlementToriiRuntimeV1,
    payload_digest: &str,
    access_policy: &iroha_data_model::nexus::PrivateSettlementAuditPolicyV1,
    signing_key: &PublicKey,
) -> Result<
    (
        Hash,
        u64,
        iroha_core::private_settlement::PrivateSettlementAuthenticatedAuditorViewV1,
    ),
    Response,
> {
    let store = runtime.store()?;
    let state = app.state.view();
    let height = u64::try_from(state.height()).map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "private_settlement_height_unavailable",
        )
    })?;
    active_config(app, height)?;
    let digest = parse_digest(payload_digest)?;
    let authenticated =
        fetch_private_settlement_auditor_view_v1(&state, store, digest, access_policy, signing_key)
            .map_err(map_store_error)?;
    Ok((digest, height, authenticated))
}

/// Return the padded encrypted capsule only to an exact governed auditor key.
pub(crate) async fn handler_auditor_capsule(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<crate::operator_signatures::AuthenticatedOperatorPublicKey>,
    Path(payload_digest): Path<String>,
    NoritoJson(request): NoritoJson<PrivateSettlementAuditorCapsuleRequestV1>,
) -> Response {
    let Ok(signer) = runtime.availability_signer() else {
        return private_settlement_unavailable();
    };
    let (payload_digest, authoritative_height, authenticated_view) = match governed_auditor_view(
        &app,
        &runtime,
        &payload_digest,
        &request.audit_policy,
        &authenticated.0,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let access_audit_policy = authenticated_view.access_policy;
    let view = authenticated_view.view;
    let lifecycle = lifecycle_dto(view.lifecycle);
    let view_digest = match (PrivateSettlementAuditorViewDigestMaterialV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        authoritative_height,
        manifest: view.manifest.clone(),
        access_audit_policy: access_audit_policy.clone(),
        audit_policy: view.policy.clone(),
        committee_authority: view.authority.clone(),
        statement: view.statement.clone(),
        delta: view.delta.clone(),
        audit_capsule: view.audit_capsule.clone(),
        availability: view.availability.clone(),
        lifecycle_code: lifecycle.attestation_code(),
    })
    .digest()
    {
        Ok(digest) => digest,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "private_settlement_service_unavailable",
            );
        }
    };
    let authority_digest = match view.authority.digest() {
        Ok(digest) => digest,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "private_settlement_service_unavailable",
            );
        }
    };
    let attestation = match signer.sign_auditor_view(
        PrivateSettlementAuditorViewAttestationBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: view.manifest.network_id,
            payload_digest,
            view_digest,
            authority_digest,
            lifecycle_code: lifecycle.attestation_code(),
            authoritative_height,
            responder: signer.peer_id().clone(),
        },
        &view.authority,
    ) {
        Ok(attestation) => attestation,
        Err(error) => return map_availability_error(error),
    };
    JsonBody(PrivateSettlementAuditorCapsuleResponseV1 {
        authoritative_height,
        manifest: view.manifest,
        access_audit_policy,
        audit_policy: view.policy,
        committee_authority: view.authority,
        statement: view.statement,
        delta: view.delta,
        audit_capsule: view.audit_capsule,
        availability: view.availability,
        lifecycle,
        responder_attestation: attestation,
    })
    .into_response()
}

/// Persist one approval after binding its body to the authenticated auditor key.
pub(crate) async fn handler_auditor_approval(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Extension(authenticated): Extension<crate::operator_signatures::AuthenticatedOperatorPublicKey>,
    Path(payload_digest): Path<String>,
    NoritoJson(request): NoritoJson<PrivateSettlementAuditApprovalRequestV1>,
) -> Response {
    let Ok(signer) = runtime.availability_signer() else {
        return private_settlement_unavailable();
    };
    let (digest, height, authenticated_view) = match governed_auditor_view(
        &app,
        &runtime,
        &payload_digest,
        &request.audit_policy,
        &authenticated.0,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let approval: PrivateSettlementAuditApprovalV1 = request.approval;
    if authenticated_view.access_policy != authenticated_view.view.policy
        || approval.body.auditor_id != authenticated_view.auditor_id
    {
        return private_settlement_unavailable();
    }
    let authority = authenticated_view.view.authority.clone();
    if !authority
        .validators
        .iter()
        .any(|validator| validator == signer.peer_id())
    {
        return private_settlement_unavailable();
    }
    let network_id = approval.body.network_id;
    let approval_digest = match approval.digest() {
        Ok(digest) => digest,
        Err(_) => return private_settlement_unavailable(),
    };
    let config = match active_config(&app, height) {
        Ok(config) => config,
        Err(response) => return response,
    };
    let status = match runtime
        .store()
        .and_then(|store| store.public_status(digest, height).map_err(map_store_error))
    {
        Ok(status) => status,
        Err(response) => return response,
    };
    if height
        > status
            .stored_at_height
            .saturating_add(config.audit_timeout_blocks.get())
    {
        return error_response(StatusCode::CONFLICT, "private_settlement_audit_timeout");
    }
    let outcome = match runtime.store().and_then(|store| {
        store
            .record_audit_approval(digest, approval, height)
            .map_err(map_store_error)
    }) {
        Ok(outcome) => outcome,
        Err(response) => return response,
    };
    let lifecycle = if outcome.audited {
        PrivateSettlementLifecycleDtoV1::Audited
    } else {
        PrivateSettlementLifecycleDtoV1::Collecting
    };
    let bundle_id = authenticated_view.view.manifest.bundle_id;
    let leg_ordinal = authenticated_view.view.statement.leg_ordinal;
    let acknowledgement_digest =
        match (PrivateSettlementAuditApprovalAcknowledgementDigestMaterialV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            authoritative_height: height,
            bundle_id,
            payload_digest: digest,
            leg_ordinal,
            committee_authority: authority.clone(),
            collected: outcome.collected,
            required: outcome.required,
            newly_recorded: outcome.newly_recorded,
            lifecycle_code: lifecycle.attestation_code(),
        })
        .digest()
        {
            Ok(digest) => digest,
            Err(_) => return private_settlement_unavailable(),
        };
    let authority_digest = match authority.digest() {
        Ok(digest) => digest,
        Err(_) => return private_settlement_unavailable(),
    };
    let responder_attestation = match signer.sign_audit_approval_acknowledgement(
        PrivateSettlementAuditApprovalAcknowledgementAttestationBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id,
            payload_digest: digest,
            approval_digest,
            acknowledgement_digest,
            authority_digest,
            lifecycle_code: lifecycle.attestation_code(),
            authoritative_height: height,
            responder: signer.peer_id().clone(),
        },
        &authority,
    ) {
        Ok(attestation) => attestation,
        Err(error) => return map_availability_error(error),
    };
    JsonBody(PrivateSettlementAuditApprovalResponseV1 {
        authoritative_height: height,
        bundle_id,
        payload_digest: digest,
        leg_ordinal,
        committee_authority: authority,
        collected: outcome.collected,
        required: outcome.required,
        newly_recorded: outcome.newly_recorded,
        lifecycle,
        responder_attestation,
    })
    .into_response()
}

enum ExactPrivateSettlementCarrierV1<'a> {
    RegisterPrepare(&'a RegisterAtomicPrivateSettlementPrepareV1),
    Finalize(&'a FinalizeAtomicPrivateSettlementV1),
    Abort(&'a AbortAtomicPrivateSettlementV1),
}

impl ExactPrivateSettlementCarrierV1<'_> {
    fn manifest(&self) -> &iroha_data_model::nexus::AtomicPrivateSettlementV1 {
        match self {
            Self::RegisterPrepare(carrier) => &carrier.barrier.manifest,
            Self::Finalize(carrier) => &carrier.commit_bundle.manifest,
            Self::Abort(carrier) => &carrier.manifest,
        }
    }

    fn is_structurally_admissible(&self, current_height: u64, max_participants: u16) -> bool {
        let manifest = self.manifest();
        if manifest.validate().is_err() || manifest.legs.len() > usize::from(max_participants) {
            return false;
        }
        match self {
            Self::RegisterPrepare(carrier) => {
                private_settlement_prepare_registration_height_is_live_v1(
                    current_height,
                    manifest.authority_context_height,
                    manifest.expiry_height,
                ) && carrier.barrier.validate_shape().is_ok()
                    && carrier.barrier.deltas.len() <= usize::from(max_participants)
                    && carrier.barrier.prepare_certificates.len() == carrier.barrier.deltas.len()
            }
            Self::Finalize(carrier) => {
                let candidate_receipt = carrier
                    .commit_bundle
                    .clone()
                    .into_receipt(manifest.authority_context_height);
                private_settlement_carrier_height_is_live_v1(
                    current_height,
                    manifest.authority_context_height,
                    manifest.expiry_height,
                ) && candidate_receipt.validate_shape().is_ok()
                    && carrier.commit_bundle.legs.len() <= usize::from(max_participants)
            }
            Self::Abort(carrier) => private_settlement_abort_height_is_admissible_v1(
                current_height,
                manifest.authority_context_height,
                manifest.expiry_height,
                carrier.reason,
            ),
        }
    }
}

fn exact_private_settlement_carrier(
    transaction: &SignedTransaction,
) -> Result<ExactPrivateSettlementCarrierV1<'_>, Response> {
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_carrier",
        ));
    };
    if instructions.len() != 1 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "private_settlement_invalid_carrier",
        ));
    }
    let instruction = instructions[0].as_any();
    if let Some(carrier) = instruction.downcast_ref::<RegisterAtomicPrivateSettlementPrepareV1>() {
        return Ok(ExactPrivateSettlementCarrierV1::RegisterPrepare(carrier));
    }
    if let Some(carrier) = instruction.downcast_ref::<FinalizeAtomicPrivateSettlementV1>() {
        return Ok(ExactPrivateSettlementCarrierV1::Finalize(carrier));
    }
    if let Some(carrier) = instruction.downcast_ref::<AbortAtomicPrivateSettlementV1>() {
        return Ok(ExactPrivateSettlementCarrierV1::Abort(carrier));
    }
    Err(error_response(
        StatusCode::BAD_REQUEST,
        "private_settlement_invalid_carrier",
    ))
}

/// Admit one exact sponsor-signed global Prepare-lock, finalization, or abort carrier.
pub(crate) async fn handler_bundle_submit(
    State(app): State<SharedAppState>,
    Extension(authenticated): Extension<VerifiedCanonicalRequest>,
    headers: HeaderMap,
    accept: Option<crate::utils::extractors::ExtractAccept>,
    NoritoJson(request): NoritoJson<PrivateSettlementBundleSubmitRequestV1>,
) -> Result<Response, crate::Error> {
    let height = authoritative_height(&app).map_err(|_| crate::Error::AppServiceUnavailable {
        code: "private_settlement_height_unavailable",
        message: "private-settlement height is unavailable".to_owned(),
    })?;
    let config = active_config(&app, height).map_err(|_| crate::Error::AppServiceUnavailable {
        code: "private_settlement_unavailable",
        message: "private-settlement carrier admission is unavailable".to_owned(),
    })?;
    let transaction = request.transaction;
    let carrier = exact_private_settlement_carrier(&transaction).map_err(|_| {
        crate::Error::AppQueryValidation {
            code: "private_settlement_invalid_carrier",
            message: "private-settlement carrier is invalid".to_owned(),
        }
    })?;
    let manifest = carrier.manifest();
    let carrier_within_bound = private_settlement_carrier_within_wire_bound_v1(
        &transaction,
        config.max_carrier_bytes.get(),
    )
    .map_err(|_| crate::Error::AppQueryValidation {
        code: "private_settlement_invalid_carrier",
        message: "private-settlement carrier is not canonically encodable".to_owned(),
    })?;
    if authenticated.account != manifest.sponsor
        || transaction.authority() != &manifest.sponsor
        || transaction.fee_payment_intent() != &manifest.public_fee_intent
        || manifest.network_id != app.state.network_id
        || !carrier.is_structurally_admissible(height, config.max_participants.get())
        || manifest
            .expiry_height
            .checked_sub(manifest.authority_context_height)
            .is_none_or(|span| span > config.max_expiry_blocks.get())
        || !carrier_within_bound
    {
        return Err(crate::Error::AppQueryValidation {
            code: "private_settlement_invalid_carrier",
            message: "private-settlement carrier is invalid".to_owned(),
        });
    }
    let bundle_id = manifest.bundle_id;
    let carrier_id = Hash::from(transaction.hash());
    let admitted =
        crate::submit_signed_transaction_for_ingress(app, headers, accept, transaction).await?;
    if !admitted.status().is_success() {
        return Ok(admitted);
    }
    let mut response = JsonBody(PrivateSettlementBundleSubmitResponseV1 {
        bundle_id,
        accepted_at_height: height,
        carrier_id,
    })
    .into_response();
    *response.status_mut() = admitted.status();
    Ok(response)
}

fn terminal_bundle_state(
    app: &SharedAppState,
    bundle_id: Hash,
) -> (
    Option<iroha_data_model::nexus::PrivateSettlementReceiptV1>,
    Option<iroha_data_model::nexus::PrivateSettlementAbortReceiptV1>,
) {
    let view = app.state.view();
    let world = view.world();
    (
        world.private_settlement_receipt_v1(&bundle_id).cloned(),
        world.private_settlement_abort_v1(&bundle_id).copied(),
    )
}

/// Return an allowlisted aggregate bundle lifecycle.
pub(crate) async fn handler_bundle_status(
    State(app): State<SharedAppState>,
    Extension(runtime): Extension<PrivateSettlementToriiRuntimeV1>,
    Path(bundle_id): Path<String>,
) -> Response {
    let bundle_id = match parse_digest(&bundle_id) {
        Ok(bundle_id) => bundle_id,
        Err(response) => return response,
    };
    let height = match authoritative_height(&app) {
        Ok(height) => height,
        Err(response) => return response,
    };
    if active_config(&app, height).is_err() {
        return private_settlement_unavailable();
    }
    let (receipt, abort) = terminal_bundle_state(&app, bundle_id);
    if let Some(receipt) = receipt {
        return JsonBody(PrivateSettlementBundleStatusResponseV1 {
            manifest: Some(receipt.manifest),
            lifecycle: PrivateSettlementLifecycleDtoV1::Finalized,
            finalized_height: Some(receipt.finalized_height),
        })
        .into_response();
    }
    let sidecar = runtime.store().and_then(|store| {
        store
            .public_bundle_status(bundle_id, height)
            .map_err(map_store_error)
    });
    if let Some(abort) = abort {
        let manifest = sidecar.ok().map(|status| status.manifest);
        let lifecycle = if abort.reason == PrivateSettlementAbortReasonV1::Expired {
            PrivateSettlementLifecycleDtoV1::Expired
        } else {
            PrivateSettlementLifecycleDtoV1::Aborted
        };
        return JsonBody(PrivateSettlementBundleStatusResponseV1 {
            manifest,
            lifecycle,
            finalized_height: Some(abort.finalized_height),
        })
        .into_response();
    }
    let status = match sidecar {
        Ok(status) => status,
        Err(response) => return response,
    };
    JsonBody(PrivateSettlementBundleStatusResponseV1 {
        manifest: Some(status.manifest),
        lifecycle: lifecycle_dto(status.lifecycle),
        finalized_height: None,
    })
    .into_response()
}

/// Read only public terminal state; absence makes no claim about local sidecars.
fn public_bundle_receipt(
    bundle_id: Hash,
    receipt: Option<iroha_data_model::nexus::PrivateSettlementReceiptV1>,
    abort: Option<iroha_data_model::nexus::PrivateSettlementAbortReceiptV1>,
) -> PrivateSettlementBundleReceiptResponseV1 {
    if let Some(receipt) = receipt {
        PrivateSettlementBundleReceiptResponseV1::Finalized(receipt)
    } else if let Some(abort) = abort {
        PrivateSettlementBundleReceiptResponseV1::Aborted(abort)
    } else {
        PrivateSettlementBundleReceiptResponseV1::Pending { bundle_id }
    }
}

/// Return public terminal state from one committed view, independently of sidecar placement.
pub(crate) async fn handler_bundle_receipt(
    State(app): State<SharedAppState>,
    Path(bundle_id): Path<String>,
) -> Response {
    let bundle_id = match parse_digest(&bundle_id) {
        Ok(bundle_id) => bundle_id,
        Err(response) => return response,
    };
    let view = app.state.view();
    let height = match u64::try_from(view.height()) {
        Ok(height) => height,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "private_settlement_height_unavailable",
            );
        }
    };
    if active_config_at_view(height, &view).is_err() {
        return private_settlement_unavailable();
    }
    let world = view.world();
    JsonBody(public_bundle_receipt(
        bundle_id,
        world.private_settlement_receipt_v1(&bundle_id).cloned(),
        world.private_settlement_abort_v1(&bundle_id).copied(),
    ))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        block::BlockHeader,
        nexus::{
            AtomicPrivateSettlementV1, PrivateSettlementLegCommitmentV1, PrivateSettlementRouteV1,
        },
        privacy::PrivacyPoolIdV1,
        transaction::FeePaymentIntent,
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};

    fn abort_carrier_manifest_fixture() -> AtomicPrivateSettlementV1 {
        let sponsor = KeyPair::from_seed(vec![0xD4; 32], Algorithm::Ed25519);
        let mut manifest = AtomicPrivateSettlementV1 {
            version: AtomicPrivateSettlementV1::VERSION,
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"carrier bound network")),
            ),
            bundle_id: Hash::new(b"carrier bound bundle"),
            authority_context_height: 10,
            expiry_height: 20,
            sponsor: AccountId::new(sponsor.public_key().clone()),
            public_fee_intent: FeePaymentIntent::authority(Vec::new(), None),
            fee_intent_digest: Hash::new(b"carrier bound fee intent"),
            reimbursement_terms_commitment: Hash::new(b"carrier bound reimbursement"),
            reimbursement_leg_ordinal: 0,
            legs: (0_u8..2)
                .map(|ordinal| PrivateSettlementLegCommitmentV1 {
                    ordinal,
                    route: PrivateSettlementRouteV1 {
                        dataspace_id: DataSpaceId::new(u64::from(ordinal) + 1),
                        lane_id: LaneId::new(u32::from(ordinal) + 1),
                        lane_incarnation: Hash::new([ordinal, 0x11]),
                    },
                    pool_id: PrivacyPoolIdV1::new([ordinal + 1; 32]),
                    asset_binding_commitment: Hash::new([ordinal, 0x22]),
                    audit_policy_digest: Hash::new([ordinal, 0x33]),
                    payload_digest: Hash::new([ordinal, 0x44]),
                    availability_certificate_digest: Hash::new([ordinal, 0x55]),
                    delta_digest: Hash::new([ordinal, 0x66]),
                })
                .collect(),
        };
        manifest.fee_intent_digest = manifest
            .computed_fee_intent_digest()
            .expect("fixture fee intent hashes");
        manifest.bundle_id = manifest
            .computed_bundle_id()
            .expect("fixture bundle hashes");
        manifest
    }

    #[test]
    fn public_receipt_absence_is_pending_and_terminal_state_takes_precedence() {
        let manifest = abort_carrier_manifest_fixture();
        let bundle_id = manifest.bundle_id;
        assert_eq!(
            public_bundle_receipt(bundle_id, None, None),
            PrivateSettlementBundleReceiptResponseV1::Pending { bundle_id }
        );
        let abort = iroha_data_model::nexus::PrivateSettlementAbortReceiptV1 {
            version: AtomicPrivateSettlementV1::VERSION,
            network_id: manifest.network_id,
            bundle_id,
            manifest_digest: manifest.manifest_digest().expect("manifest digest"),
            finalized_height: 12,
            reason: PrivateSettlementAbortReasonV1::ParticipantRejected,
        };
        assert_eq!(
            public_bundle_receipt(bundle_id, None, Some(abort)),
            PrivateSettlementBundleReceiptResponseV1::Aborted(abort)
        );
        // Classification trusts authenticated WSV terminal records, without consulting a sidecar store.
        let receipt = iroha_data_model::nexus::PrivateSettlementReceiptV1 {
            version: AtomicPrivateSettlementV1::VERSION,
            manifest,
            authority_catalog: Default::default(),
            legs: Vec::new(),
            finalized_height: 12,
        };
        for competing_abort in [None, Some(abort)] {
            assert_eq!(
                public_bundle_receipt(bundle_id, Some(receipt.clone()), competing_abort),
                PrivateSettlementBundleReceiptResponseV1::Finalized(receipt.clone())
            );
        }
    }

    #[cfg(feature = "app_api")]
    fn activated_private_settlement_chain_for_test()
    -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
        use iroha_core::state::World;
        use iroha_data_model::{
            isi::privacy::{
                RegisterPrivacyProtocolActivationV1, TransitionPrivacyProtocolLifecycleV1,
            },
            privacy::{
                PrivacyActiveLifecycleV1, PrivacyProposedLifecycleV1, PrivacyProtocolIdV1,
                PrivacyProtocolLifecycleV1,
            },
        };
        use std::num::NonZeroU64;

        let mut config = iroha_config::parameters::actual::Nexus::default();
        config.atomic_private_settlement.enabled = true;
        config.atomic_private_settlement.activation_height = Some(2);
        config
            .atomic_private_settlement
            .minimum_activation_notice_blocks = NonZeroU64::new(1).expect("notice");
        let protocol_id = PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1;
        let profile =
            iroha_core_privacy::privacy_profiles::compiled_privacy_profile_v1(protocol_id)
                .expect("compiled profile");
        let mut chain_config =
            iroha_core::sumeragi::test_chain::TestChainConfig::new(World::default(), 1);
        chain_config.nexus = Some(config);
        chain_config.genesis_instructions = vec![
            RegisterPrivacyProtocolActivationV1::new(profile.activation_record(
                PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
                    proposed_at_height: 1,
                }),
            ))
            .into(),
            TransitionPrivacyProtocolLifecycleV1::new(
                protocol_id,
                PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 1,
                    state_since_height: 1,
                }),
            )
            .into(),
        ];
        let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(chain_config)
            .expect("execute original privacy activation genesis");
        chain.commit_at(2, Vec::new());
        chain
    }

    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn activated_public_receipt_route_returns_pending_without_sidecar_runtime() {
        use tower::ServiceExt as _;
        let chain = activated_private_settlement_chain_for_test();
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let inner = Arc::get_mut(&mut app).expect("unique test app");
        inner.state = chain.state().clone();
        inner.kura = chain.kura().clone();
        let view = app.state.view();
        assert_eq!(view.height(), 2);
        active_config_at_view(2, &view).expect("real active capability gate");
        let bundle_id = Hash::new(b"identifier without local sidecars or terminal records");
        assert!(
            view.world()
                .private_settlement_receipt_v1(&bundle_id)
                .is_none()
        );
        assert!(
            view.world()
                .private_settlement_abort_v1(&bundle_id)
                .is_none()
        );
        drop(view);
        // The real route has no PrivateSettlementToriiRuntimeV1 Extension at all.
        let router = axum::Router::new()
            .route(
                "/v1/nexus/private-settlements/bundles/{bundle_id}/receipt",
                axum::routing::get(handler_bundle_receipt),
            )
            .with_state(app);
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!(
                        "/v1/nexus/private-settlements/bundles/{bundle_id}/receipt"
                    ))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("bounded response");
        let decoded: PrivateSettlementBundleReceiptResponseV1 =
            norito::json::from_slice(&bytes).expect("strict receipt DTO");
        assert_eq!(
            decoded,
            PrivateSettlementBundleReceiptResponseV1::Pending { bundle_id }
        );
        let json: norito::json::Value = norito::json::from_slice(&bytes).expect("JSON");
        assert_eq!(json["value"].as_object().expect("pending value").len(), 1);
    }

    #[cfg(all(
        feature = "app_api",
        feature = "test-network-private-settlement-route-control"
    ))]
    #[test]
    fn state_evidence_retains_one_committed_view_across_publication() {
        let mut chain = activated_private_settlement_chain_for_test();
        let state = Arc::clone(chain.state());
        let captured = state.view();
        let original = private_settlement_test_network_ledger_evidence_at_view(&captured)
            .expect("original active evidence cut");
        assert_eq!(original.0, 2);
        chain.commit_at(3, Vec::new());
        assert_eq!(
            private_settlement_test_network_ledger_evidence_at_view(&captured).unwrap(),
            original,
            "a later publication cannot mix the retained height, ledger and replicated locks"
        );
        let mut current = state.view();
        assert_eq!(
            private_settlement_test_network_ledger_evidence_at_view(&current)
                .unwrap()
                .0,
            3
        );
        assert!(
            active_config_at_view(2, &current).is_err(),
            "a height from another cut is rejected"
        );
        current.nexus.atomic_private_settlement.enabled = false;
        assert!(
            private_settlement_test_network_ledger_evidence_at_view(&current).is_err(),
            "activation must use the supplied view's policy"
        );
    }

    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn public_receipt_preserves_disabled_service_and_digest_errors_without_runtime() {
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let digest = Hash::new(b"unknown receipt bundle");
        let disabled = handler_bundle_receipt(State(app.clone()), Path(digest.to_string())).await;
        assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
        let malformed = handler_bundle_receipt(State(app), Path("invalid-digest".to_owned())).await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn structural_carrier_applies_governed_u16_participant_boundary() {
        let carrier = AbortAtomicPrivateSettlementV1::new(
            abort_carrier_manifest_fixture(),
            PrivateSettlementAbortReasonV1::ParticipantRejected,
        );
        let carrier = ExactPrivateSettlementCarrierV1::Abort(&carrier);
        let exact_participant_bound: u16 = 2;

        assert!(carrier.is_structurally_admissible(10, exact_participant_bound));
        assert!(!carrier.is_structurally_admissible(10, exact_participant_bound - 1));
    }

    #[test]
    fn phase_certificate_acknowledgement_is_monotonic() {
        assert!(phase_certificate_acknowledges_lifecycle_v1(
            PrivateSettlementPhaseV1::Prepare,
            PrivateSettlementSidecarLifecycleV1::Prepared,
        ));
        assert!(phase_certificate_acknowledges_lifecycle_v1(
            PrivateSettlementPhaseV1::Prepare,
            PrivateSettlementSidecarLifecycleV1::CommitCertified,
        ));
        assert!(!phase_certificate_acknowledges_lifecycle_v1(
            PrivateSettlementPhaseV1::Prepare,
            PrivateSettlementSidecarLifecycleV1::Audited,
        ));
        assert!(phase_certificate_acknowledges_lifecycle_v1(
            PrivateSettlementPhaseV1::Commit,
            PrivateSettlementSidecarLifecycleV1::CommitCertified,
        ));
        assert!(!phase_certificate_acknowledges_lifecycle_v1(
            PrivateSettlementPhaseV1::Commit,
            PrivateSettlementSidecarLifecycleV1::Prepared,
        ));
    }

    #[test]
    fn digest_path_segments_require_canonical_lowercase_hex() {
        let digest = Hash::new(b"canonical private settlement digest");
        let canonical = digest.to_string();
        assert_eq!(parse_digest(&canonical).expect("canonical digest"), digest);

        for alias in [
            canonical.to_ascii_uppercase(),
            format!("0x{canonical}"),
            format!(" {canonical}"),
            format!("{canonical} "),
        ] {
            assert!(
                parse_digest(&alias).is_err(),
                "non-canonical digest alias must fail: {alias:?}"
            );
        }
    }
}
