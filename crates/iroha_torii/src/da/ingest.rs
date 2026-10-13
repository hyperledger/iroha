//! Data availability ingest handlers for Torii.

#![allow(clippy::redundant_pub_crate)]
use super::persistence::{ReceiptInsertOutcome, receipt_signature_placeholder};
use super::rs16::{
    MAX_CANONICAL_PAYLOAD_BYTES, MAX_CHUNK_SIZE_BYTES, MAX_DATA_CHUNKS, MAX_DATA_SHARDS,
    MAX_PARITY_SHARDS, MAX_ROW_PARITY_SOURCE_STRIPES, MAX_ROW_PARITY_STRIPES, MIN_CHUNK_SIZE_BYTES,
    build_chunk_commitments, validate_erasure_work_budget,
};
use super::{
    DaIngestAdmissionSnapshot, DaSpoolAction, DaSpoolActionOutput, DaSpoolBatch,
    DaSpoolBatchReport, persistence, storage_class_label, taikai, taikai::taikai_ingest,
};
use crate::{
    SharedAppState, panic_recovery,
    routing::MaybeTelemetry,
    sorafs::api::ResponseError,
    utils::{self, ResponseFormat},
};
use axum::{
    extract::{Extension, Path as AxumPath, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blake3::{Hasher as Blake3Hasher, hash as blake3_hash};
use eyre::{WrapErr, eyre};
use flate2::read::{DeflateDecoder, GzDecoder};
use iroha_config::parameters::actual::{DaReplicationPolicy, Nexus as ConfigNexus};
use iroha_core::da::{
    LaneEpoch, ReplayCache, ReplayFingerprint, ReplayInsertOutcome, ReplayKey, ReplayReservation,
};
use iroha_crypto::{
    Hash, KeyPair, Signature,
    encryption::{ChaCha20Poly1305, SymmetricEncryptor},
};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    da::{
        commitment::{DaCommitmentRecord, DaProofScheme},
        manifest::ChunkRole,
        pin_intent::DaPinIntent,
        prelude::*,
    },
    sorafs::pin_registry::{ManifestDigest, StorageClass},
    taikai::TaikaiSegmentWindow,
};
use iroha_logger::{error, warn};
use iroha_model_base::topology::LaneId;
use iroha_torii_shared::da::sampling::compute_sample_window;
#[cfg(feature = "ipa-commitment")]
use iroha_zkp_halo2::pallas::{
    Params as IpaCurveParams, Polynomial as IpaPolynomial, Scalar as IpaScalar,
};
#[cfg(test)]
use norito::json::Map;
use norito::{
    decode_from_bytes,
    json::{self, JsonSerialize},
    to_bytes,
};
use sorafs_car::{
    ChunkStore, build_plan_from_da_manifest, fetch_plan::try_chunk_fetch_plan_to_json,
};
use sorafs_chunker::ChunkProfile;
use sorafs_manifest::{
    BLAKE3_256_MULTIHASH_CODE, ChunkingProfileV1,
    pdp::{PdpCommitmentV1, PdpMerkleTreeV1},
};
use std::{
    borrow::{Cow, ToOwned},
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zstd::stream::read::Decoder as ZstdDecoder;
const HEADER_SORA_PDP_COMMITMENT: &str = "sora-pdp-commitment";
const META_DA_REGISTRY_ALIAS: &str = "da.registry.alias";
const META_DA_REGISTRY_OWNER: &str = "da.registry.owner";
const RETIRED_TAIKAI_CACHE_HINT_KEY: &str = "taikai.cache_hint";
const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;
const SECS_PER_MONTH: u64 = 30 * 24 * 60 * 60;
struct FreshReplayReservation {
    cache: Arc<ReplayCache>,
    reservation: Option<ReplayReservation>,
    committed: bool,
}
struct PendingTaikaiLineageCommit {
    guard: taikai_ingest::TrmLineageGuard,
    segment_window: TaikaiSegmentWindow,
    manifest_digest_hex: String,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    storage_ticket: StorageTicketId,
    fingerprint: ReplayFingerprint,
}
impl PendingTaikaiLineageCommit {
    fn stage(&mut self) -> Result<(), String> {
        self.guard
            .persist_lineage_hint(
                self.lane_id,
                self.epoch,
                self.sequence,
                &self.storage_ticket,
                &self.fingerprint,
            )
            .map_err(|(_, message)| message)?;
        self.guard
            .stage_ingest(
                self.segment_window.clone(),
                &self.manifest_digest_hex,
                self.lane_id,
                self.epoch,
                self.sequence,
                &self.storage_ticket,
                &self.fingerprint,
            )
            .map_err(|(_, message)| message)
    }

    fn recover(&mut self, receipt_log: &persistence::DaReceiptLog) -> Result<(), String> {
        self.guard
            .recover_pending(receipt_log)
            .map_err(|(_, message)| message)
    }

    fn discard(&mut self) -> Result<(), String> {
        self.guard.discard_pending().map_err(|(_, message)| message)
    }
}
impl FreshReplayReservation {
    fn new(cache: Arc<ReplayCache>, reservation: ReplayReservation) -> Self {
        Self {
            cache,
            reservation: Some(reservation),
            committed: false,
        }
    }
    fn commit(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            let _ = self.cache.commit_reservation(&reservation);
        }
        self.committed = true;
    }
    fn resolve_receipt_outcome(&mut self, outcome: &ReceiptInsertOutcome) {
        if matches!(
            outcome,
            ReceiptInsertOutcome::Stored { .. } | ReceiptInsertOutcome::Duplicate { .. }
        ) {
            self.commit();
        }
    }
}
impl Drop for FreshReplayReservation {
    fn drop(&mut self) {
        if !self.committed
            && let Some(reservation) = self.reservation.take()
        {
            let _ = self.cache.rollback_reservation(reservation);
        }
    }
}
#[cfg(test)]
mod fresh_replay_reservation_tests {
    use super::*;
    use crate::da::DaSpooler;
    use iroha_core::da::ReplayCacheConfig;

    #[test]
    fn reservation_rolls_back_uncommitted_entries_and_retains_committed_entries() {
        let cache = Arc::new(ReplayCache::new(ReplayCacheConfig::new()));
        let key = ReplayKey::new(
            LaneEpoch::new(LaneId::SINGLE, 19),
            0,
            ReplayFingerprint::from_hash(blake3_hash(b"taikai-replay-reservation")),
        );
        let now = Instant::now();
        let (first_outcome, first_reservation) = cache.reserve(key, now);
        assert!(matches!(first_outcome, ReplayInsertOutcome::Fresh { .. }));
        let first_reservation = first_reservation.expect("fresh outcome carries reservation");
        {
            let _reservation = FreshReplayReservation::new(Arc::clone(&cache), first_reservation);
        }
        let (second_outcome, second_reservation) = cache.reserve(key, now);
        assert!(matches!(second_outcome, ReplayInsertOutcome::Fresh { .. }));
        let second_reservation = second_reservation.expect("fresh outcome carries reservation");
        {
            let mut reservation =
                FreshReplayReservation::new(Arc::clone(&cache), second_reservation);
            reservation.commit();
        }
        assert!(matches!(
            cache.insert(key, now),
            ReplayInsertOutcome::Duplicate { .. }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_reservation_survives_submitter_cancellation() {
        let cache = Arc::new(ReplayCache::new(ReplayCacheConfig::new()));
        let key = ReplayKey::new(
            LaneEpoch::new(LaneId::SINGLE, 20),
            0,
            ReplayFingerprint::from_hash(blake3_hash(b"taikai-cancelled-submitter")),
        );
        let now = Instant::now();
        let (outcome, reservation) = cache.reserve(key, now);
        assert!(matches!(outcome, ReplayInsertOutcome::Fresh { .. }));
        let mut replay_reservation = FreshReplayReservation::new(
            Arc::clone(&cache),
            reservation.expect("fresh outcome carries reservation"),
        );

        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release_for_action = Arc::clone(&release);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let mut batch = DaSpoolBatch::new();
        batch.push(DaSpoolAction::new("blocked_artifact", move || {
            let _ = started_tx.send(());
            let (lock, wake) = &*release_for_action;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = wake.wait(released).expect("release wait");
            }
            Ok(DaSpoolActionOutput::None)
        }));
        batch.push_commit(DaSpoolAction::new("receipt_log", move || {
            let outcome = ReceiptInsertOutcome::Stored {
                cursor_advanced: true,
            };
            replay_reservation.resolve_receipt_outcome(&outcome);
            let _ = finished_tx.send(());
            Ok(DaSpoolActionOutput::ReceiptOutcome(outcome))
        }));
        let spooler = DaSpooler::spawn(
            std::num::NonZeroUsize::new(1).expect("non-zero queue"),
            std::num::NonZeroUsize::new(1).expect("non-zero batch"),
            MaybeTelemetry::disabled(),
        );
        let submitter = Arc::clone(&spooler);
        let submit = tokio::spawn(async move { submitter.submit(batch).await });
        started_rx.await.expect("worker started artifact action");

        submit.abort();
        assert!(
            submit
                .await
                .expect_err("submitter must be cancelled")
                .is_cancelled()
        );
        assert!(matches!(
            cache.insert(key, now),
            ReplayInsertOutcome::InFlight { .. }
        ));

        let (lock, wake) = &*release;
        *lock.lock().expect("release lock") = true;
        wake.notify_all();
        tokio::time::timeout(Duration::from_secs(2), finished_rx)
            .await
            .expect("worker must finish after release")
            .expect("commit action must signal completion");
        assert!(matches!(
            cache.insert(key, now),
            ReplayInsertOutcome::Duplicate { .. }
        ));
    }
}
#[derive(Debug)]
struct CanonicalPayload<'a> {
    bytes: Cow<'a, [u8]>,
}
impl CanonicalPayload<'_> {
    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    fn into_vec(self) -> Vec<u8> {
        self.bytes.into_owned()
    }
}
async fn run_da_ingest_compute_job<T, F>(
    limiter: Arc<tokio::sync::Semaphore>,
    job: F,
) -> Result<T, (StatusCode, String)>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, (StatusCode, String)> + Send + 'static,
{
    let permit = limiter.try_acquire_owned().map_err(|err| match err {
        tokio::sync::TryAcquireError::Closed => (
            StatusCode::SERVICE_UNAVAILABLE,
            "DA ingest compute limiter is closed".to_owned(),
        ),
        tokio::sync::TryAcquireError::NoPermits => (
            StatusCode::SERVICE_UNAVAILABLE,
            "DA ingest compute capacity is saturated".to_owned(),
        ),
    })?;
    panic_recovery::join_recoverable(panic_recovery::spawn_blocking_recoverable(move || {
        let result = job();
        // The owned permit lives in the physical worker. Dropping the request
        // future only detaches this task; capacity is not released until the
        // blocking computation has actually stopped.
        drop(permit);
        result
    }))
    .await
    .map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DA ingest compute worker failed: {err}"),
        )
    })?
}
struct DaManifestComputeArtifacts {
    server_assignment: persistence::DaIngestServerAssignmentV1,
    proof_scheme: DaProofScheme,
    canonical_payload: Vec<u8>,
    chunk_store: ChunkStore,
    manifest: ManifestArtifacts,
    enforced_retention: RetentionPolicy,
    retention_mismatch: bool,
    taikai_ssm_payload: Option<Vec<u8>>,
    taikai_trm_payload: Option<Vec<u8>>,
    queued_at_secs: u64,
}

struct DaManifestPreparedRequest {
    canonical_payload: Vec<u8>,
    chunk_store: ChunkStore,
}

fn admission_snapshot_for_request(
    app: &crate::AppState,
    owner: &AccountId,
    lane_id: LaneId,
    epoch: u64,
) -> Result<DaIngestAdmissionSnapshot, (StatusCode, String)> {
    let snapshot = super::committed_da_ingest_admission_snapshot(&app.state).map_err(|error| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("committed DA ingest admission policy is invalid: {error}"),
        )
    })?;
    if !snapshot.is_configured() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "DA ingest is disabled until governance installs an admission policy".to_owned(),
        ));
    }
    if !snapshot.authorizes(owner, lane_id, epoch) {
        return Err((
            StatusCode::FORBIDDEN,
            "authenticated account is not an authorised producer for this active DA lane/epoch"
                .to_owned(),
        ));
    }
    Ok(snapshot)
}

fn reconcile_da_replay_state(
    snapshot: &DaIngestAdmissionSnapshot,
    receipt_log: &super::DaReceiptLog,
    replay_cache: &ReplayCache,
) -> Result<(), String> {
    let retired = receipt_log
        .retain_lane_epochs(|lane_epoch| snapshot.retains(lane_epoch.lane_id, lane_epoch.epoch))
        .map_err(|error| format!("failed to retire superseded DA replay windows: {error}"))?;
    for lane_epoch in retired {
        replay_cache.clear_lane_epoch(lane_epoch);
    }
    Ok(())
}

fn metadata_for_server_assignment(
    request: &DaIngestRequest,
    transformed_metadata: &ExtraMetadata,
    enforced_retention: &RetentionPolicy,
) -> Result<(ExtraMetadata, Option<Vec<u8>>, Option<Vec<u8>>), (StatusCode, String)> {
    let mut metadata = transformed_metadata.clone();
    let taikai_ssm_payload = taikai_ingest::take_ssm_entry(&mut metadata)?;
    if matches!(request.blob_class, BlobClass::TaikaiSegment)
        && taikai_ssm_payload.is_some()
        && request.norito_manifest.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Taikai ingest requests carrying `taikai.ssm` require a caller-supplied `norito_manifest`"
                .to_owned(),
        ));
    }
    let taikai_trm_payload = taikai_ingest::take_trm_entry(&mut metadata)?;
    let taikai_availability = if matches!(request.blob_class, BlobClass::TaikaiSegment) {
        taikai::taikai_availability_from_metadata(&request.metadata, taikai_trm_payload.as_deref())?
    } else {
        None
    };
    if matches!(request.blob_class, BlobClass::TaikaiSegment) {
        taikai::apply_taikai_ingest_tags(
            &mut metadata,
            taikai_availability,
            enforced_retention,
            request.total_size,
        );
    }
    Ok((metadata, taikai_ssm_payload, taikai_trm_payload))
}

fn validate_assigned_transformed_metadata(
    request: &DaIngestRequest,
    assigned: &ExtraMetadata,
) -> Result<(), (StatusCode, String)> {
    if request.metadata.items.len() != assigned.items.len() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "durable DA ingest assignment metadata count does not match the signed request"
                .to_owned(),
        ));
    }
    for (submitted, stored) in request.metadata.items.iter().zip(&assigned.items) {
        if submitted.key != stored.key || submitted.visibility != stored.visibility {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "durable DA ingest assignment metadata identity does not match the signed request"
                    .to_owned(),
            ));
        }
        match submitted.visibility {
            MetadataVisibility::Public => {
                if submitted != stored {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "durable DA ingest assignment changed public metadata entry `{}`",
                            submitted.key
                        ),
                    ));
                }
            }
            MetadataVisibility::GovernanceOnly => match &submitted.encryption {
                MetadataEncryption::ChaCha20Poly1305(_) => {
                    if submitted != stored {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!(
                                "durable DA ingest assignment changed caller-encrypted metadata entry `{}`",
                                submitted.key
                            ),
                        ));
                    }
                }
                MetadataEncryption::None => {
                    if !matches!(stored.encryption, MetadataEncryption::ChaCha20Poly1305(_)) {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!(
                                "durable DA ingest assignment did not encrypt metadata entry `{}`",
                                submitted.key
                            ),
                        ));
                    }
                }
            },
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn recover_da_manifest_artifacts(
    request: &DaIngestRequest,
    canonical_payload: &[u8],
    chunk_store: &ChunkStore,
    assignment: &persistence::DaIngestServerAssignmentV1,
    chunking_observer: Option<&dyn Fn(Duration)>,
) -> Result<DaManifestComputeArtifacts, (StatusCode, String)> {
    if assignment.queued_at_secs == 0
        || assignment.retention_mismatch
            != (assignment.enforced_retention != request.retention_policy)
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "durable DA ingest assignment contains inconsistent server policy fields".to_owned(),
        ));
    }
    validate_assigned_transformed_metadata(request, &assignment.transformed_metadata)?;
    let (metadata, taikai_ssm_payload, taikai_trm_payload) = metadata_for_server_assignment(
        request,
        &assignment.transformed_metadata,
        &assignment.enforced_retention,
    )?;
    let manifest =
        decode_from_bytes::<DaManifestV1>(&assignment.manifest_bytes).map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to decode durable assigned DA manifest: {err}"),
            )
        })?;
    let canonical_manifest = to_bytes(&manifest).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to re-encode durable assigned DA manifest: {err}"),
        )
    })?;
    if canonical_manifest != assignment.manifest_bytes {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "durable assigned DA manifest is not canonically encoded".to_owned(),
        ));
    }
    let blob_hash = BlobDigest::from_hash(*chunk_store.payload_digest());
    let chunk_root = BlobDigest::new(*chunk_store.por_tree().root());
    let (total_stripes, shards_per_stripe) =
        manifest_stripe_layout_fields(chunk_store.chunks().len(), &request.erasure_profile)?;
    let chunking_started = Instant::now();
    let chunk_commitments = build_chunk_commitments(request, chunk_store, canonical_payload)?;
    if let Some(observer) = chunking_observer {
        observer(chunking_started.elapsed());
    }
    verify_manifest_against_request(
        request,
        &manifest,
        &assignment.enforced_retention,
        &metadata,
        &chunk_commitments,
        blob_hash,
        chunk_root,
        &manifest.rent_quote,
    )
    .map_err(|(_, message)| (StatusCode::INTERNAL_SERVER_ERROR, message))?;
    if manifest.total_stripes != total_stripes
        || manifest.shards_per_stripe != shards_per_stripe
        || manifest.ipa_commitment != ipa_commitment_from_chunks(&chunk_commitments)?
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "durable assigned DA manifest has inconsistent stripe or IPA commitment fields"
                .to_owned(),
        ));
    }
    let expected_issued_at = if matches!(request.blob_class, BlobClass::TaikaiSegment) {
        request
            .norito_manifest
            .as_deref()
            .map(decode_from_bytes::<DaManifestV1>)
            .transpose()
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to recheck submitted Taikai manifest: {err}"),
                )
            })?
            .map_or(assignment.queued_at_secs, |manifest| {
                manifest.issued_at_unix
            })
    } else {
        assignment.queued_at_secs
    };
    if manifest.issued_at_unix != expected_issued_at {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "durable assigned DA manifest has an inconsistent issuance time".to_owned(),
        ));
    }
    let mut fingerprint_template = manifest.clone();
    fingerprint_template.storage_ticket = StorageTicketId::default();
    fingerprint_template.issued_at_unix = 0;
    let fingerprint = manifest_fingerprint(&fingerprint_template)?;
    if manifest.storage_ticket.as_bytes() != fingerprint.as_bytes() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "durable assigned DA manifest storage ticket is not its canonical fingerprint"
                .to_owned(),
        ));
    }
    let (rent_gib, rent_months) =
        rent_usage_from_request(request.total_size, &assignment.enforced_retention)?;
    let manifest_hash = BlobDigest::from_hash(blake3_hash(&assignment.manifest_bytes));
    Ok(DaManifestComputeArtifacts {
        server_assignment: assignment.clone(),
        proof_scheme: assignment.proof_scheme,
        canonical_payload: canonical_payload.to_vec(),
        chunk_store: chunk_store.clone(),
        manifest: ManifestArtifacts {
            storage_ticket: manifest.storage_ticket,
            manifest,
            encoded: assignment.manifest_bytes.clone(),
            manifest_hash,
            blob_hash,
            chunk_root,
            fingerprint,
            rent_gib,
            rent_months,
        },
        enforced_retention: assignment.enforced_retention.clone(),
        retention_mismatch: assignment.retention_mismatch,
        taikai_ssm_payload,
        taikai_trm_payload,
        queued_at_secs: assignment.queued_at_secs,
    })
}

fn prepare_da_manifest_request(
    request: &DaIngestRequest,
) -> Result<DaManifestPreparedRequest, (StatusCode, String)> {
    request.verify_signatures().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "DA ingest request signature is invalid".to_owned(),
        )
    })?;
    let canonical = normalize_payload(request)?;
    validate_request(request, canonical.as_slice())
        .map_err(|(status, message)| (status, message.to_owned()))?;
    if request
        .metadata
        .items
        .iter()
        .any(|entry| entry.key == RETIRED_TAIKAI_CACHE_HINT_KEY)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "retired Taikai metadata field `taikai.cache_hint` is not accepted in V1".to_owned(),
        ));
    }
    let chunk_store = try_build_chunk_store(request, canonical.as_slice())?;
    Ok(DaManifestPreparedRequest {
        canonical_payload: canonical.into_vec(),
        chunk_store,
    })
}

#[allow(clippy::too_many_arguments)]
fn compute_da_manifest_candidate(
    request: &DaIngestRequest,
    prepared: DaManifestPreparedRequest,
    nexus: &ConfigNexus,
    committed_height: u64,
    governance_metadata_key: Option<&[u8; 32]>,
    governance_metadata_key_label: Option<&str>,
    replication_policy: &DaReplicationPolicy,
    rent_policy: &DaRentPolicyV1,
    server_assignment_signer: &KeyPair,
    chunking_observer: Option<&dyn Fn(Duration)>,
) -> Result<DaManifestComputeArtifacts, (StatusCode, String)> {
    let DaManifestPreparedRequest {
        canonical_payload,
        chunk_store,
    } = prepared;
    let proof_scheme = lane_proof_scheme(nexus, request.lane_id, committed_height)?;
    let transformed_metadata = encrypt_governance_metadata(
        &request.metadata,
        governance_metadata_key,
        governance_metadata_key_label,
    )?;
    let mut metadata = transformed_metadata.clone();
    let taikai_ssm_payload = taikai_ingest::take_ssm_entry(&mut metadata)?;
    if matches!(request.blob_class, BlobClass::TaikaiSegment)
        && taikai_ssm_payload.is_some()
        && request.norito_manifest.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Taikai ingest requests carrying `taikai.ssm` require a caller-supplied `norito_manifest`"
                .to_owned(),
        ));
    }
    let taikai_trm_payload = taikai_ingest::take_trm_entry(&mut metadata)?;
    let taikai_availability = if matches!(request.blob_class, BlobClass::TaikaiSegment) {
        taikai::taikai_availability_from_metadata(&request.metadata, taikai_trm_payload.as_deref())?
    } else {
        None
    };
    let (expected_retention, retention_mismatch) = replication_policy.enforce(
        request.blob_class,
        taikai_availability,
        &request.retention_policy,
    );
    let enforced_retention = expected_retention.clone();
    if matches!(request.blob_class, BlobClass::TaikaiSegment) {
        taikai::apply_taikai_ingest_tags(
            &mut metadata,
            taikai_availability,
            &enforced_retention,
            request.total_size,
        );
    }
    let queued_at_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let manifest = resolve_manifest_with_observer(
        request,
        &chunk_store,
        canonical_payload.as_slice(),
        &metadata,
        &enforced_retention,
        queued_at_secs,
        rent_policy,
        chunking_observer,
    )?;
    let candidate = persistence::DaIngestServerAssignmentV1::try_new(
        request,
        queued_at_secs,
        transformed_metadata,
        proof_scheme,
        (enforced_retention.clone(), retention_mismatch),
        manifest.encoded.clone(),
        server_assignment_signer,
    )
    .map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to attest DA ingest server assignment: {err}"),
        )
    })?;
    Ok(DaManifestComputeArtifacts {
        server_assignment: candidate,
        proof_scheme,
        canonical_payload,
        chunk_store,
        manifest,
        enforced_retention,
        retention_mismatch,
        taikai_ssm_payload,
        taikai_trm_payload,
        queued_at_secs,
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn compute_da_manifest_artifacts(
    request: &DaIngestRequest,
    nexus: &ConfigNexus,
    committed_height: u64,
    governance_metadata_key: Option<&[u8; 32]>,
    governance_metadata_key_label: Option<&str>,
    replication_policy: &DaReplicationPolicy,
    rent_policy: &DaRentPolicyV1,
    spool_dir: &Path,
    server_assignment_signer: &KeyPair,
    chunking_observer: Option<&dyn Fn(Duration)>,
) -> Result<DaManifestComputeArtifacts, (StatusCode, String)> {
    let prepared = prepare_da_manifest_request(request)?;
    if let Some(assignment) = persistence::load_da_ingest_server_assignment(
        spool_dir,
        request,
        server_assignment_signer.public_key(),
    )
    .map_err(|err| {
        (
            if err.kind() == ErrorKind::AlreadyExists {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            format!("failed to recover durable DA ingest server assignment: {err}"),
        )
    })? {
        return recover_da_manifest_artifacts(
            request,
            prepared.canonical_payload.as_slice(),
            &prepared.chunk_store,
            &assignment,
            chunking_observer,
        );
    }
    compute_da_manifest_candidate(
        request,
        prepared,
        nexus,
        committed_height,
        governance_metadata_key,
        governance_metadata_key_label,
        replication_policy,
        rent_policy,
        server_assignment_signer,
        chunking_observer,
    )
}

fn revalidate_da_ingest_lifecycle(
    app: &crate::AppState,
    authenticated_owner: &AccountId,
    request: &DaIngestRequest,
    format: ResponseFormat,
) -> Result<(), ResponseError> {
    let admission_snapshot =
        admission_snapshot_for_request(app, authenticated_owner, request.lane_id, request.epoch)
            .map_err(|(status, message)| {
                ResponseError::from(build_error_response(status, &message, format))
            })?;
    reconcile_da_replay_state(
        &admission_snapshot,
        app.da_receipt_log.as_ref(),
        app.da_replay_cache.as_ref(),
    )
    .map_err(|message| {
        ResponseError::from(build_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &message,
            format,
        ))
    })
}

fn load_da_ingest_server_assignment_for_handler(
    app: &crate::AppState,
    request: &DaIngestRequest,
    format: ResponseFormat,
) -> Result<Option<persistence::DaIngestServerAssignmentV1>, ResponseError> {
    persistence::load_da_ingest_server_assignment(
        &app.da_ingest.manifest_store_dir,
        request,
        app.da_receipt_signer.public_key(),
    )
    .map_err(|err| {
        let status = if err.kind() == ErrorKind::AlreadyExists {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        ResponseError::from(build_error_response(
            status,
            &format!("failed to select durable DA ingest server assignment: {err}"),
            format,
        ))
    })
}

fn da_ingest_assignment_replay_identity(
    assignment: &persistence::DaIngestServerAssignmentV1,
    format: ResponseFormat,
) -> Result<(StorageTicketId, ReplayFingerprint), ResponseError> {
    let manifest =
        decode_from_bytes::<DaManifestV1>(&assignment.manifest_bytes).map_err(|err| {
            ResponseError::from(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to decode selected DA ingest assignment manifest: {err}"),
                format,
            ))
        })?;
    let fingerprint = ReplayFingerprint::from(*manifest.storage_ticket.as_bytes());
    Ok((manifest.storage_ticket, fingerprint))
}

fn adopt_recovered_da_receipt_in_replay_cache(
    replay_cache: &ReplayCache,
    lane_epoch: LaneEpoch,
    sequence: u64,
    fingerprint: ReplayFingerprint,
) -> Result<(), String> {
    let replay_key = ReplayKey::new(lane_epoch, sequence, fingerprint);
    let (outcome, reservation) = replay_cache.reserve(replay_key, Instant::now());
    match outcome {
        ReplayInsertOutcome::Fresh { .. } => {
            let reservation = reservation
                .ok_or_else(|| "fresh recovered DA receipt has no replay reservation".to_owned())?;
            if !replay_cache.commit_reservation(&reservation) {
                return Err(
                    "fresh recovered DA receipt reservation could not be committed".to_owned(),
                );
            }
            Ok(())
        }
        ReplayInsertOutcome::Duplicate { .. } | ReplayInsertOutcome::StaleSequence { .. } => Ok(()),
        ReplayInsertOutcome::SequenceGap { .. }
            if replay_cache.len_for_lane_epoch(lane_epoch) == 0 =>
        {
            replay_cache
                .prime_lane_epoch(lane_epoch, sequence)
                .map_err(|err| format!("failed to prime recovered DA replay floor: {err}"))
        }
        ReplayInsertOutcome::SequenceGap { .. } => {
            Err("recovered DA receipt would skip live replay entries or reservations".to_owned())
        }
        ReplayInsertOutcome::ConflictingFingerprint { .. } => {
            Err("recovered DA receipt conflicts with the replay-cache fingerprint".to_owned())
        }
        ReplayInsertOutcome::InFlight { .. } => {
            Err("recovered DA receipt still has an in-flight replay reservation".to_owned())
        }
        ReplayInsertOutcome::LaneEpochCapacityExceeded { capacity } => Err(format!(
            "recovered DA receipt exceeds replay lane/epoch capacity {capacity}"
        )),
        ReplayInsertOutcome::ReservationCapacityExceeded { capacity } => Err(format!(
            "recovered DA receipt exceeds replay reservation capacity {capacity}"
        )),
    }
}

fn completed_da_ingest_response_if_present(
    app: &crate::AppState,
    telemetry: &MaybeTelemetry,
    request: &DaIngestRequest,
    lane_epoch: LaneEpoch,
    storage_ticket: &StorageTicketId,
    fingerprint: ReplayFingerprint,
    format: ResponseFormat,
) -> Result<Option<Response>, ResponseError> {
    let Some(artifacts) = load_duplicate_da_artifacts_if_receipt_present(
        app.da_receipt_log.as_ref(),
        &app.da_ingest.manifest_store_dir,
        lane_epoch,
        request.sequence,
        storage_ticket,
        fingerprint,
        request,
    )
    .map_err(|err| {
        duplicate_da_artifacts_response_error(
            err,
            "failed to recover durable duplicate DA ingest artifacts",
            format,
        )
    })?
    else {
        return Ok(None);
    };
    adopt_recovered_da_receipt_in_replay_cache(
        app.da_replay_cache.as_ref(),
        lane_epoch,
        request.sequence,
        fingerprint,
    )
    .map_err(|err| {
        ResponseError::from(build_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("failed to reconcile recovered DA replay cache state: {err}"),
            format,
        ))
    })?;
    let (artifacts, finalized) = finalize_duplicate_da_pin_intent(
        &app.da_ingest.manifest_store_dir,
        request,
        lane_epoch,
        fingerprint,
        artifacts,
    )
    .map_err(|err| {
        duplicate_da_artifacts_response_error(err, "failed to finalize DA pin intent", format)
    })?;
    duplicate_da_ingest_response_from_artifacts(
        telemetry,
        lane_epoch,
        request.sequence,
        artifacts,
        finalized,
        format,
    )
    .map(Some)
}

fn preflight_absent_da_replay_slot(
    replay_cache: &ReplayCache,
    request: &DaIngestRequest,
    lane_epoch: LaneEpoch,
    format: ResponseFormat,
) -> Result<Option<Response>, ResponseError> {
    let preflight_fingerprint =
        ReplayFingerprint::from_hash(blake3_hash(&request.signing_digest()));
    let replay_key = ReplayKey::new(lane_epoch, request.sequence, preflight_fingerprint);
    let (outcome, reservation) = replay_cache.reserve(replay_key, Instant::now());
    match outcome {
        ReplayInsertOutcome::Fresh { .. } => {
            let reservation = reservation.expect("fresh replay preflight carries a reservation");
            if !replay_cache.rollback_reservation(reservation) {
                return Err(ResponseError::from(build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to roll back temporary DA replay-slot preflight",
                    format,
                )));
            }
            Ok(None)
        }
        ReplayInsertOutcome::StaleSequence { highest_observed } => {
            let message = format!(
                "sequence {} is too far behind; highest observed is {}",
                request.sequence, highest_observed
            );
            Ok(Some(build_error_response(
                StatusCode::CONFLICT,
                &message,
                format,
            )))
        }
        ReplayInsertOutcome::SequenceGap {
            expected_next,
            observed,
        } => {
            let message =
                format!("sequence {observed} skips required next DA sequence {expected_next}");
            Ok(Some(build_error_response(
                StatusCode::CONFLICT,
                &message,
                format,
            )))
        }
        ReplayInsertOutcome::LaneEpochCapacityExceeded { capacity } => {
            let message = format!("global DA replay lane/epoch capacity ({capacity}) is exhausted");
            Ok(Some(build_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &message,
                format,
            )))
        }
        ReplayInsertOutcome::ReservationCapacityExceeded { capacity } => {
            let message =
                format!("DA replay in-flight reservation capacity ({capacity}) is exhausted");
            Ok(Some(build_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &message,
                format,
            )))
        }
        ReplayInsertOutcome::Duplicate { .. }
        | ReplayInsertOutcome::ConflictingFingerprint { .. }
        | ReplayInsertOutcome::InFlight { .. } => Err(ResponseError::from(build_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DA replay cache contains a slot with no durable server assignment",
            format,
        ))),
    }
}

/// HTTP handler for `/v1/da/ingest`.
pub async fn handler_post_da_ingest(
    State(app): State<SharedAppState>,
    Extension(verified_principal): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    headers: HeaderMap,
    utils::extractors::JsonOnly(request): utils::extractors::JsonOnly<DaIngestRequest>,
) -> Result<Response, ResponseError> {
    let format = utils::negotiate_response_format(headers.get(axum::http::header::ACCEPT))
        .map_err(ResponseError::from)?;
    reject_emergency_fast_da_service(app.as_ref(), format)?;
    let authenticated_owner =
        authenticate_da_ingest_request(&request, &verified_principal, app.state.network_id_ref())
            .map_err(|(status, message)| {
            ResponseError::from(build_error_response(status, message, format))
        })?;
    let telemetry = app.telemetry_handle();
    let cluster_label = app
        .da_ingest
        .telemetry_cluster_label
        .as_deref()
        .unwrap_or("default");
    validate_request_shape(&request).map_err(|(status, message)| {
        ResponseError::from(build_error_response(status, message, format))
    })?;
    admission_snapshot_for_request(
        app.as_ref(),
        &authenticated_owner,
        request.lane_id,
        request.epoch,
    )
    .map_err(|(status, message)| {
        ResponseError::from(build_error_response(status, &message, format))
    })?;
    let compute_request = request;
    let (request, prepared) =
        run_da_ingest_compute_job(Arc::clone(&app.da_ingest_compute_inflight), move || {
            let prepared = prepare_da_manifest_request(&compute_request)?;
            Ok((compute_request, prepared))
        })
        .await
        .map_err(|(status, message)| {
            ResponseError::from(build_error_response(status, &message, format))
        })?;
    debug_assert_eq!(request.owner, authenticated_owner);
    let lane_epoch = LaneEpoch::new(request.lane_id, request.epoch);
    let initial_selection = {
        let replay_lifecycle_guard = app.da_replay_lifecycle_lock.lock();
        revalidate_da_ingest_lifecycle(app.as_ref(), &authenticated_owner, &request, format)?;
        if let Some(assignment) =
            load_da_ingest_server_assignment_for_handler(app.as_ref(), &request, format)?
        {
            let (storage_ticket, fingerprint) =
                da_ingest_assignment_replay_identity(&assignment, format)?;
            if let Some(response) = completed_da_ingest_response_if_present(
                app.as_ref(),
                &telemetry,
                &request,
                lane_epoch,
                &storage_ticket,
                fingerprint,
                format,
            )? {
                return Ok(response);
            }
            let replay_key = ReplayKey::new(lane_epoch, request.sequence, fingerprint);
            let (outcome, fresh_reservation) =
                app.da_replay_cache.reserve(replay_key, Instant::now());
            let replay_reservation = fresh_reservation.map(|reservation| {
                FreshReplayReservation::new(Arc::clone(&app.da_replay_cache), reservation)
            });
            if matches!(outcome, ReplayInsertOutcome::Fresh { .. }) {
                let persisted = persistence::load_or_create_da_ingest_server_assignment(
                    &app.da_ingest.manifest_store_dir,
                    &request,
                    app.da_receipt_signer.public_key(),
                    &assignment,
                )
                .map_err(|err| {
                    let status = if err.kind() == ErrorKind::AlreadyExists {
                        StatusCode::CONFLICT
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    };
                    ResponseError::from(build_error_response(
                        status,
                        &format!("failed to recover durable DA ingest server assignment: {err}"),
                        format,
                    ))
                })?;
                if persisted != assignment {
                    return Err(ResponseError::from(build_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "durable DA ingest assignment changed during recovery",
                        format,
                    )));
                }
            }
            drop(replay_lifecycle_guard);
            Some((assignment, fingerprint, outcome, replay_reservation))
        } else {
            if let Some(response) = preflight_absent_da_replay_slot(
                app.da_replay_cache.as_ref(),
                &request,
                lane_epoch,
                format,
            )? {
                return Ok(response);
            }
            drop(replay_lifecycle_guard);
            None
        }
    };

    let (request, computed, outcome, mut replay_reservation, fingerprint) =
        if let Some((assignment, fingerprint, outcome, replay_reservation)) = initial_selection {
            let compute_telemetry = telemetry.clone();
            let (request, computed) =
                run_da_ingest_compute_job(Arc::clone(&app.da_ingest_compute_inflight), move || {
                    let chunking_observer = |elapsed: Duration| {
                        record_da_chunking_metrics(&compute_telemetry, elapsed);
                    };
                    let recovered = recover_da_manifest_artifacts(
                        &request,
                        prepared.canonical_payload.as_slice(),
                        &prepared.chunk_store,
                        &assignment,
                        Some(&chunking_observer),
                    )?;
                    Ok((request, recovered))
                })
                .await
                .map_err(|(status, message)| {
                    ResponseError::from(build_error_response(status, &message, format))
                })?;
            (request, computed, outcome, replay_reservation, fingerprint)
        } else {
            let nexus = app.state.nexus_snapshot();
            let committed_height = u64::try_from(app.state.committed_height()).unwrap_or(u64::MAX);
            let governance_metadata_key = app.da_ingest.governance_metadata_key;
            let governance_metadata_key_label = app.da_ingest.governance_metadata_key_label.clone();
            let replication_policy = app.da_ingest.replication_policy.clone();
            let rent_policy = app.da_ingest.rent_policy.clone();
            let server_assignment_signer = app.da_receipt_signer.clone();
            let compute_telemetry = telemetry.clone();
            let (request, candidate_result) =
                run_da_ingest_compute_job(Arc::clone(&app.da_ingest_compute_inflight), move || {
                    let chunking_observer = |elapsed: Duration| {
                        record_da_chunking_metrics(&compute_telemetry, elapsed);
                    };
                    let candidate_result = compute_da_manifest_candidate(
                        &request,
                        prepared,
                        &nexus,
                        committed_height,
                        governance_metadata_key.as_ref(),
                        governance_metadata_key_label.as_deref(),
                        &replication_policy,
                        &rent_policy,
                        &server_assignment_signer,
                        Some(&chunking_observer),
                    );
                    Ok((request, candidate_result))
                })
                .await
                .map_err(|(status, message)| {
                    ResponseError::from(build_error_response(status, &message, format))
                })?;

            let replay_lifecycle_guard = app.da_replay_lifecycle_lock.lock();
            revalidate_da_ingest_lifecycle(app.as_ref(), &authenticated_owner, &request, format)?;
            let selected_assignment =
                match load_da_ingest_server_assignment_for_handler(app.as_ref(), &request, format)?
                {
                    Some(assignment) => assignment,
                    None => match &candidate_result {
                        Ok(computed) => computed.server_assignment.clone(),
                        Err((status, message)) => {
                            return Err(ResponseError::from(build_error_response(
                                *status, message, format,
                            )));
                        }
                    },
                };
            let (storage_ticket, fingerprint) =
                da_ingest_assignment_replay_identity(&selected_assignment, format)?;
            if let Some(response) = completed_da_ingest_response_if_present(
                app.as_ref(),
                &telemetry,
                &request,
                lane_epoch,
                &storage_ticket,
                fingerprint,
                format,
            )? {
                return Ok(response);
            }
            let replay_key = ReplayKey::new(lane_epoch, request.sequence, fingerprint);
            let (outcome, fresh_reservation) =
                app.da_replay_cache.reserve(replay_key, Instant::now());
            let replay_reservation = fresh_reservation.map(|reservation| {
                FreshReplayReservation::new(Arc::clone(&app.da_replay_cache), reservation)
            });
            if matches!(outcome, ReplayInsertOutcome::Fresh { .. }) {
                let persisted = persistence::load_or_create_da_ingest_server_assignment(
                    &app.da_ingest.manifest_store_dir,
                    &request,
                    app.da_receipt_signer.public_key(),
                    &selected_assignment,
                )
                .map_err(|err| {
                    let status = if err.kind() == ErrorKind::AlreadyExists {
                        StatusCode::CONFLICT
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    };
                    ResponseError::from(build_error_response(
                        status,
                        &format!("failed to publish durable DA ingest server assignment: {err}"),
                        format,
                    ))
                })?;
                if persisted != selected_assignment {
                    return Err(ResponseError::from(build_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "durable DA ingest assignment changed after replay reservation",
                        format,
                    )));
                }
            }
            drop(replay_lifecycle_guard);
            let (request, computed) = match candidate_result {
                Ok(computed) if selected_assignment == computed.server_assignment => {
                    (request, computed)
                }
                Ok(computed) => {
                    let DaManifestComputeArtifacts {
                        canonical_payload,
                        chunk_store,
                        ..
                    } = computed;
                    let compute_telemetry = telemetry.clone();
                    run_da_ingest_compute_job(
                        Arc::clone(&app.da_ingest_compute_inflight),
                        move || {
                            let chunking_observer = |elapsed: Duration| {
                                record_da_chunking_metrics(&compute_telemetry, elapsed);
                            };
                            let recovered = recover_da_manifest_artifacts(
                                &request,
                                canonical_payload.as_slice(),
                                &chunk_store,
                                &selected_assignment,
                                Some(&chunking_observer),
                            )?;
                            Ok((request, recovered))
                        },
                    )
                    .await
                    .map_err(|(status, message)| {
                        ResponseError::from(build_error_response(status, &message, format))
                    })?
                }
                Err(_) => {
                    let compute_telemetry = telemetry.clone();
                    run_da_ingest_compute_job(
                        Arc::clone(&app.da_ingest_compute_inflight),
                        move || {
                            let prepared = prepare_da_manifest_request(&request)?;
                            let chunking_observer = |elapsed: Duration| {
                                record_da_chunking_metrics(&compute_telemetry, elapsed);
                            };
                            let recovered = recover_da_manifest_artifacts(
                                &request,
                                prepared.canonical_payload.as_slice(),
                                &prepared.chunk_store,
                                &selected_assignment,
                                Some(&chunking_observer),
                            )?;
                            Ok((request, recovered))
                        },
                    )
                    .await
                    .map_err(|(status, message)| {
                        ResponseError::from(build_error_response(status, &message, format))
                    })?
                }
            };
            (request, computed, outcome, replay_reservation, fingerprint)
        };
    let DaManifestComputeArtifacts {
        server_assignment: _,
        proof_scheme,
        canonical_payload: canonical,
        chunk_store,
        manifest,
        enforced_retention,
        retention_mismatch,
        mut taikai_ssm_payload,
        mut taikai_trm_payload,
        queued_at_secs,
    } = computed;
    debug_assert_eq!(manifest.fingerprint, fingerprint);
    if retention_mismatch {
        warn!(
            blob_class = ?request.blob_class,
            submitted = ?request.retention_policy,
            expected = ?enforced_retention,
            "overriding DA retention policy to match configured network baseline"
        );
    }
    match outcome {
        ReplayInsertOutcome::Fresh { .. } | ReplayInsertOutcome::Duplicate { .. } => {
            let duplicate = matches!(&outcome, ReplayInsertOutcome::Duplicate { .. });
            record_da_rent_quote_metrics(
                &telemetry,
                cluster_label,
                enforced_retention.storage_class,
                manifest.rent_gib,
                manifest.rent_months,
                &manifest.manifest.rent_quote,
            );
            if duplicate {
                return handle_duplicate_da_ingest(
                    app.as_ref(),
                    &telemetry,
                    &request,
                    &manifest,
                    lane_epoch,
                    format,
                );
            }
            let pin_scope =
                build_da_pin_scope(&request, manifest.storage_ticket, manifest.manifest_hash)
                    .map_err(|(status, message)| {
                        ResponseError::from(build_error_response(status, &message, format))
                    })?;
            let pin_scope_authorization =
                submitted_pin_scope_authorization(&request, pin_scope.clone()).map_err(
                    |(status, message)| {
                        ResponseError::from(build_error_response(status, &message, format))
                    },
                )?;
            let pin_intent = if let Some(authorization) = pin_scope_authorization {
                let candidate = build_da_pin_intent(&request, authorization);
                Some(
                    persistence::select_da_pin_intent_for_persistence(
                        &app.da_ingest.manifest_store_dir,
                        &candidate,
                        request.lane_id,
                        request.epoch,
                        request.sequence,
                        &manifest.storage_ticket,
                        &fingerprint,
                    )
                    .map_err(|err| {
                        let status = if err.kind() == ErrorKind::AlreadyExists {
                            StatusCode::CONFLICT
                        } else {
                            StatusCode::INTERNAL_SERVER_ERROR
                        };
                        ResponseError::from(build_error_response(
                            status,
                            &format!("failed to select durable DA pin intent: {err}"),
                            format,
                        ))
                    })?,
                )
            } else {
                match persistence::load_da_pin_intent(
                    &app.da_ingest.manifest_store_dir,
                    request.lane_id,
                    request.epoch,
                    request.sequence,
                    &manifest.storage_ticket,
                    &fingerprint,
                ) {
                    Ok(existing) => {
                        if existing.pin_scope_authorization.scope != pin_scope {
                            return Ok(build_error_response(
                                StatusCode::CONFLICT,
                                "durable DA pin intent is bound to a different pin scope",
                                format,
                            ));
                        }
                        persistence::validate_da_pin_intent_retry_authorization(
                            &existing,
                            &request.authorization(),
                        )
                        .map_err(|err| {
                            ResponseError::from(build_error_response(
                                StatusCode::CONFLICT,
                                &err.to_string(),
                                format,
                            ))
                        })?;
                        Some(existing)
                    }
                    Err(err) if err.kind() == ErrorKind::NotFound => None,
                    Err(err) => {
                        return Err(ResponseError::from(build_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("failed to recover durable DA pin intent: {err}"),
                            format,
                        )));
                    }
                }
            };
            let replay_reservation = replay_reservation
                .take()
                .expect("fresh replay outcome carries a reservation guard");
            let taikai_stream_label =
                matches!(request.blob_class, BlobClass::TaikaiSegment).then(|| {
                    taikai::stream_label_from_metadata(&request.metadata)
                        .unwrap_or_else(|| taikai_ingest::STREAM_LABEL_FALLBACK.to_string())
                });
            let compute_telemetry = telemetry.clone();
            let (
                request,
                manifest,
                pdp_commitment,
                pdp_commitment_bytes,
                pdp_header_value,
                taikai_artifacts,
            ) = run_da_ingest_compute_job(Arc::clone(&app.da_ingest_compute_inflight), move || {
                let taikai_artifacts = if matches!(request.blob_class, BlobClass::TaikaiSegment) {
                    let chunking_observer = |elapsed: Duration| {
                        record_da_chunking_metrics(&compute_telemetry, elapsed);
                    };
                    match taikai_ingest::build_envelope(
                        &manifest,
                        &chunk_store,
                        canonical.as_slice(),
                        Some(&chunking_observer),
                    ) {
                        Ok(value) => Some(value),
                        Err(err) => return Ok(Err(err)),
                    }
                } else {
                    None
                };
                let pdp_commitment = compute_pdp_commitment(
                    &manifest.manifest_hash,
                    &manifest.manifest,
                    &chunk_store,
                    canonical.as_slice(),
                    queued_at_secs,
                )?;
                let pdp_commitment_bytes = encode_pdp_commitment_bytes(&pdp_commitment)?;
                let pdp_header_value = pdp_commitment_header_value(&pdp_commitment_bytes)?;
                Ok(Ok((
                    request,
                    manifest,
                    pdp_commitment,
                    pdp_commitment_bytes,
                    pdp_header_value,
                    taikai_artifacts,
                )))
            })
            .await
            .map_err(|(status, message)| {
                ResponseError::from(build_error_response(status, &message, format))
            })?
            .map_err(|(status, message)| {
                if let Some(stream_label) = taikai_stream_label.as_deref() {
                    taikai::record_taikai_ingest_error(
                        &telemetry,
                        cluster_label,
                        stream_label,
                        status,
                    );
                }
                ResponseError::from(build_error_response(status, &message, format))
            })?;
            let mut spool_batch = DaSpoolBatch::new();
            {
                let spool_dir = app.da_ingest.manifest_store_dir.clone();
                let encoded = manifest.encoded.clone();
                let storage_ticket = manifest.storage_ticket.clone();
                let lane_id = request.lane_id;
                let epoch = request.epoch;
                let sequence = request.sequence;
                spool_batch.push(DaSpoolAction::new("manifest", move || {
                    persistence::persist_manifest_for_sorafs(
                        &spool_dir,
                        &encoded,
                        lane_id,
                        epoch,
                        sequence,
                        &storage_ticket,
                        &fingerprint,
                    )
                    .map(|_| DaSpoolActionOutput::None)
                    .map_err(|err| err.to_string())
                }));
            }
            {
                let spool_dir = app.da_ingest.manifest_store_dir.clone();
                let pdp_commitment = pdp_commitment.clone();
                let storage_ticket = manifest.storage_ticket.clone();
                let lane_id = request.lane_id;
                let epoch = request.epoch;
                let sequence = request.sequence;
                spool_batch.push(DaSpoolAction::new("pdp_commitment", move || {
                    persistence::persist_pdp_commitment(
                        &spool_dir,
                        &pdp_commitment,
                        lane_id,
                        epoch,
                        sequence,
                        &storage_ticket,
                        &fingerprint,
                    )
                    .map(|_| DaSpoolActionOutput::None)
                    .map_err(|err| err.to_string())
                }));
            }
            let stripe_layout = stripe_layout_from_manifest(&manifest.manifest);
            let receipt = build_receipt(
                &app.da_receipt_signer,
                &request,
                queued_at_secs,
                manifest.blob_hash,
                manifest.chunk_root,
                manifest.manifest_hash,
                manifest.storage_ticket,
                pdp_commitment_bytes.clone(),
                manifest.manifest.rent_quote.clone(),
                stripe_layout,
            )
            .map_err(|(status, message)| {
                ResponseError::from(build_error_response(status, &message, format))
            })?;
            let receipt = persistence::load_or_create_da_ingest_signed_receipt(
                &app.da_ingest.manifest_store_dir,
                &request,
                app.da_receipt_signer.public_key(),
                &receipt,
            )
            .map_err(|err| {
                ResponseError::from(build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to establish durable signed DA receipt assignment: {err}"),
                    format,
                ))
            })?;
            let commitment_record = build_da_commitment_record(
                &request,
                &manifest,
                &enforced_retention,
                &receipt.operator_signature,
                &pdp_commitment_bytes,
                proof_scheme,
            );
            {
                let spool_dir = app.da_ingest.manifest_store_dir.clone();
                let commitment_record = commitment_record.clone();
                let storage_ticket = manifest.storage_ticket.clone();
                let lane_id = request.lane_id;
                let epoch = request.epoch;
                let sequence = request.sequence;
                spool_batch.push(DaSpoolAction::new("commitment_record", move || {
                    persistence::persist_da_commitment_record(
                        &spool_dir,
                        &commitment_record,
                        lane_id,
                        epoch,
                        sequence,
                        &storage_ticket,
                        &fingerprint,
                    )
                    .map(|_| DaSpoolActionOutput::None)
                    .map_err(|err| err.to_string())
                }));
            }
            {
                let spool_dir = app.da_ingest.manifest_store_dir.clone();
                let commitment_record = commitment_record.clone();
                let pdp_commitment_bytes = pdp_commitment_bytes.clone();
                let storage_ticket = manifest.storage_ticket.clone();
                let lane_id = request.lane_id;
                let epoch = request.epoch;
                let sequence = request.sequence;
                spool_batch.push(DaSpoolAction::new("commitment_schedule", move || {
                    persistence::persist_da_commitment_schedule_entry(
                        &spool_dir,
                        &commitment_record,
                        &pdp_commitment_bytes,
                        lane_id,
                        epoch,
                        sequence,
                        &storage_ticket,
                        &fingerprint,
                    )
                    .map(|_| DaSpoolActionOutput::None)
                    .map_err(|err| err.to_string())
                }));
            }
            {
                let spool_dir = app.da_ingest.manifest_store_dir.clone();
                let pin_scope = pin_scope.clone();
                let storage_ticket = manifest.storage_ticket.clone();
                let lane_id = request.lane_id;
                let epoch = request.epoch;
                let sequence = request.sequence;
                spool_batch.push(DaSpoolAction::new("pin_scope", move || {
                    persistence::persist_da_pin_scope(
                        &spool_dir,
                        &pin_scope,
                        lane_id,
                        epoch,
                        sequence,
                        &storage_ticket,
                        &fingerprint,
                    )
                    .map(|_| DaSpoolActionOutput::None)
                    .map_err(|err| err.to_string())
                }));
            }
            if let Some(pin_intent) = pin_intent.as_ref() {
                let spool_dir = app.da_ingest.manifest_store_dir.clone();
                let pin_intent = pin_intent.clone();
                let storage_ticket = manifest.storage_ticket;
                let lane_id = request.lane_id;
                let epoch = request.epoch;
                let sequence = request.sequence;
                spool_batch.push(DaSpoolAction::new("pin_intent", move || {
                    persistence::persist_da_pin_intent(
                        &spool_dir,
                        &pin_intent,
                        lane_id,
                        epoch,
                        sequence,
                        &storage_ticket,
                        &fingerprint,
                    )
                    .map(|_| DaSpoolActionOutput::None)
                    .map_err(|err| err.to_string())
                }));
            }
            let mut taikai_alias_rotation_event = None;
            let mut taikai_lineage_commit = None;
            if let Some(taikai) = taikai_artifacts {
                {
                    let spool_dir = app.da_ingest.manifest_store_dir.clone();
                    let envelope_bytes = taikai.envelope_bytes.clone();
                    let storage_ticket = manifest.storage_ticket.clone();
                    let lane_id = request.lane_id;
                    let epoch = request.epoch;
                    let sequence = request.sequence;
                    spool_batch.push(DaSpoolAction::new("taikai_envelope", move || {
                        taikai_ingest::persist_envelope(
                            &spool_dir,
                            lane_id,
                            epoch,
                            sequence,
                            &storage_ticket,
                            &fingerprint,
                            &envelope_bytes,
                        )
                        .map(|_| DaSpoolActionOutput::None)
                        .map_err(|err| err.to_string())
                    }));
                }
                {
                    let spool_dir = app.da_ingest.manifest_store_dir.clone();
                    let indexes_json = taikai.indexes_json.clone();
                    let storage_ticket = manifest.storage_ticket.clone();
                    let lane_id = request.lane_id;
                    let epoch = request.epoch;
                    let sequence = request.sequence;
                    spool_batch.push(DaSpoolAction::new("taikai_indexes", move || {
                        taikai_ingest::persist_indexes(
                            &spool_dir,
                            lane_id,
                            epoch,
                            sequence,
                            &storage_ticket,
                            &fingerprint,
                            &indexes_json,
                        )
                        .map(|_| DaSpoolActionOutput::None)
                        .map_err(|err| err.to_string())
                    }));
                }
                let ssm_bytes = taikai_ssm_payload.take().ok_or_else(|| {
                    build_error_response(
                        StatusCode::BAD_REQUEST,
                        "metadata entry `taikai.ssm` is required for Taikai segments",
                        format,
                    )
                })?;
                let ssm_outcome = taikai::validate_taikai_ssm(
                    &ssm_bytes,
                    (&manifest.manifest_hash, &taikai.car_digest),
                    &taikai.envelope_bytes,
                    taikai.telemetry.segment_sequence,
                    &app.sorafs_alias_cache_policy,
                    app.sorafs_admission
                        .as_deref()
                        .and_then(crate::sorafs::AdmissionRegistry::council_policy)
                        .as_deref(),
                    &telemetry,
                )
                .map_err(|(status, message)| {
                    ResponseError::from(build_error_response(status, &message, format))
                })?;
                taikai::validate_taikai_publisher_owner(&ssm_outcome, &authenticated_owner)
                    .map_err(|(status, message)| {
                        ResponseError::from(build_error_response(status, &message, format))
                    })?;
                {
                    let spool_dir = app.da_ingest.manifest_store_dir.clone();
                    let ssm_bytes_for_spool = ssm_bytes.clone();
                    let storage_ticket = manifest.storage_ticket.clone();
                    let lane_id = request.lane_id;
                    let epoch = request.epoch;
                    let sequence = request.sequence;
                    spool_batch.push(DaSpoolAction::new("taikai_ssm", move || {
                        taikai_ingest::persist_ssm(
                            &spool_dir,
                            lane_id,
                            epoch,
                            sequence,
                            &storage_ticket,
                            &fingerprint,
                            &ssm_bytes_for_spool,
                        )
                        .map(|_| DaSpoolActionOutput::None)
                        .map_err(|err| err.to_string())
                    }));
                }
                iroha_logger::info!(
                    manifest_hash = %hex::encode(manifest.manifest_hash.as_ref()),
                    alias = %ssm_outcome.alias_label,
                    ssm_digest = %hex::encode(ssm_outcome.ssm_digest.as_ref()),
                    "accepted Taikai signing manifest"
                );
                if let Some(trm_bytes) = taikai_trm_payload.take() {
                    let routing_manifest = taikai::validate_taikai_trm(
                        &trm_bytes,
                        &taikai,
                        &ssm_outcome.alias_binding,
                    )
                    .map_err(|(status, message): (StatusCode, String)| {
                        ResponseError::from(build_error_response(status, &message, format))
                    })?;
                    let manifest_digest_hex = hex::encode(blake3_hash(&trm_bytes).as_bytes());
                    let mut lineage_guard = taikai_ingest::TrmLineageGuard::new(
                        &app.da_ingest.manifest_store_dir,
                        &routing_manifest.alias_binding,
                    )
                    .map_err(|(status, message): (StatusCode, String)| {
                        ResponseError::from(build_error_response(status, &message, format))
                    })?;
                    if let Some(guard) = lineage_guard.as_mut() {
                        guard.recover_pending(app.da_receipt_log.as_ref()).map_err(
                            |(status, message): (StatusCode, String)| {
                                ResponseError::from(build_error_response(status, &message, format))
                            },
                        )?;
                    }
                    let lineage_validation = if let Some(guard) = lineage_guard.as_ref() {
                        guard
                            .validate_ingest_retry(
                                &routing_manifest,
                                &manifest_digest_hex,
                                request.lane_id,
                                request.epoch,
                                request.sequence,
                                &manifest.storage_ticket,
                                &fingerprint,
                                &trm_bytes,
                            )
                            .map_err(|(status, message): (StatusCode, String)| {
                                ResponseError::from(build_error_response(status, &message, format))
                            })?
                    } else {
                        taikai_ingest::TrmLineageValidation::Fresh
                    };
                    let spool_dir = app.da_ingest.manifest_store_dir.clone();
                    let storage_ticket = manifest.storage_ticket.clone();
                    let lane_id = request.lane_id;
                    let epoch = request.epoch;
                    let sequence = request.sequence;
                    let trm_bytes_for_spool = trm_bytes.clone();
                    spool_batch.push(DaSpoolAction::new("taikai_trm", move || {
                        if matches!(
                            lineage_validation,
                            taikai_ingest::TrmLineageValidation::ExactArtifactRetry
                        ) {
                            taikai_ingest::validate_existing_trm_retry_artifact(
                                &spool_dir,
                                lane_id,
                                epoch,
                                sequence,
                                &storage_ticket,
                                &fingerprint,
                                &trm_bytes_for_spool,
                            )
                            .map_err(|err| err.to_string())?;
                            return Ok(DaSpoolActionOutput::None);
                        }
                        taikai_ingest::persist_trm(
                            &spool_dir,
                            lane_id,
                            epoch,
                            sequence,
                            &storage_ticket,
                            &fingerprint,
                            &trm_bytes_for_spool,
                        )
                        .map_err(|err| err.to_string())?;
                        Ok(DaSpoolActionOutput::None)
                    }));
                    if lineage_validation.records_alias_rotation() {
                        taikai_lineage_commit =
                            lineage_guard.map(|guard| PendingTaikaiLineageCommit {
                                guard,
                                segment_window: routing_manifest.segment_window.clone(),
                                manifest_digest_hex: manifest_digest_hex.clone(),
                                lane_id: request.lane_id,
                                epoch: request.epoch,
                                sequence: request.sequence,
                                storage_ticket: manifest.storage_ticket.clone(),
                                fingerprint,
                            });
                        taikai_alias_rotation_event =
                            Some((routing_manifest.clone(), manifest_digest_hex));
                    }
                }
                taikai::record_taikai_ingest_metrics(&telemetry, cluster_label, &taikai.telemetry);
            }
            {
                let receipt_log = Arc::clone(&app.da_receipt_log);
                let replay_cache = Arc::clone(&app.da_replay_cache);
                let replay_lifecycle_lock = Arc::clone(&app.da_replay_lifecycle_lock);
                let state = Arc::clone(&app.state);
                let receipt = receipt.clone();
                let sequence = request.sequence;
                let owner = authenticated_owner.clone();
                let lane_id = request.lane_id;
                let epoch = request.epoch;
                let mut replay_reservation = replay_reservation;
                let mut taikai_lineage_commit = taikai_lineage_commit;
                let pin_finalized = pin_intent.is_some();
                let taikai_ready = (pin_finalized
                    && matches!(request.blob_class, BlobClass::TaikaiSegment))
                .then(|| {
                    (
                        app.da_ingest.manifest_store_dir.clone(),
                        request.lane_id,
                        request.epoch,
                        request.sequence,
                        manifest.storage_ticket,
                    )
                });
                // The durable receipt and replay cursor commit only after every
                // artifact required by this ingest has been written successfully. Moving the
                // reservation into the queued action keeps it live if the HTTP future is
                // cancelled after the spool worker accepts the batch.
                spool_batch.push_commit(DaSpoolAction::new("receipt_log", move || {
                    let _lifecycle_guard = replay_lifecycle_lock.lock();
                    let admission_snapshot = super::committed_da_ingest_admission_snapshot(&state)
                        .map_err(|error| {
                            format!("committed DA ingest admission policy is invalid: {error}")
                        })?;
                    if !admission_snapshot.is_configured() {
                        return Err(
                            "DA ingest admission policy was removed before durable commit"
                                .to_owned(),
                        );
                    }
                    if !admission_snapshot.authorizes(&owner, lane_id, epoch) {
                        return Err(
                            "DA ingest authorization was retired before durable commit".to_owned()
                        );
                    }
                    reconcile_da_replay_state(
                        &admission_snapshot,
                        receipt_log.as_ref(),
                        replay_cache.as_ref(),
                    )?;
                    if let Some(lineage) = taikai_lineage_commit.as_mut() {
                        lineage.stage()?;
                    }
                    let outcome = match receipt_log.append(
                        lane_epoch,
                        sequence,
                        receipt,
                        fingerprint,
                    ) {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            let append_error = error.to_string();
                            match receipt_log.receipt_for_duplicate(
                                lane_epoch,
                                sequence,
                                fingerprint,
                            ) {
                                Ok(Some(_)) => replay_reservation.commit(),
                                Ok(None) => {}
                                Err(recovery_error) => {
                                    return Err(format!(
                                        "{append_error}; failed to reconcile a possibly published DA receipt: {recovery_error}"
                                    ));
                                }
                            }
                            if let Some(lineage) = taikai_lineage_commit.as_mut() {
                                let recovery_snapshot =
                                    super::committed_da_ingest_admission_snapshot(&state).map_err(
                                        |snapshot_error| {
                                            format!(
                                                "{append_error}; could not reconcile staged Taikai lineage because the committed DA admission policy is invalid: {snapshot_error}"
                                            )
                                        },
                                    )?;
                                if !recovery_snapshot.authorizes(&owner, lane_id, epoch) {
                                    reconcile_da_replay_state(
                                        &recovery_snapshot,
                                        receipt_log.as_ref(),
                                        replay_cache.as_ref(),
                                    )
                                    .map_err(|reconcile_error| {
                                        format!(
                                            "{append_error}; could not retire a possibly written receipt before Taikai lineage recovery: {reconcile_error}"
                                        )
                                    })?;
                                }
                                lineage.recover(receipt_log.as_ref()).map_err(
                                    |recovery_error| {
                                        format!(
                                            "{append_error}; failed to reconcile staged Taikai lineage against the receipt log: {recovery_error}"
                                        )
                                    },
                                )?;
                            }
                            return Err(append_error);
                        }
                    };
                    let post_commit_snapshot = super::committed_da_ingest_admission_snapshot(
                        &state,
                    )
                    .map_err(|error| {
                        format!(
                            "failed to recheck DA admission policy after receipt commit: {error}"
                        )
                    })?;
                    if !post_commit_snapshot.authorizes(&owner, lane_id, epoch) {
                        reconcile_da_replay_state(
                            &post_commit_snapshot,
                            receipt_log.as_ref(),
                            replay_cache.as_ref(),
                        )?;
                        if let Some(lineage) = taikai_lineage_commit.as_mut() {
                            lineage.discard()?;
                        }
                        return Err(
                            "DA ingest authorization changed during durable commit; retired receipt"
                                .to_owned(),
                        );
                    }
                    if matches!(
                        &outcome,
                        ReceiptInsertOutcome::Stored { .. }
                            | ReceiptInsertOutcome::Duplicate { .. }
                    ) {
                        if let Some(lineage) = taikai_lineage_commit.as_mut() {
                            lineage.recover(receipt_log.as_ref())?;
                        }
                    } else if let Some(lineage) = taikai_lineage_commit.as_mut() {
                        lineage.discard()?;
                    }
                    if matches!(
                        &outcome,
                        ReceiptInsertOutcome::Stored { .. }
                            | ReceiptInsertOutcome::Duplicate { .. }
                    ) && let Some((spool_dir, lane_id, epoch, sequence, storage_ticket)) =
                        taikai_ready
                    {
                        taikai_ingest::persist_anchor_ready(
                            &spool_dir,
                            lane_id,
                            epoch,
                            sequence,
                            &storage_ticket,
                            &fingerprint,
                        )
                        .map_err(|err| err.to_string())?;
                    }
                    replay_reservation.resolve_receipt_outcome(&outcome);
                    Ok(DaSpoolActionOutput::ReceiptOutcome(outcome))
                }));
            }
            let spool_report = flush_da_spool_batch(app.as_ref(), spool_batch).await;
            log_da_spool_failures(&spool_report);
            let mut receipt_log_recorded = false;
            for action in spool_report.actions() {
                if let Some(DaSpoolActionOutput::ReceiptOutcome(outcome)) = action.output() {
                    receipt_log_recorded = true;
                    record_da_receipt_metrics(&telemetry, lane_epoch, request.sequence, outcome);
                }
            }
            if !receipt_log_recorded {
                record_da_receipt_error_metrics(&telemetry, lane_epoch, request.sequence);
            }
            if let Some(response) = da_spool_rejection_response(&spool_report, format) {
                return Ok(response);
            }
            if let Some((routing_manifest, manifest_digest_hex)) = taikai_alias_rotation_event
                && spool_report_action_ok(&spool_report, "taikai_trm")
            {
                taikai::record_taikai_alias_rotation_event(
                    &telemetry,
                    cluster_label,
                    &routing_manifest,
                    &manifest_digest_hex,
                );
            }
            let response = DaIngestResponse {
                status: if pin_intent.is_some() {
                    "accepted"
                } else {
                    "pending_pin_authorization"
                },
                duplicate,
                receipt: Some(receipt),
                pin_scope: Some(pin_scope),
            };
            let mut http_response = utils::respond_with_format(response, format);
            http_response.headers_mut().insert(
                HeaderName::from_static(HEADER_SORA_PDP_COMMITMENT),
                pdp_header_value,
            );
            Ok(with_status(http_response, StatusCode::ACCEPTED))
        }
        ReplayInsertOutcome::StaleSequence { highest_observed } => {
            let message = format!(
                "sequence {} is too far behind; highest observed is {}",
                request.sequence, highest_observed
            );
            Ok(build_error_response(StatusCode::CONFLICT, &message, format))
        }
        ReplayInsertOutcome::SequenceGap {
            expected_next,
            observed,
        } => {
            let message =
                format!("sequence {observed} skips required next DA sequence {expected_next}");
            Ok(build_error_response(StatusCode::CONFLICT, &message, format))
        }
        ReplayInsertOutcome::ConflictingFingerprint { .. } => Ok(build_error_response(
            StatusCode::CONFLICT,
            "sequence already used for a different manifest",
            format,
        )),
        ReplayInsertOutcome::InFlight { .. } => Ok(build_error_response(
            StatusCode::CONFLICT,
            "an identical DA ingest is still in flight; retry after it completes",
            format,
        )),
        ReplayInsertOutcome::LaneEpochCapacityExceeded { capacity } => {
            let message = format!("global DA replay lane/epoch capacity ({capacity}) is exhausted");
            Ok(build_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &message,
                format,
            ))
        }
        ReplayInsertOutcome::ReservationCapacityExceeded { capacity } => {
            let message =
                format!("DA replay in-flight reservation capacity ({capacity}) is exhausted");
            Ok(build_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &message,
                format,
            ))
        }
    }
}
#[derive(Debug)]
struct DuplicateDaArtifacts {
    receipt_path: PathBuf,
    receipt: DaIngestReceipt,
    pdp_commitment_bytes: Vec<u8>,
    pin_scope: DaPinScopeV1,
    pin_intent: Option<DaPinIntent>,
}
#[derive(Debug)]
enum DuplicateDaArtifactsError {
    Client(StatusCode, String),
    Conflict(String),
    Internal(eyre::Report),
}
impl std::fmt::Display for DuplicateDaArtifactsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(_, message) => formatter.write_str(message),
            Self::Conflict(message) => formatter.write_str(message),
            Self::Internal(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for DuplicateDaArtifactsError {}

fn duplicate_da_artifacts_response_error(
    error: DuplicateDaArtifactsError,
    internal_context: &str,
    format: ResponseFormat,
) -> ResponseError {
    let (status, message) = match error {
        DuplicateDaArtifactsError::Client(status, message) => (status, message),
        DuplicateDaArtifactsError::Conflict(message) => (StatusCode::CONFLICT, message),
        DuplicateDaArtifactsError::Internal(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{internal_context}: {error}"),
        ),
    };
    ResponseError::from(build_error_response(status, &message, format))
}

fn load_duplicate_da_artifacts(
    receipt_log: &persistence::DaReceiptLog,
    spool_dir: &Path,
    lane_epoch: LaneEpoch,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: ReplayFingerprint,
    request: &DaIngestRequest,
) -> Result<DuplicateDaArtifacts, DuplicateDaArtifactsError> {
    let pin_scope = persistence::load_da_pin_scope(
        spool_dir,
        lane_epoch.lane_id,
        lane_epoch.epoch,
        sequence,
        storage_ticket,
        &fingerprint,
    )
    .wrap_err("failed to load duplicate DA pin-scope artifact")
    .map_err(DuplicateDaArtifactsError::Internal)?;
    if !pin_scope.matches_authorization(&request.authorization()) {
        return Err(DuplicateDaArtifactsError::Conflict(
            "completed DA ingest identity conflicts with the submitted request".to_owned(),
        ));
    }
    let manifest_artifact =
        persistence::load_manifest_artifact_from_spool(spool_dir, storage_ticket)
            .wrap_err("failed to load duplicate DA manifest artifact")
            .map_err(DuplicateDaArtifactsError::Internal)?;
    let manifest_hash = BlobDigest::from_hash(blake3_hash(&manifest_artifact.bytes));
    if pin_scope.manifest_hash.as_bytes() != manifest_hash.as_bytes() {
        return Err(DuplicateDaArtifactsError::Internal(eyre!(
            "duplicate DA pin scope manifest digest does not match durable manifest"
        )));
    }
    let pdp_commitment_bytes = persistence::load_pdp_commitment_for_manifest_artifact(
        spool_dir,
        &manifest_artifact,
        &manifest_hash,
    )
    .wrap_err("failed to load duplicate DA PDP commitment artifact")
    .map_err(DuplicateDaArtifactsError::Internal)?;
    let (receipt_path, receipt) = receipt_log
        .receipt_for_duplicate(lane_epoch, sequence, fingerprint)
        .wrap_err("failed to load duplicate DA receipt")
        .map_err(DuplicateDaArtifactsError::Internal)?
        .ok_or_else(|| {
            DuplicateDaArtifactsError::Internal(eyre!("duplicate DA receipt was not found"))
        })?;
    if receipt.storage_ticket != *storage_ticket {
        return Err(DuplicateDaArtifactsError::Internal(eyre!(
            "duplicate DA receipt storage ticket does not match replay fingerprint"
        )));
    }
    if receipt.manifest_hash != manifest_hash {
        return Err(DuplicateDaArtifactsError::Internal(eyre!(
            "duplicate DA receipt manifest hash does not match durable manifest"
        )));
    }
    if receipt.pdp_commitment.as_deref() != Some(pdp_commitment_bytes.as_slice()) {
        return Err(DuplicateDaArtifactsError::Internal(eyre!(
            "duplicate DA receipt PDP commitment does not match durable PDP artifact"
        )));
    }
    let pin_intent = match persistence::load_da_pin_intent(
        spool_dir,
        lane_epoch.lane_id,
        lane_epoch.epoch,
        sequence,
        storage_ticket,
        &fingerprint,
    ) {
        Ok(intent) => Some(intent),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            return Err(DuplicateDaArtifactsError::Internal(eyre!(
                "failed to load duplicate DA pin-intent artifact: {error}"
            )));
        }
    };
    if pin_intent
        .as_ref()
        .is_some_and(|intent| intent.pin_scope_authorization.scope != pin_scope)
    {
        return Err(DuplicateDaArtifactsError::Internal(eyre!(
            "duplicate DA pin intent does not match the durable producer scope"
        )));
    }
    Ok(DuplicateDaArtifacts {
        receipt_path,
        receipt,
        pdp_commitment_bytes,
        pin_scope,
        pin_intent,
    })
}
fn load_duplicate_da_artifacts_if_receipt_present(
    receipt_log: &persistence::DaReceiptLog,
    spool_dir: &Path,
    lane_epoch: LaneEpoch,
    sequence: u64,
    storage_ticket: &StorageTicketId,
    fingerprint: ReplayFingerprint,
    request: &DaIngestRequest,
) -> Result<Option<DuplicateDaArtifacts>, DuplicateDaArtifactsError> {
    if receipt_log
        .receipt_for_duplicate(lane_epoch, sequence, fingerprint)
        .wrap_err("failed to check durable DA receipt log for duplicate")
        .map_err(DuplicateDaArtifactsError::Internal)?
        .is_none()
    {
        return Ok(None);
    }
    load_duplicate_da_artifacts(
        receipt_log,
        spool_dir,
        lane_epoch,
        sequence,
        storage_ticket,
        fingerprint,
        request,
    )
    .map(Some)
}
fn handle_duplicate_da_ingest(
    app: &crate::AppState,
    telemetry: &MaybeTelemetry,
    request: &DaIngestRequest,
    manifest: &ManifestArtifacts,
    lane_epoch: LaneEpoch,
    format: ResponseFormat,
) -> Result<Response, ResponseError> {
    let _lifecycle_guard = app.da_replay_lifecycle_lock.lock();
    let artifacts = load_duplicate_da_artifacts(
        app.da_receipt_log.as_ref(),
        &app.da_ingest.manifest_store_dir,
        lane_epoch,
        request.sequence,
        &manifest.storage_ticket,
        manifest.fingerprint,
        request,
    )
    .map_err(|err| {
        duplicate_da_artifacts_response_error(
            err,
            "failed to recover duplicate DA ingest artifacts",
            format,
        )
    })?;
    let (artifacts, finalized) = finalize_duplicate_da_pin_intent(
        &app.da_ingest.manifest_store_dir,
        request,
        lane_epoch,
        manifest.fingerprint,
        artifacts,
    )
    .map_err(|err| {
        duplicate_da_artifacts_response_error(err, "failed to finalize DA pin intent", format)
    })?;
    duplicate_da_ingest_response_from_artifacts(
        telemetry,
        lane_epoch,
        request.sequence,
        artifacts,
        finalized,
        format,
    )
}
fn finalize_duplicate_da_pin_intent(
    spool_dir: &Path,
    request: &DaIngestRequest,
    lane_epoch: LaneEpoch,
    fingerprint: ReplayFingerprint,
    mut artifacts: DuplicateDaArtifacts,
) -> Result<(DuplicateDaArtifacts, bool), DuplicateDaArtifactsError> {
    let submitted_scope_authorization =
        submitted_pin_scope_authorization(request, artifacts.pin_scope.clone())
            .map_err(|(status, message)| DuplicateDaArtifactsError::Client(status, message))?;
    if let Some(existing) = artifacts.pin_intent.take() {
        persistence::validate_da_pin_intent_retry_authorization(
            &existing,
            &request.authorization(),
        )
        .map_err(|err| DuplicateDaArtifactsError::Conflict(err.to_string()))?;
        artifacts.pin_intent = if let Some(scope_authorization) = submitted_scope_authorization {
            let candidate = build_da_pin_intent(request, scope_authorization);
            Some(
                persistence::select_da_pin_intent_for_persistence(
                    spool_dir,
                    &candidate,
                    lane_epoch.lane_id,
                    lane_epoch.epoch,
                    request.sequence,
                    &artifacts.pin_scope.storage_ticket,
                    &fingerprint,
                )
                .map_err(|err| {
                    if err.kind() == ErrorKind::AlreadyExists {
                        DuplicateDaArtifactsError::Conflict(err.to_string())
                    } else {
                        DuplicateDaArtifactsError::Internal(eyre!(
                            "failed to select canonical DA pin intent: {err}"
                        ))
                    }
                })?,
            )
        } else {
            Some(existing)
        };
    } else {
        let Some(scope_authorization) = submitted_scope_authorization else {
            return Ok((artifacts, false));
        };
        let candidate = build_da_pin_intent(request, scope_authorization);
        let intent = persistence::select_da_pin_intent_for_persistence(
            spool_dir,
            &candidate,
            lane_epoch.lane_id,
            lane_epoch.epoch,
            request.sequence,
            &artifacts.pin_scope.storage_ticket,
            &fingerprint,
        )
        .map_err(|err| {
            if err.kind() == ErrorKind::AlreadyExists {
                DuplicateDaArtifactsError::Conflict(err.to_string())
            } else {
                DuplicateDaArtifactsError::Internal(eyre!(
                    "failed to select canonical DA pin intent: {err}"
                ))
            }
        })?;
        persistence::persist_da_pin_intent(
            spool_dir,
            &intent,
            lane_epoch.lane_id,
            lane_epoch.epoch,
            request.sequence,
            &artifacts.pin_scope.storage_ticket,
            &fingerprint,
        )
        .wrap_err("failed to persist producer-authorized DA pin intent")
        .map_err(DuplicateDaArtifactsError::Internal)?;
        artifacts.pin_intent = Some(
            persistence::load_da_pin_intent(
                spool_dir,
                lane_epoch.lane_id,
                lane_epoch.epoch,
                request.sequence,
                &artifacts.pin_scope.storage_ticket,
                &fingerprint,
            )
            .wrap_err("failed to reload canonical producer-authorized DA pin intent")
            .map_err(DuplicateDaArtifactsError::Internal)?,
        );
    }
    ensure_taikai_anchor_ready_for_scope(spool_dir, request, &artifacts.pin_scope)
        .map_err(DuplicateDaArtifactsError::Internal)?;
    Ok((artifacts, true))
}
fn ensure_taikai_anchor_ready_for_scope(
    spool_dir: &Path,
    request: &DaIngestRequest,
    scope: &DaPinScopeV1,
) -> eyre::Result<()> {
    if !matches!(request.blob_class, BlobClass::TaikaiSegment) {
        return Ok(());
    }
    taikai_ingest::persist_anchor_ready(
        spool_dir,
        request.lane_id,
        request.epoch,
        request.sequence,
        &scope.storage_ticket,
        &ReplayFingerprint::from(*scope.storage_ticket.as_bytes()),
    )
    .wrap_err("failed to persist Taikai anchor readiness marker")?;
    Ok(())
}
fn duplicate_da_ingest_response_from_artifacts(
    telemetry: &MaybeTelemetry,
    lane_epoch: LaneEpoch,
    sequence: u64,
    artifacts: DuplicateDaArtifacts,
    finalized: bool,
    format: ResponseFormat,
) -> Result<Response, ResponseError> {
    record_da_receipt_metrics(
        telemetry,
        lane_epoch,
        sequence,
        &ReceiptInsertOutcome::Duplicate {
            path: artifacts.receipt_path,
        },
    );
    let pdp_header_value = pdp_commitment_header_value(&artifacts.pdp_commitment_bytes).map_err(
        |(status, message)| ResponseError::from(build_error_response(status, &message, format)),
    )?;
    let response = DaIngestResponse {
        status: if finalized {
            "accepted"
        } else {
            "pending_pin_authorization"
        },
        duplicate: true,
        receipt: Some(artifacts.receipt),
        pin_scope: Some(artifacts.pin_scope),
    };
    let mut http_response = utils::respond_with_format(response, format);
    http_response.headers_mut().insert(
        HeaderName::from_static(HEADER_SORA_PDP_COMMITMENT),
        pdp_header_value,
    );
    Ok(with_status(http_response, StatusCode::ACCEPTED))
}
/// HTTP handler for `/v1/da/manifests/{ticket}`.
pub async fn handler_get_da_manifest(
    State(app): State<SharedAppState>,
    AxumPath(ticket_hex): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Response, ResponseError> {
    utils::negotiate_json_only_response(headers.get(axum::http::header::ACCEPT))
        .map_err(ResponseError::from)?;
    let format = ResponseFormat::Json;
    reject_emergency_fast_da_service(app.as_ref(), format)?;
    let ticket_bytes = match parse_storage_ticket_hex(ticket_hex.trim()) {
        Ok(bytes) => bytes,
        Err(message) => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::BAD_REQUEST,
                &message,
                format,
            )));
        }
    };
    let ticket = StorageTicketId::new(ticket_bytes);
    let manifest_artifact = match persistence::load_manifest_artifact_from_spool(
        &app.da_ingest.manifest_store_dir,
        &ticket,
    ) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::NOT_FOUND,
                "manifest not found for storage ticket",
                format,
            )));
        }
        Err(err) => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to read manifest from spool: {err}"),
                format,
            )));
        }
    };
    let manifest_bytes = manifest_artifact.bytes.as_slice();
    let manifest: DaManifestV1 = match decode_from_bytes(manifest_bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to decode stored manifest: {err}"),
                format,
            )));
        }
    };
    let plan = match build_plan_from_da_manifest(&manifest) {
        Ok(plan) => plan,
        Err(err) => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to derive chunk plan from manifest: {err}"),
                format,
            )));
        }
    };
    let chunk_plan = match try_chunk_fetch_plan_to_json(&plan) {
        Ok(plan) => plan,
        Err(err) => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to derive chunk fetch specifications: {err}"),
                format,
            )));
        }
    };
    let manifest_json = match json::to_value(&manifest) {
        Ok(value) => value,
        Err(err) => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to render manifest JSON: {err}"),
                format,
            )));
        }
    };
    let manifest_hash = BlobDigest::from_hash(blake3_hash(manifest_bytes));
    let body = iroha_torii_shared::da::DaManifestResponse {
        storage_ticket: hex::encode(ticket.as_bytes()),
        client_blob_id: hex::encode(manifest.client_blob_id.as_bytes()),
        blob_hash: hex::encode(manifest.blob_hash.as_bytes()),
        chunk_root: hex::encode(manifest.chunk_root.as_bytes()),
        manifest_hash: hex::encode(manifest_hash.as_bytes()),
        lane_id: manifest.lane_id.as_u32(),
        epoch: manifest.epoch,
        manifest_len: manifest_bytes.len() as u64,
        manifest_norito: BASE64.encode(manifest_bytes),
        manifest: manifest_json,
        chunk_plan,
    };
    let body = json::to_value(&body).map_err(|err| {
        ResponseError::from(build_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to render manifest response: {err}"),
            format,
        ))
    })?;
    let response = utils::respond_value_with_format(body, format);
    attach_pdp_commitment_header_from_spool(
        &app.da_ingest.manifest_store_dir,
        &manifest_artifact,
        &manifest_hash,
        response,
        format,
    )
}

fn reject_emergency_fast_da_service(
    app: &crate::AppState,
    format: ResponseFormat,
) -> Result<(), ResponseError> {
    if app.kura.emergency_fast_startup_enabled() {
        return Err(ResponseError::from(build_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "DA ingest and manifest storage are unavailable during emergency Fast startup",
            format,
        )));
    }
    Ok(())
}
fn attach_pdp_commitment_header_from_spool(
    spool_dir: &Path,
    manifest_artifact: &persistence::LoadedManifestArtifact,
    manifest_hash: &BlobDigest,
    mut response: Response,
    format: ResponseFormat,
) -> Result<Response, ResponseError> {
    match persistence::load_pdp_commitment_for_manifest_artifact(
        spool_dir,
        manifest_artifact,
        manifest_hash,
    ) {
        Ok(commitment) => match pdp_commitment_header_value(&commitment) {
            Ok(value) => {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static(HEADER_SORA_PDP_COMMITMENT), value);
            }
            Err((_, message)) => {
                return Err(ResponseError::from(build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to encode PDP commitment header: {message}"),
                    format,
                )));
            }
        },
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(ResponseError::from(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to read PDP commitment from spool: {err}"),
                format,
            )));
        }
    }
    Ok(response)
}
fn normalize_payload(
    request: &DaIngestRequest,
) -> Result<CanonicalPayload<'_>, (StatusCode, String)> {
    let expected_decompressed_len = || {
        if request.total_size > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "total_size {} exceeds the 64 MiB DA ingest limit",
                    request.total_size
                ),
            ));
        }
        usize::try_from(request.total_size).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "total_size {} exceeds this node's supported payload length",
                    request.total_size
                ),
            )
        })
    };
    match request.compression {
        Compression::Identity => Ok(CanonicalPayload {
            bytes: Cow::Borrowed(&request.payload),
        }),
        Compression::Gzip => Ok(CanonicalPayload {
            bytes: Cow::Owned(decompress_reader(
                GzDecoder::new(request.payload.as_slice()),
                expected_decompressed_len()?,
                "gzip",
            )?),
        }),
        Compression::Deflate => Ok(CanonicalPayload {
            bytes: Cow::Owned(decompress_reader(
                DeflateDecoder::new(request.payload.as_slice()),
                expected_decompressed_len()?,
                "deflate",
            )?),
        }),
        Compression::Zstd => Ok(CanonicalPayload {
            bytes: Cow::Owned(decompress_zstd(
                request.payload.as_slice(),
                expected_decompressed_len()?,
            )?),
        }),
    }
}
fn parse_storage_ticket_hex(input: &str) -> Result<[u8; 32], String> {
    if input.is_empty() {
        return Err("storage ticket must be provided".into());
    }
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(trimmed)
        .map_err(|_| "storage ticket must be a 64-character hex string".to_owned())?;
    if bytes.len() != 32 {
        return Err(format!(
            "storage ticket must decode to 32 bytes (got {})",
            bytes.len()
        ));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}
fn encode_pdp_commitment_bytes(
    commitment: &PdpCommitmentV1,
) -> Result<Vec<u8>, (StatusCode, String)> {
    to_bytes(commitment).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode PDP commitment: {err}"),
        )
    })
}
fn pdp_commitment_header_value(bytes: &[u8]) -> Result<HeaderValue, (StatusCode, String)> {
    let encoded = BASE64.encode(bytes);
    HeaderValue::from_str(&encoded).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode Sora-PDP-Commitment header: {err}"),
        )
    })
}
fn decompress_reader<R>(
    reader: R,
    expected_len: usize,
    algorithm: &'static str,
) -> Result<Vec<u8>, (StatusCode, String)>
where
    R: Read,
{
    let read_limit = expected_len
        .checked_add(1)
        .and_then(|limit| u64::try_from(limit).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("{algorithm} total_size exceeds supported decompression boundary"),
            )
        })?;
    let mut buffer = Vec::with_capacity(expected_len.min(16 * 1024));
    reader
        .take(read_limit)
        .read_to_end(&mut buffer)
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("failed to decompress {algorithm} payload: {err}"),
            )
        })?;
    verify_decompressed_len(buffer, expected_len, algorithm)
}
fn decompress_zstd(payload: &[u8], expected_len: usize) -> Result<Vec<u8>, (StatusCode, String)> {
    let decoder = ZstdDecoder::new(payload).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("failed to decompress zstd payload: {err}"),
        )
    })?;
    decompress_reader(decoder, expected_len, "zstd")
}
fn verify_decompressed_len(
    buffer: Vec<u8>,
    expected_len: usize,
    algorithm: &'static str,
) -> Result<Vec<u8>, (StatusCode, String)> {
    if buffer.len() != expected_len {
        Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{algorithm} payload decompressed to {} bytes but total_size advertises {} bytes",
                buffer.len(),
                expected_len
            ),
        ))
    } else {
        Ok(buffer)
    }
}
fn validate_request(
    request: &DaIngestRequest,
    canonical_payload: &[u8],
) -> Result<(), (StatusCode, &'static str)> {
    validate_request_shape(request)?;
    if request.total_size != canonical_payload.len() as u64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "payload length does not match total_size",
        ));
    }
    if request.payload_hash != BlobDigest::from_hash(blake3_hash(canonical_payload)) {
        return Err((
            StatusCode::BAD_REQUEST,
            "canonical payload hash does not match payload_hash",
        ));
    }
    Ok(())
}
fn authenticate_da_ingest_request(
    request: &DaIngestRequest,
    principal: &crate::app_auth::VerifiedCanonicalRequest,
    expected_network_id: &NetworkId,
) -> Result<AccountId, (StatusCode, &'static str)> {
    if &request.network_id != expected_network_id {
        return Err((
            StatusCode::FORBIDDEN,
            "DA ingest request targets a different network",
        ));
    }
    if request.owner != principal.account {
        return Err((
            StatusCode::FORBIDDEN,
            "DA ingest quota owner does not match the authenticated account",
        ));
    }
    if request.signatures.iter().any(|witness| {
        !principal
            .verified_signers
            .iter()
            .any(|signer| signer == &witness.signer)
    }) {
        return Err((
            StatusCode::FORBIDDEN,
            "DA ingest authorization includes a signer outside the authenticated account witness",
        ));
    }
    if !request.pin_scope_signatures.is_empty() {
        let scope_signers = request
            .pin_scope_signatures
            .iter()
            .map(|witness| &witness.signer)
            .collect::<Vec<_>>();
        let mut principal_signers = principal.verified_signers.iter().collect::<Vec<_>>();
        principal_signers.sort();
        if scope_signers != principal_signers {
            return Err((
                StatusCode::FORBIDDEN,
                "DA pin-scope signers must exactly match the authenticated account witness",
            ));
        }
    }
    request.verify_signatures().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "DA ingest request signatures are invalid",
        )
    })?;
    if request
        .metadata
        .items
        .iter()
        .any(|entry| entry.key == META_DA_REGISTRY_OWNER)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "metadata entry `da.registry.owner` is retired; pin ownership comes from the authenticated account",
        ));
    }
    Ok(principal.account.clone())
}
fn validate_request_shape(request: &DaIngestRequest) -> Result<(), (StatusCode, &'static str)> {
    if request.sequence == u64::MAX {
        return Err((
            StatusCode::BAD_REQUEST,
            "sequence must leave room for a monotonic successor",
        ));
    }
    if request.total_size == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "total_size must contain at least one byte",
        ));
    }
    if request.total_size > MAX_CANONICAL_PAYLOAD_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "total_size exceeds the 64 MiB DA ingest limit",
        ));
    }
    if request.chunk_size == 0 || !request.chunk_size.is_power_of_two() {
        return Err((
            StatusCode::BAD_REQUEST,
            "chunk_size must be a non-zero power of two",
        ));
    }
    if request.chunk_size < MIN_CHUNK_SIZE_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            "chunk_size is below the supported 1 KiB minimum",
        ));
    }
    if request.chunk_size > MAX_CHUNK_SIZE_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            "chunk_size exceeds supported maximum (2 MiB)",
        ));
    }
    let profile = request.erasure_profile;
    if profile.data_shards == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "erasure profile must include at least one data shard",
        ));
    }
    if profile.data_shards > MAX_DATA_SHARDS {
        return Err((
            StatusCode::BAD_REQUEST,
            "erasure profile exceeds the 64 data-shard limit",
        ));
    }
    if profile.parity_shards < 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            "erasure profile requires at least 2 parity shards",
        ));
    }
    if profile.parity_shards > MAX_PARITY_SHARDS {
        return Err((
            StatusCode::BAD_REQUEST,
            "erasure profile exceeds the 64 parity-shard limit",
        ));
    }
    if profile.row_parity_stripes > MAX_ROW_PARITY_STRIPES {
        return Err((
            StatusCode::BAD_REQUEST,
            "erasure profile exceeds the 64 row-parity-stripe limit",
        ));
    }
    let chunk_size = u64::from(request.chunk_size);
    let data_chunk_count_u64 = request.total_size.div_ceil(chunk_size);
    let data_chunk_count = usize::try_from(data_chunk_count_u64).map_err(|_| {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "DA source chunk count exceeds this host's address space",
        )
    })?;
    if data_chunk_count > MAX_DATA_CHUNKS {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "DA manifest exceeds the 1024 source-chunk limit",
        ));
    }
    let stripes = data_chunk_count.div_ceil(usize::from(profile.data_shards));
    if profile.row_parity_stripes > 0 && stripes > MAX_ROW_PARITY_SOURCE_STRIPES {
        return Err((
            StatusCode::BAD_REQUEST,
            "row parity exceeds the 64 source-stripe computation limit",
        ));
    }
    let chunk_size_usize = usize::try_from(request.chunk_size).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "chunk_size exceeds this host's address space",
        )
    })?;
    validate_erasure_work_budget(
        data_chunk_count,
        chunk_size_usize,
        usize::from(profile.data_shards),
        usize::from(profile.parity_shards),
        usize::from(profile.row_parity_stripes),
    )
    .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    Ok(())
}
fn lane_proof_scheme(
    nexus: &ConfigNexus,
    lane_id: LaneId,
    block_height: u64,
) -> Result<DaProofScheme, (StatusCode, String)> {
    iroha_core::da::active_lane_proof_policy_at_height(nexus, lane_id, block_height)
        .map(|policy| policy.proof_scheme)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "lane {} not present in active lane catalog",
                    lane_id.as_u32()
                ),
            )
        })
}
fn manifest_fingerprint(
    manifest: &DaManifestV1,
) -> Result<ReplayFingerprint, (StatusCode, String)> {
    let encoded = to_bytes(manifest).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode DA manifest for fingerprint: {err}"),
        )
    })?;
    Ok(ReplayFingerprint::from_hash(blake3_hash(&encoded)))
}
#[allow(clippy::too_many_arguments)]
fn build_receipt(
    signer: &KeyPair,
    request: &DaIngestRequest,
    queued_at: u64,
    blob_hash: BlobDigest,
    chunk_root: BlobDigest,
    manifest_hash: BlobDigest,
    storage_ticket: StorageTicketId,
    pdp_commitment: Vec<u8>,
    rent_quote: DaRentQuote,
    stripe_layout: DaStripeLayout,
) -> Result<DaIngestReceipt, (StatusCode, String)> {
    let mut receipt = DaIngestReceipt {
        client_blob_id: request.client_blob_id.clone(),
        lane_id: request.lane_id,
        epoch: request.epoch,
        blob_hash,
        chunk_root,
        manifest_hash,
        storage_ticket,
        pdp_commitment: Some(pdp_commitment),
        stripe_layout,
        queued_at_unix: queued_at,
        rent_quote,
        operator_signature: receipt_signature_placeholder(),
    };
    let unsigned_bytes =
        persistence::unsigned_receipt_bytes(&receipt, request.sequence).map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to encode DA ingest receipt for signing: {err}"),
            )
        })?;
    receipt.operator_signature = Signature::try_new(signer.private_key(), &unsigned_bytes)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to sign DA ingest receipt: {err}"),
            )
        })?;
    Ok(receipt)
}
fn stripe_layout_from_manifest(manifest: &DaManifestV1) -> DaStripeLayout {
    DaStripeLayout {
        total_stripes: manifest.total_stripes,
        shards_per_stripe: manifest.shards_per_stripe,
        row_parity_stripes: manifest.erasure_profile.row_parity_stripes,
    }
}
fn manifest_stripe_layout_fields(
    chunk_count: usize,
    erasure_profile: &ErasureProfile,
) -> Result<(u32, u32), (StatusCode, String)> {
    let data_shards = u32::from(erasure_profile.data_shards);
    if data_shards == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "erasure profile must include at least one data shard".into(),
        ));
    }
    let chunk_count = u32::try_from(chunk_count).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "chunk count exceeds supported manifest stripe space".into(),
        )
    })?;
    let total_stripes = chunk_count.div_ceil(data_shards);
    let shards_per_stripe = data_shards
        .checked_add(u32::from(erasure_profile.parity_shards))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "shards per stripe exceeds supported manifest stripe space".into(),
            )
        })?;
    let total_stripes_full = total_stripes
        .checked_add(u32::from(erasure_profile.row_parity_stripes))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "total stripes exceeds supported manifest stripe space".into(),
            )
        })?;
    Ok((total_stripes_full, shards_per_stripe))
}
fn chunk_profile_for_request(chunk_size: u32) -> ChunkProfile {
    let size = usize::try_from(chunk_size.max(1)).unwrap_or(usize::MAX);
    ChunkProfile {
        min_size: size,
        target_size: size,
        max_size: size,
        break_mask: 1,
    }
}
fn try_build_chunk_store(
    request: &DaIngestRequest,
    canonical_payload: &[u8],
) -> Result<ChunkStore, (StatusCode, String)> {
    let mut store = ChunkStore::with_profile(chunk_profile_for_request(request.chunk_size));
    store.ingest_bytes(canonical_payload).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("failed to chunk canonical DA payload: {error}"),
        )
    })?;
    Ok(store)
}
#[cfg(test)]
fn build_chunk_store(request: &DaIngestRequest, canonical_payload: &[u8]) -> ChunkStore {
    try_build_chunk_store(request, canonical_payload).expect("test DA payload must be ingestible")
}
fn encrypt_governance_metadata(
    metadata: &ExtraMetadata,
    key: Option<&[u8; 32]>,
    key_label: Option<&str>,
) -> Result<ExtraMetadata, (StatusCode, String)> {
    if metadata.items.is_empty() {
        return Ok(metadata.clone());
    }
    let mut encryptor: Option<SymmetricEncryptor<ChaCha20Poly1305>> = None;
    let mut processed = Vec::with_capacity(metadata.items.len());
    for entry in &metadata.items {
        let mut entry = entry.clone();
        match entry.visibility {
            MetadataVisibility::Public => {
                if entry.encryption != MetadataEncryption::None {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!(
                            "metadata entry `{}` is public but declares encryption {:?}",
                            entry.key, entry.encryption
                        ),
                    ));
                }
            }
            MetadataVisibility::GovernanceOnly => {
                let key_bytes = key.ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Torii governance metadata encryption key is not configured".into(),
                    )
                })?;
                let expected_label = key_label;
                if encryptor.is_none() {
                    let enc = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(key_bytes)
                        .map_err(|err| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!(
                                    "failed to initialise governance metadata encryptor: {err}"
                                ),
                            )
                        })?;
                    encryptor = Some(enc);
                }
                let Some(encryptor) = encryptor.as_ref() else {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Torii governance metadata encryptor was not initialised".into(),
                    ));
                };
                match entry.encryption {
                    MetadataEncryption::None => {
                        let ciphertext = encryptor
                            .encrypt_easy(entry.key.as_bytes(), &entry.value)
                            .map_err(|err| {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!(
                                        "failed to encrypt governance metadata entry `{}`: {err}",
                                        entry.key
                                    ),
                                )
                            })?;
                        entry.value = ciphertext;
                        entry.encryption = MetadataEncryption::chacha20poly1305_with_label(
                            expected_label.map(ToOwned::to_owned),
                        );
                    }
                    MetadataEncryption::ChaCha20Poly1305(ref envelope) => {
                        if let Some(label) = expected_label {
                            match envelope.key_label.as_deref() {
                                Some(observed) if observed == label => {}
                                Some(other) => {
                                    return Err((
                                        StatusCode::BAD_REQUEST,
                                        format!(
                                            "governance metadata entry `{}` encrypted with unexpected key `{other}` (expected `{label}`)",
                                            entry.key
                                        ),
                                    ));
                                }
                                None => {
                                    return Err((
                                        StatusCode::BAD_REQUEST,
                                        format!(
                                            "governance metadata entry `{}` missing key label (expected `{label}`)",
                                            entry.key
                                        ),
                                    ));
                                }
                            }
                        }
                        encryptor
                            .decrypt_easy(entry.key.as_bytes(), &entry.value)
                            .map_err(|_| {
                                (
                                    StatusCode::BAD_REQUEST,
                                    format!(
                                        "governance metadata entry `{}` has invalid ciphertext",
                                        entry.key
                                    ),
                                )
                            })?;
                    }
                }
            }
        }
        processed.push(entry);
    }
    Ok(ExtraMetadata { items: processed })
}
fn role_tag(role: ChunkRole) -> u8 {
    match role {
        ChunkRole::Data => 0,
        ChunkRole::LocalParity => 1,
        ChunkRole::GlobalParity => 2,
        ChunkRole::StripeParity => 3,
    }
}
#[cfg(feature = "ipa-commitment")]
fn ipa_scalar_from_chunk(commitment: &ChunkCommitment) -> IpaScalar {
    let mut hasher = Blake3Hasher::new();
    hasher.update(&commitment.index.to_le_bytes());
    hasher.update(&commitment.offset.to_le_bytes());
    hasher.update(&commitment.length.to_le_bytes());
    hasher.update(commitment.commitment.as_bytes());
    hasher.update(&[commitment.parity as u8, role_tag(commitment.role)]);
    hasher.update(&commitment.group_id.to_le_bytes());
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    IpaScalar::from_uniform(&wide)
}
#[cfg(feature = "ipa-commitment")]
pub fn ipa_commitment_from_chunks(
    commitments: &[ChunkCommitment],
) -> Result<BlobDigest, (StatusCode, String)> {
    if commitments.is_empty() {
        return Ok(BlobDigest::default());
    }
    let params_len = ipa_params_len_for_commitment_count(commitments.len())?;
    let params = IpaCurveParams::new(params_len).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to derive IPA parameters: {err}"),
        )
    })?;
    let mut scalars: Vec<IpaScalar> = commitments.iter().map(ipa_scalar_from_chunk).collect();
    while scalars.len() < params_len {
        scalars.push(IpaScalar::zero());
    }
    let poly = IpaPolynomial::from_coeffs(scalars);
    let commitment = poly.commit(&params).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to commit IPA vector: {err}"),
        )
    })?;
    Ok(BlobDigest::new(commitment.to_bytes()))
}
#[cfg(not(feature = "ipa-commitment"))]
pub fn ipa_commitment_from_chunks(
    _commitments: &[ChunkCommitment],
) -> Result<BlobDigest, (StatusCode, String)> {
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "IPA commitments require the `ipa-commitment` feature".to_owned(),
    ))
}
#[cfg(any(feature = "ipa-commitment", test))]
fn ipa_params_len_for_commitment_count(count: usize) -> Result<usize, (StatusCode, String)> {
    if count == 0 {
        return Ok(1);
    }
    count.checked_next_power_of_two().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "chunk count exceeds supported IPA commitment parameter size".to_owned(),
        )
    })
}
fn compute_pdp_commitment(
    manifest_digest: &BlobDigest,
    manifest: &DaManifestV1,
    chunk_store: &ChunkStore,
    canonical_payload: &[u8],
    sealed_at_unix: u64,
) -> Result<PdpCommitmentV1, (StatusCode, String)> {
    let tree = PdpMerkleTreeV1::from_bytes(canonical_payload).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("failed to build canonical PDP tree: {err}"),
        )
    })?;
    PdpCommitmentV1::from_tree(
        &tree,
        *manifest_digest.as_ref(),
        ChunkingProfileV1::from_profile(chunk_store.profile(), BLAKE3_256_MULTIHASH_CODE),
        compute_sample_window(manifest.total_size),
        sealed_at_unix,
    )
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}
#[derive(Debug)]
/// Manifest data captured during DA ingest for downstream spool writers.
pub(crate) struct ManifestArtifacts {
    pub(super) manifest: DaManifestV1,
    pub(super) encoded: Vec<u8>,
    pub(super) manifest_hash: BlobDigest,
    pub(super) blob_hash: BlobDigest,
    pub(super) chunk_root: BlobDigest,
    pub(super) storage_ticket: StorageTicketId,
    pub(super) fingerprint: ReplayFingerprint,
    pub(super) rent_gib: u64,
    pub(super) rent_months: u32,
}
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn resolve_manifest(
    request: &DaIngestRequest,
    chunk_store: &ChunkStore,
    canonical_payload: &[u8],
    metadata: &ExtraMetadata,
    enforced_retention: &RetentionPolicy,
    queued_at_unix: u64,
    rent_policy: &DaRentPolicyV1,
) -> Result<ManifestArtifacts, (StatusCode, String)> {
    resolve_manifest_with_observer(
        request,
        chunk_store,
        canonical_payload,
        metadata,
        enforced_retention,
        queued_at_unix,
        rent_policy,
        None,
    )
}
#[allow(clippy::too_many_arguments)]
fn resolve_manifest_with_observer(
    request: &DaIngestRequest,
    chunk_store: &ChunkStore,
    canonical_payload: &[u8],
    metadata: &ExtraMetadata,
    enforced_retention: &RetentionPolicy,
    queued_at_unix: u64,
    rent_policy: &DaRentPolicyV1,
    chunking_observer: Option<&dyn Fn(Duration)>,
) -> Result<ManifestArtifacts, (StatusCode, String)> {
    let blob_hash = BlobDigest::from_hash(*chunk_store.payload_digest());
    let chunk_root = BlobDigest::new(*chunk_store.por_tree().root());
    let (total_stripes_full, shards_per_stripe) =
        manifest_stripe_layout_fields(chunk_store.chunks().len(), &request.erasure_profile)?;
    let chunking_started = Instant::now();
    let chunk_commitments = build_chunk_commitments(request, chunk_store, canonical_payload)?;
    if let Some(observer) = chunking_observer {
        observer(chunking_started.elapsed());
    }
    let (rent_gib, rent_months) = rent_usage_from_request(request.total_size, enforced_retention)?;
    let rent_quote = rent_policy.quote(rent_gib, rent_months).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to compute DA rent quote: {err}"),
        )
    })?;
    let (manifest_template, supplied_taikai_issued_at_unix) = if let Some(bytes) =
        &request.norito_manifest
    {
        let manifest = decode_from_bytes::<DaManifestV1>(bytes).map_err(|err| {
            warn!(?err, "failed to decode DA manifest");
            (
                StatusCode::BAD_REQUEST,
                format!("failed to decode DA manifest: {err}"),
            )
        })?;
        let supplied_taikai_issued_at_unix = matches!(request.blob_class, BlobClass::TaikaiSegment)
            .then_some(manifest.issued_at_unix);
        if supplied_taikai_issued_at_unix == Some(0) {
            return Err((
                StatusCode::BAD_REQUEST,
                "caller-supplied Taikai manifest issued_at_unix must be greater than zero"
                    .to_owned(),
            ));
        }
        let expected_ipa = ipa_commitment_from_chunks(&chunk_commitments)?;
        let ipa_commitment = if manifest.ipa_commitment.is_zero() {
            expected_ipa
        } else if manifest.ipa_commitment == expected_ipa {
            manifest.ipa_commitment
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                "manifest ipa_commitment does not match computed value".into(),
            ));
        };
        verify_manifest_against_request(
            request,
            &manifest,
            enforced_retention,
            metadata,
            &chunk_commitments,
            blob_hash,
            chunk_root,
            &rent_quote,
        )?;
        (
            DaManifestV1 {
                version: manifest.version,
                storage_ticket: StorageTicketId::default(),
                total_stripes: total_stripes_full,
                shards_per_stripe,
                metadata: metadata.clone(),
                rent_quote,
                ipa_commitment,
                issued_at_unix: 0,
                ..manifest
            },
            supplied_taikai_issued_at_unix,
        )
    } else {
        let ipa_commitment = ipa_commitment_from_chunks(&chunk_commitments)?;
        (
            DaManifestV1 {
                version: DaManifestV1::VERSION,
                client_blob_id: request.client_blob_id.clone(),
                lane_id: request.lane_id,
                epoch: request.epoch,
                blob_class: request.blob_class,
                codec: request.codec.clone(),
                blob_hash,
                chunk_root,
                storage_ticket: StorageTicketId::default(),
                total_size: request.total_size,
                chunk_size: request.chunk_size,
                total_stripes: total_stripes_full,
                shards_per_stripe,
                erasure_profile: request.erasure_profile,
                retention_policy: enforced_retention.clone(),
                rent_quote,
                chunks: chunk_commitments.clone(),
                ipa_commitment,
                metadata: metadata.clone(),
                issued_at_unix: 0,
            },
            None,
        )
    };
    let fingerprint = manifest_fingerprint(&manifest_template)?;
    let storage_ticket = StorageTicketId::new(*fingerprint.as_bytes());
    let manifest = DaManifestV1 {
        storage_ticket,
        issued_at_unix: supplied_taikai_issued_at_unix.unwrap_or(queued_at_unix),
        ..manifest_template
    };
    let encoded =
        to_bytes(&manifest).map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let manifest_hash = BlobDigest::from_hash(blake3_hash(&encoded));
    Ok(ManifestArtifacts {
        manifest,
        encoded,
        manifest_hash,
        blob_hash,
        chunk_root,
        storage_ticket,
        fingerprint,
        rent_gib,
        rent_months,
    })
}
fn build_da_commitment_record(
    request: &DaIngestRequest,
    manifest: &ManifestArtifacts,
    retention: &RetentionPolicy,
    operator_signature: &Signature,
    pdp_commitment_bytes: &[u8],
    proof_scheme: DaProofScheme,
) -> DaCommitmentRecord {
    let manifest_digest = ManifestDigest::new(*manifest.manifest_hash.as_bytes());
    let chunk_root = Hash::prehashed(*manifest.chunk_root.as_bytes());
    let proof_digest = Hash::new(pdp_commitment_bytes);
    DaCommitmentRecord::new(
        request.lane_id,
        request.epoch,
        request.sequence,
        request.client_blob_id.clone(),
        manifest_digest,
        proof_scheme,
        chunk_root,
        Some(proof_digest),
        retention.clone(),
        manifest.storage_ticket,
        operator_signature.clone(),
    )
}
fn record_da_rent_quote_metrics(
    telemetry: &MaybeTelemetry,
    cluster_label: &str,
    storage_class: StorageClass,
    rent_gib: u64,
    rent_months: u32,
    rent_quote: &DaRentQuote,
) {
    if !telemetry.is_enabled() {
        return;
    }
    let months_u64 = u64::from(rent_months);
    let gib_months = rent_gib.saturating_mul(months_u64);
    let storage_label = storage_class_label(storage_class);
    telemetry.with_metrics(|handle| {
        handle.record_da_rent_quote(cluster_label, storage_label, gib_months, rent_quote);
    });
}
fn record_da_chunking_metrics(telemetry: &MaybeTelemetry, elapsed: Duration) {
    if !telemetry.is_enabled() {
        return;
    }
    telemetry.with_metrics(|handle| {
        handle.observe_da_chunking_seconds(elapsed.as_secs_f64());
    });
}
fn record_da_receipt_metrics(
    telemetry: &MaybeTelemetry,
    lane_epoch: LaneEpoch,
    sequence: u64,
    outcome: &ReceiptInsertOutcome,
) {
    if !telemetry.is_enabled() {
        return;
    }
    let (outcome_label, cursor_advanced) = match outcome {
        ReceiptInsertOutcome::Stored { cursor_advanced } => ("stored", *cursor_advanced),
        ReceiptInsertOutcome::Duplicate { .. } => ("duplicate", false),
        ReceiptInsertOutcome::DuplicateFingerprintConflict { .. } => {
            ("duplicate_fingerprint_conflict", false)
        }
        ReceiptInsertOutcome::ReceiptConflict { .. } => ("receipt_conflict", false),
        ReceiptInsertOutcome::ManifestConflict { .. } => ("manifest_conflict", false),
        ReceiptInsertOutcome::StaleSequence { .. } => ("stale_sequence", false),
        ReceiptInsertOutcome::SequenceGap { .. } => ("sequence_gap", false),
    };
    telemetry.with_metrics(|handle| {
        handle.record_da_receipt_outcome(
            lane_epoch.lane_id.as_u32(),
            lane_epoch.epoch,
            sequence,
            outcome_label,
            cursor_advanced,
        );
    });
}
fn record_da_receipt_error_metrics(
    telemetry: &MaybeTelemetry,
    lane_epoch: LaneEpoch,
    sequence: u64,
) {
    if !telemetry.is_enabled() {
        return;
    }
    telemetry.with_metrics(|handle| {
        handle.record_da_receipt_outcome(
            lane_epoch.lane_id.as_u32(),
            lane_epoch.epoch,
            sequence,
            "error",
            false,
        );
    });
}
async fn flush_da_spool_batch(app: &crate::AppState, batch: DaSpoolBatch) -> DaSpoolBatchReport {
    if let Some(spooler) = app.da_spooler.as_ref() {
        spooler.submit(batch).await
    } else {
        batch.execute_sync()
    }
}
fn log_da_spool_failures(report: &DaSpoolBatchReport) {
    for action in report.actions() {
        if let Some(error) = action.error() {
            error!(
                kind = action.kind(),
                outcome = action.outcome_label(),
                error,
                "DA spool action failed"
            );
        }
    }
}
fn da_spool_rejection_response(
    report: &DaSpoolBatchReport,
    format: ResponseFormat,
) -> Option<Response> {
    for action in report.actions() {
        if let Some(error) = action.error() {
            let message = format!("DA spool action `{}` failed: {error}", action.kind());
            return Some(build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &message,
                format,
            ));
        }
    }
    let mut saw_receipt_log = false;
    for action in report.actions() {
        let Some(DaSpoolActionOutput::ReceiptOutcome(outcome)) = action.output() else {
            continue;
        };
        saw_receipt_log = true;
        match outcome {
            ReceiptInsertOutcome::Stored { .. } | ReceiptInsertOutcome::Duplicate { .. } => {}
            ReceiptInsertOutcome::DuplicateFingerprintConflict { .. } => {
                return Some(build_error_response(
                    StatusCode::CONFLICT,
                    "duplicate receipt replay fingerprint does not match the persisted receipt",
                    format,
                ));
            }
            ReceiptInsertOutcome::ReceiptConflict { .. } => {
                return Some(build_error_response(
                    StatusCode::CONFLICT,
                    "receipt sequence already used for different receipt evidence",
                    format,
                ));
            }
            ReceiptInsertOutcome::ManifestConflict { .. } => {
                return Some(build_error_response(
                    StatusCode::CONFLICT,
                    "receipt sequence already used for a different manifest",
                    format,
                ));
            }
            ReceiptInsertOutcome::StaleSequence { highest } => {
                let message = format!(
                    "sequence is stale relative to persisted DA receipts; highest stored sequence is {highest}"
                );
                return Some(build_error_response(StatusCode::CONFLICT, &message, format));
            }
            ReceiptInsertOutcome::SequenceGap {
                expected_next,
                observed,
            } => {
                let message = format!(
                    "receipt sequence {observed} skips required next DA receipt sequence {expected_next}"
                );
                return Some(build_error_response(StatusCode::CONFLICT, &message, format));
            }
        }
    }
    if !saw_receipt_log {
        return Some(build_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DA receipt log did not report an outcome",
            format,
        ));
    }
    None
}
fn spool_report_action_ok(report: &DaSpoolBatchReport, kind: &'static str) -> bool {
    report
        .actions()
        .iter()
        .any(|action| action.kind() == kind && action.error().is_none())
}
fn da_metadata_error(key: &str, message: impl Into<String>) -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        format!("invalid DA metadata `{key}`: {}", message.into()),
    )
}
fn validate_public_metadata_entry(
    entry: &MetadataEntry,
    key: &str,
) -> Result<(), (StatusCode, String)> {
    if entry.visibility != MetadataVisibility::Public {
        return Err(da_metadata_error(key, "must use public visibility"));
    }
    if !matches!(entry.encryption, MetadataEncryption::None) {
        return Err(da_metadata_error(key, "must not be encrypted"));
    }
    Ok(())
}
fn registry_alias_from_metadata(
    metadata: &ExtraMetadata,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(entry) = metadata
        .items
        .iter()
        .find(|entry| entry.key == META_DA_REGISTRY_ALIAS)
    else {
        return Ok(None);
    };
    validate_public_metadata_entry(entry, META_DA_REGISTRY_ALIAS)?;
    let value = std::str::from_utf8(&entry.value)
        .map_err(|_| da_metadata_error(META_DA_REGISTRY_ALIAS, "value must be valid UTF-8"))?
        .trim();
    if value.is_empty() {
        return Err(da_metadata_error(
            META_DA_REGISTRY_ALIAS,
            "alias must not be empty",
        ));
    }
    Ok(Some(value.to_owned()))
}
fn build_da_pin_intent(
    request: &DaIngestRequest,
    scope_authorization: DaPinScopeAuthorizationV1,
) -> DaPinIntent {
    DaPinIntent::new(request.authorization(), scope_authorization)
}
fn build_da_pin_scope(
    request: &DaIngestRequest,
    storage_ticket: StorageTicketId,
    manifest_hash: BlobDigest,
) -> Result<DaPinScopeV1, (StatusCode, String)> {
    let alias = registry_alias_from_metadata(&request.metadata)?;
    Ok(DaPinScopeV1::new(
        &request.authorization(),
        storage_ticket,
        ManifestDigest::new(*manifest_hash.as_bytes()),
        alias,
    ))
}
fn submitted_pin_scope_authorization(
    request: &DaIngestRequest,
    scope: DaPinScopeV1,
) -> Result<Option<DaPinScopeAuthorizationV1>, (StatusCode, String)> {
    if request.pin_scope_signatures.is_empty() {
        return Ok(None);
    }
    let authorization = request.pin_scope_authorization(scope);
    if !authorization.has_valid_canonical_signatures() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "DA pin-scope signatures are invalid or non-canonical".to_owned(),
        ));
    }
    Ok(Some(authorization))
}
#[allow(clippy::too_many_arguments)]
fn verify_manifest_against_request(
    request: &DaIngestRequest,
    manifest: &DaManifestV1,
    expected_retention: &RetentionPolicy,
    expected_metadata: &ExtraMetadata,
    computed_chunks: &[ChunkCommitment],
    blob_hash: BlobDigest,
    chunk_root: BlobDigest,
    expected_rent: &DaRentQuote,
) -> Result<(), (StatusCode, String)> {
    if manifest.version != DaManifestV1::VERSION {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported manifest version {}; expected {}",
                manifest.version,
                DaManifestV1::VERSION
            ),
        ));
    }
    if manifest.client_blob_id != request.client_blob_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest client_blob_id does not match ingest request".into(),
        ));
    }
    if manifest.lane_id != request.lane_id || manifest.epoch != request.epoch {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest lane/epoch do not match ingest request".into(),
        ));
    }
    if manifest.blob_class != request.blob_class || manifest.codec != request.codec {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest blob classification does not match ingest request".into(),
        ));
    }
    if manifest.total_size != request.total_size || manifest.chunk_size != request.chunk_size {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest total_size or chunk_size does not match ingest request".into(),
        ));
    }
    if manifest.erasure_profile != request.erasure_profile {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest erasure profile does not match ingest request".into(),
        ));
    }
    if manifest.retention_policy != *expected_retention {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest retention policy does not match ingest request".into(),
        ));
    }
    if manifest.metadata != *expected_metadata {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest metadata does not match ingest request".into(),
        ));
    }
    if manifest.rent_quote != *expected_rent {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest rent quote does not match configured policy".into(),
        ));
    }
    if manifest.blob_hash != blob_hash {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest blob_hash does not match canonical payload digest".into(),
        ));
    }
    if manifest.chunk_root != chunk_root {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest chunk_root does not match recomputed chunk root".into(),
        ));
    }
    if manifest.chunks.len() != computed_chunks.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest chunk count does not match chunker output".into(),
        ));
    }
    if manifest.blob_class == BlobClass::TaikaiSegment {
        taikai::validate_da_proof_tier(expected_metadata, manifest.retention_policy.storage_class)?;
    }
    for (expected, actual) in computed_chunks.iter().zip(manifest.chunks.iter()) {
        if expected.index != actual.index
            || expected.offset != actual.offset
            || expected.length != actual.length
            || expected.commitment != actual.commitment
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "manifest chunk commitment mismatch at index {}",
                    expected.index
                ),
            ));
        }
        if expected.parity != actual.parity {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("manifest parity flag mismatch at index {}", expected.index),
            ));
        }
        if expected.role != actual.role {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("manifest role mismatch at index {}", expected.index),
            ));
        }
        if expected.group_id != actual.group_id {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("manifest group_id mismatch at index {}", expected.index),
            ));
        }
    }
    Ok(())
}
fn build_error_response(status: StatusCode, message: &str, format: ResponseFormat) -> Response {
    let payload =
        iroha_torii_shared::ErrorEnvelope::new(error_code_for_status(status), message.to_owned());
    utils::respond_with_status_and_format(status, payload, format)
}
fn error_code_for_status(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
        StatusCode::TOO_MANY_REQUESTS => "too_many_requests",
        StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
        _ if status.is_client_error() => "client_error",
        _ if status.is_server_error() => "server_error",
        _ => "error",
    }
}
fn ceil_div_u64(value: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    if value == 0 {
        return 0;
    }
    value.div_ceil(divisor)
}
fn rent_usage_from_request(
    total_size: u64,
    retention: &RetentionPolicy,
) -> Result<(u64, u32), (StatusCode, String)> {
    let adjusted_size = total_size.max(1);
    let gib = ceil_div_u64(adjusted_size, BYTES_PER_GIB).max(1);
    let retention_secs = retention
        .hot_retention_secs
        .max(retention.cold_retention_secs)
        .max(1);
    let months_u64 = ceil_div_u64(retention_secs, SECS_PER_MONTH).max(1);
    let months_u32 = u32::try_from(months_u64).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "retention period exceeds supported rent quote month range".to_string(),
        )
    })?;
    Ok((gib, months_u32))
}
fn with_status(mut response: Response, status: StatusCode) -> Response {
    *response.status_mut() = status;
    response
}
#[derive(JsonSerialize, norito::derive::NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::da::ingest::DaIngestResponse")]
struct DaIngestResponse {
    status: &'static str,
    duplicate: bool,
    receipt: Option<DaIngestReceipt>,
    pin_scope: Option<DaPinScopeV1>,
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
