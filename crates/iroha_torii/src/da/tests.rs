//! DA ingest and persistence tests.
use super::*;
use crate::da::taikai;
use crate::da::taikai::taikai_ingest;
use crate::da::taikai::taikai_ingest::{
    AnchorSendError, AnchorSender, collect_pending_uploads, process_batch,
};
use crate::da::taikai::{
    TAIKAI_ANCHOR_INVALID_SUFFIX, TAIKAI_ANCHOR_READY_PREFIX, TAIKAI_ANCHOR_READY_SUFFIX,
    TAIKAI_ANCHOR_REQUEST_PREFIX, TAIKAI_ANCHOR_REQUEST_SUFFIX, TAIKAI_ANCHOR_SENTINEL_PREFIX,
    TAIKAI_ANCHOR_SENTINEL_SUFFIX, TAIKAI_SPOOL_SUBDIR, TAIKAI_TRM_LINEAGE_PREFIX,
    TAIKAI_TRM_LINEAGE_SUFFIX, TAIKAI_TRM_LOCK_PREFIX, TAIKAI_TRM_LOCK_SUFFIX,
    TAIKAI_TRM_PENDING_PREFIX, TAIKAI_TRM_PENDING_SUFFIX,
};
use crate::da::{
    DaReceiptLog, DaSpoolAction, DaSpoolActionOutput, DaSpoolBatch, DaSpooler, ReplayCursorStore,
};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use core::convert::TryInto;
use flate2::{Compression as FlateCompression, write::GzEncoder};
use http_body_util::BodyExt as _;
use iroha_config::parameters::actual::{
    DaTaikaiAnchor, LaneConfig as ConfigLaneConfig, Nexus as ConfigNexus, TelemetryProfile,
};
use iroha_core::{da::LaneEpoch, state::StateReadOnly, telemetry::Telemetry};
use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, Signature, SignatureOf};
use iroha_data_model::{
    account::AccountId,
    block::BlockHeader,
    da::{
        ingest::{DaIngestAdmissionLaneV1, DaIngestAdmissionPolicyV1, DaStripeLayout},
        types::{BlobDigest, DaRentQuote, StorageTicketId},
    },
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig as ModelLaneConfig},
    parameter::{Parameter, custom::CustomParameter},
    sorafs::pin_registry::{ManifestAliasBinding, ManifestDigest},
    taikai::{
        SegmentTimestamp, TAIKAI_ANCHOR_RECEIPT_SCHEMA_V1, TAIKAI_ANCHOR_RECEIPT_VERSION_V1,
        TaikaiAliasBinding, TaikaiAnchorReceiptBodyV1, TaikaiAnchorReceiptV1,
        TaikaiAvailabilityClass, TaikaiCarPointer, TaikaiCidIndexKey, TaikaiEnvelopeIndexes,
        TaikaiEventId, TaikaiRenditionId, TaikaiRenditionRouteV1, TaikaiRoutingManifestV1,
        TaikaiSegmentEnvelopeV1, TaikaiSegmentSigningBodyV1, TaikaiSegmentSigningManifestV1,
        TaikaiSegmentWindow, TaikaiStreamId, TaikaiTimeIndexKey,
    },
};
use iroha_model_base::name::Name;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::{json::Json, numeric::XorQuantity};
use iroha_telemetry::metrics::Metrics;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use norito::{
    DeserializePayload, from_bytes,
    json::{self, Value},
    to_bytes,
};
use reqwest::Url;
use sorafs_car::{CarBuildPlan, PersistedChunkRecord};
use sorafs_manifest::{
    BLAKE3_256_MULTIHASH_CODE, ChunkingProfileV1, CouncilSignature, ProviderAdmissionCouncilPolicy,
    canonical_manifest_root_cid,
    pdp::{PdpCommitmentV1, PdpMerkleTreeV1},
    pin_registry::{
        AliasBindingV1, AliasProofBundleV1, alias_merkle_root, alias_proof_signature_digest,
    },
};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, ErrorKind, Read, Write},
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, Barrier, LazyLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use tempfile::tempdir;
use tokio::{fs as async_fs, sync::Mutex as AsyncMutex};
fn checked_signature(private_key: &PrivateKey, payload: &[u8]) -> Signature {
    Signature::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn checked_taikai_segment_signature(
    private_key: &PrivateKey,
    body: &TaikaiSegmentSigningBodyV1,
) -> SignatureOf<TaikaiSegmentSigningBodyV1> {
    SignatureOf::try_new(private_key, body).expect("test Taikai segment signing should succeed")
}
fn checked_fixture_keypair(seed: Vec<u8>, algorithm: Algorithm) -> KeyPair {
    KeyPair::try_from_seed(seed, algorithm).expect("test fixture key derivation should succeed")
}
fn checked_fixture_ed25519_keypair(seed: u8) -> KeyPair {
    checked_fixture_keypair(vec![seed; 32], Algorithm::Ed25519)
}
fn checked_random_keypair() -> KeyPair {
    KeyPair::try_random().expect("test fixture random key generation should succeed")
}
fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm)
        .expect("test fixture algorithm-specific random key generation should succeed")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn da_ingest_compute_jobs_respect_configured_parallelism() {
    const LIMIT: usize = 2;
    let limiter = Arc::new(tokio::sync::Semaphore::new(LIMIT));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (started_tx, started_rx) = mpsc::channel();
    let mut release_senders = Vec::with_capacity(LIMIT);
    let mut tasks = Vec::with_capacity(LIMIT);
    for id in 0..LIMIT {
        let (release_tx, release_rx) = mpsc::channel();
        release_senders.push(Some(release_tx));
        let limiter = Arc::clone(&limiter);
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        let started_tx = started_tx.clone();
        tasks.push(tokio::spawn(run_da_ingest_compute_job(
            limiter,
            move || {
                let active_now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(active_now, Ordering::SeqCst);
                started_tx.send(id).expect("report started compute job");
                release_rx.recv().expect("release compute job");
                active.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, (StatusCode, String)>(id)
            },
        )));
    }
    drop(started_tx);
    let first = started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first compute job should start");
    let second = started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second compute job should start");
    assert_ne!(first, second);
    assert_eq!(peak.load(Ordering::SeqCst), LIMIT);
    let rejected_job_ran = Arc::new(AtomicBool::new(false));
    let rejected_job_ran_in_worker = Arc::clone(&rejected_job_ran);
    let err = tokio::time::timeout(
        Duration::from_secs(2),
        run_da_ingest_compute_job(Arc::clone(&limiter), move || {
            rejected_job_ran_in_worker.store(true, Ordering::SeqCst);
            Ok::<_, (StatusCode, String)>(())
        }),
    )
    .await
    .expect("saturated compute admission must return promptly")
    .expect_err("saturated compute admission must fail fast");
    assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(err.1.contains("capacity is saturated"));
    assert!(
        !rejected_job_ran.load(Ordering::SeqCst),
        "a rejected compute job must never reach a physical worker"
    );
    for sender in release_senders.into_iter().flatten() {
        let _ = sender.send(());
    }
    for task in tasks {
        task.await
            .expect("compute task should join")
            .expect("compute job should succeed");
    }
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(peak.load(Ordering::SeqCst), LIMIT);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_da_ingest_keeps_compute_permit_until_physical_worker_exits() {
    let limiter = Arc::new(tokio::sync::Semaphore::new(1));
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let task = tokio::spawn(run_da_ingest_compute_job(Arc::clone(&limiter), move || {
        started_tx.send(()).expect("report started compute job");
        release_rx.recv().expect("release physical compute job");
        Ok::<_, (StatusCode, String)>(())
    }));
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("physical compute job should start");
    task.abort();
    let join_error = task
        .await
        .expect_err("aborted request task should not complete normally");
    assert!(join_error.is_cancelled());
    assert!(
        limiter.clone().try_acquire_owned().is_err(),
        "request cancellation must not release capacity while physical work continues"
    );
    release_tx.send(()).expect("release physical compute job");
    let permit = tokio::time::timeout(Duration::from_secs(2), limiter.clone().acquire_owned())
        .await
        .expect("physical worker should release capacity")
        .expect("compute limiter should remain open");
    drop(permit);
}
#[test]
fn checked_fixture_ed25519_keypair_uses_fallible_seed_derivation() {
    assert_eq!(
        checked_fixture_ed25519_keypair(0x50).algorithm(),
        Algorithm::Ed25519
    );
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
    );
}
#[test]
fn replay_cursor_temp_path_keeps_suffixes() {
    let base = Path::new("/var/lib/iroha/replay_cursors.norito.json");
    let tmp = persistence::replay_cursor_temp_path(base);
    assert_eq!(
        tmp,
        Path::new("/var/lib/iroha/replay_cursors.norito.json.tmp")
    );
}
#[path = "tests/error_response_tests.rs"]
mod error_response_tests;
#[test]
fn parse_storage_ticket_hex_validates_variants() {
    let valid = format!("0x{}", "aa".repeat(32));
    let parsed = parse_storage_ticket_hex(&valid).expect("valid ticket");
    assert_eq!(parsed.len(), 32);
    assert!(parse_storage_ticket_hex("").is_err());
    assert!(parse_storage_ticket_hex("zz").is_err());
    assert!(parse_storage_ticket_hex("ab").is_err(), "too short");
}
fn spool_artifact_path(
    spool_dir: &Path,
    prefix: &str,
    ticket: &StorageTicketId,
    sequence: u64,
    fingerprint: [u8; 32],
) -> PathBuf {
    spool_artifact_path_for_key(
        spool_dir,
        prefix,
        LaneId::new(1),
        1,
        sequence,
        ticket,
        fingerprint,
    )
}
fn spool_artifact_path_for_key(
    spool_dir: &Path,
    prefix: &str,
    lane_id: LaneId,
    epoch: u64,
    sequence: u64,
    ticket: &StorageTicketId,
    fingerprint: [u8; 32],
) -> PathBuf {
    match prefix {
        "manifest-" | "pdp-commitment-" => {
            let file_name = if prefix == "manifest-" {
                "manifest.norito"
            } else {
                "pdp-commitment.norito"
            };
            let artifact_dir = persistence::ticket_artifact_dir(spool_dir, ticket);
            fs::create_dir_all(&artifact_dir).expect("create ticket artifact fixture directory");
            artifact_dir.join(file_name)
        }
        "da-commitment-" | "da-commitment-schedule-" | "da-pin-intent-" | "da-pin-scope-" => {
            let lane = lane_id.as_u32();
            let ticket_hex = hex::encode(ticket.as_bytes());
            let fingerprint_hex = hex::encode(fingerprint);
            spool_dir.join(format!(
                "{prefix}{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.norito"
            ))
        }
        other => panic!("unknown spool artifact prefix `{other}`"),
    }
}
fn write_sample_manifest_artifact(
    dir: &Path,
) -> (
    ManifestFixtureContext,
    persistence::LoadedManifestArtifact,
    BlobDigest,
) {
    let context = sample_manifest_context_for(BlobClass::NexusLaneSidecar);
    let ticket = context.artifacts.storage_ticket;
    let path = spool_artifact_path_for_key(
        dir,
        "manifest-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    fs::write(&path, &context.artifacts.encoded).expect("manifest artifact");
    let artifact =
        persistence::load_manifest_artifact_from_spool(dir, &ticket).expect("manifest artifact");
    let manifest_hash = BlobDigest::from_hash(blake3_hash(&artifact.bytes));
    (context, artifact, manifest_hash)
}
#[tokio::test]
async fn da_spooler_executes_batch_before_ack() {
    let marker = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let spooler = DaSpooler::spawn(
        NonZeroUsize::new(4).expect("non-zero queue"),
        NonZeroUsize::new(2).expect("non-zero batch"),
        crate::routing::MaybeTelemetry::disabled(),
    );
    let mut batch = DaSpoolBatch::new();
    let marker_for_action = Arc::clone(&marker);
    batch.push(DaSpoolAction::new("test_artifact", move || {
        marker_for_action.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(DaSpoolActionOutput::None)
    }));
    let report = spooler.submit(batch).await;
    assert_eq!(marker.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(report.actions().len(), 1);
    assert_eq!(report.actions()[0].kind(), "test_artifact");
    assert!(report.actions()[0].error().is_none());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn da_spooler_cancelled_pending_send_restores_queue_depth() {
    let spooler = DaSpooler::spawn(
        NonZeroUsize::new(1).expect("non-zero queue"),
        NonZeroUsize::new(1).expect("non-zero batch"),
        crate::routing::MaybeTelemetry::disabled(),
    );
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release_for_action = Arc::clone(&release);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut first_batch = DaSpoolBatch::new();
    first_batch.push(DaSpoolAction::new("blocked", move || {
        let _ = started_tx.send(());
        let (lock, wake) = &*release_for_action;
        let mut released = lock.lock().expect("release lock");
        while !*released {
            released = wake.wait(released).expect("release wait");
        }
        Ok(DaSpoolActionOutput::None)
    }));
    let first_spooler = Arc::clone(&spooler);
    let first = tokio::spawn(async move { first_spooler.submit(first_batch).await });
    started_rx.await.expect("first worker action started");

    let mut second_batch = DaSpoolBatch::new();
    second_batch.push(DaSpoolAction::new("queued", || {
        Ok(DaSpoolActionOutput::None)
    }));
    let second_spooler = Arc::clone(&spooler);
    let second = tokio::spawn(async move { second_spooler.submit(second_batch).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while spooler.queued_depth() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second batch must fill the bounded queue");

    let mut third_batch = DaSpoolBatch::new();
    third_batch.push(DaSpoolAction::new("cancelled", || {
        Ok(DaSpoolActionOutput::None)
    }));
    let third_spooler = Arc::clone(&spooler);
    let third = tokio::spawn(async move { third_spooler.submit(third_batch).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while spooler.queued_depth() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("third submit must wait behind the full queue");
    third.abort();
    assert!(
        third
            .await
            .expect_err("third submit must cancel")
            .is_cancelled()
    );
    assert_eq!(
        spooler.queued_depth(),
        1,
        "cancelling a pending send must release its reserved depth"
    );

    let (lock, wake) = &*release;
    *lock.lock().expect("release lock") = true;
    wake.notify_all();
    tokio::time::timeout(Duration::from_secs(2), first)
        .await
        .expect("first submit must finish")
        .expect("first submit task");
    tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("second submit must finish")
        .expect("second submit task");
    assert_eq!(spooler.queued_depth(), 0);
}
#[test]
fn da_spool_batch_reports_action_panic_as_error() {
    let marker = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new(
        "manifest",
        || -> Result<DaSpoolActionOutput, String> {
            panic!("panic during DA spool action");
        },
    ));
    let marker_for_action = Arc::clone(&marker);
    batch.push(DaSpoolAction::new("receipt_log", move || {
        marker_for_action.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(DaSpoolActionOutput::None)
    }));
    let report = batch.execute_sync();
    assert_eq!(marker.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(report.actions().len(), 2);
    assert_eq!(report.actions()[0].kind(), "manifest");
    let error = report.actions()[0]
        .error()
        .expect("panic must be reported as an action error");
    assert!(
        error.contains("panicked") && error.contains("panic during DA spool action"),
        "unexpected panic report: {error}"
    );
    assert_eq!(report.actions()[1].kind(), "receipt_log");
    assert!(report.actions()[1].error().is_none());
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("panic report must fail closed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn da_spool_batch_skips_commit_after_artifact_error() {
    let independent_marker = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let commit_marker = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new("manifest", || {
        Err("disk full".to_owned())
    }));
    let independent_marker_for_action = Arc::clone(&independent_marker);
    batch.push(DaSpoolAction::new("taikai_envelope", move || {
        independent_marker_for_action.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(DaSpoolActionOutput::None)
    }));
    let commit_marker_for_action = Arc::clone(&commit_marker);
    batch.push_commit(DaSpoolAction::new("receipt_log", move || {
        commit_marker_for_action.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(DaSpoolActionOutput::None)
    }));

    let report = batch.execute_sync();

    assert_eq!(
        independent_marker.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "independent artifact actions should still complete"
    );
    assert_eq!(
        commit_marker.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a failed artifact must prevent durable receipt publication"
    );
    assert_eq!(report.actions().len(), 2);
    assert_eq!(report.actions()[0].kind(), "manifest");
    assert_eq!(report.actions()[1].kind(), "taikai_envelope");
}
#[test]
fn da_spool_batch_runs_commit_after_artifacts_succeed() {
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut batch = DaSpoolBatch::new();
    let order_for_artifact = Arc::clone(&order);
    batch.push(DaSpoolAction::new("taikai_envelope", move || {
        order_for_artifact
            .lock()
            .expect("order lock")
            .push("artifact");
        Ok(DaSpoolActionOutput::None)
    }));
    let order_for_commit = Arc::clone(&order);
    batch.push_commit(DaSpoolAction::new("receipt_log", move || {
        order_for_commit.lock().expect("order lock").push("commit");
        Ok(DaSpoolActionOutput::None)
    }));

    let report = batch.execute_sync();

    assert_eq!(
        *order.lock().expect("order lock"),
        vec!["artifact", "commit"]
    );
    assert_eq!(report.actions().len(), 2);
    assert!(
        report
            .actions()
            .iter()
            .all(|action| action.error().is_none())
    );
}
#[tokio::test]
async fn da_spooler_reports_action_panic_before_ack() {
    let spooler = DaSpooler::spawn(
        NonZeroUsize::new(4).expect("non-zero queue"),
        NonZeroUsize::new(2).expect("non-zero batch"),
        crate::routing::MaybeTelemetry::disabled(),
    );
    let mut batch = DaSpoolBatch::new();
    batch.push(DaSpoolAction::new(
        "pdp_commitment",
        || -> Result<DaSpoolActionOutput, String> {
            std::panic::panic_any(1234_u64);
        },
    ));
    let report = spooler.submit(batch).await;
    assert_eq!(report.actions().len(), 1);
    assert_eq!(report.actions()[0].kind(), "pdp_commitment");
    let error = report.actions()[0]
        .error()
        .expect("panic must be reported before acknowledgement");
    assert!(
        error.contains("panicked") && error.contains("non-string panic payload"),
        "unexpected panic report: {error}"
    );
    let response = da_spool_rejection_response(&report, ResponseFormat::Json)
        .expect("panic report must fail closed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn load_manifest_from_spool_locates_ticket() {
    let dir = tempdir().expect("dir");
    let context = sample_manifest_context_for(BlobClass::NexusLaneSidecar);
    let ticket = context.artifacts.storage_ticket;
    let path = spool_artifact_path_for_key(
        dir.path(),
        "manifest-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    fs::write(&path, &context.artifacts.encoded).expect("manifest file");
    let bytes = persistence::load_manifest_from_spool(dir.path(), &ticket).expect("manifest bytes");
    assert_eq!(bytes, context.artifacts.encoded);
    let missing = StorageTicketId::new([0x55; 32]);
    let err =
        persistence::load_manifest_from_spool(dir.path(), &missing).expect_err("missing ticket");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
#[test]
fn load_pdp_commitment_from_spool_locates_ticket() {
    let dir = tempdir().expect("dir");
    let ticket = StorageTicketId::new([0x99; 32]);
    let path = spool_artifact_path(dir.path(), "pdp-commitment-", &ticket, 2, [0x55; 32]);
    let commitment = sample_pdp_commitment_for_tests();
    let bytes = encode_pdp_commitment_bytes(&commitment).expect("encode commitment");
    fs::write(&path, &bytes).expect("commitment file");
    let loaded =
        persistence::load_pdp_commitment_from_spool(dir.path(), &ticket).expect("commitment");
    assert_eq!(loaded, bytes);
    let missing = StorageTicketId::new([0x55; 32]);
    let err = persistence::load_pdp_commitment_from_spool(dir.path(), &missing)
        .expect_err("missing commitment");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
#[test]
fn load_manifest_from_spool_ignores_unrelated_flat_artifacts() {
    let dir = tempdir().expect("dir");
    let context = sample_manifest_context_for(BlobClass::NexusLaneSidecar);
    let ticket = context.artifacts.storage_ticket;
    let path = spool_artifact_path_for_key(
        dir.path(),
        "manifest-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    fs::write(&path, &context.artifacts.encoded).expect("manifest file");
    fs::create_dir(dir.path().join("manifest-malformed.norito"))
        .expect("create unrelated malformed flat artifact");
    let loaded = persistence::load_manifest_from_spool(dir.path(), &ticket)
        .expect("ticket-indexed manifest");
    assert_eq!(loaded, context.artifacts.encoded);
}
#[test]
fn load_manifest_from_spool_rejects_manifest_shaped_directory() {
    let dir = tempdir().expect("dir");
    let ticket = StorageTicketId::new([0x77; 32]);
    let path = spool_artifact_path(dir.path(), "manifest-", &ticket, 2, [0x44; 32]);
    fs::create_dir(path).expect("create manifest-shaped directory");
    let err = persistence::load_manifest_from_spool(dir.path(), &ticket)
        .expect_err("manifest-shaped directory must fail closed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("is not a direct regular file"),
        "unexpected error: {err}"
    );
}
#[test]
fn load_manifest_from_spool_rejects_body_ticket_mismatch() {
    let dir = tempdir().expect("dir");
    let context = sample_manifest_context_for(BlobClass::NexusLaneSidecar);
    let ticket = context.artifacts.storage_ticket;
    let path = spool_artifact_path_for_key(
        dir.path(),
        "manifest-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    let mut manifest = context.artifacts.manifest.clone();
    manifest.storage_ticket = StorageTicketId::new([0x99; 32]);
    let bytes = to_bytes(&manifest).expect("encode mismatched manifest");
    fs::write(&path, bytes).expect("manifest file");
    let err = persistence::load_manifest_from_spool(dir.path(), &ticket)
        .expect_err("body ticket mismatch must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn load_manifest_from_spool_rejects_fingerprint_mismatch() {
    let dir = tempdir().expect("dir");
    let context = sample_manifest_context_for(BlobClass::NexusLaneSidecar);
    let ticket = context.artifacts.storage_ticket;
    let path = spool_artifact_path_for_key(
        dir.path(),
        "manifest-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    let mut manifest = context.artifacts.manifest.clone();
    manifest.blob_hash = BlobDigest::new([0xA5; 32]);
    fs::write(
        &path,
        to_bytes(&manifest).expect("encode tampered manifest"),
    )
    .expect("manifest file");
    let err = persistence::load_manifest_from_spool(dir.path(), &ticket)
        .expect_err("canonical manifest fingerprint mismatch must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
#[cfg(unix)]
#[test]
fn load_manifest_from_spool_rejects_ticket_shard_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("dir");
    let context = sample_manifest_context_for(BlobClass::NexusLaneSidecar);
    let ticket = context.artifacts.storage_ticket;
    let ticket_hex = hex::encode(ticket.as_bytes());
    let artifacts_dir = dir.path().join("artifacts");
    fs::create_dir(&artifacts_dir).expect("create artifact index");
    let external_shard = dir.path().join("external-shard");
    let external_ticket = external_shard.join(&ticket_hex);
    fs::create_dir_all(&external_ticket).expect("create external ticket directory");
    fs::write(
        external_ticket.join("manifest.norito"),
        &context.artifacts.encoded,
    )
    .expect("write external manifest");
    symlink(&external_shard, artifacts_dir.join(&ticket_hex[..2]))
        .expect("create ticket shard symlink");
    let err = persistence::load_manifest_from_spool(dir.path(), &ticket)
        .expect_err("ticket shard symlink must fail closed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("DA spool path"),
        "unexpected ticket shard error: {err}"
    );
}
#[test]
fn load_pdp_commitment_from_spool_ignores_unrelated_flat_artifacts() {
    let dir = tempdir().expect("dir");
    let ticket = StorageTicketId::new([0x99; 32]);
    let path = spool_artifact_path(dir.path(), "pdp-commitment-", &ticket, 2, [0x55; 32]);
    let commitment = sample_pdp_commitment_for_tests();
    let bytes = encode_pdp_commitment_bytes(&commitment).expect("encode commitment");
    fs::write(path, &bytes).expect("commitment");
    fs::create_dir(dir.path().join("pdp-commitment-malformed.norito"))
        .expect("create unrelated malformed flat artifact");
    let loaded =
        persistence::load_pdp_commitment_from_spool(dir.path(), &ticket).expect("commitment");
    assert_eq!(loaded, bytes);
}
#[test]
fn load_pdp_commitment_from_spool_rejects_commitment_shaped_directory() {
    let dir = tempdir().expect("dir");
    let ticket = StorageTicketId::new([0x99; 32]);
    let path = spool_artifact_path(dir.path(), "pdp-commitment-", &ticket, 2, [0x55; 32]);
    fs::create_dir(path).expect("create PDP-shaped directory");
    let err = persistence::load_pdp_commitment_from_spool(dir.path(), &ticket)
        .expect_err("PDP-shaped directory must fail closed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("is not a direct regular file"),
        "unexpected error: {err}"
    );
}
#[cfg(unix)]
#[test]
fn load_pdp_commitment_from_spool_rejects_spool_dir_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("dir");
    let target = dir.path().join("pdp-spool-target");
    fs::create_dir(&target).expect("create target directory");
    let spool = dir.path().join("pdp-spool-link");
    symlink(&target, &spool).expect("create PDP spool symlink");
    let ticket = StorageTicketId::new([0x99; 32]);
    let err = persistence::load_pdp_commitment_from_spool(&spool, &ticket)
        .expect_err("symlinked PDP spool root must reject");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("DA spool path"),
        "unexpected PDP load error: {err}"
    );
    assert!(
        fs::symlink_metadata(&spool)
            .expect("inspect spool symlink")
            .file_type()
            .is_symlink(),
        "failed load should leave spool symlink visible"
    );
    assert!(
        target.exists(),
        "spool symlink target should not be removed"
    );
}
#[test]
fn load_pdp_commitment_from_spool_rejects_invalid_body() {
    let dir = tempdir().expect("dir");
    let ticket = StorageTicketId::new([0x99; 32]);
    let path = spool_artifact_path(dir.path(), "pdp-commitment-", &ticket, 2, [0x55; 32]);
    let mut commitment = sample_pdp_commitment_for_tests();
    commitment.manifest_digest = [0; 32];
    fs::write(
        &path,
        encode_pdp_commitment_bytes(&commitment).expect("encode commitment"),
    )
    .expect("commitment file");
    let err = persistence::load_pdp_commitment_from_spool(dir.path(), &ticket)
        .expect_err("invalid PDP body must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn pdp_commitment_header_value_matches_base64_payload() {
    let commitment = sample_pdp_commitment_for_tests();
    let bytes = encode_pdp_commitment_bytes(&commitment).expect("encode commitment");
    let header_value = pdp_commitment_header_value(&bytes).expect("header value");
    let expected = BASE64.encode(bytes);
    assert_eq!(header_value.to_str().expect("utf8 header"), expected);
}
#[test]
fn manifest_response_pdp_header_is_optional_when_missing() {
    let dir = tempdir().expect("dir");
    let (_context, manifest_artifact, manifest_hash) = write_sample_manifest_artifact(dir.path());
    let response =
        utils::respond_value_with_format(Value::Object(Default::default()), ResponseFormat::Json);
    let response = attach_pdp_commitment_header_from_spool(
        dir.path(),
        &manifest_artifact,
        &manifest_hash,
        response,
        ResponseFormat::Json,
    )
    .expect("missing PDP commitment should remain optional");
    assert!(
        !response
            .headers()
            .contains_key(HeaderName::from_static(HEADER_SORA_PDP_COMMITMENT)),
        "missing PDP commitment must not attach a header"
    );
}
#[test]
fn manifest_response_attaches_pdp_commitment_header() {
    let dir = tempdir().expect("dir");
    let (context, manifest_artifact, manifest_hash) = write_sample_manifest_artifact(dir.path());
    let ticket = context.artifacts.storage_ticket;
    let mut commitment = sample_pdp_commitment_for_tests();
    commitment.manifest_digest = *manifest_hash.as_bytes();
    let bytes = encode_pdp_commitment_bytes(&commitment).expect("encode commitment");
    let path = spool_artifact_path_for_key(
        dir.path(),
        "pdp-commitment-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    fs::write(&path, &bytes).expect("commitment file");
    let response =
        utils::respond_value_with_format(Value::Object(Default::default()), ResponseFormat::Json);
    let response = attach_pdp_commitment_header_from_spool(
        dir.path(),
        &manifest_artifact,
        &manifest_hash,
        response,
        ResponseFormat::Json,
    )
    .expect("valid PDP commitment should attach");
    let header = response
        .headers()
        .get(HeaderName::from_static(HEADER_SORA_PDP_COMMITMENT))
        .expect("PDP commitment header");
    assert_eq!(header.to_str().expect("header utf8"), BASE64.encode(bytes));
}
#[test]
fn manifest_response_rejects_corrupt_pdp_commitment_sidecar() {
    let dir = tempdir().expect("dir");
    let (context, manifest_artifact, manifest_hash) = write_sample_manifest_artifact(dir.path());
    let ticket = context.artifacts.storage_ticket;
    let path = spool_artifact_path_for_key(
        dir.path(),
        "pdp-commitment-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    fs::write(&path, b"not a PDP commitment").expect("commitment file");
    let response =
        utils::respond_value_with_format(Value::Object(Default::default()), ResponseFormat::Json);
    let err = attach_pdp_commitment_header_from_spool(
        dir.path(),
        &manifest_artifact,
        &manifest_hash,
        response,
        ResponseFormat::Json,
    )
    .expect_err("corrupt PDP commitment should fail manifest response");
    let response = axum::response::IntoResponse::into_response(err);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[test]
fn manifest_response_rejects_pdp_commitment_manifest_digest_mismatch() {
    let dir = tempdir().expect("dir");
    let (context, manifest_artifact, manifest_hash) = write_sample_manifest_artifact(dir.path());
    let ticket = context.artifacts.storage_ticket;
    let mut commitment = sample_pdp_commitment_for_tests();
    commitment.manifest_digest = *manifest_hash.as_bytes();
    commitment.manifest_digest[0] ^= 0xFF;
    let bytes = encode_pdp_commitment_bytes(&commitment).expect("encode commitment");
    let path = spool_artifact_path_for_key(
        dir.path(),
        "pdp-commitment-",
        context.request.lane_id,
        context.request.epoch,
        context.request.sequence,
        &ticket,
        *context.artifacts.fingerprint.as_bytes(),
    );
    fs::write(&path, &bytes).expect("digest-mismatched PDP commitment");
    let response =
        utils::respond_value_with_format(Value::Object(Default::default()), ResponseFormat::Json);
    let err = attach_pdp_commitment_header_from_spool(
        dir.path(),
        &manifest_artifact,
        &manifest_hash,
        response,
        ResponseFormat::Json,
    )
    .expect_err("wrong-digest PDP commitment should fail manifest response");
    let response = axum::response::IntoResponse::into_response(err);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
fn taikai_metadata() -> ExtraMetadata {
    ExtraMetadata {
        items: vec![
            MetadataEntry::new(
                taikai::META_TAIKAI_EVENT_ID,
                b"global-keynote".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_STREAM_ID,
                b"stage-a".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_RENDITION_ID,
                b"1080p".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_TRACK_KIND,
                b"video".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_TRACK_CODEC,
                b"av1-main".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_TRACK_BITRATE,
                b"8000".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_TRACK_RESOLUTION,
                b"1920x1080".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_SEGMENT_SEQUENCE,
                b"42".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_SEGMENT_START,
                b"3600000".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_SEGMENT_DURATION,
                b"2000000".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_WALLCLOCK_MS,
                b"1702560000000".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_INGEST_LATENCY_MS,
                b"120".to_vec(),
                MetadataVisibility::Public,
            ),
            MetadataEntry::new(
                taikai::META_TAIKAI_INGEST_NODE_ID,
                b"ingest-node-1".to_vec(),
                MetadataVisibility::Public,
            ),
        ],
    }
}
#[test]
fn taikai_availability_defaults_without_trm() {
    let metadata = taikai_metadata();
    let availability = taikai::taikai_availability_from_metadata(&metadata, None).expect("derive");
    assert!(availability.is_none());
}
#[test]
fn taikai_availability_uses_trm_payload() {
    let metadata = taikai_metadata();
    let mut manifest = sample_trm_manifest();
    manifest.renditions[0].availability_class = TaikaiAvailabilityClass::Warm;
    let bytes = to_bytes(&manifest).expect("encode trm");
    let availability = taikai::taikai_availability_from_metadata(&metadata, Some(&bytes))
        .expect("derive")
        .expect("class");
    assert_eq!(availability, TaikaiAvailabilityClass::Warm);
}

#[test]
fn taikai_availability_rejects_duplicate_consumed_metadata() {
    let mut metadata = taikai_metadata();
    metadata.items.push(MetadataEntry::new(
        taikai::META_TAIKAI_EVENT_ID,
        b"shadow-event".to_vec(),
        MetadataVisibility::Public,
    ));
    let bytes = to_bytes(&sample_trm_manifest()).expect("encode trm");
    let err = taikai::taikai_availability_from_metadata(&metadata, Some(&bytes))
        .expect_err("duplicate Taikai metadata must reject before routing selection");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("metadata entry must appear at most once"),
        "unexpected duplicate-metadata error: {}",
        err.1
    );
}

#[test]
fn taikai_availability_rejects_rendition_window_that_misses_segment() {
    let metadata = taikai_metadata();
    let mut manifest = sample_trm_manifest();
    manifest.renditions[0].ssm_range = TaikaiSegmentWindow::new(50, 64);
    let bytes = to_bytes(&manifest).expect("encode trm");
    let err = taikai::taikai_availability_from_metadata(&metadata, Some(&bytes))
        .expect_err("out-of-window rendition must not select a retention policy");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("rendition `1080p` signing window"),
        "unexpected error: {}",
        err.1
    );
}
#[test]
fn taikai_ingest_tags_include_availability_and_proof_policy() {
    let mut metadata = taikai_metadata();
    metadata.items.extend([
        MetadataEntry::new(
            taikai::META_TAIKAI_AVAILABILITY_CLASS,
            b"hot".to_vec(),
            MetadataVisibility::Public,
        ),
        MetadataEntry::new(
            taikai::META_TAIKAI_AVAILABILITY_CLASS,
            b"warm".to_vec(),
            MetadataVisibility::Public,
        ),
    ]);
    let retention = RetentionPolicy {
        hot_retention_secs: 3_600,
        cold_retention_secs: 12 * 60 * 60,
        required_replicas: 4,
        storage_class: StorageClass::Warm,
        governance_tag: GovernanceTag::new("da.taikai.test"),
    };
    taikai::apply_taikai_ingest_tags(
        &mut metadata,
        Some(TaikaiAvailabilityClass::Cold),
        &retention,
        1024,
    );
    fn value_for(metadata: &ExtraMetadata, key: &str) -> String {
        let entry = metadata
            .items
            .iter()
            .find(|entry| entry.key == key)
            .unwrap_or_else(|| panic!("missing metadata entry `{key}`"));
        String::from_utf8(entry.value.clone()).expect("utf8 value")
    }
    assert_eq!(
        value_for(&metadata, taikai::META_TAIKAI_AVAILABILITY_CLASS),
        "cold"
    );
    assert_eq!(
        metadata
            .items
            .iter()
            .filter(|entry| entry.key == taikai::META_TAIKAI_AVAILABILITY_CLASS)
            .count(),
        1,
        "server-derived tags must replace every submitted copy"
    );
    assert_eq!(value_for(&metadata, taikai::META_DA_PROOF_TIER), "warm");
    assert_eq!(
        value_for(&metadata, taikai::META_TAIKAI_REPLICATION_REPLICAS),
        "4"
    );
    assert_eq!(
        value_for(&metadata, taikai::META_TAIKAI_REPLICATION_STORAGE),
        "warm"
    );
    assert_eq!(
        value_for(&metadata, taikai::META_TAIKAI_REPLICATION_HOT_SECS),
        "3600"
    );
    assert_eq!(
        value_for(&metadata, taikai::META_TAIKAI_REPLICATION_COLD_SECS),
        "43200"
    );
    assert_eq!(
        value_for(&metadata, taikai::META_DA_PDP_SAMPLE_WINDOW),
        "32"
    );
    assert_eq!(
        value_for(&metadata, taikai::META_DA_POTR_SAMPLE_WINDOW),
        "32"
    );
}
fn taikai_manifest_fixture() -> (DaIngestRequest, ManifestArtifacts) {
    let mut request = sample_request();
    request.metadata = taikai_metadata();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let mut metadata = request.metadata.clone();
    taikai::apply_taikai_ingest_tags(
        &mut metadata,
        Some(TaikaiAvailabilityClass::Hot),
        &request.retention_policy,
        request.total_size,
    );
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        0,
        &rent_policy,
    )
    .expect("manifest");
    (request, manifest)
}
#[test]
fn verify_manifest_rejects_missing_proof_tier() {
    let (request, manifest) = taikai_manifest_fixture();
    let mut tampered = manifest.manifest.clone();
    tampered
        .metadata
        .items
        .retain(|entry| entry.key != taikai::META_DA_PROOF_TIER);
    let err = verify_manifest_against_request(
        &request,
        &tampered,
        &request.retention_policy,
        &tampered.metadata,
        &tampered.chunks,
        manifest.blob_hash,
        manifest.chunk_root,
        &manifest.manifest.rent_quote,
    )
    .expect_err("missing proof tier must be rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
fn sample_pdp_commitment_for_tests() -> PdpCommitmentV1 {
    let tree = PdpMerkleTreeV1::from_bytes(&[0x44; 8_193]).expect("fixture PDP tree");
    PdpCommitmentV1::from_tree(
        &tree,
        [0x11; 32],
        ChunkingProfileV1::from_profile(
            chunk_profile_for_request(64 * 1024),
            BLAKE3_256_MULTIHASH_CODE,
        ),
        32,
        1_707_300_000,
    )
    .expect("fixture PDP commitment")
}
fn encode_alias_proof_bytes(
    (alias_namespace, alias_name): (&str, &str),
    manifest_cid: &[u8],
    bound_epoch: u64,
    expiry_epoch: u64,
    generated_at_unix: u64,
    expires_at_hint: u64,
    council_seeds: &[[u8; 32]],
) -> Vec<u8> {
    let binding = AliasBindingV1 {
        alias: format!("{alias_namespace}/{alias_name}"),
        manifest_cid: manifest_cid.to_vec(),
        bound_at: bound_epoch,
        expiry_epoch,
    };
    let mut bundle = AliasProofBundleV1 {
        binding,
        registry_root: [0u8; 32],
        registry_height: 1,
        generated_at_unix,
        expires_at_unix: expires_at_hint.max(generated_at_unix + 1),
        merkle_path: Vec::new(),
        council_signatures: Vec::new(),
    };
    bundle.registry_root =
        alias_merkle_root(&bundle.binding, &bundle.merkle_path).expect("compute alias proof root");
    let digest = alias_proof_signature_digest(&bundle);
    bundle.council_signatures = council_seeds
        .iter()
        .map(|seed| {
            let keypair = alias_council_keypair(seed);
            let signature = checked_signature(keypair.private_key(), digest.as_ref());
            let (_, signer_bytes) = keypair
                .public_key()
                .try_to_bytes()
                .expect("fixture public key must be valid");
            CouncilSignature {
                signer: signer_bytes.try_into().expect("ed25519 pk length"),
                signature: signature.payload().to_vec(),
            }
        })
        .collect();
    bundle
        .council_signatures
        .sort_by_key(|signature| signature.signer);
    to_bytes(&bundle).expect("encode alias proof")
}
fn alias_council_keypair(seed: &[u8; 32]) -> KeyPair {
    let private = PrivateKey::from_bytes(Algorithm::Ed25519, seed).expect("seeded council key");
    KeyPair::from_private_key(private).expect("derive council keypair")
}
fn alias_council_policy(
    council_seeds: &[[u8; 32]],
    threshold: usize,
) -> ProviderAdmissionCouncilPolicy {
    let trusted_signers = council_seeds.iter().map(|seed| {
        let keypair = alias_council_keypair(seed);
        let (_, signer_bytes) = keypair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key must be valid");
        signer_bytes.try_into().expect("ed25519 pk length")
    });
    ProviderAdmissionCouncilPolicy::new(trusted_signers, threshold)
        .expect("valid fixture council policy")
}
fn build_ssm_bytes(
    manifest_hash: BlobDigest,
    car_digest: BlobDigest,
    envelope_hash: BlobDigest,
    segment_sequence: u64,
    generated_at_unix: u64,
    expires_at_hint: u64,
) -> Vec<u8> {
    build_ssm_bytes_with_alias_council(
        manifest_hash,
        manifest_hash,
        car_digest,
        envelope_hash,
        segment_sequence,
        generated_at_unix,
        expires_at_hint,
        Algorithm::Ed25519,
        &[[0x33; 32]],
    )
}
fn build_ssm_bytes_with_publisher_algorithm(
    manifest_hash: BlobDigest,
    car_digest: BlobDigest,
    envelope_hash: BlobDigest,
    segment_sequence: u64,
    generated_at_unix: u64,
    expires_at_hint: u64,
    publisher_algorithm: Algorithm,
) -> Vec<u8> {
    build_ssm_bytes_with_alias_council(
        manifest_hash,
        manifest_hash,
        car_digest,
        envelope_hash,
        segment_sequence,
        generated_at_unix,
        expires_at_hint,
        publisher_algorithm,
        &[[0x33; 32]],
    )
}
#[allow(clippy::too_many_arguments)]
fn build_ssm_bytes_with_alias_council(
    manifest_hash: BlobDigest,
    alias_manifest_hash: BlobDigest,
    car_digest: BlobDigest,
    envelope_hash: BlobDigest,
    segment_sequence: u64,
    generated_at_unix: u64,
    expires_at_hint: u64,
    publisher_algorithm: Algorithm,
    council_seeds: &[[u8; 32]],
) -> Vec<u8> {
    build_ssm_bytes_with_alias_council_and_body_mutation(
        manifest_hash,
        alias_manifest_hash,
        car_digest,
        envelope_hash,
        segment_sequence,
        generated_at_unix,
        expires_at_hint,
        publisher_algorithm,
        council_seeds,
        |_| {},
    )
}

#[allow(clippy::too_many_arguments)]
fn build_ssm_bytes_with_alias_council_and_body_mutation<F>(
    manifest_hash: BlobDigest,
    alias_manifest_hash: BlobDigest,
    car_digest: BlobDigest,
    envelope_hash: BlobDigest,
    segment_sequence: u64,
    generated_at_unix: u64,
    expires_at_hint: u64,
    publisher_algorithm: Algorithm,
    council_seeds: &[[u8; 32]],
    mutate_body: F,
) -> Vec<u8>
where
    F: FnOnce(&mut TaikaiSegmentSigningBodyV1),
{
    let manifest_cid = canonical_manifest_root_cid(*alias_manifest_hash.as_bytes());
    let alias_proof = encode_alias_proof_bytes(
        ("sora", "docs"),
        &manifest_cid,
        1,
        32,
        generated_at_unix,
        expires_at_hint,
        council_seeds,
    );
    let alias_binding = ManifestAliasBinding {
        name: "docs".into(),
        namespace: "sora".into(),
        proof: alias_proof,
    };
    let publisher = checked_random_keypair_with_algorithm(publisher_algorithm);
    let publisher_account = AccountId::new(publisher.public_key().clone());
    let mut body = TaikaiSegmentSigningBodyV1::new(
        envelope_hash,
        manifest_hash,
        car_digest,
        segment_sequence,
        publisher_account,
        publisher.public_key().clone(),
        generated_at_unix * 1_000,
        alias_binding,
    );
    mutate_body(&mut body);
    let signature = checked_taikai_segment_signature(publisher.private_key(), &body);
    let manifest = TaikaiSegmentSigningManifestV1::new(body, signature);
    to_bytes(&manifest).expect("encode signing manifest")
}
fn sample_trm_manifest() -> TaikaiRoutingManifestV1 {
    let event_id = TaikaiEventId::new(Name::from_str("global-keynote").unwrap());
    let stream_id = TaikaiStreamId::new(Name::from_str("stage-a").unwrap());
    let rendition_id = TaikaiRenditionId::new(Name::from_str("1080p").unwrap());
    let route = TaikaiRenditionRouteV1 {
        rendition_id: rendition_id.clone(),
        latest_manifest_hash: BlobDigest::from_hash(blake3_hash(b"manifest")),
        latest_car: TaikaiCarPointer::new(
            "zbafyqra",
            BlobDigest::from_hash(blake3_hash(b"car")),
            131_072,
        ),
        availability_class: TaikaiAvailabilityClass::Hot,
        ssm_range: TaikaiSegmentWindow::new(40, 64),
    };
    TaikaiRoutingManifestV1 {
        version: TaikaiRoutingManifestV1::VERSION,
        event_id,
        stream_id,
        segment_window: TaikaiSegmentWindow::new(0, 64),
        renditions: vec![route],
        alias_binding: TaikaiAliasBinding {
            name: "docs".to_owned(),
            namespace: "sora".to_owned(),
            proof: vec![0xAB, 0xCD],
        },
    }
}
fn sample_trm_bytes() -> Vec<u8> {
    to_bytes(&sample_trm_manifest()).expect("encode trm")
}
fn sample_trm_manifest_for_envelope(
    envelope: &taikai_ingest::EnvelopeArtifacts,
) -> TaikaiRoutingManifestV1 {
    let mut manifest = sample_trm_manifest();
    manifest.renditions[0].latest_manifest_hash = envelope.ingest.manifest_hash;
    manifest.renditions[0].latest_car = envelope.ingest.car.clone();
    manifest
}
fn taikai_envelope_fixture() -> taikai_ingest::EnvelopeArtifacts {
    let (_, envelope) = taikai_ssm_validation_fixture();
    envelope
}
fn sample_request() -> DaIngestRequest {
    // Golden fixture tests must not depend on OS randomness.
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let payload = b"example".to_vec();
    DaIngestRequestIntentV1 {
        network_id: crate::signed_query_test_network_id(),
        owner: ALICE_ID.clone(),
        client_blob_id: BlobDigest::from_hash(blake3::hash(b"blob-id")),
        lane_id: LaneId::new(1),
        epoch: 5,
        sequence: 7,
        blob_class: BlobClass::TaikaiSegment,
        codec: BlobCodec::new("cmaf"),
        erasure_profile: ErasureProfile {
            data_shards: 8,
            parity_shards: 4,
            row_parity_stripes: 0,
            chunk_alignment: 2,
            fec_scheme: FecScheme::Rs12_10,
        },
        retention_policy: RetentionPolicy {
            hot_retention_secs: 3600,
            cold_retention_secs: 10 * 3600,
            required_replicas: 3,
            storage_class: StorageClass::Hot,
            governance_tag: GovernanceTag::new("baseline"),
        },
        chunk_size: 1 << 10,
        total_size: payload.len() as u64,
        payload_hash: BlobDigest::from_hash(blake3::hash(&payload)),
        compression: Compression::Identity,
        norito_manifest: None,
        payload,
        metadata: ExtraMetadata {
            items: vec![MetadataEntry::new(
                "content-type",
                b"video/cmaf".to_vec(),
                MetadataVisibility::Public,
            )],
        },
    }
    .try_sign(&keypair)
    .expect("sign canonical DA request fixture")
}

fn resign_sample_request(request: &mut DaIngestRequest) {
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    request.signatures.clear();
    request.pin_scope_signatures.clear();
    let signature = Signature::try_new(keypair.private_key(), &request.signing_digest())
        .expect("re-sign canonical DA request fixture");
    request.signatures.push(DaIngestSignatureV1 {
        signer: keypair.public_key().clone(),
        signature,
    });
}

fn signed_pin_intent(
    request: &DaIngestRequest,
    storage_ticket: StorageTicketId,
    manifest_hash: ManifestDigest,
    alias: Option<String>,
) -> DaPinIntent {
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let authorization = request.authorization();
    let scope = DaPinScopeV1::new(&authorization, storage_ticket, manifest_hash, alias);
    let scope_authorization = DaPinScopeAuthorizationV1::try_sign(scope, &keypair)
        .expect("sign canonical DA pin-scope fixture");
    DaPinIntent::new(authorization, scope_authorization)
}

fn signed_pin_intent_for_manifest(
    request: &DaIngestRequest,
    manifest: &ManifestArtifacts,
) -> DaPinIntent {
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let scope = build_da_pin_scope(request, manifest.storage_ticket, manifest.manifest_hash)
        .expect("build canonical DA pin scope");
    let scope_authorization =
        DaPinScopeAuthorizationV1::try_sign(scope, &keypair).expect("sign canonical DA pin scope");
    build_da_pin_intent(request, scope_authorization)
}

fn seed_da_admission_parameter(app: &crate::SharedAppState, parameter: CustomParameter) {
    let next_height = u64::try_from(app.state.view().height())
        .expect("test state height fits u64")
        .checked_add(1)
        .expect("test block height advances");
    let header = BlockHeader::new(
        NonZeroU64::new(next_height).expect("test block height is non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut transaction = block.transaction();
    transaction
        .world_mut_for_testing()
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(Parameter::Custom(parameter))
        .expect("valid fixture parameters");
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit governed DA admission test parameter");
}

fn da_admission_policy(
    lane_id: LaneId,
    lane_incarnation: Hash,
    producers: Vec<AccountId>,
    current_epoch: u64,
    grace_epoch: Option<u64>,
) -> DaIngestAdmissionPolicyV1 {
    let policy = DaIngestAdmissionPolicyV1 {
        version: DaIngestAdmissionPolicyV1::VERSION,
        revision: 1,
        expected_previous_policy_hash: None,
        lanes: vec![DaIngestAdmissionLaneV1 {
            lane_id,
            lane_incarnation,
            producers,
            current_epoch,
            grace_epoch,
        }],
    };
    policy
        .validate()
        .expect("DA admission test policy must be canonical");
    policy
}

#[tokio::test]
async fn da_ingest_admission_fails_closed_without_governed_policy() {
    let app = crate::mk_app_state_for_tests();
    let error = admission_snapshot_for_request(&app, &ALICE_ID, LaneId::SINGLE, 5)
        .expect_err("DA ingest without a committed policy must fail closed");

    assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error.1.contains("governance installs an admission policy"));
}

#[tokio::test]
async fn da_ingest_admission_fails_closed_for_malformed_governed_policy() {
    let app = crate::mk_app_state_for_tests();
    seed_da_admission_parameter(
        &app,
        CustomParameter::new(
            DaIngestAdmissionPolicyV1::parameter_id(),
            Json::new("not-a-da-admission-policy"),
        ),
    );

    let error = admission_snapshot_for_request(&app, &ALICE_ID, LaneId::SINGLE, 5)
        .expect_err("malformed committed DA admission policy must fail closed");
    assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        error
            .1
            .contains("committed DA ingest admission policy is invalid")
    );
}

#[tokio::test]
async fn da_ingest_admission_rejects_wrong_producer_and_epoch() {
    let app = crate::mk_app_state_for_tests();
    let lane_id = LaneId::SINGLE;
    let incarnation = app
        .state
        .view()
        .lane_incarnation_at_height(
            lane_id,
            u64::try_from(app.state.committed_height()).unwrap() + 1,
        )
        .expect("active canonical DA incarnation");
    let policy = da_admission_policy(lane_id, incarnation, vec![ALICE_ID.clone()], 5, Some(4));
    seed_da_admission_parameter(&app, policy.into_custom_parameter());

    for (owner, epoch, label) in [
        (&*BOB_ID, 5, "unlisted producer"),
        (&*ALICE_ID, 3, "retired epoch"),
        (&*ALICE_ID, 6, "future epoch"),
    ] {
        let error = admission_snapshot_for_request(&app, owner, lane_id, epoch).expect_err(label);
        assert_eq!(error.0, StatusCode::FORBIDDEN, "{label}");
    }
}

#[tokio::test]
async fn da_ingest_admission_accepts_current_and_grace_epochs_for_exact_scope() {
    let app = crate::mk_app_state_for_tests();
    let lane_id = LaneId::SINGLE;
    let incarnation = app
        .state
        .view()
        .lane_incarnation_at_height(
            lane_id,
            u64::try_from(app.state.committed_height()).unwrap() + 1,
        )
        .expect("active canonical DA incarnation");
    let policy = da_admission_policy(lane_id, incarnation, vec![ALICE_ID.clone()], 5, Some(4));
    seed_da_admission_parameter(&app, policy.into_custom_parameter());

    for epoch in [4, 5] {
        admission_snapshot_for_request(&app, &ALICE_ID, lane_id, epoch)
            .unwrap_or_else(|error| panic!("exact admitted epoch {epoch} rejected: {error:?}"));
    }
}

#[path = "tests/principal_binding_tests.rs"]
mod principal_binding_tests;
#[test]
fn compute_da_manifest_artifacts_builds_canonical_pipeline_outputs() {
    let spool = tempdir().expect("assignment spool");
    let mut request = sample_request();
    request.blob_class = BlobClass::NexusLaneSidecar;
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let digest = request.signing_digest();
    request.signatures[0].signature = checked_signature(keypair.private_key(), &digest);
    let replication_policy = DaReplicationPolicy::default();
    let rent_policy = DaRentPolicyV1::default();
    let nexus = nexus_with_scheme(request.lane_id, DaProofScheme::MerkleSha256);
    let computed = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        None,
        None,
        &replication_policy,
        &rent_policy,
        spool.path(),
        &keypair,
        None,
    )
    .expect("canonical DA compute pipeline");
    crate::frame_test_support::assert_current_frame(
        &computed.manifest.manifest,
        "iroha_data_model::da::manifest::DaManifestV1",
    );
    crate::frame_test_support::assert_current_frame(
        &computed.server_assignment,
        "iroha_torii::da::persistence::DaIngestServerAssignmentV1",
    );
    assert_eq!(computed.proof_scheme, DaProofScheme::MerkleSha256);
    assert_eq!(computed.canonical_payload, request.payload);
    assert_eq!(
        computed.manifest.manifest.retention_policy,
        computed.enforced_retention
    );
    assert_eq!(
        computed.manifest.manifest.total_size,
        computed.canonical_payload.len() as u64
    );
    assert_eq!(
        computed.chunk_store.payload_len(),
        computed.canonical_payload.len() as u64
    );
    assert!(computed.taikai_ssm_payload.is_none());
    assert!(computed.taikai_trm_payload.is_none());
    assert!(computed.queued_at_secs > 0);
}

fn governance_assignment_request() -> DaIngestRequest {
    let mut request = sample_request();
    request.blob_class = BlobClass::NexusLaneSidecar;
    request.metadata.items.push(MetadataEntry::new(
        "governance.retry-secret",
        b"freeze-this-plaintext".to_vec(),
        MetadataVisibility::GovernanceOnly,
    ));
    resign_sample_request(&mut request);
    request
}

#[test]
fn durable_server_assignment_survives_metadata_key_and_rent_policy_rotation() {
    let spool = tempdir().expect("assignment spool");
    let request = governance_assignment_request();
    let nexus = nexus_with_scheme(request.lane_id, DaProofScheme::MerkleSha256);
    let replication_policy = DaReplicationPolicy::default();
    let operator = checked_fixture_ed25519_keypair(0x52);
    let key = [0xA5; 32];
    let first = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        Some(&key),
        Some("before-rotation"),
        &replication_policy,
        &DaRentPolicyV1::default(),
        spool.path(),
        &operator,
        None,
    )
    .expect("compute initial server assignment");
    let frozen = persistence::load_or_create_da_ingest_server_assignment(
        spool.path(),
        &request,
        operator.public_key(),
        &first.server_assignment,
    )
    .expect("publish initial server assignment");
    let rotated_rent = DaRentPolicyV1 {
        base_rate_per_gib_month: "0.75".parse().expect("rotated rent rate"),
        ..Default::default()
    };
    let recovered = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        None,
        Some("after-rotation"),
        &replication_policy,
        &rotated_rent,
        spool.path(),
        &operator,
        None,
    )
    .expect("recover frozen server assignment without the retired metadata key");
    assert_eq!(recovered.server_assignment, frozen);
    assert_eq!(recovered.manifest.encoded, first.manifest.encoded);
    assert_eq!(recovered.queued_at_secs, first.queued_at_secs);
    assert_eq!(recovered.proof_scheme, first.proof_scheme);
    assert_eq!(
        recovered.manifest.manifest.rent_quote,
        first.manifest.manifest.rent_quote
    );
}

#[test]
fn concurrent_server_assignment_publishers_converge_on_one_replay_slot() {
    let spool = tempdir().expect("assignment spool");
    let request = governance_assignment_request();
    let nexus = nexus_with_scheme(request.lane_id, DaProofScheme::MerkleSha256);
    let replication_policy = DaReplicationPolicy::default();
    let rent_policy = DaRentPolicyV1::default();
    let operator = checked_fixture_ed25519_keypair(0x53);
    let key = [0xB6; 32];
    let first = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        Some(&key),
        Some("primary"),
        &replication_policy,
        &rent_policy,
        spool.path(),
        &operator,
        None,
    )
    .expect("compute first candidate")
    .server_assignment;
    let second = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        Some(&key),
        Some("primary"),
        &replication_policy,
        &rent_policy,
        spool.path(),
        &operator,
        None,
    )
    .expect("compute second candidate")
    .server_assignment;
    assert_ne!(
        first.transformed_metadata, second.transformed_metadata,
        "fresh candidates should exercise independent encryption nonces"
    );
    let (first_result, second_result) = std::thread::scope(|scope| {
        let first_thread = scope.spawn(|| {
            persistence::load_or_create_da_ingest_server_assignment(
                spool.path(),
                &request,
                operator.public_key(),
                &first,
            )
        });
        let second_thread = scope.spawn(|| {
            persistence::load_or_create_da_ingest_server_assignment(
                spool.path(),
                &request,
                operator.public_key(),
                &second,
            )
        });
        (
            first_thread.join().expect("first publisher joins"),
            second_thread.join().expect("second publisher joins"),
        )
    });
    let first_result = first_result.expect("first publisher converges");
    let second_result = second_result.expect("second publisher converges");
    assert_eq!(first_result, second_result);
    assert!(first_result == first || first_result == second);

    let mut conflicting_request = request.clone();
    conflicting_request.client_blob_id = BlobDigest::new([0xE4; 32]);
    resign_sample_request(&mut conflicting_request);
    let conflict = persistence::load_da_ingest_server_assignment(
        spool.path(),
        &conflicting_request,
        operator.public_key(),
    )
    .expect_err("one replay slot must reject a different signed request digest");
    assert_eq!(conflict.kind(), ErrorKind::AlreadyExists);

    let untrusted_operator = checked_fixture_ed25519_keypair(0x54);
    let untrusted = persistence::load_da_ingest_server_assignment(
        spool.path(),
        &request,
        untrusted_operator.public_key(),
    )
    .expect_err("assignment attestation must be verified against the trusted receipt signer");
    assert_eq!(untrusted.kind(), ErrorKind::InvalidData);
}

#[test]
fn signed_receipt_assignment_freezes_randomized_mldsa_signature() {
    let spool = tempdir().expect("assignment spool");
    let mut request = sample_request();
    request.blob_class = BlobClass::NexusLaneSidecar;
    resign_sample_request(&mut request);
    let nexus = nexus_with_scheme(request.lane_id, DaProofScheme::MerkleSha256);
    let operator = checked_random_keypair_with_algorithm(Algorithm::MlDsa);
    let computed = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        None,
        None,
        &DaReplicationPolicy::default(),
        &DaRentPolicyV1::default(),
        spool.path(),
        &operator,
        None,
    )
    .expect("compute ML-DSA assignment fixture");
    persistence::load_or_create_da_ingest_server_assignment(
        spool.path(),
        &request,
        operator.public_key(),
        &computed.server_assignment,
    )
    .expect("persist ML-DSA server assignment");
    let pdp = compute_pdp_commitment(
        &computed.manifest.manifest_hash,
        &computed.manifest.manifest,
        &computed.chunk_store,
        &computed.canonical_payload,
        computed.queued_at_secs,
    )
    .expect("compute PDP commitment");
    let pdp_bytes = encode_pdp_commitment_bytes(&pdp).expect("encode PDP commitment");
    let build_candidate = || {
        build_receipt(
            &operator,
            &request,
            computed.queued_at_secs,
            computed.manifest.blob_hash,
            computed.manifest.chunk_root,
            computed.manifest.manifest_hash,
            computed.manifest.storage_ticket,
            pdp_bytes.clone(),
            computed.manifest.manifest.rent_quote.clone(),
            stripe_layout_from_manifest(&computed.manifest.manifest),
        )
        .expect("sign ML-DSA receipt candidate")
    };
    let first = build_candidate();
    let second = build_candidate();
    assert_ne!(first.operator_signature, second.operator_signature);
    let frozen = persistence::load_or_create_da_ingest_signed_receipt(
        spool.path(),
        &request,
        operator.public_key(),
        &first,
    )
    .expect("persist first signed receipt");
    let retried = persistence::load_or_create_da_ingest_signed_receipt(
        spool.path(),
        &request,
        operator.public_key(),
        &second,
    )
    .expect("recover first signed receipt");
    assert_eq!(frozen, first);
    assert_eq!(retried, first);
}

#[test]
fn pin_intent_retry_adopts_randomized_mldsa_witness_bytes() {
    let spool = tempdir().expect("pin-intent spool");
    let mut request = sample_request();
    let primary = checked_random_keypair_with_algorithm(Algorithm::MlDsa);
    let pin_signer = checked_random_keypair_with_algorithm(Algorithm::MlDsa);
    request.signatures.clear();
    let request_digest = request.signing_digest();
    request.signatures.push(DaIngestSignatureV1 {
        signer: primary.public_key().clone(),
        signature: checked_signature(primary.private_key(), &request_digest),
    });
    let storage_ticket = StorageTicketId::new([0xD1; 32]);
    let manifest_hash = ManifestDigest::new([0xD2; 32]);
    let scope = DaPinScopeV1::new(
        &request.authorization(),
        storage_ticket,
        manifest_hash,
        None,
    );
    request
        .try_add_pin_scope_signature(&scope, &pin_signer)
        .expect("sign initial pin scope");
    let first = build_da_pin_intent(&request, request.pin_scope_authorization(scope.clone()));
    let mut retry = request.clone();
    let retry_digest = retry.signing_digest();
    retry.signatures[0].signature = checked_signature(primary.private_key(), &retry_digest);
    retry.pin_scope_signatures.clear();
    retry
        .try_add_pin_scope_signature(&scope, &pin_signer)
        .expect("re-sign retry pin scope");
    let second = build_da_pin_intent(&retry, retry.pin_scope_authorization(scope.clone()));
    assert_ne!(to_bytes(&first).unwrap(), to_bytes(&second).unwrap());
    let fingerprint = ReplayFingerprint::from(*storage_ticket.as_bytes());
    persistence::persist_da_pin_intent(
        spool.path(),
        &first,
        request.lane_id,
        request.epoch,
        request.sequence,
        &storage_ticket,
        &fingerprint,
    )
    .expect("persist first pin intent");
    persistence::persist_da_pin_intent(
        spool.path(),
        &second,
        retry.lane_id,
        retry.epoch,
        retry.sequence,
        &storage_ticket,
        &fingerprint,
    )
    .expect("semantic retry adopts frozen pin intent");
    let frozen = persistence::load_da_pin_intent(
        spool.path(),
        request.lane_id,
        request.epoch,
        request.sequence,
        &storage_ticket,
        &fingerprint,
    )
    .expect("reload frozen pin intent");
    assert_eq!(frozen, first);

    let different_pin_signer = checked_random_keypair_with_algorithm(Algorithm::MlDsa);
    let mut conflicting_retry = request.clone();
    conflicting_retry.pin_scope_signatures.clear();
    conflicting_retry
        .try_add_pin_scope_signature(&scope, &different_pin_signer)
        .expect("sign conflicting retry pin scope");
    let conflicting = build_da_pin_intent(
        &conflicting_retry,
        conflicting_retry.pin_scope_authorization(scope),
    );
    let error = persistence::select_da_pin_intent_for_persistence(
        spool.path(),
        &conflicting,
        request.lane_id,
        request.epoch,
        request.sequence,
        &storage_ticket,
        &fingerprint,
    )
    .expect_err("a different pin-scope signer set must conflict with the frozen intent");
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
}
#[test]
fn compute_da_manifest_artifacts_authenticates_before_lane_lookup() {
    let spool = tempdir().expect("DA assignment spool");
    let nexus = nexus_with_scheme(LaneId::new(1), DaProofScheme::MerkleSha256);
    let replication_policy = DaReplicationPolicy::default();
    let rent_policy = DaRentPolicyV1::default();
    let operator = checked_fixture_ed25519_keypair(0x51);
    let mut invalid_signature_valid_lane = sample_request();
    invalid_signature_valid_lane.sequence += 1;
    let mut invalid_signature_unknown_lane = invalid_signature_valid_lane.clone();
    invalid_signature_unknown_lane.lane_id = LaneId::new(99);
    let compute_error = |request: &DaIngestRequest| {
        compute_da_manifest_artifacts(
            request,
            &nexus,
            1,
            None,
            None,
            &replication_policy,
            &rent_policy,
            spool.path(),
            &operator,
            None,
        )
        .err()
        .expect("request must be rejected")
    };
    let valid_lane_error = compute_error(&invalid_signature_valid_lane);
    let unknown_lane_error = compute_error(&invalid_signature_unknown_lane);
    assert_eq!(
        unknown_lane_error, valid_lane_error,
        "an invalid signature must not reveal whether its lane is active"
    );
    assert_eq!(unknown_lane_error.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown_lane_error.1,
        "DA ingest request signature is invalid"
    );
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    invalid_signature_unknown_lane.signatures[0].signature = checked_signature(
        keypair.private_key(),
        &invalid_signature_unknown_lane.signing_digest(),
    );
    let authenticated_error = compute_error(&invalid_signature_unknown_lane);
    assert_eq!(authenticated_error.0, StatusCode::BAD_REQUEST);
    assert!(authenticated_error.1.contains("active lane catalog"));
}
fn lane_catalog_with_lanes(lanes: Vec<ModelLaneConfig>) -> LaneCatalog {
    let max_lane = lanes
        .iter()
        .map(|lane| lane.id.as_u32())
        .max()
        .unwrap_or_default();
    LaneCatalog::new(
        NonZeroU32::new(max_lane.saturating_add(1)).expect("lane count"),
        lanes,
    )
    .expect("lane catalog")
}
fn nexus_with_catalog(lane_catalog: LaneCatalog) -> ConfigNexus {
    let dataspace_catalog = DataSpaceCatalog::new(
        lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.dataspace_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|id| DataSpaceMetadata {
                id,
                alias: format!("ds-{}", id.as_u64()),
                description: None,
                fault_tolerance: 1,
            })
            .collect(),
    )
    .expect("dataspace catalog");
    ConfigNexus {
        lane_config: ConfigLaneConfig::from_catalog(&lane_catalog),
        lane_catalog,
        dataspace_catalog,
        ..Default::default()
    }
}
fn nexus_with_scheme(lane_id: LaneId, scheme: DaProofScheme) -> ConfigNexus {
    let lane = ModelLaneConfig {
        id: lane_id,
        dataspace_id: DataSpaceId::new(u64::from(lane_id.as_u32())),
        alias: format!("lane-{}", lane_id.as_u32()),
        proof_scheme: scheme,
        ..ModelLaneConfig::default()
    };
    nexus_with_catalog(lane_catalog_with_lanes(vec![lane]))
}
#[test]
fn validate_request_accepts_well_formed_payload() {
    let request = sample_request();
    let canonical = normalize_payload(&request).expect("normalize payload");
    assert!(validate_request(&request, canonical.as_slice()).is_ok());
}
#[test]
fn validate_request_rejects_non_power_two_chunks() {
    let mut request = sample_request();
    request.chunk_size = 1_500;
    let canonical = normalize_payload(&request).expect("normalize payload");
    let err = match validate_request(&request, canonical.as_slice()) {
        Ok(_) => panic!("expected validation to reject non power-of-two chunk size"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}
#[test]
fn validate_request_rejects_unbounded_erasure_work_before_allocation() {
    let canonical = sample_request().payload;
    let mut request = sample_request();
    request.erasure_profile.data_shards = MAX_DATA_SHARDS + 1;
    assert_eq!(
        validate_request(&request, &canonical)
            .expect_err("excess data shards must reject")
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut request = sample_request();
    request.erasure_profile.parity_shards = MAX_PARITY_SHARDS + 1;
    assert_eq!(
        validate_request(&request, &canonical)
            .expect_err("excess parity shards must reject")
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut request = sample_request();
    request.erasure_profile.row_parity_stripes = MAX_ROW_PARITY_STRIPES + 1;
    assert_eq!(
        validate_request(&request, &canonical)
            .expect_err("excess row parity must reject")
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut request = sample_request();
    request.total_size = MAX_CANONICAL_PAYLOAD_BYTES;
    request.chunk_size = MAX_CHUNK_SIZE_BYTES;
    request.erasure_profile.data_shards = 1;
    request.erasure_profile.parity_shards = MAX_PARITY_SHARDS;
    request.erasure_profile.row_parity_stripes = 0;
    let err = validate_request_shape(&request)
        .expect_err("multiplicative parity output must be rejected before allocation");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("generated-parity budget"));
    let mut request = sample_request();
    request.total_size = MAX_CANONICAL_PAYLOAD_BYTES;
    request.chunk_size = MAX_CHUNK_SIZE_BYTES;
    request.erasure_profile.data_shards = 2;
    // Keep generated parity below its cap so this fixture reaches the distinct
    // retained workspace bound: 72 MiB generated, 164 MiB workspace.
    request.erasure_profile.parity_shards = 2;
    request.erasure_profile.row_parity_stripes = 1;
    let err = validate_request_shape(&request)
        .expect_err("retained row-parity matrix must fit the workspace budget");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("RS16 workspace budget"));
}
#[test]
fn validate_request_rejects_excess_source_chunks_and_row_work() {
    let mut request = sample_request();
    request.total_size =
        u64::try_from(MAX_DATA_CHUNKS + 1).unwrap() * u64::from(request.chunk_size);
    let err = validate_request_shape(&request).expect_err("excess source chunks must be rejected");
    assert_eq!(err.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(err.1.contains("source-chunk limit"));
    let mut request = sample_request();
    request.erasure_profile.data_shards = 1;
    request.erasure_profile.row_parity_stripes = 1;
    request.total_size =
        u64::try_from(MAX_ROW_PARITY_SOURCE_STRIPES + 1).unwrap() * u64::from(request.chunk_size);
    let err = validate_request_shape(&request)
        .expect_err("cubic row-parity source count must be bounded");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("source-stripe computation limit"));
}
#[test]
fn validate_request_rejects_terminal_sequence() {
    let mut request = sample_request();
    request.sequence = u64::MAX;
    let err = validate_request_shape(&request)
        .expect_err("a terminal sequence must not poison the replay window");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("monotonic successor"));
}
#[test]
fn normalize_payload_rejects_claimed_decompression_bomb_before_decoding() {
    let mut request = sample_request();
    request.compression = Compression::Gzip;
    request.payload = vec![0x00];
    request.total_size = MAX_CANONICAL_PAYLOAD_BYTES + 1;
    let err = normalize_payload(&request)
        .expect_err("oversized decompressed length must reject before decoding");
    assert_eq!(err.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(err.1.contains("64 MiB"));
}
fn fingerprint_for_request(request: &DaIngestRequest) -> ReplayFingerprint {
    let canonical = normalize_payload(request).expect("normalize payload");
    let chunk_store = build_chunk_store(request, canonical.as_slice());
    let rent_policy = DaRentPolicyV1::default();
    resolve_manifest(
        request,
        &chunk_store,
        canonical.as_slice(),
        &request.metadata,
        &request.retention_policy,
        0,
        &rent_policy,
    )
    .expect("manifest")
    .fingerprint
}
#[test]
fn fingerprint_changes_with_client_blob_id() {
    let request = sample_request();
    let mut other = request.clone();
    other.client_blob_id = BlobDigest::from_hash(blake3::hash(b"different"));
    assert_ne!(
        fingerprint_for_request(&request),
        fingerprint_for_request(&other)
    );
}
#[test]
fn fingerprint_ignores_manifest_storage_ticket_and_timestamp() {
    let mut request = sample_request();
    request.blob_class = BlobClass::NexusLaneSidecar;
    let canonical = normalize_payload(&request)
        .expect("normalize payload")
        .into_vec();
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let rent_policy = DaRentPolicyV1::default();
    let baseline_manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &request.metadata,
        &request.retention_policy,
        7,
        &rent_policy,
    )
    .expect("manifest");
    request.norito_manifest =
        Some(to_bytes(&baseline_manifest.manifest).expect("encode baseline manifest"));
    let baseline = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &request.metadata,
        &request.retention_policy,
        7,
        &rent_policy,
    )
    .expect("manifest with provided bytes");
    let mut tampered = baseline.manifest.clone();
    tampered.storage_ticket = StorageTicketId::new([0xAB; 32]);
    tampered.issued_at_unix = 123_456;
    request.norito_manifest = Some(to_bytes(&tampered).expect("encode manifest"));
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &request.metadata,
        &request.retention_policy,
        7,
        &rent_policy,
    )
    .expect("manifest with provided bytes");
    assert_eq!(baseline.fingerprint, manifest.fingerprint);
    assert_eq!(manifest.manifest.issued_at_unix, 7);
}

#[test]
fn supplied_taikai_manifest_is_stable_across_server_queue_times() {
    let (mut request, mut supplied) = taikai_manifest_fixture();
    let canonical = normalize_payload(&request)
        .expect("normalize payload")
        .into_vec();
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let rent_policy = DaRentPolicyV1::default();
    let manifest_metadata = supplied.manifest.metadata.clone();
    supplied.manifest.issued_at_unix = 1_701_000_123;
    let supplied_bytes = to_bytes(&supplied.manifest).expect("encode caller-supplied manifest");
    let supplied_hash = BlobDigest::from_hash(blake3_hash(&supplied_bytes));
    request.norito_manifest = Some(supplied_bytes.clone());

    let first = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &manifest_metadata,
        &request.retention_policy,
        1_701_000_200,
        &rent_policy,
    )
    .expect("resolve supplied manifest at first queue time");
    let second = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &manifest_metadata,
        &request.retention_policy,
        1_701_000_900,
        &rent_policy,
    )
    .expect("resolve supplied manifest at later queue time");

    assert_eq!(first.manifest.issued_at_unix, 1_701_000_123);
    assert_eq!(first.manifest, supplied.manifest);
    assert_eq!(first.encoded, supplied_bytes);
    assert_eq!(first.manifest_hash, supplied_hash);
    assert_eq!(first.manifest, second.manifest);
    assert_eq!(first.encoded, second.encoded);
    assert_eq!(first.manifest_hash, second.manifest_hash);
    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(first.storage_ticket, second.storage_ticket);
}

#[test]
fn supplied_taikai_manifest_rejects_zero_issued_at() {
    let (mut request, mut supplied) = taikai_manifest_fixture();
    let canonical = normalize_payload(&request)
        .expect("normalize payload")
        .into_vec();
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let rent_policy = DaRentPolicyV1::default();
    let manifest_metadata = supplied.manifest.metadata.clone();
    supplied.manifest.issued_at_unix = 0;
    request.norito_manifest =
        Some(to_bytes(&supplied.manifest).expect("encode zero-time manifest"));

    let err = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &manifest_metadata,
        &request.retention_policy,
        1_701_000_200,
        &rent_policy,
    )
    .expect_err("zero caller-supplied Taikai issued_at_unix must reject");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("issued_at_unix must be greater than zero"),
        "unexpected zero issued_at_unix error: {}",
        err.1
    );
}

#[test]
fn taikai_ssm_requires_caller_supplied_manifest_in_compute_path() {
    let spool = tempdir().expect("assignment spool");
    let mut request = sample_request();
    request.metadata = taikai_metadata();
    request.metadata.items.push(MetadataEntry::new(
        taikai::META_TAIKAI_SSM,
        b"signed-manifest-placeholder".to_vec(),
        MetadataVisibility::Public,
    ));
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let digest = request.signing_digest();
    request.signatures[0].signature = checked_signature(keypair.private_key(), &digest);
    let nexus = nexus_with_scheme(request.lane_id, DaProofScheme::MerkleSha256);

    let err = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        None,
        None,
        &DaReplicationPolicy::default(),
        &DaRentPolicyV1::default(),
        spool.path(),
        &keypair,
        None,
    )
    .err()
    .expect("Taikai SSM without caller-supplied manifest must reject");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1
            .contains("require a caller-supplied `norito_manifest`"),
        "unexpected missing manifest error: {}",
        err.1
    );
}

#[test]
fn taikai_cache_hint_is_rejected_in_compute_path() {
    let mut request = sample_request();
    request.metadata = taikai_metadata();
    request.metadata.items.push(MetadataEntry::new(
        RETIRED_TAIKAI_CACHE_HINT_KEY,
        b"stale-cache-hint".to_vec(),
        MetadataVisibility::Public,
    ));
    let keypair = checked_fixture_keypair(vec![0x42; 32], Algorithm::Ed25519);
    let digest = request.signing_digest();
    request.signatures[0].signature = checked_signature(keypair.private_key(), &digest);
    let nexus = nexus_with_scheme(request.lane_id, DaProofScheme::MerkleSha256);

    let err = compute_da_manifest_artifacts(
        &request,
        &nexus,
        1,
        None,
        None,
        &DaReplicationPolicy::default(),
        &DaRentPolicyV1::default(),
        Path::new(""),
        &keypair,
        None,
    )
    .err()
    .expect("retired Taikai cache hint must reject");

    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(
        err.1.contains("`taikai.cache_hint` is not accepted in V1"),
        "unexpected retired cache-hint error: {}",
        err.1
    );
}

#[test]
fn lane_proof_scheme_rejects_stale_geometry_only_lane() {
    let stale_lane = LaneId::new(3);
    let authoritative_catalog = lane_catalog_with_lanes(vec![ModelLaneConfig::default()]);
    let stale_geometry_catalog = lane_catalog_with_lanes(vec![
        ModelLaneConfig::default(),
        ModelLaneConfig {
            id: stale_lane,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "stale-ingest".to_owned(),
            proof_scheme: DaProofScheme::MerkleSha256,
            ..ModelLaneConfig::default()
        },
    ]);
    let mut nexus = nexus_with_catalog(authoritative_catalog);
    nexus.lane_config = ConfigLaneConfig::from_catalog(&stale_geometry_catalog);
    assert!(
        nexus.lane_config.entry(stale_lane).is_some(),
        "test must seed derived geometry for the removed lane"
    );
    let err = lane_proof_scheme(&nexus, stale_lane, 1)
        .expect_err("stale geometry-only lane must not resolve a proof scheme");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("active lane catalog"));
}
#[test]
fn lane_proof_scheme_rejects_future_created_autoscale_lane_before_committed_height() {
    let lane_id = LaneId::new(1);
    let mut elastic_lane = ModelLaneConfig {
        id: lane_id,
        dataspace_id: DataSpaceId::UNIVERSAL,
        alias: "elastic-lane-1".to_owned(),
        proof_scheme: DaProofScheme::MerkleSha256,
        ..ModelLaneConfig::default()
    };
    elastic_lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_MANAGED.to_owned(),
        "true".to_owned(),
    );
    elastic_lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
        "7".to_owned(),
    );
    let keys = (0xa1_u8..=0xa4)
        .map(|seed| checked_fixture_keypair(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    crate::test_utils::pin_autoscale_lane_committee_for_test(&mut elastic_lane, &keys);
    let mut nexus = nexus_with_catalog(lane_catalog_with_lanes(vec![
        ModelLaneConfig::default(),
        elastic_lane,
    ]));
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("non-zero min lanes");
    nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(3).expect("non-zero max lanes");
    let err = lane_proof_scheme(&nexus, lane_id, 6)
        .expect_err("future-created autoscale lane must not resolve before creation height");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("active lane catalog"));
    let scheme = lane_proof_scheme(&nexus, lane_id, 7)
        .expect("autoscale lane should resolve at creation height");
    assert_eq!(scheme, DaProofScheme::MerkleSha256);
}
#[test]
fn taikai_envelope_generation_requires_metadata() {
    let request = sample_request();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let metadata = request.metadata.clone();
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        0,
        &rent_policy,
    )
    .expect("manifest");
    let err =
        match taikai_ingest::build_envelope(&manifest, &chunk_store, canonical.as_slice(), None) {
            Ok(_) => panic!("missing metadata must error"),
            Err(err) => err,
        };
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
}

fn taikai_envelope_error_with_metadata_value(key: &str, value: &[u8]) -> (StatusCode, String) {
    let mut request = sample_request();
    request.metadata = taikai_metadata();
    request
        .metadata
        .items
        .iter_mut()
        .find(|entry| entry.key == key)
        .expect("Taikai fixture metadata entry")
        .value = value.to_vec();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let metadata = request.metadata.clone();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        1,
        &DaRentPolicyV1::default(),
    )
    .expect("manifest");
    match taikai_ingest::build_envelope(&manifest, &chunk_store, canonical.as_slice(), None) {
        Ok(_) => panic!("zero-valued `{key}` metadata must fail"),
        Err(err) => err,
    }
}

#[test]
fn taikai_envelope_generation_rejects_zero_bitrate() {
    let err = taikai_envelope_error_with_metadata_value(taikai::META_TAIKAI_TRACK_BITRATE, b"0");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("must be greater than zero"));
}

#[test]
fn taikai_envelope_generation_rejects_zero_duration() {
    let err = taikai_envelope_error_with_metadata_value(taikai::META_TAIKAI_SEGMENT_DURATION, b"0");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    assert!(err.1.contains("must be greater than zero"));
}

#[test]
fn taikai_envelope_generation_computes_pointers() {
    let mut request = sample_request();
    request.metadata = taikai_metadata();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let metadata = request.metadata.clone();
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        1,
        &rent_policy,
    )
    .expect("manifest");
    let artifacts =
        taikai_ingest::build_envelope(&manifest, &chunk_store, canonical.as_slice(), None)
            .expect("taikai envelope");
    let envelope: TaikaiSegmentEnvelopeV1 =
        norito::decode_from_bytes(&artifacts.envelope_bytes).expect("decode framed envelope");
    assert_eq!(
        artifacts.envelope_bytes,
        to_bytes(&envelope).expect("re-encode framed envelope")
    );
    assert_eq!(
        envelope.event_id.as_name(),
        &Name::from_str("global-keynote").unwrap()
    );
    assert_eq!(envelope.segment_sequence, 42);
    assert_eq!(
        envelope.ingest.chunk_count,
        chunk_store.chunks().len() as u32
    );
    assert!(envelope.ingest.car.cid_multibase.starts_with('b'));
    let indexes: TaikaiEnvelopeIndexes =
        norito::json::from_slice(&artifacts.indexes_json).expect("decode indexes");
    assert_eq!(indexes.time_key.event_id, envelope.event_id);
    assert_eq!(
        indexes.cid_key.cid_multibase,
        envelope.ingest.car.cid_multibase
    );
}
#[test]
fn taikai_envelope_calls_chunking_observer() {
    let mut request = sample_request();
    request.metadata = taikai_metadata();
    let canonical = normalize_payload(&request).expect("normalize payload");
    let chunk_store = build_chunk_store(&request, canonical.as_slice());
    let metadata = request.metadata.clone();
    let rent_policy = DaRentPolicyV1::default();
    let manifest = resolve_manifest(
        &request,
        &chunk_store,
        canonical.as_slice(),
        &metadata,
        &request.retention_policy,
        1,
        &rent_policy,
    )
    .expect("manifest");
    let called = Cell::new(0u32);
    let observer = |_: Duration| {
        called.set(called.get() + 1);
    };
    taikai_ingest::build_envelope(
        &manifest,
        &chunk_store,
        canonical.as_slice(),
        Some(&observer),
    )
    .expect("envelope");
    assert_eq!(called.get(), 1);
}
#[test]
fn taikai_artifacts_persist_idempotent() {
    let dir = tempdir().expect("tempdir");
    let lane_id = LaneId::new(3);
    let epoch = 7;
    let sequence = 11;
    let storage_ticket = StorageTicketId::new([0x11; 32]);
    let fingerprint = ReplayFingerprint::from_hash(blake3::hash(b"fingerprint"));
    let envelope_path = taikai_ingest::persist_envelope(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"envelope",
    )
    .expect("persist envelope")
    .expect("path");
    assert!(envelope_path.exists());
    let index_path = taikai_ingest::persist_indexes(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"indexes",
    )
    .expect("persist indexes")
    .expect("path");
    assert!(index_path.exists());
    let trm_path = taikai_ingest::persist_trm(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"trm",
    )
    .expect("persist trm")
    .expect("path");
    assert!(trm_path.exists());
    let ssm_path = taikai_ingest::persist_ssm(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"ssm",
    )
    .expect("persist ssm")
    .expect("path");
    assert!(ssm_path.exists());
    let envelope_second = taikai_ingest::persist_envelope(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"envelope",
    )
    .expect("persist envelope second")
    .expect("path");
    assert_eq!(envelope_path, envelope_second);
    let index_second = taikai_ingest::persist_indexes(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"indexes",
    )
    .expect("persist indexes second")
    .expect("path");
    assert_eq!(index_path, index_second);
    let ssm_second = taikai_ingest::persist_ssm(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"ssm",
    )
    .expect("persist ssm second")
    .expect("path");
    assert_eq!(ssm_path, ssm_second);
    let trm_second = taikai_ingest::persist_trm(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"trm",
    )
    .expect("persist trm second")
    .expect("path");
    assert_eq!(trm_path, trm_second);
    let ready_path = taikai_ingest::persist_anchor_ready(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
    )
    .expect("persist readiness marker")
    .expect("readiness path");
    assert_eq!(
        fs::read(&ready_path).expect("read readiness"),
        b"ready-v1\n"
    );
    let err = taikai_ingest::persist_envelope(
        dir.path(),
        lane_id,
        epoch,
        sequence,
        &storage_ticket,
        &fingerprint,
        b"other",
    )
    .expect_err("mismatched envelope bytes must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
#[test]
fn taikai_anchor_readiness_does_not_recreate_retired_sources() {
    let dir = tempdir().expect("tempdir");
    let path = taikai_ingest::persist_anchor_ready(
        dir.path(),
        LaneId::new(3),
        7,
        11,
        &StorageTicketId::new([0x11; 32]),
        &ReplayFingerprint::from_hash(blake3::hash(b"fingerprint")),
    )
    .expect("missing source is an idempotent no-op");
    assert!(path.is_none());
}
#[cfg(unix)]
#[test]
fn taikai_artifact_persistence_rejects_spool_dir_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("taikai-write-target");
    fs::create_dir(&target).expect("create Taikai target directory");
    let spool_link = dir.path().join(TAIKAI_SPOOL_SUBDIR);
    symlink(&target, &spool_link).expect("create Taikai spool symlink");
    let lane_id = LaneId::new(3);
    let storage_ticket = StorageTicketId::new([0x11; 32]);
    let fingerprint = ReplayFingerprint::from_hash(blake3::hash(b"fingerprint"));
    let err = taikai_ingest::persist_envelope(
        dir.path(),
        lane_id,
        7,
        11,
        &storage_ticket,
        &fingerprint,
        b"envelope",
    )
    .expect_err("symlinked Taikai spool root must reject artifact persistence");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("Taikai spool directory"),
        "unexpected Taikai spool error: {err}"
    );
    assert!(
        fs::symlink_metadata(&spool_link)
            .expect("inspect Taikai spool symlink")
            .file_type()
            .is_symlink(),
        "failed persistence should leave Taikai spool symlink visible"
    );
    assert_eq!(
        fs::read_dir(&target)
            .expect("read Taikai target directory")
            .count(),
        0,
        "symlink target must not receive Taikai artifacts"
    );
}
#[test]
fn taikai_artifact_persistence_converges_under_same_process_writers() {
    let dir = tempdir().expect("tempdir");
    let spool_dir = dir.path().to_path_buf();
    let lane_id = LaneId::new(3);
    let epoch = 7;
    let sequence = 11;
    let storage_ticket = StorageTicketId::new([0x11; 32]);
    let fingerprint = ReplayFingerprint::from_hash(blake3::hash(b"fingerprint"));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::with_capacity(4);
    // Start every barrier participant before waiting for any worker.
    for _ in 0..4 {
        let spool_dir = spool_dir.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            taikai_ingest::persist_envelope(
                &spool_dir,
                lane_id,
                epoch,
                sequence,
                &storage_ticket,
                &fingerprint,
                b"envelope",
            )
            .expect("concurrent Taikai artifact persist")
            .expect("artifact path")
        }));
    }
    let paths: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("writer thread"))
        .collect();
    let first = paths.first().expect("at least one writer");
    assert!(paths.iter().all(|path| path == first));
    assert_eq!(fs::read(first).expect("read Taikai envelope"), b"envelope");
    assert!(
        temp_artifact_names(&dir.path().join(TAIKAI_SPOOL_SUBDIR)).is_empty(),
        "concurrent Taikai install should not leave temp artifacts"
    );
}
#[path = "tests/artifact_persistence.rs"]
mod artifact_persistence;
#[path = "tests/taikai_anchor_and_lineage.rs"]
mod taikai_anchor_and_lineage;
#[path = "tests/taikai_validation.rs"]
mod taikai_validation;
use artifact_persistence::{ManifestResolutionFixture, resolved_manifest_fixture};
#[path = "tests/receipt_journal_and_duplicates.rs"]
mod receipt_journal_and_duplicates;
use receipt_journal_and_duplicates::{
    open_receipt_log, receipt_fingerprint, receipt_spool_path, temp_artifact_names,
    test_fingerprint, test_receipt,
};
#[path = "tests/replay_manifest_and_metrics.rs"]
mod replay_manifest_and_metrics;
use replay_manifest_and_metrics::{
    ManifestFixtureContext, assert_replay_cursor_sequences, format_base_id,
    sample_manifest_context_for, telemetry_handle_for_tests, zero_sequence_manifest_context_for,
};
use taikai_validation::taikai_ssm_validation_fixture;

#[tokio::test]
async fn ingest_response_binary_body_advertises_exact_current_owner() {
    assert_eq!(
        <DaIngestResponse as norito::NoritoSchema>::nominal_name(),
        "iroha_torii::da::ingest::DaIngestResponse"
    );
    let value = DaIngestResponse {
        status: "pending_pin_authorization",
        duplicate: false,
        receipt: None,
        pin_scope: None,
    };
    let expected = norito::to_bytes(&value).expect("encode response frame");
    assert_eq!(
        &expected[6..22],
        &norito::schema::identity::frame_hash::<DaIngestResponse>()
    );
    let response = utils::respond_with_format(value, ResponseFormat::Norito);
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read response body");
    assert_eq!(body.as_ref(), expected.as_slice());
}
