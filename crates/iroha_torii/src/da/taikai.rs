//! Taikai ingest helpers and anchor integration for DA.

#![allow(clippy::redundant_pub_crate)]
use super::{ingest::ManifestArtifacts, persistence::DaReceiptLog, storage_class_label};
use crate::{routing::MaybeTelemetry, sorafs::AliasCachePolicy};
use async_trait::async_trait;
use axum::http::StatusCode;
use blake3::{Hasher as Blake3Hasher, hash as blake3_hash};
use iroha_config::parameters::actual::DaTaikaiAnchor;
use iroha_core::da::{LaneEpoch, ReplayFingerprint};
use iroha_data_model::{
    account::AccountId,
    da::prelude::*,
    sorafs::pin_registry::StorageClass,
    taikai::{
        SegmentDuration, SegmentTimestamp, TaikaiAliasBinding, TaikaiAnchorReceiptV1,
        TaikaiAudioLayout, TaikaiAvailabilityClass, TaikaiCarPointer, TaikaiCodec, TaikaiEventId,
        TaikaiIngestPointer, TaikaiParseError, TaikaiRenditionId, TaikaiRenditionRouteV1,
        TaikaiResolution, TaikaiRoutingManifestV1, TaikaiSegmentEnvelopeV1,
        TaikaiSegmentSigningBodyV1, TaikaiSegmentSigningManifestV1, TaikaiSegmentWindow,
        TaikaiStreamId, TaikaiTrackKind, TaikaiTrackMetadata, is_canonical_taikai_anchor_base_id,
    },
};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_logger::debug;
use iroha_model_base::name::Name;
use iroha_model_base::topology::LaneId;
use iroha_torii_shared::da::sampling::compute_sample_window;
use norito::{
    decode_from_bytes,
    json::{self, Map, Value},
};
use reqwest::Client;
use sorafs_car::ChunkStore;
use sorafs_manifest::{ProviderAdmissionCouncilPolicy, canonical_manifest_root_cid};
use std::{
    borrow::Cow,
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub(crate) const TAIKAI_SPOOL_SUBDIR: &str = "taikai";
pub(crate) const META_TAIKAI_EVENT_ID: &str = "taikai.event_id";
pub(crate) const META_TAIKAI_STREAM_ID: &str = "taikai.stream_id";
pub(crate) const META_TAIKAI_RENDITION_ID: &str = "taikai.rendition_id";
pub(crate) const META_TAIKAI_TRACK_KIND: &str = "taikai.track.kind";
pub(crate) const META_TAIKAI_TRACK_CODEC: &str = "taikai.track.codec";
pub(crate) const META_TAIKAI_TRACK_BITRATE: &str = "taikai.track.bitrate_kbps";
pub(crate) const META_TAIKAI_TRACK_RESOLUTION: &str = "taikai.track.resolution";
pub(crate) const META_TAIKAI_TRACK_AUDIO_LAYOUT: &str = "taikai.track.audio_layout";
pub(crate) const META_TAIKAI_SEGMENT_SEQUENCE: &str = "taikai.segment.sequence";
pub(crate) const META_TAIKAI_SEGMENT_START: &str = "taikai.segment.start_pts";
pub(crate) const META_TAIKAI_SEGMENT_DURATION: &str = "taikai.segment.duration";
pub(crate) const META_TAIKAI_WALLCLOCK_MS: &str = "taikai.wallclock_unix_ms";
pub(crate) const META_TAIKAI_INGEST_LATENCY_MS: &str = "taikai.instrumentation.ingest_latency_ms";
pub(crate) const META_TAIKAI_LIVE_EDGE_DRIFT_MS: &str = "taikai.instrumentation.live_edge_drift_ms";
pub(crate) const META_TAIKAI_INGEST_NODE_ID: &str = "taikai.instrumentation.ingest_node_id";
pub(crate) const META_TAIKAI_SSM: &str = "taikai.ssm";
pub(crate) const META_TAIKAI_TRM: &str = "taikai.trm";
pub(crate) const META_TAIKAI_AVAILABILITY_CLASS: &str = "taikai.availability_class";
pub(crate) const META_TAIKAI_REPLICATION_REPLICAS: &str = "taikai.replication.replicas";
pub(crate) const META_TAIKAI_REPLICATION_STORAGE: &str = "taikai.replication.storage_class";
pub(crate) const META_TAIKAI_REPLICATION_HOT_SECS: &str = "taikai.replication.hot_retention_secs";
pub(crate) const META_TAIKAI_REPLICATION_COLD_SECS: &str = "taikai.replication.cold_retention_secs";
pub(crate) const META_DA_PROOF_TIER: &str = "da.proof.tier";
pub(crate) const META_DA_PDP_SAMPLE_WINDOW: &str = "da.proof.pdp.sample_window";
pub(crate) const META_DA_POTR_SAMPLE_WINDOW: &str = "da.proof.potr.sample_window";
pub(crate) const TAIKAI_ANCHOR_SENTINEL_PREFIX: &str = "taikai-anchor-";
pub(crate) const TAIKAI_ANCHOR_SENTINEL_SUFFIX: &str = ".ok";
pub(crate) const TAIKAI_ANCHOR_INVALID_SUFFIX: &str = ".invalid";
pub(crate) const TAIKAI_ANCHOR_REQUEST_PREFIX: &str = "taikai-anchor-request-";
pub(crate) const TAIKAI_ANCHOR_REQUEST_SUFFIX: &str = ".json";
pub(crate) const TAIKAI_ANCHOR_READY_PREFIX: &str = "taikai-ready-";
pub(crate) const TAIKAI_ANCHOR_READY_SUFFIX: &str = ".ok";
pub(crate) const TAIKAI_TRM_LINEAGE_PREFIX: &str = "taikai-trm-state-";
pub(crate) const TAIKAI_TRM_LINEAGE_SUFFIX: &str = ".json";
pub(crate) const TAIKAI_TRM_PENDING_PREFIX: &str = "taikai-trm-pending-";
pub(crate) const TAIKAI_TRM_PENDING_SUFFIX: &str = ".json";
pub(crate) const TAIKAI_TRM_LOCK_PREFIX: &str = "taikai-trm-lock-";
pub(crate) const TAIKAI_TRM_LOCK_SUFFIX: &str = ".lock";
pub(crate) const TAIKAI_LINEAGE_HINT_PREFIX: &str = "taikai-lineage";
/// Maximum envelopes selected by one deterministic anchor-worker pass.
pub(crate) const TAIKAI_ANCHOR_BATCH_MAX: usize = 16;
/// Retained replay-suppression window: four complete anchor-worker batches.
pub(crate) const TAIKAI_ANCHOR_ACK_RETENTION_MAX: usize = 4 * TAIKAI_ANCHOR_BATCH_MAX;
/// Maximum canonical JSON signed receipt stored as an anchor acknowledgement.
pub(crate) const TAIKAI_ANCHOR_SENTINEL_MAX_BYTES: usize = 8 * 1024;
/// Maximum decoded HTTP body accepted from the Taikai anchor.
pub(crate) const TAIKAI_ANCHOR_RESPONSE_MAX_BYTES: usize = TAIKAI_ANCHOR_SENTINEL_MAX_BYTES;
const TAIKAI_ANCHOR_READY_MARKER: &[u8] = b"ready-v1\n";
/// Maximum encoded Taikai segment envelope accepted by the anchor spool.
pub(crate) const TAIKAI_ANCHOR_ENVELOPE_MAX_BYTES: usize = 256 * 1024;
/// Maximum encoded Taikai indexes JSON accepted by the anchor spool.
pub(crate) const TAIKAI_ANCHOR_INDEXES_MAX_BYTES: usize = 256 * 1024;
/// Maximum encoded Taikai signing manifest accepted by the anchor spool.
pub(crate) const TAIKAI_ANCHOR_SSM_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded Taikai routing manifest accepted by the anchor spool.
pub(crate) const TAIKAI_ANCHOR_TRM_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded Taikai lineage record or per-envelope hint.
pub(crate) const TAIKAI_ANCHOR_LINEAGE_MAX_BYTES: usize = 64 * 1024;
/// Maximum canonical JSON request capture sent to the anchor service.
///
/// This exceeds the base64 expansion of both capped 4 MiB manifests plus the
/// capped envelope, indexes, lineage, and JSON field overhead.
pub(crate) const TAIKAI_ANCHOR_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod taikai_ingest {
    use super::*;
    use crate::secure_file_metadata::{self, SecureMetadata};
    use sorafs_car::{CarBuildPlan, CarWriter};
    use std::{
        cmp::Reverse,
        collections::BinaryHeap,
        ffi::OsStr,
        io::{self, Read, Write},
        str::FromStr,
        sync::atomic::{AtomicU64, Ordering},
    };
    static ARTIFACT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    pub(crate) const STREAM_LABEL_FALLBACK: &str = "<unknown>";
    pub(crate) struct EnvelopeArtifacts {
        pub envelope_bytes: Vec<u8>,
        pub indexes_json: Vec<u8>,
        pub telemetry: TaikaiTelemetrySample,
        pub car_digest: BlobDigest,
        pub ingest: TaikaiIngestPointer,
    }
    #[derive(Clone)]
    pub(crate) struct TaikaiTelemetrySample {
        pub event_id: String,
        pub stream_id: String,
        pub rendition_id: String,
        pub segment_sequence: u64,
        pub ingest_latency_ms: Option<u32>,
        pub live_edge_drift_ms: Option<i32>,
    }
    const TAIKAI_TRM_LINEAGE_VERSION: u64 = 1;
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TrmLineageRecord {
        alias_namespace: String,
        alias_name: String,
        manifest_digest_hex: String,
        window_start_sequence: u64,
        window_end_sequence: u64,
        artifact_base_id: Option<String>,
        updated_unix: u64,
    }
    /// Result of checking a routing manifest against durable alias lineage.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum TrmLineageValidation {
        /// The routing manifest advances the alias lineage.
        Fresh,
        /// The exact routing-manifest artifact was already durably staged by
        /// an interrupted ingest at the same replay coordinates.
        ExactArtifactRetry,
    }
    impl TrmLineageValidation {
        /// Whether accepting this manifest represents a new alias-lineage
        /// rotation rather than recovery of an already committed rotation.
        pub(crate) const fn records_alias_rotation(self) -> bool {
            matches!(self, Self::Fresh)
        }
    }
    pub(crate) struct TrmLineageGuard {
        manifest_store_dir: PathBuf,
        alias_namespace: String,
        alias_name: String,
        _lock: TrmAliasLock,
        record_path: PathBuf,
        pending_path: PathBuf,
        previous: Option<TrmLineageRecord>,
        pending: Option<TrmLineageRecord>,
    }
    impl TrmLineageGuard {
        pub fn new(
            spool_dir: &Path,
            alias: &TaikaiAliasBinding,
        ) -> Result<Option<Self>, (StatusCode, String)> {
            if spool_dir.as_os_str().is_empty() {
                return Ok(None);
            }
            let base_dir = spool_dir.join(TAIKAI_SPOOL_SUBDIR);
            create_taikai_spool_dir_no_follow(&base_dir).map_err(|err| {
                internal_error(format!(
                    "failed to prepare Taikai spool directory `{}`: {err}",
                    base_dir.display()
                ))
            })?;
            let alias_slug = alias_slug(&alias.namespace, &alias.name);
            let lock = TrmAliasLock::acquire(&base_dir, &alias_slug)?;
            let record_path = lineage_record_path(&base_dir, &alias_slug);
            let pending_path = pending_lineage_record_path(&base_dir, &alias_slug);
            let previous = read_lineage_record(&record_path).map_err(|err| {
                internal_error(format!(
                    "failed to read Taikai routing manifest lineage `{}`: {err}",
                    record_path.display()
                ))
            })?;
            if let Some(previous) = &previous {
                validate_lineage_alias(previous, &alias.namespace, &alias.name, &record_path)
                    .map_err(|err| {
                        internal_error(format!(
                            "failed to validate Taikai routing manifest lineage `{}`: {err}",
                            record_path.display()
                        ))
                    })?;
            }
            let pending = read_lineage_record(&pending_path).map_err(|err| {
                internal_error(format!(
                    "failed to read pending Taikai routing manifest lineage `{}`: {err}",
                    pending_path.display()
                ))
            })?;
            if let Some(pending) = &pending {
                validate_lineage_alias(pending, &alias.namespace, &alias.name, &pending_path)
                    .map_err(|err| {
                        internal_error(format!(
                            "failed to validate pending Taikai routing manifest lineage `{}`: {err}",
                            pending_path.display()
                        ))
                    })?;
                if pending.artifact_base_id.is_none() {
                    return Err(internal_error(format!(
                        "pending Taikai routing manifest lineage `{}` is missing artifact provenance",
                        pending_path.display()
                    )));
                }
            }
            Ok(Some(Self {
                manifest_store_dir: spool_dir.to_path_buf(),
                alias_namespace: alias.namespace.clone(),
                alias_name: alias.name.clone(),
                _lock: lock,
                record_path,
                pending_path,
                previous,
                pending,
            }))
        }
        pub fn validate(
            &self,
            manifest: &TaikaiRoutingManifestV1,
            manifest_digest_hex: &str,
        ) -> Result<(), (StatusCode, String)> {
            if self.pending.is_some() {
                return Err(internal_error(format!(
                    "pending routing manifest lineage for alias {}.{} must be reconciled against the durable receipt log before validation",
                    self.alias_name, self.alias_namespace
                )));
            }
            if let Some(previous) = &self.previous {
                if previous.manifest_digest_hex == manifest_digest_hex {
                    return Err(bad_request(
                        META_TAIKAI_TRM,
                        format!(
                            "routing manifest digest `{manifest_digest_hex}` already accepted for alias {}.{}",
                            self.alias_name, self.alias_namespace
                        ),
                    ));
                }
                if manifest.segment_window.start_sequence <= previous.window_end_sequence {
                    return Err(bad_request(
                        META_TAIKAI_TRM,
                        format!(
                            "routing manifest window {}–{} overlaps previously accepted window {}–{} for alias {}.{}",
                            manifest.segment_window.start_sequence,
                            manifest.segment_window.end_sequence,
                            previous.window_start_sequence,
                            previous.window_end_sequence,
                            self.alias_name,
                            self.alias_namespace
                        ),
                    ));
                }
                let expected_start = previous
                    .window_end_sequence
                    .checked_add(1)
                    .ok_or_else(|| {
                        internal_error(
                            "committed Taikai routing manifest lineage has no representable successor"
                                .into(),
                        )
                    })?;
                if manifest.segment_window.start_sequence != expected_start {
                    return Err(bad_request(
                        META_TAIKAI_TRM,
                        format!(
                            "routing manifest window {}–{} does not immediately follow previously accepted window {}–{} for alias {}.{}; expected start {expected_start}",
                            manifest.segment_window.start_sequence,
                            manifest.segment_window.end_sequence,
                            previous.window_start_sequence,
                            previous.window_end_sequence,
                            self.alias_name,
                            self.alias_namespace
                        ),
                    ));
                }
            } else if manifest.segment_window.start_sequence != 0 {
                return Err(bad_request(
                    META_TAIKAI_TRM,
                    format!(
                        "initial routing manifest window for alias {}.{} must start at sequence 0",
                        self.alias_name, self.alias_namespace
                    ),
                ));
            }
            Ok(())
        }
        /// Validate one ingest, admitting an exact retry only when the
        /// previously staged TRM is bound to the same replay coordinates and
        /// has identical bytes.
        #[allow(clippy::too_many_arguments)]
        pub fn validate_ingest_retry(
            &self,
            manifest: &TaikaiRoutingManifestV1,
            manifest_digest_hex: &str,
            lane_id: LaneId,
            epoch: u64,
            sequence: u64,
            storage_ticket: &StorageTicketId,
            fingerprint: &ReplayFingerprint,
            trm_bytes: &[u8],
        ) -> Result<TrmLineageValidation, (StatusCode, String)> {
            let artifact_base_id =
                taikai_artifact_base_id(lane_id, epoch, sequence, storage_ticket, fingerprint);
            if let Some(previous) = &self.previous
                && previous.manifest_digest_hex == manifest_digest_hex
                && previous.window_start_sequence == manifest.segment_window.start_sequence
                && previous.window_end_sequence == manifest.segment_window.end_sequence
                && previous.artifact_base_id.as_deref() == Some(artifact_base_id.as_str())
            {
                match validate_existing_trm_retry_artifact(
                    &self.manifest_store_dir,
                    lane_id,
                    epoch,
                    sequence,
                    storage_ticket,
                    fingerprint,
                    trm_bytes,
                ) {
                    Ok(()) => return Ok(TrmLineageValidation::ExactArtifactRetry),
                    Err(err) if err.kind() == ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(internal_error(format!(
                            "failed to validate exact Taikai routing manifest retry artifact: {err}"
                        )));
                    }
                }
            }
            self.validate(manifest, manifest_digest_hex)?;
            Ok(TrmLineageValidation::Fresh)
        }
        /// Reconcile an interrupted two-phase lineage update against the
        /// cryptographically verified durable receipt log.
        ///
        /// A pending record without its exact receipt is discarded. A pending
        /// record with that receipt is promoted after its staged TRM bytes are
        /// re-read and matched to the recorded digest. This makes the receipt,
        /// rather than an earlier artifact write, the lineage commit point.
        pub fn recover_pending(
            &mut self,
            receipt_log: &DaReceiptLog,
        ) -> Result<(), (StatusCode, String)> {
            let Some(pending) = self.pending.clone() else {
                return Ok(());
            };
            if self.previous.as_ref() == Some(&pending) {
                self.remove_pending_record()?;
                return Ok(());
            }
            validate_lineage_successor(self.previous.as_ref(), &pending).map_err(|err| {
                internal_error(format!(
                    "failed to validate pending Taikai routing manifest lineage `{}`: {err}",
                    self.pending_path.display()
                ))
            })?;
            let artifact_base_id = pending.artifact_base_id.as_deref().ok_or_else(|| {
                internal_error(
                    "pending Taikai routing manifest lineage is missing artifact provenance"
                        .to_owned(),
                )
            })?;
            let coordinates = parse_taikai_artifact_base_id(artifact_base_id).map_err(|err| {
                internal_error(format!(
                    "failed to parse pending Taikai routing manifest artifact identity: {err}"
                ))
            })?;
            if coordinates.storage_ticket.as_bytes() != coordinates.fingerprint.as_bytes() {
                return Err(internal_error(
                    "pending Taikai routing manifest artifact identity does not bind the storage ticket to its replay fingerprint"
                        .to_owned(),
                ));
            }
            let receipt = receipt_log
                .receipt_for_duplicate(
                    LaneEpoch::new(coordinates.lane_id, coordinates.epoch),
                    coordinates.sequence,
                    coordinates.fingerprint,
                )
                .map_err(|err| {
                    internal_error(format!(
                        "failed to verify the receipt for pending Taikai routing manifest lineage: {err}"
                    ))
                })?;
            let Some((_, receipt)) = receipt else {
                self.remove_pending_record()?;
                return Ok(());
            };
            if receipt.storage_ticket != coordinates.storage_ticket {
                return Err(internal_error(
                    "pending Taikai routing manifest lineage does not match the durable receipt storage ticket"
                        .to_owned(),
                ));
            }
            validate_pending_trm_artifact(&self.manifest_store_dir, &pending).map_err(|err| {
                internal_error(format!(
                    "failed to verify the TRM for pending Taikai routing manifest lineage: {err}"
                ))
            })?;
            write_lineage_record(&self.record_path, &pending).map_err(|err| {
                internal_error(format!(
                    "failed to promote Taikai routing manifest lineage `{}`: {err}",
                    self.record_path.display()
                ))
            })?;
            self.previous = Some(pending);
            self.remove_pending_record()?;
            Ok(())
        }
        /// Stage an alias-lineage advance before the exact durable receipt is
        /// appended. The staged record is not authoritative until
        /// [`Self::recover_pending`] verifies that receipt.
        #[allow(clippy::too_many_arguments)]
        pub fn stage_ingest(
            &mut self,
            window: TaikaiSegmentWindow,
            manifest_digest_hex: &str,
            lane_id: LaneId,
            epoch: u64,
            sequence: u64,
            storage_ticket: &StorageTicketId,
            fingerprint: &ReplayFingerprint,
        ) -> Result<(), (StatusCode, String)> {
            if self.pending.is_some() {
                return Err(internal_error(format!(
                    "pending routing manifest lineage for alias {}.{} was not reconciled before staging",
                    self.alias_name, self.alias_namespace
                )));
            }
            let artifact_base_id =
                taikai_artifact_base_id(lane_id, epoch, sequence, storage_ticket, fingerprint);
            let record = self.build_record(window, manifest_digest_hex, Some(artifact_base_id))?;
            validate_lineage_successor(self.previous.as_ref(), &record).map_err(|err| {
                internal_error(format!(
                    "failed to validate staged Taikai routing manifest lineage: {err}"
                ))
            })?;
            write_lineage_record(&self.pending_path, &record).map_err(|err| {
                internal_error(format!(
                    "failed to stage Taikai routing manifest lineage `{}`: {err}",
                    self.pending_path.display()
                ))
            })?;
            self.pending = Some(record);
            Ok(())
        }
        /// Discard a staged lineage update after the receipt outcome proves
        /// that the ingest did not durably commit.
        pub fn discard_pending(&mut self) -> Result<(), (StatusCode, String)> {
            self.remove_pending_record()
        }
        pub fn persist_lineage_hint(
            &self,
            lane_id: LaneId,
            epoch: u64,
            sequence: u64,
            storage_ticket: &StorageTicketId,
            fingerprint: &ReplayFingerprint,
        ) -> Result<(), (StatusCode, String)> {
            let bytes = build_lineage_hint_bytes(
                &self.alias_namespace,
                &self.alias_name,
                self.previous.as_ref(),
            )
            .map_err(|err| {
                internal_error(format!(
                    "failed to build Taikai routing manifest lineage hint: {err}"
                ))
            })?;
            persist_artifact(
                &self.manifest_store_dir,
                lane_id,
                epoch,
                sequence,
                storage_ticket,
                fingerprint,
                TAIKAI_LINEAGE_HINT_PREFIX,
                "json",
                &bytes,
                TAIKAI_ANCHOR_LINEAGE_MAX_BYTES,
            )
            .map_err(|err| {
                internal_error(format!(
                    "failed to persist Taikai routing manifest lineage hint in `{}`: {err}",
                    self.manifest_store_dir.display()
                ))
            })?;
            Ok(())
        }
        #[cfg(test)]
        pub fn commit(
            &mut self,
            window: TaikaiSegmentWindow,
            manifest_digest_hex: &str,
        ) -> Result<(), (StatusCode, String)> {
            self.commit_record(window, manifest_digest_hex, None)
        }
        /// Commit test-fixture lineage with deterministic artifact identity.
        ///
        /// Production ingest uses [`Self::stage_ingest`] followed by
        /// [`Self::recover_pending`] at the durable receipt boundary.
        #[cfg(test)]
        #[allow(clippy::too_many_arguments)]
        pub fn commit_ingest(
            &mut self,
            window: TaikaiSegmentWindow,
            manifest_digest_hex: &str,
            lane_id: LaneId,
            epoch: u64,
            sequence: u64,
            storage_ticket: &StorageTicketId,
            fingerprint: &ReplayFingerprint,
        ) -> Result<(), (StatusCode, String)> {
            let artifact_base_id =
                taikai_artifact_base_id(lane_id, epoch, sequence, storage_ticket, fingerprint);
            self.commit_record(window, manifest_digest_hex, Some(artifact_base_id))
        }
        #[cfg(test)]
        fn commit_record(
            &mut self,
            window: TaikaiSegmentWindow,
            manifest_digest_hex: &str,
            artifact_base_id: Option<String>,
        ) -> Result<(), (StatusCode, String)> {
            let record = self.build_record(window, manifest_digest_hex, artifact_base_id)?;
            validate_lineage_successor(self.previous.as_ref(), &record).map_err(|err| {
                internal_error(format!(
                    "failed to validate Taikai routing manifest lineage before commit: {err}"
                ))
            })?;
            write_lineage_record(&self.record_path, &record).map_err(|err| {
                internal_error(format!(
                    "failed to persist Taikai routing manifest lineage `{}`: {err}",
                    self.record_path.display()
                ))
            })?;
            self.previous = Some(record);
            Ok(())
        }
        fn build_record(
            &self,
            window: TaikaiSegmentWindow,
            manifest_digest_hex: &str,
            artifact_base_id: Option<String>,
        ) -> Result<TrmLineageRecord, (StatusCode, String)> {
            validate_manifest_digest_hex(manifest_digest_hex).map_err(|err| {
                internal_error(format!(
                    "failed to validate Taikai routing manifest digest before lineage commit: {err}"
                ))
            })?;
            window.validate().map_err(|err| {
                internal_error(format!(
                    "failed to validate Taikai routing manifest window before lineage commit: {err}"
                ))
            })?;
            Ok(TrmLineageRecord {
                alias_namespace: self.alias_namespace.clone(),
                alias_name: self.alias_name.clone(),
                manifest_digest_hex: manifest_digest_hex.to_owned(),
                window_start_sequence: window.start_sequence,
                window_end_sequence: window.end_sequence,
                artifact_base_id,
                updated_unix: current_unix_seconds(),
            })
        }
        fn remove_pending_record(&mut self) -> Result<(), (StatusCode, String)> {
            remove_lineage_record(&self.pending_path).map_err(|err| {
                internal_error(format!(
                    "failed to remove pending Taikai routing manifest lineage `{}`: {err}",
                    self.pending_path.display()
                ))
            })?;
            self.pending = None;
            Ok(())
        }
    }
    /// Recover every interrupted alias-lineage transaction before an anchor
    /// worker can observe a receipt-backed envelope.
    pub fn recover_pending_lineages(
        spool_dir: &Path,
        receipt_log: &DaReceiptLog,
    ) -> Result<(), (StatusCode, String)> {
        if spool_dir.as_os_str().is_empty() {
            return Ok(());
        }
        let base_dir = spool_dir.join(TAIKAI_SPOOL_SUBDIR);
        let entries = match fs::read_dir(&base_dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(internal_error(format!(
                    "failed to scan pending Taikai routing manifest lineages in `{}`: {err}",
                    base_dir.display()
                )));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|err| {
                internal_error(format!(
                    "failed to enumerate pending Taikai routing manifest lineages in `{}`: {err}",
                    base_dir.display()
                ))
            })?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if !name.starts_with(TAIKAI_TRM_PENDING_PREFIX)
                || !name.ends_with(TAIKAI_TRM_PENDING_SUFFIX)
            {
                continue;
            }
            let pending = read_lineage_record(&path)
                .map_err(|err| {
                    internal_error(format!(
                        "failed to read pending Taikai routing manifest lineage `{}`: {err}",
                        path.display()
                    ))
                })?
                .ok_or_else(|| {
                    internal_error(format!(
                        "pending Taikai routing manifest lineage disappeared during recovery: {}",
                        path.display()
                    ))
                })?;
            let alias = TaikaiAliasBinding {
                name: pending.alias_name.clone(),
                namespace: pending.alias_namespace.clone(),
                proof: Vec::new(),
            };
            let expected_path =
                pending_lineage_record_path(&base_dir, &alias_slug(&alias.namespace, &alias.name));
            if path != expected_path {
                return Err(internal_error(format!(
                    "pending Taikai routing manifest lineage filename does not match its alias: {}",
                    path.display()
                )));
            }
            let mut guard = TrmLineageGuard::new(spool_dir, &alias)?.ok_or_else(|| {
                internal_error("Taikai lineage recovery requires durable storage".to_owned())
            })?;
            guard.recover_pending(receipt_log)?;
        }
        Ok(())
    }
    struct TrmAliasLock {
        _file: fs::File,
    }
    impl TrmAliasLock {
        fn acquire(base_dir: &Path, slug: &str) -> Result<Self, (StatusCode, String)> {
            let path = base_dir.join(format!(
                "{TAIKAI_TRM_LOCK_PREFIX}{slug}{TAIKAI_TRM_LOCK_SUFFIX}"
            ));
            let before = match secure_file_metadata::from_path(&path) {
                Ok(metadata) => Some(metadata),
                Err(err) if err.kind() == ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(internal_error(format!(
                        "failed to inspect Taikai routing manifest lock `{}`: {err}",
                        path.display()
                    )));
                }
            };
            if before.as_ref().is_some_and(|metadata| {
                !secure_file_metadata::is_direct_file(metadata)
                    || secure_file_metadata::number_of_links(metadata) != Some(1)
                    || metadata.len() != 0
            }) {
                return Err(internal_error(format!(
                    "Taikai routing manifest lock is not an empty single-link regular file: {}",
                    path.display()
                )));
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            set_taikai_no_follow_open_options(&mut options);
            set_taikai_lock_share_mode(&mut options);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let file = options.open(&path).map_err(|err| {
                internal_error(format!(
                    "failed to open Taikai routing manifest lock `{}`: {err}",
                    path.display()
                ))
            })?;
            let opened = secure_file_metadata::from_file(&file).map_err(|err| {
                internal_error(format!(
                    "failed to inspect open Taikai routing manifest lock `{}`: {err}",
                    path.display()
                ))
            })?;
            let linked = secure_file_metadata::from_path(&path).map_err(|err| {
                internal_error(format!(
                    "failed to re-inspect Taikai routing manifest lock `{}`: {err}",
                    path.display()
                ))
            })?;
            if !secure_file_metadata::is_direct_file(&opened)
                || !secure_file_metadata::is_direct_file(&linked)
                || secure_file_metadata::number_of_links(&opened) != Some(1)
                || secure_file_metadata::number_of_links(&linked) != Some(1)
                || opened.len() != 0
                || linked.len() != 0
                || before
                    .as_ref()
                    .is_some_and(|metadata| !secure_file_metadata::same_file(metadata, &opened))
                || !secure_file_metadata::same_file(&opened, &linked)
            {
                return Err(internal_error(format!(
                    "Taikai routing manifest lock changed identity while opening: {}",
                    path.display()
                )));
            }
            match file.try_lock() {
                Ok(()) => {}
                Err(fs::TryLockError::WouldBlock) => {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("routing manifest lock busy for alias slug `{slug}`; retry later"),
                    ));
                }
                Err(fs::TryLockError::Error(err)) => {
                    return Err(internal_error(format!(
                        "failed to lock Taikai routing manifest lock `{}`: {err}",
                        path.display()
                    )));
                }
            }
            let locked_link = secure_file_metadata::from_path(&path).map_err(|err| {
                internal_error(format!(
                    "failed to inspect locked Taikai routing manifest lock `{}`: {err}",
                    path.display()
                ))
            })?;
            if !secure_file_metadata::is_direct_file(&locked_link)
                || secure_file_metadata::number_of_links(&locked_link) != Some(1)
                || locked_link.len() != 0
                || !secure_file_metadata::same_file(&opened, &locked_link)
            {
                return Err(internal_error(format!(
                    "Taikai routing manifest lock changed identity while acquiring ownership: {}",
                    path.display()
                )));
            }
            file.sync_all().map_err(|err| {
                internal_error(format!(
                    "failed to sync Taikai routing manifest lock `{}`: {err}",
                    path.display()
                ))
            })?;
            sync_parent_dir(&path).map_err(|err| {
                internal_error(format!(
                    "failed to sync Taikai routing manifest lock directory `{}`: {err}",
                    base_dir.display()
                ))
            })?;
            Ok(Self { _file: file })
        }
    }
    fn alias_slug(namespace: &str, name: &str) -> String {
        let mut hasher = Blake3Hasher::new();
        hasher.update(namespace.as_bytes());
        hasher.update(&[0xFF]);
        hasher.update(name.as_bytes());
        let digest = hasher.finalize();
        let digest_hex = hex::encode(&digest.as_bytes()[..6]);
        format!(
            "{}-{}-{digest_hex}",
            sanitize_alias_component(namespace),
            sanitize_alias_component(name)
        )
    }
    fn sanitize_alias_component(component: &str) -> String {
        component
            .chars()
            .map(|ch| match ch {
                'a'..='z' => ch,
                'A'..='Z' => ch.to_ascii_lowercase(),
                '0'..='9' => ch,
                _ => '-',
            })
            .collect()
    }
    fn lineage_record_path(base_dir: &Path, slug: &str) -> PathBuf {
        base_dir.join(format!(
            "{TAIKAI_TRM_LINEAGE_PREFIX}{slug}{TAIKAI_TRM_LINEAGE_SUFFIX}"
        ))
    }
    fn pending_lineage_record_path(base_dir: &Path, slug: &str) -> PathBuf {
        base_dir.join(format!(
            "{TAIKAI_TRM_PENDING_PREFIX}{slug}{TAIKAI_TRM_PENDING_SUFFIX}"
        ))
    }
    fn current_unix_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    pub(super) fn ensure_taikai_artifact_size(
        label: &str,
        actual: usize,
        maximum: usize,
    ) -> io::Result<()> {
        if actual > maximum {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{label} is {actual} bytes, exceeding the {maximum}-byte limit"),
            ));
        }
        Ok(())
    }
    fn read_regular_taikai_file_bounded(
        path: &Path,
        label: &str,
        maximum: usize,
    ) -> io::Result<Vec<u8>> {
        let before = secure_file_metadata::from_path(path)?;
        validate_regular_taikai_metadata(path, label, &before)?;
        let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
        if before.len() > maximum_u64 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{label} is {} bytes, exceeding the {maximum}-byte limit: {}",
                    before.len(),
                    path.display()
                ),
            ));
        }
        #[cfg(windows)]
        let mut file = secure_file_metadata::open_direct_file(path)?;
        #[cfg(not(windows))]
        let mut file = {
            let mut options = OpenOptions::new();
            options.read(true);
            set_taikai_no_follow_open_options(&mut options);
            options.open(path)?
        };
        let opened = secure_file_metadata::from_file(&file)?;
        validate_regular_taikai_metadata(path, label, &opened)?;
        let linked = secure_file_metadata::from_path(path)?;
        validate_regular_taikai_metadata(path, label, &linked)?;
        if !secure_file_metadata::same_file(&before, &opened)
            || !secure_file_metadata::same_file(&opened, &linked)
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{label} changed identity while opening: {}", path.display()),
            ));
        }
        let capacity = usize::try_from(opened.len()).unwrap_or(0);
        let mut bytes = Vec::with_capacity(capacity);
        Read::by_ref(&mut file)
            .take(maximum_u64.saturating_add(1))
            .read_to_end(&mut bytes)?;
        ensure_taikai_artifact_size(label, bytes.len(), maximum)?;
        revalidate_regular_taikai_read(path, &file, &opened, bytes.len(), label)?;
        Ok(bytes)
    }
    fn validate_regular_taikai_metadata(
        path: &Path,
        label: &str,
        metadata: &SecureMetadata,
    ) -> io::Result<()> {
        if !secure_file_metadata::is_direct_file(metadata) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{label} is not a regular file: {}", path.display()),
            ));
        }
        Ok(())
    }
    fn revalidate_regular_taikai_read(
        path: &Path,
        file: &fs::File,
        original: &SecureMetadata,
        bytes_len: usize,
        label: &str,
    ) -> io::Result<()> {
        let opened_after = secure_file_metadata::from_file(file)?;
        let linked_after = secure_file_metadata::from_path(path)?;
        validate_regular_taikai_metadata(path, label, &opened_after)?;
        validate_regular_taikai_metadata(path, label, &linked_after)?;
        if !secure_file_metadata::unchanged(original, &opened_after)
            || !secure_file_metadata::unchanged(&opened_after, &linked_after)
            || u64::try_from(bytes_len).ok() != Some(original.len())
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{label} changed while reading: {}", path.display()),
            ));
        }
        Ok(())
    }
    #[cfg(unix)]
    fn set_taikai_no_follow_open_options(options: &mut OpenOptions) {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    fn set_taikai_no_follow_open_options(options: &mut OpenOptions) {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    fn set_taikai_no_follow_open_options(_options: &mut OpenOptions) {}
    #[cfg(windows)]
    fn set_taikai_lock_share_mode(options: &mut OpenOptions) {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;
        options.share_mode(FILE_SHARE_READ_WRITE);
    }
    #[cfg(not(windows))]
    fn set_taikai_lock_share_mode(_options: &mut OpenOptions) {}
    fn create_taikai_spool_dir_no_follow(base_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(base_dir)?;
        validate_taikai_spool_dir_no_follow(base_dir)
    }
    fn validate_taikai_spool_dir_no_follow(base_dir: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(base_dir)?;
        validate_taikai_spool_dir_metadata(base_dir, &metadata)
    }
    fn validate_taikai_spool_dir_metadata(
        base_dir: &Path,
        metadata: &fs::Metadata,
    ) -> io::Result<()> {
        let is_direct_directory =
            !metadata.file_type().is_symlink() && metadata.file_type().is_dir();
        #[cfg(windows)]
        let is_direct_directory = {
            use std::os::windows::fs::MetadataExt as _;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
            is_direct_directory && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
        };
        if !is_direct_directory {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Taikai spool directory `{}` is not a direct directory",
                    base_dir.display()
                ),
            ));
        }
        Ok(())
    }
    fn read_lineage_record(path: &Path) -> io::Result<Option<TrmLineageRecord>> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Taikai routing manifest lineage record is not a regular file: {}",
                    path.display()
                ),
            ));
        }
        let bytes = read_regular_taikai_file_bounded(
            path,
            "Taikai routing manifest lineage record",
            TAIKAI_ANCHOR_LINEAGE_MAX_BYTES,
        )?;
        let value: Value = json::from_slice(&bytes)
            .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
        let map = value.as_object().ok_or_else(|| {
            io::Error::new(
                ErrorKind::Other,
                "Taikai routing manifest lineage record must be a JSON object",
            )
        })?;
        let version = map.get("version").and_then(Value::as_u64).ok_or_else(|| {
            invalid_lineage_record("Taikai routing manifest lineage record missing version")
        })?;
        if version != TAIKAI_TRM_LINEAGE_VERSION {
            return Err(invalid_lineage_record(format!(
                "unsupported Taikai routing manifest lineage record version {version}"
            )));
        }
        let alias_namespace = map
            .get("alias_namespace")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::Other,
                    "Taikai routing manifest lineage record missing alias_namespace",
                )
            })?
            .to_owned();
        let alias_name = map
            .get("alias_name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::Other,
                    "Taikai routing manifest lineage record missing alias_name",
                )
            })?
            .to_owned();
        let manifest_digest_hex = map
            .get("manifest_digest_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::Other,
                    "Taikai routing manifest lineage record missing manifest_digest_hex",
                )
            })?
            .to_owned();
        validate_manifest_digest_hex(&manifest_digest_hex)?;
        let window_start_sequence = map
            .get("window_start_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::Other,
                    "Taikai routing manifest lineage record missing window_start_sequence",
                )
            })?;
        let window_end_sequence = map
            .get("window_end_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::Other,
                    "Taikai routing manifest lineage record missing window_end_sequence",
                )
            })?;
        if window_start_sequence > window_end_sequence {
            return Err(invalid_lineage_record(
                "Taikai routing manifest lineage record window_start_sequence exceeds window_end_sequence",
            ));
        }
        TaikaiSegmentWindow::new(window_start_sequence, window_end_sequence)
            .validate()
            .map_err(|err| {
                invalid_lineage_record(format!(
                    "Taikai routing manifest lineage record has an invalid segment window: {err}"
                ))
            })?;
        let artifact_base_id = match map.get("artifact_base_id") {
            None => None,
            Some(value) => {
                let base_id = value.as_str().ok_or_else(|| {
                    invalid_lineage_record(
                        "Taikai routing manifest lineage record artifact_base_id must be a string",
                    )
                })?;
                validate_taikai_artifact_base_id(base_id)?;
                Some(base_id.to_owned())
            }
        };
        let updated_unix = map
            .get("updated_unix")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                invalid_lineage_record(
                    "Taikai routing manifest lineage record missing updated_unix",
                )
            })?;
        Ok(Some(TrmLineageRecord {
            alias_namespace,
            alias_name,
            manifest_digest_hex,
            window_start_sequence,
            window_end_sequence,
            artifact_base_id,
            updated_unix,
        }))
    }
    fn write_lineage_record(path: &Path, record: &TrmLineageRecord) -> io::Result<()> {
        let mut map = Map::new();
        map.insert("version".into(), Value::from(TAIKAI_TRM_LINEAGE_VERSION));
        map.insert(
            "alias_namespace".into(),
            Value::from(record.alias_namespace.clone()),
        );
        map.insert("alias_name".into(), Value::from(record.alias_name.clone()));
        map.insert(
            "manifest_digest_hex".into(),
            Value::from(record.manifest_digest_hex.clone()),
        );
        map.insert(
            "window_start_sequence".into(),
            Value::from(record.window_start_sequence),
        );
        map.insert(
            "window_end_sequence".into(),
            Value::from(record.window_end_sequence),
        );
        if let Some(artifact_base_id) = &record.artifact_base_id {
            map.insert(
                "artifact_base_id".into(),
                Value::from(artifact_base_id.clone()),
            );
        }
        map.insert("updated_unix".into(), Value::from(record.updated_unix));
        let rendered = json::to_json_pretty(&Value::Object(map))
            .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
        let tmp_path = path.with_extension(format!("tmp-{}", artifact_temp_suffix()?));
        match open_new_private_artifact(&tmp_path) {
            Ok(mut file) => {
                if let Err(err) = file.write_all(rendered.as_bytes()) {
                    return Err(temp_artifact_write_error(&tmp_path, err));
                }
                if let Err(err) = file.sync_all() {
                    return Err(temp_artifact_write_error(&tmp_path, err));
                }
            }
            Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
        }
        if let Err(err) = fs::rename(&tmp_path, path) {
            remove_temp_artifact(&tmp_path)?;
            return Err(err);
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                sync_dir(parent)?;
            }
        }
        Ok(())
    }
    fn remove_lineage_record(path: &Path) -> io::Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Taikai routing manifest lineage record is not a regular file: {}",
                        path.display()
                    ),
                ));
            }
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        }
        fs::remove_file(path)?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            sync_dir(parent)?;
        }
        Ok(())
    }
    fn validate_lineage_alias(
        record: &TrmLineageRecord,
        expected_namespace: &str,
        expected_name: &str,
        path: &Path,
    ) -> io::Result<()> {
        if record.alias_namespace != expected_namespace || record.alias_name != expected_name {
            return Err(invalid_lineage_record(format!(
                "Taikai routing manifest lineage record `{}` belongs to alias {}.{} instead of {}.{}",
                path.display(),
                record.alias_name,
                record.alias_namespace,
                expected_name,
                expected_namespace
            )));
        }
        Ok(())
    }
    fn validate_manifest_digest_hex(digest: &str) -> io::Result<()> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid_lineage_record(
                "Taikai routing manifest lineage record manifest_digest_hex must be 32-byte lowercase hex",
            ));
        }
        let bytes = hex::decode(digest).map_err(|err| invalid_lineage_record(err.to_string()))?;
        if bytes.len() != 32 {
            return Err(invalid_lineage_record(
                "Taikai routing manifest lineage record manifest_digest_hex must decode to 32 bytes",
            ));
        }
        Ok(())
    }
    fn validate_taikai_artifact_base_id(base_id: &str) -> io::Result<()> {
        let mut components = base_id.split('-');
        for width in [8, 16, 16, 64, 64] {
            let Some(component) = components.next() else {
                return Err(invalid_lineage_record(
                    "Taikai routing manifest lineage record artifact_base_id must be canonical lowercase hex",
                ));
            };
            if component.len() != width
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid_lineage_record(
                    "Taikai routing manifest lineage record artifact_base_id must be canonical lowercase hex",
                ));
            }
        }
        if components.next().is_some() {
            return Err(invalid_lineage_record(
                "Taikai routing manifest lineage record artifact_base_id must be canonical lowercase hex",
            ));
        }
        Ok(())
    }
    struct TaikaiArtifactCoordinates {
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: StorageTicketId,
        fingerprint: ReplayFingerprint,
    }
    fn parse_taikai_artifact_base_id(base_id: &str) -> io::Result<TaikaiArtifactCoordinates> {
        validate_taikai_artifact_base_id(base_id)?;
        let mut components = base_id.split('-');
        let lane_id = u32::from_str_radix(components.next().unwrap_or_default(), 16)
            .map(LaneId::new)
            .map_err(|err| invalid_lineage_record(err.to_string()))?;
        let epoch = u64::from_str_radix(components.next().unwrap_or_default(), 16)
            .map_err(|err| invalid_lineage_record(err.to_string()))?;
        let sequence = u64::from_str_radix(components.next().unwrap_or_default(), 16)
            .map_err(|err| invalid_lineage_record(err.to_string()))?;
        let mut storage_ticket = [0_u8; 32];
        hex::decode_to_slice(components.next().unwrap_or_default(), &mut storage_ticket)
            .map_err(|err| invalid_lineage_record(err.to_string()))?;
        let mut fingerprint = [0_u8; 32];
        hex::decode_to_slice(components.next().unwrap_or_default(), &mut fingerprint)
            .map_err(|err| invalid_lineage_record(err.to_string()))?;
        Ok(TaikaiArtifactCoordinates {
            lane_id,
            epoch,
            sequence,
            storage_ticket: StorageTicketId::new(storage_ticket),
            fingerprint: ReplayFingerprint::from(fingerprint),
        })
    }
    fn validate_lineage_successor(
        previous: Option<&TrmLineageRecord>,
        candidate: &TrmLineageRecord,
    ) -> io::Result<()> {
        if let Some(previous) = previous {
            if previous.manifest_digest_hex == candidate.manifest_digest_hex {
                return Err(invalid_lineage_record(
                    "pending Taikai routing manifest repeats the committed manifest digest",
                ));
            }
            if candidate.window_start_sequence <= previous.window_end_sequence {
                return Err(invalid_lineage_record(
                    "pending Taikai routing manifest overlaps the committed segment window",
                ));
            }
            let expected_start = previous.window_end_sequence.checked_add(1).ok_or_else(|| {
                invalid_lineage_record(
                    "committed Taikai routing manifest lineage has no representable successor",
                )
            })?;
            if candidate.window_start_sequence != expected_start {
                return Err(invalid_lineage_record(format!(
                    "pending Taikai routing manifest starts at sequence {}; expected contiguous successor {expected_start}",
                    candidate.window_start_sequence
                )));
            }
        } else if candidate.window_start_sequence != 0 {
            return Err(invalid_lineage_record(
                "initial Taikai routing manifest lineage must start at sequence 0",
            ));
        }
        Ok(())
    }
    fn validate_pending_trm_artifact(
        manifest_store_dir: &Path,
        pending: &TrmLineageRecord,
    ) -> io::Result<()> {
        let artifact_base_id = pending.artifact_base_id.as_deref().ok_or_else(|| {
            invalid_lineage_record(
                "pending Taikai routing manifest lineage is missing artifact provenance",
            )
        })?;
        validate_taikai_artifact_base_id(artifact_base_id)?;
        let path = manifest_store_dir
            .join(TAIKAI_SPOOL_SUBDIR)
            .join(format!("taikai-trm-{artifact_base_id}.norito"));
        let bytes = read_regular_taikai_file_bounded(
            &path,
            "pending Taikai routing manifest",
            TAIKAI_ANCHOR_TRM_MAX_BYTES,
        )?;
        let observed = hex::encode(blake3_hash(&bytes).as_bytes());
        if observed != pending.manifest_digest_hex {
            return Err(invalid_lineage_record(format!(
                "pending Taikai routing manifest digest mismatch at {}",
                path.display()
            )));
        }
        Ok(())
    }
    fn invalid_lineage_record(message: impl Into<String>) -> io::Error {
        io::Error::new(ErrorKind::InvalidData, message.into())
    }
    fn sync_dir(path: &Path) -> io::Result<()> {
        let file = fs::File::open(path)?;
        file.sync_all()
    }
    fn build_lineage_hint_bytes(
        alias_namespace: &str,
        alias_name: &str,
        previous: Option<&TrmLineageRecord>,
    ) -> Result<Vec<u8>, io::Error> {
        let mut map = Map::new();
        map.insert("version".into(), Value::from(1));
        map.insert(
            "alias_namespace".into(),
            Value::from(alias_namespace.to_owned()),
        );
        map.insert("alias_name".into(), Value::from(alias_name.to_owned()));
        if let Some(previous) = previous {
            map.insert(
                "previous_manifest_digest_hex".into(),
                Value::from(previous.manifest_digest_hex.clone()),
            );
            map.insert(
                "previous_window_start_sequence".into(),
                Value::from(previous.window_start_sequence),
            );
            map.insert(
                "previous_window_end_sequence".into(),
                Value::from(previous.window_end_sequence),
            );
            map.insert(
                "previous_updated_unix".into(),
                Value::from(previous.updated_unix),
            );
        } else {
            map.insert("previous_manifest_digest_hex".into(), Value::Null);
            map.insert("previous_window_start_sequence".into(), Value::Null);
            map.insert("previous_window_end_sequence".into(), Value::Null);
            map.insert("previous_updated_unix".into(), Value::Null);
        }
        let rendered = json::to_json_pretty(&Value::Object(map))
            .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
        Ok(rendered.into_bytes())
    }
    pub(crate) fn build_envelope(
        manifest: &ManifestArtifacts,
        chunk_store: &ChunkStore,
        canonical_payload: &[u8],
        chunking_observer: Option<&dyn Fn(Duration)>,
    ) -> Result<EnvelopeArtifacts, (StatusCode, String)> {
        let metadata = &manifest.manifest.metadata;
        let event_id = TaikaiEventId::new(parse_name(metadata, META_TAIKAI_EVENT_ID)?);
        let stream_id = TaikaiStreamId::new(parse_name(metadata, META_TAIKAI_STREAM_ID)?);
        let rendition_id = TaikaiRenditionId::new(parse_name(metadata, META_TAIKAI_RENDITION_ID)?);
        let track_kind = TaikaiTrackKind::from_str(require_utf8(metadata, META_TAIKAI_TRACK_KIND)?)
            .map_err(|err| parse_error(META_TAIKAI_TRACK_KIND, err))?;
        let codec = TaikaiCodec::from_str(require_utf8(metadata, META_TAIKAI_TRACK_CODEC)?)
            .map_err(|err| parse_error(META_TAIKAI_TRACK_CODEC, err))?;
        let bitrate = parse_u32(
            require_utf8(metadata, META_TAIKAI_TRACK_BITRATE)?,
            META_TAIKAI_TRACK_BITRATE,
        )?;
        if bitrate == 0 {
            return Err(bad_request(
                META_TAIKAI_TRACK_BITRATE,
                "must be greater than zero",
            ));
        }
        let track = match track_kind {
            TaikaiTrackKind::Video => {
                let resolution_str = require_utf8(metadata, META_TAIKAI_TRACK_RESOLUTION)?;
                let resolution = TaikaiResolution::from_str(resolution_str)
                    .map_err(|err| parse_error(META_TAIKAI_TRACK_RESOLUTION, err))?;
                if !matches!(
                    codec,
                    TaikaiCodec::AvcHigh
                        | TaikaiCodec::HevcMain10
                        | TaikaiCodec::Av1Main
                        | TaikaiCodec::Custom(_)
                ) {
                    return Err(bad_request(
                        META_TAIKAI_TRACK_CODEC,
                        "codec is not valid for a video track; expected AV1/AVC/HEVC or custom",
                    ));
                }
                TaikaiTrackMetadata::video(codec, bitrate, resolution)
            }
            TaikaiTrackKind::Audio => {
                let layout_str = require_utf8(metadata, META_TAIKAI_TRACK_AUDIO_LAYOUT)?;
                let layout = TaikaiAudioLayout::from_str(layout_str)
                    .map_err(|err| parse_error(META_TAIKAI_TRACK_AUDIO_LAYOUT, err))?;
                if !matches!(
                    codec,
                    TaikaiCodec::AacLc | TaikaiCodec::Opus | TaikaiCodec::Custom(_)
                ) {
                    return Err(bad_request(
                        META_TAIKAI_TRACK_CODEC,
                        "codec is not valid for an audio track; expected AAC/Opus or custom",
                    ));
                }
                TaikaiTrackMetadata::audio(codec, bitrate, layout)
            }
            TaikaiTrackKind::Data => TaikaiTrackMetadata::data(codec, bitrate),
        };
        if matches!(track.kind, TaikaiTrackKind::Video) && track.resolution.is_none() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "metadata entry `{META_TAIKAI_TRACK_RESOLUTION}` is required for video tracks"
                ),
            ));
        }
        if matches!(track.kind, TaikaiTrackKind::Audio) && track.audio_layout.is_none() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "metadata entry `{META_TAIKAI_TRACK_AUDIO_LAYOUT}` is required for audio tracks"
                ),
            ));
        }
        let segment_sequence = parse_u64(
            require_utf8(metadata, META_TAIKAI_SEGMENT_SEQUENCE)?,
            META_TAIKAI_SEGMENT_SEQUENCE,
        )?;
        let segment_start_pts = parse_u64(
            require_utf8(metadata, META_TAIKAI_SEGMENT_START)?,
            META_TAIKAI_SEGMENT_START,
        )?;
        let segment_duration = parse_u32(
            require_utf8(metadata, META_TAIKAI_SEGMENT_DURATION)?,
            META_TAIKAI_SEGMENT_DURATION,
        )?;
        if segment_duration == 0 {
            return Err(bad_request(
                META_TAIKAI_SEGMENT_DURATION,
                "must be greater than zero",
            ));
        }
        let wallclock_unix_ms = parse_u64(
            require_utf8(metadata, META_TAIKAI_WALLCLOCK_MS)?,
            META_TAIKAI_WALLCLOCK_MS,
        )?;
        let chunk_count: u32 = chunk_store
            .chunks()
            .len()
            .try_into()
            .map_err(|_| internal_error("chunk count exceeds supported range".into()))?;
        let chunking_started = Instant::now();
        let plan = CarBuildPlan::single_file(canonical_payload)
            .map_err(|err| internal_error(format!("failed to derive CAR plan: {err}")))?;
        let mut sink = io::sink();
        let stats = CarWriter::new(&plan, canonical_payload)
            .map_err(|err| internal_error(format!("failed to initialise CAR writer: {err}")))?
            .write_to(&mut sink)
            .map_err(|err| internal_error(format!("failed to compute CAR digests: {err}")))?;
        if let Some(observer) = chunking_observer {
            observer(chunking_started.elapsed());
        }
        let car_digest = BlobDigest::from_hash(stats.car_archive_digest);
        let car_pointer = TaikaiCarPointer::new(
            format!("b{}", encode_base32_lower(&stats.car_cid)),
            car_digest,
            stats.car_size,
        );
        let ingest_pointer = TaikaiIngestPointer::new(
            manifest.manifest_hash,
            manifest.storage_ticket,
            manifest.chunk_root,
            chunk_count,
            car_pointer,
        );
        let event_label = event_id.as_name().as_ref().to_owned();
        let stream_label = stream_id.as_name().as_ref().to_owned();
        let rendition_label = rendition_id.as_name().as_ref().to_owned();
        let mut envelope = TaikaiSegmentEnvelopeV1::new(
            event_id,
            stream_id,
            rendition_id,
            track,
            segment_sequence,
            SegmentTimestamp::new(segment_start_pts),
            SegmentDuration::new(segment_duration),
            wallclock_unix_ms,
            ingest_pointer,
        );
        if let Some(latency_str) = optional_utf8(metadata, META_TAIKAI_INGEST_LATENCY_MS)? {
            let latency = parse_u32(latency_str, META_TAIKAI_INGEST_LATENCY_MS)?;
            envelope.instrumentation.encoder_to_ingest_latency_ms = Some(latency);
        }
        let live_edge_drift_ms =
            if let Some(drift_str) = optional_utf8(metadata, META_TAIKAI_LIVE_EDGE_DRIFT_MS)? {
                Some(parse_i32(drift_str, META_TAIKAI_LIVE_EDGE_DRIFT_MS)?)
            } else {
                None
            };
        if let Some(drift) = live_edge_drift_ms {
            envelope.instrumentation.live_edge_drift_ms = Some(drift);
        }
        if let Some(node_id) = optional_utf8(metadata, META_TAIKAI_INGEST_NODE_ID)? {
            if !node_id.trim().is_empty() {
                envelope.instrumentation.ingest_node_id = Some(node_id.trim().to_owned());
            }
        }
        let indexes = envelope.indexes();
        let envelope_bytes = norito::to_bytes(&envelope)
            .map_err(|err| internal_error(format!("failed to encode Taikai envelope: {err}")))?;
        let indexes_json = norito::json::to_json_pretty(&indexes)
            .map_err(|err| internal_error(format!("failed to render Taikai indexes: {err}")))?
            .into_bytes();
        let telemetry = TaikaiTelemetrySample {
            event_id: event_label,
            stream_id: stream_label,
            rendition_id: rendition_label,
            segment_sequence,
            ingest_latency_ms: envelope.instrumentation.encoder_to_ingest_latency_ms,
            live_edge_drift_ms,
        };
        Ok(EnvelopeArtifacts {
            envelope_bytes,
            indexes_json,
            telemetry,
            car_digest,
            ingest: envelope.ingest,
        })
    }
    pub(crate) fn persist_envelope(
        spool_dir: &Path,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
        bytes: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        persist_artifact(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            storage_ticket,
            fingerprint,
            "taikai-envelope",
            "norito",
            bytes,
            TAIKAI_ANCHOR_ENVELOPE_MAX_BYTES,
        )
    }
    pub(crate) fn persist_indexes(
        spool_dir: &Path,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
        bytes: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        persist_artifact(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            storage_ticket,
            fingerprint,
            "taikai-indexes",
            "json",
            bytes,
            TAIKAI_ANCHOR_INDEXES_MAX_BYTES,
        )
    }
    pub(crate) fn persist_ssm(
        spool_dir: &Path,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
        bytes: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        persist_artifact(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            storage_ticket,
            fingerprint,
            "taikai-ssm",
            "norito",
            bytes,
            TAIKAI_ANCHOR_SSM_MAX_BYTES,
        )
    }
    pub(crate) fn persist_trm(
        spool_dir: &Path,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
        bytes: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        persist_artifact(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            storage_ticket,
            fingerprint,
            "taikai-trm",
            "norito",
            bytes,
            TAIKAI_ANCHOR_TRM_MAX_BYTES,
        )
    }
    /// Require the exact TRM artifact staged for one interrupted ingest.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_existing_trm_retry_artifact(
        spool_dir: &Path,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
        bytes: &[u8],
    ) -> io::Result<()> {
        ensure_taikai_artifact_size("taikai-trm", bytes.len(), TAIKAI_ANCHOR_TRM_MAX_BYTES)?;
        if spool_dir.as_os_str().is_empty() {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "exact Taikai routing manifest retry artifact is unavailable without a spool directory",
            ));
        }
        let base_id =
            taikai_artifact_base_id(lane_id, epoch, sequence, storage_ticket, fingerprint);
        let path = spool_dir
            .join(TAIKAI_SPOOL_SUBDIR)
            .join(format!("taikai-trm-{base_id}.norito"));
        match existing_taikai_artifact_path_if_matching(&path, bytes, "taikai-trm")? {
            Some(_) => Ok(()),
            None => Err(io::Error::new(
                ErrorKind::NotFound,
                format!(
                    "exact Taikai routing manifest retry artifact is missing: {}",
                    path.display()
                ),
            )),
        }
    }
    pub(crate) fn persist_anchor_ready(
        spool_dir: &Path,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
    ) -> io::Result<Option<PathBuf>> {
        persist_artifact(
            spool_dir,
            lane_id,
            epoch,
            sequence,
            storage_ticket,
            fingerprint,
            "taikai-ready",
            "ok",
            TAIKAI_ANCHOR_READY_MARKER,
            TAIKAI_ANCHOR_READY_MARKER.len(),
        )
    }
    fn install_artifact_without_overwrite(
        tmp_path: &Path,
        target_path: &Path,
        expected: &[u8],
        prefix: &str,
    ) -> io::Result<()> {
        match fs::hard_link(tmp_path, target_path) {
            Ok(()) => {
                let sync_result = sync_parent_dir(target_path);
                let remove_result = remove_temp_artifact(tmp_path);
                sync_result?;
                remove_result
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                let existing_result =
                    validate_existing_taikai_artifact(target_path, expected, prefix);
                let remove_result = remove_temp_artifact(tmp_path);
                existing_result?;
                remove_result
            }
            Err(err) => {
                remove_temp_artifact(tmp_path)?;
                Err(err)
            }
        }
    }
    fn open_new_private_artifact(path: &Path) -> io::Result<fs::File> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }
    fn write_temp_artifact(tmp_path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = open_new_private_artifact(tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
    fn temp_artifact_write_error(tmp_path: &Path, err: io::Error) -> io::Error {
        if err.kind() == ErrorKind::AlreadyExists {
            return err;
        }
        remove_temp_artifact(tmp_path).err().unwrap_or(err)
    }
    fn allocate_artifact_temp_counter(counter: &AtomicU64) -> io::Result<u64> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                io::Error::new(
                    ErrorKind::Other,
                    "Taikai artifact temp suffix counter exhausted",
                )
            })
    }
    fn artifact_temp_suffix() -> io::Result<String> {
        let counter = allocate_artifact_temp_counter(&ARTIFACT_TEMP_COUNTER)?;
        Ok(format!("{}-{counter:016x}", std::process::id()))
    }
    fn sync_parent_dir(path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            sync_dir(parent)?;
        }
        Ok(())
    }
    fn remove_temp_artifact(tmp_path: &Path) -> io::Result<()> {
        match fs::remove_file(tmp_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io::Error::new(
                err.kind(),
                format!(
                    "failed to remove Taikai temp artifact {}: {err}",
                    tmp_path.display()
                ),
            )),
        }
    }
    #[cfg(test)]
    mod temp_cleanup_tests {
        use super::*;
        use tempfile::tempdir;
        #[test]
        fn taikai_temp_artifact_cleanup_reports_unremovable_path() {
            let dir = tempdir().expect("tempdir");
            let tmp_path = dir.path().join(".taikai.tmp");
            fs::create_dir(&tmp_path).expect("block temp cleanup");
            let err = remove_temp_artifact(&tmp_path).expect_err("directory cleanup should fail");
            assert!(
                err.to_string()
                    .contains("failed to remove Taikai temp artifact"),
                "unexpected error: {err}"
            );
            assert!(
                tmp_path.is_dir(),
                "failed cleanup should leave temp path visible for operator repair"
            );
        }
        #[test]
        fn taikai_temp_artifact_write_rejects_existing_path_without_truncating() {
            let dir = tempdir().expect("tempdir");
            let tmp_path = dir.path().join(".taikai.tmp");
            fs::write(&tmp_path, b"existing").expect("seed temp artifact");
            let err = write_temp_artifact(&tmp_path, b"replacement")
                .expect_err("existing temp artifact should not be overwritten");
            assert_eq!(err.kind(), ErrorKind::AlreadyExists);
            assert_eq!(
                fs::read(&tmp_path).expect("read existing temp artifact"),
                b"existing"
            );
            let err =
                temp_artifact_write_error(&tmp_path, io::Error::from(ErrorKind::AlreadyExists));
            assert_eq!(err.kind(), ErrorKind::AlreadyExists);
            assert_eq!(
                fs::read(&tmp_path).expect("read existing temp artifact after cleanup helper"),
                b"existing"
            );
        }
        #[cfg(unix)]
        #[test]
        fn taikai_temp_artifact_write_uses_owner_only_permissions() {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempdir().expect("tempdir");
            let tmp_path = dir.path().join(".taikai.tmp");
            write_temp_artifact(&tmp_path, b"sensitive Taikai artifact")
                .expect("write owner-only temp artifact");
            let mode = fs::metadata(&tmp_path)
                .expect("inspect temp artifact")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "Taikai temp artifact must not grant group or world access"
            );
        }
        #[test]
        fn taikai_temp_artifact_counter_rejects_exhaustion_without_wrapping() {
            let counter = AtomicU64::new(u64::MAX);
            let err = allocate_artifact_temp_counter(&counter)
                .expect_err("exhausted temp counter must reject");
            assert_eq!(err.kind(), ErrorKind::Other);
            assert!(
                err.to_string().contains("temp suffix counter exhausted"),
                "unexpected error: {err}"
            );
            assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        }
        #[test]
        fn taikai_temp_artifact_counter_allocates_pre_exhaustion_suffix_once() {
            let counter = AtomicU64::new(u64::MAX - 1);
            let suffix = allocate_artifact_temp_counter(&counter)
                .expect("last non-exhausted temp counter should allocate");
            assert_eq!(suffix, u64::MAX - 1);
            assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
            assert!(
                allocate_artifact_temp_counter(&counter).is_err(),
                "counter must fail closed once exhausted"
            );
            assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        }
        #[test]
        fn taikai_read_revalidation_rejects_length_change() {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("taikai-artifact.norito");
            fs::write(&path, b"old-artifact").expect("seed artifact");
            let file = fs::File::open(&path).expect("open original artifact");
            let original =
                secure_file_metadata::from_file(&file).expect("inspect original artifact");
            fs::write(&path, b"replacement-artifact").expect("replace artifact");
            let err = revalidate_regular_taikai_read(
                &path,
                &file,
                &original,
                b"old-artifact".len(),
                "Taikai artifact test",
            )
            .expect_err("changed artifact length must reject");
            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(
                err.to_string().contains("changed while reading"),
                "unexpected error: {err}"
            );
        }
        #[cfg(unix)]
        #[test]
        fn taikai_read_revalidation_rejects_symlink_replacement() {
            use std::os::unix::fs::symlink;
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("taikai-artifact.norito");
            fs::write(&path, b"old-artifact").expect("seed artifact");
            let file = fs::File::open(&path).expect("open original artifact");
            let original =
                secure_file_metadata::from_file(&file).expect("inspect original artifact");
            let target = dir.path().join("artifact-target.norito");
            fs::write(&target, b"old-artifact").expect("write symlink target");
            fs::remove_file(&path).expect("remove original artifact");
            symlink(&target, &path).expect("replace artifact with symlink");
            revalidate_regular_taikai_read(
                &path,
                &file,
                &original,
                b"old-artifact".len(),
                "Taikai artifact test",
            )
            .expect_err("symlink replacement must reject");
            assert!(
                fs::symlink_metadata(&path)
                    .expect("inspect symlink")
                    .file_type()
                    .is_symlink(),
                "failed revalidation should leave symlink visible"
            );
            assert!(target.exists(), "symlink target should not be removed");
        }
        #[test]
        fn taikai_install_artifact_reports_temp_cleanup_failure_after_link_error() {
            let dir = tempdir().expect("tempdir");
            let tmp_path = dir.path().join(".taikai.tmp");
            let target_path = dir.path().join("taikai-target.norito");
            fs::create_dir(&tmp_path).expect("block temp cleanup");
            let err =
                install_artifact_without_overwrite(&tmp_path, &target_path, b"expected", "taikai")
                    .expect_err("directory temp artifact should fail cleanup");
            assert!(
                err.to_string()
                    .contains("failed to remove Taikai temp artifact"),
                "unexpected error: {err}"
            );
            assert!(
                tmp_path.is_dir(),
                "failed cleanup should leave temp path visible for operator repair"
            );
            assert!(
                !target_path.exists(),
                "failed hard-link install must not create the target artifact"
            );
        }
        #[cfg(unix)]
        #[test]
        fn taikai_existing_artifact_rejects_target_symlink() {
            use std::os::unix::fs::symlink;
            let dir = tempdir().expect("tempdir");
            let target = dir.path().join("artifact-target.norito");
            fs::write(&target, b"expected").expect("write symlink target");
            let path = dir.path().join("taikai-envelope-test.norito");
            symlink(&target, &path).expect("create Taikai artifact symlink");
            let err = existing_taikai_artifact_path_if_matching(&path, b"expected", "taikai")
                .expect_err("symlinked existing artifact must reject");
            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(
                fs::symlink_metadata(&path)
                    .expect("inspect symlink")
                    .file_type()
                    .is_symlink(),
                "failed comparison should leave symlink visible"
            );
            assert!(target.exists(), "symlink target should not be removed");
        }
        #[cfg(unix)]
        #[test]
        fn taikai_install_artifact_rejects_existing_target_symlink() {
            use std::os::unix::fs::symlink;
            let dir = tempdir().expect("tempdir");
            let tmp_path = dir.path().join(".taikai.tmp");
            fs::write(&tmp_path, b"expected").expect("write temp artifact");
            let target = dir.path().join("artifact-target.norito");
            fs::write(&target, b"expected").expect("write symlink target");
            let target_path = dir.path().join("taikai-envelope-test.norito");
            symlink(&target, &target_path).expect("create Taikai artifact symlink");
            let err =
                install_artifact_without_overwrite(&tmp_path, &target_path, b"expected", "taikai")
                    .expect_err("existing artifact symlink must reject install");
            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(
                !tmp_path.exists(),
                "failed idempotent comparison should still clean the temp artifact"
            );
            assert!(
                fs::symlink_metadata(&target_path)
                    .expect("inspect symlink")
                    .file_type()
                    .is_symlink(),
                "failed install should leave existing symlink visible"
            );
            assert!(target.exists(), "symlink target should not be removed");
        }
        #[cfg(unix)]
        #[test]
        fn taikai_anchor_request_capture_rejects_symlink() {
            use std::os::unix::fs::symlink;
            let dir = tempdir().expect("tempdir");
            let target = dir.path().join("request-target.json");
            fs::write(&target, b"expected").expect("write symlink target");
            let request_path = dir.path().join("taikai-anchor-request-test.json");
            symlink(&target, &request_path).expect("create anchor request symlink");
            let err = validate_existing_anchor_request_capture(&request_path, b"expected")
                .expect_err("symlinked anchor request capture must reject");
            assert_eq!(err.kind(), ErrorKind::AlreadyExists);
            assert!(
                fs::symlink_metadata(&request_path)
                    .expect("inspect symlink")
                    .file_type()
                    .is_symlink(),
                "failed validation should leave request symlink visible"
            );
            assert!(target.exists(), "symlink target should not be removed");
        }
    }
    fn existing_taikai_artifact_path_if_matching(
        target_path: &Path,
        expected: &[u8],
        prefix: &str,
    ) -> io::Result<Option<PathBuf>> {
        let metadata = match fs::symlink_metadata(target_path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Taikai artifact {prefix} already exists at {} but is not a regular file",
                    target_path.display()
                ),
            ));
        }
        let label = format!("Taikai artifact {prefix}");
        let expected_len = u64::try_from(expected.len()).unwrap_or(u64::MAX);
        if metadata.len() != expected_len {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Taikai artifact {prefix} already exists at {} with different bytes",
                    target_path.display()
                ),
            ));
        }
        let existing = read_regular_taikai_file_bounded(target_path, &label, expected.len())?;
        if existing == expected {
            Ok(Some(target_path.to_path_buf()))
        } else {
            Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Taikai artifact {prefix} already exists at {} with different bytes",
                    target_path.display()
                ),
            ))
        }
    }
    fn validate_existing_taikai_artifact(
        target_path: &Path,
        expected: &[u8],
        prefix: &str,
    ) -> io::Result<()> {
        match existing_taikai_artifact_path_if_matching(target_path, expected, prefix)? {
            Some(_) => Ok(()),
            None => Err(io::Error::new(
                ErrorKind::NotFound,
                format!(
                    "Taikai artifact {prefix} disappeared before idempotent comparison at {}",
                    target_path.display()
                ),
            )),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn persist_artifact(
        spool_dir: &Path,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
        prefix: &str,
        extension: &str,
        bytes: &[u8],
        maximum: usize,
    ) -> io::Result<Option<PathBuf>> {
        ensure_taikai_artifact_size(prefix, bytes.len(), maximum)?;
        if spool_dir.as_os_str().is_empty() {
            return Ok(None);
        }
        let base_dir = spool_dir.join(TAIKAI_SPOOL_SUBDIR);
        create_taikai_spool_dir_no_follow(&base_dir)?;
        let lane = lane_id.as_u32();
        let ticket_hex = hex::encode(storage_ticket.as_ref());
        let fingerprint_hex = hex::encode(fingerprint.as_bytes());
        let file_name = format!(
            "{prefix}-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.{extension}"
        );
        let target_path = base_dir.join(&file_name);
        let base_id =
            taikai_artifact_base_id(lane_id, epoch, sequence, storage_ticket, fingerprint);
        let sentinel_path = base_dir.join(format!(
            "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
        ));
        match fs::symlink_metadata(&sentinel_path) {
            // Only the anchor worker has the governed public key required to
            // authenticate this receipt. A regular file here is therefore
            // not sufficient evidence that the ingest was acknowledged: keep
            // materializing the replay so the worker can either verify and
            // retire it or quarantine the invalid receipt and upload it.
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Taikai anchor sentinel is not a regular file: {}",
                        sentinel_path.display()
                    ),
                ));
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        if prefix != "taikai-envelope" && prefix != TAIKAI_LINEAGE_HINT_PREFIX {
            let envelope_path = base_dir.join(format!("taikai-envelope-{base_id}.norito"));
            match fs::symlink_metadata(&envelope_path) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                Ok(_) => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "Taikai envelope is not a regular file: {}",
                            envelope_path.display()
                        ),
                    ));
                }
                Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(err),
            }
        }
        if let Some(path) = existing_taikai_artifact_path_if_matching(&target_path, bytes, prefix)?
        {
            return Ok(Some(path));
        }
        let tmp_name = format!(
            ".{prefix}-{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}.tmp-{}",
            artifact_temp_suffix()?
        );
        let tmp_path = base_dir.join(tmp_name);
        match write_temp_artifact(&tmp_path, bytes) {
            Ok(()) => {}
            Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
        }
        install_artifact_without_overwrite(&tmp_path, &target_path, bytes, prefix)?;
        debug!(
            path = ?target_path,
            lane = lane,
            epoch,
            sequence,
            ticket = %ticket_hex,
            kind = prefix,
            "queued Taikai artefact for anchoring"
        );
        Ok(Some(target_path))
    }
    fn taikai_artifact_base_id(
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        storage_ticket: &StorageTicketId,
        fingerprint: &ReplayFingerprint,
    ) -> String {
        format!(
            "{lane:08x}-{epoch:016x}-{sequence:016x}-{ticket_hex}-{fingerprint_hex}",
            lane = lane_id.as_u32(),
            ticket_hex = hex::encode(storage_ticket.as_ref()),
            fingerprint_hex = hex::encode(fingerprint.as_bytes()),
        )
    }
    fn parse_u64(value: &str, key: &str) -> Result<u64, (StatusCode, String)> {
        value
            .trim()
            .parse::<u64>()
            .map_err(|err| bad_request(key, format!("invalid integer `{value}`: {err}")))
    }
    pub(crate) fn parse_u64_metadata(
        metadata: &ExtraMetadata,
        key: &str,
    ) -> Result<u64, (StatusCode, String)> {
        parse_u64(require_utf8(metadata, key)?, key)
    }
    fn parse_u32(value: &str, key: &str) -> Result<u32, (StatusCode, String)> {
        value
            .trim()
            .parse::<u32>()
            .map_err(|err| bad_request(key, format!("invalid integer `{value}`: {err}")))
    }
    fn parse_i32(value: &str, key: &str) -> Result<i32, (StatusCode, String)> {
        value
            .trim()
            .parse::<i32>()
            .map_err(|err| bad_request(key, format!("invalid integer `{value}`: {err}")))
    }
    pub(crate) fn parse_name(
        metadata: &ExtraMetadata,
        key: &str,
    ) -> Result<Name, (StatusCode, String)> {
        let value = require_utf8(metadata, key)?;
        Name::from_str(value.trim())
            .map_err(|err| bad_request(key, format!("invalid Name `{value}`: {err}")))
    }
    fn require_utf8<'a>(
        metadata: &'a ExtraMetadata,
        key: &str,
    ) -> Result<&'a str, (StatusCode, String)> {
        let entry = metadata_entry(metadata, key)?;
        std::str::from_utf8(&entry.value).map_err(|_| bad_request(key, "value must be valid UTF-8"))
    }
    fn optional_utf8<'a>(
        metadata: &'a ExtraMetadata,
        key: &str,
    ) -> Result<Option<&'a str>, (StatusCode, String)> {
        let Some(entry) = unique_metadata_entry(metadata, key)? else {
            return Ok(None);
        };
        validate_metadata_entry(entry).map_err(|message| bad_request(key, message))?;
        let value = std::str::from_utf8(&entry.value)
            .map_err(|_| bad_request(key, "value must be valid UTF-8"))?;
        Ok(Some(value))
    }
    pub(crate) fn take_ssm_entry(
        metadata: &mut ExtraMetadata,
    ) -> Result<Option<Vec<u8>>, (StatusCode, String)> {
        let mut matching = metadata
            .items
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.key == META_TAIKAI_SSM);
        if let Some((index, _)) = matching.next() {
            if matching.next().is_some() {
                return Err(bad_request(
                    META_TAIKAI_SSM,
                    "metadata entry must appear at most once",
                ));
            }
            let entry = metadata.items.remove(index);
            validate_metadata_entry(&entry)
                .map_err(|message| bad_request(META_TAIKAI_SSM, message))?;
            ensure_taikai_artifact_size(
                "Taikai signing manifest",
                entry.value.len(),
                TAIKAI_ANCHOR_SSM_MAX_BYTES,
            )
            .map_err(|err| bad_request(META_TAIKAI_SSM, err.to_string()))?;
            return Ok(Some(entry.value));
        }
        Ok(None)
    }
    pub(crate) fn take_trm_entry(
        metadata: &mut ExtraMetadata,
    ) -> Result<Option<Vec<u8>>, (StatusCode, String)> {
        let mut matching = metadata
            .items
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.key == META_TAIKAI_TRM);
        if let Some((index, _)) = matching.next() {
            if matching.next().is_some() {
                return Err(bad_request(
                    META_TAIKAI_TRM,
                    "metadata entry must appear at most once",
                ));
            }
            let entry = metadata.items.remove(index);
            validate_metadata_entry(&entry)
                .map_err(|message| bad_request(META_TAIKAI_TRM, message))?;
            ensure_taikai_artifact_size(
                "Taikai routing manifest",
                entry.value.len(),
                TAIKAI_ANCHOR_TRM_MAX_BYTES,
            )
            .map_err(|err| bad_request(META_TAIKAI_TRM, err.to_string()))?;
            return Ok(Some(entry.value));
        }
        Ok(None)
    }
    fn metadata_entry<'a>(
        metadata: &'a ExtraMetadata,
        key: &str,
    ) -> Result<&'a MetadataEntry, (StatusCode, String)> {
        let entry = unique_metadata_entry(metadata, key)?.ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("metadata entry `{key}` is required for Taikai segments"),
            )
        })?;
        validate_metadata_entry(entry).map_err(|message| bad_request(key, message))?;
        Ok(entry)
    }
    fn unique_metadata_entry<'a>(
        metadata: &'a ExtraMetadata,
        key: &str,
    ) -> Result<Option<&'a MetadataEntry>, (StatusCode, String)> {
        let mut matching = metadata.items.iter().filter(|entry| entry.key == key);
        let first = matching.next();
        if matching.next().is_some() {
            return Err(bad_request(key, "metadata entry must appear at most once"));
        }
        Ok(first)
    }
    fn validate_metadata_entry(entry: &MetadataEntry) -> Result<(), String> {
        if entry.visibility != MetadataVisibility::Public {
            return Err("must use public visibility".into());
        }
        if !matches!(entry.encryption, MetadataEncryption::None) {
            return Err("must not be encrypted".into());
        }
        Ok(())
    }
    pub(crate) fn bad_request(key: &str, message: impl Into<String>) -> (StatusCode, String) {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid Taikai metadata `{key}`: {}", message.into()),
        )
    }
    fn parse_error(key: &str, err: TaikaiParseError) -> (StatusCode, String) {
        bad_request(key, err.to_string())
    }
    pub(crate) fn internal_error(message: String) -> (StatusCode, String) {
        (StatusCode::INTERNAL_SERVER_ERROR, message)
    }
    fn encode_base32_lower(data: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        if data.is_empty() {
            return String::new();
        }
        let mut acc = 0u32;
        let mut bits = 0u32;
        let capacity = data.len().saturating_mul(8).div_ceil(5);
        let mut out = Vec::with_capacity(capacity);
        for &byte in data {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let index = ((acc >> bits) & 0x1f) as usize;
                out.push(ALPHABET[index]);
            }
        }
        if bits > 0 {
            let index = ((acc << (5 - bits)) & 0x1f) as usize;
            out.push(ALPHABET[index]);
        }
        let mut encoded = String::with_capacity(out.len());
        for byte in out {
            encoded.push(char::from(byte));
        }
        encoded
    }
    /// Validate and start the configured Taikai anchor worker.
    pub async fn spawn_anchor_worker(
        manifest_store_dir: PathBuf,
        anchor_cfg: DaTaikaiAnchor,
        shutdown: ShutdownSignal,
    ) -> Result<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>, String> {
        if anchor_cfg.poll_interval.is_zero() {
            return Err("Taikai anchor poll interval must be greater than zero".to_owned());
        }
        let poll_interval = anchor_cfg.poll_interval;
        let spool_dir = manifest_store_dir.join(TAIKAI_SPOOL_SUBDIR);
        let sender = HttpAnchorSender::new(anchor_cfg.request_timeout)
            .map_err(|err| format!("failed to initialise Taikai anchor HTTP client: {err}"))?;
        create_taikai_spool_dir_no_follow_async(&spool_dir).await?;
        let worker_shutdown = shutdown.clone();
        Ok(tokio::spawn(async move {
            run_anchor_worker(spool_dir, anchor_cfg, sender, shutdown, poll_interval).await;
            if worker_shutdown.is_sent() {
                crate::ToriiCriticalWorkerExit::StoppedByShutdown
            } else {
                crate::ToriiCriticalWorkerExit::UnexpectedExit
            }
        }))
    }
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use tokio::{
        fs as async_fs,
        time::{MissedTickBehavior, interval},
    };
    struct HttpAnchorSender {
        client: Client,
    }
    impl HttpAnchorSender {
        fn new(request_timeout: Duration) -> Result<Self, reqwest::Error> {
            Ok(Self {
                client: Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(request_timeout)
                    .build()?,
            })
        }
    }
    pub(crate) type AnchorSendError = Box<dyn std::error::Error + Send + Sync + 'static>;
    #[async_trait]
    pub(crate) trait AnchorSender: Send + Sync {
        async fn send(
            &self,
            endpoint: &reqwest::Url,
            base_id: &str,
            body: &str,
            api_token: Option<&str>,
        ) -> Result<Vec<u8>, AnchorSendError>;
    }
    #[async_trait]
    impl AnchorSender for HttpAnchorSender {
        async fn send(
            &self,
            endpoint: &reqwest::Url,
            _base_id: &str,
            body: &str,
            api_token: Option<&str>,
        ) -> Result<Vec<u8>, AnchorSendError> {
            let mut request = self
                .client
                .post(endpoint.clone())
                .header("content-type", "application/json");
            if let Some(token) = api_token {
                request = request.header("authorization", token);
            }
            let mut response = request
                .body(body.to_owned())
                .send()
                .await?
                .error_for_status()?;
            crate::read_reqwest_response_body_bounded(
                &mut response,
                TAIKAI_ANCHOR_RESPONSE_MAX_BYTES,
                "Taikai anchor receipt",
            )
            .await
            .map_err(Into::into)
        }
    }
    pub(crate) struct PendingUpload {
        base_id: String,
        body: String,
        sentinel_path: PathBuf,
    }
    #[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct PendingEnvelope {
        file_name: String,
        base_id: String,
        envelope_path: PathBuf,
    }
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct AnchorAckRecord {
        acknowledged_unix_secs: u64,
        base_id: String,
    }
    impl PendingUpload {
        #[cfg(test)]
        pub(crate) fn base_id(&self) -> &str {
            &self.base_id
        }
        #[cfg(test)]
        pub(crate) fn body(&self) -> &str {
            &self.body
        }
    }
    fn persist_anchor_request_capture(
        spool_dir: &Path,
        base_id: &str,
        body: &str,
    ) -> io::Result<()> {
        ensure_taikai_artifact_size(
            "Taikai anchor request payload",
            body.len(),
            TAIKAI_ANCHOR_REQUEST_MAX_BYTES,
        )?;
        let request_path = spool_dir.join(format!(
            "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
        ));
        let Some(name) = request_path.file_name().and_then(|name| name.to_str()) else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Taikai anchor request capture path is not valid UTF-8: {}",
                    request_path.display()
                ),
            ));
        };
        let tmp_path =
            request_path.with_file_name(format!(".{name}.tmp-{}", artifact_temp_suffix()?));
        match write_temp_artifact(&tmp_path, body.as_bytes()) {
            Ok(()) => {}
            Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
        }
        install_anchor_request_capture(&tmp_path, &request_path, body.as_bytes())
    }
    fn install_anchor_request_capture(
        tmp_path: &Path,
        request_path: &Path,
        expected: &[u8],
    ) -> io::Result<()> {
        match fs::hard_link(tmp_path, request_path) {
            Ok(()) => {
                let sync_result = sync_parent_dir(request_path);
                let remove_result = remove_temp_artifact(tmp_path);
                sync_result?;
                remove_result
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                let existing_result =
                    validate_existing_anchor_request_capture(request_path, expected);
                let remove_result = remove_temp_artifact(tmp_path);
                existing_result?;
                remove_result
            }
            Err(err) => {
                remove_temp_artifact(tmp_path)?;
                Err(err)
            }
        }
    }
    fn validate_existing_anchor_request_capture(
        request_path: &Path,
        expected: &[u8],
    ) -> io::Result<()> {
        let metadata = fs::symlink_metadata(request_path)?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "Taikai anchor request capture path is not a file: {}",
                    request_path.display()
                ),
            ));
        }
        let expected_len = u64::try_from(expected.len()).unwrap_or(u64::MAX);
        if metadata.len() != expected_len {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Taikai anchor request capture already exists with different contents: {}",
                    request_path.display()
                ),
            ));
        }
        let existing = read_regular_taikai_file_bounded(
            request_path,
            "Taikai anchor request capture",
            expected.len().min(TAIKAI_ANCHOR_REQUEST_MAX_BYTES),
        )?;
        if existing == expected {
            return Ok(());
        }
        Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "Taikai anchor request capture already exists with different contents: {}",
                request_path.display()
            ),
        ))
    }
    fn persist_anchor_sentinel(path: &Path, receipt: &[u8]) -> io::Result<()> {
        ensure_taikai_artifact_size(
            "Taikai anchor sentinel",
            receipt.len(),
            TAIKAI_ANCHOR_SENTINEL_MAX_BYTES,
        )?;
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Taikai anchor sentinel path is not valid UTF-8: {}",
                    path.display()
                ),
            ));
        };
        let tmp_path = path.with_file_name(format!(".{name}.tmp-{}", artifact_temp_suffix()?));
        match write_temp_artifact(&tmp_path, receipt) {
            Ok(()) => {}
            Err(err) => return Err(temp_artifact_write_error(&tmp_path, err)),
        }
        match fs::hard_link(&tmp_path, path) {
            Ok(()) => {
                let sync_result = sync_parent_dir(path);
                let remove_result = remove_temp_artifact(&tmp_path);
                sync_result?;
                remove_result
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                let existing_result = validate_existing_anchor_sentinel(path, receipt);
                let remove_result = remove_temp_artifact(&tmp_path);
                existing_result?;
                remove_result
            }
            Err(err) => {
                remove_temp_artifact(&tmp_path)?;
                Err(err)
            }
        }
    }
    fn validate_existing_anchor_sentinel(path: &Path, expected: &[u8]) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "Taikai anchor sentinel path is not a file: {}",
                    path.display()
                ),
            ));
        }
        if metadata.len() != u64::try_from(expected.len()).unwrap_or(u64::MAX) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Taikai anchor sentinel already exists with different contents: {}",
                    path.display()
                ),
            ));
        }
        let existing = read_regular_taikai_file_bounded(
            path,
            "Taikai anchor sentinel",
            expected.len().min(TAIKAI_ANCHOR_SENTINEL_MAX_BYTES),
        )?;
        if existing == expected {
            return Ok(());
        }
        Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "Taikai anchor sentinel already exists with different contents: {}",
                path.display()
            ),
        ))
    }

    fn quarantine_invalid_anchor_sentinel(path: &Path, marker: &[u8]) -> io::Result<PathBuf> {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Taikai anchor sentinel path is not valid UTF-8: {}",
                    path.display()
                ),
            ));
        };
        // A canonical sentinel name is already close to NAME_MAX. Bind its
        // complete identity with a digest instead of appending another digest
        // to the original name and making recovery fail with ENAMETOOLONG.
        let name_digest = hex::encode(blake3_hash(name.as_bytes()).as_bytes());
        let digest = hex::encode(blake3_hash(marker).as_bytes());
        let quarantine_path = path.with_file_name(format!(
            "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{name_digest}{TAIKAI_ANCHOR_INVALID_SUFFIX}-{digest}"
        ));
        match fs::hard_link(path, &quarantine_path) {
            Ok(()) => sync_parent_dir(&quarantine_path)?,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                validate_existing_anchor_sentinel(&quarantine_path, marker)?;
            }
            Err(err) => return Err(err),
        }
        fs::remove_file(path)?;
        sync_parent_dir(path)?;
        Ok(quarantine_path)
    }

    fn retire_anchored_source_artifacts(spool_dir: &Path, base_id: &str) -> io::Result<()> {
        if !valid_spool_artifact_base_id(base_id) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("malformed Taikai spool artifact id `{base_id}`"),
            ));
        }
        // Remove the envelope last. If cleanup is interrupted, its durable
        // acknowledgement still suppresses delivery and a later scan retries
        // retirement of the remaining companions.
        let artifacts = [
            (
                format!("taikai-indexes-{base_id}.json"),
                "Taikai indexes JSON",
            ),
            (
                format!("taikai-ssm-{base_id}.norito"),
                "Taikai signing manifest",
            ),
            (
                format!("taikai-trm-{base_id}.norito"),
                "Taikai routing manifest",
            ),
            (
                format!("{TAIKAI_LINEAGE_HINT_PREFIX}-{base_id}.json"),
                "Taikai lineage hint JSON",
            ),
            (
                format!("{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"),
                "Taikai anchor readiness marker",
            ),
            (
                format!("taikai-envelope-{base_id}.norito"),
                "Taikai envelope",
            ),
        ];
        let mut removed = false;
        for (file_name, label) in artifacts {
            removed |= remove_regular_taikai_file_if_present(&spool_dir.join(file_name), label)?;
        }
        if removed {
            sync_dir(spool_dir)?;
        }
        Ok(())
    }
    fn remove_regular_taikai_file_if_present(path: &Path, label: &str) -> io::Result<bool> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err),
        };
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{label} is not a regular file: {}", path.display()),
            ));
        }
        fs::remove_file(path)?;
        Ok(true)
    }
    async fn run_anchor_worker<S>(
        spool_dir: PathBuf,
        anchor_cfg: DaTaikaiAnchor,
        sender: S,
        shutdown: ShutdownSignal,
        poll_interval: Duration,
    ) where
        S: AnchorSender + 'static,
    {
        let mut ticker = interval(poll_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.receive() => break,
                _ = ticker.tick() => {
                    if let Err(err) = process_batch(&spool_dir, &anchor_cfg, &sender).await {
                        iroha_logger::error!(?err, "failed to process Taikai anchor batch");
                    }
                }
            }
        }
    }
    /// Deliver at most one fixed-size spool batch to the configured anchor.
    ///
    /// Directory enumeration retains only the earliest bounded set of paths,
    /// and each request body is loaded, sent, and dropped before the next one.
    /// A successful delivery is acknowledged durably before its source files
    /// are retired; acknowledgement/request audit files use a fixed window.
    pub(crate) async fn process_batch<S>(
        spool_dir: &Path,
        anchor_cfg: &DaTaikaiAnchor,
        sender: &S,
    ) -> Result<(), String>
    where
        S: AnchorSender + ?Sized,
    {
        let pending = collect_pending_envelopes(spool_dir, &anchor_cfg.receipt_public_key).await?;
        prune_anchor_ack_history(spool_dir, &anchor_cfg.receipt_public_key).await?;
        let mut processing_errors = Vec::with_capacity(pending.len());
        for candidate in pending {
            let candidate_base_id = candidate.base_id.clone();
            let upload = match load_pending_upload(spool_dir, candidate).await {
                Ok(upload) => upload,
                Err(err) => {
                    let message =
                        format!("failed to load Taikai anchor upload `{candidate_base_id}`: {err}");
                    iroha_logger::warn!(
                        base = candidate_base_id.as_str(),
                        ?err,
                        "failed to load Taikai anchor upload"
                    );
                    processing_errors.push(message);
                    continue;
                }
            };
            let PendingUpload {
                base_id,
                body,
                sentinel_path,
            } = upload;
            match sender
                .send(
                    &anchor_cfg.endpoint,
                    &base_id,
                    &body,
                    anchor_cfg.api_token.as_deref(),
                )
                .await
            {
                Ok(response) => {
                    let receipt = match validate_anchor_receipt(
                        &response,
                        &base_id,
                        body.as_bytes(),
                        &anchor_cfg.receipt_public_key,
                    ) {
                        Ok(receipt) => receipt,
                        Err(err) => {
                            let message = format!(
                                "anchor service returned an invalid Taikai receipt for `{base_id}`: {err}"
                            );
                            iroha_logger::warn!(
                                base = base_id.as_str(),
                                ?err,
                                "anchor service returned an invalid Taikai receipt"
                            );
                            processing_errors.push(message);
                            continue;
                        }
                    };
                    let canonical_receipt = json::to_vec(&receipt).map_err(|err| {
                        format!(
                            "failed to encode verified Taikai anchor receipt for `{base_id}`: {err}"
                        )
                    })?;
                    if let Err(err) = persist_anchor_sentinel(&sentinel_path, &canonical_receipt) {
                        let message = format!(
                            "failed to persist Taikai anchor sentinel `{}`: {err}",
                            sentinel_path.display()
                        );
                        iroha_logger::warn!(
                            ?err,
                            sentinel = %sentinel_path.display(),
                            base = base_id.as_str(),
                            "failed to persist Taikai anchor sentinel"
                        );
                        processing_errors.push(message);
                    } else if let Err(err) = retire_anchored_source_artifacts(spool_dir, &base_id) {
                        let message = format!(
                            "failed to retire anchored Taikai source artifacts for `{base_id}`: {err}"
                        );
                        iroha_logger::warn!(
                            ?err,
                            base = base_id.as_str(),
                            "failed to retire anchored Taikai source artifacts"
                        );
                        processing_errors.push(message);
                    }
                }
                Err(err) => {
                    let message = format!(
                        "failed to deliver Taikai envelope `{}` to anchor service: {err}",
                        base_id.as_str()
                    );
                    iroha_logger::warn!(
                        ?err,
                        base = base_id.as_str(),
                        "failed to deliver Taikai envelope to anchor service"
                    );
                    processing_errors.push(message);
                }
            }
        }
        if let Err(err) = prune_anchor_ack_history(spool_dir, &anchor_cfg.receipt_public_key).await
        {
            processing_errors.push(format!(
                "failed to prune Taikai anchor acknowledgements: {err}"
            ));
        }
        match processing_errors.as_slice() {
            [] => Ok(()),
            [message] => Err(message.clone()),
            messages => Err(format!(
                "failed to process {count} Taikai anchor uploads: {}",
                messages.join("; "),
                count = messages.len()
            )),
        }
    }
    /// Collect one deterministic, bounded upload batch for source-coupled tests.
    ///
    /// Production processing loads and sends one selected envelope at a time;
    /// this adapter remains bounded by [`TAIKAI_ANCHOR_BATCH_MAX`].
    #[cfg(test)]
    pub(crate) async fn collect_pending_uploads(
        spool_dir: &Path,
    ) -> Result<Vec<PendingUpload>, String> {
        let receipt_public_key = test_anchor_receipt_public_key();
        let pending = collect_pending_envelopes(spool_dir, &receipt_public_key).await?;
        let mut uploads = Vec::with_capacity(pending.len());
        for candidate in pending {
            uploads.push(load_pending_upload(spool_dir, candidate).await?);
        }
        Ok(uploads)
    }
    async fn collect_pending_envelopes(
        spool_dir: &Path,
        receipt_public_key: &iroha_crypto::PublicKey,
    ) -> Result<Vec<PendingEnvelope>, String> {
        let mut earliest = BinaryHeap::with_capacity(TAIKAI_ANCHOR_BATCH_MAX);
        let Some(mut dir) = open_taikai_spool_dir(spool_dir).await? else {
            return Ok(Vec::new());
        };
        while let Some(entry) = dir.next_entry().await.map_err(|err| {
            format!(
                "failed to iterate Taikai spool directory `{}`: {err}",
                spool_dir.display()
            )
        })? {
            let file_name = entry.file_name();
            let Some(file_name) = taikai_envelope_file_name(&file_name)?.map(ToOwned::to_owned)
            else {
                continue;
            };
            let base_id =
                file_name["taikai-envelope-".len()..file_name.len() - ".norito".len()].to_string();
            if !valid_spool_artifact_base_id(base_id.as_str()) {
                return Err(format!(
                    "Taikai envelope has malformed spool artifact id `{base_id}`"
                ));
            }
            let sentinel_path = spool_dir.join(format!(
                "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
            ));
            match async_fs::symlink_metadata(&sentinel_path).await {
                Ok(metadata) => {
                    if metadata.file_type().is_file() {
                        if let Err(err) = read_verified_anchor_ack(
                            spool_dir,
                            &sentinel_path,
                            &base_id,
                            receipt_public_key,
                        )
                        .await
                        {
                            let marker = read_required_regular_file(
                                &sentinel_path,
                                "Taikai anchor sentinel",
                                TAIKAI_ANCHOR_SENTINEL_MAX_BYTES,
                            )
                            .await
                            .map_err(|read_err| {
                                format!(
                                    "{err}; failed to read invalid Taikai anchor sentinel `{}` for quarantine: {read_err}",
                                    sentinel_path.display()
                                )
                            })?;
                            let quarantine_path = quarantine_invalid_anchor_sentinel(
                                &sentinel_path,
                                &marker,
                            )
                            .map_err(|quarantine_err| {
                                format!(
                                    "{err}; failed to quarantine invalid Taikai anchor sentinel `{}`: {quarantine_err}",
                                    sentinel_path.display()
                                )
                            })?;
                            iroha_logger::warn!(
                                base = base_id.as_str(),
                                sentinel = %sentinel_path.display(),
                                quarantine = %quarantine_path.display(),
                                reason = err,
                                "quarantined invalid Taikai anchor acknowledgement"
                            );
                        } else {
                            retire_anchored_source_artifacts(spool_dir, &base_id).map_err(|err| {
                                format!(
                                    "failed to retire acknowledged Taikai source artifacts for `{base_id}`: {err}"
                                )
                            })?;
                            continue;
                        }
                    } else {
                        return Err(format!(
                            "Taikai anchor sentinel `{}` is not a regular file",
                            sentinel_path.display()
                        ));
                    }
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "failed to inspect Taikai anchor sentinel `{}`: {err}",
                        sentinel_path.display()
                    ));
                }
            }
            let ready_path = spool_dir.join(format!(
                "{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"
            ));
            if matches!(
                async_fs::symlink_metadata(&ready_path).await,
                Err(ref err) if err.kind() == ErrorKind::NotFound
            ) {
                continue;
            }
            let candidate = PendingEnvelope {
                file_name,
                base_id,
                envelope_path: entry.path(),
            };
            if earliest.len() < TAIKAI_ANCHOR_BATCH_MAX {
                earliest.push(candidate);
            } else if earliest
                .peek()
                .is_some_and(|latest_selected| candidate < *latest_selected)
            {
                let _ = earliest.pop();
                earliest.push(candidate);
            }
        }
        Ok(earliest.into_sorted_vec())
    }
    #[cfg(test)]
    fn test_anchor_receipt_public_key() -> iroha_crypto::PublicKey {
        test_anchor_receipt_keypair().public_key().clone()
    }
    #[cfg(test)]
    fn test_anchor_receipt_keypair() -> iroha_crypto::KeyPair {
        iroha_crypto::KeyPair::try_from_seed(vec![0xA7; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("derive deterministic Taikai anchor test key")
    }
    #[cfg(test)]
    fn test_anchor_receipt_bytes(
        base_id: &str,
        request_body: &[u8],
        acknowledged_unix_secs: u64,
    ) -> Vec<u8> {
        let body = TaikaiAnchorReceiptBodyV1 {
            schema: TAIKAI_ANCHOR_RECEIPT_SCHEMA_V1.to_owned(),
            version: TAIKAI_ANCHOR_RECEIPT_VERSION_V1,
            base_id: base_id.to_owned(),
            request_digest: *blake3_hash(request_body).as_bytes(),
            acknowledged_unix_secs,
        };
        let receipt = TaikaiAnchorReceiptV1::try_sign(body, &test_anchor_receipt_keypair())
            .expect("sign deterministic Taikai anchor test receipt");
        json::to_vec(&receipt).expect("encode deterministic Taikai anchor test receipt")
    }
    async fn load_pending_upload(
        spool_dir: &Path,
        candidate: PendingEnvelope,
    ) -> Result<PendingUpload, String> {
        let PendingEnvelope {
            base_id,
            envelope_path,
            ..
        } = candidate;
        let ready_path = spool_dir.join(format!(
            "{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"
        ));
        let ready_marker = read_required_regular_file(
            &ready_path,
            "Taikai anchor readiness marker",
            TAIKAI_ANCHOR_READY_MARKER.len(),
        )
        .await?;
        if ready_marker != TAIKAI_ANCHOR_READY_MARKER {
            return Err(format!(
                "Taikai anchor readiness marker `{}` has invalid contents",
                ready_path.display()
            ));
        }
        let indexes_name = format!("taikai-indexes-{base_id}.json");
        let indexes_path = spool_dir.join(&indexes_name);
        let ssm_name = format!("taikai-ssm-{base_id}.norito");
        let ssm_path = spool_dir.join(&ssm_name);
        let envelope_bytes = read_required_regular_file(
            &envelope_path,
            "Taikai envelope",
            TAIKAI_ANCHOR_ENVELOPE_MAX_BYTES,
        )
        .await?;
        let envelope_b64 = BASE64.encode(envelope_bytes);
        let indexes_bytes = read_required_regular_file(
            &indexes_path,
            "Taikai indexes JSON",
            TAIKAI_ANCHOR_INDEXES_MAX_BYTES,
        )
        .await?;
        let indexes_value: Value = json::from_slice(&indexes_bytes).map_err(|err| {
            format!(
                "failed to parse Taikai indexes JSON `{}`: {err}",
                indexes_path.display()
            )
        })?;
        drop(indexes_bytes);
        let ssm_bytes = read_required_regular_file(
            &ssm_path,
            "Taikai signing manifest",
            TAIKAI_ANCHOR_SSM_MAX_BYTES,
        )
        .await?;
        let ssm_b64 = BASE64.encode(ssm_bytes);
        let trm_name = format!("taikai-trm-{base_id}.norito");
        let trm_path = spool_dir.join(&trm_name);
        let trm_b64 = read_optional_regular_file(
            &trm_path,
            "Taikai routing manifest",
            TAIKAI_ANCHOR_TRM_MAX_BYTES,
        )
        .await?
        .map(|bytes| BASE64.encode(bytes));
        let lineage_name = format!("{TAIKAI_LINEAGE_HINT_PREFIX}-{base_id}.json");
        let lineage_path = spool_dir.join(&lineage_name);
        let lineage_value = match read_optional_regular_file(
            &lineage_path,
            "Taikai lineage hint JSON",
            TAIKAI_ANCHOR_LINEAGE_MAX_BYTES,
        )
        .await?
        {
            Some(bytes) => Some(json::from_slice(&bytes).map_err(|err| {
                format!(
                    "failed to parse Taikai lineage hint JSON `{}`: {err}",
                    lineage_path.display()
                )
            })?),
            None => None,
        };
        let mut payload = Map::new();
        payload.insert("envelope_base64".to_string(), Value::String(envelope_b64));
        payload.insert("indexes".to_string(), indexes_value);
        payload.insert("ssm_base64".to_string(), Value::String(ssm_b64));
        if let Some(trm_b64) = trm_b64 {
            payload.insert("trm_base64".to_string(), Value::String(trm_b64));
        }
        if let Some(value) = lineage_value {
            payload.insert("lineage_hint".to_string(), value);
        }
        let payload = Value::Object(payload);
        let body = json::to_string(&payload).map_err(|err| {
            format!("failed to encode Taikai anchor payload for `{base_id}`: {err}")
        })?;
        ensure_taikai_artifact_size(
            "Taikai anchor request payload",
            body.len(),
            TAIKAI_ANCHOR_REQUEST_MAX_BYTES,
        )
        .map_err(|err| err.to_string())?;
        persist_anchor_request_capture(spool_dir, base_id.as_str(), &body).map_err(|err| {
            format!(
                "failed to persist Taikai anchor request payload `{}`: {err}",
                spool_dir
                    .join(format!(
                        "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
                    ))
                    .display()
            )
        })?;
        let sentinel_path = spool_dir.join(format!(
            "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
        ));
        Ok(PendingUpload {
            base_id,
            body,
            sentinel_path,
        })
    }
    fn validate_anchor_receipt(
        encoded: &[u8],
        expected_base_id: &str,
        request_body: &[u8],
        receipt_public_key: &iroha_crypto::PublicKey,
    ) -> Result<TaikaiAnchorReceiptV1, String> {
        if encoded.is_empty() || encoded.len() > TAIKAI_ANCHOR_RESPONSE_MAX_BYTES {
            return Err(format!(
                "Taikai anchor receipt must contain 1..={TAIKAI_ANCHOR_RESPONSE_MAX_BYTES} bytes"
            ));
        }
        let receipt: TaikaiAnchorReceiptV1 = json::from_slice(encoded)
            .map_err(|err| format!("failed to decode Taikai anchor receipt JSON: {err}"))?;
        if receipt.body.base_id != expected_base_id {
            return Err(format!(
                "Taikai anchor receipt base_id `{}` does not match `{expected_base_id}`",
                receipt.body.base_id
            ));
        }
        if !valid_spool_artifact_base_id(&receipt.body.base_id) {
            return Err("Taikai anchor receipt base_id is not canonical".to_owned());
        }
        let expected_digest = *blake3_hash(request_body).as_bytes();
        if receipt.body.request_digest != expected_digest {
            return Err(
                "Taikai anchor receipt request digest does not match the upload".to_owned(),
            );
        }
        receipt
            .verify(receipt_public_key)
            .map_err(|err| format!("Taikai anchor receipt signature validation failed: {err}"))?;
        Ok(receipt)
    }
    async fn read_verified_anchor_ack(
        spool_dir: &Path,
        sentinel_path: &Path,
        expected_base_id: &str,
        receipt_public_key: &iroha_crypto::PublicKey,
    ) -> Result<TaikaiAnchorReceiptV1, String> {
        let marker = read_required_regular_file(
            sentinel_path,
            "Taikai anchor sentinel",
            TAIKAI_ANCHOR_SENTINEL_MAX_BYTES,
        )
        .await
        .map_err(|err| {
            format!(
                "failed to validate Taikai anchor sentinel `{}`: {err}",
                sentinel_path.display()
            )
        })?;
        let request_path = spool_dir.join(format!(
            "{TAIKAI_ANCHOR_REQUEST_PREFIX}{expected_base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
        ));
        let request_body = read_required_regular_file(
            &request_path,
            "Taikai anchor request capture",
            TAIKAI_ANCHOR_REQUEST_MAX_BYTES,
        )
        .await?;
        validate_anchor_receipt(&marker, expected_base_id, &request_body, receipt_public_key)
            .map_err(|err| {
                format!(
                    "Taikai anchor sentinel `{}` is not a verified receipt: {err}",
                    sentinel_path.display()
                )
            })
    }
    async fn prune_anchor_ack_history(
        spool_dir: &Path,
        receipt_public_key: &iroha_crypto::PublicKey,
    ) -> Result<(), String> {
        let Some(mut dir) = open_taikai_spool_dir(spool_dir).await? else {
            return Ok(());
        };
        let mut newest = BinaryHeap::with_capacity(TAIKAI_ANCHOR_ACK_RETENTION_MAX);
        let mut acknowledgement_count = 0usize;
        while let Some(entry) = dir.next_entry().await.map_err(|err| {
            format!(
                "failed to scan Taikai anchor acknowledgements in `{}`: {err}",
                spool_dir.display()
            )
        })? {
            let Some(record) =
                read_anchor_ack_record(spool_dir, &entry, receipt_public_key).await?
            else {
                continue;
            };
            retire_anchored_source_artifacts(spool_dir, &record.base_id).map_err(|err| {
                format!(
                    "failed to retire acknowledged Taikai source artifacts for `{}`: {err}",
                    record.base_id
                )
            })?;
            acknowledgement_count = acknowledgement_count.checked_add(1).ok_or_else(|| {
                "Taikai anchor acknowledgement count exceeds platform limits".to_string()
            })?;
            if newest.len() < TAIKAI_ANCHOR_ACK_RETENTION_MAX {
                newest.push(Reverse(record));
            } else if newest
                .peek()
                .is_some_and(|oldest_retained| record > oldest_retained.0)
            {
                let _ = newest.pop();
                newest.push(Reverse(record));
            }
        }
        drop(dir);
        if acknowledgement_count <= TAIKAI_ANCHOR_ACK_RETENTION_MAX {
            return Ok(());
        }
        let retention_floor = newest
            .peek()
            .map(|Reverse(record)| record.clone())
            .ok_or_else(|| "Taikai anchor acknowledgement retention window is empty".to_string())?;
        let Some(mut dir) = open_taikai_spool_dir(spool_dir).await? else {
            return Ok(());
        };
        let mut removed = false;
        while let Some(entry) = dir.next_entry().await.map_err(|err| {
            format!(
                "failed to prune Taikai anchor acknowledgements in `{}`: {err}",
                spool_dir.display()
            )
        })? {
            let Some(record) =
                read_anchor_ack_record(spool_dir, &entry, receipt_public_key).await?
            else {
                continue;
            };
            if record >= retention_floor {
                continue;
            }
            ensure_anchor_source_retired(spool_dir, &record.base_id).await?;
            removed |= remove_anchor_ack_record(spool_dir, &record.base_id, &entry.path()).await?;
        }
        drop(dir);
        if removed {
            sync_dir(spool_dir).map_err(|err| {
                format!(
                    "failed to sync pruned Taikai anchor acknowledgements in `{}`: {err}",
                    spool_dir.display()
                )
            })?;
        }
        Ok(())
    }
    async fn read_anchor_ack_record(
        spool_dir: &Path,
        entry: &async_fs::DirEntry,
        receipt_public_key: &iroha_crypto::PublicKey,
    ) -> Result<Option<AnchorAckRecord>, String> {
        let file_name = entry.file_name();
        let Some(base_id) = taikai_anchor_sentinel_base_id(&file_name)?.map(ToOwned::to_owned)
        else {
            return Ok(None);
        };
        if !valid_spool_artifact_base_id(&base_id) {
            return Err(format!(
                "Taikai anchor sentinel has malformed spool artifact id `{base_id}`"
            ));
        }
        let sentinel_path = entry.path();
        let receipt = match read_verified_anchor_ack(
            spool_dir,
            &sentinel_path,
            &base_id,
            receipt_public_key,
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(reason) => {
                let marker = read_required_regular_file(
                    &sentinel_path,
                    "Taikai anchor sentinel",
                    TAIKAI_ANCHOR_SENTINEL_MAX_BYTES,
                )
                .await
                .map_err(|read_err| {
                    format!(
                        "{reason}; failed to read invalid Taikai anchor sentinel `{}` for quarantine: {read_err}",
                        sentinel_path.display()
                    )
                })?;
                let quarantine_path = quarantine_invalid_anchor_sentinel(&sentinel_path, &marker)
                    .map_err(|quarantine_err| {
                        format!(
                            "{reason}; failed to quarantine invalid Taikai anchor sentinel `{}`: {quarantine_err}",
                            sentinel_path.display()
                        )
                    })?;
                iroha_logger::warn!(
                    base = base_id.as_str(),
                    sentinel = %sentinel_path.display(),
                    quarantine = %quarantine_path.display(),
                    reason,
                    "quarantined invalid Taikai anchor acknowledgement"
                );
                return Ok(None);
            }
        };
        Ok(Some(AnchorAckRecord {
            acknowledged_unix_secs: receipt.body.acknowledged_unix_secs,
            base_id,
        }))
    }
    async fn ensure_anchor_source_retired(spool_dir: &Path, base_id: &str) -> Result<(), String> {
        let envelope_path = spool_dir.join(format!("taikai-envelope-{base_id}.norito"));
        match async_fs::symlink_metadata(&envelope_path).await {
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to inspect acknowledged Taikai envelope `{}`: {err}",
                envelope_path.display()
            )),
            Ok(_) => Err(format!(
                "refusing to prune Taikai anchor acknowledgement while source envelope remains: {}",
                envelope_path.display()
            )),
        }
    }
    async fn remove_anchor_ack_record(
        spool_dir: &Path,
        base_id: &str,
        sentinel_path: &Path,
    ) -> Result<bool, String> {
        let request_path = spool_dir.join(format!(
            "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
        ));
        let mut removed = false;
        // Source retirement is verified before pruning. Remove the sentinel
        // first so a crash can never leave a receipt that has lost the exact
        // request capture required for restart verification.
        removed |=
            remove_regular_taikai_file_if_present_async(sentinel_path, "Taikai anchor sentinel")
                .await?;
        removed |= remove_regular_taikai_file_if_present_async(
            &request_path,
            "Taikai anchor request capture",
        )
        .await?;
        Ok(removed)
    }
    async fn remove_regular_taikai_file_if_present_async(
        path: &Path,
        label: &str,
    ) -> Result<bool, String> {
        let metadata = match async_fs::symlink_metadata(path).await {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(format!(
                    "failed to inspect {label} `{}`: {err}",
                    path.display()
                ));
            }
        };
        if !metadata.file_type().is_file() {
            return Err(format!(
                "{label} `{}` is not a regular file",
                path.display()
            ));
        }
        async_fs::remove_file(path)
            .await
            .map_err(|err| format!("failed to remove {label} `{}`: {err}", path.display()))?;
        Ok(true)
    }
    async fn open_taikai_spool_dir(spool_dir: &Path) -> Result<Option<async_fs::ReadDir>, String> {
        let metadata = match async_fs::symlink_metadata(spool_dir).await {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(format!(
                    "failed to read Taikai spool directory `{}`: {err}",
                    spool_dir.display()
                ));
            }
        };
        validate_taikai_spool_dir_metadata(spool_dir, &metadata).map_err(|err| err.to_string())?;
        async_fs::read_dir(spool_dir)
            .await
            .map(Some)
            .map_err(|err| {
                format!(
                    "failed to read Taikai spool directory `{}`: {err}",
                    spool_dir.display()
                )
            })
    }
    async fn create_taikai_spool_dir_no_follow_async(spool_dir: &Path) -> Result<(), String> {
        async_fs::create_dir_all(spool_dir).await.map_err(|err| {
            format!(
                "failed to create Taikai spool directory `{}`: {err}",
                spool_dir.display()
            )
        })?;
        let metadata = async_fs::symlink_metadata(spool_dir).await.map_err(|err| {
            format!(
                "failed to inspect Taikai spool directory `{}`: {err}",
                spool_dir.display()
            )
        })?;
        validate_taikai_spool_dir_metadata(spool_dir, &metadata).map_err(|err| err.to_string())
    }
    async fn read_required_regular_file(
        path: &Path,
        label: &str,
        maximum: usize,
    ) -> Result<Vec<u8>, String> {
        read_optional_regular_file(path, label, maximum)
            .await?
            .ok_or_else(|| {
                format!(
                    "failed to read {label} `{}`: entity not found",
                    path.display()
                )
            })
    }
    async fn read_optional_regular_file(
        path: &Path,
        label: &str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, String> {
        let owned_path = path.to_path_buf();
        let owned_label = label.to_owned();
        let display_path = owned_path.clone();
        let result = crate::panic_recovery::join_recoverable(
            crate::panic_recovery::spawn_blocking_recoverable(move || {
                read_regular_taikai_file_bounded(&owned_path, &owned_label, maximum)
            }),
        )
        .await
        .map_err(|err| {
            format!(
                "failed to read {label} `{}` because the blocking reader failed: {err}",
                display_path.display()
            )
        })?;
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!(
                "failed to read {label} `{}`: {err}",
                display_path.display()
            )),
        }
    }
    fn valid_spool_artifact_base_id(base_id: &str) -> bool {
        is_canonical_taikai_anchor_base_id(base_id)
    }
    fn taikai_envelope_file_name(name: &OsStr) -> Result<Option<&str>, String> {
        if let Some(name) = name.to_str() {
            return Ok(
                (name.starts_with("taikai-envelope-") && name.ends_with(".norito")).then_some(name),
            );
        }
        if non_utf8_artifact_name_matches(name, b"taikai-envelope-", b".norito") {
            return Err("Taikai envelope filename is not valid UTF-8".to_string());
        }
        Ok(None)
    }
    fn taikai_anchor_sentinel_base_id(name: &OsStr) -> Result<Option<&str>, String> {
        let Some(name) = name.to_str() else {
            if non_utf8_artifact_name_matches(
                name,
                TAIKAI_ANCHOR_SENTINEL_PREFIX.as_bytes(),
                TAIKAI_ANCHOR_SENTINEL_SUFFIX.as_bytes(),
            ) {
                return Err("Taikai anchor sentinel filename is not valid UTF-8".to_string());
            }
            return Ok(None);
        };
        let Some(base_id) = name
            .strip_prefix(TAIKAI_ANCHOR_SENTINEL_PREFIX)
            .and_then(|name| name.strip_suffix(TAIKAI_ANCHOR_SENTINEL_SUFFIX))
        else {
            return Ok(None);
        };
        Ok(Some(base_id))
    }
    #[cfg(unix)]
    fn non_utf8_artifact_name_matches(name: &OsStr, prefix: &[u8], suffix: &[u8]) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let bytes = name.as_bytes();
        bytes.starts_with(prefix) && bytes.ends_with(suffix)
    }
    #[cfg(not(unix))]
    fn non_utf8_artifact_name_matches(_name: &OsStr, _prefix: &[u8], _suffix: &[u8]) -> bool {
        false
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn anchor_worker_config(poll_interval: Duration) -> DaTaikaiAnchor {
            DaTaikaiAnchor {
                endpoint: reqwest::Url::parse("https://anchor.example")
                    .expect("valid anchor endpoint"),
                api_token: None,
                receipt_public_key: test_anchor_receipt_public_key(),
                poll_interval,
                request_timeout: Duration::from_secs(1),
            }
        }
        fn anchor_test_base_id(sequence: usize) -> String {
            format!(
                "00000001-0000000000000002-{sequence:016x}-\
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-\
                 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
        }
        #[test]
        fn invalid_anchor_quarantine_bounds_names_and_preserves_exact_evidence() {
            let directory = tempfile::tempdir().expect("quarantine fixture");
            let source = directory.path().join(format!(
                "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}",
                "a".repeat(220),
            ));
            fs::write(&source, b"invalid-first").unwrap();
            let first = quarantine_invalid_anchor_sentinel(&source, b"invalid-first").unwrap();
            assert!(first.file_name().unwrap().len() < 255);
            assert_eq!(fs::read(&first).unwrap(), b"invalid-first");
            assert!(!source.exists());
            fs::write(&source, b"invalid-first").unwrap();
            assert_eq!(
                quarantine_invalid_anchor_sentinel(&source, b"invalid-first").unwrap(),
                first
            );
            fs::write(&source, b"invalid-second").unwrap();
            let second = quarantine_invalid_anchor_sentinel(&source, b"invalid-second").unwrap();
            assert_ne!(first, second);
            assert_eq!(fs::read(&first).unwrap(), b"invalid-first");
            assert_eq!(fs::read(&second).unwrap(), b"invalid-second");
            let other = directory.path().join("taikai-anchor-other.ok");
            fs::write(&other, b"invalid-first").unwrap();
            assert_ne!(
                quarantine_invalid_anchor_sentinel(&other, b"invalid-first").unwrap(),
                first
            );
            fs::write(&first, b"conflicting evidence").unwrap();
            fs::write(&source, b"invalid-first").unwrap();
            quarantine_invalid_anchor_sentinel(&source, b"invalid-first")
                .expect_err("conflicting evidence must not be overwritten or retire the source");
            assert_eq!(fs::read(&source).unwrap(), b"invalid-first");
            assert_eq!(fs::read(&first).unwrap(), b"conflicting evidence");
        }
        #[tokio::test]
        async fn anchor_worker_startup_is_fallible_and_shutdown_owned() {
            let directory = tempfile::tempdir().expect("tempdir");
            let shutdown = ShutdownSignal::new();
            let zero_interval = spawn_anchor_worker(
                directory.path().to_path_buf(),
                anchor_worker_config(Duration::ZERO),
                shutdown.clone(),
            )
            .await
            .expect_err("zero interval must fail startup");
            assert!(zero_interval.contains("greater than zero"));

            fs::write(
                directory.path().join(TAIKAI_SPOOL_SUBDIR),
                b"not a directory",
            )
            .expect("block spool directory");
            let invalid_store = spawn_anchor_worker(
                directory.path().to_path_buf(),
                anchor_worker_config(Duration::from_secs(1)),
                shutdown,
            )
            .await
            .expect_err("unsafe spool path must fail startup");
            assert!(invalid_store.contains("Taikai spool directory"));

            let directory = tempfile::tempdir().expect("valid worker tempdir");
            let shutdown = ShutdownSignal::new();
            let worker = spawn_anchor_worker(
                directory.path().to_path_buf(),
                anchor_worker_config(Duration::from_secs(1)),
                shutdown.clone(),
            )
            .await
            .expect("valid worker starts");
            shutdown.send();
            assert_eq!(
                worker.await.expect("worker joins"),
                crate::ToriiCriticalWorkerExit::StoppedByShutdown
            );
        }
        #[test]
        fn taikai_artifact_size_accepts_boundary_and_rejects_overflow() {
            ensure_taikai_artifact_size("test artifact", 8, 8).expect("exact boundary accepts");
            let err = ensure_taikai_artifact_size("test artifact", 9, 8)
                .expect_err("one byte over the limit rejects");
            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err.to_string().contains("exceeding the 8-byte limit"));
        }
        #[test]
        fn oversized_envelope_is_rejected_before_spool_creation() {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage_ticket = StorageTicketId::new([0xAA; 32]);
            let fingerprint = ReplayFingerprint::from_hash(blake3_hash(b"oversized-envelope"));
            let oversized = vec![0_u8; TAIKAI_ANCHOR_ENVELOPE_MAX_BYTES + 1];
            let err = persist_envelope(
                dir.path(),
                LaneId::new(1),
                2,
                3,
                &storage_ticket,
                &fingerprint,
                &oversized,
            )
            .expect_err("oversized envelope must fail closed");
            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err.to_string().contains("exceeding"));
            assert!(
                !dir.path().join(TAIKAI_SPOOL_SUBDIR).exists(),
                "oversized append must not create the spool directory"
            );
        }
        #[test]
        fn unverified_anchor_sentinel_does_not_suppress_replayed_artifact() {
            let dir = tempfile::tempdir().expect("tempdir");
            let storage_ticket = StorageTicketId::new([0xAA; 32]);
            let fingerprint = ReplayFingerprint::from_hash(blake3_hash(b"replayed-envelope"));
            let base_id =
                taikai_artifact_base_id(LaneId::new(1), 2, 3, &storage_ticket, &fingerprint);
            let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
            fs::create_dir(&spool_dir).expect("create spool directory");
            fs::write(
                spool_dir.join(format!(
                    "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
                )),
                b"unverified receipt",
            )
            .expect("write unverified receipt");

            let persisted = persist_envelope(
                dir.path(),
                LaneId::new(1),
                2,
                3,
                &storage_ticket,
                &fingerprint,
                b"envelope",
            )
            .expect("replay must remain materialized for receipt verification");

            assert!(persisted.is_some());
            assert_eq!(
                fs::read(spool_dir.join(format!("taikai-envelope-{base_id}.norito")))
                    .expect("read replayed envelope"),
                b"envelope"
            );
        }
        #[tokio::test]
        async fn pending_envelope_selection_is_sorted_and_batch_bounded() {
            let dir = tempfile::tempdir().expect("tempdir");
            let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
            async_fs::create_dir(&spool_dir)
                .await
                .expect("create spool");
            let total = TAIKAI_ANCHOR_BATCH_MAX + 2;
            for sequence in (0..total).rev() {
                let base_id = anchor_test_base_id(sequence);
                async_fs::write(
                    spool_dir.join(format!("taikai-envelope-{base_id}.norito")),
                    b"envelope",
                )
                .await
                .expect("write envelope");
                async_fs::write(
                    spool_dir.join(format!(
                        "{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"
                    )),
                    TAIKAI_ANCHOR_READY_MARKER,
                )
                .await
                .expect("write readiness marker");
            }
            let pending = collect_pending_envelopes(&spool_dir, &test_anchor_receipt_public_key())
                .await
                .expect("select bounded batch");
            let observed: Vec<_> = pending
                .into_iter()
                .map(|candidate| candidate.base_id)
                .collect();
            let expected: Vec<_> = (0..TAIKAI_ANCHOR_BATCH_MAX)
                .map(anchor_test_base_id)
                .collect();
            assert_eq!(observed, expected);
        }
        #[tokio::test]
        async fn bounded_async_artifact_read_rejects_oversized_sparse_file() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("taikai-envelope.norito");
            let file = async_fs::File::create(&path)
                .await
                .expect("create artifact");
            file.set_len(65).await.expect("extend sparse artifact");
            let err = read_required_regular_file(&path, "Taikai envelope", 64)
                .await
                .expect_err("oversized artifact rejects before buffering");
            assert!(err.contains("exceeding the 64-byte limit"));
        }
        #[test]
        fn anchored_source_retirement_preserves_bounded_audit_artifacts() {
            let dir = tempfile::tempdir().expect("tempdir");
            let spool_dir = dir.path();
            let base_id = anchor_test_base_id(7);
            let source_names = [
                format!("taikai-envelope-{base_id}.norito"),
                format!("taikai-indexes-{base_id}.json"),
                format!("taikai-ssm-{base_id}.norito"),
                format!("taikai-trm-{base_id}.norito"),
                format!("{TAIKAI_LINEAGE_HINT_PREFIX}-{base_id}.json"),
                format!("{TAIKAI_ANCHOR_READY_PREFIX}{base_id}{TAIKAI_ANCHOR_READY_SUFFIX}"),
            ];
            for name in &source_names {
                fs::write(spool_dir.join(name), b"artifact").expect("write source artifact");
            }
            let sentinel = spool_dir.join(format!(
                "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
            ));
            let capture = spool_dir.join(format!(
                "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
            ));
            fs::write(&sentinel, b"ack").expect("write sentinel");
            fs::write(&capture, b"request").expect("write capture");
            retire_anchored_source_artifacts(spool_dir, &base_id).expect("retire source artifacts");
            for name in source_names {
                assert!(!spool_dir.join(name).exists(), "source artifact remains");
            }
            assert!(sentinel.exists(), "durable acknowledgement must remain");
            assert!(capture.exists(), "bounded request capture must remain");
        }
        #[tokio::test]
        async fn anchor_ack_history_retains_only_deterministic_newest_window() {
            let dir = tempfile::tempdir().expect("tempdir");
            let spool_dir = dir.path().join(TAIKAI_SPOOL_SUBDIR);
            async_fs::create_dir(&spool_dir)
                .await
                .expect("create spool");
            let total = TAIKAI_ANCHOR_ACK_RETENTION_MAX + 2;
            for sequence in 0..total {
                let base_id = anchor_test_base_id(sequence);
                let request_body = b"request";
                async_fs::write(
                    spool_dir.join(format!(
                        "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
                    )),
                    test_anchor_receipt_bytes(
                        &base_id,
                        request_body,
                        u64::try_from(sequence).expect("small sequence") + 1,
                    ),
                )
                .await
                .expect("write sentinel");
                async_fs::write(
                    spool_dir.join(format!(
                        "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
                    )),
                    request_body,
                )
                .await
                .expect("write request capture");
            }
            prune_anchor_ack_history(&spool_dir, &test_anchor_receipt_public_key())
                .await
                .expect("prune acknowledgement history");
            for sequence in 0..total {
                let base_id = anchor_test_base_id(sequence);
                let sentinel = spool_dir.join(format!(
                    "{TAIKAI_ANCHOR_SENTINEL_PREFIX}{base_id}{TAIKAI_ANCHOR_SENTINEL_SUFFIX}"
                ));
                let capture = spool_dir.join(format!(
                    "{TAIKAI_ANCHOR_REQUEST_PREFIX}{base_id}{TAIKAI_ANCHOR_REQUEST_SUFFIX}"
                ));
                let should_remain = sequence >= total - TAIKAI_ANCHOR_ACK_RETENTION_MAX;
                assert_eq!(sentinel.exists(), should_remain, "sentinel retention");
                assert_eq!(capture.exists(), should_remain, "capture retention");
            }
        }
        #[test]
        fn encode_base32_lower_uses_lowercase_no_padding_alphabet() {
            assert_eq!(encode_base32_lower(b""), "");
            assert_eq!(encode_base32_lower(b"foo"), "mzxw6");
            assert_eq!(encode_base32_lower(&[0xff, 0x00]), "74aa");
        }
        #[cfg(unix)]
        #[test]
        fn taikai_envelope_file_name_rejects_non_utf8_shaped_name() {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            let name = OsString::from_vec(b"taikai-envelope-\xFF.norito".to_vec());
            let err = taikai_envelope_file_name(name.as_os_str())
                .expect_err("non-UTF8 envelope-shaped name rejects");
            assert!(err.contains("not valid UTF-8"));
        }
        #[cfg(unix)]
        #[test]
        fn taikai_envelope_file_name_ignores_unrelated_non_utf8_name() {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            let name = OsString::from_vec(b"taikai-index-\xFF.norito".to_vec());
            assert!(
                taikai_envelope_file_name(name.as_os_str())
                    .expect("unrelated non-UTF8 name is ignored")
                    .is_none()
            );
        }
        #[tokio::test]
        async fn taikai_async_reader_rejects_oversized_artifact() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("taikai-artifact.norito");
            async_fs::write(&path, b"replacement-artifact")
                .await
                .expect("seed oversized artifact");
            let err =
                read_optional_regular_file(&path, "Taikai artifact test", b"old-artifact".len())
                    .await
                    .expect_err("oversized artifact must reject");
            assert!(err.contains("exceeding"), "unexpected error: {err}");
        }
        #[cfg(unix)]
        #[tokio::test]
        async fn taikai_async_read_revalidation_rejects_symlink_replacement() {
            use std::os::unix::fs::symlink;
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("taikai-artifact.norito");
            async_fs::write(&path, b"old-artifact")
                .await
                .expect("seed artifact");
            let target = dir.path().join("artifact-target.norito");
            async_fs::write(&target, b"old-artifact")
                .await
                .expect("write symlink target");
            async_fs::remove_file(&path)
                .await
                .expect("remove original artifact");
            symlink(&target, &path).expect("replace artifact with symlink");
            let err =
                read_optional_regular_file(&path, "Taikai artifact test", b"old-artifact".len())
                    .await
                    .expect_err("symlink replacement must reject");
            assert!(
                err.contains("Taikai artifact test") && err.contains("taikai-artifact.norito"),
                "unexpected error: {err}"
            );
            assert!(
                fs::symlink_metadata(&path)
                    .expect("inspect symlink")
                    .file_type()
                    .is_symlink(),
                "failed revalidation should leave symlink visible"
            );
            assert!(target.exists(), "symlink target should not be removed");
        }
    }
}
#[cfg(test)]
use iroha_data_model::taikai::TAIKAI_ANCHOR_RECEIPT_SCHEMA_V1;
#[cfg(test)]
use iroha_data_model::taikai::TAIKAI_ANCHOR_RECEIPT_VERSION_V1;
#[cfg(test)]
use iroha_data_model::taikai::TaikaiAnchorReceiptBodyV1;
pub use taikai_ingest::spawn_anchor_worker;
/// Extract the Taikai stream label from metadata for telemetry tagging.
pub(crate) fn stream_label_from_metadata(metadata: &ExtraMetadata) -> Option<String> {
    metadata
        .items
        .iter()
        .find(|entry| entry.key == META_TAIKAI_STREAM_ID)
        .and_then(|entry| std::str::from_utf8(&entry.value).ok())
        .map(|value| value.trim().to_owned())
}
/// Validate the proof tier metadata against the enforced storage class.
pub(crate) fn validate_da_proof_tier(
    metadata: &ExtraMetadata,
    expected_storage_class: StorageClass,
) -> Result<(), (StatusCode, String)> {
    let entry = metadata
        .items
        .iter()
        .find(|entry| entry.key == META_DA_PROOF_TIER)
        .ok_or_else(|| {
            taikai_ingest::bad_request(
                META_DA_PROOF_TIER,
                "metadata entry is required for Taikai segments",
            )
        })?;
    if entry.visibility != MetadataVisibility::Public
        || !matches!(entry.encryption, MetadataEncryption::None)
    {
        return Err(taikai_ingest::bad_request(
            META_DA_PROOF_TIER,
            "metadata entry must be public and unencrypted",
        ));
    }
    let value = std::str::from_utf8(&entry.value)
        .map_err(|_| taikai_ingest::bad_request(META_DA_PROOF_TIER, "value must be UTF-8"))?
        .trim();
    let expected = storage_class_label(expected_storage_class);
    if value != expected {
        return Err(taikai_ingest::bad_request(
            META_DA_PROOF_TIER,
            format!("tier `{value}` does not match enforced storage class `{expected}`"),
        ));
    }
    Ok(())
}
#[derive(Debug)]
/// Result details from validating a Taikai signing manifest.
pub(crate) struct TaikaiSsmOutcome {
    /// Canonical publisher authenticated by the SSM signature.
    pub(crate) publisher_account: AccountId,
    /// Namespaced alias label referenced by the SSM.
    pub(crate) alias_label: String,
    /// Digest of the signing manifest payload.
    pub(crate) ssm_digest: BlobDigest,
    /// Alias binding authenticated by the SSM proof.
    pub(crate) alias_binding: TaikaiAliasBinding,
}
/// Validate a Taikai signing manifest payload against ingest artifacts.
pub(crate) fn validate_taikai_ssm(
    ssm_bytes: &[u8],
    (manifest_hash, car_digest): (&BlobDigest, &BlobDigest),
    envelope_bytes: &[u8],
    expected_sequence: u64,
    alias_policy: &AliasCachePolicy,
    alias_council_policy: Option<&ProviderAdmissionCouncilPolicy>,
    telemetry: &MaybeTelemetry,
) -> Result<TaikaiSsmOutcome, (StatusCode, String)> {
    taikai_ingest::ensure_taikai_artifact_size(
        "Taikai signing manifest",
        ssm_bytes.len(),
        TAIKAI_ANCHOR_SSM_MAX_BYTES,
    )
    .map_err(|err| taikai_ingest::bad_request(META_TAIKAI_SSM, err.to_string()))?;
    let signing_manifest: TaikaiSegmentSigningManifestV1 =
        decode_from_bytes(ssm_bytes).map_err(|err| {
            taikai_ingest::bad_request(
                META_TAIKAI_SSM,
                format!("failed to decode signing manifest: {err}"),
            )
        })?;
    if signing_manifest.body.version != TaikaiSegmentSigningBodyV1::VERSION {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            format!(
                "unsupported signing manifest version {}; expected {}",
                signing_manifest.body.version,
                TaikaiSegmentSigningBodyV1::VERSION
            ),
        ));
    }
    if signing_manifest.body.signed_unix_ms == 0 {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "signed_unix_ms must be a non-zero production timestamp",
        ));
    }
    match signing_manifest.body.publisher_key.try_algorithm() {
        Ok(iroha_crypto::Algorithm::Ed25519) => {
            iroha_crypto::ed25519_parse_signature(signing_manifest.signature.payload()).map_err(
                |err| {
                    taikai_ingest::bad_request(
                        META_TAIKAI_SSM,
                        format!("publisher signature material malformed: {err}"),
                    )
                },
            )?;
        }
        Ok(iroha_crypto::Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_parse_signature(signing_manifest.signature.payload()).map_err(
                |err| {
                    taikai_ingest::bad_request(
                        META_TAIKAI_SSM,
                        format!("publisher signature material malformed: {err}"),
                    )
                },
            )?;
        }
        _ => {}
    }
    signing_manifest
        .signature
        .verify(&signing_manifest.body.publisher_key, &signing_manifest.body)
        .map_err(|err| {
            taikai_ingest::bad_request(
                META_TAIKAI_SSM,
                format!("publisher signature verification failed: {err}"),
            )
        })?;
    if signing_manifest.body.publisher_account
        != AccountId::new(signing_manifest.body.publisher_key.clone())
    {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "publisher account does not match the account controlled by publisher_key",
        ));
    }
    if &signing_manifest.body.manifest_hash != manifest_hash {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "manifest hash mismatch between SSM and ingest artefact",
        ));
    }
    if &signing_manifest.body.car_digest != car_digest {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "CAR digest mismatch between SSM and ingest artefact",
        ));
    }
    let envelope_hash = BlobDigest::from_hash(blake3_hash(envelope_bytes));
    if signing_manifest.body.segment_envelope_hash != envelope_hash {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "envelope hash mismatch between SSM and ingest artefact",
        ));
    }
    if signing_manifest.body.segment_sequence != expected_sequence {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "segment sequence mismatch between SSM and ingest metadata",
        ));
    }
    let alias_binding = &signing_manifest.body.alias_binding;
    if alias_binding.proof.is_empty() {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "alias proof payload must not be empty",
        ));
    }
    let alias_label = format!("{}/{}", alias_binding.namespace, alias_binding.name);
    let alias_council_policy = alias_council_policy.ok_or_else(|| {
        taikai_ingest::internal_error(
            "Taikai alias admission requires a configured SoraFS council trust policy".into(),
        )
    })?;
    let alias_proof = crate::sorafs::decode_alias_proof(&alias_binding.proof, alias_council_policy)
        .map_err(|err| {
            taikai_ingest::bad_request(
                META_TAIKAI_SSM,
                format!("alias proof failed validation for `{alias_label}`: {err}"),
            )
        })?;
    if alias_proof.binding.alias != alias_label {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            format!(
                "alias proof binding `{}` does not match signing manifest alias `{alias_label}`",
                alias_proof.binding.alias
            ),
        ));
    }
    let expected_manifest_cid = canonical_manifest_root_cid(*manifest_hash.as_bytes());
    if alias_proof.binding.manifest_cid != expected_manifest_cid {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            format!(
                "alias proof manifest CID does not commit to the canonical DA manifest for `{alias_label}`"
            ),
        ));
    }
    let now_secs = crate::sorafs::unix_now_secs();
    let evaluation = alias_policy.evaluate(&alias_proof, now_secs);
    let status_label = evaluation.status_label();
    let result = if evaluation.state.is_servable() {
        "success"
    } else {
        "error"
    };
    telemetry.with_metrics(|metrics| {
        metrics.record_sorafs_alias_cache(result, status_label, evaluation.age.as_secs_f64());
    });
    if !evaluation.state.is_servable() {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            format!("alias proof for `{alias_label}` expired ({status_label})"),
        ));
    }
    let ssm_digest = BlobDigest::from_hash(blake3_hash(ssm_bytes));
    Ok(TaikaiSsmOutcome {
        publisher_account: signing_manifest.body.publisher_account.clone(),
        alias_label,
        ssm_digest,
        alias_binding: alias_binding.clone(),
    })
}
/// Require the outer DA principal to be the publisher authenticated by the SSM.
pub(crate) fn validate_taikai_publisher_owner(
    outcome: &TaikaiSsmOutcome,
    authenticated_owner: &AccountId,
) -> Result<(), (StatusCode, String)> {
    if &outcome.publisher_account != authenticated_owner {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_SSM,
            "authenticated DA owner does not match the SSM publisher account",
        ));
    }
    Ok(())
}
/// Derive the Taikai availability class from the routing manifest metadata.
pub(crate) fn taikai_availability_from_metadata(
    metadata: &ExtraMetadata,
    trm_payload: Option<&[u8]>,
) -> Result<Option<TaikaiAvailabilityClass>, (StatusCode, String)> {
    let Some(bytes) = trm_payload else {
        return Ok(None);
    };
    taikai_ingest::ensure_taikai_artifact_size(
        "Taikai routing manifest",
        bytes.len(),
        TAIKAI_ANCHOR_TRM_MAX_BYTES,
    )
    .map_err(|err| taikai_ingest::bad_request(META_TAIKAI_TRM, err.to_string()))?;
    let manifest: TaikaiRoutingManifestV1 = decode_from_bytes(bytes).map_err(|err| {
        taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!("failed to decode routing manifest: {err}"),
        )
    })?;
    let event_id = taikai_ingest::parse_name(metadata, META_TAIKAI_EVENT_ID)?;
    let stream_id = taikai_ingest::parse_name(metadata, META_TAIKAI_STREAM_ID)?;
    let rendition_name = taikai_ingest::parse_name(metadata, META_TAIKAI_RENDITION_ID)?;
    let sequence = taikai_ingest::parse_u64_metadata(metadata, META_TAIKAI_SEGMENT_SEQUENCE)?;
    let route = validate_taikai_trm_binding(
        &manifest,
        event_id.as_ref(),
        stream_id.as_ref(),
        rendition_name.as_ref(),
        sequence,
    )?;
    Ok(Some(route.availability_class))
}

fn validate_taikai_trm_binding<'a>(
    manifest: &'a TaikaiRoutingManifestV1,
    expected_event: &str,
    expected_stream: &str,
    expected_rendition: &str,
    expected_sequence: u64,
) -> Result<&'a TaikaiRenditionRouteV1, (StatusCode, String)> {
    if manifest.version != TaikaiRoutingManifestV1::VERSION {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!(
                "unsupported manifest version {}; expected {}",
                manifest.version,
                TaikaiRoutingManifestV1::VERSION
            ),
        ));
    }
    if let Err(err) = manifest.validate() {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!("invalid routing manifest: {err}"),
        ));
    }
    if manifest.event_id.as_name().as_ref() != expected_event {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!(
                "manifest event_id `{}` does not match segment metadata `{expected_event}`",
                manifest.event_id.as_name()
            ),
        ));
    }
    if manifest.stream_id.as_name().as_ref() != expected_stream {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!(
                "manifest stream_id `{}` does not match segment metadata `{expected_stream}`",
                manifest.stream_id.as_name()
            ),
        ));
    }
    let Some(route) = manifest
        .renditions
        .iter()
        .find(|route| route.rendition_id.as_name().as_ref() == expected_rendition)
    else {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!("manifest missing rendition `{expected_rendition}` required by this segment"),
        ));
    };
    if !manifest.covers_sequence(expected_sequence) {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            "manifest window does not cover this segment sequence",
        ));
    }
    if !route.covers_sequence(expected_sequence) {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!(
                "rendition `{expected_rendition}` signing window does not cover this segment sequence"
            ),
        ));
    }
    Ok(route)
}
/// Apply Taikai-specific metadata tags for ingest and proof policy enforcement.
pub(crate) fn apply_taikai_ingest_tags(
    metadata: &mut ExtraMetadata,
    availability: Option<TaikaiAvailabilityClass>,
    retention: &RetentionPolicy,
    payload_len: u64,
) {
    let availability_class =
        availability.unwrap_or_else(|| TaikaiAvailabilityClass::from(retention.storage_class));
    upsert_metadata(
        metadata,
        META_TAIKAI_AVAILABILITY_CLASS,
        availability_label(availability_class),
    );
    upsert_metadata(
        metadata,
        META_DA_PROOF_TIER,
        storage_class_label(retention.storage_class),
    );
    upsert_metadata(
        metadata,
        META_TAIKAI_REPLICATION_REPLICAS,
        retention.required_replicas.to_string(),
    );
    upsert_metadata(
        metadata,
        META_TAIKAI_REPLICATION_STORAGE,
        storage_class_label(retention.storage_class),
    );
    upsert_metadata(
        metadata,
        META_TAIKAI_REPLICATION_HOT_SECS,
        retention.hot_retention_secs.to_string(),
    );
    upsert_metadata(
        metadata,
        META_TAIKAI_REPLICATION_COLD_SECS,
        retention.cold_retention_secs.to_string(),
    );
    let sample_window = compute_sample_window(payload_len);
    upsert_metadata(
        metadata,
        META_DA_PDP_SAMPLE_WINDOW,
        sample_window.to_string(),
    );
    upsert_metadata(
        metadata,
        META_DA_POTR_SAMPLE_WINDOW,
        sample_window.to_string(),
    );
}
fn upsert_metadata(metadata: &mut ExtraMetadata, key: &str, value: impl Into<Vec<u8>>) {
    metadata.items.retain(|entry| entry.key != key);
    metadata.items.push(MetadataEntry::new(
        key,
        value.into(),
        MetadataVisibility::Public,
    ));
}
fn availability_label(class: TaikaiAvailabilityClass) -> &'static str {
    match class {
        TaikaiAvailabilityClass::Hot => "hot",
        TaikaiAvailabilityClass::Warm => "warm",
        TaikaiAvailabilityClass::Cold => "cold",
    }
}
/// Validate a Taikai routing manifest payload against the segment envelope.
pub(crate) fn validate_taikai_trm(
    trm_bytes: &[u8],
    envelope: &taikai_ingest::EnvelopeArtifacts,
    ssm_alias_binding: &TaikaiAliasBinding,
) -> Result<TaikaiRoutingManifestV1, (StatusCode, String)> {
    taikai_ingest::ensure_taikai_artifact_size(
        "Taikai routing manifest",
        trm_bytes.len(),
        TAIKAI_ANCHOR_TRM_MAX_BYTES,
    )
    .map_err(|err| taikai_ingest::bad_request(META_TAIKAI_TRM, err.to_string()))?;
    let manifest: TaikaiRoutingManifestV1 = decode_from_bytes(trm_bytes).map_err(|err| {
        taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            format!("failed to decode routing manifest: {err}"),
        )
    })?;
    let route = validate_taikai_trm_binding(
        &manifest,
        envelope.telemetry.event_id.as_str(),
        envelope.telemetry.stream_id.as_str(),
        envelope.telemetry.rendition_id.as_str(),
        envelope.telemetry.segment_sequence,
    )?;
    if &manifest.alias_binding != ssm_alias_binding {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            "routing manifest alias binding must match the authenticated SSM alias binding",
        ));
    }
    if route.latest_manifest_hash != envelope.ingest.manifest_hash {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            "rendition latest_manifest_hash does not reference this segment manifest",
        ));
    }
    if route.latest_car != envelope.ingest.car {
        return Err(taikai_ingest::bad_request(
            META_TAIKAI_TRM,
            "rendition latest_car does not reference this segment CAR",
        ));
    }
    Ok(manifest)
}
/// Record Taikai ingest latency/drift metrics for telemetry.
pub(crate) fn record_taikai_ingest_metrics(
    telemetry: &MaybeTelemetry,
    cluster_label: &str,
    sample: &taikai_ingest::TaikaiTelemetrySample,
) {
    if !telemetry.is_enabled() {
        return;
    }
    telemetry.with_metrics(|handle| {
        if let Some(latency) = sample.ingest_latency_ms {
            handle.observe_taikai_ingest_latency(cluster_label, sample.stream_id.as_str(), latency);
        }
        if let Some(drift) = sample.live_edge_drift_ms {
            handle.observe_taikai_live_edge_drift(cluster_label, sample.stream_id.as_str(), drift);
        }
    });
}
/// Record a Taikai alias rotation event in telemetry.
pub(crate) fn record_taikai_alias_rotation_event(
    telemetry: &MaybeTelemetry,
    cluster_label: &str,
    manifest: &TaikaiRoutingManifestV1,
    manifest_digest_hex: &str,
) {
    if !telemetry.is_enabled() {
        return;
    }
    let event_label = manifest.event_id.as_name().as_ref().to_owned();
    let stream_label = manifest.stream_id.as_name().as_ref().to_owned();
    let alias_namespace = manifest.alias_binding.namespace.clone();
    let alias_name = manifest.alias_binding.name.clone();
    let window = manifest.segment_window;
    telemetry.with_metrics(|handle| {
        handle.record_taikai_alias_rotation(
            cluster_label,
            &event_label,
            &stream_label,
            &alias_namespace,
            &alias_name,
            window.start_sequence,
            window.end_sequence,
            manifest_digest_hex,
        );
    });
}
/// Record a Taikai ingest error classified by status code.
pub(crate) fn record_taikai_ingest_error(
    telemetry: &MaybeTelemetry,
    cluster_label: &str,
    stream_label: &str,
    status: StatusCode,
) {
    if !telemetry.is_enabled() {
        return;
    }
    let reason = status
        .canonical_reason()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(status.as_u16().to_string()));
    telemetry.with_metrics(|handle| {
        handle.inc_taikai_ingest_error(cluster_label, stream_label, &reason);
    });
}
