use crate::set_no_follow_flag;
use crate::{CarWriter, ingest_single_file, verifier::CarVerifier};
use eyre::{Result, WrapErr, eyre};
use iroha_data_model::{
    da::types::{BlobDigest, ExtraMetadata, StorageTicketId},
    taikai::{
        SegmentDuration, SegmentTimestamp, TaikaiAudioLayout, TaikaiCarPointer, TaikaiCodec,
        TaikaiEnvelopeIndexes, TaikaiEventId, TaikaiIngestPointer, TaikaiRenditionId,
        TaikaiSegmentEnvelopeV1, TaikaiStreamId, TaikaiTrackKind, TaikaiTrackMetadata,
    },
};
use norito::json::{self, Map, Value};
use output_fs::{ensure_parent_dir, validate_output_path, validate_output_writable};
use std::{
    borrow::Cow,
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(test)]
mod output_file;
mod output_fs;
#[cfg(test)]
use output_file::write_output_bytes;

static STAGED_OUTPUT_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Request describing a Taikai segment bundle operation.
pub struct BundleRequest<'a> {
    pub payload_path: &'a Path,
    pub payload_bytes: Option<&'a [u8]>,
    pub car_out: &'a Path,
    pub envelope_out: &'a Path,
    pub indexes_out: Option<&'a Path>,
    pub ingest_metadata_out: Option<&'a Path>,
    pub manifest_hash: BlobDigest,
    pub storage_ticket: StorageTicketId,
    pub event_id: TaikaiEventId,
    pub stream_id: TaikaiStreamId,
    pub rendition_id: TaikaiRenditionId,
    pub track: TaikaiTrackMetadata,
    pub segment_sequence: u64,
    pub segment_start_pts: u64,
    pub segment_duration: u32,
    pub wallclock_unix_ms: u64,
    pub ingest_latency_ms: Option<u32>,
    pub live_edge_drift_ms: Option<i32>,
    pub ingest_node_id: Option<String>,
    pub extra_metadata: Option<ExtraMetadata>,
}
/// Summary describing the bundle artifacts that were generated.
#[derive(Debug, Clone)]
pub struct BundleSummary {
    pub car_pointer: TaikaiCarPointer,
    pub chunk_root: BlobDigest,
    pub chunk_count: u32,
    pub car_out: PathBuf,
    pub envelope_out: PathBuf,
    pub indexes: TaikaiEnvelopeIndexes,
    pub indexes_out: Option<PathBuf>,
    pub ingest_metadata_out: Option<PathBuf>,
    pub ingest_metadata: Map,
}
/// Commitments reconstructed from a canonically verified single-file Taikai CAR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTaikaiCar {
    /// Canonical CAR CID, archive digest, and archive size.
    pub car_pointer: TaikaiCarPointer,
    /// Merkle root of the reconstructed chunk set.
    pub chunk_root: BlobDigest,
    /// Number of chunks in the reconstructed chunk set.
    pub chunk_count: u32,
}
struct SegmentDetails<'a> {
    event_id: &'a TaikaiEventId,
    stream_id: &'a TaikaiStreamId,
    rendition_id: &'a TaikaiRenditionId,
    track: &'a TaikaiTrackMetadata,
    segment_sequence: u64,
    segment_start_pts: u64,
    segment_duration: u32,
    wallclock_unix_ms: u64,
    ingest_latency_ms: Option<u32>,
    live_edge_drift_ms: Option<i32>,
    ingest_node_id: Option<&'a str>,
    extra_metadata: Option<ExtraMetadata>,
}
/// Request describing how to regenerate Taikai bundle metadata from an existing CAR.
pub struct RehydrateRequest<'a> {
    pub car_in: &'a Path,
    pub car_out: &'a Path,
    pub envelope_out: &'a Path,
    pub indexes_out: Option<&'a Path>,
    pub ingest_metadata_out: Option<&'a Path>,
    pub manifest_hash: BlobDigest,
    pub storage_ticket: StorageTicketId,
    pub event_id: TaikaiEventId,
    pub stream_id: TaikaiStreamId,
    pub rendition_id: TaikaiRenditionId,
    pub track: TaikaiTrackMetadata,
    pub segment_sequence: u64,
    pub segment_start_pts: u64,
    pub segment_duration: u32,
    pub wallclock_unix_ms: u64,
    pub ingest_latency_ms: Option<u32>,
    pub live_edge_drift_ms: Option<i32>,
    pub ingest_node_id: Option<String>,
    pub extra_metadata: Option<ExtraMetadata>,
}
/// Validate the track shape and codec pairing accepted by Taikai DA ingest.
pub fn validate_track_metadata(track: &TaikaiTrackMetadata) -> Result<()> {
    if track.average_bitrate_kbps == 0 {
        return Err(eyre!("track bitrate must be greater than zero"));
    }
    if let TaikaiCodec::Custom(profile) = &track.codec
        && (profile.is_empty() || profile.trim() != profile.as_str())
    {
        return Err(eyre!(
            "custom codec profile must be non-empty and must not have surrounding whitespace"
        ));
    }
    if let TaikaiCodec::Custom(profile) = &track.codec
        && profile.chars().any(char::is_control)
    {
        return Err(eyre!(
            "custom codec profile must not contain control characters"
        ));
    }
    match track.kind {
        TaikaiTrackKind::Video => {
            if track.resolution.is_none() || track.audio_layout.is_some() {
                return Err(eyre!(
                    "video track metadata requires a resolution and no audio layout"
                ));
            }
            if track
                .resolution
                .is_some_and(|resolution| resolution.width == 0 || resolution.height == 0)
            {
                return Err(eyre!("video track resolution dimensions must be non-zero"));
            }
            if !matches!(
                &track.codec,
                TaikaiCodec::AvcHigh
                    | TaikaiCodec::HevcMain10
                    | TaikaiCodec::Av1Main
                    | TaikaiCodec::Custom(_)
            ) {
                return Err(eyre!(
                    "codec is not valid for a video track; expected AV1/AVC/HEVC or custom"
                ));
            }
        }
        TaikaiTrackKind::Audio => {
            if track.resolution.is_some() || track.audio_layout.is_none() {
                return Err(eyre!(
                    "audio track metadata requires an audio layout and no resolution"
                ));
            }
            if matches!(track.audio_layout, Some(TaikaiAudioLayout::Custom(0))) {
                return Err(eyre!(
                    "custom audio layout channel count must be greater than zero"
                ));
            }
            if !matches!(
                &track.codec,
                TaikaiCodec::AacLc | TaikaiCodec::Opus | TaikaiCodec::Custom(_)
            ) {
                return Err(eyre!(
                    "codec is not valid for an audio track; expected AAC/Opus or custom"
                ));
            }
        }
        TaikaiTrackKind::Data => {
            if track.resolution.is_some() || track.audio_layout.is_some() {
                return Err(eyre!(
                    "data track metadata must not include a resolution or audio layout"
                ));
            }
        }
    }
    Ok(())
}
/// Reconstruct and canonically verify a single-file Taikai CAR.
///
/// The payload and its chunk plan are derived from the archive before the complete CAR encoding is
/// reproduced byte-for-byte. Callers receive only commitments derived from that verified archive.
pub fn verify_taikai_car(car_bytes: &[u8]) -> Result<VerifiedTaikaiCar> {
    let verification = CarVerifier::verify_canonical_single_file_car(car_bytes)
        .map_err(|err| eyre!("failed to verify canonical Taikai CAR: {err}"))?;
    let chunk_count = verification
        .chunk_store
        .chunks()
        .len()
        .try_into()
        .map_err(|_| eyre!("chunk count exceeds u32::MAX"))?;
    let chunk_root = BlobDigest::new(*verification.chunk_store.por_tree().root());
    let car_stats = verification.stats;
    let car_digest = BlobDigest::from_hash(car_stats.car_archive_digest);
    let cid_multibase = format!("b{}", encode_base32_lower(&car_stats.car_cid)?);
    let car_pointer = TaikaiCarPointer::new(cid_multibase, car_digest, car_stats.car_size);
    Ok(VerifiedTaikaiCar {
        car_pointer,
        chunk_root,
        chunk_count,
    })
}
/// Bundle a Taikai segment into deterministic CAR + Norito artifacts.
pub fn bundle_segment(request: &BundleRequest<'_>) -> Result<BundleSummary> {
    validate_track_metadata(&request.track)?;
    if request.segment_duration == 0 {
        return Err(eyre!("segment duration must be greater than zero"));
    }
    let mut paths = vec![
        ("CAR output", request.car_out),
        ("envelope output", request.envelope_out),
    ];
    if let Some(path) = request.indexes_out {
        paths.push(("index output", path));
    }
    if let Some(path) = request.ingest_metadata_out {
        paths.push(("ingest metadata output", path));
    }
    for (_, path) in &paths {
        validate_output_writable(path)?;
    }
    if request.payload_bytes.is_none() {
        paths.push(("payload input", request.payload_path));
    }
    validate_distinct_artifact_paths(&paths)?;

    let payload_cow: Cow<'_, [u8]> = if let Some(bytes) = request.payload_bytes {
        Cow::Borrowed(bytes)
    } else {
        Cow::Owned(fs::read(request.payload_path).wrap_err_with(|| {
            format!(
                "failed to read payload `{}`",
                request.payload_path.display()
            )
        })?)
    };
    if payload_cow.is_empty() {
        return Err(eyre!(
            "payload `{}` is empty; segments must contain data",
            request.payload_path.display()
        ));
    }
    let summary = ingest_single_file(payload_cow.as_ref()).map_err(|err| {
        eyre!(
            "failed to build CAR plan for `{}`: {err}",
            request.payload_path.display()
        )
    })?;
    let chunk_count: u32 = summary
        .chunk_store
        .chunks()
        .len()
        .try_into()
        .map_err(|_| eyre!("chunk count exceeds u32::MAX"))?;
    let chunk_root = BlobDigest::new(*summary.chunk_store.por_tree().root());
    let writer = CarWriter::new(&summary.plan, payload_cow.as_ref())
        .map_err(|err| eyre!("failed to initialise CAR writer: {err}"))?;
    let (car_stage, mut car_file) = create_staged_output(request.car_out, "CAR archive")?;
    let car_stats = writer.write_to(&mut car_file).map_err(|err| {
        eyre!(
            "failed to stage CAR archive `{}`: {err}",
            request.car_out.display()
        )
    })?;
    car_file
        .flush()
        .wrap_err_with(|| format!("failed to flush staged CAR `{}`", request.car_out.display()))?;
    drop(car_file);
    let car_digest = BlobDigest::from_hash(car_stats.car_archive_digest);
    let cid_multibase = format!("b{}", encode_base32_lower(&car_stats.car_cid)?);
    let car_pointer = TaikaiCarPointer::new(cid_multibase.clone(), car_digest, car_stats.car_size);
    let ingest_pointer = TaikaiIngestPointer::new(
        request.manifest_hash,
        request.storage_ticket,
        chunk_root,
        chunk_count,
        car_pointer.clone(),
    );
    let ingest_node_id = request
        .ingest_node_id
        .as_deref()
        .map(str::trim)
        .filter(|node_id| !node_id.is_empty());
    let details = SegmentDetails {
        event_id: &request.event_id,
        stream_id: &request.stream_id,
        rendition_id: &request.rendition_id,
        track: &request.track,
        segment_sequence: request.segment_sequence,
        segment_start_pts: request.segment_start_pts,
        segment_duration: request.segment_duration,
        wallclock_unix_ms: request.wallclock_unix_ms,
        ingest_latency_ms: request.ingest_latency_ms,
        live_edge_drift_ms: request.live_edge_drift_ms,
        ingest_node_id,
        extra_metadata: request.extra_metadata.clone(),
    };
    let envelope = build_envelope(&details, ingest_pointer);
    let ingest_metadata = build_ingest_metadata_from_details(&details)?;
    let (bundle_summary, prepared_outputs) = prepare_outputs(
        &envelope,
        ingest_metadata,
        request.envelope_out,
        request.indexes_out,
        request.ingest_metadata_out,
        request.car_out,
    )?;
    let mut staged_outputs = Vec::with_capacity(1 + prepared_outputs.len());
    staged_outputs.push(car_stage);
    staged_outputs.extend(stage_prepared_outputs(prepared_outputs)?);
    publish_staged_outputs(staged_outputs)?;
    Ok(bundle_summary)
}
fn build_envelope(
    details: &SegmentDetails<'_>,
    ingest_pointer: TaikaiIngestPointer,
) -> TaikaiSegmentEnvelopeV1 {
    let mut envelope = TaikaiSegmentEnvelopeV1::new(
        details.event_id.clone(),
        details.stream_id.clone(),
        details.rendition_id.clone(),
        details.track.clone(),
        details.segment_sequence,
        SegmentTimestamp::new(details.segment_start_pts),
        SegmentDuration::new(details.segment_duration),
        details.wallclock_unix_ms,
        ingest_pointer,
    );
    if let Some(latency) = details.ingest_latency_ms {
        envelope.instrumentation.encoder_to_ingest_latency_ms = Some(latency);
    }
    if let Some(drift) = details.live_edge_drift_ms {
        envelope.instrumentation.live_edge_drift_ms = Some(drift);
    }
    if let Some(node_id) = details.ingest_node_id {
        envelope.instrumentation.ingest_node_id = Some(node_id.to_owned());
    }
    if let Some(extra) = &details.extra_metadata {
        envelope.metadata = extra.clone();
    }
    envelope
}
fn build_ingest_metadata_from_details(details: &SegmentDetails<'_>) -> Result<Map> {
    let params = IngestMetadataParams {
        event_id: details.event_id,
        stream_id: details.stream_id,
        rendition_id: details.rendition_id,
        track: details.track,
        segment_sequence: details.segment_sequence,
        segment_start_pts: details.segment_start_pts,
        segment_duration: details.segment_duration,
        wallclock_unix_ms: details.wallclock_unix_ms,
        ingest_latency_ms: details.ingest_latency_ms,
        live_edge_drift_ms: details.live_edge_drift_ms,
        ingest_node_id: details.ingest_node_id,
    };
    build_ingest_metadata_inner(&params)
}
fn prepare_outputs<'a>(
    envelope: &TaikaiSegmentEnvelopeV1,
    ingest_metadata: Map,
    envelope_out: &'a Path,
    indexes_out: Option<&'a Path>,
    ingest_metadata_out: Option<&'a Path>,
    car_out: &Path,
) -> Result<(BundleSummary, Vec<PreparedOutput<'a>>)> {
    let envelope_bytes =
        norito::to_bytes(envelope).wrap_err("failed to encode Taikai envelope payload")?;
    let mut prepared_outputs = vec![PreparedOutput {
        target: envelope_out,
        label: "envelope output",
        bytes: envelope_bytes,
    }];
    let indexes = envelope.indexes();
    let indexes_out_paths = if let Some(path) = indexes_out {
        let rendered = json::to_json_pretty(&indexes)
            .map_err(|err| eyre!("failed to render Taikai index JSON: {err}"))?;
        prepared_outputs.push(PreparedOutput {
            target: path,
            label: "index output",
            bytes: rendered.into_bytes(),
        });
        Some(path.to_path_buf())
    } else {
        None
    };
    let ingest_metadata_out_paths = if let Some(path) = ingest_metadata_out {
        let rendered = json::to_json_pretty(&Value::Object(ingest_metadata.clone()))
            .map_err(|err| eyre!("failed to render ingest metadata JSON: {err}"))?;
        prepared_outputs.push(PreparedOutput {
            target: path,
            label: "ingest metadata output",
            bytes: rendered.into_bytes(),
        });
        Some(path.to_path_buf())
    } else {
        None
    };
    Ok((
        BundleSummary {
            car_pointer: envelope.ingest.car.clone(),
            chunk_root: envelope.ingest.chunk_root,
            chunk_count: envelope.ingest.chunk_count,
            car_out: car_out.to_path_buf(),
            envelope_out: envelope_out.to_path_buf(),
            indexes,
            indexes_out: indexes_out_paths,
            ingest_metadata_out: ingest_metadata_out_paths,
            ingest_metadata,
        },
        prepared_outputs,
    ))
}
/// Rebuild Taikai envelope/index/ingest metadata for an existing CAR archive.
pub fn rehydrate_from_car(request: &RehydrateRequest<'_>) -> Result<BundleSummary> {
    validate_track_metadata(&request.track)?;
    if request.segment_duration == 0 {
        return Err(eyre!("segment duration must be greater than zero"));
    }
    let mut outputs = vec![
        ("CAR output", request.car_out),
        ("envelope output", request.envelope_out),
    ];
    let mut non_car_outputs = vec![
        ("CAR input", request.car_in),
        ("envelope output", request.envelope_out),
    ];
    if let Some(path) = request.indexes_out {
        outputs.push(("index output", path));
        non_car_outputs.push(("index output", path));
    }
    if let Some(path) = request.ingest_metadata_out {
        outputs.push(("ingest metadata output", path));
        non_car_outputs.push(("ingest metadata output", path));
    }
    for (_, path) in &outputs {
        validate_output_path(path)?;
    }
    validate_distinct_artifact_paths(&outputs)?;
    // Rehydrating in place (including normalized aliases and hard links) is supported, but no
    // metadata artifact may overwrite the source archive.
    validate_distinct_artifact_paths(&non_car_outputs)?;
    let car_output_is_input = paths_resolve_to_same_entry(request.car_in, request.car_out)?;
    if !car_output_is_input {
        validate_output_writable(request.car_out)?;
    }
    validate_output_writable(request.envelope_out)?;
    if let Some(path) = request.indexes_out {
        validate_output_writable(path)?;
    }
    if let Some(path) = request.ingest_metadata_out {
        validate_output_writable(path)?;
    }

    let car_bytes = fs::read(request.car_in)
        .wrap_err_with(|| format!("failed to read CAR `{}`", request.car_in.display()))?;
    let verified = verify_taikai_car(&car_bytes).wrap_err_with(|| {
        format!(
            "failed to reconstruct canonical Taikai CAR `{}`",
            request.car_in.display()
        )
    })?;
    let ingest_pointer = TaikaiIngestPointer::new(
        request.manifest_hash,
        request.storage_ticket,
        verified.chunk_root,
        verified.chunk_count,
        verified.car_pointer,
    );
    let ingest_node_id = request
        .ingest_node_id
        .as_deref()
        .map(str::trim)
        .filter(|node_id| !node_id.is_empty());
    let details = SegmentDetails {
        event_id: &request.event_id,
        stream_id: &request.stream_id,
        rendition_id: &request.rendition_id,
        track: &request.track,
        segment_sequence: request.segment_sequence,
        segment_start_pts: request.segment_start_pts,
        segment_duration: request.segment_duration,
        wallclock_unix_ms: request.wallclock_unix_ms,
        ingest_latency_ms: request.ingest_latency_ms,
        live_edge_drift_ms: request.live_edge_drift_ms,
        ingest_node_id,
        extra_metadata: request.extra_metadata.clone(),
    };
    let envelope = build_envelope(&details, ingest_pointer);
    let ingest_metadata = build_ingest_metadata_from_details(&details)?;
    let (bundle_summary, prepared_outputs) = prepare_outputs(
        &envelope,
        ingest_metadata,
        request.envelope_out,
        request.indexes_out,
        request.ingest_metadata_out,
        request.car_out,
    )?;
    let car_output_count = if car_output_is_input { 0 } else { 1 };
    let mut staged_outputs = Vec::with_capacity(car_output_count + prepared_outputs.len());
    if !car_output_is_input {
        staged_outputs.push(stage_output_bytes(
            request.car_out,
            "CAR output",
            &car_bytes,
        )?);
    }
    staged_outputs.extend(stage_prepared_outputs(prepared_outputs)?);
    publish_staged_outputs(staged_outputs)?;
    Ok(bundle_summary)
}
/// Load the optional extra metadata JSON document used by publishers.
pub fn load_extra_metadata(path: &Path) -> Result<ExtraMetadata> {
    let contents = fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read metadata JSON `{}`", path.display()))?;
    json::from_str(&contents)
        .wrap_err_with(|| format!("failed to parse metadata JSON `{}`", path.display()))
}
/// Validate that named Taikai inputs and outputs neither alias nor nest within one another.
pub fn validate_distinct_artifact_paths(paths: &[(&str, &Path)]) -> Result<()> {
    for (index, (left_label, left_path)) in paths.iter().enumerate() {
        for (right_label, right_path) in &paths[index + 1..] {
            let left_normalized = normalize_absolute_path(left_path)?;
            let right_normalized = normalize_absolute_path(right_path)?;
            if left_normalized != right_normalized
                && (left_normalized.starts_with(&right_normalized)
                    || right_normalized.starts_with(&left_normalized))
            {
                return Err(eyre!(
                    "{left_label} `{}` and {right_label} `{}` must not be nested paths",
                    left_path.display(),
                    right_path.display()
                ));
            }
            if paths_resolve_to_same_entry(left_path, right_path)? {
                return Err(eyre!(
                    "{left_label} `{}` and {right_label} `{}` must use distinct paths",
                    left_path.display(),
                    right_path.display()
                ));
            }
        }
    }
    Ok(())
}
fn paths_resolve_to_same_entry(left: &Path, right: &Path) -> Result<bool> {
    if normalize_absolute_path(left)? == normalize_absolute_path(right)? {
        return Ok(true);
    }

    let left_metadata = match fs::metadata(left) {
        Ok(metadata) => Some(metadata),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(eyre!(
                "failed to inspect artifact path `{}`: {err}",
                left.display()
            ));
        }
    };
    let right_metadata = match fs::metadata(right) {
        Ok(metadata) => Some(metadata),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(eyre!(
                "failed to inspect artifact path `{}`: {err}",
                right.display()
            ));
        }
    };
    let (Some(left_metadata), Some(right_metadata)) = (left_metadata, right_metadata) else {
        return Ok(false);
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(left_metadata.dev() == right_metadata.dev()
            && left_metadata.ino() == right_metadata.ino())
    }
    #[cfg(not(unix))]
    {
        match (fs::canonicalize(left), fs::canonicalize(right)) {
            (Ok(left), Ok(right)) => Ok(left == right),
            _ => Ok(false),
        }
    }
}
fn normalize_absolute_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .wrap_err_with(|| format!("failed to resolve artifact path `{}`", path.display()))?;
    let mut existing_prefix = absolute.as_path();
    loop {
        match fs::canonicalize(existing_prefix) {
            Ok(canonical_prefix) => {
                let suffix = absolute.strip_prefix(existing_prefix).map_err(|err| {
                    eyre!(
                        "failed to preserve artifact path suffix for `{}`: {err}",
                        path.display()
                    )
                })?;
                return Ok(normalize_path_components(&canonical_prefix.join(suffix)));
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                existing_prefix = existing_prefix.parent().ok_or_else(|| {
                    eyre!(
                        "failed to find an existing ancestor for artifact path `{}`",
                        path.display()
                    )
                })?;
            }
            Err(err) => {
                return Err(eyre!(
                    "failed to canonicalize artifact path ancestor `{}`: {err}",
                    existing_prefix.display()
                ));
            }
        }
    }
}
fn normalize_path_components(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}
struct PreparedOutput<'a> {
    target: &'a Path,
    label: &'static str,
    bytes: Vec<u8>,
}
struct StagedOutput {
    target: PathBuf,
    stage: Option<PathBuf>,
    label: &'static str,
}
impl StagedOutput {
    fn stage_path(&self) -> &Path {
        self.stage
            .as_deref()
            .expect("staged output path is present until publication")
    }
}
impl Drop for StagedOutput {
    fn drop(&mut self) {
        if let Some(stage) = self.stage.take() {
            let _ = fs::remove_file(stage);
        }
    }
}
struct PublishedOutput {
    target: PathBuf,
    backup: Option<PathBuf>,
}
fn create_staged_output(target: &Path, label: &'static str) -> Result<(StagedOutput, fs::File)> {
    validate_output_writable(target)?;
    ensure_parent_dir(target)?;
    validate_output_writable(target)?;
    let target_permissions = match fs::symlink_metadata(target) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(eyre!(
                "failed to inspect {label} `{}` before staging: {err}",
                target.display()
            ));
        }
    };
    let parent = output_parent(target);
    for _ in 0..128 {
        let stage_path = unique_sibling_path(parent, "stage");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        set_no_follow_flag(&mut options);
        match options.open(&stage_path) {
            Ok(file) => {
                if let Some(permissions) = target_permissions.clone()
                    && let Err(err) = fs::set_permissions(&stage_path, permissions)
                {
                    drop(file);
                    let _ = fs::remove_file(&stage_path);
                    return Err(eyre!(
                        "failed to preserve permissions while staging {label} `{}`: {err}",
                        target.display()
                    ));
                }
                return Ok((
                    StagedOutput {
                        target: target.to_path_buf(),
                        stage: Some(stage_path),
                        label,
                    },
                    file,
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(eyre!(
                    "failed to create staged {label} for `{}`: {err}",
                    target.display()
                ));
            }
        }
    }
    Err(eyre!(
        "failed to allocate a unique staged {label} for `{}`",
        target.display()
    ))
}
fn stage_output_bytes(target: &Path, label: &'static str, bytes: &[u8]) -> Result<StagedOutput> {
    let (staged, mut file) = create_staged_output(target, label)?;
    file.write_all(bytes)
        .wrap_err_with(|| format!("failed to stage {label} `{}`", target.display()))?;
    file.flush()
        .wrap_err_with(|| format!("failed to flush staged {label} `{}`", target.display()))?;
    drop(file);
    Ok(staged)
}
fn stage_prepared_outputs(outputs: Vec<PreparedOutput<'_>>) -> Result<Vec<StagedOutput>> {
    outputs
        .into_iter()
        .map(|output| stage_output_bytes(output.target, output.label, &output.bytes))
        .collect()
}
fn publish_staged_outputs(outputs: Vec<StagedOutput>) -> Result<()> {
    publish_staged_outputs_with_hook(outputs, |_| Ok(()))
}
fn publish_staged_outputs_with_hook(
    mut outputs: Vec<StagedOutput>,
    mut before_publish: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    let mut published = Vec::with_capacity(outputs.len());
    for (index, output) in outputs.iter_mut().enumerate() {
        if let Err(err) = before_publish(index) {
            return Err(error_with_rollback(err, &published));
        }
        if let Err(err) = validate_output_writable(&output.target) {
            return Err(error_with_rollback(err, &published));
        }
        let backup = match backup_existing_output(&output.target, output.label) {
            Ok(backup) => backup,
            Err(err) => return Err(error_with_rollback(err, &published)),
        };
        let publication = PublishedOutput {
            target: output.target.clone(),
            backup,
        };
        if let Err(err) = fs::rename(output.stage_path(), &output.target) {
            published.push(publication);
            return Err(error_with_rollback(
                eyre!(
                    "failed to publish staged {} `{}`: {err}",
                    output.label,
                    output.target.display()
                ),
                &published,
            ));
        }
        output.stage = None;
        published.push(publication);
    }
    cleanup_backups(&published)
}
fn backup_existing_output(target: &Path, label: &str) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(target) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(eyre!(
                "failed to inspect {label} `{}` before publication: {err}",
                target.display()
            ));
        }
    }
    let parent = output_parent(target);
    for _ in 0..128 {
        let backup_dir = unique_sibling_path(parent, "backup");
        match fs::create_dir(&backup_dir) {
            Ok(()) => {
                let backup = backup_dir.join("original");
                return match fs::rename(target, &backup) {
                    Ok(()) => Ok(Some(backup)),
                    Err(err) => {
                        let cleanup_error = fs::remove_dir(&backup_dir).err();
                        Err(match cleanup_error {
                            Some(cleanup_error) => eyre!(
                                "failed to preserve existing {label} `{}` before publication: {err}; failed to remove backup directory `{}`: {cleanup_error}",
                                target.display(),
                                backup_dir.display()
                            ),
                            None => eyre!(
                                "failed to preserve existing {label} `{}` before publication: {err}",
                                target.display()
                            ),
                        })
                    }
                };
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(eyre!(
                    "failed to create a backup directory for existing {label} `{}`: {err}",
                    target.display()
                ));
            }
        }
    }
    Err(eyre!(
        "failed to allocate a backup for existing {label} `{}`",
        target.display()
    ))
}
fn error_with_rollback(error: eyre::Report, published: &[PublishedOutput]) -> eyre::Report {
    match rollback_published_outputs(published) {
        Ok(()) => error,
        Err(rollback_error) => {
            eyre!("{error}; failed to roll back published outputs: {rollback_error}")
        }
    }
}
fn rollback_published_outputs(published: &[PublishedOutput]) -> Result<()> {
    let mut failures = Vec::new();
    for output in published.iter().rev() {
        match fs::remove_file(&output.target) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                failures.push(format!(
                    "failed to remove replacement `{}`: {err}",
                    output.target.display()
                ));
                continue;
            }
        }
        if let Some(backup) = &output.backup
            && let Err(err) = fs::rename(backup, &output.target)
        {
            failures.push(format!(
                "failed to restore `{}` from `{}`: {err}",
                output.target.display(),
                backup.display()
            ));
            continue;
        }
        if let Some(backup) = &output.backup
            && let Some(backup_dir) = backup.parent()
            && let Err(err) = fs::remove_dir(backup_dir)
        {
            failures.push(format!(
                "failed to remove restored backup directory `{}`: {err}",
                backup_dir.display()
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(eyre!(failures.join("; ")))
    }
}
fn cleanup_backups(published: &[PublishedOutput]) -> Result<()> {
    let mut failures = Vec::new();
    for output in published {
        if let Some(backup) = &output.backup
            && let Err(err) = fs::remove_file(backup)
            && err.kind() != io::ErrorKind::NotFound
        {
            failures.push(format!(
                "failed to remove backup `{}`: {err}",
                backup.display()
            ));
            continue;
        }
        if let Some(backup) = &output.backup
            && let Some(backup_dir) = backup.parent()
            && let Err(err) = fs::remove_dir(backup_dir)
            && err.kind() != io::ErrorKind::NotFound
        {
            failures.push(format!(
                "failed to remove backup directory `{}`: {err}",
                backup_dir.display()
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(eyre!(
            "outputs were published but backup cleanup failed: {}",
            failures.join("; ")
        ))
    }
}
fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
fn unique_sibling_path(parent: &Path, kind: &str) -> PathBuf {
    let counter = STAGED_OUTPUT_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".taikai-car-{kind}-{}-{counter}",
        std::process::id()
    ))
}
struct IngestMetadataParams<'a> {
    event_id: &'a TaikaiEventId,
    stream_id: &'a TaikaiStreamId,
    rendition_id: &'a TaikaiRenditionId,
    track: &'a TaikaiTrackMetadata,
    segment_sequence: u64,
    segment_start_pts: u64,
    segment_duration: u32,
    wallclock_unix_ms: u64,
    ingest_latency_ms: Option<u32>,
    live_edge_drift_ms: Option<i32>,
    ingest_node_id: Option<&'a str>,
}
fn build_ingest_metadata_inner(params: &IngestMetadataParams<'_>) -> Result<Map> {
    let mut map = Map::new();
    map.insert(
        "taikai.event_id".into(),
        Value::from(params.event_id.as_name().as_ref()),
    );
    map.insert(
        "taikai.stream_id".into(),
        Value::from(params.stream_id.as_name().as_ref()),
    );
    map.insert(
        "taikai.rendition_id".into(),
        Value::from(params.rendition_id.as_name().as_ref()),
    );
    let (kind_label, codec_label, resolution_label, audio_layout_label) =
        track_labels(params.track);
    map.insert("taikai.track.kind".into(), Value::from(kind_label));
    map.insert("taikai.track.codec".into(), Value::from(codec_label));
    map.insert(
        "taikai.track.bitrate_kbps".into(),
        Value::from(params.track.average_bitrate_kbps.to_string()),
    );
    if let Some(resolution) = resolution_label {
        map.insert(
            "taikai.track.resolution".into(),
            Value::from(resolution.to_string()),
        );
    }
    if let Some(layout) = audio_layout_label {
        map.insert(
            "taikai.track.audio_layout".into(),
            Value::from(layout.to_string()),
        );
    }
    map.insert(
        "taikai.segment.sequence".into(),
        Value::from(params.segment_sequence.to_string()),
    );
    map.insert(
        "taikai.segment.start_pts".into(),
        Value::from(params.segment_start_pts.to_string()),
    );
    map.insert(
        "taikai.segment.duration".into(),
        Value::from(params.segment_duration.to_string()),
    );
    map.insert(
        "taikai.wallclock_unix_ms".into(),
        Value::from(params.wallclock_unix_ms.to_string()),
    );
    if let Some(latency) = params.ingest_latency_ms {
        map.insert(
            "taikai.instrumentation.ingest_latency_ms".into(),
            Value::from(latency.to_string()),
        );
    }
    if let Some(drift) = params.live_edge_drift_ms {
        map.insert(
            "taikai.instrumentation.live_edge_drift_ms".into(),
            Value::from(drift.to_string()),
        );
    }
    if let Some(node_id) = params.ingest_node_id {
        map.insert(
            "taikai.instrumentation.ingest_node_id".into(),
            Value::from(node_id.to_owned()),
        );
    }
    Ok(map)
}
fn track_labels(
    track: &TaikaiTrackMetadata,
) -> (&'static str, String, Option<String>, Option<String>) {
    let kind_label = match track.kind {
        TaikaiTrackKind::Video => "video",
        TaikaiTrackKind::Audio => "audio",
        TaikaiTrackKind::Data => "data",
    };
    let codec_label = match &track.codec {
        iroha_data_model::taikai::TaikaiCodec::AvcHigh => "avc-high".to_owned(),
        iroha_data_model::taikai::TaikaiCodec::HevcMain10 => "hevc-main10".to_owned(),
        iroha_data_model::taikai::TaikaiCodec::Av1Main => "av1-main".to_owned(),
        iroha_data_model::taikai::TaikaiCodec::AacLc => "aac-lc".to_owned(),
        iroha_data_model::taikai::TaikaiCodec::Opus => "opus".to_owned(),
        iroha_data_model::taikai::TaikaiCodec::Custom(name) => format!("custom:{name}"),
    };
    let resolution_label = track
        .resolution
        .as_ref()
        .map(|res| format!("{}x{}", res.width, res.height));
    let audio_layout_label = track.audio_layout.as_ref().map(|layout| match layout {
        iroha_data_model::taikai::TaikaiAudioLayout::Mono => "mono".to_owned(),
        iroha_data_model::taikai::TaikaiAudioLayout::Stereo => "stereo".to_owned(),
        iroha_data_model::taikai::TaikaiAudioLayout::FiveOne => "5.1".to_owned(),
        iroha_data_model::taikai::TaikaiAudioLayout::SevenOne => "7.1".to_owned(),
        iroha_data_model::taikai::TaikaiAudioLayout::Custom(channels) => {
            format!("custom:{channels}")
        }
    });
    (
        kind_label,
        codec_label,
        resolution_label,
        audio_layout_label,
    )
}
fn encode_base32_lower(data: &[u8]) -> Result<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    if data.is_empty() {
        return Ok(String::new());
    }
    let bit_len = data
        .len()
        .checked_mul(8)
        .ok_or_else(|| eyre!("base32 input length exceeds host bounds"))?;
    let output_len = bit_len.div_ceil(5);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = String::new();
    out.try_reserve_exact(output_len).map_err(|error| {
        eyre!("failed to reserve {output_len} bytes for base32 output: {error}")
    })?;
    for byte in data {
        acc = (acc << 8) | (*byte as u32);
        bits += 8;
        while bits >= 5 {
            let index = ((acc >> (bits - 5)) & 0x1F) as usize;
            out.push(char::from(ALPHABET[index]));
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((acc << (5 - bits)) & 0x1F) as usize;
        out.push(char::from(ALPHABET[index]));
    }
    if out.len() != output_len {
        return Err(eyre!(
            "base32 encoder produced {} bytes; expected {output_len}",
            out.len()
        ));
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use crate::verifier::ParsedCar;
    use iroha_data_model::taikai::{TaikaiAudioLayout, TaikaiCodec, TaikaiResolution};
    use iroha_model_base::name::Name;
    use std::str::FromStr;
    use tempfile::{TempDir, tempdir};
    #[test]
    fn base32_lower_matches_rfc4648_unpadded_vectors() {
        for (input, expected) in [
            (b"".as_slice(), ""),
            (b"f".as_slice(), "my"),
            (b"fo".as_slice(), "mzxq"),
            (b"foo".as_slice(), "mzxw6"),
            (b"foob".as_slice(), "mzxw6yq"),
            (b"fooba".as_slice(), "mzxw6ytb"),
            (b"foobar".as_slice(), "mzxw6ytboi"),
        ] {
            assert_eq!(encode_base32_lower(input).expect("encode base32"), expected);
        }
    }
    use super::*;
    fn canonical_tempdir() -> (TempDir, PathBuf) {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().canonicalize().expect("canonical tempdir");
        (temp, path)
    }
    fn minimal_bundle_request<'a>(
        payload_path: &'a Path,
        car_out: &'a Path,
        envelope_out: &'a Path,
    ) -> BundleRequest<'a> {
        BundleRequest {
            payload_path,
            payload_bytes: None,
            car_out,
            envelope_out,
            indexes_out: None,
            ingest_metadata_out: None,
            manifest_hash: BlobDigest::new([1u8; 32]),
            storage_ticket: StorageTicketId::new([2u8; 32]),
            event_id: TaikaiEventId::new(Name::from_str("event").expect("name")),
            stream_id: TaikaiStreamId::new(Name::from_str("stream").expect("name")),
            rendition_id: TaikaiRenditionId::new(Name::from_str("1080p").expect("name")),
            track: TaikaiTrackMetadata::video(
                TaikaiCodec::Av1Main,
                8_000,
                TaikaiResolution::new(1920, 1080),
            ),
            segment_sequence: 42,
            segment_start_pts: 36_000,
            segment_duration: 2_000_000,
            wallclock_unix_ms: 1_702_560_000_000,
            ingest_latency_ms: None,
            live_edge_drift_ms: None,
            ingest_node_id: None,
            extra_metadata: None,
        }
    }
    fn minimal_rehydrate_request<'a>(
        car_in: &'a Path,
        car_out: &'a Path,
        envelope_out: &'a Path,
    ) -> RehydrateRequest<'a> {
        RehydrateRequest {
            car_in,
            car_out,
            envelope_out,
            indexes_out: None,
            ingest_metadata_out: None,
            manifest_hash: BlobDigest::new([1u8; 32]),
            storage_ticket: StorageTicketId::new([2u8; 32]),
            event_id: TaikaiEventId::new(Name::from_str("event").expect("name")),
            stream_id: TaikaiStreamId::new(Name::from_str("stream").expect("name")),
            rendition_id: TaikaiRenditionId::new(Name::from_str("1080p").expect("name")),
            track: TaikaiTrackMetadata::video(
                TaikaiCodec::Av1Main,
                8_000,
                TaikaiResolution::new(1920, 1080),
            ),
            segment_sequence: 42,
            segment_start_pts: 36_000,
            segment_duration: 2_000_000,
            wallclock_unix_ms: 1_702_560_000_000,
            ingest_latency_ms: None,
            live_edge_drift_ms: None,
            ingest_node_id: None,
            extra_metadata: None,
        }
    }
    #[test]
    fn bundle_writes_outputs() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = tmp_path.join("segment.bin");
        fs::write(&payload, b"taikai-payload").expect("write payload");
        let car_out = tmp_path.join("bundle").join("segment.car");
        let envelope_out = tmp_path.join("bundle").join("segment.to");
        let indexes_out = tmp_path.join("bundle").join("segment.indexes.json");
        let ingest_out = tmp_path.join("bundle").join("segment.ingest.json");
        let request = BundleRequest {
            payload_path: &payload,
            payload_bytes: None,
            car_out: &car_out,
            envelope_out: &envelope_out,
            indexes_out: Some(&indexes_out),
            ingest_metadata_out: Some(&ingest_out),
            manifest_hash: BlobDigest::new([0u8; 32]),
            storage_ticket: StorageTicketId::new([1u8; 32]),
            event_id: TaikaiEventId::new(Name::from_str("event").expect("name")),
            stream_id: TaikaiStreamId::new(Name::from_str("stream").expect("name")),
            rendition_id: TaikaiRenditionId::new(Name::from_str("1080p").expect("name")),
            track: TaikaiTrackMetadata::video(
                TaikaiCodec::Av1Main,
                8_000,
                TaikaiResolution {
                    width: 1920,
                    height: 1080,
                },
            ),
            segment_sequence: 42,
            segment_start_pts: 36_000,
            segment_duration: 2_000_000,
            wallclock_unix_ms: 1_702_560_000_000,
            ingest_latency_ms: Some(120),
            live_edge_drift_ms: Some(-45),
            ingest_node_id: Some("node-a".into()),
            extra_metadata: None,
        };
        let summary = bundle_segment(&request).expect("bundle");
        assert_eq!(summary.chunk_count, 1);
        assert!(summary.car_out.exists());
        assert!(summary.envelope_out.exists());
        assert_eq!(summary.indexes.time_key.event_id, request.event_id);
        assert_eq!(summary.indexes.time_key.stream_id, request.stream_id);
        assert_eq!(summary.indexes.time_key.rendition_id, request.rendition_id);
        assert_eq!(
            summary.indexes.time_key.segment_start_pts.as_micros(),
            request.segment_start_pts
        );
        assert_eq!(
            summary.indexes.cid_key.cid_multibase,
            summary.car_pointer.cid_multibase
        );
        assert!(summary.indexes_out.as_ref().unwrap().exists());
        assert!(summary.ingest_metadata_out.as_ref().unwrap().exists());
    }
    #[test]
    fn verify_taikai_car_reconstructs_canonical_commitments() {
        let payload = b"taikai-verified-car-payload";
        let ingest = ingest_single_file(payload).expect("plan payload");
        let expected_chunk_count =
            u32::try_from(ingest.chunk_store.chunks().len()).expect("chunk count fits u32");
        let expected_chunk_root = BlobDigest::new(*ingest.chunk_store.por_tree().root());
        let mut car_bytes = Vec::new();
        let stats = CarWriter::new(&ingest.plan, payload)
            .expect("create writer")
            .write_to(&mut car_bytes)
            .expect("write CAR");

        let verified = verify_taikai_car(&car_bytes).expect("verify canonical Taikai CAR");

        assert_eq!(verified.chunk_count, expected_chunk_count);
        assert_eq!(verified.chunk_root, expected_chunk_root);
        assert_eq!(verified.car_pointer.car_size_bytes, stats.car_size);
        assert_eq!(
            verified.car_pointer.car_digest,
            BlobDigest::from_hash(stats.car_archive_digest)
        );
        assert_eq!(
            verified.car_pointer.cid_multibase,
            format!(
                "b{}",
                encode_base32_lower(&stats.car_cid).expect("encode CID")
            )
        );
    }
    #[test]
    fn verify_taikai_car_rejects_noncanonical_container() {
        let payload = b"taikai-noncanonical-car-payload";
        let ingest = ingest_single_file(payload).expect("plan payload");
        let mut car_bytes = Vec::new();
        CarWriter::new(&ingest.plan, payload)
            .expect("create writer")
            .write_to(&mut car_bytes)
            .expect("write CAR");
        car_bytes[crate::PRAGMA.len() + 1] ^= 1;
        ParsedCar::parse(&car_bytes).expect("mutated CAR remains structurally parseable");

        let err = verify_taikai_car(&car_bytes).expect_err("reject non-canonical container");

        assert!(
            err.to_string().contains("canonical Taikai CAR"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn rehydrate_rejects_noncanonical_car_before_writing_outputs() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = b"taikai-rehydrate-payload";
        let ingest = ingest_single_file(payload).expect("plan payload");
        let mut car_bytes = Vec::new();
        CarWriter::new(&ingest.plan, payload)
            .expect("create writer")
            .write_to(&mut car_bytes)
            .expect("write CAR");

        // Reserved CARv2 header bytes must stay zero. The structural parser accepts this
        // mutation, so rehydration must still run the canonical-container verifier.
        car_bytes[crate::PRAGMA.len() + 1] ^= 1;
        ParsedCar::parse(&car_bytes).expect("mutated CAR remains structurally parseable");

        let car_in = tmp_path.join("noncanonical.car");
        let car_out = tmp_path.join("copy.car");
        let envelope_out = tmp_path.join("segment.to");
        fs::write(&car_in, car_bytes).expect("write mutated CAR");
        let request = minimal_rehydrate_request(&car_in, &car_out, &envelope_out);

        let err = rehydrate_from_car(&request).expect_err("reject non-canonical CAR");
        assert!(
            err.to_string().contains("canonical Taikai CAR"),
            "unexpected error: {err}"
        );
        assert!(
            !car_out.exists(),
            "failed rehydration must not copy the CAR"
        );
        assert!(
            !envelope_out.exists(),
            "failed rehydration must not emit an envelope"
        );
    }
    #[test]
    fn bundle_rejects_colliding_artifact_paths_before_writing() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = tmp_path.join("segment.bin");
        fs::write(&payload, b"taikai-payload").expect("write payload");
        let colliding_output = tmp_path.join("segment.car");
        let request = minimal_bundle_request(&payload, &colliding_output, &colliding_output);

        let err = bundle_segment(&request).expect_err("reject colliding outputs");
        assert!(
            err.to_string().contains("must use distinct paths"),
            "unexpected error: {err}"
        );
        assert!(
            !colliding_output.exists(),
            "collision must fail before opening either output"
        );
    }
    #[test]
    fn bundle_rejects_nested_artifact_paths_before_writing() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = tmp_path.join("segment.bin");
        fs::write(&payload, b"taikai-payload").expect("write payload");
        let car_out = tmp_path.join("artifact");
        let envelope_out = car_out.join("segment.to");
        let request = minimal_bundle_request(&payload, &car_out, &envelope_out);

        let err = bundle_segment(&request).expect_err("reject nested outputs");
        assert!(
            err.to_string().contains("must not be nested paths"),
            "unexpected error: {err}"
        );
        assert!(
            !car_out.exists(),
            "collision must fail before writing the CAR"
        );
    }
    #[cfg(unix)]
    #[test]
    fn distinct_artifact_paths_resolve_symlinked_input_ancestors() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let real_root = tmp_path.join("real");
        let real_bundle = real_root.join("bundle");
        fs::create_dir_all(&real_bundle).expect("create real bundle directory");
        let linked_root = tmp_path.join("linked");
        std::os::unix::fs::symlink(&real_root, &linked_root).expect("create root symlink");
        let input = linked_root.join("bundle");
        let output = real_bundle.join("report.json");

        let err = validate_distinct_artifact_paths(&[
            ("bundle input", input.as_path()),
            ("report output", output.as_path()),
        ])
        .expect_err("reject nesting through a symlinked input ancestor");

        assert!(
            err.to_string().contains("must not be nested paths"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn transactional_publish_rolls_back_prior_outputs_on_late_failure() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let first = tmp_path.join("first.out");
        let second = tmp_path.join("second.out");
        fs::write(&first, b"old-first").expect("write first target");
        fs::write(&second, b"old-second").expect("write second target");
        let staged = vec![
            stage_output_bytes(&first, "first output", b"new-first").expect("stage first"),
            stage_output_bytes(&second, "second output", b"new-second").expect("stage second"),
        ];

        let err = publish_staged_outputs_with_hook(staged, |index| {
            if index == 1 {
                Err(eyre!("injected late publication failure"))
            } else {
                Ok(())
            }
        })
        .expect_err("inject failure after first publication");

        assert!(
            err.to_string()
                .contains("injected late publication failure"),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&first).expect("read first target"), b"old-first");
        assert_eq!(
            fs::read(&second).expect("read second target"),
            b"old-second"
        );
        let leaked_paths = fs::read_dir(&tmp_path)
            .expect("read temp directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .filter(|name| name.to_string_lossy().starts_with(".taikai-car-"))
            .collect::<Vec<_>>();
        assert!(leaked_paths.is_empty(), "leaked paths: {leaked_paths:?}");
    }
    #[test]
    fn bundle_rejects_track_codec_mismatch_before_writing() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = tmp_path.join("segment.bin");
        fs::write(&payload, b"taikai-payload").expect("write payload");
        let car_out = tmp_path.join("segment.car");
        let envelope_out = tmp_path.join("segment.to");
        let mut request = minimal_bundle_request(&payload, &car_out, &envelope_out);
        request.track.codec = TaikaiCodec::AacLc;

        let err = bundle_segment(&request).expect_err("reject AAC video track");
        assert!(
            err.to_string().contains("not valid for a video track"),
            "unexpected error: {err}"
        );
        assert!(
            !car_out.exists(),
            "invalid track must fail before CAR output"
        );
        assert!(
            !envelope_out.exists(),
            "invalid track must fail before envelope output"
        );
    }
    #[test]
    fn validate_track_metadata_rejects_custom_codec_control_characters() {
        let track = TaikaiTrackMetadata::data(TaikaiCodec::Custom("id3\0spoof".into()), 32);

        let err = validate_track_metadata(&track).expect_err("reject control character");

        assert!(
            err.to_string().contains("control characters"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn bundle_normalizes_ingest_node_id_across_outputs() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = tmp_path.join("segment.bin");
        fs::write(&payload, b"taikai-payload").expect("write payload");
        let car_out = tmp_path.join("segment.car");
        let envelope_out = tmp_path.join("segment.to");
        let ingest_out = tmp_path.join("segment.ingest.json");
        let mut request = minimal_bundle_request(&payload, &car_out, &envelope_out);
        request.ingest_metadata_out = Some(&ingest_out);
        request.ingest_node_id = Some("  node-a  ".to_owned());

        let summary = bundle_segment(&request).expect("bundle");
        let envelope: TaikaiSegmentEnvelopeV1 =
            norito::decode_from_bytes(&fs::read(&envelope_out).expect("read envelope"))
                .expect("decode envelope");

        assert_eq!(
            envelope.instrumentation.ingest_node_id.as_deref(),
            Some("node-a")
        );
        assert_eq!(
            summary
                .ingest_metadata
                .get("taikai.instrumentation.ingest_node_id")
                .and_then(Value::as_str),
            Some("node-a")
        );
    }
    #[test]
    fn bundle_preflights_readonly_late_output_before_writing() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = tmp_path.join("segment.bin");
        fs::write(&payload, b"taikai-payload").expect("write payload");
        let car_out = tmp_path.join("segment.car");
        let envelope_out = tmp_path.join("segment.to");
        let indexes_out = tmp_path.join("segment.indexes.json");
        fs::write(&indexes_out, b"preserve").expect("write existing index");
        let mut permissions = fs::metadata(&indexes_out)
            .expect("index metadata")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&indexes_out, permissions).expect("make index read-only");
        let mut request = minimal_bundle_request(&payload, &car_out, &envelope_out);
        request.indexes_out = Some(&indexes_out);

        let err = bundle_segment(&request).expect_err("reject read-only late output");

        assert!(
            err.to_string().contains("must be writable"),
            "unexpected error: {err}"
        );
        assert!(
            !car_out.exists(),
            "CAR must not be written before preflight"
        );
        assert!(
            !envelope_out.exists(),
            "envelope must not be written before preflight"
        );
        assert_eq!(fs::read(indexes_out).expect("read index"), b"preserve");
    }
    #[cfg(unix)]
    #[test]
    fn bundle_preflights_all_outputs_before_writing_car() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = tmp_path.join("segment.bin");
        fs::write(&payload, b"taikai-payload").expect("write payload");
        let car_out = tmp_path.join("segment.car");
        let envelope_target = tmp_path.join("target.to");
        fs::write(&envelope_target, b"unchanged").expect("write envelope target");
        let envelope_out = tmp_path.join("segment.to");
        std::os::unix::fs::symlink(&envelope_target, &envelope_out).expect("create symlink");
        let request = minimal_bundle_request(&payload, &car_out, &envelope_out);

        let err = bundle_segment(&request).expect_err("reject invalid envelope output");
        assert!(
            err.to_string().contains("must not be a symlink"),
            "unexpected error: {err}"
        );
        assert!(
            !car_out.exists(),
            "preflight must run before writing the CAR"
        );
        assert_eq!(
            fs::read(&envelope_target).expect("read target"),
            b"unchanged"
        );
    }
    #[test]
    fn rehydrate_rejects_metadata_output_that_aliases_car_input() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = b"taikai-rehydrate-payload";
        let ingest = ingest_single_file(payload).expect("plan payload");
        let mut car_bytes = Vec::new();
        CarWriter::new(&ingest.plan, payload)
            .expect("create writer")
            .write_to(&mut car_bytes)
            .expect("write CAR");
        let car_in = tmp_path.join("segment.car");
        let car_out = tmp_path.join("copy.car");
        fs::write(&car_in, &car_bytes).expect("write CAR input");
        let request = minimal_rehydrate_request(&car_in, &car_out, &car_in);

        let err = rehydrate_from_car(&request).expect_err("protect CAR input");
        assert!(
            err.to_string().contains("must use distinct paths"),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&car_in).expect("read CAR input"), car_bytes);
        assert!(
            !car_out.exists(),
            "collision must fail before copying the CAR"
        );
    }
    #[cfg(unix)]
    #[test]
    fn rehydrate_treats_hard_link_car_output_as_in_place() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let payload = b"taikai-hard-link-car-payload";
        let ingest = ingest_single_file(payload).expect("plan payload");
        let mut car_bytes = Vec::new();
        CarWriter::new(&ingest.plan, payload)
            .expect("create writer")
            .write_to(&mut car_bytes)
            .expect("write CAR");
        let car_in = tmp_path.join("segment.car");
        let car_out = tmp_path.join("segment-alias.car");
        let envelope_out = tmp_path.join("segment.to");
        fs::write(&car_in, &car_bytes).expect("write CAR input");
        fs::hard_link(&car_in, &car_out).expect("create hard link");
        let mut permissions = fs::metadata(&car_in).expect("CAR metadata").permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&car_in, permissions).expect("make CAR read-only");
        let request = minimal_rehydrate_request(&car_in, &car_out, &envelope_out);

        rehydrate_from_car(&request).expect("rehydrate without rewriting hard-linked CAR");

        assert_eq!(fs::read(&car_in).expect("read CAR input"), car_bytes);
        assert_eq!(
            fs::read(&car_out).expect("read CAR output alias"),
            car_bytes
        );
        assert!(envelope_out.is_file());
    }
    #[test]
    fn write_output_bytes_creates_parent_and_writes_all_bytes() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let output_path = tmp_path.join("nested").join("segment.to");
        write_output_bytes(&output_path, "test output", b"taikai-output")
            .expect("write output bytes");
        assert_eq!(
            fs::read(output_path).expect("read output"),
            b"taikai-output"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_output_bytes_rejects_symlink_output() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let target_path = tmp_path.join("target.to");
        fs::write(&target_path, b"unchanged\n").expect("write target");
        let output_path = tmp_path.join("segment.to");
        std::os::unix::fs::symlink(&target_path, &output_path).expect("create symlink");
        let err = write_output_bytes(&output_path, "test output", b"replace")
            .expect_err("reject symlink output");
        let message = err.to_string();
        assert!(
            message.contains("must not be a symlink"),
            "unexpected error: {message}"
        );
        assert_eq!(fs::read(&target_path).expect("read target"), b"unchanged\n");
    }
    #[cfg(unix)]
    #[test]
    fn write_output_bytes_rejects_socket_output() {
        // Unix socket addresses have a small fixed byte limit, independent of PATH_MAX.
        // A caller's TMPDIR can exceed it; keep this real socket fixture under /tmp.
        let socket_root = tempfile::tempdir_in("/tmp").expect("short Unix socket directory");
        let tmp_path = socket_root
            .path()
            .canonicalize()
            .expect("canonical socket root");
        let output_path = tmp_path.join("segment.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&output_path).expect("bind Unix socket");

        let err = write_output_bytes(&output_path, "test output", b"replace")
            .expect_err("reject socket output");

        assert!(
            err.to_string().contains("must be a regular file"),
            "unexpected error: {err}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_output_bytes_rejects_symlink_parent() {
        let (_tmp, tmp_path) = canonical_tempdir();
        let real_dir = tmp_path.join("real");
        fs::create_dir(&real_dir).expect("create real dir");
        let linked_dir = tmp_path.join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).expect("create symlink");
        let output_path = linked_dir.join("segment.to");
        let err = write_output_bytes(&output_path, "test output", b"replace")
            .expect_err("reject symlink parent");
        let message = err.to_string();
        assert!(
            message.contains("parent") && message.contains("must not be a symlink"),
            "unexpected error: {message}"
        );
        assert!(
            !real_dir.join("segment.to").exists(),
            "symlink parent should not receive output"
        );
    }
    #[test]
    fn track_labels_cover_audio() {
        let track =
            TaikaiTrackMetadata::audio(TaikaiCodec::Opus, 192, TaikaiAudioLayout::Custom(6));
        let (_, codec, _, layout) = track_labels(&track);
        assert_eq!(codec, "opus");
        assert_eq!(layout.as_deref(), Some("custom:6"));
    }
}
