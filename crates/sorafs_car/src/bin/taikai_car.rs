//! CLI for building deterministic SoraFS Taikai CAR bundles and envelopes.
use clap::{Parser, ValueEnum};
use eyre::{Result, WrapErr, eyre};
use iroha_data_model::{
    da::types::{BlobDigest, ExtraMetadata, StorageTicketId},
    taikai::{
        TaikaiAudioLayout, TaikaiCodec, TaikaiEventId, TaikaiRenditionId, TaikaiResolution,
        TaikaiStreamId, TaikaiTrackKind, TaikaiTrackMetadata,
    },
};
use iroha_model_base::name::Name;
use norito::json::{self, Map, Value};
use sorafs_car::taikai::{
    BundleRequest, BundleSummary, RehydrateRequest, bundle_segment, load_extra_metadata,
    rehydrate_from_car, validate_distinct_artifact_paths, validate_track_metadata,
};
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
#[path = "../taikai/output_file.rs"]
mod output_file;
#[path = "../taikai/output_fs.rs"]
mod output_fs;
use output_file::write_output_bytes;
use output_fs::{ensure_parent_dir, validate_output_writable};
use sorafs_car::set_no_follow_flag;
#[derive(Parser, Debug)]
#[command(
    name = "taikai_car",
    about = "Bundle Taikai segments into deterministic CAR archives."
)]
struct Args {
    /// Path to the CMAF fragment or segment payload to ingest.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "car_in",
        required_unless_present = "car_in"
    )]
    payload: Option<PathBuf>,
    /// Path to an existing CAR archive to rehydrate metadata from.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "payload",
        required_unless_present = "payload"
    )]
    car_in: Option<PathBuf>,
    /// Where to write the generated CARv2 archive.
    #[arg(long, value_name = "PATH")]
    car_out: PathBuf,
    /// Where to write the Norito-encoded Taikai segment envelope.
    #[arg(long, value_name = "PATH")]
    envelope_out: PathBuf,
    /// Optional path for a JSON file containing the time/CID index keys.
    #[arg(long, value_name = "PATH")]
    indexes_out: Option<PathBuf>,
    /// Optional path for the ingest metadata JSON map consumed by `/v1/da/ingest`.
    #[arg(long, value_name = "PATH")]
    ingest_metadata_out: Option<PathBuf>,
    /// Optional path for a JSON summary describing the bundle outputs.
    #[arg(long, value_name = "PATH")]
    summary_out: Option<PathBuf>,
    /// Optional path to a summary JSON (single object, array entry, or NDJSON line) to seed metadata.
    #[arg(long, value_name = "PATH")]
    summary_in: Option<PathBuf>,
    /// Optional index to select from a summary array or NDJSON log (0-based).
    #[arg(long, value_name = "INDEX", requires = "summary_in")]
    summary_entry: Option<String>,
    /// Identifier of the Taikai event.
    #[arg(long, value_name = "NAME")]
    event_id: Option<String>,
    /// Logical stream identifier within the event.
    #[arg(long, value_name = "NAME")]
    stream_id: Option<String>,
    /// Rendition identifier (ladder rung).
    #[arg(long, value_name = "NAME")]
    rendition_id: Option<String>,
    /// Track kind carried by the segment.
    #[arg(long, value_enum)]
    track_kind: Option<CliTrackKind>,
    /// Codec identifier (`avc-high`, `hevc-main10`, `av1-main`, `aac-lc`, `opus`, or `custom:<name>`).
    #[arg(long)]
    codec: Option<String>,
    /// Average bitrate in kilobits per second.
    #[arg(long, value_name = "KBPS")]
    bitrate_kbps: Option<String>,
    /// Video resolution (`WIDTHxHEIGHT`). Required for `video` tracks.
    #[arg(long)]
    resolution: Option<String>,
    /// Audio layout (`mono`, `stereo`, `5.1`, `7.1`, or `custom:<channels>`). Required for `audio` tracks.
    #[arg(long)]
    audio_layout: Option<String>,
    /// Monotonic segment sequence number.
    #[arg(long)]
    segment_sequence: Option<String>,
    /// Presentation timestamp (start) in microseconds since stream origin.
    #[arg(long)]
    segment_start_pts: Option<String>,
    /// Presentation duration in microseconds.
    #[arg(long)]
    segment_duration: Option<String>,
    /// Wall-clock reference (Unix milliseconds) when the segment was finalised.
    #[arg(long)]
    wallclock_unix_ms: Option<String>,
    /// Deterministic manifest hash emitted by the ingest pipeline (hex).
    #[arg(long, value_name = "HEX")]
    manifest_hash: Option<String>,
    /// Storage ticket identifier assigned by the orchestrator (hex).
    #[arg(long, value_name = "HEX")]
    storage_ticket: Option<String>,
    /// Optional encoder-to-ingest latency in milliseconds.
    #[arg(long)]
    ingest_latency_ms: Option<String>,
    /// Optional live-edge drift measurement in milliseconds (negative = stream ahead of ingest).
    #[arg(long, allow_hyphen_values = true)]
    live_edge_drift_ms: Option<String>,
    /// Optional identifier for the ingest node that sealed the segment.
    #[arg(long)]
    ingest_node_id: Option<String>,
    /// Optional JSON file describing additional metadata entries.
    #[arg(long, value_name = "PATH")]
    metadata_json: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliTrackKind {
    Video,
    Audio,
    Data,
}
impl From<CliTrackKind> for TaikaiTrackKind {
    fn from(value: CliTrackKind) -> Self {
        match value {
            CliTrackKind::Video => TaikaiTrackKind::Video,
            CliTrackKind::Audio => TaikaiTrackKind::Audio,
            CliTrackKind::Data => TaikaiTrackKind::Data,
        }
    }
}
impl CliTrackKind {
    fn as_str(&self) -> &'static str {
        match self {
            CliTrackKind::Video => "video",
            CliTrackKind::Audio => "audio",
            CliTrackKind::Data => "data",
        }
    }
}
impl FromStr for CliTrackKind {
    type Err = eyre::Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "video" => Ok(Self::Video),
            "audio" => Ok(Self::Audio),
            "data" => Ok(Self::Data),
            other => Err(eyre!("invalid track kind `{other}`")),
        }
    }
}
#[derive(Debug)]
enum InputSource {
    Payload(PathBuf),
    Car(PathBuf),
}
#[derive(Debug)]
struct BundleMetadata {
    manifest_hash: BlobDigest,
    manifest_hash_hex: String,
    storage_ticket: StorageTicketId,
    storage_ticket_hex: String,
    event_id: TaikaiEventId,
    stream_id: TaikaiStreamId,
    rendition_id: TaikaiRenditionId,
    track_kind: CliTrackKind,
    track_metadata: TaikaiTrackMetadata,
    codec_label: String,
    bitrate_kbps: u32,
    resolution: Option<String>,
    audio_layout: Option<String>,
    segment_sequence: u64,
    segment_start_pts: u64,
    segment_duration: u32,
    wallclock_unix_ms: u64,
    ingest_latency_ms: Option<u32>,
    live_edge_drift_ms: Option<i32>,
    ingest_node_id: Option<String>,
}
#[derive(Debug)]
struct BundleInputs {
    input: InputSource,
    summary_in: Option<PathBuf>,
    metadata_json: Option<PathBuf>,
    car_out: PathBuf,
    envelope_out: PathBuf,
    indexes_out: Option<PathBuf>,
    ingest_metadata_out: Option<PathBuf>,
    summary_out: Option<PathBuf>,
    metadata: BundleMetadata,
    extra_metadata: Option<ExtraMetadata>,
}
#[derive(Debug, Default)]
struct SummarySeed {
    manifest_hash: Option<String>,
    storage_ticket: Option<String>,
    event_id: Option<String>,
    stream_id: Option<String>,
    rendition_id: Option<String>,
    track_kind: Option<CliTrackKind>,
    codec: Option<String>,
    bitrate_kbps: Option<u32>,
    resolution: Option<String>,
    audio_layout: Option<String>,
    segment_sequence: Option<u64>,
    segment_start_pts: Option<u64>,
    segment_duration: Option<u32>,
    wallclock_unix_ms: Option<u64>,
    ingest_latency_ms: Option<u32>,
    live_edge_drift_ms: Option<i32>,
    ingest_node_id: Option<String>,
}
fn main() -> Result<()> {
    let args = Args::parse();
    run(args)
}
fn run(args: Args) -> Result<()> {
    let inputs = resolve_inputs(args)?;
    validate_cli_artifact_paths(&inputs)?;
    let metadata = &inputs.metadata;
    let summary = match &inputs.input {
        InputSource::Payload(payload) => bundle_segment(&BundleRequest {
            payload_path: payload,
            payload_bytes: None,
            car_out: &inputs.car_out,
            envelope_out: &inputs.envelope_out,
            indexes_out: inputs.indexes_out.as_deref(),
            ingest_metadata_out: inputs.ingest_metadata_out.as_deref(),
            manifest_hash: metadata.manifest_hash,
            storage_ticket: metadata.storage_ticket,
            event_id: metadata.event_id.clone(),
            stream_id: metadata.stream_id.clone(),
            rendition_id: metadata.rendition_id.clone(),
            track: metadata.track_metadata.clone(),
            segment_sequence: metadata.segment_sequence,
            segment_start_pts: metadata.segment_start_pts,
            segment_duration: metadata.segment_duration,
            wallclock_unix_ms: metadata.wallclock_unix_ms,
            ingest_latency_ms: metadata.ingest_latency_ms,
            live_edge_drift_ms: metadata.live_edge_drift_ms,
            ingest_node_id: metadata.ingest_node_id.clone(),
            extra_metadata: inputs.extra_metadata.clone(),
        })?,
        InputSource::Car(car_in) => rehydrate_from_car(&RehydrateRequest {
            car_in,
            car_out: &inputs.car_out,
            envelope_out: &inputs.envelope_out,
            indexes_out: inputs.indexes_out.as_deref(),
            ingest_metadata_out: inputs.ingest_metadata_out.as_deref(),
            manifest_hash: metadata.manifest_hash,
            storage_ticket: metadata.storage_ticket,
            event_id: metadata.event_id.clone(),
            stream_id: metadata.stream_id.clone(),
            rendition_id: metadata.rendition_id.clone(),
            track: metadata.track_metadata.clone(),
            segment_sequence: metadata.segment_sequence,
            segment_start_pts: metadata.segment_start_pts,
            segment_duration: metadata.segment_duration,
            wallclock_unix_ms: metadata.wallclock_unix_ms,
            ingest_latency_ms: metadata.ingest_latency_ms,
            live_edge_drift_ms: metadata.live_edge_drift_ms,
            ingest_node_id: metadata.ingest_node_id.clone(),
            extra_metadata: inputs.extra_metadata.clone(),
        })?,
    };
    println!("Taikai segment bundle generated");
    println!("car_cid (multibase): {}", summary.car_pointer.cid_multibase);
    println!(
        "car_digest (blake3-256 hex): {}",
        hex::encode(summary.car_pointer.car_digest.as_bytes())
    );
    println!("car_size_bytes: {}", summary.car_pointer.car_size_bytes);
    println!(
        "chunk_root (blake3-256 hex): {}",
        hex::encode(summary.chunk_root.as_bytes())
    );
    println!("chunk_count: {}", summary.chunk_count);
    println!("car_out: {}", summary.car_out.display());
    println!("envelope_out: {}", summary.envelope_out.display());
    if let Some(path) = summary.indexes_out.as_ref() {
        println!("indexes_out: {}", path.display());
    }
    if let Some(path) = summary.ingest_metadata_out.as_ref() {
        println!("ingest_metadata_out: {}", path.display());
    }
    if let Some(path) = inputs.summary_out.as_deref() {
        let summary_value = render_summary_value(&inputs, &summary);
        write_summary_json(path, &summary_value)?;
        println!("summary_out: {}", path.display());
    }
    Ok(())
}
fn validate_cli_artifact_paths(inputs: &BundleInputs) -> Result<()> {
    let mut outputs = vec![
        ("CAR output", inputs.car_out.as_path()),
        ("envelope output", inputs.envelope_out.as_path()),
    ];
    if let Some(path) = inputs.indexes_out.as_deref() {
        outputs.push(("index output", path));
    }
    if let Some(path) = inputs.ingest_metadata_out.as_deref() {
        outputs.push(("ingest metadata output", path));
    }
    if let Some(path) = inputs.summary_out.as_deref() {
        validate_output_writable(path)?;
        outputs.push(("bundle summary output", path));
    }
    validate_distinct_artifact_paths(&outputs)?;

    let (primary_label, primary_path, allow_car_output_alias) = match &inputs.input {
        InputSource::Payload(path) => ("payload input", path.as_path(), false),
        InputSource::Car(path) => ("CAR input", path.as_path(), true),
    };
    for (index, (output_label, output_path)) in outputs.iter().enumerate() {
        if !(allow_car_output_alias && index == 0) {
            validate_distinct_artifact_paths(&[
                (primary_label, primary_path),
                (*output_label, *output_path),
            ])?;
        }
    }
    for (input_label, input_path) in [
        ("summary input", inputs.summary_in.as_deref()),
        ("extra metadata input", inputs.metadata_json.as_deref()),
    ] {
        if let Some(input_path) = input_path {
            for (output_label, output_path) in &outputs {
                validate_distinct_artifact_paths(&[
                    (input_label, input_path),
                    (*output_label, *output_path),
                ])?;
            }
        }
    }
    Ok(())
}
fn resolve_inputs(args: Args) -> Result<BundleInputs> {
    let summary_in = args.summary_in.clone();
    let metadata_json = args.metadata_json.clone();
    let summary_entry = args
        .summary_entry
        .as_deref()
        .map(|value| parse_usize_arg("summary-entry", value))
        .transpose()?;
    let summary_seed = match args.summary_in.as_ref() {
        Some(path) => Some(load_summary_seed(path, summary_entry)?),
        None => None,
    };
    let input = resolve_input_source(args.payload, args.car_in)?;
    let manifest_hash_str = resolve_required_owned(
        "manifest-hash",
        args.manifest_hash,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.manifest_hash.clone()),
    )?;
    let manifest_hash = parse_blob_digest(&manifest_hash_str, "manifest-hash")?;
    let manifest_hash_hex = hex::encode(manifest_hash.as_bytes());
    let storage_ticket_str = resolve_required_owned(
        "storage-ticket",
        args.storage_ticket,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.storage_ticket.clone()),
    )?;
    let storage_ticket = StorageTicketId::new(parse_hex_32(&storage_ticket_str, "storage-ticket")?);
    let storage_ticket_hex = hex::encode(storage_ticket.as_ref());
    let event_id_literal = resolve_required_owned(
        "event-id",
        args.event_id,
        summary_seed.as_ref().and_then(|seed| seed.event_id.clone()),
    )?;
    let stream_id_literal = resolve_required_owned(
        "stream-id",
        args.stream_id,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.stream_id.clone()),
    )?;
    let rendition_id_literal = resolve_required_owned(
        "rendition-id",
        args.rendition_id,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.rendition_id.clone()),
    )?;
    let track_kind = resolve_required(
        "track-kind",
        args.track_kind,
        summary_seed.as_ref().and_then(|seed| seed.track_kind),
    )?;
    let codec_label = resolve_required_owned(
        "codec",
        args.codec,
        summary_seed.as_ref().and_then(|seed| seed.codec.clone()),
    )?;
    let bitrate_kbps = resolve_required_u32(
        "bitrate-kbps",
        args.bitrate_kbps,
        summary_seed.as_ref().and_then(|seed| seed.bitrate_kbps),
    )?;
    let bitrate_kbps = require_positive_u32("bitrate-kbps", bitrate_kbps)?;
    let resolution = resolve_optional_owned(
        args.resolution,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.resolution.clone()),
    );
    let audio_layout = resolve_optional_owned(
        args.audio_layout,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.audio_layout.clone()),
    );
    let track_metadata = build_track_metadata(
        track_kind,
        &codec_label,
        bitrate_kbps,
        resolution.as_deref(),
        audio_layout.as_deref(),
    )?;
    let (codec_label, resolution, audio_layout) = canonical_track_labels(&track_metadata);
    let segment_sequence = resolve_required_u64(
        "segment-sequence",
        args.segment_sequence,
        summary_seed.as_ref().and_then(|seed| seed.segment_sequence),
    )?;
    let segment_start_pts = resolve_required_u64(
        "segment-start-pts",
        args.segment_start_pts,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.segment_start_pts),
    )?;
    let segment_duration = resolve_required_u32(
        "segment-duration",
        args.segment_duration,
        summary_seed.as_ref().and_then(|seed| seed.segment_duration),
    )?;
    let segment_duration = require_positive_u32("segment-duration", segment_duration)?;
    let wallclock_unix_ms = resolve_required_u64(
        "wallclock-unix-ms",
        args.wallclock_unix_ms,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.wallclock_unix_ms),
    )?;
    let ingest_latency_ms = resolve_optional_u32(
        "ingest-latency-ms",
        args.ingest_latency_ms,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.ingest_latency_ms),
    )?;
    let live_edge_drift_ms = resolve_optional_i32(
        "live-edge-drift-ms",
        args.live_edge_drift_ms,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.live_edge_drift_ms),
    )?;
    let ingest_node_id = normalize_ingest_node_id(resolve_optional_owned(
        args.ingest_node_id,
        summary_seed
            .as_ref()
            .and_then(|seed| seed.ingest_node_id.clone()),
    ));
    let event_name = parse_name(&event_id_literal, "event-id")?;
    let stream_name = parse_name(&stream_id_literal, "stream-id")?;
    let rendition_name = parse_name(&rendition_id_literal, "rendition-id")?;
    let extra_metadata = match args.metadata_json.as_deref() {
        Some(path) => Some(load_extra_metadata(path)?),
        None => None,
    };
    Ok(BundleInputs {
        input,
        summary_in,
        metadata_json,
        car_out: args.car_out,
        envelope_out: args.envelope_out,
        indexes_out: args.indexes_out,
        ingest_metadata_out: args.ingest_metadata_out,
        summary_out: args.summary_out,
        metadata: BundleMetadata {
            manifest_hash,
            manifest_hash_hex,
            storage_ticket,
            storage_ticket_hex,
            event_id: TaikaiEventId::new(event_name),
            stream_id: TaikaiStreamId::new(stream_name),
            rendition_id: TaikaiRenditionId::new(rendition_name),
            track_kind,
            track_metadata,
            codec_label,
            bitrate_kbps,
            resolution,
            audio_layout,
            segment_sequence,
            segment_start_pts,
            segment_duration,
            wallclock_unix_ms,
            ingest_latency_ms,
            live_edge_drift_ms,
            ingest_node_id,
        },
        extra_metadata,
    })
}
fn resolve_input_source(payload: Option<PathBuf>, car_in: Option<PathBuf>) -> Result<InputSource> {
    match (payload, car_in) {
        (Some(path), None) => Ok(InputSource::Payload(path)),
        (None, Some(path)) => Ok(InputSource::Car(path)),
        (Some(_), Some(_)) => Err(eyre!("specify only one of --payload or --car-in")),
        (None, None) => Err(eyre!(
            "either --payload or --car-in must be provided to build or rehydrate a bundle"
        )),
    }
}
fn resolve_required_owned<T: Clone>(field: &str, cli: Option<T>, seed: Option<T>) -> Result<T> {
    cli.or(seed).ok_or_else(|| {
        eyre!("missing required `{field}` (pass the flag or supply it via --summary-in)")
    })
}
fn resolve_required<T: Copy>(field: &str, cli: Option<T>, seed: Option<T>) -> Result<T> {
    cli.or(seed).ok_or_else(|| {
        eyre!("missing required `{field}` (pass the flag or supply it via --summary-in)")
    })
}
fn resolve_required_u64(field: &str, cli: Option<String>, seed: Option<u64>) -> Result<u64> {
    match cli {
        Some(raw) => parse_u64_arg(field, &raw),
        None => resolve_required(field, seed, None),
    }
}
fn resolve_required_u32(field: &str, cli: Option<String>, seed: Option<u32>) -> Result<u32> {
    match cli {
        Some(raw) => parse_u32_arg(field, &raw),
        None => resolve_required(field, seed, None),
    }
}
fn resolve_optional_u32(
    field: &str,
    cli: Option<String>,
    seed: Option<u32>,
) -> Result<Option<u32>> {
    match cli {
        Some(raw) => Ok(Some(parse_u32_arg(field, &raw)?)),
        None => Ok(seed),
    }
}
fn resolve_optional_i32(
    field: &str,
    cli: Option<String>,
    seed: Option<i32>,
) -> Result<Option<i32>> {
    match cli {
        Some(raw) => Ok(Some(parse_i32_arg(field, &raw)?)),
        None => Ok(seed),
    }
}
fn resolve_optional_owned<T: Clone>(cli: Option<T>, seed: Option<T>) -> Option<T> {
    cli.or(seed)
}
fn load_summary_seed(path: &Path, entry: Option<usize>) -> Result<SummarySeed> {
    let contents = fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read summary seed `{}`", path.display()))?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err(eyre!("summary seed `{}` is empty", path.display()));
    }
    let value = match json::from_str::<Value>(&contents) {
        Ok(value) => pick_summary_value(value, entry, path)?,
        Err(_) => load_ndjson_entry(&contents, entry, path)?,
    };
    summary_seed_from_value(&value, path)
}
fn pick_summary_value(value: Value, entry: Option<usize>, path: &Path) -> Result<Value> {
    match value {
        Value::Array(entries) => {
            if entries.is_empty() {
                return Err(eyre!(
                    "summary `{}` does not contain any entries",
                    path.display()
                ));
            }
            let idx = match (entry, entries.len()) {
                (Some(idx), len) if idx < len => idx,
                (Some(idx), len) => {
                    return Err(eyre!(
                        "summary entry {idx} out of range for `{}` (found {len} entries)",
                        path.display()
                    ));
                }
                (None, 1) => 0,
                (None, len) => {
                    return Err(eyre!(
                        "summary `{}` contains {len} entries; pass --summary-entry to select one",
                        path.display()
                    ));
                }
            };
            Ok(entries[idx].clone())
        }
        Value::Object(_) => Ok(value),
        other => Err(eyre!(
            "summary `{}` must be a JSON object or array, found {}",
            path.display(),
            describe_value_kind(&other)
        )),
    }
}
fn load_ndjson_entry(contents: &str, entry: Option<usize>, path: &Path) -> Result<Value> {
    let lines: Vec<&str> = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return Err(eyre!("summary seed `{}` is empty", path.display()));
    }
    let idx = match (entry, lines.len()) {
        (Some(idx), len) if idx < len => idx,
        (Some(idx), len) => {
            return Err(eyre!(
                "summary entry {idx} out of range for `{}` (found {len} lines)",
                path.display()
            ));
        }
        (None, 1) => 0,
        (None, len) => {
            return Err(eyre!(
                "summary `{}` contains {len} entries; pass --summary-entry to select one",
                path.display()
            ));
        }
    };
    let value: Value = json::from_str(lines[idx]).wrap_err_with(|| {
        format!(
            "failed to parse summary entry {idx} from `{}`",
            path.display()
        )
    })?;
    pick_summary_value(value, None, path)
}
fn summary_seed_from_value(value: &Value, path: &Path) -> Result<SummarySeed> {
    let obj = value.as_object().ok_or_else(|| {
        eyre!(
            "summary entry in `{}` must be a JSON object, found {}",
            path.display(),
            describe_value_kind(value)
        )
    })?;
    let ingest = obj
        .get("ingest")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            eyre!(
                "summary `{}` does not contain an `ingest` object",
                path.display()
            )
        })?;
    let track = obj.get("track").and_then(Value::as_object).ok_or_else(|| {
        eyre!(
            "summary `{}` does not contain a `track` object",
            path.display()
        )
    })?;
    let event_id = ingest
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let stream_id = ingest
        .get("stream_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let rendition_id = ingest
        .get("rendition_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let segment_sequence = ingest.get("segment_sequence").and_then(Value::as_u64);
    let segment_start_pts = ingest.get("segment_start_pts").and_then(Value::as_u64);
    let segment_duration = match ingest.get("segment_duration") {
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| {
                    eyre!(
                        "`segment_duration` in summary `{}` must be an unsigned integer",
                        path.display()
                    )
                })?
                .try_into()
                .map_err(|_| eyre!("segment_duration overflows u32"))?,
        ),
        None => None,
    };
    let wallclock_unix_ms = ingest.get("wallclock_unix_ms").and_then(Value::as_u64);
    let manifest_hash = ingest
        .get("manifest_hash")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let storage_ticket = ingest
        .get("storage_ticket")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let ingest_latency_ms = ingest
        .get("ingest_latency_ms")
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                eyre!(
                    "`ingest_latency_ms` in summary `{}` must be an unsigned integer",
                    path.display()
                )
            })
        })
        .transpose()?
        .map(|value| {
            u32::try_from(value).map_err(|_| {
                eyre!(
                    "`ingest_latency_ms` in summary `{}` does not fit in u32",
                    path.display()
                )
            })
        })
        .transpose()?;
    let live_edge_drift_ms = ingest
        .get("live_edge_drift_ms")
        .map(|value| {
            value.as_i64().ok_or_else(|| {
                eyre!(
                    "`live_edge_drift_ms` in summary `{}` must be a signed integer",
                    path.display()
                )
            })
        })
        .transpose()?
        .map(|value| {
            i32::try_from(value).map_err(|_| {
                eyre!(
                    "`live_edge_drift_ms` in summary `{}` does not fit in i32",
                    path.display()
                )
            })
        })
        .transpose()?;
    let ingest_node_id = ingest
        .get("ingest_node_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let track_kind = track
        .get("kind")
        .and_then(Value::as_str)
        .map(<CliTrackKind as FromStr>::from_str)
        .transpose()?;
    let codec = track
        .get("codec")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let bitrate_kbps = track
        .get("bitrate_kbps")
        .and_then(Value::as_u64)
        .map(|value| {
            value.try_into().map_err(|_| {
                eyre!(
                    "`bitrate_kbps` in summary `{}` overflows u32",
                    path.display()
                )
            })
        })
        .transpose()?;
    let resolution = track
        .get("resolution")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let audio_layout = track
        .get("audio_layout")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(SummarySeed {
        manifest_hash,
        storage_ticket,
        event_id,
        stream_id,
        rendition_id,
        track_kind,
        codec,
        bitrate_kbps,
        resolution,
        audio_layout,
        segment_sequence,
        segment_start_pts,
        segment_duration,
        wallclock_unix_ms,
        ingest_latency_ms,
        live_edge_drift_ms,
        ingest_node_id,
    })
}
fn describe_value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
fn build_track_metadata(
    track_kind: CliTrackKind,
    codec: &str,
    bitrate_kbps: u32,
    resolution: Option<&str>,
    audio_layout: Option<&str>,
) -> Result<TaikaiTrackMetadata> {
    let codec =
        TaikaiCodec::from_str(codec).map_err(|err| eyre!("invalid codec `{}`: {err}", codec))?;
    let track = match track_kind {
        CliTrackKind::Video => {
            let resolution = resolution.ok_or_else(|| {
                eyre!("resolution is required for video tracks (pass --resolution or include it in the summary)")
            })?;
            let parsed = TaikaiResolution::from_str(resolution)
                .map_err(|err| eyre!("invalid resolution `{resolution}`: {err}"))?;
            TaikaiTrackMetadata::video(codec, bitrate_kbps, parsed)
        }
        CliTrackKind::Audio => {
            let layout = audio_layout.ok_or_else(|| {
                eyre!(
                    "audio layout is required for audio tracks (pass --audio-layout or include it in the summary)"
                )
            })?;
            let parsed = TaikaiAudioLayout::from_str(layout)
                .map_err(|err| eyre!("invalid audio layout `{layout}`: {err}"))?;
            TaikaiTrackMetadata::audio(codec, bitrate_kbps, parsed)
        }
        CliTrackKind::Data => TaikaiTrackMetadata::data(codec, bitrate_kbps),
    };
    validate_track_metadata(&track)?;
    Ok(track)
}
fn canonical_track_labels(track: &TaikaiTrackMetadata) -> (String, Option<String>, Option<String>) {
    let codec = match &track.codec {
        TaikaiCodec::AvcHigh => "avc-high".to_owned(),
        TaikaiCodec::HevcMain10 => "hevc-main10".to_owned(),
        TaikaiCodec::Av1Main => "av1-main".to_owned(),
        TaikaiCodec::AacLc => "aac-lc".to_owned(),
        TaikaiCodec::Opus => "opus".to_owned(),
        TaikaiCodec::Custom(profile) => format!("custom:{profile}"),
    };
    let resolution = track
        .resolution
        .map(|resolution| format!("{}x{}", resolution.width, resolution.height));
    let audio_layout = track.audio_layout.map(|layout| match layout {
        TaikaiAudioLayout::Mono => "mono".to_owned(),
        TaikaiAudioLayout::Stereo => "stereo".to_owned(),
        TaikaiAudioLayout::FiveOne => "5.1".to_owned(),
        TaikaiAudioLayout::SevenOne => "7.1".to_owned(),
        TaikaiAudioLayout::Custom(channels) => format!("custom:{channels}"),
    });
    (codec, resolution, audio_layout)
}
fn normalize_ingest_node_id(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}
fn parse_name(value: &str, field: &str) -> Result<Name> {
    Name::from_str(value).map_err(|err| eyre!("invalid {field} `{value}`: {err}"))
}
fn parse_u64_arg(field: &str, raw: &str) -> Result<u64> {
    require_canonical_unsigned(field, raw)?;
    raw.parse::<u64>()
        .map_err(|err| eyre!("invalid {field} `{raw}`: {err}"))
}
fn parse_u32_arg(field: &str, raw: &str) -> Result<u32> {
    let parsed = parse_u64_arg(field, raw)?;
    u32::try_from(parsed).map_err(|_| eyre!("{field} value {parsed} exceeds u32 range"))
}
fn parse_usize_arg(field: &str, raw: &str) -> Result<usize> {
    let parsed = parse_u64_arg(field, raw)?;
    usize::try_from(parsed).map_err(|_| eyre!("{field} value {parsed} exceeds usize range"))
}
fn parse_i32_arg(field: &str, raw: &str) -> Result<i32> {
    require_canonical_signed(field, raw)?;
    raw.parse::<i32>()
        .map_err(|err| eyre!("invalid {field} `{raw}`: {err}"))
}
fn require_positive_u32(field: &str, value: u32) -> Result<u32> {
    if value == 0 {
        return Err(eyre!("{field} must be greater than zero"));
    }
    Ok(value)
}
fn require_canonical_unsigned(field: &str, raw: &str) -> Result<()> {
    if raw.is_empty() {
        return Err(eyre!("{field} must not be empty"));
    }
    if raw.as_bytes().iter().any(u8::is_ascii_whitespace) {
        return Err(eyre!("{field} must not contain ASCII whitespace"));
    }
    if raw.starts_with('+') || raw.starts_with('-') {
        return Err(eyre!("{field} must be an unsigned decimal token"));
    }
    if !raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(eyre!("{field} must contain only decimal digits"));
    }
    if raw.len() > 1 && raw.starts_with('0') {
        return Err(eyre!(
            "{field} must use canonical decimal without leading zeros"
        ));
    }
    Ok(())
}
fn require_canonical_signed(field: &str, raw: &str) -> Result<()> {
    if raw.is_empty() {
        return Err(eyre!("{field} must not be empty"));
    }
    if raw.as_bytes().iter().any(u8::is_ascii_whitespace) {
        return Err(eyre!("{field} must not contain ASCII whitespace"));
    }
    if raw.starts_with('+') {
        return Err(eyre!("{field} must not use an explicit plus sign"));
    }
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty() {
        return Err(eyre!("{field} must include decimal digits"));
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(eyre!("{field} must contain only decimal digits"));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(eyre!(
            "{field} must use canonical decimal without leading zeros"
        ));
    }
    if raw.starts_with('-') && digits == "0" {
        return Err(eyre!("{field} must not encode negative zero"));
    }
    Ok(())
}
fn parse_blob_digest(value: &str, field: &str) -> Result<BlobDigest> {
    let bytes = parse_hex_32(value, field)?;
    Ok(BlobDigest::new(bytes))
}
fn parse_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    if value.is_empty() {
        return Err(eyre!("{field} hex must not be empty"));
    }
    if value.as_bytes().iter().any(u8::is_ascii_whitespace) {
        return Err(eyre!("{field} hex must not contain ASCII whitespace"));
    }
    if value.starts_with("0x") || value.starts_with("0X") {
        return Err(eyre!("{field} hex must not use a 0x prefix"));
    }
    if value.len() != 64 {
        return Err(eyre!(
            "{field} must contain 32 bytes (64 lowercase hex chars), got {} chars",
            value.len()
        ));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
    {
        return Err(eyre!("{field} hex must be lowercase canonical hex"));
    }
    let bytes = hex::decode(value).map_err(|err| eyre!("invalid {field} hex `{value}`: {err}"))?;
    if bytes.len() != 32 {
        return Err(eyre!(
            "{field} must contain 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    if out.iter().all(|byte| *byte == 0) {
        return Err(eyre!("{field} must not be all zeros"));
    }
    Ok(out)
}
fn render_summary_value(inputs: &BundleInputs, summary: &BundleSummary) -> Value {
    let meta = &inputs.metadata;
    let mut ingest = Map::new();
    ingest.insert(
        "event_id".into(),
        Value::from(meta.event_id.as_name().as_ref()),
    );
    ingest.insert(
        "stream_id".into(),
        Value::from(meta.stream_id.as_name().as_ref()),
    );
    ingest.insert(
        "rendition_id".into(),
        Value::from(meta.rendition_id.as_name().as_ref()),
    );
    ingest.insert(
        "segment_sequence".into(),
        Value::from(meta.segment_sequence),
    );
    ingest.insert(
        "segment_start_pts".into(),
        Value::from(meta.segment_start_pts),
    );
    ingest.insert(
        "segment_duration".into(),
        Value::from(meta.segment_duration),
    );
    ingest.insert(
        "wallclock_unix_ms".into(),
        Value::from(meta.wallclock_unix_ms),
    );
    ingest.insert(
        "manifest_hash".into(),
        Value::from(meta.manifest_hash_hex.clone()),
    );
    ingest.insert(
        "storage_ticket".into(),
        Value::from(meta.storage_ticket_hex.clone()),
    );
    if let Some(latency) = meta.ingest_latency_ms {
        ingest.insert("ingest_latency_ms".into(), Value::from(latency));
    }
    if let Some(drift) = meta.live_edge_drift_ms {
        ingest.insert("live_edge_drift_ms".into(), Value::from(drift));
    }
    if let Some(node_id) = &meta.ingest_node_id {
        ingest.insert("ingest_node_id".into(), Value::from(node_id.clone()));
    }
    let mut track = Map::new();
    track.insert("kind".into(), Value::from(meta.track_kind.as_str()));
    track.insert("codec".into(), Value::from(meta.codec_label.clone()));
    track.insert("bitrate_kbps".into(), Value::from(meta.bitrate_kbps));
    if let Some(resolution) = &meta.resolution {
        track.insert("resolution".into(), Value::from(resolution.clone()));
    }
    if let Some(layout) = &meta.audio_layout {
        track.insert("audio_layout".into(), Value::from(layout.clone()));
    }
    let mut car = Map::new();
    car.insert(
        "cid_multibase".into(),
        Value::from(summary.car_pointer.cid_multibase.clone()),
    );
    car.insert(
        "digest_blake3_hex".into(),
        Value::from(hex::encode(summary.car_pointer.car_digest.as_bytes())),
    );
    car.insert(
        "size_bytes".into(),
        Value::from(summary.car_pointer.car_size_bytes),
    );
    let mut chunk = Map::new();
    chunk.insert(
        "root_blake3_hex".into(),
        Value::from(hex::encode(summary.chunk_root.as_bytes())),
    );
    chunk.insert("count".into(), Value::from(summary.chunk_count));
    let mut outputs = Map::new();
    outputs.insert(
        "car".into(),
        Value::from(summary.car_out.to_string_lossy().into_owned()),
    );
    outputs.insert(
        "envelope".into(),
        Value::from(summary.envelope_out.to_string_lossy().into_owned()),
    );
    if let Some(path) = summary.indexes_out.as_ref() {
        outputs.insert(
            "indexes".into(),
            Value::from(path.to_string_lossy().into_owned()),
        );
    }
    if let Some(path) = summary.ingest_metadata_out.as_ref() {
        outputs.insert(
            "ingest_metadata".into(),
            Value::from(path.to_string_lossy().into_owned()),
        );
    }
    let mut root = Map::new();
    root.insert("ingest".into(), Value::Object(ingest));
    root.insert("track".into(), Value::Object(track));
    root.insert("car".into(), Value::Object(car));
    root.insert("chunk".into(), Value::Object(chunk));
    root.insert("outputs".into(), Value::Object(outputs));
    root.insert(
        "indexes".into(),
        Value::Object(render_indexes_map(&summary.indexes)),
    );
    root.insert(
        "ingest_metadata".into(),
        Value::Object(summary.ingest_metadata.clone()),
    );
    Value::Object(root)
}
fn write_summary_json(path: &Path, value: &Value) -> Result<()> {
    let rendered = json::to_json_pretty(value)
        .map_err(|err| eyre!("failed to render bundle summary JSON: {err}"))?;
    write_output_bytes(path, "bundle summary", rendered.as_bytes())
}
fn render_indexes_map(indexes: &iroha_data_model::taikai::TaikaiEnvelopeIndexes) -> Map {
    let mut time_key = Map::new();
    time_key.insert(
        "event_id".into(),
        Value::from(indexes.time_key.event_id.as_name().as_ref()),
    );
    time_key.insert(
        "stream_id".into(),
        Value::from(indexes.time_key.stream_id.as_name().as_ref()),
    );
    time_key.insert(
        "rendition_id".into(),
        Value::from(indexes.time_key.rendition_id.as_name().as_ref()),
    );
    time_key.insert(
        "segment_start_pts".into(),
        Value::from(indexes.time_key.segment_start_pts.as_micros()),
    );
    let mut cid_key = Map::new();
    cid_key.insert(
        "event_id".into(),
        Value::from(indexes.cid_key.event_id.as_name().as_ref()),
    );
    cid_key.insert(
        "stream_id".into(),
        Value::from(indexes.cid_key.stream_id.as_name().as_ref()),
    );
    cid_key.insert(
        "rendition_id".into(),
        Value::from(indexes.cid_key.rendition_id.as_name().as_ref()),
    );
    cid_key.insert(
        "cid_multibase".into(),
        Value::from(indexes.cid_key.cid_multibase.clone()),
    );
    let mut rendered = Map::new();
    rendered.insert("time_key".into(), Value::Object(time_key));
    rendered.insert("cid_key".into(), Value::Object(cid_key));
    rendered
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};
    fn canonical_tempdir() -> (TempDir, PathBuf) {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().canonicalize().expect("canonical tempdir");
        (temp, path)
    }
    #[test]
    fn numeric_arg_parsers_reject_noncanonical_values() {
        assert_eq!(parse_u64_arg("segment-sequence", "0").expect("zero"), 0);
        assert_eq!(parse_u64_arg("segment-sequence", "42").expect("u64"), 42);
        assert_eq!(parse_i32_arg("live-edge-drift-ms", "-7").expect("i32"), -7);
        assert_eq!(parse_i32_arg("live-edge-drift-ms", "0").expect("zero"), 0);
        for value in ["", " 1", "1 ", "+1", "-1", "01", "0x1", "1_000"] {
            let err = parse_u64_arg("segment-sequence", value)
                .expect_err("noncanonical unsigned must fail");
            let message = err.to_string();
            assert!(
                message.contains("empty")
                    || message.contains("whitespace")
                    || message.contains("unsigned decimal")
                    || message.contains("decimal digits")
                    || message.contains("leading zeros"),
                "unexpected unsigned error for {value:?}: {message}"
            );
        }
        for value in ["", " -1", "+1", "-01", "-0", "01", "1.5"] {
            let err = parse_i32_arg("live-edge-drift-ms", value)
                .expect_err("noncanonical signed value must fail");
            let message = err.to_string();
            assert!(
                message.contains("empty")
                    || message.contains("whitespace")
                    || message.contains("plus")
                    || message.contains("decimal")
                    || message.contains("leading zeros")
                    || message.contains("negative zero"),
                "unexpected signed error for {value:?}: {message}"
            );
        }
        let err = parse_u32_arg("bitrate-kbps", "4294967296").expect_err("u32 overflow must fail");
        assert!(
            err.to_string().contains("u32 range"),
            "unexpected overflow error: {err}"
        );
        let err =
            require_positive_u32("segment-duration", 0).expect_err("zero positive field must fail");
        assert!(
            err.to_string().contains("greater than zero"),
            "unexpected positive error: {err}"
        );
    }
    #[test]
    fn parse_hex_32_rejects_noncanonical_or_zero_values() {
        assert_eq!(
            parse_hex_32(&"11".repeat(32), "manifest-hash").expect("hex"),
            [0x11; 32]
        );
        let cases = vec![
            String::new(),
            "00".repeat(32),
            format!("0x{}", "11".repeat(32)),
            "AA".repeat(32),
            format!("{} ", "11".repeat(32)),
            "11".repeat(31),
        ];
        for value in cases {
            let err =
                parse_hex_32(&value, "manifest-hash").expect_err("noncanonical hex must fail");
            let message = err.to_string();
            assert!(
                message.contains("empty")
                    || message.contains("all zeros")
                    || message.contains("0x prefix")
                    || message.contains("lowercase")
                    || message.contains("whitespace")
                    || message.contains("64 lowercase hex"),
                "unexpected hex error for {value:?}: {message}"
            );
        }
    }
    #[test]
    fn summary_seed_rejects_overflowing_ingest_latency() {
        let mut ingest = Map::new();
        ingest.insert(
            "ingest_latency_ms".into(),
            Value::from(u64::from(u32::MAX) + 1),
        );
        let mut root = Map::new();
        root.insert("ingest".into(), Value::Object(ingest));
        root.insert("track".into(), Value::Object(Map::new()));
        let err = summary_seed_from_value(&Value::Object(root), Path::new("summary.json"))
            .expect_err("overflowing ingest latency must fail");
        let message = err.to_string();
        assert!(
            message.contains("does not fit in u32"),
            "unexpected overflow error: {message}"
        );
    }
    #[test]
    fn track_metadata_rejects_codec_kind_mismatches() {
        let video_error = build_track_metadata(
            CliTrackKind::Video,
            "aac-lc",
            8_000,
            Some("1920x1080"),
            None,
        )
        .expect_err("AAC must not be sealed as a video codec");
        assert!(
            video_error
                .to_string()
                .contains("not valid for a video track"),
            "unexpected video error: {video_error}"
        );

        let audio_error =
            build_track_metadata(CliTrackKind::Audio, "av1-main", 192, None, Some("stereo"))
                .expect_err("AV1 must not be sealed as an audio codec");
        assert!(
            audio_error
                .to_string()
                .contains("not valid for an audio track"),
            "unexpected audio error: {audio_error}"
        );
    }
    #[test]
    fn track_labels_and_ingest_node_id_are_canonicalized() {
        let track = build_track_metadata(
            CliTrackKind::Video,
            "  AV1-MAIN  ",
            8_000,
            Some(" 1920 X 1080 "),
            Some("stereo"),
        )
        .expect("video metadata");

        assert_eq!(
            canonical_track_labels(&track),
            ("av1-main".to_owned(), Some("1920x1080".to_owned()), None)
        );
        assert_eq!(
            normalize_ingest_node_id(Some("  node-a  ".to_owned())).as_deref(),
            Some("node-a")
        );
        assert_eq!(normalize_ingest_node_id(Some("   ".to_owned())), None);
    }
    #[test]
    fn write_summary_json_creates_parent_and_writes_document() {
        let (_temp, temp_path) = canonical_tempdir();
        let summary_path = temp_path.join("nested").join("summary.json");
        let mut value = Map::new();
        value.insert("schema".into(), Value::from("taikai.summary.v1"));
        write_summary_json(&summary_path, &Value::Object(value)).expect("write summary");
        let text = fs::read_to_string(&summary_path).expect("read summary");
        assert!(
            text.contains("taikai.summary.v1"),
            "summary JSON missing marker: {text}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_summary_json_rejects_symlink_output() {
        let (_temp, temp_path) = canonical_tempdir();
        let target_path = temp_path.join("target.json");
        fs::write(&target_path, b"unchanged\n").expect("write target");
        let summary_path = temp_path.join("summary.json");
        std::os::unix::fs::symlink(&target_path, &summary_path).expect("create symlink");
        let err = write_summary_json(&summary_path, &Value::Object(Map::new()))
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
    fn write_summary_json_rejects_socket_output() {
        // Unix socket addresses have a small fixed byte limit, independent of PATH_MAX.
        // A caller's TMPDIR can exceed it; keep this real socket fixture under /tmp.
        let socket_root = tempfile::tempdir_in("/tmp").expect("short Unix socket directory");
        let temp_path = socket_root
            .path()
            .canonicalize()
            .expect("canonical socket root");
        let summary_path = temp_path.join("summary.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&summary_path).expect("bind Unix socket");

        let err = write_summary_json(&summary_path, &Value::Object(Map::new()))
            .expect_err("reject socket output");

        assert!(
            err.to_string().contains("must be a regular file"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn write_summary_json_rejects_readonly_output_without_truncating() {
        let (_temp, temp_path) = canonical_tempdir();
        let summary_path = temp_path.join("summary.json");
        fs::write(&summary_path, b"preserve").expect("write summary");
        let mut permissions = fs::metadata(&summary_path)
            .expect("summary metadata")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&summary_path, permissions).expect("make summary read-only");

        let err = write_summary_json(&summary_path, &Value::Object(Map::new()))
            .expect_err("reject read-only summary output");

        assert!(
            err.to_string().contains("must be writable"),
            "unexpected error: {err}"
        );
        assert_eq!(fs::read(&summary_path).expect("read summary"), b"preserve");
    }
    #[cfg(unix)]
    #[test]
    fn write_summary_json_rejects_symlink_parent() {
        let (_temp, temp_path) = canonical_tempdir();
        let real_dir = temp_path.join("real");
        fs::create_dir(&real_dir).expect("create real dir");
        let linked_dir = temp_path.join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).expect("create symlink");
        let summary_path = linked_dir.join("summary.json");
        let err = write_summary_json(&summary_path, &Value::Object(Map::new()))
            .expect_err("reject symlink parent");
        let message = err.to_string();
        assert!(
            message.contains("parent") && message.contains("must not be a symlink"),
            "unexpected error: {message}"
        );
        assert!(
            !real_dir.join("summary.json").exists(),
            "symlink parent should not receive output"
        );
    }
}
