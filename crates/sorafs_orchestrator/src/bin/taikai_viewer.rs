//! Minimal Taikai viewer harness used for SN13-F/SN13-G validation.
//!
//! The tool validates Taikai segment envelopes against CAR archives, records playback telemetry
//! (segments, rebuffer events, CEK fetch/rotation, PQ health), and emits Prometheus text along with
//! an optional JSON summary. Multiple renditions or events can be supplied via repeated `--segment`
//! flags; streams with the same name in different events remain distinct in telemetry.
#![allow(unexpected_cfgs)]
use iroha_data_model::taikai::{
    CEK_ROTATION_RECEIPT_VERSION_V1, CekRotationReceiptV1, TaikaiEventId, TaikaiRenditionId,
    TaikaiSegmentEnvelopeV1, TaikaiStreamId,
};
use iroha_telemetry::metrics::Metrics;
use norito::{
    decode_from_bytes, json,
    json::{Map, Value},
};
use rand::{rand_core::TryRngCore, rngs::OsRng};
#[cfg(unix)]
use sorafs_car::platform_no_follow_flag;
use sorafs_car::taikai::{
    validate_distinct_artifact_paths, validate_track_metadata, verify_taikai_car,
};
use sorafs_car::{ensure_output_parent_dir, set_no_follow_flag};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
    fs, io,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
const USAGE: &str = "\
taikai_viewer --segment envelope=PATH,car=PATH [--segment ...] [--cluster LABEL] [--lane LABEL]
              [--rebuffer-events N] [--pq-health PCT] [--cek-receipt PATH] [--cek-fetch-ms N]
              [--alert ALERTNAME ...] [--metrics-out PATH] [--summary-out PATH]
";
const TAIKAI_VIEWER_ENVELOPE_MAX_BYTES: usize = 256 * 1024;
const TAIKAI_VIEWER_CEK_RECEIPT_MAX_BYTES: usize = 256 * 1024;
const TAIKAI_VIEWER_CAR_MAX_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug)]
struct SegmentInput {
    envelope: PathBuf,
    car: PathBuf,
}
#[derive(Debug, Default)]
struct StreamStats {
    segments: u64,
    rebuffer_events: u64,
}
fn main() {
    if let Err(err) = run() {
        eprintln!("taikai_viewer: {err}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    run_with_args(args)
}
fn run_with_args(args: ParsedArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.segments.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one --segment=... entry is required",
        )
        .into());
    }
    preflight_output_collisions(&args)?;
    let metrics = Metrics::default();
    let mut summaries: Vec<Value> = Vec::new();
    let mut stream_stats: HashMap<(TaikaiEventId, TaikaiStreamId), StreamStats> = HashMap::new();
    let mut stream_order: Vec<(TaikaiEventId, TaikaiStreamId)> = Vec::new();
    let mut segment_identities: HashSet<(TaikaiEventId, TaikaiStreamId, TaikaiRenditionId, u64)> =
        HashSet::new();
    let mut viewed_streams: Vec<(TaikaiEventId, TaikaiStreamId)> = Vec::new();
    for segment in &args.segments {
        let envelope = load_envelope(&segment.envelope)?;
        let segment_identity = (
            envelope.event_id.clone(),
            envelope.stream_id.clone(),
            envelope.rendition_id.clone(),
            envelope.segment_sequence,
        );
        if !segment_identities.insert(segment_identity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "duplicate Taikai segment identity {}/{}/{} sequence {}",
                    envelope.event_id,
                    envelope.stream_id,
                    envelope.rendition_id,
                    envelope.segment_sequence
                ),
            )
            .into());
        }
        let car_bytes =
            read_bounded_regular_file(&segment.car, "Taikai CAR", TAIKAI_VIEWER_CAR_MAX_BYTES)?;
        validate_car(&envelope, &car_bytes, &segment.car)?;
        if !viewed_streams.iter().any(|(event_id, stream_id)| {
            event_id == &envelope.event_id && stream_id == &envelope.stream_id
        }) {
            viewed_streams.push((envelope.event_id.clone(), envelope.stream_id.clone()));
        }
        let render_name = envelope.rendition_id.to_string();
        let stream = envelope.stream_id.to_string();
        let stream_key = (envelope.event_id.clone(), envelope.stream_id.clone());
        if !stream_stats.contains_key(&stream_key) {
            stream_order.push(stream_key.clone());
        }
        let stats = stream_stats.entry(stream_key).or_default();
        stats.segments += 1;
        let ingest = &envelope.ingest;
        let instrumentation = &envelope.instrumentation;
        let mut entry = Map::new();
        entry.insert("event".into(), Value::from(envelope.event_id.to_string()));
        entry.insert("stream".into(), Value::from(stream));
        entry.insert("rendition".into(), Value::from(render_name));
        entry.insert("sequence".into(), Value::from(envelope.segment_sequence));
        entry.insert(
            "car_path".into(),
            Value::from(segment.car.to_string_lossy().into_owned()),
        );
        entry.insert(
            "car_digest_hex".into(),
            Value::from(hex::encode(ingest.car.car_digest.as_bytes())),
        );
        entry.insert(
            "car_size_bytes".into(),
            Value::from(ingest.car.car_size_bytes),
        );
        entry.insert(
            "chunk_count".into(),
            Value::from(u64::from(ingest.chunk_count)),
        );
        if let Some(latency) = instrumentation.encoder_to_ingest_latency_ms {
            entry.insert("encoder_to_ingest_latency_ms".into(), Value::from(latency));
        }
        if let Some(drift) = instrumentation.live_edge_drift_ms {
            entry.insert("live_edge_drift_ms".into(), Value::from(drift));
        }
        summaries.push(Value::Object(entry));
    }
    let mut stream_name_counts: HashMap<TaikaiStreamId, usize> = HashMap::new();
    for (_, stream_id) in stream_stats.keys() {
        *stream_name_counts.entry(stream_id.clone()).or_default() += 1;
    }
    if let Some(first_stream) = stream_order.first()
        && let Some(first_stats) = stream_stats.get_mut(first_stream)
    {
        first_stats.rebuffer_events = args.rebuffer_events;
        if args.rebuffer_events > 0 {
            let stream_label = metric_stream_label(first_stream, &stream_name_counts);
            metrics.inc_taikai_viewer_rebuffer(&args.cluster, &stream_label, args.rebuffer_events);
        }
    }
    for (stream_key, stats) in &stream_stats {
        let stream_label = metric_stream_label(stream_key, &stream_name_counts);
        metrics.inc_taikai_viewer_segments(&args.cluster, &stream_label, stats.segments);
    }
    metrics.set_taikai_viewer_pq_health(&args.cluster, args.pq_health);
    let mut cek_summary: Option<Map> = None;
    if let Some(path) = args.cek_receipt.as_ref() {
        let observation = read_cek_receipt(path)?;
        if !viewed_streams.iter().any(|(event_id, stream_id)| {
            event_id == &observation.receipt.event_id && stream_id == &observation.receipt.stream_id
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "CEK rotation receipt {} targets {}/{} which is absent from the viewed segments",
                    path.display(),
                    observation.receipt.event_id,
                    observation.receipt.stream_id
                ),
            )
            .into());
        }
        let measured_ms = observation.measured_ms;
        let age_seconds = observation.age_seconds;
        let applied_ms = args.cek_fetch_ms.unwrap_or(measured_ms);
        metrics.observe_taikai_viewer_cek_fetch_duration(&args.cluster, &args.lane, applied_ms);
        metrics.set_taikai_viewer_cek_rotation_age(&args.lane, age_seconds);
        let mut cek = Map::new();
        cek.insert(
            "path".into(),
            Value::from(path.to_string_lossy().into_owned()),
        );
        cek.insert(
            "event".into(),
            Value::from(observation.receipt.event_id.to_string()),
        );
        cek.insert(
            "stream".into(),
            Value::from(observation.receipt.stream_id.to_string()),
        );
        cek.insert("duration_ms".into(), Value::from(u64::from(applied_ms)));
        cek.insert(
            "measured_duration_ms".into(),
            Value::from(u64::from(measured_ms)),
        );
        cek.insert("rotation_age_seconds".into(), Value::from(age_seconds));
        cek_summary = Some(cek);
    }
    for alertname in &args.alerts {
        metrics.inc_taikai_viewer_alert_firing(&args.cluster, alertname);
    }
    let metrics_text = metrics.try_to_string()?;
    let summary_text = if args.summary_out.is_some() {
        let mut root = Map::new();
        root.insert("cluster".into(), Value::from(args.cluster));
        root.insert("lane".into(), Value::from(args.lane));
        root.insert("pq_health_percent".into(), Value::from(args.pq_health));
        root.insert(
            "rebuffer_events_applied".into(),
            Value::from(args.rebuffer_events),
        );
        if let Some(cek) = cek_summary {
            root.insert("cek".into(), Value::Object(cek));
        }
        if let Some(path) = args.metrics_out.as_ref() {
            root.insert(
                "metrics_out".into(),
                Value::from(path.to_string_lossy().into_owned()),
            );
        }
        if !args.alerts.is_empty() {
            root.insert(
                "alerts".into(),
                Value::Array(args.alerts.iter().cloned().map(Value::from).collect()),
            );
        }
        root.insert("segments".into(), Value::Array(summaries));
        Some(json::to_json_pretty(&Value::Object(root))?)
    } else {
        None
    };

    let mut staged_outputs = Vec::with_capacity(2);
    if let Some(path) = args.metrics_out.as_ref() {
        staged_outputs.push(StagedOutput::prepare(
            path,
            "metrics output",
            metrics_text.as_bytes(),
        )?);
    }
    if let (Some(path), Some(rendered)) = (args.summary_out.as_ref(), summary_text.as_ref()) {
        staged_outputs.push(StagedOutput::prepare(
            path,
            "summary output",
            rendered.as_bytes(),
        )?);
    }
    publish_staged_outputs(staged_outputs)?;
    if args.metrics_out.is_none() {
        println!("{metrics_text}");
    }
    Ok(())
}
fn metric_stream_label(
    stream: &(TaikaiEventId, TaikaiStreamId),
    stream_name_counts: &HashMap<TaikaiStreamId, usize>,
) -> String {
    if stream_name_counts
        .get(&stream.1)
        .copied()
        .unwrap_or_default()
        > 1
    {
        // `Name` reserves `@`, so the scoped label cannot collide with an ordinary stream name.
        format!("{}@{}", stream.0, stream.1)
    } else {
        stream.1.to_string()
    }
}
struct StagedOutput {
    target_path: PathBuf,
    temporary_path: Option<PathBuf>,
    label: String,
}
impl StagedOutput {
    fn prepare(path: &Path, label: &str, bytes: &[u8]) -> io::Result<Self> {
        validate_output_path(path)?;
        ensure_output_parent_dir(path)?;
        validate_output_path(path)?;
        let (temporary_path, mut file) = create_temporary_output(path, label)?;
        if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary_path);
            return Err(io::Error::new(
                err.kind(),
                format!("failed to write {label} `{}`: {err}", path.display()),
            ));
        }
        drop(file);
        if let Err(err) = validate_output_path(path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(err);
        }
        Ok(Self {
            target_path: path.to_path_buf(),
            temporary_path: Some(temporary_path),
            label: label.to_owned(),
        })
    }
    fn validate_target(&self) -> io::Result<()> {
        validate_output_path(&self.target_path)
    }
    fn publish(&mut self) -> io::Result<()> {
        self.validate_target()?;
        let Some(temporary_path) = self.temporary_path.take() else {
            return Err(io::Error::other(format!(
                "{} `{}` has no staged temporary file",
                self.label,
                self.target_path.display()
            )));
        };
        if let Err(err) = fs::rename(&temporary_path, &self.target_path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "failed to atomically publish {} `{}`: {err}",
                    self.label,
                    self.target_path.display()
                ),
            ));
        }
        Ok(())
    }
}
impl Drop for StagedOutput {
    fn drop(&mut self) {
        if let Some(path) = self.temporary_path.take() {
            let _ = fs::remove_file(path);
        }
    }
}
fn publish_staged_outputs(staged: Vec<StagedOutput>) -> io::Result<()> {
    publish_staged_outputs_with_hook(staged, |_, _| Ok(()))
}
fn publish_staged_outputs_with_hook<F>(
    mut staged: Vec<StagedOutput>,
    mut before_publish: F,
) -> io::Result<()>
where
    F: FnMut(usize, &mut StagedOutput) -> io::Result<()>,
{
    for output in &staged {
        output.validate_target()?;
    }
    let mut backups = Vec::with_capacity(staged.len());
    for output in &staged {
        backups.push(snapshot_output(output)?);
    }

    for index in 0..staged.len() {
        let result =
            before_publish(index, &mut staged[index]).and_then(|()| staged[index].publish());
        if let Err(err) = result {
            let rollback_error = rollback_outputs(&staged, &mut backups, index);
            let mut message = format!(
                "failed to publish output transaction at {} `{}`: {err}",
                staged[index].label,
                staged[index].target_path.display()
            );
            if let Err(rollback_error) = rollback_error {
                message.push_str(&format!("; rollback also failed: {rollback_error}"));
            }
            return Err(io::Error::new(err.kind(), message));
        }
    }
    Ok(())
}
fn snapshot_output(output: &StagedOutput) -> io::Result<Option<StagedOutput>> {
    let metadata = match fs::symlink_metadata(&output.target_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "failed to inspect existing {} `{}`: {err}",
                    output.label,
                    output.target_path.display()
                ),
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::other(format!(
            "{} `{}` must be a regular file and must not be a symlink",
            output.label,
            output.target_path.display()
        )));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    set_no_follow_flag(&mut options);
    let mut file = options.open(&output.target_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to open existing {} `{}`: {err}",
                output.label,
                output.target_path.display()
            ),
        )
    })?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(format!(
            "{} `{}` changed to a non-regular file while preparing output",
            output.label,
            output.target_path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to snapshot existing {} `{}`: {err}",
                output.label,
                output.target_path.display()
            ),
        )
    })?;
    let snapshot_label = format!("{} rollback snapshot", output.label);
    let snapshot = StagedOutput::prepare(&output.target_path, &snapshot_label, &bytes)?;
    if let Some(path) = snapshot.temporary_path.as_ref() {
        fs::set_permissions(path, metadata.permissions()).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "failed to preserve permissions for {} `{}`: {err}",
                    output.label,
                    output.target_path.display()
                ),
            )
        })?;
    }
    Ok(Some(snapshot))
}
fn rollback_outputs(
    staged: &[StagedOutput],
    backups: &mut [Option<StagedOutput>],
    published: usize,
) -> io::Result<()> {
    let mut failures = Vec::new();
    for index in (0..published).rev() {
        let target = &staged[index].target_path;
        let result = match backups[index].as_mut() {
            Some(backup) => backup.publish(),
            None => fs::remove_file(target),
        };
        if let Err(err) = result {
            failures.push(format!("`{}`: {err}", target.display()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "failed to restore viewer outputs: {}",
            failures.join(", ")
        )))
    }
}
#[cfg(test)]
fn write_output_bytes(path: &Path, label: &str, bytes: &[u8]) -> io::Result<()> {
    publish_staged_outputs(vec![StagedOutput::prepare(path, label, bytes)?])
}
fn create_temporary_output(path: &Path, label: &str) -> io::Result<(PathBuf, fs::File)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} path `{}` has no file name", path.display()),
        )
    })?;
    for _ in 0..16 {
        let mut nonce = [0_u8; 16];
        OsRng.try_fill_bytes(&mut nonce).map_err(|err| {
            io::Error::other(format!(
                "failed to generate temporary name for {label} `{}`: {err}",
                path.display()
            ))
        })?;
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(".tmp-");
        temporary_name.push(hex::encode(nonce));
        let temporary_path = parent.join(temporary_name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        set_no_follow_flag(&mut options);
        match options.open(&temporary_path) {
            Ok(file) => return Ok((temporary_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(io::Error::new(
                    err.kind(),
                    format!(
                        "failed to create temporary {label} beside `{}`: {err}",
                        path.display()
                    ),
                ));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "failed to allocate a unique temporary {label} beside `{}`",
            path.display()
        ),
    ))
}
fn validate_output_path(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(io::Error::other(format!(
                    "output `{}` must not be a symlink",
                    path.display()
                )));
            }
            if !metadata.is_file() {
                return Err(io::Error::other(format!(
                    "output `{}` must be a regular file",
                    path.display()
                )));
            }
            if metadata.permissions().readonly() {
                return Err(io::Error::other(format!(
                    "output `{}` must be writable",
                    path.display()
                )));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(io::Error::new(
                err.kind(),
                format!("failed to inspect output `{}`: {err}", path.display()),
            ));
        }
    }
    if let Some(parent) = path.parent() {
        for ancestor in std::iter::once(parent).chain(parent.ancestors().skip(1)) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(io::Error::other(format!(
                            "output parent `{}` must not be a symlink",
                            ancestor.display()
                        )));
                    }
                    if !metadata.is_dir() {
                        return Err(io::Error::other(format!(
                            "output parent `{}` must be a directory",
                            ancestor.display()
                        )));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(io::Error::new(
                        err.kind(),
                        format!(
                            "failed to inspect output parent `{}`: {err}",
                            ancestor.display()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_nonblocking_read_flag() -> i32 {
    0o4000
}
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android")),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
fn platform_nonblocking_read_flag() -> i32 {
    0x4
}
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
fn platform_nonblocking_read_flag() -> i32 {
    0
}
#[cfg(unix)]
fn open_bounded_input(path: &Path) -> io::Result<fs::File> {
    let no_follow = platform_no_follow_flag();
    let nonblocking = platform_nonblocking_read_flag();
    if no_follow == 0 || nonblocking == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure direct-file input opens are unavailable on this Unix target",
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(no_follow | nonblocking);
    options.open(path)
}
#[cfg(windows)]
fn open_bounded_input(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}
#[cfg(not(any(unix, windows)))]
fn open_bounded_input(_path: &Path) -> io::Result<fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure direct-file input opens are unavailable on this platform",
    ))
}
fn bounded_input_metadata_is_indirect(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    false
}
#[cfg(unix)]
fn bounded_input_metadata_same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}
#[cfg(windows)]
fn bounded_input_metadata_same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    left.volume_serial_number().is_some()
        && left.file_index().is_some()
        && left.volume_serial_number() == right.volume_serial_number()
        && left.file_index() == right.file_index()
}
#[cfg(not(any(unix, windows)))]
fn bounded_input_metadata_same_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}
#[cfg(unix)]
fn bounded_input_metadata_unchanged(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    bounded_input_metadata_same_identity(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(windows)]
fn bounded_input_metadata_unchanged(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    bounded_input_metadata_same_identity(left, right)
        && left.file_size() == right.file_size()
        && left.last_write_time() == right.last_write_time()
        && left.creation_time() == right.creation_time()
}
#[cfg(not(any(unix, windows)))]
fn bounded_input_metadata_unchanged(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}
fn load_envelope(path: &Path) -> Result<TaikaiSegmentEnvelopeV1, Box<dyn std::error::Error>> {
    let bytes = read_bounded_regular_file(
        path,
        "Taikai segment envelope",
        TAIKAI_VIEWER_ENVELOPE_MAX_BYTES,
    )?;
    let envelope: TaikaiSegmentEnvelopeV1 = decode_from_bytes(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    if envelope.version != TaikaiSegmentEnvelopeV1::VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported Taikai segment envelope version {} (expected {})",
                envelope.version,
                TaikaiSegmentEnvelopeV1::VERSION
            ),
        )
        .into());
    }
    validate_envelope(&envelope)?;
    Ok(envelope)
}
fn validate_envelope(envelope: &TaikaiSegmentEnvelopeV1) -> io::Result<()> {
    validate_track_metadata(&envelope.track).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Taikai track metadata: {err}"),
        )
    })?;
    let duration = envelope.segment_duration.as_micros();
    if duration == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Taikai segment duration must be greater than zero",
        ));
    }
    envelope
        .segment_start_pts
        .as_micros()
        .checked_add(u64::from(duration))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Taikai segment presentation interval overflows u64",
            )
        })?;
    Ok(())
}
fn validate_car(
    envelope: &TaikaiSegmentEnvelopeV1,
    car_bytes: &[u8],
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let verified = verify_taikai_car(car_bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CAR canonical verification failed for {}: {err}",
                path.display()
            ),
        )
    })?;
    if verified.car_pointer.car_digest != envelope.ingest.car.car_digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CAR digest mismatch for {} (expected {}, got {})",
                path.display(),
                hex::encode(envelope.ingest.car.car_digest.as_bytes()),
                hex::encode(verified.car_pointer.car_digest.as_bytes())
            ),
        )
        .into());
    }
    if verified.car_pointer.car_size_bytes != envelope.ingest.car.car_size_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CAR size mismatch for {} (expected {} bytes, got {} bytes)",
                path.display(),
                envelope.ingest.car.car_size_bytes,
                verified.car_pointer.car_size_bytes
            ),
        )
        .into());
    }
    if verified.car_pointer.cid_multibase != envelope.ingest.car.cid_multibase {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CAR CID mismatch for {} (expected {}, got {})",
                path.display(),
                envelope.ingest.car.cid_multibase,
                verified.car_pointer.cid_multibase
            ),
        )
        .into());
    }
    if verified.chunk_root != envelope.ingest.chunk_root {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CAR chunk root mismatch for {} (expected {}, got {})",
                path.display(),
                hex::encode(envelope.ingest.chunk_root.as_bytes()),
                hex::encode(verified.chunk_root.as_bytes())
            ),
        )
        .into());
    }
    if verified.chunk_count != envelope.ingest.chunk_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CAR chunk count mismatch for {} (expected {}, got {})",
                path.display(),
                envelope.ingest.chunk_count,
                verified.chunk_count
            ),
        )
        .into());
    }
    Ok(())
}
#[derive(Debug)]
struct CekReceiptObservation {
    receipt: CekRotationReceiptV1,
    measured_ms: u32,
    age_seconds: u64,
}
fn read_cek_receipt(path: &Path) -> Result<CekReceiptObservation, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let bytes = read_bounded_regular_file(
        path,
        "CEK rotation receipt",
        TAIKAI_VIEWER_CEK_RECEIPT_MAX_BYTES,
    )?;
    let decode_start = Instant::now();
    let receipt: CekRotationReceiptV1 = decode_from_bytes(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    if receipt.schema_version != CEK_ROTATION_RECEIPT_VERSION_V1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported CEK rotation receipt version {} (expected {})",
                receipt.schema_version, CEK_ROTATION_RECEIPT_VERSION_V1
            ),
        )
        .into());
    }
    validate_cek_receipt(&receipt)?;
    let decode_elapsed = decode_start.elapsed();
    let duration_ms = start.elapsed().as_millis();
    let observed_ms = duration_ms.max(decode_elapsed.as_millis());
    let clamped_ms = observed_ms.min(u128::from(u32::MAX)) as u32;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let age = now.saturating_sub(receipt.issued_at_unix);
    Ok(CekReceiptObservation {
        receipt,
        measured_ms: clamped_ms,
        age_seconds: age,
    })
}
fn validate_cek_receipt(receipt: &CekRotationReceiptV1) -> io::Result<()> {
    receipt
        .validate()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}
fn read_bounded_regular_file(path: &Path, label: &str, max_bytes: usize) -> io::Result<Vec<u8>> {
    read_bounded_regular_file_with_post_read(path, label, max_bytes, || {})
}
fn read_bounded_regular_file_with_post_read(
    path: &Path,
    label: &str,
    max_bytes: usize,
    post_read: impl FnOnce(),
) -> io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to inspect {label} `{}`: {err}", path.display()),
        )
    })?;
    if bounded_input_metadata_is_indirect(&before) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} `{}` must not be a symlink", path.display()),
        ));
    }
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} `{}` must be a regular file", path.display()),
        ));
    }
    let max_bytes_u64 = u64::try_from(max_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} byte limit exceeds the platform file-size representation"),
        )
    })?;
    if before.len() > max_bytes_u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} `{}` is {} bytes; maximum is {max_bytes}",
                path.display(),
                before.len()
            ),
        ));
    }
    let mut file = open_bounded_input(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to open {label} `{}`: {err}", path.display()),
        )
    })?;
    let opened = file.metadata().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to inspect {label} `{}`: {err}", path.display()),
        )
    })?;
    if bounded_input_metadata_is_indirect(&opened) || !opened.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} `{}` must be a regular file", path.display()),
        ));
    }
    let linked_after_open = fs::symlink_metadata(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to re-inspect {label} `{}`: {err}", path.display()),
        )
    })?;
    if bounded_input_metadata_is_indirect(&linked_after_open)
        || !linked_after_open.is_file()
        || !bounded_input_metadata_unchanged(&before, &opened)
        || !bounded_input_metadata_unchanged(&opened, &linked_after_open)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{label} `{}` changed while it was being opened",
                path.display()
            ),
        ));
    }
    let read_limit = max_bytes_u64.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} byte limit cannot be incremented safely"),
        )
    })?;
    let initial_capacity = usize::try_from(opened.len()).unwrap_or(max_bytes);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(initial_capacity).map_err(|err| {
        io::Error::other(format!(
            "failed to reserve {initial_capacity} bytes for {label} `{}`: {err}",
            path.display()
        ))
    })?;
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to read {label} `{}`: {err}", path.display()),
            )
        })?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} `{}` grew beyond the {max_bytes}-byte maximum while being read",
                path.display()
            ),
        ));
    }
    post_read();
    let opened_after_read = file.metadata().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to re-inspect open {label} `{}`: {err}",
                path.display()
            ),
        )
    })?;
    let linked_after_read = fs::symlink_metadata(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to re-inspect {label} `{}`: {err}", path.display()),
        )
    })?;
    if bounded_input_metadata_is_indirect(&linked_after_read)
        || !opened_after_read.is_file()
        || !linked_after_read.is_file()
        || !bounded_input_metadata_unchanged(&opened, &opened_after_read)
        || !bounded_input_metadata_unchanged(&opened_after_read, &linked_after_read)
        || u64::try_from(bytes.len()).ok() != Some(opened.len())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} `{}` changed while it was being read",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}
struct ParsedArgs {
    cluster: String,
    lane: String,
    rebuffer_events: u64,
    pq_health: f64,
    cek_receipt: Option<PathBuf>,
    cek_fetch_ms: Option<u32>,
    metrics_out: Option<PathBuf>,
    summary_out: Option<PathBuf>,
    segments: Vec<SegmentInput>,
    alerts: Vec<String>,
}
fn preflight_output_collisions(args: &ParsedArgs) -> io::Result<()> {
    let mut outputs = Vec::with_capacity(2);
    if let Some(path) = args.metrics_out.as_deref() {
        outputs.push(("metrics output", path));
    }
    if let Some(path) = args.summary_out.as_deref() {
        outputs.push(("summary output", path));
    }

    for (_, output_path) in &outputs {
        validate_output_path(output_path)?;
    }
    for (index, (left_label, left_path)) in outputs.iter().enumerate() {
        for (right_label, right_path) in &outputs[index + 1..] {
            require_distinct_paths(left_label, left_path, right_label, right_path)?;
        }
    }
    for (output_label, output_path) in outputs {
        for segment in &args.segments {
            require_distinct_paths(
                output_label,
                output_path,
                "segment envelope input",
                &segment.envelope,
            )?;
            require_distinct_paths(output_label, output_path, "segment CAR input", &segment.car)?;
        }
        if let Some(cek_receipt) = args.cek_receipt.as_deref() {
            require_distinct_paths(output_label, output_path, "CEK receipt input", cek_receipt)?;
        }
    }
    Ok(())
}
fn require_distinct_paths(
    left_label: &str,
    left_path: &Path,
    right_label: &str,
    right_path: &Path,
) -> io::Result<()> {
    validate_distinct_artifact_paths(&[(left_label, left_path), (right_label, right_path)])
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}
fn parse_args() -> Result<ParsedArgs, Box<dyn std::error::Error>> {
    let mut cluster = String::from("local");
    let mut lane = String::from("lane-a");
    let mut rebuffer_events: u64 = 0;
    let mut pq_health: f64 = 100.0;
    let mut cek_receipt: Option<PathBuf> = None;
    let mut cek_fetch_ms: Option<u32> = None;
    let mut metrics_out: Option<PathBuf> = None;
    let mut summary_out: Option<PathBuf> = None;
    let mut segments = Vec::new();
    let mut alerts = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            flag if flag.starts_with("--segment=") => {
                let value = flag.trim_start_matches("--segment=");
                segments.push(parse_segment(value)?);
            }
            "--segment" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--segment requires envelope=...,car=... value",
                    )
                })?;
                segments.push(parse_segment(&value)?);
            }
            flag if flag.starts_with("--cluster=") => {
                cluster = flag.trim_start_matches("--cluster=").to_string()
            }
            "--cluster" => {
                cluster = args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing cluster")
                })?;
            }
            flag if flag.starts_with("--lane=") => {
                lane = flag.trim_start_matches("--lane=").to_string()
            }
            "--lane" => {
                lane = args
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing lane"))?;
            }
            flag if flag.starts_with("--rebuffer-events=") => {
                rebuffer_events = flag
                    .trim_start_matches("--rebuffer-events=")
                    .parse::<u64>()?
            }
            "--rebuffer-events" => {
                rebuffer_events = args
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "missing value for --rebuffer-events",
                        )
                    })?
                    .parse::<u64>()?;
            }
            flag if flag.starts_with("--pq-health=") => {
                pq_health = parse_pq_health(flag.trim_start_matches("--pq-health="))?;
            }
            "--pq-health" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing --pq-health value")
                })?;
                pq_health = parse_pq_health(&value)?;
            }
            flag if flag.starts_with("--cek-receipt=") => {
                cek_receipt = Some(PathBuf::from(flag.trim_start_matches("--cek-receipt=")));
            }
            "--cek-receipt" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value for --cek-receipt",
                    )
                })?;
                cek_receipt = Some(PathBuf::from(value));
            }
            flag if flag.starts_with("--cek-fetch-ms=") => {
                cek_fetch_ms = Some(flag.trim_start_matches("--cek-fetch-ms=").parse::<u32>()?);
            }
            "--cek-fetch-ms" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing value for --cek-fetch-ms",
                    )
                })?;
                cek_fetch_ms = Some(value.parse::<u32>()?);
            }
            flag if flag.starts_with("--metrics-out=") => {
                metrics_out = Some(PathBuf::from(flag.trim_start_matches("--metrics-out=")));
            }
            "--metrics-out" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing path for --metrics-out",
                    )
                })?;
                metrics_out = Some(PathBuf::from(value));
            }
            flag if flag.starts_with("--summary-out=") => {
                summary_out = Some(PathBuf::from(flag.trim_start_matches("--summary-out=")));
            }
            "--summary-out" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing path for --summary-out",
                    )
                })?;
                summary_out = Some(PathBuf::from(value));
            }
            flag if flag.starts_with("--alert=") => {
                alerts.push(flag.trim_start_matches("--alert=").to_string());
            }
            "--alert" => {
                let value = args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --alert")
                })?;
                alerts.push(value);
            }
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unrecognised argument `{unknown}`\n\n{USAGE}"),
                )
                .into());
            }
        }
    }
    Ok(ParsedArgs {
        cluster,
        lane,
        rebuffer_events,
        pq_health,
        cek_receipt,
        cek_fetch_ms,
        metrics_out,
        summary_out,
        segments,
        alerts,
    })
}
fn parse_pq_health(raw: &str) -> Result<f64, io::Error> {
    let value = raw.parse::<f64>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid --pq-health percentage `{raw}`: {err}"),
        )
    })?;
    if !(0.0..=100.0).contains(&value) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--pq-health percentage must be finite and within 0..=100, got `{raw}`"),
        ));
    }
    Ok(value)
}
fn parse_segment(raw: &str) -> Result<SegmentInput, Box<dyn std::error::Error>> {
    let mut envelope = None;
    let mut car = None;
    for part in raw.split(',') {
        let (component, value) = part.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid segment component `{part}`; expected NAME=PATH"),
            )
        })?;
        if value.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("segment component `{component}` requires a non-empty path"),
            )
            .into());
        }
        match component {
            "envelope" => {
                if envelope.replace(PathBuf::from(value)).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "segment contains duplicate envelope=PATH components",
                    )
                    .into());
                }
            }
            "car" => {
                if car.replace(PathBuf::from(value)).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "segment contains duplicate car=PATH components",
                    )
                    .into());
                }
            }
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown segment component `{unknown}`"),
                )
                .into());
            }
        }
    }
    let envelope = envelope.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "segment missing envelope=PATH component",
        )
    })?;
    let car = car.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "segment missing car=PATH component",
        )
    })?;
    Ok(SegmentInput { envelope, car })
}
#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hash as blake3_hash;
    use iroha_data_model::{
        da::types::{BlobDigest, StorageTicketId},
        taikai::{
            SegmentDuration, SegmentTimestamp, TaikaiCarPointer, TaikaiCodec, TaikaiEventId,
            TaikaiIngestPointer, TaikaiRenditionId, TaikaiResolution, TaikaiStreamId,
            TaikaiTrackMetadata,
        },
    };
    use iroha_model_base::name::Name;
    use sorafs_car::{CarWriter, ingest_single_file};
    use std::str::FromStr;
    use tempfile::{TempDir, tempdir};
    fn canonical_tempdir() -> (TempDir, PathBuf) {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().canonicalize().expect("canonical tempdir");
        (temp, path)
    }
    fn sample_envelope(car_bytes: &[u8]) -> TaikaiSegmentEnvelopeV1 {
        let track = TaikaiTrackMetadata::video(
            TaikaiCodec::AvcHigh,
            8_000,
            TaikaiResolution::new(1_920, 1_080),
        );
        let ingest = TaikaiIngestPointer::new(
            BlobDigest::new([0x11; 32]),
            StorageTicketId::new([0x22; 32]),
            BlobDigest::new([0x33; 32]),
            1,
            TaikaiCarPointer::new(
                "bafy-test-car",
                BlobDigest::new(blake3_hash(car_bytes).into()),
                u64::try_from(car_bytes.len()).expect("fixture length fits in u64"),
            ),
        );
        TaikaiSegmentEnvelopeV1::new(
            TaikaiEventId::new(Name::from_str("soranet-demo").expect("event name")),
            TaikaiStreamId::new(Name::from_str("primary").expect("stream name")),
            TaikaiRenditionId::new(Name::from_str("1080p-main").expect("rendition name")),
            track,
            1,
            SegmentTimestamp::new(0),
            SegmentDuration::new(2_000_000),
            1_726_000_000_000,
            ingest,
        )
    }
    fn canonical_car_fixture(payload: &[u8]) -> (Vec<u8>, TaikaiSegmentEnvelopeV1) {
        let ingest = ingest_single_file(payload).expect("build canonical CAR plan");
        let mut car_bytes = Vec::new();
        CarWriter::new(&ingest.plan, payload)
            .expect("canonical CAR writer")
            .write_to(&mut car_bytes)
            .expect("write canonical CAR");
        let verified = verify_taikai_car(&car_bytes).expect("verify fixture CAR");
        let mut envelope = sample_envelope(&car_bytes);
        envelope.ingest.car = verified.car_pointer;
        envelope.ingest.chunk_root = verified.chunk_root;
        envelope.ingest.chunk_count = verified.chunk_count;
        (car_bytes, envelope)
    }
    fn parsed_args_fixture(temp_path: &Path) -> ParsedArgs {
        ParsedArgs {
            cluster: "local".to_owned(),
            lane: "lane-a".to_owned(),
            rebuffer_events: 0,
            pq_health: 100.0,
            cek_receipt: Some(temp_path.join("rotation.norito")),
            cek_fetch_ms: None,
            metrics_out: None,
            summary_out: None,
            segments: vec![SegmentInput {
                envelope: temp_path.join("segment.norito"),
                car: temp_path.join("segment.car"),
            }],
            alerts: Vec::new(),
        }
    }
    fn sample_cek_receipt() -> CekRotationReceiptV1 {
        CekRotationReceiptV1 {
            schema_version: CEK_ROTATION_RECEIPT_VERSION_V1,
            event_id: TaikaiEventId::new(Name::from_str("soranet-demo").expect("event name")),
            stream_id: TaikaiStreamId::new(Name::from_str("primary").expect("stream name")),
            kms_profile: "test-kms".to_owned(),
            new_wrap_key_label: "wrap-v2".to_owned(),
            previous_wrap_key_label: Some("wrap-v1".to_owned()),
            hkdf_salt: [0x44; 32],
            effective_segment_sequence: 1,
            issued_at_unix: 1_726_000_000,
            notes: None,
        }
    }
    #[test]
    fn parse_segment_rejects_unknown_duplicate_and_empty_components() {
        for (raw, expected) in [
            ("envelope=a,car=b,extra=c", "unknown segment component"),
            ("envelope=a,envelope=b,car=c", "duplicate envelope=PATH"),
            ("envelope=a,car=b,car=c", "duplicate car=PATH"),
            ("envelope=,car=b", "requires a non-empty path"),
            ("envelope=a,car", "expected NAME=PATH"),
        ] {
            let error = parse_segment(raw).expect_err("malformed segment input must be rejected");
            assert!(
                error.to_string().contains(expected),
                "unexpected error for `{raw}`: {error}"
            );
        }
    }
    #[test]
    fn write_output_bytes_creates_parent_and_writes_all_bytes() {
        let (_temp, temp_path) = canonical_tempdir();
        let output_path = temp_path.join("nested").join("metrics.prom");
        write_output_bytes(&output_path, "metrics output", b"metric 1\n").expect("write metrics");
        assert_eq!(fs::read(&output_path).expect("read output"), b"metric 1\n");
    }
    #[cfg(unix)]
    #[test]
    fn write_output_bytes_atomically_replaces_hard_link_without_mutating_alias() {
        let (_temp, temp_path) = canonical_tempdir();
        let alias_path = temp_path.join("existing-alias.prom");
        let output_path = temp_path.join("metrics.prom");
        fs::write(&alias_path, b"old metric\n").expect("write existing alias");
        fs::hard_link(&alias_path, &output_path).expect("hard-link output fixture");

        write_output_bytes(&output_path, "metrics output", b"new metric\n")
            .expect("atomically replace output");

        assert_eq!(
            fs::read(&output_path).expect("read new output"),
            b"new metric\n"
        );
        assert_eq!(
            fs::read(&alias_path).expect("read preserved alias"),
            b"old metric\n",
            "in-place truncation would corrupt every hard-link alias"
        );
    }
    #[cfg(unix)]
    #[test]
    fn publish_staged_outputs_rolls_back_after_second_rename_failure() {
        let (_temp, temp_path) = canonical_tempdir();
        for target_existed in [false, true] {
            let case_dir = temp_path.join(if target_existed { "existing" } else { "new" });
            fs::create_dir(&case_dir).expect("create case directory");
            let metrics_path = case_dir.join("metrics.prom");
            let summary_path = case_dir.join("summary.json");
            if target_existed {
                fs::write(&metrics_path, b"old metrics\n").expect("write old metrics");
            }
            fs::write(&summary_path, b"old summary\n").expect("write old summary");
            let staged = vec![
                StagedOutput::prepare(&metrics_path, "metrics output", b"new metrics\n")
                    .expect("stage metrics"),
                StagedOutput::prepare(&summary_path, "summary output", b"new summary\n")
                    .expect("stage summary"),
            ];

            let error = publish_staged_outputs_with_hook(staged, |index, output| {
                if index == 1 {
                    fs::remove_file(
                        output
                            .temporary_path
                            .as_ref()
                            .expect("second output remains staged"),
                    )?;
                }
                Ok(())
            })
            .expect_err("missing second staged file must fail its rename");
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            if target_existed {
                assert_eq!(
                    fs::read(&metrics_path).expect("read restored metrics"),
                    b"old metrics\n"
                );
            } else {
                assert!(
                    !metrics_path.exists(),
                    "rollback must remove a newly created earlier output"
                );
            }
            assert_eq!(
                fs::read(&summary_path).expect("read untouched summary"),
                b"old summary\n"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn write_output_bytes_rejects_symlink_output() {
        let (_temp, temp_path) = canonical_tempdir();
        let target_path = temp_path.join("target.prom");
        fs::write(&target_path, b"unchanged\n").expect("write target");
        let output_path = temp_path.join("metrics.prom");
        std::os::unix::fs::symlink(&target_path, &output_path).expect("create symlink");
        let err = write_output_bytes(&output_path, "metrics output", b"replace")
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
    fn write_output_bytes_rejects_read_only_output() {
        let (_temp, temp_path) = canonical_tempdir();
        let output_path = temp_path.join("metrics.prom");
        fs::write(&output_path, b"unchanged\n").expect("write output fixture");
        let mut permissions = fs::metadata(&output_path)
            .expect("inspect output fixture")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&output_path, permissions).expect("make output read-only");

        let error = write_output_bytes(&output_path, "metrics output", b"replacement")
            .expect_err("read-only output must be rejected");
        assert!(
            error.to_string().contains("must be writable"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(&output_path).expect("read preserved output"),
            b"unchanged\n"
        );
    }
    #[cfg(unix)]
    #[test]
    fn write_output_bytes_rejects_symlink_parent() {
        let (_temp, temp_path) = canonical_tempdir();
        let real_dir = temp_path.join("real");
        fs::create_dir(&real_dir).expect("create real dir");
        let linked_dir = temp_path.join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).expect("create symlink");
        let output_path = linked_dir.join("summary.json");
        let err = write_output_bytes(&output_path, "summary output", b"replace")
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
    #[cfg(unix)]
    #[test]
    fn write_output_bytes_rejects_unix_socket_output() {
        let (_temp, temp_path) = canonical_tempdir();
        let output_path = temp_path.join("metrics.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&output_path).expect("bind fixture Unix socket");
        let err = write_output_bytes(&output_path, "metrics output", b"replace")
            .expect_err("reject Unix socket output");
        let message = err.to_string();
        assert!(
            message.contains("must be a regular file"),
            "unexpected error: {message}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn run_preflights_bad_summary_before_writing_metrics() {
        let (_temp, temp_path) = canonical_tempdir();
        let mut args = parsed_args_fixture(&temp_path);
        let metrics_path = temp_path.join("metrics.prom");
        let summary_path = temp_path.join("summary.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&summary_path).expect("bind summary socket");
        args.metrics_out = Some(metrics_path.clone());
        args.summary_out = Some(summary_path);

        let error = run_with_args(args).expect_err("bad summary output must fail preflight");
        assert!(
            error.to_string().contains("must be a regular file"),
            "unexpected error: {error}"
        );
        assert!(
            !metrics_path.exists(),
            "metrics must not be written before all outputs pass preflight"
        );
    }
    #[cfg(unix)]
    #[test]
    fn run_stages_every_output_before_publishing_metrics() {
        let (_temp, temp_path) = canonical_tempdir();
        let (car_bytes, envelope) = canonical_car_fixture(b"viewer staging payload");
        let envelope_path = temp_path.join("segment.norito");
        let car_path = temp_path.join("segment.car");
        fs::write(
            &envelope_path,
            norito::to_bytes(&envelope).expect("encode envelope"),
        )
        .expect("write envelope");
        fs::write(&car_path, car_bytes).expect("write CAR");

        let metrics_path = temp_path.join("metrics.prom");
        fs::write(&metrics_path, b"preserve existing metrics\n").expect("write old metrics");
        // The target itself fits the common Unix NAME_MAX, but its hidden temporary name does
        // not. This forces a deterministic failure only after the metrics file has been staged.
        let summary_path = temp_path.join("s".repeat(255));
        let mut args = parsed_args_fixture(&temp_path);
        args.cek_receipt = None;
        args.metrics_out = Some(metrics_path.clone());
        args.summary_out = Some(summary_path.clone());

        run_with_args(args).expect_err("second output staging must fail");
        assert_eq!(
            fs::read(&metrics_path).expect("read preserved metrics"),
            b"preserve existing metrics\n",
            "no output may be published until every target is staged"
        );
        assert!(!summary_path.exists());
        let leaked_metrics_temp = fs::read_dir(&temp_path)
            .expect("read tempdir")
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".metrics.prom.tmp-")
            });
        assert!(
            !leaked_metrics_temp,
            "failed staging must clean prior temps"
        );
    }
    #[test]
    fn output_preflight_rejects_normalized_output_aliases() {
        let (_temp, temp_path) = canonical_tempdir();
        let mut args = parsed_args_fixture(&temp_path);
        args.metrics_out = Some(temp_path.join("viewer.out"));
        args.summary_out = Some(temp_path.join("nested").join("..").join("viewer.out"));

        let error = preflight_output_collisions(&args)
            .expect_err("normalized metrics and summary aliases must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let message = error.to_string();
        assert!(
            message.contains("metrics output")
                && message.contains("summary output")
                && message.contains("must use distinct paths"),
            "unexpected error: {message}"
        );
    }
    #[test]
    fn output_preflight_rejects_every_input_path() {
        let (_temp, temp_path) = canonical_tempdir();
        let mut args = parsed_args_fixture(&temp_path);
        let collisions = [
            ("segment envelope input", args.segments[0].envelope.clone()),
            ("segment CAR input", args.segments[0].car.clone()),
            (
                "CEK receipt input",
                args.cek_receipt.clone().expect("fixture CEK receipt"),
            ),
        ];
        for (input_label, input_path) in collisions {
            args.metrics_out = Some(input_path);
            let error = preflight_output_collisions(&args)
                .expect_err("output collision with an input must be rejected");
            let message = error.to_string();
            assert!(
                message.contains("metrics output") && message.contains(input_label),
                "unexpected error: {message}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn run_rejects_hard_link_output_alias_before_writing() {
        let (_temp, temp_path) = canonical_tempdir();
        let mut args = parsed_args_fixture(&temp_path);
        let input_path = args.segments[0].envelope.clone();
        fs::write(&input_path, b"preserve envelope input").expect("write envelope input");
        let output_alias = temp_path.join("metrics.prom");
        fs::hard_link(&input_path, &output_alias).expect("create hard-link output alias");
        args.metrics_out = Some(output_alias.clone());

        let error = run_with_args(args).expect_err("hard-link input alias must be rejected");
        assert!(
            error.to_string().contains("must use distinct paths"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(&input_path).expect("read preserved input"),
            b"preserve envelope input"
        );
        assert_eq!(
            fs::read(&output_alias).expect("read preserved alias"),
            b"preserve envelope input"
        );
    }
    #[test]
    fn load_envelope_rejects_unsupported_version() {
        let (_temp, temp_path) = canonical_tempdir();
        let mut envelope = sample_envelope(b"car");
        envelope.version = TaikaiSegmentEnvelopeV1::VERSION + 1;
        let path = temp_path.join("unsupported-envelope.norito");
        fs::write(&path, norito::to_bytes(&envelope).expect("encode envelope"))
            .expect("write envelope");
        let error = load_envelope(&path).expect_err("unsupported envelope must be rejected");
        assert!(
            error
                .to_string()
                .contains("unsupported Taikai segment envelope version"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn load_envelope_rejects_oversized_file_before_decode() {
        let (_temp, temp_path) = canonical_tempdir();
        let path = temp_path.join("oversized-envelope.norito");
        let file = fs::File::create(&path).expect("create sparse envelope");
        file.set_len(u64::try_from(TAIKAI_VIEWER_ENVELOPE_MAX_BYTES + 1).expect("limit fits u64"))
            .expect("size sparse envelope");

        let error = load_envelope(&path).expect_err("oversized envelope must be rejected");

        assert!(
            error.to_string().contains("maximum is 262144"),
            "unexpected error: {error}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn bounded_input_rejects_symlinks() {
        let (_temp, temp_path) = canonical_tempdir();
        let target = temp_path.join("target.car");
        fs::write(&target, b"car").expect("write target");
        let link = temp_path.join("linked.car");
        std::os::unix::fs::symlink(&target, &link).expect("create input symlink");

        let error = read_bounded_regular_file(&link, "Taikai CAR", 16)
            .expect_err("input symlink must be rejected");

        assert!(
            error.to_string().contains("must not be a symlink"),
            "unexpected error: {error}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn bounded_input_rejects_fifo_without_opening_it() {
        let (_temp, temp_path) = canonical_tempdir();
        let fifo = temp_path.join("segment.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo must create the test input");

        let error = read_bounded_regular_file(&fifo, "Taikai CAR", 16)
            .expect_err("FIFO input must be rejected without waiting for a writer");

        assert!(
            error.to_string().contains("must be a regular file"),
            "unexpected error: {error}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn bounded_input_rejects_in_place_size_change_during_read() {
        let (_temp, temp_path) = canonical_tempdir();
        let path = temp_path.join("changing.car");
        fs::write(&path, b"original").expect("write original input");

        let error = read_bounded_regular_file_with_post_read(&path, "Taikai CAR", 32, || {
            fs::write(&path, b"x").expect("shrink input after read");
        })
        .expect_err("an in-place size change must invalidate the read");

        assert!(
            error
                .to_string()
                .contains("changed while it was being read"),
            "unexpected error: {error}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn bounded_input_rejects_same_length_content_change_during_read() {
        let (_temp, temp_path) = canonical_tempdir();
        let path = temp_path.join("mutating.car");
        fs::write(&path, b"original").expect("write original input");
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open original input");
        file.set_times(
            fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1)),
        )
        .expect("set stable old modification time");
        drop(file);

        let error = read_bounded_regular_file_with_post_read(&path, "Taikai CAR", 32, || {
            fs::write(&path, b"mutated!").expect("mutate input without changing its length");
        })
        .expect_err("a same-length in-place mutation must invalidate the read");

        assert!(
            error
                .to_string()
                .contains("changed while it was being read"),
            "unexpected error: {error}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn bounded_input_rejects_same_length_path_replacement_during_read() {
        let (_temp, temp_path) = canonical_tempdir();
        let path = temp_path.join("replaced.car");
        let moved = temp_path.join("original.car");
        fs::write(&path, b"original").expect("write original input");

        let error = read_bounded_regular_file_with_post_read(&path, "Taikai CAR", 32, || {
            fs::rename(&path, &moved).expect("move original input");
            fs::write(&path, b"replaced").expect("publish same-length replacement");
        })
        .expect_err("a same-length path replacement must invalidate the read");

        assert!(
            error
                .to_string()
                .contains("changed while it was being read"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn load_envelope_rejects_semantically_invalid_metadata() {
        let (_temp, temp_path) = canonical_tempdir();
        let mut envelope = sample_envelope(b"car");
        envelope.segment_duration = SegmentDuration::new(0);
        let path = temp_path.join("zero-duration-envelope.norito");
        fs::write(&path, norito::to_bytes(&envelope).expect("encode envelope"))
            .expect("write envelope");
        let error = load_envelope(&path).expect_err("zero-duration envelope must be rejected");
        assert!(
            error
                .to_string()
                .contains("duration must be greater than zero"),
            "unexpected error: {error}"
        );

        envelope.segment_duration = SegmentDuration::new(1);
        envelope.track.average_bitrate_kbps = 0;
        fs::write(&path, norito::to_bytes(&envelope).expect("encode envelope"))
            .expect("write envelope");
        let error = load_envelope(&path).expect_err("zero-bitrate envelope must be rejected");
        assert!(
            error
                .to_string()
                .contains("bitrate must be greater than zero"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn read_cek_receipt_rejects_unsupported_version() {
        let (_temp, temp_path) = canonical_tempdir();
        let mut receipt = sample_cek_receipt();
        receipt.schema_version = CEK_ROTATION_RECEIPT_VERSION_V1 + 1;
        let path = temp_path.join("unsupported-cek-receipt.norito");
        fs::write(&path, norito::to_bytes(&receipt).expect("encode receipt"))
            .expect("write receipt");
        let error = read_cek_receipt(&path).expect_err("unsupported receipt must be rejected");
        assert!(
            error
                .to_string()
                .contains("unsupported CEK rotation receipt version"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn read_cek_receipt_rejects_oversized_file_before_decode() {
        let (_temp, temp_path) = canonical_tempdir();
        let path = temp_path.join("oversized-cek-receipt.norito");
        let file = fs::File::create(&path).expect("create sparse CEK receipt");
        file.set_len(
            u64::try_from(TAIKAI_VIEWER_CEK_RECEIPT_MAX_BYTES + 1).expect("limit fits u64"),
        )
        .expect("size sparse CEK receipt");

        let error = read_cek_receipt(&path).expect_err("oversized CEK receipt must be rejected");

        assert!(
            error.to_string().contains("maximum is 262144"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn read_cek_receipt_rejects_malformed_fields() {
        let (_temp, temp_path) = canonical_tempdir();
        let path = temp_path.join("malformed-cek-receipt.norito");
        let mut receipt = sample_cek_receipt();
        receipt.new_wrap_key_label = " ".to_owned();
        fs::write(&path, norito::to_bytes(&receipt).expect("encode receipt"))
            .expect("write receipt");
        let error = read_cek_receipt(&path).expect_err("blank wrap-key label must be rejected");
        assert!(error.to_string().contains("new_wrap_key_label"));

        receipt.new_wrap_key_label = "wrap-v2".to_owned();
        receipt.hkdf_salt = [0; 32];
        fs::write(&path, norito::to_bytes(&receipt).expect("encode receipt"))
            .expect("write receipt");
        let error = read_cek_receipt(&path).expect_err("zero HKDF salt must be rejected");
        assert!(error.to_string().contains("HKDF salt"));
    }
    #[test]
    fn run_rejects_cek_receipt_for_unviewed_stream() {
        let (_temp, temp_path) = canonical_tempdir();
        let (car_bytes, envelope) = canonical_car_fixture(b"canonical viewer payload");
        let envelope_path = temp_path.join("segment.norito");
        let car_path = temp_path.join("segment.car");
        let receipt_path = temp_path.join("rotation.norito");
        fs::write(
            &envelope_path,
            norito::to_bytes(&envelope).expect("encode envelope"),
        )
        .expect("write envelope");
        fs::write(&car_path, car_bytes).expect("write CAR");
        let mut receipt = sample_cek_receipt();
        receipt.event_id =
            TaikaiEventId::new(Name::from_str("different-event").expect("event name"));
        fs::write(
            &receipt_path,
            norito::to_bytes(&receipt).expect("encode receipt"),
        )
        .expect("write receipt");
        let args = parsed_args_fixture(&temp_path);

        let error = run_with_args(args).expect_err("unrelated CEK receipt must be rejected");
        assert!(
            error
                .to_string()
                .contains("absent from the viewed segments"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn run_rejects_duplicate_segment_identity() {
        let (_temp, temp_path) = canonical_tempdir();
        let (first_car, first_envelope) = canonical_car_fixture(b"first duplicate payload");
        let (second_car, second_envelope) = canonical_car_fixture(b"second duplicate payload");
        let first_envelope_path = temp_path.join("first.norito");
        let first_car_path = temp_path.join("first.car");
        let second_envelope_path = temp_path.join("second.norito");
        let second_car_path = temp_path.join("second.car");
        fs::write(
            &first_envelope_path,
            norito::to_bytes(&first_envelope).expect("encode first envelope"),
        )
        .expect("write first envelope");
        fs::write(&first_car_path, first_car).expect("write first CAR");
        fs::write(
            &second_envelope_path,
            norito::to_bytes(&second_envelope).expect("encode second envelope"),
        )
        .expect("write second envelope");
        fs::write(&second_car_path, second_car).expect("write second CAR");
        let metrics_path = temp_path.join("metrics.prom");
        let mut args = parsed_args_fixture(&temp_path);
        args.cek_receipt = None;
        args.metrics_out = Some(metrics_path.clone());
        args.segments = vec![
            SegmentInput {
                envelope: first_envelope_path,
                car: first_car_path,
            },
            SegmentInput {
                envelope: second_envelope_path,
                car: second_car_path,
            },
        ];

        let error = run_with_args(args).expect_err("duplicate identity must be rejected");

        assert!(
            error
                .to_string()
                .contains("duplicate Taikai segment identity"),
            "unexpected error: {error}"
        );
        assert!(
            !metrics_path.exists(),
            "invalid input must fail before publishing metrics"
        );
    }
    #[test]
    fn run_rejects_oversized_car_before_verification() {
        let (_temp, temp_path) = canonical_tempdir();
        let envelope = sample_envelope(b"unused CAR bytes");
        let envelope_path = temp_path.join("segment.norito");
        fs::write(
            &envelope_path,
            norito::to_bytes(&envelope).expect("encode envelope"),
        )
        .expect("write envelope");
        let car_path = temp_path.join("oversized.car");
        let file = fs::File::create(&car_path).expect("create sparse CAR");
        file.set_len(u64::try_from(TAIKAI_VIEWER_CAR_MAX_BYTES + 1).expect("limit fits u64"))
            .expect("size sparse CAR");
        let mut args = parsed_args_fixture(&temp_path);
        args.cek_receipt = None;
        args.segments = vec![SegmentInput {
            envelope: envelope_path,
            car: car_path,
        }];

        let error = run_with_args(args).expect_err("oversized CAR must be rejected");

        assert!(
            error.to_string().contains("maximum is 67108864"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn run_scopes_colliding_stream_names_by_event_in_metrics() {
        let (_temp, temp_path) = canonical_tempdir();
        let (first_car, first_envelope) = canonical_car_fixture(b"first event payload");
        let (second_car, mut second_envelope) = canonical_car_fixture(b"second event payload");
        second_envelope.event_id =
            TaikaiEventId::new(Name::from_str("second-event").expect("event name"));
        let first_envelope_path = temp_path.join("first.norito");
        let first_car_path = temp_path.join("first.car");
        let second_envelope_path = temp_path.join("second.norito");
        let second_car_path = temp_path.join("second.car");
        fs::write(
            &first_envelope_path,
            norito::to_bytes(&first_envelope).expect("encode first envelope"),
        )
        .expect("write first envelope");
        fs::write(&first_car_path, first_car).expect("write first CAR");
        fs::write(
            &second_envelope_path,
            norito::to_bytes(&second_envelope).expect("encode second envelope"),
        )
        .expect("write second envelope");
        fs::write(&second_car_path, second_car).expect("write second CAR");
        let metrics_path = temp_path.join("metrics.prom");
        let mut args = parsed_args_fixture(&temp_path);
        args.cek_receipt = None;
        args.rebuffer_events = 3;
        args.metrics_out = Some(metrics_path.clone());
        args.segments = vec![
            SegmentInput {
                envelope: first_envelope_path,
                car: first_car_path,
            },
            SegmentInput {
                envelope: second_envelope_path,
                car: second_car_path,
            },
        ];

        run_with_args(args).expect("colliding stream names are scoped by event");

        let metrics = fs::read_to_string(metrics_path).expect("read metrics");
        assert!(
            metrics.contains("stream=\"soranet-demo@primary\"} 1"),
            "first event stream missing: {metrics}"
        );
        assert!(
            metrics.contains("stream=\"second-event@primary\"} 1"),
            "second event stream missing: {metrics}"
        );
        assert!(
            metrics.contains("stream=\"soranet-demo@primary\"} 3"),
            "rebuffer count must target the first event-scoped stream: {metrics}"
        );
        assert!(
            !metrics.contains("stream=\"primary\"}"),
            "ambiguous unscoped stream label must not be emitted: {metrics}"
        );
    }
    #[test]
    fn pq_health_requires_finite_percentage() {
        assert_eq!(parse_pq_health("0").expect("lower bound"), 0.0);
        assert_eq!(parse_pq_health("100").expect("upper bound"), 100.0);
        for invalid in ["NaN", "inf", "-0.1", "100.1"] {
            let error = parse_pq_health(invalid).expect_err("invalid percentage");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }
    #[test]
    fn validate_car_rejects_noncanonical_bytes_with_matching_outer_commitments() {
        let car_bytes = b"not a canonical CARv2 archive";
        let envelope = sample_envelope(car_bytes);
        let error = validate_car(&envelope, car_bytes, Path::new("noncanonical.car"))
            .expect_err("noncanonical archive must be rejected");
        assert!(
            error.to_string().contains("canonical verification failed"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn validate_car_matches_every_envelope_commitment() {
        let (car_bytes, envelope) = canonical_car_fixture(b"canonical Taikai viewer payload");
        let path = Path::new("canonical.car");
        validate_car(&envelope, &car_bytes, path).expect("canonical commitments match");

        let mut wrong_digest = envelope.clone();
        wrong_digest.ingest.car.car_digest = BlobDigest::new([0xAA; 32]);
        let error = validate_car(&wrong_digest, &car_bytes, path).expect_err("digest mismatch");
        assert!(error.to_string().contains("CAR digest mismatch"));

        let mut wrong_size = envelope.clone();
        wrong_size.ingest.car.car_size_bytes = wrong_size
            .ingest
            .car
            .car_size_bytes
            .checked_add(1)
            .expect("fixture CAR size can increment");
        let error = validate_car(&wrong_size, &car_bytes, path).expect_err("size mismatch");
        assert!(error.to_string().contains("CAR size mismatch"));

        let mut wrong_cid = envelope.clone();
        wrong_cid.ingest.car.cid_multibase = "binvalid".to_owned();
        let error = validate_car(&wrong_cid, &car_bytes, path).expect_err("CID mismatch");
        assert!(error.to_string().contains("CAR CID mismatch"));

        let mut wrong_root = envelope.clone();
        wrong_root.ingest.chunk_root = BlobDigest::new([0xBB; 32]);
        let error = validate_car(&wrong_root, &car_bytes, path).expect_err("chunk root mismatch");
        assert!(error.to_string().contains("CAR chunk root mismatch"));

        let mut wrong_count = envelope;
        wrong_count.ingest.chunk_count = wrong_count
            .ingest
            .chunk_count
            .checked_add(1)
            .expect("fixture chunk count can increment");
        let error = validate_car(&wrong_count, &car_bytes, path).expect_err("chunk count mismatch");
        assert!(error.to_string().contains("CAR chunk count mismatch"));
    }
}
