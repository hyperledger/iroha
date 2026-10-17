//! Render current explicitly identified FASTPQ native primitive captures.
#![allow(unexpected_cfgs)]
#[path = "../digest384_report.rs"]
mod digest384_report;
use anyhow::{Context, Result, anyhow};
use clap::Parser;
use norito::json::{self, Value};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};
const TARGET_GPU_MS: f64 = 900.0;
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Summarize FASTPQ Metal benchmark captures for stage-by-stage profiling"
)]
struct Cli {
    /// Benchmark JSON path(s) emitted by `fastpq_metal_bench`.
    #[arg(value_name = "PATH", required = true)]
    inputs: Vec<PathBuf>,
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut writer = io::BufWriter::new(io::stdout());
    for (index, path) in cli.inputs.iter().enumerate() {
        let body = fs::read_to_string(path)
            .with_context(|| format!("read benchmark JSON {}", path.display()))?;
        let value: Value =
            json::from_str(&body).with_context(|| format!("parse {}", path.display()))?;
        let summary = ProfileSummary::from_value(path.to_string_lossy().into_owned(), &value)?;
        if index > 0 {
            writeln!(&mut writer)?;
        }
        summary.render_markdown(&mut writer)?;
    }
    writer.flush()?;
    Ok(())
}
#[derive(Clone, Debug)]
struct ProfileSummary {
    validated_report: Value,
    label: String,
    rows: Option<u64>,
    padded_rows: Option<u64>,
    column_count: Option<u64>,
    trace_log2: Option<u64>,
    lde_log2: Option<u64>,
    execution_mode: Option<String>,
    backend: Option<String>,
    operations: Vec<OperationProfile>,
    queue: Option<QueueProfile>,
    column_staging: Option<ColumnStagingSummary>,
}
impl ProfileSummary {
    fn from_value(label: String, root: &Value) -> Result<Self> {
        let report = digest384_report::report_from_root(root).map_err(|error| anyhow!(error))?;
        let object = report
            .as_object()
            .ok_or_else(|| anyhow!("benchmark JSON must be an object"))?;
        let rows = as_u64(object.get("rows"));
        let padded_rows = as_u64(object.get("padded_rows"));
        let column_count = as_u64(object.get("column_count"));
        let trace_log2 = as_u64(object.get("trace_log2"));
        let lde_log2 = as_u64(object.get("lde_log2"));
        let execution_mode = as_string(object.get("execution_mode")).map(str::to_owned);
        let backend = as_string(object.get("gpu_backend")).map(str::to_owned);
        let operations = object
            .get("operations")
            .and_then(Value::as_array)
            .map(|ops| {
                ops.iter()
                    .filter_map(OperationProfile::from_value)
                    .collect()
            })
            .unwrap_or_default();
        let queue = object
            .get("metal_dispatch_queue")
            .and_then(QueueProfile::from_value);
        let column_staging = object
            .get("column_staging")
            .and_then(ColumnStagingSummary::from_value);
        Ok(Self {
            validated_report: root.clone(),
            label,
            rows,
            padded_rows,
            column_count,
            trace_log2,
            lde_log2,
            execution_mode,
            backend,
            operations,
            queue,
            column_staging,
        })
    }
    fn total_gpu_ms(&self) -> f64 {
        self.operations.iter().filter_map(|op| op.gpu.mean_ms).sum()
    }
    fn total_cpu_ms(&self) -> f64 {
        self.operations.iter().filter_map(|op| op.cpu.mean_ms).sum()
    }
    fn render_markdown<W: Write>(&self, writer: &mut W) -> Result<()> {
        writeln!(writer, "### {}", self.label)?;
        if let Some(rows) = self.rows {
            if let Some(padded) = self.padded_rows {
                writeln!(
                    writer,
                    "- rows: {rows} (padded {padded})  ",
                    rows = rows,
                    padded = padded
                )?;
            } else {
                writeln!(writer, "- rows: {}  ", rows)?;
            }
        }
        if let Some(columns) = self.column_count {
            let trace = self
                .trace_log2
                .map(|log| format!("trace_log2={log} "))
                .unwrap_or_default();
            let lde = self
                .lde_log2
                .map(|log| format!("lde_log2={log} "))
                .unwrap_or_default();
            writeln!(writer, "- columns: {} {}{}", columns, trace, lde)?;
        }
        if let Some(mode) = self.execution_mode.as_deref() {
            let backend = self.backend.as_deref().unwrap_or("unknown");
            writeln!(writer, "- execution: {} (backend: {})  ", mode, backend)?;
        }
        let gpu_total = self.total_gpu_ms();
        let cpu_total = self.total_cpu_ms();
        if gpu_total > 0.0 {
            let gap = gpu_total - TARGET_GPU_MS;
            writeln!(
                writer,
                "- GPU mean total: {:.3} ms ({:+.3} ms vs 900 ms target)  ",
                gpu_total, gap
            )?;
        } else {
            writeln!(writer, "- GPU mean total: (missing data)  ")?;
        }
        if cpu_total > 0.0 {
            writeln!(writer, "- CPU mean total: {:.3} ms  ", cpu_total)?;
        }
        writeln!(
            writer,
            "\n| Stage | Columns | Input len | GPU mean (ms) | CPU mean (ms) | GPU share | Speedup | Δ CPU (ms) |"
        )?;
        writeln!(
            writer,
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        )?;
        for op in &self.operations {
            if op.cpu.mean_ms.is_none() && op.gpu.mean_ms.is_none() {
                continue;
            }
            let share = if gpu_total > 0.0 {
                op.gpu.mean_ms.map(|ms| ms / gpu_total * 100.0)
            } else {
                None
            };
            writeln!(
                writer,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                op.name,
                format_u64(op.columns),
                format_u64(op.input_len),
                format_timing(&op.gpu),
                format_timing(&op.cpu),
                format_pct(share),
                format_ratio(op.speedup_ratio),
                format_delta(op.delta_ms)
            )?;
        }
        if let Some(op) = self.operations.iter().find(|op| op.zero_fill.is_some())
            && let Some(zero_fill) = &op.zero_fill
        {
            writeln!(
                writer,
                "\n- Zero-fill: {} bytes, mean {} ms ({} stage)",
                zero_fill
                    .bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "-".to_owned()),
                format_ms(zero_fill.timings.mean_ms),
                op.name
            )?;
        }
        match &self.queue {
            Some(queue) => {
                if queue.dispatch_count.unwrap_or(0) == 0 {
                    writeln!(
                        writer,
                        "\n- Queue telemetry: dispatch_count=0 (no GPU occupancy sample recorded)."
                    )?;
                } else {
                    writeln!(
                        writer,
                        "\n- Queue telemetry: limit={} dispatches={} busy={} ms ({} busy) max_in_flight={} overlap={} ms ({} overlap) window={} ms.",
                        format_u32(queue.limit),
                        format_u32(queue.dispatch_count),
                        format_ms(queue.busy_ms),
                        format_pct(queue.busy_ratio.map(|ratio| ratio * 100.0)),
                        format_u32(queue.max_in_flight),
                        format_ms(queue.overlap_ms),
                        format_pct(queue.overlap_ratio.map(|ratio| ratio * 100.0)),
                        format_ms(queue.window_ms),
                    )?;
                    if !queue.lanes.is_empty() {
                        for lane in &queue.lanes {
                            writeln!(
                                writer,
                                "  - Queue {}: dispatches={} max_in_flight={} busy={} ms ({} busy) overlap={} ms ({} overlap)",
                                format_u32(lane.index),
                                format_u32(lane.dispatch_count),
                                format_u32(lane.max_in_flight),
                                format_ms(lane.busy_ms),
                                format_pct(lane.busy_ratio.map(|ratio| ratio * 100.0)),
                                format_ms(lane.overlap_ms),
                                format_pct(lane.overlap_ratio.map(|ratio| ratio * 100.0)),
                            )?;
                        }
                    }
                }
            }
            None => {
                writeln!(writer, "\n- Queue telemetry: not captured.")?;
            }
        }
        if let Some(staging) = &self.column_staging {
            writeln!(
                writer,
                "- Column staging: batches={} flatten={} ms wait={} ms (wait ratio {}).",
                format_u64(staging.batches),
                format_ms(staging.flatten_ms),
                format_ms(staging.wait_ms),
                staging
                    .wait_ratio
                    .map(|ratio| format!("{:.3}", ratio))
                    .unwrap_or_else(|| "-".to_owned())
            )?;
        }
        for operation in &self.operations {
            if let Some(evidence) = &operation.digest384 {
                writeln!(
                    writer,
                    "- {}: {} complete six-lane frames per invocation, {} canonical words, {} output bytes.",
                    operation.name,
                    format_u64(as_u64(evidence.get("frame_count"))),
                    format_u64(as_u64(evidence.get("canonical_words"))),
                    format_u64(as_u64(evidence.get("output_bytes")))
                )?;
                if let Some(gpu) = evidence.get("gpu") {
                    writeln!(
                        writer,
                        "  - {} successful payload dispatches; {} digests and {} canonical lanes checked, including warmups.",
                        format_u64(as_u64(gpu.get("dispatches"))),
                        format_u64(as_u64(gpu.get("parity_checked_digests"))),
                        format_u64(as_u64(gpu.get("parity_checked_lanes")))
                    )?;
                }
            }
        }
        writeln!(
            writer,
            "\nValidated primitive report (consistency only; no device provenance or proof qualification):\n\n```json"
        )?;
        writeln!(writer, "{}", json::to_json_pretty(&self.validated_report)?)?;
        writeln!(writer, "```")?;
        Ok(())
    }
}
#[derive(Clone, Debug)]
struct OperationProfile {
    name: String,
    columns: Option<u64>,
    input_len: Option<u64>,
    cpu: StageTimings,
    gpu: StageTimings,
    speedup_ratio: Option<f64>,
    delta_ms: Option<f64>,
    zero_fill: Option<ZeroFillStats>,
    digest384: Option<Value>,
}
impl OperationProfile {
    fn from_value(value: &Value) -> Option<Self> {
        let name = as_string(value.get("operation"))?.to_owned();
        let columns = as_u64(value.get("columns"));
        let input_len = as_u64(value.get("input_len"));
        let cpu = StageTimings::from_value(value.get("cpu"));
        let gpu = StageTimings::from_value(value.get("gpu"));
        let speedup_ratio = value
            .get("speedup")
            .and_then(|obj| as_f64(obj.get("ratio")));
        let delta_ms = value
            .get("speedup")
            .and_then(|obj| as_f64(obj.get("delta_ms")));
        let zero_fill = value.get("zero_fill").and_then(ZeroFillStats::from_value);
        Some(Self {
            name,
            columns,
            input_len,
            cpu,
            gpu,
            speedup_ratio,
            delta_ms,
            zero_fill,
            digest384: value.get("digest384").cloned(),
        })
    }
}
#[derive(Clone, Copy, Debug, Default)]
struct StageTimings {
    min_ms: Option<f64>,
    mean_ms: Option<f64>,
    max_ms: Option<f64>,
}
impl StageTimings {
    fn from_value(value: Option<&Value>) -> Self {
        let Some(obj) = value.and_then(Value::as_object) else {
            return Self::default();
        };
        Self {
            min_ms: as_f64(obj.get("min_ms")),
            mean_ms: as_f64(obj.get("mean_ms")),
            max_ms: as_f64(obj.get("max_ms")),
        }
    }
    fn summary_string(&self) -> Option<String> {
        self.mean_ms.map(|mean| match (self.min_ms, self.max_ms) {
            (Some(min), Some(max))
                if (min - mean).abs() > f64::EPSILON || (max - mean).abs() > f64::EPSILON =>
            {
                format!("{mean:.3} ({min:.3}-{max:.3})")
            }
            _ => format!("{mean:.3}"),
        })
    }
}
#[derive(Clone, Debug)]
struct ZeroFillStats {
    bytes: Option<u64>,
    timings: StageTimings,
}
impl ZeroFillStats {
    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        Some(Self {
            bytes: as_u64(object.get("bytes")),
            timings: StageTimings::from_value(object.get("ms")),
        })
    }
}
#[derive(Clone, Debug)]
struct QueueProfile {
    limit: Option<u32>,
    dispatch_count: Option<u32>,
    max_in_flight: Option<u32>,
    busy_ms: Option<f64>,
    busy_ratio: Option<f64>,
    overlap_ms: Option<f64>,
    overlap_ratio: Option<f64>,
    window_ms: Option<f64>,
    lanes: Vec<QueueLaneProfile>,
}
impl QueueProfile {
    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let busy_ms = as_f64(object.get("busy_ms"));
        let overlap_ms = as_f64(object.get("overlap_ms"));
        let window_ms = as_f64(object.get("window_ms"));
        let busy_ratio = object
            .get("busy_ratio")
            .and_then(|value| as_f64(Some(value)))
            .or_else(|| match (busy_ms, window_ms) {
                (Some(busy), Some(window)) if window > 0.0 => Some((busy / window).clamp(0.0, 1.0)),
                _ => None,
            });
        let overlap_ratio = object
            .get("overlap_ratio")
            .and_then(|value| as_f64(Some(value)))
            .or_else(|| match (overlap_ms, busy_ms) {
                (Some(overlap), Some(busy)) if busy > 0.0 => Some((overlap / busy).clamp(0.0, 1.0)),
                _ => None,
            });
        let lanes = object
            .get("queues")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|lane| QueueLaneProfile::from_value(lane, window_ms))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            limit: as_u32(object.get("limit")),
            dispatch_count: as_u32(object.get("dispatch_count")),
            max_in_flight: as_u32(object.get("max_in_flight")),
            busy_ms,
            busy_ratio,
            overlap_ms,
            overlap_ratio,
            window_ms,
            lanes,
        })
    }
}
#[derive(Clone, Debug)]
struct QueueLaneProfile {
    index: Option<u32>,
    dispatch_count: Option<u32>,
    max_in_flight: Option<u32>,
    busy_ms: Option<f64>,
    overlap_ms: Option<f64>,
    busy_ratio: Option<f64>,
    overlap_ratio: Option<f64>,
}
impl QueueLaneProfile {
    fn from_value(value: &Value, window_ms: Option<f64>) -> Option<Self> {
        let object = value.as_object()?;
        let busy_ms = as_f64(object.get("busy_ms"));
        let overlap_ms = as_f64(object.get("overlap_ms"));
        Some(Self {
            index: as_u32(object.get("index")),
            dispatch_count: as_u32(object.get("dispatch_count")),
            max_in_flight: as_u32(object.get("max_in_flight")),
            busy_ms,
            overlap_ms,
            busy_ratio: object
                .get("busy_ratio")
                .and_then(|value| as_f64(Some(value)))
                .or_else(|| match (busy_ms, window_ms) {
                    (Some(busy), Some(window)) if window > 0.0 => {
                        Some((busy / window).clamp(0.0, 1.0))
                    }
                    _ => None,
                }),
            overlap_ratio: object
                .get("overlap_ratio")
                .and_then(|value| as_f64(Some(value)))
                .or_else(|| match (overlap_ms, busy_ms) {
                    (Some(overlap), Some(busy)) if busy > 0.0 => {
                        Some((overlap / busy).clamp(0.0, 1.0))
                    }
                    _ => None,
                }),
        })
    }
}
#[derive(Clone, Debug)]
struct ColumnStagingSummary {
    batches: Option<u64>,
    flatten_ms: Option<f64>,
    wait_ms: Option<f64>,
    wait_ratio: Option<f64>,
}
impl ColumnStagingSummary {
    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        Some(Self {
            batches: as_u64(object.get("batches")),
            flatten_ms: as_f64(object.get("flatten_ms")),
            wait_ms: as_f64(object.get("wait_ms")),
            wait_ratio: as_f64(object.get("wait_ratio")),
        })
    }
}
fn as_string(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}
fn as_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}
fn as_u32(value: Option<&Value>) -> Option<u32> {
    as_u64(value).and_then(|raw| u32::try_from(raw).ok())
}
fn as_f64(value: Option<&Value>) -> Option<f64> {
    value.and_then(Value::as_f64)
}
fn format_ms(value: Option<f64>) -> String {
    value
        .map(|ms| format!("{:.3}", ms))
        .unwrap_or_else(|| "-".to_owned())
}
fn format_timing(timings: &StageTimings) -> String {
    timings.summary_string().unwrap_or_else(|| "-".to_owned())
}
fn format_ratio(value: Option<f64>) -> String {
    value
        .map(|ratio| format!("{:.3}x", ratio))
        .unwrap_or_else(|| "-".to_owned())
}
fn format_pct(value: Option<f64>) -> String {
    value
        .map(|pct| format!("{:.1}%", pct))
        .unwrap_or_else(|| "-".to_owned())
}
fn format_delta(value: Option<f64>) -> String {
    value
        .map(|delta| format!("{:+.3}", delta))
        .unwrap_or_else(|| "-".to_owned())
}
fn format_u32(value: Option<u32>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_owned())
}
fn format_u64(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_owned())
}
fn format_bytes(value: u64) -> String {
    const UNITS: &[(&str, u64)] = &[("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)];
    for (label, unit) in UNITS {
        if value >= *unit {
            let exact = value as f64 / *unit as f64;
            return format!("{exact:.2} {label}");
        }
    }
    format!("{value} B")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_operations_and_totals() {
        let json = r#"
        {
            "producer_schema": "metal_flat",
            "rows": 20000,
            "padded_rows": 32768,
            "column_count": 16,
            "trace_log2": 15,
            "lde_log2": 18,
            "execution_mode": "gpu",
            "gpu_backend": "metal",
            "operations": [
                {
                    "operation": "fft",
                    "columns": 16,
                    "input_len": 32768,
                    "gpu_recorded": true, "cpu": {"mean_ms": 110.0, "min_ms": 110.0, "max_ms": 110.0},
                    "gpu": {"mean_ms": 130.0, "min_ms": 130.0, "max_ms": 130.0},
                    "speedup": {"ratio": 0.85, "delta_ms": -20.0}
                },
                {
                    "operation": "lde",
                    "columns": 16,
                    "input_len": 262144,
                    "gpu_recorded": true, "cpu": {"mean_ms": 1750.0, "min_ms": 1750.0, "max_ms": 1750.0},
                    "gpu": {"mean_ms": 1570.0, "min_ms": 1570.0, "max_ms": 1570.0},
                    "speedup": {"ratio": 1.11, "delta_ms": 180.0},
                    "zero_fill": {"bytes": 33554432, "ms": {"mean_ms": 0.31}}
                }
            ],
            "metal_dispatch_queue": {
                "limit": 8,
                "dispatch_count": 32,
                "max_in_flight": 4,
                "busy_ms": 1200.0,
                "overlap_ms": 600.0,
                "window_ms": 2000.0,
                "queues": [
                    {"index": 0, "dispatch_count": 16, "max_in_flight": 2, "busy_ms": 500.0, "overlap_ms": 100.0}
                ]
            },
            "column_staging": {
                "batches": 32,
                "flatten_ms": 420.0,
                "wait_ms": 180.0,
                "wait_ratio": 0.3
            }
        }"#;
        let fixture: Value = json::from_str(json).expect("parse sample JSON");
        let mut value = digest384_report::test_metal_report(20_000);
        let fixture_operations = fixture.get("operations").unwrap().as_array().unwrap();
        let map = value.as_object_mut().unwrap();
        for entry in map.get_mut("operations").unwrap().as_array_mut().unwrap() {
            if let Some(replacement) = fixture_operations
                .iter()
                .find(|other| other.get("operation") == entry.get("operation"))
            {
                *entry = replacement.clone();
            }
        }
        map.insert(
            "metal_dispatch_queue".into(),
            fixture.get("metal_dispatch_queue").unwrap().clone(),
        );
        map.insert("column_staging".into(), digest384_report::test_staging());
        let summary =
            ProfileSummary::from_value("sample.json".to_owned(), &value).expect("summary");
        assert_eq!(summary.operations.len(), digest384_report::OPERATIONS.len());
        assert_eq!(
            summary
                .operations
                .iter()
                .filter(|op| matches!(op.name.as_str(), "fft" | "lde"))
                .count(),
            2
        );
        assert!(summary.total_gpu_ms() > 0.0);
        assert!(summary.total_cpu_ms() > 0.0);
        assert_eq!(summary.queue.as_ref().and_then(|q| q.limit), Some(8));
        assert_eq!(
            summary
                .operations
                .iter()
                .find(|op| op.name == "lde")
                .and_then(|op| op.zero_fill.as_ref())
                .and_then(|zf| zf.bytes),
            Some(33_554_432)
        );
    }
    #[test]
    fn profile_projects_complete_digest_work_and_rejects_retired_or_tampered_input() {
        let report = digest384_report::test_metal_report(3);
        let summary =
            ProfileSummary::from_value("synthetic schema control".into(), &report).unwrap();
        let mut rendered = Vec::new();
        summary.render_markdown(&mut rendered).unwrap();
        let text = String::from_utf8(rendered).unwrap();
        assert!(text.contains("complete six-lane frames"));
        assert!(text.contains("canonical lanes checked"));
        assert!(!text.contains("Poseidon microbench"));
        let embedded = text
            .split("```json\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap();
        let retained: Value = json::from_str(embedded).unwrap();
        digest384_report::report_from_root(&retained)
            .expect("complete exported report revalidates");
        assert_eq!(retained, report);
        let mut retired = report.clone();
        retired
            .as_object_mut()
            .unwrap()
            .insert("poseidon_microbench".into(), Value::Null);
        assert!(ProfileSummary::from_value("retired".into(), &retired).is_err());
        let mut corrupted = report;
        corrupted
            .get_mut("operations")
            .unwrap()
            .as_array_mut()
            .unwrap()[3]
            .get_mut("digest384")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("digest_lanes".into(), Value::from(1_u8));
        assert!(ProfileSummary::from_value("corrupted".into(), &corrupted).is_err());
    }
}
