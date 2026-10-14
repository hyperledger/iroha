#![allow(unexpected_cfgs)]
use anyhow::{Context, Result};
use clap::Parser;
use norito::derive::{JsonSerialize, NoritoSerialize};
use norito::json;
use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const LOG_PREFIX: &str = "fastpq_production_prover:";
const DEFAULT_OUTPUT_EXTENSION: &str = "jsonl";
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Emit FASTPQ production perf telemetry payloads"
)]
struct Cli {
    /// Path to the FASTPQ perf log emitted by the regression test.
    #[arg(long, default_value = "fastpq_production_perf.log")]
    input: PathBuf,
    /// Optional output path for the telemetry NDJSON payload.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Telemetry message name to embed in the payload.
    #[arg(long, default_value = "fastpq.production.perf")]
    msg: String,
}
#[derive(Debug, Clone, Copy, PartialEq)]
struct PerfMetrics {
    rows: u32,
    duration_ms: f64,
    proof_kib: f64,
}
#[derive(Debug, JsonSerialize, NoritoSerialize)]
struct TelemetryEnvelope {
    msg: String,
    event: TelemetryEvent,
}
#[derive(Debug, JsonSerialize, NoritoSerialize)]
struct TelemetryEvent {
    rows: u32,
    duration_ms: f64,
    proof_kib: f64,
    expected_ms: Option<f64>,
    expected_kib: Option<f64>,
    duration_ms_over_budget: bool,
    proof_kib_over_budget: bool,
    timestamp_ms: u64,
    repository: Option<String>,
    workflow: Option<String>,
    run_id: Option<String>,
    run_attempt: Option<String>,
    job: Option<String>,
    sha: Option<String>,
    runner: Option<String>,
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_path = &cli.input;
    let contents = fs::read_to_string(log_path)
        .with_context(|| format!("read FASTPQ perf log {}", log_path.display()))?;
    let metrics = parse_latest_metrics(&contents)
        .with_context(|| format!("no production perf entry found in {}", log_path.display()))?;
    let expected_ms = parse_env_f64("FASTPQ_EXPECTED_MS");
    let expected_kib = parse_env_f64("FASTPQ_EXPECTED_KIB");
    let timestamp_ms = current_timestamp_ms();
    let event = TelemetryEvent {
        rows: metrics.rows,
        duration_ms: metrics.duration_ms,
        proof_kib: metrics.proof_kib,
        expected_ms,
        expected_kib,
        duration_ms_over_budget: expected_ms
            .map(|threshold| metrics.duration_ms > threshold)
            .unwrap_or(false),
        proof_kib_over_budget: expected_kib
            .map(|threshold| metrics.proof_kib > threshold)
            .unwrap_or(false),
        timestamp_ms,
        repository: env::var("GITHUB_REPOSITORY").ok(),
        workflow: env::var("GITHUB_WORKFLOW").ok(),
        run_id: env::var("GITHUB_RUN_ID").ok(),
        run_attempt: env::var("GITHUB_RUN_ATTEMPT").ok(),
        job: env::var("GITHUB_JOB").ok(),
        sha: env::var("GITHUB_SHA").ok(),
        runner: env::var("RUNNER_NAME").ok(),
    };
    let payload = TelemetryEnvelope {
        msg: cli.msg,
        event,
    };
    let json_value = json::to_value(&payload)?;
    let json_string = json::to_string(&json_value)?;
    let output_path = cli
        .output
        .unwrap_or_else(|| cli.input.with_extension(DEFAULT_OUTPUT_EXTENSION));
    write_payload(&output_path, &json_string)
        .with_context(|| format!("write telemetry payload {}", output_path.display()))?;
    println!("FASTPQ perf telemetry written to {}", output_path.display());
    Ok(())
}
fn parse_env_f64(name: &str) -> Option<f64> {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|parsed| parsed.is_finite() && *parsed > 0.0)
}
fn current_timestamp_ms() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = now.as_millis();
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}
fn write_payload(path: &Path, body: &str) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(body.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
fn parse_latest_metrics(contents: &str) -> Option<PerfMetrics> {
    contents.lines().filter_map(parse_metrics_line).next_back()
}
fn parse_metrics_line(line: &str) -> Option<PerfMetrics> {
    let trimmed = line.trim();
    let payload = trimmed.strip_prefix(LOG_PREFIX)?.trim();
    let mut rows = None;
    let mut duration_ms = None;
    let mut proof_kib = None;
    for token in payload.split_whitespace() {
        if let Some(value) = token.strip_prefix("rows=") {
            rows = value.parse::<u32>().ok();
            continue;
        }
        if let Some(value) = token.strip_prefix("duration_ms=") {
            duration_ms = value.parse::<f64>().ok();
            continue;
        }
        if let Some(value) = token.strip_prefix("proof_kib=") {
            proof_kib = value.parse::<f64>().ok();
        }
    }
    match (rows, duration_ms, proof_kib) {
        (Some(rows), Some(duration_ms), Some(proof_kib)) => Some(PerfMetrics {
            rows,
            duration_ms,
            proof_kib,
        }),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_metrics_line_extracts_values() {
        let input = "fastpq_production_prover: rows=16384 duration_ms=912.42 proof_kib=128.5";
        let metrics = parse_metrics_line(input).expect("metrics parsed");
        assert_eq!(
            metrics,
            PerfMetrics {
                rows: 16_384,
                duration_ms: 912.42,
                proof_kib: 128.5
            }
        );
    }
    #[test]
    fn parse_latest_metrics_returns_last_entry() {
        let log = r#"
noise line
fastpq_production_prover: rows=4 duration_ms=1.0 proof_kib=2.0
fastpq_production_prover: rows=8 duration_ms=3.5 proof_kib=4.5
"#;
        let metrics = parse_latest_metrics(log).expect("latest metrics parsed");
        assert_eq!(
            metrics,
            PerfMetrics {
                rows: 8,
                duration_ms: 3.5,
                proof_kib: 4.5
            }
        );
    }
    #[test]
    fn parse_metrics_line_ignores_malformed_tokens() {
        let malformed = "fastpq_production_prover: rows=abc duration_ms=3 proof_kib=4";
        assert!(parse_metrics_line(malformed).is_none());
    }
}
