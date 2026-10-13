//! Source-coupled FASTPQ benchmark capture and release manifest tooling.
#[path = "../../scripts/fastpq/src/digest384_report.rs"]
mod digest384_report;
use crate::workspace_root;
use blake3::hash as blake3_hash;
use eyre::{Context, Result, bail, ensure, eyre};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, PublicKey, Signature};
use norito::{
    derive::{JsonDeserialize, JsonSerialize},
    json::{self, Value},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description};
#[derive(Debug, Clone)]
pub struct BenchInput {
    pub label: String,
    pub path: PathBuf,
}
#[derive(Debug)]
pub struct BenchManifestOptions {
    pub benches: Vec<BenchInput>,
    pub output: PathBuf,
    pub signing_key: Option<PathBuf>,
    pub require_rows: Option<u64>,
    pub max_operation_ms: BTreeMap<String, f64>,
    pub min_operation_speedup: BTreeMap<String, f64>,
    pub matrix_manifest: Option<PathBuf>,
    pub label_max_operation_ms: BTreeMap<String, BTreeMap<String, f64>>,
    pub label_min_operation_speedup: BTreeMap<String, BTreeMap<String, f64>>,
    pub label_operation_filters: BTreeMap<String, BTreeSet<String>>,
}
impl Default for BenchManifestOptions {
    fn default() -> Self {
        Self {
            benches: Vec::new(),
            output: default_manifest_path(),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        }
    }
}
pub fn default_manifest_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("fastpq_bench_manifest.json")
}
pub fn default_matrix_manifest_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("fastpq_benchmarks")
        .join("matrix")
        .join("matrix_manifest.json")
}
pub fn default_stage_profile_dir() -> PathBuf {
    let timestamp = stage_profile_timestamp();
    workspace_root()
        .join("artifacts")
        .join("fastpq_stage_profiles")
        .join(timestamp)
}
#[derive(JsonSerialize, JsonDeserialize)]
struct BenchHashes {
    blake3_hex: String,
    sha256_hex: String,
}
#[derive(JsonSerialize, Default, JsonDeserialize)]
struct BenchMetadata {
    generated_at: Option<String>,
    host: Option<String>,
    platform: Option<String>,
    machine: Option<String>,
    command: Option<String>,
    notes: Option<String>,
}
#[derive(JsonSerialize, JsonDeserialize)]
struct BenchEntry {
    label: String,
    path: String,
    rows: u64,
    padded_rows: Option<u64>,
    iterations: Option<u64>,
    warmups: Option<u64>,
    #[norito(skip_serializing_if = "Option::is_none")]
    operation_filter: Option<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    matrix_operation_filters: Option<Vec<String>>,
    gpu_backend: Option<String>,
    gpu_available: Option<bool>,
    metadata: BenchMetadata,
    hashes: BenchHashes,
}
#[derive(JsonSerialize, JsonDeserialize)]
struct ConstraintSummary {
    require_rows: Option<u64>,
    max_operation_ms: BTreeMap<String, f64>,
    min_operation_speedup: BTreeMap<String, f64>,
}
#[derive(JsonSerialize, JsonDeserialize)]
struct BenchManifestPayload {
    version: u32,
    generated_unix_ms: u64,
    generator_commit: String,
    benches: Vec<BenchEntry>,
    constraints: ConstraintSummary,
}
#[derive(JsonSerialize, JsonDeserialize)]
struct SignatureEnvelope {
    algorithm: String,
    public_key_hex: String,
    signature_hex: String,
}
#[derive(JsonSerialize, JsonDeserialize)]
struct SignedBenchManifest {
    payload: BenchManifestPayload,
    signature: Option<SignatureEnvelope>,
}
#[derive(Clone, Copy, Debug)]
struct OperationStats {
    gpu_mean_ms: Option<f64>,
    speedup_ratio: Option<f64>,
}
impl OperationStats {
    fn from_value(value: &Value) -> OperationStats {
        let gpu_mean_ms = value.get("gpu_mean_ms").and_then(|v| v.as_f64());
        let speedup_ratio = value.get("speedup_ratio").and_then(|v| v.as_f64());
        OperationStats {
            gpu_mean_ms,
            speedup_ratio,
        }
    }
}
impl BenchManifestOptions {
    fn effective_max_operation_ms(&self, label: &str) -> BTreeMap<String, f64> {
        let mut map = self.max_operation_ms.clone();
        if let Some(per_label) = self.label_max_operation_ms.get(label) {
            if map.is_empty() {
                return per_label.clone();
            }
            for (operation, limit) in per_label {
                map.insert(operation.clone(), *limit);
            }
        }
        map
    }
    fn effective_min_operation_speedup(&self, label: &str) -> BTreeMap<String, f64> {
        let mut map = self.min_operation_speedup.clone();
        if let Some(per_label) = self.label_min_operation_speedup.get(label) {
            if map.is_empty() {
                return per_label.clone();
            }
            for (operation, limit) in per_label {
                map.insert(operation.clone(), *limit);
            }
        }
        map
    }
}
#[derive(Debug, JsonDeserialize)]
struct MatrixManifest {
    version: u32,
    #[norito(default)]
    require_rows: Option<u64>,
    #[norito(default)]
    max_operation_ms: BTreeMap<String, f64>,
    #[norito(default)]
    min_operation_speedup: BTreeMap<String, f64>,
    #[norito(default)]
    devices: Vec<MatrixDeviceEntry>,
}
#[derive(Debug, JsonDeserialize)]
struct MatrixDeviceEntry {
    label: String,
    #[norito(default)]
    operation_filters: Vec<String>,
    #[norito(default)]
    max_operation_ms: BTreeMap<String, f64>,
    #[norito(default)]
    min_operation_speedup: BTreeMap<String, f64>,
}
fn apply_matrix_manifest(options: &mut BenchManifestOptions, manifest_path: &Path) -> Result<()> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read matrix manifest {}", manifest_path.display()))?;
    digest384_report::retired_fields(&json::from_slice::<Value>(&bytes)?)
        .map_err(|error| eyre!(error))?;
    let manifest: MatrixManifest = json::from_slice(&bytes)
        .with_context(|| format!("parse matrix manifest {}", manifest_path.display()))?;
    ensure!(
        manifest.version == 1,
        "matrix manifest {} has unsupported version {}",
        manifest_path.display(),
        manifest.version
    );
    for operation in manifest
        .max_operation_ms
        .keys()
        .chain(manifest.min_operation_speedup.keys())
        .chain(manifest.devices.iter().flat_map(|device| {
            device
                .max_operation_ms
                .keys()
                .chain(device.min_operation_speedup.keys())
        }))
    {
        digest384_report::require_operation(operation).map_err(|error| eyre!(error))?;
    }
    for filter in manifest
        .devices
        .iter()
        .flat_map(|device| &device.operation_filters)
    {
        digest384_report::require_filter(filter).map_err(|error| eyre!(error))?;
    }
    if options.require_rows.is_none() {
        options.require_rows = manifest.require_rows;
    }
    if options.max_operation_ms.is_empty() && !manifest.max_operation_ms.is_empty() {
        options.max_operation_ms = manifest.max_operation_ms.clone();
    }
    if options.min_operation_speedup.is_empty() && !manifest.min_operation_speedup.is_empty() {
        options.min_operation_speedup = manifest.min_operation_speedup.clone();
    }
    for device in &manifest.devices {
        if !device.max_operation_ms.is_empty() {
            options
                .label_max_operation_ms
                .insert(device.label.clone(), device.max_operation_ms.clone());
        }
        if !device.min_operation_speedup.is_empty() {
            options
                .label_min_operation_speedup
                .insert(device.label.clone(), device.min_operation_speedup.clone());
        }
        if !device.operation_filters.is_empty() {
            options.label_operation_filters.insert(
                device.label.clone(),
                device.operation_filters.iter().cloned().collect(),
            );
        }
    }
    Ok(())
}
pub fn write_bench_manifest(mut options: BenchManifestOptions) -> Result<()> {
    if let Some(path) = options.matrix_manifest.clone() {
        apply_matrix_manifest(&mut options, &path)?;
    }
    for operation in options
        .max_operation_ms
        .keys()
        .chain(options.min_operation_speedup.keys())
        .chain(
            options
                .label_max_operation_ms
                .values()
                .flat_map(|map| map.keys()),
        )
        .chain(
            options
                .label_min_operation_speedup
                .values()
                .flat_map(|map| map.keys()),
        )
    {
        digest384_report::require_operation(operation).map_err(|error| eyre!(error))?;
    }
    for filter in options
        .label_operation_filters
        .values()
        .flat_map(|set| set.iter())
    {
        digest384_report::require_filter(filter).map_err(|error| eyre!(error))?;
    }
    if options.benches.is_empty() {
        bail!("fastpq-bench-manifest requires at least one --bench label=path argument");
    }
    let mut entries = Vec::with_capacity(options.benches.len());
    for bench in &options.benches {
        let entry = parse_bench_entry(bench, &options)?;
        entries.push(entry);
    }
    let payload = BenchManifestPayload {
        version: 1,
        generated_unix_ms: current_unix_ms(),
        generator_commit: current_commit().unwrap_or_else(|_| "unknown".to_string()),
        benches: entries,
        constraints: ConstraintSummary {
            require_rows: options.require_rows,
            max_operation_ms: options.max_operation_ms.clone(),
            min_operation_speedup: options.min_operation_speedup.clone(),
        },
    };
    validate_manifest_payload(&payload)?;
    digest384_report::retired_fields(&json::to_value(&payload)?).map_err(|error| eyre!(error))?;
    let payload_bytes = json::to_vec(&payload).context("serialize bench manifest payload")?;
    let signature = if let Some(key_path) = options.signing_key.as_ref() {
        Some(sign_manifest(&payload_bytes, key_path)?)
    } else {
        None
    };
    let signed = SignedBenchManifest { payload, signature };
    let json = json::to_json_pretty(&signed).context("serialize signed manifest")?;
    if let Some(parent) = options.output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&options.output, json)
        .with_context(|| format!("write {}", options.output.display()))?;
    if let Ok(rel) = options.output.strip_prefix(workspace_root()) {
        println!("wrote {}", rel.display());
    } else {
        println!("wrote {}", options.output.display());
    }
    Ok(())
}
fn parse_bench_entry(bench: &BenchInput, constraints: &BenchManifestOptions) -> Result<BenchEntry> {
    let bytes = fs::read(&bench.path)
        .with_context(|| format!("read benchmark {}", bench.path.display()))?;
    let blake3_hex = blake3_hash(&bytes).to_hex().to_string();
    let sha256_hex = hex::encode(Sha256::digest(&bytes));
    let bundle: Value = json::from_slice(&bytes)
        .with_context(|| format!("decode JSON from {}", bench.path.display()))?;
    digest384_report::report_from_root(&bundle).map_err(|error| eyre!(error))?;
    let metadata_value = bundle
        .get("metadata")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let benchmarks_value = bundle
        .get("benchmarks")
        .and_then(|v| v.as_object())
        .ok_or_else(|| eyre!("benchmarks block missing in {}", bench.path.display()))?;
    let rows = benchmarks_value
        .get("rows")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            eyre!(
                "benchmarks.rows missing or invalid in {}",
                bench.path.display()
            )
        })?;
    if let Some(required) = constraints.require_rows {
        ensure!(
            rows >= required,
            "bench `{}` rows {} below required threshold {}",
            bench.label,
            rows,
            required
        );
    }
    let operations = benchmarks_value
        .get("operations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| eyre!("benchmarks.operations missing in {}", bench.path.display()))?;
    let operation_map = build_operation_map(operations);
    let effective_max = constraints.effective_max_operation_ms(&bench.label);
    let effective_min = constraints.effective_min_operation_speedup(&bench.label);
    enforce_operation_limits(
        &bench.label,
        &operation_map,
        &effective_max,
        |stats| stats.gpu_mean_ms,
        "gpu_mean_ms",
        "max-operation-ms",
    )?;
    enforce_operation_limits(
        &bench.label,
        &operation_map,
        &effective_min,
        |stats| stats.speedup_ratio,
        "speedup_ratio",
        "min-operation-speedup",
    )?;
    let metadata = BenchMetadata {
        generated_at: metadata_value
            .get("generated_at")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        host: metadata_value
            .get("host")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        platform: metadata_value
            .get("platform")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        machine: metadata_value
            .get("machine")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        command: metadata_value
            .get("command")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        notes: metadata_value
            .get("notes")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
    };
    let benchmark_path = display_path(&bench.path);
    let gpu_backend = benchmarks_value
        .get("gpu_backend")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let operation_filter = benchmarks_value
        .get("operation_filter")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    validate_declared_operation_filter(
        &bench.label,
        operation_filter.as_deref(),
        operations.len(),
        &operation_map,
    )?;
    Ok(BenchEntry {
        label: bench.label.clone(),
        path: benchmark_path,
        rows,
        padded_rows: benchmarks_value.get("padded_rows").and_then(|v| v.as_u64()),
        iterations: benchmarks_value.get("iterations").and_then(|v| v.as_u64()),
        warmups: benchmarks_value.get("warmups").and_then(|v| v.as_u64()),
        operation_filter,
        matrix_operation_filters: constraints
            .label_operation_filters
            .get(&bench.label)
            .filter(|filters| !filters.is_empty())
            .map(canonical_matrix_filters),
        gpu_backend,
        gpu_available: benchmarks_value
            .get("gpu_available")
            .and_then(|v| v.as_bool()),
        metadata,
        hashes: BenchHashes {
            blake3_hex,
            sha256_hex,
        },
    })
}

/// Encode a matrix's filter set in the V1 inventory order, with `all` first.
fn canonical_matrix_filters(filters: &BTreeSet<String>) -> Vec<String> {
    std::iter::once("all")
        .chain(digest384_report::OPERATIONS)
        .filter(|filter| filters.contains(*filter))
        .map(str::to_owned)
        .collect()
}

fn validate_declared_operation_filter(
    label: &str,
    operation_filter: Option<&str>,
    operation_entry_count: usize,
    operations: &BTreeMap<String, OperationStats>,
) -> Result<()> {
    let operation_filter = operation_filter
        .ok_or_else(|| eyre!("bench `{label}` requires canonical operation_filter"))?;
    ensure!(
        operation_entry_count == operations.len(),
        "bench `{label}` contains malformed or duplicate operation rows"
    );
    if operation_filter == "all" {
        ensure!(
            operations.len() == digest384_report::OPERATIONS.len()
                && digest384_report::OPERATIONS
                    .iter()
                    .all(|operation| operations.contains_key(*operation)),
            "bench `{label}` declares operation_filter `all` but does not contain every canonical operation"
        );
        return Ok(());
    }
    ensure!(
        digest384_report::OPERATIONS.contains(&operation_filter),
        "bench `{label}` declares unknown operation_filter `{operation_filter}`"
    );
    ensure!(
        operations.len() == 1 && operations.contains_key(operation_filter),
        "bench `{label}` declares operation_filter `{operation_filter}` but its operation rows do not match"
    );
    Ok(())
}
fn build_operation_map(entries: &[Value]) -> BTreeMap<String, OperationStats> {
    let mut map = BTreeMap::new();
    for entry in entries {
        if let Some(name) = entry.get("operation").and_then(|v| v.as_str()) {
            map.insert(name.to_string(), OperationStats::from_value(entry));
        }
    }
    map
}
fn enforce_operation_limits<F>(
    label: &str,
    operations: &BTreeMap<String, OperationStats>,
    limits: &BTreeMap<String, f64>,
    extractor: F,
    field_name: &str,
    flag_name: &str,
) -> Result<()>
where
    F: Fn(&OperationStats) -> Option<f64>,
{
    for (operation, limit) in limits {
        let stats = operations.get(operation).ok_or_else(|| {
            eyre!("bench `{label}` missing `{operation}` operation required by --{flag_name}")
        })?;
        let value = extractor(stats)
            .ok_or_else(|| eyre!("bench `{label}` operation `{operation}` missing {field_name}"))?;
        if flag_name == "max-operation-ms" {
            ensure!(
                value <= *limit,
                "bench `{label}` operation `{operation}` exceeded max {field_name} (value={value:.3} ms, limit={limit})"
            );
        } else {
            ensure!(
                value >= *limit,
                "bench `{label}` operation `{operation}` fell below min {field_name} (value={value:.3}, limit={limit})"
            );
        }
    }
    Ok(())
}
fn sign_manifest(payload: &[u8], key_path: &Path) -> Result<SignatureEnvelope> {
    let key_hex = fs::read_to_string(key_path)
        .with_context(|| format!("read signing key {}", key_path.display()))?;
    let cleaned: String = key_hex
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let private_key =
        PrivateKey::from_hex(Algorithm::Ed25519, &cleaned).context("parse signing key")?;
    let key_pair: KeyPair = private_key.clone().into();
    let signature = Signature::try_new(key_pair.private_key(), payload)
        .map_err(|err| eyre!("failed to sign FastPQ manifest payload: {err}"))?;
    let (algorithm, public_bytes) = key_pair
        .public_key()
        .try_to_bytes()
        .map_err(|err| eyre!("signing public key is malformed: {err}"))?;
    ensure!(
        algorithm == Algorithm::Ed25519,
        "only Ed25519 signing keys are supported"
    );
    Ok(SignatureEnvelope {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex::encode(public_bytes),
        signature_hex: hex::encode(signature.payload()),
    })
}

fn validate_manifest_payload(payload: &BenchManifestPayload) -> Result<()> {
    ensure!(
        payload.version == 1,
        "unsupported benchmark manifest version"
    );
    ensure!(
        !payload.benches.is_empty(),
        "benchmark manifest benches must not be empty"
    );
    for operation in payload
        .constraints
        .max_operation_ms
        .keys()
        .chain(payload.constraints.min_operation_speedup.keys())
    {
        digest384_report::require_operation(operation).map_err(|error| eyre!(error))?;
    }
    for bench in &payload.benches {
        let filter = bench
            .operation_filter
            .as_deref()
            .ok_or_else(|| eyre!("benchmark manifest requires canonical operation_filter"))?;
        digest384_report::require_filter(filter).map_err(|error| eyre!(error))?;
        if let Some(filters) = &bench.matrix_operation_filters {
            for filter in filters {
                digest384_report::require_filter(filter).map_err(|error| eyre!(error))?;
            }
            ensure!(
                !filters.is_empty()
                    && *filters == canonical_matrix_filters(&filters.iter().cloned().collect()),
                "matrix_operation_filters must be nonempty, unique and in canonical inventory order"
            );
        }
    }
    Ok(())
}

/// Authenticate a benchmark manifest with an independently supplied Ed25519 key.
///
/// The manifest's claimed public key is never a trust anchor. Re-encoding the
/// typed payload with Norito reproduces the exact compact preimage used by
/// `write_bench_manifest`, including its field order and floating-point format.
pub fn verify_bench_manifest(manifest_path: &Path, trusted_public_key_hex: &str) -> Result<()> {
    let content = fs::read(manifest_path)
        .with_context(|| format!("read benchmark manifest {}", manifest_path.display()))?;
    let raw: Value = json::from_slice(&content).context("decode benchmark manifest object")?;
    digest384_report::retired_fields(&raw).map_err(|error| eyre!(error))?;
    let signed: SignedBenchManifest =
        json::from_slice(&content).context("decode signed benchmark manifest")?;
    validate_manifest_payload(&signed.payload)?;
    let envelope = signed
        .signature
        .ok_or_else(|| eyre!("benchmark manifest requires a release signature"))?;
    ensure!(
        envelope.algorithm == "ed25519",
        "benchmark manifest must use Ed25519"
    );
    let trusted_key = PublicKey::from_hex(Algorithm::Ed25519, trusted_public_key_hex)
        .context("parse independently trusted FASTPQ release public key")?;
    let claimed_key = PublicKey::from_hex(Algorithm::Ed25519, &envelope.public_key_hex)
        .context("parse manifest signer public key")?;
    ensure!(
        claimed_key == trusted_key,
        "benchmark manifest signer is not the trusted release key"
    );
    let signature = Signature::try_from_bytes(
        &hex::decode(&envelope.signature_hex).context("decode benchmark manifest signature")?,
    )
    .map_err(|err| eyre!("invalid benchmark manifest signature: {err}"))?;
    let preimage =
        json::to_vec(&signed.payload).context("encode benchmark manifest signature preimage")?;
    signature
        .verify(&trusted_key, &preimage)
        .map_err(|err| eyre!("benchmark manifest signature verification failed: {err}"))?;
    Ok(())
}
fn display_path(path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(workspace_root()) {
        rel.display().to_string()
    } else {
        path.display().to_string()
    }
}
fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn current_commit() -> Result<String> {
    let output = Command::new("git")
        .current_dir(workspace_root())
        .args(["rev-parse", "HEAD"])
        .output()
        .context("git rev-parse HEAD failed")?;
    if !output.status.success() {
        bail!("git rev-parse HEAD returned {}", output.status);
    }
    let text = String::from_utf8(output.stdout).context("rev-parse output")?;
    Ok(text.trim().to_string())
}
#[derive(Debug)]
pub struct StageProfileOptions {
    pub rows: usize,
    pub warmups: usize,
    pub iterations: usize,
    pub output_dir: PathBuf,
    pub release: bool,
    pub capture_trace: bool,
    pub trace_dir: Option<PathBuf>,
    pub trace_template: Option<String>,
    pub trace_seconds: Option<u32>,
    pub gpu_probe: bool,
    pub stages: Vec<StageKind>,
}
impl Default for StageProfileOptions {
    fn default() -> Self {
        Self {
            rows: 20_000,
            warmups: 1,
            iterations: 5,
            output_dir: default_stage_profile_dir(),
            release: true,
            capture_trace: false,
            trace_dir: None,
            trace_template: None,
            trace_seconds: None,
            gpu_probe: true,
            stages: vec![
                StageKind::Fft,
                StageKind::Lde,
                StageKind::Digest384TraceColumns,
            ],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StageKind {
    Fft,
    Ifft,
    Lde,
    Digest384TraceColumns,
    Digest384MerklePairs,
    Bn254PoseidonWords,
}
impl StageKind {
    pub fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "fft" => Some(Self::Fft),
            "ifft" => Some(Self::Ifft),
            "lde" => Some(Self::Lde),
            "digest384_trace_columns" => Some(Self::Digest384TraceColumns),
            "digest384_merkle_pairs" => Some(Self::Digest384MerklePairs),
            "bn254_poseidon_words" => Some(Self::Bn254PoseidonWords),
            _ => None,
        }
    }
    fn spec(self) -> StageSpec {
        match self {
            StageKind::Fft => StageSpec {
                label: "fft",
                operation: "fft",
                dir: "fft",
            },
            StageKind::Ifft => StageSpec {
                label: "ifft",
                operation: "ifft",
                dir: "ifft",
            },
            StageKind::Lde => StageSpec {
                label: "lde",
                operation: "lde",
                dir: "lde",
            },
            StageKind::Digest384TraceColumns => StageSpec {
                label: "digest384_trace_columns",
                operation: "digest384_trace_columns",
                dir: "digest384_trace_columns",
            },
            StageKind::Digest384MerklePairs => StageSpec {
                label: "digest384_merkle_pairs",
                operation: "digest384_merkle_pairs",
                dir: "digest384_merkle_pairs",
            },
            StageKind::Bn254PoseidonWords => StageSpec {
                label: "bn254_poseidon_words",
                operation: "bn254_poseidon_words",
                dir: "bn254_poseidon_words",
            },
        }
    }
    fn cuda_operation(self) -> &'static str {
        self.spec().operation
    }
}
struct StageSpec {
    label: &'static str,
    operation: &'static str,
    dir: &'static str,
}
#[derive(JsonSerialize)]
struct StageProfileSummary {
    generated_at: String,
    rows: usize,
    warmups: usize,
    iterations: usize,
    release_build: bool,
    capture_trace: bool,
    stages: Vec<StageSummary>,
}
#[derive(JsonSerialize)]
struct StageSummary {
    // Full validated input retains producer, context and every operation claim for independent revalidation.
    validated_report: Value,
    stage: String,
    operation: String,
    benchmark_json: String,
    #[norito(skip_serializing_if = "Option::is_none")]
    trace_artifact: Option<String>,
    stats: StageStats,
    #[norito(skip_serializing_if = "Option::is_none")]
    digest384: Option<Value>,
    #[norito(skip_serializing_if = "Option::is_none")]
    metal_dispatch_queue: Option<Value>,
    #[norito(skip_serializing_if = "Option::is_none")]
    column_staging: Option<Value>,
    #[norito(skip_serializing_if = "Option::is_none")]
    kernel_profiles: Option<Value>,
    #[norito(skip_serializing_if = "Option::is_none")]
    post_tile_dispatches: Option<Value>,
    #[norito(skip_serializing_if = "Option::is_none")]
    twiddle_cache: Option<Value>,
    #[norito(skip_serializing_if = "Option::is_none")]
    device_profile: Option<Value>,
    #[norito(skip_serializing_if = "Option::is_none")]
    metal_heuristics: Option<Value>,
}
#[derive(JsonSerialize)]
struct StageStats {
    cpu: StageStat,
    #[norito(skip_serializing_if = "Option::is_none")]
    gpu: Option<StageStat>,
    #[norito(skip_serializing_if = "Option::is_none")]
    speedup_ratio: Option<f64>,
    #[norito(skip_serializing_if = "Option::is_none")]
    speedup_delta_ms: Option<f64>,
    #[norito(skip_serializing_if = "Option::is_none")]
    columns: Option<u64>,
    #[norito(skip_serializing_if = "Option::is_none")]
    input_len: Option<u64>,
}
#[derive(JsonSerialize)]
struct StageStat {
    mean_ms: f64,
    min_ms: f64,
    max_ms: f64,
}
pub fn run_stage_profile(options: &StageProfileOptions) -> Result<PathBuf> {
    if options.stages.is_empty() {
        bail!("fastpq-stage-profile requires at least one --stage");
    }
    fs::create_dir_all(&options.output_dir)
        .with_context(|| format!("failed to create {}", options.output_dir.display()))?;
    let mut stages = Vec::new();
    for kind in dedup_stages(&options.stages) {
        let spec = kind.spec();
        let summary = run_stage(spec, options)?;
        stages.push(summary);
    }
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into());
    let summary = StageProfileSummary {
        generated_at,
        rows: options.rows,
        warmups: options.warmups,
        iterations: options.iterations,
        release_build: options.release,
        capture_trace: options.capture_trace,
        stages,
    };
    let summary_path = options.output_dir.join("stage_profile_summary.json");
    let encoded =
        json::to_vec_pretty(&summary).context("failed to encode stage profile summary")?;
    fs::write(&summary_path, encoded)
        .with_context(|| format!("failed to write {}", summary_path.display()))?;
    eprintln!(
        "fastpq-stage-profile: wrote {}",
        display_path(&summary_path)
    );
    Ok(summary_path)
}
fn run_stage(spec: StageSpec, options: &StageProfileOptions) -> Result<StageSummary> {
    eprintln!("fastpq-stage-profile: running {}", spec.label);
    let stage_dir = options.output_dir.join(spec.dir);
    fs::create_dir_all(&stage_dir)
        .with_context(|| format!("failed to create {}", stage_dir.display()))?;
    let bench_path = stage_dir.join("fastpq_metal_bench.json");
    let mut command = Command::new("cargo");
    command.current_dir(workspace_root());
    command.arg("run");
    if options.release {
        command.arg("--release");
    }
    command.args([
        "-p",
        "fastpq_prover",
        "--features",
        "dev-tools,fastpq-gpu",
        "--bin",
        "fastpq_metal_bench",
        "--",
    ]);
    command.arg("--rows").arg(options.rows.to_string());
    command.arg("--warmups").arg(options.warmups.to_string());
    command
        .arg("--iterations")
        .arg(options.iterations.to_string());
    if options.gpu_probe {
        command.arg("--gpu-probe");
    }
    if options.capture_trace {
        let trace_root = options.trace_dir.as_ref().unwrap_or(&stage_dir);
        fs::create_dir_all(trace_root).with_context(|| {
            format!(
                "failed to create Metal trace directory {}",
                trace_root.display()
            )
        })?;
        command.arg("--trace-auto");
        command.arg("--trace-dir").arg(trace_root);
        if let Some(template) = &options.trace_template {
            command.arg("--trace-template").arg(template);
        }
        if let Some(seconds) = options.trace_seconds {
            command.arg("--trace-seconds").arg(seconds.to_string());
        }
    }
    command.arg("--operation").arg(spec.operation);
    command.arg("--output").arg(&bench_path);
    let status = command
        .status()
        .context("failed to run fastpq_metal_bench")?;
    ensure!(
        status.success(),
        "fastpq_metal_bench exited with {status} for stage {}",
        spec.label
    );
    let data = fs::read_to_string(&bench_path)
        .with_context(|| format!("failed to read {}", bench_path.display()))?;
    let payload: Value = json::from_str(&data)
        .with_context(|| format!("failed to parse {}", bench_path.display()))?;
    build_stage_summary(spec, &payload, &bench_path)
}
fn build_stage_summary(
    spec: StageSpec,
    payload: &Value,
    bench_path: &Path,
) -> Result<StageSummary> {
    let validated = digest384_report::report_from_root(payload).map_err(|error| eyre!(error))?;
    let report = validated.as_object().expect("validated report object");
    let operations = report
        .get("operations")
        .and_then(|value| value.as_array())
        .ok_or_else(|| eyre!("bench {} missing report.operations", bench_path.display()))?;
    let entry = operations
        .iter()
        .find(|value| value.get("operation").and_then(|op| op.as_str()) == Some(spec.operation));
    let op_value =
        entry.ok_or_else(|| eyre!("bench {} missing {}", bench_path.display(), spec.operation))?;
    let stats = parse_stage_stats(op_value)
        .ok_or_else(|| eyre!("operation {} missing stats", spec.operation))?;
    let trace_artifact = report
        .get("metal_trace_output")
        .and_then(|value| value.as_str())
        .map(PathBuf::from)
        .map(|path| display_path(&path));
    Ok(StageSummary {
        validated_report: payload.clone(),
        stage: spec.label.to_string(),
        operation: spec.operation.to_string(),
        benchmark_json: display_path(bench_path),
        trace_artifact,
        stats,
        digest384: op_value.get("digest384").cloned(),
        metal_dispatch_queue: report.get("metal_dispatch_queue").cloned(),
        column_staging: report.get("column_staging").cloned(),
        kernel_profiles: report.get("kernel_profiles").cloned(),
        post_tile_dispatches: report.get("post_tile_dispatches").cloned(),
        twiddle_cache: report.get("twiddle_cache").cloned(),
        device_profile: report.get("device_profile").cloned(),
        metal_heuristics: report.get("metal_heuristics").cloned(),
    })
}
fn parse_stage_stats(value: &Value) -> Option<StageStats> {
    let cpu = value.get("cpu")?.as_object()?;
    let cpu_stats = StageStat {
        mean_ms: cpu.get("mean_ms")?.as_f64()?,
        min_ms: cpu.get("min_ms")?.as_f64()?,
        max_ms: cpu.get("max_ms")?.as_f64()?,
    };
    let gpu_stats = value.get("gpu").and_then(|gpu| {
        let obj = gpu.as_object()?;
        Some(StageStat {
            mean_ms: obj.get("mean_ms")?.as_f64()?,
            min_ms: obj.get("min_ms")?.as_f64()?,
            max_ms: obj.get("max_ms")?.as_f64()?,
        })
    });
    let speedup_ratio = value
        .get("speedup")
        .and_then(|speedup| speedup.get("ratio"))
        .and_then(|ratio| ratio.as_f64());
    let speedup_delta_ms = value
        .get("speedup")
        .and_then(|speedup| speedup.get("delta_ms"))
        .and_then(|delta| delta.as_f64());
    Some(StageStats {
        cpu: cpu_stats,
        gpu: gpu_stats,
        speedup_ratio,
        speedup_delta_ms,
        columns: value.get("columns").and_then(|col| col.as_u64()),
        input_len: value.get("input_len").and_then(|len| len.as_u64()),
    })
}
fn dedup_stages(stages: &[StageKind]) -> Vec<StageKind> {
    let mut set = BTreeSet::new();
    for stage in stages {
        set.insert(*stage);
    }
    set.into_iter().collect()
}
fn stage_profile_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .unwrap_or_else(|_| "unknown".into())
}
#[derive(Debug, Clone)]
pub struct CudaSuiteOptions {
    pub rows: usize,
    pub warmups: usize,
    pub iterations: usize,
    pub column_count: usize,
    pub operation: Option<StageKind>,
    pub require_gpu: bool,
    pub output: PathBuf,
    pub raw_output: PathBuf,
    pub wrap_output: bool,
    pub wrapper: PathBuf,
    pub require_lde_mean_ms: f64,
    pub require_digest384_mean_ms: f64,
    pub labels: BTreeMap<String, String>,
    pub row_usage: Option<PathBuf>,
    pub device: Option<String>,
    pub notes: Option<String>,
    pub accel_instance: Option<String>,
    pub accel_state_json: Option<PathBuf>,
    pub accel_state_prom: Option<PathBuf>,
    pub sign_output: bool,
    pub gpg_key: Option<String>,
    pub dry_run: bool,
}
impl Default for CudaSuiteOptions {
    fn default() -> Self {
        let output = default_cuda_bench_output_path();
        let raw_output = default_cuda_raw_output(&output);
        Self {
            rows: 20_000,
            warmups: 1,
            iterations: 5,
            column_count: 16,
            operation: None,
            require_gpu: false,
            output,
            raw_output,
            wrap_output: true,
            wrapper: default_wrapper_path(),
            require_lde_mean_ms: 950.0,
            require_digest384_mean_ms: 1_000.0,
            labels: BTreeMap::new(),
            row_usage: None,
            device: None,
            notes: None,
            accel_instance: None,
            accel_state_json: None,
            accel_state_prom: None,
            sign_output: false,
            gpg_key: None,
            dry_run: false,
        }
    }
}
#[derive(Debug, Clone)]
pub struct CudaSuiteResult {
    pub raw_output: PathBuf,
    pub wrapped_output: Option<PathBuf>,
    pub summary: PathBuf,
    pub dry_run: bool,
}
#[derive(Clone, JsonSerialize)]
struct RecordedCommand {
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: String,
}
#[derive(JsonSerialize)]
struct CudaSuiteSummary {
    raw_output: String,
    #[norito(skip_serializing_if = "Option::is_none")]
    wrapped_output: Option<String>,
    dry_run: bool,
    rows: usize,
    warmups: usize,
    iterations: usize,
    columns: usize,
    operation: String,
    require_gpu: bool,
    #[norito(skip_serializing_if = "Option::is_none")]
    require_lde_mean_ms: Option<f64>,
    #[norito(skip_serializing_if = "Option::is_none")]
    require_digest384_mean_ms: Option<f64>,
    #[norito(skip_serializing_if = "Option::is_none")]
    row_usage: Option<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    #[norito(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[norito(skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    commands: Vec<RecordedCommand>,
}
struct CommandPlan {
    record: RecordedCommand,
    command: Command,
}
impl CudaSuiteOptions {
    fn operation_arg(&self) -> &'static str {
        self.operation
            .map(StageKind::cuda_operation)
            .unwrap_or("all")
    }
    fn requires_lde_threshold(&self) -> bool {
        self.operation.is_none() || self.operation == Some(StageKind::Lde)
    }
    fn requires_digest384_threshold(&self) -> bool {
        self.operation.is_none() || self.operation == Some(StageKind::Digest384TraceColumns)
    }
}
fn validate_cuda_suite_options(options: &CudaSuiteOptions) -> Result<()> {
    ensure!(options.rows > 0, "fastpq-cuda-suite requires --rows > 0");
    ensure!(
        options.iterations > 0,
        "fastpq-cuda-suite requires --iterations > 0"
    );
    ensure!(
        options.column_count > 0,
        "fastpq-cuda-suite requires --columns > 0"
    );
    ensure!(
        options.rows.checked_next_power_of_two().is_some(),
        "fastpq-cuda-suite --rows exceeds supported range"
    );
    if options.wrap_output {
        ensure!(
            options.output != options.raw_output,
            "fastpq-cuda-suite requires distinct --output and --raw-output when wrapping"
        );
    }
    if options.wrap_output && options.requires_lde_threshold() {
        ensure!(
            options.require_lde_mean_ms.is_finite() && options.require_lde_mean_ms >= 0.0,
            "fastpq-cuda-suite requires finite non-negative --require-lde-mean-ms"
        );
    }
    if options.wrap_output && options.requires_digest384_threshold() {
        ensure!(
            options.require_digest384_mean_ms.is_finite()
                && options.require_digest384_mean_ms >= 0.0,
            "fastpq-cuda-suite requires finite non-negative --require-digest384-mean-ms"
        );
    }
    Ok(())
}
pub fn run_cuda_suite(options: &CudaSuiteOptions) -> Result<CudaSuiteResult> {
    validate_cuda_suite_options(options)?;
    fs::create_dir_all(
        options
            .output
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(workspace_root),
    )
    .with_context(|| format!("failed to create {}", options.output.display()))?;
    fs::create_dir_all(
        options
            .raw_output
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(workspace_root),
    )
    .with_context(|| format!("failed to create {}", options.raw_output.display()))?;
    let mut bench = build_cuda_bench_command(options)?;
    let bench_record = bench.record.clone();
    let mut wrap = options
        .wrap_output
        .then(|| build_wrap_command(options))
        .transpose()?;
    let wrap_record = wrap.as_ref().map(|plan| plan.record.clone());
    let mut commands = Vec::new();
    if options.dry_run {
        commands.push(bench_record);
        if let Some(plan) = wrap_record {
            commands.push(plan);
        }
        let summary = write_cuda_suite_summary(options, &commands)?;
        eprintln!(
            "fastpq-cuda-suite: dry run wrote plan {}",
            display_path(&summary)
        );
        return Ok(CudaSuiteResult {
            raw_output: options.raw_output.clone(),
            wrapped_output: wrap.as_ref().map(|_| options.output.clone()),
            summary,
            dry_run: true,
        });
    }
    run_command(&mut bench)?;
    commands.push(bench_record);
    if let Some(plan) = wrap.as_mut() {
        run_command(plan)?;
        if let Some(record) = wrap_record {
            commands.push(record);
        }
    }
    let summary = write_cuda_suite_summary(options, &commands)?;
    eprintln!("fastpq-cuda-suite: wrote plan {}", display_path(&summary));
    Ok(CudaSuiteResult {
        raw_output: options.raw_output.clone(),
        wrapped_output: options.wrap_output.then(|| options.output.clone()),
        summary,
        dry_run: false,
    })
}
fn write_cuda_suite_summary(
    options: &CudaSuiteOptions,
    commands: &[RecordedCommand],
) -> Result<PathBuf> {
    let summary_path = plan_summary_path(&options.output);
    let summary_dir = summary_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(workspace_root);
    fs::create_dir_all(&summary_dir)
        .with_context(|| format!("failed to create {}", summary_dir.display()))?;
    let summary = CudaSuiteSummary {
        raw_output: display_path(&options.raw_output),
        wrapped_output: options.wrap_output.then(|| display_path(&options.output)),
        dry_run: options.dry_run,
        rows: options.rows,
        warmups: options.warmups,
        iterations: options.iterations,
        columns: options.column_count,
        operation: options.operation_arg().to_owned(),
        require_gpu: options.require_gpu,
        require_lde_mean_ms: options
            .requires_lde_threshold()
            .then_some(options.require_lde_mean_ms),
        require_digest384_mean_ms: options
            .requires_digest384_threshold()
            .then_some(options.require_digest384_mean_ms),
        row_usage: options.row_usage.as_deref().map(display_path),
        device: options.device.clone(),
        notes: options.notes.clone(),
        labels: options.labels.clone(),
        commands: commands.to_vec(),
    };
    let encoded = json::to_vec_pretty(&summary).context("failed to encode CUDA suite summary")?;
    fs::write(&summary_path, encoded)
        .with_context(|| format!("failed to write {}", summary_path.display()))?;
    Ok(summary_path)
}
fn run_command(plan: &mut CommandPlan) -> Result<()> {
    let status = plan.command.status().context("failed to execute command")?;
    ensure!(
        status.success(),
        "command exited with {status} ({})",
        plan.record.program
    );
    Ok(())
}
fn build_cuda_bench_command(options: &CudaSuiteOptions) -> Result<CommandPlan> {
    validate_cuda_suite_options(options)?;
    let mut args = vec![
        "run".to_owned(),
        "--release".to_owned(),
        "-p".to_owned(),
        "fastpq_prover".to_owned(),
        "--bin".to_owned(),
        "fastpq_cuda_bench".to_owned(),
        "--features".to_owned(),
        "dev-tools,fastpq-gpu".to_owned(),
        "--".to_owned(),
        "--rows".to_owned(),
        options.rows.to_string(),
        "--iterations".to_owned(),
        options.iterations.to_string(),
        "--warmups".to_owned(),
        options.warmups.to_string(),
        "--column-count".to_owned(),
        options.column_count.to_string(),
        "--operation".to_owned(),
        options.operation_arg().to_owned(),
        "--output".to_owned(),
        display_path(&options.raw_output),
    ];
    if let Some(row_usage) = &options.row_usage {
        args.push("--row-usage".to_owned());
        args.push(display_path(row_usage));
    }
    if let Some(device) = &options.device {
        args.push("--device".to_owned());
        args.push(device.clone());
    }
    if let Some(notes) = &options.notes {
        args.push("--notes".to_owned());
        args.push(notes.clone());
    }
    if options.require_gpu {
        args.push("--require-gpu".to_owned());
    }
    let mut env = BTreeMap::new();
    env.insert("FASTPQ_GPU".into(), "gpu".into());
    let workspace = workspace_root();
    let mut command = Command::new("cargo");
    command.current_dir(&workspace);
    command.args(args.iter());
    for (key, value) in &env {
        command.env(key, value);
    }
    Ok(CommandPlan {
        record: RecordedCommand {
            program: "cargo".into(),
            args,
            env,
            cwd: display_path(&workspace),
        },
        command,
    })
}
fn build_wrap_command(options: &CudaSuiteOptions) -> Result<CommandPlan> {
    validate_cuda_suite_options(options)?;
    let mut args = vec![display_path(&options.wrapper)];
    if options.requires_lde_threshold() {
        args.push("--require-lde-mean-ms".to_owned());
        args.push(options.require_lde_mean_ms.to_string());
    }
    if options.requires_digest384_threshold() {
        args.push("--require-digest384-mean-ms".to_owned());
        args.push(options.require_digest384_mean_ms.to_string());
    }
    if let Some(row_usage) = &options.row_usage {
        args.push("--row-usage".to_owned());
        args.push(display_path(row_usage));
    }
    if let Some(instance) = &options.accel_instance {
        args.push("--accel-instance".to_owned());
        args.push(instance.clone());
    }
    if let Some(path) = &options.accel_state_json {
        args.push("--accel-state-json".to_owned());
        args.push(display_path(path));
    }
    if let Some(path) = &options.accel_state_prom {
        args.push("--accel-state-prom".to_owned());
        args.push(display_path(path));
    }
    for (key, value) in &options.labels {
        args.push("--label".to_owned());
        args.push(format!("{key}={value}"));
    }
    if options.sign_output {
        args.push("--sign-output".to_owned());
    }
    if let Some(key) = &options.gpg_key {
        args.push("--gpg-key".to_owned());
        args.push(key.clone());
    }
    args.push(display_path(&options.raw_output));
    args.push(display_path(&options.output));
    let workspace = workspace_root();
    let mut command = Command::new("python3");
    command.current_dir(&workspace);
    command.args(args.iter());
    Ok(CommandPlan {
        record: RecordedCommand {
            program: "python3".into(),
            args,
            env: BTreeMap::new(),
            cwd: display_path(&workspace),
        },
        command,
    })
}
fn plan_summary_path(output: &Path) -> PathBuf {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(workspace_root);
    let stem = output
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("fastpq_cuda_bench");
    parent.join(format!("{stem}_plan.json"))
}
pub fn default_cuda_bench_output_path() -> PathBuf {
    default_cuda_bench_output_path_for_operation(None)
}
pub fn default_cuda_bench_output_path_for_operation(operation: Option<StageKind>) -> PathBuf {
    let stem = operation
        .map(StageKind::cuda_operation)
        .map(|operation| format!("fastpq_cuda_bench_{operation}"))
        .unwrap_or_else(|| "fastpq_cuda_bench".to_owned());
    workspace_root()
        .join("artifacts")
        .join("fastpq_benchmarks")
        .join(format!("{stem}_{}.json", stage_profile_timestamp()))
}
pub fn default_cuda_raw_output(output: &Path) -> PathBuf {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(workspace_root);
    let stem = output
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("fastpq_cuda_bench");
    parent.join(format!("{stem}_raw.json"))
}
fn default_wrapper_path() -> PathBuf {
    workspace_root()
        .join("scripts")
        .join("fastpq")
        .join("wrap_benchmark.py")
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;
    fn sample_bundle(rows: u64) -> Value {
        let flat = digest384_report::test_report(rows, true);
        let report = digest384_report::test_report(rows, false);
        Value::Object([
            ("producer_schema".into(), Value::from("cuda_nested")),
            ("metadata".into(), norito::json!({"host": "synthetic-schema-test", "notes": "No device run or qualification"})),
            ("benchmarks".into(), flat), ("report".into(), report),
        ].into_iter().collect())
    }
    fn encode_test_bundle(bundle: &Value) -> Vec<u8> {
        // Keep both representations of intentional fixture mutations identical;
        // projection disagreement has separate adversarial controls in the shared owner.
        let mut bundle = bundle.clone();
        let mut report = bundle.get("benchmarks").unwrap().clone();
        for entry in report
            .get_mut("operations")
            .unwrap()
            .as_array_mut()
            .unwrap()
        {
            let map = entry.as_object_mut().unwrap();
            for (flat, group, field) in [
                ("cpu_mean_ms", "cpu", "mean_ms"),
                ("gpu_mean_ms", "gpu", "mean_ms"),
                ("speedup_ratio", "speedup", "ratio"),
                ("speedup_delta_ms", "speedup", "delta_ms"),
            ] {
                if let Some(value) = map.remove(flat) {
                    let object = map
                        .entry(group.into())
                        .or_insert_with(|| Value::Object(json::Map::new()))
                        .as_object_mut()
                        .unwrap();
                    object.insert(field.into(), value);
                }
            }
        }
        bundle
            .as_object_mut()
            .unwrap()
            .insert("report".into(), report);
        json::to_vec_pretty(&bundle).unwrap()
    }
    fn write_bundle(temp: &TempDir, name: &str, rows: u64) -> PathBuf {
        let path = temp.path().join(name);
        let json = sample_bundle(rows);
        fs::write(&path, encode_test_bundle(&json)).unwrap();
        path
    }
    #[test]
    fn sign_manifest_exports_checked_public_key_payload() {
        let temp = TempDir::new().expect("tempdir");
        let key_hex = hex::encode([0x55u8; 32]);
        let key_path = temp.path().join("signing.key");
        fs::write(&key_path, &key_hex).expect("write key");
        let expected_key_pair: KeyPair = PrivateKey::from_hex(Algorithm::Ed25519, &key_hex)
            .expect("private key parses")
            .into();
        let (_, expected_public) = expected_key_pair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key is well-formed");
        let signature = sign_manifest(b"bench manifest", &key_path).expect("sign manifest");
        assert_eq!(signature.algorithm, "ed25519");
        assert_eq!(signature.public_key_hex, hex::encode(expected_public));
        Signature::try_from_bytes(
            &hex::decode(&signature.signature_hex).expect("decode signature"),
        )
        .expect("FastPQ manifest signature is non-empty and nonzero")
        .verify(expected_key_pair.public_key(), b"bench manifest")
        .expect("checked manifest signature verifies");
    }

    fn signed_manifest_fixture(temp: &TempDir) -> (PathBuf, String) {
        let private_hex = hex::encode([0x55u8; 32]);
        let private_path = temp.path().join("fixture-signing.key");
        fs::write(&private_path, &private_hex).expect("write fixture signing key");
        let key_pair: KeyPair = PrivateKey::from_hex(Algorithm::Ed25519, &private_hex)
            .expect("fixture key")
            .into();
        let (_, public_bytes) = key_pair.public_key().try_to_bytes().expect("public bytes");
        let output = temp.path().join("signed-manifest.json");
        write_bench_manifest(BenchManifestOptions {
            benches: vec![BenchInput {
                label: "metal".into(),
                path: write_bundle(temp, "capture.json", 20_000),
            }],
            output: output.clone(),
            signing_key: Some(private_path),
            require_rows: Some(20_000),
            max_operation_ms: BTreeMap::from([("lde".into(), 950.0)]),
            ..BenchManifestOptions::default()
        })
        .expect("write signed manifest");
        (output, hex::encode(public_bytes))
    }

    #[test]
    fn verify_bench_manifest_authenticates_the_generated_compact_preimage() {
        let temp = TempDir::new().expect("tempdir");
        let (path, trusted) = signed_manifest_fixture(&temp);
        verify_bench_manifest(&path, &trusted).expect("trusted signature verifies");
    }

    #[test]
    fn verify_bench_manifest_rejects_retired_microbench_even_when_null() {
        let temp = TempDir::new().expect("tempdir");
        let (path, trusted) = signed_manifest_fixture(&temp);
        verify_bench_manifest(&path, &trusted).expect("positive trusted signature");
        let original: Value = json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for retired in [Value::Null, norito::json!({"default": {"mean_ms": 1.0}})] {
            let mut changed = original.clone();
            changed
                .get_mut("payload")
                .unwrap()
                .get_mut("benches")
                .unwrap()
                .as_array_mut()
                .unwrap()[0]
                .as_object_mut()
                .unwrap()
                .insert("poseidon_microbench".into(), retired);
            fs::write(&path, json::to_vec(&changed).unwrap()).unwrap();
            let error = verify_bench_manifest(&path, &trusted)
                .expect_err("retired field must not be silently discarded");
            assert!(
                error
                    .to_string()
                    .contains("retired benchmark field `poseidon_microbench`"),
                "{error}"
            );
        }
    }
    #[test]
    fn manifest_writer_rejects_old_constraint_and_filter_names_before_output() {
        let temp = TempDir::new().unwrap();
        for mutant in 0..4 {
            let mut options = BenchManifestOptions {
                benches: vec![BenchInput {
                    label: "fixture".into(),
                    path: write_bundle(&temp, "fixture.json", 20_000),
                }],
                output: temp.path().join("must-not-exist.json"),
                ..BenchManifestOptions::default()
            };
            match mutant {
                0 => {
                    options
                        .max_operation_ms
                        .insert("poseidon_hash_columns".into(), 1.0);
                }
                1 => {
                    options
                        .min_operation_speedup
                        .insert("merkle-pairs".into(), 1.0);
                }
                2 => {
                    options
                        .label_max_operation_ms
                        .insert("fixture".into(), BTreeMap::from([("poseidon".into(), 1.0)]));
                }
                3 => {
                    options
                        .label_operation_filters
                        .insert("fixture".into(), BTreeSet::from(["ALL".into()]));
                }
                _ => unreachable!(),
            }
            let error = write_bench_manifest(options).expect_err("retired namespace must reject");
            assert!(
                error.to_string().contains("unknown benchmark operation"),
                "{error}"
            );
            assert!(!temp.path().join("must-not-exist.json").exists());
        }
    }
    #[test]
    fn signed_manifest_rejects_canonical_resigned_operation_aliases() {
        let temp = TempDir::new().unwrap();
        let (path, trusted) = signed_manifest_fixture(&temp);
        let bytes = fs::read(&path).unwrap();
        for mutant in 0..4 {
            let mut signed: SignedBenchManifest = json::from_slice(&bytes).unwrap();
            match mutant {
                0 => {
                    signed
                        .payload
                        .constraints
                        .max_operation_ms
                        .insert("poseidon_hash_columns".into(), 1.0);
                }
                1 => {
                    signed
                        .payload
                        .constraints
                        .min_operation_speedup
                        .insert("merkle-pairs".into(), 1.0);
                }
                2 => {
                    signed.payload.benches[0].operation_filter = Some("poseidon".into());
                }
                3 => {
                    signed.payload.benches[0].matrix_operation_filters = Some(vec!["ALL".into()]);
                }
                _ => unreachable!(),
            }
            let payload = json::to_vec(&signed.payload).unwrap();
            signed.signature =
                Some(sign_manifest(&payload, &temp.path().join("fixture-signing.key")).unwrap());
            fs::write(&path, json::to_vec(&signed).unwrap()).unwrap();
            let error = verify_bench_manifest(&path, &trusted)
                .expect_err("signed old namespace must fail current owner validation");
            assert!(
                error.to_string().contains("unknown benchmark operation"),
                "{error}"
            );
        }
    }
    #[test]
    fn signed_manifest_requires_canonical_matrix_filter_inventory() {
        let temp = TempDir::new().unwrap();
        let (path, trusted) = signed_manifest_fixture(&temp);
        let original = fs::read(&path).unwrap();
        let expected: Vec<String> = std::iter::once("all")
            .chain(digest384_report::OPERATIONS)
            .map(str::to_owned)
            .collect();
        assert_eq!(
            canonical_matrix_filters(&expected.iter().cloned().collect()),
            expected
        );
        let mut lexical = expected.clone();
        lexical.sort();
        let mut duplicate = expected.clone();
        duplicate.push("fft".into());
        let mut swapped = expected.clone();
        swapped.swap(1, 2);
        for (filters, valid) in [
            (expected, true),
            (vec!["lde".into()], true),
            (lexical, false),
            (duplicate, false),
            (swapped, false),
            (vec![], false),
        ] {
            let mut signed: SignedBenchManifest = json::from_slice(&original).unwrap();
            signed.payload.benches[0].matrix_operation_filters = Some(filters);
            let payload = json::to_vec(&signed.payload).unwrap();
            signed.signature =
                Some(sign_manifest(&payload, &temp.path().join("fixture-signing.key")).unwrap());
            fs::write(&path, json::to_vec(&signed).unwrap()).unwrap();
            let result = verify_bench_manifest(&path, &trusted);
            if valid {
                result.expect("canonical signed filter inventory verifies");
            } else {
                let error = result.expect_err("a valid signature cannot admit malformed inventory");
                assert!(
                    error.to_string().contains("canonical inventory order"),
                    "{error}"
                );
            }
        }
    }
    #[test]
    fn verify_bench_manifest_rejects_untrusted_signers_and_payload_tampering() {
        let temp = TempDir::new().expect("tempdir");
        let (path, trusted) = signed_manifest_fixture(&temp);
        let other: KeyPair = PrivateKey::from_hex(Algorithm::Ed25519, hex::encode([0x66u8; 32]))
            .expect("other key")
            .into();
        let (_, other_bytes) = other
            .public_key()
            .try_to_bytes()
            .expect("other public bytes");
        let error =
            verify_bench_manifest(&path, &hex::encode(other_bytes)).expect_err("wrong trust root");
        assert!(error.to_string().contains("not the trusted release key"));
        let mut manifest: SignedBenchManifest =
            json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest.payload.constraints.require_rows = Some(1);
        fs::write(&path, json::to_vec(&manifest).unwrap()).unwrap();
        let error = verify_bench_manifest(&path, &trusted).expect_err("modified signed payload");
        assert!(error.to_string().contains("signature verification failed"));
    }

    #[test]
    fn verify_bench_manifest_rejects_missing_malformed_or_wrong_algorithm_signatures() {
        let temp = TempDir::new().expect("tempdir");
        let (path, trusted) = signed_manifest_fixture(&temp);
        let original = fs::read(&path).unwrap();
        for invalid in ["missing", "algorithm", "malformed", "corrupt"] {
            let mut manifest: SignedBenchManifest = json::from_slice(&original).unwrap();
            match invalid {
                "missing" => manifest.signature = None,
                "algorithm" => manifest.signature.as_mut().unwrap().algorithm = "unknown".into(),
                "malformed" => manifest.signature.as_mut().unwrap().signature_hex = "zz".into(),
                "corrupt" => manifest.signature.as_mut().unwrap().signature_hex = "11".repeat(64),
                _ => unreachable!(),
            }
            fs::write(&path, json::to_vec(&manifest).unwrap()).unwrap();
            assert!(
                verify_bench_manifest(&path, &trusted).is_err(),
                "must reject {invalid}"
            );
        }
    }
    #[test]
    fn build_stage_summary_extracts_stats() {
        let payload = norito::json!({
            "report": {
                "operations": [{
                    "operation": "fft",
                    "columns": 16,
                    "input_len": 32768,
                    "gpu_recorded": true,
                    "cpu": { "mean_ms": 10.0, "min_ms": 9.5, "max_ms": 10.5 },
                    "gpu": { "mean_ms": 8.0, "min_ms": 7.5, "max_ms": 8.5 },
                    "speedup": { "ratio": 1.25, "delta_ms": 2.0 }
                }],
                "metal_dispatch_queue": { "limit": 4, "dispatch_count": 32 },
                "column_staging": { "idle_ms": 1.0 },
                "kernel_profiles": [{ "name": "fft", "mean_ms": 10.0 }]
            }
        });
        let spec = StageSpec {
            label: "fft",
            operation: "fft",
            dir: "fft",
        };
        let fixture = payload.get("report").expect("fixture report");
        let mut payload = digest384_report::test_metal_report(20_000);
        let map = payload.as_object_mut().unwrap();
        map.insert("operation_filter".into(), Value::from("fft"));
        for key in ["operations", "metal_dispatch_queue", "kernel_profiles"] {
            map.insert(key.into(), fixture.get(key).unwrap().clone());
        }
        map.insert("column_staging".into(), digest384_report::test_staging());
        let summary = build_stage_summary(spec, &payload, Path::new("fft.json")).expect("summary");
        digest384_report::report_from_root(&summary.validated_report)
            .expect("complete retained report revalidates");
        assert_eq!(summary.validated_report, payload);
        assert_eq!(summary.stage, "fft");
        assert_eq!(summary.operation, "fft");
        assert_eq!(summary.stats.columns, Some(16));
        assert_eq!(summary.stats.input_len, Some(32_768));
        assert!(summary.metal_dispatch_queue.is_some());
        assert!(summary.column_staging.is_some());
        assert!(summary.kernel_profiles.is_some());
        assert!(summary.stats.gpu.is_some());
    }
    #[test]
    fn dedup_stages_orders_unique() {
        let list = vec![
            StageKind::Fft,
            StageKind::Digest384TraceColumns,
            StageKind::Fft,
            StageKind::Lde,
            StageKind::Digest384TraceColumns,
        ];
        let deduped = dedup_stages(&list);
        assert_eq!(
            deduped,
            vec![
                StageKind::Fft,
                StageKind::Lde,
                StageKind::Digest384TraceColumns
            ]
        );
    }
    #[test]
    fn manifest_writes_with_constraints() {
        let temp = TempDir::new().expect("tempdir");
        let bench_path = write_bundle(&temp, "metal.json", 20_000);
        let mut options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "metal".into(),
                path: bench_path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: Some(19_000),
            max_operation_ms: [("lde".into(), 900.0)].into(),
            min_operation_speedup: [("fft".into(), 1.1)].into(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        options.max_operation_ms.extend([("fft".into(), 500.0)]);
        write_bench_manifest(options).expect("manifest succeeds");
        let manifest_text =
            fs::read_to_string(temp.path().join("manifest.json")).expect("read manifest");
        let manifest: json::Value = json::from_str(&manifest_text).expect("manifest json");
        let benches = manifest
            .get("payload")
            .and_then(|p| p.get("benches"))
            .and_then(|b| b.as_array())
            .expect("benches array");
        assert_eq!(benches.len(), 1, "expected single bench entry");
        assert_eq!(
            benches[0]
                .get("label")
                .and_then(|v| v.as_str())
                .expect("bench label"),
            "metal"
        );
        assert_eq!(
            benches[0]
                .get("operation_filter")
                .and_then(|v| v.as_str())
                .expect("operation filter"),
            "all"
        );
        assert_eq!(
            manifest
                .get("payload")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_u64())
                .expect("manifest version"),
            1
        );
    }
    #[test]
    fn manifest_rejects_bad_threshold() {
        let temp = TempDir::new().expect("tempdir");
        let bench_path = write_bundle(&temp, "metal.json", 18_000);
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "metal".into(),
                path: bench_path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: Some(20_000),
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        let err = write_bench_manifest(options).expect_err("rows threshold fails");
        assert!(
            err.to_string()
                .contains("rows 18000 below required threshold")
        );
    }
    #[test]
    fn matrix_constraints_enforced() {
        let temp = TempDir::new().expect("tempdir");
        let bench_path = write_bundle(&temp, "metal.json", 20_000);
        let manifest_path = temp.path().join("matrix_manifest.json");
        let manifest_value = norito::json!({
            "version": 1,
            "require_rows": 20000,
            "devices": [{
                "label": "metal",
                "operation_filters": ["all", "lde"],
                "max_operation_ms": { "lde": 1600.0 },
                "min_operation_speedup": { "fft": 1.05 }
            }]
        });
        fs::write(
            &manifest_path,
            json::to_vec_pretty(&manifest_value).unwrap(),
        )
        .unwrap();
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "metal".into(),
                path: bench_path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: Some(manifest_path.clone()),
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        write_bench_manifest(options).expect("matrix constraints pass");
        let mut slow_bundle = sample_bundle(20_000);
        if let Some(entries) = slow_bundle
            .get_mut("benchmarks")
            .and_then(|b| b.get_mut("operations"))
            .and_then(|ops| ops.as_array_mut())
        {
            for entry in entries {
                if entry
                    .get("operation")
                    .and_then(|v| v.as_str())
                    .is_some_and(|name| name == "lde")
                    && let Some(map) = entry.as_object_mut()
                {
                    map.insert("gpu_mean_ms".into(), norito::json!(2_500.0));
                }
            }
        }
        let slow_path = temp.path().join("metal_slow.json");
        fs::write(&slow_path, encode_test_bundle(&slow_bundle)).unwrap();
        let failing = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "metal".into(),
                path: slow_path,
            }],
            output: temp.path().join("manifest_slow.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: Some(manifest_path),
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        let err = write_bench_manifest(failing).expect_err("matrix threshold should fail");
        assert!(
            err.to_string().contains("exceeded max gpu_mean_ms"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn manifest_records_focused_operation_filter() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("cuda_lde.json");
        let mut bundle = sample_bundle(20_000);
        if let Some(map) = bundle.get_mut("benchmarks").and_then(Value::as_object_mut) {
            map.insert("operation_filter".into(), norito::json!("lde"));
            let mut entry = map
                .get("operations")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry.get("operation").and_then(Value::as_str) == Some("lde"))
                .unwrap()
                .clone();
            entry
                .as_object_mut()
                .unwrap()
                .insert("gpu_mean_ms".into(), Value::from(800.0));
            entry
                .as_object_mut()
                .unwrap()
                .insert("speedup_ratio".into(), Value::from(1.05));
            map.insert("operations".into(), Value::Array(vec![entry]));
        }
        fs::write(&path, encode_test_bundle(&bundle)).unwrap();
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "cuda-lde".into(),
                path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        write_bench_manifest(options).expect("manifest succeeds");
        let manifest_text =
            fs::read_to_string(temp.path().join("manifest.json")).expect("read manifest");
        let manifest: json::Value = json::from_str(&manifest_text).expect("manifest json");
        let bench = manifest["payload"]["benches"][0].clone();
        assert_eq!(bench["label"], norito::json!("cuda-lde"));
        assert_eq!(bench["operation_filter"], norito::json!("lde"));
    }
    #[test]
    fn manifest_accepts_focused_fft_without_digest384_work() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("metal_fft.json");
        let mut bundle = sample_bundle(20_000);
        if let Some(map) = bundle.get_mut("benchmarks").and_then(Value::as_object_mut) {
            map.insert("operation_filter".into(), norito::json!("fft"));
            let mut entry = map
                .get("operations")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry.get("operation").and_then(Value::as_str) == Some("fft"))
                .unwrap()
                .clone();
            entry
                .as_object_mut()
                .unwrap()
                .insert("gpu_mean_ms".into(), Value::from(420.0));
            entry
                .as_object_mut()
                .unwrap()
                .insert("speedup_ratio".into(), Value::from(1.2));
            map.insert("operations".into(), Value::Array(vec![entry]));
        }
        fs::write(&path, encode_test_bundle(&bundle)).unwrap();
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "metal-fft".into(),
                path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        write_bench_manifest(options).expect("focused FFT manifest succeeds");
    }
    #[test]
    fn manifest_rejects_digest384_without_complete_evidence() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("digest384.json");
        let mut bundle = sample_bundle(20_000);
        if let Some(map) = bundle.get_mut("benchmarks").and_then(Value::as_object_mut) {
            map.insert(
                "operation_filter".into(),
                norito::json!("digest384_trace_columns"),
            );
            let mut entry = map
                .get("operations")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| {
                    entry.get("operation").and_then(Value::as_str)
                        == Some("digest384_trace_columns")
                })
                .unwrap()
                .clone();
            entry
                .as_object_mut()
                .unwrap()
                .insert("gpu_mean_ms".into(), Value::from(700.0));
            entry
                .as_object_mut()
                .unwrap()
                .insert("speedup_ratio".into(), Value::from(1.1));
            entry.as_object_mut().unwrap().remove("digest384");
            map.insert("operations".into(), Value::Array(vec![entry]));
        }
        fs::write(&path, encode_test_bundle(&bundle)).unwrap();
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "digest384".into(),
                path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        let error = write_bench_manifest(options).expect_err("missing digest384 work must fail");
        assert!(
            error.to_string().contains("missing digest384 evidence"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn manifest_rejects_declared_digest384_without_operations() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("digest384_empty.json");
        let mut bundle = sample_bundle(20_000);
        if let Some(map) = bundle.get_mut("benchmarks").and_then(Value::as_object_mut) {
            map.insert(
                "operation_filter".into(),
                norito::json!("digest384_trace_columns"),
            );
            map.insert("operations".into(), norito::json!([]));
        }
        fs::write(&path, encode_test_bundle(&bundle)).unwrap();
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "digest384-empty".into(),
                path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        let error = write_bench_manifest(options).expect_err("missing digest384 work must fail");
        assert!(
            error.to_string().contains("operation rows do not match"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn manifest_rejects_declared_filter_operation_mismatch() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("metal_fft_with_lde.json");
        let mut bundle = sample_bundle(20_000);
        if let Some(map) = bundle.get_mut("benchmarks").and_then(Value::as_object_mut) {
            map.insert("operation_filter".into(), norito::json!("fft"));
            let mut entry = map
                .get("operations")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry.get("operation").and_then(Value::as_str) == Some("lde"))
                .unwrap()
                .clone();
            entry
                .as_object_mut()
                .unwrap()
                .insert("gpu_mean_ms".into(), Value::from(800.0));
            entry
                .as_object_mut()
                .unwrap()
                .insert("speedup_ratio".into(), Value::from(1.05));
            map.insert("operations".into(), Value::Array(vec![entry]));
        }
        fs::write(&path, encode_test_bundle(&bundle)).unwrap();
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "metal-fft-with-lde".into(),
                path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: None,
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        let error = write_bench_manifest(options).expect_err("filter mismatch must fail");
        assert!(
            error.to_string().contains("operation rows do not match"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn manifest_records_matrix_operation_filters() {
        let temp = TempDir::new().expect("tempdir");
        let bench_path = write_bundle(&temp, "cuda.json", 20_000);
        let manifest_path = temp.path().join("matrix_manifest.json");
        let manifest_value = norito::json!({
            "version": 1,
            "devices": [{
                "label": "cuda",
                "operation_filters": ["digest384_trace_columns", "lde", "fft"]
            }]
        });
        fs::write(
            &manifest_path,
            json::to_vec_pretty(&manifest_value).unwrap(),
        )
        .unwrap();
        let options = BenchManifestOptions {
            benches: vec![BenchInput {
                label: "cuda".into(),
                path: bench_path,
            }],
            output: temp.path().join("manifest.json"),
            signing_key: None,
            require_rows: None,
            max_operation_ms: BTreeMap::new(),
            min_operation_speedup: BTreeMap::new(),
            matrix_manifest: Some(manifest_path),
            label_max_operation_ms: BTreeMap::new(),
            label_min_operation_speedup: BTreeMap::new(),
            label_operation_filters: BTreeMap::new(),
        };
        write_bench_manifest(options).expect("manifest succeeds");
        let manifest_text =
            fs::read_to_string(temp.path().join("manifest.json")).expect("read manifest");
        let manifest: json::Value = json::from_str(&manifest_text).expect("manifest json");
        let bench = manifest["payload"]["benches"][0].clone();
        assert_eq!(
            bench["matrix_operation_filters"],
            norito::json!(["fft", "lde", "digest384_trace_columns"])
        );
    }
    #[test]
    fn manifest_omits_an_empty_matrix_filter_set() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("manifest.json");
        write_bench_manifest(BenchManifestOptions {
            benches: vec![BenchInput {
                label: "cuda".into(),
                path: write_bundle(&temp, "cuda.json", 20_000),
            }],
            output: output.clone(),
            label_operation_filters: BTreeMap::from([("cuda".into(), BTreeSet::new())]),
            ..BenchManifestOptions::default()
        })
        .expect("an empty source set represents absent matrix metadata");
        let bytes = fs::read(output).unwrap();
        let manifest: SignedBenchManifest = json::from_slice(&bytes).unwrap();
        validate_manifest_payload(&manifest.payload).expect("writer emits an admissible payload");
        let raw: Value = json::from_slice(&bytes).unwrap();
        assert!(
            raw["payload"]["benches"][0]
                .get("matrix_operation_filters")
                .is_none()
        );
    }
    #[test]
    fn cuda_suite_defaults_land_in_artifacts_dir() {
        let defaults = CudaSuiteOptions::default();
        let output = display_path(&defaults.output);
        assert!(
            output.contains("artifacts/fastpq_benchmarks/fastpq_cuda_bench_"),
            "unexpected default output path: {output}"
        );
        assert_eq!(
            defaults
                .raw_output
                .parent()
                .map(display_path)
                .unwrap_or_default(),
            defaults
                .output
                .parent()
                .map(display_path)
                .unwrap_or_default(),
            "raw output should share parent directory"
        );
    }
    #[test]
    fn filtered_cuda_default_output_includes_operation_name() {
        let output =
            default_cuda_bench_output_path_for_operation(Some(StageKind::Digest384TraceColumns));
        let output = display_path(&output);
        assert!(
            output
                .contains("artifacts/fastpq_benchmarks/fastpq_cuda_bench_digest384_trace_columns_"),
            "unexpected filtered output path: {output}"
        );
    }
    #[test]
    fn cuda_operation_filter_accepts_final_digest_ids_and_rejects_scalar_aliases() {
        assert_eq!(
            StageKind::from_str("digest384_trace_columns"),
            Some(StageKind::Digest384TraceColumns)
        );
        assert_eq!(
            StageKind::from_str("digest384_merkle_pairs"),
            Some(StageKind::Digest384MerklePairs)
        );
        for retired in [
            "poseidon",
            "poseidon-hash",
            "poseidon_hash_columns",
            "poseidon_merkle_pairs",
            "poseidon-merkle-pairs",
            "merkle-pairs",
            "bn254-poseidon-words",
        ] {
            assert!(StageKind::from_str(retired).is_none(), "{retired}");
        }
        assert_eq!(
            StageKind::Digest384MerklePairs.cuda_operation(),
            "digest384_merkle_pairs"
        );
        assert_eq!(
            StageKind::Bn254PoseidonWords.cuda_operation(),
            "bn254_poseidon_words"
        );
    }
    #[test]
    fn cuda_suite_rejects_zero_dimensions_before_planning() {
        let temp = TempDir::new().expect("tempdir");
        for (field, mut options) in [
            (
                "rows",
                CudaSuiteOptions {
                    rows: 0,
                    output: temp.path().join("rows-wrapped.json"),
                    raw_output: temp.path().join("rows-raw.json"),
                    ..CudaSuiteOptions::default()
                },
            ),
            (
                "iterations",
                CudaSuiteOptions {
                    iterations: 0,
                    output: temp.path().join("iterations-wrapped.json"),
                    raw_output: temp.path().join("iterations-raw.json"),
                    ..CudaSuiteOptions::default()
                },
            ),
            (
                "columns",
                CudaSuiteOptions {
                    column_count: 0,
                    output: temp.path().join("columns-wrapped.json"),
                    raw_output: temp.path().join("columns-raw.json"),
                    ..CudaSuiteOptions::default()
                },
            ),
        ] {
            options.wrap_output = false;
            let message = match build_cuda_bench_command(&options) {
                Ok(_) => panic!("invalid {field} accepted by CUDA suite planner"),
                Err(error) => error.to_string(),
            };
            assert!(
                message.contains(field),
                "error should identify invalid {field}: {message}"
            );
        }
    }
    #[test]
    fn cuda_suite_rejects_output_collision_when_wrapping() {
        let temp = TempDir::new().expect("tempdir");
        let same = temp.path().join("cuda.json");
        let options = CudaSuiteOptions {
            output: same.clone(),
            raw_output: same,
            dry_run: true,
            ..CudaSuiteOptions::default()
        };
        let message = match run_cuda_suite(&options) {
            Ok(_) => panic!("colliding CUDA suite outputs were accepted"),
            Err(error) => error.to_string(),
        };
        assert!(
            message.contains("distinct --output and --raw-output"),
            "unexpected collision error: {message}"
        );
    }
    #[test]
    fn cuda_suite_rejects_nonfinite_active_thresholds() {
        let temp = TempDir::new().expect("tempdir");
        let options = CudaSuiteOptions {
            output: temp.path().join("wrapped.json"),
            raw_output: temp.path().join("raw.json"),
            require_digest384_mean_ms: f64::NAN,
            dry_run: true,
            ..CudaSuiteOptions::default()
        };
        let message = match run_cuda_suite(&options) {
            Ok(_) => panic!("NaN CUDA digest384 threshold was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(
            message.contains("finite non-negative --require-digest384-mean-ms"),
            "unexpected threshold error: {message}"
        );
    }
    #[test]
    fn cuda_suite_ignores_thresholds_when_wrapping_is_disabled() {
        let temp = TempDir::new().expect("tempdir");
        let options = CudaSuiteOptions {
            output: temp.path().join("wrapped.json"),
            raw_output: temp.path().join("raw.json"),
            require_digest384_mean_ms: f64::NAN,
            wrap_output: false,
            ..CudaSuiteOptions::default()
        };
        build_cuda_bench_command(&options).expect("unused threshold should not block no-wrap run");
    }
    #[test]
    fn cuda_bench_command_builds_expected_args() {
        let temp = TempDir::new().expect("tempdir");
        let options = CudaSuiteOptions {
            rows: 128,
            warmups: 0,
            iterations: 2,
            column_count: 4,
            operation: Some(StageKind::Ifft),
            require_gpu: true,
            output: temp.path().join("wrapped.json"),
            raw_output: temp.path().join("raw.json"),
            wrap_output: false,
            wrapper: default_wrapper_path(),
            require_lde_mean_ms: 950.0,
            require_digest384_mean_ms: 1_000.0,
            labels: BTreeMap::new(),
            row_usage: Some(temp.path().join("row_usage.json")),
            device: Some("gpu0".into()),
            notes: Some("test run".into()),
            accel_instance: None,
            accel_state_json: None,
            accel_state_prom: None,
            sign_output: false,
            gpg_key: None,
            dry_run: false,
        };
        fs::write(
            options.row_usage.as_ref().unwrap(),
            json::to_vec_pretty(&norito::json!({ "batches": [] })).unwrap(),
        )
        .expect("write row usage");
        let plan = build_cuda_bench_command(&options).expect("build bench");
        let args: Vec<_> = plan.record.args.clone();
        assert_eq!(
            &args[..9],
            &[
                "run",
                "--release",
                "-p",
                "fastpq_prover",
                "--bin",
                "fastpq_cuda_bench",
                "--features",
                "dev-tools,fastpq-gpu",
                "--"
            ]
        );
        assert!(args.contains(&"--rows".to_string()));
        assert!(args.contains(&"128".to_string()));
        assert!(args.contains(&"--require-gpu".to_string()));
        assert!(args.contains(&"--operation".to_string()));
        assert!(args.contains(&"ifft".to_string()));
        assert!(
            plan.record
                .env
                .get("FASTPQ_GPU")
                .is_some_and(|value| value == "gpu"),
            "FASTPQ_GPU env should be set"
        );
    }
    #[test]
    fn cuda_wrap_command_applies_labels_and_thresholds() {
        let temp = TempDir::new().expect("tempdir");
        let mut options = CudaSuiteOptions {
            output: temp.path().join("wrapped.json"),
            raw_output: temp.path().join("raw.json"),
            accel_instance: Some("xeon-rtx".into()),
            require_lde_mean_ms: 777.0,
            require_digest384_mean_ms: 888.0,
            row_usage: Some(temp.path().join("row_usage.json")),
            ..CudaSuiteOptions::default()
        };
        options
            .labels
            .insert("device_class".into(), "xeon-rtx".into());
        let plan = build_wrap_command(&options).expect("wrap plan");
        let args = plan.record.args.join(" ");
        assert!(args.contains("--require-lde-mean-ms 777"));
        assert!(args.contains("--require-digest384-mean-ms 888"));
        assert!(args.contains("device_class=xeon-rtx"));
        assert!(args.contains("--accel-instance xeon-rtx"));
    }
    #[test]
    fn cuda_wrap_command_skips_irrelevant_thresholds_for_filtered_runs() {
        let temp = TempDir::new().expect("tempdir");
        let options = CudaSuiteOptions {
            output: temp.path().join("wrapped.json"),
            raw_output: temp.path().join("raw.json"),
            operation: Some(StageKind::Fft),
            require_lde_mean_ms: 777.0,
            require_digest384_mean_ms: 888.0,
            ..CudaSuiteOptions::default()
        };
        let plan = build_wrap_command(&options).expect("wrap plan");
        let args = plan.record.args.join(" ");
        assert!(!args.contains("--require-lde-mean-ms"));
        assert!(!args.contains("--require-digest384-mean-ms"));
    }
    #[test]
    fn cuda_wrap_command_keeps_selected_threshold_for_digest384_columns_only() {
        let temp = TempDir::new().expect("tempdir");
        let options = CudaSuiteOptions {
            output: temp.path().join("wrapped.json"),
            raw_output: temp.path().join("raw.json"),
            operation: Some(StageKind::Digest384TraceColumns),
            require_lde_mean_ms: 777.0,
            require_digest384_mean_ms: 888.0,
            ..CudaSuiteOptions::default()
        };
        let plan = build_wrap_command(&options).expect("wrap plan");
        let args = plan.record.args.join(" ");
        assert!(!args.contains("--require-lde-mean-ms"));
        assert!(args.contains("--require-digest384-mean-ms 888"));
    }
    #[test]
    fn cuda_suite_dry_run_writes_summary() {
        let temp = TempDir::new().expect("tempdir");
        let options = CudaSuiteOptions {
            output: temp.path().join("wrapped.json"),
            raw_output: temp.path().join("raw.json"),
            wrapper: default_wrapper_path(),
            wrap_output: false,
            rows: 16,
            iterations: 1,
            warmups: 0,
            operation: Some(StageKind::Lde),
            dry_run: true,
            ..CudaSuiteOptions::default()
        };
        let result = run_cuda_suite(&options).expect("run dry suite");
        assert!(result.summary.exists());
        let summary_text = fs::read_to_string(&result.summary).expect("read summary");
        let value: Value = json::from_str(&summary_text).expect("summary json");
        assert_eq!(value["dry_run"], norito::json!(true));
        assert_eq!(
            value["raw_output"].as_str(),
            Some(display_path(&options.raw_output).as_str())
        );
        assert_eq!(
            value["commands"].as_array().map(|array| array.len()),
            Some(1)
        );
        assert_eq!(value["operation"], norito::json!("lde"));
        assert_eq!(value["require_lde_mean_ms"], norito::json!(950.0));
        assert!(value.get("require_digest384_mean_ms").is_none());
    }
}
