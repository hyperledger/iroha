use crate::{JsonTarget, write_json_output};
use blake3::hash;
use hex::encode as hex_encode;
use integration_tests::da::pdp_potr::{DEFAULT_SEED, SimulationConfig, run_simulation};
use iroha_config::{
    base::read::ConfigReader,
    parameters::{
        actual::{DaIngest, DaReplicationPolicy},
        user,
    },
};
use iroha_crypto::Hash as CryptoHash;
use iroha_data_model::{
    block::decode_framed_signed_block,
    da::{
        commitment::{DaCommitmentBundle, DaCommitmentRecord},
        ingest::DaIngestReceipt,
        manifest::{ChunkCommitment, ChunkRole, DaManifestV1},
        types::{
            BlobClass, BlobCodec, BlobDigest, ChunkDigest, DaRentQuote, ErasureProfile,
            ExtraMetadata, FecScheme, MetadataEntry, MetadataVisibility, RetentionPolicy,
            StorageTicketId,
        },
    },
    sorafs::pin_registry::StorageClass,
};
use iroha_model_base::topology::LaneId;
use iroha_storage_client::da::{DaProofBenchmark, DaProofConfig, benchmark_da_proof_verification};
use norito::{
    decode_from_bytes,
    derive::{JsonDeserialize, JsonSerialize},
    json, to_bytes,
};
use sorafs_car::ChunkStore;
use sorafs_chunker::ChunkProfile;
use sorafs_manifest::ReplicationOrderV1;
use std::{
    collections::HashMap,
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use walkdir::WalkDir;
/// Options accepted by `cargo xtask da-threat-model-report`.
pub(crate) struct ThreatModelReportOptions {
    pub output: JsonTarget,
    pub seed: u64,
    pub config_path: Option<PathBuf>,
}
#[derive(Debug, Default, JsonDeserialize)]
struct SimulationConfigOverrides {
    nodes: Option<usize>,
    adversarial: Option<usize>,
    regions: Option<usize>,
    max_partition_regions: Option<usize>,
    epochs: Option<usize>,
    pdp_challenges_per_epoch: Option<usize>,
    potr_windows_per_epoch: Option<usize>,
    challenge_interval_ms: Option<u64>,
    partition_probability: Option<f64>,
    adversary_failure_probability: Option<f64>,
    honest_network_failure_probability: Option<f64>,
    potr_late_threshold: Option<usize>,
    detection_bias_no_partition: Option<f64>,
    repair_capacity_per_epoch: Option<usize>,
}
impl SimulationConfigOverrides {
    fn apply(self, config: &mut SimulationConfig) {
        macro_rules! apply_field {
            ($field:ident) => {
                if let Some(value) = self.$field {
                    config.$field = value;
                }
            };
        }
        apply_field!(nodes);
        apply_field!(adversarial);
        apply_field!(regions);
        apply_field!(max_partition_regions);
        apply_field!(epochs);
        apply_field!(pdp_challenges_per_epoch);
        apply_field!(potr_windows_per_epoch);
        apply_field!(partition_probability);
        apply_field!(adversary_failure_probability);
        apply_field!(honest_network_failure_probability);
        apply_field!(potr_late_threshold);
        apply_field!(detection_bias_no_partition);
        apply_field!(repair_capacity_per_epoch);
        if let Some(ms) = self.challenge_interval_ms {
            config.challenge_interval = Duration::from_millis(ms);
        }
    }
}
pub(crate) fn generate_threat_model_report(
    options: ThreatModelReportOptions,
) -> Result<(), Box<dyn Error>> {
    let mut config = SimulationConfig::default();
    if let Some(path) = options.config_path.as_deref() {
        let bytes = fs::read(path)?;
        let overrides: SimulationConfigOverrides = json::from_slice(&bytes)?;
        overrides.apply(&mut config);
    }
    config.validate();
    let stats = run_simulation(config, options.seed);
    let summary = stats.json_summary();
    write_json_output(&summary, options.output)
}
/// Default target when no `--seed` is provided.
pub(crate) const DEFAULT_REPORT_SEED: u64 = DEFAULT_SEED;
pub(crate) fn parse_seed(value: &str) -> Result<u64, Box<dyn Error>> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|err| err.into())
    } else {
        value.parse::<u64>().map_err(|err| err.into())
    }
}
/// Options accepted by `cargo xtask da-replication-audit`.
pub(crate) struct ReplicationAuditOptions {
    pub config: PathBuf,
    pub manifests: Vec<PathBuf>,
    pub replication_orders: Vec<PathBuf>,
    pub json_output: Option<JsonTarget>,
    pub plan_output: Option<JsonTarget>,
    pub allow_mismatch: bool,
}
/// Runs the replication audit command.
pub(crate) fn run_replication_audit(
    options: ReplicationAuditOptions,
) -> Result<(), Box<dyn Error>> {
    if options.manifests.is_empty() {
        return Err("da-replication-audit requires at least one --manifest".into());
    }
    let policy = load_replication_policy(&options.config)?;
    let manifests = load_manifests(&options.manifests)?;
    let orders = load_replication_orders(&options.replication_orders)?;
    let mut manifests_out = Vec::with_capacity(manifests.len());
    let mut order_index: HashMap<[u8; 32], Vec<LoadedOrder>> = HashMap::new();
    for order in orders {
        order_index
            .entry(order.order.manifest_digest)
            .or_default()
            .push(order);
    }
    for manifest in manifests {
        let matching_orders = order_index.remove(&manifest.digest).unwrap_or_default();
        manifests_out.push(audit_manifest(&policy, manifest, matching_orders));
    }
    let summary = build_summary(&manifests_out);
    let report = ReplicationAuditReport {
        summary: summary.clone(),
        manifests: manifests_out,
    };
    let remediation_plan = build_remediation_plan(&report.manifests);
    if let Some(target) = options.json_output.clone() {
        let value = json::to_value(&report)?;
        write_json_output(&value, target)?;
    }
    if let Some(target) = options.plan_output.clone() {
        let value = json::to_value(&remediation_plan)?;
        write_json_output(&value, target)?;
    }
    print_report(&report);
    let has_failures = summary.policy_mismatches > 0 || summary.replica_shortfalls > 0;
    if has_failures && !options.allow_mismatch {
        return Err("replication audit detected policy mismatches or replica shortfalls".into());
    }
    Ok(())
}
#[derive(Clone, Debug, JsonSerialize)]
struct ReplicationAuditReport {
    summary: AuditSummary,
    manifests: Vec<ManifestAudit>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct AuditSummary {
    total: usize,
    ok: usize,
    policy_mismatches: usize,
    replica_shortfalls: usize,
    status: ManifestAuditStatus,
}
#[derive(Clone, Debug, JsonSerialize)]
struct ManifestAudit {
    manifest_path: String,
    blob_class: String,
    manifest_digest_hex: String,
    policy_match: bool,
    replication_orders_found: usize,
    replica_shortfall: bool,
    status: ManifestAuditStatus,
    policy: PolicySnapshot,
    expected_policy: PolicySnapshot,
    replication: Vec<ReplicationOrderSnapshot>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct PolicySnapshot {
    hot_retention_secs: u64,
    cold_retention_secs: u64,
    required_replicas: u16,
    storage_class: String,
    governance_tag: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct ReplicationOrderSnapshot {
    order_path: String,
    order_id_hex: String,
    target_replicas: u16,
    assignment_count: usize,
    target_matches_policy: bool,
    assignments_sufficient: bool,
}
#[derive(Clone, Debug, JsonSerialize)]
struct ReplicationRemediationPlan {
    manifests: Vec<ManifestRemediation>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct ManifestRemediation {
    manifest_path: String,
    manifest_digest_hex: String,
    blob_class: String,
    policy_tag: String,
    required_replicas: u16,
    assigned_replicas: usize,
    missing_replicas: u16,
    storage_class: String,
    governance_tag: String,
    notes: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestAuditStatus {
    Ok,
    ReplicaShortfall,
    PolicyMismatch,
}
impl ManifestAuditStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ReplicaShortfall => "replica_shortfall",
            Self::PolicyMismatch => "policy_mismatch",
        }
    }
    fn severity(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::ReplicaShortfall => 1,
            Self::PolicyMismatch => 2,
        }
    }
    fn escalate(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
    fn from_flags(policy_match: bool, replica_shortfall: bool) -> Self {
        if !policy_match {
            Self::PolicyMismatch
        } else if replica_shortfall {
            Self::ReplicaShortfall
        } else {
            Self::Ok
        }
    }
}
impl norito::json::FastJsonWrite for ManifestAuditStatus {
    fn write_json(&self, out: &mut String) {
        norito::json::write_json_string(self.as_str(), out);
    }
}
#[derive(Clone)]
struct LoadedManifest {
    path: PathBuf,
    manifest: DaManifestV1,
    digest: [u8; 32],
}
#[derive(Clone)]
struct LoadedOrder {
    path: PathBuf,
    order: ReplicationOrderV1,
}
fn load_manifests(paths: &[PathBuf]) -> Result<Vec<LoadedManifest>, Box<dyn Error>> {
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        entries.push(load_manifest(path)?);
    }
    Ok(entries)
}
fn load_manifest(path: &Path) -> Result<LoadedManifest, Box<dyn Error>> {
    let manifest = read_manifest(path)?;
    let bytes = to_bytes(&manifest)?;
    let digest: [u8; 32] = hash(&bytes).into();
    Ok(LoadedManifest {
        path: path.to_path_buf(),
        manifest,
        digest,
    })
}
fn read_manifest(path: &Path) -> Result<DaManifestV1, Box<dyn Error>> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
    {
        Some(true) => {
            let raw = fs::read_to_string(path)?;
            let manifest = json::from_str(&raw)?;
            Ok(manifest)
        }
        _ => {
            let bytes = fs::read(path)?;
            let manifest = decode_from_bytes::<DaManifestV1>(&bytes)?;
            Ok(manifest)
        }
    }
}
fn load_replication_orders(paths: &[PathBuf]) -> Result<Vec<LoadedOrder>, Box<dyn Error>> {
    let mut orders = Vec::with_capacity(paths.len());
    for path in paths {
        orders.push(load_replication_order(path)?);
    }
    Ok(orders)
}
fn load_replication_order(path: &Path) -> Result<LoadedOrder, Box<dyn Error>> {
    let order = match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
    {
        Some(true) => {
            let raw = fs::read_to_string(path)?;
            json::from_str(&raw)?
        }
        _ => {
            let bytes = fs::read(path)?;
            decode_from_bytes::<ReplicationOrderV1>(&bytes)?
        }
    };
    Ok(LoadedOrder {
        path: path.to_path_buf(),
        order,
    })
}
fn audit_manifest(
    policy: &DaReplicationPolicy,
    manifest: LoadedManifest,
    matching_orders: Vec<LoadedOrder>,
) -> ManifestAudit {
    let expected = policy.retention_for(manifest.manifest.blob_class, None);
    let policy_match = manifest.manifest.retention_policy == *expected;
    let mut replica_shortfall = expected.required_replicas > 0 && matching_orders.is_empty();
    let mut replication = Vec::with_capacity(matching_orders.len());
    for order in matching_orders {
        let assignments = order.order.assignments.len();
        let target_matches_policy = order.order.target_replicas == expected.required_replicas;
        let assignments_sufficient = usize::from(order.order.target_replicas) <= assignments;
        if !target_matches_policy || !assignments_sufficient {
            replica_shortfall = true;
        }
        replication.push(ReplicationOrderSnapshot {
            order_path: order.path.display().to_string(),
            order_id_hex: hex_encode(order.order.order_id),
            target_replicas: order.order.target_replicas,
            assignment_count: assignments,
            target_matches_policy,
            assignments_sufficient,
        });
    }
    ManifestAudit {
        manifest_path: manifest.path.display().to_string(),
        blob_class: blob_class_label(manifest.manifest.blob_class).to_string(),
        manifest_digest_hex: hex_encode(manifest.digest),
        policy_match,
        replication_orders_found: replication.len(),
        replica_shortfall,
        status: ManifestAuditStatus::from_flags(policy_match, replica_shortfall),
        policy: policy_snapshot(&manifest.manifest.retention_policy),
        expected_policy: policy_snapshot(expected),
        replication,
    }
}
fn load_replication_policy(path: &Path) -> Result<DaReplicationPolicy, Box<dyn Error>> {
    let reader = ConfigReader::new()
        .read_toml_with_extends(path)
        .map_err(|err| format!("failed to read config {path:?}: {err}"))?;
    let config = reader
        .read_and_complete::<user::Root>()
        .map_err(|err| format!("failed to complete config {path:?}: {err}"))?
        .parse()
        .map_err(|err| format!("failed to parse config {path:?}: {err}"))?;
    Ok(config.torii.da_ingest.replication_policy)
}
fn policy_snapshot(policy: &RetentionPolicy) -> PolicySnapshot {
    PolicySnapshot {
        hot_retention_secs: policy.hot_retention_secs,
        cold_retention_secs: policy.cold_retention_secs,
        required_replicas: policy.required_replicas,
        storage_class: storage_class_label(policy.storage_class).to_string(),
        governance_tag: policy.governance_tag.0.clone(),
    }
}
fn storage_class_label(class: StorageClass) -> &'static str {
    match class {
        StorageClass::Hot => "hot",
        StorageClass::Warm => "warm",
        StorageClass::Cold => "cold",
    }
}
fn blob_class_label(class: BlobClass) -> &'static str {
    match class {
        BlobClass::TaikaiSegment => "taikai_segment",
        BlobClass::NexusLaneSidecar => "nexus_lane_sidecar",
        BlobClass::GovernanceArtifact => "governance_artifact",
        BlobClass::Custom(_) => "custom",
    }
}
fn build_remediation_plan(manifests: &[ManifestAudit]) -> ReplicationRemediationPlan {
    let mut entries = Vec::new();
    for audit in manifests {
        if matches!(audit.status, ManifestAuditStatus::Ok) {
            continue;
        }
        let required = audit.expected_policy.required_replicas;
        let assigned = audit
            .replication
            .iter()
            .map(|order| order.assignment_count as u16)
            .max()
            .unwrap_or(0);
        let missing = required.saturating_sub(assigned);
        let mut notes = Vec::new();
        if !audit.policy_match {
            notes.push(String::from(
                "retention or governance tag drifted from configured policy",
            ));
        }
        if audit.replica_shortfall || missing > 0 {
            notes.push(format!(
                "replicas short of policy target by {}",
                missing.max(1)
            ));
        }
        entries.push(ManifestRemediation {
            manifest_path: audit.manifest_path.clone(),
            manifest_digest_hex: audit.manifest_digest_hex.clone(),
            blob_class: audit.blob_class.clone(),
            policy_tag: audit.expected_policy.governance_tag.clone(),
            required_replicas: required,
            assigned_replicas: assigned as usize,
            missing_replicas: missing,
            storage_class: audit.expected_policy.storage_class.clone(),
            governance_tag: audit.expected_policy.governance_tag.clone(),
            notes,
        });
    }
    ReplicationRemediationPlan { manifests: entries }
}
fn build_summary(results: &[ManifestAudit]) -> AuditSummary {
    let mut summary = AuditSummary {
        total: results.len(),
        ok: 0,
        policy_mismatches: 0,
        replica_shortfalls: 0,
        status: ManifestAuditStatus::Ok,
    };
    for result in results {
        summary.status = summary.status.escalate(result.status);
        match result.status {
            ManifestAuditStatus::Ok => summary.ok += 1,
            ManifestAuditStatus::ReplicaShortfall => summary.replica_shortfalls += 1,
            ManifestAuditStatus::PolicyMismatch => summary.policy_mismatches += 1,
        }
    }
    summary
}
fn print_report(report: &ReplicationAuditReport) {
    for manifest in &report.manifests {
        println!(
            "Manifest: {} [{}]",
            manifest.manifest_path, manifest.blob_class
        );
        println!("  Status: {}", manifest.status.as_str());
        println!(
            "  Actual retention: hot={}s cold={}s replicas={} storage={} tag={}",
            manifest.policy.hot_retention_secs,
            manifest.policy.cold_retention_secs,
            manifest.policy.required_replicas,
            manifest.policy.storage_class,
            manifest.policy.governance_tag
        );
        if !manifest.policy_match {
            println!(
                "  Expected retention: hot={}s cold={}s replicas={} storage={} tag={}",
                manifest.expected_policy.hot_retention_secs,
                manifest.expected_policy.cold_retention_secs,
                manifest.expected_policy.required_replicas,
                manifest.expected_policy.storage_class,
                manifest.expected_policy.governance_tag
            );
        }
        if manifest.replication.is_empty() {
            println!("  Replication orders: none provided");
        } else {
            println!("  Replication orders:");
            for order in &manifest.replication {
                let mut notes = Vec::new();
                if !order.target_matches_policy {
                    notes.push("target≠policy");
                }
                if !order.assignments_sufficient {
                    notes.push("assignments<target");
                }
                let note_str = if notes.is_empty() {
                    String::from("ok")
                } else {
                    notes.join(", ")
                };
                println!(
                    "    - {} (target {} replicas, {} assignments) [{note_str}]",
                    order.order_id_hex, order.target_replicas, order.assignment_count
                );
            }
        }
        println!();
    }
    println!(
        "Summary: {}/{} ok · {} policy mismatch · {} replica shortfall",
        report.summary.ok,
        report.summary.total,
        report.summary.policy_mismatches,
        report.summary.replica_shortfalls
    );
    println!("Overall status: {}", report.summary.status.as_str());
}
/// Options for the DA commitment reconciliation command.
pub(crate) struct CommitmentReconcileOptions {
    pub receipts: Vec<PathBuf>,
    pub blocks: Vec<PathBuf>,
    pub json_output: Option<JsonTarget>,
    pub allow_unexpected_commitments: bool,
}
/// Options for the DA privilege audit command.
pub(crate) struct PrivilegeAuditOptions {
    pub config: PathBuf,
    pub extra_paths: Vec<PathBuf>,
    pub json_output: Option<JsonTarget>,
}
/// Local benchmark target; independent of node verifier admission policy.
const DEFAULT_PROOF_BENCH_BUDGET_MS: u64 = 20;

/// Options for benchmarking DA proof verification.
pub(crate) struct ProofBenchOptions {
    pub manifest: PathBuf,
    pub payload: PathBuf,
    pub payload_bytes: Option<usize>,
    pub sample_count: Option<usize>,
    pub sample_seed: Option<u64>,
    pub budget_ms: Option<u64>,
    pub json_output: Option<JsonTarget>,
    pub markdown_output: Option<PathBuf>,
    pub iterations: usize,
}
struct ReceiptArtifact {
    receipt: DaIngestReceipt,
    source: String,
}
struct CommitmentArtifact {
    record: DaCommitmentRecord,
    source: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct ReconciliationReport {
    summary: ReconciliationSummary,
    missing_commitments: Vec<MissingCommitment>,
    mismatches: Vec<CommitmentMismatch>,
    unexpected_commitments: Vec<UnexpectedCommitment>,
    duplicate_receipts: Vec<DuplicateTicket>,
    duplicate_commitments: Vec<DuplicateTicket>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct ReconciliationSummary {
    total_receipts: usize,
    total_commitments: usize,
    matched: usize,
    missing_from_blocks: usize,
    unexpected_commitments: usize,
    mismatches: usize,
    duplicate_receipts: usize,
    duplicate_commitments: usize,
    status: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct MissingCommitment {
    ticket_hex: String,
    lane_id: u32,
    epoch: u64,
    client_blob_id_hex: String,
    manifest_hash_hex: String,
    chunk_root_hex: String,
    source: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct CommitmentMismatch {
    ticket_hex: String,
    receipt_source: String,
    commitment_source: String,
    differences: Vec<String>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct UnexpectedCommitment {
    ticket_hex: String,
    lane_id: u32,
    epoch: u64,
    sequence: u64,
    client_blob_id_hex: String,
    manifest_hash_hex: String,
    chunk_root_hex: String,
    source: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct DuplicateTicket {
    ticket_hex: String,
    sources: Vec<String>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct PrivilegeAuditReport {
    summary: PrivilegeAuditSummary,
    entries: Vec<PrivilegeEntry>,
    config_hash_hex: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct PrivilegeAuditSummary {
    checked_paths: usize,
    missing: usize,
    non_directory: usize,
    world_writable: usize,
    metadata_errors: usize,
    status: String,
}
#[derive(Clone, Debug, JsonSerialize)]
struct PrivilegeEntry {
    path: String,
    exists: bool,
    is_directory: bool,
    mode_octal: Option<String>,
    world_writable: Option<bool>,
    issue: Option<String>,
}
/// Compare DA ingest receipts against on-chain DA commitment records.
pub(crate) fn run_commitment_reconciliation(
    options: CommitmentReconcileOptions,
) -> Result<(), Box<dyn Error>> {
    let receipts = load_receipt_artifacts(&options.receipts)?;
    let commitments = load_commitment_artifacts(&options.blocks)?;
    let report = reconcile_receipts_and_commitments(&receipts, &commitments);
    if let Some(target) = options.json_output.clone() {
        let value = json::to_value(&report)?;
        write_json_output(&value, target)?;
    }
    print_reconciliation_summary(&report, options.allow_unexpected_commitments);
    let mut alert = report.summary.missing_from_blocks > 0
        || report.summary.mismatches > 0
        || report.summary.duplicate_receipts > 0;
    if !options.allow_unexpected_commitments {
        alert |=
            report.summary.unexpected_commitments > 0 || report.summary.duplicate_commitments > 0;
    }
    if alert {
        return Err(
            "DA commitment reconciliation detected missing or mismatched commitments".into(),
        );
    }
    Ok(())
}
/// Audit DA privilege-sensitive directories for missing paths or insecure permissions.
pub(crate) fn run_privilege_audit(options: PrivilegeAuditOptions) -> Result<(), Box<dyn Error>> {
    let config_bytes = fs::read(&options.config).map_err(|err| -> Box<dyn Error> {
        format!("failed to read config {:?}: {err}", options.config).into()
    })?;
    let config_hash_hex = hex_encode(hash(&config_bytes).as_bytes());
    let da_ingest = load_da_ingest_config(&options.config)?;
    let mut paths = vec![
        da_ingest.replay_cache_store_dir,
        da_ingest.manifest_store_dir,
    ];
    paths.extend(options.extra_paths.iter().cloned());
    paths.retain(|path| !path.as_os_str().is_empty());
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err(
            "da-privilege-audit requires at least one path (from config or --extra-path)".into(),
        );
    }
    let mut entries = Vec::with_capacity(paths.len());
    let mut missing = 0usize;
    let mut non_directory = 0usize;
    let mut world_writable = 0usize;
    let mut metadata_errors = 0usize;
    for path in paths {
        let entry = inspect_path(&path)?;
        if !entry.exists {
            missing += 1;
        }
        if entry.exists && !entry.is_directory {
            non_directory += 1;
        }
        if entry.world_writable.unwrap_or(false) {
            world_writable += 1;
        }
        if entry.issue.is_some() {
            metadata_errors += 1;
        }
        entries.push(entry);
    }
    let mut status = "ok";
    if missing > 0 || non_directory > 0 || world_writable > 0 || metadata_errors > 0 {
        status = "alert";
    }
    let report = PrivilegeAuditReport {
        summary: PrivilegeAuditSummary {
            checked_paths: entries.len(),
            missing,
            non_directory,
            world_writable,
            metadata_errors,
            status: status.to_string(),
        },
        entries,
        config_hash_hex,
    };
    if let Some(target) = options.json_output.clone() {
        let value = json::to_value(&report)?;
        write_json_output(&value, target)?;
    }
    println!(
        "DA privilege audit: checked {} path(s) · missing={} · non-directory={} · world-writable={} · metadata-errors={} · status={}",
        report.summary.checked_paths,
        report.summary.missing,
        report.summary.non_directory,
        report.summary.world_writable,
        report.summary.metadata_errors,
        report.summary.status
    );
    if report.summary.status == "alert" {
        return Err("DA privilege audit found issues".into());
    }
    Ok(())
}
fn reconcile_receipts_and_commitments(
    receipts: &[ReceiptArtifact],
    commitments: &[CommitmentArtifact],
) -> ReconciliationReport {
    let mut receipt_map: HashMap<_, Vec<&ReceiptArtifact>> = HashMap::new();
    for receipt in receipts {
        receipt_map
            .entry(receipt.receipt.storage_ticket)
            .or_default()
            .push(receipt);
    }
    let mut commitment_map: HashMap<_, Vec<&CommitmentArtifact>> = HashMap::new();
    for commitment in commitments {
        commitment_map
            .entry(commitment.record.storage_ticket)
            .or_default()
            .push(commitment);
    }
    let duplicate_receipts = collect_receipt_duplicates(&receipt_map);
    let duplicate_commitments = collect_commitment_duplicates(&commitment_map);
    let mut missing_commitments = Vec::new();
    let mut mismatches = Vec::new();
    let mut unmatched_commitments = Vec::new();
    let mut matched = 0usize;
    for (ticket, receipt_entries) in receipt_map {
        let receipt = receipt_entries[0];
        match commitment_map.remove(&ticket) {
            Some(records) => {
                if let Some((best_match, best_idx)) = pick_best_match(receipt, &records) {
                    match best_match {
                        MatchOutcome::Match => matched += 1,
                        MatchOutcome::Mismatch {
                            differences,
                            source,
                        } => mismatches.push(CommitmentMismatch {
                            ticket_hex: ticket_hex(&ticket),
                            receipt_source: receipt.source.clone(),
                            commitment_source: source,
                            differences,
                        }),
                    }
                    for (idx, record) in records.into_iter().enumerate() {
                        if idx == best_idx {
                            continue;
                        }
                        let differences =
                            diff_receipt_and_commitment(&receipt.receipt, &record.record);
                        if differences.is_empty() {
                            matched += 1;
                        } else {
                            mismatches.push(CommitmentMismatch {
                                ticket_hex: ticket_hex(&ticket),
                                receipt_source: receipt.source.clone(),
                                commitment_source: record.source.clone(),
                                differences,
                            });
                        }
                    }
                }
            }
            None => {
                missing_commitments.push(MissingCommitment {
                    ticket_hex: ticket_hex(&receipt.receipt.storage_ticket),
                    lane_id: receipt.receipt.lane_id.as_u32(),
                    epoch: receipt.receipt.epoch,
                    client_blob_id_hex: hex_encode(receipt.receipt.client_blob_id.as_ref()),
                    manifest_hash_hex: hex_encode(receipt.receipt.manifest_hash.as_bytes()),
                    chunk_root_hex: hex_encode(receipt.receipt.chunk_root.as_ref()),
                    source: receipt.source.clone(),
                });
            }
        }
    }
    // Anything left in the commitment map was not paired with a receipt.
    for orphan in commitment_map.into_values().flatten() {
        unmatched_commitments.push(orphan);
    }
    let unexpected_commitments = unmatched_commitments
        .into_iter()
        .map(|commitment| UnexpectedCommitment {
            ticket_hex: ticket_hex(&commitment.record.storage_ticket),
            lane_id: commitment.record.lane_id.as_u32(),
            epoch: commitment.record.epoch,
            sequence: commitment.record.sequence,
            client_blob_id_hex: hex_encode(commitment.record.client_blob_id.as_ref()),
            manifest_hash_hex: hex_encode(commitment.record.manifest_hash.as_bytes()),
            chunk_root_hex: hex_encode(commitment.record.chunk_root.as_ref()),
            source: commitment.source.clone(),
        })
        .collect::<Vec<_>>();
    let mut status = "ok";
    if !missing_commitments.is_empty()
        || !mismatches.is_empty()
        || !unexpected_commitments.is_empty()
        || !duplicate_receipts.is_empty()
        || !duplicate_commitments.is_empty()
    {
        status = "alert";
    }
    ReconciliationReport {
        summary: ReconciliationSummary {
            total_receipts: receipts.len(),
            total_commitments: commitments.len(),
            matched,
            missing_from_blocks: missing_commitments.len(),
            unexpected_commitments: unexpected_commitments.len(),
            mismatches: mismatches.len(),
            duplicate_receipts: duplicate_receipts.len(),
            duplicate_commitments: duplicate_commitments.len(),
            status: status.to_string(),
        },
        missing_commitments,
        mismatches,
        unexpected_commitments,
        duplicate_receipts,
        duplicate_commitments,
    }
}
fn collect_receipt_duplicates(
    grouped: &HashMap<StorageTicketId, Vec<&ReceiptArtifact>>,
) -> Vec<DuplicateTicket> {
    grouped
        .iter()
        .filter_map(|(ticket, entries)| {
            if entries.len() > 1 {
                Some(DuplicateTicket {
                    ticket_hex: ticket_hex(ticket),
                    sources: entries.iter().map(|entry| entry.source.clone()).collect(),
                })
            } else {
                None
            }
        })
        .collect()
}
fn collect_commitment_duplicates(
    grouped: &HashMap<StorageTicketId, Vec<&CommitmentArtifact>>,
) -> Vec<DuplicateTicket> {
    grouped
        .iter()
        .filter_map(|(ticket, entries)| {
            if entries.len() > 1 {
                Some(DuplicateTicket {
                    ticket_hex: ticket_hex(ticket),
                    sources: entries.iter().map(|entry| entry.source.clone()).collect(),
                })
            } else {
                None
            }
        })
        .collect()
}
enum MatchOutcome {
    Match,
    Mismatch {
        differences: Vec<String>,
        source: String,
    },
}
fn pick_best_match(
    receipt: &ReceiptArtifact,
    candidates: &[&CommitmentArtifact],
) -> Option<(MatchOutcome, usize)> {
    let mut best: Option<(usize, MatchOutcome, usize)> = None;
    for (idx, candidate) in candidates.iter().enumerate() {
        let differences = diff_receipt_and_commitment(&receipt.receipt, &candidate.record);
        if differences.is_empty() {
            return Some((MatchOutcome::Match, idx));
        }
        if best
            .as_ref()
            .map(|(len, _, _)| differences.len() < *len)
            .unwrap_or(true)
        {
            best = Some((
                differences.len(),
                MatchOutcome::Mismatch {
                    differences,
                    source: candidate.source.clone(),
                },
                idx,
            ));
        }
    }
    best.map(|(_, outcome, idx)| (outcome, idx))
}
fn diff_receipt_and_commitment(
    receipt: &DaIngestReceipt,
    commitment: &DaCommitmentRecord,
) -> Vec<String> {
    let mut differences = Vec::new();
    if receipt.lane_id != commitment.lane_id {
        differences.push(format!(
            "lane_id receipt={} block={}",
            receipt.lane_id.as_u32(),
            commitment.lane_id.as_u32()
        ));
    }
    if receipt.epoch != commitment.epoch {
        differences.push(format!(
            "epoch receipt={} block={}",
            receipt.epoch, commitment.epoch
        ));
    }
    if receipt.client_blob_id != commitment.client_blob_id {
        differences.push(format!(
            "client_blob_id {} vs {}",
            hex_encode(receipt.client_blob_id.as_ref()),
            hex_encode(commitment.client_blob_id.as_ref())
        ));
    }
    if receipt.manifest_hash.as_bytes() != commitment.manifest_hash.as_bytes() {
        differences.push(format!(
            "manifest_hash {} vs {}",
            hex_encode(receipt.manifest_hash.as_bytes()),
            hex_encode(commitment.manifest_hash.as_bytes())
        ));
    }
    if receipt.chunk_root.as_ref() != commitment.chunk_root.as_ref() {
        differences.push(format!(
            "chunk_root {} vs {}",
            hex_encode(receipt.chunk_root.as_ref()),
            hex_encode(commitment.chunk_root.as_ref())
        ));
    }
    let receipt_proof_hex = receipt
        .pdp_commitment
        .as_ref()
        .map(|bytes| hex_encode(CryptoHash::new(bytes).as_ref()));
    let commitment_proof_hex = commitment
        .proof_digest
        .as_ref()
        .map(|hash| hex_encode(hash.as_ref()));
    if receipt_proof_hex != commitment_proof_hex {
        differences.push(format!(
            "pdp/proof digest {} vs {}",
            receipt_proof_hex.unwrap_or_else(|| String::from("<none>")),
            commitment_proof_hex.unwrap_or_else(|| String::from("<none>"))
        ));
    }
    differences
}
fn load_receipt_artifacts(paths: &[PathBuf]) -> Result<Vec<ReceiptArtifact>, Box<dyn Error>> {
    let files = collect_input_files(paths)?;
    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let receipt = decode_receipt(&path)?;
        out.push(ReceiptArtifact {
            receipt,
            source: path.display().to_string(),
        });
    }
    Ok(out)
}
fn load_commitment_artifacts(paths: &[PathBuf]) -> Result<Vec<CommitmentArtifact>, Box<dyn Error>> {
    let files = collect_input_files(paths)?;
    let mut out = Vec::new();
    for path in files {
        let mut records = decode_commitments(&path)?;
        out.append(&mut records);
    }
    Ok(out)
}
fn decode_receipt(path: &Path) -> Result<DaIngestReceipt, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    decode_from_bytes::<DaIngestReceipt>(&bytes)
        .map_err(|err| err.to_string())
        .or_else(|_| json::from_slice::<DaIngestReceipt>(&bytes).map_err(|err| err.to_string()))
        .map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode receipt {:?}: {err}", path),
            )
        })
        .map_err(Into::into)
}
fn decode_commitments(path: &Path) -> Result<Vec<CommitmentArtifact>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    match decode_framed_signed_block(&bytes) {
        Ok(block) => {
            if let Some(bundle) = block.da_commitments() {
                let height = block.header().height();
                return Ok(bundle
                    .commitments()
                    .iter()
                    .map(|record| CommitmentArtifact {
                        record: record.clone(),
                        source: format!("{}#block_height={}", path.display(), height.get()),
                    })
                    .collect());
            }
        }
        Err(error) if error.kind() != norito::core::DecodeAttemptErrorKind::Invalid => {
            // A refused canonical block attempt cannot authorize another format probe.
            return Err(Box::new(error));
        }
        Err(_) => {}
    }
    if let Ok(bundle) = decode_from_bytes::<DaCommitmentBundle>(&bytes) {
        return Ok(bundle
            .commitments()
            .iter()
            .cloned()
            .map(|record| CommitmentArtifact {
                record,
                source: path.display().to_string(),
            })
            .collect());
    }
    if let Ok(record) = decode_from_bytes::<DaCommitmentRecord>(&bytes) {
        return Ok(vec![CommitmentArtifact {
            record,
            source: path.display().to_string(),
        }]);
    }
    if let Ok(bundle) = json::from_slice::<DaCommitmentBundle>(&bytes) {
        return Ok(bundle
            .commitments()
            .iter()
            .cloned()
            .map(|record| CommitmentArtifact {
                record,
                source: path.display().to_string(),
            })
            .collect());
    }
    if let Ok(record) = json::from_slice::<DaCommitmentRecord>(&bytes) {
        return Ok(vec![CommitmentArtifact {
            record,
            source: path.display().to_string(),
        }]);
    }
    Err::<Vec<CommitmentArtifact>, Box<dyn Error>>(
        format!("failed to decode commitments from {:?}", path).into(),
    )
}
fn collect_input_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();
    for path in paths {
        let metadata = fs::metadata(path).map_err(|err| -> Box<dyn Error> {
            format!("failed to read metadata for {:?}: {err}", path).into()
        })?;
        if metadata.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file() {
                    files.push(entry.path().to_path_buf());
                }
            }
        } else if metadata.is_file() {
            files.push(path.to_path_buf());
        }
    }
    if files.is_empty() {
        return Err("no files found for provided paths".into());
    }
    Ok(files)
}
fn print_reconciliation_summary(report: &ReconciliationReport, allow_unexpected: bool) {
    println!(
        "DA commitment reconciliation: matched {} of {} receipts",
        report.summary.matched, report.summary.total_receipts
    );
    if report.summary.missing_from_blocks > 0 {
        println!(
            "  Missing commitments for {} receipt(s)",
            report.summary.missing_from_blocks
        );
    }
    if report.summary.mismatches > 0 {
        println!(
            "  Detected {} mismatch(es) between receipts and commitments",
            report.summary.mismatches
        );
    }
    if report.summary.duplicate_receipts > 0 {
        println!(
            "  Detected {} duplicate receipt ticket(s)",
            report.summary.duplicate_receipts
        );
    }
    if report.summary.duplicate_commitments > 0 {
        println!(
            "  Detected {} duplicate commitment ticket(s)",
            report.summary.duplicate_commitments
        );
    }
    if report.summary.unexpected_commitments > 0 {
        if allow_unexpected {
            println!(
                "  {} commitment(s) lacked receipts (allowed by flag)",
                report.summary.unexpected_commitments
            );
        } else {
            println!(
                "  {} commitment(s) lacked receipts",
                report.summary.unexpected_commitments
            );
        }
    }
    println!("Overall status: {}", report.summary.status);
}
fn ticket_hex(ticket: &StorageTicketId) -> String {
    hex_encode(ticket.as_ref())
}
fn load_da_ingest_config(path: &Path) -> Result<DaIngest, Box<dyn Error>> {
    let reader =
        ConfigReader::new()
            .read_toml_with_extends(path)
            .map_err(|err| -> Box<dyn Error> {
                format!("failed to read config {path:?}: {err}").into()
            })?;
    reader
        .read_and_complete::<user::Root>()
        .map_err(|err| -> Box<dyn Error> {
            format!("failed to complete config {path:?}: {err}").into()
        })?
        .parse()
        .map(|config| config.torii.da_ingest)
        .map_err(|err| -> Box<dyn Error> {
            format!("failed to parse config {path:?}: {err}").into()
        })
}
fn inspect_path(path: &Path) -> Result<PrivilegeEntry, Box<dyn Error>> {
    let display = path.display().to_string();
    match fs::metadata(path) {
        Ok(metadata) => {
            let (mode_octal, world_writable) = permission_snapshot(&metadata);
            Ok(PrivilegeEntry {
                path: display,
                exists: true,
                is_directory: metadata.is_dir(),
                mode_octal,
                world_writable,
                issue: None,
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(PrivilegeEntry {
            path: display,
            exists: false,
            is_directory: false,
            mode_octal: None,
            world_writable: None,
            issue: Some(String::from("not_found")),
        }),
        Err(err) => Ok(PrivilegeEntry {
            path: display,
            exists: false,
            is_directory: false,
            mode_octal: None,
            world_writable: None,
            issue: Some(format!("metadata_error: {err}")),
        }),
    }
}
#[cfg(unix)]
fn permission_snapshot(metadata: &fs::Metadata) -> (Option<String>, Option<bool>) {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    let world_writable = mode & 0o002 != 0;
    (Some(format!("{mode:04o}")), Some(world_writable))
}
#[cfg(not(unix))]
fn permission_snapshot(_metadata: &fs::Metadata) -> (Option<String>, Option<bool>) {
    (None, None)
}
#[derive(Clone, Debug, JsonSerialize)]
pub struct ProofBenchReport {
    pub manifest_path: String,
    pub payload_path: String,
    pub sample_count: usize,
    pub sample_seed: u64,
    pub budget_ms: u64,
    pub iterations: usize,
    pub stats: ProofBenchStats,
    pub runs: Vec<DaProofBenchmark>,
}
#[derive(Clone, Debug, JsonSerialize)]
pub struct ProofBenchStats {
    pub proof_count: usize,
    pub leaf_count: usize,
    pub average_total_ms: f64,
    pub max_total_ms: u64,
    pub average_per_proof_ms: f64,
    pub max_single_ms: u64,
    pub budget_pass_rate: f64,
    pub recommended_budget_ms: u64,
}
/// Benchmark DA proof verification time against the configured budget.
pub(crate) fn run_proof_bench(
    options: ProofBenchOptions,
) -> Result<ProofBenchReport, Box<dyn Error>> {
    if matches!(options.payload_bytes, Some(0)) {
        return Err("payload-bytes must be greater than zero".into());
    }
    let manifest_bytes = fs::read(&options.manifest).map_err(|err| -> Box<dyn Error> {
        format!("failed to read manifest {:?}: {err}", options.manifest).into()
    })?;
    let mut manifest: DaManifestV1 = json::from_slice(&manifest_bytes)?;
    ensure_taikai_metadata(&mut manifest).map_err(|err| -> Box<dyn Error> { err.into() })?;
    let mut config = DaProofConfig::default();
    if let Some(count) = options.sample_count {
        config.sample_count = count;
    }
    if let Some(seed) = options.sample_seed {
        config.sample_seed = seed;
    }
    let budget_ms = options.budget_ms.unwrap_or(DEFAULT_PROOF_BENCH_BUDGET_MS);
    let iterations = options.iterations.max(1);
    let chunk_size_hint = {
        let base = if manifest.chunk_size == 0 {
            64 * 1024
        } else {
            manifest.chunk_size
        };
        base.max(64 * 1024)
    };
    let (payload, payload_label) = if let Some(bytes) = options.payload_bytes {
        let data = deterministic_payload(bytes);
        if let Some(parent) = options.payload.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&options.payload, &data)?;
        (
            data,
            format!("{} (generated {} bytes)", options.payload.display(), bytes),
        )
    } else {
        let data = fs::read(&options.payload).map_err(|err| -> Box<dyn Error> {
            format!("failed to read payload {:?}: {err}", options.payload).into()
        })?;
        (data, options.payload.display().to_string())
    };
    let (runs, manifest_label) = if options.payload_bytes.is_some() {
        let synthetic = synthesize_manifest_from_payload(&payload, chunk_size_hint)?;
        let runs = run_benchmark_iterations(&synthetic, &payload, &config, budget_ms, iterations)?;
        (runs, format!("synthetic (chunk_size={chunk_size_hint})"))
    } else {
        let mut label = options.manifest.display().to_string();
        let runs = run_benchmark_iterations(&manifest, &payload, &config, budget_ms, iterations)
            .or_else(|err| {
                eprintln!("warning: proof benchmark fell back to synthetic manifest: {err}");
                label = format!("synthetic (chunk_size={chunk_size_hint})");
                let synthetic = synthesize_manifest_from_payload(&payload, chunk_size_hint)?;
                run_benchmark_iterations(&synthetic, &payload, &config, budget_ms, iterations)
            })?;
        (runs, label)
    };
    let stats = summarize_proof_bench(&runs, budget_ms);
    let report = ProofBenchReport {
        manifest_path: manifest_label,
        payload_path: payload_label,
        sample_count: config.sample_count,
        sample_seed: config.sample_seed,
        budget_ms,
        iterations,
        stats,
        runs,
    };
    if let Some(target) = options.json_output.clone() {
        let value = json::to_value(&report)?;
        write_json_output(&value, target)?;
    }
    if let Some(path) = options.markdown_output.as_deref() {
        let markdown = render_proof_bench_markdown(&report);
        if path == Path::new("-") {
            println!("{markdown}");
        } else {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, markdown)?;
        }
    }
    println!(
        "DA proof verification benchmark: total={}ms budget={}ms status={}",
        report.stats.max_total_ms,
        report.stats.recommended_budget_ms,
        if report.stats.budget_pass_rate >= 100.0 {
            "within_budget"
        } else {
            "over_budget"
        }
    );
    if report.stats.budget_pass_rate < 100.0 {
        eprintln!("warning: proof verification exceeds budget for at least one iteration");
    }
    Ok(report)
}
fn run_benchmark_iterations(
    manifest: &DaManifestV1,
    payload: &[u8],
    config: &DaProofConfig,
    budget_ms: u64,
    iterations: usize,
) -> Result<Vec<DaProofBenchmark>, Box<dyn Error>> {
    let mut runs = Vec::with_capacity(iterations.max(1));
    for _ in 0..iterations.max(1) {
        runs.push(
            benchmark_da_proof_verification(manifest, payload, config, budget_ms)
                .map_err(|err| -> Box<dyn Error> { err.into() })?,
        );
    }
    Ok(runs)
}
fn synthesize_manifest_from_payload(
    payload: &[u8],
    chunk_size: u32,
) -> Result<DaManifestV1, Box<dyn Error>> {
    let effective_chunk = if chunk_size == 0 {
        u32::try_from(payload.len()).unwrap_or(1)
    } else {
        chunk_size
    };
    let profile = ChunkProfile {
        min_size: usize::try_from(effective_chunk)?,
        target_size: usize::try_from(effective_chunk)?,
        max_size: usize::try_from(effective_chunk)?,
        break_mask: 1,
    };
    let mut store = ChunkStore::with_profile(profile);
    store.ingest_bytes(payload)?;
    let chunk_commitments = store
        .chunks()
        .iter()
        .enumerate()
        .map(|(idx, chunk)| {
            let idx = u32::try_from(idx)?;
            Ok(ChunkCommitment::new_with_role(
                idx,
                chunk.offset,
                chunk.length,
                ChunkDigest::new(chunk.blake3),
                ChunkRole::Data,
                0,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let blob_hash = BlobDigest::from_hash(hash(payload));
    let chunk_root = BlobDigest::new(*store.por_tree().root());
    let chunk_size = chunk_commitments
        .first()
        .map(|commitment| commitment.length)
        .unwrap_or(effective_chunk);
    let erasure_profile = ErasureProfile {
        data_shards: 1,
        parity_shards: 0,
        row_parity_stripes: 0,
        chunk_alignment: 1,
        fec_scheme: FecScheme::Rs12_10,
    };
    let total_stripes = u32::try_from(
        chunk_commitments
            .len()
            .div_ceil(usize::from(erasure_profile.data_shards.max(1))),
    )?;
    let shards_per_stripe = u32::from(erasure_profile.data_shards + erasure_profile.parity_shards);
    Ok(DaManifestV1 {
        version: DaManifestV1::VERSION,
        client_blob_id: blob_hash,
        lane_id: LaneId::new(0),
        epoch: 0,
        blob_class: BlobClass::NexusLaneSidecar,
        codec: BlobCodec::new("bench.binary"),
        blob_hash,
        chunk_root,
        storage_ticket: StorageTicketId::new([0u8; 32]),
        total_size: payload.len() as u64,
        chunk_size,
        total_stripes,
        shards_per_stripe,
        erasure_profile,
        retention_policy: RetentionPolicy::default(),
        rent_quote: DaRentQuote::default(),
        chunks: chunk_commitments,
        ipa_commitment: chunk_root,
        metadata: ExtraMetadata::default(),
        issued_at_unix: 0,
    })
}
fn summarize_proof_bench(runs: &[DaProofBenchmark], _budget_ms: u64) -> ProofBenchStats {
    let proof_count = runs.first().map(|run| run.proof_count).unwrap_or(0);
    let leaf_count = runs.first().map(|run| run.leaf_count).unwrap_or(0);
    let average_total_ms = if runs.is_empty() {
        0.0
    } else {
        runs.iter()
            .map(|run| run.total_duration_ms as f64)
            .sum::<f64>()
            / runs.len() as f64
    };
    let max_total_ms = runs
        .iter()
        .map(|run| run.total_duration_ms)
        .max()
        .unwrap_or(0);
    let average_per_proof_ms = if proof_count == 0 {
        0.0
    } else {
        average_total_ms / proof_count as f64
    };
    let max_single_ms = runs
        .iter()
        .map(|run| run.max_duration_ms)
        .max()
        .unwrap_or(0);
    let budget_hits = runs.iter().filter(|run| run.within_budget).count();
    let budget_pass_rate = if runs.is_empty() {
        0.0
    } else {
        (budget_hits as f64 / runs.len() as f64) * 100.0
    };
    let recommended_budget_ms =
        (((max_total_ms.max(max_single_ms) as f64) * 1.1_f64).ceil() as u64).max(1);
    ProofBenchStats {
        proof_count,
        leaf_count,
        average_total_ms,
        max_total_ms,
        average_per_proof_ms,
        max_single_ms,
        budget_pass_rate,
        recommended_budget_ms,
    }
}
const META_TAIKAI_EVENT_ID: &str = "taikai.event_id";
const META_TAIKAI_STREAM_ID: &str = "taikai.stream_id";
const META_TAIKAI_RENDITION_ID: &str = "taikai.rendition_id";
const META_TAIKAI_SEGMENT_SEQUENCE: &str = "taikai.segment.sequence";
fn ensure_taikai_metadata(manifest: &mut DaManifestV1) -> Result<(), String> {
    if manifest.blob_class != BlobClass::TaikaiSegment {
        return Ok(());
    }
    let entries = &mut manifest.metadata.items;
    ensure_metadata_entry(entries, META_TAIKAI_EVENT_ID, b"bench_event");
    ensure_metadata_entry(entries, META_TAIKAI_STREAM_ID, b"bench_stream");
    ensure_metadata_entry(entries, META_TAIKAI_RENDITION_ID, b"bench_rendition");
    ensure_metadata_entry(entries, META_TAIKAI_SEGMENT_SEQUENCE, b"0");
    let missing = [
        META_TAIKAI_EVENT_ID,
        META_TAIKAI_STREAM_ID,
        META_TAIKAI_RENDITION_ID,
        META_TAIKAI_SEGMENT_SEQUENCE,
    ]
    .iter()
    .filter(|key| entries.iter().all(|entry| entry.key != **key))
    .cloned()
    .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "manifest missing Taikai metadata fields after autofill: {}",
            missing.join(", ")
        ))
    }
}
fn ensure_metadata_entry(entries: &mut Vec<MetadataEntry>, key: &str, value: &[u8]) {
    if entries.iter().any(|entry| entry.key == key) {
        return;
    }
    entries.push(MetadataEntry::new(
        key.to_owned(),
        value.to_vec(),
        MetadataVisibility::Public,
    ));
}
fn deterministic_payload(len: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(len);
    let mut state: u8 = 0x5A;
    for idx in 0..len {
        state = state
            .wrapping_mul(37)
            .wrapping_add((idx as u8).wrapping_add(3));
        payload.push(state);
    }
    payload
}
fn render_proof_bench_markdown(report: &ProofBenchReport) -> String {
    let mut output = String::new();
    let _ = writeln!(&mut output, "# DA Proof Verification Benchmark");
    let _ = writeln!(&mut output);
    let _ = writeln!(&mut output, "- Manifest: `{}`", report.manifest_path);
    let _ = writeln!(&mut output, "- Payload: `{}`", report.payload_path);
    if let Some(first) = report.runs.first() {
        let _ = writeln!(
            &mut output,
            "- Payload bytes: {} | Chunk size: {}",
            first.payload_bytes, first.chunk_size
        );
    }
    let _ = writeln!(
        &mut output,
        "- Sample count: {} | Sample seed: {}",
        report.sample_count, report.sample_seed
    );
    let _ = writeln!(
        &mut output,
        "- Iterations: {} | Budget (ms): {} | Recommended budget (ms): {}",
        report.iterations, report.budget_ms, report.stats.recommended_budget_ms
    );
    let _ = writeln!(
        &mut output,
        "- Proofs/run: {} | Leaves: {}",
        report.stats.proof_count, report.stats.leaf_count
    );
    let _ = writeln!(
        &mut output,
        "- Avg total (ms): {:.2} | Max total (ms): {} | Avg/proof (ms): {:.4} | Max proof (ms): {}",
        report.stats.average_total_ms,
        report.stats.max_total_ms,
        report.stats.average_per_proof_ms,
        report.stats.max_single_ms
    );
    let _ = writeln!(
        &mut output,
        "- Budget pass rate: {:.2}%",
        report.stats.budget_pass_rate
    );
    let _ = writeln!(&mut output);
    let _ = writeln!(
        &mut output,
        "| run | proofs | total_ms | max_proof_ms | within_budget |"
    );
    let _ = writeln!(&mut output, "| --- | --- | --- | --- | --- |");
    for (idx, run) in report.runs.iter().enumerate() {
        let _ = writeln!(
            &mut output,
            "| {idx} | {} | {} | {} | {} |",
            run.proof_count,
            run.total_duration_ms,
            run.max_duration_ms,
            if run.within_budget { "yes" } else { "no" }
        );
    }
    output
}
#[cfg(test)]
mod tests {
    use super::{
        CommitmentArtifact, ManifestAudit, ManifestAuditStatus, PolicySnapshot, ProofBenchOptions,
        ReceiptArtifact, ReplicationOrderSnapshot, blob_class_label, build_remediation_plan,
        diff_receipt_and_commitment, reconcile_receipts_and_commitments, run_proof_bench,
        storage_class_label,
    };
    use crate::JsonTarget;
    use iroha_crypto::{Hash as CryptoHash, Signature};
    use iroha_data_model::{
        da::{
            commitment::{DaCommitmentRecord, DaProofScheme},
            ingest::{DaIngestReceipt, DaStripeLayout},
            types::{BlobClass, BlobDigest, RetentionPolicy, StorageTicketId},
        },
        sorafs::pin_registry::{ManifestDigest, StorageClass},
    };
    use iroha_model_base::topology::LaneId;
    use std::path::PathBuf;
    fn sample_receipt(
        ticket: [u8; 32],
        manifest: [u8; 32],
        chunk_root: [u8; 32],
    ) -> ReceiptArtifact {
        ReceiptArtifact {
            receipt: DaIngestReceipt {
                client_blob_id: BlobDigest::new([0xAA; 32]),
                lane_id: LaneId::new(7),
                epoch: 9,
                blob_hash: BlobDigest::new([0xBB; 32]),
                chunk_root: BlobDigest::new(chunk_root),
                manifest_hash: BlobDigest::new(manifest),
                storage_ticket: StorageTicketId::new(ticket),
                pdp_commitment: Some(vec![0x11, 0x22]),
                stripe_layout: DaStripeLayout {
                    total_stripes: 1,
                    shards_per_stripe: 1,
                    row_parity_stripes: 0,
                },
                queued_at_unix: 1700000000,
                rent_quote: Default::default(),
                operator_signature: Signature::try_from_bytes(&[0xCC; 64])
                    .expect("DA receipt fixture operator signature is non-empty and nonzero"),
            },
            source: String::from("receipt.norito"),
        }
    }
    fn sample_commitment(
        ticket: [u8; 32],
        manifest: [u8; 32],
        chunk_root: [u8; 32],
    ) -> CommitmentArtifact {
        CommitmentArtifact {
            record: DaCommitmentRecord::new(
                LaneId::new(7),
                9,
                3,
                BlobDigest::new([0xAA; 32]),
                ManifestDigest::new(manifest),
                DaProofScheme::MerkleSha256,
                CryptoHash::prehashed(chunk_root),
                Some(CryptoHash::new([0x11, 0x22])),
                RetentionPolicy::default(),
                StorageTicketId::new(ticket),
                Signature::try_from_bytes(&[0xDD; 64])
                    .expect("DA commitment fixture signature is non-empty and nonzero"),
            ),
            source: String::from("block.block"),
        }
    }
    #[test]
    fn commitment_block_decode_keeps_original_scope_and_retries_unchanged_file() {
        use iroha_data_model::{
            block::{BlockHeader, BlockPayload, SignedBlock},
            da::commitment::DaCommitmentBundle,
        };
        use norito::core::DecodeAttemptErrorKind;
        use std::{error::Error as _, num::NonZeroU64};

        let expected = sample_commitment([1; 32], [2; 32], [3; 32]).record;
        let bundle = DaCommitmentBundle::new(vec![expected.clone()]);
        let mut header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
        header.set_da_commitments_hash(bundle.merkle_commitment());
        let block = SignedBlock::unsigned_with_payload(BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: Some(bundle),
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        });
        let wire = block.encode_wire().expect("canonical DA block fixture");
        let directory = tempfile::tempdir().expect("temporary original file");
        let path = directory.path().join("block.norito");
        std::fs::write(&path, &wire).expect("original block bytes");
        let refusal = match norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || super::decode_commitments(&path),
        ) {
            Err(original) => original,
            Ok(_) => panic!("actual inherited allocation ceiling must refuse the block attempt"),
        };
        let original = refusal
            .downcast_ref::<norito::core::DecodeAttemptError>()
            .expect("alternate bundle/JSON probes must not replace the original cause");
        assert_eq!(original.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        assert!(
            original.source().is_some(),
            "original Norito error remains available after scope exit"
        );
        assert_eq!(std::fs::read(&path).unwrap(), wire);
        let records = super::decode_commitments(&path).expect("retry exact unchanged block");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record, expected);
        assert_eq!(
            records[0].source,
            format!("{}#block_height=1", path.display())
        );
        assert_eq!(std::fs::read(&path).unwrap(), wire);
    }
    #[test]
    fn blob_class_labels_are_stable() {
        assert_eq!(blob_class_label(BlobClass::TaikaiSegment), "taikai_segment");
        assert_eq!(
            blob_class_label(BlobClass::NexusLaneSidecar),
            "nexus_lane_sidecar"
        );
        assert_eq!(
            blob_class_label(BlobClass::GovernanceArtifact),
            "governance_artifact"
        );
        assert_eq!(blob_class_label(BlobClass::Custom(7)), "custom");
    }
    #[test]
    fn storage_class_labels_are_stable() {
        assert_eq!(storage_class_label(StorageClass::Hot), "hot");
        assert_eq!(storage_class_label(StorageClass::Warm), "warm");
        assert_eq!(storage_class_label(StorageClass::Cold), "cold");
    }
    #[test]
    fn status_from_flags_covers_all_cases() {
        assert_eq!(
            ManifestAuditStatus::from_flags(true, false),
            ManifestAuditStatus::Ok
        );
        assert_eq!(
            ManifestAuditStatus::from_flags(true, true),
            ManifestAuditStatus::ReplicaShortfall
        );
        assert_eq!(
            ManifestAuditStatus::from_flags(false, false),
            ManifestAuditStatus::PolicyMismatch
        );
        assert_eq!(
            ManifestAuditStatus::from_flags(false, true),
            ManifestAuditStatus::PolicyMismatch
        );
    }
    #[test]
    fn reconciliation_detects_missing() {
        let receipt = sample_receipt([1; 32], [2; 32], [3; 32]);
        let report = reconcile_receipts_and_commitments(&[receipt], &[]);
        assert_eq!(report.summary.missing_from_blocks, 1);
        assert_eq!(report.summary.mismatches, 0);
        assert_eq!(report.summary.matched, 0);
    }
    #[test]
    fn reconciliation_detects_mismatch_and_match() {
        let receipt = sample_receipt([9; 32], [4; 32], [5; 32]);
        let bad_commitment = sample_commitment([9; 32], [8; 32], [6; 32]);
        let good_commitment = sample_commitment([9; 32], [4; 32], [5; 32]);
        let report =
            reconcile_receipts_and_commitments(&[receipt], &[bad_commitment, good_commitment]);
        assert_eq!(report.summary.mismatches, 1);
        assert_eq!(report.summary.matched, 1);
    }
    #[test]
    fn diff_includes_all_fields() {
        let receipt = sample_receipt([1; 32], [2; 32], [3; 32]);
        let mut mismatched = sample_commitment([1; 32], [4; 32], [5; 32]);
        mismatched.record.proof_digest = None;
        let diffs = diff_receipt_and_commitment(&receipt.receipt, &mismatched.record);
        assert!(diffs.iter().any(|d| d.contains("manifest_hash")));
        assert!(diffs.iter().any(|d| d.contains("chunk_root")));
        assert!(diffs.iter().any(|d| d.contains("pdp/proof")));
    }
    #[test]
    fn remediation_plan_reports_policy_and_replica_gap() {
        let audit = ManifestAudit {
            manifest_path: "manifest.norito".into(),
            blob_class: "taikai_segment".into(),
            manifest_digest_hex: "aa".repeat(32),
            policy_match: false,
            replication_orders_found: 1,
            replica_shortfall: true,
            status: ManifestAuditStatus::ReplicaShortfall,
            policy: PolicySnapshot {
                hot_retention_secs: 10,
                cold_retention_secs: 20,
                required_replicas: 3,
                storage_class: "hot".into(),
                governance_tag: "g0".into(),
            },
            expected_policy: PolicySnapshot {
                hot_retention_secs: 10,
                cold_retention_secs: 20,
                required_replicas: 3,
                storage_class: "hot".into(),
                governance_tag: "g0".into(),
            },
            replication: vec![ReplicationOrderSnapshot {
                order_path: "order.json".into(),
                order_id_hex: "bb".repeat(32),
                target_replicas: 3,
                assignment_count: 1,
                target_matches_policy: true,
                assignments_sufficient: false,
            }],
        };
        let plan = build_remediation_plan(&[audit]);
        assert_eq!(plan.manifests.len(), 1);
        let entry = &plan.manifests[0];
        assert_eq!(entry.missing_replicas, 2);
        assert!(
            entry
                .notes
                .iter()
                .any(|note| note.contains("replicas short"))
        );
        assert!(entry.notes.iter().any(|note| note.contains("retention")));
    }
    #[test]
    fn proof_bench_runner_accepts_fixture() {
        let root = crate::workspace_root();
        for budget_ms in [None, Some(5_000)] {
            let options = ProofBenchOptions {
                manifest: root
                    .join("fixtures")
                    .join("da")
                    .join("reconstruct")
                    .join("rs_parity_v1")
                    .join("manifest.json"),
                payload: root
                    .join("fixtures")
                    .join("da")
                    .join("reconstruct")
                    .join("rs_parity_v1")
                    .join("payload.bin"),
                payload_bytes: None,
                sample_count: Some(1),
                sample_seed: Some(0),
                budget_ms,
                json_output: Some(JsonTarget::Stdout),
                markdown_output: Some(PathBuf::from("-")),
                iterations: 1,
            };
            let report =
                run_proof_bench(options).expect("benchmark should succeed for fixture payload");
            assert_eq!(report.iterations, 1);
            assert_eq!(report.runs.len(), 1);
            assert_eq!(report.stats.proof_count, report.runs[0].proof_count);
            assert_eq!(report.budget_ms, budget_ms.unwrap_or(20));
        }
    }
}
