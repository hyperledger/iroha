//! Developer automation entrypoint for repository maintenance tasks.
use eyre::eyre;
use iroha_config::{
    base::read::ConfigReader,
    parameters::{
        actual::{self, IsoReferenceData},
        user,
    },
};
use iroha_core::iso_bridge::reference_data::{
    DatasetSnapshot, ReferenceDataError, ReferenceDataSnapshots, SnapshotState,
};
use iroha_crypto::{Algorithm, PublicKey};
#[cfg(test)]
use iroha_crypto::{KeyPair, PrivateKey, Signature};
use iroha_data_model::{
    account::address::compliance_vectors::compliance_vectors_json, nexus::AssetPermissionManifest,
};
use iroha_service_model::soranet::RolloutPhase;
use norito::{
    derive::{JsonDeserialize, JsonSerialize},
    json::{self, Value},
    streaming::{
        codec::{BundleContextId, ContextFrequency},
        load_bundle_tables_from_toml,
    },
    to_bytes,
};
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    ffi::OsStr,
    fmt::Write as FmtWrite,
    fs,
    path::{Path, PathBuf},
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
};
use tempfile::TempDir;
use time::{
    Date, OffsetDateTime,
    format_description::{self, well_known::Rfc3339},
};
mod da;
mod vote_tally;
use fastpq::{BenchInput, BenchManifestOptions};
use sorafs_manifest::deal::XorQuantity;
use soranet_testnet::{
    DrillBundleOptions, VerificationAttachment, VerificationFeedOptions, evaluate_testnet_metrics,
    generate_drill_bundle, generate_testnet_kit, generate_verification_feed,
};
use vote_tally::{
    BundleSummary, bundle_file_names, iroha_hash, read_summary, summary_to_json, write_bundle,
};
mod codec;
mod compute;
mod compute_harness;
mod fastpq;
mod gar;
mod i3_bench_suite;
mod i3_slo_harness;
mod kagami_bundle;
mod kagami_profiles;
mod ministry;
mod ministry_agenda;
mod ministry_jury;
mod ministry_panel;
mod mochi;
mod network_profiles;
mod nexus;
mod nexus_lane_maintenance;
mod norito_rpc;
mod openapi_git;
mod openapi_validation;
mod poseidon_bench;
mod sm;
mod sns;
mod soracloud_inrou;
mod soradns;
mod sorafs;
mod soranet;
mod soranet_bug_bounty;
mod soranet_chaos;
mod soranet_common;
mod soranet_gar_controller;
mod soranet_gateway;
mod soranet_gateway_billing;
mod soranet_gateway_chaos;
mod soranet_gateway_hardening;
mod soranet_gateway_m1;
mod soranet_gateway_m2;
mod soranet_gateway_m3;
mod soranet_gateway_ops;
mod soranet_gateway_pq;
mod soranet_pop;
mod soranet_privacy;
mod soranet_rollout;
mod soranet_testnet;
#[cfg(test)]
mod soranet_vpn;
mod stage1_bench;
mod streaming_bench;
mod taikai;
mod taikai_anchor;
use crate::norito_rpc::{
    FixtureOptions as NoritoRpcFixtureOptions, generate_fixtures as run_norito_rpc_fixtures,
    run_verify,
};
fn main() {
    if let Err(err) = entrypoint() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}
enum CommandKind {
    OpenApi {
        outputs: Vec<PathBuf>,
        canonical_spec: PathBuf,
        manifest: PathBuf,
        signature_envelope: Option<PathBuf>,
        signing_payload: Option<PathBuf>,
        unsigned_manifest: bool,
    },
    OpenApiVerify {
        spec: PathBuf,
        manifest: PathBuf,
        allow_unsigned: bool,
        allowed_signers: PathBuf,
    },
    AddressVectors {
        target: JsonTarget,
        verify: bool,
    },
    SoranetFixtures {
        output: PathBuf,
        verify: bool,
    },
    SoranetChaosKit {
        options: soranet_chaos::ChaosKitOptions,
    },
    SoranetChaosReport {
        options: soranet_chaos::ChaosReportOptions,
    },
    ComputeSloReport {
        options: compute::ComputeSloReportOptions,
    },
    ComputeFixtures {
        options: compute::ComputeFixtureOptions,
    },
    ZkDevVoteFixture {
        output: PathBuf,
        verify: bool,
        print_hashes: bool,
        summary_target: Option<JsonTarget>,
        attestation_target: Option<JsonTarget>,
    },
    KagamiBundle {
        output: PathBuf,
        profile: String,
        network_profiles: Option<PathBuf>,
    },
    MochiBundle {
        output: PathBuf,
        profile: String,
        archive: bool,
        matrix: Option<PathBuf>,
        smoke: bool,
        stage: Option<PathBuf>,
        network_profiles: Option<PathBuf>,
    },
    MochiLatency {
        bundle: PathBuf,
        output: PathBuf,
    },
    MochiLatencyReport {
        samples: PathBuf,
        output: PathBuf,
    },
    MochiLatencyRemote {
        bundle: PathBuf,
        driver: PathBuf,
        output: PathBuf,
    },
    KagamiProfiles {
        options: kagami_profiles::KagamiProfileOptions,
    },
    SorafsAdmissionFixtures {
        output: PathBuf,
    },
    SorafsFetchFixture {
        options: Box<sorafs::FetchFixtureOptions>,
    },
    SorafsGatewayFixtures {
        output: PathBuf,
        verify: bool,
    },
    SorafsPinFixtures {
        output: PathBuf,
    },
    SorafsAdoptionCheck {
        options: sorafs::adoption::AdoptionCheckOptions,
        report: Option<PathBuf>,
    },
    SorafsScoreboardDiff {
        options: sorafs::adoption::ScoreboardDiffOptions,
        report: Option<PathBuf>,
    },
    SorafsBurnInCheck {
        options: sorafs::adoption::BurnInCheckOptions,
        output: Option<PathBuf>,
    },
    SorafsReserveMatrix {
        options: sorafs::ReserveMatrixOptions,
        target: JsonTarget,
    },
    SorafsGatewayAttest {
        options: Box<sorafs::GatewayAttestOptions>,
    },
    SorafsGatewayAttestVerify {
        envelope: PathBuf,
    },
    SorafsGatewayProbe {
        options: Box<sorafs::GatewayProbeOptions>,
    },
    SoracloudInrouSmoke {
        mode: soracloud_inrou::CommandMode,
    },
    SorafsGatewayCli {
        command: Box<sorafs::GatewayCliCommand>,
    },
    SoranetPopBundle {
        options: Box<soranet_pop::PopBundleOptions>,
    },
    SoranetPopCtl {
        options: Box<soranet_pop::PopBundleOptions>,
    },
    SoranetPopTemplate {
        input: PathBuf,
        output: PathBuf,
        resolver_config: Option<PathBuf>,
        edns_out: Option<PathBuf>,
        edns_resolver: Option<String>,
        ds_out: Option<PathBuf>,
        edns_tool: Option<String>,
    },
    SoranetPopValidate {
        input: PathBuf,
        roa: Option<PathBuf>,
        output: JsonTarget,
    },
    SoranetPopPolicyReport {
        options: Box<soranet_pop::PopPolicyHarnessOptions>,
    },
    SoranetPopPlan {
        input: PathBuf,
        roa: Option<PathBuf>,
        frr_out: PathBuf,
        report_out: JsonTarget,
    },
    SoranetGatewayM0 {
        options: soranet_gateway::GatewayM0Options,
    },
    SoranetGatewayM1 {
        options: soranet_gateway_m1::GatewayM1Options,
    },
    SoranetGatewayM2 {
        options: soranet_gateway_m2::GatewayM2Options,
    },
    SoranetGatewayM3 {
        options: soranet_gateway_m3::GatewayM3Options,
    },
    SoranetGatewayOpsM0 {
        options: soranet_gateway_ops::GatewayOpsOptions,
    },
    SoranetGatewayPq {
        options: soranet_gateway_pq::GatewayPqOptions,
    },
    SoranetGarController {
        options: soranet_gar_controller::GarControllerOptions,
    },
    SoranetBugBounty {
        options: soranet_bug_bounty::BugBountyOptions,
    },
    SoranetGatewayOpsM1 {
        options: soranet_gateway_ops::GatewayOpsMultiOptions,
    },
    SoranetGatewayChaos {
        options: soranet_gateway_chaos::ChaosOptions,
    },
    SoranetGatewayHardening {
        options: soranet_gateway_hardening::GatewayHardeningOptions,
    },
    SoranetGarExport {
        options: gar::ExportOptions,
        output: JsonTarget,
    },
    SoranetGatewayBilling {
        options: soranet_gateway_billing::BillingOptions,
    },
    TaikaiAnchorBundle {
        options: taikai_anchor::AnchorBundleOptions,
    },
    TaikaiRptVerify {
        options: taikai::RptVerifyOptions,
    },
    SoranetPrivacyReport {
        options: soranet_privacy::PrivacyReportOptions,
        json_out: Option<JsonTarget>,
        max_bucket_records: usize,
        suppression_ratio_budget: Option<f64>,
    },
    SoranetConstantRateProfile {
        selection: soranet::ConstantRateSelection,
        format: soranet::ConstantRateOutputFormat,
        include_tick_table: bool,
        tick_values: Vec<f64>,
        json_out: Option<JsonTarget>,
    },
    NexusLaneMaintenance {
        options: nexus_lane_maintenance::LaneMaintenanceOptions,
    },
    NexusLaneAudit {
        options: nexus::LaneAuditOptions,
    },
    NexusConnectFixture {
        options: nexus::NexusConnectFixtureOptions,
    },
    SoranetTestnetKit {
        output: PathBuf,
    },
    SoranetTestnetMetrics {
        input: PathBuf,
        output: JsonTarget,
    },
    SoranetTestnetFeed {
        options: Box<VerificationFeedOptions>,
    },
    SoranetTestnetDrillBundle {
        options: Box<DrillBundleOptions>,
    },
    FastpqBenchManifest {
        options: Box<BenchManifestOptions>,
    },
    FastpqVerifyBenchManifest {
        manifest: PathBuf,
        trusted_public_key: String,
    },
    FastpqStageProfile {
        options: Box<fastpq::StageProfileOptions>,
    },
    FastpqCudaSuite {
        options: Box<fastpq::CudaSuiteOptions>,
    },
    SoradnsDirectoryRelease {
        options: Box<soradns::DirectoryReleaseOptions>,
    },
    SoradnsHosts {
        names: Vec<String>,
        pretty_suffix: String,
        json: Option<JsonTarget>,
        verify: Vec<PathBuf>,
    },
    SoradnsBindingTemplate {
        options: soradns::BindingTemplateOptions,
        json: Option<JsonTarget>,
        headers_out: Option<PathBuf>,
    },
    SoradnsGarTemplate {
        options: soradns::GarTemplateOptions,
        output: Option<JsonTarget>,
    },
    SoradnsAcmePlan {
        options: soradns::AcmePlanOptions,
        output: JsonTarget,
    },
    SoradnsCachePlan {
        options: soradns::CacheInvalidationPlanOptions,
        output: JsonTarget,
    },
    SoradnsRoutePlan {
        options: soradns::RoutePlanOptions,
        output: JsonTarget,
    },
    SoradnsVerifyBinding {
        binding: PathBuf,
        alias: Option<String>,
        content_cid: Option<String>,
        hostname: Option<String>,
        proof_status: Option<String>,
        manifest: Option<PathBuf>,
    },
    SoradnsVerifyGar {
        options: SoradnsVerifyGarOptions,
    },
    DaThreatModelReport {
        output: JsonTarget,
        seed: u64,
        config_path: Option<PathBuf>,
    },
    DaReplicationAudit {
        options: da::ReplicationAuditOptions,
    },
    DaCommitmentReconcile {
        options: da::CommitmentReconcileOptions,
    },
    DaPrivilegeAudit {
        options: da::PrivilegeAuditOptions,
    },
    DaProofBench {
        options: da::ProofBenchOptions,
    },
    ConfigDebug {
        config: PathBuf,
    },
    SoranetRolloutPlan {
        options: soranet_rollout::PlanOptions,
    },
    SoranetRolloutCapture {
        options: soranet_rollout::CaptureOptions,
    },
    SmWycheproofSync(sm::WycheproofSyncOptions),
    SmOperatorSnippet {
        options: sm::SmOperatorSnippetOptions,
    },
    IsoBridgeLint {
        options: IsoLintOptions,
    },
    CodecRansTables {
        options: codec::RansTablesOptions,
    },
    VerifyRansTables {
        paths: Vec<PathBuf>,
    },
    StreamingBundleCheck {
        options: StreamingBundleCheckOptions,
    },
    StreamingEntropyBench {
        options: streaming_bench::EntropyBenchOptions,
        output: JsonTarget,
    },
    StreamingDecode {
        options: streaming_bench::DecodeOptions,
        output: Option<JsonTarget>,
    },
    Stage1Bench {
        options: stage1_bench::Stage1BenchOptions,
    },
    I3BenchSuite {
        options: i3_bench_suite::I3BenchOptions,
    },
    I3SloHarness {
        options: i3_slo_harness::SloHarnessOptions,
    },
    PoseidonBench {
        options: poseidon_bench::PoseidonBenchOptions,
    },
    StreamingContextRemap {
        options: StreamingContextRemapOptions,
    },
    SpaceDirectoryEncode {
        input: PathBuf,
        output: PathBuf,
    },
    SnsScorecard(sns::ScorecardOptions),
    SnsAnnex(sns::AnnexOptions),
    MinistryTransparency(ministry::Command),
    MinistryAgenda(ministry_agenda::Command),
    MinistryPanel(ministry_panel::Command),
    MinistryJury(ministry_jury::Command),
    NoritoRpcVerify {
        json_out: Option<JsonTarget>,
    },
    NoritoRpcFixtures {
        options: NoritoRpcFixtureOptions,
    },
    AccelerationState {
        format: AccelerationOutputFormat,
    },
    Help,
}
#[derive(Clone, Debug)]
pub(crate) enum JsonTarget {
    Stdout,
    File(PathBuf),
}
#[derive(Clone, Copy)]
enum AccelerationOutputFormat {
    Json,
    Table,
}
impl AccelerationOutputFormat {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            other => Err(format!("unknown format `{other}` (expected json or table)").into()),
        }
    }
}
#[derive(Clone, Debug, JsonSerialize)]
struct AccelerationConfigReport {
    enable_simd: bool,
    enable_metal: bool,
    enable_cuda: bool,
    max_gpus: Option<usize>,
    merkle_min_leaves_gpu: Option<usize>,
    merkle_min_leaves_metal: Option<usize>,
    merkle_min_leaves_cuda: Option<usize>,
    prefer_cpu_sha2_max_leaves_aarch64: Option<usize>,
    prefer_cpu_sha2_max_leaves_x86: Option<usize>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct AccelerationBackendReport {
    supported: bool,
    configured: bool,
    available: bool,
    parity_ok: bool,
    last_error: Option<String>,
}
#[derive(Clone, Debug, JsonSerialize)]
struct AccelerationStateReport {
    config: AccelerationConfigReport,
    simd: AccelerationBackendReport,
    metal: AccelerationBackendReport,
    cuda: AccelerationBackendReport,
}
impl AccelerationStateReport {
    fn capture() -> Self {
        Self::from_parts(
            ivm::acceleration_config(),
            ivm::acceleration_runtime_status(),
            ivm::acceleration_runtime_errors(),
        )
    }
    fn from_parts(
        config: ivm::AccelerationConfig,
        runtime: ivm::AccelerationRuntimeStatus,
        errors: ivm::AccelerationErrorStatus,
    ) -> Self {
        Self {
            config: AccelerationConfigReport::from_config(config),
            simd: AccelerationBackendReport::from_status(runtime.simd, errors.simd),
            metal: AccelerationBackendReport::from_status(runtime.metal, errors.metal),
            cuda: AccelerationBackendReport::from_status(runtime.cuda, errors.cuda),
        }
    }
}
impl AccelerationConfigReport {
    fn from_config(config: ivm::AccelerationConfig) -> Self {
        Self {
            enable_simd: config.enable_simd,
            enable_metal: config.enable_metal,
            enable_cuda: config.enable_cuda,
            max_gpus: config.max_gpus,
            merkle_min_leaves_gpu: config.merkle_min_leaves_gpu,
            merkle_min_leaves_metal: config.merkle_min_leaves_metal,
            merkle_min_leaves_cuda: config.merkle_min_leaves_cuda,
            prefer_cpu_sha2_max_leaves_aarch64: config.prefer_cpu_sha2_max_leaves_aarch64,
            prefer_cpu_sha2_max_leaves_x86: config.prefer_cpu_sha2_max_leaves_x86,
        }
    }
}
impl AccelerationBackendReport {
    fn from_status(status: ivm::BackendRuntimeStatus, last_error: Option<String>) -> Self {
        Self {
            supported: status.supported,
            configured: status.configured,
            available: status.available,
            parity_ok: status.parity_ok,
            last_error,
        }
    }
}
fn run_acceleration_state(format: AccelerationOutputFormat) -> Result<(), Box<dyn Error>> {
    let state = AccelerationStateReport::capture();
    let rendered = render_acceleration_state(&state, format)?;
    println!("{rendered}");
    Ok(())
}
fn render_acceleration_state(
    state: &AccelerationStateReport,
    format: AccelerationOutputFormat,
) -> Result<String, Box<dyn Error>> {
    match format {
        AccelerationOutputFormat::Json => Ok(json::to_string_pretty(state)?),
        AccelerationOutputFormat::Table => Ok(format_acceleration_table(state)),
    }
}
fn format_acceleration_table(state: &AccelerationStateReport) -> String {
    let mut output = String::new();
    let cfg = &state.config;
    let _ = writeln!(output, "Acceleration Configuration");
    let _ = writeln!(output, "--------------------------");
    let _ = writeln!(output, "enable_simd: {}", format_bool(cfg.enable_simd));
    let _ = writeln!(output, "enable_metal: {}", format_bool(cfg.enable_metal));
    let _ = writeln!(output, "enable_cuda: {}", format_bool(cfg.enable_cuda));
    let _ = writeln!(output, "max_gpus: {}", format_optional(cfg.max_gpus));
    let _ = writeln!(
        output,
        "merkle_min_leaves_gpu: {}",
        format_optional(cfg.merkle_min_leaves_gpu)
    );
    let _ = writeln!(
        output,
        "merkle_min_leaves_metal: {}",
        format_optional(cfg.merkle_min_leaves_metal)
    );
    let _ = writeln!(
        output,
        "merkle_min_leaves_cuda: {}",
        format_optional(cfg.merkle_min_leaves_cuda)
    );
    let _ = writeln!(
        output,
        "prefer_cpu_sha2_max_leaves_aarch64: {}",
        format_optional(cfg.prefer_cpu_sha2_max_leaves_aarch64)
    );
    let _ = writeln!(
        output,
        "prefer_cpu_sha2_max_leaves_x86: {}",
        format_optional(cfg.prefer_cpu_sha2_max_leaves_x86)
    );
    let _ = writeln!(output, "Backend Status");
    let _ = writeln!(output, "--------------");
    let _ = writeln!(
        output,
        "{:<6} {:<10} {:<11} {:<10} {:<9} Last error",
        "Backend", "Supported", "Configured", "Available", "ParityOK"
    );
    for (name, backend) in [
        ("SIMD", &state.simd),
        ("Metal", &state.metal),
        ("CUDA", &state.cuda),
    ] {
        let last_error = backend.last_error.as_deref().unwrap_or("-");
        let _ = writeln!(
            output,
            "{:<6} {:<10} {:<11} {:<10} {:<9} {}",
            name,
            format_bool(backend.supported),
            format_bool(backend.configured),
            format_bool(backend.available),
            format_bool(backend.parity_ok),
            last_error
        );
    }
    output
}
fn format_optional(value: Option<usize>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "auto".to_string(),
    }
}
fn format_bool(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
#[derive(Default)]
struct IsoLintOptions {
    isin_path: Option<PathBuf>,
    bic_lei_path: Option<PathBuf>,
    mic_path: Option<PathBuf>,
    fixtures_path: Option<PathBuf>,
}
impl IsoLintOptions {
    fn is_empty(&self) -> bool {
        self.isin_path.is_none()
            && self.bic_lei_path.is_none()
            && self.mic_path.is_none()
            && self.fixtures_path.is_none()
    }
    fn ensure_defaults(&mut self) {
        if self.is_empty() {
            let root = workspace_root();
            self.isin_path = Some(root.join("fixtures/iso_bridge/isin_crosswalk.sample.json"));
            self.bic_lei_path = Some(root.join("fixtures/iso_bridge/bic_lei.sample.json"));
            self.mic_path = Some(root.join("fixtures/iso_bridge/mic_directory.sample.json"));
            self.fixtures_path = Some(root.join("fixtures/iso_bridge/fixtures.json"));
        }
    }
}
struct IsoFixtures {
    instruments: Vec<String>,
    bics: Vec<String>,
    leis: Vec<String>,
    mics: Vec<String>,
}
struct StreamingBundleCheckOptions {
    config_path: PathBuf,
    tables_override: Option<PathBuf>,
    output: JsonTarget,
}
struct StreamingContextRemapOptions {
    input: PathBuf,
    top: usize,
    output: JsonTarget,
}
struct SoradnsVerifyGarOptions {
    gar_path: PathBuf,
    expectations: soradns::GarVerifyOptions,
    json_out: Option<JsonTarget>,
}
impl IsoFixtures {
    fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let raw = fs::read_to_string(path)?;
        let value: Value = json::from_str(&raw)?;
        Ok(Self {
            instruments: string_array(&value, "instruments")?,
            bics: string_array(&value, "bics")?,
            leis: string_array(&value, "leis")?,
            mics: string_array(&value, "mics")?,
        })
    }
}
fn parse_u64_flag(raw: &str, flag: &str) -> Result<u64, Box<dyn Error>> {
    let trimmed = raw.trim();
    let parsed = trimmed
        .parse::<u64>()
        .map_err(|_| format!("{flag} requires an unsigned integer"))?;
    Ok(parsed)
}
fn validate_sorafs_adoption_override_id(raw: &str) -> Result<(), Box<dyn Error>> {
    let mut chars = raw.chars();
    let Some(first) = chars.next() else {
        return Err(
            "--adoption-override-id must be 3-128 characters and start with alphanumeric".into(),
        );
    };
    if raw.len() < 3 || raw.len() > 128 || !first.is_ascii_alphanumeric() {
        return Err(
            "--adoption-override-id must be 3-128 characters and start with alphanumeric".into(),
        );
    }
    if !chars
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '@' | '+' | '-'))
    {
        return Err("--adoption-override-id may contain only [A-Za-z0-9._:@+-] characters".into());
    }
    Ok(())
}
fn unix_timestamp_now() -> Result<u64, Box<dyn Error>> {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok(duration.as_secs()),
        Err(err) => Err(Box::new(err)),
    }
}
fn string_array(root: &Value, key: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let Some(value) = root.as_object().and_then(|map| map.get(key)) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| format!("`{key}` must be an array of strings"))?;
    let mut out = Vec::with_capacity(array.len());
    for entry in array {
        let text = entry
            .as_str()
            .ok_or_else(|| format!("`{key}` entries must be strings"))?
            .trim();
        if !text.is_empty() {
            out.push(text.to_string());
        }
    }
    Ok(out)
}
fn ensure_dataset_loaded<T>(
    snapshot: &DatasetSnapshot<T>,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    match snapshot.state() {
        SnapshotState::Loaded => Ok(()),
        SnapshotState::Missing => Err(format!("{label} dataset was not provided").into()),
        SnapshotState::Failed => {
            let diagnostics = snapshot.diagnostics().unwrap_or("unknown error");
            let source = snapshot
                .configured_path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unknown path".to_string());
            Err(format!("{label} dataset at {source} failed to load: {diagnostics}").into())
        }
    }
}
fn ensure_reference(
    label: &str,
    outcome: Result<(), ReferenceDataError>,
) -> Result<(), Box<dyn Error>> {
    match outcome {
        Ok(()) => Ok(()),
        Err(err) => Err(format!("{label} validation failed: {err}").into()),
    }
}
fn lint_iso_bridge(mut options: IsoLintOptions) -> Result<(), Box<dyn Error>> {
    options.ensure_defaults();
    let config = IsoReferenceData {
        isin_crosswalk_path: options.isin_path.clone(),
        bic_lei_path: options.bic_lei_path.clone(),
        mic_directory_path: options.mic_path.clone(),
        ..IsoReferenceData::default()
    };
    let snapshots = ReferenceDataSnapshots::from_config(&config);
    if options.isin_path.is_some() {
        ensure_dataset_loaded(snapshots.isin_cusip(), "ISIN↔CUSIP crosswalk")?;
    }
    if options.bic_lei_path.is_some() {
        ensure_dataset_loaded(snapshots.bic_lei(), "BIC↔LEI crosswalk")?;
    }
    if options.mic_path.is_some() {
        ensure_dataset_loaded(snapshots.mic_directory(), "MIC directory")?;
    }
    if let Some(fixtures_path) = options.fixtures_path.as_ref() {
        let fixtures = IsoFixtures::load(fixtures_path)?;
        if !fixtures.instruments.is_empty() {
            if options.isin_path.is_none() {
                return Err(
                    "instrument fixtures specified but no ISIN crosswalk configured".into(),
                );
            }
            for isin in &fixtures.instruments {
                ensure_reference(&format!("Instrument {isin}"), snapshots.validate_isin(isin))?;
            }
        }
        if !fixtures.bics.is_empty() {
            if options.bic_lei_path.is_none() {
                return Err("BIC fixtures specified but no BIC↔LEI dataset configured".into());
            }
            for bic in &fixtures.bics {
                ensure_reference(&format!("BIC {bic}"), snapshots.validate_bic(bic))?;
            }
        }
        if !fixtures.leis.is_empty() {
            if options.bic_lei_path.is_none() {
                return Err("LEI fixtures specified but no BIC↔LEI dataset configured".into());
            }
            for lei in &fixtures.leis {
                ensure_reference(&format!("LEI {lei}"), snapshots.validate_lei(lei))?;
            }
        }
        if !fixtures.mics.is_empty() {
            if options.mic_path.is_none() {
                return Err("MIC fixtures specified but no MIC directory configured".into());
            }
            for mic in &fixtures.mics {
                ensure_reference(&format!("MIC {mic}"), snapshots.validate_mic(mic))?;
            }
        }
    }
    println!("ISO bridge reference data lint passed");
    Ok(())
}
fn streaming_bundle_check(options: StreamingBundleCheckOptions) -> Result<(), Box<dyn Error>> {
    let summary = build_streaming_bundle_summary(&options.config_path, options.tables_override)?;
    write_json_output(&summary, options.output)?;
    Ok(())
}
fn build_streaming_bundle_summary(
    config_path: &Path,
    tables_override: Option<PathBuf>,
) -> Result<Value, Box<dyn Error>> {
    let actual = load_actual_config(config_path)?;
    let codec = &actual.streaming.codec;
    let tables_path = tables_override.unwrap_or_else(|| codec.rans_tables_path.clone());
    let tables_path = if tables_path.is_relative() {
        workspace_root().join(&tables_path)
    } else {
        tables_path
    };
    let tables = load_bundle_tables_from_toml(&tables_path).map_err(|err| {
        format!(
            "failed to load bundled rANS tables `{}`: {err}",
            tables_path.display()
        )
    })?;
    let checksum_hex = hex::encode(tables.checksum());
    let mut tables_json = json::Map::new();
    tables_json.insert(
        "path".into(),
        json::Value::from(tables_path.display().to_string()),
    );
    tables_json.insert(
        "precision_bits".into(),
        json::Value::from(tables.precision_bits()),
    );
    tables_json.insert("checksum".into(), json::Value::from(checksum_hex));
    let mut summary = json::Map::new();
    summary.insert(
        "config".into(),
        json::Value::from(config_path.display().to_string()),
    );
    summary.insert(
        "feature_bits".into(),
        json::Value::from(actual.streaming.feature_bits),
    );
    summary.insert(
        "bundle_required".into(),
        json::Value::from(codec.entropy_mode.is_bundled()),
    );
    summary.insert(
        "entropy_mode".into(),
        json::Value::from(codec.entropy_mode.to_string()),
    );
    summary.insert("bundle_width".into(), json::Value::from(codec.bundle_width));
    summary.insert(
        "bundle_accel".into(),
        json::Value::from(bundle_accel_label(codec.bundle_accel)),
    );
    let gpu_available = norito::streaming::BUNDLED_RANS_GPU_BUILD_AVAILABLE;
    let accel_allowed = match codec.bundle_accel {
        actual::BundleAcceleration::Gpu => gpu_available,
        _ => true,
    };
    summary.insert(
        "gpu_build_available".into(),
        json::Value::from(gpu_available),
    );
    summary.insert(
        "bundle_accel_allowed".into(),
        json::Value::from(accel_allowed),
    );
    summary.insert("tables".into(), json::Value::Object(tables_json));
    Ok(json::Value::Object(summary))
}
fn bundle_accel_label(accel: actual::BundleAcceleration) -> &'static str {
    match accel {
        actual::BundleAcceleration::None => "none",
        actual::BundleAcceleration::CpuSimd => "cpu_simd",
        actual::BundleAcceleration::Gpu => "gpu",
    }
}
#[derive(JsonSerialize)]
struct ContextRemapRow {
    original: u16,
    remapped: Option<u16>,
    bundles: u64,
    total_bits: u64,
    dominant_symbol: Option<SymbolCount>,
}
#[derive(JsonSerialize)]
struct SymbolCount {
    symbol: u8,
    count: u64,
}
#[derive(JsonSerialize)]
struct ContextRemapReport {
    input: String,
    total_contexts: usize,
    escape_context: u16,
    kept: Vec<ContextRemapRow>,
    dropped: Vec<ContextRemapRow>,
}
const CONTEXT_SYMBOL_CAP: usize = 1 << 4;
fn streaming_context_remap(options: StreamingContextRemapOptions) -> Result<(), Box<dyn Error>> {
    let raw = fs::read_to_string(&options.input)?;
    let telemetry: Value = json::from_str(&raw)?;
    let Some(raw_contexts) = telemetry
        .get("context_frequencies")
        .and_then(Value::as_array)
    else {
        return Err("context_frequencies missing from telemetry".into());
    };
    let mut contexts: Vec<ContextFrequency> = raw_contexts
        .iter()
        .filter_map(parse_context_frequency)
        .collect();
    if contexts.is_empty() {
        return Err("context_frequencies empty or unparsable".into());
    }
    contexts.sort_by(|a, b| {
        b.bundles
            .cmp(&a.bundles)
            .then_with(|| b.total_bits.cmp(&a.total_bits))
    });
    let keep = options.top.min(contexts.len());
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for (idx, ctx) in contexts.iter().enumerate() {
        let remapped = (idx < keep).then_some(idx as u16);
        let row = ContextRemapRow::from_frequency(ctx, remapped);
        if idx < keep {
            kept.push(row);
        } else {
            dropped.push(row);
        }
    }
    let report = ContextRemapReport {
        input: options.input.display().to_string(),
        total_contexts: contexts.len(),
        escape_context: u16::MAX,
        kept,
        dropped,
    };
    let value = json::to_value(&report)?;
    write_json_output(&value, options.output)
}
impl ContextRemapRow {
    fn from_frequency(freq: &ContextFrequency, remapped: Option<u16>) -> Self {
        let dominant_symbol = dominant_symbol(&freq.symbol_counts);
        Self {
            original: freq.context.0,
            remapped,
            bundles: freq.bundles,
            total_bits: freq.total_bits,
            dominant_symbol,
        }
    }
}
fn dominant_symbol(counts: &[u64]) -> Option<SymbolCount> {
    counts
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, count)| *count > 0)
        .max_by(
            |(a_idx, a_count), (b_idx, b_count)| match b_count.cmp(a_count) {
                Ordering::Equal => a_idx.cmp(b_idx),
                other => other,
            },
        )
        .map(|(symbol, count)| SymbolCount {
            symbol: symbol as u8,
            count,
        })
}
fn parse_context_frequency(entry: &Value) -> Option<ContextFrequency> {
    let obj = entry.as_object()?;
    let context = obj.get("context")?.as_u64()? as u16;
    let bundles = obj.get("bundles").and_then(Value::as_u64).unwrap_or(0);
    let total_bits = obj.get("total_bits").and_then(Value::as_u64).unwrap_or(0);
    let mut symbol_counts = [0u64; CONTEXT_SYMBOL_CAP];
    if let Some(array) = obj.get("symbol_counts").and_then(Value::as_array) {
        for (idx, value) in array.iter().enumerate().take(CONTEXT_SYMBOL_CAP) {
            symbol_counts[idx] = value.as_u64().unwrap_or(0);
        }
    }
    Some(ContextFrequency {
        context: BundleContextId::new(context),
        bundles,
        total_bits,
        symbol_counts,
    })
}
fn entrypoint() -> Result<(), Box<dyn Error>> {
    let command = parse_command(env::args())?;
    match command {
        CommandKind::OpenApi {
            outputs,
            canonical_spec,
            manifest,
            signature_envelope,
            signing_payload,
            unsigned_manifest,
        } => generate_openapi(
            outputs,
            canonical_spec,
            manifest,
            signature_envelope,
            signing_payload,
            unsigned_manifest,
        )?,
        CommandKind::OpenApiVerify {
            spec,
            manifest,
            allow_unsigned,
            allowed_signers,
        } => verify_openapi_manifest(&spec, &manifest, allow_unsigned, Some(&allowed_signers))?,
        CommandKind::AddressVectors { target, verify } => match (target, verify) {
            (JsonTarget::Stdout, true) => {
                return Err(
                    "--verify is not supported when writing address vectors to stdout".into(),
                );
            }
            (JsonTarget::Stdout, false) => {
                write_address_vectors(JsonTarget::Stdout)?;
            }
            (JsonTarget::File(path), false) => {
                write_address_vectors(JsonTarget::File(path))?;
            }
            (JsonTarget::File(path), true) => {
                verify_address_vectors(&path)?;
            }
        },
        CommandKind::ZkDevVoteFixture {
            output,
            verify,
            print_hashes,
            summary_target,
            attestation_target,
        } => generate_dev_vote_fixture(
            output,
            verify,
            print_hashes,
            summary_target,
            attestation_target,
        )?,
        CommandKind::SoranetFixtures { output, verify } => {
            if verify {
                soranet::verify_fixtures(&output)?;
            } else {
                soranet::generate_capability_fixtures(&output)?;
            }
        }
        CommandKind::SoranetChaosKit { options } => {
            let outcome = soranet_chaos::write_chaos_kit(options)?;
            println!(
                "soranet-chaos-kit wrote plan={} markdown={} ({} scripts, log={})",
                outcome.plan_json.display(),
                outcome.plan_markdown.display(),
                outcome.scripts.len(),
                outcome.log_path.display()
            );
        }
        CommandKind::SoranetChaosReport { options } => {
            let summary = soranet_chaos::summarize_log(options)?;
            println!(
                "soranet-chaos-report processed {} (scenarios={})",
                summary.log_path.display(),
                summary.scenarios.len()
            );
        }
        CommandKind::ComputeSloReport { options } => {
            compute::run_slo_report(options)?;
        }
        CommandKind::ComputeFixtures { options } => {
            compute::write_fixtures(options)?;
        }
        CommandKind::DaThreatModelReport {
            output,
            seed,
            config_path,
        } => {
            da::generate_threat_model_report(da::ThreatModelReportOptions {
                output,
                seed,
                config_path,
            })?;
        }
        CommandKind::DaReplicationAudit { options } => {
            da::run_replication_audit(options)?;
        }
        CommandKind::DaCommitmentReconcile { options } => {
            da::run_commitment_reconciliation(options)?;
        }
        CommandKind::DaPrivilegeAudit { options } => {
            da::run_privilege_audit(options)?;
        }
        CommandKind::DaProofBench { options } => {
            let report = da::run_proof_bench(options)?;
            println!(
                "da-proof-bench: iterations={} proofs/run={} avg_total_ms={:.2} recommended_budget_ms={}",
                report.iterations,
                report.stats.proof_count,
                report.stats.average_total_ms,
                report.stats.recommended_budget_ms
            );
        }
        CommandKind::ConfigDebug { config } => {
            run_config_debug(&config)?;
        }
        CommandKind::KagamiBundle {
            output,
            profile,
            network_profiles,
        } => {
            let path = kagami_bundle::bundle(&output, &profile, network_profiles.as_deref())?;
            println!("Kagami CLI bundle: {}", path.display());
        }
        CommandKind::MochiBundle {
            output,
            profile,
            archive,
            matrix,
            smoke,
            stage,
            network_profiles,
        } => {
            let result =
                mochi::bundle_mochi(&output, &profile, archive, network_profiles.as_deref())?;
            let smoke_passed = if smoke {
                mochi::run_bundle_smoke(&result)?;
                true
            } else {
                false
            };
            if let Some(matrix_path) = matrix {
                mochi::update_bundle_matrix(&result, &matrix_path, smoke_passed)?;
            }
            if let Some(stage_root) = stage {
                mochi::stage_bundle(&result, &stage_root)?;
            }
        }
        CommandKind::MochiLatency { bundle, output } => {
            mochi::latency::collect(&bundle, &output)?;
        }
        CommandKind::MochiLatencyReport { samples, output } => {
            mochi::latency::summarize(&samples, &output)?;
        }
        CommandKind::MochiLatencyRemote {
            bundle,
            driver,
            output,
        } => {
            mochi::latency::collect_remote(&bundle, &driver, &output)?;
        }
        CommandKind::KagamiProfiles { options } => {
            kagami_profiles::generate(options)?;
        }
        CommandKind::SorafsAdmissionFixtures { output } => {
            sorafs::write_admission_fixtures(&output)?;
        }
        CommandKind::SorafsGatewayFixtures { output, verify } => {
            if verify {
                sorafs::verify_gateway_fixtures(&output)?;
            } else {
                sorafs::write_gateway_fixtures(&output)?;
            }
        }
        CommandKind::SorafsFetchFixture { options } => {
            sorafs::fetch_fixture(*options)?;
        }
        CommandKind::SorafsPinFixtures { output } => {
            sorafs::write_pin_registry_fixture(output)?;
        }
        CommandKind::SorafsAdoptionCheck { options, report } => {
            let adoption = sorafs::adoption::run_adoption_check(options)?;
            let mut message = format!(
                "sorafs adoption check: validated {} scoreboard(s) (min eligible per file = {})",
                adoption.total_evaluated, adoption.min_providers_required
            );
            if adoption.single_source_override_used {
                message.push_str(" (single-source override accepted)");
            }
            println!("{message}");
            if let Some(path) = report {
                let rendered = json::to_string_pretty(&adoption)?;
                fs::write(&path, rendered)?;
                println!("sorafs adoption check report written to {}", path.display());
            }
        }
        CommandKind::SorafsScoreboardDiff { options, report } => {
            let diff = sorafs::adoption::run_scoreboard_diff(options)?;
            sorafs::adoption::print_scoreboard_diff(&diff);
            if let Some(path) = report {
                let rendered = json::to_string_pretty(&diff)?;
                fs::write(&path, rendered)?;
                println!(
                    "sorafs scoreboard diff report written to {}",
                    path.display()
                );
            }
        }
        CommandKind::SorafsBurnInCheck { options, output } => {
            let summary = sorafs::adoption::run_burn_in_check(options)?;
            let rendered = json::to_string_pretty(&summary)?;
            if let Some(path) = output {
                fs::write(path, rendered)?;
            } else {
                println!("{rendered}");
            }
        }
        CommandKind::SorafsReserveMatrix { options, target } => {
            let value = sorafs::reserve_matrix_report(options)?;
            write_json_output(&value, target)?;
        }
        CommandKind::SorafsGatewayAttest { options } => {
            sorafs::generate_gateway_attestation(*options)?;
        }
        CommandKind::SorafsGatewayAttestVerify { envelope } => {
            sorafs::verify_gateway_attestation(&envelope)?;
        }
        CommandKind::SorafsGatewayProbe { options } => {
            sorafs::run_gateway_probe(*options)?;
        }
        CommandKind::SoracloudInrouSmoke { mode } => {
            soracloud_inrou::run(mode)?;
        }
        CommandKind::SorafsGatewayCli { command } => {
            sorafs::run_gateway_cli(*command)?;
        }
        CommandKind::SoranetPopBundle { options } => {
            let outcome = soranet_pop::build_pop_bundle(*options)?;
            let (pop_name, image_tag) = outcome.summary();
            println!(
                "soranet-pop-bundle wrote {} (pop={}, image_tag={})",
                outcome.manifest_path.display(),
                pop_name,
                image_tag
            );
        }
        CommandKind::SoranetPopCtl { options } => {
            let outcome = soranet_pop::build_pop_bundle(*options)?;
            let (pop_name, image_tag) = outcome.summary();
            println!(
                "soranet-popctl wrote {} (pop={}, image_tag={})",
                outcome.manifest_path.display(),
                pop_name,
                image_tag
            );
        }
        CommandKind::SoranetPopTemplate {
            input,
            output,
            resolver_config,
            edns_out,
            edns_resolver,
            ds_out,
            edns_tool,
        } => {
            soranet_pop::render_frr_config(&input, &output)?;
            if let Some(config_path) = resolver_config {
                soranet_pop::render_resolver_config(&input, &config_path)?;
            }
            if let Some(ds_path) = ds_out {
                soranet_pop::run_ds_validation(&ds_path)?;
            }
            if let Some(edns_path) = edns_out {
                let resolver = edns_resolver.as_deref().unwrap_or("127.0.0.1");
                soranet_pop::run_edns_matrix(resolver, &edns_path, edns_tool.as_deref())?;
            }
        }
        CommandKind::SoranetPopValidate { input, roa, output } => {
            let report = soranet_pop::validate_pop_descriptor(&input, roa.as_deref())?;
            let value = report.to_value();
            write_json_output(&value, output)?;
        }
        CommandKind::SoranetPopPolicyReport { options } => {
            let outcome = soranet_pop::build_pop_policy_harness(*options)?;
            println!(
                "soranet-pop-policy-report wrote {}",
                outcome.report_path.display()
            );
        }
        CommandKind::SoranetPopPlan {
            input,
            roa,
            frr_out,
            report_out,
        } => {
            soranet_pop::render_frr_config(&input, &frr_out)?;
            let report = soranet_pop::validate_pop_descriptor(&input, roa.as_deref())?;
            let value = report.to_value();
            write_json_output(&value, report_out)?;
            println!("soranet-pop-plan wrote FRR config to {}", frr_out.display());
        }
        CommandKind::SoranetGatewayM0 { options } => {
            let outcome = soranet_gateway::write_gateway_m0_pack(options)?;
            println!(
                "soranet-gateway-m0 wrote {}",
                outcome.summary_path.display()
            );
        }
        CommandKind::SoranetGatewayM1 { options } => {
            let outcome = soranet_gateway_m1::run_gateway_m1(options)?;
            println!(
                "soranet-gateway-m1 wrote {}",
                outcome.summary_path.display()
            );
        }
        CommandKind::SoranetGatewayM2 { options } => {
            let outcome = soranet_gateway_m2::run_gateway_m2(options)?;
            println!(
                "soranet-gateway-m2 wrote {}",
                outcome.summary_path.display()
            );
        }
        CommandKind::SoranetGatewayM3 { options } => {
            let outcome = soranet_gateway_m3::run_gateway_m3(options)?;
            println!(
                "soranet-gateway-m3 wrote {} (markdown {})",
                outcome.summary_json.display(),
                outcome.summary_markdown.display()
            );
        }
        CommandKind::SoranetGatewayOpsM0 { options } => {
            let outcome = soranet_gateway_ops::write_gateway_ops_pack(options)?;
            println!(
                "soranet-gateway-ops-m0 wrote {}",
                outcome.summary_path.display()
            );
        }
        CommandKind::SoranetGatewayPq { options } => {
            let outcome = soranet_gateway_pq::run_gateway_pq_readiness(options)?;
            println!(
                "soranet-gateway-pq wrote json={} markdown={}",
                outcome.summary_json.display(),
                outcome.summary_markdown.display()
            );
        }
        CommandKind::SoranetBugBounty { options } => {
            let outcome = soranet_bug_bounty::generate_bug_bounty_pack(options)?;
            println!(
                "soranet-bug-bounty wrote summary={} triage={}",
                outcome.summary_path.display(),
                outcome.triage_checklist_path.display()
            );
        }
        CommandKind::SoranetGatewayOpsM1 { options } => {
            let outcome = soranet_gateway_ops::write_gateway_ops_federated_pack(options)?;
            println!(
                "soranet-gateway-ops-m1 wrote {}",
                outcome.summary_path.display()
            );
        }
        CommandKind::SoranetGatewayChaos { options } => {
            let outcome = soranet_gateway_chaos::run(options)?;
            println!(
                "soranet-gateway-chaos wrote plan={} report={} markdown={}",
                outcome.plan_path.display(),
                outcome.report_path.display(),
                outcome.markdown_path.display()
            );
        }
        CommandKind::SoranetGatewayHardening { options } => {
            let outcome = soranet_gateway_hardening::run_gateway_hardening(options)?;
            println!(
                "soranet-gateway-hardening wrote json={} markdown={}",
                outcome.summary_json.display(),
                outcome.summary_markdown.display()
            );
        }
        CommandKind::SoranetGarController { options } => {
            let summary = soranet_gar_controller::run_gar_controller(options)?;
            println!(
                "soranet-gar-controller wrote events {} receipts {} metrics {} reconciliation {}",
                summary.events_path,
                summary.receipts_dir,
                summary.metrics_path,
                summary.reconciliation_path
            );
            println!(
                "audit log {} report: {}",
                summary.audit_log_path,
                summary
                    .markdown_report
                    .as_deref()
                    .unwrap_or("no report emitted")
            );
        }
        CommandKind::SoranetGarExport { options, output } => {
            let summary = gar::export_receipts(options)?;
            write_json_output(&summary, output)?;
        }
        CommandKind::SoranetGatewayBilling { options } => {
            let outcome = soranet_gateway_billing::run_billing(options)?;
            println!(
                "soranet-gateway-billing wrote invoice={} csv={} parquet={} ledger={} reconciliation={}",
                outcome.invoice_path.display(),
                outcome.csv_path.display(),
                outcome.parquet_path.display(),
                outcome.ledger_path.display(),
                outcome.reconciliation_report_path.display()
            );
        }
        CommandKind::TaikaiAnchorBundle { options } => {
            taikai_anchor::run_anchor_bundle(options)?;
        }
        CommandKind::TaikaiRptVerify { options } => {
            taikai::run_rpt_verify(options)?;
        }
        CommandKind::SoranetPrivacyReport {
            options,
            json_out,
            max_bucket_records,
            suppression_ratio_budget,
        } => {
            let report = soranet_privacy::run_privacy_report(&options)?;
            soranet_privacy::print_summary(&report, max_bucket_records);
            if let Some(target) = json_out {
                soranet_privacy::write_report_json(&report, target, max_bucket_records)?;
            }
            if let Some(threshold) = suppression_ratio_budget {
                match report.suppression_ratio() {
                    Some(ratio) => {
                        if ratio > threshold {
                            return Err(format!(
                                "suppression ratio {:.2}% exceeded threshold {:.2}%",
                                ratio * 100.0,
                                threshold * 100.0
                            )
                            .into());
                        }
                    }
                    None => {
                        return Err(
                            "no completed buckets available; rerun after relays emit privacy metrics"
                                .into(),
                        );
                    }
                }
            }
        }
        CommandKind::SoranetConstantRateProfile {
            selection,
            format,
            include_tick_table,
            tick_values,
            json_out,
        } => {
            let options = soranet::ConstantRateProfileOptions {
                selection,
                include_tick_table,
                tick_values_ms: tick_values,
            };
            let report = soranet::build_constant_rate_report(&options)?;
            match format {
                soranet::ConstantRateOutputFormat::Table => {
                    let table = soranet::format_profile_table(&report.profiles);
                    print!("{table}");
                    if let Some(entries) = &report.tick_bandwidth {
                        println!();
                        let ticks = soranet::format_tick_table(entries);
                        print!("{ticks}");
                    }
                    if !report.profiles.is_empty() {
                        println!();
                        for summary in &report.profiles {
                            println!("{}: {}", summary.name, summary.description);
                        }
                    }
                }
                soranet::ConstantRateOutputFormat::Json => {
                    let rendered = json::to_string_pretty(&report)?;
                    println!("{rendered}");
                }
                soranet::ConstantRateOutputFormat::Markdown => {
                    let table = soranet::format_profile_markdown_table(&report.profiles);
                    print!("{table}");
                    if let Some(entries) = &report.tick_bandwidth {
                        println!();
                        let ticks = soranet::format_tick_markdown_table(entries);
                        print!("{ticks}");
                    }
                    if !report.profiles.is_empty() {
                        println!();
                        for summary in &report.profiles {
                            println!("* `{}` – {}", summary.name, summary.description);
                        }
                    }
                }
            }
            if let Some(target) = json_out {
                let mut serialized = json::to_string_pretty(&report)?;
                serialized.push('\n');
                match target {
                    JsonTarget::Stdout => {
                        print!("{serialized}");
                    }
                    JsonTarget::File(path) => {
                        if let Some(parent) = path.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::write(path, serialized)?;
                    }
                }
            }
        }
        CommandKind::NexusLaneMaintenance { options } => {
            let report = nexus_lane_maintenance::run(options)?;
            eprintln!(
                "surveyed {} declared lane(s) and {} instance block path(s)",
                report.declared_lanes.len(),
                report.instance_blocks.len()
            );
        }
        CommandKind::NexusLaneAudit { options } => {
            nexus::run_lane_audit(&options)?;
        }
        CommandKind::NexusConnectFixture { options } => {
            nexus::run_nexus_connect_fixture(&options)?;
        }
        CommandKind::SoranetTestnetKit { output } => {
            generate_testnet_kit(output)?;
        }
        CommandKind::SoranetTestnetMetrics { input, output } => {
            evaluate_testnet_metrics(input, output)?;
        }
        CommandKind::SoranetTestnetFeed { options } => {
            generate_verification_feed(*options)?;
        }
        CommandKind::SoranetTestnetDrillBundle { options } => {
            generate_drill_bundle(*options)?;
        }
        CommandKind::FastpqBenchManifest { options } => {
            fastpq::write_bench_manifest(*options)?;
        }
        CommandKind::FastpqVerifyBenchManifest {
            manifest,
            trusted_public_key,
        } => {
            fastpq::verify_bench_manifest(&manifest, &trusted_public_key)?;
        }
        CommandKind::FastpqStageProfile { options } => {
            fastpq::run_stage_profile(&options)?;
        }
        CommandKind::FastpqCudaSuite { options } => {
            let result = fastpq::run_cuda_suite(&options)?;
            eprintln!("fastpq-cuda-suite: raw {}", result.raw_output.display());
            if let Some(wrapped) = result.wrapped_output {
                eprintln!("fastpq-cuda-suite: wrapped {}", wrapped.display());
            }
            eprintln!(
                "fastpq-cuda-suite: plan {}{}",
                result.summary.display(),
                if result.dry_run { " (dry-run)" } else { "" }
            );
        }
        CommandKind::SoradnsDirectoryRelease { options } => {
            soradns::release_directory(*options)?;
        }
        CommandKind::SoradnsHosts {
            names,
            pretty_suffix,
            json,
            verify,
        } => {
            let summaries =
                soradns::derive_host_summaries_with_pretty_suffix(&names, &pretty_suffix)?;
            if let Some(target) = json {
                let mut rendered = json::to_string_pretty(&summaries)?;
                rendered.push('\n');
                match target {
                    JsonTarget::Stdout => {
                        print!("{rendered}");
                    }
                    JsonTarget::File(path) => {
                        fs::write(path, rendered)?;
                    }
                }
            } else {
                for summary in &summaries {
                    println!("{}", summary.name);
                    println!("  normalized : {}", summary.normalized_name);
                    println!("  canonical  : {}", summary.canonical_host);
                    println!("  pretty     : {}", summary.pretty_host);
                    println!("  hash label : {}", summary.canonical_label);
                    println!("  wildcard   : {}", summary.canonical_wildcard);
                    println!();
                }
            }
            if !verify.is_empty() {
                soradns::verify_host_patterns(&summaries, &verify)?;
            }
        }
        CommandKind::SoradnsBindingTemplate {
            options,
            json,
            headers_out,
        } => {
            let render = soradns::build_binding_template(&options)?;
            let mut rendered = json::to_string_pretty(&render.payload)?;
            rendered.push('\n');
            match json {
                Some(JsonTarget::Stdout) | None => {
                    print!("{rendered}");
                }
                Some(JsonTarget::File(path)) => {
                    fs::write(path, rendered)?;
                }
            }
            if let Some(path) = headers_out {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, render.headers_template.as_bytes())?;
                println!("headers written to {}", path.display());
            } else {
                println!("{}", render.headers_template);
            }
        }
        CommandKind::SoradnsGarTemplate { options, output } => {
            let payload = soradns::build_gar_template(&options)?;
            let mut rendered = json::to_string_pretty(&payload)?;
            rendered.push('\n');
            match output {
                Some(JsonTarget::Stdout) | None => {
                    print!("{rendered}");
                }
                Some(JsonTarget::File(path)) => {
                    fs::write(path, rendered)?;
                }
            }
        }
        CommandKind::SoradnsAcmePlan { options, output } => {
            let plan = soradns::build_acme_plan(&options)?;
            let mut rendered = json::to_string_pretty(&plan)?;
            rendered.push('\n');
            match output {
                JsonTarget::Stdout => {
                    print!("{rendered}");
                }
                JsonTarget::File(path) => {
                    fs::write(path, rendered)?;
                }
            }
        }
        CommandKind::SoradnsCachePlan { options, output } => {
            let plan = soradns::build_cache_invalidation_plan(&options)?;
            let mut rendered = json::to_string_pretty(&plan)?;
            rendered.push('\n');
            match output {
                JsonTarget::Stdout => {
                    print!("{rendered}");
                }
                JsonTarget::File(path) => {
                    fs::write(path, rendered)?;
                }
            }
        }
        CommandKind::SoradnsRoutePlan { options, output } => {
            let plan = soradns::build_route_plan(&options)?;
            let mut rendered = json::to_string_pretty(&plan)?;
            rendered.push('\n');
            match output {
                JsonTarget::Stdout => {
                    print!("{rendered}");
                }
                JsonTarget::File(path) => {
                    fs::write(path, rendered)?;
                }
            }
        }
        CommandKind::SoradnsVerifyBinding {
            binding,
            alias,
            content_cid,
            hostname,
            proof_status,
            manifest,
        } => {
            let summary = soradns::verify_gateway_binding(
                &binding,
                &soradns::GatewayBindingExpectations {
                    alias,
                    content_cid,
                    hostname,
                    proof_status,
                    manifest_path: manifest,
                },
            )?;
            let alias_display = summary.alias.as_deref().unwrap_or("<no-alias>");
            let status_display = summary.proof_status.as_deref().unwrap_or("<unknown>");
            println!(
                "[soradns] verified gateway binding {alias_display} -> {} (canonical_label={}, canonical_host={}, status={status_display})",
                summary.content_cid, summary.canonical_label, summary.canonical_host
            );
        }
        CommandKind::SoradnsVerifyGar { options } => {
            let summary = soradns::verify_gar_payload(&options.gar_path, &options.expectations)?;
            if let Some(target) = &options.json_out {
                let mut rendered = json::to_string_pretty(&summary.to_json_value())?;
                rendered.push('\n');
                match target {
                    JsonTarget::Stdout => {
                        print!("{rendered}");
                    }
                    JsonTarget::File(path) => {
                        if let Some(parent) = path.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::write(path, rendered)?;
                    }
                }
            } else {
                println!(
                    "[soradns] verified GAR {} -> {} (canonical_label={}, hosts={}, telemetry_labels={}, valid_from={}, valid_until={})",
                    summary.normalized_name,
                    summary.manifest_cid,
                    summary.canonical_label,
                    summary.host_patterns.len(),
                    summary.telemetry_labels.len(),
                    summary.valid_from_epoch,
                    summary
                        .valid_until_epoch
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                );
            }
        }
        CommandKind::SoranetRolloutPlan { options } => {
            soranet_rollout::generate_plan(options)?;
        }
        CommandKind::SoranetRolloutCapture { options } => {
            soranet_rollout::capture_rollout(options)?;
        }
        CommandKind::SmWycheproofSync(options) => sm::sync_wycheproof(options)?,
        CommandKind::SmOperatorSnippet { options } => sm::generate_sm_operator_snippet(options)?,
        CommandKind::IsoBridgeLint { options } => lint_iso_bridge(options)?,
        CommandKind::NoritoRpcVerify { json_out } => {
            run_verify(json_out).map_err(|err| -> Box<dyn Error> { err.into() })?;
        }
        CommandKind::NoritoRpcFixtures { options } => {
            run_norito_rpc_fixtures(options)?;
        }
        CommandKind::CodecRansTables { options } => {
            codec::execute_rans_tables(options)?;
        }
        CommandKind::VerifyRansTables { paths } => {
            codec::verify_tables(&paths)?;
        }
        CommandKind::StreamingBundleCheck { options } => {
            streaming_bundle_check(options)?;
        }
        CommandKind::StreamingEntropyBench { options, output } => {
            let summary = streaming_bench::run_entropy_bench(options)?;
            write_json_output(&summary, output)?;
        }
        CommandKind::StreamingDecode { options, output } => {
            let summary = streaming_bench::run_streaming_decode(options)?;
            if let Some(target) = output {
                write_json_output(&summary, target)?;
            }
        }
        CommandKind::Stage1Bench { options } => {
            stage1_bench::run_stage1_bench(options)?;
        }
        CommandKind::I3BenchSuite { options } => {
            let report = i3_bench_suite::run_i3_bench_suite(options.clone())?;
            println!(
                "i3 bench suite wrote {} scenarios to {}",
                report.scenarios.len(),
                options.json_out.display()
            );
        }
        CommandKind::I3SloHarness { options } => {
            i3_slo_harness::run_i3_slo_harness(options)?;
        }
        CommandKind::PoseidonBench { options } => {
            poseidon_bench::run_poseidon_bench(options)?;
        }
        CommandKind::StreamingContextRemap { options } => {
            streaming_context_remap(options)?;
        }
        CommandKind::SpaceDirectoryEncode { input, output } => {
            encode_space_directory_manifest(&input, &output)?;
        }
        CommandKind::AccelerationState { format } => run_acceleration_state(format)?,
        CommandKind::SnsScorecard(options) => {
            sns::generate_scorecard(options)?;
        }
        CommandKind::SnsAnnex(options) => {
            sns::generate_annex(options)?;
        }
        CommandKind::MinistryTransparency(command) => {
            ministry::run(command)?;
        }
        CommandKind::MinistryAgenda(command) => {
            ministry_agenda::run(command)?;
        }
        CommandKind::MinistryPanel(command) => {
            ministry_panel::run(command)?;
        }
        CommandKind::MinistryJury(command) => {
            ministry_jury::run(command)?;
        }
        CommandKind::Help => {
            print_usage();
        }
    }
    Ok(())
}
fn parse_command<I>(mut args: I) -> Result<CommandKind, Box<dyn Error>>
where
    I: Iterator<Item = String>,
{
    let _ = args.next();
    let Some(cmd) = args.next() else {
        print_usage();
        return Err("missing command".into());
    };
    match cmd.as_str() {
        "-h" | "--help" => Ok(CommandKind::Help),
        "soracloud-inrou-smoke" => {
            let Some(mode) = args.next() else {
                return Err("soracloud-inrou-smoke requires mode `portable`".into());
            };
            match mode.as_str() {
                "portable" => Ok(CommandKind::SoracloudInrouSmoke {
                    mode: soracloud_inrou::CommandMode::Portable,
                }),
                other => Err(format!(
                    "unknown soracloud-inrou-smoke mode `{other}` (expected `portable`)"
                )
                .into()),
            }
        }
        "openapi" => {
            let mut outputs = Vec::new();
            let mut output_root: Option<PathBuf> = None;
            let mut manifest_path: Option<PathBuf> = None;
            let mut signature_envelope: Option<PathBuf> = None;
            let mut signing_payload: Option<PathBuf> = None;
            let mut unsigned_manifest = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        outputs.push(normalize_path(Path::new(&path))?);
                    }
                    "--output-root" => {
                        let Some(path) = pending.next() else {
                            return Err("expected directory after --output-root".into());
                        };
                        if output_root.is_some() {
                            return Err("openapi accepts --output-root only once".into());
                        }
                        output_root = Some(normalize_openapi_output_root(&path)?);
                    }
                    "--manifest" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --manifest".into());
                        };
                        if manifest_path.is_some() {
                            return Err("openapi accepts --manifest only once".into());
                        }
                        manifest_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--signature-envelope" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --signature-envelope".into());
                        };
                        if signature_envelope.is_some() {
                            return Err("openapi accepts --signature-envelope only once".into());
                        }
                        signature_envelope = Some(normalize_path(Path::new(&path))?);
                    }
                    "--signing-payload" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --signing-payload".into());
                        };
                        if signing_payload.is_some() {
                            return Err("openapi accepts --signing-payload only once".into());
                        }
                        signing_payload = Some(normalize_path(Path::new(&path))?);
                    }
                    "--unsigned-manifest" => {
                        if unsigned_manifest {
                            return Err("openapi accepts --unsigned-manifest only once".into());
                        }
                        unsigned_manifest = true;
                    }
                    flag => return Err(format!("unknown flag for openapi: {flag}").into()),
                }
            }
            if unsigned_manifest && signature_envelope.is_some() {
                return Err(
                    "openapi flag --unsigned-manifest cannot be combined with --signature-envelope"
                        .into(),
                );
            }
            if signing_payload.is_some() && !unsigned_manifest && signature_envelope.is_none() {
                return Err(
                    "openapi flag --signing-payload requires --unsigned-manifest or --signature-envelope"
                        .into(),
                );
            }
            if output_root.is_some() && (!outputs.is_empty() || manifest_path.is_some()) {
                return Err(
                    "openapi --output-root cannot be combined with --output or --manifest".into(),
                );
            }
            let (canonical_spec, manifest) = if let Some(root) = output_root {
                let canonical_spec = root.join("torii.json");
                let manifest = root.join("manifest.json");
                outputs.push(canonical_spec.clone());
                (canonical_spec, manifest)
            } else {
                if outputs.is_empty() {
                    outputs.push(default_openapi_path());
                }
                (
                    default_openapi_path(),
                    manifest_path.unwrap_or_else(default_openapi_manifest_path),
                )
            };
            for (index, output) in outputs.iter().enumerate() {
                if openapi_paths_alias(output, &manifest) {
                    return Err(format!(
                        "openapi output {} must not alias the manifest path {}",
                        output.display(),
                        manifest.display()
                    )
                    .into());
                }
                for other in &outputs[index + 1..] {
                    if openapi_paths_alias(output, other) {
                        return Err(format!(
                            "openapi output paths must be distinct and non-aliasing: {} and {}",
                            output.display(),
                            other.display()
                        )
                        .into());
                    }
                }
            }
            outputs.sort();
            if let Some(signing_payload_path) = signing_payload.as_deref() {
                for (label, reserved) in outputs
                    .iter()
                    .map(|path| ("OpenAPI output", path.as_path()))
                    .chain(std::iter::once(("manifest", manifest.as_path())))
                    .chain(
                        signature_envelope
                            .as_deref()
                            .map(|path| ("signature envelope", path)),
                    )
                {
                    if openapi_paths_alias(signing_payload_path, reserved) {
                        return Err(format!(
                            "openapi --signing-payload must not alias the {label} path {}",
                            reserved.display()
                        )
                        .into());
                    }
                }
            }
            if let Some(signature_envelope_path) = signature_envelope.as_deref() {
                for (label, reserved) in outputs
                    .iter()
                    .map(|path| ("OpenAPI output", path.as_path()))
                    .chain(std::iter::once(("manifest", manifest.as_path())))
                {
                    if openapi_paths_alias(signature_envelope_path, reserved) {
                        return Err(format!(
                            "openapi --signature-envelope must not alias the {label} path {}",
                            reserved.display()
                        )
                        .into());
                    }
                }
            }
            Ok(CommandKind::OpenApi {
                outputs,
                canonical_spec,
                manifest,
                signature_envelope,
                signing_payload,
                unsigned_manifest,
            })
        }
        "da-threat-model-report" => {
            let mut output: Option<JsonTarget> = None;
            let mut seed = da::DEFAULT_REPORT_SEED;
            let mut config_path: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        if path == "-" {
                            output = Some(JsonTarget::Stdout);
                        } else {
                            output = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--seed" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --seed".into());
                        };
                        seed = da::parse_seed(&value)?;
                    }
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config_path = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for da-threat-model-report: {flag}").into()
                        );
                    }
                }
            }
            let output = output.unwrap_or_else(|| JsonTarget::File(default_da_report_path()));
            Ok(CommandKind::DaThreatModelReport {
                output,
                seed,
                config_path,
            })
        }
        "da-replication-audit" => {
            let mut config: Option<PathBuf> = None;
            let mut manifests = Vec::new();
            let mut orders = Vec::new();
            let mut json_out: Option<JsonTarget> = None;
            let mut plan_out: Option<JsonTarget> = None;
            let mut allow_mismatch = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config = Some(normalize_path(Path::new(&path))?);
                    }
                    "--manifest" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --manifest".into());
                        };
                        manifests.push(normalize_path(Path::new(&path))?);
                    }
                    "--replication-order" | "--order" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --replication-order".into());
                        };
                        orders.push(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--plan-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --plan-out".into());
                        };
                        if path == "-" {
                            plan_out = Some(JsonTarget::Stdout);
                        } else {
                            plan_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--allow-mismatch" => allow_mismatch = true,
                    flag => {
                        return Err(format!("unknown flag for da-replication-audit: {flag}").into());
                    }
                }
            }
            let config =
                config.ok_or("da-replication-audit requires --config <torii_config.toml>")?;
            if manifests.is_empty() {
                return Err("da-replication-audit requires at least one --manifest <path>".into());
            }
            let json_output =
                json_out.unwrap_or_else(|| JsonTarget::File(default_da_replication_audit_path()));
            Ok(CommandKind::DaReplicationAudit {
                options: da::ReplicationAuditOptions {
                    config,
                    manifests,
                    replication_orders: orders,
                    json_output: Some(json_output),
                    plan_output: plan_out,
                    allow_mismatch,
                },
            })
        }
        "da-commitment-reconcile" => {
            let mut receipts = Vec::new();
            let mut blocks = Vec::new();
            let mut json_out: Option<JsonTarget> = None;
            let mut allow_unexpected = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--receipt" | "--receipts" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --receipt/--receipts".into());
                        };
                        receipts.push(normalize_path(Path::new(&path))?);
                    }
                    "--block" | "--commitment" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --block".into());
                        };
                        blocks.push(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--allow-unexpected" => {
                        allow_unexpected = true;
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for da-commitment-reconcile: {flag}").into()
                        );
                    }
                }
            }
            if receipts.is_empty() {
                return Err(
                    "da-commitment-reconcile requires at least one --receipt <path>".into(),
                );
            }
            if blocks.is_empty() {
                return Err("da-commitment-reconcile requires at least one --block <path>".into());
            }
            let json_output = json_out
                .unwrap_or_else(|| JsonTarget::File(default_da_commitment_reconcile_path()));
            Ok(CommandKind::DaCommitmentReconcile {
                options: da::CommitmentReconcileOptions {
                    receipts,
                    blocks,
                    json_output: Some(json_output),
                    allow_unexpected_commitments: allow_unexpected,
                },
            })
        }
        "da-privilege-audit" => {
            let mut config: Option<PathBuf> = None;
            let mut extra_paths = Vec::new();
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config = Some(normalize_path(Path::new(&path))?);
                    }
                    "--extra-path" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --extra-path".into());
                        };
                        extra_paths.push(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for da-privilege-audit: {flag}").into());
                    }
                }
            }
            let config =
                config.ok_or("da-privilege-audit requires --config <torii_config.toml>")?;
            let json_output =
                json_out.unwrap_or_else(|| JsonTarget::File(default_da_privilege_audit_path()));
            Ok(CommandKind::DaPrivilegeAudit {
                options: da::PrivilegeAuditOptions {
                    config,
                    extra_paths,
                    json_output: Some(json_output),
                },
            })
        }
        "da-proof-bench" => {
            let mut manifest: Option<PathBuf> = None;
            let mut payload: Option<PathBuf> = None;
            let mut payload_bytes: Option<usize> = None;
            let mut sample_count: Option<usize> = None;
            let mut sample_seed: Option<u64> = None;
            let mut budget_ms: Option<u64> = None;
            let mut json_out: Option<JsonTarget> = None;
            let mut markdown_out: Option<PathBuf> = None;
            let mut iterations: usize = 5;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--manifest" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --manifest".into());
                        };
                        manifest = Some(normalize_path(Path::new(&path))?);
                    }
                    "--payload" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --payload".into());
                        };
                        payload = Some(normalize_path(Path::new(&path))?);
                    }
                    "--payload-bytes" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --payload-bytes".into());
                        };
                        payload_bytes = Some(
                            value
                                .parse::<usize>()
                                .map_err(|err| format!("invalid --payload-bytes: {err}"))?,
                        );
                    }
                    "--sample-count" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --sample-count".into());
                        };
                        sample_count = Some(
                            value
                                .parse::<usize>()
                                .map_err(|err| format!("invalid --sample-count: {err}"))?,
                        );
                    }
                    "--sample-seed" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --sample-seed".into());
                        };
                        sample_seed = Some(da::parse_seed(&value)?);
                    }
                    "--budget-ms" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --budget-ms".into());
                        };
                        budget_ms = Some(
                            value
                                .parse::<u64>()
                                .map_err(|err| format!("invalid --budget-ms: {err}"))?,
                        );
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        if path == "-" {
                            markdown_out = Some(PathBuf::from("-"));
                        } else {
                            markdown_out = Some(normalize_path(Path::new(&path))?);
                        }
                    }
                    "--iterations" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --iterations".into());
                        };
                        iterations = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --iterations: {err}"))?;
                    }
                    flag => {
                        return Err(format!("unknown flag for da-proof-bench: {flag}").into());
                    }
                }
            }
            let manifest = match manifest {
                Some(path) => path,
                None => normalize_path(&default_da_proof_manifest())?,
            };
            let payload = match payload {
                Some(path) => path,
                None => {
                    if payload_bytes.is_some() {
                        normalize_path(&default_da_proof_generated_payload())?
                    } else {
                        normalize_path(&default_da_proof_payload())?
                    }
                }
            };
            let json_output =
                json_out.unwrap_or_else(|| JsonTarget::File(default_da_proof_bench_json_path()));
            let markdown_output = markdown_out.unwrap_or_else(default_da_proof_bench_markdown_path);
            Ok(CommandKind::DaProofBench {
                options: da::ProofBenchOptions {
                    manifest,
                    payload,
                    payload_bytes,
                    sample_count,
                    sample_seed,
                    budget_ms,
                    json_output: Some(json_output),
                    markdown_output: Some(markdown_output),
                    iterations,
                },
            })
        }
        "config-debug" => {
            let mut config: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for config-debug: {flag}").into());
                    }
                }
            }
            let config = config.ok_or("config-debug requires --config <path>")?;
            Ok(CommandKind::ConfigDebug { config })
        }
        "openapi-verify" => {
            let mut manifest_path: Option<PathBuf> = None;
            let mut spec_path: Option<PathBuf> = None;
            let mut allow_unsigned = false;
            let mut allowed_signers: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--manifest" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --manifest".into());
                        };
                        manifest_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--spec" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --spec".into());
                        };
                        spec_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--allow-unsigned" => allow_unsigned = true,
                    "--allowed-signers" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --allowed-signers".into());
                        };
                        allowed_signers = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for openapi-verify: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::OpenApiVerify {
                spec: spec_path.unwrap_or_else(default_openapi_path),
                manifest: manifest_path.unwrap_or_else(default_openapi_manifest_path),
                allow_unsigned,
                allowed_signers: allowed_signers
                    .unwrap_or_else(default_openapi_allowed_signers_path),
            })
        }
        "compute" => {
            let Some(subcmd) = args.next() else {
                return Err("compute requires a subcommand (slo-report|fixtures)".into());
            };
            match subcmd.as_str() {
                "slo-report" => {
                    let mut manifest =
                        PathBuf::from("fixtures/compute/manifest_compute_payments.json");
                    let mut json_out = PathBuf::from("artifacts/compute/compute_slo_report.json");
                    let mut markdown_out =
                        Some(PathBuf::from("artifacts/compute/compute_slo_report.md"));
                    let mut samples = std::num::NonZeroUsize::new(24).expect("non-zero");
                    let mut pending = args.peekable();
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--manifest" => {
                                let Some(path) = pending.next() else {
                                    return Err("--manifest requires a path".into());
                                };
                                manifest = normalize_path(Path::new(&path))?;
                            }
                            "--json-out" => {
                                let Some(path) = pending.next() else {
                                    return Err("--json-out requires a path".into());
                                };
                                json_out = PathBuf::from(path);
                            }
                            "--markdown-out" => {
                                let Some(path) = pending.next() else {
                                    return Err("--markdown-out requires a path or '-'".into());
                                };
                                if path == "-" {
                                    markdown_out = None;
                                } else {
                                    markdown_out = Some(PathBuf::from(path));
                                }
                            }
                            "--samples" => {
                                let Some(val) = pending.next() else {
                                    return Err("--samples requires a positive integer".into());
                                };
                                let parsed: usize = val.parse().map_err(|_| {
                                    format!("invalid value `{val}` for --samples (usize expected)")
                                })?;
                                samples = std::num::NonZeroUsize::new(parsed)
                                    .ok_or("--samples must be > 0")?;
                            }
                            flag => {
                                return Err(format!(
                                    "unknown option `{flag}` for compute slo-report"
                                )
                                .into());
                            }
                        }
                    }
                    Ok(CommandKind::ComputeSloReport {
                        options: compute::ComputeSloReportOptions {
                            manifest,
                            json_out,
                            markdown_out,
                            samples,
                        },
                    })
                }
                "fixtures" => {
                    let mut output_dir = PathBuf::from("fixtures/compute/sdk_parity");
                    let mut pending = args.peekable();
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "-o" | "--out" | "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("--output requires a directory".into());
                                };
                                output_dir = PathBuf::from(path);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown option `{flag}` for compute fixtures"
                                )
                                .into());
                            }
                        }
                    }
                    Ok(CommandKind::ComputeFixtures {
                        options: compute::ComputeFixtureOptions { output_dir },
                    })
                }
                other => Err(format!(
                    "unknown compute subcommand `{other}` (expected slo-report|fixtures)"
                )
                .into()),
            }
        }
        "address-vectors" => {
            let mut target: Option<JsonTarget> = None;
            let mut verify = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        target = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                    }
                    "--stdout" => target = Some(JsonTarget::Stdout),
                    "--verify" => verify = true,
                    flag => {
                        return Err(format!("unknown flag for address-vectors: {flag}").into());
                    }
                }
            }
            if verify && matches!(target, Some(JsonTarget::Stdout)) {
                return Err("--verify cannot be combined with --stdout for address-vectors".into());
            }
            let target = target.unwrap_or(JsonTarget::File(default_address_vectors_path()?));
            Ok(CommandKind::AddressVectors { target, verify })
        }
        "zk-dev-vote-fixture" => {
            let mut output = None;
            let mut verify = false;
            let mut print_hashes = false;
            let mut summary_target = None;
            let mut attestation_target = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--verify" => verify = true,
                    "--print-hashes" => print_hashes = true,
                    "--summary-json" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --summary-json".into());
                        };
                        if value == "-" {
                            summary_target = Some(JsonTarget::Stdout);
                        } else {
                            summary_target =
                                Some(JsonTarget::File(normalize_path(Path::new(&value))?));
                        }
                    }
                    "--attestation" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --attestation".into());
                        };
                        if value == "-" {
                            attestation_target = Some(JsonTarget::Stdout);
                        } else {
                            attestation_target =
                                Some(JsonTarget::File(normalize_path(Path::new(&value))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for zk-dev-vote-fixture: {flag}").into());
                    }
                }
            }
            let output = output.unwrap_or_else(default_dev_vote_fixture_path);
            Ok(CommandKind::ZkDevVoteFixture {
                output,
                verify,
                print_hashes,
                summary_target,
                attestation_target,
            })
        }
        "kagami-bundle" => {
            let mut output = None;
            let mut profile = String::from("release");
            let mut network_profiles = None;
            let mut pending = args.peekable();
            while let Some(flag) = pending.next() {
                match flag.as_str() {
                    "--out" => {
                        let path = pending.next().ok_or("expected path after --out")?;
                        if output.is_some() {
                            return Err("--out may be supplied only once".into());
                        }
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--profile" => {
                        profile = pending.next().ok_or("expected profile after --profile")?;
                    }
                    "--network-profiles" => {
                        let path = pending
                            .next()
                            .ok_or("expected installation artifact after --network-profiles")?;
                        if network_profiles.is_some() {
                            return Err("--network-profiles may be supplied only once".into());
                        }
                        network_profiles = Some(normalize_path(Path::new(&path))?);
                    }
                    _ => return Err(format!("unknown kagami-bundle flag: {flag}").into()),
                }
            }
            kagami_bundle::validate_profile(&profile)?;
            network_profiles::validate_input(&profile, network_profiles.as_deref())?;
            Ok(CommandKind::KagamiBundle {
                output: output.unwrap_or_else(|| workspace_root().join("target/kagami-bundle")),
                profile,
                network_profiles,
            })
        }
        "mochi-bundle" => {
            let mut output: Option<PathBuf> = None;
            let mut profile = String::from("release");
            let mut archive = true;
            let mut matrix: Option<PathBuf> = None;
            let mut smoke = false;
            let mut stage: Option<PathBuf> = None;
            let mut network_profiles: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--profile" => {
                        let Some(value) = pending.next() else {
                            return Err("expected profile name after --profile".into());
                        };
                        profile = value;
                    }
                    "--no-archive" => archive = false,
                    "--matrix" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --matrix".into());
                        };
                        matrix = Some(normalize_path(Path::new(&path))?);
                    }
                    "--smoke" => {
                        smoke = true;
                    }
                    "--stage" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --stage".into());
                        };
                        stage = Some(normalize_path(Path::new(&path))?);
                    }
                    "--network-profiles" => {
                        let Some(path) = pending.next() else {
                            return Err(
                                "expected installation artifact path after --network-profiles"
                                    .into(),
                            );
                        };
                        if network_profiles.is_some() {
                            return Err("--network-profiles may be supplied only once".into());
                        }
                        network_profiles = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for mochi-bundle: {flag}").into());
                    }
                }
            }
            let output = output.unwrap_or_else(default_mochi_bundle_path);
            mochi::validate_bundle_profile(&profile)?;
            network_profiles::validate_input(&profile, network_profiles.as_deref())?;
            Ok(CommandKind::MochiBundle {
                output,
                profile,
                archive,
                matrix,
                smoke,
                stage,
                network_profiles,
            })
        }
        "mochi-latency" | "mochi-latency-report" | "mochi-latency-remote" => {
            let reporting = cmd == "mochi-latency-report";
            let remote = cmd == "mochi-latency-remote";
            let input_flag = if reporting { "--samples" } else { "--bundle" };
            let mut input = None;
            let mut output = None;
            let mut driver = None;
            let mut pending = args.peekable();
            while let Some(flag) = pending.next() {
                let target = if flag == input_flag {
                    &mut input
                } else if flag == "--out" {
                    &mut output
                } else if remote && flag == "--driver" {
                    &mut driver
                } else {
                    return Err("unsupported diagnostic latency flag".into());
                };
                if target.is_some() {
                    return Err("duplicate diagnostic latency flag".into());
                }
                let value = pending.next().ok_or("missing diagnostic latency path")?;
                *target = Some(normalize_path(Path::new(&value))?);
            }
            let input = input.ok_or("missing diagnostic latency input")?;
            let output = output.ok_or("missing --out diagnostic path")?;
            Ok(if remote {
                CommandKind::MochiLatencyRemote {
                    bundle: input,
                    driver: driver.ok_or("missing --driver release test executable")?,
                    output,
                }
            } else if reporting {
                CommandKind::MochiLatencyReport {
                    samples: input,
                    output,
                }
            } else {
                CommandKind::MochiLatency {
                    bundle: input,
                    output,
                }
            })
        }
        "kagami-profiles" => {
            let mut output: Option<PathBuf> = None;
            let mut profiles: Vec<String> = Vec::new();
            let mut kagami: Option<PathBuf> = None;
            let mut nexus_xor_asset_definition_id: Option<String> = None;
            let mut xor_allocations_dir: Option<PathBuf> = None;
            let mut genesis_creation_time_ms: Option<u64> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--profile" => {
                        let Some(value) = pending.next() else {
                            return Err("expected profile after --profile".into());
                        };
                        profiles.push(value);
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--kagami" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --kagami".into());
                        };
                        kagami = Some(normalize_path(Path::new(&path))?);
                    }
                    "--nexus-xor-asset-definition-id" => {
                        let Some(asset_definition_id) = pending.next() else {
                            return Err(
                                "expected canonical Base58 id after --nexus-xor-asset-definition-id"
                                    .into(),
                            );
                        };
                        nexus_xor_asset_definition_id = Some(asset_definition_id);
                    }
                    "--genesis-creation-time-ms" => {
                        if genesis_creation_time_ms.is_some() {
                            return Err(
                                "--genesis-creation-time-ms may be supplied only once".into()
                            );
                        }
                        let record = pending
                            .next()
                            .ok_or("expected milliseconds after --genesis-creation-time-ms")?;
                        let value: u64 = record
                            .parse()
                            .map_err(|_| "genesis creation time must be a canonical u64")?;
                        if value == 0 || value.to_string() != record {
                            return Err(
                                "genesis creation time must be one canonical nonzero u64".into()
                            );
                        }
                        genesis_creation_time_ms = Some(value);
                    }
                    "--xor-allocations-dir" => {
                        let path = pending
                            .next()
                            .ok_or("expected path after --xor-allocations-dir")?;
                        xor_allocations_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for kagami-profiles: {flag}").into());
                    }
                }
            }
            let output = output
                .map(Ok)
                .unwrap_or_else(|| normalize_path(Path::new("defaults/kagami")))?;
            Ok(CommandKind::KagamiProfiles {
                options: kagami_profiles::KagamiProfileOptions {
                    output,
                    profiles,
                    kagami_override: kagami,
                    nexus_xor_asset_definition_id,
                    xor_allocations_dir: xor_allocations_dir
                        .ok_or("kagami-profiles requires --xor-allocations-dir <DIR>")?,
                    genesis_creation_time_ms: genesis_creation_time_ms.ok_or(
                        "kagami-profiles requires --genesis-creation-time-ms <MILLISECONDS>",
                    )?,
                },
            })
        }
        "soranet-fixtures" => {
            let mut output: Option<PathBuf> = None;
            let mut verify = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--verify" => verify = true,
                    flag => {
                        return Err(format!("unknown flag for soranet-fixtures: {flag}").into());
                    }
                }
            }
            let output = output.unwrap_or_else(|| soranet::default_fixture_dir(&workspace_root()));
            Ok(CommandKind::SoranetFixtures { output, verify })
        }
        "soranet-chaos-kit" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut pop_label = "soranet-pop-m0".to_string();
            let mut gateway_host = "soranet-gw-m0".to_string();
            let mut resolver_host = "soradns-resolver-m0".to_string();
            let mut quarter_label: Option<String> = None;
            let mut now_override: Option<SystemTime> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--out" | "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--pop" => {
                        let Some(value) = pending.next() else {
                            return Err("expected label after --pop".into());
                        };
                        pop_label = value;
                    }
                    "--gateway" => {
                        let Some(value) = pending.next() else {
                            return Err("expected host after --gateway".into());
                        };
                        gateway_host = value;
                    }
                    "--resolver" => {
                        let Some(value) = pending.next() else {
                            return Err("expected host after --resolver".into());
                        };
                        resolver_host = value;
                    }
                    "--quarter" => {
                        let Some(value) = pending.next() else {
                            return Err("expected label after --quarter".into());
                        };
                        quarter_label = Some(value);
                    }
                    "--now" => {
                        let Some(value) = pending.next() else {
                            return Err("expected unix seconds after --now".into());
                        };
                        let secs: u64 = value.parse()?;
                        now_override = Some(UNIX_EPOCH + Duration::from_secs(secs));
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-chaos-kit: {flag}").into());
                    }
                }
            }
            let now_for_default = now_override.unwrap_or_else(SystemTime::now);
            let output_dir =
                output_dir.unwrap_or_else(|| default_soranet_chaos_dir(now_for_default));
            let options = soranet_chaos::ChaosKitOptions {
                output_dir,
                pop_label,
                gateway_host,
                resolver_host,
                quarter_label,
                now: Some(now_for_default),
            };
            Ok(CommandKind::SoranetChaosKit { options })
        }
        "soranet-chaos-report" => {
            let mut log_path: Option<PathBuf> = None;
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--log" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --log".into());
                        };
                        log_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-chaos-report: {flag}").into());
                    }
                }
            }
            let log_path = log_path.ok_or("soranet-chaos-report requires --log <path>")?;
            let output = json_out.unwrap_or(JsonTarget::Stdout);
            Ok(CommandKind::SoranetChaosReport {
                options: soranet_chaos::ChaosReportOptions { log_path, output },
            })
        }
        "sorafs-gateway-fixtures" => {
            let mut output: Option<PathBuf> = None;
            let mut verify = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--verify" | "--check" => {
                        verify = true;
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-gateway-fixtures: {flag}").into()
                        );
                    }
                }
            }
            let default = sorafs::default_gateway_fixture_dir();
            Ok(CommandKind::SorafsGatewayFixtures {
                output: output.unwrap_or(default),
                verify,
            })
        }
        "sorafs-admission-fixtures" => {
            let mut output: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-admission-fixtures: {flag}").into(),
                        );
                    }
                }
            }
            let default = normalize_path(Path::new("fixtures/sorafs_manifest/provider_admission"))?;
            Ok(CommandKind::SorafsAdmissionFixtures {
                output: output.unwrap_or(default),
            })
        }
        "sorafs-adoption-check" => {
            let mut pending = args.peekable();
            let mut scoreboard_paths: Vec<PathBuf> = Vec::new();
            let mut summary_paths: Vec<PathBuf> = Vec::new();
            let mut min_providers: usize = 2;
            let mut require_positive_weight = true;
            let mut allow_single_source = false;
            let mut report: Option<PathBuf> = None;
            let mut require_telemetry_source = false;
            let mut require_telemetry_region = false;
            let mut allow_implicit_metadata = false;
            let mut require_direct_only = false;
            let mut adoption_override_id: Option<String> = None;
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--scoreboard" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --scoreboard".into());
                        };
                        scoreboard_paths.push(normalize_path(Path::new(&path))?);
                    }
                    "--min-providers" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --min-providers".into());
                        };
                        let parsed: usize = value.parse().map_err(|err| {
                            format!("invalid --min-providers value `{value}`: {err}")
                        })?;
                        if parsed == 0 {
                            return Err("--min-providers must be at least 1".into());
                        }
                        min_providers = parsed;
                    }
                    "--summary" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --summary".into());
                        };
                        summary_paths.push(normalize_path(Path::new(&path))?);
                    }
                    "--allow-zero-weight" => {
                        require_positive_weight = false;
                    }
                    "--allow-single-source" => {
                        allow_single_source = true;
                    }
                    "--require-telemetry" | "--require-telemetry-source" => {
                        require_telemetry_source = true;
                    }
                    "--require-telemetry-region" => {
                        require_telemetry_region = true;
                    }
                    "--allow-implicit-metadata" => {
                        allow_implicit_metadata = true;
                    }
                    "--require-direct-only" => {
                        require_direct_only = true;
                    }
                    "--adoption-override-id" | "--override-id" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --adoption-override-id".into());
                        };
                        validate_sorafs_adoption_override_id(&value)?;
                        adoption_override_id = Some(value);
                    }
                    "--report" | "--report-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --report".into());
                        };
                        report = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-adoption-check: {flag}").into()
                        );
                    }
                }
            }
            if (allow_single_source || !require_positive_weight) && adoption_override_id.is_none() {
                return Err(
                    "sorafs-adoption-check relaxation flags (--allow-single-source/--allow-zero-weight) require --adoption-override-id <incident-or-approval-id>"
                        .into(),
                );
            }
            Ok(CommandKind::SorafsAdoptionCheck {
                options: sorafs::adoption::AdoptionCheckOptions {
                    scoreboard_paths,
                    summary_paths,
                    min_eligible_providers: min_providers,
                    require_positive_weight,
                    allow_single_source_fallback: allow_single_source,
                    require_telemetry_source,
                    require_telemetry_region,
                    allow_implicit_metadata,
                    require_direct_only,
                },
                report,
            })
        }
        "sorafs-scoreboard-diff" => {
            let mut pending = args.peekable();
            let mut previous: Option<PathBuf> = None;
            let mut current: Option<PathBuf> = None;
            let mut threshold_percent = 10.0f64;
            let mut report: Option<PathBuf> = None;
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--previous" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --previous".into());
                        };
                        previous = Some(normalize_path(Path::new(&value))?);
                    }
                    "--current" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --current".into());
                        };
                        current = Some(normalize_path(Path::new(&value))?);
                    }
                    "--threshold-percent" => {
                        let Some(raw) = pending.next() else {
                            return Err("expected value after --threshold-percent".into());
                        };
                        threshold_percent = raw.parse().map_err(|err| {
                            format!("invalid --threshold-percent value `{raw}`: {err}")
                        })?;
                    }
                    "--report" | "--report-out" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --report".into());
                        };
                        report = Some(normalize_path(Path::new(&value))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-scoreboard-diff: {flag}").into()
                        );
                    }
                }
            }
            let previous =
                previous.ok_or("sorafs-scoreboard-diff requires --previous <scoreboard.json>")?;
            let current =
                current.ok_or("sorafs-scoreboard-diff requires --current <scoreboard.json>")?;
            Ok(CommandKind::SorafsScoreboardDiff {
                options: sorafs::adoption::ScoreboardDiffOptions {
                    previous_scoreboard: previous,
                    current_scoreboard: current,
                    threshold_percent,
                },
                report,
            })
        }
        "taikai-anchor-bundle" => {
            let mut spool_dir: Option<PathBuf> = None;
            let mut copy_dir: Option<PathBuf> = None;
            let mut signing_key: Option<PathBuf> = None;
            let mut receipt_public_key: Option<PublicKey> = None;
            let mut output: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--spool" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --spool".into());
                        };
                        spool_dir = Some(normalize_path(Path::new(&value))?);
                    }
                    "--copy-dir" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --copy-dir".into());
                        };
                        copy_dir = Some(normalize_path(Path::new(&value))?);
                    }
                    "--signing-key" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --signing-key".into());
                        };
                        signing_key = Some(normalize_path(Path::new(&value))?);
                    }
                    "--receipt-public-key" => {
                        let Some(value) = pending.next() else {
                            return Err("expected key after --receipt-public-key".into());
                        };
                        let key = value.parse::<PublicKey>().map_err(|err| {
                            format!("invalid Taikai anchor receipt public key `{value}`: {err}")
                        })?;
                        if !matches!(key.try_algorithm(), Ok(Algorithm::Ed25519)) {
                            return Err("Taikai anchor receipt public key must use Ed25519".into());
                        }
                        receipt_public_key = Some(key);
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --out/--output".into());
                        };
                        if value == "-" {
                            output = Some(JsonTarget::Stdout);
                        } else {
                            output = Some(JsonTarget::File(normalize_path(Path::new(&value))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for taikai-anchor-bundle: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::TaikaiAnchorBundle {
                options: taikai_anchor::AnchorBundleOptions {
                    spool_dir: spool_dir.unwrap_or_else(default_taikai_spool_dir),
                    copy_dir,
                    signing_key,
                    receipt_public_key,
                    output: output.unwrap_or(JsonTarget::Stdout),
                },
            })
        }
        "taikai-rpt-verify" => {
            let mut envelope: Option<PathBuf> = None;
            let mut gar_path: Option<PathBuf> = None;
            let mut cek_receipt: Option<PathBuf> = None;
            let mut bundle_path: Option<PathBuf> = None;
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--envelope" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --envelope".into());
                        };
                        envelope = Some(normalize_path(Path::new(&path))?);
                    }
                    "--gar" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --gar".into());
                        };
                        gar_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--cek-receipt" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --cek-receipt".into());
                        };
                        cek_receipt = Some(normalize_path(Path::new(&path))?);
                    }
                    "--bundle" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --bundle".into());
                        };
                        bundle_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --json-out".into());
                        };
                        if value == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&value))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for taikai-rpt-verify: {flag}").into());
                    }
                }
            }
            let envelope_path = envelope
                .ok_or_else(|| "taikai-rpt-verify requires --envelope <path>".to_string())?;
            let gar_path =
                gar_path.ok_or_else(|| "taikai-rpt-verify requires --gar <path>".to_string())?;
            let cek_receipt_path = cek_receipt
                .ok_or_else(|| "taikai-rpt-verify requires --cek-receipt <path>".to_string())?;
            let bundle_path = bundle_path
                .ok_or_else(|| "taikai-rpt-verify requires --bundle <path>".to_string())?;
            Ok(CommandKind::TaikaiRptVerify {
                options: taikai::RptVerifyOptions {
                    envelope_path,
                    gar_path,
                    cek_receipt_path,
                    bundle_path,
                    output: json_out,
                },
            })
        }
        "sorafs-burn-in-check" => {
            let mut pending = args.peekable();
            let mut log_paths: Vec<PathBuf> = Vec::new();
            let mut window_days: u64 = 30;
            let mut min_pq_ratio: f64 = 0.95;
            let mut max_no_provider_errors: u64 = 0;
            let mut max_brownout_ratio: f64 = 0.01;
            let mut min_fetches: u64 = 100;
            let mut output: Option<PathBuf> = None;
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--log" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --log".into());
                        };
                        log_paths.push(normalize_path(Path::new(&path))?);
                    }
                    "--window-days" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --window-days".into());
                        };
                        let parsed: u64 = value.parse().map_err(|err| {
                            format!("invalid --window-days value `{value}`: {err}")
                        })?;
                        if parsed == 0 {
                            return Err("--window-days must be at least 1".into());
                        }
                        window_days = parsed;
                    }
                    "--min-pq-ratio" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --min-pq-ratio".into());
                        };
                        let parsed: f64 = value.parse().map_err(|err| {
                            format!("invalid --min-pq-ratio value `{value}`: {err}")
                        })?;
                        if !(0.0..=1.0).contains(&parsed) {
                            return Err("--min-pq-ratio must be between 0.0 and 1.0".into());
                        }
                        min_pq_ratio = parsed;
                    }
                    "--max-no-provider-errors" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --max-no-provider-errors".into());
                        };
                        max_no_provider_errors = value.parse().map_err(|err| {
                            format!("invalid --max-no-provider-errors value `{value}`: {err}")
                        })?;
                    }
                    "--max-brownout-ratio" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --max-brownout-ratio".into());
                        };
                        let parsed: f64 = value.parse().map_err(|err| {
                            format!("invalid --max-brownout-ratio value `{value}`: {err}")
                        })?;
                        if !(0.0..=1.0).contains(&parsed) {
                            return Err("--max-brownout-ratio must be between 0.0 and 1.0".into());
                        }
                        max_brownout_ratio = parsed;
                    }
                    "--min-fetches" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --min-fetches".into());
                        };
                        let parsed: u64 = value.parse().map_err(|err| {
                            format!("invalid --min-fetches value `{value}`: {err}")
                        })?;
                        if parsed == 0 {
                            return Err("--min-fetches must be at least 1".into());
                        }
                        min_fetches = parsed;
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for sorafs-burn-in-check: {flag}").into());
                    }
                }
            }
            if log_paths.is_empty() {
                return Err("sorafs-burn-in-check requires at least one --log <path>".into());
            }
            Ok(CommandKind::SorafsBurnInCheck {
                options: sorafs::adoption::BurnInCheckOptions {
                    log_paths,
                    required_window_days: window_days,
                    min_pq_ratio,
                    max_no_provider_errors,
                    max_brownout_ratio,
                    min_fetches,
                },
                output,
            })
        }
        "sorafs-reserve-matrix" => {
            let mut capacities = Vec::new();
            let mut storage_classes = Vec::new();
            let mut tiers = Vec::new();
            let mut durations = Vec::new();
            let mut policy_json: Option<PathBuf> = None;
            let mut policy_norito: Option<PathBuf> = None;
            let mut reserve_balance: Option<XorQuantity> = None;
            let mut label: Option<String> = None;
            let mut target: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--capacity" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --capacity".into());
                        };
                        let parsed = parse_u64_flag(&value, "--capacity")?;
                        capacities.push(parsed);
                    }
                    "--storage-class" => {
                        let Some(value) = pending.next() else {
                            return Err("expected label after --storage-class".into());
                        };
                        let class = sorafs::parse_storage_class_label(&value)?;
                        storage_classes.push(class);
                    }
                    "--tier" => {
                        let Some(value) = pending.next() else {
                            return Err("expected label after --tier".into());
                        };
                        let tier = sorafs::parse_reserve_tier_label(&value)?;
                        tiers.push(tier);
                    }
                    "--duration" => {
                        let Some(value) = pending.next() else {
                            return Err("expected label after --duration".into());
                        };
                        let duration = sorafs::parse_reserve_duration_label(&value)?;
                        durations.push(duration);
                    }
                    "--policy-json" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --policy-json".into());
                        };
                        policy_json = Some(normalize_path(Path::new(&path))?);
                    }
                    "--policy-norito" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --policy-norito".into());
                        };
                        policy_norito = Some(normalize_path(Path::new(&path))?);
                    }
                    "--reserve-balance" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --reserve-balance".into());
                        };
                        let amount = sorafs::parse_xor_amount_decimal(&value)?;
                        reserve_balance = Some(amount);
                    }
                    "--label" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --label".into());
                        };
                        label = Some(value);
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        if path == "-" {
                            target = Some(JsonTarget::Stdout);
                        } else {
                            target = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-reserve-matrix: {flag}").into()
                        );
                    }
                }
            }
            let options = sorafs::ReserveMatrixOptions {
                capacities_gib: capacities,
                storage_classes,
                tiers,
                durations,
                reserve_balance: reserve_balance.unwrap_or_else(XorQuantity::zero),
                policy_json,
                policy_norito,
                label,
            };
            let target = target.unwrap_or(JsonTarget::Stdout);
            Ok(CommandKind::SorafsReserveMatrix { options, target })
        }
        "sorafs-fetch-fixture" => {
            let mut signatures: Option<sorafs::FetchSource> = None;
            let mut manifest: Option<sorafs::FetchSource> = None;
            let mut output: Option<PathBuf> = None;
            let mut profile = String::from("sorafs.sf1@1.0.0");
            let mut allow_unsigned = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--signatures" => {
                        let Some(value) = pending.next() else {
                            return Err("expected argument after --signatures".into());
                        };
                        signatures = Some(sorafs::FetchSource::parse(&value)?);
                    }
                    "--manifest" => {
                        let Some(value) = pending.next() else {
                            return Err("expected argument after --manifest".into());
                        };
                        manifest = Some(sorafs::FetchSource::parse(&value)?);
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected argument after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--profile" => {
                        let Some(value) = pending.next() else {
                            return Err("expected argument after --profile".into());
                        };
                        profile = value;
                    }
                    "--allow-unsigned" => allow_unsigned = true,
                    flag => {
                        return Err(format!("unknown flag for sorafs-fetch-fixture: {flag}").into());
                    }
                }
            }
            let signatures =
                signatures.ok_or("sorafs-fetch-fixture requires --signatures <path|url>")?;
            let output =
                output.unwrap_or_else(|| workspace_root().join("fixtures").join("sorafs_chunker"));
            Ok(CommandKind::SorafsFetchFixture {
                options: Box::new(sorafs::FetchFixtureOptions {
                    signatures_source: signatures,
                    manifest_source: manifest,
                    output_dir: output,
                    profile_handle: profile,
                    allow_unsigned,
                }),
            })
        }
        "sorafs-gateway-attest" => {
            let mut output: Option<PathBuf> = None;
            let mut signing_key: Option<PathBuf> = None;
            let mut signer_account: Option<String> = None;
            let mut gateway_target: Option<String> = None;
            let mut verify_envelope: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--signing-key" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --signing-key".into());
                        };
                        signing_key = Some(normalize_path(Path::new(&path))?);
                    }
                    "--signer-account" => {
                        let Some(value) = pending.next() else {
                            return Err("expected account after --signer-account".into());
                        };
                        signer_account = Some(value);
                    }
                    "--gateway" => {
                        let Some(value) = pending.next() else {
                            return Err("expected URL after --gateway".into());
                        };
                        gateway_target = Some(value);
                    }
                    "--verify" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --verify".into());
                        };
                        verify_envelope = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-gateway-attest: {flag}").into()
                        );
                    }
                }
            }
            if let Some(envelope) = verify_envelope {
                if output.is_some()
                    || signing_key.is_some()
                    || signer_account.is_some()
                    || gateway_target.is_some()
                {
                    return Err("sorafs-gateway-attest --verify cannot be combined with attestation generation flags".into());
                }
                return Ok(CommandKind::SorafsGatewayAttestVerify { envelope });
            }
            let signing_key_path =
                signing_key.ok_or("sorafs-gateway-attest requires --signing-key <path>")?;
            let signer_account = signer_account
                .ok_or("sorafs-gateway-attest requires --signer-account <account>")?;
            let output = output.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("sorafs_gateway_attest")
            });
            Ok(CommandKind::SorafsGatewayAttest {
                options: Box::new(sorafs::GatewayAttestOptions {
                    output_dir: output,
                    signing_key_path,
                    signer_account,
                    gateway_target,
                }),
            })
        }
        "sorafs-gateway-probe" => {
            let mut gateway: Option<String> = None;
            let mut headers_path: Option<PathBuf> = None;
            let mut method: Option<String> = None;
            let mut timeout_secs: Option<u64> = None;
            let mut extra_headers: Vec<(String, String)> = Vec::new();
            let mut gar_path: Option<PathBuf> = None;
            let mut gar_keys: Vec<(String, Vec<u8>)> = Vec::new();
            let mut cache_max_age: Option<u64> = None;
            let mut cache_swr: Option<u64> = None;
            let mut now_override: Option<u64> = None;
            let mut host_override: Option<String> = None;
            let mut require_tls_state = true;
            let mut report_target: Option<JsonTarget> = None;
            let mut summary_path: Option<PathBuf> = None;
            let mut drill_log_path: Option<PathBuf> = None;
            let mut drill_scenario: Option<String> = None;
            let mut drill_ic: Option<String> = None;
            let mut drill_scribe: Option<String> = None;
            let mut drill_notes: Option<String> = None;
            let mut drill_link: Option<String> = None;
            let mut pagerduty_payload: Option<PathBuf> = None;
            let mut pagerduty_routing_key: Option<String> = None;
            let mut pagerduty_severity: Option<String> = None;
            let mut pagerduty_source: Option<String> = None;
            let mut pagerduty_component: Option<String> = None;
            let mut pagerduty_group: Option<String> = None;
            let mut pagerduty_class: Option<String> = None;
            let mut pagerduty_dedup_key: Option<String> = None;
            let mut pagerduty_links: Vec<(String, String)> = Vec::new();
            let mut pagerduty_url: Option<Url> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--gateway" => {
                        let Some(value) = pending.next() else {
                            return Err("expected URL after --gateway".into());
                        };
                        gateway = Some(value);
                    }
                    "--headers-file" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --headers-file".into());
                        };
                        headers_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--method" => {
                        let Some(value) = pending.next() else {
                            return Err("expected method after --method".into());
                        };
                        method = Some(value);
                    }
                    "--timeout-secs" => {
                        let Some(value) = pending.next() else {
                            return Err("expected integer after --timeout-secs".into());
                        };
                        timeout_secs = Some(
                            value
                                .parse()
                                .map_err(|_| "invalid integer for --timeout-secs")?,
                        );
                    }
                    "--header" => {
                        let Some(value) = pending.next() else {
                            return Err("expected `Name: Value` after --header".into());
                        };
                        let (name, val) = value
                            .split_once(':')
                            .ok_or("expected --header value in `Name: Value` form")?;
                        extra_headers.push((name.trim().to_string(), val.trim().to_string()));
                    }
                    "--gar" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --gar".into());
                        };
                        gar_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--gar-key" => {
                        let Some(value) = pending.next() else {
                            return Err("expected `kid=hex` after --gar-key".into());
                        };
                        let (kid, hex_value) = value
                            .split_once('=')
                            .ok_or("expected --gar-key value in `kid=hex` form")?;
                        let bytes = hex::decode(hex_value.trim())
                            .map_err(|_| "failed to decode --gar-key hex value")?;
                        gar_keys.push((kid.trim().to_string(), bytes));
                    }
                    "--cache-max-age" => {
                        let Some(value) = pending.next() else {
                            return Err("expected integer after --cache-max-age".into());
                        };
                        cache_max_age = Some(
                            value
                                .parse()
                                .map_err(|_| "invalid integer for --cache-max-age")?,
                        );
                    }
                    "--cache-stale-while-revalidate" => {
                        let Some(value) = pending.next() else {
                            return Err(
                                "expected integer after --cache-stale-while-revalidate".into()
                            );
                        };
                        cache_swr =
                            Some(value.parse().map_err(
                                |_| "invalid integer for --cache-stale-while-revalidate",
                            )?);
                    }
                    "--now" => {
                        let Some(value) = pending.next() else {
                            return Err("expected unix timestamp after --now".into());
                        };
                        now_override = Some(
                            value
                                .parse()
                                .map_err(|_| "invalid integer for --now (unix seconds)")?,
                        );
                    }
                    "--host" => {
                        let Some(value) = pending.next() else {
                            return Err("expected host after --host".into());
                        };
                        host_override = Some(value);
                    }
                    "--allow-missing-tls-state" => {
                        require_tls_state = false;
                    }
                    "--report-json" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path or - after --report-json".into());
                        };
                        if value == "-" {
                            report_target = Some(JsonTarget::Stdout);
                        } else {
                            report_target =
                                Some(JsonTarget::File(normalize_path(Path::new(&value))?));
                        }
                    }
                    "--summary-json" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --summary-json".into());
                        };
                        summary_path = Some(normalize_path(Path::new(&value))?);
                    }
                    "--drill-log" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --drill-log".into());
                        };
                        drill_log_path = Some(normalize_path(Path::new(&value))?);
                    }
                    "--drill-scenario" => {
                        let Some(value) = pending.next() else {
                            return Err("expected name after --drill-scenario".into());
                        };
                        drill_scenario = Some(value);
                    }
                    "--drill-ic" => {
                        let Some(value) = pending.next() else {
                            return Err("expected name after --drill-ic".into());
                        };
                        drill_ic = Some(value);
                    }
                    "--drill-scribe" => {
                        let Some(value) = pending.next() else {
                            return Err("expected name after --drill-scribe".into());
                        };
                        drill_scribe = Some(value);
                    }
                    "--drill-notes" => {
                        let Some(value) = pending.next() else {
                            return Err("expected text after --drill-notes".into());
                        };
                        drill_notes = Some(value);
                    }
                    "--drill-link" => {
                        let Some(value) = pending.next() else {
                            return Err("expected URL after --drill-link".into());
                        };
                        drill_link = Some(value);
                    }
                    "--pagerduty-payload" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --pagerduty-payload".into());
                        };
                        pagerduty_payload = Some(normalize_path(Path::new(&value))?);
                    }
                    "--pagerduty-routing-key" => {
                        let Some(value) = pending.next() else {
                            return Err("expected key after --pagerduty-routing-key".into());
                        };
                        pagerduty_routing_key = Some(value);
                    }
                    "--pagerduty-severity" => {
                        let Some(value) = pending.next() else {
                            return Err("expected severity after --pagerduty-severity".into());
                        };
                        pagerduty_severity = Some(value);
                    }
                    "--pagerduty-source" => {
                        let Some(value) = pending.next() else {
                            return Err("expected source after --pagerduty-source".into());
                        };
                        pagerduty_source = Some(value);
                    }
                    "--pagerduty-component" => {
                        let Some(value) = pending.next() else {
                            return Err("expected component after --pagerduty-component".into());
                        };
                        pagerduty_component = Some(value);
                    }
                    "--pagerduty-group" => {
                        let Some(value) = pending.next() else {
                            return Err("expected group after --pagerduty-group".into());
                        };
                        pagerduty_group = Some(value);
                    }
                    "--pagerduty-class" => {
                        let Some(value) = pending.next() else {
                            return Err("expected class after --pagerduty-class".into());
                        };
                        pagerduty_class = Some(value);
                    }
                    "--pagerduty-dedup-key" => {
                        let Some(value) = pending.next() else {
                            return Err("expected key after --pagerduty-dedup-key".into());
                        };
                        pagerduty_dedup_key = Some(value);
                    }
                    "--pagerduty-link" => {
                        let Some(value) = pending.next() else {
                            return Err("expected text=url after --pagerduty-link".into());
                        };
                        let (text, href) = value
                            .split_once('=')
                            .ok_or("expected --pagerduty-link value in `text=url` form")?;
                        pagerduty_links.push((text.trim().to_string(), href.trim().to_string()));
                    }
                    "--pagerduty-url" => {
                        let Some(value) = pending.next() else {
                            return Err("expected URL after --pagerduty-url".into());
                        };
                        pagerduty_url = Some(Url::parse(&value)?);
                    }
                    flag => {
                        return Err(format!("unknown flag for sorafs-gateway-probe: {flag}").into());
                    }
                }
            }
            if gateway.is_none() && headers_path.is_none() {
                return Err("sorafs-gateway-probe requires --gateway or --headers-file".into());
            }
            if gateway.is_some() && headers_path.is_some() {
                return Err("provide either --gateway or --headers-file, not both".into());
            }
            let gar_path =
                gar_path.ok_or("sorafs-gateway-probe requires --gar <path-to-gar-jws>")?;
            if gar_keys.is_empty() {
                return Err("sorafs-gateway-probe requires at least one --gar-key kid=hex".into());
            }
            let drill = if drill_log_path.is_some()
                || drill_scenario.is_some()
                || drill_ic.is_some()
                || drill_scribe.is_some()
                || drill_notes.is_some()
                || drill_link.is_some()
            {
                let scenario = drill_scenario
                    .ok_or("--drill-scenario is required when enabling drill logging")?;
                let log_path = drill_log_path
                    .unwrap_or_else(|| workspace_root().join("ops").join("drill-log.md"));
                Some(sorafs::DrillLogConfig {
                    log_path,
                    scenario,
                    ic: drill_ic,
                    scribe: drill_scribe,
                    notes: drill_notes,
                    link: drill_link,
                })
            } else {
                None
            };
            let pagerduty = if pagerduty_payload.is_some()
                || pagerduty_routing_key.is_some()
                || pagerduty_severity.is_some()
                || pagerduty_source.is_some()
                || pagerduty_component.is_some()
                || pagerduty_group.is_some()
                || pagerduty_class.is_some()
                || pagerduty_dedup_key.is_some()
                || !pagerduty_links.is_empty()
                || pagerduty_url.is_some()
            {
                let routing_key = pagerduty_routing_key.ok_or(
                    "--pagerduty-routing-key is required when enabling PagerDuty payloads",
                )?;
                let payload_path = pagerduty_payload.unwrap_or_else(|| {
                    workspace_root()
                        .join("artifacts")
                        .join("sorafs_gateway_probe")
                        .join("pagerduty_event.json")
                });
                Some(sorafs::PagerDutyConfig {
                    payload_path,
                    routing_key,
                    severity: pagerduty_severity.unwrap_or_else(|| "error".to_string()),
                    source: pagerduty_source.unwrap_or_else(|| "sorafs-gateway-probe".to_string()),
                    component: pagerduty_component,
                    group: pagerduty_group,
                    class_name: pagerduty_class,
                    dedup_key: pagerduty_dedup_key,
                    links: pagerduty_links
                        .into_iter()
                        .map(|(text, href)| sorafs::PagerDutyLink { text, href })
                        .collect(),
                    endpoint_url: pagerduty_url,
                })
            } else {
                None
            };
            let options = sorafs::GatewayProbeOptions {
                request: gateway.map(|url| sorafs::GatewayProbeRequest {
                    url,
                    method: method.unwrap_or_else(|| "HEAD".to_string()),
                    timeout_secs,
                    extra_headers,
                }),
                headers_path,
                gar_path,
                gar_keys,
                cache_max_age,
                cache_swr,
                now_override,
                host_override,
                require_tls_state,
                report_target,
                summary_path,
                drill,
                pagerduty,
            };
            Ok(CommandKind::SorafsGatewayProbe {
                options: Box::new(options),
            })
        }
        "sorafs-gateway" => {
            let remaining: Vec<String> = args.collect();
            let command = sorafs::parse_gateway_cli(remaining.into_iter())?;
            Ok(CommandKind::SorafsGatewayCli {
                command: Box::new(command),
            })
        }
        "soranet-pop-bundle" => {
            let mut input_path: Option<PathBuf> = None;
            let mut roa_path: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut edns_resolver: Option<String> = None;
            let mut edns_tool: Option<String> = None;
            let mut skip_edns = false;
            let mut skip_ds = false;
            let mut image_tag = "latest".to_string();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--roa" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --roa".into());
                        };
                        roa_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--edns-resolver" => {
                        let Some(value) = pending.next() else {
                            return Err("expected resolver address after --edns-resolver".into());
                        };
                        edns_resolver = Some(value);
                    }
                    "--edns-tool" => {
                        let Some(value) = pending.next() else {
                            return Err("expected binary name after --edns-tool".into());
                        };
                        edns_tool = Some(value);
                    }
                    "--skip-edns" => {
                        skip_edns = true;
                    }
                    "--skip-ds" => {
                        skip_ds = true;
                    }
                    "--image-tag" => {
                        let Some(value) = pending.next() else {
                            return Err("expected tag after --image-tag".into());
                        };
                        image_tag = value;
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-pop-bundle: {flag}").into());
                    }
                }
            }
            let input = input_path
                .ok_or_else(|| "soranet-pop-bundle requires --input <path>".to_string())?;
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet_pop")
                    .join("bundle")
            });
            let options = soranet_pop::PopBundleOptions {
                descriptor: input,
                roa_bundle: roa_path,
                output_dir,
                edns_resolver,
                edns_tool,
                skip_edns,
                skip_ds,
                image_tag,
            };
            Ok(CommandKind::SoranetPopBundle {
                options: Box::new(options),
            })
        }
        "soranet-popctl" => {
            let mut input_path: Option<PathBuf> = None;
            let mut roa_path: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut edns_resolver: Option<String> = None;
            let mut edns_tool: Option<String> = None;
            let mut skip_edns = false;
            let mut skip_ds = false;
            let mut image_tag = "latest".to_string();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--roa" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --roa".into());
                        };
                        roa_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--edns-resolver" => {
                        let Some(value) = pending.next() else {
                            return Err("expected resolver address after --edns-resolver".into());
                        };
                        edns_resolver = Some(value);
                    }
                    "--edns-tool" => {
                        let Some(value) = pending.next() else {
                            return Err("expected binary name after --edns-tool".into());
                        };
                        edns_tool = Some(value);
                    }
                    "--skip-edns" => skip_edns = true,
                    "--skip-ds" => skip_ds = true,
                    "--image-tag" => {
                        let Some(value) = pending.next() else {
                            return Err("expected tag after --image-tag".into());
                        };
                        image_tag = value;
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-popctl: {flag}").into());
                    }
                }
            }
            let input =
                input_path.ok_or_else(|| "soranet-popctl requires --input <path>".to_string())?;
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet_pop")
                    .join("bundle")
            });
            let options = soranet_pop::PopBundleOptions {
                descriptor: input,
                roa_bundle: roa_path,
                output_dir,
                edns_resolver,
                edns_tool,
                skip_edns,
                skip_ds,
                image_tag,
            };
            Ok(CommandKind::SoranetPopCtl {
                options: Box::new(options),
            })
        }
        "soranet-pop-template" => {
            let mut input_path: Option<PathBuf> = None;
            let mut output_path: Option<PathBuf> = None;
            let mut resolver_config: Option<PathBuf> = None;
            let mut edns_out: Option<PathBuf> = None;
            let mut ds_out: Option<PathBuf> = None;
            let mut edns_resolver: Option<String> = None;
            let mut edns_tool: Option<String> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        output_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--resolver-config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --resolver-config".into());
                        };
                        resolver_config = Some(normalize_path(Path::new(&path))?);
                    }
                    "--edns-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --edns-out".into());
                        };
                        edns_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--edns-resolver" => {
                        let Some(value) = pending.next() else {
                            return Err("expected resolver address after --edns-resolver".into());
                        };
                        edns_resolver = Some(value);
                    }
                    "--edns-tool" => {
                        let Some(value) = pending.next() else {
                            return Err("expected binary name after --edns-tool".into());
                        };
                        edns_tool = Some(value);
                    }
                    "--ds-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --ds-out".into());
                        };
                        ds_out = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-pop-template: {flag}").into());
                    }
                }
            }
            let input = input_path
                .ok_or_else(|| "soranet-pop-template requires --input <path>".to_string())?;
            let output = output_path.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet_pop")
                    .join("frr.conf")
            });
            Ok(CommandKind::SoranetPopTemplate {
                input,
                output,
                resolver_config,
                edns_out,
                edns_resolver,
                ds_out,
                edns_tool,
            })
        }
        "soranet-pop-validate" => {
            let mut input_path: Option<PathBuf> = None;
            let mut roa_path: Option<PathBuf> = None;
            let mut output: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--roa" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --roa".into());
                        };
                        roa_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--out" | "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path or '-' after --json-out".into());
                        };
                        if path == "-" {
                            output = Some(JsonTarget::Stdout);
                        } else {
                            output = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-pop-validate: {flag}").into());
                    }
                }
            }
            let input = input_path
                .ok_or_else(|| "soranet-pop-validate requires --input <path>".to_string())?;
            let output = output.unwrap_or(JsonTarget::Stdout);
            Ok(CommandKind::SoranetPopValidate {
                input,
                roa: roa_path,
                output,
            })
        }
        "soranet-pop-policy-report" => {
            let mut input_path: Option<PathBuf> = None;
            let mut roa_path: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut grafana_out: Option<PathBuf> = None;
            let mut alert_rules_out: Option<PathBuf> = None;
            let mut report_out: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--roa" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --roa".into());
                        };
                        roa_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--grafana-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --grafana-out".into());
                        };
                        grafana_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--alert-rules-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --alert-rules-out".into());
                        };
                        alert_rules_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" | "--report-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out/--report-out".into());
                        };
                        report_out = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-pop-policy-report: {flag}").into(),
                        );
                    }
                }
            }
            let input = input_path
                .ok_or_else(|| "soranet-pop-policy-report requires --input <path>".to_string())?;
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet_pop")
                    .join("policy")
            });
            let options = soranet_pop::PopPolicyHarnessOptions {
                descriptor: input,
                roa_bundle: roa_path,
                output_dir,
                grafana_out,
                alert_rules_out,
                report_out,
            };
            Ok(CommandKind::SoranetPopPolicyReport {
                options: Box::new(options),
            })
        }
        "soranet-pop-plan" => {
            let mut input_path: Option<PathBuf> = None;
            let mut roa_path: Option<PathBuf> = None;
            let mut frr_out: Option<PathBuf> = None;
            let mut report_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--roa" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --roa".into());
                        };
                        roa_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--frr-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --frr-out".into());
                        };
                        frr_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--report-out" | "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path or '-' after --json-out".into());
                        };
                        if path == "-" {
                            report_out = Some(JsonTarget::Stdout);
                        } else {
                            report_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-pop-plan: {flag}").into());
                    }
                }
            }
            let input =
                input_path.ok_or_else(|| "soranet-pop-plan requires --input <path>".to_string())?;
            let frr_out = frr_out.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet_pop")
                    .join("frr.conf")
            });
            let report_out = report_out.unwrap_or(JsonTarget::Stdout);
            Ok(CommandKind::SoranetPopPlan {
                input,
                roa: roa_path,
                frr_out,
                report_out,
            })
        }
        "soranet-gateway-m0" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut edge_name = "soranet-edge-m0".to_string();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--edge-name" => {
                        let Some(value) = pending.next() else {
                            return Err("expected name after --edge-name".into());
                        };
                        edge_name = value;
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-gateway-m0: {flag}").into());
                    }
                }
            }
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m0")
            });
            Ok(CommandKind::SoranetGatewayM0 {
                options: soranet_gateway::GatewayM0Options {
                    output_dir,
                    edge_name,
                },
            })
        }
        "soranet-gateway-m1" => {
            let mut config_path: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" | "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir/--out".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-gateway-m1: {flag}").into());
                    }
                }
            }
            let config_path = config_path.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m1")
                    .join("alpha_config.json")
            });
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway_m1")
                    .join("alpha")
            });
            Ok(CommandKind::SoranetGatewayM1 {
                options: soranet_gateway_m1::GatewayM1Options {
                    config_path,
                    output_dir,
                },
            })
        }
        "soranet-gateway-m2" => {
            let mut config_path: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" | "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir/--out".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-gateway-m2: {flag}").into());
                    }
                }
            }
            let config_path = config_path.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m2")
                    .join("beta_config.json")
            });
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway_m2")
                    .join("beta")
            });
            Ok(CommandKind::SoranetGatewayM2 {
                options: soranet_gateway_m2::GatewayM2Options {
                    config_path,
                    output_dir,
                },
            })
        }
        "soranet-gateway-m3" => {
            let mut m2_summary: Option<PathBuf> = None;
            let mut autoscale_plan: Option<PathBuf> = None;
            let mut worker_pack: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut sla_target: Option<String> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--m2-summary" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --m2-summary".into());
                        };
                        m2_summary = Some(normalize_path(Path::new(&path))?);
                    }
                    "--autoscale-plan" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --autoscale-plan".into());
                        };
                        autoscale_plan = Some(normalize_path(Path::new(&path))?);
                    }
                    "--worker-pack" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --worker-pack".into());
                        };
                        worker_pack = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" | "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir/--out".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--sla-target" => {
                        let Some(value) = pending.next() else {
                            return Err("expected label after --sla-target".into());
                        };
                        sla_target = Some(value);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-gateway-m3: {flag}").into());
                    }
                }
            }
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway_m3")
            });
            let m2_summary = m2_summary
                .ok_or_else(|| "soranet-gateway-m3 requires --m2-summary <path>".to_string())?;
            let autoscale_plan = autoscale_plan
                .ok_or_else(|| "soranet-gateway-m3 requires --autoscale-plan <path>".to_string())?;
            let worker_pack = worker_pack
                .ok_or_else(|| "soranet-gateway-m3 requires --worker-pack <path>".to_string())?;
            Ok(CommandKind::SoranetGatewayM3 {
                options: soranet_gateway_m3::GatewayM3Options {
                    m2_summary,
                    output_dir,
                    autoscale_plan,
                    worker_pack,
                    sla_target,
                },
            })
        }
        "soranet-gateway-ops-m0" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut pop = "soranet-pop-m0".to_string();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--pop" => {
                        let Some(value) = pending.next() else {
                            return Err("expected name after --pop".into());
                        };
                        pop = value;
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-gateway-ops-m0: {flag}").into()
                        );
                    }
                }
            }
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m0")
                    .join("observability")
            });
            Ok(CommandKind::SoranetGatewayOpsM0 {
                options: soranet_gateway_ops::GatewayOpsOptions { output_dir, pop },
            })
        }
        "soranet-gateway-pq" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut pop = "soranet-pop-pq".to_string();
            let mut srcv2_bundle: Option<PathBuf> = None;
            let mut issuer_ed25519_hex: Option<String> = None;
            let mut issuer_mldsa65_hex: Option<String> = None;
            let mut tls_bundle_dir: Option<PathBuf> = None;
            let mut trustless_config: Option<PathBuf> = None;
            let mut at_unix: Option<i64> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--output-dir" | "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir/--out".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--pop" => {
                        let Some(value) = pending.next() else {
                            return Err("expected name after --pop".into());
                        };
                        pop = value;
                    }
                    "--srcv2" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --srcv2".into());
                        };
                        srcv2_bundle = Some(normalize_path(Path::new(&path))?);
                    }
                    "--issuer-ed25519-hex" => {
                        let Some(value) = pending.next() else {
                            return Err("expected public key after --issuer-ed25519-hex".into());
                        };
                        issuer_ed25519_hex = Some(value);
                    }
                    "--issuer-mldsa65-hex" => {
                        let Some(value) = pending.next() else {
                            return Err("expected public key after --issuer-mldsa65-hex".into());
                        };
                        issuer_mldsa65_hex = Some(value);
                    }
                    "--tls-bundle" => {
                        let Some(path) = pending.next() else {
                            return Err("expected directory after --tls-bundle".into());
                        };
                        tls_bundle_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--trustless-config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --trustless-config".into());
                        };
                        trustless_config = Some(normalize_path(Path::new(&path))?);
                    }
                    "--at-unix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected Unix second after --at-unix".into());
                        };
                        let parsed = value.parse::<i64>().map_err(|error| {
                            format!("invalid Unix second `{value}` after --at-unix: {error}")
                        })?;
                        if parsed < 0 {
                            return Err("--at-unix must be non-negative".into());
                        }
                        at_unix = Some(parsed);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-gateway-pq: {flag}").into());
                    }
                }
            }
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway_pq")
            });
            let srcv2_bundle = srcv2_bundle
                .ok_or_else(|| "soranet-gateway-pq requires --srcv2 <bundle>".to_string())?;
            let issuer_ed25519_hex = issuer_ed25519_hex.ok_or_else(|| {
                "soranet-gateway-pq requires --issuer-ed25519-hex <hex> from an independent trusted source"
                    .to_string()
            })?;
            let issuer_mldsa65_hex = issuer_mldsa65_hex.ok_or_else(|| {
                "soranet-gateway-pq requires --issuer-mldsa65-hex <hex> from an independent trusted source"
                    .to_string()
            })?;
            let tls_bundle_dir = tls_bundle_dir
                .ok_or_else(|| "soranet-gateway-pq requires --tls-bundle <dir>".to_string())?;
            let trustless_config = trustless_config.ok_or_else(|| {
                "soranet-gateway-pq requires --trustless-config <path>".to_string()
            })?;
            let at_unix = at_unix.ok_or_else(|| {
                "soranet-gateway-pq requires --at-unix <unix-seconds>".to_string()
            })?;
            Ok(CommandKind::SoranetGatewayPq {
                options: soranet_gateway_pq::GatewayPqOptions {
                    output_dir,
                    pop,
                    srcv2_bundle,
                    issuer_ed25519_hex,
                    issuer_mldsa65_hex,
                    tls_bundle_dir,
                    trustless_config,
                    at_unix,
                },
            })
        }
        "soranet-bug-bounty" => {
            let mut config_path: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-bug-bounty: {flag}").into());
                    }
                }
            }
            let config_path = config_path
                .ok_or_else(|| "soranet-bug-bounty requires --config <path>".to_string())?;
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway")
                    .join("bug_bounty")
            });
            Ok(CommandKind::SoranetBugBounty {
                options: soranet_bug_bounty::BugBountyOptions {
                    config_path,
                    output_dir,
                },
            })
        }
        "soranet-gateway-ops-m1" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut pops: Vec<String> = Vec::new();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--pops" => {
                        let Some(list) = pending.next() else {
                            return Err("expected comma-separated list after --pops".into());
                        };
                        pops.extend(list.split(',').map(|s| s.to_string()));
                    }
                    "--pop" => {
                        let Some(pop) = pending.next() else {
                            return Err("expected name after --pop".into());
                        };
                        pops.push(pop);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-gateway-ops-m1: {flag}").into()
                        );
                    }
                }
            }
            if pops.is_empty() {
                pops = vec![
                    "soranet-sjc01".to_string(),
                    "soranet-iad01".to_string(),
                    "soranet-fra01".to_string(),
                ];
            }
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m1")
            });
            Ok(CommandKind::SoranetGatewayOpsM1 {
                options: soranet_gateway_ops::GatewayOpsMultiOptions { output_dir, pops },
            })
        }
        "soranet-gateway-chaos" => {
            let mut config: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut pop = "soranet-pop-m0".to_string();
            let mut scenarios: Option<Vec<String>> = None;
            let mut execute = false;
            let mut note: Option<String> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config = Some(normalize_path(Path::new(&path))?);
                    }
                    "--out" | "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out/--output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--pop" => {
                        let Some(value) = pending.next() else {
                            return Err("expected name after --pop".into());
                        };
                        pop = value;
                    }
                    "--scenario" => {
                        let Some(value) = pending.next() else {
                            return Err("expected id after --scenario".into());
                        };
                        let ids = value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>();
                        scenarios = Some(ids);
                    }
                    "--execute" => {
                        execute = true;
                    }
                    "--note" => {
                        let Some(value) = pending.next() else {
                            return Err("expected note after --note".into());
                        };
                        note = Some(value);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-gateway-chaos: {flag}").into()
                        );
                    }
                }
            }
            let config_path = config.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m0")
                    .join("observability")
                    .join("chaos_scenarios.json")
            });
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway_chaos")
            });
            let selection = scenarios
                .map(|ids| {
                    if ids.iter().any(|id| id == "all") {
                        soranet_gateway_chaos::ScenarioSelection::All
                    } else {
                        soranet_gateway_chaos::ScenarioSelection::Only(ids)
                    }
                })
                .unwrap_or(soranet_gateway_chaos::ScenarioSelection::All);
            Ok(CommandKind::SoranetGatewayChaos {
                options: soranet_gateway_chaos::ChaosOptions {
                    config_path,
                    output_dir,
                    pop,
                    scenarios: selection,
                    execute,
                    note,
                    now: OffsetDateTime::now_utc(),
                },
            })
        }
        "soranet-gateway-hardening" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut sbom: Option<PathBuf> = None;
            let mut vuln_report: Option<PathBuf> = None;
            let mut signing_policy: Option<PathBuf> = None;
            let mut sandbox_profile: Option<PathBuf> = None;
            let mut data_retention_days: u32 = 30;
            let mut log_retention_days: u32 = 30;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--output-dir" | "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir/--out".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--sbom" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --sbom".into());
                        };
                        sbom = Some(normalize_path(Path::new(&path))?);
                    }
                    "--vuln-report" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --vuln-report".into());
                        };
                        vuln_report = Some(normalize_path(Path::new(&path))?);
                    }
                    "--signing-policy" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --signing-policy".into());
                        };
                        signing_policy = Some(normalize_path(Path::new(&path))?);
                    }
                    "--sandbox-profile" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --sandbox-profile".into());
                        };
                        sandbox_profile = Some(normalize_path(Path::new(&path))?);
                    }
                    "--data-retention-days" => {
                        let Some(value) = pending.next() else {
                            return Err("expected integer after --data-retention-days".into());
                        };
                        data_retention_days = value.parse().map_err(|_| {
                            "data retention must be an unsigned integer".to_string()
                        })?;
                    }
                    "--log-retention-days" => {
                        let Some(value) = pending.next() else {
                            return Err("expected integer after --log-retention-days".into());
                        };
                        log_retention_days = value
                            .parse()
                            .map_err(|_| "log retention must be an unsigned integer")?;
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-gateway-hardening: {flag}").into(),
                        );
                    }
                }
            }
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway_hardening")
            });
            Ok(CommandKind::SoranetGatewayHardening {
                options: soranet_gateway_hardening::GatewayHardeningOptions {
                    output_dir,
                    sbom,
                    vuln_report,
                    signing_policy,
                    sandbox_profile,
                    data_retention_days,
                    log_retention_days,
                },
            })
        }
        "soranet-gar-controller" => {
            let mut config: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut markdown_out: Option<PathBuf> = None;
            let mut now_unix: Option<u64> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        markdown_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--now" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --now".into());
                        };
                        now_unix = Some(
                            value
                                .parse::<u64>()
                                .map_err(|_| "expected u64 after --now")?,
                        );
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-gar-controller: {flag}").into()
                        );
                    }
                }
            }
            let config = config.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m0")
                    .join("gar_controller.sample.json")
            });
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway")
                    .join("gar_controller")
            });
            Ok(CommandKind::SoranetGarController {
                options: soranet_gar_controller::GarControllerOptions {
                    config,
                    output_dir,
                    markdown_out,
                    now_unix,
                },
            })
        }
        "soranet-gar-export" => {
            let mut receipts_dir: Option<PathBuf> = None;
            let mut ack_dir: Option<PathBuf> = None;
            let mut json_out: Option<JsonTarget> = None;
            let mut markdown_out: Option<PathBuf> = None;
            let mut pop_label: Option<String> = None;
            let mut now_unix: Option<u64> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--receipts-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --receipts-dir".into());
                        };
                        receipts_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--acks-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --acks-dir".into());
                        };
                        ack_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        markdown_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--pop" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --pop".into());
                        };
                        pop_label = Some(value);
                    }
                    "--now" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --now".into());
                        };
                        now_unix = Some(
                            value
                                .parse::<u64>()
                                .map_err(|_| "expected u64 after --now")?,
                        );
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-gar-export: {flag}").into());
                    }
                }
            }
            let pop_clone = pop_label.clone();
            let receipts_dir = match receipts_dir {
                Some(dir) => dir,
                None => {
                    let pop = pop_label.clone().ok_or_else(|| {
                        "soranet-gar-export requires --receipts-dir or --pop".to_string()
                    })?;
                    default_gar_receipts_dir(&pop)
                }
            };
            let ack_dir = match ack_dir {
                Some(dir) => Some(dir),
                None => pop_clone.as_ref().map(|pop| default_gar_acks_dir(pop)),
            };
            let output = json_out.unwrap_or_else(|| {
                pop_clone
                    .as_ref()
                    .map(|pop| JsonTarget::File(default_gar_summary_path(pop)))
                    .unwrap_or(JsonTarget::Stdout)
            });
            Ok(CommandKind::SoranetGarExport {
                options: gar::ExportOptions {
                    receipts_dir,
                    ack_dir,
                    pop_label,
                    markdown_out,
                    now_unix,
                },
                output,
            })
        }
        "soranet-gateway-billing" => {
            let mut usage_path: Option<PathBuf> = None;
            let mut catalog_path: Option<PathBuf> = None;
            let mut guardrails_path: Option<PathBuf> = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut payer = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D".to_string();
            let mut treasury = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D".to_string();
            let mut asset = "4cuvDVPuLBKJyN6dPbRQhmLh68sU".to_string();
            let mut allow_hard_cap = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--usage" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --usage".into());
                        };
                        usage_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--catalog" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --catalog".into());
                        };
                        catalog_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--guardrails" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --guardrails".into());
                        };
                        guardrails_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-dir" | "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-dir".into());
                        };
                        output_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--payer" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --payer".into());
                        };
                        payer = value;
                    }
                    "--treasury" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --treasury".into());
                        };
                        treasury = value;
                    }
                    "--asset" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --asset".into());
                        };
                        asset = value;
                    }
                    "--allow-hard-cap" => {
                        allow_hard_cap = true;
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-gateway-billing: {flag}").into()
                        );
                    }
                }
            }
            let output_dir = output_dir.unwrap_or_else(|| {
                workspace_root()
                    .join("artifacts")
                    .join("soranet")
                    .join("gateway_billing")
            });
            let usage_path = usage_path.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m0")
                    .join("billing_usage_sample.json")
            });
            let catalog_path = catalog_path.unwrap_or_else(|| {
                workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m0")
                    .join("meter_catalog.json")
            });
            let guardrails_path = guardrails_path.or_else(|| {
                let default = workspace_root()
                    .join("configs")
                    .join("soranet")
                    .join("gateway_m0")
                    .join("billing_guardrails.json");
                default.exists().then_some(default)
            });
            Ok(CommandKind::SoranetGatewayBilling {
                options: soranet_gateway_billing::BillingOptions {
                    usage_path,
                    catalog_path,
                    guardrails_path,
                    output_dir,
                    payer,
                    treasury,
                    asset_definition: asset,
                    allow_hard_cap,
                },
            })
        }
        "soranet-privacy-report" => {
            let mut pending = args.peekable();
            let mut inputs: Vec<PathBuf> = Vec::new();
            let mut config = iroha_telemetry::privacy::PrivacyBucketConfig::default();
            let mut drain_at_unix: Option<u64> = None;
            let mut max_bucket_records = soranet_privacy::DEFAULT_MAX_BUCKET_RECORDS;
            let mut json_out: Option<JsonTarget> = None;
            let mut suppression_ratio_budget: Option<f64> = None;
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" | "-i" | "--in" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        let resolved = normalize_path(Path::new(&path))?;
                        inputs.push(resolved);
                    }
                    "--bucket-secs" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --bucket-secs".into());
                        };
                        config.bucket_secs = value.parse().map_err(|err| {
                            format!("invalid --bucket-secs value `{value}`: {err}")
                        })?;
                    }
                    "--min-contributors" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --min-contributors".into());
                        };
                        config.min_contributors = value.parse().map_err(|err| {
                            format!("invalid --min-contributors value `{value}`: {err}")
                        })?;
                    }
                    "--flush-delay-buckets" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --flush-delay-buckets".into());
                        };
                        config.flush_delay_buckets = value.parse().map_err(|err| {
                            format!("invalid --flush-delay-buckets value `{value}`: {err}")
                        })?;
                    }
                    "--force-flush-buckets" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --force-flush-buckets".into());
                        };
                        config.force_flush_buckets = value.parse().map_err(|err| {
                            format!("invalid --force-flush-buckets value `{value}`: {err}")
                        })?;
                    }
                    "--max-completed-buckets" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --max-completed-buckets".into());
                        };
                        config.max_completed_buckets = value.parse().map_err(|err| {
                            format!("invalid --max-completed-buckets value `{value}`: {err}")
                        })?;
                    }
                    "--expected-shares" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --expected-shares".into());
                        };
                        config.expected_shares = value.parse().map_err(|err| {
                            format!("invalid --expected-shares value `{value}`: {err}")
                        })?;
                    }
                    "--drain-at" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --drain-at".into());
                        };
                        drain_at_unix =
                            Some(value.parse().map_err(|err| {
                                format!("invalid --drain-at value `{value}`: {err}")
                            })?);
                    }
                    "--max-buckets" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --max-buckets".into());
                        };
                        let parsed: usize = value.parse().map_err(|err| {
                            format!("invalid --max-buckets value `{value}`: {err}")
                        })?;
                        if parsed == 0 {
                            return Err("--max-buckets must be at least 1".into());
                        }
                        max_bucket_records = parsed;
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--max-suppression-ratio" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --max-suppression-ratio".into());
                        };
                        let parsed: f64 = value.parse().map_err(|err| {
                            format!("invalid --max-suppression-ratio value `{value}`: {err}")
                        })?;
                        if !(0.0..=1.0).contains(&parsed) {
                            return Err("--max-suppression-ratio must be between 0 and 1".into());
                        }
                        suppression_ratio_budget = Some(parsed);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-privacy-report: {flag}").into()
                        );
                    }
                }
            }
            if inputs.is_empty() {
                return Err("soranet-privacy-report requires at least one --input <path>".into());
            }
            let options = soranet_privacy::PrivacyReportOptions {
                input_paths: inputs,
                bucket_config: config,
                drain_at_unix,
            };
            Ok(CommandKind::SoranetPrivacyReport {
                options,
                json_out,
                max_bucket_records,
                suppression_ratio_budget,
            })
        }
        "nexus-connect-fixture" => Ok(CommandKind::NexusConnectFixture {
            options: nexus::parse_nexus_connect_fixture_options(args)?,
        }),
        "nexus-lane-maintenance" => {
            let mut config: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-c" | "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for nexus-lane-maintenance: {flag}").into()
                        );
                    }
                }
            }
            let config = config
                .ok_or_else(|| "nexus-lane-maintenance requires --config <path>".to_string())?;
            let options = nexus_lane_maintenance::LaneMaintenanceOptions {
                config_path: config,
            };
            Ok(CommandKind::NexusLaneMaintenance { options })
        }
        "nexus-lane-audit" => {
            let mut status_path: Option<PathBuf> = None;
            let mut json_out: Option<PathBuf> = None;
            let mut parquet_out: Option<PathBuf> = None;
            let mut markdown_out: Option<PathBuf> = None;
            let mut captured_at: Option<String> = None;
            let mut lane_compliance: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--status" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --status".into());
                        };
                        status_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--parquet-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --parquet-out".into());
                        };
                        parquet_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        markdown_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--captured-at" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --captured-at".into());
                        };
                        captured_at = Some(value);
                    }
                    "--lane-compliance" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --lane-compliance".into());
                        };
                        lane_compliance = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for nexus-lane-audit: {flag}").into());
                    }
                }
            }
            let status_path = status_path
                .ok_or_else(|| "nexus-lane-audit requires --status <path>".to_string())?;
            let options = nexus::LaneAuditOptions {
                status_path,
                json_output: json_out
                    .unwrap_or_else(|| PathBuf::from("artifacts/nexus_lane_audit.json")),
                parquet_output: parquet_out
                    .unwrap_or_else(|| PathBuf::from("artifacts/nexus_lane_audit.parquet")),
                markdown_output: markdown_out
                    .unwrap_or_else(|| PathBuf::from("artifacts/nexus_lane_audit.md")),
                captured_at,
                lane_compliance,
            };
            Ok(CommandKind::NexusLaneAudit { options })
        }
        "soranet-testnet-kit" => {
            let mut output: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-testnet-kit: {flag}").into());
                    }
                }
            }
            let output = output.unwrap_or_else(default_testnet_kit_path);
            Ok(CommandKind::SoranetTestnetKit { output })
        }
        "soranet-testnet-metrics" => {
            let mut input_path: Option<PathBuf> = None;
            let mut output: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-i" | "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        if path == "-" {
                            output = Some(JsonTarget::Stdout);
                        } else {
                            output = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-testnet-metrics: {flag}").into()
                        );
                    }
                }
            }
            let Some(input) = input_path else {
                return Err("soranet-testnet-metrics requires --input <path>".into());
            };
            let output = output.unwrap_or(JsonTarget::Stdout);
            Ok(CommandKind::SoranetTestnetMetrics { input, output })
        }
        "soranet-testnet-feed" => {
            let mut promotion: Option<String> = None;
            let mut window_start: Option<Date> = None;
            let mut window_end: Option<Date> = None;
            let mut relays: Vec<String> = Vec::new();
            let mut relays_file: Option<PathBuf> = None;
            let mut metrics_report: Option<PathBuf> = None;
            let mut drill_log: Option<PathBuf> = None;
            let mut stage_report: Option<PathBuf> = None;
            let mut attachments: Vec<VerificationAttachment> = Vec::new();
            let mut output: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--promotion" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --promotion".into());
                        };
                        promotion = Some(value);
                    }
                    "--window-start" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --window-start".into());
                        };
                        window_start = Some(parse_gate_date(&value)?);
                    }
                    "--window-end" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --window-end".into());
                        };
                        window_end = Some(parse_gate_date(&value)?);
                    }
                    "--relay" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --relay".into());
                        };
                        relays.push(value);
                    }
                    "--relays-file" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --relays-file".into());
                        };
                        relays_file = Some(normalize_path(Path::new(&path))?);
                    }
                    "--metrics-report" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --metrics-report".into());
                        };
                        metrics_report = Some(normalize_path(Path::new(&path))?);
                    }
                    "--drill-log" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --drill-log".into());
                        };
                        drill_log = Some(normalize_path(Path::new(&path))?);
                    }
                    "--stage-report" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --stage-report".into());
                        };
                        stage_report = Some(normalize_path(Path::new(&path))?);
                    }
                    "--attachment" => {
                        let Some(spec) = pending.next() else {
                            return Err("expected spec after --attachment".into());
                        };
                        let (label, path) = parse_attachment_spec(&spec)?;
                        attachments.push(VerificationAttachment { label, path });
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        if path == "-" {
                            output = Some(JsonTarget::Stdout);
                        } else {
                            output = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-testnet-feed: {flag}").into());
                    }
                }
            }
            let promotion = promotion.ok_or("soranet-testnet-feed requires --promotion <value>")?;
            let window_start =
                window_start.ok_or("soranet-testnet-feed requires --window-start <date>")?;
            let window_end =
                window_end.ok_or("soranet-testnet-feed requires --window-end <date>")?;
            let metrics_report =
                metrics_report.ok_or("soranet-testnet-feed requires --metrics-report <path>")?;
            if let Some(path) = relays_file {
                let mut from_file = load_relays_from_file(&path)?;
                relays.append(&mut from_file);
            }
            if relays.is_empty() {
                return Err(
                    "soranet-testnet-feed requires at least one --relay or --relays-file".into(),
                );
            }
            let options = VerificationFeedOptions {
                promotion,
                window_start,
                window_end,
                relays,
                metrics_report,
                drill_log,
                stage_report,
                attachments,
                output: output.unwrap_or(JsonTarget::Stdout),
            };
            Ok(CommandKind::SoranetTestnetFeed {
                options: Box::new(options),
            })
        }
        "soranet-testnet-drill-bundle" => {
            let mut log_path: Option<PathBuf> = None;
            let mut signing_key: Option<PathBuf> = None;
            let mut promotion: Option<String> = None;
            let mut window_start: Option<Date> = None;
            let mut window_end: Option<Date> = None;
            let mut attachments: Vec<VerificationAttachment> = Vec::new();
            let mut output: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--log" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --log".into());
                        };
                        log_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--signing-key" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --signing-key".into());
                        };
                        signing_key = Some(normalize_path(Path::new(&path))?);
                    }
                    "--promotion" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --promotion".into());
                        };
                        promotion = Some(value);
                    }
                    "--window-start" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --window-start".into());
                        };
                        window_start = Some(parse_gate_date(&value)?);
                    }
                    "--window-end" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --window-end".into());
                        };
                        window_end = Some(parse_gate_date(&value)?);
                    }
                    "--attachment" => {
                        let Some(spec) = pending.next() else {
                            return Err("expected spec after --attachment".into());
                        };
                        let (label, path) = parse_attachment_spec(&spec)?;
                        attachments.push(VerificationAttachment { label, path });
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        if path == "-" {
                            output = Some(JsonTarget::Stdout);
                        } else {
                            output = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!(
                            "unknown flag for soranet-testnet-drill-bundle: {flag}"
                        )
                        .into());
                    }
                }
            }
            let log_path = log_path.ok_or("soranet-testnet-drill-bundle requires --log <path>")?;
            let signing_key =
                signing_key.ok_or("soranet-testnet-drill-bundle requires --signing-key <path>")?;
            let options = DrillBundleOptions {
                log_path,
                signing_key,
                promotion,
                window_start,
                window_end,
                attachments,
                output: output.unwrap_or(JsonTarget::Stdout),
            };
            Ok(CommandKind::SoranetTestnetDrillBundle {
                options: Box::new(options),
            })
        }
        "fastpq-verify-bench-manifest" => {
            let mut manifest = None;
            let mut trusted_public_key = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--manifest" => {
                        let path = pending.next().ok_or("expected path after --manifest")?;
                        if manifest.is_some() {
                            return Err("duplicate --manifest".into());
                        }
                        manifest = Some(normalize_path(Path::new(&path))?);
                    }
                    "--trusted-public-key" => {
                        if trusted_public_key.is_some() {
                            return Err("duplicate --trusted-public-key".into());
                        }
                        trusted_public_key = Some(
                            pending
                                .next()
                                .ok_or("expected hex key after --trusted-public-key")?,
                        );
                    }
                    flag => {
                        return Err(format!(
                            "unknown flag for fastpq-verify-bench-manifest: {flag}"
                        )
                        .into());
                    }
                }
            }
            Ok(CommandKind::FastpqVerifyBenchManifest {
                manifest: manifest.ok_or("fastpq-verify-bench-manifest requires --manifest")?,
                trusted_public_key: trusted_public_key
                    .ok_or("fastpq-verify-bench-manifest requires --trusted-public-key")?,
            })
        }
        "fastpq-bench-manifest" => {
            let mut benches = Vec::new();
            let mut output: Option<PathBuf> = None;
            let mut require_rows: Option<u64> = None;
            let mut max_operation_ms: BTreeMap<String, f64> = BTreeMap::new();
            let mut min_operation_speedup: BTreeMap<String, f64> = BTreeMap::new();
            let mut signing_key: Option<PathBuf> = None;
            let mut matrix_manifest: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--bench" => {
                        let Some(spec) = pending.next() else {
                            return Err("expected value after --bench".into());
                        };
                        let (label, path) = parse_labelled_path(&spec, "--bench")?;
                        benches.push(BenchInput { label, path });
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--require-rows" => {
                        let Some(value) = pending.next() else {
                            return Err("expected integer after --require-rows".into());
                        };
                        let rows = value
                            .parse::<u64>()
                            .map_err(|err| format!("invalid --require-rows `{value}`: {err}"))?;
                        require_rows = Some(rows);
                    }
                    "--max-operation-ms" => {
                        let Some(spec) = pending.next() else {
                            return Err("expected spec after --max-operation-ms".into());
                        };
                        let (name, limit) = parse_operation_limit(&spec, "--max-operation-ms")?;
                        max_operation_ms.insert(name, limit);
                    }
                    "--min-operation-speedup" => {
                        let Some(spec) = pending.next() else {
                            return Err("expected spec after --min-operation-speedup".into());
                        };
                        let (name, limit) =
                            parse_operation_limit(&spec, "--min-operation-speedup")?;
                        min_operation_speedup.insert(name, limit);
                    }
                    "--signing-key" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --signing-key".into());
                        };
                        signing_key = Some(normalize_path(Path::new(&path))?);
                    }
                    "--matrix" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --matrix".into());
                        };
                        matrix_manifest = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for fastpq-bench-manifest: {flag}").into()
                        );
                    }
                }
            }
            if matrix_manifest.is_none() {
                let default_matrix = fastpq::default_matrix_manifest_path();
                if default_matrix.is_file() {
                    matrix_manifest = Some(default_matrix);
                }
            }
            let options = BenchManifestOptions {
                benches,
                output: output.unwrap_or_else(fastpq::default_manifest_path),
                signing_key,
                require_rows,
                max_operation_ms,
                min_operation_speedup,
                matrix_manifest,
                label_max_operation_ms: BTreeMap::new(),
                label_min_operation_speedup: BTreeMap::new(),
                label_operation_filters: BTreeMap::new(),
            };
            if options.benches.is_empty() {
                return Err(
                    "fastpq-bench-manifest requires at least one --bench label=path".into(),
                );
            }
            Ok(CommandKind::FastpqBenchManifest {
                options: Box::new(options),
            })
        }
        "fastpq-stage-profile" => {
            let mut options = fastpq::StageProfileOptions::default();
            let mut custom_stages = Vec::new();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--rows" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --rows".into());
                        };
                        options.rows = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --rows `{value}`: {err}"))?;
                    }
                    "--warmups" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --warmups".into());
                        };
                        options.warmups = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --warmups `{value}`: {err}"))?;
                    }
                    "--iterations" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --iterations".into());
                        };
                        options.iterations = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --iterations `{value}`: {err}"))?;
                    }
                    "--out-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out-dir".into());
                        };
                        options.output_dir = normalize_path(Path::new(&path))?;
                    }
                    "--trace" => {
                        options.capture_trace = true;
                    }
                    "--no-trace" => {
                        options.capture_trace = false;
                    }
                    "--trace-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --trace-dir".into());
                        };
                        options.capture_trace = true;
                        options.trace_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--trace-template" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --trace-template".into());
                        };
                        options.capture_trace = true;
                        options.trace_template = Some(value);
                    }
                    "--trace-seconds" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --trace-seconds".into());
                        };
                        let seconds = value
                            .parse::<u32>()
                            .map_err(|err| format!("invalid --trace-seconds `{value}`: {err}"))?;
                        options.capture_trace = true;
                        options.trace_seconds = Some(seconds);
                    }
                    "--debug" => {
                        options.release = false;
                    }
                    "--no-gpu-probe" => {
                        options.gpu_probe = false;
                    }
                    "--stage" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --stage".into());
                        };
                        let Some(stage) = fastpq::StageKind::from_str(&value) else {
                            return Err(format!("unknown --stage `{value}`").into());
                        };
                        custom_stages.push(stage);
                    }
                    flag => {
                        return Err(format!("unknown flag for fastpq-stage-profile: {flag}").into());
                    }
                }
            }
            if !custom_stages.is_empty() {
                options.stages = custom_stages;
            }
            Ok(CommandKind::FastpqStageProfile {
                options: Box::new(options),
            })
        }
        "fastpq-cuda-suite" => {
            let mut options = fastpq::CudaSuiteOptions::default();
            let mut output_overridden = false;
            let mut raw_overridden = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--rows" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --rows".into());
                        };
                        options.rows = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --rows `{value}`: {err}"))?;
                    }
                    "--warmups" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --warmups".into());
                        };
                        options.warmups = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --warmups `{value}`: {err}"))?;
                    }
                    "--iterations" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --iterations".into());
                        };
                        options.iterations = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --iterations `{value}`: {err}"))?;
                    }
                    "--columns" | "--column-count" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --columns".into());
                        };
                        options.column_count = value
                            .parse::<usize>()
                            .map_err(|err| format!("invalid --columns `{value}`: {err}"))?;
                    }
                    "--operation" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --operation".into());
                        };
                        options.operation = if value.eq_ignore_ascii_case("all") {
                            None
                        } else {
                            Some(fastpq::StageKind::from_str(&value).ok_or_else(|| {
                                format!(
                                    "invalid --operation `{value}`: expected fft, ifft, lde, digest384_trace_columns, digest384_merkle_pairs, bn254_poseidon_words, or all"
                                )
                            })?)
                        };
                    }
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        options.output = normalize_path(Path::new(&path))?;
                        output_overridden = true;
                    }
                    "--raw-output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --raw-output".into());
                        };
                        options.raw_output = normalize_path(Path::new(&path))?;
                        raw_overridden = true;
                    }
                    "--no-wrap" => {
                        options.wrap_output = false;
                    }
                    "--wrapper" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --wrapper".into());
                        };
                        options.wrapper = normalize_path(Path::new(&path))?;
                    }
                    "--require-lde-mean-ms" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --require-lde-mean-ms".into());
                        };
                        options.require_lde_mean_ms = value.parse::<f64>().map_err(|err| {
                            format!("invalid --require-lde-mean-ms `{value}`: {err}")
                        })?;
                    }
                    "--require-digest384-mean-ms" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --require-digest384-mean-ms".into());
                        };
                        options.require_digest384_mean_ms =
                            value.parse::<f64>().map_err(|err| {
                                format!("invalid --require-digest384-mean-ms `{value}`: {err}")
                            })?;
                    }
                    "--label" => {
                        let Some(spec) = pending.next() else {
                            return Err("expected value after --label".into());
                        };
                        let (key, value) = parse_label_value(&spec, "--label")?;
                        options.labels.insert(key, value);
                    }
                    "--row-usage" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --row-usage".into());
                        };
                        options.row_usage = Some(normalize_path(Path::new(&path))?);
                    }
                    "--device" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --device".into());
                        };
                        options.device = Some(value);
                    }
                    "--notes" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --notes".into());
                        };
                        options.notes = Some(value);
                    }
                    "--accel-instance" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --accel-instance".into());
                        };
                        options.accel_instance = Some(value);
                    }
                    "--accel-state-json" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --accel-state-json".into());
                        };
                        options.accel_state_json = Some(normalize_path(Path::new(&path))?);
                    }
                    "--accel-state-prom" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --accel-state-prom".into());
                        };
                        options.accel_state_prom = Some(normalize_path(Path::new(&path))?);
                    }
                    "--sign-output" => {
                        options.sign_output = true;
                    }
                    "--gpg-key" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --gpg-key".into());
                        };
                        options.gpg_key = Some(value);
                    }
                    "--dry-run" => {
                        options.dry_run = true;
                    }
                    "--require-gpu" => {
                        options.require_gpu = true;
                    }
                    flag => {
                        return Err(format!("unknown flag for fastpq-cuda-suite: {flag}").into());
                    }
                }
            }
            if !output_overridden {
                options.output =
                    fastpq::default_cuda_bench_output_path_for_operation(options.operation);
            }
            if !raw_overridden {
                options.raw_output = fastpq::default_cuda_raw_output(&options.output);
            }
            Ok(CommandKind::FastpqCudaSuite {
                options: Box::new(options),
            })
        }
        "soranet-constant-rate-profile" => {
            let mut profile_name: Option<String> = None;
            let mut format = soranet::ConstantRateOutputFormat::Table;
            let mut include_tick_table = false;
            let mut tick_values: Vec<f64> = Vec::new();
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--profile" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --profile".into());
                        };
                        if value.trim().is_empty() {
                            return Err("--profile requires a non-empty value".into());
                        }
                        profile_name = Some(value);
                    }
                    "--format" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --format".into());
                        };
                        format = match value.as_str() {
                            "table" => soranet::ConstantRateOutputFormat::Table,
                            "json" => soranet::ConstantRateOutputFormat::Json,
                            "markdown" => soranet::ConstantRateOutputFormat::Markdown,
                            other => {
                                return Err(format!(
                                    "unknown --format `{other}`; expected table|json|markdown"
                                )
                                .into());
                            }
                        };
                    }
                    "--tick-table" => {
                        include_tick_table = true;
                    }
                    "--tick-values" => {
                        let Some(value) = pending.next() else {
                            return Err(
                                "expected comma-separated values after --tick-values".into()
                            );
                        };
                        include_tick_table = true;
                        let mut parsed = Vec::new();
                        for raw in value.split(',') {
                            let trimmed = raw.trim();
                            if trimmed.is_empty() {
                                return Err("tick values may not be empty".into());
                            }
                            let parsed_value = trimmed
                                .parse::<f64>()
                                .map_err(|err| format!("invalid tick value `{trimmed}`: {err}"))?;
                            parsed.push(parsed_value);
                        }
                        tick_values = parsed;
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!(
                            "unknown flag for soranet-constant-rate-profile: {flag}"
                        )
                        .into());
                    }
                }
            }
            let selection = match profile_name {
                Some(name) => soranet::ConstantRateSelection::Named(name),
                None => soranet::ConstantRateSelection::All,
            };
            Ok(CommandKind::SoranetConstantRateProfile {
                selection,
                format,
                include_tick_table,
                tick_values,
                json_out,
            })
        }
        "soradns-hosts" => {
            let mut names = Vec::new();
            let mut pretty_suffix = soradns::default_pretty_gateway_suffix();
            let mut json_out: Option<JsonTarget> = None;
            let mut verify_paths: Vec<PathBuf> = Vec::new();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--name" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --name".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--name requires a non-empty value".into());
                        }
                        names.push(trimmed.to_string());
                    }
                    "--pretty-suffix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --pretty-suffix".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--pretty-suffix requires a non-empty value".into());
                        }
                        pretty_suffix = trimmed.to_string();
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--verify-host-patterns" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --verify-host-patterns".into());
                        };
                        verify_paths.push(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for soradns-hosts: {flag}").into());
                    }
                }
            }
            if names.is_empty() {
                return Err("soradns-hosts requires at least one --name <fqdn>".into());
            }
            Ok(CommandKind::SoradnsHosts {
                names,
                pretty_suffix,
                json: json_out,
                verify: verify_paths,
            })
        }
        "soradns-binding-template" => {
            let mut manifest: Option<PathBuf> = None;
            let mut alias: Option<String> = None;
            let mut hostname: Option<String> = None;
            let mut route_label: Option<String> = None;
            let mut proof_status: Option<String> = None;
            let mut csp_template: Option<String> = None;
            let mut permissions_template: Option<String> = None;
            let mut hsts_template: Option<String> = None;
            let mut include_csp = true;
            let mut include_permissions = true;
            let mut include_hsts = true;
            let mut json_out: Option<JsonTarget> = None;
            let mut headers_out: Option<PathBuf> = None;
            let mut generated_at: Option<OffsetDateTime> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--manifest" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --manifest".into());
                        };
                        manifest = Some(normalize_path(Path::new(&value))?);
                    }
                    "--alias" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --alias".into());
                        };
                        alias = Some(value);
                    }
                    "--hostname" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --hostname".into());
                        };
                        hostname = Some(value);
                    }
                    "--route-label" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --route-label".into());
                        };
                        route_label = Some(value);
                    }
                    "--proof-status" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --proof-status".into());
                        };
                        proof_status = Some(value);
                    }
                    "--csp-template" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --csp-template".into());
                        };
                        csp_template = Some(value);
                    }
                    "--permissions-template" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --permissions-template".into());
                        };
                        permissions_template = Some(value);
                    }
                    "--hsts-template" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --hsts-template".into());
                        };
                        hsts_template = Some(value);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--headers-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --headers-out".into());
                        };
                        headers_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--generated-at" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --generated-at".into());
                        };
                        let parsed = OffsetDateTime::parse(&value, &Rfc3339)
                            .map_err(|err| format!("invalid RFC3339 timestamp `{value}`: {err}"))?;
                        generated_at = Some(parsed);
                    }
                    "--no-csp" => include_csp = false,
                    "--no-permissions-policy" => include_permissions = false,
                    "--no-hsts" => include_hsts = false,
                    flag => {
                        return Err(
                            format!("unknown flag for soradns-binding-template: {flag}").into()
                        );
                    }
                }
            }
            let manifest = manifest.ok_or("soradns-binding-template requires --manifest <path>")?;
            let alias = alias.ok_or("soradns-binding-template requires --alias <value>")?;
            let hostname =
                hostname.ok_or("soradns-binding-template requires --hostname <value>")?;
            let options = soradns::BindingTemplateOptions {
                manifest_path: manifest,
                alias,
                hostname,
                route_label,
                proof_status,
                csp_template,
                permissions_template,
                hsts_template,
                include_csp,
                include_permissions,
                include_hsts,
                generated_at: generated_at.unwrap_or_else(OffsetDateTime::now_utc),
            };
            Ok(CommandKind::SoradnsBindingTemplate {
                options,
                json: json_out,
                headers_out,
            })
        }
        "soradns-gar-template" => {
            let mut name: Option<String> = None;
            let mut manifest_cid: Option<String> = None;
            let mut manifest_digest: Option<String> = None;
            let mut manifest_path: Option<PathBuf> = None;
            let mut valid_from_epoch: Option<u64> = None;
            let mut valid_until_epoch: Option<u64> = None;
            let mut csp_template: Option<String> = None;
            let mut hsts_template: Option<String> = None;
            let mut permissions_template: Option<String> = None;
            let mut telemetry_labels: Vec<String> = Vec::new();
            let mut pretty_suffix = soradns::default_pretty_gateway_suffix();
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--name" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --name".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--name requires a non-empty value".into());
                        }
                        name = Some(trimmed.to_string());
                    }
                    "--manifest-cid" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --manifest-cid".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--manifest-cid requires a non-empty value".into());
                        }
                        manifest_cid = Some(trimmed.to_string());
                    }
                    "--manifest-digest" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --manifest-digest".into());
                        };
                        if value.trim().is_empty() {
                            manifest_digest = None;
                        } else {
                            manifest_digest = Some(value);
                        }
                    }
                    "--manifest" => {
                        let Some(value) = pending.next() else {
                            return Err("expected path after --manifest".into());
                        };
                        manifest_path = Some(normalize_path(Path::new(&value))?);
                    }
                    "--valid-from" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --valid-from".into());
                        };
                        let parsed = parse_u64_flag(&value, "--valid-from")?;
                        valid_from_epoch = Some(parsed);
                    }
                    "--valid-until" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --valid-until".into());
                        };
                        let parsed = parse_u64_flag(&value, "--valid-until")?;
                        valid_until_epoch = Some(parsed);
                    }
                    "--csp-template" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --csp-template".into());
                        };
                        if value.trim().is_empty() {
                            csp_template = None;
                        } else {
                            csp_template = Some(value);
                        }
                    }
                    "--hsts-template" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --hsts-template".into());
                        };
                        if value.trim().is_empty() {
                            hsts_template = None;
                        } else {
                            hsts_template = Some(value);
                        }
                    }
                    "--permissions-template" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --permissions-template".into());
                        };
                        if value.trim().is_empty() {
                            permissions_template = None;
                        } else {
                            permissions_template = Some(value);
                        }
                    }
                    "--telemetry-label" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --telemetry-label".into());
                        };
                        let trimmed = value.trim();
                        if !trimmed.is_empty() {
                            telemetry_labels.push(trimmed.to_string());
                        }
                    }
                    "--pretty-suffix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --pretty-suffix".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--pretty-suffix requires a non-empty value".into());
                        }
                        pretty_suffix = trimmed.to_string();
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for soradns-gar-template: {flag}").into());
                    }
                }
            }
            let Some(name) = name else {
                return Err("soradns-gar-template requires --name <fqdn>".into());
            };
            if manifest_cid.is_none() && manifest_path.is_none() {
                return Err(
                    "soradns-gar-template requires --manifest <path> or --manifest-cid <cid>"
                        .into(),
                );
            }
            let mut resolved_manifest_cid = manifest_cid;
            let mut resolved_manifest_digest = manifest_digest;
            if let Some(path) = manifest_path {
                let manifest_meta =
                    soradns::manifest_cid_and_digest_from_path(&path).map_err(|err| {
                        format!(
                            "failed to derive manifest metadata from {}: {err}",
                            path.display()
                        )
                    })?;
                match resolved_manifest_cid {
                    Some(ref mut manual) => {
                        let trimmed = manual.trim();
                        if !trimmed.eq_ignore_ascii_case(manifest_meta.manifest_cid.as_str()) {
                            return Err(format!(
                                "--manifest-cid `{}` does not match derived `{}`",
                                trimmed, manifest_meta.manifest_cid
                            )
                            .into());
                        }
                        *manual = manifest_meta.manifest_cid.clone();
                    }
                    None => {
                        resolved_manifest_cid = Some(manifest_meta.manifest_cid.clone());
                    }
                }
                match resolved_manifest_digest {
                    Some(ref mut manual) => {
                        let normalized =
                            soradns::normalize_manifest_digest(manual).map_err(|err| {
                                format!("invalid --manifest-digest `{manual}`: {err}")
                            })?;
                        if normalized != manifest_meta.manifest_digest_hex {
                            return Err(format!(
                                "--manifest-digest `{}` does not match derived `{}`",
                                manual, manifest_meta.manifest_digest_hex
                            )
                            .into());
                        }
                        *manual = normalized;
                    }
                    None => {
                        resolved_manifest_digest = Some(manifest_meta.manifest_digest_hex.clone());
                    }
                }
            }
            let Some(manifest_cid) = resolved_manifest_cid else {
                return Err(
                    "soradns-gar-template could not determine a manifest CID (pass --manifest or --manifest-cid)".into(),
                );
            };
            let default_valid_from = unix_timestamp_now()?;
            let options = soradns::GarTemplateOptions {
                name,
                pretty_suffix,
                manifest_cid,
                manifest_digest: resolved_manifest_digest,
                csp_template,
                hsts_template,
                permissions_template,
                valid_from_epoch: valid_from_epoch.unwrap_or(default_valid_from),
                valid_until_epoch,
                telemetry_labels,
            };
            Ok(CommandKind::SoradnsGarTemplate {
                options,
                output: json_out,
            })
        }
        "soradns-acme-plan" => {
            let mut names: Vec<String> = Vec::new();
            let mut directory_url: Option<String> = None;
            let mut include_pretty = true;
            let mut include_canonical_wildcard = true;
            let mut pretty_suffix = soradns::default_pretty_gateway_suffix();
            let mut generated_at: Option<OffsetDateTime> = None;
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--name" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --name".into());
                        };
                        names.push(value);
                    }
                    "--directory-url" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --directory-url".into());
                        };
                        directory_url = Some(value);
                    }
                    "--pretty-suffix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --pretty-suffix".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--pretty-suffix requires a non-empty value".into());
                        }
                        pretty_suffix = trimmed.to_string();
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = Some(if path == "-" {
                            JsonTarget::Stdout
                        } else {
                            JsonTarget::File(normalize_path(Path::new(&path))?)
                        });
                    }
                    "--generated-at" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --generated-at".into());
                        };
                        let parsed = OffsetDateTime::parse(&value, &Rfc3339)
                            .map_err(|err| format!("invalid RFC3339 timestamp `{value}`: {err}"))?;
                        generated_at = Some(parsed);
                    }
                    "--no-pretty" => include_pretty = false,
                    "--no-canonical-wildcard" => include_canonical_wildcard = false,
                    flag => {
                        return Err(format!("unknown flag for soradns-acme-plan: {flag}").into());
                    }
                }
            }
            if names.is_empty() {
                return Err("soradns-acme-plan requires at least one --name <fqdn>".into());
            }
            if !include_pretty && !include_canonical_wildcard {
                return Err("soradns-acme-plan requires at least one certificate target; enable canonical wildcard and/or pretty hosts".into());
            }
            let options = soradns::AcmePlanOptions {
                names,
                directory_url: directory_url
                    .unwrap_or_else(|| soradns::DEFAULT_ACME_DIRECTORY_URL.to_string()),
                include_canonical_wildcard,
                include_pretty_hosts: include_pretty,
                pretty_suffix,
                generated_at: generated_at.unwrap_or_else(OffsetDateTime::now_utc),
            };
            Ok(CommandKind::SoradnsAcmePlan {
                options,
                output: json_out.unwrap_or(JsonTarget::Stdout),
            })
        }
        "soradns-cache-plan" => {
            let mut names: Vec<String> = Vec::new();
            let mut include_pretty_hosts = true;
            let mut pretty_suffix = soradns::default_pretty_gateway_suffix();
            let mut paths: Vec<String> = Vec::new();
            let mut http_method: Option<String> = None;
            let mut auth_header: Option<String> = None;
            let mut auth_env: Option<String> = None;
            let mut generated_at: Option<OffsetDateTime> = None;
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--name" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --name".into());
                        };
                        names.push(value);
                    }
                    "--path" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --path".into());
                        };
                        paths.push(value);
                    }
                    "--http-method" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --http-method".into());
                        };
                        http_method = Some(value);
                    }
                    "--auth-header" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --auth-header".into());
                        };
                        auth_header = Some(value);
                    }
                    "--auth-env" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --auth-env".into());
                        };
                        auth_env = Some(value);
                    }
                    "--generated-at" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --generated-at".into());
                        };
                        let parsed = OffsetDateTime::parse(&value, &Rfc3339)
                            .map_err(|err| format!("invalid RFC3339 timestamp `{value}`: {err}"))?;
                        generated_at = Some(parsed);
                    }
                    "--no-pretty" => include_pretty_hosts = false,
                    "--pretty-suffix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --pretty-suffix".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--pretty-suffix requires a non-empty value".into());
                        }
                        pretty_suffix = trimmed.to_string();
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = Some(if path == "-" {
                            JsonTarget::Stdout
                        } else {
                            JsonTarget::File(normalize_path(Path::new(&path))?)
                        });
                    }
                    flag => {
                        return Err(format!("unknown flag for soradns-cache-plan: {flag}").into());
                    }
                }
            }
            if names.is_empty() {
                return Err("soradns-cache-plan requires at least one --name <fqdn>".into());
            }
            let options = soradns::CacheInvalidationPlanOptions {
                names,
                include_pretty_hosts,
                pretty_suffix,
                paths,
                http_method: http_method.unwrap_or_else(|| "PURGE".to_string()),
                auth_header,
                auth_env,
                generated_at: generated_at.unwrap_or_else(OffsetDateTime::now_utc),
            };
            Ok(CommandKind::SoradnsCachePlan {
                options,
                output: json_out.unwrap_or(JsonTarget::Stdout),
            })
        }
        "soradns-route-plan" => {
            let mut names: Vec<String> = Vec::new();
            let mut include_pretty_hosts = true;
            let mut pretty_suffix = soradns::default_pretty_gateway_suffix();
            let mut generated_at: Option<OffsetDateTime> = None;
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--name" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --name".into());
                        };
                        names.push(value);
                    }
                    "--no-pretty" => include_pretty_hosts = false,
                    "--pretty-suffix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --pretty-suffix".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--pretty-suffix requires a non-empty value".into());
                        }
                        pretty_suffix = trimmed.to_string();
                    }
                    "--generated-at" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --generated-at".into());
                        };
                        let parsed = OffsetDateTime::parse(&value, &Rfc3339)
                            .map_err(|err| format!("invalid RFC3339 timestamp `{value}`: {err}"))?;
                        generated_at = Some(parsed);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = Some(if path == "-" {
                            JsonTarget::Stdout
                        } else {
                            JsonTarget::File(normalize_path(Path::new(&path))?)
                        });
                    }
                    flag => {
                        return Err(format!("unknown flag for soradns-route-plan: {flag}").into());
                    }
                }
            }
            if names.is_empty() {
                return Err("soradns-route-plan requires at least one --name <fqdn>".into());
            }
            let options = soradns::RoutePlanOptions {
                names,
                include_pretty_hosts,
                pretty_suffix,
                generated_at: generated_at.unwrap_or_else(OffsetDateTime::now_utc),
            };
            Ok(CommandKind::SoradnsRoutePlan {
                options,
                output: json_out.unwrap_or(JsonTarget::Stdout),
            })
        }
        "soradns-verify-gar" => {
            let mut gar_path: Option<PathBuf> = None;
            let mut name: Option<String> = None;
            let mut manifest_cid: Option<String> = None;
            let mut manifest_digest: Option<String> = None;
            let mut telemetry_labels: Vec<String> = Vec::new();
            let mut pretty_suffix = soradns::default_pretty_gateway_suffix();
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--gar" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --gar".into());
                        };
                        gar_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--name" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --name".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--name requires a non-empty value".into());
                        }
                        name = Some(trimmed.to_string());
                    }
                    "--manifest-cid" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --manifest-cid".into());
                        };
                        manifest_cid = Some(value);
                    }
                    "--manifest-digest" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --manifest-digest".into());
                        };
                        manifest_digest = Some(value);
                    }
                    "--telemetry-label" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --telemetry-label".into());
                        };
                        if !value.trim().is_empty() {
                            telemetry_labels.push(value);
                        }
                    }
                    "--pretty-suffix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --pretty-suffix".into());
                        };
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            return Err("--pretty-suffix requires a non-empty value".into());
                        }
                        pretty_suffix = trimmed.to_string();
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            json_out = Some(JsonTarget::Stdout);
                        } else {
                            json_out = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for soradns-verify-gar: {flag}").into());
                    }
                }
            }
            let gar_path =
                gar_path.ok_or("soradns-verify-gar requires --gar <path/to/gar.json>")?;
            let name = name.ok_or("soradns-verify-gar requires --name <fqdn>")?;
            let options = soradns::GarVerifyOptions {
                name,
                pretty_suffix,
                expected_manifest_cid: manifest_cid,
                expected_manifest_digest: manifest_digest,
                required_telemetry_labels: telemetry_labels,
            };
            Ok(CommandKind::SoradnsVerifyGar {
                options: SoradnsVerifyGarOptions {
                    gar_path,
                    expectations: options,
                    json_out,
                },
            })
        }
        "soradns-verify-binding" => {
            let mut binding: Option<PathBuf> = None;
            let mut alias: Option<String> = None;
            let mut content_cid: Option<String> = None;
            let mut hostname: Option<String> = None;
            let mut proof_status: Option<String> = None;
            let mut manifest_json: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--binding" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --binding".into());
                        };
                        binding = Some(normalize_path(Path::new(&path))?);
                    }
                    "--alias" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --alias".into());
                        };
                        alias = Some(value.trim().to_string());
                    }
                    "--content-cid" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --content-cid".into());
                        };
                        content_cid = Some(value.trim().to_string());
                    }
                    "--hostname" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --hostname".into());
                        };
                        hostname = Some(value.trim().to_string());
                    }
                    "--proof-status" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --proof-status".into());
                        };
                        proof_status = Some(value.trim().to_string());
                    }
                    "--manifest-json" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --manifest-json".into());
                        };
                        manifest_json = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soradns-verify-binding: {flag}").into()
                        );
                    }
                }
            }
            let Some(binding_path) = binding else {
                return Err("soradns-verify-binding requires --binding <path>".into());
            };
            Ok(CommandKind::SoradnsVerifyBinding {
                binding: binding_path,
                alias,
                content_cid,
                hostname,
                proof_status,
                manifest: manifest_json,
            })
        }
        "soradns-directory-release" => {
            let mut rad_dir = None;
            let mut output_root = None;
            let mut release_key = None;
            let mut car_cid = None;
            let mut prev_id = None;
            let mut created_at = None;
            let mut note = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--rad-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --rad-dir".into());
                        };
                        rad_dir = Some(PathBuf::from(path));
                    }
                    "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        output_root = Some(normalize_path(Path::new(&path))?);
                    }
                    "--release-key" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --release-key".into());
                        };
                        release_key = Some(normalize_path(Path::new(&path))?);
                    }
                    "--car-cid" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --car-cid".into());
                        };
                        car_cid = Some(value);
                    }
                    "--prev-id" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --prev-id".into());
                        };
                        prev_id = Some(value.to_ascii_lowercase());
                    }
                    "--created-at" => {
                        let Some(value) = pending.next() else {
                            return Err("expected RFC3339 timestamp after --created-at".into());
                        };
                        let timestamp = OffsetDateTime::parse(&value, &Rfc3339)
                            .map_err(|err| format!("invalid --created-at `{value}`: {err}"))?;
                        created_at = Some(timestamp);
                    }
                    "--note" => {
                        let Some(value) = pending.next() else {
                            return Err("expected note after --note".into());
                        };
                        note = Some(value);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soradns-directory-release: {flag}").into(),
                        );
                    }
                }
            }
            let rad_dir = rad_dir.ok_or("missing required --rad-dir")?;
            let release_key_path = release_key.ok_or("missing required --release-key")?;
            let car_cid = car_cid.ok_or("missing required --car-cid")?;
            let options = soradns::DirectoryReleaseOptions {
                rad_dir,
                output_root: output_root.unwrap_or_else(default_directory_release_output_root),
                release_key_path,
                car_cid,
                prev_id_hex: prev_id,
                created_at,
                note,
            };
            Ok(CommandKind::SoradnsDirectoryRelease {
                options: Box::new(options),
            })
        }
        "soranet-rollout-plan" => {
            let mut regions: Option<String> = None;
            let mut start: Option<OffsetDateTime> = None;
            let mut window_spec: Option<String> = None;
            let mut spacing_spec: Option<String> = None;
            let mut client_offset_spec: Option<String> = None;
            let mut output_json: Option<PathBuf> = None;
            let mut markdown_out: Option<PathBuf> = None;
            let mut label: Option<String> = None;
            let mut environment: Option<String> = None;
            let mut phase = RolloutPhase::Ramp;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--regions" => {
                        let Some(value) = pending.next() else {
                            return Err("expected comma-separated list after --regions".into());
                        };
                        regions = Some(value);
                    }
                    "--start" => {
                        let Some(value) = pending.next() else {
                            return Err("expected RFC3339 timestamp after --start".into());
                        };
                        let parsed = OffsetDateTime::parse(&value, &Rfc3339)
                            .map_err(|err| format!("invalid --start timestamp `{value}`: {err}"))?;
                        start = Some(parsed);
                    }
                    "--window" => {
                        let Some(value) = pending.next() else {
                            return Err("expected duration after --window".into());
                        };
                        window_spec = Some(value);
                    }
                    "--spacing" => {
                        let Some(value) = pending.next() else {
                            return Err("expected duration after --spacing".into());
                        };
                        spacing_spec = Some(value);
                    }
                    "--client-offset" => {
                        let Some(value) = pending.next() else {
                            return Err("expected duration after --client-offset".into());
                        };
                        client_offset_spec = Some(value);
                    }
                    "--phase" => {
                        let Some(value) = pending.next() else {
                            return Err("expected phase label after --phase".into());
                        };
                        phase = RolloutPhase::parse(&value).ok_or_else(|| {
                            format!("invalid rollout phase `{value}`; expected canary|ramp|default")
                        })?;
                    }
                    "--label" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --label".into());
                        };
                        label = Some(value);
                    }
                    "--environment" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --environment".into());
                        };
                        environment = Some(value);
                    }
                    "-o" | "--out" | "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        output_json = Some(normalize_path(Path::new(&path))?);
                    }
                    "--markdown" | "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        markdown_out = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for soranet-rollout-plan: {flag}").into());
                    }
                }
            }
            let regions = regions.ok_or("soranet-rollout-plan requires --regions <a,b,...>")?;
            let start = start.ok_or("soranet-rollout-plan requires --start <RFC3339 timestamp>")?;
            let regions_vec: Vec<String> = regions
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
                .collect();
            if regions_vec.is_empty() {
                return Err("at least one region must be provided after --regions".into());
            }
            let window =
                soranet_rollout::parse_duration_spec(window_spec.as_deref().unwrap_or("6h"))?;
            let spacing =
                soranet_rollout::parse_duration_spec(spacing_spec.as_deref().unwrap_or("24h"))?;
            let client_offset = match client_offset_spec {
                Some(spec) => Some(soranet_rollout::parse_duration_spec(&spec)?),
                None => None,
            };
            let options = soranet_rollout::PlanOptions {
                label: label.unwrap_or_else(|| "SNNet-16G rollout".to_string()),
                environment: environment.unwrap_or_else(|| "production".to_string()),
                phase,
                start,
                regions: regions_vec,
                window,
                spacing,
                client_offset,
                output_json: output_json.unwrap_or_else(default_rollout_plan_path),
                output_markdown: Some(markdown_out.unwrap_or_else(default_rollout_markdown_path)),
            };
            Ok(CommandKind::SoranetRolloutPlan { options })
        }
        "soranet-rollout-capture" => {
            let mut base_dir: Option<PathBuf> = None;
            let mut label: Option<String> = None;
            let mut environment = String::from("production");
            let mut phase = RolloutPhase::Ramp;
            let mut log_path: Option<PathBuf> = None;
            let mut artifacts: Vec<soranet_rollout::ArtifactInput> = Vec::new();
            let mut key_path: Option<PathBuf> = None;
            let mut note: Option<String> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out".into());
                        };
                        base_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    "--label" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --label".into());
                        };
                        label = Some(value);
                    }
                    "--environment" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --environment".into());
                        };
                        environment = value;
                    }
                    "--phase" => {
                        let Some(value) = pending.next() else {
                            return Err("expected phase label after --phase".into());
                        };
                        phase = RolloutPhase::parse(&value).ok_or_else(|| {
                            format!("invalid rollout phase `{value}`; expected canary|ramp|default")
                        })?;
                    }
                    "--log" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --log".into());
                        };
                        log_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--artifact" => {
                        let Some(spec) = pending.next() else {
                            return Err("expected spec after --artifact".into());
                        };
                        let (kind, path_str) = parse_rollout_artifact_spec(&spec)?;
                        let path = normalize_path(Path::new(&path_str))?;
                        artifacts.push(soranet_rollout::ArtifactInput { kind, path });
                    }
                    "--key" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --key".into());
                        };
                        key_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--note" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --note".into());
                        };
                        note = Some(value);
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for soranet-rollout-capture: {flag}").into()
                        );
                    }
                }
            }
            let log_path = log_path.ok_or("soranet-rollout-capture requires --log <path>")?;
            let key_path = key_path.ok_or("soranet-rollout-capture requires --key <path>")?;
            let options = soranet_rollout::CaptureOptions {
                base_output_dir: base_dir.unwrap_or_else(default_rollout_capture_dir),
                label,
                environment,
                phase,
                log_path,
                additional_artifacts: artifacts,
                key_path,
                note,
            };
            Ok(CommandKind::SoranetRolloutCapture { options })
        }
        "sorafs-pin-fixtures" => {
            let mut output: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "-o" | "--out" | "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for sorafs-pin-fixtures: {flag}").into());
                    }
                }
            }
            let output = output.unwrap_or_else(default_pin_fixture_path);
            Ok(CommandKind::SorafsPinFixtures { output })
        }
        "space-directory" => {
            let Some(subcommand) = args.next() else {
                print_usage();
                return Err("missing space-directory subcommand".into());
            };
            match subcommand.as_str() {
                "encode" => {
                    let mut input: Option<PathBuf> = None;
                    let mut output: Option<PathBuf> = None;
                    while let Some(arg) = args.next() {
                        match arg.as_str() {
                            "--json" => {
                                let value = args
                                    .next()
                                    .ok_or("--json requires a path to the manifest JSON")?;
                                input = Some(normalize_path(Path::new(&value))?);
                            }
                            "--out" | "--output" => {
                                let value = args
                                    .next()
                                    .ok_or("--out/--output requires a destination path")?;
                                output = Some(normalize_path(Path::new(&value))?);
                            }
                            "-h" | "--help" => {
                                print_usage();
                                return Err("".into());
                            }
                            other => {
                                return Err(format!(
                                    "unknown flag `{other}` for space-directory encode"
                                )
                                .into());
                            }
                        }
                    }
                    let input =
                        input.ok_or("space-directory encode requires --json <manifest.json>")?;
                    let output = output.unwrap_or_else(|| {
                        let mut candidate = input.clone();
                        candidate.set_extension("to");
                        candidate
                    });
                    Ok(CommandKind::SpaceDirectoryEncode { input, output })
                }
                other => Err(format!(
                    "unknown space-directory subcommand `{other}` (expected encode)"
                )
                .into()),
            }
        }
        "acceleration-state" => {
            let mut format = AccelerationOutputFormat::Table;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--format" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --format".into());
                        };
                        format = AccelerationOutputFormat::parse(&value)?;
                    }
                    flag => {
                        return Err(format!("unknown flag for acceleration-state: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::AccelerationState { format })
        }
        "sns-scorecard" => {
            let mut input: Option<PathBuf> = None;
            let mut output_json: Option<PathBuf> = None;
            let mut output_markdown: Option<PathBuf> = None;
            let mut output_handoff_json: Option<PathBuf> = None;
            let mut output_handoff_markdown: Option<PathBuf> = None;
            let mut handoff_dir: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-json" | "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-json".into());
                        };
                        output_json = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output-markdown" | "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-markdown".into());
                        };
                        output_markdown = Some(normalize_path(Path::new(&path))?);
                    }
                    "--handoff-json" | "--handoff-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --handoff-json".into());
                        };
                        output_handoff_json = Some(normalize_path(Path::new(&path))?);
                    }
                    "--handoff-markdown" | "--handoff-md" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --handoff-markdown".into());
                        };
                        output_handoff_markdown = Some(normalize_path(Path::new(&path))?);
                    }
                    "--handoff-dir" | "--handoffs" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --handoff-dir".into());
                        };
                        handoff_dir = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for sns-scorecard: {flag}").into());
                    }
                }
            }
            let input =
                input.ok_or("sns-scorecard requires --input <path to steward metrics JSON>")?;
            let output_json = output_json.ok_or(
                "sns-scorecard requires --output-json <path> to write the canonical scoreboard",
            )?;
            Ok(CommandKind::SnsScorecard(sns::ScorecardOptions {
                input,
                output_json,
                output_markdown,
                output_handoff_json,
                output_handoff_markdown,
                handoff_dir,
            }))
        }
        "sns-annex" => {
            let mut suffix: Option<String> = None;
            let mut cycle: Option<String> = None;
            let mut dashboard: Option<PathBuf> = None;
            let mut output: Option<PathBuf> = None;
            let mut dashboard_label: Option<String> = None;
            let mut dashboard_artifact: Option<PathBuf> = None;
            let mut regulatory_entry: Option<PathBuf> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--suffix" => {
                        let Some(value) = pending.next() else {
                            return Err("expected suffix after --suffix (e.g., .sora)".into());
                        };
                        suffix = Some(value);
                    }
                    "--cycle" => {
                        let Some(value) = pending.next() else {
                            return Err("expected cycle after --cycle (YYYY-MM)".into());
                        };
                        cycle = Some(value);
                    }
                    "--dashboard" | "--dashboard-json" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --dashboard".into());
                        };
                        dashboard = Some(normalize_path(Path::new(&path))?);
                    }
                    "--output" | "--output-markdown" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--dashboard-label" | "--dashboard-path-label" => {
                        let Some(value) = pending.next() else {
                            return Err("expected string after --dashboard-label".into());
                        };
                        dashboard_label = Some(value);
                    }
                    "--dashboard-artifact"
                    | "--dashboard-artifact-path"
                    | "--dashboard-copy-to" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --dashboard-artifact".into());
                        };
                        dashboard_artifact = Some(normalize_path(Path::new(&path))?);
                    }
                    "--regulatory-entry" | "--regulatory-memo" => {
                        let Some(path) = pending.next() else {
                            return Err(
                                "expected path after --regulatory-entry (regulatory memo)".into()
                            );
                        };
                        regulatory_entry = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for sns-annex: {flag}").into());
                    }
                }
            }
            let suffix = suffix.ok_or("sns-annex requires --suffix <.suffix>")?;
            let cycle = cycle.ok_or("sns-annex requires --cycle <YYYY-MM>")?;
            let dashboard_path =
                dashboard.ok_or("sns-annex requires --dashboard <path to grafana export>")?;
            let output_markdown = output.unwrap_or_else(|| {
                let mut candidate = workspace_root();
                candidate.push("specs/sns/reports");
                candidate.push(&suffix);
                candidate.push(format!("{cycle}.md"));
                candidate
            });
            Ok(CommandKind::SnsAnnex(sns::AnnexOptions {
                suffix,
                cycle,
                dashboard_path,
                output_markdown,
                dashboard_label,
                dashboard_artifact,
                regulatory_entry,
            }))
        }
        "codec" => {
            let Some(subcmd) = args.next() else {
                return Err("missing codec subcommand".into());
            };
            match subcmd.as_str() {
                "rans-tables" => {
                    let mut options = codec::RansTablesOptions::default();
                    let mut pending = args.peekable();
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--seed" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --seed".into());
                                };
                                options.seed = parse_seed(&value)?;
                            }
                            "--bundle-width" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --bundle-width".into());
                                };
                                let width = value.parse::<u8>().map_err(|_| {
                                    format!("invalid bundle width `{value}` (expected integer)")
                                })?;
                                if !(codec::MIN_BUNDLE_WIDTH..=codec::MAX_BUNDLE_WIDTH)
                                    .contains(&width)
                                {
                                    return Err(format!(
                                        "bundle width must be within {}..={}",
                                        codec::MIN_BUNDLE_WIDTH,
                                        codec::MAX_BUNDLE_WIDTH
                                    )
                                    .into());
                                }
                                options.bundle_width = width;
                            }
                            "-o" | "--out" | "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --output".into());
                                };
                                options.output_base = normalize_path(Path::new(&path))?;
                            }
                            "--format" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --format".into());
                                };
                                options.add_format(&value)?;
                            }
                            "--signing-key" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --signing-key".into());
                                };
                                options.signing_key = Some(normalize_path(Path::new(&path))?);
                            }
                            "--verify" => {
                                let mut path = None;
                                if let Some(next) = pending.peek()
                                    && !next.starts_with('-')
                                {
                                    let value = pending.next().expect("peeked value");
                                    path = Some(normalize_path(Path::new(&value))?);
                                }
                                options.verify_paths.push(path.unwrap_or_else(|| {
                                    options.default_output_path(codec::OutputFormat::Json)
                                }));
                            }
                            flag => {
                                return Err(
                                    format!("unknown flag for codec rans-tables: {flag}").into()
                                );
                            }
                        }
                    }
                    options.finalize_formats();
                    Ok(CommandKind::CodecRansTables { options })
                }
                other => Err(format!("unknown codec subcommand: {other}").into()),
            }
        }
        "verify-tables" => {
            let mut paths: Vec<PathBuf> = Vec::new();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--tables" | "--table" | "-t" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --tables".into());
                        };
                        paths.push(normalize_path(Path::new(&path))?);
                    }
                    flag if flag.starts_with('-') => {
                        return Err(format!("unknown flag for verify-tables: {flag}").into());
                    }
                    value => {
                        paths.push(normalize_path(Path::new(value))?);
                    }
                }
            }
            if paths.is_empty() {
                paths.push(normalize_path(Path::new(
                    "codec/rans/tables/rans_seed0.toml",
                ))?);
            }
            Ok(CommandKind::VerifyRansTables { paths })
        }
        "streaming-bundle-check" => {
            let mut config: Option<PathBuf> = None;
            let mut tables: Option<PathBuf> = None;
            let mut output: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--config" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --config".into());
                        };
                        config = Some(normalize_path(Path::new(&path))?);
                    }
                    "--tables" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --tables".into());
                        };
                        tables = Some(normalize_path(Path::new(&path))?);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            output = Some(JsonTarget::Stdout);
                        } else {
                            output = Some(JsonTarget::File(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for streaming-bundle-check: {flag}").into()
                        );
                    }
                }
            }
            let config = config
                .ok_or_else(|| "streaming-bundle-check requires --config <path>".to_string())?;
            Ok(CommandKind::StreamingBundleCheck {
                options: StreamingBundleCheckOptions {
                    config_path: config,
                    tables_override: tables,
                    output: output.unwrap_or(JsonTarget::Stdout),
                },
            })
        }
        "streaming-entropy-bench" => {
            let mut options = streaming_bench::EntropyBenchOptions::default();
            let mut output = JsonTarget::File(normalize_path(Path::new(
                "artifacts/nsc/entropy_bench.json",
            ))?);
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--frames" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --frames".into());
                        };
                        options.frames_per_segment = value
                            .parse::<u16>()
                            .map_err(|_| "--frames must be a positive integer".to_string())?;
                    }
                    "--segments" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --segments".into());
                        };
                        options.segments = value
                            .parse::<u16>()
                            .map_err(|_| "--segments must be a positive integer".to_string())?;
                    }
                    "--width" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --width".into());
                        };
                        options.bundle_width = value
                            .parse::<u8>()
                            .map_err(|_| "--width must be between 1 and 255".to_string())?;
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            output = JsonTarget::Stdout;
                        } else {
                            output = JsonTarget::File(normalize_path(Path::new(&path))?);
                        }
                    }
                    "--y4m-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --y4m-out".into());
                        };
                        options.y4m_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--y4m-in" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --y4m-in".into());
                        };
                        options.y4m_in = Some(normalize_path(Path::new(&path))?);
                    }
                    "--chunk-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --chunk-out".into());
                        };
                        options.chunk_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--quantizer" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --quantizer".into());
                        };
                        let quantizer = value
                            .parse::<u8>()
                            .map_err(|_| "--quantizer must be between 1 and 255".to_string())?;
                        if quantizer == 0 {
                            return Err("--quantizer must be at least 1".into());
                        }
                        options.quantizers.push(quantizer);
                    }
                    "--target-bitrate-mbps" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --target-bitrate-mbps".into());
                        };
                        let target = value
                            .parse::<f64>()
                            .map_err(|_| "--target-bitrate-mbps must be positive".to_string())?;
                        if !(target.is_finite() && target > 0.0) {
                            return Err("--target-bitrate-mbps must be positive".into());
                        }
                        options.target_bitrates_mbps.push(target);
                    }
                    "--psnr-mode" => {
                        let Some(mode) = pending.next() else {
                            return Err("expected value after --psnr-mode".into());
                        };
                        options.psnr_mode = match mode.as_str() {
                            "y" => streaming_bench::PsnrMode::Luma,
                            "yuv" => streaming_bench::PsnrMode::Yuv,
                            _ => {
                                return Err(format!(
                                    "invalid psnr-mode '{mode}', expected one of: y, yuv"
                                )
                                .into());
                            }
                        };
                    }
                    "--tiny-clip-preset" => {
                        options.tiny_clip_preset = true;
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for streaming-entropy-bench: {flag}").into()
                        );
                    }
                }
            }
            Ok(CommandKind::StreamingEntropyBench { options, output })
        }
        "streaming-decode" => {
            let mut options = streaming_bench::DecodeOptions {
                bundle_path: PathBuf::new(),
                y4m_out: PathBuf::new(),
                reference_y4m: None,
                psnr_mode: streaming_bench::PsnrMode::Luma,
            };
            let mut output: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" | "--bundle" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --bundle".into());
                        };
                        options.bundle_path = normalize_path(Path::new(&path))?;
                    }
                    "--y4m-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --y4m-out".into());
                        };
                        options.y4m_out = normalize_path(Path::new(&path))?;
                    }
                    "--psnr-ref" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --psnr-ref".into());
                        };
                        options.reference_y4m = Some(normalize_path(Path::new(&path))?);
                    }
                    "--psnr-mode" => {
                        let Some(mode) = pending.next() else {
                            return Err("expected value after --psnr-mode".into());
                        };
                        options.psnr_mode = match mode.as_str() {
                            "y" => streaming_bench::PsnrMode::Luma,
                            "yuv" => streaming_bench::PsnrMode::Yuv,
                            _ => {
                                return Err(format!(
                                    "invalid psnr-mode '{mode}', expected one of: y, yuv"
                                )
                                .into());
                            }
                        };
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        output = if path == "-" {
                            Some(JsonTarget::Stdout)
                        } else {
                            Some(JsonTarget::File(normalize_path(Path::new(&path))?))
                        };
                    }
                    flag => return Err(format!("unknown flag for streaming-decode: {flag}").into()),
                }
            }
            if options.bundle_path.as_os_str().is_empty() {
                return Err("streaming-decode requires --bundle <path>".into());
            }
            if options.y4m_out.as_os_str().is_empty() {
                return Err("streaming-decode requires --y4m-out <path>".into());
            }
            Ok(CommandKind::StreamingDecode { options, output })
        }
        "stage1-bench" => {
            let mut sizes: Vec<usize> = vec![4 * 1024, 16 * 1024, 64 * 1024, 128 * 1024];
            let mut iterations: u32 = 5;
            let mut json_out = normalize_path(Path::new("benchmarks/norito_stage1/latest.json"))?;
            let mut markdown_out = Some(normalize_path(Path::new(
                "benchmarks/norito_stage1/latest.md",
            ))?);
            let mut allow_overwrite = false;
            fn parse_size_bytes(raw: &str) -> Result<usize, String> {
                let raw = raw.trim();
                if let Some(stripped) = raw.strip_suffix('k').or_else(|| raw.strip_suffix('K')) {
                    return stripped
                        .parse::<usize>()
                        .map(|n| n * 1024)
                        .map_err(|_| format!("invalid size `{raw}`"));
                }
                if let Some(stripped) = raw.strip_suffix('m').or_else(|| raw.strip_suffix('M')) {
                    return stripped
                        .parse::<usize>()
                        .map(|n| n * 1024 * 1024)
                        .map_err(|_| format!("invalid size `{raw}`"));
                }
                raw.parse::<usize>()
                    .map_err(|_| format!("invalid size `{raw}`"))
            }
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--size" | "--bytes" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --size".into());
                        };
                        let size = parse_size_bytes(&value)?;
                        sizes.push(size);
                    }
                    "--iterations" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --iterations".into());
                        };
                        iterations = value
                            .parse::<u32>()
                            .map_err(|_| "--iterations must be a positive integer".to_string())?;
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = normalize_path(Path::new(&path))?;
                    }
                    "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        markdown_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--no-markdown" => {
                        markdown_out = None;
                    }
                    "--allow-overwrite" => {
                        allow_overwrite = true;
                    }
                    flag => {
                        return Err(format!("unknown flag for stage1-bench: {flag}").into());
                    }
                }
            }
            sizes.sort_unstable();
            sizes.dedup();
            Ok(CommandKind::Stage1Bench {
                options: stage1_bench::Stage1BenchOptions {
                    sizes,
                    iterations,
                    json_out,
                    markdown_out,
                    allow_overwrite,
                },
            })
        }
        "i3-bench-suite" => {
            let mut iterations: u32 = 64;
            let mut sample_size: u32 = 5;
            let mut json_out = normalize_path(Path::new("benchmarks/i3/latest.json"))?;
            let mut csv_out = Some(normalize_path(Path::new("benchmarks/i3/latest.csv"))?);
            let mut markdown_out = Some(normalize_path(Path::new("benchmarks/i3/latest.md"))?);
            let mut threshold = Some(normalize_path(Path::new("benchmarks/i3/thresholds.json"))?);
            let mut allow_overwrite = false;
            let mut flamegraph_hint = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--iterations" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --iterations".into());
                        };
                        iterations = value
                            .parse::<u32>()
                            .map_err(|_| "--iterations must be a positive integer".to_string())?;
                    }
                    "--sample-count" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --sample-count".into());
                        };
                        sample_size = value
                            .parse::<u32>()
                            .map_err(|_| "--sample-count must be a positive integer".to_string())?;
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = normalize_path(Path::new(&path))?;
                    }
                    "--csv-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --csv-out".into());
                        };
                        csv_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--no-csv" => {
                        csv_out = None;
                    }
                    "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        markdown_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--no-markdown" => {
                        markdown_out = None;
                    }
                    "--threshold" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --threshold".into());
                        };
                        threshold = Some(normalize_path(Path::new(&path))?);
                    }
                    "--no-threshold" => {
                        threshold = None;
                    }
                    "--allow-overwrite" => {
                        allow_overwrite = true;
                    }
                    "--flamegraph-hint" => {
                        flamegraph_hint = true;
                    }
                    flag => {
                        return Err(format!("unknown flag for i3-bench-suite: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::I3BenchSuite {
                options: i3_bench_suite::I3BenchOptions {
                    iterations,
                    sample_size,
                    json_out,
                    csv_out,
                    markdown_out,
                    allow_overwrite,
                    threshold,
                    flamegraph_hint,
                },
            })
        }
        "i3-slo-harness" => {
            let mut iterations: u32 = 64;
            let mut sample_size: u32 = 5;
            let mut out_dir = normalize_path(Path::new("artifacts/i3_slo/latest"))?;
            let mut budgets = normalize_path(Path::new("benchmarks/i3/slo_budgets.json"))?;
            let mut threshold = normalize_path(Path::new("benchmarks/i3/slo_thresholds.json"))?;
            let mut allow_overwrite = false;
            let mut flamegraph_hint = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--iterations" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --iterations".into());
                        };
                        iterations = value
                            .parse::<u32>()
                            .map_err(|_| "--iterations must be a positive integer".to_string())?;
                    }
                    "--sample-count" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --sample-count".into());
                        };
                        sample_size = value
                            .parse::<u32>()
                            .map_err(|_| "--sample-count must be a positive integer".to_string())?;
                    }
                    "--out-dir" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --out-dir".into());
                        };
                        out_dir = normalize_path(Path::new(&path))?;
                    }
                    "--budget" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --budget".into());
                        };
                        budgets = normalize_path(Path::new(&path))?;
                    }
                    "--threshold" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --threshold".into());
                        };
                        threshold = normalize_path(Path::new(&path))?;
                    }
                    "--allow-overwrite" => {
                        allow_overwrite = true;
                    }
                    "--flamegraph-hint" => {
                        flamegraph_hint = true;
                    }
                    flag => {
                        return Err(format!("unknown flag for i3-slo-harness: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::I3SloHarness {
                options: i3_slo_harness::SloHarnessOptions {
                    iterations,
                    sample_size,
                    out_dir,
                    budgets,
                    threshold,
                    allow_overwrite,
                    flamegraph_hint,
                },
            })
        }
        "poseidon-cuda-bench" => {
            let mut batch_size: usize = 1024;
            let mut iterations: u32 = 32;
            let mut json_out =
                normalize_path(Path::new("benchmarks/poseidon/poseidon_cuda_latest.json"))?;
            let mut markdown_out = Some(normalize_path(Path::new(
                "benchmarks/poseidon/poseidon_cuda_latest.md",
            ))?);
            let mut allow_overwrite = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--batch-size" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --batch-size".into());
                        };
                        batch_size = value
                            .parse::<usize>()
                            .map_err(|_| "--batch-size must be a positive integer".to_string())?;
                    }
                    "--iterations" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --iterations".into());
                        };
                        iterations = value
                            .parse::<u32>()
                            .map_err(|_| "--iterations must be a positive integer".to_string())?;
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = normalize_path(Path::new(&path))?;
                    }
                    "--markdown-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --markdown-out".into());
                        };
                        markdown_out = Some(normalize_path(Path::new(&path))?);
                    }
                    "--no-markdown" => {
                        markdown_out = None;
                    }
                    "--allow-overwrite" => {
                        allow_overwrite = true;
                    }
                    flag => {
                        return Err(format!("unknown flag for poseidon-cuda-bench: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::PoseidonBench {
                options: poseidon_bench::PoseidonBenchOptions {
                    batch_size,
                    iterations,
                    json_out,
                    markdown_out,
                    allow_overwrite,
                },
            })
        }
        "streaming-context-remap" => {
            let mut input: Option<PathBuf> = None;
            let mut top = 32usize;
            let mut output = JsonTarget::Stdout;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        input = Some(normalize_path(Path::new(&path))?);
                    }
                    "--top" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --top".into());
                        };
                        top = value
                            .parse::<usize>()
                            .map_err(|_| "--top must be a positive integer".to_string())?;
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        output = if path == "-" {
                            JsonTarget::Stdout
                        } else {
                            JsonTarget::File(normalize_path(Path::new(&path))?)
                        };
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for streaming-context-remap: {flag}").into()
                        );
                    }
                }
            }
            let input = input
                .ok_or_else(|| "streaming-context-remap requires --input <path>".to_string())?;
            Ok(CommandKind::StreamingContextRemap {
                options: StreamingContextRemapOptions { input, top, output },
            })
        }
        "norito-rpc-fixtures" => {
            let mut output_root: Option<PathBuf> = None;
            let mut local_integration = false;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--local-integration" if !local_integration => local_integration = true,
                    "--local-integration" => {
                        return Err("--local-integration was supplied more than once".into());
                    }
                    "--output-root" if output_root.is_none() => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output-root".into());
                        };
                        output_root = Some(normalize_norito_rpc_output_root(&path)?);
                    }
                    "--output-root" => {
                        return Err("--output-root was supplied more than once".into());
                    }
                    flag => {
                        return Err(format!("unknown flag for norito-rpc-fixtures: {flag}").into());
                    }
                }
            }
            let output_root = output_root.ok_or(
                "norito-rpc-fixtures requires --output-root <absent-absolute-external-directory>",
            )?;
            Ok(CommandKind::NoritoRpcFixtures {
                options: if local_integration {
                    NoritoRpcFixtureOptions::local_integration(output_root)
                } else {
                    NoritoRpcFixtureOptions::new(Some(output_root))
                },
            })
        }
        "norito-rpc-verify" => {
            let mut json_out: Option<JsonTarget> = None;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--json-out" if json_out.is_none() => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        json_out = Some(if path == "-" {
                            JsonTarget::Stdout
                        } else {
                            if path.is_empty() || path.starts_with('-') {
                                return Err(
                                    "--json-out requires a non-empty file path or `-`".into()
                                );
                            }
                            JsonTarget::File(normalize_path(Path::new(&path))?)
                        });
                    }
                    "--json-out" => {
                        return Err("--json-out was supplied more than once".into());
                    }
                    flag => {
                        return Err(format!("unknown flag for norito-rpc-verify: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::NoritoRpcVerify { json_out })
        }
        "sm-wycheproof-sync" => {
            let mut input: Option<sm::WycheproofInput> = None;
            let mut output: Option<PathBuf> = None;
            let mut generator_version: Option<String> = None;
            let mut pretty = true;
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--input" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --input".into());
                        };
                        if input.is_some() {
                            return Err(
                                "sm-wycheproof-sync accepts only one of --input/--input-url/--input-official"
                                    .into(),
                            );
                        }
                        input = Some(sm::WycheproofInput::File(normalize_path(Path::new(&path))?));
                    }
                    "--input-url" => {
                        let Some(url) = pending.next() else {
                            return Err("expected URL after --input-url".into());
                        };
                        if input.is_some() {
                            return Err(
                                "sm-wycheproof-sync accepts only one of --input/--input-url/--input-official"
                                    .into(),
                            );
                        }
                        input = Some(sm::WycheproofInput::Url(url));
                    }
                    "--input-official" => {
                        if input.is_some() {
                            return Err(
                                "sm-wycheproof-sync accepts only one of --input/--input-url/--input-official"
                                    .into(),
                            );
                        }
                        input = Some(sm::WycheproofInput::Official);
                    }
                    "--output" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --output".into());
                        };
                        output = Some(normalize_path(Path::new(&path))?);
                    }
                    "--generator-version" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --generator-version".into());
                        };
                        generator_version = Some(value);
                    }
                    "--minify" => pretty = false,
                    "--pretty" => pretty = true,
                    flag => {
                        return Err(format!("unknown flag for sm-wycheproof-sync: {flag}").into());
                    }
                }
            }
            let Some(input) = input else {
                return Err(
                    "sm-wycheproof-sync requires one of --input <path>, --input-url <url>, or --input-official"
                        .into(),
                );
            };
            let output = output.unwrap_or_else(default_sm_wycheproof_path);
            Ok(CommandKind::SmWycheproofSync(sm::WycheproofSyncOptions {
                input,
                output,
                generator_version,
                pretty,
            }))
        }
        "sm-operator-snippet" => {
            let mut options = sm::SmOperatorSnippetOptions::default();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--distid" => {
                        let Some(value) = pending.next() else {
                            return Err("expected value after --distid".into());
                        };
                        options.distid = Some(value);
                    }
                    "--seed-hex" => {
                        let Some(value) = pending.next() else {
                            return Err("expected hex string after --seed-hex".into());
                        };
                        options.seed_hex = Some(value);
                    }
                    "--json-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --json-out".into());
                        };
                        if path == "-" {
                            options.json_out = Some(sm::OutputTarget::Stdout);
                        } else {
                            options.json_out =
                                Some(sm::OutputTarget::file(normalize_path(Path::new(&path))?));
                        }
                    }
                    "--snippet-out" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --snippet-out".into());
                        };
                        if path == "-" {
                            options.snippet_out = Some(sm::OutputTarget::Stdout);
                        } else {
                            options.snippet_out =
                                Some(sm::OutputTarget::file(normalize_path(Path::new(&path))?));
                        }
                    }
                    flag => {
                        return Err(format!("unknown flag for sm-operator-snippet: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::SmOperatorSnippet { options })
        }
        "iso-bridge-lint" => {
            let mut options = IsoLintOptions::default();
            let mut pending = args.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--isin" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --isin".into());
                        };
                        options.isin_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--bic-lei" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --bic-lei".into());
                        };
                        options.bic_lei_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--mic" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --mic".into());
                        };
                        options.mic_path = Some(normalize_path(Path::new(&path))?);
                    }
                    "--fixtures" => {
                        let Some(path) = pending.next() else {
                            return Err("expected path after --fixtures".into());
                        };
                        options.fixtures_path = Some(normalize_path(Path::new(&path))?);
                    }
                    flag => {
                        return Err(format!("unknown flag for iso-bridge-lint: {flag}").into());
                    }
                }
            }
            Ok(CommandKind::IsoBridgeLint { options })
        }
        "ministry-transparency" => {
            let mut pending = args.peekable();
            let Some(subcommand) = pending.next() else {
                return Err(
                    "ministry-transparency requires a subcommand (ingest|build|sanitize|anchor|volunteer-validate)"
                        .into(),
                );
            };
            match subcommand.as_str() {
                "ingest" => {
                    let mut quarter = None;
                    let mut ledger = None;
                    let mut appeals = None;
                    let mut denylist = None;
                    let mut treasury = None;
                    let mut volunteer = None;
                    let mut red_team_reports = Vec::new();
                    let mut panel_proposal = None;
                    let mut panel_ai_manifest = None;
                    let mut panel_round = None;
                    let mut panel_summary_out = None;
                    let mut panel_language = None;
                    let mut panel_generated_at = None;
                    let mut output = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--quarter" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --quarter".into());
                                };
                                quarter = Some(value);
                            }
                            "--ledger" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --ledger".into());
                                };
                                ledger = Some(normalize_path(Path::new(&path))?);
                            }
                            "--appeals" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --appeals".into());
                                };
                                appeals = Some(normalize_path(Path::new(&path))?);
                            }
                            "--denylist" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --denylist".into());
                                };
                                denylist = Some(normalize_path(Path::new(&path))?);
                            }
                            "--treasury" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --treasury".into());
                                };
                                treasury = Some(normalize_path(Path::new(&path))?);
                            }
                            "--volunteer" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --volunteer".into());
                                };
                                volunteer = Some(normalize_path(Path::new(&path))?);
                            }
                            "--red-team-report" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --red-team-report".into());
                                };
                                red_team_reports.push(normalize_path(Path::new(&path))?);
                            }
                            "--panel-proposal" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --panel-proposal".into());
                                };
                                panel_proposal = Some(normalize_path(Path::new(&path))?);
                            }
                            "--panel-ai-manifest" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --panel-ai-manifest".into());
                                };
                                panel_ai_manifest = Some(normalize_path(Path::new(&path))?);
                            }
                            "--panel-round" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --panel-round".into());
                                };
                                panel_round = Some(value);
                            }
                            "--panel-summary-out" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --panel-summary-out".into());
                                };
                                panel_summary_out = Some(normalize_path(Path::new(&path))?);
                            }
                            "--panel-language" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --panel-language".into());
                                };
                                panel_language = Some(value);
                            }
                            "--panel-generated-at" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --panel-generated-at".into());
                                };
                                let millis: u64 = value.parse().map_err(|err| {
                                    format!("invalid --panel-generated-at value `{value}`: {err}")
                                })?;
                                panel_generated_at = Some(millis);
                            }
                            "-o" | "--out" | "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --output".into());
                                };
                                output = Some(normalize_path(Path::new(&path))?);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-transparency ingest: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let quarter = quarter
                        .ok_or("ministry-transparency ingest requires --quarter <YYYY-Q>")?;
                    let ledger =
                        ledger.ok_or("ministry-transparency ingest requires --ledger <path>")?;
                    let appeals =
                        appeals.ok_or("ministry-transparency ingest requires --appeals <path>")?;
                    let denylist = denylist
                        .ok_or("ministry-transparency ingest requires --denylist <path>")?;
                    let treasury = treasury
                        .ok_or("ministry-transparency ingest requires --treasury <path>")?;
                    let output =
                        output.ok_or("ministry-transparency ingest requires --output <path>")?;
                    let panel_summary = match (
                        panel_proposal,
                        panel_ai_manifest,
                        panel_round,
                        panel_summary_out,
                    ) {
                        (None, None, None, None) => None,
                        (Some(proposal), Some(ai_manifest), Some(round), Some(summary_out)) => {
                            let volunteer_path = volunteer.clone().ok_or(
                                "ministry-transparency ingest --panel-* flags require --volunteer <path>",
                            )?;
                            Some(ministry::PanelSummaryRequest {
                                proposal_path: proposal,
                                volunteer_path,
                                ai_manifest_path: ai_manifest,
                                panel_round_id: round,
                                output_path: summary_out,
                                language_override: panel_language,
                                generated_at_unix_ms: panel_generated_at,
                            })
                        }
                        _ => {
                            return Err("ministry-transparency ingest requires all of --panel-proposal/--panel-ai-manifest/--panel-round/--panel-summary-out when any are supplied".into());
                        }
                    };
                    Ok(CommandKind::MinistryTransparency(
                        ministry::Command::Ingest(Box::new(ministry::IngestOptions {
                            quarter,
                            ledger_path: ledger,
                            appeals_path: appeals,
                            denylist_path: denylist,
                            treasury_path: treasury,
                            volunteer_path: volunteer,
                            red_team_reports,
                            panel_summary,
                            output_path: output,
                        })),
                    ))
                }
                "build" => {
                    let mut ingest = None;
                    let mut metrics_out = None;
                    let mut manifest_out = None;
                    let mut note = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--ingest" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --ingest".into());
                                };
                                ingest = Some(normalize_path(Path::new(&path))?);
                            }
                            "--metrics-out" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --metrics-out".into());
                                };
                                metrics_out = Some(normalize_path(Path::new(&path))?);
                            }
                            "--manifest-out" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --manifest-out".into());
                                };
                                manifest_out = Some(normalize_path(Path::new(&path))?);
                            }
                            "--note" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --note".into());
                                };
                                note = Some(value);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-transparency build: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let ingest =
                        ingest.ok_or("ministry-transparency build requires --ingest <path>")?;
                    let metrics_out = metrics_out
                        .ok_or("ministry-transparency build requires --metrics-out <path>")?;
                    let manifest_out = manifest_out
                        .ok_or("ministry-transparency build requires --manifest-out <path>")?;
                    Ok(CommandKind::MinistryTransparency(ministry::Command::Build(
                        Box::new(ministry::BuildOptions {
                            ingest_path: ingest,
                            metrics_output: metrics_out,
                            manifest_output: manifest_out,
                            note,
                        }),
                    )))
                }
                "sanitize" => {
                    let mut ingest = None;
                    let mut output = None;
                    let mut report = None;
                    let mut epsilon_counts = 0.75;
                    let mut epsilon_accuracy = 0.5;
                    let mut delta = 1e-6;
                    let mut suppress_threshold = 5;
                    let mut min_accuracy_samples = 100;
                    let mut seed = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--ingest" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --ingest".into());
                                };
                                ingest = Some(normalize_path(Path::new(&path))?);
                            }
                            "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --output".into());
                                };
                                output = Some(normalize_path(Path::new(&path))?);
                            }
                            "--report" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --report".into());
                                };
                                report = Some(normalize_path(Path::new(&path))?);
                            }
                            "--epsilon-counts" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --epsilon-counts".into());
                                };
                                epsilon_counts = value.parse()?;
                            }
                            "--epsilon-accuracy" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --epsilon-accuracy".into());
                                };
                                epsilon_accuracy = value.parse()?;
                            }
                            "--delta" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --delta".into());
                                };
                                delta = value.parse()?;
                            }
                            "--suppress-threshold" => {
                                let Some(value) = pending.next() else {
                                    return Err(
                                        "expected value after --suppress-threshold".into()
                                    );
                                };
                                suppress_threshold = value.parse()?;
                            }
                            "--min-accuracy-samples" => {
                                let Some(value) = pending.next() else {
                                    return Err(
                                        "expected value after --min-accuracy-samples".into()
                                    );
                                };
                                min_accuracy_samples = value.parse()?;
                            }
                            "--seed" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --seed".into());
                                };
                                seed = Some(value.parse()?);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-transparency sanitize: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let ingest =
                        ingest.ok_or("ministry-transparency sanitize requires --ingest <path>")?;
                    let output =
                        output.ok_or("ministry-transparency sanitize requires --output <path>")?;
                    let report =
                        report.ok_or("ministry-transparency sanitize requires --report <path>")?;
                    Ok(CommandKind::MinistryTransparency(
                        ministry::Command::Sanitize(Box::new(ministry::SanitizeOptions {
                            ingest_path: ingest,
                            output_path: output,
                            report_path: report,
                            epsilon_counts,
                            epsilon_accuracy,
                            delta,
                            suppress_threshold,
                            min_accuracy_samples,
                            seed,
                        })),
                    ))
                }
                "anchor" => {
                    let mut action = None;
                    let mut governance_dir = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--action" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --action".into());
                                };
                                action = Some(normalize_path(Path::new(&path))?);
                            }
                            "--governance-dir" => {
                                let Some(path) = pending.next() else {
                                    return Err(
                                        "expected path after --governance-dir".into()
                                    );
                                };
                                governance_dir = Some(normalize_path(Path::new(&path))?);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-transparency anchor: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let action_path =
                        action.ok_or("ministry-transparency anchor requires --action <path>")?;
                    let governance_dir = governance_dir.ok_or(
                        "ministry-transparency anchor requires --governance-dir <path>",
                    )?;
                    Ok(CommandKind::MinistryTransparency(ministry::Command::Anchor(
                        Box::new(ministry::AnchorOptions {
                            action_path,
                            governance_dir,
                        }),
                    )))
                }
                "volunteer-validate" => {
                    let mut inputs: Vec<PathBuf> = Vec::new();
                    let mut json_output = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--input" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --input".into());
                                };
                                inputs.push(normalize_path(Path::new(&path))?);
                            }
                            "--json-output" => {
                                let Some(path) = pending.next() else {
                                    return Err(
                                        "expected path after --json-output".into()
                                    );
                                };
                                json_output = Some(normalize_path(Path::new(&path))?);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-transparency volunteer-validate: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    Ok(CommandKind::MinistryTransparency(
                        ministry::Command::VolunteerValidate(Box::new(
                            ministry::VolunteerValidateOptions {
                                inputs,
                                json_output,
                            },
                        )),
                    ))
                }
                other => Err(format!(
                    "unknown ministry-transparency subcommand `{other}` (expected ingest|build|sanitize|anchor|volunteer-validate)"
                )
                .into()),
            }
        }
        "ministry-agenda" => {
            let mut pending = args.peekable();
            let Some(subcommand) = pending.next() else {
                return Err(
                    "ministry-agenda requires a subcommand (validate|sortition|impact)".into(),
                );
            };
            match subcommand.as_str() {
                "validate" => {
                    let mut proposal = None;
                    let mut registry = None;
                    let mut allow_conflicts = false;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--proposal" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --proposal".into());
                                };
                                proposal = Some(normalize_path(Path::new(&path))?);
                            }
                            "--registry" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --registry".into());
                                };
                                registry = Some(normalize_path(Path::new(&path))?);
                            }
                            "--allow-registry-conflicts" => allow_conflicts = true,
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-agenda validate: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let proposal =
                        proposal.ok_or("ministry-agenda validate requires --proposal <path>")?;
                    Ok(CommandKind::MinistryAgenda(
                        ministry_agenda::Command::Validate(ministry_agenda::ValidateOptions {
                            proposal_path: proposal,
                            registry_path: registry,
                            allow_registry_conflicts: allow_conflicts,
                        }),
                    ))
                }
                "sortition" => {
                    let mut roster = None;
                    let mut slots = None;
                    let mut seed = None;
                    let mut output = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--roster" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --roster".into());
                                };
                                roster = Some(normalize_path(Path::new(&path))?);
                            }
                            "--slots" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --slots".into());
                                };
                                let parsed: usize = value.parse().map_err(|err| {
                                    format!("invalid --slots value `{value}`: {err}")
                                })?;
                                slots = Some(parsed);
                            }
                            "--seed" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --seed".into());
                                };
                                seed = Some(value);
                            }
                            "-o" | "--out" | "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --out/--output".into());
                                };
                                output = Some(normalize_path(Path::new(&path))?);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-agenda sortition: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let roster_path =
                        roster.ok_or("ministry-agenda sortition requires --roster <path>")?;
                    let slots =
                        slots.ok_or("ministry-agenda sortition requires --slots <count>")?;
                    let seed_hex = seed.ok_or("ministry-agenda sortition requires --seed <hex>")?;
                    Ok(CommandKind::MinistryAgenda(
                        ministry_agenda::Command::Sortition(ministry_agenda::SortitionOptions {
                            roster_path,
                            slots,
                            seed_hex,
                            output_path: output,
                        }),
                    ))
                }
                "impact" => {
                    let mut options = ministry_agenda::ImpactOptions::default();
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--proposal" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --proposal".into());
                                };
                                options
                                    .proposal_paths
                                    .push(normalize_path(Path::new(&path))?);
                            }
                            "--proposal-dir" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --proposal-dir".into());
                                };
                                options
                                    .proposal_dirs
                                    .push(normalize_path(Path::new(&path))?);
                            }
                            "--registry" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --registry".into());
                                };
                                options.registry_path = Some(normalize_path(Path::new(&path))?);
                            }
                            "--policy-snapshot" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --policy-snapshot".into());
                                };
                                options.policy_snapshot_path =
                                    Some(normalize_path(Path::new(&path))?);
                            }
                            "-o" | "--out" | "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --out/--output".into());
                                };
                                options.output_path = Some(normalize_path(Path::new(&path))?);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-agenda impact: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    if options.proposal_paths.is_empty() && options.proposal_dirs.is_empty() {
                        return Err(
                            "ministry-agenda impact requires at least one --proposal <path> or --proposal-dir <dir>"
                                .into(),
                        );
                    }
                    Ok(CommandKind::MinistryAgenda(
                        ministry_agenda::Command::impact(options),
                    ))
                }
                other => Err(format!(
                    "unknown ministry-agenda subcommand `{other}` (expected validate|sortition|impact)"
                )
                .into()),
            }
        }
        "ministry-panel" => {
            let mut pending = args.peekable();
            let Some(subcommand) = pending.next() else {
                return Err("ministry-panel requires a subcommand (synthesize|packet)".into());
            };
            match subcommand.as_str() {
                "synthesize" => {
                    let mut proposal = None;
                    let mut volunteer = None;
                    let mut ai_manifest = None;
                    let mut output = None;
                    let mut panel_round = None;
                    let mut language = None;
                    let mut generated_at = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--proposal" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --proposal".into());
                                };
                                proposal = Some(normalize_path(Path::new(&path))?);
                            }
                            "--volunteer" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --volunteer".into());
                                };
                                volunteer = Some(normalize_path(Path::new(&path))?);
                            }
                            "--ai-manifest" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --ai-manifest".into());
                                };
                                ai_manifest = Some(normalize_path(Path::new(&path))?);
                            }
                            "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --output".into());
                                };
                                let resolved = if path == "-" {
                                    PathBuf::from("-")
                                } else {
                                    normalize_path(Path::new(&path))?
                                };
                                output = Some(resolved);
                            }
                            "--panel-round" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --panel-round".into());
                                };
                                panel_round = Some(value);
                            }
                            "--language" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --language".into());
                                };
                                language = Some(value);
                            }
                            "--generated-at" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --generated-at".into());
                                };
                                let millis = value.parse::<u64>().map_err(|err| {
                                    format!("invalid --generated-at value `{value}`: {err}")
                                })?;
                                generated_at = Some(millis);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-panel synthesize: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let proposal_path =
                        proposal.ok_or("ministry-panel synthesize requires --proposal <path>")?;
                    let volunteer_path =
                        volunteer.ok_or("ministry-panel synthesize requires --volunteer <path>")?;
                    let ai_manifest_path = ai_manifest
                        .ok_or("ministry-panel synthesize requires --ai-manifest <path>")?;
                    let output_path =
                        output.ok_or("ministry-panel synthesize requires --output <path>")?;
                    let panel_round_id = panel_round
                        .ok_or("ministry-panel synthesize requires --panel-round <id>")?;
                    Ok(CommandKind::MinistryPanel(
                        ministry_panel::Command::Synthesize(ministry_panel::SynthesizeOptions {
                            proposal_path,
                            volunteer_path,
                            ai_manifest_path,
                            output_path,
                            panel_round_id,
                            language_override: language,
                            generated_at_unix_ms: generated_at,
                        }),
                    ))
                }
                "packet" => {
                    let mut proposal = None;
                    let mut volunteer = None;
                    let mut ai_manifest = None;
                    let mut panel_round = None;
                    let mut language = None;
                    let mut generated_at = None;
                    let mut sortition = None;
                    let mut impact = None;
                    let mut summary_out = None;
                    let mut output = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--proposal" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --proposal".into());
                                };
                                proposal = Some(normalize_path(Path::new(&path))?);
                            }
                            "--volunteer" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --volunteer".into());
                                };
                                volunteer = Some(normalize_path(Path::new(&path))?);
                            }
                            "--ai-manifest" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --ai-manifest".into());
                                };
                                ai_manifest = Some(normalize_path(Path::new(&path))?);
                            }
                            "--panel-round" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --panel-round".into());
                                };
                                panel_round = Some(value);
                            }
                            "--language" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --language".into());
                                };
                                language = Some(value);
                            }
                            "--generated-at" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --generated-at".into());
                                };
                                let millis = value.parse::<u64>().map_err(|err| {
                                    format!("invalid --generated-at value `{value}`: {err}")
                                })?;
                                generated_at = Some(millis);
                            }
                            "--sortition" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --sortition".into());
                                };
                                sortition = Some(normalize_path(Path::new(&path))?);
                            }
                            "--impact" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --impact".into());
                                };
                                impact = Some(normalize_path(Path::new(&path))?);
                            }
                            "--summary-out" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --summary-out".into());
                                };
                                let resolved = if path == "-" {
                                    PathBuf::from("-")
                                } else {
                                    normalize_path(Path::new(&path))?
                                };
                                summary_out = Some(resolved);
                            }
                            "--output" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --output".into());
                                };
                                let resolved = if path == "-" {
                                    PathBuf::from("-")
                                } else {
                                    normalize_path(Path::new(&path))?
                                };
                                output = Some(resolved);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-panel packet: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let proposal_path =
                        proposal.ok_or("ministry-panel packet requires --proposal <path>")?;
                    let volunteer_path =
                        volunteer.ok_or("ministry-panel packet requires --volunteer <path>")?;
                    let ai_manifest_path =
                        ai_manifest.ok_or("ministry-panel packet requires --ai-manifest <path>")?;
                    let panel_round_id =
                        panel_round.ok_or("ministry-panel packet requires --panel-round <id>")?;
                    let sortition_path =
                        sortition.ok_or("ministry-panel packet requires --sortition <path>")?;
                    let impact_path =
                        impact.ok_or("ministry-panel packet requires --impact <path>")?;
                    let output_path =
                        output.ok_or("ministry-panel packet requires --output <path>")?;
                    let synth = ministry_panel::SynthesizeOptions {
                        proposal_path,
                        volunteer_path,
                        ai_manifest_path,
                        output_path: PathBuf::from("-"),
                        panel_round_id,
                        language_override: language,
                        generated_at_unix_ms: generated_at,
                    };
                    Ok(CommandKind::MinistryPanel(ministry_panel::Command::Packet(
                        ministry_panel::PacketOptions {
                            synth,
                            sortition_summary_path: sortition_path,
                            impact_report_path: impact_path,
                            output_path,
                            summary_out_path: summary_out,
                        },
                    )))
                }
                other => Err(format!(
                    "unknown ministry-panel subcommand `{other}` (expected synthesize|packet)"
                )
                .into()),
            }
        }
        "ministry-jury" => {
            let mut pending = args.peekable();
            let Some(subcommand) = pending.next() else {
                return Err("ministry-jury requires a subcommand (sortition|ballot)".into());
            };
            match subcommand.as_str() {
                "sortition" => {
                    let mut roster = None;
                    let mut proposal_id = None;
                    let mut round_id = None;
                    let mut beacon = None;
                    let mut committee = None;
                    let mut waitlist = None;
                    let mut drawn_at = None;
                    let mut waitlist_ttl_hours: u32 = 72;
                    let mut grace_period_secs: u32 = 900;
                    let mut failover_grace_secs: u32 = 600;
                    let mut output = None;
                    while let Some(arg) = pending.next() {
                        match arg.as_str() {
                            "--roster" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --roster".into());
                                };
                                roster = Some(normalize_path(Path::new(&path))?);
                            }
                            "--proposal" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --proposal".into());
                                };
                                proposal_id = Some(value);
                            }
                            "--round" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --round".into());
                                };
                                round_id = Some(value);
                            }
                            "--beacon" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --beacon".into());
                                };
                                beacon = Some(value);
                            }
                            "--committee-size" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --committee-size".into());
                                };
                                let parsed = value.parse::<usize>().map_err(|err| {
                                    format!("invalid --committee-size value `{value}`: {err}")
                                })?;
                                committee = Some(parsed);
                            }
                            "--waitlist-size" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --waitlist-size".into());
                                };
                                let parsed = value.parse::<usize>().map_err(|err| {
                                    format!("invalid --waitlist-size value `{value}`: {err}")
                                })?;
                                waitlist = Some(parsed);
                            }
                            "--drawn-at" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --drawn-at".into());
                                };
                                let timestamp = ministry_jury::parse_drawn_at(&value)?;
                                drawn_at = Some(timestamp);
                            }
                            "--waitlist-ttl-hours" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --waitlist-ttl-hours".into());
                                };
                                waitlist_ttl_hours = value.parse::<u32>().map_err(|err| {
                                    format!("invalid --waitlist-ttl-hours value `{value}`: {err}")
                                })?;
                            }
                            "--grace-period" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --grace-period".into());
                                };
                                grace_period_secs = value.parse::<u32>().map_err(|err| {
                                    format!("invalid --grace-period value `{value}`: {err}")
                                })?;
                            }
                            "--failover-grace" => {
                                let Some(value) = pending.next() else {
                                    return Err("expected value after --failover-grace".into());
                                };
                                failover_grace_secs = value.parse::<u32>().map_err(|err| {
                                    format!("invalid --failover-grace value `{value}`: {err}")
                                })?;
                            }
                            "--out" => {
                                let Some(path) = pending.next() else {
                                    return Err("expected path after --out".into());
                                };
                                output = Some(normalize_path(Path::new(&path))?);
                            }
                            flag => {
                                return Err(format!(
                                    "unknown flag for ministry-jury sortition: {flag}"
                                )
                                .into());
                            }
                        }
                    }
                    let roster = roster
                        .ok_or_else(|| eyre!("ministry-jury sortition requires --roster <path>"))
                        .map_err(|err| -> Box<dyn Error> { err.into() })?;
                    let proposal_id = proposal_id
                        .ok_or_else(|| eyre!("ministry-jury sortition requires --proposal <id>"))
                        .map_err(|err| -> Box<dyn Error> { err.into() })?;
                    let round_id = round_id
                        .ok_or_else(|| eyre!("ministry-jury sortition requires --round <id>"))
                        .map_err(|err| -> Box<dyn Error> { err.into() })?;
                    let beacon = beacon
                        .ok_or_else(|| eyre!("ministry-jury sortition requires --beacon <hex>"))
                        .map_err(|err| -> Box<dyn Error> { err.into() })?;
                    let committee = committee
                        .ok_or_else(|| {
                            eyre!("ministry-jury sortition requires --committee-size <count>")
                        })
                        .map_err(|err| -> Box<dyn Error> { err.into() })?;
                    let waitlist = waitlist
                        .ok_or_else(|| {
                            eyre!("ministry-jury sortition requires --waitlist-size <count>")
                        })
                        .map_err(|err| -> Box<dyn Error> { err.into() })?;
                    let drawn_at = drawn_at
                        .ok_or_else(|| {
                            eyre!("ministry-jury sortition requires --drawn-at <RFC3339>")
                        })
                        .map_err(|err| -> Box<dyn Error> { err.into() })?;
                    Ok(CommandKind::MinistryJury(
                        ministry_jury::Command::Sortition(ministry_jury::SortitionOptions {
                            roster_path: roster,
                            proposal_id,
                            round_id,
                            beacon_hex: beacon,
                            committee_size: committee,
                            waitlist_size: waitlist,
                            drawn_at,
                            waitlist_ttl_hours,
                            grace_period_secs,
                            failover_grace_secs,
                            output_path: output,
                        }),
                    ))
                }
                "ballot" => {
                    let Some(action) = pending.next() else {
                        return Err(
                            "ministry-jury ballot requires a subcommand (commit|verify)".into()
                        );
                    };
                    match action.as_str() {
                        "commit" => {
                            let mut proposal_id = None;
                            let mut round_id = None;
                            let mut juror_id = None;
                            let mut choice_literal: Option<String> = None;
                            let mut nonce_hex: Option<String> = None;
                            let mut committed_at: Option<OffsetDateTime> = None;
                            let mut revealed_at: Option<OffsetDateTime> = None;
                            let mut output = None;
                            let mut reveal_output = None;
                            while let Some(flag) = pending.next() {
                                match flag.as_str() {
                                    "--proposal" => {
                                        let Some(value) = pending.next() else {
                                            return Err(
                                                "expected value after --proposal".into()
                                            );
                                        };
                                        proposal_id = Some(value);
                                    }
                                    "--round" => {
                                        let Some(value) = pending.next() else {
                                            return Err("expected value after --round".into());
                                        };
                                        round_id = Some(value);
                                    }
                                    "--juror" => {
                                        let Some(value) = pending.next() else {
                                            return Err("expected value after --juror".into());
                                        };
                                        juror_id = Some(value);
                                    }
                                    "--choice" => {
                                        let Some(value) = pending.next() else {
                                            return Err("expected value after --choice".into());
                                        };
                                        choice_literal = Some(value);
                                    }
                                    "--nonce-hex" => {
                                        let Some(value) = pending.next() else {
                                            return Err(
                                                "expected value after --nonce-hex".into()
                                            );
                                        };
                                        nonce_hex = Some(value);
                                    }
                                    "--committed-at" => {
                                        let Some(value) = pending.next() else {
                                            return Err(
                                                "expected value after --committed-at".into()
                                            );
                                        };
                                        committed_at =
                                            Some(ministry_jury::parse_ballot_timestamp(
                                                "--committed-at",
                                                &value,
                                            )?);
                                    }
                                    "--revealed-at" => {
                                        let Some(value) = pending.next() else {
                                            return Err(
                                                "expected value after --revealed-at".into()
                                            );
                                        };
                                        revealed_at =
                                            Some(ministry_jury::parse_ballot_timestamp(
                                                "--revealed-at",
                                                &value,
                                            )?);
                                    }
                                    "--out" => {
                                        let Some(path) = pending.next() else {
                                            return Err("expected path after --out".into());
                                        };
                                        output = Some(normalize_path(Path::new(&path))?);
                                    }
                                    "--reveal-out" => {
                                        let Some(path) = pending.next() else {
                                            return Err(
                                                "expected path after --reveal-out".into()
                                            );
                                        };
                                        reveal_output =
                                            Some(normalize_path(Path::new(&path))?);
                                    }
                                    flag => {
                                        return Err(format!(
                                            "unknown flag for ministry-jury ballot commit: {flag}"
                                        )
                                        .into());
                                    }
                                }
                            }
                            let proposal_id = proposal_id
                                .ok_or_else(|| {
                                    eyre!("ministry-jury ballot commit requires --proposal <id>")
                                })
                                .map_err(|err| -> Box<dyn Error> { err.into() })?;
                            let round_id = round_id
                                .ok_or_else(|| {
                                    eyre!("ministry-jury ballot commit requires --round <id>")
                                })
                                .map_err(|err| -> Box<dyn Error> { err.into() })?;
                            let juror_id = juror_id
                                .ok_or_else(|| {
                                    eyre!("ministry-jury ballot commit requires --juror <id>")
                                })
                                .map_err(|err| -> Box<dyn Error> { err.into() })?;
                            let choice_literal = choice_literal
                                .ok_or_else(|| {
                                    eyre!(
                                        "ministry-jury ballot commit requires --choice <approve|reject|abstain>"
                                    )
                                })
                                .map_err(|err| -> Box<dyn Error> { err.into() })?;
                            let choice = ministry_jury::parse_vote_choice(&choice_literal)?;
                            let nonce =
                                ministry_jury::parse_nonce_hex_or_random(nonce_hex.as_deref())?;
                            let committed_at =
                                committed_at.unwrap_or_else(OffsetDateTime::now_utc);
                            Ok(CommandKind::MinistryJury(
                                ministry_jury::Command::BallotCommit(
                                    ministry_jury::BallotCommitOptions {
                                        proposal_id,
                                        round_id,
                                        juror_id,
                                        choice,
                                        nonce,
                                        committed_at,
                                        revealed_at,
                                        output_path: output,
                                        reveal_output_path: reveal_output,
                                    },
                                ),
                            ))
                        }
                        "verify" => {
                            let mut commit_path = None;
                            let mut reveal_path = None;
                            while let Some(flag) = pending.next() {
                                match flag.as_str() {
                                    "--commit" => {
                                        let Some(path) = pending.next() else {
                                            return Err(
                                                "expected path after --commit".into()
                                            );
                                        };
                                        commit_path =
                                            Some(normalize_path(Path::new(&path))?);
                                    }
                                    "--reveal" => {
                                        let Some(path) = pending.next() else {
                                            return Err(
                                                "expected path after --reveal".into()
                                            );
                                        };
                                        reveal_path =
                                            Some(normalize_path(Path::new(&path))?);
                                    }
                                    flag => {
                                        return Err(format!(
                                            "unknown flag for ministry-jury ballot verify: {flag}"
                                        )
                                        .into());
                                    }
                                }
                            }
                            let commit_path = commit_path
                                .ok_or_else(|| {
                                    eyre!("ministry-jury ballot verify requires --commit <path>")
                                })
                                .map_err(|err| -> Box<dyn Error> { err.into() })?;
                            let reveal_path = reveal_path
                                .ok_or_else(|| {
                                    eyre!("ministry-jury ballot verify requires --reveal <path>")
                                })
                                .map_err(|err| -> Box<dyn Error> { err.into() })?;
                            Ok(CommandKind::MinistryJury(
                                ministry_jury::Command::BallotVerify(
                                    ministry_jury::BallotVerifyOptions {
                                        commit_path,
                                        reveal_path,
                                    },
                                ),
                            ))
                        }
                        other => Err(format!(
                            "unknown ministry-jury ballot subcommand `{other}` (expected commit|verify)"
                        )
                        .into()),
                    }
                }
                other => Err(format!(
                    "unknown ministry-jury subcommand `{other}` (expected sortition|ballot)"
                )
                .into()),
            }
        }
        other => {
            print_usage();
            Err(format!("unknown command: {other}").into())
        }
    }
}
fn generate_openapi(
    outputs: Vec<PathBuf>,
    canonical_spec: PathBuf,
    manifest: PathBuf,
    signature_envelope: Option<PathBuf>,
    signing_payload: Option<PathBuf>,
    unsigned_manifest: bool,
) -> Result<(), Box<dyn Error>> {
    let spec_bytes = canonical_release_openapi(&iroha_torii::openapi::generate_spec())?;
    let emits_manifest = signature_envelope.is_some() || unsigned_manifest;
    if emits_manifest
        && !outputs
            .iter()
            .any(|output| openapi_paths_alias(output, &canonical_spec))
    {
        return Err(format!(
            "OpenAPI manifests require emitting the canonical authority {}",
            canonical_spec.display()
        )
        .into());
    }
    let generator_provenance = if emits_manifest {
        Some(git_source_provenance(
            &workspace_root(),
            &openapi_generator_output_paths(
                &canonical_spec,
                &outputs,
                &manifest,
                signing_payload.as_deref(),
                signature_envelope.as_deref(),
            ),
        )?)
    } else {
        None
    };
    if signature_envelope.is_some()
        && generator_provenance
            .as_ref()
            .is_some_and(|provenance| provenance.dirty)
    {
        return Err(
            "refusing to sign an OpenAPI artifact emitted from a dirty source tree; commit or clean the source changes, then replay the authority"
                .into(),
        );
    }
    for path in &outputs {
        write_openapi_file_atomic(path, &spec_bytes, "OpenAPI output")?;
        println!("wrote {}", path.display());
    }
    if emits_manifest {
        let provenance = generator_provenance
            .as_ref()
            .expect("manifest provenance captured");
        if let Some(signature_envelope) = signature_envelope {
            let signature = load_signature_envelope(&signature_envelope)?;
            write_openapi_manifest_with_signature(
                &canonical_spec,
                &manifest,
                signature,
                provenance,
                signing_payload.as_deref(),
            )?;
        } else {
            write_openapi_manifest_unsigned(
                &canonical_spec,
                &manifest,
                provenance,
                signing_payload.as_deref(),
            )?;
        }
    }
    Ok(())
}
/// Validate Torii's compiled OpenAPI authority and render it as canonical pretty JSON.
///
/// The document is the same feature-pruned projection Torii serves at `/openapi.json`.
fn canonical_release_openapi(spec: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    openapi_validation::validate_release_openapi_spec(spec)?;
    Ok(json::to_vec_pretty(spec)?)
}
fn validate_release_openapi_bytes(spec_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    validated_release_openapi_value(spec_bytes).map(|_| ())
}
fn validated_release_openapi_value(spec_bytes: &[u8]) -> Result<Value, Box<dyn Error>> {
    let spec = json::from_slice::<Value>(spec_bytes)
        .map_err(|err| format!("failed to parse release OpenAPI document as JSON: {err}"))?;
    openapi_validation::validate_release_openapi_spec(&spec)?;
    Ok(spec)
}
const OPENAPI_MANIFEST_VERSION: u32 = 2;
const OPENAPI_MANIFEST_SIGNATURE_DOMAIN_V2: &[u8] = b"iroha.openapi.manifest.signature.v2";
const OPENAPI_MANIFEST_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const OPENAPI_SPEC_MAX_BYTES: u64 = 64 * 1024 * 1024;
const OPENAPI_MANIFEST_MAX_BYTES: u64 = 64 * 1024;
const OPENAPI_SIGNATURE_ENVELOPE_MAX_BYTES: u64 = 4_096;
const OPENAPI_SIGNER_ALLOWLIST_MAX_BYTES: u64 = 64 * 1024;
const OPENAPI_SIGNER_ALLOWLIST_MAX_ENTRIES: usize = 256;
const OPENAPI_GENERATOR_INPUT_INVENTORY: &[u8] =
    include_bytes!("../../release/openapi-generator-inputs-v1.txt");
const OPENAPI_GENERATOR_INPUT_INVENTORY_HEADER: &str = "iroha.openapi.generator-inputs.v1";
const OPENAPI_GENERATOR_INPUT_TREE_DOMAIN: &[u8] = b"iroha-openapi-generator-input-tree-v3";
const OPENAPI_GENERATOR_TRACKED_INPUT: &str = "Cargo.lock";
const OPENAPI_GENERATOR_TRACKED_INPUT_MODE: &[u8] = b"100644";
const OPENAPI_GENERATOR_TRACKED_INPUT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const OPENAPI_CARGO_LOCK_PIN: &[u8] = include_bytes!("../../release/openapi-cargo-lock-v1.txt");
const OPENAPI_CARGO_LOCK_PIN_PATH: &str = "release/openapi-cargo-lock-v1.txt";
const OPENAPI_CARGO_LOCK_PIN_SCHEMA: &str = "iroha.openapi.cargo-lock.v1";
const OPENAPI_CARGO_LOCK_PIN_MAX_BYTES: u64 = 1_024;
const OPENAPI_GENERATOR_INPUT_PATHS: &[&str] = &[
    ".cargo/config.toml",
    ".github/workflows/openapi.yml",
    "Cargo.lock",
    "Cargo.toml",
    "IrohaSwift",
    "Makefile",
    "artifacts/openapi/allowed_signers.json",
    "ci",
    "ci/check_android_codegen.sh",
    "ci/check_openapi_spec.sh",
    "crates",
    "csharp",
    "data_model",
    "fixtures",
    "integration_tests",
    "java/iroha_android",
    "java/norito_java",
    "javascript/iroha_js",
    "kotlin",
    "mochi",
    "python/iroha_python",
    "python/iroha_torii_client",
    "release/openapi-cargo-lock-v1.txt",
    "release/openapi-generator-inputs-v1.txt",
    "release/version-map.toml",
    "rust-toolchain.toml",
    "scripts",
    "scripts/android_codegen_docs.py",
    "scripts/android_codegen_replay_sorafs_fixture.py",
    "scripts/check_android_codegen_parity.py",
    "scripts/check_sorafs_release_version_map.py",
    "specs/sdk/android/generated",
    "specs/sdk/android/generated/codegen_hash_tree.json",
    "specs/sdk/android/generated/codegen_manifest_metadata.json",
    "tools",
    "vendor",
    "xtask",
];
#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenApiCargoLockPinV1 {
    bytes: u64,
    sha256_hex: String,
}
#[derive(Clone, Debug, Eq, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct OpenApiManifest {
    version: u32,
    generated_unix_ms: u64,
    generator_commit: Option<String>,
    generator_dirty: bool,
    #[norito(skip_serializing_if = "Option::is_none")]
    generator_source_sha256_hex: Option<String>,
    artifact: OpenApiArtifact,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenApiGeneratorProvenance {
    generated_unix_ms: u64,
    commit: Option<String>,
    dirty: bool,
    source_sha256_hex: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct OpenApiArtifact {
    path: String,
    bytes: u64,
    sha256_hex: String,
    blake3_hex: String,
    signature: Option<SignatureEnvelope>,
}
#[derive(Clone, Debug, Eq, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SignatureEnvelope {
    algorithm: String,
    public_key_hex: String,
    signature_hex: String,
}
#[derive(Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SignerAllowlist {
    version: u32,
    allow: Vec<AllowedSigner>,
}
#[derive(Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct AllowedSigner {
    algorithm: String,
    public_key_hex: String,
}
#[cfg(test)]
fn write_openapi_manifest(
    spec_path: &Path,
    manifest_path: &Path,
    signing_key: &Path,
    provenance: &OpenApiGeneratorProvenance,
) -> Result<(), Box<dyn Error>> {
    let spec_bytes = read_openapi_input_stable(
        spec_path,
        "OpenAPI specification for manifest signing",
        OPENAPI_SPEC_MAX_BYTES,
    )?;
    validate_release_openapi_bytes(&spec_bytes)?;
    let unsigned = build_openapi_manifest(spec_path, &spec_bytes, provenance)?;
    let signing_payload = encode_openapi_manifest_signing_payload(&unsigned, &spec_bytes)?;
    let signature = sign_manifest_payload_for_test(&signing_payload, signing_key)?;
    write_openapi_manifest_from_bytes(
        spec_path,
        manifest_path,
        &spec_bytes,
        Some(signature),
        provenance,
        None,
    )
}
fn write_openapi_manifest_with_signature(
    spec_path: &Path,
    manifest_path: &Path,
    signature: SignatureEnvelope,
    provenance: &OpenApiGeneratorProvenance,
    signing_payload_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let spec_bytes = read_openapi_input_stable(
        spec_path,
        "OpenAPI specification for manifest signature verification",
        OPENAPI_SPEC_MAX_BYTES,
    )?;
    validate_release_openapi_bytes(&spec_bytes)?;
    write_openapi_manifest_from_bytes(
        spec_path,
        manifest_path,
        &spec_bytes,
        Some(signature),
        provenance,
        signing_payload_path,
    )
}
fn write_openapi_manifest_unsigned(
    spec_path: &Path,
    manifest_path: &Path,
    provenance: &OpenApiGeneratorProvenance,
    signing_payload_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let spec_bytes = read_openapi_input_stable(
        spec_path,
        "OpenAPI specification for unsigned manifest generation",
        OPENAPI_SPEC_MAX_BYTES,
    )?;
    validate_release_openapi_bytes(&spec_bytes)?;
    write_openapi_manifest_from_bytes(
        spec_path,
        manifest_path,
        &spec_bytes,
        None,
        provenance,
        signing_payload_path,
    )
}
fn write_openapi_manifest_from_bytes(
    spec_path: &Path,
    manifest_path: &Path,
    spec_bytes: &[u8],
    signature: Option<SignatureEnvelope>,
    provenance: &OpenApiGeneratorProvenance,
    signing_payload_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    validate_release_openapi_bytes(spec_bytes)?;
    validate_openapi_generator_provenance(provenance, signature.is_none())?;
    if signature.is_some() && provenance.dirty {
        return Err(
            "refusing to write a signed OpenAPI manifest with dirty source provenance".into(),
        );
    }
    let mut manifest = build_openapi_manifest(spec_path, spec_bytes, provenance)?;
    let signing_payload = encode_openapi_manifest_signing_payload(&manifest, spec_bytes)?;
    if let Some(signature) = signature {
        verify_manifest_signature(&signature, &signing_payload)?;
        manifest.artifact.signature = Some(signature);
    }
    if let Some(path) = signing_payload_path {
        write_openapi_signing_payload_new(path, &signing_payload)?;
        println!("wrote {}", path.display());
    }
    let manifest_json = json::to_string_pretty(&manifest)?;
    write_openapi_manifest_atomic(manifest_path, manifest_json.as_bytes())?;
    println!("wrote {}", manifest_path.display());
    Ok(())
}
fn write_openapi_signing_payload_new(
    path: &Path,
    signing_payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        validate_openapi_output_ancestors(parent, "--signing-payload")?;
        fs::create_dir_all(parent)?;
        validate_openapi_output_ancestors(parent, "--signing-payload")?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    set_openapi_no_follow_flag(&mut options);
    let mut file = options.open(path).map_err(|err| {
        format!(
            "refusing to overwrite or follow an existing --signing-payload path {}: {err}",
            path.display()
        )
    })?;
    let write_result = (|| -> Result<(), Box<dyn Error>> {
        use std::io::Write as _;
        validate_openapi_open_file(path, &file, "--signing-payload")?;
        file.write_all(signing_payload)?;
        file.flush()?;
        file.sync_all()?;
        validate_openapi_open_file(path, &file, "--signing-payload")?;
        if let Some(parent) = path.parent() {
            validate_openapi_output_ancestors(parent, "--signing-payload")?;
        }
        Ok(())
    })();
    if write_result.is_err() && openapi_path_matches_file(path, &file) {
        let _ = fs::remove_file(path);
    }
    write_result
}
fn write_openapi_manifest_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    write_openapi_file_atomic(path, bytes, "OpenAPI manifest")
}
fn write_openapi_file_atomic(path: &Path, bytes: &[u8], label: &str) -> Result<(), Box<dyn Error>> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path must have a parent directory"))?;
    validate_openapi_output_ancestors(parent, label)?;
    fs::create_dir_all(parent)?;
    validate_openapi_output_ancestors(parent, label)?;
    validate_openapi_replace_target(path, label)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".openapi-manifest-v2.")
        .tempfile_in(parent)
        .map_err(|err| {
            format!(
                "failed to create an atomic {label} temporary file in {}: {err}",
                parent.display()
            )
        })?;
    {
        use std::io::Write as _;
        temporary.write_all(bytes)?;
        temporary.flush()?;
    }
    temporary.as_file().sync_all()?;
    validate_openapi_replace_target(path, label)?;
    validate_openapi_output_ancestors(parent, label)?;
    let published = temporary.persist(path).map_err(|err| {
        format!(
            "failed to atomically publish {label} {}: {}",
            path.display(),
            err.error
        )
    })?;
    validate_openapi_open_file(path, &published, &format!("published {label}"))?;
    validate_openapi_output_ancestors(parent, label)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn validate_openapi_replace_target(path: &Path, label: &str) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("{label} {} must not be a symlink", path.display()).into());
            }
            if !metadata.is_file() {
                return Err(format!("{label} {} must be a regular file", path.display()).into());
            }
            validate_openapi_single_link(&metadata, path, label)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!("failed to inspect {label} {}: {err}", path.display()).into());
        }
    }
    Ok(())
}
fn validate_openapi_output_ancestors(parent: &Path, label: &str) -> Result<(), Box<dyn Error>> {
    for ancestor in std::iter::once(parent).chain(parent.ancestors().skip(1)) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    #[cfg(unix)]
                    if ancestor.parent() == Some(Path::new("/")) {
                        // macOS exposes system-owned aliases such as /var and
                        // /tmp. Deeper symlinked output parents remain banned.
                        continue;
                    }
                    return Err(format!(
                        "{label} parent {} must not be a symlink",
                        ancestor.display()
                    )
                    .into());
                }
                if !metadata.is_dir() {
                    return Err(format!(
                        "{label} parent {} must be a directory",
                        ancestor.display()
                    )
                    .into());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "failed to inspect {label} parent {}: {err}",
                    ancestor.display()
                )
                .into());
            }
        }
    }
    Ok(())
}
fn validate_openapi_open_file(
    path: &Path,
    file: &fs::File,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let opened = file
        .metadata()
        .map_err(|err| format!("failed to inspect opened {label} {}: {err}", path.display()))?;
    if !opened.is_file() {
        return Err(format!("{label} {} must be a regular file", path.display()).into());
    }
    validate_openapi_single_link(&opened, path, label)?;
    let current = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to re-inspect {label} {}: {err}", path.display()))?;
    if current.file_type().is_symlink() || !current.is_file() {
        return Err(format!("{label} {} changed to a non-regular file", path.display()).into());
    }
    validate_openapi_single_link(&current, path, label)?;
    if !openapi_metadata_matches(&opened, &current) {
        return Err(format!("{label} {} changed while it was open", path.display()).into());
    }
    Ok(())
}
#[cfg(unix)]
fn validate_openapi_single_link(
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.nlink() != 1 {
        return Err(format!("{label} {} must have exactly one hard link", path.display()).into());
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_openapi_single_link(
    _metadata: &fs::Metadata,
    _path: &Path,
    _label: &str,
) -> Result<(), Box<dyn Error>> {
    Ok(())
}
#[cfg(unix)]
fn openapi_metadata_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}
#[cfg(not(unix))]
fn openapi_metadata_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
}
fn openapi_path_matches_file(path: &Path, file: &fs::File) -> bool {
    let Ok(opened) = file.metadata() else {
        return false;
    };
    let Ok(current) = fs::symlink_metadata(path) else {
        return false;
    };
    !current.file_type().is_symlink()
        && current.is_file()
        && openapi_metadata_matches(&opened, &current)
}
fn read_openapi_input_stable(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    read_openapi_input_stable_with_policy(path, label, max_bytes, false, false)
}
fn read_openapi_input_stable_with_policy(
    path: &Path,
    label: &str,
    max_bytes: u64,
    require_safe_permissions: bool,
    forbid_executable: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path must have a parent directory"))?;
    validate_openapi_output_ancestors(parent, label)?;
    validate_openapi_replace_target(path, label)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    set_openapi_no_follow_flag(&mut options);
    let file = options.open(path).map_err(|err| {
        format!(
            "failed to open {label} {} without following symlinks: {err}",
            path.display()
        )
    })?;
    validate_openapi_open_file(path, &file, label)?;
    let opened_before = file
        .metadata()
        .map_err(|err| format!("failed to inspect opened {label} {}: {err}", path.display()))?;
    if require_safe_permissions {
        validate_openapi_open_trust_file_permissions(path, &file, label)?;
    }
    if forbid_executable {
        validate_openapi_open_non_executable_permissions(path, &file, label)?;
    }
    let declared_len = opened_before.len();
    if declared_len > max_bytes {
        return Err(format!(
            "{label} {} exceeds the {max_bytes}-byte limit",
            path.display()
        )
        .into());
    }
    let capacity = usize::try_from(declared_len)
        .map_err(|_| format!("{label} {} does not fit in memory", path.display()))?;
    let mut bytes = Vec::with_capacity(capacity);
    {
        use std::io::Read as _;
        (&file)
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| format!("failed to read {label} {}: {err}", path.display()))?;
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!(
            "{label} {} exceeds the {max_bytes}-byte limit",
            path.display()
        )
        .into());
    }
    let opened_after = file.metadata().map_err(|err| {
        format!(
            "failed to re-inspect opened {label} {}: {err}",
            path.display()
        )
    })?;
    if !openapi_read_state_matches(&opened_before, &opened_after) {
        return Err(format!("{label} {} changed while it was read", path.display()).into());
    }
    validate_openapi_open_file(path, &file, label)?;
    if require_safe_permissions {
        validate_openapi_open_trust_file_permissions(path, &file, label)?;
    }
    if forbid_executable {
        validate_openapi_open_non_executable_permissions(path, &file, label)?;
    }
    validate_openapi_output_ancestors(parent, label)?;
    Ok(bytes)
}
#[cfg(unix)]
fn openapi_read_state_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(not(unix))]
fn openapi_read_state_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
fn read_openapi_utf8_input_stable(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<String, Box<dyn Error>> {
    let bytes = read_openapi_input_stable(path, label, max_bytes)?;
    String::from_utf8(bytes)
        .map_err(|err| format!("{label} {} must be UTF-8: {err}", path.display()).into())
}
fn read_openapi_utf8_trust_input_stable(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<String, Box<dyn Error>> {
    let bytes = read_openapi_input_stable_with_policy(path, label, max_bytes, true, false)?;
    String::from_utf8(bytes)
        .map_err(|err| format!("{label} {} must be UTF-8: {err}", path.display()).into())
}
#[cfg(unix)]
fn set_openapi_no_follow_flag(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(openapi_no_follow_flag());
}
#[cfg(not(unix))]
fn set_openapi_no_follow_flag(_options: &mut fs::OpenOptions) {}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn openapi_no_follow_flag() -> i32 {
    0o400000
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
fn openapi_no_follow_flag() -> i32 {
    0x100
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
fn openapi_no_follow_flag() -> i32 {
    0
}
fn build_openapi_manifest(
    _spec_path: &Path,
    spec_bytes: &[u8],
    provenance: &OpenApiGeneratorProvenance,
) -> Result<OpenApiManifest, Box<dyn Error>> {
    validate_release_openapi_bytes(spec_bytes)?;
    validate_openapi_generator_provenance(provenance, true)?;
    let size_bytes =
        u64::try_from(spec_bytes.len()).map_err(|_| "OpenAPI artifact size does not fit in u64")?;
    Ok(OpenApiManifest {
        version: OPENAPI_MANIFEST_VERSION,
        generated_unix_ms: provenance.generated_unix_ms,
        generator_commit: provenance.commit.clone(),
        generator_dirty: provenance.dirty,
        generator_source_sha256_hex: provenance.source_sha256_hex.clone(),
        artifact: OpenApiArtifact {
            path: "torii.json".to_owned(),
            bytes: size_bytes,
            sha256_hex: hex::encode(Sha256::digest(spec_bytes)),
            blake3_hex: blake3::hash(spec_bytes).to_hex().to_string(),
            signature: None,
        },
    })
}
fn verify_openapi_manifest(
    spec_path: &Path,
    manifest_path: &Path,
    allow_unsigned: bool,
    allowed_signers_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let spec_bytes = read_openapi_input_stable(
        spec_path,
        "OpenAPI specification for manifest verification",
        OPENAPI_SPEC_MAX_BYTES,
    )?;
    validate_release_openapi_bytes(&spec_bytes)?;
    let manifest_text = read_openapi_utf8_input_stable(
        manifest_path,
        "OpenAPI manifest for verification",
        OPENAPI_MANIFEST_MAX_BYTES,
    )?;
    let _: Value = json::from_str(&manifest_text).map_err(|err| {
        format!(
            "failed to parse {} as duplicate-free JSON manifest: {err}",
            manifest_path.display()
        )
    })?;
    let manifest: OpenApiManifest = json::from_str(&manifest_text).map_err(|err| {
        format!(
            "failed to parse {} as JSON manifest: {err}",
            manifest_path.display()
        )
    })?;
    if manifest.version != OPENAPI_MANIFEST_VERSION {
        return Err(format!(
            "unsupported OpenAPI manifest version {}; expected {OPENAPI_MANIFEST_VERSION}",
            manifest.version,
        )
        .into());
    }
    if manifest.generated_unix_ms == 0
        || manifest.generated_unix_ms > OPENAPI_MANIFEST_MAX_SAFE_INTEGER
    {
        return Err("OpenAPI manifest generated_unix_ms must be a positive safe integer".into());
    }
    let provenance = OpenApiGeneratorProvenance {
        generated_unix_ms: manifest.generated_unix_ms,
        commit: manifest.generator_commit.clone(),
        dirty: manifest.generator_dirty,
        source_sha256_hex: manifest.generator_source_sha256_hex.clone(),
    };
    validate_openapi_generator_provenance(
        &provenance,
        allow_unsigned && manifest.artifact.signature.is_none(),
    )?;
    verify_openapi_artifact_path(spec_path, &manifest.artifact.path)?;
    let expected_sha256 = hex::encode(Sha256::digest(&spec_bytes));
    if manifest.artifact.sha256_hex != expected_sha256 {
        return Err(format!(
            "manifest sha256_hex mismatch (expected {expected_sha256}, found {})",
            manifest.artifact.sha256_hex
        )
        .into());
    }
    let expected_blake3 = blake3::hash(&spec_bytes).to_hex().to_string();
    if manifest.artifact.blake3_hex != expected_blake3 {
        return Err(format!(
            "manifest blake3_hex mismatch (expected {expected_blake3}, found {})",
            manifest.artifact.blake3_hex
        )
        .into());
    }
    let actual_size = spec_bytes.len() as u64;
    if manifest.artifact.bytes != actual_size {
        return Err(format!(
            "manifest size mismatch (expected {actual_size} bytes, found {})",
            manifest.artifact.bytes
        )
        .into());
    }
    let signing_payload = encode_openapi_manifest_signing_payload(&manifest, &spec_bytes)?;
    match &manifest.artifact.signature {
        Some(signature) => {
            let allowed_signers = allowed_signers_path
                .map(load_signer_allowlist)
                .transpose()
                .map_err(|err| {
                    format!(
                        "failed to load allowed signers from {}: {err}",
                        allowed_signers_path
                            .expect("allowed_signers_path present when reporting error")
                            .display()
                    )
                })?;
            verify_manifest_signature(signature, &signing_payload)?;
            if let Some(allowlist) = allowed_signers.as_ref() {
                ensure_signer_allowed(signature, allowlist)?;
            }
        }
        None if allow_unsigned => {
            eprintln!(
                "warning: manifest {} missing signature; continuing due to --allow-unsigned",
                manifest_path.display()
            );
        }
        None => {
            return Err(
                "manifest missing signature; emit a deterministic --signing-payload, sign it with the external software signer, and provide --signature-envelope <path>"
                    .into(),
            );
        }
    }
    println!(
        "verified {} against {}",
        manifest_path.display(),
        spec_path.display()
    );
    Ok(())
}
fn verify_openapi_artifact_path(
    _spec_path: &Path,
    artifact_path: &str,
) -> Result<(), Box<dyn Error>> {
    if artifact_path != "torii.json" {
        return Err(format!(
            "manifest artifact.path `{artifact_path}` must be exactly `torii.json`"
        )
        .into());
    }
    Ok(())
}
fn encode_space_directory_manifest(input: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    if !input.exists() {
        return Err(format!("manifest JSON `{}` does not exist", input.display()).into());
    }
    if !input.is_file() {
        return Err(format!("manifest JSON `{}` is not a file", input.display()).into());
    }
    let contents = fs::read(input)
        .map_err(|err| format!("failed to read manifest JSON `{}`: {err}", input.display()))?;
    let manifest: AssetPermissionManifest = json::from_slice(&contents).map_err(|err| {
        format!(
            "failed to parse `{}` as capability manifest JSON: {err}",
            input.display()
        )
    })?;
    let norito_bytes = to_bytes(&manifest).map_err(|err| {
        format!(
            "failed to encode Norito payload for `{}`: {err}",
            input.display()
        )
    })?;
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create directory `{}`: {err}", parent.display()))?;
    }
    fs::write(output, &norito_bytes).map_err(|err| {
        format!(
            "failed to write Norito manifest `{}`: {err}",
            output.display()
        )
    })?;
    let blake3_hex = blake3::hash(&norito_bytes).to_hex().to_string();
    println!(
        "encoded manifest for UAID {} in dataspace {} -> {} ({} entries, {} bytes, blake3={})",
        manifest.uaid,
        manifest.dataspace,
        output.display(),
        manifest.entries.len(),
        norito_bytes.len(),
        blake3_hex
    );
    Ok(())
}
fn encode_openapi_manifest_signing_payload(
    manifest: &OpenApiManifest,
    artifact_bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    validate_openapi_manifest_v2_fields(manifest, artifact_bytes)?;
    let mut encoded = Vec::with_capacity(artifact_bytes.len().saturating_add(512));
    append_openapi_signing_component(
        &mut encoded,
        b"domain",
        OPENAPI_MANIFEST_SIGNATURE_DOMAIN_V2,
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"version",
        manifest.version.to_string().as_bytes(),
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"generated_unix_ms",
        manifest.generated_unix_ms.to_string().as_bytes(),
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"generator_commit",
        manifest
            .generator_commit
            .as_deref()
            .unwrap_or("null")
            .as_bytes(),
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"generator_dirty",
        if manifest.generator_dirty {
            b"true"
        } else {
            b"false"
        },
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"generator_source_sha256_hex",
        manifest
            .generator_source_sha256_hex
            .as_deref()
            .unwrap_or("null")
            .as_bytes(),
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"artifact.path",
        manifest.artifact.path.as_bytes(),
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"artifact.bytes",
        manifest.artifact.bytes.to_string().as_bytes(),
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"artifact.sha256_hex",
        manifest.artifact.sha256_hex.as_bytes(),
    )?;
    append_openapi_signing_component(
        &mut encoded,
        b"artifact.blake3_hex",
        manifest.artifact.blake3_hex.as_bytes(),
    )?;
    append_openapi_signing_component(&mut encoded, b"artifact.content", artifact_bytes)?;
    Ok(encoded)
}
fn append_openapi_signing_component(
    output: &mut Vec<u8>,
    label: &[u8],
    value: &[u8],
) -> Result<(), Box<dyn Error>> {
    let label_len =
        u64::try_from(label.len()).map_err(|_| "OpenAPI signing label length exceeds u64")?;
    let value_len =
        u64::try_from(value.len()).map_err(|_| "OpenAPI signing value length exceeds u64")?;
    output.extend_from_slice(&label_len.to_le_bytes());
    output.extend_from_slice(label);
    output.extend_from_slice(&value_len.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}
fn validate_openapi_manifest_v2_fields(
    manifest: &OpenApiManifest,
    artifact_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    if manifest.version != OPENAPI_MANIFEST_VERSION {
        return Err(format!(
            "unsupported OpenAPI manifest version {}; expected {OPENAPI_MANIFEST_VERSION}",
            manifest.version
        )
        .into());
    }
    if manifest.generated_unix_ms == 0
        || manifest.generated_unix_ms > OPENAPI_MANIFEST_MAX_SAFE_INTEGER
    {
        return Err("OpenAPI manifest generated_unix_ms must be a positive safe integer".into());
    }
    validate_openapi_generator_provenance(
        &OpenApiGeneratorProvenance {
            generated_unix_ms: manifest.generated_unix_ms,
            commit: manifest.generator_commit.clone(),
            dirty: manifest.generator_dirty,
            source_sha256_hex: manifest.generator_source_sha256_hex.clone(),
        },
        manifest.artifact.signature.is_none(),
    )?;
    verify_openapi_artifact_path(Path::new(&manifest.artifact.path), &manifest.artifact.path)?;
    let actual_size =
        u64::try_from(artifact_bytes.len()).map_err(|_| "OpenAPI artifact exceeds u64")?;
    if actual_size > OPENAPI_MANIFEST_MAX_SAFE_INTEGER {
        return Err("OpenAPI artifact exceeds the V2 safe-integer byte limit".into());
    }
    if manifest.artifact.bytes != actual_size {
        return Err(format!(
            "manifest size mismatch (expected {actual_size} bytes, found {})",
            manifest.artifact.bytes
        )
        .into());
    }
    let expected_sha256 = hex::encode(Sha256::digest(artifact_bytes));
    if manifest.artifact.sha256_hex != expected_sha256 {
        return Err(format!(
            "manifest sha256_hex mismatch (expected {expected_sha256}, found {})",
            manifest.artifact.sha256_hex
        )
        .into());
    }
    let expected_blake3 = blake3::hash(artifact_bytes).to_hex().to_string();
    if manifest.artifact.blake3_hex != expected_blake3 {
        return Err(format!(
            "manifest blake3_hex mismatch (expected {expected_blake3}, found {})",
            manifest.artifact.blake3_hex
        )
        .into());
    }
    if let Some(signature) = &manifest.artifact.signature {
        validate_signature_envelope_fields(signature)?;
    }
    Ok(())
}
#[cfg(test)]
fn sign_manifest_payload_for_test(
    payload: &[u8],
    key_path: &Path,
) -> Result<SignatureEnvelope, Box<dyn Error>> {
    let key_hex = fs::read_to_string(key_path)
        .map_err(|err| format!("failed to read signing key {}: {err}", key_path.display()))?;
    let cleaned: String = key_hex
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let private_key = PrivateKey::from_hex(Algorithm::Ed25519, &cleaned).map_err(|err| {
        format!(
            "failed to parse signing key {} as Ed25519 hex: {err}",
            key_path.display()
        )
    })?;
    let key_pair: KeyPair = private_key.clone().into();
    let signature = Signature::try_new(key_pair.private_key(), payload)
        .map_err(|err| format!("failed to sign OpenAPI manifest payload: {err}"))?;
    let (algorithm, public_bytes) = key_pair
        .public_key()
        .try_to_bytes()
        .map_err(|err| format!("signing public key is malformed: {err}"))?;
    if algorithm != Algorithm::Ed25519 {
        return Err("OpenAPI test signing supports Ed25519 keys only".into());
    }
    Ok(SignatureEnvelope {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex::encode(public_bytes),
        signature_hex: hex::encode(signature.payload()),
    })
}
fn load_signature_envelope(path: &Path) -> Result<SignatureEnvelope, Box<dyn Error>> {
    let text = read_openapi_utf8_input_stable(
        path,
        "signature envelope",
        OPENAPI_SIGNATURE_ENVELOPE_MAX_BYTES,
    )?;
    let _: Value = json::from_str(&text).map_err(|err| {
        format!(
            "failed to parse signature envelope {} as duplicate-free JSON: {err}",
            path.display()
        )
    })?;
    let envelope: SignatureEnvelope = json::from_str(&text).map_err(|err| -> Box<dyn Error> {
        format!(
            "failed to parse signature envelope {}: {err}",
            path.display()
        )
        .into()
    })?;
    validate_signature_envelope_fields(&envelope)?;
    Ok(envelope)
}
fn validate_signature_envelope_fields(signature: &SignatureEnvelope) -> Result<(), Box<dyn Error>> {
    if signature.algorithm != "ed25519" {
        return Err(format!(
            "unsupported manifest signature algorithm `{}`; expected exactly `ed25519`",
            signature.algorithm
        )
        .into());
    }
    validate_openapi_ed25519_public_key_hex(&signature.public_key_hex, "manifest public_key_hex")?;
    if !is_lower_hex_digest(&signature.signature_hex, 64) {
        return Err(
            "manifest signature_hex must be exactly 128 lowercase hexadecimal characters".into(),
        );
    }
    Ok(())
}
fn validate_openapi_ed25519_public_key_hex(
    public_key_hex: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if !is_lower_hex_digest(public_key_hex, 32) {
        return Err(format!("{label} must be exactly 64 lowercase hexadecimal characters").into());
    }
    let public_key_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = hex::decode(public_key_hex)
        .map_err(|err| format!("{label} decoding failed: {err}"))?
        .try_into()
        .map_err(|_| format!("{label} must decode to exactly 32 bytes"))?;
    let dalek_public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|err| format!("{label} is not an Ed25519 point: {err}"))?;
    if dalek_public_key.to_bytes() != public_key_bytes {
        return Err(format!("{label} is not a canonical Ed25519 point").into());
    }
    if dalek_public_key.is_weak() {
        return Err(format!("{label} is a weak or small-order Ed25519 point").into());
    }
    Ok(())
}
fn verify_manifest_signature(
    signature: &SignatureEnvelope,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    validate_signature_envelope_fields(signature)?;
    let algorithm = Algorithm::Ed25519;
    let public_key = PublicKey::from_hex(algorithm, &signature.public_key_hex)
        .map_err(|err| format!("invalid manifest public key hex: {err}"))?;
    let sig_bytes = hex::decode(&signature.signature_hex)
        .map_err(|err| format!("invalid manifest signature hex: {err}"))?;
    let sig = iroha_crypto::ed25519_parse_signature(&sig_bytes)
        .map_err(|err| format!("invalid manifest signature material: {err}"))?;
    sig.verify(&public_key, payload)
        .map_err(|err| format!("manifest signature verification failed: {err}").into())
}
fn load_signer_allowlist(path: &Path) -> Result<SignerAllowlist, Box<dyn Error>> {
    let contents = read_openapi_utf8_trust_input_stable(
        path,
        "OpenAPI signer allowlist",
        OPENAPI_SIGNER_ALLOWLIST_MAX_BYTES,
    )?;
    let _: Value = json::from_str(&contents)
        .map_err(|err| format!("invalid duplicate-free allowlist JSON: {err}"))?;
    let allowlist: SignerAllowlist =
        json::from_str(&contents).map_err(|err| format!("invalid allowlist JSON: {err}"))?;
    if allowlist.version != 1 {
        return Err(format!(
            "unsupported allowlist version {}; expected 1",
            allowlist.version
        )
        .into());
    }
    if allowlist.allow.len() > OPENAPI_SIGNER_ALLOWLIST_MAX_ENTRIES {
        return Err(format!(
            "OpenAPI signer allowlist has {} entries; the limit is {}",
            allowlist.allow.len(),
            OPENAPI_SIGNER_ALLOWLIST_MAX_ENTRIES
        )
        .into());
    }
    let mut identities = BTreeSet::new();
    for (index, signer) in allowlist.allow.iter().enumerate() {
        if signer.algorithm != "ed25519" {
            return Err(format!(
                "OpenAPI signer allowlist entry {index} algorithm must be exactly `ed25519`"
            )
            .into());
        }
        validate_openapi_ed25519_public_key_hex(
            &signer.public_key_hex,
            &format!("OpenAPI signer allowlist entry {index} public_key_hex"),
        )?;
        if !identities.insert(signer.public_key_hex.as_str()) {
            return Err(format!(
                "OpenAPI signer allowlist entry {index} duplicates public key {}",
                signer.public_key_hex
            )
            .into());
        }
    }
    Ok(allowlist)
}
#[cfg(unix)]
fn validate_openapi_open_trust_file_permissions(
    path: &Path,
    file: &fs::File,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = file.metadata().map_err(|err| {
        format!(
            "failed to inspect opened {label} {} permissions: {err}",
            path.display()
        )
    })?;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "{label} {} must not be writable by group or other users",
            path.display()
        )
        .into());
    }
    Ok(())
}
#[cfg(unix)]
fn validate_openapi_open_non_executable_permissions(
    path: &Path,
    file: &fs::File,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = file.metadata().map_err(|err| {
        format!(
            "failed to inspect opened {label} {} permissions: {err}",
            path.display()
        )
    })?;
    if metadata.permissions().mode() & 0o111 != 0 {
        return Err(format!("{label} {} must not be executable", path.display()).into());
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_openapi_open_non_executable_permissions(
    _path: &Path,
    _file: &fs::File,
    _label: &str,
) -> Result<(), Box<dyn Error>> {
    Ok(())
}
#[cfg(not(unix))]
fn validate_openapi_open_trust_file_permissions(
    _path: &Path,
    _file: &fs::File,
    _label: &str,
) -> Result<(), Box<dyn Error>> {
    Ok(())
}
fn ensure_signer_allowed(
    signature: &SignatureEnvelope,
    allowlist: &SignerAllowlist,
) -> Result<(), Box<dyn Error>> {
    let allowed = allowlist.allow.iter().any(|signer| {
        signer.algorithm == signature.algorithm && signer.public_key_hex == signature.public_key_hex
    });
    if allowed {
        return Ok(());
    }
    let allowed_keys: Vec<String> = allowlist
        .allow
        .iter()
        .map(|signer| format!("{}:{}", signer.algorithm, signer.public_key_hex))
        .collect();
    Err(format!(
        "unrecognized manifest signer {}:{}; allowed signers: {}",
        signature.algorithm,
        signature.public_key_hex,
        allowed_keys.join(", ")
    )
    .into())
}
fn validate_openapi_generator_provenance(
    provenance: &OpenApiGeneratorProvenance,
    allow_dirty_unsigned: bool,
) -> Result<(), Box<dyn Error>> {
    if provenance.generated_unix_ms == 0
        || provenance.generated_unix_ms > OPENAPI_MANIFEST_MAX_SAFE_INTEGER
    {
        return Err(
            "OpenAPI generator provenance timestamp must be a positive safe integer".into(),
        );
    }
    let Some(source_digest) = provenance.source_sha256_hex.as_deref() else {
        return Err("OpenAPI generator provenance is missing generator_source_sha256_hex".into());
    };
    if !is_lower_hex_digest(source_digest, 32) || source_digest.bytes().all(|byte| byte == b'0') {
        return Err(
            "generator_source_sha256_hex must be exactly 64 lowercase hexadecimal characters and must be nonzero"
                .into(),
        );
    }
    if provenance.dirty {
        if provenance.commit.is_some() {
            return Err(
                "dirty OpenAPI generator provenance must set generator_commit to null".into(),
            );
        }
        if !allow_dirty_unsigned {
            return Err(
                "dirty OpenAPI generator provenance cannot be release-verified; regenerate from a clean source tree"
                    .into(),
            );
        }
    } else {
        let Some(commit) = provenance.commit.as_deref() else {
            return Err("clean OpenAPI generator provenance is missing generator_commit".into());
        };
        if !is_lower_hex_digest(commit, 20) {
            return Err(
                "generator_commit must be exactly 40 lowercase hexadecimal characters".into(),
            );
        }
        if commit.bytes().all(|byte| byte == b'0') {
            return Err("generator_commit must identify a nonzero Git commit".into());
        }
    }
    Ok(())
}
fn is_lower_hex_digest(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn openapi_generator_output_paths(
    canonical_spec: &Path,
    outputs: &[PathBuf],
    manifest: &Path,
    signing_payload: Option<&Path>,
    signature_envelope: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for spec in [default_openapi_path(), canonical_spec.to_path_buf()] {
        let openapi_dir = spec
            .parent()
            .expect("canonical OpenAPI output has a parent")
            .to_path_buf();
        paths.extend([
            spec,
            openapi_dir.join("manifest.json"),
            openapi_dir.join("versions.json"),
            openapi_dir.join("versions/current/torii.json"),
            openapi_dir.join("versions/current/manifest.json"),
        ]);
    }
    paths.push(manifest.to_path_buf());
    paths.extend(outputs.iter().cloned());
    paths.extend(signing_payload.map(Path::to_path_buf));
    paths.extend(signature_envelope.map(Path::to_path_buf));
    paths.sort();
    paths.dedup();
    paths
}
fn git_source_provenance(
    repo_root: &Path,
    excluded_paths: &[PathBuf],
) -> Result<OpenApiGeneratorProvenance, Box<dyn Error>> {
    let head = git_stdout(repo_root, &["rev-parse", "--verify", "HEAD"])?;
    let head = std::str::from_utf8(&head)
        .map_err(|err| format!("git HEAD is not valid UTF-8: {err}"))?
        .trim();
    if head.is_empty() {
        return Err("git rev-parse returned an empty HEAD".into());
    }
    let generated_unix_ms = git_head_timestamp_ms(repo_root)?;
    let pathspecs = git_source_pathspecs(repo_root, excluded_paths)?;
    let mut status_args = vec![
        OsString::from("status"),
        OsString::from("--porcelain=v1"),
        OsString::from("-z"),
        OsString::from("--untracked-files=all"),
    ];
    status_args.extend(pathspecs.iter().cloned());
    let status = git_stdout(repo_root, &status_args)?;
    let committed_source_sha256_hex = git_openapi_generator_input_tree_sha256_with_pin_source(
        repo_root,
        head,
        if status.is_empty() {
            OpenApiCargoLockPinSource::Committed
        } else {
            OpenApiCargoLockPinSource::WorkingDirtyUnsigned
        },
    )?;
    if status.is_empty() {
        return Ok(OpenApiGeneratorProvenance {
            generated_unix_ms,
            commit: Some(head.to_owned()),
            dirty: false,
            source_sha256_hex: Some(committed_source_sha256_hex),
        });
    }
    let mut diff_args = vec![
        OsString::from("diff"),
        OsString::from("--binary"),
        OsString::from("--full-index"),
        OsString::from("--no-color"),
        OsString::from("--no-ext-diff"),
        OsString::from("HEAD"),
    ];
    diff_args.extend(pathspecs.iter().cloned());
    let tracked_diff = git_stdout(repo_root, &diff_args)?;
    let mut untracked_args = vec![
        OsString::from("ls-files"),
        OsString::from("--others"),
        OsString::from("--exclude-standard"),
        OsString::from("-z"),
    ];
    untracked_args.extend(pathspecs);
    let untracked = git_stdout(repo_root, &untracked_args)?;
    let mut source_digest = Sha256::new();
    update_sha256_component(
        &mut source_digest,
        b"domain",
        b"iroha-openapi-generator-working-source-v3",
    );
    update_sha256_component(&mut source_digest, b"head", head.as_bytes());
    update_sha256_component(
        &mut source_digest,
        b"committed-input-tree-sha256",
        committed_source_sha256_hex.as_bytes(),
    );
    update_sha256_component(&mut source_digest, b"status", &status);
    update_sha256_component(&mut source_digest, b"tracked-diff", &tracked_diff);
    for path_bytes in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        update_sha256_component(&mut source_digest, b"untracked-path", path_bytes);
        let relative_path = git_path_from_bytes(path_bytes)?;
        hash_untracked_path(&mut source_digest, &repo_root.join(relative_path))?;
    }
    Ok(OpenApiGeneratorProvenance {
        generated_unix_ms,
        commit: None,
        dirty: true,
        source_sha256_hex: Some(hex::encode(source_digest.finalize())),
    })
}
#[cfg(test)]
fn git_openapi_generator_input_tree_sha256(
    repo_root: &Path,
    commit: &str,
) -> Result<String, Box<dyn Error>> {
    git_openapi_generator_input_tree_sha256_with_pin_source(
        repo_root,
        commit,
        OpenApiCargoLockPinSource::Committed,
    )
}
#[derive(Clone, Copy)]
enum OpenApiCargoLockPinSource {
    Committed,
    WorkingDirtyUnsigned,
}
fn git_openapi_generator_input_tree_sha256_with_pin_source(
    repo_root: &Path,
    commit: &str,
    pin_source: OpenApiCargoLockPinSource,
) -> Result<String, Box<dyn Error>> {
    if !is_lower_hex_digest(commit, 20) {
        return Err(
            "OpenAPI generator input commit must be exactly 40 lowercase hex digits".into(),
        );
    }
    let inventory_paths = validate_openapi_generator_input_inventory()?;
    let mut args = vec![
        OsString::from("ls-tree"),
        OsString::from("-r"),
        OsString::from("-z"),
        OsString::from("--full-tree"),
        OsString::from(commit),
        OsString::from("--"),
    ];
    args.extend(inventory_paths.iter().map(|path| OsString::from(*path)));
    let tree = git_stdout(repo_root, &args)?;
    if tree.is_empty() {
        return Err("OpenAPI generator input inventory resolved to an empty Git tree".into());
    }
    if !tree.ends_with(&[0]) {
        return Err("git ls-tree output for OpenAPI generator inputs must end in NUL".into());
    }
    let mut resolved_paths = Vec::new();
    let mut unique_paths = BTreeSet::new();
    let mut cargo_lock_pin_mode = None;
    let mut cargo_lock_mode = None;
    let mut cargo_lock_blob_oid = None;
    for entry in tree
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let tab = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("git ls-tree returned an OpenAPI generator input without a path separator")?;
        let metadata = std::str::from_utf8(&entry[..tab]).map_err(|err| {
            format!("git ls-tree returned non-UTF-8 OpenAPI generator metadata: {err}")
        })?;
        let fields = metadata.split(' ').collect::<Vec<_>>();
        if fields.len() != 3
            || !matches!(fields[0], "100644" | "100755" | "120000")
            || fields[1] != "blob"
            || !is_lower_hex_digest(fields[2], 20)
        {
            return Err("OpenAPI generator inputs must resolve only to canonical Git blobs".into());
        }
        let path = std::str::from_utf8(&entry[tab + 1..]).map_err(|err| {
            format!("git ls-tree returned a non-UTF-8 OpenAPI generator input path: {err}")
        })?;
        if !unique_paths.insert(path) {
            return Err(format!("git ls-tree duplicated OpenAPI generator input `{path}`").into());
        }
        if path == OPENAPI_CARGO_LOCK_PIN_PATH {
            cargo_lock_pin_mode = Some(fields[0].to_owned());
        }
        if path == OPENAPI_GENERATOR_TRACKED_INPUT {
            cargo_lock_mode = Some(fields[0].to_owned());
            cargo_lock_blob_oid = Some(fields[2].to_owned());
        }
        resolved_paths.push(path);
    }
    for required in &inventory_paths {
        let prefix = format!("{required}/");
        if !resolved_paths
            .iter()
            .any(|path| *path == *required || path.starts_with(&prefix))
        {
            return Err(format!(
                "OpenAPI generator input inventory path `{required}` is missing at commit {commit}"
            )
            .into());
        }
    }
    match cargo_lock_pin_mode.as_deref() {
        Some("100644") => {}
        Some(mode) => {
            return Err(format!(
                "OpenAPI Cargo.lock pin must have Git mode 100644 at commit {commit}, found {mode}"
            )
            .into());
        }
        None => return Err(format!("OpenAPI Cargo.lock pin is missing at commit {commit}").into()),
    }
    match cargo_lock_mode.as_deref() {
        Some("100644") => {}
        Some(mode) => {
            return Err(format!(
                "OpenAPI Cargo.lock must have Git mode 100644 at commit {commit}, found {mode}"
            )
            .into());
        }
        None => return Err(format!("OpenAPI Cargo.lock is missing at commit {commit}").into()),
    }
    let cargo_lock_blob_oid = cargo_lock_blob_oid.ok_or("OpenAPI Cargo.lock blob is missing")?;
    let pin = match pin_source {
        OpenApiCargoLockPinSource::Committed => read_git_openapi_cargo_lock_pin(repo_root, commit)?,
        OpenApiCargoLockPinSource::WorkingDirtyUnsigned => {
            read_working_openapi_cargo_lock_pin(repo_root)?
        }
    };
    let tracked_input =
        read_openapi_generator_tracked_input(repo_root, commit, &cargo_lock_blob_oid, &pin)?;
    Ok(openapi_generator_input_closure_sha256(
        &tree,
        &tracked_input,
    ))
}
fn openapi_generator_input_closure_sha256(tree: &[u8], tracked_input: &[u8]) -> String {
    let mut source_digest = Sha256::new();
    update_sha256_component(
        &mut source_digest,
        b"domain",
        OPENAPI_GENERATOR_INPUT_TREE_DOMAIN,
    );
    update_sha256_component(
        &mut source_digest,
        b"inventory",
        OPENAPI_GENERATOR_INPUT_INVENTORY,
    );
    update_sha256_component(&mut source_digest, b"tree", tree);
    update_sha256_component(
        &mut source_digest,
        b"tracked-input-path",
        OPENAPI_GENERATOR_TRACKED_INPUT.as_bytes(),
    );
    update_sha256_component(
        &mut source_digest,
        b"tracked-input-mode",
        OPENAPI_GENERATOR_TRACKED_INPUT_MODE,
    );
    update_sha256_component(&mut source_digest, b"tracked-input-bytes", tracked_input);
    hex::encode(source_digest.finalize())
}
fn parse_openapi_cargo_lock_pin(bytes: &[u8]) -> Result<OpenApiCargoLockPinV1, Box<dyn Error>> {
    if bytes.is_empty() || u64::try_from(bytes.len())? > OPENAPI_CARGO_LOCK_PIN_MAX_BYTES {
        return Err(format!(
            "OpenAPI Cargo.lock pin must contain 1..={OPENAPI_CARGO_LOCK_PIN_MAX_BYTES} bytes"
        )
        .into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|err| format!("OpenAPI Cargo.lock pin is not UTF-8: {err}"))?;
    if text.contains('\r') || !text.ends_with('\n') {
        return Err("OpenAPI Cargo.lock pin must use LF endings and one final newline".into());
    }
    let mut fields = text.split('\n');
    if fields.next() != Some(OPENAPI_CARGO_LOCK_PIN_SCHEMA) {
        return Err("OpenAPI Cargo.lock pin has an invalid schema".into());
    }
    let byte_text = fields
        .next()
        .and_then(|field| field.strip_prefix("bytes="))
        .ok_or("OpenAPI Cargo.lock pin has an invalid bytes field")?;
    if byte_text.is_empty()
        || byte_text.starts_with('0')
        || !byte_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("OpenAPI Cargo.lock pin has a noncanonical bytes field".into());
    }
    let expected_bytes = byte_text
        .parse::<u64>()
        .map_err(|err| format!("OpenAPI Cargo.lock pin bytes field is invalid: {err}"))?;
    let sha256_hex = fields
        .next()
        .and_then(|field| field.strip_prefix("sha256_hex="))
        .ok_or("OpenAPI Cargo.lock pin has an invalid SHA-256 field")?;
    if fields.next() != Some("") || fields.next().is_some() {
        return Err("OpenAPI Cargo.lock pin must contain exactly three fields".into());
    }
    if expected_bytes == 0 || expected_bytes > OPENAPI_GENERATOR_TRACKED_INPUT_MAX_BYTES {
        return Err(format!(
            "OpenAPI Cargo.lock pin bytes must be within 1..={OPENAPI_GENERATOR_TRACKED_INPUT_MAX_BYTES}"
        )
        .into());
    }
    if !is_lower_hex_digest(sha256_hex, 32) || sha256_hex.bytes().all(|byte| byte == b'0') {
        return Err(
            "OpenAPI Cargo.lock pin SHA-256 must be lowercase hexadecimal and nonzero".into(),
        );
    }
    Ok(OpenApiCargoLockPinV1 {
        bytes: expected_bytes,
        sha256_hex: sha256_hex.to_owned(),
    })
}
fn read_git_openapi_cargo_lock_pin(
    repo_root: &Path,
    commit: &str,
) -> Result<OpenApiCargoLockPinV1, Box<dyn Error>> {
    let object = OsString::from(format!("{commit}:{OPENAPI_CARGO_LOCK_PIN_PATH}"));
    let size = git_stdout(
        repo_root,
        &[
            OsString::from("cat-file"),
            OsString::from("-s"),
            object.clone(),
        ],
    )?;
    let size_text = std::str::from_utf8(&size)
        .map_err(|err| format!("OpenAPI Cargo.lock pin Git size is not UTF-8: {err}"))?;
    if !size_text.ends_with('\n')
        || size_text[..size_text.len() - 1].is_empty()
        || !size_text[..size_text.len() - 1]
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err("OpenAPI Cargo.lock pin Git size is noncanonical".into());
    }
    let object_size = size_text[..size_text.len() - 1]
        .parse::<u64>()
        .map_err(|err| format!("OpenAPI Cargo.lock pin Git size is invalid: {err}"))?;
    if object_size != u64::try_from(OPENAPI_CARGO_LOCK_PIN.len())?
        || object_size > OPENAPI_CARGO_LOCK_PIN_MAX_BYTES
    {
        return Err(format!(
            "OpenAPI Cargo.lock pin Git blob has {object_size} bytes; expected exactly {}",
            OPENAPI_CARGO_LOCK_PIN.len()
        )
        .into());
    }
    let committed_pin = git_stdout(
        repo_root,
        &[OsString::from("cat-file"), OsString::from("blob"), object],
    )?;
    if u64::try_from(committed_pin.len())? != object_size {
        return Err("OpenAPI Cargo.lock pin Git blob changed while it was read".into());
    }
    if committed_pin != OPENAPI_CARGO_LOCK_PIN {
        return Err(
            "OpenAPI Cargo.lock pin at the generator commit differs from the compiled V1 pin"
                .into(),
        );
    }
    parse_openapi_cargo_lock_pin(&committed_pin)
}
fn read_working_openapi_cargo_lock_pin(
    repo_root: &Path,
) -> Result<OpenApiCargoLockPinV1, Box<dyn Error>> {
    let path = repo_root.join(OPENAPI_CARGO_LOCK_PIN_PATH);
    let working_pin = read_openapi_input_stable_with_policy(
        &path,
        "working OpenAPI Cargo.lock pin",
        OPENAPI_CARGO_LOCK_PIN_MAX_BYTES,
        true,
        true,
    )?;
    if working_pin != OPENAPI_CARGO_LOCK_PIN {
        return Err(
            "working OpenAPI Cargo.lock pin differs from the pin compiled into xtask".into(),
        );
    }
    parse_openapi_cargo_lock_pin(&working_pin)
}
fn read_openapi_generator_tracked_input(
    repo_root: &Path,
    commit: &str,
    expected_blob_oid: &str,
    pin: &OpenApiCargoLockPinV1,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let index_entry = git_stdout(
        repo_root,
        &[
            "ls-files",
            "--stage",
            "-z",
            "--",
            OPENAPI_GENERATOR_TRACKED_INPUT,
        ],
    )?;
    let generator_tree_entry = git_stdout(
        repo_root,
        &[
            "ls-tree",
            "-z",
            "--full-tree",
            commit,
            "--",
            OPENAPI_GENERATOR_TRACKED_INPUT,
        ],
    )?;
    let head_tree_entry = git_stdout(
        repo_root,
        &[
            "ls-tree",
            "-z",
            "--full-tree",
            "HEAD",
            "--",
            OPENAPI_GENERATOR_TRACKED_INPUT,
        ],
    )?;
    let index_blob_oid = parse_openapi_cargo_lock_index_entry(&index_entry)?;
    let generator_blob_oid =
        parse_openapi_cargo_lock_tree_entry(&generator_tree_entry, "generator Git tree")?;
    let head_blob_oid = parse_openapi_cargo_lock_tree_entry(&head_tree_entry, "HEAD Git tree")?;
    if generator_blob_oid != expected_blob_oid
        || index_blob_oid != generator_blob_oid
        || generator_blob_oid != head_blob_oid
    {
        return Err(
            "OpenAPI Cargo.lock must reference the same blob in the index, generator Git tree, and HEAD Git tree"
                .into(),
        );
    }
    let committed = git_stdout(
        repo_root,
        &[
            OsString::from("cat-file"),
            OsString::from("blob"),
            OsString::from(generator_blob_oid),
        ],
    )?;
    if committed.is_empty()
        || u64::try_from(committed.len())? > OPENAPI_GENERATOR_TRACKED_INPUT_MAX_BYTES
    {
        return Err(format!(
            "tracked OpenAPI generator Cargo.lock Git blob must contain 1..={OPENAPI_GENERATOR_TRACKED_INPUT_MAX_BYTES} bytes"
        )
        .into());
    }
    let path = repo_root.join(OPENAPI_GENERATOR_TRACKED_INPUT);
    let working = read_openapi_input_stable_with_policy(
        &path,
        "tracked OpenAPI generator Cargo lock",
        OPENAPI_GENERATOR_TRACKED_INPUT_MAX_BYTES,
        false,
        true,
    )?;
    if working != committed {
        return Err(
            "tracked OpenAPI generator Cargo.lock working bytes must equal the authenticated Git blob"
                .into(),
        );
    }
    if u64::try_from(committed.len())? != pin.bytes {
        return Err(format!(
            "tracked OpenAPI generator Cargo.lock has {} bytes; expected exactly {}",
            committed.len(),
            pin.bytes
        )
        .into());
    }
    let digest = hex::encode(Sha256::digest(&committed));
    if digest != pin.sha256_hex {
        return Err(format!(
            "tracked OpenAPI generator Cargo.lock SHA-256 {digest} does not match pinned {}",
            pin.sha256_hex
        )
        .into());
    }
    Ok(committed)
}
fn parse_openapi_cargo_lock_index_entry(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let entry = parse_single_nul_git_entry(bytes, "OpenAPI Cargo.lock Git index")?;
    let (metadata, path) = entry
        .split_once('\t')
        .ok_or("OpenAPI Cargo.lock Git index entry is missing its path separator")?;
    if path != OPENAPI_GENERATOR_TRACKED_INPUT {
        return Err("OpenAPI Cargo.lock Git index entry has a noncanonical root path".into());
    }
    let fields = metadata.split(' ').collect::<Vec<_>>();
    if fields.len() != 3
        || fields[0] != "100644"
        || !is_lower_hex_digest(fields[1], 20)
        || fields[1].bytes().all(|byte| byte == b'0')
        || fields[2] != "0"
    {
        return Err("OpenAPI Cargo.lock index must be one stage-zero 100644 blob".into());
    }
    Ok(fields[1].to_owned())
}
fn parse_openapi_cargo_lock_tree_entry(
    bytes: &[u8],
    label: &str,
) -> Result<String, Box<dyn Error>> {
    let entry = parse_single_nul_git_entry(bytes, label)?;
    let (metadata, path) = entry
        .split_once('\t')
        .ok_or_else(|| format!("OpenAPI Cargo.lock {label} entry is missing its path separator"))?;
    if path != OPENAPI_GENERATOR_TRACKED_INPUT {
        return Err(
            format!("OpenAPI Cargo.lock {label} entry has a noncanonical root path").into(),
        );
    }
    let fields = metadata.split(' ').collect::<Vec<_>>();
    if fields.len() != 3
        || fields[0] != "100644"
        || fields[1] != "blob"
        || !is_lower_hex_digest(fields[2], 20)
        || fields[2].bytes().all(|byte| byte == b'0')
    {
        return Err(
            format!("OpenAPI Cargo.lock must be one canonical 100644 blob in the {label}").into(),
        );
    }
    Ok(fields[2].to_owned())
}
fn parse_single_nul_git_entry<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, Box<dyn Error>> {
    if !bytes.ends_with(&[0]) || bytes[..bytes.len().saturating_sub(1)].contains(&0) {
        return Err(
            format!("{label} evidence must contain exactly one NUL-terminated entry").into(),
        );
    }
    std::str::from_utf8(&bytes[..bytes.len() - 1])
        .map_err(|err| format!("{label} evidence is not UTF-8: {err}").into())
}
fn validate_openapi_generator_input_inventory() -> Result<Vec<&'static str>, Box<dyn Error>> {
    let inventory = std::str::from_utf8(OPENAPI_GENERATOR_INPUT_INVENTORY)
        .map_err(|err| format!("OpenAPI generator input inventory is not UTF-8: {err}"))?;
    if inventory.contains('\r') || !inventory.ends_with('\n') {
        return Err(
            "OpenAPI generator input inventory must use LF endings and one final newline".into(),
        );
    }
    let mut lines = inventory.lines();
    if lines.next() != Some(OPENAPI_GENERATOR_INPUT_INVENTORY_HEADER) {
        return Err("OpenAPI generator input inventory has an invalid schema header".into());
    }
    let paths = lines.collect::<Vec<_>>();
    if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(
            "OpenAPI generator input inventory paths must be strictly sorted and unique".into(),
        );
    }
    if paths != OPENAPI_GENERATOR_INPUT_PATHS {
        return Err(
            "OpenAPI generator input inventory does not match the exact V1 release-input contract"
                .into(),
        );
    }
    for path in &paths {
        if path.is_empty()
            || path.starts_with('/')
            || path.ends_with('/')
            || path.contains('\\')
            || path
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(format!(
                "OpenAPI generator input inventory contains a noncanonical path `{path}`"
            )
            .into());
        }
    }
    Ok(paths)
}
fn git_head_timestamp_ms(repo_root: &Path) -> Result<u64, Box<dyn Error>> {
    let timestamp = git_stdout(repo_root, &["show", "-s", "--format=%ct", "HEAD"])?;
    let seconds = std::str::from_utf8(&timestamp)
        .map_err(|err| format!("git HEAD timestamp is not valid UTF-8: {err}"))?
        .trim()
        .parse::<u64>()
        .map_err(|err| format!("git HEAD timestamp is not an unsigned integer: {err}"))?;
    seconds
        .checked_mul(1_000)
        .filter(|milliseconds| *milliseconds > 0)
        .ok_or_else(|| "git HEAD timestamp cannot be represented as positive milliseconds".into())
}
fn git_source_pathspecs(
    repo_root: &Path,
    excluded_paths: &[PathBuf],
) -> Result<Vec<OsString>, Box<dyn Error>> {
    let canonical_root = repo_root.canonicalize().map_err(|err| {
        format!(
            "failed to canonicalize git source root {}: {err}",
            repo_root.display()
        )
    })?;
    let mut relative_exclusions = Vec::new();
    for path in excluded_paths {
        let absolute = if path.is_absolute() {
            path.clone()
        } else {
            repo_root.join(path)
        };
        let relative = absolute
            .strip_prefix(repo_root)
            .or_else(|_| absolute.strip_prefix(&canonical_root));
        let Ok(relative) = relative else { continue };
        if relative.as_os_str().is_empty() {
            return Err("refusing to exclude the entire repository from source provenance".into());
        }
        let relative = relative
            .to_str()
            .ok_or_else(|| {
                format!(
                    "OpenAPI generator output path is not valid UTF-8: {}",
                    relative.display()
                )
            })?
            .replace('\\', "/");
        relative_exclusions.push(relative);
    }
    relative_exclusions.sort();
    relative_exclusions.dedup();
    let mut pathspecs = vec![OsString::from("--"), OsString::from(".")];
    pathspecs.extend(
        relative_exclusions
            .into_iter()
            .map(|path| OsString::from(format!(":(exclude,literal){path}"))),
    );
    Ok(pathspecs)
}
fn git_stdout<S: AsRef<OsStr>>(repo_root: &Path, args: &[S]) -> Result<Vec<u8>, Box<dyn Error>> {
    let rendered_args = args
        .iter()
        .map(|arg| arg.as_ref().to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let output = openapi_git::command()
        .current_dir(repo_root)
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute git {rendered_args}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed with status {}: {}",
            rendered_args,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(output.stdout)
}
fn update_sha256_component(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}
#[cfg(unix)]
fn git_path_from_bytes(bytes: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}
#[cfg(not(unix))]
fn git_path_from_bytes(bytes: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
    let path = std::str::from_utf8(bytes)
        .map_err(|err| format!("git returned a non-UTF-8 untracked path: {err}"))?;
    Ok(PathBuf::from(path))
}
fn hash_untracked_path(hasher: &mut Sha256, path: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "failed to inspect untracked source path {}: {err}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|err| {
            format!(
                "failed to read untracked source symlink {}: {err}",
                path.display()
            )
        })?;
        update_sha256_component(hasher, b"untracked-kind", b"symlink");
        update_sha256_os_str_component(hasher, b"untracked-symlink-target", target.as_os_str());
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(format!(
            "unsupported untracked source path type for {}",
            path.display()
        )
        .into());
    }
    update_sha256_component(hasher, b"untracked-kind", b"file");
    update_sha256_component(hasher, b"untracked-size", &metadata.len().to_le_bytes());
    let mut file = fs::File::open(path).map_err(|err| {
        format!(
            "failed to read untracked source file {}: {err}",
            path.display()
        )
    })?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        use std::io::Read as _;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(())
}
fn update_sha256_os_str_component(hasher: &mut Sha256, label: &[u8], value: &OsStr) {
    #[cfg(unix)]
    {
        update_sha256_component(hasher, label, value.as_bytes());
    }
    #[cfg(not(unix))]
    {
        update_sha256_component(hasher, label, value.to_string_lossy().as_bytes());
    }
}
#[cfg(test)]
mod kagami_profiles_cli_tests {
    use super::*;

    fn arguments() -> Vec<String> {
        [
            "xtask",
            "kagami-profiles",
            "--profile",
            "iroha3-dev",
            "--xor-allocations-dir",
            "allocations",
            "--genesis-creation-time-ms",
            "1700000000000",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    #[test]
    fn profiles_require_explicit_genesis_creation_time() {
        let CommandKind::KagamiProfiles { options } =
            parse_command(arguments().into_iter()).expect("ordinary profile selection")
        else {
            panic!("expected profile generation");
        };
        assert_eq!(options.genesis_creation_time_ms, 1_700_000_000_000);
    }

    #[test]
    fn creation_time_cannot_be_supplied_twice() {
        let mut args = arguments();
        args.extend(["--genesis-creation-time-ms".into(), "1700000000000".into()]);
        let error = match parse_command(args.into_iter()) {
            Ok(_) => panic!("duplicate creation time must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "--genesis-creation-time-ms may be supplied only once"
        );
    }

    #[test]
    fn creation_time_is_required_canonical_nonzero_and_bounded() {
        let mut args = arguments();
        args.truncate(args.len() - 2);
        assert!(parse_command(args.into_iter()).is_err());
        for record in ["0", "01", "+1", " 1", "18446744073709551616", "１２"] {
            let mut args = arguments();
            *args.last_mut().unwrap() = record.into();
            assert!(parse_command(args.into_iter()).is_err(), "{record}");
        }
    }
}

#[cfg(test)]
mod acceleration_state_tests {
    use super::*;
    use norito::json::Value;
    use soranet_pq::MlDsaSuite;
    #[test]
    fn parse_rejects_retired_nexus_commitment_fixture_generator() {
        let error = match parse_command(["xtask", "nexus-fixtures"].into_iter().map(String::from)) {
            Ok(_) => panic!("retired lane commitment generator must not be accepted"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "unknown command: nexus-fixtures");
    }

    #[test]
    fn parse_nexus_lane_maintenance_read_only_inventory() {
        let command = parse_command(
            ["xtask", "nexus-lane-maintenance", "--config", "config.toml"]
                .into_iter()
                .map(String::from),
        )
        .expect("read-only inventory command");
        let CommandKind::NexusLaneMaintenance { options } = command else {
            panic!("expected lane inventory");
        };
        assert!(options.config_path.ends_with("config.toml"));
    }

    #[test]
    fn parse_nexus_lane_maintenance_rejects_file_output() {
        let error = match parse_command(
            [
                "xtask",
                "nexus-lane-maintenance",
                "--config",
                "config.toml",
                "--json-out",
                "blocks/canonical/blocks.data",
            ]
            .into_iter()
            .map(String::from),
        ) {
            Ok(_) => panic!("read-only maintenance must not open an output file"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "unknown flag for nexus-lane-maintenance: --json-out"
        );
    }

    #[test]
    fn parse_nexus_lane_maintenance_rejects_compaction() {
        let error = match parse_command(
            [
                "xtask",
                "nexus-lane-maintenance",
                "--config",
                "config.toml",
                "--compact-retired",
            ]
            .into_iter()
            .map(String::from),
        ) {
            Ok(_) => panic!("config-only storage mutation must not be accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "unknown flag for nexus-lane-maintenance: --compact-retired"
        );
    }

    #[test]
    fn parse_supports_acceleration_state_command() {
        let args = ["xtask", "acceleration-state", "--format", "json"];
        let iter = args.into_iter().map(String::from);
        let command = parse_command(iter).expect("parse acceleration-state command");
        match command {
            CommandKind::AccelerationState {
                format: AccelerationOutputFormat::Json,
            } => {}
            _ => panic!("expected acceleration-state command"),
        }
    }
    #[test]
    fn parse_fastpq_manifest_verification_requires_external_trust() {
        let args = [
            "xtask",
            "fastpq-verify-bench-manifest",
            "--manifest",
            "capture.json",
        ];
        assert!(parse_command(args.into_iter().map(String::from)).is_err());
        let args = [
            "xtask",
            "fastpq-verify-bench-manifest",
            "--manifest",
            "capture.json",
            "--trusted-public-key",
            "external-release-key",
        ];
        match parse_command(args.into_iter().map(String::from)).expect("verification command") {
            CommandKind::FastpqVerifyBenchManifest {
                manifest,
                trusted_public_key,
            } => {
                assert!(manifest.ends_with("capture.json"));
                assert_eq!(trusted_public_key, "external-release-key");
            }
            _ => panic!("expected manifest verification"),
        }
    }
    #[test]
    fn parse_gateway_pq_requires_and_routes_explicit_issuer_trust() {
        let issuer_ed25519_hex = "11".repeat(ed25519_dalek::PUBLIC_KEY_LENGTH);
        let issuer_mldsa65_hex = "22".repeat(MlDsaSuite::MlDsa65.public_key_len());
        let args = vec![
            "xtask".to_owned(),
            "soranet-gateway-pq".to_owned(),
            "--srcv2".to_owned(),
            "relay.srcv2.cbor".to_owned(),
            "--issuer-ed25519-hex".to_owned(),
            issuer_ed25519_hex.clone(),
            "--issuer-mldsa65-hex".to_owned(),
            issuer_mldsa65_hex.clone(),
            "--tls-bundle".to_owned(),
            "tls".to_owned(),
            "--trustless-config".to_owned(),
            "trustless.toml".to_owned(),
            "--at-unix".to_owned(),
            "1734000001".to_owned(),
        ];
        let command = parse_command(args.into_iter()).expect("parse gateway PQ command");
        let CommandKind::SoranetGatewayPq { options } = command else {
            panic!("expected gateway PQ command");
        };
        assert_eq!(options.issuer_ed25519_hex, issuer_ed25519_hex);
        assert_eq!(options.issuer_mldsa65_hex, issuer_mldsa65_hex);
        assert_eq!(options.at_unix, 1_734_000_001);

        let missing_time = vec![
            "xtask".to_owned(),
            "soranet-gateway-pq".to_owned(),
            "--srcv2".to_owned(),
            "relay.srcv2.cbor".to_owned(),
            "--issuer-ed25519-hex".to_owned(),
            issuer_ed25519_hex.clone(),
            "--issuer-mldsa65-hex".to_owned(),
            issuer_mldsa65_hex.clone(),
            "--tls-bundle".to_owned(),
            "tls".to_owned(),
            "--trustless-config".to_owned(),
            "trustless.toml".to_owned(),
        ];
        let error = match parse_command(missing_time.into_iter()) {
            Ok(_) => panic!("certificate evaluation time must be mandatory"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--at-unix"));

        let missing_issuer = [
            "xtask",
            "soranet-gateway-pq",
            "--srcv2",
            "relay.srcv2.cbor",
            "--tls-bundle",
            "tls",
            "--trustless-config",
            "trustless.toml",
        ];
        let error = match parse_command(missing_issuer.into_iter().map(str::to_owned)) {
            Ok(_) => panic!("issuer trust must be mandatory"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--issuer-ed25519-hex"));
    }
    #[test]
    fn parse_routes_nexus_connect_fixture_to_the_closed_owner() {
        let root = workspace_root();
        let args = vec![
            "xtask".to_owned(),
            "nexus-connect-fixture".to_owned(),
            "--check".to_owned(),
            "--output-root".to_owned(),
            root.to_string_lossy().into_owned(),
        ];
        let command = parse_command(args.into_iter()).expect("parse Nexus fixture command");
        let CommandKind::NexusConnectFixture { options } = command else {
            panic!("expected Nexus Connect fixture command");
        };
        assert_eq!(options.mode, nexus::NexusConnectFixtureMode::Check);
        assert_eq!(options.output_root, Some(root));
        let printed = parse_command(
            ["xtask", "nexus-connect-fixture", "--print"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("parse native stdout command");
        let CommandKind::NexusConnectFixture { options } = printed else {
            panic!("expected Nexus Connect fixture command");
        };
        assert_eq!(options.mode, nexus::NexusConnectFixtureMode::Print);
        assert_eq!(options.output_root, None);
    }
    #[test]
    fn parse_fastpq_cuda_suite_operation_updates_default_artifact_names() {
        let args = ["xtask", "fastpq-cuda-suite", "--operation", "lde"];
        let iter = args.into_iter().map(String::from);
        let command = parse_command(iter).expect("parse fastpq-cuda-suite");
        match command {
            CommandKind::FastpqCudaSuite { options } => {
                let output = options
                    .output
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("output filename");
                let raw_output = options
                    .raw_output
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("raw output filename");
                assert!(
                    output.starts_with("fastpq_cuda_bench_lde_"),
                    "unexpected output filename: {output}"
                );
                assert!(
                    raw_output.starts_with("fastpq_cuda_bench_lde_"),
                    "unexpected raw output filename: {raw_output}"
                );
                assert!(
                    raw_output.ends_with("_raw.json"),
                    "unexpected raw output filename: {raw_output}"
                );
            }
            _ => panic!("expected fastpq-cuda-suite command"),
        }
    }
    #[test]
    fn parse_sorafs_gateway_attest_verify_command() {
        let args = [
            "xtask",
            "sorafs-gateway-attest",
            "--verify",
            "attestation.to",
        ];
        let iter = args.into_iter().map(String::from);
        let command = parse_command(iter).expect("parse sorafs-gateway-attest verify");
        match command {
            CommandKind::SorafsGatewayAttestVerify { envelope } => {
                assert!(
                    envelope.ends_with("attestation.to"),
                    "unexpected envelope path: {}",
                    envelope.display()
                );
            }
            _ => panic!("expected sorafs-gateway-attest verify command"),
        }
    }
    #[test]
    fn parse_sorafs_gateway_attest_verify_rejects_generation_flags() {
        let args = [
            "xtask",
            "sorafs-gateway-attest",
            "--verify",
            "attestation.to",
            "--signing-key",
            "key.hex",
        ];
        let iter = args.into_iter().map(String::from);
        let err = match parse_command(iter) {
            Ok(_) => panic!("verify mode must reject generation flags"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("cannot be combined"),
            "unexpected error: {message}"
        );
    }
    #[test]
    fn render_outputs_include_last_error() {
        let config = ivm::AccelerationConfig {
            enable_simd: true,
            enable_metal: true,
            enable_cuda: false,
            max_gpus: Some(2),
            merkle_min_leaves_gpu: Some(4_096),
            ..Default::default()
        };
        let runtime = ivm::AccelerationRuntimeStatus {
            simd: ivm::BackendRuntimeStatus {
                supported: true,
                configured: true,
                available: true,
                parity_ok: true,
            },
            metal: ivm::BackendRuntimeStatus {
                supported: true,
                configured: true,
                available: false,
                parity_ok: true,
            },
            cuda: ivm::BackendRuntimeStatus {
                supported: false,
                configured: false,
                available: false,
                parity_ok: false,
            },
        };
        let errors = ivm::AccelerationErrorStatus {
            simd: None,
            metal: Some("policy disabled".to_string()),
            cuda: None,
        };
        let state = AccelerationStateReport::from_parts(config, runtime, errors);
        let table =
            render_acceleration_state(&state, AccelerationOutputFormat::Table).expect("render");
        assert!(
            table.contains("policy disabled"),
            "table output should include last error"
        );
        assert!(
            table.contains("max_gpus: 2"),
            "table output should include config values"
        );
        let json =
            render_acceleration_state(&state, AccelerationOutputFormat::Json).expect("render json");
        let parsed: Value = json::from_str(&json).expect("json parse");
        assert_eq!(parsed["config"]["max_gpus"], norito::json!(2));
        assert_eq!(parsed["config"]["enable_simd"], norito::json!(true));
        assert_eq!(parsed["simd"]["supported"], norito::json!(true));
        assert_eq!(parsed["metal"]["supported"], norito::json!(true));
        assert_eq!(parsed["cuda"]["supported"], norito::json!(false));
        assert_eq!(
            parsed["metal"]["last_error"],
            norito::json!("policy disabled")
        );
        assert_eq!(parsed["simd"]["last_error"], json::Value::Null);
    }
}
#[cfg(test)]
mod openapi_tests {
    use super::*;
    use tempfile::tempdir;
    const RELEASE_OPENAPI_FIXTURE: &[u8] = br#"{
  "openapi": "3.1.0",
  "info": {"title": "Torii fixture", "version": "1.0.0"},
  "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
  "components": {"schemas": {"Health": {"type": "object"}}}
}"#;
    const ALTERED_RELEASE_OPENAPI_FIXTURE: &[u8] = br#"{
  "openapi": "3.1.0",
  "info": {"title": "Torii fixture", "version": "1.0.1"},
  "paths": {"/status": {"get": {"responses": {"200": {"description": "ok"}}}}},
  "components": {"schemas": {"Status": {"type": "object"}}}
}"#;
    fn write_release_openapi_fixture(path: &Path) {
        fs::write(path, RELEASE_OPENAPI_FIXTURE).expect("write release OpenAPI fixture");
    }
    fn empty_openapi_stub() -> Value {
        json::from_slice(
            br#"{
  "openapi": "3.1.0",
  "info": {"title": "Torii fixture", "version": "1.0.0"},
  "paths": {},
  "components": {}
}"#,
        )
        .expect("parse empty OpenAPI fixture")
    }
    fn clean_generator_provenance() -> OpenApiGeneratorProvenance {
        OpenApiGeneratorProvenance {
            generated_unix_ms: 1_700_000_000_000,
            commit: Some("11".repeat(20)),
            dirty: false,
            source_sha256_hex: Some("22".repeat(32)),
        }
    }
    #[test]
    fn manifest_v2_signing_payload_matches_the_cross_language_fixture() {
        const ARTIFACT: &[u8] = b"OpenAPI V2 deterministic fixture\n";
        let manifest = OpenApiManifest {
            version: OPENAPI_MANIFEST_VERSION,
            generated_unix_ms: 1_700_000_000_000,
            generator_commit: Some("11".repeat(20)),
            generator_dirty: false,
            generator_source_sha256_hex: Some("22".repeat(32)),
            artifact: OpenApiArtifact {
                path: "torii.json".to_owned(),
                bytes: u64::try_from(ARTIFACT.len()).expect("fixture length"),
                sha256_hex: hex::encode(Sha256::digest(ARTIFACT)),
                blake3_hex: "d39d778cc128eafcfb89fbc286690120032a99eff18ffdec08c2a373e8618d41"
                    .to_owned(),
                signature: None,
            },
        };
        assert_eq!(
            manifest.artifact.blake3_hex,
            "d39d778cc128eafcfb89fbc286690120032a99eff18ffdec08c2a373e8618d41"
        );
        let payload = encode_openapi_manifest_signing_payload(&manifest, ARTIFACT)
            .expect("encode deterministic V2 signing payload");
        assert_eq!(
            hex::encode(Sha256::digest(payload)),
            "775b7af4c2c8a98dc49cf117745f0032f5064485b82a807f946a71b27539b9cd"
        );
    }
    #[test]
    fn openapi_generator_input_closure_matches_the_cross_language_fixture() {
        assert_eq!(
            openapi_generator_input_closure_sha256(b"tree-fixture-v1\0", b"lock-fixture-v1\n"),
            "5034e34e44a804546302178b2f13468096663997b2074ef0a2fe6916f654e080"
        );
    }
    #[test]
    fn openapi_cargo_lock_pin_parser_requires_the_canonical_v1_profile() {
        let pin =
            parse_openapi_cargo_lock_pin(OPENAPI_CARGO_LOCK_PIN).expect("parse canonical pin");
        assert!(pin.bytes > 0);
        assert!(pin.bytes <= OPENAPI_GENERATOR_TRACKED_INPUT_MAX_BYTES);
        assert!(is_lower_hex_digest(&pin.sha256_hex, 32));
        assert!(!pin.sha256_hex.bytes().all(|byte| byte == b'0'));
        let canonical = std::str::from_utf8(OPENAPI_CARGO_LOCK_PIN).expect("UTF-8 canonical pin");
        for (changed, expected) in [
            (
                OPENAPI_CARGO_LOCK_PIN[..OPENAPI_CARGO_LOCK_PIN.len() - 1].to_vec(),
                "one final newline",
            ),
            (
                canonical
                    .replace(OPENAPI_CARGO_LOCK_PIN_SCHEMA, "iroha.openapi.cargo-lock.v2")
                    .into_bytes(),
                "invalid schema",
            ),
            (
                canonical
                    .replace(&format!("bytes={}", pin.bytes), "bytes=0")
                    .into_bytes(),
                "noncanonical bytes",
            ),
            (
                canonical
                    .replace(&pin.sha256_hex, &"0".repeat(64))
                    .into_bytes(),
                "nonzero",
            ),
        ] {
            let error =
                parse_openapi_cargo_lock_pin(&changed).expect_err("substituted pin must fail");
            assert!(
                error.to_string().contains(expected),
                "unexpected pin error for {changed:?}: {error}"
            );
        }
    }
    fn initialize_git_fixture(root: &Path) {
        git_stdout(root, &["init", "--quiet"]).expect("initialize git fixture");
        const DIRECTORY_INPUTS: &[&str] = &[
            "IrohaSwift",
            "ci",
            "crates",
            "csharp",
            "data_model",
            "fixtures",
            "integration_tests",
            "java/iroha_android",
            "java/norito_java",
            "javascript/iroha_js",
            "kotlin",
            "mochi",
            "python/iroha_python",
            "python/iroha_torii_client",
            "scripts",
            "specs/sdk/android/generated",
            "tools",
            "vendor",
            "xtask",
        ];
        for relative in OPENAPI_GENERATOR_INPUT_PATHS {
            let target = root.join(relative);
            if DIRECTORY_INPUTS.contains(relative) {
                fs::create_dir_all(&target).expect("create generator input directory");
                fs::write(target.join(".fixture"), b"fixture\n")
                    .expect("write generator input directory fixture");
            } else {
                fs::create_dir_all(target.parent().expect("generator input has a parent"))
                    .expect("create generator input parent");
                if *relative == OPENAPI_GENERATOR_TRACKED_INPUT {
                    fs::copy(
                        workspace_root().join(OPENAPI_GENERATOR_TRACKED_INPUT),
                        &target,
                    )
                    .expect("copy canonical tracked Cargo lock fixture");
                } else {
                    let bytes = if *relative == OPENAPI_CARGO_LOCK_PIN_PATH {
                        OPENAPI_CARGO_LOCK_PIN
                    } else if *relative == "release/openapi-generator-inputs-v1.txt" {
                        OPENAPI_GENERATOR_INPUT_INVENTORY
                    } else {
                        b"fixture\n"
                    };
                    fs::write(target, bytes).expect("write generator input fixture");
                }
            }
        }
        fs::write(root.join(".gitignore"), b"**/Cargo.lock\n!/Cargo.lock\n")
            .expect("write tracked root Cargo lock rule");
        fs::write(root.join("xtask/source.txt"), b"source-v1\n").expect("write fixture source");
        fs::create_dir_all(root.join("artifacts/openapi/versions/current"))
            .expect("create generated fixture directory");
        fs::write(
            root.join("artifacts/openapi/torii.json"),
            b"{\"version\":1}\n",
        )
        .expect("write generated fixture spec");
        fs::write(
            root.join("artifacts/openapi/manifest.json"),
            b"{\"generated_unix_ms\":1}\n",
        )
        .expect("write generated fixture manifest");
        git_stdout(root, &["add", "."]).expect("stage git fixture");
        git_stdout(
            root,
            &[
                "-c",
                "user.name=OpenAPI Test",
                "-c",
                "user.email=openapi-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        )
        .expect("commit git fixture");
    }
    #[test]
    fn openapi_cli_rejects_removed_stub_escape_hatch() {
        let args = ["xtask", "openapi", "--allow-stub"];
        let err = match parse_command(args.into_iter().map(String::from)) {
            Ok(_) => panic!("the removed stub escape hatch must stay unavailable"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("unknown flag for openapi"),
            "unexpected removed-flag error: {err}"
        );
    }
    #[test]
    fn openapi_output_root_binds_the_canonical_spec_and_manifest() {
        let args = [
            "xtask",
            "openapi",
            "--output-root",
            "staging/openapi",
            "--unsigned-manifest",
        ];
        let command = parse_command(args.into_iter().map(String::from))
            .expect("parse staging-root OpenAPI command");
        let CommandKind::OpenApi {
            outputs,
            canonical_spec,
            manifest,
            unsigned_manifest,
            ..
        } = command
        else {
            panic!("expected OpenAPI command");
        };
        let root = workspace_root().join("staging/openapi");
        assert_eq!(canonical_spec, root.join("torii.json"));
        assert_eq!(outputs, vec![root.join("torii.json")]);
        assert_eq!(manifest, root.join("manifest.json"));
        assert!(unsigned_manifest);
    }
    #[test]
    fn openapi_output_root_rejects_ambiguous_or_unsafe_paths() {
        for (args, expected) in [
            (
                vec![
                    "xtask",
                    "openapi",
                    "--output-root",
                    "staging/openapi",
                    "--output",
                    "other.json",
                ],
                "cannot be combined",
            ),
            (
                vec![
                    "xtask",
                    "openapi",
                    "--output-root",
                    "staging/openapi",
                    "--manifest",
                    "other.json",
                ],
                "cannot be combined",
            ),
            (
                vec![
                    "xtask",
                    "openapi",
                    "--output-root",
                    "staging/openapi",
                    "--output-root",
                    "staging/other",
                ],
                "only once",
            ),
            (
                vec!["xtask", "openapi", "--output-root", "."],
                "unambiguous directory path",
            ),
            (
                vec!["xtask", "openapi", "--output-root", "../escape"],
                "unambiguous directory path",
            ),
            (
                vec!["xtask", "openapi", "--output-root", ".git/openapi"],
                "Git metadata",
            ),
        ] {
            let error = match parse_command(args.iter().map(|arg| (*arg).to_owned())) {
                Ok(_) => panic!("ambiguous OpenAPI output layout must fail: {args:?}"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` for {args:?}, got {error}"
            );
        }
    }
    #[test]
    fn openapi_outputs_reject_manifest_and_duplicate_aliases() {
        for args in [
            vec![
                "xtask",
                "openapi",
                "--output",
                "artifacts/openapi/manifest.json",
            ],
            vec![
                "xtask",
                "openapi",
                "--output",
                "staging/torii.json",
                "--output",
                "staging/./torii.json",
            ],
            vec![
                "xtask",
                "openapi",
                "--unsigned-manifest",
                "--unsigned-manifest",
            ],
        ] {
            let error = match parse_command(args.iter().map(|arg| (*arg).to_owned())) {
                Ok(_) => panic!("aliased OpenAPI outputs must fail: {args:?}"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("alias") || error.to_string().contains("only once"),
                "unexpected duplicate/alias error for {args:?}: {error}"
            );
        }
    }
    #[test]
    fn empty_documents_fail_closed() {
        let empty = canonical_release_openapi(&empty_openapi_stub())
            .expect_err("an empty OpenAPI document must never be accepted");
        assert!(
            empty
                .to_string()
                .contains("empty/stub specifications are forbidden")
        );
    }
    #[test]
    fn compiled_torii_document_satisfies_release_validation() {
        let bytes = canonical_release_openapi(&iroha_torii::openapi::generate_spec())
            .expect("the compiled Torii OpenAPI authority must satisfy release validation");
        let spec = json::from_slice::<Value>(&bytes)
            .expect("validated Torii OpenAPI remains canonical JSON");
        openapi_validation::validate_release_openapi_spec(&spec)
            .expect("the canonicalized Torii document remains release-valid");
    }
    #[test]
    fn canonical_rendering_preserves_exact_integers() {
        let exact = br#"{
  "openapi": "3.1.0",
  "info": {"title": "Torii fixture", "version": "1.0.0"},
  "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
  "components": {"schemas": {"Height": {"type": "integer", "maximum": 18446744073709551615}}}
}"#;
        let parsed = json::from_slice::<Value>(exact).expect("parse OpenAPI fixture");
        let emitted = canonical_release_openapi(&parsed).expect("exact document must be accepted");
        let canonical = json::to_vec_pretty(&parsed).expect("render canonical fixture");

        assert_eq!(emitted, canonical);
        assert!(
            std::str::from_utf8(&emitted)
                .expect("canonical OpenAPI is UTF-8")
                .contains("18446744073709551615"),
            "canonicalization must preserve exact u64 JSON integers"
        );
        assert!(!emitted.ends_with(b"\n"));
    }
    // Direct fragment keeps this cohesive OpenAPI regression test together.
    include!("tests/openapi_empty_manifest_writers.rs");
    #[test]
    fn manifest_verifier_rejects_digest_matching_empty_openapi() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("torii.json");
        let stub_bytes = json::to_vec(&empty_openapi_stub()).expect("serialize empty OpenAPI");
        fs::write(&spec_path, &stub_bytes).expect("write empty OpenAPI");
        let manifest_path = tmp.path().join("manifest.json");
        let manifest = OpenApiManifest {
            version: OPENAPI_MANIFEST_VERSION,
            generated_unix_ms: 1,
            generator_commit: Some("11".repeat(20)),
            generator_dirty: false,
            generator_source_sha256_hex: Some("22".repeat(32)),
            artifact: OpenApiArtifact {
                path: "torii.json".to_owned(),
                bytes: stub_bytes.len() as u64,
                sha256_hex: hex::encode(Sha256::digest(&stub_bytes)),
                blake3_hex: blake3::hash(&stub_bytes).to_hex().to_string(),
                signature: None,
            },
        };
        fs::write(
            &manifest_path,
            json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write matching manifest");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect_err("digest-matching empty OpenAPI must not verify");
        assert!(
            err.to_string()
                .contains("empty/stub specifications are forbidden")
        );
    }
    #[test]
    fn manifest_signature_round_trip() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        fs::write(&spec_path, b"{\"ok\":true}").expect("write spec");
        let key_path = tmp.path().join("key.hex");
        let key_hex = hex::encode([0x11u8; 32]);
        fs::write(&key_path, key_hex).expect("write key");
        let payload = fs::read(&spec_path).expect("read spec");
        let signature = sign_manifest_payload_for_test(&payload, &key_path).expect("sign payload");
        verify_manifest_signature(&signature, &payload).expect("verify signature");
    }
    #[test]
    fn openapi_v2_signing_payload_matches_javascript_fixture() {
        let artifact = b"OpenAPI V2 deterministic fixture\n";
        let manifest = OpenApiManifest {
            version: OPENAPI_MANIFEST_VERSION,
            generated_unix_ms: 1_700_000_000_000,
            generator_commit: Some("11".repeat(20)),
            generator_dirty: false,
            generator_source_sha256_hex: Some("22".repeat(32)),
            artifact: OpenApiArtifact {
                path: "torii.json".to_owned(),
                bytes: artifact.len() as u64,
                sha256_hex: hex::encode(Sha256::digest(artifact)),
                blake3_hex: blake3::hash(artifact).to_hex().to_string(),
                signature: None,
            },
        };
        let payload = encode_openapi_manifest_signing_payload(&manifest, artifact)
            .expect("encode deterministic signing payload");
        assert_eq!(
            hex::encode(Sha256::digest(payload)),
            "775b7af4c2c8a98dc49cf117745f0032f5064485b82a807f946a71b27539b9cd"
        );
    }
    #[test]
    fn openapi_v2_manifest_deserialization_rejects_v1_and_unknown_fields() {
        let v1 = br#"{
  "version": 1,
  "generated_unix_ms": 1700000000000,
  "generator_commit": "1111111111111111111111111111111111111111",
  "generator_dirty": false,
  "artifact": {
    "path": "torii.json",
    "bytes": 1,
    "sha256_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "blake3_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "signature": null
  }
}"#;
        let parsed: OpenApiManifest =
            json::from_slice(v1).expect("V1 remains syntactically distinct");
        assert_ne!(parsed.version, OPENAPI_MANIFEST_VERSION);
        let err = encode_openapi_manifest_signing_payload(&parsed, b"x")
            .expect_err("V1 manifests must not produce a signing payload");
        assert!(err.to_string().contains("expected 2"));
        let unknown = br#"{
  "version": 2,
  "generated_unix_ms": 1700000000000,
  "generator_commit": "1111111111111111111111111111111111111111",
  "generator_dirty": false,
  "legacy_provenance": true,
  "artifact": {
    "path": "torii.json",
    "bytes": 1,
    "sha256_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "blake3_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "signature": null
  }
}"#;
        let err = json::from_slice::<OpenApiManifest>(unknown)
            .expect_err("unknown V1 compatibility fields must fail closed");
        assert!(err.to_string().contains("unknown field"));
    }
    #[test]
    fn detached_signature_envelope_writes_manifest() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let key_path = tmp.path().join("key.hex");
        let key_hex = hex::encode([0x22u8; 32]);
        fs::write(&key_path, key_hex).expect("write key");
        let payload = fs::read(&spec_path).expect("read spec");
        let unsigned = build_openapi_manifest(&spec_path, &payload, &clean_generator_provenance())
            .expect("build unsigned manifest");
        let signing_payload =
            encode_openapi_manifest_signing_payload(&unsigned, &payload).expect("encode payload");
        let signature =
            sign_manifest_payload_for_test(&signing_payload, &key_path).expect("sign payload");
        let envelope_path = tmp.path().join("signature.json");
        fs::write(
            &envelope_path,
            json::to_string_pretty(&signature).expect("serialize signature"),
        )
        .expect("write detached envelope");
        let manifest_path = tmp.path().join("manifest.json");
        let loaded = load_signature_envelope(&envelope_path).expect("load detached envelope");
        write_openapi_manifest_with_signature(
            &spec_path,
            &manifest_path,
            loaded,
            &clean_generator_provenance(),
            None,
        )
        .expect("write manifest with detached signature");
        verify_openapi_manifest(&spec_path, &manifest_path, false, None)
            .expect("verify detached manifest");
    }
    #[test]
    fn openapi_manifest_verifier_rejects_duplicate_json_members() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("torii.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest_unsigned(
            &spec_path,
            &manifest_path,
            &clean_generator_provenance(),
            None,
        )
        .expect("write unsigned manifest");
        let manifest = fs::read_to_string(&manifest_path).expect("read manifest");
        let duplicated =
            manifest.replacen("\"version\": 2,", "\"version\": 2,\n  \"version\": 2,", 1);
        fs::write(&manifest_path, duplicated).expect("write duplicate-key manifest");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect_err("duplicate JSON members must fail closed");
        assert!(
            err.to_string().contains("duplicate"),
            "unexpected duplicate-key manifest error: {err}"
        );
    }
    #[test]
    fn signature_envelope_reader_rejects_duplicate_json_members() {
        let tmp = tempdir().expect("tempdir");
        let envelope_path = tmp.path().join("signature.json");
        fs::write(
            &envelope_path,
            r#"{
  "algorithm": "ed25519",
  "algorithm": "ed25519",
  "public_key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "signature_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}"#,
        )
        .expect("write duplicate-key envelope");
        let err = load_signature_envelope(&envelope_path)
            .expect_err("duplicate signature-envelope members must fail closed");
        assert!(
            err.to_string().contains("duplicate"),
            "unexpected duplicate-key envelope error: {err}"
        );
    }
    #[test]
    fn openapi_local_signing_flag_is_removed() {
        let args = ["xtask", "openapi", "--sign", "signing.key"];
        let iter = args.into_iter().map(String::from);
        let err = match parse_command(iter) {
            Ok(_) => panic!("removed local signing mode must fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("unknown flag for openapi: --sign"),
            "expected removed flag rejection, got {message}"
        );
    }
    #[test]
    fn openapi_unsigned_manifest_mode_conflicts_with_signing() {
        let args = [
            "xtask",
            "openapi",
            "--unsigned-manifest",
            "--signature-envelope",
            "signature.json",
        ];
        let err = match parse_command(args.into_iter().map(String::from)) {
            Ok(_) => panic!("unsigned manifest and detached signature must fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("cannot be combined"),
            "expected cannot be combined message, got {message}"
        );
    }
    #[test]
    fn unsigned_openapi_manifest_verifies_when_allowed() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest_unsigned(
            &spec_path,
            &manifest_path,
            &clean_generator_provenance(),
            None,
        )
        .expect("write unsigned manifest");
        verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect("unsigned manifest should verify when allowed");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, false, None)
            .expect_err("unsigned manifest should fail without opt-in");
        let message = err.to_string();
        assert!(
            message.contains("missing signature"),
            "expected missing signature message, got {message}"
        );
    }
    #[test]
    fn unchanged_unsigned_openapi_manifest_write_is_byte_idempotent() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        let provenance = clean_generator_provenance();
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &provenance, None)
            .expect("write unsigned manifest");
        let expected_bytes = fs::read(&manifest_path).expect("read unsigned manifest");
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &provenance, None)
            .expect("rewrite unchanged unsigned manifest");
        assert_eq!(
            fs::read(&manifest_path).expect("read rewritten manifest"),
            expected_bytes,
            "an unchanged writer pass must be a byte-level no-op"
        );
    }
    #[test]
    fn changed_openapi_content_or_provenance_refreshes_manifest() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        let clean = clean_generator_provenance();
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &clean, None)
            .expect("write unsigned manifest");
        let mut manifest: OpenApiManifest =
            json::from_slice(&fs::read(&manifest_path).expect("read unsigned manifest"))
                .expect("parse unsigned manifest");
        let original_sha256 = manifest.artifact.sha256_hex.clone();
        fs::write(&spec_path, ALTERED_RELEASE_OPENAPI_FIXTURE).expect("alter OpenAPI fixture");
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &clean, None)
            .expect("rewrite content-changed manifest");
        manifest =
            json::from_slice(&fs::read(&manifest_path).expect("read content-changed manifest"))
                .expect("parse content-changed manifest");
        assert_eq!(manifest.generated_unix_ms, clean.generated_unix_ms);
        assert_ne!(manifest.artifact.sha256_hex, original_sha256);
        let dirty = OpenApiGeneratorProvenance {
            generated_unix_ms: clean.generated_unix_ms + 1,
            commit: None,
            dirty: true,
            source_sha256_hex: Some("ab".repeat(32)),
        };
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &dirty, None)
            .expect("rewrite provenance-changed manifest");
        manifest =
            json::from_slice(&fs::read(&manifest_path).expect("read provenance-changed manifest"))
                .expect("parse provenance-changed manifest");
        assert_eq!(manifest.generated_unix_ms, dirty.generated_unix_ms);
        assert!(manifest.generator_dirty);
        assert_eq!(manifest.generator_commit, None);
        assert_eq!(
            manifest.generator_source_sha256_hex,
            dirty.source_sha256_hex
        );
    }
    #[test]
    fn invalid_existing_openapi_timestamp_is_not_reused() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        let provenance = clean_generator_provenance();
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &provenance, None)
            .expect("write unsigned manifest");
        let mut manifest: OpenApiManifest =
            json::from_slice(&fs::read(&manifest_path).expect("read unsigned manifest"))
                .expect("parse unsigned manifest");
        manifest.generated_unix_ms = OPENAPI_MANIFEST_MAX_SAFE_INTEGER + 1;
        fs::write(
            &manifest_path,
            json::to_vec_pretty(&manifest).expect("serialize unsafe-time manifest"),
        )
        .expect("write unsafe-time manifest");
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &provenance, None)
            .expect("replace unsafe existing timestamp");
        let rewritten: OpenApiManifest =
            json::from_slice(&fs::read(&manifest_path).expect("read rewritten manifest"))
                .expect("parse rewritten manifest");
        assert_eq!(rewritten.generated_unix_ms, provenance.generated_unix_ms);
        assert!(rewritten.generated_unix_ms <= OPENAPI_MANIFEST_MAX_SAFE_INTEGER);
    }
    #[test]
    fn openapi_manifest_rejects_unknown_fields() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest_unsigned(
            &spec_path,
            &manifest_path,
            &clean_generator_provenance(),
            None,
        )
        .expect("write unsigned manifest");
        let mut manifest: json::Value =
            json::from_slice(&fs::read(&manifest_path).expect("read unsigned manifest"))
                .expect("parse unsigned manifest");
        manifest
            .as_object_mut()
            .expect("manifest must be an object")
            .insert("unexpected".to_owned(), norito::json!(true));
        fs::write(
            &manifest_path,
            json::to_vec_pretty(&manifest).expect("serialize malformed manifest"),
        )
        .expect("write malformed manifest");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect_err("unknown manifest fields must fail closed");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected unknown-field error: {err}"
        );
    }
    #[test]
    fn unsigned_openapi_manifest_still_checks_payload_integrity() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest_unsigned(
            &spec_path,
            &manifest_path,
            &clean_generator_provenance(),
            None,
        )
        .expect("write unsigned manifest");
        fs::write(&spec_path, ALTERED_RELEASE_OPENAPI_FIXTURE).expect("tamper spec");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect_err("allowing unsigned manifests must not allow stale digests");
        let message = err.to_string();
        assert!(
            message.contains("sha256_hex mismatch"),
            "expected digest mismatch message, got {message}"
        );
    }
    #[test]
    fn dirty_unsigned_openapi_manifest_records_explicit_source_provenance() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        let dirty = OpenApiGeneratorProvenance {
            generated_unix_ms: 1_700_000_000_000,
            commit: None,
            dirty: true,
            source_sha256_hex: Some("ab".repeat(32)),
        };
        write_openapi_manifest_unsigned(&spec_path, &manifest_path, &dirty, None)
            .expect("write dirty unsigned manifest");
        verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect("explicitly allowed dirty unsigned manifest should verify");
        let manifest: OpenApiManifest =
            json::from_slice(&fs::read(&manifest_path).expect("read dirty unsigned manifest"))
                .expect("parse dirty unsigned manifest");
        assert!(manifest.generator_dirty);
        assert_eq!(manifest.generator_commit, None);
        assert_eq!(
            manifest.generator_source_sha256_hex.as_deref(),
            Some("abababababababababababababababababababababababababababababababab")
        );
        let err = verify_openapi_manifest(&spec_path, &manifest_path, false, None)
            .expect_err("release verification must reject dirty provenance");
        assert!(
            err.to_string().contains("cannot be release-verified"),
            "unexpected dirty release error: {err}"
        );
    }
    #[test]
    fn openapi_manifest_rejects_ambiguous_or_forged_dirty_provenance() {
        for (name, provenance, expected) in [
            (
                "dirty-with-commit",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some("pretend-clean-head".to_owned()),
                    dirty: true,
                    source_sha256_hex: Some("ab".repeat(32)),
                },
                "must set generator_commit to null",
            ),
            (
                "dirty-without-digest",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: None,
                    dirty: true,
                    source_sha256_hex: None,
                },
                "missing generator_source_sha256_hex",
            ),
            (
                "dirty-with-uppercase-digest",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: None,
                    dirty: true,
                    source_sha256_hex: Some("AB".repeat(32)),
                },
                "64 lowercase hexadecimal",
            ),
            (
                "clean-without-source-digest",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some("11".repeat(20)),
                    dirty: false,
                    source_sha256_hex: None,
                },
                "missing generator_source_sha256_hex",
            ),
            (
                "clean-zero-source-digest",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some("11".repeat(20)),
                    dirty: false,
                    source_sha256_hex: Some("00".repeat(32)),
                },
                "64 lowercase hexadecimal",
            ),
            (
                "clean-short-commit",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some("ab".repeat(19)),
                    dirty: false,
                    source_sha256_hex: Some("ab".repeat(32)),
                },
                "exactly 40 lowercase hexadecimal",
            ),
            (
                "clean-uppercase-commit",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some("AB".repeat(20)),
                    dirty: false,
                    source_sha256_hex: Some("ab".repeat(32)),
                },
                "exactly 40 lowercase hexadecimal",
            ),
            (
                "clean-nonhex-commit",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some("gg".repeat(20)),
                    dirty: false,
                    source_sha256_hex: Some("ab".repeat(32)),
                },
                "exactly 40 lowercase hexadecimal",
            ),
            (
                "clean-padded-commit",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some(format!(" {} ", "ab".repeat(20))),
                    dirty: false,
                    source_sha256_hex: Some("ab".repeat(32)),
                },
                "exactly 40 lowercase hexadecimal",
            ),
            (
                "clean-zero-commit",
                OpenApiGeneratorProvenance {
                    generated_unix_ms: 1_700_000_000_000,
                    commit: Some("00".repeat(20)),
                    dirty: false,
                    source_sha256_hex: Some("ab".repeat(32)),
                },
                "nonzero Git commit",
            ),
        ] {
            let err = validate_openapi_generator_provenance(&provenance, true)
                .expect_err("malformed provenance must fail closed");
            assert!(
                err.to_string().contains(expected),
                "{name}: expected `{expected}`, got {err}"
            );
        }
    }
    #[test]
    fn signed_openapi_manifest_rejects_dirty_source_provenance() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let key_path = tmp.path().join("key.hex");
        fs::write(&key_path, hex::encode([0x77_u8; 32])).expect("write signing key");
        let manifest_path = tmp.path().join("manifest.json");
        let dirty = OpenApiGeneratorProvenance {
            generated_unix_ms: 1_700_000_000_000,
            commit: None,
            dirty: true,
            source_sha256_hex: Some("ab".repeat(32)),
        };
        let err = write_openapi_manifest(&spec_path, &manifest_path, &key_path, &dirty)
            .expect_err("dirty source must never produce a signed manifest");
        assert!(
            err.to_string().contains("cannot be release-verified"),
            "unexpected dirty signing error: {err}"
        );
        assert!(!manifest_path.exists());
    }
    #[test]
    fn git_source_provenance_excludes_only_generated_outputs_and_is_deterministic() {
        let tmp = tempdir().expect("tempdir");
        initialize_git_fixture(tmp.path());
        let generated = vec![
            tmp.path().join("artifacts/openapi/torii.json"),
            tmp.path().join("artifacts/openapi/manifest.json"),
            tmp.path()
                .join("artifacts/openapi/versions/current/torii.json"),
            tmp.path()
                .join("artifacts/openapi/versions/current/manifest.json"),
            tmp.path().join("artifacts/openapi/versions.json"),
        ];
        let clean = git_source_provenance(tmp.path(), &generated).expect("clean provenance");
        assert!(!clean.dirty);
        assert!(clean.commit.is_some());
        let expected_source_digest = git_openapi_generator_input_tree_sha256(
            tmp.path(),
            clean.commit.as_deref().expect("clean commit"),
        )
        .expect("generator input tree digest");
        assert_eq!(
            clean.source_sha256_hex.as_deref(),
            Some(expected_source_digest.as_str()),
            "clean provenance must bind the canonical generator input inventory"
        );
        assert_eq!(
            clean.generated_unix_ms,
            git_head_timestamp_ms(tmp.path()).expect("HEAD timestamp"),
            "generated_unix_ms must derive from immutable HEAD metadata"
        );
        fs::write(
            &generated[0],
            b"{\"version\":2,\"generated_unix_ms\":100}\n",
        )
        .expect("rewrite generated spec");
        fs::write(&generated[1], b"{\"generated_unix_ms\":100}\n")
            .expect("rewrite generated manifest");
        fs::write(&generated[4], b"{\"generatedAt\":100}\n")
            .expect("write untracked generated versions index");
        let generated_only =
            git_source_provenance(tmp.path(), &generated).expect("generated-only provenance");
        assert_eq!(
            generated_only, clean,
            "generated files are not source inputs"
        );
        fs::write(tmp.path().join("Cargo.lock"), b"fixture-lock-v2\n")
            .expect("change tracked Cargo lock");
        let lock_changed = git_source_provenance(tmp.path(), &generated)
            .expect_err("substituted tracked Cargo lock must fail");
        assert!(
            lock_changed
                .to_string()
                .contains("working bytes must equal the authenticated Git blob"),
            "unexpected substituted lock error: {lock_changed}"
        );
        fs::copy(
            workspace_root().join(OPENAPI_GENERATOR_TRACKED_INPUT),
            tmp.path().join(OPENAPI_GENERATOR_TRACKED_INPUT),
        )
        .expect("restore tracked Cargo lock");
        let lock_restored =
            git_source_provenance(tmp.path(), &generated).expect("restored lock provenance");
        assert_eq!(
            lock_restored, clean,
            "restoring the tracked Cargo lock must restore clean provenance"
        );
        fs::write(tmp.path().join("xtask/source.txt"), b"source-v2\n")
            .expect("modify tracked source");
        let first = git_source_provenance(tmp.path(), &generated).expect("first dirty provenance");
        assert!(first.dirty);
        assert_eq!(first.commit, None);
        assert!(first.source_sha256_hex.is_some());
        assert_eq!(
            first.generated_unix_ms, clean.generated_unix_ms,
            "dirty development generation must retain the deterministic HEAD timestamp"
        );
        fs::write(
            &generated[0],
            b"{\"version\":2,\"generated_unix_ms\":200}\n",
        )
        .expect("rewrite generated spec again");
        fs::write(&generated[1], b"{\"generated_unix_ms\":200}\n")
            .expect("rewrite generated manifest again");
        fs::write(&generated[4], b"{\"generatedAt\":200}\n")
            .expect("rewrite generated versions index");
        let second =
            git_source_provenance(tmp.path(), &generated).expect("second dirty provenance");
        assert_eq!(
            second.source_sha256_hex, first.source_sha256_hex,
            "identical source must retain its digest across generated timestamps"
        );
        fs::write(tmp.path().join("xtask/source.txt"), b"source-v3\n")
            .expect("change tracked source content");
        let changed =
            git_source_provenance(tmp.path(), &generated).expect("changed dirty provenance");
        assert_ne!(changed.source_sha256_hex, first.source_sha256_hex);
        fs::write(tmp.path().join("untracked-source.rs"), b"fn one() {}\n")
            .expect("write untracked source");
        let untracked_one =
            git_source_provenance(tmp.path(), &generated).expect("untracked provenance");
        fs::write(tmp.path().join("untracked-source.rs"), b"fn two() {}\n")
            .expect("change untracked source content");
        let untracked_two =
            git_source_provenance(tmp.path(), &generated).expect("changed untracked provenance");
        assert_ne!(
            untracked_two.source_sha256_hex, untracked_one.source_sha256_hex,
            "untracked non-output contents must be provenance-bound"
        );
    }
    #[test]
    fn dirty_unsigned_provenance_accepts_only_a_compiled_pin_repair_for_the_committed_lock() {
        let fixture = tempdir().expect("pin-repair tempdir");
        initialize_git_fixture(fixture.path());
        let pin_path = fixture.path().join(OPENAPI_CARGO_LOCK_PIN_PATH);
        let stale_pin = format!(
            "{OPENAPI_CARGO_LOCK_PIN_SCHEMA}\nbytes=1\nsha256_hex={}\n",
            "11".repeat(32)
        );
        fs::write(&pin_path, stale_pin).expect("write stale committed pin");
        git_stdout(fixture.path(), &["add", "--", OPENAPI_CARGO_LOCK_PIN_PATH])
            .expect("stage stale pin");
        git_stdout(
            fixture.path(),
            &[
                "-c",
                "user.name=OpenAPI Test",
                "-c",
                "user.email=openapi-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "stale pin",
            ],
        )
        .expect("commit stale pin");
        fs::write(&pin_path, OPENAPI_CARGO_LOCK_PIN).expect("restore compiled working pin");

        let provenance = git_source_provenance(fixture.path(), &[])
            .expect("dirty unsigned provenance with an exact compiled pin repair");
        assert!(provenance.dirty);
        assert_eq!(provenance.commit, None);
        assert!(provenance.source_sha256_hex.is_some());

        fs::write(&pin_path, b"not-the-compiled-pin\n").expect("substitute working pin");
        let error = git_source_provenance(fixture.path(), &[])
            .expect_err("an uncompiled working pin substitution must fail");
        assert!(
            error
                .to_string()
                .contains("differs from the pin compiled into xtask"),
            "unexpected working-pin substitution error: {error}"
        );
    }
    include!("tests/openapi_tracked_lock.rs");
    #[cfg(unix)]
    #[test]
    fn openapi_generator_pin_rejects_missing_executable_and_symlinked_git_blobs() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        for mutation in 0..3 {
            let fixture = tempdir().expect("pin tempdir");
            initialize_git_fixture(fixture.path());
            let pin = fixture.path().join(OPENAPI_CARGO_LOCK_PIN_PATH);
            match mutation {
                0 => {
                    fs::remove_file(&pin).expect("remove pin");
                    git_stdout(
                        fixture.path(),
                        &["rm", "--quiet", "--", OPENAPI_CARGO_LOCK_PIN_PATH],
                    )
                    .expect("stage removed pin");
                }
                1 => {
                    fs::set_permissions(&pin, fs::Permissions::from_mode(0o755))
                        .expect("make pin executable");
                    git_stdout(fixture.path(), &["add", "--", OPENAPI_CARGO_LOCK_PIN_PATH])
                        .expect("stage executable pin");
                }
                2 => {
                    fs::remove_file(&pin).expect("remove regular pin");
                    symlink("openapi-generator-inputs-v1.txt", &pin)
                        .expect("replace pin with symlink");
                    git_stdout(fixture.path(), &["add", "--", OPENAPI_CARGO_LOCK_PIN_PATH])
                        .expect("stage symlinked pin");
                }
                _ => unreachable!(),
            }
            git_stdout(
                fixture.path(),
                &[
                    "-c",
                    "user.name=OpenAPI Test",
                    "-c",
                    "user.email=openapi-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "mutate pin",
                ],
            )
            .expect("commit mutated pin");
            let head = std::str::from_utf8(
                &git_stdout(fixture.path(), &["rev-parse", "--verify", "HEAD"])
                    .expect("fixture HEAD"),
            )
            .expect("UTF-8 fixture HEAD")
            .trim()
            .to_owned();
            let error = git_openapi_generator_input_tree_sha256(fixture.path(), &head)
                .expect_err("invalid pin tree entry must fail");
            let expected = if mutation == 0 {
                "is missing"
            } else {
                "must have Git mode 100644"
            };
            assert!(
                error.to_string().contains(expected),
                "unexpected pin-tree error: {error}"
            );
        }
    }
    #[test]
    fn openapi_generator_rejects_generator_and_head_lock_blob_divergence() {
        let fixture = tempdir().expect("divergent lock tempdir");
        initialize_git_fixture(fixture.path());
        let generator_commit = std::str::from_utf8(
            &git_stdout(fixture.path(), &["rev-parse", "--verify", "HEAD"])
                .expect("generator HEAD"),
        )
        .expect("UTF-8 generator HEAD")
        .trim()
        .to_owned();
        fs::write(
            fixture.path().join(OPENAPI_GENERATOR_TRACKED_INPUT),
            b"substituted tracked lock\n",
        )
        .expect("substitute tracked Cargo lock");
        git_stdout(
            fixture.path(),
            &["add", "--", OPENAPI_GENERATOR_TRACKED_INPUT],
        )
        .expect("stage substituted Cargo lock");
        git_stdout(
            fixture.path(),
            &[
                "-c",
                "user.name=OpenAPI Test",
                "-c",
                "user.email=openapi-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "change tracked lock",
            ],
        )
        .expect("commit changed tracked lock");
        let error = git_openapi_generator_input_tree_sha256(fixture.path(), &generator_commit)
            .expect_err("generator and HEAD lock divergence must fail");
        assert!(
            error.to_string().contains("same blob in the index"),
            "unexpected divergent-lock error: {error}"
        );
    }
    #[test]
    fn detached_signature_envelope_must_match_spec_bytes() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let key_path = tmp.path().join("key.hex");
        let key_hex = hex::encode([0x55u8; 32]);
        fs::write(&key_path, key_hex).expect("write key");
        let other_payload = ALTERED_RELEASE_OPENAPI_FIXTURE;
        let other_manifest =
            build_openapi_manifest(&spec_path, other_payload, &clean_generator_provenance())
                .expect("build other manifest");
        let other_signing_payload =
            encode_openapi_manifest_signing_payload(&other_manifest, other_payload)
                .expect("encode other signing payload");
        let signature = sign_manifest_payload_for_test(&other_signing_payload, &key_path)
            .expect("sign payload");
        let manifest_path = tmp.path().join("manifest.json");
        let err = write_openapi_manifest_with_signature(
            &spec_path,
            &manifest_path,
            signature,
            &clean_generator_provenance(),
            None,
        )
        .expect_err("detached signature for another payload must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("manifest signature verification failed"),
            "expected signature verification failure, got {message}"
        );
        assert!(
            !manifest_path.exists(),
            "manifest must not be written after signature verification fails"
        );
    }
    #[test]
    fn openapi_allow_unsigned_still_rejects_invalid_signature() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let key_path = tmp.path().join("key.hex");
        let key_hex = hex::encode([0x66u8; 32]);
        fs::write(&key_path, key_hex).expect("write key");
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest(
            &spec_path,
            &manifest_path,
            &key_path,
            &clean_generator_provenance(),
        )
        .expect("sign manifest");
        let manifest_json = fs::read_to_string(&manifest_path).expect("manifest json");
        let mut manifest: OpenApiManifest =
            json::from_str(&manifest_json).expect("parse manifest json");
        let signature = manifest
            .artifact
            .signature
            .as_mut()
            .expect("signed manifest should include signature");
        signature.signature_hex = "00".repeat(signature.signature_hex.len() / 2);
        fs::write(
            &manifest_path,
            json::to_string_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("rewrite manifest");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect_err("allow-unsigned must not bypass invalid signatures");
        let message = err.to_string();
        assert!(
            message.contains("invalid manifest signature material"),
            "expected signature material rejection, got {message}"
        );
    }
    #[test]
    fn openapi_signature_envelope_rejects_malformed_ed25519_signature_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let tmp = tempdir().expect("tempdir");
        let key_path = tmp.path().join("key.hex");
        fs::write(&key_path, hex::encode([0x67u8; 32])).expect("write key");
        let payload = b"{\"ok\":true}";
        let signature = sign_manifest_payload_for_test(payload, &key_path).expect("sign payload");
        verify_manifest_signature(&signature, payload).expect("valid signature verifies");
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut malformed = signature.clone();
            let mut signature_bytes =
                hex::decode(&malformed.signature_hex).expect("decode signature hex");
            signature_bytes[..32].copy_from_slice(&replacement_r);
            malformed.signature_hex = hex::encode(signature_bytes);
            let err = verify_manifest_signature(&malformed, payload)
                .expect_err("malformed Ed25519 R must fail admission");
            let message = err.to_string();
            assert!(
                message.contains("invalid manifest signature material"),
                "unexpected {label} R error: {message}"
            );
        }
    }
    #[test]
    fn openapi_signature_envelope_rejects_unsupported_algorithm() {
        let payload = b"{\"ok\":true}";
        let signature = SignatureEnvelope {
            algorithm: "ed448".to_owned(),
            public_key_hex: hex::encode([0x77u8; 32]),
            signature_hex: hex::encode([0x88u8; 64]),
        };
        let err = verify_manifest_signature(&signature, payload)
            .expect_err("unsupported signature algorithms must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("unsupported manifest signature algorithm"),
            "expected unsupported algorithm message, got {message}"
        );
    }
    #[test]
    fn openapi_signature_envelope_rejects_invalid_hex_fields() {
        let payload = b"{\"ok\":true}";
        let invalid_public_key = SignatureEnvelope {
            algorithm: "ed25519".to_owned(),
            public_key_hex: "not-hex".to_owned(),
            signature_hex: hex::encode([0x88u8; 64]),
        };
        let err = verify_manifest_signature(&invalid_public_key, payload)
            .expect_err("invalid public key hex must fail verification");
        let message = err.to_string();
        assert!(
            message.contains("public_key_hex must be exactly 64 lowercase"),
            "expected invalid public key message, got {message}"
        );
        let tmp = tempdir().expect("tempdir");
        let key_path = tmp.path().join("key.hex");
        fs::write(&key_path, hex::encode([0x78_u8; 32])).expect("write signing key");
        let valid_signature =
            sign_manifest_payload_for_test(payload, &key_path).expect("sign fixture payload");
        let invalid_signature = SignatureEnvelope {
            algorithm: "ed25519".to_owned(),
            public_key_hex: valid_signature.public_key_hex,
            signature_hex: "not-hex".to_owned(),
        };
        let err = verify_manifest_signature(&invalid_signature, payload)
            .expect_err("invalid signature hex must fail verification");
        let message = err.to_string();
        assert!(
            message.contains("signature_hex must be exactly 128 lowercase"),
            "expected invalid signature hex message, got {message}"
        );
    }
    #[test]
    fn openapi_signature_envelope_rejects_weak_and_noncanonical_public_keys() {
        let cases = [
            ("identity", format!("01{}", "00".repeat(31))),
            ("all-zero", "00".repeat(32)),
            (
                "noncanonical-field-encoding",
                format!("ed{}7f", "ff".repeat(30)),
            ),
        ];
        for (name, public_key_hex) in cases {
            let envelope = SignatureEnvelope {
                algorithm: "ed25519".to_owned(),
                public_key_hex,
                signature_hex: "00".repeat(64),
            };
            let err = validate_signature_envelope_fields(&envelope)
                .expect_err("weak or noncanonical public key must fail admission");
            let message = err.to_string();
            assert!(
                message.contains("weak")
                    || message.contains("small-order")
                    || message.contains("canonical")
                    || message.contains("not an Ed25519 point"),
                "unexpected {name} public-key error: {message}"
            );
        }
    }
    #[test]
    fn openapi_manifest_rejects_unsafe_artifact_path() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("torii.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest_unsigned(
            &spec_path,
            &manifest_path,
            &clean_generator_provenance(),
            None,
        )
        .expect("write unsigned manifest");
        let manifest_json = fs::read_to_string(&manifest_path).expect("manifest json");
        let mut manifest: OpenApiManifest =
            json::from_str(&manifest_json).expect("parse manifest json");
        manifest.artifact.path = "../torii.json".to_owned();
        fs::write(
            &manifest_path,
            json::to_string_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("rewrite manifest");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect_err("unsafe artifact path must fail verification");
        let message = err.to_string();
        assert!(
            message.contains("must be exactly `torii.json`"),
            "expected unsafe path message, got {message}"
        );
    }
    #[test]
    fn openapi_manifest_rejects_platform_specific_artifact_paths() {
        for artifact_path in ["versions\\current\\torii.json", "C:/outside/torii.json", ""] {
            let tmp = tempdir().expect("tempdir");
            let spec_path = tmp.path().join("torii.json");
            write_release_openapi_fixture(&spec_path);
            let manifest_path = tmp.path().join("manifest.json");
            write_openapi_manifest_unsigned(
                &spec_path,
                &manifest_path,
                &clean_generator_provenance(),
                None,
            )
            .expect("write unsigned manifest");
            let manifest_json = fs::read_to_string(&manifest_path).expect("manifest json");
            let mut manifest: OpenApiManifest =
                json::from_str(&manifest_json).expect("parse manifest json");
            manifest.artifact.path = artifact_path.to_owned();
            fs::write(
                &manifest_path,
                json::to_string_pretty(&manifest).expect("serialize manifest"),
            )
            .expect("rewrite manifest");
            let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
                .expect_err("platform-specific artifact paths must fail verification");
            let message = err.to_string();
            assert!(
                message.contains("artifact.path"),
                "expected artifact path rejection for `{artifact_path}`, got {message}"
            );
        }
    }
    #[test]
    fn openapi_manifest_rejects_artifact_file_name_mismatch() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("torii.json");
        write_release_openapi_fixture(&spec_path);
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest_unsigned(
            &spec_path,
            &manifest_path,
            &clean_generator_provenance(),
            None,
        )
        .expect("write unsigned manifest");
        let manifest_json = fs::read_to_string(&manifest_path).expect("manifest json");
        let mut manifest: OpenApiManifest =
            json::from_str(&manifest_json).expect("parse manifest json");
        manifest.artifact.path = "other.json".to_owned();
        fs::write(
            &manifest_path,
            json::to_string_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("rewrite manifest");
        let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
            .expect_err("artifact filename mismatch must fail verification");
        let message = err.to_string();
        assert!(
            message.contains("must be exactly `torii.json`"),
            "expected artifact path mismatch message, got {message}"
        );
    }
    #[test]
    fn signing_payload_output_is_create_new_and_never_overwrites() {
        let tmp = tempdir().expect("tempdir");
        let payload_path = tmp.path().join("manifest-v2.payload");
        write_openapi_signing_payload_new(&payload_path, b"first").expect("write new payload");
        let err = write_openapi_signing_payload_new(&payload_path, b"replacement")
            .expect_err("existing signing payload must not be overwritten");
        assert!(
            err.to_string().contains("refusing to overwrite or follow"),
            "unexpected overwrite error: {err}"
        );
        assert_eq!(
            fs::read(&payload_path).expect("read original payload"),
            b"first"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&payload_path)
                .expect("payload metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "signing payload must be owner-only");
        }
    }
    #[cfg(unix)]
    #[test]
    fn signing_payload_output_refuses_symlinks() {
        let tmp = tempdir().expect("tempdir");
        let target = tmp.path().join("target.payload");
        let link = tmp.path().join("manifest-v2.payload");
        fs::write(&target, b"target").expect("write symlink target");
        std::os::unix::fs::symlink(&target, &link).expect("create payload symlink");
        let err = write_openapi_signing_payload_new(&link, b"replacement")
            .expect_err("signing payload symlink must fail closed");
        assert!(
            err.to_string().contains("refusing to overwrite or follow"),
            "unexpected symlink error: {err}"
        );
        assert_eq!(fs::read(&target).expect("read target"), b"target");
    }
    #[cfg(unix)]
    #[test]
    fn signing_payload_output_refuses_symlinked_parent() {
        let tmp = tempdir().expect("tempdir");
        let real_parent = tmp.path().join("real");
        let linked_parent = tmp.path().join("linked");
        fs::create_dir(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create parent symlink");
        let err = write_openapi_signing_payload_new(&linked_parent.join("payload"), b"replacement")
            .expect_err("symlinked signing payload parent must fail closed");
        assert!(
            err.to_string().contains("parent") && err.to_string().contains("symlink"),
            "unexpected symlink-parent error: {err}"
        );
        assert!(!real_parent.join("payload").exists());
    }
    #[cfg(unix)]
    #[test]
    fn openapi_manifest_writer_refuses_symlink_and_hardlink_targets() {
        for target_kind in ["symlink", "hardlink"] {
            let tmp = tempdir().expect("tempdir");
            let spec_path = tmp.path().join("torii.json");
            write_release_openapi_fixture(&spec_path);
            let protected = tmp.path().join("protected.json");
            let manifest_path = tmp.path().join("manifest.json");
            fs::write(&protected, b"protected").expect("write protected target");
            if target_kind == "symlink" {
                std::os::unix::fs::symlink(&protected, &manifest_path)
                    .expect("create manifest symlink");
            } else {
                fs::hard_link(&protected, &manifest_path).expect("create manifest hard link");
            }
            let err = write_openapi_manifest_unsigned(
                &spec_path,
                &manifest_path,
                &clean_generator_provenance(),
                None,
            )
            .expect_err("linked manifest target must fail closed");
            assert!(
                err.to_string().contains("symlink") || err.to_string().contains("hard link"),
                "unexpected {target_kind} manifest error: {err}"
            );
            assert_eq!(
                fs::read(&protected).expect("read protected target"),
                b"protected"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn openapi_output_writer_refuses_symlink_and_hardlink_targets() {
        for target_kind in ["symlink", "hardlink"] {
            let tmp = tempdir().expect("tempdir");
            let protected = tmp.path().join("protected.json");
            let output_path = tmp.path().join("torii.json");
            fs::write(&protected, b"protected").expect("write protected target");
            if target_kind == "symlink" {
                std::os::unix::fs::symlink(&protected, &output_path)
                    .expect("create OpenAPI output symlink");
            } else {
                fs::hard_link(&protected, &output_path).expect("create OpenAPI output hard link");
            }
            let err = write_openapi_file_atomic(&output_path, b"replacement", "OpenAPI output")
                .expect_err("linked OpenAPI output target must fail closed");
            assert!(
                err.to_string().contains("symlink") || err.to_string().contains("hard link"),
                "unexpected {target_kind} OpenAPI output error: {err}"
            );
            assert_eq!(
                fs::read(&protected).expect("read protected target"),
                b"protected"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn signature_envelope_reader_refuses_symlinks_and_hardlinks() {
        for target_kind in ["symlink", "hardlink"] {
            let tmp = tempdir().expect("tempdir");
            let protected = tmp.path().join("protected.json");
            let envelope_path = tmp.path().join("signature.json");
            fs::write(&protected, b"{}").expect("write protected envelope");
            if target_kind == "symlink" {
                std::os::unix::fs::symlink(&protected, &envelope_path)
                    .expect("create envelope symlink");
            } else {
                fs::hard_link(&protected, &envelope_path).expect("create envelope hard link");
            }
            let err = load_signature_envelope(&envelope_path)
                .expect_err("linked signature envelope must fail closed");
            assert!(
                err.to_string().contains("symlink") || err.to_string().contains("hard link"),
                "unexpected {target_kind} envelope error: {err}"
            );
        }
    }
    #[test]
    fn signature_envelope_reader_bounds_input() {
        let tmp = tempdir().expect("tempdir");
        let envelope_path = tmp.path().join("signature.json");
        fs::write(
            &envelope_path,
            vec![b' '; OPENAPI_SIGNATURE_ENVELOPE_MAX_BYTES as usize + 1],
        )
        .expect("write oversized envelope");
        let err = load_signature_envelope(&envelope_path)
            .expect_err("oversized signature envelope must fail closed");
        assert!(
            err.to_string().contains("exceeds the 4096-byte limit"),
            "unexpected oversized-envelope error: {err}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn openapi_manifest_verifier_refuses_linked_inputs() {
        for (input_kind, target_kind) in [
            ("specification", "symlink"),
            ("specification", "hardlink"),
            ("manifest", "symlink"),
            ("manifest", "hardlink"),
        ] {
            let tmp = tempdir().expect("tempdir");
            let spec_path = tmp.path().join("torii.json");
            write_release_openapi_fixture(&spec_path);
            let manifest_path = tmp.path().join("manifest.json");
            write_openapi_manifest_unsigned(
                &spec_path,
                &manifest_path,
                &clean_generator_provenance(),
                None,
            )
            .expect("write unsigned manifest");
            let linked_path = if input_kind == "specification" {
                &spec_path
            } else {
                &manifest_path
            };
            let protected = tmp
                .path()
                .join(format!("protected-{input_kind}-{target_kind}.json"));
            fs::rename(linked_path, &protected).expect("preserve linked input");
            if target_kind == "symlink" {
                std::os::unix::fs::symlink(&protected, linked_path)
                    .expect("create OpenAPI verifier input symlink");
            } else {
                fs::hard_link(&protected, linked_path)
                    .expect("create OpenAPI verifier input hard link");
            }
            let err = verify_openapi_manifest(&spec_path, &manifest_path, true, None)
                .expect_err("linked verifier input must fail closed");
            assert!(
                err.to_string().contains("symlink") || err.to_string().contains("hard link"),
                "unexpected {target_kind} {input_kind} error: {err}"
            );
        }
    }
    #[test]
    fn openapi_signer_allowlist_is_canonical_and_duplicate_free() {
        let tmp = tempdir().expect("tempdir");
        let key_path = tmp.path().join("key.hex");
        fs::write(&key_path, hex::encode([0x55u8; 32])).expect("write key");
        let signer = sign_manifest_payload_for_test(b"allowlist", &key_path)
            .expect("derive valid signer public key");
        for (name, contents, expected) in [
            (
                "duplicate-json-member",
                r#"{"version":1,"version":1,"allow":[]}"#.to_owned(),
                "duplicate",
            ),
            (
                "unknown-field",
                r#"{"version":1,"allow":[],"legacy":true}"#.to_owned(),
                "unknown field",
            ),
            (
                "noncanonical-algorithm",
                format!(
                    r#"{{"version":1,"allow":[{{"algorithm":"Ed25519","public_key_hex":"{}"}}]}}"#,
                    signer.public_key_hex
                ),
                "exactly `ed25519`",
            ),
            (
                "duplicate-signer",
                format!(
                    r#"{{"version":1,"allow":[{{"algorithm":"ed25519","public_key_hex":"{0}"}},{{"algorithm":"ed25519","public_key_hex":"{0}"}}]}}"#,
                    signer.public_key_hex
                ),
                "duplicates public key",
            ),
        ] {
            let allowlist_path = tmp.path().join(format!("{name}.json"));
            fs::write(&allowlist_path, contents).expect("write malformed allowlist");
            let err =
                load_signer_allowlist(&allowlist_path).expect_err("malformed allowlist must fail");
            assert!(
                err.to_string().contains(expected),
                "unexpected {name} allowlist error: {err}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn openapi_signer_allowlist_refuses_unsafe_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempdir().expect("tempdir");
        let allowlist_path = tmp.path().join("allow.json");
        fs::write(&allowlist_path, r#"{"version":1,"allow":[]}"#).expect("write empty allowlist");
        fs::set_permissions(&allowlist_path, fs::Permissions::from_mode(0o666))
            .expect("make allowlist unsafe");
        let err = load_signer_allowlist(&allowlist_path)
            .expect_err("group/world-writable allowlist must fail closed");
        assert!(
            err.to_string()
                .contains("must not be writable by group or other users"),
            "unexpected unsafe-permission error: {err}"
        );
    }
    #[test]
    fn signing_payload_path_must_not_alias_generated_outputs() {
        let tmp = tempdir().expect("tempdir");
        let output = tmp.path().join("torii.json");
        let args = vec![
            "xtask".to_owned(),
            "openapi".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
            "--unsigned-manifest".to_owned(),
            "--signing-payload".to_owned(),
            output.display().to_string(),
        ];
        let err = match parse_command(args.into_iter()) {
            Ok(_) => panic!("signing payload alias must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("--signing-payload must not alias the OpenAPI output"),
            "unexpected alias error: {err}"
        );
    }
    #[test]
    fn manifest_signature_must_be_allowlisted() {
        let tmp = tempdir().expect("tempdir");
        let spec_path = tmp.path().join("spec.json");
        write_release_openapi_fixture(&spec_path);
        let signing_key_path = tmp.path().join("signing.key");
        let signing_key_hex = hex::encode([0x33u8; 32]);
        fs::write(&signing_key_path, signing_key_hex).expect("write key");
        let manifest_path = tmp.path().join("manifest.json");
        write_openapi_manifest(
            &spec_path,
            &manifest_path,
            &signing_key_path,
            &clean_generator_provenance(),
        )
        .expect("sign manifest");
        let manifest_json = fs::read_to_string(&manifest_path).expect("manifest json");
        let manifest: OpenApiManifest =
            json::from_str(&manifest_json).expect("parse manifest json");
        let signer = manifest
            .artifact
            .signature
            .as_ref()
            .expect("signature must exist after signing");
        let allowlist_path = tmp.path().join("allow.json");
        let allowlist_contents = format!(
            "{{\"version\":1,\"allow\":[{{\"algorithm\":\"ed25519\",\"public_key_hex\":\"{}\"}}]}}",
            signer.public_key_hex
        );
        fs::write(&allowlist_path, allowlist_contents).expect("write allowlist");
        verify_openapi_manifest(
            &spec_path,
            &manifest_path,
            false,
            Some(allowlist_path.as_path()),
        )
        .expect("allowed signer should verify");
        let rejecting_key_path = tmp.path().join("rejecting.key");
        fs::write(&rejecting_key_path, hex::encode([0x44u8; 32])).expect("write rejecting key");
        let rejecting_signer = sign_manifest_payload_for_test(b"rejecting", &rejecting_key_path)
            .expect("derive rejecting signer public key");
        let rejecting_path = tmp.path().join("reject.json");
        let rejecting_contents = format!(
            "{{\"version\":1,\"allow\":[{{\"algorithm\":\"ed25519\",\"public_key_hex\":\"{}\"}}]}}",
            rejecting_signer.public_key_hex
        );
        fs::write(&rejecting_path, rejecting_contents).expect("write rejecting allowlist");
        let err = verify_openapi_manifest(
            &spec_path,
            &manifest_path,
            false,
            Some(rejecting_path.as_path()),
        )
        .expect_err("verification should fail for unlisted signer");
        let message = err.to_string();
        assert!(
            message.contains("unrecognized manifest signer"),
            "expected unrecognized signer message, got {message}"
        );
    }
}
#[cfg(test)]
mod space_directory_tests {
    use super::*;
    use tempfile::tempdir;
    const SAMPLE_MANIFEST: &str = r#"{
  "version": 1,
  "uaid": "uaid:0f4d86b20839a8ddbe8a1a3d21cf1c502d49f3f79f0fa1cd88d5f24c56c0ab11",
  "dataspace": 11,
  "issued_ms": 1762723200000,
  "activation_epoch": 4097,
  "expiry_epoch": 4600,
  "entries": [
    {
      "scope": {
        "dataspace": 11,
        "program": "cbdc.transfer",
        "method": "transfer",
        "asset": "61CtjvNd9T3THAR65GsMVHr82Bjc",
        "role": "Initiator"
      },
      "effect": {
        "Allow": {
          "max_amount": "500000000",
          "window": "PerDay"
        }
      },
      "notes": "Wholesale transfer allowance (per UAID, per day)."
    },
    {
      "scope": {
        "dataspace": 11,
        "program": "cbdc.kit",
        "method": "withdraw"
      },
      "effect": {
        "Deny": {
          "reason": "Withdrawals disabled for this UAID."
        }
      },
      "notes": "Deny wins over any preceding allowance."
    }
  ]
}"#;
    const INVALID_MANIFEST: &str = r#"{
  "version": 2,
  "uaid": "uaid:0f4d86b20839a8ddbe8a1a3d21cf1c502d49f3f79f0fa1cd88d5f24c56c0ab11",
  "dataspace": 12,
  "issued_ms": 1700000000000,
  "activation_epoch": 1024,
  "entries": []
}"#;
    #[test]
    fn encode_manifest_round_trips_through_norito() {
        let tmp = tempdir().expect("tempdir");
        let json_path = tmp.path().join("cbdc_wholesale.manifest.json");
        fs::write(&json_path, SAMPLE_MANIFEST).expect("write manifest json");
        let output_path = tmp.path().join("cbdc_wholesale.manifest.to");
        encode_space_directory_manifest(&json_path, &output_path)
            .expect("encode manifest into Norito");
        let norito_bytes = fs::read(&output_path).expect("read encoded manifest");
        assert!(
            norito_bytes.starts_with(&norito::core::MAGIC),
            "encoded manifest must include Norito magic header"
        );
    }
    #[test]
    fn reject_unsupported_manifest_version() {
        assert!(
            json::from_str::<AssetPermissionManifest>(INVALID_MANIFEST).is_err(),
            "unsupported manifest versions must be rejected"
        );
    }
}
#[cfg(test)]
mod streaming_bundle_tests {
    use super::*;
    fn fixtures_dir() -> PathBuf {
        workspace_root()
            .join("crates")
            .join("iroha_config")
            .join("tests")
            .join("fixtures")
    }
    #[test]
    fn bundle_summary_reports_defaults() {
        let config = fixtures_dir().join("minimal_with_trusted_peers.toml");
        let summary =
            build_streaming_bundle_summary(&config, None).expect("summary for minimal config");
        assert_eq!(
            summary.get("entropy_mode").and_then(|v| v.as_str()),
            Some("rans_bundled")
        );
        assert_eq!(
            summary.get("bundle_required").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            summary.get("bundle_accel").and_then(|v| v.as_str()),
            Some("none")
        );
        assert_eq!(
            summary.get("bundle_width").and_then(|v| v.as_u64()),
            Some(2)
        );
        let expected_checksum = {
            let path = workspace_root().join("codec/rans/tables/rans_seed0.toml");
            let tables = load_bundle_tables_from_toml(path).expect("load default tables");
            hex::encode(tables.checksum())
        };
        let tables = summary
            .get("tables")
            .and_then(|v| v.as_object())
            .expect("tables object");
        assert_eq!(
            tables.get("precision_bits").and_then(|v| v.as_u64()),
            Some(12)
        );
        assert_eq!(
            tables.get("checksum").and_then(|v| v.as_str()),
            Some(expected_checksum.as_str())
        );
    }
    #[test]
    fn bundle_summary_honors_config_overrides() {
        let config = fixtures_dir().join("streaming_bundled.toml");
        let summary =
            build_streaming_bundle_summary(&config, None).expect("summary for bundled config");
        assert_eq!(
            summary.get("entropy_mode").and_then(|v| v.as_str()),
            Some("rans_bundled")
        );
        assert_eq!(
            summary.get("bundle_required").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            summary.get("bundle_accel").and_then(|v| v.as_str()),
            Some("cpu_simd")
        );
        assert_eq!(
            summary.get("bundle_width").and_then(|v| v.as_u64()),
            Some(3)
        );
    }
    #[test]
    fn context_remap_produces_top_mapping() {
        let tmp = TempDir::new().expect("tmp dir");
        let telemetry_path = tmp.path().join("telemetry.json");
        let mut symbol_counts = vec![0u64; CONTEXT_SYMBOL_CAP];
        symbol_counts[1] = 10;
        let mut secondary_counts = vec![0u64; CONTEXT_SYMBOL_CAP];
        secondary_counts[2] = 4;
        let telemetry = norito::json!({
            "context_frequencies": [
                {
                    "context": 1,
                    "bundles": 10,
                    "total_bits": 40,
                    "symbol_counts": symbol_counts,
                },
                {
                    "context": 2,
                    "bundles": 4,
                    "total_bits": 16,
                    "symbol_counts": secondary_counts,
                }
            ]
        });
        let json = json::to_string_pretty(&telemetry).expect("serialize telemetry string");
        fs::write(&telemetry_path, json).expect("write telemetry");
        let output_path = tmp.path().join("remap.json");
        streaming_context_remap(StreamingContextRemapOptions {
            input: telemetry_path.clone(),
            top: 1,
            output: JsonTarget::File(output_path.clone()),
        })
        .expect("remap");
        let rendered = fs::read_to_string(output_path).expect("read remap output");
        let value: Value = json::from_str(&rendered).expect("json");
        assert_eq!(
            value
                .get("kept")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|row| row.get("remapped"))
                .and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            value
                .get("dropped")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|row| row.get("remapped"))
                .and_then(|v| v.as_u64()),
            None
        );
    }
}
fn generate_dev_vote_fixture(
    output: PathBuf,
    verify: bool,
    print_hashes: bool,
    summary_target: Option<JsonTarget>,
    attestation_target: Option<JsonTarget>,
) -> Result<(), Box<dyn Error>> {
    if verify {
        if !output.exists() {
            return Err(format!(
                "expected fixture directory {} to exist; run without --verify first to seed the baseline bundle",
                output.display()
            )
            .into());
        }
        for name in bundle_file_names() {
            let baseline_path = output.join(name);
            if !baseline_path.exists() {
                return Err(format!(
                    "expected fixture {} to exist; run `cargo xtask zk-dev-vote-fixture --out {} --print-hashes` first to materialize the baseline artifacts",
                    baseline_path.display(),
                    output.display()
                )
                .into());
            }
        }
        let temp = TempDir::new()?;
        let _summary = write_bundle(temp.path())?;
        compare_bundle_dirs(temp.path(), &output)?;
        println!(
            "development-only membership bundle matches fixtures at {}",
            output.display()
        );
        if print_hashes {
            print_bundle_hashes(&output)?;
        }
        let summary = read_summary(&output)?;
        println!("{summary}");
        if let Some(target) = summary_target {
            write_summary_json(&summary, target)?;
        }
        if let Some(target) = attestation_target {
            handle_attestation_manifest(&summary, &output, target, true)?;
        }
        return Ok(());
    }
    let summary = write_bundle(&output)?;
    if print_hashes {
        print_bundle_hashes(&output)?;
    }
    println!("{summary}");
    if let Some(target) = summary_target {
        write_summary_json(&summary, target)?;
    }
    if let Some(target) = attestation_target {
        handle_attestation_manifest(&summary, &output, target, false)?;
    }
    Ok(())
}
fn compare_bundle_dirs(generated: &Path, expected: &Path) -> Result<(), Box<dyn Error>> {
    for name in bundle_file_names() {
        let fresh_path = generated.join(name);
        let baseline_path = expected.join(name);
        if !baseline_path.exists() {
            return Err(format!(
                "expected fixture {} to exist; regenerate without --verify",
                baseline_path.display()
            )
            .into());
        }
        let fresh = fs::read(&fresh_path)?;
        let baseline = fs::read(&baseline_path)?;
        if fresh != baseline {
            let fresh_hash = compute_hash(&fresh);
            let baseline_hash = compute_hash(&baseline);
            return Err(format!(
                "fixture mismatch for {name}: generated {fresh_hash}, baseline {baseline_hash}"
            )
            .into());
        }
    }
    Ok(())
}
fn write_summary_json(summary: &BundleSummary, target: JsonTarget) -> Result<(), Box<dyn Error>> {
    let value = summary_to_json(summary);
    write_json_output(&value, target)
}
pub(crate) fn write_json_output(value: &Value, target: JsonTarget) -> Result<(), Box<dyn Error>> {
    let mut json_text = json::to_string_pretty(value)?;
    json_text.push('\n');
    match target {
        JsonTarget::Stdout => {
            print!("{json_text}");
        }
        JsonTarget::File(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, json_text)?;
        }
    }
    Ok(())
}
fn write_address_vectors(target: JsonTarget) -> Result<(), Box<dyn Error>> {
    let value = compliance_vectors_json();
    write_json_output(&value, target)
}
fn verify_address_vectors(path: &Path) -> Result<(), Box<dyn Error>> {
    let generated = compliance_vectors_json();
    let raw = fs::read_to_string(path)?;
    let existing: Value = json::from_str(&raw)?;
    if existing != generated {
        return Err(format!(
            "address vector fixture `{}` is stale; regenerate with `cargo xtask address-vectors`",
            path.display()
        )
        .into());
    }
    Ok(())
}
fn handle_attestation_manifest(
    summary: &BundleSummary,
    dir: &Path,
    target: JsonTarget,
    verify_mode: bool,
) -> Result<(), Box<dyn Error>> {
    let manifest = vote_tally::attestation_manifest(summary, dir)?;
    match target {
        JsonTarget::Stdout => write_json_output(&manifest, JsonTarget::Stdout),
        JsonTarget::File(path) => {
            if verify_mode {
                let existing = fs::read_to_string(&path).map_err(|err| {
                    format!(
                        "failed to read attestation manifest {} during verification: {err}",
                        path.display()
                    )
                })?;
                let parsed: Value = json::from_str(&existing)?;
                if parsed["hash_algorithm"] != manifest["hash_algorithm"] {
                    return Err(format!(
                        "attestation manifest at {} has hash_algorithm {:?}, expected {:?}",
                        path.display(),
                        parsed["hash_algorithm"],
                        manifest["hash_algorithm"]
                    )
                    .into());
                }
                if parsed["bundle"] != manifest["bundle"] {
                    return Err(format!(
                        "attestation manifest at {} has mismatched bundle metadata",
                        path.display()
                    )
                    .into());
                }
                let parsed_artifacts = parsed["artifacts"]
                    .as_array()
                    .ok_or("attestation manifest artifacts must be an array")?;
                let manifest_artifacts = manifest["artifacts"]
                    .as_array()
                    .ok_or("regenerated attestation artifacts must be an array")?;
                if parsed_artifacts.len() != manifest_artifacts.len() {
                    return Err(format!(
                        "attestation manifest at {} lists {} artifacts, regenerated bundle has {}",
                        path.display(),
                        parsed_artifacts.len(),
                        manifest_artifacts.len()
                    )
                    .into());
                }
                let parsed_map = artifacts_to_map(parsed_artifacts)?;
                let manifest_map = artifacts_to_map(manifest_artifacts)?;
                if parsed_map.keys().ne(manifest_map.keys()) {
                    return Err(format!(
                        "attestation manifest at {} lists different artifact set than regenerated bundle",
                        path.display()
                    )
                    .into());
                }
                for (name, (len, hash)) in manifest_map.iter() {
                    let Some((existing_len, existing_hash)) = parsed_map.get(name) else {
                        return Err(format!(
                            "attestation manifest at {} missing artifact {}",
                            path.display(),
                            name
                        )
                        .into());
                    };
                    if existing_len != len {
                        return Err(format!(
                            "attestation manifest at {} records len {} for {}, but regenerated bundle len is {}",
                            path.display(),
                            existing_len,
                            name,
                            len
                        )
                        .into());
                    }
                    if existing_hash != hash {
                        return Err(format!(
                            "attestation manifest at {} records digest {} for {}, but regenerated bundle digest is {} (deterministic artifacts must match)",
                            path.display(),
                            existing_hash,
                            name,
                            hash
                        )
                        .into());
                    }
                }
                Ok(())
            } else {
                let mut text = json::to_string_pretty(&manifest)?;
                text.push('\n');
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, text)?;
                Ok(())
            }
        }
    }
}
fn artifacts_to_map(
    artifacts: &[Value],
) -> Result<BTreeMap<String, (u64, String)>, Box<dyn Error>> {
    let mut map = BTreeMap::new();
    for entry in artifacts {
        let file = entry["file"]
            .as_str()
            .ok_or("artifact missing file name")?
            .to_owned();
        let len = entry["len"].as_u64().ok_or("artifact missing len")?;
        let hash = entry["blake2b_256"]
            .as_str()
            .ok_or("artifact missing blake2b_256")?
            .to_owned();
        map.insert(file, (len, hash));
    }
    Ok(map)
}
fn print_bundle_hashes(dir: &Path) -> Result<(), Box<dyn Error>> {
    for name in bundle_file_names() {
        let path = dir.join(name);
        let hash = compute_hash(&fs::read(&path)?);
        println!("{}  {}", hash, path.display());
    }
    Ok(())
}
fn compute_hash(bytes: &[u8]) -> String {
    hex::encode(iroha_hash(bytes))
}
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask resides in workspace root")
        .to_path_buf()
}
fn default_openapi_path() -> PathBuf {
    workspace_root().join("artifacts/openapi/torii.json")
}
fn default_openapi_manifest_path() -> PathBuf {
    workspace_root().join("artifacts/openapi/manifest.json")
}
fn default_openapi_allowed_signers_path() -> PathBuf {
    workspace_root().join("artifacts/openapi/allowed_signers.json")
}
fn normalize_openapi_output_root(value: &str) -> Result<PathBuf, Box<dyn Error>> {
    let requested = Path::new(value);
    if value.is_empty()
        || value.trim() != value
        || value.starts_with('-')
        || requested == Path::new(".")
        || requested.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("openapi --output-root requires an unambiguous directory path".into());
    }
    let normalized = normalize_path(requested)?;
    if normalized.parent().is_none() {
        return Err("openapi --output-root must not be the filesystem root".into());
    }
    let workspace = openapi_path_identity(&workspace_root());
    let identity = openapi_path_identity(&normalized);
    if identity == workspace {
        return Err("openapi --output-root must not be the workspace root".into());
    }
    let git_metadata = workspace.join(".git");
    if identity == git_metadata || identity.starts_with(&git_metadata) {
        return Err("openapi --output-root must not write inside Git metadata".into());
    }
    Ok(normalized)
}
fn default_da_report_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("da")
        .join("threat_model_report.json")
}
fn default_da_replication_audit_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("da")
        .join("replication_audit.json")
}
fn default_da_commitment_reconcile_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("da")
        .join("commitment_reconciliation.json")
}
fn default_da_privilege_audit_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("da")
        .join("privilege_audit.json")
}
fn default_da_proof_bench_json_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("da")
        .join("proof_bench")
        .join("benchmark.json")
}
fn default_da_proof_bench_markdown_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("da")
        .join("proof_bench")
        .join("benchmark.md")
}
fn default_da_proof_manifest() -> PathBuf {
    workspace_root()
        .join("fixtures")
        .join("da")
        .join("reconstruct")
        .join("rs_parity_v1")
        .join("manifest.json")
}
fn default_da_proof_payload() -> PathBuf {
    workspace_root()
        .join("fixtures")
        .join("da")
        .join("reconstruct")
        .join("rs_parity_v1")
        .join("payload.bin")
}
fn default_da_proof_generated_payload() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("da")
        .join("proof_bench")
        .join("payload.bin")
}
fn default_gar_receipts_dir(pop_label: &str) -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("soranet")
        .join("gateway")
        .join(pop_label)
        .join("gar_receipts")
}
fn default_gar_acks_dir(pop_label: &str) -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("soranet")
        .join("gateway")
        .join(pop_label)
        .join("gar_acks")
}
fn default_gar_summary_path(pop_label: &str) -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("soranet")
        .join("gateway")
        .join(pop_label)
        .join("gar_receipts_summary.json")
}
fn run_config_debug(path: &Path) -> Result<(), Box<dyn Error>> {
    println!("reading config {}", path.display());
    let reader = ConfigReader::new();
    let reader = match reader.read_toml_with_extends(path) {
        Ok(reader) => reader,
        Err(err) => {
            eprintln!(
                "config reader failed to load `{}`:\n{err:?}",
                path.display()
            );
            return Err("failed to read config source".into());
        }
    };
    match reader.read_and_complete::<user::Root>() {
        Ok(_cfg) => {
            println!("config OK");
            Ok(())
        }
        Err(err) => {
            eprintln!("config `{}` failed to parse:\n{err:?}", path.display());
            Err("config parse failed".into())
        }
    }
}
fn load_actual_config(path: &Path) -> eyre::Result<actual::Root> {
    let reader = ConfigReader::new();
    let reader = reader
        .read_toml_with_extends(path)
        .map_err(|err| eyre!("failed to read `{}`: {err}", path.display()))?;
    let user_cfg = reader
        .read_and_complete::<user::Root>()
        .map_err(|err| eyre!("failed to parse `{}`: {err:?}", path.display()))?;
    user_cfg
        .parse()
        .map_err(|err| eyre!("configuration `{}` invalid: {err:?}", path.display()))
}
fn default_address_vectors_path() -> Result<PathBuf, Box<dyn Error>> {
    normalize_path(Path::new("fixtures/account/address_vectors.json"))
}
fn default_dev_vote_fixture_path() -> PathBuf {
    workspace_root().join("fixtures/zk/dev_vote_membership")
}
fn default_mochi_bundle_path() -> PathBuf {
    workspace_root().join("target/mochi-bundle")
}
fn default_taikai_spool_dir() -> PathBuf {
    workspace_root()
        .join("storage")
        .join("da_manifests")
        .join("taikai")
}
fn default_testnet_kit_path() -> PathBuf {
    workspace_root()
        .join("docs")
        .join("examples")
        .join("soranet_testnet_operator_kit")
}
fn default_rollout_plan_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("soranet_pq_rollout_plan.json")
}
fn default_rollout_markdown_path() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("soranet_pq_rollout_plan.md")
}
fn default_rollout_capture_dir() -> PathBuf {
    workspace_root()
        .join("artifacts")
        .join("soranet_pq_rollout")
}
fn default_soranet_chaos_dir(now: SystemTime) -> PathBuf {
    let datetime = OffsetDateTime::from(now);
    let slug = format!(
        "{:04}{:02}{:02}",
        datetime.year(),
        datetime.month() as u8,
        datetime.day()
    );
    workspace_root()
        .join("artifacts")
        .join("soranet")
        .join("chaos_game_day")
        .join(slug)
}
fn default_directory_release_output_root() -> PathBuf {
    workspace_root().join("artifacts").join("soradns_directory")
}
fn default_pin_fixture_path() -> PathBuf {
    workspace_root()
        .join("crates")
        .join("iroha_core")
        .join("tests")
        .join("fixtures")
        .join("sorafs_pin_registry")
        .join("snapshot.json")
}
fn parse_seed(value: &str) -> Result<u64, Box<dyn Error>> {
    if let Some(stripped) = value.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).map_err(|err| err.into())
    } else if let Some(stripped) = value.strip_prefix("0X") {
        u64::from_str_radix(stripped, 16).map_err(|err| err.into())
    } else {
        value.parse::<u64>().map_err(|err| err.into())
    }
}
fn default_sm_wycheproof_path() -> PathBuf {
    workspace_root()
        .join("crates")
        .join("iroha_crypto")
        .join("tests")
        .join("fixtures")
        .join("wycheproof_sm2.json")
}
pub(crate) fn normalize_path(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(workspace_root().join(path))
    }
}
fn normalize_norito_rpc_output_root(value: &str) -> Result<PathBuf, Box<dyn Error>> {
    let requested = Path::new(value);
    if value.is_empty()
        || value.starts_with('-')
        || !requested.is_absolute()
        || requested == Path::new(".")
        || requested.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("--output-root requires an absolute unambiguous directory path".into());
    }
    if requested.parent().is_none() {
        return Err("--output-root must not be the filesystem root".into());
    }
    Ok(requested.to_path_buf())
}
fn openapi_paths_alias(left: &Path, right: &Path) -> bool {
    openapi_path_identity(left) == openapi_path_identity(right)
}
fn openapi_path_identity(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name())
        && let Ok(canonical_parent) = parent.canonicalize()
    {
        return canonical_parent.join(file_name);
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
fn parse_gate_date(value: &str) -> Result<Date, Box<dyn Error>> {
    let spec = format_description::parse("[year]-[month]-[day]")
        .map_err(|err| -> Box<dyn Error> { format!("invalid gate date spec: {err}").into() })?;
    Date::parse(value, &spec)
        .map_err(|err| -> Box<dyn Error> { format!("invalid date `{value}`: {err}").into() })
}
fn parse_attachment_spec(spec: &str) -> Result<(String, PathBuf), Box<dyn Error>> {
    let Some((label, path)) = spec.split_once('=') else {
        return Err(
            "invalid --attachment spec; expected label=path (e.g., bond=artifacts/bond.json)"
                .into(),
        );
    };
    let label = label.trim();
    let path = path.trim();
    if label.is_empty() {
        return Err("attachment label cannot be empty".into());
    }
    if path.is_empty() {
        return Err("attachment path cannot be empty".into());
    }
    let normalized = normalize_path(Path::new(path))?;
    Ok((label.to_string(), normalized))
}
fn load_relays_from_file(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        let value: Value = json::from_str(trimmed)?;
        let array = value
            .as_array()
            .ok_or("relays file must contain a JSON array of strings")?;
        let mut relays = Vec::with_capacity(array.len());
        for entry in array {
            let text = entry
                .as_str()
                .ok_or("relays file entries must be strings")?
                .trim();
            if !text.is_empty() {
                relays.push(text.to_string());
            }
        }
        Ok(relays)
    } else {
        Ok(raw
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(|line| line.to_string())
            .collect())
    }
}
fn parse_label_value(spec: &str, flag: &str) -> Result<(String, String), Box<dyn Error>> {
    let Some((label, value)) = spec.split_once('=') else {
        return Err(format!("{flag} expects label=value").into());
    };
    let label = label.trim();
    let value = value.trim();
    if label.is_empty() {
        return Err(format!("{flag} label cannot be empty").into());
    }
    if value.is_empty() {
        return Err(format!("{flag} value cannot be empty").into());
    }
    Ok((label.to_string(), value.to_string()))
}
fn parse_labelled_path(spec: &str, flag: &str) -> Result<(String, PathBuf), Box<dyn Error>> {
    let (label, path_str) = parse_label_value(spec, flag)?;
    let path = normalize_path(Path::new(&path_str))?;
    Ok((label, path))
}
fn parse_operation_limit(spec: &str, flag: &str) -> Result<(String, f64), Box<dyn Error>> {
    let (label, value_str) = parse_label_value(spec, flag)?;
    let value = value_str.parse::<f64>().map_err(|err| {
        format!("{flag} expects label=float; failed to parse `{value_str}`: {err}")
    })?;
    Ok((label, value))
}
fn parse_rollout_artifact_spec(spec: &str) -> Result<(String, String), Box<dyn Error>> {
    let mut kind: Option<String> = None;
    let mut path: Option<String> = None;
    for entry in spec.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(
                format!("invalid --artifact spec `{spec}`; expected key=value pairs").into(),
            );
        };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            return Err(format!("empty value for `{key}` in --artifact spec `{spec}`").into());
        }
        match key {
            "kind" => kind = Some(value.to_string()),
            "path" => path = Some(value.to_string()),
            other => {
                return Err(format!("unknown key `{other}` in --artifact spec `{spec}`").into());
            }
        }
    }
    let kind = kind.ok_or("missing `kind=` in --artifact spec")?;
    let path = path.ok_or("missing `path=` in --artifact spec")?;
    Ok((kind, path))
}
const NORITO_RPC_FIXTURES_USAGE_DESCRIPTION: &str = "    Regenerate canonical Norito-RPC transaction fixtures, the typed V1 alias-setup fixture, and Android/Python/Swift mirrors in one absent absolute create-only output root outside the workspace.";
const NORITO_RPC_VERIFY_USAGE_DESCRIPTION: &str = "    Re-render and compare canonical Norito-RPC transaction and alias-setup fixture bytes, schema hashes, the compact hash vector, and Android/Python/Swift mirrors; optionally emit a JSON verification report.";
include!("usage.rs");
#[cfg(test)]
mod tests;
