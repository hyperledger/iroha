#[path = "atomic_private_settlement_transport.rs"]
mod transport_evidence;

#[path = "atomic_private_settlement_session.rs"]
mod benchmark_session;

#[path = "atomic_private_settlement_matched_workload.rs"]
mod matched_benchmark_workload;
use matched_benchmark_workload::*;

#[path = "atomic_private_settlement_executable_inventory.rs"]
mod executable_inventory;
use executable_inventory::{ExecutableInventory, sha256_regular_file};

use base64::Engine as _;
use futures_util::StreamExt as _;
use iroha::data_model::block::consensus::HeightContextId;
use iroha::data_model::events::{
    EventBox,
    pipeline::{PipelineEventBox, TransactionEventFilter, TransactionStatus},
};
use iroha_test_network::{PrivateSettlementRouteControlAction, PrivateSettlementRouteControlPhase};
use norito::json::Value as HarnessJsonValue;
use sha2::{Digest as Sha2Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    num::NonZeroU64,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

const HARNESS_REQUEST_ENV: &str = "APS_REAL_PROCESS_REQUEST";
const HARNESS_RESULT_ENV: &str = "APS_REAL_PROCESS_RESULT";
const HARNESS_REQUEST_SHA_ENV: &str = "APS_REAL_PROCESS_REQUEST_SHA256";
const HARNESS_VALIDATOR_SHA_ENV: &str = "APS_REAL_PROCESS_VALIDATOR_SHA256";
const HARNESS_EVIDENCE_DIR_ENV: &str = "APS_REAL_PROCESS_EVIDENCE_DIR";
const HARNESS_PORT_MANIFEST_ENV: &str = "APS_REAL_PROCESS_PORT_MANIFEST";
const RAYON_NUM_THREADS_ENV: &str = "RAYON_NUM_THREADS";
const REAL_PROCESS_RAYON_WORKER_THREADS: u64 = 8;
const REAL_PROCESS_RAYON_WORKER_THREADS_TEXT: &str = "8";
const REAL_PROCESS_CARGO_BUILD_JOBS: u64 = 1;
const REAL_PROCESS_CARGO_RELEASE_CODEGEN_UNITS: u64 = 1;
const COORDINATOR_ROOT_ENV: &str = "APS_REAL_PROCESS_COORDINATOR_ROOT";
const COORDINATOR_COMMAND_FILE: &str = "command.json";
const COORDINATOR_ACK_FILE: &str = "ack.json";
const COORDINATOR_CONFIG_FILE: &str = "client.toml";
const COORDINATOR_SHUTDOWN_FILE: &str = "shutdown";
const COORDINATOR_STDOUT_FILE: &str = "stdout.log";
const COORDINATOR_STDERR_FILE: &str = "stderr.log";
const HARNESS_MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
const FAULT_CONTROL_EVIDENCE_FILE: &str = "fault-control.jsonl";
const FAULT_OBSERVATION_EVIDENCE_FILE: &str = "fault-observations.jsonl";
const FAULT_ROUTE_MATCHES: u64 = 20;
// Node-internal process cuts belong to deterministic protocol/storage owner tests. The live
// harness qualifies authenticated HTTP loss/hold and externally observed restart recovery.
const PRIVATE_SETTLEMENT_CRASH_BOUNDARIES: &[&str] = &[];
const FAULT_CAMPAIGN_TRIALS: usize = 9 + 3 + 1;
const FAULT_BUNDLE_EXPIRY_BLOCKS: u64 = 96;
const FAULT_CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const FAULT_CONTINUOUS_OBSERVATION_DOMAIN_V1: &[u8] =
    b"iroha:aps-fault-continuous-observation:v1\0";
const FAULT_CONTINUOUS_OBSERVATION_PHASE_DOMAIN_V1: &[u8] =
    b"iroha:aps-fault-continuous-observation-phase:v1\0";
const FAULT_CONTINUOUS_EXPECTED_UNAVAILABLE_CLASS_V1: &str = "expected_transport_unavailable";
const FAULT_CONTINUOUS_MAX_ATTEMPTS_PER_PEER: u64 = 20_000;
const LEAKAGE_BLOCK_WIRE_MAGIC_V1: &[u8; 8] = b"APSBLK1\0";
const LEAKAGE_ARTIFACT_FRAME_DOMAIN_V1: &[u8] = b"iroha:aps-leakage-artifact:v1\0";
const LEAKAGE_RESTRICTED_SOURCE_DOMAIN_V1: &[u8; 8] = b"APSRAW1\0";
const LEAKAGE_MAX_SOURCE_FILES: usize = 100_000;
const LEAKAGE_MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024 * 1024;
const LEAKAGE_MAX_OBSERVATIONS_PER_PEER: usize = 10_000;
const LEAKAGE_MEMO_FIELD_BYTES: usize = 96;
const LEAKAGE_ALIAS_FIELD_BYTES: usize = 64;
const LEAKAGE_CAPSULE_FIELD_BYTES: usize = 64;

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessBenchmarkPayloadV1 {
    profile: String,
    warmup: bool,
    stages: Vec<String>,
    resources: Vec<String>,
}

/// Bound input for one fresh correctness run, before any benchmark campaign.
#[derive(Clone, Debug, norito::JsonDeserialize, norito::JsonSerialize)]
#[norito(deny_unknown_fields)]
struct RealProcessSmokeRequestV1 {
    version: u8,
    protocol: String,
    kind: String,
    request_id: String,
    invocation_nonce: String,
    commit: String,
    seed: u64,
    run: u64,
}

fn validate_real_process_smoke_request(request: &RealProcessSmokeRequestV1) -> Result<()> {
    ensure!(
        request.version == 1
            && request.protocol == "AtomicPrivateSettlementV1"
            && matches!(request.kind.as_str(), "smoke" | "happy_day")
            && request.run < 10
            && lowercase_digest(&request.request_id, &[64])
            && lowercase_digest(&request.invocation_nonce, &[64])
            && lowercase_digest(&request.commit, &[40, 64]),
        "malformed bound N=3 smoke request"
    );
    Ok(())
}

#[test]
fn smoke_request_rejects_unbound_or_noncanonical_inputs() {
    let valid = RealProcessSmokeRequestV1 {
        version: 1,
        protocol: "AtomicPrivateSettlementV1".to_owned(),
        kind: "smoke".to_owned(),
        request_id: "a".repeat(64),
        invocation_nonce: "b".repeat(64),
        commit: "c".repeat(40),
        seed: u64::MAX,
        run: 9,
    };
    validate_real_process_smoke_request(&valid).expect("bound request validates");
    for field in [
        "version",
        "protocol",
        "kind",
        "request_id",
        "invocation_nonce",
        "commit",
        "run",
    ] {
        let mut altered = valid.clone();
        match field {
            "version" => altered.version = 2,
            "protocol" => altered.protocol.clear(),
            "kind" => altered.kind = "benchmark".to_owned(),
            "request_id" => altered.request_id = "0".repeat(64),
            "invocation_nonce" => altered.invocation_nonce = "B".repeat(64),
            "commit" => altered.commit = "c".repeat(39),
            "run" => altered.run = 10,
            _ => unreachable!(),
        }
        assert!(
            validate_real_process_smoke_request(&altered).is_err(),
            "accepted {field}"
        );
    }
    let mut value = norito::json::to_value(&valid).expect("request JSON");
    value
        .as_object_mut()
        .unwrap()
        .insert("skip_network".to_owned(), true.into());
    assert!(norito::json::from_value::<RealProcessSmokeRequestV1>(value).is_err());
}

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessBenchmarkRequestV1 {
    version: u8,
    protocol: String,
    request_id: String,
    invocation_nonce: String,
    kind: String,
    commit: String,
    hardware_sha256: String,
    hardware_profile_sha256: String,
    configuration_sha256: String,
    participants: usize,
    participant_visibilities: Vec<String>,
    validators_per_dataspace: usize,
    global_validators: usize,
    quorum: String,
    mandatory_signed_rs16_da_rbc: bool,
    minimum_signed_rs16_da_observations: u64,
    authenticated_private_settlement_route_control: bool,
    seed: u64,
    session_id: String,
    session_invocation_nonce: String,
    workload_manifest_sha256: String,
    session_attempt_index: u64,
    configuration: HarnessJsonValue,
    payload: RealProcessBenchmarkPayloadV1,
}

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessPrepareQcNormalizationRequestV1 {
    first_signer_subset: Vec<u8>,
    second_signer_subset: Vec<u8>,
    accept_equivalent_subsets_only_for_identical_body: bool,
    bind_authority_indices: bool,
    bind_every_signed_body: bool,
    reject_changed_certified_body: bool,
}

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessFaultPayloadV1 {
    loss_phases: Vec<String>,
    loss_percentages: Vec<u8>,
    phase_cuts: Vec<String>,
    crash_boundaries: Vec<String>,
    committee_validator_restarts: Vec<usize>,
    restart_coordinator: bool,
    restart_global_node: bool,
    maximum_simultaneously_unavailable_per_committee: usize,
    continuous_atomicity_checks: bool,
    prepare_qc_normalization: RealProcessPrepareQcNormalizationRequestV1,
}

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessFaultRequestV1 {
    version: u8,
    protocol: String,
    request_id: String,
    invocation_nonce: String,
    kind: String,
    commit: String,
    hardware_sha256: String,
    hardware_profile_sha256: String,
    configuration_sha256: String,
    participants: usize,
    participant_visibilities: Vec<String>,
    validators_per_dataspace: usize,
    global_validators: usize,
    quorum: String,
    mandatory_signed_rs16_da_rbc: bool,
    minimum_signed_rs16_da_observations: u64,
    authenticated_private_settlement_route_control: bool,
    seed: u64,
    run: u64,
    configuration: HarnessJsonValue,
    payload: RealProcessFaultPayloadV1,
}

#[derive(Clone, Debug, norito::JsonSerialize, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessLeakageCanaryV1 {
    name: String,
    kind: String,
    value: HarnessJsonValue,
}

#[derive(Clone, Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessLeakageCaptureSurfaceV1 {
    surface: String,
    relative_name: String,
}

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessLeakagePayloadV1 {
    variant: String,
    canaries: Vec<RealProcessLeakageCanaryV1>,
    canary_commitments: BTreeMap<String, String>,
    only_secret_fields_change: bool,
    capture_surfaces: Vec<RealProcessLeakageCaptureSurfaceV1>,
    traffic_count_channels: Vec<String>,
}

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessLeakageRequestV1 {
    version: u8,
    protocol: String,
    request_id: String,
    invocation_nonce: String,
    kind: String,
    commit: String,
    hardware_sha256: String,
    hardware_profile_sha256: String,
    configuration_sha256: String,
    participants: usize,
    participant_visibilities: Vec<String>,
    validators_per_dataspace: usize,
    global_validators: usize,
    quorum: String,
    mandatory_signed_rs16_da_rbc: bool,
    minimum_signed_rs16_da_observations: u64,
    authenticated_private_settlement_route_control: bool,
    seed: u64,
    run: u64,
    configuration: HarnessJsonValue,
    payload: RealProcessLeakagePayloadV1,
}

enum RealProcessBoundRequestV1 {
    Smoke(RealProcessSmokeRequestV1),
    Benchmark(RealProcessBenchmarkRequestV1),
    Fault(RealProcessFaultRequestV1),
    Leakage(RealProcessLeakageRequestV1),
}

#[derive(Clone, Debug, norito::JsonSerialize, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessInventoryRowV1 {
    role: String,
    #[norito(required)]
    dataspace_ordinal: Option<u64>,
    #[norito(required)]
    validator_ordinal: Option<u64>,
    pid: u32,
    executable_sha256: String,
    revision: String,
    health_observed: bool,
}

#[derive(Clone, Debug, norito::JsonSerialize, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessBenchmarkResultPayloadV1 {
    economic_vector_sha256: String,
    primary_payment_count: usize,
    monetary_movement_count: usize,
    stages_ms: HarnessJsonValue,
    proof_bytes: u64,
    receipt_bytes: u64,
    storage_growth_bytes: u64,
    finalized_receipt_observed: bool,
    successful_leg_applications: usize,
    each_leg_applied_exactly_once: bool,
    partial_visible_observations: u64,
    partial_spendable_observations: u64,
}

#[derive(Debug, norito::JsonSerialize, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RealProcessBenchmarkResultV1 {
    version: u8,
    protocol: String,
    request_id: String,
    invocation_nonce: String,
    request_sha256: String,
    commit: String,
    participants: usize,
    mandatory_signed_rs16_da_rbc: bool,
    signed_rs16_da_observations: u64,
    authenticated_private_settlement_route_control: bool,
    process_inventory: Vec<RealProcessInventoryRowV1>,
    payload: RealProcessBenchmarkResultPayloadV1,
}

/// Closed completion-deadline vocabulary, separate from measured latency stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchmarkDeadlineStageV1 {
    CoordinatorAck,
    StateConvergence,
    TransparentConsents,
    TransparentBalances,
    SettlementFinality,
    CanonicalCarrier,
    PrivateReceipt,
}

impl BenchmarkDeadlineStageV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::CoordinatorAck => "coordinator_ack",
            Self::StateConvergence => "state_convergence",
            Self::TransparentConsents => "transparent_consents",
            Self::TransparentBalances => "transparent_balances",
            Self::SettlementFinality => "settlement_finality",
            Self::CanonicalCarrier => "canonical_carrier",
            Self::PrivateReceipt => "private_receipt",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "coordinator_ack" => Some(Self::CoordinatorAck),
            "state_convergence" => Some(Self::StateConvergence),
            "transparent_consents" => Some(Self::TransparentConsents),
            "transparent_balances" => Some(Self::TransparentBalances),
            "settlement_finality" => Some(Self::SettlementFinality),
            "canonical_carrier" => Some(Self::CanonicalCarrier),
            "private_receipt" => Some(Self::PrivateReceipt),
            _ => None,
        }
    }
}

/// Produced only where an existing declared completion deadline is exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BenchmarkDeadlineV1 {
    stage: BenchmarkDeadlineStageV1,
    budget_ms: u64,
    elapsed_ms: u64,
}

impl std::fmt::Display for BenchmarkDeadlineV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "declared completion deadline exhausted: {}",
            self.stage.as_str()
        )
    }
}

impl std::error::Error for BenchmarkDeadlineV1 {}

fn benchmark_duration_ms(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_millis()).wrap_err("benchmark duration exceeds u64 milliseconds")
}

fn benchmark_deadline_error(
    stage: BenchmarkDeadlineStageV1,
    budget: Duration,
    elapsed: Duration,
) -> eyre::Report {
    let deadline = (|| -> Result<BenchmarkDeadlineV1> {
        ensure!(elapsed >= budget, "completion deadline has not elapsed");
        let budget_ms = benchmark_duration_ms(budget)?;
        ensure!(
            budget_ms > 0,
            "completion deadline budget must be positive milliseconds"
        );
        Ok(BenchmarkDeadlineV1 {
            stage,
            budget_ms,
            elapsed_ms: benchmark_duration_ms(elapsed)?,
        })
    })();
    match deadline {
        Ok(deadline) => eyre::Report::new(deadline),
        Err(error) => error,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchmarkFailureReasonV1 {
    ExecutionError,
    WorkerPanic,
    WorkerSpawnError,
}

impl BenchmarkFailureReasonV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionError => "execution_error",
            Self::WorkerPanic => "worker_panic",
            Self::WorkerSpawnError => "worker_spawn_error",
        }
    }
}

/// Exactly one outcome; unsuccessful attempts cannot carry measurement payloads.
#[derive(Debug)]
enum RealProcessBenchmarkOutcomeV1 {
    Succeeded(RealProcessBenchmarkResultV1),
    Failed(BenchmarkFailureReasonV1),
    TimedOut(BenchmarkDeadlineV1),
}

impl RealProcessBenchmarkOutcomeV1 {
    fn from_error(error: &eyre::Report) -> Self {
        // Eyre preserves typed causes through wrap_err; diagnostic text is never a classifier.
        match error
            .chain()
            .find_map(|cause| cause.downcast_ref::<BenchmarkDeadlineV1>())
        {
            Some(deadline) => Self::TimedOut(*deadline),
            None => Self::Failed(BenchmarkFailureReasonV1::ExecutionError),
        }
    }
}

impl norito::json::FastJsonWrite for RealProcessBenchmarkOutcomeV1 {
    fn write_json(&self, out: &mut String) {
        norito::json::write_json_unbounded(self, out);
    }

    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> std::result::Result<(), norito::json::BoundedJsonError> {
        use norito::json::FastJsonWrite as _;
        out.begin_container()?;
        match self {
            Self::Succeeded(result) => {
                out.push_str("{\"kind\":\"succeeded\",\"result\":")?;
                result.write_json_to(out)?;
            }
            Self::Failed(reason) => {
                out.push_str("{\"kind\":\"failed\",\"stage\":\"benchmark_worker\",\"reason\":")?;
                reason.as_str().write_json_to(out)?;
            }
            Self::TimedOut(deadline) => {
                out.push_str("{\"kind\":\"timed_out\",\"stage\":")?;
                deadline.stage.as_str().write_json_to(out)?;
                out.push_str(",\"budget_ms\":")?;
                deadline.budget_ms.write_json_to(out)?;
                out.push_str(",\"elapsed_ms\":")?;
                deadline.elapsed_ms.write_json_to(out)?;
            }
        }
        out.push('}')?;
        out.end_container();
        Ok(())
    }
}

impl norito::json::JsonDeserialize for RealProcessBenchmarkOutcomeV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> std::result::Result<Self, norito::json::Error> {
        #[derive(norito::JsonDeserialize)]
        #[norito(deny_unknown_fields)]
        struct Success {
            result: RealProcessBenchmarkResultV1,
        }
        #[derive(norito::JsonDeserialize)]
        #[norito(deny_unknown_fields)]
        struct Failure {
            stage: String,
            reason: String,
        }
        #[derive(norito::JsonDeserialize)]
        #[norito(deny_unknown_fields)]
        struct Timeout {
            stage: String,
            budget_ms: u64,
            elapsed_ms: u64,
        }
        let invalid = || norito::json::Error::Message("invalid benchmark terminal outcome".into());
        let mut value =
            <HarnessJsonValue as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        let kind = value
            .as_object_mut()
            .and_then(|fields| fields.remove("kind"))
            .ok_or_else(invalid)?;
        match kind.as_str() {
            Some("succeeded") => Ok(Self::Succeeded(
                norito::json::from_value::<Success>(value)?.result,
            )),
            Some("failed") => {
                let failure: Failure = norito::json::from_value(value)?;
                if failure.stage != "benchmark_worker" {
                    return Err(invalid());
                }
                let reason = match failure.reason.as_str() {
                    "execution_error" => BenchmarkFailureReasonV1::ExecutionError,
                    "worker_panic" => BenchmarkFailureReasonV1::WorkerPanic,
                    "worker_spawn_error" => BenchmarkFailureReasonV1::WorkerSpawnError,
                    _ => return Err(invalid()),
                };
                Ok(Self::Failed(reason))
            }
            Some("timed_out") => {
                let timeout: Timeout = norito::json::from_value(value)?;
                if timeout.budget_ms == 0 || timeout.elapsed_ms < timeout.budget_ms {
                    return Err(invalid());
                }
                Ok(Self::TimedOut(BenchmarkDeadlineV1 {
                    stage: BenchmarkDeadlineStageV1::parse(&timeout.stage).ok_or_else(invalid)?,
                    budget_ms: timeout.budget_ms,
                    elapsed_ms: timeout.elapsed_ms,
                }))
            }
            _ => Err(invalid()),
        }
    }
}

/// Retained before the validated request moves into the benchmark worker.
#[derive(Clone, Debug)]
struct BenchmarkTerminalIdentityV1 {
    request_id: String,
    invocation_nonce: String,
    request_sha256: String,
    commit: String,
    participants: usize,
}

impl BenchmarkTerminalIdentityV1 {
    fn from_request(request: &RealProcessBenchmarkRequestV1, request_sha256: String) -> Self {
        Self {
            request_id: request.request_id.clone(),
            invocation_nonce: request.invocation_nonce.clone(),
            request_sha256,
            commit: request.commit.clone(),
            participants: request.participants,
        }
    }

    fn terminal(
        self,
        elapsed_ms: u64,
        outcome: RealProcessBenchmarkOutcomeV1,
    ) -> Result<RealProcessBenchmarkTerminalV1> {
        if let RealProcessBenchmarkOutcomeV1::Succeeded(result) = &outcome {
            ensure!(
                result.version == 1
                    && result.protocol == "AtomicPrivateSettlementV1"
                    && result.request_id == self.request_id
                    && result.invocation_nonce == self.invocation_nonce
                    && result.request_sha256 == self.request_sha256
                    && result.commit == self.commit
                    && result.participants == self.participants,
                "benchmark success does not match retained request identity"
            );
        }
        Ok(RealProcessBenchmarkTerminalV1 {
            version: 1,
            protocol: "AtomicPrivateSettlementV1".to_owned(),
            request_id: self.request_id,
            invocation_nonce: self.invocation_nonce,
            request_sha256: self.request_sha256,
            commit: self.commit,
            participants: self.participants,
            elapsed_ms,
            outcome,
        })
    }
}

#[derive(Debug, norito::JsonSerialize, norito::JsonDeserialize)]
#[norito(deny_unknown_fields, no_fast_from_json)]
struct RealProcessBenchmarkTerminalV1 {
    version: u8,
    protocol: String,
    request_id: String,
    invocation_nonce: String,
    request_sha256: String,
    commit: String,
    participants: usize,
    elapsed_ms: u64,
    outcome: RealProcessBenchmarkOutcomeV1,
}

#[derive(Debug, norito::JsonSerialize)]
struct RealProcessFaultResultV1 {
    version: u8,
    protocol: String,
    request_id: String,
    invocation_nonce: String,
    request_sha256: String,
    commit: String,
    participants: usize,
    mandatory_signed_rs16_da_rbc: bool,
    signed_rs16_da_observations: u64,
    authenticated_private_settlement_route_control: bool,
    process_inventory: Vec<RealProcessInventoryRowV1>,
    payload: HarnessJsonValue,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct RealProcessLeakageArtifactV1 {
    surface: String,
    relative_name: String,
    sha256: String,
    bytes: u64,
    source_sha256: String,
    source_bytes: u64,
    source_count: usize,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct RealProcessLeakageResultPayloadV1 {
    variant: String,
    canaries_injected: Vec<String>,
    canary_commitments: BTreeMap<String, String>,
    only_secret_fields_changed: bool,
    nonpacket_capture_complete: bool,
    finalized_receipt_observed: bool,
    successful_leg_applications: usize,
    each_leg_applied_exactly_once: bool,
    continuous_atomicity_checks: u64,
    partial_visible_observations: u64,
    partial_spendable_observations: u64,
    nonpacket_artifacts: Vec<RealProcessLeakageArtifactV1>,
    nonpacket_record_counts: BTreeMap<String, u64>,
}

#[derive(Debug, norito::JsonSerialize)]
struct RealProcessLeakageResultV1 {
    version: u8,
    protocol: String,
    request_id: String,
    invocation_nonce: String,
    request_sha256: String,
    commit: String,
    participants: usize,
    mandatory_signed_rs16_da_rbc: bool,
    signed_rs16_da_observations: u64,
    authenticated_private_settlement_route_control: bool,
    process_inventory: Vec<RealProcessInventoryRowV1>,
    payload: RealProcessLeakageResultPayloadV1,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct LeakageAtomicityObservationEvidenceV1 {
    version: u8,
    peer_index: usize,
    registered: FaultStateObservationV1,
    observations: Vec<FaultStateObservationV1>,
}

#[derive(Clone, Debug, norito::JsonSerialize, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CoordinatorCommandV1 {
    format_version: u8,
    revision: u64,
    operation: String,
    committee_endpoints: Vec<Vec<String>>,
    #[norito(required)]
    manifest: Option<AtomicPrivateSettlementV1>,
    authority_catalog: Vec<PrivateSettlementCommitteeAuthorityV1>,
    deltas: Vec<PrivateSettlementDeltaV1>,
    #[norito(required)]
    barrier: Option<iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1>,
}

#[derive(Clone, Debug, norito::JsonSerialize, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CoordinatorAckV1 {
    format_version: u8,
    revision: u64,
    command_sha256: String,
    pid: u32,
    operation: String,
    #[norito(required)]
    barrier: Option<iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1>,
    commit_certificates: Vec<iroha::data_model::nexus::PrivateSettlementPhaseCertificateV1>,
}

fn submit_prepare_registration_and_wait_v1(
    client: &Client,
    barrier: &iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1,
) -> Result<()> {
    client
        .client()
        .register_private_settlement_prepare_and_wait_v1(
            barrier,
            u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1)
                .expect("V1 carrier ceiling fits u64"),
            iroha::client::TransactionWaitOptions {
                timeout: FINALITY_TIMEOUT,
                poll_interval: POLL_INTERVAL,
            },
        )?;
    Ok(())
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultControlOccurrenceV1 {
    control_type: String,
    #[norito(required)]
    peer_index: Option<usize>,
    command_sha256: String,
    command_hex: String,
    acknowledgement_sha256: String,
    acknowledgement_hex: String,
    #[norito(required)]
    before_pid: Option<u32>,
    #[norito(required)]
    after_pid: Option<u32>,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultControlRecordV1 {
    record: String,
    bundle_id: String,
    participants: usize,
    seed: u64,
    run: u64,
    collection: String,
    trial_index: usize,
    controls: Vec<FaultControlOccurrenceV1>,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultStateObservationV1 {
    peer_index: usize,
    response_sha256: String,
    response_hex: String,
    height: u64,
    commitment: String,
    ledger_commitment: String,
    replicated_staged_lock_commitment: String,
    staged_lock_commitment: String,
    counts: HarnessJsonValue,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultStateSnapshotV1 {
    label: String,
    validators: Vec<FaultStateObservationV1>,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultObservationRecordV1 {
    record: String,
    bundle_id: String,
    participants: usize,
    seed: u64,
    run: u64,
    collection: String,
    trial_index: usize,
    expected_after_state: String,
    continuous_checks: u64,
    continuous_observations: Vec<FaultContinuousObservationSummaryV1>,
    partial_visibility_observed: bool,
    partial_spendable_observations: u64,
    snapshots: Vec<FaultStateSnapshotV1>,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultContinuousObservationSummaryV1 {
    peer_index: usize,
    check_count: u64,
    poll_failure_count: u64,
    first_response_sha256: String,
    last_response_sha256: String,
    response_chain_sha256: String,
    baseline_observations: u64,
    finalized_observations: u64,
    phase_coverage: Vec<FaultContinuousObservationPhaseSummaryV1>,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultContinuousObservationPhaseSummaryV1 {
    phase: String,
    expected_unavailable: bool,
    finalization_allowed: bool,
    successful_observations: u64,
    poll_failures: u64,
    baseline_observations: u64,
    finalized_observations: u64,
    checkpoint_attempt: u64,
    checkpoint_control_bindings: Vec<String>,
    attempt_chain_sha256: String,
    attempts: Vec<FaultContinuousObservationAttemptRunV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, norito::JsonSerialize)]
struct FaultContinuousObservationAttemptRunV1 {
    class: String,
    evidence: String,
    repetitions: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultStateIdentityV1 {
    ledger_commitment: String,
    replicated_staged_lock_commitment: String,
    staged_lock_commitment: String,
    counts: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultLedgerIdentityV1 {
    ledger_commitment: String,
    counts: String,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultPrepareQcNormalizationV1 {
    first_signer_subset: Vec<u8>,
    second_signer_subset: Vec<u8>,
    certified_body_sha256: String,
    first_qc_sha256: String,
    second_qc_sha256: String,
    first_normalized_barrier_sha256: String,
    second_normalized_barrier_sha256: String,
    equivalent_subsets_accepted: bool,
    changed_body_rejected: bool,
    authority_index_binding_verified: bool,
    signed_body_binding_verified: bool,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultRestartCommandV1 {
    format_version: u8,
    revision: u64,
    operation: String,
    peer_index: usize,
    before_pid: u32,
}

#[derive(Clone, Debug, norito::JsonSerialize)]
struct FaultRestartAckV1 {
    format_version: u8,
    revision: u64,
    command_sha256: String,
    operation: String,
    peer_index: usize,
    before_pid: u32,
    after_pid: u32,
    health_observed: bool,
}

struct FaultStoppedPeerV1 {
    peer: NetworkPeer,
    peer_index: usize,
    before_pid: u32,
    revision: u64,
    command_bytes: Vec<u8>,
}

struct FaultTrialDraftV1 {
    collection: &'static str,
    trial_index: usize,
    bundle_id: String,
    expected_after_state: &'static str,
    controls: Vec<FaultControlOccurrenceV1>,
    before: FaultStateSnapshotV1,
    nonfinalized: FaultStateSnapshotV1,
    continuous_observations: Vec<FaultContinuousObservationSummaryV1>,
}

struct FaultPreparedBundleV1 {
    manifest: AtomicPrivateSettlementV1,
    prepared: Vec<PreparedLeg>,
    materials: Vec<PrivateSettlementProvisionalLegMaterialV1>,
    authorities: Vec<PrivateSettlementCommitteeAuthorityV1>,
    deltas: Vec<PrivateSettlementDeltaV1>,
}

#[derive(Clone, Copy, Debug)]
struct ProcessResourceSample {
    cpu_seconds: f64,
    rss_bytes: u64,
}

const PRIVATE_BENCHMARK_STAGES: &[&str] = &[
    "proof_generation",
    "restricted_upload_availability",
    "auditor_response",
    "committee_verification",
    "prepare",
    "prepare_registration",
    "commit",
    "global_finality",
    "end_to_end",
];
const TRANSPARENT_CONTROL_BENCHMARK_STAGES: &[&str] = &["global_finality", "end_to_end"];
const LEAKAGE_CAPTURE_SURFACES: &[(&str, &str)] = &[
    ("block_wire_capture", "block-wire.bin"),
    ("event_capture", "events.json"),
    ("kura_artifact", "kura.bin"),
    ("merge_artifact", "merge.bin"),
    ("operator_log", "operator.json"),
    ("public_p2p_capture", "public-p2p.pcapng"),
    ("query_capture", "queries.json"),
    ("restricted_audit_source", "restricted-audit-sources.bin"),
    ("restricted_p2p_capture", "restricted-p2p.pcapng"),
    ("restricted_packet_source", "raw-loopback.pcap"),
    ("sanitized_capture", "sanitized-capture.pcapng"),
    ("snapshot_artifact", "snapshot.bin"),
    ("telemetry_capture", "telemetry.json"),
    ("torii_capture", "torii.pcapng"),
];
const LEAKAGE_TRAFFIC_COUNT_CHANNELS: &[&str] = &[
    "torii_request_packets",
    "torii_response_packets",
    "public_p2p_packets",
    "restricted_p2p_packets",
    "block_messages",
    "query_responses",
    "event_records",
    "log_records",
    "telemetry_records",
];
const LEAKAGE_CANARY_BASE_NAMES: &[&str] = &[
    "account_id",
    "amount",
    "asset_alias",
    "asset_id",
    "capsule",
    "memo",
];

fn benchmark_stages(profile: &str) -> Result<&'static [&'static str]> {
    match profile {
        "private" => Ok(PRIVATE_BENCHMARK_STAGES),
        "transparent_control" => Ok(TRANSPARENT_CONTROL_BENCHMARK_STAGES),
        _ => Err(eyre!("unsupported real-process benchmark profile")),
    }
}

fn lowercase_digest(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !value.bytes().all(|byte| byte == b'0')
}

fn harness_json_object_u64(value: &HarnessJsonValue, outer: &str, inner: &str) -> Option<u64> {
    value.get(outer)?.get(inner)?.as_u64()
}

fn harness_json_object_bool(value: &HarnessJsonValue, outer: &str, inner: &str) -> Option<bool> {
    value.get(outer)?.get(inner)?.as_bool()
}

fn harness_json_string_array<'a>(value: &'a HarnessJsonValue, key: &str) -> Option<Vec<&'a str>> {
    value
        .get(key)?
        .as_array()?
        .iter()
        .map(HarnessJsonValue::as_str)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn validate_real_process_request_common(
    version: u8,
    protocol: &str,
    kind: &str,
    request_id: &str,
    invocation_nonce: &str,
    commit: &str,
    hardware_sha256: &str,
    hardware_profile_sha256: &str,
    configuration_sha256: &str,
    participants: usize,
    participant_visibilities: &[String],
    validators_per_dataspace: usize,
    global_validators: usize,
    quorum: &str,
    mandatory_signed_rs16_da_rbc: bool,
    minimum_signed_rs16_da_observations: u64,
    authenticated_private_settlement_route_control: bool,
    configuration: &HarnessJsonValue,
) -> Result<()> {
    let shape = TopologyShape::new(participants);
    shape.validate()?;
    let expected_participant_visibilities = shape
        .participant_visibility_profile()
        .into_iter()
        .map(LaneVisibility::as_str)
        .collect::<Vec<_>>();
    ensure!(
        version == 1
            && protocol == "AtomicPrivateSettlementV1"
            && matches!(kind, "benchmark" | "fault" | "leakage"),
        "Rust harness supports only AtomicPrivateSettlementV1 release requests"
    );
    ensure!(
        validators_per_dataspace == VALIDATORS_PER_LANE
            && global_validators == VALIDATORS_PER_LANE
            && quorum == "3-of-4"
            && mandatory_signed_rs16_da_rbc
            && authenticated_private_settlement_route_control,
        "request weakens the required real-process topology"
    );
    ensure!(
        minimum_signed_rs16_da_observations
            == u64::try_from(shape.process_count()).expect("process count fits u64"),
        "signed RS16 observation minimum must cover every validator and committee observer"
    );
    ensure!(
        participant_visibilities
            .iter()
            .map(String::as_str)
            .eq(expected_participant_visibilities.iter().copied()),
        "request substitutes the canonical mixed participant visibility profile"
    );
    ensure!(
        harness_json_string_array(configuration, "participant_visibilities")
            .is_some_and(|profile| profile == expected_participant_visibilities),
        "embedded configuration substitutes the canonical mixed participant visibility profile"
    );
    ensure!(
        lowercase_digest(request_id, &[64])
            && lowercase_digest(invocation_nonce, &[64])
            && lowercase_digest(commit, &[40, 64])
            && lowercase_digest(hardware_sha256, &[64])
            && lowercase_digest(hardware_profile_sha256, &[64])
            && lowercase_digest(configuration_sha256, &[64]),
        "request contains a malformed binding digest"
    );
    ensure!(
        configuration
            .get("version")
            .and_then(HarnessJsonValue::as_u64)
            == Some(1)
            && configuration
                .get("protocol")
                .and_then(HarnessJsonValue::as_str)
                == Some("AtomicPrivateSettlementV1")
            && configuration
                .get("participants")
                .and_then(HarnessJsonValue::as_u64)
                == u64::try_from(participants).ok()
            && harness_json_object_u64(configuration, "execution", "rayon_worker_threads")
                == Some(REAL_PROCESS_RAYON_WORKER_THREADS)
            && harness_json_object_u64(configuration, "execution", "validator_worker_threads")
                == Some(REAL_PROCESS_VALIDATOR_WORKER_THREADS)
            && harness_json_object_u64(configuration, "execution", "cargo_build_jobs")
                == Some(REAL_PROCESS_CARGO_BUILD_JOBS)
            && harness_json_object_u64(configuration, "execution", "cargo_release_codegen_units",)
                == Some(REAL_PROCESS_CARGO_RELEASE_CODEGEN_UNITS)
            && harness_json_object_bool(configuration, "execution", "cargo_incremental")
                == Some(false)
            && harness_json_object_u64(configuration, "topology", "validators_per_dataspace",)
                == Some(4)
            && harness_json_object_u64(configuration, "topology", "global_validators",) == Some(4)
            && harness_json_object_bool(configuration, "consensus", "mandatory_signed_rs16_da_rbc",)
                == Some(true)
            && harness_json_object_bool(
                configuration,
                "consensus",
                "authenticated_private_settlement_route_control",
            ) == Some(true),
        "embedded configuration does not bind the required topology and execution widths"
    );
    ensure!(
        std::env::var(RAYON_NUM_THREADS_ENV).ok().as_deref()
            == Some(REAL_PROCESS_RAYON_WORKER_THREADS_TEXT),
        "Rust harness Rayon width differs from the bound release configuration"
    );
    ensure!(
        std::env::var("CARGO_BUILD_JOBS").ok().as_deref() == Some("1")
            && std::env::var("CARGO_INCREMENTAL").ok().as_deref() == Some("0")
            && std::env::var("CARGO_PROFILE_RELEASE_CODEGEN_UNITS")
                .ok()
                .as_deref()
                == Some("1")
            && std::env::var("CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_CODEGEN_UNITS")
                .ok()
                .as_deref()
                == Some("1")
            && std::env::var_os("RUSTFLAGS").is_none()
            && std::env::var_os("RUSTC_WRAPPER").is_none()
            && std::env::var_os("RUSTC_WORKSPACE_WRAPPER").is_none(),
        "Rust harness build environment differs from the bound release configuration"
    );
    Ok(())
}

fn validate_real_process_request(request: &RealProcessBenchmarkRequestV1) -> Result<()> {
    validate_real_process_request_common(
        request.version,
        &request.protocol,
        &request.kind,
        &request.request_id,
        &request.invocation_nonce,
        &request.commit,
        &request.hardware_sha256,
        &request.hardware_profile_sha256,
        &request.configuration_sha256,
        request.participants,
        &request.participant_visibilities,
        request.validators_per_dataspace,
        request.global_validators,
        &request.quorum,
        request.mandatory_signed_rs16_da_rbc,
        request.minimum_signed_rs16_da_observations,
        request.authenticated_private_settlement_route_control,
        &request.configuration,
    )?;
    ensure!(
        request.kind == "benchmark"
            && matches!(
                request.payload.profile.as_str(),
                "private" | "transparent_control"
            ),
        "Rust harness supports only canonical benchmark profiles"
    );
    ensure!(
        request.payload.stages
            == benchmark_stages(&request.payload.profile)?
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        "request contains a non-canonical profile stage inventory"
    );
    ensure!(
        request.payload.resources == ["proof_bytes", "receipt_bytes", "storage_growth_bytes",],
        "request contains a non-canonical resource inventory"
    );
    ensure!(
        lowercase_digest(&request.session_id, &[64])
            && lowercase_digest(&request.session_invocation_nonce, &[64])
            && lowercase_digest(&request.workload_manifest_sha256, &[64]),
        "benchmark request lacks exact session bindings"
    );
    let benchmark = request
        .configuration
        .get("benchmark")
        .ok_or_else(|| eyre!("configuration lacks benchmark session policy"))?;
    let warmups = benchmark
        .get("warmups_per_session")
        .and_then(HarnessJsonValue::as_u64)
        .ok_or_else(|| eyre!("configuration lacks per-session warmups"))?;
    ensure!(
        (5..=1000).contains(&warmups)
            && benchmark.get("warmups_per_profile").is_none()
            && benchmark
                .get("network_lifecycle")
                .and_then(HarnessJsonValue::as_str)
                == Some("one_retained_network_per_profile_participants_seed")
            && benchmark
                .get("prefunding_policy")
                .and_then(HarnessJsonValue::as_str)
                == Some("session_union_of_disjoint_attempts")
            && request.payload.warmup == (request.session_attempt_index < warmups),
        "benchmark session configuration or warmup classification differs"
    );
    Ok(())
}

fn validate_real_process_fault_request(request: &RealProcessFaultRequestV1) -> Result<()> {
    validate_real_process_request_common(
        request.version,
        &request.protocol,
        &request.kind,
        &request.request_id,
        &request.invocation_nonce,
        &request.commit,
        &request.hardware_sha256,
        &request.hardware_profile_sha256,
        &request.configuration_sha256,
        request.participants,
        &request.participant_visibilities,
        request.validators_per_dataspace,
        request.global_validators,
        &request.quorum,
        request.mandatory_signed_rs16_da_rbc,
        request.minimum_signed_rs16_da_observations,
        request.authenticated_private_settlement_route_control,
        &request.configuration,
    )?;
    let normalization = &request.payload.prepare_qc_normalization;
    ensure!(
        request.kind == "fault"
            && request.payload.loss_phases == ["restricted_da", "prepare", "commit"]
            && request.payload.loss_percentages == [5, 10, 20]
            && request.payload.phase_cuts
                == [
                    "da_before_availability_qc",
                    "prepare_before_complete_barrier",
                    "commit_before_complete_barrier",
                    "restart_before_global_finality",
                ]
            && request.payload.crash_boundaries == PRIVATE_SETTLEMENT_CRASH_BOUNDARIES
            && request.payload.committee_validator_restarts
                == (0..request.participants).collect::<Vec<_>>()
            && request.payload.restart_coordinator
            && request.payload.restart_global_node
            && request
                .payload
                .maximum_simultaneously_unavailable_per_committee
                == 1
            && request.payload.continuous_atomicity_checks
            && normalization.first_signer_subset == [0, 1, 2]
            && normalization.second_signer_subset == [0, 1, 3]
            && normalization.accept_equivalent_subsets_only_for_identical_body
            && normalization.bind_authority_indices
            && normalization.bind_every_signed_body
            && normalization.reject_changed_certified_body,
        "fault request differs from the exact release matrix"
    );
    let _ = request.run;
    Ok(())
}

fn validate_real_process_leakage_request(request: &RealProcessLeakageRequestV1) -> Result<()> {
    validate_real_process_request_common(
        request.version,
        &request.protocol,
        &request.kind,
        &request.request_id,
        &request.invocation_nonce,
        &request.commit,
        &request.hardware_sha256,
        &request.hardware_profile_sha256,
        &request.configuration_sha256,
        request.participants,
        &request.participant_visibilities,
        request.validators_per_dataspace,
        request.global_validators,
        &request.quorum,
        request.mandatory_signed_rs16_da_rbc,
        request.minimum_signed_rs16_da_observations,
        request.authenticated_private_settlement_route_control,
        &request.configuration,
    )?;
    ensure!(
        request.kind == "leakage"
            && request.participants == PARTICIPANT_COUNT
            && request.run == 0
            && matches!(request.payload.variant.as_str(), "left" | "right")
            && request.payload.only_secret_fields_change,
        "leakage request is outside the exact primary differential profile"
    );
    let suffix = if request.payload.variant == "left" {
        ""
    } else {
        "_variant_b"
    };
    let expected_names = LEAKAGE_CANARY_BASE_NAMES
        .iter()
        .map(|name| format!("{name}{suffix}"))
        .collect::<Vec<_>>();
    ensure!(
        request
            .payload
            .canaries
            .iter()
            .map(|canary| canary.name.clone())
            .collect::<Vec<_>>()
            == expected_names
            && request
                .payload
                .canary_commitments
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                == expected_names
            && request
                .payload
                .canary_commitments
                .values()
                .all(|digest| lowercase_digest(digest, &[64])),
        "leakage request has a substituted canary inventory"
    );
    let expected_kinds = ["text", "integer", "text", "text", "binary_base64", "text"];
    ensure!(
        request
            .payload
            .canaries
            .iter()
            .map(|canary| canary.kind.as_str())
            .eq(expected_kinds),
        "leakage request has a substituted canary kind"
    );
    for canary in &request.payload.canaries {
        ensure!(
            request.payload.canary_commitments.get(&canary.name)
                == Some(&leakage_canary_commitment(canary)?),
            "leakage request canary commitment does not bind its canonical value"
        );
    }
    ensure!(
        request
            .payload
            .capture_surfaces
            .iter()
            .map(|surface| (surface.surface.as_str(), surface.relative_name.as_str()))
            .eq(LEAKAGE_CAPTURE_SURFACES.iter().copied())
            && request
                .payload
                .traffic_count_channels
                .iter()
                .map(String::as_str)
                .eq(LEAKAGE_TRAFFIC_COUNT_CHANNELS.iter().copied()),
        "leakage request changed the exact capture inventory"
    );
    Ok(())
}

fn leakage_canary_commitment(canary: &RealProcessLeakageCanaryV1) -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical_harness_json_bytes(
        canary,
    )?)))
}

fn leakage_canary<'a>(
    request: &'a RealProcessLeakageRequestV1,
    base_name: &str,
) -> Result<&'a RealProcessLeakageCanaryV1> {
    let suffix = if request.payload.variant == "left" {
        ""
    } else {
        "_variant_b"
    };
    let expected = format!("{base_name}{suffix}");
    request
        .payload
        .canaries
        .iter()
        .find(|canary| canary.name == expected)
        .ok_or_else(|| eyre!("leakage request lacks {expected}"))
}

fn leakage_text_canary(request: &RealProcessLeakageRequestV1, base_name: &str) -> Result<String> {
    leakage_canary(request, base_name)?
        .value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| eyre!("leakage {base_name} canary is not text"))
}

fn append_fixed_leakage_memo_field(
    output: &mut Vec<u8>,
    tag: &[u8; 8],
    value: &[u8],
    capacity: usize,
) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= capacity && capacity <= usize::from(u16::MAX),
        "leakage memo field is empty or exceeds its fixed capacity"
    );
    output.extend_from_slice(tag);
    output.extend_from_slice(&u16::try_from(value.len())?.to_le_bytes());
    output.extend_from_slice(value);
    output.resize(output.len() + capacity - value.len(), 0);
    Ok(())
}

fn leakage_private_leg_zero(
    request: &RealProcessLeakageRequestV1,
) -> Result<(PrivateSettlementLegPrivateData, AssetDefinitionId)> {
    let variant = request.payload.variant.as_str();
    let expected_account = leakage_canary_account_id(variant)?;
    let account_text = leakage_text_canary(request, "account_id")?;
    ensure!(
        account_text == expected_account.canonical_i105()?,
        "leakage account canary does not match the fixed typed payer"
    );
    let expected_asset = leakage_canary_asset_definition_id(variant)?;
    let asset_text = leakage_text_canary(request, "asset_id")?;
    ensure!(
        asset_text.parse::<AssetDefinitionId>()? == expected_asset,
        "leakage asset canary does not match the fixed restricted-governance asset"
    );
    let amount = leakage_canary(request, "amount")?
        .value
        .as_u128()
        .ok_or_else(|| eyre!("leakage amount canary is not an unsigned integer"))?;
    ensure!(
        amount > 5 && amount < (1_u128 << 120),
        "leakage amount is outside the proof-safe bound"
    );
    let memo_text = leakage_text_canary(request, "memo")?;
    let asset_alias = leakage_text_canary(request, "asset_alias")?;
    let capsule_text = leakage_text_canary(request, "capsule")?;
    let capsule = base64::engine::general_purpose::STANDARD
        .decode(capsule_text.as_bytes())
        .wrap_err("decode leakage capsule canary")?;
    ensure!(
        base64::engine::general_purpose::STANDARD.encode(&capsule) == capsule_text,
        "leakage capsule canary is not canonical Base64"
    );
    let mut memo = b"iroha:aps-leakage-memo:v1\0".to_vec();
    append_fixed_leakage_memo_field(
        &mut memo,
        b"memo-v1\0",
        memo_text.as_bytes(),
        LEAKAGE_MEMO_FIELD_BYTES,
    )?;
    append_fixed_leakage_memo_field(
        &mut memo,
        b"alias-v1",
        asset_alias.as_bytes(),
        LEAKAGE_ALIAS_FIELD_BYTES,
    )?;
    append_fixed_leakage_memo_field(
        &mut memo,
        b"caps-v1\0",
        &capsule,
        LEAKAGE_CAPSULE_FIELD_BYTES,
    )?;
    Ok((
        PrivateSettlementLegPrivateData {
            payer: leakage_canary_keypair(variant)?,
            recipient: default_private_settlement_leg_data(0).recipient,
            amount,
            memo,
        },
        expected_asset,
    ))
}

#[derive(Clone, Debug)]
struct LeakageCanaryNeedleV1 {
    name: String,
    encoding: String,
    bytes: Vec<u8>,
}

fn push_leakage_canary_needle(
    needles: &mut Vec<LeakageCanaryNeedleV1>,
    name: &str,
    encoding: &str,
    bytes: Vec<u8>,
) {
    if bytes.is_empty()
        || needles
            .iter()
            .any(|needle| needle.name == name && needle.bytes == bytes)
    {
        return;
    }
    needles.push(LeakageCanaryNeedleV1 {
        name: name.to_owned(),
        encoding: encoding.to_owned(),
        bytes,
    });
}

fn leakage_percent_encoded(value: &str) -> Vec<u8> {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded.into_bytes()
}

fn leakage_json_ascii_string(value: &str) -> Vec<u8> {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\u{08}' => encoded.push_str("\\b"),
            '\u{0c}' => encoded.push_str("\\f"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if (' '..='~').contains(&character) => encoded.push(character),
            character => {
                let scalar = u32::from(character);
                if scalar <= 0xffff {
                    encoded.push_str(&format!("\\u{scalar:04x}"));
                } else {
                    let value = scalar - 0x1_0000;
                    let high = 0xd800 + (value >> 10);
                    let low = 0xdc00 + (value & 0x3ff);
                    encoded.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                }
            }
        }
    }
    encoded.push('\"');
    encoded.into_bytes()
}

fn append_leakage_text_needles(needles: &mut Vec<LeakageCanaryNeedleV1>, name: &str, value: &str) {
    let raw = value.as_bytes().to_vec();
    push_leakage_canary_needle(needles, name, "utf8", raw.clone());
    push_leakage_canary_needle(
        needles,
        name,
        "utf16le",
        value.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    );
    push_leakage_canary_needle(
        needles,
        name,
        "utf16be",
        value.encode_utf16().flat_map(u16::to_be_bytes).collect(),
    );
    push_leakage_canary_needle(needles, name, "hex_lower", hex::encode(&raw).into_bytes());
    push_leakage_canary_needle(
        needles,
        name,
        "hex_upper",
        hex::encode_upper(&raw).into_bytes(),
    );
    push_leakage_canary_needle(
        needles,
        name,
        "base64",
        base64::engine::general_purpose::STANDARD
            .encode(&raw)
            .into_bytes(),
    );
    push_leakage_canary_needle(
        needles,
        name,
        "base64url",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&raw)
            .into_bytes(),
    );
    push_leakage_canary_needle(needles, name, "url_percent", leakage_percent_encoded(value));
    push_leakage_canary_needle(
        needles,
        name,
        "json_string",
        leakage_json_ascii_string(value),
    );
}

fn leakage_leb128(mut value: u128) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = u8::try_from(value & 0x7f).expect("LEB128 digit fits u8");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn leakage_asset_address_payload(asset: &AssetDefinitionId) -> [u8; 21] {
    let mut payload = [0_u8; 21];
    payload[0] = 1;
    payload[1..17].copy_from_slice(&asset.aid_bytes());
    let checksum = blake3::hash(&payload[..17]);
    payload[17..].copy_from_slice(&checksum.as_bytes()[..4]);
    payload
}

fn leakage_canary_needles(
    request: &RealProcessLeakageRequestV1,
) -> Result<Vec<LeakageCanaryNeedleV1>> {
    let mut needles = Vec::new();
    for base_name in ["account_id", "asset_alias", "asset_id", "memo"] {
        let canary = leakage_canary(request, base_name)?;
        let value = canary
            .value
            .as_str()
            .ok_or_else(|| eyre!("leakage {base_name} canary is not text"))?;
        append_leakage_text_needles(&mut needles, &canary.name, value);
    }
    let amount_canary = leakage_canary(request, "amount")?;
    let amount = amount_canary
        .value
        .as_u128()
        .ok_or_else(|| eyre!("leakage amount canary is not an unsigned integer"))?;
    for (encoding, bytes) in [
        ("decimal", amount.to_string().into_bytes()),
        ("decimal_json_string", format!("\"{amount}\"").into_bytes()),
        ("hex_lower", format!("{amount:x}").into_bytes()),
        ("hex_upper", format!("{amount:X}").into_bytes()),
        ("leb128", leakage_leb128(amount)),
        ("u128_le", amount.to_le_bytes().to_vec()),
        ("u128_be", amount.to_be_bytes().to_vec()),
        (
            "u256_le",
            amount.to_le_bytes().into_iter().chain([0_u8; 16]).collect(),
        ),
        (
            "u256_be",
            [0_u8; 16].into_iter().chain(amount.to_be_bytes()).collect(),
        ),
    ] {
        push_leakage_canary_needle(&mut needles, &amount_canary.name, encoding, bytes);
    }
    let capsule_canary = leakage_canary(request, "capsule")?;
    let capsule_text = capsule_canary
        .value
        .as_str()
        .ok_or_else(|| eyre!("leakage capsule canary is not text"))?;
    let capsule = base64::engine::general_purpose::STANDARD
        .decode(capsule_text.as_bytes())
        .wrap_err("decode leakage capsule scan canary")?;
    for (encoding, bytes) in [
        ("raw", capsule.clone()),
        ("hex_lower", hex::encode(&capsule).into_bytes()),
        ("hex_upper", hex::encode_upper(&capsule).into_bytes()),
        ("base64", capsule_text.as_bytes().to_vec()),
        (
            "base64url",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&capsule)
                .into_bytes(),
        ),
    ] {
        push_leakage_canary_needle(&mut needles, &capsule_canary.name, encoding, bytes);
    }
    let account = leakage_canary_account_id(&request.payload.variant)?;
    let asset = leakage_canary_asset_definition_id(&request.payload.variant)?;
    push_leakage_canary_needle(
        &mut needles,
        &leakage_canary(request, "account_id")?.name,
        "canonical_account_bytes",
        hex::decode(account.to_canonical_hex()?)?,
    );
    push_leakage_canary_needle(
        &mut needles,
        &leakage_canary(request, "account_id")?.name,
        "account_public_key_bytes",
        account.expect_single_signatory().to_bytes().1.to_vec(),
    );
    push_leakage_canary_needle(
        &mut needles,
        &leakage_canary(request, "account_id")?.name,
        "norito_account_id",
        norito::encode_canonical(&account)?,
    );
    push_leakage_canary_needle(
        &mut needles,
        &leakage_canary(request, "asset_id")?.name,
        "asset_address_payload",
        leakage_asset_address_payload(&asset).to_vec(),
    );
    push_leakage_canary_needle(
        &mut needles,
        &leakage_canary(request, "asset_id")?.name,
        "norito_asset_definition_id",
        norito::encode_canonical(&asset)?,
    );
    push_leakage_canary_needle(
        &mut needles,
        &leakage_canary(request, "asset_id")?.name,
        "asset_uuid_bytes",
        asset.aid_bytes().to_vec(),
    );
    ensure!(
        !needles.is_empty(),
        "leakage canary scan inventory is empty"
    );
    Ok(needles)
}

fn ensure_leakage_sources_redacted(
    needles: &[LeakageCanaryNeedleV1],
    label: &str,
    sources: &[&[u8]],
) -> Result<()> {
    ensure!(!sources.is_empty(), "{label} has no genuine source bytes");
    for (source_index, source) in sources.iter().enumerate() {
        ensure!(
            !source.is_empty(),
            "{label} source #{source_index} is empty"
        );
        for needle in needles {
            ensure!(
                !source
                    .windows(needle.bytes.len())
                    .any(|window| window == needle.bytes),
                "{label} raw source #{source_index} leaked canary {} ({})",
                needle.name,
                needle.encoding
            );
        }
    }
    Ok(())
}

fn read_bound_real_process_request() -> Result<(RealProcessBoundRequestV1, String)> {
    let path = PathBuf::from(
        std::env::var(HARNESS_REQUEST_ENV).wrap_err("missing real-process request path")?,
    );
    let metadata = fs::symlink_metadata(&path).wrap_err("inspect real-process request")?;
    ensure!(
        metadata.file_type().is_file(),
        "request is not a regular file"
    );
    ensure!(
        usize::try_from(metadata.len()).is_ok_and(|len| len <= HARNESS_MAX_JSON_BYTES),
        "request exceeds the Rust JSON bound"
    );
    let mut file = File::open(&path).wrap_err("open real-process request")?;
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(HARNESS_MAX_JSON_BYTES + 1).expect("bound fits u64"))
        .read_to_end(&mut raw)
        .wrap_err("read real-process request")?;
    ensure!(raw.len() <= HARNESS_MAX_JSON_BYTES, "request is too large");
    let request_sha = hex::encode(Sha256::digest(&raw));
    let expected_sha =
        std::env::var(HARNESS_REQUEST_SHA_ENV).wrap_err("missing real-process request digest")?;
    ensure!(
        lowercase_digest(&expected_sha, &[64]) && request_sha == expected_sha,
        "request bytes do not match the launcher binding"
    );
    let text = std::str::from_utf8(&raw).wrap_err("request is not UTF-8")?;
    let value: HarnessJsonValue =
        norito::json::from_str(text).wrap_err("decode strict real-process request")?;
    let kind = value
        .get("kind")
        .and_then(HarnessJsonValue::as_str)
        .ok_or_else(|| eyre!("real-process request lacks kind"))?;
    let request = match kind {
        "smoke" | "happy_day" => {
            let request: RealProcessSmokeRequestV1 =
                norito::json::from_value(value).wrap_err("decode strict smoke request")?;
            validate_real_process_smoke_request(&request)?;
            RealProcessBoundRequestV1::Smoke(request)
        }
        "benchmark" => {
            let request: RealProcessBenchmarkRequestV1 =
                norito::json::from_value(value).wrap_err("decode strict benchmark request")?;
            validate_real_process_request(&request)?;
            RealProcessBoundRequestV1::Benchmark(request)
        }
        "fault" => {
            let request: RealProcessFaultRequestV1 =
                norito::json::from_value(value).wrap_err("decode strict fault request")?;
            validate_real_process_fault_request(&request)?;
            RealProcessBoundRequestV1::Fault(request)
        }
        "leakage" => {
            let request: RealProcessLeakageRequestV1 =
                norito::json::from_value(value).wrap_err("decode strict leakage request")?;
            validate_real_process_leakage_request(&request)?;
            RealProcessBoundRequestV1::Leakage(request)
        }
        _ => return Err(eyre!("unsupported real-process request kind")),
    };
    Ok((request, request_sha))
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

/// Resolve the kernel-owned executable path, never a process display string.
#[cfg_attr(target_os = "macos", allow(unsafe_code))]
fn executable_for_pid(pid: u32) -> Result<PathBuf> {
    ensure!(
        pid > 0 && i32::try_from(pid).is_ok(),
        "invalid process PID {pid}"
    );
    #[cfg(target_os = "linux")]
    {
        return fs::read_link(format!("/proc/{pid}/exe"))
            .wrap_err_with(|| format!("resolve executable for PID {pid}"));
    }
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::c_void, os::unix::ffi::OsStringExt as _};

        #[link(name = "proc")]
        unsafe extern "C" {
            fn proc_pidpath(pid: i32, buffer: *mut c_void, buffersize: u32) -> i32;
        }
        // The Darwin SDK defines PROC_PIDPATHINFO_MAXSIZE as 4 * MAXPATHLEN.
        const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
        let mut buffer = [0_u8; PROC_PIDPATHINFO_MAXSIZE];
        let native_pid = i32::try_from(pid).expect("PID was checked above");
        // SAFETY: the valid mutable buffer spans the exact supplied capacity;
        // proc_pidpath writes at most that capacity and retains no pointer.
        let count = unsafe {
            proc_pidpath(
                native_pid,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).expect("Darwin path bound fits u32"),
            )
        };
        if count <= 0 {
            return Err(std::io::Error::last_os_error())
                .wrap_err_with(|| format!("read kernel executable path for PID {pid}"));
        }
        let count = usize::try_from(count).expect("positive path length fits usize");
        ensure!(
            count < buffer.len() && buffer[count] == 0 && !buffer[..count].contains(&0),
            "kernel executable path for PID {pid} is incomplete"
        );
        // Unix paths are byte strings. Neither the caller's locale nor lossy
        // Unicode conversion may reinterpret the kernel's image identity.
        let path = PathBuf::from(std::ffi::OsString::from_vec(buffer[..count].to_vec()));
        ensure!(
            path.is_absolute(),
            "kernel executable path for PID {pid} is not absolute"
        );
        return fs::canonicalize(path)
            .wrap_err_with(|| format!("resolve kernel executable path for PID {pid}"));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(eyre!(
            "kernel executable identity is unsupported on this platform"
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn executable_identity_current_process_matches_kernel_image() {
    let actual = executable_for_pid(std::process::id()).expect("current kernel image");
    let expected = fs::canonicalize(std::env::current_exe().expect("current test image"))
        .expect("canonical current test image");
    assert_eq!(actual, expected);
    assert_eq!(
        sha256_regular_file(&actual).expect("kernel image digest"),
        sha256_regular_file(&expected).expect("current image digest")
    );
}

#[test]
fn executable_identity_rejects_invalid_pid() {
    for pid in [0, u32::MAX] {
        assert!(
            executable_for_pid(pid).is_err(),
            "accepted invalid PID {pid}"
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn with_executable_identity_child(
    observe: impl FnOnce(&mut Child, &Path),
    reaped: &std::cell::Cell<bool>,
) {
    use std::os::unix::process::CommandExt as _;

    let directory = tempfile::tempdir().expect("owned image fixture root");
    let image = directory.path().join("証明 image with spaces");
    let original = std::env::current_exe().expect("locally compiled test image");
    fs::copy(&original, &image).expect("copy local test image, not a platform executable");
    fs::set_permissions(&image, fs::Permissions::from_mode(0o700))
        .expect("executable fixture mode");
    let image = fs::canonicalize(image).expect("canonical fixture image");
    let mut child = Command::new(&image)
        .arg0("misleading argv0 that is not an executable path")
        .args([
            "--ignored",
            "--exact",
            "nexus::atomic_private_settlement_localnet::executable_identity_self_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the owned local-image fixture");
    // Every fallible observation/assertion is inside the unwind boundary. Close
    // stdin and reap the actual child before propagating the original panic.
    let mut output = None;
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        use std::io::BufRead as _;
        output = Some(std::io::BufReader::new(
            child.stdout.take().expect("child stdout"),
        ));
        let mut line = String::new();
        loop {
            line.clear();
            assert!(
                output
                    .as_mut()
                    .expect("owned stdout reader")
                    .read_line(&mut line)
                    .expect("read child ready")
                    > 0,
                "child exited before entering the exact fixture"
            );
            if line.trim_end().ends_with("executable-identity-ready") {
                break;
            }
        }
        observe(&mut child, &image);
    }));
    drop(child.stdin.take());
    let status = loop {
        match child.wait() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            status => break status.expect("reap the owned image fixture"),
        }
    };
    // Keep the read end alive until the child finishes its bounded libtest output.
    drop(output);
    reaped.set(true);
    assert!(status.success(), "owned image fixture failed: {status}");
    if let Err(payload) = observed {
        std::panic::resume_unwind(payload);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn executable_identity_preserves_unicode_spaces_and_ignores_argv0() {
    let reaped = std::cell::Cell::new(false);
    with_executable_identity_child(
        |child, image| {
            assert!(child.try_wait().expect("observe live child").is_none());
            let actual = executable_for_pid(child.id()).expect("kernel child image");
            assert_eq!(actual.as_path(), image);
            assert_eq!(
                sha256_regular_file(&actual).expect("actual child digest"),
                sha256_regular_file(image).expect("copied image digest")
            );
        },
        &reaped,
    );
    assert!(reaped.get());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn executable_identity_observation_unwind_reaps_child() {
    let reaped = std::cell::Cell::new(false);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_executable_identity_child(
            |_, _| {
                std::panic::resume_unwind(Box::new("image observation panic"));
            },
            &reaped,
        );
    }))
    .expect_err("the observation panic must remain visible");
    assert!(
        reaped.get(),
        "the child must be reaped before the panic escapes"
    );
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"image observation panic")
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "owned executable-identity subprocess entrypoint"]
fn executable_identity_self_child() {
    assert_eq!(
        std::env::args_os().next(),
        Some(std::ffi::OsString::from(
            "misleading argv0 that is not an executable path"
        ))
    );
    println!("executable-identity-ready");
    std::io::stdout().flush().expect("publish child ready");
    let mut byte = [0_u8; 1];
    assert_eq!(
        std::io::stdin()
            .read(&mut byte)
            .expect("wait for parent EOF"),
        0
    );
}

/// Parse the portable ps CPU clock without accepting signed or nonfinite values.
fn parse_ps_cpu_time(value: &str) -> Result<f64> {
    let decimal_integer = |part: &str| -> Result<u64> {
        ensure!(
            !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid ps CPU integer component"
        );
        Ok(part.parse::<u64>()?)
    };
    let (days, clock, has_days) = if let Some((days, clock)) = value.split_once('-') {
        (decimal_integer(days)?, clock, true)
    } else {
        (0_u64, value, false)
    };
    let parts = clock.split(':').collect::<Vec<_>>();
    ensure!(
        (2..=3).contains(&parts.len()) && (!has_days || parts.len() == 3),
        "invalid ps CPU clock shape"
    );
    let (hours, minutes, seconds) = if parts.len() == 3 {
        let hours = decimal_integer(parts[0])?;
        let minutes = decimal_integer(parts[1])?;
        ensure!(
            minutes < 60 && (!has_days || hours < 24),
            "invalid ps CPU clock range"
        );
        (hours, minutes, parts[2])
    } else {
        (0, decimal_integer(parts[0])?, parts[1])
    };
    let mut second_parts = seconds.split('.');
    decimal_integer(second_parts.next().expect("split yields one component"))?;
    if let Some(fraction) = second_parts.next() {
        ensure!(
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid ps CPU fractional seconds"
        );
    }
    ensure!(second_parts.next().is_none(), "invalid ps CPU seconds");
    let seconds = seconds.parse::<f64>()?;
    ensure!(
        seconds.is_finite() && (0.0..60.0).contains(&seconds),
        "invalid ps CPU seconds range"
    );
    let total = days as f64 * 86_400.0 + hours as f64 * 3_600.0 + minutes as f64 * 60.0 + seconds;
    ensure!(total.is_finite(), "ps CPU total is not finite");
    Ok(total)
}

/// Require a complete sample of exactly the requested live process set.
fn parse_process_resource_rows(text: &str, pids: &[u32]) -> Result<ProcessResourceSample> {
    ensure!(
        !pids.is_empty()
            && pids.iter().all(|pid| *pid != 0)
            && pids.iter().copied().collect::<BTreeSet<_>>().len() == pids.len(),
        "resource process inventory is empty, duplicated, or invalid"
    );
    let mut observed = BTreeSet::new();
    let mut cpu_seconds = 0.0;
    let mut rss_kib = 0_u64;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(fields.len() == 3, "unexpected ps resource row");
        let pid = fields[0].parse::<u32>()?;
        ensure!(pids.contains(&pid), "ps returned an unrequested PID");
        ensure!(observed.insert(pid), "ps returned a duplicate PID");
        rss_kib = rss_kib
            .checked_add(fields[1].parse::<u64>()?)
            .ok_or_else(|| eyre!("RSS total overflow"))?;
        cpu_seconds += parse_ps_cpu_time(fields[2])?;
        ensure!(cpu_seconds.is_finite(), "process CPU total is not finite");
    }
    ensure!(
        observed.len() == pids.len(),
        "one measured process disappeared"
    );
    Ok(ProcessResourceSample {
        cpu_seconds,
        rss_bytes: rss_kib
            .checked_mul(1_024)
            .ok_or_else(|| eyre!("RSS byte total overflow"))?,
    })
}

fn sample_process_resources(pids: &[u32]) -> Result<ProcessResourceSample> {
    ensure!(!pids.is_empty(), "cannot sample an empty process set");
    let joined = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let output = Command::new("ps")
        .args(["-p", &joined, "-o", "pid=,rss=,time="])
        .output()
        .wrap_err("sample process resources")?;
    ensure!(output.status.success(), "ps resource sampling failed");
    let text = std::str::from_utf8(&output.stdout).wrap_err("ps output is not UTF-8")?;
    parse_process_resource_rows(text, pids)
}

/// A failed periodic sample invalidates the measurement instead of hiding a gap.
struct ProcessResourceSampler {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Result<u64>>>,
}

impl ProcessResourceSampler {
    fn start(pids: Vec<u32>, initial_rss_bytes: u64) -> Result<Self> {
        Self::start_with_sampler(pids, initial_rss_bytes, sample_process_resources)
    }

    /// Keep sampler ownership identical for native sampling and deterministic failure tests.
    fn start_with_sampler<F>(pids: Vec<u32>, initial_rss_bytes: u64, mut sample: F) -> Result<Self>
    where
        F: FnMut(&[u32]) -> Result<ProcessResourceSample> + Send + 'static,
    {
        ensure!(
            !pids.is_empty()
                && pids.iter().all(|pid| *pid != 0)
                && pids.iter().copied().collect::<BTreeSet<_>>().len() == pids.len(),
            "resource process inventory is empty, duplicated, or invalid"
        );
        let stop = Arc::new(AtomicBool::new(false));
        let sampler_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("aps-real-process-rss-sampler".to_owned())
            .spawn(move || {
                let mut peak_rss_bytes = initial_rss_bytes;
                while !sampler_stop.load(Ordering::Relaxed) {
                    let observed =
                        sample(&pids).wrap_err("periodic process resource sample failed")?;
                    peak_rss_bytes = peak_rss_bytes.max(observed.rss_bytes);
                    thread::sleep(Duration::from_millis(100));
                }
                Ok(peak_rss_bytes)
            })?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }

    fn finish(mut self, final_rss_bytes: u64) -> Result<u64> {
        self.stop.store(true, Ordering::Relaxed);
        let handle = self
            .handle
            .take()
            .ok_or_else(|| eyre!("RSS sampler ownership missing"))?;
        let peak = handle
            .join()
            .map_err(|_| eyre!("RSS sampler thread panicked"))??;
        Ok(peak.max(final_rss_bytes))
    }
}

impl Drop for ProcessResourceSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn regular_tree_bytes(root: &Path) -> Result<u64> {
    let mut total = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    while let Some(path) = stack.pop() {
        let metadata = fs::symlink_metadata(&path)
            .wrap_err_with(|| format!("inspect storage path {}", path.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "storage measurement encountered a symbolic link"
        );
        if metadata.is_file() {
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| eyre!("storage measurement overflow"))?;
            continue;
        }
        ensure!(metadata.is_dir(), "storage contains a special file");
        for entry in fs::read_dir(&path)? {
            stack.push(entry?.path());
            entries += 1;
            ensure!(entries <= 1_000_000, "storage tree exceeds entry bound");
        }
    }
    Ok(total)
}

fn network_storage_bytes(network: &Network) -> Result<u64> {
    network.all_peers().try_fold(0_u64, |total, peer| {
        total
            .checked_add(regular_tree_bytes(&peer.kura_store_dir())?)
            .ok_or_else(|| eyre!("network storage total overflow"))
    })
}

#[derive(Debug, norito::JsonSerialize)]
struct LeakagePortManifestV1 {
    version: u8,
    torii_ports: Vec<u16>,
    public_p2p_ports: Vec<u16>,
    restricted_p2p_ports: Vec<u16>,
}

fn leakage_evidence_root() -> Result<PathBuf> {
    let root = PathBuf::from(
        std::env::var(HARNESS_EVIDENCE_DIR_ENV).wrap_err("missing leakage evidence directory")?,
    );
    let canonical = root
        .canonicalize()
        .wrap_err("resolve leakage evidence directory")?;
    ensure!(
        canonical == root,
        "leakage evidence directory is not canonical"
    );
    let metadata = fs::symlink_metadata(&root)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == 0o700
            && fs::read_dir(&root)?.next().is_none(),
        "leakage evidence directory is unsafe or non-empty"
    );
    Ok(root)
}

fn collect_network_port_manifest(
    network: &Network,
    shape: TopologyShape,
) -> Result<LeakagePortManifestV1> {
    shape.validate()?;
    ensure!(
        network.all_peers().count() == shape.process_count(),
        "network endpoint process count differs"
    );
    let mut torii_ports = network
        .all_peers()
        .map(|peer| peer.api_address().port())
        .collect::<Vec<_>>();
    let processes = network.all_peers().collect::<Vec<_>>();
    let mut public_p2p_ports = Vec::new();
    let mut restricted_p2p_ports = Vec::new();
    for lane in 0..shape.lane_count() {
        let visibility = if lane == 0 {
            LaneVisibility::Public
        } else {
            shape.participant_visibility(lane - 1)
        };
        let destination = match visibility {
            LaneVisibility::Public => &mut public_p2p_ports,
            LaneVisibility::Restricted => &mut restricted_p2p_ports,
        };
        destination.extend(
            processes[shape.committee_range(lane)]
                .iter()
                .map(|peer| peer.p2p_address().port()),
        );
    }
    for ports in [
        &mut torii_ports,
        &mut public_p2p_ports,
        &mut restricted_p2p_ports,
    ] {
        ports.sort_unstable();
        ports.dedup();
    }
    let all_ports = torii_ports
        .iter()
        .chain(&public_p2p_ports)
        .chain(&restricted_p2p_ports)
        .copied()
        .collect::<BTreeSet<_>>();
    let (expected_public_p2p, expected_restricted_p2p) = shape.p2p_process_counts_by_visibility();
    ensure!(
        !all_ports.contains(&0)
            && torii_ports.len() == shape.process_count()
            && public_p2p_ports.len() == expected_public_p2p
            && restricted_p2p_ports.len() == expected_restricted_p2p
            && all_ports.len()
                == torii_ports.len() + public_p2p_ports.len() + restricted_p2p_ports.len(),
        "leakage capture ports are incomplete or overlap"
    );
    Ok(LeakagePortManifestV1 {
        version: 1,
        torii_ports,
        public_p2p_ports,
        restricted_p2p_ports,
    })
}

fn write_leakage_port_manifest(network: &Network, shape: TopologyShape) -> Result<()> {
    let path = PathBuf::from(
        std::env::var(HARNESS_PORT_MANIFEST_ENV)
            .wrap_err("missing leakage capture port-manifest path")?,
    );
    ensure!(!path.exists(), "leakage port manifest path already exists");
    write_owner_only_atomic(
        &path,
        &canonical_harness_json_bytes(&collect_network_port_manifest(network, shape)?)?,
    )
}

fn read_stable_leakage_source(path: &Path) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("inspect leakage source {}", path.display()))?;
    ensure!(
        before.is_file()
            && !before.file_type().is_symlink()
            && usize::try_from(before.len()).is_ok_and(|len| len <= LEAKAGE_MAX_SOURCE_BYTES),
        "leakage source is not a bounded regular file"
    );
    let mut file =
        File::open(path).wrap_err_with(|| format!("open leakage source {}", path.display()))?;
    let opened = file.metadata()?;
    ensure!(
        std::os::unix::fs::MetadataExt::dev(&before)
            == std::os::unix::fs::MetadataExt::dev(&opened)
            && std::os::unix::fs::MetadataExt::ino(&before)
                == std::os::unix::fs::MetadataExt::ino(&opened),
        "leakage source changed before open"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(LEAKAGE_MAX_SOURCE_BYTES + 1).expect("bound fits u64"))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() <= LEAKAGE_MAX_SOURCE_BYTES
            && before.len() == u64::try_from(bytes.len())?
            && opened.len() == after.len()
            && std::os::unix::fs::MetadataExt::mtime(&opened)
                == std::os::unix::fs::MetadataExt::mtime(&after)
            && std::os::unix::fs::MetadataExt::mtime_nsec(&opened)
                == std::os::unix::fs::MetadataExt::mtime_nsec(&after),
        "leakage source changed while read"
    );
    Ok(bytes)
}

fn collect_leakage_source_files<F>(root: &Path, mut selected: F) -> Result<Vec<(String, Vec<u8>)>>
where
    F: FnMut(&Path) -> bool,
{
    let canonical_root = root
        .canonicalize()
        .wrap_err("canonicalize leakage source root")?;
    let mut stack = vec![canonical_root.clone()];
    let mut paths = Vec::new();
    let mut visited = 0_usize;
    while let Some(path) = stack.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "leakage source tree contains a symbolic link"
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                stack.push(entry?.path());
                visited += 1;
                ensure!(
                    visited <= LEAKAGE_MAX_SOURCE_FILES,
                    "leakage source tree exceeds its entry bound"
                );
            }
        } else if metadata.is_file() && selected(&path) && metadata.len() > 0 {
            paths.push(path);
        }
    }
    paths.sort();
    let mut total = 0_usize;
    let mut sources = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = read_stable_leakage_source(&path)?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| eyre!("leakage source byte count overflow"))?;
        ensure!(
            total <= LEAKAGE_MAX_SOURCE_BYTES,
            "leakage source set exceeds its byte bound"
        );
        let relative = path
            .strip_prefix(&canonical_root)
            .wrap_err("leakage source escaped its root")?
            .to_str()
            .ok_or_else(|| eyre!("leakage source path is not UTF-8"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        ensure!(
            !relative.is_empty()
                && !relative
                    .split('/')
                    .any(|part| part.is_empty() || part == ".."),
            "leakage source path is not canonical"
        );
        sources.push((relative, bytes));
    }
    Ok(sources)
}

fn framed_leakage_sources(kind: &str, sources: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    ensure!(
        !kind.is_empty() && !sources.is_empty(),
        "empty leakage artifact frame"
    );
    let mut output = LEAKAGE_ARTIFACT_FRAME_DOMAIN_V1.to_vec();
    output.extend_from_slice(&u16::try_from(kind.len())?.to_le_bytes());
    output.extend_from_slice(kind.as_bytes());
    output.extend_from_slice(&u32::try_from(sources.len())?.to_le_bytes());
    // This public fixed-width derivative binds source ordering, size, and
    // digests. The exact canary-scanned bytes are retained separately in the
    // restricted audit-source archive for independent replay.
    for (index, (path, bytes)) in sources.iter().enumerate() {
        output.extend_from_slice(&u32::try_from(index)?.to_le_bytes());
        output.extend_from_slice(&Sha256::digest(path.as_bytes()));
        output.extend_from_slice(&u64::try_from(bytes.len())?.to_le_bytes());
        output.extend_from_slice(&Sha256::digest(bytes));
    }
    ensure!(
        output.len() <= LEAKAGE_MAX_SOURCE_BYTES,
        "framed leakage artifact exceeds its byte bound"
    );
    Ok(output)
}

struct LeakageRestrictedSourceRefV1<'a> {
    surface: &'a str,
    relative_path: String,
    bytes: &'a [u8],
}

fn framed_restricted_leakage_sources_v1(
    mut sources: Vec<LeakageRestrictedSourceRefV1<'_>>,
) -> Result<Vec<u8>> {
    ensure!(
        !sources.is_empty(),
        "restricted leakage source archive is empty"
    );
    sources.sort_by(|left, right| {
        (left.surface, left.relative_path.as_str())
            .cmp(&(right.surface, right.relative_path.as_str()))
    });
    ensure!(
        sources.windows(2).all(|pair| {
            (pair[0].surface, pair[0].relative_path.as_str())
                != (pair[1].surface, pair[1].relative_path.as_str())
        }),
        "restricted leakage source archive contains a duplicate source"
    );
    let mut output = LEAKAGE_RESTRICTED_SOURCE_DOMAIN_V1.to_vec();
    output.extend_from_slice(&u32::try_from(sources.len())?.to_le_bytes());
    for (ordinal, source) in sources.into_iter().enumerate() {
        ensure!(
            !source.surface.is_empty()
                && source.surface.len() <= 64
                && source.surface.is_ascii()
                && source
                    .surface
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                && !source.relative_path.is_empty()
                && source.relative_path.len() <= 4_096
                && !source
                    .relative_path
                    .split('/')
                    .any(|part| { part.is_empty() || part == "." || part == ".." })
                && !source.bytes.is_empty(),
            "restricted leakage source archive row is non-canonical"
        );
        output.extend_from_slice(&u32::try_from(ordinal)?.to_le_bytes());
        output.extend_from_slice(&u16::try_from(source.surface.len())?.to_le_bytes());
        output.extend_from_slice(source.surface.as_bytes());
        output.extend_from_slice(&u32::try_from(source.relative_path.len())?.to_le_bytes());
        output.extend_from_slice(source.relative_path.as_bytes());
        output.extend_from_slice(&u64::try_from(source.bytes.len())?.to_le_bytes());
        output.extend_from_slice(source.bytes);
        ensure!(
            output.len() <= LEAKAGE_MAX_SOURCE_BYTES,
            "restricted leakage source archive exceeds its byte bound"
        );
    }
    Ok(output)
}

fn leakage_source_binding(sources: &[&[u8]]) -> Result<(String, u64)> {
    ensure!(!sources.is_empty(), "leakage source binding is empty");
    let mut digest = Sha256::new();
    digest.update(b"iroha:aps-leakage-source-binding:v1\0");
    digest.update(u64::try_from(sources.len())?.to_le_bytes());
    let mut total = 0_u64;
    for source in sources {
        let length = u64::try_from(source.len())?;
        ensure!(
            length > 0,
            "leakage source binding contains an empty source"
        );
        total = total
            .checked_add(length)
            .ok_or_else(|| eyre!("leakage source byte total overflow"))?;
        digest.update(length.to_le_bytes());
        digest.update(source);
    }
    Ok((hex::encode(digest.finalize()), total))
}

fn write_leakage_artifact(
    root: &Path,
    surface: &str,
    relative_name: &str,
    bytes: &[u8],
    sources: &[&[u8]],
) -> Result<RealProcessLeakageArtifactV1> {
    ensure!(!bytes.is_empty(), "leakage artifact is empty");
    let expected = LEAKAGE_CAPTURE_SURFACES
        .iter()
        .find(|(candidate, _)| *candidate == surface)
        .ok_or_else(|| eyre!("unknown leakage surface {surface}"))?;
    ensure!(
        expected.1 == relative_name && !relative_name.contains('/'),
        "leakage artifact name is not canonical"
    );
    let path = root.join(relative_name);
    ensure!(!path.exists(), "leakage artifact already exists");
    write_owner_only_atomic(&path, bytes)?;
    let (source_sha256, source_bytes) = leakage_source_binding(sources)?;
    Ok(RealProcessLeakageArtifactV1 {
        surface: surface.to_owned(),
        relative_name: relative_name.to_owned(),
        sha256: sha256_hex(bytes),
        bytes: u64::try_from(bytes.len())?,
        source_sha256,
        source_bytes,
        source_count: sources.len(),
    })
}

fn leakage_json_records(records: Vec<HarnessJsonValue>) -> Result<Vec<u8>> {
    ensure!(!records.is_empty(), "leakage JSON record set is empty");
    canonical_harness_json_value_bytes(&norito::json!({
        "version": 1,
        "records": records,
    }))
}

fn leakage_block_wire(block: &iroha::data_model::block::SignedBlock) -> Result<Vec<u8>> {
    let wire = block
        .encode_wire()
        .map_err(|error| eyre!("encode canonical leakage carrier block: {error}"))?;
    ensure!(!wire.is_empty(), "carrier block wire is empty");
    let mut output = LEAKAGE_BLOCK_WIRE_MAGIC_V1.to_vec();
    output.extend_from_slice(&1_u32.to_le_bytes());
    output.extend_from_slice(&u64::try_from(wire.len())?.to_le_bytes());
    output.extend_from_slice(&wire);
    Ok(output)
}

fn leakage_carrier_block(
    client: &Client,
    entrypoint: HashOf<TransactionEntrypoint>,
) -> Result<iroha::data_model::block::SignedBlock> {
    let mut matching = client
        .client()
        .query(FindBlocks)
        .execute_all()?
        .into_iter()
        .filter(|block| block.network_input_hashes().any(|hash| hash == entrypoint))
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "leakage carrier must occur in exactly one canonical block"
    );
    Ok(matching.remove(0))
}

fn submit_leakage_carrier_with_event(
    runtime: &tokio::runtime::Runtime,
    sponsor: &Client,
    submit: PrivateSettlementBundleSubmitRequestV1,
    expected_bundle: Hash,
) -> Result<(HarnessJsonValue, Vec<u8>)> {
    let transaction_hash = submit.transaction.hash();
    let client = sponsor.clone();
    runtime.block_on(async move {
        let mut events = tokio::time::timeout(
            FAULT_CONTROL_TIMEOUT,
            client
                .account_client()
                .events()
                .subscribe([TransactionEventFilter::default().for_hash(transaction_hash)]),
        )
        .await
        .map_err(|_| eyre!("timed out opening leakage carrier event stream"))??;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let submitter = client.clone();
        let response = tokio::task::spawn_blocking(move || {
            submitter
                .client()
                .submit_private_settlement_bundle_v1(&submit)
        })
        .await
        .wrap_err("leakage carrier submit worker panicked")??;
        ensure!(
            response.bundle_id == expected_bundle,
            "leakage carrier response substituted its bundle"
        );
        let record = tokio::time::timeout(FINALITY_TIMEOUT, async {
            loop {
                let Some(next) = events.next().await else {
                    return Err(eyre!("leakage carrier event stream closed"));
                };
                let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = next? else {
                    continue;
                };
                match event.status() {
                    TransactionStatus::Queued => {}
                    TransactionStatus::Approved => {
                        let source = norito::encode_canonical(&event)?;
                        return Ok((
                            norito::json!({
                                "peer_index": 0,
                                "source_sha256": (sha256_hex(&source)),
                                "source_bytes": (source.len()),
                            }),
                            source,
                        ));
                    }
                    TransactionStatus::Rejected(reason) => {
                        return Err(eyre!("leakage carrier rejected: {reason}"));
                    }
                    TransactionStatus::Expired => {
                        return Err(eyre!("leakage carrier expired"));
                    }
                }
            }
        })
        .await
        .map_err(|_| eyre!("timed out waiting for leakage carrier event"))??;
        events.close().await?;
        Ok(record)
    })
}

fn leakage_query_records(
    network: &Network,
    bundle_id: Hash,
    expected: &iroha::data_model::nexus::PrivateSettlementReceiptV1,
) -> Result<(Vec<HarnessJsonValue>, Vec<Vec<u8>>)> {
    let captured = network
        .all_peers()
        .enumerate()
        .map(|(peer_index, peer)| {
            let response = peer
                .client()
                .client()
                .private_settlement_bundle_receipt_v1(bundle_id)?;
            let PrivateSettlementBundleReceiptResponseV1::Finalized(receipt) = response else {
                return Err(eyre!("leakage public receipt query is not finalized"));
            };
            ensure!(
                receipt == *expected,
                "leakage public receipt query diverged"
            );
            let encoded = norito::encode_canonical(&receipt)?;
            Ok((
                norito::json!({
                    "peer_index": peer_index,
                    "source_sha256": (sha256_hex(&encoded)),
                    "source_bytes": (encoded.len()),
                }),
                encoded,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let (rows, sources): (Vec<_>, Vec<_>) = captured.into_iter().unzip();
    Ok((rows, sources))
}

fn leakage_telemetry_records(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
) -> Result<(Vec<HarnessJsonValue>, Vec<Vec<u8>>)> {
    let sources = network
        .all_peers()
        .map(|peer| {
            let status = peer.client().status().get()?;
            let status = norito::encode_canonical(&status)?;
            let metrics_url = peer.client().client().endpoint().join("metrics")?;
            let metrics = runtime.block_on(async {
                let response = reqwest::get(metrics_url)
                    .await
                    .wrap_err("fetch leakage runtime metrics")?;
                ensure!(
                    response.status().is_success(),
                    "leakage runtime metrics request failed"
                );
                response
                    .bytes()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .wrap_err("read leakage runtime metrics")
            })?;
            ensure!(!metrics.is_empty(), "leakage runtime metrics are empty");
            let mut source = Vec::new();
            source.extend_from_slice(&u64::try_from(status.len())?.to_le_bytes());
            source.extend_from_slice(&status);
            source.extend_from_slice(&u64::try_from(metrics.len())?.to_le_bytes());
            source.extend_from_slice(&metrics);
            Ok((source, status, metrics))
        })
        .collect::<Result<Vec<_>>>()?;
    let rows = sources
        .iter()
        .enumerate()
        .map(|(peer_index, (source, status, metrics))| {
            norito::json!({
                "peer_index": peer_index,
                "status_sha256": (sha256_hex(status)),
                "status_bytes": (status.len()),
                "metrics_sha256": (sha256_hex(metrics)),
                "metrics_bytes": (metrics.len()),
                "source_sha256": (sha256_hex(source)),
                "source_bytes": (source.len()),
            })
        })
        .collect();
    Ok((
        rows,
        sources.into_iter().map(|(source, _, _)| source).collect(),
    ))
}

fn leakage_operator_log_records(
    network: &Network,
) -> Result<(Vec<HarnessJsonValue>, Vec<Vec<u8>>)> {
    let snapshots = network.startup_snapshot();
    ensure!(
        snapshots.len() == network.all_peers().count(),
        "leakage log snapshot omitted a validator or committee observer"
    );
    let mut sources = Vec::with_capacity(snapshots.len() * 2);
    let rows = snapshots
        .into_iter()
        .map(|snapshot| {
            let stdout_path = snapshot
                .logs
                .stdout_log
                .ok_or_else(|| eyre!("validator log snapshot lacks stdout source"))?;
            let stderr_path = snapshot
                .logs
                .stderr_log
                .ok_or_else(|| eyre!("validator log snapshot lacks stderr source"))?;
            let stdout = read_stable_leakage_source(&stdout_path)?;
            let stderr = read_stable_leakage_source(&stderr_path)?;
            ensure!(
                !stdout.is_empty() || !stderr.is_empty(),
                "validator emitted no source-backed operator log"
            );
            let mut source = Vec::new();
            source.extend_from_slice(&u64::try_from(stdout.len())?.to_le_bytes());
            source.extend_from_slice(&stdout);
            source.extend_from_slice(&u64::try_from(stderr.len())?.to_le_bytes());
            source.extend_from_slice(&stderr);
            sources.push(source);
            Ok(norito::json!({
                "peer_index": (snapshot.index),
                "stdout_sha256": (sha256_hex(&stdout)),
                "stderr_sha256": (sha256_hex(&stderr)),
                "stdout_bytes": (stdout.len()),
                "stderr_bytes": (stderr.len()),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((rows, sources))
}

fn verify_controller_readiness(
    network: &Network,
    _runtime: &tokio::runtime::Runtime,
) -> Result<()> {
    for peer in network.all_peers() {
        ensure!(
            peer.private_settlement_route_control().is_some() && peer.is_running(),
            "peer {} lacks the configured live HTTP route controller",
            peer.id()
        );
        peer.client().status().get()?;
    }
    // Exact acknowledgements are required after each real route request by its scenario.
    Ok(())
}

fn collect_process_inventory(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    shape: TopologyShape,
    revision: &str,
    coordinator: &CoordinatorProcessV1,
) -> Result<Vec<RealProcessInventoryRowV1>> {
    let validator_sha =
        std::env::var(HARNESS_VALIDATOR_SHA_ENV).wrap_err("missing validator executable digest")?;
    ensure!(
        lowercase_digest(&validator_sha, &[64]),
        "validator executable digest is malformed"
    );
    let coordinator_pid = coordinator.pid;
    let mut rows = vec![RealProcessInventoryRowV1 {
        role: "coordinator".to_owned(),
        dataspace_ordinal: None,
        validator_ordinal: None,
        pid: coordinator_pid,
        executable_sha256: coordinator.executable_sha256.clone(),
        revision: revision.to_owned(),
        health_observed: sample_process_resources(&[coordinator_pid]).is_ok(),
    }];
    for (index, peer) in network.all_peers().enumerate() {
        let pid = runtime
            .block_on(peer.process_id())
            .ok_or_else(|| eyre!("peer {} has no live child PID", peer.id()))?;
        let actual_path = executable_for_pid(pid)?;
        let actual_sha = sha256_regular_file(&actual_path)?;
        ensure!(
            actual_sha == validator_sha,
            "peer {} executable differs from the launcher-bound daemon",
            peer.id()
        );
        let lane = index / VALIDATORS_PER_LANE;
        rows.push(RealProcessInventoryRowV1 {
            role: if lane == 0 {
                "global_validator".to_owned()
            } else {
                "dataspace_validator".to_owned()
            },
            dataspace_ordinal: (lane != 0).then(|| u64::try_from(lane - 1).unwrap()),
            validator_ordinal: Some(
                u64::try_from(index % VALIDATORS_PER_LANE).expect("validator ordinal fits u64"),
            ),
            pid,
            executable_sha256: actual_sha,
            revision: revision.to_owned(),
            health_observed: peer.is_running() && peer.client().status().get().is_ok(),
        });
    }
    ensure!(
        rows.len() == shape.process_count() + 1
            && rows.iter().all(|row| row.health_observed)
            && rows
                .iter()
                .map(|row| row.pid)
                .collect::<BTreeSet<_>>()
                .len()
                == rows.len(),
        "process inventory is incomplete or unhealthy"
    );
    Ok(rows)
}

fn canonical_harness_json_bytes<T: norito::json::JsonSerialize>(value: &T) -> Result<Vec<u8>> {
    let value = norito::json::to_value(value).wrap_err("encode harness evidence value")?;
    norito::json::to_string(&value)
        .map(String::into_bytes)
        .wrap_err("encode canonical harness evidence JSON")
}

/// Digest of a retained correctness-run artifact; private configuration bytes stay local.
#[derive(Clone, Debug, norito::JsonSerialize)]
struct SmokeEvidenceFileV1 {
    name: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, norito::JsonSerialize)]
struct SmokeProcessInventoryRowV1 {
    peer_index: usize,
    peer_id: PeerId,
    committee_index: usize,
    validator_index: usize,
    pid: u32,
    executable_sha256: String,
    configuration_sha256: String,
}

#[derive(Debug, norito::JsonSerialize)]
struct SmokeContinuousEvidenceV1 {
    summary: FaultContinuousObservationSummaryV1,
    observations: Vec<FaultStateObservationV1>,
}

#[derive(Debug, norito::JsonSerialize)]
struct SmokeRestartV1 {
    peer_index: usize,
    before_pid: u32,
    after_pid: u32,
}

#[derive(Debug, norito::JsonSerialize)]
struct RealProcessSmokeResultV1 {
    version: u8,
    protocol: String,
    kind: String,
    request: RealProcessSmokeRequestV1,
    request_sha256: String,
    network_id: HarnessJsonValue,
    participants: usize,
    processes: usize,
    restarted: usize,
    activation_height: u64,
    authority_context_height: u64,
    finalized_height: u64,
    signed_rs16_observations: u64,
    continuous_checks: u64,
    passed: bool,
    artifacts: Vec<SmokeEvidenceFileV1>,
}

fn write_smoke_evidence<T: norito::json::JsonSerialize>(
    root: &Path,
    name: &str,
    value: &T,
) -> Result<SmokeEvidenceFileV1> {
    let raw = canonical_harness_json_bytes(value)?;
    write_smoke_evidence_bytes(root, name, &raw, ".json", HARNESS_MAX_JSON_BYTES)
}

fn write_smoke_evidence_bytes(
    root: &Path,
    name: &str,
    raw: &[u8],
    extension: &str,
    limit: usize,
) -> Result<SmokeEvidenceFileV1> {
    ensure!(
        name.ends_with(extension)
            && name.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'.'))
            && !name.starts_with('.'),
        "smoke evidence name is not a canonical basename"
    );
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.file_type().is_dir() && metadata.permissions().mode() & 0o777 == 0o700,
        "smoke evidence requires an owner-only regular directory"
    );
    ensure!(raw.len() <= limit, "smoke evidence exceeds its byte bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))?;
    file.write_all(raw)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(SmokeEvidenceFileV1 {
        name: name.to_owned(),
        bytes: u64::try_from(raw.len())?,
        sha256: sha256_hex(raw),
    })
}

#[test]
fn smoke_transport_prefix_is_retained_exactly_and_bounded() {
    let temporary = tempfile::tempdir().expect("temporary evidence directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let raw = b"original process output\n";
    let name = "finality-before-transport-00.log";
    let artifact =
        write_smoke_evidence_bytes(temporary.path(), name, raw, ".log", raw.len()).unwrap();
    assert_eq!(fs::read(temporary.path().join(name)).unwrap(), raw);
    assert_eq!(artifact.sha256, sha256_hex(raw));
    assert_eq!(artifact.bytes, raw.len() as u64);
    assert!(write_smoke_evidence_bytes(temporary.path(), name, raw, ".log", raw.len()).is_err());
    assert!(
        write_smoke_evidence_bytes(
            temporary.path(),
            "too-large.log",
            raw,
            ".log",
            raw.len() - 1
        )
        .is_err()
    );
    assert!(!temporary.path().join("too-large.log").exists());
}

#[test]
fn smoke_evidence_binds_bytes_and_rejects_overwrite_or_path_escape() {
    let temporary = tempfile::tempdir().expect("temporary evidence directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let value = norito::json!({"state": "pending"});
    let artifact = write_smoke_evidence(temporary.path(), "state-before.json", &value).unwrap();
    let path = temporary.path().join(&artifact.name);
    let raw = fs::read(&path).unwrap();
    assert_eq!(artifact.sha256, sha256_hex(&raw));
    assert_eq!(artifact.bytes, raw.len() as u64);
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(write_smoke_evidence(temporary.path(), "state-before.json", &value).is_err());
    for name in [
        "../escape.json",
        "/absolute.json",
        ".hidden.json",
        "nested/file.json",
        "state.JSON",
    ] {
        assert!(write_smoke_evidence(temporary.path(), name, &value).is_err());
    }
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(write_smoke_evidence(temporary.path(), "unsafe.json", &value).is_err());
}

/// The final inventory remains a single health observation. Only initial
/// startup may await readiness, within its already established startup budget.
#[derive(Clone, Copy)]
enum SmokeInventoryReadinessV1 {
    Immediate,
    StartupUntil(Instant),
}

fn smoke_inventory_transient_status_v1(error: &iroha::Error) -> bool {
    matches!(
        error,
        iroha::Error::StatusUnavailable {
            reason: Some(
                iroha::StatusFailureReason::DeadlineElapsed
                    | iroha::StatusFailureReason::StateBusy
                    | iroha::StatusFailureReason::MailboxUnavailable
                    | iroha::StatusFailureReason::CheckpointChanged
            ),
            ..
        } | iroha::Error::Timeout {
            operation: "diagnostic.status"
        }
    )
}

fn smoke_inventory_identity_v1(
    expected_pid: u32,
    expected_sha: &str,
    mut process_id: impl FnMut() -> Option<u32>,
    mut image_sha: impl FnMut(u32) -> Result<String>,
) -> Result<()> {
    ensure!(
        process_id() == Some(expected_pid),
        "smoke validator live PID changed or disappeared"
    );
    ensure!(
        image_sha(expected_pid)? == expected_sha,
        "smoke validator executable differs from the launcher-bound image"
    );
    ensure!(
        process_id() == Some(expected_pid),
        "smoke validator live PID changed during executable verification"
    );
    Ok(())
}

fn smoke_inventory_health_v1(
    peer_index: usize,
    readiness: SmokeInventoryReadinessV1,
    // Outer errors are identity/inventory failures and are never retried. Inner
    // errors retain the SDK's typed result from the actual status request.
    mut probe: impl FnMut(Option<Duration>) -> Result<std::result::Result<(), iroha::Error>>,
) -> Result<()> {
    let mut last_error: Option<iroha::Error> = None;
    loop {
        let remaining = match readiness {
            SmokeInventoryReadinessV1::Immediate => None,
            SmokeInventoryReadinessV1::StartupUntil(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    let error = last_error.map_or_else(
                        || eyre!("no successful startup status observation"),
                        eyre::Report::from,
                    );
                    return Err(error).wrap_err_with(|| {
                        format!("smoke peer {peer_index} exceeded the original startup deadline")
                    });
                }
                Some(remaining)
            }
        };
        let status = probe(remaining)
            .wrap_err_with(|| format!("smoke peer {peer_index} inventory identity check failed"))?;
        match status {
            Ok(()) => {
                if let SmokeInventoryReadinessV1::StartupUntil(deadline) = readiness {
                    ensure!(
                        Instant::now() < deadline,
                        "smoke peer {peer_index} became ready after the original startup deadline"
                    );
                }
                return Ok(());
            }
            Err(error) => {
                let SmokeInventoryReadinessV1::StartupUntil(deadline) = readiness else {
                    return Err(error).wrap_err_with(|| {
                        format!("smoke peer {peer_index} final inventory health check failed")
                    });
                };
                if !smoke_inventory_transient_status_v1(&error) {
                    return Err(error).wrap_err_with(|| {
                        format!("smoke peer {peer_index} startup status failed permanently")
                    });
                }
                last_error = Some(error);
                thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
    }
}

#[test]
fn smoke_inventory_startup_retries_transient_status_until_ready() {
    for reason in [
        iroha::StatusFailureReason::DeadlineElapsed,
        iroha::StatusFailureReason::StateBusy,
    ] {
        let mut polls = 0;
        smoke_inventory_health_v1(
            7,
            SmokeInventoryReadinessV1::StartupUntil(Instant::now() + Duration::from_secs(2)),
            |remaining| {
                assert!(remaining.is_some_and(|value| !value.is_zero()));
                polls += 1;
                Ok(if polls == 1 {
                    Err(iroha::Error::StatusUnavailable {
                        reason: Some(reason),
                        retry_after: None,
                    })
                } else {
                    Ok(())
                })
            },
        )
        .unwrap();
        assert_eq!(polls, 2);
    }
}

#[test]
fn smoke_inventory_startup_deadline_retains_status_error() {
    for reason in [
        iroha::StatusFailureReason::DeadlineElapsed,
        iroha::StatusFailureReason::StateBusy,
    ] {
        let mut polls = 0;
        let error = smoke_inventory_health_v1(
            7,
            SmokeInventoryReadinessV1::StartupUntil(Instant::now() + Duration::from_secs(1)),
            |remaining| {
                polls += 1;
                thread::sleep(remaining.unwrap() + Duration::from_millis(1));
                Ok(Err(iroha::Error::StatusUnavailable {
                    reason: Some(reason),
                    retry_after: None,
                }))
            },
        )
        .unwrap_err();
        assert_eq!(polls, 1);
        let error = format!("{error:?}");
        assert!(error.contains("smoke peer 7 exceeded the original startup deadline"));
        assert!(error.contains(reason.code()));
    }
}

#[test]
fn smoke_inventory_startup_rejects_permanent_status_error() {
    for reason in [
        iroha::StatusFailureReason::JournalMismatch,
        iroha::StatusFailureReason::StateUnavailable,
    ] {
        let mut polls = 0;
        let error = smoke_inventory_health_v1(
            3,
            SmokeInventoryReadinessV1::StartupUntil(Instant::now() + Duration::from_secs(2)),
            |_| {
                polls += 1;
                Ok(Err(iroha::Error::StatusUnavailable {
                    reason: Some(reason),
                    retry_after: None,
                }))
            },
        )
        .unwrap_err();
        assert_eq!(polls, 1);
        let error = format!("{error:?}");
        assert!(error.contains("smoke peer 3 startup status failed permanently"));
        assert!(error.contains(reason.code()));
    }
}

#[test]
fn smoke_inventory_startup_rejects_late_success() {
    let mut polls = 0;
    let error = smoke_inventory_health_v1(
        2,
        SmokeInventoryReadinessV1::StartupUntil(Instant::now() + Duration::from_secs(1)),
        |remaining| {
            polls += 1;
            thread::sleep(remaining.unwrap() + Duration::from_millis(1));
            Ok(Ok(()))
        },
    )
    .unwrap_err();
    assert_eq!(polls, 1);
    assert!(format!("{error:?}").contains("became ready after the original startup deadline"));
}

#[test]
fn smoke_inventory_identity_rejects_pid_change_during_retry() {
    let mut polls = 0;
    let mut image_reads = 0;
    let error = smoke_inventory_health_v1(
        4,
        SmokeInventoryReadinessV1::StartupUntil(Instant::now() + Duration::from_secs(2)),
        |_| {
            polls += 1;
            smoke_inventory_identity_v1(
                42,
                "expected",
                || Some(if polls == 1 { 42 } else { 43 }),
                |_| {
                    image_reads += 1;
                    Ok("expected".to_owned())
                },
            )?;
            Ok(Err(iroha::Error::Timeout {
                operation: "diagnostic.status",
            }))
        },
    )
    .unwrap_err();
    assert_eq!(polls, 2);
    assert_eq!(image_reads, 1);
    assert!(format!("{error:?}").contains("live PID changed or disappeared"));
}

#[test]
fn smoke_inventory_identity_rejects_image_change_during_retry() {
    let mut polls = 0;
    let error = smoke_inventory_health_v1(
        5,
        SmokeInventoryReadinessV1::StartupUntil(Instant::now() + Duration::from_secs(2)),
        |_| {
            polls += 1;
            smoke_inventory_identity_v1(
                42,
                "expected",
                || Some(42),
                |_| {
                    Ok(if polls == 1 {
                        "expected"
                    } else {
                        "substituted"
                    }
                    .to_owned())
                },
            )?;
            Ok(Err(iroha::Error::Timeout {
                operation: "diagnostic.status",
            }))
        },
    )
    .unwrap_err();
    assert_eq!(polls, 2);
    assert!(format!("{error:?}").contains("executable differs from the launcher-bound image"));
}

#[test]
fn smoke_inventory_final_health_check_remains_single_poll() {
    for status_error in [
        iroha::Error::Timeout {
            operation: "diagnostic.status",
        },
        iroha::Error::StatusUnavailable {
            reason: Some(iroha::StatusFailureReason::StateBusy),
            retry_after: None,
        },
    ] {
        let mut polls = 0;
        let mut status_error = Some(status_error);
        let error =
            smoke_inventory_health_v1(8, SmokeInventoryReadinessV1::Immediate, |remaining| {
                assert!(remaining.is_none());
                polls += 1;
                Ok(Err(status_error
                    .take()
                    .expect("final health must not retry")))
            })
            .unwrap_err();
        assert_eq!(polls, 1);
        assert!(format!("{error:?}").contains("smoke peer 8 final inventory health check failed"));
    }
}

#[test]
fn smoke_inventory_transient_status_classifier_is_exact() {
    use iroha::StatusFailureReason as Reason;
    for reason in [
        Reason::DeadlineElapsed,
        Reason::StateBusy,
        Reason::MailboxUnavailable,
        Reason::CheckpointChanged,
    ] {
        assert!(smoke_inventory_transient_status_v1(
            &iroha::Error::StatusUnavailable {
                reason: Some(reason),
                retry_after: None,
            }
        ));
    }
    for reason in [
        None,
        Some(Reason::Disabled),
        Some(Reason::ActorClosed),
        Some(Reason::StateUnavailable),
        Some(Reason::MissingBlock),
        Some(Reason::JournalMismatch),
        Some(Reason::CounterOverflow),
        Some(Reason::CounterMismatch),
        Some(Reason::MetricsStale),
        Some(Reason::ProfileRestricted),
    ] {
        assert!(!smoke_inventory_transient_status_v1(
            &iroha::Error::StatusUnavailable {
                reason,
                retry_after: None,
            }
        ));
    }
    assert!(smoke_inventory_transient_status_v1(
        &iroha::Error::Timeout {
            operation: "diagnostic.status"
        }
    ));
    assert!(!smoke_inventory_transient_status_v1(
        &iroha::Error::Timeout { operation: "other" }
    ));
    assert!(!smoke_inventory_transient_status_v1(
        &iroha::Error::Decode {
            operation: "diagnostic.status",
            details: "bad status".to_owned(),
        }
    ));
}

fn smoke_process_inventory(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    shape: TopologyShape,
    readiness: SmokeInventoryReadinessV1,
) -> Result<Vec<SmokeProcessInventoryRowV1>> {
    let expected_sha = std::env::var(HARNESS_VALIDATOR_SHA_ENV)
        .wrap_err("missing smoke validator executable digest")?;
    ensure!(
        lowercase_digest(&expected_sha, &[64]),
        "malformed smoke executable digest"
    );
    let mut pids = BTreeSet::new();
    let mut peers = BTreeSet::new();
    let mut inventory = Vec::new();
    let mut images = ExecutableInventory::default();
    for (index, peer) in network.all_peers().enumerate() {
        let pid = runtime
            .block_on(peer.process_id())
            .ok_or_else(|| eyre!("smoke peer has no PID"))?;
        ensure!(pids.insert(pid), "smoke peer {index} duplicates PID {pid}");
        ensure!(
            peers.insert(peer.id().clone()),
            "smoke peer {index} duplicates validator identity {}",
            peer.id()
        );
        let client = peer.client();
        smoke_inventory_health_v1(index, readiness, |_| {
            let mut check_identity = || {
                smoke_inventory_identity_v1(
                    pid,
                    &expected_sha,
                    || runtime.block_on(peer.process_id()),
                    |live_pid| images.sha256(&executable_for_pid(live_pid)?),
                )
            };
            check_identity()?;
            let status = match readiness {
                SmokeInventoryReadinessV1::Immediate => client.status().get(),
                SmokeInventoryReadinessV1::StartupUntil(deadline) => {
                    // Recompute after image verification; the HTTP request may
                    // consume only the original startup budget that remains.
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    runtime.block_on(async {
                        tokio::time::timeout(remaining, client.client().status().get())
                            .await
                            .unwrap_or(Err(iroha::Error::Timeout {
                                operation: "diagnostic.status",
                            }))
                    })
                }
            };
            check_identity()?;
            Ok(status.map(|_| ()))
        })?;
        // Retain only a commitment to the complete ordered input layers: they
        // contain runtime private keys and must not enter a research artifact.
        let layers = network
            .config_layers_for_peer(peer)
            .map(|layer| toml::to_string(layer.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        let configuration_sha256 = sha256_hex(&canonical_harness_json_bytes(&layers)?);
        inventory.push(SmokeProcessInventoryRowV1 {
            peer_index: index,
            peer_id: peer.id().clone(),
            committee_index: index / VALIDATORS_PER_LANE,
            validator_index: index % VALIDATORS_PER_LANE,
            pid,
            executable_sha256: expected_sha.clone(),
            configuration_sha256,
        });
    }
    ensure!(
        inventory.len() == shape.process_count(),
        "smoke process inventory is incomplete"
    );
    images.verify_all()?;
    Ok(inventory)
}

fn canonical_harness_json_value_bytes(value: &HarnessJsonValue) -> Result<Vec<u8>> {
    norito::json::to_string(value)
        .map(String::into_bytes)
        .wrap_err("encode canonical harness evidence JSON value")
}

fn canonical_hash_json_literal(hash: &Hash) -> Result<String> {
    let value = norito::json::to_value(hash).wrap_err("encode canonical hash literal")?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre!("canonical hash JSON is not a string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fault_control_occurrence(
    control_type: impl Into<String>,
    peer_index: Option<usize>,
    command_bytes: Vec<u8>,
    acknowledgement_bytes: Vec<u8>,
    before_pid: Option<u32>,
    after_pid: Option<u32>,
) -> Result<FaultControlOccurrenceV1> {
    ensure!(
        !command_bytes.is_empty()
            && !acknowledgement_bytes.is_empty()
            && canonical_harness_json_value_bytes(&norito::json::from_slice(&command_bytes)?)?
                == command_bytes
            && canonical_harness_json_value_bytes(&norito::json::from_slice(
                &acknowledgement_bytes,
            )?)? == acknowledgement_bytes,
        "fault control evidence is empty or non-canonical"
    );
    if let (Some(before), Some(after)) = (before_pid, after_pid) {
        ensure!(before != after, "fault restart reused one process id");
    }
    Ok(FaultControlOccurrenceV1 {
        control_type: control_type.into(),
        peer_index,
        command_sha256: sha256_hex(&command_bytes),
        command_hex: hex::encode(command_bytes),
        acknowledgement_sha256: sha256_hex(&acknowledgement_bytes),
        acknowledgement_hex: hex::encode(acknowledgement_bytes),
        before_pid,
        after_pid,
    })
}

fn fault_checkpoint_acknowledgement_binding(control: &FaultControlOccurrenceV1) -> String {
    format!("acknowledgement:{}", control.acknowledgement_sha256)
}

fn fault_record_id(
    participants: usize,
    seed: u64,
    run: u64,
    collection: &str,
    trial_index: usize,
) -> String {
    format!("n{participants}:s{seed}:r{run}:{collection}:{trial_index}")
}

fn fault_derivation_bytes(
    request: &RealProcessFaultRequestV1,
    bundle_ordinal: usize,
    leg_ordinal: usize,
    purpose: &[u8],
) -> [u8; 32] {
    fault_derivation_bytes_from_run(
        request.seed,
        request.run,
        bundle_ordinal,
        leg_ordinal,
        purpose,
    )
}

fn fault_derivation_bytes_from_run(
    seed: u64,
    run: u64,
    bundle_ordinal: usize,
    leg_ordinal: usize,
    purpose: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"iroha:atomic-private-settlement:fault-campaign:v1\0");
    digest.update(seed.to_le_bytes());
    digest.update(run.to_le_bytes());
    digest.update(
        u64::try_from(bundle_ordinal)
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    digest.update(u64::try_from(leg_ordinal).unwrap_or(u64::MAX).to_le_bytes());
    digest.update(purpose);
    digest.finalize().into()
}

fn fault_governed_legs(
    request: &RealProcessFaultRequestV1,
    bundle_ordinal: usize,
    routes: &[PrivateSettlementRouteV1],
    authority_context_height: u64,
    expiry_height: u64,
) -> Result<Vec<GovernedLeg>> {
    governed_legs(routes, authority_context_height, expiry_height)?
        .into_iter()
        .enumerate()
        .map(|(leg_ordinal, base)| {
            let mut policy_body = base.policy.body.clone();
            policy_body.policy_id = Hash::prehashed(fault_derivation_bytes(
                request,
                bundle_ordinal,
                leg_ordinal,
                b"audit-policy",
            ));
            let policy = PrivateSettlementAuditPolicyV1::new(policy_body)?;
            let governance = PrivateSettlementPoolGovernanceV1::from_restricted_mapping(
                base.route,
                PrivacyPoolIdV1::new(fault_derivation_bytes(
                    request,
                    bundle_ordinal,
                    leg_ordinal,
                    b"pool-id",
                )),
                base.governance.body.asset_definition_id.clone(),
                fault_derivation_bytes(request, bundle_ordinal, leg_ordinal, b"asset-binding-salt"),
                &policy,
                PrivateSettlementPoolGovernanceLifecycleV1 {
                    governance_revision: 1,
                    activation_height: authority_context_height,
                    retirement_height: Some(expiry_height + 1),
                },
            )?;
            Ok(GovernedLeg {
                route: base.route,
                policy,
                governance,
                auditor_signing: base.auditor_signing,
                auditor_encryption: base.auditor_encryption,
            })
        })
        .collect()
}

fn write_owner_only_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("owner-only file has no parent"))?;
    let metadata = fs::symlink_metadata(parent).wrap_err("inspect owner-only parent")?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == 0o700,
        "owner-only parent is unsafe"
    );
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| eyre!("owner-only file name is invalid"))?,
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .wrap_err("create owner-only temporary file")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_owner_only_bounded(path: &Path) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).wrap_err("inspect owner-only file")?;
    ensure!(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.permissions().mode() & 0o777 == 0o600
            && std::os::unix::fs::MetadataExt::uid(&before)
                == std::os::unix::fs::MetadataExt::uid(&fs::symlink_metadata(
                    path.parent()
                        .ok_or_else(|| eyre!("owner-only file lacks parent"))?,
                )?,)
            && usize::try_from(before.len()).is_ok_and(|len| len <= HARNESS_MAX_JSON_BYTES),
        "owner-only file is unsafe or oversized"
    );
    let mut file = File::open(path).wrap_err("open owner-only file")?;
    let opened = file.metadata()?;
    ensure!(
        std::os::unix::fs::MetadataExt::dev(&before)
            == std::os::unix::fs::MetadataExt::dev(&opened)
            && std::os::unix::fs::MetadataExt::ino(&before)
                == std::os::unix::fs::MetadataExt::ino(&opened),
        "owner-only file changed before open"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(HARNESS_MAX_JSON_BYTES + 1).expect("bound fits u64"))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() <= HARNESS_MAX_JSON_BYTES
            && opened.len() == after.len()
            && std::os::unix::fs::MetadataExt::mtime(&opened)
                == std::os::unix::fs::MetadataExt::mtime(&after)
            && std::os::unix::fs::MetadataExt::mtime_nsec(&opened)
                == std::os::unix::fs::MetadataExt::mtime_nsec(&after),
        "owner-only file changed while read"
    );
    Ok(bytes)
}

fn coordinator_client_config(client: &Client) -> Result<Vec<u8>> {
    let client = client.client();
    let private_key = iroha_crypto::ExposedPrivateKey(client.key_pair().private_key().clone());
    let mut root = Table::new();
    root.insert(
        "chain".to_owned(),
        TomlValue::String(client.chain().to_string()),
    );
    root.insert(
        "network_id".to_owned(),
        TomlValue::String(client.network_id().to_string()),
    );
    root.insert(
        "torii_url".to_owned(),
        TomlValue::String(client.endpoint().to_string()),
    );
    root.insert(
        "torii_request_timeout_ms".to_owned(),
        TomlValue::Integer(i64::try_from(client.torii_request_timeout().as_millis())?),
    );
    let mut account = Table::new();
    account.insert(
        "chain_discriminant".to_owned(),
        TomlValue::Integer(i64::from(client.account_chain_discriminant())),
    );
    account.insert(
        "public_key".to_owned(),
        TomlValue::String(client.key_pair().public_key().to_string()),
    );
    account.insert(
        "private_key".to_owned(),
        TomlValue::String(private_key.to_string()),
    );
    root.insert("account".to_owned(), TomlValue::Table(account));
    let mut transaction = Table::new();
    transaction.insert(
        "time_to_live_ms".to_owned(),
        TomlValue::Integer(i64::try_from(
            client
                .transaction_ttl()
                .unwrap_or(Duration::from_secs(60))
                .as_millis(),
        )?),
    );
    transaction.insert(
        "status_timeout_ms".to_owned(),
        TomlValue::Integer(i64::try_from(
            client.transaction_status_timeout().as_millis(),
        )?),
    );
    transaction.insert(
        "nonce".to_owned(),
        TomlValue::Boolean(client.add_transaction_nonce()),
    );
    root.insert("transaction".to_owned(), TomlValue::Table(transaction));
    Ok(toml::to_string(&root)?.into_bytes())
}

struct CoordinatorProcessV1 {
    root: tempfile::TempDir,
    child: Child,
    pid: u32,
    executable_sha256: String,
    revision: u64,
}

impl CoordinatorProcessV1 {
    fn start(client: &Client) -> Result<Self> {
        let root = tempfile::tempdir().wrap_err("create coordinator runtime root")?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        write_owner_only_atomic(
            &root.path().join(COORDINATOR_CONFIG_FILE),
            &coordinator_client_config(client)?,
        )?;
        let command = CoordinatorCommandV1 {
            format_version: 1,
            revision: 1,
            operation: "idle".to_owned(),
            committee_endpoints: Vec::new(),
            manifest: None,
            authority_catalog: Vec::new(),
            deltas: Vec::new(),
            barrier: None,
        };
        let command_bytes = canonical_harness_json_bytes(&command)?;
        write_owner_only_atomic(&root.path().join(COORDINATOR_COMMAND_FILE), &command_bytes)?;
        let executable = std::env::current_exe().wrap_err("resolve coordinator test binary")?;
        let executable_sha256 = sha256_regular_file(&executable)?;
        let child = Self::spawn_child(root.path(), &executable)?;
        let pid = child.id();
        let mut process = Self {
            root,
            child,
            pid,
            executable_sha256,
            revision: 1,
        };
        let (_bytes, acknowledgement) = process.wait_for_ack(&command_bytes)?;
        ensure!(
            acknowledgement.pid == pid && acknowledgement.operation == "idle",
            "coordinator helper did not acknowledge its live PID"
        );
        Ok(process)
    }

    fn spawn_child(root: &Path, executable: &Path) -> Result<Child> {
        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(root.join(COORDINATOR_STDOUT_FILE))?;
        let stderr = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(root.join(COORDINATOR_STDERR_FILE))?;
        Command::new(executable)
            .args([
                "--ignored",
                "--exact",
                "nexus::atomic_private_settlement_localnet::atomic_private_settlement_real_process_coordinator_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(COORDINATOR_ROOT_ENV, root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .wrap_err("spawn coordinator helper process")
    }

    fn stop_and_collect_logs(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        write_owner_only_atomic(
            &self.root.path().join(COORDINATOR_SHUTDOWN_FILE),
            b"shutdown\n",
        )?;
        self.child.kill().wrap_err("stop leakage coordinator")?;
        let _status = self.child.wait().wrap_err("reap leakage coordinator")?;
        let stdout = read_stable_leakage_source(&self.root.path().join(COORDINATOR_STDOUT_FILE))?;
        let stderr = read_stable_leakage_source(&self.root.path().join(COORDINATOR_STDERR_FILE))?;
        let mut framed = Vec::new();
        framed.extend_from_slice(&u64::try_from(stdout.len())?.to_le_bytes());
        framed.extend_from_slice(&stdout);
        framed.extend_from_slice(&u64::try_from(stderr.len())?.to_le_bytes());
        framed.extend_from_slice(&stderr);
        Ok(vec![(
            "coordinator-000/stdout-stderr.log".to_owned(),
            framed,
        )])
    }

    fn wait_for_ack(&mut self, command_bytes: &[u8]) -> Result<(Vec<u8>, CoordinatorAckV1)> {
        let expected = hex::encode(Sha256::digest(command_bytes));
        let path = self.root.path().join(COORDINATOR_ACK_FILE);
        let started = Instant::now();
        while started.elapsed() <= FINALITY_TIMEOUT {
            if let Some(status) = self.child.try_wait()? {
                return Err(eyre!(
                    "coordinator helper exited before acknowledgement: {status}"
                ));
            }
            if let Ok(bytes) = read_owner_only_bounded(&path) {
                let acknowledgement: CoordinatorAckV1 = norito::json::from_slice(&bytes)?;
                ensure!(
                    canonical_harness_json_bytes(&acknowledgement)? == bytes
                        && acknowledgement.format_version == 1
                        && acknowledgement.revision == self.revision
                        && acknowledgement.command_sha256 == expected
                        && acknowledgement.pid == self.pid,
                    "coordinator acknowledgement is substituted or non-canonical"
                );
                return Ok((bytes, acknowledgement));
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(benchmark_deadline_error(
            BenchmarkDeadlineStageV1::CoordinatorAck,
            FINALITY_TIMEOUT,
            started.elapsed(),
        )
        .wrap_err("timed out waiting for coordinator acknowledgement"))
    }

    fn restart_with(
        &mut self,
        mut command: CoordinatorCommandV1,
    ) -> Result<(u32, u32, Vec<u8>, Vec<u8>, CoordinatorAckV1)> {
        let before_pid = self.pid;
        self.child.kill().wrap_err("kill coordinator helper")?;
        let status = self.child.wait().wrap_err("reap coordinator helper")?;
        ensure!(
            !status.success(),
            "killed coordinator helper exited successfully"
        );
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| eyre!("coordinator revision overflow"))?;
        command.revision = self.revision;
        let command_bytes = canonical_harness_json_bytes(&command)?;
        let ack_path = self.root.path().join(COORDINATOR_ACK_FILE);
        if ack_path.exists() {
            fs::remove_file(&ack_path)?;
        }
        write_owner_only_atomic(
            &self.root.path().join(COORDINATOR_COMMAND_FILE),
            &command_bytes,
        )?;
        let executable = std::env::current_exe().wrap_err("resolve coordinator test binary")?;
        self.child = Self::spawn_child(self.root.path(), &executable)?;
        self.pid = self.child.id();
        ensure!(
            self.pid != before_pid,
            "coordinator helper reused its killed PID"
        );
        let (ack_bytes, acknowledgement) = self.wait_for_ack(&command_bytes)?;
        Ok((
            before_pid,
            self.pid,
            command_bytes,
            ack_bytes,
            acknowledgement,
        ))
    }
}

impl Drop for CoordinatorProcessV1 {
    fn drop(&mut self) {
        let _ = write_owner_only_atomic(
            &self.root.path().join(COORDINATOR_SHUTDOWN_FILE),
            b"shutdown\n",
        );
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_coordinator_helper_process() -> Result<()> {
    let root = PathBuf::from(
        std::env::var(COORDINATOR_ROOT_ENV).wrap_err("missing coordinator runtime root")?,
    );
    let canonical = root
        .canonicalize()
        .wrap_err("resolve coordinator runtime root")?;
    ensure!(
        canonical == root,
        "coordinator runtime root is not canonical"
    );
    let metadata = fs::symlink_metadata(&root)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == 0o700,
        "coordinator runtime root is unsafe"
    );
    let command_bytes = read_owner_only_bounded(&root.join(COORDINATOR_COMMAND_FILE))?;
    let command: CoordinatorCommandV1 = norito::json::from_slice(&command_bytes)?;
    ensure!(
        canonical_harness_json_bytes(&command)? == command_bytes
            && command.format_version == 1
            && command.revision > 0,
        "coordinator command is substituted or non-canonical"
    );
    let config_path = root.join(COORDINATOR_CONFIG_FILE);
    let config_bytes = read_owner_only_bounded(&config_path)?;
    let (config, _publication) =
        iroha::config::Config::load_bytes_with_musubi_publication(&config_path, &config_bytes)
            .map_err(|error| {
                eyre!("load stable explicit coordinator client configuration: {error:?}")
            })?;
    let client = Client::new(config)?;
    let endpoints = command
        .committee_endpoints
        .iter()
        .map(|committee| {
            committee
                .iter()
                .map(|endpoint| Url::parse(endpoint).wrap_err("parse coordinator endpoint"))
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let (barrier, commit_certificates) = match command.operation.as_str() {
        "idle"
            if command.manifest.is_none()
                && command.authority_catalog.is_empty()
                && command.deltas.is_empty()
                && command.barrier.is_none()
                && endpoints.is_empty() =>
        {
            (None, Vec::new())
        }
        "recover_prepare" => {
            let manifest = command
                .manifest
                .as_ref()
                .ok_or_else(|| eyre!("recover_prepare lacks manifest"))?;
            let barrier = client
                .client()
                .recover_or_prepare_private_settlement_bundle_v1(
                    &endpoints,
                    manifest,
                    &command.authority_catalog,
                    &command.deltas,
                )?;
            submit_prepare_registration_and_wait_v1(&client, &barrier)?;
            (Some(barrier), Vec::new())
        }
        "recover_prepare_commit" => {
            let manifest = command
                .manifest
                .as_ref()
                .ok_or_else(|| eyre!("recover_prepare_commit lacks manifest"))?;
            let barrier = client
                .client()
                .recover_or_prepare_private_settlement_bundle_v1(
                    &endpoints,
                    manifest,
                    &command.authority_catalog,
                    &command.deltas,
                )?;
            submit_prepare_registration_and_wait_v1(&client, &barrier)?;
            let commits = client
                .client()
                .recover_or_commit_private_settlement_bundle_v1(&endpoints, &barrier)?;
            (Some(barrier), commits)
        }
        "recover_commit" => {
            let barrier = command
                .barrier
                .as_ref()
                .ok_or_else(|| eyre!("recover_commit lacks barrier"))?;
            let commits = client
                .client()
                .recover_or_commit_private_settlement_bundle_v1(&endpoints, barrier)?;
            (Some(barrier.clone()), commits)
        }
        _ => return Err(eyre!("coordinator command operation or fields are invalid")),
    };
    let acknowledgement = CoordinatorAckV1 {
        format_version: 1,
        revision: command.revision,
        command_sha256: hex::encode(Sha256::digest(&command_bytes)),
        pid: std::process::id(),
        operation: command.operation,
        barrier,
        commit_certificates,
    };
    write_owner_only_atomic(
        &root.join(COORDINATOR_ACK_FILE),
        &canonical_harness_json_bytes(&acknowledgement)?,
    )?;
    while !root.join(COORDINATOR_SHUTDOWN_FILE).exists() {
        thread::sleep(POLL_INTERVAL);
    }
    Ok(())
}

fn fault_state_identity(observation: &FaultStateObservationV1) -> Result<FaultStateIdentityV1> {
    Ok(FaultStateIdentityV1 {
        ledger_commitment: observation.ledger_commitment.clone(),
        replicated_staged_lock_commitment: observation.replicated_staged_lock_commitment.clone(),
        staged_lock_commitment: observation.staged_lock_commitment.clone(),
        counts: norito::json::to_string(&observation.counts)
            .wrap_err("encode fault state count identity")?,
    })
}

fn fault_ledger_identity(observation: &FaultStateObservationV1) -> Result<FaultLedgerIdentityV1> {
    let mut counts = observation
        .counts
        .as_object()
        .ok_or_else(|| eyre!("fault state count vector is not an object"))?
        .clone();
    for field in [
        "staged_pool_heads",
        "staged_nullifiers",
        "staged_output_commitments",
        "replicated_staged_locks",
        "staged_locks",
    ] {
        ensure!(counts.remove(field).is_some(), "fault state lacks {field}");
    }
    Ok(FaultLedgerIdentityV1 {
        ledger_commitment: observation.ledger_commitment.clone(),
        counts: norito::json::to_string(&HarnessJsonValue::Object(counts))
            .wrap_err("encode fault ledger count identity")?,
    })
}

fn capture_fault_state_observation(
    peer_index: usize,
    peer: &NetworkPeer,
) -> Result<FaultStateObservationV1> {
    let response = peer
        .client()
        .client()
        .private_settlement_test_network_state_evidence_v1()
        .wrap_err_with(|| format!("query APS state evidence from validator #{peer_index}"))?;
    let response_bytes = canonical_harness_json_bytes(&response)?;
    let counts =
        norito::json::to_value(&response.counts).wrap_err("encode APS state evidence counts")?;
    Ok(FaultStateObservationV1 {
        peer_index,
        response_sha256: hex::encode(Sha256::digest(&response_bytes)),
        response_hex: hex::encode(response_bytes),
        height: response.height,
        commitment: canonical_hash_json_literal(&response.commitment)?,
        ledger_commitment: canonical_hash_json_literal(&response.ledger_commitment)?,
        replicated_staged_lock_commitment: canonical_hash_json_literal(
            &response.replicated_staged_lock_commitment,
        )?,
        staged_lock_commitment: canonical_hash_json_literal(&response.staged_lock_commitment)?,
        counts,
    })
}

fn capture_fault_state_snapshot(network: &Network, label: &str) -> Result<FaultStateSnapshotV1> {
    let peers = network.all_peers().cloned().enumerate().collect();
    // Each process has an independent read-only endpoint. Preserve every peer and
    // its input index while bounding concurrency exactly as receipt/finality reads.
    let validators = collect_bounded_observations(peers, TEST_STACK_BYTES, |(peer_index, peer)| {
        capture_fault_state_observation(peer_index, &peer)
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    ensure!(
        validators.len() == network.all_peers().count(),
        "fault state snapshot omitted a validator or committee observer"
    );
    Ok(FaultStateSnapshotV1 {
        label: label.to_owned(),
        validators,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultContinuousObservationClassV1 {
    Baseline,
    Finalized,
}

fn validate_fault_lock_shape_v1(
    observation: &FaultStateObservationV1,
    participants: usize,
) -> Result<()> {
    let staged_pool_heads = fault_count(&observation.counts, "staged_pool_heads")?;
    let staged_nullifiers = fault_count(&observation.counts, "staged_nullifiers")?;
    let staged_outputs = fault_count(&observation.counts, "staged_output_commitments")?;
    let staged_total = fault_count(&observation.counts, "staged_locks")?;
    ensure!(
        staged_pool_heads <= u64::try_from(participants)?
            && staged_nullifiers == staged_pool_heads.saturating_mul(2)
            && staged_outputs == staged_pool_heads.saturating_mul(3)
            && staged_total
                == staged_pool_heads
                    .saturating_add(staged_nullifiers)
                    .saturating_add(staged_outputs),
        "validator #{} exposed an impossible committee-local staged-lock shape",
        observation.peer_index
    );
    let replicated = fault_count(&observation.counts, "replicated_staged_locks")?;
    let expected_replicated = u64::try_from(participants)?
        .checked_mul(9)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| eyre!("replicated APS staged-lock count overflow"))?;
    ensure!(
        replicated == 0 || replicated == expected_replicated,
        "validator #{} exposed an impossible replicated staged-lock shape",
        observation.peer_index
    );
    Ok(())
}

fn classify_fault_continuous_observation(
    baseline: &FaultStateObservationV1,
    observation: &FaultStateObservationV1,
    participants: usize,
) -> Result<FaultContinuousObservationClassV1> {
    ensure!(
        baseline.peer_index == observation.peer_index,
        "continuous APS observation changed validator identity"
    );
    validate_fault_lock_shape_v1(baseline, participants)?;
    validate_fault_lock_shape_v1(observation, participants)?;
    if fault_ledger_identity(baseline)? == fault_ledger_identity(observation)? {
        return Ok(FaultContinuousObservationClassV1::Baseline);
    }
    ensure!(
        baseline.ledger_commitment != observation.ledger_commitment,
        "continuous APS observation changed counts without changing the ledger commitment"
    );
    let expected_deltas = [
        ("roots", participants),
        ("nullifiers", participants * 2),
        ("commitments", participants * 3),
        ("encrypted_outputs", participants * 3),
        ("replay_markers", 1),
        ("receipts", 1),
    ];
    for (field, delta) in expected_deltas {
        let expected = fault_count(&baseline.counts, field)?
            .checked_add(u64::try_from(delta)?)
            .ok_or_else(|| eyre!("continuous APS `{field}` count overflow"))?;
        ensure!(
            fault_count(&observation.counts, field)? == expected,
            "validator #{} exposed a partial APS `{field}` count",
            observation.peer_index
        );
    }
    for field in ["governance", "pools", "abort_markers"] {
        ensure!(
            fault_count(&observation.counts, field)? == fault_count(&baseline.counts, field)?,
            "validator #{} changed APS `{field}` outside one complete finalization",
            observation.peer_index
        );
    }
    // Replicated locks retire in the atomic financial transaction. Torii's
    // separate local sidecar retires reservations through its background
    // finality reconciler; the accumulator enforces monotonic cleanup and the
    // terminal snapshot still requires every local reservation to be gone.
    ensure!(
        fault_count(&observation.counts, "replicated_staged_locks")? == 0,
        "validator #{} retained replicated APS locks after finalization",
        observation.peer_index
    );
    Ok(FaultContinuousObservationClassV1::Finalized)
}

fn normalize_fault_observer_transport_failure(error: &eyre::Report) -> Option<&'static str> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .filter(|error| {
                error.is_connect()
                    || (error.is_timeout()
                        && !error.is_body()
                        && !error.is_decode()
                        && !error.is_status())
            })
            .map(|_| FAULT_CONTINUOUS_EXPECTED_UNAVAILABLE_CLASS_V1)
    })
}

struct FaultContinuousObservationPhaseAccumulatorV1 {
    phase: String,
    expected_unavailable: bool,
    finalization_allowed: bool,
    successful_observations: u64,
    poll_failures: u64,
    baseline_observations: u64,
    finalized_observations: u64,
    checkpoint: Option<(u64, u64)>,
    checkpoint_control_bindings: Vec<String>,
    attempt_chain: Sha256,
    attempts: Vec<FaultContinuousObservationAttemptRunV1>,
}

impl FaultContinuousObservationPhaseAccumulatorV1 {
    fn new(
        peer_index: usize,
        phase_index: usize,
        phase: &str,
        expected_unavailable: bool,
        finalization_allowed: bool,
        bundle_id: &[u8; Hash::LENGTH],
    ) -> Self {
        let mut attempt_chain = Sha256::new();
        attempt_chain.update(FAULT_CONTINUOUS_OBSERVATION_PHASE_DOMAIN_V1);
        attempt_chain.update(bundle_id);
        attempt_chain.update(
            u64::try_from(peer_index)
                .expect("peer index fits u64")
                .to_le_bytes(),
        );
        attempt_chain.update(
            u64::try_from(phase_index)
                .expect("phase index fits u64")
                .to_le_bytes(),
        );
        attempt_chain.update(
            u64::try_from(phase.len())
                .expect("phase length fits u64")
                .to_le_bytes(),
        );
        attempt_chain.update(phase.as_bytes());
        attempt_chain.update([u8::from(expected_unavailable)]);
        attempt_chain.update([u8::from(finalization_allowed)]);
        Self {
            phase: phase.to_owned(),
            expected_unavailable,
            finalization_allowed,
            successful_observations: 0,
            poll_failures: 0,
            baseline_observations: 0,
            finalized_observations: 0,
            checkpoint: None,
            checkpoint_control_bindings: Vec::new(),
            attempt_chain,
            attempts: Vec::new(),
        }
    }

    fn append_attempt(&mut self, class: &str, evidence: &str) -> Result<()> {
        let attempts = self
            .successful_observations
            .checked_add(self.poll_failures)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| eyre!("continuous APS phase attempt count overflow"))?;
        ensure!(
            attempts <= FAULT_CONTINUOUS_MAX_ATTEMPTS_PER_PEER,
            "continuous APS phase attempt stream exceeded its bound"
        );
        if let Some(last) = self.attempts.last_mut()
            && last.class == class
            && last.evidence == evidence
        {
            last.repetitions = last
                .repetitions
                .checked_add(1)
                .ok_or_else(|| eyre!("continuous APS attempt-run count overflow"))?;
        } else {
            self.attempts.push(FaultContinuousObservationAttemptRunV1 {
                class: class.to_owned(),
                evidence: evidence.to_owned(),
                repetitions: 1,
            });
        }
        Ok(())
    }

    fn record_success(
        &mut self,
        class: FaultContinuousObservationClassV1,
        observation: &FaultStateObservationV1,
        response_digest: &[u8],
    ) -> Result<()> {
        let (class_name, class_tag) = match class {
            FaultContinuousObservationClassV1::Baseline => {
                self.baseline_observations = self
                    .baseline_observations
                    .checked_add(1)
                    .ok_or_else(|| eyre!("continuous APS phase baseline count overflow"))?;
                ("baseline", 1_u8)
            }
            FaultContinuousObservationClassV1::Finalized => {
                ensure!(
                    self.finalization_allowed,
                    "continuous APS observer saw finalization in disallowed phase `{}`",
                    self.phase
                );
                self.finalized_observations = self
                    .finalized_observations
                    .checked_add(1)
                    .ok_or_else(|| eyre!("continuous APS phase finalized count overflow"))?;
                ("finalized", 2_u8)
            }
        };
        self.append_attempt(class_name, &observation.response_hex)?;
        self.successful_observations = self
            .successful_observations
            .checked_add(1)
            .ok_or_else(|| eyre!("continuous APS phase success count overflow"))?;
        self.attempt_chain.update([class_tag]);
        self.attempt_chain.update(response_digest);
        Ok(())
    }

    fn record_poll_failure(&mut self) -> Result<()> {
        self.append_attempt(
            "expected_unavailable",
            FAULT_CONTINUOUS_EXPECTED_UNAVAILABLE_CLASS_V1,
        )?;
        self.poll_failures = self
            .poll_failures
            .checked_add(1)
            .ok_or_else(|| eyre!("continuous APS phase poll-failure count overflow"))?;
        self.attempt_chain.update([0_u8]);
        self.attempt_chain
            .update(FAULT_CONTINUOUS_EXPECTED_UNAVAILABLE_CLASS_V1.as_bytes());
        Ok(())
    }

    fn checkpoint(&mut self, control_bindings: &[String]) -> Result<()> {
        ensure!(
            self.checkpoint.is_none(),
            "continuous APS observer phase `{}` was checkpointed twice",
            self.phase
        );
        ensure!(
            control_bindings.len() <= 32
                && control_bindings.iter().all(|binding| {
                    let Some((kind, digest)) = binding.split_once(':') else {
                        return false;
                    };
                    matches!(kind, "command" | "acknowledgement")
                        && digest.len() == 64
                        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                        && digest.bytes().all(|byte| !byte.is_ascii_uppercase())
                }),
            "continuous APS checkpoint control bindings are invalid"
        );
        self.checkpoint = Some((self.successful_observations, self.poll_failures));
        self.checkpoint_control_bindings = control_bindings.to_vec();
        Ok(())
    }

    fn coverage_met(&self) -> bool {
        let Some((success_checkpoint, failure_checkpoint)) = self.checkpoint else {
            return false;
        };
        if self.expected_unavailable {
            self.poll_failures > failure_checkpoint
        } else {
            self.successful_observations > success_checkpoint && self.poll_failures == 0
        }
    }

    fn finish(mut self) -> Result<FaultContinuousObservationPhaseSummaryV1> {
        ensure!(
            self.coverage_met(),
            "continuous APS observer phase `{}` lacks its required peer coverage",
            self.phase
        );
        let (checkpoint_successes, checkpoint_failures) = self
            .checkpoint
            .ok_or_else(|| eyre!("continuous APS observer phase lacks its fault checkpoint"))?;
        let checkpoint_attempt = checkpoint_successes
            .checked_add(checkpoint_failures)
            .ok_or_else(|| eyre!("continuous APS checkpoint attempt count overflow"))?;
        self.attempt_chain.update(b"checkpoint\0");
        self.attempt_chain.update(checkpoint_attempt.to_le_bytes());
        self.attempt_chain.update(b"checkpoint-controls\0");
        self.attempt_chain.update(
            u64::try_from(self.checkpoint_control_bindings.len())
                .expect("checkpoint control count fits u64")
                .to_le_bytes(),
        );
        for binding in &self.checkpoint_control_bindings {
            self.attempt_chain.update(
                u64::try_from(binding.len())
                    .expect("checkpoint control binding length fits u64")
                    .to_le_bytes(),
            );
            self.attempt_chain.update(binding.as_bytes());
        }
        Ok(FaultContinuousObservationPhaseSummaryV1 {
            phase: self.phase,
            expected_unavailable: self.expected_unavailable,
            finalization_allowed: self.finalization_allowed,
            successful_observations: self.successful_observations,
            poll_failures: self.poll_failures,
            baseline_observations: self.baseline_observations,
            finalized_observations: self.finalized_observations,
            checkpoint_attempt,
            checkpoint_control_bindings: self.checkpoint_control_bindings,
            attempt_chain_sha256: hex::encode(self.attempt_chain.finalize()),
            attempts: self.attempts,
        })
    }
}

struct FaultContinuousObservationAccumulatorV1 {
    peer_index: usize,
    check_count: u64,
    poll_failure_count: u64,
    first_response_sha256: Option<String>,
    last_response_sha256: Option<String>,
    response_chain: Sha256,
    baseline_observations: u64,
    finalized_observations: u64,
    seen_finalized: bool,
    last_finalized_local: Option<(u64, String)>,
    bundle_id: [u8; Hash::LENGTH],
    phase_coverage: Vec<FaultContinuousObservationPhaseAccumulatorV1>,
}

impl FaultContinuousObservationAccumulatorV1 {
    fn new(
        peer_index: usize,
        bundle_id: [u8; Hash::LENGTH],
        preflight_finalization_allowed: bool,
    ) -> Self {
        let mut response_chain = Sha256::new();
        response_chain.update(FAULT_CONTINUOUS_OBSERVATION_DOMAIN_V1);
        response_chain.update(bundle_id);
        response_chain.update(
            u64::try_from(peer_index)
                .expect("peer index fits u64")
                .to_le_bytes(),
        );
        Self {
            peer_index,
            check_count: 0,
            poll_failure_count: 0,
            first_response_sha256: None,
            last_response_sha256: None,
            response_chain,
            baseline_observations: 0,
            finalized_observations: 0,
            seen_finalized: false,
            last_finalized_local: None,
            bundle_id,
            phase_coverage: vec![FaultContinuousObservationPhaseAccumulatorV1::new(
                peer_index,
                0,
                "preflight",
                false,
                preflight_finalization_allowed,
                &bundle_id,
            )],
        }
    }

    fn start_phase(
        &mut self,
        phase: &str,
        expected_unavailable: bool,
        finalization_allowed: bool,
    ) -> Result<usize> {
        ensure!(
            !phase.is_empty()
                && phase.len() <= 64
                && phase
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "continuous APS observer phase name is not canonical"
        );
        ensure!(
            self.phase_coverage
                .iter()
                .all(|existing| existing.phase != phase),
            "continuous APS observer phase `{phase}` was reused"
        );
        let phase_index = self.phase_coverage.len();
        self.phase_coverage
            .push(FaultContinuousObservationPhaseAccumulatorV1::new(
                self.peer_index,
                phase_index,
                phase,
                expected_unavailable,
                finalization_allowed,
                &self.bundle_id,
            ));
        Ok(phase_index)
    }

    fn record(
        &mut self,
        baseline: &FaultStateObservationV1,
        observation: &FaultStateObservationV1,
        participants: usize,
        phase_index: usize,
    ) -> Result<()> {
        ensure!(
            self.check_count
                .checked_add(self.poll_failure_count)
                .and_then(|count| count.checked_add(1))
                .is_some_and(|count| count <= FAULT_CONTINUOUS_MAX_ATTEMPTS_PER_PEER),
            "continuous APS attempt stream exceeded its per-peer bound"
        );
        let class = classify_fault_continuous_observation(baseline, observation, participants)?;
        let digest = hex::decode(&observation.response_sha256)
            .wrap_err("decode continuous APS response digest")?;
        ensure!(
            digest.len() == Hash::LENGTH,
            "continuous APS response digest has the wrong length"
        );
        let phase = self
            .phase_coverage
            .get_mut(phase_index)
            .ok_or_else(|| eyre!("continuous APS observer selected an unknown phase"))?;
        ensure!(
            !matches!(class, FaultContinuousObservationClassV1::Baseline) || !self.seen_finalized,
            "continuous APS observer saw finalized state roll back to baseline"
        );
        let final_local = if matches!(class, FaultContinuousObservationClassV1::Finalized) {
            let current = (
                fault_count(&observation.counts, "staged_locks")?,
                observation.staged_lock_commitment.clone(),
            );
            if let Some(previous) = &self.last_finalized_local {
                ensure!(
                    current.0 <= previous.0 && (current.0 != previous.0 || current.1 == previous.1),
                    "continuous APS local staging increased or changed after financial finality"
                );
            }
            ensure!(
                phase.phase != "terminal" || current.0 == 0,
                "continuous APS terminal observation retains local staging"
            );
            Some(current)
        } else {
            None
        };
        phase.record_success(class, observation, &digest)?;
        if let Some(current) = final_local {
            self.last_finalized_local = Some(current);
        }
        self.check_count = self
            .check_count
            .checked_add(1)
            .ok_or_else(|| eyre!("continuous APS observation count overflow"))?;
        self.first_response_sha256
            .get_or_insert_with(|| observation.response_sha256.clone());
        self.last_response_sha256 = Some(observation.response_sha256.clone());
        self.response_chain.update(&digest);
        match class {
            FaultContinuousObservationClassV1::Baseline => {
                self.baseline_observations = self
                    .baseline_observations
                    .checked_add(1)
                    .ok_or_else(|| eyre!("continuous APS baseline count overflow"))?;
            }
            FaultContinuousObservationClassV1::Finalized => {
                self.seen_finalized = true;
                self.finalized_observations = self
                    .finalized_observations
                    .checked_add(1)
                    .ok_or_else(|| eyre!("continuous APS finalized count overflow"))?;
            }
        }
        Ok(())
    }

    fn record_current_poll(
        &mut self,
        baseline: &FaultStateObservationV1,
        observation: &FaultStateObservationV1,
        participants: usize,
        phase_index: usize,
        attempt_epoch: u64,
        checkpoint_epoch: u64,
        retained: Option<&mut Vec<FaultStateObservationV1>>,
    ) -> Result<bool> {
        if attempt_epoch != checkpoint_epoch {
            return Ok(false);
        }
        if let Some(rows) = retained.as_ref() {
            ensure!(
                rows.len() < LEAKAGE_MAX_OBSERVATIONS_PER_PEER,
                "continuous APS evidence exceeded its per-peer bound"
            );
        }
        self.record(baseline, observation, participants, phase_index)?;
        if let Some(rows) = retained {
            rows.push(observation.clone());
        }
        Ok(true)
    }

    fn record_poll_failure(&mut self, phase_index: usize) -> Result<bool> {
        ensure!(
            self.check_count
                .checked_add(self.poll_failure_count)
                .and_then(|count| count.checked_add(1))
                .is_some_and(|count| count <= FAULT_CONTINUOUS_MAX_ATTEMPTS_PER_PEER),
            "continuous APS attempt stream exceeded its per-peer bound"
        );
        let phase = self
            .phase_coverage
            .get_mut(phase_index)
            .ok_or_else(|| eyre!("continuous APS observer selected an unknown phase"))?;
        phase.record_poll_failure()?;
        let expected_unavailable = phase.expected_unavailable;
        self.poll_failure_count = self
            .poll_failure_count
            .checked_add(1)
            .ok_or_else(|| eyre!("continuous APS poll-failure count overflow"))?;
        Ok(expected_unavailable)
    }

    fn checkpoint_phase(&mut self, phase_index: usize, control_bindings: &[String]) -> Result<()> {
        self.phase_coverage
            .get_mut(phase_index)
            .ok_or_else(|| eyre!("continuous APS observer selected an unknown phase"))?
            .checkpoint(control_bindings)
    }

    fn phase_coverage_met(&self, phase_index: usize) -> Result<bool> {
        self.phase_coverage
            .get(phase_index)
            .map(FaultContinuousObservationPhaseAccumulatorV1::coverage_met)
            .ok_or_else(|| eyre!("continuous APS observer selected an unknown phase"))
    }

    fn finish(self) -> Result<FaultContinuousObservationSummaryV1> {
        ensure!(
            self.last_finalized_local
                .as_ref()
                .is_none_or(|local| local.0 == 0),
            "continuous APS evidence ended before local staging reconciliation"
        );
        ensure!(
            self.check_count >= 3,
            "continuous APS observer did not record a live poll between its bound endpoints"
        );
        let phase_successes = self.phase_coverage.iter().try_fold(0_u64, |total, phase| {
            total
                .checked_add(phase.successful_observations)
                .ok_or_else(|| eyre!("continuous APS phase success total overflow"))
        })?;
        let phase_failures = self.phase_coverage.iter().try_fold(0_u64, |total, phase| {
            total
                .checked_add(phase.poll_failures)
                .ok_or_else(|| eyre!("continuous APS phase failure total overflow"))
        })?;
        ensure!(
            phase_successes == self.check_count && phase_failures == self.poll_failure_count,
            "continuous APS phase totals do not equal the peer summary"
        );
        let phase_coverage = self
            .phase_coverage
            .into_iter()
            .map(FaultContinuousObservationPhaseAccumulatorV1::finish)
            .collect::<Result<Vec<_>>>()?;
        Ok(FaultContinuousObservationSummaryV1 {
            peer_index: self.peer_index,
            check_count: self.check_count,
            poll_failure_count: self.poll_failure_count,
            first_response_sha256: self
                .first_response_sha256
                .ok_or_else(|| eyre!("continuous APS observer lacks a first response"))?,
            last_response_sha256: self
                .last_response_sha256
                .ok_or_else(|| eyre!("continuous APS observer lacks a last response"))?,
            response_chain_sha256: hex::encode(self.response_chain.finalize()),
            baseline_observations: self.baseline_observations,
            finalized_observations: self.finalized_observations,
            phase_coverage,
        })
    }
}

struct FaultContinuousObserverV1 {
    stop: Arc<AtomicBool>,
    active_phase: Arc<AtomicU64>,
    observed_phase: Arc<AtomicU64>,
    checkpoint_epoch: Arc<AtomicU64>,
    accumulators: Arc<Mutex<Vec<FaultContinuousObservationAccumulatorV1>>>,
    retained_observations: Option<Arc<Mutex<Vec<Vec<FaultStateObservationV1>>>>>,
    failure: Arc<Mutex<Option<String>>>,
    baselines: Vec<FaultStateObservationV1>,
    participants: usize,
    phase_complete: bool,
    handle: Option<thread::JoinHandle<()>>,
}

impl FaultContinuousObserverV1 {
    fn start(
        network: &Network,
        before: &FaultStateSnapshotV1,
        participants: usize,
        bundle_id: &Hash,
        preflight_finalization_allowed: bool,
    ) -> Result<Self> {
        Self::start_internal(
            network,
            before,
            participants,
            bundle_id,
            preflight_finalization_allowed,
            false,
        )
    }

    fn start_retaining_evidence(
        network: &Network,
        before: &FaultStateSnapshotV1,
        participants: usize,
        bundle_id: &Hash,
        preflight_finalization_allowed: bool,
    ) -> Result<Self> {
        Self::start_internal(
            network,
            before,
            participants,
            bundle_id,
            preflight_finalization_allowed,
            true,
        )
    }

    fn start_internal(
        network: &Network,
        before: &FaultStateSnapshotV1,
        participants: usize,
        bundle_id: &Hash,
        preflight_finalization_allowed: bool,
        retain_evidence: bool,
    ) -> Result<Self> {
        ensure_fault_state_converged(before)?;
        ensure!(
            before.validators.len() == network.all_peers().count(),
            "continuous APS observer baseline omits validators or committee observers"
        );
        let baselines = before.validators.clone();
        let bundle_id: [u8; Hash::LENGTH] = *bundle_id.as_ref();
        let mut initial = (0..baselines.len())
            .map(|peer_index| {
                FaultContinuousObservationAccumulatorV1::new(
                    peer_index,
                    bundle_id,
                    preflight_finalization_allowed,
                )
            })
            .collect::<Vec<_>>();
        for (accumulator, observation) in initial.iter_mut().zip(&baselines) {
            accumulator.checkpoint_phase(0, &[])?;
            accumulator.record(observation, observation, participants, 0)?;
        }
        let accumulators = Arc::new(Mutex::new(initial));
        let retained_observations = retain_evidence.then(|| {
            Arc::new(Mutex::new(
                baselines
                    .iter()
                    .cloned()
                    .map(|baseline| vec![baseline])
                    .collect::<Vec<_>>(),
            ))
        });
        let failure = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let active_phase = Arc::new(AtomicU64::new(0));
        let observed_phase = Arc::new(AtomicU64::new(0));
        let checkpoint_epoch = Arc::new(AtomicU64::new(0));
        let peers = network.all_peers().cloned().collect::<Vec<_>>();
        let thread_baselines = baselines.clone();
        let thread_accumulators = Arc::clone(&accumulators);
        let thread_retained_observations = retained_observations.clone();
        let thread_failure = Arc::clone(&failure);
        let thread_stop = Arc::clone(&stop);
        let thread_active_phase = Arc::clone(&active_phase);
        let thread_observed_phase = Arc::clone(&observed_phase);
        let thread_checkpoint_epoch = Arc::clone(&checkpoint_epoch);
        let handle = thread::Builder::new()
            .name("aps-fault-continuous-observer".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    let phase_index = usize::try_from(thread_active_phase.load(Ordering::Acquire))
                        .expect("continuous APS phase index fits usize");
                    thread_observed_phase.store(
                        u64::try_from(phase_index).expect("continuous APS phase index fits u64"),
                        Ordering::Release,
                    );
                    for (peer_index, peer) in peers.iter().enumerate() {
                        if thread_stop.load(Ordering::Relaxed) {
                            break;
                        }
                        let attempt_epoch = thread_checkpoint_epoch.load(Ordering::Acquire);
                        let observation = match capture_fault_state_observation(peer_index, peer) {
                            Ok(observation) => observation,
                            Err(error) => {
                                if normalize_fault_observer_transport_failure(&error).is_none() {
                                    *thread_failure
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(
                                        format!(
                                            "validator #{peer_index} returned invalid APS state evidence"
                                        ),
                                    );
                                    thread_stop.store(true, Ordering::Relaxed);
                                    break;
                                }
                                let expected_unavailable = {
                                    let mut accumulators = thread_accumulators
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    if thread_checkpoint_epoch.load(Ordering::Acquire)
                                        != attempt_epoch
                                    {
                                        continue;
                                    }
                                    accumulators[peer_index].record_poll_failure(phase_index)
                                };
                                match expected_unavailable {
                                    Ok(true) => continue,
                                    Ok(false) => {
                                        *thread_failure
                                            .lock()
                                            .unwrap_or_else(
                                                std::sync::PoisonError::into_inner,
                                            ) = Some(format!(
                                            "unexpected peer #{peer_index} poll failure"
                                        ));
                                    }
                                    Err(error) => {
                                        *thread_failure
                                            .lock()
                                            .unwrap_or_else(
                                                std::sync::PoisonError::into_inner,
                                            ) = Some(error.to_string());
                                    }
                                }
                                thread_stop.store(true, Ordering::Relaxed);
                                break;
                            }
                        };
                        let result = {
                            // Match observe_snapshot's accumulator -> evidence lock order.
                            // An in-flight poll discarded by a checkpoint must be absent
                            // from both the summary and its retained response sequence.
                            let mut accumulators = thread_accumulators
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let mut retained = thread_retained_observations.as_ref().map(|rows| {
                                rows.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
                            });
                            accumulators[peer_index].record_current_poll(
                                &thread_baselines[peer_index],
                                &observation,
                                participants,
                                phase_index,
                                attempt_epoch,
                                thread_checkpoint_epoch.load(Ordering::Acquire),
                                retained.as_mut().map(|rows| &mut rows[peer_index]),
                            )
                        };
                        if let Err(error) = result {
                            *thread_failure
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(error.to_string());
                            thread_stop.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    if !thread_stop.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_millis(25));
                    }
                }
            })?;
        let mut observer = Self {
            stop,
            active_phase,
            observed_phase,
            checkpoint_epoch,
            accumulators,
            retained_observations,
            failure,
            baselines,
            participants,
            phase_complete: false,
            handle: Some(handle),
        };
        observer.wait_for_initial_poll()?;
        observer.phase_complete = true;
        Ok(observer)
    }

    fn wait_for_initial_poll(&self) -> Result<()> {
        let started = Instant::now();
        loop {
            if let Some(error) = self
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .cloned()
            {
                return Err(eyre!("continuous APS observer rejected state: {error}"));
            }
            if self
                .accumulators
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .all(|accumulator| {
                    accumulator.check_count >= 2
                        && matches!(accumulator.phase_coverage_met(0), Ok(true))
                })
            {
                return Ok(());
            }
            ensure!(
                started.elapsed() <= FAULT_CONTROL_TIMEOUT,
                "continuous APS observer did not poll every validator before the trial"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn begin_phase(
        &mut self,
        phase: &str,
        expected_unavailable: &[usize],
        finalization_allowed: bool,
    ) -> Result<()> {
        ensure!(
            self.phase_complete,
            "continuous APS observer cannot replace an incomplete phase"
        );
        ensure!(
            self.handle.is_some() && !self.stop.load(Ordering::Relaxed),
            "continuous APS observer cannot begin a phase after stopping"
        );
        let expected = expected_unavailable
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        ensure!(
            expected.len() == expected_unavailable.len()
                && expected
                    .iter()
                    .all(|peer_index| *peer_index < self.baselines.len()),
            "continuous APS observer expected-unavailable peer set is invalid"
        );
        let phase_index = {
            let mut accumulators = self
                .accumulators
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut phase_index = None;
            for accumulator in accumulators.iter_mut() {
                let current = accumulator.start_phase(
                    phase,
                    expected.contains(&accumulator.peer_index),
                    finalization_allowed,
                )?;
                ensure!(
                    phase_index.map_or(true, |expected| expected == current),
                    "continuous APS observer phase indexes diverged"
                );
                phase_index = Some(current);
            }
            phase_index.ok_or_else(|| eyre!("continuous APS observer has no peers"))?
        };
        let phase_index = u64::try_from(phase_index).expect("continuous APS phase index fits u64");
        self.active_phase.store(phase_index, Ordering::Release);
        self.phase_complete = false;
        let started = Instant::now();
        while self.observed_phase.load(Ordering::Acquire) != phase_index {
            if let Some(error) = self
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .cloned()
            {
                return Err(eyre!("continuous APS observer rejected state: {error}"));
            }
            ensure!(
                started.elapsed() <= FAULT_CONTROL_TIMEOUT,
                "continuous APS observer did not enter its requested phase"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn checkpoint_active_phase(&self, control_bindings: &[String]) -> Result<()> {
        ensure!(
            !self.phase_complete,
            "continuous APS observer cannot checkpoint a completed phase"
        );
        let phase_index = usize::try_from(self.active_phase.load(Ordering::Acquire))
            .expect("continuous APS phase index fits usize");
        self.checkpoint_epoch.fetch_add(1, Ordering::AcqRel);
        let mut accumulators = self
            .accumulators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for accumulator in accumulators.iter_mut() {
            accumulator.checkpoint_phase(phase_index, control_bindings)?;
        }
        Ok(())
    }

    fn active_phase_coverage_met(&self) -> Result<bool> {
        let phase_index = usize::try_from(self.active_phase.load(Ordering::Acquire))
            .expect("continuous APS phase index fits usize");
        self.accumulators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .try_fold(true, |covered, accumulator| {
                Ok(covered && accumulator.phase_coverage_met(phase_index)?)
            })
    }

    fn complete_phase(&mut self) -> Result<()> {
        ensure!(
            !self.phase_complete,
            "continuous APS observer phase was completed twice"
        );
        let started = Instant::now();
        loop {
            if let Some(error) = self
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .cloned()
            {
                return Err(eyre!("continuous APS observer rejected state: {error}"));
            }
            if self.active_phase_coverage_met()? {
                self.phase_complete = true;
                return Ok(());
            }
            ensure!(
                started.elapsed() <= FAULT_CONTROL_TIMEOUT,
                "continuous APS observer did not cover every peer in the active phase"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn observe_snapshot(&self, snapshot: &FaultStateSnapshotV1) -> Result<()> {
        ensure!(
            snapshot.validators.len() == self.baselines.len(),
            "continuous APS snapshot omits validators"
        );
        let mut accumulators = self
            .accumulators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let phase_index = usize::try_from(self.active_phase.load(Ordering::Acquire))
            .expect("continuous APS phase index fits usize");
        for ((accumulator, baseline), observation) in accumulators
            .iter_mut()
            .zip(&self.baselines)
            .zip(&snapshot.validators)
        {
            accumulator.record(baseline, observation, self.participants, phase_index)?;
        }
        if let Some(retained) = &self.retained_observations {
            let mut retained = retained
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (peer, observation) in retained.iter_mut().zip(&snapshot.validators) {
                ensure!(
                    peer.len() < LEAKAGE_MAX_OBSERVATIONS_PER_PEER,
                    "continuous APS evidence exceeded its per-peer bound"
                );
                peer.push(observation.clone());
            }
        }
        Ok(())
    }

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| eyre!("continuous APS observer thread panicked"))?;
        }
        if let Some(error) = self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            return Err(eyre!("continuous APS observer rejected state: {error}"));
        }
        Ok(())
    }

    fn finish(
        mut self,
        after: &FaultStateSnapshotV1,
    ) -> Result<Vec<FaultContinuousObservationSummaryV1>> {
        let (summaries, _) = self.finish_inner(after)?;
        Ok(summaries)
    }

    fn finish_with_evidence(
        mut self,
        after: &FaultStateSnapshotV1,
    ) -> Result<(
        Vec<FaultContinuousObservationSummaryV1>,
        Vec<Vec<FaultStateObservationV1>>,
    )> {
        ensure!(
            self.retained_observations.is_some(),
            "continuous APS observer was not configured to retain evidence"
        );
        self.finish_inner(after)
    }

    fn finish_inner(
        &mut self,
        after: &FaultStateSnapshotV1,
    ) -> Result<(
        Vec<FaultContinuousObservationSummaryV1>,
        Vec<Vec<FaultStateObservationV1>>,
    )> {
        ensure!(
            self.phase_complete,
            "continuous APS observer cannot finish with an incomplete phase"
        );
        let terminal_finalization_allowed =
            after
                .validators
                .iter()
                .try_fold(false, |allowed, observation| -> Result<bool> {
                    let baseline = self
                        .baselines
                        .get(observation.peer_index)
                        .ok_or_else(|| eyre!("terminal APS observation has an unknown peer"))?;
                    Ok(allowed
                        || matches!(
                            classify_fault_continuous_observation(
                                baseline,
                                observation,
                                self.participants
                            )?,
                            FaultContinuousObservationClassV1::Finalized
                        ))
                })?;
        self.begin_phase("terminal", &[], terminal_finalization_allowed)?;
        self.checkpoint_active_phase(&[])?;
        self.stop_and_join()?;
        self.observe_snapshot(after)?;
        ensure!(
            self.active_phase_coverage_met()?,
            "continuous APS terminal observation did not cover every peer"
        );
        self.phase_complete = true;
        let accumulators = {
            let mut guard = self
                .accumulators
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        let summaries = accumulators
            .into_iter()
            .map(FaultContinuousObservationAccumulatorV1::finish)
            .collect::<Result<Vec<_>>>()?;
        let retained = self
            .retained_observations
            .as_ref()
            .map(|retained| {
                let mut retained = retained
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::mem::take(&mut *retained)
            })
            .unwrap_or_default();
        Ok((summaries, retained))
    }
}

impl Drop for FaultContinuousObserverV1 {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn wait_for_converged_fault_state_snapshot(
    network: &Network,
    label: &str,
) -> Result<FaultStateSnapshotV1> {
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() <= FINALITY_TIMEOUT {
        match capture_fault_state_snapshot(network, label) {
            Ok(snapshot) if ensure_fault_state_converged(&snapshot).is_ok() => return Ok(snapshot),
            Ok(snapshot) => {
                last = Some(format!(
                    "non-converged {}-validator snapshot",
                    snapshot.validators.len()
                ))
            }
            Err(error) => last = Some(error.to_string()),
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::StateConvergence,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err(format!(
        "timed out waiting for a coherent APS state snapshot `{label}`: {}",
        last.unwrap_or_else(|| "no state response".to_owned())
    )))
}

fn wait_for_recovered_prepare_registration(
    network: &Network,
    before: &FaultStateSnapshotV1,
    participants: usize,
) -> Result<FaultStateSnapshotV1> {
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() <= FINALITY_TIMEOUT {
        match capture_fault_state_snapshot(network, "nonfinalized") {
            Ok(snapshot)
                if ensure_fault_prepare_lock_planes_full_v1(before, &snapshot, participants)
                    .is_ok() =>
            {
                return Ok(snapshot);
            }
            Ok(_) => last = Some("complete Prepare lock planes have not converged".to_owned()),
            Err(error) => last = Some(error.to_string()),
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for recovered replicated Prepare registration: {}",
        last.unwrap_or_else(|| "no state response".to_owned())
    ))
}

/// Test-only readiness decision for one bundle registered from an empty lock baseline.
/// The expected map is pinned to peer zero after that sponsor reports the exact
/// registration transaction Applied; it is never replaced by a later replica map.
/// Local Prepare locks may cover only the three successful voters per committee.
fn fault_replicated_prepare_registration_ready_v1(
    before: &FaultStateSnapshotV1,
    prepared: &FaultStateSnapshotV1,
    participants: usize,
    registered_commitment: &str,
) -> Result<bool> {
    let expected_peers = participants
        .checked_add(1)
        .and_then(|lanes| lanes.checked_mul(VALIDATORS_PER_LANE))
        .ok_or_else(|| eyre!("Prepare-lock validator count overflow"))?;
    ensure!(
        participants > 0
            && before.validators.len() == expected_peers
            && prepared.validators.len() == expected_peers,
        "Prepare-lock snapshots omit validators"
    );
    for (peer_index, (baseline, observation)) in before
        .validators
        .iter()
        .zip(&prepared.validators)
        .enumerate()
    {
        ensure!(
            baseline.peer_index == peer_index && observation.peer_index == peer_index,
            "Prepare-lock snapshots changed validator inventory"
        );
    }
    ensure_fault_state_converged(before)?;
    let baseline = &before.validators[0];
    for field in [
        "staged_pool_heads",
        "staged_nullifiers",
        "staged_output_commitments",
        "replicated_staged_locks",
        "staged_locks",
    ] {
        ensure!(
            fault_count(&baseline.counts, field)? == 0,
            "Prepare-lock baseline is not empty"
        );
    }
    ensure_fault_ledger_unchanged_before_finality(before, prepared)?;
    let expected_replicated = u64::try_from(participants)?
        .checked_mul(9)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| eyre!("replicated Prepare-lock count overflow"))?;
    ensure!(
        registered_commitment != baseline.replicated_staged_lock_commitment,
        "replicated Prepare-lock commitment remained empty"
    );
    // Network::client() addresses the first global validator, also all_peers()[0].
    // Its exact Applied registration establishes the single-bundle map anchor.
    let sponsor = &prepared.validators[0];
    ensure!(
        fault_count(&sponsor.counts, "replicated_staged_locks")? == expected_replicated
            && sponsor.replicated_staged_lock_commitment == registered_commitment,
        "Applied sponsor registration does not match the pinned replicated Prepare lock"
    );
    let mut ready = true;
    for observation in &prepared.validators {
        validate_fault_lock_shape_v1(observation, participants)?;
        if fault_count(&observation.counts, "replicated_staged_locks")? == 0 {
            ensure!(
                observation.replicated_staged_lock_commitment
                    == baseline.replicated_staged_lock_commitment,
                "validator #{} changed the empty replicated Prepare map",
                observation.peer_index
            );
            ready = false;
        } else {
            ensure!(
                observation.replicated_staged_lock_commitment == registered_commitment,
                "validator #{} observed a different replicated Prepare map",
                observation.peer_index
            );
        }
    }
    Ok(ready)
}

/// Wait after the smoke sponsor's exact Applied registration, without requiring
/// a fourth local Prepare vote or lock from any participant committee.
fn wait_for_smoke_prepare_registration(
    network: &Network,
    before: &FaultStateSnapshotV1,
    participants: usize,
) -> Result<FaultStateSnapshotV1> {
    let started = Instant::now();
    let mut registered_commitment = None;
    let mut last = None;
    while started.elapsed() <= FINALITY_TIMEOUT {
        match capture_fault_state_snapshot(network, "smoke-registered") {
            Ok(snapshot) => {
                let sponsor = snapshot
                    .validators
                    .first()
                    .ok_or_else(|| eyre!("Prepare registration snapshot has no sponsor"))?;
                let expected = registered_commitment
                    .get_or_insert_with(|| sponsor.replicated_staged_lock_commitment.clone());
                if fault_replicated_prepare_registration_ready_v1(
                    before,
                    &snapshot,
                    participants,
                    expected,
                )? {
                    return Ok(snapshot);
                }
                last = Some(
                    "replicated Prepare registration has not reached every validator".to_owned(),
                );
            }
            Err(error) => last = Some(error.to_string()),
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for smoke replicated Prepare registration: {}",
        last.unwrap_or_else(|| "no state response".to_owned())
    ))
}

fn ensure_fault_prepare_lock_planes_full_v1(
    before: &FaultStateSnapshotV1,
    prepared: &FaultStateSnapshotV1,
    participants: usize,
) -> Result<()> {
    let registered_commitment = &prepared
        .validators
        .first()
        .ok_or_else(|| eyre!("Prepare-lock snapshots omit validators"))?
        .replicated_staged_lock_commitment;
    ensure!(
        fault_replicated_prepare_registration_ready_v1(
            before,
            prepared,
            participants,
            registered_commitment,
        )?,
        "validators did not observe one complete replicated Prepare lock"
    );
    let baseline = &before.validators[0];
    let mut committee_commitments = BTreeMap::<usize, String>::new();
    for observation in &prepared.validators {
        if observation.peer_index < VALIDATORS_PER_LANE {
            ensure!(
                fault_count(&observation.counts, "staged_pool_heads")? == 0
                    && fault_count(&observation.counts, "staged_nullifiers")? == 0
                    && fault_count(&observation.counts, "staged_output_commitments")? == 0
                    && fault_count(&observation.counts, "staged_locks")? == 0
                    && observation.staged_lock_commitment == baseline.staged_lock_commitment,
                "global validator #{} exposed a committee-local lock",
                observation.peer_index
            );
            continue;
        }
        ensure!(
            fault_count(&observation.counts, "staged_pool_heads")? == 1
                && fault_count(&observation.counts, "staged_nullifiers")? == 2
                && fault_count(&observation.counts, "staged_output_commitments")? == 3
                && fault_count(&observation.counts, "staged_locks")? == 6
                && observation.staged_lock_commitment != baseline.staged_lock_commitment,
            "participant validator #{} lacks one complete committee-local leg lock",
            observation.peer_index
        );
        let committee = (observation.peer_index - VALIDATORS_PER_LANE) / VALIDATORS_PER_LANE;
        if let Some(expected) = committee_commitments.get(&committee) {
            ensure!(
                expected == &observation.staged_lock_commitment,
                "participant committee {committee} has divergent local lock commitments"
            );
        } else {
            committee_commitments.insert(committee, observation.staged_lock_commitment.clone());
        }
    }
    ensure!(
        committee_commitments.len() == participants,
        "Prepare-lock snapshot omits a participant committee"
    );
    Ok(())
}

fn fault_count(value: &HarnessJsonValue, name: &str) -> Result<u64> {
    value
        .get(name)
        .and_then(HarnessJsonValue::as_u64)
        .ok_or_else(|| eyre!("APS evidence count `{name}` is absent"))
}

fn ensure_fault_state_finalized_once(
    before: &FaultStateSnapshotV1,
    after: &FaultStateSnapshotV1,
    participants: usize,
) -> Result<()> {
    ensure_fault_state_converged(before)?;
    ensure_fault_state_converged(after)?;
    let before = &before.validators[0];
    let after = &after.validators[0];
    ensure!(
        before.ledger_commitment != after.ledger_commitment
            && before.replicated_staged_lock_commitment == after.replicated_staged_lock_commitment
            && before.staged_lock_commitment == after.staged_lock_commitment,
        "finalized APS trial did not atomically change the financial ledger and release both lock layers"
    );
    let expected_deltas = [
        ("roots", participants),
        ("nullifiers", participants * 2),
        ("commitments", participants * 3),
        ("encrypted_outputs", participants * 3),
        ("replay_markers", 1),
        ("receipts", 1),
    ];
    for (field, delta) in expected_deltas {
        ensure!(
            fault_count(&after.counts, field)?
                == fault_count(&before.counts, field)? + u64::try_from(delta)?,
            "finalized APS trial has the wrong `{field}` count delta"
        );
    }
    for field in [
        "governance",
        "pools",
        "abort_markers",
        "staged_pool_heads",
        "staged_nullifiers",
        "staged_output_commitments",
        "replicated_staged_locks",
        "staged_locks",
    ] {
        ensure!(
            fault_count(&after.counts, field)? == fault_count(&before.counts, field)?,
            "finalized APS trial unexpectedly changed `{field}`"
        );
    }
    ensure!(
        fault_count(&after.counts, "replicated_staged_locks")? == 0
            && fault_count(&after.counts, "staged_locks")? == 0,
        "finalized APS trial retained a replicated or committee-local lock"
    );
    Ok(())
}

fn ensure_fault_state_reverted(
    before: &FaultStateSnapshotV1,
    after: &FaultStateSnapshotV1,
) -> Result<()> {
    ensure!(
        before.validators.len() == after.validators.len() && !before.validators.is_empty(),
        "fault state snapshots have different validator inventories"
    );
    for (before, after) in before.validators.iter().zip(&after.validators) {
        ensure!(
            before.peer_index == after.peer_index
                && fault_state_identity(before)? == fault_state_identity(after)?,
            "validator #{} changed APS state after a nonfinalized trial",
            before.peer_index
        );
    }
    Ok(())
}

fn ensure_finalized_retry_acknowledgment(
    acknowledgment: &iroha::client::PrivateSettlementBundleSubmitResponseV1,
    bundle_id: Hash,
    carrier_id: Hash,
    observed_height: u64,
    expiry_height: u64,
) -> Result<()> {
    ensure!(
        acknowledgment.bundle_id == bundle_id && acknowledgment.carrier_id == carrier_id,
        "exact finalized retry acknowledgment changed the bundle or signed carrier identity"
    );
    ensure!(
        acknowledgment.accepted_at_height >= observed_height
            && acknowledgment
                .accepted_at_height
                .checked_add(1)
                .is_some_and(|candidate| candidate <= expiry_height),
        "exact finalized retry acknowledgment is outside the original carrier's live height window"
    );
    Ok(())
}

/// Retry the same signed carrier and verify acknowledgment without any repeated effect.
fn observe_idempotent_finalized_retry(
    sponsor: &Client,
    network: &Network,
    manifest: &AtomicPrivateSettlementV1,
    request: &PrivateSettlementBundleSubmitRequestV1,
    receipt: &iroha::data_model::nexus::PrivateSettlementReceiptV1,
) -> Result<FaultStateSnapshotV1> {
    let before = wait_for_converged_fault_state_snapshot(network, "before-finalized-retry")?;
    let fee_before = sponsor_nexus_fee_balance(sponsor)?;
    let observed_height = sponsor
        .client()
        .get_privacy_capabilities()?
        .committed_height;
    ensure!(
        observed_height >= receipt.finalized_height
            && observed_height >= manifest.authority_context_height
            && observed_height
                .checked_add(1)
                .is_some_and(|candidate| candidate <= manifest.expiry_height),
        "exact finalized retry is outside the original carrier's live height window"
    );
    let acknowledgment = sponsor
        .client()
        .submit_private_settlement_bundle_v1(request)
        .wrap_err("live exact finalized retry must acknowledge its immutable admission owner")?;
    ensure_finalized_retry_acknowledgment(
        &acknowledgment,
        manifest.bundle_id,
        Hash::from(request.transaction.hash()),
        observed_height,
        manifest.expiry_height,
    )?;
    ensure!(
        sponsor_nexus_fee_balance(sponsor)? == fee_before,
        "acknowledged finalized retry charged another carrier fee"
    );
    ensure!(
        wait_for_identical_receipt(network, manifest.bundle_id)? == *receipt,
        "acknowledged finalized retry changed the terminal receipt"
    );
    let after = wait_for_converged_fault_state_snapshot(network, "after-finalized-retry")?;
    ensure_fault_state_reverted(&before, &after)?;
    Ok(after)
}

#[test]
fn finalized_retry_acknowledgment_rejects_wrong_identity_or_height() {
    let bundle_id = Hash::new(b"finalized bundle");
    let carrier_id = Hash::new(b"original signed carrier");
    let expected = iroha::client::PrivateSettlementBundleSubmitResponseV1 {
        bundle_id,
        carrier_id,
        accepted_at_height: 10,
    };
    assert!(
        ensure_finalized_retry_acknowledgment(&expected, bundle_id, carrier_id, 10, 11).is_ok()
    );
    for changed in [
        iroha::client::PrivateSettlementBundleSubmitResponseV1 {
            bundle_id: Hash::new(b"substituted bundle"),
            ..expected
        },
        iroha::client::PrivateSettlementBundleSubmitResponseV1 {
            carrier_id: Hash::new(b"new signed carrier"),
            ..expected
        },
        iroha::client::PrivateSettlementBundleSubmitResponseV1 {
            accepted_at_height: 9,
            ..expected
        },
        iroha::client::PrivateSettlementBundleSubmitResponseV1 {
            accepted_at_height: 11,
            ..expected
        },
        iroha::client::PrivateSettlementBundleSubmitResponseV1 {
            accepted_at_height: u64::MAX,
            ..expected
        },
    ] {
        assert!(
            ensure_finalized_retry_acknowledgment(&changed, bundle_id, carrier_id, 10, 11).is_err()
        );
    }
    let overflow = iroha::client::PrivateSettlementBundleSubmitResponseV1 {
        accepted_at_height: u64::MAX,
        ..expected
    };
    assert!(
        ensure_finalized_retry_acknowledgment(&overflow, bundle_id, carrier_id, u64::MAX, u64::MAX)
            .is_err()
    );
}

fn ensure_fault_state_converged(snapshot: &FaultStateSnapshotV1) -> Result<()> {
    let first = snapshot
        .validators
        .first()
        .ok_or_else(|| eyre!("fault state convergence snapshot is empty"))?;
    let expected = fault_state_identity(first)?;
    for observation in &snapshot.validators {
        ensure!(
            fault_state_identity(observation)? == expected,
            "validators did not converge on one APS state commitment/count vector"
        );
    }
    Ok(())
}

fn ensure_fault_ledger_unchanged_before_finality(
    before: &FaultStateSnapshotV1,
    nonfinalized: &FaultStateSnapshotV1,
) -> Result<()> {
    ensure!(
        before.validators.len() == nonfinalized.validators.len() && !before.validators.is_empty(),
        "fault state snapshots have different validator inventories"
    );
    let expected = fault_ledger_identity(&before.validators[0])?;
    for observation in &before.validators {
        ensure!(
            fault_ledger_identity(observation)? == expected,
            "validators lack a coherent APS ledger before the trial"
        );
    }
    for observation in &nonfinalized.validators {
        ensure!(
            fault_ledger_identity(observation)? == expected,
            "validator #{} exposed a global APS map change before finality",
            observation.peer_index
        );
    }
    Ok(())
}

/// One immutable global decision, independent of equivalent QC signer subsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedRs16FinalityAnchorV1 {
    block_hash: HashOf<BlockHeader>,
    context_id: HeightContextId,
}

/// Complete all-process observations of the same authorized global decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedRs16FinalityObservationsV1 {
    observations: u64,
    anchor: SignedRs16FinalityAnchorV1,
}

fn ensure_signed_rs16_finality_identity(
    expected_roster: &BTreeSet<PeerId>,
    observed_roster: &[PeerId],
    previous_anchor: Option<SignedRs16FinalityAnchorV1>,
    observed_anchor: SignedRs16FinalityAnchorV1,
) -> Result<()> {
    ensure!(
        expected_roster.len() == VALIDATORS_PER_LANE
            && observed_roster.len() == VALIDATORS_PER_LANE
            && observed_roster.iter().cloned().collect::<BTreeSet<_>>() == *expected_roster,
        "signed finality substituted the configured global committee"
    );
    ensure!(
        previous_anchor.is_none_or(|previous| previous == observed_anchor),
        "validators returned conflicting finalized blocks or height contexts"
    );
    Ok(())
}

/// Initial live ingress and canonical restart recovery are distinct observations.
#[derive(Clone, Copy)]
enum FinalityObservationV1 {
    LiveTransport,
    Restored(SignedRs16FinalityAnchorV1),
}

impl FinalityObservationV1 {
    fn prior_anchor(self) -> Option<SignedRs16FinalityAnchorV1> {
        match self {
            Self::LiveTransport => None,
            Self::Restored(anchor) => Some(anchor),
        }
    }
}

#[test]
fn recovered_finality_requires_the_original_anchor_without_new_transport() {
    let anchor = SignedRs16FinalityAnchorV1 {
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"restored-block")),
        context_id: HeightContextId(HashOf::from_untyped_unchecked(Hash::new(
            b"restored-context",
        ))),
    };
    assert_eq!(FinalityObservationV1::LiveTransport.prior_anchor(), None);
    assert_eq!(
        FinalityObservationV1::Restored(anchor).prior_anchor(),
        Some(anchor)
    );
}

fn verify_signed_rs16_finality(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    finalized_height: u64,
) -> Result<SignedRs16FinalityObservationsV1> {
    Ok(collect_signed_rs16_finality(
        network,
        runtime,
        finalized_height,
        FinalityObservationV1::LiveTransport,
        None,
    )?
    .0)
}

fn collect_signed_rs16_finality(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    finalized_height: u64,
    observation: FinalityObservationV1,
    evidence: Option<(&Path, &str)>,
) -> Result<(SignedRs16FinalityObservationsV1, Vec<SmokeEvidenceFileV1>)> {
    let height = NonZeroU64::new(finalized_height)
        .ok_or_else(|| eyre!("finalized receipt height is zero"))?;
    let expected_roster = network.validators().iter().map(|peer| peer.id()).collect();
    let peers = network.all_peers().cloned().collect::<Vec<_>>();
    let expected_observations = peers.len();
    ensure!(
        expected_observations > 0,
        "finality observations omitted every validator"
    );
    let pids = peers
        .iter()
        .map(|peer| {
            runtime
                .block_on(peer.process_id())
                .ok_or_else(|| eyre!("finality peer lacks a live PID"))
        })
        .collect::<Result<Vec<_>>>()?;
    let responses = collect_bounded_observations(peers.clone(), TEST_STACK_BYTES, |peer| {
        let client = peer.client();
        let response = (|| -> Result<_> {
            let root_scope =
                iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
                    .sumeragi_context
                    .root_scope;
            let proof = client
                .client()
                .get_sumeragi_finality_proof(height, root_scope)?;
            let certified = authenticated_native_history(network, &client)?
                .into_iter()
                .find(|block| block.committed().height() == finalized_height)
                .ok_or_else(|| eyre!("peer omitted the requested certified native height"))?;
            Ok((proof, certified))
        })();
        (peer.id(), response)
    });
    let mut observations = 0_u64;
    let mut anchor = observation.prior_anchor();
    let mut files = Vec::new();
    let mut failures = Vec::new();
    let snapshots = network.startup_snapshot();
    ensure!(
        snapshots.len() == expected_observations,
        "transport snapshot omitted a process"
    );
    for (peer_index, (peer_id, response)) in responses.into_iter().enumerate() {
        let validated = (|| -> Result<()> {
            let (proof, certified) = response
                .wrap_err_with(|| format!("verify native finality history from {peer_id}"))?;
            let owned_peer = &peers[peer_index];
            ensure!(
                owned_peer.id() == peer_id
                    && snapshots[peer_index].index == peer_index
                    && owned_peer.is_running()
                    && runtime.block_on(owned_peer.process_id()) == Some(pids[peer_index]),
                "finality observation changed its owned process identity"
            );
            let committed = certified.committed();
            ensure!(
                proof.block_header.height() == height
                    && proof.block_header == committed.block().header()
                    && proof.block_wire == committed.block().encode_wire()?
                    && proof.committee.len()
                        == committed.commitment().schedule.current.committee.len()
                    && proof
                        .committee
                        .iter()
                        .zip(&committed.commitment().schedule.current.committee)
                        .all(|(candidate, original)| candidate.public_key
                            == *original.validator.public_key()
                            && candidate.proof_of_possession == original.proof_of_possession)
                    && certified
                        .commit_qc()
                        .is_some_and(|qc| qc.signers.count_ones() == 3),
                "peer {peer_id} native proof does not bind the original exact quorum carrier"
            );
            let observed_anchor = SignedRs16FinalityAnchorV1 {
                block_hash: committed.block_hash(),
                context_id: committed.id(),
            };
            let observed_roster = committed
                .commitment()
                .schedule
                .current
                .committee
                .iter()
                .map(|member| member.validator.clone())
                .collect::<Vec<_>>();
            ensure_signed_rs16_finality_identity(
                &expected_roster,
                &observed_roster,
                anchor,
                observed_anchor,
            )?;
            if matches!(observation, FinalityObservationV1::LiveTransport) {
                let log_name =
                    evidence.map(|(_, prefix)| format!("{prefix}-transport-{peer_index:02}.log"));
                let (transport, log) = verify_signed_rs16_transport(
                    network,
                    owned_peer,
                    pids[peer_index],
                    &snapshots[peer_index],
                    &certified,
                    &proof,
                    log_name.as_deref(),
                )?;
                if let Some((root, prefix)) = evidence {
                    files.push(write_smoke_evidence_bytes(
                        root,
                        log_name.as_deref().expect("evidence log name"),
                        &log,
                        ".log",
                        64 * 1024 * 1024,
                    )?);
                    files.push(write_smoke_evidence(
                        root,
                        &format!("{prefix}-transport-{peer_index:02}.json"),
                        &transport,
                    )?);
                }
            }
            ensure!(
                owned_peer.is_running()
                    && runtime.block_on(owned_peer.process_id()) == Some(pids[peer_index]),
                "finality process changed while retaining observations"
            );
            anchor = Some(observed_anchor);
            observations += 1;
            // Evidence writes remain on the caller in stable all_peers order.
            if let Some((root, prefix)) = evidence {
                files.push(write_smoke_evidence(
                    root,
                    &format!("{prefix}-{peer_index:02}.json"),
                    &proof,
                )?);
            }
            Ok(())
        })();
        if let Err(error) = validated {
            failures.push(format!("peer #{peer_index} {peer_id}: {error:?}"));
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    ensure!(
        usize::try_from(observations)? == expected_observations,
        "signed finality omitted a configured peer"
    );
    Ok((
        SignedRs16FinalityObservationsV1 {
            observations,
            anchor: anchor.ok_or_else(|| eyre!("finality observations omitted every validator"))?,
        },
        files,
    ))
}

/// A bounded prefix of the current process log; appends cannot alter retained evidence.
fn transport_log_prefix(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt as _;
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink() && before.len() <= 64 * 1024 * 1024,
        "invalid transport log source"
    );
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "transport log source replaced"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(before.len())
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len() && file.metadata()?.len() >= before.len(),
        "transport log truncated"
    );
    // A logger may be appending one unrelated line after the observed application.
    if let Some(end) = bytes.iter().rposition(|byte| *byte == b'\n') {
        bytes.truncate(end + 1);
    } else {
        bytes.clear();
    }
    Ok(bytes)
}

fn verify_signed_rs16_transport(
    network: &Network,
    peer: &iroha_test_network::NetworkPeer,
    pid: u32,
    snapshot: &iroha_test_network::PeerStartupState,
    certified: &iroha_core::sumeragi::certified_chain::CertifiedBlock,
    proof: &iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
    log_artifact: Option<&str>,
) -> Result<(HarnessJsonValue, Vec<u8>)> {
    let peer_id = peer.id();
    let committed = certified.committed();
    let header = committed
        .header()
        .ok_or_else(|| eyre!("transport requires a non-genesis header"))?;
    let current = &committed.commitment().schedule.current;
    let author = current
        .committee
        .get(usize::try_from(header.proposer)?)
        .ok_or_else(|| eyre!("certified proposer absent from original committee"))?;
    let layout = current.da_layout;
    let shape = layout.shape(u64::from(header.payload_len))?;
    let key = |peer: &PeerId| -> Result<String> {
        Ok(hex::encode(
            iroha_core::sumeragi::schedule::consensus_key(peer)?.as_bytes(),
        ))
    };
    let expected = transport_evidence::Expected {
        process_id: pid,
        instance: header.instance.to_string(),
        height: header.height,
        block: committed.core_hash().to_string(),
        result: committed.result().to_string(),
        availability: header.availability_digest.to_string(),
        payload: header.payload_hash.to_string(),
        bytes: u64::from(header.payload_len),
        epoch: header.epoch.epoch,
        context: header.epoch.context.to_string(),
        proposer: u64::from(header.proposer),
        local_is_author: author.validator == peer_id,
        local: key(&peer_id)?,
        peers: network
            .all_peers()
            .map(|p| key(&p.id()))
            .collect::<Result<_>>()?,
        k: usize::from(layout.data_shards),
        width: usize::from(layout.data_shards) + usize::from(layout.parity_shards),
        stripes: shape.stripe_count(),
    };
    ensure!(
        snapshot.is_running && snapshot.logs.stderr_run_id.is_some(),
        "transport source lacks live process identity"
    );
    let path = snapshot
        .logs
        .stdout_log
        .as_ref()
        .ok_or_else(|| eyre!("transport source lacks process stdout"))?;
    let stderr = snapshot
        .logs
        .stderr_log
        .as_ref()
        .ok_or_else(|| eyre!("transport source lacks process stderr"))?;
    let run_id = transport_evidence::current_run_log(
        &network.env_dir().join(peer.mnemonic()),
        snapshot.logs.stderr_run_id,
        path,
        stderr,
    )?;
    let stdout_path = path
        .strip_prefix(network.env_dir())?
        .to_str()
        .ok_or_else(|| eyre!("transport source path is not UTF-8"))?;
    let bytes = transport_log_prefix(path)?;
    let verified = transport_evidence::verify(&bytes, &expected)?;
    let value = norito::json!({
        "peer_index": (snapshot.index), "peer": (peer_id), "pid": (pid),
        "run_id": (run_id), "stdout_path": (stdout_path), "log_artifact": (log_artifact),
        "log_sha256": (sha256_hex(&bytes)), "log_bytes": (bytes.len()),
        "network_id": (network.network_id()), "proof_sha256": (sha256_hex(&canonical_harness_json_bytes(proof)?)),
        "instance": (expected.instance), "height": (header.height),
        "block": (expected.block), "availability_digest": (expected.availability),
        "result": (expected.result),
        "payload_hash": (expected.payload), "payload_bytes": (expected.bytes),
        "epoch": (expected.epoch), "context": (expected.context), "proposer": (expected.proposer),
        "local_key": (expected.local), "peer_keys": (expected.peers),
        "data_shards": (expected.k), "parity_shards": (expected.width - expected.k), "stripes": (expected.stripes),
        "admitted_rows": (verified.admitted_rows), "local_author": (expected.local_is_author),
        "audit_lines": (verified.audit_lines),
        "provenance": "retained process binary and local authenticated-ingress observations"
    });
    Ok((value, bytes))
}

#[test]
fn signed_rs16_finality_rejects_substituted_global_authority_and_conflicting_decisions() {
    let peers = (1_u8..=5)
        .map(|seed| {
            PeerId::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .expect("deterministic finality test key")
                    .public_key()
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    let expected = peers[..4].iter().cloned().collect::<BTreeSet<_>>();
    let anchor = SignedRs16FinalityAnchorV1 {
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"finality-block")),
        context_id: HeightContextId(HashOf::from_untyped_unchecked(Hash::new(
            b"finality-context",
        ))),
    };
    assert!(ensure_signed_rs16_finality_identity(&expected, &peers[..4], None, anchor).is_ok());
    assert!(
        ensure_signed_rs16_finality_identity(&expected, &peers[..4], Some(anchor), anchor).is_ok()
    );
    assert!(
        ensure_signed_rs16_finality_identity(&expected, &peers[1..], Some(anchor), anchor).is_err()
    );
    let mut duplicated = peers[..4].to_vec();
    duplicated[3] = duplicated[0].clone();
    assert!(
        ensure_signed_rs16_finality_identity(&expected, &duplicated, Some(anchor), anchor).is_err()
    );
    let changed_block = SignedRs16FinalityAnchorV1 {
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"conflicting-block")),
        ..anchor
    };
    assert!(
        ensure_signed_rs16_finality_identity(&expected, &peers[..4], Some(anchor), changed_block)
            .is_err()
    );
    let changed_context = SignedRs16FinalityAnchorV1 {
        context_id: HeightContextId(HashOf::from_untyped_unchecked(Hash::new(
            b"conflicting-context",
        ))),
        ..anchor
    };
    assert!(
        ensure_signed_rs16_finality_identity(&expected, &peers[..4], Some(anchor), changed_context)
            .is_err()
    );
}

fn prepare_fault_bundle(
    request: &RealProcessFaultRequestV1,
    bundle_ordinal: usize,
    sponsor: &Client,
    network: &Network,
    routes: &[PrivateSettlementRouteV1],
    committees: &[CommitteeEndpoints],
) -> Result<FaultPreparedBundleV1> {
    let current_height = sponsor
        .client()
        .get_privacy_capabilities()?
        .committed_height;
    let expiry_height = current_height
        .checked_add(FAULT_BUNDLE_EXPIRY_BLOCKS)
        .ok_or_else(|| eyre!("fault expiry height overflow"))?;
    let governed = fault_governed_legs(
        request,
        bundle_ordinal,
        routes,
        current_height,
        expiry_height,
    )?;
    let private_data = (0..routes.len())
        .map(default_private_settlement_leg_data)
        .collect::<Vec<_>>();
    let authority_context_height = activate_governed_private_pools(
        sponsor,
        network.network_id(),
        &governed,
        &private_data,
        expiry_height,
    )?;
    let manifest = proof_manifest(
        network.network_id(),
        authority_context_height,
        expiry_height,
        &governed,
    )?;
    let prepared = governed
        .into_iter()
        .zip(committees)
        .enumerate()
        .map(|(ordinal, (leg, committee))| {
            prepare_leg(ordinal, leg, &manifest, committee.authority.digest()?)
        })
        .collect::<Result<Vec<_>>>()?;
    let materials = provisional_materials(manifest.clone(), &prepared, committees)?;
    let authorities = committees
        .iter()
        .map(|committee| committee.authority.clone())
        .collect();
    let deltas = prepared
        .iter()
        .map(|leg| leg.prepared.delta.clone())
        .collect();
    Ok(FaultPreparedBundleV1 {
        manifest,
        prepared,
        materials,
        authorities,
        deltas,
    })
}

fn certify_and_upload_fault_bundle(
    sponsor: &Client,
    bundle: &mut FaultPreparedBundleV1,
    committees: &[CommitteeEndpoints],
) -> Result<()> {
    let certificates = bundle
        .materials
        .iter()
        .zip(committees)
        .map(|(material, committee)| {
            sponsor
                .client()
                .certify_private_settlement_leg_availability_v1(&committee.endpoints, material)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut final_manifest = bundle.materials[0].manifest.clone();
    for (ordinal, certificate) in certificates.iter().enumerate() {
        final_manifest.legs[ordinal].availability_certificate_digest = certificate.digest()?;
    }
    final_manifest.validate()?;
    for (ordinal, ((material, certificate), committee)) in bundle
        .materials
        .iter()
        .zip(&certificates)
        .zip(committees)
        .enumerate()
    {
        let upload = PrivateSettlementLegUploadRequestV1 {
            manifest: final_manifest.clone(),
            audit_policy: material.audit_policy.clone(),
            committee_authority: material.committee_authority.clone(),
            payload: material.payload_with_certificate(certificate.clone()),
        };
        for endpoint in &committee.endpoints {
            let response = sponsor
                .client()
                .upload_private_settlement_leg_to_v1(endpoint, &upload)?;
            ensure!(
                usize::from(response.leg_ordinal) == ordinal,
                "fault upload ordinal was substituted"
            );
        }
    }
    bundle.manifest = final_manifest;
    Ok(())
}

fn audit_fault_bundle(
    sponsor: &Client,
    bundle: &FaultPreparedBundleV1,
    committees: &[CommitteeEndpoints],
) -> Result<()> {
    for (ordinal, (leg, committee)) in bundle.prepared.iter().zip(committees).enumerate() {
        let auditor_transport_signer =
            BorrowedKeyPairIdentityRequestSignerV1::new(&leg.governed.auditor_signing);
        let capsule_request = PrivateSettlementAuditorCapsuleRequestV1 {
            audit_policy: leg.governed.policy.clone(),
        };
        let fetched = sponsor
            .client()
            .private_settlement_auditor_capsule_quorum_for_authority_v1(
                &committee.endpoints,
                &bundle.authorities[ordinal],
                bundle.manifest.legs[ordinal].payload_digest,
                &capsule_request,
                &auditor_transport_signer,
            )?;
        ensure!(
            fetched.lifecycle == PrivateSettlementLifecycleDtoV1::Collecting,
            "unexpected fault audit lifecycle"
        );
        let authoritative_height = fetched.authoritative_height;
        let view = PrivateSettlementAuditorSidecarViewV1 {
            manifest: fetched.manifest,
            policy: fetched.audit_policy,
            authority: fetched.committee_authority,
            statement: fetched.statement,
            delta: fetched.delta,
            audit_capsule: fetched.audit_capsule,
            availability: fetched.availability,
            lifecycle: PrivateSettlementSidecarLifecycleV1::Collecting,
        };
        let auditor_id = AccountId::new(leg.governed.auditor_signing.public_key().clone());
        let approval = approve_private_settlement_leg_v1(
            &view,
            &leg.governed.governance,
            authoritative_height,
            &auditor_id,
            leg.governed.auditor_encryption.secret(),
            &leg.governed.auditor_signing,
            &approve_all_audit_material,
        )?;
        let response = sponsor
            .client()
            .submit_private_settlement_audit_approval_quorum_for_authority_v1(
                &committee.endpoints,
                &bundle.authorities[ordinal],
                bundle.manifest.legs[ordinal].payload_digest,
                &auditor_transport_signer,
                &PrivateSettlementAuditApprovalRequestV1 {
                    audit_policy: capsule_request.audit_policy,
                    approval,
                },
            )?;
        ensure!(
            response.lifecycle == PrivateSettlementLifecycleDtoV1::Audited,
            "fault audit approval quorum was not durable"
        );
    }
    Ok(())
}

fn fault_endpoint_matrix(committees: &[CommitteeEndpoints]) -> Vec<Vec<Url>> {
    committees
        .iter()
        .map(|committee| committee.endpoints.clone())
        .collect()
}

fn finalize_fault_bundle(
    sponsor: &Client,
    network: &Network,
    bundle: &FaultPreparedBundleV1,
    barrier: iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1,
    commits: Vec<iroha::data_model::nexus::PrivateSettlementPhaseCertificateV1>,
) -> Result<iroha::data_model::nexus::PrivateSettlementReceiptV1> {
    let legs = bundle
        .deltas
        .iter()
        .cloned()
        .zip(barrier.prepare_certificates.iter().cloned())
        .zip(commits)
        .map(|((delta, prepare), commit)| PrivateSettlementLegReceiptV1 {
            delta,
            prepare,
            commit,
        })
        .collect();
    let carrier = FinalizeAtomicPrivateSettlementV1::new(PrivateSettlementCommitBundleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: bundle.manifest.clone(),
        authority_catalog: barrier.authority_catalog.clone(),
        legs,
    });
    let transaction = {
        let account = sponsor.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [InstructionBox::from(carrier)],
                bundle.manifest.public_fee_intent.clone(),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .wrap_err("build integration-test transaction")?;
    sponsor.client().submit_private_settlement_bundle_v1(
        &PrivateSettlementBundleSubmitRequestV1 { transaction },
    )?;
    wait_for_identical_receipt(network, bundle.manifest.bundle_id)
}

fn route_control_type(phase: PrivateSettlementRouteControlPhase) -> &'static str {
    match phase {
        PrivateSettlementRouteControlPhase::RestrictedDa => "restricted_da",
        PrivateSettlementRouteControlPhase::Prepare => "prepare",
        PrivateSettlementRouteControlPhase::Commit => "commit",
    }
}

fn exercise_route_loss<F>(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    observer: &mut FaultContinuousObserverV1,
    peer_index: usize,
    phase: PrivateSettlementRouteControlPhase,
    bundle_id: Hash,
    seed: u64,
    loss_percent: u8,
    mut request: F,
) -> Result<(Vec<FaultControlOccurrenceV1>, FaultStateSnapshotV1)>
where
    F: FnMut() -> Result<()>,
{
    observer.begin_phase(&format!("{}_loss", route_control_type(phase)), &[], false)?;
    let peer = process_peer(network, peer_index);
    let control = peer
        .private_settlement_route_control()
        .ok_or_else(|| eyre!("fault peer lacks APS route control"))?;
    let drop_first = FAULT_ROUTE_MATCHES
        .checked_mul(u64::from(loss_percent))
        .and_then(|value| value.checked_div(100))
        .ok_or_else(|| eyre!("fault loss ratio overflow"))?;
    ensure!(
        drop_first * 100 == FAULT_ROUTE_MATCHES * u64::from(loss_percent),
        "fault loss ratio is not exactly representable"
    );
    let command = control.arm_private_settlement_route_control(
        phase,
        PrivateSettlementRouteControlAction::Loss,
        *bundle_id.as_ref(),
        seed,
        drop_first,
        FAULT_ROUTE_MATCHES,
    )?;
    let mut rejected = 0_u64;
    for _ in 0..FAULT_ROUTE_MATCHES {
        if request().is_err() {
            rejected += 1;
        }
    }
    ensure!(
        rejected == drop_first,
        "APS route control did not reject the exact configured loss count"
    );
    let (loss_ack_bytes, loss_ack) = runtime.block_on(
        control.wait_for_private_settlement_route_control(&command, FAULT_CONTROL_TIMEOUT),
    )?;
    ensure!(
        loss_ack.matched == FAULT_ROUTE_MATCHES
            && loss_ack.dropped == drop_first
            && loss_ack.passed == FAULT_ROUTE_MATCHES - drop_first
            && loss_ack.held == 0
            && loss_ack.released == 0,
        "APS loss acknowledgement counters differ from the in-flight trial"
    );
    let loss_occurrence = fault_control_occurrence(
        route_control_type(phase),
        Some(peer_index),
        command.canonical_bytes,
        loss_ack_bytes,
        None,
        None,
    )?;
    observer
        .checkpoint_active_phase(&[fault_checkpoint_acknowledgement_binding(&loss_occurrence)])?;
    observer.complete_phase()?;

    let healing = control.arm_private_settlement_route_control(
        phase,
        PrivateSettlementRouteControlAction::Pass,
        *bundle_id.as_ref(),
        seed,
        0,
        0,
    )?;
    request().wrap_err("APS route healing request did not pass")?;
    let (healing_ack_bytes, healing_ack) = runtime.block_on(
        control.wait_for_private_settlement_route_control(&healing, FAULT_CONTROL_TIMEOUT),
    )?;
    ensure!(
        healing_ack.matched == 1
            && healing_ack.passed == 1
            && healing_ack.dropped == 0
            && healing_ack.held == 0
            && healing_ack.released == 0,
        "APS route healing acknowledgement is not exact"
    );
    let healing_occurrence = fault_control_occurrence(
        route_control_type(phase),
        Some(peer_index),
        healing.canonical_bytes,
        healing_ack_bytes,
        None,
        None,
    )?;
    observer.begin_phase("post_recovery", &[], true)?;
    observer.checkpoint_active_phase(&[fault_checkpoint_acknowledgement_binding(
        &healing_occurrence,
    )])?;
    let nonfinalized = capture_fault_state_snapshot(network, "nonfinalized")?;
    Ok((vec![loss_occurrence, healing_occurrence], nonfinalized))
}

fn exercise_route_hold<F>(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    observer: &mut FaultContinuousObserverV1,
    peer_index: usize,
    phase: PrivateSettlementRouteControlPhase,
    bundle_id: Hash,
    seed: u64,
    request: F,
) -> Result<(Vec<FaultControlOccurrenceV1>, FaultStateSnapshotV1)>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    observer.begin_phase(&format!("{}_hold", route_control_type(phase)), &[], false)?;
    let peer = process_peer(network, peer_index);
    let control = peer
        .private_settlement_route_control()
        .ok_or_else(|| eyre!("fault peer lacks APS route control"))?;
    let hold = control.arm_private_settlement_route_control(
        phase,
        PrivateSettlementRouteControlAction::Hold,
        *bundle_id.as_ref(),
        seed,
        0,
        1,
    )?;
    let request_thread = thread::Builder::new()
        .name(format!("aps-fault-{}-hold", route_control_type(phase)))
        .spawn(request)?;
    let (hold_ack_bytes, hold_ack) = runtime.block_on(
        control.wait_for_private_settlement_route_control(&hold, FAULT_CONTROL_TIMEOUT),
    )?;
    ensure!(
        hold_ack.matched == 1
            && hold_ack.held == 1
            && hold_ack.passed == 0
            && hold_ack.dropped == 0
            && hold_ack.released == 0,
        "APS Hold acknowledgement is not exact"
    );
    let hold_occurrence = fault_control_occurrence(
        route_control_type(phase),
        Some(peer_index),
        hold.canonical_bytes,
        hold_ack_bytes,
        None,
        None,
    )?;
    observer
        .checkpoint_active_phase(&[fault_checkpoint_acknowledgement_binding(&hold_occurrence)])?;
    let nonfinalized = capture_fault_state_snapshot(network, "nonfinalized")?;
    observer.complete_phase()?;
    let pass = control.arm_private_settlement_route_control(
        phase,
        PrivateSettlementRouteControlAction::Pass,
        *bundle_id.as_ref(),
        seed,
        0,
        0,
    )?;
    request_thread
        .join()
        .map_err(|_| eyre!("APS held request thread panicked"))??;
    let (pass_ack_bytes, pass_ack) = runtime.block_on(
        control.wait_for_private_settlement_route_control(&pass, FAULT_CONTROL_TIMEOUT),
    )?;
    ensure!(
        pass_ack.predecessor_command_sha256.as_deref() == Some(hold.sha256.as_str())
            && pass_ack.matched == 1
            && pass_ack.held == 1
            && pass_ack.released == 1,
        "APS Hold-to-Pass acknowledgement lost predecessor evidence"
    );
    let pass_occurrence = fault_control_occurrence(
        route_control_type(phase),
        Some(peer_index),
        pass.canonical_bytes,
        pass_ack_bytes,
        None,
        None,
    )?;
    observer.begin_phase("post_recovery", &[], true)?;
    observer
        .checkpoint_active_phase(&[fault_checkpoint_acknowledgement_binding(&pass_occurrence)])?;
    Ok((vec![hold_occurrence, pass_occurrence], nonfinalized))
}

fn stop_peer_for_quorum_progress(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    peer_index: usize,
    revision: u64,
) -> Result<FaultStoppedPeerV1> {
    let peer = process_peer(network, peer_index).clone();
    let before_pid = runtime
        .block_on(peer.process_id())
        .ok_or_else(|| eyre!("quorum-unavailability target has no live PID"))?;
    let command = FaultRestartCommandV1 {
        format_version: 1,
        revision,
        operation: "stop_validator_for_quorum_progress".to_owned(),
        peer_index,
        before_pid,
    };
    let command_bytes = canonical_harness_json_bytes(&command)?;
    ensure!(
        runtime.block_on(peer.shutdown_if_started())
            && runtime.block_on(peer.process_id()).is_none(),
        "quorum-unavailability target did not stop"
    );
    Ok(FaultStoppedPeerV1 {
        peer,
        peer_index,
        before_pid,
        revision,
        command_bytes,
    })
}

fn restart_quorum_progress_peer(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    stopped: FaultStoppedPeerV1,
) -> Result<FaultControlOccurrenceV1> {
    let config_layers = network
        .config_layers_for_peer(&stopped.peer)
        .collect::<Vec<_>>();
    runtime.block_on(stopped.peer.start_checked(config_layers.iter(), None))?;
    let after_pid = runtime
        .block_on(stopped.peer.process_id())
        .ok_or_else(|| eyre!("quorum-progress restart has no live PID"))?;
    ensure!(
        after_pid != stopped.before_pid && stopped.peer.client().status().get().is_ok(),
        "quorum-progress restart did not produce a healthy new process"
    );
    let acknowledgement = FaultRestartAckV1 {
        format_version: 1,
        revision: stopped.revision,
        command_sha256: sha256_hex(&stopped.command_bytes),
        operation: "validator_restarted_after_quorum_progress".to_owned(),
        peer_index: stopped.peer_index,
        before_pid: stopped.before_pid,
        after_pid,
        health_observed: true,
    };
    fault_control_occurrence(
        "validator_restart",
        Some(stopped.peer_index),
        stopped.command_bytes,
        canonical_harness_json_bytes(&acknowledgement)?,
        Some(stopped.before_pid),
        Some(after_pid),
    )
}

fn restart_peer_with_evidence(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    observer: &mut FaultContinuousObserverV1,
    peer_index: usize,
    revision: u64,
    control_type: &str,
) -> Result<FaultControlOccurrenceV1> {
    let peer = process_peer(network, peer_index).clone();
    let before_pid = runtime
        .block_on(peer.process_id())
        .ok_or_else(|| eyre!("restart target has no live PID"))?;
    let command = FaultRestartCommandV1 {
        format_version: 1,
        revision,
        operation: "restart_validator".to_owned(),
        peer_index,
        before_pid,
    };
    let command_bytes = canonical_harness_json_bytes(&command)?;
    let config_layers = network.config_layers_for_peer(&peer).collect::<Vec<_>>();
    observer.begin_phase(control_type, &[peer_index], false)?;
    ensure!(
        runtime.block_on(peer.shutdown_if_started())
            && runtime.block_on(peer.process_id()).is_none(),
        "restart target was not running"
    );
    observer.checkpoint_active_phase(&[format!("command:{}", sha256_hex(&command_bytes))])?;
    observer.complete_phase()?;
    runtime.block_on(peer.start_checked(config_layers.iter(), None))?;
    let after_pid = runtime
        .block_on(peer.process_id())
        .ok_or_else(|| eyre!("restarted target has no live PID"))?;
    ensure!(
        after_pid != before_pid && peer.client().status().get().is_ok(),
        "validator restart did not produce a healthy new process"
    );
    let acknowledgement = FaultRestartAckV1 {
        format_version: 1,
        revision,
        command_sha256: sha256_hex(&command_bytes),
        operation: command.operation,
        peer_index,
        before_pid,
        after_pid,
        health_observed: true,
    };
    let occurrence = fault_control_occurrence(
        control_type,
        Some(peer_index),
        command_bytes,
        canonical_harness_json_bytes(&acknowledgement)?,
        Some(before_pid),
        Some(after_pid),
    )?;
    observer.begin_phase("global_recovery", &[], false)?;
    observer.checkpoint_active_phase(&[fault_checkpoint_acknowledgement_binding(&occurrence)])?;
    observer.complete_phase()?;
    Ok(occurrence)
}

fn aggregate_fault_phase_votes(
    votes: &[iroha::data_model::nexus::PrivateSettlementPhaseVoteV1],
    signer_subset: [usize; 3],
    authority_catalog_index: u8,
) -> Result<iroha::data_model::nexus::PrivateSettlementPhaseCertificateV1> {
    ensure!(
        votes.len() == VALIDATORS_PER_LANE,
        "fault vote roster is incomplete"
    );
    let body = votes[signer_subset[0]].body.clone();
    ensure!(
        signer_subset.iter().all(|index| votes[*index].body == body),
        "fault votes do not certify one body"
    );
    let signatures = signer_subset
        .iter()
        .map(|index| votes[*index].signature.as_slice())
        .collect::<Vec<_>>();
    let signers_bitmap = signer_subset
        .iter()
        .fold(0_u8, |bitmap, index| bitmap | (1_u8 << index));
    Ok(
        iroha::data_model::nexus::PrivateSettlementPhaseCertificateV1 {
            body,
            authority_catalog_index,
            signers_bitmap,
            aggregate_signature: iroha_crypto::bls_normal_aggregate_signatures(&signatures)?,
        },
    )
}

fn prepare_fault_bundle_with_normalization(
    sponsor: &Client,
    bundle: &FaultPreparedBundleV1,
    committees: &[CommitteeEndpoints],
) -> Result<(
    iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1,
    FaultPrepareQcNormalizationV1,
)> {
    let mut first_certificates = Vec::with_capacity(committees.len());
    let mut alternate_first = None;
    for (ordinal, committee) in committees.iter().enumerate() {
        let payload_digest = bundle.manifest.legs[ordinal].payload_digest;
        let votes = committee
            .endpoints
            .iter()
            .map(|endpoint| {
                sponsor
                    .client()
                    .request_private_settlement_prepare_vote_v1(
                        endpoint,
                        &bundle.manifest,
                        payload_digest,
                        &committee.authority,
                    )
                    .map(|response| response.vote)
            })
            .collect::<Result<Vec<_>>>()?;
        let first = aggregate_fault_phase_votes(
            &votes,
            [0, 1, 2],
            u8::try_from(ordinal).expect("leg ordinal fits u8"),
        )?;
        if ordinal == 0 {
            alternate_first = Some(aggregate_fault_phase_votes(&votes, [0, 1, 3], 0)?);
        }
        for endpoint in &committee.endpoints {
            sponsor
                .client()
                .persist_private_settlement_phase_certificate_v1(
                    endpoint,
                    &bundle.manifest,
                    payload_digest,
                    &first,
                )?;
        }
        first_certificates.push(first);
    }
    let alternate_first =
        alternate_first.ok_or_else(|| eyre!("fault normalization lacks leg 0"))?;
    let first_barrier = SdkClient::build_private_settlement_prepare_barrier_v1(
        bundle.manifest.clone(),
        &bundle.authorities,
        bundle.deltas.clone(),
        first_certificates.clone(),
    )?;
    let mut second_certificates = first_certificates.clone();
    second_certificates[0] = alternate_first.clone();
    let second_barrier = SdkClient::build_private_settlement_prepare_barrier_v1(
        bundle.manifest.clone(),
        &bundle.authorities,
        bundle.deltas.clone(),
        second_certificates,
    )?;
    ensure!(
        first_barrier.prepared_bundle_digest == second_barrier.prepared_bundle_digest,
        "quorum-equivalent Prepare QCs did not normalize to one bundle digest"
    );

    let first_qc = &first_certificates[0];
    let mut changed_body = alternate_first.clone();
    changed_body.body.bundle_id = Hash::prehashed([0xa5; Hash::LENGTH]);
    let mut changed_certificates = first_certificates.clone();
    changed_certificates[0] = changed_body;
    let changed_body_rejected = SdkClient::build_private_settlement_prepare_barrier_v1(
        bundle.manifest.clone(),
        &bundle.authorities,
        bundle.deltas.clone(),
        changed_certificates,
    )
    .is_err();
    let mut changed_index = alternate_first.clone();
    changed_index.authority_catalog_index = 1;
    let mut changed_index_certificates = first_certificates.clone();
    changed_index_certificates[0] = changed_index;
    let authority_index_binding_verified = SdkClient::build_private_settlement_prepare_barrier_v1(
        bundle.manifest.clone(),
        &bundle.authorities,
        bundle.deltas.clone(),
        changed_index_certificates,
    )
    .is_err();
    let mut changed_signed_body = alternate_first.clone();
    changed_signed_body.body.delta_digest = Hash::prehashed([0x5a; Hash::LENGTH]);
    let mut changed_signed_certificates = first_certificates.clone();
    changed_signed_certificates[0] = changed_signed_body;
    let signed_body_binding_verified = SdkClient::build_private_settlement_prepare_barrier_v1(
        bundle.manifest.clone(),
        &bundle.authorities,
        bundle.deltas.clone(),
        changed_signed_certificates,
    )
    .is_err();
    ensure!(
        changed_body_rejected && authority_index_binding_verified && signed_body_binding_verified,
        "Prepare QC negative binding probes were accepted"
    );
    let normalized_sha = sha256_hex(first_barrier.prepared_bundle_digest.as_ref());
    let normalization = FaultPrepareQcNormalizationV1 {
        first_signer_subset: vec![0, 1, 2],
        second_signer_subset: vec![0, 1, 3],
        certified_body_sha256: sha256_hex(&norito::encode_canonical(&first_qc.body)?),
        first_qc_sha256: sha256_hex(&norito::encode_canonical(first_qc)?),
        second_qc_sha256: sha256_hex(&norito::encode_canonical(&alternate_first)?),
        first_normalized_barrier_sha256: normalized_sha.clone(),
        second_normalized_barrier_sha256: normalized_sha,
        equivalent_subsets_accepted: true,
        changed_body_rejected,
        authority_index_binding_verified,
        signed_body_binding_verified,
    };
    // Every committee retained the first QC encoding above. Register and use
    // the second barrier so this real-process trial proves that an equivalent
    // coordinator recovery cannot orphan the global lock or block Commit.
    Ok((second_barrier, normalization))
}

fn build_fault_carrier_submit(
    sponsor: &Client,
    bundle: &FaultPreparedBundleV1,
    barrier: &iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1,
    commits: &[iroha::data_model::nexus::PrivateSettlementPhaseCertificateV1],
) -> Result<PrivateSettlementBundleSubmitRequestV1> {
    let legs = bundle
        .deltas
        .iter()
        .cloned()
        .zip(barrier.prepare_certificates.iter().cloned())
        .zip(commits.iter().cloned())
        .map(|((delta, prepare), commit)| PrivateSettlementLegReceiptV1 {
            delta,
            prepare,
            commit,
        })
        .collect();
    let carrier = FinalizeAtomicPrivateSettlementV1::new(PrivateSettlementCommitBundleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: bundle.manifest.clone(),
        authority_catalog: barrier.authority_catalog.clone(),
        legs,
    });
    let account = sponsor.account_client();
    let transaction = account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(
            [InstructionBox::from(carrier)],
            bundle.manifest.public_fee_intent.clone(),
            Metadata::default(),
        ))
        .and_then(|payload| account.sign_transaction(payload))
        .wrap_err("build integration-test transaction")?;
    Ok(PrivateSettlementBundleSubmitRequestV1 { transaction })
}

fn verify_invalid_leg_carrier_is_state_byte_identical(
    sponsor: &Client,
    network: &Network,
    bundle: &FaultPreparedBundleV1,
    barrier: &iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1,
    commits: &[iroha::data_model::nexus::PrivateSettlementPhaseCertificateV1],
) -> Result<()> {
    let before = capture_fault_state_snapshot(network, "invalid-leg-before")?;
    let mut invalid_deltas = bundle.deltas.clone();
    let first = invalid_deltas
        .first_mut()
        .ok_or_else(|| eyre!("invalid-leg probe lacks a participant delta"))?;
    first.new_epoch = first
        .new_epoch
        .checked_add(1)
        .ok_or_else(|| eyre!("invalid-leg epoch probe overflow"))?;
    let legs = invalid_deltas
        .into_iter()
        .zip(barrier.prepare_certificates.iter().cloned())
        .zip(commits.iter().cloned())
        .map(|((delta, prepare), commit)| PrivateSettlementLegReceiptV1 {
            delta,
            prepare,
            commit,
        })
        .collect();
    let carrier = FinalizeAtomicPrivateSettlementV1::new(PrivateSettlementCommitBundleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: bundle.manifest.clone(),
        authority_catalog: barrier.authority_catalog.clone(),
        legs,
    });
    let account = sponsor.account_client();
    let transaction = account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(
            [InstructionBox::from(carrier)],
            bundle.manifest.public_fee_intent.clone(),
            Metadata::default(),
        ))
        .and_then(|payload| account.sign_transaction(payload))
        .wrap_err("build integration-test transaction")?;
    let request = PrivateSettlementBundleSubmitRequestV1 { transaction };
    ensure!(
        sponsor
            .client()
            .submit_private_settlement_bundle_v1(&request)
            .is_err(),
        "global carrier accepted an invalid private-settlement leg delta"
    );
    let after = capture_fault_state_snapshot(network, "invalid-leg-after")?;
    ensure!(
        before.validators.len() == after.validators.len(),
        "invalid-leg probe changed the validator evidence inventory"
    );
    for (before_peer, after_peer) in before.validators.iter().zip(&after.validators) {
        ensure!(
            before_peer.peer_index == after_peer.peer_index
                && fault_state_identity(before_peer)? == fault_state_identity(after_peer)?,
            "invalid-leg carrier changed APS state on validator #{}",
            before_peer.peer_index
        );
    }
    for snapshot in [&before, &after] {
        let expected = fault_ledger_identity(
            snapshot
                .validators
                .first()
                .ok_or_else(|| eyre!("invalid-leg probe has no validator observations"))?,
        )?;
        ensure!(
            snapshot
                .validators
                .iter()
                .all(|observation| fault_ledger_identity(observation)
                    .is_ok_and(|value| value == expected)),
            "invalid-leg probe observed a globally incoherent APS ledger"
        );
    }
    Ok(())
}

fn restart_ack_occurrence(
    peer_index: usize,
    revision: u64,
    control_type: &str,
    before_pid: u32,
    after_pid: u32,
) -> Result<FaultControlOccurrenceV1> {
    let command = FaultRestartCommandV1 {
        format_version: 1,
        revision,
        operation: "recover_crashed_validator".to_owned(),
        peer_index,
        before_pid,
    };
    let command_bytes = canonical_harness_json_bytes(&command)?;
    let acknowledgement = FaultRestartAckV1 {
        format_version: 1,
        revision,
        command_sha256: sha256_hex(&command_bytes),
        operation: command.operation,
        peer_index,
        before_pid,
        after_pid,
        health_observed: true,
    };
    fault_control_occurrence(
        control_type,
        Some(peer_index),
        command_bytes,
        canonical_harness_json_bytes(&acknowledgement)?,
        Some(before_pid),
        Some(after_pid),
    )
}

fn wait_for_fault_state_reverted(
    network: &Network,
    before: &FaultStateSnapshotV1,
) -> Result<FaultStateSnapshotV1> {
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() <= FINALITY_TIMEOUT {
        match capture_fault_state_snapshot(network, "after") {
            Ok(snapshot) if ensure_fault_state_reverted(before, &snapshot).is_ok() => {
                return Ok(snapshot);
            }
            Ok(_) => last = Some("APS state has not returned to its pre-trial identity".to_owned()),
            Err(error) => last = Some(error.to_string()),
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for pre-carrier crash reconciliation: {}",
        last.unwrap_or_else(|| "no state response".to_owned())
    ))
}

fn advance_fault_bundle_past_expiry(
    sponsor: &Client,
    bundle: &FaultPreparedBundleV1,
) -> Result<()> {
    loop {
        let height = sponsor
            .client()
            .get_privacy_capabilities()?
            .committed_height;
        if height > bundle.manifest.expiry_height {
            return Ok(());
        }
        let tick = {
            let account = sponsor.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    [InstructionBox::from(Log::new(
                        Level::INFO,
                        format!("APS fault expiry {} h{height}", bundle.manifest.bundle_id),
                    ))],
                    bounded_nexus_fee(),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .wrap_err("build integration-test transaction")?;
        sponsor.submit_transaction_and_wait(&tick)?;
    }
}

fn phase_certificate_for_leg(
    sponsor: &Client,
    bundle: &FaultPreparedBundleV1,
    committee: &CommitteeEndpoints,
    leg_ordinal: usize,
    phase: iroha::data_model::nexus::PrivateSettlementPhaseV1,
    barrier: Option<&iroha::data_model::nexus::PrivateSettlementPrepareBarrierV1>,
) -> Result<iroha::data_model::nexus::PrivateSettlementPhaseCertificateV1> {
    let payload = bundle.manifest.legs[leg_ordinal].payload_digest;
    let votes = committee
        .endpoints
        .iter()
        .map(|endpoint| match (phase, barrier) {
            (iroha::data_model::nexus::PrivateSettlementPhaseV1::Prepare, None) => sponsor
                .client()
                .request_private_settlement_prepare_vote_v1(
                    endpoint,
                    &bundle.manifest,
                    payload,
                    &committee.authority,
                )
                .map(|response| response.vote),
            (iroha::data_model::nexus::PrivateSettlementPhaseV1::Commit, Some(barrier)) => sponsor
                .client()
                .request_private_settlement_commit_vote_v1(
                    endpoint,
                    payload,
                    barrier,
                    &committee.authority,
                )
                .map(|response| response.vote),
            _ => Err(eyre!("fault phase/barrier combination is invalid")),
        })
        .collect::<Result<Vec<_>>>()?;
    aggregate_fault_phase_votes(
        &votes,
        [0, 1, 2],
        u8::try_from(leg_ordinal).expect("leg ordinal fits u8"),
    )
}

#[derive(Clone, Copy, Debug)]
enum FreshRouteFaultV1 {
    Loss {
        phase: PrivateSettlementRouteControlPhase,
        percentage: u8,
        trial_index: usize,
    },
    Hold {
        phase: PrivateSettlementRouteControlPhase,
        trial_index: usize,
    },
    RestartRecovery,
}

#[allow(clippy::too_many_arguments)]
fn run_fresh_route_fault_trial(
    request: &RealProcessFaultRequestV1,
    bundle_ordinal: usize,
    fault: FreshRouteFaultV1,
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    sponsor: &Client,
    routes: &[PrivateSettlementRouteV1],
    committees: &[CommitteeEndpoints],
    coordinator: &mut CoordinatorProcessV1,
) -> Result<(
    FaultTrialDraftV1,
    FaultStateSnapshotV1,
    Option<FaultPrepareQcNormalizationV1>,
    Option<Vec<RealProcessInventoryRowV1>>,
    u64,
)> {
    let mut bundle = prepare_fault_bundle(
        request,
        bundle_ordinal,
        sponsor,
        network,
        routes,
        committees,
    )?;
    let before = wait_for_converged_fault_state_snapshot(network, "before")?;
    let mut controls = Vec::new();
    let mut inventory = None;
    let mut observer = FaultContinuousObserverV1::start(
        network,
        &before,
        request.participants,
        &bundle.manifest.bundle_id,
        false,
    )?;

    match fault {
        FreshRouteFaultV1::Loss {
            phase: PrivateSettlementRouteControlPhase::RestrictedDa,
            percentage,
            ..
        } => {
            let (observed, nonfinalized) = exercise_route_loss(
                network,
                runtime,
                &mut observer,
                VALIDATORS_PER_LANE,
                PrivateSettlementRouteControlPhase::RestrictedDa,
                bundle.manifest.bundle_id,
                request.seed,
                percentage,
                || {
                    sponsor
                        .client()
                        .request_private_settlement_availability_share_v1(
                            &committees[0].endpoints[0],
                            &bundle.materials[0],
                        )
                        .map(|_| ())
                },
            )?;
            ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
            controls.extend(observed);
        }
        FreshRouteFaultV1::Hold {
            phase: PrivateSettlementRouteControlPhase::RestrictedDa,
            ..
        } => {
            let client = sponsor.clone();
            let endpoint = committees[0].endpoints[0].clone();
            let material = bundle.materials[0].clone();
            let (observed, nonfinalized) = exercise_route_hold(
                network,
                runtime,
                &mut observer,
                VALIDATORS_PER_LANE,
                PrivateSettlementRouteControlPhase::RestrictedDa,
                bundle.manifest.bundle_id,
                request.seed,
                move || {
                    client
                        .client()
                        .request_private_settlement_availability_share_v1(&endpoint, &material)
                        .map(|_| ())
                },
            )?;
            ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
            controls.extend(observed);
        }
        _ => {}
    }
    certify_and_upload_fault_bundle(sponsor, &mut bundle, committees)?;
    audit_fault_bundle(sponsor, &bundle, committees)?;

    match fault {
        FreshRouteFaultV1::Loss {
            phase: PrivateSettlementRouteControlPhase::Prepare,
            percentage,
            ..
        } => {
            let (observed, nonfinalized) = exercise_route_loss(
                network,
                runtime,
                &mut observer,
                VALIDATORS_PER_LANE,
                PrivateSettlementRouteControlPhase::Prepare,
                bundle.manifest.bundle_id,
                request.seed,
                percentage,
                || {
                    sponsor
                        .client()
                        .request_private_settlement_prepare_vote_v1(
                            &committees[0].endpoints[0],
                            &bundle.manifest,
                            bundle.manifest.legs[0].payload_digest,
                            &committees[0].authority,
                        )
                        .map(|_| ())
                },
            )?;
            ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
            controls.extend(observed);
        }
        FreshRouteFaultV1::Hold {
            phase: PrivateSettlementRouteControlPhase::Prepare,
            ..
        } => {
            let client = sponsor.clone();
            let endpoint = committees[0].endpoints[0].clone();
            let manifest = bundle.manifest.clone();
            let authority = committees[0].authority.clone();
            let payload = bundle.manifest.legs[0].payload_digest;
            let (observed, nonfinalized) = exercise_route_hold(
                network,
                runtime,
                &mut observer,
                VALIDATORS_PER_LANE,
                PrivateSettlementRouteControlPhase::Prepare,
                bundle.manifest.bundle_id,
                request.seed,
                move || {
                    client
                        .client()
                        .request_private_settlement_prepare_vote_v1(
                            &endpoint, &manifest, payload, &authority,
                        )
                        .map(|_| ())
                },
            )?;
            ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
            controls.extend(observed);
        }
        _ => {}
    }
    let endpoint_matrix = fault_endpoint_matrix(committees);
    let (barrier, normalization) = if matches!(fault, FreshRouteFaultV1::RestartRecovery) {
        let (barrier, normalization) =
            prepare_fault_bundle_with_normalization(sponsor, &bundle, committees)?;
        (barrier, Some(normalization))
    } else {
        (
            sponsor.client().prepare_private_settlement_bundle_v1(
                &endpoint_matrix,
                &bundle.manifest,
                &bundle.authorities,
                &bundle.deltas,
            )?,
            None,
        )
    };
    let fee_before_registration = sponsor_nexus_fee_balance(sponsor)?;
    submit_prepare_registration_and_wait_v1(sponsor, &barrier)?;
    let fee_after_registration = sponsor_nexus_fee_balance(sponsor)?;
    ensure_exact_private_settlement_carrier_fee(
        &fee_before_registration,
        &fee_after_registration,
        "fault-trial Prepare registration",
    )?;

    match fault {
        FreshRouteFaultV1::Loss {
            phase: PrivateSettlementRouteControlPhase::Commit,
            percentage,
            ..
        } => {
            let (observed, nonfinalized) = exercise_route_loss(
                network,
                runtime,
                &mut observer,
                VALIDATORS_PER_LANE,
                PrivateSettlementRouteControlPhase::Commit,
                bundle.manifest.bundle_id,
                request.seed,
                percentage,
                || {
                    sponsor
                        .client()
                        .request_private_settlement_commit_vote_v1(
                            &committees[0].endpoints[0],
                            bundle.manifest.legs[0].payload_digest,
                            &barrier,
                            &committees[0].authority,
                        )
                        .map(|_| ())
                },
            )?;
            ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
            controls.extend(observed);
        }
        FreshRouteFaultV1::Hold {
            phase: PrivateSettlementRouteControlPhase::Commit,
            ..
        } => {
            let client = sponsor.clone();
            let endpoint = committees[0].endpoints[0].clone();
            let hold_barrier = barrier.clone();
            let authority = committees[0].authority.clone();
            let payload = bundle.manifest.legs[0].payload_digest;
            let (observed, nonfinalized) = exercise_route_hold(
                network,
                runtime,
                &mut observer,
                VALIDATORS_PER_LANE,
                PrivateSettlementRouteControlPhase::Commit,
                bundle.manifest.bundle_id,
                request.seed,
                move || {
                    client
                        .client()
                        .request_private_settlement_commit_vote_v1(
                            &endpoint,
                            payload,
                            &hold_barrier,
                            &authority,
                        )
                        .map(|_| ())
                },
            )?;
            ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
            controls.extend(observed);
        }
        _ => {}
    }
    let unavailable = if matches!(fault, FreshRouteFaultV1::RestartRecovery) {
        let expected_unavailable = (0..request.participants)
            .map(|dataspace_ordinal| (dataspace_ordinal + 1) * VALIDATORS_PER_LANE)
            .collect::<Vec<_>>();
        observer.begin_phase("committee_unavailable", &expected_unavailable, false)?;
        let stopped = expected_unavailable
            .iter()
            .copied()
            .enumerate()
            .map(|(dataspace_ordinal, peer_index)| {
                stop_peer_for_quorum_progress(
                    network,
                    runtime,
                    peer_index,
                    u64::try_from(dataspace_ordinal + 1).expect("participant ordinal fits u64"),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let stop_bindings = stopped
            .iter()
            .map(|stopped| format!("command:{}", sha256_hex(&stopped.command_bytes)))
            .collect::<Vec<_>>();
        observer.checkpoint_active_phase(&stop_bindings)?;
        observer.complete_phase()?;
        stopped
    } else {
        Vec::new()
    };
    if !unavailable.is_empty() {
        let recovered_while_unavailable = sponsor
            .client()
            .recover_or_prepare_private_settlement_bundle_v1(
                &endpoint_matrix,
                &bundle.manifest,
                &bundle.authorities,
                &bundle.deltas,
            )?;
        ensure!(
            recovered_while_unavailable.prepared_bundle_digest == barrier.prepared_bundle_digest,
            "Prepare recovery changed the complete barrier with one validator unavailable per committee"
        );
    }
    let commits = sponsor
        .client()
        .commit_private_settlement_bundle_v1(&endpoint_matrix, &barrier)?;
    if !unavailable.is_empty() {
        ensure!(
            commits.len() == request.participants
                && commits.iter().all(|certificate| {
                    certificate.signers_bitmap.count_ones() == 3
                        && certificate.signers_bitmap & 1 == 0
                }),
            "Commit did not make exact 3-of-4 progress with committee seat 0 unavailable"
        );
        let recovery_controls = unavailable
            .into_iter()
            .map(|stopped| restart_quorum_progress_peer(network, runtime, stopped))
            .collect::<Result<Vec<_>>>()?;
        observer.begin_phase("committee_recovery", &[], false)?;
        let recovery_bindings = recovery_controls
            .iter()
            .map(fault_checkpoint_acknowledgement_binding)
            .collect::<Vec<_>>();
        observer.checkpoint_active_phase(&recovery_bindings)?;
        observer.complete_phase()?;
        controls.extend(recovery_controls);
    }
    let fee_before_finalization = sponsor_nexus_fee_balance(sponsor)?;
    let (nonfinalized, receipt) = if matches!(fault, FreshRouteFaultV1::RestartRecovery) {
        controls.push(restart_peer_with_evidence(
            network,
            runtime,
            &mut observer,
            0,
            u64::try_from(request.participants + 1)?,
            "global_restart",
        )?);
        let post_restart = capture_fault_state_snapshot(network, "post-restart")?;
        ensure_fault_ledger_unchanged_before_finality(&before, &post_restart)?;
        let coordinator_command = CoordinatorCommandV1 {
            format_version: 1,
            revision: 0,
            operation: "recover_prepare_commit".to_owned(),
            committee_endpoints: endpoint_matrix
                .iter()
                .map(|endpoints| endpoints.iter().map(ToString::to_string).collect())
                .collect(),
            manifest: Some(bundle.manifest.clone()),
            authority_catalog: bundle.authorities.clone(),
            deltas: bundle.deltas.clone(),
            barrier: None,
        };
        let (before_pid, after_pid, command, acknowledgement, recovered) =
            coordinator.restart_with(coordinator_command)?;
        let recovered_barrier = recovered
            .barrier
            .ok_or_else(|| eyre!("coordinator restart did not recover Prepare"))?;
        ensure!(
            recovered_barrier.prepared_bundle_digest == barrier.prepared_bundle_digest
                && recovered.commit_certificates.len() == request.participants,
            "coordinator restart did not recover the exact complete bundle"
        );
        verify_invalid_leg_carrier_is_state_byte_identical(
            sponsor,
            network,
            &bundle,
            &recovered_barrier,
            &recovered.commit_certificates,
        )?;
        controls.push(fault_control_occurrence(
            "coordinator_restart",
            None,
            command,
            acknowledgement,
            Some(before_pid),
            Some(after_pid),
        )?);
        let submit = build_fault_carrier_submit(
            sponsor,
            &bundle,
            &recovered_barrier,
            &recovered.commit_certificates,
        )?;
        let replay = submit.clone();
        let nonfinalized = capture_fault_state_snapshot(network, "nonfinalized")?;
        ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
        observer.begin_phase("post_recovery", &[], true)?;
        sponsor
            .client()
            .submit_private_settlement_bundle_v1(&submit)?;
        let receipt = wait_for_identical_receipt(network, bundle.manifest.bundle_id)?;
        observe_idempotent_finalized_retry(sponsor, network, &bundle.manifest, &replay, &receipt)?;
        inventory = Some(collect_process_inventory(
            network,
            runtime,
            TopologyShape::new(request.participants),
            &request.commit,
            coordinator,
        )?);
        (nonfinalized, receipt)
    } else {
        let nonfinalized = capture_fault_state_snapshot(network, "nonfinalized")?;
        let receipt = finalize_fault_bundle(sponsor, network, &bundle, barrier, commits)?;
        (nonfinalized, receipt)
    };
    let fee_after_finalization = sponsor_nexus_fee_balance(sponsor)?;
    ensure_exact_private_settlement_carrier_fee(
        &fee_before_finalization,
        &fee_after_finalization,
        "fault-trial financial finalization",
    )?;
    ensure_fault_ledger_unchanged_before_finality(&before, &nonfinalized)?;
    ensure_fault_prepare_lock_planes_full_v1(&before, &nonfinalized, request.participants)?;
    let after = wait_for_converged_fault_state_snapshot(network, "after")?;
    ensure_fault_state_finalized_once(&before, &after, request.participants)?;
    observer.complete_phase()?;
    let continuous_observations = observer.finish(&after)?;
    let signed_rs16 =
        verify_signed_rs16_finality(network, runtime, receipt.finalized_height)?.observations;
    let (collection, trial_index) = match fault {
        FreshRouteFaultV1::Loss { trial_index, .. } => ("loss_trials", trial_index),
        FreshRouteFaultV1::Hold { trial_index, .. } => ("phase_cut_partitions", trial_index),
        FreshRouteFaultV1::RestartRecovery => ("phase_cut_partitions", 3),
    };
    Ok((
        FaultTrialDraftV1 {
            collection,
            trial_index,
            bundle_id: hex::encode(bundle.manifest.bundle_id.as_ref()),
            expected_after_state: "finalized",
            controls,
            before,
            nonfinalized,
            continuous_observations,
        },
        after,
        normalization,
        inventory,
        signed_rs16,
    ))
}

fn write_fault_jsonl<T: norito::json::JsonSerialize>(path: &Path, rows: &[T]) -> Result<Vec<u8>> {
    ensure!(!rows.is_empty(), "fault evidence JSONL is empty");
    let mut bytes = Vec::new();
    for row in rows {
        let encoded = canonical_harness_json_bytes(row)?;
        ensure!(
            !encoded.contains(&b'\n') && !encoded.contains(&b'\r'),
            "fault evidence record is not one canonical JSON line"
        );
        bytes.extend_from_slice(&encoded);
        bytes.push(b'\n');
    }
    ensure!(!path.exists(), "fault evidence path already exists");
    write_owner_only_atomic(path, &bytes)?;
    Ok(bytes)
}

fn fault_evidence_root() -> Result<PathBuf> {
    let root = PathBuf::from(
        std::env::var(HARNESS_EVIDENCE_DIR_ENV).wrap_err("missing fault evidence directory")?,
    );
    let canonical = root
        .canonicalize()
        .wrap_err("resolve fault evidence directory")?;
    ensure!(
        canonical == root,
        "fault evidence directory is not canonical"
    );
    let metadata = fs::symlink_metadata(&root)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == 0o700
            && fs::read_dir(&root)?.next().is_none(),
        "fault evidence directory is unsafe or non-empty"
    );
    Ok(root)
}

fn materialize_fault_campaign_payload(
    request: &RealProcessFaultRequestV1,
    trials: Vec<(FaultTrialDraftV1, FaultStateSnapshotV1)>,
    normalization: &FaultPrepareQcNormalizationV1,
) -> Result<HarnessJsonValue> {
    ensure!(
        trials.len() == FAULT_CAMPAIGN_TRIALS,
        "fault campaign trial inventory is incomplete"
    );
    let mut control_rows = Vec::with_capacity(trials.len());
    let mut observation_rows = Vec::with_capacity(trials.len());
    let mut bundle_ids = BTreeSet::new();
    for (draft, after) in &trials {
        ensure!(
            lowercase_digest(&draft.bundle_id, &[64]) && bundle_ids.insert(draft.bundle_id.clone()),
            "fault campaign reused or malformed a fresh bundle id"
        );
        ensure!(
            draft.continuous_observations.len() == (request.participants + 1) * VALIDATORS_PER_LANE
                && draft
                    .continuous_observations
                    .iter()
                    .enumerate()
                    .all(|(peer_index, summary)| summary.peer_index == peer_index),
            "fault continuous observer omitted or reordered validators"
        );
        let continuous_checks =
            draft
                .continuous_observations
                .iter()
                .try_fold(0_u64, |total, summary| {
                    total
                        .checked_add(summary.check_count)
                        .ok_or_else(|| eyre!("fault continuous-check trial total overflow"))
                })?;
        let record = fault_record_id(
            request.participants,
            request.seed,
            request.run,
            draft.collection,
            draft.trial_index,
        );
        control_rows.push(FaultControlRecordV1 {
            record: record.clone(),
            bundle_id: draft.bundle_id.clone(),
            participants: request.participants,
            seed: request.seed,
            run: request.run,
            collection: draft.collection.to_owned(),
            trial_index: draft.trial_index,
            controls: draft.controls.clone(),
        });
        observation_rows.push(FaultObservationRecordV1 {
            record,
            bundle_id: draft.bundle_id.clone(),
            participants: request.participants,
            seed: request.seed,
            run: request.run,
            collection: draft.collection.to_owned(),
            trial_index: draft.trial_index,
            expected_after_state: draft.expected_after_state.to_owned(),
            continuous_checks,
            continuous_observations: draft.continuous_observations.clone(),
            partial_visibility_observed: false,
            partial_spendable_observations: 0,
            snapshots: vec![
                draft.before.clone(),
                draft.nonfinalized.clone(),
                after.clone(),
            ],
        });
    }
    control_rows.sort_by_key(|row| {
        let collection = match row.collection.as_str() {
            "loss_trials" => 0,
            "phase_cut_partitions" => 1,
            "crash_recoveries" => 2,
            _ => 3,
        };
        (collection, row.trial_index)
    });
    observation_rows.sort_by_key(|row| {
        let collection = match row.collection.as_str() {
            "loss_trials" => 0,
            "phase_cut_partitions" => 1,
            "crash_recoveries" => 2,
            _ => 3,
        };
        (collection, row.trial_index)
    });
    let evidence_root = fault_evidence_root()?;
    let control_bytes = write_fault_jsonl(
        &evidence_root.join(FAULT_CONTROL_EVIDENCE_FILE),
        &control_rows,
    )?;
    let observation_bytes = write_fault_jsonl(
        &evidence_root.join(FAULT_OBSERVATION_EVIDENCE_FILE),
        &observation_rows,
    )?;
    let control_sha = sha256_hex(&control_bytes);
    let observation_sha = sha256_hex(&observation_bytes);
    let total_checks = observation_rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.continuous_checks)
            .ok_or_else(|| eyre!("fault continuous-check total overflow"))
    })?;

    let make_reference = |collection: &str, trial_index: usize| {
        fault_record_id(
            request.participants,
            request.seed,
            request.run,
            collection,
            trial_index,
        )
    };
    let loss_trials = ["restricted_da", "prepare", "commit"]
        .into_iter()
        .flat_map(|phase| {
            [5_u8, 10, 20]
                .into_iter()
                .map(move |percentage| (phase, percentage))
        })
        .enumerate()
        .map(|(index, (phase, percentage))| {
            norito::json!({
                "phase": phase,
                "loss_percent": percentage,
                "control_acknowledged": true,
                "healed": true,
                "converged": true,
                "partial_visibility_observed": false,
                "control_transcript_sha256": (control_sha.clone()),
                "control_transcript_record": (make_reference("loss_trials", index)),
                "observation_capture_sha256": (observation_sha.clone()),
                "observation_capture_record": (make_reference("loss_trials", index)),
            })
        })
        .collect::<Vec<_>>();
    let phase_cut_partitions = [
        "da_before_availability_qc",
        "prepare_before_complete_barrier",
        "commit_before_complete_barrier",
        "restart_before_global_finality",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, cut)| {
        norito::json!({
            "cut": cut,
            "control_acknowledged": true,
            "delayed_delivery": (index < 3),
            "healed": true,
            "converged": true,
            "partial_visibility_observed": false,
            "control_transcript_sha256": (control_sha.clone()),
            "control_transcript_record": (make_reference("phase_cut_partitions", index)),
            "observation_capture_sha256": (observation_sha.clone()),
            "observation_capture_record": (make_reference("phase_cut_partitions", index)),
        })
    })
    .collect::<Vec<_>>();
    let crash_recoveries = PRIVATE_SETTLEMENT_CRASH_BOUNDARIES
        .iter()
        .copied()
        .enumerate()
        .map(|(index, boundary)| {
            norito::json!({
                "boundary": boundary,
                "process_restarted": true,
                "durable_state_reconciled": true,
                "converged": true,
                "partial_visibility_observed": false,
                "control_transcript_sha256": (control_sha.clone()),
                "control_transcript_record": (make_reference("crash_recoveries", index)),
                "observation_capture_sha256": (observation_sha.clone()),
                "observation_capture_record": (make_reference("crash_recoveries", index)),
            })
        })
        .collect::<Vec<_>>();
    Ok(norito::json!({
        "committee_validator_restarts": ((0..request.participants).collect::<Vec<_>>()),
        "maximum_simultaneously_unavailable_per_committee": 1,
        "quorum_progress_with_one_unavailable": true,
        "coordinator_restarted": true,
        "global_node_restarted": true,
        "prepare_qc_normalization": (norito::json::to_value(normalization)?),
        "loss_trials": loss_trials,
        "phase_cut_partitions": phase_cut_partitions,
        "crash_recoveries": crash_recoveries,
        "atomicity": {
            "continuous_checks": total_checks,
            "partial_visible_observations": 0,
            "partial_spendable_observations": 0,
            "aborted_private_state_changes": 0,
            "successful_leg_applications": (request.participants),
            "each_leg_applied_exactly_once": true,
            "invalid_leg_state_byte_identical": true,
            "exact_retry_idempotent": true,
        },
        "all_nodes_converged": true,
    }))
}

fn run_real_process_fault_campaign(
    request: RealProcessFaultRequestV1,
    request_sha: String,
) -> Result<RealProcessFaultResultV1> {
    let shape = TopologyShape::new(request.participants);
    shape.validate()?;
    let context = format!(
        "atomic_private_settlement_fault_n{}_s{}_r{}",
        request.participants, request.seed, request.run
    );
    let builder = localnet_builder(shape)
        .with_base_seed(format!(
            "atomic-private-settlement-fault-v1-n{}-seed-{}-run-{}",
            request.participants, request.seed, request.run
        ))
        .with_private_settlement_route_control();
    let started = sandbox::start_network_blocking_or_skip(builder, &context)?;
    let Some((network, runtime)) = sandbox::enforce_network_start_requirement(started, &context)?
    else {
        return Err(eyre!("real-process fault network was skipped"));
    };
    verify_controller_readiness(&network, &runtime)?;
    let sponsor = network.client();
    prepare_participant_assets(&network, shape)?;
    require_genesis_private_note_active(&sponsor)?;
    let routes = routes_from_network(&network, shape)?;
    let committees = committees_from_network(&network, shape, &routes)?;
    ensure!(
        routes.len() == request.participants && committees.len() == request.participants,
        "fault campaign topology material is incomplete"
    );
    let mut coordinator = CoordinatorProcessV1::start(&sponsor)?;
    let mut trials = Vec::with_capacity(FAULT_CAMPAIGN_TRIALS);
    let mut bundle_ordinal = 0_usize;
    let mut signed_rs16_da_observations = 0_u64;

    let route_phases = [
        PrivateSettlementRouteControlPhase::RestrictedDa,
        PrivateSettlementRouteControlPhase::Prepare,
        PrivateSettlementRouteControlPhase::Commit,
    ];
    for (phase_ordinal, phase) in route_phases.into_iter().enumerate() {
        for (percentage_ordinal, percentage) in [5_u8, 10, 20].into_iter().enumerate() {
            let trial_index = phase_ordinal * 3 + percentage_ordinal;
            let (draft, after, observed_normalization, observed_inventory, signed_rs16) =
                run_fresh_route_fault_trial(
                    &request,
                    bundle_ordinal,
                    FreshRouteFaultV1::Loss {
                        phase,
                        percentage,
                        trial_index,
                    },
                    &network,
                    &runtime,
                    &sponsor,
                    &routes,
                    &committees,
                    &mut coordinator,
                )?;
            ensure!(
                observed_normalization.is_none() && observed_inventory.is_none(),
                "ordinary loss trial unexpectedly produced carrier-only evidence"
            );
            signed_rs16_da_observations = signed_rs16_da_observations.max(signed_rs16);
            trials.push((draft, after));
            bundle_ordinal += 1;
        }
    }
    for (trial_index, phase) in route_phases.into_iter().enumerate() {
        let (draft, after, observed_normalization, observed_inventory, signed_rs16) =
            run_fresh_route_fault_trial(
                &request,
                bundle_ordinal,
                FreshRouteFaultV1::Hold { phase, trial_index },
                &network,
                &runtime,
                &sponsor,
                &routes,
                &committees,
                &mut coordinator,
            )?;
        ensure!(
            observed_normalization.is_none() && observed_inventory.is_none(),
            "ordinary phase cut unexpectedly produced carrier-only evidence"
        );
        signed_rs16_da_observations = signed_rs16_da_observations.max(signed_rs16);
        trials.push((draft, after));
        bundle_ordinal += 1;
    }
    let (draft, after, observed_normalization, observed_inventory, signed_rs16) =
        run_fresh_route_fault_trial(
            &request,
            bundle_ordinal,
            FreshRouteFaultV1::RestartRecovery,
            &network,
            &runtime,
            &sponsor,
            &routes,
            &committees,
            &mut coordinator,
        )?;
    let normalization = observed_normalization
        .ok_or_else(|| eyre!("carrier trial did not produce QC normalization evidence"))?;
    ensure!(
        observed_inventory.is_some(),
        "carrier trial did not capture a live post-restart inventory"
    );
    signed_rs16_da_observations = signed_rs16_da_observations.max(signed_rs16);
    trials.push((draft, after));
    bundle_ordinal += 1;

    ensure!(
        bundle_ordinal == FAULT_CAMPAIGN_TRIALS
            && signed_rs16_da_observations >= request.minimum_signed_rs16_da_observations,
        "fault campaign did not complete its fresh-bundle/RS16 matrix"
    );
    let process_inventory =
        collect_process_inventory(&network, &runtime, shape, &request.commit, &coordinator)?;
    let payload = materialize_fault_campaign_payload(&request, trials, &normalization)?;
    Ok(RealProcessFaultResultV1 {
        version: 1,
        protocol: "AtomicPrivateSettlementV1".to_owned(),
        request_id: request.request_id,
        invocation_nonce: request.invocation_nonce,
        request_sha256: request_sha,
        commit: request.commit,
        participants: request.participants,
        mandatory_signed_rs16_da_rbc: true,
        signed_rs16_da_observations,
        authenticated_private_settlement_route_control: true,
        process_inventory,
        payload,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransparentControlBalanceExpectation {
    asset_id: AssetId,
    amount: Quantity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransparentControlSnapshotState {
    Initial,
    Finalized,
}

fn classify_transparent_control_values(
    observed: &[Quantity],
    initial: &[TransparentControlBalanceExpectation],
    finalized: &[TransparentControlBalanceExpectation],
) -> Result<TransparentControlSnapshotState> {
    ensure!(
        observed.len() == initial.len()
            && initial.len() == finalized.len()
            && initial
                .iter()
                .zip(finalized)
                .all(|(before, after)| { before.asset_id == after.asset_id }),
        "transparent-control atomicity vectors are not aligned"
    );
    let matches = |expected: &[TransparentControlBalanceExpectation]| {
        observed
            .iter()
            .zip(expected)
            .all(|(value, expectation)| *value == expectation.amount)
    };
    if matches(initial) {
        Ok(TransparentControlSnapshotState::Initial)
    } else if matches(finalized) {
        Ok(TransparentControlSnapshotState::Finalized)
    } else {
        Err(eyre!(
            "transparent-control observer detected a mixed pre/post balance vector"
        ))
    }
}

fn observe_transparent_control_atomicity(
    client: &Client,
    initial: &[TransparentControlBalanceExpectation],
    finalized: &[TransparentControlBalanceExpectation],
) -> Result<TransparentControlSnapshotState> {
    let ids = initial
        .iter()
        .map(|row| row.asset_id.clone())
        .collect::<Vec<_>>();
    let observed = coherent_control_balances(client, &ids)?
        .into_iter()
        .map(|row| row.amount)
        .collect::<Vec<_>>();
    classify_transparent_control_values(&observed, initial, finalized)
}

struct TransparentControlAtomicityObserver {
    stop: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    observations: Arc<Vec<AtomicU64>>,
    failure: Arc<Mutex<Option<String>>>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl TransparentControlAtomicityObserver {
    fn start(
        clients: Vec<Client>,
        initial: Vec<TransparentControlBalanceExpectation>,
        finalized: Vec<TransparentControlBalanceExpectation>,
    ) -> Result<Self> {
        ensure!(!clients.is_empty(), "atomicity observer has no clients");
        for client in &clients {
            ensure!(
                observe_transparent_control_atomicity(client, &initial, &finalized)?
                    == TransparentControlSnapshotState::Initial,
                "transparent-control observer did not start from the initial state"
            );
        }
        let observations = Arc::new(
            (0..clients.len())
                .map(|_| AtomicU64::new(1))
                .collect::<Vec<_>>(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let mut client_groups = Vec::<Vec<(usize, Client)>>::new();
        for (index, client) in clients.into_iter().enumerate() {
            let group = index / VALIDATORS_PER_LANE;
            if client_groups.len() == group {
                client_groups.push(Vec::with_capacity(VALIDATORS_PER_LANE));
            }
            client_groups[group].push((index, client));
        }
        let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(client_groups.len());
        for (group, clients) in client_groups.into_iter().enumerate() {
            let thread_stop = Arc::clone(&stop);
            let thread_active = Arc::clone(&active);
            let thread_observations = Arc::clone(&observations);
            let thread_failure = Arc::clone(&failure);
            let thread_initial = initial.clone();
            let thread_finalized = finalized.clone();
            let handle = match thread::Builder::new()
                .name(format!("aps-transparent-atomicity-observer-{group}"))
                .spawn(move || {
                    while !thread_stop.load(Ordering::Relaxed) {
                        if !thread_active.load(Ordering::Relaxed) {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        for (index, client) in &clients {
                            if let Err(error) = observe_transparent_control_atomicity(
                                client,
                                &thread_initial,
                                &thread_finalized,
                            ) {
                                if let Ok(mut failure) = thread_failure.lock() {
                                    if failure.is_none() {
                                        *failure = Some(format!("observer#{index}: {error}"));
                                    }
                                }
                                thread_stop.store(true, Ordering::Relaxed);
                                return;
                            }
                            thread_observations[*index].fetch_add(1, Ordering::Relaxed);
                        }
                        thread::sleep(Duration::from_millis(25));
                    }
                }) {
                Ok(handle) => handle,
                Err(error) => {
                    stop.store(true, Ordering::Relaxed);
                    for handle in handles.drain(..) {
                        let _ = handle.join();
                    }
                    return Err(error.into());
                }
            };
            handles.push(handle);
        }
        Ok(Self {
            stop,
            active,
            observations,
            failure,
            handles,
        })
    }

    fn begin(&self) -> Result<()> {
        self.active
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .map_err(|_| eyre!("transparent-control atomicity observer started twice"))?;
        Ok(())
    }

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        let mut panicked = false;
        for handle in self.handles.drain(..) {
            panicked |= handle.join().is_err();
        }
        ensure!(
            !panicked,
            "one or more transparent-control atomicity observers panicked"
        );
        Ok(())
    }

    fn finish(mut self, minimum_observations_per_validator: u64) -> Result<u64> {
        self.stop_and_join()?;
        if let Some(failure) = self
            .failure
            .lock()
            .map_err(|_| eyre!("transparent-control atomicity observer lock was poisoned"))?
            .take()
        {
            return Err(eyre!(failure));
        }
        let per_validator = self
            .observations
            .iter()
            .map(|observations| observations.load(Ordering::Relaxed))
            .collect::<Vec<_>>();
        ensure!(
            per_validator
                .iter()
                .all(|observations| *observations >= minimum_observations_per_validator),
            "transparent-control atomicity observer missed one or more validators: {per_validator:?}"
        );
        per_validator.iter().try_fold(0_u64, |total, observations| {
            total
                .checked_add(*observations)
                .ok_or_else(|| eyre!("atomicity observation total overflow"))
        })
    }
}

impl Drop for TransparentControlAtomicityObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

fn wait_for_transparent_control_balances(
    network: &Network,
    shape: TopologyShape,
    expectations: &[TransparentControlBalanceExpectation],
    context: &str,
) -> Result<()> {
    let started = Instant::now();
    let ids = expectations
        .iter()
        .map(|row| row.asset_id.clone())
        .collect::<Vec<_>>();
    ensure!(
        network.all_peers().count() == shape.process_count(),
        "balance check omits a validator"
    );
    while started.elapsed() <= FINALITY_TIMEOUT {
        let mut complete = 0;
        for peer in network.all_peers() {
            if let Ok(observed) = coherent_control_balances(&peer.client(), &ids) {
                if observed == expectations {
                    complete += 1;
                }
            }
        }
        if complete == shape.process_count() {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::TransparentBalances,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err(format!("{context}: exact balances did not converge")))
}

/// Exact original native carrier, independently verified from the configured signed genesis.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CertifiedSettlement {
    block_header: BlockHeader,
    block_wire: Vec<u8>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
}

fn authenticated_native_history(
    network: &Network,
    client: &Client,
) -> Result<Vec<iroha_core::sumeragi::certified_chain::CertifiedBlock>> {
    let started = Instant::now();
    let deadline = started + FINALITY_TIMEOUT;
    let client = client.client().with_request_deadline(deadline);
    let mut captured_tip = None;
    let result = (|| {
        // The advertised height bounds retrieval only; every original carrier is
        // independently authenticated below against the configured signed genesis.
        let height = client.get_privacy_capabilities()?.committed_height;
        captured_tip = Some(height);
        let root_scope = iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
            .sumeragi_context
            .root_scope;
        certified_native_history_from_proofs(
            &network.genesis().0,
            &network.chain_id(),
            network.network_id(),
            height,
            deadline,
            |at| Ok(client.get_sumeragi_finality_proof(at, root_scope)?),
        )
    })();
    if SmokeDiagnosticScopeV1::capture().is_some() {
        // A complete prefix includes genesis; a rejected prefix qualifies no blocks.
        let block_count = result.as_ref().map_or(0, |blocks| blocks.len() + 1);
        let _ = write_native_history_diagnostic(
            &mut std::io::stderr().lock(),
            captured_tip,
            block_count,
            started.elapsed().as_nanos(),
            result.is_ok(),
        );
    }
    result
}

/// Emit only bounded public counters; observation failure cannot change verification.
fn write_native_history_diagnostic(
    writer: &mut impl std::io::Write,
    captured_tip: Option<u64>,
    block_count: usize,
    elapsed_ns: u128,
    complete: bool,
) -> std::io::Result<()> {
    let tip = captured_tip.map_or_else(|| "none".to_owned(), |tip| tip.to_string());
    let record = format!(
        "APS_NATIVE_HISTORY_DIAGNOSTIC_V1 captured_tip={tip} block_count={block_count} elapsed_ns={elapsed_ns} complete={complete}\n"
    );
    writer.write_all(record.as_bytes())
}

#[test]
fn native_history_diagnostic_contains_only_public_counts() {
    let mut record = Vec::new();
    write_native_history_diagnostic(&mut record, Some(3), 3, 42, true).unwrap();
    assert_eq!(
        String::from_utf8(record).unwrap(),
        "APS_NATIVE_HISTORY_DIAGNOSTIC_V1 captured_tip=3 block_count=3 elapsed_ns=42 complete=true\n"
    );
    let mut record = Vec::new();
    write_native_history_diagnostic(&mut record, None, 0, 99, false).unwrap();
    assert_eq!(
        String::from_utf8(record).unwrap(),
        "APS_NATIVE_HISTORY_DIAGNOSTIC_V1 captured_tip=none block_count=0 elapsed_ns=99 complete=false\n"
    );
}

fn certified_native_history_from_proofs(
    trusted_genesis: &iroha::data_model::block::SignedBlock,
    chain_id: &iroha_model_base::chain::ChainId,
    network_id: iroha::data_model::NetworkId,
    height: u64,
    deadline: Instant,
    mut fetch: impl FnMut(
        NonZeroU64,
    ) -> Result<iroha::data_model::sumeragi_finality::SumeragiFinalityProof>,
) -> Result<Vec<iroha_core::sumeragi::certified_chain::CertifiedBlock>> {
    const MAX_NATIVE_HISTORY_HEIGHT: u64 = 4_096;
    ensure!(
        (1..=MAX_NATIVE_HISTORY_HEIGHT).contains(&height),
        "native history exceeds the bounded diagnostic corridor"
    );
    let root_scope = iroha_genesis::signed_genesis_consensus_metadata(trusted_genesis)?
        .sumeragi_context
        .root_scope;
    // All independently fetched carriers retain controls in this one bounded inspection pool.
    let budget = iroha_core::state::AllocationBudget::new(32 * 1024 * 1024);
    let mut verifier = None;
    let mut certified = Vec::new();
    for at in 1..=height {
        ensure!(
            Instant::now() < deadline,
            "native history verification deadline elapsed"
        );
        let proof = fetch(NonZeroU64::new(at).expect("history heights start at one"))?;
        ensure!(
            proof.height() == at,
            "native history proof differs from requested height"
        );
        proof.decode_checked(root_scope.into())?;
        let block = iroha::data_model::block::decode_framed_signed_block(&proof.block_wire)?;
        let block = iroha::data_model::block::SharedSignedBlock::try_new(block, &budget)
            .map_err(|(_, error)| error)?;
        if at == 1 {
            ensure!(
                block.canonical_resultless_proposal()?.encode_wire()?
                    == trusted_genesis
                        .canonical_resultless_proposal()?
                        .encode_wire()?,
                "peer substituted the independently signed genesis"
            );
            verifier = Some(iroha_core::sumeragi::certified_chain::CertifiedPrefix::new(
                chain_id, network_id, block,
            )?);
        } else {
            let step = verifier
                .as_mut()
                .expect("original genesis authenticated first")
                .push(block)?;
            certified.push(step.into_parts().0);
        }
    }
    ensure!(
        Instant::now() < deadline,
        "native history verification deadline elapsed"
    );
    Ok(certified)
}

#[test]
fn native_history_public_proofs_authenticate_exact_complete_prefix() {
    thread::Builder::new()
        .name("native-history-proof-control".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| {
            use iroha::data_model::Registrable;
            use iroha_core::{
                state::{StateReadOnly, World, WorldReadOnly},
                sumeragi::{
                    finality::build_proof,
                    test_chain::{CertifiedTestChain, TestChainConfig},
                },
            };
            let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
            let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 10_000)).unwrap();
            for ordinal in 0..2 {
                let transaction = chain.sign(
                    &ALICE_KEYPAIR,
                    [InstructionBox::from(Log::new(
                        Level::INFO,
                        format!("required history work {ordinal}"),
                    ))],
                    10_001 + ordinal,
                );
                assert_eq!(chain.commit(vec![transaction]), vec![true]);
            }
            let view = chain.state().view();
            assert!(
                view.world()
                    .account_permissions_iter(&ALICE_ID)
                    .unwrap()
                    .next()
                    .is_none(),
                "public consensus proofs require no broad or restricted observer grant"
            );
            let proofs = (1..=3)
                .map(|height| build_proof(&view, height).unwrap())
                .collect::<Vec<_>>();
            let chain_id = view.chain_id().clone();
            drop(view);
            let verify =
                |height, proofs: &[iroha::data_model::sumeragi_finality::SumeragiFinalityProof]| {
                    certified_native_history_from_proofs(
                        chain.genesis(),
                        &chain_id,
                        chain.network_id(),
                        height,
                        Instant::now() + Duration::from_secs(30),
                        |height| {
                            proofs
                                .get(height.get() as usize - 1)
                                .cloned()
                                .ok_or_else(|| eyre!("requested proof is missing"))
                        },
                    )
                };
            let certified = verify(3, &proofs).expect("all original proof carriers authenticate");
            assert_eq!(certified.len(), 2);
            for (ordinal, block) in certified.iter().enumerate() {
                assert_eq!(block.committed().height(), ordinal as u64 + 2);
                assert_eq!(
                    block.committed().block().encode_wire().unwrap(),
                    proofs[ordinal + 1].block_wire
                );
            }
            assert!(verify(0, &proofs).is_err());
            assert!(verify(4_097, &proofs).is_err());
            assert!(
                verify(3, &proofs[..2]).is_err(),
                "a prefix cannot omit the selected tip"
            );
            let mut changed = proofs.clone();
            changed.swap(1, 2);
            assert!(
                verify(3, &changed).is_err(),
                "height gaps or reordered responses reject"
            );
            let mut changed = proofs.clone();
            changed[1].block_wire[0] ^= 1;
            assert!(
                verify(3, &changed).is_err(),
                "altered canonical frame rejects"
            );
            let mut changed = proofs.clone();
            changed[1].committee.pop();
            assert!(
                verify(3, &changed).is_err(),
                "candidate committee substitution rejects"
            );
            let foreign =
                CertifiedTestChain::start(TestChainConfig::new(World::new(), 20_000)).unwrap();
            let mut changed = proofs.clone();
            changed[0] = build_proof(&foreign.state().view(), 1).unwrap();
            assert!(
                verify(3, &changed).is_err(),
                "even an authentic foreign genesis cannot choose the trust root"
            );
            assert!(
                certified_native_history_from_proofs(
                    chain.genesis(),
                    &chain_id,
                    chain.network_id(),
                    3,
                    Instant::now(),
                    |_| panic!("an expired request must not fetch")
                )
                .is_err()
            );
        })
        .expect("spawn bounded proof verifier control")
        .join()
        .expect("proof verifier control completes");
}

fn certified_settlement(
    network: &Network,
    client: &Client,
    source_id: [u8; 32],
) -> Result<Option<CertifiedSettlement>> {
    let mut receipt = None;
    for certified in authenticated_native_history(network, client)? {
        let committed = certified.committed();
        for (index, entrypoint) in committed.block().network_entrypoints().enumerate() {
            let TransactionEntrypoint::External(transaction) = entrypoint else {
                continue;
            };
            if transaction.hash().as_ref() != &source_id {
                continue;
            }
            ensure!(
                receipt.is_none(),
                "settlement appears more than once in certified history"
            );
            let (_, output) = committed
                .block()
                .network_output_at(u32::try_from(index)?)
                .ok_or_else(|| eyre!("certified settlement omitted its exact Network output"))?;
            ensure!(
                output.result.0.is_ok(),
                "certified settlement was rejected: {:?}",
                output.result
            );
            ensure!(
                certified
                    .commit_qc()
                    .is_some_and(|qc| qc.signers.count_ones() == 3),
                "settlement lacks exact three-of-four native quorum"
            );
            receipt = Some(CertifiedSettlement {
                block_header: committed.block().header(),
                block_wire: committed.block().encode_wire()?,
                entrypoint_hash: transaction.hash_as_entrypoint(),
            });
        }
    }
    Ok(receipt)
}

fn wait_for_identical_settlement_finality(
    network: &Network,
    source_id: [u8; 32],
) -> Result<CertifiedSettlement> {
    let started = Instant::now();
    let mut last_observed = Vec::new();
    while started.elapsed() <= FINALITY_TIMEOUT {
        let mut receipts = Vec::new();
        last_observed.clear();
        for (peer_index, peer) in network.all_peers().enumerate() {
            match certified_settlement(network, &peer.client(), source_id) {
                Ok(Some(receipt)) => receipts.push(receipt),
                Ok(None) => last_observed.push(format!("peer#{peer_index}:pending")),
                Err(error) => last_observed.push(format!("peer#{peer_index}:error={error}")),
            }
        }
        if receipts.len() == network.all_peers().count() {
            let expected = receipts.remove(0);
            ensure!(
                receipts.iter().all(|receipt| *receipt == expected),
                "validators differ on certified settlement carrier"
            );
            return Ok(expected);
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::SettlementFinality,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err(format!(
        "exact native settlement finality did not converge: {last_observed:?}"
    )))
}

fn canonical_carrier_header(
    client: &Client,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> Result<Option<BlockHeader>> {
    let matching = client
        .client()
        .query(FindBlocks)
        .execute_all()?
        .into_iter()
        .filter(|block| {
            block
                .network_input_hashes()
                .any(|observed| observed == entrypoint_hash)
        })
        .map(|block| block.header())
        .collect::<Vec<_>>();
    ensure!(
        matching.len() <= 1,
        "one transaction entrypoint occurs in multiple canonical blocks"
    );
    Ok(matching.into_iter().next())
}

fn wait_for_identical_canonical_carrier(
    network: &Network,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> Result<BlockHeader> {
    let started = Instant::now();
    let mut last_observed = Vec::new();
    while started.elapsed() <= FINALITY_TIMEOUT {
        let process_count = network.all_peers().count();
        let mut headers = Vec::with_capacity(process_count);
        last_observed.clear();
        for (peer_index, peer) in network.all_peers().enumerate() {
            match canonical_carrier_header(&peer.client(), entrypoint_hash) {
                Ok(Some(header)) => {
                    last_observed.push(format!(
                        "peer#{peer_index}:h{}:{}",
                        header.height().get(),
                        header.hash()
                    ));
                    headers.push(header);
                }
                Ok(None) => last_observed.push(format!("peer#{peer_index}:pending")),
                Err(error) => last_observed.push(format!("peer#{peer_index}:error={error}")),
            }
        }
        if headers.len() == process_count {
            let expected = headers[0].clone();
            ensure!(
                headers.iter().all(|header| *header == expected),
                "validators disagree on the canonical native settlement carrier"
            );
            return Ok(expected);
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::CanonicalCarrier,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err(format!(
        "timed out waiting for exact-once canonical carrier convergence: {last_observed:?}"
    )))
}

fn validate_transparent_native_receipt(
    receipt: &CertifiedSettlement,
    transaction: &SignedTransaction,
    _participants: usize,
) -> Result<()> {
    ensure!(
        receipt.entrypoint_hash == transaction.hash_as_entrypoint(),
        "native carrier does not bind the original settlement transaction"
    );
    let block = iroha_data_model::block::decode_framed_signed_block(&receipt.block_wire)?;
    ensure!(
        block.header() == receipt.block_header
            && block
                .external_transactions()
                .any(|candidate| candidate == transaction),
        "native certified carrier changed the exact original transaction bytes"
    );
    Ok(())
}

fn transparent_control_permissions(settlement: &SettleAtomic) -> Result<Vec<CanExecuteSettlement>> {
    settlement.validate().map_err(|error| eyre!(error))?;
    let intent_hash = settlement.intent_hash()?;
    Ok(settlement
        .movements
        .as_slice()
        .iter()
        .map(|movement| movement.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|debited_asset| CanExecuteSettlement {
            debited_asset,
            settlement_id: settlement.settlement_id.clone(),
            intent_hash,
        })
        .collect())
}

fn grant_transparent_control_consents(
    network: &Network,
    workload: &MatchedBenchmarkWorkloadV1,
    settlement: &SettleAtomic,
) -> Result<()> {
    let permissions = transparent_control_permissions(settlement)?;
    ensure!(
        permissions.len() == workload.payments.len(),
        "control consent source inventory differs"
    );
    for (ordinal, payment) in workload.payments.iter().enumerate() {
        let payer_key = workload.payer_key(ordinal)?;
        let payer = payment.source.account();
        let client = network.validators()[0].client_for(payer, payer_key.private_key().clone());
        let permission = permissions
            .iter()
            .find(|permission| permission.debited_asset == payment.source)
            .ok_or_else(|| eyre!("missing exact owner-issued consent"))?
            .clone();
        let account = client.account_client();
        let transaction = account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [InstructionBox::from(Grant::account_permission(
                    permission,
                    ALICE_ID.clone(),
                ))],
                bounded_nexus_fee(),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
            .wrap_err("build complete-intent payer consent")?;
        client
            .submit_transaction_and_wait(&transaction)
            .wrap_err_with(|| format!("commit matched payer consent {ordinal}"))?;
    }
    Ok(())
}

fn wait_for_transparent_control_consents(
    network: &Network,
    settlement: &SettleAtomic,
) -> Result<()> {
    let expected = transparent_control_permissions(settlement)?
        .into_iter()
        .map(Permission::from)
        .collect::<Vec<_>>();
    let started = Instant::now();
    while started.elapsed() <= FINALITY_TIMEOUT {
        let mut complete = 0;
        for peer in network.all_peers() {
            // Consents were granted TO the independent carrier sponsor. Query
            // that exact grantee on every validator, not each granting payer.
            if let Ok(permissions) = peer
                .client()
                .client()
                .query(FindPermissionsByAccountId::new(ALICE_ID.clone()))
                .execute_all()
            {
                if expected
                    .iter()
                    .all(|permission| permissions.contains(permission))
                {
                    complete += 1;
                }
            }
        }
        if complete == network.all_peers().count() {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(benchmark_deadline_error(
        BenchmarkDeadlineStageV1::TransparentConsents,
        FINALITY_TIMEOUT,
        started.elapsed(),
    )
    .wrap_err("matched complete-intent consents did not converge on the sponsor"))
}

fn build_transparent_control_carrier(
    client: &Client,
    settlement: &SettleAtomic,
) -> Result<SignedTransaction> {
    settlement.validate().map_err(|error| eyre!(error))?;
    let account = client.account_client();
    let transaction = account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(
            [InstructionBox::from(settlement.clone())],
            bounded_nexus_fee(),
            Metadata::default(),
        ))
        .and_then(|payload| account.sign_transaction(payload))
        .wrap_err("build the complete matched SettleAtomic carrier")?;
    ensure!(
        transaction.authority() == &*ALICE_ID
            && transaction.network_id() == Some(&settlement.network_id),
        "matched carrier context differs from its independent sponsor or network"
    );
    Ok(transaction)
}

#[test]
fn release_client_context_preserves_carrier_authority_and_preparation_errors() -> Result<()> {
    iroha_test_network::init_instruction_registry();
    let network_id = iroha::data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xD7)),
    );
    let key_pair = (*ALICE_KEYPAIR).clone();
    let table = Table::from_iter([
        (
            "chain".to_owned(),
            TomlValue::String("aps-local-signing-test".to_owned()),
        ),
        (
            "network_id".to_owned(),
            TomlValue::String(network_id.to_string()),
        ),
        (
            "torii_url".to_owned(),
            TomlValue::String("http://127.0.0.1:18080/".to_owned()),
        ),
        (
            "account".to_owned(),
            TomlValue::Table(Table::from_iter([
                ("chain_discriminant".to_owned(), TomlValue::Integer(753)),
                (
                    "public_key".to_owned(),
                    TomlValue::String(key_pair.public_key().to_string()),
                ),
                (
                    "private_key".to_owned(),
                    TomlValue::String(
                        iroha_crypto::ExposedPrivateKey(key_pair.private_key().clone()).to_string(),
                    ),
                ),
            ])),
        ),
    ]);
    let mut config: iroha::config::Config = iroha_config_base::read::ConfigReader::new()
        .with_toml_source(iroha_config_base::toml::TomlSource::inline(table))
        .read_and_complete::<iroha::config::UserConfig>()
        .expect("explicit local client configuration")
        .parse()
        .expect("valid local client configuration");
    config.transaction_add_nonce = false;
    let client = Client::new(config)?;
    let authority = ALICE_ID.clone();
    let settlement =
        MatchedBenchmarkWorkloadV1::new(2, 7, 0, false)?.settlement(network_id, 1000)?;
    let transaction = build_transparent_control_carrier(&client, &settlement)?;
    assert_eq!(transaction.network_id(), Some(&network_id));
    assert_eq!(transaction.authority(), &authority);
    assert_eq!(transaction.fee_payment_intent(), &bounded_nexus_fee());
    transaction
        .signature()
        .0
        .verify(key_pair.public_key(), transaction.payload())?;

    let exported = coordinator_client_config(&client)?;
    let (mut restored, _) = iroha::config::Config::load_bytes_with_musubi_publication(
        Path::new("aps-local-signing-test.toml"),
        &exported,
    )
    .map_err(|error| eyre!("reload explicit coordinator client context: {error:?}"))?;
    assert_eq!(restored.network_id, network_id);
    assert_eq!(restored.account, authority);
    assert_eq!(restored.key_pair, key_pair);
    assert_eq!(&restored.torii_api_url, client.account_client().endpoint());
    restored.transaction_ttl = Duration::ZERO;
    let invalid = Client::new(restored)?;
    assert!(build_transparent_control_carrier(&invalid, &settlement).is_err());
    Ok(())
}

fn fresh_transparent_control_replay(
    client: &Client,
    settlement: &SettleAtomic,
    original_entrypoint: HashOf<TransactionEntrypoint>,
) -> Result<SignedTransaction> {
    for _ in 0..100 {
        let candidate = build_transparent_control_carrier(client, settlement)?;
        if candidate.hash_as_entrypoint() != original_entrypoint {
            return Ok(candidate);
        }
        thread::sleep(Duration::from_millis(1));
    }
    Err(eyre!(
        "could not construct a fresh carrier for settlement-id replay testing"
    ))
}

fn run_real_process_transparent_control_benchmark(
    request: RealProcessBenchmarkRequestV1,
    request_sha: String,
    owner: &benchmark_session::RetainedBenchmarkNetwork,
    evidence_root: &Path,
    measurement_boundary: &mut impl FnMut(&'static str) -> Result<()>,
) -> Result<RealProcessBenchmarkResultV1> {
    let shape = TopologyShape::new(request.participants);
    shape.validate()?;
    let network: &Network = &owner.network;
    let workload = MatchedBenchmarkWorkloadV1::from_request(&request)?;
    let economic_vector_sha256 = workload.digest()?;
    publish_matched_workload(&request, &request_sha, network, &workload, evidence_root)?;
    let inventory = owner.inventory(&request.commit)?;
    let authority = network.client();
    // Both profiles use a retained session whose mandatory profile-activation
    // notice completed before these per-attempt consent and observation checks.
    let activated_height = owner.current_height()?;
    let expiry = activated_height
        .checked_add(1000)
        .ok_or_else(|| eyre!("expiry overflow"))?;
    let settlement = workload.settlement(network.network_id(), expiry)?;
    grant_transparent_control_consents(&network, &workload, &settlement)?;
    wait_for_transparent_control_consents(&network, &settlement)?;
    let initial_balances = read_matched_control_prestate(&network, shape, &workload)?;
    let final_balances = transparent_control_balance_expectations(&workload, &initial_balances)?;
    let atomicity_clients = network
        .all_peers()
        .map(NetworkPeer::client)
        .collect::<Vec<_>>();
    ensure!(
        atomicity_clients.len() == shape.process_count(),
        "transparent-control atomicity observer does not cover every process"
    );
    let atomicity_observer = TransparentControlAtomicityObserver::start(
        atomicity_clients.clone(),
        initial_balances.clone(),
        final_balances.clone(),
    )?;

    // Setup/prefunding is excluded; the storage baseline precedes measurement-ready.
    let storage_before = network_storage_bytes(&network)?;
    measurement_boundary("ready")?;
    let end_to_end_started = Instant::now();
    atomicity_observer.begin()?;
    let transaction = build_transparent_control_carrier(&authority, &settlement)?;
    let transaction_hash = transaction.hash();
    let entrypoint_hash = transaction.hash_as_entrypoint();
    let mut source_id = [0_u8; Hash::LENGTH];
    source_id.copy_from_slice(transaction_hash.as_ref());
    let finality_started = Instant::now();
    authority
        .submit_transaction_and_wait(&transaction)
        .wrap_err("submit production transparent native settlement carrier")?;
    let receipt = wait_for_identical_settlement_finality(&network, source_id)?;
    validate_transparent_native_receipt(&receipt, &transaction, request.participants)?;
    let carrier_started = Instant::now();
    let carrier = wait_for_identical_canonical_carrier(&network, entrypoint_hash)?;
    let business_receipt =
        wait_for_matched_business_receipt(&network, &settlement, &carrier, carrier_started)?;
    ensure!(
        receipt.block_header.height().get() == carrier.height().get(),
        "native settlement certificate authority context differs from its canonical carrier"
    );
    // Match the private endpoint: the expected authenticated receipts agree
    // on every peer. Finalized balances and observer completion remain
    // mandatory acceptance checks outside the measurement window.
    let global_finality = elapsed_ms(finality_started);
    let end_to_end = elapsed_ms(end_to_end_started);
    measurement_boundary("finished")?;
    // Storage is a sequential all-peer Kura file-size snapshot immediately
    // after the timing handshake, before replay or correctness postchecks.
    // It brackets boundary handshakes too; it is not isolated transaction bytes.
    let storage_after = network_storage_bytes(&network)?;
    wait_for_transparent_control_balances(
        &network,
        shape,
        &final_balances,
        "transparent-control finalized state",
    )?;
    for client in &atomicity_clients {
        ensure!(
            observe_transparent_control_atomicity(client, &initial_balances, &final_balances)?
                == TransparentControlSnapshotState::Finalized,
            "transparent-control atomicity observer did not reach the finalized state"
        );
    }
    let _atomicity_observations = atomicity_observer.finish(3)?;

    // The same complete N-payment-plus-reimbursement business intent must
    // not apply twice, even in a fresh transaction carrier.
    let replay = fresh_transparent_control_replay(&authority, &settlement, entrypoint_hash)?;
    let _replay_error = authority
        .submit_transaction_and_wait(&replay)
        .expect_err("a fresh carrier reusing the committed settlement id was accepted");
    wait_for_matched_replay_rejection(&network, &replay, &settlement)?;
    wait_for_transparent_control_balances(
        &network,
        shape,
        &final_balances,
        "transparent-control state after rejected replay",
    )?;
    let replay_business_receipt =
        wait_for_matched_business_receipt(&network, &settlement, &carrier, Instant::now())?;
    ensure!(
        replay_business_receipt == business_receipt,
        "business receipt changed after rejected replay"
    );
    ensure!(
        wait_for_identical_settlement_finality(&network, source_id)? == receipt
            && wait_for_identical_canonical_carrier(&network, entrypoint_hash)? == carrier,
        "replay changed the durable native settlement certificate or canonical carrier"
    );
    // Rejected results may be recorded in canonical history. Their exact
    // typed failure was authenticated on every peer above; no applied replay is accepted.

    let signed_rs16_da_observations = owner
        .verify_signed_rs16_finality(carrier.height().get())?
        .observations;
    ensure!(
        signed_rs16_da_observations >= request.minimum_signed_rs16_da_observations,
        "signed RS16 finality observations are incomplete"
    );
    // Measure the received canonical carrier, including its native certificate, and the
    // queried business receipt. The local comparison wrapper is not an additional wire receipt.
    let receipt_bytes = u64::try_from(
        receipt.block_wire.len() + norito::encode_canonical(&business_receipt)?.len(),
    )?;
    let storage_growth_bytes = storage_after
        .checked_sub(storage_before)
        .ok_or_else(|| eyre!("Kura storage shrank during benchmark"))?;
    ensure!(
        global_finality > 0.0 && end_to_end > 0.0 && receipt_bytes > 0,
        "one or more required genuine transparent-control measurements is empty"
    );
    Ok(RealProcessBenchmarkResultV1 {
        version: 1,
        protocol: "AtomicPrivateSettlementV1".to_owned(),
        request_id: request.request_id,
        invocation_nonce: request.invocation_nonce,
        request_sha256: request_sha,
        commit: request.commit,
        participants: request.participants,
        mandatory_signed_rs16_da_rbc: true,
        signed_rs16_da_observations,
        authenticated_private_settlement_route_control: true,
        process_inventory: inventory,
        payload: RealProcessBenchmarkResultPayloadV1 {
            economic_vector_sha256,
            primary_payment_count: request.participants,
            monetary_movement_count: request.participants + 1,
            stages_ms: norito::json!({
                "global_finality": global_finality,
                "end_to_end": end_to_end,
            }),
            // Transparent Native AMX carries no private proof bytes by construction.
            proof_bytes: 0,
            receipt_bytes,
            storage_growth_bytes,
            finalized_receipt_observed: true,
            successful_leg_applications: request.participants,
            each_leg_applied_exactly_once: true,
            // The full-topology observer rejected every mixed balance snapshot.
            partial_visible_observations: 0,
            partial_spendable_observations: 0,
        },
    })
}

fn verify_committee_proof_views(
    network: &Network,
    sponsor: &Client,
    manifest: &AtomicPrivateSettlementV1,
    prepared: &[PreparedLeg],
    committees: &[CommitteeEndpoints],
) -> Result<()> {
    for (ordinal, (leg, committee)) in prepared.iter().zip(committees).enumerate() {
        ensure!(
            committee.endpoints.len() == VALIDATORS_PER_LANE
                && committee.validator_keys.len() == VALIDATORS_PER_LANE,
            "committee proof matrix is incomplete"
        );
        for (endpoint, key) in committee.endpoints.iter().zip(&committee.validator_keys) {
            let peer = network
                .all_peers()
                .map(|peer| Ok((Url::parse(&peer.torii_url())?, peer)))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .find_map(|(url, peer)| (url == *endpoint).then_some(peer))
                .ok_or_else(|| eyre!("committee proof endpoint is absent from the network"))?;
            // Construct a fresh endpoint-bound context; cloned clients share transport and
            // compatibility state and must not be retargeted by changing their public fields.
            let client = peer.client_for(
                sponsor.account_client().authority(),
                sponsor.client().key_pair().private_key().clone(),
            );
            ensure!(
                client.account_client().network_id() == sponsor.account_client().network_id()
                    && client.account_client().authority() == sponsor.account_client().authority()
                    && client.account_client().endpoint() == endpoint,
                "committee proof client changed its network, account authority, or endpoint"
            );
            let view = client.client().private_settlement_committee_proof_v1(
                manifest.legs[ordinal].payload_digest,
                key,
            )?;
            ensure!(
                view.manifest == *manifest
                    && view.committee_authority == committee.authority
                    && view.statement == leg.prepared.statement
                    && view.proof == leg.prepared.proof
                    && view.delta == leg.prepared.delta
                    && view.audit_capsule_digest == leg.prepared.audit_capsule.digest()?
                    && !view.audit_approvals.is_empty()
                    && view.lifecycle == PrivateSettlementLifecycleDtoV1::Audited,
                "committee proof view was substituted or incomplete"
            );
        }
    }
    Ok(())
}

fn collect_network_leakage_sources<F>(
    network: &Network,
    mut selected: F,
) -> Result<Vec<(String, Vec<u8>)>>
where
    F: FnMut(&Path) -> bool,
{
    let mut sources = Vec::new();
    let mut total = 0_usize;
    for (peer_index, peer) in network.all_peers().enumerate() {
        let peer_sources = collect_leakage_source_files(&peer.kura_store_dir(), &mut selected)?;
        for (relative, bytes) in peer_sources {
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| eyre!("network leakage source byte count overflow"))?;
            ensure!(
                total <= LEAKAGE_MAX_SOURCE_BYTES,
                "network leakage source set exceeds its byte bound"
            );
            sources.push((format!("peer-{peer_index:03}/{relative}"), bytes));
        }
    }
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    ensure!(
        !sources.is_empty(),
        "network leakage source inventory is empty"
    );
    Ok(sources)
}

fn run_real_process_leakage_campaign(
    request: RealProcessLeakageRequestV1,
    request_sha: String,
) -> Result<RealProcessLeakageResultV1> {
    let shape = TopologyShape::new(request.participants);
    shape.validate()?;
    ensure!(
        request.participants == PARTICIPANT_COUNT,
        "leakage campaign is restricted to the primary N=3 topology"
    );
    let evidence_root = leakage_evidence_root()?;
    let context = format!(
        "atomic_private_settlement_real_process_leakage_n{}_s{}_r{}",
        request.participants, request.seed, request.run
    );
    let builder = localnet_builder(shape)
        .with_base_seed(format!(
            "atomic-private-settlement-real-process-leakage-v1-n{}-seed-{}-run-{}",
            request.participants, request.seed, request.run
        ))
        .with_private_settlement_route_control();
    let started = sandbox::start_network_blocking_or_skip(builder, &context)?;
    let Some((network, runtime)) = sandbox::enforce_network_start_requirement(started, &context)?
    else {
        return Err(eyre!("real-process leakage network was skipped"));
    };
    write_leakage_port_manifest(&network, shape)?;
    verify_controller_readiness(&network, &runtime)?;
    let mut coordinator = CoordinatorProcessV1::start(&network.client())?;
    let inventory =
        collect_process_inventory(&network, &runtime, shape, &request.commit, &coordinator)?;
    let sponsor = network.client();
    prepare_participant_assets(&network, shape)?;
    let activated_height = require_genesis_private_note_active(&sponsor)?;
    let expiry_height = activated_height + 1_000;
    let routes = routes_from_network(&network, shape)?;
    ensure!(routes.len() == request.participants, "route count mismatch");
    let committees = committees_from_network(&network, shape, &routes)?;
    let (private_leg_zero, canary_asset) = leakage_private_leg_zero(&request)?;
    let mut asset_definition_ids = (0..request.participants)
        .map(cbdc_asset_definition_id)
        .collect::<Vec<_>>();
    asset_definition_ids[0] = canary_asset;
    let governed = governed_legs_with_asset_definitions(
        &routes,
        activated_height,
        expiry_height,
        Some(&asset_definition_ids),
    )?;
    let mut private_data = (0..routes.len())
        .map(default_private_settlement_leg_data)
        .collect::<Vec<_>>();
    private_data[0] = private_leg_zero.clone();
    let authority_context_height = activate_governed_private_pools(
        &sponsor,
        network.network_id(),
        &governed,
        &private_data,
        expiry_height,
    )?;
    let manifest = proof_manifest(
        network.network_id(),
        authority_context_height,
        expiry_height,
        &governed,
    )?;
    let prepared = governed
        .into_iter()
        .zip(&committees)
        .enumerate()
        .map(|(ordinal, (leg, committee))| {
            // The paired privacy experiment intentionally changes only secret
            // plaintext fields, but it must never reuse output-encryption or
            // capsule key/nonce material across invocations.  OS entropy changes
            // only fixed-width cryptographic values and therefore preserves the
            // public shape, padding, and packet/message/record-count comparison.
            let mut output_rng = rand_core_06::OsRng;
            let mut capsule_rng = rand::rngs::OsRng;
            if ordinal == 0 {
                prepare_leg_with_private_data_and_rngs(
                    ordinal,
                    leg,
                    &manifest,
                    committee.authority.digest()?,
                    &private_leg_zero,
                    &mut output_rng,
                    &mut capsule_rng,
                )
            } else {
                let private_data = default_private_settlement_leg_data(ordinal);
                prepare_leg_with_private_data_and_rngs(
                    ordinal,
                    leg,
                    &manifest,
                    committee.authority.digest()?,
                    &private_data,
                    &mut output_rng,
                    &mut capsule_rng,
                )
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let before = wait_for_converged_fault_state_snapshot(&network, "leakage-before")?;
    let observer = FaultContinuousObserverV1::start_retaining_evidence(
        &network,
        &before,
        request.participants,
        &manifest.bundle_id,
        true,
    )?;
    let materials = provisional_materials(manifest, &prepared, &committees)?;
    let certificates = materials
        .iter()
        .zip(&committees)
        .map(|(material, committee)| {
            sponsor
                .client()
                .certify_private_settlement_leg_availability_v1(&committee.endpoints, material)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut final_manifest = materials[0].manifest.clone();
    for (ordinal, certificate) in certificates.iter().enumerate() {
        final_manifest.legs[ordinal].availability_certificate_digest = certificate.digest()?;
    }
    final_manifest.validate()?;
    for (ordinal, ((material, certificate), committee)) in materials
        .iter()
        .zip(&certificates)
        .zip(&committees)
        .enumerate()
    {
        let upload = PrivateSettlementLegUploadRequestV1 {
            manifest: final_manifest.clone(),
            audit_policy: material.audit_policy.clone(),
            committee_authority: material.committee_authority.clone(),
            payload: material.payload_with_certificate(certificate.clone()),
        };
        for endpoint in &committee.endpoints {
            let response = sponsor
                .client()
                .upload_private_settlement_leg_to_v1(endpoint, &upload)?;
            ensure!(
                usize::from(response.leg_ordinal) == ordinal,
                "leakage upload ordinal substitution"
            );
        }
    }
    assert_no_partial_visibility(&network, final_manifest.bundle_id, "leakage-collecting")?;

    for (ordinal, (leg, committee)) in prepared.iter().zip(&committees).enumerate() {
        let auditor_transport_signer =
            BorrowedKeyPairIdentityRequestSignerV1::new(&leg.governed.auditor_signing);
        let capsule_request = PrivateSettlementAuditorCapsuleRequestV1 {
            audit_policy: leg.governed.policy.clone(),
        };
        let fetched = sponsor
            .client()
            .private_settlement_auditor_capsule_quorum_for_authority_v1(
                &committee.endpoints,
                &materials[ordinal].committee_authority,
                final_manifest.legs[ordinal].payload_digest,
                &capsule_request,
                &auditor_transport_signer,
            )?;
        ensure!(
            fetched.lifecycle == PrivateSettlementLifecycleDtoV1::Collecting,
            "unexpected leakage audit lifecycle"
        );
        let authoritative_height = fetched.authoritative_height;
        let view = PrivateSettlementAuditorSidecarViewV1 {
            manifest: fetched.manifest,
            policy: fetched.audit_policy,
            authority: fetched.committee_authority,
            statement: fetched.statement,
            delta: fetched.delta,
            audit_capsule: fetched.audit_capsule,
            availability: fetched.availability,
            lifecycle: PrivateSettlementSidecarLifecycleV1::Collecting,
        };
        let auditor_id = AccountId::new(leg.governed.auditor_signing.public_key().clone());
        let approval = approve_private_settlement_leg_v1(
            &view,
            &leg.governed.governance,
            authoritative_height,
            &auditor_id,
            leg.governed.auditor_encryption.secret(),
            &leg.governed.auditor_signing,
            &approve_all_audit_material,
        )?;
        let response = sponsor
            .client()
            .submit_private_settlement_audit_approval_quorum_for_authority_v1(
                &committee.endpoints,
                &materials[ordinal].committee_authority,
                final_manifest.legs[ordinal].payload_digest,
                &auditor_transport_signer,
                &PrivateSettlementAuditApprovalRequestV1 {
                    audit_policy: capsule_request.audit_policy,
                    approval,
                },
            )?;
        ensure!(
            response.lifecycle == PrivateSettlementLifecycleDtoV1::Audited,
            "leakage approval quorum was not durable"
        );
    }
    assert_no_partial_visibility(&network, final_manifest.bundle_id, "leakage-audited")?;
    verify_committee_proof_views(&network, &sponsor, &final_manifest, &prepared, &committees)?;

    let endpoint_matrix = committees
        .iter()
        .map(|committee| committee.endpoints.clone())
        .collect::<Vec<_>>();
    let authorities = committees
        .iter()
        .map(|committee| committee.authority.clone())
        .collect::<Vec<_>>();
    let deltas = prepared
        .iter()
        .map(|leg| leg.prepared.delta.clone())
        .collect::<Vec<_>>();
    let barrier = sponsor.client().prepare_private_settlement_bundle_v1(
        &endpoint_matrix,
        &final_manifest,
        &authorities,
        &deltas,
    )?;
    assert_no_partial_visibility(&network, final_manifest.bundle_id, "leakage-prepared")?;
    let fee_before_registration = sponsor_nexus_fee_balance(&sponsor)?;
    submit_prepare_registration_and_wait_v1(&sponsor, &barrier)?;
    let fee_after_registration = sponsor_nexus_fee_balance(&sponsor)?;
    ensure_exact_private_settlement_carrier_fee(
        &fee_before_registration,
        &fee_after_registration,
        "leakage Prepare registration",
    )?;
    let registered =
        wait_for_recovered_prepare_registration(&network, &before, request.participants)?;
    let commits = sponsor
        .client()
        .commit_private_settlement_bundle_v1(&endpoint_matrix, &barrier)?;
    assert_no_partial_visibility(
        &network,
        final_manifest.bundle_id,
        "leakage-commit-certified",
    )?;
    let legs = deltas
        .into_iter()
        .zip(barrier.prepare_certificates)
        .zip(commits)
        .map(|((delta, prepare), commit)| PrivateSettlementLegReceiptV1 {
            delta,
            prepare,
            commit,
        })
        .collect();
    let carrier = FinalizeAtomicPrivateSettlementV1::new(PrivateSettlementCommitBundleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: final_manifest.clone(),
        authority_catalog: barrier.authority_catalog.clone(),
        legs,
    });
    let transaction = {
        let account = sponsor.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [InstructionBox::from(carrier)],
                final_manifest.public_fee_intent.clone(),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .wrap_err("build integration-test transaction")?;
    let entrypoint_hash = transaction.hash_as_entrypoint();
    let submit = PrivateSettlementBundleSubmitRequestV1 {
        transaction: transaction.clone(),
    };
    let fee_before_finalization = sponsor_nexus_fee_balance(&sponsor)?;
    let (event_record, event_source) = submit_leakage_carrier_with_event(
        &runtime,
        &sponsor,
        submit.clone(),
        final_manifest.bundle_id,
    )?;
    let receipt = wait_for_identical_receipt(&network, final_manifest.bundle_id)?;
    let fee_after_finalization = sponsor_nexus_fee_balance(&sponsor)?;
    ensure_exact_private_settlement_carrier_fee(
        &fee_before_finalization,
        &fee_after_finalization,
        "leakage financial finalization",
    )?;
    ensure!(
        receipt.legs.len() == request.participants,
        "leakage receipt participant count mismatch"
    );
    for (ordinal, leg) in receipt.legs.iter().enumerate() {
        ensure!(
            usize::from(leg.delta.leg_ordinal) == ordinal
                && leg.delta == prepared[ordinal].prepared.delta
                && receipt
                    .legs
                    .iter()
                    .filter(|candidate| candidate.delta.route == leg.delta.route)
                    .count()
                    == 1,
            "leakage receipt omitted, duplicated, or reordered a private leg"
        );
    }
    ensure!(
        sponsor
            .client()
            .submit_private_settlement_bundle_v1(&submit)
            .is_err(),
        "replaying the exact leakage carrier was accepted"
    );
    ensure!(
        sponsor_nexus_fee_balance(&sponsor)? == fee_after_finalization,
        "rejected leakage replay charged a third carrier fee"
    );
    ensure!(
        wait_for_identical_receipt(&network, final_manifest.bundle_id)? == receipt,
        "leakage replay changed the terminal receipt"
    );
    let after = wait_for_converged_fault_state_snapshot(&network, "leakage-after")?;
    let (continuous_observations, continuous_observation_evidence) =
        observer.finish_with_evidence(&after)?;
    ensure!(
        continuous_observations.len() == shape.process_count()
            && continuous_observations
                .iter()
                .all(|row| row.check_count >= 3 && row.finalized_observations >= 1),
        "leakage atomicity observer did not cover every validator through finality"
    );
    let continuous_atomicity_checks =
        continuous_observations
            .iter()
            .try_fold(0_u64, |total, row| {
                total
                    .checked_add(row.check_count)
                    .ok_or_else(|| eyre!("leakage atomicity check count overflow"))
            })?;
    let signed_rs16_da_observations =
        verify_signed_rs16_finality(&network, &runtime, receipt.finalized_height)?.observations;
    ensure!(
        signed_rs16_da_observations >= request.minimum_signed_rs16_da_observations,
        "signed RS16 leakage finality observations are incomplete"
    );

    let carrier_block = leakage_carrier_block(&sponsor, entrypoint_hash)?;
    let block_wire = leakage_block_wire(&carrier_block)?;
    let (query_records, query_sources) =
        leakage_query_records(&network, final_manifest.bundle_id, &receipt)?;
    let (telemetry_records, telemetry_sources) = leakage_telemetry_records(&network, &runtime)?;
    let needles = leakage_canary_needles(&request)?;
    let atomicity_observation_sources = continuous_observation_evidence
        .into_iter()
        .enumerate()
        .map(|(peer_index, observations)| {
            ensure!(
                !observations.is_empty(),
                "leakage atomicity evidence omitted a validator"
            );
            Ok((
                format!("peer-{peer_index:03}.json"),
                canonical_harness_json_bytes(&LeakageAtomicityObservationEvidenceV1 {
                    version: 1,
                    peer_index,
                    registered: registered.validators[peer_index].clone(),
                    observations,
                })?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure_leakage_sources_redacted(&needles, "carrier block", &[&block_wire])?;
    ensure_leakage_sources_redacted(&needles, "carrier event", &[&event_source])?;
    let query_source_refs = query_sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
    ensure_leakage_sources_redacted(&needles, "receipt queries", &query_source_refs)?;
    let telemetry_source_refs = telemetry_sources
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    ensure_leakage_sources_redacted(&needles, "telemetry", &telemetry_source_refs)?;
    let atomicity_observation_source_refs = atomicity_observation_sources
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect::<Vec<_>>();
    ensure_leakage_sources_redacted(
        &needles,
        "continuous atomicity observations",
        &atomicity_observation_source_refs,
    )?;

    let coordinator_sources = coordinator.stop_and_collect_logs()?;
    let coordinator_source_refs = coordinator_sources
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect::<Vec<_>>();
    ensure_leakage_sources_redacted(&needles, "coordinator logs", &coordinator_source_refs)?;
    drop(coordinator);
    runtime.block_on(network.shutdown());
    let (operator_records, operator_sources) = leakage_operator_log_records(&network)?;
    let operator_source_refs = operator_sources
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    ensure_leakage_sources_redacted(&needles, "operator logs", &operator_source_refs)?;
    let kura_sources = collect_network_leakage_sources(&network, |path| {
        path.file_name().and_then(|name| name.to_str()) == Some("blocks.data")
    })?;
    let merge_sources = collect_network_leakage_sources(&network, |path| {
        path.extension().and_then(|extension| extension.to_str()) == Some("log")
            && path
                .components()
                .any(|component| component.as_os_str() == "merge_ledger")
    })?;
    let snapshot_sources = collect_network_leakage_sources(&network, |path| {
        path.extension().and_then(|extension| extension.to_str()) == Some("norito")
            && path
                .components()
                .any(|component| component.as_os_str() == "wsv_checkpoints")
    })?;
    let sidecar_sources = collect_network_leakage_sources(&network, |path| {
        path.components()
            .any(|component| component.as_os_str() == "private-settlement-sidecars-v1")
    })?;
    let kura_source_refs = kura_sources
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect::<Vec<_>>();
    let merge_source_refs = merge_sources
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect::<Vec<_>>();
    let snapshot_source_refs = snapshot_sources
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect::<Vec<_>>();
    let sidecar_source_refs = sidecar_sources
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect::<Vec<_>>();
    ensure_leakage_sources_redacted(&needles, "Kura", &kura_source_refs)?;
    ensure_leakage_sources_redacted(&needles, "merge ledger", &merge_source_refs)?;
    ensure_leakage_sources_redacted(&needles, "WSV checkpoints", &snapshot_source_refs)?;
    ensure_leakage_sources_redacted(&needles, "confidential DA", &sidecar_source_refs)?;

    let event_json = leakage_json_records(vec![event_record])?;
    let query_json = leakage_json_records(query_records)?;
    let telemetry_json = leakage_json_records(telemetry_records)?;
    let operator_json = leakage_json_records(operator_records)?;
    let kura_artifact = framed_leakage_sources("kura", &kura_sources)?;
    let merge_artifact = framed_leakage_sources("merge", &merge_sources)?;
    let snapshot_artifact = framed_leakage_sources("snapshot", &snapshot_sources)?;
    let mut restricted_sources = vec![
        LeakageRestrictedSourceRefV1 {
            surface: "block_wire_capture",
            relative_path: "carrier-block-wire.bin".to_owned(),
            bytes: &block_wire,
        },
        LeakageRestrictedSourceRefV1 {
            surface: "event_capture",
            relative_path: "event-000.norito".to_owned(),
            bytes: &event_source,
        },
    ];
    for (index, source) in query_sources.iter().enumerate() {
        restricted_sources.push(LeakageRestrictedSourceRefV1 {
            surface: "query_capture",
            relative_path: format!("peer-{index:03}.norito"),
            bytes: source,
        });
    }
    for (index, source) in telemetry_sources.iter().enumerate() {
        restricted_sources.push(LeakageRestrictedSourceRefV1 {
            surface: "telemetry_capture",
            relative_path: format!("peer-{index:03}.status-metrics"),
            bytes: source,
        });
    }
    for (index, source) in operator_sources.iter().enumerate() {
        restricted_sources.push(LeakageRestrictedSourceRefV1 {
            surface: "operator_log",
            relative_path: format!("validator-{index:03}.stdout-stderr"),
            bytes: source,
        });
    }
    for (path, source) in &coordinator_sources {
        restricted_sources.push(LeakageRestrictedSourceRefV1 {
            surface: "coordinator_log",
            relative_path: path.clone(),
            bytes: source,
        });
    }
    for (surface, sources) in [
        ("kura_artifact", &kura_sources),
        ("merge_artifact", &merge_sources),
        ("snapshot_artifact", &snapshot_sources),
        ("confidential_da", &sidecar_sources),
        ("atomicity_observation", &atomicity_observation_sources),
    ] {
        for (path, source) in sources {
            restricted_sources.push(LeakageRestrictedSourceRefV1 {
                surface,
                relative_path: path.clone(),
                bytes: source,
            });
        }
    }
    let restricted_source_archive = framed_restricted_leakage_sources_v1(restricted_sources)?;
    ensure_leakage_sources_redacted(
        &needles,
        "restricted audit-source archive",
        &[restricted_source_archive.as_slice()],
    )?;
    let block_source = [block_wire.as_slice()];
    let event_sources = [event_source.as_slice()];
    let mut artifacts = vec![
        write_leakage_artifact(
            &evidence_root,
            "block_wire_capture",
            "block-wire.bin",
            &block_wire,
            &block_source,
        )?,
        write_leakage_artifact(
            &evidence_root,
            "event_capture",
            "events.json",
            &event_json,
            &event_sources,
        )?,
        write_leakage_artifact(
            &evidence_root,
            "kura_artifact",
            "kura.bin",
            &kura_artifact,
            &kura_source_refs,
        )?,
        write_leakage_artifact(
            &evidence_root,
            "merge_artifact",
            "merge.bin",
            &merge_artifact,
            &merge_source_refs,
        )?,
        write_leakage_artifact(
            &evidence_root,
            "operator_log",
            "operator.json",
            &operator_json,
            &operator_source_refs,
        )?,
        write_leakage_artifact(
            &evidence_root,
            "query_capture",
            "queries.json",
            &query_json,
            &query_source_refs,
        )?,
        write_leakage_artifact(
            &evidence_root,
            "restricted_audit_source",
            "restricted-audit-sources.bin",
            &restricted_source_archive,
            &[restricted_source_archive.as_slice()],
        )?,
        write_leakage_artifact(
            &evidence_root,
            "snapshot_artifact",
            "snapshot.bin",
            &snapshot_artifact,
            &snapshot_source_refs,
        )?,
        write_leakage_artifact(
            &evidence_root,
            "telemetry_capture",
            "telemetry.json",
            &telemetry_json,
            &telemetry_source_refs,
        )?,
    ];
    artifacts.sort_by(|left, right| left.surface.cmp(&right.surface));
    let nonpacket_record_counts = BTreeMap::from([
        ("block_messages".to_owned(), 1),
        (
            "query_responses".to_owned(),
            u64::try_from(query_sources.len())?,
        ),
        ("event_records".to_owned(), 1),
        (
            "log_records".to_owned(),
            u64::try_from(operator_sources.len())?,
        ),
        (
            "telemetry_records".to_owned(),
            u64::try_from(telemetry_sources.len())?,
        ),
    ]);
    ensure!(
        nonpacket_record_counts.values().all(|count| *count > 0),
        "leakage non-packet evidence contains an empty channel"
    );
    Ok(RealProcessLeakageResultV1 {
        version: 1,
        protocol: "AtomicPrivateSettlementV1".to_owned(),
        request_id: request.request_id,
        invocation_nonce: request.invocation_nonce,
        request_sha256: request_sha,
        commit: request.commit,
        participants: request.participants,
        mandatory_signed_rs16_da_rbc: true,
        signed_rs16_da_observations,
        authenticated_private_settlement_route_control: true,
        process_inventory: inventory,
        payload: RealProcessLeakageResultPayloadV1 {
            variant: request.payload.variant,
            canaries_injected: request
                .payload
                .canaries
                .into_iter()
                .map(|canary| canary.name)
                .collect(),
            canary_commitments: request.payload.canary_commitments,
            only_secret_fields_changed: true,
            nonpacket_capture_complete: true,
            finalized_receipt_observed: true,
            successful_leg_applications: request.participants,
            each_leg_applied_exactly_once: true,
            continuous_atomicity_checks,
            partial_visible_observations: 0,
            partial_spendable_observations: 0,
            nonpacket_artifacts: artifacts,
            nonpacket_record_counts,
        },
    })
}

fn run_real_process_private_benchmark(
    request: RealProcessBenchmarkRequestV1,
    request_sha: String,
    owner: &benchmark_session::RetainedBenchmarkNetwork,
    evidence_root: &Path,
    measurement_boundary: &mut impl FnMut(&'static str) -> Result<()>,
) -> Result<RealProcessBenchmarkResultV1> {
    let shape = TopologyShape::new(request.participants);
    shape.validate()?;
    let network: &Network = &owner.network;
    let workload = MatchedBenchmarkWorkloadV1::from_request(&request)?;
    let economic_vector_sha256 = workload.digest()?;
    publish_matched_workload(&request, &request_sha, network, &workload, evidence_root)?;
    let inventory = owner.inventory(&request.commit)?;
    let sponsor = network.client();
    let activated_height = owner.current_height()?;
    let expiry_height = activated_height + 1_000;
    let routes = routes_from_network(&network, shape)?;
    ensure!(routes.len() == request.participants, "route count mismatch");
    let committees = committees_from_network(&network, shape, &routes)?;
    let governed = workload.governance(&routes, activated_height, expiry_height)?;

    let private_data = workload.private_data()?;
    let authority_context_height = activate_governed_private_pools(
        &sponsor,
        network.network_id(),
        &governed,
        &private_data,
        expiry_height,
    )?;
    let manifest = proof_manifest(
        network.network_id(),
        authority_context_height,
        expiry_height,
        &governed,
    )?;

    // Disjoint private pools are prepared outside the shared carrier/proof window.
    // Baseline convergence and observer startup are setup for both profiles.
    let atomicity_before = wait_for_converged_fault_state_snapshot(&network, "benchmark-before")?;
    let atomicity_observer = FaultContinuousObserverV1::start(
        &network,
        &atomicity_before,
        request.participants,
        &manifest.bundle_id,
        true,
    )?;

    // Setup/prefunding is excluded; the storage baseline precedes measurement-ready.
    let storage_before = network_storage_bytes(&network)?;
    measurement_boundary("ready")?;
    let end_to_end_started = Instant::now();

    let proof_started = Instant::now();
    let prepared = governed
        .into_iter()
        .zip(&committees)
        .enumerate()
        .map(|(ordinal, (leg, committee))| {
            prepare_leg_with_private_data(
                ordinal,
                leg,
                &manifest,
                committee.authority.digest()?,
                &private_data[ordinal],
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let proof_generation = elapsed_ms(proof_started);
    let proof_bytes = prepared.iter().try_fold(0_u64, |total, leg| {
        total
            .checked_add(u64::try_from(leg.prepared.proof.len()).expect("proof length fits u64"))
            .ok_or_else(|| eyre!("proof byte total overflow"))
    })?;

    let upload_started = Instant::now();
    let materials = provisional_materials(manifest, &prepared, &committees)?;
    let certificates = materials
        .iter()
        .zip(&committees)
        .map(|(material, committee)| {
            sponsor
                .client()
                .certify_private_settlement_leg_availability_v1(&committee.endpoints, material)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut final_manifest = materials[0].manifest.clone();
    for (ordinal, certificate) in certificates.iter().enumerate() {
        final_manifest.legs[ordinal].availability_certificate_digest = certificate.digest()?;
    }
    final_manifest.validate()?;
    for (ordinal, ((material, certificate), committee)) in materials
        .iter()
        .zip(&certificates)
        .zip(&committees)
        .enumerate()
    {
        let upload = PrivateSettlementLegUploadRequestV1 {
            manifest: final_manifest.clone(),
            audit_policy: material.audit_policy.clone(),
            committee_authority: material.committee_authority.clone(),
            payload: material.payload_with_certificate(certificate.clone()),
        };
        for endpoint in &committee.endpoints {
            let response = sponsor
                .client()
                .upload_private_settlement_leg_to_v1(endpoint, &upload)?;
            ensure!(
                usize::from(response.leg_ordinal) == ordinal,
                "upload ordinal substitution"
            );
        }
    }
    let restricted_upload_availability = elapsed_ms(upload_started);
    assert_no_partial_visibility(&network, final_manifest.bundle_id, "collecting")?;

    let auditor_started = Instant::now();
    for (ordinal, (leg, committee)) in prepared.iter().zip(&committees).enumerate() {
        let auditor_transport_signer =
            BorrowedKeyPairIdentityRequestSignerV1::new(&leg.governed.auditor_signing);
        let capsule_request = PrivateSettlementAuditorCapsuleRequestV1 {
            audit_policy: leg.governed.policy.clone(),
        };
        let fetched = sponsor
            .client()
            .private_settlement_auditor_capsule_quorum_for_authority_v1(
                &committee.endpoints,
                &materials[ordinal].committee_authority,
                final_manifest.legs[ordinal].payload_digest,
                &capsule_request,
                &auditor_transport_signer,
            )?;
        ensure!(
            fetched.lifecycle == PrivateSettlementLifecycleDtoV1::Collecting,
            "unexpected audit lifecycle"
        );
        let authoritative_height = fetched.authoritative_height;
        let view = PrivateSettlementAuditorSidecarViewV1 {
            manifest: fetched.manifest,
            policy: fetched.audit_policy,
            authority: fetched.committee_authority,
            statement: fetched.statement,
            delta: fetched.delta,
            audit_capsule: fetched.audit_capsule,
            availability: fetched.availability,
            lifecycle: PrivateSettlementSidecarLifecycleV1::Collecting,
        };
        let auditor_id = AccountId::new(leg.governed.auditor_signing.public_key().clone());
        let approval = approve_private_settlement_leg_v1(
            &view,
            &leg.governed.governance,
            authoritative_height,
            &auditor_id,
            leg.governed.auditor_encryption.secret(),
            &leg.governed.auditor_signing,
            &approve_all_audit_material,
        )?;
        let response = sponsor
            .client()
            .submit_private_settlement_audit_approval_quorum_for_authority_v1(
                &committee.endpoints,
                &materials[ordinal].committee_authority,
                final_manifest.legs[ordinal].payload_digest,
                &auditor_transport_signer,
                &PrivateSettlementAuditApprovalRequestV1 {
                    audit_policy: capsule_request.audit_policy,
                    approval,
                },
            )?;
        ensure!(
            response.lifecycle == PrivateSettlementLifecycleDtoV1::Audited,
            "approval quorum was not durable"
        );
    }
    let auditor_response = elapsed_ms(auditor_started);
    assert_no_partial_visibility(&network, final_manifest.bundle_id, "audited")?;

    let committee_started = Instant::now();
    verify_committee_proof_views(&network, &sponsor, &final_manifest, &prepared, &committees)?;
    let committee_verification = elapsed_ms(committee_started);

    let endpoint_matrix = committees
        .iter()
        .map(|committee| committee.endpoints.clone())
        .collect::<Vec<_>>();
    let authorities = committees
        .iter()
        .map(|committee| committee.authority.clone())
        .collect::<Vec<_>>();
    let deltas = prepared
        .iter()
        .map(|leg| leg.prepared.delta.clone())
        .collect::<Vec<_>>();
    let prepare_started = Instant::now();
    let barrier = sponsor.client().prepare_private_settlement_bundle_v1(
        &endpoint_matrix,
        &final_manifest,
        &authorities,
        &deltas,
    )?;
    assert_no_partial_visibility(&network, final_manifest.bundle_id, "prepared")?;
    let prepare = elapsed_ms(prepare_started);
    let prepare_registration_started = Instant::now();
    let fee_before_registration = sponsor_nexus_fee_balance(&sponsor)?;
    submit_prepare_registration_and_wait_v1(&sponsor, &barrier)?;
    let fee_after_registration = sponsor_nexus_fee_balance(&sponsor)?;
    ensure_exact_private_settlement_carrier_fee(
        &fee_before_registration,
        &fee_after_registration,
        "benchmark Prepare registration",
    )?;
    let prepare_registration = elapsed_ms(prepare_registration_started);
    let commit_started = Instant::now();
    let commits = sponsor
        .client()
        .commit_private_settlement_bundle_v1(&endpoint_matrix, &barrier)?;
    let commit = elapsed_ms(commit_started);
    assert_no_partial_visibility(&network, final_manifest.bundle_id, "commit-certified")?;

    let legs = deltas
        .into_iter()
        .zip(barrier.prepare_certificates)
        .zip(commits)
        .map(|((delta, prepare), commit)| PrivateSettlementLegReceiptV1 {
            delta,
            prepare,
            commit,
        })
        .collect();
    let carrier = FinalizeAtomicPrivateSettlementV1::new(PrivateSettlementCommitBundleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: final_manifest.clone(),
        authority_catalog: barrier.authority_catalog.clone(),
        legs,
    });
    let transaction = {
        let account = sponsor.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [InstructionBox::from(carrier)],
                final_manifest.public_fee_intent.clone(),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .wrap_err("build integration-test transaction")?;
    let submit = PrivateSettlementBundleSubmitRequestV1 {
        transaction: transaction.clone(),
    };
    let fee_before_finalization = sponsor_nexus_fee_balance(&sponsor)?;
    let finality_started = Instant::now();
    sponsor
        .client()
        .submit_private_settlement_bundle_v1(&submit)?;
    let receipt = wait_for_identical_receipt(&network, final_manifest.bundle_id)?;
    ensure!(
        receipt.legs.len() == request.participants,
        "receipt participant count mismatch"
    );
    for (ordinal, leg) in receipt.legs.iter().enumerate() {
        ensure!(
            usize::from(leg.delta.leg_ordinal) == ordinal
                && leg.delta == prepared[ordinal].prepared.delta
                && receipt
                    .legs
                    .iter()
                    .filter(|candidate| candidate.delta.route == leg.delta.route)
                    .count()
                    == 1,
            "receipt omitted, duplicated, or reordered a private leg"
        );
    }
    // Both profiles stop after the expected authenticated receipt agrees on
    // every peer. Convergence, observer completion, replay and RS16 remain
    // mandatory acceptance checks outside this matched receipt window.
    let global_finality = elapsed_ms(finality_started);
    let end_to_end = elapsed_ms(end_to_end_started);
    measurement_boundary("finished")?;
    // Storage is a sequential all-peer Kura file-size snapshot immediately
    // after the timing handshake, before replay or correctness postchecks.
    // It brackets boundary handshakes too; it is not isolated transaction bytes.
    let storage_after = network_storage_bytes(&network)?;

    let fee_after_finalization = sponsor_nexus_fee_balance(&sponsor)?;
    ensure_exact_private_settlement_carrier_fee(
        &fee_before_finalization,
        &fee_after_finalization,
        "benchmark financial finalization",
    )?;
    let atomicity_after =
        observe_idempotent_finalized_retry(&sponsor, &network, &final_manifest, &submit, &receipt)?;
    ensure!(
        sponsor_nexus_fee_balance(&sponsor)? == fee_after_finalization,
        "acknowledged benchmark retry charged a third carrier fee"
    );
    ensure!(
        wait_for_identical_receipt(&network, final_manifest.bundle_id)? == receipt,
        "replay changed the terminal receipt"
    );
    ensure_fault_state_finalized_once(&atomicity_before, &atomicity_after, request.participants)?;
    let atomicity_observations = atomicity_observer.finish(&atomicity_after)?;
    ensure!(
        atomicity_observations.len() == network.all_peers().count(),
        "private benchmark atomicity observer omitted a validator or committee observer"
    );
    let signed_rs16_da_observations = owner
        .verify_signed_rs16_finality(receipt.finalized_height)?
        .observations;
    ensure!(
        signed_rs16_da_observations >= request.minimum_signed_rs16_da_observations,
        "signed RS16 finality observations are incomplete"
    );
    let receipt_bytes =
        u64::try_from(norito::encode_canonical(&receipt)?.len()).expect("receipt length fits u64");
    let storage_growth_bytes = storage_after
        .checked_sub(storage_before)
        .ok_or_else(|| eyre!("Kura storage shrank during benchmark"))?;
    ensure!(
        proof_generation > 0.0
            && restricted_upload_availability > 0.0
            && auditor_response > 0.0
            && committee_verification > 0.0
            && prepare > 0.0
            && prepare_registration > 0.0
            && commit > 0.0
            && global_finality > 0.0
            && end_to_end > 0.0
            && proof_bytes > 0
            && receipt_bytes > 0,
        "one or more required genuine benchmark measurements is empty"
    );
    Ok(RealProcessBenchmarkResultV1 {
        version: 1,
        protocol: "AtomicPrivateSettlementV1".to_owned(),
        request_id: request.request_id,
        invocation_nonce: request.invocation_nonce,
        request_sha256: request_sha,
        commit: request.commit,
        participants: request.participants,
        mandatory_signed_rs16_da_rbc: true,
        signed_rs16_da_observations,
        authenticated_private_settlement_route_control: true,
        process_inventory: inventory,
        payload: RealProcessBenchmarkResultPayloadV1 {
            economic_vector_sha256,
            primary_payment_count: request.participants,
            monetary_movement_count: request.participants + 1,
            stages_ms: norito::json!({
                "proof_generation": proof_generation,
                "restricted_upload_availability": restricted_upload_availability,
                "auditor_response": auditor_response,
                "committee_verification": committee_verification,
                "prepare": prepare,
                "prepare_registration": prepare_registration,
                "commit": commit,
                "global_finality": global_finality,
                "end_to_end": end_to_end,
            }),
            proof_bytes,
            receipt_bytes,
            storage_growth_bytes,
            finalized_receipt_observed: true,
            successful_leg_applications: request.participants,
            each_leg_applied_exactly_once: true,
            // The full-topology observer accepted only the exact baseline or complete
            // finalized private-state vector throughout the measured workflow.
            partial_visible_observations: 0,
            partial_spendable_observations: 0,
        },
    })
}

fn write_real_process_result<T: norito::json::JsonSerialize>(result: &T) -> Result<()> {
    let path = PathBuf::from(
        std::env::var(HARNESS_RESULT_ENV).wrap_err("missing real-process result path")?,
    );
    write_real_process_result_at(&path, result)
}

fn write_real_process_result_at<T: norito::json::JsonSerialize>(
    path: &Path,
    result: &T,
) -> Result<()> {
    ensure!(!path.exists(), "real-process result path already exists");
    let parent = path
        .parent()
        .ok_or_else(|| eyre!("real-process result has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent).wrap_err("inspect result parent")?;
    ensure!(
        parent_metadata.file_type().is_dir(),
        "real-process result parent is not a regular directory"
    );
    let encoded = format!("{}\n", norito::json::to_string_pretty(result)?);
    let temporary = parent.join(format!(".aps-rust-result-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .wrap_err("create temporary Rust result")?;
    file.write_all(encoded.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    fs::hard_link(&temporary, &path).wrap_err("atomically publish Rust result")?;
    fs::remove_file(&temporary)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Publish the terminal before preserving the worker's failing return or panic.
fn complete_benchmark_worker(
    identity: BenchmarkTerminalIdentityV1,
    elapsed_ms: u64,
    completion: std::thread::Result<Result<RealProcessBenchmarkResultV1>>,
    publish: impl FnOnce(&RealProcessBenchmarkTerminalV1) -> Result<()>,
) -> Result<()> {
    match completion {
        Ok(Ok(result)) => publish(
            &identity.terminal(elapsed_ms, RealProcessBenchmarkOutcomeV1::Succeeded(result))?,
        ),
        Ok(Err(error)) => {
            publish(&identity.terminal(
                elapsed_ms,
                RealProcessBenchmarkOutcomeV1::from_error(&error),
            )?)?;
            Err(error)
        }
        Err(panic) => {
            publish(&identity.terminal(
                elapsed_ms,
                RealProcessBenchmarkOutcomeV1::Failed(BenchmarkFailureReasonV1::WorkerPanic),
            )?)?;
            std::panic::resume_unwind(panic)
        }
    }
}

#[test]
#[ignore = "release-only: one retained 12-68 validator network per benchmark session"]
fn atomic_private_settlement_real_process_benchmark_session_harness() -> Result<()> {
    thread::Builder::new()
        .name("atomic-private-settlement-benchmark-session".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(benchmark_session::run_from_environment)
        .wrap_err("spawn retained benchmark session owner")?
        .join()
        .map_err(|_| eyre!("retained session owner panicked before terminal publication"))?
}

#[test]
#[ignore = "offline native verifier: requires exact owner-only vector inputs; starts no network"]
fn atomic_private_settlement_verify_benchmark_economic_vector() -> Result<()> {
    benchmark_session::verify_vector_from_environment()
}

#[test]
#[ignore = "release-only: starts 12-68 validators and runs the complete authenticated fault matrix"]
fn atomic_private_settlement_real_process_fault_harness() -> Result<()> {
    let handle = thread::Builder::new()
        .name("atomic-private-settlement-real-process-fault-harness".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| {
            let (bound, request_sha) = read_bound_real_process_request()?;
            let RealProcessBoundRequestV1::Fault(request) = bound else {
                return Err(eyre!("fault entrypoint received a non-fault request"));
            };
            let result = run_real_process_fault_campaign(request, request_sha)?;
            write_real_process_result(&result)
        })
        .expect("spawn real-process fault release harness thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
#[ignore = "release-only: starts 16 validators and captures a real secret-only differential run"]
fn atomic_private_settlement_real_process_leakage_harness() -> Result<()> {
    let handle = thread::Builder::new()
        .name("atomic-private-settlement-real-process-leakage-harness".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| {
            let (bound, request_sha) = read_bound_real_process_request()?;
            let RealProcessBoundRequestV1::Leakage(request) = bound else {
                return Err(eyre!("leakage entrypoint received a non-leakage request"));
            };
            let result = run_real_process_leakage_campaign(request, request_sha)?;
            write_real_process_result(&result)
        })
        .expect("spawn real-process leakage release harness thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
#[ignore = "release-only child: owner-only restartable private-settlement coordinator"]
fn atomic_private_settlement_real_process_coordinator_helper() -> Result<()> {
    run_coordinator_helper_process()
}

#[test]
fn real_process_request_digest_validation_is_fail_closed() {
    assert!(lowercase_digest(&"a".repeat(64), &[64]));
    assert!(lowercase_digest(&"b".repeat(40), &[40, 64]));
    assert!(!lowercase_digest(&"0".repeat(64), &[64]));
    assert!(!lowercase_digest(&"A".repeat(64), &[64]));
    assert!(!lowercase_digest("not-a-digest", &[64]));
}

#[test]
fn fault_bundle_governance_derivation_is_reproducible_and_disjoint() {
    let purposes: &[&[u8]] = &[b"audit-policy", b"pool-id", b"asset-binding-salt"];
    let maximum_participants = 16;
    let mut materials = BTreeSet::new();
    for bundle_ordinal in 0..FAULT_CAMPAIGN_TRIALS {
        for leg_ordinal in 0..maximum_participants {
            for purpose in purposes {
                let material =
                    fault_derivation_bytes_from_run(17, 29, bundle_ordinal, leg_ordinal, purpose);
                assert_eq!(
                    material,
                    fault_derivation_bytes_from_run(17, 29, bundle_ordinal, leg_ordinal, purpose,),
                    "fault campaign derivation must be reproducible"
                );
                assert!(
                    materials.insert(material),
                    "fault bundle {bundle_ordinal} leg {leg_ordinal} reused {purpose:?}"
                );
            }
        }
    }
    assert_eq!(
        materials.len(),
        FAULT_CAMPAIGN_TRIALS * maximum_participants * purposes.len()
    );
}

fn fault_observation_fixture(
    peer_index: usize,
    ledger_byte: char,
    roots: u64,
) -> FaultStateObservationV1 {
    let finalized = roots != 0;
    FaultStateObservationV1 {
        peer_index,
        response_sha256: if finalized { "2" } else { "1" }.repeat(64),
        response_hex: "7b7d".to_owned(),
        height: 1,
        commitment: ledger_byte.to_string().repeat(64),
        ledger_commitment: ledger_byte.to_string().repeat(64),
        replicated_staged_lock_commitment: "4".repeat(64),
        staged_lock_commitment: "3".repeat(64),
        counts: norito::json!({
            "governance": 1,
            "pools": 1,
            "roots": roots,
            "nullifiers": (if finalized { 4 } else { 0 }),
            "commitments": (if finalized { 6 } else { 0 }),
            "encrypted_outputs": (if finalized { 6 } else { 0 }),
            "replay_markers": (if finalized { 1 } else { 0 }),
            "receipts": (if finalized { 1 } else { 0 }),
            "abort_markers": 0,
            "staged_pool_heads": 0,
            "staged_nullifiers": 0,
            "staged_output_commitments": 0,
            "replicated_staged_locks": 0,
            "staged_locks": 0,
        }),
    }
}

/// A single N=3 registration; every participant has a valid three-of-four local
/// Prepare shape, while the replicated map is complete on all sixteen peers.
fn smoke_registration_snapshot_fixture() -> (FaultStateSnapshotV1, FaultStateSnapshotV1) {
    assert_eq!(VALIDATORS_PER_LANE, 4);
    let before = FaultStateSnapshotV1 {
        label: "smoke-before-fixture".to_owned(),
        validators: (0..16)
            .map(|peer_index| {
                let mut observation = fault_observation_fixture(peer_index, 'a', 0);
                set_smoke_registration_count(&mut observation, "pools", 3);
                observation
            })
            .collect(),
    };
    let mut registered = before.clone();
    registered.label = "smoke-registered-fixture".to_owned();
    for observation in &mut registered.validators {
        set_smoke_registration_count(observation, "replicated_staged_locks", 28);
        observation.replicated_staged_lock_commitment = "8".repeat(64);
        if observation.peer_index >= 4 && observation.peer_index % 4 != 3 {
            set_smoke_registration_local_leg(observation);
        }
    }
    (before, registered)
}

fn set_smoke_registration_count(
    observation: &mut FaultStateObservationV1,
    field: &str,
    count: u64,
) {
    observation
        .counts
        .as_object_mut()
        .expect("fixture counts are an object")
        .insert(field.to_owned(), HarnessJsonValue::from(count));
}

fn set_smoke_registration_local_leg(observation: &mut FaultStateObservationV1) {
    for (field, count) in [
        ("staged_pool_heads", 1),
        ("staged_nullifiers", 2),
        ("staged_output_commitments", 3),
        ("staged_locks", 6),
    ] {
        set_smoke_registration_count(observation, field, count);
    }
    let committee = (observation.peer_index - 4) / 4;
    observation.staged_lock_commitment = (committee + 5).to_string().repeat(64);
}

#[test]
fn smoke_prepare_registration_waits_for_exact_replicated_map() {
    let (before, registered) = smoke_registration_snapshot_fixture();
    let expected = registered.validators[0]
        .replicated_staged_lock_commitment
        .clone();
    let mut lagging = registered.clone();
    for peer_index in [4, 8, 12] {
        let observation = &mut lagging.validators[peer_index];
        set_smoke_registration_count(observation, "replicated_staged_locks", 0);
        observation.replicated_staged_lock_commitment = before.validators[peer_index]
            .replicated_staged_lock_commitment
            .clone();
    }
    assert!(
        !fault_replicated_prepare_registration_ready_v1(&before, &lagging, 3, &expected).unwrap()
    );
    for peer_index in [4, 8] {
        lagging.validators[peer_index] = registered.validators[peer_index].clone();
        assert!(
            !fault_replicated_prepare_registration_ready_v1(&before, &lagging, 3, &expected)
                .unwrap()
        );
    }
    lagging.validators[12] = registered.validators[12].clone();
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &lagging, 3, &expected).unwrap()
    );
}

#[test]
fn smoke_prepare_registration_rejects_partial_missing_or_different_maps() {
    let (before, registered) = smoke_registration_snapshot_fixture();
    let expected = registered.validators[0]
        .replicated_staged_lock_commitment
        .clone();
    for invalid_count in [1, 27, 29] {
        let mut invalid = registered.clone();
        set_smoke_registration_count(
            &mut invalid.validators[15],
            "replicated_staged_locks",
            invalid_count,
        );
        assert!(
            fault_replicated_prepare_registration_ready_v1(&before, &invalid, 3, &expected)
                .is_err()
        );
    }
    let mut missing = registered.clone();
    missing.validators[15]
        .counts
        .as_object_mut()
        .unwrap()
        .remove("replicated_staged_locks");
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &missing, 3, &expected).is_err()
    );
    let mut different = registered.clone();
    different.validators[15].replicated_staged_lock_commitment = "9".repeat(64);
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &different, 3, &expected).is_err()
    );
    // The sponsor anchor cannot be silently replaced even if all replicas agree.
    for observation in &mut different.validators {
        observation.replicated_staged_lock_commitment = "9".repeat(64);
    }
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &different, 3, &expected).is_err()
    );
    let mut inconsistent_empty = registered.clone();
    set_smoke_registration_count(
        &mut inconsistent_empty.validators[15],
        "replicated_staged_locks",
        0,
    );
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &inconsistent_empty, 3, &expected)
            .is_err()
    );
    let mut inconsistent_full = registered.clone();
    inconsistent_full.validators[15].replicated_staged_lock_commitment = before.validators[15]
        .replicated_staged_lock_commitment
        .clone();
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &inconsistent_full, 3, &expected)
            .is_err()
    );
    let mut sponsor_missing = registered.clone();
    sponsor_missing.validators[0] = before.validators[0].clone();
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &sponsor_missing, 3, &expected)
            .is_err()
    );
}

#[test]
fn smoke_prepare_registration_rejects_financial_mutation_while_replica_lags() {
    let (before, mut registered) = smoke_registration_snapshot_fixture();
    let expected = registered.validators[0]
        .replicated_staged_lock_commitment
        .clone();
    registered.validators[4] = before.validators[4].clone();
    for field in [
        "roots",
        "nullifiers",
        "commitments",
        "encrypted_outputs",
        "replay_markers",
        "receipts",
        "abort_markers",
        "governance",
        "pools",
    ] {
        let mut mutated = registered.clone();
        let original = fault_count(&mutated.validators[15].counts, field).unwrap();
        set_smoke_registration_count(&mut mutated.validators[15], field, original + 1);
        assert!(
            fault_replicated_prepare_registration_ready_v1(&before, &mutated, 3, &expected)
                .is_err()
        );
    }
    registered.validators[15].ledger_commitment = "b".repeat(64);
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &registered, 3, &expected).is_err()
    );
}

#[test]
fn smoke_prepare_registration_preserves_three_of_four_local_prepare() {
    let (before, mut registered) = smoke_registration_snapshot_fixture();
    let expected = registered.validators[0]
        .replicated_staged_lock_commitment
        .clone();
    for committee in 0..3 {
        assert_eq!(
            registered.validators[4 + committee * 4..8 + committee * 4]
                .iter()
                .filter(
                    |observation| fault_count(&observation.counts, "staged_pool_heads").unwrap()
                        == 1
                )
                .count(),
            3
        );
    }
    assert!(
        fault_replicated_prepare_registration_ready_v1(&before, &registered, 3, &expected).unwrap()
    );
    // Recovery's existing all-four local-plane predicate must stay stronger.
    assert!(ensure_fault_prepare_lock_planes_full_v1(&before, &registered, 3).is_err());
    for peer_index in [7, 11, 15] {
        set_smoke_registration_local_leg(&mut registered.validators[peer_index]);
    }
    ensure_fault_prepare_lock_planes_full_v1(&before, &registered, 3).unwrap();
    let mut different_local = registered.clone();
    different_local.validators[7].staged_lock_commitment = "9".repeat(64);
    assert!(ensure_fault_prepare_lock_planes_full_v1(&before, &different_local, 3).is_err());
    let mut global_local = registered;
    global_local.validators[0].staged_lock_commitment = "9".repeat(64);
    assert!(ensure_fault_prepare_lock_planes_full_v1(&before, &global_local, 3).is_err());
}

#[test]
fn smoke_prepare_registration_requires_empty_baseline_and_exact_inventory() {
    let (before, registered) = smoke_registration_snapshot_fixture();
    let expected = registered.validators[0]
        .replicated_staged_lock_commitment
        .clone();
    let mut nonempty = before.clone();
    for observation in &mut nonempty.validators {
        set_smoke_registration_count(observation, "replicated_staged_locks", 28);
        observation.replicated_staged_lock_commitment = "7".repeat(64);
    }
    assert!(
        fault_replicated_prepare_registration_ready_v1(&nonempty, &registered, 3, &expected)
            .is_err()
    );
    for invalid_baseline in [false, true] {
        let mut baseline = before.clone();
        let mut snapshot = registered.clone();
        let invalid = if invalid_baseline {
            &mut baseline
        } else {
            &mut snapshot
        };
        invalid.validators[15].peer_index = 14;
        assert!(
            fault_replicated_prepare_registration_ready_v1(&baseline, &snapshot, 3, &expected)
                .is_err()
        );
        let mut baseline = before.clone();
        let mut snapshot = registered.clone();
        if invalid_baseline {
            baseline.validators.pop();
        } else {
            snapshot.validators.pop();
        }
        assert!(
            fault_replicated_prepare_registration_ready_v1(&baseline, &snapshot, 3, &expected)
                .is_err()
        );
    }
}

#[test]
fn fault_continuous_observer_tracks_local_reconciliation_without_partial_financial_state() {
    let baseline = fault_observation_fixture(0, 'a', 0);
    let finalized = fault_observation_fixture(0, 'b', 2);
    let mut pending = finalized.clone();
    set_smoke_registration_local_leg(&mut pending);
    let mut accumulator = FaultContinuousObservationAccumulatorV1::new(0, [9; Hash::LENGTH], true);
    accumulator.checkpoint_phase(0, &[]).unwrap();
    accumulator.record(&baseline, &baseline, 2, 0).unwrap();
    accumulator.record(&baseline, &pending, 2, 0).unwrap();
    accumulator.record(&baseline, &pending, 2, 0).unwrap();
    let mut substituted = pending.clone();
    substituted.staged_lock_commitment = "8".repeat(64);
    assert!(accumulator.record(&baseline, &substituted, 2, 0).is_err());
    assert!(accumulator.record(&baseline, &baseline, 2, 0).is_err());
    let mut replicated = pending.clone();
    set_smoke_registration_count(&mut replicated, "replicated_staged_locks", 19);
    assert!(accumulator.record(&baseline, &replicated, 2, 0).is_err());
    let terminal = accumulator.start_phase("terminal", false, true).unwrap();
    accumulator.checkpoint_phase(terminal, &[]).unwrap();
    assert!(
        accumulator
            .record(&baseline, &pending, 2, terminal)
            .is_err()
    );
    accumulator
        .record(&baseline, &finalized, 2, terminal)
        .unwrap();
    assert!(
        accumulator
            .record(&baseline, &pending, 2, terminal)
            .is_err()
    );
    accumulator.finish().unwrap();
    let mut stranded = FaultContinuousObservationAccumulatorV1::new(0, [9; Hash::LENGTH], true);
    stranded.checkpoint_phase(0, &[]).unwrap();
    stranded.record(&baseline, &baseline, 2, 0).unwrap();
    stranded.record(&baseline, &pending, 2, 0).unwrap();
    stranded.record(&baseline, &pending, 2, 0).unwrap();
    assert!(stranded.finish().is_err());
}

#[test]
fn fault_continuous_observer_accepts_only_baseline_or_complete_finalization() {
    let baseline = fault_observation_fixture(0, 'a', 0);
    let finalized = fault_observation_fixture(0, 'b', 2);
    assert_eq!(
        classify_fault_continuous_observation(&baseline, &baseline, 2).unwrap(),
        FaultContinuousObservationClassV1::Baseline
    );
    assert_eq!(
        classify_fault_continuous_observation(&baseline, &finalized, 2).unwrap(),
        FaultContinuousObservationClassV1::Finalized
    );
    let partial = fault_observation_fixture(0, 'c', 1);
    assert!(classify_fault_continuous_observation(&baseline, &partial, 2).is_err());
    let mut malformed_lock = baseline.clone();
    malformed_lock
        .counts
        .as_object_mut()
        .expect("fixture counts are an object")
        .insert(
            "replicated_staged_locks".to_owned(),
            HarnessJsonValue::from(2_u64),
        );
    assert!(classify_fault_continuous_observation(&baseline, &malformed_lock, 2).is_err());

    let mut accumulator = FaultContinuousObservationAccumulatorV1::new(0, [9; Hash::LENGTH], true);
    accumulator.checkpoint_phase(0, &[]).unwrap();
    accumulator.record(&baseline, &baseline, 2, 0).unwrap();
    accumulator.record(&baseline, &baseline, 2, 0).unwrap();
    accumulator.record(&baseline, &finalized, 2, 0).unwrap();
    let summary = accumulator.finish().unwrap();
    assert_eq!(summary.check_count, 3);
    assert_eq!(summary.poll_failure_count, 0);
    assert_eq!(summary.baseline_observations, 2);
    assert_eq!(summary.finalized_observations, 1);
    assert_eq!(summary.first_response_sha256, baseline.response_sha256);
    assert_eq!(summary.last_response_sha256, finalized.response_sha256);
    assert_eq!(summary.phase_coverage.len(), 1);
    assert_eq!(summary.phase_coverage[0].phase, "preflight");
    assert_eq!(summary.phase_coverage[0].successful_observations, 3);
    assert_eq!(summary.phase_coverage[0].poll_failures, 0);
}

#[test]
fn fault_continuous_observer_discards_stale_polls_from_counts_and_evidence() {
    let baseline = fault_observation_fixture(0, 'a', 0);
    let mut accumulator = FaultContinuousObservationAccumulatorV1::new(0, [9; Hash::LENGTH], false);
    accumulator.checkpoint_phase(0, &[]).unwrap();
    let mut retained = Vec::new();
    let initial_chain = accumulator.response_chain.clone().finalize();
    assert!(
        !accumulator
            .record_current_poll(&baseline, &baseline, 2, 0, 0, 1, Some(&mut retained))
            .unwrap()
    );
    assert_eq!(accumulator.check_count, 0);
    assert!(retained.is_empty());
    assert_eq!(accumulator.response_chain.clone().finalize(), initial_chain);
    assert!(
        accumulator
            .record_current_poll(&baseline, &baseline, 2, 0, 1, 1, Some(&mut retained))
            .unwrap()
    );
    assert_eq!(accumulator.check_count, retained.len() as u64);
    assert_eq!(retained[0].response_sha256, baseline.response_sha256);
    let accepted_chain = accumulator.response_chain.clone().finalize();
    assert!(
        !accumulator
            .record_current_poll(&baseline, &baseline, 2, 0, 1, 2, Some(&mut retained))
            .unwrap()
    );
    assert_eq!(accumulator.check_count, retained.len() as u64);
    assert_eq!(
        accumulator.response_chain.clone().finalize(),
        accepted_chain
    );
    retained.resize(LEAKAGE_MAX_OBSERVATIONS_PER_PEER, baseline.clone());
    assert!(
        accumulator
            .record_current_poll(&baseline, &baseline, 2, 0, 2, 2, Some(&mut retained))
            .is_err()
    );
    assert_eq!(accumulator.check_count, 1);
    assert_eq!(
        accumulator.response_chain.clone().finalize(),
        accepted_chain
    );
}

#[test]
fn fault_continuous_observer_hashes_expected_outages_and_rejects_wrong_coverage() {
    let baseline = fault_observation_fixture(0, 'a', 0);
    let finalized = fault_observation_fixture(0, 'b', 2);
    let mut accumulator = FaultContinuousObservationAccumulatorV1::new(0, [9; Hash::LENGTH], false);
    accumulator.checkpoint_phase(0, &[]).unwrap();
    accumulator.record(&baseline, &baseline, 2, 0).unwrap();
    accumulator.record(&baseline, &baseline, 2, 0).unwrap();
    let outage = accumulator
        .start_phase("committee_unavailable", true, false)
        .unwrap();
    assert!(accumulator.record_poll_failure(outage).unwrap());
    assert!(!accumulator.phase_coverage_met(outage).unwrap());
    let binding = format!("acknowledgement:{}", "a".repeat(64));
    accumulator.checkpoint_phase(outage, &[binding]).unwrap();
    assert!(!accumulator.phase_coverage_met(outage).unwrap());
    assert!(accumulator.record_poll_failure(outage).unwrap());
    assert!(accumulator.phase_coverage_met(outage).unwrap());
    let recovery = accumulator
        .start_phase("post_recovery", false, false)
        .unwrap();
    accumulator.checkpoint_phase(recovery, &[]).unwrap();
    accumulator
        .record(&baseline, &baseline, 2, recovery)
        .unwrap();
    let terminal = accumulator.start_phase("terminal", false, true).unwrap();
    accumulator.checkpoint_phase(terminal, &[]).unwrap();
    accumulator
        .record(&baseline, &finalized, 2, terminal)
        .unwrap();
    let summary = accumulator.finish().unwrap();
    assert_eq!(summary.poll_failure_count, 2);
    assert_eq!(
        summary
            .phase_coverage
            .iter()
            .map(|phase| phase.phase.as_str())
            .collect::<Vec<_>>(),
        vec![
            "preflight",
            "committee_unavailable",
            "post_recovery",
            "terminal"
        ]
    );
    let outage = &summary.phase_coverage[1];
    assert!(outage.expected_unavailable);
    assert_eq!(outage.successful_observations, 0);
    assert_eq!(outage.poll_failures, 2);
    assert_eq!(outage.checkpoint_attempt, 1);
    assert_eq!(outage.checkpoint_control_bindings.len(), 1);
    assert_eq!(outage.attempts.len(), 1);
    assert_eq!(
        outage.attempts[0].evidence,
        FAULT_CONTINUOUS_EXPECTED_UNAVAILABLE_CLASS_V1
    );

    let mut unexpected = FaultContinuousObservationAccumulatorV1::new(0, [9; Hash::LENGTH], false);
    unexpected.checkpoint_phase(0, &[]).unwrap();
    for _ in 0..3 {
        unexpected.record(&baseline, &baseline, 2, 0).unwrap();
    }
    assert!(!unexpected.record_poll_failure(0).unwrap());
    assert!(unexpected.finish().is_err());

    let mut unobserved_outage =
        FaultContinuousObservationAccumulatorV1::new(0, [9; Hash::LENGTH], false);
    unobserved_outage.checkpoint_phase(0, &[]).unwrap();
    for _ in 0..3 {
        unobserved_outage
            .record(&baseline, &baseline, 2, 0)
            .unwrap();
    }
    let outage = unobserved_outage
        .start_phase("committee_unavailable", true, false)
        .unwrap();
    unobserved_outage
        .checkpoint_phase(outage, &[format!("command:{}", "b".repeat(64))])
        .unwrap();
    unobserved_outage
        .record(&baseline, &baseline, 2, outage)
        .unwrap();
    assert!(unobserved_outage.finish().is_err());
}

#[test]
fn fault_continuous_observer_rejects_premature_finalization_and_rollback() {
    let baseline = fault_observation_fixture(0, 'a', 0);
    let finalized = fault_observation_fixture(0, 'b', 2);

    let mut premature = FaultContinuousObservationAccumulatorV1::new(0, [7; Hash::LENGTH], false);
    premature.checkpoint_phase(0, &[]).unwrap();
    assert!(premature.record(&baseline, &finalized, 2, 0).is_err());

    let mut rollback = FaultContinuousObservationAccumulatorV1::new(0, [7; Hash::LENGTH], true);
    rollback.checkpoint_phase(0, &[]).unwrap();
    rollback.record(&baseline, &baseline, 2, 0).unwrap();
    rollback.record(&baseline, &finalized, 2, 0).unwrap();
    assert!(rollback.record(&baseline, &baseline, 2, 0).is_err());
}

#[test]
fn fault_continuous_observer_chains_bind_the_bundle() {
    let baseline = fault_observation_fixture(0, 'a', 0);
    let summarize = |bundle_id| {
        let mut accumulator = FaultContinuousObservationAccumulatorV1::new(0, bundle_id, false);
        accumulator.checkpoint_phase(0, &[]).unwrap();
        for _ in 0..3 {
            accumulator.record(&baseline, &baseline, 2, 0).unwrap();
        }
        accumulator.finish().unwrap()
    };
    let first = summarize([1; Hash::LENGTH]);
    let second = summarize([2; Hash::LENGTH]);
    assert_ne!(first.response_chain_sha256, second.response_chain_sha256);
    assert_ne!(
        first.phase_coverage[0].attempt_chain_sha256,
        second.phase_coverage[0].attempt_chain_sha256
    );
}

#[test]
fn fault_continuous_observer_normalizes_only_connect_or_timeout_errors() {
    for private_error in ["private malformed body", "private cache-header detail"] {
        let report = eyre::Report::msg(private_error);
        assert_eq!(normalize_fault_observer_transport_failure(&report), None);
    }

    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(20))
        .build()
        .unwrap();
    let timeout = client
        .get(format!("http://{endpoint}/"))
        .send()
        .unwrap_err();
    assert!(timeout.is_timeout());
    let report = eyre::Report::new(timeout);
    assert_eq!(
        normalize_fault_observer_transport_failure(&report),
        Some(FAULT_CONTINUOUS_EXPECTED_UNAVAILABLE_CLASS_V1)
    );
}

#[test]
fn fault_inventory_uses_http_routes_and_external_restarts() {
    assert!(PRIVATE_SETTLEMENT_CRASH_BOUNDARIES.is_empty());
    assert_eq!(FAULT_CAMPAIGN_TRIALS, 13);
}

#[test]
fn ps_cpu_time_parser_accepts_portable_shapes_and_rejects_malformed_values() {
    assert_eq!(parse_ps_cpu_time("01:02").unwrap(), 62.0);
    assert_eq!(parse_ps_cpu_time("01:02:03.5").unwrap(), 3_723.5);
    assert_eq!(parse_ps_cpu_time("2-01:02:03").unwrap(), 176_523.0);
    assert_eq!(parse_ps_cpu_time("120:00.25").unwrap(), 7_200.25);
    assert_eq!(parse_ps_cpu_time("00:00").unwrap(), 0.0);
    for malformed in [
        "broken",
        "01:NaN",
        "01:inf",
        "01:-1",
        "01:+1",
        "01:1e1",
        "01:60",
        "01:02.",
        "01:.5",
        "01:02.3.4",
        "1-01:02",
        "1-24:00:00",
        "01:60:00",
        "+01:02",
        "-1-01:02:03",
        "18446744073709551616-01:02:03",
    ] {
        assert!(
            parse_ps_cpu_time(malformed).is_err(),
            "accepted {malformed}"
        );
    }
}

#[test]
fn process_resource_rows_require_exact_finite_complete_samples() {
    let sample = parse_process_resource_rows("23 4 01:02.5\n11 8 00:03\n", &[11, 23]).unwrap();
    assert_eq!(sample.cpu_seconds, 65.5);
    assert_eq!(sample.rss_bytes, 12 * 1_024);
    for text in [
        "11 8 00:03\n",
        "11 8 00:03\n11 4 00:01\n",
        "11 8 00:03\n24 4 00:01\n",
        "11 8 00:03\n23 4 00:NaN\n",
        "11 8 00:03\n23 -4 00:01\n",
        "11 8 00:03 extra\n23 4 00:01\n",
        "11 18446744073709551615 00:03\n23 1 00:01\n",
    ] {
        assert!(parse_process_resource_rows(text, &[11, 23]).is_err());
    }
    assert!(parse_process_resource_rows("11 18446744073709551615 00:03\n", &[11]).is_err());
    for pids in [vec![], vec![0], vec![11, 11]] {
        assert!(parse_process_resource_rows("11 8 00:03\n", &pids).is_err());
    }
}

#[test]
fn process_resource_sampler_preserves_observed_and_endpoint_peaks() {
    for (initial, observed, final_rss, expected) in [
        (900, 500, 300, 900),
        (100, 900, 300, 900),
        (100, 300, 900, 900),
    ] {
        let (ready, received) = std::sync::mpsc::channel();
        let sampler = ProcessResourceSampler::start_with_sampler(vec![11], initial, move |_| {
            ready.send(()).unwrap();
            Ok(ProcessResourceSample {
                cpu_seconds: 1.0,
                rss_bytes: observed,
            })
        })
        .unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(sampler.finish(final_rss).unwrap(), expected);
    }
}

#[test]
fn process_resource_sampler_propagates_sampling_failure() {
    let (ready, received) = std::sync::mpsc::channel();
    let sampler = ProcessResourceSampler::start_with_sampler(vec![11], 100, move |_| {
        ready.send(()).unwrap();
        Err(eyre!("measured process disappeared"))
    })
    .unwrap();
    received.recv_timeout(Duration::from_secs(5)).unwrap();
    let error = sampler.finish(900).unwrap_err();
    assert!(format!("{error:#}").contains("measured process disappeared"));
}

#[test]
fn process_resource_sampler_rejects_invalid_process_inventory() {
    for pids in [vec![], vec![0], vec![11, 11]] {
        assert!(ProcessResourceSampler::start(pids, 100).is_err());
    }
}

#[test]
fn real_process_benchmark_stage_inventory_is_profile_exact() {
    assert_eq!(
        benchmark_stages("private").unwrap(),
        PRIVATE_BENCHMARK_STAGES
    );
    assert_eq!(
        benchmark_stages("transparent_control").unwrap(),
        TRANSPARENT_CONTROL_BENCHMARK_STAGES
    );
    assert!(benchmark_stages("ordinary-transfer-substitute").is_err());
}

/// Protocol-only fixture; never used as a network measurement or release evidence.
fn benchmark_terminal_request_fixture() -> RealProcessBenchmarkRequestV1 {
    RealProcessBenchmarkRequestV1 {
        version: 1,
        protocol: "AtomicPrivateSettlementV1".to_owned(),
        request_id: "a".repeat(64),
        invocation_nonce: "b".repeat(64),
        kind: "benchmark".to_owned(),
        commit: "c".repeat(40),
        hardware_sha256: "d".repeat(64),
        hardware_profile_sha256: "e".repeat(64),
        configuration_sha256: "f".repeat(64),
        participants: 3,
        participant_visibilities: vec![
            "public".to_owned(),
            "restricted".to_owned(),
            "restricted".to_owned(),
        ],
        validators_per_dataspace: 4,
        global_validators: 4,
        quorum: "2f+1".to_owned(),
        mandatory_signed_rs16_da_rbc: true,
        minimum_signed_rs16_da_observations: 1,
        authenticated_private_settlement_route_control: true,
        seed: 1,
        session_id: "1".repeat(64),
        session_invocation_nonce: "2".repeat(64),
        workload_manifest_sha256: "3".repeat(64),
        session_attempt_index: 5,
        configuration: norito::json!({}),
        payload: RealProcessBenchmarkPayloadV1 {
            profile: "private".to_owned(),
            warmup: false,
            stages: PRIVATE_BENCHMARK_STAGES
                .iter()
                .map(ToString::to_string)
                .collect(),
            resources: Vec::new(),
        },
    }
}

fn benchmark_terminal_fixture() -> (BenchmarkTerminalIdentityV1, RealProcessBenchmarkResultV1) {
    let request = benchmark_terminal_request_fixture();
    let identity = BenchmarkTerminalIdentityV1::from_request(&request, "d".repeat(64));
    let result = RealProcessBenchmarkResultV1 {
        version: 1,
        protocol: "AtomicPrivateSettlementV1".to_owned(),
        request_id: identity.request_id.clone(),
        invocation_nonce: identity.invocation_nonce.clone(),
        request_sha256: identity.request_sha256.clone(),
        commit: identity.commit.clone(),
        participants: identity.participants,
        mandatory_signed_rs16_da_rbc: true,
        signed_rs16_da_observations: 1,
        authenticated_private_settlement_route_control: true,
        process_inventory: Vec::new(),
        payload: RealProcessBenchmarkResultPayloadV1 {
            economic_vector_sha256: "a".repeat(64),
            primary_payment_count: 3,
            monetary_movement_count: 4,
            stages_ms: norito::json!({"end_to_end_ms": 1.5}),
            proof_bytes: 3,
            receipt_bytes: 4,
            storage_growth_bytes: 5,
            finalized_receipt_observed: true,
            successful_leg_applications: 3,
            each_leg_applied_exactly_once: true,
            partial_visible_observations: 0,
            partial_spendable_observations: 0,
        },
    };
    (identity, result)
}

#[test]
fn benchmark_terminal_deadline_classification_preserves_typed_causes() {
    for stage in [
        BenchmarkDeadlineStageV1::CoordinatorAck,
        BenchmarkDeadlineStageV1::StateConvergence,
        BenchmarkDeadlineStageV1::TransparentConsents,
        BenchmarkDeadlineStageV1::TransparentBalances,
        BenchmarkDeadlineStageV1::SettlementFinality,
        BenchmarkDeadlineStageV1::CanonicalCarrier,
        BenchmarkDeadlineStageV1::PrivateReceipt,
    ] {
        let error =
            benchmark_deadline_error(stage, Duration::from_millis(10), Duration::from_millis(11))
                .wrap_err("restricted diagnostic context")
                .wrap_err("benchmark operation");
        let outcome = RealProcessBenchmarkOutcomeV1::from_error(&error);
        assert!(
            matches!(outcome, RealProcessBenchmarkOutcomeV1::TimedOut(BenchmarkDeadlineV1 {
            stage: observed, budget_ms: 10, elapsed_ms: 11,
        }) if observed == stage)
        );
        let encoded = norito::json::to_value(&outcome).unwrap();
        assert_eq!(
            encoded,
            norito::json!({
                "kind": "timed_out", "stage": (stage.as_str()), "budget_ms": 10, "elapsed_ms": 11,
            })
        );
        assert!(
            !norito::json::to_json(&outcome)
                .unwrap()
                .contains("restricted")
        );
    }
    for message in [
        "timeout",
        "timed out waiting for receipt",
        "ordinary failure",
    ] {
        let error = eyre!(message.to_owned()).wrap_err("outer context");
        assert!(matches!(
            RealProcessBenchmarkOutcomeV1::from_error(&error),
            RealProcessBenchmarkOutcomeV1::Failed(BenchmarkFailureReasonV1::ExecutionError)
        ));
    }
    let premature = benchmark_deadline_error(
        BenchmarkDeadlineStageV1::PrivateReceipt,
        Duration::from_millis(10),
        Duration::from_millis(9),
    );
    assert!(matches!(
        RealProcessBenchmarkOutcomeV1::from_error(&premature),
        RealProcessBenchmarkOutcomeV1::Failed(BenchmarkFailureReasonV1::ExecutionError)
    ));
    assert_eq!(
        benchmark_duration_ms(Duration::from_micros(1_999)).unwrap(),
        1
    );
    assert!(benchmark_duration_ms(Duration::MAX).is_err());
    for budget in [Duration::ZERO, Duration::from_nanos(1)] {
        let error = benchmark_deadline_error(
            BenchmarkDeadlineStageV1::PrivateReceipt,
            budget,
            Duration::from_millis(1),
        );
        assert!(matches!(
            RealProcessBenchmarkOutcomeV1::from_error(&error),
            RealProcessBenchmarkOutcomeV1::Failed(BenchmarkFailureReasonV1::ExecutionError)
        ));
    }
}

#[test]
fn benchmark_terminal_serialization_is_exact_and_rejects_unknown_fields() {
    let (identity, result) = benchmark_terminal_fixture();
    let expected_result = norito::json::to_value(&result).unwrap();
    let mut outcomes = vec![RealProcessBenchmarkOutcomeV1::Succeeded(result)];
    for reason in [
        BenchmarkFailureReasonV1::ExecutionError,
        BenchmarkFailureReasonV1::WorkerPanic,
        BenchmarkFailureReasonV1::WorkerSpawnError,
    ] {
        outcomes.push(RealProcessBenchmarkOutcomeV1::Failed(reason));
    }
    outcomes.push(RealProcessBenchmarkOutcomeV1::TimedOut(
        BenchmarkDeadlineV1 {
            stage: BenchmarkDeadlineStageV1::PrivateReceipt,
            budget_ms: 10,
            elapsed_ms: 11,
        },
    ));
    for outcome in outcomes {
        let terminal = identity.clone().terminal(15, outcome).unwrap();
        let value = norito::json::to_value(&terminal).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "version",
                "protocol",
                "request_id",
                "invocation_nonce",
                "request_sha256",
                "commit",
                "participants",
                "elapsed_ms",
                "outcome"
            ]
            .into_iter()
            .collect()
        );
        if value["outcome"]["kind"].as_str() == Some("succeeded") {
            assert_eq!(value["outcome"]["result"], expected_result);
        } else {
            assert!(value["outcome"].get("result").is_none());
        }
        let decoded: RealProcessBenchmarkTerminalV1 =
            norito::json::from_value(value.clone()).unwrap();
        assert_eq!(norito::json::to_value(&decoded).unwrap(), value);
        for key in [
            "version",
            "protocol",
            "request_id",
            "invocation_nonce",
            "request_sha256",
            "commit",
            "participants",
            "elapsed_ms",
            "outcome",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                norito::json::from_value::<RealProcessBenchmarkTerminalV1>(missing).is_err(),
                "missing {key}"
            );
        }
        let mut extra = value.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("unbound".to_owned(), true.into());
        assert!(norito::json::from_value::<RealProcessBenchmarkTerminalV1>(extra).is_err());
        let mut extra = value;
        extra
            .as_object_mut()
            .unwrap()
            .get_mut("outcome")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unbound".to_owned(), true.into());
        assert!(norito::json::from_value::<RealProcessBenchmarkTerminalV1>(extra).is_err());
    }
    for invalid in [
        norito::json!({"kind":"legacy_success"}),
        norito::json!({"kind":"failed","stage":"unknown","reason":"execution_error"}),
        norito::json!({"kind":"failed","stage":"benchmark_worker","reason":"private error"}),
        norito::json!({"kind":"timed_out","stage":"unknown","budget_ms":10,"elapsed_ms":11}),
        norito::json!({"kind":"timed_out","stage":"private_receipt","budget_ms":0,"elapsed_ms":0}),
        norito::json!({"kind":"timed_out","stage":"private_receipt","budget_ms":10,"elapsed_ms":9}),
    ] {
        assert!(norito::json::from_value::<RealProcessBenchmarkOutcomeV1>(invalid).is_err());
    }
    for duplicate in [
        r#"{"kind":"failed","kind":"failed","stage":"benchmark_worker","reason":"execution_error"}"#,
        r#"{"kind":"failed","stage":"benchmark_worker","stage":"benchmark_worker","reason":"execution_error"}"#,
        r#"{"kind":"failed","stage":"benchmark_worker","reason":"execution_error","reason":"execution_error"}"#,
    ] {
        assert!(norito::json::from_json::<RealProcessBenchmarkOutcomeV1>(duplicate).is_err());
    }
    let (identity, _) = benchmark_terminal_fixture();
    let terminal = identity
        .terminal(
            15,
            RealProcessBenchmarkOutcomeV1::Failed(BenchmarkFailureReasonV1::ExecutionError),
        )
        .unwrap();
    let mut duplicate = norito::json::to_json(&terminal).unwrap();
    assert_eq!(duplicate.pop(), Some('}'));
    duplicate.push_str(
        r#", "outcome":{"kind":"failed","stage":"benchmark_worker","reason":"execution_error"}}"#,
    );
    assert!(norito::json::from_json::<RealProcessBenchmarkTerminalV1>(&duplicate).is_err());
}

#[test]
fn benchmark_terminal_success_requires_retained_request_identity() {
    let mut request = benchmark_terminal_request_fixture();
    let identity = BenchmarkTerminalIdentityV1::from_request(&request, "d".repeat(64));
    request.request_id = "f".repeat(64);
    request.invocation_nonce = "e".repeat(64);
    drop(request);
    assert_eq!(identity.request_id, "a".repeat(64));
    assert_eq!(identity.invocation_nonce, "b".repeat(64));
    for field in [
        "version",
        "protocol",
        "request_id",
        "invocation_nonce",
        "request_sha256",
        "commit",
        "participants",
    ] {
        let (identity, mut result) = benchmark_terminal_fixture();
        match field {
            "version" => result.version = 2,
            "protocol" => result.protocol.clear(),
            "request_id" => result.request_id.clear(),
            "invocation_nonce" => result.invocation_nonce.clear(),
            "request_sha256" => result.request_sha256.clear(),
            "commit" => result.commit.clear(),
            "participants" => result.participants = 2,
            _ => unreachable!(),
        }
        assert!(
            identity
                .terminal(15, RealProcessBenchmarkOutcomeV1::Succeeded(result))
                .is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn benchmark_terminal_publication_preserves_failures_and_panics() {
    let directory = tempfile::tempdir().unwrap();
    for (name, error, expected) in [
        (
            "failure.json",
            eyre!("restricted worker diagnostic"),
            "failed",
        ),
        (
            "timeout.json",
            benchmark_deadline_error(
                BenchmarkDeadlineStageV1::PrivateReceipt,
                Duration::from_millis(10),
                Duration::from_millis(11),
            ),
            "timed_out",
        ),
    ] {
        let path = directory.path().join(name);
        let (identity, _) = benchmark_terminal_fixture();
        let returned = complete_benchmark_worker(identity, 15, Ok(Err(error)), |terminal| {
            write_real_process_result_at(&path, terminal)
        });
        assert!(returned.is_err());
        let bytes = fs::read(&path).unwrap();
        let terminal: HarnessJsonValue = norito::json::from_slice(&bytes).unwrap();
        assert_eq!(terminal["outcome"]["kind"].as_str(), Some(expected));
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("restricted worker diagnostic")
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let path = directory.path().join("panic.json");
    let (identity, _) = benchmark_terminal_fixture();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        complete_benchmark_worker(
            identity,
            15,
            Err(Box::new("restricted panic payload")),
            |terminal| write_real_process_result_at(&path, terminal),
        )
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"restricted panic payload")
    );
    let terminal: HarnessJsonValue = norito::json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        terminal["outcome"],
        norito::json!({
            "kind":"failed", "stage":"benchmark_worker", "reason":"worker_panic",
        })
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}

#[test]
fn benchmark_terminal_publication_is_required_and_never_overwrites() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("result.json");
    let (identity, result) = benchmark_terminal_fixture();
    complete_benchmark_worker(identity, 15, Ok(Ok(result)), |terminal| {
        write_real_process_result_at(&path, terminal)
    })
    .unwrap();
    let first = fs::read(&path).unwrap();
    let (identity, result) = benchmark_terminal_fixture();
    assert!(
        complete_benchmark_worker(identity, 15, Ok(Ok(result)), |terminal| {
            write_real_process_result_at(&path, terminal)
        })
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), first);
    let (identity, result) = benchmark_terminal_fixture();
    assert!(
        complete_benchmark_worker(identity, 15, Ok(Ok(result)), |_| Err(eyre!(
            "publication unavailable"
        )))
        .is_err()
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn leakage_memo_framing_and_raw_source_scan_are_fail_closed() {
    let mut left = b"iroha:aps-leakage-memo:v1\0".to_vec();
    append_fixed_leakage_memo_field(&mut left, b"memo-v1\0", b"left", 16).unwrap();
    let mut right = b"iroha:aps-leakage-memo:v1\0".to_vec();
    append_fixed_leakage_memo_field(&mut right, b"memo-v1\0", b"right", 16).unwrap();
    assert_eq!(left.len(), right.len());
    assert_ne!(left, right);
    assert!(append_fixed_leakage_memo_field(&mut Vec::new(), b"memo-v1\0", b"", 16).is_err());

    let needles = vec![LeakageCanaryNeedleV1 {
        name: "memo".to_owned(),
        encoding: "utf8".to_owned(),
        bytes: b"never-public".to_vec(),
    }];
    assert!(ensure_leakage_sources_redacted(&needles, "fixture", &[b"opaque"]).is_ok());
    assert!(
        ensure_leakage_sources_redacted(&needles, "fixture", &[b"prefix-never-public-suffix"])
            .is_err()
    );
    assert_eq!(leakage_leb128(0), [0]);
    assert_eq!(leakage_leb128(128), [0x80, 0x01]);
    let asset = leakage_canary_asset_definition_id("left").expect("typed leakage asset");
    let asset_payload = leakage_asset_address_payload(&asset);
    assert_eq!(asset_payload[0], 1);
    assert_eq!(&asset_payload[1..17], &asset.aid_bytes());
    assert_eq!(
        &asset_payload[17..],
        &blake3::hash(&asset_payload[..17]).as_bytes()[..4]
    );
    let commitment = leakage_canary_commitment(&RealProcessLeakageCanaryV1 {
        name: "account_id".to_owned(),
        kind: "text".to_owned(),
        value: HarnessJsonValue::String("fixture".to_owned()),
    })
    .expect("canonical leakage canary commitment");
    assert_eq!(
        commitment,
        "0a85640748c1a32f1f088cdb5065806c7531526d33bd4af7796bab9ff6284905"
    );
}

#[test]
fn transparent_control_identifiers_are_distinct_and_dataspace_scoped() {
    let workload = MatchedBenchmarkWorkloadV1::new(16, 7, 0, false).unwrap();
    let accounts = workload
        .payments
        .iter()
        .flat_map(|p| [p.source.account().clone(), p.recipient.clone()])
        .collect::<BTreeSet<_>>();
    let definitions = workload
        .payments
        .iter()
        .map(|p| p.source.definition())
        .collect::<BTreeSet<_>>();
    assert_eq!(accounts.len(), 32);
    assert_eq!(definitions.len(), 16);
    assert!(!accounts.contains(&*ALICE_ID));
    for (ordinal, payment) in workload.payments.iter().enumerate() {
        assert_eq!(
            payment.source.scope(),
            &AssetBalanceScope::Dataspace(DataSpaceId::new((ordinal + 1) as u64))
        );
    }
}

#[test]
fn transparent_control_atomicity_classifier_rejects_mixed_vectors() {
    let workload = MatchedBenchmarkWorkloadV1::new(3, 7, 0, false).unwrap();
    let initial = workload
        .movements()
        .unwrap()
        .as_slice()
        .iter()
        .flat_map(|m| [m.source.clone(), m.destination()])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|asset_id| TransparentControlBalanceExpectation {
            asset_id,
            amount: Quantity::from(1000_u64),
        })
        .collect::<Vec<_>>();
    let finalized = transparent_control_balance_expectations(&workload, &initial).unwrap();
    let initial_values = initial
        .iter()
        .map(|row| row.amount.clone())
        .collect::<Vec<_>>();
    let final_values = finalized
        .iter()
        .map(|row| row.amount.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        classify_transparent_control_values(&initial_values, &initial, &finalized).unwrap(),
        TransparentControlSnapshotState::Initial
    );
    assert_eq!(
        classify_transparent_control_values(&final_values, &initial, &finalized).unwrap(),
        TransparentControlSnapshotState::Finalized
    );
    for ordinal in 0..initial.len() {
        let mut mixed = initial_values.clone();
        mixed[ordinal] = final_values[ordinal].clone();
        assert!(classify_transparent_control_values(&mixed, &initial, &finalized).is_err());
    }
}

#[test]
fn benchmark_native_payload_excludes_adapter_measurements() {
    let (_, result) = benchmark_terminal_fixture();
    let value = norito::json::to_value(&result.payload).unwrap();
    let decoded: RealProcessBenchmarkResultPayloadV1 =
        norito::json::from_value(value.clone()).unwrap();
    assert_eq!(
        canonical_harness_json_bytes(&decoded).unwrap(),
        canonical_harness_json_bytes(&result.payload).unwrap()
    );
    for key in [
        "throughput_bundles_per_second",
        "cpu_seconds",
        "peak_rss_bytes",
        "network_bytes",
    ] {
        assert!(value.get(key).is_none());
        let mut changed = value.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), 1.into());
        assert!(norito::json::from_value::<RealProcessBenchmarkResultPayloadV1>(changed).is_err());
    }
}
