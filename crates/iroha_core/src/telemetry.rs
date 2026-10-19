//! Metrics and status reporting.
//!
//! Full status uses one nonblocking original State read for each World sample.
//! Busy publication refuses locally instead of spinning on the async telemetry actor;
//! the existing 500 ms service deadline and verified journal catch-up remain unchanged.
//!
//! Aggregate TEU gauges and per-lane/dataspace instruments are updated together for the mandatory
//! Nexus scheduler so operators can inspect both network-wide and routed scheduler activity.
mod manifest_status;
#[cfg(all(test, feature = "telemetry"))]
use crate::pipeline::access::AccessSetSource;
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use crate::smartcontracts::isi::settlement::{SETTLEMENT_KIND_DVP, SETTLEMENT_KIND_PVP};
use crate::{
    gossiper::{GossipPlane, gossip_plane_label},
    governance::manifest::{LaneManifestRegistryHandle, LaneManifestStatus},
    json_macros::{JsonDeserialize, JsonSerialize},
    kura::Kura,
    nexus::space_directory::SpaceDirectoryManifestSet,
    queue::Queue,
    state::{State, WorldReadOnly},
    status::{self, SettlementOutcomeKind},
};
use http::StatusCode;
use iroha_crypto::HashOf;
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_data_model::da::types::DaRentQuote;
#[cfg(feature = "telemetry")]
use iroha_data_model::events::data::{
    DataEvent, governance::GovernanceEvent, social::SocialEvent,
    space_directory::SpaceDirectoryEvent,
};
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_data_model::soranet::privacy_metrics::{
    SoranetPrivacyEventV1, SoranetPrivacyPrioShareV1,
};
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_data_model::{
    Identifiable,
    block::BlockHeader,
    nexus::{
        AxtPolicySnapshot, AxtRejectReason, DataSpaceCatalog, LaneCatalog, LaneStorageProfile,
        LaneVisibility, PublicLaneValidatorStatus, UniversalAccountId,
    },
    proof::ProofStatus,
    query::QueryOutput,
};
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_data_model::{
    account::AccountId,
    isi::settlement::{
        SettlementAtomicity, SettlementExecutionOrder, SettlementId, SettlementPlan,
    },
    kaigi::KaigiRelayHealthStatus,
};
use iroha_data_model::{events::data::sorafs::SorafsProofHealthAlert, oracle::OraclePenaltyKind};
use iroha_futures::supervisor::{Child, OnShutdown};
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_model_base::domain::DomainId;
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_model_base::name::Name;
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_model_base::peer::PeerId;
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_p2p::OnlinePeers;
use iroha_primitives::numeric::Quantity;
#[cfg(feature = "telemetry")]
use iroha_primitives::numeric::XOR_QUANTITY_SCALE;
use iroha_primitives::{json::Json, numeric::Numeric, time::TimeSource};
#[cfg(feature = "telemetry")]
use iroha_telemetry::metrics::GaugeVec;
pub use iroha_telemetry::metrics::musubi::{
    MusubiCacheOperationV1, MusubiCursorFailureReasonV1, MusubiGovernanceActionV1,
    MusubiGovernanceRejectionReasonV1, MusubiIngestDeadletterReasonV1, MusubiIntegritySurfaceV1,
    MusubiPublicationPhaseMetricV1,
};
pub use iroha_telemetry::metrics::{
    GOVERNANCE_MANIFEST_RECENT_CAP, Metrics, SorafsGatewayRequestMetricLabels,
    SorafsGatewayResponseMetricLabels, SorafsReserveFinalizedProjection,
};
use iroha_telemetry::privacy::{
    PrivacyBucketConfig, PrivacyEventError, PrivacyShareError, SoranetSecureAggregator,
};
use iroha_torii_shared::status::{
    GovernanceManifestActivation, NexusDataspaceTeuStatus, NexusLaneTeuBuckets, NexusLaneTeuStatus,
    TxGossipCaps, TxGossipStatus,
};
use mv::storage::StorageReadOnly;
#[cfg(feature = "telemetry")]
use norito::streaming::{
    ContentKeyUpdate, EncryptionSuite, SyncDiagnostics, TelemetryAuditOutcome,
    TelemetryDecodeStats, TelemetryEncodeStats, TelemetryEnergyStats, TelemetryEvent,
    TelemetryNetworkStats, TelemetrySecurityStats,
};
#[cfg(feature = "telemetry")]
use std::collections::btree_map::Entry as BTreeEntry;
#[cfg(feature = "telemetry")]
use std::sync::Mutex;
#[cfg_attr(not(feature = "telemetry"), allow(unused_imports))]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::{RwLock, mpsc, oneshot, watch};
fn quantity_metric_parts(amount: &Quantity) -> (u64, u64) {
    let units = amount
        .as_numeric()
        .try_mantissa_u128()
        .map(|value| u64::try_from(value).unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX);
    (units, u64::from(amount.scale()))
}
#[cfg(feature = "telemetry")]
fn json_value<T: norito::json::JsonSerialize + ?Sized>(value: &T) -> norito::json::Value {
    match norito::json::to_value(value) {
        Ok(value) => value,
        Err(err) => {
            // Telemetry must never crash node startup on malformed persisted payloads.
            iroha_logger::warn!(
                ?err,
                "failed to serialize telemetry json value; emitting null"
            );
            norito::json::Value::Null
        }
    }
}
#[cfg(feature = "telemetry")]
fn telemetry_event_to_json(event: &TelemetryEvent) -> norito::json::Value {
    match event {
        TelemetryEvent::Encode(stats) => encode_event_to_json(stats),
        TelemetryEvent::Decode(stats) => decode_event_to_json(stats),
        TelemetryEvent::Network(stats) => network_event_to_json(stats),
        TelemetryEvent::Security(stats) => security_event_to_json(stats),
        TelemetryEvent::Energy(stats) => energy_event_to_json(stats),
        TelemetryEvent::AuditOutcome(outcome) => audit_outcome_to_json(outcome),
    }
}
#[cfg(feature = "telemetry")]
fn encode_event_to_json(stats: &TelemetryEncodeStats) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("kind".to_string(), norito::json!("encode"));
    map.insert("segment".to_string(), norito::json!(stats.segment));
    map.insert(
        "avg_latency_ms".to_string(),
        norito::json!(stats.avg_latency_ms),
    );
    map.insert(
        "dropped_layers".to_string(),
        norito::json!(stats.dropped_layers),
    );
    norito::json::Value::Object(map)
}
#[cfg(feature = "telemetry")]
fn decode_event_to_json(stats: &TelemetryDecodeStats) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("kind".to_string(), norito::json!("decode"));
    map.insert("segment".to_string(), norito::json!(stats.segment));
    map.insert("buffer_ms".to_string(), norito::json!(stats.buffer_ms));
    map.insert(
        "dropped_frames".to_string(),
        norito::json!(stats.dropped_frames),
    );
    map.insert(
        "max_decode_queue_ms".to_string(),
        norito::json!(stats.max_decode_queue_ms),
    );
    norito::json::Value::Object(map)
}
#[cfg(feature = "telemetry")]
fn network_event_to_json(stats: &TelemetryNetworkStats) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("kind".to_string(), norito::json!("network"));
    map.insert("rtt_ms".to_string(), norito::json!(stats.rtt_ms));
    map.insert(
        "loss_percent_x100".to_string(),
        norito::json!(stats.loss_percent_x100),
    );
    map.insert("fec_repairs".to_string(), norito::json!(stats.fec_repairs));
    map.insert(
        "fec_failures".to_string(),
        norito::json!(stats.fec_failures),
    );
    map.insert(
        "datagram_reinjects".to_string(),
        norito::json!(stats.datagram_reinjects),
    );
    norito::json::Value::Object(map)
}
#[cfg(feature = "telemetry")]
fn security_event_to_json(stats: &TelemetrySecurityStats) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("kind".to_string(), norito::json!("security"));
    map.insert(
        "suite".to_string(),
        StreamingTelemetry::suite_to_json(&stats.suite),
    );
    map.insert("rekeys".to_string(), norito::json!(stats.rekeys));
    map.insert(
        "gck_rotations".to_string(),
        norito::json!(stats.gck_rotations),
    );
    if let Some(key_id) = &stats.last_content_key_id {
        map.insert("last_content_key_id".to_string(), norito::json!(key_id));
    }
    if let Some(valid_from) = stats.last_content_key_valid_from {
        map.insert(
            "last_content_key_valid_from".to_string(),
            norito::json!(valid_from),
        );
    }
    norito::json::Value::Object(map)
}
#[cfg(feature = "telemetry")]
fn energy_event_to_json(stats: &TelemetryEnergyStats) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("kind".to_string(), norito::json!("energy"));
    map.insert("segment".to_string(), norito::json!(stats.segment));
    map.insert(
        "encoder_milliwatts".to_string(),
        norito::json!(stats.encoder_milliwatts),
    );
    map.insert(
        "decoder_milliwatts".to_string(),
        norito::json!(stats.decoder_milliwatts),
    );
    norito::json::Value::Object(map)
}
#[cfg(feature = "telemetry")]
fn audit_outcome_to_json(outcome: &TelemetryAuditOutcome) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("kind".to_string(), norito::json!("audit_outcome"));
    map.insert("trace_id".to_string(), norito::json!(outcome.trace_id));
    map.insert(
        "slot_height".to_string(),
        norito::json!(outcome.slot_height),
    );
    map.insert("reviewer".to_string(), norito::json!(outcome.reviewer));
    map.insert("status".to_string(), norito::json!(outcome.status));
    if let Some(url) = &outcome.mitigation_url {
        map.insert("mitigation_url".to_string(), norito::json!(url));
    }
    norito::json::Value::Object(map)
}
#[cfg_attr(not(feature = "telemetry"), allow(dead_code))]
#[inline]
fn u64_to_f64(value: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        value as f64
    }
}
#[cfg(feature = "telemetry")]
fn quantity_to_nano_saturating(value: &Quantity) -> u128 {
    fn scaled_mantissa(value: &Numeric) -> u128 {
        let Some(mantissa) = value.try_mantissa_u128() else {
            return u128::MAX;
        };
        mantissa.saturating_mul(10_u128.pow(XOR_QUANTITY_SCALE.saturating_sub(value.scale())))
    }
    if value.scale() <= XOR_QUANTITY_SCALE {
        return scaled_mantissa(value.as_numeric());
    }
    // This is a fixed-unit, presentation-only nano-XOR gauge. Keep the event's
    // exact Quantity untouched and use an explicit deterministic projection
    // only for that metric.
    value
        .as_numeric()
        .try_quantize(
            XOR_QUANTITY_SCALE,
            iroha_primitives::numeric::RoundingMode::TowardZero,
        )
        .map_or(0, |projected| scaled_mantissa(&projected))
}
#[derive(Clone, Debug)]
struct LaneMetadataSnapshot {
    alias: String,
    dataspace_id: DataSpaceId,
    dataspace_alias: Option<String>,
    visibility: LaneVisibility,
    storage_profile: LaneStorageProfile,
    lane_type: Option<String>,
    governance: Option<String>,
    settlement: Option<String>,
    scheduler_teu_capacity: Option<u64>,
    scheduler_starvation_bound_slots: Option<u64>,
}
impl Default for LaneMetadataSnapshot {
    fn default() -> Self {
        Self {
            alias: String::new(),
            dataspace_id: DataSpaceId::UNIVERSAL,
            dataspace_alias: None,
            visibility: LaneVisibility::Public,
            storage_profile: LaneStorageProfile::FullReplica,
            lane_type: None,
            governance: None,
            settlement: None,
            scheduler_teu_capacity: None,
            scheduler_starvation_bound_slots: None,
        }
    }
}
#[derive(Clone, Debug, Default)]
struct DataspaceMetadataSnapshot {
    alias: String,
    description: Option<String>,
    fault_tolerance: u32,
}
#[derive(Clone, Debug, Default)]
struct DataspaceLabelSet {
    alias: String,
    profile: String,
    dataspace_id: String,
}
#[derive(Clone, Debug, Default)]
struct SpaceDirectoryActiveIndex {
    entries: BTreeSet<(UniversalAccountId, u64)>,
    counts: BTreeMap<u64, u64>,
}
impl SpaceDirectoryActiveIndex {
    fn clear(&mut self) {
        self.entries.clear();
        self.counts.clear();
    }
    fn insert(&mut self, uaid: UniversalAccountId, dataspace: u64) {
        if self.entries.insert((uaid, dataspace)) {
            *self.counts.entry(dataspace).or_default() += 1;
        }
    }
    #[cfg(feature = "telemetry")]
    fn remove(&mut self, uaid: UniversalAccountId, dataspace: u64) {
        if self.entries.remove(&(uaid, dataspace)) {
            if let Some(entry) = self.counts.get_mut(&dataspace) {
                *entry = entry.saturating_sub(1);
                if *entry == 0 {
                    self.counts.remove(&dataspace);
                }
            }
        }
    }
    #[cfg(feature = "telemetry")]
    fn count(&self, dataspace: u64) -> u64 {
        self.counts.get(&dataspace).copied().unwrap_or(0)
    }
    fn counts_snapshot(&self) -> BTreeMap<u64, u64> {
        self.counts
            .iter()
            .map(|(id, count)| (*id, *count))
            .collect()
    }
}
/// Gauge update for per-lane TEU metrics.
#[derive(Clone, Copy, Debug, Default)]
pub struct LaneTeuGaugeUpdate {
    /// Configured TEU capacity for the current slot.
    pub capacity: u64,
    /// TEU committed in the latest envelope.
    pub committed: u64,
    /// Bucket breakdown for committed TEU.
    pub buckets: NexusLaneTeuBuckets,
    /// Active circuit-breaker trigger level (0 = normal).
    pub trigger_level: u64,
    /// Starvation bound applied to this lane (in slots).
    pub starvation_bound_slots: u64,
}
const NEXUS_HEADROOM_WARN_PCT: u64 = 15;
/// Gauge update for per-dataspace TEU metrics.
#[derive(Clone, Copy, Debug, Default)]
pub struct DataspaceTeuGaugeUpdate {
    /// Pending TEU backlog remaining after scheduling.
    pub backlog: u64,
    /// Slots since the dataspace was last served.
    pub age_slots: u64,
    /// Latest SFQ virtual-finish tag.
    pub virtual_finish: u64,
}
#[cfg(test)]
/// Summary of per-lane pipeline activity for the latest block.
#[derive(Clone, Copy, Debug, Default)]
pub struct LanePipelineSummary {
    /// Block height for which this summary was recorded.
    pub block_height: u64,
    /// Transactions scheduled/executed for this lane.
    pub tx_vertices: u64,
    /// Conflict edges among the transactions for this lane.
    pub tx_edges: u64,
    /// Overlay fragments executed for this lane.
    pub overlay_count: u64,
    /// Total overlay instructions executed for this lane.
    pub overlay_instr_total: u64,
    /// Total overlay byte size executed for this lane.
    pub overlay_bytes_total: u64,
    /// RBC chunks contributed by this lane in the latest block (approximate).
    pub rbc_chunks: u64,
    /// Total payload bytes attributed to this lane for RBC chunking.
    pub rbc_bytes_total: u64,
    /// Peak scheduler layer width observed for this lane.
    pub peak_layer_width: u64,
    /// Number of scheduler layers executed for this lane.
    pub layer_count: u64,
    /// Average scheduler layer width (rounded) for this lane.
    pub avg_layer_width: u64,
    /// Median scheduler layer width for this lane.
    pub median_layer_width: u64,
    /// Scheduler utilization percentage (0..100) for this lane.
    pub scheduler_utilization_pct: u64,
    /// Histogram buckets for scheduler layer widths (le = [1,2,4,8,16,32,64,128]).
    pub layer_width_buckets: iroha_torii_shared::status::SchedulerLayerWidthBuckets,
    /// Detached overlay executions prepared in the latest block.
    pub detached_prepared: u64,
    /// Detached overlay merges applied in the latest block.
    pub detached_merged: u64,
    /// Detached overlay fallbacks applied in the latest block.
    pub detached_fallback: u64,
    /// Quarantine transactions executed for this lane.
    pub quarantine_executed: u64,
}
#[cfg(test)]
/// Per-dataspace pipeline delta for the latest block.
#[derive(Clone, Copy, Debug, Default)]
pub struct DataspacePipelineSummary {
    /// Transactions scheduled for this dataspace in the latest block.
    pub tx_served: u64,
}
#[cfg(feature = "telemetry")]
#[derive(Clone)]
struct NexusConfigDiff {
    knob: &'static str,
    baseline: norito::json::Value,
    current: norito::json::Value,
}
#[cfg(feature = "telemetry")]
fn push_nexus_diff(
    diffs: &mut Vec<NexusConfigDiff>,
    knob: &'static str,
    baseline: norito::json::Value,
    current: norito::json::Value,
) {
    if baseline != current {
        diffs.push(NexusConfigDiff {
            knob,
            baseline,
            current,
        });
    }
}
#[cfg(feature = "telemetry")]
#[derive(Clone, Copy, Debug)]
/// Aggregated counters for confidential Merkle tree maintenance.
pub struct ConfidentialTreeStats {
    /// Total number of commitments stored in the tree.
    pub commitments: u64,
    /// Current depth of the tree.
    pub tree_depth: u64,
    /// Count of root history records retained.
    pub root_history: u64,
    /// Number of checkpoints currently tracked for the frontier.
    pub frontier_checkpoints: u64,
    /// Height of the latest recorded frontier checkpoint (0 when none exists).
    pub last_checkpoint_height: u64,
    /// Commitment count captured alongside the latest checkpoint.
    pub last_checkpoint_commitments: u64,
    /// How many times the root history evicted entries.
    pub root_evictions: u64,
    /// How many times the frontier evicted entries.
    pub frontier_evictions: u64,
}
fn proof_status_label(status: ProofStatus) -> &'static str {
    use ProofStatus as PS;
    match status {
        PS::Submitted => "submitted",
        PS::Verified => "verified",
        PS::Rejected => "rejected",
    }
}
fn proposal_status_label(status: crate::state::GovernanceProposalStatus) -> &'static str {
    use crate::state::GovernanceProposalStatus as GPS;
    match status {
        GPS::Proposed => "proposed",
        GPS::Rejected => "rejected",
        GPS::Enacted => "enacted",
        GPS::Superseded => "superseded",
        GPS::ExecutionFailed => "execution_failed",
    }
}
#[cfg(feature = "telemetry")]
fn parliament_transition_label(
    kind: iroha_data_model::isi::governance::ParliamentLifecycleTransitionKindV1,
) -> &'static str {
    use iroha_data_model::isi::governance::ParliamentLifecycleTransitionKindV1 as Kind;
    match kind {
        Kind::EscalateRisk => "escalate_risk",
        Kind::CompleteQualification => "complete_qualification",
        Kind::RegisterSortitionRequest => "register_sortition_request",
        Kind::RegisterInitialSortition => "register_initial_sortition",
        Kind::ConsumeSortitionPulseBatch => "consume_sortition_pulse_batch",
        Kind::BeginInvitationAcceptance => "begin_invitation_acceptance",
        Kind::FailBodyElectionNoRoster => "fail_body_election_no_roster",
        Kind::SealBodyRoster => "seal_body_roster",
        Kind::AdvanceBodyPhase => "advance_body_phase",
        Kind::RecordAttemptAbsence => "record_attempt_absence",
        Kind::EndorsePublicFinding => "endorse_public_finding",
        Kind::FailPublicFindingNoResult => "fail_public_finding_no_result",
        Kind::RegisterBallotAttempt => "register_ballot_attempt",
        Kind::CloseBallotRegistration => "close_ballot_registration",
        Kind::FreezeBallotSurvivors => "freeze_ballot_survivors",
        Kind::FreezeTimedOvnCorpus => "freeze_timed_ovn_corpus",
        Kind::BeginBallotOpeningBatch => "begin_ballot_opening_batch",
        Kind::FailBallotNoResult => "fail_ballot_no_result",
        Kind::FinalizeOpenedBallot => "finalize_opened_ballot",
        Kind::MarkEnacted => "mark_enacted",
        Kind::MarkSuperseded => "mark_superseded",
        Kind::MarkExecutionFailed => "mark_execution_failed",
        Kind::RecordInvitationResponse => "record_invitation_response",
        Kind::RegisterBallotParticipant => "register_ballot_participant",
        Kind::RecordBallotDropout => "record_ballot_dropout",
    }
}
#[cfg(feature = "telemetry")]
fn parliament_no_result_label(
    kind: iroha_data_model::governance::types::ParliamentNoResultKindV1,
) -> &'static str {
    use iroha_data_model::governance::types::ParliamentNoResultKindV1 as Kind;
    match kind {
        Kind::PublicFindingQuorumUnreachable => "public_finding_quorum_unreachable",
        Kind::PublicFindingDeadlineExpired => "public_finding_deadline_expired",
        Kind::BallotRegistrationDeadlineExpired => "ballot_registration_deadline_expired",
        Kind::BallotSurvivorDeadlineExpired => "ballot_survivor_deadline_expired",
        Kind::BallotCommitmentDeadlineExpired => "ballot_commitment_deadline_expired",
        Kind::BallotReleasePulseUnavailable => "ballot_release_pulse_unavailable",
        Kind::BallotOpeningDeadlineExpired => "ballot_opening_deadline_expired",
        Kind::SortitionRetriesExhausted => "sortition_retries_exhausted",
        Kind::ConfirmationJuryCapacityUnavailable => "confirmation_jury_capacity_unavailable",
        Kind::RandomnessRedrawBudgetExhausted => "randomness_redraw_budget_exhausted",
    }
}
#[cfg(feature = "telemetry")]
fn parliament_no_result_matches_transition(
    transition: iroha_data_model::isi::governance::ParliamentLifecycleTransitionKindV1,
    no_result: iroha_data_model::governance::types::ParliamentNoResultKindV1,
) -> bool {
    use iroha_data_model::{
        governance::types::ParliamentNoResultKindV1 as NoResult,
        isi::governance::ParliamentLifecycleTransitionKindV1 as Transition,
    };
    match no_result {
        NoResult::PublicFindingQuorumUnreachable => matches!(
            transition,
            Transition::RecordAttemptAbsence | Transition::EndorsePublicFinding
        ),
        NoResult::PublicFindingDeadlineExpired => {
            transition == Transition::FailPublicFindingNoResult
        }
        NoResult::BallotRegistrationDeadlineExpired
        | NoResult::BallotSurvivorDeadlineExpired
        | NoResult::BallotCommitmentDeadlineExpired
        | NoResult::BallotReleasePulseUnavailable
        | NoResult::BallotOpeningDeadlineExpired => transition == Transition::FailBallotNoResult,
        NoResult::SortitionRetriesExhausted => transition == Transition::FailBodyElectionNoRoster,
        NoResult::ConfirmationJuryCapacityUnavailable
        | NoResult::RandomnessRedrawBudgetExhausted => {
            transition == Transition::FinalizeOpenedBallot
        }
    }
}
#[cfg(feature = "telemetry")]
fn parliament_attempt_status_label(
    status: iroha_data_model::governance::types::GovernanceAttemptStatusV1,
) -> &'static str {
    use iroha_data_model::governance::types::GovernanceAttemptStatusV1 as Status;
    match status {
        Status::Active => "active",
        Status::Certified => "certified",
        Status::Rejected => "rejected",
        Status::Enacted => "enacted",
        Status::Superseded => "superseded",
        Status::ExecutionFailed => "execution_failed",
    }
}
#[cfg(feature = "telemetry")]
fn parliament_attempt_stage_label(
    stage: iroha_data_model::governance::types::GovernanceStageV1,
) -> &'static str {
    use iroha_data_model::governance::types::GovernanceStageV1 as Stage;
    match stage {
        Stage::Qualification => "qualification",
        Stage::Rules => "rules",
        Stage::Agenda => "agenda",
        Stage::Interest => "interest",
        Stage::Review => "review",
        Stage::Coordination => "coordination",
        Stage::Mpc => "mpc",
        Stage::Fma => "fma",
        Stage::Oversight => "oversight",
        Stage::PolicyJury => "policy_jury",
        Stage::ConfirmationJury => "confirmation_jury",
        Stage::Certification => "certification",
        Stage::Enactment => "enactment",
    }
}
/// Reduce a committed governance event to its bounded Parliament metric fields.
///
/// The projection intentionally drops every identifier, digest, certificate,
/// automatic-outcome payload, and private-protocol record.
#[cfg(feature = "telemetry")]
pub(crate) fn parliament_lifecycle_metric_projection(
    event: &GovernanceEvent,
) -> Option<(
    iroha_data_model::isi::governance::ParliamentLifecycleTransitionKindV1,
    Option<iroha_data_model::governance::types::ParliamentNoResultKindV1>,
)> {
    let GovernanceEvent::ParliamentLifecycleTransitionApplied(payload) = event else {
        return None;
    };
    Some((payload.transition_kind, payload.no_result_kind))
}
#[cfg(test)]
#[cfg(feature = "telemetry")]
fn access_set_source_label(source: AccessSetSource) -> &'static str {
    match source {
        AccessSetSource::ManifestHints => "manifest_hints",
        AccessSetSource::EntrypointHints => "entrypoint_hints",
        AccessSetSource::PrepassMerge => "prepass_merge",
        AccessSetSource::ConservativeFallback => "conservative_fallback",
    }
}
/// Snapshot of the last observed AXT proof cache state for a dataspace.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
pub struct AxtProofCacheStatus {
    /// Dataspace identifier.
    pub dataspace: DataSpaceId,
    /// Cache status label (hit/miss/reject/expired/cleared).
    pub status: String,
    /// Manifest root the proof was validated against (if any).
    pub manifest_root: Option<[u8; 32]>,
    /// Slot at which the proof was verified.
    pub verified_slot: u64,
    /// Expiry slot (with skew applied) recorded for the proof.
    pub expiry_slot: Option<u64>,
}
/// Snapshot of the latest AXT policy rejection for debugging/alerting.
#[derive(Copy, Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
pub struct AxtPolicyRejectSnapshot {
    /// Lane associated with the rejected usage.
    pub lane: LaneId,
    /// Reason label describing the reject category.
    pub reason: AxtRejectReason,
    /// AXT policy snapshot version active when the rejection occurred.
    pub snapshot_version: u64,
}
/// Aggregate AXT debug status returned over Torii debug endpoints.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
pub struct AxtDebugStatus {
    /// Current AXT policy snapshot version observed by the host.
    pub policy_snapshot_version: u64,
    /// Most recent rejection (if any).
    pub last_reject: Option<AxtPolicyRejectSnapshot>,
    /// Cached proof state by dataspace.
    pub cache: Vec<AxtProofCacheStatus>,
    /// Optional hints for refreshing handles after a rejection.
    pub hints: Vec<AxtRejectHint>,
}
/// Hint to help callers refresh handles after a rejected AXT envelope.
#[derive(Copy, Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
pub struct AxtRejectHint {
    /// Dataspace associated with the rejected handle.
    pub dataspace: DataSpaceId,
    /// Target lane for the handle.
    pub target_lane: LaneId,
    /// Exact active handle era required by the policy.
    pub active_handle_era: u64,
    /// Exact next handle counter required by the policy.
    pub next_handle_counter: u64,
    /// Reason label for the rejection (e.g., `era`, `sub_nonce`, `expiry`).
    pub reason: AxtRejectReason,
}
/// Slice of metrics used to be used from within [`State`].
///
/// Needed to brake the circular dependency from [`Telemetry`] to [`State`].
#[derive(Clone)]
pub struct StateTelemetry {
    metrics: Arc<Metrics>,
    enabled: bool,
    time_source: TimeSource,
    lane_metadata: Arc<StdRwLock<BTreeMap<u32, LaneMetadataSnapshot>>>,
    dataspace_metadata: Arc<StdRwLock<BTreeMap<u64, DataspaceMetadataSnapshot>>>,
    lane_manifest_registry: Arc<StdRwLock<Option<LaneManifestRegistryHandle>>>,
    space_directory_active_index: Arc<StdRwLock<SpaceDirectoryActiveIndex>>,
    soranet_privacy: Arc<SoranetSecureAggregator>,
    axt_proof_cache: Arc<StdRwLock<BTreeMap<DataSpaceId, AxtProofCacheStatus>>>,
    axt_last_policy_reject: Arc<StdRwLock<Option<AxtPolicyRejectSnapshot>>>,
    axt_policy_snapshot_version: Arc<AtomicU64>,
    axt_reject_hints: Arc<StdRwLock<BTreeMap<DataSpaceId, AxtRejectHint>>>,
    #[cfg(feature = "telemetry")]
    governance_status_cache: Arc<Mutex<BTreeMap<[u8; 32], crate::state::GovernanceProposalStatus>>>,
}
include!("telemetry/enabled_metric_macros.rs");
impl StateTelemetry {
    /// Create from [`Metrics`]
    pub fn new(metrics: Arc<Metrics>, enabled: bool) -> Self {
        Self::with_privacy_config(metrics, enabled, PrivacyBucketConfig::default())
    }
    /// Access the underlying metrics registry.
    #[cfg(all(test, feature = "telemetry"))]
    pub(crate) fn metrics_ref(&self) -> &Metrics {
        &self.metrics
    }
    /// Create a [`StateTelemetry`] instance using an explicit `SoraNet` privacy bucket configuration.
    pub fn with_privacy_config(
        metrics: Arc<Metrics>,
        enabled: bool,
        privacy_config: PrivacyBucketConfig,
    ) -> Self {
        let soranet_privacy = Arc::new(
            SoranetSecureAggregator::new(privacy_config).expect("valid SoraNet privacy config"),
        );
        let telemetry = Self {
            metrics,
            enabled,
            time_source: TimeSource::new_system(),
            lane_metadata: Arc::new(StdRwLock::new(BTreeMap::new())),
            dataspace_metadata: Arc::new(StdRwLock::new(BTreeMap::new())),
            lane_manifest_registry: Arc::new(StdRwLock::new(None)),
            space_directory_active_index: Arc::new(StdRwLock::new(
                SpaceDirectoryActiveIndex::default(),
            )),
            soranet_privacy,
            axt_proof_cache: Arc::new(StdRwLock::new(BTreeMap::new())),
            axt_last_policy_reject: Arc::new(StdRwLock::new(None)),
            axt_policy_snapshot_version: Arc::new(AtomicU64::new(0)),
            axt_reject_hints: Arc::new(StdRwLock::new(BTreeMap::new())),
            #[cfg(feature = "telemetry")]
            governance_status_cache: Arc::new(Mutex::new(BTreeMap::new())),
        };
        telemetry.set_nexus_catalogs(&LaneCatalog::default(), &DataSpaceCatalog::default());
        telemetry
    }
    /// Create [`StateTelemetry`] using parameters supplied from configuration.
    pub fn from_privacy_parameters(
        metrics: Arc<Metrics>,
        enabled: bool,
        privacy: &iroha_config::parameters::actual::SoranetPrivacy,
    ) -> Self {
        let privacy_config = PrivacyBucketConfig {
            bucket_secs: privacy.bucket_secs,
            min_contributors: privacy.min_handshakes,
            flush_delay_buckets: privacy.flush_delay_buckets,
            force_flush_buckets: privacy.force_flush_buckets,
            max_completed_buckets: privacy.max_completed_buckets,
            expected_shares: privacy.expected_shares,
            max_share_lag_buckets: privacy.max_share_lag_buckets,
        };
        Self::with_privacy_config(metrics, enabled, privacy_config)
    }
    /// Access the `SoraNet` privacy aggregator.
    pub fn soranet_privacy(&self) -> Arc<SoranetSecureAggregator> {
        Arc::clone(&self.soranet_privacy)
    }
    /// Observe state_write_lock wait/hold durations during block commit.
    pub fn observe_state_commit_write_lock(&self, wait: Duration, hold: Duration) {
        if !self.enabled {
            return;
        }
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let hold_ms = u64::try_from(hold.as_millis()).unwrap_or(u64::MAX);
        self.metrics
            .state_commit_write_lock_wait_ms
            .observe(u64_to_f64(wait_ms));
        self.metrics
            .state_commit_write_lock_hold_ms
            .observe(u64_to_f64(hold_ms));
    }
    /// Replace the cached Nexus lane/dataspace metadata used for telemetry labels.
    pub fn set_nexus_catalogs(
        &self,
        lane_catalog: &LaneCatalog,
        dataspace_catalog: &DataSpaceCatalog,
    ) {
        self.metrics
            .nexus_lane_configured_total
            .set(u64::from(lane_catalog.lane_count().get()));
        let lane_ids: Vec<u32> = lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.id.as_u32())
            .collect();
        let dataspace_lookup: BTreeMap<u64, DataspaceMetadataSnapshot> = dataspace_catalog
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.id.as_u64(),
                    DataspaceMetadataSnapshot {
                        alias: entry.alias.clone(),
                        description: entry.description.clone(),
                        fault_tolerance: entry.fault_tolerance,
                    },
                )
            })
            .collect();
        {
            let mut guard = self
                .lane_metadata
                .write()
                .expect("lane metadata lock poisoned");
            guard.clear();
            for lane in lane_catalog.lanes() {
                let dataspace_alias = dataspace_lookup
                    .get(&lane.dataspace_id.as_u64())
                    .map(|entry| entry.alias.clone());
                let scheduler_teu_capacity = lane
                    .scheduler
                    .as_ref()
                    .and_then(|policy| policy.teu_capacity)
                    .map(NonZeroU64::get);
                let scheduler_starvation_bound_slots = lane
                    .scheduler
                    .as_ref()
                    .and_then(|policy| policy.starvation_bound_slots)
                    .map(NonZeroU64::get);
                guard.insert(
                    lane.id.as_u32(),
                    LaneMetadataSnapshot {
                        alias: lane.alias.clone(),
                        dataspace_id: lane.dataspace_id,
                        dataspace_alias,
                        visibility: lane.visibility,
                        storage_profile: lane.storage,
                        lane_type: lane.lane_type.clone(),
                        governance: lane.governance.clone(),
                        settlement: lane.settlement.clone(),
                        scheduler_teu_capacity,
                        scheduler_starvation_bound_slots,
                    },
                );
            }
        }
        self.refresh_lane_metadata_cache();
        {
            let mut guard = self
                .dataspace_metadata
                .write()
                .expect("dataspace metadata lock poisoned");
            guard.clear();
            for (dataspace_id, snapshot) in &dataspace_lookup {
                guard.insert(*dataspace_id, snapshot.clone());
            }
        }
        self.refresh_dataspace_metadata_cache(&lane_ids);
        self.refresh_space_directory_active_gauges();
    }
    fn refresh_lane_metadata_cache(&self) {
        let snapshots: Vec<(u32, LaneMetadataSnapshot)> = {
            let guard = self
                .lane_metadata
                .read()
                .expect("lane metadata lock poisoned");
            guard.iter().map(|(k, v)| (*k, v.clone())).collect()
        };
        let valid_lane_ids: BTreeSet<u32> = snapshots.iter().map(|(id, _)| *id).collect();
        let mut guard = self
            .metrics
            .nexus_scheduler_lane_teu_status
            .write()
            .expect("lane TEU cache poisoned");
        for (lane_id, info) in snapshots {
            let entry = guard.entry(lane_id).or_insert_with(|| NexusLaneTeuStatus {
                lane_id,
                ..NexusLaneTeuStatus::default()
            });
            entry.lane_id = lane_id;
            if entry.block_height == 0 {
                entry.block_height = self.metrics.block_height.get();
            }
            entry.alias.clone_from(&info.alias);
            entry.dataspace_id = info.dataspace_id.as_u64();
            entry.dataspace_alias.clone_from(&info.dataspace_alias);
            entry.visibility = Some(info.visibility.as_str().to_string());
            entry.storage_profile = info.storage_profile.as_str().to_string();
            entry.lane_type.clone_from(&info.lane_type);
            entry.governance.clone_from(&info.governance);
            entry.settlement.clone_from(&info.settlement);
            entry.scheduler_teu_capacity_override = info.scheduler_teu_capacity;
            entry.scheduler_starvation_bound_override = info.scheduler_starvation_bound_slots;
            self.apply_manifest_status(LaneId::new(lane_id), entry);
        }
        guard.retain(|lane_id, _| valid_lane_ids.contains(lane_id));
    }
    fn refresh_dataspace_metadata_cache(&self, lane_ids: &[u32]) {
        let snapshot_map: BTreeMap<u64, DataspaceMetadataSnapshot> = {
            let guard = self
                .dataspace_metadata
                .read()
                .expect("dataspace metadata lock poisoned");
            guard.iter().map(|(k, v)| (*k, v.clone())).collect()
        };
        let lane_id_set: BTreeSet<u32> = lane_ids.iter().copied().collect();
        let mut guard = self
            .metrics
            .nexus_scheduler_dataspace_teu_status
            .write()
            .expect("dataspace TEU cache poisoned");
        guard.retain(|(lane_id, dataspace_id), _| {
            lane_id_set.contains(lane_id) && snapshot_map.contains_key(dataspace_id)
        });
        for lane_id in lane_ids {
            for (dataspace_id, info) in &snapshot_map {
                let entry = guard.entry((*lane_id, *dataspace_id)).or_insert_with(|| {
                    NexusDataspaceTeuStatus {
                        lane_id: *lane_id,
                        dataspace_id: *dataspace_id,
                        ..NexusDataspaceTeuStatus::default()
                    }
                });
                entry.lane_id = *lane_id;
                entry.dataspace_id = *dataspace_id;
                entry.alias.clone_from(&info.alias);
                entry.description.clone_from(&info.description);
                entry.fault_tolerance = info.fault_tolerance;
            }
        }
    }
    fn dataspace_labels(&self, dataspace: DataSpaceId) -> DataspaceLabelSet {
        let id = dataspace.as_u64();
        if let Ok(guard) = self.dataspace_metadata.read() {
            if let Some(entry) = guard.get(&id) {
                let profile = entry
                    .description
                    .clone()
                    .unwrap_or_else(|| entry.alias.clone());
                return DataspaceLabelSet {
                    alias: entry.alias.clone(),
                    profile,
                    dataspace_id: id.to_string(),
                };
            }
        }
        let fallback = format!("dataspace-{id}");
        DataspaceLabelSet {
            alias: fallback.clone(),
            profile: fallback.clone(),
            dataspace_id: id.to_string(),
        }
    }
    /// Record the configured caps and frame limits for transaction gossip.
    #[allow(clippy::too_many_arguments)]
    pub fn record_tx_gossip_caps(
        &self,
        frame_cap_bytes: usize,
        public_cap: Option<usize>,
        restricted_cap: Option<usize>,
        drop_unknown: bool,
        public_target_reshuffle: std::time::Duration,
        restricted_target_reshuffle: std::time::Duration,
    ) {
        if !self.is_enabled() {
            return;
        }
        let public_target_reshuffle_ms =
            u64::try_from(public_target_reshuffle.as_millis()).unwrap_or(u64::MAX);
        let restricted_target_reshuffle_ms =
            u64::try_from(restricted_target_reshuffle.as_millis()).unwrap_or(u64::MAX);
        self.metrics
            .tx_gossip_frame_cap_bytes
            .set(frame_cap_bytes as u64);
        self.metrics
            .tx_gossip_public_target_cap
            .set(public_cap.map_or(0, |cap| cap as u64));
        self.metrics
            .tx_gossip_restricted_target_cap
            .set(restricted_cap.map_or(0, |cap| cap as u64));
        self.metrics
            .tx_gossip_public_target_reshuffle_ms
            .set(public_target_reshuffle_ms);
        self.metrics
            .tx_gossip_restricted_target_reshuffle_ms
            .set(restricted_target_reshuffle_ms);
        self.metrics
            .tx_gossip_drop_unknown_dataspace
            .set(u64::from(drop_unknown));
        let mut caps = self
            .metrics
            .tx_gossip_caps
            .write()
            .expect("tx gossip caps cache poisoned");
        *caps = TxGossipCaps {
            frame_cap_bytes: frame_cap_bytes as u64,
            public_target_cap: public_cap.map(|cap| cap as u64),
            restricted_target_cap: restricted_cap.map(|cap| cap as u64),
            public_target_reshuffle_ms: Some(public_target_reshuffle_ms),
            restricted_target_reshuffle_ms: Some(restricted_target_reshuffle_ms),
            drop_unknown_dataspace: drop_unknown,
        };
    }
    /// Record a transaction gossip attempt (sent or dropped) with labels for status/metrics.
    #[allow(clippy::too_many_arguments)]
    pub fn record_tx_gossip_attempt(
        &self,
        plane: GossipPlane,
        dataspace: DataSpaceId,
        lane_ids: &[LaneId],
        targets: &[PeerId],
        target_cap: Option<NonZeroUsize>,
        sent: bool,
        reason: Option<&str>,
        batch_txs: usize,
        frame_bytes: usize,
    ) {
        if !self.is_enabled() {
            return;
        }
        let mut target_peers: Vec<String> = targets.iter().map(ToString::to_string).collect();
        target_peers.sort();
        target_peers.dedup();
        let target_count = targets.len();
        let target_cap_value = target_cap.map_or(0, NonZeroUsize::get) as u64;
        let plane_label = gossip_plane_label(plane);
        let ds_label = dataspace.as_u64().to_string();
        if sent {
            self.metrics
                .tx_gossip_sent_total
                .with_label_values(&[plane_label, ds_label.as_str()])
                .inc();
            self.metrics
                .tx_gossip_targets
                .with_label_values(&[plane_label, ds_label.as_str()])
                .set(target_count as u64);
        } else {
            let reason = reason.unwrap_or("unknown");
            self.metrics
                .tx_gossip_dropped_total
                .with_label_values(&[plane_label, ds_label.as_str(), reason])
                .inc();
            self.metrics
                .tx_gossip_targets
                .with_label_values(&[plane_label, ds_label.as_str()])
                .set(0);
        }
        let dataspace_alias = self
            .dataspace_metadata
            .read()
            .expect("dataspace metadata lock poisoned")
            .get(&dataspace.as_u64())
            .map(|meta| meta.alias.clone())
            .filter(|alias| !alias.is_empty());
        let mut lanes: Vec<u32> = lane_ids.iter().map(|lane| lane.as_u32()).collect();
        lanes.sort_unstable();
        lanes.dedup();
        let snapshot = TxGossipStatus {
            plane: plane_label.to_string(),
            dataspace_id: dataspace.as_u64(),
            dataspace_alias,
            lane_ids: lanes,
            targets: target_count as u64,
            target_peers,
            outcome: if sent {
                "sent".to_string()
            } else {
                "dropped".to_string()
            },
            reason: reason.map(ToOwned::to_owned),
            target_cap: target_cap_value,
            batch_txs: batch_txs as u64,
            frame_bytes: frame_bytes as u64,
        };
        let mut cache = self
            .metrics
            .tx_gossip_status
            .write()
            .expect("tx gossip status cache poisoned");
        cache.retain(|entry| {
            !(entry.plane == snapshot.plane && entry.dataspace_id == snapshot.dataspace_id)
        });
        cache.push(snapshot);
        cache.sort_by(|a, b| {
            a.plane
                .cmp(&b.plane)
                .then_with(|| a.dataspace_id.cmp(&b.dataspace_id))
        });
    }
    fn publish_space_directory_active(&self, dataspace: DataSpaceId, count: u64) {
        let labels = self.dataspace_labels(dataspace);
        self.metrics.set_space_directory_active_manifests(
            labels.alias.as_str(),
            labels.dataspace_id.as_str(),
            labels.profile.as_str(),
            count,
        );
    }
    fn refresh_space_directory_active_gauges(&self) {
        let mut dataspace_ids: BTreeSet<u64> = {
            let guard = self
                .dataspace_metadata
                .read()
                .expect("dataspace metadata lock poisoned");
            guard.keys().copied().collect()
        };
        let counts_snapshot = self
            .space_directory_active_index
            .read()
            .map(|index| {
                let snapshot = index.counts_snapshot();
                dataspace_ids.extend(snapshot.keys().copied());
                snapshot
            })
            .unwrap_or_default();
        for dataspace_id in dataspace_ids {
            let count = counts_snapshot
                .get(&dataspace_id)
                .copied()
                .unwrap_or_default();
            self.publish_space_directory_active(DataSpaceId::new(dataspace_id), count);
        }
    }
    /// Seed the cached Space Directory bindings from the on-ledger manifest registry.
    pub fn seed_space_directory_manifests(
        &self,
        manifests: &impl StorageReadOnly<UniversalAccountId, SpaceDirectoryManifestSet>,
    ) {
        let mut guard = self
            .space_directory_active_index
            .write()
            .expect("space directory cache poisoned");
        guard.clear();
        for (uaid, set) in manifests.iter() {
            for (dataspace, record) in set.iter() {
                if record.is_active() {
                    guard.insert(*uaid, dataspace.as_u64());
                }
            }
        }
        drop(guard);
        self.refresh_space_directory_active_gauges();
    }
    #[cfg(feature = "telemetry")]
    fn record_space_directory_activation(&self, uaid: UniversalAccountId, dataspace: DataSpaceId) {
        let count = {
            let mut guard = self
                .space_directory_active_index
                .write()
                .expect("space directory cache poisoned");
            guard.insert(uaid, dataspace.as_u64());
            guard.count(dataspace.as_u64())
        };
        self.publish_space_directory_active(dataspace, count);
    }
    #[cfg(feature = "telemetry")]
    fn record_space_directory_deactivation(
        &self,
        uaid: UniversalAccountId,
        dataspace: DataSpaceId,
    ) {
        let count = {
            let mut guard = self
                .space_directory_active_index
                .write()
                .expect("space directory cache poisoned");
            guard.remove(uaid, dataspace.as_u64());
            guard.count(dataspace.as_u64())
        };
        self.publish_space_directory_active(dataspace, count);
    }
    #[cfg(feature = "telemetry")]
    fn record_space_directory_revocation(&self, dataspace: DataSpaceId, reason: Option<&str>) {
        let labels = self.dataspace_labels(dataspace);
        let reason_label = reason
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unspecified");
        self.metrics.inc_space_directory_revocations(
            labels.alias.as_str(),
            labels.dataspace_id.as_str(),
            reason_label,
        );
    }
    /// Update validator lifecycle counters for a public lane.
    #[cfg(feature = "telemetry")]
    pub fn record_public_lane_validator_status(
        &self,
        lane_id: LaneId,
        previous: Option<&PublicLaneValidatorStatus>,
        current: &PublicLaneValidatorStatus,
    ) {
        if !self.is_enabled() {
            return;
        }
        if let Some(prev) = previous {
            if Self::validator_status_label(prev) == Self::validator_status_label(current) {
                return;
            }
            self.adjust_public_lane_validator_count(lane_id, prev, -1);
        }
        self.adjust_public_lane_validator_count(lane_id, current, 1);
    }
    /// Record a rejected public-lane validator operation grouped by reason.
    #[cfg(feature = "telemetry")]
    pub fn record_public_lane_validator_reject(&self, reason: &str) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .nexus_public_lane_validator_reject_total
            .with_label_values(&[reason])
            .inc();
    }
    /// Increase the bonded stake gauge for the provided lane.
    #[cfg(feature = "telemetry")]
    pub fn increase_public_lane_bonded(&self, lane_id: LaneId, amount: &Quantity) {
        self.adjust_public_lane_amount(
            &self.metrics.nexus_public_lane_stake_bonded,
            lane_id,
            amount,
            true,
        );
    }
    /// Decrease the bonded stake gauge for the provided lane.
    #[cfg(feature = "telemetry")]
    pub fn decrease_public_lane_bonded(&self, lane_id: LaneId, amount: &Quantity) {
        self.adjust_public_lane_amount(
            &self.metrics.nexus_public_lane_stake_bonded,
            lane_id,
            amount,
            false,
        );
    }
    /// Increase the pending-unbond gauge for the provided lane.
    #[cfg(feature = "telemetry")]
    pub fn increase_public_lane_pending_unbond(&self, lane_id: LaneId, amount: &Quantity) {
        self.adjust_public_lane_amount(
            &self.metrics.nexus_public_lane_unbond_pending,
            lane_id,
            amount,
            true,
        );
    }
    /// Decrease the pending-unbond gauge for the provided lane.
    #[cfg(feature = "telemetry")]
    pub fn decrease_public_lane_pending_unbond(&self, lane_id: LaneId, amount: &Quantity) {
        self.adjust_public_lane_amount(
            &self.metrics.nexus_public_lane_unbond_pending,
            lane_id,
            amount,
            false,
        );
    }
    /// Increment the slash counter for a public lane.
    #[cfg(feature = "telemetry")]
    pub fn record_public_lane_slash(&self, lane_id: LaneId) {
        if !self.is_enabled() {
            return;
        }
        let lane_label = Self::lane_label(lane_id);
        self.metrics
            .nexus_public_lane_slash_total
            .with_label_values(&[lane_label.as_str()])
            .inc();
    }
    #[cfg(feature = "telemetry")]
    fn adjust_public_lane_validator_count(
        &self,
        lane_id: LaneId,
        status: &PublicLaneValidatorStatus,
        delta: i64,
    ) {
        if !self.is_enabled() {
            return;
        }
        let lane_label = Self::lane_label(lane_id);
        let counter = self
            .metrics
            .nexus_public_lane_validator_total
            .with_label_values(&[lane_label.as_str(), Self::validator_status_label(status)]);
        let current = counter.get();
        let next = (current + delta).max(0);
        counter.set(next);
    }
    #[cfg(feature = "telemetry")]
    fn adjust_public_lane_amount(
        &self,
        gauge: &GaugeVec,
        lane_id: LaneId,
        amount: &Quantity,
        increase: bool,
    ) {
        if !self.is_enabled() {
            return;
        }
        let lane_label = Self::lane_label(lane_id);
        let metric = gauge.with_label_values(&[lane_label.as_str()]);
        let delta = amount.as_numeric().to_f64_lossy();
        let base = metric.get();
        let updated = if increase {
            base + delta
        } else {
            (base - delta).max(0.0)
        };
        metric.set(updated);
    }
    #[cfg(feature = "telemetry")]
    fn lane_label(lane_id: LaneId) -> String {
        lane_id.as_u32().to_string()
    }
    #[cfg(feature = "telemetry")]
    /// Record a public-lane validator activation event.
    pub fn record_public_lane_validator_activation(&self, lane_id: LaneId, epoch: u64) {
        if !self.is_enabled() {
            return;
        }
        let lane_label = Self::lane_label(lane_id);
        self.metrics
            .nexus_public_lane_validator_activation_total
            .with_label_values(&[lane_label.as_str()])
            .inc();
        iroha_logger::debug!(
            lane = lane_label.as_str(),
            epoch,
            "public lane validator activated"
        );
    }
    #[cfg(feature = "telemetry")]
    fn validator_status_label(status: &PublicLaneValidatorStatus) -> &'static str {
        match status {
            PublicLaneValidatorStatus::PendingActivation(_) => "pending",
            PublicLaneValidatorStatus::Active => "active",
            PublicLaneValidatorStatus::Exiting(_) => "exiting",
            PublicLaneValidatorStatus::Exited => "exited",
            PublicLaneValidatorStatus::Slashed(_) => "slashed",
        }
    }
    #[cfg(feature = "telemetry")]
    /// Compare the active Nexus configuration against the single-lane baseline, emitting a diff event.
    ///
    /// Returns a Norito JSON payload summarizing the changed knobs when differences are detected.
    pub fn record_nexus_config_diff(
        &self,
        nexus: &iroha_config::parameters::actual::Nexus,
    ) -> Option<norito::json::Value> {
        if !self.is_enabled() {
            return None;
        }
        let diffs = Self::collect_nexus_config_diffs(nexus);
        if diffs.is_empty() {
            return None;
        }
        for diff in &diffs {
            self.metrics
                .nexus_config_diff_total
                .with_label_values(&[diff.knob, "active"])
                .inc();
        }
        let payload: Vec<norito::json::Value> = diffs
            .iter()
            .map(|diff| {
                let mut map = norito::json::Map::new();
                map.insert("knob".to_string(), json_value(diff.knob));
                map.insert("baseline".to_string(), diff.baseline.clone());
                map.insert("current".to_string(), diff.current.clone());
                norito::json::Value::Object(map)
            })
            .collect();
        let mut root = norito::json::Map::new();
        root.insert("profile".to_string(), json_value("active"));
        root.insert("diffs".to_string(), norito::json::Value::Array(payload));
        Some(norito::json::Value::Object(root))
    }
    #[cfg(feature = "telemetry")]
    #[allow(clippy::too_many_lines)]
    fn collect_nexus_config_diffs(
        nexus: &iroha_config::parameters::actual::Nexus,
    ) -> Vec<NexusConfigDiff> {
        let mut diffs = Vec::new();
        let baseline_lane_catalog = LaneCatalog::default();
        let baseline_dataspace_catalog = DataSpaceCatalog::default();
        let baseline_registry = iroha_config::parameters::actual::LaneRegistry::default();
        let baseline_fusion = iroha_config::parameters::actual::Fusion::default();
        let baseline_commit = iroha_config::parameters::actual::Commit::default();
        let baseline_da = iroha_config::parameters::actual::Da::default();
        let baseline_governance = iroha_config::parameters::actual::GovernanceCatalog::default();
        push_nexus_diff(
            &mut diffs,
            "nexus.lane_catalog.count",
            json_value(&baseline_lane_catalog.lane_count().get()),
            json_value(&nexus.lane_catalog.lane_count().get()),
        );
        let baseline_lane_aliases: Vec<String> = baseline_lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.alias.clone())
            .collect();
        let current_lane_aliases: Vec<String> = nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.alias.clone())
            .collect();
        push_nexus_diff(
            &mut diffs,
            "nexus.lane_catalog.aliases",
            json_value(&baseline_lane_aliases),
            json_value(&current_lane_aliases),
        );
        let baseline_lane_details: Vec<norito::json::Value> = baseline_lane_catalog
            .lanes()
            .iter()
            .map(|lane| {
                let mut map = norito::json::Map::new();
                map.insert("id".to_string(), json_value(&lane.id.as_u32()));
                map.insert("alias".to_string(), json_value(&lane.alias));
                map.insert(
                    "dataspace_id".to_string(),
                    json_value(&lane.dataspace_id.as_u64()),
                );
                map.insert(
                    "visibility".to_string(),
                    json_value(&lane.visibility.as_str()),
                );
                map.insert("lane_type".to_string(), json_value(&lane.lane_type));
                map.insert("governance".to_string(), json_value(&lane.governance));
                map.insert("settlement".to_string(), json_value(&lane.settlement));
                map.insert("storage".to_string(), json_value(&lane.storage.as_str()));
                map.insert("metadata".to_string(), json_value(&lane.metadata));
                norito::json::Value::Object(map)
            })
            .collect();
        let current_lane_details: Vec<norito::json::Value> = nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| {
                let mut map = norito::json::Map::new();
                map.insert("id".to_string(), json_value(&lane.id.as_u32()));
                map.insert("alias".to_string(), json_value(&lane.alias));
                map.insert(
                    "dataspace_id".to_string(),
                    json_value(&lane.dataspace_id.as_u64()),
                );
                map.insert(
                    "visibility".to_string(),
                    json_value(&lane.visibility.as_str()),
                );
                map.insert("lane_type".to_string(), json_value(&lane.lane_type));
                map.insert("governance".to_string(), json_value(&lane.governance));
                map.insert("settlement".to_string(), json_value(&lane.settlement));
                map.insert("storage".to_string(), json_value(&lane.storage.as_str()));
                map.insert("metadata".to_string(), json_value(&lane.metadata));
                norito::json::Value::Object(map)
            })
            .collect();
        push_nexus_diff(
            &mut diffs,
            "nexus.lane_catalog.details",
            json_value(&baseline_lane_details),
            json_value(&current_lane_details),
        );
        push_nexus_diff(
            &mut diffs,
            "nexus.dataspace_catalog.count",
            json_value(&baseline_dataspace_catalog.entries().len()),
            json_value(&nexus.dataspace_catalog.entries().len()),
        );
        let baseline_dataspace_details: Vec<norito::json::Value> = baseline_dataspace_catalog
            .entries()
            .iter()
            .map(|entry| {
                let mut map = norito::json::Map::new();
                map.insert("id".to_string(), json_value(&entry.id.as_u64()));
                map.insert("alias".to_string(), json_value(&entry.alias));
                map.insert("description".to_string(), json_value(&entry.description));
                map.insert(
                    "fault_tolerance".to_string(),
                    json_value(&entry.fault_tolerance),
                );
                norito::json::Value::Object(map)
            })
            .collect();
        let current_dataspace_details: Vec<norito::json::Value> = nexus
            .dataspace_catalog
            .entries()
            .iter()
            .map(|entry| {
                let mut map = norito::json::Map::new();
                map.insert("id".to_string(), json_value(&entry.id.as_u64()));
                map.insert("alias".to_string(), json_value(&entry.alias));
                map.insert("description".to_string(), json_value(&entry.description));
                map.insert(
                    "fault_tolerance".to_string(),
                    json_value(&entry.fault_tolerance),
                );
                norito::json::Value::Object(map)
            })
            .collect();
        push_nexus_diff(
            &mut diffs,
            "nexus.dataspace_catalog.details",
            json_value(&baseline_dataspace_details),
            json_value(&current_dataspace_details),
        );
        push_nexus_diff(
            &mut diffs,
            "nexus.routing.default_lane",
            json_value(&LaneId::SINGLE.as_u32()),
            json_value(&nexus.routing_policy.default_lane.as_u32()),
        );
        push_nexus_diff(
            &mut diffs,
            "nexus.routing.default_dataspace",
            json_value(&DataSpaceId::UNIVERSAL.as_u64()),
            json_value(&nexus.routing_policy.default_dataspace.as_u64()),
        );
        let routing_rules: Vec<norito::json::Value> = nexus
            .routing_policy
            .rules
            .iter()
            .map(|rule| {
                let mut matcher = norito::json::Map::new();
                matcher.insert("account".to_string(), json_value(&rule.matcher.account));
                matcher.insert(
                    "instruction".to_string(),
                    json_value(&rule.matcher.instruction),
                );
                matcher.insert(
                    "description".to_string(),
                    json_value(&rule.matcher.description),
                );
                let mut map = norito::json::Map::new();
                map.insert("lane".to_string(), json_value(&rule.lane.as_u32()));
                map.insert(
                    "dataspace".to_string(),
                    json_value(&rule.dataspace.map(DataSpaceId::as_u64)),
                );
                map.insert("matcher".to_string(), norito::json::Value::Object(matcher));
                norito::json::Value::Object(map)
            })
            .collect();
        let empty_rules: Vec<norito::json::Value> = Vec::new();
        push_nexus_diff(
            &mut diffs,
            "nexus.routing.rules",
            json_value(&empty_rules),
            json_value(&routing_rules),
        );
        let registry_manifest_baseline = baseline_registry
            .manifest_directory
            .as_ref()
            .map(|path| path.display().to_string());
        let registry_manifest_current = nexus
            .registry
            .manifest_directory
            .as_ref()
            .map(|path| path.display().to_string());
        push_nexus_diff(
            &mut diffs,
            "nexus.registry.manifest_directory",
            json_value(&registry_manifest_baseline),
            json_value(&registry_manifest_current),
        );
        let registry_cache_baseline = baseline_registry
            .cache_directory
            .as_ref()
            .map(|path| path.display().to_string());
        let registry_cache_current = nexus
            .registry
            .cache_directory
            .as_ref()
            .map(|path| path.display().to_string());
        push_nexus_diff(
            &mut diffs,
            "nexus.registry.cache_directory",
            json_value(&registry_cache_baseline),
            json_value(&registry_cache_current),
        );
        push_nexus_diff(
            &mut diffs,
            "nexus.registry.poll_interval_secs",
            json_value(&baseline_registry.poll_interval.as_secs()),
            json_value(&nexus.registry.poll_interval.as_secs()),
        );
        let fusion_to_json = |fusion: &iroha_config::parameters::actual::Fusion| {
            let mut map = norito::json::Map::new();
            map.insert("floor_teu".to_string(), json_value(&fusion.floor_teu));
            map.insert("exit_teu".to_string(), json_value(&fusion.exit_teu));
            map.insert(
                "observation_slots".to_string(),
                json_value(&fusion.observation_slots.get()),
            );
            map.insert(
                "max_window_slots".to_string(),
                json_value(&fusion.max_window_slots.get()),
            );
            norito::json::Value::Object(map)
        };
        push_nexus_diff(
            &mut diffs,
            "nexus.fusion",
            fusion_to_json(&baseline_fusion),
            fusion_to_json(&nexus.fusion),
        );
        let commit_to_json = |commit: &iroha_config::parameters::actual::Commit| {
            let mut map = norito::json::Map::new();
            map.insert(
                "window_slots".to_string(),
                json_value(&commit.window_slots.get()),
            );
            norito::json::Value::Object(map)
        };
        push_nexus_diff(
            &mut diffs,
            "nexus.commit",
            commit_to_json(&baseline_commit),
            commit_to_json(&nexus.commit),
        );
        let da_to_json = |da: &iroha_config::parameters::actual::Da| {
            let mut map = norito::json::Map::new();
            map.insert(
                "q_in_slot_total".to_string(),
                json_value(&da.q_in_slot_total.get()),
            );
            map.insert(
                "q_in_slot_per_ds_min".to_string(),
                json_value(&da.q_in_slot_per_ds_min.get()),
            );
            map.insert(
                "sample_size_base".to_string(),
                json_value(&da.sample_size_base.get()),
            );
            map.insert(
                "sample_size_max".to_string(),
                json_value(&da.sample_size_max.get()),
            );
            map.insert(
                "threshold_base".to_string(),
                json_value(&da.threshold_base.get()),
            );
            map.insert(
                "per_attester_shards".to_string(),
                json_value(&da.per_attester_shards.get()),
            );
            let mut audit = norito::json::Map::new();
            audit.insert(
                "sample_size".to_string(),
                json_value(&da.audit.sample_size.get()),
            );
            audit.insert(
                "window_count".to_string(),
                json_value(&da.audit.window_count.get()),
            );
            audit.insert(
                "interval_secs".to_string(),
                json_value(&da.audit.interval.as_secs()),
            );
            map.insert("audit".to_string(), norito::json::Value::Object(audit));
            let mut recovery = norito::json::Map::new();
            recovery.insert(
                "request_timeout_secs".to_string(),
                json_value(&da.recovery.request_timeout.as_secs()),
            );
            map.insert(
                "recovery".to_string(),
                norito::json::Value::Object(recovery),
            );
            let mut rotation = norito::json::Map::new();
            rotation.insert(
                "max_hits_per_window".to_string(),
                json_value(&da.rotation.max_hits_per_window.get()),
            );
            rotation.insert(
                "window_slots".to_string(),
                json_value(&da.rotation.window_slots.get()),
            );
            rotation.insert("seed_tag".to_string(), json_value(&da.rotation.seed_tag));
            rotation.insert(
                "latency_decay".to_string(),
                json_value(&da.rotation.latency_decay),
            );
            map.insert(
                "rotation".to_string(),
                norito::json::Value::Object(rotation),
            );
            norito::json::Value::Object(map)
        };
        push_nexus_diff(
            &mut diffs,
            "nexus.da",
            da_to_json(&baseline_da),
            da_to_json(&nexus.da),
        );
        push_nexus_diff(
            &mut diffs,
            "nexus.governance.default_module",
            json_value(&baseline_governance.default_module),
            json_value(&nexus.governance.default_module),
        );
        let governance_modules: Vec<norito::json::Value> = nexus
            .governance
            .modules
            .iter()
            .map(|(name, module)| {
                let mut map = norito::json::Map::new();
                map.insert("name".to_string(), json_value(name));
                map.insert("type".to_string(), json_value(&module.module_type));
                map.insert("params".to_string(), json_value(&module.params));
                norito::json::Value::Object(map)
            })
            .collect();
        push_nexus_diff(
            &mut diffs,
            "nexus.governance.modules",
            json_value(&Vec::<norito::json::Value>::new()),
            json_value(&governance_modules),
        );
        diffs
    }
    fn lane_metadata_snapshot(&self, lane_id: LaneId) -> LaneMetadataSnapshot {
        self.lane_metadata
            .read()
            .expect("lane metadata lock poisoned")
            .get(&lane_id.as_u32())
            .cloned()
            .unwrap_or_else(|| LaneMetadataSnapshot {
                alias: format!("lane-{}", lane_id.as_u32()),
                ..LaneMetadataSnapshot::default()
            })
    }
    fn dataspace_metadata_snapshot(&self, dataspace_id: DataSpaceId) -> DataspaceMetadataSnapshot {
        self.dataspace_metadata
            .read()
            .expect("dataspace metadata lock poisoned")
            .get(&dataspace_id.as_u64())
            .cloned()
            .unwrap_or_else(|| DataspaceMetadataSnapshot {
                alias: format!("dataspace-{}", dataspace_id.as_u64()),
                ..DataspaceMetadataSnapshot::default()
            })
    }
    fn apply_lane_metadata(&self, lane_id: LaneId, entry: &mut NexusLaneTeuStatus) {
        let info = self.lane_metadata_snapshot(lane_id);
        entry.alias.clone_from(&info.alias);
        entry.dataspace_id = info.dataspace_id.as_u64();
        entry.dataspace_alias.clone_from(&info.dataspace_alias);
        entry.visibility = Some(info.visibility.as_str().to_string());
        entry.storage_profile = info.storage_profile.as_str().to_string();
        entry.lane_type = info.lane_type;
        entry.governance = info.governance;
        entry.settlement = info.settlement;
    }
    fn apply_dataspace_metadata(
        &self,
        dataspace_id: DataSpaceId,
        entry: &mut NexusDataspaceTeuStatus,
    ) {
        let info = self.dataspace_metadata_snapshot(dataspace_id);
        entry.alias = info.alias;
        entry.description = info.description;
        entry.fault_tolerance = info.fault_tolerance;
    }
    fn apply_manifest_status(&self, lane_id: LaneId, entry: &mut NexusLaneTeuStatus) {
        let registry = self
            .lane_manifest_registry
            .read()
            .expect("manifest registry lock poisoned")
            .clone();
        if let Some(registry) = registry
            && let Some(status) = registry.status(lane_id)
        {
            entry.manifest_required = status.governance.is_some();
            entry.manifest_ready = registry.has_manifest(lane_id);
            entry.manifest_path = status
                .manifest_path
                .as_ref()
                .map(|path| path.display().to_string());
            entry.manifest_validators = Vec::new();
            entry.manifest_validator_bindings = Vec::new();
            entry.manifest_quorum = None;
            entry.manifest_protected_namespaces = Vec::new();
            entry.manifest_runtime_upgrade = None;
            if let Some(rules) = status.rules() {
                manifest_status::populate_manifest_rules(entry, rules);
            }
            return;
        }
        entry.manifest_required = false;
        entry.manifest_ready = true;
        entry.manifest_path = None;
        entry.manifest_validators = Vec::new();
        entry.manifest_validator_bindings = Vec::new();
        entry.manifest_quorum = None;
        entry.manifest_protected_namespaces = Vec::new();
        entry.manifest_runtime_upgrade = None;
    }
    /// Update manifest registry used by telemetry snapshots.
    pub fn set_lane_manifest_registry(&self, registry: LaneManifestRegistryHandle) {
        let statuses = registry.statuses();
        *self
            .lane_manifest_registry
            .write()
            .expect("manifest registry lock poisoned") = Some(registry);
        self.refresh_lane_metadata_cache();
        self.record_lane_governance_statuses(&statuses);
    }
    /// Update telemetry gauges reflecting governance seal status per lane.
    pub fn record_lane_governance_statuses(&self, statuses: &[LaneManifestStatus]) {
        if !self.enabled {
            return;
        }
        let previous_sealed: BTreeSet<String> = self
            .metrics
            .lane_governance_sealed_aliases()
            .into_iter()
            .collect();
        let mut current_sealed = BTreeSet::new();
        self.metrics.nexus_lane_governance_sealed.reset();
        let mut sealed_aliases = Vec::new();
        let registry = self
            .lane_manifest_registry
            .read()
            .expect("manifest registry lock poisoned")
            .clone();
        for status in statuses {
            let manifest_present = registry.as_ref().map_or_else(
                || status.manifest_path.is_some(),
                |registry| registry.has_manifest(status.lane),
            );
            let sealed = status.governance.is_some() && !manifest_present;
            self.metrics
                .nexus_lane_governance_sealed
                .with_label_values(&[status.alias.as_str()])
                .set(u64::from(sealed));
            if sealed {
                sealed_aliases.push(status.alias.clone());
                current_sealed.insert(status.alias.clone());
            }
        }
        for alias in previous_sealed.difference(&current_sealed) {
            self.metrics
                .nexus_lane_governance_sealed
                .with_label_values(&[alias.as_str()])
                .set(0);
        }
        self.metrics
            .nexus_lane_governance_sealed_total
            .set(sealed_aliases.len() as u64);
        self.metrics
            .set_lane_governance_sealed_aliases(sealed_aliases);
    }
    /// Record the latest `SoraFS` fee projection for `provider`.
    pub fn record_sorafs_fee_projection(&self, provider: &str, fee: &Quantity) {
        if self.enabled {
            self.metrics.record_sorafs_fee_projection(provider, fee);
        }
    }
    /// Increment the dispute submission counter for `SoraFS` capacity flows.
    pub fn inc_sorafs_disputes(&self, result: &'static str) {
        if self.enabled {
            self.metrics.inc_sorafs_disputes(result);
        }
    }
    /// Mirror the committed count of Musubi releases below fresh-selection quorum.
    ///
    /// This exact setter intentionally remains active while telemetry collection is
    /// disabled so enabling telemetry later exposes the current committed value.
    pub fn set_musubi_replication_shortfall_releases(&self, releases: u64) {
        self.metrics
            .musubi
            .set_replication_shortfall_releases(releases);
    }
    /// Record a rejected Musubi package, alias, or Parliament mutation.
    pub fn record_musubi_governance_rejection(
        &self,
        action: MusubiGovernanceActionV1,
        reason: MusubiGovernanceRejectionReasonV1,
    ) {
        if self.enabled {
            self.metrics.musubi.inc_governance_rejection(action, reason);
        }
    }
    /// Record one bounded Musubi finalized-query cursor failure.
    pub fn record_musubi_cursor_failure(&self, reason: MusubiCursorFailureReasonV1) {
        if self.enabled {
            self.metrics.musubi.inc_cursor_failure(reason);
        }
    }
    #[cfg(feature = "telemetry")]
    /// Mirror a data-event into telemetry gauges.
    pub fn ingest_data_event(&self, event: &DataEvent) {
        match event {
            DataEvent::Governance(ev) => self.on_governance_event(ev),
            DataEvent::Social(ev) => self.on_social_event(ev),
            DataEvent::SpaceDirectory(ev) => self.on_space_directory_event(ev),
            _ => {}
        }
    }
    /// Record the OpenSSL SM preview toggle state (0/1 gauge).
    pub fn set_sm_openssl_preview(&self, enabled: bool) {
        self.metrics.sm_openssl_preview.set(u64::from(enabled));
    }
    #[cfg(feature = "telemetry")]
    fn on_governance_event(&self, event: &GovernanceEvent) {
        use crate::state::GovernanceProposalStatus as GPS;
        match event {
            GovernanceEvent::ProposalSubmitted(payload) => {
                self.update_governance_status(payload.id, GPS::Proposed);
            }
            GovernanceEvent::ProposalRejected(payload) => {
                self.update_governance_status(payload.id, GPS::Rejected);
            }
            GovernanceEvent::ProposalEnacted(payload) => {
                self.update_governance_status(payload.id, GPS::Enacted);
            }
            GovernanceEvent::LockCreated(_) => {
                self.record_governance_bond_event("lock_created");
            }
            GovernanceEvent::LockExtended(_) => {
                self.record_governance_bond_event("lock_extended");
            }
            GovernanceEvent::LockUnlocked(_) => {
                self.record_governance_bond_event("lock_unlocked");
            }
            GovernanceEvent::LockSlashed(_) => {
                self.record_governance_bond_event("lock_slashed");
            }
            GovernanceEvent::LockRestituted(_) => {
                self.record_governance_bond_event("lock_restituted");
            }
            GovernanceEvent::BallotAccepted(_)
            | GovernanceEvent::BallotRejected(_)
            | GovernanceEvent::ReferendumOpened(_)
            | GovernanceEvent::ReferendumClosed(_)
            | GovernanceEvent::ParliamentAttemptCreated(_)
            | GovernanceEvent::ParliamentLifecycleTransitionApplied(_)
            | GovernanceEvent::ThresholdKeyLifecycleApplied(_)
            | GovernanceEvent::CitizenRegistered(_)
            | GovernanceEvent::CitizenRevoked(_)
            | GovernanceEvent::ReferendumDecided(_) => {}
        }
    }
    #[cfg(feature = "telemetry")]
    fn on_social_event(&self, event: &SocialEvent) {
        let label = match event {
            SocialEvent::RewardPaid(_) => "reward_paid",
            SocialEvent::EscrowCreated(_) => "escrow_created",
            SocialEvent::EscrowReleased(_) => "escrow_released",
            SocialEvent::EscrowCancelled(_) => "escrow_cancelled",
        };
        self.metrics
            .social_events_total
            .with_label_values(&[label])
            .inc();
        match event {
            SocialEvent::RewardPaid(payload) => {
                self.metrics
                    .social_budget_spent
                    .set(payload.budget.spent.as_numeric().to_f64_lossy());
                self.metrics
                    .social_campaign_active
                    .set(if payload.promo_active { 1.0 } else { 0.0 });
                self.metrics
                    .social_halted
                    .set(if payload.halted { 1.0 } else { 0.0 });
                if let Some(campaign) = payload.campaign.as_ref() {
                    let spent = campaign.spent.clone();
                    let cap = payload.campaign_cap.clone();
                    self.metrics
                        .social_campaign_spent
                        .set(spent.as_numeric().to_f64_lossy());
                    self.metrics
                        .social_campaign_cap
                        .set(cap.as_numeric().to_f64_lossy());
                    let remaining = cap.checked_sub(&spent).unwrap_or_else(|_| Quantity::zero());
                    self.metrics
                        .social_campaign_remaining
                        .set(remaining.as_numeric().to_f64_lossy());
                } else {
                    self.metrics
                        .social_campaign_spent
                        .set(Quantity::zero().as_numeric().to_f64_lossy());
                    self.metrics
                        .social_campaign_cap
                        .set(payload.campaign_cap.as_numeric().to_f64_lossy());
                    self.metrics
                        .social_campaign_remaining
                        .set(payload.campaign_cap.as_numeric().to_f64_lossy());
                }
            }
            SocialEvent::EscrowCreated(_) => {
                self.metrics.social_open_escrows.inc();
            }
            SocialEvent::EscrowReleased(_) | SocialEvent::EscrowCancelled(_) => {
                let current = self.metrics.social_open_escrows.get();
                if current > 0 {
                    self.metrics.social_open_escrows.dec();
                } else {
                    self.metrics.social_open_escrows.set(0);
                }
            }
        }
    }
    #[cfg(feature = "telemetry")]
    fn update_governance_status(
        &self,
        proposal_id: [u8; 32],
        new_status: crate::state::GovernanceProposalStatus,
    ) {
        let prev = {
            let mut cache = self
                .governance_status_cache
                .lock()
                .expect("governance proposal cache poisoned");
            cache.insert(proposal_id, new_status)
        };
        self.record_governance_proposal_transition(prev, new_status);
    }
    #[cfg(feature = "telemetry")]
    pub(crate) fn on_space_directory_event(&self, event: &SpaceDirectoryEvent) {
        match event {
            SpaceDirectoryEvent::ManifestActivated(payload) => {
                self.record_space_directory_activation(payload.uaid, payload.dataspace);
            }
            SpaceDirectoryEvent::ManifestExpired(payload) => {
                self.record_space_directory_deactivation(payload.uaid, payload.dataspace);
            }
            SpaceDirectoryEvent::ManifestRevoked(payload) => {
                self.record_space_directory_deactivation(payload.uaid, payload.dataspace);
                self.record_space_directory_revocation(
                    payload.dataspace,
                    payload.reason.as_deref(),
                );
            }
        }
    }
    /// Record a manifest revision for the provided dataspace.
    pub fn record_space_directory_revision(&self, dataspace: DataSpaceId) {
        let labels = self.dataspace_labels(dataspace);
        self.metrics
            .inc_space_directory_revision(labels.alias.as_str(), labels.dataspace_id.as_str());
    }
    #[cfg(feature = "telemetry")]
    /// Seed governance proposal gauges and cache with explicit id/status pairs.
    pub fn seed_governance_proposals(
        &self,
        proposals: impl IntoIterator<Item = ([u8; 32], crate::state::GovernanceProposalStatus)>,
    ) {
        use crate::state::GovernanceProposalStatus as GPS;
        let mut counts = [0u64; 5];
        let mut cache = self
            .governance_status_cache
            .lock()
            .expect("governance proposal cache poisoned");
        cache.clear();
        for (id, status) in proposals {
            cache.insert(id, status);
            match status {
                GPS::Proposed => counts[0] = counts[0].saturating_add(1),
                GPS::Rejected => counts[1] = counts[1].saturating_add(1),
                GPS::Enacted => counts[2] = counts[2].saturating_add(1),
                GPS::Superseded => counts[3] = counts[3].saturating_add(1),
                GPS::ExecutionFailed => counts[4] = counts[4].saturating_add(1),
            }
        }
        drop(cache);
        if !self.is_enabled() {
            return;
        }
        for (status, count) in [
            (GPS::Proposed, counts[0]),
            (GPS::Rejected, counts[1]),
            (GPS::Enacted, counts[2]),
            (GPS::Superseded, counts[3]),
            (GPS::ExecutionFailed, counts[4]),
        ] {
            self.metrics
                .governance_proposals_status
                .with_label_values(&[proposal_status_label(status)])
                .set(count);
        }
    }
    /// Record one accepted Parliament transition from the committed event buffer.
    ///
    /// Both labels are closed enums. Identifiers, roots, member records, ballots,
    /// shares, openings, and account labels never enter the metric registry.
    #[cfg(feature = "telemetry")]
    pub(crate) fn record_committed_parliament_transition(
        &self,
        transition: iroha_data_model::isi::governance::ParliamentLifecycleTransitionKindV1,
        no_result_kind: Option<iroha_data_model::governance::types::ParliamentNoResultKindV1>,
    ) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .governance_parliament_transitions_total
            .with_label_values(&[parliament_transition_label(transition)])
            .inc();
        if let Some(no_result_kind) = no_result_kind
            && parliament_no_result_matches_transition(transition, no_result_kind)
        {
            self.metrics
                .governance_parliament_no_result_total
                .with_label_values(&[parliament_no_result_label(no_result_kind)])
                .inc();
        }
    }
    /// Replace Parliament attempt gauges with a snapshot of committed state.
    #[cfg(all(test, feature = "telemetry"))]
    pub(crate) fn seed_parliament_attempts(
        &self,
        attempts: impl IntoIterator<
            Item = (
                iroha_data_model::governance::types::GovernanceAttemptStatusV1,
                iroha_data_model::governance::types::GovernanceStageV1,
            ),
        >,
    ) {
        use iroha_data_model::governance::types::{
            GovernanceAttemptStatusV1 as Status, GovernanceStageV1 as Stage,
        };

        let mut status_counts = [0_u64; 6];
        let mut stage_counts = [0_u64; 13];
        for (status, stage) in attempts {
            let status_index = match status {
                Status::Active => 0,
                Status::Certified => 1,
                Status::Rejected => 2,
                Status::Enacted => 3,
                Status::Superseded => 4,
                Status::ExecutionFailed => 5,
            };
            let stage_index = match stage {
                Stage::Qualification => 0,
                Stage::Rules => 1,
                Stage::Agenda => 2,
                Stage::Interest => 3,
                Stage::Review => 4,
                Stage::Coordination => 5,
                Stage::Mpc => 6,
                Stage::Fma => 7,
                Stage::Oversight => 8,
                Stage::PolicyJury => 9,
                Stage::ConfirmationJury => 10,
                Stage::Certification => 11,
                Stage::Enactment => 12,
            };
            status_counts[status_index] = status_counts[status_index].saturating_add(1);
            stage_counts[stage_index] = stage_counts[stage_index].saturating_add(1);
        }
        self.set_parliament_attempt_counts(status_counts, stage_counts);
    }

    /// Replace Parliament attempt gauges from the exact derived-state counters.
    ///
    /// Status order is Active, Certified, Rejected, Enacted, Superseded,
    /// ExecutionFailed. Stage order follows the closed `GovernanceStageV1`
    /// lifecycle from Qualification through Enactment.
    #[cfg(feature = "telemetry")]
    pub(crate) fn set_parliament_attempt_counts(
        &self,
        status_counts: [u64; 6],
        stage_counts: [u64; 13],
    ) {
        use iroha_data_model::governance::types::{
            GovernanceAttemptStatusV1 as Status, GovernanceStageV1 as Stage,
        };

        if !self.is_enabled() {
            return;
        }
        for (status, count) in [
            (Status::Active, status_counts[0]),
            (Status::Certified, status_counts[1]),
            (Status::Rejected, status_counts[2]),
            (Status::Enacted, status_counts[3]),
            (Status::Superseded, status_counts[4]),
            (Status::ExecutionFailed, status_counts[5]),
        ] {
            self.metrics
                .governance_parliament_attempts_by_status
                .with_label_values(&[parliament_attempt_status_label(status)])
                .set(count);
        }
        for (stage, count) in [
            (Stage::Qualification, stage_counts[0]),
            (Stage::Rules, stage_counts[1]),
            (Stage::Agenda, stage_counts[2]),
            (Stage::Interest, stage_counts[3]),
            (Stage::Review, stage_counts[4]),
            (Stage::Coordination, stage_counts[5]),
            (Stage::Mpc, stage_counts[6]),
            (Stage::Fma, stage_counts[7]),
            (Stage::Oversight, stage_counts[8]),
            (Stage::PolicyJury, stage_counts[9]),
            (Stage::ConfirmationJury, stage_counts[10]),
            (Stage::Certification, stage_counts[11]),
            (Stage::Enactment, stage_counts[12]),
        ] {
            self.metrics
                .governance_parliament_attempts_by_stage
                .with_label_values(&[parliament_attempt_stage_label(stage)])
                .set(count);
        }
    }
    /// Whether telemetry observations are enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// Record the latest storage budget usage for a component.
    pub fn record_storage_budget_usage(&self, component: &'static str, used: u64, limit: u64) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .storage_budget_bytes_used
            .with_label_values(&[component])
            .set(used);
        self.metrics
            .storage_budget_bytes_limit
            .with_label_values(&[component])
            .set(limit);
    }
    state_telemetry_enabled_metric_methods_early_return! {
    /// Record a storage budget exceed event for a component.
    [inc_storage_budget_exceeded(component: &'static str) =>
        .storage_budget_exceeded_total.with_label_values(&[component]).inc();]
    /// Record a DA cache hit/miss for a component.
    #[cfg(feature = "telemetry")]
    [inc_storage_da_cache(component: &'static str, result: &'static str) =>
        .storage_da_cache_total.with_label_values(&[component, result]).inc();]
    }
    /// No-op when telemetry is disabled.
    #[cfg(not(feature = "telemetry"))]
    #[allow(unused_variables)]
    pub fn inc_storage_da_cache(&self, component: &'static str, result: &'static str) {}
    /// Record DA-backed storage churn bytes for a component.
    #[cfg(feature = "telemetry")]
    pub fn add_storage_da_churn_bytes(
        &self,
        component: &'static str,
        direction: &'static str,
        bytes: u64,
    ) {
        if !self.is_enabled() || bytes == 0 {
            return;
        }
        self.metrics
            .storage_da_churn_bytes_total
            .with_label_values(&[component, direction])
            .inc_by(bytes);
    }
    /// No-op when telemetry is disabled.
    #[cfg(not(feature = "telemetry"))]
    #[allow(unused_variables)]
    pub fn add_storage_da_churn_bytes(
        &self,
        component: &'static str,
        direction: &'static str,
        bytes: u64,
    ) {
    }
    state_telemetry_enabled_metric_methods_early_return! {
    /// Record an ISI execution attempt.
    [record_isi_total(name: &str) => .isi.with_label_values(&[name, "total"]).inc();]
    /// Record a successful ISI execution.
    [record_isi_success(name: &str) => .isi.with_label_values(&[name, "success"]).inc();]
    }
    /// Record ISI execution latency.
    pub fn record_isi_time(&self, name: &str, elapsed: Duration) {
        if !self.is_enabled() {
            return;
        }
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.metrics
            .isi_times
            .with_label_values(&[name])
            .observe(u64_to_f64(elapsed_ms));
    }
    #[cfg(test)]
    #[cfg(feature = "telemetry")]
    fn lane_label_values(&self, lane_id: LaneId) -> (String, String) {
        let lane_label = lane_id.as_u32().to_string();
        let dataspace_label = self
            .lane_metadata
            .read()
            .ok()
            .and_then(|guard| guard.get(&lane_id.as_u32()).map(|entry| entry.dataspace_id))
            .unwrap_or(DataSpaceId::UNIVERSAL)
            .as_u64()
            .to_string();
        (lane_label, dataspace_label)
    }
    fn with_lane_snapshot<F>(&self, lane_id: LaneId, update: F)
    where
        F: FnOnce(&mut NexusLaneTeuStatus),
    {
        let mut guard = self
            .metrics
            .nexus_scheduler_lane_teu_status
            .write()
            .expect("lane TEU cache poisoned");
        let entry = guard
            .entry(lane_id.as_u32())
            .or_insert_with(|| NexusLaneTeuStatus {
                lane_id: lane_id.as_u32(),
                ..NexusLaneTeuStatus::default()
            });
        entry.lane_id = lane_id.as_u32();
        self.apply_lane_metadata(lane_id, entry);
        self.apply_manifest_status(lane_id, entry);
        update(entry);
    }
    fn lane_headroom_pct(update: &LaneTeuGaugeUpdate) -> u64 {
        if update.capacity == 0 {
            return 100;
        }
        update.buckets.headroom.saturating_mul(100) / update.capacity.max(1)
    }
    fn should_emit_lane_headroom_event(headroom_pct: u64, update: &LaneTeuGaugeUpdate) -> bool {
        update.capacity > 0
            && (update.buckets.headroom == 0
                || headroom_pct <= NEXUS_HEADROOM_WARN_PCT
                || update.trigger_level > 0)
    }
    fn emit_lane_headroom_event(
        &self,
        lane_id: LaneId,
        snapshot: &NexusLaneTeuStatus,
        update: &LaneTeuGaugeUpdate,
        headroom_pct: u64,
    ) -> Option<norito::json::Value> {
        if !self.is_enabled() {
            return None;
        }
        let payload = Self::build_lane_headroom_payload(lane_id, snapshot, update, headroom_pct);
        match Json::try_new(payload.clone()) {
            Ok(json) => {
                iroha_logger::telemetry!(msg = "nexus.scheduler.headroom", event = %json)
            }
            Err(err) => iroha_logger::warn!(
                ?err,
                lane = lane_id.as_u32(),
                "failed to encode lane headroom telemetry"
            ),
        }
        Some(payload)
    }
    fn build_lane_headroom_payload(
        lane_id: LaneId,
        snapshot: &NexusLaneTeuStatus,
        update: &LaneTeuGaugeUpdate,
        headroom_pct: u64,
    ) -> norito::json::Value {
        use norito::json::{Map, Value};
        let mut buckets = Map::new();
        buckets.insert("floor".into(), Value::from(update.buckets.floor));
        buckets.insert("headroom".into(), Value::from(update.buckets.headroom));
        buckets.insert("must_serve".into(), Value::from(update.buckets.must_serve));
        buckets.insert(
            "circuit_breaker".into(),
            Value::from(update.buckets.circuit_breaker),
        );
        let mut deferrals = Map::new();
        deferrals.insert(
            "cap_exceeded".into(),
            Value::from(snapshot.deferrals.cap_exceeded),
        );
        deferrals.insert(
            "envelope_limit".into(),
            Value::from(snapshot.deferrals.envelope_limit),
        );
        deferrals.insert("quota".into(), Value::from(snapshot.deferrals.quota));
        deferrals.insert(
            "circuit_breaker".into(),
            Value::from(snapshot.deferrals.circuit_breaker),
        );
        let mut payload = Map::new();
        payload.insert("lane_id".into(), Value::from(lane_id.as_u32()));
        payload.insert("capacity".into(), Value::from(update.capacity));
        payload.insert("committed".into(), Value::from(update.committed));
        payload.insert("headroom_teu".into(), Value::from(update.buckets.headroom));
        payload.insert("headroom_pct".into(), Value::from(headroom_pct));
        payload.insert("trigger_level".into(), Value::from(update.trigger_level));
        payload.insert(
            "starvation_bound_slots".into(),
            Value::from(update.starvation_bound_slots),
        );
        payload.insert("buckets".into(), Value::Object(buckets));
        payload.insert("deferrals".into(), Value::Object(deferrals));
        payload.insert(
            "must_serve_truncations".into(),
            Value::from(snapshot.must_serve_truncations),
        );
        Value::Object(payload)
    }
    #[cfg(test)]
    #[cfg(feature = "telemetry")]
    /// Record per-lane pipeline summary data for the latest block.
    pub fn record_lane_pipeline_summary(&self, lane_id: LaneId, summary: LanePipelineSummary) {
        if !self.is_enabled() {
            return;
        }
        let (lane_label, dataspace_label) = self.lane_label_values(lane_id);
        self.metrics.set_lane_block_height(
            lane_label.as_str(),
            dataspace_label.as_str(),
            summary.block_height,
        );
        self.with_lane_snapshot(lane_id, |entry| {
            entry.block_height = summary.block_height;
            entry.finality_lag_slots = 0;
            entry.tx_vertices = summary.tx_vertices;
            entry.tx_edges = summary.tx_edges;
            entry.overlay_count = summary.overlay_count;
            entry.overlay_instr_total = summary.overlay_instr_total;
            entry.overlay_bytes_total = summary.overlay_bytes_total;
            entry.rbc_chunks = summary.rbc_chunks;
            entry.rbc_bytes_total = summary.rbc_bytes_total;
            entry.peak_layer_width = summary.peak_layer_width;
            entry.layer_count = summary.layer_count;
            entry.avg_layer_width = summary.avg_layer_width;
            entry.median_layer_width = summary.median_layer_width;
            entry.scheduler_utilization_pct = summary.scheduler_utilization_pct;
            entry.layer_width_buckets = summary.layer_width_buckets;
            entry.detached_prepared = summary.detached_prepared;
            entry.detached_merged = summary.detached_merged;
            entry.detached_fallback = summary.detached_fallback;
            entry.quarantine_executed = summary.quarantine_executed;
        });
    }
    /// Record finality information derived from a lane relay envelope.
    pub fn record_lane_relay_finality(
        &self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        block_height: u64,
        head_height: u64,
        rbc_bytes_total: u64,
    ) {
        if !self.is_enabled() {
            return;
        }
        let lag = head_height.saturating_sub(block_height);
        let lane_label = lane_id.as_u32().to_string();
        let dataspace_label = dataspace_id.as_u64().to_string();
        self.metrics.set_lane_block_height(
            lane_label.as_str(),
            dataspace_label.as_str(),
            block_height,
        );
        self.metrics
            .set_lane_finality_lag(lane_label.as_str(), dataspace_label.as_str(), lag);
        self.with_lane_snapshot(lane_id, |entry| {
            entry.block_height = block_height;
            entry.finality_lag_slots = lag;
            entry.rbc_bytes_total = rbc_bytes_total;
        });
    }
    fn with_dataspace_snapshot<F>(&self, lane_id: LaneId, dataspace_id: DataSpaceId, update: F)
    where
        F: FnOnce(&mut NexusDataspaceTeuStatus),
    {
        let mut guard = self
            .metrics
            .nexus_scheduler_dataspace_teu_status
            .write()
            .expect("dataspace TEU cache poisoned");
        let key = (lane_id.as_u32(), dataspace_id.as_u64());
        let entry = guard.entry(key).or_insert_with(|| NexusDataspaceTeuStatus {
            lane_id: lane_id.as_u32(),
            dataspace_id: dataspace_id.as_u64(),
            ..NexusDataspaceTeuStatus::default()
        });
        entry.lane_id = lane_id.as_u32();
        entry.dataspace_id = dataspace_id.as_u64();
        self.apply_dataspace_metadata(dataspace_id, entry);
        update(entry);
    }
    #[cfg(test)]
    #[cfg(feature = "telemetry")]
    /// Record per-dataspace pipeline summary delta for the latest block.
    ///
    /// The in-memory `tx_served` status is cumulative and is incremented by this delta.
    pub fn record_dataspace_pipeline_summary(
        &self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        summary: DataspacePipelineSummary,
    ) {
        if !self.is_enabled() {
            return;
        }
        self.with_dataspace_snapshot(lane_id, dataspace_id, |entry| {
            entry.tx_served = entry.tx_served.saturating_add(summary.tx_served);
        });
    }
    /// Current unix timestamp in milliseconds (used for settlement event snapshots).
    #[inline]
    fn now_millis(&self) -> u64 {
        let now = self.time_source.now().as_millis();
        u64::try_from(now).unwrap_or(u64::MAX)
    }
    state_telemetry_enabled_metric_methods! {
    /// Record a successful SM helper syscall invocation.
    [note_sm_syscall_success(kind: &'static str, mode: &'static str) =>
        .sm_syscall_total.with_label_values(&[kind, mode]).inc();]
    /// Record a failed SM helper syscall invocation with a reason label.
    [note_sm_syscall_failure(kind: &'static str, mode: &'static str, reason: &'static str) =>
        .sm_syscall_failures_total.with_label_values(&[kind, mode, reason]).inc();]
    /// Record a subscription billing attempt grouped by pricing kind.
    [record_subscription_billing_attempt(pricing: &'static str) =>
        .subscription_billing_attempts_total.with_label_values(&[pricing]).inc();]
    /// Record a subscription billing outcome grouped by pricing kind and result.
    [record_subscription_billing_outcome(pricing: &'static str, outcome: &'static str) =>
        .subscription_billing_outcomes_total.with_label_values(&[pricing, outcome]).inc();]
    }
    /// Record an AXT policy rejection grouped by lane id and reason.
    pub fn note_axt_policy_reject(
        &self,
        lane: LaneId,
        reason: AxtRejectReason,
        snapshot_version: u64,
    ) {
        {
            let mut guard = self
                .axt_last_policy_reject
                .write()
                .expect("axt reject cache poisoned");
            *guard = Some(AxtPolicyRejectSnapshot {
                lane,
                reason,
                snapshot_version,
            });
        }
        if self.is_enabled() {
            let lane_label = lane.as_u32().to_string();
            let reason_label = reason.label();
            self.metrics
                .axt_policy_reject_total
                .with_label_values(&[lane_label.as_str(), reason_label])
                .inc();
        }
    }
    /// Record which source supplied the latest AXT policy snapshot (cache hit/miss).
    /// Record whether AXT policy hydration pulled from cache or required a rebuild.
    ///
    /// Canonical `event` labels: `cache_hit` and `cache_miss`.
    pub fn note_axt_policy_snapshot_cache_event(&self, event: &'static str) {
        if self.is_enabled() {
            self.metrics
                .axt_policy_snapshot_cache_events_total
                .with_label_values(&[event])
                .inc();
        }
    }
    /// Record an AXT proof cache event grouped by label.
    ///
    /// Canonical `event` labels: `hit`, `miss`, `expired`, `cleared`, `pruned`.
    pub fn note_axt_proof_cache_event(&self, event: &'static str) {
        if self.is_enabled() {
            self.metrics
                .axt_proof_cache_events_total
                .with_label_values(&[event])
                .inc();
        }
    }
    fn manifest_root_or_zero(manifest_root: Option<[u8; 32]>) -> [u8; 32] {
        manifest_root.unwrap_or([0; 32])
    }
    fn manifest_root_label(manifest_root: Option<[u8; 32]>) -> String {
        hex::encode(Self::manifest_root_or_zero(manifest_root))
    }
    fn remove_axt_proof_cache_metric(&self, entry: &AxtProofCacheStatus) {
        let ds_label = entry.dataspace.as_u64().to_string();
        let slot_label = entry.verified_slot.to_string();
        let root_hex = Self::manifest_root_label(entry.manifest_root);
        let _ = self.metrics.axt_proof_cache_state.remove_label_values(&[
            ds_label.as_str(),
            entry.status.as_str(),
            root_hex.as_str(),
            slot_label.as_str(),
        ]);
    }
    /// Publish the current AXT proof cache state for a dataspace.
    ///
    /// Labels: `dsid`, `status`, `manifest_root_hex`, `verified_slot`; value: `expiry_slot` (with skew).
    pub fn set_axt_proof_cache_state(
        &self,
        dsid: DataSpaceId,
        status: &'static str,
        manifest_root: [u8; 32],
        verified_slot: u64,
        expiry_slot: Option<u64>,
    ) {
        if !self.is_enabled() {
            return;
        }
        let expiry_slot_raw = expiry_slot;
        let ds_label = dsid.as_u64().to_string();
        let slot_label = verified_slot.to_string();
        let expiry_slot = expiry_slot_raw.map_or(0, |slot| i64::try_from(slot).unwrap_or(i64::MAX));
        let manifest_root_opt = manifest_root
            .iter()
            .any(|byte| *byte != 0)
            .then_some(manifest_root);
        if let Ok(mut guard) = self.axt_proof_cache.write() {
            if let Some(prev) = guard.get(&dsid) {
                self.remove_axt_proof_cache_metric(prev);
            }
            guard.insert(
                dsid,
                AxtProofCacheStatus {
                    dataspace: dsid,
                    status: status.to_owned(),
                    manifest_root: manifest_root_opt,
                    verified_slot,
                    expiry_slot: expiry_slot_raw,
                },
            );
        }
        let root_hex = hex::encode(manifest_root);
        self.metrics
            .axt_proof_cache_state
            .with_label_values(&[
                ds_label.as_str(),
                status,
                root_hex.as_str(),
                slot_label.as_str(),
            ])
            .set(expiry_slot);
    }
    /// Remove cached AXT proof state for a dataspace.
    pub fn clear_axt_proof_cache_state(
        &self,
        dsid: DataSpaceId,
        status: &'static str,
        manifest_root: [u8; 32],
        verified_slot: u64,
    ) {
        if !self.is_enabled() {
            return;
        }
        let ds_label = dsid.as_u64().to_string();
        let slot_label = verified_slot.to_string();
        let manifest_root_opt = manifest_root
            .iter()
            .any(|byte| *byte != 0)
            .then_some(manifest_root);
        if let Ok(mut guard) = self.axt_proof_cache.write() {
            if let Some(prev) = guard.get(&dsid) {
                self.remove_axt_proof_cache_metric(prev);
            }
            guard.insert(
                dsid,
                AxtProofCacheStatus {
                    dataspace: dsid,
                    status: String::from("cleared"),
                    manifest_root: manifest_root_opt,
                    verified_slot,
                    expiry_slot: None,
                },
            );
        }
        let root_hex = hex::encode(manifest_root);
        let _ = self.metrics.axt_proof_cache_state.remove_label_values(&[
            ds_label.as_str(),
            status,
            root_hex.as_str(),
            slot_label.as_str(),
        ]);
        self.metrics
            .axt_proof_cache_state
            .with_label_values(&[
                ds_label.as_str(),
                "cleared",
                root_hex.as_str(),
                slot_label.as_str(),
            ])
            .set(0);
    }
    /// Snapshot the current AXT proof cache state for diagnostics and debug endpoints.
    #[must_use]
    pub fn axt_proof_cache_status_snapshot(&self) -> Vec<AxtProofCacheStatus> {
        if !self.is_enabled() {
            return Vec::new();
        }
        self.axt_proof_cache
            .read()
            .map(|map| map.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Record a hint describing the next required handle era/sub-nonce after a rejection.
    pub fn set_axt_reject_hint(
        &self,
        dsid: DataSpaceId,
        target_lane: LaneId,
        active_handle_era: u64,
        next_handle_counter: u64,
        reason: AxtRejectReason,
    ) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut guard) = self.axt_reject_hints.write() {
            guard.insert(
                dsid,
                AxtRejectHint {
                    dataspace: dsid,
                    target_lane,
                    active_handle_era,
                    next_handle_counter,
                    reason,
                },
            );
        }
    }
    /// Snapshot the current set of AXT reject hints.
    #[must_use]
    pub fn axt_reject_hints_snapshot(&self) -> Vec<AxtRejectHint> {
        if !self.is_enabled() {
            return Vec::new();
        }
        self.axt_reject_hints
            .read()
            .map(|map| map.values().copied().collect())
            .unwrap_or_default()
    }
    /// Set the version hash for the AXT policy snapshot used when hydrating the host.
    pub fn set_axt_policy_snapshot_version(&self, snapshot: &AxtPolicySnapshot) {
        debug_assert!(snapshot.validate().is_ok());
        let version = snapshot.version;
        self.axt_policy_snapshot_version
            .store(version, Ordering::SeqCst);
        if !self.is_enabled() {
            return;
        }
        self.metrics.axt_policy_snapshot_version.set(version);
    }
    /// Snapshot the most recent AXT policy rejection (if any).
    #[must_use]
    pub fn axt_policy_reject_snapshot(&self) -> Option<AxtPolicyRejectSnapshot> {
        self.axt_last_policy_reject
            .read()
            .ok()
            .and_then(|guard| *guard)
    }
    /// Latest recorded AXT policy snapshot version.
    #[must_use]
    pub fn axt_policy_snapshot_version_value(&self) -> u64 {
        self.axt_policy_snapshot_version.load(Ordering::SeqCst)
    }
    /// Composite snapshot containing the policy version, last rejection, cache state, and hints.
    #[must_use]
    pub fn axt_debug_status(&self) -> AxtDebugStatus {
        AxtDebugStatus {
            policy_snapshot_version: self.axt_policy_snapshot_version_value(),
            last_reject: self.axt_policy_reject_snapshot(),
            cache: self.axt_proof_cache_status_snapshot(),
            hints: self.axt_reject_hints_snapshot(),
        }
    }
    state_telemetry_enabled_metric_methods! {
    /// Record a settlement completion event.
    [note_settlement_success(kind: &'static str) =>
        .settlement_events_total.with_label_values(&[kind, "success", "-"]).inc();]
    /// Record a settlement failure with a categorized reason.
    [note_settlement_failure(kind: &'static str, reason: &'static str) =>
        .settlement_events_total.with_label_values(&[kind, "failure", reason]).inc();]
    }
    fn settlement_order_label(order: SettlementExecutionOrder) -> &'static str {
        match order {
            SettlementExecutionOrder::DeliveryThenPayment => "delivery_then_payment",
            SettlementExecutionOrder::PaymentThenDelivery => "payment_then_delivery",
        }
    }
    fn settlement_atomicity_label(atomicity: SettlementAtomicity) -> &'static str {
        match atomicity {
            SettlementAtomicity::AllOrNothing => "all_or_nothing",
        }
    }
    fn dvp_final_state_label(delivery_committed: bool, payment_committed: bool) -> &'static str {
        match (delivery_committed, payment_committed) {
            (false, false) => "none",
            (true, false) => "delivery_only",
            (false, true) => "payment_only",
            (true, true) => "both",
        }
    }
    fn pvp_final_state_label(primary_committed: bool, counter_committed: bool) -> &'static str {
        match (primary_committed, counter_committed) {
            (false, false) => "none",
            (true, false) => "primary_only",
            (false, true) => "counter_only",
            (true, true) => "both",
        }
    }
    /// Record `DvP` settlement finality state for status/metrics surfaces.
    pub fn record_dvp_finality(
        &self,
        settlement_id: &SettlementId,
        plan: SettlementPlan,
        outcome: SettlementOutcomeKind,
        failure_reason: Option<&'static str>,
        delivery_committed: bool,
        payment_committed: bool,
    ) {
        if !self.is_enabled() {
            return;
        }
        let final_state_label = Self::dvp_final_state_label(delivery_committed, payment_committed);
        self.metrics
            .settlement_finality_events_total
            .with_label_values(&[SETTLEMENT_KIND_DVP, outcome.as_str(), final_state_label])
            .inc();
        let observed_at_ms = self.now_millis();
        status::record_dvp_settlement_event(status::DvpSettlementEventUpdate {
            observed_at_ms,
            settlement_id: Some(settlement_id.to_string()),
            plan_order: plan.order(),
            plan_atomicity: plan.atomicity(),
            outcome,
            failure_reason: failure_reason.map(str::to_owned),
            final_state_label: final_state_label.to_owned(),
            delivery_committed,
            payment_committed,
        });
    }
    /// Record `PvP` settlement finality state and FX window telemetry.
    #[allow(clippy::too_many_arguments)]
    pub fn record_pvp_finality(
        &self,
        settlement_id: &SettlementId,
        plan: SettlementPlan,
        outcome: SettlementOutcomeKind,
        failure_reason: Option<&'static str>,
        primary_committed: bool,
        counter_committed: bool,
        fx_window_ms: Option<u64>,
    ) {
        if !self.is_enabled() {
            return;
        }
        let final_state_label = Self::pvp_final_state_label(primary_committed, counter_committed);
        self.metrics
            .settlement_finality_events_total
            .with_label_values(&[SETTLEMENT_KIND_PVP, outcome.as_str(), final_state_label])
            .inc();
        if let Some(window_ms) = fx_window_ms {
            self.metrics
                .settlement_fx_window_ms
                .with_label_values(&[
                    SETTLEMENT_KIND_PVP,
                    Self::settlement_order_label(plan.order()),
                    Self::settlement_atomicity_label(plan.atomicity()),
                ])
                .observe(u64_to_f64(window_ms));
        }
        let observed_at_ms = self.now_millis();
        status::record_pvp_settlement_event(status::PvpSettlementEventUpdate {
            observed_at_ms,
            settlement_id: Some(settlement_id.to_string()),
            plan_order: plan.order(),
            plan_atomicity: plan.atomicity(),
            outcome,
            failure_reason: failure_reason.map(str::to_owned),
            final_state_label: final_state_label.to_owned(),
            primary_committed,
            counter_committed,
            fx_window_ms,
        });
    }
    /// Record a PSP fraud assessment missing event (e.g., missing metadata or grace).
    pub fn record_fraud_missing_assessment(
        &self,
        lane_id: LaneId,
        dataspace_label: &str,
        tenant: &str,
        cause: &'static str,
    ) {
        if self.is_enabled() {
            let tenant_trimmed = tenant.trim();
            let tenant_label = if tenant_trimmed.is_empty() {
                "unknown"
            } else {
                tenant_trimmed
            };
            let lane_label = lane_id.as_u32().to_string();
            let labels = [tenant_label, lane_label.as_str(), dataspace_label, cause];
            self.metrics
                .fraud_psp_missing_assessment_total
                .with_label_values(&labels)
                .inc();
        }
    }
    /// Record a Kaigi relay registration event.
    pub fn record_kaigi_relay_registration(
        &self,
        domain: &iroha_model_base::domain::DomainId,
        bandwidth_class: u8,
    ) {
        if self.is_enabled() {
            let domain_label = domain.to_string();
            self.metrics
                .kaigi_relay_registered_total
                .with_label_values(&[domain_label.as_str()])
                .inc();
            self.metrics
                .kaigi_relay_registration_bandwidth
                .with_label_values(&[domain_label.as_str()])
                .observe(u64_to_f64(u64::from(bandwidth_class)));
        }
    }
    /// Record a Kaigi relay manifest update.
    pub fn record_kaigi_manifest_update(
        &self,
        domain: &iroha_model_base::domain::DomainId,
        action: &'static str,
        hop_count: u32,
    ) {
        if self.is_enabled() {
            let domain_label = domain.to_string();
            self.metrics
                .kaigi_relay_manifest_updates_total
                .with_label_values(&[domain_label.as_str(), action])
                .inc();
            self.metrics
                .kaigi_relay_manifest_updates_by_domain_total
                .with_label_values(&[domain_label.as_str()])
                .inc();
            self.metrics
                .kaigi_relay_manifest_hop_count
                .with_label_values(&[domain_label.as_str()])
                .observe(u64_to_f64(u64::from(hop_count)));
        }
    }
    /// Record a Kaigi relay failover event.
    pub fn record_kaigi_failover(&self, domain: &DomainId, call: &Name, hop_count: u32) {
        if self.is_enabled() {
            let domain_label = domain.to_string();
            let call_label = call.to_string();
            self.metrics
                .kaigi_relay_failover_total
                .with_label_values(&[domain_label.as_str(), call_label.as_str()])
                .inc();
            self.metrics
                .kaigi_relay_failovers_by_domain_total
                .with_label_values(&[domain_label.as_str()])
                .inc();
            self.metrics
                .kaigi_relay_failover_hop_count
                .with_label_values(&[domain_label.as_str()])
                .observe(u64_to_f64(u64::from(hop_count)));
        }
    }
    /// Record a Kaigi relay health update.
    pub fn record_kaigi_relay_health(
        &self,
        domain: &DomainId,
        relay: &AccountId,
        status: KaigiRelayHealthStatus,
    ) {
        if self.is_enabled() {
            let domain_label = domain.to_string();
            let relay_label = relay.to_string();
            let status_label = status.label();
            self.metrics
                .kaigi_relay_health_reports_total
                .with_label_values(&[domain_label.as_str(), status_label])
                .inc();
            self.metrics
                .kaigi_relay_health_reports_by_domain_total
                .with_label_values(&[domain_label.as_str()])
                .inc();
            self.metrics
                .kaigi_relay_health_state
                .with_label_values(&[domain_label.as_str(), relay_label.as_str()])
                .set(status.metric_value());
        }
    }
    /// Record per-lane TEU metrics for the latest scheduler envelope.
    pub fn record_nexus_scheduler_lane_teu(&self, lane_id: LaneId, update: LaneTeuGaugeUpdate) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .nexus_scheduler_lane_teu_capacity
                .with_label_values(&[lane_label.as_str()])
                .set(update.capacity);
            self.metrics
                .nexus_scheduler_lane_teu_slot_committed
                .with_label_values(&[lane_label.as_str()])
                .set(update.committed);
            self.metrics
                .nexus_scheduler_lane_trigger_level
                .with_label_values(&[lane_label.as_str()])
                .set(update.trigger_level);
            self.metrics
                .nexus_scheduler_starvation_bound_slots
                .with_label_values(&[lane_label.as_str()])
                .set(update.starvation_bound_slots);
            for (bucket, value) in update.buckets.iter() {
                self.metrics
                    .nexus_scheduler_lane_teu_slot_breakdown
                    .with_label_values(&[lane_label.as_str(), bucket])
                    .set(value);
            }
            let headroom_pct = Self::lane_headroom_pct(&update);
            let emit_headroom_event = Self::should_emit_lane_headroom_event(headroom_pct, &update);
            if emit_headroom_event {
                self.metrics
                    .nexus_scheduler_lane_headroom_events_total
                    .with_label_values(&[lane_label.as_str()])
                    .inc();
            }
            self.with_lane_snapshot(lane_id, |snapshot| {
                snapshot.capacity = update.capacity;
                snapshot.committed = update.committed;
                snapshot.buckets = update.buckets;
                snapshot.trigger_level = update.trigger_level;
                snapshot.starvation_bound_slots = update.starvation_bound_slots;
                if emit_headroom_event {
                    let _ = self.emit_lane_headroom_event(lane_id, snapshot, &update, headroom_pct);
                }
            });
        }
    }
    #[cfg(test)]
    /// Increment TEU deferral counters for the provided lane and reason.
    pub fn inc_nexus_scheduler_lane_teu_deferral(
        &self,
        lane_id: LaneId,
        reason: &'static str,
        amount: u64,
    ) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .nexus_scheduler_lane_teu_deferral_total
                .with_label_values(&[lane_label.as_str(), reason])
                .inc_by(amount);
            self.with_lane_snapshot(lane_id, |snapshot| {
                snapshot.deferrals.increment(reason, amount);
            });
        }
    }
    #[cfg(test)]
    /// Increment the must-serve truncation counter for the provided lane.
    pub fn inc_nexus_scheduler_must_serve_truncations(&self, lane_id: LaneId, amount: u64) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .nexus_scheduler_must_serve_truncations_total
                .with_label_values(&[lane_label.as_str()])
                .inc_by(amount);
            self.with_lane_snapshot(lane_id, |snapshot| {
                snapshot.must_serve_truncations =
                    snapshot.must_serve_truncations.saturating_add(amount);
            });
        }
    }
    /// Record per-dataspace TEU backlog metrics for the latest scheduler envelope.
    pub fn record_nexus_scheduler_dataspace_teu(
        &self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        update: DataspaceTeuGaugeUpdate,
    ) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            let ds_label = dataspace_id.as_u64().to_string();
            self.metrics
                .nexus_scheduler_dataspace_teu_backlog
                .with_label_values(&[lane_label.as_str(), ds_label.as_str()])
                .set(update.backlog);
            self.metrics
                .nexus_scheduler_dataspace_age_slots
                .with_label_values(&[lane_label.as_str(), ds_label.as_str()])
                .set(update.age_slots);
            self.metrics
                .nexus_scheduler_dataspace_virtual_finish
                .with_label_values(&[lane_label.as_str(), ds_label.as_str()])
                .set(update.virtual_finish);
            self.with_dataspace_snapshot(lane_id, dataspace_id, |snapshot| {
                snapshot.backlog = update.backlog;
                snapshot.age_slots = update.age_slots;
                snapshot.virtual_finish = update.virtual_finish;
            });
        }
    }
    /// Record invalid PSP fraud metadata fields encountered during admission.
    pub fn record_fraud_invalid_metadata(
        &self,
        lane_id: LaneId,
        dataspace_label: &str,
        tenant: &str,
        field: &'static str,
    ) {
        if self.is_enabled() {
            let tenant_trimmed = tenant.trim();
            let tenant_label = if tenant_trimmed.is_empty() {
                "unknown"
            } else {
                tenant_trimmed
            };
            let lane_label = lane_id.as_u32().to_string();
            let labels = [tenant_label, field, lane_label.as_str(), dataspace_label];
            self.metrics
                .fraud_psp_invalid_metadata_total
                .with_label_values(&labels)
                .inc();
        }
    }
    /// Record PSP fraud assessment metrics (counts, score/latency histograms).
    pub fn record_fraud_assessment(
        &self,
        lane_id: LaneId,
        dataspace_label: &str,
        tenant: &str,
        band: &str,
        score_bps: Option<u16>,
        latency_ms: Option<u64>,
    ) {
        if self.is_enabled() {
            let tenant_trimmed = tenant.trim();
            let tenant_label = if tenant_trimmed.is_empty() {
                "unknown"
            } else {
                tenant_trimmed
            };
            let lane_label = lane_id.as_u32().to_string();
            let assessment_labels = [tenant_label, band, lane_label.as_str(), dataspace_label];
            self.metrics
                .fraud_psp_assessments_total
                .with_label_values(&assessment_labels)
                .inc();
            if let Some(score) = score_bps {
                self.metrics
                    .fraud_psp_score_bps
                    .with_label_values(&assessment_labels)
                    .observe(u64_to_f64(u64::from(score)));
            }
            if let Some(latency) = latency_ms {
                let latency_labels = [tenant_label, lane_label.as_str(), dataspace_label];
                self.metrics
                    .fraud_psp_latency_ms
                    .with_label_values(&latency_labels)
                    .observe(u64_to_f64(latency));
            }
        }
    }
    /// Record proof verification metrics (latency/size) for the given backend and outcome.
    pub fn record_zk_verify(
        &self,
        backend: &str,
        status: ProofStatus,
        proof_bytes: usize,
        latency_ms: u64,
    ) {
        if self.is_enabled() {
            let status_label = proof_status_label(status);
            let proof_bytes_value =
                u64::try_from(proof_bytes).map_or_else(|_| u64_to_f64(u64::MAX), u64_to_f64);
            self.metrics
                .zk_verify_latency_ms
                .with_label_values(&[backend, status_label])
                .observe(u64_to_f64(latency_ms));
            self.metrics
                .zk_verify_proof_bytes
                .with_label_values(&[backend, status_label])
                .observe(proof_bytes_value);
        }
    }
    #[cfg(test)]
    #[cfg(feature = "telemetry")]
    /// Record snapshot + eviction telemetry for confidential commitment trees.
    pub fn record_confidential_tree_stats(
        &self,
        asset_id: &iroha_data_model::asset::AssetDefinitionId,
        stats: ConfidentialTreeStats,
    ) {
        if !self.is_enabled() {
            return;
        }
        let asset_label = asset_id.to_string();
        let labels = [&asset_label[..]];
        self.metrics
            .confidential_tree_commitments
            .with_label_values(&labels)
            .set(stats.commitments);
        self.metrics
            .confidential_tree_depth
            .with_label_values(&labels)
            .set(stats.tree_depth);
        self.metrics
            .confidential_root_history_entries
            .with_label_values(&labels)
            .set(stats.root_history);
        self.metrics
            .confidential_frontier_checkpoints
            .with_label_values(&labels)
            .set(stats.frontier_checkpoints);
        self.metrics
            .confidential_frontier_last_height
            .with_label_values(&labels)
            .set(stats.last_checkpoint_height);
        self.metrics
            .confidential_frontier_last_commitments
            .with_label_values(&labels)
            .set(stats.last_checkpoint_commitments);
        if stats.root_evictions > 0 {
            self.metrics
                .confidential_root_evictions_total
                .with_label_values(&labels)
                .inc_by(stats.root_evictions);
        }
        if stats.frontier_evictions > 0 {
            self.metrics
                .confidential_frontier_evictions_total
                .with_label_values(&labels)
                .inc_by(stats.frontier_evictions);
        }
    }
    /// Record a mismatch between PSP disposition and the fraud engine decision.
    pub fn record_fraud_outcome_mismatch(
        &self,
        lane_id: LaneId,
        dataspace_label: &str,
        tenant: &str,
        direction: &'static str,
    ) {
        if self.is_enabled() {
            let tenant_trimmed = tenant.trim();
            let tenant_label = if tenant_trimmed.is_empty() {
                "unknown"
            } else {
                tenant_trimmed
            };
            let lane_label = lane_id.as_u32().to_string();
            let labels = [
                tenant_label,
                direction,
                lane_label.as_str(),
                dataspace_label,
            ];
            self.metrics
                .fraud_psp_outcome_mismatch_total
                .with_label_values(&labels)
                .inc();
        }
    }
    /// Record attestation verification outcomes for fraud assessments.
    pub fn record_fraud_attestation(
        &self,
        lane_id: LaneId,
        dataspace_label: &str,
        tenant: &str,
        engine_id: &str,
        status: &'static str,
    ) {
        if !self.is_enabled() {
            return;
        }
        let tenant_trimmed = tenant.trim();
        let tenant_label = if tenant_trimmed.is_empty() {
            "unknown"
        } else {
            tenant_trimmed
        };
        let engine_trimmed = engine_id.trim();
        let engine_label = if engine_trimmed.is_empty() {
            "unknown"
        } else {
            engine_trimmed
        };
        let lane_label = lane_id.as_u32().to_string();
        let labels = [
            tenant_label,
            engine_label,
            lane_label.as_str(),
            dataspace_label,
            status,
        ];
        self.metrics
            .fraud_psp_attestation_total
            .with_label_values(&labels)
            .inc();
    }
    state_telemetry_enabled_metric_methods! {
    /// Commit an observation of amounts used in transactions
    [observe_tx_amount(value: f64) => .tx_amounts.observe(value);]
    }
    #[cfg(test)]
    /// Set DAG vertices/edges for the latest validated block.
    pub fn set_pipeline_dag(&self, vertices: u64, edges: u64) {
        if self.is_enabled() {
            self.metrics.pipeline_dag_vertices.set(vertices);
            self.metrics.pipeline_dag_edges.set(edges);
        }
    }
    #[cfg(test)]
    /// Set DAG conflict rate in basis points for the latest validated block.
    pub fn set_pipeline_conflict_rate_bps(&self, bps: u64) {
        if self.is_enabled() {
            self.metrics.pipeline_conflict_rate_bps.set(bps);
        }
    }
    #[cfg(test)]
    /// Increment the access-set source counter by `count`.
    #[cfg(feature = "telemetry")]
    pub(crate) fn inc_pipeline_access_set_source(&self, source: AccessSetSource, count: u64) {
        if self.is_enabled() && count > 0 {
            let label = access_set_source_label(source);
            self.metrics
                .pipeline_access_set_source_total
                .with_label_values(&[label])
                .inc_by(count);
        }
    }
    state_telemetry_enabled_metric_methods! {
    /// Increment runtime upgrade event counter labeled by kind
    [inc_runtime_upgrade_event(kind: &'static str) =>
        .runtime_upgrade_events_total.with_label_values(&[kind]).inc();]
    }
    /// Increment runtime upgrade provenance rejection counter labeled by reason.
    pub fn record_runtime_upgrade_provenance_rejection(
        &self,
        reason: iroha_data_model::runtime::RuntimeUpgradeProvenanceError,
    ) {
        if self.is_enabled() {
            let label = reason.as_label();
            self.metrics
                .runtime_upgrade_provenance_rejections_total
                .with_label_values(&[label])
                .inc();
        }
    }
    /// Update governance proposal counters on status transition.
    pub fn record_governance_proposal_transition(
        &self,
        from: Option<crate::state::GovernanceProposalStatus>,
        to: crate::state::GovernanceProposalStatus,
    ) {
        if !self.is_enabled() {
            return;
        }
        if let Some(prev) = from {
            if prev == to {
                return;
            }
            let prev_label = proposal_status_label(prev);
            let gauge = self
                .metrics
                .governance_proposals_status
                .with_label_values(&[prev_label]);
            let current = gauge.get();
            gauge.set(current.saturating_sub(1));
        }
        let to_label = proposal_status_label(to);
        let gauge = self
            .metrics
            .governance_proposals_status
            .with_label_values(&[to_label]);
        let current = gauge.get();
        gauge.set(current.saturating_add(1));
    }
    state_telemetry_enabled_metric_methods_early_return! {
    /// Increment a governance bond lifecycle counter.
    [record_governance_bond_event(event: &'static str) =>
        .governance_bond_events_total.with_label_values(&[event]).inc();]
    /// Set the total citizen count gauge.
    [record_citizens_total(total: u64) => .governance_citizens_total.set(total);]
    }
    #[cfg(test)]
    /// Seed governance proposal gauges with the provided statuses.
    pub fn seed_governance_proposal_statuses(
        &self,
        statuses: impl IntoIterator<Item = crate::state::GovernanceProposalStatus>,
    ) {
        use crate::state::GovernanceProposalStatus as GPS;
        let collected: Vec<GPS> = statuses.into_iter().collect();
        #[cfg(feature = "telemetry")]
        {
            let mut cache = self
                .governance_status_cache
                .lock()
                .expect("governance proposal cache poisoned");
            cache.clear();
            for (idx, status) in collected.iter().copied().enumerate() {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                cache.insert(id, status);
            }
        }
        if !self.is_enabled() {
            return;
        }
        let mut counts = [0u64; 5];
        for status in collected {
            match status {
                GPS::Proposed => counts[0] = counts[0].saturating_add(1),
                GPS::Rejected => counts[1] = counts[1].saturating_add(1),
                GPS::Enacted => counts[2] = counts[2].saturating_add(1),
                GPS::Superseded => counts[3] = counts[3].saturating_add(1),
                GPS::ExecutionFailed => counts[4] = counts[4].saturating_add(1),
            }
        }
        for (status, count) in [
            (GPS::Proposed, counts[0]),
            (GPS::Rejected, counts[1]),
            (GPS::Enacted, counts[2]),
            (GPS::Superseded, counts[3]),
            (GPS::ExecutionFailed, counts[4]),
        ] {
            self.metrics
                .governance_proposals_status
                .with_label_values(&[proposal_status_label(status)])
                .set(count);
        }
    }
    state_telemetry_enabled_metric_methods! {
    /// Record protected-namespace enforcement outcome (allowed or rejected).
    [record_protected_namespace_enforcement(outcome: &'static str) =>
        .governance_protected_namespace_total.with_label_values(&[outcome]).inc();]
    /// Record manifest quorum enforcement outcome (satisfied or rejected).
    [record_manifest_quorum_enforcement(outcome: &'static str) =>
        .governance_manifest_quorum_total.with_label_values(&[outcome]).inc();]
    /// Record overall manifest admission outcome (allowed or rejected by reason).
    [record_manifest_admission(result: &'static str) =>
        .governance_manifest_admission_total.with_label_values(&[result]).inc();]
    /// Record manifest hook enforcement outcome for a specific hook.
    [record_manifest_hook_enforcement(hook: &'static str, outcome: &'static str) =>
        .governance_manifest_hook_total.with_label_values(&[hook, outcome]).inc();]
    }
    /// Record a manifest activation event emitted by governance enactment.
    pub fn record_manifest_activation(
        &self,
        activation: Option<GovernanceManifestActivation>,
        event: &'static str,
    ) {
        if self.is_enabled() {
            self.metrics
                .governance_manifest_activations_total
                .with_label_values(&[event])
                .inc();
            if let Some(activation) = activation {
                let mut recent = self
                    .metrics
                    .governance_manifest_recent
                    .write()
                    .expect("governance manifest cache lock poisoned");
                recent.push_front(activation);
                if recent.len() > GOVERNANCE_MANIFEST_RECENT_CAP {
                    recent.pop_back();
                }
            }
        }
    }
    #[cfg(test)]
    /// Set detached pipeline counters for the latest validated block.
    pub fn set_pipeline_detached_prepared(&self, count: u64) {
        if self.is_enabled() {
            self.metrics.pipeline_detached_prepared.set(count);
        }
    }
    #[cfg(test)]
    /// Set detached-merged counter for the latest validated block.
    pub fn set_pipeline_detached_merged(&self, count: u64) {
        if self.is_enabled() {
            self.metrics.pipeline_detached_merged.set(count);
        }
    }
    #[cfg(test)]
    /// Set detached-fallback counter for the latest validated block.
    pub fn set_pipeline_detached_fallback(&self, count: u64) {
        if self.is_enabled() {
            self.metrics.pipeline_detached_fallback.set(count);
        }
    }
    #[cfg(test)]
    /// Set detached-fallback count for a specific reason in the latest validated block.
    pub fn set_pipeline_detached_fallback_reason(&self, reason: &'static str, count: u64) {
        if self.is_enabled() {
            self.metrics
                .pipeline_detached_fallback_reason
                .with_label_values(&[reason])
                .set(count);
        }
    }
    /// Observe snapshot query lane iterable metrics for a completed first batch.
    pub fn observe_snapshot_iterable(
        &self,
        mode_label: &'static str,
        elapsed_ms: f64,
        output: &QueryOutput,
    ) {
        if self.is_enabled() {
            self.metrics
                .query_snapshot_lane_first_batch_ms
                .with_label_values(&[mode_label])
                .observe(elapsed_ms);
            let first_batch_items: u64 = output.batch.iter().map(|entry| entry.len() as u64).sum();
            self.metrics
                .query_snapshot_lane_first_batch_items
                .with_label_values(&[mode_label])
                .observe(u64_to_f64(first_batch_items));
            self.metrics
                .query_snapshot_lane_remaining_items
                .with_label_values(&[mode_label])
                .set(output.remaining_items_hint());
            if output.continue_cursor.is_some() {
                self.metrics
                    .query_snapshot_lane_cursors_total
                    .with_label_values(&[mode_label])
                    .inc();
            }
        }
    }
    #[cfg(test)]
    /// Observe a pipeline stage timing (milliseconds) labeled by `stage`.
    pub fn observe_pipeline_stage_ms(&self, lane_id: LaneId, stage: &'static str, ms: f64) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .pipeline_stage_ms
                .with_label_values(&[lane_label.as_str(), stage])
                .observe(ms);
        }
    }
    #[cfg(test)]
    /// Observe AMX prepare latency (milliseconds) for the provided lane.
    pub fn observe_amx_prepare_ms(&self, lane_id: LaneId, ms: f64) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .amx_prepare_ms
                .with_label_values(&[lane_label.as_str()])
                .observe(ms);
        }
    }
    #[cfg(test)]
    /// Observe AMX commit latency (milliseconds) for the provided lane.
    pub fn observe_amx_commit_ms(&self, lane_id: LaneId, ms: f64) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .amx_commit_ms
                .with_label_values(&[lane_label.as_str()])
                .observe(ms);
        }
    }
    #[cfg(test)]
    /// Observe IVM execution latency (milliseconds) for the provided lane.
    pub fn observe_ivm_exec_ms(&self, lane_id: LaneId, ms: f64) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .ivm_exec_ms
                .with_label_values(&[lane_label.as_str()])
                .observe(ms);
        }
    }
    /// Increment the AMX abort counter for the provided lane/stage.
    pub fn inc_amx_abort(&self, lane_id: LaneId, stage: &'static str) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .amx_abort_total
                .with_label_values(&[lane_label.as_str(), stage])
                .inc();
        }
    }
    /// Set BLS signature verification counters for the latest validated block.
    pub fn set_pipeline_sig_bls_counts(
        &self,
        same_msg_agg: u64,
        multi_msg_agg: u64,
        deterministic: u64,
    ) {
        if self.is_enabled() {
            self.metrics.pipeline_sig_bls_agg_same.set(same_msg_agg);
            self.metrics.pipeline_sig_bls_agg_multi.set(multi_msg_agg);
            self.metrics
                .pipeline_sig_bls_deterministic
                .set(deterministic);
        }
    }
    /// Increment cumulative BLS aggregate verification counters for the provided lane/result.
    pub fn inc_pipeline_sig_bls_result(&self, lane_id: LaneId, same_message: bool, success: bool) {
        if self.is_enabled() {
            let lane_label = lane_id.as_u32().to_string();
            let result_label = if success { "success" } else { "failure" };
            let counter = if same_message {
                &self.metrics.pipeline_sig_bls_agg_same_total
            } else {
                &self.metrics.pipeline_sig_bls_agg_multi_total
            };
            counter
                .with_label_values(&[lane_label.as_str(), result_label])
                .inc();
        }
    }
    #[cfg(test)]
    /// Get BLS signature verification counters for the latest validated block.
    /// Returns (`same_message_aggregate`, `multi_message_aggregate`, deterministic).
    pub fn pipeline_sig_bls_counts(&self) -> (u64, u64, u64) {
        (
            self.metrics.pipeline_sig_bls_agg_same.get(),
            self.metrics.pipeline_sig_bls_agg_multi.get(),
            self.metrics.pipeline_sig_bls_deterministic.get(),
        )
    }
    #[cfg(test)]
    /// Get cumulative BLS aggregate counters for `lane_id`, broken down by result.
    /// Returns ((`same_success`, `same_failure`), (`multi_success`, `multi_failure`)).
    pub fn pipeline_sig_bls_result_totals(&self, lane_id: LaneId) -> ((u64, u64), (u64, u64)) {
        if !self.is_enabled() {
            return ((0, 0), (0, 0));
        }
        let lane_label = lane_id.as_u32().to_string();
        let same_success = self
            .metrics
            .pipeline_sig_bls_agg_same_total
            .with_label_values(&[lane_label.as_str(), "success"])
            .get();
        let same_failure = self
            .metrics
            .pipeline_sig_bls_agg_same_total
            .with_label_values(&[lane_label.as_str(), "failure"])
            .get();
        let multi_success = self
            .metrics
            .pipeline_sig_bls_agg_multi_total
            .with_label_values(&[lane_label.as_str(), "success"])
            .get();
        let multi_failure = self
            .metrics
            .pipeline_sig_bls_agg_multi_total
            .with_label_values(&[lane_label.as_str(), "failure"])
            .get();
        ((same_success, same_failure), (multi_success, multi_failure))
    }
    #[cfg(test)]
    /// Get detached-pipeline counters for the latest validated block.
    /// Returns (prepared, merged, fallback).
    pub fn pipeline_detached_counts(&self) -> (u64, u64, u64) {
        (
            self.metrics.pipeline_detached_prepared.get(),
            self.metrics.pipeline_detached_merged.get(),
            self.metrics.pipeline_detached_fallback.get(),
        )
    }
    state_telemetry_enabled_metric_methods! {
    /// Set total gas used for the current (latest) block.
    [set_block_gas_used(gas: u64) => .block_gas_used.set(gas);]
    }
    /// Set confidential gas usage for the current transaction/block pair.
    pub fn set_confidential_gas_usage(&self, tx_gas: u64, block_gas: u64) {
        if self.is_enabled() {
            self.metrics.confidential_gas_tx_used.set(tx_gas);
            self.metrics.confidential_gas_block_used.set(block_gas);
            self.metrics.confidential_gas_total.inc_by(tx_gas);
        }
    }
    #[cfg(test)]
    /// Record oracle settlement context (TWAP price/window, haircut, staleness).
    #[cfg(feature = "telemetry")]
    pub fn observe_oracle_settlement_context(
        &self,
        twap_local_per_xor: &Numeric,
        twap_window_seconds: u32,
        epsilon_bps: u16,
        staleness_ms: u64,
    ) {
        if self.is_enabled() {
            self.metrics
                .oracle_price_local_per_xor
                .set(twap_local_per_xor.to_f64_lossy());
            self.metrics
                .oracle_twap_window_seconds
                .set(u64::from(twap_window_seconds));
            self.metrics
                .oracle_haircut_basis_points
                .set(u64::from(epsilon_bps));
            let staleness_seconds = Duration::from_millis(staleness_ms).as_secs_f64();
            self.metrics
                .oracle_staleness_seconds
                .set(staleness_seconds.max(0.0));
        }
    }
    /// Record oracle aggregation metrics (observation count and latency).
    #[cfg(feature = "telemetry")]
    pub fn observe_oracle_aggregation(
        &self,
        feed_id: &iroha_data_model::oracle::FeedId,
        observation_count: u64,
        evidence_hashes: &[iroha_crypto::Hash],
        duration: Duration,
    ) {
        if self.is_enabled() {
            let label = feed_id.as_str();
            self.metrics
                .oracle_feed_events_total
                .with_label_values(&[label])
                .inc();
            self.metrics
                .oracle_observations_total
                .with_label_values(&[label])
                .inc_by(observation_count);
            self.metrics
                .oracle_aggregation_duration_ms
                .with_label_values(&[label])
                .observe(duration.as_secs_f64() * 1_000.0);
            if !evidence_hashes.is_empty() {
                self.metrics
                    .oracle_feed_events_with_evidence_total
                    .with_label_values(&[label])
                    .inc();
                self.metrics
                    .oracle_evidence_hashes_total
                    .with_label_values(&[label])
                    .inc_by(evidence_hashes.len() as u64);
            }
        }
    }
    /// Record a twitter binding attestation event (piggybacks on oracle feed counters).
    #[cfg(feature = "telemetry")]
    pub fn observe_twitter_binding(
        &self,
        feed_id: &str,
        status: iroha_data_model::oracle::TwitterBindingStatus,
        expired: bool,
    ) {
        if self.is_enabled() {
            let _ = status;
            let _expired_label = if expired { "true" } else { "false" };
            self.metrics
                .oracle_feed_events_total
                .with_label_values(&[feed_id])
                .inc();
        }
    }
    /// Record oracle reward distribution.
    #[cfg(feature = "telemetry")]
    pub fn observe_oracle_reward(
        &self,
        feed_id: &iroha_data_model::oracle::FeedId,
        amount: &Quantity,
    ) {
        if self.is_enabled() {
            let label = feed_id.as_str();
            let amt = amount.as_numeric().try_mantissa_u128().unwrap_or(0);
            self.metrics
                .oracle_rewards_total
                .with_label_values(&[label])
                .inc_by(u64::try_from(amt).unwrap_or(u64::MAX));
        }
    }
    /// Record oracle penalty distribution.
    #[cfg(feature = "telemetry")]
    pub fn observe_oracle_penalty(
        &self,
        feed_id: &iroha_data_model::oracle::FeedId,
        amount: &Quantity,
        _kind: OraclePenaltyKind,
    ) {
        if self.is_enabled() {
            let label = feed_id.as_str();
            let amt = amount.as_numeric().try_mantissa_u128().unwrap_or(0);
            self.metrics
                .oracle_penalties_total
                .with_label_values(&[label])
                .inc_by(u64::try_from(amt).unwrap_or(u64::MAX));
        }
    }
    /// Record oracle reward distribution (no-op when telemetry is disabled).
    #[cfg(not(feature = "telemetry"))]
    #[allow(unused_variables)]
    pub fn observe_oracle_reward(
        &self,
        feed_id: &iroha_data_model::oracle::FeedId,
        amount: &Quantity,
    ) {
    }
    /// Record oracle penalty distribution (no-op when telemetry is disabled).
    #[cfg(not(feature = "telemetry"))]
    #[allow(unused_variables)]
    pub fn observe_oracle_penalty(
        &self,
        feed_id: &iroha_data_model::oracle::FeedId,
        amount: &Quantity,
        _kind: OraclePenaltyKind,
    ) {
    }
    #[cfg(test)]
    /// Record oracle settlement context (TWAP price/window, haircut, staleness).
    #[cfg(not(feature = "telemetry"))]
    #[allow(unused_variables)]
    pub fn observe_oracle_settlement_context(
        &self,
        twap_local_per_xor: &Numeric,
        twap_window_seconds: u32,
        epsilon_bps: u16,
        staleness_ms: u64,
    ) {
    }
    /// Add to the total fee amount for the current (latest) block.
    pub fn add_block_fee_amount(&self, delta_amount: &Quantity) {
        if self.is_enabled() {
            let current = Quantity::from_canonical_numeric(Numeric::new(
                self.metrics.block_fee_total_units.get(),
                u32::try_from(self.metrics.block_fee_total_scale.get()).unwrap_or(u32::MAX),
            ))
            .expect("block fee metric must remain in the quantity domain");
            let updated = current
                .checked_add(delta_amount)
                .expect("block fee metric exceeds supported numeric bounds");
            let (units, scale) = quantity_metric_parts(&updated);
            self.metrics.block_fee_total_units.set(units);
            self.metrics.block_fee_total_scale.set(scale);
        }
    }
    /// Reset total fee units for the current (latest) block.
    pub fn reset_block_fee_units(&self) {
        if self.is_enabled() {
            self.metrics.block_fee_total_units.set(0);
            self.metrics.block_fee_total_scale.set(0);
        }
    }
    /// Record proof-health alert telemetry for a provider.
    #[cfg(feature = "telemetry")]
    /// Record a `SoraFS` proof-health alert snapshot in the cached status state.
    /// Push a `SoraFS` proof-health alert into the `/status` overlay cache.
    pub fn record_sorafs_proof_health_alert(&self, alert: &SorafsProofHealthAlert) {
        if !self.enabled {
            return;
        }
        emit_sorafs_proof_health_alert(&self.metrics, alert);
    }
    #[cfg(not(feature = "telemetry"))]
    #[allow(unused_variables)]
    /// Push a `SoraFS` proof-health alert into the `/status` overlay cache.
    pub fn record_sorafs_proof_health_alert(&self, alert: &SorafsProofHealthAlert) {
        let _ = alert;
    }
}
#[cfg(feature = "telemetry")]
/// Increment the social rejection counter for the provided reason label.
pub fn record_social_rejection(telemetry: &StateTelemetry, reason: &'static str) {
    telemetry
        .metrics
        .social_rejections_total
        .with_label_values(&[reason])
        .inc();
    if reason == "multisig_direct_sign" {
        telemetry.metrics.multisig_direct_sign_reject_total.inc();
    }
}
#[cfg(not(feature = "telemetry"))]
/// No-op social rejection recorder when telemetry is disabled.
pub fn record_social_rejection(_: &StateTelemetry, _: &'static str) {}
impl Default for StateTelemetry {
    fn default() -> Self {
        Self::new(Arc::new(Metrics::default()), true)
    }
}
impl core::fmt::Debug for StateTelemetry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateTelemetry")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}
impl core::ops::Deref for StateTelemetry {
    type Target = Metrics;
    fn deref(&self) -> &Self::Target {
        self.metrics.as_ref()
    }
}
/// Streaming telemetry helper capturing Norito streaming metrics.
#[cfg(feature = "telemetry")]
#[derive(Clone)]
pub struct StreamingTelemetry {
    metrics: Arc<Metrics>,
    enabled: bool,
    parity_buckets: Arc<Mutex<BTreeMap<PeerId, &'static str>>>,
    rekeys_total: Arc<AtomicU64>,
    gck_rotations_total: Arc<AtomicU64>,
}
#[cfg(feature = "telemetry")]
impl core::fmt::Debug for StreamingTelemetry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let parity_buckets_len = self
            .parity_buckets
            .try_lock()
            .map_or(0, |guard| guard.len());
        f.debug_struct("StreamingTelemetry")
            .field("enabled", &self.enabled)
            .field("parity_buckets_len", &parity_buckets_len)
            .field("rekeys_total", &self.rekeys_total.load(Ordering::Relaxed))
            .field(
                "gck_rotations_total",
                &self.gck_rotations_total.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}
#[cfg(feature = "telemetry")]
macro_rules! streaming_telemetry_enabled_metric_methods {
    ($( $(#[$attr:meta])* [$name:ident($($arg:ident: $arg_ty:ty),* $(,)?) => $($op:tt)*] )+) => {
        $(
            $(#[$attr])*
            pub fn $name(&self $(, $arg: $arg_ty)*) {
                if self.is_enabled() {
                    self.metrics $($op)*
                }
            }
        )+
    };
}
#[cfg(feature = "telemetry")]
macro_rules! streaming_telemetry_enabled_metric_methods_early_return {
    ($( $(#[$attr:meta])* [$name:ident($($arg:ident: $arg_ty:ty),* $(,)?) => $($op:tt)*] )+) => {
        $(
            $(#[$attr])*
            pub fn $name(&self $(, $arg: $arg_ty)*) {
                if !self.is_enabled() {
                    return;
                }
                self.metrics $($op)*
            }
        )+
    };
}
#[cfg(feature = "telemetry")]
impl StreamingTelemetry {
    /// Construct a streaming telemetry handle backed by the shared metrics registry.
    pub fn new(metrics: Arc<Metrics>, enabled: bool) -> Self {
        Self {
            metrics,
            enabled,
            parity_buckets: Arc::new(Mutex::new(BTreeMap::new())),
            rekeys_total: Arc::new(AtomicU64::new(0)),
            gck_rotations_total: Arc::new(AtomicU64::new(0)),
        }
    }
    /// Return whether telemetry collection is enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// Record an accepted HPKE rekey for the provided suite.
    pub fn record_hpke_rekey(&self, suite: &EncryptionSuite) {
        if !self.is_enabled() {
            return;
        }
        let label = match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(_) => "x25519",
            EncryptionSuite::Kyber768XChaCha20Poly1305(_) => "kyber768",
        };
        self.metrics
            .streaming_hpke_rekeys_total
            .with_label_values(&[label])
            .inc();
        let total = self.rekeys_total.fetch_add(1, Ordering::Relaxed) + 1;
        let gck_total = self.gck_rotations_total.load(Ordering::Relaxed);
        let event = TelemetryEvent::Security(TelemetrySecurityStats {
            suite: *suite,
            rekeys: u32::try_from(total).unwrap_or(u32::MAX),
            gck_rotations: u32::try_from(gck_total).unwrap_or(u32::MAX),
            last_content_key_id: None,
            last_content_key_valid_from: None,
        });
        self.emit_event("streaming_security", &event);
    }
    /// Record a content key rotation event.
    pub fn record_content_key_update(
        &self,
        suite: Option<&EncryptionSuite>,
        update: &ContentKeyUpdate,
    ) {
        if self.is_enabled() {
            self.metrics.streaming_gck_rotations_total.inc();
            let total = self.gck_rotations_total.fetch_add(1, Ordering::Relaxed) + 1;
            let rekeys = self.rekeys_total.load(Ordering::Relaxed);
            let suite = suite
                .copied()
                .unwrap_or(EncryptionSuite::X25519ChaCha20Poly1305([0; 32]));
            let event = TelemetryEvent::Security(TelemetrySecurityStats {
                suite,
                rekeys: u32::try_from(rekeys).unwrap_or(u32::MAX),
                gck_rotations: u32::try_from(total).unwrap_or(u32::MAX),
                last_content_key_id: Some(update.content_key_id),
                last_content_key_valid_from: Some(update.valid_from_segment),
            });
            self.emit_event("streaming_security", &event);
        }
    }
    #[cfg(test)]
    /// Record encode telemetry exported by the publisher.
    pub fn record_encode_stats(&self, stats: &TelemetryEncodeStats) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .streaming_encode_latency_ms
            .observe(u64_to_f64(u64::from(stats.avg_latency_ms)));
        self.metrics
            .streaming_encode_dropped_layers_total
            .inc_by(u64::from(stats.dropped_layers));
        self.metrics
            .streaming_encode_audio_jitter_ms
            .observe(u64_to_f64(u64::from(stats.avg_audio_jitter_ms)));
        self.metrics
            .streaming_encode_audio_max_jitter_ms
            .set(u64::from(stats.max_audio_jitter_ms));
        self.emit_event("streaming_encode", &TelemetryEvent::Encode(*stats));
    }
    #[cfg(test)]
    /// Record decoder telemetry exported by viewers.
    pub fn record_decode_stats(&self, stats: &TelemetryDecodeStats) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .streaming_decode_buffer_ms
            .observe(u64_to_f64(u64::from(stats.buffer_ms)));
        self.metrics
            .streaming_decode_dropped_frames_total
            .inc_by(u64::from(stats.dropped_frames));
        self.metrics
            .streaming_decode_max_queue_ms
            .observe(u64_to_f64(u64::from(stats.max_decode_queue_ms)));
        self.metrics
            .streaming_decode_av_drift_ms
            .observe(u64_to_f64(u64::from(stats.avg_av_drift_ms.unsigned_abs())));
        self.metrics
            .streaming_decode_max_drift_ms
            .set(u64::from(stats.max_av_drift_ms));
        self.emit_event("streaming_decode", &TelemetryEvent::Decode(*stats));
    }
    #[cfg(test)]
    /// Record network telemetry emitted by viewers or relays.
    pub fn record_network_stats(&self, stats: &TelemetryNetworkStats) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .streaming_network_rtt_ms
            .observe(u64_to_f64(u64::from(stats.rtt_ms)));
        self.metrics
            .streaming_network_loss_percent_x100
            .observe(u64_to_f64(u64::from(stats.loss_percent_x100)));
        self.metrics
            .streaming_network_fec_repairs_total
            .inc_by(u64::from(stats.fec_repairs));
        self.metrics
            .streaming_network_fec_failures_total
            .inc_by(u64::from(stats.fec_failures));
        self.metrics
            .streaming_network_datagram_reinjects_total
            .inc_by(u64::from(stats.datagram_reinjects));
        self.emit_event("streaming_network", &TelemetryEvent::Network(*stats));
    }
    /// Record viewer sync diagnostics emitted in receiver reports.
    pub fn record_sync_diagnostics(&self, diagnostics: &SyncDiagnostics) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .streaming_audio_jitter_ms
            .observe(u64_to_f64(u64::from(diagnostics.avg_audio_jitter_ms)));
        self.metrics
            .streaming_audio_max_jitter_ms
            .set(u64::from(diagnostics.max_audio_jitter_ms));
        self.metrics
            .streaming_av_drift_ms
            .observe(u64_to_f64(u64::from(
                diagnostics.avg_av_drift_ms.unsigned_abs(),
            )));
        self.metrics
            .streaming_av_max_drift_ms
            .set(u64::from(diagnostics.max_av_drift_ms));
        self.metrics
            .streaming_av_drift_ewma_ms
            .set(i64::from(diagnostics.ewma_av_drift_ms));
        self.metrics
            .streaming_av_sync_window_ms
            .set(u64::from(diagnostics.window_ms));
        if diagnostics.violation_count > 0 {
            self.metrics
                .streaming_av_sync_violation_total
                .inc_by(u64::from(diagnostics.violation_count));
        }
    }
    #[cfg(test)]
    /// Record energy telemetry exported by publishers/viewers.
    pub fn record_energy_stats(&self, stats: &TelemetryEnergyStats) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .streaming_energy_encoder_mw
            .observe(u64_to_f64(u64::from(stats.encoder_milliwatts)));
        self.metrics
            .streaming_energy_decoder_mw
            .observe(u64_to_f64(u64::from(stats.decoder_milliwatts)));
        self.emit_event("streaming_energy", &TelemetryEvent::Energy(*stats));
    }
    /// Record storage budget usage for streaming components.
    pub fn record_storage_budget_usage(&self, component: &'static str, used: u64, limit: u64) {
        if !self.is_enabled() {
            return;
        }
        self.metrics
            .storage_budget_bytes_used
            .with_label_values(&[component])
            .set(used);
        self.metrics
            .storage_budget_bytes_limit
            .with_label_values(&[component])
            .set(limit);
    }
    streaming_telemetry_enabled_metric_methods_early_return! {
    /// Record storage budget exceed events for streaming components.
    [inc_storage_budget_exceeded(component: &'static str) =>
        .storage_budget_exceeded_total.with_label_values(&[component]).inc();]
    }
    /// Update the active parity bucket for the given peer.
    pub fn record_fec_parity(&self, peer: &PeerId, parity: u8) {
        if !self.is_enabled() {
            return;
        }
        let bucket = match parity {
            0 => "0",
            1 => "1",
            2 => "2",
            3 => "3",
            4 => "4",
            _ => "ge5",
        };
        let mut guard = self
            .parity_buckets
            .lock()
            .expect("streaming parity bucket map poisoned");
        match guard.entry(peer.clone()) {
            BTreeEntry::Occupied(mut entry) => {
                let previous = *entry.get();
                if previous != bucket {
                    self.metrics
                        .streaming_fec_parity_current
                        .with_label_values(&[previous])
                        .dec();
                    self.metrics
                        .streaming_fec_parity_current
                        .with_label_values(&[bucket])
                        .inc();
                    entry.insert(bucket);
                }
            }
            BTreeEntry::Vacant(entry) => {
                self.metrics
                    .streaming_fec_parity_current
                    .with_label_values(&[bucket])
                    .inc();
                entry.insert(bucket);
            }
        }
    }
    streaming_telemetry_enabled_metric_methods! {
    /// Increment the sent datagram counter by the provided delta.
    [inc_quic_datagrams_sent(delta: u64) => .streaming_quic_datagrams_sent_total.inc_by(delta);]
    /// Increment the dropped datagram counter by the provided delta.
    [inc_quic_datagrams_dropped(delta: u64) =>
        .streaming_quic_datagrams_dropped_total.inc_by(delta);]
    /// Record a feedback timeout event.
    [inc_feedback_timeout() => .streaming_feedback_timeout_total.inc();]
    /// Record a privacy redaction failure event.
    [inc_privacy_redaction_failure() => .streaming_privacy_redaction_fail_total.inc();]
    }
    fn emit_event(&self, msg: &str, event: &TelemetryEvent) {
        if !self.is_enabled() {
            return;
        }
        let payload = telemetry_event_to_json(event);
        match norito::json::to_json(&payload) {
            Ok(json) => iroha_logger::telemetry!(msg = msg, event = json),
            Err(err) => iroha_logger::warn!(
                ?err,
                "failed to encode streaming telemetry event for {}",
                msg
            ),
        }
    }
    fn suite_to_json(suite: &EncryptionSuite) -> norito::json::Value {
        match suite {
            EncryptionSuite::X25519ChaCha20Poly1305(fingerprint) => {
                let mut map = norito::json::Map::new();
                map.insert(
                    "suite".to_string(),
                    norito::json!("x25519_chacha20poly1305"),
                );
                map.insert(
                    "fingerprint".to_string(),
                    norito::json!(hex::encode(fingerprint)),
                );
                norito::json::Value::Object(map)
            }
            EncryptionSuite::Kyber768XChaCha20Poly1305(fingerprint) => {
                let mut map = norito::json::Map::new();
                map.insert(
                    "suite".to_string(),
                    norito::json!("kyber768_xchacha20poly1305"),
                );
                map.insert(
                    "fingerprint".to_string(),
                    norito::json!(hex::encode(fingerprint)),
                );
                norito::json::Value::Object(map)
            }
        }
    }
}
#[cfg(feature = "telemetry")]
fn emit_sorafs_proof_health_alert(metrics: &Metrics, alert: &SorafsProofHealthAlert) {
    let provider_hex = hex::encode(alert.provider_id.as_bytes());
    let trigger = match (alert.triggered_by_pdp, alert.triggered_by_potr) {
        (true, true) => "both",
        (true, false) => "pdp",
        (false, true) => "potr",
        (false, false) => "unknown",
    };
    let penalty_nano = quantity_to_nano_saturating(&alert.penalty_applied);
    metrics.record_sorafs_proof_health_alert(
        provider_hex.as_str(),
        trigger,
        !alert.penalty_applied.is_zero() && !alert.cooldown_active,
        alert.pdp_failures,
        alert.potr_breaches,
        penalty_nano,
        alert.cooldown_active,
        alert.window_end_epoch,
    );
}
/// Update gauges that track transaction queue load and saturation as observed by consensus.
pub fn record_state_tx_queue_backpressure(
    telemetry: &StateTelemetry,
    depth: u64,
    capacity: u64,
    retained_bytes: u64,
    max_retained_bytes: u64,
    saturated_by_count: bool,
    saturated_by_bytes: bool,
    saturated_by_age: bool,
    oldest_queued_age_ms: u64,
) {
    if telemetry.is_enabled() {
        telemetry.metrics.sumeragi_tx_queue_depth.set(depth);
        telemetry.metrics.sumeragi_tx_queue_capacity.set(capacity);
        telemetry
            .metrics
            .sumeragi_tx_queue_retained_bytes
            .set(retained_bytes);
        telemetry
            .metrics
            .sumeragi_tx_queue_max_retained_bytes
            .set(max_retained_bytes);
        telemetry
            .metrics
            .sumeragi_tx_queue_saturated
            .set(u64::from(saturated_by_count || saturated_by_bytes));
        telemetry
            .metrics
            .sumeragi_tx_queue_saturated_by_count
            .set(u64::from(saturated_by_count));
        telemetry
            .metrics
            .sumeragi_tx_queue_saturated_by_bytes
            .set(u64::from(saturated_by_bytes));
        telemetry
            .metrics
            .sumeragi_tx_queue_saturated_by_age
            .set(u64::from(saturated_by_age));
        telemetry
            .metrics
            .sumeragi_tx_queue_oldest_queued_age_ms
            .set(oldest_queued_age_ms);
    }
}
/// Update gauges that reflect the most recent tiered-state snapshot.
#[allow(clippy::too_many_arguments)]
pub fn record_state_tiered_snapshot(
    telemetry: &StateTelemetry,
    snapshot_index: u64,
    hot_entries: usize,
    hot_bytes: u64,
    cold_entries: usize,
    cold_bytes: u64,
    hot_promotions: usize,
    hot_demotions: usize,
    hot_budget_overflow_keys: usize,
    hot_budget_overflow_bytes: u64,
    cold_reused_entries: usize,
    cold_reused_bytes: u64,
) {
    if telemetry.is_enabled() {
        telemetry
            .metrics
            .state_tiered_last_snapshot_index
            .set(snapshot_index);
        telemetry
            .metrics
            .state_tiered_hot_entries
            .set(hot_entries as u64);
        telemetry.metrics.state_tiered_hot_bytes.set(hot_bytes);
        telemetry
            .metrics
            .state_tiered_cold_entries
            .set(cold_entries as u64);
        telemetry.metrics.state_tiered_cold_bytes.set(cold_bytes);
        telemetry
            .metrics
            .state_tiered_hot_promotions
            .set(hot_promotions as u64);
        telemetry
            .metrics
            .state_tiered_hot_demotions
            .set(hot_demotions as u64);
        telemetry
            .metrics
            .state_tiered_hot_budget_overflow_keys
            .set(hot_budget_overflow_keys as u64);
        telemetry
            .metrics
            .state_tiered_hot_budget_overflow_bytes
            .set(hot_budget_overflow_bytes);
        telemetry
            .metrics
            .state_tiered_cold_reused_entries
            .set(cold_reused_entries as u64);
        telemetry
            .metrics
            .state_tiered_cold_reused_bytes
            .set(cold_reused_bytes);
    }
}
const CHANNEL_CAPACITY: usize = 1024;
#[cfg(feature = "telemetry")]
/// Upper bound for waiting on the telemetry actor to refresh metrics.
///
/// Keep this short so HTTP status/metrics endpoints cannot stall the runtime
/// when the telemetry task is unavailable or backlogged.
const METRICS_SYNC_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg_attr(not(feature = "telemetry"), allow(dead_code))]
enum Message {
    Sync {
        reply: Option<oneshot::Sender<Result<(), StatusSnapshotError>>>,
    },
    #[cfg(test)]
    TestInspectStatusRefusal {
        inspect: Box<dyn FnOnce(Option<&crate::execution_attempt::ExecutionDeferred>) + Send>,
        reply: oneshot::Sender<()>,
    },
    #[cfg(test)]
    TestBarrier {
        entered: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    },
    #[cfg(test)]
    TestChunkBarrier {
        entered: oneshot::Sender<usize>,
        resume: oneshot::Receiver<()>,
    },
    #[cfg(feature = "telemetry")]
    Status {
        build: iroha_torii_shared::status::BuildStatus,
        deadline: tokio::time::Instant,
        reply: oneshot::Sender<Result<OwnedStatus, StatusSnapshotError>>,
    },
}
/// Handle to the telemetry state
pub struct Telemetry {
    actor: mpsc::Sender<Message>,
    last_reported_block: Arc<RwLock<Option<BlockCommitReport>>>,
    metrics: Arc<Metrics>,
    enabled: bool,
    sync_requested: Arc<AtomicBool>,
    time_source: TimeSource,
    soranet_privacy: Arc<SoranetSecureAggregator>,
}
impl Clone for Telemetry {
    fn clone(&self) -> Self {
        Self {
            actor: self.actor.clone(),
            last_reported_block: Arc::clone(&self.last_reported_block),
            metrics: Arc::clone(&self.metrics),
            enabled: self.enabled,
            sync_requested: Arc::clone(&self.sync_requested),
            time_source: self.time_source.clone(),
            soranet_privacy: Arc::clone(&self.soranet_privacy),
        }
    }
}
macro_rules! telemetry_enabled_metric_methods {
    () => {};
    ($(#[$attr:meta])* [$name:ident($($arg:ident: $arg_ty:ty),* $(,)?) => $($op:tt)*] $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $name(&self $(, $arg: $arg_ty)*) {
            if self.enabled {
                self.metrics $($op)*
            }
        }
        telemetry_enabled_metric_methods! { $($rest)* }
    };
    ($(#[$attr:meta])* [$name:ident($first:ident: $first_ty:ty, $($arg:ident: $arg_ty:ty,)*) ;] $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $name(&self, $first: $first_ty $(, $arg: $arg_ty)*) {
            if self.enabled {
                self.metrics.$name($first $(, $arg)*,);
            }
        }
        telemetry_enabled_metric_methods! { $($rest)* }
    };
    ($(#[$attr:meta])* [$name:ident($($arg:ident: $arg_ty:ty),* $(,)?) ;] $($rest:tt)*) => {
        $(#[$attr])*
        pub fn $name(&self $(, $arg: $arg_ty)*) {
            if self.enabled {
                self.metrics.$name($($arg),*);
            }
        }
        telemetry_enabled_metric_methods! { $($rest)* }
    };
}
impl Telemetry {
    /// Lightweight constructor for tests: does not spawn the background actor.
    pub fn new(metrics: Arc<Metrics>, enabled: bool) -> Self {
        let (actor, _handle) = mpsc::channel(CHANNEL_CAPACITY);
        let soranet_privacy = Arc::new(
            SoranetSecureAggregator::new(PrivacyBucketConfig::default())
                .expect("valid default SoraNet privacy config"),
        );
        Telemetry {
            actor,
            last_reported_block: Arc::new(RwLock::new(None)),
            metrics,
            enabled,
            sync_requested: Arc::new(AtomicBool::new(false)),
            time_source: TimeSource::new_system(),
            soranet_privacy,
        }
    }
    /// Whether telemetry observations are enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    telemetry_enabled_metric_methods! {
    /// Record one bounded Musubi finalized-query cursor failure.
    [record_musubi_cursor_failure(reason: MusubiCursorFailureReasonV1) =>
        .musubi.inc_cursor_failure(reason);]
    }
    /// Record an AXT policy rejection grouped by lane id and reason.
    pub fn note_axt_policy_reject(
        &self,
        lane: LaneId,
        reason: AxtRejectReason,
        snapshot_version: u64,
    ) {
        let _ = snapshot_version;
        if !self.enabled {
            return;
        }
        let lane_label = lane.as_u32().to_string();
        let reason = reason.label();
        self.metrics
            .axt_policy_reject_total
            .with_label_values(&[lane_label.as_str(), reason])
            .inc();
    }
    telemetry_enabled_metric_methods! {
    /// Record whether AXT policy hydration pulled from cache or required a rebuild.
    ///
    /// Canonical `event` labels: `cache_hit` and `cache_miss`.
    [note_axt_policy_snapshot_cache_event(event: &'static str) =>
        .axt_policy_snapshot_cache_events_total.with_label_values(&[event]).inc();]
    /// Record an AXT proof cache event grouped by label.
    ///
    /// Canonical `event` labels: `hit`, `miss`, `expired`, `cleared`, `pruned`.
    [note_axt_proof_cache_event(event: &'static str) =>
        .axt_proof_cache_events_total.with_label_values(&[event]).inc();]
    }
    /// Publish the current AXT proof cache state for a dataspace.
    ///
    /// Labels: `dsid`, `status`, `manifest_root_hex`, `verified_slot`; value: `expiry_slot` (with skew).
    pub fn set_axt_proof_cache_state(
        &self,
        dsid: DataSpaceId,
        status: &'static str,
        manifest_root: [u8; 32],
        verified_slot: u64,
        expiry_slot: Option<u64>,
    ) {
        if self.enabled {
            let ds_label = dsid.as_u64().to_string();
            let slot_label = verified_slot.to_string();
            let root_hex = hex::encode(manifest_root);
            let expiry_slot = expiry_slot.map_or(0, |slot| i64::try_from(slot).unwrap_or(i64::MAX));
            self.metrics
                .axt_proof_cache_state
                .with_label_values(&[
                    ds_label.as_str(),
                    status,
                    root_hex.as_str(),
                    slot_label.as_str(),
                ])
                .set(expiry_slot);
        }
    }
    /// Remove cached AXT proof state for a dataspace.
    pub fn clear_axt_proof_cache_state(
        &self,
        dsid: DataSpaceId,
        status: &'static str,
        manifest_root: [u8; 32],
        verified_slot: u64,
    ) {
        if self.enabled {
            let ds_label = dsid.as_u64().to_string();
            let slot_label = verified_slot.to_string();
            let root_hex = hex::encode(manifest_root);
            let _ = self.metrics.axt_proof_cache_state.remove_label_values(&[
                ds_label.as_str(),
                status,
                root_hex.as_str(),
                slot_label.as_str(),
            ]);
        }
    }
    /// Set the version hash for the AXT policy snapshot used when hydrating the host.
    pub fn set_axt_policy_snapshot_version(&self, snapshot: &AxtPolicySnapshot) {
        if !self.enabled {
            return;
        }
        debug_assert!(snapshot.validate().is_ok());
        let version = snapshot.version;
        self.metrics.axt_policy_snapshot_version.set(version);
    }
    #[cfg(test)]
    /// Update gauges that track transaction queue load and saturation as observed by consensus.
    pub fn record_tx_queue_backpressure(
        &self,
        depth: u64,
        capacity: u64,
        retained_bytes: u64,
        max_retained_bytes: u64,
        saturated_by_count: bool,
        saturated_by_bytes: bool,
        saturated_by_age: bool,
        oldest_queued_age_ms: u64,
    ) {
        if self.enabled {
            self.metrics.sumeragi_tx_queue_depth.set(depth);
            self.metrics.sumeragi_tx_queue_capacity.set(capacity);
            self.metrics
                .sumeragi_tx_queue_retained_bytes
                .set(retained_bytes);
            self.metrics
                .sumeragi_tx_queue_max_retained_bytes
                .set(max_retained_bytes);
            self.metrics
                .sumeragi_tx_queue_saturated
                .set(u64::from(saturated_by_count || saturated_by_bytes));
            self.metrics
                .sumeragi_tx_queue_saturated_by_count
                .set(u64::from(saturated_by_count));
            self.metrics
                .sumeragi_tx_queue_saturated_by_bytes
                .set(u64::from(saturated_by_bytes));
            self.metrics
                .sumeragi_tx_queue_saturated_by_age
                .set(u64::from(saturated_by_age));
            self.metrics
                .sumeragi_tx_queue_oldest_queued_age_ms
                .set(oldest_queued_age_ms);
        }
    }
    telemetry_enabled_metric_methods! {
    /// Increment Torii pre-auth rejection counter for the provided reason label.
    [inc_torii_pre_auth_reject(reason: &'static str) =>
        .torii_pre_auth_reject_total.with_label_values(&[reason]).inc();]
    /// Increment Torii operator auth event counters.
    [inc_torii_operator_auth(action: &'static str, result: &'static str, reason: &'static str);]
    /// Increment Torii operator auth lockout counters.
    [inc_torii_operator_auth_lockout(action: &'static str, reason: &'static str);]
    }
    /// Record a signature-limit rejection with the observed count and configured cap.
    pub fn inc_torii_signature_limit_reject(
        &self,
        count: u64,
        limit: u64,
        authority: &'static str,
    ) {
        if self.enabled {
            self.metrics.torii_signature_limit_total.inc();
            self.metrics
                .torii_signature_limit_by_authority_total
                .with_label_values(&[authority])
                .inc();
            self.metrics.torii_signature_limit_last_count.set(count);
            self.metrics.torii_signature_limit_max.set(limit);
        }
    }
    telemetry_enabled_metric_methods! {
    /// Record a rejection when NTS is unhealthy for time-sensitive admission.
    [inc_torii_nts_unhealthy_reject() => .torii_nts_unhealthy_reject_total.inc();]
    /// Record a rejection of a transaction directly signed by a multisig account.
    [inc_torii_multisig_direct_sign_reject() => .torii_multisig_direct_sign_reject_total.inc();]
    /// Increment Torii `SoraFS` admission counter for the given result/reason pair.
    [inc_torii_sorafs_admission(result: &'static str, reason: &'static str) =>
        .torii_sorafs_admission_total.with_label_values(&[result, reason]).inc();]
    }
    #[cfg(test)]
    /// Record an SNS registrar outcome grouped by result and suffix.
    pub fn inc_sns_registrar_status(&self, result: &'static str, suffix: &str) {
        self.metrics.inc_sns_registrar_status(result, suffix);
    }
    telemetry_enabled_metric_methods! {
    /// Record an invalid Torii address observation labeled by endpoint + reason.
    [inc_torii_address_invalid(endpoint: &'static str, reason: &'static str);]
    /// Record the `account literal` selection emitted by a Torii endpoint.
    [inc_torii_account_literal(endpoint: &'static str, format: &'static str);]
    /// Record a Norito-RPC gate observation grouped by rollout stage and outcome.
    [inc_torii_norito_rpc_gate(stage: &'static str, outcome: &'static str);]
    /// Record a DA rent quote projection for observability.
    [record_da_rent_quote(
        cluster_label: &str, storage_label: &str, gib_months: u64, rent_quote: &DaRentQuote
    );]
    /// Observe the latency of DA chunking performed by Torii.
    [observe_da_chunking_seconds(seconds: f64);]
    /// Record a Torii DA spool batch write outcome.
    [record_torii_da_spool_batch(outcome: &'static str, write_ms: f64);]
    /// Record Torii DA spool artifact outcomes.
    [record_torii_da_spool_artifact(kind: &'static str, outcome: &'static str, count: u64);]
    /// Set the current Torii DA spool queue depth.
    [set_torii_da_spool_queue_depth(depth: u64);]
    /// Record the result of a DA receipt ingestion attempt.
    [record_da_receipt_outcome(
        lane_id: u32, epoch: u64, sequence: u64, outcome: &str, cursor_advanced: bool,
    );]
    /// Update the highest-seen DA receipt cursor for a lane/epoch.
    [set_da_receipt_cursor(lane_id: u32, epoch: u64, sequence: u64);]
    /// Remove DA receipt metric state owned by retired lanes.
    [prune_da_receipt_lanes(lane_ids: impl IntoIterator<Item = u32>);]
    /// Record a DA shard cursor event with lane/shard labels.
    [record_da_shard_cursor_event(event: &str, lane_id: u32, shard_id: u32, block_height: u64);]
    }
    telemetry_enabled_metric_methods! {
    /// Record the shard cursor lag measured in blocks.
    [record_da_shard_cursor_lag(lane_id: u32, shard_id: u32, lag_blocks: i64) =>
        .set_da_shard_cursor_lag(lane_id, shard_id, lag_blocks);]
    /// Record the projected `SoraFS` fee for `provider`.
    [record_sorafs_fee_projection(provider: &str, fee: &Quantity);]
    /// Record `SoraFS` egress counters and observer drift for `provider`.
    [record_sorafs_egress_reconciliation(
        provider: &str, billing_bytes: u64, gateway_bytes: Option<u64>,
        orchestrator_bytes: Option<u64>,
    );]
    /// Record the latest accepted `SoraFS` reputation snapshot metrics.
    [record_sorafs_reputation_snapshot(
        generated_at_unix: u64, observed_at_unix: u64, provider_scores: &[(&str, u16, bool)],
    );]
    /// Record one `SoraFS` orderbook API response for a routed endpoint.
    [record_sorafs_orderbook_api_request(route: &str, is_error: bool);]
    /// Mark the finalized `SoraFS` orderbook projection unready while
    /// retaining the last complete metric values for diagnosis.
    [mark_sorafs_orderbook_finalized_projection_unready();]
    /// Record one fail-closed finalized `SoraFS` orderbook projection failure.
    [record_sorafs_orderbook_finalized_projection_failure(reason: &str);]
    /// Publish one complete finalized `SoraFS` orderbook metric projection.
    #[allow(clippy::too_many_arguments)]
    [record_sorafs_orderbook_finalized_projection(
        finalized_height: u64, finalized_timestamp_seconds: u64, event_count_deltas: [u64; 8],
        open_depth_gib: [[u64; 2]; 3], matcher_lag_seconds: u64, settlement_backlog: u64,
        oldest_settlement_age_seconds: u64, escrow_runway_seconds: u64, book_revision: u64,
        matcher_scan_book_revision: u64,
    );]
    /// Record one authenticated `SoraFS` gateway-compliance control response.
    [record_sorafs_gateway_compliance_request(operation: &str, outcome: &str);]
    /// Record one `SoraFS` gateway-compliance failure.
    [record_sorafs_gateway_compliance_failure(surface: &str, class: &str);]
    /// Record one `SoraFS` gateway-compliance serving decision.
    [record_sorafs_gateway_compliance_serving_decision(
        subject_kind: &str, disposition: &str, source: &str,
    );]
    /// Publish one complete `SoraFS` gateway-compliance serving-catalog snapshot.
    [record_sorafs_gateway_compliance_serving_catalog(
        sequence: Option<u64>, valid_until_unix: Option<u64>, ready: bool,
    );]
    /// Mark the `SoraFS` gateway-compliance serving policy unavailable.
    [mark_sorafs_gateway_compliance_unready();]
    /// Publish one complete, reconciled `SoraFS` reserve projection.
    [record_sorafs_reserve_finalized_projection(projection: &SorafsReserveFinalizedProjection);]
    /// Mark the finalized `SoraFS` reserve projection unavailable.
    [mark_sorafs_reserve_finalized_projection_unready();]
    /// Record one failed finalized `SoraFS` reserve projection attempt.
    [record_sorafs_reserve_finalized_projection_failure();]
    /// Record one `SoraFS` reserve service request outcome.
    [record_sorafs_reserve_service_request(route: &str, result: &str);]
    /// Increment one `SoraFS` reserve service rate-limit counter.
    [inc_sorafs_reserve_service_rate_limit(route: &str, reason: &str);]
    /// Increment the `SoraFS` dispute counter for the provided result label.
    [inc_sorafs_disputes(result: &'static str);]
    }
    #[cfg(test)]
    /// Emit an audit outcome telemetry event for routed-trace checkpoints.
    #[cfg(feature = "telemetry")]
    pub fn record_audit_outcome(
        &self,
        outcome: &TelemetryAuditOutcome,
    ) -> Option<norito::json::Value> {
        if !self.is_enabled() {
            return None;
        }
        self.metrics
            .nexus_audit_outcome_total
            .with_label_values(&[outcome.trace_id.as_str(), outcome.status.as_str()])
            .inc();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        self.metrics
            .nexus_audit_outcome_last_timestamp
            .with_label_values(&[outcome.trace_id.as_str()])
            .set(now_secs);
        let payload = telemetry_event_to_json(&TelemetryEvent::AuditOutcome(outcome.clone()));
        match norito::json::to_json(&payload) {
            Ok(json) => iroha_logger::telemetry!(msg = "nexus.audit.outcome", event = json),
            Err(err) => {
                iroha_logger::warn!(?err, "failed to encode audit outcome telemetry event");
            }
        }
        Some(payload)
    }
    telemetry_enabled_metric_methods! {
    /// Record a proof stream outcome and optional latency.
    #[cfg(feature = "telemetry")]
    [record_sorafs_proof_stream_event(
        kind: &str, result: &str, reason: Option<&str>, provider_id: Option<&str>,
        tier: Option<&str>, latency_ms: Option<f64>,
    );]
    }
    /// Record proof-health alert telemetry for a provider.
    #[cfg(feature = "telemetry")]
    pub fn record_sorafs_proof_health_alert(&self, alert: &SorafsProofHealthAlert) {
        if !self.enabled {
            return;
        }
        emit_sorafs_proof_health_alert(&self.metrics, alert);
    }
    #[cfg(not(feature = "telemetry"))]
    #[allow(unused_variables)]
    /// No-op proof-health alert recorder when the `telemetry` feature is disabled.
    pub fn record_sorafs_proof_health_alert(&self, alert: &SorafsProofHealthAlert) {
        let _ = alert;
    }
    telemetry_enabled_metric_methods! {
    /// Increment canonical active-request accounting for a SoraFS gateway route.
    [start_sorafs_gateway_request(labels: SorafsGatewayRequestMetricLabels<'_>);]
    /// Complete canonical request accounting and record the response/TTFB metrics.
    [finish_sorafs_gateway_request(labels: SorafsGatewayResponseMetricLabels<'_>, ttfb: Duration) =>
        .finish_sorafs_gateway_request(labels, ttfb.as_secs_f64() * 1000.0);]
    /// Record one canonical SoraFS gateway proof-verification outcome.
    [record_sorafs_gateway_proof_verification(
        profile_version: &str, result: &str, error_code: &str, duration: Duration,
    ) =>
        .record_sorafs_gateway_proof_verification(
                        profile_version,
                        result,
                        error_code,
                        duration.as_secs_f64() * 1000.0,
                    );]
    /// Record `SoraFS` chunk-range fetch telemetry exposed by Torii.
    #[allow(clippy::too_many_arguments)]
    [record_sorafs_chunk_range(
        endpoint: &str, status: u16, bytes: u64, chunker: Option<&str>, profile: Option<&str>,
        provider_id: Option<&str>, tier: Option<&str>, latency_ms: Option<f64>,
    );]
    /// Update the provider range capability gauge.
    [set_sorafs_provider_range_capability(feature: &str, count: i64);]
    /// Increment the committed routing-authority cache outcome counter.
    [inc_sorafs_routing_authority_cache(outcome: &str);]
    /// Increment the range fetch throttle counter for `reason`.
    [inc_sorafs_range_fetch_throttle(reason: &str);]
    /// Increment the active range fetch concurrency gauge.
    [inc_sorafs_range_fetch_concurrency();]
    /// Decrement the active range fetch concurrency gauge.
    [dec_sorafs_range_fetch_concurrency();]
    /// Record a GAR policy violation observed by the gateway.
    [record_sorafs_gar_violation(reason: &str, detail: &str);]
    /// Record a deterministic gateway refusal emitted by Torii.
    [record_sorafs_gateway_refusal(
        status: u16, reason: &str, profile: &str, provider_id: &str, scope: &str
    );]
    /// Publish metadata about the canonical `SoraFS` gateway fixture bundle.
    [set_sorafs_gateway_fixture_metadata(
        version: &str, profile: &str, digest_hex: &str, released_at_unix: u64,
    );]
    /// Observe encoder-to-ingest latency for an incoming Taikai segment.
    [observe_taikai_ingest_latency(cluster: &str, stream: &str, latency_ms: u32);]
    /// Observe live-edge drift for an incoming Taikai segment (signed gauge + absolute histogram).
    [observe_taikai_live_edge_drift(cluster: &str, stream: &str, drift_ms: i32);]
    /// Increment Taikai ingest error counters grouped by cluster/stream/reason.
    [inc_taikai_ingest_error(cluster: &str, stream: &str, reason: &str);]
    /// Record a Taikai alias rotation accepted via `/v1/da/ingest`.
    #[allow(clippy::too_many_arguments)]
    [record_taikai_alias_rotation(
        cluster: &str, event: &str, stream: &str, alias_namespace: &str, alias_name: &str,
        window_start_sequence: u64, window_end_sequence: u64, manifest_digest_hex: &str,
    );]
    }
    telemetry_enabled_metric_methods! {
    /// Increment Torii active connection gauge for the provided scheme label.
    [inc_torii_active_conn(scheme: &'static str) =>
        .torii_active_connections_total.with_label_values(&[scheme]).inc();]
    /// Decrement Torii active connection gauge for the provided scheme label.
    [dec_torii_active_conn(scheme: &'static str) =>
        .torii_active_connections_total.with_label_values(&[scheme]).dec();]
    }
    telemetry_enabled_metric_methods! {
    /// Record the latest `SoraFS` metering snapshot for `provider`.
    #[cfg(feature = "telemetry")]
    #[allow(clippy::too_many_arguments)]
    [record_sorafs_metering(
        provider: &str, declared_gib: u64, effective_gib: u64, utilised_gib: u64,
        outstanding_gib: u64, outstanding_orders: u64, gib_hours: f64, orders_issued: u64,
        orders_completed: u64, orders_failed: u64, uptime_bps: u32, por_bps: u32,
    );]
    /// Record the latest `SoraFS` storage scheduler snapshot for `provider`.
    #[cfg(feature = "telemetry")]
    #[allow(clippy::too_many_arguments)]
    [record_sorafs_storage(
        provider: &str, bytes_used: u64, bytes_capacity: u64, provider_ingest_inflight: u64,
        fetch_inflight: u64, fetch_bytes_per_sec: u64, por_inflight: u64,
        por_samples_success: u64, por_samples_failed: u64,
    );]
    }
    /// Record the `PoR` ingestion backlog for a manifest/provider pair.
    #[cfg(feature = "telemetry")]
    pub fn record_sorafs_por_ingestion_backlog(
        &self,
        provider: &str,
        manifest: &str,
        pending: u64,
    ) {
        self.metrics
            .record_sorafs_por_ingestion_backlog(provider, manifest, pending);
    }
    /// Record the cumulative `PoR` ingestion failure count for a manifest/provider pair.
    #[cfg(feature = "telemetry")]
    pub fn record_sorafs_por_ingestion_failures(
        &self,
        provider: &str,
        manifest: &str,
        failures_total: u64,
    ) {
        self.metrics
            .record_sorafs_por_ingestion_failures(provider, manifest, failures_total);
    }
    /// Record a `PoR` scheduler challenge.
    #[cfg(feature = "telemetry")]
    pub fn record_sorafs_por_scheduler_challenge(&self, forced: bool, duplicate_samples: usize) {
        self.metrics
            .record_sorafs_por_scheduler_challenge(forced, duplicate_samples);
    }
    /// Record a failed `PoR` scheduler run.
    #[cfg(feature = "telemetry")]
    pub fn record_sorafs_por_scheduler_failure(&self) {
        self.metrics.record_sorafs_por_scheduler_failure();
    }
    telemetry_enabled_metric_methods! {
    /// Record the consensus-maintained global `SoraFS` pin resource summary.
    #[cfg(feature = "telemetry")]
    [record_sorafs_pin_resource_usage(retained_manifests: u64, live_content_bytes: u64);]
    /// Record `SoraFS` alias cache observations exposed by Torii.
    #[cfg(feature = "telemetry")]
    [record_sorafs_alias_cache(result: &str, reason: &str, age_secs: f64);]
    }
    /// Record cardinality-safe HTTP request metrics for Torii.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_torii_http_request(
        &self,
        route_id: &str,
        route_template: &str,
        surface: &str,
        method: &str,
        status: StatusCode,
        content_type: &str,
        representation: &str,
        error_code: &str,
        duration: Duration,
        request_bytes: Option<u64>,
        response_bytes: Option<u64>,
    ) {
        if self.enabled {
            let status_label = status.as_u16().to_string();
            let content_label = if content_type.is_empty() {
                String::from("unknown")
            } else {
                content_type.to_ascii_lowercase()
            };
            self.metrics
                .torii_http_requests_total
                .with_label_values(&[
                    route_id,
                    route_template,
                    surface,
                    representation,
                    error_code,
                    content_label.as_str(),
                    method,
                    status_label.as_str(),
                ])
                .inc();
            self.metrics
                .torii_http_request_duration_seconds
                .with_label_values(&[
                    route_id,
                    route_template,
                    surface,
                    representation,
                    content_label.as_str(),
                    method,
                ])
                .observe(duration.as_secs_f64());
            if let Some(bytes) = request_bytes {
                self.metrics
                    .torii_http_request_bytes_total
                    .with_label_values(&[
                        route_id,
                        route_template,
                        surface,
                        representation,
                        content_label.as_str(),
                        method,
                    ])
                    .inc_by(bytes);
            }
            if let Some(bytes) = response_bytes {
                self.metrics
                    .torii_http_response_bytes_total
                    .with_label_values(&[
                        route_id,
                        route_template,
                        surface,
                        representation,
                        error_code,
                        content_label.as_str(),
                        method,
                        status_label.as_str(),
                    ])
                    .inc_by(bytes);
            }
        }
    }
    /// Record Torii transaction lane-admission latency without synchronizing the telemetry actor.
    pub fn observe_torii_lane_admission_latency(
        &self,
        endpoint: &str,
        lane_id: LaneId,
        elapsed_seconds: f64,
    ) {
        if self.enabled {
            let lane_label = lane_id.as_u32().to_string();
            self.metrics
                .torii_lane_admission_latency_seconds
                .with_label_values(&[lane_label.as_str(), endpoint])
                .observe(elapsed_seconds);
        }
    }
    telemetry_enabled_metric_methods! {
    /// Record Torii route-stage latency without synchronizing the telemetry actor.
    [observe_torii_route_stage_latency(
        route_kind: &str, stage: &str, outcome: &str, duration: Duration,
    ) =>
                        .torii_route_stage_latency_seconds
                        .with_label_values(&[route_kind, stage, outcome])
                        .observe(duration.as_secs_f64());]
    }
    /// Record Torii snapshot query metrics without synchronizing the telemetry actor.
    pub fn observe_torii_query_snapshot(
        &self,
        mode: &str,
        first_batch_latency_ms: Option<f64>,
        gas_units: &[u64],
    ) {
        if self.enabled {
            self.metrics
                .torii_query_snapshot_requests
                .with_label_values(&[mode])
                .inc();
            if let Some(ms) = first_batch_latency_ms {
                self.metrics
                    .torii_query_snapshot_first_batch_ms
                    .with_label_values(&[mode])
                    .observe(ms);
            }
            for units in gas_units {
                self.metrics
                    .torii_query_snapshot_gas_consumed_units_total
                    .with_label_values(&[mode])
                    .inc_by(*units);
            }
        }
    }
    telemetry_enabled_metric_methods! {
    /// Record an API-token-gated Torii endpoint hit without exposing token material.
    [inc_torii_api_token_hit(endpoint: &str, token_state: &str);]
    }
    /// Record metrics for the content gateway path.
    pub fn observe_torii_content_request(&self, outcome: &str, bytes: u64, duration: Duration) {
        if self.enabled {
            self.metrics
                .torii_content_requests_total
                .with_label_values(&[outcome])
                .inc();
            self.metrics
                .torii_content_request_duration_seconds
                .with_label_values(&[outcome])
                .observe(duration.as_secs_f64());
            self.metrics
                .torii_content_response_bytes_total
                .with_label_values(&[outcome])
                .inc_by(bytes);
        }
    }
    telemetry_enabled_metric_methods! {
    /// Record proof endpoint request metrics.
    [observe_torii_proof_request(endpoint: &str, outcome: &str, bytes: u64, duration: Duration) =>
        .record_torii_proof_request(endpoint, outcome, bytes, duration);]
    /// Record explorer endpoint request metrics.
    [record_torii_explorer_request(endpoint: &str, outcome: &str, duration: Duration);]
    /// Increment proof cache hit counter for the provided endpoint.
    [inc_torii_proof_cache_hit(endpoint: &str);]
    }
    /// Record scheme-level Torii request latency and failure counters.
    pub fn observe_torii_request_by_scheme(
        &self,
        scheme: &str,
        status: StatusCode,
        duration: Duration,
    ) {
        if self.enabled {
            self.metrics
                .torii_request_duration_seconds
                .with_label_values(&[scheme])
                .observe(duration.as_secs_f64());
            if status.is_client_error() || status.is_server_error() {
                let status_label = status.as_u16().to_string();
                self.metrics
                    .torii_request_failures_total
                    .with_label_values(&[scheme, status_label.as_str()])
                    .inc();
            }
        }
    }
    telemetry_enabled_metric_methods! {
    /// Record a rejected attachment during Torii sanitization.
    [inc_torii_attachment_reject(reason: &str);]
    /// Record attachment sanitization latency in milliseconds.
    [observe_torii_attachment_sanitize_ms(millis: u64);]
    }
    /// Observe attachment size/latency for the background prover.
    pub fn observe_torii_zk_prover(
        &self,
        status: &'static str,
        content_type: &str,
        size_bytes: u64,
        latency_ms: u64,
    ) {
        if self.enabled {
            self.metrics
                .torii_zk_prover_attachment_bytes
                .with_label_values(&[status, content_type])
                .observe(u64_to_f64(size_bytes));
            self.metrics
                .torii_zk_prover_latency_ms
                .with_label_values(&[status])
                .observe(u64_to_f64(latency_ms));
        }
    }
    telemetry_enabled_metric_methods! {
    /// Increment the TTL GC counter for the background prover by `deleted` entries.
    [inc_torii_zk_prover_gc(deleted: u64) => .torii_zk_prover_gc_total.inc_by(deleted);]
    /// Set the number of background prover attachments currently in flight.
    [set_torii_zk_prover_inflight(inflight: u64) => .torii_zk_prover_inflight.set(inflight);]
    /// Set the number of background prover attachments pending processing.
    [set_torii_zk_prover_pending(pending: u64) => .torii_zk_prover_pending.set(pending);]
    }
    /// Record bytes processed and duration for the last background prover scan.
    pub fn record_torii_zk_prover_scan(&self, bytes: u64, millis: u64) {
        if self.enabled {
            self.metrics.torii_zk_prover_last_scan_bytes.set(bytes);
            self.metrics.torii_zk_prover_last_scan_ms.set(millis);
        }
    }
    telemetry_enabled_metric_methods! {
    /// Increment the background prover budget exhaustion counter.
    [inc_torii_zk_prover_budget_exhausted(reason: &'static str) =>
        .torii_zk_prover_budget_exhausted_total.with_label_values(&[reason]).inc();]
    /// Increment the in-flight proof stream gauge for `kind`.
    #[cfg(feature = "telemetry")]
    [inc_sorafs_proof_stream_inflight(kind: &str);]
    /// Decrement the in-flight proof stream gauge for `kind`.
    #[cfg(feature = "telemetry")]
    [dec_sorafs_proof_stream_inflight(kind: &str);]
    /// Update TLS state gauges exposed by Torii.
    [set_sorafs_tls_state(ech_enabled: bool, expiry: Option<Duration>);]
    /// Record the outcome of a TLS renewal attempt.
    [record_sorafs_tls_renewal(result: &str);]
    /// Update the gauge tracking the active `SoraFS` gateway fixture version.
    [set_sorafs_gateway_fixture_version(version: &str);]
    /// Increment Torii contract error counter for the provided endpoint label.
    [inc_torii_contract_error(endpoint: &'static str) =>
        .torii_contract_errors_total.with_label_values(&[endpoint]).inc();]
    /// Increment Torii contract throttle counter for the provided endpoint label.
    [inc_torii_contract_throttle(endpoint: &'static str) =>
        .torii_contract_throttled_total.with_label_values(&[endpoint]).inc();]
    /// Increment Torii proof throttle counter for the provided endpoint label.
    [inc_torii_proof_throttle(endpoint: &'static str) =>
        .torii_proof_throttled_total.with_label_values(&[endpoint]).inc();]
    }
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    #[allow(clippy::too_many_arguments)]
    pub fn record_sorafs_metering(
        &self,
        _provider: &str,
        _declared_gib: u64,
        _effective_gib: u64,
        _utilised_gib: u64,
        _outstanding_gib: u64,
        _outstanding_orders: u64,
        _gib_hours: f64,
        _orders_issued: u64,
        _orders_completed: u64,
        _orders_failed: u64,
        _uptime_bps: u32,
        _por_bps: u32,
    ) {
    }
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn record_sorafs_por_ingestion_backlog(
        &self,
        _provider: &str,
        _manifest: &str,
        _pending: u64,
    ) {
    }
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn record_sorafs_por_ingestion_failures(
        &self,
        _provider: &str,
        _manifest: &str,
        _failures_total: u64,
    ) {
    }
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn record_sorafs_por_scheduler_challenge(&self, _forced: bool, _duplicate_samples: usize) {}
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn record_sorafs_por_scheduler_failure(&self) {}
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn record_sorafs_pin_resource_usage(
        &self,
        _retained_manifests: u64,
        _live_content_bytes: u64,
    ) {
    }
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    #[allow(clippy::too_many_arguments)]
    pub fn record_sorafs_storage(
        &self,
        _provider: &str,
        _bytes_used: u64,
        _bytes_capacity: u64,
        _provider_ingest_inflight: u64,
        _fetch_inflight: u64,
        _fetch_bytes_per_sec: u64,
        _por_inflight: u64,
        _por_samples_success: u64,
        _por_samples_failed: u64,
    ) {
    }
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn record_sorafs_alias_cache(&self, _result: &str, _reason: &str, _age_secs: f64) {}
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn inc_sorafs_proof_stream_inflight(&self, _kind: &str) {}
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn dec_sorafs_proof_stream_inflight(&self, _kind: &str) {}
    #[cfg(not(feature = "telemetry"))]
    /// No-op when telemetry is disabled.
    pub fn record_sorafs_proof_stream_event(
        &self,
        _kind: &str,
        _result: &str,
        _reason: Option<&str>,
        _provider_id: Option<&str>,
        _tier: Option<&str>,
        _latency_ms: Option<f64>,
    ) {
    }
    #[cfg(test)]
    /// Record a committed block as the latest reported block (the status actor's notification).
    pub fn report_block_commit_blocking(&self, block_header: &BlockHeader) {
        let report = BlockCommitReport::new(block_header, &self.time_source);
        // Tests call this from async and blocking contexts; `blocking_write` would panic on a
        // Tokio worker.
        match self.last_reported_block.try_write() {
            Ok(mut lock) => *lock = Some(report),
            Err(_) if tokio::runtime::Handle::try_current().is_ok() => {
                let last_reported_block = Arc::clone(&self.last_reported_block);
                tokio::spawn(async move {
                    let mut lock = last_reported_block.write().await;
                    *lock = Some(report);
                });
            }
            Err(_) => {
                let mut lock = self.last_reported_block.blocking_write();
                *lock = Some(report);
            }
        }
    }
    #[cfg(feature = "telemetry")]
    fn request_metrics_sync(&self) {
        if !self.enabled {
            return;
        }
        if self
            .sync_requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if let Err(err) = self.actor.try_send(Message::Sync { reply: None }) {
            self.sync_requested.store(false, Ordering::Release);
            iroha_logger::debug!(
                ?err,
                "telemetry sync request skipped; returning last metrics snapshot"
            );
        }
    }
    /// Return the latest metrics snapshot and schedule a best-effort lazy refresh.
    #[cfg(feature = "telemetry")]
    pub fn metrics(&self) -> &Metrics {
        self.request_metrics_sync();
        refresh_ivm_cache_metrics(&self.metrics);
        &self.metrics
    }
    #[cfg(test)]
    /// Refresh lazy metrics within a bound, falling back when the actor is unavailable.
    #[cfg(feature = "telemetry")]
    pub async fn metrics_fresh(&self) -> &Metrics {
        if let Err(err) = self.synchronize_metrics().await {
            self.sync_requested.store(false, Ordering::Release);
            iroha_logger::warn!(
                ?err,
                timeout_ms = METRICS_SYNC_TIMEOUT.as_millis(),
                "telemetry sync failed; returning last metrics snapshot"
            );
        }
        refresh_ivm_cache_metrics(&self.metrics);
        &self.metrics
    }
    /// Refresh lazy metrics, reporting failure when callers cannot publish stale state.
    #[cfg(feature = "telemetry")]
    ///
    /// # Errors
    /// Returns an error if the bounded actor mailbox rejects synchronization, the
    /// actor closes, the synchronization deadline expires, or the actor reports
    /// a failure while refreshing metrics.
    pub async fn metrics_fresh_checked(&self) -> Result<&Metrics, String> {
        if let Err(err) = self.synchronize_metrics().await {
            self.sync_requested.store(false, Ordering::Release);
            return Err(err);
        }
        refresh_ivm_cache_metrics(&self.metrics);
        Ok(&self.metrics)
    }
    /// Return an immutable classified State/Nexus status under one service deadline.
    ///
    /// The bounded actor owns physical catch-up after a waiter expires; no late
    /// response is accepted and no request keeps State or transaction guards.
    #[cfg(feature = "telemetry")]
    ///
    /// # Errors
    /// Returns a status error for disabled telemetry, mailbox/actor/deadline failure,
    /// busy or changed State custody, unavailable or inconsistent history, original
    /// resource refusal, or invalid classified counters.
    pub async fn status_snapshot(
        &self,
        build: &iroha_torii_shared::status::BuildStatus,
    ) -> Result<OwnedStatus, StatusSnapshotError> {
        if !self.enabled {
            return Err(StatusSnapshotError::Disabled);
        }
        let deadline = tokio::time::Instant::now() + METRICS_SYNC_TIMEOUT;
        let (reply, receiver) = oneshot::channel();
        self.actor
            .try_send(Message::Status {
                build: build.clone(),
                deadline,
                reply,
            })
            .map_err(|_| StatusSnapshotError::MailboxUnavailable)?;
        let result = tokio::time::timeout_at(deadline, receiver)
            .await
            .map_err(|_| StatusSnapshotError::DeadlineElapsed)?
            .map_err(|_| StatusSnapshotError::ActorClosed)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(StatusSnapshotError::DeadlineElapsed);
        }
        result
    }
    #[cfg(feature = "telemetry")]
    async fn synchronize_metrics(&self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.sync_requested.store(true, Ordering::Release);
        self.actor
            .try_send(Message::Sync { reply: Some(tx) })
            .map_err(|err| format!("schedule telemetry sync: {err}"))?;
        tokio::time::timeout(METRICS_SYNC_TIMEOUT, rx)
            .await
            .map_err(|_| "telemetry sync timed out".to_owned())?
            .map_err(|_| "telemetry actor closed".to_owned())?
            .map_err(|error| error.to_string())?;
        Ok(())
    }
    /// Access the `SoraNet` privacy aggregator.
    pub fn soranet_privacy(&self) -> Arc<SoranetSecureAggregator> {
        Arc::clone(&self.soranet_privacy)
    }
    /// Record a `SoraNet` privacy telemetry event and publish ready buckets.
    ///
    /// # Errors
    /// Returns [`PrivacyEventError`] when the event falls outside the bounded live-ingest window.
    pub fn record_soranet_privacy_event(
        &self,
        event: &SoranetPrivacyEventV1,
    ) -> Result<(), PrivacyEventError> {
        if !self.enabled {
            return Ok(());
        }
        self.soranet_privacy.record_event(event)?;
        self.publish_ready_soranet_privacy_buckets();
        Ok(())
    }
    /// Ingest a `SoraNet` privacy Prio share emitted by a collector.
    ///
    /// # Errors
    /// Returns [`PrivacyShareError`] when the share fails validation or aggregation.
    pub fn ingest_soranet_privacy_share(
        &self,
        share: SoranetPrivacyPrioShareV1,
    ) -> Result<(), PrivacyShareError> {
        if !self.enabled {
            return Ok(());
        }
        self.soranet_privacy.ingest_prio_share(share)?;
        self.publish_ready_soranet_privacy_buckets();
        Ok(())
    }
    fn publish_ready_soranet_privacy_buckets(&self) {
        let (buckets, snapshot) = self.soranet_privacy.drain_ready_now_with_snapshot();
        self.metrics
            .record_soranet_privacy_queue_snapshot(&snapshot);
        for bucket in buckets {
            self.metrics.record_soranet_privacy_bucket(&bucket);
        }
    }
}
/// Record the shard cursor lag measured in blocks for a given telemetry handle.
pub fn record_da_shard_cursor_lag(
    telemetry: &StateTelemetry,
    lane_id: u32,
    shard_id: u32,
    lag_blocks: i64,
) {
    if telemetry.enabled {
        telemetry
            .metrics
            .set_da_shard_cursor_lag(lane_id, shard_id, lag_blocks);
    }
}
impl From<StateTelemetry> for Telemetry {
    fn from(st: StateTelemetry) -> Self {
        let (actor, _handle) = mpsc::channel(CHANNEL_CAPACITY);
        Telemetry {
            actor,
            last_reported_block: Arc::new(RwLock::new(None)),
            metrics: st.metrics.clone(),
            enabled: st.enabled,
            sync_requested: Arc::new(AtomicBool::new(false)),
            time_source: TimeSource::new_system(),
            soranet_privacy: st.soranet_privacy(),
        }
    }
}
struct Actor {
    handle: mpsc::Receiver<Message>,
    last_reported_block: Arc<RwLock<Option<BlockCommitReport>>>,
    last_sync_block: usize,
    last_sync_hash: Option<HashOf<BlockHeader>>,
    /// Original local history refusal retained independently of an HTTP waiter's lifetime.
    status_read_refusal: Option<(NonZeroUsize, crate::execution_attempt::ExecutionDeferred)>,
    /// Creation time of the committed genesis block. Genesis never changes, so
    /// its body is read from Kura once instead of on every sync.
    genesis_creation_time: Option<Duration>,
    #[cfg(test)]
    status_chunk_barrier: Option<(oneshot::Sender<usize>, oneshot::Receiver<()>)>,
    last_online_peers: BTreeSet<PeerId>,
    online_peers: watch::Receiver<OnlinePeers>,
    local_peer_id: PeerId,
    metrics: Arc<Metrics>,
    state: Arc<State>,
    kura: Arc<Kura>,
    queue: Arc<Queue>,
    enabled: bool,
    sync_requested: Arc<AtomicBool>,
    time_source: TimeSource,
}
impl Actor {
    async fn run(mut self) {
        while let Some(message) = self.handle.recv().await {
            match message {
                #[cfg(test)]
                Message::TestInspectStatusRefusal { inspect, reply } => {
                    inspect(
                        self.status_read_refusal
                            .as_ref()
                            .map(|(_, original)| original),
                    );
                    let _ = reply.send(());
                }
                #[cfg(test)]
                Message::TestBarrier { entered, resume } => {
                    let _ = entered.send(());
                    let _ = resume.await;
                }
                #[cfg(test)]
                Message::TestChunkBarrier { entered, resume } => {
                    self.status_chunk_barrier = Some((entered, resume));
                }
                Message::Sync { reply } => {
                    let result = self.sync().await.map(|_| ());
                    self.sync_requested.store(false, Ordering::Release);
                    if let Some(reply) = reply {
                        let _ = reply.send(result);
                    }
                }
                #[cfg(feature = "telemetry")]
                Message::Status {
                    build,
                    deadline,
                    reply,
                } => {
                    if reply.is_closed() || tokio::time::Instant::now() >= deadline {
                        let _ = reply.send(Err(StatusSnapshotError::DeadlineElapsed));
                        continue;
                    }
                    // Work remains actor-owned through finite chunked catch-up.
                    // Expiration retires only the response, never verified progress.
                    let result = match self.sync().await {
                        Ok(target) => self.owned_status(target, &build),
                        Err(error) => Err(error),
                    };
                    self.sync_requested.store(false, Ordering::Release);
                    let result = if tokio::time::Instant::now() >= deadline {
                        Err(StatusSnapshotError::DeadlineElapsed)
                    } else {
                        result
                    };
                    let _ = reply.send(result);
                }
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    async fn sync(&mut self) -> Result<crate::state::TelemetryStatusTarget, StatusSnapshotError> {
        // Disabled profiles skip recording/updating all metrics.
        if !self.enabled {
            return Err(StatusSnapshotError::Disabled);
        }
        let local_removed = {
            // Release this exact view before any actor await or history read.
            let view = status_state_view(&self.state)?;
            refresh_sumeragi_mode(&self.metrics, &view);
            refresh_ivm_execution_budget_metrics(&self.metrics, &self.state.ivm_execution_budget());
            !view
                .world()
                .peers()
                .iter()
                .any(|peer| peer == &self.local_peer_id)
        };
        if crate::status::local_peer_removed() != local_removed {
            crate::status::set_local_removed_from_world(local_removed);
        }
        let mut peer_count;
        let mut current_online;
        {
            let peer_snapshot = self.online_peers.borrow();
            peer_count = peer_snapshot.len() as u64;
            current_online = peer_snapshot
                .iter()
                .map(|peer| peer.id().clone())
                .collect::<BTreeSet<_>>();
        }
        if local_removed {
            peer_count = 0;
            current_online.clear();
        }
        let mut connected_delta = 0u64;
        for peer_id in &current_online {
            if !self.last_online_peers.contains(peer_id) {
                connected_delta += 1;
            }
        }
        let mut disconnected_delta = 0u64;
        for peer_id in &self.last_online_peers {
            if !current_online.contains(peer_id) {
                disconnected_delta += 1;
            }
        }
        if connected_delta > 0 {
            self.metrics
                .p2p_peer_churn_total
                .with_label_values(&["connected"])
                .inc_by(connected_delta);
        }
        if disconnected_delta > 0 {
            self.metrics
                .p2p_peer_churn_total
                .with_label_values(&["disconnected"])
                .inc_by(disconnected_delta);
        }
        self.last_online_peers = current_online;
        self.metrics.connected_peers.set(peer_count);
        // Queue transitions may have no StateTelemetry handle. Refresh the entire
        // queue observation here so a drained queue cannot retain an earlier
        // consensus-pressure sample indefinitely while the node is idle.
        let pressure = self.queue.pressure_snapshot();
        let queued = pressure.queued_tx_count as u64;
        let active = pressure.tracked_tx_count as u64;
        let inflight = active.saturating_sub(queued);
        self.metrics.queue_size.set(active);
        self.metrics.queue_queued.set(queued);
        self.metrics.queue_inflight.set(inflight);
        self.metrics.sumeragi_tx_queue_depth.set(queued);
        self.metrics
            .sumeragi_tx_queue_capacity
            .set(pressure.capacity.get() as u64);
        self.metrics
            .sumeragi_tx_queue_retained_bytes
            .set(pressure.retained_bytes);
        self.metrics
            .sumeragi_tx_queue_max_retained_bytes
            .set(pressure.max_retained_bytes.get());
        // Match QueuePressureSnapshot::into_backpressure and the operator
        // status projection. Age is a latency signal, not capacity exhaustion.
        self.metrics.sumeragi_tx_queue_saturated.set(u64::from(
            pressure.saturated_by_count || pressure.saturated_by_bytes,
        ));
        self.metrics
            .sumeragi_tx_queue_saturated_by_count
            .set(u64::from(pressure.saturated_by_count));
        self.metrics
            .sumeragi_tx_queue_saturated_by_bytes
            .set(u64::from(pressure.saturated_by_bytes));
        self.metrics
            .sumeragi_tx_queue_saturated_by_age
            .set(u64::from(pressure.saturated_by_age));
        self.metrics
            .sumeragi_tx_queue_oldest_queued_age_ms
            .set(pressure.oldest_queued_tx_age_ms);
        // P2P counters (gauges): sample from p2p module
        self.metrics
            .p2p_dropped_posts
            .set(iroha_p2p::network::dropped_post_count());
        self.metrics
            .p2p_dropped_broadcasts
            .set(iroha_p2p::network::dropped_broadcast_count());
        self.metrics
            .p2p_subscriber_queue_full_total
            .set(iroha_p2p::network::subscriber_queue_full_count());
        let full = &self.metrics.p2p_subscriber_queue_full_by_topic_total;
        full.with_label_values(&["ConsensusSafety"])
            .set(iroha_p2p::network::subscriber_queue_full_consensus_safety_count());
        full.with_label_values(&["Consensus"])
            .set(iroha_p2p::network::subscriber_queue_full_consensus_count());
        full.with_label_values(&["ConsensusChunk"])
            .set(iroha_p2p::network::subscriber_queue_full_consensus_chunk_count());
        full.with_label_values(&["Control"])
            .set(iroha_p2p::network::subscriber_queue_full_control_count());
        full.with_label_values(&["BlockSync"])
            .set(iroha_p2p::network::subscriber_queue_full_block_sync_count());
        full.with_label_values(&["TxGossip"])
            .set(iroha_p2p::network::subscriber_queue_full_tx_gossip_count());
        full.with_label_values(&["PeerGossip"])
            .set(iroha_p2p::network::subscriber_queue_full_peer_gossip_count());
        full.with_label_values(&["Health"])
            .set(iroha_p2p::network::subscriber_queue_full_health_count());
        full.with_label_values(&["Other"])
            .set(iroha_p2p::network::subscriber_queue_full_other_count());
        self.metrics
            .p2p_subscriber_unrouted_total
            .set(iroha_p2p::network::subscriber_unrouted_count());
        let unrouted = &self.metrics.p2p_subscriber_unrouted_by_topic_total;
        unrouted
            .with_label_values(&["ConsensusSafety"])
            .set(iroha_p2p::network::subscriber_unrouted_consensus_safety_count());
        unrouted
            .with_label_values(&["Consensus"])
            .set(iroha_p2p::network::subscriber_unrouted_consensus_count());
        unrouted
            .with_label_values(&["ConsensusChunk"])
            .set(iroha_p2p::network::subscriber_unrouted_consensus_chunk_count());
        unrouted
            .with_label_values(&["Control"])
            .set(iroha_p2p::network::subscriber_unrouted_control_count());
        unrouted
            .with_label_values(&["BlockSync"])
            .set(iroha_p2p::network::subscriber_unrouted_block_sync_count());
        unrouted
            .with_label_values(&["TxGossip"])
            .set(iroha_p2p::network::subscriber_unrouted_tx_gossip_count());
        unrouted
            .with_label_values(&["PeerGossip"])
            .set(iroha_p2p::network::subscriber_unrouted_peer_gossip_count());
        unrouted
            .with_label_values(&["Health"])
            .set(iroha_p2p::network::subscriber_unrouted_health_count());
        unrouted
            .with_label_values(&["Other"])
            .set(iroha_p2p::network::subscriber_unrouted_other_count());
        self.metrics
            .p2p_handshake_failures
            .set(iroha_p2p::peer::handshake_failure_count());
        self.metrics
            .p2p_low_post_throttled_total
            .set(iroha_p2p::network::low_post_throttled_count());
        self.metrics
            .p2p_low_broadcast_throttled_total
            .set(iroha_p2p::network::low_broadcast_throttled_count());
        self.metrics
            .p2p_post_overflow_total
            .set(iroha_p2p::network::post_overflow_count());
        // Per-topic breakdown
        // High/Low by topic
        let by = &self.metrics.p2p_post_overflow_by_topic;
        by.with_label_values(&["High", "ConsensusSafety"])
            .set(iroha_p2p::network::post_overflow_consensus_safety_high_count());
        by.with_label_values(&["High", "Consensus"])
            .set(iroha_p2p::network::post_overflow_consensus_high_count());
        by.with_label_values(&["High", "Control"])
            .set(iroha_p2p::network::post_overflow_control_high_count());
        by.with_label_values(&["High", "BlockSync"])
            .set(iroha_p2p::network::post_overflow_block_sync_high_count());
        by.with_label_values(&["High", "TxGossip"])
            .set(iroha_p2p::network::post_overflow_tx_gossip_high_count());
        by.with_label_values(&["High", "PeerGossip"])
            .set(iroha_p2p::network::post_overflow_peer_gossip_high_count());
        by.with_label_values(&["High", "Health"])
            .set(iroha_p2p::network::post_overflow_health_high_count());
        by.with_label_values(&["High", "Other"])
            .set(iroha_p2p::network::post_overflow_other_high_count());
        by.with_label_values(&["Low", "Consensus"])
            .set(iroha_p2p::network::post_overflow_consensus_low_count());
        by.with_label_values(&["Low", "ConsensusSafety"])
            .set(iroha_p2p::network::post_overflow_consensus_safety_low_count());
        by.with_label_values(&["Low", "Control"])
            .set(iroha_p2p::network::post_overflow_control_low_count());
        by.with_label_values(&["Low", "BlockSync"])
            .set(iroha_p2p::network::post_overflow_block_sync_low_count());
        by.with_label_values(&["Low", "TxGossip"])
            .set(iroha_p2p::network::post_overflow_tx_gossip_low_count());
        by.with_label_values(&["Low", "PeerGossip"])
            .set(iroha_p2p::network::post_overflow_peer_gossip_low_count());
        by.with_label_values(&["Low", "Health"])
            .set(iroha_p2p::network::post_overflow_health_low_count());
        by.with_label_values(&["Low", "Other"])
            .set(iroha_p2p::network::post_overflow_other_low_count());
        // Network Time Service (basic gauges)
        let nts_snapshot = crate::time::telemetry_snapshot();
        let nts = nts_snapshot.status;
        self.metrics.nts_offset_ms.set(nts.offset_ms);
        self.metrics.nts_confidence_ms.set(nts.confidence_ms);
        self.metrics.nts_peers_sampled.set(nts.peer_count as u64);
        self.metrics.nts_samples_used.set(nts.sample_count as u64);
        self.metrics.nts_healthy.set(i64::from(nts.health.healthy));
        self.metrics.nts_fallback.set(i64::from(nts.fallback));
        self.metrics
            .nts_min_samples_ok
            .set(i64::from(nts.health.min_samples_ok));
        self.metrics
            .nts_offset_ok
            .set(i64::from(nts.health.offset_ok));
        self.metrics
            .nts_confidence_ok
            .set(i64::from(nts.health.confidence_ok));
        // NTS RTT histogram (export counters)
        let rtt = nts_snapshot.rtt;
        for (le, cnt) in rtt.bounds_ms.iter().zip(rtt.bucket_counts.iter()) {
            let label = if *le == u64::MAX {
                "+Inf".to_owned()
            } else {
                le.to_string()
            };
            self.metrics
                .nts_rtt_ms_bucket
                .with_label_values(&[&label])
                .set(*cnt);
        }
        self.metrics.nts_rtt_ms_sum.set(rtt.sum_ms);
        self.metrics.nts_rtt_ms_count.set(rtt.count);
        self.metrics
            .p2p_dns_refresh_total
            .set(iroha_p2p::network::dns_refresh_count());
        self.metrics
            .p2p_dns_ttl_refresh_total
            .set(iroha_p2p::network::dns_ttl_refresh_count());
        self.metrics
            .p2p_dns_resolution_fail_total
            .set(iroha_p2p::network::dns_resolution_fail_count());
        self.metrics
            .p2p_dns_reconnect_success_total
            .set(iroha_p2p::network::dns_reconnect_success_count());
        self.metrics
            .p2p_backoff_scheduled_total
            .set(iroha_p2p::network::backoff_scheduled_count());
        self.metrics
            .p2p_deferred_send_enqueued_total
            .set(iroha_p2p::network::deferred_send_enqueued_count());
        self.metrics
            .p2p_deferred_send_dropped_total
            .set(iroha_p2p::network::deferred_send_dropped_count());
        self.metrics
            .p2p_session_reconnect_total
            .set(iroha_p2p::network::session_reconnect_total());
        self.metrics
            .p2p_connect_retry_seconds
            .set(iroha_p2p::network::connect_retry_seconds_total());
        self.metrics
            .p2p_accept_throttled_total
            .set(iroha_p2p::network::accept_throttled_count());
        self.metrics
            .p2p_accept_bucket_evictions_total
            .set(iroha_p2p::network::accept_bucket_evictions_count());
        self.metrics
            .p2p_accept_buckets_current
            .set(iroha_p2p::network::accept_bucket_count());
        let prefix_cache = &self.metrics.p2p_accept_prefix_cache_total;
        prefix_cache
            .with_label_values(&["hit"])
            .set(iroha_p2p::network::accept_prefix_hits_count());
        prefix_cache
            .with_label_values(&["miss"])
            .set(iroha_p2p::network::accept_prefix_misses_count());
        let throttle = &self.metrics.p2p_accept_throttle_decisions_total;
        throttle
            .with_label_values(&["prefix", "allowed"])
            .set(iroha_p2p::network::accept_prefix_allowed_count());
        throttle
            .with_label_values(&["prefix", "throttled"])
            .set(iroha_p2p::network::accept_prefix_throttled_count());
        throttle
            .with_label_values(&["ip", "allowed"])
            .set(iroha_p2p::network::accept_ip_allowed_count());
        throttle
            .with_label_values(&["ip", "throttled"])
            .set(iroha_p2p::network::accept_ip_throttled_count());
        self.metrics
            .p2p_incoming_cap_reject_total
            .set(iroha_p2p::network::incoming_cap_reject_count());
        self.metrics
            .p2p_total_cap_reject_total
            .set(iroha_p2p::network::total_cap_reject_count());
        self.metrics
            .p2p_preauth_source_cap_reject_total
            .set(iroha_p2p::network::preauth_source_cap_reject_count());
        self.metrics
            .p2p_scion_inbound_total
            .set(iroha_p2p::network::scion_inbound_total());
        self.metrics
            .p2p_scion_outbound_total
            .set(iroha_p2p::network::scion_outbound_total());
        // Safety/progress/high/low bounded-queue depth (network actor queues)
        let queue_depth = &self.metrics.p2p_queue_depth;
        queue_depth
            .with_label_values(&["Safety"])
            .set(iroha_p2p::network::network_queue_depth_safety());
        queue_depth
            .with_label_values(&["Progress"])
            .set(iroha_p2p::network::network_queue_depth_progress());
        queue_depth
            .with_label_values(&["High"])
            .set(iroha_p2p::network::network_queue_depth_high());
        queue_depth
            .with_label_values(&["Low"])
            .set(iroha_p2p::network::network_queue_depth_low());
        // High/Low bounded-queue drops (network actor queues)
        let drops = &self.metrics.p2p_queue_dropped_total;
        drops
            .with_label_values(&["High", "Post"])
            .set(iroha_p2p::network::dropped_post_high_count());
        drops
            .with_label_values(&["Low", "Post"])
            .set(iroha_p2p::network::dropped_post_low_count());
        drops
            .with_label_values(&["High", "Broadcast"])
            .set(iroha_p2p::network::dropped_broadcast_high_count());
        drops
            .with_label_values(&["Low", "Broadcast"])
            .set(iroha_p2p::network::dropped_broadcast_low_count());
        // Handshake latency histogram (buckets)
        let bounds = iroha_p2p::peer::handshake_bucket_bounds_ms();
        let counts = iroha_p2p::peer::handshake_bucket_counts();
        for (le, cnt) in bounds.iter().zip(counts.iter()) {
            self.metrics
                .p2p_handshake_ms_bucket
                .with_label_values(&[&le.to_string()])
                .set(*cnt);
        }
        self.metrics
            .p2p_handshake_ms_sum
            .set(iroha_p2p::peer::handshake_ms_sum());
        self.metrics
            .p2p_handshake_ms_count
            .set(iroha_p2p::peer::handshake_ms_count());
        // Handshake error taxonomy
        let herr = &self.metrics.p2p_handshake_error_total;
        herr.with_label_values(&["timeout"])
            .set(iroha_p2p::peer::handshake_error_timeout());
        herr.with_label_values(&["preface"])
            .set(iroha_p2p::peer::handshake_error_preface());
        herr.with_label_values(&["verify"])
            .set(iroha_p2p::peer::handshake_error_verify());
        herr.with_label_values(&["decrypt"])
            .set(iroha_p2p::peer::handshake_error_decrypt());
        herr.with_label_values(&["codec"])
            .set(iroha_p2p::peer::handshake_error_codec());
        herr.with_label_values(&["io"])
            .set(iroha_p2p::peer::handshake_error_io());
        herr.with_label_values(&["other"])
            .set(iroha_p2p::peer::handshake_error_other());
        // Topic frame cap violations
        let caps = &self.metrics.p2p_frame_cap_violations_total;
        caps.with_label_values(&["ConsensusSafety"])
            .set(iroha_p2p::network::cap_violations_consensus_safety());
        caps.with_label_values(&["Consensus"])
            .set(iroha_p2p::network::cap_violations_consensus());
        caps.with_label_values(&["Control"])
            .set(iroha_p2p::network::cap_violations_control());
        caps.with_label_values(&["BlockSync"])
            .set(iroha_p2p::network::cap_violations_block_sync());
        caps.with_label_values(&["TxGossip"])
            .set(iroha_p2p::network::cap_violations_tx_gossip());
        caps.with_label_values(&["PeerGossip"])
            .set(iroha_p2p::network::cap_violations_peer_gossip());
        caps.with_label_values(&["Health"])
            .set(iroha_p2p::network::cap_violations_health());
        caps.with_label_values(&["Other"])
            .set(iroha_p2p::network::cap_violations_other());
        // Reconnect-success export remains pending a dedicated metrics counter.
        // Capture routing and applied journal together; no State guard survives.
        let target = self
            .state
            .telemetry_status_target()
            .map_err(StatusSnapshotError::from)?;
        self.classify_status_target(&target).await?;
        #[allow(clippy::cast_possible_truncation)]
        if self.state.committed_height() > 0 {
            let index = NonZeroUsize::MIN;
            let genesis_timestamp = if self.genesis_creation_time.is_some()
                || self.kura.is_canonical_body_missing(index)
            {
                self.genesis_creation_time
            } else {
                let timestamp = self
                    .read_status_block(index)?
                    .map(|genesis_block| genesis_block.header().creation_time());
                self.genesis_creation_time = timestamp;
                timestamp
            };
            if let Some(timestamp) = genesis_timestamp {
                let curr_time = self.time_source.get_unix_time();
                // this will overflow in 584,942,417 years
                let uptime = curr_time.checked_sub(timestamp).unwrap_or(Duration::ZERO);
                self.metrics.uptime_since_genesis_ms.set(
                    uptime
                        .as_millis()
                        .try_into()
                        .expect("Timestamp should fit into u64"),
                );
            } else if !self.kura.is_canonical_body_missing(
                NonZeroUsize::new(1).expect("genesis height is non-zero"),
            ) {
                iroha_logger::error!("Failed to get genesis block from Kura.");
            }
        }
        let view = status_state_view(&self.state)?;
        let world_view = view.world();
        // These metrics may briefly lead "latest block" when the world snapshot is ahead;
        // that observation window should remain very narrow.
        self.metrics.domains.set(world_view.domains().len() as u64);
        // Domains are registered by users: export a bounded label set, and
        // count each domain from the account-scope index instead of visiting
        // its accounts.
        for domain in world_view.domains_iter().take(ACCOUNTS_GAUGE_MAX_DOMAINS) {
            match self
                .metrics
                .accounts
                .get_metric_with_label_values(&[domain.id().name().as_ref()])
            {
                Err(err) => {
                    #[cfg(debug_assertions)]
                    panic!("BUG: Failed to compose domains: {err}");
                    #[cfg(not(debug_assertions))]
                    iroha_logger::error!(?err, "Failed to compose domains")
                }
                Ok(metrics) => {
                    metrics.set(domain_account_count(world_view, domain.id()) as u64);
                }
            }
        }
        // Runtime: export the fixed v1 ABI version used by this release.
        self.metrics
            .runtime_abi_version
            .set(u64::from(world_view.abi_version()));
        refresh_ivm_cache_metrics(&self.metrics);
        Ok(target)
    }
}
/// Most domains exported with a per-domain `accounts` gauge, in domain-id order.
///
/// Domains are registered on chain, so an unbounded label set would grow the
/// metrics registry, every scrape and every status sync with each new domain.
const ACCOUNTS_GAUGE_MAX_DOMAINS: usize = 256;
/// Number of accounts bound to `domain` through its account-scope index.
///
/// The index is maintained with every alias, label and account change, so its
/// size equals the accounts `accounts_in_domain_iter` yields without looking up
/// each of them.
fn domain_account_count(world: &impl WorldReadOnly, domain: &DomainId) -> usize {
    world
        .account_scope_domain_key(domain)
        .and_then(|key| world.account_scope_account_counts().get(&key))
        .map_or(0, |count| usize::try_from(*count).unwrap_or(usize::MAX))
}
fn refresh_ivm_cache_metrics(metrics: &Metrics) {
    let stats = ivm::ivm_cache::global_stats();
    metrics.ivm_cache_hits.set(stats.hits);
    metrics.ivm_cache_misses.set(stats.misses);
    metrics.ivm_cache_evictions.set(stats.evictions);
    metrics.ivm_cache_decoded_streams.set(stats.decoded_streams);
    metrics
        .ivm_cache_decoded_ops_total
        .set(stats.decoded_ops_total);
    metrics.ivm_cache_decode_failures.set(stats.decode_failures);
    metrics
        .ivm_cache_decode_time_ns_total
        .set(stats.decode_time_ns_total);
    let memory = ivm::cache_memory::memory_stats();
    let as_metric = |bytes: usize| u64::try_from(bytes).unwrap_or(u64::MAX);
    metrics
        .ivm_cache_memory_resident_bytes
        .set(as_metric(memory.measured_resident_bytes()));
    metrics
        .ivm_cache_memory_active_bytes
        .set(as_metric(memory.active_bytes));
    metrics
        .ivm_cache_memory_retained_bytes
        .set(as_metric(memory.retained_bytes));
    metrics
        .ivm_cache_memory_shared_reclaimable_bytes
        .set(as_metric(memory.shared_reclaimable_bytes));
    metrics
        .ivm_cache_memory_shared_borrowed_bytes
        .set(as_metric(memory.shared_borrowed_bytes));
    metrics
        .ivm_cache_memory_shared_evicted_live_bytes
        .set(as_metric(memory.shared_evicted_live_bytes));
    metrics
        .ivm_cache_memory_unclassified_retained_bytes
        .set(as_metric(memory.unclassified_retained_bytes()));
    metrics
        .ivm_cache_memory_peak_bytes
        .set(as_metric(memory.peak_reserved_bytes));
    metrics
        .ivm_cache_memory_unmeasured_owners
        .set(as_metric(memory.unmeasured_active_owners));
}
fn refresh_ivm_execution_budget_metrics(
    metrics: &Metrics,
    budget: &iroha_allocation::AllocationBudget,
) {
    let as_metric = |bytes: usize| u64::try_from(bytes).unwrap_or(u64::MAX);
    metrics
        .ivm_execution_memory_reserved_bytes
        .set(as_metric(budget.reserved_bytes()));
    metrics
        .ivm_execution_memory_peak_bytes
        .set(as_metric(budget.peak_reserved_bytes()));
    metrics
        .ivm_execution_memory_limit_bytes
        .set(as_metric(budget.limit_bytes()));
}
fn block_counts_as_non_empty(block: &iroha_data_model::block::SignedBlock) -> bool {
    !block.is_empty() || block.header().is_genesis()
}
#[derive(Copy, Clone, Debug)]
struct BlockCommitReport {
    hash: HashOf<BlockHeader>,
    height: usize,
    commit_time: Duration,
    observed_at_ms: u64,
}
impl BlockCommitReport {
    fn new(block_header: &BlockHeader, time_source: &TimeSource) -> Self {
        let now = time_source.get_unix_time();
        let observed_at_ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
        let commit_time = if block_header.is_genesis() {
            Duration::ZERO
        } else {
            let created_at = block_header.creation_time();
            now.checked_sub(created_at).unwrap_or(Duration::ZERO)
        };
        Self {
            hash: block_header.hash(),
            height: usize::try_from(block_header.height().get())
                .expect("block height should fit into usize"),
            commit_time,
            observed_at_ms,
        }
    }
}
fn reconcile_last_reported_block_with_kura(
    reported: &mut BlockCommitReport,
    block_header: &BlockHeader,
    time_source: &TimeSource,
) -> bool {
    let actual = BlockCommitReport::new(block_header, time_source);
    if reported.height == actual.height && reported.hash == actual.hash {
        return false;
    }
    iroha_logger::warn!(
        reported_height = reported.height,
        reported_hash = %reported.hash,
        actual_height = actual.height,
        actual_hash = %actual.hash,
        "telemetry last reported block diverged from persisted block; using Kura block as authoritative"
    );
    *reported = actual;
    true
}
/// Start the telemetry service after binding its authoritative resource collector.
///
/// # Errors
/// Returns an error before spawning the actor if the collector descriptors are invalid
/// or the registry already has a resource source. Disabled telemetry does not bind one.
pub fn start(
    metrics: Arc<Metrics>,
    state: Arc<State>,
    kura: Arc<Kura>,
    queue: Arc<Queue>,
    online_peers: watch::Receiver<OnlinePeers>,
    local_peer_id: PeerId,
    time_source: TimeSource,
    enabled: bool,
) -> Result<(Telemetry, Child), iroha_telemetry::metrics::CollectorRegistrationError> {
    #[cfg(feature = "telemetry")]
    if enabled {
        kura.register_resource_telemetry(&metrics)?;
    }
    let (actor, handle) = mpsc::channel(CHANNEL_CAPACITY);
    let last_reported_block = Arc::new(RwLock::new(None));
    let sync_requested = Arc::new(AtomicBool::new(false));
    let soranet_privacy = Arc::new(
        SoranetSecureAggregator::new(PrivacyBucketConfig::default())
            .expect("valid default SoraNet privacy config"),
    );
    Ok((
        Telemetry {
            actor,
            last_reported_block: last_reported_block.clone(),
            metrics: metrics.clone(),
            enabled,
            sync_requested: sync_requested.clone(),
            time_source: time_source.clone(),
            soranet_privacy: Arc::clone(&soranet_privacy),
        },
        Child::new(
            tokio::spawn(
                Actor {
                    handle,
                    metrics,
                    state,
                    kura,
                    queue,
                    last_sync_block: 0,
                    last_sync_hash: None,
                    status_read_refusal: None,
                    genesis_creation_time: None,
                    #[cfg(test)]
                    status_chunk_barrier: None,
                    last_online_peers: BTreeSet::new(),
                    last_reported_block,
                    online_peers,
                    local_peer_id,
                    enabled,
                    sync_requested,
                    time_source,
                }
                .run(),
            ),
            OnShutdown::Abort,
        ),
    ))
}
/// Capture one original State view without waiting on its publishing writer.
fn status_state_view(state: &State) -> Result<crate::state::StateView<'_>, StatusSnapshotError> {
    #[cfg(all(test, sumeragi_core_mutation = "HC203"))]
    {
        // Deliberate mutant: restore the actor's unbounded publication wait.
        Ok(state.view())
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC203")))]
    {
        state.try_view_once().map_err(StatusSnapshotError::from)
    }
}

/// Project the next height's authenticated mode from the status sample's admitted view.
/// Missing, pending or malformed authority clears a stale mode instead of using configuration.
fn refresh_sumeragi_mode(metrics: &Metrics, view: &impl crate::state::StateReadOnly) {
    use iroha_data_model::parameter::system::ConsensusMode;
    let schedule = view.world().consensus_schedule();
    let mode_tag = u64::try_from(view.height())
        .ok()
        .and_then(|height| schedule.ready_after_tip(height))
        .map(|config| match config.epoch.mode {
            ConsensusMode::Permissioned => "permissioned",
            ConsensusMode::Npos => "npos",
        })
        .unwrap_or_default();
    metrics.set_sumeragi_mode_tag(mode_tag);
}

#[cfg(all(feature = "telemetry", test))]
#[allow(clippy::disallowed_types, clippy::float_cmp)]
mod tests {
    #[cfg(feature = "telemetry")]
    use super::StreamingTelemetry;
    use super::*;
    use crate::{
        governance::manifest::{GovernanceRules, LaneManifestRegistry, LaneManifestStatus},
        nexus::space_directory::{SpaceDirectoryManifestRecord, SpaceDirectoryManifestSet},
        pipeline::access::AccessSetSource,
        prelude::World,
        query::store::LiveQueryStore,
        state::StateReadOnly,
        tx::AcceptedTransaction,
    };
    use iroha_config::parameters::actual::ConfidentialGas as ActualConfidentialGas;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, PrivateKey, SignatureOf};
    #[cfg(feature = "telemetry")]
    use iroha_data_model::events::data::social::{
        SocialEvent, ViralEscrowCancelled, ViralEscrowCreated,
    };
    #[cfg(feature = "telemetry")]
    use iroha_data_model::social::ViralEscrowRecord;
    use iroha_data_model::{
        Level, NetworkId, Registrable,
        account::{Account, AccountId},
        asset::{AssetDefinitionId, AssetId},
        events::{
            data::space_directory::{SpaceDirectoryEvent, SpaceDirectoryManifestRevoked},
            time::{ExecutionTime, TimeEventFilter},
        },
        isi::{InstructionBox, Log, Register, Transfer},
        nexus::{
            AssetPermissionManifest, AxtPolicyBinding, AxtPolicyEntry, AxtPolicySnapshot,
            DataSpaceMetadata, LaneConfig, ManifestVersion, UniversalAccountId,
        },
        oracle::KeyedHash,
        peer::Peer,
        prelude::TransactionBuilder,
        trigger::prelude::{Action, Repeats, Trigger, TriggerId},
    };
    #[cfg(feature = "telemetry")]
    use iroha_data_model::{
        events::data::sorafs::SorafsProofHealthAlert, sorafs::capacity::ProviderId,
    };
    use iroha_model_base::peer::PeerId;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_primitives::{
        addr::{SocketAddr, socket_addr},
        time::{MockTimeHandle, TimeSource},
    };
    use iroha_test_samples::gen_account_in;
    use nonzero_ext::nonzero;
    #[cfg(feature = "telemetry")]
    use norito::streaming::{
        SyncDiagnostics, TelemetryAuditOutcome, TelemetryDecodeStats, TelemetryEncodeStats,
        TelemetryEnergyStats, TelemetryNetworkStats,
    };
    use std::{
        collections::{BTreeMap, HashSet},
        path::PathBuf,
        sync::Arc,
        time::Duration,
    };
    use tokio::task::spawn_blocking;
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("telemetry fixture key generation should succeed")
    }
    fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("telemetry algorithm-specific fixture key generation should succeed")
    }
    fn checked_peer_id() -> PeerId {
        PeerId::new(checked_keypair().public_key().clone())
    }
    #[test]
    fn torii_http_metrics_expose_only_stable_route_labels() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(Arc::clone(&metrics), true);
        telemetry.observe_torii_http_request(
            "ledger.executed_block_wire",
            "/v1/ledger/block/{height}",
            "public",
            "GET",
            StatusCode::NOT_FOUND,
            "application/json",
            "json",
            "block_not_found",
            Duration::from_millis(3),
            Some(0),
            Some(96),
        );
        assert_eq!(
            metrics
                .torii_http_requests_total
                .with_label_values(&[
                    "ledger.executed_block_wire",
                    "/v1/ledger/block/{height}",
                    "public",
                    "json",
                    "block_not_found",
                    "application/json",
                    "GET",
                    "404",
                ])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_http_request_bytes_total
                .with_label_values(&[
                    "ledger.executed_block_wire",
                    "/v1/ledger/block/{height}",
                    "public",
                    "json",
                    "application/json",
                    "GET",
                ])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .torii_http_response_bytes_total
                .with_label_values(&[
                    "ledger.executed_block_wire",
                    "/v1/ledger/block/{height}",
                    "public",
                    "json",
                    "block_not_found",
                    "application/json",
                    "GET",
                    "404",
                ])
                .get(),
            96
        );
        let exposition = metrics.try_to_string().expect("encode metrics");
        assert!(exposition.contains("route_id=\"ledger.executed_block_wire\""));
        assert!(exposition.contains("route_template=\"/v1/ledger/block/{height}\""));
        assert!(!exposition.contains("op_8f61d9a9"));
        assert!(!exposition.contains("cursor=eyJzbmFwc2hvdCI6"));
    }
    #[test]
    fn checked_keypair_helpers_preserve_requested_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        assert_eq!(
            checked_keypair_with_algorithm(Algorithm::BlsNormal).algorithm(),
            Algorithm::BlsNormal
        );
    }
    #[test]
    fn metrics_returns_when_actor_not_running() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(Arc::clone(&metrics), true);
        assert!(std::ptr::eq(telemetry.metrics(), metrics.as_ref()));
    }
    #[test]
    fn direct_torii_lane_admission_metric_records_without_actor() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        let histogram = metrics
            .torii_lane_admission_latency_seconds
            .with_label_values(&["0", "transaction"]);
        let before = histogram.get_sample_count();
        telemetry.observe_torii_lane_admission_latency("transaction", LaneId::SINGLE, 0.25);
        assert_eq!(histogram.get_sample_count(), before + 1);
    }
    #[test]
    fn direct_torii_route_stage_metric_records_without_actor() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        let histogram = metrics
            .torii_route_stage_latency_seconds
            .with_label_values(&["query", "verify", "ok"]);
        let before = histogram.get_sample_count();
        telemetry.observe_torii_route_stage_latency(
            "query",
            "verify",
            "ok",
            Duration::from_micros(25),
        );
        assert_eq!(histogram.get_sample_count(), before + 1);
    }
    #[test]
    fn direct_sorafs_pin_resource_usage_records_without_actor_and_honors_gate() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.record_sorafs_pin_resource_usage(17, 4_096);
        assert_eq!(metrics.torii_sorafs_pin_retained_manifests.get(), 17);
        assert_eq!(metrics.torii_sorafs_pin_live_content_bytes.get(), 4_096);
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.record_sorafs_pin_resource_usage(23, 8_192);
        assert_eq!(metrics.torii_sorafs_pin_retained_manifests.get(), 17);
        assert_eq!(metrics.torii_sorafs_pin_live_content_bytes.get(), 4_096);
    }
    #[test]
    fn direct_sorafs_orderbook_api_request_records_without_actor() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        let route = "/v1/sorafs/orderbook/orders";
        telemetry.record_sorafs_orderbook_api_request(route, true);
        assert_eq!(
            metrics
                .torii_sorafs_orderbook_api_requests_total
                .with_label_values(&["orders", "error"])
                .get(),
            1
        );
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.record_sorafs_orderbook_api_request(route, true);
        assert_eq!(
            metrics
                .torii_sorafs_orderbook_api_requests_total
                .with_label_values(&["orders", "error"])
                .get(),
            1
        );
    }
    #[test]
    fn direct_sorafs_orderbook_projection_records_and_fails_closed_without_actor() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.record_sorafs_orderbook_finalized_projection(
            42,
            1_800_000_000,
            [1, 2, 0, 3, 0, 0, 0, 4],
            [[42, 5], [6, 7], [8, 9]],
            1,
            7,
            120,
            86_400,
            12,
            11,
        );
        assert_eq!(
            metrics
                .torii_sorafs_orderbook_finalized_projection_ready
                .get(),
            1
        );
        telemetry.record_sorafs_orderbook_finalized_projection_failure("query_failed");
        assert_eq!(
            metrics
                .torii_sorafs_orderbook_finalized_projection_ready
                .get(),
            0
        );
        assert_eq!(
            metrics
                .torii_sorafs_orderbook_finalized_projection_failures_total
                .with_label_values(&["query_failed"])
                .get(),
            1
        );
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.mark_sorafs_orderbook_finalized_projection_unready();
        telemetry.record_sorafs_orderbook_finalized_projection_failure("query_failed");
        assert_eq!(
            metrics
                .torii_sorafs_orderbook_finalized_projection_failures_total
                .with_label_values(&["query_failed"])
                .get(),
            1
        );
    }
    #[test]
    fn direct_sorafs_gateway_compliance_metrics_record_without_actor() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.record_sorafs_gateway_compliance_request("promote", "success");
        telemetry.record_sorafs_gateway_compliance_serving_decision(
            "manifest_digest",
            "deny",
            "legal_safety_hold",
        );
        telemetry.record_sorafs_gateway_compliance_failure("serving", "expired_catalog");
        telemetry.record_sorafs_gateway_compliance_serving_catalog(
            Some(42),
            Some(1_800_003_600),
            true,
        );
        assert_eq!(
            metrics
                .torii_sorafs_gateway_compliance_requests_total
                .with_label_values(&["promote", "success"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_gateway_compliance_serving_decisions_total
                .with_label_values(&["manifest_digest", "deny", "legal_safety_hold"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_gateway_compliance_failures_total
                .with_label_values(&["serving", "expired_catalog"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_gateway_compliance_serving_catalog_sequence
                .get(),
            42
        );
        assert_eq!(metrics.torii_sorafs_gateway_compliance_ready.get(), 1);
        telemetry.mark_sorafs_gateway_compliance_unready();
        assert_eq!(metrics.torii_sorafs_gateway_compliance_ready.get(), 0);
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.record_sorafs_gateway_compliance_request("promote", "success");
        telemetry.record_sorafs_gateway_compliance_failure("serving", "expired_catalog");
        telemetry.record_sorafs_gateway_compliance_serving_catalog(Some(84), None, true);
        assert_eq!(
            metrics
                .torii_sorafs_gateway_compliance_requests_total
                .with_label_values(&["promote", "success"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_gateway_compliance_failures_total
                .with_label_values(&["serving", "expired_catalog"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_gateway_compliance_serving_catalog_sequence
                .get(),
            42
        );
        assert_eq!(metrics.torii_sorafs_gateway_compliance_ready.get(), 0);
    }
    #[test]
    fn direct_sorafs_reserve_projection_records_and_fails_closed_without_actor() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.record_sorafs_reserve_finalized_projection(&SorafsReserveFinalizedProjection {
            finalized_height: 42,
            lifecycle_stage_counts: [2, 0, 0, 0, 1],
            credit_principal_micro_xor: [120_000_000, 0, 0, 0, 7_000_000],
            credit_shortfall_micro_xor: [5_000_000, 0, 0, 0, 1_000_000],
            accrued_interest_micro_xor: [45_000, 0, 0, 0, 9_000],
            open_appeals: 3,
            custody_counts: [1, 2, 1],
            chain_reconciled_counts: [2, 1],
        });
        assert_eq!(
            metrics
                .torii_sorafs_reserve_finalized_projection_height
                .get(),
            42
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_finalized_projection_ready
                .get(),
            1
        );
        telemetry.record_sorafs_reserve_service_request("top_up", "accepted");
        telemetry.inc_sorafs_reserve_service_rate_limit("top_up", "ingress");
        telemetry.record_sorafs_reserve_service_request(
            "attacker-controlled-route",
            "attacker-controlled-result",
        );
        telemetry.inc_sorafs_reserve_service_rate_limit(
            "attacker-controlled-route",
            "attacker-controlled-reason",
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_service_requests_total
                .with_label_values(&["top_up", "accepted"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_service_rate_limit_total
                .with_label_values(&["top_up", "ingress"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_service_requests_total
                .with_label_values(&["unknown", "unknown"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_service_rate_limit_total
                .with_label_values(&["unknown", "unknown"])
                .get(),
            1
        );
        telemetry.record_sorafs_reserve_finalized_projection_failure();
        assert_eq!(
            metrics
                .torii_sorafs_reserve_finalized_projection_ready
                .get(),
            0
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_finalized_projection_failure_total
                .get(),
            1
        );
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.record_sorafs_reserve_finalized_projection(&SorafsReserveFinalizedProjection {
            finalized_height: 84,
            lifecycle_stage_counts: [0; 5],
            credit_principal_micro_xor: [0; 5],
            credit_shortfall_micro_xor: [0; 5],
            accrued_interest_micro_xor: [0; 5],
            open_appeals: 0,
            custody_counts: [0; 3],
            chain_reconciled_counts: [0; 2],
        });
        telemetry.mark_sorafs_reserve_finalized_projection_unready();
        telemetry.record_sorafs_reserve_finalized_projection_failure();
        telemetry.record_sorafs_reserve_service_request("top_up", "accepted");
        telemetry.inc_sorafs_reserve_service_rate_limit("top_up", "ingress");
        assert_eq!(
            metrics
                .torii_sorafs_reserve_finalized_projection_height
                .get(),
            42
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_finalized_projection_failure_total
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_service_requests_total
                .with_label_values(&["top_up", "accepted"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_reserve_service_rate_limit_total
                .with_label_values(&["top_up", "ingress"])
                .get(),
            1
        );
    }
    #[test]
    fn direct_torii_query_snapshot_metric_records_request_latency_and_gas() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.observe_torii_query_snapshot("stored", Some(7.5), &[11, 13]);
        assert_eq!(
            metrics
                .torii_query_snapshot_requests
                .with_label_values(&["stored"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_query_snapshot_first_batch_ms
                .with_label_values(&["stored"])
                .get_sample_count(),
            1
        );
        assert_eq!(
            metrics
                .torii_query_snapshot_gas_consumed_units_total
                .with_label_values(&["stored"])
                .get(),
            24
        );
    }
    #[tokio::test]
    async fn commit_time_clamps_when_block_created_in_future() {
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(1_000));
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 2_000, 0);
        let report = BlockCommitReport::new(&header, &time_source);
        assert_eq!(report.commit_time, Duration::ZERO);
    }
    #[tokio::test]
    async fn reconcile_last_reported_block_keeps_matching_report() {
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(1_000));
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 900, 0);
        let mut report = BlockCommitReport::new(&header, &time_source);
        let corrected = reconcile_last_reported_block_with_kura(&mut report, &header, &time_source);
        assert!(!corrected);
        assert_eq!(report.hash, header.hash());
        assert_eq!(report.height, 2);
        assert_eq!(report.commit_time, Duration::from_millis(100));
    }
    #[tokio::test]
    async fn reconcile_last_reported_block_uses_kura_block_on_hash_mismatch() {
        let (_handle, time_source) = TimeSource::new_mock(Duration::from_millis(1_000));
        let stale_header = BlockHeader::new(nonzero!(2_u64), None, None, 900, 0);
        let persisted_header = BlockHeader::new(nonzero!(2_u64), None, None, 800, 0);
        let mut report = BlockCommitReport::new(&stale_header, &time_source);
        let corrected =
            reconcile_last_reported_block_with_kura(&mut report, &persisted_header, &time_source);
        assert!(corrected);
        assert_eq!(report.hash, persisted_header.hash());
        assert_eq!(report.height, 2);
        assert_eq!(report.commit_time, Duration::from_millis(200));
    }
    #[tokio::test]
    async fn metrics_sync_reconciles_last_reported_block_without_blocking_runtime() {
        let sut = SystemUnderTest::new_native();
        let block = sut.commit_block(sut.create_block());
        let header = block.block().header();
        let stale_header = BlockHeader::new(
            header.height(),
            None,
            None,
            u64::try_from(header.creation_time().as_millis()).expect("time should fit into u64")
                + 1,
            0,
        );
        {
            let mut lock = sut.telemetry.last_reported_block.write().await;
            *lock = Some(BlockCommitReport::new(&stale_header, &sut.time_source));
        }
        sut.force_sync().await;
        let report = sut
            .telemetry
            .last_reported_block
            .read()
            .await
            .expect("telemetry sync should preserve a commit report");
        assert_eq!(report.hash, header.hash());
        assert_eq!(
            report.height,
            usize::try_from(header.height().get()).expect("height should fit into usize")
        );
    }
    #[test]
    fn da_chunking_latency_metrics_updated() {
        let metrics = Arc::new(iroha_telemetry::metrics::Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.observe_da_chunking_seconds(0.25);
        assert_eq!(metrics.torii_da_chunking_seconds.get_sample_count(), 1);
    }
    #[test]
    fn isi_metrics_record_when_enabled() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.record_isi_total("register_domain");
        telemetry.record_isi_success("register_domain");
        telemetry.record_isi_time("register_domain", Duration::from_millis(42));
        assert_eq!(
            metrics
                .isi
                .with_label_values(&["register_domain", "total"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .isi
                .with_label_values(&["register_domain", "success"])
                .get(),
            1
        );
        let histogram = metrics.isi_times.with_label_values(&["register_domain"]);
        assert_eq!(histogram.get_sample_count(), 1);
        assert_eq!(histogram.get_sample_sum(), 42.0);
    }
    #[test]
    fn isi_metrics_skip_when_disabled() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), false);
        telemetry.record_isi_total("register_domain");
        telemetry.record_isi_success("register_domain");
        telemetry.record_isi_time("register_domain", Duration::from_millis(42));
        assert_eq!(
            metrics
                .isi
                .with_label_values(&["register_domain", "total"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .isi
                .with_label_values(&["register_domain", "success"])
                .get(),
            0
        );
        let histogram = metrics.isi_times.with_label_values(&["register_domain"]);
        assert_eq!(histogram.get_sample_count(), 0);
    }
    #[cfg(feature = "telemetry")]
    #[allow(clippy::too_many_lines)]
    #[test]
    fn tx_gossip_caps_and_status_cached() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.record_tx_gossip_caps(
            2_048,
            Some(3),
            None,
            true,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(5),
        );
        assert_eq!(metrics.tx_gossip_frame_cap_bytes.get(), 2_048);
        assert_eq!(metrics.tx_gossip_public_target_cap.get(), 3);
        assert_eq!(metrics.tx_gossip_restricted_target_cap.get(), 0);
        assert_eq!(metrics.tx_gossip_public_target_reshuffle_ms.get(), 2_000);
        assert_eq!(
            metrics.tx_gossip_restricted_target_reshuffle_ms.get(),
            5_000
        );
        assert_eq!(metrics.tx_gossip_drop_unknown_dataspace.get(), 1);
        let caps = *metrics
            .tx_gossip_caps
            .read()
            .expect("tx gossip caps cache poisoned");
        assert_eq!(caps.public_target_reshuffle_ms, Some(2_000));
        assert_eq!(caps.restricted_target_reshuffle_ms, Some(5_000));
        assert!(caps.drop_unknown_dataspace);
        let dataspace = DataSpaceId::new(7);
        let lane = LaneId::new(2);
        let peer_id = checked_peer_id();
        let targets = vec![peer_id];
        telemetry.record_tx_gossip_attempt(
            GossipPlane::Restricted,
            dataspace,
            &[lane],
            &targets,
            Some(nonzero!(3usize)),
            true,
            None,
            2,
            128,
        );
        let sent = metrics
            .tx_gossip_sent_total
            .with_label_values(&["restricted", "7"])
            .get();
        assert_eq!(sent, 1);
        let targets = metrics
            .tx_gossip_targets
            .with_label_values(&["restricted", "7"])
            .get();
        assert_eq!(targets, 1);
        let status = metrics
            .tx_gossip_status
            .read()
            .expect("tx gossip status cache poisoned")
            .clone();
        assert_eq!(status.len(), 1);
        let entry = &status[0];
        assert_eq!(entry.dataspace_id, 7);
        assert_eq!(entry.lane_ids, vec![lane.as_u32()]);
        assert_eq!(entry.targets, 1);
        assert_eq!(entry.target_cap, 3);
        assert_eq!(entry.batch_txs, 2);
        assert_eq!(entry.frame_bytes, 128);
        assert_eq!(entry.outcome, "sent");
        assert!(entry.reason.is_none());
        assert_eq!(entry.target_peers.len(), 1);
        telemetry.record_tx_gossip_attempt(
            GossipPlane::Restricted,
            dataspace,
            &[lane],
            &[],
            Some(nonzero!(3usize)),
            false,
            Some("no_restricted_targets"),
            0,
            0,
        );
        let dropped = metrics
            .tx_gossip_dropped_total
            .with_label_values(&["restricted", "7", "no_restricted_targets"])
            .get();
        assert_eq!(dropped, 1);
        let targets_after = metrics
            .tx_gossip_targets
            .with_label_values(&["restricted", "7"])
            .get();
        assert_eq!(targets_after, 0);
        let status = metrics
            .tx_gossip_status
            .read()
            .expect("tx gossip status cache poisoned")
            .clone();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].reason.as_deref(), Some("no_restricted_targets"));
        assert_eq!(status[0].outcome, "dropped");
    }
    #[cfg(feature = "telemetry")]
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn status_exposes_tx_gossip_targets_with_aliases() {
        use super::StateTelemetry;
        use iroha_data_model::nexus::{
            DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility,
        };
        use iroha_model_base::peer::PeerId;
        use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
        use iroha_test_samples::PEER_KEYPAIR;
        use nonzero_ext::nonzero;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig {
                    id: LaneId::new(0),
                    dataspace_id: DataSpaceId::new(7),
                    alias: "restricted-alpha".to_owned(),
                    visibility: LaneVisibility::Restricted,
                    ..LaneConfig::default()
                },
                LaneConfig {
                    id: LaneId::new(1),
                    dataspace_id: DataSpaceId::new(9),
                    alias: "restricted-beta".to_owned(),
                    visibility: LaneVisibility::Restricted,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("lane catalog");
        let dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata {
                id: DataSpaceId::new(7),
                alias: "alpha".to_owned(),
                description: Some("restricted alpha".to_owned()),
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: DataSpaceId::new(9),
                alias: "beta".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("dataspace catalog");
        telemetry.set_nexus_catalogs(&lane_catalog, &dataspace_catalog);
        let peer = PeerId::new(PEER_KEYPAIR.public_key().clone());
        telemetry.record_tx_gossip_attempt(
            GossipPlane::Restricted,
            DataSpaceId::new(7),
            &[LaneId::new(0)],
            &[peer],
            Some(nonzero!(3usize)),
            true,
            None,
            2,
            256,
        );
        telemetry.record_tx_gossip_attempt(
            GossipPlane::Restricted,
            DataSpaceId::new(9),
            &[LaneId::new(1)],
            &[],
            Some(nonzero!(2usize)),
            false,
            Some("no_restricted_targets"),
            0,
            0,
        );
        let status = telemetry.status_snapshot(
            &crate::release_identity::BuildIdentity::from_compiled_parts(
                "test-executable",
                Some("1111111111111111111111111111111111111111"),
                None,
                None,
                Some("telemetry"),
                Some("test-target"),
            )
            .expect("explicit executable identity")
            .status(),
        );
        let alpha = status
            .tx_gossip
            .targets
            .iter()
            .find(|entry| entry.dataspace_id == 7)
            .expect("alpha dataspace entry");
        assert_eq!(alpha.dataspace_alias.as_deref(), Some("alpha"));
        assert_eq!(alpha.lane_ids, vec![0]);
        assert_eq!(alpha.targets, 1);
        assert_eq!(alpha.target_peers.len(), 1);
        assert_eq!(alpha.outcome, "sent");
        assert!(alpha.reason.is_none());
        let beta = status
            .tx_gossip
            .targets
            .iter()
            .find(|entry| entry.dataspace_id == 9)
            .expect("beta dataspace entry");
        assert_eq!(beta.dataspace_alias.as_deref(), Some("beta"));
        assert_eq!(beta.lane_ids, vec![1]);
        assert_eq!(beta.targets, 0);
        assert_eq!(beta.outcome, "dropped");
        assert_eq!(beta.reason.as_deref(), Some("no_restricted_targets"));
        assert_eq!(beta.target_cap, 2);
        assert_eq!(beta.batch_txs, 0);
        assert_eq!(beta.frame_bytes, 0);
    }
    #[test]
    fn axt_policy_reject_counter_increments_by_reason() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        let lane = LaneId::new(3);
        telemetry.note_axt_policy_reject(lane, AxtRejectReason::Lane, 7);
        assert_eq!(
            metrics
                .axt_policy_reject_total
                .with_label_values(&["3", "lane"])
                .get(),
            1
        );
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.note_axt_policy_reject(lane, AxtRejectReason::Manifest, 7);
        assert_eq!(
            metrics
                .axt_policy_reject_total
                .with_label_values(&["3", "manifest"])
                .get(),
            0,
            "disabled telemetry must not record additional rejects"
        );
    }
    #[test]
    fn axt_policy_reject_snapshot_tracks_reason_and_version() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics, true);
        let lane = LaneId::new(5);
        telemetry.note_axt_policy_reject(lane, AxtRejectReason::Expiry, 42);
        let snapshot = telemetry
            .axt_policy_reject_snapshot()
            .expect("snapshot recorded");
        assert_eq!(snapshot.lane, lane);
        assert_eq!(snapshot.reason, AxtRejectReason::Expiry);
        assert_eq!(snapshot.snapshot_version, 42);
        let dsid = DataSpaceId::new(99);
        telemetry.set_axt_reject_hint(dsid, lane, 5, 7, AxtRejectReason::HandleEra);
        let entry = AxtPolicyBinding {
            dsid,
            policy: AxtPolicyEntry {
                manifest_root: [1; 32],
                target_lane: lane,
                active_handle_era: 5,
                next_handle_counter: 7,
                current_slot: 0,
            },
        };
        let entries = vec![entry];
        let policy_version = AxtPolicySnapshot::compute_version(&entries);
        telemetry.set_axt_policy_snapshot_version(&AxtPolicySnapshot {
            version: policy_version,
            entries,
        });
        telemetry.set_axt_proof_cache_state(dsid, "hit", [1; 32], 3, Some(4));
        let debug_status = telemetry.axt_debug_status();
        assert_eq!(debug_status.policy_snapshot_version, policy_version);
        assert_eq!(
            debug_status.last_reject.as_ref().map(|r| r.reason),
            Some(AxtRejectReason::Expiry)
        );
        assert_eq!(debug_status.hints.len(), 1);
        assert_eq!(debug_status.cache.len(), 1);
        telemetry.note_axt_policy_reject(lane, AxtRejectReason::Budget, 0);
        let empty_snapshot_reject = telemetry
            .axt_policy_reject_snapshot()
            .expect("zero-version rejection recorded");
        assert_eq!(
            empty_snapshot_reject.snapshot_version, 0,
            "the exact empty-snapshot version must not fall back to a cached non-zero version"
        );
    }
    #[test]
    fn axt_policy_snapshot_cache_events_respect_enabled_flag() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.note_axt_policy_snapshot_cache_event("cache_hit");
        assert_eq!(
            metrics
                .axt_policy_snapshot_cache_events_total
                .with_label_values(&["cache_hit"])
                .get(),
            1
        );
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.note_axt_policy_snapshot_cache_event("cache_miss");
        assert_eq!(
            metrics
                .axt_policy_snapshot_cache_events_total
                .with_label_values(&["cache_miss"])
                .get(),
            0,
            "disabled telemetry must not record cache misses"
        );
    }
    #[test]
    fn axt_proof_cache_events_respect_enabled_flag() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.note_axt_proof_cache_event("hit");
        assert_eq!(
            metrics
                .axt_proof_cache_events_total
                .with_label_values(&["hit"])
                .get(),
            1
        );
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.note_axt_proof_cache_event("miss");
        assert_eq!(
            metrics
                .axt_proof_cache_events_total
                .with_label_values(&["miss"])
                .get(),
            0,
            "disabled telemetry must not record cache misses"
        );
    }
    #[test]
    fn axt_proof_cache_state_tracks_entries() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        let dsid = DataSpaceId::new(5);
        let manifest_root = [0xAA; 32];
        let labels = ["5", "miss", &hex::encode(manifest_root), "7"];
        telemetry.set_axt_proof_cache_state(dsid, "miss", manifest_root, 7, Some(30));
        assert_eq!(
            metrics
                .axt_proof_cache_state
                .with_label_values(&labels)
                .get(),
            30
        );
        telemetry.clear_axt_proof_cache_state(dsid, "miss", manifest_root, 7);
        assert_eq!(
            metrics
                .axt_proof_cache_state
                .with_label_values(&labels)
                .get(),
            0
        );
    }
    #[test]
    fn state_telemetry_tracks_axt_proof_cache_snapshot() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let dsid = DataSpaceId::new(6);
        let manifest_root = [0xBC; 32];
        let labels = ["6", "cleared", &hex::encode(manifest_root), "4"];
        telemetry.set_axt_proof_cache_state(dsid, "miss", manifest_root, 4, Some(12));
        let snapshot = telemetry.axt_proof_cache_status_snapshot();
        assert_eq!(snapshot.len(), 1);
        let entry = &snapshot[0];
        assert_eq!(entry.dataspace, dsid);
        assert_eq!(entry.status, "miss");
        assert_eq!(entry.manifest_root, Some(manifest_root));
        assert_eq!(entry.verified_slot, 4);
        assert_eq!(entry.expiry_slot, Some(12));
        telemetry.clear_axt_proof_cache_state(dsid, "miss", manifest_root, 4);
        let snapshot = telemetry.axt_proof_cache_status_snapshot();
        assert_eq!(snapshot.len(), 1);
        let entry = &snapshot[0];
        assert_eq!(entry.dataspace, dsid);
        assert_eq!(entry.status, "cleared");
        assert_eq!(entry.manifest_root, Some(manifest_root));
        assert_eq!(entry.verified_slot, 4);
        assert_eq!(entry.expiry_slot, None);
        assert_eq!(
            metrics
                .axt_proof_cache_state
                .with_label_values(&labels)
                .get(),
            0
        );
    }
    #[test]
    fn axt_policy_snapshot_version_tracks_hash() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        let entries = vec![
            AxtPolicyBinding {
                dsid: DataSpaceId::new(7),
                policy: AxtPolicyEntry {
                    manifest_root: [0x11; 32],
                    target_lane: LaneId::new(3),
                    active_handle_era: 4,
                    next_handle_counter: 2,
                    current_slot: 9,
                },
            },
            AxtPolicyBinding {
                dsid: DataSpaceId::new(8),
                policy: AxtPolicyEntry {
                    manifest_root: [0x22; 32],
                    target_lane: LaneId::new(4),
                    active_handle_era: 5,
                    next_handle_counter: 3,
                    current_slot: 10,
                },
            },
        ];
        let snapshot = AxtPolicySnapshot {
            version: AxtPolicySnapshot::compute_version(&entries),
            entries,
        };
        telemetry.set_axt_policy_snapshot_version(&snapshot);
        let expected = snapshot.version;
        assert_eq!(metrics.axt_policy_snapshot_version.get(), expected);
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.set_axt_policy_snapshot_version(&AxtPolicySnapshot::default());
        assert_eq!(
            metrics.axt_policy_snapshot_version.get(),
            expected,
            "disabled telemetry must not change the recorded version"
        );
    }
    struct SystemUnderTest {
        telemetry: Telemetry,
        _child: Child,
        online_peers_tx: watch::Sender<OnlinePeers>,
        mock_time_handle: MockTimeHandle,
        time_source: TimeSource,
        kura: Arc<Kura>,
        state: Arc<State>,
        network_id: NetworkId,
        account_id: AccountId,
        account_keypair: KeyPair,
        native_chain: Mutex<Option<crate::sumeragi::test_chain::CertifiedTestChain>>,
    }
    #[test]
    fn lane_manifest_readiness_exposed() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("lane catalog");
        telemetry.set_nexus_catalogs(&lane_catalog, &DataSpaceCatalog::default());
        let mut statuses = BTreeMap::new();
        statuses.insert(
            LaneId::new(0),
            LaneManifestStatus {
                lane: LaneId::new(0),
                alias: "gov".to_string(),
                dataspace: DataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("parliament".to_string()),
                manifest_path: None,
                governance_rules: None,
                privacy_commitments: Vec::new(),
            },
        );
        telemetry
            .set_lane_manifest_registry(Arc::new(LaneManifestRegistry::from_statuses(statuses)));
        telemetry.record_lane_pipeline_summary(LaneId::new(0), LanePipelineSummary::default());
        let snapshot = metrics
            .nexus_scheduler_lane_teu_status
            .read()
            .expect("lane TEU cache")
            .get(&0)
            .cloned()
            .expect("lane snapshot");
        assert!(snapshot.manifest_required);
        assert!(!snapshot.manifest_ready);
        let mut ready_statuses = BTreeMap::new();
        ready_statuses.insert(
            LaneId::new(0),
            LaneManifestStatus {
                lane: LaneId::new(0),
                alias: "gov".to_string(),
                dataspace: DataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("parliament".to_string()),
                manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
                governance_rules: Some(GovernanceRules::default()),
                privacy_commitments: Vec::new(),
            },
        );
        telemetry.set_lane_manifest_registry(Arc::new(LaneManifestRegistry::from_statuses(
            ready_statuses,
        )));
        telemetry.record_lane_pipeline_summary(LaneId::new(0), LanePipelineSummary::default());
        let updated = metrics
            .nexus_scheduler_lane_teu_status
            .read()
            .expect("lane TEU cache")
            .get(&0)
            .cloned()
            .expect("lane snapshot");
        assert!(updated.manifest_required);
        assert!(updated.manifest_ready);
    }
    #[test]
    fn amx_metrics_recorded() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let lane_catalog = LaneCatalog::new(
            nonzero!(8_u32),
            vec![LaneConfig {
                id: LaneId::new(7),
                alias: "exec".to_string(),
                ..LaneConfig::default()
            }],
        )
        .expect("lane catalog");
        telemetry.set_nexus_catalogs(&lane_catalog, &DataSpaceCatalog::default());
        let lane = LaneId::new(7);
        telemetry.observe_amx_prepare_ms(lane, 12.0);
        telemetry.observe_amx_commit_ms(lane, 4.0);
        telemetry.observe_ivm_exec_ms(lane, 9.0);
        telemetry.inc_amx_abort(lane, "prepare");
        assert_eq!(
            metrics
                .amx_prepare_ms
                .with_label_values(&["7"])
                .get_sample_count(),
            1
        );
        assert_eq!(
            metrics
                .amx_commit_ms
                .with_label_values(&["7"])
                .get_sample_count(),
            1
        );
        assert_eq!(
            metrics
                .ivm_exec_ms
                .with_label_values(&["7"])
                .get_sample_count(),
            1
        );
        assert_eq!(
            metrics
                .amx_abort_total
                .with_label_values(&["7", "prepare"])
                .get(),
            1
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn quantity_nano_projection_is_deterministic_and_saturating() {
        let exact = Quantity::from_canonical_numeric(Numeric::new(42_u32, 9))
            .expect("nano-exact fixture is a quantity");
        assert_eq!(quantity_to_nano_saturating(&exact), 42);
        let sub_nano = Quantity::from_canonical_numeric(Numeric::new(19_u32, 10))
            .expect("sub-nano fixture is a quantity");
        assert_eq!(quantity_to_nano_saturating(&sub_nano), 1);
        assert_eq!(
            quantity_to_nano_saturating(&Quantity::from(u128::MAX)),
            u128::MAX
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn sorafs_proof_health_metrics_recorded() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let provider_id = ProviderId::new([0x11; 32]);
        let alert = SorafsProofHealthAlert {
            provider_id,
            window_start_epoch: 1,
            window_end_epoch: 2,
            prior_strikes: 0,
            strike_threshold: 1,
            pdp_challenges: 4,
            pdp_failures: 3,
            potr_windows: 2,
            potr_breaches: 1,
            triggered_by_pdp: true,
            triggered_by_potr: false,
            max_pdp_failures: 0,
            max_potr_breaches: 0,
            penalty_bond_bps: 100,
            penalty_applied: Quantity::from_canonical_numeric(Numeric::new(42_u32, 9))
                .expect("nano-XOR penalty fixture is a valid quantity"),
            cooldown_active: false,
        };
        telemetry.record_sorafs_proof_health_alert(&alert);
        let provider_hex = hex::encode(provider_id.as_bytes());
        assert_eq!(
            metrics
                .torii_sorafs_proof_health_alerts_total
                .with_label_values(&[provider_hex.as_str(), "pdp", "penalty_applied"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .torii_sorafs_proof_health_pdp_failures
                .with_label_values(&[provider_hex.as_str()])
                .get(),
            i64::from(alert.pdp_failures)
        );
        assert_eq!(
            metrics
                .torii_sorafs_proof_health_potr_breaches
                .with_label_values(&[provider_hex.as_str()])
                .get(),
            i64::from(alert.potr_breaches)
        );
        let penalty_nano = u64::try_from(
            quantity_to_nano_saturating(&alert.penalty_applied).min(u128::from(u64::MAX)),
        )
        .expect("clamped");
        assert_eq!(
            metrics
                .torii_sorafs_proof_health_penalty_nano
                .with_label_values(&[provider_hex.as_str()])
                .get(),
            penalty_nano
        );
        assert_eq!(
            metrics
                .torii_sorafs_proof_health_window_end_epoch
                .with_label_values(&[provider_hex.as_str()])
                .get(),
            alert.window_end_epoch
        );
        assert_eq!(
            metrics
                .torii_sorafs_proof_health_cooldown
                .with_label_values(&[provider_hex.as_str()])
                .get(),
            0
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn confidential_tree_metrics_recorded() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let asset_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("sora", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let label = asset_id.to_string();
        let initial = ConfidentialTreeStats {
            commitments: 42,
            tree_depth: 17,
            root_history: 8,
            frontier_checkpoints: 3,
            last_checkpoint_height: 24,
            last_checkpoint_commitments: 21,
            root_evictions: 0,
            frontier_evictions: 0,
        };
        telemetry.record_confidential_tree_stats(&asset_id, initial);
        assert_eq!(
            metrics
                .confidential_tree_commitments
                .with_label_values(&[label.as_str()])
                .get(),
            initial.commitments
        );
        assert_eq!(
            metrics
                .confidential_tree_depth
                .with_label_values(&[label.as_str()])
                .get(),
            initial.tree_depth
        );
        assert_eq!(
            metrics
                .confidential_root_history_entries
                .with_label_values(&[label.as_str()])
                .get(),
            initial.root_history
        );
        assert_eq!(
            metrics
                .confidential_frontier_checkpoints
                .with_label_values(&[label.as_str()])
                .get(),
            initial.frontier_checkpoints
        );
        assert_eq!(
            metrics
                .confidential_frontier_last_height
                .with_label_values(&[label.as_str()])
                .get(),
            initial.last_checkpoint_height
        );
        assert_eq!(
            metrics
                .confidential_frontier_last_commitments
                .with_label_values(&[label.as_str()])
                .get(),
            initial.last_checkpoint_commitments
        );
        assert_eq!(
            metrics
                .confidential_root_evictions_total
                .with_label_values(&[label.as_str()])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .confidential_frontier_evictions_total
                .with_label_values(&[label.as_str()])
                .get(),
            0
        );
        let updated = ConfidentialTreeStats {
            commitments: 64,
            tree_depth: 19,
            root_history: 10,
            frontier_checkpoints: 4,
            last_checkpoint_height: 48,
            last_checkpoint_commitments: 34,
            root_evictions: 2,
            frontier_evictions: 1,
        };
        telemetry.record_confidential_tree_stats(&asset_id, updated);
        assert_eq!(
            metrics
                .confidential_tree_commitments
                .with_label_values(&[label.as_str()])
                .get(),
            updated.commitments
        );
        assert_eq!(
            metrics
                .confidential_tree_depth
                .with_label_values(&[label.as_str()])
                .get(),
            updated.tree_depth
        );
        assert_eq!(
            metrics
                .confidential_root_history_entries
                .with_label_values(&[label.as_str()])
                .get(),
            updated.root_history
        );
        assert_eq!(
            metrics
                .confidential_frontier_checkpoints
                .with_label_values(&[label.as_str()])
                .get(),
            updated.frontier_checkpoints
        );
        assert_eq!(
            metrics
                .confidential_frontier_last_height
                .with_label_values(&[label.as_str()])
                .get(),
            updated.last_checkpoint_height
        );
        assert_eq!(
            metrics
                .confidential_frontier_last_commitments
                .with_label_values(&[label.as_str()])
                .get(),
            updated.last_checkpoint_commitments
        );
        assert_eq!(
            metrics
                .confidential_root_evictions_total
                .with_label_values(&[label.as_str()])
                .get(),
            updated.root_evictions
        );
        assert_eq!(
            metrics
                .confidential_frontier_evictions_total
                .with_label_values(&[label.as_str()])
                .get(),
            updated.frontier_evictions
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn confidential_tree_metrics_skip_when_disabled() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), false);
        let asset_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("sora", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let label = asset_id.to_string();
        let stats = ConfidentialTreeStats {
            commitments: 5,
            tree_depth: 6,
            root_history: 2,
            frontier_checkpoints: 1,
            last_checkpoint_height: 11,
            last_checkpoint_commitments: 7,
            root_evictions: 3,
            frontier_evictions: 4,
        };
        telemetry.record_confidential_tree_stats(&asset_id, stats);
        assert_eq!(
            metrics
                .confidential_tree_commitments
                .with_label_values(&[label.as_str()])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .confidential_root_evictions_total
                .with_label_values(&[label.as_str()])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .confidential_frontier_evictions_total
                .with_label_values(&[label.as_str()])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .confidential_frontier_last_height
                .with_label_values(&[label.as_str()])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .confidential_frontier_last_commitments
                .with_label_values(&[label.as_str()])
                .get(),
            0
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn confidential_gas_schedule_metrics_update() {
        let metrics = Metrics::default();
        let gas = ActualConfidentialGas {
            proof_base: 7,
            per_public_input: 11,
            per_proof_byte: 13,
            per_nullifier: 17,
            per_commitment: 19,
        };
        metrics.set_confidential_gas_schedule(&gas);
        assert_eq!(metrics.confidential_gas_base_verify.get(), gas.proof_base);
        assert_eq!(
            metrics.confidential_gas_per_public_input.get(),
            gas.per_public_input
        );
        assert_eq!(
            metrics.confidential_gas_per_proof_byte.get(),
            gas.per_proof_byte
        );
        assert_eq!(
            metrics.confidential_gas_per_nullifier.get(),
            gas.per_nullifier
        );
        assert_eq!(
            metrics.confidential_gas_per_commitment.get(),
            gas.per_commitment
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn confidential_gas_usage_metrics_update() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.set_confidential_gas_usage(42, 84);
        assert_eq!(metrics.confidential_gas_tx_used.get(), 42);
        assert_eq!(metrics.confidential_gas_block_used.get(), 84);
        assert_eq!(metrics.confidential_gas_total.get(), 42);
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn block_fee_units_reset_clears_gauge() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.add_block_fee_amount(
            &"0.042"
                .parse::<Quantity>()
                .expect("canonical block fee quantity"),
        );
        assert_eq!(metrics.block_fee_total_units.get(), 42);
        assert_eq!(metrics.block_fee_total_scale.get(), 3);
        telemetry.reset_block_fee_units();
        assert_eq!(metrics.block_fee_total_units.get(), 0);
        assert_eq!(metrics.block_fee_total_scale.get(), 0);
    }
    #[test]
    fn space_directory_metrics_cover_lifecycle() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let dataspace = DataSpaceId::new(11);
        let dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: dataspace,
            alias: "cbdc".to_string(),
            description: Some("CBDC lane profile".to_string()),
            fault_tolerance: 1,
        }])
        .expect("dataspace catalog");
        telemetry.set_nexus_catalogs(&LaneCatalog::default(), &dataspace_catalog);
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::telemetry"));
        let manifest = AssetPermissionManifest {
            version: ManifestVersion::default(),
            uaid,
            dataspace,
            issued_ms: 1,
            activation_epoch: 5,
            expiry_epoch: None,
            entries: Vec::new(),
        };
        let mut record = SpaceDirectoryManifestRecord::new(manifest);
        record.lifecycle.mark_activated(5);
        let mut manifest_set = SpaceDirectoryManifestSet::default();
        manifest_set.upsert(record);
        let mut world = World::default();
        {
            let storage = world.space_directory_manifests_mut_for_testing();
            storage.insert(uaid, manifest_set);
        }
        let manifest_view = world.space_directory_manifests.view();
        telemetry.seed_space_directory_manifests(&manifest_view);
        assert_eq!(
            metrics
                .nexus_space_directory_active_manifests
                .with_label_values(&["cbdc", "11", "CBDC lane profile"])
                .get(),
            1
        );
        let revoked = SpaceDirectoryEvent::ManifestRevoked(SpaceDirectoryManifestRevoked {
            dataspace,
            uaid,
            manifest_hash: Hash::new(b"manifest-hash"),
            revoked_epoch: 9,
            reason: Some("fraud".to_string()),
        });
        telemetry.on_space_directory_event(&revoked);
        assert_eq!(
            metrics
                .nexus_space_directory_active_manifests
                .with_label_values(&["cbdc", "11", "CBDC lane profile"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .nexus_space_directory_revocations_total
                .with_label_values(&["cbdc", "11", "fraud"])
                .get(),
            1
        );
        telemetry.record_space_directory_revision(dataspace);
        assert_eq!(
            metrics
                .nexus_space_directory_revision_total
                .with_label_values(&["cbdc", "11"])
                .get(),
            1
        );
    }
    #[test]
    fn lane_headroom_pct_computes_expected_ratio() {
        let low = LaneTeuGaugeUpdate {
            capacity: 1_000,
            committed: 950,
            buckets: NexusLaneTeuBuckets {
                floor: 600,
                headroom: 50,
                must_serve: 300,
                circuit_breaker: 0,
            },
            trigger_level: 0,
            starvation_bound_slots: 16,
        };
        assert_eq!(StateTelemetry::lane_headroom_pct(&low), 5);
        let zero_capacity = LaneTeuGaugeUpdate {
            capacity: 0,
            committed: 0,
            buckets: NexusLaneTeuBuckets::default(),
            trigger_level: 0,
            starvation_bound_slots: 0,
        };
        assert_eq!(StateTelemetry::lane_headroom_pct(&zero_capacity), 100);
    }
    #[test]
    fn lane_headroom_event_emits_expected_fields() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let mut snapshot = NexusLaneTeuStatus::default();
        snapshot.deferrals.cap_exceeded = 3;
        snapshot.must_serve_truncations = 1;
        let update = LaneTeuGaugeUpdate {
            capacity: 1_000,
            committed: 950,
            buckets: NexusLaneTeuBuckets {
                floor: 600,
                headroom: 50,
                must_serve: 300,
                circuit_breaker: 50,
            },
            trigger_level: 0,
            starvation_bound_slots: 24,
        };
        let payload = telemetry
            .emit_lane_headroom_event(LaneId::new(2), &snapshot, &update, 5)
            .expect("headroom payload");
        let json = norito::json::to_string(&payload).expect("serialize headroom payload");
        assert!(json.contains("\"lane_id\":2"));
        assert!(json.contains("\"headroom_pct\":5"));
        assert!(json.contains("\"cap_exceeded\":3"));
    }
    #[test]
    fn lane_headroom_event_triggers_below_threshold() {
        let low = LaneTeuGaugeUpdate {
            capacity: 1_000,
            committed: 950,
            buckets: NexusLaneTeuBuckets {
                floor: 600,
                headroom: 50,
                must_serve: 300,
                circuit_breaker: 50,
            },
            trigger_level: 0,
            starvation_bound_slots: 24,
        };
        let high = LaneTeuGaugeUpdate {
            capacity: 1_000,
            committed: 800,
            buckets: NexusLaneTeuBuckets {
                floor: 600,
                headroom: 200,
                must_serve: 200,
                circuit_breaker: 0,
            },
            trigger_level: 0,
            starvation_bound_slots: 24,
        };
        let low_pct = StateTelemetry::lane_headroom_pct(&low);
        let high_pct = StateTelemetry::lane_headroom_pct(&high);
        assert!(StateTelemetry::should_emit_lane_headroom_event(
            low_pct, &low
        ));
        assert!(!StateTelemetry::should_emit_lane_headroom_event(
            high_pct, &high
        ));
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn social_escrow_gauge_and_rejections_recorded() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let binding = KeyedHash::new(
            "pepper-social-test",
            b"pepper-social-test",
            b"handle-social",
        );
        let (sender, _sender_keypair) = gen_account_in("wonderland");
        let escrow = ViralEscrowRecord {
            binding_hash: binding.clone(),
            sender,
            amount: Quantity::from(5_u32),
            created_at_ms: 10,
        };
        telemetry.on_social_event(&SocialEvent::EscrowCreated(ViralEscrowCreated {
            escrow: escrow.clone(),
        }));
        assert_eq!(metrics.social_open_escrows.get(), 1);
        telemetry.on_social_event(&SocialEvent::EscrowCancelled(ViralEscrowCancelled {
            escrow,
            cancelled_at_ms: 20,
        }));
        assert_eq!(metrics.social_open_escrows.get(), 0);
        record_social_rejection(&telemetry, "duplicate_escrow");
        assert_eq!(
            metrics
                .social_rejections_total
                .with_label_values(&["duplicate_escrow"])
                .get(),
            1
        );
    }
    #[test]
    fn oracle_metrics_recorded() {
        use iroha_crypto::Hash;
        use iroha_primitives::numeric::Numeric;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.observe_oracle_settlement_context(
            &"12.5".parse::<Numeric>().expect("canonical TWAP"),
            75,
            150,
            4_500,
        );
        assert_eq!(metrics.oracle_twap_window_seconds.get(), 75);
        assert_eq!(metrics.oracle_haircut_basis_points.get(), 150);
        assert!((metrics.oracle_price_local_per_xor.get() - 12.5).abs() < f64::EPSILON);
        assert!(
            (metrics.oracle_staleness_seconds.get() - 4.5).abs() < f64::EPSILON,
            "expected 4.5s staleness"
        );
        let feed_id: iroha_data_model::oracle::FeedId =
            "price_xor_usd".parse().expect("feed id parses");
        let evidence_hashes = vec![Hash::new(b"evidence-1"), Hash::new(b"evidence-2")];
        telemetry.observe_oracle_aggregation(
            &feed_id,
            3,
            &evidence_hashes,
            Duration::from_millis(12),
        );
        let observations = metrics
            .oracle_observations_total
            .get_metric_with_label_values(&[feed_id.as_str()])
            .expect("counter present")
            .get();
        assert_eq!(observations, 3);
        let feed_events = metrics
            .oracle_feed_events_total
            .get_metric_with_label_values(&[feed_id.as_str()])
            .expect("counter present")
            .get();
        assert_eq!(feed_events, 1);
        let with_evidence = metrics
            .oracle_feed_events_with_evidence_total
            .get_metric_with_label_values(&[feed_id.as_str()])
            .expect("counter present")
            .get();
        assert_eq!(with_evidence, 1);
        let evidence_hashes_total = metrics
            .oracle_evidence_hashes_total
            .get_metric_with_label_values(&[feed_id.as_str()])
            .expect("counter present")
            .get();
        assert_eq!(evidence_hashes_total, 2);
        let histogram = metrics
            .oracle_aggregation_duration_ms
            .get_metric_with_label_values(&[feed_id.as_str()])
            .expect("histogram present");
        assert_eq!(histogram.get_sample_count(), 1);
        assert!(
            histogram.get_sample_sum() >= 12.0,
            "histogram sum should record latency"
        );
    }
    #[test]
    #[cfg(feature = "telemetry")]
    fn audit_outcome_event_includes_expected_fields() {
        use norito::json::to_string as to_json_string;
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics, true);
        let outcome = TelemetryAuditOutcome {
            trace_id: "TRACE-TEST".to_string(),
            slot_height: 42,
            reviewer: "qa-veracity".to_string(),
            status: "fail".to_string(),
            mitigation_url: Some("https://example.net/mitigation".to_string()),
        };
        let payload = telemetry
            .record_audit_outcome(&outcome)
            .expect("telemetry enabled");
        let serialized = to_json_string(&payload).expect("serialize audit event");
        assert!(
            serialized.contains("\"trace_id\":\"TRACE-TEST\""),
            "audit event should include trace identifier"
        );
        assert!(
            serialized.contains("\"status\":\"fail\""),
            "audit event should include status label"
        );
        assert!(
            serialized.contains("mitigation"),
            "audit event should propagate mitigation link"
        );
        assert_eq!(
            telemetry
                .metrics
                .nexus_audit_outcome_total
                .with_label_values(&["TRACE-TEST", "fail"])
                .get(),
            1
        );
        assert!(
            telemetry
                .metrics
                .nexus_audit_outcome_last_timestamp
                .with_label_values(&["TRACE-TEST"])
                .get()
                > 0
        );
    }
    #[cfg(feature = "telemetry")]
    fn record_encode_metrics(telemetry: &StreamingTelemetry, metrics: &Metrics) {
        let encode_stats = TelemetryEncodeStats {
            segment: 7,
            avg_latency_ms: 18,
            dropped_layers: 3,
            avg_audio_jitter_ms: 5,
            max_audio_jitter_ms: 9,
        };
        telemetry.record_encode_stats(&encode_stats);
        assert_eq!(
            metrics.streaming_encode_dropped_layers_total.get(),
            u64::from(encode_stats.dropped_layers)
        );
        assert_eq!(metrics.streaming_encode_latency_ms.get_sample_count(), 1);
        assert_eq!(
            metrics.streaming_encode_audio_jitter_ms.get_sample_count(),
            1
        );
        assert_eq!(
            metrics.streaming_encode_audio_max_jitter_ms.get(),
            u64::from(encode_stats.max_audio_jitter_ms)
        );
    }
    #[cfg(feature = "telemetry")]
    fn record_decode_metrics(telemetry: &StreamingTelemetry, metrics: &Metrics) {
        let decode_stats = TelemetryDecodeStats {
            segment: 7,
            buffer_ms: 120,
            dropped_frames: 2,
            max_decode_queue_ms: 240,
            avg_av_drift_ms: -3,
            max_av_drift_ms: 11,
        };
        telemetry.record_decode_stats(&decode_stats);
        assert_eq!(
            metrics.streaming_decode_dropped_frames_total.get(),
            u64::from(decode_stats.dropped_frames)
        );
        assert_eq!(metrics.streaming_decode_buffer_ms.get_sample_count(), 1);
        assert_eq!(metrics.streaming_decode_max_queue_ms.get_sample_count(), 1);
        assert_eq!(metrics.streaming_decode_av_drift_ms.get_sample_count(), 1);
        assert_eq!(
            metrics.streaming_decode_max_drift_ms.get(),
            u64::from(decode_stats.max_av_drift_ms)
        );
    }
    #[cfg(feature = "telemetry")]
    fn record_network_metrics(telemetry: &StreamingTelemetry, metrics: &Metrics) {
        let network_stats = TelemetryNetworkStats {
            rtt_ms: 33,
            loss_percent_x100: 125,
            fec_repairs: 4,
            fec_failures: 1,
            datagram_reinjects: 6,
        };
        telemetry.record_network_stats(&network_stats);
        assert_eq!(
            metrics.streaming_network_fec_repairs_total.get(),
            u64::from(network_stats.fec_repairs)
        );
        assert_eq!(
            metrics.streaming_network_fec_failures_total.get(),
            u64::from(network_stats.fec_failures)
        );
        assert_eq!(
            metrics.streaming_network_datagram_reinjects_total.get(),
            u64::from(network_stats.datagram_reinjects)
        );
    }
    #[cfg(feature = "telemetry")]
    fn record_sync_metrics(telemetry: &StreamingTelemetry, metrics: &Metrics) {
        let sync_diagnostics = SyncDiagnostics {
            window_ms: 500,
            samples: 96,
            avg_audio_jitter_ms: 6,
            max_audio_jitter_ms: 12,
            avg_av_drift_ms: -4,
            max_av_drift_ms: 15,
            ewma_av_drift_ms: -2,
            violation_count: 3,
        };
        telemetry.record_sync_diagnostics(&sync_diagnostics);
        assert_eq!(metrics.streaming_audio_jitter_ms.get_sample_count(), 1);
        assert_eq!(
            metrics.streaming_audio_max_jitter_ms.get(),
            u64::from(sync_diagnostics.max_audio_jitter_ms)
        );
        assert_eq!(metrics.streaming_av_drift_ms.get_sample_count(), 1);
        assert_eq!(
            metrics.streaming_av_max_drift_ms.get(),
            u64::from(sync_diagnostics.max_av_drift_ms)
        );
        assert_eq!(
            metrics.streaming_av_drift_ewma_ms.get(),
            i64::from(sync_diagnostics.ewma_av_drift_ms)
        );
        assert_eq!(
            metrics.streaming_av_sync_window_ms.get(),
            u64::from(sync_diagnostics.window_ms)
        );
        assert_eq!(
            metrics.streaming_av_sync_violation_total.get(),
            u64::from(sync_diagnostics.violation_count)
        );
        assert_eq!(metrics.streaming_network_rtt_ms.get_sample_count(), 1);
    }
    #[cfg(feature = "telemetry")]
    fn record_energy_metrics(telemetry: &StreamingTelemetry, metrics: &Metrics) {
        let energy_stats = TelemetryEnergyStats {
            segment: 7,
            encoder_milliwatts: 950,
            decoder_milliwatts: 870,
        };
        telemetry.record_energy_stats(&energy_stats);
        assert_eq!(metrics.streaming_energy_encoder_mw.get_sample_count(), 1);
        assert_eq!(metrics.streaming_energy_decoder_mw.get_sample_count(), 1);
    }
    #[test]
    #[cfg(feature = "telemetry")]
    fn streaming_telemetry_records_metrics() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StreamingTelemetry::new(metrics.clone(), true);
        let metrics_ref: &Metrics = &metrics;
        record_encode_metrics(&telemetry, metrics_ref);
        record_decode_metrics(&telemetry, metrics_ref);
        record_network_metrics(&telemetry, metrics_ref);
        record_sync_metrics(&telemetry, metrics_ref);
        record_energy_metrics(&telemetry, metrics_ref);
        telemetry.record_storage_budget_usage("wsv_cold", 64, 128);
        telemetry.inc_storage_budget_exceeded("wsv_cold");
        assert_eq!(
            metrics
                .storage_budget_bytes_used
                .with_label_values(&["wsv_cold"])
                .get(),
            64
        );
        assert_eq!(
            metrics
                .storage_budget_bytes_limit
                .with_label_values(&["wsv_cold"])
                .get(),
            128
        );
        assert_eq!(
            metrics
                .storage_budget_exceeded_total
                .with_label_values(&["wsv_cold"])
                .get(),
            1
        );
    }
    #[test]
    #[cfg(feature = "telemetry")]
    fn streaming_telemetry_debug_includes_counters() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StreamingTelemetry::new(metrics, true);
        let rendered = format!("{telemetry:?}");
        assert!(rendered.contains("StreamingTelemetry"));
        assert!(rendered.contains("rekeys_total"));
        assert!(rendered.contains("gck_rotations_total"));
    }
    #[test]
    fn state_telemetry_detached_counters_set() {
        let metrics = Arc::new(iroha_telemetry::metrics::Metrics::default());
        let st = StateTelemetry::new(metrics.clone(), true);
        st.set_pipeline_detached_prepared(3);
        st.set_pipeline_detached_merged(2);
        st.set_pipeline_detached_fallback(1);
        st.set_pipeline_detached_fallback_reason("fee_postprocessing", 1);
        assert_eq!(metrics.pipeline_detached_prepared.get(), 3);
        assert_eq!(metrics.pipeline_detached_merged.get(), 2);
        assert_eq!(metrics.pipeline_detached_fallback.get(), 1);
        assert_eq!(
            metrics
                .pipeline_detached_fallback_reason
                .with_label_values(&["fee_postprocessing"])
                .get(),
            1
        );
    }
    #[test]
    fn state_telemetry_pipeline_dag_emits() {
        let metrics = Arc::new(Metrics::default());
        let st = StateTelemetry::new(metrics.clone(), true);
        st.set_pipeline_dag(7, 3);
        assert_eq!(metrics.pipeline_dag_vertices.get(), 7);
        assert_eq!(metrics.pipeline_dag_edges.get(), 3);
    }
    #[test]
    fn state_telemetry_pipeline_access_sources_and_conflict_rate_set() {
        let metrics = Arc::new(Metrics::default());
        let st = StateTelemetry::new(metrics.clone(), true);
        st.inc_pipeline_access_set_source(AccessSetSource::ManifestHints, 2);
        st.inc_pipeline_access_set_source(AccessSetSource::PrepassMerge, 1);
        st.set_pipeline_conflict_rate_bps(250);
        assert_eq!(
            metrics
                .pipeline_access_set_source_total
                .with_label_values(&["manifest_hints"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .pipeline_access_set_source_total
                .with_label_values(&["prepass_merge"])
                .get(),
            1
        );
        assert_eq!(metrics.pipeline_conflict_rate_bps.get(), 250);
    }
    #[test]
    fn pipeline_sig_bls_result_totals_are_selected_by_exact_lane() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics, true);
        let first_lane = LaneId::new(1);
        let second_lane = LaneId::new(2);

        telemetry.inc_pipeline_sig_bls_result(first_lane, true, true);
        telemetry.inc_pipeline_sig_bls_result(first_lane, false, false);
        telemetry.inc_pipeline_sig_bls_result(second_lane, true, false);

        assert_eq!(
            telemetry.pipeline_sig_bls_result_totals(first_lane),
            ((1, 0), (0, 1))
        );
        assert_eq!(
            telemetry.pipeline_sig_bls_result_totals(second_lane),
            ((0, 1), (0, 0))
        );
    }
    #[test]
    fn nexus_teu_metrics_recorded() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let lane_update = LaneTeuGaugeUpdate {
            capacity: 128,
            committed: 64,
            buckets: NexusLaneTeuBuckets {
                floor: 32,
                headroom: 32,
                must_serve: 0,
                circuit_breaker: 0,
            },
            trigger_level: 1,
            starvation_bound_slots: 42,
        };
        telemetry.record_nexus_scheduler_lane_teu(LaneId::SINGLE, lane_update);
        telemetry.inc_nexus_scheduler_lane_teu_deferral(LaneId::SINGLE, "cap_exceeded", 3);
        telemetry.inc_nexus_scheduler_must_serve_truncations(LaneId::SINGLE, 2);
        telemetry.record_nexus_scheduler_dataspace_teu(
            LaneId::SINGLE,
            DataSpaceId::UNIVERSAL,
            DataspaceTeuGaugeUpdate {
                backlog: 5,
                age_slots: 3,
                virtual_finish: 7,
            },
        );
        let lane_label = LaneId::SINGLE.as_u32().to_string();
        assert_eq!(
            metrics
                .nexus_scheduler_lane_teu_capacity
                .with_label_values(&[lane_label.as_str()])
                .get(),
            128
        );
        assert_eq!(
            metrics
                .nexus_scheduler_lane_trigger_level
                .with_label_values(&[lane_label.as_str()])
                .get(),
            1
        );
        for (bucket, value) in lane_update.buckets.iter() {
            assert_eq!(
                metrics
                    .nexus_scheduler_lane_teu_slot_breakdown
                    .with_label_values(&[lane_label.as_str(), bucket])
                    .get(),
                value
            );
        }
        assert_eq!(
            metrics
                .nexus_scheduler_lane_teu_deferral_total
                .with_label_values(&[lane_label.as_str(), "cap_exceeded"])
                .get(),
            3
        );
        assert_eq!(
            metrics
                .nexus_scheduler_must_serve_truncations_total
                .with_label_values(&[lane_label.as_str()])
                .get(),
            2
        );
        let lane_snapshots = metrics
            .nexus_scheduler_lane_teu_status
            .read()
            .expect("lane TEU cache poisoned");
        let snapshot = lane_snapshots
            .get(&LaneId::SINGLE.as_u32())
            .expect("lane snapshot missing");
        assert_eq!(snapshot.capacity, lane_update.capacity);
        assert_eq!(snapshot.committed, lane_update.committed);
        assert_eq!(snapshot.deferrals.cap_exceeded, 3);
        assert_eq!(snapshot.must_serve_truncations, 2);
        let ds_label = DataSpaceId::UNIVERSAL.as_u64().to_string();
        assert_eq!(
            metrics
                .nexus_scheduler_dataspace_teu_backlog
                .with_label_values(&[lane_label.as_str(), ds_label.as_str()])
                .get(),
            5
        );
        let ds_snapshots = metrics
            .nexus_scheduler_dataspace_teu_status
            .read()
            .expect("dataspace TEU cache poisoned");
        let ds_snapshot = ds_snapshots
            .get(&(LaneId::SINGLE.as_u32(), DataSpaceId::UNIVERSAL.as_u64()))
            .expect("dataspace snapshot missing");
        assert_eq!(ds_snapshot.backlog, 5);
        assert_eq!(ds_snapshot.age_slots, 3);
        assert_eq!(ds_snapshot.virtual_finish, 7);
    }
    #[test]
    fn dataspace_pipeline_summary_accumulates_tx_served_lifetime() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let lane_id = LaneId::SINGLE;
        let dataspace_id = DataSpaceId::UNIVERSAL;
        telemetry.record_dataspace_pipeline_summary(
            lane_id,
            dataspace_id,
            DataspacePipelineSummary { tx_served: 2 },
        );
        telemetry.record_dataspace_pipeline_summary(
            lane_id,
            dataspace_id,
            DataspacePipelineSummary { tx_served: 3 },
        );
        let ds_snapshots = metrics
            .nexus_scheduler_dataspace_teu_status
            .read()
            .expect("dataspace TEU cache poisoned");
        let ds_snapshot = ds_snapshots
            .get(&(lane_id.as_u32(), dataspace_id.as_u64()))
            .expect("dataspace snapshot missing");
        assert_eq!(ds_snapshot.tx_served, 5);
    }
    #[test]
    fn public_mode_tracks_authenticated_native_state_and_clears_without_authority() {
        use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_data_model::parameter::system::SumeragiConsensusMode;
        let metrics = Metrics::default();
        let exported_mode = || {
            metrics
                .status_snapshot(&iroha_torii_shared::status::BuildStatus::default())
                .sumeragi
                .expect("public consensus telemetry")
                .mode_tag
        };
        let unstarted = State::new(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        refresh_sumeragi_mode(&metrics, &unstarted.view());
        assert_eq!(exported_mode(), "", "pre-genesis state has no authority");
        for (mode, expected) in [
            (SumeragiConsensusMode::Npos, "npos"),
            (SumeragiConsensusMode::Permissioned, "permissioned"),
        ] {
            let mut config = TestChainConfig::new(World::new(), 1_000);
            config.consensus_mode = mode;
            if mode == SumeragiConsensusMode::Npos {
                let policy = iroha_data_model::parameter::system::SumeragiNposParameters {
                    epoch_seed: [0x61; 32],
                    ..Default::default()
                };
                config
                    .genesis_parameters
                    .push(iroha_data_model::parameter::Parameter::Custom(
                        policy.into_custom_parameter(),
                    ));
            }
            let chain = CertifiedTestChain::start(config).expect("authenticated signed genesis");
            refresh_sumeragi_mode(&metrics, &chain.state().view());
            assert_eq!(exported_mode(), expected);
        }
        refresh_sumeragi_mode(&metrics, &unstarted.view());
        assert_eq!(
            exported_mode(),
            "",
            "a missing authority cannot leave a stale mode"
        );
        let mode_cache = Arc::clone(&metrics.sumeragi_mode_tag);
        assert!(
            std::thread::spawn(move || {
                let _lock = mode_cache.write().expect("unpoisoned mode cache");
                panic!("poison the mode cache");
            })
            .join()
            .is_err()
        );
        assert_eq!(exported_mode(), "", "a failed cache must not invent a mode");
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn queue_backpressure_metrics_updated() {
        use std::sync::Arc;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        record_state_tx_queue_backpressure(
            &telemetry, 12, 64, 1_024, 2_048, false, false, false, 500,
        );
        assert_eq!(metrics.sumeragi_tx_queue_depth.get(), 12);
        assert_eq!(metrics.sumeragi_tx_queue_capacity.get(), 64);
        assert_eq!(metrics.sumeragi_tx_queue_retained_bytes.get(), 1_024);
        assert_eq!(metrics.sumeragi_tx_queue_max_retained_bytes.get(), 2_048);
        assert_eq!(metrics.sumeragi_tx_queue_saturated.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_count.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_bytes.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_age.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_oldest_queued_age_ms.get(), 500);
        record_state_tx_queue_backpressure(
            &telemetry, 63, 64, 2_048, 2_048, false, true, true, 7_500,
        );
        assert_eq!(metrics.sumeragi_tx_queue_depth.get(), 63);
        assert_eq!(metrics.sumeragi_tx_queue_capacity.get(), 64);
        assert_eq!(metrics.sumeragi_tx_queue_retained_bytes.get(), 2_048);
        assert_eq!(metrics.sumeragi_tx_queue_max_retained_bytes.get(), 2_048);
        assert_eq!(metrics.sumeragi_tx_queue_saturated.get(), 1);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_count.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_bytes.get(), 1);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_age.get(), 1);
        assert_eq!(metrics.sumeragi_tx_queue_oldest_queued_age_ms.get(), 7_500);
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn queue_age_pressure_is_not_capacity_backpressure() {
        let metrics = Arc::new(Metrics::default());
        let state_telemetry = StateTelemetry::new(metrics.clone(), true);
        let telemetry = Telemetry::new(metrics.clone(), true);
        record_state_tx_queue_backpressure(
            &state_telemetry,
            2,
            20_000,
            21_888,
            134_217_728,
            false,
            false,
            true,
            23_611,
        );
        assert_eq!(metrics.sumeragi_tx_queue_saturated.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_age.get(), 1);
        assert_eq!(metrics.sumeragi_tx_queue_oldest_queued_age_ms.get(), 23_611);

        metrics.sumeragi_tx_queue_saturated.set(1);
        telemetry.record_tx_queue_backpressure(
            2,
            20_000,
            21_888,
            134_217_728,
            false,
            false,
            true,
            23_611,
        );
        assert_eq!(metrics.sumeragi_tx_queue_saturated.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_age.get(), 1);
    }
    #[tokio::test]
    async fn fresh_queue_metrics_replace_stale_pressure_on_an_idle_node() {
        let system = SystemUnderTest::new();
        // Model the last event-driven sample before work was removed without
        // StateTelemetry. No new block or transaction should be needed to clear it.
        system
            .telemetry
            .record_tx_queue_backpressure(2, 2, 21_888, 21_888, true, true, true, 23_611);
        assert_eq!(system.telemetry.metrics.sumeragi_tx_queue_depth.get(), 2);
        assert_eq!(
            system.telemetry.metrics.sumeragi_tx_queue_saturated.get(),
            1
        );

        let metrics = system
            .telemetry
            .metrics_fresh_checked()
            .await
            .expect("fresh metrics for the idle queue");
        assert_eq!(metrics.queue_size.get(), 0);
        assert_eq!(metrics.queue_queued.get(), 0);
        assert_eq!(metrics.queue_inflight.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_depth.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_capacity.get(), 10);
        assert_eq!(metrics.sumeragi_tx_queue_retained_bytes.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_count.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_bytes.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_saturated_by_age.get(), 0);
        assert_eq!(metrics.sumeragi_tx_queue_oldest_queued_age_ms.get(), 0);
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn tiered_snapshot_metrics_updated() {
        use std::sync::Arc;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        record_state_tiered_snapshot(&telemetry, 7, 3, 512, 2, 1024, 1, 2, 3, 2048, 4, 512);
        assert_eq!(metrics.state_tiered_last_snapshot_index.get(), 7);
        assert_eq!(metrics.state_tiered_hot_entries.get(), 3);
        assert_eq!(metrics.state_tiered_hot_bytes.get(), 512);
        assert_eq!(metrics.state_tiered_cold_entries.get(), 2);
        assert_eq!(metrics.state_tiered_cold_bytes.get(), 1024);
        assert_eq!(metrics.state_tiered_hot_promotions.get(), 1);
        assert_eq!(metrics.state_tiered_hot_demotions.get(), 2);
        assert_eq!(metrics.state_tiered_hot_budget_overflow_keys.get(), 3);
        assert_eq!(metrics.state_tiered_hot_budget_overflow_bytes.get(), 2048);
        assert_eq!(metrics.state_tiered_cold_reused_entries.get(), 4);
        assert_eq!(metrics.state_tiered_cold_reused_bytes.get(), 512);
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn storage_budget_metrics_updated() {
        use std::sync::Arc;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.record_storage_budget_usage("kura", 512, 2048);
        telemetry.inc_storage_budget_exceeded("kura");
        assert_eq!(
            metrics
                .storage_budget_bytes_used
                .with_label_values(&["kura"])
                .get(),
            512
        );
        assert_eq!(
            metrics
                .storage_budget_bytes_limit
                .with_label_values(&["kura"])
                .get(),
            2048
        );
        assert_eq!(
            metrics
                .storage_budget_exceeded_total
                .with_label_values(&["kura"])
                .get(),
            1
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn storage_da_metrics_updated() {
        use std::sync::Arc;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.inc_storage_da_cache("kura", "hit");
        telemetry.inc_storage_da_cache("kura", "miss");
        telemetry.add_storage_da_churn_bytes("kura", "evicted", 1024);
        telemetry.add_storage_da_churn_bytes("kura", "rehydrated", 512);
        assert_eq!(
            metrics
                .storage_da_cache_total
                .with_label_values(&["kura", "hit"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .storage_da_cache_total
                .with_label_values(&["kura", "miss"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .storage_da_churn_bytes_total
                .with_label_values(&["kura", "evicted"])
                .get(),
            1024
        );
        assert_eq!(
            metrics
                .storage_da_churn_bytes_total
                .with_label_values(&["kura", "rehydrated"])
                .get(),
            512
        );
    }
    #[test]
    fn state_telemetry_debug_smoke() {
        let telemetry = StateTelemetry::new(Arc::new(Metrics::default()), true);
        let formatted = format!("{telemetry:?}");
        assert!(formatted.contains("StateTelemetry"));
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn governance_proposal_transition_updates_gauges() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.record_governance_proposal_transition(
            None,
            crate::state::GovernanceProposalStatus::Proposed,
        );
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["proposed"])
                .get(),
            1
        );
        telemetry.record_governance_proposal_transition(
            Some(crate::state::GovernanceProposalStatus::Proposed),
            crate::state::GovernanceProposalStatus::ExecutionFailed,
        );
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["proposed"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["execution_failed"])
                .get(),
            1
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn governance_proposal_gauge_seeding_resets_counts() {
        use crate::state::GovernanceProposalStatus as GPS;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.record_governance_proposal_transition(None, GPS::Proposed);
        telemetry.seed_governance_proposal_statuses([
            GPS::ExecutionFailed,
            GPS::ExecutionFailed,
            GPS::Rejected,
        ]);
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["proposed"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["execution_failed"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["rejected"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["enacted"])
                .get(),
            0
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn initial_sortition_uses_an_exact_closed_metric_label() {
        assert_eq!(
            parliament_transition_label(
                iroha_data_model::isi::governance::ParliamentLifecycleTransitionKindV1::RegisterInitialSortition
            ),
            "register_initial_sortition"
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn parliament_metrics_use_only_closed_low_cardinality_labels() {
        use iroha_data_model::{
            events::data::governance::{
                GovernanceEvent, GovernanceParliamentLifecycleTransitionApplied,
            },
            governance::types::{
                GovernanceAttemptId, GovernanceCertificateId, ParliamentNoResultKindV1 as NoResult,
                ProposalContentId,
            },
            isi::governance::ParliamentLifecycleTransitionKindV1 as Transition,
        };

        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let event = GovernanceEvent::ParliamentLifecycleTransitionApplied(
            GovernanceParliamentLifecycleTransitionApplied {
                proposal_content_id: ProposalContentId::new([0xAB; 32]),
                governance_attempt_id: GovernanceAttemptId::new([0xCD; 32]),
                transition_kind: Transition::FailBallotNoResult,
                no_result_kind: Some(NoResult::BallotOpeningDeadlineExpired),
                automatic_outcome: None,
                transition_digest: [0xEF; 32],
                certificate_id: Some(GovernanceCertificateId::new([0x12; 32])),
                at_height: 42,
            },
        );
        let projection = parliament_lifecycle_metric_projection(&event)
            .expect("project committed Parliament lifecycle event");
        telemetry.record_committed_parliament_transition(projection.0, projection.1);
        telemetry.record_committed_parliament_transition(
            Transition::EndorsePublicFinding,
            Some(NoResult::PublicFindingQuorumUnreachable),
        );
        telemetry.record_committed_parliament_transition(
            Transition::FailPublicFindingNoResult,
            Some(NoResult::PublicFindingDeadlineExpired),
        );
        telemetry.record_committed_parliament_transition(
            Transition::FailBodyElectionNoRoster,
            Some(NoResult::SortitionRetriesExhausted),
        );
        telemetry.record_committed_parliament_transition(
            Transition::FinalizeOpenedBallot,
            Some(NoResult::ConfirmationJuryCapacityUnavailable),
        );
        telemetry.record_committed_parliament_transition(
            Transition::FinalizeOpenedBallot,
            Some(NoResult::RandomnessRedrawBudgetExhausted),
        );
        telemetry.record_committed_parliament_transition(
            Transition::CompleteQualification,
            Some(NoResult::PublicFindingDeadlineExpired),
        );

        assert_eq!(
            metrics
                .governance_parliament_transitions_total
                .with_label_values(&["fail_ballot_no_result"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_parliament_transitions_total
                .with_label_values(&["endorse_public_finding"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_parliament_no_result_total
                .with_label_values(&["ballot_opening_deadline_expired"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_parliament_no_result_total
                .with_label_values(&["public_finding_quorum_unreachable"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_parliament_no_result_total
                .with_label_values(&["public_finding_deadline_expired"])
                .get(),
            1,
            "an incompatible transition must not increment the valid deadline outcome again"
        );
        assert_eq!(
            metrics
                .governance_parliament_no_result_total
                .with_label_values(&["sortition_retries_exhausted"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_parliament_no_result_total
                .with_label_values(&["confirmation_jury_capacity_unavailable"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_parliament_no_result_total
                .with_label_values(&["randomness_redraw_budget_exhausted"])
                .get(),
            1
        );

        let exposition = metrics.try_to_string().expect("encode metrics exposition");
        for secret in ["ab", "cd", "ef", "12"] {
            assert!(
                !exposition.contains(&secret.repeat(32)),
                "Parliament metric exposition leaked an event identifier or digest"
            );
        }
        for line in exposition
            .lines()
            .filter(|line| line.starts_with("governance_parliament_"))
        {
            let Some((_, labels_and_value)) = line.split_once('{') else {
                continue;
            };
            let labels = labels_and_value
                .split_once('}')
                .expect("labeled Parliament metric")
                .0;
            assert!(
                labels.starts_with("transition=\"")
                    || labels.starts_with("class=\"")
                    || labels.starts_with("status=\"")
                    || labels.starts_with("stage=\""),
                "unexpected Parliament metric label: {labels}"
            );
            assert!(
                !labels.contains(','),
                "Parliament metrics have one bounded label"
            );
        }
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn parliament_attempt_gauge_seeding_replaces_committed_snapshot() {
        use iroha_data_model::governance::types::{
            GovernanceAttemptStatusV1 as Status, GovernanceStageV1 as Stage,
        };

        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.seed_parliament_attempts([
            (Status::Active, Stage::Qualification),
            (Status::Active, Stage::Rules),
            (Status::Certified, Stage::Enactment),
        ]);
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_status
                .with_label_values(&["active"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_stage
                .with_label_values(&["enactment"])
                .get(),
            1
        );

        telemetry.seed_parliament_attempts([(Status::Rejected, Stage::PolicyJury)]);
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_status
                .with_label_values(&["active"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_status
                .with_label_values(&["rejected"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_stage
                .with_label_values(&["qualification"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_stage
                .with_label_values(&["policy_jury"])
                .get(),
            1
        );

        telemetry.set_parliament_attempt_counts(
            [3, 2, 1, 0, 4, 5],
            [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        );
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_status
                .with_label_values(&["execution_failed"])
                .get(),
            5
        );
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_stage
                .with_label_values(&["qualification"])
                .get(),
            13
        );
        assert_eq!(
            metrics
                .governance_parliament_attempts_by_stage
                .with_label_values(&["enactment"])
                .get(),
            1
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn governance_events_drive_metrics_via_ingest() {
        use crate::state::GovernanceProposalStatus as GPS;
        use iroha_data_model::events::data::governance::{
            GovernanceEvent, GovernanceProposalEnacted,
        };
        use std::sync::Arc;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let proposal_id = [0xAB; 32];
        telemetry.seed_governance_proposals([(proposal_id, GPS::Proposed)]);
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["proposed"])
                .get(),
            1
        );
        telemetry.ingest_data_event(&DataEvent::Governance(GovernanceEvent::ProposalEnacted(
            GovernanceProposalEnacted { id: proposal_id },
        )));
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["proposed"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .governance_proposals_status
                .with_label_values(&["enacted"])
                .get(),
            1
        );
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn governance_bond_events_increment() {
        use iroha_data_model::events::data::governance::{
            GovernanceEvent, GovernanceLockCreated, GovernanceLockExtended, GovernanceLockUnlocked,
        };
        use std::sync::Arc;
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.ingest_data_event(&DataEvent::Governance(GovernanceEvent::LockCreated(
            GovernanceLockCreated {
                referendum_id: "ref".to_string(),
                owner: iroha_test_samples::ALICE_ID.clone(),
                amount: 10_u64.into(),
                expiry_height: 5,
            },
        )));
        telemetry.ingest_data_event(&DataEvent::Governance(GovernanceEvent::LockExtended(
            GovernanceLockExtended {
                referendum_id: "ref".to_string(),
                owner: iroha_test_samples::ALICE_ID.clone(),
                amount: 12_u64.into(),
                expiry_height: 6,
            },
        )));
        telemetry.ingest_data_event(&DataEvent::Governance(GovernanceEvent::LockUnlocked(
            GovernanceLockUnlocked {
                referendum_id: "ref".to_string(),
                owner: iroha_test_samples::ALICE_ID.clone(),
                amount: 12_u64.into(),
            },
        )));
        assert_eq!(
            metrics
                .governance_bond_events_total
                .with_label_values(&["lock_created"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_bond_events_total
                .with_label_values(&["lock_extended"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_bond_events_total
                .with_label_values(&["lock_unlocked"])
                .get(),
            1
        );
    }
    #[test]
    fn protected_namespace_enforcement_and_manifest_activation_metrics() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        telemetry.record_protected_namespace_enforcement("allowed");
        telemetry.record_protected_namespace_enforcement("rejected");
        telemetry.record_manifest_quorum_enforcement("satisfied");
        telemetry.record_manifest_quorum_enforcement("rejected");
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["allowed"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["rejected"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_manifest_quorum_total
                .with_label_values(&["satisfied"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_manifest_quorum_total
                .with_label_values(&["rejected"])
                .get(),
            1
        );
        telemetry.record_manifest_activation(None, "manifest_inserted");
        let activation = GovernanceManifestActivation {
            contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .to_string(),
            code_hash_hex: "deadbeef".to_string(),
            abi_hash_hex: Some("cafebabe".to_string()),
            height: 9,
            activated_at_ms: 42,
        };
        telemetry.record_manifest_activation(Some(activation.clone()), "instance_bound");
        assert_eq!(
            metrics
                .governance_manifest_activations_total
                .with_label_values(&["manifest_inserted"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .governance_manifest_activations_total
                .with_label_values(&["instance_bound"])
                .get(),
            1
        );
        let recent = metrics
            .governance_manifest_recent
            .read()
            .expect("governance manifest cache lock poisoned");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].contract_address, activation.contract_address);
    }
    #[cfg(feature = "telemetry")]
    mod classified_status_tests {
        use super::*;
        include!("telemetry/classified_status_tests.rs");
    }
    impl SystemUnderTest {
        fn new() -> Self {
            Self::with_native_chain(false)
        }
        fn new_native() -> Self {
            Self::with_native_chain(true)
        }
        fn with_native_chain(native: bool) -> Self {
            let metrics = Arc::new(Metrics::default());
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let mut finality_keys = (0xD3_u8..=0xD6)
                .map(|seed| {
                    KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                        .expect("derive telemetry finality validator")
                })
                .collect::<Vec<_>>();
            finality_keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
            let local_peer_id = PeerId::new(finality_keys[0].public_key().clone());
            let (account_id, account_keypair) = gen_account_in("wonderland");
            let account = Account::new(account_id.clone()).build(&account_id);
            let world = World::with([], [account], []);
            {
                let mut peers_block = world.peers.block();
                peers_block.get_mut().extend(
                    finality_keys
                        .iter()
                        .map(|key| PeerId::new(key.public_key().clone())),
                );
                peers_block.commit();
            }
            let (state, kura, native_chain) = if native {
                let mut prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(
                    crate::sumeragi::test_chain::TestChainConfig::new(world, 1),
                )
                .expect("authentic telemetry genesis");
                Arc::get_mut(&mut prepared.state)
                    .expect("exclusive prepared State")
                    .telemetry = StateTelemetry::new(metrics.clone(), true);
                let chain =
                    crate::sumeragi::test_chain::CertifiedTestChain::from_prepared(prepared)
                        .expect("execute original telemetry genesis");
                (
                    Arc::clone(chain.state()),
                    Arc::clone(chain.kura()),
                    Some(chain),
                )
            } else {
                (
                    Arc::new(State::with_telemetry(
                        world,
                        kura.clone(),
                        query_handle,
                        StateTelemetry::new(metrics.clone(), true),
                    )),
                    kura,
                    None,
                )
            };
            let (peers_tx, peers_rx) = watch::channel(<_>::default());
            let (mock_time_handle, time_source) = TimeSource::new_mock(Duration::default());
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue {
                    capacity: nonzero!(10usize),
                    capacity_per_user: nonzero!(10usize),
                    transaction_time_to_live: Duration::from_secs(100),
                    ..Default::default()
                },
                &time_source,
            ));
            let (telemetry, child) = start(
                metrics,
                state.clone(),
                kura.clone(),
                queue,
                peers_rx,
                local_peer_id.clone(),
                time_source.clone(),
                true,
            )
            .expect("test telemetry resource registration");
            let network_id = state.network_id;
            Self {
                telemetry,
                _child: child,
                mock_time_handle,
                time_source,
                kura,
                state,
                network_id,
                online_peers_tx: peers_tx,
                account_id,
                account_keypair,
                native_chain: Mutex::new(native_chain),
            }
        }
        fn accepted_transaction<I>(
            &self,
            instructions: impl IntoIterator<Item = I>,
        ) -> AcceptedTransaction<'static>
        where
            I: Into<InstructionBox>,
        {
            let (max_clock_drift, tx_limits) = {
                let params = &self.state.view().world.parameters;
                (params.sumeragi().max_clock_drift(), params.transaction())
            };
            let genesis = self.state.committed_height() == 0;
            let builder = if genesis {
                TransactionBuilder::new_genesis_with_time_source(
                    self.account_id.clone(),
                    &self.time_source,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
            } else {
                TransactionBuilder::new_with_time_source(
                    self.network_id,
                    self.account_id.clone(),
                    &self.time_source,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
            };
            let tx = builder
                .with_instructions(instructions)
                .sign(self.account_keypair.private_key());
            let crypto_cfg = self.state.crypto();
            if genesis {
                AcceptedTransaction::validate_genesis_with_now(
                    &tx,
                    max_clock_drift,
                    &self.account_id,
                    crypto_cfg.as_ref(),
                    self.time_source.get_unix_time(),
                )
                .expect("telemetry fixture uses authenticated genesis transactions");
                return AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(tx));
            }
            AcceptedTransaction::accept_with_time_source(
                tx,
                &self.network_id,
                max_clock_drift,
                tx_limits,
                crypto_cfg.as_ref(),
                &self.time_source,
            )
            .unwrap()
        }
        fn build_block(
            &self,
            transactions: Vec<AcceptedTransaction<'static>>,
        ) -> iroha_data_model::block::SignedBlock {
            self.native_chain
                .lock()
                .expect("native chain mutex")
                .as_ref()
                .expect("native fixture")
                .proposal(
                    None,
                    transactions
                        .into_iter()
                        .map(|transaction| match transaction.into_entrypoint() {
                            iroha_data_model::transaction::TransactionEntrypoint::External(
                                signed,
                            ) => signed,
                            _ => panic!("telemetry fixture authors an external transaction"),
                        })
                        .collect(),
                )
        }
        fn create_block(&self) -> iroha_data_model::block::SignedBlock {
            // The mocked clock may stay fixed across commits. Each genuine successor
            // must still carry a distinct signed transaction rather than replay its parent.
            let height = self
                .state
                .committed_height()
                .checked_add(1)
                .expect("original telemetry fixture successor height");
            let tx = self.accepted_transaction([Log::new(
                Level::DEBUG,
                format!("meow at original height {height}"),
            )]);
            self.build_block(vec![tx])
        }
        fn commit_block(
            &self,
            block: iroha_data_model::block::SignedBlock,
        ) -> crate::sumeragi::certified_chain::CommittedBlock {
            self.native_chain
                .lock()
                .expect("native chain mutex")
                .as_mut()
                .expect("native fixture")
                .commit_proposal(
                    block,
                    crate::sumeragi::test_chain::Signers::Quorum,
                    iroha_sumeragi::types::ControlWitness::default(),
                )
        }
        async fn report_commit_block(&self, block_header: &BlockHeader) {
            let handle = self.telemetry.clone();
            let header = *block_header;
            spawn_blocking(move || handle.report_block_commit_blocking(&header))
                .await
                .unwrap();
        }
        async fn force_sync(&self) {
            let _ = self.telemetry.metrics_fresh().await;
        }
    }
    fn random_peer(addr: SocketAddr) -> Peer {
        Peer::new(addr, checked_keypair().public_key().clone())
    }
    #[tokio::test]
    async fn initial_metrics() {
        let sut = SystemUnderTest::new();
        let metrics = sut.telemetry.metrics();
        assert_eq!(metrics.block_height.get(), 0);
        assert_eq!(metrics.last_commit_time_ms.get(), 0);
        assert_eq!(metrics.last_block_committed_at_ms.get(), 0);
        assert_eq!(metrics.last_non_empty_block_committed_at_ms.get(), 0);
        assert_eq!(metrics.domains.get(), 0);
        assert_eq!(metrics.connected_peers.get(), 0);
    }
    #[tokio::test]
    async fn uptime_since_genesis_reads_the_genesis_body_once() {
        let sut = SystemUnderTest::new_native();
        let genesis = NonZeroUsize::MIN;
        let genesis_time = sut
            .kura
            .get_block(genesis, &sut.state.ivm_execution_budget())
            .expect("funded genesis read")
            .expect("committed genesis")
            .header()
            .creation_time();
        sut.mock_time_handle
            .set(genesis_time + Duration::from_millis(1_500));
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        assert_eq!(metrics.uptime_since_genesis_ms.get(), 1_500);
        // A later sync could not read the genesis body: the resident copy is
        // dropped and the history read pool is fully occupied.
        sut.kura
            .forget_cached_block_for_testing(genesis)
            .expect("drop the resident genesis body");
        let pool = sut.state.ivm_execution_budget();
        let _occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .expect("occupy the history read pool");
        sut.mock_time_handle.advance(Duration::from_millis(500));
        sut.force_sync().await;
        assert_eq!(
            metrics.uptime_since_genesis_ms.get(),
            2_000,
            "uptime reuses the cached genesis creation time"
        );
    }
    #[test]
    fn domain_account_count_reads_the_account_scope_index() {
        use iroha_data_model::{
            account::rekey::{AccountAlias, AccountAliasDomain},
            domain::Domain,
        };
        let wonderland = DomainId::try_new("wonderland", "universal").expect("domain id");
        let garden = DomainId::try_new("garden", "universal").expect("domain id");
        let (aliased, _) = gen_account_in("wonderland");
        let (unaliased, _) = gen_account_in("wonderland");
        let alias = AccountAlias::new(
            "alice".parse().expect("label"),
            Some(AccountAliasDomain::new(
                "wonderland".parse().expect("domain name"),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let world = World::with(
            [
                Domain::new(wonderland.clone()).build(&aliased),
                Domain::new(garden.clone()).build(&aliased),
            ],
            [
                Account::new(aliased.clone()).build(&aliased),
                Account::new(unaliased.clone()).build(&unaliased),
            ],
            [],
        );
        {
            // Binding a domain alias indexes the account under that domain.
            let mut block = world.block();
            let mut tx = block.transaction_without_telemetry(
                iroha_config::parameters::actual::LaneConfig::default(),
                0,
            );
            tx.insert_account_alias_binding(alias, aliased.clone());
            tx.apply();
            block.commit();
        }
        let view = world.view();
        for domain in [&wonderland, &garden] {
            assert_eq!(
                domain_account_count(&view, domain),
                view.accounts_in_domain_iter(domain).count(),
                "{domain}"
            );
        }
        assert_eq!(domain_account_count(&view, &wonderland), 1);
        assert_eq!(domain_account_count(&view, &garden), 0);
    }
    #[tokio::test]
    async fn telemetry_start_rejects_a_second_resource_owner() {
        let system = SystemUnderTest::new();
        let metrics = Arc::clone(&system.telemetry.metrics);
        let events = tokio::sync::broadcast::channel(1).0;
        let queue = Arc::new(Queue::from_config(
            iroha_config::parameters::actual::Queue::default(),
            events,
        ));
        let (_peers_tx, peers_rx) = watch::channel(std::collections::HashSet::default());
        let (peer_key, _) = checked_keypair_with_algorithm(Algorithm::BlsNormal).into_parts();
        let result = start(
            metrics,
            Arc::clone(&system.state),
            Kura::blank_kura_for_testing(),
            queue,
            peers_rx,
            PeerId::new(peer_key),
            system.time_source.clone(),
            true,
        );
        assert!(matches!(
            result,
            Err(iroha_telemetry::metrics::CollectorRegistrationError::AlreadyReg)
        ));
    }

    #[tokio::test]
    async fn telemetry_disabled_skips_updates() {
        use iroha_primitives::time::TimeSource;
        use tokio::sync::watch;
        // Build minimal components
        let metrics = Arc::new(Metrics::default());
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let (local_pk, _) = checked_keypair_with_algorithm(Algorithm::BlsNormal).into_parts();
        let local_peer_id = PeerId::new(local_pk);
        let world = World::default();
        {
            let mut peers_block = world.peers.block();
            let _ = peers_block.get_mut().push(local_peer_id.clone());
            peers_block.commit();
        }
        let state = Arc::new(State::with_telemetry(
            world,
            kura.clone(),
            query,
            StateTelemetry::new(metrics.clone(), false),
        ));
        let (peers_tx, peers_rx) = watch::channel(<_>::default());
        let (_mh, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue {
                capacity: nonzero_ext::nonzero!(10usize),
                capacity_per_user: nonzero_ext::nonzero!(10usize),
                transaction_time_to_live: Duration::from_secs(100),
                ..Default::default()
            },
            &time_source,
        ));
        let (tel, _child) = start(
            metrics.clone(),
            state,
            kura,
            queue,
            peers_rx,
            local_peer_id,
            time_source,
            false, // disabled
        )
        .expect("test telemetry resource registration");
        let _ = peers_tx; // keep sender alive
        // Attempt to change metrics via Telemetry API
        tel.inc_torii_pre_auth_reject("rate");
        tel.inc_torii_active_conn("http");
        // Force a sync; actor should no-op when disabled
        let m = tel.metrics();
        assert_eq!(
            m.torii_pre_auth_reject_total
                .with_label_values(&["rate"])
                .get(),
            0
        );
        assert_eq!(
            m.torii_active_connections_total
                .with_label_values(&["http"])
                .get(),
            0
        );
        assert!(
            !m.try_to_string().unwrap().contains("iroha_kura_resource_"),
            "disabled telemetry must not fabricate an available resource source"
        );
    }
    #[test]
    fn state_commit_write_lock_metrics_recorded() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), true);
        telemetry
            .observe_state_commit_write_lock(Duration::from_millis(12), Duration::from_millis(34));
        assert_eq!(
            metrics.state_commit_write_lock_wait_ms.get_sample_count(),
            1
        );
        assert_eq!(
            metrics.state_commit_write_lock_hold_ms.get_sample_count(),
            1
        );
    }
    #[tokio::test]
    async fn ivm_cache_counters_exposed() {
        use ivm::ivm_cache::global_get;
        static CACHE_TEST_NONCE: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        // Arrange system and baseline
        let sut = SystemUnderTest::new();
        let stats0 = ivm::ivm_cache::global_stats();
        // Build unique valid code so this test observes its own miss even when
        // other tests have already warmed common HALT programs.
        let nonce = CACHE_TEST_NONCE.fetch_add(1, Ordering::Relaxed);
        let halt = ivm::encoding::wide::encode_halt().to_le_bytes();
        let decoded_ops_added = 257 + nonce;
        let mut code = Vec::new();
        for _ in 0..decoded_ops_added {
            code.extend_from_slice(&halt);
        }
        // Miss on first get, hit on second
        let _ = global_get(&code).expect("predecode ok");
        let _ = global_get(&code).expect("predecode hit");
        let stats1 = ivm::ivm_cache::global_stats();
        assert!(
            stats1.misses > stats0.misses,
            "test program should add an IVM cache miss"
        );
        assert!(
            stats1.hits > stats0.hits,
            "second lookup should add an IVM cache hit"
        );
        // Force telemetry sync
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        // Verify the counters are >= baseline + 1
        assert!(metrics.ivm_cache_misses.get() >= stats1.misses);
        assert!(metrics.ivm_cache_hits.get() >= stats1.hits);
        // Evictions may or may not have changed, but the gauge should be >= baseline
        assert!(metrics.ivm_cache_evictions.get() >= stats0.evictions);
        assert!(
            metrics.ivm_cache_decoded_streams.get() > stats0.decoded_streams,
            "expected at least one new decoded stream"
        );
        assert!(
            metrics.ivm_cache_decoded_ops_total.get()
                >= stats0.decoded_ops_total
                    + u64::try_from(decoded_ops_added).expect("op count fits"),
            "expected HALT stream decode to add its op count"
        );
        assert!(
            metrics.ivm_cache_decode_time_ns_total.get() >= stats0.decode_time_ns_total,
            "decode time counter must not regress"
        );
        assert_eq!(
            metrics.ivm_cache_decode_failures.get(),
            stats0.decode_failures,
            "decode failures should not increase on successful decode"
        );
    }
    #[test]
    fn ivm_cache_memory_metrics_preserve_snapshot_accounting() {
        let metrics = Metrics::default();
        refresh_ivm_cache_metrics(&metrics);
        let active = metrics.ivm_cache_memory_active_bytes.get();
        let retained = metrics.ivm_cache_memory_retained_bytes.get();
        let resident = metrics.ivm_cache_memory_resident_bytes.get();
        assert_eq!(resident, active.saturating_add(retained));
        assert_eq!(
            retained,
            metrics.ivm_cache_memory_shared_reclaimable_bytes.get()
                + metrics.ivm_cache_memory_shared_borrowed_bytes.get()
                + metrics.ivm_cache_memory_shared_evicted_live_bytes.get()
                + metrics.ivm_cache_memory_unclassified_retained_bytes.get()
        );
        assert!(metrics.ivm_cache_memory_peak_bytes.get() >= resident);
    }
    #[test]
    fn ivm_execution_memory_metrics_follow_original_pool_through_shrink_and_release() {
        let metrics = Metrics::default();
        let budget = iroha_allocation::AllocationBudget::new(128);
        let held = budget.try_reserve_bytes(80).expect("initial reservation");
        budget.set_limit_bytes(64);
        refresh_ivm_execution_budget_metrics(&metrics, &budget);
        assert_eq!(metrics.ivm_execution_memory_reserved_bytes.get(), 80);
        assert_eq!(metrics.ivm_execution_memory_peak_bytes.get(), 80);
        assert_eq!(metrics.ivm_execution_memory_limit_bytes.get(), 64);
        drop(held);
        refresh_ivm_execution_budget_metrics(&metrics, &budget);
        assert_eq!(metrics.ivm_execution_memory_reserved_bytes.get(), 0);
        assert_eq!(metrics.ivm_execution_memory_peak_bytes.get(), 80);
    }
    #[tokio::test]
    async fn set_online_peers() {
        let sut = SystemUnderTest::new();
        let peers: HashSet<_> = vec![
            random_peer(socket_addr!(100.100.100.100:80)),
            random_peer(socket_addr!(200.100.30.1:9001)),
        ]
        .into_iter()
        .collect();
        sut.online_peers_tx.send(peers.clone()).unwrap();
        let metrics = sut.telemetry.metrics_fresh().await;
        assert_eq!(metrics.connected_peers.get(), 2);
        assert_eq!(
            metrics
                .p2p_peer_churn_total
                .with_label_values(&["connected"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .p2p_peer_churn_total
                .with_label_values(&["disconnected"])
                .get(),
            0
        );
        // Remove one peer and ensure churn metrics capture the disconnect event.
        let mut remaining = peers.clone();
        if let Some(to_remove) = remaining.iter().next().cloned() {
            remaining.remove(&to_remove);
        }
        sut.online_peers_tx.send(remaining.clone()).unwrap();
        let metrics = sut.telemetry.metrics_fresh().await;
        assert_eq!(metrics.connected_peers.get(), remaining.len() as u64);
        assert_eq!(
            metrics
                .p2p_peer_churn_total
                .with_label_values(&["connected"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .p2p_peer_churn_total
                .with_label_values(&["disconnected"])
                .get(),
            1
        );
        // Finally, drop all peers to observe another disconnect increment.
        sut.online_peers_tx.send(HashSet::new()).unwrap();
        let metrics = sut.telemetry.metrics_fresh().await;
        assert_eq!(metrics.connected_peers.get(), 0);
        assert_eq!(
            metrics
                .p2p_peer_churn_total
                .with_label_values(&["disconnected"])
                .get(),
            2
        );
    }
    #[tokio::test]
    async fn connected_peers_zero_when_local_peer_missing_from_world() {
        use tokio::sync::watch;
        let metrics = Arc::new(Metrics::default());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = World::default();
        let state = Arc::new(State::with_telemetry(
            world,
            kura.clone(),
            query_handle,
            StateTelemetry::new(metrics.clone(), true),
        ));
        let (peers_tx, peers_rx) = watch::channel(<_>::default());
        let (_mh, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue {
                capacity: nonzero_ext::nonzero!(10usize),
                capacity_per_user: nonzero_ext::nonzero!(10usize),
                transaction_time_to_live: Duration::from_secs(100),
                ..Default::default()
            },
            &time_source,
        ));
        let (local_pk, _) = checked_keypair_with_algorithm(Algorithm::BlsNormal).into_parts();
        let local_peer_id = PeerId::new(local_pk);
        let (telemetry, _child) = start(
            metrics,
            state,
            kura,
            queue,
            peers_rx,
            local_peer_id,
            time_source,
            true,
        )
        .expect("test telemetry resource registration");
        let peers: HashSet<_> = vec![
            random_peer(socket_addr!(100.100.100.100:80)),
            random_peer(socket_addr!(200.100.30.1:9001)),
        ]
        .into_iter()
        .collect();
        peers_tx.send(peers).unwrap();
        let metrics = telemetry.metrics();
        assert_eq!(metrics.connected_peers.get(), 0);
    }
    #[tokio::test]
    async fn metrics_sync_excludes_unpublished_kura_blocks_and_catches_up_once() {
        for already_applied in [false, true] {
            for report_before_publication in [false, true] {
                let sut = SystemUnderTest::new_native();
                if already_applied {
                    sut.commit_block(sut.create_block());
                }
                sut.force_sync().await;
                let metrics = &sut.telemetry.metrics;
                let old_height = metrics.block_height.get();
                let old_non_empty = metrics.block_height_non_empty.get();
                let old_accepted = metrics.txs.with_label_values(&["accepted"]).get();
                let old_rejected = metrics.txs.with_label_values(&["rejected"]).get();
                let old_total = metrics.txs.with_label_values(&["total"]).get();
                let old_observed = metrics.last_block_committed_at_ms.get();
                assert_eq!(old_height, 1 + u64::from(already_applied));

                let candidate = sut.create_block();
                {
                    let parent = sut
                        .state
                        .view()
                        .latest_block()
                        .expect("completed original telemetry parent read")
                        .expect("original telemetry committed parent");
                    for transaction in candidate.external_transactions() {
                        assert!(
                            parent
                                .external_transactions()
                                .all(|previous| previous.hash() != transaction.hash()),
                            "each unpublished successor carries a new signed transaction even at the unchanged mock time"
                        );
                    }
                }
                // Keep the genuine chain owner across the async observations without
                // carrying its fixture-slot mutex into the runtime.
                let mut chain = {
                    let mut original = sut.native_chain.lock().expect("native chain mutex");
                    original.take().expect("native fixture")
                };
                let mut pending = chain
                    .begin_proposal(candidate, iroha_sumeragi::types::ControlWitness::default())
                    .expect("original unpublished execution");
                assert!(pending.inspect_prepared(|_| ()).is_err());
                // Durability requires the genuine certificate, while State and
                // its classified telemetry remain at the original publication.
                pending
                    .prepare(crate::sumeragi::test_chain::Signers::Quorum)
                    .expect("certify the original execution before storing its body");
                assert!(pending.inspect_prepared(|_| ()).is_err());
                pending
                    .prepare_publication_for_inspection(
                        crate::sumeragi::test_chain::Signers::Quorum,
                    )
                    .expect("durable original metadata defers at the actual history writer");
                let certified = pending
                    .inspect_prepared(|view| view.block.shared().clone())
                    .expect("retain the exact unpublished certified carrier");
                let external_count = certified.external_transactions().len() as u64;
                sut.kura
                    .store_block(certified.clone())
                    .expect("unpublished exact Kura body");
                sut.mock_time_handle.advance(Duration::from_millis(100));
                if report_before_publication {
                    sut.report_commit_block(&certified.header()).await;
                }
                sut.force_sync().await;
                assert_eq!(sut.state.committed_height() as u64, old_height);
                assert_eq!(metrics.block_height.get(), old_height);
                assert_eq!(metrics.block_height_non_empty.get(), old_non_empty);
                assert_eq!(
                    metrics.txs.with_label_values(&["accepted"]).get(),
                    old_accepted
                );
                assert_eq!(
                    metrics.txs.with_label_values(&["rejected"]).get(),
                    old_rejected
                );
                assert_eq!(metrics.txs.with_label_values(&["total"]).get(), old_total);
                assert_eq!(metrics.last_block_committed_at_ms.get(), old_observed);
                #[cfg(feature = "telemetry")]
                {
                    let (status, height) = sut
                        .telemetry
                        .status_snapshot(&iroha_torii_shared::status::BuildStatus::default())
                        .await
                        .expect("unpublished Kura body cannot extend the owned target")
                        .into_parts();
                    assert_eq!(height, old_height);
                    assert_eq!(status.blocks, old_height);
                    assert_eq!(status.blocks_non_empty, old_non_empty);
                }

                pending
                    .publish(crate::sumeragi::test_chain::Signers::Quorum)
                    .expect("publish original execution with its native certificate");
                drop(pending);
                {
                    let mut original = sut.native_chain.lock().expect("native chain mutex");
                    assert!(
                        original.is_none(),
                        "the original fixture chain has one owner"
                    );
                    *original = Some(chain);
                }
                sut.force_sync().await;
                assert_eq!(metrics.block_height.get(), old_height + 1);
                assert_eq!(metrics.block_height_non_empty.get(), old_non_empty + 1);
                assert_eq!(
                    metrics.txs.with_label_values(&["total"]).get(),
                    old_total + external_count
                );
                let accepted = metrics.txs.with_label_values(&["accepted"]).get();
                let rejected = metrics.txs.with_label_values(&["rejected"]).get();
                assert_eq!(accepted + rejected, old_total + external_count);
                let observed = metrics.last_block_committed_at_ms.get();
                sut.force_sync().await;
                assert_eq!(metrics.block_height.get(), old_height + 1);
                assert_eq!(metrics.block_height_non_empty.get(), old_non_empty + 1);
                assert_eq!(metrics.txs.with_label_values(&["accepted"]).get(), accepted);
                assert_eq!(metrics.txs.with_label_values(&["rejected"]).get(), rejected);
                assert_eq!(metrics.last_block_committed_at_ms.get(), observed);
            }
        }
    }
    #[tokio::test]
    async fn commit_blocks() {
        // this indicates time padding applied in the block builder
        let sut = SystemUnderTest::new_native();
        // Commit the first ordinary block after original genesis.
        let block = sut.create_block();
        sut.mock_time_handle.advance(Duration::from_millis(100));
        let block = sut.commit_block(block);
        sut.report_commit_block(&block.block().header()).await;
        let metrics = sut.telemetry.metrics_fresh().await;
        assert_eq!(metrics.block_height.get(), 2);
        assert_eq!(metrics.block_height_non_empty.get(), 2);
        assert_eq!(
            metrics.last_commit_time_ms.get(),
            u64::try_from(
                sut.time_source
                    .get_unix_time()
                    .saturating_sub(block.block().header().creation_time())
                    .as_millis()
            )
            .unwrap()
        ); // zero for genesis
        assert_eq!(metrics.last_block_committed_at_ms.get(), 100);
        assert_eq!(metrics.last_non_empty_block_committed_at_ms.get(), 100);
        let first_accepted = metrics.txs.with_label_values(&["accepted"]).get();
        let first_rejected = metrics.txs.with_label_values(&["rejected"]).get();
        let total_first = metrics.txs.with_label_values(&["total"]).get();
        assert_eq!(first_accepted + first_rejected, total_first);
        assert!(total_first >= 1);
        // second block
        let block = sut.create_block();
        sut.mock_time_handle.advance(Duration::from_millis(150));
        let block = sut.commit_block(block);
        sut.report_commit_block(&block.block().header()).await;
        let metrics = sut.telemetry.metrics_fresh().await;
        assert_eq!(metrics.block_height.get(), 3);
        assert_eq!(metrics.block_height_non_empty.get(), 3);
        assert_eq!(
            metrics.last_commit_time_ms.get(),
            u64::try_from(
                sut.time_source
                    .get_unix_time()
                    .saturating_sub(block.block().header().creation_time())
                    .as_millis()
            )
            .unwrap()
        );
        assert_eq!(metrics.last_block_committed_at_ms.get(), 250);
        assert_eq!(metrics.last_non_empty_block_committed_at_ms.get(), 250);
        let accepted = metrics.txs.with_label_values(&["accepted"]).get();
        let rejected = metrics.txs.with_label_values(&["rejected"]).get();
        let total = metrics.txs.with_label_values(&["total"]).get();
        assert_eq!(accepted + rejected, total);
        assert!(accepted >= 1, "at least one tx should be accepted");
        assert!(
            total > total_first,
            "tx counters should increase after second block"
        );
        // third block - committed, but not reported yet
        let block = sut.create_block();
        sut.mock_time_handle.advance(Duration::from_millis(170));
        let block = sut.commit_block(block);
        sut.report_commit_block(&block.block().header()).await;
        let metrics = sut.telemetry.metrics_fresh().await;
        assert_eq!(metrics.block_height.get(), 4);
        assert_eq!(metrics.block_height_non_empty.get(), 4);
        assert_eq!(
            metrics.last_commit_time_ms.get(),
            u64::try_from(
                sut.time_source
                    .get_unix_time()
                    .saturating_sub(block.block().header().creation_time())
                    .as_millis()
            )
            .unwrap()
        );
        assert_eq!(metrics.last_block_committed_at_ms.get(), 420);
        assert_eq!(metrics.last_non_empty_block_committed_at_ms.get(), 420);
    }
    #[tokio::test]
    async fn tx_counters_ignore_time_trigger_failures() {
        let sut = SystemUnderTest::new_native();
        let trigger_id: TriggerId = "telemetry_time_trigger".parse().expect("trigger id");
        let missing_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("ghost", "universal").unwrap(),
                "ghost".parse().unwrap(),
            );
        let missing_asset = AssetId::new(missing_def, sut.account_id.clone());
        let action = Action::new(
            [Transfer::asset_quantity(
                missing_asset,
                1_u32,
                sut.account_id.clone(),
            )],
            Repeats::Indefinitely,
            sut.account_id.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        )
        .expect("trigger action fixture satisfies validation invariants");
        let trigger = Trigger::new(trigger_id, action);
        let register_tx = sut.accepted_transaction([Register::trigger(trigger)]);
        let register_block = sut.build_block(vec![register_tx]);
        sut.mock_time_handle.advance(Duration::from_millis(100));
        let register_block = sut.commit_block(register_block);
        sut.report_commit_block(&register_block.block().header())
            .await;
        let metrics = sut.telemetry.metrics_fresh().await;
        let base_accepted = metrics.txs.with_label_values(&["accepted"]).get();
        let base_rejected = metrics.txs.with_label_values(&["rejected"]).get();
        let base_total = metrics.txs.with_label_values(&["total"]).get();
        let tx = sut.accepted_transaction([Log::new(Level::INFO, "ok".to_string())]);
        let block = sut.build_block(vec![tx]);
        sut.mock_time_handle.advance(Duration::from_millis(150));
        let block = sut.commit_block(block);
        let mut errors = block.block().failed_outputs();
        let (idx, _) = errors
            .next()
            .expect("time trigger should fail in telemetry test");
        assert_eq!(idx, 1, "time trigger failure should follow external tx");
        assert!(errors.next().is_none(), "only time trigger should fail");
        sut.report_commit_block(&block.block().header()).await;
        let metrics = sut.telemetry.metrics_fresh().await;
        let accepted = metrics.txs.with_label_values(&["accepted"]).get();
        let rejected = metrics.txs.with_label_values(&["rejected"]).get();
        let total = metrics.txs.with_label_values(&["total"]).get();
        assert_eq!(
            rejected, base_rejected,
            "time trigger failures should not bump rejected tx count"
        );
        assert_eq!(
            accepted,
            base_accepted + 1,
            "external tx should be accepted"
        );
        assert_eq!(total, accepted + rejected);
        assert!(total > base_total);
    }
    #[tokio::test]
    async fn p2p_queue_drop_labels_reflect_counters() {
        let sut = SystemUnderTest::new();
        // Baseline
        let metrics = sut.telemetry.metrics();
        let drops = &metrics.p2p_queue_dropped_total;
        let baseline_high_post = drops.with_label_values(&["High", "Post"]).get();
        let baseline_low_post = drops.with_label_values(&["Low", "Post"]).get();
        let baseline_high_broadcast = drops.with_label_values(&["High", "Broadcast"]).get();
        let baseline_low_broadcast = drops.with_label_values(&["Low", "Broadcast"]).get();
        // Bump P2P counters directly
        iroha_p2p::network::inc_queue_drop_for_test(true, false, 3); // High/Post +3
        iroha_p2p::network::inc_queue_drop_for_test(false, false, 2); // Low/Post +2
        iroha_p2p::network::inc_queue_drop_for_test(true, true, 5); // High/Broadcast +5
        iroha_p2p::network::inc_queue_drop_for_test(false, true, 7); // Low/Broadcast +7
        // Force telemetry to sync metrics from p2p counters
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        let drops = &metrics.p2p_queue_dropped_total;
        assert!(drops.with_label_values(&["High", "Post"]).get() >= baseline_high_post + 3);
        assert!(drops.with_label_values(&["Low", "Post"]).get() >= baseline_low_post + 2);
        assert!(
            drops.with_label_values(&["High", "Broadcast"]).get() >= baseline_high_broadcast + 5
        );
        assert!(drops.with_label_values(&["Low", "Broadcast"]).get() >= baseline_low_broadcast + 7);
    }
    #[tokio::test]
    async fn p2p_queue_depth_metric_tracks_updates() {
        let sut = SystemUnderTest::new();
        iroha_p2p::network::set_network_safety_queue_depth_for_test(3);
        iroha_p2p::network::set_network_progress_queue_depth_for_test(5);
        iroha_p2p::network::set_network_queue_depth_for_test(true, 12);
        iroha_p2p::network::set_network_queue_depth_for_test(false, 7);
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        let depth = &metrics.p2p_queue_depth;
        assert_eq!(depth.with_label_values(&["Safety"]).get(), 3);
        assert_eq!(depth.with_label_values(&["Progress"]).get(), 5);
        assert_eq!(depth.with_label_values(&["High"]).get(), 12);
        assert_eq!(depth.with_label_values(&["Low"]).get(), 7);
    }
    #[tokio::test]
    async fn p2p_subscriber_unrouted_metric_tracks_counter() {
        use iroha_p2p::network::message::Topic;
        let sut = SystemUnderTest::new();
        let metrics = sut.telemetry.metrics();
        let baseline = metrics.p2p_subscriber_unrouted_total.get();
        iroha_p2p::network::inc_subscriber_unrouted_for_test(Topic::Consensus, 4);
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        assert!(
            metrics.p2p_subscriber_unrouted_total.get() >= baseline + 4,
            "subscriber unrouted metric should track the network counter"
        );
    }
    #[tokio::test]
    async fn p2p_subscriber_queue_full_metric_tracks_counter() {
        use iroha_p2p::network::message::Topic;
        let sut = SystemUnderTest::new();
        let metrics = sut.telemetry.metrics();
        let baseline = metrics.p2p_subscriber_queue_full_total.get();
        iroha_p2p::network::inc_subscriber_queue_full_for_test(Topic::Control, 2);
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        assert!(
            metrics.p2p_subscriber_queue_full_total.get() >= baseline + 2,
            "subscriber queue-full metric should track the network counter"
        );
    }
    #[tokio::test]
    async fn p2p_subscriber_queue_full_by_topic_tracks_counters() {
        use iroha_p2p::network::{inc_subscriber_queue_full_for_test as bump, message::Topic};
        let sut = SystemUnderTest::new();
        let metrics = sut.telemetry.metrics();
        let by = &metrics.p2p_subscriber_queue_full_by_topic_total;
        let mut baseline = BTreeMap::new();
        for topic in [
            "ConsensusSafety",
            "Consensus",
            "ConsensusChunk",
            "Control",
            "BlockSync",
            "TxGossip",
            "PeerGossip",
            "Health",
            "Other",
        ] {
            baseline.insert(topic.to_string(), by.with_label_values(&[topic]).get());
        }
        for &topic in &[
            Topic::ConsensusSafety,
            Topic::Consensus,
            Topic::ConsensusChunk,
            Topic::Control,
            Topic::BlockSync,
            Topic::TxGossip,
            Topic::PeerGossip,
            Topic::Health,
            Topic::Other,
        ] {
            bump(topic, 1);
        }
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        let by = &metrics.p2p_subscriber_queue_full_by_topic_total;
        for topic in [
            "ConsensusSafety",
            "Consensus",
            "ConsensusChunk",
            "Control",
            "BlockSync",
            "TxGossip",
            "PeerGossip",
            "Health",
            "Other",
        ] {
            let after = by.with_label_values(&[topic]).get();
            let before = baseline.get(topic).copied().unwrap_or(0);
            assert!(
                after > before,
                "expected {topic} queue-full metric to increase"
            );
        }
    }
    #[tokio::test]
    async fn p2p_subscriber_unrouted_by_topic_tracks_counters() {
        use iroha_p2p::network::{inc_subscriber_unrouted_for_test as bump, message::Topic};
        let sut = SystemUnderTest::new();
        let metrics = sut.telemetry.metrics();
        let by = &metrics.p2p_subscriber_unrouted_by_topic_total;
        let mut baseline = BTreeMap::new();
        for topic in [
            "ConsensusSafety",
            "Consensus",
            "ConsensusChunk",
            "Control",
            "BlockSync",
            "TxGossip",
            "PeerGossip",
            "Health",
            "Other",
        ] {
            baseline.insert(topic.to_string(), by.with_label_values(&[topic]).get());
        }
        for &topic in &[
            Topic::ConsensusSafety,
            Topic::Consensus,
            Topic::ConsensusChunk,
            Topic::Control,
            Topic::BlockSync,
            Topic::TxGossip,
            Topic::PeerGossip,
            Topic::Health,
            Topic::Other,
        ] {
            bump(topic, 1);
        }
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        let by = &metrics.p2p_subscriber_unrouted_by_topic_total;
        for topic in [
            "ConsensusSafety",
            "Consensus",
            "ConsensusChunk",
            "Control",
            "BlockSync",
            "TxGossip",
            "PeerGossip",
            "Health",
            "Other",
        ] {
            let after = by.with_label_values(&[topic]).get();
            let before = baseline.get(topic).copied().unwrap_or(0);
            assert!(
                after > before,
                "expected {topic} unrouted metric to increase"
            );
        }
    }
    #[tokio::test]
    async fn p2p_overflow_label_matrix_reflects_counters() {
        use iroha_p2p::network::{inc_post_overflow_for_test as bump, message::Topic};
        let sut = SystemUnderTest::new();
        // Baseline read
        let metrics = sut.telemetry.metrics();
        let by = &metrics.p2p_post_overflow_by_topic;
        let mut baseline = BTreeMap::new();
        for prio in ["High", "Low"] {
            for topic in [
                "ConsensusSafety",
                "Consensus",
                "Control",
                "BlockSync",
                "TxGossip",
                "PeerGossip",
                "Health",
                "Other",
            ] {
                let v = by.with_label_values(&[prio, topic]).get();
                baseline.insert((prio.to_string(), topic.to_string()), v);
            }
        }
        // Bump P2P network counters for each pair by +1
        let topics = [
            Topic::ConsensusSafety,
            Topic::Consensus,
            Topic::Control,
            Topic::BlockSync,
            Topic::TxGossip,
            Topic::PeerGossip,
            Topic::Health,
            Topic::Other,
        ];
        for &t in &topics {
            bump(true, t, 1);
            bump(false, t, 1);
        }
        // Force sync and assert increments >= 1 for each label pair
        sut.force_sync().await;
        let metrics = sut.telemetry.metrics();
        let by = &metrics.p2p_post_overflow_by_topic;
        for prio in ["High", "Low"] {
            for topic in [
                "ConsensusSafety",
                "Consensus",
                "Control",
                "BlockSync",
                "TxGossip",
                "PeerGossip",
                "Health",
                "Other",
            ] {
                let after = by.with_label_values(&[prio, topic]).get();
                let before = baseline
                    .get(&(prio.to_string(), topic.to_string()))
                    .copied()
                    .unwrap_or(0);
                assert!(
                    after > before,
                    "expected {prio}:{topic} to increase by at least 1"
                );
            }
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn torii_pre_auth_metrics_track_usage() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(Arc::clone(&metrics), true);
        telemetry.inc_torii_pre_auth_reject("rate");
        assert_eq!(
            metrics
                .torii_pre_auth_reject_total
                .with_label_values(&["rate"])
                .get(),
            1
        );
        telemetry.inc_torii_operator_auth("gate", "allowed", "session");
        assert_eq!(
            metrics
                .torii_operator_auth_total
                .with_label_values(&["gate", "allowed", "session"])
                .get(),
            1
        );
        telemetry.inc_torii_operator_auth_lockout("gate", "invalid_session");
        assert_eq!(
            metrics
                .torii_operator_auth_lockout_total
                .with_label_values(&["gate", "invalid_session"])
                .get(),
            1
        );
        telemetry.inc_torii_active_conn("http");
        assert_eq!(
            metrics
                .torii_active_connections_total
                .with_label_values(&["http"])
                .get(),
            1
        );
        telemetry.dec_torii_active_conn("http");
        assert_eq!(
            metrics
                .torii_active_connections_total
                .with_label_values(&["http"])
                .get(),
            0
        );
        telemetry.inc_torii_signature_limit_reject(5, 3, "single");
        assert_eq!(metrics.torii_signature_limit_total.get(), 1);
        assert_eq!(
            metrics
                .torii_signature_limit_by_authority_total
                .with_label_values(&["single"])
                .get(),
            1
        );
        assert_eq!(metrics.torii_signature_limit_last_count.get(), 5);
        assert_eq!(metrics.torii_signature_limit_max.get(), 3);
        telemetry.inc_torii_nts_unhealthy_reject();
        assert_eq!(metrics.torii_nts_unhealthy_reject_total.get(), 1);
        telemetry.inc_torii_multisig_direct_sign_reject();
        assert_eq!(metrics.torii_multisig_direct_sign_reject_total.get(), 1);
        telemetry.inc_torii_attachment_reject("type");
        assert_eq!(
            metrics
                .torii_attachment_reject_total
                .with_label_values(&["type"])
                .get(),
            1
        );
        telemetry.observe_torii_attachment_sanitize_ms(12);
        assert_eq!(
            metrics
                .torii_attachment_sanitize_ms
                .with_label_values::<&str>(&[])
                .get_sample_count(),
            1
        );
        telemetry.inc_sns_registrar_status("ok", "sora");
        assert_eq!(
            metrics
                .sns_registrar_status_total
                .with_label_values(&["ok", "sora"])
                .get(),
            1
        );
        telemetry.inc_torii_api_token_hit("v1/status", "present");
        assert_eq!(
            metrics
                .torii_api_token_hits_total
                .with_label_values(&["v1/status", "present"])
                .get(),
            1
        );
        let telemetry = Telemetry::new(Arc::clone(&metrics), false);
        telemetry.inc_torii_api_token_hit("v1/status", "present");
        assert_eq!(
            metrics
                .torii_api_token_hits_total
                .with_label_values(&["v1/status", "present"])
                .get(),
            1,
            "disabled telemetry must not record additional API-token hits"
        );
        telemetry.inc_torii_signature_limit_reject(10, 7, "single");
        assert_eq!(
            metrics.torii_signature_limit_total.get(),
            1,
            "disabled telemetry must not record additional signature-limit increments"
        );
        assert_eq!(
            metrics
                .torii_signature_limit_by_authority_total
                .with_label_values(&["single"])
                .get(),
            1,
            "disabled telemetry must not record labeled signature-limit increments"
        );
        assert_eq!(
            metrics.torii_signature_limit_last_count.get(),
            5,
            "disabled telemetry must not update the last-count gauge"
        );
        telemetry.inc_torii_nts_unhealthy_reject();
        assert_eq!(
            metrics.torii_nts_unhealthy_reject_total.get(),
            1,
            "disabled telemetry must not record additional NTS rejects"
        );
        telemetry.inc_torii_multisig_direct_sign_reject();
        assert_eq!(
            metrics.torii_multisig_direct_sign_reject_total.get(),
            1,
            "disabled telemetry must not record additional direct-sign rejects"
        );
        telemetry.inc_torii_operator_auth("gate", "denied", "missing_session");
        assert_eq!(
            metrics
                .torii_operator_auth_total
                .with_label_values(&["gate", "allowed", "session"])
                .get(),
            1,
            "disabled telemetry must not record operator auth events"
        );
        telemetry.inc_torii_operator_auth_lockout("gate", "missing_session");
        assert_eq!(
            metrics
                .torii_operator_auth_lockout_total
                .with_label_values(&["gate", "invalid_session"])
                .get(),
            1,
            "disabled telemetry must not record operator auth lockouts"
        );
        telemetry.inc_torii_attachment_reject("type");
        assert_eq!(
            metrics
                .torii_attachment_reject_total
                .with_label_values(&["type"])
                .get(),
            1,
            "disabled telemetry must not record attachment rejects"
        );
        telemetry.observe_torii_attachment_sanitize_ms(7);
        assert_eq!(
            metrics
                .torii_attachment_sanitize_ms
                .with_label_values::<&str>(&[])
                .get_sample_count(),
            1,
            "disabled telemetry must not record attachment sanitize latency"
        );
        telemetry.inc_sns_registrar_status("ok", "sora");
        assert_eq!(
            metrics
                .sns_registrar_status_total
                .with_label_values(&["ok", "sora"])
                .get(),
            2,
            "SNS registrar status must continue to track handler outcomes even when periodic telemetry is disabled"
        );
    }
    include!("telemetry/kaigi_and_multisig_metric_tests.rs");
    #[test]
    fn sm_syscall_counters_respect_enablement() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), true);
        telemetry.note_sm_syscall_success("hash", "-");
        assert_eq!(
            metrics
                .sm_syscall_total
                .with_label_values(&["hash", "-"])
                .get(),
            1
        );
        telemetry.note_sm_syscall_failure("hash", "-", "disabled");
        assert_eq!(
            metrics
                .sm_syscall_failures_total
                .with_label_values(&["hash", "-", "disabled"])
                .get(),
            1
        );
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), false);
        telemetry.note_sm_syscall_success("hash", "-");
        assert_eq!(
            metrics
                .sm_syscall_total
                .with_label_values(&["hash", "-"])
                .get(),
            1,
            "disabled telemetry must not record additional successes"
        );
    }
    #[test]
    fn subscription_billing_counters_respect_enablement() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), true);
        telemetry.record_subscription_billing_attempt("usage");
        telemetry.record_subscription_billing_outcome("usage", "paid");
        assert_eq!(
            metrics
                .subscription_billing_attempts_total
                .with_label_values(&["usage"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .subscription_billing_outcomes_total
                .with_label_values(&["usage", "paid"])
                .get(),
            1
        );
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), false);
        telemetry.record_subscription_billing_attempt("fixed");
        telemetry.record_subscription_billing_outcome("fixed", "failed");
        assert_eq!(
            metrics
                .subscription_billing_attempts_total
                .with_label_values(&["fixed"])
                .get(),
            0,
            "disabled telemetry must not record attempts"
        );
        assert_eq!(
            metrics
                .subscription_billing_outcomes_total
                .with_label_values(&["fixed", "failed"])
                .get(),
            0,
            "disabled telemetry must not record outcomes"
        );
    }
    #[test]
    fn settlement_event_counters_track_outcomes() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), true);
        telemetry.note_settlement_success("dvp");
        assert_eq!(
            metrics
                .settlement_events_total
                .with_label_values(&["dvp", "success", "-"])
                .get(),
            1
        );
        telemetry.note_settlement_failure("pvp", "insufficient_funds");
        assert_eq!(
            metrics
                .settlement_events_total
                .with_label_values(&["pvp", "failure", "insufficient_funds"])
                .get(),
            1
        );
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), false);
        telemetry.note_settlement_success("dvp");
        telemetry.note_settlement_failure("pvp", "insufficient_funds");
        assert_eq!(
            metrics
                .settlement_events_total
                .with_label_values(&["dvp", "success", "-"])
                .get(),
            1,
            "disabled telemetry must not record additional successes"
        );
        assert_eq!(
            metrics
                .settlement_events_total
                .with_label_values(&["pvp", "failure", "insufficient_funds"])
                .get(),
            1,
            "disabled telemetry must not record additional failures"
        );
    }
    #[test]
    fn settlement_finality_updates_metrics_and_status() {
        crate::status::settlement_status_reset_for_tests();
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(Arc::clone(&metrics), true);
        let dvp_id = SettlementId::new(
            iroha_test_samples::ALICE_ID.clone(),
            "trade-1".parse().expect("settlement reference"),
        );
        let dvp_plan = SettlementPlan::new(
            SettlementExecutionOrder::DeliveryThenPayment,
            SettlementAtomicity::AllOrNothing,
        );
        telemetry.record_dvp_finality(
            &dvp_id,
            dvp_plan,
            SettlementOutcomeKind::Success,
            None,
            true,
            false,
        );
        assert_eq!(
            metrics
                .settlement_finality_events_total
                .with_label_values(&["dvp", "success", "delivery_only"])
                .get(),
            1
        );
        let pvp_id = SettlementId::new(
            iroha_test_samples::ALICE_ID.clone(),
            "fx-1".parse().expect("settlement reference"),
        );
        let pvp_plan = SettlementPlan::new(
            SettlementExecutionOrder::DeliveryThenPayment,
            SettlementAtomicity::AllOrNothing,
        );
        telemetry.record_pvp_finality(
            &pvp_id,
            pvp_plan,
            SettlementOutcomeKind::Failure,
            Some("insufficient_funds"),
            true,
            false,
            Some(42),
        );
        assert_eq!(
            metrics
                .settlement_finality_events_total
                .with_label_values(&["pvp", "failure", "primary_only"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .settlement_fx_window_ms
                .with_label_values(&["pvp", "delivery_then_payment", "all_or_nothing"])
                .get_sample_count(),
            1
        );
        let snapshot = crate::status::settlement_snapshot();
        assert_eq!(snapshot.dvp.success_total, 1);
        let dvp_event = snapshot.dvp.last_event.expect("dvp last event");
        assert_eq!(dvp_event.final_state_label, "delivery_only");
        assert_eq!(dvp_event.outcome, SettlementOutcomeKind::Success);
        assert!(dvp_event.delivery_committed);
        assert!(!dvp_event.payment_committed);
        assert_eq!(snapshot.pvp.failure_total, 1);
        let pvp_event = snapshot.pvp.last_event.expect("pvp last event");
        assert_eq!(pvp_event.final_state_label, "primary_only");
        assert_eq!(pvp_event.outcome, SettlementOutcomeKind::Failure);
        assert!(pvp_event.primary_committed);
        assert!(!pvp_event.counter_committed);
        assert_eq!(pvp_event.fx_window_ms, Some(42));
        assert_eq!(
            pvp_event.failure_reason.as_deref(),
            Some("insufficient_funds")
        );
    }
    #[test]
    #[cfg(feature = "telemetry")]
    fn public_lane_metrics_track_validator_and_amounts() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = StateTelemetry::new(metrics.clone(), true);
        let lane = LaneId::new(5);
        telemetry.record_public_lane_validator_status(
            lane,
            None,
            &PublicLaneValidatorStatus::PendingActivation(0),
        );
        assert_eq!(
            metrics
                .nexus_public_lane_validator_total
                .with_label_values(&["5", "pending"])
                .get(),
            1
        );
        telemetry.record_public_lane_validator_status(
            lane,
            Some(&PublicLaneValidatorStatus::PendingActivation(0)),
            &PublicLaneValidatorStatus::Active,
        );
        assert_eq!(
            metrics
                .nexus_public_lane_validator_total
                .with_label_values(&["5", "pending"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .nexus_public_lane_validator_total
                .with_label_values(&["5", "active"])
                .get(),
            1
        );
        telemetry.increase_public_lane_bonded(lane, &Quantity::from(1_000_u32));
        telemetry.decrease_public_lane_bonded(lane, &Quantity::from(250_u32));
        let bonded = metrics
            .nexus_public_lane_stake_bonded
            .with_label_values(&["5"])
            .get();
        assert!(
            (bonded - 750.0).abs() < f64::EPSILON,
            "bonded stake gauge should track deltas"
        );
        telemetry.increase_public_lane_pending_unbond(lane, &Quantity::from(400_u32));
        telemetry.decrease_public_lane_pending_unbond(lane, &Quantity::from(150_u32));
        let pending = metrics
            .nexus_public_lane_unbond_pending
            .with_label_values(&["5"])
            .get();
        assert!(
            (pending - 250.0).abs() < f64::EPSILON,
            "pending unbond gauge should track deltas"
        );
        telemetry.record_public_lane_slash(lane);
        assert_eq!(
            metrics
                .nexus_public_lane_slash_total
                .with_label_values(&["5"])
                .get(),
            1
        );
    }
    #[test]
    fn torii_request_scheme_metrics_capture_latency_and_failures() {
        let metrics = Arc::new(Metrics::default());
        let telemetry = Telemetry::new(metrics.clone(), true);
        telemetry.observe_torii_request_by_scheme(
            "norito_rpc",
            StatusCode::OK,
            Duration::from_millis(25),
        );
        assert_eq!(
            metrics
                .torii_request_duration_seconds
                .with_label_values(&["norito_rpc"])
                .get_sample_count(),
            1,
            "latency histogram should capture successful request"
        );
        assert_eq!(
            metrics
                .torii_request_failures_total
                .with_label_values(&["norito_rpc", "500"])
                .get(),
            0,
            "successes should not increment failure counters"
        );
        telemetry.observe_torii_request_by_scheme(
            "norito_rpc",
            StatusCode::INTERNAL_SERVER_ERROR,
            Duration::from_millis(10),
        );
        assert_eq!(
            metrics
                .torii_request_duration_seconds
                .with_label_values(&["norito_rpc"])
                .get_sample_count(),
            2,
            "latency histogram should record every observation"
        );
        assert_eq!(
            metrics
                .torii_request_failures_total
                .with_label_values(&["norito_rpc", "500"])
                .get(),
            1,
            "5xx responses must increment failure counters"
        );
    }
    include!("telemetry/torii_explorer_request_metrics_test.rs");
    include!("telemetry/genesis_commit_time_test.rs");
    include!("telemetry/block_payload_tests.rs");
}

mod classified_status;
#[cfg(feature = "telemetry")]
pub use classified_status::OwnedStatus;
pub use classified_status::StatusSnapshotError;
