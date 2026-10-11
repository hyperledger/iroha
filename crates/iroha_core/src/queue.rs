//! Module with queue actor
//!
//! Handles transaction admission, TEU accounting, and per-lane telemetry
//! updates. Lane/dataspace routing is delegated to a pluggable router so the
//! queue can expose the actual Nexus assignments instead of single-lane
//! placeholders.
mod payload_leases;
mod sumeragi_wake;
pub(crate) use sumeragi_wake::SumeragiQueueRegistration;
use sumeragi_wake::SumeragiQueueReservation;
use sumeragi_wake::SumeragiQueueWake;
mod resident_owner;
use resident_owner::{QueueResidentLedger, QueuedTransaction};
mod router;
use crate::state::LaneLifecycleError;
#[cfg(feature = "telemetry")]
use crate::telemetry::{DataspaceTeuGaugeUpdate, LaneTeuGaugeUpdate};
use crate::{
    EventsSender,
    compliance::{LaneComplianceContext, LaneComplianceEngine, LaneComplianceEvaluation},
    executor::{
        FeeAdmissionQuote, FeeChargeBound, FeeSponsorRelayLeaseCapacity, NexusFeeAdmissionError,
        quote_external_nexus_fee_admission,
    },
    gas,
    governance::manifest::{
        GovernanceGuardError, GovernanceRules, LaneManifestRegistry, LaneManifestRegistryHandle,
        LaneManifestSourceSnapshot, LaneManifestStatus,
    },
    interlane::{LanePrivacyRegistry, LanePrivacyRegistryHandle, verify_lane_privacy_proofs},
    nexus::space_directory::{
        LaneIdentityMetadataError,
        extract_authority_domains as extract_directory_authority_domains,
        extract_lane_identity_metadata as extract_directory_lane_identity_metadata,
    },
    prelude::*,
    publication_lock::PublicationMutex,
    state::{State, StateReadOnly, WorldReadOnly},
    status,
    telemetry::StateTelemetry,
    tx::{
        CheckedTransaction, allows_unregistered_authority,
        instructions_allow_multisig_envelope_authority,
    },
};
use core::time::Duration;
use crossbeam_queue::ArrayQueue;
use dashmap::{DashMap, mapref::entry::Entry};
use eyre::Result;
#[cfg(test)]
use iroha_config::parameters::actual::LaneConfig as LaneGeometry;
use iroha_config::parameters::actual::{
    GovernanceCatalog, LaneRegistry, LaneRoutingPolicy, Nexus, Pipeline, Queue as Config,
};
use iroha_crypto::{Hash, HashOf};
#[cfg(test)]
use iroha_data_model::block::BlockHeader;
use iroha_data_model::nexus::{
    DataSpaceCatalog, FeeDebitSource, FeeRejectionCode, FeeSponsorBeneficiaryEpochBudgetWindow,
    FeeSponsorBlockBudgetWindow, FeeSponsorBudgetCounterKey, FeeSponsorBudgetWindow,
    FeeSponsorProgramEpochBudgetWindow, FeeSponsorProgramId, FeeSponsorProgramRevisionKey,
    LaneCatalog, LanePrivacyProof, UniversalAccountId,
};
#[cfg(test)]
use iroha_data_model::nexus::{LaneLifecyclePlan, LaneStorageProfile, LaneVisibility};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    block::{ExternalExecutionContext, ExternalExecutionRouteLeg, ExternalExecutionRouteRole},
    events::pipeline::{TransactionEvent, TransactionStatus},
    isi::{
        InstructionBox,
        error::Mismatch,
        runtime_upgrade::{ActivateRuntimeUpgrade, CancelRuntimeUpgrade, ProposeRuntimeUpgrade},
        smart_contract_code::{
            ActivateContractInstance, CommitContractDeployment, DeactivateContractInstance,
            FinalizeSmartContractCodeUpload, RegisterSmartContractBytes, RegisterSmartContractCode,
            RemoveSmartContractBytes, UploadSmartContractCodeChunk,
        },
    },
    transaction::{
        Executable, ExecutableBatchItem, SignedTransaction, TransactionDomain,
        TransactionEntrypoint, signed::TransactionPayload,
    },
};
use iroha_logger::{trace, warn};
use iroha_model_base::name::Name;
#[cfg(test)]
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::{numeric::Quantity, time::TimeSource};
#[cfg(feature = "telemetry")]
use iroha_torii_shared::status::NexusLaneTeuBuckets;
#[cfg(any(test, feature = "telemetry"))]
use ivm::ProgramMetadata;
use mv::storage::StorageReadOnly;
#[cfg(test)]
use norito::core as ncore;
use parking_lot::RwLock;
pub(crate) use payload_leases::{PendingPayloadLease, PendingPayloadSelection};
pub use router::{
    ConfigLaneRouter, LaneRouter, NativeAmxRoutingPlan, RouteLeg, RouteLegRole, RoutingDecision,
    RoutingPlan, RoutingResolveError, TransactionRoutingView, evaluate_policy_plan_with_catalog,
    evaluate_policy_plan_with_catalog_and_world, evaluate_policy_plan_with_catalog_and_world_at,
    evaluate_policy_plan_with_nexus_and_world_at,
    evaluate_policy_plan_with_nexus_and_world_at_block_height, evaluate_policy_with_catalog,
    evaluate_policy_with_catalog_and_world, evaluate_policy_with_catalog_and_world_at,
    resolve_query_routing_decision, resolve_routing_decision,
};
pub(crate) use router::{
    matchers_match_with_world, native_execution_target, native_instruction_execution_target,
    private_genesis_instruction_target,
};
#[cfg(test)]
use std::sync::mpsc;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fmt,
    num::{NonZeroU64, NonZeroUsize},
    str::FromStr,
    sync::{
        Arc, LazyLock, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use thiserror::Error;
use tokio::{
    sync::watch,
    time::{MissedTickBehavior, interval},
};
pub(crate) mod policy_route;
type EntrypointHash = HashOf<TransactionEntrypoint>;
use crate::smartcontracts::isi::sccp::admission::{
    SccpAdmissionKeysV1, SccpAdmissionRejectV1, SccpExemptBlockBudgetV1, SccpPendingClaimErrorV1,
    SccpPendingIndexV1,
};
#[cfg(test)]
fn queue_test_network_id() -> iroha_data_model::NetworkId {
    // Match the exact genesis hash in `iroha_config/iroha_test_config.toml` so
    // state-free queue fixtures remain in the same domain as `State::new`.
    let mut genesis_hash = [0; Hash::LENGTH];
    genesis_hash[Hash::LENGTH - 1] = 1;
    iroha_data_model::NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed(genesis_hash),
    ))
}
/// Convert a queue routing plan into durable block execution-context legs.
#[must_use]
pub(crate) fn execution_context_legs_for_routing_plan(
    plan: &RoutingPlan,
) -> Vec<ExternalExecutionRouteLeg> {
    plan.legs()
        .into_iter()
        .map(|leg| {
            let role = match leg.role {
                RouteLegRole::Coordinator => ExternalExecutionRouteRole::Coordinator,
                RouteLegRole::Participant => ExternalExecutionRouteRole::Participant,
            };
            ExternalExecutionRouteLeg::new(leg.route.lane_id, leg.route.dataspace_id, role)
        })
        .collect()
}
/// Reconstruct the canonical routing plan and reject inconsistent redundant fields.
pub(crate) fn routing_plan_from_execution_context(
    context: &ExternalExecutionContext,
) -> Result<RoutingPlan, String> {
    let coordinator = context
        .routing_plan_legs
        .first()
        .ok_or_else(|| "execution context routing plan has no coordinator leg".to_owned())?;
    if coordinator.role != ExternalExecutionRouteRole::Coordinator
        || coordinator.lane_id != context.lane_id
        || coordinator.dataspace_id != context.dataspace_id
    {
        return Err(
            "execution context coordinator leg differs from its redundant route fields".to_owned(),
        );
    }
    let coordinator = RoutingDecision::new(coordinator.lane_id, coordinator.dataspace_id);
    let plan = if context.routing_plan_legs.len() == 1 {
        RoutingPlan::single(coordinator)
    } else {
        let participants = context
            .routing_plan_legs
            .iter()
            .skip(1)
            .map(|leg| {
                if leg.role != ExternalExecutionRouteRole::Participant {
                    return Err(
                        "execution context has a non-participant leg after its coordinator"
                            .to_owned(),
                    );
                }
                Ok(RouteLeg::new(
                    RoutingDecision::new(leg.lane_id, leg.dataspace_id),
                    RouteLegRole::Participant,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        RoutingPlan::native_amx(coordinator, participants)
    };
    if plan.digest() != context.routing_plan_digest
        || execution_context_legs_for_routing_plan(&plan) != context.routing_plan_legs
    {
        return Err(
            "execution context routing digest, roles, or leg order is noncanonical".to_owned(),
        );
    }
    Ok(plan)
}
/// Compare routing-plan topology while deliberately ignoring lane selection.
///
/// Roles, multiplicity, and plan variants remain significant.
#[must_use]
#[cfg(test)]
pub(crate) fn routing_plans_have_same_dataspace_role_topology(
    left: &RoutingPlan,
    right: &RoutingPlan,
) -> bool {
    if core::mem::discriminant(left) != core::mem::discriminant(right) {
        return false;
    }
    let topology = |plan: &RoutingPlan| {
        let mut legs = plan
            .legs()
            .into_iter()
            .map(|leg| {
                let role = u8::from(leg.role == RouteLegRole::Participant);
                (leg.route.dataspace_id, role)
            })
            .collect::<Vec<_>>();
        legs.sort_unstable();
        legs
    };
    topology(left) == topology(right)
}
/// Convert a queue routing plan into one durable external block execution context.
#[must_use]
#[cfg(test)]
pub(crate) fn execution_context_for_routing_plan(
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    plan: &RoutingPlan,
) -> ExternalExecutionContext {
    let coordinator = plan.coordinator_route();
    ExternalExecutionContext::with_routing_plan(
        entrypoint_hash,
        coordinator.lane_id,
        coordinator.dataspace_id,
        plan.digest(),
        execution_context_legs_for_routing_plan(plan),
    )
}

/// Resolve every coordinator and participant leg in a full routing plan against active catalogs.
pub(crate) fn resolve_routing_plan_against_catalogs(
    plan: RoutingPlan,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
) -> Result<RoutingPlan, RoutingResolveError> {
    match plan {
        RoutingPlan::Single(leg) => {
            let route = resolve_routing_decision(leg.route, lane_catalog, dataspace_catalog)?;
            Ok(RoutingPlan::single(route))
        }
        RoutingPlan::NativeAmx(plan) => {
            let coordinator =
                resolve_routing_decision(plan.coordinator.route, lane_catalog, dataspace_catalog)?;
            let participants = plan
                .participants
                .into_iter()
                .map(|leg| {
                    resolve_routing_decision(leg.route, lane_catalog, dataspace_catalog)
                        .map(|route| RouteLeg::new(route, RouteLegRole::Participant))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RoutingPlan::native_amx(coordinator, participants))
        }
    }
}

fn ensure_routing_plan_active_at_height(
    plan: &RoutingPlan,
    nexus: &Nexus,
    block_height: u64,
) -> Result<(), RoutingResolveError> {
    for leg in plan.legs() {
        let route = leg.route;
        if crate::state::consensus_lane_dataspace_at_height(route.lane_id, nexus, block_height)
            != Some(route.dataspace_id)
        {
            return Err(RoutingResolveError::InactiveLane {
                lane_id: route.lane_id,
                dataspace_id: route.dataspace_id,
            });
        }
    }
    Ok(())
}

fn resolve_routing_plan_against_nexus_at_height(
    plan: RoutingPlan,
    nexus: &Nexus,
    block_height: u64,
) -> Result<RoutingPlan, RoutingResolveError> {
    let plan =
        resolve_routing_plan_against_catalogs(plan, &nexus.lane_catalog, &nexus.dataspace_catalog)?;
    ensure_routing_plan_active_at_height(&plan, nexus, block_height)?;
    Ok(plan)
}

/// Validate the physical route against the applied catalog and the next proposal height.
/// Native logical lane selection is independently derived from World.sumeragi_lanes.
fn resolve_routing_plan_for_queue_admission(
    plan: RoutingPlan,
    nexus: &Nexus,
    committed_height: u64,
) -> Result<RoutingPlan, RoutingResolveError> {
    policy_route::resolve_plan_for_admission(plan, nexus, committed_height)
}

fn state_height_for_routing(state: &State) -> u64 {
    u64::try_from(state.committed_height()).unwrap_or(u64::MAX)
}

fn state_view_height_for_routing(state_view: &StateView<'_>) -> u64 {
    u64::try_from(state_view.height()).unwrap_or(u64::MAX)
}

fn nexus_with_route_catalogs(
    nexus: &Nexus,
    lane_catalog: &LaneCatalog,
    dataspace_catalog: &DataSpaceCatalog,
) -> Nexus {
    let mut nexus = nexus.clone();
    nexus.lane_catalog = lane_catalog.clone();
    nexus.dataspace_catalog = dataspace_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus
}

/// Per-lane queue scheduling limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneSchedulingLimits {
    /// TEU capacity per lane for telemetry snapshots.
    pub teu_capacity: u64,
    /// Starvation bound (slots) applied to dataspace metrics.
    pub starvation_bound_slots: u64,
}
impl LaneSchedulingLimits {
    /// Construct scheduling limits from explicit capacity and starvation configuration.
    pub const fn new(teu_capacity: u64, starvation_bound_slots: u64) -> Self {
        Self {
            teu_capacity,
            starvation_bound_slots,
        }
    }
}
/// Nexus-derived limits that influence queue telemetry and scheduling defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueLimits {
    fallback: LaneSchedulingLimits,
    per_lane: BTreeMap<LaneId, LaneSchedulingLimits>,
}
impl QueueLimits {
    /// Build limits using values from the runtime Nexus configuration.
    #[must_use]
    pub fn from_nexus(nexus: &Nexus) -> Self {
        let fallback = LaneSchedulingLimits::new(
            u64::from(nexus.fusion.exit_teu),
            u64::from(nexus.da.rotation.window_slots.get()),
        );
        let mut per_lane = BTreeMap::new();
        for lane in nexus.lane_catalog.lanes() {
            let limits = Self::lane_limits_from_policy(lane, fallback);
            per_lane.insert(lane.id, limits);
        }
        Self { fallback, per_lane }
    }
    /// Derive lane-specific limits from typed overrides or fall back to the global defaults.
    pub(crate) fn lane_limits_from_policy(
        lane: &iroha_data_model::nexus::LaneConfig,
        fallback: LaneSchedulingLimits,
    ) -> LaneSchedulingLimits {
        let mut limits = fallback;
        if let Some(policy) = lane.scheduler.as_ref() {
            if let Some(teu_capacity) = policy.teu_capacity {
                limits.teu_capacity = teu_capacity.get();
            }
            if let Some(starvation_bound_slots) = policy.starvation_bound_slots {
                limits.starvation_bound_slots = starvation_bound_slots.get();
            }
        }
        limits
    }
    /// Return the scheduling limits associated with `lane`, falling back to the global defaults.
    #[must_use]
    pub fn for_lane(&self, lane: LaneId) -> LaneSchedulingLimits {
        self.per_lane.get(&lane).copied().unwrap_or(self.fallback)
    }
}
impl Default for QueueLimits {
    fn default() -> Self {
        Self::from_nexus(&Nexus::default())
    }
}
static GOV_CONTRACT_ADDRESS_METADATA_KEY: LazyLock<Name> = LazyLock::new(|| {
    Name::from_str("gov_contract_address").expect("static governance metadata key")
});
static GOV_APPROVERS_METADATA_KEY: LazyLock<Name> = LazyLock::new(|| {
    Name::from_str("gov_manifest_approvers").expect("static governance metadata key")
});
static CONTRACT_ADDRESS_METADATA_KEY: LazyLock<Name> =
    LazyLock::new(|| Name::from_str("contract_address").expect("static contract metadata key"));

/// Advisory position for bounded leader sampling of local queue availability.
#[derive(Default)]
struct BoundedPendingScanCursor {
    next_index: usize,
}

/// Queue for admitted transactions.
///
/// Producers publish under one mutation lock. Native lane and global payload builders sample
/// signed inputs without removing them; only applied global execution retires committed inputs.
pub struct Queue {
    events_sender: EventsSender,
    /// Resolves lane/dataspace assignments for queued transactions.
    router: RwLock<Arc<dyn LaneRouter>>,
    /// Optional lane compliance engine.
    lane_compliance: RwLock<Option<Arc<crate::compliance::LaneComplianceEngine>>>,
    /// Cached lane catalog for routing/telemetry.
    lane_catalog: RwLock<Arc<LaneCatalog>>,
    /// Cached dataspace catalog for routing/telemetry.
    dataspace_catalog: RwLock<Arc<DataSpaceCatalog>>,
    /// Cached routing policy used by the active router.
    routing_policy: RwLock<LaneRoutingPolicy>,
    /// The queue for transactions
    tx_hashes: ArrayQueue<EntrypointHash>,
    /// Accepted transactions addressed by `Hash`.
    /// Its exact shared control is prepaid from the original State pool and retains
    /// resident admission credit through its final original reader.
    txs: DashMap<EntrypointHash, QueuedTransaction>,
    /// Admission keys of every queued fee-exempt SCCP transaction (`specs/sccp.md` §4.19),
    /// maintained atomically with `txs` under `push_remove_lock`.
    pending_sccp_exempt: parking_lot::Mutex<SccpPendingIndexV1>,
    /// Authoritative cached routing plan per entrypoint hash.
    routing_plans: DashMap<EntrypointHash, RoutingPlan>,
    /// Cached encoded length per queued transaction hash.
    tx_encoded_len: DashMap<EntrypointHash, usize>,
    /// Cached proposal gas cost per queued transaction hash.
    tx_gas_cost: DashMap<EntrypointHash, u64>,
    /// Canonical admission timestamp in milliseconds for tracked transactions.
    tx_enqueued_at_ms: DashMap<EntrypointHash, u64>,
    /// Canonical admission timestamp in milliseconds for hashes still waiting in `tx_hashes`.
    queued_tx_enqueued_at_ms: DashMap<EntrypointHash, u64>,
    /// FIFO enqueue-age index used to read the oldest queued transaction without scanning.
    /// Also serializes `tx_hashes` updates with this age index.
    queued_age_ring: parking_lot::Mutex<VecDeque<(EntrypointHash, u64)>>,
    /// Local leader sampling position. This is never part of proposal validity.
    pending_scan_cursor: parking_lot::Mutex<BoundedPendingScanCursor>,
    /// Live sponsor-program capacity holds keyed by canonical entrypoint hash.
    fee_admission_reservations: parking_lot::Mutex<FeeAdmissionReservationStore>,
    /// Sticky process-lifetime fault when accepted work exposes internally inconsistent immutable
    /// routing or fee-admission identity. Expected catalog retirement evicts affected work instead.
    accepted_work_validation_fault: AtomicBool,
    /// Process-lifetime emergency gate which prevents normal transaction admission.
    emergency_fast_startup: AtomicBool,
    /// Amount of transactions per user in the queue
    txs_per_user: DashMap<AccountId, usize>,
    /// Lock to synchronize push and remove operations
    push_remove_lock: PublicationMutex,
    /// Checked original-owner generation; every successful input insertion/removal advances it.
    pending_ownership_generation: AtomicU64,
    /// Serializes complete Nexus revalidation passes while their per-hash queue fences are
    /// released between the initial catalog rebuild and stable owner observations.
    nexus_revalidation_lock: parking_lot::Mutex<()>,
    /// One-shot notification immediately before a pending lookup acquires its State view.
    #[cfg(test)]
    pending_hash_state_view_handoff: parking_lot::Mutex<Option<mpsc::SyncSender<()>>>,
    /// The maximum number of transactions in the queue
    capacity: NonZeroUsize,
    /// The maximum number of transactions in the queue per user. Used to apply throttling
    capacity_per_user: NonZeroUsize,
    /// Estimated maximum retained queue memory budget in bytes.
    max_retained_bytes: NonZeroU64,
    /// Original State-funded counters retained through the last shared accepted owner.
    resident_accounting: OnceLock<iroha_allocation::ChargedShared<QueueResidentLedger>>,
    /// Preserve the existing test-only override before its first real State admission.
    #[cfg(test)]
    retained_bytes_before_admission: AtomicU64,
    /// The time source used to check transaction against
    ///
    /// A mock time source is used in tests for determinism
    time_source: TimeSource,
    /// Length of time after which transactions are dropped.
    pub tx_time_to_live: Duration,
    /// Minimum interval between expired-transaction sweeps.
    expired_cull_interval: Duration,
    /// Maximum number of entries scanned per expired-transaction sweep.
    expired_cull_batch: NonZeroUsize,
    /// Last time (unix ms) we swept expired transactions.
    last_expired_cull_ms: AtomicU64,
    /// Round-robin ring of queued transaction hashes used for TTL sweeps.
    expiry_ring: parking_lot::Mutex<VecDeque<EntrypointHash>>,
    /// Membership guard for the expiry ring to prevent unbounded growth.
    expiry_ring_members: DashMap<EntrypointHash, ()>,
    /// Queue to gossip transactions
    tx_gossip: ArrayQueue<EntrypointHash>,
    /// Broadcast queue load so producers can observe backpressure.
    backpressure_tx: watch::Sender<BackpressureState>,
    /// Age budget in milliseconds used to mark queue pressure as latency-saturated.
    pressure_age_budget_ms: AtomicU64,
    /// Optional wake handle for the Sumeragi worker when new transactions are enqueued.
    sumeragi_wake: parking_lot::Mutex<Option<SumeragiQueueWake>>,
    sumeragi_start_ticket: AtomicU64,
    /// Observe the actual native worker's completed EMPTY answer, never a timer or hint.
    #[cfg(test)]
    empty_native_payloads: AtomicUsize,
    #[cfg(test)]
    empty_lane_payloads: AtomicUsize,
    /// Limits derived from Nexus configuration (TEU capacity, starvation bounds).
    nexus_limits: RwLock<QueueLimits>,
    /// Cached TEU metadata for queued transactions keyed by hash.
    #[cfg(feature = "telemetry")]
    tx_teu: DashMap<EntrypointHash, TxTeuInfo>,
    /// Aggregated TEU per lane for queued transactions.
    #[cfg(feature = "telemetry")]
    lane_teu_pending: DashMap<LaneId, PendingTeu>,
    /// Aggregated TEU per (lane, dataspace) for queued transactions.
    #[cfg(feature = "telemetry")]
    dataspace_teu_pending: DashMap<(LaneId, DataSpaceId), PendingTeu>,
    /// Governance manifest registry for Nexus lanes.
    lane_manifests: parking_lot::RwLock<LaneManifestRegistryHandle>,
    /// Privacy commitments advertised by lane manifests.
    lane_privacy_registry: parking_lot::RwLock<LanePrivacyRegistryHandle>,
    #[cfg(test)]
    vacant_entry_warnings: AtomicUsize,
}
impl fmt::Debug for Queue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Queue")
            .field("capacity", &self.capacity)
            .field("capacity_per_user", &self.capacity_per_user)
            .field("max_retained_bytes", &self.max_retained_bytes)
            .field("tx_time_to_live", &self.tx_time_to_live)
            .field("expired_cull_interval", &self.expired_cull_interval)
            .field("expired_cull_batch", &self.expired_cull_batch)
            .field(
                "pressure_age_budget_ms",
                &self.pressure_age_budget_ms.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}
const QUEUE_PRESSURE_MIN_AGE_BUDGET_MS: u64 = 2_000;
const QUEUE_PRESSURE_MAX_AGE_BUDGET_MS: u64 = 5_000;
/// Fixed queue/index overhead charged to every retained transaction.
///
/// Canonical bytes are charged separately with a conservative expansion factor so small
/// transactions do not each consume an arbitrary 128 KiB while large decoded payloads cannot
/// evade the retained-memory budget.
const TX_RETAINED_OVERHEAD_BYTES: u64 = 2 * 1024;
/// Conservative encoded-to-retained expansion for decoded transaction payloads and canonical
/// bytes kept across queue indexes.
const TX_RETAINED_DECODE_EXPANSION_FACTOR: u64 = 8;
/// Snapshot of queue pressure used by Torii admission and status reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuePressureSnapshot {
    /// Number of transactions tracked by the queue (queued, in-flight, or durably owned while
    /// awaiting exact payload replay).
    pub tracked_tx_count: usize,
    /// Number of transactions still waiting in the queue.
    pub queued_tx_count: usize,
    /// Maximum queue capacity configured for the peer.
    pub capacity: NonZeroUsize,
    /// Estimated retained bytes for all pending transactions.
    pub retained_bytes: u64,
    /// Configured maximum estimated retained bytes for the queue.
    pub max_retained_bytes: NonZeroU64,
    /// Age in milliseconds of the oldest queue-resident transaction's local queue residence.
    pub oldest_queued_tx_age_ms: u64,
    /// Whether the queue saturated because the tracked count hit capacity.
    pub saturated_by_count: bool,
    /// Whether the queue saturated because the retained-byte budget is exhausted.
    pub saturated_by_bytes: bool,
    /// Whether the queue saturated because the oldest queued age exceeded the budget.
    pub saturated_by_age: bool,
}
impl QueuePressureSnapshot {
    /// Whether any saturation signal is active.
    #[must_use]
    pub const fn is_saturated(self) -> bool {
        self.saturated_by_count || self.saturated_by_bytes || self.saturated_by_age
    }
    /// Convert the richer pressure snapshot into the coarse backpressure state.
    ///
    /// Coarse backpressure gates admission and consensus pacing. Keep it tied to
    /// count/byte capacity saturation; age pressure stays available through the
    /// richer snapshot for status reporting and diagnostics.
    #[must_use]
    pub const fn into_backpressure(self) -> BackpressureState {
        if self.saturated_by_count || self.saturated_by_bytes {
            BackpressureState::Saturated {
                queued: self.queued_tx_count,
                capacity: self.capacity,
            }
        } else {
            BackpressureState::Healthy {
                queued: self.queued_tx_count,
                capacity: self.capacity,
            }
        }
    }
}
/// Snapshot of queue occupancy used to coordinate backpressure across Torii,
/// the gossiper, and consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressureState {
    /// Queue has room for new transactions.
    Healthy {
        /// Number of transactions still waiting in the queue.
        queued: usize,
        /// Maximum queue capacity configured for the peer.
        capacity: NonZeroUsize,
    },
    /// Queue reached capacity; callers should defer submissions.
    Saturated {
        /// Number of transactions still waiting in the queue when saturation triggered.
        queued: usize,
        /// Maximum queue capacity configured for the peer.
        capacity: NonZeroUsize,
    },
}
impl BackpressureState {
    #[must_use]
    /// Whether the queue snapshot represents a saturated state.
    pub const fn is_saturated(self) -> bool {
        matches!(self, Self::Saturated { .. })
    }
    #[must_use]
    /// Number of transactions still waiting in the queue in the snapshot.
    pub const fn queued(self) -> usize {
        match self {
            Self::Healthy { queued, .. } | Self::Saturated { queued, .. } => queued,
        }
    }
    #[must_use]
    /// Queue capacity recorded in the snapshot.
    pub const fn capacity(self) -> NonZeroUsize {
        match self {
            Self::Healthy { capacity, .. } | Self::Saturated { capacity, .. } => capacity,
        }
    }
}
impl Default for BackpressureState {
    fn default() -> Self {
        Self::Healthy {
            queued: 0,
            capacity: NonZeroUsize::new(1).expect("capacity must be non-zero"),
        }
    }
}
/// Gossip payload paired with its routing metadata.
#[derive(Clone)]
pub struct GossipBatchEntry {
    /// Accepted transaction to gossip.
    pub tx: AcceptedTransaction<'static>,
    /// Lane/dataspace routing decision resolved for this gossip sample.
    pub routing: RoutingDecision,
    /// Full routing plan resolved for this gossip sample.
    pub routing_plan: RoutingPlan,
    /// Pre-serialized full-frame transaction payload for retransmit.
    pub payload: Arc<Vec<u8>>,
}
struct PreparedQueueAdmission {
    checked: CheckedTransaction<'static>,
    hash: EntrypointHash,
    /// SCCP exemption keys claimed with the transaction.
    sccp_exempt: Option<SccpAdmissionKeysV1>,
    routing_decision: RoutingDecision,
    routing_plan: RoutingPlan,
    encoded_len: usize,
    proposal_gas_cost: u64,
    enqueued_at_ms: u64,
    fee_reservation: Option<FeeAdmissionReservation>,
    #[cfg(feature = "telemetry")]
    pending_teu: u64,
}
/// Failure deriving a signature-bound proposal gas limit.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum ProposalGasCostError {
    /// An executable with runtime-dependent work omitted its signature-bound gas limit.
    #[error("runtime-dependent executable is missing its signed gas limit")]
    MissingSignedGasLimit,
}
/// Exact balance resource held by one queued fee component.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FeeReservationAssetSource {
    Authority(AssetId),
    SponsorProgram {
        program_id: FeeSponsorProgramId,
        asset_definition_id: AssetDefinitionId,
    },
}
/// In-memory hold on fee-payer capacity for one admitted transaction.
///
/// Persisted budget counters remain authoritative. This reservation prevents
/// multiple live queue entries from independently passing against the same
/// pre-execution vault and budget snapshot.
#[derive(Clone, Debug)]
struct FeeAdmissionReservation {
    program_revision: Option<u64>,
    beneficiary: AccountId,
    asset_charges: BTreeMap<FeeReservationAssetSource, Quantity>,
    window_charges: BTreeMap<FeeSponsorBudgetCounterKey, Quantity>,
    relay_lease_charges: BTreeMap<Hash, Quantity>,
    asset_remaining: BTreeMap<FeeReservationAssetSource, Quantity>,
    window_remaining: BTreeMap<FeeSponsorBudgetCounterKey, Quantity>,
    relay_lease_remaining: BTreeMap<Hash, Quantity>,
}
fn sponsored_charge_totals(
    charges: &[FeeChargeBound],
) -> Result<BTreeMap<AssetDefinitionId, Quantity>, Error> {
    let mut totals = BTreeMap::<AssetDefinitionId, Quantity>::new();
    for charge in charges {
        let current = totals
            .get(&charge.asset_definition_id)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        let total = FeeAdmissionReservationStore::checked_add(
            &current,
            &charge.max_bound,
            "per-asset charge",
        )?;
        totals.insert(charge.asset_definition_id.clone(), total);
    }
    Ok(totals)
}
fn relay_lease_reservation_maps(
    program_id: &FeeSponsorProgramId,
    sponsor_charges: &BTreeMap<AssetDefinitionId, Quantity>,
    relay_leases: BTreeMap<AssetDefinitionId, FeeSponsorRelayLeaseCapacity>,
) -> Result<(BTreeMap<Hash, Quantity>, BTreeMap<Hash, Quantity>), Error> {
    let mut relay_lease_charges = BTreeMap::<Hash, Quantity>::new();
    let mut relay_lease_remaining = BTreeMap::<Hash, Quantity>::new();
    for (asset_definition_id, selection) in relay_leases {
        let charge = sponsor_charges.get(&asset_definition_id).ok_or_else(|| {
            Error::NexusFeeAdmissionConfigInvalid {
                code: FeeRejectionCode::InvalidProgramConfiguration,
                reason: format!(
                    "sponsor program `{program_id}` quote selected spend lease `{}` for uncharged asset `{asset_definition_id}`",
                    selection.lease_id
                ),
            }
        })?;
        let current = relay_lease_charges
            .get(&selection.lease_id)
            .cloned()
            .unwrap_or_else(Quantity::zero);
        relay_lease_charges.insert(
            selection.lease_id,
            FeeAdmissionReservationStore::checked_add(&current, charge, "per-lease charge")?,
        );
        if let Some(previous) =
            relay_lease_remaining.insert(selection.lease_id, selection.remaining.clone())
            && previous != selection.remaining
        {
            return Err(Error::NexusFeeAdmissionConfigInvalid {
                code: FeeRejectionCode::InvalidProgramConfiguration,
                reason: format!(
                    "sponsor program `{program_id}` quote reported inconsistent remaining capacity for spend lease `{}`",
                    selection.lease_id
                ),
            });
        }
    }
    Ok((relay_lease_charges, relay_lease_remaining))
}
#[derive(Clone, Default)]
struct FeeAdmissionReservationStore {
    live_by_entrypoint: BTreeMap<EntrypointHash, FeeAdmissionReservation>,
}
impl FeeAdmissionReservationStore {
    fn checked_add(
        lhs: &Quantity,
        rhs: &Quantity,
        context: &'static str,
    ) -> Result<Quantity, Error> {
        lhs.checked_add(rhs)
            .map_err(|_| Error::NexusFeeAdmissionConfigInvalid {
                code: FeeRejectionCode::InvalidProgramConfiguration,
                reason: format!("fee reservation {context} arithmetic overflow"),
            })
    }
    fn ensure_capacity(&self, reservation: &FeeAdmissionReservation) -> Result<(), Error> {
        for (source, amount) in &reservation.asset_charges {
            let already_reserved = self
                .live_by_entrypoint
                .values()
                .filter_map(|existing| existing.asset_charges.get(source))
                .try_fold(Quantity::zero(), |total, amount| {
                    Self::checked_add(&total, amount, "payer balance capacity")
                })?;
            let required = Self::checked_add(&already_reserved, amount, "payer balance capacity")?;
            let available = reservation
                .asset_remaining
                .get(source)
                .cloned()
                .unwrap_or_else(Quantity::zero);
            if required > available {
                let (code, detail) = match source {
                    FeeReservationAssetSource::Authority(asset_id) => (
                        FeeRejectionCode::AuthorityPayerInsufficient,
                        format!(
                            "authority balance `{asset_id}` for `{}`",
                            reservation.beneficiary
                        ),
                    ),
                    FeeReservationAssetSource::SponsorProgram {
                        program_id,
                        asset_definition_id,
                    } => (
                        FeeRejectionCode::VaultInsufficient,
                        format!(
                            "sponsor program `{program_id}` revision {} vault `{asset_definition_id}` for beneficiary `{}`",
                            reservation.program_revision.map_or_else(
                                || "unknown".to_owned(),
                                |revision| revision.to_string()
                            ),
                            reservation.beneficiary,
                        ),
                    ),
                };
                return Err(Error::NexusFeeAdmissionRejected {
                    code,
                    reason: format!(
                        "live queue reservations exhaust {detail}: requires {required}, available {available}"
                    ),
                });
            }
        }
        for (key, amount) in &reservation.window_charges {
            let already_reserved = self
                .live_by_entrypoint
                .values()
                .filter_map(|existing| existing.window_charges.get(key))
                .try_fold(Quantity::zero(), |total, amount| {
                    Self::checked_add(&total, amount, "budget-window capacity")
                })?;
            let required = Self::checked_add(&already_reserved, amount, "budget-window capacity")?;
            let available = reservation
                .window_remaining
                .get(key)
                .cloned()
                .unwrap_or_else(Quantity::zero);
            if required > available {
                let code = match &key.window {
                    FeeSponsorBudgetWindow::Block(_) => {
                        FeeRejectionCode::ProgramBlockBudgetExhausted
                    }
                    FeeSponsorBudgetWindow::ProgramEpoch(_) => {
                        FeeRejectionCode::ProgramEpochBudgetExhausted
                    }
                    FeeSponsorBudgetWindow::BeneficiaryEpoch(_) => {
                        FeeRejectionCode::BeneficiaryEpochBudgetExhausted
                    }
                };
                return Err(Error::NexusFeeAdmissionRejected {
                    code,
                    reason: format!(
                        "live queue reservations exhaust sponsor program `{}` revision {} budget window for beneficiary `{}` and asset `{}`: requires {required}, available {available}",
                        key.program_id,
                        reservation
                            .program_revision
                            .map_or_else(|| "unknown".to_owned(), |revision| revision.to_string()),
                        reservation.beneficiary,
                        key.asset_definition_id,
                    ),
                });
            }
        }
        for (lease_id, amount) in &reservation.relay_lease_charges {
            let already_reserved = self
                .live_by_entrypoint
                .values()
                .filter_map(|existing| existing.relay_lease_charges.get(lease_id))
                .try_fold(Quantity::zero(), |total, amount| {
                    Self::checked_add(&total, amount, "relay spend-lease capacity")
                })?;
            let required =
                Self::checked_add(&already_reserved, amount, "relay spend-lease capacity")?;
            let available = reservation
                .relay_lease_remaining
                .get(lease_id)
                .cloned()
                .unwrap_or_else(Quantity::zero);
            if required > available {
                return Err(Error::NexusFeeAdmissionRejected {
                    code: FeeRejectionCode::RelayCapacityUnavailable,
                    reason: format!(
                        "live queue reservations exhaust sponsor spend lease `{lease_id}`: requires {required}, available {available}"
                    ),
                });
            }
        }
        Ok(())
    }
    fn reserve(
        &mut self,
        hash: EntrypointHash,
        reservation: FeeAdmissionReservation,
    ) -> Result<(), Error> {
        if self.live_by_entrypoint.contains_key(&hash) {
            return Err(Error::IsInQueue);
        }
        self.ensure_capacity(&reservation)?;
        self.live_by_entrypoint.insert(hash, reservation);
        Ok(())
    }
    fn release(&mut self, hash: &EntrypointHash) {
        self.live_by_entrypoint.remove(hash);
    }
}

struct QueueAdmissionNotification {
    hash: EntrypointHash,
    _entrypoint_hash: HashOf<TransactionEntrypoint>,
    lane_id: LaneId,
    dataspace_id: DataSpaceId,
    _enqueue_timestamp_ms: u64,
    _routing_plan: RoutingPlan,
    signed_transaction_hash: Option<HashOf<iroha_data_model::transaction::SignedTransaction>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GossipEntryState {
    Pending,
    Committed,
    Other,
}
#[cfg(feature = "telemetry")]
#[derive(Clone, Copy, Debug)]
struct TxTeuInfo {
    lane_id: LaneId,
    dataspace_id: DataSpaceId,
    teu: u64,
}
#[cfg(feature = "telemetry")]
#[derive(Clone, Copy, Debug, Default)]
struct PendingTeu {
    teu: u64,
    tx_count: usize,
}
#[cfg(any(test, feature = "telemetry"))]
const IVM_TEU_FALLBACK: u64 = 5_000;
/// Handle that observers can clone to subscribe to queue backpressure updates.
#[derive(Clone, Debug)]
pub struct BackpressureHandle {
    rx: watch::Receiver<BackpressureState>,
}
impl BackpressureHandle {
    #[must_use]
    /// Subscribe to backpressure state updates.
    pub fn subscribe(&self) -> watch::Receiver<BackpressureState> {
        self.rx.clone()
    }
    #[must_use]
    /// Return the most recent backpressure snapshot without subscribing.
    pub fn snapshot(&self) -> BackpressureState {
        *self.rx.borrow()
    }
}
/// Queue push error
#[derive(Error, Clone, Debug, displaydoc::Display)]
#[allow(variant_size_differences)]
pub enum Error {
    /// Local admission did not complete: {0}
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// Queue is full
    Full,
    /// Queue latency budget is saturated
    LatencySaturated,
    /// Transaction expired
    Expired,
    /// Signed transaction domain does not match the committed admission State: {0}
    TransactionDomainMismatch(Mismatch<TransactionDomain>),
    /// Transaction is already applied
    InBlockchain,
    /// User reached maximum number of transactions in the queue
    MaximumTransactionsPerUser,
    /// The transaction is already in the queue
    IsInQueue,
    /// Transaction authority is not registered: {authority}
    UnregisteredAuthority {
        /// Authority that was absent from the committed world state.
        authority: AccountId,
    },
    /// Current consensus cannot execute this transaction admission: {reason}
    UnsupportedTransactionAdmission {
        /// Unsupported signed intent, resolved multi-route execution, or a transaction larger
        /// than any proposer of the committed chain can include.
        reason: String,
    },
    /// Transaction routing could not be resolved: {reason}
    UnresolvedRoute {
        /// Deterministic route-resolution failure reason.
        reason: String,
    },
    /// Lane governance manifest is missing or invalid: {0}
    Governance(GovernanceGuardError),
    /// Transaction not permitted by lane governance manifest: {alias} ({reason})
    GovernanceNotPermitted {
        /// Lane alias that triggered the governance rejection.
        alias: String,
        /// Explanation describing why the manifest rejected the transaction.
        reason: String,
    },
    /// Transaction violates lane compliance policy for {alias}: {reason}
    LaneComplianceDenied {
        /// Lane alias configured for the policy.
        alias: String,
        /// Reason describing why the policy denied the transaction.
        reason: String,
    },
    /// Lane privacy proof rejected for {alias}: {reason}
    LanePrivacyProofRejected {
        /// Lane alias configured for the policy.
        alias: String,
        /// Reason describing why the privacy proof failed.
        reason: String,
    },
    /// Nexus fee admission rejected the transaction before queueing [{code}]: {reason}
    NexusFeeAdmissionRejected {
        /// Stable machine-readable fee/sponsor rejection code.
        code: FeeRejectionCode,
        /// Reason describing why the transaction could not cover the Nexus fee bound.
        reason: String,
    },
    /// Nexus fee admission encountered invalid node configuration [{code}]: {reason}
    NexusFeeAdmissionConfigInvalid {
        /// Stable machine-readable invalid-configuration code.
        code: FeeRejectionCode,
        /// Reason describing which Nexus fee configuration entry is invalid.
        reason: String,
    },
    /// Queue admission indexes are inconsistent: {reason}
    AdmissionInvariant {
        /// Exact local invariant failure.
        reason: String,
    },
}

impl From<RoutingResolveError> for Error {
    fn from(error: RoutingResolveError) -> Self {
        match error {
            RoutingResolveError::Deferred(reason) => Self::Deferred(reason),
            error => Self::UnresolvedRoute {
                reason: error.to_string(),
            },
        }
    }
}

/// Require a single resolved route supported by the current consensus executor.
///
/// # Errors
/// Returns a permanent rejection for multi-route execution without a current owner.
pub fn validate_current_admission_route(plan: &RoutingPlan) -> Result<(), Error> {
    if !matches!(plan, RoutingPlan::Single(_)) {
        return Err(Error::UnsupportedTransactionAdmission {
            reason: "current consensus does not support multi-route transaction admission"
                .to_owned(),
        });
    }
    Ok(())
}

/// Failure that can pop up when pushing transaction into the queue
#[derive(Debug)]
pub struct Failure {
    /// Transaction failed to be pushed into the queue
    pub tx: Box<AcceptedTransaction<'static>>,
    /// Push failure reason
    pub err: Error,
}
trait QueueAdmissionStateAccess {
    fn authority_exists(&mut self, authority: &AccountId) -> bool;
    /// Whether a proposer of the committed chain can include `transaction` on its route
    /// (`sumeragi::payload::check_includable_transaction`).
    fn check_includable_transaction(
        &mut self,
        transaction: &AcceptedTransaction<'_>,
    ) -> Result<
        (),
        crate::execution_attempt::ExecutionAttemptError<
            iroha_data_model::parameter::system::TransactionNeverIncludable,
        >,
    >;
    /// Classify an external signed transaction's SCCP exemption against committed state
    /// (`specs/sccp.md` §4.19).
    fn sccp_exempt_admission(
        &mut self,
        transaction: &SignedTransaction,
    ) -> Result<Option<SccpAdmissionKeysV1>, SccpAdmissionRejectV1>;
    fn manifest_authority_eligible_lanes(
        &mut self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
    ) -> BTreeSet<LaneId>;
    fn recheck_external_nexus_fee_admission(
        &mut self,
        queue: &Queue,
        tx: &AcceptedTransaction<'static>,
        route_dataspace_id: Option<DataSpaceId>,
    ) -> Result<Option<FeeAdmissionReservation>, Error>;
    fn extract_lane_identity_metadata(
        &mut self,
        authority: &AccountId,
        dataspace_id: DataSpaceId,
        lane_alias: &str,
    ) -> Result<(Option<UniversalAccountId>, Vec<String>), Error>;
    fn extract_lane_authority_domains(
        &mut self,
        authority: &AccountId,
        lane_alias: &str,
    ) -> Result<Vec<iroha_model_base::domain::DomainId>, Error>;
}
struct EagerAdmissionStateAccess<'view, W: WorldReadOnly> {
    world: &'view W,
    nexus: &'view Nexus,
    pipeline: &'view Pipeline,
    /// Committed SCCP attestation statement digests (block hashes and the live `NetworkId`),
    /// which SCCP exempt pre-verification checks signatures against.
    sccp_digests: &'view dyn crate::smartcontracts::isi::sccp::subjects::SccpStatementDigests,
    next_block_height: u64,
    ledger_time_ms: u64,
}
impl<W: WorldReadOnly> EagerAdmissionStateAccess<'_, W> {
    const fn new<'view>(
        world: &'view W,
        nexus: &'view Nexus,
        pipeline: &'view Pipeline,
        sccp_digests: &'view dyn crate::smartcontracts::isi::sccp::subjects::SccpStatementDigests,
        next_block_height: u64,
        ledger_time_ms: u64,
    ) -> EagerAdmissionStateAccess<'view, W> {
        EagerAdmissionStateAccess {
            world,
            nexus,
            pipeline,
            sccp_digests,
            next_block_height,
            ledger_time_ms,
        }
    }
}
impl<W: WorldReadOnly> QueueAdmissionStateAccess for EagerAdmissionStateAccess<'_, W> {
    fn authority_exists(&mut self, authority: &AccountId) -> bool {
        self.world.accounts().get(authority).is_some()
    }
    fn check_includable_transaction(
        &mut self,
        transaction: &AcceptedTransaction<'_>,
    ) -> Result<
        (),
        crate::execution_attempt::ExecutionAttemptError<
            iroha_data_model::parameter::system::TransactionNeverIncludable,
        >,
    > {
        crate::sumeragi::payload::check_includable_transaction(
            self.world,
            &self.nexus.dataspace_catalog,
            self.ledger_time_ms,
            self.next_block_height,
            transaction,
        )
    }
    fn sccp_exempt_admission(
        &mut self,
        transaction: &SignedTransaction,
    ) -> Result<Option<SccpAdmissionKeysV1>, SccpAdmissionRejectV1> {
        crate::smartcontracts::isi::sccp::admission::classify(
            self.world,
            self.sccp_digests,
            self.next_block_height,
            transaction,
        )
    }
    fn manifest_authority_eligible_lanes(
        &mut self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
    ) -> BTreeSet<LaneId> {
        crate::state::nexus_manifest_authority_eligible_lanes_at_height(
            lane_id,
            dataspace_id,
            self.nexus,
            self.next_block_height,
        )
    }
    fn recheck_external_nexus_fee_admission(
        &mut self,
        queue: &Queue,
        tx: &AcceptedTransaction<'static>,
        route_dataspace_id: Option<DataSpaceId>,
    ) -> Result<Option<FeeAdmissionReservation>, Error> {
        queue.recheck_external_nexus_fee_admission(
            tx,
            self.world,
            self.nexus,
            self.pipeline,
            self.next_block_height,
            route_dataspace_id,
        )
    }
    fn extract_lane_identity_metadata(
        &mut self,
        authority: &AccountId,
        dataspace_id: DataSpaceId,
        lane_alias: &str,
    ) -> Result<(Option<UniversalAccountId>, Vec<String>), Error> {
        Queue::extract_lane_identity_metadata(self.world, authority, dataspace_id, lane_alias)
    }
    fn extract_lane_authority_domains(
        &mut self,
        authority: &AccountId,
        lane_alias: &str,
    ) -> Result<Vec<iroha_model_base::domain::DomainId>, Error> {
        Queue::extract_lane_authority_domains(
            self.world,
            authority,
            lane_alias,
            self.ledger_time_ms,
        )
    }
}
impl Queue {
    /// Return the configured retained-byte budget for the queue.
    pub fn max_retained_bytes(&self) -> NonZeroU64 {
        self.max_retained_bytes
    }

    /// Checks if the transaction is waiting longer than its TTL or than the TTL from [`Config`].
    pub fn is_expired(&self, tx: &AcceptedTransaction<'static>) -> bool {
        self.is_expired_at(tx, self.time_source.get_unix_time())
    }

    fn push_queued_hash(&self, hash: EntrypointHash, enqueued_at_ms: u64) -> bool {
        let mut age_ring = self.queued_age_ring.lock();
        if self.tx_hashes.push(hash).is_err() {
            return false;
        }
        self.record_queued_age_locked(&mut age_ring, hash, enqueued_at_ms);
        true
    }
    fn remove_pending_hash_locked(
        &self,
        hash: EntrypointHash,
        telemetry: Option<&StateTelemetry>,
    ) -> Option<QueuedTransaction> {
        let removed = self.txs.remove(&hash).map(|(_, tx)| tx);
        if removed.is_some() {
            self.advance_pending_ownership_generation(hash);
        }
        self.remove_pending_sccp_exempt_locked(hash);
        self.fee_admission_reservations.lock().release(&hash);
        self.routing_plans.remove(&hash);
        #[cfg(all(test, sumeragi_core_mutation = "HC137"))]
        if removed.is_some()
            && let Some(len) = self.tx_encoded_len.get(&hash)
        {
            self.resident_accounting
                .get()
                .expect("original resident owner")
                .retained_bytes
                .fetch_sub(Self::retained_byte_cost(*len), Ordering::Relaxed);
        }
        self.remove_tx_encoded_len(&hash);
        self.tx_gas_cost.remove(&hash);
        self.tx_enqueued_at_ms.remove(&hash);
        self.remove_queued_age(&hash);
        self.untrack_expiry_hash(&hash);
        if let Some(tx) = removed.as_ref() {
            self.untrack_active_transaction();
            if let Some(authority) = tx.as_ref().as_ref().authority_opt() {
                self.decrease_per_user_tx_count(authority);
            }
            #[cfg(feature = "telemetry")]
            self.record_teu_dequeue(&hash, telemetry);
        }
        removed
    }
    /// Inspect the bounded native pending-input window in component integration tests.
    /// This retains queue ownership exactly as the production lane driver does.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn bounded_pending_snapshot_for_testing(
        self: &Arc<Self>,
        state_view: &StateView<'_>,
        max_scan: NonZeroUsize,
    ) -> Option<Vec<AcceptedTransaction<'static>>> {
        self.bounded_pending_snapshot(state_view, max_scan)
    }

    /// Remove exact inputs after a test has published their genuinely certified block.
    /// The caller must authenticate and apply that original block before cleanup.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn remove_committed_hashes_for_testing(
        &self,
        hashes: impl IntoIterator<Item = EntrypointHash>,
    ) -> usize {
        self.remove_committed_hashes(hashes, None)
    }

    /// Retire exact transaction identities after the authenticated G block is applied.
    pub(crate) fn remove_committed_hashes(
        &self,
        hashes: impl IntoIterator<Item = EntrypointHash>,
        telemetry: Option<&StateTelemetry>,
    ) -> usize {
        self.with_resident_refunds(
            || {
                let mut removed = 0;
                for hash in hashes {
                    removed +=
                        usize::from(self.remove_pending_hash_locked(hash, telemetry).is_some());
                }
                if removed > 0 {
                    self.compact_hash_queue_locked();
                }
                removed
            },
            |removed| {
                self.publish_backpressure_state(self.active_len(), telemetry);
                removed
            },
        )
    }
    /// Clear local pending inputs and gossip when this node stops accepting work.
    pub fn clear_all(&self) {
        self.with_resident_refunds(
            || {
                let hashes = self.txs.iter().map(|row| *row.key()).collect::<Vec<_>>();
                for hash in hashes {
                    self.remove_pending_hash_locked(hash, None);
                }
                self.compact_hash_queue_locked();
                while self.tx_gossip.pop().is_some() {}
            },
            |()| self.publish_backpressure_state(self.active_len(), None),
        )
    }

    /// Admit an ordered batch, reporting the first failure after publishing its accepted prefix.
    pub fn push_batch_with_lane_with_state_and_routing_plans(
        &self,
        txs: Vec<(AcceptedTransaction<'static>, RoutingPlan)>,
        state: &State,
    ) -> Result<usize, Failure> {
        let _lifecycle = state.lock_lane_lifecycle_work_admission();
        let view = state.view();
        self.sync_nexus_routing_with_view(&view);
        let mut accepted = 0;
        for (tx, plan) in txs {
            let plan = self
                .resolve_precomputed_routing_plan_with_view(&tx, &view, plan)
                .map_err(|error| Failure {
                    tx: tx.clone().into(),
                    err: error.into(),
                })?;
            self.admit_in_view(tx, plan, &view, None)?;
            accepted += 1;
        }
        Ok(accepted)
    }
    /// Number of locally pending signed inputs.
    pub fn active_len(&self) -> usize {
        self.resident_accounting
            .get()
            .map_or(0, |ledger| ledger.active_count.load(Ordering::Relaxed))
    }
    /// Whether local admission must wait for recovery of its original index owner.
    pub fn admission_faulted(&self) -> bool {
        self.accepted_work_validation_fault.load(Ordering::Acquire)
            || self.emergency_fast_startup.load(Ordering::Acquire)
    }
    /// Whether accepted transaction metadata failed exact identity validation.
    pub fn accepted_work_validation_faulted(&self) -> bool {
        self.accepted_work_validation_fault.load(Ordering::Acquire)
    }
    fn mark_accepted_work_validation_fault(
        &self,
        hash: EntrypointHash,
        stage: &str,
        reason: &(impl std::fmt::Display + ?Sized),
        telemetry: Option<&StateTelemetry>,
    ) {
        self.accepted_work_validation_fault
            .store(true, Ordering::Release);
        iroha_logger::error!(tx = %hash, stage, reason = %reason, "queue admission identity is inconsistent");
        self.publish_backpressure_state(self.active_len(), telemetry);
    }
    fn pending_status(
        &self,
        tx: &CheckedTransaction<'static>,
        state_view: &StateView<'_>,
    ) -> Result<bool, String> {
        Ok(!tx.is_in_blockchain(state_view) && !self.is_expired(tx.as_accepted()))
    }

    /// The signed transaction whose SCCP exemption admission classifies: the transaction of an
    /// external or sealed-reveal entry point (`specs/sccp.md` §4.19).
    fn sccp_signed_transaction(entrypoint: &TransactionEntrypoint) -> Option<&SignedTransaction> {
        match entrypoint {
            TransactionEntrypoint::External(transaction) => Some(transaction),
            TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction()),
            TransactionEntrypoint::SealedCommitment(_) => None,
        }
    }

    /// Release the SCCP exemption claim of a transaction leaving the queue while holding
    /// `push_remove_lock`. Releasing a transaction without a claim is a no-op.
    fn remove_pending_sccp_exempt_locked(&self, hash: EntrypointHash) {
        self.pending_sccp_exempt.lock().release(&hash);
    }

    /// Map a refused SCCP pending claim onto the queue's admission errors: a transaction that
    /// adds nothing new is a duplicate, and a held pending limit is an admission refusal.
    fn sccp_pending_claim_error(error: SccpPendingClaimErrorV1) -> Error {
        match error {
            SccpPendingClaimErrorV1::EntrypointClaimed | SccpPendingClaimErrorV1::NothingNew => {
                Error::IsInQueue
            }
            SccpPendingClaimErrorV1::ExclusiveHeld { .. } => Error::NexusFeeAdmissionRejected {
                code: FeeRejectionCode::OperationNotAllowed,
                reason: format!("SCCP exempt admission rejected: {error}"),
            },
        }
    }

    fn collect_lane_privacy_proofs(tx: &CheckedTransaction<'_>) -> Vec<LanePrivacyProof> {
        tx.external()
            .into_iter()
            .flat_map(|signed| signed.attachments().into_iter())
            .into_iter()
            .flat_map(|list| list.as_slice().iter())
            .filter_map(|attachment| attachment.lane_privacy.clone())
            .collect()
    }
    fn publishes_only_space_directory_manifests(tx: &CheckedTransaction<'_>) -> bool {
        let Some(signed) = tx.external() else {
            return false;
        };
        let is_publish = |instruction: &InstructionBox| {
            instruction
                .as_any()
                .downcast_ref::<
                    iroha_data_model::isi::space_directory::PublishSpaceDirectoryManifest,
                >()
                .is_some()
        };
        match signed.instructions() {
            Executable::Instructions(instructions) if !instructions.is_empty() => {
                instructions.iter().all(is_publish)
            }
            Executable::Batch(items) if !items.is_empty() => items.iter().all(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => is_publish(instruction),
                ExecutableBatchItem::ContractCall(_) => false,
            }),
            _ => false,
        }
    }
    fn compute_tx_encoded_len(tx: &AcceptedTransaction<'_>) -> usize {
        tx.entrypoint_bytes().len()
    }
    fn retained_byte_cost(encoded_len: usize) -> u64 {
        u64::try_from(encoded_len)
            .unwrap_or(u64::MAX)
            .saturating_mul(TX_RETAINED_DECODE_EXPANSION_FACTOR)
            .saturating_add(TX_RETAINED_OVERHEAD_BYTES)
    }
    /// Return the minimum retained-byte estimate charged for `count` incoming transactions.
    ///
    /// This excludes canonical transaction bytes because Torii may not have decoded the
    /// payloads yet; it is intended for early admission shedding before expensive work.
    pub fn retained_byte_cost_floor_for_transactions(count: usize) -> u64 {
        u64::try_from(count)
            .unwrap_or(u64::MAX)
            .saturating_mul(TX_RETAINED_OVERHEAD_BYTES)
    }
    fn insert_tx_encoded_len(&self, hash: EntrypointHash, encoded_len: usize) {
        self.tx_encoded_len.insert(hash, encoded_len);
    }
    fn remove_tx_encoded_len(&self, hash: &EntrypointHash) {
        self.tx_encoded_len.remove(hash);
    }
    fn encode_gossip_payload(tx: &AcceptedTransaction<'_>) -> Arc<Vec<u8>> {
        tx.entrypoint_bytes()
    }
    /// Quarantine an empty queue while startup authenticates its State.
    pub fn enter_emergency_fast_startup(&self) -> std::io::Result<()> {
        let _guard = self.push_remove_lock.lock();
        if self.active_len() != 0 {
            return Err(std::io::Error::other(
                "startup quarantine requires an empty queue",
            ));
        }
        self.emergency_fast_startup.store(true, Ordering::Release);
        Ok(())
    }
}
impl Queue {
    fn signed_executable_proposal_gas_cost(
        signed: &iroha_data_model::transaction::SignedTransaction,
    ) -> Result<u64, ProposalGasCostError> {
        let executable = signed.instructions();
        if executable.requires_transaction_gas_limit() {
            return iroha_data_model::transaction::require_transaction_gas_limit(
                signed.fee_payment_intent(),
            )
            .map_err(|_| ProposalGasCostError::MissingSignedGasLimit);
        }
        match executable {
            Executable::Instructions(batch) => Ok(gas::meter_instructions(batch.as_ref())),
            Executable::Batch(items) => {
                let instructions = items
                    .iter()
                    .filter_map(|item| match item {
                        ExecutableBatchItem::Instruction(instruction) => Some(instruction.clone()),
                        ExecutableBatchItem::ContractCall(_) => None,
                    })
                    .collect::<Vec<_>>();
                Ok(gas::meter_instructions(&instructions))
            }
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => {
                Err(ProposalGasCostError::MissingSignedGasLimit)
            }
        }
    }
    /// Derive the deterministic upper bound charged to proposal gas selection.
    ///
    /// External transactions and sealed reveals with runtime-dependent executables are charged
    /// their signature-bound gas limit. Native instruction executables use the deterministic
    /// instruction meter; sealed commitments use their encoded-size accounting.
    ///
    /// # Errors
    ///
    /// Returns an error when an accepted runtime-dependent executable has no signed gas limit or
    /// when gas accounting cannot derive a deterministic upper bound.
    pub(crate) fn compute_proposal_gas_cost(
        tx: &AcceptedTransaction<'_>,
    ) -> Result<u64, ProposalGasCostError> {
        match tx.entrypoint() {
            iroha_data_model::transaction::TransactionEntrypoint::External(signed) => {
                Self::signed_executable_proposal_gas_cost(signed)
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedCommitment(_) => {
                Ok(gas::meter_sealed_transaction_commitment(tx.encoded_len()))
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedReveal(reveal) => {
                Self::signed_executable_proposal_gas_cost(reveal.signed_transaction())
            }
        }
    }
    fn extract_lane_identity_metadata(
        world: &impl WorldReadOnly,
        authority: &AccountId,
        dataspace_id: DataSpaceId,
        lane_alias: &str,
    ) -> Result<(Option<UniversalAccountId>, Vec<String>), Error> {
        extract_directory_lane_identity_metadata(world, authority, dataspace_id).map_err(|err| {
            match err {
                LaneIdentityMetadataError::MissingDataspaceBinding { uaid, dataspace } => {
                    Error::LaneComplianceDenied {
                        alias: lane_alias.to_string(),
                        reason: format!(
                            "UAID {uaid} is not bound to dataspace {}",
                            dataspace.as_u64()
                        ),
                    }
                }
                LaneIdentityMetadataError::InactiveManifest { uaid, dataspace } => {
                    Error::LaneComplianceDenied {
                        alias: lane_alias.to_string(),
                        reason: format!(
                            "UAID {uaid} manifest for dataspace {} is not active",
                            dataspace.as_u64()
                        ),
                    }
                }
            }
        })
    }
    fn extract_lane_authority_domains(
        world: &impl WorldReadOnly,
        authority: &AccountId,
        lane_alias: &str,
        now_ms: u64,
    ) -> Result<Vec<iroha_model_base::domain::DomainId>, Error> {
        extract_directory_authority_domains(world, authority, now_ms).map_err(|err| {
            Error::LaneComplianceDenied {
                alias: lane_alias.to_string(),
                reason: format!("authority alias domain resolution failed: {err}"),
            }
        })
    }
    /// Install an arbitrary manifest snapshot into an isolated Queue fixture.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn install_lane_manifests_for_testing(&self, manifests: &LaneManifestRegistryHandle) {
        self.install_lane_manifests_unchecked_in_queue(manifests);
    }
    /// Install an empty Queue projection after entering emergency Fast quarantine.
    ///
    /// # Errors
    /// Refuses an ordinary or not-yet-quarantined Queue. This provisional
    /// projection cannot authorize transaction admission.
    pub fn install_provisional_empty_lane_manifests_for_emergency_fast_startup(
        &self,
    ) -> std::io::Result<()> {
        if !self.emergency_fast_startup.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "provisional Queue manifests require emergency Fast quarantine",
            ));
        }
        self.install_lane_manifests_unchecked_in_queue(&Arc::new(
            LaneManifestRegistry::provisional_empty_for_emergency_fast_startup(),
        ));
        Ok(())
    }
    fn install_lane_manifests_unchecked_in_queue(&self, manifests: &LaneManifestRegistryHandle) {
        let _ = self.replace_lane_manifests(manifests, false, None);
    }
    /// Install an arbitrary manifest snapshot into State and Queue test fixtures.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn install_lane_manifests_with_state_for_testing(
        &self,
        manifests: &LaneManifestRegistryHandle,
        state: &State,
    ) {
        state.install_lane_manifests_for_testing(manifests);
        self.install_lane_manifests_unchecked_in_queue(manifests);
    }
    /// Validate materialized startup authority and install this Queue projection
    /// while ingress is paused. Identical State authority keeps its original handles
    /// and generation; Queue receives the refreshed local diagnostics.
    ///
    /// # Errors
    /// Rejects a status-only, stale, or incomplete manifest before either
    /// registry is changed. The caller supplies the authenticated replay catalog.
    pub fn install_materialized_lane_manifests_with_state(
        &self,
        manifests: &LaneManifestRegistryHandle,
        state: &State,
        catalog: &LaneCatalog,
        governance: &GovernanceCatalog,
    ) -> Result<(), LaneLifecycleError> {
        state.install_materialized_lane_manifests_for_catalog(manifests, catalog, governance)?;
        self.install_lane_manifests_unchecked_in_queue(manifests);
        Ok(())
    }
    fn install_lane_manifests_if_consensus_compatible(
        &self,
        manifests: &LaneManifestRegistryHandle,
    ) -> bool {
        self.replace_lane_manifests(manifests, true, None)
    }
    fn install_lane_manifests_with_state_if_consensus_compatible(
        &self,
        manifests: &LaneManifestRegistryHandle,
        state: &State,
    ) -> bool {
        self.replace_lane_manifests(manifests, true, Some(state))
    }
    fn replace_lane_manifests(
        &self,
        manifests: &LaneManifestRegistryHandle,
        require_consensus_compatibility: bool,
        state: Option<&State>,
    ) -> bool {
        // Admission holds a read guard while checking manifest semantics. Keep
        // this write guard across State authority validation so no transaction
        // observes an unvalidated Queue policy.
        let mut guard = self.lane_manifests.write();
        if require_consensus_compatibility {
            let current_digest = guard.consensus_policy_digest();
            let candidate_digest = manifests.consensus_policy_digest();
            if current_digest != candidate_digest {
                iroha_logger::warn!(
                    current_digest = %hex::encode(current_digest),
                    candidate_digest = %hex::encode(candidate_digest),
                    "rejecting lane-manifest hot reload with consensus-semantic drift; coordinated restart/config rollout required"
                );
                return false;
            }
        }
        let previous_missing = guard.missing_aliases();
        if let Some(state) = state {
            assert!(
                require_consensus_compatibility,
                "State hot reload must authenticate the current manifest authority"
            );
            if !state.install_lane_manifests_if_consensus_compatible(manifests) {
                return false;
            }
        }
        *guard = Arc::clone(manifests);
        drop(guard);
        let current_missing = manifests.missing_aliases();
        for alias in current_missing.difference(&previous_missing) {
            iroha_logger::warn!(
                lane = alias,
                "governance manifest missing; lane is sealed until a manifest is installed"
            );
        }
        for alias in previous_missing.difference(&current_missing) {
            iroha_logger::info!(lane = alias, "governance manifest loaded");
        }
        let statuses_snapshot = manifests.statuses();
        status::update_lane_governance_from_statuses(&statuses_snapshot);
        let mut privacy_guard = self.lane_privacy_registry.write();
        *privacy_guard = Arc::new(LanePrivacyRegistry::from_statuses(&statuses_snapshot));
        true
    }
    /// Snapshot of lane privacy commitments derived from manifests.
    #[must_use]
    pub fn lane_privacy_registry(&self) -> LanePrivacyRegistryHandle {
        self.lane_privacy_registry.read().clone()
    }
    /// Reconstruct refreshed manifests from the static baseline and committed runtime additions.
    fn refreshed_lane_manifest_registry(
        &self,
        governance: &GovernanceCatalog,
        registry_cfg: &LaneRegistry,
        state: Option<&State>,
    ) -> Result<LaneManifestRegistryHandle, String> {
        if let Some(state) = state {
            let nexus = state.nexus_snapshot();
            let baseline = Arc::new(LaneManifestRegistry::from_config(
                &nexus.configured_lane_catalog,
                &nexus.governance,
                registry_cfg,
            ));
            state
                .lane_manifests_with_committed_catalog(&baseline, &nexus)
                .map_err(|error| error.to_string())
        } else {
            let lane_catalog = self.lane_catalog.read().clone();
            let source_snapshot = Arc::new(LaneManifestSourceSnapshot::load(registry_cfg));
            let registry = Arc::new(source_snapshot.bind(&lane_catalog, governance));
            registry
                .validate_active_coverage_for_catalog(&lane_catalog)
                .map_err(|error| error.to_string())?;
            Ok(registry)
        }
    }
    /// Refresh local manifest diagnostics on the configured schedule.
    ///
    /// Complete materialized State authority must remain unchanged; policy changes
    /// are rejected rather than installed by this watcher.
    pub async fn watch_lane_manifests_task(
        self: Arc<Self>,
        telemetry: Option<StateTelemetry>,
        governance: Arc<GovernanceCatalog>,
        registry_cfg: LaneRegistry,
        state: Option<Arc<State>>,
    ) {
        let initial = match self.refreshed_lane_manifest_registry(
            &governance,
            &registry_cfg,
            state.as_deref(),
        ) {
            Ok(registry) => registry,
            Err(err) => {
                iroha_logger::warn!(reason = %err, "refusing to install incomplete initial lane-manifest snapshot");
                return;
            }
        };
        let initial_applied = if let Some(state_handle) = state.as_ref() {
            self.install_lane_manifests_with_state_if_consensus_compatible(&initial, state_handle)
        } else {
            self.install_lane_manifests_if_consensus_compatible(&initial)
        };
        if initial_applied {
            if let Some(telemetry_handle) = telemetry.as_ref() {
                telemetry_handle.set_lane_manifest_registry(Arc::clone(&initial));
            }
        }
        if registry_cfg.poll_interval.is_zero() {
            return;
        }
        let mut ticker = interval(registry_cfg.poll_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let registry = match self.refreshed_lane_manifest_registry(
                &governance,
                &registry_cfg,
                state.as_deref(),
            ) {
                Ok(registry) => registry,
                Err(err) => {
                    iroha_logger::warn!(reason = %err, "refusing lane-manifest hot reload without exact active-lane coverage");
                    continue;
                }
            };
            let applied = if let Some(state_handle) = state.as_ref() {
                self.install_lane_manifests_with_state_if_consensus_compatible(
                    &registry,
                    state_handle,
                )
            } else {
                self.install_lane_manifests_if_consensus_compatible(&registry)
            };
            if !applied {
                continue;
            }
            if let Some(telemetry_handle) = telemetry.as_ref() {
                telemetry_handle.set_lane_manifest_registry(Arc::clone(&registry));
            }
        }
    }
    fn lane_manifest_admission_snapshot(
        &self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        authority_eligible_lanes: &BTreeSet<LaneId>,
    ) -> Result<
        (
            LaneManifestRegistryHandle,
            Option<LaneManifestStatus>,
            Option<GovernanceRules>,
        ),
        GovernanceGuardError,
    > {
        let guard = self.lane_manifests.read();
        guard.ensure_lane_ready(lane_id)?;
        let status = guard.status(lane_id).cloned();
        let authority_rules = guard
            .dataspace_authority_rules_for_lanes(lane_id, dataspace_id, authority_eligible_lanes)?
            .cloned();
        Ok((Arc::clone(&*guard), status, authority_rules))
    }
    fn enforcement_error(alias: &str, reason: impl Into<String>) -> Error {
        Error::GovernanceNotPermitted {
            alias: alias.to_string(),
            reason: reason.into(),
        }
    }
    fn enforce_manifest_quorum(
        alias: &str,
        rules: &GovernanceRules,
        tx: &CheckedTransaction<'_>,
    ) -> Result<(), Error> {
        if let Executable::Instructions(instructions) = tx.as_ref().as_ref().instructions()
            && instructions_allow_multisig_envelope_authority(instructions)
        {
            return Ok(());
        }
        let Some(quorum) = rules.quorum else {
            return Ok(());
        };
        if quorum <= 1 {
            return Ok(());
        }
        if rules.validators.is_empty() {
            return Ok(());
        }
        let approvals = Self::collect_manifest_approvals(alias, tx)?;
        let validators = Self::canonical_manifest_validators(alias, rules)?;
        let approved = approvals
            .iter()
            .filter(|account| validators.contains(*account))
            .count();
        let required = usize::try_from(quorum).unwrap_or(usize::MAX);
        if approved < required {
            return Err(Self::enforcement_error(
                alias,
                format!(
                    "lane manifest quorum requires {quorum} validator approvals but {approved} were provided"
                ),
            ));
        }
        Ok(())
    }
    fn tx_contains_runtime_upgrade_instruction(tx: &CheckedTransaction<'_>) -> bool {
        let contains = |instruction: &InstructionBox| {
            instruction
                .as_any()
                .downcast_ref::<ProposeRuntimeUpgrade>()
                .is_some()
                || instruction
                    .as_any()
                    .downcast_ref::<ActivateRuntimeUpgrade>()
                    .is_some()
                || instruction
                    .as_any()
                    .downcast_ref::<CancelRuntimeUpgrade>()
                    .is_some()
        };
        match tx.as_ref().as_ref().instructions() {
            Executable::Instructions(instructions) => instructions.iter().any(contains),
            Executable::Batch(items) => items.iter().any(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => contains(instruction),
                ExecutableBatchItem::ContractCall(_) => false,
            }),
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => false,
        }
    }
    fn tx_touches_manifest_protected_namespace_surface(tx: &CheckedTransaction<'_>) -> bool {
        let signed = tx.as_ref().as_ref();
        let metadata = signed.metadata();
        let has_governance_contract_address =
            metadata.get(&*GOV_CONTRACT_ADDRESS_METADATA_KEY).is_some();
        let has_contract_address_hint = metadata.get(&*CONTRACT_ADDRESS_METADATA_KEY).is_some();
        let mut contract_targets_seen = false;
        let mut register_code_seen = false;
        match signed.instructions() {
            Executable::Instructions(instructions) => {
                for instruction in instructions {
                    if instruction
                        .as_any()
                        .downcast_ref::<ActivateContractInstance>()
                        .is_some()
                        || instruction
                            .as_any()
                            .downcast_ref::<CommitContractDeployment>()
                            .is_some()
                        || instruction
                            .as_any()
                            .downcast_ref::<DeactivateContractInstance>()
                            .is_some()
                    {
                        contract_targets_seen = true;
                    } else {
                        let any = instruction.as_any();
                        if any.is::<RegisterSmartContractCode>()
                            || any.is::<RegisterSmartContractBytes>()
                            || any.is::<UploadSmartContractCodeChunk>()
                            || any.is::<FinalizeSmartContractCodeUpload>()
                            || any.is::<RemoveSmartContractBytes>()
                        {
                            register_code_seen = true;
                        }
                    }
                }
            }
            Executable::ContractCall(_) => {
                contract_targets_seen = true;
            }
            Executable::Batch(items) => {
                for item in items {
                    match item {
                        ExecutableBatchItem::ContractCall(_) => contract_targets_seen = true,
                        ExecutableBatchItem::Instruction(instruction) => {
                            if instruction
                                .as_any()
                                .downcast_ref::<ActivateContractInstance>()
                                .is_some()
                                || instruction
                                    .as_any()
                                    .downcast_ref::<CommitContractDeployment>()
                                    .is_some()
                                || instruction
                                    .as_any()
                                    .downcast_ref::<DeactivateContractInstance>()
                                    .is_some()
                            {
                                contract_targets_seen = true;
                            } else {
                                let any = instruction.as_any();
                                if any.is::<RegisterSmartContractCode>()
                                    || any.is::<RegisterSmartContractBytes>()
                                    || any.is::<UploadSmartContractCodeChunk>()
                                    || any.is::<FinalizeSmartContractCodeUpload>()
                                    || any.is::<RemoveSmartContractBytes>()
                                {
                                    register_code_seen = true;
                                }
                            }
                        }
                    }
                }
            }
            Executable::Ivm(_) | Executable::IvmProved(_) => {}
        }
        let ivm_with_contract_metadata = matches!(signed.instructions(), Executable::Ivm(_))
            && (has_governance_contract_address || has_contract_address_hint);
        register_code_seen || contract_targets_seen || ivm_with_contract_metadata
    }
    fn tx_requires_manifest_validator_gating(
        rules: &GovernanceRules,
        tx: &CheckedTransaction<'_>,
    ) -> bool {
        Self::tx_contains_runtime_upgrade_instruction(tx)
            || (!rules.protected_namespaces.is_empty()
                && Self::tx_touches_manifest_protected_namespace_surface(tx))
    }
    fn collect_manifest_approvals(
        alias: &str,
        tx: &CheckedTransaction<'_>,
    ) -> Result<BTreeSet<String>, Error> {
        let mut approvals = BTreeSet::new();
        if let Some(authority) = tx.as_ref().authority_opt() {
            let authority_i105 = authority.canonical_i105().map_err(|err| {
                Self::enforcement_error(
                    alias,
                    format!("failed to encode authority `{authority}` as i105: {err}"),
                )
            })?;
            approvals.insert(authority_i105);
        }
        let Some(metadata) = tx.as_ref().metadata() else {
            return Ok(approvals);
        };
        let Some(raw) = metadata.get(&*GOV_APPROVERS_METADATA_KEY) else {
            return Ok(approvals);
        };
        let entries = raw.try_into_any_norito::<Vec<String>>().map_err(|_| {
            Self::enforcement_error(
                alias,
                "`gov_manifest_approvers` metadata must be an array of account identifiers",
            )
        })?;
        for entry in entries {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                return Err(Self::enforcement_error(
                    alias,
                    "`gov_manifest_approvers` metadata entries must not be blank",
                ));
            }
            let canonical = AccountId::canonicalize(trimmed).map_err(|err| {
                Self::enforcement_error(
                    alias,
                    format!("invalid account id `{trimmed}` in `gov_manifest_approvers`: {err}"),
                )
            })?;
            if !approvals.insert(canonical) {
                return Err(Self::enforcement_error(
                    alias,
                    "`gov_manifest_approvers` metadata must not duplicate approvers",
                ));
            }
        }
        Ok(approvals)
    }
    fn canonical_manifest_validators(
        alias: &str,
        rules: &GovernanceRules,
    ) -> Result<BTreeSet<String>, Error> {
        let mut validators = BTreeSet::new();
        for validator in &rules.validators {
            let i105 = validator.canonical_i105().map_err(|err| {
                Self::enforcement_error(
                    alias,
                    format!("failed to encode validator `{validator}` as i105: {err}"),
                )
            })?;
            if !validators.insert(i105) {
                return Err(Self::enforcement_error(
                    alias,
                    "lane manifest validator set contains duplicate validators",
                ));
            }
        }
        Ok(validators)
    }
    #[allow(clippy::too_many_lines)]
    fn enforce_manifest_protected_namespaces(
        alias: &str,
        rules: &GovernanceRules,
        tx: &CheckedTransaction<'_>,
    ) -> Result<bool, Error> {
        if rules.protected_namespaces.is_empty() {
            return Ok(false);
        }
        let signed = tx.as_ref().as_ref();
        let metadata = signed.metadata();
        let metadata_governance_contract_address = metadata
            .get(&*GOV_CONTRACT_ADDRESS_METADATA_KEY)
            .map(|value| {
                let raw = value.try_into_any_norito::<String>().map_err(|_| {
                    Self::enforcement_error(
                        alias,
                        "`gov_contract_address` metadata must be a string value",
                    )
                })?;
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(Self::enforcement_error(
                        alias,
                        "`gov_contract_address` metadata must not be blank",
                    ));
                }
                trimmed
                    .parse::<iroha_data_model::smart_contract::ContractAddress>()
                    .map_err(|err| {
                    Self::enforcement_error(
                        alias,
                        format!(
                            "`gov_contract_address` metadata `{trimmed}` is not a valid ContractAddress: {err}"
                        ),
                    )
                })
            })
            .transpose()?;
        let metadata_contract_address_hint = metadata
            .get(&*CONTRACT_ADDRESS_METADATA_KEY)
            .map(|value| {
                let raw = value.try_into_any_norito::<String>().map_err(|_| {
                    Self::enforcement_error(
                        alias,
                        "`contract_address` metadata must be a string value",
                    )
                })?;
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(Self::enforcement_error(
                        alias,
                        "`contract_address` metadata must not be blank",
                    ));
                }
                trimmed
                    .parse::<iroha_data_model::smart_contract::ContractAddress>()
                    .map_err(|err| {
                        Self::enforcement_error(
                            alias,
                            format!(
                                "`contract_address` metadata `{trimmed}` is not a valid ContractAddress: {err}"
                            ),
                        )
                    })
            })
            .transpose()?;
        let mut contract_targets = BTreeSet::new();
        let mut register_code_seen = false;
        let mut commit_deployment_count = 0_usize;
        let mut activate_seen = false;
        let mut deactivate_seen = false;
        match signed.instructions() {
            Executable::Instructions(instructions) => {
                for instruction in instructions {
                    if let Some(commit) = instruction
                        .as_any()
                        .downcast_ref::<CommitContractDeployment>()
                    {
                        commit_deployment_count += 1;
                        contract_targets.insert(commit.contract_address().clone());
                    } else if let Some(activate) = instruction
                        .as_any()
                        .downcast_ref::<ActivateContractInstance>()
                    {
                        activate_seen = true;
                        contract_targets.insert(activate.contract_address().clone());
                    } else if let Some(deactivate) = instruction
                        .as_any()
                        .downcast_ref::<DeactivateContractInstance>()
                    {
                        deactivate_seen = true;
                        contract_targets.insert(deactivate.contract_address().clone());
                    } else {
                        let modifies_contract_code = {
                            let any = instruction.as_any();
                            any.is::<RegisterSmartContractCode>()
                                || any.is::<RegisterSmartContractBytes>()
                                || any.is::<UploadSmartContractCodeChunk>()
                                || any.is::<FinalizeSmartContractCodeUpload>()
                                || any.is::<RemoveSmartContractBytes>()
                        };
                        if modifies_contract_code {
                            register_code_seen = true;
                        }
                    }
                }
            }
            Executable::ContractCall(call) => {
                contract_targets.insert(call.contract_address.clone());
            }
            Executable::Batch(items) => {
                for item in items {
                    match item {
                        ExecutableBatchItem::ContractCall(call) => {
                            contract_targets.insert(call.contract_address.clone());
                        }
                        ExecutableBatchItem::Instruction(instruction) => {
                            if let Some(commit) = instruction
                                .as_any()
                                .downcast_ref::<CommitContractDeployment>()
                            {
                                commit_deployment_count += 1;
                                contract_targets.insert(commit.contract_address().clone());
                            } else if let Some(activate) = instruction
                                .as_any()
                                .downcast_ref::<ActivateContractInstance>(
                            ) {
                                activate_seen = true;
                                contract_targets.insert(activate.contract_address().clone());
                            } else if let Some(deactivate) = instruction
                                .as_any()
                                .downcast_ref::<DeactivateContractInstance>(
                            ) {
                                deactivate_seen = true;
                                contract_targets.insert(deactivate.contract_address().clone());
                            } else {
                                let any = instruction.as_any();
                                if any.is::<RegisterSmartContractCode>()
                                    || any.is::<RegisterSmartContractBytes>()
                                    || any.is::<UploadSmartContractCodeChunk>()
                                    || any.is::<FinalizeSmartContractCodeUpload>()
                                    || any.is::<RemoveSmartContractBytes>()
                                {
                                    register_code_seen = true;
                                }
                            }
                        }
                    }
                }
            }
            Executable::Ivm(_) | Executable::IvmProved(_) => {}
        }
        if commit_deployment_count > 1
            || (commit_deployment_count == 1 && (activate_seen || deactivate_seen))
            || (activate_seen && deactivate_seen)
        {
            return Err(Self::enforcement_error(
                alias,
                "protected contract rotations must use exactly one `CommitContractDeployment` instruction and no legacy activate/deactivate pair",
            ));
        }
        if let Some(contract_address) = metadata_governance_contract_address.clone() {
            contract_targets.insert(contract_address);
        }
        let ivm_with_contract_metadata = matches!(signed.instructions(), Executable::Ivm(_))
            && (metadata_governance_contract_address.is_some()
                || metadata_contract_address_hint.is_some());
        let contract_instr_seen =
            register_code_seen || !contract_targets.is_empty() || ivm_with_contract_metadata;
        let explicit_contract_instruction_seen =
            register_code_seen || commit_deployment_count > 0 || activate_seen || deactivate_seen;
        let has_directly_addressed_call = match signed.instructions() {
            Executable::ContractCall(_) => true,
            Executable::Batch(items) => items
                .iter()
                .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_))),
            Executable::Instructions(_) | Executable::Ivm(_) | Executable::IvmProved(_) => false,
        };
        if !contract_instr_seen {
            return Ok(false);
        }
        if contract_instr_seen
            && metadata_governance_contract_address.is_none()
            && (!has_directly_addressed_call || explicit_contract_instruction_seen)
        {
            return Err(Self::enforcement_error(
                alias,
                "transactions with contract operations must set `gov_contract_address` metadata when lane governance protects namespaces",
            ));
        }
        if let (Some(hint), Some(meta)) = (
            metadata_contract_address_hint.as_ref(),
            metadata_governance_contract_address.as_ref(),
        ) && hint != meta
        {
            return Err(Self::enforcement_error(
                alias,
                "`contract_address` metadata must match `gov_contract_address` for protected operations",
            ));
        }
        if let Some(meta_contract_address) = metadata_governance_contract_address.as_ref()
            && !contract_targets.is_empty()
            && contract_targets
                .iter()
                .any(|contract_address| contract_address != meta_contract_address)
        {
            return Err(Self::enforcement_error(
                alias,
                "`gov_contract_address` metadata does not match contract addresses referenced by contract instructions",
            ));
        }
        Ok(true)
    }
    fn enforce_runtime_upgrade_hook(
        alias: &str,
        rules: &GovernanceRules,
        tx: &CheckedTransaction<'_>,
    ) -> Result<bool, Error> {
        let signed = tx.as_ref().as_ref();
        if !Self::tx_contains_runtime_upgrade_instruction(tx) {
            return Ok(false);
        }
        let Some(hook) = rules.hooks.runtime_upgrade.as_ref() else {
            return Ok(false);
        };
        if !hook.allow {
            return Err(Self::enforcement_error(
                alias,
                "runtime upgrade hook prohibits runtime upgrade instructions".to_string(),
            ));
        }
        if hook.require_metadata || hook.allowed_ids.is_some() {
            let Some(key) = hook.metadata_key.as_ref() else {
                return Err(Self::enforcement_error(
                    alias,
                    "runtime upgrade hook missing metadata_key despite requiring metadata"
                        .to_string(),
                ));
            };
            let metadata = signed.metadata();
            let Some(raw_value) = metadata.get(key) else {
                return Err(Self::enforcement_error(
                    alias,
                    format!("runtime upgrade hook requires metadata `{}`", key.as_ref()),
                ));
            };
            let value = raw_value.try_into_any_norito::<String>().map_err(|_| {
                Self::enforcement_error(
                    alias,
                    format!(
                        "runtime upgrade metadata `{}` must be a string",
                        key.as_ref()
                    ),
                )
            })?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(Self::enforcement_error(
                    alias,
                    format!(
                        "runtime upgrade metadata `{}` must not be blank",
                        key.as_ref()
                    ),
                ));
            }
            if let Some(ids) = hook.allowed_ids.as_ref()
                && !ids.contains(trimmed)
            {
                return Err(Self::enforcement_error(
                    alias,
                    format!(
                        "runtime upgrade metadata `{}` value `{trimmed}` not permitted by lane manifest",
                        key.as_ref()
                    ),
                ));
            }
        }
        Ok(true)
    }
    /// Makes queue from configuration
    pub fn from_config(config: Config, events_sender: EventsSender) -> Self {
        let lane_catalog = Arc::new(LaneCatalog::default());
        let dataspace_catalog = Arc::new(DataSpaceCatalog::default());
        let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
            LaneRoutingPolicy::default(),
            dataspace_catalog.as_ref().clone(),
            lane_catalog.as_ref().clone(),
        ));
        Self::from_config_with_router_limits_and_catalogs(
            config,
            events_sender,
            router,
            QueueLimits::default(),
            &lane_catalog,
            &dataspace_catalog,
            None,
        )
    }
    /// Build the queue using the provided router implementation.
    pub fn from_config_with_router(
        Config {
            capacity,
            capacity_per_user,
            max_retained_bytes,
            transaction_time_to_live,
            expired_cull_interval,
            expired_cull_batch,
        }: Config,
        events_sender: EventsSender,
        router: Arc<dyn LaneRouter>,
    ) -> Self {
        let lane_catalog = Arc::new(LaneCatalog::default());
        let dataspace_catalog = Arc::new(DataSpaceCatalog::default());
        Self::from_config_with_router_limits_and_catalogs(
            Config {
                capacity,
                capacity_per_user,
                max_retained_bytes,
                transaction_time_to_live,
                expired_cull_interval,
                expired_cull_batch,
            },
            events_sender,
            router,
            QueueLimits::default(),
            &lane_catalog,
            &dataspace_catalog,
            None,
        )
    }
    /// Build the queue using the provided router and explicit Nexus-derived limits.
    pub fn from_config_with_router_and_limits(
        Config {
            capacity,
            capacity_per_user,
            max_retained_bytes,
            transaction_time_to_live,
            expired_cull_interval,
            expired_cull_batch,
        }: Config,
        events_sender: EventsSender,
        router: Arc<dyn LaneRouter>,
        limits: QueueLimits,
        lane_compliance: Option<Arc<LaneComplianceEngine>>,
    ) -> Self {
        let lane_catalog = Arc::new(LaneCatalog::default());
        let dataspace_catalog = Arc::new(DataSpaceCatalog::default());
        Self::from_config_with_router_limits_and_catalogs(
            Config {
                capacity,
                capacity_per_user,
                max_retained_bytes,
                transaction_time_to_live,
                expired_cull_interval,
                expired_cull_batch,
            },
            events_sender,
            router,
            limits,
            &lane_catalog,
            &dataspace_catalog,
            lane_compliance,
        )
    }
    /// Build the queue using the provided router, limits, and Nexus catalogs.
    pub fn from_config_with_router_limits_and_catalogs(
        Config {
            capacity,
            capacity_per_user,
            max_retained_bytes,
            transaction_time_to_live,
            expired_cull_interval,
            expired_cull_batch,
        }: Config,
        events_sender: EventsSender,
        router: Arc<dyn LaneRouter>,
        limits: QueueLimits,
        lane_catalog: &Arc<LaneCatalog>,
        dataspace_catalog: &Arc<DataSpaceCatalog>,
        lane_compliance: Option<Arc<LaneComplianceEngine>>,
    ) -> Self {
        let (backpressure_tx, _) = watch::channel(BackpressureState::Healthy {
            queued: 0,
            capacity,
        });
        let lane_manifests = Arc::new(
            LaneManifestRegistry::empty()
                .rebind(lane_catalog.as_ref(), &GovernanceCatalog::default()),
        );
        let lane_privacy_registry = Arc::new(LanePrivacyRegistry::from_manifest_registry(
            lane_manifests.as_ref(),
        ));
        let queue = {
            let queue = Self {
                events_sender,
                router: RwLock::new(router),
                lane_compliance: RwLock::new(lane_compliance),
                lane_catalog: RwLock::new(Arc::clone(lane_catalog)),
                dataspace_catalog: RwLock::new(Arc::clone(dataspace_catalog)),
                routing_policy: RwLock::new(LaneRoutingPolicy::default()),
                tx_hashes: ArrayQueue::new(capacity.get()),
                txs: DashMap::new(),
                pending_sccp_exempt: parking_lot::Mutex::new(SccpPendingIndexV1::default()),
                txs_per_user: DashMap::new(),
                routing_plans: DashMap::new(),
                tx_encoded_len: DashMap::new(),
                tx_gas_cost: DashMap::new(),
                tx_enqueued_at_ms: DashMap::new(),
                queued_tx_enqueued_at_ms: DashMap::new(),
                queued_age_ring: parking_lot::Mutex::new(VecDeque::new()),
                pending_scan_cursor: parking_lot::Mutex::new(BoundedPendingScanCursor::default()),
                fee_admission_reservations: parking_lot::Mutex::new(
                    FeeAdmissionReservationStore::default(),
                ),
                accepted_work_validation_fault: AtomicBool::new(false),
                emergency_fast_startup: AtomicBool::new(false),
                push_remove_lock: PublicationMutex::default(),
                pending_ownership_generation: AtomicU64::new(0),
                nexus_revalidation_lock: parking_lot::Mutex::new(()),
                #[cfg(test)]
                pending_hash_state_view_handoff: parking_lot::Mutex::new(None),
                capacity,
                capacity_per_user,
                max_retained_bytes,
                resident_accounting: OnceLock::new(),
                #[cfg(test)]
                retained_bytes_before_admission: AtomicU64::new(0),
                time_source: TimeSource::new_system(),
                tx_time_to_live: transaction_time_to_live,
                expired_cull_interval,
                expired_cull_batch,
                last_expired_cull_ms: AtomicU64::new(0),
                expiry_ring: parking_lot::Mutex::new(VecDeque::new()),
                expiry_ring_members: DashMap::new(),
                tx_gossip: ArrayQueue::new(capacity.get()),
                backpressure_tx,
                pressure_age_budget_ms: AtomicU64::new(Self::default_pressure_age_budget_ms()),
                sumeragi_wake: parking_lot::Mutex::new(None),
                sumeragi_start_ticket: AtomicU64::new(0),
                #[cfg(test)]
                empty_native_payloads: AtomicUsize::new(0),
                #[cfg(test)]
                empty_lane_payloads: AtomicUsize::new(0),
                nexus_limits: RwLock::new(limits),
                #[cfg(feature = "telemetry")]
                tx_teu: DashMap::new(),
                #[cfg(feature = "telemetry")]
                lane_teu_pending: DashMap::new(),
                #[cfg(feature = "telemetry")]
                dataspace_teu_pending: DashMap::new(),
                lane_manifests: parking_lot::RwLock::new(lane_manifests),
                lane_privacy_registry: parking_lot::RwLock::new(lane_privacy_registry),
                #[cfg(test)]
                vacant_entry_warnings: AtomicUsize::new(0),
            };
            #[cfg(feature = "telemetry")]
            {
                for lane in lane_catalog.lanes() {
                    queue.lane_teu_pending.entry(lane.id).or_default();
                    for dataspace in dataspace_catalog.entries() {
                        queue
                            .dataspace_teu_pending
                            .entry((lane.id, dataspace.id))
                            .or_default();
                    }
                }
            }
            queue
        };
        #[cfg(not(feature = "telemetry"))]
        let _ = limits;
        #[cfg(not(feature = "telemetry"))]
        {
            let _ = lane_catalog;
            let _ = dataspace_catalog;
        }
        queue.publish_backpressure_state(0, None);
        queue
    }
    /// Reserve one native startup before any executor attachment or driver launch.
    /// A Queue has one successful native owner for its lifetime; ordinary restart uses a
    /// fresh Queue and the existing authenticated State/journal recovery. Retiring wake
    /// delivery never releases that exclusion while physical workers may still be joining.
    pub(crate) fn reserve_sumeragi_start(
        self: &Arc<Self>,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<SumeragiQueueReservation, &'static str> {
        let (ticket, retired) = self.with_resident_refunds(
            || {
                // One critical section excludes every earlier native reservation/owner,
                // including terminal retirement, before touching another startup owner.
                let mut binding = self.sumeragi_wake.lock();
                #[cfg(not(all(test, sumeragi_core_mutation = "HC191")))]
                if binding.is_some() {
                    return Err("transaction queue already has an original native owner; restart with a fresh Queue");
                }
                #[cfg(not(all(test, sumeragi_core_mutation = "HC193")))]
                if self.resident_accounting.get().is_some_and(|ledger| !ledger.belongs_to(budget)) {
                    return Err("transaction queue resident custody belongs to a different original State pool");
                }
                let ticket = self.sumeragi_start_ticket
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| previous.checked_add(1))
                    .map_err(|_| "transaction queue startup identity is exhausted")?;
                Ok((ticket, binding.replace(SumeragiQueueWake::Reserved { ticket, budget: budget.clone() })))
            },
            |completed| completed,
        )?;
        // Only the deliberate HC191 mutant can replace an earlier owner. Even there,
        // original charged wake/input references retire after both guards have released.
        drop(retired);
        Ok(SumeragiQueueReservation {
            queue: Arc::downgrade(self),
            ticket,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_sumeragi_wake(&self, wake: mpsc::SyncSender<()>) {
        let retired = self
            .sumeragi_wake
            .lock()
            .replace(SumeragiQueueWake::Probe(wake));
        drop(retired);
    }

    /// Check the original startup/active pool without retaining its driver or lane owners.
    pub(crate) fn belongs_to_sumeragi_pool(
        &self,
        original: &iroha_allocation::AllocationBudget,
    ) -> bool {
        let binding = self.sumeragi_wake.lock();
        match binding.as_ref() {
            Some(SumeragiQueueWake::Reserved { budget, .. })
            | Some(SumeragiQueueWake::Node { budget, .. }) => budget.same_pool(original),
            Some(SumeragiQueueWake::Retired { .. }) | None => false,
            #[cfg(test)]
            Some(SumeragiQueueWake::Probe(_)) => true,
        }
    }

    /// A durable certified lane frame makes new merge work available only to the root.
    /// Preserve Queue retirement and drop the original charged notification owner outside
    /// the binding lock. No lane-map walk or lane-build feedback is needed for this edge.
    pub(crate) fn wake_sumeragi_root(&self, original: &iroha_allocation::AllocationBudget) {
        let root = {
            let binding = self.sumeragi_wake.lock();
            match binding.as_ref() {
                Some(SumeragiQueueWake::Node { budget, root, .. })
                    if budget.same_pool(original) =>
                {
                    Some(root.clone())
                }
                #[cfg(test)]
                Some(SumeragiQueueWake::Probe(sender)) => {
                    let _ = sender.try_send(());
                    None
                }
                _ => None,
            }
        };
        if let Some(root) = root {
            root.notify();
        }
    }

    pub(crate) fn wake_sumeragi(&self) {
        // No queue lock survives a driver notification or a last charged-reference drop.
        let wake = self.sumeragi_wake.lock().clone();
        if let Some(wake) = wake {
            wake.notify();
        }
    }

    #[cfg(test)]
    pub(crate) fn record_empty_native_payload(&self) {
        self.empty_native_payloads.fetch_add(1, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn record_empty_lane_payload(&self) {
        self.empty_lane_payloads.fetch_add(1, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn empty_payload_answers_for_test(&self) -> (usize, usize) {
        (
            self.empty_native_payloads.load(Ordering::Acquire),
            self.empty_lane_payloads.load(Ordering::Acquire),
        )
    }
    /// Checks if the transaction is expired at a specific time.
    fn is_expired_at(&self, tx: &AcceptedTransaction<'static>, now: Duration) -> bool {
        let enqueue_timestamp_ms =
            if matches!(tx.entrypoint(), TransactionEntrypoint::SealedCommitment(_)) {
                self.tx_enqueued_at_ms
                    .get(&tx.hash_as_entrypoint())
                    .map(|entry| *entry.value())
            } else {
                None
            };
        self.is_expired_at_with_enqueue_timestamp(tx, now, enqueue_timestamp_ms)
    }
    /// Check expiry against an explicitly bound queue-admission timestamp.
    ///
    /// Queue-plan replay uses the authenticated journal timestamp because a sealed commitment's
    /// in-memory timestamp is deliberately not published until the complete replay applies.
    fn is_expired_at_with_enqueue_timestamp(
        &self,
        tx: &AcceptedTransaction<'_>,
        now: Duration,
        enqueue_timestamp_ms: Option<u64>,
    ) -> bool {
        if matches!(tx.entrypoint(), TransactionEntrypoint::SealedCommitment(_)) {
            // Sealed commitments have no signed wall-clock creation timestamp. Bound their local
            // queue residence from the admission timestamp instead; reveal-height validation
            // remains the consensus rule after inclusion, but cannot reclaim a commitment that
            // never reaches a block.
            let Some(enqueued_at_ms) = enqueue_timestamp_ms else {
                // A transaction being checked before admission has no queue residence yet.
                return false;
            };
            let now_ms = Self::duration_to_millis(now);
            return now_ms.saturating_sub(enqueued_at_ms)
                > Self::duration_to_millis(self.tx_time_to_live);
        }
        let tx_creation_time = tx.creation_time();
        let time_limit = self.effective_tx_time_to_live(tx);
        now.saturating_sub(tx_creation_time) > time_limit
    }
    fn effective_tx_time_to_live(&self, tx: &AcceptedTransaction<'_>) -> Duration {
        tx.time_to_live().map_or_else(
            || self.tx_time_to_live,
            |tx_time_to_live| core::cmp::min(self.tx_time_to_live, tx_time_to_live),
        )
    }
    fn nexus_fee_admission_observation_time_ms(&self, tx: &AcceptedTransaction<'_>) -> u64 {
        let deadline = tx
            .creation_time()
            .saturating_add(self.effective_tx_time_to_live(tx));
        Self::duration_to_millis(deadline)
    }
    fn map_nexus_fee_admission_error(
        err: crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
    ) -> Error {
        let err = match err {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                return Error::Deferred(reason);
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(err) => err,
        };
        match err {
            NexusFeeAdmissionError::Rejected { code, reason } => {
                Error::NexusFeeAdmissionRejected { code, reason }
            }
            NexusFeeAdmissionError::ConfigInvalid(reason) => {
                Error::NexusFeeAdmissionConfigInvalid {
                    code: FeeRejectionCode::InvalidProgramConfiguration,
                    reason,
                }
            }
        }
    }
    fn recheck_external_nexus_fee_admission(
        &self,
        tx: &AcceptedTransaction<'static>,
        world: &impl WorldReadOnly,
        nexus: &Nexus,
        pipeline: &Pipeline,
        next_block_height: u64,
        route_dataspace_id: Option<DataSpaceId>,
    ) -> Result<Option<FeeAdmissionReservation>, Error> {
        let Some(transaction) = tx.external() else {
            return Ok(None);
        };
        let observation_time_ms = self.nexus_fee_admission_observation_time_ms(tx);
        let quote = quote_external_nexus_fee_admission(
            world,
            nexus,
            pipeline,
            transaction,
            observation_time_ms,
            next_block_height,
            route_dataspace_id,
        )
        .map_err(Self::map_nexus_fee_admission_error)?;
        quote
            .map(|quote| {
                Self::fee_admission_reservation_from_quote(
                    world,
                    transaction.authority(),
                    next_block_height,
                    quote,
                )
            })
            .transpose()
    }
    fn fee_admission_reservation_from_quote(
        world: &impl WorldReadOnly,
        beneficiary: &AccountId,
        next_block_height: u64,
        quote: FeeAdmissionQuote,
    ) -> Result<FeeAdmissionReservation, Error> {
        let FeeAdmissionQuote {
            charges,
            debit_source,
            program_revision,
            relay_leases,
            capacities,
            authority_balances,
            authority_charge_assets,
        } = quote;
        if let FeeDebitSource::Account(account) = &debit_source {
            if account != beneficiary {
                return Err(Error::NexusFeeAdmissionConfigInvalid {
                    code: FeeRejectionCode::InvalidProgramConfiguration,
                    reason: format!(
                        "authority fee quote selected `{account}` for beneficiary `{beneficiary}`"
                    ),
                });
            }
            let mut asset_charges = BTreeMap::new();
            let mut asset_remaining = BTreeMap::new();
            for charge in charges {
                let asset_id = authority_charge_assets.get(&charge.kind).ok_or_else(|| {
                    Error::NexusFeeAdmissionConfigInvalid {
                        code: FeeRejectionCode::InvalidProgramConfiguration,
                        reason: format!(
                            "authority fee quote omitted the exact {:?} balance bucket",
                            charge.kind
                        ),
                    }
                })?;
                let source = FeeReservationAssetSource::Authority(asset_id.clone());
                let current = asset_charges
                    .get(&source)
                    .cloned()
                    .unwrap_or_else(Quantity::zero);
                asset_charges.insert(
                    source.clone(),
                    FeeAdmissionReservationStore::checked_add(
                        &current,
                        &charge.max_bound,
                        "per-authority-asset charge",
                    )?,
                );
                let available = authority_balances.get(asset_id).cloned().ok_or_else(|| {
                    Error::NexusFeeAdmissionConfigInvalid {
                        code: FeeRejectionCode::InvalidProgramConfiguration,
                        reason: format!(
                            "authority fee quote omitted observed balance for `{asset_id}`"
                        ),
                    }
                })?;
                asset_remaining.insert(source, available);
            }
            return Ok(FeeAdmissionReservation {
                program_revision: None,
                beneficiary: beneficiary.clone(),
                asset_charges,
                window_charges: BTreeMap::new(),
                relay_lease_charges: BTreeMap::new(),
                asset_remaining,
                window_remaining: BTreeMap::new(),
                relay_lease_remaining: BTreeMap::new(),
            });
        }
        let FeeDebitSource::SponsorProgram(program_id) = &debit_source else {
            unreachable!("fee debit source has only account and sponsor-program variants")
        };
        let program_revision =
            program_revision.ok_or_else(|| Error::NexusFeeAdmissionConfigInvalid {
                code: FeeRejectionCode::InvalidProgramConfiguration,
                reason: format!(
                    "sponsor program `{program_id}` quote omitted its immutable revision"
                ),
            })?;
        let revision = world
            .fee_sponsor_program_revisions()
            .get(&FeeSponsorProgramRevisionKey::new(
                program_id.clone(),
                program_revision,
            ))
            .ok_or_else(|| Error::NexusFeeAdmissionConfigInvalid {
                code: FeeRejectionCode::InvalidProgramConfiguration,
                reason: format!(
                    "sponsor program `{program_id}` revision {program_revision} disappeared while preparing its queue reservation"
                ),
            })?;
        let sponsor_charges = sponsored_charge_totals(&charges)?;
        let mut asset_charges = BTreeMap::new();
        let mut asset_remaining = BTreeMap::new();
        let mut window_charges = BTreeMap::new();
        let mut window_remaining = BTreeMap::new();
        for (asset_definition_id, amount) in &sponsor_charges {
            let capacity = capacities.get(asset_definition_id).ok_or_else(|| {
                Error::NexusFeeAdmissionConfigInvalid {
                    code: FeeRejectionCode::InvalidProgramConfiguration,
                    reason: format!(
                        "sponsor program `{program_id}` quote omitted capacity for `{asset_definition_id}`"
                    ),
                }
            })?;
            let available_vault = capacity
                .vault_balance
                .checked_sub(&capacity.reserve_floor)
                .unwrap_or_else(|_| Quantity::zero());
            let source = FeeReservationAssetSource::SponsorProgram {
                program_id: program_id.clone(),
                asset_definition_id: asset_definition_id.clone(),
            };
            asset_charges.insert(source.clone(), amount.clone());
            asset_remaining.insert(source, available_vault);
            let budget = revision
                .asset_budgets
                .iter()
                .find(|budget| budget.asset_definition_id == *asset_definition_id)
                .ok_or_else(|| Error::NexusFeeAdmissionConfigInvalid {
                    code: FeeRejectionCode::InvalidProgramConfiguration,
                    reason: format!(
                        "sponsor program `{program_id}` revision {program_revision} has no budget for `{asset_definition_id}`"
                    ),
                })?;
            let epoch = next_block_height.saturating_sub(1) / budget.epoch_length_blocks.get();
            let windows = [
                (
                    FeeSponsorBudgetWindow::Block(FeeSponsorBlockBudgetWindow {
                        height: next_block_height,
                    }),
                    capacity.block_remaining.clone(),
                ),
                (
                    FeeSponsorBudgetWindow::ProgramEpoch(FeeSponsorProgramEpochBudgetWindow {
                        epoch,
                    }),
                    capacity.program_epoch_remaining.clone(),
                ),
                (
                    FeeSponsorBudgetWindow::BeneficiaryEpoch(
                        FeeSponsorBeneficiaryEpochBudgetWindow {
                            epoch,
                            beneficiary: beneficiary.clone(),
                        },
                    ),
                    capacity.beneficiary_epoch_remaining.clone(),
                ),
            ];
            for (window, remaining) in windows {
                let key = FeeSponsorBudgetCounterKey {
                    program_id: program_id.clone(),
                    asset_definition_id: asset_definition_id.clone(),
                    window,
                };
                window_charges.insert(key.clone(), amount.clone());
                window_remaining.insert(key, remaining);
            }
        }
        let (relay_lease_charges, relay_lease_remaining) =
            relay_lease_reservation_maps(program_id, &sponsor_charges, relay_leases)?;
        Ok(FeeAdmissionReservation {
            program_revision: Some(program_revision),
            beneficiary: beneficiary.clone(),
            asset_charges,
            window_charges,
            relay_lease_charges,
            asset_remaining,
            window_remaining,
            relay_lease_remaining,
        })
    }
    /// Returns all pending transactions.
    pub fn all_transactions<'state>(
        &'state self,
        state_view: &'state StateView,
    ) -> impl Iterator<Item = AcceptedTransaction<'static>> + 'state {
        // Release every DashMap shard guard before consulting the durability-transition index.
        // A terminal transition keeps its per-hash marker live while removing the transaction;
        // taking the locks in the opposite order here could otherwise make enumeration wait on
        // that marker while the remover waits for this iterator's shard read guard.
        let tracked = self
            .txs
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        let mut pending = Vec::new();
        let mut pending_status_fault = None;
        for tx in tracked {
            let tx_ref = tx.as_ref();
            match self.pending_status(tx_ref, state_view) {
                Ok(true) => {
                    // Deep-clone underlying transaction to preserve queue semantics.
                    pending.push(tx_ref.as_accepted().clone());
                }
                Ok(false) => {}
                Err(reason) => {
                    pending_status_fault.get_or_insert((tx_ref.hash_as_entrypoint(), reason));
                }
            }
        }
        if let Some((hash, reason)) = pending_status_fault {
            self.mark_accepted_work_validation_fault(
                hash,
                "global_candidate_expiry_registry",
                &reason,
                None,
            );
        }
        pending.into_iter()
    }
    /// Clone a finite FIFO window without transferring or reserving queue ownership.
    /// Lane commits leave these signed inputs resident until G applies them.
    pub(crate) fn bounded_pending_snapshot(
        self: &Arc<Self>,
        state_view: &StateView<'_>,
        max_scan: NonZeroUsize,
    ) -> Option<Vec<AcceptedTransaction<'static>>> {
        let _ = self.cull_expired_entries_if_due();
        if self.admission_faulted() {
            return None;
        }
        let queue_guard = self.push_remove_lock.lock();
        if self.admission_faulted() {
            return None;
        }
        let mut age_ring = self.queued_age_ring.lock();
        let mut cursor = self.pending_scan_cursor.lock();
        let mut remaining = max_scan.get();
        while remaining > 0
            && let Some((hash, enqueued_at)) = age_ring.front().copied()
        {
            if self
                .queued_tx_enqueued_at_ms
                .get(&hash)
                .is_some_and(|row| *row == enqueued_at)
                && self.txs.contains_key(&hash)
            {
                break;
            }
            age_ring.pop_front();
            cursor.next_index = 0;
            remaining -= 1;
        }
        if cursor.next_index >= age_ring.len() {
            cursor.next_index = 0;
        }
        let start = cursor.next_index;
        let mut seen = HashSet::with_capacity(remaining.min(age_ring.len().saturating_sub(start)));
        let mut sccp_budget = SccpExemptBlockBudgetV1::new(state_view.world());
        let pending = age_ring
            .iter()
            .skip(start)
            .take(remaining)
            .filter_map(|(hash, enqueued_at)| {
                if !seen.insert(*hash)
                    || !self
                        .queued_tx_enqueued_at_ms
                        .get(hash)
                        .is_some_and(|row| *row == *enqueued_at)
                {
                    return None;
                }
                let tx = self.txs.get(hash)?;
                if tx.is_in_blockchain(state_view) || self.is_expired(tx.as_accepted()) {
                    return None;
                }
                // Eligibility is judged against the committed parent World, exactly as block
                // validation counts it (`specs/sccp.md` §4.19).
                sccp_budget
                    .admit(
                        crate::smartcontracts::isi::sccp::admission::exempt_class_of_entrypoint(
                            state_view.world(),
                            tx.as_accepted().entrypoint(),
                        ),
                    )
                    .then(|| tx.value().clone())
            })
            .collect::<Vec<_>>();
        cursor.next_index = start.saturating_add(remaining).min(age_ring.len());
        let more = cursor.next_index < age_ring.len();
        drop(cursor);
        drop(age_ring);
        drop(queue_guard);
        if more {
            self.wake_sumeragi();
        }
        Some(
            pending
                .into_iter()
                .map(|tx| tx.as_accepted().clone())
                .collect(),
        )
    }
    /// Returns `n` transactions in a batch for gossiping
    pub fn gossip_batch(&self, n: u32, state_view: &StateView) -> Vec<GossipBatchEntry> {
        if self.admission_faulted() {
            return Vec::new();
        }
        #[cfg(feature = "telemetry")]
        let backpressure_telemetry: Option<&StateTelemetry> = Some(state_view.telemetry);
        #[cfg(not(feature = "telemetry"))]
        let backpressure_telemetry: Option<&StateTelemetry> = None;
        self.gossip_batch_inner(
            n,
            |_, tx_ref| {
                if self.is_expired(tx_ref.as_accepted()) {
                    GossipEntryState::Other
                } else if tx_ref.is_in_blockchain(state_view) {
                    GossipEntryState::Committed
                } else {
                    GossipEntryState::Pending
                }
            },
            |hash, tx_ref| self.immutable_queued_routing_plan_with_view(hash, tx_ref, state_view),
            backpressure_telemetry,
        )
    }
    /// Gossip from one applied State and exact locally pending identity.
    pub fn gossip_batch_with_state(&self, n: u32, state: &State) -> Vec<GossipBatchEntry> {
        let _lifecycle = state.lock_lane_lifecycle_work_admission();
        let view = state.view();
        self.gossip_batch(n, &view)
    }
    fn gossip_batch_inner<F, R>(
        &self,
        n: u32,
        mut entry_state: F,
        mut resolve_immutable_routing: R,
        backpressure_telemetry: Option<&StateTelemetry>,
    ) -> Vec<GossipBatchEntry>
    where
        F: FnMut(EntrypointHash, &CheckedTransaction<'static>) -> GossipEntryState,
        R: FnMut(
            EntrypointHash,
            &CheckedTransaction<'static>,
        ) -> Result<Option<RoutingPlan>, RoutingResolveError>,
    {
        let mut batch = Vec::with_capacity(n as usize);
        let mut remaining_scan = self.tx_gossip.len();
        while remaining_scan > 0 && batch.len() < n as usize {
            remaining_scan -= 1;
            let Some(hash) = self.tx_gossip.pop() else {
                break;
            };
            let Some(tx_arc) = self.txs.get(&hash).map(|entry| entry.value().clone()) else {
                // NOTE: Transaction already in the blockchain
                continue;
            };
            let tx_ref = tx_arc.as_ref();
            match entry_state(hash, tx_ref) {
                GossipEntryState::Pending => {
                    let routing_plan = match resolve_immutable_routing(hash, tx_ref) {
                        Ok(Some(routing_plan)) => routing_plan,
                        Ok(None) => {
                            if let Err(requeue_hash) = self.tx_gossip.push(hash) {
                                warn!(
                                    tx = %requeue_hash,
                                    "failed to restore transitioning queued transaction to gossip backlog"
                                );
                            }
                            continue;
                        }
                        Err(
                            RoutingResolveError::OrdinaryRouteUnavailable { .. }
                            | RoutingResolveError::Deferred(_),
                        ) => {
                            if let Err(requeue_hash) = self.tx_gossip.push(hash) {
                                warn!(
                                    tx = %requeue_hash,
                                    "failed to restore temporarily unroutable Ordinary input to gossip backlog"
                                );
                            }
                            continue;
                        }
                        Err(err) => {
                            iroha_logger::error!(
                                tx = %hash,
                                reason = %err,
                                reason_label = err.as_label(),
                                "queued transaction failed immutable routing validation before gossip"
                            );
                            if let Err(requeue_hash) = self.tx_gossip.push(hash) {
                                warn!(
                                    tx = %requeue_hash,
                                    "failed to restore immutable queued transaction to gossip backlog"
                                );
                            }
                            self.mark_accepted_work_validation_fault(
                                hash,
                                "gossip_routing",
                                &err,
                                backpressure_telemetry,
                            );
                            break;
                        }
                    };
                    let routing = routing_plan.coordinator_route();
                    let payload = Self::encode_gossip_payload(tx_ref.as_accepted());
                    batch.push(GossipBatchEntry {
                        tx: tx_ref.as_accepted().clone(),
                        routing,
                        routing_plan,
                        payload,
                    });
                    if batch.len() >= n as usize {
                        break;
                    }
                }
                GossipEntryState::Committed => {
                    drop(tx_arc);
                    self.remove_committed_hashes([hash], backpressure_telemetry);
                }
                GossipEntryState::Other => {}
            }
        }
        batch
    }
    fn resolve_view_routing_plan(
        plan: RoutingPlan,
        state_view: &StateView<'_>,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        let nexus = state_view.nexus();
        resolve_routing_plan_for_queue_admission(
            plan,
            nexus,
            state_view_height_for_routing(state_view),
        )
    }
    fn resolve_precomputed_routing_plan_with_view(
        &self,
        tx: &AcceptedTransaction<'_>,
        state_view: &StateView<'_>,
        plan: RoutingPlan,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        let block_height = state_view_height_for_routing(state_view);
        let plan =
            resolve_routing_plan_for_queue_admission(plan, state_view.nexus(), block_height)?;
        let current_plan = self
            .router
            .read()
            .try_route_plan_with_view(tx, state_view)
            .and_then(|plan| {
                resolve_routing_plan_for_queue_admission(plan, state_view.nexus(), block_height)
            })?;
        if current_plan == plan {
            Ok(plan)
        } else {
            Err(RoutingResolveError::StaleRoutingPlan)
        }
    }
    fn sync_nexus_routing_with_state(&self, state: &State) -> Nexus {
        let nexus = state.nexus_snapshot();
        self.reconfigure_nexus_with_state_if_needed(&nexus, state, self.lane_compliance_engine());
        nexus
    }
    fn sync_nexus_routing_with_view(&self, state_view: &StateView<'_>) {
        let nexus = state_view.nexus();
        if !self.nexus_routing_matches(nexus) {
            self.reconfigure_nexus(nexus, state_view, self.lane_compliance_engine());
        }
    }
    /// Resolve a full routing plan for an inbound gossip transaction with the current state.
    pub(crate) fn route_plan_for_gossip_with_state(
        &self,
        tx: &AcceptedTransaction<'_>,
        state: &State,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        self.route_plan_with_state(tx, state)
    }
    fn immutable_queued_routing_plan_in_view(
        &self,
        hash: EntrypointHash,
        tx: &CheckedTransaction<'static>,
        view: &StateView<'_>,
        nexus: &Nexus,
        height: u64,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        let tracked = self
            .txs
            .get(&hash)
            .ok_or(RoutingResolveError::StaleRoutingPlan)?;
        if tx.hash_as_entrypoint() != hash
            || tracked.as_accepted().entrypoint() != tx.as_accepted().entrypoint()
            || crate::tx::exact_signed_transaction_hash(tracked.as_accepted().entrypoint())
                != crate::tx::exact_signed_transaction_hash(tx.as_accepted().entrypoint())
        {
            return Err(RoutingResolveError::StaleRoutingPlan);
        }
        drop(tracked);
        if !self.routing_plans.contains_key(&hash) {
            return Err(RoutingResolveError::StaleRoutingPlan);
        }
        let fresh = self
            .router
            .read()
            .try_route_plan_with_view(tx.as_accepted(), view)
            .and_then(|plan| resolve_routing_plan_for_queue_admission(plan, nexus, height))
            .map_err(|error| match error {
                RoutingResolveError::Deferred(_) => error,
                error => RoutingResolveError::OrdinaryRouteUnavailable {
                    reason: error.to_string(),
                },
            })?;
        validate_current_admission_route(&fresh).map_err(|error| {
            RoutingResolveError::OrdinaryRouteUnavailable {
                reason: error.to_string(),
            }
        })?;
        Ok(fresh)
    }
    fn immutable_queued_routing_plan_if_available_in_view(
        &self,
        hash: EntrypointHash,
        tx: &CheckedTransaction<'static>,
        view: &StateView<'_>,
        nexus: &Nexus,
        height: u64,
    ) -> Result<Option<RoutingPlan>, RoutingResolveError> {
        let _guard = self.push_remove_lock.lock();
        if !self.txs.contains_key(&hash) {
            return Ok(None);
        }
        self.immutable_queued_routing_plan_in_view(hash, tx, view, nexus, height)
            .map(Some)
    }
    fn immutable_queued_routing_plan_with_view(
        &self,
        hash: EntrypointHash,
        tx: &CheckedTransaction<'static>,
        view: &StateView<'_>,
    ) -> Result<Option<RoutingPlan>, RoutingResolveError> {
        self.immutable_queued_routing_plan_if_available_in_view(
            hash,
            tx,
            view,
            view.nexus(),
            state_view_height_for_routing(view),
        )
    }
    /// Local cached routing hint; execution always derives routing from committed State.
    pub fn routing_plan_hint(&self, hash: &EntrypointHash) -> Option<RoutingPlan> {
        self.routing_plans.get(hash).map(|plan| plan.clone())
    }
    /// Resolve routing for an admitted transaction against the current state.
    ///
    /// This is used by Torii ingress proxying to compute the authoritative lane
    /// before deciding whether the request can be executed locally.
    pub fn route_with_state(
        &self,
        tx: &AcceptedTransaction<'_>,
        state: &State,
    ) -> Result<RoutingDecision, RoutingResolveError> {
        self.route_plan_with_state(tx, state)
            .map(|plan| plan.coordinator_route())
    }
    /// Resolve the full routing plan for an admitted transaction against the current state.
    ///
    /// This is used by Torii, gossip, and block proposal paths to preserve native AMX
    /// participant legs alongside the coordinator route.
    pub fn route_plan_with_state(
        &self,
        tx: &AcceptedTransaction<'_>,
        state: &State,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        let _lifecycle_guard = state.lock_lane_lifecycle_work_admission();
        let _ = self.sync_nexus_routing_with_state(state);
        let state_view = state.view();
        self.sync_nexus_routing_with_view(&state_view);
        let hash = tx.hash_as_entrypoint();
        if let Some(tracked) = self.txs.get(&hash).map(|entry| entry.value().clone()) {
            let exact_owner = tracked.as_accepted().entrypoint() == tx.entrypoint()
                && tracked.as_accepted().hash_as_entrypoint() == tx.hash_as_entrypoint()
                && crate::tx::exact_signed_transaction_hash(tracked.as_accepted().entrypoint())
                    == crate::tx::exact_signed_transaction_hash(tx.entrypoint());
            if !exact_owner {
                return Err(RoutingResolveError::StaleRoutingPlan);
            }
            let result = self.immutable_queued_routing_plan_if_available_in_view(
                hash,
                tracked.as_ref(),
                &state_view,
                state_view.nexus(),
                state_view_height_for_routing(&state_view),
            );
            let result = match result {
                Ok(Some(plan)) => Ok(plan),
                Ok(None) => return Err(RoutingResolveError::StaleRoutingPlan),
                Err(error) => Err(error),
            };
            if let Err(error) = result.as_ref()
                && !matches!(
                    error,
                    RoutingResolveError::OrdinaryRouteUnavailable { .. }
                        | RoutingResolveError::Deferred(_)
                )
            {
                self.mark_accepted_work_validation_fault(hash, "queued_route_lookup", error, None);
            }
            if self.admission_faulted() {
                return Err(RoutingResolveError::StaleRoutingPlan);
            }
            return result;
        }
        let plan = {
            let router = self.router.read();
            match router.try_route_plan_without_state(tx)? {
                Some(plan) => plan,
                None => router.try_route_plan_with_view(tx, &state_view)?,
            }
        };
        resolve_routing_plan_for_queue_admission(
            plan,
            state_view.nexus(),
            state_view_height_for_routing(&state_view),
        )
    }
    /// Resolve the complete routing plan for an exact unsigned payload.
    ///
    /// Native AMX participant legs are retained alongside the coordinator route.
    pub fn route_payload_plan_with_state(
        &self,
        payload: &TransactionPayload,
        state: &State,
    ) -> Result<RoutingPlan, RoutingResolveError> {
        let _lifecycle_guard = state.lock_lane_lifecycle_work_admission();
        let nexus = self.sync_nexus_routing_with_state(state);
        let plan = self
            .router
            .read()
            .try_route_plan_with_state(payload, state)?;
        resolve_routing_plan_for_queue_admission(plan, &nexus, state_height_for_routing(state))
    }
    /// Returns whether the queue currently tracks the entrypoint hash.
    ///
    /// This is used by gossip fast paths to skip expensive re-validation for
    /// entries that are already known locally.
    pub(crate) fn contains_entrypoint_hash(&self, hash: EntrypointHash) -> bool {
        self.txs.contains_key(&hash)
    }
    /// Whether the exact input remains locally pending at this applied State.
    pub fn contains_pending_hash(&self, hash: EntrypointHash, state: &State) -> bool {
        #[cfg(test)]
        if let Some(reached) = self.pending_hash_state_view_handoff.lock().take() {
            let _ = reached.try_send(());
        }
        let view = state.view();
        let _guard = self.push_remove_lock.lock();
        self.txs
            .get(&hash)
            .is_some_and(|tx| !tx.is_in_blockchain(&view) && !self.is_expired(tx.as_accepted()))
    }
    /// Whether the byte-identical input still has healthy local pending custody.
    ///
    /// Ingress authenticates the caller and current route before using this observation to
    /// acknowledge a retry. It promises no persistence across restart or global execution.
    pub fn contains_exact_pending_input(
        &self,
        transaction: &AcceptedTransaction<'_>,
        state: &State,
    ) -> bool {
        let view = state.view();
        let _guard = self.push_remove_lock.lock();
        !self.admission_faulted()
            && self
                .txs
                .get(&transaction.hash_as_entrypoint())
                .is_some_and(|tracked| {
                    tracked.as_accepted().entrypoint_bytes() == transaction.entrypoint_bytes()
                        && !tracked.is_in_blockchain(&view)
                        && !self.is_expired(tracked.as_accepted())
                })
    }
    /// Return transactions back to the gossip backlog by their hashes.
    pub fn requeue_gossip_hashes(&self, hashes: impl IntoIterator<Item = EntrypointHash>) {
        for hash in hashes {
            if !self.txs.contains_key(&hash) {
                continue;
            }
            if let Err(err_hash) = self.tx_gossip.push(hash) {
                warn!(
                    tx = %err_hash,
                    "Gossiper is lagging behind, not able to requeue tx for gossiping"
                );
                break;
            }
        }
    }
    fn check_startup_admission(&self) -> Result<(), Error> {
        if self.admission_faulted() {
            return Err(Error::AdmissionInvariant {
                reason: "queue admission requires restart recovery".to_owned(),
            });
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC194")))]
        if matches!(
            self.sumeragi_wake.lock().as_ref(),
            Some(SumeragiQueueWake::Retired { .. })
        ) {
            return Err(Error::AdmissionInvariant {
                reason: "transaction queue native owner has retired; restart with a fresh Queue"
                    .to_owned(),
            });
        }
        Ok(())
    }
    fn push_with_lane_internal(
        &self,
        tx: AcceptedTransaction<'static>,
        state_view: &StateView<'_>,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<RoutingDecision, Failure> {
        self.check_startup_admission().map_err(|err| Failure {
            tx: tx.clone().into(),
            err,
        })?;
        self.sync_nexus_routing_with_view(state_view);
        let plan = self
            .router
            .read()
            .try_route_plan_with_view(&tx, state_view)
            .and_then(|plan| Self::resolve_view_routing_plan(plan, state_view))
            .map_err(|error| Failure {
                tx: tx.clone().into(),
                err: error.into(),
            })?;
        self.admit_in_view(tx, plan, state_view, gossip_payload)
    }
    fn push_with_lane_internal_with_state(
        &self,
        tx: AcceptedTransaction<'static>,
        state: &State,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<RoutingDecision, Failure> {
        self.push_with_lane_internal_with_state_and_routing(tx, state, None, gossip_payload)
    }
    fn push_with_lane_internal_with_state_and_routing(
        &self,
        tx: AcceptedTransaction<'static>,
        state: &State,
        routing_plan: Option<RoutingPlan>,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<RoutingDecision, Failure> {
        let _lifecycle = state.lock_lane_lifecycle_work_admission();
        let view = state.view();
        self.check_startup_admission().map_err(|err| Failure {
            tx: tx.clone().into(),
            err,
        })?;
        self.sync_nexus_routing_with_view(&view);
        let plan = match routing_plan {
            Some(plan) => self.resolve_precomputed_routing_plan_with_view(&tx, &view, plan),
            None => self
                .router
                .read()
                .try_route_plan_with_view(&tx, &view)
                .and_then(|plan| Self::resolve_view_routing_plan(plan, &view)),
        }
        .map_err(|error| Failure {
            tx: tx.clone().into(),
            err: error.into(),
        })?;
        self.admit_in_view(tx, plan, &view, gossip_payload)
    }
    fn admit_in_view(
        &self,
        tx: AcceptedTransaction<'static>,
        routing_plan: RoutingPlan,
        view: &StateView<'_>,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<RoutingDecision, Failure> {
        // Preacceptance belongs to the original signed security domain. It cannot
        // authorize another State's queue, fee reservations, indexes or gossip.
        let actual = match tx.entrypoint() {
            TransactionEntrypoint::External(signed) => *signed.domain(),
            TransactionEntrypoint::SealedCommitment(commitment) => {
                TransactionDomain::Network(commitment.payload().network_id)
            }
            TransactionEntrypoint::SealedReveal(reveal) => *reveal.signed_transaction().domain(),
        };
        let expected = TransactionDomain::Network(*view.network_id());
        if actual != expected && !cfg!(all(test, sumeragi_core_mutation = "HC22")) {
            return Err(Failure {
                tx: Box::new(tx),
                err: Error::TransactionDomainMismatch(Mismatch { expected, actual }),
            });
        }
        let checked = tx.into_checked(view).map_err(|(tx, _)| Failure {
            tx: tx.into(),
            err: Error::InBlockchain,
        })?;
        if self.is_expired(checked.as_accepted()) {
            return Err(Failure {
                tx: checked.into_accepted().into(),
                err: Error::Expired,
            });
        }
        let route = routing_plan.coordinator_route();
        let height = state_view_height_for_routing(view)
            .checked_add(1)
            .ok_or_else(|| Failure {
                tx: checked.as_accepted().clone().into(),
                err: Error::UnresolvedRoute {
                    reason: "admission height overflows".to_owned(),
                },
            })?;
        let mut access = EagerAdmissionStateAccess::new(
            view.world(),
            &view.nexus,
            &view.pipeline,
            view,
            height,
            view.query_ledger_time_ms(),
        );
        let prepared = self.prepare_checked_for_enqueue(
            checked,
            routing_plan,
            &mut access,
            gossip_payload,
            #[cfg(feature = "telemetry")]
            view.telemetry,
        )?;
        #[cfg(feature = "telemetry")]
        let telemetry = Some(view.telemetry);
        #[cfg(not(feature = "telemetry"))]
        let telemetry = None;
        match self.enqueue_prepared_admissions(vec![prepared], telemetry, &view.execution_budget())
        {
            Ok(notifications) => {
                self.publish_admission_notifications(&notifications);
                Ok(route)
            }
            Err((notifications, error)) => {
                self.publish_admission_notifications(&notifications);
                Err(error)
            }
        }
    }
    fn prepare_checked_for_enqueue<C: QueueAdmissionStateAccess>(
        &self,
        checked: CheckedTransaction<'static>,
        routing_plan: RoutingPlan,
        state_access: &mut C,
        _gossip_payload: Option<Arc<Vec<u8>>>,
        #[cfg(feature = "telemetry")] telemetry_handle: &StateTelemetry,
    ) -> Result<PreparedQueueAdmission, Failure> {
        validate_current_admission_route(&routing_plan).map_err(|err| Failure {
            tx: checked.as_accepted().clone().into(),
            err,
        })?;
        // A transaction larger than the selection budget of every proposer on its route would
        // only wait for its expiry. The bound comes from committed parameters and the committed
        // route, so every node decides alike; an unfinished local read defers the assessment.
        if let Err(refusal) = state_access.check_includable_transaction(checked.as_accepted()) {
            use crate::execution_attempt::ExecutionAttemptError;
            return Err(Failure {
                tx: checked.as_accepted().clone().into(),
                err: match refusal {
                    ExecutionAttemptError::Rejected(never_includable) => {
                        Error::UnsupportedTransactionAdmission {
                            reason: never_includable.to_string(),
                        }
                    }
                    ExecutionAttemptError::Deferred(reason) => Error::Deferred(reason),
                },
            });
        }
        // Reclaim bounded stale work and reject cheap saturation/duplication cases before fee,
        // manifest, privacy-proof, compliance, and gas analysis.
        let _ = self.cull_expired_entries_if_due();
        let hash = checked.hash_as_entrypoint();
        let encoded_len = Self::compute_tx_encoded_len(checked.as_accepted());
        let retained_cost = Self::retained_byte_cost(encoded_len);
        let cheap_error = if self.admission_faulted() {
            Some(Error::AdmissionInvariant {
                reason: "queue admission is unavailable".to_owned(),
            })
        } else if self.txs.contains_key(&hash) {
            Some(Error::IsInQueue)
        } else if self.active_len() >= self.capacity.get()
            || self.retained_bytes().saturating_add(retained_cost) > self.max_retained_bytes.get()
        {
            Some(Error::Full)
        } else {
            checked.as_ref().authority_opt().and_then(|authority| {
                self.txs_per_user
                    .get(authority)
                    .is_some_and(|count| *count >= self.capacity_per_user.get())
                    .then_some(Error::MaximumTransactionsPerUser)
            })
        };
        if let Some(err) = cheap_error {
            return Err(Failure {
                tx: checked.as_accepted().clone().into(),
                err,
            });
        }
        let routing_decision = routing_plan.coordinator_route();
        if let Some(transaction) = checked.as_accepted().external() {
            let authority = transaction.authority();
            if !state_access.authority_exists(authority)
                && !allows_unregistered_authority(transaction.instructions(), authority)
            {
                return Err(Failure {
                    tx: Box::new(checked.as_accepted().clone()),
                    err: Error::UnregisteredAuthority {
                        authority: authority.clone(),
                    },
                });
            }
        }
        // SCCP exemption checks use this exact committed view; there is no inherited queue authority.
        // A transaction that is not eligible for an SCCP exemption classifies as `None` and
        // pays the ordinary fee below; only an eligible transaction that fails pre-verification
        // is rejected here (`specs/sccp.md` §4.19).
        let sccp_exempt = Self::sccp_signed_transaction(checked.as_accepted().entrypoint())
            .map(|transaction| state_access.sccp_exempt_admission(transaction))
            .transpose()
            .map_err(|reject| Failure {
                tx: checked.as_accepted().clone().into(),
                err: Error::NexusFeeAdmissionRejected {
                    code: FeeRejectionCode::OperationNotAllowed,
                    reason: reject.to_string(),
                },
            })?
            .flatten();
        let lane_id = routing_decision.lane_id;
        let dataspace_id = routing_decision.dataspace_id;
        let fee_reservation = if checked.as_accepted().external().is_some() {
            match state_access.recheck_external_nexus_fee_admission(
                self,
                checked.as_accepted(),
                Some(dataspace_id),
            ) {
                Ok(reservation) => reservation,
                Err(err) => {
                    return Err(Failure {
                        tx: Box::new(checked.as_accepted().clone()),
                        err,
                    });
                }
            }
        } else {
            None
        };
        #[cfg(feature = "telemetry")]
        let mut manifest_allowed = false;
        let manifest_authority_eligible_lanes =
            state_access.manifest_authority_eligible_lanes(lane_id, dataspace_id);
        if !manifest_authority_eligible_lanes.contains(&lane_id) {
            let alias = self
                .lane_catalog
                .read()
                .lanes()
                .iter()
                .find(|lane| lane.id == lane_id)
                .map_or_else(
                    || format!("lane-{}", lane_id.as_u32()),
                    |lane| lane.alias.clone(),
                );
            return Err(Failure {
                tx: Box::new(checked.as_accepted().clone()),
                err: Self::enforcement_error(
                    &alias,
                    "lane is not active in the routed dataspace at the next block height",
                ),
            });
        }
        let (manifest_snapshot, manifest_status, manifest_authority_rules) = match self
            .lane_manifest_admission_snapshot(
                lane_id,
                dataspace_id,
                &manifest_authority_eligible_lanes,
            ) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                let reason = err.message();
                iroha_logger::warn!(
                    lane = %lane_id.as_u32(),
                    reason,
                    "rejecting transaction while governance manifest authority is unavailable"
                );
                #[cfg(feature = "telemetry")]
                telemetry_handle.record_manifest_admission("missing_manifest");
                return Err(Failure {
                    tx: Box::new(checked.as_accepted().clone()),
                    err: Error::Governance(err),
                });
            }
        };
        let lane_alias = manifest_status.as_ref().map_or_else(
            || format!("lane-{}", lane_id.as_u32()),
            |status| status.alias.clone(),
        );
        if let Some(status) = manifest_status {
            if status.governance.is_some()
                && let Some(policy_rules) = status.rules()
            {
                let authority_rules = manifest_authority_rules.as_ref().unwrap_or(policy_rules);
                let alias = status.alias.clone();
                let allows_multisig_envelope_authority =
                    match checked.as_accepted().as_ref().instructions() {
                        Executable::Instructions(instructions) => {
                            instructions_allow_multisig_envelope_authority(&instructions)
                        }
                        Executable::ContractCall(_)
                        | Executable::IvmProved(_)
                        | Executable::Ivm(_)
                        | Executable::Batch(_) => false,
                    };
                let governance_sensitive =
                    Self::tx_requires_manifest_validator_gating(policy_rules, &checked);
                if governance_sensitive {
                    let manifest_validators = if authority_rules.validators.is_empty() {
                        None
                    } else {
                        match Self::canonical_manifest_validators(&alias, authority_rules) {
                            Ok(validators) => Some(validators),
                            Err(err) => {
                                #[cfg(feature = "telemetry")]
                                telemetry_handle.record_manifest_admission("malformed_validators");
                                return Err(Failure {
                                    tx: Box::new(checked.as_accepted().clone()),
                                    err,
                                });
                            }
                        }
                    };
                    if manifest_validators.is_some() && checked.as_ref().authority_opt().is_none() {
                        #[cfg(feature = "telemetry")]
                        telemetry_handle.record_manifest_admission("missing_authority");
                        return Err(Failure {
                            tx: Box::new(checked.as_accepted().clone()),
                            err: Error::GovernanceNotPermitted {
                                alias: alias.clone(),
                                reason: "authority-free transactions cannot satisfy lane validator gating"
                                    .to_string(),
                            },
                        });
                    }
                    if let Some(authority) = checked.as_ref().authority_opt()
                        && let Some(validators) = manifest_validators.as_ref()
                        && !allows_multisig_envelope_authority
                    {
                        let authority_i105 = match authority.canonical_i105() {
                            Ok(value) => value,
                            Err(err) => {
                                return Err(Failure {
                                    tx: Box::new(checked.as_accepted().clone()),
                                    err: Self::enforcement_error(
                                        &alias,
                                        format!(
                                            "failed to encode authority `{authority}` as i105: {err}"
                                        ),
                                    ),
                                });
                            }
                        };
                        if !validators.contains(&authority_i105) {
                            iroha_logger::warn!(
                                lane = %alias,
                                authority = %authority,
                                "rejecting transaction not signed by governance validator"
                            );
                            #[cfg(feature = "telemetry")]
                            telemetry_handle.record_manifest_admission("non_validator_authority");
                            return Err(Failure {
                                tx: Box::new(checked.as_accepted().clone()),
                                err: Error::GovernanceNotPermitted {
                                    alias: alias.clone(),
                                    reason: "authority not part of lane validator set".to_string(),
                                },
                            });
                        }
                    }
                    let quorum_required = !allows_multisig_envelope_authority
                        && authority_rules.quorum.unwrap_or(0).saturating_sub(1) > 0
                        && !authority_rules.validators.is_empty();
                    let quorum_result =
                        Self::enforce_manifest_quorum(&alias, authority_rules, &checked);
                    if quorum_required {
                        match quorum_result {
                            Ok(()) => {
                                #[cfg(feature = "telemetry")]
                                telemetry_handle.record_manifest_quorum_enforcement("satisfied");
                            }
                            Err(err) => {
                                #[cfg(feature = "telemetry")]
                                telemetry_handle.record_manifest_quorum_enforcement("rejected");
                                #[cfg(feature = "telemetry")]
                                telemetry_handle.record_manifest_admission("quorum_rejected");
                                return Err(Failure {
                                    tx: Box::new(checked.as_accepted().clone()),
                                    err,
                                });
                            }
                        }
                    } else if let Err(err) = quorum_result {
                        #[cfg(feature = "telemetry")]
                        telemetry_handle.record_manifest_admission("quorum_rejected");
                        return Err(Failure {
                            tx: Box::new(checked.as_accepted().clone()),
                            err,
                        });
                    }
                }
                let protected_namespace_result =
                    Self::enforce_manifest_protected_namespaces(&alias, policy_rules, &checked);
                let protected_namespace_applied = match protected_namespace_result {
                    Ok(applied) => applied,
                    Err(err) => {
                        #[cfg(feature = "telemetry")]
                        if !policy_rules.protected_namespaces.is_empty() {
                            telemetry_handle.record_protected_namespace_enforcement("rejected");
                        }
                        #[cfg(feature = "telemetry")]
                        telemetry_handle.record_manifest_admission("protected_namespace_rejected");
                        return Err(Failure {
                            tx: Box::new(checked.as_accepted().clone()),
                            err,
                        });
                    }
                };
                #[cfg(feature = "telemetry")]
                if protected_namespace_applied {
                    telemetry_handle.record_protected_namespace_enforcement("allowed");
                }
                #[cfg(not(feature = "telemetry"))]
                let _ = protected_namespace_applied;
                let runtime_hook_result =
                    Self::enforce_runtime_upgrade_hook(&alias, policy_rules, &checked);
                let runtime_hook_applied = match runtime_hook_result {
                    Ok(applied) => applied,
                    Err(err) => {
                        #[cfg(feature = "telemetry")]
                        telemetry_handle
                            .record_manifest_hook_enforcement("runtime_upgrade", "rejected");
                        #[cfg(feature = "telemetry")]
                        telemetry_handle.record_manifest_admission("runtime_hook_rejected");
                        return Err(Failure {
                            tx: Box::new(checked.as_accepted().clone()),
                            err,
                        });
                    }
                };
                #[cfg(feature = "telemetry")]
                if runtime_hook_applied {
                    telemetry_handle.record_manifest_hook_enforcement("runtime_upgrade", "allowed");
                }
                #[cfg(not(feature = "telemetry"))]
                let _ = runtime_hook_applied;
                #[cfg(feature = "telemetry")]
                {
                    manifest_allowed = true;
                }
            }
        }
        // Keep proof verification on the same manifest cut used by this
        // admission. The separately published privacy handle is a cache.
        let lane_privacy_registry_handle = Arc::new(LanePrivacyRegistry::from_manifest_registry(
            &manifest_snapshot,
        ));
        let privacy_proofs = Self::collect_lane_privacy_proofs(&checked);
        let verified_privacy_commitments = if privacy_proofs.is_empty() {
            BTreeSet::new()
        } else {
            match verify_lane_privacy_proofs(
                lane_privacy_registry_handle.as_ref(),
                lane_id,
                &privacy_proofs,
            ) {
                Ok(verified) => verified,
                Err(err) => {
                    return Err(Failure {
                        tx: Box::new(checked.as_accepted().clone()),
                        err: Error::LanePrivacyProofRejected {
                            alias: lane_alias.clone(),
                            reason: err.to_string(),
                        },
                    });
                }
            }
        };
        let lane_privacy_registry = if lane_privacy_registry_handle.is_empty() {
            None
        } else {
            Some(lane_privacy_registry_handle)
        };
        let publishes_space_directory_manifest =
            Self::publishes_only_space_directory_manifests(&checked);
        let lane_identity = if publishes_space_directory_manifest {
            (None, Vec::new())
        } else {
            checked
                .as_ref()
                .authority_opt()
                .map(|authority| {
                    state_access.extract_lane_identity_metadata(
                        authority,
                        dataspace_id,
                        &lane_alias,
                    )
                })
                .transpose()
                .map_err(|err| Failure {
                    tx: Box::new(checked.as_accepted().clone()),
                    err,
                })?
                .unwrap_or((None, Vec::new()))
        };
        let lane_compliance = self.lane_compliance.read().clone();
        if !publishes_space_directory_manifest
            && let (Some(engine), Some(authority)) =
                (lane_compliance.as_ref(), checked.as_ref().authority_opt())
        {
            let (uaid_value, capability_tags) = lane_identity;
            let authority_domains = state_access
                .extract_lane_authority_domains(authority, &lane_alias)
                .map_err(|err| Failure {
                    tx: Box::new(checked.as_accepted().clone()),
                    err,
                })?;
            let ctx = LaneComplianceContext {
                lane_id,
                dataspace_id,
                authority,
                authority_domains: authority_domains.as_slice(),
                uaid: uaid_value.as_ref(),
                capability_tags: capability_tags.as_slice(),
                lane_privacy_registry,
                verified_privacy_commitments: &verified_privacy_commitments,
            };
            let evaluation = engine.evaluate(&ctx);
            match evaluation {
                LaneComplianceEvaluation::NotConfigured => {
                    if !engine.audit_only() {
                        return Err(Failure {
                            tx: Box::new(checked.as_accepted().clone()),
                            err: Error::LaneComplianceDenied {
                                alias: lane_alias.clone(),
                                reason: "no exact lane compliance policy is configured".to_string(),
                            },
                        });
                    }
                }
                LaneComplianceEvaluation::Allowed(record) => {
                    record.log(engine.audit_only());
                }
                LaneComplianceEvaluation::Denied(record) => {
                    record.log(engine.audit_only());
                    if !engine.audit_only() {
                        let reason = record
                            .reason
                            .clone()
                            .unwrap_or_else(|| "lane compliance policy denied".to_string());
                        return Err(Failure {
                            tx: Box::new(checked.as_accepted().clone()),
                            err: Error::LaneComplianceDenied {
                                alias: lane_alias.clone(),
                                reason,
                            },
                        });
                    }
                }
            }
        }
        #[cfg(feature = "telemetry")]
        if manifest_allowed {
            telemetry_handle.record_manifest_admission("allowed");
        }
        let proposal_gas_cost =
            Self::compute_proposal_gas_cost(checked.as_accepted()).map_err(|error| Failure {
                tx: Box::new(checked.as_accepted().clone()),
                err: Error::NexusFeeAdmissionRejected {
                    code: FeeRejectionCode::InvalidGasLimit,
                    reason: error.to_string(),
                },
            })?;
        let enqueued_at_ms = self.validation_timestamp_ms(checked.as_accepted());
        #[cfg(feature = "telemetry")]
        let pending_teu = Self::compute_teu_weight(checked.as_accepted());
        Ok(PreparedQueueAdmission {
            checked,
            hash,
            sccp_exempt,
            routing_decision,
            routing_plan,
            encoded_len,
            proposal_gas_cost,
            enqueued_at_ms,
            fee_reservation,
            #[cfg(feature = "telemetry")]
            pending_teu,
        })
    }
    fn enqueue_prepared_admissions(
        &self,
        prepared: Vec<PreparedQueueAdmission>,
        telemetry: Option<&StateTelemetry>,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Vec<QueueAdmissionNotification>, (Vec<QueueAdmissionNotification>, Failure)> {
        budget.with_deferred_refund_notifications(|_| {
            let mut notifications = Vec::with_capacity(prepared.len());
            for admission in prepared {
                let PreparedQueueAdmission {
                    checked,
                    hash,
                    sccp_exempt,
                    routing_decision,
                    routing_plan,
                    encoded_len,
                    proposal_gas_cost,
                    enqueued_at_ms,
                    fee_reservation,
                    #[cfg(feature = "telemetry")]
                    pending_teu,
                } = admission;
                let ledger = {
                    let _initialization = self.push_remove_lock.lock();
                    if let Err(err) = self.check_startup_admission() {
                        return Err((
                            notifications,
                            Failure {
                                tx: checked.into_accepted().into(),
                                err,
                            },
                        ));
                    }
                    match self.resident_ledger(budget) {
                        Ok(ledger) => ledger,
                        Err(err) => {
                            return Err((
                                notifications,
                                Failure {
                                    tx: checked.into_accepted().into(),
                                    err,
                                },
                            ));
                        }
                    }
                };
                let _resident_mutation = ledger.mutation();
                let guard = self.push_remove_lock.lock();
                let fail = |err| Failure {
                    tx: checked.as_accepted().clone().into(),
                    err,
                };
                if let Err(err) = self.check_startup_admission() {
                    return Err((notifications, fail(err)));
                }
                if self.txs.contains_key(&hash) {
                    return Err((notifications, fail(Error::IsInQueue)));
                }
                if self.is_expired(checked.as_accepted()) {
                    return Err((notifications, fail(Error::Expired)));
                }
                if self.active_len() >= self.capacity.get()
                    || self
                        .retained_bytes()
                        .saturating_add(Self::retained_byte_cost(encoded_len))
                        > self.max_retained_bytes.get()
                {
                    return Err((notifications, fail(Error::Full)));
                }
                let authority = checked.as_ref().authority_opt().cloned();
                if authority.as_ref().is_some_and(|id| {
                    self.queued_tx_count_for_user(id) >= self.capacity_per_user.get()
                }) {
                    return Err((notifications, fail(Error::MaximumTransactionsPerUser)));
                }
                if let Some(keys) = sccp_exempt.as_ref()
                    && let Err(error) = self.pending_sccp_exempt.lock().validate_claim(&hash, keys)
                {
                    return Err((notifications, fail(Self::sccp_pending_claim_error(error))));
                }
                if self.tx_hashes.is_full() {
                    self.compact_hash_queue_locked();
                }
                if self.tx_hashes.is_full() {
                    return Err((notifications, fail(Error::Full)));
                }
                let original_shell = match QueuedTransaction::reserve(ledger, encoded_len) {
                    Ok(shell) => shell,
                    Err(err) => {
                        return Err((
                            notifications,
                            Failure {
                                tx: checked.into_accepted().into(),
                                err,
                            },
                        ));
                    }
                };
                if let Some(hold) = fee_reservation
                    && let Err(err) = self.fee_admission_reservations.lock().reserve(hash, hold)
                {
                    return Err((notifications, fail(err)));
                }
                // Every fallible policy/capacity decision precedes the original index publication.
                if !self.push_queued_hash(hash, enqueued_at_ms) {
                    self.fee_admission_reservations.lock().release(&hash);
                    return Err((
                        notifications,
                        fail(Error::AdmissionInvariant {
                            reason: "FIFO capacity changed under its mutation lock".to_owned(),
                        }),
                    ));
                }
                if let Some(keys) = sccp_exempt {
                    self.pending_sccp_exempt
                        .lock()
                        .claim(hash, keys)
                        .expect("exact SCCP claim validated under original mutation lock");
                }
                let signed_transaction_hash =
                    crate::tx::exact_signed_transaction_hash(checked.as_accepted().entrypoint());
                self.txs
                    .insert(hash, QueuedTransaction::initialize(original_shell, checked));
                self.advance_pending_ownership_generation(hash);
                self.track_active_transaction();
                self.routing_plans.insert(hash, routing_plan.clone());
                self.tx_enqueued_at_ms.insert(hash, enqueued_at_ms);
                self.insert_tx_encoded_len(hash, encoded_len);
                self.tx_gas_cost.insert(hash, proposal_gas_cost);
                self.track_expiry_hash(hash);
                if let Some(authority) = authority {
                    self.apply_per_user_tx_count_increments(HashMap::from([(authority, 1)]));
                }
                #[cfg(feature = "telemetry")]
                self.record_teu_enqueue_locked(
                    hash,
                    TxTeuInfo {
                        lane_id: routing_decision.lane_id,
                        dataspace_id: routing_decision.dataspace_id,
                        teu: pending_teu,
                    },
                );
                notifications.push(QueueAdmissionNotification {
                    hash,
                    _entrypoint_hash: hash,
                    lane_id: routing_decision.lane_id,
                    dataspace_id: routing_decision.dataspace_id,
                    _enqueue_timestamp_ms: enqueued_at_ms,
                    _routing_plan: routing_plan,
                    signed_transaction_hash,
                });
                drop(guard);
            }
            #[cfg(feature = "telemetry")]
            self.publish_teu_backlog_metrics(telemetry);
            self.publish_backpressure_state(self.active_len(), telemetry);
            Ok(notifications)
        })
    }
    fn publish_admission_notifications(&self, notifications: &[QueueAdmissionNotification]) {
        if notifications.is_empty() {
            return;
        }
        for notification in notifications {
            if let Err(err_hash) = self.tx_gossip.push(notification.hash) {
                warn!(
                    lane_id = %notification.lane_id,
                    dataspace_id = %notification.dataspace_id,
                    tx = %err_hash,
                    "Gossiper is lagging behind, not able to queue tx for gossiping"
                );
            }
            if let Some(hash) = notification.signed_transaction_hash {
                let _ = self.events_sender.send(
                    TransactionEvent {
                        hash,
                        block_height: None,
                        lane_id: notification.lane_id,
                        dataspace_id: notification.dataspace_id,
                        status: TransactionStatus::Queued,
                    }
                    .into(),
                );
            }
            iroha_logger::debug!(
                tx = %notification.hash,
                lane_id = %notification.lane_id,
                dataspace_id = %notification.dataspace_id,
                queued = self.tx_hashes.len(),
                "transaction enqueued"
            );
        }
        trace!(
            len = self.tx_hashes.len(),
            "Transaction queue length after batch admission"
        );
        self.wake_sumeragi();
    }
    /// Pushes an accepted transaction into the queue using a cached default full-frame gossip payload.
    ///
    /// # Errors
    /// Propagates [`Failure`] when the queue rejects the transaction (for example, when it is full
    /// or violates lane limits).
    pub fn push_with_gossip_payload_in_view(
        &self,
        tx: AcceptedTransaction<'static>,
        state_view: &StateView<'_>,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<(), Failure> {
        self.push_with_lane_internal(tx, state_view, gossip_payload)
            .map(|_| ())
    }
    /// Pushes an accepted transaction into the queue using a cached default full-frame gossip payload.
    ///
    /// # Errors
    /// Propagates [`Failure`] when the queue rejects the transaction (for example, when it is full
    /// or violates lane limits).
    pub fn push_with_gossip_payload(
        &self,
        tx: AcceptedTransaction<'static>,
        state_view: StateView,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<(), Failure> {
        self.push_with_gossip_payload_in_view(tx, &state_view, gossip_payload)
    }
    /// Pushes an accepted transaction into the queue using narrow state accessors and a cached
    /// default full-frame gossip payload.
    ///
    /// # Errors
    /// Propagates [`Failure`] when the queue rejects the transaction (for example, when it is
    /// full or violates lane limits).
    pub fn push_with_gossip_payload_with_state(
        &self,
        tx: AcceptedTransaction<'static>,
        state: &State,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<(), Failure> {
        self.push_with_lane_internal_with_state(tx, state, gossip_payload)
            .map(|_| ())
    }
    /// Pushes an accepted transaction into the queue using a precomputed full routing plan and a
    /// cached default full-frame gossip payload.
    ///
    /// # Errors
    /// Propagates [`Failure`] when the queue rejects the transaction.
    pub(crate) fn push_with_gossip_payload_with_state_and_routing_plan(
        &self,
        tx: AcceptedTransaction<'static>,
        state: &State,
        routing_plan: RoutingPlan,
        gossip_payload: Option<Arc<Vec<u8>>>,
    ) -> Result<(), Failure> {
        self.push_with_lane_internal_with_state_and_routing(
            tx,
            state,
            Some(routing_plan),
            gossip_payload,
        )
        .map(|_| ())
    }
    /// Push transaction into queue.
    ///
    /// # Errors
    /// See [`enum@Error`]
    pub fn push_with_lane(
        &self,
        tx: AcceptedTransaction<'static>,
        state_view: StateView,
    ) -> Result<RoutingDecision, Failure> {
        self.push_with_lane_in_view(tx, &state_view)
    }
    /// Push transaction into queue with a shared [`StateView`] snapshot.
    ///
    /// # Errors
    /// See [`enum@Error`]
    pub fn push_with_lane_in_view(
        &self,
        tx: AcceptedTransaction<'static>,
        state_view: &StateView<'_>,
    ) -> Result<RoutingDecision, Failure> {
        self.push_with_lane_internal(tx, state_view, None)
    }
    /// Push transaction into queue using narrow state access when possible.
    ///
    /// # Errors
    /// See [`enum@Error`]
    pub fn push_with_lane_with_state(
        &self,
        tx: AcceptedTransaction<'static>,
        state: &State,
    ) -> Result<RoutingDecision, Failure> {
        self.push_with_lane_internal_with_state(tx, state, None)
    }
    /// Push transaction into queue using a caller-provided full routing plan.
    ///
    /// # Errors
    /// See [`enum@Error`]
    pub fn push_with_lane_with_state_and_routing_plan(
        &self,
        tx: AcceptedTransaction<'static>,
        state: &State,
        routing_plan: RoutingPlan,
    ) -> Result<RoutingDecision, Failure> {
        self.push_with_lane_internal_with_state_and_routing(tx, state, Some(routing_plan), None)
    }
    /// Pushes an accepted transaction into the queue, routing it to the lane resolved from the
    /// supplied [`StateView`].
    ///
    /// # Errors
    /// Propagates [`Failure`] when the queue rejects the transaction (for example, when it is full
    /// or violates lane limits).
    pub fn push(
        &self,
        tx: AcceptedTransaction<'static>,
        state_view: StateView,
    ) -> Result<(), Failure> {
        self.push_in_view(tx, &state_view)
    }
    /// Pushes an accepted transaction into the queue with a shared [`StateView`] snapshot.
    ///
    /// # Errors
    /// Propagates [`Failure`] when the queue rejects the transaction (for example, when it is full
    /// or violates lane limits).
    pub fn push_in_view(
        &self,
        tx: AcceptedTransaction<'static>,
        state_view: &StateView<'_>,
    ) -> Result<(), Failure> {
        self.push_with_lane_in_view(tx, state_view).map(|_| ())
    }
    /// Return the number of transactions still awaiting selection from the queue.
    pub fn queued_len(&self) -> usize {
        let _age_ring = self.queued_age_ring.lock();
        if self.tx_hashes.is_empty() {
            return 0;
        }
        self.resident_accounting
            .get()
            .map_or(0, |ledger| ledger.queued_count.load(Ordering::Relaxed))
    }
    /// Estimated residence of original accepted owners, including detached last readers.
    /// Nested decoded graph allocations remain a separate physical-funding boundary.
    pub fn retained_bytes(&self) -> u64 {
        if let Some(ledger) = self.resident_accounting.get() {
            return ledger.retained_bytes.load(Ordering::Relaxed);
        }
        #[cfg(test)]
        return self.retained_bytes_before_admission.load(Ordering::Relaxed);
        #[cfg(not(test))]
        0
    }
    /// Override retained-byte accounting in tests and return the resulting pressure snapshot.
    #[cfg(test)]
    pub fn set_retained_bytes_for_tests(&self, retained_bytes: u64) -> QueuePressureSnapshot {
        if let Some(ledger) = self.resident_accounting.get() {
            ledger
                .retained_bytes
                .store(retained_bytes, Ordering::Relaxed);
        } else {
            self.retained_bytes_before_admission
                .store(retained_bytes, Ordering::Relaxed);
        }
        self.pressure_snapshot()
    }
    fn track_active_transaction(&self) {
        self.resident_accounting
            .get()
            .expect("admitted original resident ledger")
            .active_count
            .fetch_add(1, Ordering::Relaxed);
    }
    fn untrack_active_transaction(&self) {
        Self::decrement_atomic_count(
            &self
                .resident_accounting
                .get()
                .expect("admitted original resident ledger")
                .active_count,
            "active transaction",
        );
    }
    fn track_queued_hash(&self) {
        self.resident_accounting
            .get()
            .expect("admitted original resident ledger")
            .queued_count
            .fetch_add(1, Ordering::Relaxed);
    }
    fn untrack_queued_hash(&self) {
        Self::decrement_atomic_count(
            &self
                .resident_accounting
                .get()
                .expect("admitted original resident ledger")
                .queued_count,
            "queued transaction",
        );
    }
    #[cfg(test)]
    fn assert_pressure_counters_consistent_for_tests(&self) {
        assert_eq!(
            self.active_len(),
            self.txs.len(),
            "active transaction counter must match tracked transactions"
        );
        assert_eq!(
            self.resident_accounting
                .get()
                .map_or(0, |ledger| ledger.queued_count.load(Ordering::Relaxed)),
            self.queued_tx_enqueued_at_ms.len(),
            "queued transaction counter must match queued-age index"
        );
        if self.tx_hashes.is_empty() {
            assert_eq!(
                self.queued_len(),
                0,
                "empty hash queue must report zero queued transactions"
            );
        } else {
            assert_eq!(
                self.queued_len(),
                self.queued_tx_enqueued_at_ms.len(),
                "queued length must match queued-age index while the hash queue is non-empty"
            );
        }
    }
    fn decrement_atomic_count(counter: &AtomicUsize, name: &str) {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            debug_assert!(current > 0, "{name} counter underflow");
            if current == 0 {
                return;
            }
            match counter.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }
    /// Track a queued transaction hash for TTL sweeps.
    fn track_expiry_hash(&self, hash: EntrypointHash) {
        if self.expiry_ring_members.insert(hash, ()).is_none() {
            let mut ring = self.expiry_ring.lock();
            ring.push_back(hash);
        }
    }
    /// Drop a transaction hash from TTL sweep tracking.
    fn untrack_expiry_hash(&self, hash: &EntrypointHash) {
        self.expiry_ring_members.remove(hash);
    }
    /// Remove expired transactions if the configured sweep interval has elapsed.
    ///
    /// A zero interval disables throttling, not reclamation: every caller runs a
    /// bounded sweep. This keeps the queue live for an explicit zero-duration
    /// configuration instead of turning the TTL mechanism off.
    pub(crate) fn cull_expired_entries_if_due(&self) -> usize {
        let interval_ms = Self::duration_to_millis(self.expired_cull_interval);
        let now = self.time_source.get_unix_time();
        if interval_ms != 0 {
            let now_ms = Self::duration_to_millis(now);
            let last_ms = self.last_expired_cull_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last_ms) < interval_ms {
                return 0;
            }
            self.last_expired_cull_ms.store(now_ms, Ordering::Relaxed);
        }
        self.cull_expired_entries(now)
    }
    fn duration_to_millis(duration: Duration) -> u64 {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    }
    fn validation_timestamp_ms(&self, tx: &AcceptedTransaction<'_>) -> u64 {
        Self::duration_to_millis(
            tx.validation_time()
                .unwrap_or_else(|| self.time_source.get_unix_time()),
        )
    }
    fn pressure_age_budget_ms_from_block_time(block_time: Duration) -> u64 {
        Self::duration_to_millis(block_time)
            .saturating_mul(3)
            .clamp(
                QUEUE_PRESSURE_MIN_AGE_BUDGET_MS,
                QUEUE_PRESSURE_MAX_AGE_BUDGET_MS,
            )
    }
    fn default_pressure_age_budget_ms() -> u64 {
        Self::pressure_age_budget_ms_from_block_time(
            iroha_data_model::parameter::system::SumeragiParameters::default().block_cadence(),
        )
    }
    fn record_queued_age_locked(
        &self,
        age_ring: &mut VecDeque<(EntrypointHash, u64)>,
        hash: EntrypointHash,
        enqueued_at_ms: u64,
    ) {
        if self
            .queued_tx_enqueued_at_ms
            .insert(hash, enqueued_at_ms)
            .is_none()
        {
            self.track_queued_hash();
        }
        age_ring.push_back((hash, enqueued_at_ms));
    }
    fn remove_queued_age_locked(&self, hash: &EntrypointHash) {
        if self.queued_tx_enqueued_at_ms.remove(hash).is_some() {
            self.untrack_queued_hash();
        }
    }
    fn remove_queued_age(&self, hash: &EntrypointHash) {
        let _age_ring = self.queued_age_ring.lock();
        self.remove_queued_age_locked(hash);
    }
    fn clear_queued_age_index_locked(&self, age_ring: &mut VecDeque<(EntrypointHash, u64)>) {
        self.queued_tx_enqueued_at_ms.clear();
        age_ring.clear();
        self.pending_scan_cursor.lock().next_index = 0;
        if let Some(ledger) = self.resident_accounting.get() {
            ledger.queued_count.store(0, Ordering::Relaxed);
        }
    }
    fn oldest_queued_tx_age_ms(&self) -> u64 {
        let mut ring = self.queued_age_ring.lock();
        if self.tx_hashes.is_empty() {
            ring.clear();
            self.pending_scan_cursor.lock().next_index = 0;
            return 0;
        }
        let now_ms = Self::duration_to_millis(self.time_source.get_unix_time());
        while let Some(&(hash, enqueued_at_ms)) = ring.front() {
            if self
                .queued_tx_enqueued_at_ms
                .get(&hash)
                .is_some_and(|entry| *entry.value() == enqueued_at_ms)
            {
                return now_ms.saturating_sub(enqueued_at_ms);
            }
            ring.pop_front();
            self.pending_scan_cursor.lock().next_index = 0;
        }
        0
    }
    fn rebuild_queued_age_index_locked(
        &self,
        age_ring: &mut VecDeque<(EntrypointHash, u64)>,
        queued_hashes: impl IntoIterator<Item = EntrypointHash>,
    ) {
        self.clear_queued_age_index_locked(age_ring);
        let mut age_entries = Vec::new();
        let mut inserted = 0usize;
        for hash in queued_hashes {
            let Some(enqueued_at_ms) = self
                .tx_enqueued_at_ms
                .get(&hash)
                .map(|entry| *entry.value())
            else {
                continue;
            };
            if self
                .queued_tx_enqueued_at_ms
                .insert(hash, enqueued_at_ms)
                .is_none()
            {
                inserted = inserted.saturating_add(1);
            }
            age_entries.push((hash, enqueued_at_ms));
        }
        age_ring.extend(age_entries);
        if let Some(ledger) = self.resident_accounting.get() {
            ledger.queued_count.store(inserted, Ordering::Relaxed);
        }
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    fn rebuild_queued_age_index(&self, queued_hashes: impl IntoIterator<Item = EntrypointHash>) {
        let mut age_ring = self.queued_age_ring.lock();
        self.rebuild_queued_age_index_locked(&mut age_ring, queued_hashes);
    }
    fn pressure_snapshot_with_tracked_count(
        &self,
        tracked_tx_count: usize,
    ) -> QueuePressureSnapshot {
        let queued_tx_count = self.queued_len();
        let retained_bytes = self.retained_bytes();
        let max_retained_bytes = self.max_retained_bytes;
        let oldest_queued_tx_age_ms = self.oldest_queued_tx_age_ms();
        // An inconsistent original admission index remains unavailable until recovery.
        let saturated_by_count =
            self.admission_faulted() || tracked_tx_count >= self.capacity.get();
        let saturated_by_bytes =
            retained_bytes.saturating_add(TX_RETAINED_OVERHEAD_BYTES) > max_retained_bytes.get();
        let age_budget_ms = self.pressure_age_budget_ms.load(Ordering::Relaxed);
        let saturated_by_age =
            queued_tx_count > 0 && oldest_queued_tx_age_ms >= age_budget_ms && age_budget_ms > 0;
        QueuePressureSnapshot {
            tracked_tx_count,
            queued_tx_count,
            capacity: self.capacity,
            retained_bytes,
            max_retained_bytes,
            oldest_queued_tx_age_ms,
            saturated_by_count,
            saturated_by_bytes,
            saturated_by_age,
        }
    }
    fn refresh_backpressure_state(
        &self,
        tracked_tx_count: usize,
        telemetry: Option<&StateTelemetry>,
    ) -> BackpressureState {
        let snapshot = self.pressure_snapshot_with_tracked_count(tracked_tx_count);
        let state = if let Some(ledger) = self.resident_accounting.get() {
            ledger
                .faulted
                .store(self.admission_faulted(), Ordering::Release);
            ledger.publish_backpressure()
        } else {
            let state = snapshot.into_backpressure();
            let _ = self.backpressure_tx.send_if_modified(|current| {
                if *current == state {
                    false
                } else {
                    *current = state;
                    true
                }
            });
            state
        };
        #[cfg(feature = "telemetry")]
        if let Some(tel) = telemetry {
            crate::telemetry::record_state_tx_queue_backpressure(
                tel,
                snapshot.queued_tx_count as u64,
                self.capacity.get() as u64,
                snapshot.retained_bytes,
                snapshot.max_retained_bytes.get(),
                snapshot.saturated_by_count,
                snapshot.saturated_by_bytes,
                snapshot.saturated_by_age,
                snapshot.oldest_queued_tx_age_ms,
            );
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = telemetry;
        state
    }
    fn cull_expired_entries(&self, now: Duration) -> usize {
        self.with_resident_refunds(
            || {
                let mut expired = Vec::new();
                let mut ring = self.expiry_ring.lock();
                let max_scan = self.expired_cull_batch.get().min(ring.len());
                for _ in 0..max_scan {
                    let Some(hash) = ring.pop_front() else {
                        break;
                    };
                    if !self.expiry_ring_members.contains_key(&hash) {
                        continue;
                    }
                    let Some(tx) = self.txs.get(&hash) else {
                        self.expiry_ring_members.remove(&hash);
                        continue;
                    };
                    if self.is_expired_at(tx.as_accepted(), now) {
                        expired.push(hash);
                    } else {
                        ring.push_back(hash);
                    }
                }
                drop(ring);
                let mut notifications = Vec::new();
                let mut removed = 0;
                for hash in expired {
                    let route = self
                        .routing_plans
                        .get(&hash)
                        .map(|plan| plan.coordinator_route());
                    if let Some(tx) = self.remove_pending_hash_locked(hash, None) {
                        removed += 1;
                        if let (Some(route), Some(hash)) = (
                            route,
                            crate::tx::exact_signed_transaction_hash(tx.as_accepted().entrypoint()),
                        ) {
                            notifications.push(TransactionEvent {
                                hash,
                                block_height: None,
                                lane_id: route.lane_id,
                                dataspace_id: route.dataspace_id,
                                status: TransactionStatus::Expired,
                            });
                        }
                    }
                }
                if removed > 0 {
                    self.compact_hash_queue_locked();
                }
                (removed, notifications)
            },
            |(removed, notifications)| {
                for event in notifications {
                    let _ = self.events_sender.send(event.into());
                }
                if removed > 0 {
                    self.publish_backpressure_state(self.active_len(), None);
                }
                removed
            },
        )
    }
    fn compact_hash_queue_locked(&self) -> usize {
        let mut age_ring = self.queued_age_ring.lock();
        let mut retained = Vec::with_capacity(self.active_len());
        let mut dropped = 0;
        while let Some(hash) = self.tx_hashes.pop() {
            if self.txs.contains_key(&hash) {
                retained.push(hash);
            } else {
                dropped += 1;
            }
        }
        for hash in &retained {
            self.tx_hashes
                .push(*hash)
                .expect("compaction cannot exceed original FIFO capacity");
        }
        self.rebuild_queued_age_index_locked(&mut age_ring, retained);
        dropped
    }
    fn decrease_per_user_tx_count(&self, account_id: &AccountId) {
        let Entry::Occupied(mut occupied) = self.txs_per_user.entry(account_id.clone()) else {
            warn!(
                %account_id,
                "per-user transaction count was already absent during queue removal"
            );
            return;
        };
        let count = occupied.get_mut();
        if *count > 1 {
            *count -= 1;
        } else {
            occupied.remove_entry();
        }
    }
    fn queued_tx_count_for_user(&self, account_id: &AccountId) -> usize {
        self.txs_per_user
            .get(account_id)
            .map_or(0, |count| *count.value())
    }
    fn apply_per_user_tx_count_increments(&self, increments: HashMap<AccountId, usize>) {
        for (account_id, delta) in increments {
            if delta == 0 {
                continue;
            }
            self.txs_per_user
                .entry(account_id)
                .and_modify(|count| *count = count.saturating_add(delta))
                .or_insert(delta);
        }
    }
    #[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
    fn publish_backpressure_state(&self, queued: usize, telemetry: Option<&StateTelemetry>) {
        let _ = self.refresh_backpressure_state(queued, telemetry);
    }
    #[cfg(any(test, feature = "telemetry"))]
    fn compute_teu_weight(tx: &AcceptedTransaction<'static>) -> u64 {
        use iroha_data_model::transaction::Executable;
        match tx.entrypoint() {
            iroha_data_model::transaction::TransactionEntrypoint::External(signed) => {
                match signed.instructions() {
                    Executable::Instructions(batch) => {
                        let instructions: Vec<_> = batch.iter().map(Clone::clone).collect();
                        gas::meter_instructions(&instructions)
                    }
                    Executable::ContractCall(_) => {
                        crate::executor::transaction_gas_limit(signed).unwrap_or(0)
                    }
                    Executable::Batch(items) => {
                        if items
                            .iter()
                            .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)))
                        {
                            crate::executor::transaction_gas_limit(signed).unwrap_or(0)
                        } else {
                            let instructions = signed
                                .instructions()
                                .explicit_instructions()
                                .cloned()
                                .collect::<Vec<_>>();
                            gas::meter_instructions(&instructions)
                        }
                    }
                    Executable::IvmProved(proved) => {
                        gas::meter_instructions(proved.overlay.as_ref())
                    }
                    Executable::Ivm(bytecode) => Self::compute_ivm_teu_weight(bytecode.as_ref()),
                }
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedCommitment(_) => {
                gas::meter_sealed_transaction_commitment(tx.encoded_len())
            }
            iroha_data_model::transaction::TransactionEntrypoint::SealedReveal(reveal) => {
                match reveal.signed_transaction().instructions() {
                    Executable::Instructions(batch) => {
                        let instructions: Vec<_> = batch.iter().map(Clone::clone).collect();
                        gas::meter_instructions(&instructions)
                    }
                    Executable::ContractCall(_) => {
                        crate::executor::transaction_gas_limit(reveal.signed_transaction())
                            .unwrap_or(0)
                    }
                    Executable::Batch(items) => {
                        if items
                            .iter()
                            .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)))
                        {
                            crate::executor::transaction_gas_limit(reveal.signed_transaction())
                                .unwrap_or(0)
                        } else {
                            let instructions = reveal
                                .signed_transaction()
                                .instructions()
                                .explicit_instructions()
                                .cloned()
                                .collect::<Vec<_>>();
                            gas::meter_instructions(&instructions)
                        }
                    }
                    Executable::IvmProved(proved) => {
                        gas::meter_instructions(proved.overlay.as_ref())
                    }
                    Executable::Ivm(bytecode) => Self::compute_ivm_teu_weight(bytecode.as_ref()),
                }
            }
        }
    }
    #[cfg(any(test, feature = "telemetry"))]
    fn compute_ivm_teu_weight(bytecode: &[u8]) -> u64 {
        match ProgramMetadata::parse(bytecode) {
            Ok(parsed) => {
                let max_cycles = parsed.metadata.max_cycles;
                if max_cycles == 0 {
                    IVM_TEU_FALLBACK
                } else {
                    max_cycles
                }
            }
            Err(err) => {
                warn!(
                    ?err,
                    "Failed to parse IVM metadata while deriving TEU weight; using fallback"
                );
                IVM_TEU_FALLBACK
            }
        }
    }
    #[cfg(feature = "telemetry")]
    fn record_teu_enqueue_locked(&self, hash: EntrypointHash, info: TxTeuInfo) {
        self.tx_teu.insert(hash, info);
        self.lane_teu_pending
            .entry(info.lane_id)
            .and_modify(|agg| {
                agg.teu = agg.teu.saturating_add(info.teu);
                agg.tx_count += 1;
            })
            .or_insert(PendingTeu {
                teu: info.teu,
                tx_count: 1,
            });
        self.dataspace_teu_pending
            .entry((info.lane_id, info.dataspace_id))
            .and_modify(|agg| {
                agg.teu = agg.teu.saturating_add(info.teu);
                agg.tx_count += 1;
            })
            .or_insert(PendingTeu {
                teu: info.teu,
                tx_count: 1,
            });
    }
    #[cfg(feature = "telemetry")]
    fn record_teu_dequeue(
        &self,
        hash: &EntrypointHash,
        telemetry: Option<&crate::telemetry::StateTelemetry>,
    ) {
        let Some((_, info)) = self.tx_teu.remove(hash) else {
            return;
        };
        if let Entry::Occupied(mut occ) = self.lane_teu_pending.entry(info.lane_id) {
            let agg = occ.get_mut();
            agg.teu = agg.teu.saturating_sub(info.teu);
            agg.tx_count = agg.tx_count.saturating_sub(1);
        }
        if let Entry::Occupied(mut occ) = self
            .dataspace_teu_pending
            .entry((info.lane_id, info.dataspace_id))
        {
            let agg = occ.get_mut();
            agg.teu = agg.teu.saturating_sub(info.teu);
            agg.tx_count = agg.tx_count.saturating_sub(1);
        }
        self.publish_teu_backlog_metric_keys(
            telemetry,
            [info.lane_id].into_iter(),
            [(info.lane_id, info.dataspace_id)].into_iter(),
        );
    }
    #[cfg(feature = "telemetry")]
    fn publish_teu_backlog_metrics(&self, telemetry: Option<&crate::telemetry::StateTelemetry>) {
        let Some(telemetry) = telemetry else {
            return;
        };
        let lane_snapshot: Vec<(LaneId, PendingTeu)> = self
            .lane_teu_pending
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();
        for (lane_id, aggregate) in lane_snapshot {
            let limits = self.nexus_limits.read().for_lane(lane_id);
            let committed = aggregate.teu.min(limits.teu_capacity);
            let headroom = limits.teu_capacity.saturating_sub(committed);
            telemetry.record_nexus_scheduler_lane_teu(
                lane_id,
                LaneTeuGaugeUpdate {
                    capacity: limits.teu_capacity,
                    committed,
                    buckets: NexusLaneTeuBuckets {
                        floor: 0,
                        headroom,
                        must_serve: 0,
                        circuit_breaker: 0,
                    },
                    trigger_level: 0,
                    starvation_bound_slots: limits.starvation_bound_slots,
                },
            );
        }
        let dataspace_snapshot: Vec<((LaneId, DataSpaceId), PendingTeu)> = self
            .dataspace_teu_pending
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect();
        for ((lane_id, dataspace_id), aggregate) in dataspace_snapshot {
            telemetry.record_nexus_scheduler_dataspace_teu(
                lane_id,
                dataspace_id,
                DataspaceTeuGaugeUpdate {
                    backlog: aggregate.teu,
                    age_slots: 0,
                    virtual_finish: 0,
                },
            );
        }
    }
    #[cfg(feature = "telemetry")]
    fn publish_teu_backlog_metric_keys(
        &self,
        telemetry: Option<&crate::telemetry::StateTelemetry>,
        lanes: impl IntoIterator<Item = LaneId>,
        dataspaces: impl IntoIterator<Item = (LaneId, DataSpaceId)>,
    ) {
        let Some(telemetry) = telemetry else {
            return;
        };
        for lane_id in lanes {
            let aggregate = self
                .lane_teu_pending
                .get(&lane_id)
                .map(|entry| entry.value().clone())
                .unwrap_or_default();
            let limits = self.nexus_limits.read().for_lane(lane_id);
            let committed = aggregate.teu.min(limits.teu_capacity);
            let headroom = limits.teu_capacity.saturating_sub(committed);
            telemetry.record_nexus_scheduler_lane_teu(
                lane_id,
                LaneTeuGaugeUpdate {
                    capacity: limits.teu_capacity,
                    committed,
                    buckets: NexusLaneTeuBuckets {
                        floor: 0,
                        headroom,
                        must_serve: 0,
                        circuit_breaker: 0,
                    },
                    trigger_level: 0,
                    starvation_bound_slots: limits.starvation_bound_slots,
                },
            );
        }
        for (lane_id, dataspace_id) in dataspaces {
            let aggregate = self
                .dataspace_teu_pending
                .get(&(lane_id, dataspace_id))
                .map(|entry| entry.value().clone())
                .unwrap_or_default();
            telemetry.record_nexus_scheduler_dataspace_teu(
                lane_id,
                dataspace_id,
                DataspaceTeuGaugeUpdate {
                    backlog: aggregate.teu,
                    age_slots: 0,
                    virtual_finish: 0,
                },
            );
        }
    }
    #[cfg(not(feature = "telemetry"))]
    #[allow(dead_code)]
    fn publish_teu_backlog_metrics(&self, _telemetry: Option<&()>) {
        let _ = self;
    }
    fn revalidate_pending_transactions(
        &self,
        _router: &Arc<dyn LaneRouter>,
        view: &StateView<'_>,
        lane_catalog: &LaneCatalog,
        dataspace_catalog: &DataSpaceCatalog,
        _routing_generation_unchanged: bool,
    ) {
        // Preserve Nexus-before-Queue acquisition, then retain that same Nexus
        // guard through the after-unlock actions inside the original refund scope.
        let revalidation = self.nexus_revalidation_lock.lock();
        self.with_resident_refunds(
            || {
                let revalidation = revalidation;
                let nexus =
                    nexus_with_route_catalogs(view.nexus(), lane_catalog, dataspace_catalog);
                let height = state_view_height_for_routing(view);
                let tracked = self
                    .txs
                    .iter()
                    .map(|entry| *entry.key())
                    .collect::<Vec<_>>();
                let mut fault = None;
                for hash in tracked {
                    let Some(tx) = self.txs.get(&hash).map(|entry| entry.value().clone()) else {
                        continue;
                    };
                    if tx.is_in_blockchain(view) || self.is_expired(tx.as_accepted()) {
                        self.remove_pending_hash_locked(hash, None);
                        continue;
                    }
                    match self.immutable_queued_routing_plan_in_view(
                        hash,
                        tx.as_ref(),
                        view,
                        &nexus,
                        height,
                    ) {
                        Ok(plan) => {
                            #[cfg(feature = "telemetry")]
                            {
                                let route = plan.coordinator_route();
                                self.record_teu_dequeue(&hash, None);
                                self.record_teu_enqueue_locked(
                                    hash,
                                    TxTeuInfo {
                                        lane_id: route.lane_id,
                                        dataspace_id: route.dataspace_id,
                                        teu: Self::compute_teu_weight(tx.as_accepted()),
                                    },
                                );
                            }
                            self.routing_plans.insert(hash, plan);
                        }
                        Err(
                            RoutingResolveError::OrdinaryRouteUnavailable { .. }
                            | RoutingResolveError::Deferred(_),
                        ) => {}
                        Err(error) => {
                            fault.get_or_insert((hash, error));
                        }
                    }
                }
                self.compact_hash_queue_locked();
                (fault, revalidation)
            },
            |(fault, _revalidation)| {
                if let Some((hash, reason)) = fault {
                    self.mark_accepted_work_validation_fault(
                        hash,
                        "nexus_reconfiguration",
                        &reason,
                        None,
                    );
                }
                #[cfg(feature = "telemetry")]
                self.publish_teu_backlog_metrics(Some(view.telemetry));
            },
        )
    }
    #[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
    fn revalidate_pending_transactions_with_state(
        &self,
        router: &Arc<dyn LaneRouter>,
        state: &State,
        lane_catalog: &LaneCatalog,
        dataspace_catalog: &DataSpaceCatalog,
        routing_generation_unchanged: bool,
    ) {
        let state_view = state.view();
        self.revalidate_pending_transactions(
            router,
            &state_view,
            lane_catalog,
            dataspace_catalog,
            routing_generation_unchanged,
        );
    }
    /// Expose a handle for observing queue load.
    #[must_use]
    pub fn backpressure_handle(&self) -> BackpressureHandle {
        BackpressureHandle {
            rx: self.backpressure_tx.subscribe(),
        }
    }
    /// Snapshot current load without subscribing to updates.
    #[must_use]
    pub fn current_backpressure(&self) -> BackpressureState {
        self.refresh_backpressure_state(self.active_len(), None)
    }
    /// Compute the richer queue pressure snapshot without subscribing to the
    /// watch channel.
    #[must_use]
    pub fn pressure_snapshot(&self) -> QueuePressureSnapshot {
        self.pressure_snapshot_with_tracked_count(self.active_len())
    }
    /// Refresh the queue age budget from the effective block time and return
    /// the latest pressure snapshot.
    #[must_use]
    pub fn refresh_pressure_budget_from_block_time(
        &self,
        block_time: Duration,
    ) -> QueuePressureSnapshot {
        let budget_ms = Self::pressure_age_budget_ms_from_block_time(block_time);
        self.pressure_age_budget_ms
            .store(budget_ms, Ordering::Relaxed);
        self.refresh_backpressure_state(self.active_len(), None);
        self.pressure_snapshot()
    }
    /// Set the age budget used by queue pressure snapshots in tests.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn set_pressure_age_budget_for_tests(&self, budget: Duration) -> QueuePressureSnapshot {
        self.pressure_age_budget_ms
            .store(Self::duration_to_millis(budget), Ordering::Relaxed);
        self.refresh_backpressure_state(self.active_len(), None);
        self.pressure_snapshot()
    }
    /// Backdate queued transaction residence timestamps in tests.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn backdate_queued_transactions_for_tests(&self, age: Duration) -> QueuePressureSnapshot {
        let now_ms = Self::duration_to_millis(self.time_source.get_unix_time());
        let enqueued_at_ms = now_ms.saturating_sub(Self::duration_to_millis(age));
        let queued_hashes: Vec<EntrypointHash> = self
            .queued_tx_enqueued_at_ms
            .iter()
            .map(|entry| *entry.key())
            .collect();
        for hash in queued_hashes.iter().copied() {
            self.tx_enqueued_at_ms.insert(hash, enqueued_at_ms);
            self.queued_tx_enqueued_at_ms.insert(hash, enqueued_at_ms);
        }
        self.rebuild_queued_age_index(queued_hashes);
        self.refresh_backpressure_state(self.active_len(), None);
        self.pressure_snapshot()
    }
    fn router_for_nexus(
        nexus: &Nexus,
        lane_catalog: &LaneCatalog,
        dataspace_catalog: &DataSpaceCatalog,
    ) -> Arc<dyn LaneRouter> {
        Arc::new(ConfigLaneRouter::new(
            nexus.routing_policy.clone(),
            dataspace_catalog.clone(),
            lane_catalog.clone(),
        ))
    }
    fn nexus_routing_matches(&self, nexus: &Nexus) -> bool {
        let expected_limits = QueueLimits::from_nexus(nexus);
        *self.routing_policy.read() == nexus.routing_policy
            && self.lane_catalog.read().as_ref() == &nexus.lane_catalog
            && self.dataspace_catalog.read().as_ref() == &nexus.dataspace_catalog
            && *self.nexus_limits.read() == expected_limits
    }
    /// Align cached Nexus metadata around an explicitly supplied test router.
    #[cfg(test)]
    pub(crate) fn install_test_router_metadata_for_nexus(&self, nexus: &Nexus) {
        let lane_catalog = Arc::new(nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(nexus.dataspace_catalog.clone());
        *self.nexus_limits.write() = QueueLimits::from_nexus(nexus);
        *self.lane_catalog.write() = Arc::clone(&lane_catalog);
        *self.dataspace_catalog.write() = Arc::clone(&dataspace_catalog);
        *self.routing_policy.write() = nexus.routing_policy.clone();
        let registry = Arc::new(
            self.lane_manifests
                .read()
                .rebind(&lane_catalog, &nexus.governance),
        );
        self.install_lane_manifests_unchecked_in_queue(&registry);
    }
    /// Ensure the queue router and cached catalogs match the committed Nexus state.
    ///
    /// Proposal leaders use cached queue routing to build block execution contexts, while
    /// validators recompute those contexts from committed state. This guard keeps those two
    /// surfaces aligned even after startup replay or runtime Nexus updates.
    pub fn reconfigure_nexus_with_state_if_needed(
        &self,
        nexus: &Nexus,
        state: &State,
        lane_compliance: Option<Arc<LaneComplianceEngine>>,
    ) -> bool {
        if self.nexus_routing_matches(nexus) {
            return false;
        }
        self.reconfigure_nexus_with_state(nexus, state, lane_compliance);
        true
    }
    /// Returns the queue capacity limits enforced when admitting transactions.
    #[must_use]
    pub fn queue_limits(&self) -> QueueLimits {
        self.nexus_limits.read().clone()
    }
    /// Return the currently configured lane compliance engine, if any.
    #[must_use]
    pub fn lane_compliance_engine(&self) -> Option<Arc<LaneComplianceEngine>> {
        self.lane_compliance.read().clone()
    }
    /// Refresh router configuration, limits, manifests, and telemetry after a Nexus catalog
    /// update. Certified plans retain their exact route; Ordinary input is rerouted from State.
    pub fn reconfigure_nexus(
        &self,
        nexus: &Nexus,
        state_view: &StateView<'_>,
        lane_compliance: Option<Arc<LaneComplianceEngine>>,
    ) {
        let routing_generation_unchanged = self.nexus_routing_matches(nexus);
        let lane_catalog = Arc::new(nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(nexus.dataspace_catalog.clone());
        let router = Self::router_for_nexus(nexus, &lane_catalog, &dataspace_catalog);
        // State owns the installed consensus policy. A Queue cache may lag
        // startup replay or committed lifecycle publication and cannot supply
        // authority for this refresh.
        let registry = Arc::new(
            state_view
                .lane_manifests
                .rebind(&lane_catalog, &nexus.governance),
        );
        if let Err(err) = registry.validate_active_coverage_for_catalog(&lane_catalog) {
            iroha_logger::warn!(
                reason = %err,
                "rebound lane-manifest snapshot is incomplete; affected ingress remains fail-closed"
            );
        }
        // Publish fail-closed manifest semantics before exposing new routes.
        self.install_lane_manifests_unchecked_in_queue(&registry);
        *self.router.write() = Arc::clone(&router);
        *self.nexus_limits.write() = QueueLimits::from_nexus(nexus);
        *self.lane_catalog.write() = Arc::clone(&lane_catalog);
        *self.dataspace_catalog.write() = Arc::clone(&dataspace_catalog);
        *self.routing_policy.write() = nexus.routing_policy.clone();
        *self.lane_compliance.write() = lane_compliance;
        #[cfg(feature = "telemetry")]
        {
            state_view
                .telemetry
                .set_nexus_catalogs(&lane_catalog, &dataspace_catalog);
        }
        self.revalidate_pending_transactions(
            &router,
            state_view,
            &lane_catalog,
            &dataspace_catalog,
            routing_generation_unchanged,
        );
    }
    /// Refresh router configuration, limits, manifests, and telemetry after a Nexus catalog
    /// update. Certified plans retain their exact route; Ordinary input is rerouted from State.
    pub fn reconfigure_nexus_with_state(
        &self,
        nexus: &Nexus,
        state: &State,
        lane_compliance: Option<Arc<LaneComplianceEngine>>,
    ) {
        let routing_generation_unchanged = self.nexus_routing_matches(nexus);
        let lane_catalog = Arc::new(nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(nexus.dataspace_catalog.clone());
        let router = Self::router_for_nexus(nexus, &lane_catalog, &dataspace_catalog);
        // State owns the installed consensus policy. Rebinding a stale Queue
        // cache here could erase or resurrect validator authority after Apply.
        let registry = Arc::new(
            state
                .lane_manifests
                .read()
                .rebind(&lane_catalog, &nexus.governance),
        );
        if let Err(err) = registry.validate_active_coverage_for_catalog(&lane_catalog) {
            iroha_logger::warn!(
                reason = %err,
                "rebound lane-manifest snapshot is incomplete; affected ingress remains fail-closed"
            );
        }
        // Refresh the Queue projection before routing. Only explicit manifest
        // installation or an authenticated lifecycle may publish State policy.
        self.install_lane_manifests_unchecked_in_queue(&registry);
        *self.router.write() = Arc::clone(&router);
        *self.nexus_limits.write() = QueueLimits::from_nexus(nexus);
        *self.lane_catalog.write() = Arc::clone(&lane_catalog);
        *self.dataspace_catalog.write() = Arc::clone(&dataspace_catalog);
        *self.routing_policy.write() = nexus.routing_policy.clone();
        *self.lane_compliance.write() = lane_compliance;
        #[cfg(feature = "telemetry")]
        {
            state
                .metrics()
                .set_nexus_catalogs(&lane_catalog, &dataspace_catalog);
        }
        self.revalidate_pending_transactions_with_state(
            &router,
            state,
            &lane_catalog,
            &dataspace_catalog,
            routing_generation_unchanged,
        );
    }
    /// Apply a lane lifecycle plan to the WSV and refresh queue routing/limits.
    ///
    /// This helper keeps queue routing, manifests, and telemetry aligned with
    /// the latest Nexus catalogs after lanes are added or retired at runtime.
    ///
    /// # Errors
    /// Returns an error if updating the lane lifecycle or reconfiguring Nexus metadata fails.
    #[cfg(test)]
    pub(crate) fn apply_lane_lifecycle(
        &self,
        state: &mut State,
        plan: &LaneLifecyclePlan,
    ) -> Result<(), LaneLifecycleError> {
        let lane_compliance = self.lane_compliance.read().clone();
        state.apply_lane_lifecycle(plan)?;
        let nexus = state.nexus_snapshot();
        self.reconfigure_nexus_with_state(&nexus, state, lane_compliance);
        Ok(())
    }
}
#[cfg(test)]
/// Test helpers and cases for `Queue` and related logic.
pub mod tests {
    #[allow(unused_imports)]
    use super::*;
    use crate::state::StateReadOnlyWithTransactions as _;
    use crate::{
        block::ValidBlock,
        compliance::LaneComplianceEngine,
        governance::manifest::{
            GovernanceHooks, GovernanceRules, LaneManifestRegistry, LaneManifestStatus,
            RuntimeUpgradeHook,
        },
        kura::Kura,
        nexus::space_directory::{
            SpaceDirectoryManifestRecord, SpaceDirectoryManifestSet, UaidDataspaceBindings,
        },
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_config::{
        base::WithOrigin,
        parameters::{
            actual::{Kura as KuraConfig, LaneRoutingMatcher, LaneRoutingRule},
            defaults::kura as kura_defaults,
        },
    };
    use iroha_crypto::{
        Algorithm, Hash, KeyPair, MerkleProof,
        privacy::{LaneCommitmentId, LanePrivacyCommitment, MerkleCommitment, MerkleWitness},
    };
    use iroha_data_model::{
        account::{AccountDetails, AccountValue},
        block::SignedBlock,
        events::pipeline::PipelineEventBox,
        isi::runtime_upgrade::ProposeRuntimeUpgrade,
        nexus::{
            AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_MANAGED, AssetPermissionManifest,
            AuditControls, DataSpaceCatalog, DataSpaceMetadata, JurisdictionSet, LaneCatalog,
            LaneCompliancePolicy, LaneCompliancePolicyId, LaneComplianceRule, LaneConfig,
            LaneLifecyclePlan, LanePrivacyMerkleWitness, LanePrivacyProof, LanePrivacyWitness,
            LaneSchedulerPolicy, ManifestVersion, ParticipantSelector,
        },
        parameter::TransactionParameters,
        prelude::*,
        proof::{ProofAttachment, ProofAttachmentList, ProofBox},
        runtime::RuntimeUpgradeManifest,
        transaction::signed::{
            SealedTransactionCommitmentPayload, SealedTransactionReveal,
            SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
        },
    };
    use iroha_executor_data_model::isi::multisig::{MultisigPropose, MultisigSpec};
    use iroha_logger::Level;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_primitives::json::Json;
    use iroha_schema::Ident;
    #[cfg(feature = "telemetry")]
    use iroha_telemetry::metrics::Metrics;
    use iroha_test_samples::{ALICE_KEYPAIR, gen_account_in};
    use mv::storage::StorageReadOnly;
    use nonzero_ext::nonzero;
    use std::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet},
        fs,
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::Duration,
    };
    use tempfile::tempdir;
    static NEXT_TEST_DOMAIN_SUFFIX: AtomicU64 = AtomicU64::new(1);
    #[test]
    fn execution_context_routing_plan_reconstruction_is_exact_and_canonical() {
        let coordinator = RoutingDecision::new(LaneId::new(5), DataSpaceId::new(7));
        let plan = RoutingPlan::native_amx(
            coordinator,
            vec![
                RouteLeg::new(coordinator, RouteLegRole::Participant),
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(8), DataSpaceId::new(9)),
                    RouteLegRole::Participant,
                ),
            ],
        );
        let entrypoint_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
            b"canonical execution-context routing plan",
        ));
        let context = execution_context_for_routing_plan(entrypoint_hash, &plan);
        assert_eq!(
            routing_plan_from_execution_context(&context).expect("canonical context plan"),
            plan
        );

        let mut reordered = context.clone();
        reordered.routing_plan_legs.swap(1, 2);
        assert!(routing_plan_from_execution_context(&reordered).is_err());

        let mut repeated_coordinator = context;
        repeated_coordinator.routing_plan_legs[1].role = ExternalExecutionRouteRole::Coordinator;
        assert!(routing_plan_from_execution_context(&repeated_coordinator).is_err());
    }
    #[test]
    fn routing_topology_comparison_ignores_only_lane_selection() {
        let coordinator_dataspace = DataSpaceId::new(7);
        let participant_dataspace = DataSpaceId::new(9);
        let previous = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::new(5), coordinator_dataspace),
            vec![
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(5), coordinator_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(8), participant_dataspace),
                    RouteLegRole::Participant,
                ),
            ],
        );
        let reconfigured = RoutingPlan::native_amx(
            RoutingDecision::new(LaneId::new(2), coordinator_dataspace),
            vec![
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(2), coordinator_dataspace),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(3), participant_dataspace),
                    RouteLegRole::Participant,
                ),
            ],
        );
        assert!(routing_plans_have_same_dataspace_role_topology(
            &previous,
            &reconfigured
        ));

        let changed_membership = RoutingPlan::native_amx(
            reconfigured.coordinator_route(),
            vec![
                RouteLeg::new(reconfigured.coordinator_route(), RouteLegRole::Participant),
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(3), DataSpaceId::new(10)),
                    RouteLegRole::Participant,
                ),
            ],
        );
        assert!(!routing_plans_have_same_dataspace_role_topology(
            &previous,
            &changed_membership
        ));
        assert!(!routing_plans_have_same_dataspace_role_topology(
            &previous,
            &RoutingPlan::single(previous.coordinator_route())
        ));
    }
    fn lane_authority_for_queue_test(
        state: &mut State,
        validator_keys: &[iroha_crypto::KeyPair],
    ) -> Arc<LaneManifestRegistry> {
        let validator_peers = validator_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        let validator_accounts = validator_keys
            .iter()
            .map(|key| AccountId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        {
            let mut world_block = state.world.block();
            {
                let mut peers = world_block.peers_mut_for_testing().transaction();
                for validator_peer in &validator_peers {
                    if !peers.iter().any(|peer| peer == validator_peer) {
                        peers.push(validator_peer.clone());
                    }
                }
                peers.apply();
            }
            world_block.commit();
        }
        for validator_key in validator_keys {
            let validator_pop = iroha_crypto::bls_normal_pop_prove(validator_key.private_key())
                .expect("deterministic queue manifest validator PoP");
            state.world.register_validator_pop_for_testing(
                validator_key.public_key().clone(),
                validator_pop.clone(),
            );
            let id = crate::state::derive_committee_key_id(validator_key.public_key());
            let record = iroha_data_model::consensus::ConsensusKeyRecord {
                id: id.clone(),
                public_key: validator_key.public_key().clone(),
                pop: Some(validator_pop),
                activation_height: 0,
                expiry_height: None,
                replaces: None,
                status: iroha_data_model::consensus::ConsensusKeyStatus::Active,
            };
            let mut world = state.world.block();
            world.consensus_keys.insert(id.clone(), record.clone());
            let pk = record.public_key.to_string();
            let mut by_pk = world
                .consensus_keys_by_pk
                .get(&pk)
                .cloned()
                .unwrap_or_default();
            if !by_pk.contains(&id) {
                by_pk.push(id);
                world.consensus_keys_by_pk.insert(pk, by_pk);
            }
            world.commit();
        }
        {
            let mut topology = state.commit_topology.block();
            topology.clear();
            topology.extend(validator_peers);
            topology.commit();
        }
        let nexus = state.nexus_snapshot();
        // Queue persistence rebinds the source authority. Keep actual canonical
        // source bytes in the frozen registry instead of telemetry-only statuses.
        let directory = tempfile::tempdir().expect("queue manifest source directory");
        for lane in nexus.lane_catalog.lanes() {
            let manifest = iroha_data_model::nexus::NativeLaneManifestV1 {
                lane: Some(lane.alias.clone()),
                governance: lane.governance.clone(),
                version: Some(iroha_data_model::nexus::NativeLaneManifestV1::VERSION),
                validators: Some(
                    validator_accounts
                        .iter()
                        .zip(validator_keys)
                        .map(|(account, key)| {
                            iroha_data_model::nexus::NativeLaneValidatorBindingV1 {
                                validator: Some(account.to_string()),
                                peer_id: Some(PeerId::new(key.public_key().clone()).to_string()),
                                torii_url: None,
                            }
                        })
                        .collect(),
                ),
                ..iroha_data_model::nexus::NativeLaneManifestV1::default()
            };
            std::fs::write(
                directory
                    .path()
                    .join(format!("{}.manifest.json", lane.alias)),
                norito::json::to_vec(&manifest).expect("encode canonical queue manifest"),
            )
            .expect("write canonical queue manifest source");
        }
        let mut registry_config = nexus.registry.clone();
        registry_config.manifest_directory = Some(directory.path().to_path_buf());
        Arc::new(LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &registry_config,
        ))
    }
    #[test]
    fn queue_lane_authority_retains_frozen_source_and_exact_committee() {
        let mut state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let manifests = exact_f1_lane_authority_for_queue_test(&mut state, 0x71);
        let nexus = state.nexus_snapshot();
        let rebound = manifests.rebind(&nexus.lane_catalog, &nexus.governance);
        assert_eq!(
            rebound.consensus_policy_digest(),
            manifests.consensus_policy_digest()
        );
        let rules = rebound
            .lane_rules(LaneId::SINGLE)
            .expect("frozen lane rules");
        assert_eq!(rules.validators.len(), 4);
        assert_eq!(rules.validator_bindings.len(), 4);
        assert_eq!(rules.version, 1);
        let status = rebound.status(LaneId::SINGLE).expect("lane source status");
        assert!(
            !status
                .manifest_path
                .as_ref()
                .expect("original source path")
                .exists(),
            "rebinding retains the frozen original after temporary files are removed"
        );
        state.install_lane_manifests_for_testing(&Arc::new(rebound));
        assert_eq!(state.view().commit_topology().len(), 4);
    }

    fn exact_lane_authority_for_queue_test(
        state: &mut State,
        validator_keys: &[iroha_crypto::KeyPair],
    ) -> Arc<LaneManifestRegistry> {
        assert_eq!(
            validator_keys.len(),
            4,
            "the default queue dataspace has f=1 and therefore requires exactly four validators"
        );
        lane_authority_for_queue_test(state, validator_keys)
    }
    fn exact_f1_lane_authority_for_queue_test(
        state: &mut State,
        seed: u8,
    ) -> Arc<LaneManifestRegistry> {
        let validator_keys = (0_u8..4)
            .map(|offset| {
                iroha_crypto::KeyPair::from_seed(
                    vec![seed.wrapping_add(offset); 32],
                    iroha_crypto::Algorithm::BlsNormal,
                )
            })
            .collect::<Vec<_>>();
        exact_lane_authority_for_queue_test(state, &validator_keys)
    }
    fn install_single_validator_topology_for_queue_test(state: &mut State, seed: u8) {
        let manifests = exact_f1_lane_authority_for_queue_test(state, seed);
        state.install_lane_manifests_for_testing(&manifests);
    }
    fn seed_committed_height_for_queue_test(state: &State, height: u64) {
        let mut block_hashes = state.block_hashes.block();
        while u64::try_from(block_hashes.len()).unwrap_or(u64::MAX) < height {
            let next = u8::try_from(block_hashes.len() % usize::from(u8::MAX))
                .expect("modulo u8::MAX fits u8")
                .saturating_add(1);
            block_hashes.push_for_tests(
                HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                    Hash::prehashed([next; Hash::LENGTH]),
                ),
            );
        }
        block_hashes.commit_for_tests();
    }
    fn state_with_future_created_autoscale_lane(
        created_height: u64,
        committed_height: u64,
    ) -> State {
        let mut future_elastic = LaneConfig {
            id: LaneId::new(1),
            alias: "elastic-lane-1".to_owned(),
            dataspace_id: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            ..LaneConfig::default()
        };
        future_elastic
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
        future_elastic.metadata.insert(
            AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
            created_height.to_string(),
        );
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut future_elastic);
        let lane_catalog =
            LaneCatalog::new(nonzero!(2_u32), vec![LaneConfig::default(), future_elastic])
                .expect("future-created autoscale lane catalog");
        let lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog);
        let kura_config = KuraConfig {
            init_mode: iroha_config::kura::InitMode::Strict,
            // The authenticated temporary constructor replaces this placeholder.
            store_dir: WithOrigin::inline(PathBuf::new()),
            max_disk_usage_bytes: kura_defaults::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: kura_defaults::BLOCKS_IN_MEMORY,
            debug_output_new_blocks: false,
            fsync_mode: iroha_config::kura::FsyncMode::Batched,
            fsync_interval: kura_defaults::FSYNC_INTERVAL,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        };
        let kura = Kura::new_temporary_with_configured_lane_catalog(
            &kura_config,
            &lane_config,
            &lane_catalog,
        )
        .expect("initialize authenticated future-created autoscale Kura");
        let mut state = State::try_new(
            crate::state::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            world_with_test_domains(),
            kura,
            LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            <_>::default(),
        )
        .expect("initialize authenticated future-created autoscale State");
        let mut nexus = state.nexus_snapshot();
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id = nonzero!(1_u32);
        nexus.autoscale.max_lane_id_exclusive = nonzero!(8_u32);
        nexus.lane_catalog = lane_catalog;
        nexus.lane_config = lane_config;
        *state.nexus.get_mut() = nexus;
        state.reseed_static_lane_incarnations_for_tests();
        state.install_active_lane_markers_for_tests();
        assert_eq!(
            crate::state::nexus_active_lane_dataspace_at_height(
                LaneId::new(1),
                &state.nexus_snapshot(),
                created_height,
            ),
            Some(DataSpaceId::UNIVERSAL),
            "future-created autoscale fixture must be valid once its creation height is reached"
        );
        if committed_height < created_height {
            assert_eq!(
                crate::state::nexus_active_lane_dataspace_at_height(
                    LaneId::new(1),
                    &state.nexus_snapshot(),
                    committed_height,
                ),
                None,
                "future-created autoscale fixture must be inactive before its creation height"
            );
        }
        seed_committed_height_for_queue_test(&state, committed_height);
        state
    }
    fn unique_test_domain_name(prefix: &str) -> String {
        let suffix = NEXT_TEST_DOMAIN_SUFFIX.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}{suffix}")
    }
    fn checked_random_queue_keypair() -> KeyPair {
        KeyPair::try_random().expect("queue fixture key generation should succeed")
    }
    #[test]
    fn queue_fixture_key_generation_preserves_default_algorithm() {
        assert_eq!(
            checked_random_queue_keypair().public_key().algorithm(),
            Algorithm::default()
        );
    }
    #[test]
    fn default_queue_uses_strict_transaction_aware_router() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let (authority_id, authority_keypair) = gen_account_in("wonderland");
        let unknown_dataspace = DataSpaceId::new(9_999);
        let tx = accepted_tx_with(
            authority_id.clone(),
            &authority_keypair,
            &time_source,
            vec![InstructionBox::from(Grant::account_permission(
                iroha_executor_data_model::permission::nexus::CanPublishSpaceDirectoryManifest {
                    dataspace: unknown_dataspace,
                },
                authority_id,
            ))],
            Metadata::default(),
        );
        assert_eq!(
            queue.router.read().try_route(&tx),
            Err(RoutingResolveError::UnknownDataspace {
                dataspace_id: unknown_dataspace,
            })
        );
    }
    impl Queue {
        /// Construct a `Queue` instance suitable for unit tests.
        ///
        /// Initializes bounded queues and counters using the provided configuration
        /// and a controllable `time_source`.
        pub fn test(cfg: Config, time_source: &TimeSource) -> Self {
            let nexus = Nexus::default();
            let router =
                Queue::router_for_nexus(&nexus, &nexus.lane_catalog, &nexus.dataspace_catalog);
            Self::test_with_router(cfg, time_source, router)
        }
        /// Construct a `Queue` instance for unit tests with a custom router.
        pub fn test_with_router(
            cfg: Config,
            time_source: &TimeSource,
            router: Arc<dyn LaneRouter>,
        ) -> Self {
            let queue = Self::test_with_router_for_routes(cfg, time_source, router, &[]);
            queue.install_test_router_metadata_for_nexus(&Nexus::default());
            queue
        }
        /// Construct a `Queue` with synthetic Nexus catalogs matching static test routes.
        pub fn test_with_router_for_routes(
            cfg: Config,
            time_source: &TimeSource,
            router: Arc<dyn LaneRouter>,
            routes: &[(LaneId, DataSpaceId)],
        ) -> Self {
            let (lane_catalog, dataspace_catalog) = Self::test_catalogs_for_routes(routes);
            let mut queue = Self::from_config_with_router_limits_and_catalogs(
                cfg,
                tokio::sync::broadcast::Sender::new(1),
                router,
                QueueLimits::default(),
                &lane_catalog,
                &dataspace_catalog,
                None,
            );
            let mut nexus = Nexus::default();
            nexus.lane_catalog = (*lane_catalog).clone();
            nexus.lane_config = LaneGeometry::from_catalog(&nexus.lane_catalog);
            nexus.dataspace_catalog = (*dataspace_catalog).clone();
            queue.install_test_router_metadata_for_nexus(&nexus);
            queue.time_source = time_source.clone();
            queue
        }
        fn test_catalogs_for_routes(
            routes: &[(LaneId, DataSpaceId)],
        ) -> (Arc<LaneCatalog>, Arc<DataSpaceCatalog>) {
            let mut lanes_by_id = BTreeMap::new();
            let mut dataspaces = BTreeSet::new();
            for (lane, dataspace) in routes {
                match lanes_by_id.insert(*lane, *dataspace) {
                    Some(existing) if existing != *dataspace => {
                        panic!("test route catalog cannot bind lane {lane:?} to two dataspaces")
                    }
                    _ => {}
                }
                dataspaces.insert(*dataspace);
            }
            lanes_by_id
                .entry(LaneId::SINGLE)
                .or_insert(DataSpaceId::UNIVERSAL);
            dataspaces.insert(DataSpaceId::UNIVERSAL);
            let max_lane_id = lanes_by_id
                .keys()
                .map(|id| id.as_u32())
                .max()
                .expect("at least one lane");
            let lane_count = NonZeroU32::new(max_lane_id.saturating_add(1))
                .expect("lane count should be non-zero");
            let lanes = lanes_by_id
                .into_iter()
                .map(|(id, dataspace_id)| LaneConfig {
                    id,
                    dataspace_id,
                    alias: if id == LaneId::SINGLE {
                        "default".to_string()
                    } else {
                        format!("test-lane-{}", id.as_u32())
                    },
                    ..LaneConfig::default()
                })
                .collect();
            let lane_catalog =
                Arc::new(LaneCatalog::new(lane_count, lanes).expect("valid test lane catalog"));
            let entries = dataspaces
                .into_iter()
                .map(|id| DataSpaceMetadata {
                    id,
                    alias: if id == DataSpaceId::UNIVERSAL {
                        "universal".to_string()
                    } else {
                        format!("test-dataspace-{}", id.as_u64())
                    },
                    description: None,
                    fault_tolerance: 1,
                })
                .collect();
            let dataspace_catalog =
                Arc::new(DataSpaceCatalog::new(entries).expect("valid test dataspace catalog"));
            (lane_catalog, dataspace_catalog)
        }
    }
    struct StaticRouter {
        lane: LaneId,
        dataspace: DataSpaceId,
    }
    #[test]
    fn queue_limits_default_matches_nexus_defaults() {
        let defaults = QueueLimits::default();
        let expected = QueueLimits::from_nexus(&Nexus::default());
        assert_eq!(
            defaults.fallback.teu_capacity,
            expected.fallback.teu_capacity
        );
        assert_eq!(
            defaults.fallback.starvation_bound_slots,
            expected.fallback.starvation_bound_slots
        );
        assert_eq!(defaults.per_lane, expected.per_lane);
        assert!(
            defaults.fallback.teu_capacity > 0,
            "fallback TEU capacity should remain non-zero without telemetry"
        );
    }
    #[test]
    fn apply_lane_lifecycle_reconfigures_router_and_limits() {
        let NexusRoutingFixture {
            mut state,
            authority_id,
            authority_keypair,
            ..
        } = nexus_routing_fixture();
        let lane_catalog =
            LaneCatalog::new(nonzero!(1_u32), vec![LaneConfig::default()]).expect("lane catalog");
        let mut nexus = state.nexus_snapshot();
        nexus.lane_catalog = lane_catalog.clone();
        state
            .set_nexus(nexus.clone())
            .expect("apply initial Nexus config");
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
            nexus.routing_policy.clone(),
            nexus.dataspace_catalog.clone(),
            nexus.lane_catalog.clone(),
        ));
        let lane_catalog = Arc::new(nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(nexus.dataspace_catalog.clone());
        let mut queue = Queue::from_config_with_router_limits_and_catalogs(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(8_usize),
                capacity_per_user: nonzero!(4_usize),
                ..Config::default()
            },
            tokio::sync::broadcast::Sender::new(1),
            router,
            QueueLimits::from_nexus(&nexus),
            &lane_catalog,
            &dataspace_catalog,
            None,
        );
        queue.time_source = time_source.clone();
        let tx = accepted_tx_with(
            authority_id.clone(),
            &authority_keypair,
            &time_source,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "lane lifecycle revalidation".into(),
            ))],
            Metadata::default(),
        );
        let tx_hash = tx.as_ref().hash_as_entrypoint();
        queue.push(tx, state.view()).expect("push");
        let lane_b = LaneConfig {
            id: LaneId::new(1),
            alias: "beta".to_string(),
            scheduler: Some(LaneSchedulerPolicy::new(
                Some(NonZeroU64::new(123).expect("positive TEU capacity")),
                None,
            )),
            ..LaneConfig::default()
        };
        let plan = LaneLifecyclePlan {
            additions: vec![lane_b.clone()],
            retire: Vec::new(),
        };
        queue
            .apply_lane_lifecycle(&mut state, &plan)
            .expect("plan applied");
        let mut published_nexus = state.nexus_snapshot();
        published_nexus.routing_policy.default_lane = lane_b.id;
        state
            .set_nexus(published_nexus)
            .expect("publish default-lane policy");
        {
            let routing = queue.routing_plans.get(&tx_hash).expect("routing plan");
            assert_eq!(
                routing.coordinator_route().lane_id,
                LaneId::SINGLE,
                "accepted work must retain its immutable routing plan across reconfiguration"
            );
        }
        // Release the DashMap shard read guard before admitting the successor,
        // which may need to write the same shard even for a different hash.
        assert_eq!(queue.queue_limits().for_lane(lane_b.id).teu_capacity, 123);
        assert_eq!(queue.lane_catalog.read().lanes().len(), 2);
        let successor = accepted_tx_with(
            authority_id,
            &authority_keypair,
            &time_source,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "lane lifecycle successor routing".into(),
            ))],
            Metadata::default(),
        );
        let successor_hash = successor.as_ref().hash_as_entrypoint();
        queue
            .push(successor, state.view())
            .expect("push after reconfiguration");
        assert_eq!(
            queue
                .routing_plans
                .get(&successor_hash)
                .expect("successor routing plan")
                .coordinator_route()
                .lane_id,
            lane_b.id,
            "newly accepted work must use the reconfigured default lane"
        );
    }
    #[test]
    fn apply_lane_lifecycle_error_preserves_router_and_limits() {
        let NexusRoutingFixture { mut state, .. } = nexus_routing_fixture();
        let lane_catalog =
            LaneCatalog::new(nonzero!(1_u32), vec![LaneConfig::default()]).expect("lane catalog");
        let mut nexus = state.nexus_snapshot();
        nexus.lane_catalog = lane_catalog;
        state
            .set_nexus(nexus.clone())
            .expect("apply initial Nexus config");
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
            nexus.routing_policy.clone(),
            nexus.dataspace_catalog.clone(),
            nexus.lane_catalog.clone(),
        ));
        let lane_catalog = Arc::new(nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(nexus.dataspace_catalog.clone());
        let mut queue = Queue::from_config_with_router_limits_and_catalogs(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(8_usize),
                capacity_per_user: nonzero!(4_usize),
                ..Config::default()
            },
            tokio::sync::broadcast::Sender::new(1),
            router,
            QueueLimits::from_nexus(&nexus),
            &lane_catalog,
            &dataspace_catalog,
            None,
        );
        queue.time_source = time_source;
        let before_state_catalog = state.nexus_snapshot().lane_catalog;
        let before_queue_catalog = queue.lane_catalog.read().as_ref().clone();
        let before_limits = queue.queue_limits();
        let mut forged_metadata = BTreeMap::new();
        forged_metadata.insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
        forged_metadata.insert(AUTOSCALE_META_CREATED_HEIGHT.to_owned(), "2".to_owned());
        let plan = LaneLifecyclePlan {
            additions: vec![LaneConfig {
                id: LaneId::new(1),
                alias: "forged-elastic".to_string(),
                scheduler: Some(LaneSchedulerPolicy::new(Some(NonZeroU64::MIN), None)),
                metadata: forged_metadata,
                ..LaneConfig::default()
            }],
            retire: Vec::new(),
        };
        let err = queue
            .apply_lane_lifecycle(&mut state, &plan)
            .expect_err("reserved autoscale metadata must reject before queue reconfiguration");
        assert!(matches!(
            err,
            LaneLifecycleError::ReservedAutoscaleManagedLane(id) if id == LaneId::new(1)
        ));
        assert_eq!(
            state.nexus_snapshot().lane_catalog,
            before_state_catalog,
            "rejected lifecycle plan must not mutate the committed catalog"
        );
        assert_eq!(
            queue.lane_catalog.read().as_ref(),
            &before_queue_catalog,
            "rejected lifecycle plan must not refresh queue catalogs"
        );
        assert_eq!(
            queue.queue_limits(),
            before_limits,
            "forged scheduler metadata from a rejected plan must not enter queue limits"
        );
        assert_eq!(
            queue.queue_limits().for_lane(LaneId::new(1)),
            before_limits.fallback,
            "rejected lane-specific TEU capacity must keep falling back"
        );
    }
    #[test]
    fn apply_lane_lifecycle_physical_retirement_refusal_preserves_queue_limits() {
        let target_lane = LaneId::new(1);
        let teu_capacity = 321;
        let mut state = state_with_future_created_autoscale_lane(7, 0);
        assert!(
            state.lane_incarnation(target_lane).is_some(),
            "repair fixture must keep exact incarnation coverage for every catalog lane"
        );
        let mut nexus = state.nexus_snapshot();
        {
            let mut lanes = nexus.lane_catalog.lanes().to_vec();
            lanes
                .iter_mut()
                .find(|lane| lane.id == target_lane)
                .expect("future-created autoscale lane exists")
                .scheduler = Some(LaneSchedulerPolicy::new(
                Some(NonZeroU64::new(teu_capacity).expect("positive TEU capacity")),
                None,
            ));
            nexus.lane_catalog =
                LaneCatalog::new(nexus.lane_catalog.lane_count(), lanes).expect("lane catalog");
            nexus.lane_config = LaneGeometry::from_catalog(&nexus.lane_catalog);
        }
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
            nexus.routing_policy.clone(),
            nexus.dataspace_catalog.clone(),
            nexus.lane_catalog.clone(),
        ));
        let lane_catalog = Arc::new(nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(nexus.dataspace_catalog.clone());
        let mut queue = Queue::from_config_with_router_limits_and_catalogs(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(8_usize),
                capacity_per_user: nonzero!(4_usize),
                ..Config::default()
            },
            tokio::sync::broadcast::Sender::new(1),
            router,
            QueueLimits::from_nexus(&nexus),
            &lane_catalog,
            &dataspace_catalog,
            None,
        );
        queue.time_source = time_source;
        assert_eq!(
            queue.queue_limits().for_lane(target_lane).teu_capacity,
            teu_capacity,
            "test setup must expose the lane-specific TEU override"
        );
        assert!(
            queue.queue_limits().per_lane.contains_key(&target_lane),
            "test setup must cache its lane-specific queue limit"
        );
        let plan = LaneLifecyclePlan {
            additions: Vec::new(),
            retire: vec![target_lane],
        };
        let state_catalog_before = state.nexus_snapshot().lane_catalog;
        let queue_catalog_before = queue.lane_catalog.read().as_ref().clone();
        let limits_before = queue.queue_limits();
        let incarnation_before = state.lane_incarnation(target_lane);
        let error = queue
            .apply_lane_lifecycle(&mut state, &plan)
            .expect_err("physical retirement must retain catalog data and limits");
        assert!(
            matches!(error, LaneLifecycleError::UnsafeRetirement { lane, reason }
            if lane == target_lane && reason ==
                "physical catalog retirement is unsupported; native lane closure retains its data")
        );
        assert_eq!(state.nexus_snapshot().lane_catalog, state_catalog_before);
        assert_eq!(queue.lane_catalog.read().as_ref(), &queue_catalog_before);
        assert_eq!(state.lane_incarnation(target_lane), incarnation_before);
        assert_eq!(queue.queue_limits(), limits_before);
        assert_eq!(
            queue.queue_limits().for_lane(target_lane).teu_capacity,
            teu_capacity
        );
        assert!(queue.queue_limits().per_lane.contains_key(&target_lane));
    }
    #[test]
    fn reconfiguration_retains_ordinary_input_when_its_admission_lane_is_removed() {
        let retired_lane = LaneId::new(1);
        let lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: retired_lane,
                    alias: "retire-me".to_string(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("lane catalog");
        let mut nexus = Nexus::default();
        nexus.lane_catalog = lane_catalog.clone();
        nexus.routing_policy.default_lane = retired_lane;
        nexus.routing_policy.default_dataspace = DataSpaceId::UNIVERSAL;
        let NexusRoutingFixture {
            state,
            authority_id,
            authority_keypair,
        } = nexus_routing_fixture_with_nexus(nexus.clone());
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let router: Arc<dyn LaneRouter> = Arc::new(StaticRouter {
            lane: retired_lane,
            dataspace: DataSpaceId::UNIVERSAL,
        });
        let lane_catalog = Arc::new(nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(nexus.dataspace_catalog.clone());
        let mut queue = Queue::from_config_with_router_limits_and_catalogs(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(8_usize),
                capacity_per_user: nonzero!(4_usize),
                ..Config::default()
            },
            tokio::sync::broadcast::Sender::new(1),
            Arc::clone(&router),
            QueueLimits::from_nexus(&nexus),
            &lane_catalog,
            &dataspace_catalog,
            None,
        );
        queue.time_source = time_source.clone();
        let tx = accepted_tx_with(
            authority_id.clone(),
            &authority_keypair,
            &time_source,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "retired lane pending route".into(),
            ))],
            Metadata::default(),
        );
        let tx_hash = tx.as_ref().hash_as_entrypoint();
        queue.push(tx, state.view()).expect("push");
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .map(|entry| entry.value().coordinator_route().lane_id),
            Some(retired_lane)
        );
        #[cfg(feature = "telemetry")]
        {
            let info = queue.tx_teu.get(&tx_hash).expect("queued TEU metadata");
            assert_eq!(info.lane_id, retired_lane);
            assert!(info.teu > 0);
            let retired_pending = queue
                .lane_teu_pending
                .get(&retired_lane)
                .expect("retired lane TEU aggregate");
            assert_eq!(retired_pending.tx_count, 1);
            assert_eq!(retired_pending.teu, info.teu);
        }
        assert!(
            queue.routing_plan_hint(&tx_hash).is_some(),
            "queued transaction should retain its initial routing plan"
        );
        let active_catalog =
            LaneCatalog::new(nonzero!(1_u32), vec![LaneConfig::default()]).expect("lane catalog");
        *queue.lane_catalog.write() = Arc::new(active_catalog.clone());
        queue.revalidate_pending_transactions_with_state(
            &router,
            &state,
            &active_catalog,
            dataspace_catalog.as_ref(),
            false,
        );
        assert_eq!(queue.active_len(), 1);
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(queue.queued_tx_count_for_user(&authority_id), 1);
        assert!(queue.txs.get(&tx_hash).is_some());
        assert_eq!(
            queue.routing_plan_hint(&tx_hash),
            Some(RoutingPlan::single(RoutingDecision::new(
                retired_lane,
                DataSpaceId::UNIVERSAL,
            )))
        );
        assert!(!queue.accepted_work_validation_faulted());
        assert!(!queue.admission_faulted());
        assert!(
            active_catalog
                .lanes()
                .iter()
                .all(|lane| lane.id != retired_lane)
        );
        queue.assert_pressure_counters_consistent_for_tests();
    }
    #[test]
    fn proposal_queue_routes_ordinary_input_from_committed_policy() {
        let lane_id = LaneId::new(3);
        let dataspace_id = DataSpaceId::new(10);
        let mut nexus = test_nexus_for_routes(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (lane_id, dataspace_id),
        ]);
        let NexusRoutingFixture {
            mut state,
            authority_id,
            authority_keypair,
        } = nexus_routing_fixture_with_nexus(nexus.clone());
        nexus.routing_policy.default_lane = lane_id;
        nexus.routing_policy.default_dataspace = dataspace_id;
        nexus.fees.base_fee = Quantity::zero();
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(8_usize),
                capacity_per_user: nonzero!(4_usize),
                ..Config::default()
            },
            &time_source,
        ));
        let tx = accepted_tx_with(
            authority_id,
            &authority_keypair,
            &time_source,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "stale router sync".into(),
            ))],
            Metadata::default(),
        );
        let tx_hash = tx.as_ref().hash_as_entrypoint();
        let original_input = tx.entrypoint_bytes().to_vec();
        queue.push(tx, state.view()).expect("push");
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("initial routing plan")
                .coordinator_route(),
            RoutingDecision::default()
        );
        let original_hint = queue.routing_plan_hint(&tx_hash).unwrap();
        let expected_current = evaluate_policy_plan_with_nexus_and_world_at_block_height(
            &nexus,
            queue.txs.get(&tx_hash).unwrap().as_accepted(),
            &state.world_view(),
            0,
            state_height_for_routing(&state),
        )
        .expect("independent committed routing policy");
        assert_eq!(
            expected_current.coordinator_route(),
            RoutingDecision::new(lane_id, dataspace_id)
        );
        state
            .set_nexus(nexus.clone())
            .expect("change routing policy within the original configured catalog");
        assert!(queue.reconfigure_nexus_with_state_if_needed(&nexus, &state, None));
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("refreshed routing hint")
                .coordinator_route(),
            expected_current.coordinator_route()
        );
        assert_eq!(
            original_hint,
            RoutingPlan::single(RoutingDecision::default())
        );
        assert_eq!(
            queue
                .txs
                .get(&tx_hash)
                .unwrap()
                .as_accepted()
                .entrypoint_bytes()
                .as_slice(),
            original_input.as_slice()
        );
        let admitted = queue
            .txs
            .get(&tx_hash)
            .expect("tracked transaction")
            .as_accepted()
            .clone();
        assert_eq!(
            queue
                .route_plan_with_state(&admitted, &state)
                .expect("queued Ordinary input follows committed policy")
                .coordinator_route(),
            RoutingDecision::new(lane_id, dataspace_id)
        );
        assert!(!queue.reconfigure_nexus_with_state_if_needed(&nexus, &state, None));
        assert!(!queue.accepted_work_validation_faulted());
        let popped = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .unwrap();
        assert_eq!(popped.len(), 1);
        assert_eq!(
            queue
                .route_plan_with_state(&popped[0], &state)
                .unwrap()
                .coordinator_route(),
            RoutingDecision::new(lane_id, dataspace_id)
        );
    }
    #[test]
    fn autoscale_scale_out_refreshes_pending_ordinary_application_route() {
        let NexusRoutingFixture {
            mut state,
            authority_id,
            authority_keypair,
            ..
        } = nexus_routing_fixture();
        let mut nexus = state.nexus_snapshot();
        nexus.fees.base_fee = Quantity::zero();
        state
            .set_nexus(nexus.clone())
            .expect("apply initial single-lane Nexus config");
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(16_usize),
                capacity_per_user: nonzero!(16_usize),
                ..Config::default()
            },
            &time_source,
        );
        let tx = (0_u32..128)
            .map(|idx| {
                accepted_tx_with(
                    authority_id.clone(),
                    &authority_keypair,
                    &time_source,
                    vec![InstructionBox::from(Log::new(
                        Level::INFO,
                        format!("autoscale shard candidate {idx}").into(),
                    ))],
                    Metadata::default(),
                )
            })
            .find(|tx| {
                let hash = tx.routing_hash();
                let mut bytes = [0_u8; core::mem::size_of::<u64>()];
                bytes.copy_from_slice(&hash.as_ref()[..core::mem::size_of::<u64>()]);
                u64::from_le_bytes(bytes) % 2 == 1
            })
            .expect("fixture should find a transaction hashing to the elastic shard");
        let tx_hash = tx.as_ref().hash_as_entrypoint();
        let original_input = tx.entrypoint_bytes().to_vec();
        let routed_input = tx.clone();
        queue.push(tx, state.view()).expect("push pending tx");
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("initial routing plan")
                .coordinator_route(),
            RoutingDecision::default()
        );
        let original_hint = queue.routing_plan_hint(&tx_hash).unwrap();
        let mut elastic = LaneConfig {
            id: LaneId::new(1),
            alias: "elastic-lane-1".to_string(),
            ..LaneConfig::default()
        };
        elastic
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_string(), "true".to_string());
        elastic
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "2".to_string());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut elastic);
        let lane_catalog = LaneCatalog::new(nonzero!(2_u32), vec![LaneConfig::default(), elastic])
            .expect("autoscale lane catalog");
        {
            let nexus = state.nexus.get_mut();
            nexus.lane_catalog = lane_catalog;
            nexus.lane_config =
                iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
            nexus.autoscale.enabled = true;
            nexus.autoscale.last_transition_height = 2;
        }
        // This synthetic future-lane fixture has an explicit canonical runtime owner.
        state.reseed_static_lane_incarnations_for_tests();
        seed_committed_height_for_queue_test(&state, 2);
        let expected = RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL);
        let original = queue
            .txs
            .get(&tx_hash)
            .unwrap()
            .as_accepted()
            .entrypoint_bytes()
            .to_vec();
        assert_eq!(
            original, original_input,
            "scale-out retains the original signed input"
        );
        let original_owner = queue.txs.get(&tx_hash).unwrap().value().clone();
        let committed_nexus = state.nexus_snapshot();
        let expected_current = evaluate_policy_plan_with_nexus_and_world_at_block_height(
            &committed_nexus,
            &routed_input,
            &state.world_view(),
            0,
            state_height_for_routing(&state),
        )
        .expect("independent current elastic routing plan");
        assert_eq!(expected_current.coordinator_route(), expected);
        let authoritative_manifests = Arc::clone(&state.lane_manifests.read());
        let manifest_policy_digest_before = state.lane_manifests.read().consensus_policy_digest();
        assert!(queue.reconfigure_nexus_with_state_if_needed(&committed_nexus, &state, None));
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("refreshed current plan")
                .coordinator_route(),
            expected_current.coordinator_route()
        );
        let admitted_plan = queue
            .routing_plans
            .get(&tx_hash)
            .expect("admitted plan")
            .clone();
        assert_eq!(
            admitted_plan.coordinator_route(),
            expected_current.coordinator_route(),
            "autoscale scale-out refreshes the current routing hint"
        );
        assert_eq!(
            queue
                .routing_plan_hint(&tx_hash)
                .map(|plan| plan.coordinator_route()),
            Some(expected_current.coordinator_route()),
            "the queue-owned plan store follows independently resolved current policy"
        );
        assert_eq!(
            original_hint,
            RoutingPlan::single(RoutingDecision::default())
        );
        let retained = queue.txs.get(&tx_hash).unwrap();
        assert!(QueuedTransaction::ptr_eq(retained.value(), &original_owner));
        assert_eq!(
            retained.as_accepted().entrypoint_bytes().as_slice(),
            original.as_slice()
        );
        assert_eq!((queue.active_len(), queue.queued_len()), (1, 1));
        drop(retained);
        assert!(!queue.accepted_work_validation_faulted());
        assert_eq!(queue.lane_catalog.read().lanes().len(), 2);
        assert!(
            queue.lane_manifests.read().status(LaneId::new(1)).is_some(),
            "queue reconfiguration must refresh its manifest projection for the current catalog"
        );
        assert!(
            Arc::ptr_eq(&state.lane_manifests.read(), &authoritative_manifests),
            "refreshing a queue projection must preserve State's authoritative manifest registry"
        );
        assert_eq!(
            state.lane_manifests.read().consensus_policy_digest(),
            manifest_policy_digest_before,
            "a manifest-free autoscale catalog transition must not change the static handshake policy digest"
        );
    }
    #[test]
    fn proposal_queue_keeps_pending_default_route_off_future_created_autoscale_lane() {
        let NexusRoutingFixture {
            mut state,
            authority_id,
            authority_keypair,
            ..
        } = nexus_routing_fixture();
        let mut nexus = state.nexus_snapshot();
        nexus.fees.base_fee = Quantity::zero();
        state
            .set_nexus(nexus.clone())
            .expect("apply initial single-lane Nexus config");
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(16_usize),
                capacity_per_user: nonzero!(16_usize),
                ..Config::default()
            },
            &time_source,
        );
        let tx = (0_u32..128)
            .map(|idx| {
                accepted_tx_with(
                    authority_id.clone(),
                    &authority_keypair,
                    &time_source,
                    vec![InstructionBox::from(Log::new(
                        Level::INFO,
                        format!("future autoscale shard candidate {idx}").into(),
                    ))],
                    Metadata::default(),
                )
            })
            .find(|tx| {
                let hash = tx.as_ref().hash_as_entrypoint();
                let mut bytes = [0_u8; core::mem::size_of::<u64>()];
                bytes.copy_from_slice(&hash.as_ref()[..core::mem::size_of::<u64>()]);
                u64::from_le_bytes(bytes) % 2 == 1
            })
            .expect("fixture should find a transaction hashing to the future elastic shard");
        let tx_hash = tx.as_ref().hash_as_entrypoint();
        queue.push(tx, state.view()).expect("push pending tx");
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("initial routing plan")
                .coordinator_route(),
            RoutingDecision::default()
        );
        let mut future_elastic = LaneConfig {
            id: LaneId::new(1),
            alias: "elastic-lane-1".to_string(),
            dataspace_id: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            ..LaneConfig::default()
        };
        future_elastic
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_string(), "true".to_string());
        future_elastic
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "7".to_string());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut future_elastic);
        let lane_catalog =
            LaneCatalog::new(nonzero!(2_u32), vec![LaneConfig::default(), future_elastic])
                .expect("future autoscale lane catalog");
        {
            let nexus = state.nexus.get_mut();
            nexus.lane_catalog = lane_catalog;
            nexus.lane_config =
                iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
            nexus.autoscale.enabled = true;
            nexus.autoscale.last_transition_height = 7;
        }
        // This synthetic future-lane fixture has an explicit canonical runtime owner.
        state.reseed_static_lane_incarnations_for_tests();
        seed_committed_height_for_queue_test(&state, 6);
        let committed_nexus = state.nexus_snapshot();
        assert!(queue.reconfigure_nexus_with_state_if_needed(&committed_nexus, &state, None));
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("immutable plan")
                .coordinator_route(),
            RoutingDecision::default(),
            "future-created autoscale lanes must not receive pending default-route traffic before activation"
        );
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("immutable plan")
                .coordinator_route(),
            RoutingDecision::default(),
            "reconfiguration must preserve the admitted active default route"
        );
        assert_eq!(
            queue
                .routing_plan_hint(&tx_hash)
                .map(|plan| plan.coordinator_route()),
            Some(RoutingDecision::default()),
            "queue-owned plan store must not advertise the future-created elastic lane"
        );
    }
    #[test]
    fn physical_scale_in_refusal_retains_ordinary_input_without_global_fault() {
        let NexusRoutingFixture {
            mut state,
            authority_id,
            authority_keypair,
            ..
        } = nexus_routing_fixture();
        let mut initial_lane_1 = LaneConfig {
            id: LaneId::new(1),
            alias: "elastic-lane-1".to_string(),
            ..LaneConfig::default()
        };
        initial_lane_1
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_string(), "true".to_string());
        initial_lane_1
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "2".to_string());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut initial_lane_1);
        let mut initial_lane_2 = LaneConfig {
            id: LaneId::new(2),
            alias: "elastic-lane-2".to_string(),
            ..LaneConfig::default()
        };
        initial_lane_2
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_string(), "true".to_string());
        initial_lane_2
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_string(), "3".to_string());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut initial_lane_2);
        let initial_catalog = LaneCatalog::new(
            nonzero!(3_u32),
            vec![
                LaneConfig::default(),
                initial_lane_1.clone(),
                initial_lane_2.clone(),
            ],
        )
        .expect("initial autoscale lane catalog");
        {
            let nexus = state.nexus.get_mut();
            nexus.fees.base_fee = Quantity::zero();
            nexus.lane_catalog = initial_catalog;
            nexus.lane_config =
                iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
            nexus.autoscale.enabled = true;
            nexus.autoscale.min_lane_id = nonzero!(1_u32);
            nexus.autoscale.max_lane_id_exclusive = nonzero!(8_u32);
            nexus.autoscale.last_transition_height = 3;
        }
        state.reseed_static_lane_incarnations_for_tests();
        seed_committed_height_for_queue_test(&state, 3);
        let initial_nexus = state.nexus_snapshot();
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(
            Config {
                transaction_time_to_live: Duration::from_secs(60),
                capacity: nonzero!(16_usize),
                capacity_per_user: nonzero!(16_usize),
                ..Config::default()
            },
            &time_source,
        );
        assert!(queue.reconfigure_nexus_with_state_if_needed(&initial_nexus, &state, None));
        let tx = (0_u32..512)
            .map(|idx| {
                accepted_tx_with(
                    authority_id.clone(),
                    &authority_keypair,
                    &time_source,
                    vec![InstructionBox::from(Log::new(
                        Level::INFO,
                        format!("physical scale-in candidate {idx}").into(),
                    ))],
                    Metadata::default(),
                )
            })
            .find(|tx| {
                queue
                    .route_with_state(tx, &state)
                    .is_ok_and(|routing| routing.lane_id == LaneId::new(1))
            })
            .expect("fixture finds input hashing to the requested physical scale-in lane");
        let tx_hash = tx.as_ref().hash_as_entrypoint();
        queue
            .push(tx.clone(), state.view())
            .expect("push pending tx");
        assert_eq!(
            queue
                .routing_plans
                .get(&tx_hash)
                .expect("initial routing plan")
                .coordinator_route(),
            RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL)
        );
        let original_incarnation = state.lane_incarnation(LaneId::new(1));
        let error = state
            .apply_autoscale_lane_lifecycle_for_tests(&LaneLifecyclePlan {
                additions: Vec::new(),
                retire: vec![LaneId::new(1)],
            })
            .expect_err("physical scale-in must refuse instead of deleting retained data");
        assert!(
            matches!(error, LaneLifecycleError::UnsafeRetirement { lane, reason }
            if lane == LaneId::new(1) && reason ==
                "physical catalog retirement is unsupported; native lane closure retains its data")
        );
        let committed_nexus = state.nexus_snapshot();
        assert_eq!(committed_nexus.lane_catalog, initial_nexus.lane_catalog);
        assert_eq!(state.lane_incarnation(LaneId::new(1)), original_incarnation);
        assert_eq!(queue.active_len(), 1);
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(
            queue
                .routing_plan_hint(&tx_hash)
                .map(|plan| plan.coordinator_route()),
            Some(RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL)),
            "the durable admission hint still authenticates the original signed input"
        );
        let current_route = queue
            .route_plan_with_state(&tx, &state)
            .expect("ordinary input retains its route after rejected physical scale-in")
            .coordinator_route();
        assert_eq!(current_route.lane_id, LaneId::new(1));
        assert!(
            committed_nexus
                .lane_catalog
                .lanes()
                .iter()
                .any(|lane| lane.id == current_route.lane_id)
        );
        assert!(!queue.accepted_work_validation_faulted());
        assert!(!queue.admission_faulted());
        assert_eq!(
            queue.lane_catalog.read().as_ref(),
            &initial_nexus.lane_catalog
        );
        assert!(queue.contains_entrypoint_hash(tx_hash));
    }
    impl LaneRouter for StaticRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(self.lane, self.dataspace))
        }
    }
    struct MutableRouter {
        decision: Arc<parking_lot::RwLock<Result<RoutingDecision, RoutingResolveError>>>,
    }
    impl MutableRouter {
        fn new(decision: RoutingDecision) -> Self {
            Self {
                decision: Arc::new(parking_lot::RwLock::new(Ok(decision))),
            }
        }
        fn set(&self, decision: RoutingDecision) {
            *self.decision.write() = Ok(decision);
        }
        fn set_error(&self, err: RoutingResolveError) {
            *self.decision.write() = Err(err);
        }
        fn current(&self) -> Result<RoutingDecision, RoutingResolveError> {
            self.decision.read().clone()
        }
    }
    impl LaneRouter for MutableRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            self.current()
        }
        fn try_route_with_view(
            &self,
            _tx: &dyn TransactionRoutingView,
            _state_view: &StateView<'_>,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            self.current()
        }
        fn try_route_without_state(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<Option<RoutingDecision>, RoutingResolveError> {
            self.current().map(Some)
        }
        fn try_route_plan(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingPlan, RoutingResolveError> {
            self.current().map(RoutingPlan::single)
        }
        fn try_route_plan_with_view(
            &self,
            _tx: &dyn TransactionRoutingView,
            _state_view: &StateView<'_>,
        ) -> Result<RoutingPlan, RoutingResolveError> {
            self.current().map(RoutingPlan::single)
        }
        fn try_route_plan_with_state(
            &self,
            _tx: &dyn TransactionRoutingView,
            _state: &State,
        ) -> Result<RoutingPlan, RoutingResolveError> {
            self.current().map(RoutingPlan::single)
        }
        fn try_route_plan_without_state(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<Option<RoutingPlan>, RoutingResolveError> {
            self.current().map(|route| Some(RoutingPlan::single(route)))
        }
    }
    struct PolicyOnlyDataspaceQueueFixture {
        queue: Queue,
        state: State,
        primary: AccountId,
        primary_keypair: KeyPair,
        secondary: AccountId,
        outsider: AccountId,
        outsider_keypair: KeyPair,
        policy_metadata_key: Name,
    }

    fn policy_only_dataspace_queue_fixture(
        time_source: &TimeSource,
        conflicting_lane_is_active: bool,
        autoscale_lane: Option<(LaneId, u64)>,
    ) -> PolicyOnlyDataspaceQueueFixture {
        let authority_lane = LaneId::SINGLE;
        let policy_lane = LaneId::new(1);
        let conflicting_lane = LaneId::new(2);
        let dataspace = DataSpaceId::UNIVERSAL;
        let router = Arc::new(MutableRouter::new(RoutingDecision::new(
            policy_lane,
            dataspace,
        )));
        let mut routes = vec![(policy_lane, dataspace)];
        if conflicting_lane_is_active {
            routes.push((conflicting_lane, dataspace));
        }
        let queue =
            Queue::test_with_router_for_routes(config_factory(), time_source, router, &routes);

        let (primary, primary_keypair) = gen_account_in("wonderland");
        let (secondary, _) = gen_account_in("wonderland");
        let (outsider, outsider_keypair) = gen_account_in("wonderland");
        let (conflicting_validator, _) = gen_account_in("wonderland");

        let mut lane_catalog = queue.lane_catalog.read().as_ref().clone();
        if let Some((autoscale_lane, created_height)) = autoscale_lane {
            let mut lanes = lane_catalog.lanes().to_vec();
            let lane = lanes
                .iter_mut()
                .find(|lane| lane.id == autoscale_lane)
                .expect("autoscale fixture lane is present");
            lane.alias = format!("elastic-lane-{}", autoscale_lane.as_u32());
            lane.metadata.insert(
                iroha_data_model::nexus::AUTOSCALE_META_MANAGED.to_owned(),
                "true".to_owned(),
            );
            lane.metadata.insert(
                iroha_data_model::nexus::AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
                created_height.to_string(),
            );
            crate::state::attach_synthetic_autoscale_committee_for_test(lane);
            lane_catalog = LaneCatalog::new(lane_catalog.lane_count(), lanes)
                .expect("autoscale queue fixture lane catalog");
        }
        let dataspace_catalog = queue.dataspace_catalog.read().as_ref().clone();
        let mut nexus = Nexus::default();
        if let Some((autoscale_lane, _)) = autoscale_lane {
            nexus.autoscale.enabled = true;
            nexus.autoscale.min_lane_id =
                NonZeroU32::new(autoscale_lane.as_u32()).expect("nonzero autoscale lane id");
            nexus.autoscale.max_lane_id_exclusive =
                NonZeroU32::new(autoscale_lane.as_u32().saturating_add(1))
                    .expect("nonzero autoscale upper bound");
        } else {
            nexus.autoscale.enabled = false;
        }
        nexus.lane_catalog = lane_catalog.clone();
        nexus.configured_lane_catalog = lane_catalog;
        nexus.lane_config = LaneGeometry::from_catalog(&nexus.lane_catalog);
        nexus.dataspace_catalog = dataspace_catalog;
        nexus.routing_policy.default_lane = policy_lane;
        nexus.routing_policy.default_dataspace = dataspace;
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        queue.install_test_router_metadata_for_nexus(&nexus);
        let mut state = if autoscale_lane.is_some() {
            // Deliberately model a future lane that production startup refuses.
            let state = State::new(
                world_with_test_domains(),
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
            );
            nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
            *state.nexus.write() = nexus;
            state.reseed_static_lane_incarnations_for_tests();
            state
        } else {
            State::new_with_nexus_for_testing(
                world_with_test_domains(),
                nexus,
                LiveQueryStore::start_test(),
            )
        };
        for authority in [&primary, &secondary, &outsider, &conflicting_validator] {
            register_test_authority(&mut state, authority);
        }

        let policy_metadata_key =
            Name::from_str("target_upgrade_id").expect("static target policy metadata key");
        let target_rules = GovernanceRules {
            hooks: GovernanceHooks {
                runtime_upgrade: Some(RuntimeUpgradeHook {
                    allow: true,
                    require_metadata: true,
                    metadata_key: Some(policy_metadata_key.clone()),
                    allowed_ids: Some(BTreeSet::from([RUNTIME_UPGRADE_ALLOWED_ID.to_owned()])),
                }),
                ..GovernanceHooks::default()
            },
            ..GovernanceRules::default()
        };
        let authority_rules = GovernanceRules {
            validators: vec![primary.clone(), secondary.clone()],
            quorum: Some(2),
            ..GovernanceRules::default()
        };
        let conflicting_rules = GovernanceRules {
            validators: vec![conflicting_validator],
            quorum: Some(1),
            ..GovernanceRules::default()
        };
        let status = |lane, alias: &str, rules| LaneManifestStatus {
            lane,
            alias: alias.to_owned(),
            dataspace,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_owned()),
            manifest_path: Some(PathBuf::from(format!("/tmp/{alias}.manifest.json"))),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::from([
            (
                authority_lane,
                status(authority_lane, "authority", authority_rules),
            ),
            (policy_lane, status(policy_lane, "policy", target_rules)),
            (
                conflicting_lane,
                status(conflicting_lane, "stale-conflict", conflicting_rules),
            ),
        ])));
        queue.install_lane_manifests_for_testing(&manifests);

        PolicyOnlyDataspaceQueueFixture {
            queue,
            state,
            primary,
            primary_keypair,
            secondary,
            outsider,
            outsider_keypair,
            policy_metadata_key,
        }
    }

    fn policy_only_runtime_upgrade_metadata(
        policy_metadata_key: &Name,
        approver: Option<&AccountId>,
    ) -> Metadata {
        let mut metadata = Metadata::default();
        metadata.insert(
            policy_metadata_key.clone(),
            Json::new(RUNTIME_UPGRADE_ALLOWED_ID),
        );
        if let Some(approver) = approver {
            metadata.insert(
                (*super::GOV_APPROVERS_METADATA_KEY).clone(),
                Json::new(vec![approver.to_string()]),
            );
        }
        metadata
    }

    #[test]
    fn policy_only_lane_inherits_active_dataspace_authority_and_ignores_stale_status() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let PolicyOnlyDataspaceQueueFixture {
            queue,
            state,
            primary,
            primary_keypair,
            secondary,
            outsider,
            outsider_keypair,
            policy_metadata_key,
        } = policy_only_dataspace_queue_fixture(&time_source, false, None);

        let outsider_tx = accepted_tx_with(
            outsider,
            &outsider_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            policy_only_runtime_upgrade_metadata(&policy_metadata_key, Some(&secondary)),
        );
        let err = queue
            .push(outsider_tx, state.view())
            .expect_err("target policy-only lane must inherit validator membership");
        match err.err {
            Error::GovernanceNotPermitted { alias, reason } => {
                assert_eq!(alias, "policy");
                assert!(
                    reason.contains("validator set"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected inherited validator rejection, got {other:?}"),
        }

        let no_quorum_tx = accepted_tx_with(
            primary.clone(),
            &primary_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            policy_only_runtime_upgrade_metadata(&policy_metadata_key, None),
        );
        let err = queue
            .push(no_quorum_tx, state.view())
            .expect_err("target policy-only lane must inherit dataspace quorum");
        match err.err {
            Error::GovernanceNotPermitted { alias, reason } => {
                assert_eq!(alias, "policy");
                assert!(
                    reason.contains("quorum requires 2"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected inherited quorum rejection, got {other:?}"),
        }

        let mut missing_policy_metadata = Metadata::default();
        missing_policy_metadata.insert(
            (*super::GOV_APPROVERS_METADATA_KEY).clone(),
            Json::new(vec![secondary.to_string()]),
        );
        let missing_policy_tx = accepted_tx_with(
            primary.clone(),
            &primary_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            missing_policy_metadata,
        );
        let err = queue
            .push(missing_policy_tx, state.view())
            .expect_err("authority inheritance must preserve the target-local hook");
        match err.err {
            Error::GovernanceNotPermitted { alias, reason } => {
                assert_eq!(alias, "policy");
                assert!(
                    reason.contains("target_upgrade_id"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected target-local policy rejection, got {other:?}"),
        }

        let admitted_tx = accepted_tx_with(
            primary,
            &primary_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            policy_only_runtime_upgrade_metadata(&policy_metadata_key, Some(&secondary)),
        );
        queue.push(admitted_tx, state.view()).expect(
            "active dataspace authority and target-local hook should both be satisfied; stale status must be ignored",
        );
    }

    #[test]
    fn policy_only_lane_fails_closed_on_active_dataspace_authority_conflict() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let PolicyOnlyDataspaceQueueFixture {
            queue,
            state,
            primary,
            primary_keypair,
            secondary,
            policy_metadata_key,
            ..
        } = policy_only_dataspace_queue_fixture(&time_source, true, None);
        let tx = accepted_tx_with(
            primary,
            &primary_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            policy_only_runtime_upgrade_metadata(&policy_metadata_key, Some(&secondary)),
        );

        let err = queue
            .push(tx, state.view())
            .expect_err("conflicting active dataspace authority must fail closed");
        match err.err {
            Error::Governance(err) => assert_eq!(
                err.reason(),
                crate::governance::manifest::GovernanceGuardReason::DataspaceAuthorityConflict
            ),
            other => panic!("expected dataspace authority conflict, got {other:?}"),
        }
    }

    #[test]
    fn policy_only_lane_fails_closed_when_active_authority_source_manifest_is_missing() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let PolicyOnlyDataspaceQueueFixture {
            queue,
            state,
            primary,
            primary_keypair,
            secondary,
            policy_metadata_key,
            ..
        } = policy_only_dataspace_queue_fixture(&time_source, true, None);
        let missing_lane = LaneId::new(2);
        let mut statuses = queue
            .lane_manifests
            .read()
            .statuses()
            .into_iter()
            .map(|status| (status.lane, status))
            .collect::<BTreeMap<_, _>>();
        let missing_status = statuses
            .get_mut(&missing_lane)
            .expect("active authority source status");
        missing_status.manifest_path = None;
        missing_status.governance_rules = None;
        queue.install_lane_manifests_for_testing(&Arc::new(LaneManifestRegistry::from_statuses(
            statuses,
        )));

        let tx = accepted_tx_with(
            primary,
            &primary_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            policy_only_runtime_upgrade_metadata(&policy_metadata_key, Some(&secondary)),
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("a missing active authority source must not disable inherited gating");
        match err.err {
            Error::Governance(err) => assert_eq!(
                err.reason(),
                crate::governance::manifest::GovernanceGuardReason::MissingManifest
            ),
            other => panic!("expected missing sibling manifest rejection, got {other:?}"),
        }
    }

    #[test]
    fn policy_only_static_lane_ignores_conflicting_active_autoscale_manifest() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let PolicyOnlyDataspaceQueueFixture {
            queue,
            state,
            primary,
            primary_keypair,
            secondary,
            policy_metadata_key,
            ..
        } = policy_only_dataspace_queue_fixture(&time_source, true, Some((LaneId::new(2), 1)));
        let tx = accepted_tx_with(
            primary,
            &primary_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            policy_only_runtime_upgrade_metadata(&policy_metadata_key, Some(&secondary)),
        );

        queue.push(tx, state.view()).expect(
            "a conflicting autoscale manifest must not contaminate static dataspace authority",
        );
    }

    #[test]
    fn policy_only_autoscale_lane_keeps_exact_manifest_authority() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let PolicyOnlyDataspaceQueueFixture {
            queue,
            state,
            outsider,
            outsider_keypair,
            policy_metadata_key,
            ..
        } = policy_only_dataspace_queue_fixture(&time_source, false, Some((LaneId::new(1), 1)));
        seed_committed_height_for_queue_test(&state, 1);
        let tx = accepted_tx_with(
            outsider,
            &outsider_keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            policy_only_runtime_upgrade_metadata(&policy_metadata_key, None),
        );

        queue
            .push(tx, state.view())
            .expect("a policy-only autoscale target must not inherit a static sibling's authority");
    }

    #[test]
    fn policy_only_future_autoscale_lane_is_rejected_before_manifest_resolution() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let PolicyOnlyDataspaceQueueFixture {
            queue,
            state,
            primary,
            primary_keypair,
            ..
        } = policy_only_dataspace_queue_fixture(&time_source, false, Some((LaneId::new(1), 2)));
        let tx = accepted_tx_with(
            primary,
            &primary_keypair,
            &time_source,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "future autoscale admission".into(),
            ))],
            Metadata::default(),
        );

        let state_view = state.view();
        #[cfg(feature = "telemetry")]
        let telemetry_handle = state_view.telemetry;
        let mut state_access = EagerAdmissionStateAccess::new(
            state_view.world(),
            &state_view.nexus,
            &state_view.pipeline,
            &state_view,
            1,
            0,
        );
        let err = match queue.prepare_checked_for_enqueue(
            CheckedTransaction::new_unchecked(tx),
            RoutingPlan::single(RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL)),
            &mut state_access,
            None,
            #[cfg(feature = "telemetry")]
            telemetry_handle,
        ) {
            Err(err) => err,
            Ok(_) => panic!("a future autoscale target cannot be admitted early"),
        };
        match err.err {
            Error::GovernanceNotPermitted { reason, .. } => assert!(
                reason.contains("not active in the routed dataspace at the next block height"),
                "unexpected inactive-route rejection: {reason}"
            ),
            other => panic!("expected inactive manifest-authority rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn governance_manifest_allows_ordinary_transactions_from_non_validator_authorities() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let time_source = TimeSource::new_system();
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator_id, validator_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator_id);
        let (other_id, other_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &other_id);
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator_id.clone()],
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "default".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let validator_tx = accepted_tx_by(validator_id.clone(), &validator_keypair, &time_source);
        queue
            .push(validator_tx, state.view())
            .expect("validator should be admitted");
        let other_tx = accepted_tx_by(other_id.clone(), &other_keypair, &time_source);
        queue.push(other_tx, state.view()).expect(
            "ordinary governed-lane transactions must not require end users to be validators",
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["allowed"])
                .get(),
            2
        );
    }
    #[tokio::test]
    async fn non_governed_manifest_validators_do_not_gate_admission() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(Arc::new(Metrics::default()), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let time_source = TimeSource::new_system();
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator_id, _validator_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator_id);
        let (other_id, other_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &other_id);
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator_id],
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "default".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: None,
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let other_tx = accepted_tx_by(other_id.clone(), &other_keypair, &time_source);
        queue
            .push(other_tx, state.view())
            .expect("non-governed manifest should not gate transaction authority");
    }
    #[test]
    fn manifest_hot_reload_rejects_semantic_drift_atomically() {
        fn registry(path: &str, validator: AccountId, quorum: u32) -> LaneManifestRegistryHandle {
            let rules = GovernanceRules {
                validators: vec![validator],
                quorum: Some(quorum),
                ..GovernanceRules::default()
            };
            let status = LaneManifestStatus {
                lane: LaneId::SINGLE,
                alias: "default".to_owned(),
                dataspace: DataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: Some("parliament".to_owned()),
                manifest_path: Some(PathBuf::from(path)),
                governance_rules: Some(rules),
                privacy_commitments: Vec::new(),
            };
            Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::from([(
                LaneId::SINGLE,
                status,
            )])))
        }
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (alice, _) = gen_account_in("wonderland");
        let (bob, _) = gen_account_in("wonderland");
        let baseline = registry("/srv/default.manifest.json", alice.clone(), 1);
        queue.install_lane_manifests_for_testing(&baseline);
        let baseline_digest = baseline.consensus_policy_digest();
        let drift = registry("/srv/default.manifest.json", bob, 2);
        assert!(!queue.install_lane_manifests_if_consensus_compatible(&drift));
        let retained = queue.lane_manifests.read().clone();
        assert!(Arc::ptr_eq(&retained, &baseline));
        assert_eq!(retained.consensus_policy_digest(), baseline_digest);
        let relocated = registry("/relocated/default.manifest.json", alice, 1);
        assert!(queue.install_lane_manifests_if_consensus_compatible(&relocated));
        let installed = queue.lane_manifests.read().clone();
        assert!(Arc::ptr_eq(&installed, &relocated));
        assert_eq!(installed.consensus_policy_digest(), baseline_digest);
    }
    #[test]
    fn materialized_manifest_refresh_updates_local_diagnostics_without_state_publication() {
        use iroha_config::parameters::actual::LaneRegistry;

        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let nexus = state.nexus_snapshot();
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let original_directory = tempfile::tempdir().unwrap();
        let relocated_directory = tempfile::tempdir().unwrap();
        let alias = &nexus.lane_catalog.lanes()[0].alias;
        let manifest = norito::json::to_vec(&norito::json!({ "lane": alias })).unwrap();
        let load = |directory: &std::path::Path| {
            std::fs::write(directory.join(format!("{alias}.manifest.json")), &manifest).unwrap();
            Arc::new(LaneManifestRegistry::from_config(
                &nexus.lane_catalog,
                &nexus.governance,
                &LaneRegistry {
                    manifest_directory: Some(directory.to_path_buf()),
                    ..LaneRegistry::default()
                },
            ))
        };
        let original = load(original_directory.path());
        let relocated = load(relocated_directory.path());
        queue
            .install_materialized_lane_manifests_with_state(
                &original,
                &state,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .unwrap();
        let generation = state.state_view_generation();
        let original_privacy = state.lane_privacy_registry.read().clone();
        assert!(
            queue.install_lane_manifests_with_state_if_consensus_compatible(&relocated, &state,)
        );
        assert_eq!(state.state_view_generation(), generation);
        assert!(Arc::ptr_eq(&state.lane_manifests.read(), &original));
        assert!(Arc::ptr_eq(
            &state.lane_privacy_registry.read(),
            &original_privacy
        ));
        assert!(Arc::ptr_eq(&queue.lane_manifests.read(), &relocated));
        let refreshed = queue.lane_manifests.read();
        assert_eq!(
            refreshed.statuses()[0].manifest_path,
            Some(
                relocated_directory
                    .path()
                    .join(format!("{alias}.manifest.json"))
            )
        );
        assert_eq!(
            refreshed
                .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance,)
                .unwrap(),
            original
                .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance,)
                .unwrap(),
        );
    }

    #[test]
    fn materialized_queue_manifest_handoff_rejects_status_only_without_mutation() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let nexus = state.nexus_snapshot();
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let state_generation_before = state.state_view_generation();
        let state_before = state.lane_manifests.read().clone();
        let state_privacy_before = state.lane_privacy_registry.read().clone();
        let queue_before = queue.lane_manifests.read().clone();
        let queue_privacy_before = queue.lane_privacy_registry.read().clone();
        let status_only = Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::new()));
        let error = queue
            .install_materialized_lane_manifests_with_state(
                &status_only,
                &state,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .expect_err("status-only authority must not reach State or Queue");
        assert!(error.to_string().contains("materialized frozen source"));
        assert_eq!(state.state_view_generation(), state_generation_before);
        assert!(Arc::ptr_eq(&*state.lane_manifests.read(), &state_before));
        assert!(Arc::ptr_eq(
            &*state.lane_privacy_registry.read(),
            &state_privacy_before
        ));
        assert!(Arc::ptr_eq(&*queue.lane_manifests.read(), &queue_before));
        assert!(Arc::ptr_eq(
            &*queue.lane_privacy_registry.read(),
            &queue_privacy_before
        ));

        let source_backed = Arc::new(LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &nexus.registry,
        ));
        assert_eq!(
            state_before
                .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance)
                .unwrap(),
            source_backed
                .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance)
                .unwrap(),
        );
        queue
            .install_materialized_lane_manifests_with_state(
                &source_backed,
                &state,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .expect("equal source authority refreshes Queue without State publication");
        assert_eq!(state.state_view_generation(), state_generation_before);
        assert!(Arc::ptr_eq(&*state.lane_manifests.read(), &state_before));
        assert!(Arc::ptr_eq(
            &*state.lane_privacy_registry.read(),
            &state_privacy_before
        ));
        assert!(Arc::ptr_eq(&*queue.lane_manifests.read(), &source_backed));
    }
    #[test]
    fn nexus_reconfiguration_revalidates_pending_transaction_without_relocking_transition_index() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let nexus = state.nexus_snapshot();
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let tx = accepted_tx_by_someone(&time_source);
        let hash = tx.as_ref().hash_as_entrypoint();
        queue
            .push(tx, state.view())
            .expect("enqueue transaction before Nexus reconfiguration");
        queue.reconfigure_nexus_with_state(&nexus, &state, None);
        assert!(
            queue.txs.contains_key(&hash),
            "still-pending transaction must survive an unchanged Nexus reconfiguration"
        );
        assert_eq!(queue.active_len(), 1);
    }
    include!("queue/nexus_reconfigure_manifest_reload_tests.rs");
    include!("queue/privacy_governance_compliance_tests.rs");
    #[tokio::test]
    async fn governance_manifest_enforces_quorum_metadata() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator_primary, primary_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator_primary);
        let (validator_secondary, _secondary_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator_secondary);
        let mut protected = BTreeSet::new();
        protected.insert(Name::from_str("apps").expect("static namespace"));
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator_primary.clone(), validator_secondary.clone()],
            quorum: Some(2),
            protected_namespaces: protected,
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "gov".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator_primary,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = iroha_crypto::Hash::new(b"demo");
        let activate = InstructionBox::from(ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        });
        // Without additional approvals the quorum rule must reject the transaction.
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            validator_primary.clone(),
            &primary_keypair,
            &time_source,
            vec![activate.clone()],
            metadata,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("quorum without approvals should reject");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_quorum_total
                .with_label_values(&["rejected"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["quorum_rejected"])
                .get(),
            1
        );
        // Duplicate metadata approvals are malformed even when the unique approver set
        // would satisfy quorum.
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        metadata.insert(
            (*super::GOV_APPROVERS_METADATA_KEY).clone(),
            Json::new(vec![
                validator_secondary.to_string(),
                validator_secondary.to_string(),
            ]),
        );
        let tx = accepted_tx_with(
            validator_primary.clone(),
            &primary_keypair,
            &time_source,
            vec![activate.clone()],
            metadata,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("duplicate manifest approvers should reject");
        match err.err {
            Error::GovernanceNotPermitted { reason, .. } => {
                assert!(
                    reason.contains("duplicate approvers"),
                    "expected duplicate approver rejection, got {reason}"
                );
            }
            other => panic!("expected governance rejection, got {other:?}"),
        }
        // Attach metadata listing the secondary validator so the quorum threshold is satisfied.
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        metadata.insert(
            (*super::GOV_APPROVERS_METADATA_KEY).clone(),
            Json::new(vec![validator_secondary.to_string()]),
        );
        let tx = accepted_tx_with(
            validator_primary.clone(),
            &primary_keypair,
            &time_source,
            vec![activate],
            metadata,
        );
        queue
            .push(tx, state.view())
            .expect("quorum satisfied via metadata approvals");
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_quorum_total
                .with_label_values(&["satisfied"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["allowed"])
                .get(),
            1
        );
    }
    #[tokio::test]
    async fn governance_manifest_rejects_non_validator_authority_for_protected_contract_ops() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator_id, _validator_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator_id);
        let (other_id, other_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &other_id);
        let mut protected = BTreeSet::new();
        protected.insert(Name::from_str("apps").expect("static namespace"));
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator_id.clone()],
            protected_namespaces: protected,
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "gov".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator_id,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = iroha_crypto::Hash::new(b"demo");
        let activate = InstructionBox::from(ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        });
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            other_id.clone(),
            &other_keypair,
            &time_source,
            vec![activate],
            metadata,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("protected contract operations must still require validator authority");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["non_validator_authority"])
                .get(),
            1
        );
    }
    #[tokio::test]
    async fn governance_manifest_rejects_duplicate_validator_set_for_protected_contract_ops() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator_id, validator_keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator_id);
        let mut protected = BTreeSet::new();
        protected.insert(Name::from_str("apps").expect("static namespace"));
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator_id.clone(), validator_id.clone()],
            protected_namespaces: protected,
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "gov".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator_id,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = iroha_crypto::Hash::new(b"demo");
        let activate = InstructionBox::from(ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        });
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            validator_id,
            &validator_keypair,
            &time_source,
            vec![activate],
            metadata,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("duplicate manifest validators must fail closed");
        match err.err {
            Error::GovernanceNotPermitted { reason, .. } => {
                assert!(
                    reason.contains("duplicate validators"),
                    "expected duplicate validator rejection, got {reason}"
                );
            }
            other => panic!("expected governance rejection, got {other:?}"),
        }
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["malformed_validators"])
                .get(),
            1
        );
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn governance_manifest_enforces_protected_namespace_metadata() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator, keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator);
        let mut protected = BTreeSet::new();
        protected.insert(Name::from_str("apps").expect("static namespace"));
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator.clone()],
            protected_namespaces: protected,
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "gov".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let other_contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = iroha_crypto::Hash::new(b"demo");
        let activate = InstructionBox::from(ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        });
        // Metadata with a governed contract address is accepted for protected contract ops.
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![activate.clone()],
            metadata,
        );
        queue
            .push(tx, state.view())
            .expect("governed contract metadata should be accepted");
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["allowed"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["protected_namespace_rejected"])
                .get(),
            0
        );
        // Missing governance contract address metadata must be rejected.
        let metadata_missing_cid = Metadata::default();
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![activate.clone()],
            metadata_missing_cid,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("missing contract id metadata must reject");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["rejected"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["protected_namespace_rejected"])
                .get(),
            1
        );
        // Mismatched contract-address hints must be rejected.
        let mut valid_metadata = Metadata::default();
        valid_metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        valid_metadata.insert(
            (*super::CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(other_contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![activate],
            valid_metadata,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("mismatched contract-address metadata must reject");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["allowed"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["allowed"])
                .get(),
            1
        );
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn governance_manifest_requires_metadata_for_contract_namespace_ops() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator, keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator);
        let mut protected = BTreeSet::new();
        protected.insert(Name::from_str("apps").expect("static namespace"));
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator.clone()],
            protected_namespaces: protected,
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "gov".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let other_contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let code_hash = iroha_crypto::Hash::new(b"demo");
        let activate = InstructionBox::from(ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        });
        // Missing metadata must reject when touching a protected namespace.
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![activate.clone()],
            Metadata::default(),
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("protected namespace operations require governance metadata");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["rejected"])
                .get(),
            1
        );
        // Metadata contract address present but mismatched should reject.
        let mut metadata_mismatch = Metadata::default();
        metadata_mismatch.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(other_contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![activate.clone()],
            metadata_mismatch,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("contract_id mismatch must reject");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["rejected"])
                .get(),
            2
        );
        // Matching metadata should allow the transaction.
        let mut metadata_ok = Metadata::default();
        metadata_ok.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![activate],
            metadata_ok,
        );
        queue
            .push(tx, state.view())
            .expect("matching metadata must allow");
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_protected_namespace_total
                .with_label_values(&["allowed"])
                .get(),
            1
        );
        // Contract artifact instructions must also carry governance metadata.
        let (code_hash, code) = minimal_contract_bytes();
        let total_size = u64::try_from(code.len()).expect("contract fixture size fits u64");
        let artifact_operations = [
            (
                "register bytes",
                InstructionBox::from(RegisterSmartContractBytes {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        code_hash,
                    ),
                    code: code.clone(),
                }),
            ),
            (
                "upload chunk",
                InstructionBox::from(UploadSmartContractCodeChunk {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        code_hash,
                    ),
                    total_size,
                    chunk_index: 0,
                    chunk_count: 1,
                    chunk: code,
                }),
            ),
            (
                "finalize upload",
                InstructionBox::from(FinalizeSmartContractCodeUpload {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        code_hash,
                    ),
                    total_size,
                    chunk_count: 1,
                }),
            ),
        ];
        for (label, operation) in artifact_operations {
            let tx = accepted_tx_with(
                validator.clone(),
                &keypair,
                &time_source,
                vec![operation.clone()],
                Metadata::default(),
            );
            let err = queue
                .push(tx, state.view())
                .expect_err("contract artifact operation requires governance metadata");
            assert!(
                matches!(err.err, Error::GovernanceNotPermitted { .. }),
                "unexpected {label} admission result: {err:?}"
            );
            let mut metadata = Metadata::default();
            metadata.insert(
                (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
                Json::new(contract_address.to_string()),
            );
            let tx = accepted_tx_with(
                validator.clone(),
                &keypair,
                &time_source,
                vec![operation],
                metadata,
            );
            queue
                .push(tx, state.view())
                .unwrap_or_else(|error| panic!("{label} metadata should be satisfied: {error:?}"));
        }
        let cancel = InstructionBox::from(
            iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    code_hash,
                ),
            },
        );
        let tx = accepted_tx_with(
            validator,
            &keypair,
            &time_source,
            vec![cancel],
            Metadata::default(),
        );
        queue
            .push(tx, state.view())
            .expect("owner cleanup must not require deployment governance metadata");
    }
    #[tokio::test]
    async fn governance_manifest_rejects_cross_namespace_rebind() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = world_with_test_domains();
        let (validator, keypair) = gen_account_in("wonderland");
        let existing_contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &validator,
            7,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let state = Arc::new(State::new(world, kura.clone(), query_handle.clone()));
        register_test_authority(&state, &validator);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let mut protected = BTreeSet::new();
        protected.insert(Name::from_str("apps").expect("static namespace"));
        protected.insert(Name::from_str("ops").expect("static namespace"));
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            validators: vec![validator.clone()],
            protected_namespaces: protected,
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "gov".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let code_hash = iroha_crypto::Hash::new(b"demo");
        let instruction_contract_address =
            iroha_data_model::smart_contract::ContractAddress::derive(
                &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                    .parse()
                    .expect("canonical test network id"),
                &validator,
                8,
                DataSpaceId::UNIVERSAL,
            )
            .expect("contract address");
        let activate = InstructionBox::from(ActivateContractInstance {
            contract_address: instruction_contract_address,
            expected_revision: 1,
            code_hash,
        });
        let mut metadata = Metadata::default();
        metadata.insert(
            (*super::GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
            Json::new(existing_contract_address.to_string()),
        );
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![activate],
            metadata,
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("cross-namespace rebinding must be rejected");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
    }
    #[tokio::test]
    async fn governance_manifest_runtime_upgrade_hook_blocks_when_disabled() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator, keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator);
        let mut statuses = BTreeMap::new();
        let rules = GovernanceRules {
            hooks: GovernanceHooks {
                runtime_upgrade: Some(RuntimeUpgradeHook {
                    allow: false,
                    require_metadata: false,
                    metadata_key: None,
                    allowed_ids: None,
                }),
                ..GovernanceHooks::default()
            },
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "upgrade".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let tx = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            Metadata::default(),
        );
        let err = queue
            .push(tx, state.view())
            .expect_err("runtime upgrade instructions must be rejected when hook is disabled");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_hook_total
                .with_label_values(&["runtime_upgrade", "rejected"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["runtime_hook_rejected"])
                .get(),
            1
        );
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn governance_manifest_runtime_upgrade_hook_requires_metadata() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        #[cfg(feature = "telemetry")]
        let metrics = Arc::new(Metrics::default());
        #[cfg(feature = "telemetry")]
        let state = Arc::new(State::with_telemetry(
            world_with_test_domains(),
            kura.clone(),
            query_handle.clone(),
            StateTelemetry::new(metrics.clone(), true),
        ));
        #[cfg(not(feature = "telemetry"))]
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let (validator, keypair) = gen_account_in("wonderland");
        register_test_authority(&state, &validator);
        let mut statuses = BTreeMap::new();
        let metadata_key = Name::from_str("gov_upgrade_id").expect("static metadata key");
        let mut allowed_ids = BTreeSet::new();
        allowed_ids.insert(RUNTIME_UPGRADE_ALLOWED_ID.to_string());
        let rules = GovernanceRules {
            hooks: GovernanceHooks {
                runtime_upgrade: Some(RuntimeUpgradeHook {
                    allow: true,
                    require_metadata: true,
                    metadata_key: Some(metadata_key.clone()),
                    allowed_ids: Some(allowed_ids),
                }),
                ..GovernanceHooks::default()
            },
            ..GovernanceRules::default()
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "upgrade".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        statuses.insert(LaneId::SINGLE, status);
        let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
        queue.install_lane_manifests_for_testing(&manifests);
        let tx_missing_metadata = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            Metadata::default(),
        );
        let err = queue
            .push(tx_missing_metadata, state.view())
            .expect_err("hook requires metadata and should reject when absent");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_hook_total
                .with_label_values(&["runtime_upgrade", "rejected"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["runtime_hook_rejected"])
                .get(),
            1
        );
        let mut wrong_metadata = Metadata::default();
        wrong_metadata.insert(metadata_key.clone(), Json::new("not-allowed"));
        let tx_wrong = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            wrong_metadata,
        );
        let err = queue
            .push(tx_wrong, state.view())
            .expect_err("hook must reject metadata values outside allowlist");
        assert!(matches!(err.err, Error::GovernanceNotPermitted { .. }));
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_hook_total
                .with_label_values(&["runtime_upgrade", "rejected"])
                .get(),
            2
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["runtime_hook_rejected"])
                .get(),
            2
        );
        let mut valid_metadata = Metadata::default();
        valid_metadata.insert(metadata_key.clone(), Json::new(RUNTIME_UPGRADE_ALLOWED_ID));
        let tx_valid = accepted_tx_with(
            validator.clone(),
            &keypair,
            &time_source,
            vec![runtime_upgrade_instruction()],
            valid_metadata,
        );
        queue
            .push(tx_valid, state.view())
            .expect("hook should allow runtime upgrade with approved metadata");
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_hook_total
                .with_label_values(&["runtime_upgrade", "allowed"])
                .get(),
            1
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            metrics
                .governance_manifest_admission_total
                .with_label_values(&["allowed"])
                .get(),
            1
        );
    }
    fn accepted_tx_by_someone(time_source: &TimeSource) -> AcceptedTransaction<'static> {
        accepted_tx_by(
            AccountId::new(ALICE_KEYPAIR.public_key().clone()),
            &ALICE_KEYPAIR,
            time_source,
        )
    }
    fn register_accepted_tx_authority_for_queue_test(
        state: &mut State,
        transaction: &AcceptedTransaction<'_>,
    ) {
        register_test_authority(state, transaction.as_ref().authority());
    }
    fn accepted_unique_entrypoint_tx_by_someone(
        time_source: &TimeSource,
    ) -> AcceptedTransaction<'static> {
        let domain_name = unique_test_domain_name("reservation");
        let instructions = vec![InstructionBox::from(Unregister::domain(
            DomainId::try_new(&domain_name, "universal").expect("unique reservation domain"),
        ))];
        accepted_tx_with(
            AccountId::new(ALICE_KEYPAIR.public_key().clone()),
            &ALICE_KEYPAIR,
            time_source,
            instructions,
            Metadata::default(),
        )
    }
    #[cfg(feature = "telemetry")]
    fn accepted_tx_in_dataspace_by_someone(
        dataspace_alias: &str,
        time_source: &TimeSource,
    ) -> AcceptedTransaction<'static> {
        let domain_name = unique_test_domain_name("dummy");
        let instructions = vec![InstructionBox::from(Unregister::domain(
            DomainId::try_new(&domain_name, dataspace_alias).unwrap(),
        ))];
        accepted_tx_with(
            AccountId::new(ALICE_KEYPAIR.public_key().clone()),
            &ALICE_KEYPAIR,
            time_source,
            instructions,
            Metadata::default(),
        )
    }
    #[test]
    fn shared_queue_transactions_have_registered_authority_and_unique_entrypoints() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let transactions = [
            accepted_tx_by_someone(&time_source),
            accepted_tx_by_someone(&time_source),
            accepted_tx_by_someone(&time_source),
            accepted_unique_entrypoint_tx_by_someone(&time_source),
            accepted_unique_entrypoint_tx_by_someone(&time_source),
        ];
        let view = state.view();
        let mut hashes = BTreeSet::new();
        for transaction in transactions {
            assert!(
                view.world()
                    .accounts()
                    .get(transaction.as_ref().authority())
                    .is_some()
            );
            assert!(hashes.insert(transaction.hash_as_entrypoint()));
        }
    }
    #[test]
    fn compute_tx_encoded_len_matches_payload() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let tx = accepted_tx_by_someone(&time_source);
        let expected = tx.entrypoint_bytes().len();
        assert_eq!(Queue::compute_tx_encoded_len(&tx), expected);
    }
    #[test]
    fn retained_byte_cost_floor_scales_with_incoming_count() {
        let one = Queue::retained_byte_cost_floor_for_transactions(1);
        assert!(one > 0, "each incoming tx must carry a non-zero floor");
        assert_eq!(Queue::retained_byte_cost_floor_for_transactions(0), 0);
        assert_eq!(Queue::retained_byte_cost_floor_for_transactions(3), one * 3);
    }
    #[test]
    fn provisional_queue_manifests_require_fast_quarantine() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let original = queue.lane_manifests.read().clone();
        let error = queue
            .install_provisional_empty_lane_manifests_for_emergency_fast_startup()
            .expect_err("an ordinary Queue cannot install provisional manifests");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(Arc::ptr_eq(&*queue.lane_manifests.read(), &original));

        queue
            .enter_emergency_fast_startup()
            .expect("a fresh Queue can enter Fast quarantine");
        queue
            .install_provisional_empty_lane_manifests_for_emergency_fast_startup()
            .expect("a quarantined Queue admits only an empty provisional registry");
        assert!(queue.lane_manifests.read().statuses().is_empty());
        assert!(
            queue
                .lane_manifests
                .read()
                .validate_materialized_source_projection()
                .is_err()
        );
        assert!(queue.emergency_fast_startup.load(Ordering::Acquire));
    }
    #[test]
    fn emergency_fast_queue_quarantine_rejects_local_admission() {
        let mut state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        queue.enter_emergency_fast_startup().unwrap();
        queue.enter_emergency_fast_startup().unwrap();
        assert!(queue.admission_faulted());
        let tx = accepted_tx_by_someone(&time_source);
        register_accepted_tx_authority_for_queue_test(&mut state, &tx);
        let failure = queue
            .push(tx, state.view())
            .expect_err("Fast quarantine rejects admission");
        assert!(matches!(failure.err, Error::AdmissionInvariant { .. }));
        assert_eq!(queue.active_len(), 0);
    }
    #[test]
    fn queue_rejects_unregistered_authority_before_expensive_admission() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let key_pair = checked_random_queue_keypair();
        let authority = AccountId::new(key_pair.public_key().clone());
        assert!(state.view().world().accounts().get(&authority).is_none());
        let tx = accepted_tx_with(
            authority.clone(),
            &key_pair,
            &time_source,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "unregistered authority".into(),
            ))],
            Metadata::default(),
        );
        let failure = queue
            .push(tx, state.view())
            .expect_err("ordinary unregistered authority must fail at queue admission");
        assert!(matches!(
            failure.err,
            Error::UnregisteredAuthority {
                authority: rejected
            } if rejected == authority
        ));
        assert_eq!(queue.active_len(), 0);
    }
    #[test]
    fn queue_preserves_self_registration_bootstrap() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let key_pair = checked_random_queue_keypair();
        let authority = AccountId::new(key_pair.public_key().clone());
        let tx = accepted_tx_with(
            authority.clone(),
            &key_pair,
            &time_source,
            vec![InstructionBox::from(Register::account(Account::new(
                authority,
            )))],
            Metadata::default(),
        );
        queue
            .push(tx, state.view())
            .expect("exact self-registration remains the intentional bootstrap exception");
        assert_eq!(queue.active_len(), 1);
    }
    #[test]
    fn committed_sealed_signed_alias_releases_ordinary_sibling_carriers() {
        let mut state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let (authority, keypair) = gen_account_in("sealed-queue-cleanup");
        let signed = TransactionBuilder::new(
            state.network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sealed queue cleanup".into())])
        .sign(keypair.private_key());
        let deadline = 9;
        let carriers = [[0x51; 32], [0x52; 32]].map(|salt| {
            AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(
                TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
                    compute_sealed_transaction_commitment(
                        &state.network_id,
                        &signed,
                        salt,
                        deadline,
                    ),
                    signed.clone(),
                    salt,
                )),
            ))
        });
        register_accepted_tx_authority_for_queue_test(&mut state, &carriers[0]);
        for carrier in carriers {
            queue
                .push(carrier, state.view())
                .expect("distinct reveal carriers may be pending before either alias commits");
        }
        assert_eq!(queue.active_len(), 2);
        {
            let mut transactions = state.transactions.block();
            transactions
                .insert_block_with_single_tx(signed.hash_as_entrypoint(), nonzero!(1_usize));
            transactions
                .commit()
                .expect("commit authenticated signed reveal alias");
        }

        assert!(
            queue.gossip_batch_with_state(2, &state).is_empty(),
            "committed signed aliases cannot be gossiped again"
        );
        assert_eq!(queue.active_len(), 0);
        assert_eq!(queue.retained_bytes(), 0);
    }
    #[test]
    fn retained_byte_budget_rejects_before_count_capacity_and_releases_on_remove() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let first = accepted_tx_by_someone(&time_source);
        let first_hash = first.as_ref().hash_as_entrypoint();
        let first_cost = Queue::retained_byte_cost(Queue::compute_tx_encoded_len(&first));
        let mut cfg = config_factory();
        cfg.capacity = nonzero!(16_usize);
        cfg.capacity_per_user = nonzero!(16_usize);
        cfg.max_retained_bytes = NonZeroU64::new(first_cost).expect("non-zero retained cost");
        let queue = Queue::test(cfg, &time_source);
        queue
            .push(first, state.view())
            .expect("first tx fits budget");
        assert_eq!(queue.retained_bytes(), first_cost);
        let pressure = queue.pressure_snapshot();
        assert!(pressure.saturated_by_bytes);
        assert!(!pressure.saturated_by_count);
        assert!(queue.current_backpressure().is_saturated());
        let second = accepted_tx_by_someone(&time_source);
        let err = queue
            .push(second, state.view())
            .expect_err("byte budget should reject second tx before count capacity");
        assert!(matches!(err.err, Error::Full));
        assert_eq!(queue.active_len(), 1);
        assert_eq!(queue.retained_bytes(), first_cost);
        assert_eq!(
            queue.remove_committed_hashes(std::iter::once(first_hash), None),
            1
        );
        assert_eq!(queue.retained_bytes(), 0);
        assert!(!queue.pressure_snapshot().saturated_by_bytes);
    }
    mod resident_owner_tests {
        use super::*;
        include!("queue/resident_owner_tests.rs");
    }
    include!("queue/current_admission_tests.rs");
    include!("queue/domain_admission_tests.rs");
    include!("queue/resource_contract_tests.rs");
    #[test]
    fn push_wakes_sumeragi_when_configured() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut state = State::new(world_with_test_domains(), kura, query_handle);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Queue::test(config_factory(), &time_source);
        let (wake_tx, wake_rx) = std::sync::mpsc::sync_channel(1);
        queue.set_sumeragi_wake(wake_tx);
        let transaction = accepted_tx_by_someone(&time_source);
        register_accepted_tx_authority_for_queue_test(&mut state, &transaction);
        queue
            .push(transaction, state.view())
            .expect("push should succeed");
        assert!(matches!(wake_rx.try_recv(), Ok(())));
    }
    #[test]
    fn bounded_pending_snapshot_caps_fee_exempt_sccp_transactions() {
        use crate::{
            smartcontracts::isi::sccp::{
                admission::{self, SccpExemptClassV1},
                bridge_keys, roster, subjects,
                test_support::sample_bridge_key_state,
            },
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig, fixture_validators},
        };
        use iroha_data_model::{
            IntoKeyValue, isi::sccp::SubmitSccpAttestationsV1,
            sccp::attestation::SccpAttestationSignatureV1,
        };
        use iroha_sccp::v1::key_file::SccpBridgeKeyFileV1;

        let bridge_keys = (1_u8..=4)
            .map(|seed| SccpBridgeKeyFileV1::new([seed; 32], 0).expect("bridge key"))
            .collect::<Vec<_>>();
        let mut world = world_with_test_domains();
        for key in &bridge_keys {
            let account = bridge_keys::account_of(&key.public_key().expect("bridge public key"))
                .expect("bridge account");
            let (id, value) = Account::new(account.clone())
                .build(&account)
                .into_key_value();
            world.accounts.insert(id, value);
        }
        let alice = AccountId::new(ALICE_KEYPAIR.public_key().clone());
        let (id, value) = Account::new(alice.clone()).build(&alice).into_key_value();
        world.accounts.insert(id, value);
        {
            let mut parameters = iroha_data_model::sccp::params::SccpParametersV1::taira_default();
            parameters.max_exempt_transactions_per_block = 1;
            let mut world = world.block();
            *world.sccp_parameters.get_mut() = Some(parameters);
            for ((peer, _), key) in fixture_validators().into_iter().zip(&bridge_keys) {
                let mut binding = sample_bridge_key_state(1);
                let active = binding.active.as_mut().expect("active bridge key");
                active.public_key = key.public_key().expect("bridge public key");
                active.address = key.address().expect("bridge address");
                // A registered key's owner index makes its attestations eligible.
                world
                    .sccp_bridge_key_owners
                    .insert(active.address, peer.clone());
                world.sccp_bridge_keys.insert(peer, binding);
            }
            world.commit();
        }
        // Genesis creates the real bridge roster; its initial non-rotation height
        // has no attestation subject. Commit actual signed work at the original
        // roster's heartbeat to obtain a certified rotation subject.
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(world, 0)).expect("signed SCCP genesis");
        assert!(subjects::statement_digest_of(&chain.state().view(), 1).is_none());
        let heartbeat = {
            let view = chain.state().view();
            let (_, original_roster) =
                roster::current(view.world()).expect("original genesis roster");
            original_roster
                .valid_from_ms
                .checked_add(
                    view.world()
                        .sccp_parameters()
                        .as_ref()
                        .unwrap()
                        .roster_max_age_ms,
                )
                .expect("original heartbeat time fits u64")
        };
        let work = chain.sign(
            &ALICE_KEYPAIR,
            [Log::new(Level::INFO, "certified SCCP heartbeat".into()).into()],
            heartbeat,
        );
        assert_eq!(chain.commit_at(heartbeat, vec![work]), vec![true]);
        let subject_height = chain.height();
        let state = chain.state();
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::from_millis(heartbeat));
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let accepted = |keypair: &KeyPair, instructions: Vec<InstructionBox>| {
            let transaction = TransactionBuilder::new_with_time_source(
                state.network_id,
                AccountId::new(keypair.public_key().clone()),
                &time_source,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions(instructions)
            .sign(keypair.private_key());
            let view = state.view();
            AcceptedTransaction::accept_with_time_source(
                transaction,
                state.network_id_ref(),
                view.world().parameters().sumeragi().max_clock_drift(),
                view.world().parameters().transaction(),
                &state.crypto(),
                &time_source,
            )
            .expect("signed queue input accepted")
        };
        let attestation = |key: &SccpBridgeKeyFileV1| {
            let view = state.view();
            let (_, roster) = roster::current(view.world()).expect("committed SCCP roster");
            assert_eq!(roster.members.len(), 4);
            assert!(!roster.is_inert());
            let address = key.address().expect("bridge address");
            let signer_index = u8::try_from(
                roster
                    .members
                    .iter()
                    .position(|member| member.address == address)
                    .expect("original bridge key is a roster member"),
            )
            .expect("four-member index fits u8");
            let digest = subjects::statement_digest_of(&view, subject_height)
                .expect("original committed heartbeat statement digest");
            let instruction = SubmitSccpAttestationsV1 {
                entries: vec![SccpAttestationSignatureV1 {
                    height: subject_height,
                    signer_index,
                    signature: key.sign_digest(&digest).expect("sign committed statement"),
                }],
            };
            drop(view);
            let signer = KeyPair::from_private_key(
                iroha_crypto::PrivateKey::from_bytes(Algorithm::Secp256k1, key.secret())
                    .expect("bridge signing scalar"),
            )
            .expect("bridge signing keypair");
            accepted(&signer, vec![instruction.into()])
        };
        // Concurrent claims use distinct actual bridge accounts; an account may retain
        // only one pending attestation batch under the SCCP admission contract.
        let transactions = vec![
            attestation(&bridge_keys[0]),
            attestation(&bridge_keys[1]),
            accepted(
                &ALICE_KEYPAIR,
                vec![Log::new(Level::INFO, "ordinary".into()).into()],
            ),
        ];
        let hashes = transactions
            .iter()
            .map(AcceptedTransaction::hash_as_entrypoint)
            .collect::<Vec<_>>();
        for transaction in transactions {
            queue.push(transaction, state.view()).expect("push");
        }
        assert_eq!(
            queue.pending_sccp_exempt.lock().len(),
            2,
            "both authenticated admission claims remain resident before bounded selection"
        );
        let snapshot = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(16_usize))
            .expect("queue selection must remain healthy");
        let selected = snapshot
            .iter()
            .map(AcceptedTransaction::hash_as_entrypoint)
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![hashes[0], hashes[2]],
            "one eligible SCCP transaction fits the cap; ordinary work is unaffected"
        );
        assert!(
            queue.contains_entrypoint_hash(hashes[1]),
            "the capped one stays queued"
        );
        let view = state.view();
        let classes = snapshot
            .iter()
            .filter_map(|transaction| {
                admission::exempt_class_of_entrypoint(view.world(), transaction.entrypoint())
            })
            .collect::<Vec<_>>();
        assert_eq!(classes, vec![SccpExemptClassV1::Attestation]);
        assert_eq!(queue.pending_sccp_exempt.lock().len(), 2);
        assert_eq!(
            queue.pending_sccp_exempt.lock().class_of(&hashes[1]),
            Some(SccpExemptClassV1::Attestation),
            "selection preserves the capped input's original admission ownership"
        );
        assert!(
            admission::block_exempt_cap_ok(view.world(), &classes),
            "block validation accepts exactly what the proposer selected"
        );
        assert!(!admission::block_exempt_cap_ok(
            view.world(),
            &[SccpExemptClassV1::Attestation; 2]
        ));
    }
    #[test]
    fn sccp_claim_refusals_map_onto_existing_admission_errors() {
        assert!(matches!(
            Queue::sccp_pending_claim_error(SccpPendingClaimErrorV1::NothingNew),
            Error::IsInQueue
        ));
        assert!(matches!(
            Queue::sccp_pending_claim_error(SccpPendingClaimErrorV1::EntrypointClaimed),
            Error::IsInQueue
        ));
        let holder = HashOf::from_untyped_unchecked(Hash::prehashed([7; 32]));
        assert!(matches!(
            Queue::sccp_pending_claim_error(SccpPendingClaimErrorV1::ExclusiveHeld { holder }),
            Error::NexusFeeAdmissionRejected {
                code: FeeRejectionCode::OperationNotAllowed,
                ..
            }
        ));
    }
    #[test]
    fn bounded_pending_snapshot_is_fifo_bounded_and_non_destructive() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world_with_test_domains(), kura, query_handle);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let first = accepted_tx_by_someone(&time_source);
        let first_hash = first.hash_as_entrypoint();
        let second = accepted_tx_by_someone(&time_source);
        let second_hash = second.hash_as_entrypoint();
        queue.push(first, state.view()).expect("push first");
        queue.push(second, state.view()).expect("push second");
        let snapshot = queue
            .bounded_pending_snapshot(&state.view(), NonZeroUsize::new(1).expect("non-zero bound"))
            .expect("queue selection must remain healthy");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].hash_as_entrypoint(), first_hash);
        assert!(queue.contains_entrypoint_hash(first_hash));
        assert!(queue.contains_entrypoint_hash(second_hash));
        assert_eq!(queue.active_len(), 2);
    }
    #[test]
    fn bounded_pending_snapshot_accepts_maximal_scan_limit_without_oversized_allocation() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut state = State::new(world_with_test_domains(), kura, query_handle);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let max_scan = NonZeroUsize::new(usize::MAX).expect("non-zero bound");
        let empty = queue
            .bounded_pending_snapshot(&state.view(), max_scan)
            .expect("an empty queue must not allocate for the configured scan limit");
        assert!(empty.is_empty());

        let first = accepted_tx_by_someone(&time_source);
        register_accepted_tx_authority_for_queue_test(&mut state, &first);
        let first_hash = first.hash_as_entrypoint();
        let second = accepted_tx_by_someone(&time_source);
        register_accepted_tx_authority_for_queue_test(&mut state, &second);
        let second_hash = second.hash_as_entrypoint();
        queue.push(first, state.view()).expect("push first");
        queue.push(second, state.view()).expect("push second");
        let first_snapshot = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .expect("select the first transaction");
        assert_eq!(first_snapshot.len(), 1);
        assert_eq!(first_snapshot[0].hash_as_entrypoint(), first_hash);

        let second_snapshot = queue
            .bounded_pending_snapshot(&state.view(), max_scan)
            .expect("allocation must follow the remaining queue suffix");
        assert_eq!(second_snapshot.len(), 1);
        assert_eq!(second_snapshot[0].hash_as_entrypoint(), second_hash);
        assert_eq!(queue.active_len(), 2);
        assert_eq!(queue.queued_len(), 2);
        assert!(queue.contains_entrypoint_hash(first_hash));
        assert!(queue.contains_entrypoint_hash(second_hash));
    }
    #[test]
    fn bounded_pending_snapshot_excludes_committed_front() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let first = accepted_tx_by_someone(&time_source);
        let first_hash = first.hash_as_entrypoint();
        let second = accepted_tx_by_someone(&time_source);
        let second_hash = second.hash_as_entrypoint();
        queue.push(first, state.view()).unwrap();
        queue.push(second, state.view()).unwrap();
        assert_eq!(queue.remove_committed_hashes([first_hash], None), 1);
        let snapshot = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(2_usize))
            .unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].hash_as_entrypoint(), second_hash);
        assert_eq!(queue.active_len(), 1);
    }
    #[test]
    fn bounded_pending_snapshot_charges_stale_front_pruning_to_scan_budget() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut state = State::new(world_with_test_domains(), kura, query_handle);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let first = accepted_tx_by_someone(&time_source);
        register_accepted_tx_authority_for_queue_test(&mut state, &first);
        let first_hash = first.hash_as_entrypoint();
        let second = accepted_tx_by_someone(&time_source);
        register_accepted_tx_authority_for_queue_test(&mut state, &second);
        let second_hash = second.hash_as_entrypoint();
        let third = accepted_tx_by_someone(&time_source);
        register_accepted_tx_authority_for_queue_test(&mut state, &third);
        let third_hash = third.hash_as_entrypoint();
        queue.push(first, state.view()).expect("push first");
        queue.push(second, state.view()).expect("push second");
        queue.push(third, state.view()).expect("push third");
        // Observe the intermediate stale-ring state before the ordinary pop path publishes
        // backpressure and lazily prunes these entries while measuring queue age.
        queue.queued_tx_enqueued_at_ms.remove(&first_hash);
        queue.queued_tx_enqueued_at_ms.remove(&second_hash);
        let one = NonZeroUsize::new(1).expect("non-zero bound");
        assert!(
            queue
                .bounded_pending_snapshot(&state.view(), one)
                .expect("queue selection must remain healthy")
                .is_empty(),
            "first call spends its only scan slot pruning the first stale entry"
        );
        assert!(
            queue
                .bounded_pending_snapshot(&state.view(), one)
                .expect("queue selection must remain healthy")
                .is_empty(),
            "second call spends its only scan slot pruning the second stale entry"
        );
        let snapshot = queue
            .bounded_pending_snapshot(&state.view(), one)
            .expect("queue selection must remain healthy");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].hash_as_entrypoint(), third_hash);
    }
    #[test]
    fn native_snapshot_retains_encoded_length_and_gas_until_commit_cleanup() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let tx = accepted_tx_by_someone(&time_source);
        let hash = tx.hash_as_entrypoint();
        let signed_len = tx.encoded_len();
        let original_frame = tx.entrypoint_bytes();
        let encoded_len = original_frame.len();
        let expected_gas = Queue::compute_proposal_gas_cost(&tx).unwrap();
        queue.push(tx, state.view()).unwrap();
        let snapshot = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .unwrap();
        assert_eq!(snapshot[0].entrypoint_bytes().len(), encoded_len);
        assert_eq!(snapshot[0].encoded_len(), signed_len);
        assert_eq!(
            snapshot[0].entrypoint_bytes().as_slice(),
            original_frame.as_slice()
        );
        assert_eq!(
            Queue::compute_proposal_gas_cost(&snapshot[0]),
            Ok(expected_gas)
        );
        drop(snapshot);
        assert_eq!(*queue.tx_encoded_len.get(&hash).unwrap(), encoded_len);
        assert_eq!(*queue.tx_gas_cost.get(&hash).unwrap(), expected_gas);
        assert_eq!(queue.remove_committed_hashes([hash], None), 1);
        assert!(queue.tx_encoded_len.is_empty());
        assert!(queue.tx_gas_cost.is_empty());
    }
    #[test]
    fn sealed_network_sources_preserve_routing_identity_and_queue_costs() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::from_secs(1));
        let (authority, keypair) = gen_account_in("sealed-network-queue");
        let signed = TransactionBuilder::new_with_time_source(
            queue_test_network_id(),
            authority.clone(),
            &time_source,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "sealed queue accounting".into())])
        .sign(keypair.private_key());
        let salt = [0x53; 32];
        let deadline = 9;
        let commitment_hash = compute_sealed_transaction_commitment(
            &queue_test_network_id(),
            &signed,
            salt,
            deadline,
        );
        let commitment = SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(
                queue_test_network_id(),
                authority.clone(),
                commitment_hash,
                2,
                deadline,
                None,
            ),
            keypair.private_key(),
        );
        let reveal = SealedTransactionReveal::new(commitment_hash, signed.clone(), salt);
        let accept = |entrypoint| {
            AcceptedTransaction::accept_entrypoint_at_time(
                entrypoint,
                &queue_test_network_id(),
                Duration::ZERO,
                TransactionParameters::default(),
                &iroha_config::parameters::actual::Crypto::default(),
                signed.creation_time(),
            )
            .expect("signed Network source passes stateless admission")
        };
        let external = accept(TransactionEntrypoint::External(signed.clone()));
        let revealed = accept(TransactionEntrypoint::SealedReveal(reveal));
        let committed = accept(TransactionEntrypoint::SealedCommitment(commitment));
        assert_ne!(revealed.hash_as_entrypoint(), external.hash_as_entrypoint());
        assert_eq!(revealed.external(), Some(&signed));
        assert_eq!(committed.external(), None);
        assert_eq!(
            crate::tx::exact_signed_transaction_hash(revealed.entrypoint()),
            Some(signed.hash()),
        );
        assert_eq!(
            crate::tx::exact_signed_transaction_hash(committed.entrypoint()),
            None
        );
        assert_eq!(SignedTransaction::from(revealed.clone()), signed);
        assert_eq!(revealed.creation_time(), external.creation_time());
        assert_eq!(revealed.time_to_live(), external.time_to_live());
        assert_eq!(committed.creation_time(), Duration::ZERO);
        assert_eq!(committed.time_to_live(), None);
        assert_eq!(
            TransactionRoutingView::authority_opt(&revealed),
            Some(&authority)
        );
        assert_eq!(
            TransactionRoutingView::authority_opt(&committed),
            Some(&authority)
        );
        assert_eq!(
            TransactionRoutingView::executable(&revealed),
            TransactionRoutingView::executable(&external),
        );
        assert!(TransactionRoutingView::executable(&committed).is_none());
        assert_eq!(
            TransactionRoutingView::routing_hash(&revealed),
            TransactionRoutingView::routing_hash(&external),
        );
        assert_eq!(
            TransactionRoutingView::routing_hash(&committed),
            Hash::from(committed.hash_as_entrypoint()),
        );
        assert!(TransactionRoutingView::any_matching_instruction(
            &revealed,
            &mut |_| true
        ));
        assert!(!TransactionRoutingView::any_matching_instruction(
            &committed,
            &mut |_| true
        ));
        assert_eq!(
            Queue::compute_proposal_gas_cost(&revealed),
            Queue::compute_proposal_gas_cost(&external)
        );
        assert_eq!(
            Queue::compute_teu_weight(&revealed),
            Queue::compute_teu_weight(&external)
        );
        let commitment_cost = gas::meter_sealed_transaction_commitment(committed.encoded_len());
        assert_eq!(
            Queue::compute_proposal_gas_cost(&committed),
            Ok(commitment_cost)
        );
        assert_eq!(Queue::compute_teu_weight(&committed), commitment_cost);
    }
    #[test]
    fn proposal_gas_cost_fails_closed_and_charges_signed_runtime_limit() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let network_id = queue_test_network_id();
        let (authority, keypair) = gen_account_in("wonderland");
        let build_unchecked = |executable: Executable,
                               gas_limit: Option<NonZeroU64>|
         -> AcceptedTransaction<'static> {
            let signed = TransactionBuilder::new_with_time_source(
                network_id,
                authority.clone(),
                &time_source,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), gas_limit),
            )
            .with_executable(executable)
            .sign(keypair.private_key());
            AcceptedTransaction::new_unchecked(Cow::Owned(signed))
        };
        let missing_limit =
            build_unchecked(Executable::Ivm(IvmBytecode::from_compiled(vec![0])), None);
        assert_eq!(
            Queue::compute_proposal_gas_cost(&missing_limit),
            Err(ProposalGasCostError::MissingSignedGasLimit),
            "an invariant violation must not become zero-cost proposal work"
        );
        let missing_signed = missing_limit.external().expect("external fixture").clone();
        let missing_salt = [0x54; 32];
        let missing_reveal = AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(
            TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
                compute_sealed_transaction_commitment(
                    &network_id,
                    &missing_signed,
                    missing_salt,
                    9,
                ),
                missing_signed,
                missing_salt,
            )),
        ));
        assert_eq!(
            Queue::compute_proposal_gas_cost(&missing_reveal),
            Err(ProposalGasCostError::MissingSignedGasLimit),
            "wrapping an invalid runtime gas owner in a sealed reveal must not make it free",
        );
        let invocation = iroha_data_model::transaction::executable::ContractInvocation {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            expected_code_hash: Hash::new(b"proposal-gas-contract-code"),
            entrypoint: "run".to_owned(),
            arguments: None,
        };
        let signed_limit = NonZeroU64::new(77).expect("non-zero gas fixture");
        let runtime_executables = [
            Executable::ContractCall(invocation.clone()),
            Executable::Ivm(IvmBytecode::from_compiled(vec![0])),
            Executable::IvmProved(iroha_data_model::transaction::IvmProved {
                bytecode: IvmBytecode::from_compiled(vec![0]),
                overlay: vec![sample_unregister_instruction()].into(),
                events_commitment: Hash::new(b"proposal-gas-events"),
                gas_policy_commitment: Hash::new(b"proposal-gas-policy"),
            }),
            Executable::Batch(
                vec![
                    ExecutableBatchItem::Instruction(sample_unregister_instruction()),
                    ExecutableBatchItem::ContractCall(invocation),
                ]
                .into(),
            ),
        ];
        for executable in runtime_executables {
            let accepted = build_unchecked(executable, Some(signed_limit));
            assert_eq!(
                Queue::compute_proposal_gas_cost(&accepted),
                Ok(signed_limit.get()),
                "every runtime-dependent executable must consume its signed upper bound"
            );
        }
        let native_instruction = sample_unregister_instruction();
        let native_expected = gas::meter_instruction(&native_instruction);
        let native = build_unchecked(
            Executable::Instructions(vec![native_instruction].into()),
            Some(NonZeroU64::new(999).expect("non-zero ignored native limit")),
        );
        assert_eq!(
            Queue::compute_proposal_gas_cost(&native),
            Ok(native_expected),
            "deterministic native work remains charged by the instruction meter"
        );
    }
    #[test]
    fn queued_tx_metadata_cleared_on_committed_batch_cleanup() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_, time_source) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time_source));
        let first = accepted_tx_by_someone(&time_source);
        let second = accepted_tx_by_someone(&time_source);
        let hashes = [first.hash_as_entrypoint(), second.hash_as_entrypoint()];
        queue.push(first, state.view()).unwrap();
        queue.push(second, state.view()).unwrap();
        assert_eq!(
            queue
                .bounded_pending_snapshot(&state.view(), nonzero!(2_usize))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(queue.remove_committed_hashes(hashes, None), 2);
        assert_eq!(queue.remove_committed_hashes(hashes, None), 0);
        assert!(queue.txs.is_empty());
        assert!(queue.tx_encoded_len.is_empty());
        assert!(queue.tx_gas_cost.is_empty());
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn native_snapshots_preserve_order_accounting_and_pending_metadata() {
        let mut state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        install_single_validator_topology_for_queue_test(&mut state, 0xC2);
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let mut cfg = config_factory();
        cfg.capacity = nonzero!(8_usize);
        cfg.capacity_per_user = nonzero!(8_usize);
        let mut queue = Queue::test(cfg, &time_source);
        let (event_sender, mut event_receiver) = tokio::sync::broadcast::channel(16);
        queue.events_sender = event_sender;
        let queue = Arc::new(queue);
        let transactions = (0..4)
            .map(|_| accepted_tx_by_someone(&time_source))
            .collect::<Vec<_>>();
        let hashes = transactions
            .iter()
            .map(|tx| tx.as_ref().hash_as_entrypoint())
            .collect::<Vec<_>>();
        for tx in transactions {
            queue.push(tx, state.view()).expect("push transaction");
        }
        while event_receiver.try_recv().is_ok() {}
        let retained_bytes_before = queue.retained_bytes();
        let per_user_before = queue
            .txs_per_user
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect::<BTreeMap<_, _>>();
        let routing_before = hashes
            .iter()
            .map(|hash| {
                (
                    *hash,
                    queue
                        .routing_plans
                        .get(hash)
                        .map(|entry| entry.value().clone())
                        .expect("routing plan"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let enqueue_times_before = hashes
            .iter()
            .map(|hash| {
                (
                    *hash,
                    queue
                        .tx_enqueued_at_ms
                        .get(hash)
                        .map(|entry| *entry.value())
                        .expect("enqueue timestamp"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let expiry_before = hashes
            .iter()
            .filter(|hash| queue.expiry_ring_members.contains_key(hash))
            .copied()
            .collect::<BTreeSet<_>>();
        let gossip_len_before = queue.tx_gossip.len();
        #[cfg(feature = "telemetry")]
        let teu_before = queue
            .tx_teu
            .iter()
            .map(|entry| {
                (
                    *entry.key(),
                    (
                        entry.value().lane_id,
                        entry.value().dataspace_id,
                        entry.value().teu,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let state_view = state.view();
        for _ in 0..2 {
            let snapshot = queue
                .bounded_pending_snapshot(&state_view, nonzero!(4_usize))
                .unwrap();
            assert_eq!(
                snapshot
                    .iter()
                    .map(AcceptedTransaction::hash_as_entrypoint)
                    .collect::<Vec<_>>(),
                hashes
            );
            drop(snapshot);
        }
        assert_eq!(queue.active_len(), 4);
        assert_eq!(queue.queued_len(), 4);
        assert_eq!(queue.retained_bytes(), retained_bytes_before);
        assert_eq!(
            queue
                .txs_per_user
                .iter()
                .map(|entry| (entry.key().clone(), *entry.value()))
                .collect::<BTreeMap<_, _>>(),
            per_user_before
        );
        assert_eq!(
            hashes
                .iter()
                .map(|hash| {
                    (
                        *hash,
                        queue
                            .routing_plans
                            .get(hash)
                            .map(|entry| entry.value().clone())
                            .expect("routing plan after return"),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            routing_before
        );
        assert_eq!(
            hashes
                .iter()
                .map(|hash| {
                    (
                        *hash,
                        queue
                            .tx_enqueued_at_ms
                            .get(hash)
                            .map(|entry| *entry.value())
                            .expect("enqueue timestamp after return"),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            enqueue_times_before
        );
        assert_eq!(
            hashes
                .iter()
                .filter(|hash| queue.expiry_ring_members.contains_key(hash))
                .copied()
                .collect::<BTreeSet<_>>(),
            expiry_before
        );
        assert_eq!(queue.tx_gossip.len(), gossip_len_before);
        assert!(
            matches!(
                event_receiver.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "guard return must not emit a duplicate Queued event"
        );
        #[cfg(feature = "telemetry")]
        assert_eq!(
            queue
                .tx_teu
                .iter()
                .map(|entry| {
                    (
                        *entry.key(),
                        (
                            entry.value().lane_id,
                            entry.value().dataspace_id,
                            entry.value().teu,
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            teu_before
        );
        assert_eq!(queue.remove_committed_hashes(hashes, None), 4);
        assert!(queue.txs.is_empty());
    }
    include!("queue/queue_metadata_and_admission_tests.rs");
    include!("queue/instruction_and_state_routing_tests.rs");
    include!("queue/routing_batch_admission_tests.rs");
    include!("queue/config_factory_test_support.rs");
    /// Choose the complete initial catalog before constructing State and Kura.
    fn test_nexus_for_routes(routes: &[(LaneId, DataSpaceId)]) -> Nexus {
        let (lane_catalog, dataspace_catalog) = Queue::test_catalogs_for_routes(routes);
        let mut nexus = Nexus::default();
        nexus.lane_catalog = (*lane_catalog).clone();
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        nexus.lane_config = LaneGeometry::from_catalog(&nexus.lane_catalog);
        nexus.dataspace_catalog = (*dataspace_catalog).clone();
        nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
        let primary = nexus
            .lane_catalog
            .lanes()
            .iter()
            .find(|lane| lane.id == nexus.routing_policy.default_lane)
            .expect("fixture catalog contains the primary route");
        nexus.routing_policy.default_dataspace = primary.dataspace_id;
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        nexus
    }
    fn world_with_uaid_account(
        uaid: UniversalAccountId,
        dataspace: DataSpaceId,
        bind_manifest: bool,
    ) -> (World, AccountId, KeyPair) {
        let (account_id, key_pair) = gen_account_in("wonderland");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("Valid");
        let domain = Domain::new(domain_id.clone()).build(&account_id);
        let account = Account::new(account_id.clone())
            .with_uaid(Some(uaid))
            .build(&account_id);
        let mut world = World::with([domain], [account], []);
        // This queue component has explicit Global routing metadata; its UAID
        // fixtures do not authenticate a native genesis or publication source.
        let mut parameters = world.parameters.block();
        parameters.set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ));
        parameters.commit();
        if bind_manifest {
            let manifest = AssetPermissionManifest {
                version: ManifestVersion::default(),
                uaid,
                dataspace,
                issued_ms: 1,
                activation_epoch: 1,
                expiry_epoch: None,
                entries: Vec::new(),
            };
            let mut record = SpaceDirectoryManifestRecord::new(manifest);
            record.lifecycle.mark_activated(1);
            let mut set = SpaceDirectoryManifestSet::default();
            set.upsert(record);
            world.space_directory_manifests.insert(uaid, set);
            let mut bindings = UaidDataspaceBindings::default();
            bindings.bind_account(dataspace, account_id.clone());
            world.uaid_dataspaces.insert(uaid, bindings);
        }
        (world, account_id, key_pair)
    }
    include!("queue/teu_limit_and_backlog_tests.rs");
    include!("queue/routing_projection_resilience_tests.rs");
    include!("queue/capacity_and_concurrency_tests.rs");
    include!("queue/pressure_resync_tests.rs");
    include!("queue/expiry_tracking_tests.rs");
    include!("queue/pending_sampling_tests.rs");
    #[test]
    fn native_snapshot_drop_keeps_metadata_until_global_application_cleanup() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_clock, time) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time));
        let tx = accepted_tx_by_someone(&time);
        let hash = tx.hash_as_entrypoint();
        let encoded_len = tx.entrypoint_bytes().len();
        let gas = Queue::compute_proposal_gas_cost(&tx).expect("signature-bound gas");
        queue
            .push(tx, state.view())
            .expect("admit original signed input");
        let snapshot = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .expect("snapshot");
        assert_eq!(snapshot[0].hash_as_entrypoint(), hash);
        drop(snapshot);
        assert_eq!(queue.active_len(), 1);
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(
            *queue.tx_encoded_len.get(&hash).expect("retained bytes"),
            encoded_len
        );
        assert_eq!(*queue.tx_gas_cost.get(&hash).expect("retained gas"), gas);
        assert_eq!(queue.remove_committed_hashes([hash], None), 1);
        assert_eq!(queue.remove_committed_hashes([hash], None), 0);
        assert_eq!(queue.active_len(), 0);
        assert_eq!(queue.queued_len(), 0);
        assert_eq!(queue.retained_bytes(), 0);
        assert!(queue.tx_encoded_len.is_empty());
        assert!(queue.tx_gas_cost.is_empty());
        assert!(queue.routing_plans.is_empty());
        assert!(
            queue
                .fee_admission_reservations
                .lock()
                .live_by_entrypoint
                .is_empty()
        );
    }

    #[test]
    fn native_snapshot_does_not_reserve_input_against_later_lane_sampling() {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let (_clock, time) = TimeSource::new_mock(Duration::default());
        let queue = Arc::new(Queue::test(config_factory(), &time));
        let tx = accepted_tx_by_someone(&time);
        let hash = tx.hash_as_entrypoint();
        queue
            .push(tx, state.view())
            .expect("admit original signed input");
        let first = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .expect("first sample");
        let second = queue
            .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
            .expect("second sample");
        assert_eq!(first[0].hash_as_entrypoint(), hash);
        assert_eq!(second[0].hash_as_entrypoint(), hash);
        assert_eq!(queue.active_len(), 1);
        assert_eq!(queue.queued_len(), 1);
    }
}

#[cfg(test)]
#[test]
fn original_fee_admission_refusal_preserves_queue_retry_owner() {
    let budget = iroha_allocation::AllocationBudget::new(8);
    let occupied = budget.try_reserve_bytes(8).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let error = Queue::map_nexus_fee_admission_error(
        crate::execution_attempt::ExecutionAttemptError::Deferred(original.clone().into()),
    );
    let Error::Deferred(owner) = error else {
        panic!("local fee refusal became a completed queue rejection");
    };
    assert_eq!(owner.allocation_refusal(), Some(&original));
    let deterministic = Queue::map_nexus_fee_admission_error(
        NexusFeeAdmissionError::Rejected {
            code: FeeRejectionCode::AuthorityPayerInsufficient,
            reason: "actual insufficient balance".into(),
        }
        .into(),
    );
    assert!(matches!(
        deterministic,
        Error::NexusFeeAdmissionRejected {
            code: FeeRejectionCode::AuthorityPayerInsufficient,
            ..
        }
    ));
    drop(occupied);
}

#[cfg(test)]
#[test]
fn original_routing_refusal_preserves_queue_retry_owner_and_completed_errors() {
    let budget = iroha_allocation::AllocationBudget::new(8);
    let occupied = budget.try_reserve_bytes(8).unwrap();
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let error = Error::from(RoutingResolveError::Deferred(original.clone().into()));
    let Error::Deferred(owner) = error else {
        panic!("unfinished routing became a completed queue rejection");
    };
    assert_eq!(owner.allocation_refusal(), Some(&original));
    assert!(matches!(
        Error::from(RoutingResolveError::StaleRoutingPlan),
        Error::UnresolvedRoute { .. }
    ));
    drop(occupied);
    assert!(budget.try_reserve_bytes(1).is_ok());
}
