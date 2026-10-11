//! Explicit authority declarations for every actual State field.

use super::{Canonical, DerivationCheck, Field, Role, Schema, V1_LAYOUT, schema};
use crate::state::*;

// Current membership and its rollback cut are separate complete key spaces.
// A single aggregate cell would force unbounded disclosure for absence/ranges.
const TRANSACTION_MEMBERSHIP_FIELDS: &[Field] = &[
    Field::new(
        "state.transactions.frontier",
        Role::Canonical(Canonical::Cell(schema::<u64>())),
    ),
    Field::new(
        "state.transactions.current",
        Role::Canonical(Canonical::Table {
            key: schema::<HashOf<TransactionEntrypoint>>(),
            value: schema::<u64>(),
        }),
    ),
    Field::new(
        "state.transactions.rollback",
        Role::Canonical(Canonical::Table {
            key: schema::<HashOf<TransactionEntrypoint>>(),
            value: schema::<u64>(),
        }),
    ),
];

classified_owner!(State, check_state_fields, STATE_FIELDS, {
    world: World => ("state.world",
        Role::Canonical(Canonical::Owner(super::WORLD_FIELDS)));
    block_hashes: BlockHashes => ("state.block_hashes",
        Role::History { source: "Canonical SignedBlockWire/finality history in height order", authentication: "Kura authenticated recovery prefix; State block-hash publication owner" });
    native_execution_tip: native_execution_tip::TipCell => ("state.native_execution_tip",
        Role::History { source: "Original native height, Iroha hash, core header hash and execution result; current and undo cuts outside World", authentication: "Original worker verified exact quorum and output seal, or original signed-genesis execution; restore verifies the actual certified native prefix and configured chain/network before accepting snapshot claims" });
    native_world_cut: parking_lot::Mutex<Option<iroha_allocation::ChargedShared<world_projection::world_state_accumulator::world_state_cut::CutCapsule>>> => ("state.native_world_cut",
        Role::History { source: "Original pre-tail World root, count and native journal differences bound to the execution tip and publication generation", authentication: "Original completed executor captures R; frozen publication reconstructs that exact root and count from the complete native tail journal; restoration must replay original execution rather than decode a caller-supplied cut" });
    latest_block_header: PublicationRwLock<Option<BlockHeader>> => ("state.latest_block_header",
        Role::Derived { sources: &["state.block_hashes"], check: DerivationCheck::Rebuild("State::update_latest_block_header_cache from exact retained canonical tip") });
    transactions: TransactionsStorage => ("state.transactions",
        Role::Canonical(Canonical::Owner(TRANSACTION_MEMBERSHIP_FIELDS)));
    commit_topology: Cell<Vec<PeerId>> => ("state.commit_topology",
        Role::Canonical(Canonical::Cell(schema::<Vec<PeerId>>())));
    prev_commit_topology: Cell<Vec<PeerId>> => ("state.prev_commit_topology",
        Role::Canonical(Canonical::Cell(schema::<Vec<PeerId>>())));
    da_commitments: PublicationRwLock<DaCommitmentStore> => ("state.da_commitments",
        Role::Derived { sources: &["state.block_hashes"], check: DerivationCheck::Rebuild("state::da_hydration::ensure_da_indexes_hydrated; exact committed Kura prefix and rewind reconstruction") });
    da_confidential_compute: PublicationRwLock<ConfidentialComputeStore> => ("state.da_confidential_compute",
        Role::Derived { sources: &["state.block_hashes"], check: DerivationCheck::Rebuild("state::da_hydration::ensure_da_indexes_hydrated; exact committed Kura prefix and rewind reconstruction") });
    da_receipt_cursors: PublicationRwLock<DaReceiptCursorIndex> => ("state.da_receipt_cursors",
        Role::Derived { sources: &["state.block_hashes"], check: DerivationCheck::Rebuild("state::da_hydration::ensure_da_indexes_hydrated; exact committed Kura prefix and rewind reconstruction") });
    da_shard_cursors: PublicationRwLock<DaShardCursorIndex> => ("state.da_shard_cursors",
        Role::Derived { sources: &["state.block_hashes"], check: DerivationCheck::Rebuild("state::da_hydration::ensure_da_indexes_hydrated; exact committed Kura prefix and rewind reconstruction") });
    da_shard_cursor_persistor: DaShardCursorJournalPersistor => ("state.da_shard_cursor_persistor",
        Role::Local("Physical persistence/hydration coordination; authenticated logical DA/history owners are separately classified"));
    query_index_journal: parking_lot::RwLock<QueryIndexJournal> => ("state.query_index_journal",
        Role::Local("Physical query projection checkpoint descriptors; rebuildable from committed authoritative State and canonical history"));
    query_index_journal_persistence_lock: parking_lot::Mutex<()> => ("state.query_index_journal_persistence_lock",
        Role::Local("Physical persistence/hydration coordination; authenticated logical DA/history owners are separately classified"));
    query_projection_checkpoint_journal: parking_lot::RwLock<QueryProjectionCheckpointJournal> => ("state.query_projection_checkpoint_journal",
        Role::Local("Physical query projection checkpoint descriptors; rebuildable from committed authoritative State and canonical history"));
    query_projection_checkpoint_journal_persistence_lock: parking_lot::Mutex<()> => ("state.query_projection_checkpoint_journal_persistence_lock",
        Role::Local("Physical persistence/hydration coordination; authenticated logical DA/history owners are separately classified"));
    da_pin_intents: PublicationRwLock<DaPinStore> => ("state.da_pin_intents",
        Role::Derived { sources: &["world.da_pin_intents_by_ticket", "world.da_pin_intents_by_alias"], check: DerivationCheck::Rebuild("State::da_pin_cache_from_world reconstructs ticket and exact current alias bindings after World publication") });
    lane_manifests: PublicationRwLock<LaneManifestRegistryHandle> => ("state.lane_manifests",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:lane_manifests:v1", encoder: "state::authority_registry::lane_manifest_policy::canonical_preimage_once; exact installed effective/current/baseline source bytes, bound catalog and retained predecessor; rejects provisional emergency authority", layout: V1_LAYOUT })));
    provisional_emergency_lane_manifests_consumed: bool => ("state.provisional_emergency_lane_manifests_consumed",
        Role::Local("One-shot pre-authentication startup latch; provisional empty authority is never a finalized execution source"));
    lane_privacy_registry: PublicationRwLock<LanePrivacyRegistryHandle> => ("state.lane_privacy_registry",
        Role::Derived { sources: &["state.lane_manifests"], check: DerivationCheck::Rebuild("State startup, restore and lifecycle publication reconstruct exact privacy commitments from manifests; tx::enforce_lane_policies and Queue admission rebuild from their manifest snapshot; autonomous merge compares the projection") });
    lane_compliance: parking_lot::RwLock<Option<Arc<LaneComplianceEngine>>> => ("state.lane_compliance",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:lane_compliance:v1", encoder: "compliance::authority::LaneComplianceAuthorityV1::from_engine; exact optional enforcement mode and ordered canonical LaneCompliancePolicy values", layout: V1_LAYOUT })));
    da_index_hydration_fence: parking_lot::Mutex<()> => ("state.da_index_hydration_fence",
        Role::Local("Physical persistence/hydration coordination; authenticated logical DA/history owners are separately classified"));
    da_indexes_hydrated: PublicationRwLock<Option<Result<(), DaIndexHydrationError>>> => ("state.da_indexes_hydrated",
        Role::Local("Physical persistence/hydration coordination; authenticated logical DA/history owners are separately classified"));
    ivm: IVM => ("state.ivm",
        Role::Local("Reusable execution/validation machinery; semantics belong to bytecode, ABI and canonical policy; capacity/refusal cannot select consensus validity"));
    kura: Arc<Kura> => ("state.kura",
        Role::Local("Physical storage handle; logical SignedBlockWire and finality authority is state.block_hashes, never paths, file offsets or cache residency"));
    query_handle: LiveQueryStoreHandle => ("state.query_handle",
        Role::Local("Ephemeral live query cursor service, not an execution-state row"));
    pipeline: iroha_config::parameters::actual::Pipeline => ("state.pipeline",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:pipeline:v1", encoder: "state::authority_registry::pipeline_policy::PipelineExecutionPolicyV1::from_actual; execution_policy_digest_v1 pipeline, gas, cycle, query and AMX terms", layout: V1_LAYOUT })));
    pipeline_parallelism: PipelineParallelism => ("state.pipeline_parallelism",
        Role::Local("Derived worker pool/scheduling mechanics; no consensus policy authority"));
    soracloud_runtime: parking_lot::RwLock<Option<crate::soracloud_runtime::SharedSoracloudRuntime>> => ("state.soracloud_runtime",
        Role::Local("Node-local runtime explicitly excluded from production replay"));
    stateless_validation_cache: parking_lot::Mutex<StatelessValidationCache> => ("state.stateless_validation_cache",
        Role::Local("Reusable execution/validation machinery; semantics belong to bytecode, ABI and canonical policy; capacity/refusal cannot select consensus validity"));
    trigger_ivm_cache: parking_lot::Mutex<IvmCache> => ("state.trigger_ivm_cache",
        Role::Local("Reusable execution/validation machinery; semantics belong to bytecode, ABI and canonical policy; capacity/refusal cannot select consensus validity"));
    contract_query_ivm_cache: parking_lot::Mutex<IvmCache> => ("state.contract_query_ivm_cache",
        Role::Local("Reusable execution/validation machinery; semantics belong to bytecode, ABI and canonical policy; capacity/refusal cannot select consensus validity"));
    pipeline_ivm_prepared_cache: PublicationRwLock<PreparedContractCache> => ("state.pipeline_ivm_prepared_cache",
        Role::Local("Reusable execution/validation machinery; semantics belong to bytecode, ABI and canonical policy; capacity/refusal cannot select consensus validity"));
    ivm_execution_budget: iroha_allocation::AllocationBudget => ("state.ivm_execution_budget",
        Role::Local("Original immutable execution pool handle; capacity and release observations carry no consensus authority"));
    oracle: iroha_config::parameters::actual::Oracle => ("state.oracle",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:oracle:v1", encoder: "state::authority_registry::oracle_policy::OraclePolicyV1::from_actual; oracle state transitions and execution_policy_digest_v1", layout: V1_LAYOUT })));
    crypto: PublicationRwLock<Arc<iroha_config::parameters::actual::Crypto>> => ("state.crypto",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:crypto:v1", encoder: "state::authority_registry::crypto_policy::CryptoAdmissionPolicyV1::from_actual; transaction/account admission and IVM SM host policy", layout: V1_LAYOUT })));
    nexus: PublicationRwLock<iroha_config::parameters::actual::Nexus> => ("state.nexus",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:nexus:v1", encoder: "state::authority_registry::nexus_policy::canonical_preimage_once; exact effective policy from generation-bound canonical runtime, protected World catalog, materialized manifests, and installed compliance", layout: V1_LAYOUT })));
    canonical_runtime: Cell<SnapshotNexusRuntime> => ("state.canonical_runtime",
        Role::Canonical(Canonical::Owner(super::runtime::RUNTIME_FIELDS)));
    nexus_runtime_restored_from_snapshot: bool => ("state.nexus_runtime_restored_from_snapshot",
        Role::Local("Startup provenance latch; authenticated canonical_runtime retains effective lifecycle values"));
    nexus_storage_budget_last_check_height: AtomicU64 => ("state.nexus_storage_budget_last_check_height",
        Role::Local("Physical storage-budget scan scheduling cursor; storage refusal is local and cannot invalidate execution"));
    evidence_preparation_budget: iroha_allocation::AllocationBudget => ("state.evidence_preparation_budget",
        Role::Local("Original process-local evidence preparation capacity; refusal cannot choose consensus validity"));
    stake_index_budget: iroha_allocation::AllocationBudget => ("state.stake_index_budget",
        Role::Local("Original process-local flat stake-index capacity; canonical staking values are classified in World"));
    tiered_backend: Arc<PublicationMutex<TieredStateBackend>> => ("state.tiered_backend",
        Role::Local("Physical tiered storage and background persistence; logical authority stays in State and authenticated history"));
    tiered_snapshot_worker: TieredSnapshotWorker => ("state.tiered_snapshot_worker",
        Role::Local("Physical tiered storage and background persistence; logical authority stays in State and authenticated history"));
    fraud_monitoring: iroha_config::parameters::actual::FraudMonitoring => ("state.fraud_monitoring",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:fraud_monitoring:v1", encoder: "state::authority_registry::fraud_policy::FraudAdmissionPolicyV1::from_actual; tx::enforce_fraud_policy", layout: V1_LAYOUT })));
    zk: iroha_config::parameters::actual::Zk => ("state.zk",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:zk:v1", encoder: "state::authority_registry::zk_policy::ZkConsensusPolicyV1::from_actual; exact Halo2/STARK/SCCP/confidential verification and gas fields, excluding local prover queues and timeouts", layout: V1_LAYOUT })));
    gov: iroha_config::parameters::actual::Governance => ("state.gov",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:governance:v1", encoder: "state::authority_registry::governance_policy::GovernanceAuthorityV1::from_actual; governance admission, rewards, SoraFS and Parliament policy excluding diagnostics", layout: V1_LAYOUT })));
    content: iroha_config::parameters::actual::Content => ("state.content",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:content:v1", encoder: "state::authority_registry::content_policy::ContentAdmissionPolicyV1::from_actual; isi::content::PublishContentBundle", layout: V1_LAYOUT })));
    settlement: iroha_config::parameters::actual::Settlement => ("state.settlement",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:settlement:v1", encoder: "state::authority_registry::settlement_policy::SettlementPolicyV1::from_actual; exact router inputs", layout: V1_LAYOUT })));
    settlement_engine: crate::settlement::SettlementEngine => ("state.settlement_engine",
        Role::Derived { sources: &["state.settlement"], check: DerivationCheck::Rebuild("SettlementEngine::from_router_config(&State::settlement.router); SettlementEngine::matches_router_config before complete State root publication and after recovery") });
    chain_id: iroha_model_base::chain::ChainId => ("state.chain_id",
        Role::Canonical(Canonical::Cell(schema::<iroha_model_base::chain::ChainId>())));
    network_id: iroha_data_model::NetworkId => ("state.network_id",
        Role::Canonical(Canonical::Cell(schema::<iroha_data_model::NetworkId>())));
    #[cfg(feature = "telemetry")]
    telemetry: StateTelemetry => ("state.telemetry",
        Role::Local("Observability sink excluded from deterministic execution"));
    lane_lifecycle_lock: PublicationMutex => ("state.lane_lifecycle_lock",
        Role::Local("Physical publication/reader coordination and wakeup ownership; generation protects coherent reads but is not semantic State"));
    geometry_publication: parking_lot::Mutex<Option<LaneGeometryPublication>> => ("state.geometry_publication",
        Role::Local("Retained physical filesystem publication/recovery plan; no independent protocol state"));
    tiered_startup_geometry: Option<TieredStartupGeometry> => ("state.tiered_startup_geometry",
        Role::Local("Retained physical filesystem publication/recovery plan; no independent protocol state"));
    state_commit_lock: Arc<PublicationMutex> => ("state.state_commit_lock",
        Role::Local("Physical publication/reader coordination and wakeup ownership; generation protects coherent reads but is not semantic State"));
    state_write_lock: PublicationMutex => ("state.state_write_lock",
        Role::Local("Physical publication/reader coordination and wakeup ownership; generation protects coherent reads but is not semantic State"));
    view_generation: AtomicU64 => ("state.view_generation",
        Role::Local("Physical publication/reader coordination and wakeup ownership; generation protects coherent reads but is not semantic State"));
    publication_notify: tokio::sync::Notify => ("state.publication_notify",
        Role::Local("Physical publication/reader coordination and wakeup ownership; generation protects coherent reads but is not semantic State"));
    view_lock_contention_log: parking_lot::Mutex<ViewLockContentionLog> => ("state.view_lock_contention_log",
        Role::Local("Physical publication/reader coordination and wakeup ownership; generation protects coherent reads but is not semantic State"));
    native_evidence_admission: parking_lot::Mutex<crate::sumeragi::evidence::admission::AdmissionCache> => ("state.native_evidence_admission",
        Role::Local("Original-cut proof acquisition and capacity retry owner; only independently admitted records enter world.consensus_evidence"));
    native_pending_evidence: parking_lot::Mutex<crate::sumeragi::evidence::NativeEvidencePool> => ("state.native_pending_evidence",
        Role::Local("Private gossip-timing cache; only admitted canonical evidence records enter world.consensus_evidence"));
});
