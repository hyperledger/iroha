//! Validated non-secret policy for `SoraFS` reputation and reserve transparency runtimes.
use iroha_config_base::util::Bytes;
use std::{path::PathBuf, time::Duration};
/// Public binding for the reputation finalized-archive retention authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsReputationFinalizedArchiveRetentionAuthority {
    /// Identity-pinned credential-free sealed-CAS provider handle.
    pub handle: String,
    /// Exact non-zero adapter and public-policy revision.
    pub revision: u64,
    /// Exact non-zero digest of the authority's public policy.
    pub policy_digest: [u8; 32],
}
/// Non-secret production policy for the committed `SoraFS` reputation runtime.
#[derive(Debug, Clone)]
pub struct SorafsReputationRuntime {
    /// Private directory containing canonical projector/publication checkpoints.
    pub state_dir: PathBuf,
    /// Deterministic private root for the immutable finalized reputation archive.
    pub finalized_archive_root: PathBuf,
    /// Maximum bytes accepted for one canonical finalized archive record.
    pub finalized_archive_max_record_bytes: u64,
    /// Maximum immutable records admitted in each finalized archive namespace.
    pub finalized_archive_max_entries: usize,
    /// Maximum aggregate canonical anchor and policy bytes admitted.
    pub finalized_archive_max_total_bytes: u64,
    /// Maximum admitted lag between the Kura tip and the finalized archive head.
    pub finalized_archive_max_kura_tip_lag_blocks: u64,
    /// External authority required before any finalized-prefix retention.
    pub finalized_archive_retention_authority:
        Option<SorafsReputationFinalizedArchiveRetentionAuthority>,
    /// Inclusive first finalized block in the governed scoring window.
    pub window_start_height: u64,
    /// Inclusive final block and mandatory signing-material target.
    pub window_end_height: u64,
    /// Identity-pinned finalized-query adapter handle.
    pub finalized_query_handle: String,
    /// Identity-pinned external monotonic journal-checkpoint provider handle.
    pub journal_checkpoint_provider_handle: String,
    /// Exact non-zero journal-checkpoint provider contract revision.
    pub journal_checkpoint_provider_revision: u64,
    /// Exact journal-checkpoint provider public-policy digest.
    pub journal_checkpoint_provider_policy_digest: [u8; 32],
    /// Identity-pinned runtime-only journal transaction submitter handle.
    pub journal_transaction_submitter_handle: String,
    /// Exact non-zero journal transaction submitter adapter and public-policy revision.
    pub journal_transaction_submitter_revision: u64,
    /// Exact journal transaction submitter public-policy digest.
    pub journal_transaction_submitter_policy_digest: [u8; 32],
    /// Identity-pinned external threshold-signer adapter handle.
    pub threshold_signer_handle: String,
    /// Exact non-zero threshold-signer adapter and public-policy revision.
    pub threshold_signer_revision: u64,
    /// Exact threshold-signer public-policy digest.
    pub threshold_signer_policy_digest: [u8; 32],
    /// Identity-pinned Governance DAG publication/readback adapter handle.
    pub governance_dag_handle: String,
    /// Exact non-zero Governance DAG adapter and public-policy revision.
    pub governance_dag_revision: u64,
    /// Exact Governance DAG public-policy digest.
    pub governance_dag_policy_digest: [u8; 32],
    /// Exact governed Governance DAG publisher peer identity.
    pub governance_publisher_peer_id: Vec<u8>,
    /// Exact governed Ed25519 Governance DAG publisher public key.
    pub governance_publisher_public_key: [u8; 32],
    /// Exact-anchor reconciliation cadence.
    pub poll_interval: Duration,
    /// Maximum items requested from one native finalized query page.
    pub page_items: u32,
    /// Maximum native pages accepted in one coherent ingest batch.
    pub max_pages_per_batch: u32,
    /// Maximum provider accumulators retained.
    pub max_providers: u32,
    /// Maximum typed events staged in one atomic projector batch.
    pub max_pending_events: u32,
    /// Maximum exact-replay receipts retained.
    pub max_replay_receipts: u32,
    /// Maximum external-delivery failures retained before dead-lettering.
    pub max_material_delivery_failures: u32,
    /// Maximum canonical projector checkpoint size.
    pub ingest_checkpoint_max_bytes: Bytes,
    /// Maximum canonical publication checkpoint size.
    pub publication_checkpoint_max_bytes: Bytes,
    /// Governed PoR-success weight.
    pub por_success_bps: u16,
    /// Governed PDP-success weight.
    pub pdp_success_bps: u16,
    /// Governed PoTR-success weight.
    pub potr_success_bps: u16,
    /// Governed latency-health weight.
    pub latency_bps: u16,
    /// Governed upheld-dispute penalty weight.
    pub dispute_bps: u16,
    /// Governed stream-token violation penalty weight.
    pub token_violation_bps: u16,
    /// Governed unresolved-repair penalty weight.
    pub repair_breach_bps: u16,
}
/// Non-secret policy for the finalized reserve transparency scanner.
#[derive(Debug, Clone)]
pub struct SorafsReserveTransparencyRuntime {
    /// Private directory containing the canonical monotonic scanner cursor.
    pub state_dir: PathBuf,
    /// Exact immutable finalized-query provider handle shared with reputation.
    pub finalized_query_handle: String,
    /// Normal scan cadence after a successful tick.
    pub poll_interval: Duration,
    /// Maximum bounded retry delay for transient archive/projection failures.
    pub retry_max_interval: Duration,
    /// Maximum reserve events requested from one immutable page.
    pub page_items: u32,
    /// Maximum immutable pages consumed by one scanner tick.
    pub max_pages_per_tick: u32,
    /// Maximum canonical bytes accepted for the local scanner checkpoint.
    pub checkpoint_max_bytes: Bytes,
}
