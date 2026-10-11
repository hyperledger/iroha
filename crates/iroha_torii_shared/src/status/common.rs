//! Common status wire records.
use super::{consensus::*, gossip::*, governance::*, nexus::*, taikai::*};
use iroha_schema::{Ident, IntoSchema, MetaMap, Metadata, TypeId, UnnamedFieldsMeta};
use norito::{
    core::DecodeFromSlice,
    derive::{NoritoDeserialize, NoritoSerialize},
    json::{JsonDeserialize, JsonSerialize},
};
use std::time::Duration;

/// Thin wrapper around duration that `impl`s [`Default`]
#[derive(Debug, Clone, Copy, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::status::common::Uptime",
    frame = "iroha_telemetry::metrics::Uptime"
)]
pub struct Uptime(pub Duration);
impl Default for Uptime {
    fn default() -> Self {
        Self(Duration::from_millis(0))
    }
}

impl norito::core::SerializePayload for Uptime {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let pair = (self.0.as_secs(), self.0.subsec_nanos());
        norito::core::SerializePayload::serialize(&pair, writer)
    }
}

impl<'a> norito::core::DeserializePayload<'a> for Uptime {
    fn deserialize(archived: &'a norito::core::Archived<Uptime>) -> Self {
        let (secs, nanos): (u64, u32) =
            norito::core::DeserializePayload::deserialize(archived.cast());
        Uptime(Duration::from_secs(secs) + Duration::from_nanos(u64::from(nanos)))
    }
}
impl<'a> DecodeFromSlice<'a> for Uptime {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let ((secs, nanos), used) = <(u64, u32)>::decode_from_slice(bytes)?;
        let duration =
            Duration::from_secs(secs).saturating_add(Duration::from_nanos(u64::from(nanos)));
        Ok((Uptime(duration), used))
    }
}
impl JsonSerialize for Uptime {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"secs\":");
        norito::json::JsonSerialize::json_serialize(&self.0.as_secs(), out);
        out.push(',');
        out.push_str("\"nanos\":");
        norito::json::JsonSerialize::json_serialize(&self.0.subsec_nanos(), out);
        out.push('}');
    }
}
impl JsonDeserialize for Uptime {
    fn json_deserialize(p: &mut norito::json::Parser<'_>) -> Result<Self, norito::json::Error> {
        let mut map = norito::json::MapVisitor::new(p)?;
        let mut secs: Option<u64> = None;
        let mut nanos: Option<u32> = None;
        while let Some(key) = map.next_key()? {
            match key.as_str() {
                "secs" => {
                    if secs.is_some() {
                        return Err(norito::json::Error::duplicate_field("secs"));
                    }
                    secs = Some(map.parse_value::<u64>()?);
                }
                "nanos" => {
                    if nanos.is_some() {
                        return Err(norito::json::Error::duplicate_field("nanos"));
                    }
                    nanos = Some(map.parse_value::<u32>()?);
                }
                _ => {
                    map.skip_value()?;
                }
            }
        }
        map.finish()?;
        let secs = secs.ok_or_else(|| norito::json::Error::missing_field("secs"))?;
        let nanos = nanos.ok_or_else(|| norito::json::Error::missing_field("nanos"))?;
        Ok(Uptime(
            Duration::from_secs(secs) + Duration::from_nanos(u64::from(nanos)),
        ))
    }
}
impl TypeId for Uptime {
    fn id() -> Ident {
        "Uptime".to_owned()
    }
}
impl IntoSchema for Uptime {
    fn type_name() -> Ident {
        Self::id()
    }
    fn update_schema_map(metamap: &mut MetaMap) {
        metamap.insert::<Self>(Metadata::Tuple(UnnamedFieldsMeta {
            types: vec![
                core::any::TypeId::of::<u64>(),
                core::any::TypeId::of::<u32>(),
            ],
        }));
    }
}
/// Cryptography-related status exposed via `/status`.
#[derive(
    Clone,
    Copy,
    Debug,
    IntoSchema,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_torii_shared::status::common::CryptoStatus",
    frame = "iroha_telemetry::metrics::CryptoStatus"
)]
pub struct CryptoStatus {
    /// Indicates whether SM helper syscalls are available in this build.
    #[norito(default)]
    pub sm_helpers_available: bool,
    /// Indicates whether the OpenSSL-backed SM preview helpers are enabled.
    #[norito(default)]
    pub sm_openssl_preview_enabled: bool,
    /// Local diagnostic trace configuration snapshot.
    #[norito(default)]
    pub trace: DiagnosticTraceStatus,
}
/// Snapshot of local diagnostic trace scheduling; it grants no proof authority.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    IntoSchema,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::status::common::DiagnosticTraceStatus")]
pub struct DiagnosticTraceStatus {
    /// Whether local trace checking is enabled.
    #[norito(default)]
    pub enabled: bool,
    /// Maximum diagnostic tasks dispatched per batch.
    #[norito(default)]
    pub max_batch: u32,
    /// Effective worker count, or zero when disabled.
    #[norito(default)]
    pub worker_threads: u64,
    /// Effective ingress capacity, or zero when disabled.
    #[norito(default)]
    pub queue_cap: u64,
}
#[allow(clippy::derivable_impls)]
impl Default for CryptoStatus {
    fn default() -> Self {
        Self {
            sm_helpers_available: false,
            sm_openssl_preview_enabled: false,
            trace: DiagnosticTraceStatus::default(),
        }
    }
}
/// Stack sizing snapshot for scheduler/prover pools and guest VMs.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    IntoSchema,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_torii_shared::status::common::StackStatus",
    frame = "iroha_telemetry::metrics::StackStatus"
)]
pub struct StackStatus {
    /// Requested scheduler stack size in bytes.
    #[norito(default)]
    pub requested_scheduler_bytes: u64,
    /// Requested prover stack size in bytes.
    #[norito(default)]
    pub requested_prover_bytes: u64,
    /// Requested guest stack size in bytes.
    #[norito(default)]
    pub requested_guest_bytes: u64,
    /// Applied scheduler stack size in bytes after clamping.
    #[norito(default)]
    pub scheduler_bytes: u64,
    /// Applied prover stack size in bytes after clamping.
    #[norito(default)]
    pub prover_bytes: u64,
    /// Applied guest stack size in bytes after clamping.
    #[norito(default)]
    pub guest_bytes: u64,
    /// Gas→stack multiplier currently in effect.
    #[norito(default)]
    pub gas_to_stack_multiplier: u64,
    /// Whether the scheduler stack request was clamped.
    #[norito(default)]
    pub scheduler_clamped: bool,
    /// Whether the prover stack request was clamped.
    #[norito(default)]
    pub prover_clamped: bool,
    /// Whether the guest stack request was clamped.
    #[norito(default)]
    pub guest_clamped: bool,
    /// Count of fallbacks to an existing Rayon pool when applying stack sizes.
    #[norito(default)]
    pub pool_fallback_total: u64,
    /// Count of VM constructions that hit the guest stack budget clamp.
    #[norito(default)]
    pub budget_hit_total: u64,
}
/// Build metadata reported by the node serving `/status`.
#[derive(
    Clone,
    Debug,
    Default,
    IntoSchema,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_torii_shared::status::common::BuildStatus",
    frame = "iroha_telemetry::metrics::BuildStatus"
)]
pub struct BuildStatus {
    /// Semantic version baked into this binary.
    pub version: String,
    /// Git commit SHA baked into this binary.
    pub git_commit_sha: String,
    /// DPN validator release commit baked into a Taira validator binary.
    pub dpn_validator_release_commit: String,
    /// Enabled Cargo features baked into this binary.
    pub cargo_features: String,
    /// Target triple used to compile this binary.
    pub target_triple: String,
    /// Lowercase hex of the compiled consensus/block wire-schema and IVM ABI identity
    /// (`iroha_core::release_identity::wire_schema_hash`); release manifests pin the same value.
    pub wire_schema_hash: String,
}
/// Response body for the Torii GET `/status` endpoint.
#[derive(
    Clone,
    Debug,
    Default,
    IntoSchema,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_torii_shared::status::common::Status",
    frame = "iroha_telemetry::metrics::Status"
)]
pub struct Status {
    /// Build metadata for the currently running node binary.
    pub build: BuildStatus,
    /// Millisecond UNIX timestamp when this status snapshot was observed.
    pub observed_at_ms: u64,
    /// Number of currently connected peers excluding the reporting peer
    pub peers: u64,
    /// Number of committed blocks (blockchain height)
    pub blocks: u64,
    /// Number of committed non-empty blocks
    pub blocks_non_empty: u64,
    /// Time (since block creation) it took for the latest block to be committed by _this_ peer
    pub commit_time_ms: u64,
    /// Number of approved transactions
    pub txs_approved: u64,
    /// Number of rejected transactions
    pub txs_rejected: u64,
    /// Millisecond UNIX timestamp when this node most recently observed rejected transactions.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub last_rejection_at_ms: Option<u64>,
    /// Number of rejected transactions observed by this node within the last five minutes.
    pub txs_rejected_recent_5m: u64,
    /// Uptime since genesis block creation
    pub uptime: Uptime,
    /// Number of view changes in the current round
    pub view_changes: u32,
    /// Number of transactions tracked by the queue (queued + in-flight)
    pub queue_size: u64,
    /// Number of transactions still queued for selection.
    pub queue_queued: u64,
    /// Number of transactions in-flight after selection.
    pub queue_inflight: u64,
    /// Millisecond UNIX timestamp when this peer last processed a committed block.
    pub last_block_committed_at_ms: u64,
    /// Millisecond UNIX timestamp when this peer last processed a committed non-empty block.
    pub last_non_empty_block_committed_at_ms: u64,
    /// Milliseconds since this peer last processed a committed block.
    pub time_since_last_block_ms: u64,
    /// Milliseconds since this peer last processed a committed non-empty block.
    pub time_since_last_non_empty_block_ms: u64,
    /// Cryptography feature snapshot (SM enablement flags).
    pub crypto: CryptoStatus,
    /// Stack sizing/configuration snapshot.
    pub stack: StackStatus,
    /// Summary of the consensus snapshot (leader, QCs, queue state).
    #[norito(skip_serializing_if = "Option::is_none")]
    pub sumeragi: Option<SumeragiConsensusStatus>,
    /// Governance telemetry snapshot (proposal counts, protections, activations)
    pub governance: GovernanceStatus,
    /// Nexus lane-level TEU scheduling snapshot
    pub teu_lane_commit: Vec<NexusLaneTeuStatus>,
    /// Nexus dataspace-level backlog snapshot
    pub teu_dataspace_backlog: Vec<NexusDataspaceTeuStatus>,
    /// Configured Nexus dataspace catalog joined with lane metadata.
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub dataspace_catalog: Vec<NexusDataspaceCatalogStatus>,
    /// Effective Nexus status derived from committed state/configuration.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub nexus: Option<NexusStatus>,
    /// Transaction gossip target/cap snapshots grouped by dataspace/plane.
    pub tx_gossip: TxGossipSnapshot,
    /// Taikai alias rotation telemetry snapshots grouped by (cluster, event, stream).
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub taikai_alias_rotations: Vec<TaikaiAliasRotationStatus>,
    /// Taikai ingest telemetry snapshots grouped by (cluster, stream).
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub taikai_ingest: Vec<TaikaiIngestStatus>,
    /// Latest DA receipt cursor retained for each lane.
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub da_receipt_cursors: Vec<DaReceiptCursorStatus>,
}

#[cfg(test)]
mod captured_frame_identity_tests {
    #[test]
    fn observed_declared_identities() {
        crate::captured_identity_tests::assert_bidirectional::<super::BuildStatus>(
            "iroha_torii_shared::status::common::BuildStatus",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::CryptoStatus>(
            "iroha_torii_shared::status::common::CryptoStatus",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::DiagnosticTraceStatus>(
            "iroha_torii_shared::status::common::DiagnosticTraceStatus",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::StackStatus>(
            "iroha_torii_shared::status::common::StackStatus",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::Status>(
            "iroha_torii_shared::status::common::Status",
        );
    }
    #[test]
    fn observed_manual_frame_goldens() {
        crate::captured_identity_tests::assert_manual::<super::Uptime>("Uptime");
    }
}
