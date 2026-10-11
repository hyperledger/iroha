//! Nexus lane and dataspace routing types.
//!
//! These identifiers model the multi-lane/data-space routing surface described
//! in `nexus.md` and `nexus_transition_notes`. The default catalog contains one
//! universal lane; deployments may declare additional lane and dataspace entries
//! for independent routing, storage, and consensus policy.
use crate::{
    account::AccountId,
    asset::AssetDefinitionId,
    da::{commitment::DaProofScheme, confidential_compute::ConfidentialComputePolicy},
    id::IdBox,
    parameter::{CustomParameter, CustomParameterId},
};
use derive_more::Display;
use iroha_crypto::Hash;
use iroha_model_base::topology::{DataSpaceId, LaneId, ShardId};

use iroha_primitives::json::Json;
use iroha_primitives::numeric::XorQuantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::{NonZeroU32, NonZeroU64},
    str::FromStr,
};
use thiserror::Error;
mod amx_context;
mod axt;
mod committee;
mod committee_status;
mod compliance;
mod endorsement;
mod fee_sponsor_program;
mod manifest;
mod native_lane_manifest;
mod privacy;
mod private_settlement;
mod relay;
mod runtime_catalog;
pub use amx_context::*;
pub use axt::*;
pub use committee::*;
pub use committee_status::*;
pub use compliance::*;
pub use endorsement::*;
pub use fee_sponsor_program::*;
pub use manifest::*;
pub use native_lane_manifest::*;
pub use privacy::*;
#[cfg(test)]
pub(crate) use private_settlement::tests::measured_receipt as measured_private_settlement_receipt;
pub use private_settlement::*;
pub mod portfolio;
pub use portfolio::*;
pub mod staking;
pub use relay::*;
pub use runtime_catalog::*;
pub use staking::*;
mod staking_preparation;
pub use staking_preparation::*;
/// Consensus-wide maximum number of simultaneously active execution lanes.
///
/// This is a protocol admission bound shared by lifecycle catalogs, merge
/// execution, Native AMX manifests, and diagnostics. Sparse lane identifiers
/// may exceed this number; only the number of active catalog entries is bounded.
pub const MAX_ACTIVE_EXECUTION_LANES: usize = 1_024;
/// Declarative lane lifecycle changes (additions and retirements).
#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode, IntoSchema)]
pub struct LaneLifecyclePlan {
    /// Lane metadata to add, or to replace when the same current lane is retired.
    pub additions: Vec<LaneConfig>,
    /// Lane identifiers to retire.
    pub retire: Vec<LaneId>,
}
/// Versioned, optimistic-concurrency envelope for a consensus-replayed lane lifecycle update.
///
/// The envelope is carried in a [`crate::isi::SetParameter`] instruction. The expected catalog and
/// active-incarnation root bind an operator request to the exact topology it was reviewed against,
/// so a delayed or concurrently reordered request fails closed instead of mutating a newer topology
/// or a replacement lane that happens to reuse identical metadata.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema)]
pub struct LaneLifecycleParameterV1 {
    /// Payload layout version. This must be [`Self::VERSION`].
    pub version: u8,
    /// Domain-separated hash of the exact committed catalog that must precede this transition.
    pub expected_catalog_hash: Hash,
    /// Domain-separated root of the exact active lane incarnations that must precede this transition.
    pub expected_incarnation_root: Hash,
    /// Declarative lane additions, replacements, and retirements.
    pub plan: LaneLifecyclePlan,
}
/// Canonical active lane-incarnation commitment advertised to lifecycle clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
pub struct LaneLifecycleIncarnationEntry {
    /// Active lane identifier.
    pub lane_id: LaneId,
    /// Non-zero commitment identifying this exact lane incarnation.
    pub incarnation: Hash,
}
/// Read-only snapshot used to construct an optimistic lane lifecycle transaction.
///
/// The status carries the exact canonical lane catalog and its domain-separated commitment. Clients
/// must validate the snapshot before embedding [`Self::catalog_hash`] as
/// [`LaneLifecycleParameterV1::expected_catalog_hash`].
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::LaneLifecycleStatusV1")]
pub struct LaneLifecycleStatusV1 {
    /// Status layout version. This must be [`Self::VERSION`].
    pub version: u8,
    /// Exclusive lane-id bound for the current catalog namespace.
    pub lane_count: u32,
    /// Canonically ordered active lane metadata.
    pub lanes: Vec<LaneConfig>,
    /// Domain-separated commitment to `lane_count` and `lanes`.
    pub catalog_hash: Hash,
    /// Canonically ordered active lane-incarnation commitments.
    pub incarnations: Vec<LaneLifecycleIncarnationEntry>,
    /// Domain-separated commitment to `incarnations`.
    pub incarnation_root: Hash,
    /// Native commitment to the complete committed runtime catalog overlay.
    ///
    /// `None` means the protected overlay parameter is absent before its first transition.
    /// Copy this exact value into [`NexusCatalogTransitionV1::expected_runtime_catalog_hash`].
    /// The lane-only snapshot cannot independently reconstruct this overlay commitment.
    pub runtime_catalog_hash: Option<Hash>,
}
impl LaneLifecycleStatusV1 {
    /// Supported status layout version.
    pub const VERSION: u8 = 1;
    /// Construct a snapshot from one committed catalog, incarnation map, and runtime overlay hash.
    ///
    /// # Errors
    ///
    /// Returns [`LaneLifecycleStatusError`] when the incarnation map does not
    /// exactly and canonically cover the active catalog, or a present runtime hash is empty.
    pub fn new(
        catalog: &LaneCatalog,
        incarnations: &BTreeMap<LaneId, Hash>,
        runtime_catalog_hash: Option<Hash>,
    ) -> Result<Self, LaneLifecycleStatusError> {
        Self::validate_runtime_catalog_hash(runtime_catalog_hash)?;
        let incarnations = LaneLifecycleParameterV1::canonical_incarnations(catalog, incarnations)?;
        Ok(Self {
            version: Self::VERSION,
            lane_count: catalog.lane_count().get(),
            lanes: catalog.lanes().to_vec(),
            catalog_hash: LaneLifecycleParameterV1::catalog_hash(catalog),
            incarnation_root: LaneLifecycleParameterV1::incarnation_root(&incarnations),
            incarnations,
            runtime_catalog_hash,
        })
    }
    fn validate_runtime_catalog_hash(
        runtime_catalog_hash: Option<Hash>,
    ) -> Result<(), LaneLifecycleStatusError> {
        if runtime_catalog_hash.is_some_and(|hash| {
            hash == Hash::prehashed([0; Hash::LENGTH])
                || hash.as_ref().iter().all(|byte| *byte == 0)
        }) {
            return Err(LaneLifecycleStatusError::ZeroRuntimeCatalogHash);
        }
        Ok(())
    }
    /// Validate the version, catalog structure, canonical order, and commitments.
    ///
    /// The runtime catalog hash is checked for a non-empty value when present; reconstructing
    /// that commitment requires the complete protected overlay, which this status does not carry.
    ///
    /// # Errors
    /// Returns [`LaneLifecycleStatusError`] when the snapshot is unsupported,
    /// malformed, non-canonical, or carries a forged/stale catalog commitment.
    pub fn validate(&self) -> Result<LaneCatalog, LaneLifecycleStatusError> {
        if self.version != Self::VERSION {
            return Err(LaneLifecycleStatusError::UnsupportedVersion {
                actual: self.version,
                expected: Self::VERSION,
            });
        }
        Self::validate_runtime_catalog_hash(self.runtime_catalog_hash)?;
        let lane_count =
            NonZeroU32::new(self.lane_count).ok_or(LaneLifecycleStatusError::ZeroLaneCount)?;
        let catalog = LaneCatalog::new(lane_count, self.lanes.clone())?;
        if catalog.lanes() != self.lanes.as_slice() {
            return Err(LaneLifecycleStatusError::NonCanonicalLaneOrder);
        }
        let expected = LaneLifecycleParameterV1::catalog_hash(&catalog);
        if self.catalog_hash != expected {
            return Err(LaneLifecycleStatusError::CatalogHashMismatch {
                advertised: self.catalog_hash,
                computed: expected,
            });
        }
        LaneLifecycleParameterV1::validate_incarnations(&catalog, &self.incarnations)?;
        let expected_root = LaneLifecycleParameterV1::incarnation_root(&self.incarnations);
        if self.incarnation_root != expected_root {
            return Err(LaneLifecycleStatusError::IncarnationRootMismatch {
                advertised: self.incarnation_root,
                computed: expected_root,
            });
        }
        Ok(catalog)
    }
}
/// Validation failures for a read-only lane lifecycle status snapshot.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LaneLifecycleStatusError {
    /// A present runtime catalog commitment used the empty hash sentinel.
    #[error("Nexus lane lifecycle status advertised an empty runtime catalog hash")]
    ZeroRuntimeCatalogHash,
    /// The server advertised an unsupported status layout version.
    #[error("unsupported Nexus lane lifecycle status version {actual}; expected {expected}")]
    UnsupportedVersion {
        /// Advertised version.
        actual: u8,
        /// Version understood by this client.
        expected: u8,
    },
    /// A catalog namespace cannot have a zero exclusive bound.
    #[error("Nexus lane lifecycle status advertised a zero lane count")]
    ZeroLaneCount,
    /// Lane entries were not ordered canonically by lane identifier.
    #[error("Nexus lane lifecycle status lane entries are not canonically ordered")]
    NonCanonicalLaneOrder,
    /// The advertised catalog commitment did not bind the supplied catalog.
    #[error(
        "Nexus lane lifecycle status catalog hash mismatch: advertised {advertised}, computed {computed}"
    )]
    CatalogHashMismatch {
        /// Hash supplied by the server.
        advertised: Hash,
        /// Hash computed from the supplied catalog.
        computed: Hash,
    },
    /// Active incarnation entries were not strictly ordered by lane identifier.
    #[error("Nexus lane lifecycle incarnation entries are not canonically ordered")]
    NonCanonicalIncarnationOrder,
    /// Active incarnation entries did not cover exactly the catalog's lane identifiers.
    #[error("Nexus lane lifecycle incarnation lane ids do not exactly match the active catalog")]
    IncarnationLaneSetMismatch,
    /// An active lane advertised an all-zero incarnation commitment.
    #[error("Nexus lane lifecycle status lane {lane_id} has an all-zero incarnation")]
    ZeroIncarnation {
        /// Lane carrying the invalid commitment.
        lane_id: LaneId,
    },
    /// Two active lanes reused the same incarnation commitment.
    #[error("Nexus lane lifecycle status lane {lane_id} reuses an active incarnation")]
    DuplicateIncarnation {
        /// Later lane carrying the duplicate commitment.
        lane_id: LaneId,
    },
    /// The incarnation root did not bind the advertised active entries.
    #[error(
        "Nexus lane lifecycle status incarnation root mismatch: advertised {advertised}, computed {computed}"
    )]
    IncarnationRootMismatch {
        /// Root supplied by the server.
        advertised: Hash,
        /// Root computed from the supplied entries.
        computed: Hash,
    },
    /// The supplied lane metadata did not form a valid catalog.
    #[error(transparent)]
    InvalidCatalog(#[from] LaneCatalogError),
}
impl LaneLifecycleParameterV1 {
    /// Supported payload layout version.
    pub const VERSION: u8 = 1;
    /// Reserved custom-parameter identifier for consensus lane lifecycle changes.
    pub const PARAMETER_ID_STR: &'static str = "nexus_lane_lifecycle_v1";
    /// Construct a lifecycle parameter bound to the exact catalog and incarnations.
    ///
    /// # Errors
    ///
    /// Returns [`LaneLifecycleStatusError`] when the incarnation entries do not
    /// exactly and canonically cover the expected catalog.
    pub fn new(
        expected_catalog: &LaneCatalog,
        expected_incarnations: &[LaneLifecycleIncarnationEntry],
        plan: LaneLifecyclePlan,
    ) -> Result<Self, LaneLifecycleStatusError> {
        Self::validate_incarnations(expected_catalog, expected_incarnations)?;
        Ok(Self {
            version: Self::VERSION,
            expected_catalog_hash: Self::catalog_hash(expected_catalog),
            expected_incarnation_root: Self::incarnation_root(expected_incarnations),
            plan,
        })
    }
    /// Compute the canonical, domain-separated commitment for a lane catalog.
    #[must_use]
    pub fn catalog_hash(catalog: &LaneCatalog) -> Hash {
        const DOMAIN: &[u8] = b"iroha:nexus:lane-catalog:v1\0";
        let encoded = (catalog.lane_count().get(), catalog.lanes().to_vec()).encode();
        Hash::new_from_chunks(&[DOMAIN, encoded.as_slice()])
    }
    /// Convert the active incarnation map to its canonical exact catalog order.
    ///
    /// # Errors
    ///
    /// Returns [`LaneLifecycleStatusError`] when the map does not exactly cover
    /// the catalog, contains a zero or duplicate incarnation, or cannot be
    /// represented in canonical lane-id order.
    pub fn canonical_incarnations(
        catalog: &LaneCatalog,
        incarnations: &BTreeMap<LaneId, Hash>,
    ) -> Result<Vec<LaneLifecycleIncarnationEntry>, LaneLifecycleStatusError> {
        let entries = incarnations
            .iter()
            .map(|(&lane_id, &incarnation)| LaneLifecycleIncarnationEntry {
                lane_id,
                incarnation,
            })
            .collect::<Vec<_>>();
        Self::validate_incarnations(catalog, &entries)?;
        Ok(entries)
    }
    /// Validate exact coverage, canonical ordering, non-zero values, and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`LaneLifecycleStatusError`] when any invariant is violated.
    pub fn validate_incarnations(
        catalog: &LaneCatalog,
        incarnations: &[LaneLifecycleIncarnationEntry],
    ) -> Result<(), LaneLifecycleStatusError> {
        let expected_ids = catalog
            .lanes()
            .iter()
            .map(|lane| lane.id)
            .collect::<Vec<_>>();
        let actual_ids = incarnations
            .iter()
            .map(|entry| entry.lane_id)
            .collect::<Vec<_>>();
        if actual_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(LaneLifecycleStatusError::NonCanonicalIncarnationOrder);
        }
        if actual_ids != expected_ids {
            return Err(LaneLifecycleStatusError::IncarnationLaneSetMismatch);
        }
        let mut unique = BTreeSet::new();
        for entry in incarnations {
            if entry.incarnation.as_ref().iter().all(|byte| *byte == 0) {
                return Err(LaneLifecycleStatusError::ZeroIncarnation {
                    lane_id: entry.lane_id,
                });
            }
            if !unique.insert(entry.incarnation) {
                return Err(LaneLifecycleStatusError::DuplicateIncarnation {
                    lane_id: entry.lane_id,
                });
            }
        }
        Ok(())
    }
    /// Compute the domain-separated commitment to canonical incarnation entries.
    #[must_use]
    pub fn incarnation_root(incarnations: &[LaneLifecycleIncarnationEntry]) -> Hash {
        const DOMAIN: &[u8] = b"iroha:nexus:lane-incarnations:v1\0";
        let encoded = incarnations.to_vec().encode();
        Hash::new_from_chunks(&[DOMAIN, encoded.as_slice()])
    }
    /// Identifier used by the on-chain custom parameter.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("valid Nexus lane lifecycle custom parameter identifier")
    }
    /// Convert this envelope into the custom parameter accepted by `SetParameter`.
    #[must_use]
    pub fn into_custom_parameter(self) -> CustomParameter {
        CustomParameter::new(Self::parameter_id(), Json::new(self))
    }
    /// Decode a matching lifecycle custom parameter.
    ///
    /// Non-matching parameter identifiers return `Ok(None)`. Matching identifiers
    /// are parsed strictly and reject unsupported versions.
    ///
    /// # Errors
    ///
    /// Returns [`norito::json::Error`] when a matching payload is malformed or
    /// carries an unsupported lifecycle version.
    pub fn from_custom_parameter(
        custom: &CustomParameter,
    ) -> Result<Option<Self>, norito::json::Error> {
        if custom.id != Self::parameter_id() {
            return Ok(None);
        }
        let payload = norito::json::from_str::<Self>(custom.payload().get())?;
        if payload.version != Self::VERSION {
            return Err(norito::json::Error::Message(format!(
                "unsupported Nexus lane lifecycle parameter version {}; expected {}",
                payload.version,
                Self::VERSION
            )));
        }
        Ok(Some(payload))
    }
}
impl crate::Identifiable for LaneId {
    type Id = LaneId;
    fn id(&self) -> &Self::Id {
        self
    }
}

impl From<ShardId> for IdBox {
    fn from(value: ShardId) -> Self {
        IdBox::LaneId(value.into())
    }
}

impl crate::Identifiable for ShardId {
    type Id = ShardId;
    fn id(&self) -> &Self::Id {
        self
    }
}
/// Metadata key marking a lane as created and owned by the deterministic autoscaler.
pub const AUTOSCALE_META_MANAGED: &str = "autoscale.managed";
/// Metadata key recording the block height where the autoscaler created the lane.
pub const AUTOSCALE_META_CREATED_HEIGHT: &str = "autoscale.created_height";
/// Metadata key carrying the consensus-persisted two-phase lane drain state.
pub const AUTOSCALE_META_DRAIN_STATE: &str = "autoscale.drain_state";
/// Metadata key pinning the authoritative committee for one elastic-lane incarnation.
pub const AUTOSCALE_META_COMMITTEE: &str = "autoscale.committee_v1";
const RETIRED_SHARD_ID_METADATA_KEY: &str = "da_shard_id";
const RETIRED_FUNCTIONAL_METADATA_KEYS: [&str; 10] = [
    "da_manifest_policy",
    "confidential_compute",
    "confidential_mechanism",
    "confidential_key_version",
    "confidential_access",
    "scheduler.teu_capacity",
    "scheduler.starvation_bound_slots",
    "settlement.buffer_account",
    "settlement.buffer_asset",
    "settlement.buffer_capacity",
];
/// Lane-level DA manifest availability policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode, IntoSchema)]
pub enum DaManifestPolicy {
    /// Missing manifests block commitment and proposal sealing.
    #[default]
    Strict,
    /// Missing manifests are reported but do not block commitment.
    Audit,
}
impl DaManifestPolicy {
    /// Return the exact first-release configuration label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Audit => "audit",
        }
    }
}
impl fmt::Display for DaManifestPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
impl FromStr for DaManifestPolicy {
    type Err = DaManifestPolicyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict" => Ok(Self::Strict),
            "audit" => Ok(Self::Audit),
            _ => Err(DaManifestPolicyParseError(value.to_owned())),
        }
    }
}
/// Error returned for a non-canonical DA manifest policy label.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid DA manifest policy `{0}`")]
pub struct DaManifestPolicyParseError(pub String);
/// Optional positive per-lane scheduler overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize)]
pub struct LaneSchedulerPolicy {
    /// Positive per-block TEU capacity override; absent values use the global fallback.
    #[norito(required)]
    pub teu_capacity: Option<NonZeroU64>,
    /// Positive starvation bound in slots; absent values use the global fallback.
    #[norito(required)]
    pub starvation_bound_slots: Option<NonZeroU64>,
}
impl LaneSchedulerPolicy {
    /// Construct scheduler overrides. At least one override must be present for catalog admission.
    #[must_use]
    pub const fn new(
        teu_capacity: Option<NonZeroU64>,
        starvation_bound_slots: Option<NonZeroU64>,
    ) -> Self {
        Self {
            teu_capacity,
            starvation_bound_slots,
        }
    }
    /// Return whether this descriptor carries no override.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.teu_capacity.is_none() && self.starvation_bound_slots.is_none()
    }
}
/// Typed settlement reserve configuration for one lane.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema)]
#[norito(deny_unknown_fields)]
#[derive(crate :: DeriveJsonSerialize, crate :: DeriveJsonDeserialize)]
pub struct LaneSettlementBufferPolicy {
    /// Canonical universal account holding the reserve asset.
    pub account_id: AccountId,
    /// Canonical asset definition debited for settlement headroom.
    pub asset_definition_id: AssetDefinitionId,
    /// Positive exact XOR capacity.
    pub capacity: XorQuantity,
}
impl LaneSettlementBufferPolicy {
    /// Construct a typed settlement buffer policy.
    #[must_use]
    pub fn new(
        account_id: AccountId,
        asset_definition_id: AssetDefinitionId,
        capacity: XorQuantity,
    ) -> Self {
        Self {
            account_id,
            asset_definition_id,
            capacity,
        }
    }
}
/// Canonical first-release projection of one lane's consensus-relevant configuration.
///
/// Aliases are committed because autoscale ownership and catalog lifecycle
/// admission inspect them. Descriptions and arbitrary instrumentation metadata
/// are excluded. Reserved autoscale metadata remains committed because it can
/// affect deterministic execution; scheduler and settlement policy are typed.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::nexus::LaneConsensusProjectionV1")]
pub struct LaneConsensusProjectionV1 {
    version: u16,
    id: LaneId,
    alias: String,
    shard_id: ShardId,
    dataspace_id: DataSpaceId,
    visibility: LaneVisibility,
    lane_type: Option<String>,
    governance: Option<String>,
    settlement: Option<String>,
    storage: LaneStorageProfile,
    proof_scheme: DaProofScheme,
    manifest_policy: DaManifestPolicy,
    confidential_compute: Option<ConfidentialComputePolicy>,
    scheduler: Option<LaneSchedulerPolicy>,
    settlement_buffer: Option<LaneSettlementBufferPolicy>,
    consensus_metadata: BTreeMap<String, String>,
}
impl LaneConsensusProjectionV1 {
    /// Current canonical projection layout.
    pub const VERSION: u16 = 1;
}
/// Metadata describing an execution lane.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema)]
pub struct LaneConfig {
    /// Lane identifier.
    pub id: LaneId,
    /// Explicit DA/storage shard override; absent values follow the lane identifier.
    pub shard_id: Option<ShardId>,
    /// Physical dataspace this logical lane belongs to.
    pub dataspace_id: DataSpaceId,
    /// Human-friendly alias.
    pub alias: String,
    /// Optional description for dashboards and docs.
    pub description: Option<String>,
    /// Declarative visibility profile.
    pub visibility: LaneVisibility,
    /// Lane profile/type (`default_public`, `cbdc_private`, etc.).
    pub lane_type: Option<String>,
    /// Governance policy identifier.
    pub governance: Option<String>,
    /// Settlement/fee policy identifier.
    pub settlement: Option<String>,
    /// Storage profile bound to this lane.
    pub storage: LaneStorageProfile,
    /// Proof scheme used for DA commitments on this lane.
    pub proof_scheme: DaProofScheme,
    /// DA manifest availability policy.
    pub manifest_policy: DaManifestPolicy,
    /// Confidential-compute policy, absent for ordinary lanes.
    pub confidential_compute: Option<ConfidentialComputePolicy>,
    /// Optional positive scheduler overrides.
    pub scheduler: Option<LaneSchedulerPolicy>,
    /// Optional typed settlement reserve policy.
    pub settlement_buffer: Option<LaneSettlementBufferPolicy>,
    /// Operator metadata for instrumentation.
    ///
    /// Reserved autoscale keys remain consensus-relevant. Raw scheduler and settlement buffer
    /// metadata are rejected in favor of their dedicated typed fields.
    pub metadata: BTreeMap<String, String>,
}
impl Default for LaneConfig {
    fn default() -> Self {
        Self {
            id: LaneId::SINGLE,
            shard_id: None,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "default".to_string(),
            description: None,
            visibility: LaneVisibility::Public,
            lane_type: None,
            governance: None,
            settlement: None,
            storage: LaneStorageProfile::FullReplica,
            proof_scheme: DaProofScheme::default(),
            manifest_policy: DaManifestPolicy::default(),
            confidential_compute: None,
            scheduler: None,
            settlement_buffer: None,
            metadata: BTreeMap::new(),
        }
    }
}
impl LaneConfig {
    /// Project this descriptor onto fields that can affect deterministic lane behavior.
    #[must_use]
    pub fn consensus_projection(&self) -> LaneConsensusProjectionV1 {
        LaneConsensusProjectionV1 {
            version: LaneConsensusProjectionV1::VERSION,
            id: self.id,
            alias: self.alias.clone(),
            shard_id: self.effective_shard_id(),
            dataspace_id: self.dataspace_id,
            visibility: self.visibility,
            lane_type: self.lane_type.clone(),
            governance: self.governance.clone(),
            settlement: self.settlement.clone(),
            storage: self.storage,
            proof_scheme: self.proof_scheme,
            manifest_policy: self.manifest_policy,
            confidential_compute: self.confidential_compute.clone(),
            scheduler: self.scheduler,
            settlement_buffer: self.settlement_buffer.clone(),
            consensus_metadata: self
                .metadata
                .iter()
                .filter(|(key, _)| is_consensus_lane_metadata_key(key))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }
    /// Resolve the effective DA/storage shard for this lane.
    #[must_use]
    pub fn effective_shard_id(&self) -> ShardId {
        self.shard_id.unwrap_or_else(|| self.id.into())
    }
    /// Validate this borrowed lane's mandatory functional policy without copying metadata.
    ///
    /// # Errors
    /// Rejects retired policy keys, empty scheduler/settlement policies, and incompatible
    /// confidential-compute storage or audience settings.
    pub fn validate_policy_surface(&self) -> Result<(), LaneCatalogError> {
        if self.metadata.contains_key(RETIRED_SHARD_ID_METADATA_KEY) {
            return Err(LaneCatalogError::RetiredShardIdMetadata(self.id));
        }
        if let Some(key) = self
            .metadata
            .keys()
            .find(|key| is_retired_functional_metadata_key(key))
        {
            return Err(LaneCatalogError::RetiredFunctionalMetadata {
                lane: self.id,
                key: key.clone(),
            });
        }
        let invalid = |reason: String| LaneCatalogError::InvalidFunctionalPolicy {
            lane: self.id,
            reason,
        };
        if self
            .scheduler
            .as_ref()
            .is_some_and(LaneSchedulerPolicy::is_empty)
        {
            return Err(invalid(
                "scheduler policy must define `teu_capacity`, `starvation_bound_slots`, or both"
                    .to_owned(),
            ));
        }
        if self
            .settlement_buffer
            .as_ref()
            .is_some_and(|policy| policy.capacity.is_zero())
        {
            return Err(invalid(
                "settlement buffer capacity must be positive".to_owned(),
            ));
        }
        let Some(policy) = self.confidential_compute.as_ref() else {
            return Ok(());
        };
        if self.storage == LaneStorageProfile::FullReplica {
            return Err(invalid(
                "confidential compute requires `commitment_only` or `split_replica` storage"
                    .to_owned(),
            ));
        }
        if let Some(audience) = policy
            .allowed_audiences
            .iter()
            .find(|audience| audience.is_empty() || audience.trim() != audience.as_str())
        {
            return Err(invalid(format!(
                "confidential audience `{audience}` must be non-empty and must not contain surrounding whitespace"
            )));
        }
        Ok(())
    }
    /// Return `true` when this lane uses the reserved autoscale ownership metadata key.
    #[must_use]
    pub fn claims_autoscale_managed(&self) -> bool {
        self.metadata.contains_key(AUTOSCALE_META_MANAGED)
    }
    /// Parse the positive autoscale creation height marker, when present and valid.
    #[must_use]
    pub fn autoscale_created_height(&self) -> Option<u64> {
        self.metadata
            .get(AUTOSCALE_META_CREATED_HEIGHT)
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|height| *height > 0)
    }
    /// Return `true` when a consensus autoscale drain state is attached.
    #[must_use]
    pub fn has_autoscale_drain_state(&self) -> bool {
        self.metadata.contains_key(AUTOSCALE_META_DRAIN_STATE)
    }
    /// Return `true` when a consensus-pinned incarnation committee is attached.
    #[must_use]
    pub fn has_autoscale_committee(&self) -> bool {
        self.metadata.contains_key(AUTOSCALE_META_COMMITTEE)
    }
    /// Return `true` when this lane is a valid deterministic autoscale elastic lane.
    #[must_use]
    pub fn is_autoscale_managed_elastic(&self) -> bool {
        self.visibility == LaneVisibility::Public
            && self
                .metadata
                .get(AUTOSCALE_META_MANAGED)
                .is_some_and(|value| value == "true")
            && self.alias == format!("elastic-lane-{}", self.id.as_u32())
            && self.autoscale_created_height().is_some()
    }
    /// Return `true` when this lane inherits the functional autoscale profile of `base`.
    ///
    /// Elastic lanes have their own identifier, alias, description, and reserved autoscale
    /// metadata. All routing, security, storage, proof, and operator-defined metadata must remain
    /// identical to the routing default lane they scale.
    #[must_use]
    pub fn inherits_autoscale_profile_from(&self, base: &Self) -> bool {
        self.shard_id == base.shard_id
            && self.dataspace_id == base.dataspace_id
            && self.visibility == base.visibility
            && self.lane_type == base.lane_type
            && self.governance == base.governance
            && self.settlement == base.settlement
            && self.storage == base.storage
            && self.proof_scheme == base.proof_scheme
            && self.manifest_policy == base.manifest_policy
            && self.confidential_compute == base.confidential_compute
            && self.scheduler == base.scheduler
            && self.settlement_buffer == base.settlement_buffer
            && self
                .metadata
                .iter()
                .filter(|(key, _)| !is_reserved_autoscale_metadata_key(key.as_str()))
                .eq(base
                    .metadata
                    .iter()
                    .filter(|(key, _)| !is_reserved_autoscale_metadata_key(key.as_str())))
    }
}
fn is_reserved_autoscale_metadata_key(key: &str) -> bool {
    matches!(
        key,
        AUTOSCALE_META_MANAGED
            | AUTOSCALE_META_CREATED_HEIGHT
            | AUTOSCALE_META_DRAIN_STATE
            | AUTOSCALE_META_COMMITTEE
    )
}
fn is_consensus_lane_metadata_key(key: &str) -> bool {
    is_reserved_autoscale_metadata_key(key)
}
fn is_retired_functional_metadata_key(key: &str) -> bool {
    RETIRED_FUNCTIONAL_METADATA_KEYS.contains(&key)
        || key.starts_with("confidential_")
        || key.starts_with("scheduler.")
        || key.starts_with("settlement.buffer_")
}
/// Declarative visibility profile for a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, Display)]
pub enum LaneVisibility {
    /// Lane is discoverable without authentication.
    #[display("public")]
    Public,
    /// Lane requires explicit admission for visibility.
    #[display("restricted")]
    Restricted,
}
impl LaneVisibility {
    /// Returns the canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Restricted => "restricted",
        }
    }
}
impl FromStr for LaneVisibility {
    type Err = LaneVisibilityParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(Self::Public),
            "restricted" => Ok(Self::Restricted),
            other => Err(LaneVisibilityParseError(other.to_string())),
        }
    }
}
#[allow(clippy::derivable_impls)]
impl Default for LaneVisibility {
    fn default() -> Self {
        Self::Public
    }
}
/// Storage profile describing how state/WAL data is persisted for a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema)]
pub enum LaneStorageProfile {
    /// Full state replication (state + WAL) is retained by the lane.
    FullReplica,
    /// Only commitment metadata is persisted globally (lane retains private state locally).
    CommitmentOnly,
    /// Encrypted payloads and commitments are stored separately.
    SplitReplica,
}
impl LaneStorageProfile {
    /// Returns the canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullReplica => "full_replica",
            Self::CommitmentOnly => "commitment_only",
            Self::SplitReplica => "split_replica",
        }
    }
}
impl fmt::Display for LaneStorageProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl FromStr for LaneStorageProfile {
    type Err = LaneStorageProfileParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full_replica" => Ok(Self::FullReplica),
            "commitment_only" => Ok(Self::CommitmentOnly),
            "split_replica" => Ok(Self::SplitReplica),
            other => Err(LaneStorageProfileParseError(other.to_string())),
        }
    }
}
#[allow(clippy::derivable_impls)]
impl Default for LaneStorageProfile {
    fn default() -> Self {
        Self::FullReplica
    }
}
/// Error surfaced when parsing [`LaneVisibility`] from a string.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid lane visibility `{0}`")]
pub struct LaneVisibilityParseError(pub String);
/// Error surfaced when parsing [`LaneStorageProfile`] from a string.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid lane storage profile `{0}`")]
pub struct LaneStorageProfileParseError(pub String);

impl norito::json::FastJsonWrite for LaneVisibility {
    fn write_json(&self, out: &mut String) {
        out.push('"');
        out.push_str(self.as_str());
        out.push('"');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(self.as_str(), out)
    }
}

impl norito::json::JsonDeserialize for LaneVisibility {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        value
            .parse()
            .map_err(|err: LaneVisibilityParseError| norito::json::Error::Message(err.to_string()))
    }
}

impl norito::json::FastJsonWrite for LaneStorageProfile {
    fn write_json(&self, out: &mut String) {
        out.push('"');
        out.push_str(self.as_str());
        out.push('"');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(self.as_str(), out)
    }
}

impl norito::json::JsonDeserialize for LaneStorageProfile {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        value.parse().map_err(|err: LaneStorageProfileParseError| {
            norito::json::Error::Message(err.to_string())
        })
    }
}

impl norito::json::FastJsonWrite for DaManifestPolicy {
    fn write_json(&self, out: &mut String) {
        norito::json::write_json_string(self.as_str(), out);
    }

    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_json_string_to(self.as_str(), out)
    }
}

impl norito::json::JsonDeserialize for DaManifestPolicy {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        parser
            .parse_string()?
            .parse()
            .map_err(|error: DaManifestPolicyParseError| {
                norito::json::Error::Message(error.to_string())
            })
    }
}

impl norito::json::FastJsonWrite for LaneConfig {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("id", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.id, out);
        out.push(',');
        norito::json::write_json_string("shard_id", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.shard_id, out);
        out.push(',');
        norito::json::write_json_string("dataspace_id", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.dataspace_id, out);
        out.push(',');
        norito::json::write_json_string("alias", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.alias, out);
        out.push(',');
        norito::json::write_json_string("description", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.description, out);
        out.push(',');
        norito::json::write_json_string("visibility", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.visibility, out);
        out.push(',');
        norito::json::write_json_string("lane_type", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.lane_type, out);
        out.push(',');
        norito::json::write_json_string("governance", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.governance, out);
        out.push(',');
        norito::json::write_json_string("settlement", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.settlement, out);
        out.push(',');
        norito::json::write_json_string("storage", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.storage, out);
        out.push(',');
        norito::json::write_json_string("proof_scheme", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.proof_scheme.to_string(), out);
        out.push(',');
        norito::json::write_json_string("manifest_policy", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.manifest_policy, out);
        out.push(',');
        norito::json::write_json_string("confidential_compute", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.confidential_compute, out);
        out.push(',');
        norito::json::write_json_string("scheduler", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.scheduler, out);
        out.push(',');
        norito::json::write_json_string("settlement_buffer", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.settlement_buffer, out);
        out.push(',');
        norito::json::write_json_string("metadata", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.metadata, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"id\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.id, out)?;
            out.push_str(",\"shard_id\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.shard_id, out)?;
            out.push_str(",\"dataspace_id\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.dataspace_id, out)?;
            out.push_str(",\"alias\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.alias, out)?;
            out.push_str(",\"description\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.description, out)?;
            out.push_str(",\"visibility\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.visibility, out)?;
            out.push_str(",\"lane_type\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.lane_type, out)?;
            out.push_str(",\"governance\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.governance, out)?;
            out.push_str(",\"settlement\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.settlement, out)?;
            out.push_str(",\"storage\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.storage, out)?;
            out.push_str(",\"proof_scheme\":")?;
            norito::json::write_json_string_to(&self.proof_scheme.to_string(), out)?;
            out.push_str(",\"manifest_policy\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.manifest_policy, out)?;
            out.push_str(",\"confidential_compute\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.confidential_compute, out)?;
            out.push_str(",\"scheduler\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.scheduler, out)?;
            out.push_str(",\"settlement_buffer\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.settlement_buffer, out)?;
            out.push_str(",\"metadata\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.metadata, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

fn ensure_lane_config_json_fields(
    seen_fields: &BTreeSet<String>,
) -> Result<(), norito::json::Error> {
    const REQUIRED_FIELDS: [&str; 16] = [
        "id",
        "shard_id",
        "dataspace_id",
        "alias",
        "description",
        "visibility",
        "lane_type",
        "governance",
        "settlement",
        "storage",
        "proof_scheme",
        "manifest_policy",
        "confidential_compute",
        "scheduler",
        "settlement_buffer",
        "metadata",
    ];
    if let Some(missing_field) = REQUIRED_FIELDS
        .into_iter()
        .find(|field| !seen_fields.contains(*field))
    {
        return Err(norito::json::Error::Message(format!(
            "missing required lane config field `{missing_field}`"
        )));
    }
    Ok(())
}

impl norito::json::JsonDeserialize for LaneConfig {
    #[allow(
        clippy::too_many_lines,
        reason = "the strict LaneConfig decoder keeps its complete required-field and rejection policy in one auditable implementation"
    )]
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut lane = LaneConfig::default();
        let mut seen_fields = BTreeSet::new();
        while let Some(key) = visitor.next_key()? {
            let key_name = key.as_str();
            if !seen_fields.insert(key_name.to_owned()) {
                return Err(norito::json::Error::Message(format!(
                    "duplicate field `{key_name}` in lane config"
                )));
            }
            match key_name {
                "id" => {
                    lane.id = visitor.parse_value()?;
                }
                "shard_id" => {
                    lane.shard_id = visitor.parse_value()?;
                }
                "dataspace_id" => {
                    lane.dataspace_id = visitor.parse_value()?;
                }
                "alias" => {
                    lane.alias = visitor.parse_value()?;
                }
                "description" => {
                    lane.description = visitor.parse_value()?;
                }
                "visibility" => {
                    lane.visibility = visitor.parse_value()?;
                }
                "lane_type" => {
                    lane.lane_type = visitor.parse_value()?;
                }
                "governance" => {
                    lane.governance = visitor.parse_value()?;
                }
                "settlement" => {
                    lane.settlement = visitor.parse_value()?;
                }
                "storage" => {
                    lane.storage = visitor.parse_value()?;
                }
                "proof_scheme" => {
                    let raw: String = visitor.parse_value()?;
                    lane.proof_scheme = raw.parse().map_err(|err| {
                        norito::json::Error::Message(format!(
                            "invalid lane proof_scheme `{raw}`: {err}"
                        ))
                    })?;
                }
                "manifest_policy" => {
                    lane.manifest_policy = visitor.parse_value()?;
                }
                "confidential_compute" => {
                    lane.confidential_compute = visitor.parse_value()?;
                }
                "scheduler" => {
                    lane.scheduler = visitor.parse_value()?;
                }
                "settlement_buffer" => {
                    lane.settlement_buffer = visitor.parse_value()?;
                }
                "metadata" => {
                    lane.metadata = visitor.parse_value()?;
                }
                other => {
                    return Err(norito::json::Error::Message(format!(
                        "unknown field `{other}` in lane config"
                    )));
                }
            }
        }
        visitor.finish()?;
        ensure_lane_config_json_fields(&seen_fields)?;
        lane.validate_policy_surface()
            .map_err(|error| norito::json::Error::Message(error.to_string()))?;
        Ok(lane)
    }
}

impl norito::json::FastJsonWrite for LaneLifecyclePlan {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("additions", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.additions, out);
        out.push(',');
        norito::json::write_json_string("retire", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.retire, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"additions\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.additions, out)?;
            out.push_str(",\"retire\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.retire, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for LaneLifecyclePlan {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut additions: Option<Vec<LaneConfig>> = None;
        let mut retire: Option<Vec<LaneId>> = None;
        while let Some(key) = visitor.next_key()? {
            match key.as_str() {
                "additions" => {
                    if additions.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `additions` in lane lifecycle plan".into(),
                        ));
                    }
                    additions = Some(visitor.parse_value()?);
                }
                "retire" => {
                    if retire.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `retire` in lane lifecycle plan".into(),
                        ));
                    }
                    retire = Some(visitor.parse_value()?);
                }
                other => {
                    return Err(norito::json::Error::Message(format!(
                        "unknown field `{other}` in lane lifecycle plan"
                    )));
                }
            }
        }
        visitor.finish()?;
        Ok(Self {
            additions: additions.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required lane lifecycle plan field `additions`".into(),
                )
            })?,
            retire: retire.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required lane lifecycle plan field `retire`".into(),
                )
            })?,
        })
    }
}

impl norito::json::FastJsonWrite for LaneLifecycleParameterV1 {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("version", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.version, out);
        out.push(',');
        norito::json::write_json_string("expected_catalog_hash", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.expected_catalog_hash, out);
        out.push(',');
        norito::json::write_json_string("expected_incarnation_root", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.expected_incarnation_root, out);
        out.push(',');
        norito::json::write_json_string("plan", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.plan, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"version\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.version, out)?;
            out.push_str(",\"expected_catalog_hash\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.expected_catalog_hash, out)?;
            out.push_str(",\"expected_incarnation_root\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.expected_incarnation_root, out)?;
            out.push_str(",\"plan\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.plan, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for LaneLifecycleParameterV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut version = None;
        let mut expected_catalog_hash = None;
        let mut expected_incarnation_root = None;
        let mut plan = None;
        while let Some(key) = visitor.next_key()? {
            match key.as_str() {
                "version" => {
                    if version.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `version` in Nexus lane lifecycle parameter".into(),
                        ));
                    }
                    version = Some(visitor.parse_value()?);
                }
                "expected_catalog_hash" => {
                    if expected_catalog_hash.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `expected_catalog_hash` in Nexus lane lifecycle parameter"
                                .into(),
                        ));
                    }
                    expected_catalog_hash = Some(visitor.parse_value()?);
                }
                "plan" => {
                    if plan.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `plan` in Nexus lane lifecycle parameter".into(),
                        ));
                    }
                    plan = Some(visitor.parse_value()?);
                }
                "expected_incarnation_root" => {
                    if expected_incarnation_root.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `expected_incarnation_root` in Nexus lane lifecycle parameter"
                                .into(),
                        ));
                    }
                    expected_incarnation_root = Some(visitor.parse_value()?);
                }
                other => {
                    return Err(norito::json::Error::Message(format!(
                        "unknown field `{other}` in Nexus lane lifecycle parameter"
                    )));
                }
            }
        }
        visitor.finish()?;
        Ok(Self {
            version: version.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required Nexus lane lifecycle field `version`".into(),
                )
            })?,
            expected_catalog_hash: expected_catalog_hash.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required Nexus lane lifecycle field `expected_catalog_hash`".into(),
                )
            })?,
            expected_incarnation_root: expected_incarnation_root.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required Nexus lane lifecycle field `expected_incarnation_root`"
                        .into(),
                )
            })?,
            plan: plan.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required Nexus lane lifecycle field `plan`".into(),
                )
            })?,
        })
    }
}

impl norito::json::FastJsonWrite for LaneLifecycleIncarnationEntry {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("lane_id", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.lane_id, out);
        out.push(',');
        norito::json::write_json_string("incarnation", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.incarnation, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"lane_id\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.lane_id, out)?;
            out.push_str(",\"incarnation\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.incarnation, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for LaneLifecycleIncarnationEntry {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut lane_id = None;
        let mut incarnation = None;
        while let Some(key) = visitor.next_key()? {
            match key.as_str() {
                "lane_id" => {
                    if lane_id.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `lane_id` in lane lifecycle incarnation".into(),
                        ));
                    }
                    lane_id = Some(visitor.parse_value()?);
                }
                "incarnation" => {
                    if incarnation.is_some() {
                        return Err(norito::json::Error::Message(
                            "duplicate field `incarnation` in lane lifecycle incarnation".into(),
                        ));
                    }
                    incarnation = Some(visitor.parse_value()?);
                }
                other => {
                    return Err(norito::json::Error::Message(format!(
                        "unknown field `{other}` in lane lifecycle incarnation"
                    )));
                }
            }
        }
        visitor.finish()?;
        Ok(Self {
            lane_id: lane_id.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required lane lifecycle incarnation field `lane_id`".into(),
                )
            })?,
            incarnation: incarnation.ok_or_else(|| {
                norito::json::Error::Message(
                    "missing required lane lifecycle incarnation field `incarnation`".into(),
                )
            })?,
        })
    }
}

impl norito::json::FastJsonWrite for LaneLifecycleStatusV1 {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        norito::json::write_json_string("version", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.version, out);
        out.push(',');
        norito::json::write_json_string("lane_count", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.lane_count, out);
        out.push(',');
        norito::json::write_json_string("lanes", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.lanes, out);
        out.push(',');
        norito::json::write_json_string("catalog_hash", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.catalog_hash, out);
        out.push(',');
        norito::json::write_json_string("incarnations", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.incarnations, out);
        out.push(',');
        norito::json::write_json_string("incarnation_root", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.incarnation_root, out);
        out.push(',');
        norito::json::write_json_string("runtime_catalog_hash", out);
        out.push(':');
        norito::json::JsonSerialize::json_serialize(&self.runtime_catalog_hash, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"version\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.version, out)?;
            out.push_str(",\"lane_count\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.lane_count, out)?;
            out.push_str(",\"lanes\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.lanes, out)?;
            out.push_str(",\"catalog_hash\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.catalog_hash, out)?;
            out.push_str(",\"incarnations\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.incarnations, out)?;
            out.push_str(",\"incarnation_root\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.incarnation_root, out)?;
            out.push_str(",\"runtime_catalog_hash\":")?;
            norito::json::JsonSerialize::json_serialize_to(&self.runtime_catalog_hash, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl norito::json::JsonDeserialize for LaneLifecycleStatusV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        use norito::json::MapVisitor;
        let mut visitor = MapVisitor::new(parser)?;
        let mut version = None;
        let mut lane_count = None;
        let mut lanes = None;
        let mut catalog_hash = None;
        let mut incarnations = None;
        let mut incarnation_root = None;
        let mut runtime_catalog_hash: Option<Option<Hash>> = None;
        while let Some(key) = visitor.next_key()? {
            let duplicate = |field: &str| {
                norito::json::Error::Message(format!(
                    "duplicate field `{field}` in Nexus lane lifecycle status"
                ))
            };
            match key.as_str() {
                "version" => {
                    if version.is_some() {
                        return Err(duplicate("version"));
                    }
                    version = Some(visitor.parse_value()?);
                }
                "lane_count" => {
                    if lane_count.is_some() {
                        return Err(duplicate("lane_count"));
                    }
                    lane_count = Some(visitor.parse_value()?);
                }
                "lanes" => {
                    if lanes.is_some() {
                        return Err(duplicate("lanes"));
                    }
                    lanes = Some(visitor.parse_value()?);
                }
                "catalog_hash" => {
                    if catalog_hash.is_some() {
                        return Err(duplicate("catalog_hash"));
                    }
                    catalog_hash = Some(visitor.parse_value()?);
                }
                "incarnations" => {
                    if incarnations.is_some() {
                        return Err(duplicate("incarnations"));
                    }
                    incarnations = Some(visitor.parse_value()?);
                }
                "incarnation_root" => {
                    if incarnation_root.is_some() {
                        return Err(duplicate("incarnation_root"));
                    }
                    incarnation_root = Some(visitor.parse_value()?);
                }
                "runtime_catalog_hash" => {
                    if runtime_catalog_hash.is_some() {
                        return Err(duplicate("runtime_catalog_hash"));
                    }
                    runtime_catalog_hash = Some(visitor.parse_value()?);
                }
                other => {
                    return Err(norito::json::Error::Message(format!(
                        "unknown field `{other}` in Nexus lane lifecycle status"
                    )));
                }
            }
        }
        visitor.finish()?;
        let missing = |field: &str| {
            norito::json::Error::Message(format!(
                "missing required Nexus lane lifecycle status field `{field}`"
            ))
        };
        Ok(Self {
            version: version.ok_or_else(|| missing("version"))?,
            lane_count: lane_count.ok_or_else(|| missing("lane_count"))?,
            lanes: lanes.ok_or_else(|| missing("lanes"))?,
            catalog_hash: catalog_hash.ok_or_else(|| missing("catalog_hash"))?,
            incarnations: incarnations.ok_or_else(|| missing("incarnations"))?,
            incarnation_root: incarnation_root.ok_or_else(|| missing("incarnation_root"))?,
            runtime_catalog_hash: runtime_catalog_hash
                .ok_or_else(|| missing("runtime_catalog_hash"))?,
        })
    }
}
/// Validated catalog of configured lanes.
///
/// `lane_count` is the exclusive identifier bound for the current namespace, not the number of
/// active entries. Catalogs may be sparse, and lifecycle additions can expand the bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneCatalog {
    lane_count: NonZeroU32,
    lanes: Vec<LaneConfig>,
}
impl LaneCatalog {
    /// Build a catalog ensuring identifiers and aliases are unique and in range.
    ///
    /// Every lane of one dataspace shares one [`LaneVisibility`], and the universal dataspace is
    /// always public, so a dataspace has a single read and disclosure class.
    ///
    /// # Errors
    /// Returns a [`LaneCatalogError`] when lane metadata uses the retired shard key, carries an
    /// invalid functional policy, violates alias or identifier uniqueness, exceeds the configured
    /// lane count, exceeds the consensus-wide active-lane bound, mixes visibilities within one
    /// dataspace, or restricts a universal lane.
    pub fn new(
        lane_count: NonZeroU32,
        mut lanes: Vec<LaneConfig>,
    ) -> Result<Self, LaneCatalogError> {
        if lanes.is_empty() {
            return Err(LaneCatalogError::EmptyCatalog);
        }
        if lanes.len() > MAX_ACTIVE_EXECUTION_LANES {
            return Err(LaneCatalogError::ActiveLaneBoundExceeded {
                actual: lanes.len(),
                maximum: MAX_ACTIVE_EXECUTION_LANES,
            });
        }
        let mut seen_ids = BTreeSet::new();
        let mut seen_aliases = BTreeSet::new();
        let mut dataspace_visibility = BTreeMap::new();
        for lane in &lanes {
            if lane.alias.trim().is_empty() {
                return Err(LaneCatalogError::EmptyAlias(lane.id));
            }
            if lane.dataspace_id == DataSpaceId::UNIVERSAL
                && lane.visibility != LaneVisibility::Public
            {
                return Err(LaneCatalogError::RestrictedUniversalLane(lane.id));
            }
            if *dataspace_visibility
                .entry(lane.dataspace_id)
                .or_insert(lane.visibility)
                != lane.visibility
            {
                return Err(LaneCatalogError::MixedDataspaceVisibility {
                    dataspace: lane.dataspace_id,
                });
            }
            lane.validate_policy_surface()?;
            if lane.id.as_u32() >= lane_count.get() {
                return Err(LaneCatalogError::LaneOutOfBounds {
                    lane: lane.id,
                    lane_count: lane_count.get(),
                });
            }
            if !seen_ids.insert(lane.id) {
                return Err(LaneCatalogError::DuplicateLaneId(lane.id));
            }
            if !seen_aliases.insert(lane.alias.clone()) {
                return Err(LaneCatalogError::DuplicateLaneAlias(lane.alias.clone()));
            }
        }
        // Catalog iteration feeds derived storage geometry, snapshot encoding,
        // and lifecycle commitments. Canonicalize it here so semantically
        // identical configuration files cannot disagree about the primary
        // lane or any other order-sensitive derived artifact.
        lanes.sort_unstable_by_key(|lane| lane.id);
        Ok(Self { lane_count, lanes })
    }
    /// Exclusive lane-id bound for the current catalog namespace.
    ///
    /// This can exceed [`Self::lanes`]'s length when the catalog is sparse.
    #[must_use]
    pub const fn lane_count(&self) -> NonZeroU32 {
        self.lane_count
    }
    /// Metadata for all registered lanes.
    #[must_use]
    pub fn lanes(&self) -> &[LaneConfig] {
        &self.lanes
    }
    /// Project the namespace bound and canonically ordered lanes onto consensus-relevant fields.
    #[must_use]
    pub fn consensus_projection(&self) -> (u32, Vec<LaneConsensusProjectionV1>) {
        (
            self.lane_count.get(),
            self.lanes
                .iter()
                .map(LaneConfig::consensus_projection)
                .collect(),
        )
    }
    /// Find a lane by alias.
    #[must_use]
    pub fn by_alias(&self, alias: &str) -> Option<&LaneConfig> {
        self.lanes.iter().find(|lane| lane.alias == alias)
    }
    /// The single visibility shared by every lane of `dataspace`, or `None` when the catalog
    /// has no lane for it.
    #[must_use]
    pub fn dataspace_visibility(&self, dataspace: DataSpaceId) -> Option<LaneVisibility> {
        self.lanes
            .iter()
            .find(|lane| lane.dataspace_id == dataspace)
            .map(|lane| lane.visibility)
    }
    /// Apply a lifecycle plan, producing a new catalog with the requested additions and retirements.
    ///
    /// The exclusive namespace bound expands for higher additions but never shrinks when lanes are
    /// retired, preserving sparse identifiers and retained incarnation lineage.
    ///
    /// # Errors
    /// Returns a [`LaneCatalogError`] when additions or retirements are duplicated, retirements
    /// reference unknown lanes, or the resulting catalog is invalid (empty, duplicate
    /// identifiers/aliases, out-of-bounds ids, or too many active entries).
    pub fn apply_lifecycle(&self, plan: &LaneLifecyclePlan) -> Result<Self, LaneCatalogError> {
        let mut retire_set = BTreeSet::new();
        for retire_id in &plan.retire {
            if !retire_set.insert(*retire_id) {
                return Err(LaneCatalogError::DuplicateRetireLane(*retire_id));
            }
        }
        for retire_id in &retire_set {
            let present = self.lanes.iter().any(|lane| lane.id == *retire_id);
            if !present {
                return Err(LaneCatalogError::MissingLane(*retire_id));
            }
        }
        let mut addition_ids = BTreeSet::new();
        let mut addition_aliases = BTreeSet::new();
        for addition in &plan.additions {
            if addition.alias.trim().is_empty() {
                return Err(LaneCatalogError::EmptyAlias(addition.id));
            }
            if !addition_ids.insert(addition.id) {
                return Err(LaneCatalogError::DuplicateLaneId(addition.id));
            }
            if !addition_aliases.insert(addition.alias.as_str()) {
                return Err(LaneCatalogError::DuplicateLaneAlias(addition.alias.clone()));
            }
        }
        let mut merged: Vec<LaneConfig> = self
            .lanes
            .iter()
            .filter(|lane| !retire_set.contains(&lane.id))
            .cloned()
            .collect();
        merged.extend(plan.additions.iter().cloned());
        let Some(max_lane_id) = merged.iter().map(|lane| lane.id.as_u32()).max() else {
            return Err(LaneCatalogError::EmptyCatalog);
        };
        let lane_count = NonZeroU32::new(self.lane_count.get().max(max_lane_id.saturating_add(1)))
            .expect("lane ids are u32 so +1 always fits NonZeroU32");
        LaneCatalog::new(lane_count, merged)
    }
}
impl Default for LaneCatalog {
    fn default() -> Self {
        Self {
            lane_count: NonZeroU32::new(1).expect("nonzero lane count"),
            lanes: vec![LaneConfig::default()],
        }
    }
}
/// Errors returned when constructing a [`LaneCatalog`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LaneCatalogError {
    /// Duplicate lane identifier detected.
    #[error("duplicate lane id {0}")]
    DuplicateLaneId(LaneId),
    /// Duplicate alias detected.
    #[error("duplicate lane alias {0}")]
    DuplicateLaneAlias(String),
    /// Retire plan referenced a lane that does not exist.
    #[error("cannot retire unknown lane {0}")]
    MissingLane(LaneId),
    /// Retire plan referenced the same lane more than once.
    #[error("duplicate retire lane {0}")]
    DuplicateRetireLane(LaneId),
    /// Alias was left blank.
    #[error("lane {0} has an empty alias")]
    EmptyAlias(LaneId),
    /// Lane used the retired string metadata representation for its shard override.
    #[error("lane {0} uses retired metadata key `da_shard_id`; use the typed `shard_id` field")]
    RetiredShardIdMetadata(LaneId),
    /// Lane used a retired string metadata key for typed functional policy.
    #[error(
        "lane {lane} uses retired functional metadata key `{key}`; use typed lane policy fields"
    )]
    RetiredFunctionalMetadata {
        /// Lane carrying the retired metadata key.
        lane: LaneId,
        /// Retired key which must be represented by a typed field.
        key: String,
    },
    /// Lane functional policy was internally inconsistent.
    #[error("lane {lane} has invalid functional policy: {reason}")]
    InvalidFunctionalPolicy {
        /// Lane carrying the invalid policy metadata.
        lane: LaneId,
        /// Deterministic explanation of the rejected metadata.
        reason: String,
    },
    /// Lifecycle plan would leave the catalog empty.
    #[error("lane catalog cannot be empty")]
    EmptyCatalog,
    /// Catalog contains more simultaneously active lanes than consensus can represent.
    #[error("lane catalog has {actual} active entries, exceeding the consensus maximum {maximum}")]
    ActiveLaneBoundExceeded {
        /// Number of active entries supplied.
        actual: usize,
        /// Consensus-wide active-entry maximum.
        maximum: usize,
    },
    /// Lane identifier outside the configured lane count.
    #[error("lane {lane} exceeds configured lane count {lane_count}")]
    LaneOutOfBounds {
        /// Identifier that exceeded the configured lane count.
        lane: LaneId,
        /// Total number of configured lanes.
        lane_count: u32,
    },
    /// Lanes of one dataspace declared different visibilities.
    #[error("dataspace {} mixes public and restricted lanes", dataspace.as_u64())]
    MixedDataspaceVisibility {
        /// Dataspace whose lanes disagree about their visibility.
        dataspace: DataSpaceId,
    },
    /// A lane of the universal dataspace was declared restricted.
    #[error("universal lane {0} must be public")]
    RestrictedUniversalLane(LaneId),
}
/// Metadata describing a configured physical data space.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::nexus::DataSpaceMetadata")]
pub struct DataSpaceMetadata {
    /// Identifier assigned to the data space.
    pub id: DataSpaceId,
    /// Human-friendly alias.
    pub alias: String,
    /// Optional description for dashboards and docs.
    pub description: Option<String>,
    /// Fault tolerance value (f) used to size data-space consensus and relay committees (3f + 1).
    pub fault_tolerance: u32,
}
impl Default for DataSpaceMetadata {
    fn default() -> Self {
        Self {
            id: DataSpaceId::UNIVERSAL,
            alias: "universal".to_string(),
            description: None,
            fault_tolerance: 1,
        }
    }
}
/// Validated catalog describing configured data spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSpaceCatalog {
    entries: Vec<DataSpaceMetadata>,
}
/// Borrowed lookup in one already validated dataspace catalog or its scoped overlay.
///
/// A read projection can retain native catalog owners without copying their strings or
/// descriptions. Implementations must expose one unambiguous identifier/alias binding.
pub trait DataSpaceCatalogRead {
    /// Borrow the entry whose canonical alias matches `alias`.
    fn by_alias(&self, alias: &str) -> Option<&DataSpaceMetadata>;
    /// Borrow the entry whose identifier matches `id`.
    fn by_id(&self, id: DataSpaceId) -> Option<&DataSpaceMetadata>;
}
impl DataSpaceCatalogRead for DataSpaceCatalog {
    fn by_alias(&self, alias: &str) -> Option<&DataSpaceMetadata> {
        self.by_alias(alias)
    }
    fn by_id(&self, id: DataSpaceId) -> Option<&DataSpaceMetadata> {
        self.by_id(id)
    }
}
impl DataSpaceCatalog {
    /// Build a catalog ensuring identifiers and aliases remain unique.
    ///
    /// # Errors
    /// Returns a [`DataSpaceCatalogError`] when metadata reuses an identifier or alias, when
    /// an alias is left blank, or when fault tolerance is below 1. Scalar validation runs in
    /// input order, followed by alias duplicates in alias order, then identifier duplicates
    /// in identifier order. Both uniqueness passes sort the original vector in place; valid
    /// entries retain their canonical identifier order without an auxiliary allocation.
    pub fn new(mut entries: Vec<DataSpaceMetadata>) -> Result<Self, DataSpaceCatalogError> {
        for entry in &entries {
            if entry.alias.trim().is_empty() {
                return Err(DataSpaceCatalogError::EmptyAlias(entry.id));
            }
            if entry.fault_tolerance == 0 {
                return Err(DataSpaceCatalogError::InvalidFaultTolerance {
                    id: entry.id,
                    fault_tolerance: entry.fault_tolerance,
                });
            }
        }
        entries.sort_unstable_by(|left, right| left.alias.cmp(&right.alias));
        if let Some(index) = entries
            .windows(2)
            .position(|pair| pair[0].alias == pair[1].alias)
        {
            // The consumed original alias is already owned. Refusal needs no graph copy.
            return Err(DataSpaceCatalogError::DuplicateAlias(
                entries.swap_remove(index).alias,
            ));
        }
        entries.sort_unstable_by_key(|entry| entry.id);
        if let Some(pair) = entries.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(DataSpaceCatalogError::DuplicateId(pair[0].id));
        }
        Ok(Self { entries })
    }
    /// Access the catalog entries.
    #[must_use]
    pub fn entries(&self) -> &[DataSpaceMetadata] {
        &self.entries
    }
    /// Find an entry by alias.
    #[must_use]
    pub fn by_alias(&self, alias: &str) -> Option<&DataSpaceMetadata> {
        self.entries.iter().find(|entry| entry.alias == alias)
    }
    /// Find an entry by identifier.
    #[must_use]
    pub fn by_id(&self, id: DataSpaceId) -> Option<&DataSpaceMetadata> {
        self.entries.iter().find(|entry| entry.id == id)
    }
}
impl Default for DataSpaceCatalog {
    fn default() -> Self {
        Self {
            entries: vec![DataSpaceMetadata::default()],
        }
    }
}
/// Errors returned when constructing a [`DataSpaceCatalog`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DataSpaceCatalogError {
    /// Duplicate identifier encountered.
    #[error("duplicate dataspace id {0}")]
    DuplicateId(DataSpaceId),
    /// Duplicate alias encountered.
    #[error("duplicate dataspace alias {0}")]
    DuplicateAlias(String),
    /// Alias field left blank.
    #[error("dataspace {0} has an empty alias")]
    EmptyAlias(DataSpaceId),
    /// Fault tolerance must be at least 1.
    #[error("dataspace {id} has invalid fault_tolerance {fault_tolerance}; must be >= 1")]
    InvalidFaultTolerance {
        /// Dataspace identifier with an invalid fault tolerance value.
        id: DataSpaceId,
        /// Fault tolerance value that failed validation.
        fault_tolerance: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da::confidential_compute::ConfidentialComputeMechanism;
    use iroha_crypto::{Algorithm, KeyPair};
    use norito::codec::{DecodeAll, Encode};
    use std::num::{NonZeroU32, NonZeroU64};
    fn settlement_buffer_policy() -> LaneSettlementBufferPolicy {
        let keypair = KeyPair::try_from_seed(vec![0xA5; 32], Algorithm::Ed25519)
            .expect("settlement account key");
        let account_id = AccountId::new(keypair.public_key().clone());
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("settlement", "universal")
                .expect("settlement domain"),
            "xor".parse().expect("asset name"),
        );
        LaneSettlementBufferPolicy::new(
            account_id,
            asset_definition_id,
            "1000".parse().expect("positive XOR capacity"),
        )
    }
    fn incarnation_map(catalog: &LaneCatalog) -> BTreeMap<LaneId, Hash> {
        catalog
            .lanes()
            .iter()
            .map(|lane| {
                (
                    lane.id,
                    Hash::new(format!("test-lane-incarnation-{}", lane.id.as_u32())),
                )
            })
            .collect()
    }
    fn lifecycle_status(catalog: &LaneCatalog) -> LaneLifecycleStatusV1 {
        LaneLifecycleStatusV1::new(catalog, &incarnation_map(catalog), None)
            .expect("valid lifecycle status")
    }
    #[test]
    fn lane_profile_labels_are_canonical() {
        assert_eq!(
            "public".parse::<LaneVisibility>().expect("public lane"),
            LaneVisibility::Public
        );
        assert_eq!(
            "split_replica"
                .parse::<LaneStorageProfile>()
                .expect("split replica"),
            LaneStorageProfile::SplitReplica
        );
        assert_eq!(
            "audit"
                .parse::<DaManifestPolicy>()
                .expect("audit manifest policy"),
            DaManifestPolicy::Audit
        );
        for retired_alias in ["Public", "PUBLIC", "Restricted"] {
            assert!(
                retired_alias.parse::<LaneVisibility>().is_err(),
                "non-canonical visibility `{retired_alias}` must fail closed"
            );
        }
        for retired_alias in ["Full_Replica", "FULL_REPLICA", "split-replica"] {
            assert!(
                retired_alias.parse::<LaneStorageProfile>().is_err(),
                "non-canonical storage profile `{retired_alias}` must fail closed"
            );
        }
        for retired_alias in ["Audit", "audit_only", "warn"] {
            assert!(
                retired_alias.parse::<DaManifestPolicy>().is_err(),
                "non-canonical manifest policy `{retired_alias}` must fail closed"
            );
        }
        for retired_alias in ["MerkleSha256", "merkle-sha256", "MERKLE_SHA256"] {
            assert!(
                retired_alias.parse::<DaProofScheme>().is_err(),
                "non-canonical proof scheme `{retired_alias}` must fail closed"
            );
        }
    }
    #[test]
    fn lane_catalog_validates_alias_and_range() {
        let lane_count = NonZeroU32::new(2).expect("nonzero");
        let catalog = LaneCatalog::new(
            lane_count,
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "alpha".into(),
                description: None,
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        assert_eq!(catalog.lane_count(), lane_count);
        assert!(catalog.by_alias("alpha").is_some());
        let dup = LaneCatalog::new(
            lane_count,
            vec![
                LaneConfig {
                    id: LaneId::new(0),
                    alias: "dup".into(),
                    description: None,
                    ..LaneConfig::default()
                },
                LaneConfig {
                    id: LaneId::new(0),
                    alias: "dup".into(),
                    description: None,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect_err("duplicate lanes");
        assert!(matches!(dup, LaneCatalogError::DuplicateLaneId(_)));
        let out_of_range = LaneCatalog::new(
            lane_count,
            vec![LaneConfig {
                id: LaneId::new(5),
                alias: "gamma".into(),
                description: None,
                ..LaneConfig::default()
            }],
        )
        .expect_err("out of range lane");
        assert!(matches!(
            out_of_range,
            LaneCatalogError::LaneOutOfBounds { lane, lane_count: 2 }
                if lane.as_u32() == 5
        ));

        let mut retired_shard_metadata = LaneConfig::default();
        retired_shard_metadata
            .metadata
            .insert("da_shard_id".to_owned(), "9".to_owned());
        assert_eq!(
            LaneCatalog::new(lane_count, vec![retired_shard_metadata]),
            Err(LaneCatalogError::RetiredShardIdMetadata(LaneId::SINGLE))
        );
    }
    #[test]
    fn lane_catalog_uses_only_typed_functional_policy() {
        let lane_count = NonZeroU32::new(1).expect("nonzero lane count");
        for retired_key in RETIRED_FUNCTIONAL_METADATA_KEYS.into_iter().chain([
            "confidential_future_policy",
            "scheduler.future_policy",
            "settlement.buffer_future_policy",
        ]) {
            let mut retired = LaneConfig::default();
            retired
                .metadata
                .insert(retired_key.to_owned(), "retired".to_owned());
            assert!(matches!(
                LaneCatalog::new(lane_count, vec![retired]),
                Err(LaneCatalogError::RetiredFunctionalMetadata { lane, key })
                    if lane == LaneId::SINGLE && key == retired_key
            ));
        }

        let full_replica = LaneConfig {
            confidential_compute: Some(ConfidentialComputePolicy::new(
                ConfidentialComputeMechanism::Encryption,
                NonZeroU32::new(7).expect("nonzero key version"),
                BTreeSet::new(),
            )),
            ..LaneConfig::default()
        };
        assert!(matches!(
            LaneCatalog::new(lane_count, vec![full_replica]),
            Err(LaneCatalogError::InvalidFunctionalPolicy { .. })
        ));

        let padded_audience = LaneConfig {
            storage: LaneStorageProfile::SplitReplica,
            confidential_compute: Some(ConfidentialComputePolicy::new(
                ConfidentialComputeMechanism::SecretSharing,
                NonZeroU32::new(7).expect("nonzero key version"),
                BTreeSet::from([" auditor".to_owned()]),
            )),
            ..LaneConfig::default()
        };
        assert!(matches!(
            LaneCatalog::new(lane_count, vec![padded_audience]),
            Err(LaneCatalogError::InvalidFunctionalPolicy { .. })
        ));

        let empty_scheduler = LaneConfig {
            scheduler: Some(LaneSchedulerPolicy::new(None, None)),
            ..LaneConfig::default()
        };
        assert!(matches!(
            LaneCatalog::new(lane_count, vec![empty_scheduler]),
            Err(LaneCatalogError::InvalidFunctionalPolicy { .. })
        ));

        let mut zero_settlement = settlement_buffer_policy();
        zero_settlement.capacity = XorQuantity::zero();
        let zero_settlement = LaneConfig {
            settlement_buffer: Some(zero_settlement),
            ..LaneConfig::default()
        };
        assert!(matches!(
            LaneCatalog::new(lane_count, vec![zero_settlement]),
            Err(LaneCatalogError::InvalidFunctionalPolicy { .. })
        ));

        let confidential = LaneConfig {
            storage: LaneStorageProfile::SplitReplica,
            manifest_policy: DaManifestPolicy::Audit,
            confidential_compute: Some(ConfidentialComputePolicy::new(
                ConfidentialComputeMechanism::SecretSharing,
                NonZeroU32::new(7).expect("nonzero key version"),
                BTreeSet::from(["auditor".to_owned(), "operator".to_owned()]),
            )),
            ..LaneConfig::default()
        };
        LaneCatalog::new(lane_count, vec![confidential])
            .expect("complete typed confidential policy must be accepted");
    }
    #[test]
    fn lane_catalog_rejects_active_entries_above_consensus_bound() {
        let lanes = (0..MAX_ACTIVE_EXECUTION_LANES)
            .map(|index| LaneConfig {
                id: LaneId::new(u32::try_from(index).expect("lane index fits u32")),
                alias: format!("lane-{index}"),
                ..LaneConfig::default()
            })
            .collect::<Vec<_>>();
        let boundary_count =
            NonZeroU32::new(u32::try_from(MAX_ACTIVE_EXECUTION_LANES).expect("bound fits u32"))
                .expect("active-lane bound is non-zero");
        let catalog = LaneCatalog::new(boundary_count, lanes.clone())
            .expect("the exact active-lane protocol bound is admissible");
        let overflow_id =
            LaneId::new(u32::try_from(MAX_ACTIVE_EXECUTION_LANES).expect("bound fits u32"));
        let overflow = LaneConfig {
            id: overflow_id,
            alias: "overflow".to_owned(),
            ..LaneConfig::default()
        };
        let overflow_count = NonZeroU32::new(
            u32::try_from(MAX_ACTIVE_EXECUTION_LANES + 1).expect("bound plus one fits u32"),
        )
        .expect("bound plus one is non-zero");
        let mut oversized = lanes;
        oversized.push(overflow.clone());
        assert_eq!(
            LaneCatalog::new(overflow_count, oversized),
            Err(LaneCatalogError::ActiveLaneBoundExceeded {
                actual: MAX_ACTIVE_EXECUTION_LANES + 1,
                maximum: MAX_ACTIVE_EXECUTION_LANES,
            })
        );
        let lifecycle_error = catalog
            .apply_lifecycle(&LaneLifecyclePlan {
                additions: vec![overflow],
                retire: Vec::new(),
            })
            .expect_err("lifecycle admission must reject an unrepresentable active catalog");
        assert_eq!(
            lifecycle_error,
            LaneCatalogError::ActiveLaneBoundExceeded {
                actual: MAX_ACTIVE_EXECUTION_LANES + 1,
                maximum: MAX_ACTIVE_EXECUTION_LANES,
            }
        );
    }
    #[test]
    fn lane_catalog_canonicalizes_entry_order_and_lifecycle_commitment() {
        let lane_count = NonZeroU32::new(2).expect("nonzero lane count");
        let secondary = LaneConfig {
            id: LaneId::new(1),
            alias: "secondary".to_owned(),
            ..LaneConfig::default()
        };
        let canonical =
            LaneCatalog::new(lane_count, vec![LaneConfig::default(), secondary.clone()])
                .expect("canonical catalog");
        let permuted = LaneCatalog::new(lane_count, vec![secondary, LaneConfig::default()])
            .expect("permuted catalog");
        assert_eq!(permuted, canonical);
        assert_eq!(
            permuted
                .lanes()
                .iter()
                .map(|lane| lane.id)
                .collect::<Vec<_>>(),
            vec![LaneId::SINGLE, LaneId::new(1)]
        );
        assert_eq!(
            LaneLifecycleParameterV1::catalog_hash(&permuted),
            LaneLifecycleParameterV1::catalog_hash(&canonical),
            "semantic catalog permutations must share one optimistic-concurrency commitment"
        );
    }
    #[test]
    fn lane_config_roundtrips_every_typed_policy_field() {
        let mut metadata = BTreeMap::new();
        metadata.insert("instrumentation.owner".to_string(), "ops".to_string());
        let config = LaneConfig {
            id: LaneId::new(1),
            shard_id: Some(ShardId::new(9)),
            dataspace_id: DataSpaceId::new(5),
            alias: "governance".to_string(),
            description: Some("Governance lane".to_string()),
            visibility: LaneVisibility::Restricted,
            lane_type: Some("governance".to_string()),
            governance: Some("parliament".to_string()),
            settlement: Some("xor_lane".to_string()),
            storage: LaneStorageProfile::CommitmentOnly,
            proof_scheme: DaProofScheme::default(),
            manifest_policy: DaManifestPolicy::Audit,
            confidential_compute: Some(ConfidentialComputePolicy::new(
                ConfidentialComputeMechanism::Encryption,
                NonZeroU32::new(11).expect("non-zero key version"),
                BTreeSet::from(["auditor".to_owned(), "operator".to_owned()]),
            )),
            scheduler: Some(LaneSchedulerPolicy::new(
                Some(NonZeroU64::new(1024).expect("positive TEU capacity")),
                Some(NonZeroU64::new(6).expect("positive starvation bound")),
            )),
            settlement_buffer: Some(settlement_buffer_policy()),
            metadata,
        };
        let bytes = Encode::encode(&config);
        let mut slice: &[u8] = &bytes;
        let decoded = LaneConfig::decode_all(&mut slice).expect("decode LaneConfig");
        assert_eq!(decoded, config);
        assert_eq!(decoded.effective_shard_id(), ShardId::new(9));
        let json = norito::json::to_string(&config).expect("encode LaneConfig JSON");
        let decoded_json =
            norito::json::from_str::<LaneConfig>(&json).expect("decode LaneConfig JSON");
        assert_eq!(decoded_json, config);
    }
    #[test]
    fn lane_config_rejects_retired_policy_metadata_after_json_or_norito_decode() {
        for retired_key in RETIRED_FUNCTIONAL_METADATA_KEYS.into_iter().chain([
            "confidential_future_policy",
            "scheduler.future_policy",
            "settlement.buffer_future_policy",
        ]) {
            let mut retired = LaneConfig::default();
            retired
                .metadata
                .insert(retired_key.to_owned(), "retired".to_owned());

            let encoded_json =
                norito::json::to_string(&retired).expect("encode retired JSON fixture");
            let json_error = norito::json::from_str::<LaneConfig>(&encoded_json)
                .expect_err("JSON must reject retired functional metadata");
            assert!(
                json_error.to_string().contains(retired_key),
                "unexpected JSON rejection for `{retired_key}`: {json_error}"
            );

            let encoded = retired.encode();
            let mut encoded = encoded.as_slice();
            let decoded = LaneConfig::decode_all(&mut encoded)
                .expect("Norito retains the raw value until catalog admission");
            assert!(matches!(
                LaneCatalog::new(NonZeroU32::new(1).expect("non-zero"), vec![decoded]),
                Err(LaneCatalogError::RetiredFunctionalMetadata { lane, key })
                    if lane == LaneId::SINGLE && key == retired_key
            ));
        }
    }
    #[test]
    fn lane_config_shard_defaults_to_lane_identifier() {
        let config = LaneConfig {
            id: LaneId::new(7),
            alias: "default-shard".to_owned(),
            ..LaneConfig::default()
        };
        assert_eq!(config.shard_id, None);
        assert_eq!(config.effective_shard_id(), ShardId::new(7));

        let mut following_clone = config.clone();
        following_clone.id = LaneId::new(8);
        assert_eq!(following_clone.effective_shard_id(), ShardId::new(8));

        let mut pinned_clone = config;
        pinned_clone.shard_id = Some(ShardId::new(7));
        pinned_clone.id = LaneId::new(8);
        assert_eq!(pinned_clone.effective_shard_id(), ShardId::new(7));
    }
    #[test]
    fn dataspace_catalog_validates_entries() {
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata {
                id: DataSpaceId::new(2),
                alias: "settlement".into(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: DataSpaceId::new(1),
                alias: "telemetry".into(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("valid dataspace");
        assert!(catalog.by_alias("telemetry").is_some());
        assert_eq!(
            catalog
                .entries()
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            vec![DataSpaceId::new(1), DataSpaceId::new(2)],
            "catalog construction must canonicalize semantic entry order"
        );
        let invalid_fault_tolerance = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: DataSpaceId::new(9),
            alias: "invalid".into(),
            description: None,
            fault_tolerance: 0,
        }])
        .expect_err("fault tolerance below 1 should fail");
        assert!(matches!(
            invalid_fault_tolerance,
            DataSpaceCatalogError::InvalidFaultTolerance { .. }
        ));
        let dup = DataSpaceCatalog::new(vec![
            DataSpaceMetadata {
                id: DataSpaceId::new(2),
                alias: "different".into(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: DataSpaceId::new(2),
                alias: "ops".into(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect_err("duplicate dataspace");
        assert!(matches!(dup, DataSpaceCatalogError::DuplicateId(_)));
        let empty_alias = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: DataSpaceId::new(3),
            alias: "   ".into(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect_err("blank alias");
        assert!(matches!(empty_alias, DataSpaceCatalogError::EmptyAlias(_)));
    }

    #[test]
    fn dataspace_catalog_duplicate_alias_moves_original_storage_and_precedes_ids() {
        let first = DataSpaceMetadata {
            id: DataSpaceId::new(2),
            alias: "shared-alias".to_owned(),
            description: None,
            fault_tolerance: 1,
        };
        let second = first.clone();
        let original_aliases = [first.alias.as_ptr(), second.alias.as_ptr()];
        let error = DataSpaceCatalog::new(vec![first, second]).unwrap_err();
        let DataSpaceCatalogError::DuplicateAlias(alias) = error else {
            panic!("alias duplicate must precede the simultaneous identifier duplicate");
        };
        assert_eq!(alias, "shared-alias");
        assert!(
            original_aliases.contains(&alias.as_ptr()),
            "the returned error moves an original alias instead of allocating a clone"
        );

        let error = DataSpaceCatalog::new(vec![
            DataSpaceMetadata {
                id: DataSpaceId::new(2),
                alias: "same".into(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: DataSpaceId::new(3),
                alias: "same".into(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .unwrap_err();
        assert!(matches!(error, DataSpaceCatalogError::DuplicateAlias(alias) if alias == "same"));
        let error = DataSpaceCatalog::new(vec![
            DataSpaceMetadata {
                id: DataSpaceId::new(2),
                alias: "same".into(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: DataSpaceId::new(2),
                alias: "same".into(),
                description: None,
                fault_tolerance: 0,
            },
        ])
        .unwrap_err();
        assert!(
            matches!(error, DataSpaceCatalogError::InvalidFaultTolerance { .. }),
            "scalar errors precede either uniqueness pass"
        );
    }

    #[test]
    fn dataspace_catalog_sorts_original_graph_without_changing_native_wire_or_hash() {
        let mut entries: Vec<_> = (1_u64..=4096)
            .rev()
            .map(|id| DataSpaceMetadata {
                id: DataSpaceId::new(id),
                // This alias order deliberately differs from the final identifier order.
                alias: format!("entry-{}", 4097 - id),
                description: Some(format!("retained description {id}")),
                fault_tolerance: 1,
            })
            .collect();
        let original_allocation = entries.as_ptr();
        let original_capacity = entries.capacity();
        let mut expected = entries.clone();
        expected.sort_unstable_by_key(|entry| entry.id);
        let expected_wire = expected.encode();
        let expected_hash = iroha_crypto::Hash::new_from_chunks(&[
            b"iroha:nexus:dataspace-catalog:v1\0",
            &expected_wire,
        ]);
        let catalog = DataSpaceCatalog::new(std::mem::take(&mut entries)).unwrap();
        assert_eq!(catalog.entries.as_ptr(), original_allocation);
        assert_eq!(catalog.entries.capacity(), original_capacity);
        assert_eq!(catalog.entries, expected);
        assert_eq!(catalog.entries.encode(), expected_wire);
        assert_eq!(try_dataspace_catalog_hash(&catalog).unwrap(), expected_hash);
    }
    #[test]
    fn dataspace_default_fault_tolerance_is_nonzero() {
        let entry = DataSpaceMetadata::default();
        assert_eq!(entry.fault_tolerance, 1);
        assert_eq!(entry.alias, "universal");
    }
    #[test]
    fn lane_consensus_projection_binds_alias_and_reserved_metadata_only() {
        let mut lane = LaneConfig {
            id: LaneId::new(3),
            alias: "elastic-lane-3".into(),
            description: Some("operator presentation".into()),
            ..LaneConfig::default()
        };
        lane.metadata
            .insert(AUTOSCALE_META_MANAGED.into(), "true".into());
        let projection = lane.consensus_projection();
        assert_eq!(
            <LaneConsensusProjectionV1 as norito::NoritoSchema>::nominal_name(),
            "iroha_data_model::nexus::LaneConsensusProjectionV1"
        );
        let bytes = norito::encode_canonical(&projection).expect("canonical projection");
        assert_eq!(
            norito::decode_canonical::<LaneConsensusProjectionV1>(&bytes)
                .expect("decode canonical projection"),
            projection
        );

        let mut changed = lane.clone();
        changed.alias = "manual-lane-3".into();
        assert_ne!(changed.consensus_projection(), projection);
        let mut changed = lane.clone();
        changed
            .metadata
            .insert(AUTOSCALE_META_MANAGED.into(), "false".into());
        assert_ne!(changed.consensus_projection(), projection);

        lane.description = Some("changed presentation".into());
        lane.metadata
            .insert("operator.color".into(), "green".into());
        assert_eq!(lane.consensus_projection(), projection);
    }
    #[test]
    fn lane_config_identifies_only_valid_autoscale_managed_elastic_lanes() {
        let mut lane = LaneConfig {
            id: LaneId::new(3),
            alias: "elastic-lane-3".into(),
            ..LaneConfig::default()
        };
        assert!(!lane.claims_autoscale_managed());
        assert!(!lane.is_autoscale_managed_elastic());
        lane.metadata
            .insert(AUTOSCALE_META_MANAGED.into(), "true".into());
        lane.metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.into(), "42".into());
        assert!(lane.claims_autoscale_managed());
        assert_eq!(lane.autoscale_created_height(), Some(42));
        assert!(lane.is_autoscale_managed_elastic());
        assert!(!lane.has_autoscale_drain_state());
        lane.metadata.insert(
            AUTOSCALE_META_DRAIN_STATE.into(),
            "canonical-drain-state".into(),
        );
        assert!(lane.has_autoscale_drain_state());
        assert!(!lane.has_autoscale_committee());
        lane.metadata.insert(
            AUTOSCALE_META_COMMITTEE.into(),
            "canonical-incarnation-committee".into(),
        );
        assert!(lane.has_autoscale_committee());
        assert!(lane.is_autoscale_managed_elastic());
        let mut spoofed_value = lane.clone();
        spoofed_value
            .metadata
            .insert(AUTOSCALE_META_MANAGED.into(), "TRUE".into());
        assert!(spoofed_value.claims_autoscale_managed());
        assert!(!spoofed_value.is_autoscale_managed_elastic());
        let mut spoofed_alias = lane.clone();
        spoofed_alias.alias = "renamed-elastic".into();
        assert!(!spoofed_alias.is_autoscale_managed_elastic());
        let mut zero_height = lane.clone();
        zero_height
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.into(), "0".into());
        assert_eq!(zero_height.autoscale_created_height(), None);
        assert!(!zero_height.is_autoscale_managed_elastic());
        let mut restricted = lane;
        restricted.visibility = LaneVisibility::Restricted;
        assert!(!restricted.is_autoscale_managed_elastic());
    }
    #[test]
    fn autoscale_profile_inheritance_ignores_identity_and_reserved_metadata_only() {
        let mut base = LaneConfig {
            id: LaneId::new(2),
            shard_id: None,
            dataspace_id: DataSpaceId::new(7),
            alias: "settlement-base".into(),
            description: Some("operator-facing base lane".into()),
            visibility: LaneVisibility::Public,
            lane_type: Some("regulated-public".into()),
            governance: Some("governance-v2".into()),
            settlement: Some("settlement-v3".into()),
            storage: LaneStorageProfile::SplitReplica,
            proof_scheme: DaProofScheme::MerkleSha256,
            manifest_policy: DaManifestPolicy::Strict,
            confidential_compute: None,
            scheduler: Some(LaneSchedulerPolicy::new(
                Some(NonZeroU64::new(2400).expect("positive TEU capacity")),
                None,
            )),
            settlement_buffer: None,
            metadata: BTreeMap::new(),
        };
        base.metadata
            .insert("security.profile".into(), "strict".into());
        let mut elastic = base.clone();
        elastic.id = LaneId::new(3);
        elastic.alias = "elastic-lane-3".into();
        elastic.description = Some("Consensus-managed elastic lane".into());
        elastic
            .metadata
            .insert(AUTOSCALE_META_MANAGED.into(), "true".into());
        elastic
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.into(), "42".into());
        assert!(elastic.inherits_autoscale_profile_from(&base));
        elastic.metadata.insert(
            AUTOSCALE_META_DRAIN_STATE.into(),
            "canonical-drain-state".into(),
        );
        assert!(elastic.inherits_autoscale_profile_from(&base));
        elastic.metadata.insert(
            AUTOSCALE_META_COMMITTEE.into(),
            "canonical-incarnation-committee".into(),
        );
        assert!(elastic.inherits_autoscale_profile_from(&base));
        let profile_drifts = [
            ("shard policy", {
                let mut drift = elastic.clone();
                drift.shard_id = Some(ShardId::new(9));
                drift
            }),
            ("dataspace", {
                let mut drift = elastic.clone();
                drift.dataspace_id = DataSpaceId::new(8);
                drift
            }),
            ("visibility", {
                let mut drift = elastic.clone();
                drift.visibility = LaneVisibility::Restricted;
                drift
            }),
            ("lane type", {
                let mut drift = elastic.clone();
                drift.lane_type = Some("unregulated".into());
                drift
            }),
            ("governance", {
                let mut drift = elastic.clone();
                drift.governance = Some("governance-v1".into());
                drift
            }),
            ("settlement", {
                let mut drift = elastic.clone();
                drift.settlement = Some("settlement-v1".into());
                drift
            }),
            ("storage", {
                let mut drift = elastic.clone();
                drift.storage = LaneStorageProfile::CommitmentOnly;
                drift
            }),
            ("metadata value", {
                let mut drift = elastic.clone();
                drift
                    .metadata
                    .insert("security.profile".into(), "permissive".into());
                drift
            }),
            ("missing scheduler policy", {
                let mut drift = elastic.clone();
                drift.scheduler = None;
                drift
            }),
            ("extra metadata", {
                let mut drift = elastic;
                drift.metadata.insert("unexpected".into(), "value".into());
                drift
            }),
        ];
        for (field, drift) in profile_drifts {
            assert!(
                !drift.inherits_autoscale_profile_from(&base),
                "autoscale profile comparison accepted {field} drift"
            );
        }
    }
    #[test]
    fn lane_lifecycle_plan_adds_and_retires() {
        let lane_count = NonZeroU32::new(2).expect("nonzero");
        let base = LaneCatalog::new(
            lane_count,
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "alpha".into(),
                ..LaneConfig::default()
            }],
        )
        .expect("base catalog");
        let plan = LaneLifecyclePlan {
            additions: vec![LaneConfig {
                id: LaneId::new(1),
                alias: "beta".into(),
                ..LaneConfig::default()
            }],
            retire: Vec::new(),
        };
        let expanded = base.apply_lifecycle(&plan).expect("apply lifecycle");
        assert_eq!(expanded.lane_count().get(), 2);
        assert!(expanded.by_alias("beta").is_some());
        let retire_plan = LaneLifecyclePlan {
            additions: Vec::new(),
            retire: vec![LaneId::new(1)],
        };
        let trimmed = expanded
            .apply_lifecycle(&retire_plan)
            .expect("retire lifecycle");
        assert_eq!(
            trimmed.lane_count().get(),
            2,
            "retiring the highest active lane must not shrink the namespace bound"
        );
        assert_eq!(trimmed.lanes().len(), 1);
        assert!(trimmed.by_alias("beta").is_none());
    }
    #[test]
    fn lane_lifecycle_parameter_roundtrips_and_binds_exact_catalog() {
        let catalog = LaneCatalog::default();
        let incarnation_entries =
            LaneLifecycleParameterV1::canonical_incarnations(&catalog, &incarnation_map(&catalog))
                .expect("canonical incarnations");
        let parameter = LaneLifecycleParameterV1::new(
            &catalog,
            &incarnation_entries,
            LaneLifecyclePlan {
                additions: vec![LaneConfig {
                    id: LaneId::new(1),
                    alias: "manual-lane".to_owned(),
                    ..LaneConfig::default()
                }],
                retire: Vec::new(),
            },
        )
        .expect("valid lifecycle parameter");
        let custom = parameter.clone().into_custom_parameter();
        assert_eq!(
            LaneLifecycleParameterV1::from_custom_parameter(&custom)
                .expect("decode lifecycle custom parameter"),
            Some(parameter.clone())
        );
        let changed = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lane count"),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "other".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("changed catalog");
        assert_ne!(
            parameter.expected_catalog_hash,
            LaneLifecycleParameterV1::catalog_hash(&changed),
            "catalog commitment must change with topology metadata"
        );
    }
    #[test]
    fn lane_lifecycle_parameter_rejects_unknown_version_and_fields() {
        let catalog = LaneCatalog::default();
        let entries = lifecycle_status(&catalog).incarnations;
        let mut unsupported =
            LaneLifecycleParameterV1::new(&catalog, &entries, LaneLifecyclePlan::default())
                .expect("valid lifecycle parameter");
        unsupported.version = LaneLifecycleParameterV1::VERSION.saturating_add(1);
        let err =
            LaneLifecycleParameterV1::from_custom_parameter(&unsupported.into_custom_parameter())
                .expect_err("unsupported lifecycle payload version must fail closed");
        assert!(err.to_string().contains("unsupported"));
        let valid = LaneLifecycleParameterV1::new(&catalog, &entries, LaneLifecyclePlan::default())
            .expect("valid lifecycle parameter");
        let mut encoded = norito::json::to_value(&valid).expect("serialize lifecycle payload");
        encoded
            .as_object_mut()
            .expect("lifecycle payload object")
            .insert("unexpected".to_owned(), norito::json::Value::Bool(true));
        let custom = CustomParameter::new(
            LaneLifecycleParameterV1::parameter_id(),
            iroha_primitives::json::Json::from_norito_value_ref(&encoded)
                .expect("serialize canonical adversarial payload"),
        );
        let err = LaneLifecycleParameterV1::from_custom_parameter(&custom)
            .expect_err("unknown lifecycle payload field must fail closed");
        assert!(err.to_string().contains("unexpected"));
    }
    #[test]
    fn lane_lifecycle_status_roundtrips_json_and_norito() {
        let catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lane count"),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "secondary".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("valid lifecycle status catalog");
        for runtime_catalog_hash in [None, Some(Hash::new(b"committed runtime overlay"))] {
            let status = LaneLifecycleStatusV1::new(
                &catalog,
                &incarnation_map(&catalog),
                runtime_catalog_hash,
            )
            .expect("valid lifecycle status");
            assert_eq!(status.validate().expect("validate status"), catalog);
            let json = norito::json::to_string(&status).expect("serialize lifecycle status JSON");
            assert_eq!(
                norito::json::to_json_bounded(&status, json.len()).expect("bounded status JSON"),
                json
            );
            assert!(norito::json::to_json_bounded(&status, json.len() - 1).is_err());
            if runtime_catalog_hash.is_none() {
                assert!(json.contains("\"runtime_catalog_hash\":null"));
            }
            let from_json = norito::json::from_str::<LaneLifecycleStatusV1>(&json)
                .expect("decode lifecycle status JSON");
            assert_eq!(from_json, status);
            let bytes = norito::to_bytes(&status).expect("encode lifecycle status Norito");
            let from_norito = norito::decode_from_bytes::<LaneLifecycleStatusV1>(&bytes)
                .expect("decode lifecycle status Norito");
            assert_eq!(from_norito, status);
        }
    }
    #[test]
    fn lane_lifecycle_status_rejects_empty_runtime_catalog_hash() {
        let catalog = LaneCatalog::default();
        let empty = Hash::prehashed([0; Hash::LENGTH]);
        assert_eq!(
            LaneLifecycleStatusV1::new(&catalog, &incarnation_map(&catalog), Some(empty)),
            Err(LaneLifecycleStatusError::ZeroRuntimeCatalogHash)
        );
        let mut status = lifecycle_status(&catalog);
        status.runtime_catalog_hash = Some(empty);
        assert_eq!(
            status.validate(),
            Err(LaneLifecycleStatusError::ZeroRuntimeCatalogHash)
        );
    }
    #[test]
    fn lane_lifecycle_status_requires_explicit_unique_nullable_runtime_catalog_hash() {
        for runtime_catalog_hash in [None, Some(Hash::new(b"committed runtime overlay"))] {
            let mut status = lifecycle_status(&LaneCatalog::default());
            status.runtime_catalog_hash = runtime_catalog_hash;
            let mut encoded = norito::json::to_string(&status).unwrap();
            assert_eq!(encoded.pop(), Some('}'));
            encoded.push_str(",\"runtime_catalog_hash\":null}");
            let error = norito::json::from_str::<LaneLifecycleStatusV1>(&encoded)
                .expect_err("duplicate runtime hash, including null, must fail");
            assert!(
                error
                    .to_string()
                    .contains("duplicate field `runtime_catalog_hash`")
            );
            let mut value = norito::json::to_value(&status).unwrap();
            let fields = value.as_object_mut().unwrap();
            fields.remove("runtime_catalog_hash").unwrap();
            let error = norito::json::from_str::<LaneLifecycleStatusV1>(
                &norito::json::to_string(&value).unwrap(),
            )
            .expect_err("missing runtime hash must not become absence");
            assert!(error.to_string().contains("runtime_catalog_hash"));
            for malformed in [
                norito::json::Value::Bool(false),
                norito::json::Value::String(String::new()),
            ] {
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("runtime_catalog_hash".into(), malformed);
                assert!(
                    norito::json::from_str::<LaneLifecycleStatusV1>(
                        &norito::json::to_string(&value).unwrap(),
                    )
                    .is_err()
                );
            }
        }
    }
    #[test]
    fn lane_lifecycle_status_rejects_forged_hash_version_and_order() {
        let mut status = lifecycle_status(&LaneCatalog::default());
        status.catalog_hash = Hash::prehashed([0xA5; Hash::LENGTH]);
        assert!(matches!(
            status.validate(),
            Err(LaneLifecycleStatusError::CatalogHashMismatch { .. })
        ));
        let mut status = lifecycle_status(&LaneCatalog::default());
        status.version = LaneLifecycleStatusV1::VERSION.saturating_add(1);
        assert!(matches!(
            status.validate(),
            Err(LaneLifecycleStatusError::UnsupportedVersion { .. })
        ));
        let canonical = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lane count"),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "secondary".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("valid catalog");
        let mut status = lifecycle_status(&canonical);
        status.lanes.reverse();
        assert_eq!(
            status.validate(),
            Err(LaneLifecycleStatusError::NonCanonicalLaneOrder)
        );
        let mut status = lifecycle_status(&canonical);
        status.incarnations.reverse();
        assert_eq!(
            status.validate(),
            Err(LaneLifecycleStatusError::NonCanonicalIncarnationOrder)
        );
        let mut status = lifecycle_status(&canonical);
        status.incarnations[1].incarnation = status.incarnations[0].incarnation;
        assert!(matches!(
            status.validate(),
            Err(LaneLifecycleStatusError::DuplicateIncarnation { .. })
        ));
        let mut status = lifecycle_status(&canonical);
        status.incarnation_root = Hash::new(b"forged-incarnation-root");
        assert!(matches!(
            status.validate(),
            Err(LaneLifecycleStatusError::IncarnationRootMismatch { .. })
        ));
    }
    #[test]
    fn lane_lifecycle_incarnation_root_changes_for_identical_catalog_replacement() {
        let catalog = LaneCatalog::default();
        let first = BTreeMap::from([(
            LaneId::SINGLE,
            Hash::new(b"lane-incarnation-before-replacement"),
        )]);
        let replacement = BTreeMap::from([(
            LaneId::SINGLE,
            Hash::new(b"lane-incarnation-after-replacement"),
        )]);
        let first_status =
            LaneLifecycleStatusV1::new(&catalog, &first, None).expect("first lifecycle status");
        let replacement_status = LaneLifecycleStatusV1::new(&catalog, &replacement, None)
            .expect("replacement lifecycle status");
        assert_eq!(first_status.catalog_hash, replacement_status.catalog_hash);
        assert_ne!(
            first_status.incarnation_root, replacement_status.incarnation_root,
            "same metadata must not make a prior-incarnation request replayable"
        );
    }
    #[test]
    fn lane_lifecycle_status_json_rejects_duplicate_unknown_and_missing_fields() {
        let status = lifecycle_status(&LaneCatalog::default());
        let encoded = norito::json::to_string(&status).expect("serialize lifecycle status");
        assert!(
            !encoded.contains("nexus_enabled"),
            "the first-release status layout must not retain the removed enablement switch"
        );
        let mut encoded = encoded;
        assert_eq!(encoded.pop(), Some('}'));
        encoded.push_str(",\"version\":1}");
        let err = norito::json::from_str::<LaneLifecycleStatusV1>(&encoded)
            .expect_err("duplicate status fields must fail closed");
        assert!(err.to_string().contains("duplicate field `version`"));
        let mut encoded = norito::json::to_string(&status).expect("serialize lifecycle status");
        assert_eq!(encoded.pop(), Some('}'));
        encoded.push_str(",\"unexpected\":true}");
        let err = norito::json::from_str::<LaneLifecycleStatusV1>(&encoded)
            .expect_err("unknown status fields must fail closed");
        assert!(err.to_string().contains("unexpected"));
        let mut encoded = norito::json::to_string(&status).expect("serialize lifecycle status");
        assert_eq!(encoded.pop(), Some('}'));
        encoded.push_str(",\"nexus_enabled\":true}");
        let err = norito::json::from_str::<LaneLifecycleStatusV1>(&encoded)
            .expect_err("the removed enablement field must fail as unknown");
        assert!(err.to_string().contains("nexus_enabled"));
        let mut value = norito::json::to_value(&status).expect("serialize lifecycle status value");
        assert!(
            value
                .as_object_mut()
                .expect("lifecycle status JSON object")
                .remove("incarnation_root")
                .is_some()
        );
        let encoded = norito::json::to_string(&value).expect("serialize shortened status");
        let err = norito::json::from_str::<LaneLifecycleStatusV1>(&encoded)
            .expect_err("a missing current field must fail closed");
        assert!(err.to_string().contains("incarnation_root"));
    }
    #[test]
    fn lane_lifecycle_plan_json_rejects_duplicate_fields() {
        let duplicate = r#"{"additions":[],"retire":[],"retire":[]}"#;
        let err = norito::json::from_str::<LaneLifecyclePlan>(duplicate)
            .expect_err("duplicate lifecycle plan field must fail closed");
        assert!(err.to_string().contains("duplicate field `retire`"));
    }
    #[test]
    fn lane_lifecycle_plan_json_requires_both_current_fields() {
        for (payload, missing) in [
            (r#"{"retire":[]}"#, "additions"),
            (r#"{"additions":[]}"#, "retire"),
        ] {
            let err = norito::json::from_str::<LaneLifecyclePlan>(payload)
                .expect_err("shortened lifecycle plan must fail closed");
            assert!(
                err.to_string().contains(&format!(
                    "missing required lane lifecycle plan field `{missing}`"
                )),
                "unexpected missing-field error: {err}"
            );
        }
    }
    #[test]
    fn lane_config_json_rejects_duplicate_fields() {
        use core::fmt::Write as _;

        let duplicate_values = [
            (
                "id",
                norito::json::to_string(&LaneId::new(1)).expect("serialize lane id"),
            ),
            (
                "alias",
                norito::json::to_string("shadow").expect("serialize lane alias"),
            ),
            ("manifest_policy", "\"audit\"".to_owned()),
            ("confidential_compute", "null".to_owned()),
            ("scheduler", "null".to_owned()),
            ("settlement_buffer", "null".to_owned()),
            ("metadata", "{}".to_owned()),
        ];
        for (field, value) in duplicate_values {
            let mut encoded =
                norito::json::to_string(&LaneConfig::default()).expect("serialize lane metadata");
            assert_eq!(encoded.pop(), Some('}'));
            write!(&mut encoded, ",\"{field}\":{value}}}")
                .expect("writing duplicate field to a String cannot fail");
            let err = norito::json::from_str::<LaneConfig>(&encoded)
                .expect_err("duplicate lane metadata fields must fail closed");
            assert!(
                err.to_string()
                    .contains(&format!("duplicate field `{field}`")),
                "unexpected duplicate-field error: {err}"
            );
        }
    }
    #[test]
    fn lane_config_json_rejects_partial_payloads() {
        let partial = r#"{"id":0,"alias":"default"}"#;
        let err = norito::json::from_str::<LaneConfig>(partial)
            .expect_err("canonical V1 lane metadata must include every serialized field");
        assert!(
            err.to_string()
                .contains("missing required lane config field `shard_id`")
        );
    }
    #[test]
    fn lane_config_json_rejects_unknown_nested_confidential_policy_fields() {
        let lane = LaneConfig {
            storage: LaneStorageProfile::SplitReplica,
            confidential_compute: Some(ConfidentialComputePolicy::new(
                ConfidentialComputeMechanism::Encryption,
                NonZeroU32::MIN,
                BTreeSet::new(),
            )),
            ..LaneConfig::default()
        };
        let encoded = norito::json::to_string(&lane).expect("serialize confidential lane");
        let injected = encoded.replacen(
            "\"confidential_compute\":{",
            "\"confidential_compute\":{\"unexpected\":true,",
            1,
        );
        assert_ne!(
            injected, encoded,
            "confidential object marker must be present"
        );
        let error = norito::json::from_str::<LaneConfig>(&injected)
            .expect_err("unknown confidential policy fields must fail closed");
        assert!(error.to_string().contains("unexpected"));
    }
    #[test]
    fn lane_config_json_rejects_unknown_nested_scheduler_and_settlement_fields() {
        let lane = LaneConfig {
            scheduler: Some(LaneSchedulerPolicy::new(Some(NonZeroU64::MIN), None)),
            settlement_buffer: Some(settlement_buffer_policy()),
            ..LaneConfig::default()
        };
        let encoded = norito::json::to_string(&lane).expect("serialize typed lane policies");
        for marker in ["\"scheduler\":{", "\"settlement_buffer\":{"] {
            let injected = encoded.replacen(marker, &format!("{marker}\"unexpected\":true,"), 1);
            assert_ne!(injected, encoded, "nested policy marker must be present");
            let error = norito::json::from_str::<LaneConfig>(&injected)
                .expect_err("unknown nested policy fields must fail closed");
            assert!(
                error.to_string().contains("unexpected"),
                "unexpected nested-policy error: {error}"
            );
        }
        let missing_scheduler_field = encoded.replacen(",\"starvation_bound_slots\":null", "", 1);
        let error = norito::json::from_str::<LaneConfig>(&missing_scheduler_field)
            .expect_err("canonical scheduler JSON must carry explicit null override fields");
        assert!(error.to_string().contains("starvation_bound_slots"));
    }
    #[test]
    fn lane_lifecycle_json_rejects_nested_duplicate_lane_field() {
        let catalog = LaneCatalog::default();
        let entries = lifecycle_status(&catalog).incarnations;
        let parameter = LaneLifecycleParameterV1::new(
            &catalog,
            &entries,
            LaneLifecyclePlan {
                additions: vec![LaneConfig {
                    id: LaneId::new(1),
                    alias: "manual-lane".to_owned(),
                    ..LaneConfig::default()
                }],
                retire: Vec::new(),
            },
        )
        .expect("valid lifecycle parameter");
        let encoded = norito::json::to_string(&parameter)
            .expect("serialize lifecycle payload")
            .replacen(
                "\"alias\":\"manual-lane\"",
                "\"alias\":\"manual-lane\",\"alias\":\"forged-lane\"",
                1,
            );
        assert!(encoded.contains("\"alias\":\"forged-lane\""));
        let err = norito::json::from_str::<LaneLifecycleParameterV1>(&encoded)
            .expect_err("nested duplicate lane fields must fail closed");
        assert!(err.to_string().contains("duplicate field `alias`"));
    }
    fn visibility_lane(
        id: u32,
        alias: &str,
        dataspace: DataSpaceId,
        visibility: LaneVisibility,
    ) -> LaneConfig {
        LaneConfig {
            id: LaneId::new(id),
            alias: alias.to_owned(),
            dataspace_id: dataspace,
            visibility,
            ..LaneConfig::default()
        }
    }
    /// The fresh Taira layout: three public universal lanes, restricted dpn (3), is2 (4),
    /// cbsi (6) and is (7), and public bpng (5), one dataspace per participant lane.
    fn taira_reset_catalog_lanes() -> Vec<LaneConfig> {
        let dataspace = |seed: u64| DataSpaceId::new(0x7a1a_0000_0000_0000 | seed);
        let mut lanes = vec![
            visibility_lane(0, "core", DataSpaceId::UNIVERSAL, LaneVisibility::Public),
            visibility_lane(
                1,
                "governance",
                DataSpaceId::UNIVERSAL,
                LaneVisibility::Public,
            ),
            visibility_lane(2, "zk", DataSpaceId::UNIVERSAL, LaneVisibility::Public),
        ];
        for (id, alias, visibility) in [
            (3, "dpn", LaneVisibility::Restricted),
            (4, "is2", LaneVisibility::Restricted),
            (5, "bpng", LaneVisibility::Public),
            (6, "cbsi", LaneVisibility::Restricted),
            (7, "is", LaneVisibility::Restricted),
        ] {
            lanes.push(visibility_lane(
                id,
                alias,
                dataspace(u64::from(id)),
                visibility,
            ));
        }
        lanes
    }
    #[test]
    fn lane_catalog_keeps_one_visibility_per_dataspace_and_public_universal_lanes() {
        let lane_count = NonZeroU32::new(8).expect("nonzero");
        let catalog =
            LaneCatalog::new(lane_count, taira_reset_catalog_lanes()).expect("Taira reset layout");
        assert_eq!(
            catalog.dataspace_visibility(DataSpaceId::UNIVERSAL),
            Some(LaneVisibility::Public)
        );
        for lane in catalog.lanes() {
            assert_eq!(
                catalog.dataspace_visibility(lane.dataspace_id),
                Some(lane.visibility)
            );
        }
        assert_eq!(catalog.dataspace_visibility(DataSpaceId::new(99)), None);

        let mut mixed = taira_reset_catalog_lanes();
        let cbsi = mixed[6].dataspace_id;
        mixed.push(visibility_lane(
            8,
            "cbsi-public",
            cbsi,
            LaneVisibility::Public,
        ));
        assert_eq!(
            LaneCatalog::new(NonZeroU32::new(9).unwrap(), mixed),
            Err(LaneCatalogError::MixedDataspaceVisibility { dataspace: cbsi })
        );

        let mut restricted_universal = taira_reset_catalog_lanes();
        restricted_universal[2].visibility = LaneVisibility::Restricted;
        assert_eq!(
            LaneCatalog::new(lane_count, restricted_universal),
            Err(LaneCatalogError::RestrictedUniversalLane(LaneId::new(2)))
        );

        // A lifecycle addition cannot introduce a second visibility for an existing dataspace.
        let addition = LaneLifecyclePlan {
            additions: vec![visibility_lane(
                8,
                "bpng-restricted",
                catalog.lanes()[5].dataspace_id,
                LaneVisibility::Restricted,
            )],
            retire: Vec::new(),
        };
        assert!(matches!(
            catalog.apply_lifecycle(&addition),
            Err(LaneCatalogError::MixedDataspaceVisibility { .. })
        ));
        let same_class = LaneLifecyclePlan {
            additions: vec![visibility_lane(
                8,
                "bpng-second",
                catalog.lanes()[5].dataspace_id,
                LaneVisibility::Public,
            )],
            retire: Vec::new(),
        };
        catalog
            .apply_lifecycle(&same_class)
            .expect("a same-class addition keeps the dataspace class");
    }
    #[test]
    fn lane_lifecycle_rejects_unknown_retire_or_empty() {
        let base = LaneCatalog::default();
        let missing = LaneLifecyclePlan {
            additions: Vec::new(),
            retire: vec![LaneId::new(9)],
        };
        let err = base
            .apply_lifecycle(&missing)
            .expect_err("unknown retire must fail");
        assert!(matches!(err, LaneCatalogError::MissingLane(lane) if lane.as_u32() == 9));
        let duplicate_retire = LaneLifecyclePlan {
            additions: Vec::new(),
            retire: vec![LaneId::SINGLE, LaneId::SINGLE],
        };
        let err = base
            .apply_lifecycle(&duplicate_retire)
            .expect_err("duplicate retire must fail");
        assert!(matches!(
            err,
            LaneCatalogError::DuplicateRetireLane(lane) if lane == LaneId::SINGLE
        ));
        let forged_present = LaneLifecyclePlan {
            additions: vec![LaneConfig {
                id: LaneId::new(9),
                alias: "forged-present".into(),
                ..LaneConfig::default()
            }],
            retire: vec![LaneId::new(9)],
        };
        let err = base
            .apply_lifecycle(&forged_present)
            .expect_err("addition must not satisfy retire precondition");
        assert!(matches!(err, LaneCatalogError::MissingLane(lane) if lane.as_u32() == 9));
        let empty_plan = LaneLifecyclePlan {
            additions: Vec::new(),
            retire: vec![LaneId::SINGLE],
        };
        let err = base
            .apply_lifecycle(&empty_plan)
            .expect_err("empty catalog must be rejected");
        assert!(matches!(err, LaneCatalogError::EmptyCatalog));
    }
    #[test]
    fn lane_lifecycle_rejects_duplicate_additions_before_merge() {
        let base = LaneCatalog::default();
        let duplicate_id = LaneLifecyclePlan {
            additions: vec![
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "beta".into(),
                    ..LaneConfig::default()
                },
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "gamma".into(),
                    ..LaneConfig::default()
                },
            ],
            retire: Vec::new(),
        };
        let err = base
            .apply_lifecycle(&duplicate_id)
            .expect_err("duplicate additions must fail before merge");
        assert!(matches!(
            err,
            LaneCatalogError::DuplicateLaneId(lane) if lane == LaneId::new(1)
        ));
        let duplicate_alias = LaneLifecyclePlan {
            additions: vec![
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "beta".into(),
                    ..LaneConfig::default()
                },
                LaneConfig {
                    id: LaneId::new(2),
                    alias: "beta".into(),
                    ..LaneConfig::default()
                },
            ],
            retire: Vec::new(),
        };
        let err = base
            .apply_lifecycle(&duplicate_alias)
            .expect_err("duplicate addition aliases must fail before merge");
        assert!(matches!(
            err,
            LaneCatalogError::DuplicateLaneAlias(alias) if alias == "beta"
        ));
    }
    #[test]
    fn lane_catalog_constructor_rejects_empty_catalog() {
        let error = LaneCatalog::new(NonZeroU32::new(1).expect("non-zero bound"), Vec::new())
            .expect_err("validated catalogs must never be empty");
        assert_eq!(error, LaneCatalogError::EmptyCatalog);
    }
}
/// Prelude re-export for the Nexus module.
pub mod prelude {
    pub use super::{
        DaManifestPolicy, DaManifestPolicyParseError, DataSpaceCatalog, DataSpaceCatalogError,
        DataSpaceMetadata, LaneCatalog, LaneCatalogError, LaneConfig,
        LaneLifecycleIncarnationEntry, LaneLifecycleParameterV1, LaneLifecyclePlan,
        LaneLifecycleStatusError, LaneLifecycleStatusV1, LaneStorageProfile,
        LaneStorageProfileParseError, LaneVisibility, LaneVisibilityParseError,
    };
}

#[cfg(test)]
mod additional_frame_owner_identity_tests {
    //! Typed frame contracts observed with the original codec.

    #[test]
    fn captured_additional_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<
            crate::nexus::LaneLifecycleStatusV1,
        >("iroha_data_model::nexus::LaneLifecycleStatusV1");
    }
}

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::audit;

    #[test]
    fn original_lane_config_checked_container_retains_bytes_errors_and_depth() {
        audit(&LaneConfig::default());
    }

    #[test]
    fn original_lane_lifecycle_plan_checked_container_retains_original_vectors_and_depth() {
        let value = LaneLifecyclePlan {
            additions: vec![LaneConfig::default()],
            retire: vec![LaneId::new(7)],
        };
        let pointer = value.additions.as_ptr();
        audit(&value);
        assert_eq!(value.additions.as_ptr(), pointer);
    }

    #[test]
    fn original_lane_lifecycle_parameter_checked_container_retains_source_hashes_and_depth() {
        audit(&LaneLifecycleParameterV1 {
            version: LaneLifecycleParameterV1::VERSION,
            expected_catalog_hash: Hash::new(b"catalog"),
            expected_incarnation_root: Hash::new(b"incarnations"),
            plan: LaneLifecyclePlan {
                additions: vec![LaneConfig::default()],
                retire: vec![LaneId::new(7)],
            },
        });
    }

    #[test]
    fn original_lane_incarnation_checked_container_retains_bytes_errors_and_depth() {
        audit(&LaneLifecycleIncarnationEntry {
            lane_id: LaneId::new(7),
            incarnation: Hash::new(b"original incarnation"),
        });
    }

    #[test]
    fn original_lane_lifecycle_status_checked_container_retains_bytes_errors_and_depth() {
        audit(&LaneLifecycleStatusV1 {
            version: LaneLifecycleStatusV1::VERSION,
            lane_count: 1,
            lanes: vec![LaneConfig::default()],
            catalog_hash: Hash::new(b"catalog"),
            incarnations: vec![LaneLifecycleIncarnationEntry {
                lane_id: LaneId::SINGLE,
                incarnation: Hash::new(b"original incarnation"),
            }],
            incarnation_root: Hash::new(b"incarnations"),
            runtime_catalog_hash: Some(Hash::new(b"runtime")),
        });
    }
}
