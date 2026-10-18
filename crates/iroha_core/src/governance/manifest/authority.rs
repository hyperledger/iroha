//! Typed effective lane-manifest policy retained for the State authority cut.
//!
//! This projection binds effective lane admission/routing fields and the
//! materialized current/baseline source bodies and catalog rows. Filesystem
//! paths and local invalid-source diagnostics are excluded. This cell can be
//! encoded only after its actual installed State handle is checked against the
//! current catalog and its retained source rebinding. Complete State-root
//! publication and finalized custody remain separate obligations.

use super::{
    GovernanceRules, LaneManifestRegistry, LaneManifestSourceSnapshot, LaneManifestStatus,
};
use iroha_config::parameters::actual::GovernanceCatalog;
use iroha_crypto::{Hash, privacy::CommitmentScheme};
use iroha_data_model::account::AccountId;
use iroha_data_model::nexus::{LaneCatalog, LaneConsensusProjectionV1};
use iroha_model_base::{name::Name, peer::PeerId};
use norito::{Decode, Encode, NoritoSchema};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane_manifests:v1")]
pub(super) struct LaneManifestEffectiveAuthorityV1 {
    source_policy_digest: [u8; 32],
    baseline_source_policy_digest: [u8; 32],
    bound_catalog_hash: Option<[u8; 32]>,
    source_aliases: Vec<String>,
    statuses: Vec<LaneManifestStatusAuthorityV1>,
    current_source: Option<LaneManifestSourceAuthorityV1>,
    baseline_source: Option<LaneManifestSourceAuthorityV1>,
}

/// Complete materialized source state needed for deterministic catalog rebinding.
/// Local filesystem paths and invalid-source diagnostic strings have no effect
/// on rebinding and are intentionally omitted.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-source:v1")]
struct LaneManifestSourceAuthorityV1 {
    policy_digest: [u8; 32],
    bound_lanes: Vec<LaneBoundCatalogAuthorityV1>,
    manifests: Vec<LaneManifestSourceEntryAuthorityV1>,
    governance_overlay: Option<LaneManifestSourceContentAuthorityV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-bound-catalog-row:v1")]
struct LaneBoundCatalogAuthorityV1 {
    lookup_lane: u32,
    consensus: LaneConsensusProjectionV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-source-entry:v1")]
struct LaneManifestSourceEntryAuthorityV1 {
    alias: String,
    content: LaneManifestSourceContentAuthorityV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-source-content:v1")]
struct LaneManifestSourceContentAuthorityV1 {
    valid: bool,
    digest: [u8; 32],
    canonical_json: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-status:v1")]
struct LaneManifestStatusAuthorityV1 {
    lookup_lane: u32,
    lane: u32,
    alias: String,
    dataspace: u64,
    visibility: u8,
    storage: u8,
    governance: Option<String>,
    has_manifest: bool,
    rules: Option<GovernanceRulesAuthorityV1>,
    privacy_commitments: Vec<LanePrivacyCommitmentAuthorityV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-rules:v1")]
struct GovernanceRulesAuthorityV1 {
    version: u32,
    validators: Vec<AccountId>,
    validator_bindings: Vec<ManifestValidatorBindingAuthorityV1>,
    quorum: Option<u32>,
    protected_namespaces: Vec<Name>,
    runtime_upgrade: Option<RuntimeUpgradeAuthorityV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-validator-binding:v1")]
struct ManifestValidatorBindingAuthorityV1 {
    validator: AccountId,
    peer_id: PeerId,
    torii_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-runtime-upgrade:v1")]
struct RuntimeUpgradeAuthorityV1 {
    allow: bool,
    require_metadata: bool,
    metadata_key: Option<Name>,
    allowed_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(tag = "kind", content = "value", deny_unknown_fields)]
#[norito_schema(name = "iroha:state:lane-manifest-privacy-commitment:v1")]
enum LanePrivacyCommitmentAuthorityV1 {
    Merkle {
        id: u16,
        root: [u8; 32],
        max_depth: u8,
    },
}

impl LaneManifestEffectiveAuthorityV1 {
    /// Capture one registry's effective policy and materialized sources in map-key order.
    /// A deferred source can still open local files and cannot authorize State.
    pub(super) fn try_from_registry(registry: &LaneManifestRegistry) -> Result<Self, String> {
        let current_source = registry
            .source_snapshot
            .as_deref()
            .map(LaneManifestSourceAuthorityV1::try_from_snapshot)
            .transpose()?;
        let baseline_source = registry
            .baseline_source_snapshot
            .as_deref()
            .map(LaneManifestSourceAuthorityV1::try_from_snapshot)
            .transpose()?;
        if let Some(source) = current_source.as_ref() {
            if source.policy_digest != registry.consensus_policy_digest {
                return Err(
                    "lane manifest registry source digest differs from its frozen source".into(),
                );
            }
            if !source
                .manifests
                .iter()
                .map(|row| row.alias.as_str())
                .eq(registry.manifest_source_aliases.iter().map(String::as_str))
            {
                return Err("lane manifest registry aliases differ from its frozen source".into());
            }
        }
        Ok(Self {
            source_policy_digest: registry.consensus_policy_digest,
            baseline_source_policy_digest: registry.baseline_consensus_policy_digest(),
            bound_catalog_hash: registry.bound_catalog_hash.map(Into::into),
            source_aliases: registry.manifest_source_aliases.iter().cloned().collect(),
            statuses: registry
                .statuses
                .iter()
                .map(|(lookup_lane, status)| {
                    LaneManifestStatusAuthorityV1::from_status(
                        lookup_lane.as_u32(),
                        status,
                        registry.has_manifest(*lookup_lane),
                    )
                })
                .collect(),
            current_source,
            baseline_source,
        })
    }

    #[cfg(test)]
    fn from_registry(registry: &LaneManifestRegistry) -> Self {
        let value =
            Self::try_from_registry(registry).expect("materialized lane manifest authority");
        crate::state::authority_registry::policy_borrowed::assert_same_payload(
            &BorrowedManifest(registry),
            &value,
        );
        value
    }
}

impl LaneManifestSourceAuthorityV1 {
    fn try_from_snapshot(source: &LaneManifestSourceSnapshot) -> Result<Self, String> {
        if source.pending_registry.is_some() {
            return Err("lane manifest source has not been materialized for a catalog".into());
        }
        if source.consensus_policy_digest != source.compute_consensus_policy_digest() {
            return Err("lane manifest source digest does not match its contents".into());
        }
        let manifests = source
            .manifests_by_alias
            .iter()
            .map(|(alias, source)| {
                let canonical_json = source
                    .parsed
                    .as_ref()
                    .ok()
                    .map(norito::json::to_json)
                    .transpose()
                    .map_err(|error| {
                        format!("lane manifest canonical source encode failed: {error}")
                    })?;
                Ok(LaneManifestSourceEntryAuthorityV1 {
                    alias: alias.clone(),
                    content: LaneManifestSourceContentAuthorityV1::checked(
                        source.content_digest.valid,
                        source.content_digest.digest,
                        canonical_json,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let governance_overlay = source
            .governance_overlay
            .as_ref()
            .map(|source| {
                let canonical_json = source
                    .parsed
                    .as_ref()
                    .ok()
                    .map(norito::json::to_json)
                    .transpose()
                    .map_err(|error| {
                        format!("governance overlay canonical source encode failed: {error}")
                    })?;
                LaneManifestSourceContentAuthorityV1::checked(
                    source.content_digest.valid,
                    source.content_digest.digest,
                    canonical_json,
                )
            })
            .transpose()?;
        Ok(Self {
            policy_digest: source.consensus_policy_digest,
            bound_lanes: source
                .bound_lanes
                .iter()
                .map(|(lookup_lane, lane)| LaneBoundCatalogAuthorityV1 {
                    lookup_lane: lookup_lane.as_u32(),
                    consensus: lane.consensus_projection(),
                })
                .collect(),
            manifests,
            governance_overlay,
        })
    }
}

impl LaneManifestSourceContentAuthorityV1 {
    fn checked(
        valid: bool,
        digest: [u8; 32],
        canonical_json: Option<String>,
    ) -> Result<Self, String> {
        if valid != canonical_json.is_some() {
            return Err("lane manifest source validity differs from parsed body".into());
        }
        if canonical_json
            .as_ref()
            .is_some_and(|body| <[u8; 32]>::from(Hash::new(body.as_bytes())) != digest)
        {
            return Err("lane manifest source digest differs from parsed body".into());
        }
        Ok(Self {
            valid,
            digest,
            canonical_json,
        })
    }
}

impl LaneManifestRegistry {
    /// Refuse a source registry whose materialized authority cannot be encoded
    /// coherently. This check does not itself publish a complete State root.
    pub(crate) fn validate_authority_projection(&self) -> Result<(), String> {
        LaneManifestEffectiveAuthorityV1::try_from_registry(self).map(|_| ())
    }

    /// Require a complete frozen source, independent of the next catalog binding.
    pub(crate) fn validate_materialized_source_projection(&self) -> Result<(), String> {
        if self.source_snapshot.is_none() {
            return Err("lane manifest authority has no materialized frozen source".into());
        }
        self.validate_authority_projection()
    }

    /// Check that current status was actually derived from the retained frozen
    /// sources and this catalog. Rebinding reads no filesystem paths.
    fn validate_authority_rebinding(
        &self,
        catalog: &LaneCatalog,
        governance: &GovernanceCatalog,
    ) -> Result<LaneManifestEffectiveAuthorityV1, String> {
        let current = LaneManifestEffectiveAuthorityV1::try_from_registry(self)?;
        let rebound = self.rebind(catalog, governance);
        let expected = LaneManifestEffectiveAuthorityV1::try_from_registry(&rebound)?;
        if current != expected {
            return Err(
                "lane manifest policy differs from retained frozen-source rebinding".into(),
            );
        }
        Ok(current)
    }

    /// Require a materialized frozen source bound to this exact publication catalog.
    ///
    /// Status-only scaffolds can be useful in isolated tests but cannot authorize
    /// a first-release lifecycle or a complete State authority transition.
    pub(crate) fn validate_materialized_authority_for_catalog(
        &self,
        catalog: &LaneCatalog,
        governance: &GovernanceCatalog,
    ) -> Result<(), String> {
        self.materialized_authority_for_catalog(catalog, governance)
            .map(|_| ())
    }

    /// Canonical V1 value for the effective policy and both retained source
    /// authorities. An emergency or status-only registry has no such value.
    pub(crate) fn canonical_materialized_authority_preimage(
        &self,
        catalog: &LaneCatalog,
        governance: &GovernanceCatalog,
    ) -> Result<Vec<u8>, String> {
        let authority = self.materialized_authority_for_catalog(catalog, governance)?;
        norito::encode_canonical(&authority)
            .map_err(|error| format!("lane manifest authority canonical encode failed: {error}"))
    }

    fn materialized_authority_for_catalog(
        &self,
        catalog: &LaneCatalog,
        governance: &GovernanceCatalog,
    ) -> Result<LaneManifestEffectiveAuthorityV1, String> {
        self.validate_materialized_source_projection()?;
        if !self.is_bound_to_catalog(catalog) {
            return Err("lane manifest authority is bound to a different lane catalog".into());
        }
        self.validate_authority_rebinding(catalog, governance)
    }

    /// Compare the complete effective and frozen-source authority for a refresh.
    /// A matching source digest alone does not establish identical retained
    /// parsed bodies, baseline bindings, or effective lane status.
    pub(crate) fn has_same_authority_as(&self, other: &Self) -> bool {
        match (
            LaneManifestEffectiveAuthorityV1::try_from_registry(self),
            LaneManifestEffectiveAuthorityV1::try_from_registry(other),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }
}

impl LaneManifestStatusAuthorityV1 {
    fn from_status(lookup_lane: u32, status: &LaneManifestStatus, has_manifest: bool) -> Self {
        Self {
            lookup_lane,
            lane: status.lane.as_u32(),
            alias: status.alias.clone(),
            dataspace: status.dataspace.as_u64(),
            visibility: match status.visibility {
                iroha_data_model::nexus::LaneVisibility::Public => 0,
                iroha_data_model::nexus::LaneVisibility::Restricted => 1,
            },
            storage: match status.storage {
                iroha_data_model::nexus::LaneStorageProfile::FullReplica => 0,
                iroha_data_model::nexus::LaneStorageProfile::CommitmentOnly => 1,
                iroha_data_model::nexus::LaneStorageProfile::SplitReplica => 2,
            },
            governance: status.governance.clone(),
            has_manifest,
            rules: status.governance_rules.as_ref().map(Into::into),
            privacy_commitments: status
                .privacy_commitments
                .iter()
                .map(|commitment| match commitment.scheme() {
                    CommitmentScheme::Merkle(merkle) => LanePrivacyCommitmentAuthorityV1::Merkle {
                        id: commitment.id().get(),
                        root: *merkle.root().as_ref(),
                        max_depth: merkle.max_depth(),
                    },
                })
                .collect(),
        }
    }
}

impl From<&GovernanceRules> for GovernanceRulesAuthorityV1 {
    fn from(rules: &GovernanceRules) -> Self {
        Self {
            version: rules.version,
            // Preserve the declared order: lane consumers can observe the
            // validator pool and its peer bindings in that exact order.
            validators: rules.validators.clone(),
            validator_bindings: rules
                .validator_bindings
                .iter()
                .map(|binding| ManifestValidatorBindingAuthorityV1 {
                    validator: binding.validator.clone(),
                    peer_id: binding.peer_id.clone(),
                    torii_url: binding.torii_url.clone(),
                })
                .collect(),
            quorum: rules.quorum,
            protected_namespaces: rules.protected_namespaces.iter().cloned().collect(),
            runtime_upgrade: rules.hooks.runtime_upgrade.as_ref().map(|hook| {
                RuntimeUpgradeAuthorityV1 {
                    allow: hook.allow,
                    require_metadata: hook.require_metadata,
                    metadata_key: hook.metadata_key.clone(),
                    allowed_ids: hook
                        .allowed_ids
                        .as_ref()
                        .map(|ids| ids.iter().cloned().collect()),
                }
            }),
        }
    }
}

/// Exact original materialized registry bytes. This is an encoder, not an
/// authorization capability: original-cut callers must retain StatePublication's
/// validated and frozen runtime/catalog/manifest owner throughout both passes.
pub(crate) struct BorrowedManifest<'a>(&'a LaneManifestRegistry);
impl LaneManifestRegistry {
    /// Check the original retained source bodies and exact catalog, then borrow
    /// their complete authority payload. The publication owner separately retains
    /// the source-rebinding proof from before these same originals were frozen.
    pub(crate) fn borrowed_materialized_for_frozen_catalog(
        &self,
        lane_count: u32,
        lanes: &[iroha_data_model::nexus::LaneConfig],
    ) -> Result<BorrowedManifest<'_>, norito::Error> {
        use crate::state::authority_registry::policy_borrowed::{Ref, Seq, hash_payload, record};
        let invalid = |message: &str| norito::Error::Message(message.into());
        let source = self
            .source_snapshot
            .as_deref()
            .ok_or_else(|| invalid("lane manifest authority has no materialized frozen source"))?;
        validate_borrowed_source(source)?;
        if let Some(baseline) = self.baseline_source_snapshot.as_deref() {
            validate_borrowed_source(baseline)?;
        }
        if source.consensus_policy_digest != self.consensus_policy_digest
            || !source
                .manifests_by_alias
                .keys()
                .eq(self.manifest_source_aliases.iter())
        {
            return Err(invalid(
                "lane manifest registry differs from its retained source",
            ));
        }
        let catalog_hash = hash_payload(
            b"iroha:nexus:lane-catalog:v1\0",
            &record!(lane_count, Seq(lanes.iter().map(Ref))),
        )?;
        if self.bound_catalog_hash.map(<[u8; 32]>::from) != Some(catalog_hash) {
            return Err(invalid(
                "lane manifest authority is bound to a different frozen catalog",
            ));
        }
        if self.statuses.len() != lanes.len()
            || !self.statuses.iter().zip(lanes).all(|((id, status), lane)| {
                *id == lane.id
                    && status.lane == lane.id
                    && status.alias == lane.alias
                    && status.dataspace == lane.dataspace_id
                    && status.visibility == lane.visibility
                    && status.storage == lane.storage
            })
        {
            return Err(invalid(
                "lane manifest statuses differ from the frozen catalog",
            ));
        }
        Ok(BorrowedManifest(self))
    }
}
impl norito::SerializePayload for BorrowedManifest<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        use crate::state::authority_registry::policy_borrowed::{Raw, Ref, Seq, record};
        let registry = self.0;
        let baseline_digest = registry.baseline_consensus_policy_digest();
        record!(
            Raw(&registry.consensus_policy_digest),
            Raw(&baseline_digest),
            registry.bound_catalog_hash.map(<[u8; 32]>::from),
            Seq(registry.manifest_source_aliases.iter().map(Ref)),
            Seq(registry.statuses.iter().map(|(id, status)| borrowed_status(
                id.as_u32(),
                status,
                registry.has_manifest(*id)
            ))),
            registry.source_snapshot.as_deref().map(borrowed_source),
            registry
                .baseline_source_snapshot
                .as_deref()
                .map(borrowed_source)
        )
        .serialize(writer)
    }
}
fn validate_borrowed_source(source: &LaneManifestSourceSnapshot) -> Result<(), norito::Error> {
    use crate::state::authority_registry::policy_borrowed::{
        Raw, Ref, Seq, hash_json, hash_payload, record,
    };
    if source.pending_registry.is_some() {
        return Err(norito::Error::Message(
            "lane manifest source has not been materialized for a catalog".into(),
        ));
    }
    let digest = hash_payload(
        b"iroha:nexus:lane-manifest-source-set:v1\0",
        &record!(
            1_u8,
            Seq(source
                .manifests_by_alias
                .iter()
                .map(|(alias, value)| record!(
                    Ref(alias),
                    record!(
                        value.content_digest.valid,
                        Raw(&value.content_digest.digest)
                    )
                ))),
            source.governance_overlay.as_ref().map(|value| record!(
                value.content_digest.valid,
                Raw(&value.content_digest.digest)
            ))
        ),
    )?;
    if digest != source.consensus_policy_digest {
        return Err(norito::Error::Message(
            "lane manifest source digest does not match its contents".into(),
        ));
    }
    fn check<T: norito::json::JsonSerialize>(
        valid: bool,
        digest: &[u8; 32],
        parsed: Result<&T, &String>,
    ) -> Result<(), norito::Error> {
        if valid != parsed.is_ok() {
            return Err(norito::Error::Message(
                "lane manifest source validity differs from its retained body".into(),
            ));
        }
        if let Ok(parsed) = parsed
            && hash_json(parsed)? != *digest
        {
            return Err(norito::Error::Message(
                "lane manifest source digest differs from its retained canonical JSON".into(),
            ));
        }
        Ok(())
    }
    for value in source.manifests_by_alias.values() {
        check(
            value.content_digest.valid,
            &value.content_digest.digest,
            value.parsed.as_ref(),
        )?;
    }
    if let Some(value) = &source.governance_overlay {
        check(
            value.content_digest.valid,
            &value.content_digest.digest,
            value.parsed.as_ref(),
        )?;
    }
    Ok(())
}
fn borrowed_source(source: &LaneManifestSourceSnapshot) -> impl norito::SerializePayload + '_ {
    use crate::state::authority_registry::policy_borrowed::{JsonString, Raw, Ref, Seq, record};
    record!(
        Raw(&source.consensus_policy_digest),
        Seq(source
            .bound_lanes
            .iter()
            .map(|(id, lane)| record!(id.as_u32(), lane.borrowed_consensus_projection()))),
        Seq(source
            .manifests_by_alias
            .iter()
            .map(|(alias, value)| record!(
                Ref(alias),
                record!(
                    value.content_digest.valid,
                    Raw(&value.content_digest.digest),
                    value.parsed.as_ref().ok().map(JsonString)
                )
            ))),
        source.governance_overlay.as_ref().map(|value| record!(
            value.content_digest.valid,
            Raw(&value.content_digest.digest),
            value.parsed.as_ref().ok().map(JsonString)
        ))
    )
}
fn borrowed_status(
    lookup_lane: u32,
    status: &LaneManifestStatus,
    has_manifest: bool,
) -> impl norito::SerializePayload + '_ {
    use crate::state::authority_registry::policy_borrowed::{Ref, Seq, record};
    use iroha_data_model::nexus::{LaneStorageProfile, LaneVisibility};
    record!(
        lookup_lane,
        status.lane.as_u32(),
        Ref(&status.alias),
        status.dataspace.as_u64(),
        match status.visibility {
            LaneVisibility::Public => 0_u8,
            LaneVisibility::Restricted => 1_u8,
        },
        match status.storage {
            LaneStorageProfile::FullReplica => 0_u8,
            LaneStorageProfile::CommitmentOnly => 1_u8,
            LaneStorageProfile::SplitReplica => 2_u8,
        },
        Ref(&status.governance),
        has_manifest,
        status.governance_rules.as_ref().map(borrowed_rules),
        Seq(status
            .privacy_commitments
            .iter()
            .map(|commitment| match commitment.scheme() {
                CommitmentScheme::Merkle(merkle) => LanePrivacyCommitmentAuthorityV1::Merkle {
                    id: commitment.id().get(),
                    root: *merkle.root().as_ref(),
                    max_depth: merkle.max_depth(),
                },
            }))
    )
}
fn borrowed_rules(rules: &GovernanceRules) -> impl norito::SerializePayload + '_ {
    use crate::state::authority_registry::policy_borrowed::{Ref, Seq, record};
    record!(
        rules.version,
        Ref(&rules.validators),
        Seq(rules.validator_bindings.iter().map(|binding| record!(
            Ref(&binding.validator),
            Ref(&binding.peer_id),
            Ref(&binding.torii_url)
        ))),
        rules.quorum,
        Seq(rules.protected_namespaces.iter().map(Ref)),
        rules.hooks.runtime_upgrade.as_ref().map(|hook| record!(
            hook.allow,
            hook.require_metadata,
            Ref(&hook.metadata_key),
            hook.allowed_ids
                .as_ref()
                .map(|ids| Seq(ids.iter().map(Ref)))
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::manifest::{
        FrozenGovernanceOverlaySource, FrozenLaneManifestSource, GovernanceCatalogFile,
        GovernanceHooks, LaneManifestSourceContentDigestV1, LaneManifestSourceSnapshot,
        ManifestValidatorBinding, RuntimeUpgradeHook,
    };
    use iroha_config::parameters::actual::{GovernanceCatalog, LaneRegistry};
    use iroha_crypto::privacy::{LaneCommitmentId, LanePrivacyCommitment, MerkleCommitment};
    use iroha_data_model::nexus::{
        LaneCatalog, LaneConfig, LaneStorageProfile, LaneVisibility, NativeLaneManifestV1,
    };
    use iroha_model_base::topology::{DataSpaceId, LaneId};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::PathBuf,
        str::FromStr,
        sync::Arc,
    };

    #[test]
    fn borrowed_materialized_source_binds_complete_body_and_catalog() {
        let source = materialized_source(
            NativeLaneManifestV1::default(),
            Some(GovernanceCatalogFile::default()),
        );
        let registry = materialized_registry(source.clone());
        let catalog = LaneCatalog::default();
        let borrowed = registry
            .borrowed_materialized_for_frozen_catalog(catalog.lane_count().get(), catalog.lanes())
            .unwrap();
        crate::state::authority_registry::policy_borrowed::assert_same_payload(
            &borrowed,
            &LaneManifestEffectiveAuthorityV1::try_from_registry(&registry).unwrap(),
        );
        let mut wrong = catalog.lanes().to_vec();
        wrong[0].alias = "rebound".into();
        assert!(
            registry
                .borrowed_materialized_for_frozen_catalog(catalog.lane_count().get(), &wrong)
                .is_err()
        );
        let mut changed = source;
        changed
            .manifests_by_alias
            .get_mut("default")
            .unwrap()
            .parsed
            .as_mut()
            .unwrap()
            .lane = Some("changed-body".into());
        assert!(
            validate_borrowed_source(&changed).is_err(),
            "digest cannot substitute for retained source bytes"
        );
        let provisional = LaneManifestRegistry::from_statuses(BTreeMap::new());
        assert!(
            provisional
                .borrowed_materialized_for_frozen_catalog(
                    catalog.lane_count().get(),
                    catalog.lanes()
                )
                .is_err()
        );
    }

    #[test]
    fn emergency_empty_registry_cannot_claim_materialized_source() {
        let materialized_empty = LaneManifestRegistry::empty();
        let provisional = LaneManifestRegistry::provisional_empty_for_emergency_fast_startup();
        assert!(
            materialized_empty
                .validate_materialized_source_projection()
                .is_ok()
        );
        assert!(
            provisional
                .validate_materialized_source_projection()
                .is_err()
        );
        assert!(materialized_empty.statuses().is_empty());
        assert!(provisional.statuses().is_empty());
        assert!(!provisional.has_same_authority_as(&materialized_empty));
        assert_eq!(
            provisional.consensus_policy_digest(),
            materialized_empty.consensus_policy_digest(),
            "the emergency marker changes authority, not the empty source-set digest"
        );
    }

    fn status() -> LaneManifestStatus {
        let validator = ALICE_ID.clone();
        LaneManifestStatus {
            lane: LaneId::new(1),
            alias: "private".into(),
            dataspace: DataSpaceId::new(7),
            visibility: LaneVisibility::Restricted,
            storage: LaneStorageProfile::CommitmentOnly,
            governance: Some("council".into()),
            manifest_path: Some(PathBuf::from("/srv/a.json")),
            governance_rules: Some(GovernanceRules {
                version: 1,
                validators: vec![validator.clone()],
                validator_bindings: vec![ManifestValidatorBinding {
                    peer_id: PeerId::from(validator.expect_single_signatory().clone()),
                    validator,
                    torii_url: Some("https://validator.example".into()),
                }],
                quorum: Some(1),
                protected_namespaces: BTreeSet::from([
                    Name::from_str("protected").expect("valid namespace")
                ]),
                hooks: GovernanceHooks {
                    runtime_upgrade: Some(RuntimeUpgradeHook {
                        allow: true,
                        require_metadata: true,
                        metadata_key: Some(Name::from_str("upgrade_id").expect("valid key")),
                        allowed_ids: Some(BTreeSet::from(["upgrade-a".into()])),
                    }),
                },
            }),
            privacy_commitments: vec![LanePrivacyCommitment::merkle(
                LaneCommitmentId::new(1),
                MerkleCommitment::from_root_bytes([0xAA; 32], 12),
            )],
        }
    }

    fn registry(status: LaneManifestStatus) -> LaneManifestRegistry {
        LaneManifestRegistry::from_statuses(BTreeMap::from([(LaneId::new(1), status)]))
    }

    fn status_bytes(status: LaneManifestStatus) -> Vec<u8> {
        let policy = LaneManifestEffectiveAuthorityV1::from_registry(&registry(status));
        norito::encode_canonical(&policy.statuses[0]).expect("canonical status")
    }

    fn materialized_source(
        manifest: NativeLaneManifestV1,
        overlay: Option<GovernanceCatalogFile>,
    ) -> LaneManifestSourceSnapshot {
        let mut source = LaneManifestSourceSnapshot::empty();
        let manifest_json = norito::json::to_json(&manifest).expect("canonical source JSON");
        source.manifests_by_alias.insert(
            "default".into(),
            FrozenLaneManifestSource {
                path: Some(PathBuf::from("/host/a/default.manifest.json")),
                parsed: Ok(manifest),
                content_digest: LaneManifestSourceContentDigestV1 {
                    valid: true,
                    digest: Hash::new(manifest_json.as_bytes()).into(),
                },
            },
        );
        source
            .bound_lanes
            .insert(LaneId::SINGLE, LaneConfig::default());
        source.governance_overlay = overlay.map(|overlay| {
            let canonical = norito::json::to_json(&overlay).expect("canonical overlay JSON");
            FrozenGovernanceOverlaySource {
                path: PathBuf::from("/host/a/governance_catalog.json"),
                parsed: Ok(overlay),
                content_digest: LaneManifestSourceContentDigestV1 {
                    valid: true,
                    digest: Hash::new(canonical.as_bytes()).into(),
                },
            }
        });
        source.consensus_policy_digest = source.compute_consensus_policy_digest();
        source
    }

    fn materialized_registry(source: LaneManifestSourceSnapshot) -> LaneManifestRegistry {
        LaneManifestRegistry::from_source_snapshot(
            Arc::new(source),
            &LaneCatalog::default(),
            &GovernanceCatalog::default(),
        )
    }

    #[test]
    fn effective_policy_roundtrips_with_explicit_v1_identity() {
        let policy = LaneManifestEffectiveAuthorityV1::from_registry(&registry(status()));
        assert_eq!(
            LaneManifestEffectiveAuthorityV1::nominal_name(),
            "iroha:state:lane_manifests:v1"
        );
        let bytes = norito::encode_canonical(&policy).expect("canonical policy");
        assert_eq!(
            norito::decode_canonical::<LaneManifestEffectiveAuthorityV1>(&bytes)
                .expect("decode canonical policy"),
            policy
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(
            norito::encode_canonical(&policy).expect("ambient-independent encoding"),
            bytes
        );
    }

    #[test]
    fn effective_status_binds_every_lane_and_governance_input() {
        let baseline = status_bytes(status());
        let check = |mutate: fn(&mut LaneManifestStatus), field| {
            let mut changed = status();
            mutate(&mut changed);
            assert_ne!(status_bytes(changed), baseline, "{field}");
        };
        check(|row| row.lane = LaneId::new(2), "lane");
        check(|row| row.alias = "other".into(), "alias");
        check(|row| row.dataspace = DataSpaceId::new(8), "dataspace");
        check(|row| row.visibility = LaneVisibility::Public, "visibility");
        check(
            |row| row.storage = LaneStorageProfile::SplitReplica,
            "storage",
        );
        check(|row| row.governance = None, "governance");
        check(|row| row.manifest_path = None, "manifest source presence");
        check(
            |row| row.governance_rules.as_mut().unwrap().version += 1,
            "version",
        );
        check(
            |row| row.governance_rules.as_mut().unwrap().validators = vec![BOB_ID.clone()],
            "validators",
        );
        check(
            |row| {
                row.governance_rules.as_mut().unwrap().validator_bindings[0].validator =
                    BOB_ID.clone()
            },
            "validator binding",
        );
        check(
            |row| {
                row.governance_rules.as_mut().unwrap().validator_bindings[0].peer_id =
                    PeerId::from(BOB_ID.expect_single_signatory().clone())
            },
            "validator peer binding",
        );
        check(
            |row| row.governance_rules.as_mut().unwrap().validator_bindings[0].torii_url = None,
            "routing URL",
        );
        check(
            |row| row.governance_rules.as_mut().unwrap().quorum = Some(2),
            "quorum",
        );
        check(
            |row| {
                row.governance_rules
                    .as_mut()
                    .unwrap()
                    .protected_namespaces
                    .clear()
            },
            "protected namespace",
        );
        check(
            |row| {
                row.governance_rules
                    .as_mut()
                    .unwrap()
                    .hooks
                    .runtime_upgrade
                    .as_mut()
                    .unwrap()
                    .allow = false
            },
            "runtime-upgrade allow",
        );
        check(
            |row| {
                row.governance_rules
                    .as_mut()
                    .unwrap()
                    .hooks
                    .runtime_upgrade
                    .as_mut()
                    .unwrap()
                    .require_metadata = false
            },
            "runtime-upgrade metadata requirement",
        );
        check(
            |row| {
                row.governance_rules
                    .as_mut()
                    .unwrap()
                    .hooks
                    .runtime_upgrade
                    .as_mut()
                    .unwrap()
                    .metadata_key = None
            },
            "runtime-upgrade metadata key",
        );
        check(
            |row| {
                row.governance_rules
                    .as_mut()
                    .unwrap()
                    .hooks
                    .runtime_upgrade
                    .as_mut()
                    .unwrap()
                    .allowed_ids = None
            },
            "runtime-upgrade allowlist",
        );
        check(
            |row| {
                row.privacy_commitments = vec![LanePrivacyCommitment::merkle(
                    LaneCommitmentId::new(2),
                    MerkleCommitment::from_root_bytes([0xAA; 32], 12),
                )]
            },
            "privacy commitment ID",
        );
        check(
            |row| {
                row.privacy_commitments = vec![LanePrivacyCommitment::merkle(
                    LaneCommitmentId::new(1),
                    MerkleCommitment::from_root_bytes([0xBB; 32], 12),
                )]
            },
            "privacy commitment root",
        );
        check(
            |row| {
                row.privacy_commitments = vec![LanePrivacyCommitment::merkle(
                    LaneCommitmentId::new(1),
                    MerkleCommitment::from_root_bytes([0xAA; 32], 13),
                )]
            },
            "privacy commitment depth",
        );
    }

    #[test]
    fn filesystem_relocation_does_not_change_effective_policy() {
        let baseline = LaneManifestEffectiveAuthorityV1::from_registry(&registry(status()));
        let mut relocated = status();
        relocated.manifest_path = Some(PathBuf::from("/other/host/a.json"));
        assert_eq!(
            LaneManifestEffectiveAuthorityV1::from_registry(&registry(relocated)),
            baseline
        );
    }

    #[test]
    fn effective_registry_binds_source_identity_and_orders_lane_keys() {
        let baseline = registry(status());
        let original = LaneManifestEffectiveAuthorityV1::from_registry(&baseline);
        let different_lookup_key =
            LaneManifestRegistry::from_statuses(BTreeMap::from([(LaneId::new(2), status())]));
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&different_lookup_key).statuses,
            original.statuses,
            "the lookup key is authoritative even if the embedded lane is unchanged"
        );
        let mut changed = registry(status());
        changed.consensus_policy_digest[0] ^= 1;
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&changed),
            original
        );
        let mut changed = registry(status());
        changed.baseline_source_snapshot = Some(Arc::new(LaneManifestSourceSnapshot::empty()));
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&changed),
            original
        );
        let mut changed = registry(status());
        changed.bound_catalog_hash = Some(iroha_crypto::Hash::new(b"bound catalog"));
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&changed),
            original
        );
        let mut changed = registry(status());
        changed.manifest_source_aliases.insert("another".into());
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&changed),
            original
        );

        let mut second = status();
        second.lane = LaneId::new(2);
        second.alias = "second".into();
        let first = status();
        let left = LaneManifestRegistry::from_statuses(BTreeMap::from([
            (LaneId::new(1), first.clone()),
            (LaneId::new(2), second.clone()),
        ]));
        let right = LaneManifestRegistry::from_statuses(BTreeMap::from([
            (LaneId::new(2), second),
            (LaneId::new(1), first),
        ]));
        assert_eq!(
            LaneManifestEffectiveAuthorityV1::from_registry(&left),
            LaneManifestEffectiveAuthorityV1::from_registry(&right),
            "map insertion order cannot change the canonical lane policy"
        );
    }

    #[test]
    fn materialized_current_and_baseline_sources_bind_bodies_overlay_and_catalog_rows() {
        let manifest = NativeLaneManifestV1 {
            lane: Some("default".into()),
            ..NativeLaneManifestV1::default()
        };
        let overlay = GovernanceCatalogFile {
            default_module: Some("council".into()),
            ..GovernanceCatalogFile::default()
        };
        let baseline_source = materialized_source(manifest.clone(), Some(overlay.clone()));
        let baseline_registry = materialized_registry(baseline_source.clone());
        let baseline = LaneManifestEffectiveAuthorityV1::from_registry(&baseline_registry);
        assert_eq!(
            baseline.current_source.as_ref().unwrap().bound_lanes.len(),
            1
        );
        assert!(
            baseline.current_source.as_ref().unwrap().manifests[0]
                .content
                .canonical_json
                .is_some()
        );
        let encoded = norito::encode_canonical(&baseline).expect("canonical source authority");
        assert_eq!(
            norito::decode_canonical::<LaneManifestEffectiveAuthorityV1>(&encoded)
                .expect("roundtrip source authority"),
            baseline
        );

        let changed_manifest = NativeLaneManifestV1 {
            version: Some(NativeLaneManifestV1::VERSION),
            ..manifest
        };
        let changed = LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(
            materialized_source(changed_manifest, Some(overlay.clone())),
        ));
        assert_ne!(changed.current_source, baseline.current_source);

        let changed_overlay = GovernanceCatalogFile {
            default_module: Some("parliament".into()),
            ..overlay
        };
        let changed = LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(
            materialized_source(NativeLaneManifestV1::default(), Some(changed_overlay)),
        ));
        assert_ne!(changed.current_source, baseline.current_source);

        let mut changed_source = baseline_source.clone();
        changed_source
            .bound_lanes
            .get_mut(&LaneId::SINGLE)
            .unwrap()
            .description = Some("dashboard only".into());
        assert_eq!(
            LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(changed_source))
                .current_source,
            baseline.current_source,
            "non-consensus catalog fields do not change authority"
        );
        let mut changed_source = baseline_source.clone();
        changed_source
            .bound_lanes
            .get_mut(&LaneId::SINGLE)
            .unwrap()
            .governance = Some("council".into());
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(changed_source))
                .current_source,
            baseline.current_source
        );
        let mut changed_source = baseline_source.clone();
        let lane = changed_source.bound_lanes.remove(&LaneId::SINGLE).unwrap();
        changed_source.bound_lanes.insert(LaneId::new(8), lane);
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(changed_source))
                .current_source,
            baseline.current_source,
            "the catalog lookup key is independent authority"
        );

        let mut registry = baseline_registry;
        registry.baseline_source_snapshot = Some(Arc::new(baseline_source));
        let with_baseline = LaneManifestEffectiveAuthorityV1::from_registry(&registry);
        assert_eq!(with_baseline.baseline_source, with_baseline.current_source);
        registry.baseline_source_snapshot = Some(Arc::new(materialized_source(
            NativeLaneManifestV1::default(),
            None,
        )));
        assert_ne!(
            LaneManifestEffectiveAuthorityV1::from_registry(&registry).baseline_source,
            with_baseline.baseline_source
        );
    }

    #[test]
    fn source_projection_rejects_pending_and_inconsistent_materialization() {
        let mut registry = registry(status());
        registry.source_snapshot = Some(Arc::new(LaneManifestSourceSnapshot::load(
            &LaneRegistry::default(),
        )));
        assert!(
            LaneManifestEffectiveAuthorityV1::try_from_registry(&registry)
                .unwrap_err()
                .contains("not been materialized")
        );

        let source = materialized_source(NativeLaneManifestV1::default(), None);
        let mut registry = materialized_registry(source);
        assert!(registry.validate_authority_projection().is_ok());
        assert!(
            registry
                .validate_authority_rebinding(
                    &LaneCatalog::default(),
                    &GovernanceCatalog::default()
                )
                .is_ok()
        );
        Arc::make_mut(registry.source_snapshot.as_mut().unwrap())
            .manifests_by_alias
            .get_mut("default")
            .unwrap()
            .parsed = Ok(NativeLaneManifestV1 {
            version: Some(1),
            ..NativeLaneManifestV1::default()
        });
        assert!(
            LaneManifestEffectiveAuthorityV1::try_from_registry(&registry)
                .unwrap_err()
                .contains("digest differs from parsed body")
        );
        assert!(registry.validate_authority_projection().is_err());

        let mut registry =
            materialized_registry(materialized_source(NativeLaneManifestV1::default(), None));
        Arc::make_mut(registry.source_snapshot.as_mut().unwrap()).pending_registry =
            Some(LaneRegistry::default());
        assert!(LaneManifestEffectiveAuthorityV1::try_from_registry(&registry).is_err());
    }

    #[test]
    fn lifecycle_authority_rejects_status_only_and_wrong_catalog() {
        let catalog = LaneCatalog::default();
        let governance = GovernanceCatalog::default();
        let status_only = registry(status());
        assert!(
            status_only
                .validate_materialized_authority_for_catalog(&catalog, &governance)
                .unwrap_err()
                .contains("no materialized frozen source")
        );
        let materialized =
            materialized_registry(materialized_source(NativeLaneManifestV1::default(), None));
        materialized
            .validate_materialized_authority_for_catalog(&catalog, &governance)
            .expect("exact materialized source and catalog");
        let wrong_catalog = LaneCatalog::new(
            std::num::NonZeroU32::new(2).unwrap(),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "second".into(),
                    ..LaneConfig::default()
                },
            ],
        )
        .unwrap();
        assert!(
            materialized
                .validate_materialized_authority_for_catalog(&wrong_catalog, &governance)
                .unwrap_err()
                .contains("different lane catalog")
        );
    }

    #[test]
    fn lifecycle_authority_rejects_exact_source_or_effective_status_substitution() {
        let catalog = LaneCatalog::default();
        let governance = GovernanceCatalog::default();
        let source = materialized_source(NativeLaneManifestV1::default(), None);
        let mut changed_source = materialized_registry(source.clone());
        Arc::make_mut(changed_source.source_snapshot.as_mut().unwrap())
            .manifests_by_alias
            .get_mut("default")
            .unwrap()
            .parsed = Ok(NativeLaneManifestV1 {
            version: Some(1),
            ..NativeLaneManifestV1::default()
        });
        assert!(
            changed_source
                .validate_materialized_authority_for_catalog(&catalog, &governance)
                .unwrap_err()
                .contains("digest differs from parsed body")
        );
        let mut changed_status = materialized_registry(source);
        changed_status
            .statuses
            .get_mut(&LaneId::SINGLE)
            .unwrap()
            .alias = "replaced".into();
        assert!(
            changed_status
                .validate_materialized_authority_for_catalog(&catalog, &governance)
                .unwrap_err()
                .contains("rebinding")
        );
    }

    #[test]
    fn invalid_frozen_source_projects_digest_without_local_diagnostic_or_path() {
        let mut source = materialized_source(NativeLaneManifestV1::default(), None);
        let entry = source.manifests_by_alias.get_mut("default").unwrap();
        entry.parsed = Err("host A local parse diagnostic".into());
        entry.content_digest.valid = false;
        source.consensus_policy_digest = source.compute_consensus_policy_digest();
        let baseline =
            LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(source.clone()));
        assert!(
            baseline.current_source.as_ref().unwrap().manifests[0]
                .content
                .canonical_json
                .is_none()
        );
        let entry = source.manifests_by_alias.get_mut("default").unwrap();
        entry.parsed = Err("host B different local parse diagnostic".into());
        entry.path = Some(PathBuf::from("/different/path"));
        assert_eq!(
            LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(source)),
            baseline
        );
    }

    #[test]
    fn source_projection_excludes_local_paths() {
        let source = materialized_source(NativeLaneManifestV1::default(), None);
        let baseline =
            LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(source.clone()));
        let mut relocated = source;
        relocated
            .manifests_by_alias
            .get_mut("default")
            .unwrap()
            .path = Some(PathBuf::from("/other/host/default.manifest.json"));
        let relocated =
            LaneManifestEffectiveAuthorityV1::from_registry(&materialized_registry(relocated));
        assert_eq!(relocated, baseline);
    }

    #[test]
    fn equal_source_digest_cannot_authorize_changed_effective_status_or_frozen_body() {
        let original = registry(status());
        let mut changed = registry(status());
        changed.statuses.get_mut(&LaneId::new(1)).unwrap().alias = "different".into();
        assert_eq!(
            changed.consensus_policy_digest,
            original.consensus_policy_digest
        );
        assert!(!original.has_same_authority_as(&changed));
        assert!(
            changed
                .validate_authority_rebinding(
                    &LaneCatalog::default(),
                    &GovernanceCatalog::default()
                )
                .is_err()
        );

        let source = materialized_source(NativeLaneManifestV1::default(), None);
        let original = materialized_registry(source.clone());
        let mut changed_status = materialized_registry(source.clone());
        changed_status
            .statuses
            .get_mut(&LaneId::SINGLE)
            .unwrap()
            .alias = "forged".into();
        assert!(
            changed_status
                .validate_authority_rebinding(
                    &LaneCatalog::default(),
                    &GovernanceCatalog::default()
                )
                .is_err()
        );
        let mut changed = materialized_registry(source);
        Arc::make_mut(changed.source_snapshot.as_mut().unwrap())
            .manifests_by_alias
            .get_mut("default")
            .unwrap()
            .parsed = Ok(NativeLaneManifestV1 {
            version: Some(1),
            ..NativeLaneManifestV1::default()
        });
        assert_eq!(
            changed.consensus_policy_digest,
            original.consensus_policy_digest
        );
        assert!(!original.has_same_authority_as(&changed));
    }

    #[test]
    fn materialized_state_cell_roundtrips_and_binds_current_and_baseline_sources() {
        let catalog = LaneCatalog::default();
        let governance = GovernanceCatalog::default();
        let source = materialized_source(NativeLaneManifestV1::default(), None);
        let original = materialized_registry(source.clone());
        let bytes = original
            .canonical_materialized_authority_preimage(&catalog, &governance)
            .expect("strict materialized State value");
        let decoded = norito::decode_canonical::<LaneManifestEffectiveAuthorityV1>(&bytes)
            .expect("canonical typed State value");
        assert_eq!(
            decoded,
            LaneManifestEffectiveAuthorityV1::from_registry(&original)
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(
            original
                .canonical_materialized_authority_preimage(&catalog, &governance)
                .expect("ambient-independent State value"),
            bytes
        );

        let changed_source = materialized_registry(materialized_source(
            NativeLaneManifestV1 {
                version: Some(1),
                ..NativeLaneManifestV1::default()
            },
            None,
        ));
        assert_ne!(
            changed_source
                .canonical_materialized_authority_preimage(&catalog, &governance)
                .expect("changed frozen current body"),
            bytes
        );
        let mut changed_baseline = original;
        changed_baseline.baseline_source_snapshot = Some(Arc::new(materialized_source(
            NativeLaneManifestV1 {
                version: Some(1),
                ..NativeLaneManifestV1::default()
            },
            None,
        )));
        assert_ne!(
            changed_baseline
                .canonical_materialized_authority_preimage(&catalog, &governance)
                .expect("changed retained baseline source"),
            bytes
        );
        let mut changed_catalog_row = source;
        changed_catalog_row
            .bound_lanes
            .get_mut(&LaneId::SINGLE)
            .unwrap()
            .alias = "substituted".into();
        changed_catalog_row.consensus_policy_digest =
            changed_catalog_row.compute_consensus_policy_digest();
        assert_ne!(
            materialized_registry(changed_catalog_row)
                .canonical_materialized_authority_preimage(&catalog, &governance)
                .expect("changed source catalog row"),
            bytes
        );
    }

    #[test]
    fn materialized_state_cell_rejects_provisional_and_status_only_authority() {
        let catalog = LaneCatalog::default();
        let governance = GovernanceCatalog::default();
        for registry in [
            LaneManifestRegistry::provisional_empty_for_emergency_fast_startup(),
            LaneManifestRegistry::from_statuses(BTreeMap::new()),
        ] {
            assert!(
                registry
                    .canonical_materialized_authority_preimage(&catalog, &governance)
                    .unwrap_err()
                    .contains("materialized frozen source")
            );
        }
    }
}
